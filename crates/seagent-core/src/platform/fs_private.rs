//! Files and directories only the owning account can read: secrets, tokens, sockets, audit
//! logs, session transcripts.
//!
//! * **Unix** — `chmod`, exactly as the call sites did it: directories `0700`, files `0600`,
//!   new files created with mode `0600` (no window where they are world-readable).
//! * **Windows** — a *protected* DACL with one entry, full control for the current user's SID
//!   (inheritance from the parent is cut, so a world-readable profile folder does not leak in;
//!   directories pass the entry on to new children). New files get the DACL at creation through
//!   `SECURITY_ATTRIBUTES`. Failures come back as an explicit error naming the path, never a
//!   silent success.
//!
//! The Windows security-descriptor helpers also serve [`super::ipc`] (owner-only named pipes).

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// How [`open_private`] opens the file (always for writing, always creating it owner-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Create or truncate.
    Truncate,
    /// Create or append.
    Append,
    /// Create; fail with `AlreadyExists` when it exists.
    CreateNew,
}

/// `create_dir_all(dir)`, then make `dir` itself owner-only (`0700`). Parents keep whatever
/// they had (they may be shared, like `/run/user/<uid>` or the profile folder).
pub fn create_dir_private(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    set_private(dir)
}

/// Make an existing file (`0600`) or directory (`0700`) owner-only.
#[cfg(unix)]
pub fn set_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if std::fs::metadata(path)?.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Make an existing file or directory owner-only (protected single-entry DACL).
#[cfg(windows)]
pub fn set_private(path: &Path) -> io::Result<()> {
    let dir = std::fs::metadata(path)?.is_dir();
    win::apply_owner_only(path, dir).map_err(|e| io::Error::new(e.kind(), format!("owner-only ACL on {}: {e}", path.display())))
}

#[cfg(not(any(unix, windows)))]
pub fn set_private(path: &Path) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, format!("no owner-only permissions on this target ({})", path.display())))
}

/// Open `path` for writing, created owner-only; an existing file is made owner-only too.
#[cfg(unix)]
pub fn open_private(path: &Path, mode: OpenMode) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut o = std::fs::OpenOptions::new();
    o.write(true).mode(0o600);
    match mode {
        OpenMode::Truncate => o.create(true).truncate(true),
        OpenMode::Append => o.create(true).append(true),
        OpenMode::CreateNew => o.create_new(true),
    };
    let f = o.open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(f)
}

/// Open `path` for writing, created owner-only; an existing file is made owner-only too.
#[cfg(windows)]
pub fn open_private(path: &Path, mode: OpenMode) -> io::Result<File> {
    let created = win::create_owner_only(path).map_err(|e| io::Error::new(e.kind(), format!("create {} owner-only: {e}", path.display())))?;
    if mode == OpenMode::CreateNew && !created {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", path.display())));
    }
    let mut o = std::fs::OpenOptions::new();
    match mode {
        OpenMode::Truncate => o.write(true).truncate(true),
        OpenMode::Append => o.append(true),
        OpenMode::CreateNew => o.write(true),
    };
    let f = o.open(path)?;
    if !created {
        set_private(path)?;
    }
    Ok(f)
}

#[cfg(not(any(unix, windows)))]
pub fn open_private(path: &Path, _mode: OpenMode) -> io::Result<File> {
    Err(io::Error::new(io::ErrorKind::Unsupported, format!("no owner-only files on this target ({})", path.display())))
}

/// Write `data` to `path` (create or truncate), owner-only.
pub fn write_private(path: &Path, data: impl AsRef<[u8]>) -> io::Result<()> {
    let mut f = open_private(path, OpenMode::Truncate)?;
    f.write_all(data.as_ref())?;
    f.flush()
}

/// Is `path` readable by its owner only? Unix: no group / other bits. Windows: every
/// access-allowed entry in the DACL grants to the current user, `SYSTEM` or `Administrators`
/// (the Windows counterpart of "root can always read"); a NULL DACL (everyone) is not private.
/// Elsewhere: `Unsupported` (an `Ok(true)` would be a guess).
pub fn is_private(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 == 0)
    }
    #[cfg(windows)]
    {
        win::dacl_is_owner_only(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("permission check not implemented on this OS ({})", path.display())))
    }
}

#[cfg(windows)]
pub(crate) mod win {
    //! Owner-only security descriptors (SDDL `D:P(A;…;FA;;;<user SID>)`).
    use std::io;
    use std::path::Path;
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_FILE_EXISTS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// NUL-terminated UTF-16.
    pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// The current user's SID as a string (`S-1-5-21-…`), cached.
    pub fn user_sid() -> io::Result<String> {
        static SID: OnceLock<Result<String, String>> = OnceLock::new();
        SID.get_or_init(|| query_sid().map_err(|e| e.to_string())).clone().map_err(io::Error::other)
    }

    fn query_sid() -> io::Result<String> {
        // SAFETY: token handle and buffers are owned here and sized by the first call.
        unsafe {
            let mut tok: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut len);
            // u64 words: TOKEN_USER needs pointer alignment.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len);
            let err = io::Error::last_os_error();
            CloseHandle(tok);
            if ok == 0 {
                return Err(err);
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut n = 0;
            while *s.add(n) != 0 {
                n += 1;
            }
            let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            LocalFree(s.cast());
            Ok(out)
        }
    }

    /// A self-relative security descriptor from SDDL, freed on drop.
    pub struct OwnerSd(PSECURITY_DESCRIPTOR);
    // SAFETY: immutable after construction; LocalAlloc memory is not thread-bound.
    unsafe impl Send for OwnerSd {}
    unsafe impl Sync for OwnerSd {}

    impl OwnerSd {
        /// Full control for the current user only. `inherit`: directory entries pass on to
        /// new children (OICI). `rights`: `FA` for files, `GA` for pipes.
        pub fn new(inherit: bool, rights: &str) -> io::Result<OwnerSd> {
            let sddl = format!("D:P(A;{};{rights};;;{})", if inherit { "OICI" } else { "" }, user_sid()?);
            let w = wide(&sddl);
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: valid NUL-terminated SDDL; `sd` receives a LocalAlloc'd descriptor.
            if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(OwnerSd(sd))
        }

        /// `SECURITY_ATTRIBUTES` pointing at this descriptor (valid while `self` lives).
        pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.0, bInheritHandle: 0 }
        }

        fn dacl(&self) -> io::Result<*mut ACL> {
            let (mut present, mut defaulted) = (0, 0);
            let mut acl: *mut ACL = std::ptr::null_mut();
            // SAFETY: `self.0` is a valid descriptor; out-parameters are local.
            if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0 || present == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(acl)
        }
    }

    impl Drop for OwnerSd {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }

    /// Replace the DACL of `path` with the protected owner-only one.
    pub fn apply_owner_only(path: &Path, dir: bool) -> io::Result<()> {
        let sd = OwnerSd::new(dir, "FA")?;
        let acl = sd.dacl()?;
        let w = wide(path.as_os_str());
        // SAFETY: valid path, DACL owned by `sd` for the duration of the call.
        let rc = unsafe { SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), acl, std::ptr::null()) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    /// SIDs besides the current user that may hold access without making a file "shared":
    /// LocalSystem and the built-in Administrators group (both can take ownership anyway).
    const TRUSTED_SIDS: &[&str] = &["S-1-5-18", "S-1-5-32-544"];

    /// Does the DACL of `path` grant access only to the current user (plus [`TRUSTED_SIDS`])?
    pub fn dacl_is_owner_only(path: &Path) -> io::Result<bool> {
        use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
        use windows_sys::Win32::Security::{GetAce, ACE_HEADER};
        // ACCESS_ALLOWED_ACE_TYPE; the other allow types (object / callback ACEs) carry extra
        // fields before the SID, so they are treated as "not owner-only" rather than parsed.
        const ACCESS_ALLOWED: u8 = 0;
        const ALLOW_TYPES: &[u8] = &[0, 4, 5, 9, 11];
        const INHERIT_ONLY: u8 = 0x08;
        let me = user_sid()?;
        let w = wide(path.as_os_str());
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: valid path; out-pointers are local; `sd` is LocalFree'd below.
        let rc = unsafe { GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut acl, std::ptr::null_mut(), &mut sd) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let verdict = (|| -> io::Result<bool> {
            if acl.is_null() {
                return Ok(false); // NULL DACL: full access for everyone
            }
            // SAFETY: `acl` points into `sd`, alive until LocalFree below.
            let count = unsafe { (*acl).AceCount };
            for i in 0..count as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                // SAFETY: index < AceCount.
                if unsafe { GetAce(acl, i, &mut ace) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: every ACE starts with an ACE_HEADER.
                let h = unsafe { &*(ace as *const ACE_HEADER) };
                if !ALLOW_TYPES.contains(&h.AceType) || h.AceFlags & INHERIT_ONLY != 0 {
                    continue; // deny entries and entries that only pass to children
                }
                if h.AceType != ACCESS_ALLOWED {
                    return Ok(false);
                }
                // ACCESS_ALLOWED_ACE = { ACE_HEADER (4), Mask: u32 (4), SidStart }.
                // SAFETY: the SID follows at offset 8 within AceSize bytes.
                let sid = unsafe { (ace as *mut u8).add(8) } as *mut core::ffi::c_void;
                let mut s: *mut u16 = std::ptr::null_mut();
                // SAFETY: `sid` is a valid SID inside the ACE; `s` is LocalFree'd.
                if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                let text = unsafe {
                    let mut n = 0;
                    while *s.add(n) != 0 {
                        n += 1;
                    }
                    let t = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
                    LocalFree(s.cast());
                    t
                };
                if text != me && !TRUSTED_SIDS.contains(&text.as_str()) {
                    return Ok(false);
                }
            }
            Ok(true)
        })();
        // SAFETY: allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(sd) };
        verdict
    }

    /// Create `path` with the owner-only DACL; `Ok(false)` when it already exists.
    pub fn create_owner_only(path: &Path) -> io::Result<bool> {
        let sd = OwnerSd::new(false, "FA")?;
        let sa = sd.attributes();
        let w = wide(path.as_os_str());
        // SAFETY: valid path and SECURITY_ATTRIBUTES; the handle is closed right away.
        let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0) };
        if h == INVALID_HANDLE_VALUE {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(ERROR_FILE_EXISTS as i32) { Ok(false) } else { Err(e) };
        }
        // SAFETY: fresh handle owned here.
        unsafe { CloseHandle(h) };
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_and_dirs() {
        let t = crate::tmp::TempDir::new("seagent-fs-private");
        let d = t.path().join("a/b");
        create_dir_private(&d).unwrap();
        let f = d.join("secret");
        write_private(&f, b"one").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"one");
        open_private(&f, OpenMode::Append).unwrap().write_all(b"+two").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"one+two");
        assert_eq!(open_private(&f, OpenMode::CreateNew).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        write_private(&f, b"3").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"3");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&d), 0o700);
            assert_eq!(mode(&f), 0o600);
            // an existing world-readable file is tightened
            let g = d.join("loose");
            std::fs::write(&g, "x").unwrap();
            std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!is_private(&g).unwrap());
            open_private(&g, OpenMode::Append).unwrap();
            assert_eq!(mode(&g), 0o600);
            assert!(is_private(&g).unwrap() && is_private(&d).unwrap());
        }
    }
}
