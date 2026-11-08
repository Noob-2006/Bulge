//! OS seams for the policy crate (docs/cross-platform.md).
//!
//! `seagent-security` sits below `seagent-core`, so it cannot use `seagent_core::platform`;
//! the handful of OS facts it needs live here instead. Unix keeps the exact calls the crate
//! always made (modes, `/dev/urandom`, `/proc` hostname, `getuid`); other systems get the
//! nearest native equivalent:
//!
//! | need            | unix                         | Windows                                   |
//! |-----------------|------------------------------|-------------------------------------------|
//! | file mode       | `chmod` / `mode(0o600)`       | read-only attribute; owner-only access comes from the data dir's DACL (inherited) |
//! | random bytes    | `/dev/urandom`               | `ring::rand::SystemRandom` (BCryptGenRandom) |
//! | user name / uid | `$USER` / `getuid`           | `%USERNAME%`                              |
//! | host name       | `/proc/sys/kernel/hostname` (Linux), `gethostname` | `%COMPUTERNAME%`        |

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// `chmod path mode` on unix. Elsewhere only the write bits mean anything: a mode without
/// any `w` bit sets the read-only attribute, any other mode clears it.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let mut p = std::fs::metadata(path)?.permissions();
        p.set_readonly(mode & 0o222 == 0);
        std::fs::set_permissions(path, p)
    }
}

/// Create new files with `mode` on unix (no-op elsewhere: the file inherits its directory's ACL).
pub fn with_mode(o: &mut OpenOptions, mode: u32) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        o
    }
}

/// Whether a file would run as a program. Unix: any execute bit. Windows has no execute
/// bit, so the extension decides (`PATHEXT`'s defaults).
pub fn is_executable(path: &Path, md: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = path;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        ["exe", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msc", "msi", "scr"].contains(&ext.as_str())
    }
}

/// Fill `buf` from the OS CSPRNG. Returns false when the source is unavailable (callers
/// keep their documented clock fallback).
pub fn fill_random(buf: &mut [u8]) -> bool {
    #[cfg(unix)]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).is_ok()
    }
    #[cfg(not(unix))]
    {
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), buf).is_ok()
    }
}

/// The login name of this process's user, or `uid:N` (unix) / `user` when unknown.
pub fn user_name() -> String {
    #[cfg(unix)]
    {
        // SAFETY: getuid cannot fail.
        std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| format!("uid:{}", unsafe { libc::getuid() }))
    }
    #[cfg(not(unix))]
    {
        std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into())
    }
}

/// This machine's host name (`-` when unknown, as syslog wants).
pub fn hostname() -> String {
    #[cfg(target_os = "linux")]
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    #[cfg(all(unix, not(target_os = "linux")))]
    let h = {
        let mut b = [0u8; 256];
        // SAFETY: the buffer is ours and its length is passed.
        (unsafe { libc::gethostname(b.as_mut_ptr().cast(), b.len()) } == 0).then(|| {
            let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..n]).into_owned()
        })
    };
    #[cfg(not(unix))]
    let h = std::env::var("COMPUTERNAME").ok();
    h.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "-".into())
}

/// Test helper: a file symlink where the OS allows it (Windows needs developer mode or admin,
/// so a failure there is returned, not panicked).
#[cfg(test)]
pub fn symlink(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(src, dst);
    #[cfg(windows)]
    return if src.as_ref().is_dir() { std::os::windows::fs::symlink_dir(src, dst) } else { std::os::windows::fs::symlink_file(src, dst) };
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, format!("symlink {} -> {}", dst.as_ref().display(), src.as_ref().display())));
}

/// Windows Event Log sink for the audit exporter (`eventlog://` syslog addresses): one
/// `ReportEventW` per record under the event source `source` (registered on first use by
/// the Event Log service; unregistered sources still log, with a generic message prefix).
#[cfg(windows)]
pub fn report_events(source: &str, lines: &[(u16, String)]) -> Result<(), String> {
    use windows_sys::Win32::System::EventLog::{DeregisterEventSource, RegisterEventSourceW, ReportEventW};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let src = wide(source);
    // SAFETY: a NUL-terminated wide string; NULL server = this machine.
    let h = unsafe { RegisterEventSourceW(std::ptr::null(), src.as_ptr()) };
    if h == 0 {
        return Err(format!("eventlog: RegisterEventSource({source}): {}", io::Error::last_os_error()));
    }
    let mut res = Ok(());
    for (kind, line) in lines {
        let w = wide(line);
        let strs = [w.as_ptr()];
        // SAFETY: one valid NUL-terminated string, no SID, no raw data.
        if unsafe { ReportEventW(h, *kind, 0, 1, std::ptr::null_mut(), 1, 0, strs.as_ptr(), std::ptr::null()) } == 0 {
            res = Err(format!("eventlog: ReportEvent: {}", io::Error::last_os_error()));
            break;
        }
    }
    // SAFETY: the handle came from RegisterEventSourceW.
    unsafe { DeregisterEventSource(h) };
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hostname_and_user_are_available() {
        let mut b = [0u8; 16];
        assert!(fill_random(&mut b) && b != [0u8; 16]);
        assert!(!hostname().is_empty() && !user_name().is_empty());
    }

    #[test]
    fn read_only_mode_round_trips() {
        let d = seagent_core::tmp::TempDir::new("seagent-sec-os");
        let p = d.path().join("f");
        std::fs::write(&p, "x").unwrap();
        set_mode(&p, 0o400).unwrap();
        assert!(std::fs::metadata(&p).unwrap().permissions().readonly());
        set_mode(&p, 0o600).unwrap();
        assert!(!std::fs::metadata(&p).unwrap().permissions().readonly());
    }
}
