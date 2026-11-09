//! The portable OS layer (docs/cross-platform.md, phase 1): the one place in the workspace that
//! knows how each operating system does processes, shells, private files, local IPC, terminals,
//! system facts, randomness and default directories. Every other crate calls these functions
//! instead of `libc`, `std::os::unix` or `windows-sys` directly.
//!
//! Rule one of the port: **Linux behaves exactly as before.** Each Linux code path here is the
//! code that used to live in the calling crate, moved behind `cfg(unix)` /
//! `cfg(target_os = "linux")` unchanged; other systems get their own branch, not a lowest common
//! denominator. Android is a Linux kernel but *not* `target_os = "linux"`, so kernel features
//! (PDEATHSIG, `/proc`) are gated on `any(target_os = "linux", target_os = "android")`.
//!
//! | module | Linux (unchanged) | macOS | Windows |
//! |---|---|---|---|
//! | [`proc`] | pgid, `setsid`, PDEATHSIG, `/proc` | pgid, `proc_listpgrppids` / `proc_pidinfo` | Job Object (KILL_ON_JOB_CLOSE), `CREATE_NEW_PROCESS_GROUP` |
//! | [`shell`] | `bash -c` / `bash -lc` / `sh -c` | same | Git Bash / MSYS2 bash, else `pwsh`, else Windows PowerShell |
//! | [`fs_private`] | `chmod 0600 / 0700` | same | protected owner-only DACL |
//! | [`ipc`] | unix socket | unix socket | named pipe with an owner-only DACL |
//! | [`term`] | termios, `TIOCGWINSZ`, `posix_openpt` | same | console modes, ConPTY |
//! | [`sysinfo`] | `/proc/sys/kernel/hostname`, `/proc/meminfo`, `statvfs` | `gethostname`, `sysctl hw.memsize` | `GetComputerNameExW`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW` |
//! | [`random`] | `getrandom(2)` | `getentropy` | `BCryptGenRandom` |
//! | [`layout`] | XDG / FHS (in `crate::layout`) | `~/Library/...` | `%APPDATA%` / `%LOCALAPPDATA%`, `PATHEXT` |
//!
//! File locks need nothing here: the workspace MSRV is 1.89, so `std::fs::File::lock` /
//! `try_lock` (flock on Unix, `LockFileEx` on Windows) are the portable API.
//!
//! Errors are `std::io::Error` (these are std-like primitives; callers at a boundary turn them
//! into strings). Nothing here prints.

pub mod fs_private;
pub mod ipc;
pub mod layout;
pub mod proc;
pub mod shell;
pub mod sysinfo;
pub mod term;

/// Cryptographically secure random bytes straight from the operating system (replaces the
/// scattered `/dev/urandom` reads). No user-space generator, no extra crate: on every target
/// this is the same OS source `ring::rand::SystemRandom` uses, called directly so that this
/// layer-0 crate stays free of C build scripts (cross `cargo check` needs no C toolchain).
pub mod random {
    use std::io;

    /// Fill `buf` with OS randomness. Fails only when the OS source is unavailable.
    pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
        imp(buf)
    }

    /// A random `u64`.
    pub fn random_u64() -> io::Result<u64> {
        let mut b = [0u8; 8];
        fill_random(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// `bytes` random bytes as lowercase hex (`2 * bytes` characters): tokens, nonces, ids.
    pub fn random_hex(bytes: usize) -> io::Result<String> {
        let mut b = vec![0u8; bytes];
        fill_random(&mut b)?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn imp(buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let rest = &mut buf[done..];
            // SAFETY: `rest` is a valid writable buffer of `rest.len()` bytes.
            #[cfg(target_os = "linux")]
            let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
            // Bionic only exports getrandom(3) from API 28; the app's minSdk is 26, so use the
            // syscall (Linux 3.17+, every Android 8 kernel has it).
            #[cfg(target_os = "android")]
            let n = unsafe { libc::syscall(libc::SYS_getrandom, rest.as_mut_ptr(), rest.len(), 0 as libc::c_uint) } as isize;
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Kernels before 3.17: the device node is the same pool.
                    Some(libc::ENOSYS) => return urandom(rest),
                    _ => return Err(e),
                }
            }
            done += n as usize;
        }
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    fn imp(buf: &mut [u8]) -> io::Result<()> {
        // getentropy serves at most 256 bytes per call.
        for chunk in buf.chunks_mut(256) {
            // SAFETY: `chunk` is a valid writable buffer of at most 256 bytes.
            if unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))))]
    fn imp(buf: &mut [u8]) -> io::Result<()> {
        urandom(buf)
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    fn urandom(buf: &mut [u8]) -> io::Result<()> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(buf)
    }

    #[cfg(windows)]
    fn imp(buf: &mut [u8]) -> io::Result<()> {
        use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            // SAFETY: `chunk` is a valid writable buffer; a null algorithm handle is allowed with
            // BCRYPT_USE_SYSTEM_PREFERRED_RNG.
            let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
            if status != 0 {
                return Err(io::Error::other(format!("BCryptGenRandom failed (NTSTATUS {status:#x})")));
            }
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn imp(_buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no OS random source on this target"))
    }
}

#[cfg(test)]
mod tests {
    use super::random::*;

    #[test]
    fn random_bytes_differ_and_fill_everything() {
        let mut a = [0u8; 300]; // > 256: exercises the getentropy chunking on Apple
        let mut b = [0u8; 300];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a.iter().any(|&x| x != 0));
        let h = random_hex(16).unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(random_u64().unwrap(), random_u64().unwrap());
        fill_random(&mut []).unwrap();
    }
}
