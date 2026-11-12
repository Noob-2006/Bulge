//! Facts about this machine and account: host name, memory, free disk, privilege, home.
//!
//! The Linux readings are the ones the kernel / app crates used to do themselves, unchanged
//! (`/proc/sys/kernel/hostname` then `/etc/hostname`, `/proc/meminfo`, `statvfs`, `geteuid`).
//! Other systems: `gethostname` / `sysctl hw.memsize` / `sysconf` on the other Unixes, and
//! `GetComputerNameExW` / `GlobalMemoryStatusEx` / `GetDiskFreeSpaceExW` / the token's
//! elevation on Windows. Machine CPU time (for a delta-based busy share): `/proc/stat`,
//! `GetSystemTimes`, Mach `host_statistics`. "Unknown" is `None`, never a made-up number.

use std::io;
use std::path::{Path, PathBuf};

/// The host name; `"localhost"` when none can be read.
pub fn hostname() -> String {
    raw_hostname().filter(|s| !s.is_empty()).unwrap_or_else(|| "localhost".into())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn raw_hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname").or_else(|_| std::fs::read_to_string("/etc/hostname")).map(|s| s.trim().to_string()).ok()
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn raw_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` has room for 256 bytes; the result is NUL-terminated within it on success.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).trim().to_string())
}

#[cfg(windows)]
fn raw_hostname() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
    let mut n = 0u32;
    // SAFETY: the first call only reports the needed size (in UTF-16 units, NUL included).
    unsafe { GetComputerNameExW(ComputerNameDnsHostname, std::ptr::null_mut(), &mut n) };
    let mut buf = vec![0u16; n.max(1) as usize];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units.
    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) } == 0 {
        return std::env::var("COMPUTERNAME").ok();
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]).trim().to_string())
}

#[cfg(not(any(unix, windows)))]
fn raw_hostname() -> Option<String> {
    None
}

/// `/proc/meminfo` field `key` (in kB) as bytes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn meminfo(key: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb = s.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse::<u64>().ok())?;
    Some(kb * 1024)
}

/// Physical memory in bytes.
pub fn total_memory() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        meminfo("MemTotal:")
    }
    #[cfg(target_vendor = "apple")]
    {
        let mut v: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: NUL-terminated name; `v` / `len` describe a u64 out-buffer.
        let rc = unsafe { libc::sysctlbyname(c"hw.memsize".as_ptr(), (&mut v as *mut u64).cast(), &mut len, std::ptr::null_mut(), 0) };
        (rc == 0 && v > 0).then_some(v)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))))]
    {
        // SAFETY: sysconf has no preconditions.
        let (pages, size) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
        (pages > 0 && size > 0).then(|| pages as u64 * size as u64)
    }
    #[cfg(windows)]
    {
        memory_status().map(|m| m.ullTotalPhys)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Memory available to new work in bytes (`MemAvailable` on Linux, `ullAvailPhys` on Windows).
/// macOS / iOS: physical memory minus what Activity Monitor calls "Memory Used" (app memory =
/// internal minus purgeable pages, plus wired, plus compressed), from `host_statistics64`.
pub fn available_memory() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        meminfo("MemAvailable:")
    }
    #[cfg(windows)]
    {
        memory_status().map(|m| m.ullAvailPhys)
    }
    #[cfg(target_vendor = "apple")]
    {
        mach::available_memory()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows, target_vendor = "apple")))]
    {
        None
    }
}

/// Cumulative CPU time of the whole machine, all cores together, in OS-specific ticks: `busy`
/// excludes idle (and iowait) time, `total` includes it. Only differences between two readings
/// mean anything: busy% = Δbusy / Δtotal (see [`cpu_busy_pct`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuTimes {
    pub busy: u64,
    pub total: u64,
}

/// Busy share of the CPU between two [`cpu_times`] readings, 0–100; `None` when no time passed.
pub fn cpu_busy_pct(before: CpuTimes, after: CpuTimes) -> Option<f64> {
    let dt = after.total.checked_sub(before.total).filter(|d| *d > 0)?;
    Some((after.busy.saturating_sub(before.busy) as f64 * 100.0 / dt as f64).clamp(0.0, 100.0))
}

/// Parse the aggregate `cpu` line of Linux `/proc/stat` (user nice system idle iowait irq
/// softirq steal …; idle + iowait are not busy, guest time is already inside user).
pub fn parse_proc_stat(stat: &str) -> Option<CpuTimes> {
    let first = stat.lines().next()?;
    if !first.starts_with("cpu ") {
        return None;
    }
    let f: Vec<u64> = first.split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    if f.len() < 4 {
        return None;
    }
    let idle = f[3] + f.get(4).copied().unwrap_or(0);
    let total: u64 = f.iter().take(8).sum();
    Some(CpuTimes { busy: total.saturating_sub(idle), total })
}

/// The machine's cumulative [`CpuTimes`] now. Linux / Android: `/proc/stat`. Windows:
/// `GetSystemTimes` (100 ns units; kernel time includes idle). macOS / iOS:
/// `host_statistics(HOST_CPU_LOAD_INFO)` ticks. `None` when the OS refuses (Android apps since
/// 8.0 cannot read `/proc/stat`: callers fall back to [`load_average`]).
pub fn cpu_times() -> Option<CpuTimes> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        parse_proc_stat(&std::fs::read_to_string("/proc/stat").ok()?)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::FILETIME;
        let z = || FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut idle, mut kernel, mut user) = (z(), z(), z());
        // SAFETY: three valid FILETIME out-pointers.
        if unsafe { windows_sys::Win32::System::Threading::GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
            return None;
        }
        let v = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
        let total = v(kernel) + v(user);
        Some(CpuTimes { busy: total.saturating_sub(v(idle)), total })
    }
    #[cfg(target_vendor = "apple")]
    {
        mach::cpu_times()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows, target_vendor = "apple")))]
    {
        None
    }
}

/// 1, 5 and 15 minute load averages. Linux / Android: the `sysinfo(2)` syscall (allowed to
/// Android apps, unlike `/proc/loadavg`); other Unixes: `getloadavg`. Windows has no load
/// average: `None`.
pub fn load_average() -> Option<[f64; 3]> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: zeroed POD out-parameter.
        let mut s: libc::sysinfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::sysinfo(&mut s) } != 0 {
            return None;
        }
        let f = |x: libc::c_ulong| x as f64 / 65536.0;
        Some([f(s.loads[0]), f(s.loads[1]), f(s.loads[2])])
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    {
        let mut l = [0f64; 3];
        // SAFETY: `l` holds the 3 doubles asked for.
        (unsafe { libc::getloadavg(l.as_mut_ptr(), 3) } == 3).then_some(l)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Mach host statistics (macOS and iOS share the Mach kernel interface).
#[cfg(target_vendor = "apple")]
mod mach {
    use super::CpuTimes;

    const HOST_CPU_LOAD_INFO: i32 = 3;
    const HOST_VM_INFO64: i32 = 4;
    /// `sizeof(vm_statistics64_data_t) / sizeof(integer_t)`.
    const VM_INFO64_COUNT: usize = 38;

    extern "C" {
        fn mach_host_self() -> u32;
        fn host_statistics(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    }

    /// The host port, asked for once (every `mach_host_self` call adds a send right).
    fn host() -> u32 {
        static H: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        // SAFETY: no preconditions.
        *H.get_or_init(|| unsafe { mach_host_self() })
    }

    /// `host_cpu_load_info`: user, system, idle, nice ticks.
    pub fn cpu_times() -> Option<CpuTimes> {
        let mut t = [0i32; 4];
        let mut n = t.len() as u32;
        // SAFETY: `t` holds `n` integers, the size of host_cpu_load_info.
        if unsafe { host_statistics(host(), HOST_CPU_LOAD_INFO, t.as_mut_ptr(), &mut n) } != 0 {
            return None;
        }
        let [user, system, idle, nice] = t.map(|x| x as u32 as u64);
        let busy = user + system + nice;
        Some(CpuTimes { busy, total: busy + idle })
    }

    pub fn available_memory() -> Option<u64> {
        // vm_statistics64 viewed as natural_t words (u64 fields span two): free 0, active 1,
        // inactive 2, wire 3, purgeable 22, speculative 23, compressor 32, external 34,
        // internal 35.
        let mut w = [0i32; VM_INFO64_COUNT];
        let mut n = VM_INFO64_COUNT as u32;
        // SAFETY: `w` holds `n` integers, the size of vm_statistics64.
        if unsafe { host_statistics64(host(), HOST_VM_INFO64, w.as_mut_ptr(), &mut n) } != 0 {
            return None;
        }
        let g = |i: usize| w[i] as u32 as u64;
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
        let used = (g(35).saturating_sub(g(22)) + g(3) + g(32)) * page;
        let total = super::total_memory()?;
        Some(total.saturating_sub(used))
    }
}

#[cfg(windows)]
fn memory_status() -> Option<windows_sys::Win32::System::SystemInformation::MEMORYSTATUSEX> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: zeroed POD with dwLength set, as the API requires.
    unsafe {
        let mut m: MEMORYSTATUSEX = std::mem::zeroed();
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (GlobalMemoryStatusEx(&mut m) != 0).then_some(m)
    }
}

/// Space on the file system holding `path`, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    /// Free space this (unprivileged) user may use.
    pub available: u64,
    pub total: u64,
}

/// [`DiskSpace`] of the file system holding `path` (`statvfs` / `GetDiskFreeSpaceExW`).
pub fn disk_space(path: &Path) -> io::Result<DiskSpace> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: valid C string and a zeroed POD out-parameter.
        unsafe {
            let mut s: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c.as_ptr(), &mut s) != 0 {
                return Err(io::Error::last_os_error());
            }
            let frsize = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
            Ok(DiskSpace { available: s.f_bavail as u64 * frsize, total: s.f_blocks as u64 * frsize })
        }
    }
    #[cfg(windows)]
    {
        let w = super::fs_private::win::wide(path.as_os_str());
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        // SAFETY: valid NUL-terminated path and u64 out-parameters.
        if unsafe { windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(DiskSpace { available: avail, total })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(io::ErrorKind::Unsupported, "no disk statistics on this target"))
    }
}

/// Free bytes for this user on the file system holding `path`.
pub fn disk_free(path: &Path) -> io::Result<u64> {
    disk_space(path).map(|d| d.available)
}

/// Running with full privileges? Unix: effective uid 0. Windows: an elevated token.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        windows_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(windows)]
fn windows_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: token handle owned and closed here; zeroed POD out-parameter.
    unsafe {
        let mut tok = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e: TOKEN_ELEVATION = std::mem::zeroed();
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, (&mut e as *mut TOKEN_ELEVATION).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len);
        CloseHandle(tok);
        ok != 0 && e.TokenIsElevated != 0
    }
}

/// Effective uid on Unix; `None` on systems without uids (Windows).
pub fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The account name (`$USER` / `$LOGNAME`, else the passwd entry on Unix; `%USERNAME%` on
/// Windows); `"user"` when nothing is known.
pub fn current_user() -> String {
    let env = ["USER", "LOGNAME", "USERNAME"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    env.or_else(passwd_name).unwrap_or_else(|| "user".into())
}

#[cfg(unix)]
fn passwd_name() -> Option<String> {
    use std::ffi::CStr;
    let mut buf = vec![0u8; 4096];
    // SAFETY: zeroed POD out-parameters and a buffer of `buf.len()` bytes.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(libc::geteuid(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut out);
        if rc != 0 || out.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned())
    }
}

#[cfg(not(unix))]
fn passwd_name() -> Option<String> {
    None
}

/// The home directory: `$HOME`, else (Windows) `%USERPROFILE%`, else the passwd entry, else
/// the temp dir. Same as `crate::layout::home`.
pub fn home_dir() -> PathBuf {
    crate::layout::home()
}

/// The kernel release (`uname -r`; `/proc/sys/kernel/osrelease` on Linux); `None` on Windows.
pub fn kernel_release() -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    // SAFETY: zeroed POD out-parameter; the release field is NUL-terminated.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy().into_owned())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_facts_are_sane() {
        let h = hostname();
        assert!(!h.is_empty() && !h.contains('\n'));
        let total = total_memory().expect("total memory on a test host");
        assert!(total > 64 * 1024 * 1024);
        if let Some(a) = available_memory() {
            assert!(a <= total);
        }
        let scratch = crate::tmp::TempDir::new("seagent-core-tmp-sysinfo");
        let d = disk_space(scratch.path()).unwrap();
        assert!(d.total > 0 && d.available <= d.total);
        assert_eq!(disk_free(scratch.path()).unwrap() > 0, d.available > 0);
        assert!(disk_space(Path::new("/definitely/not/here")).is_err());
        assert!(!current_user().is_empty());
        assert!(home_dir().is_absolute());
        #[cfg(unix)]
        {
            assert_eq!(is_root(), current_uid() == Some(0));
            assert!(kernel_release().is_some());
        }
    }

    /// The status bar's CPU / memory readings are real on every host OS: CPU time advances
    /// while a thread spins, so the delta-based busy share is above 0 (the Windows sampler
    /// used to read `/proc/stat` and always showed 0.0%), and memory in use is a real share.
    #[test]
    fn cpu_and_memory_readings_are_live() {
        let a = cpu_times().expect("machine CPU times on a test host");
        let until = std::time::Instant::now() + std::time::Duration::from_millis(400);
        let mut x = 0u64;
        while std::time::Instant::now() < until {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
        }
        let b = cpu_times().unwrap();
        assert!(b.total > a.total && b.busy > a.busy, "{a:?} -> {b:?}");
        let pct = cpu_busy_pct(a, b).unwrap();
        assert!(pct > 0.0 && pct <= 100.0, "{pct}");
        assert_eq!(cpu_busy_pct(b, b), None);
        let total = total_memory().unwrap();
        let avail = available_memory().expect("available memory on a test host");
        assert!(avail > 0 && avail < total, "{avail} of {total}");
        #[cfg(unix)]
        assert!(load_average().is_some_and(|l| l.iter().all(|v| *v >= 0.0)));
    }

    #[test]
    fn proc_stat_and_busy_share() {
        let t = parse_proc_stat("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        assert_eq!((t.busy, t.total), (150, 1000));
        assert_eq!(parse_proc_stat("intr 1 2 3 4 5\n"), None);
        let later = CpuTimes { busy: 200, total: 1100 };
        assert_eq!(cpu_busy_pct(t, later), Some(50.0));
        assert_eq!(cpu_busy_pct(later, t), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_hostname_is_the_kernel_one() {
        let k = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
        assert_eq!(hostname(), k.trim());
    }
}
