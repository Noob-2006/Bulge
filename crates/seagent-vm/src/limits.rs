//! Resource ceilings for one VM (B4: CPU, memory, disk, process count, wall
//! clock) — enforced twice, as §0 asks: the VMM gets `vcpu`/`mem`, and the
//! *guest* sets rlimits so a fork bomb inside dies before it can hurt the host.

use crate::config::VmConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub nproc: u64,
    pub nofile: u64,
    /// Total CPU seconds the whole VM may burn (0 = only per-command timeouts).
    pub cpu_seconds: u64,
    /// Guest `/tmp` tmpfs size in MB.
    pub disk_mb: u64,
    /// Wall clock for one command (0 = caller decides).
    pub exec_timeout_secs: u64,
}

impl Limits {
    pub fn from_config(cfg: &VmConfig, exec_default_timeout: u64) -> Limits {
        Limits {
            nproc: cfg.max_processes,
            nofile: cfg.max_open_files,
            cpu_seconds: cfg.cpu_seconds,
            disk_mb: if cfg.disk_mb == 0 { 256 } else { cfg.disk_mb },
            exec_timeout_secs: if cfg.exec_timeout_secs == 0 { exec_default_timeout } else { cfg.exec_timeout_secs },
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits { nproc: 512, nofile: 4096, cpu_seconds: 0, disk_mb: 256, exec_timeout_secs: 0 }
    }
}

/// Apply the guest-side ceilings. Called by the agent as PID 1 for the `agent`
/// user, so *every* command inherits them and nothing can raise them back
/// (`RLIMIT_NPROC` is per-uid, and the uid has no CAP_SYS_RESOURCE).
#[cfg(unix)]
pub fn apply_guest_limits(l: &Limits) {
    // glibc takes `__rlimit_resource_t` (u32); musl, bionic (Android) and the BSD libc of
    // macOS/iOS take `c_int`.
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    type Res = libc::__rlimit_resource_t;
    #[cfg(not(all(target_os = "linux", not(target_env = "musl"))))]
    type Res = libc::c_int;
    let set = |res: Res, v: u64| {
        if v == 0 {
            return;
        }
        let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
        // SAFETY: plain setrlimit on our own process.
        unsafe { libc::setrlimit(res, &rl) };
    };
    set(libc::RLIMIT_NPROC as Res, l.nproc);
    set(libc::RLIMIT_NOFILE as Res, l.nofile);
    set(libc::RLIMIT_CORE as Res, 0);
    set(libc::RLIMIT_FSIZE as Res, l.disk_mb.saturating_mul(1024 * 1024));
    if l.cpu_seconds > 0 {
        // Per-process ceiling; the VM-wide budget is `Watchdog`'s job.
        set(libc::RLIMIT_CPU as Res, l.cpu_seconds);
    }
}

/// Host-side wall-clock/CPU watchdog for a VM process.
#[derive(Debug, Clone, Copy)]
pub struct Watchdog {
    pub started: std::time::Instant,
    pub cpu_seconds: u64,
    pub wall_secs: u64,
}

impl Watchdog {
    pub fn new(cpu_seconds: u64, wall_secs: u64) -> Watchdog {
        Watchdog { started: std::time::Instant::now(), cpu_seconds, wall_secs }
    }
    pub fn wall_exceeded(&self) -> bool {
        self.wall_secs > 0 && self.started.elapsed().as_secs() >= self.wall_secs
    }
    /// Should this VM be killed? `(cpu_ticks, hertz)` come from `/proc`.
    pub fn cpu_exceeded(&self, cpu_ticks: u64, hertz: u64) -> bool {
        self.cpu_seconds > 0 && hertz > 0 && cpu_ticks / hertz > self.cpu_seconds
    }
}

/// CPU ticks and RSS of a process from `/proc`, without extra dependencies. Where there is no
/// `/proc` (macOS, Windows) the OS's own process accounting answers ([`crate::host::usage`]).
pub fn proc_usage(pid: u32) -> Option<(u64, u64)> {
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return crate::host::usage(pid);
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let f: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    // f[11] = utime, f[12] = stime (field 14/15 of stat, 0-based after comm)
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let rss = status.lines().find_map(|l| l.strip_prefix("VmRSS:").and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse::<u64>().ok())).unwrap_or(0);
    Some((utime + stime, rss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_limits_reach_the_guest() {
        let cfg = VmConfig { max_processes: 99, max_open_files: 1024, disk_mb: 64, exec_timeout_secs: 30, ..Default::default() };
        let l = Limits::from_config(&cfg, 120);
        assert_eq!(l.nproc, 99);
        assert_eq!(l.nofile, 1024);
        assert_eq!(l.disk_mb, 64);
        assert_eq!(l.exec_timeout_secs, 30, "an explicit exec limit wins");
        let l2 = Limits::from_config(&VmConfig::default(), 120);
        assert_eq!(l2.exec_timeout_secs, 120, "otherwise `[exec] default_timeout`");
        assert_eq!(l2.disk_mb, 256, "0 means the 256 MB tmpfs default");
    }

    #[test]
    fn watchdog_uses_wall_and_cpu_budgets() {
        let w = Watchdog::new(60, 0);
        assert!(!w.cpu_exceeded(59 * 100, 100));
        assert!(w.cpu_exceeded(61 * 100, 100));
        assert!(!w.wall_exceeded());
        let w = Watchdog::new(0, 1);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(w.wall_exceeded());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", windows))]
    fn proc_usage_reads_this_process() {
        let (ticks, rss) = proc_usage(std::process::id()).unwrap();
        assert!(ticks < 10_000_000);
        assert!(rss > 0, "our own RSS is visible");
    }
}
