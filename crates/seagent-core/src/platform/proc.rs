//! Process groups that stop as one unit, and children that die with seagent.
//!
//! A "group" is named by its leader's pid everywhere (`pgid` on Unix), so callers that record
//! pids in registries keep working on every OS:
//!
//! * **Linux / Android** — the code that used to live in `crate::proc`, unchanged: the child
//!   leads its own process group (`setsid` / `setpgid`), gets `PR_SET_PDEATHSIG`, and group
//!   membership / zombie state come from `/proc`.
//! * **macOS** — same process groups and signals; members and zombie state come from
//!   `proc_listpgrppids` / `proc_pidinfo` (there is no `/proc`, which used to make
//!   [`group_members`] empty and [`kill_group`] skip the grace period). The kernel has no
//!   parent-death signal: by default a tied child outlives a `SIGKILL`ed seagent (a clean exit
//!   or a [`kill_group`] still stops it). Opt-in substitute (`SEAGENT_MACOS_WATCHDOG=1`, see
//!   [`set_parent_watchdog`]): every child passed to [`spawn_in_group`] / [`adopt`] gets a
//!   tiny watchdog process (`seagent __watch-parent`, its own session) that waits on kqueue
//!   `EVFILT_PROC NOTE_EXIT` for seagent and for the child, and when seagent goes first
//!   `SIGTERM`s the child's group, then `SIGKILL`s it after 2 s.
//! * **Windows** — every group is a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, kept
//!   in a process-wide registry keyed by the leader pid: when seagent exits, however it exits,
//!   the kernel closes the job handle and kills the whole tree (the Windows form of PDEATHSIG).
//!   The child is started with `CREATE_NEW_PROCESS_GROUP` so [`kill_group`] can send
//!   `CTRL_BREAK` first and `TerminateJobObject` after the grace period.
//!
//! [`start_time`] is an opaque per-OS token (Linux: clock ticks since boot, `/proc/<pid>/stat`
//! field 22; macOS: microseconds since the epoch; Windows: creation FILETIME) used to tell a
//! recycled pid from the process that was recorded.

use std::io;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Signal delivered to a tied child when seagent dies (Linux / Android). `SIGTERM` lets Chrome
/// close its profile and take its helpers down; the guards escalate to `SIGKILL` themselves.
#[cfg(unix)]
pub const DEATH_SIGNAL: i32 = libc::SIGTERM;

// ───────────────────────── spawning ─────────────────────────

/// Spawn `cmd` as the leader of its own group, tied to this process (the caller is
/// `crate::proc::spawn_tied`, which runs this on a process-lifetime thread because PDEATHSIG
/// fires when the *forking thread* exits).
///
/// Unix: `setsid` when `own_session`, else `setpgid(0, 0)`, plus PDEATHSIG on Linux / Android.
/// Windows: `CREATE_NEW_PROCESS_GROUP` and a kill-on-close Job Object ([`adopt`]).
#[cfg(unix)]
pub fn spawn_in_group(cmd: &mut Command, own_session: bool) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if own_session {
                libc::setsid();
            } else {
                libc::setpgid(0, 0);
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                libc::prctl(libc::PR_SET_PDEATHSIG, DEATH_SIGNAL as libc::c_ulong);
                // The parent may already be gone (it died between fork and prctl).
                if libc::getppid() != parent {
                    libc::_exit(137);
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let _ = parent;
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    #[cfg(target_os = "macos")]
    mac::watch(child.id() as i32);
    Ok(child)
}

/// See the Unix variant. A child that cannot be put in its job is killed again and the error
/// returned: an untracked child would silently lose the die-with-seagent guarantee.
#[cfg(windows)]
pub fn spawn_in_group(cmd: &mut Command, own_session: bool) -> io::Result<Child> {
    spawn_in_group_with(cmd, own_session, 0)
}

/// A log file to hand to a child as stdout / stderr, appending. Unix: `O_APPEND`, as always.
/// Windows: write access positioned at the end instead of an append-only handle — MSYS /
/// Cygwin programs (Git Bash and everything it runs) exit 1 at startup when their stdout
/// lacks `FILE_WRITE_DATA`.
pub fn open_child_log(p: &std::path::Path) -> io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::io::Seek;
        let mut f = std::fs::OpenOptions::new().create(true).write(true).open(p)?;
        f.seek(std::io::SeekFrom::End(0))?;
        Ok(f)
    }
    #[cfg(not(windows))]
    {
        std::fs::OpenOptions::new().create(true).append(true).open(p)
    }
}

/// [`spawn_in_group`] with extra Windows creation flags (see [`new_group_with`]); the flags are
/// ignored on Unix.
pub fn spawn_in_group_with(cmd: &mut Command, own_session: bool, windows_flags: u32) -> io::Result<Child> {
    #[cfg(unix)]
    {
        let _ = windows_flags;
        spawn_in_group(cmd, own_session)
    }
    #[cfg(windows)]
    {
        new_group_with(cmd, own_session, windows_flags);
        let mut child = cmd.spawn()?;
        if let Err(e) = adopt(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", child.id())));
        }
        Ok(child)
    }
}

/// Windows `CREATE_NO_WINDOW`, for [`new_group_with`] / [`spawn_in_group_with`]: the child
/// gets a console that is never shown. Ignored on Unix.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The extra creation flags a child of *this* process needs: [`CREATE_NO_WINDOW`] on Windows
/// when we have no console of our own (the daemon, a GUI host) — a console program started
/// from there would otherwise pop up a new console window — and 0 when we have one (the child
/// shares it, so `CTRL_BREAK` still reaches its group), and always 0 on Unix.
pub fn console_flags() -> u32 {
    #[cfg(windows)]
    {
        // SAFETY: plain call; 0 means "no console attached".
        if unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() } == 0 {
            return CREATE_NO_WINDOW;
        }
        0
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Only the "new group" half of [`spawn_in_group`], for callers that spawn themselves.
/// Unix: `setsid` / `setpgid(0, 0)` in the child. Windows: `CREATE_NEW_PROCESS_GROUP` (this
/// replaces any creation flags set before); call [`adopt`] after the spawn.
pub fn new_group(cmd: &mut Command, own_session: bool) {
    new_group_with(cmd, own_session, 0)
}

/// [`new_group`] plus extra Windows creation flags (e.g. [`CREATE_NO_WINDOW`], or
/// [`console_flags`]), OR-ed with `CREATE_NEW_PROCESS_GROUP`. `windows_flags` is ignored on
/// Unix, so callers need no `cfg`.
pub fn new_group_with(cmd: &mut Command, own_session: bool, windows_flags: u32) {
    #[cfg(unix)]
    {
        let _ = windows_flags;
        use std::os::unix::process::CommandExt;
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if own_session {
                    libc::setsid();
                } else {
                    libc::setpgid(0, 0);
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = own_session;
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP | windows_flags);
    }
}

/// Only the "die with seagent" half: PDEATHSIG on Linux / Android (spawn from a long-lived
/// thread, see [`spawn_in_group`]). No-op on macOS (no kernel support) and on Windows, where
/// [`adopt`] after the spawn gives the same guarantee.
pub fn die_with_parent(cmd: &mut Command) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                libc::prctl(libc::PR_SET_PDEATHSIG, DEATH_SIGNAL as libc::c_ulong);
                if libc::getppid() != parent {
                    libc::_exit(137);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = cmd;
}

/// Put an already spawned child (and everything it starts later) in a kill-on-close Job
/// Object registered under its pid, so [`kill_group`] / [`group_members`] see the whole tree
/// and the tree dies with seagent. Unix: no-op (the process group already is the unit), except
/// that macOS arms the opt-in parent watchdog (see the module docs).
pub fn adopt(child: &Child) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::adopt(child)
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "macos")]
        mac::watch(child.id() as i32);
        let _ = child;
        Ok(())
    }
}

/// [`adopt`] for a process started outside `std::process` (raw `CreateProcessW`): `process`
/// is its handle (needs `PROCESS_SET_QUOTA | PROCESS_TERMINATE`), `pid` its id. It is put in a
/// new kill-on-close job registered under `pid`. A process that is already in a job of its
/// own should use [`adopt_job`] instead.
#[cfg(windows)]
pub fn adopt_handle(process: std::os::windows::io::RawHandle, pid: u32) -> io::Result<()> {
    win::adopt_handle(process as windows_sys::Win32::Foundation::HANDLE, pid)
}

/// Register a Job Object the caller built itself (e.g. one with UI restrictions) as the group
/// led by `pid`, so [`kill_group`] / [`group_members`] — the kernel reaper included — act on
/// the whole tree. The handle is duplicated: the caller keeps (and closes) its own.
#[cfg(windows)]
pub fn adopt_job(job: std::os::windows::io::RawHandle, pid: u32) -> io::Result<()> {
    win::adopt_job(job as windows_sys::Win32::Foundation::HANDLE, pid)
}

/// `CTRL_BREAK_EVENT` to the console process group led by `pid`. False when it cannot be
/// delivered (no shared console).
#[cfg(windows)]
pub fn ctrl_break(pid: u32) -> bool {
    win::ctrl_break(pid)
}

/// The parent pid of `pid`, `None` when it is gone (or, on iOS / BSDs, for any process but
/// our own). Linux / Android: `/proc/<pid>/stat`; macOS: `proc_pidinfo`; Windows: a Toolhelp
/// snapshot (the parent may have exited since: Windows does not reparent).
pub fn parent_pid(pid: i32) -> Option<i32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // Fields after `comm`: state ppid ...
        s.rsplit(')').next()?.split_whitespace().nth(1)?.parse().ok()
    }
    #[cfg(target_os = "macos")]
    {
        mac::bsdinfo(pid).map(|i| i.pbi_ppid as i32)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_os = "macos"))))]
    {
        (pid as u32 == std::process::id()).then(|| unsafe { libc::getppid() })
    }
    #[cfg(windows)]
    {
        if pid <= 0 {
            return None;
        }
        win::parent_pid(pid as u32).map(|p| p as i32)
    }
}

/// The hidden command word of the macOS parent watchdog (`seagent __watch-parent <ppid>
/// <pid> <start>`).
pub const WATCH_PARENT_CMD: &str = "__watch-parent";
/// Opt-in switch for the macOS parent watchdog: `1` arms it.
pub const WATCHDOG_ENV: &str = "SEAGENT_MACOS_WATCHDOG";

/// Name the executable that serves [`WATCH_PARENT_CMD`] (the `seagent` binary calls this at
/// start-up). macOS only, and only when `SEAGENT_MACOS_WATCHDOG=1`: from then on every child
/// passed to [`spawn_in_group`] / [`adopt`] gets a watchdog. Returns whether it is armed.
/// Elsewhere a no-op returning false (Linux / Android have PDEATHSIG, Windows kill-on-close
/// jobs, iOS spawns nothing).
pub fn set_parent_watchdog(exe: std::path::PathBuf) -> bool {
    #[cfg(target_os = "macos")]
    {
        if std::env::var(WATCHDOG_ENV).as_deref() != Ok("1") {
            return false;
        }
        let _ = mac::WATCHDOG.set(exe);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = exe;
        false
    }
}

/// Body of `seagent __watch-parent <ppid> <pid> <start>` (macOS): wait until either process
/// exits; if the parent went first, `SIGTERM` the child's group (or the child, when it leads
/// none), then `SIGKILL` it after 2 s. Returns the exit code.
#[cfg(target_os = "macos")]
pub fn run_parent_watchdog(argv: &[String]) -> i32 {
    mac::run_watchdog(argv)
}

// ───────────────────────── inspecting ─────────────────────────

/// Is `pid` alive (and not a zombie)?
#[cfg(unix)]
pub fn alive(pid: i32) -> bool {
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    !zombie(pid)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn zombie(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
}

#[cfg(target_os = "macos")]
fn zombie(pid: i32) -> bool {
    mac::bsdinfo(pid).is_some_and(|i| i.pbi_status == libc::SZOMB)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_os = "macos"))))]
fn zombie(_pid: i32) -> bool {
    false
}

/// Is any process still in group `pgid`?
#[cfg(unix)]
pub fn group_alive(pgid: i32) -> bool {
    pgid > 1 && unsafe { libc::kill(-pgid, 0) } == 0 && !group_members(pgid).is_empty()
}

/// Live (non-zombie) members of process group `pgid`, read from `/proc`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn group_members(pgid: i32) -> Vec<i32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return vec![] };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
            // Fields after `comm`: state ppid pgrp ...
            let mut f = s.rsplit(')').next().unwrap_or("").split_whitespace();
            let state = f.next().unwrap_or("Z");
            let _ppid = f.next();
            state != "Z" && f.next().and_then(|g| g.parse::<i32>().ok()) == Some(pgid)
        })
        .collect()
}

/// Live (non-zombie) members of process group `pgid` (`proc_listpgrppids`).
#[cfg(target_os = "macos")]
pub fn group_members(pgid: i32) -> Vec<i32> {
    mac::pgrp_pids(pgid).into_iter().filter(|&p| p > 0 && !zombie(p)).collect()
}

/// Without a process table API the group is reported by its leader id while
/// `kill(-pgid, 0)` still reaches someone (iOS, BSDs).
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_os = "macos"))))]
pub fn group_members(pgid: i32) -> Vec<i32> {
    if pgid > 1 && unsafe { libc::kill(-pgid, 0) } == 0 {
        vec![pgid]
    } else {
        vec![]
    }
}

/// `SIGTERM` the group, wait up to `grace`, then `SIGKILL` it. Never signals pgid 0/1 or our
/// own group.
#[cfg(unix)]
pub fn kill_group(pgid: i32, grace: Duration) {
    if pgid <= 1 || pgid == unsafe { libc::getpgrp() } {
        return;
    }
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    let until = Instant::now() + grace;
    while Instant::now() < until && group_alive(pgid) {
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

/// Send `sig` to every process of group `pgid` (no grace logic). Same guards as
/// [`kill_group`]. Unix only: Windows has no signals (use [`kill_group`]).
#[cfg(unix)]
pub fn signal_group(pgid: i32, sig: i32) -> io::Result<()> {
    if pgid <= 1 || pgid == unsafe { libc::getpgrp() } {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("refusing to signal process group {pgid}")));
    }
    if unsafe { libc::kill(-pgid, sig) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The group id of this process (`getpgrp`; on Windows our own pid).
pub fn own_group() -> i32 {
    #[cfg(unix)]
    {
        unsafe { libc::getpgrp() }
    }
    #[cfg(not(unix))]
    {
        std::process::id() as i32
    }
}

/// Start time of `pid` as an opaque token (see the module docs), `None` when it is gone.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn start_time(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = s.get(s.rfind(')')? + 2..)?;
    after.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "macos")]
pub fn start_time(pid: i32) -> Option<u64> {
    mac::bsdinfo(pid).map(|i| i.pbi_start_tvsec * 1_000_000 + i.pbi_start_tvusec)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_os = "macos"))))]
pub fn start_time(_pid: i32) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
mod mac {
    /// `proc_pidinfo(PROC_PIDTBSDINFO)`: state, pgid and start time of one process.
    pub fn bsdinfo(pid: i32) -> Option<libc::proc_bsdinfo> {
        if pid <= 0 {
            return None;
        }
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: zeroed POD out-parameter of exactly `size` bytes.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
        (n == size).then_some(info)
    }

    /// Pids of process group `pgid` (may include zombies).
    pub fn pgrp_pids(pgid: i32) -> Vec<i32> {
        if pgid <= 1 {
            return vec![];
        }
        // SAFETY: a null buffer asks for the size in bytes.
        let need = unsafe { libc::proc_listpgrppids(pgid, std::ptr::null_mut(), 0) };
        if need <= 0 {
            return vec![];
        }
        let mut buf = vec![0 as libc::pid_t; need as usize / std::mem::size_of::<libc::pid_t>() + 16];
        let bytes = (buf.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: `buf` holds `bytes` writable bytes.
        let got = unsafe { libc::proc_listpgrppids(pgid, buf.as_mut_ptr().cast(), bytes) };
        if got <= 0 {
            return vec![];
        }
        buf.truncate(got as usize / std::mem::size_of::<libc::pid_t>());
        buf
    }

    // ───── the opt-in parent watchdog (see the module docs) ─────

    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    /// The executable serving `__watch-parent`; set only when the watchdog is opted in.
    pub static WATCHDOG: OnceLock<PathBuf> = OnceLock::new();

    /// Start a watchdog for child `pid` (no-op unless armed). Best-effort: a watchdog that
    /// cannot start leaves the child exactly as it was without one.
    pub fn watch(pid: i32) {
        let Some(exe) = WATCHDOG.get() else { return };
        let Some(start) = super::start_time(pid) else { return };
        let mut c = Command::new(exe);
        c.arg(super::WATCH_PARENT_CMD).arg(std::process::id().to_string()).arg(pid.to_string()).arg(start.to_string());
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        // Its own session: a kill_group of the child, or ^C in our terminal, never reaches it.
        use std::os::unix::process::CommandExt;
        // SAFETY: only async-signal-safe libc calls between fork and exec.
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        if let Ok(w) = c.spawn() {
            reap_later(w);
        }
    }

    /// Watchdogs are our children: one thread reaps the ones that finished.
    fn reap_later(w: Child) {
        static Q: OnceLock<Mutex<Vec<Child>>> = OnceLock::new();
        let mut started = false;
        let q = Q.get_or_init(|| {
            started = true;
            Mutex::new(Vec::new())
        });
        q.lock().unwrap_or_else(|e| e.into_inner()).push(w);
        if started {
            let _ = std::thread::Builder::new().name("seagent-watchdog-reaper".into()).stack_size(64 * 1024).spawn(move || loop {
                std::thread::sleep(Duration::from_secs(2));
                q.lock().unwrap_or_else(|e| e.into_inner()).retain_mut(|c| matches!(c.try_wait(), Ok(None)));
            });
        }
    }

    fn proc_event(pid: i32) -> libc::kevent {
        libc::kevent { ident: pid as libc::uintptr_t, filter: libc::EVFILT_PROC, flags: libc::EV_ADD | libc::EV_ONESHOT | libc::EV_RECEIPT, fflags: libc::NOTE_EXIT, data: 0, udata: std::ptr::null_mut() }
    }

    pub fn run_watchdog(argv: &[String]) -> i32 {
        let num = |i: usize| argv.get(i).and_then(|s| s.parse::<i64>().ok());
        let (Some(ppid), Some(pid), Some(start)) = (num(0), num(1), num(2)) else {
            eprintln!("usage: seagent {} <ppid> <pid> <start>", super::WATCH_PARENT_CMD);
            return 2;
        };
        let (ppid, pid, start) = (ppid as i32, pid as i32, start as u64);
        if pid <= 1 || ppid <= 1 {
            return 2;
        }
        // SAFETY: kqueue / kevent on our own descriptor with stack-allocated event arrays of
        // the sizes we pass.
        let parent_gone = unsafe {
            let kq = libc::kqueue();
            if kq < 0 {
                return 1;
            }
            let changes = [proc_event(ppid), proc_event(pid)];
            let mut out: [libc::kevent; 2] = std::mem::zeroed();
            let n = libc::kevent(kq, changes.as_ptr(), 2, out.as_mut_ptr(), 2, std::ptr::null());
            let mut parent_gone = false;
            for e in out.iter().take(n.max(0) as usize) {
                if e.flags & libc::EV_ERROR != 0 && e.data != 0 {
                    if e.ident == ppid as libc::uintptr_t {
                        parent_gone = true; // ESRCH: seagent already exited
                    } else {
                        libc::close(kq);
                        return 0; // the child already exited
                    }
                }
            }
            // Registered first, checked second: if seagent died before the registration we
            // were reparented to launchd and see it here.
            if libc::getppid() != ppid {
                parent_gone = true;
            }
            if super::start_time(pid) != Some(start) {
                libc::close(kq);
                return 0; // the pid is no longer the child we were started for
            }
            while !parent_gone {
                let mut ev: libc::kevent = std::mem::zeroed();
                let n = libc::kevent(kq, std::ptr::null(), 0, &mut ev, 1, std::ptr::null());
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if n == 1 && ev.filter == libc::EVFILT_PROC {
                    if ev.ident == pid as libc::uintptr_t {
                        break; // the child went first: nothing to do
                    }
                    parent_gone = ev.ident == ppid as libc::uintptr_t;
                }
            }
            libc::close(kq);
            parent_gone
        };
        if parent_gone && super::start_time(pid) == Some(start) {
            // SAFETY: plain signal syscalls; the target was re-checked to be our child.
            unsafe {
                let group = libc::getpgid(pid) == pid;
                let target = if group { -pid } else { pid };
                let running = || if group { super::group_alive(pid) } else { super::alive(pid) };
                libc::kill(target, libc::SIGTERM);
                let until = Instant::now() + Duration::from_secs(2);
                while Instant::now() < until && running() {
                    std::thread::sleep(Duration::from_millis(50));
                }
                libc::kill(target, libc::SIGKILL);
            }
        }
        0
    }
}

// ───────────────────────── Windows ─────────────────────────

/// Is `pid` running? (`OpenProcess` + `GetExitCodeProcess`; a process of another account that
/// denies us access counts as alive.)
#[cfg(windows)]
pub fn alive(pid: i32) -> bool {
    pid > 0 && win::alive(pid as u32)
}

/// Is any process left in the group led by `pgid` (its job, or the process itself)?
#[cfg(windows)]
pub fn group_alive(pgid: i32) -> bool {
    !group_members(pgid).is_empty()
}

/// Live members of the group led by `pgid`: the processes in its Job Object, or just the
/// process itself when it was not started through [`spawn_in_group`] / [`adopt`].
#[cfg(windows)]
pub fn group_members(pgid: i32) -> Vec<i32> {
    if pgid <= 0 {
        return vec![];
    }
    match win::job_members(pgid) {
        Some(m) => m,
        None if alive(pgid) => vec![pgid],
        None => vec![],
    }
}

/// `CTRL_BREAK` the group (when we created it), wait up to `grace`, then `TerminateJobObject`
/// (or `TerminateProcess` for a process that has no job). Never touches our own process.
#[cfg(windows)]
pub fn kill_group(pgid: i32, grace: Duration) {
    if pgid <= 0 || pgid as u32 == std::process::id() {
        return;
    }
    if win::has_job(pgid) && win::ctrl_break(pgid as u32) {
        let until = Instant::now() + grace;
        while Instant::now() < until && group_alive(pgid) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    win::terminate(pgid);
}

/// Every live descendant of `pid` (children, grandchildren, …), not `pid` itself. Windows: a
/// Toolhelp snapshot, where a recycled parent pid is told apart by creation time (a real child
/// starts no earlier than its parent); Linux / Android: `/proc/*/stat` ppid; macOS: `ps`.
/// Other targets: empty.
pub fn descendants(pid: i32) -> Vec<i32> {
    if pid <= 0 {
        return vec![];
    }
    #[cfg(windows)]
    let pairs = win::process_pairs();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let pairs: Vec<(i32, i32, u64)> = std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
                .filter_map(|p| {
                    let s = std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?;
                    let mut f = s.rsplit(')').next()?.split_whitespace();
                    let state = f.next()?;
                    (state != "Z").then_some(())?;
                    Some((p, f.next()?.parse().ok()?, 0))
                })
                .collect()
        })
        .unwrap_or_default();
    #[cfg(target_os = "macos")]
    let pairs: Vec<(i32, i32, u64)> = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid="])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| {
                    let mut w = l.split_whitespace();
                    Some((w.next()?.parse().ok()?, w.next()?.parse().ok()?, 0))
                })
                .collect()
        })
        .unwrap_or_default();
    #[cfg(not(any(windows, target_os = "linux", target_os = "android", target_os = "macos")))]
    let pairs: Vec<(i32, i32, u64)> = vec![];
    tree_below(pid, &pairs)
}

/// The descendants of `root` in a `(pid, ppid, creation time)` table (creation time 0 =
/// unknown, never used to reject). Pure, so the walk is unit-tested on every target.
pub fn tree_below(root: i32, pairs: &[(i32, i32, u64)]) -> Vec<i32> {
    let born = |p: i32| pairs.iter().find(|(q, _, _)| *q == p).map(|(_, _, t)| *t).unwrap_or(0);
    let mut out: Vec<i32> = vec![];
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        let pt = born(parent);
        for &(p, pp, t) in pairs {
            // A child is never older than its parent: an older "child" names a recycled pid.
            if pp == parent && p != root && !out.contains(&p) && (pt == 0 || t == 0 || t >= pt) {
                out.push(p);
                frontier.push(p);
            }
        }
    }
    out
}

/// Windows: end `pid` and every descendant (a launcher such as Git's `bin\sh.exe` hands its
/// real work to a child, so ending only `pid` would leave that child running). A process with
/// a registered job goes through [`kill_group`]. Never touches our own process.
#[cfg(windows)]
pub fn kill_tree(pid: i32) {
    if pid <= 0 || pid as u32 == std::process::id() {
        return;
    }
    let below = descendants(pid);
    kill_group(pid, Duration::ZERO);
    for p in below {
        if p as u32 != std::process::id() {
            win::terminate(p);
        }
    }
}

#[cfg(windows)]
pub fn start_time(pid: i32) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    win::creation_time(pid as u32)
}

#[cfg(windows)]
pub(crate) mod win {
    use std::collections::HashMap;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::sync::{Mutex, OnceLock};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, FILETIME, HANDLE, STILL_ACTIVE};
    use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, GetProcessTimes, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

    /// An owned job handle. Closing it kills every process in the job (KILL_ON_JOB_CLOSE).
    struct Job(HANDLE);
    // SAFETY: a kernel handle is usable from any thread.
    unsafe impl Send for Job {}
    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn jobs() -> &'static Mutex<HashMap<i32, Job>> {
        static JOBS: OnceLock<Mutex<HashMap<i32, Job>>> = OnceLock::new();
        JOBS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    struct Proc(HANDLE);
    impl Drop for Proc {
        fn drop(&mut self) {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
    fn open(pid: u32, access: u32) -> Option<Proc> {
        // SAFETY: plain call; a zero handle means failure.
        let h = unsafe { OpenProcess(access, 0, pid) };
        (h != 0).then_some(Proc(h))
    }

    pub fn adopt(child: &Child) -> io::Result<()> {
        adopt_handle(child.as_raw_handle() as HANDLE, child.id())
    }

    /// Put the process `process` (pid `pid`) in a new kill-on-close job registered under `pid`.
    pub fn adopt_handle(process: HANDLE, pid: u32) -> io::Result<()> {
        // SAFETY: plain calls on handles we own; `info` outlives SetInformationJobObject.
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h == 0 {
                return Err(io::Error::last_os_error());
            }
            let job = Job(h);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) == 0 {
                return Err(io::Error::last_os_error());
            }
            if AssignProcessToJobObject(job.0, process) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut m = jobs().lock().unwrap_or_else(|e| e.into_inner());
            // Forget jobs whose processes are all gone (closing an empty job kills nothing).
            m.retain(|_, j| active(j.0) > 0);
            m.insert(pid as i32, job);
        }
        Ok(())
    }

    /// Register a duplicate of the caller's `job` under `pid` (the caller keeps its handle).
    pub fn adopt_job(job: HANDLE, pid: u32) -> io::Result<()> {
        use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut dup: HANDLE = 0;
        // SAFETY: duplicating a handle the caller owns into our own process.
        if unsafe { DuplicateHandle(GetCurrentProcess(), job, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let job = Job(dup);
        let mut m = jobs().lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, j| active(j.0) > 0);
        m.insert(pid as i32, job);
        Ok(())
    }

    /// The parent pid from a Toolhelp snapshot.
    pub fn parent_pid(pid: u32) -> Option<u32> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
        // SAFETY: snapshot handle owned and closed here; `e` is a POD with dwSize set.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = None;
            let mut ok = Process32FirstW(snap, &mut e);
            while ok != 0 {
                if e.th32ProcessID == pid {
                    found = Some(e.th32ParentProcessID);
                    break;
                }
                ok = Process32NextW(snap, &mut e);
            }
            CloseHandle(snap);
            found
        }
    }

    /// `(pid, parent pid, creation time)` of every process in a Toolhelp snapshot (creation
    /// time 0 when the process cannot be opened).
    pub fn process_pairs() -> Vec<(i32, i32, u64)> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
        let mut raw: Vec<(u32, u32)> = vec![];
        // SAFETY: snapshot handle owned and closed here; `e` is a POD with dwSize set.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return vec![];
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut e);
            while ok != 0 {
                raw.push((e.th32ProcessID, e.th32ParentProcessID));
                ok = Process32NextW(snap, &mut e);
            }
            CloseHandle(snap);
        }
        raw.into_iter().filter(|(p, _)| *p != 0).map(|(p, pp)| (p as i32, pp as i32, creation_time(p).unwrap_or(0))).collect()
    }

    fn active(job: HANDLE) -> u32 {
        // SAFETY: zeroed POD out-parameter of the size we pass.
        unsafe {
            let mut a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
            let ok = QueryInformationJobObject(job, JobObjectBasicAccountingInformation, (&mut a as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32, std::ptr::null_mut());
            if ok == 0 {
                0
            } else {
                a.ActiveProcesses
            }
        }
    }

    pub fn has_job(pgid: i32) -> bool {
        jobs().lock().unwrap_or_else(|e| e.into_inner()).contains_key(&pgid)
    }

    /// Pids in the job led by `pgid`; `None` when we hold no job for it.
    pub fn job_members(pgid: i32) -> Option<Vec<i32>> {
        #[repr(C)]
        struct List {
            assigned: u32,
            listed: u32,
            ids: [usize; 1024],
        }
        let m = jobs().lock().unwrap_or_else(|e| e.into_inner());
        let job = m.get(&pgid)?;
        let mut l = List { assigned: 0, listed: 0, ids: [0; 1024] };
        // SAFETY: `l` has the JOBOBJECT_BASIC_PROCESS_ID_LIST layout with room for 1024 ids. A
        // bigger job reports ERROR_MORE_DATA and still fills what fits.
        let ok = unsafe { QueryInformationJobObject(job.0, JobObjectBasicProcessIdList, (&mut l as *mut List).cast(), std::mem::size_of::<List>() as u32, std::ptr::null_mut()) };
        if ok == 0 && l.listed == 0 {
            return Some(vec![]);
        }
        Some(l.ids[..(l.listed as usize).min(1024)].iter().map(|&p| p as i32).collect())
    }

    /// `CTRL_BREAK_EVENT` to the console process group `pid` leads. False when it cannot be
    /// delivered (no shared console): the caller then terminates at once.
    pub fn ctrl_break(pid: u32) -> bool {
        // SAFETY: plain call.
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0 }
    }

    pub fn terminate(pgid: i32) {
        let job = jobs().lock().unwrap_or_else(|e| e.into_inner()).remove(&pgid);
        match job {
            // SAFETY: we own the job handle; dropping it afterwards closes it.
            Some(j) => unsafe {
                TerminateJobObject(j.0, 1);
            },
            None => {
                if let Some(p) = open(pgid as u32, PROCESS_TERMINATE) {
                    // SAFETY: handle opened with PROCESS_TERMINATE.
                    unsafe { TerminateProcess(p.0, 1) };
                }
            }
        }
    }

    pub fn alive(pid: u32) -> bool {
        let Some(p) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            // SAFETY: plain call right after the failed OpenProcess.
            return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
        };
        let mut code = 0u32;
        // SAFETY: valid process handle and out-parameter.
        let ok = unsafe { GetExitCodeProcess(p.0, &mut code) };
        ok != 0 && code == STILL_ACTIVE as u32
    }

    pub fn creation_time(pid: u32) -> Option<u64> {
        let p = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        // SAFETY: valid process handle and out-parameters.
        let ok = unsafe { GetProcessTimes(p.0, &mut c, &mut e, &mut k, &mut u) };
        (ok != 0).then(|| ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
    }
}

#[cfg(test)]
mod tree_tests {
    use super::*;

    #[test]
    fn tree_walk_follows_children_and_rejects_recycled_parents() {
        // 10 → 11 → 12, 10 → 13; 14 claims parent 10 but is older (recycled pid); 20 unrelated.
        let t = [(10, 1, 100), (11, 10, 110), (12, 11, 120), (13, 10, 105), (14, 10, 50), (20, 1, 90)];
        let mut d = tree_below(10, &t);
        d.sort();
        assert_eq!(d, vec![11, 12, 13]);
        assert!(tree_below(20, &t).is_empty());
        // Unknown creation times (0) never reject.
        assert_eq!(tree_below(1, &[(2, 1, 0), (3, 2, 0)]), vec![2, 3]);
        assert!(descendants(0).is_empty());
    }

    /// A real child shows up under this process (all desktop OSes).
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[test]
    fn descendants_sees_a_live_child() {
        #[cfg(windows)]
        let mut c = std::process::Command::new("cmd").args(["/c", "ping -n 30 127.0.0.1 >nul"]).spawn().unwrap();
        #[cfg(not(windows))]
        let mut c = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let me = std::process::id() as i32;
        let seen = crate::proc::wait_until(Duration::from_secs(5), || descendants(me).contains(&(c.id() as i32)));
        let _ = c.kill();
        let _ = c.wait();
        assert!(seen, "child {} not among descendants of {me}", c.id());
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn sleeper() -> Command {
        let mut c = Command::new("sleep");
        c.arg("300").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        c
    }

    #[test]
    fn group_is_seen_and_killed_with_grace() {
        let mut c = sleeper();
        let mut child = spawn_in_group(&mut c, false).unwrap();
        let pid = child.id() as i32;
        assert!(alive(pid));
        assert_eq!(group_members(pid), vec![pid]);
        assert!(group_alive(pid));
        let t0 = start_time(pid);
        assert!(t0.is_some(), "start time of a live child");
        assert_eq!(start_time(pid), t0, "stable while it runs");
        let started = Instant::now();
        kill_group(pid, Duration::from_secs(5));
        let _ = child.wait();
        // sleep exits on SIGTERM at once: the grace loop must notice instead of waiting 5s.
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(!alive(pid));
        assert!(!group_alive(pid));
        assert_eq!(start_time(pid), None);
    }

    #[test]
    fn guards_refuse_our_own_group_and_low_pids() {
        assert!(signal_group(own_group(), 0).is_err());
        assert!(signal_group(1, 0).is_err());
        kill_group(own_group(), Duration::from_millis(1)); // must be a no-op: we are still here
        kill_group(0, Duration::from_millis(1));
        assert!(!alive(0) && !alive(-5));
        assert!(alive(std::process::id() as i32));
    }

    #[test]
    fn parent_pid_and_flags() {
        assert_eq!(parent_pid(std::process::id() as i32), Some(unsafe { libc::getppid() }));
        let mut c = sleeper();
        let mut child = spawn_in_group_with(&mut c, false, CREATE_NO_WINDOW).unwrap();
        assert_eq!(parent_pid(child.id() as i32), Some(std::process::id() as i32));
        assert_eq!(console_flags(), 0, "no creation flags on Unix");
        kill_group(child.id() as i32, Duration::from_secs(1));
        let _ = child.wait();
        assert!(!set_parent_watchdog("/nonexistent".into()) || cfg!(target_os = "macos"));
    }

    #[test]
    fn new_group_and_adopt_compose() {
        let mut c = sleeper();
        new_group(&mut c, true);
        die_with_parent(&mut c);
        let mut child = c.spawn().unwrap();
        adopt(&child).unwrap();
        let pid = child.id() as i32;
        assert!(wait(|| group_members(pid) == vec![pid]));
        signal_group(pid, libc::SIGKILL).unwrap();
        let _ = child.wait();
        assert!(!group_alive(pid));
    }

    fn wait(mut f: impl FnMut() -> bool) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}
