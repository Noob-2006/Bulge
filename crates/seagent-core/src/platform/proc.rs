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
//!   parent-death signal: a tied child outlives a `SIGKILL`ed seagent (a clean exit or a
//!   [`kill_group`] still stops it).
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
    cmd.spawn()
}

/// See the Unix variant. A child that cannot be put in its job is killed again and the error
/// returned: an untracked child would silently lose the die-with-seagent guarantee.
#[cfg(windows)]
pub fn spawn_in_group(cmd: &mut Command, own_session: bool) -> io::Result<Child> {
    new_group(cmd, own_session);
    let mut child = cmd.spawn()?;
    if let Err(e) = adopt(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", child.id())));
    }
    Ok(child)
}

/// Only the "new group" half of [`spawn_in_group`], for callers that spawn themselves.
/// Unix: `setsid` / `setpgid(0, 0)` in the child. Windows: `CREATE_NEW_PROCESS_GROUP` (this
/// replaces any creation flags set before); call [`adopt`] after the spawn.
pub fn new_group(cmd: &mut Command, own_session: bool) {
    #[cfg(unix)]
    {
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
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
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
/// and the tree dies with seagent. Unix: no-op (the process group already is the unit).
pub fn adopt(child: &Child) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::adopt(child)
    }
    #[cfg(not(windows))]
    {
        let _ = child;
        Ok(())
    }
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
