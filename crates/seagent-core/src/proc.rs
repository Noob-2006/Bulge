//! Child processes that cannot outlive seagent (rows new-001 / new-002).
//!
//! Two habits left orphans running for days: the managed browser launcher started Chrome in
//! its own session with nothing tying it to seagent (a crashed test, a `SIGKILL`ed CLI or an
//! interrupted `cargo test` left a headless Chrome behind), and tests only cleaned up on the
//! happy path. This module is the fix for both layers:
//!
//! * [`spawn_tied`] — production: the child gets its own process group (so a stop reaches its
//!   renderers/zygotes with one `kill(-pgid)`) **and** `PR_SET_PDEATHSIG`, so the kernel
//!   signals it when seagent dies, however seagent dies. `PDEATHSIG` fires when the *thread* that
//!   forked the child exits, not the process; spawning from a short-lived tool-call thread
//!   would kill the browser under us. So every tied child is forked by one process-lifetime
//!   spawner thread, which only ends when the process does.
//! * [`ChildGuard`] / [`PidGuard`] — tests (and callers that own a child for one scope): the
//!   whole process group is terminated on drop, which includes unwinding from a failed
//!   assertion.

use std::io;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Signal delivered to a tied child when seagent dies. `SIGTERM` lets Chrome close its profile
/// and take its helpers down; [`ChildGuard`] escalates to `SIGKILL` itself.
pub const DEATH_SIGNAL: i32 = libc::SIGTERM;

type Job = (Command, bool, mpsc::Sender<io::Result<Child>>);

fn spawner() -> &'static Mutex<mpsc::Sender<Job>> {
    static TX: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("seagent-proc-spawner".into())
            .spawn(move || {
                // Lives as long as the process: the sender sits in a static.
                for (mut cmd, setsid, reply) in rx {
                    let _ = reply.send(fork_tied(&mut cmd, setsid));
                }
            })
            .expect("spawn seagent-proc-spawner thread");
        Mutex::new(tx)
    })
}

fn fork_tied(cmd: &mut Command, setsid: bool) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if setsid {
                libc::setsid();
            } else {
                libc::setpgid(0, 0);
            }
            #[cfg(target_os = "linux")]
            {
                libc::prctl(libc::PR_SET_PDEATHSIG, DEATH_SIGNAL as libc::c_ulong);
                // The parent may already be gone (it died between fork and prctl).
                if libc::getppid() != parent {
                    libc::_exit(137);
                }
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Spawn `cmd` as the leader of its own process group (`setsid` when `own_session`, else
/// `setpgid`) with a parent-death signal, from the process-lifetime spawner thread.
/// The returned [`Child`] behaves like any other (wait / try_wait / kill from any thread).
pub fn spawn_tied(cmd: Command, own_session: bool) -> io::Result<Child> {
    let (tx, rx) = mpsc::channel();
    spawner().lock().unwrap_or_else(|e| e.into_inner()).send((cmd, own_session, tx)).map_err(|_| io::Error::other("seagent-proc-spawner is gone"))?;
    rx.recv().map_err(|_| io::Error::other("seagent-proc-spawner dropped the request"))?
}

/// Is `pid` alive (and not a zombie)?
pub fn alive(pid: i32) -> bool {
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
}

/// Is any process still in group `pgid`?
pub fn group_alive(pgid: i32) -> bool {
    pgid > 1 && unsafe { libc::kill(-pgid, 0) } == 0 && !group_members(pgid).is_empty()
}

/// Live (non-zombie) members of process group `pgid`, read from `/proc`.
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

/// `SIGTERM` the group, wait up to `grace`, then `SIGKILL` it. Never signals pgid 0/1 or our
/// own group.
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

/// Wait until `pred` holds or `timeout` passes.
pub fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Owns a spawned child; on drop (including a panic unwinding through the scope) its process
/// group is terminated and the child reaped. The child must lead its own group
/// ([`spawn_tied`], `process_group(0)` or `setsid`), otherwise only the child itself is killed.
pub struct ChildGuard {
    child: Option<Child>,
    group: bool,
}

impl ChildGuard {
    /// Guard a child that leads its own process group.
    pub fn group(child: Child) -> Self {
        ChildGuard { child: Some(child), group: true }
    }
    /// Guard a child in our process group (kill just the child).
    pub fn single(child: Child) -> Self {
        ChildGuard { child: Some(child), group: false }
    }
    pub fn id(&self) -> u32 {
        self.child.as_ref().map(|c| c.id()).unwrap_or(0)
    }
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("child taken")
    }
    /// Give the child back (the caller takes over its lifetime).
    pub fn into_inner(mut self) -> Child {
        self.child.take().expect("child taken")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            if self.group {
                kill_group(c.id() as i32, Duration::from_secs(2));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A process group we started but no longer hold a [`Child`] for (it was handed to a reaper
/// thread, or recorded by pid); terminated on drop.
pub struct PidGuard(pub i32);

impl Drop for PidGuard {
    fn drop(&mut self) {
        kill_group(self.0, Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn sleeper() -> Command {
        let mut c = Command::new("sleep");
        c.arg("300").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        c
    }

    #[test]
    fn tied_child_leads_its_group_and_survives_the_calling_thread() {
        // Spawned from a short-lived thread: PDEATHSIG must not fire when that thread ends.
        let child = std::thread::spawn(|| spawn_tied(sleeper(), false).unwrap()).join().unwrap();
        let g = ChildGuard::group(child);
        let pid = g.id() as i32;
        std::thread::sleep(Duration::from_millis(300));
        assert!(alive(pid), "the tied child died with the thread that asked for it");
        assert_eq!(group_members(pid), vec![pid], "own process group");
        drop(g);
        assert!(wait_until(Duration::from_secs(5), || !alive(pid)), "guard did not stop the child");
    }

    #[test]
    fn child_guard_kills_on_panic() {
        let pid = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));
        let p2 = pid.clone();
        let r = std::thread::spawn(move || {
            let g = ChildGuard::group(spawn_tied(sleeper(), true).unwrap());
            p2.store(g.id() as i32, std::sync::atomic::Ordering::SeqCst);
            panic!("deliberate test panic");
        })
        .join();
        assert!(r.is_err());
        let pid = pid.load(std::sync::atomic::Ordering::SeqCst);
        assert!(pid > 0);
        assert!(wait_until(Duration::from_secs(5), || !alive(pid)), "child {pid} survived a panic");
    }

    /// The child-side half of [`tied_children_die_with_a_panicking_process`]: runs only when
    /// re-executed with `SEAGENT_PROC_PANIC_CHILD=<pidfile>`. It starts a tied sleeper, records
    /// its pid, *forgets* the handle (no guard can help) and panics; the test process then exits.
    #[test]
    fn panicking_child_process_helper() {
        let Ok(out) = std::env::var("SEAGENT_PROC_PANIC_CHILD") else { return };
        let c = spawn_tied(sleeper(), true).unwrap();
        std::fs::write(&out, c.id().to_string()).unwrap();
        std::mem::forget(c);
        panic!("deliberate panic with a tied child running");
    }

    /// new-001: a test process that panics (or is killed) must not leave its children behind.
    /// Re-executes this test binary so the panic ends a whole process, not just a thread.
    #[test]
    fn tied_children_die_with_a_panicking_process() {
        let dir = crate::tmp::TempDir::new("seagent-proc-panic");
        let pidfile = dir.path().join("pid");
        let exe = std::env::current_exe().unwrap();
        let st = Command::new(exe)
            .args(["--exact", "proc::tests::panicking_child_process_helper", "--nocapture", "--test-threads=1"])
            .env("SEAGENT_PROC_PANIC_CHILD", &pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!st.success(), "the helper was supposed to panic");
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let gone = wait_until(Duration::from_secs(5), || !group_alive(pid));
        if !gone {
            kill_group(pid, Duration::from_secs(1)); // ours: do not leak it even when failing
        }
        assert!(gone, "process group {pid} outlived its panicking parent");
    }
}
