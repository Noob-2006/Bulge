//! Child processes the kernel starts itself (hooks, code-mode scripts, verifiers, workers,
//! cron scripts): their own process group, tied to seagent, killed as a unit.
//!
//! * **Unix** — exactly what each call site used to spell out: `setpgid(0, 0)` in the child
//!   and, on Linux / Android, `PR_SET_PDEATHSIG` (`SIGKILL` unless the call site asked for
//!   another signal) plus the "parent already gone" check; kills are `kill(-pgid, sig)`.
//! * **Windows** — `seagent_core::platform::proc`: a new console process group and a
//!   kill-on-close Job Object (the tree dies with seagent however seagent dies; not bound to
//!   the spawning thread). "SIGTERM" is CTRL_BREAK, "SIGKILL" is `TerminateJobObject`.
//!
//! `bash -c` goes through [`bash`]: the literal `bash` on Unix, the platform layer's bash
//! (Git Bash / MSYS2) on Windows, with an explicit error when only PowerShell exists.

use std::io;
use std::process::{Child, Command};
use std::time::Duration;

/// `bash -c script`. Unix: `Command::new("bash").arg("-c").arg(script)` (Android: `sh` when no
/// bash is installed). Windows: the platform's bash, or an error naming what is missing: the
/// scripts these call sites run are bash syntax and must not be fed to PowerShell.
pub fn bash(script: &str) -> Result<Command, String> {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        let mut c = seagent_core::platform::proc::command("bash");
        c.arg("-c").arg(script);
        Ok(c)
    }
    #[cfg(not(all(unix, not(target_os = "android"))))]
    {
        use seagent_core::platform::shell;
        if cfg!(windows) && !shell::active().kind.is_posix() {
            return Err(format!("bash is not available on {}: no Git Bash / MSYS2 bash was found (install Git for Windows or set SEAGENT_SHELL to a bash.exe); this machine's shell is {}", std::env::consts::OS, shell::active().kind.as_str()));
        }
        Ok(shell::command(shell::Style::Bash, script))
    }
}

/// Own process group + die with seagent, `PDEATHSIG = SIGKILL` (see the module docs).
/// Windows: plus `CREATE_NO_WINDOW` when seagent has no console (the daemon), so a hook or
/// script does not flash a console window.
pub fn tie(cmd: &mut Command) {
    #[cfg(unix)]
    tie_with(cmd, libc::SIGKILL);
    #[cfg(not(unix))]
    {
        use seagent_core::platform::proc;
        proc::new_group_with(cmd, false, proc::console_flags());
    }
}

/// [`tie`] with another parent-death signal (Linux / Android).
#[cfg(unix)]
pub fn tie_with(cmd: &mut Command, death_signal: libc::c_int) {
    use std::os::unix::process::CommandExt;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let parent = std::process::id() as i32;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = death_signal;
    // SAFETY: only async-signal-safe libc calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::setpgid(0, 0);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                libc::prctl(libc::PR_SET_PDEATHSIG, death_signal as libc::c_ulong);
                if libc::getppid() != parent {
                    libc::_exit(137);
                }
            }
            Ok(())
        });
    }
}

/// Spawn a command prepared by [`tie`]. Windows: and put it in its Job Object (a child that
/// cannot be put there is killed again: it would silently lose the die-with-seagent guarantee).
pub fn spawn(cmd: &mut Command) -> io::Result<Child> {
    let mut child = cmd.spawn()?;
    if let Err(e) = seagent_core::platform::proc::adopt(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child)
}

/// `SIGKILL` the group led by `pgid` (Windows: terminate its job now).
pub fn kill_group_now(pgid: i32) {
    #[cfg(unix)]
    {
        // SAFETY: plain signal syscall on our own child's process group.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    seagent_core::platform::proc::kill_group(pgid, Duration::ZERO);
}

/// `SIGTERM` the group, sleep `grace`, `SIGKILL` it (Windows: CTRL_BREAK, the grace, terminate).
pub fn term_then_kill(pgid: i32, grace: Duration) {
    #[cfg(unix)]
    {
        // SAFETY: plain signal syscalls on our own child's process group.
        unsafe { libc::kill(-pgid, libc::SIGTERM) };
        std::thread::sleep(grace);
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    seagent_core::platform::proc::kill_group(pgid, grace);
}

#[cfg(test)]
#[cfg(all(unix, not(target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn tied_bash_runs_in_its_own_group_and_is_killed() {
        let mut c = bash("sleep 30").unwrap();
        c.stdin(std::process::Stdio::null());
        tie(&mut c);
        let mut child = spawn(&mut c).unwrap();
        let pid = child.id() as i32;
        assert!(seagent_core::proc::wait_until(Duration::from_secs(5), || seagent_core::platform::proc::group_members(pid) == vec![pid]), "own process group");
        kill_group_now(pid);
        let st = child.wait().unwrap();
        assert!(!st.success());
        let out = bash("printf %s $((2+3))").unwrap().output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "5");
    }
}
