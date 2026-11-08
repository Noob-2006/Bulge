//! The Unix half of the local backend (`exec::local`): children on one merged output pipe or
//! a pseudo-terminal, their own process group, `poll(2)` reads with a timeout, and detached
//! jobs run through a `/bin/sh` wrapper that writes the exit status to a file.
//!
//! This is the code that used to live in `local.rs`, unchanged on Linux (same syscalls in
//! the same order). Differences on other Unix systems: no `pipe2` on Apple systems (`pipe`
//! plus close-on-exec through `std::io::pipe`), no parent-death signal outside Linux /
//! Android, and process state (zombie, start time) from `seagent_core::platform::proc`
//! instead of `/proc`.

use super::local::{proc_start_time, register_child, PreExec};
use seagent_core::exec::{ExecChild, ExecRequest, ExitInfo};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Wait until `fd` is readable (or hung up), at most `timeout`.
fn poll_in(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(r > 0);
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            // A PTY master reads EIO once the slave side is closed: that is EOF.
            Some(libc::EIO) => return Ok(0),
            _ => return Err(e),
        }
    }
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // SAFETY: data valid for its length.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn kill_group(pgid: i32, sig: i32) {
    if pgid > 1 {
        // SAFETY: plain syscall; negative pid targets the process group.
        unsafe {
            libc::kill(-pgid, sig);
        }
    }
}

fn exit_of(s: std::process::ExitStatus) -> ExitInfo {
    ExitInfo { code: s.code(), signal: s.signal() }
}

/// An anonymous pipe, both ends close-on-exec: `pipe2(O_CLOEXEC)` where the kernel has it.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds are fresh and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Apple systems have no `pipe2`: std's pipe sets close-on-exec on both ends.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (r, w) = std::io::pipe()?;
    Ok((OwnedFd::from(r), OwnedFd::from(w)))
}

/// Merged output pipe or PTY, own process group, dies with seagent.
pub(super) fn spawn_attached(mut cmd: Command, req: &ExecRequest, mut extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    let parent = std::process::id() as i32;
    let pty = req.pty;
    let (reader, stdin_fd): (OwnedFd, Option<OwnedFd>) = if let Some((rows, cols)) = pty {
        let (master, slave) = seagent_core::platform::term::open_pty(rows, cols)?;
        cmd.stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::from(slave.try_clone()?)).stderr(Stdio::from(slave));
        let w = master.try_clone()?;
        (master, Some(w))
    } else {
        let (r, w) = pipe()?;
        cmd.stdout(Stdio::from(w.try_clone()?)).stderr(Stdio::from(w));
        cmd.stdin(if req.stdin || req.stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
        (r, None)
    };
    // SAFETY: only async-signal-safe calls (setsid/setpgid/ioctl/prctl/getppid) and
    // the backend's own pre-exec hook, which must obey the same rule.
    unsafe {
        cmd.pre_exec(move || {
            if pty.is_some() {
                // New session so the PTY becomes the controlling terminal (stdin is the slave).
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            } else if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            crate::shell::die_with_parent(parent);
            if let Some(f) = extra.as_mut() {
                f()?;
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    register_child(child.id(), "");
    drop(cmd); // closes our copies of the slave / write ends
    let stdin_pipe = child.stdin.take();
    let mut c = LocalChild { child: Some(child), out: Some(reader), pty_master: stdin_fd, stdin: stdin_pipe, detached: None, exit: None };
    if let Some(d) = &req.stdin_data {
        c.write_stdin(d)?;
        if !req.stdin {
            c.close_stdin();
        }
    }
    Ok(Box::new(c))
}

/// Detached: own session, output appended to `log_file`, exit status written to
/// `exit_file` by a tiny wrapper shell, no parent-death signal.
pub(super) fn spawn_detached(cmd: Command, req: &ExecRequest, mut extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    let log = req.log_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs log_file"))?;
    let exit = req.exit_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs exit_file"))?;
    let _ = std::fs::remove_file(&exit);
    let out = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    // sh -c '"$@"; echo $? > exit' sh <program> <args…>
    let mut w = Command::new("/bin/sh");
    w.arg("-c").arg("\"$@\"; s=$?; echo $s > \"$SEAGENT_EXIT_FILE.tmp\" && mv -f \"$SEAGENT_EXIT_FILE.tmp\" \"$SEAGENT_EXIT_FILE\"").arg("sh").arg(cmd.get_program()).args(cmd.get_args());
    if let Some(d) = cmd.get_current_dir() {
        w.current_dir(d);
    }
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => w.env(k, v),
            None => w.env_remove(k),
        };
    }
    w.env("SEAGENT_EXIT_FILE", &exit).stdin(Stdio::null()).stdout(Stdio::from(out.try_clone()?)).stderr(Stdio::from(out));
    // SAFETY: setsid + optional async-signal-safe hook.
    unsafe {
        w.pre_exec(move || {
            libc::setsid();
            if let Some(f) = extra.as_mut() {
                f()?;
            }
            Ok(())
        });
    }
    let child = w.spawn()?;
    register_child(child.id(), "detached");
    Ok(Box::new(LocalChild { detached: Some(Detached { pid: child.id(), log: File::open(&log)?, exit_file: exit, start: proc_start_time(child.id()) }), child: Some(child), out: None, pty_master: None, stdin: None, exit: None }))
}

struct Detached {
    pid: u32,
    log: File,
    exit_file: PathBuf,
    start: Option<u64>,
}

pub struct LocalChild {
    child: Option<Child>,
    out: Option<OwnedFd>,
    pty_master: Option<OwnedFd>,
    stdin: Option<std::process::ChildStdin>,
    detached: Option<Detached>,
    exit: Option<ExitInfo>,
}

impl LocalChild {
    /// Re-attach to a detached process after an seagent restart (no stdin, no wait()).
    pub fn reattach(pid: u32, start: Option<u64>, log: &Path, exit_file: &Path, offset: u64) -> io::Result<LocalChild> {
        let mut f = File::open(log)?;
        f.seek(SeekFrom::Start(offset))?;
        Ok(LocalChild { child: None, out: None, pty_master: None, stdin: None, detached: Some(Detached { pid, log: f, exit_file: exit_file.to_path_buf(), start }), exit: None })
    }
    fn pgid(&self) -> i32 {
        self.child.as_ref().map(|c| c.id() as i32).or(self.detached.as_ref().map(|d| d.pid as i32)).unwrap_or(0)
    }
    fn detached_exit(d: &Detached) -> Option<ExitInfo> {
        super::local::exit_file_status(&d.exit_file)
    }
    pub fn start_time(&self) -> Option<u64> {
        self.detached.as_ref().and_then(|d| d.start)
    }
}

impl ExecChild for LocalChild {
    fn pid(&self) -> Option<u32> {
        let p = self.pgid();
        (p > 0).then_some(p as u32)
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if let Some(d) = self.detached.as_mut() {
            let n = d.log.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.exit.is_some() || LocalChild::detached_exit(d).is_some() {
                // One more read: output written just before the exit file.
                return d.log.read(buf);
            }
            std::thread::sleep(timeout.min(Duration::from_millis(50)));
            return Err(io::ErrorKind::TimedOut.into());
        }
        let Some(fd) = self.out.as_ref().map(|f| f.as_raw_fd()) else { return Ok(0) };
        if !poll_in(fd, timeout)? {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let n = read_fd(fd, buf)?;
        if n == 0 {
            self.out = None;
        }
        Ok(n)
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(m) = &self.pty_master {
            return write_all_fd(m.as_raw_fd(), data);
        }
        match self.stdin.as_mut() {
            Some(s) => {
                s.write_all(data)?;
                s.flush()
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin is closed (start the process with stdin or pty to write to it)")),
        }
    }
    fn close_stdin(&mut self) {
        if self.pty_master.is_some() {
            // EOF on a terminal is ^D at line start.
            let _ = self.write_stdin(b"\x04");
        }
        self.stdin = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        if let Some(e) = self.exit {
            return Ok(Some(e));
        }
        if let Some(c) = self.child.as_mut() {
            if let Some(s) = c.try_wait()? {
                let mut e = exit_of(s);
                if let Some(d) = &self.detached {
                    // The wrapper shell exits 0; the real status is in the exit file.
                    e = LocalChild::detached_exit(d).unwrap_or(e);
                }
                self.exit = Some(e);
            }
        } else if let Some(d) = &self.detached {
            if let Some(e) = LocalChild::detached_exit(d) {
                self.exit = Some(e);
            } else if !pid_alive(d.pid, d.start) {
                self.exit = Some(ExitInfo { code: None, signal: None });
            }
        }
        Ok(self.exit)
    }
    fn kill(&mut self, force: bool) {
        let pgid = self.pgid();
        if self.exit.is_none() {
            kill_group(pgid, if force { libc::SIGKILL } else { libc::SIGTERM });
        }
    }
    fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        let Some(m) = &self.pty_master else { return Err(io::Error::new(io::ErrorKind::Unsupported, "this process has no terminal (start it with pty=true)")) };
        seagent_core::platform::term::set_pty_size(m.as_fd(), rows, cols)
    }
    fn is_pty(&self) -> bool {
        self.pty_master.is_some()
    }
}

impl Drop for LocalChild {
    fn drop(&mut self) {
        if self.detached.is_none() {
            if let Some(c) = self.child.as_mut() {
                if matches!(c.try_wait(), Ok(None)) {
                    kill_group(c.id() as i32, libc::SIGKILL);
                    let _ = c.wait();
                }
            }
        } else if let Some(c) = self.child.as_mut() {
            let _ = c.try_wait(); // reap if done; a running detached process keeps going
        }
    }
}

/// Is `pid` alive and still the process we started (start time matches)?
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn pid_alive(pid: u32, start: Option<u64>) -> bool {
    // SAFETY: signal 0 only probes.
    let alive = unsafe { libc::kill(pid as i32, 0) == 0 } || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rfind(')').and_then(|i| s[i + 2..].chars().next())) == Some('Z');
    alive && !zombie && (start.is_none() || proc_start_time(pid) == start)
}

/// Is `pid` alive and still the process we started? No `/proc` here: the zombie state and
/// start time come from the platform layer (`proc_pidinfo` on macOS).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn pid_alive(pid: u32, start: Option<u64>) -> bool {
    // SAFETY: signal 0 only probes.
    let reachable = unsafe { libc::kill(pid as i32, 0) == 0 };
    let alive = reachable || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let zombie = reachable && !seagent_core::platform::proc::alive(pid as i32);
    alive && !zombie && (start.is_none() || proc_start_time(pid) == start)
}
