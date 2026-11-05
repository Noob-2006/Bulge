//! Host-side processes: the local backend, the two OS sandboxes (bubblewrap
//! namespaces, Landlock), and `spawn_command`, which every wrapper backend
//! (docker exec, ssh, apptainer exec…) uses to run its client program with
//! merged output pipes or a pseudo-terminal.

use super::sandbox::SandboxConfig;
use super::BackendCtx;
use ark_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

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

/// A pseudo-terminal pair: (master, slave).
fn open_pty(rows: u16, cols: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    // SAFETY: standard posix_openpt sequence; fds are checked and owned.
    unsafe {
        let m = cvt(libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?;
        let master = OwnedFd::from_raw_fd(m);
        cvt(libc::grantpt(m))?;
        cvt(libc::unlockpt(m))?;
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(m, name.as_mut_ptr(), name.len()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let s = cvt(libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?;
        let slave = OwnedFd::from_raw_fd(s);
        let ws = libc::winsize { ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
        libc::ioctl(m, libc::TIOCSWINSZ, &ws);
        Ok((master, slave))
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors.
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: both fds are fresh and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Hooks a sandbox backend runs in the child after fork, before exec
/// (Landlock). Must be async-signal-safe.
pub type PreExec = Box<dyn FnMut() -> io::Result<()> + Send + Sync>;

/// Remove inherited variables that are blocked by policy but whose names bash's `unset`
/// cannot touch (`FOO-BAR-API-KEY` — the shell tool only unsets shell identifiers, so this is
/// where those names leave the child's environment). Runs before `req.env`, so a value a
/// tool sets on purpose still wins.
fn drop_odd_named_secrets(cmd: &mut Command) {
    use ark_security::envscrub::{is_blocked, Surface};
    for (k, _) in std::env::vars_os() {
        if let Some(k) = k.to_str() {
            if !crate::shell::is_env_name(k) && is_blocked(k, Surface::Terminal) {
                cmd.env_remove(k);
            }
        }
    }
}

/// Spawn `cmd` (the backend's client program) for `req`: merged output on one
/// pipe or a PTY, own process group, dies with ark unless `req.detach`.
pub fn spawn_command(mut cmd: Command, req: &ExecRequest, mut extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    drop_odd_named_secrets(&mut cmd);
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    if req.detach {
        return spawn_detached(cmd, req, extra);
    }
    let parent = std::process::id() as i32;
    let pty = req.pty;
    let (reader, stdin_fd, slave_fd): (OwnedFd, Option<OwnedFd>, Option<RawFd>) = if let Some((rows, cols)) = pty {
        let (master, slave) = open_pty(rows, cols)?;
        let sfd = slave.as_raw_fd();
        cmd.stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::from(slave.try_clone()?)).stderr(Stdio::from(slave));
        let w = master.try_clone()?;
        (master, Some(w), Some(sfd))
    } else {
        let (r, w) = pipe()?;
        cmd.stdout(Stdio::from(w.try_clone()?)).stderr(Stdio::from(w));
        cmd.stdin(if req.stdin || req.stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
        (r, None, None)
    };
    let _ = slave_fd;
    // SAFETY: only async-signal-safe calls (setsid/setpgid/ioctl/prctl/getppid) and
    // the backend's own pre-exec hook, which must obey the same rule.
    unsafe {
        cmd.pre_exec(move || {
            if pty.is_some() {
                // New session so the PTY becomes the controlling terminal (stdin is the slave).
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::ioctl(0, libc::TIOCSCTTY, 0);
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
fn spawn_detached(cmd: Command, req: &ExecRequest, mut extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    let log = req.log_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs log_file"))?;
    let exit = req.exit_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs exit_file"))?;
    let _ = std::fs::remove_file(&exit);
    let out = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    // sh -c '"$@"; echo $? > exit' sh <program> <args…>
    let mut w = Command::new("/bin/sh");
    w.arg("-c").arg("\"$@\"; s=$?; echo $s > \"$ARK_EXIT_FILE.tmp\" && mv -f \"$ARK_EXIT_FILE.tmp\" \"$ARK_EXIT_FILE\"").arg("sh").arg(cmd.get_program()).args(cmd.get_args());
    if let Some(d) = cmd.get_current_dir() {
        w.current_dir(d);
    }
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => w.env(k, v),
            None => w.env_remove(k),
        };
    }
    w.env("ARK_EXIT_FILE", &exit).stdin(Stdio::null()).stdout(Stdio::from(out.try_clone()?)).stderr(Stdio::from(out));
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

/// `/proc/<pid>/stat` start time (field 22): tells a reused pid from ours.
pub fn proc_start_time(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &s[s.rfind(')')? + 2..];
    after.split_whitespace().nth(19)?.parse().ok()
}

// ───────── process-group registry (section C7; the reaper lives in ark-kernel) ─────────
//
// Every child starts its own group (`setpgid(0,0)` / `setsid`), so pgid == pid. Recording it
// in `<home>/reaper/procs.jsonl` is what lets the kernel reap a crashed session's children
// without guessing: the line carries the `/proc` start time (PID reuse check) and the ark pid
// (is the owner still alive?). Best-effort by design — a command must never fail to run
// because its bookkeeping could not be written.

static REAPER_HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

thread_local! {
    static REAPER_SCOPE: std::cell::RefCell<Option<(PathBuf, String, String)>> = const { std::cell::RefCell::new(None) };
}

/// Install the ark data dir once (daemon / binary startup) for child registration. Without it
/// nothing is recorded — ark-tools never guesses a home, so tests and library users stay inert.
pub fn set_reaper_home(home: &Path) {
    let _ = REAPER_HOME.set(home.to_path_buf());
}

/// Attribute the process groups spawned on this thread to `session` / `tool` until the guard
/// drops (the shell tool sets it around `spawn_tool`).
pub fn reap_scope(home: &Path, session: &str, tool: &str) -> ReapScope {
    let prev = REAPER_SCOPE.with(|s| s.borrow_mut().replace((home.to_path_buf(), session.to_string(), tool.to_string())));
    ReapScope(prev)
}

pub struct ReapScope(Option<(PathBuf, String, String)>);

impl Drop for ReapScope {
    fn drop(&mut self) {
        let prev = self.0.take();
        REAPER_SCOPE.with(|s| *s.borrow_mut() = prev);
    }
}

/// Append one `{"pgid":…,"start":…,"session":…,"tool":…,"ark_pid":…,"ts_ms":…}` line.
/// Errors are ignored: the registry is a hint for the reaper, never a precondition.
pub fn register_pgid(home: &Path, pgid: u32, session: &str, tool: &str) {
    let dir = home.join("reaper");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let line = serde_json::json!({
        "pgid": pgid,
        "start": proc_start_time(pgid),
        "session": session,
        "tool": tool,
        "ark_pid": std::process::id(),
        "ts_ms": ts_ms,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("procs.jsonl")) {
        let _ = writeln!(f, "{line}");
    }
}

/// Register a freshly spawned child (best-effort, never fails a command). `kind` overrides the
/// recorded tool name ("" = the [`reap_scope`] tool, else `exec`); `"detached"` marks a process
/// meant to survive an ark restart, which the reaper records but never kills.
fn register_child(pid: u32, kind: &str) {
    let scope = REAPER_SCOPE.with(|s| s.borrow().clone());
    let named = |t: &str| if kind.is_empty() { t.to_string() } else { kind.to_string() };
    match (scope, REAPER_HOME.get()) {
        (Some((home, session, tool)), _) => register_pgid(&home, pid, &session, &named(&tool)),
        (None, Some(home)) => register_pgid(home, pid, "", &named("exec")),
        (None, None) => {}
    }
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
    /// Re-attach to a detached process after an ark restart (no stdin, no wait()).
    pub fn reattach(pid: u32, start: Option<u64>, log: &Path, exit_file: &Path, offset: u64) -> io::Result<LocalChild> {
        let mut f = File::open(log)?;
        f.seek(SeekFrom::Start(offset))?;
        Ok(LocalChild { child: None, out: None, pty_master: None, stdin: None, detached: Some(Detached { pid, log: f, exit_file: exit_file.to_path_buf(), start }), exit: None })
    }
    fn pgid(&self) -> i32 {
        self.child.as_ref().map(|c| c.id() as i32).or(self.detached.as_ref().map(|d| d.pid as i32)).unwrap_or(0)
    }
    fn detached_exit(d: &Detached) -> Option<ExitInfo> {
        let s = std::fs::read_to_string(&d.exit_file).ok()?;
        let c: i32 = s.trim().parse().ok()?;
        Some(if c > 128 { ExitInfo { code: Some(c), signal: Some(c - 128) } } else { ExitInfo::code(c) })
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
        let ws = libc::winsize { ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
        // SAFETY: valid fd and winsize.
        cvt(unsafe { libc::ioctl(m.as_raw_fd(), libc::TIOCSWINSZ, &ws) })?;
        Ok(())
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
pub fn pid_alive(pid: u32, start: Option<u64>) -> bool {
    // SAFETY: signal 0 only probes.
    let alive = unsafe { libc::kill(pid as i32, 0) == 0 } || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rfind(')').and_then(|i| s[i + 2..].chars().next())) == Some('Z');
    alive && !zombie && (start.is_none() || proc_start_time(pid) == start)
}

fn bash_command(req: &ExecRequest) -> Command {
    let mut cmd = Command::new("bash");
    cmd.arg(if req.login { "-lc" } else { "-c" }).arg(&req.script);
    if let Some(d) = &req.cwd {
        cmd.current_dir(d);
    }
    cmd
}

/// Commands run directly on this machine.
#[derive(Default)]
pub struct LocalBackend;

impl LocalBackend {
    pub fn new() -> LocalBackend {
        LocalBackend
    }
}

impl ExecBackend for LocalBackend {
    fn id(&self) -> &str {
        "local"
    }
    fn describe(&self) -> String {
        "local: commands run directly on this machine as the ark user".into()
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        spawn_command(bash_command(req), req, None)
    }
    fn temp_dir(&self) -> String {
        std::env::temp_dir().display().to_string()
    }
}

// ───────────── bubblewrap ─────────────

/// `[exec.bwrap]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BwrapConfig {
    pub binary: String,
    /// Host directories mounted read-only to make a usable system.
    pub ro_paths: Vec<String>,
    pub extra_args: Vec<String>,
}

impl Default for BwrapConfig {
    fn default() -> Self {
        BwrapConfig { binary: "bwrap".into(), ro_paths: ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc", "/opt", "/nix", "/run/current-system"].map(String::from).to_vec(), extra_args: vec![] }
    }
}

/// Mount layout shared by the bwrap and Landlock sandboxes: the workspace
/// (or its private scratch copy) is the only user data visible.
struct Layout {
    workspace: PathBuf,
    writable: bool,
    tmp: PathBuf,
    binds: Vec<(PathBuf, String, bool)>,
    network: bool,
}

fn layout(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<Layout, String> {
    // `[exec] credential_files` are relative to the user's home, as configured.
    let home = super::sandbox::host_home();
    layout_with(sb, ctx, &super::global().cfg.credential_files, &home)
}

/// [`layout`] with the credential entries and the user's home spelled out (tests, embedders).
fn layout_with(sb: &SandboxConfig, ctx: &BackendCtx, creds: &[String], host_home: &Path) -> Result<Layout, String> {
    let (workspace, writable) = match (ctx.sandboxed, sb.workspace_access.as_str()) {
        (true, "none") => {
            let w = sb.scratch_workspace(&ctx.home, &ctx.scope_key);
            std::fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
            (w, true)
        }
        (true, "ro") => (ctx.workspace.clone(), false),
        _ => (ctx.workspace.clone(), true),
    };
    let tmp = sb.root(&ctx.home).join(&ctx.scope_key).join("tmp");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    let mut binds = sb.binds.iter().map(|b| super::sandbox::parse_bind(b)).collect::<Result<Vec<_>, _>>()?;
    // Credential files land read-only at the same path under the sandbox home (bwrap sets
    // `HOME=/tmp`; landlock only needs the host path to be readable).
    let (creds, _errs) = super::sandbox::credential_binds(creds, "/tmp", host_home);
    binds.extend(creds);
    Ok(Layout { workspace, writable, tmp, binds, network: sb.network == "host" })
}

/// Linux namespaces via bubblewrap: private mount/pid/ipc/uts (and net unless
/// `network = "host"`) namespaces, system dirs read-only, home hidden, all
/// capabilities dropped.
pub struct BwrapBackend {
    cfg: BwrapConfig,
    l: Layout,
}

impl BwrapBackend {
    pub fn new(cfg: &BwrapConfig, sb: &SandboxConfig, ctx: &BackendCtx) -> Result<BwrapBackend, String> {
        if which(&cfg.binary).is_none() {
            return Err(format!("exec backend bwrap: `{}` not found (install bubblewrap, or use landlock / docker)", cfg.binary));
        }
        let l = layout(sb, ctx)?;
        if !l.network {
            // Fail at construction, not silently at exec time: a sandbox that claims
            // "network disabled" but cannot create its network namespace must refuse to run.
            probe_net_namespace(&cfg.binary)?;
        }
        Ok(BwrapBackend { cfg: cfg.clone(), l })
    }
    pub fn args(&self, req: &ExecRequest) -> Vec<String> {
        let mut a: Vec<String> = ["--die-with-parent", "--unshare-user-try", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--new-session", "--cap-drop", "ALL"].map(String::from).to_vec();
        if req.pty.is_some() || req.detach {
            a.retain(|x| x != "--new-session"); // keep the controlling terminal
        }
        if req.detach {
            a.retain(|x| x != "--die-with-parent");
        }
        if !self.l.network {
            a.push("--unshare-net".into());
        }
        for p in &self.cfg.ro_paths {
            a.extend(["--ro-bind-try".into(), p.clone(), p.clone()]);
        }
        a.extend(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/home", "--tmpfs", "/root", "--tmpfs", "/run"].map(String::from));
        a.extend(["--bind".into(), self.l.tmp.display().to_string(), "/tmp".into()]);
        let ws = self.l.workspace.display().to_string();
        a.extend([if self.l.writable { "--bind" } else { "--ro-bind" }.into(), ws.clone(), ws.clone()]);
        for (src, dst, ro) in &self.l.binds {
            a.extend([if *ro { "--ro-bind" } else { "--bind" }.into(), src.display().to_string(), dst.clone()]);
        }
        let cwd = req.cwd.as_ref().map(|c| c.display().to_string()).filter(|c| Path::new(c).starts_with(&self.l.workspace)).unwrap_or(ws);
        // The host's TMPDIR usually lives under the hidden /home: point it at the private /tmp.
        a.extend(["--chdir".into(), cwd, "--setenv".into(), "HOME".into(), "/tmp".into(), "--setenv".into(), "TMPDIR".into(), "/tmp".into()]);
        a.extend(self.cfg.extra_args.iter().cloned());
        a.extend(["bash".into(), if req.login { "-lc" } else { "-c" }.into(), req.script.clone()]);
        a
    }
}

impl ExecBackend for BwrapBackend {
    fn id(&self) -> &str {
        "bwrap"
    }
    fn describe(&self) -> String {
        format!(
            "bwrap: Linux namespace sandbox; workspace {} {}, network {}, home hidden, /tmp private, all capabilities dropped",
            self.l.workspace.display(),
            if self.l.writable { "read-write" } else { "read-only" },
            if self.l.network { "shared with host" } else { "disabled" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut cmd = Command::new(&self.cfg.binary);
        cmd.args(self.args(req));
        let mut req = req.clone();
        req.cwd = None;
        spawn_command(cmd, &req, None)
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
}

pub fn which(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        return Path::new(bin).is_file().then(|| PathBuf::from(bin));
    }
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

/// Can `bwrap` actually create a network namespace here? `--unshare-net` is not a
/// `-try` flag: this probe runs the same flag the sandbox will use, so a host with
/// user namespaces / netns disabled is refused up front instead of handing the
/// command the host network after a silent partial failure.
pub fn probe_net_namespace(bin: &str) -> Result<(), String> {
    let script = format!("exec {} --unshare-net --unshare-user-try --die-with-parent --ro-bind / / true", super::sh_quote(bin));
    let (st, out) = super::run_capture(&LocalBackend, &script, None, Duration::from_secs(15)).map_err(|e| format!("exec backend bwrap: cannot probe `--unshare-net`: {e}"))?;
    if st.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&out);
    let detail = detail.trim();
    Err(format!(
        "exec backend bwrap: `--unshare-net` failed ({}) — this host cannot create a network namespace (unprivileged user namespaces or netns are disabled); set exec.sandbox.network = \"host\" to accept the host network, or use the landlock / docker backend",
        if detail.is_empty() { "bwrap exited nonzero with no message" } else { detail }
    ))
}

// ───────────── Landlock ─────────────

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const FS_EXECUTE: u64 = 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_WRITE_FILE: u64 = 1 << 1;
const NET_BIND_TCP: u64 = 1;
const NET_CONNECT_TCP: u64 = 2;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Highest Landlock ABI the kernel supports (0 = unavailable).
pub fn landlock_abi() -> i64 {
    // SAFETY: version query with NULL attr is the documented probe.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) }.max(0)
}

fn fs_all(abi: i64) -> u64 {
    // ABI 1: bits 0..=12; 2 adds REFER (13); 3 adds TRUNCATE (14); 5 adds IOCTL_DEV (15).
    let mut m = (1u64 << 13) - 1;
    if abi >= 2 {
        m |= 1 << 13;
    }
    if abi >= 3 {
        m |= 1 << 14;
    }
    if abi >= 5 {
        m |= 1 << 15;
    }
    m
}

/// Landlock LSM: the command may read system dirs and the workspace, write
/// only the workspace (unless read-only) and its private /tmp; TCP blocked
/// when `network = "none"` (ABI ≥ 4). No namespaces, so it works where user
/// namespaces are disabled. Home and other users' data are unreadable.
pub struct LandlockBackend {
    l: Layout,
    abi: i64,
    ro_paths: Vec<String>,
}

impl LandlockBackend {
    pub fn new(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<LandlockBackend, String> {
        let abi = landlock_abi();
        if abi < 1 {
            return Err("exec backend landlock: the kernel has no Landlock support (CONFIG_SECURITY_LANDLOCK, lsm=landlock); use bwrap or docker".into());
        }
        let l = layout(sb, ctx)?;
        if !l.network && abi < 4 {
            return Err(format!("exec backend landlock: kernel Landlock ABI {abi} cannot restrict networking (needs 4); set exec.sandbox.network = \"host\" or use bwrap"));
        }
        let mut ro_paths = BwrapConfig::default().ro_paths;
        ro_paths.extend(["/dev", "/proc", "/sys"].map(String::from));
        Ok(LandlockBackend { l, abi, ro_paths })
    }

    /// Pre-exec hook applying the ruleset in the child.
    fn hook(&self) -> io::Result<PreExec> {
        let abi = self.abi;
        let all = fs_all(abi);
        let read = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
        let mut rules: Vec<(CString, u64)> = Vec::new();
        let c = |p: &Path| CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path with NUL"));
        for p in &self.ro_paths {
            if Path::new(p).exists() {
                rules.push((c(Path::new(p))?, read));
            }
        }
        rules.push((c(Path::new("/dev/null"))?, read | FS_WRITE_FILE));
        rules.push((c(Path::new("/dev/tty"))?, read | FS_WRITE_FILE));
        rules.push((c(Path::new("/dev/pts"))?, read | FS_WRITE_FILE));
        rules.push((c(&self.l.tmp)?, all));
        rules.push((c(&self.l.workspace)?, if self.l.writable { all } else { read }));
        for (src, _, ro) in &self.l.binds {
            rules.push((c(src)?, if *ro { read } else { all }));
        }
        let net = if self.l.network { 0 } else { NET_BIND_TCP | NET_CONNECT_TCP };
        Ok(Box::new(move || {
            // Only async-signal-safe syscalls below.
            let attr = RulesetAttr { handled_access_fs: all, handled_access_net: net };
            let size = if abi >= 4 { std::mem::size_of::<RulesetAttr>() } else { 8 };
            // SAFETY: attr outlives the call; size matches the ABI.
            let rs = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size, 0u32) };
            if rs < 0 {
                return Err(io::Error::last_os_error());
            }
            for (path, access) in &rules {
                // SAFETY: valid C string; O_PATH fd closed after use.
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    continue; // missing optional path
                }
                // Directories get the full mask; files only file rights.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: valid fd and stat buffer.
                let is_dir = unsafe { libc::fstat(fd, &mut st) } == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
                let allowed = if is_dir { *access } else { *access & (FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | (1 << 14)) };
                let pb = PathBeneath { allowed_access: allowed & all, parent_fd: fd };
                // SAFETY: rule struct valid for the call.
                unsafe {
                    libc::syscall(libc::SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb as *const PathBeneath, 0u32);
                    libc::close(fd);
                }
            }
            // SAFETY: plain prctl/syscall.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(rs as i32);
            }
            Ok(())
        }))
    }
}

impl ExecBackend for LandlockBackend {
    fn id(&self) -> &str {
        "landlock"
    }
    fn describe(&self) -> String {
        format!(
            "landlock: Landlock ABI {} file-system sandbox; workspace {} {}, network {}, home unreadable",
            self.abi,
            self.l.workspace.display(),
            if self.l.writable { "read-write" } else { "read-only" },
            if self.l.network { "allowed" } else { "TCP blocked" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut cmd = bash_command(req);
        if req.cwd.as_ref().is_none_or(|c| !c.starts_with(&self.l.workspace)) {
            cmd.current_dir(&self.l.workspace);
        }
        cmd.env("HOME", &self.l.tmp).env("TMPDIR", &self.l.tmp);
        spawn_command(cmd, req, Some(self.hook()?))
    }
    fn temp_dir(&self) -> String {
        self.l.tmp.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{drain, run_capture};
    use crate::testutil::tmpdir;
    use std::sync::Arc;

    fn req(script: &str) -> ExecRequest {
        ExecRequest { script: script.into(), ..Default::default() }
    }

    #[test]
    fn local_merged_output_exit_and_stdin() {
        let b = LocalBackend::new();
        let (st, out) = run_capture(&b, "echo out; echo err >&2; exit 4", None, Duration::from_secs(5)).unwrap();
        assert_eq!(st.code, Some(4));
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("out") && s.contains("err"));
        let (st, out) = run_capture(&b, "tr a-z A-Z", Some(b"hello"), Duration::from_secs(5)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("HELLO"));
        let mut c = b.spawn(&ExecRequest { stdin: true, ..req("read x; echo got=$x") }).unwrap();
        c.write_stdin(b"abc\n").unwrap();
        let (st, out) = drain(c, Duration::from_secs(5)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("got=abc"));
    }

    #[test]
    fn spawned_group_is_registered_for_the_reaper() {
        // Section C7: what a spawned command records so the kernel's reaper can decide later.
        let home = tmpdir("reaper-reg");
        let b = LocalBackend::new();
        let scope = reap_scope(&home, "s-reg", "shell");
        let mut c = b.spawn(&req("sleep 30")).unwrap();
        drop(scope);
        let pgid = c.pid().unwrap();
        let text = std::fs::read_to_string(home.join("reaper/procs.jsonl")).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().last().expect("one registry line")).unwrap();
        assert_eq!(line["pgid"], pgid);
        assert_eq!(line["session"], "s-reg");
        assert_eq!(line["tool"], "shell");
        assert_eq!(line["ark_pid"], std::process::id());
        assert_eq!(line["start"].as_u64(), proc_start_time(pgid), "the start time is what defeats PID reuse");
        c.kill(true);
        let _ = drain(c, Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn pty_is_a_terminal_and_resizes() {
        let b = LocalBackend::new();
        let mut c = b.spawn(&ExecRequest { pty: Some((24, 80)), stdin: true, ..req("[ -t 0 ] && echo TTY; stty size; read l; echo line=$l") }).unwrap();
        assert!(c.is_pty());
        c.write_stdin(b"zz\r").unwrap();
        let (st, out) = drain(c, Duration::from_secs(5)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.success() && s.contains("TTY") && s.contains("24 80") && s.contains("line=zz"), "{s}");
        let mut c = b.spawn(&ExecRequest { pty: Some((10, 20)), stdin: true, ..req("sleep 0.3; stty size") }).unwrap();
        c.resize(30, 100).unwrap();
        let (_, out) = drain(c, Duration::from_secs(5)).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("30 100"));
        let mut p = b.spawn(&req("true")).unwrap();
        assert!(p.resize(1, 1).is_err());
    }

    #[test]
    fn kill_and_detached_survival_files() {
        let b = LocalBackend::new();
        let mut c = b.spawn(&req("sleep 30")).unwrap();
        c.kill(true);
        let t = std::time::Instant::now();
        while c.try_wait().unwrap().is_none() && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(c.try_wait().unwrap().and_then(|e| e.signal), Some(9));

        let d = tmpdir("detach");
        let (log, exit) = (d.join("p.log"), d.join("p.exit"));
        let c = b.spawn(&ExecRequest { detach: true, log_file: Some(log.clone()), exit_file: Some(exit.clone()), ..req("echo one; sleep 0.2; echo two; exit 7") }).unwrap();
        let pid = c.pid().unwrap();
        let start = proc_start_time(pid);
        drop(c); // ark "restarts": the process keeps running
        let mut r = LocalChild::reattach(pid, start, &log, &exit, 0).unwrap();
        let (st, out) = drain(Box::new(LocalChild::reattach(pid, start, &log, &exit, 0).unwrap()), Duration::from_secs(5)).unwrap();
        assert_eq!(st.code, Some(7));
        assert!(String::from_utf8_lossy(&out).contains("one\ntwo"));
        assert_eq!(r.try_wait().unwrap().unwrap().code, Some(7));
    }

    #[test]
    fn credential_files_land_in_the_sandbox_layout() {
        // `Layout::binds` is what bwrap/landlock mount: a valid credential file is read-only,
        // an ssh key is refused, and nothing lands outside the sandbox home.
        let home = tmpdir("credlayout-home");
        std::fs::write(home.join("api-token"), "t").unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), "k").unwrap();
        let sb = SandboxConfig { workspace_access: "rw".into(), network: "host".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: tmpdir("credlayout-ws"), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: tmpdir("credlayout-ark"), sandboxed: true };
        let creds = vec!["api-token".to_string(), ".ssh/id_rsa".to_string(), "/etc/passwd".to_string()];
        let l = layout_with(&sb, &ctx, &creds, &home).unwrap();
        assert_eq!(l.binds, vec![(std::fs::canonicalize(home.join("api-token")).unwrap(), "/tmp/api-token".to_string(), true)], "{:?}", l.binds);
        assert!(layout_with(&sb, &ctx, &[], &home).unwrap().binds.is_empty(), "no configured files, no mounts");
        // Operator binds and credential binds coexist.
        let sb = SandboxConfig { workspace_access: "rw".into(), network: "host".into(), binds: vec!["/usr/share:/share:ro".into()], ..Default::default() };
        let l = layout_with(&sb, &ctx, &creds, &home).unwrap();
        assert!(l.binds.iter().any(|(_, dst, ro)| dst == "/share" && *ro) && l.binds.iter().any(|(_, dst, _)| dst == "/tmp/api-token"));
    }

    #[test]
    fn bwrap_hides_home_and_blocks_network() {
        if which("bwrap").is_none() || run_capture(&LocalBackend, "bwrap --unshare-user-try --ro-bind / / true", None, Duration::from_secs(5)).map(|r| !r.0.success()).unwrap_or(true) {
            eprintln!("skipping bwrap_hides_home_and_blocks_network: bwrap is not usable on this host (missing, or user namespaces disabled)");
            return;
        }
        let ws = tmpdir("bwrapws");
        // Trailing newline: `cat` is followed by more commands and the last line is asserted.
        std::fs::write(ws.join("f.txt"), "inside\n").unwrap();
        let home = tmpdir("bwraphome");
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: ws.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: home.clone(), sandboxed: true };
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        // Capabilities are dropped before the command runs.
        let a = b.args(&req("true"));
        assert!(a.windows(2).any(|w| w[0] == "--cap-drop" && w[1] == "ALL"), "{a:?}");
        assert!(a.iter().any(|x| x == "--unshare-net"), "{a:?}");
        let script = format!(
            "cat {}/f.txt; echo w > {}/new.txt; ls $HOME_REAL 2>&1 | head -1\n\
             echo ROUTE; cat /proc/net/route\n\
             echo IPROUTE; ip route 2>&1\n\
             echo DEV; cat /proc/net/dev\n\
             echo TCP; (exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo net-open || echo net-denied",
            ws.display(),
            ws.display()
        );
        let mut r = req(&script);
        r.env.push(("HOME_REAL".into(), std::env::var("HOME").unwrap_or_default()));
        r.cwd = Some(ws.clone());
        let (st, out) = drain(b.spawn(&r).unwrap(), Duration::from_secs(15)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.success() && s.contains("inside"), "{s}");
        assert!(ws.join("new.txt").exists(), "rw workspace");
        let section = |name: &str| -> String {
            let start = match s.find(&format!("\n{name}\n")) {
                Some(i) => i + name.len() + 2,
                None => return String::new(),
            };
            s[start..].split('\n').take_while(|l| !["ROUTE", "IPROUTE", "DEV", "TCP"].contains(l)).collect::<Vec<_>>().join("\n")
        };
        // No routes at all: /proc/net/route has only its header line.
        let route = section("ROUTE");
        let lines: Vec<&str> = route.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "only the /proc/net/route header, got {route:?}");
        assert!(lines[0].starts_with("Iface"), "{route:?}");
        // `ip route` prints nothing, and only loopback exists.
        assert_eq!(section("IPROUTE").trim(), "", "ip route must be empty in the sandbox");
        let dev = section("DEV");
        assert!(dev.contains("lo:") && !dev.contains("eth0") && !dev.contains("enp") && !dev.contains("wlan"), "only loopback: {dev:?}");
        // Opening a TCP connection to the outside fails.
        assert!(section("TCP").contains("net-denied"), "{s}");
        // ro
        let sb = SandboxConfig { workspace_access: "ro".into(), ..Default::default() };
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        let (st, _) = drain(b.spawn(&req(&format!("echo x > {}/ro.txt", ws.display()))).unwrap(), Duration::from_secs(10)).unwrap();
        assert!(!st.success() && !ws.join("ro.txt").exists());
        // none: real workspace invisible, scratch dir used.
        let sb = SandboxConfig::default();
        let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &ctx).unwrap();
        let (_, out) = drain(b.spawn(&req(&format!("cat {}/f.txt 2>&1; pwd", ws.display()))).unwrap(), Duration::from_secs(10)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("inside") && s.contains("sandboxes/t/workspace"), "{s}");
        assert!(b.describe().contains("network disabled"));
    }

    #[test]
    fn bwrap_network_probe_reports_an_unusable_netns() {
        // A bwrap binary that always fails stands in for a host without netns:
        // construction must refuse with a message naming `--unshare-net`.
        let d = tmpdir("bwrapfake");
        let bin = d.join("bwrap");
        std::fs::write(&bin, "#!/bin/sh\necho 'bwrap: Failed to unshare network namespace: Operation not permitted' >&2\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = BwrapConfig { binary: bin.display().to_string(), ..Default::default() };
        let e = probe_net_namespace(&cfg.binary).unwrap_err();
        assert!(e.contains("--unshare-net") && e.contains("exec.sandbox.network"), "{e}");
        let ctx = BackendCtx { workspace: d.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: d.clone(), sandboxed: true };
        let err = BwrapBackend::new(&cfg, &SandboxConfig::default(), &ctx).err().expect("network-none bwrap must refuse to build");
        assert!(err.contains("--unshare-net"), "{err}");
        // network = "host" is the documented way out; no probe is attempted.
        let host = SandboxConfig { network: "host".into(), ..Default::default() };
        assert!(BwrapBackend::new(&cfg, &host, &ctx).is_ok());
    }

    #[test]
    fn landlock_restricts_writes_and_home() {
        if landlock_abi() < 4 {
            eprintln!("skipping: landlock ABI {}", landlock_abi());
            return;
        }
        let ws = tmpdir("llws");
        let home = tmpdir("llhome");
        let outside = tmpdir("lloutside");
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: ws.clone(), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home, sandboxed: true };
        let b = LandlockBackend::new(&sb, &ctx).unwrap();
        let script = format!("echo ok > {ws}/in.txt && echo in-ok; echo bad > {out}/x.txt 2>/dev/null || echo out-denied; cat {out}/../ 2>/dev/null; (exec 3<>/dev/tcp/127.0.0.1/9 && echo net-open) 2>/dev/null || echo net-denied", ws = ws.display(), out = outside.display());
        let (_, out) = drain(b.spawn(&req(&script)).unwrap(), Duration::from_secs(10)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("in-ok") && s.contains("out-denied") && s.contains("net-denied"), "{s}");
        assert!(!outside.join("x.txt").exists());
    }
}
