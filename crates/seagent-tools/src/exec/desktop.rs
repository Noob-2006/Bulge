//! `desktop:<name>`: run tool calls inside the graphical desktop VM (`[desktop_vm]`), the
//! machine the person watches in the 工作區 live view and where `computer_use` and the browser
//! tools act — so the shell, the screen and the browser are one environment.
//!
//! * The commands go to the VM's guest agent (`seagent-vm-guest service`, running as the
//!   desktop user `seagent`) over the VM's agent channel, multiplexed so any number of
//!   sessions and tool calls run at once ([`seagent_vm::desktop::mux`]).
//! * The host workspace stays the source of truth: it is mirrored to
//!   `~/workspace/<name>-<hash>` in the VM before each command and what the command changed
//!   comes back after it ([`super::sync::WorkspaceSync`], the SSH backend's mirror), so the
//!   file tools and the shell see the same files. A command starts there unless it names
//!   another directory (a mapped workspace path, or any absolute path inside the VM).
//! * GUI programs a command starts appear on the VM's screen (`DISPLAY=:0`).
//!
//! Routing ([`route`]): for the operator's own (unsandboxed) sessions this is the default
//! whenever the desktop VM runs (`[exec] target = "auto"`); `host: "vm"` asks for it per call,
//! `host: "host"` / `"sandbox"` and `/exec host=` keep the previous behaviour. When the VM is
//! not running the call runs where it always did, with a one-line note in the result.

use super::sync::{SyncOptions, WorkspaceSync};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use seagent_vm::desktop::agent::{GUEST_HOME, GUEST_WORKSPACE};
use seagent_vm::desktop::mux::Mux;
use seagent_vm::desktop::DesktopVms;
use seagent_vm::proto::{GuestMsg, HostMsg};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// `[exec] target` values.
pub const TARGETS: &[&str] = &["auto", "desktop", "backend"];

/// Where one call asked to run (the shell tool's `host` parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The session's default: the desktop VM when it runs (operator sessions), else the backend.
    Auto,
    /// `host: "vm"` / `"desktop"`: the desktop VM, or an error saying why not.
    Desktop,
    /// `host: "host"` (or `elevated`): this machine, as before the desktop VM existed.
    Host,
    /// `host: "sandbox"` / `"gateway"`: the sandbox backend.
    Sandbox,
}

impl Target {
    pub fn from_host(host: Option<&str>) -> Target {
        match host {
            Some("vm" | "desktop") => Target::Desktop,
            Some("host" | "local") => Target::Host,
            Some("sandbox" | "gateway") => Target::Sandbox,
            _ => Target::Auto,
        }
    }
}

fn provider() -> &'static RwLock<Option<Arc<DesktopVms>>> {
    static P: OnceLock<RwLock<Option<Arc<DesktopVms>>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// The desktop VMs of this daemon (the binary installs them from `[desktop_vm]`). Without
/// this, nothing routes to a desktop VM.
pub fn install(vms: Arc<DesktopVms>) {
    *provider().write().unwrap() = Some(vms);
}

pub fn uninstall() {
    *provider().write().unwrap() = None;
}

pub fn installed() -> Option<Arc<DesktopVms>> {
    provider().read().unwrap().clone()
}

/// What [`route`] decided.
pub enum Route {
    /// Run in the desktop VM.
    Desktop(Arc<dyn ExecBackend>),
    /// The desktop VM would be the place but cannot take the call now: run in the usual
    /// backend and say so (once per session) with this note.
    Fallback(String),
    /// The desktop VM is not involved.
    Skip,
}

/// How long a running VM's agent may take to answer before an `auto` call runs elsewhere:
/// long right after boot (the agent starts with the desktop), short once it should be up.
fn agent_wait(vms: &DesktopVms, name: &str, explicit: bool) -> Duration {
    let booting = vms.status(name).started_at.is_some_and(|t| seagent_vm_now().saturating_sub(t) < 180);
    if booting {
        Duration::from_secs(120)
    } else if explicit {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(3)
    }
}

fn seagent_vm_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A recent failure to reach a VM's agent, so `auto` calls do not each wait for it again.
fn recent_failure(name: &str) -> Option<String> {
    let m = failures().lock().unwrap();
    m.get(name).filter(|(t, _)| t.elapsed() < Duration::from_secs(30)).map(|(_, e)| e.clone())
}

fn failures() -> &'static Mutex<HashMap<String, (Instant, String)>> {
    static F: OnceLock<Mutex<HashMap<String, (Instant, String)>>> = OnceLock::new();
    F.get_or_init(Default::default)
}

/// Decide where a call goes. `mode` is `[exec] target`; `sandboxed`: the session runs in the
/// sandbox (a non-operator session never lands on the operator's desktop by default, and may
/// not ask for it).
pub fn route(mode: &str, target: Target, sandboxed: bool, workspace: &Path) -> Result<Route, String> {
    route_with(installed(), mode, target, sandboxed, workspace)
}

pub fn route_with(vms: Option<Arc<DesktopVms>>, mode: &str, target: Target, sandboxed: bool, workspace: &Path) -> Result<Route, String> {
    let explicit = match target {
        Target::Host | Target::Sandbox => return Ok(Route::Skip),
        Target::Desktop => true,
        Target::Auto => false,
    };
    if sandboxed {
        return if explicit { Err("host=vm: this session is sandboxed; the desktop VM is the operator's own machine and only the operator's sessions run there".into()) } else { Ok(Route::Skip) };
    }
    if !explicit && (mode == "backend" || !cfg!(any(target_os = "windows", target_os = "macos", target_os = "linux"))) {
        return Ok(Route::Skip);
    }
    let Some(vms) = vms.filter(|v| v.cfg.enabled) else {
        return if explicit { Err("host=vm: no desktop VM here ([desktop_vm] enabled = false, or this process has none)".into()) } else { Ok(Route::Skip) };
    };
    let name = vms.cfg.default.clone();
    let note = |why: &str| format!("the desktop VM `{name}` {why} — this command ran outside it, on this machine's usual backend. Start it from the 工作區 view or with `seagent vm desktop start {name}`; once it runs, commands run inside it again.");
    if !vms.is_running(&name) {
        if explicit {
            return Err(format!("host=vm: the desktop VM `{name}` is not running (start it from the 工作區 view or with `seagent vm desktop start {name}`)"));
        }
        // Say it only where a desktop VM was set up (or asked for): a machine that never built
        // one is not nagged on every session.
        return Ok(if mode == "desktop" || vms.image_built() { Route::Fallback(note("is not running")) } else { Route::Skip });
    }
    if !explicit {
        if let Some(e) = recent_failure(&name) {
            return Ok(Route::Fallback(note(&format!("is running but its agent is not answering ({e})"))));
        }
    }
    match vms.channel(&name, agent_wait(&vms, &name, explicit)) {
        Ok(_) => {
            failures().lock().unwrap().remove(&name);
            Ok(Route::Desktop(backend_for(&vms, &name, workspace)))
        }
        Err(e) if explicit => Err(format!("host=vm: {e}")),
        Err(e) => {
            failures().lock().unwrap().insert(name.clone(), (Instant::now(), e.clone()));
            Ok(Route::Fallback(note(&format!("is running but its agent is not answering ({e})"))))
        }
    }
}

/// One backend per (VM, host workspace): the workspace mirror's state lives in it.
fn backend_for(vms: &Arc<DesktopVms>, name: &str, workspace: &Path) -> Arc<dyn ExecBackend> {
    type Backends = Mutex<HashMap<(PathBuf, String, PathBuf), Arc<DesktopBackend>>>;
    static B: OnceLock<Backends> = OnceLock::new();
    let key = (vms.run_dir(name), name.to_string(), workspace.to_path_buf());
    let mut m = B.get_or_init(Default::default).lock().unwrap();
    m.entry(key).or_insert_with(|| Arc::new(DesktopBackend::new(vms.clone(), name, workspace))).clone()
}

/// The mirror of `workspace` inside the VM: `~/workspace/<dir name>-<hash of the host path>`
/// (two host workspaces never share one, the person sees which project it is).
pub fn guest_root(workspace: &Path) -> String {
    let base: String = workspace.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default().chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).take(40).collect();
    let base = if base.is_empty() || base.starts_with('.') { "workspace".to_string() } else { base };
    let h = super::sync::common::crc32(workspace.to_string_lossy().as_bytes());
    format!("{GUEST_WORKSPACE}/{base}-{:06x}", h & 0xff_ffff)
}

/// Variables that describe the host and would mislead a command in the VM (its own home, user,
/// paths and X session come from the guest agent).
const HOST_ONLY: &[&str] = &["HOME", "USER", "LOGNAME", "SHELL", "PATH", "PWD", "OLDPWD", "TMPDIR", "TEMP", "TMP", "DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SEAGENT_HOME"];

/// The request's environment as it may reach the VM: no host-only variable, no value that is a
/// Windows path.
pub fn guest_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter().filter(|(k, v)| !HOST_ONLY.contains(&k.as_str()) && !(v.len() > 2 && v.as_bytes()[1] == b':' && matches!(v.as_bytes()[2], b'\\' | b'/') && v.as_bytes()[0].is_ascii_alphabetic())).cloned().collect()
}

struct Inner {
    vms: Arc<DesktopVms>,
    name: String,
    host_ws: PathBuf,
    remote: String,
    sync: WorkspaceSync,
}

impl Inner {
    fn mux(&self) -> io::Result<Arc<Mux>> {
        self.vms.channel(&self.name, Duration::from_secs(60)).map_err(io::Error::other)
    }
    /// The sync transport: one command in the VM, stdin in, merged output back.
    fn run(&self, script: &str, stdin: Option<&[u8]>) -> Result<(ExitInfo, Vec<u8>), String> {
        let m = self.mux().map_err(|e| e.to_string())?;
        let r = m.run(script, None, &[], stdin, Duration::from_secs(600))?;
        Ok((ExitInfo { code: r.code, signal: r.signal }, r.output))
    }
    fn pull(&self) -> Option<String> {
        let run = |s: &str, i: Option<&[u8]>| self.run(s, i);
        match self.sync.pull(&run) {
            Ok(r) if r.skipped.is_empty() => None,
            Ok(r) => Some(format!("workspace sync: {}", r.skipped.join("; "))),
            Err(e) => Some(e),
        }
    }
    /// Where a command starts inside the VM for the host-side `cwd`.
    fn guest_cwd(&self, cwd: Option<&Path>) -> String {
        let Some(c) = cwd else { return self.remote.clone() };
        if let Ok(rel) = c.strip_prefix(&self.host_ws) {
            let parts: Vec<String> = rel.components().map(|p| p.as_os_str().to_string_lossy().into_owned()).collect();
            return if parts.is_empty() { self.remote.clone() } else { format!("{}/{}", self.remote, parts.join("/")) };
        }
        let s = c.to_string_lossy();
        // An absolute path of the VM (the model saw it in an earlier result).
        if s.starts_with('/') && !s.contains('\\') {
            return s.into_owned();
        }
        self.remote.clone()
    }
}

pub struct DesktopBackend {
    inner: Arc<Inner>,
    id: String,
}

impl DesktopBackend {
    pub fn new(vms: Arc<DesktopVms>, name: &str, workspace: &Path) -> DesktopBackend {
        let remote = guest_root(workspace);
        let sync = WorkspaceSync::new(workspace, &remote, SyncOptions::default());
        DesktopBackend { inner: Arc::new(Inner { vms, name: name.into(), host_ws: workspace.to_path_buf(), remote, sync }), id: format!("desktop:{name}") }
    }
    /// The workspace mirror inside the VM.
    pub fn guest_root(&self) -> &str {
        &self.inner.remote
    }
}

impl ExecBackend for DesktopBackend {
    fn id(&self) -> &str {
        &self.id
    }
    fn describe(&self) -> String {
        format!(
            "desktop VM `{}`: commands run inside the graphical desktop VM the person watches (Debian + Xfce, user `seagent`, home {GUEST_HOME}; the workspace is mirrored at {} and synced both ways around every command; DISPLAY=:0, so GUI programs appear on its screen)",
            self.inner.name, self.inner.remote
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mux = self.inner.mux()?;
        let cwd = self.inner.guest_cwd(req.cwd.as_deref());
        let q = super::sh_quote;
        // A directory of the mirror may not exist yet (the mirror carries files, not empty
        // directories); any other directory of the VM must.
        let in_mirror = cwd == self.inner.remote || cwd.starts_with(&format!("{}/", self.inner.remote));
        let mk = if in_mirror { &cwd } else { &self.inner.remote };
        let script = format!("mkdir -p {} 2>/dev/null\ncd -- {} || exit 1\n{}", q(mk), q(&cwd), req.script);
        let (id, rx) = mux.open().map_err(io::Error::other)?;
        let stdin = req.stdin || req.stdin_data.is_some();
        let sent = mux
            .send(&HostMsg::Exec { id, script, cwd: Some(GUEST_HOME.into()), env: guest_env(&req.env), login: req.login, stdin, pty: req.pty, timeout_secs: 0 })
            .and_then(|_| match &req.stdin_data {
                Some(d) => mux.send_stdin(id, d).and_then(|_| if req.stdin { Ok(()) } else { mux.send(&HostMsg::Eof { id }) }),
                None => Ok(()),
            });
        if let Err(e) = sent {
            mux.close(id);
            return Err(io::Error::other(e));
        }
        self.inner.vms.mark_used(&self.inner.name);
        Ok(Box::new(DesktopChild { inner: self.inner.clone(), mux, id, rx, pending: VecDeque::new(), exit: None, pty: req.pty.is_some(), stdin: req.stdin, pulled: false }))
    }
    fn map_path(&self, host: &Path) -> String {
        self.inner.guest_cwd(Some(host))
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        true
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
    fn before_exec(&self) -> Result<(), String> {
        let run = |s: &str, i: Option<&[u8]>| self.inner.run(s, i);
        self.inner.sync.push(&run).map(|_| ())
    }
    fn after_exec(&self) -> Result<(), String> {
        self.inner.pull().map_or(Ok(()), Err)
    }
}

struct DesktopChild {
    inner: Arc<Inner>,
    mux: Arc<Mux>,
    id: u64,
    rx: Receiver<GuestMsg>,
    pending: VecDeque<u8>,
    exit: Option<ExitInfo>,
    pty: bool,
    /// The command's stdin is still open (it was started with one and not closed yet).
    stdin: bool,
    pulled: bool,
}

impl DesktopChild {
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = self.pending.len().min(buf.len());
        for (i, b) in self.pending.drain(..n).enumerate() {
            buf[i] = b;
        }
        n
    }
    fn handle(&mut self, m: GuestMsg) {
        use base64::Engine as _;
        match m {
            GuestMsg::Out { data, .. } => self.pending.extend(base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default()),
            GuestMsg::Exit { code, signal, .. } => self.finish(ExitInfo { code, signal }, None),
            // A control frame that raced the command's end (`Eof` / `Signal` / `Resize` for an
            // exec that just finished) is not the command failing.
            GuestMsg::Err { message, .. } if ["is not running", "has no stdin", "has no pty"].iter().any(|m| message.contains(m)) => {}
            GuestMsg::Err { message, .. } => self.finish(ExitInfo { code: Some(125), signal: None }, Some(format!("seagent desktop VM: {message}"))),
            _ => {}
        }
    }
    fn gone(&mut self) {
        let why = self.mux.error().unwrap_or_else(|| "the desktop VM channel closed".into());
        self.finish(ExitInfo { code: Some(125), signal: None }, Some(format!("seagent desktop VM: {why}")));
    }
    /// The command is over: bring its changes back into the host workspace (once), so the
    /// file tools see them as soon as the caller sees the exit.
    fn finish(&mut self, st: ExitInfo, note: Option<String>) {
        if let Some(n) = note {
            self.pending.extend(format!("{n}\n").into_bytes());
        }
        self.mux.close(self.id);
        if !self.pulled {
            self.pulled = true;
            if let Some(e) = self.inner.pull() {
                self.pending.extend(format!("\n[{e}]\n").into_bytes());
            }
        }
        self.exit = Some(st);
    }
}

impl ExecChild for DesktopChild {
    fn pid(&self) -> Option<u32> {
        None
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if self.pending.is_empty() && self.exit.is_none() {
            match self.rx.recv_timeout(timeout) {
                Ok(m) => self.handle(m),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => self.gone(),
            }
        }
        if !self.pending.is_empty() {
            return Ok(self.take(buf));
        }
        if self.exit.is_some() {
            return Ok(0);
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no output yet"))
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        self.mux.send_stdin(self.id, data).map_err(io::Error::other)
    }
    fn close_stdin(&mut self) {
        if self.stdin && self.exit.is_none() {
            self.stdin = false;
            let _ = self.mux.send(&HostMsg::Eof { id: self.id });
        }
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        while self.exit.is_none() {
            match self.rx.try_recv() {
                Ok(m) => self.handle(m),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => self.gone(),
            }
        }
        Ok(self.exit)
    }
    fn kill(&mut self, force: bool) {
        if self.exit.is_none() {
            let _ = self.mux.send(&HostMsg::Signal { id: self.id, force });
        }
    }
    fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        if !self.pty {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "this process has no terminal"));
        }
        self.mux.send(&HostMsg::Resize { id: self.id, rows, cols }).map_err(io::Error::other)
    }
    fn is_pty(&self) -> bool {
        self.pty
    }
}

impl Drop for DesktopChild {
    fn drop(&mut self) {
        if self.exit.is_none() {
            let _ = self.mux.send(&HostMsg::Signal { id: self.id, force: true });
        }
        self.mux.close(self.id);
    }
}

/// The usual backend, with the note why the desktop VM did not take the call (shown once per
/// session at the top of the shell result, `super::session_notice`).
pub struct Noted {
    pub inner: Arc<dyn ExecBackend>,
    pub note: String,
}

impl ExecBackend for Noted {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        self.inner.spawn(req)
    }
    fn fallback_note(&self) -> Option<String> {
        Some(match self.inner.fallback_note() {
            Some(n) => format!("{} {n}", self.note),
            None => self.note.clone(),
        })
    }
    fn map_path(&self, host: &Path) -> String {
        self.inner.map_path(host)
    }
    fn shares_host_fs(&self) -> bool {
        self.inner.shares_host_fs()
    }
    fn supports_pty(&self) -> bool {
        self.inner.supports_pty()
    }
    fn temp_dir(&self) -> String {
        self.inner.temp_dir()
    }
    fn before_exec(&self) -> Result<(), String> {
        self.inner.before_exec()
    }
    fn after_exec(&self) -> Result<(), String> {
        self.inner.after_exec()
    }
    fn cleanup(&self) {
        self.inner.cleanup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_values_name_the_target() {
        assert_eq!(Target::from_host(Some("vm")), Target::Desktop);
        assert_eq!(Target::from_host(Some("desktop")), Target::Desktop);
        assert_eq!(Target::from_host(Some("host")), Target::Host);
        assert_eq!(Target::from_host(Some("gateway")), Target::Sandbox);
        assert_eq!(Target::from_host(Some("auto")), Target::Auto);
        assert_eq!(Target::from_host(None), Target::Auto);
        // `[exec] target`: auto by default, checked when stated.
        assert_eq!(super::super::ExecConfig::default().target, "auto");
        assert_eq!(super::super::ExecConfig::parse(&serde_json::json!({"target": "backend"})).unwrap().target, "backend");
        assert!(super::super::ExecConfig::parse(&serde_json::json!({"target": "elsewhere"})).unwrap_err().contains("exec.target"));
    }

    #[test]
    fn the_mirror_paths_and_the_environment_suit_the_vm() {
        let r = guest_root(Path::new("/home/me/proj x"));
        assert!(r.starts_with("/home/seagent/workspace/proj_x-") && r.len() == "/home/seagent/workspace/proj_x-".len() + 6, "{r}");
        assert_ne!(guest_root(Path::new("/a/proj")), guest_root(Path::new("/b/proj")), "two workspaces never share a mirror");
        assert!(guest_root(Path::new("/")).starts_with("/home/seagent/workspace/workspace-"));
        let env = guest_env(&[("HOME".into(), "/home/me".into()), ("TMPDIR".into(), "/x".into()), ("CACHE".into(), r"C:\Users\me\cache".into()), ("FOO".into(), "bar".into()), ("URL".into(), "http://x".into())]);
        assert_eq!(env, vec![("FOO".to_string(), "bar".to_string()), ("URL".to_string(), "http://x".to_string())]);
    }

    #[cfg(unix)]
    fn tmp(tag: &str) -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new(&format!("seagent-desk-exec-{tag}"))
    }

    #[test]
    fn routing_defaults_to_the_vm_only_for_the_operator_and_never_silently_elsewhere() {
        let ws = Path::new("/tmp/ws");
        // No desktop VM in this process: nothing changes, an explicit ask says why.
        assert!(matches!(route_with(None, "auto", Target::Auto, false, ws), Ok(Route::Skip)));
        assert!(route_with(None, "auto", Target::Desktop, false, ws).err().unwrap().contains("no desktop VM"));
        for t in [Target::Host, Target::Sandbox] {
            assert!(matches!(route_with(None, "desktop", t, false, ws), Ok(Route::Skip)));
        }
        #[cfg(unix)]
        {
            let d = tmp("route");
            let vms = Arc::new(seagent_vm::desktop::fake::fake_vms(d.path()));
            // A sandboxed (non-operator) session never lands on the operator's desktop.
            assert!(matches!(route_with(Some(vms.clone()), "auto", Target::Auto, true, ws), Ok(Route::Skip)));
            assert!(route_with(Some(vms.clone()), "auto", Target::Desktop, true, ws).err().unwrap().contains("sandboxed"));
            // Built but not running: the call runs as before, with the note.
            match route_with(Some(vms.clone()), "auto", Target::Auto, false, ws) {
                Ok(Route::Fallback(n)) => assert!(n.contains("not running") && n.contains("seagent vm desktop start desk"), "{n}"),
                _ => panic!("expected a fallback note"),
            }
            assert!(route_with(Some(vms.clone()), "auto", Target::Desktop, false, ws).err().unwrap().contains("not running"));
            assert!(matches!(route_with(Some(vms.clone()), "backend", Target::Auto, false, ws), Ok(Route::Skip)), "target = backend");
            // Never set up: no nagging, unless target = desktop asks for it.
            std::fs::remove_file(vms.image_path()).unwrap();
            assert!(matches!(route_with(Some(vms.clone()), "auto", Target::Auto, false, ws), Ok(Route::Skip)));
            assert!(matches!(route_with(Some(vms.clone()), "desktop", Target::Auto, false, ws), Ok(Route::Fallback(_))));
            let off = Arc::new(DesktopVms::new(seagent_vm::desktop::DesktopConfig { enabled: false, ..vms.cfg.clone() }, &d.join("data"), &d.join("cache"), &d.join("run")));
            assert!(matches!(route_with(Some(off), "desktop", Target::Auto, false, ws), Ok(Route::Skip)), "[desktop_vm] enabled = false");
        }
    }

    #[cfg(unix)]
    #[test]
    fn commands_run_in_the_vm_and_the_workspace_is_mirrored_both_ways() {
        let d = tmp("flow");
        let vms = Arc::new(seagent_vm::desktop::fake::fake_vms(d.path()));
        let _qmp = seagent_vm::desktop::fake::start_fake(&vms, d.path(), "desk", 800, 600);
        let home = d.join("guest-home");
        std::fs::create_dir_all(&home).unwrap();
        let _agent = seagent_vm::desktop::fake::fake_agent(&vms, "desk", &home);
        let ws = d.join("proj");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("in.txt"), "from host\n").unwrap();
        let b = match route_with(Some(vms.clone()), "auto", Target::Auto, false, &ws).unwrap() {
            Route::Desktop(b) => b,
            _ => panic!("a running desktop VM takes the operator's commands"),
        };
        assert_eq!(b.id(), "desktop:desk");
        assert!(super::super::session::script_shell(&*b).is_posix(), "bash in the VM, whatever the host shell");
        assert!(!b.shares_host_fs() && b.describe().contains("DISPLAY=:0"));
        let root = guest_root(&ws);
        assert_eq!(b.map_path(&ws.join("src")), format!("{root}/src"));
        let run = |script: &str, cwd: Option<PathBuf>, stdin: Option<&[u8]>| {
            b.before_exec().unwrap();
            let req = ExecRequest { script: script.into(), cwd, env: vec![("HOME".into(), "/host/home".into()), ("FOO".into(), "bar".into())], stdin_data: stdin.map(|s| s.to_vec()), ..Default::default() };
            super::super::drain(b.spawn(&req).unwrap(), Duration::from_secs(20)).unwrap()
        };
        let (st, out) = run("cat in.txt; echo made > out.txt; mkdir -p gen && echo deep > gen/x.txt; pwd; echo \"$FOO $HOME\"", Some(ws.clone()), None);
        let out = String::from_utf8_lossy(&out).into_owned();
        assert!(st.success(), "{st:?} {out}");
        let guest_root_here = root.replace(GUEST_HOME, &home.display().to_string());
        assert!(out.contains("from host") && out.contains(&guest_root_here), "pushed, and run in the mirror: {out}");
        assert!(out.contains(&format!("bar {}", home.display())), "the VM's own HOME, not the host's: {out}");
        // What the command made is back on the host when the caller sees the exit.
        assert_eq!(std::fs::read_to_string(ws.join("out.txt")).unwrap(), "made\n");
        assert_eq!(std::fs::read_to_string(ws.join("gen/x.txt")).unwrap(), "deep\n");
        // A sub-directory cwd, and stdin.
        let (_, out) = run("pwd; cat", Some(ws.join("src")), Some(b"typed in"));
        let out = String::from_utf8_lossy(&out).into_owned();
        assert!(out.contains(&format!("{guest_root_here}/src")) && out.ends_with("typed in"), "{out}");
        // Exit codes and a missing directory come back as such.
        assert_eq!(run("exit 7", None, None).0.code, Some(7));
        let (st, out) = run("true", Some(PathBuf::from("/nonexistent/dir")), None);
        assert_eq!(st.code, Some(1), "{}", String::from_utf8_lossy(&out));
        // Several commands at once over the one channel.
        let ts: Vec<_> = (0..4)
            .map(|i| {
                let b = b.clone();
                std::thread::spawn(move || super::super::drain(b.spawn(&ExecRequest { script: format!("sleep 0.2; echo n{i}"), ..Default::default() }).unwrap(), Duration::from_secs(20)).unwrap())
            })
            .collect();
        for (i, t) in ts.into_iter().enumerate() {
            assert_eq!(String::from_utf8_lossy(&t.join().unwrap().1).trim(), format!("n{i}"));
        }
        // kill reaches the command in the VM.
        let mut c = b.spawn(&ExecRequest { script: "sleep 30".into(), ..Default::default() }).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        c.kill(true);
        let t0 = Instant::now();
        let st = loop {
            if let Some(st) = c.try_wait().unwrap() {
                break st;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "killed command never ended");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!st.success());
        vms.stop("desk").unwrap();
    }
}
