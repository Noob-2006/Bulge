//! `exec.backend = "vm"` / `[exec.sandbox] backend = "vm"`: run tool calls in
//! the microVM from [`seagent_vm`] (B1). This file is deliberately thin — the VM
//! lifecycle, snapshots, trust tiers and the broker live in `seagent-vm`; here we
//! only adapt it to [`ExecBackend`]/[`ExecChild`] and to seagent's session model.
//!
//! Two behaviours worth knowing:
//! * When no VM can boot, `describe()` and [`VmBackend::isolation`] carry the
//!   *explicit* warning and `spawn` delegates to the bwrap backend (namespace
//!   isolation), never to `local`. Run `seagent sandbox explain` to see the level.
//! * The child streams the guest's output frames; a `Broker` frame is answered
//!   inline through the installed broker (A2/A3), so a program inside the VM can
//!   request egress but can never open a socket itself.

use super::sandbox::SandboxConfig;
use super::{sh_quote, BackendCtx};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use seagent_vm::isolation::IsolationLevel;
use seagent_vm::pool::{Broker, BrokerFrom, VmExec, VmManager, VmSession};
use seagent_vm::proto::{GuestMsg, HostMsg};
use seagent_vm::trust::TrustTier;
use seagent_vm::VmConfig;
use serde_json::Value;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// Sessions whose work is the operator's own vs. work triggered from outside
/// (B5). Installed by the binary; without it the sandboxed/main distinction is
/// used, which is the conservative direction (a non-main session is never
/// treated as the owner).
pub type TierClassifier = Arc<dyn Fn(&str) -> TrustTier + Send + Sync>;

fn tier_classifier() -> &'static RwLock<Option<TierClassifier>> {
    static C: OnceLock<RwLock<Option<TierClassifier>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

pub fn set_tier_classifier(c: TierClassifier) {
    *tier_classifier().write().unwrap() = Some(c);
}

fn tier_of(session: &str, main: bool) -> TrustTier {
    match tier_classifier().read().unwrap().as_ref() {
        Some(c) => c(session),
        None if main => TrustTier::Owner,
        None => TrustTier::Channel,
    }
}

/// Which tool is acting right now, on this thread (A5).
///
/// The daemon knows the tool that called `spawn`, but the guest's `seagent-broker` request
/// arrives later on the same thread that is pumping the child's frames — so a thread-local
/// set by the tool wrapper ([`super::sandbox`]) attributes every broker request to the
/// component that caused it. A program inside the VM can never name itself.
pub fn with_component<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let prev = CURRENT.with(|c| c.borrow_mut().replace(name.to_string()));
    let out = f();
    CURRENT.with(|c| *c.borrow_mut() = prev);
    out
}

thread_local! {
    /// The tool acting on this thread (see [`with_component`]).
    static CURRENT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The component acting on this thread; `vm` when nothing named itself (a background job, a
/// program started by an earlier call) — that manifest may run commands but may not have a
/// named secret injected, so the fallback is narrower than a tool's.
pub fn current_component() -> String {
    CURRENT.with(|c| c.borrow().clone()).unwrap_or_else(|| "vm".into())
}

/// One manager per seagent data dir (so `seagent sandbox vm status` sees every VM and a
/// session reuses its VM across tool calls).
fn registry() -> &'static Mutex<std::collections::HashMap<PathBuf, Arc<VmManager>>> {
    static R: OnceLock<Mutex<std::collections::HashMap<PathBuf, Arc<VmManager>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

pub fn manager_for(cfg: &VmConfig, data: &Path) -> Arc<VmManager> {
    let mut reg = registry().lock().unwrap();
    reg.entry(data.to_path_buf()).or_insert_with(|| Arc::new(VmManager::new(cfg.clone(), data.to_path_buf()))).clone()
}

/// Install the daemon-side broker (A2/A3/A4). Without one, a VM's broker
/// requests are refused with a clear message — failing closed.
pub fn set_broker(b: Arc<dyn Broker>) {
    for m in registry().lock().unwrap().values() {
        m.set_broker(b.clone());
    }
    *pending_broker().write().unwrap() = Some(b);
}

fn pending_broker() -> &'static RwLock<Option<Arc<dyn Broker>>> {
    static B: OnceLock<RwLock<Option<Arc<dyn Broker>>>> = OnceLock::new();
    B.get_or_init(Default::default)
}

/// Every live VM, for `seagent sandbox vm status` / `seagent doctor`.
pub fn statuses() -> Vec<(PathBuf, Vec<seagent_vm::pool::VmStatus>)> {
    registry().lock().unwrap().iter().map(|(k, m)| (k.clone(), m.status())).collect()
}

/// Stop idle VMs across every manager (called from the scheduler tick).
pub fn gc_idle() -> usize {
    registry().lock().unwrap().values().map(|m| m.gc_idle()).sum()
}

/// [`Broker`] that forwards a guest request to the daemon-side broker socket
/// (`seagent security broker`, A2/A3/A4): one JSON line per request, one per reply.
///
/// Mapping (B's kinds → A's ops), so neither side needs the other's crate:
/// * `egress.http`  → `{"op":"egress","method":…,"url":…,"headers":…,"body_b64":…}`
///   (the guest may state `"scheme"`; without one, port 443 is HTTPS and anything else HTTP)
/// * `priv.exec`    → `{"op":"exec","argv":[…]}` (argv only: no shell strings)
/// * `secret.sign`  → refused (the daemon has no signing op yet)
///
/// A's reply is `{"id":..,"ok":true,"result":{…}}` or `{"ok":false,"error":{…}}`;
/// errors are relayed to the guest verbatim so a tool can explain itself.
pub struct SocketBroker {
    path: PathBuf,
    timeout: Duration,
}

impl SocketBroker {
    pub fn new(path: impl Into<PathBuf>) -> SocketBroker {
        SocketBroker { path: path.into(), timeout: Duration::from_secs(130) }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn call(&self, op: Value) -> Result<Value, String> {
        use std::io::{BufRead, BufReader, Write};
        // The broker's own client: the unix socket on Unix (same connect, same message:
        // "daemon broker <path>: <err>"); elsewhere the loopback endpoint + token that
        // `seagent_security::broker` writes at `path`.
        let mut sock = seagent_security::broker::connect(&self.path).map_err(|e| format!("daemon {e}"))?;
        sock.set_read_timeout(Some(self.timeout)).ok();
        sock.write_all(format!("{op}\n").as_bytes()).map_err(|e| format!("broker write: {e}"))?;
        sock.flush().ok();
        let mut line = String::new();
        BufReader::new(sock).read_line(&mut line).map_err(|e| format!("broker read: {e}"))?;
        let v: Value = serde_json::from_str(&line).map_err(|e| format!("broker reply is not JSON: {e}"))?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["result"].clone())
        } else {
            let code = v["error"]["code"].as_str().unwrap_or("error");
            let msg = v["error"]["message"].as_str().unwrap_or("refused");
            Err(format!("{code}: {msg}"))
        }
    }
}

impl Broker for SocketBroker {
    fn handle(&self, kind: &str, payload: Value) -> Result<Value, String> {
        self.handle_as("vm", kind, payload)
    }
    fn handle_as(&self, component: &str, kind: &str, payload: Value) -> Result<Value, String> {
        self.handle_from(BrokerFrom { component, session: "" }, kind, payload)
    }
    fn handle_from(&self, from: BrokerFrom<'_>, kind: &str, payload: Value) -> Result<Value, String> {
        let component = from.component;
        let session = from.session;
        match kind {
            "egress.http" => {
                let host = payload["host"].as_str().ok_or("egress.http needs a host")?;
                let path = payload["path"].as_str().unwrap_or("/");
                // The guest states the scheme when it matters (a dev server on :8080 is plain
                // HTTP); otherwise the port decides, and 443 is the only port seagent assumes TLS.
                let scheme = match payload["scheme"].as_str() {
                    Some(s @ ("http" | "https")) => s,
                    _ => match payload["port"].as_u64() {
                        // No port stated, or the TLS port: HTTPS. Any other explicit port is
                        // plain HTTP (a dev server on :8080), which is why the guest may say.
                        None | Some(443) => "https",
                        _ => "http",
                    },
                };
                let port = payload["port"].as_u64().map(|p| if p == 443 || p == 80 { String::new() } else { format!(":{p}") }).unwrap_or_default();
                let op = serde_json::json!({
                    "op": "egress",
                    "component": component,
                    "session": session,
                    "method": payload["method"].as_str().unwrap_or("GET"),
                    "url": format!("{scheme}://{host}{port}{path}"),
                    "headers": payload.get("headers").cloned().unwrap_or(serde_json::json!({})),
                    "body_b64": payload.get("body_b64").cloned().unwrap_or(Value::Null),
                });
                let r = self.call(op)?;
                Ok(serde_json::json!({
                    "status": r["code"].as_u64().unwrap_or(0),
                    "headers": r.get("headers").cloned().unwrap_or(serde_json::json!({})),
                    "body_b64": r.get("body_b64").cloned().unwrap_or(Value::Null),
                }))
            }
            "priv.exec" => {
                let mut argv: Vec<String> = Vec::new();
                if let Some(c) = payload["cmd"].as_str() {
                    argv.push(c.to_string());
                }
                for a in payload["args"].as_array().into_iter().flatten() {
                    if let Some(s) = a.as_str() {
                        argv.push(s.to_string());
                    }
                }
                if argv.is_empty() {
                    return Err("priv.exec needs cmd + args (argv only, no shell strings)".into());
                }
                let r = self.call(serde_json::json!({"op": "exec", "component": component, "session": session, "argv": argv}))?;
                Ok(r)
            }
            other => Err(format!("`{other}` is not supported by the daemon broker (only egress.http and priv.exec)")),
        }
    }
}

/// Install a [`SocketBroker`] for every VM manager in this process.
pub fn install_socket_broker(path: impl Into<PathBuf>) {
    let path = path.into();
    *installed().write().unwrap() = Some(path.clone());
    set_broker(Arc::new(SocketBroker::new(path)));
}

fn installed() -> &'static RwLock<Option<PathBuf>> {
    static P: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// The daemon broker socket this process installed, if any (for `seagent doctor`, the explain
/// output and the tests that check the daemon wired it up).
pub fn installed_broker() -> Option<PathBuf> {
    installed().read().unwrap().clone()
}

pub struct VmBackend {
    mgr: Arc<VmManager>,
    cfg: VmConfig,
    session: String,
    workspace: PathBuf,
    scope_key: String,
    main: bool,
    read_only: bool,
    /// Namespace fallback, used when no microVM can boot here.
    /// (bwrap on Linux / Android, Seatbelt on macOS; none in this build on Windows.)
    fallback: Option<Arc<dyn ExecBackend>>,
    isolation: IsolationLevel,
    warning: Option<String>,
    /// `vm`, or `vm:<fallback>` naming the sandbox that really runs (`vm:bwrap` on Linux,
    /// `vm:appcontainer` on Windows, `vm:seatbelt` on macOS).
    id: String,
}

impl VmBackend {
    pub fn new(cfg: &VmConfig, sb: &SandboxConfig, ctx: &BackendCtx, main: bool) -> Result<VmBackend, String> {
        cfg.validate()?;
        let mgr = manager_for(cfg, &ctx.home);
        if let Some(b) = pending_broker().read().unwrap().clone() {
            mgr.set_broker(b);
        }
        let (kind, warning) = mgr.selection();
        let isolation = kind.isolation();
        let fallback_name = if cfg!(any(target_os = "linux", target_os = "android")) {
            "bwrap"
        } else if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "appcontainer"
        };
        let fallback = if kind.is_vm() {
            None
        } else {
            // Explicit, logged downgrade: the same OS sandbox seagent already had (bwrap).
            let name = fallback_name;
            let mut cfg = super::global().cfg.clone();
            cfg.sandbox = sb.clone();
            Some(super::os_sandbox(name, &cfg, ctx)?)
        };
        let tier = tier_of(&ctx.scope_key, !ctx.sandboxed);
        // Same rule as the bwrap layout: `workspace_access = "none"` means a
        // private scratch copy, not the project. B5 adds: an untrusted tier
        // never gets the operator's workspace, whatever the policy says.
        let workspace = if tier == TrustTier::Untrusted || (ctx.sandboxed && sb.workspace_access == "none") {
            let w = sb.scratch_workspace(&ctx.home, &ctx.scope_key);
            std::fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
            w
        } else {
            ctx.workspace.clone()
        };
        Ok(VmBackend {
            mgr,
            cfg: cfg.clone(),
            session: ctx.scope_key.clone(),
            workspace,
            scope_key: ctx.scope_key.clone(),
            main,
            read_only: cfg.workspace_readonly(&ctx.workspace),
            fallback,
            isolation,
            warning,
            id: if kind.is_vm() { "vm".into() } else { format!("vm:{fallback_name}") },
        })
    }
    pub fn isolation(&self) -> IsolationLevel {
        self.isolation
    }
    pub fn tier(&self) -> TrustTier {
        tier_of(&self.session, self.main)
    }
    /// The workspace a VM of this tier may see (untrusted tiers get a private
    /// scratch copy, B5).
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
    /// Snapshot the workspace now (undo point); `None` when this backend is the
    /// namespace fallback.
    pub fn snapshot(&self, reason: &str) -> Result<Option<seagent_vm::snapshot::SnapshotMeta>, String> {
        if self.fallback.is_some() {
            return Ok(None);
        }
        self.mgr.snapshot(&self.session, self.tier(), &self.workspace, reason).map(Some)
    }
    pub fn restore(&self, name: Option<&str>) -> Result<Option<seagent_vm::snapshot::SnapshotMeta>, String> {
        if self.fallback.is_some() {
            return Ok(None);
        }
        self.mgr.restore(&self.session, self.tier(), &self.workspace, name).map(Some)
    }
    pub fn snapshots(&self) -> Vec<seagent_vm::snapshot::SnapshotMeta> {
        self.mgr.snapshots(&self.session, self.tier(), &self.workspace)
    }
    fn request(&self, req: &ExecRequest) -> VmExec {
        let mut e = VmExec::new(&self.session, self.tier(), &self.workspace, &req.script);
        e.cwd = req.cwd.clone();
        e.env = req.env.clone();
        e.login = req.login;
        e.stdin = req.stdin;
        e.pty = req.pty;
        e.timeout = Duration::from_secs(self.cfg.exec_timeout_secs.max(super::global().cfg.default_timeout));
        e
    }
}

impl ExecBackend for VmBackend {
    fn id(&self) -> &str {
        &self.id
    }
    fn describe(&self) -> String {
        match (&self.fallback, &self.warning) {
            (Some(f), Some(w)) => format!("vm: microVM unavailable, running in {} ({}). {w}", sandbox_kind(), f.id()),
            (Some(f), None) => format!("vm: microVM unavailable, running in {} ({})", sandbox_kind(), f.id()),
            (None, Some(w)) => format!("vm: {} ({} isolation); {w}", self.mgr.status().iter().map(|s| s.provider.clone()).next().unwrap_or_else(|| "microVM".into()), self.isolation.label()),
            (None, None) => format!(
                "vm: commands run inside a microVM ({} isolation) with a {} copy of the workspace; no host socket, no keys, snapshots on",
                self.isolation.label(),
                if self.read_only { "read-only" } else { "writable" }
            ),
        }
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        if let Some(f) = &self.fallback {
            return f.spawn(req);
        }
        let e = self.request(req);
        let sess = self.mgr.spawn(&e).map_err(|err| io::Error::other(format!("seagent vm: {err}")))?;
        Ok(Box::new(VmChild { mgr: self.mgr.clone(), sess, pending: VecDeque::new(), exit: None, component: current_component(), session: self.session.clone() }))
    }
    fn fallback_note(&self) -> Option<String> {
        self.fallback.as_ref().map(|_| format!("{} Fix: {} (or set exec.vm.kernel / initramfs).", self.describe(), seagent_vm::bundle::fix_hint()))
    }
    fn map_path(&self, host: &Path) -> String {
        match host.strip_prefix(&self.workspace) {
            Ok(rel) if !rel.as_os_str().is_empty() => format!("{}/{}", seagent_vm::proto::GUEST_WORKSPACE, rel.display()),
            _ => seagent_vm::proto::GUEST_WORKSPACE.into(),
        }
    }
    fn shares_host_fs(&self) -> bool {
        self.fallback.is_some()
    }
    fn supports_pty(&self) -> bool {
        true
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
    fn cleanup(&self) {
        // Session over: drop its VM (snapshots stay).
        let key_prefix = format!("{}-", self.tier().vm_key(&self.session, &self.cfg));
        let keys: Vec<String> = self.mgr.status().into_iter().map(|s| s.key).filter(|k| k.starts_with(&key_prefix)).collect();
        for k in keys {
            self.mgr.stop(&k);
        }
        let _ = &self.scope_key;
    }
}

/// What the no-VM fallback is, in words: namespaces (bwrap) on Linux / Android, the OS's
/// policy sandbox (AppContainer, Seatbelt) elsewhere.
fn sandbox_kind() -> &'static str {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        "a namespace sandbox"
    } else {
        "an OS policy sandbox"
    }
}

struct VmChild {
    mgr: Arc<VmManager>,
    sess: VmSession,
    /// Decoded bytes not yet handed to the caller.
    pending: VecDeque<u8>,
    exit: Option<ExitInfo>,
    /// The tool that spawned this command (A5): its manifest governs what the guest may ask
    /// the broker for, and a program inside the VM cannot change it.
    component: String,
    /// The session this VM belongs to (its scope key, e.g. `s-main`): the broker queues an
    /// approval for that session and applies *its* task envelope (§0-2 #01/#03).
    session: String,
}

impl VmChild {
    fn collect(&mut self, buf: &mut [u8]) -> usize {
        let n = self.pending.len().min(buf.len());
        for (i, b) in self.pending.drain(..n).enumerate() {
            buf[i] = b;
        }
        n
    }
    /// Read one frame, answering broker requests on the way.
    fn pump(&mut self, timeout: Duration) -> io::Result<Option<()>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.sess.chan.recv(left) {
                Ok(Some(GuestMsg::Out { id, data })) if id == self.sess.id => {
                    if let Ok(b) = B64.decode(&data) {
                        self.pending.extend(b);
                    }
                    return Ok(Some(()));
                }
                Ok(Some(GuestMsg::Exit { id, code, signal })) if id == self.sess.id => {
                    self.exit = Some(ExitInfo { code, signal });
                    let _ = self.mgr.finish(&mut self.sess);
                    return Ok(None);
                }
                Ok(Some(GuestMsg::Err { id, message })) if id == self.sess.id => {
                    self.pending.extend(format!("seagent vm: {message}\n").into_bytes());
                    self.exit = Some(ExitInfo { code: Some(125), signal: None });
                    let _ = self.mgr.finish(&mut self.sess);
                    return Ok(None);
                }
                Ok(Some(GuestMsg::Broker { id, kind, payload })) => {
                    let reply = match self.mgr.broker() {
                        Some(b) => b.handle_from(BrokerFrom { component: &self.component, session: &self.session }, &kind, payload),
                        None => Err("this seagent instance has no broker: the VM may not reach the network".into()),
                    };
                    let m = match reply {
                        Ok(p) => HostMsg::BrokerReply { id, ok: true, payload: p },
                        Err(e) => HostMsg::BrokerReply { id, ok: false, payload: serde_json::json!({"error": e}) },
                    };
                    self.sess.send(&m).map_err(io::Error::other)?;
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return Ok(Some(()));
                    }
                }
                Err(e) => return Err(io::Error::other(format!("seagent vm channel: {e}"))),
            }
        }
    }
}

impl ExecChild for VmChild {
    fn pid(&self) -> Option<u32> {
        None
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if !self.pending.is_empty() {
            return Ok(self.collect(buf));
        }
        if self.exit.is_some() {
            return Ok(0);
        }
        self.pump(timeout)?;
        Ok(self.collect(buf))
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        self.sess.send(&HostMsg::Stdin { id: self.sess.id, data: B64.encode(data) }).map_err(io::Error::other)
    }
    fn close_stdin(&mut self) {
        let _ = self.sess.send(&HostMsg::Eof { id: self.sess.id });
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        if self.exit.is_none() {
            let _ = self.pump(Duration::from_millis(50));
        }
        Ok(self.exit)
    }
    fn kill(&mut self, force: bool) {
        if self.exit.is_none() {
            let _ = self.sess.send(&HostMsg::Signal { id: self.sess.id, force });
        }
    }
    fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        self.sess.send(&HostMsg::Resize { id: self.sess.id, rows, cols }).map_err(io::Error::other)
    }
    fn is_pty(&self) -> bool {
        false
    }
}

impl Drop for VmChild {
    fn drop(&mut self) {
        if self.exit.is_none() {
            let _ = self.sess.send(&HostMsg::Signal { id: self.sess.id, force: true });
        }
        self.sess.release();
    }
}

/// The command a guest-side program uses to ask the daemon for egress/privileged
/// work (`/usr/bin/seagent-broker` in the image).
pub fn broker_hint(kind: &str, payload_json: &str) -> String {
    format!("seagent-broker {}", sh_quote(&serde_json::json!({"kind": kind, "payload": payload_json}).to_string()))
}

/// For the system prompt / `seagent sandbox explain`: one line about the VM.
pub fn summary_line() -> String {
    let reg = registry().lock().unwrap();
    match reg.values().next() {
        Some(m) => {
            let (kind, warning) = m.selection();
            let status = m.status();
            let running = status.iter().filter(|s| s.running).count();
            format!("exec backend vm: {} provider `{}` ({}) — {} running VM(s){}", m.data_dir().display(), kind.name(), kind.isolation().label(), running, warning.map(|w| format!("; {w}")).unwrap_or_default())
        }
        None => "exec backend vm: no VM started in this process yet".into(),
    }
}

/// Keys of the VMs this process has started (tests, `seagent sandbox vm status`).
pub fn vm_keys(mgr: &VmManager) -> Vec<String> {
    mgr.status().into_iter().map(|s| s.key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sandbox::SandboxConfig;
    use crate::exec::{ExecConfig, ExecRequest};
    use seagent_vm::pool::VmManager;

    /// The tier classifier is process-global; tests that change it hold this.
    fn tier_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ctx(tag: &str) -> BackendCtx {
        let base = seagent_core::tmp::scratch_path(format!("seagent-vm-backend-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(base.join("ws")).unwrap();
        std::fs::create_dir_all(base.join("home")).unwrap();
        BackendCtx { workspace: base.join("ws"), scope_key: format!("s-{tag}"), secrets: Arc::new(|s: &str| s.to_string()), home: base.join("home"), sandboxed: true }
    }

    fn image(home: &Path) -> VmConfig {
        // A fake image: the backend decides what to run from `selection()`, which
        // needs the boot files to exist before it will call itself a microVM.
        let k = home.join("vmlinux");
        let i = home.join("initramfs.cpio.gz");
        std::fs::write(&k, b"x").unwrap();
        std::fs::write(&i, b"x").unwrap();
        VmConfig { kernel: k.display().to_string(), initramfs: i.display().to_string(), ..Default::default() }
    }

    #[test]
    fn the_vm_backend_is_a_registered_backend_and_config_is_validated() {
        assert!(crate::exec::BACKENDS.contains(&"vm"), "`exec.backend = \"vm\"` must be accepted");
        let c = ExecConfig::parse(&serde_json::json!({"backend": "vm"})).unwrap();
        assert_eq!(c.backend, "vm");
        assert_eq!(c.vm.provider, "auto");
        assert!(ExecConfig::parse(&serde_json::json!({"vm": {"vcpu": 0}})).is_err(), "bad [exec.vm] values are refused, not clamped");
        assert_eq!(seagent_vm::isolation::isolation_of_backend("vm"), seagent_vm::IsolationLevel::MicroVm);
    }

    #[test]
    fn without_a_microvm_the_backend_falls_back_to_namespaces_and_says_so() {
        let c = ctx("fallback");
        let vm = VmConfig { provider: "bwrap".into(), kernel: String::new(), initramfs: String::new(), allow_fallback: true, ..Default::default() };
        vm.validate().unwrap();
        let b = VmBackend::new(&vm, &SandboxConfig { mode: "all".into(), ..Default::default() }, &c, true).unwrap();
        // Named after the sandbox that really runs: bwrap on Linux, AppContainer on Windows,
        // Seatbelt on macOS (Windows used to call its AppContainer fallback "bwrap").
        let want = if cfg!(any(target_os = "linux", target_os = "android")) { "vm:bwrap" } else if cfg!(target_os = "macos") { "vm:seatbelt" } else { "vm:appcontainer" };
        assert_eq!(b.id(), want, "an explicit weaker level is labelled as such");
        assert!(b.isolation() <= seagent_vm::IsolationLevel::UserNamespace);
        assert!(b.describe().contains(if cfg!(any(target_os = "linux", target_os = "android")) { "namespace sandbox" } else { "OS policy sandbox" }), "{}", b.describe());
        assert!(b.shares_host_fs(), "bwrap shares the host file system (bind mounts)");
        // Never silent: the first command of a session says it, later ones do not.
        let note = b.fallback_note().expect("a fallback announces itself");
        assert!(note.contains("microVM unavailable") && note.contains("seagent sandbox vm image build"), "{note}");
        let session = format!("fallback-notice-{}", std::process::id());
        let first = crate::exec::session_notice(&session, &b).expect("once per session");
        assert!(first.starts_with("[seagent warning]"), "{first}");
        assert_eq!(crate::exec::session_notice(&session, &b), None, "said once");
        assert!(crate::exec::session_notice(&format!("{session}-other"), &b).is_some(), "another session hears it too");
        // The script is written for the shell that really runs it: PowerShell in the Windows
        // AppContainer, POSIX for bwrap and Seatbelt.
        let kind = crate::exec::session::script_shell(&b);
        assert_eq!(kind.is_posix(), !cfg!(windows), "{kind:?} for {}", b.id());
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn doctor_reports_a_configured_microvm_that_cannot_boot() {
        let c = ctx("doctor");
        let mut cfg = ExecConfig::parse(&serde_json::json!({"backend": "vm", "vm": {"provider": "bwrap", "allow_fallback": true}})).unwrap();
        cfg.backend_set = true;
        let r = crate::exec::doctor_line(&cfg, &c.home);
        assert!(r.as_ref().is_err_and(|e| e.contains("no microVM can boot here")), "{r:?}");
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn with_an_image_but_no_vmm_the_backend_reports_a_microvm_less_machine() {
        let c = ctx("noimage");
        let b = VmBackend::new(&image(&c.home), &SandboxConfig { mode: "all".into(), ..Default::default() }, &c, true).unwrap();
        // On a KVM machine without firecracker/qemu on PATH this is the bwrap
        // path; either way the backend must never claim more isolation than it
        // has.
        if b.id() == "vm" {
            assert_eq!(b.isolation(), seagent_vm::IsolationLevel::MicroVm);
        } else {
            assert!(b.describe().contains(sandbox_kind()), "{}", b.describe());
        }
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn host_paths_map_into_the_guest_workspace() {
        let _g = tier_lock();
        let c = ctx("map");
        let mut vm = image(&c.home);
        vm.provider = "bwrap".into();
        let sb = SandboxConfig { mode: "all".into(), workspace_access: "rw".into(), ..Default::default() };
        let b = VmBackend::new(&vm, &sb, &c, true).unwrap();
        assert_eq!(b.map_path(&c.workspace.join("src/main.rs")), "/workspace/src/main.rs");
        assert_eq!(b.map_path(Path::new("/etc/passwd")), "/workspace", "paths outside the workspace collapse to its root");
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn tiers_come_from_the_classifier_and_never_default_to_owner_for_strangers() {
        let _g = tier_lock();
        // No classifier installed: the main session is the owner, others are not.
        assert_eq!(tier_of("main", true), TrustTier::Owner);
        assert_eq!(tier_of("telegram:42", false), TrustTier::Channel);
    }

    #[test]
    fn a_manager_is_shared_per_data_dir() {
        let a = manager_for(&VmConfig::default(), Path::new("/var/empty/seagent-test-a"));
        let b = manager_for(&VmConfig::default(), Path::new("/var/empty/seagent-test-a"));
        assert!(Arc::ptr_eq(&a, &b), "one manager per data dir keeps `SE Agent sandbox vm status` complete");
        let _: fn(&VmManager) -> Vec<String> = vm_keys;
    }

    #[test]
    fn the_broker_hint_is_the_only_way_out() {
        let h = broker_hint("egress.http", "{\"host\":\"example.com\"}");
        assert!(h.starts_with("seagent-broker "), "{h}");
        assert!(h.contains("egress.http"));
    }

    /// The `ExecBackend` glue against a **real** microVM: `spawn` → streamed
    /// `read` → `try_wait` → sync back. Ignored by default; run with
    /// `SEAGENT_VM_IMAGE_DIR=… FIRECRACKER=… cargo test -p seagent-tools --lib exec::vm -- --ignored`.
    #[test]
    #[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
    fn the_exec_backend_streams_a_command_from_a_real_microvm() {
        let (Ok(img), Ok(fc)) = (std::env::var("SEAGENT_VM_IMAGE_DIR"), std::env::var("FIRECRACKER")) else {
            println!("skipping: set SEAGENT_VM_IMAGE_DIR and FIRECRACKER");
            return;
        };
        let c = ctx("realvm");
        let vm = VmConfig {
            provider: "firecracker".into(),
            kernel: format!("{img}/vmlinux"),
            initramfs: format!("{img}/initramfs.cpio.gz"),
            firecracker: fc,
            memory_mb: 256,
            vcpu: 1,
            ..Default::default()
        };
        let b = VmBackend::new(&vm, &SandboxConfig { mode: "all".into(), workspace_access: "rw".into(), ..Default::default() }, &c, false).unwrap();
        assert_eq!(b.id(), "vm");
        assert!(!b.shares_host_fs(), "the VM has a copy, not a mount");
        std::fs::write(c.workspace.join("hello.txt"), "from the host\n").unwrap();
        let req = ExecRequest { script: "id -u; cat hello.txt; echo written > back.txt".into(), stdin: false, ..Default::default() };
        let mut child = b.spawn(&req).unwrap();
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let mut buf = [0u8; 4096];
            match child.read(&mut buf, std::time::Duration::from_millis(200)) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "still running after 60s");
                }
                Err(e) => panic!("{e}"),
            }
        }
        let text = String::from_utf8_lossy(&out).to_string();
        println!("--- exec backend output ---\n{text}--- end ---");
        assert!(text.contains("1000"), "{text}");
        assert!(text.contains("from the host"), "{text}");
        let exit = child.try_wait().unwrap();
        assert_eq!(exit.map(|e| e.code), Some(Some(0)));
        // `after_exec` semantics live in the pool: the guest's new file is home.
        assert_eq!(std::fs::read_to_string(c.workspace.join("back.txt")).unwrap().trim(), "written");
        b.cleanup();
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    /// Windows counterpart of the test above: the same `ExecBackend` glue against the Windows
    /// substitute, QEMU + WHPX (TCG when the platform feature is off). Run with
    /// `set SEAGENT_VM_IMAGE_DIR=…` and `cargo test -p seagent-tools --lib exec::vm -- --ignored`.
    #[cfg(windows)]
    #[test]
    #[ignore = "boots a real VM (QEMU for Windows + guest image)"]
    fn the_exec_backend_streams_a_command_from_a_real_qemu_whpx_vm() {
        let Ok(img) = std::env::var("SEAGENT_VM_IMAGE_DIR") else {
            eprintln!("skipping: set SEAGENT_VM_IMAGE_DIR");
            return;
        };
        if seagent_vm::host::find_tool(seagent_vm::host::native_qemu()).is_none() {
            eprintln!("skipping: qemu-system-x86_64 not found");
            return;
        }
        let c = ctx("realwinvm");
        let vm = VmConfig { provider: "qemu".into(), allow_fallback: false, kernel: format!("{img}\\vmlinux"), initramfs: format!("{img}\\initramfs.cpio.gz"), memory_mb: 512, vcpu: 2, ..Default::default() };
        let b = VmBackend::new(&vm, &SandboxConfig { mode: "all".into(), workspace_access: "rw".into(), ..Default::default() }, &c, false).unwrap();
        assert_eq!((b.id(), b.isolation()), ("vm", seagent_vm::IsolationLevel::MicroVm), "{}", b.describe());
        assert!(!b.shares_host_fs(), "the VM has a copy, not a mount");
        std::fs::write(c.workspace.join("hello.txt"), "from the host\n").unwrap();
        let req = ExecRequest { script: "id -u; cat hello.txt; echo written > back.txt; exit 4".into(), stdin: false, ..Default::default() };
        let mut child = b.spawn(&req).unwrap();
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let mut buf = [0u8; 4096];
            match child.read(&mut buf, std::time::Duration::from_millis(200)) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => assert!(std::time::Instant::now() < deadline, "still running after 60s"),
                Err(e) => panic!("{e}"),
            }
        }
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(text.contains("1000") && text.contains("from the host"), "{text}");
        assert_eq!(child.try_wait().unwrap().map(|e| e.code), Some(Some(4)), "the guest's exit code reaches the tool");
        assert_eq!(std::fs::read_to_string(c.workspace.join("back.txt")).unwrap().trim(), "written");
        b.cleanup();
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[cfg(unix)]
    /// The adapter to A's daemon broker: one JSON line in, one out.
    #[test]
    fn the_socket_broker_speaks_the_daemons_protocol() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-vm-sockbroker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("broker.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let mut seen = Vec::new();
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while seen.len() < 2 && std::time::Instant::now() < deadline {
                let Ok((mut s, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                s.set_nonblocking(false).unwrap();
                let mut line = String::new();
                BufReader::new(s.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                seen.push(req.clone());
                let reply = match req["op"].as_str() {
                    Some("egress") => serde_json::json!({"id": 1, "ok": true, "result": {"status": "ok", "code": 200, "headers": {"content-type": "application/json"}, "body_b64": "e30="}}),
                    Some("exec") => serde_json::json!({"id": 2, "ok": true, "result": {"status": "ran", "exit": 0, "stdout": "ok", "stderr": ""}}),
                    _ => serde_json::json!({"id": 3, "ok": false, "error": {"code": "denied", "message": "not on the allowlist"}}),
                };
                let _ = s.write_all(format!("{reply}\n").as_bytes());
            }
            seen
        });
        let b = SocketBroker::new(&sock);
        let e = b.handle("egress.http", serde_json::json!({"host": "crates.io", "path": "/api", "method": "GET"})).unwrap();
        assert_eq!(e["status"], 200);
        assert_eq!(e["body_b64"], "e30=");
        let x = b.handle("priv.exec", serde_json::json!({"cmd": "apt-get", "args": ["install", "-y", "ripgrep"]})).unwrap();
        assert_eq!(x["exit"], 0);
        let denied = b.handle("secret.sign", serde_json::json!({"name": "TOKEN"})).unwrap_err();
        assert!(denied.contains("not supported"), "{denied}");
        let seen = server.join().unwrap();
        assert_eq!(seen[0]["op"], "egress");
        assert_eq!(seen[0]["url"], "https://crates.io/api", "host+path are rebuilt into A's url field");
        assert_eq!(seen[1]["argv"], serde_json::json!(["apt-get", "install", "-y", "ripgrep"]), "argv only, never a shell string");
        assert_eq!(seen.len(), 2, "an unsupported kind never reaches the daemon at all: {seen:?}");
        assert_eq!(seen[1]["op"], "exec", "priv.exec becomes an argv request, never a shell string");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_private_workspace_policy_is_honoured_for_the_vm_backend_too() {
        let _g = tier_lock();
        let c = ctx("private");
        let vm = VmConfig { provider: "bwrap".into(), ..Default::default() };
        let sb = SandboxConfig { mode: "all".into(), workspace_access: "none".into(), ..Default::default() };
        let b = VmBackend::new(&vm, &sb, &c, false).unwrap();
        assert_ne!(b.workspace(), c.workspace.as_path(), "`none` must not hand the project to the VM");
        assert!(b.workspace().ends_with("workspace"));
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn an_untrusted_tier_never_sees_the_operators_workspace() {
        let _g = tier_lock();
        let c = ctx("tier");
        let vm = VmConfig { provider: "bwrap".into(), ..Default::default() };
        let sb = SandboxConfig { mode: "all".into(), workspace_access: "rw".into(), ..Default::default() };
        // Install a classifier that says "this session is an untrusted plugin", and put "no
        // classifier installed" back even if an assertion below fails (the classifier is
        // process-global: a leftover one fails the other tier tests).
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                *tier_classifier().write().unwrap_or_else(|e| e.into_inner()) = None;
            }
        }
        let _reset = Reset;
        set_tier_classifier(Arc::new(|_s: &str| TrustTier::Untrusted));
        let b = VmBackend::new(&vm, &sb, &c, false).unwrap();
        assert_eq!(b.tier(), TrustTier::Untrusted);
        assert_ne!(b.workspace(), c.workspace.as_path(), "no shared workspace across trust tiers (B5)");
        assert!(b.workspace().starts_with(&c.home), "scratch lives under seagent's data dir: {}", b.workspace().display());
        // Back to "no classifier installed".
        *tier_classifier().write().unwrap() = None;
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }

    #[test]
    fn exec_request_keeps_the_workspace_copy_semantics() {
        let _g = tier_lock();
        // shares_host_fs=false means seagent's file tools must not assume host paths.
        let c = ctx("sem");
        let mut vm = image(&c.home);
        vm.provider = "bwrap".into();
        let b = VmBackend::new(&vm, &SandboxConfig { mode: "all".into(), ..Default::default() }, &c, true).unwrap();
        let req = ExecRequest { script: "echo hi".into(), ..Default::default() };
        let b = VmBackend { main: false, ..b };
        let e = b.request(&req);
        // `ctx.sandboxed = true` and no classifier installed: never assume the
        // operator's own tier for a sandboxed session.
        assert_eq!(e.tier, TrustTier::Channel);
        assert_eq!(e.script, "echo hi");
        assert!(e.timeout.as_secs() >= 1);
        let _ = std::fs::remove_dir_all(c.home.parent().unwrap());
    }
}
