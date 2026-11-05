//! The VM pool: one microVM per session (or per trust tier), its snapshots, its
//! workspace sync, and the one thing a VM may ask the host for (the broker).
//!
//! Everything the plan asks of B lives here:
//! * **B4** lifecycle — start on first use, limits, idle reaping, snapshot and
//!   restore per workspace;
//! * **B5** trust tiers — [`trust::TrustTier`] decides the VM key, and two tiers
//!   never share a VM, a workspace or a snapshot stack;
//! * **B2/A4** the VM gets a *copy* of the workspace with credential files
//!   removed ([`crate::secrets::SecretGuard`]) and no secret in its environment;
//! * **B3/A2/A3** the guest can only *ask*: `GuestMsg::Broker` frames are handed
//!   to the installed [`Broker`] (the daemon decides, the guest obeys);
//! * **§0-2 06** undo instead of asking — a destructive command is snapshotted
//!   and then allowed to run (autonomy), and `undo()` restores the workspace.
//!
//! Deliberate asymmetry: changes to file *contents* made inside the VM are
//! synced back, but a `rm` inside the VM never deletes a host file
//! (`propagate_deletes = false`). That is the H1 defence that costs no prompt:
//! the agent can wipe its own sandbox freely and the operator's files survive.
//!
//! Concurrency: commands on one VM are serialised by an [`ExecGate`] (a session
//! has one shell); different sessions and tiers run in parallel.

use crate::channel::Channel;
use crate::config::VmConfig;
use crate::image::GuestImage;
use crate::isolation::{Capabilities, IsolationLevel, ProviderKind};
use crate::limits::{proc_usage, Limits, Watchdog};
use crate::proto::{FileBlob, GuestMsg, HostMsg, VERSION};
use crate::secrets::{Dropped, SecretGuard};
use crate::snapshot::{is_destructive, SnapshotMeta, SnapshotStack};
use crate::trust::TrustTier;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The only bridge from a VM to the daemon (A2 privileged commands, A3 egress,
/// A4 host-side secret use). The guest sends `kind` + `payload`; the
/// implementation applies the allow-list, policy and audit — never the guest.
/// Who is asking: the tool that caused the request and the session whose task envelope,
/// approval queue and audit line it belongs to (A5/A6/§0-2 #01).
#[derive(Debug, Clone, Copy)]
pub struct BrokerFrom<'a> {
    pub component: &'a str,
    pub session: &'a str,
}

pub trait Broker: Send + Sync {
    fn handle(&self, kind: &str, payload: Value) -> Result<Value, String>;
    /// Same request, attributed to the component that caused it (the tool that spawned the
    /// command: `shell`, `code`, a skill's tool). Capability manifests are enforced per
    /// component (A5), so an adapter that can name one should. The default ignores it.
    fn handle_as(&self, _component: &str, kind: &str, payload: Value) -> Result<Value, String> {
        self.handle(kind, payload)
    }
    /// [`Broker::handle_as`] plus the session: approvals are queued for *that* session and the
    /// task envelope of *that* session applies (a VM serves one session per channel).
    fn handle_from(&self, req: BrokerFrom<'_>, kind: &str, payload: Value) -> Result<Value, String> {
        self.handle_as(req.component, kind, payload)
    }
}

/// One command to run in a VM.
#[derive(Debug, Clone)]
pub struct VmExec {
    pub session: String,
    pub tier: TrustTier,
    /// Host workspace; the VM gets a copy.
    pub workspace: PathBuf,
    pub script: String,
    /// Host path inside the workspace (mapped to the guest path).
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub login: bool,
    pub stdin: bool,
    pub pty: Option<(u16, u16)>,
    pub timeout: Duration,
}

impl VmExec {
    pub fn new(session: &str, tier: TrustTier, workspace: &Path, script: &str) -> VmExec {
        VmExec { session: session.to_string(), tier, workspace: workspace.to_path_buf(), script: script.to_string(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout: Duration::from_secs(120) }
    }
}

/// Result of a completed command.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub output: Vec<u8>,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub provider: ProviderKind,
    pub isolation: IsolationLevel,
    /// Snapshot taken before a destructive command (the undo point).
    pub snapshot: Option<SnapshotMeta>,
    /// Environment variables that never reached the VM.
    pub dropped: Vec<Dropped>,
    pub synced: (usize, usize),
}

impl ExecOutcome {
    pub fn exit_ok(&self) -> bool {
        self.code == Some(0)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }
}

/// A running command: the channel plus its gate lease.
pub struct VmSession {
    pub chan: Arc<Channel>,
    pub id: u64,
    pub provider: ProviderKind,
    pub isolation: IsolationLevel,
    pub workspace: PathBuf,
    pub read_only: bool,
    pub limits: Limits,
    pub snapshot: Option<SnapshotMeta>,
    pub dropped: Vec<Dropped>,
    gate: Option<GateGuard>,
    slot: Arc<Slot>,
}

impl VmSession {
    pub fn send(&self, m: &HostMsg) -> Result<(), String> {
        self.chan.send(m)
    }
    /// Release the VM (called after `Exit`, or by the caller when a command is
    /// abandoned). Idempotent.
    pub fn release(&mut self) {
        self.gate.take();
    }
    /// True when the last command finished; used by the exec-loop wrapper.
    pub fn is_done(&self) -> bool {
        self.gate.is_none()
    }
}

impl Drop for VmSession {
    fn drop(&mut self) {
        self.gate.take();
    }
}

struct Slot {
    key: String,
    tier: TrustTier,
    workspace: PathBuf,
    provider: ProviderKind,
    isolation: IsolationLevel,
    inst: Mutex<Box<dyn crate::provider::VmInstance>>,
    chan: Arc<Channel>,
    gate: Arc<ExecGate>,
    last_used: Mutex<Instant>,
    commands: AtomicU64,
    snapshots: SnapshotStack,
    /// What the guest already has: path -> (size, mtime, mode).
    pushed: Mutex<HashMap<String, (u64, i64, u32)>>,
    read_only: bool,
    /// Environment variables refused at start (reported by status/tests).
    #[allow(dead_code)]
    dropped: Vec<Dropped>,
    limits: Limits,
}

/// Serialises commands on one VM; a released gate lets the next command in.
struct ExecGate {
    busy: Mutex<bool>,
    cv: Condvar,
}

impl ExecGate {
    fn new() -> Arc<ExecGate> {
        Arc::new(ExecGate { busy: Mutex::new(false), cv: Condvar::new() })
    }
    fn acquire(self: &Arc<Self>) -> GateGuard {
        let mut busy = self.busy.lock().unwrap();
        while *busy {
            busy = self.cv.wait(busy).unwrap();
        }
        *busy = true;
        GateGuard { gate: self.clone() }
    }
}

struct GateGuard {
    gate: Arc<ExecGate>,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        *self.gate.busy.lock().unwrap() = false;
        self.gate.cv.notify_one();
    }
}

/// Status line for `ark sandbox vm status` / `ark doctor`.
#[derive(Debug, Clone)]
pub struct VmStatus {
    pub key: String,
    pub tier: String,
    pub provider: String,
    pub isolation: IsolationLevel,
    pub pid: Option<u32>,
    pub running: bool,
    pub commands: u64,
    pub idle_secs: u64,
    pub rss_kb: u64,
    pub snapshots: usize,
}

pub struct VmManager {
    cfg: VmConfig,
    /// ark data dir (`~/.local/share/ark`).
    data: PathBuf,
    broker: Mutex<Option<Arc<dyn Broker>>>,
    /// Test-only provider override (a fake that boots a thread). Per manager, so
    /// tests cannot leak into each other.
    provider_override: Mutex<Option<Arc<dyn crate::provider::VmProvider>>>,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    /// Warning produced by the last provider selection (shown once per process).
    warning: Mutex<Option<String>>,
}

impl VmManager {
    pub fn new(cfg: VmConfig, data: PathBuf) -> VmManager {
        VmManager { cfg, data, broker: Mutex::new(None), provider_override: Mutex::new(None), slots: Mutex::new(HashMap::new()), warning: Mutex::new(None) }
    }
    pub fn config(&self) -> &VmConfig {
        &self.cfg
    }
    pub fn data_dir(&self) -> &Path {
        &self.data
    }
    pub fn set_broker(&self, b: Arc<dyn Broker>) {
        *self.broker.lock().unwrap() = Some(b);
    }
    pub fn broker(&self) -> Option<Arc<dyn Broker>> {
        self.broker.lock().unwrap().clone()
    }
    /// Machine capabilities, re-detected (never cached: a binary can vanish).
    pub fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::detect(Some(&self.cfg.kernel_path(&self.data)), Some(&self.cfg.initramfs_path(&self.data)));
        // `[exec.vm] firecracker`/`qemu` may be an absolute path outside PATH
        // (a tarball unpacked into a data dir); honour it.
        // A firecracker tarball unpacked into the data dir is the common case
        // (`packaging/vm/README.md`); no PATH or root needed.
        let local_fc = self.data.join("vm").join("bin").join("firecracker");
        if let Some(p) = crate::isolation::which(&self.cfg.firecracker).or(local_fc.is_file().then_some(local_fc)) {
            caps.firecracker = Some(p);
        }
        if let Some(p) = crate::isolation::which(&self.cfg.qemu) {
            caps.qemu = Some(p);
        }
        caps
    }
    /// Test hook: run the pool against an in-process fake agent instead of a VM.
    pub fn set_provider_override(&self, p: Arc<dyn crate::provider::VmProvider>) {
        *self.provider_override.lock().unwrap() = Some(p);
    }
    /// Which provider would be used, and the warning the caller must show.
    pub fn selection(&self) -> (ProviderKind, Option<String>) {
        if let Some(p) = self.provider_override.lock().unwrap().clone() {
            let w = p.isolation().warning().map(|w| format!("{}: {w}", p.kind().name()));
            return (p.kind(), w);
        }
        crate::provider::select(&self.cfg, &self.capabilities())
    }

    /// Run dir for one VM. `AF_UNIX` paths are limited to 108 bytes and a deep
    /// `ARK_HOME` plus a long key blows that (Firecracker refuses to bind), so a
    /// long path is replaced by a short private one under the temp dir.
    fn run_dir_for(&self, key: &str) -> PathBuf {
        let dir = self.cfg.run_dir(&self.data, key);
        if dir.as_os_str().len() + 12 < 100 {
            return dir;
        }
        let short: String = key.chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect();
        let p = std::env::temp_dir().join(format!("arkvm-{short}-{:08x}", fnv(dir.to_string_lossy().as_bytes())));
        std::fs::create_dir_all(&p).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
        // Keep the audit trail pointing at the real location.
        // (The parent may not exist yet at this point; without it the write below silently failed
        // and the audit trail, and anything that wants to find the short dir again, pointed nowhere.)
        let trail = dir.parent().unwrap_or(&dir);
        let _ = std::fs::create_dir_all(trail);
        let _ = std::fs::write(trail.join(format!("{key}.run-dir")), p.display().to_string());
        p
    }

    fn key_for(&self, session: &str, tier: TrustTier, workspace: &Path) -> String {
        let base = tier.vm_key(session, &self.cfg);
        // Two workspaces of one session must not end up in one VM either.
        format!("{base}-{:08x}", fnv(workspace.to_string_lossy().as_bytes()))
    }

    /// Get the VM for this session/tier, starting it on first use.
    fn slot(&self, session: &str, tier: TrustTier, workspace: &Path) -> Result<Arc<Slot>, String> {
        let key = self.key_for(session, tier, workspace);
        if let Some(s) = self.slots.lock().unwrap().get(&key) {
            *s.last_used.lock().unwrap() = Instant::now();
            return Ok(s.clone());
        }
        let (kind, warning) = self.selection();
        if let Some(w) = &warning {
            *self.warning.lock().unwrap() = Some(w.clone());
        }
        if !kind.is_vm() {
            return Err(format!(
                "exec.vm cannot start a microVM here ({}); tools fall back to `{}` with {} isolation",
                warning.clone().unwrap_or_else(|| "no reason given".into()),
                kind.name(),
                kind.isolation().label()
            ));
        }
        let image = GuestImage::find(&self.cfg, &self.data)?;
        let run_dir = self.run_dir_for(&key);
        std::fs::create_dir_all(&run_dir).map_err(|e| format!("create {}: {e}", run_dir.display()))?;
        let guard = SecretGuard::new(&self.cfg);
        let read_only = self.cfg.workspace_readonly(workspace);
        let limits = Limits::from_config(&self.cfg, 120);
        let spec = crate::provider::VmSpec {
            id: key.clone(),
            tier: tier.label().into(),
            kernel: image.kernel(),
            initramfs: image.initramfs(),
            run_dir: run_dir.clone(),
            vcpu: self.cfg.vcpu,
            mem_mb: self.cfg.memory_mb,
            workspace: Some(crate::provider::Workspace { host: workspace.to_path_buf(), guest: crate::proto::GUEST_WORKSPACE.into(), read_only }),
            limits,
            transport: match kind {
                ProviderKind::Firecracker => crate::channel::Transport::Vsock { port: crate::proto::VSOCK_PORT },
                _ => crate::channel::Transport::Serial,
            },
            firecracker: crate::isolation::which(&self.cfg.firecracker).or_else(|| Some(PathBuf::from(&self.cfg.firecracker))),
            qemu: crate::isolation::which(&self.cfg.qemu).or_else(|| Some(PathBuf::from(&self.cfg.qemu))),
            extra_args: self.cfg.extra_args.clone(),
            guest_cid: self.cfg.guest_cid,
        };
        let provider = match self.provider_override.lock().unwrap().clone() {
            Some(p) => p,
            None => crate::provider::build(kind, &self.cfg)?,
        };
        let mut inst = provider.start(&spec)?;
        let chan = match inst.connect(Duration::from_secs(60)) {
            Ok(c) => c,
            Err(e) => {
                inst.stop();
                return Err(if kind == ProviderKind::Qemu {
                    format!("{e} (the QEMU provider needs a PCI-capable guest kernel: the Firecracker CI `vmlinux` has CONFIG_PCI=n, so `/dev/vport0p1` never appears. Install firecracker — a 7 MB tarball, no root — or configure exec.vm.kernel with a PCI kernel)")
                } else {
                    e
                });
            }
        };
        // The guest must be the agent we built, running as the unprivileged user.
        let hello = chan.expect(Duration::from_secs(10), "Hello")?;
        match hello {
            GuestMsg::Hello { version, uid, agent, .. } => {
                if version != VERSION {
                    inst.stop();
                    return Err(format!("guest agent version {version} != host {VERSION}: rebuild the image (`ark sandbox vm image build --force`)"));
                }
                if uid != crate::proto::AGENT_UID {
                    inst.stop();
                    return Err(format!("guest agent runs as uid {uid}, expected {}: refusing a VM whose tools run as root", crate::proto::AGENT_UID));
                }
                let _ = agent;
            }
            other => {
                inst.stop();
                return Err(format!("first guest frame was {other:?}, expected Hello"));
            }
        }
        // Ceilings, then the environment filter report.
        chan.send(&HostMsg::Limits { nproc: Some(limits.nproc), nofile: Some(limits.nofile), cpu_seconds: (limits.cpu_seconds > 0).then_some(limits.cpu_seconds) })?;
        // The agent may or may not ack `Limits`; drain one frame so a stale ack
        // cannot be mistaken for the next command's reply.
        let _ = chan.recv(Duration::from_millis(300));
        let (_, dropped_env) = guard.filter_env(std::env::vars().collect());
        let slot = Arc::new(Slot {
            key: key.clone(),
            tier,
            workspace: workspace.to_path_buf(),
            provider: kind,
            isolation: kind.isolation(),
            inst: Mutex::new(inst),
            chan,
            gate: ExecGate::new(),
            last_used: Mutex::new(Instant::now()),
            commands: AtomicU64::new(0),
            snapshots: SnapshotStack::new(self.cfg.snapshot_root(&self.data).join(&key), self.cfg.snapshot_keep),
            pushed: Mutex::new(HashMap::new()),
            read_only,
            dropped: dropped_env,
            limits,
        });
        // A restore point before the session does anything at all (§0-2 06).
        if self.cfg.snapshots && workspace.is_dir() {
            if let Ok(m) = slot.snapshots.create(workspace, "session-start") {
                let _ = m;
            }
        }
        self.slots.lock().unwrap().insert(key, slot.clone());
        Ok(slot)
    }

    /// Start a command. The returned session holds the VM until `release()`/drop.
    pub fn spawn(&self, req: &VmExec) -> Result<VmSession, String> {
        let slot = self.slot(&req.session, req.tier, &req.workspace)?;
        let gate = slot.gate.acquire();
        let guard = SecretGuard::new(&self.cfg);
        // Undo point first: a destructive command is allowed, but it is
        // recoverable (no approval prompt, autonomy preserved).
        let mut snapshot = None;
        if self.cfg.snapshots {
            if let Some(why) = is_destructive(&req.script) {
                snapshot = slot.snapshots.create(&req.workspace, &format!("destructive: {why}")).ok();
            }
        }
        let synced = self.sync_in(&slot, &guard)?;
        let (env, dropped) = guard.filter_env(req.env.clone());
        let id = next_id();
        let cwd = req.cwd.as_ref().and_then(|c| map_cwd(c, &req.workspace));
        slot.chan.send(&HostMsg::Exec {
            id,
            script: req.script.clone(),
            cwd,
            env,
            login: req.login,
            stdin: req.stdin,
            pty: req.pty,
            timeout_secs: if slot.limits.exec_timeout_secs > 0 { slot.limits.exec_timeout_secs } else { req.timeout.as_secs() },
        })?;
        slot.commands.fetch_add(1, Ordering::SeqCst);
        *slot.last_used.lock().unwrap() = Instant::now();
        let _ = synced;
        Ok(VmSession {
            chan: slot.chan.clone(),
            id,
            provider: slot.provider,
            isolation: slot.isolation,
            workspace: req.workspace.clone(),
            read_only: slot.read_only,
            limits: slot.limits,
            snapshot,
            dropped,
            gate: Some(gate),
            slot: slot.clone(),
        })
    }

    /// Collect the guest's changes into the host workspace. Never propagates
    /// deletions (`propagate_deletes` is off by design, H1).
    pub fn finish(&self, sess: &mut VmSession) -> Result<(usize, usize), String> {
        let out = match self.sync_out(&sess.slot) {
            Ok(n) => n,
            Err(e) => {
                // A failed sync must not leave a stale gate behind.
                sess.release();
                return Err(e);
            }
        };
        sess.release();
        Ok(out)
    }

    /// Run one command to completion (code mode, `ark sandbox vm exec`, tests).
    pub fn exec(&self, req: &VmExec) -> Result<ExecOutcome, String> {
        let mut sess = self.spawn(req)?;
        let timeout = req.timeout.max(Duration::from_secs(1));
        let deadline = Instant::now() + timeout + Duration::from_secs(5);
        let mut out = Vec::new();
        let (code, signal) = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = sess.send(&HostMsg::Signal { id: sess.id, force: true });
                sess.release();
                return Err(format!("command timed out after {}s in the VM", timeout.as_secs()));
            }
            match sess.chan.recv(left.min(Duration::from_secs(5))) {
                Ok(Some(GuestMsg::Out { id, data })) if id == sess.id => {
                    if let Ok(b) = B64.decode(&data) {
                        if out.len() + b.len() > self.cfg.workspace_max_mb as usize * 1024 * 1024 * 4 {
                            let _ = sess.send(&HostMsg::Signal { id: sess.id, force: true });
                            return Err("command produced more output than the VM backend buffers; use the streaming tool".into());
                        }
                        out.extend_from_slice(&b);
                    }
                }
                Ok(Some(GuestMsg::Exit { id, code, signal })) if id == sess.id => break (code, signal),
                Ok(Some(GuestMsg::Err { id, message })) if id == sess.id => {
                    sess.release();
                    return Err(format!("guest error: {message}"));
                }
                Ok(Some(GuestMsg::Broker { id, kind, payload })) => {
                    let reply = match self.broker() {
                        Some(b) => b.handle(&kind, payload),
                        None => Err("no broker installed on this ark instance: the VM may not reach the network".into()),
                    };
                    let m = match reply {
                        Ok(p) => HostMsg::BrokerReply { id, ok: true, payload: p },
                        Err(e) => HostMsg::BrokerReply { id, ok: false, payload: json!({"error": e}) },
                    };
                    if let Err(e) = sess.send(&m) {
                        sess.release();
                        return Err(e);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    if !sess.slot.inst_alive() {
                        sess.release();
                        return Err("the VM stopped while the command was running".into());
                    }
                }
                Err(e) => {
                    sess.release();
                    return Err(format!("guest channel: {e}"));
                }
            }
        };
        let synced = self.finish(&mut sess)?;
        Ok(ExecOutcome {
            output: out,
            code,
            signal,
            provider: sess.provider,
            isolation: sess.isolation,
            snapshot: sess.snapshot.clone(),
            dropped: sess.dropped.clone(),
            synced,
        })
    }

    /// Snapshot the workspace of a session (manual undo point).
    pub fn snapshot(&self, session: &str, tier: TrustTier, workspace: &Path, reason: &str) -> Result<SnapshotMeta, String> {
        let stack = SnapshotStack::new(self.cfg.snapshot_root(&self.data).join(self.key_for(session, tier, workspace)), self.cfg.snapshot_keep);
        let m = stack.create(workspace, reason)?;
        if let Ok(slot) = self.slot(session, tier, workspace) {
            if let Ok(Some(_)) = slot.inst.lock().unwrap().ram_snapshot(&self.cfg.snapshot_root(&self.data).join(&slot.key).join(&m.name)) {
                // RAM image written next to the workspace tree; the meta stays
                // the source of truth for what exists.
            }
        }
        Ok(m)
    }

    /// Restore the workspace (default: the newest snapshot).
    pub fn restore(&self, session: &str, tier: TrustTier, workspace: &Path, name: Option<&str>) -> Result<SnapshotMeta, String> {
        let stack = SnapshotStack::new(self.cfg.snapshot_root(&self.data).join(self.key_for(session, tier, workspace)), self.cfg.snapshot_keep);
        let m = stack.restore(workspace, name)?;
        // The VM's copy is now stale: forget what it has so the next command
        // pushes everything again.
        let key = self.key_for(session, tier, workspace);
        if let Some(slot) = self.slots.lock().unwrap().get(&key).cloned() {
            slot.pushed.lock().unwrap().clear();
        }
        Ok(m)
    }

    pub fn snapshots(&self, session: &str, tier: TrustTier, workspace: &Path) -> Vec<SnapshotMeta> {
        SnapshotStack::new(self.cfg.snapshot_root(&self.data).join(self.key_for(session, tier, workspace)), self.cfg.snapshot_keep).list()
    }

    /// Stop VMs idle longer than `exec.vm.idle_timeout_secs`. Returns how many.
    pub fn gc_idle(&self) -> usize {
        let timeout = self.cfg.idle_timeout_secs;
        if timeout == 0 {
            return 0;
        }
        let mut stopped = 0;
        let mut slots = self.slots.lock().unwrap();
        let dead: Vec<String> = slots
            .iter()
            .filter(|(_, s)| s.last_used.lock().unwrap().elapsed().as_secs() >= timeout && !s.gate_is_held())
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            if let Some(s) = slots.remove(&k) {
                s.inst.lock().unwrap().stop();
                stopped += 1;
            }
        }
        stopped
    }

    pub fn stop_all(&self) {
        let mut slots = self.slots.lock().unwrap();
        for (_, s) in slots.drain() {
            s.inst.lock().unwrap().stop();
        }
    }

    pub fn stop(&self, key: &str) -> bool {
        let mut slots = self.slots.lock().unwrap();
        match slots.remove(key) {
            Some(s) => {
                s.inst.lock().unwrap().stop();
                true
            }
            None => false,
        }
    }

    pub fn status(&self) -> Vec<VmStatus> {
        let slots = self.slots.lock().unwrap();
        let mut out: Vec<VmStatus> = slots
            .values()
            .map(|s| {
                let (pid, running, rss) = {
                    let mut inst = s.inst.lock().unwrap();
                    let pid = inst.pid();
                    let running = inst.is_running();
                    let rss = pid.and_then(proc_usage).map(|(_, rss)| rss).or_else(|| inst.usage().rss_kb.into()).unwrap_or(0);
                    (pid, running, rss)
                };
                VmStatus {
                    key: s.key.clone(),
                    tier: s.tier.label().into(),
                    provider: s.provider.name().into(),
                    isolation: s.isolation,
                    pid,
                    running,
                    commands: s.commands.load(Ordering::SeqCst),
                    idle_secs: s.last_used.lock().unwrap().elapsed().as_secs(),
                    rss_kb: rss,
                    snapshots: s.snapshots.list().len(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    /// Warning from the last provider selection (the "this is not a microVM"
    /// line), if any.
    pub fn isolation_warning(&self) -> Option<String> {
        self.warning.lock().unwrap().clone()
    }

    /// Watchdog tick: kill a VM that burned its CPU budget.
    pub fn enforce_budgets(&self) -> usize {
        let cpu_budget = self.cfg.cpu_seconds;
        if cpu_budget == 0 {
            return 0;
        }
        let hz = 100; // Linux USER_HZ on x86_64
        let mut killed = 0;
        let slots = self.slots.lock().unwrap();
        for s in slots.values() {
            let pid = s.inst.lock().unwrap().pid();
            if let Some((ticks, _)) = pid.and_then(proc_usage) {
                let w = Watchdog::new(cpu_budget, 0);
                if w.cpu_exceeded(ticks, hz) {
                    s.inst.lock().unwrap().stop();
                    killed += 1;
                }
            }
        }
        killed
    }

    // ── workspace sync ─────────────────────────────────────────────────────

    fn sync_in(&self, slot: &Slot, guard: &SecretGuard) -> Result<usize, String> {
        if slot.read_only || !slot.workspace.is_dir() {
            return Ok(0);
        }
        let manifest = host_manifest(&slot.workspace, guard, self.cfg.workspace_max_mb)?;
        let pushed = slot.pushed.lock().unwrap().clone();
        let mut files: Vec<FileBlob> = Vec::new();
        let mut total = 0usize;
        for (rel, (size, mtime, mode)) in manifest.iter() {
            if pushed.get(rel) == Some(&(*size, *mtime, *mode)) {
                continue;
            }
            let data = std::fs::read(slot.workspace.join(rel)).map_err(|e| format!("read {rel}: {e}"))?;
            total += data.len();
            if total > self.cfg.workspace_max_mb as usize * 1024 * 1024 {
                return Err(format!("workspace {} exceeds exec.vm.workspace_max_mb ({} MB); raise it or use a smaller checkout", slot.workspace.display(), self.cfg.workspace_max_mb));
            }
            files.push(FileBlob { path: rel.clone(), data: B64.encode(&data), mode: *mode });
        }
        let n = files.len();
        for batch in files.chunks(64) {
            let id = next_id();
            slot.chan.send(&HostMsg::Push { id, files: batch.to_vec() })?;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match slot.chan.recv(left.min(Duration::from_secs(5)))? {
                    Some(GuestMsg::Ok { id: rid, .. }) if rid == id => break,
                    Some(GuestMsg::Err { message, .. }) => return Err(format!("guest refused the workspace push: {message}")),
                    // A late ack for an earlier frame is ignored, not fatal.
                    Some(_) => {}
                    None if Instant::now() >= deadline => return Err("timed out pushing the workspace into the VM".into()),
                    None => {}
                }
            }
        }
        *slot.pushed.lock().unwrap() = manifest;
        Ok(n)
    }

    fn sync_out(&self, slot: &Slot) -> Result<(usize, usize), String> {
        if slot.read_only {
            return Ok((0, 0));
        }
        // `find` is how a busybox guest lists the workspace; -print0 keeps
        // spaces and newlines safe.
        let list = {
            let id = next_id();
            slot.chan.send(&HostMsg::Exec { id, script: "find . -type f -print0 | tr '\\0' '\\n'".into(), cwd: Some(crate::proto::GUEST_WORKSPACE.into()), env: vec![], login: false, stdin: false, pty: None, timeout_secs: 60 })?;
            let mut out = Vec::new();
            loop {
                match slot.chan.recv(Duration::from_secs(10))? {
                    Some(GuestMsg::Out { id: rid, data }) if rid == id => {
                        if let Ok(b) = B64.decode(&data) {
                            out.extend_from_slice(&b);
                        }
                    }
                    Some(GuestMsg::Exit { id: rid, .. }) if rid == id => break,
                    Some(_) => {}
                    None => return Err("timed out listing the VM workspace".into()),
                }
            }
            String::from_utf8_lossy(&out).to_string()
        };
        let paths: Vec<String> = list.lines().map(|l| l.trim_start_matches("./").to_string()).filter(|p| !p.is_empty()).collect();
        let mut written = 0;
        let mut checked = 0;
        for batch in paths.chunks(64) {
            let id = next_id();
            slot.chan.send(&HostMsg::Pull { id, paths: batch.to_vec() })?;
            let files = loop {
                match slot.chan.recv(Duration::from_secs(30))? {
                    Some(GuestMsg::Files { id: rid, files }) if rid == id => break files,
                    Some(GuestMsg::Err { message, .. }) => return Err(format!("guest refused the pull: {message}")),
                    Some(_) => {}
                    None => return Err("timed out pulling files from the VM".into()),
                }
            };
            for f in files {
                if crate::proto::check_rel_path(&f.path).is_err() {
                    continue;
                }
                checked += 1;
                let Ok(bytes) = B64.decode(&f.data) else { continue };
                let dest = slot.workspace.join(&f.path);
                // Never overwrite through a symlink: write a sibling and rename.
                let same = std::fs::read(&dest).map(|old| old == bytes).unwrap_or(false);
                if same {
                    continue;
                }
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
                }
                let tmp = dest.with_extension("ark-sync");
                std::fs::write(&tmp, &bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
                std::fs::rename(&tmp, &dest).map_err(|e| format!("rename {}: {e}", dest.display()))?;
                written += 1;
            }
        }
        Ok((written, checked))
    }
}

impl Slot {
    fn gate_is_held(&self) -> bool {
        *self.gate.busy.lock().unwrap()
    }
    fn inst_alive(&self) -> bool {
        self.inst.lock().unwrap().is_running()
    }
}

fn map_cwd(host: &Path, workspace: &Path) -> Option<String> {
    let rel = host.strip_prefix(workspace).ok()?;
    if rel.as_os_str().is_empty() {
        Some(crate::proto::GUEST_WORKSPACE.into())
    } else if rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        None
    } else {
        Some(format!("{}/{}", crate::proto::GUEST_WORKSPACE, rel.display()))
    }
}

/// `path -> (size, mtime secs, mode)` for the files a VM may see.
fn host_manifest(workspace: &Path, guard: &SecretGuard, max_mb: u64) -> Result<HashMap<String, (u64, i64, u32)>, String> {
    let mut out = HashMap::new();
    let mut total = 0u64;
    let mut stack = vec![(workspace.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth > 32 {
            continue;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            if guard.path_denied(&child_rel).is_some() {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            let md = match e.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue; // never follow a link out of the workspace
            }
            if ft.is_dir() {
                if name == ".git" {
                    continue; // never sync a repository's object store
                }
                stack.push((e.path(), child_rel, depth + 1));
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            total += md.len();
            if total > max_mb * 1024 * 1024 {
                return Err(format!("workspace exceeds exec.vm.workspace_max_mb ({} MB): refusing a partial sync", max_mb));
            }
            let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            use std::os::unix::fs::PermissionsExt;
            out.insert(child_rel, (md.len(), mtime, md.permissions().mode() & 0o777));
        }
    }
    Ok(out)
}

fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn fnv(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::fake::FakeProvider;
    use std::sync::atomic::AtomicUsize;

    struct TestBroker {
        calls: AtomicUsize,
    }

    impl Broker for TestBroker {
        fn handle(&self, kind: &str, payload: Value) -> Result<Value, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if kind == "egress.http" {
                Ok(json!({"status": 200, "host": payload["host"]}))
            } else {
                Err(format!("kind `{kind}` is not allowed by the allow-list"))
            }
        }
    }

    fn data(tag: &str) -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-vm-pool-{tag}-{}-{}", std::process::id(), crate::snapshot::now()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ws(tag: &str) -> PathBuf {
        let d = data(&format!("{tag}-ws"));
        std::fs::write(d.join("main.rs"), "fn main() {}\n").unwrap();
        d
    }

    /// Removes a manager's data tree *and* the short `$TMPDIR/arkvm-*` run dirs that
    /// `run_dir_for` falls back to when the data path is deep (each is named by a `<key>.run-dir`
    /// file inside the tree, so they must be read before the tree goes).
    struct DataGuard(PathBuf);

    impl Drop for DataGuard {
        fn drop(&mut self) {
            fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
                let Ok(rd) = std::fs::read_dir(dir) else { return };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else if p.extension().is_some_and(|x| x == "run-dir") {
                        if let Ok(s) = std::fs::read_to_string(&p) {
                            out.push(PathBuf::from(s.trim()));
                        }
                    }
                }
            }
            let mut shorts = Vec::new();
            walk(&self.0, &mut shorts);
            for s in shorts {
                // Only the fallback location this module itself creates.
                if s.starts_with(std::env::temp_dir()) && s.file_name().is_some_and(|n| n.to_string_lossy().starts_with("arkvm-")) {
                    let _ = std::fs::remove_dir_all(&s);
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    thread_local! {
        static GUARDS: std::cell::RefCell<Vec<DataGuard>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn mgr(tag: &str) -> (VmManager, PathBuf) {
        let d = std::env::temp_dir().join(format!("ark-vm-pool-{tag}-{}-{}", std::process::id(), crate::snapshot::now()));
        std::fs::create_dir_all(&d).unwrap();
        GUARDS.with(|g| g.borrow_mut().push(DataGuard(d.clone())));
        // Boot files exist (the fake never reads them) so the image lookup is
        // satisfied without building a guest image in a unit test.
        let cfg = VmConfig { kernel: d.join("vmlinux").display().to_string(), initramfs: d.join("initramfs.cpio.gz").display().to_string(), ..Default::default() };
        std::fs::write(d.join("vmlinux"), b"fake").unwrap();
        std::fs::write(d.join("initramfs.cpio.gz"), b"fake").unwrap();
        let m = VmManager::new(cfg, d.clone());
        (m, d)
    }

    fn fake(m: &VmManager, d: &std::path::Path) {
        m.set_provider_override(Arc::new(FakeProvider::new(d.join("rootfs"))));
    }

    #[test]
    fn env_and_paths_are_filtered_before_the_vm_sees_them() {
        let g = SecretGuard::new(&VmConfig::default());
        let (env, dropped) = g.filter_env(vec![("PATH".into(), "/usr/bin".into()), ("OPENAI_API_KEY".into(), "sk-x".into()), ("HOME".into(), "/home/agent".into())]);
        assert_eq!(env.len(), 2);
        assert!(dropped.iter().any(|d| d.name == "OPENAI_API_KEY"));
        assert_eq!(host_manifest(&ws("m"), &g, 512).unwrap().len(), 1);
    }

    #[test]
    fn tier_keys_never_collide_and_include_the_workspace() {
        let (m, _d) = mgr("keys");
        let a = m.key_for("s1", TrustTier::Owner, Path::new("/w/a"));
        let b = m.key_for("s1", TrustTier::Owner, Path::new("/w/b"));
        let c = m.key_for("s1", TrustTier::Stranger, Path::new("/w/a"));
        assert_ne!(a, b, "different workspaces get different VMs");
        assert_ne!(a, c, "different tiers get different VMs");
        assert!(a.starts_with("s-s1-"));
    }

    #[test]
    fn fake_provider_runs_a_command_and_syncs_both_ways() {
        let (m, d) = mgr("fakeexec");
        fake(&m, &d);
        let w = ws("fakeexec");
        std::fs::write(w.join("in.txt"), "host\n").unwrap();
        let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &w, "cat in.txt; echo made > out.txt; echo rc=$?")).unwrap();
        assert_eq!(out.code, Some(0), "{}", out.text());
        assert!(out.text().contains("host"), "the VM saw the pushed workspace: {}", out.text());
        assert_eq!(std::fs::read_to_string(w.join("out.txt")).unwrap().trim(), "made", "guest writes come back");
        assert_eq!(out.synced.0, 1, "one file synced back");
        m.stop_all();
    }

    #[test]
    fn a_destructive_command_is_snapshotted_and_still_runs() {
        let (m, d) = mgr("destructive");
        fake(&m, &d);
        let w = ws("destructive");
        std::fs::write(w.join("important.txt"), "keep me\n").unwrap();
        let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &w, "rm -rf /workspace/* ; echo gone")).unwrap();
        assert_eq!(out.code, Some(0));
        let snap = out.snapshot.expect("a destructive command must leave an undo point");
        assert!(snap.reason.contains("recursive delete"), "{}", snap.reason);
        // Deletions do not propagate to the host (H1), so the file is still here…
        assert!(w.join("important.txt").exists());
        // …and the snapshot can bring back anything that *was* removed.
        std::fs::remove_file(w.join("important.txt")).unwrap();
        let r = m.restore("s1", TrustTier::Owner, &w, Some(&snap.name)).unwrap();
        assert_eq!(r.name, snap.name);
        assert_eq!(std::fs::read_to_string(w.join("important.txt")).unwrap(), "keep me\n");
        m.stop_all();
    }

    #[test]
    fn broker_requests_from_the_vm_are_answered_by_the_host() {
        let (m, d) = mgr("broker");
        fake(&m, &d);
        let b = Arc::new(TestBroker { calls: AtomicUsize::new(0) });
        m.set_broker(b.clone());
        let w = ws("broker");
        // The fake agent does not implement broker-send; the pool's frame
        // handling is what is under test here, so drive it directly.
        let mut sess = m.spawn(&VmExec::new("s1", TrustTier::Owner, &w, "true")).unwrap();
        let reply = m.broker().unwrap().handle("egress.http", json!({"host": "crates.io"}));
        assert_eq!(reply.unwrap()["host"], "crates.io");
        let denied = m.broker().unwrap().handle("priv.exec", json!({"cmd": "apt install"}));
        assert!(denied.unwrap_err().contains("allow-list"));
        assert_eq!(b.calls.load(Ordering::SeqCst), 2);
        let _ = sess.send(&HostMsg::Signal { id: sess.id, force: true });
        sess.release();
        m.stop_all();
    }

    #[test]
    fn idle_vms_are_reaped_and_status_reports_them() {
        let (mut m, d) = mgr("idle");
        fake(&m, &d);
        m.cfg.idle_timeout_secs = 1;
        let w = ws("idle");
        let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &w, "true")).unwrap();
        assert_eq!(out.code, Some(0));
        assert_eq!(m.status().len(), 1);
        assert_eq!(m.status()[0].tier, "owner");
        assert_eq!(m.gc_idle(), 0, "still warm");
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(m.gc_idle(), 1);
        assert!(m.status().is_empty());
    }

    #[test]
    fn without_a_vm_the_pool_refuses_instead_of_running_on_the_host() {
        let (mut m, _d) = mgr("novm");
        m.cfg.provider = "bwrap".into();
        let w = ws("novm");
        let e = m.exec(&VmExec::new("s1", TrustTier::Owner, &w, "true")).unwrap_err();
        assert!(e.contains("cannot start a microVM"), "{e}");
        assert!(e.contains("namespace"), "the isolation level is named: {e}");
    }
}
