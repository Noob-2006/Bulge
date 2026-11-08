//! An in-process stand-in for a guest agent (used by tests and by
//! `seagent-vm`'s own pool tests): a real channel, a real framed protocol, real
//! process execution — just no VM. It exists so the pool's semantics (tier
//! separation, env filtering, snapshot-before-destructive, idle reaping, broker
//! forwarding) can be tested in milliseconds and so a test can never depend on
//! `/dev/kvm` being available.
//!
//! It deliberately does *not* pretend to be isolation: [`VmInstance::kind`]
//! reports the provider it was asked to emulate and `Capabilities` is what
//! decides isolation, never this fake.

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Endpoint, Listener, Stream, Transport};
use crate::isolation::ProviderKind;
use crate::proto::{decode, encode, GuestMsg, HostMsg, VERSION};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A provider that "boots" a thread instead of a VM.
pub struct FakeProvider {
    kind: ProviderKind,
    /// Script the fake runs for `Exec` (default: `/bin/sh -c <script>`).
    pub root: PathBuf,
}

impl FakeProvider {
    pub fn new(root: PathBuf) -> FakeProvider {
        FakeProvider { kind: ProviderKind::Qemu, root }
    }
    /// Emulate a specific provider (so `stop`/`pid`/`usage` behave).
    pub fn kind(mut self, k: ProviderKind) -> FakeProvider {
        self.kind = k;
        self
    }
}

impl VmProvider for FakeProvider {
    fn kind(&self) -> ProviderKind {
        self.kind
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        let sock = spec.channel_path();
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("run dir: {e}"))?;
        // A unix socket where the OS has them (as before), a loopback port recorded in
        // `chan.sock` elsewhere — the same endpoint rules a real VMM follows.
        let listener = Endpoint::allocate(&sock)?.listen().map_err(|e| format!("bind {}: {e}", sock.display()))?;
        let root = if self.root.as_os_str().is_empty() { spec.run_dir.clone() } else { self.root.clone() };
        std::fs::create_dir_all(root.join("workspace")).ok();
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = running.clone();
        let agent = AgentThread { root, running: thread_running, spec: spec.clone() };
        std::thread::spawn(move || agent.serve(listener));
        Ok(Box::new(FakeInstance { spec: spec.clone(), running, chan: None }))
    }
}

struct AgentThread {
    root: PathBuf,
    running: Arc<AtomicBool>,
    spec: VmSpec,
}

impl AgentThread {
    fn serve(self, listener: Listener) {
        let Ok(stream) = listener.accept() else { return };
        let (mut r, mut w) = (stream.try_clone().unwrap(), stream);
        let _ = w.write_all(&encode(&GuestMsg::Hello { version: VERSION, agent: "fake-agent".into(), kernel: "fake".into(), cid: None, transport: self.spec.transport.name().into(), uid: 1000 }).unwrap());
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while self.running.load(Ordering::SeqCst) {
            let n = match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            let frames: Vec<HostMsg> = match decode::<HostMsg>(&buf) {
                Ok((f, used)) => {
                    buf.drain(..used);
                    f
                }
                Err(_) => break,
            };
            for m in frames {
                match m {
                    HostMsg::Ping { id } => send(&mut w, GuestMsg::Pong { id }),
                    HostMsg::Shutdown => {
                        self.running.store(false, Ordering::SeqCst);
                        return;
                    }
                    HostMsg::Limits { .. } => send(&mut w, GuestMsg::Ok { id: 0, detail: serde_json::Value::Null }),
                    HostMsg::Push { id, files } => {
                        let mut n = 0;
                        for f in files {
                            if crate::proto::check_rel_path(&f.path).is_err() {
                                send(&mut w, GuestMsg::Err { id, message: "bad path".into() });
                                continue;
                            }
                            let p = self.root.join("workspace").join(&f.path);
                            if let Some(parent) = p.parent() {
                                std::fs::create_dir_all(parent).ok();
                            }
                            if let Ok(data) = B64.decode(&f.data) {
                                std::fs::write(&p, data).ok();
                                n += 1;
                            }
                        }
                        send(&mut w, GuestMsg::Ok { id, detail: serde_json::json!({"files": n}) });
                    }
                    HostMsg::Pull { id, paths } => {
                        let mut files = Vec::new();
                        for p in paths {
                            if crate::proto::check_rel_path(&p).is_err() {
                                continue;
                            }
                            if let Ok(data) = std::fs::read(self.root.join("workspace").join(&p)) {
                                files.push(crate::proto::FileBlob { path: p, data: B64.encode(data), mode: 0o644 });
                            }
                        }
                        send(&mut w, GuestMsg::Files { id, files });
                    }
                    HostMsg::Exec { id, script, cwd, env, stdin, timeout_secs, .. } => {
                        let mut cmd = std::process::Command::new("sh");
                        cmd.arg("-c").arg(&script);
                        let base = self.root.join("workspace");
                        cmd.current_dir(match cwd.as_deref() {
                            Some(c) if c.starts_with(&self.spec.workspace.as_ref().map(|w| w.guest.clone()).unwrap_or_default()) => base.clone(),
                            _ => base.clone(),
                        });
                        cmd.env_clear();
                        for (k, v) in env {
                            cmd.env(k, v);
                        }
                        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).stdin(if stdin { std::process::Stdio::piped() } else { std::process::Stdio::null() });
                        let mut child = match cmd.spawn() {
                            Ok(c) => c,
                            Err(e) => {
                                send(&mut w, GuestMsg::Err { id, message: format!("exec: {e}") });
                                continue;
                            }
                        };
                        let mut readers: Vec<Box<dyn Read + Send>> = Vec::new();
                        if let Some(o) = child.stdout.take() {
                            readers.push(Box::new(o));
                        }
                        if let Some(e) = child.stderr.take() {
                            readers.push(Box::new(e));
                        }
                        let mut open = readers.len();
                        // Read both pipes without blocking forever: a line-based
                        // read is enough for the tests that use this.
                        let send_out = |w: &mut Stream, data: &[u8]| {
                            if !data.is_empty() {
                                send(w, GuestMsg::Out { id, data: B64.encode(data) });
                            }
                        };
                        loop {
                            let mut any = false;
                            let mut closed = 0;
                            for r in readers.iter_mut() {
                                let mut b = [0u8; 4096];
                                match r.read(&mut b) {
                                    Ok(0) => closed += 1,
                                    Ok(n) => {
                                        send_out(&mut w, &b[..n]);
                                        any = true;
                                    }
                                    Err(_) => closed += 1,
                                }
                            }
                            if any {
                                continue;
                            }
                            match child.try_wait() {
                                Ok(Some(st)) => {
                                    let code = st.code();
                                    send(&mut w, GuestMsg::Exit { id, code, signal: None });
                                    open = 0;
                                    break;
                                }
                                Ok(None) => {}
                                Err(_) => break,
                            }
                            let _ = timeout_secs;
                            let _ = &mut open;
                            let _ = closed;
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        let _ = child.wait();
                    }
                    HostMsg::BrokerReply { .. } | HostMsg::Stdin { .. } | HostMsg::Eof { .. } | HostMsg::Signal { .. } | HostMsg::Resize { .. } => {}
                }
            }
        }
    }
}

fn send(w: &mut Stream, m: GuestMsg) {
    if let Ok(b) = encode(&m) {
        let _ = w.write_all(&b);
    }
}

struct FakeInstance {
    spec: VmSpec,
    running: Arc<AtomicBool>,
    chan: Option<Arc<Channel>>,
}

impl VmInstance for FakeInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Qemu
    }
    fn pid(&self) -> Option<u32> {
        static FAKE_PID: AtomicU32 = AtomicU32::new(4242);
        Some(FAKE_PID.fetch_add(1, Ordering::SeqCst))
    }
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let ch = Channel::connect(&self.spec.channel_path(), Transport::Serial, wait)?;
        let ch = Arc::new(ch);
        self.chan = Some(ch.clone());
        Ok(ch)
    }
    fn is_running(&mut self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(c) = &self.chan {
            c.shutdown();
        }
    }
    fn usage(&self) -> VmUsage {
        VmUsage { rss_kb: 1024, cpu_ticks: 1, uptime_secs: 0 }
    }
}
