//! Host-side supervision of one guest VM.
//!
//! Process tree per VM:
//!   bulge (this) ─┬─ passt        (virtual NIC, fd 3 = our filtered socketpair end)
//!                 ├─ relay threads (egress filter between VMM and passt)
//!                 └─ bulge-vmm    (becomes the VM; fd 3 = VM side of the NIC)
//! The control channel is the guest's vsock port, which libkrun exposes as a
//! unix socket inside a private 0700 runtime directory.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bulge_proto::frame::{PeerRole, SessionKey};
use bulge_proto::msg::{BOOTSTRAP_PATH, Bootstrap, CONTROL_VSOCK_PORT, GuestMessage, HostMessage, Outcome};
use bulge_proto::session::{SessionParams, establish};
use command_fds::{CommandFdExt, FdMapping};
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};

use crate::net::{EgressPolicy, RelayHandle, spawn_relay};

/// passt's DNS forwarder address handed to the guest. A documentation range
/// (never routed); the egress policy allows it on port 53 only.
const DNS_FORWARDER: &str = "198.51.100.53";
const CONTROL_SOCKET: &str = "control.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct VmConfig {
    pub vmm_binary: PathBuf,
    /// Directory holding libkrun.so / libkrunfw.so (libkrun dlopens libkrunfw).
    pub libkrun_dir: PathBuf,
    pub rootfs: PathBuf,
    /// Host directory exposed read-only as the guest's workspace lower layer.
    pub workspace: PathBuf,
    /// Parent of the per-VM 0700 runtime directory.
    pub runtime_root: PathBuf,
    pub cpus: u8,
    pub ram_mib: u32,
    pub network: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("session: {0}")]
    Session(#[from] bulge_proto::session::SessionError),
    #[error("{0}")]
    Other(String),
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Outcome>>>>;

pub struct Vm {
    vmm: Child,
    passt: Option<Child>,
    relay: Option<RelayHandle>,
    sender: Mutex<bulge_proto::session::Sender<UnixStream>>,
    pending: Pending,
    next_id: AtomicU64,
    commands: Vec<String>,
    runtime_dir: PathBuf,
}

fn random_hex(bytes: usize) -> Result<String, VmError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| VmError::Other(format!("getrandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

impl Vm {
    pub async fn launch(config: VmConfig) -> Result<Self, VmError> {
        let session_id = random_hex(16)?;
        let runtime_dir = config.runtime_root.join(&session_id);
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&runtime_dir)?;
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))?;

        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|e| VmError::Other(format!("getrandom: {e}")))?;
        let bootstrap = Bootstrap {
            session_key_hex: key.iter().map(|b| format!("{b:02x}")).collect(),
            session_id: session_id.clone(),
            generation: 1,
        };

        // Network: VMM <-> relay (filter) <-> passt.
        let (mut passt, mut relay, mut vm_net) = (None, None, None);
        if config.network {
            let (vm_ours, vm_theirs) = StdUnixStream::pair()?;
            let (net_ours, net_theirs) = StdUnixStream::pair()?;
            let mut command = Command::new("passt");
            command
                .args(["-f", "-q", "--no-map-gw", "-t", "none", "-u", "none", "--dns-forward", DNS_FORWARDER, "-D", DNS_FORWARDER])
                .args(["--dns-host", &host_resolver(), "--fd", "3"])
                .stdin(Stdio::null())
                .kill_on_drop(true);
            command
                .fd_mappings(vec![FdMapping { parent_fd: OwnedFd::from(net_theirs), child_fd: 3 }])
                .map_err(|e| VmError::Other(format!("fd mapping: {e}")))?;
            passt = Some(command.spawn()?);
            let dns = DNS_FORWARDER.parse().map_err(|_| VmError::Other("bad DNS forwarder".into()))?;
            relay = Some(spawn_relay(vm_ours, net_ours, EgressPolicy::new(dns))?);
            vm_net = Some(vm_theirs);
        }

        let control_path = runtime_dir.join(CONTROL_SOCKET);
        let vmm_config = json!({
            "rootfs": config.rootfs,
            "cpus": config.cpus,
            "ram_mib": config.ram_mib,
            "net_fd": vm_net.as_ref().map(|_| 3),
            "shares": [{ "tag": "workspace", "host_path": config.workspace }],
            "vsock_listen": [{ "port": CONTROL_VSOCK_PORT, "host_socket": control_path }],
            "one_shot_files": [{
                "path": BOOTSTRAP_PATH.trim_start_matches('/'),
                "contents": serde_json::to_string(&bootstrap).map_err(|e| VmError::Other(e.to_string()))?,
                "mode": 0o400,
            }],
            "exec": "/usr/local/bin/sandboxd",
            "env": ["PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root"],
        });
        let log = std::fs::File::create(runtime_dir.join("vmm.log"))?;
        let mut command = Command::new(&config.vmm_binary);
        command
            .env_clear()
            .env("LD_LIBRARY_PATH", &config.libkrun_dir)
            .stdin(Stdio::piped())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true);
        if let Some(fd) = vm_net {
            command
                .fd_mappings(vec![FdMapping { parent_fd: OwnedFd::from(fd), child_fd: 3 }])
                .map_err(|e| VmError::Other(format!("fd mapping: {e}")))?;
        }
        let mut vmm = command.spawn()?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = vmm.stdin.take().ok_or_else(|| VmError::Other("vmm stdin".into()))?;
            stdin.write_all(vmm_config.to_string().as_bytes()).await?;
            stdin.shutdown().await?;
        }

        let (sender, mut receiver) = connect_control(&control_path, &mut vmm, &key, &session_id).await?;
        key.fill(0);
        let ready: GuestMessage = receiver.recv().await?;
        let GuestMessage::Ready { commands } = ready else {
            return Err(VmError::Other("guest did not send Ready first".into()));
        };

        let pending: Pending = Arc::default();
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            while let Ok(message) = receiver.recv::<GuestMessage>().await {
                if let GuestMessage::Result { id, outcome } = message
                    && let Some(waiter) = reader_pending.lock().await.remove(&id)
                {
                    let _ = waiter.send(outcome);
                }
            }
            // Channel closed: fail every outstanding call.
            for (_, waiter) in reader_pending.lock().await.drain() {
                let _ = waiter.send(Outcome::Err { code: "CHANNEL_CLOSED".into(), message: "guest channel closed".into() });
            }
        });

        Ok(Self { vmm, passt, relay, sender: Mutex::new(sender), pending, next_id: AtomicU64::new(1), commands, runtime_dir })
    }

    pub fn commands(&self) -> &[String] {
        &self.commands
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn network_stats(&self) -> Option<Arc<crate::net::RelayStats>> {
        self.relay.as_ref().map(|r| r.stats.clone())
    }

    pub async fn invoke(&self, command: &str, params: Value, timeout: Option<Duration>) -> Outcome {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let message = HostMessage::Invoke {
            id,
            command: command.to_owned(),
            params,
            timeout_ms: timeout.map(|t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX)),
        };
        if let Err(error) = self.sender.lock().await.send(&message).await {
            self.pending.lock().await.remove(&id);
            return Outcome::Err { code: "SEND_FAILED".into(), message: error.to_string() };
        }
        rx.await.unwrap_or(Outcome::Err { code: "CHANNEL_CLOSED".into(), message: "guest channel closed".into() })
    }

    pub async fn shutdown(mut self) {
        let _ = self.sender.lock().await.send(&HostMessage::Shutdown).await;
        if tokio::time::timeout(Duration::from_secs(5), self.vmm.wait()).await.is_err() {
            let _ = self.vmm.kill().await;
        }
        if let Some(relay) = self.relay.take() {
            relay.shutdown();
        }
        if let Some(mut passt) = self.passt.take() {
            let _ = passt.kill().await;
        }
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

type Halves = (bulge_proto::session::Sender<UnixStream>, bulge_proto::session::Receiver<UnixStream>);

/// libkrun creates the host socket at boot, but the guest only accepts once
/// sandboxd is listening; until then connections are dropped. Retry the whole
/// connect + handshake (fresh channel state each time) until it succeeds, the
/// VMM dies, or the deadline passes.
async fn connect_control(path: &Path, vmm: &mut Child, key: &[u8; 32], session_id: &str) -> Result<Halves, VmError> {
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        if let Some(status) = vmm.try_wait()? {
            return Err(VmError::Other(format!("VMM exited during boot: {status}")));
        }
        if let Ok(stream) = UnixStream::connect(path).await {
            let params = SessionParams {
                key: SessionKey::from_bytes(*key),
                session_id: session_id.to_owned(),
                generation: 1,
                name: "bulge".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                artifact_identity: concat!("bulge-", env!("CARGO_PKG_VERSION")).into(),
            };
            if let Ok((sender, receiver, _)) = establish(stream, PeerRole::Host, params).await {
                return Ok((sender, receiver));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(VmError::Other("timed out waiting for guest control channel".into()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// First nameserver from the host's resolv.conf (often the systemd-resolved stub).
fn host_resolver() -> String {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|text| {
            text.lines()
                .filter_map(|line| line.strip_prefix("nameserver"))
                .map(|rest| rest.trim().to_owned())
                .next()
        })
        .unwrap_or_else(|| "127.0.0.53".to_owned())
}
