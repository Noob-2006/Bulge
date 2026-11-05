//! Provider interface: one `VmSpec` + one `VmInstance` trait for every way ark
//! can put a tool call behind a kernel boundary (B1), so Firecracker, QEMU and
//! the in-process fake used by tests are interchangeable from the pool's point
//! of view.

pub mod fake;
pub mod firecracker;
pub mod qemu;

use crate::channel::{Channel, Transport};
use crate::config::VmConfig;
use crate::isolation::{Capabilities, IsolationLevel, ProviderKind};
use crate::limits::Limits;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The workspace share for one VM.
#[derive(Debug, Clone, PartialEq)]
pub struct Workspace {
    /// Host directory. It is *synced* through the guest agent (no bind mount,
    /// no virtiofs path from the guest to the host fs) — a VM-level compromise
    /// cannot walk out of it.
    pub host: PathBuf,
    /// Where it appears in the guest.
    pub guest: String,
    /// `workspace_access = "ro"`: the guest agent refuses writes and the pool
    /// never pulls changes back.
    pub read_only: bool,
}

/// Everything a provider needs to boot one VM.
#[derive(Debug, Clone)]
pub struct VmSpec {
    pub id: String,
    /// Trust tier label (`owner`, `stranger`, `untrusted`, …) — carried into the
    /// cmdline and the log so a VM cannot be confused with another tier's.
    pub tier: String,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    /// Host directory for sockets, logs and the pid file of this VM.
    pub run_dir: PathBuf,
    pub vcpu: u16,
    pub mem_mb: u32,
    pub workspace: Option<Workspace>,
    pub limits: Limits,
    pub transport: Transport,
    pub firecracker: Option<PathBuf>,
    pub qemu: Option<PathBuf>,
    pub extra_args: Vec<String>,
    /// CID for AF_VSOCK (Firecracker guest CID is 3 by default; QEMU uses
    /// `vhost-vsock` — not used, see `Transport::Serial`).
    pub guest_cid: u32,
}

impl VmSpec {
    pub fn log(&self) -> PathBuf {
        self.run_dir.join("vm.log")
    }
    pub fn console_log(&self) -> PathBuf {
        self.run_dir.join("console.log")
    }
    /// The transport's host socket.
    pub fn channel_path(&self) -> PathBuf {
        match self.transport {
            Transport::Vsock { .. } => self.run_dir.join("vsock.sock"),
            Transport::Serial => self.run_dir.join("chan.sock"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq)]
pub struct VmUsage {
    pub rss_kb: u64,
    pub cpu_ticks: u64,
    pub uptime_secs: u64,
}

/// A booted VM. Every method is on `&mut self`: one owner (the pool) drives it.
pub trait VmInstance: Send {
    fn id(&self) -> &str;
    fn kind(&self) -> ProviderKind;
    /// Host pid of the VMM process (for limits, usage, kill).
    fn pid(&self) -> Option<u32>;
    /// Connect to the guest agent and wait for its `Hello`. Cached by the pool.
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String>;
    fn is_running(&mut self) -> bool;
    /// Kill the VM (and its VMM). Idempotent.
    fn stop(&mut self);
    fn usage(&self) -> VmUsage {
        VmUsage::default()
    }
    /// Pause/resume the guest (not every provider can).
    fn pause(&mut self) -> Result<(), String> {
        Err("this provider cannot pause".into())
    }
    fn resume(&mut self) -> Result<(), String> {
        Err("this provider cannot resume".into())
    }
    /// Provider-level memory snapshot into `dir`. `Ok(None)` = workspace
    /// snapshots only (still a valid undo point; not a RAM image).
    fn ram_snapshot(&mut self, _dir: &Path) -> Result<Option<PathBuf>, String> {
        Ok(None)
    }
    fn ram_restore(&mut self, _dir: &Path) -> Result<(), String> {
        Err("this provider has no memory snapshot".into())
    }
}

pub trait VmProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;
    fn isolation(&self) -> IsolationLevel {
        self.kind().isolation()
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String>;
}

/// Build the provider for `kind`, checking that the machine can run it.
pub fn build(kind: ProviderKind, cfg: &VmConfig) -> Result<Arc<dyn VmProvider>, String> {
    match kind {
        ProviderKind::Firecracker => Ok(Arc::new(firecracker::FirecrackerProvider::new(cfg))),
        ProviderKind::Qemu => Ok(Arc::new(qemu::QemuProvider::new(cfg))),
        ProviderKind::Gvisor | ProviderKind::Bwrap => Err(format!(
            "`{}` is not a microVM provider: it runs tools in a namespace sandbox on the host kernel ({})",
            kind.name(),
            kind.isolation().label()
        )),
    }
}

/// Which provider to use, given the config and the machine. Never silently
/// downgrades: a fallback is returned with the warning that must be shown.
pub fn select(cfg: &VmConfig, caps: &Capabilities) -> (ProviderKind, Option<String>) {
    if let Some(want) = ProviderKind::parse(&cfg.provider) {
        if want.is_vm() {
            let ok = match want {
                ProviderKind::Firecracker => caps.kvm && caps.firecracker.is_some() && caps.kernel.is_some() && caps.initramfs.is_some(),
                ProviderKind::Qemu => caps.kvm && caps.qemu.is_some() && caps.kernel.is_some() && caps.initramfs.is_some(),
                _ => false,
            };
            if ok {
                return (want, None);
            }
            if !cfg.allow_fallback {
                return (want, Some(format!("exec.vm.provider = `{}` is not usable here ({}) and exec.vm.allow_fallback = false", want.name(), blockers(want, caps))));
            }
            let best = caps.best().unwrap_or(ProviderKind::Bwrap);
            return (best, Some(format!("exec.vm.provider = `{}` is not usable here ({}); fell back to `{}` ({}).", want.name(), blockers(want, caps), best.name(), best.isolation().label())));
        }
        // Explicitly asked for a sandbox, no VM.
        if want != ProviderKind::Bwrap || caps.bwrap.is_some() {
            return (want, want.isolation().warning().map(|w| format!("{}: {w}", want.name())));
        }
        return (ProviderKind::Bwrap, Some(format!("`{}` not found; using bwrap", want.name())));
    }
    // "auto"
    let best = caps.best().unwrap_or(ProviderKind::Bwrap);
    if best == ProviderKind::Qemu && caps.firecracker.is_none() {
        // Be explicit: QEMU boots, but the guest channel needs a PCI kernel.
        return (best, Some("firecracker is not installed; using QEMU (needs a PCI-capable guest kernel for the guest channel — see docs)".into()));
    }
    if let Some(w) = best.isolation().warning() {
        return (best, Some(format!("no microVM available on this machine; tools run in a {} ({w})", best.isolation().label())));
    }
    (best, None)
}

fn blockers(kind: ProviderKind, caps: &Capabilities) -> String {
    let mut b = Vec::new();
    if !caps.kvm {
        b.push("/dev/kvm missing or not writable".to_string());
    }
    if kind == ProviderKind::Firecracker && caps.firecracker.is_none() {
        b.push("firecracker binary not found".into());
    }
    if kind == ProviderKind::Qemu && caps.qemu.is_none() {
        b.push("qemu-system-x86_64 not found".into());
    }
    if caps.kernel.is_none() {
        b.push("guest kernel missing (run `ark sandbox vm image build`)".into());
    }
    if caps.initramfs.is_none() {
        b.push("guest initramfs missing (run `ark sandbox vm image build`)".into());
    }
    b.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmConfig;

    fn caps_all() -> Capabilities {
        Capabilities { kvm: true, firecracker: Some("/bin/true".into()), qemu: Some("/bin/true".into()), bwrap: Some("/bin/true".into()), runsc: None, kernel: Some("/bin/true".into()), initramfs: Some("/bin/true".into()), arch: "x86_64".into() }
    }

    #[test]
    fn auto_prefers_firecracker_then_qemu_then_warns() {
        let cfg = VmConfig::default();
        let (k, w) = select(&cfg, &caps_all());
        assert_eq!(k, ProviderKind::Firecracker);
        assert!(w.is_none(), "a microVM needs no warning");
        let mut caps = caps_all();
        caps.firecracker = None;
        assert_eq!(select(&cfg, &caps).0, ProviderKind::Qemu);
        caps.qemu = None;
        let (k, w) = select(&cfg, &caps);
        assert_eq!(k, ProviderKind::Bwrap);
        assert!(w.unwrap().contains("no microVM"), "the downgrade is spelled out");
    }

    #[test]
    fn an_explicit_provider_never_downgrades_silently() {
        let mut cfg = VmConfig { provider: "firecracker".into(), allow_fallback: true, ..Default::default() };
        let mut caps = caps_all();
        caps.firecracker = None;
        let (k, w) = select(&cfg, &caps);
        assert_eq!(k, ProviderKind::Qemu);
        assert!(w.unwrap().contains("fell back"), "fallback is reported");
        cfg.allow_fallback = false;
        let (k2, w2) = select(&cfg, &caps);
        assert_eq!(k2, ProviderKind::Firecracker, "the caller still sees what was asked for");
        assert!(w2.unwrap().contains("allow_fallback = false"));
    }
}
