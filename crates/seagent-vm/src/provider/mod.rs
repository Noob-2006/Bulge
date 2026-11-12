//! Provider interface: one `VmSpec` + one `VmInstance` trait for every way seagent
//! can put a tool call behind a kernel boundary (B1), so Firecracker, QEMU and
//! the in-process fake used by tests are interchangeable from the pool's point
//! of view.
//!
//! Per OS (docs/cross-platform.md): Linux keeps Firecracker → QEMU-KVM. macOS: Apple
//! Virtualization.framework through `vfkit` ([`vfkit`]) → QEMU+HVF → VirtualBox. Windows:
//! QEMU+WHPX → Hyper-V ([`hosted`]) → VirtualBox ([`vbox`]); QEMU under TCG only as the last
//! VM, with its warning. Android: AVF/crosvm ([`hosted`]). iOS: none — [`build`] says so.

pub mod fake;
pub mod firecracker;
pub mod hosted;
pub mod qemu;
pub mod vbox;
pub mod vfkit;

use crate::channel::{Channel, Transport};
use crate::config::VmConfig;
use crate::host::{Accel, HostOs};
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
            Transport::Vsock { .. } | Transport::VsockProxy { .. } => self.run_dir.join("vsock.sock"),
            Transport::Serial | Transport::Uart => self.run_dir.join("chan.sock"),
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

/// The guest channel each provider wires up (what the pool puts in [`VmSpec::transport`]).
pub fn transport_for(kind: ProviderKind) -> Transport {
    match kind {
        ProviderKind::Firecracker => Transport::Vsock { port: crate::proto::VSOCK_PORT },
        ProviderKind::Vfkit | ProviderKind::Avf => Transport::VsockProxy { port: crate::proto::VSOCK_PORT },
        ProviderKind::VirtualBox | ProviderKind::HyperV => Transport::Uart,
        _ => Transport::Serial,
    }
}

/// Build the provider for `kind`, checking that the machine can run it.
pub fn build(kind: ProviderKind, cfg: &VmConfig) -> Result<Arc<dyn VmProvider>, String> {
    if HostOs::current() == HostOs::Ios && kind.is_vm() {
        return Err(hosted::IOS_NO_VM.into());
    }
    match kind {
        ProviderKind::Firecracker if !cfg!(target_os = "linux") => Err("firecracker is a Linux/KVM VMM; on this OS use the platform's provider (`seagent sandbox explain` lists them)".into()),
        ProviderKind::Firecracker => Ok(Arc::new(firecracker::FirecrackerProvider::new(cfg))),
        ProviderKind::Qemu => Ok(Arc::new(qemu::QemuProvider::new(cfg))),
        ProviderKind::Vfkit => Ok(Arc::new(vfkit::VfkitProvider::new(cfg))),
        ProviderKind::VirtualBox => Ok(Arc::new(vbox::VboxProvider::new(cfg))),
        ProviderKind::HyperV => Ok(Arc::new(hosted::HyperVProvider::new(cfg))),
        ProviderKind::Avf => Ok(Arc::new(hosted::AvfProvider::new(cfg))),
        ProviderKind::Gvisor | ProviderKind::Bwrap | ProviderKind::AppContainer | ProviderKind::Seatbelt => Err(format!(
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
            if let Some(accel) = caps.usable(want) {
                return (want, accel_note(want, accel, caps.os).or_else(|| nem_note(want, caps)));
            }
            if !cfg.allow_fallback {
                return (want, Some(format!("exec.vm.provider = `{}` is not usable here ({}) and exec.vm.allow_fallback = false", want.name(), blockers(want, caps))));
            }
            let best = caps.best().unwrap_or(ProviderKind::sandbox_fallback(caps.os));
            return (best, Some(format!("exec.vm.provider = `{}` is not usable here ({}); fell back to `{}` ({}).", want.name(), blockers(want, caps), best.name(), best.isolation().label())));
        }
        // Explicitly asked for a sandbox, no VM.
        if want != ProviderKind::Bwrap || caps.bwrap.is_some() {
            return (want, want.isolation().warning().map(|w| format!("{}: {w}", want.name())));
        }
        return (ProviderKind::Bwrap, Some(format!("`{}` not found; using bwrap", want.name())));
    }
    // "auto"
    let best = caps.best().unwrap_or(ProviderKind::sandbox_fallback(caps.os));
    if best == ProviderKind::Qemu && caps.firecracker.is_none() && caps.os == HostOs::Linux {
        // Be explicit: QEMU boots, but the guest channel needs a PCI kernel.
        return (best, Some("firecracker is not installed; using QEMU (needs a PCI-capable guest kernel for the guest channel — see docs)".into()));
    }
    if let Some((kind, accel)) = caps.best_vm() {
        if let Some(note) = accel_note(kind, accel, caps.os).or_else(|| nem_note(kind, caps)) {
            return (kind, Some(note));
        }
    }
    if let Some(w) = best.isolation().warning() {
        return (best, Some(format!("no microVM available on this machine; tools run in {} ({w})", with_article(best.isolation().label()))));
    }
    (best, None)
}

/// The accelerator `kind` runs with on this machine (`None`: it cannot run here). For
/// `seagent doctor`, `seagent sandbox vm exec` and the boot log.
pub fn accel_of(kind: ProviderKind, caps: &Capabilities) -> Option<Accel> {
    caps.usable(kind)
}

/// `a user-namespace`, `an os-sandbox`, `an app-kernel (gVisor)`: the article the level's
/// label takes when it is pronounced (Linux's "a user-namespace" text is unchanged).
fn with_article(label: &str) -> String {
    let an = label.starts_with("os-") || label.starts_with("app-");
    format!("{} {label}", if an { "an" } else { "a" })
}

/// VirtualBox on a Windows host whose hypervisor is running (WSL2, Hyper-V, VBS — what makes
/// WHPX available) cannot use VT-x itself and runs on the Windows Hypervisor Platform ("NEM").
/// Measured with VirtualBox 7.2.22: there an SMP guest hangs in the UEFI firmware's AP
/// start-up (`EFI: debug point DXE_AP`), so the provider boots it with one vCPU.
pub fn nem_note(kind: ProviderKind, caps: &Capabilities) -> Option<String> {
    (kind == ProviderKind::VirtualBox && caps.os == HostOs::Windows && caps.whpx).then(|| {
        "virtualbox runs on the Windows Hypervisor Platform (NEM: the Windows hypervisor holds VT-x) — slower than native VirtualBox, and the VM gets 1 vCPU because SMP guests hang in the UEFI AP start-up under NEM".to_string()
    })
}

/// What the operator must be told about a VM that *does* boot but is weaker than the design
/// target: no hardware acceleration (TCG), or a guest channel other local processes can reach.
/// `None` for KVM/Firecracker and the other hardware-backed providers.
pub fn accel_note(kind: ProviderKind, accel: Accel, os: HostOs) -> Option<String> {
    if accel == Accel::Tcg {
        let fix = match os {
            HostOs::Windows => "enable the Windows feature `HypervisorPlatform` (and VT-x/AMD-V in firmware) for -accel whpx",
            HostOs::Macos => "this Mac reports kern.hv_support = 0 (no Hypervisor.framework)",
            _ => "no hardware accelerator is available",
        };
        return Some(format!(
            "{} runs WITHOUT hardware acceleration (QEMU TCG software emulation): the guest still has its own kernel, but it is slow and the whole emulator is attack surface — {fix}",
            kind.name()
        ));
    }
    if kind == ProviderKind::Qemu && os == HostOs::Windows {
        return Some("qemu (whpx): the guest channel is a TCP port on 127.0.0.1 (Windows QEMU has no unix sockets); other local processes can connect to it, but both ends prove a per-boot key (handed to the guest by fw_cfg, never on a command line) before any frame counts, so they can delay the VM but not impersonate or drive either side".into());
    }
    None
}

fn blockers(kind: ProviderKind, caps: &Capabilities) -> String {
    let mut b = Vec::new();
    let needs_kvm = matches!(kind, ProviderKind::Firecracker | ProviderKind::Avf) || (kind == ProviderKind::Qemu && matches!(caps.os, HostOs::Linux | HostOs::Android));
    if needs_kvm && !caps.kvm {
        b.push("/dev/kvm missing or not writable".to_string());
    }
    if kind == ProviderKind::Firecracker && caps.firecracker.is_none() {
        b.push(if caps.os == HostOs::Linux { "firecracker binary not found".into() } else { format!("firecracker runs on Linux only (this is {})", caps.os.name()) });
    }
    if kind == ProviderKind::Qemu && caps.qemu.is_none() {
        b.push(format!("{} not found", if caps.os == HostOs::Linux { "qemu-system-x86_64" } else { crate::host::native_qemu() }));
    }
    match kind {
        ProviderKind::Vfkit if caps.os != HostOs::Macos => b.push("vfkit (Virtualization.framework) exists on macOS only".into()),
        ProviderKind::Vfkit if caps.vfkit.is_none() => b.push("vfkit not found (brew install vfkit)".into()),
        ProviderKind::Vfkit if !caps.hvf => b.push("Hypervisor.framework unavailable (kern.hv_support = 0)".into()),
        ProviderKind::HyperV if caps.os != HostOs::Windows => b.push("Hyper-V exists on Windows only".into()),
        ProviderKind::HyperV if caps.hyperv.is_none() => b.push(match &caps.hyperv_blocker {
            Some(why) => format!("Hyper-V {why}"),
            None => "Hyper-V is not installed (Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All)".into(),
        }),
        ProviderKind::VirtualBox if caps.vbox.is_none() => b.push("VBoxManage not found (install Oracle VirtualBox)".into()),
        ProviderKind::Avf if caps.os != HostOs::Android => b.push("AVF exists on Android only".into()),
        ProviderKind::Avf if caps.avf.is_none() => b.push(hosted::AVF_MISSING.into()),
        _ => {}
    }
    if matches!(kind, ProviderKind::VirtualBox | ProviderKind::HyperV) && caps.disk_image.is_none() {
        b.push("bootable guest disk missing (exec.vm.disk_image; VirtualBox and Hyper-V cannot boot a kernel + initramfs directly)".into());
    }
    if caps.kernel.is_none() {
        b.push(format!("guest kernel missing ({})", crate::bundle::fix_hint()));
    }
    if caps.initramfs.is_none() {
        b.push(format!("guest initramfs missing ({})", crate::bundle::fix_hint()));
    }
    b.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmConfig;

    fn caps_all() -> Capabilities {
        Capabilities { kvm: true, firecracker: Some("/bin/true".into()), qemu: Some("/bin/true".into()), bwrap: Some("/bin/true".into()), runsc: None, kernel: Some("/bin/true".into()), initramfs: Some("/bin/true".into()), arch: "x86_64".into(), ..Default::default() }
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

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

    /// Windows counterpart of `auto_prefers_firecracker_then_qemu_then_warns`: QEMU+WHPX, then
    /// Hyper-V, then VirtualBox, then QEMU under TCG (warned), then no VM at all (warned).
    #[test]
    fn auto_on_windows_prefers_qemu_whpx_then_hyperv_then_vbox_then_tcg_then_warns() {
        let cfg = VmConfig::default();
        let mut w = caps_on(HostOs::Windows);
        assert_eq!(select(&cfg, &w).0, ProviderKind::Qemu);
        assert_eq!(accel_of(ProviderKind::Qemu, &w), Some(Accel::Whpx));
        w.whpx = false;
        assert_eq!(select(&cfg, &w).0, ProviderKind::HyperV);
        w.hyperv = None;
        assert_eq!(select(&cfg, &w), (ProviderKind::VirtualBox, None), "VirtualBox is hardware-backed: no warning");
        w.vbox = None;
        let (k, note) = select(&cfg, &w);
        assert_eq!((k, accel_of(k, &w)), (ProviderKind::Qemu, Some(Accel::Tcg)));
        assert!(note.unwrap().contains("WITHOUT hardware acceleration"));
        w.qemu = None;
        let (k, note) = select(&cfg, &w);
        assert!(!k.is_vm() && accel_of(k, &w).is_none());
        // The fallback is named after what really runs on Windows: AppContainer, not bwrap.
        assert_eq!(k, ProviderKind::AppContainer);
        let note = note.unwrap();
        assert!(note.contains("no microVM") && note.contains("tools run in an os-sandbox") && !note.contains("bwrap"), "the downgrade is spelled out: {note}");
        assert_eq!((with_article("user-namespace"), with_article("app-kernel (gVisor)")), ("a user-namespace".to_string(), "an app-kernel (gVisor)".to_string()));
        // macOS likewise falls back to Seatbelt; Linux keeps bwrap.
        let mut m = caps_on(HostOs::Macos);
        (m.vfkit, m.qemu, m.vbox) = (None, None, None);
        assert_eq!(select(&VmConfig::default(), &m).0, ProviderKind::Seatbelt);
        assert_eq!(ProviderKind::Seatbelt.isolation(), IsolationLevel::OsSandbox);
        let mut l = caps_on(HostOs::Linux);
        l.kvm = false;
        assert_eq!(select(&VmConfig::default(), &l).0, ProviderKind::Bwrap);
    }

    /// This machine's case: Windows Home, WHPX on, no Hyper-V role. `auto` takes QEMU+WHPX; an
    /// explicit `hyperv` falls back to it and says *why* (Home edition), not "enable a feature".
    #[test]
    fn hyperv_on_windows_home_is_reported_as_such_and_auto_selects_the_next_provider() {
        let mut w = caps_on(HostOs::Windows);
        w.hyperv = None;
        w.vbox = None;
        w.hyperv_blocker = crate::host::hyperv_reason(Some("Core"), false, false);
        assert_eq!(select(&VmConfig::default(), &w).0, ProviderKind::Qemu);
        let cfg = VmConfig { provider: "hyperv".into(), ..Default::default() };
        let (k, why) = select(&cfg, &w);
        let why = why.unwrap();
        assert_eq!(k, ProviderKind::Qemu, "{why}");
        assert!(why.contains("Windows Home") && why.contains("fell back to `qemu`") && !why.contains("Enable-WindowsOptionalFeature"), "{why}");
        let strict = VmConfig { provider: "hyperv".into(), allow_fallback: false, ..Default::default() };
        let (k, why) = select(&strict, &w);
        assert_eq!(k, ProviderKind::HyperV, "asked for and refused, never silently swapped");
        assert!(why.unwrap().contains("Windows Home"));
        assert!(w.report().iter().any(|l| l.starts_with("hyper-v: unavailable on Windows Home")), "{:?}", w.report());
        // VirtualBox with the Windows hypervisor running is on NEM, and says so (1 vCPU).
        let mut v = caps_on(HostOs::Windows);
        (v.qemu, v.hyperv) = (None, None);
        let (k, note) = select(&VmConfig::default(), &v);
        assert_eq!(k, ProviderKind::VirtualBox);
        assert!(note.as_deref().is_some_and(|n| n.contains("NEM") && n.contains("1 vCPU")), "{note:?}");
        v.whpx = false;
        assert_eq!(select(&VmConfig::default(), &v), (ProviderKind::VirtualBox, None), "native VirtualBox: nothing to say");
    }

    /// Capabilities of a machine running `os`, with every ingredient there (pure: no probing).
    fn caps_on(os: HostOs) -> Capabilities {
        Capabilities {
            os,
            kvm: matches!(os, HostOs::Linux | HostOs::Android),
            whpx: os == HostOs::Windows,
            hvf: os == HostOs::Macos,
            firecracker: (os == HostOs::Linux).then(|| "/bin/fc".into()),
            qemu: Some("/bin/qemu".into()),
            vfkit: (os == HostOs::Macos).then(|| "/bin/vfkit".into()),
            vbox: Some("/bin/VBoxManage".into()),
            hyperv: (os == HostOs::Windows).then(|| "powershell".into()),
            avf: (os == HostOs::Android).then(|| "/apex/com.android.virt/bin/vm".into()),
            disk_image: Some("/img/disk.raw".into()),
            kernel: Some("/img/vmlinux".into()),
            initramfs: Some("/img/initramfs.cpio.gz".into()),
            ..Default::default()
        }
    }

    fn order(c: &Capabilities) -> Vec<(ProviderKind, Accel)> {
        c.vm_candidates()
    }

    #[test]
    fn each_os_picks_its_strongest_vm_first() {
        use Accel::*;
        use ProviderKind::*;
        // Linux: unchanged (Firecracker, QEMU-KVM; VirtualBox only when asked for).
        assert_eq!(order(&caps_on(HostOs::Linux)), vec![(Firecracker, Kvm), (Qemu, Kvm)]);
        // macOS: Virtualization.framework (vfkit) > QEMU+HVF > VirtualBox.
        assert_eq!(order(&caps_on(HostOs::Macos)), vec![(Vfkit, Hvf), (Qemu, Hvf), (VirtualBox, Vbox)]);
        // Windows: QEMU+WHPX > Hyper-V > VirtualBox.
        // (VirtualBox on a Windows host with its hypervisor running is on NEM, i.e. WHPX.)
        assert_eq!(order(&caps_on(HostOs::Windows)), vec![(Qemu, Whpx), (HyperV, Hyperv), (VirtualBox, Whpx)]);
        // Android: AVF only; iOS: nothing at all, ever.
        assert_eq!(order(&caps_on(HostOs::Android)), vec![(Avf, Kvm)]);
        assert!(order(&caps_on(HostOs::Ios)).is_empty());
        let cfg = VmConfig::default();
        for (os, want) in [(HostOs::Linux, Firecracker), (HostOs::Macos, Vfkit), (HostOs::Windows, Qemu), (HostOs::Android, Avf)] {
            let (k, w) = select(&cfg, &caps_on(os));
            assert_eq!(k, want, "{os:?}");
            assert_eq!(k.isolation(), IsolationLevel::MicroVm);
            if os != HostOs::Windows {
                assert!(w.is_none(), "{os:?}: a hardware VM needs no warning: {w:?}");
            }
        }
    }

    #[test]
    fn without_hardware_acceleration_qemu_is_the_last_vm_and_says_tcg() {
        use ProviderKind::*;
        // Windows without WHPX: Hyper-V and VirtualBox still beat software emulation.
        let mut w = caps_on(HostOs::Windows);
        w.whpx = false;
        assert_eq!(order(&w).iter().map(|c| c.0).collect::<Vec<_>>(), vec![HyperV, VirtualBox, Qemu]);
        assert_eq!(select(&VmConfig::default(), &w).0, HyperV);
        // … and with neither, QEMU under TCG, loudly.
        w.hyperv = None;
        w.vbox = None;
        let (k, note) = select(&VmConfig::default(), &w);
        assert_eq!((k, caps_accel(&w)), (Qemu, Some(Accel::Tcg)));
        let note = note.unwrap();
        assert!(note.contains("WITHOUT hardware acceleration") && note.contains("HypervisorPlatform"), "{note}");
        assert!(w.warning().unwrap().contains("TCG"));
        // macOS without HVF: vfkit cannot run at all; QEMU falls to TCG behind VirtualBox.
        let mut m = caps_on(HostOs::Macos);
        m.hvf = false;
        assert_eq!(order(&m).iter().map(|c| c.0).collect::<Vec<_>>(), vec![VirtualBox, Qemu]);
        // Linux never uses TCG: no KVM means no microVM (unchanged).
        let mut l = caps_on(HostOs::Linux);
        l.kvm = false;
        assert!(order(&l).is_empty() && !l.can_boot_vm());
    }

    fn caps_accel(c: &Capabilities) -> Option<Accel> {
        c.best_vm().map(|(_, a)| a)
    }

    #[test]
    fn whpx_qemu_names_its_loopback_channel_and_explicit_choices_are_honoured() {
        let w = caps_on(HostOs::Windows);
        let (k, note) = select(&VmConfig::default(), &w);
        assert_eq!(k, ProviderKind::Qemu);
        assert!(note.unwrap().contains("127.0.0.1"), "a reachable loopback channel is not hidden");
        // Explicit VirtualBox on Linux works when VBoxManage and a disk exist …
        let cfg = VmConfig { provider: "virtualbox".into(), ..Default::default() };
        assert_eq!(select(&cfg, &caps_on(HostOs::Linux)), (ProviderKind::VirtualBox, None));
        // … and without the bootable disk it falls back, saying why.
        let mut l = caps_on(HostOs::Linux);
        l.disk_image = None;
        let (k, w) = select(&cfg, &l);
        assert_eq!(k, ProviderKind::Firecracker);
        assert!(w.unwrap().contains("bootable guest disk missing"));
        // Hyper-V named on macOS: refused with the reason, never pretended.
        let cfg = VmConfig { provider: "hyperv".into(), allow_fallback: false, ..Default::default() };
        let (k, w) = select(&cfg, &caps_on(HostOs::Macos));
        assert_eq!(k, ProviderKind::HyperV);
        assert!(w.unwrap().contains("Windows only"));
        assert_eq!(transport_for(ProviderKind::Vfkit), Transport::VsockProxy { port: crate::proto::VSOCK_PORT });
        assert_eq!(transport_for(ProviderKind::HyperV), Transport::Uart);
        assert_eq!(transport_for(ProviderKind::Qemu), Transport::Serial);
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
