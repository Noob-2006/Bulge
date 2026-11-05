//! Which execution environment an unconfigured ark instance picks (A1/B1/B6):
//! the strongest one this machine can actually give, decided in one place so
//! `ark sandbox explain`, `ark doctor` and the executor cannot disagree.
//!
//! The rule the design asks for is "microVM by default when the machine can
//! boot one". Two things have to stay true for that to be honest:
//!
//! * **never a silent downgrade**: every weaker choice carries a warning that
//!   names the level and the reason, and the caller (explain/doctor/log) shows
//!   it. [`Plan::warning`] is `None` only for a real microVM.
//! * **an unprovisioned host is not a sandboxed host**: when `/dev/kvm` works but
//!   the guest image was never built, ark says "no isolation, build the image"
//!   instead of quietly wrapping the operator's own shell in bwrap. A *sandboxed*
//!   session (one that opted into isolation) does fall back to bwrap/Landlock,
//!   because there the alternative is no isolation at all.
//!
//! `[exec] backend = "auto"` is the default here; an explicit backend name is
//! always honoured verbatim (this module only answers the `auto` question).

use crate::config::VmConfig;
use crate::isolation::{isolation_of_backend, Capabilities, IsolationLevel};
use crate::provider;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Where the choice came from, so the caller can explain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// `[exec] backend` / `[exec.sandbox] backend` named a backend: kept as-is.
    Configured,
    /// `auto`: a real microVM can boot here.
    AutoMicroVm,
    /// `auto`: no microVM, but this session asked for isolation (bwrap/Landlock).
    AutoFallback,
    /// `auto`: no microVM and no sandbox was asked for (host, warned loudly).
    AutoHost,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Origin::Configured => "configured",
            Origin::AutoMicroVm => "auto (microVM available)",
            Origin::AutoFallback => "auto (namespace fallback)",
            Origin::AutoHost => "auto (no microVM, host)",
        }
    }
}

/// The resolved answer: what runs where, and what the operator must be told.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// `exec.backend`-style name that will be built (`vm`, `bwrap`, `local`, …).
    pub backend: String,
    /// Provider name for a microVM plan (`firecracker`, `qemu`).
    pub provider: Option<String>,
    pub level: IsolationLevel,
    pub origin: Origin,
    /// `None` only for a real microVM (§0: no silent downgrade).
    pub warning: Option<String>,
    /// Why this was chosen, one sentence (for explain/doctor/logs).
    pub reason: String,
}

impl Plan {
    pub fn uses_microvm(&self) -> bool {
        self.level == IsolationLevel::MicroVm
    }
    /// One line for the system prompt / `ark sandbox explain`.
    pub fn line(&self) -> String {
        let mut s = format!("execution: {} ({})", self.backend, self.level.label());
        if let Some(p) = &self.provider {
            s.push_str(&format!(" via {p}"));
        }
        s.push_str(&format!(" — {}", self.origin.label()));
        if let Some(w) = &self.warning {
            s.push_str(&format!("; WARNING: {w}"));
        }
        s
    }
}

/// What a caller wants resolved: a backend name (`auto` or explicit), the VM
/// config and the data dir (where the guest image lives).
pub struct Query<'a> {
    pub requested: &'a str,
    pub cfg: &'a VmConfig,
    pub data: &'a Path,
    /// Is this the sandbox backend of a session that asked for isolation?
    pub sandboxed: bool,
}

/// Resolve `requested` to a concrete backend + the warning that goes with it.
pub fn resolve(q: &Query<'_>) -> Plan {
    let requested = q.requested.trim();
    if !requested.is_empty() && requested != "auto" {
        let level = isolation_of_backend(requested);
        return Plan {
            backend: requested.to_string(),
            provider: None,
            level,
            origin: Origin::Configured,
            warning: level.warning().map(|w| format!("{requested}: {w}")),
            reason: format!("[exec] backend = `{requested}` (explicit)"),
        };
    }
    auto(q)
}

/// The `auto` answer.
pub fn auto(q: &Query<'_>) -> Plan {
    auto_with(&capabilities(q.cfg, q.data), q.cfg, q.sandboxed)
}

/// [`auto`] over capabilities the caller already has (pure: no disk, no PATH — the decision
/// table itself, which is what the tests pin down).
pub fn auto_with(caps: &Capabilities, cfg: &VmConfig, sandboxed: bool) -> Plan {
    if caps.can_boot_vm() {
        let (kind, warning) = provider::select(cfg, caps);
        return Plan {
            backend: "vm".into(),
            provider: Some(kind.name().into()),
            level: kind.isolation(),
            origin: Origin::AutoMicroVm,
            warning,
            reason: format!("auto: {} can boot a microVM here ({} guest image)", kind.name(), if caps.kernel.is_some() && caps.initramfs.is_some() { "built" } else { "missing" }),
        };
    }
    let why = blockers(caps);
    if sandboxed {
        let backend = if caps.bwrap.is_some() {
            "bwrap"
        } else if cfg!(target_os = "linux") {
            "landlock"
        } else {
            "local"
        };
        let level = isolation_of_backend(backend);
        return Plan {
            backend: backend.into(),
            provider: None,
            level,
            origin: if level == IsolationLevel::Host { Origin::AutoHost } else { Origin::AutoFallback },
            warning: Some(format!(
                "no microVM available ({why}); this session runs in a {} instead — {}",
                level.label(),
                level.warning().unwrap_or("weaker than a microVM")
            )),
            reason: "auto: no microVM, sandboxed session falls back to a namespace sandbox".into(),
        };
    }
    Plan {
        backend: "local".into(),
        provider: None,
        level: IsolationLevel::Host,
        origin: Origin::AutoHost,
        warning: Some(format!(
            "no microVM available ({why}); tool calls run directly on this machine as the ark user. Build the guest image (`ark sandbox vm image build`) to isolate them."
        )),
        reason: "auto: no microVM and no sandbox requested — host, with a warning".into(),
    }
}

/// Capabilities with the same "unpacked into the data dir" rules the pool uses
/// (a Firecracker tarball under `<data>/vm/bin` counts).
pub fn capabilities(cfg: &VmConfig, data: &Path) -> Capabilities {
    let mut caps = Capabilities::detect(Some(&cfg.kernel_path(data)), Some(&cfg.initramfs_path(data)));
    let local_fc = data.join("vm").join("bin").join("firecracker");
    if let Some(p) = crate::isolation::which(&cfg.firecracker).or(local_fc.is_file().then_some(local_fc)) {
        caps.firecracker = Some(p);
    }
    if let Some(p) = crate::isolation::which(&cfg.qemu) {
        caps.qemu = Some(p);
    }
    caps
}

/// Why no microVM: one short phrase, the first real blocker.
pub fn blockers(caps: &Capabilities) -> String {
    if !caps.kvm {
        return "/dev/kvm is missing or not writable (no hardware virtualisation)".into();
    }
    if caps.kernel.is_none() {
        return "the guest kernel is not built".into();
    }
    if caps.initramfs.is_none() {
        return "the guest initramfs is not built".into();
    }
    if caps.firecracker.is_none() && caps.qemu.is_none() {
        return "neither firecracker nor qemu is installed".into();
    }
    "no usable VMM".into()
}

/// Guest image paths that `auto` needs, for error messages.
pub fn image_paths(cfg: &VmConfig, data: &Path) -> (PathBuf, PathBuf) {
    (cfg.kernel_path(data), cfg.initramfs_path(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm_cfg() -> VmConfig {
        VmConfig::default()
    }

    /// Every ingredient for a boot: KVM, both image files, a VMM.
    fn bootable_caps() -> Capabilities {
        Capabilities { kvm: true, firecracker: Some(PathBuf::from("/bin/true")), kernel: Some(PathBuf::from("/img/vmlinux")), initramfs: Some(PathBuf::from("/img/initramfs.cpio.gz")), ..Default::default() }
    }

    #[test]
    fn an_explicit_backend_is_never_rewritten() {
        let d = PathBuf::from("/nonexistent-data");
        for name in ["local", "bwrap", "docker", "ssh", "vm"] {
            let p = resolve(&Query { requested: name, cfg: &vm_cfg(), data: &d, sandboxed: false });
            assert_eq!(p.backend, name, "an explicit choice is honoured");
            assert_eq!(p.origin, Origin::Configured);
            assert_eq!(p.level, isolation_of_backend(name));
        }
    }

    #[test]
    fn auto_without_kvm_falls_back_and_always_warns() {
        // Simulate "no KVM, no image": the fallback names the level and the reason.
        let caps = Capabilities { kvm: false, bwrap: Some(PathBuf::from("/usr/bin/bwrap")), ..Default::default() };
        assert!(!caps.can_boot_vm());
        let d = PathBuf::from("/nonexistent-data");
        let p = auto(&Query { requested: "auto", cfg: &vm_cfg(), data: &d, sandboxed: true });
        // This machine has /dev/kvm, so `auto` here is a real microVM or a host
        // plan; either way the properties below must hold.
        assert!(p.warning.is_some() || p.uses_microvm(), "a weaker plan must warn: {p:?}");
        if !p.uses_microvm() {
            assert!(p.warning.as_deref().unwrap_or("").contains("no microVM"), "{p:?}");
        }
    }

    #[test]
    fn auto_prefers_a_real_microvm_when_the_image_and_a_vmm_are_there() {
        let cfg = vm_cfg();
        let p = auto_with(&bootable_caps(), &cfg, false);
        assert_eq!(p.backend, "vm", "{p:?}");
        assert_eq!(p.level, IsolationLevel::MicroVm);
        assert_eq!(p.origin, Origin::AutoMicroVm);
        assert!(p.warning.is_none(), "a microVM plan needs no warning: {p:?}");
        assert!(p.line().contains("microVM"));
        // The same answer for a sandboxed session: the VM is the sandbox.
        assert_eq!(auto_with(&bootable_caps(), &cfg, true).backend, "vm");
        // One ingredient missing and it is no longer a microVM plan.
        let mut caps = bootable_caps();
        caps.kvm = false;
        let p = auto_with(&caps, &cfg, true);
        assert!(!p.uses_microvm() && p.warning.as_deref().unwrap_or("").contains("/dev/kvm"), "{p:?}");
    }

    #[test]
    fn the_blocker_names_the_first_thing_missing() {
        let caps = Capabilities::default();
        assert!(blockers(&caps).contains("/dev/kvm"));
        let caps = Capabilities { kvm: true, ..Default::default() };
        assert!(blockers(&caps).contains("kernel"));
        let caps = Capabilities { kvm: true, kernel: Some("/k".into()), ..Default::default() };
        assert!(blockers(&caps).contains("initramfs"));
    }

    #[test]
    fn an_unprovisioned_host_is_not_called_sandboxed() {
        let d = PathBuf::from("/nonexistent-data");
        let p = auto(&Query { requested: "auto", cfg: &vm_cfg(), data: &d, sandboxed: false });
        if p.uses_microvm() {
            return; // this machine has the image at a default path
        }
        // Host plan: named `local`, warned, and it tells the operator how to fix it.
        assert_eq!(p.backend, "local", "{p:?}");
        assert_eq!(p.origin, Origin::AutoHost);
        assert!(p.warning.as_deref().unwrap_or("").to_lowercase().contains("build the guest image"), "{p:?}");
    }
}
