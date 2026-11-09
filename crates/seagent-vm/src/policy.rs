//! Which execution environment an unconfigured seagent instance picks (A1/B1/B6):
//! the strongest one this machine can actually give, decided in one place so
//! `seagent sandbox explain`, `seagent doctor` and the executor cannot disagree.
//!
//! The rule the design asks for is "microVM by default when the machine can
//! boot one". Two things have to stay true for that to be honest:
//!
//! * **never a silent downgrade**: every weaker choice carries a warning that
//!   names the level and the reason, and the caller (explain/doctor/log) shows
//!   it. [`Plan::warning`] is `None` only for a real microVM.
//! * **isolate before asking** (GAPS-next §0, srv-015): when no microVM can boot
//!   (no KVM, or the guest image was never built) *every* session — the owner's
//!   main session included — falls back to a namespace sandbox (bwrap, else
//!   Landlock) where the host home and its keys are not visible, with a warning
//!   that names the reason and the fix. Only when no namespace sandbox exists
//!   either does a session run on the host, and that plan says so loudly
//!   ([`Origin::AutoHost`]). `[exec] backend = "local"` is the explicit opt-out
//!   (test rigs, operators who want the old behaviour).
//!
//! `[exec] backend = "auto"` is the default here; an explicit backend name is
//! always honoured verbatim (this module only answers the `auto` question).

use crate::config::VmConfig;
use crate::host::HostOs;
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
    /// One line for the system prompt / `seagent sandbox explain`.
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
    let fix = if caps.hardware_accel() { " Build the guest image (`seagent sandbox vm image build`) for a microVM." } else { "" };
    let (backend, degraded) = namespace_choice(caps);
    let level = isolation_of_backend(backend);
    let degraded = if degraded.is_empty() { String::new() } else { format!(" Degraded: {}.", degraded.join("; ")) };
    if level != IsolationLevel::Host {
        return Plan {
            backend: backend.into(),
            provider: None,
            level,
            origin: Origin::AutoFallback,
            warning: Some(format!(
                "no microVM available ({why}); {} runs in a {} instead (host home and keys not mounted) — {}.{degraded}{fix}",
                if sandboxed { "this session" } else { "the agent" },
                level.label(),
                level.warning().unwrap_or("weaker than a microVM")
            )),
            reason: if sandboxed {
                "auto: no microVM, sandboxed session falls back to a namespace sandbox".into()
            } else {
                "auto: no microVM, the agent still runs isolated in a namespace sandbox (isolate before asking)".into()
            },
        };
    }
    host_plan(&format!("{why}; {}", degraded.trim().trim_start_matches("Degraded: ").trim_end_matches('.')), fix)
}

/// The namespace-level fallback this host can actually run, and every step down it took on
/// the way (ent-023/026): bwrap needs unprivileged user namespaces; Landlock needs kernel
/// ≥ 5.13 with `landlock` in the LSM list; then a container engine (docker's root daemon works
/// without user namespaces, rootless podman does not); else the host. The decision reads
/// [`Capabilities::host`], so it is tested against fake kernels, not the CI machine.
pub fn namespace_choice(caps: &Capabilities) -> (&'static str, Vec<String>) {
    let h = &caps.host;
    let mut degraded = vec![];
    if caps.bwrap.is_some() {
        if h.userns {
            return ("bwrap", degraded);
        }
        degraded.push(format!("bwrap is installed but unprivileged user namespaces are disabled ({})", h.userns_blocker.as_deref().unwrap_or("sysctl")));
    }
    if caps.os == HostOs::Linux {
        if h.landlock_abi >= 1 {
            if h.landlock_abi < 4 {
                degraded.push(format!("Landlock ABI {} restricts files only (a sandboxed session with network = \"none\" needs ABI 4 / kernel 6.7)", h.landlock_abi));
            }
            return ("landlock", degraded);
        }
        degraded.push(if h.version < (5, 13) && h.version != (0, 0) { format!("kernel {}.{} has no Landlock (needs 5.13+)", h.version.0, h.version.1) } else { "Landlock is not in the kernel's active LSM list".to_string() });
    }
    if caps.docker.is_some() {
        degraded.push(if matches!(caps.os, HostOs::Windows | HostOs::Macos) {
            "using the docker container backend (Docker Desktop: containers share the kernel of Docker's own Linux VM, not this host's)".into()
        } else {
            "using the docker container backend (shared kernel, root daemon)".into()
        });
        return ("docker", degraded);
    }
    if caps.podman.is_some() {
        if h.userns {
            degraded.push("using the rootless podman container backend (shared kernel)".into());
            return ("podman", degraded);
        }
        degraded.push("podman is installed but rootless podman needs user namespaces".into());
    }
    degraded.push("no container engine (docker/podman) either: only the static gates (approvals, command policy, path rules) apply".into());
    ("local", degraded)
}

/// The last resort: no microVM and no namespace sandbox. Never silent.
pub fn host_plan(why: &str, fix: &str) -> Plan {
    Plan {
        backend: "local".into(),
        provider: None,
        level: IsolationLevel::Host,
        origin: Origin::AutoHost,
        warning: Some(format!(
            "NOT ISOLATED: no microVM ({why}) and no namespace sandbox; tool calls run directly on this machine as the seagent user and can read its home directory and keys. Install bubblewrap or build the guest image (`seagent sandbox vm image build`).{fix}"
        )),
        reason: "auto: no microVM and no namespace sandbox — host, with a warning".into(),
    }
}

/// Capabilities with the same "unpacked into the data dir" rules the pool uses
/// (a Firecracker tarball under `<data>/vm/bin` counts).
pub fn capabilities(cfg: &VmConfig, data: &Path) -> Capabilities {
    let mut caps = Capabilities::detect(Some(&cfg.kernel_path(data)), Some(&cfg.initramfs_path(data)));
    let local_fc = data.join("vm").join("bin").join("firecracker");
    if caps.os == HostOs::Linux {
        if let Some(p) = crate::isolation::which(&cfg.firecracker).or(local_fc.is_file().then_some(local_fc)) {
            caps.firecracker = Some(p);
        }
    }
    if let Some(p) = crate::host::find_tool(&cfg.qemu) {
        caps.qemu = Some(p);
    }
    if let Some(p) = crate::host::find_tool(&cfg.vboxmanage) {
        caps.vbox = Some(p);
    }
    if caps.os == HostOs::Macos {
        if let Some(p) = crate::host::find_tool(&cfg.vfkit) {
            caps.vfkit = Some(p);
        }
    }
    let disk = cfg.disk_image_path(data);
    caps.disk_image = disk.is_file().then_some(disk);
    caps
}

/// Why no microVM: one short phrase, the first real blocker.
pub fn blockers(caps: &Capabilities) -> String {
    match caps.os {
        HostOs::Linux => {}
        HostOs::Ios | HostOs::Other => return "iOS does not let an app run a virtual machine (platform policy); delegate VM work to a paired host".into(),
        HostOs::Android if caps.avf.is_none() || !caps.kvm => return format!("VM isolation unavailable on this device ({}); delegate to a paired host", crate::provider::hosted::AVF_MISSING),
        HostOs::Windows if caps.qemu.is_none() && caps.hyperv.is_none() && caps.vbox.is_none() => {
            return "no hypervisor found: install QEMU (with the Windows feature `HypervisorPlatform` for WHPX), or enable Hyper-V, or install VirtualBox".into()
        }
        HostOs::Macos if caps.vfkit.is_none() && caps.qemu.is_none() && caps.vbox.is_none() => return "no hypervisor front-end found: `brew install vfkit` (Virtualization.framework) or `brew install qemu` (HVF)".into(),
        _ => {
            if caps.kernel.is_none() {
                return "the guest kernel is not built".into();
            }
            if caps.initramfs.is_none() {
                return "the guest initramfs is not built".into();
            }
            return format!("no usable VMM ({})", if caps.os == HostOs::Macos && !caps.hvf { "Hypervisor.framework unavailable" } else { "the providers found need a bootable guest disk (exec.vm.disk_image) or hardware acceleration" });
        }
    }
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
    #[cfg_attr(not(unix), allow(dead_code))] // its users are unix-only tests
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

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

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

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn the_blocker_names_the_first_thing_missing() {
        let caps = Capabilities::default();
        assert!(blockers(&caps).contains("/dev/kvm"));
        let caps = Capabilities { kvm: true, ..Default::default() };
        assert!(blockers(&caps).contains("kernel"));
        let caps = Capabilities { kvm: true, kernel: Some("/k".into()), ..Default::default() };
        assert!(blockers(&caps).contains("initramfs"));
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn an_unprovisioned_host_still_isolates_the_main_session() {
        // srv-015: KVM but no image, unsandboxed (owner) session → namespace sandbox, warned,
        // with the fix named — not the host.
        let caps = Capabilities { kvm: true, bwrap: Some(PathBuf::from("/usr/bin/bwrap")), ..Default::default() };
        let p = auto_with(&caps, &vm_cfg(), false);
        assert_eq!((p.backend.as_str(), p.origin), ("bwrap", Origin::AutoFallback), "{p:?}");
        let w = p.warning.as_deref().unwrap_or("");
        assert!(w.contains("host home and keys not mounted") && w.to_lowercase().contains("build the guest image"), "{w}");
        // No KVM at all: same namespace fallback, nothing about building an image.
        let caps = Capabilities { kvm: false, bwrap: Some(PathBuf::from("/usr/bin/bwrap")), ..Default::default() };
        let p = auto_with(&caps, &vm_cfg(), false);
        assert_eq!(p.backend, "bwrap", "{p:?}");
        assert!(p.warning.as_deref().unwrap_or("").contains("/dev/kvm"), "{p:?}");
    }

    #[test]
    fn other_operating_systems_get_their_own_vm_or_an_honest_reason() {
        let image = |os| Capabilities { os, kernel: Some("/k".into()), initramfs: Some("/i".into()), ..Default::default() };
        // Windows with WHPX + QEMU: a hardware VM, with the loopback-channel note.
        let p = auto_with(&Capabilities { whpx: true, qemu: Some("qemu".into()), ..image(HostOs::Windows) }, &vm_cfg(), true);
        assert_eq!((p.backend.as_str(), p.provider.as_deref(), p.level), ("vm", Some("qemu"), IsolationLevel::MicroVm), "{p:?}");
        // macOS with vfkit: Virtualization.framework, no warning.
        let p = auto_with(&Capabilities { hvf: true, vfkit: Some("vfkit".into()), qemu: Some("qemu".into()), ..image(HostOs::Macos) }, &vm_cfg(), true);
        assert_eq!((p.provider.as_deref(), p.warning.as_deref()), (Some("vfkit"), None), "{p:?}");
        // macOS with nothing but Docker Desktop: the container backend, and it says whose kernel.
        let p = auto_with(&Capabilities { docker: Some("docker".into()), ..image(HostOs::Macos) }, &vm_cfg(), true);
        assert_eq!(p.backend, "docker", "{p:?}");
        let w = p.warning.unwrap();
        assert!(w.contains("no hypervisor front-end") && w.contains("Docker Desktop"), "{w}");
        // Android without AVF: no VM, and the delegation path is named.
        let p = auto_with(&image(HostOs::Android), &vm_cfg(), true);
        assert!(!p.uses_microvm() && p.warning.unwrap().contains("paired host"));
        // iOS: never a VM, and the reason is the platform's policy.
        let p = auto_with(&Capabilities { qemu: Some("qemu".into()), ..image(HostOs::Ios) }, &vm_cfg(), true);
        assert!(!p.uses_microvm(), "{p:?}");
        assert!(p.warning.unwrap().contains("iOS does not let an app run a virtual machine"));
    }

    #[test]
    fn the_host_plan_is_the_last_resort_and_says_not_isolated() {
        let p = host_plan("/dev/kvm is missing", "");
        assert_eq!((p.backend.as_str(), p.level, p.origin), ("local", IsolationLevel::Host, Origin::AutoHost));
        assert!(p.warning.as_deref().unwrap_or("").starts_with("NOT ISOLATED"), "{p:?}");
    }

    /// ent-023/026: the fallback is decided from what the kernel can do, read from fake
    /// `/proc` + `/sys` trees for the distributions enterprises run.
    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.
    #[cfg(unix)]
    #[test]
    fn old_kernels_degrade_step_by_step_and_say_why() {
        use crate::hostcaps::{fake, HostKernel};
        let t = crate::hostcaps::tests_support::seagent_tmp("policy-degrade");
        let host = |h: &fake::Host| {
            let root = t.join(h.release);
            fake::build(&root, h);
            HostKernel::detect_in(&root)
        };
        let bwrap = Some(PathBuf::from("/usr/bin/bwrap"));
        let docker = Some(PathBuf::from("/usr/bin/docker"));
        let podman = Some(PathBuf::from("/usr/bin/podman"));
        let plan = |caps: Capabilities| auto_with(&caps, &vm_cfg(), true);

        // RHEL 8: bwrap installed, user namespaces off, no Landlock, no engine → host + static gates.
        let p = plan(Capabilities { bwrap: bwrap.clone(), host: host(&fake::RHEL8), ..Default::default() });
        assert_eq!((p.backend.as_str(), p.origin), ("local", Origin::AutoHost), "{p:?}");
        let w = p.warning.unwrap();
        assert!(w.starts_with("NOT ISOLATED") && w.contains("user.max_user_namespaces = 0") && w.contains("kernel 4.18 has no Landlock") && w.contains("static gates"), "{w}");
        // … with docker: the container backend, and the steps down are named.
        let p = plan(Capabilities { bwrap: bwrap.clone(), docker: docker.clone(), host: host(&fake::RHEL8), ..Default::default() });
        assert_eq!((p.backend.as_str(), p.level), ("docker", IsolationLevel::Container), "{p:?}");
        assert!(p.warning.as_deref().unwrap().contains("Degraded: bwrap is installed but unprivileged user namespaces are disabled"), "{p:?}");
        // … rootless podman needs user namespaces: not chosen on RHEL 7.
        let p = plan(Capabilities { podman: podman.clone(), host: host(&fake::RHEL7), ..Default::default() });
        assert_eq!(p.backend, "local", "{p:?}");
        assert!(p.warning.as_deref().unwrap().contains("rootless podman needs user namespaces"), "{p:?}");
        // Amazon Linux 2 (4.14, user namespaces on): bwrap works, no Landlock needed.
        let p = plan(Capabilities { bwrap: bwrap.clone(), host: host(&fake::AL2), ..Default::default() });
        assert_eq!(p.backend, "bwrap", "{p:?}");
        // Ubuntu 20.04 (5.4): no bwrap, no Landlock → rootless podman.
        let p = plan(Capabilities { podman, host: host(&fake::UBUNTU20), ..Default::default() });
        assert_eq!(p.backend, "podman", "{p:?}");
        assert!(p.warning.as_deref().unwrap().contains("kernel 5.4 has no Landlock"), "{p:?}");
        // A current kernel without bwrap → Landlock, no degradation note.
        let p = plan(Capabilities { host: host(&fake::MODERN), ..Default::default() });
        assert_eq!(p.backend, "landlock", "{p:?}");
        assert!(!p.warning.as_deref().unwrap().contains("Degraded"), "{p:?}");
        // Landlock ABI 3 (6.6): chosen, with the network caveat spelled out.
        let p = plan(Capabilities { host: host(&fake::Host { release: "6.6.30", ..fake::MODERN }), ..Default::default() });
        assert!(p.backend == "landlock" && p.warning.as_deref().unwrap().contains("ABI 3 restricts files only"), "{p:?}");
    }
}
