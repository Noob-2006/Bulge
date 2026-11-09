//! What kind of wall separates a tool call from the host, and how loudly seagent has
//! to say so (B1: microVM first, gVisor/bwrap as an explicitly *weaker*
//! fallback — never a silent downgrade).
//!
//! Every execution backend in seagent is classified here, so `seagent sandbox explain`,
//! `seagent doctor` and the system prompt can all answer "where does this command
//! actually run, and what does that protect me from?" from one table.

use crate::host::{Accel, HostOs};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Ordering matters: higher is stronger isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// No wall at all: the process runs as the seagent user (`local`).
    Host,
    /// The OS's own policy sandbox on the shared kernel, without a separate filesystem view:
    /// macOS Seatbelt (`sandbox-exec`), Windows AppContainer. Same tier as namespaces
    /// ([`IsolationLevel::rank`] 1), reported under its own name so nobody calls it bwrap.
    OsSandbox,
    /// Namespaces/seccomp only, shared kernel: bwrap, Landlock.
    UserNamespace,
    /// Container with its own rootfs, shared kernel: docker, podman.
    Container,
    /// Kernel-level sandbox in user space (gVisor `runsc`) or a remote host.
    AppKernel,
    /// Hardware virtualisation: the guest has its own kernel (Firecracker/QEMU-KVM, and the
    /// per-OS substitutes: QEMU+WHPX/HVF, Virtualization.framework, Hyper-V, VirtualBox, AVF).
    MicroVm,
}

impl IsolationLevel {
    pub fn label(self) -> &'static str {
        match self {
            IsolationLevel::Host => "host",
            IsolationLevel::OsSandbox => "os-sandbox",
            IsolationLevel::UserNamespace => "user-namespace",
            IsolationLevel::Container => "container",
            IsolationLevel::AppKernel => "app-kernel (gVisor)",
            IsolationLevel::MicroVm => "microVM",
        }
    }
    /// 0..=4, for sorting and for "is this at least as strong as X?" checks. The numbers are
    /// part of `seagent exec` JSON output, so they never change; an OS sandbox shares tier 1.
    pub fn rank(self) -> u8 {
        match self {
            IsolationLevel::Host => 0,
            IsolationLevel::OsSandbox | IsolationLevel::UserNamespace => 1,
            IsolationLevel::Container => 2,
            IsolationLevel::AppKernel => 3,
            IsolationLevel::MicroVm => 4,
        }
    }
    /// The sentence seagent shows whenever a weaker level is used than the design
    /// target. `None` for a microVM: nothing to warn about.
    pub fn warning(self) -> Option<&'static str> {
        match self {
            IsolationLevel::MicroVm => None,
            IsolationLevel::AppKernel => Some("gVisor: the guest shares the host kernel through a user-space kernel; kernel bugs are contained but not eliminated. Keys and the daemon socket stay outside either way."),
            IsolationLevel::Container => Some("container: shares the host kernel and (for docker/podman) the host's namespaces; a kernel bug or a misconfigured mount reaches the host. Not equivalent to a microVM."),
            IsolationLevel::UserNamespace => Some("namespace sandbox (bwrap/Landlock): shares the host kernel, one kernel bug from the host. Treat untrusted code as able to read anything the seagent user can read."),
            IsolationLevel::OsSandbox => Some("OS policy sandbox (macOS Seatbelt / Windows AppContainer): the OS refuses access outside the allowed paths, but the command sees the real filesystem and shares the host kernel. Not equivalent to a microVM."),
            IsolationLevel::Host => Some("NO isolation: commands run directly on this machine as the seagent user. Only acceptable for the operator's own trusted work."),
        }
    }
    /// Does the workspace of this level need to be synced in/out?
    pub fn needs_sync(self) -> bool {
        self >= IsolationLevel::AppKernel
    }
}

/// Classify an `exec.backend` / `exec.sandbox.backend` name.
pub fn isolation_of_backend(name: &str) -> IsolationLevel {
    match name {
        "local" => IsolationLevel::Host,
        "bwrap" | "landlock" => IsolationLevel::UserNamespace,
        "seatbelt" | "appcontainer" => IsolationLevel::OsSandbox,
        "docker" | "podman" | "singularity" | "apptainer" | "openshell" => IsolationLevel::Container,
        "gvisor" | "runsc" => IsolationLevel::AppKernel,
        "vm" | "firecracker" | "qemu" => IsolationLevel::MicroVm,
        // Remote hosts and cloud sandboxes: a different machine, but not a VM we
        // control; the *isolation* is at least as good as a container (we cannot
        // see the host at all), while the trust direction differs. Reported as
        // app-kernel so nobody claims a local microVM.
        "ssh" | "modal" | "daytona" | "vercel" => IsolationLevel::AppKernel,
        _ => IsolationLevel::Host,
    }
}

/// Which microVM provider implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// Linux/KVM.
    Firecracker,
    /// Linux KVM; Windows WHPX (TCG fallback); macOS HVF (TCG fallback).
    Qemu,
    /// Apple Virtualization.framework, driven through the `vfkit` CLI (macOS).
    Vfkit,
    /// Oracle VirtualBox through `VBoxManage` (Windows, macOS, Linux).
    VirtualBox,
    /// Hyper-V through PowerShell (Windows; needs an elevated session or Hyper-V Administrators).
    HyperV,
    /// Android Virtualization Framework (crosvm under pKVM) through the AVF `vm` tool.
    Avf,
    /// Fallback: gVisor `runsc` (needs root-ish setup; detected, never assumed).
    Gvisor,
    /// Fallback: bubblewrap namespaces, the level seagent already had.
    Bwrap,
}

impl ProviderKind {
    pub fn name(self) -> &'static str {
        match self {
            ProviderKind::Firecracker => "firecracker",
            ProviderKind::Qemu => "qemu",
            ProviderKind::Vfkit => "vfkit",
            ProviderKind::VirtualBox => "virtualbox",
            ProviderKind::HyperV => "hyperv",
            ProviderKind::Avf => "avf",
            ProviderKind::Gvisor => "gvisor",
            ProviderKind::Bwrap => "bwrap",
        }
    }
    pub fn parse(s: &str) -> Option<ProviderKind> {
        Some(match s {
            "firecracker" | "fc" => ProviderKind::Firecracker,
            "qemu" => ProviderKind::Qemu,
            "vfkit" | "vz" | "virtualization-framework" => ProviderKind::Vfkit,
            "virtualbox" | "vbox" => ProviderKind::VirtualBox,
            "hyperv" | "hyper-v" => ProviderKind::HyperV,
            "avf" | "crosvm" => ProviderKind::Avf,
            "gvisor" | "runsc" => ProviderKind::Gvisor,
            "bwrap" => ProviderKind::Bwrap,
            _ => return None,
        })
    }
    pub fn is_vm(self) -> bool {
        !matches!(self, ProviderKind::Gvisor | ProviderKind::Bwrap)
    }
    pub fn isolation(self) -> IsolationLevel {
        match self {
            ProviderKind::Gvisor => IsolationLevel::AppKernel,
            ProviderKind::Bwrap => IsolationLevel::UserNamespace,
            _ => IsolationLevel::MicroVm,
        }
    }
    /// The VM providers `auto` tries on `os`, strongest first (an explicit
    /// `exec.vm.provider` may name any provider the OS supports). Linux is unchanged:
    /// Firecracker, then QEMU-KVM. A provider that would only run under TCG is moved behind
    /// every hardware-accelerated one by [`Capabilities::vm_candidates`].
    pub fn auto_order(os: HostOs) -> &'static [ProviderKind] {
        match os {
            HostOs::Linux => &[ProviderKind::Firecracker, ProviderKind::Qemu],
            HostOs::Macos => &[ProviderKind::Vfkit, ProviderKind::Qemu, ProviderKind::VirtualBox],
            HostOs::Windows => &[ProviderKind::Qemu, ProviderKind::HyperV, ProviderKind::VirtualBox],
            HostOs::Android => &[ProviderKind::Avf],
            HostOs::Ios | HostOs::Other => &[],
        }
    }
}

/// What this machine can actually do. Detected once, cached, and always
/// re-checked from disk when a VM is about to start (a `bwrap` binary that
/// disappeared must not be reported as available).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Capabilities {
    /// `/dev/kvm` exists and is readable+writable.
    pub kvm: bool,
    pub firecracker: Option<PathBuf>,
    pub qemu: Option<PathBuf>,
    pub bwrap: Option<PathBuf>,
    pub runsc: Option<PathBuf>,
    /// Guest kernel + initramfs are on disk (else the image must be built).
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    /// Host arch, for image selection.
    pub arch: String,
    /// Container engines (the fallback when neither bwrap nor Landlock can run, ent-023/026).
    pub docker: Option<PathBuf>,
    pub podman: Option<PathBuf>,
    /// Kernel features: Landlock ABI, user namespaces, seccomp, cgroups (ent-023/024/026).
    pub host: crate::hostcaps::HostKernel,
    /// The OS these capabilities describe (defaults to the running one), so the decision
    /// table is a pure function of this struct for every platform.
    pub os: HostOs,
    /// Windows Hypervisor Platform is enabled and the hypervisor runs (QEMU `-accel whpx`).
    pub whpx: bool,
    /// macOS Hypervisor.framework is available (QEMU `-accel hvf`, vfkit).
    pub hvf: bool,
    /// Hyper-V is installed: the PowerShell that drives it.
    pub hyperv: Option<PathBuf>,
    /// Why Hyper-V is unusable on this Windows machine (Home edition, feature off), so the
    /// report and the fallback message name the real reason. `None` elsewhere / when installed.
    pub hyperv_blocker: Option<String>,
    /// `VBoxManage`.
    pub vbox: Option<PathBuf>,
    /// `vfkit` (Apple Virtualization.framework CLI).
    pub vfkit: Option<PathBuf>,
    /// The AVF `vm` tool (Android, pKVM).
    pub avf: Option<PathBuf>,
    /// Bootable guest disk (UEFI, raw) for the providers that cannot boot a kernel directly
    /// (VirtualBox, Hyper-V).
    pub disk_image: Option<PathBuf>,
}

impl Capabilities {
    pub fn detect(kernel: Option<&Path>, initramfs: Option<&Path>) -> Capabilities {
        let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
        let kernel = kernel.filter(|p| p.exists()).map(PathBuf::from);
        let initramfs = initramfs.filter(|p| p.exists()).map(PathBuf::from);
        let os = HostOs::current();
        if os == HostOs::Linux {
            // The Linux probes seagent always made, plus VBoxManage, which only an explicit
            // `exec.vm.provider = "virtualbox"` uses (it is not in Linux's `auto` order).
            return Capabilities {
                kvm,
                firecracker: which("firecracker"),
                qemu: which("qemu-system-x86_64"),
                bwrap: which("bwrap"),
                runsc: which("runsc"),
                kernel,
                initramfs,
                arch: std::env::consts::ARCH.to_string(),
                docker: which("docker"),
                podman: which("podman"),
                host: crate::hostcaps::HostKernel::detect(),
                os,
                vbox: crate::host::find_tool("VBoxManage"),
                ..Default::default()
            };
        }
        let tool = crate::host::find_tool;
        Capabilities {
            kvm: crate::host::kvm_usable(),
            firecracker: None,
            qemu: tool(crate::host::native_qemu()),
            bwrap: None,
            runsc: None,
            kernel,
            initramfs,
            arch: std::env::consts::ARCH.to_string(),
            docker: tool("docker"),
            podman: tool("podman"),
            host: crate::hostcaps::HostKernel::detect(),
            os,
            whpx: crate::host::whpx_available(),
            hvf: crate::host::hvf_available(),
            hyperv: if crate::host::hyperv_available() { tool("powershell") } else { None },
            hyperv_blocker: if os == HostOs::Windows { crate::host::hyperv_unavailable() } else { None },
            vbox: if matches!(os, HostOs::Windows | HostOs::Macos) { tool("VBoxManage") } else { None },
            vfkit: if os == HostOs::Macos { tool("vfkit") } else { None },
            avf: crate::host::avf_tool(),
            disk_image: None,
        }
    }

    /// Guest kernel + initramfs are both on disk.
    pub fn has_image(&self) -> bool {
        self.kernel.is_some() && self.initramfs.is_some()
    }

    /// This OS offers hardware virtualisation to seagent (Linux/Android: `/dev/kvm`).
    pub fn hardware_accel(&self) -> bool {
        match self.os {
            HostOs::Linux | HostOs::Android => self.kvm,
            HostOs::Windows => self.whpx || self.hyperv.is_some(),
            HostOs::Macos => self.hvf,
            HostOs::Ios | HostOs::Other => false,
        }
    }

    /// The accelerator `kind` would run with on this machine, or `None` when it cannot run
    /// here at all. On Linux this is exactly the old rule (KVM + VMM + image; no TCG).
    pub fn usable(&self, kind: ProviderKind) -> Option<Accel> {
        let image = self.has_image();
        let os = self.os;
        match kind {
            ProviderKind::Firecracker => (os == HostOs::Linux && self.kvm && self.firecracker.is_some() && image).then_some(Accel::Kvm),
            ProviderKind::Qemu => {
                if self.qemu.is_none() || !image {
                    return None;
                }
                match os {
                    HostOs::Linux | HostOs::Android => self.kvm.then_some(Accel::Kvm),
                    HostOs::Windows => Some(if self.whpx { Accel::Whpx } else { Accel::Tcg }),
                    HostOs::Macos => Some(if self.hvf { Accel::Hvf } else { Accel::Tcg }),
                    HostOs::Ios | HostOs::Other => None,
                }
            }
            ProviderKind::Vfkit => (os == HostOs::Macos && self.hvf && self.vfkit.is_some() && image).then_some(Accel::Hvf),
            ProviderKind::VirtualBox => (matches!(os, HostOs::Linux | HostOs::Macos | HostOs::Windows) && self.vbox.is_some() && self.disk_image.is_some() && image).then_some(Accel::Vbox),
            ProviderKind::HyperV => (os == HostOs::Windows && self.hyperv.is_some() && self.disk_image.is_some() && image).then_some(Accel::Hyperv),
            ProviderKind::Avf => (os == HostOs::Android && self.avf.is_some() && self.kvm && image).then_some(Accel::Kvm),
            ProviderKind::Gvisor | ProviderKind::Bwrap => None,
        }
    }

    /// Every VM provider `auto` could use here, strongest first: the OS's order
    /// ([`ProviderKind::auto_order`]) with software-only (TCG) choices moved last.
    pub fn vm_candidates(&self) -> Vec<(ProviderKind, Accel)> {
        let mut v: Vec<(ProviderKind, Accel)> = ProviderKind::auto_order(self.os).iter().filter_map(|k| self.usable(*k).map(|a| (*k, a))).collect();
        v.sort_by_key(|(_, a)| !a.is_hardware());
        v
    }

    /// The VM `auto` picks, with its accelerator.
    pub fn best_vm(&self) -> Option<(ProviderKind, Accel)> {
        self.vm_candidates().into_iter().next()
    }

    /// Can a real microVM boot right now?
    pub fn can_boot_vm(&self) -> bool {
        self.best_vm().is_some()
    }
    /// Best available provider, strongest first. `None` when this machine cannot
    /// isolate at all.
    pub fn best(&self) -> Option<ProviderKind> {
        if let Some((kind, _)) = self.best_vm() {
            return Some(kind);
        }
        if self.runsc.is_some() {
            return Some(ProviderKind::Gvisor);
        }
        if self.bwrap.is_some() && self.host.userns {
            return Some(ProviderKind::Bwrap);
        }
        None
    }
    /// Human-readable lines for `seagent sandbox explain` / `seagent doctor`.
    pub fn report(&self) -> Vec<String> {
        let p = |x: &Option<PathBuf>| x.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "missing".into());
        if self.os != HostOs::Linux {
            return self.report_other_os();
        }
        vec![
            format!("/dev/kvm: {}", if self.kvm { "available" } else { "missing or not writable (no hardware virtualisation)" }),
            format!("firecracker: {}", p(&self.firecracker)),
            format!("qemu-system-x86_64: {}", p(&self.qemu)),
            format!("guest kernel: {}", p(&self.kernel)),
            format!("guest initramfs: {}", p(&self.initramfs)),
            format!("bwrap: {}", p(&self.bwrap)),
            format!("gvisor (runsc): {}", p(&self.runsc)),
            format!("best provider: {}", self.best().map(|k| k.name()).unwrap_or("none")),
            format!("docker: {}", p(&self.docker)),
            format!("podman: {}", p(&self.podman)),
        ]
        .into_iter()
        .chain(self.host.report())
        .collect()
    }
    /// `report()` for Windows / macOS / Android / iOS: the substitutes, by name.
    fn report_other_os(&self) -> Vec<String> {
        let p = |x: &Option<PathBuf>| x.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "missing".into());
        let yes = |b: bool, what: &str| if b { "available".to_string() } else { format!("unavailable ({what})") };
        let mut v = vec![format!("host os: {}", self.os.name())];
        match self.os {
            HostOs::Windows => {
                v.push(format!("windows hypervisor platform (whpx): {}", yes(self.whpx, "enable the optional feature `HypervisorPlatform` and VT-x/AMD-V in firmware")));
                v.push(format!("hyper-v: {}", self.hyperv.as_ref().map(|_| "installed (VM creation needs an elevated session or Hyper-V Administrators)".to_string()).unwrap_or_else(|| self.hyperv_blocker.clone().unwrap_or_else(|| "not installed".into()))));
                v.push(format!("virtualbox (VBoxManage): {}", p(&self.vbox)));
            }
            HostOs::Macos => {
                v.push(format!("hypervisor.framework (hvf): {}", yes(self.hvf, "kern.hv_support = 0")));
                v.push(format!("vfkit (Virtualization.framework): {}", self.vfkit.as_ref().map(|x| x.display().to_string()).unwrap_or_else(|| "missing (brew install vfkit)".into())));
                v.push(format!("virtualbox (VBoxManage): {}", p(&self.vbox)));
            }
            HostOs::Android => {
                v.push(format!("/dev/kvm (pKVM): {}", yes(self.kvm, "not a pKVM device, or not accessible to this app")));
                v.push(format!("avf `vm` tool: {}", p(&self.avf)));
            }
            HostOs::Ios | HostOs::Other => v.push("VM isolation: not available (iOS does not let an app run a hypervisor; delegate VM work to a paired host)".into()),
            HostOs::Linux => {}
        }
        v.push(format!("{}: {}", crate::host::native_qemu(), p(&self.qemu)));
        v.push(format!("guest kernel: {}", p(&self.kernel)));
        v.push(format!("guest initramfs: {}", p(&self.initramfs)));
        v.push(format!("guest disk (VirtualBox / Hyper-V): {}", p(&self.disk_image)));
        v.push(match self.best_vm() {
            Some((k, a)) => format!("best provider: {} (accelerator: {})", k.name(), a.label()),
            None => format!("best provider: {}", self.best().map(|k| k.name()).unwrap_or("none")),
        });
        v.push(format!("docker: {}", p(&self.docker)));
        v
    }

    /// The warning tied to what `best()` would actually pick.
    pub fn warning(&self) -> Option<String> {
        if let Some((kind, Accel::Tcg)) = self.best_vm() {
            return Some(format!("execution isolation is a VM without hardware acceleration ({}): the guest has its own kernel, but runs under TCG software emulation — slow, and the whole emulator is attack surface", kind.name()));
        }
        let kind = self.best()?;
        if let Some(w) = kind.isolation().warning() {
            return Some(format!("execution isolation is {} ({}): {w}", kind.isolation().label(), kind.name()));
        }
        None
    }
}

/// Minimal `which` (no shell, no PATH surprises beyond PATH itself). On Windows a bare name
/// also matches `<name>.exe`, and `\\` counts as a path separator.
pub fn which(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') || (cfg!(windows) && bin.contains('\\')) {
        let p = PathBuf::from(bin);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if cfg!(windows) {
            if let Some(p) = crate::host::exe_in(&dir, bin) {
                return Some(p);
            }
            continue;
        }
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_name_has_an_honest_level() {
        // B6: one table for the whole tree.
        assert_eq!(isolation_of_backend("local"), IsolationLevel::Host);
        assert_eq!(isolation_of_backend("bwrap"), IsolationLevel::UserNamespace);
        assert_eq!(isolation_of_backend("docker"), IsolationLevel::Container);
        assert_eq!(isolation_of_backend("vm"), IsolationLevel::MicroVm);
        assert!(isolation_of_backend("gvisor") > isolation_of_backend("docker"));
        assert!(isolation_of_backend("docker") > isolation_of_backend("bwrap"));
        assert!(isolation_of_backend("bwrap") > isolation_of_backend("local"));
        // The OS policy sandboxes: above no isolation, same tier as namespaces, own name.
        for os in ["seatbelt", "appcontainer"] {
            let l = isolation_of_backend(os);
            assert_eq!(l, IsolationLevel::OsSandbox);
            assert!(l > IsolationLevel::Host && l < IsolationLevel::UserNamespace);
            assert_eq!(l.rank(), IsolationLevel::UserNamespace.rank());
            assert_ne!(l.label(), IsolationLevel::UserNamespace.label());
        }
        // Only a real VM is warning-free.
        assert!(IsolationLevel::MicroVm.warning().is_none());
        for l in [IsolationLevel::Host, IsolationLevel::OsSandbox, IsolationLevel::UserNamespace, IsolationLevel::Container, IsolationLevel::AppKernel] {
            assert!(l.warning().is_some(), "{l:?} must warn");
        }
        assert!(isolation_of_backend("local").warning().unwrap().contains("NO isolation"));
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn a_machine_without_a_kernel_image_is_not_called_a_microvm() {
        // No provider claims MicroVm unless KVM *and* the guest image exist.
        let caps = Capabilities { kvm: true, firecracker: Some("/bin/true".into()), qemu: Some("/bin/true".into()), bwrap: Some("/bin/true".into()), ..Default::default() };
        assert!(!caps.can_boot_vm());
        assert_eq!(caps.best(), Some(ProviderKind::Bwrap), "falls back, loudly");
        assert!(caps.warning().unwrap().contains("namespace sandbox"));
        let caps = Capabilities { kernel: Some("/bin/true".into()), initramfs: Some("/bin/true".into()), ..caps };
        assert_eq!(caps.best(), Some(ProviderKind::Firecracker), "firecracker wins when everything is there");
    }

    /// Windows counterpart of `a_machine_without_a_kernel_image_is_not_called_a_microvm`:
    /// QEMU and WHPX alone are not a microVM either; with the image it is QEMU+WHPX.
    #[test]
    fn a_windows_machine_without_a_kernel_image_is_not_called_a_microvm() {
        let caps = Capabilities { os: HostOs::Windows, whpx: true, qemu: Some(r"C:\Program Files\qemu\qemu-system-x86_64.exe".into()), ..Default::default() };
        assert!(!caps.can_boot_vm(), "no image, no VM");
        let caps = Capabilities { kernel: Some(r"C:\img\vmlinux".into()), initramfs: Some(r"C:\img\initramfs.cpio.gz".into()), ..caps };
        assert_eq!(caps.best_vm(), Some((ProviderKind::Qemu, Accel::Whpx)));
        assert!(caps.warning().is_none(), "QEMU+WHPX is hardware-accelerated: {:?}", caps.warning());
        assert!(caps.report().iter().any(|l| l == "best provider: qemu (accelerator: Windows Hypervisor Platform)"), "{:?}", caps.report());
        let tcg = Capabilities { whpx: false, ..caps };
        assert_eq!(tcg.best_vm(), Some((ProviderKind::Qemu, Accel::Tcg)));
        assert!(tcg.warning().unwrap().contains("TCG"));
    }

    #[test]
    fn provider_names_parse_and_map_to_levels() {
        assert_eq!(ProviderKind::parse("fc"), Some(ProviderKind::Firecracker));
        assert_eq!(ProviderKind::parse("qemu").unwrap().isolation(), IsolationLevel::MicroVm);
        assert_eq!(ProviderKind::parse("nope"), None);
        assert!(ProviderKind::Bwrap.isolation().warning().is_some());
    }
}
