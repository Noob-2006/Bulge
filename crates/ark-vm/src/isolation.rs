//! What kind of wall separates a tool call from the host, and how loudly ark has
//! to say so (B1: microVM first, gVisor/bwrap as an explicitly *weaker*
//! fallback — never a silent downgrade).
//!
//! Every execution backend in ark is classified here, so `ark sandbox explain`,
//! `ark doctor` and the system prompt can all answer "where does this command
//! actually run, and what does that protect me from?" from one table.

use serde::Serialize;
use std::path::{Path, PathBuf};

/// Ordering matters: higher is stronger isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// No wall at all: the process runs as the ark user (`local`).
    Host,
    /// Namespaces/seccomp only, shared kernel: bwrap, Landlock.
    UserNamespace,
    /// Container with its own rootfs, shared kernel: docker, podman.
    Container,
    /// Kernel-level sandbox in user space (gVisor `runsc`) or a remote host.
    AppKernel,
    /// Hardware virtualisation: the guest has its own kernel (Firecracker/QEMU-KVM).
    MicroVm,
}

impl IsolationLevel {
    pub fn label(self) -> &'static str {
        match self {
            IsolationLevel::Host => "host",
            IsolationLevel::UserNamespace => "user-namespace",
            IsolationLevel::Container => "container",
            IsolationLevel::AppKernel => "app-kernel (gVisor)",
            IsolationLevel::MicroVm => "microVM",
        }
    }
    /// 0..=4, for sorting and for "is this at least as strong as X?" checks.
    pub fn rank(self) -> u8 {
        match self {
            IsolationLevel::Host => 0,
            IsolationLevel::UserNamespace => 1,
            IsolationLevel::Container => 2,
            IsolationLevel::AppKernel => 3,
            IsolationLevel::MicroVm => 4,
        }
    }
    /// The sentence ark shows whenever a weaker level is used than the design
    /// target. `None` for a microVM: nothing to warn about.
    pub fn warning(self) -> Option<&'static str> {
        match self {
            IsolationLevel::MicroVm => None,
            IsolationLevel::AppKernel => Some("gVisor: the guest shares the host kernel through a user-space kernel; kernel bugs are contained but not eliminated. Keys and the daemon socket stay outside either way."),
            IsolationLevel::Container => Some("container: shares the host kernel and (for docker/podman) the host's namespaces; a kernel bug or a misconfigured mount reaches the host. Not equivalent to a microVM."),
            IsolationLevel::UserNamespace => Some("namespace sandbox (bwrap/Landlock): shares the host kernel, one kernel bug from the host. Treat untrusted code as able to read anything the ark user can read."),
            IsolationLevel::Host => Some("NO isolation: commands run directly on this machine as the ark user. Only acceptable for the operator's own trusted work."),
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
    Firecracker,
    Qemu,
    /// Fallback: gVisor `runsc` (needs root-ish setup; detected, never assumed).
    Gvisor,
    /// Fallback: bubblewrap namespaces, the level ark already had.
    Bwrap,
}

impl ProviderKind {
    pub fn name(self) -> &'static str {
        match self {
            ProviderKind::Firecracker => "firecracker",
            ProviderKind::Qemu => "qemu",
            ProviderKind::Gvisor => "gvisor",
            ProviderKind::Bwrap => "bwrap",
        }
    }
    pub fn parse(s: &str) -> Option<ProviderKind> {
        Some(match s {
            "firecracker" | "fc" => ProviderKind::Firecracker,
            "qemu" => ProviderKind::Qemu,
            "gvisor" | "runsc" => ProviderKind::Gvisor,
            "bwrap" => ProviderKind::Bwrap,
            _ => return None,
        })
    }
    pub fn is_vm(self) -> bool {
        matches!(self, ProviderKind::Firecracker | ProviderKind::Qemu)
    }
    pub fn isolation(self) -> IsolationLevel {
        match self {
            ProviderKind::Firecracker | ProviderKind::Qemu => IsolationLevel::MicroVm,
            ProviderKind::Gvisor => IsolationLevel::AppKernel,
            ProviderKind::Bwrap => IsolationLevel::UserNamespace,
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
}

impl Capabilities {
    pub fn detect(kernel: Option<&Path>, initramfs: Option<&Path>) -> Capabilities {
        let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
        let kernel = kernel.filter(|p| p.exists()).map(PathBuf::from);
        let initramfs = initramfs.filter(|p| p.exists()).map(PathBuf::from);
        Capabilities {
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
        }
    }
    /// Can a real microVM boot right now?
    pub fn can_boot_vm(&self) -> bool {
        self.kvm && self.kernel.is_some() && self.initramfs.is_some() && (self.firecracker.is_some() || self.qemu.is_some())
    }
    /// Best available provider, strongest first. `None` when this machine cannot
    /// isolate at all.
    pub fn best(&self) -> Option<ProviderKind> {
        if self.can_boot_vm() && self.firecracker.is_some() {
            return Some(ProviderKind::Firecracker);
        }
        if self.can_boot_vm() && self.qemu.is_some() {
            return Some(ProviderKind::Qemu);
        }
        if self.runsc.is_some() {
            return Some(ProviderKind::Gvisor);
        }
        if self.bwrap.is_some() && self.host.userns {
            return Some(ProviderKind::Bwrap);
        }
        None
    }
    /// Human-readable lines for `ark sandbox explain` / `ark doctor`.
    pub fn report(&self) -> Vec<String> {
        let p = |x: &Option<PathBuf>| x.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "missing".into());
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
    /// The warning tied to what `best()` would actually pick.
    pub fn warning(&self) -> Option<String> {
        let kind = self.best()?;
        if let Some(w) = kind.isolation().warning() {
            return Some(format!("execution isolation is {} ({}): {w}", kind.isolation().label(), kind.name()));
        }
        None
    }
}

/// Minimal `which` (no shell, no PATH surprises beyond PATH itself).
pub fn which(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
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
        // Only a real VM is warning-free.
        assert!(IsolationLevel::MicroVm.warning().is_none());
        for l in [IsolationLevel::Host, IsolationLevel::UserNamespace, IsolationLevel::Container, IsolationLevel::AppKernel] {
            assert!(l.warning().is_some(), "{l:?} must warn");
        }
        assert!(isolation_of_backend("local").warning().unwrap().contains("NO isolation"));
    }

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

    #[test]
    fn provider_names_parse_and_map_to_levels() {
        assert_eq!(ProviderKind::parse("fc"), Some(ProviderKind::Firecracker));
        assert_eq!(ProviderKind::parse("qemu").unwrap().isolation(), IsolationLevel::MicroVm);
        assert_eq!(ProviderKind::parse("nope"), None);
        assert!(ProviderKind::Bwrap.isolation().warning().is_some());
    }
}
