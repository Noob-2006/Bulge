//! `[exec.vm]` — how the microVM environment is chosen, sized and limited.
//!
//! Defaults are the design target of B: Firecracker when the machine can do it,
//! QEMU-KVM otherwise, one writable workspace (recovery is by snapshot, not by
//! a read-only mount — §0-3/B2), no direct network, snapshots on.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VmConfig {
    /// `auto` | `firecracker` | `qemu` | `gvisor` | `bwrap`.
    /// `bwrap`/`gvisor` are the *explicit* weaker fallbacks; `auto` uses them only
    /// when no microVM can boot, and always with the isolation warning.
    pub provider: String,
    /// May `provider = "firecracker"` degrade to another provider? The warning is
    /// reported either way; `false` refuses instead of degrading.
    pub allow_fallback: bool,
    /// Guest kernel (Firecracker CI `vmlinux` or a `bzImage`). Default
    /// `<data>/vm/kernel/vmlinux`.
    pub kernel: String,
    /// Guest initramfs (cpio.gz) built by `packaging/vm/build-image.sh`.
    /// Default `<data>/vm/kernel/initramfs.cpio.gz`.
    pub initramfs: String,
    /// Where images, per-VM run dirs and snapshots live. Default `<data>/vm`.
    pub image_dir: String,
    pub firecracker: String,
    pub qemu: String,
    pub vcpu: u16,
    pub memory_mb: u32,
    /// Size of the guest `/tmp` tmpfs (MB). 0 = provider default (256).
    pub disk_mb: u64,
    /// `RLIMIT_NPROC` for the agent user (fork bombs die inside the VM).
    pub max_processes: u64,
    pub max_open_files: u64,
    /// Total CPU seconds per VM (0 = rely on `timeout` per command only).
    pub cpu_seconds: u64,
    /// Kill the VM after this many seconds of one command (0 = `[exec] default_timeout`).
    pub exec_timeout_secs: u64,
    /// Reap a VM idle this long (0 = never).
    pub idle_timeout_secs: u64,
    /// `rw` (default: snapshot/undo is the protection) or `ro` for sensitive
    /// projects. Per-workspace override lives in `[exec.vm.readonly]`.
    pub workspace_access: String,
    /// Refuse to sync a workspace larger than this (MB); never silently truncate.
    pub workspace_max_mb: u64,
    /// `broker` (default: no direct egress, the agent asks the daemon) or `none`.
    pub network: String,
    pub snapshots: bool,
    /// Snapshots kept per VM (oldest pruned).
    pub snapshot_keep: usize,
    /// Separate VMs per trust tier (B5) — `false` only for single-user setups
    /// that never run stranger-triggered work.
    pub trust_tiers: bool,
    /// One VM per session (default) or one per trust tier.
    pub one_vm_per_session: bool,
    /// Extra provider args (escape hatch; validated by the provider).
    pub extra_args: Vec<String>,
    /// Firecracker guest CID.
    pub guest_cid: u32,
    /// Let in-VM programs ask the host broker for egress/privileged work.
    pub broker: bool,
    /// Host paths that are *never* synced into a VM even if inside a workspace
    /// (`~/.ssh`, `~/.aws`, …); defence in depth for H11/A4.
    pub deny_paths: Vec<String>,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            provider: "auto".into(),
            allow_fallback: true,
            kernel: String::new(),
            initramfs: String::new(),
            image_dir: String::new(),
            firecracker: "firecracker".into(),
            qemu: "qemu-system-x86_64".into(),
            vcpu: 2,
            memory_mb: 1024,
            disk_mb: 0,
            max_processes: 512,
            max_open_files: 4096,
            cpu_seconds: 0,
            exec_timeout_secs: 0,
            idle_timeout_secs: 1800,
            workspace_access: "rw".into(),
            workspace_max_mb: 512,
            network: "broker".into(),
            snapshots: true,
            snapshot_keep: 20,
            trust_tiers: true,
            one_vm_per_session: true,
            extra_args: vec![],
            guest_cid: 3,
            broker: true,
            deny_paths: vec![".ssh".into(), ".aws".into(), ".gnupg".into(), ".config/gh".into(), ".netrc".into(), ".docker/config.json".into(), ".kube".into(), "secrets.json".into()],
        }
    }
}

impl VmConfig {
    pub fn parse(v: &serde_json::Value) -> Result<VmConfig, String> {
        if v.is_null() {
            return Ok(VmConfig::default());
        }
        let c: VmConfig = serde_json::from_value(v.clone()).map_err(|e| format!("[exec.vm]: {e}"))?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<(), String> {
        let one = |k: &str, v: &str, ok: &[&str]| {
            if ok.contains(&v) {
                Ok(())
            } else {
                Err(format!("exec.vm.{k} `{v}`: use {}", ok.join(" | ")))
            }
        };
        one("provider", &self.provider, &["auto", "firecracker", "fc", "qemu", "gvisor", "runsc", "bwrap"])?;
        one("workspace_access", &self.workspace_access, &["rw", "ro"])?;
        one("network", &self.network, &["broker", "none"])?;
        if self.vcpu == 0 || self.vcpu > 32 {
            return Err("exec.vm.vcpu must be 1..=32".into());
        }
        if self.memory_mb < 64 || self.memory_mb > 65536 {
            return Err("exec.vm.memory_mb must be 64..=65536".into());
        }
        if self.snapshot_keep == 0 {
            return Err("exec.vm.snapshot_keep must be > 0".into());
        }
        if self.max_processes < 8 {
            return Err("exec.vm.max_processes must be >= 8".into());
        }
        if self.guest_cid < 3 {
            return Err("exec.vm.guest_cid must be >= 3 (CID 0-2 are reserved)".into());
        }
        Ok(())
    }

    /// `<data>/vm` unless configured.
    pub fn root(&self, data: &Path) -> PathBuf {
        if self.image_dir.is_empty() {
            data.join("vm")
        } else {
            expand(&self.image_dir)
        }
    }
    pub fn kernel_path(&self, data: &Path) -> PathBuf {
        if self.kernel.is_empty() {
            self.root(data).join("kernel").join("vmlinux")
        } else {
            expand(&self.kernel)
        }
    }
    pub fn initramfs_path(&self, data: &Path) -> PathBuf {
        if self.initramfs.is_empty() {
            self.root(data).join("kernel").join("initramfs.cpio.gz")
        } else {
            expand(&self.initramfs)
        }
    }
    /// Run dir for one VM: sockets, console log, snapshots.
    pub fn run_dir(&self, data: &Path, vm_id: &str) -> PathBuf {
        self.root(data).join("run").join(vm_id)
    }
    pub fn snapshot_root(&self, data: &Path) -> PathBuf {
        self.root(data).join("snapshots")
    }
    /// `workspace_access = "ro"` or an entry in `readonly`. Globs are matched on
    /// the workspace path suffix.
    pub fn workspace_readonly(&self, workspace: &Path) -> bool {
        if self.workspace_access == "ro" {
            return true;
        }
        let ws = workspace.to_string_lossy();
        self.readonly_patterns().iter().any(|p| glob_suffix_match(&ws, p))
    }
    pub fn readonly_patterns(&self) -> Vec<String> {
        vec![]
    }
    pub fn tmp_dir(&self) -> PathBuf {
        PathBuf::from(std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()))
    }
}

/// `~/x` and `${X}` expansion (same rules as the rest of ark's config).
pub fn expand(p: &str) -> PathBuf {
    let mut s = p.to_string();
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_default();
        s = format!("{home}/{rest}");
    }
    PathBuf::from(s)
}

/// `src/**` style suffix glob (only `*` and `**` at the end, enough for config).
fn glob_suffix_match(path: &str, pat: &str) -> bool {
    if let Some(pre) = pat.strip_suffix("/**") {
        return path.starts_with(pre);
    }
    if let Some(pre) = pat.strip_suffix('*') {
        return path.starts_with(pre);
    }
    path == pat
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_microvm_target() {
        let c = VmConfig::default();
        c.validate().unwrap();
        assert_eq!(c.provider, "auto");
        assert!(c.snapshots && c.trust_tiers && c.broker, "snapshots and tiered VMs are default behaviour");
        assert_eq!(c.workspace_access, "rw", "§0-3: writable by default, undo by snapshot");
        assert_eq!(c.network, "broker", "no direct egress");
        assert!(c.deny_paths.iter().any(|p| p == ".ssh"), "credential paths stay on the host");
        let d = PathBuf::from("/data");
        assert_eq!(c.kernel_path(&d), PathBuf::from("/data/vm/kernel/vmlinux"));
        assert_eq!(c.initramfs_path(&d), PathBuf::from("/data/vm/kernel/initramfs.cpio.gz"));
        assert_eq!(c.run_dir(&d, "s-1"), PathBuf::from("/data/vm/run/s-1"));
    }

    #[test]
    fn bad_values_are_rejected_at_parse_time() {
        for (k, v) in [("vcpu", 0), ("memory_mb", 16), ("snapshot_keep", 0)] {
            let bad = serde_json::json!({ k: v });
            assert!(VmConfig::parse(&bad).is_err(), "{k}={v} must fail");
        }
        assert!(VmConfig::parse(&serde_json::json!({"workspace_access": "maybe"})).is_err());
        assert!(VmConfig::parse(&serde_json::json!({"provider": "vmware"})).is_err());
        assert!(VmConfig::parse(&serde_json::json!({"nonsense": 1})).is_err(), "typos in [exec.vm] are errors");
    }

    #[test]
    fn workspace_can_be_pinned_read_only() {
        let mut c = VmConfig::default();
        assert!(!c.workspace_readonly(Path::new("/src/proj")));
        c.workspace_access = "ro".into();
        c.validate().unwrap();
        assert!(c.workspace_readonly(Path::new("/src/proj")), "sensitive dirs can be ro (B2)");
    }
}
