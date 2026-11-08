//! The platform-owned hypervisors that seagent drives through the platform's own tool rather
//! than a VMM it spawns itself: **Hyper-V** (Windows, PowerShell), **AVF** (Android, the
//! `vm` tool of the Virtualization APEX, crosvm under pKVM) — and the explicit refusal on
//! **iOS**, where the platform does not allow an app to run a VM at all.
//!
//! Hyper-V: a Generation 2 VM per spec on a *differencing* VHDX over the converted guest disk
//! (`qemu-img convert -O vhdx`, done once next to `disk.raw`), so every boot starts from the
//! pristine image and the child disk is deleted at stop. The network adapter `New-VM` adds is
//! removed (no NIC), Secure Boot is off (the image's loader is not Microsoft-signed), memory is
//! static, COM2 is a named pipe the host connects to ([`Transport::Uart`]). Creating VMs needs
//! an elevated session or membership in `Hyper-V Administrators`; the PowerShell error says so
//! when it is missing. Pause/resume = `Suspend-VM`/`Resume-VM`, memory snapshots =
//! `Checkpoint-VM`/`Restore-VMSnapshot`.
//!
//! AVF: `vm run --console … --log … <config.json>` with the image's kernel + initramfs and
//! no disks (`protected: false`: a non-protected VM, since the guest is not a signed
//! Microdroid payload). The tool prints the guest CID; the host connects AF_VSOCK to
//! `CID:5000` directly ([`Transport::VsockProxy`]). Only callers with the
//! `MANAGE_VIRTUAL_MACHINE` permission (the `shell` user, privileged apps) may do this; an
//! ordinary app gets AVF's own refusal, and `seagent` reports "delegate to a paired host".

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Endpoint, Transport};
use crate::config::VmConfig;
use crate::isolation::ProviderKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Why no VM exists on iOS (platform policy; never pretended).
pub const IOS_NO_VM: &str = "VM isolation is not available on iOS: the platform does not let an app run a hypervisor, spawn processes or JIT. Delegate VM work to a paired host (node / ARP).";
/// What is missing on an Android device without AVF.
pub const AVF_MISSING: &str = "no Android Virtualization Framework: /apex/com.android.virt/bin/vm is missing or /dev/kvm (pKVM) is not accessible";

// ── Hyper-V ─────────────────────────────────────────────────────────────────

pub struct HyperVProvider {
    disk: String,
}

impl HyperVProvider {
    pub fn new(cfg: &VmConfig) -> HyperVProvider {
        HyperVProvider { disk: cfg.disk_image.clone() }
    }
}

/// Single-quote a PowerShell literal.
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn hyperv_name(spec: &VmSpec) -> String {
    format!("seagent-{}", spec.id)
}

fn pipe_name(spec: &VmSpec) -> String {
    format!(r"\\.\pipe\seagent-{}", spec.id)
}

/// The PowerShell that creates and starts `spec` on a differencing disk over `base_vhdx`.
pub fn hyperv_create_script(spec: &VmSpec, base_vhdx: &Path) -> String {
    let n = ps_quote(&hyperv_name(spec));
    let child = ps_quote(&spec.run_dir.join("disk.vhdx").display().to_string());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         New-VHD -Path {child} -ParentPath {base} -Differencing | Out-Null\n\
         New-VM -Name {n} -Generation 2 -MemoryStartupBytes {mem}MB -VHDPath {child} -Path {run} | Out-Null\n\
         Get-VMNetworkAdapter -VMName {n} | Remove-VMNetworkAdapter\n\
         Set-VMMemory -VMName {n} -DynamicMemoryEnabled $false\n\
         Set-VMProcessor -VMName {n} -Count {cpus}\n\
         Set-VMFirmware -VMName {n} -EnableSecureBoot Off\n\
         Set-VMComPort -VMName {n} -Number 2 -Path {pipe}\n\
         Set-VM -Name {n} -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction TurnOff\n\
         Start-VM -Name {n}\n",
        base = ps_quote(&base_vhdx.display().to_string()),
        mem = spec.mem_mb,
        run = ps_quote(&spec.run_dir.display().to_string()),
        cpus = spec.vcpu,
        pipe = ps_quote(&pipe_name(spec)),
    )
}

fn powershell(script: &str) -> Result<String, String> {
    let ps = crate::host::find_tool("powershell").ok_or("powershell not found")?;
    let o = Command::new(ps).args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]).stdin(Stdio::null()).output().map_err(|e| format!("powershell: {e}"))?;
    if !o.status.success() {
        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
        let hint = if err.contains("permission") || err.contains("authorization") || err.contains("Administrator") { " (Hyper-V needs an elevated session or membership in the `Hyper-V Administrators` group)" } else { "" };
        return Err(format!("Hyper-V: {err}{hint}"));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The VHDX next to `raw`, converted once with `qemu-img` (Hyper-V cannot read raw disks).
fn ensure_vhdx(raw: &Path) -> Result<PathBuf, String> {
    let vhdx = raw.with_extension("vhdx");
    if vhdx.is_file() {
        return Ok(vhdx);
    }
    if !raw.is_file() {
        return Err(format!("Hyper-V needs a bootable UEFI guest disk ({} not found): it cannot boot the kernel + initramfs directly; build a raw UEFI disk of the image and set exec.vm.disk_image", raw.display()));
    }
    let qemu_img = crate::host::find_tool("qemu-img").ok_or("converting the guest disk to VHDX needs `qemu-img` (install QEMU for Windows), or convert it yourself and put disk.vhdx next to disk.raw")?;
    let o = Command::new(&qemu_img).args(["convert", "-f", "raw", "-O", "vhdx", "-o", "subformat=dynamic"]).arg(raw).arg(&vhdx).output().map_err(|e| format!("{}: {e}", qemu_img.display()))?;
    if !o.status.success() {
        return Err(format!("qemu-img convert to VHDX: {}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(vhdx)
}

impl VmProvider for HyperVProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::HyperV
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        if !cfg!(windows) {
            return Err("Hyper-V exists on Windows only".into());
        }
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        let base = ensure_vhdx(&super::vbox::raw_disk(&self.disk, spec))?;
        Endpoint::allocate_pipe(&spec.channel_path(), &format!("seagent-{}", spec.id))?;
        let mut inst = HyperVInstance { spec: spec.clone(), chan: None, created: true };
        if let Err(e) = powershell(&hyperv_create_script(spec, &base)) {
            inst.stop();
            return Err(e);
        }
        Ok(Box::new(inst))
    }
}

pub struct HyperVInstance {
    spec: VmSpec,
    chan: Option<Arc<Channel>>,
    created: bool,
}

impl HyperVInstance {
    fn vm(&self, cmdlet: &str) -> Result<String, String> {
        powershell(&format!("$ErrorActionPreference = 'Stop'; {cmdlet}").replace("{n}", &ps_quote(&hyperv_name(&self.spec))))
    }
}

impl VmInstance for HyperVInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::HyperV
    }
    fn pid(&self) -> Option<u32> {
        None
    }
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let ch = Arc::new(Channel::connect(&self.spec.channel_path(), Transport::Uart, wait)?);
        self.chan = Some(ch.clone());
        Ok(ch)
    }
    fn is_running(&mut self) -> bool {
        self.created && self.vm("(Get-VM -Name {n}).State").is_ok_and(|s| matches!(s.trim(), "Running" | "Paused"))
    }
    fn stop(&mut self) {
        self.chan = None;
        if self.created {
            let _ = self.vm("Stop-VM -Name {n} -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -Name {n} -Force");
            self.created = false;
        }
        let _ = std::fs::remove_file(self.spec.run_dir.join("disk.vhdx"));
        let _ = std::fs::remove_file(self.spec.channel_path());
    }
    fn pause(&mut self) -> Result<(), String> {
        self.vm("Suspend-VM -Name {n}").map(|_| ())
    }
    fn resume(&mut self) -> Result<(), String> {
        self.vm("Resume-VM -Name {n}").map(|_| ())
    }
    fn ram_snapshot(&mut self, dir: &Path) -> Result<Option<PathBuf>, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let snap = format!("seagent-{}", crate::snapshot::now());
        self.vm(&format!("Checkpoint-VM -Name {{n}} -SnapshotName {}", ps_quote(&snap)))?;
        let marker = dir.join("hyperv.checkpoint");
        std::fs::write(&marker, &snap).map_err(|e| e.to_string())?;
        Ok(Some(marker))
    }
    fn ram_restore(&mut self, dir: &Path) -> Result<(), String> {
        let snap = std::fs::read_to_string(dir.join("hyperv.checkpoint")).map_err(|e| format!("no Hyper-V checkpoint marker in {}: {e}", dir.display()))?;
        self.chan = None;
        self.vm(&format!("Restore-VMSnapshot -VMName {{n}} -Name {} -Confirm:$false; Start-VM -Name {{n}}", ps_quote(snap.trim())))?;
        self.connect(Duration::from_secs(30)).map(|_| ())
    }
}

// ── Android AVF ─────────────────────────────────────────────────────────────

pub struct AvfProvider {}

impl AvfProvider {
    pub fn new(_cfg: &VmConfig) -> AvfProvider {
        AvfProvider {}
    }
}

/// The `vm run` config for `spec` (VirtualMachineRawConfig JSON): direct kernel boot, no
/// disks, not protected; `match_host` vCPUs unless one was asked for.
pub fn avf_config(spec: &VmSpec) -> serde_json::Value {
    serde_json::json!({
        "name": format!("seagent-{}", spec.id),
        "kernel": spec.kernel.display().to_string(),
        "initrd": spec.initramfs.display().to_string(),
        "params": super::qemu::cmdline_append_on(spec, "hvc0"),
        "disks": [],
        "protected": false,
        "memory_mib": spec.mem_mb,
        "cpu_topology": if spec.vcpu <= 1 { "one_cpu" } else { "match_host" },
    })
}

/// The guest CID from `vm run` output (`… with CID 2049, state is STARTING.`).
pub fn parse_cid(line: &str) -> Option<u32> {
    let rest = &line[line.find("CID")? + 3..];
    rest.trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

impl VmProvider for AvfProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Avf
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        let tool = crate::host::avf_tool().ok_or_else(|| format!("VM isolation unavailable on this device ({AVF_MISSING}); delegate to a paired host"))?;
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        let cfg_path = spec.run_dir.join("vm.json");
        std::fs::write(&cfg_path, avf_config(spec).to_string()).map_err(|e| format!("write {}: {e}", cfg_path.display()))?;
        let mut child = crate::host::spawn_vmm(Command::new(&tool).arg("run").arg("--console").arg(spec.console_log()).arg("--log").arg(spec.log()).arg(&cfg_path).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()))
            .map_err(|e| format!("start {}: {e}", tool.display()))?;
        let cid = read_cid(&mut child, Duration::from_secs(20));
        let Some(cid) = cid else {
            crate::host::stop_vmm(&mut child);
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut e, &mut err);
            }
            return Err(format!("AVF `vm run` did not report a guest CID ({}); an ordinary app lacks MANAGE_VIRTUAL_MACHINE — delegate to a paired host", err.trim()));
        };
        Ok(Box::new(AvfInstance { spec: spec.clone(), child: Some(child), cid, chan: None }))
    }
}

fn read_cid(child: &mut Child, wait: Duration) -> Option<u32> {
    let out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(c) = parse_cid(&line) {
                let _ = tx.send(c);
            }
        }
    });
    rx.recv_timeout(wait).ok()
}

pub struct AvfInstance {
    spec: VmSpec,
    child: Option<Child>,
    cid: u32,
    chan: Option<Arc<Channel>>,
}

impl VmInstance for AvfInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Avf
    }
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let deadline = Instant::now() + wait;
        loop {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let r = crate::channel::Stream::connect_vsock(self.cid, crate::proto::VSOCK_PORT);
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let r: std::io::Result<crate::channel::Stream> = Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "AF_VSOCK"));
            match r {
                Ok(s) => {
                    let ch = Arc::new(Channel::from_stream(s, Transport::VsockProxy { port: crate::proto::VSOCK_PORT })?);
                    self.chan = Some(ch.clone());
                    return Ok(ch);
                }
                Err(e) if Instant::now() < deadline && e.kind() != std::io::ErrorKind::Unsupported => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(format!("vsock {}:{}: {e}", self.cid, crate::proto::VSOCK_PORT)),
            }
        }
    }
    fn is_running(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }
    fn stop(&mut self) {
        self.chan = None;
        if let Some(mut c) = self.child.take() {
            crate::host::stop_vmm(&mut c);
        }
    }
    fn usage(&self) -> VmUsage {
        VmUsage::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    fn spec() -> VmSpec {
        VmSpec {
            id: "h-1".into(),
            tier: "owner".into(),
            kernel: "/img/vmlinux".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/r/h-1".into(),
            vcpu: 4,
            mem_mb: 2048,
            workspace: None,
            limits: Limits::default(),
            transport: Transport::Uart,
            firecracker: None,
            qemu: None,
            extra_args: vec![],
            guest_cid: 3,
        }
    }

    #[test]
    fn hyperv_vm_has_no_nic_a_throwaway_disk_and_a_pipe_channel() {
        let s = hyperv_create_script(&spec(), Path::new(r"C:\img\disk.vhdx"));
        assert!(s.contains("-Differencing") && s.contains(r"-ParentPath 'C:\img\disk.vhdx'"), "{s}");
        assert!(s.contains("Remove-VMNetworkAdapter"), "no NIC: {s}");
        assert!(s.contains("-MemoryStartupBytes 2048MB") && s.contains("-Count 4") && s.contains("-DynamicMemoryEnabled $false"), "{s}");
        assert!(s.contains(r"Set-VMComPort -VMName 'seagent-h-1' -Number 2 -Path '\\.\pipe\seagent-h-1'"), "{s}");
        assert_eq!(ps_quote("it's"), "'it''s'", "no PowerShell injection through a path");
    }

    #[test]
    fn avf_boots_the_image_unprotected_and_reports_its_cid() {
        let mut sp = spec();
        sp.transport = Transport::VsockProxy { port: 5000 };
        let c = avf_config(&sp);
        assert_eq!((c["kernel"].as_str(), c["protected"].as_bool(), c["memory_mib"].as_u64()), (Some("/img/vmlinux"), Some(false), Some(2048)));
        assert!(c["disks"].as_array().unwrap().is_empty());
        assert!(c["params"].as_str().unwrap().contains("seagent.channel=vsock"));
        assert_eq!(parse_cid("Created VM from \"/data/local/tmp/vm.json\" with CID 2049, state is STARTING."), Some(2049));
        assert_eq!(parse_cid("no id here"), None);
    }

    #[test]
    fn ios_never_gets_a_vm() {
        assert!(IOS_NO_VM.contains("not available on iOS"));
        if cfg!(target_os = "ios") {
            assert!(crate::provider::build(ProviderKind::Qemu, &VmConfig::default()).is_err());
        }
    }
}
