//! Oracle VirtualBox provider (Windows, macOS, Linux), driven entirely through `VBoxManage`.
//!
//! VirtualBox cannot boot a kernel + initramfs directly, so it boots the guest *disk*
//! (`exec.vm.disk_image`, a raw UEFI disk whose ESP starts the same kernel and initramfs with
//! `seagent.channel=uart`). On first use the raw disk is converted next to itself with
//! `VBoxManage convertfromraw … --format VDI` and attached **immutable**: every boot starts from
//! the pristine image and the differencing disk is thrown away (the B2 property the initramfs
//! gives the other providers).
//!
//! Lifecycle per VM (`seagent-<id>`, its files under the VM's run dir):
//! `createvm --register` → `modifyvm` (cpus, memory, EFI, **no NIC**, no audio/USB, COM1 =
//! console file, COM2 = the channel) → `storagectl` + `storageattach` → `startvm --type
//! headless`; `controlvm pause|resume`; `snapshot take|restore` as the memory snapshot;
//! `controlvm poweroff` + `unregistervm --delete` to stop.
//!
//! The channel is the guest's second UART ([`Transport::Uart`]): VirtualBox serves COM2 as a
//! unix socket (`--uartmode2 server <run>/chan.sock`) on Linux/macOS and as a named pipe
//! (`\\.\pipe\seagent-<id>`) on Windows — never as a TCP server, which VirtualBox binds on
//! every interface. Memory and CPU are VirtualBox's own `--memory` / `--cpus` ceilings.
//!
//! Caveat recorded in the report: the guest's kernel command line is the one baked into the
//! disk, so per-VM `seagent.*` parameters (tier label, limits) come from the host's `Limits`
//! message rather than `/proc/cmdline`.

use super::{VmInstance, VmProvider, VmSpec};
use crate::channel::{Channel, Endpoint, Transport};
use crate::config::VmConfig;
use crate::isolation::ProviderKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub struct VboxProvider {
    bin: String,
    disk: String,
}

impl VboxProvider {
    pub fn new(cfg: &VmConfig) -> VboxProvider {
        VboxProvider { bin: cfg.vboxmanage.clone(), disk: cfg.disk_image.clone() }
    }
}

/// The VM's VirtualBox name.
pub fn vm_name(spec: &VmSpec) -> String {
    format!("seagent-{}", spec.id)
}

/// The raw disk for `spec`: `exec.vm.disk_image`, else `disk.raw` next to the kernel.
pub fn raw_disk(configured: &str, spec: &VmSpec) -> PathBuf {
    if configured.is_empty() {
        spec.kernel.parent().unwrap_or(Path::new(".")).join("disk.raw")
    } else {
        crate::config::expand(configured)
    }
}

/// Where COM2 is served: a unix socket in the run dir, or a named pipe on Windows.
pub fn channel_endpoint(spec: &VmSpec, windows: bool) -> Endpoint {
    if windows {
        Endpoint::Pipe(format!(r"\\.\pipe\seagent-{}", spec.id))
    } else {
        Endpoint::Unix(spec.channel_path())
    }
}

/// Every `VBoxManage` invocation that creates and boots `spec` on this host, in order.
/// The guest architecture follows the host's: VirtualBox runs arm64 VMs only on Apple
/// Silicon (7.1+) and x86_64 VMs only on x86_64 hosts.
pub fn create_commands(spec: &VmSpec, vdi: &Path, chan: &Endpoint) -> Vec<Vec<String>> {
    create_commands_for(spec, vdi, chan, cfg!(target_arch = "aarch64"))
}

/// [`create_commands`] for an explicit guest architecture (pure: the shape is tested without
/// VirtualBox).
///
/// * x86_64: `--ostype Linux_64`, `--firmware efi`, an AHCI controller, COM1/COM2 at the
///   16550 I/O ports `0x3F8/4` and `0x2F8/3` (guest `ttyS0` / `ttyS1`).
/// * arm64 (`aarch64 = true`): `createvm --platform-architecture arm` (VirtualBox 7.1+,
///   which also selects the ARMv8 virtual chipset and its only firmware, UEFI — so no
///   `--firmware`), `--ostype Linux_arm64`, a virtio-scsi controller (the arm platform has
///   no AHCI-only boot path; the firmware reads the ESP through it and the guest never mounts
///   the disk). The UARTs: `VBoxManage --uartN` only has the `<I/O base> <IRQ>` form, and on
///   the arm platform VirtualBox ignores those numbers and maps each enabled slot to a PL011
///   at the platform's fixed MMIO address, so the same COM1/COM2 values are passed as the slot
///   defaults; the guest sees `ttyAMA0` (console) and `ttyAMA1` (the channel, which the agent
///   probes for on aarch64).
pub fn create_commands_for(spec: &VmSpec, vdi: &Path, chan: &Endpoint, aarch64: bool) -> Vec<Vec<String>> {
    let name = vm_name(spec);
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let chan_path = match chan {
        Endpoint::Unix(p) => p.display().to_string(),
        Endpoint::Pipe(n) => n.clone(),
        Endpoint::Tcp(a) => a.to_string(),
    };
    let mut create = s(&["createvm", "--name", &name, "--basefolder", &spec.run_dir.display().to_string()]);
    if aarch64 {
        create.extend(s(&["--platform-architecture", "arm", "--ostype", "Linux_arm64", "--register"]));
    } else {
        create.extend(s(&["--ostype", "Linux_64", "--register"]));
    }
    let mut modify = s(&["modifyvm", &name, "--cpus", &spec.vcpu.to_string(), "--memory", &spec.mem_mb.to_string()]);
    if !aarch64 {
        modify.extend(s(&["--firmware", "efi"]));
    }
    modify.extend(s(&["--nic1", "none", "--usb", "off", "--boot1", "disk", "--boot2", "none", "--boot3", "none", "--boot4", "none"]));
    modify.extend(s(&["--uart1", "0x3F8", "4", "--uartmode1", "file", &spec.console_log().display().to_string(), "--uart2", "0x2F8", "3", "--uartmode2", "server", &chan_path]));
    let (ctl, add, controller) = if aarch64 { ("VirtIO", "virtio", "VirtIO") } else { ("SATA", "sata", "IntelAhci") };
    vec![
        create,
        modify,
        s(&["storagectl", &name, "--name", ctl, "--add", add, "--controller", controller, "--portcount", "1"]),
        s(&["storageattach", &name, "--storagectl", ctl, "--port", "0", "--device", "0", "--type", "hdd", "--medium", &vdi.display().to_string(), "--mtype", "immutable"]),
        s(&["startvm", &name, "--type", "headless"]),
    ]
}

fn run(bin: &Path, args: &[String]) -> Result<String, String> {
    let o = Command::new(bin).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{}: {e}", bin.display()))?;
    if !o.status.success() {
        return Err(format!("VBoxManage {}: {}", args.first().map(String::as_str).unwrap_or(""), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The VDI next to `raw`, converted on first use (`VBoxManage convertfromraw`).
fn ensure_vdi(bin: &Path, raw: &Path) -> Result<PathBuf, String> {
    let vdi = raw.with_extension("vdi");
    if vdi.is_file() {
        return Ok(vdi);
    }
    if !raw.is_file() {
        return Err(format!(
            "VirtualBox needs a bootable guest disk ({} not found): VirtualBox cannot boot the kernel + initramfs directly; build a raw UEFI disk of the image and set exec.vm.disk_image",
            raw.display()
        ));
    }
    run(bin, &["convertfromraw".into(), raw.display().to_string(), vdi.display().to_string(), "--format".into(), "VDI".into()])?;
    Ok(vdi)
}

impl VmProvider for VboxProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::VirtualBox
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        let bin = crate::host::find_tool(&self.bin).ok_or_else(|| format!("`{}` not found (install Oracle VirtualBox, or set exec.vm.vboxmanage)", self.bin))?;
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        let vdi = ensure_vdi(&bin, &raw_disk(&self.disk, spec))?;
        let windows = cfg!(windows);
        let chan = channel_endpoint(spec, windows);
        if windows {
            Endpoint::allocate_pipe(&spec.channel_path(), &format!("seagent-{}", spec.id))?;
        } else {
            let _ = std::fs::remove_file(spec.channel_path());
        }
        let mut inst = VboxInstance { spec: spec.clone(), bin, chan: None, registered: false };
        for (i, args) in create_commands(spec, &vdi, &chan).into_iter().enumerate() {
            if let Err(e) = run(&inst.bin, &args) {
                inst.stop();
                return Err(e);
            }
            if i == 0 {
                inst.registered = true;
            }
        }
        Ok(Box::new(inst))
    }
}

pub struct VboxInstance {
    spec: VmSpec,
    bin: PathBuf,
    chan: Option<Arc<Channel>>,
    registered: bool,
}

impl VboxInstance {
    fn manage(&self, args: &[&str]) -> Result<String, String> {
        run(&self.bin, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }
    fn state(&self) -> Option<String> {
        let info = self.manage(&["showvminfo", &vm_name(&self.spec), "--machinereadable"]).ok()?;
        info.lines().find_map(|l| l.strip_prefix("VMState=")).map(|v| v.trim_matches('"').to_string())
    }
}

impl VmInstance for VboxInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::VirtualBox
    }
    fn pid(&self) -> Option<u32> {
        // VBoxHeadless is started by VBoxSVC, not by us; usage comes from VirtualBox itself.
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
        self.registered && matches!(self.state().as_deref(), Some("running") | Some("paused"))
    }
    fn stop(&mut self) {
        self.chan = None;
        if self.registered {
            let name = vm_name(&self.spec);
            let _ = self.manage(&["controlvm", &name, "poweroff"]);
            // VBoxSVC releases the session asynchronously; unregister once it has.
            for _ in 0..50 {
                if self.manage(&["unregistervm", &name, "--delete"]).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            self.registered = false;
        }
        let _ = std::fs::remove_file(self.spec.channel_path());
    }
    fn pause(&mut self) -> Result<(), String> {
        self.manage(&["controlvm", &vm_name(&self.spec), "pause"]).map(|_| ())
    }
    fn resume(&mut self) -> Result<(), String> {
        self.manage(&["controlvm", &vm_name(&self.spec), "resume"]).map(|_| ())
    }
    /// `snapshot take --live` (RAM + device state, kept by VirtualBox). `dir` gets a marker
    /// naming the snapshot so `ram_restore` finds it.
    fn ram_snapshot(&mut self, dir: &Path) -> Result<Option<PathBuf>, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let snap = format!("seagent-{}", crate::snapshot::now());
        self.manage(&["snapshot", &vm_name(&self.spec), "take", &snap, "--live"])?;
        let marker = dir.join("vbox.snapshot");
        std::fs::write(&marker, &snap).map_err(|e| e.to_string())?;
        Ok(Some(marker))
    }
    /// Restore needs a powered-off VM: power off, `snapshot restore`, start again.
    fn ram_restore(&mut self, dir: &Path) -> Result<(), String> {
        let snap = std::fs::read_to_string(dir.join("vbox.snapshot")).map_err(|e| format!("no VirtualBox snapshot marker in {}: {e}", dir.display()))?;
        let name = vm_name(&self.spec);
        self.chan = None;
        let _ = self.manage(&["controlvm", &name, "poweroff"]);
        std::thread::sleep(Duration::from_millis(500));
        self.manage(&["snapshot", &name, "restore", snap.trim()])?;
        self.manage(&["startvm", &name, "--type", "headless"])?;
        self.connect(Duration::from_secs(30)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    fn spec() -> VmSpec {
        VmSpec {
            id: "v-1".into(),
            tier: "owner".into(),
            kernel: "/img/vmlinux".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/r/v-1".into(),
            vcpu: 2,
            mem_mb: 1024,
            workspace: None,
            limits: Limits::default(),
            transport: Transport::Uart,
            firecracker: None,
            qemu: None,
            extra_args: vec![],
            guest_cid: 3,
        }
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn virtualbox_boots_an_immutable_disk_with_no_nic_and_a_private_channel() {
        let s = spec();
        assert_eq!(raw_disk("", &s), PathBuf::from("/img/disk.raw"), "the disk lives next to the kernel");
        let unix = channel_endpoint(&s, false);
        let cmds = create_commands_for(&s, Path::new("/img/disk.vdi"), &unix, false);
        let names: Vec<&str> = cmds.iter().map(|c| c[0].as_str()).collect();
        assert_eq!(names, ["createvm", "modifyvm", "storagectl", "storageattach", "startvm"]);
        let modify = cmds[1].join(" ");
        assert!(modify.contains("--cpus 2 --memory 1024") && modify.contains("--nic1 none"), "{modify}");
        assert!(modify.contains("--uartmode2 server /r/v-1/chan.sock") && !modify.contains("tcpserver"), "never a TCP server on all interfaces: {modify}");
        assert!(cmds[3].join(" ").ends_with("--medium /img/disk.vdi --mtype immutable"), "nothing the guest writes survives a boot");
        assert_eq!(cmds[4], ["startvm", "seagent-v-1", "--type", "headless"]);
        // Windows: COM2 is a named pipe.
        let win = create_commands_for(&s, Path::new("disk.vdi"), &channel_endpoint(&s, true), false)[1].join(" ");
        assert!(win.contains(r"--uartmode2 server \\.\pipe\seagent-v-1"), "{win}");
        // The x86_64 shape is exactly what it always was.
        assert_eq!(cmds[0].join(" "), "createvm --name seagent-v-1 --basefolder /r/v-1 --ostype Linux_64 --register");
        assert!(modify.contains("--firmware efi") && modify.contains("--uart1 0x3F8 4") && modify.contains("--uart2 0x2F8 3"), "{modify}");
        assert_eq!(cmds[2].join(" "), "storagectl seagent-v-1 --name SATA --add sata --controller IntelAhci --portcount 1");
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn virtualbox_on_arm64_creates_an_arm_platform_vm() {
        let s = spec();
        let cmds = create_commands_for(&s, Path::new("/img/disk.vdi"), &channel_endpoint(&s, false), true);
        let names: Vec<&str> = cmds.iter().map(|c| c[0].as_str()).collect();
        assert_eq!(names, ["createvm", "modifyvm", "storagectl", "storageattach", "startvm"]);
        let create = cmds[0].join(" ");
        assert!(create.contains("--platform-architecture arm") && create.contains("--ostype Linux_arm64"), "{create}");
        let modify = cmds[1].join(" ");
        assert!(!modify.contains("--firmware"), "arm VMs are UEFI-only: {modify}");
        assert!(modify.contains("--nic1 none") && modify.contains("--uartmode2 server /r/v-1/chan.sock"), "{modify}");
        assert!(cmds[2].join(" ").contains("--add virtio --controller VirtIO"), "{:?}", cmds[2]);
        assert!(cmds[3].join(" ").contains("--storagectl VirtIO") && cmds[3].join(" ").ends_with("--mtype immutable"));
    }
}
