//! QEMU-KVM provider: the microVM that works on any Linux box with `/dev/kvm`,
//! no extra privileges and no Firecracker binary (it is also the fallback when
//! the Firecracker release binary is missing).
//!
//! Shape of the VM (validated by `tests/boot_vm.rs`):
//! * `-M q35 -accel kvm -cpu host`, a real kernel boot — the guest never sees a
//!   host file descriptor or path;
//! * rootfs = the read-only initramfs from `packaging/vm/build-image.sh`, so the
//!   kernel image is immutable inside the VM and there is no block device to
//!   corrupt;
//! * `-net none`: the only route out of the guest is the agent's broker request
//!   over the channel (A3);
//! * the channel is virtio-serial (`/dev/vport0p1` in the guest, a unix socket
//!   named `chan.sock` here). vsock under QEMU needs `vhost-vsock` and
//!   `/dev/vsock` on the host, which most machines (including the CI one) do not
//!   have; Firecracker uses vsock, QEMU uses the serial port. Same frames.
//!
//! The same provider is the substitute on the other desktop systems
//! (docs/cross-platform.md):
//! * **Windows**: `-accel whpx` (Windows Hypervisor Platform), or TCG with the warning from
//!   [`super::accel_note`]; channel and monitor are TCP servers on 127.0.0.1 (Windows QEMU
//!   has no unix sockets), the VMM sits in a Job Object sized to the VM
//!   ([`crate::host::VmmJob`]); no `-sandbox` (seccomp is Linux-only).
//! * **macOS**: `-accel hvf`. On Apple Silicon `qemu-system-aarch64 -M virt,highmem=on
//!   -cpu host` with Homebrew's `edk2-aarch64-code.fd` when present, console on `ttyAMA0`;
//!   the guest image must then be an arm64 build. Unix sockets as on Linux.

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Endpoint, Transport};
use crate::config::VmConfig;
use crate::host::{Accel, HostOs, VmmJob};
use crate::isolation::ProviderKind;
use crate::limits::proc_usage;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub struct QemuProvider {
    bin: String,
    extra_args: Vec<String>,
    /// The host this VM is shaped for (Linux keeps its exact command line).
    os: HostOs,
    accel: Accel,
    /// Guest architecture = the emulator's (`qemu-system-aarch64` → `aarch64`).
    arch: &'static str,
    /// UEFI firmware for `-M virt` (aarch64), if installed.
    firmware: Option<PathBuf>,
}

impl QemuProvider {
    pub fn new(cfg: &VmConfig) -> QemuProvider {
        let os = HostOs::current();
        let accel = match os {
            HostOs::Windows if crate::host::whpx_available() => Accel::Whpx,
            HostOs::Macos if crate::host::hvf_available() => Accel::Hvf,
            HostOs::Windows | HostOs::Macos => Accel::Tcg,
            _ => Accel::Kvm,
        };
        let arch = if cfg.qemu.contains("aarch64") { "aarch64" } else { "x86_64" };
        let firmware = if arch == "aarch64" { crate::host::find_tool(&cfg.qemu).and_then(|q| crate::host::edk2_aarch64(&q)) } else { None };
        QemuProvider { bin: cfg.qemu.clone(), extra_args: cfg.extra_args.clone(), os, accel, arch, firmware }
    }

    /// The provider as it would be shaped on `os` with `accel` (tests, `seagent sandbox explain`).
    pub fn for_host(cfg: &VmConfig, os: HostOs, accel: Accel, arch: &'static str, firmware: Option<PathBuf>) -> QemuProvider {
        QemuProvider { bin: cfg.qemu.clone(), extra_args: cfg.extra_args.clone(), os, accel, arch, firmware }
    }

    pub fn accel(&self) -> Accel {
        self.accel
    }

    /// `qemu-system-x86_64 …` for one spec. Split out so a test can assert the
    /// flags (no `-net`, channel socket, read-only kernel) without booting.
    pub fn cmdline(&self, spec: &VmSpec) -> Vec<String> {
        self.cmdline_with(spec, &Endpoint::Unix(spec.channel_path()), &Endpoint::Unix(spec.run_dir.join("mon.sock")))
    }

    /// [`Self::cmdline`] with the channel / monitor endpoints the VM will actually serve.
    pub fn cmdline_with(&self, spec: &VmSpec, chan: &Endpoint, mon: &Endpoint) -> Vec<String> {
        if self.os != HostOs::Linux && self.os != HostOs::Android {
            return self.cmdline_other(spec, chan, mon);
        }
        let mut a: Vec<String> = vec![
            "-M".into(),
            "q35".into(),
            "-accel".into(),
            "kvm".into(),
            "-cpu".into(),
            "host".into(),
            "-smp".into(),
            spec.vcpu.to_string(),
            "-m".into(),
            spec.mem_mb.to_string(),
            "-kernel".into(),
            spec.kernel.display().to_string(),
            "-initrd".into(),
            spec.initramfs.display().to_string(),
            "-append".into(),
            cmdline_append(spec),
            "-display".into(),
            "none".into(),
            "-nodefaults".into(),
            // Serial console goes to a file: boot logs stay available after the VM dies.
            "-serial".into(),
            format!("file:{}", spec.console_log().display()),
            "-pidfile".into(),
            spec.run_dir.join("vm.pid").display().to_string(),
            // Guest channel: one virtio-serial port.
            "-chardev".into(),
            chan.qemu_chardev("seagent0"),
            "-device".into(),
            "virtio-serial-pci".into(),
            "-device".into(),
            "virtserialport,chardev=seagent0,name=seagent0".into(),
            "-device".into(),
            "virtio-rng-pci".into(),
            // No NIC at all: the guest cannot reach the host or the internet.
            "-net".into(),
            "none".into(),
            "-no-reboot".into(),
            "-monitor".into(),
            mon.qemu_monitor(),
            // seccomp for the VMM itself (second layer: a QEMU bug cannot spawn
            // helpers or gain privileges).
            "-sandbox".into(),
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        ];
        a.extend(self.extra_args.iter().cloned());
        a
    }

    /// Windows (WHPX/TCG) and macOS (HVF/TCG): the same VM, the host's accelerator and machine.
    fn cmdline_other(&self, spec: &VmSpec, chan: &Endpoint, mon: &Endpoint) -> Vec<String> {
        let arm = self.arch == "aarch64";
        let accel = match self.accel {
            // WHPX's in-kernel irqchip is still unreliable for Linux guests; QEMU's own is not.
            Accel::Whpx => "whpx,kernel-irqchip=off".to_string(),
            a => a.name().to_string(),
        };
        let cpu = if self.accel == Accel::Hvf { "host" } else { "max" };
        let console = if arm { "ttyAMA0" } else { "ttyS0" };
        let mut a: Vec<String> = vec!["-M".into(), if arm { "virt,highmem=on".into() } else { "q35".into() }, "-accel".into(), accel, "-cpu".into(), cpu.into()];
        if let Some(fw) = self.firmware.as_ref().filter(|_| arm) {
            a.extend(["-bios".into(), fw.display().to_string()]);
        }
        a.extend([
            "-smp".into(),
            spec.vcpu.to_string(),
            "-m".into(),
            spec.mem_mb.to_string(),
            "-kernel".into(),
            spec.kernel.display().to_string(),
            "-initrd".into(),
            spec.initramfs.display().to_string(),
            "-append".into(),
            cmdline_append_on(spec, console),
            "-display".into(),
            "none".into(),
            "-nodefaults".into(),
            "-serial".into(),
            format!("file:{}", spec.console_log().display()),
            "-pidfile".into(),
            spec.run_dir.join("vm.pid").display().to_string(),
            "-chardev".into(),
            chan.qemu_chardev("seagent0"),
            "-device".into(),
            "virtio-serial-pci".into(),
            "-device".into(),
            "virtserialport,chardev=seagent0,name=seagent0".into(),
            "-device".into(),
            "virtio-rng-pci".into(),
            "-net".into(),
            "none".into(),
            "-no-reboot".into(),
            "-monitor".into(),
            mon.qemu_monitor(),
        ]);
        a.extend(self.extra_args.iter().cloned());
        a
    }
}

/// Kernel command line: init = the guest agent, which mounts /proc, /dev and
/// /tmp, drops to `agent` and only then talks on the channel.
pub fn cmdline_append(spec: &VmSpec) -> String {
    cmdline_append_on(spec, "ttyS0")
}

/// [`cmdline_append`] with another boot console (`ttyAMA0` on aarch64 `virt`, `hvc0` under
/// Virtualization.framework).
pub fn cmdline_append_on(spec: &VmSpec, console: &str) -> String {
    let ws = spec.workspace.as_ref().map(|w| w.guest.clone()).unwrap_or_else(|| crate::proto::GUEST_WORKSPACE.to_string());
    let mut s = format!(
        "console={console} quiet rdinit=/sbin/init seagent.vm={} seagent.tier={} seagent.channel={} seagent.workspace={} seagent.disk_mb={} seagent.nproc={}",
        spec.id,
        spec.tier,
        spec.transport.name(),
        ws,
        spec.limits.disk_mb,
        spec.limits.nproc
    );
    if let Some(w) = &spec.workspace {
        if w.read_only {
            s.push_str(" seagent.workspace_ro=1");
        }
    }
    s
}

impl VmProvider for QemuProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Qemu
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        let log = std::fs::File::create(spec.log()).map_err(|e| format!("create vm log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("clone log: {e}"))?;
        let qmp = spec.run_dir.join("mon.sock");
        // unix: the socket paths themselves (what Linux always passed); Windows: loopback
        // ports recorded in those paths.
        let (chan, mon) = if cfg!(unix) { (Endpoint::Unix(spec.channel_path()), Endpoint::Unix(qmp.clone())) } else { (Endpoint::allocate(&spec.channel_path())?, Endpoint::allocate(&qmp)?) };
        let mut child = crate::host::spawn_vmm(Command::new(&self.bin).args(self.cmdline_with(spec, &chan, &mon)).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(err)))
            .map_err(|e| format!("start {}: {e}", self.bin))?;
        let job = match VmmJob::confine(&child, spec.mem_mb, spec.vcpu) {
            Ok(j) => j,
            Err(e) => {
                crate::host::stop_vmm(&mut child);
                return Err(format!("qemu: cannot put the VMM under its resource ceiling: {e}"));
            }
        };
        // A VMM that dies immediately (no KVM, bad kernel) must fail here, not
        // when the first command hangs.
        for _ in 0..50 {
            if let Ok(Some(st)) = child.try_wait() {
                let tail = std::fs::read_to_string(spec.log()).unwrap_or_default();
                let _ = std::fs::remove_file(spec.channel_path());
                return Err(format!("qemu exited during boot ({}); log tail: {}", st, tail_tail(&tail)));
            }
            if spec.channel_path().exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Box::new(QemuInstance { spec: spec.clone(), child: Some(child), chan: None, qmp, _job: job }))
    }
}

fn tail_tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(6)..].join(" | ")
}

pub struct QemuInstance {
    spec: VmSpec,
    child: Option<Child>,
    chan: Option<Arc<Channel>>,
    qmp: PathBuf,
    /// Windows: the Job Object holding the VMM (dropped = VMM killed).
    _job: VmmJob,
}

impl QemuInstance {
    /// Send one QMP command (no greeting handling beyond the first line).
    fn qmp(&self, cmd: &str) -> Result<String, String> {
        use std::io::{Read, Write};
        let mut s = Endpoint::locate(&self.qmp).and_then(|e| e.connect()).map_err(|e| format!("qmp connect: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut buf = [0u8; 4096];
        let _greeting = s.read(&mut buf).map_err(|e| format!("qmp greeting: {e}"))?;
        s.write_all(format!("{{\"execute\":\"qmp_capabilities\"}}\n{{\"execute\":\"{cmd}\"}}\n").as_bytes()).map_err(|e| format!("qmp write: {e}"))?;
        let mut out = String::new();
        for _ in 0..4 {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if out.contains("\"return\"") || out.contains("\"error\"") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if out.contains("\"error\"") {
            return Err(format!("qmp {cmd}: {out}"));
        }
        Ok(out)
    }
}

impl VmInstance for QemuInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Qemu
    }
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let ch = Channel::connect(&self.spec.channel_path(), Transport::Serial, wait)?;
        let ch = Arc::new(ch);
        self.chan = Some(ch.clone());
        Ok(ch)
    }
    fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }
    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // Terminate the whole process group (qemu spawns no children under
            // -sandbox spawn=deny, but be thorough), then reap.
            crate::host::stop_vmm(&mut c);
        }
        for f in [self.spec.channel_path(), self.spec.run_dir.join("mon.sock"), self.spec.run_dir.join("vm.pid")] {
            let _ = std::fs::remove_file(f);
        }
    }
    fn usage(&self) -> VmUsage {
        match self.pid().and_then(proc_usage) {
            Some((ticks, rss)) => VmUsage { rss_kb: rss, cpu_ticks: ticks, uptime_secs: 0 },
            None => VmUsage::default(),
        }
    }
    fn pause(&mut self) -> Result<(), String> {
        self.qmp("stop").map(|_| ())
    }
    fn resume(&mut self) -> Result<(), String> {
        self.qmp("cont").map(|_| ())
    }
}

/// Is this QEMU usable for microVMs (KVM + the machine we generate)?
pub fn probe(bin: &Path) -> Result<String, String> {
    let out = Command::new(bin).arg("--version").stdout(Stdio::piped()).stderr(Stdio::piped()).output().map_err(|e| format!("{}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!("{} --version failed", bin.display()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("qemu").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::provider::Workspace;

    fn spec() -> VmSpec {
        VmSpec {
            id: "s-1".into(),
            tier: "owner".into(),
            kernel: "/img/vmlinux".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/run/vm/s-1".into(),
            vcpu: 2,
            mem_mb: 512,
            workspace: Some(Workspace { host: "/w".into(), guest: "/workspace".into(), read_only: false }),
            limits: Limits::default(),
            transport: Transport::Serial,
            firecracker: None,
            qemu: Some("/usr/bin/qemu-system-x86_64".into()),
            extra_args: vec![],
            guest_cid: 3,
        }
    }

    #[test]
    fn cmdline_is_isolating_by_construction() {
        let p = QemuProvider::new(&VmConfig::default());
        let a = p.cmdline(&spec());
        let joined = a.join(" ");
        if !cfg!(target_os = "linux") {
            return; // the Linux shape; the other hosts are pinned below
        }
        assert!(joined.contains("-accel kvm"), "hardware virtualisation, not TCG");
        assert!(joined.contains("-net none"), "no NIC: egress only through the broker");
        assert!(joined.contains("path=/run/vm/s-1/chan.sock"), "one channel socket");
        assert!(joined.contains("virtserialport,chardev=seagent0,name=seagent0"));
        assert!(joined.contains("-kernel /img/vmlinux") && joined.contains("-initrd /img/initramfs.cpio.gz"));
        assert!(joined.contains("-sandbox on,"), "seccomp around the VMM");
        assert!(joined.contains("-m 512") && joined.contains("-smp 2"));
        assert!(!joined.contains("-hda") && !joined.contains("-drive"), "no writable disk to leak into");
        // Nothing from the host is bind-mounted: the guest root is the initramfs.
        assert!(!joined.contains("/home"), "{joined}");
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn windows_and_macos_get_their_accelerator_and_keep_the_isolation_shape() {
        let cfg = VmConfig::default();
        let tcp = Endpoint::Tcp("127.0.0.1:40001".parse().unwrap());
        let mon = Endpoint::Tcp("127.0.0.1:40002".parse().unwrap());
        let win = QemuProvider::for_host(&cfg, HostOs::Windows, Accel::Whpx, "x86_64", None).cmdline_with(&spec(), &tcp, &mon).join(" ");
        assert!(win.contains("-accel whpx,kernel-irqchip=off") && win.contains("-cpu max") && win.contains("-M q35"), "{win}");
        assert!(win.contains("socket,id=seagent0,host=127.0.0.1,port=40001,server=on,wait=off") && win.contains("-monitor tcp:127.0.0.1:40002,server=on,wait=off"), "{win}");
        assert!(win.contains("-net none") && !win.contains("-drive") && !win.contains("-sandbox"), "same walls; no Linux-only seccomp flag: {win}");
        let tcg = QemuProvider::for_host(&cfg, HostOs::Windows, Accel::Tcg, "x86_64", None).cmdline_with(&spec(), &tcp, &mon).join(" ");
        assert!(tcg.contains("-accel tcg"), "{tcg}");
        let fw = PathBuf::from("/opt/homebrew/share/qemu/edk2-aarch64-code.fd");
        let mac = QemuProvider::for_host(&cfg, HostOs::Macos, Accel::Hvf, "aarch64", Some(fw.clone())).cmdline(&spec()).join(" ");
        assert!(mac.contains("-M virt,highmem=on -accel hvf -cpu host") && mac.contains(&format!("-bios {}", fw.display())), "{mac}");
        assert!(mac.contains("console=ttyAMA0") && mac.contains("path=/run/vm/s-1/chan.sock"), "PL011 console, unix sockets on macOS: {mac}");
        let intel = QemuProvider::for_host(&cfg, HostOs::Macos, Accel::Hvf, "x86_64", None).cmdline(&spec()).join(" ");
        assert!(intel.contains("-M q35 -accel hvf -cpu host") && intel.contains("console=ttyS0") && !intel.contains("-bios"), "{intel}");
    }

    #[test]
    fn append_line_carries_tier_and_limits() {
        let mut s = spec();
        s.workspace.as_mut().unwrap().read_only = true;
        s.limits.nproc = 128;
        let c = cmdline_append(&s);
        assert!(c.contains("seagent.tier=owner"), "{c}");
        assert!(c.contains("seagent.channel=virtio-serial"));
        assert!(c.contains("seagent.workspace_ro=1"), "B2: a read-only workspace is carried into the guest");
        assert!(c.contains("seagent.nproc=128"));
        assert!(c.contains("rdinit=/sbin/init"), "init is the agent, nothing else");
    }
}
