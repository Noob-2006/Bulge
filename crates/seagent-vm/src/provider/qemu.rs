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

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Transport};
use crate::config::VmConfig;
use crate::isolation::ProviderKind;
use crate::limits::proc_usage;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub struct QemuProvider {
    bin: String,
    extra_args: Vec<String>,
}

impl QemuProvider {
    pub fn new(cfg: &VmConfig) -> QemuProvider {
        QemuProvider { bin: cfg.qemu.clone(), extra_args: cfg.extra_args.clone() }
    }
    /// `qemu-system-x86_64 …` for one spec. Split out so a test can assert the
    /// flags (no `-net`, channel socket, read-only kernel) without booting.
    pub fn cmdline(&self, spec: &VmSpec) -> Vec<String> {
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
            format!("socket,id=seagent0,path={},server=on,wait=off", spec.channel_path().display()),
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
            format!("unix:{},server=on,wait=off", spec.run_dir.join("mon.sock").display()),
            // seccomp for the VMM itself (second layer: a QEMU bug cannot spawn
            // helpers or gain privileges).
            "-sandbox".into(),
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        ];
        a.extend(self.extra_args.iter().cloned());
        a
    }
}

/// Kernel command line: init = the guest agent, which mounts /proc, /dev and
/// /tmp, drops to `agent` and only then talks on the channel.
pub fn cmdline_append(spec: &VmSpec) -> String {
    let ws = spec.workspace.as_ref().map(|w| w.guest.clone()).unwrap_or_else(|| crate::proto::GUEST_WORKSPACE.to_string());
    let mut s = format!(
        "console=ttyS0 quiet rdinit=/sbin/init seagent.vm={} seagent.tier={} seagent.channel={} seagent.workspace={} seagent.disk_mb={} seagent.nproc={}",
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
        let mut child = Command::new(&self.bin)
            .args(self.cmdline(spec))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .process_group(0)
            .spawn()
            .map_err(|e| format!("start {}: {e}", self.bin))?;
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
        Ok(Box::new(QemuInstance { spec: spec.clone(), child: Some(child), chan: None, qmp: spec.run_dir.join("mon.sock") }))
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
}

impl QemuInstance {
    /// Send one QMP command (no greeting handling beyond the first line).
    fn qmp(&self, cmd: &str) -> Result<String, String> {
        use std::io::{Read, Write};
        let mut s = std::os::unix::net::UnixStream::connect(&self.qmp).map_err(|e| format!("qmp connect: {e}"))?;
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
            // SAFETY: we own this process group (process_group(0) at spawn).
            unsafe { libc::kill(-(c.id() as i32), libc::SIGTERM) };
            for _ in 0..50 {
                if matches!(c.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if matches!(c.try_wait(), Ok(None)) {
                // SAFETY: as above; only our own child group.
                unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
                let _ = c.wait();
            }
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

    #[test]
    fn append_line_carries_tier_and_limits() {
        let mut s = spec();
        s.workspace.as_mut().unwrap().read_only = true;
        s.limits.nproc = 128;
        let c = cmdline_append(&s);
        assert!(c.contains("seagent.tier=owner"), "{c}");
        assert!(c.contains("seagent.channel=virtio-serial"));
        assert!(c.contains("seagent.workspace_ro=1"), "B2: a read-only workspace is enforced in the guest");
        assert!(c.contains("seagent.nproc=128"));
        assert!(c.contains("rdinit=/sbin/init"), "init is the agent, nothing else");
    }
}
