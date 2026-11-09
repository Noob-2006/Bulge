//! Apple Virtualization.framework provider (macOS), driven through `vfkit`.
//!
//! The agent binary may not link Swift/Objective-C, so the framework is reached through a
//! small, separately installed helper: `vfkit` (Apache-2.0, github.com/crc-org/vfkit,
//! `brew install vfkit`), the CLI podman machine and CRC use. What it gives the guest is the
//! same shape as Firecracker:
//!
//! * `--bootloader linux,kernel=…,initrd=…,cmdline="…"` — a direct kernel boot of the image
//!   from `packaging/vm`; the initramfs is the root, no disk device at all (B2);
//! * no `virtio-net` device: the broker on the channel is the only way out (A3);
//! * `--device virtio-vsock,port=5000,socketURL=<run>/vsock.sock,listen` — vfkit listens on
//!   the unix socket and connects each host connection to the guest's vsock port, so the guest
//!   agent's AF_VSOCK listener is reached exactly as under Firecracker, minus the `CONNECT`
//!   preface ([`Transport::VsockProxy`]);
//! * `--device virtio-serial,logFilePath=<run>/console.log` — the boot console (`hvc0`);
//! * `--restful-uri unix://<run>/vfkit.sock` — pause / resume / stop through vfkit's REST API.
//!
//! The guest must be an **arm64** build on Apple Silicon (Virtualization.framework runs only
//! same-architecture guests) with virtio-PCI + vsock in the kernel: the x86_64 Firecracker CI
//! kernel in `packaging/vm` boots on neither. vfkit has no memory snapshot; workspace
//! snapshots remain the undo point.

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Stream, Transport};
use crate::config::VmConfig;
use crate::isolation::ProviderKind;
use crate::limits::proc_usage;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct VfkitProvider {
    bin: String,
}

impl VfkitProvider {
    pub fn new(cfg: &VmConfig) -> VfkitProvider {
        VfkitProvider { bin: cfg.vfkit.clone() }
    }

    /// `vfkit …` for one spec (pure, so the shape is tested without a Mac).
    pub fn cmdline(&self, spec: &VmSpec) -> Vec<String> {
        let port = match spec.transport {
            Transport::VsockProxy { port } | Transport::Vsock { port } => port,
            _ => crate::proto::VSOCK_PORT,
        };
        let append = super::qemu::cmdline_append_on(spec, "hvc0");
        vec![
            "--cpus".into(),
            spec.vcpu.to_string(),
            "--memory".into(),
            spec.mem_mb.to_string(),
            "--bootloader".into(),
            format!("linux,kernel={},initrd={},cmdline=\"{append}\"", spec.kernel.display(), spec.initramfs.display()),
            "--device".into(),
            format!("virtio-vsock,port={port},socketURL={},listen", vsock_sock(spec).display()),
            "--device".into(),
            format!("virtio-serial,logFilePath={}", spec.console_log().display()),
            "--device".into(),
            "virtio-rng".into(),
            "--restful-uri".into(),
            format!("unix://{}", rest_sock(spec).display()),
        ]
    }
}

fn vsock_sock(spec: &VmSpec) -> PathBuf {
    spec.run_dir.join("vsock.sock")
}
fn rest_sock(spec: &VmSpec) -> PathBuf {
    spec.run_dir.join("vfkit.sock")
}

impl VmProvider for VfkitProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Vfkit
    }
    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        if !cfg!(target_os = "macos") {
            return Err("vfkit drives Apple Virtualization.framework, which exists on macOS only".into());
        }
        let bin = crate::host::find_tool(&self.bin).ok_or_else(|| format!("`{}` not found: install it with `brew install vfkit` (Apple Virtualization.framework CLI) or use exec.vm.provider = \"qemu\"", self.bin))?;
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        for f in [vsock_sock(spec), rest_sock(spec)] {
            let _ = std::fs::remove_file(f);
        }
        let log = std::fs::File::create(spec.log()).map_err(|e| format!("create vm log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("clone log: {e}"))?;
        let mut child = crate::host::spawn_vmm(Command::new(&bin).args(self.cmdline(spec)).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(err))).map_err(|e| format!("start {}: {e}", bin.display()))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !vsock_sock(spec).exists() {
            if let Ok(Some(st)) = child.try_wait() {
                return Err(format!("vfkit exited during boot ({st}); log: {}", std::fs::read_to_string(spec.log()).unwrap_or_default().trim()));
            }
            if Instant::now() >= deadline {
                crate::host::stop_vmm(&mut child);
                return Err("vfkit did not create its vsock socket within 10s".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Box::new(VfkitInstance { spec: spec.clone(), child: Some(child), chan: None }))
    }
}

pub struct VfkitInstance {
    spec: VmSpec,
    child: Option<Child>,
    chan: Option<Arc<Channel>>,
}

impl VfkitInstance {
    /// `POST /vm/state {"state": …}` on vfkit's REST socket (`Pause`, `Resume`, `Stop`).
    fn set_state(&self, state: &str) -> Result<(), String> {
        let body = format!("{{\"state\":\"{state}\"}}");
        let mut s = Stream::connect_unix(&rest_sock(&self.spec)).map_err(|e| format!("vfkit REST socket: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let req = format!("POST /vm/state HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        s.write_all(req.as_bytes()).map_err(|e| format!("vfkit REST: {e}"))?;
        let mut reply = String::new();
        let _ = s.read_to_string(&mut reply);
        let status = reply.split_whitespace().nth(1).unwrap_or("");
        if status.starts_with('2') {
            Ok(())
        } else {
            Err(format!("vfkit {state}: {}", reply.lines().next().unwrap_or("no reply")))
        }
    }
}

impl VmInstance for VfkitInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Vfkit
    }
    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }
    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let ch = Arc::new(Channel::connect(&vsock_sock(&self.spec), Transport::VsockProxy { port: crate::proto::VSOCK_PORT }, wait)?);
        self.chan = Some(ch.clone());
        Ok(ch)
    }
    fn is_running(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }
    fn stop(&mut self) {
        self.chan = None;
        if let Some(mut c) = self.child.take() {
            let _ = self.set_state("Stop");
            crate::host::stop_vmm(&mut c);
        }
        for f in [vsock_sock(&self.spec), rest_sock(&self.spec)] {
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
        self.set_state("Pause")
    }
    fn resume(&mut self) -> Result<(), String> {
        self.set_state("Resume")
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
    use crate::limits::Limits;

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn vfkit_boots_the_kernel_directly_with_vsock_and_no_network() {
        let spec = VmSpec {
            id: "m-1".into(),
            tier: "owner".into(),
            kernel: "/img/Image".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/r/m-1".into(),
            vcpu: 2,
            mem_mb: 1024,
            workspace: None,
            limits: Limits::default(),
            transport: crate::provider::transport_for(ProviderKind::Vfkit),
            firecracker: None,
            qemu: None,
            extra_args: vec![],
            guest_cid: 3,
        };
        let a = VfkitProvider::new(&VmConfig::default()).cmdline(&spec).join(" ");
        assert!(a.contains("--cpus 2 --memory 1024"), "{a}");
        assert!(a.contains("--bootloader linux,kernel=/img/Image,initrd=/img/initramfs.cpio.gz,cmdline=\"console=hvc0 "), "{a}");
        assert!(a.contains("seagent.channel=vsock"), "the guest listens on AF_VSOCK: {a}");
        assert!(a.contains("virtio-vsock,port=5000,socketURL=/r/m-1/vsock.sock,listen"), "{a}");
        assert!(!a.contains("virtio-net") && !a.contains("virtio-blk") && !a.contains("virtio-fs"), "no NIC, no disk, no host share: {a}");
    }
}
