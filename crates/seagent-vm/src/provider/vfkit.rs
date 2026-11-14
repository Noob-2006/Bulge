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
//! * `--device virtio-vsock,port=5000,socketURL=<run>/vsock.sock,connect` — vfkit listens on
//!   the unix socket and connects each host connection to the guest's vsock port, so the guest
//!   agent's AF_VSOCK listener is reached exactly as under Firecracker, minus the `CONNECT`
//!   preface ([`Transport::VsockProxy`]). vfkit's naming is from the guest's side: `connect`
//!   (host → guest) is what we need; `listen` (guest → host) never creates the host socket,
//!   and it is vfkit's default, so `connect` must be spelled out;
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
use std::process::{Child, Stdio};
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
            format!("virtio-vsock,port={port},socketURL={},connect", vsock_sock(spec).display()),
            "--device".into(),
            format!("virtio-serial,logFilePath={}", spec.console_log().display()),
            "--device".into(),
            "virtio-rng".into(),
            "--restful-uri".into(),
            format!("unix://{}", rest_sock(spec).display()),
        ]
    }
}

/// The host end of the vsock proxy. vfkit binds it at `url.EscapedPath()` of `socketURL`, so a
/// path with a byte URL-escaping changes (the space in macOS's `~/Library/Application Support`,
/// where the per-user run directory lives) is bound at a `%20` path that does not exist. Such a
/// run directory gets its socket in a private per-VM directory under `~/Library/Caches/seagent`
/// (no space, and not swept like `$TMPDIR`, whose files macOS deletes after 3 days unused — a
/// long-running VM would lose its socket). macOS account names cannot contain a space, so the
/// home directory itself is safe. Only the socket moves: logs and the console stay in the run
/// directory.
fn vsock_sock(spec: &VmSpec) -> PathBuf {
    let p = spec.run_dir.join("vsock.sock");
    if socket_path_ok(&p) {
        return p;
    }
    let id: String = spec.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Caches/seagent/vfkit").join(id).join("vsock.sock")).unwrap_or(p)
}
/// Every byte survives Go's `url.EscapedPath()` unchanged (RFC 3986 unreserved + `/`), and the
/// path fits `sockaddr_un.sun_path` (104 bytes on macOS, NUL included).
fn socket_path_ok(p: &std::path::Path) -> bool {
    p.to_str().is_some_and(|s| s.len() < 104 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b)))
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
        if let Some(dir) = vsock_sock(spec).parent().filter(|d| *d != spec.run_dir) {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod {}: {e}", dir.display()))?;
            }
        }
        for f in [vsock_sock(spec), rest_sock(spec)] {
            let _ = std::fs::remove_file(f);
        }
        let log = std::fs::File::create(spec.log()).map_err(|e| format!("create vm log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("clone log: {e}"))?;
        let mut child = crate::host::spawn_vmm(crate::host::command(&bin).args(self.cmdline(spec)).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(err))).map_err(|e| format!("start {}: {e}", bin.display()))?;
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
        if let Some(dir) = vsock_sock(&self.spec).parent().filter(|d| *d != self.spec.run_dir) {
            let _ = std::fs::remove_dir(dir);
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
        assert!(a.contains("virtio-vsock,port=5000,socketURL=/r/m-1/vsock.sock,connect"), "host → guest is vfkit's `connect`: {a}");
        assert!(!a.contains("virtio-net") && !a.contains("virtio-blk") && !a.contains("virtio-fs"), "no NIC, no disk, no host share: {a}");
    }

    #[cfg(unix)]
    #[test]
    fn vfkit_vsock_socket_avoids_paths_vfkit_would_url_escape() {
        let mut spec = VmSpec {
            id: "s-main-1".into(),
            tier: "owner".into(),
            kernel: "/img/Image".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/Users/u/Library/Application Support/seagent/data/vm/run/s-main-1".into(),
            vcpu: 1,
            mem_mb: 512,
            workspace: None,
            limits: Limits::default(),
            transport: crate::provider::transport_for(ProviderKind::Vfkit),
            firecracker: None,
            qemu: None,
            extra_args: vec![],
            guest_cid: 3,
        };
        let p = vsock_sock(&spec);
        assert!(socket_path_ok(&p), "vfkit binds EscapedPath(): {}", p.display());
        assert!(p.ends_with("Library/Caches/seagent/vfkit/s-main-1/vsock.sock"), "per-VM directory in Caches: {}", p.display());
        spec.run_dir = "/r/s-main-1".into();
        assert_eq!(vsock_sock(&spec), PathBuf::from("/r/s-main-1/vsock.sock"), "a safe run dir keeps the socket");
    }
}
