//! Firecracker provider: one microVM per `VmSpec`, driven entirely through the
//! Firecracker REST API on a unix socket (`<run_dir>/fc.sock`).
//!
//! Shape of the VM (same design target as the QEMU provider, different VMM):
//! * `kernel_image_path` = the guest kernel, `initrd_path` = the initramfs from
//!   `packaging/vm/build-image.sh`; **the initramfs is the guest root** (B2), so
//!   there is no `PUT /drives` at all — nothing writable exists to corrupt and
//!   the guest cannot see a host block device;
//! * `boot_args` comes from [`super::qemu::cmdline_append`], so both providers
//!   hand the guest agent the same `seagent.*` facts (`tier`, `channel`,
//!   `workspace`, limits) and the agent cannot be confused about which VM or
//!   which trust tier it is;
//! * no NIC is ever configured, so the only route out of the guest is the
//!   broker request on the channel (A3);
//! * the channel is vsock: Firecracker owns `<run_dir>/vsock.sock`, the guest
//!   listens on AF_VSOCK [`crate::proto::VSOCK_PORT`] and [`Channel::connect`]
//!   does the `CONNECT <port>\n` preface.
//!
//! The API client is a ~50-line blocking HTTP/1.1 writer/reader over
//! `UnixStream` (no new crates; the API is one request per connection with
//! `Connection: close`). It is exposed as [`Api`] and [`configure`] so the wire
//! format — endpoint order, bodies, error handling — is testable without KVM,
//! a kernel image or even the Firecracker binary (`tests/firecracker_api.rs`).
//!
//! Snapshot/restore uses the real API (`PUT /snapshot/create`,
//! `PUT /snapshot/load`); see [`FirecrackerInstance::ram_snapshot`] for the
//! pause/resume behaviour Firecracker imposes.

use super::{VmInstance, VmProvider, VmSpec, VmUsage};
use crate::channel::{Channel, Transport};
use crate::config::VmConfig;
use crate::isolation::ProviderKind;
use crate::limits::proc_usage;
use crate::proto;
use serde_json::{json, Value};
use crate::channel::Stream;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Socket the Firecracker API listens on, inside the VM's run dir.
const API_SOCK: &str = "fc.sock";
/// Socket Firecracker creates for the guest vsock device.
const VSOCK_SOCK: &str = "vsock.sock";
/// How long the VMM gets to create its API socket before `start` fails.
const API_WAIT: Duration = Duration::from_secs(5);
/// Per-request timeout for the API socket (a full snapshot of a 1 GiB guest is
/// the slow case, so this is generous compared to an ordinary `PUT`).
const API_TIMEOUT: Duration = Duration::from_secs(30);
/// AWS's reserved CIDs are 0-2; 3 is the first guest CID and Firecracker's
/// conventional default.
pub const DEFAULT_GUEST_CID: u32 = 3;

/// The guest command line under Firecracker: the one QEMU uses ([`super::qemu::cmdline_append`])
/// plus `reboot=k`. The agent ends a VM by resetting it (Firecracker has no ACPI power-off
/// device) and Firecracker exits only on the i8042 keyboard-controller reset; a kernel built with
/// ACPI tries the FADT reset register first, which Firecracker ignores, and the VM then lingers
/// until the host kills it (measured: 15 s per VM with the source-built 6.12 kernel).
pub fn boot_args(spec: &VmSpec) -> String {
    format!("{} reboot=k", super::qemu::cmdline_append(spec))
}

pub struct FirecrackerProvider {
    bin: PathBuf,
    extra_args: Vec<String>,
    guest_cid: u32,
}

impl FirecrackerProvider {
    pub fn new(cfg: &VmConfig) -> FirecrackerProvider {
        FirecrackerProvider { bin: PathBuf::from(&cfg.firecracker), extra_args: cfg.extra_args.clone(), guest_cid: cfg.guest_cid }
    }

    /// `firecracker --api-sock … --id …` for one spec. Split out so a test can
    /// assert the flags without booting (mirrors `QemuProvider::cmdline`).
    pub fn cmdline(&self, spec: &VmSpec) -> Vec<String> {
        let mut a: Vec<String> = vec!["--api-sock".into(), api_sock(&spec.run_dir).display().to_string(), "--id".into(), spec.id.clone()];
        a.extend(self.extra_args.iter().cloned());
        a
    }

    /// The binary for this VM: a per-spec override wins over `exec.vm.firecracker`.
    fn bin_for(&self, spec: &VmSpec) -> PathBuf {
        spec.firecracker.clone().unwrap_or_else(|| self.bin.clone())
    }
}

impl VmProvider for FirecrackerProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Firecracker
    }

    fn start(&self, spec: &VmSpec) -> Result<Box<dyn VmInstance>, String> {
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("create {}: {e}", spec.run_dir.display()))?;
        let api = api_sock(&spec.run_dir);
        let vsock = vsock_sock(&spec.run_dir);
        // A socket file left behind by a previous VM with the same id would make
        // the API client connect to nothing (or to the wrong VMM).
        let _ = std::fs::remove_file(&api);
        let _ = std::fs::remove_file(&vsock);

        let log = std::fs::File::create(spec.log()).map_err(|e| format!("create vm log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("clone log: {e}"))?;
        let bin = self.bin_for(spec);
        let mut child = crate::host::spawn_vmm(crate::host::command(&bin).args(self.cmdline(spec)).stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(err)))
            .map_err(|e| format!("start {}: {e}", bin.display()))?;

        // Fail here, not when the first command hangs: a VMM without /dev/kvm,
        // with a bad kernel or with an unparsable flag dies immediately.
        let deadline = Instant::now() + API_WAIT;
        loop {
            if let Ok(Some(st)) = child.try_wait() {
                let _ = std::fs::remove_file(&api);
                let _ = std::fs::remove_file(&vsock);
                return Err(format!("firecracker exited during boot ({st}); log tail: {}", log_tail(&spec.log())));
            }
            // Probe with a real connection: the socket file may exist a moment
            // before the API is listening (and a stale one must not count).
            if Stream::connect_unix(&api).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                kill_group(&mut child);
                let _ = std::fs::remove_file(&api);
                let _ = std::fs::remove_file(&vsock);
                return Err(format!("firecracker did not accept connections on {} within {}s; log tail: {}", api.display(), API_WAIT.as_secs(), log_tail(&spec.log())));
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        // Boot: boot-source -> machine-config -> vsock -> actions. Any error is
        // the API's own words plus the VMM log, and the process is not left
        // running behind a half-configured VM.
        let cid = cid_or(spec.guest_cid, self.guest_cid);
        if let Err(e) = configure_with(&api, &boot_requests(spec, cid)) {
            kill_group(&mut child);
            let _ = std::fs::remove_file(&api);
            let _ = std::fs::remove_file(&vsock);
            return Err(format!("{e}; log tail: {}", log_tail(&spec.log())));
        }

        Ok(Box::new(FirecrackerInstance { spec: spec.clone(), child: Some(child), api, chan: None }))
    }
}

fn api_sock(run_dir: &Path) -> PathBuf {
    run_dir.join(API_SOCK)
}

fn vsock_sock(run_dir: &Path) -> PathBuf {
    run_dir.join(VSOCK_SOCK)
}

/// Open one owned [`Channel`] to a booted VM over vsock (`Channel::connect`
/// performs the `CONNECT <port>\n` preface for us).
///
/// This is the body of [`VmInstance::connect`] without the caching: callers that
/// must *drive* the channel (it needs `&mut self`) need ownership, which the
/// trait's `Arc<Channel>` cannot give them while the instance keeps its copy.
pub fn connect_channel(run_dir: &Path, wait: Duration) -> Result<Channel, String> {
    Channel::connect(&vsock_sock(run_dir), Transport::Vsock { port: proto::VSOCK_PORT }, wait)
}

/// Guest CID: the spec's unless it is unset/too low (0-2 are reserved), in which
/// case the configured default, and finally Firecracker's own 3.
fn cid_or(spec_cid: u32, fallback: u32) -> u32 {
    if spec_cid >= DEFAULT_GUEST_CID {
        spec_cid
    } else if fallback >= DEFAULT_GUEST_CID {
        fallback
    } else {
        DEFAULT_GUEST_CID
    }
}

/// The requests that turn a bare Firecracker process into a booting guest, in
/// order and fully built: `(method, path, body)`.
///
/// Deliberately public and side-effect free: the exact wire format (and the
/// absence of a `/drives` call) is what `tests/firecracker_api.rs` asserts.
pub fn boot_requests(spec: &VmSpec, guest_cid: u32) -> Vec<(String, String, Value)> {
    let mut boot: serde_json::Map<String, Value> = serde_json::Map::new();
    boot.insert("kernel_image_path".into(), Value::String(spec.kernel.display().to_string()));
    if !spec.initramfs.as_os_str().is_empty() {
        // The initramfs *is* the guest root (B2): immutable, no block device.
        boot.insert("initrd_path".into(), Value::String(spec.initramfs.display().to_string()));
    }
    boot.insert("boot_args".into(), Value::String(boot_args(spec)));
    vec![
        ("PUT".into(), "/boot-source".into(), Value::Object(boot)),
        ("PUT".into(), "/machine-config".into(), json!({ "vcpu_count": spec.vcpu, "mem_size_mib": spec.mem_mb, "smt": false })),
        ("PUT".into(), "/vsock".into(), json!({ "guest_cid": guest_cid, "uds_path": vsock_sock(&spec.run_dir).display().to_string() })),
        // Last: everything above must be in place before the instance exists.
        ("PUT".into(), "/actions".into(), json!({ "action_type": "InstanceStart" })),
    ]
}

/// Configure a *running* API socket for `spec` and boot it. Returns the
/// requests it sent, so a caller (or a test) can see exactly what went out.
pub fn configure(api: &Path, spec: &VmSpec) -> Result<Vec<(String, String, Value)>, String> {
    configure_with(api, &boot_requests(spec, cid_or(spec.guest_cid, DEFAULT_GUEST_CID)))
}

fn configure_with(api: &Path, reqs: &[(String, String, Value)]) -> Result<Vec<(String, String, Value)>, String> {
    let client = Api::new(api);
    for (method, path, body) in reqs {
        client.call(method, path, body)?;
    }
    Ok(reqs.to_vec())
}

/// `PUT /snapshot/create` body: a full snapshot = guest RAM + device state.
pub fn snapshot_create_body(snapshot: &Path, mem: &Path) -> Value {
    json!({
        "snapshot_type": "Full",
        "snapshot_path": snapshot.display().to_string(),
        "mem_file_path": mem.display().to_string(),
    })
}

/// `PUT /snapshot/load` body (Firecracker >= 1.0 takes a `mem_backend` object).
pub fn snapshot_load_body(snapshot: &Path, mem: &Path) -> Value {
    json!({
        "snapshot_path": snapshot.display().to_string(),
        "mem_backend": { "backend_path": mem.display().to_string(), "backend_type": "File" },
        "resume_vm": true,
    })
}

/// Minimal blocking HTTP/1.1 client for the Firecracker API socket.
///
/// One request per connection (`Connection: close`), which is all the API
/// needs and keeps the code free of keep-alive state. Every non-2xx status is
/// an `Err` carrying the API's response body — that is where Firecracker puts
/// the reason (`{"fault_message": …}`).
#[derive(Debug, Clone)]
pub struct Api {
    sock: PathBuf,
}

impl Api {
    pub fn new(sock: &Path) -> Api {
        Api { sock: sock.to_path_buf() }
    }

    pub fn path(&self) -> &Path {
        &self.sock
    }

    pub fn put(&self, path: &str, body: &Value) -> Result<(), String> {
        self.call("PUT", path, body)
    }

    pub fn patch(&self, path: &str, body: &Value) -> Result<(), String> {
        self.call("PATCH", path, body)
    }

    /// Send one request and check the status. 200/204 are the only successes
    /// the API produces for the calls this provider makes.
    pub fn call(&self, method: &str, path: &str, body: &Value) -> Result<(), String> {
        let body = body.to_string();
        let mut s = Stream::connect_unix(&self.sock).map_err(|e| format!("firecracker api {method} {path}: connect {}: {e}", self.sock.display()))?;
        s.set_read_timeout(Some(API_TIMEOUT)).ok();
        s.set_write_timeout(Some(API_TIMEOUT)).ok();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).map_err(|e| format!("firecracker api {method} {path}: write: {e}"))?;
        s.flush().map_err(|e| format!("firecracker api {method} {path}: flush: {e}"))?;
        let raw = read_reply(&mut s).map_err(|e| format!("firecracker api {method} {path}: {e}"))?;
        let (status, text) = split_reply(&raw).map_err(|e| format!("firecracker api {method} {path}: {e}"))?;
        match status {
            200 | 204 => Ok(()),
            _ => Err(format!("firecracker api {method} {path}: HTTP {status}: {}", text.trim())),
        }
    }
}

/// Read one HTTP reply: until the body announced by `Content-Length` is in, or
/// the peer closes, or the read times out (a server that ignores
/// `Connection: close`).
fn read_reply(s: &mut Stream) -> Result<Vec<u8>, String> {
    const MAX_REPLY: usize = 1 << 20;
    let mut raw = Vec::new();
    let mut want: Option<usize> = None;
    let mut chunk = [0u8; 8192];
    loop {
        if matches!(want, Some(w) if raw.len() >= w) {
            break;
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_REPLY {
                    return Err("reply too large".into());
                }
                if want.is_none() {
                    if let Some(i) = find_double_crlf(&raw) {
                        let head = String::from_utf8_lossy(&raw[..i]);
                        // `204 No Content` (what Firecracker answers for a
                        // successful PUT) has no body and no Content-Length:
                        // the header block is the whole reply. Waiting for a
                        // body that never comes is what made every API call
                        // cost a full API_TIMEOUT (4 calls = 2 minutes of
                        // "boot" for a 200 ms VM).
                        want = Some(i + 4 + content_length(&head).unwrap_or(0));
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    if raw.is_empty() {
        return Err("empty reply (is this a Firecracker API socket?)".into());
    }
    Ok(raw)
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

/// `(status code, body)` from a raw reply.
fn split_reply(raw: &[u8]) -> Result<(u16, String), String> {
    let sep = find_double_crlf(raw).ok_or_else(|| format!("malformed reply: {:?}", String::from_utf8_lossy(&raw[..raw.len().min(120)])))?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed status line: {:?}", head.lines().next().unwrap_or("")))?;
    Ok((status, String::from_utf8_lossy(&raw[sep + 4..]).to_string()))
}

fn log_tail(path: &Path) -> String {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return "(empty)".into();
    }
    lines[lines.len().saturating_sub(6)..].join(" | ")
}

/// SIGTERM the VM's process group, wait, then SIGKILL ([`crate::host::stop_vmm`]).
fn kill_group(child: &mut Child) {
    crate::host::stop_vmm(child)
}

pub struct FirecrackerInstance {
    spec: VmSpec,
    child: Option<Child>,
    /// `<run_dir>/fc.sock`.
    api: PathBuf,
    chan: Option<Arc<Channel>>,
}

impl FirecrackerInstance {
    fn api_client(&self) -> Api {
        Api::new(&self.api)
    }

    /// `<run_dir>/vsock.sock` — Firecracker's guest vsock endpoint.
    fn vsock(&self) -> PathBuf {
        vsock_sock(&self.spec.run_dir)
    }

    /// `PATCH /vm {"state": …}` — the only pause/resume Firecracker offers.
    fn set_state(&self, state: &str) -> Result<(), String> {
        if !self.api.exists() {
            return Err(format!("firecracker API socket {} is gone: the VM is not running", self.api.display()));
        }
        self.api_client().patch("/vm", &json!({ "state": state }))
    }
}

impl VmInstance for FirecrackerInstance {
    fn id(&self) -> &str {
        &self.spec.id
    }

    fn kind(&self) -> ProviderKind {
        ProviderKind::Firecracker
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    fn connect(&mut self, wait: Duration) -> Result<Arc<Channel>, String> {
        if let Some(c) = &self.chan {
            return Ok(c.clone());
        }
        let ch = Arc::new(connect_channel(&self.spec.run_dir, wait)?);
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
        self.chan = None;
        if let Some(mut c) = self.child.take() {
            kill_group(&mut c);
        }
        for f in [self.api.clone(), self.vsock()] {
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
        self.set_state("Paused")
    }

    fn resume(&mut self) -> Result<(), String> {
        self.set_state("Resumed")
    }

    /// `PUT /snapshot/create` with `snapshot_type: Full` (guest RAM + device
    /// state) into `dir/snap.fc` + `dir/mem.fc`.
    ///
    /// Firecracker pauses the VM while it writes the image; this resumes it
    /// again so an undo point does not silently freeze the session. If the VM
    /// was deliberately paused, pause it again after snapshotting.
    fn ram_snapshot(&mut self, dir: &Path) -> Result<Option<PathBuf>, String> {
        if !self.is_running() {
            return Err(format!("cannot snapshot {}: firecracker is not running", self.spec.id));
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("create snapshot dir {}: {e}", dir.display()))?;
        let snap = dir.join("snap.fc");
        let mem = dir.join("mem.fc");
        // A previous image at the same path must not be mistaken for this one.
        let _ = std::fs::remove_file(&snap);
        let _ = std::fs::remove_file(&mem);
        let api = self.api_client();
        api.put("/snapshot/create", &snapshot_create_body(&snap, &mem))?;
        api.patch("/vm", &json!({ "state": "Resumed" })).map_err(|e| format!("snapshot written but the VM did not resume: {e}"))?;
        Ok(Some(snap))
    }

    /// `PUT /snapshot/load … resume_vm: true`, then reconnect the channel.
    ///
    /// Firecracker loads a snapshot into a VMM that has not started an instance
    /// yet, so the pool must have a fresh `firecracker --api-sock` running (spawn
    /// it as `start` does, then call this instead of the boot sequence). If the
    /// API socket is gone the error says so rather than reporting a confusing
    /// connect failure.
    fn ram_restore(&mut self, dir: &Path) -> Result<(), String> {
        let snap = dir.join("snap.fc");
        let mem = dir.join("mem.fc");
        if !snap.exists() || !mem.exists() {
            return Err(format!(
                "no Firecracker memory snapshot in {} (expected {} and {})",
                dir.display(),
                snap.display(),
                mem.display()
            ));
        }
        if !self.api.exists() {
            return Err(format!(
                "the Firecracker API socket {} is gone: the VMM for {} is not running, so the snapshot cannot be loaded (restart the VM, then restore)",
                self.api.display(),
                self.spec.id
            ));
        }
        self.api_client().put("/snapshot/load", &snapshot_load_body(&snap, &mem))?;
        // The restored vsock device re-creates the host socket; the cached
        // Channel still points at the pre-restore guest, so it must go.
        self.chan = None;
        let _ = self
            .connect(Duration::from_secs(5))
            .map_err(|e| format!("snapshot loaded but the guest channel did not come back: {e}"))?;
        Ok(())
    }
}

/// `firecracker --version` — is this binary a usable VMM? Mirrors
/// `qemu::probe`.
pub fn probe(bin: &Path) -> Result<String, String> {
    let out = crate::host::command(bin).arg("--version").stdout(Stdio::piped()).stderr(Stdio::piped()).output().map_err(|e| format!("{}: {e}", bin.display()))?;
    if !out.status.success() {
        return Err(format!("{} --version failed", bin.display()));
    }
    let line = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("firecracker").to_string();
    if line.trim().is_empty() {
        return Ok("firecracker".into());
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::provider::Workspace;

    #[cfg_attr(not(unix), allow(dead_code))] // its users are unix-only tests
    fn spec() -> VmSpec {
        VmSpec {
            id: "fc-1".into(),
            tier: "stranger".into(),
            kernel: "/img/vmlinux".into(),
            initramfs: "/img/initramfs.cpio.gz".into(),
            run_dir: "/run/vm/fc-1".into(),
            vcpu: 2,
            mem_mb: 512,
            workspace: Some(Workspace { host: "/host/proj".into(), guest: "/workspace".into(), read_only: true }),
            limits: Limits::default(),
            transport: Transport::Vsock { port: proto::VSOCK_PORT },
            firecracker: Some("/usr/bin/firecracker".into()),
            qemu: None,
            extra_args: vec![],
            guest_cid: 7,
        }
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn cmdline_is_the_api_socket_and_an_id() {
        let cfg = VmConfig { extra_args: vec!["--no-seccomp".into()], ..Default::default() };
        let p = FirecrackerProvider::new(&cfg);
        let a = p.cmdline(&spec()).join(" ");
        assert!(a.starts_with("--api-sock /run/vm/fc-1/fc.sock --id fc-1"), "{a}");
        assert!(a.ends_with("--no-seccomp"), "extra args are honoured");
        assert!(!a.contains("--no-api"), "the API must stay enabled: it is how we configure the VM");
    }

    // Unix host paths / Linux VMM probing (KVM, Firecracker): not meaningful on a Windows host.

    #[cfg(unix)]

    #[test]
    fn boot_requests_boot_from_the_initramfs_with_no_drive() {
        let reqs = boot_requests(&spec(), 7);
        let paths: Vec<&str> = reqs.iter().map(|(_, p, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["/boot-source", "/machine-config", "/vsock", "/actions"]);
        assert!(!paths.iter().any(|p| p.contains("drive")), "the initramfs is the root: no block device exists");
        // The same cmdline the QEMU provider uses, so the guest agent agrees
        // about tier, channel and workspace.
        assert_eq!(reqs[0].2["boot_args"], boot_args(&spec()));
        assert!(boot_args(&spec()).starts_with(&super::super::qemu::cmdline_append(&spec())) && boot_args(&spec()).ends_with(" reboot=k"), "the shared command line plus the keyboard-controller reset");
        assert_eq!(reqs[2].2["uds_path"], "/run/vm/fc-1/vsock.sock");
        assert_eq!(reqs[2].2["guest_cid"], 7);
    }

    #[test]
    fn an_unset_cid_falls_back_to_firecrackers_default() {
        assert_eq!(cid_or(0, 0), DEFAULT_GUEST_CID);
        assert_eq!(cid_or(2, 5), 5, "reserved CIDs are never used");
        assert_eq!(cid_or(9, 5), 9, "the spec wins");
    }
}
