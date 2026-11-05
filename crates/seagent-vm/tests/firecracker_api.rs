//! Wire-level tests for the Firecracker provider: no VM, no KVM, no kernel.
//!
//! A fake API server (`UnixListener` in a target-dir temp dir) records the
//! `(method, path, JSON body)` of every request the provider sends and answers
//! with a canned status, so the parts that actually break in production —
//! endpoint order, field names, the absence of a `/drives` call, error bodies —
//! are asserted directly against what goes over the socket.
//!
//! The one test that needs the real thing (`boots_a_real_microvm`) is
//! `#[ignore]`d and gated on `FC_KERNEL`/`FC_INITRAMFS` + a `firecracker` on
//! `PATH`; it prints why it skipped instead of failing.

use seagent_vm::channel::Transport;
use seagent_vm::config::VmConfig;
use seagent_vm::limits::Limits;
use seagent_vm::proto::{self, GuestMsg};
use seagent_vm::provider::firecracker::{boot_requests, configure, connect_channel, probe, snapshot_create_body, snapshot_load_body, Api, FirecrackerProvider};
use seagent_vm::provider::{qemu, VmSpec, VmProvider, Workspace};
use serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ---------------------------------------------------------------- fake server

/// One recorded request.
type Record = (String, String, Value);

/// A Firecracker API socket that answers every request with `status`/`body`
/// and records what it received.
struct FakeApi {
    dir: PathBuf,
    sock: PathBuf,
    seen: Arc<Mutex<Vec<Record>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeApi {
    fn start(tag: &str, status: &'static str, body: &'static str) -> FakeApi {
        let dir = tmp_dir(tag);
        let sock = dir.join("fc.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind fake api socket");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let seen = seen.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut s, _)) => handle(&mut s, &seen, status, body),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                        Err(_) => break,
                    }
                }
            })
        };
        FakeApi { dir, sock, seen, stop, thread: Some(thread) }
    }

    /// Everything the client sent, in order.
    fn requests(&self) -> Vec<Record> {
        self.seen.lock().expect("records").clone()
    }

    fn methods_paths(&self) -> Vec<(String, String)> {
        self.requests().into_iter().map(|(m, p, _)| (m, p)).collect()
    }
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn handle(s: &mut UnixStream, seen: &Mutex<Vec<Record>>, status: &str, rbody: &str) {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 4096];
    let mut raw = Vec::new();
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let len: usize = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse().ok()))
        .unwrap_or(0);
    let mut body = raw[head_end + 4..].to_vec();
    while body.len() < len {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    let mut line = head.lines().next().unwrap_or("").split_whitespace();
    let method = line.next().unwrap_or("").to_string();
    let path = line.next().unwrap_or("").to_string();
    let parsed: Value = serde_json::from_slice(&body[..len.min(body.len())]).unwrap_or(Value::Null);
    seen.lock().expect("records").push((method, path, parsed));

    let reply = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rbody}", rbody.len());
    let _ = s.write_all(reply.as_bytes());
    let _ = s.flush();
}

/// A fresh directory for a test: `$TMPDIR` (the workspace build temp, never
/// `/tmp`) or, if unset, the target's own temp dir. Sockets go here too, and a
/// unix socket path must stay under `SUN_LEN` (~108 bytes), which is why the
/// target dir is only the fallback.
fn tmp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::AtomicUsize;
    static N: AtomicUsize = AtomicUsize::new(0);
    // Removed when the test's thread ends (panic included): nothing stays behind in `$TMPDIR`.
    let d = seagent_core::tmp::scratch_path(format!("fc-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

fn spec(run_dir: &Path) -> VmSpec {
    VmSpec {
        id: "fc-t1".into(),
        tier: "stranger".into(),
        kernel: "/img/vmlinux".into(),
        initramfs: "/img/initramfs.cpio.gz".into(),
        run_dir: run_dir.to_path_buf(),
        vcpu: 2,
        mem_mb: 512,
        workspace: Some(Workspace { host: "/host/secret-project".into(), guest: "/workspace".into(), read_only: true }),
        limits: Limits::default(),
        transport: Transport::Vsock { port: proto::VSOCK_PORT },
        firecracker: None,
        qemu: None,
        extra_args: vec![],
        guest_cid: 7,
    }
}

// ---------------------------------------------------------------------- tests

#[test]
fn configure_posts_the_expected_endpoints_in_order() {
    let api = FakeApi::start("order", "204 No Content", "");
    let dir = tmp_dir("vm-order");
    let s = spec(&dir);

    let sent = configure(&api.sock, &s).expect("configure a fake API socket");
    assert_eq!(
        api.methods_paths(),
        vec![
            ("PUT".to_string(), "/boot-source".to_string()),
            ("PUT".to_string(), "/machine-config".to_string()),
            ("PUT".to_string(), "/vsock".to_string()),
            ("PUT".to_string(), "/actions".to_string()),
        ],
        "boot-source, machine-config and vsock must all precede InstanceStart"
    );
    assert_eq!(sent.len(), 4, "configure reports what it sent");

    let rec = api.requests();
    let boot = &rec[0].2;
    assert_eq!(boot["kernel_image_path"], "/img/vmlinux");
    assert_eq!(boot["initrd_path"], "/img/initramfs.cpio.gz", "the initramfs is the guest root");
    let args = boot["boot_args"].as_str().expect("boot_args is a string");
    assert!(args.contains("rdinit=/sbin/init"), "init is the guest agent: {args}");
    assert!(args.contains("seagent.vm=fc-t1") && args.contains("seagent.tier=stranger"), "{args}");
    assert!(args.contains("seagent.channel=vsock"), "the agent must know it speaks vsock: {args}");

    let mc = &rec[1].2;
    assert_eq!(mc["vcpu_count"], 2);
    assert_eq!(mc["mem_size_mib"], 512);
    assert_eq!(mc["smt"], false);

    let vs = &rec[2].2;
    assert_eq!(vs["guest_cid"], 7, "the spec's CID reaches the API");
    assert_eq!(vs["uds_path"], dir.join("vsock.sock").display().to_string());

    assert_eq!(rec[3].2["action_type"], "InstanceStart");

    // Nothing may configure storage: the guest root is an immutable initramfs.
    for (_, path, _) in &rec {
        assert_ne!(path, "/drives", "B2: no writable block device, ever");
        assert_ne!(path, "/boot-source/drives");
        assert!(!path.contains("drive"), "{path} is not part of the boot sequence");
    }
    // And the host workspace path never appears on the wire.
    let wire = api.requests().iter().map(|(_, _, b)| b.to_string()).collect::<String>();
    assert!(!wire.contains("/host/secret-project"), "the host workspace is synced, never mounted: {wire}");
}

#[test]
fn configure_rejects_a_4xx_with_the_response_body() {
    let api = FakeApi::start("4xx", "400 Bad Request", r#"{"fault_message":"the kernel image does not exist"}"#);
    let dir = tmp_dir("vm-4xx");
    let err = configure(&api.sock, &spec(&dir)).expect_err("a 400 must not look like success");
    assert!(err.contains("400"), "the status is reported: {err}");
    assert!(err.contains("the kernel image does not exist"), "Firecracker's own reason is kept: {err}");
    assert!(err.contains("/boot-source"), "the failing endpoint is named: {err}");
    assert_eq!(api.methods_paths().len(), 1, "the boot sequence stops at the first failure");
}

#[test]
fn a_dead_api_socket_is_a_clear_error_not_a_panic() {
    let dir = tmp_dir("dead");
    let err = Api::new(&dir.join("no-such.sock")).put("/actions", &json!({"action_type": "InstanceStart"})).expect_err("no socket, no VM");
    assert!(err.contains("connect"), "the error says the socket could not be reached: {err}");
}

#[test]
fn boot_requests_never_configure_a_drive() {
    let dir = tmp_dir("pure");
    let s = spec(&dir);
    let reqs = boot_requests(&s, 7);
    let paths: Vec<&str> = reqs.iter().map(|(_, p, _)| p.as_str()).collect();
    assert_eq!(paths, vec!["/boot-source", "/machine-config", "/vsock", "/actions"]);
    assert!(reqs.iter().all(|(m, _, _)| m == "PUT"), "configuration is PUT, pause/snapshot is the only PATCH");
    for (_, _, body) in &reqs {
        assert!(body.get("drive_id").is_none(), "no drive is ever configured: {body}");
    }
    // The kernel cmdline is shared with the QEMU provider rather than forked:
    // one source of truth for the `seagent.*` facts the guest agent trusts.
    assert_eq!(reqs[0].2["boot_args"], Value::String(qemu::cmdline_append(&s)));
}

#[test]
fn snapshot_bodies_match_the_firecracker_api() {
    let dir = Path::new("/snaps/s-1");
    let create = snapshot_create_body(&dir.join("snap.fc"), &dir.join("mem.fc"));
    assert_eq!(create["snapshot_type"], "Full", "RAM + device state, not just metadata");
    assert_eq!(create["snapshot_path"], "/snaps/s-1/snap.fc");
    assert_eq!(create["mem_file_path"], "/snaps/s-1/mem.fc");

    let load = snapshot_load_body(&dir.join("snap.fc"), &dir.join("mem.fc"));
    assert_eq!(load["snapshot_path"], "/snaps/s-1/snap.fc");
    assert_eq!(load["mem_backend"]["backend_type"], "File", "Firecracker >= 1.0 wants a mem_backend object");
    assert_eq!(load["mem_backend"]["backend_path"], "/snaps/s-1/mem.fc");
    assert_eq!(load["resume_vm"], true, "the guest keeps running after a restore");
}

#[test]
fn probe_reports_a_binary_that_is_not_firecracker() {
    assert!(probe(Path::new("/nonexistent/firecracker-xyz")).is_err(), "a missing binary is an error");
    // `/bin/false --version` exits non-zero: that is not a usable VMM either.
    if Path::new("/bin/false").exists() {
        assert!(probe(Path::new("/bin/false")).is_err());
    }
    // `echo` exits 0 but prints no version line: still reported, never a panic.
    if Path::new("/bin/echo").exists() {
        assert!(probe(Path::new("/bin/echo")).is_ok());
    }
}

// ------------------------------------------------------- real microVM (opt-in)

/// Boot a real Firecracker microVM, connect over vsock and expect the agent's
/// `Hello`.
///
/// Exact commands (needs `/dev/kvm`, the Firecracker release binary and the CI
/// kernel; the initramfs is ours, from `packaging/vm/build-image.sh`):
///
/// ```text
/// export FC_KERNEL=/abs/path/to/vmlinux
/// export FC_INITRAMFS=/abs/path/to/initramfs.cpio.gz
/// cargo test -p seagent-vm --test firecracker_api -- --ignored --nocapture boots_a_real_microvm
/// ```
///
/// Without those env vars (or without `firecracker` on `PATH`) the test prints
/// a note and returns — it never fails the suite on a machine that cannot host
/// a microVM.
#[test]
#[ignore = "boots a real microVM: needs /dev/kvm, firecracker and FC_KERNEL/FC_INITRAMFS"]
fn boots_a_real_microvm() {
    let (kernel, initramfs) = match (std::env::var("FC_KERNEL"), std::env::var("FC_INITRAMFS")) {
        (Ok(k), Ok(i)) if Path::new(&k).is_absolute() && Path::new(&i).is_absolute() => (PathBuf::from(k), PathBuf::from(i)),
        _ => {
            println!("skipping boots_a_real_microvm: set FC_KERNEL and FC_INITRAMFS to absolute paths");
            return;
        }
    };
    let Some(bin) = which("firecracker") else {
        println!("skipping boots_a_real_microvm: `firecracker` is not on PATH");
        return;
    };
    if !Path::new("/dev/kvm").exists() {
        println!("skipping boots_a_real_microvm: /dev/kvm is missing");
        return;
    }

    let cfg = VmConfig { firecracker: bin.display().to_string(), ..Default::default() };
    let provider = FirecrackerProvider::new(&cfg);
    let dir = tmp_dir("boot");
    let mut s = spec(&dir);
    s.id = format!("fcreal{}", std::process::id());
    s.kernel = kernel;
    s.initramfs = initramfs;
    s.workspace = None;
    s.guest_cid = 3;
    s.vcpu = 1;
    s.mem_mb = 256;

    let mut vm = provider.start(&s).expect("boot a microVM");
    assert!(vm.is_running(), "the VMM stays up after InstanceStart");
    // `VmInstance::connect` hands out a cached `Arc<Channel>`; reading frames
    // needs `&mut Channel`, so the connection that is actually read here comes
    // from the same helper (`connect_channel`) that `connect` caches.
    let ch = connect_channel(&dir, Duration::from_secs(20)).expect("vsock channel");
    match ch.expect(Duration::from_secs(20), "Hello").expect("the guest agent says Hello") {
        GuestMsg::Hello { version, transport, uid, .. } => {
            assert_eq!(version, seagent_vm::IMAGE_VERSION, "the guest image matches this crate");
            assert!(transport.contains("vsock"), "the agent reports the transport it was told: {transport}");
            assert_ne!(uid, 0, "the agent dropped privileges before saying Hello");
        }
        other => panic!("expected a Hello, got {other:?}"),
    }
    assert!(vm.usage().rss_kb > 0, "the VMM's RSS is visible");
    vm.stop();
    assert!(!vm.is_running(), "stop is final");
    assert!(!dir.join("fc.sock").exists() && !dir.join("vsock.sock").exists(), "sockets are cleaned up");
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}
