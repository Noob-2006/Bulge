//! End-to-end A1/A3/A4/A5: a **real** microVM whose tools run as the unprivileged agent
//! user, whose only way out is the daemon broker socket, and whose requests are checked
//! against the capability manifest of the tool that caused them.
//!
//! This is the wiring round 5 left open (`audit/round5/AB-interface.md` §5: "daemon 啟動流程
//! 呼叫 `install_socket_broker(...)` 這一行還沒有人加"). It is `#[ignore]` because it boots
//! Firecracker; run it with a guest image:
//!
//! ```text
//! packaging/vm/build-image.sh --out "$TMPDIR/seagent-vm-image"
//! SEAGENT_VM_IMAGE_DIR=$TMPDIR/seagent-vm-image SEAGENT_VM_FIRECRACKER=/path/to/firecracker \
//!     cargo test -p seagent-tools --test vm_broker -- --ignored --nocapture
//! ```
//!
//! Without an image the test prints how to build one and returns, so `--ignored` stays
//! usable on a machine that has no guest image.

use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use seagent_security::broker::{Broker, BrokerConfig, Ctx};
use seagent_security::egress_proxy::{Policy, ProxyMode};
use seagent_tools::exec::vm::{self, current_component};
use seagent_tools::exec::{ExecConfig, ExecEnv};
use seagent_vm::config::VmConfig;
use base64::Engine as _;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The guest image, or `None` (with an explanation) when this machine has none.
fn image() -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::var_os("SEAGENT_VM_IMAGE_DIR").map(PathBuf::from).unwrap_or_else(|| seagent_core::tmp::scratch_path("seagent-vm-image"));
    let kernel = dir.join("vmlinux");
    let initramfs = dir.join("initramfs.cpio.gz");
    if kernel.is_file() && initramfs.is_file() {
        return Some((kernel, initramfs));
    }
    eprintln!("vm_broker: no guest image in {} — build one with `packaging/vm/build-image.sh --out {}`", dir.display(), dir.display());
    None
}

fn firecracker() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SEAGENT_VM_FIRECRACKER").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    ["firecracker", "/usr/bin/firecracker", "/usr/local/bin/firecracker"].iter().find_map(|n| seagent_vm::isolation::which(n))
}

/// A self-removing scratch tree: the guard is held for the whole test, so a panic (or a VM
/// that refuses to die) still leaves nothing behind in `$TMPDIR`.
fn scratch(tag: &str) -> seagent_core::tmp::TempDir {
    let d = seagent_core::tmp::TempDir::new(&format!("seagent-vm-broker-{tag}"));
    std::fs::create_dir_all(d.path().join("ws")).unwrap();
    d
}

/// A daemon that has one allowlisted command (`echo *`) and may reach exactly one host:
/// the local test server, by name.
fn daemon(data: &Path, socket: &Path, port: u16) -> Broker {
    let mut policy = Policy { mode: ProxyMode::Allowlist, ..Default::default() };
    policy.allow = vec!["127.0.0.1".into()];
    let mut ctx = Ctx::new(data.to_path_buf(), policy);
    ctx.session = "s-broker".into();
    ctx.cfg = BrokerConfig { exec_allow: vec!["echo *".into()], enforce_capabilities: true, ..Default::default() };
    ctx.resolve = Arc::new(move |h: &str, p: u16| {
        if h == "127.0.0.1" {
            return Ok(vec!["127.0.0.1".parse().unwrap()]);
        }
        let _ = p;
        Err("unknown host".into())
    });
    ctx.secret = Arc::new(|name: &str| if name == "TEST_TOKEN" { "tok-do-not-leak".into() } else { String::new() });
    ctx.check_body = Arc::new(|body: &str| seagent_security::risk::secret_kind(body).map(|k| format!("the body contains a {k}")));
    let _ = port;
    Broker::serve(socket, ctx).expect("serve the daemon broker")
}

/// The upstream the daemon (not the VM) talks to.
fn upstream() -> (u16, std::thread::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        // Read the whole head: the request line and the headers can arrive in separate reads.
        let mut req = String::new();
        let mut buf = [0u8; 512];
        while !req.contains("\r\n\r\n") && req.len() < 8192 {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => req.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
        let body = "hello-from-the-daemon";
        let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        req
    });
    (port, h)
}

fn backend(data: &Path, (kernel, initramfs): &(PathBuf, PathBuf)) -> Arc<dyn ExecBackend> {
    let fc = firecracker().expect("a firecracker binary");
    let cfg = ExecConfig {
        backend: "vm".into(),
        vm: VmConfig { provider: "firecracker".into(), firecracker: fc.display().to_string(), kernel: kernel.display().to_string(), initramfs: initramfs.display().to_string(), ..Default::default() },
        ..Default::default()
    };
    let env = ExecEnv::new(cfg);
    let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| if s == "{{secret:TEST_TOKEN}}" { "tok-do-not-leak".into() } else { s.to_string() });
    env.backend("s-broker", &data.join("ws"), data, &secrets, false).expect("a vm backend")
}

/// Run one command in the VM **as the component `component`** (the tool wrapper does this in
/// the daemon; here we call the same function directly) and return everything it printed.
fn run_as(b: &Arc<dyn ExecBackend>, component: &str, script: &str) -> (String, Option<i32>) {
    let req = ExecRequest { script: script.to_string(), ..Default::default() };
    let seen = current_component();
    let mut child: Box<dyn ExecChild> = vm::with_component(component, || b.spawn(&req)).expect("spawn in the vm");
    assert_eq!(current_component(), seen, "the component scope is restored");
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if Instant::now() > deadline {
            panic!("vm command timed out: {script}");
        }
        match child.read(&mut buf, Duration::from_secs(5)) {
            Ok(0) => {
                if let Some(e) = child.try_wait().unwrap_or(None) {
                    return (String::from_utf8_lossy(&out).to_string(), e.code);
                }
            }
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => {
                out.extend_from_slice(format!("\n[vm read error: {e}]").as_bytes());
                return (String::from_utf8_lossy(&out).to_string(), None);
            }
        }
    }
}

fn reply(text: &str) -> Value {
    // The guest prints exactly one JSON object for `seagent-broker '<json>'`.
    let line = text.lines().find(|l| l.trim_start().starts_with('{')).unwrap_or("");
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not a broker reply ({e}): {text}"))
}

#[test]
#[ignore = "boots a real Firecracker microVM (needs /dev/kvm and a guest image)"]
fn the_vm_runs_as_the_agent_user_and_only_reaches_the_outside_through_the_broker() {
    let Some(img) = image() else { return };
    if firecracker().is_none() {
        eprintln!("vm_broker: no firecracker binary (SEAGENT_VM_FIRECRACKER / PATH) — skipping");
        return;
    }
    let tmp = scratch("a1");
    let data = tmp.path().to_path_buf();
    let socket = data.join("run").join("broker.sock");
    let (port, upstream) = upstream();
    let broker = daemon(&data, &socket, port);
    assert_eq!(broker.path(), socket.as_path());
    // The one line round 5 was missing: the daemon hands its socket to every VM manager.
    vm::install_socket_broker(&socket);

    // A fifth of the point: a component declares exactly what it needs. This one is a test
    // component that declares the local upstream (loopback needs an explicit entry: `net: "*"`
    // is public hosts only, which is what keeps a poisoned skill off the host's services).
    seagent_security::capability::register(
        seagent_security::capability::declared("seagent-test-tool", seagent_security::capability::Kind::Tool, seagent_security::capability::Source::Operator, &["net:127.0.0.1".into(), "exec:echo *".into()]).expect("a valid declaration"),
    );

    let b = backend(&data, &img);
    assert_eq!(b.id(), "vm", "the backend is the microVM, not a fallback: {}", b.describe());

    // ── A1: the identity inside the VM ─────────────────────────────────────────────────────
    let (out, code) = run_as(&b, "shell", "id -u; id -un; cat /etc/passwd | tail -1; echo ---; cat /proc/net/dev");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.starts_with("1000\nagent\n"), "the agent user is uid 1000: {out}");
    let netdev = out.split("---").nth(1).unwrap_or("");
    assert!(netdev.contains("lo:") && !netdev.contains("eth0"), "the VM has no network interface: {netdev}");

    // The daemon's own files and secrets are not reachable from the guest at all.
    eprintln!("vm_broker: guest uid/root = {out:.120}");
    let (probe, _) = run_as(&b, "shell", &format!("test -e {} && echo LEAK || echo clean", data.display()));
    assert!(probe.contains("clean"), "the VM cannot see the daemon's data dir: {probe}");
    let (envout, _) = run_as(&b, "shell", "env | grep -c 'SEAGENT_TEST_DAEMON_SECRET' || echo none");
    assert!(envout.trim().ends_with("none") || envout.trim() == "0", "daemon credentials are stripped from the guest environment: {envout}");

    // ── A3: the only way out is the daemon broker ─────────────────────────────────────────
    let egress = json!({"kind": "egress.http", "payload": {"scheme": "http", "host": "127.0.0.1", "port": port, "method": "GET", "path": "/from-the-vm", "headers": {"x-seagent-test": "vm"}}});
    let (out, code) = run_as(&b, "seagent-test-tool", &format!("seagent-broker '{}'", egress));
    assert_eq!(code, Some(0), "{out}");
    let r = reply(&out);
    assert_eq!(r["ok"], true, "the daemon answered the egress request: {out}");
    let body = B64.decode(r["payload"]["body_b64"].as_str().unwrap_or("")).unwrap_or_default();
    assert_eq!(String::from_utf8_lossy(&body), "hello-from-the-daemon", "the answer travelled guest → host broker → upstream → back: {out}");
    let seen = upstream.join().unwrap();
    assert!(seen.contains("/from-the-vm") && seen.to_lowercase().contains("x-seagent-test: vm"), "the daemon made the request, with the guest's headers: {seen}");

    // A privileged command runs on the host because it is on the allowlist, and its output
    // comes back over the same channel.
    let priv_req = json!({"kind": "priv.exec", "payload": {"cmd": "echo", "args": ["from-the-daemon"]}});
    let (out, _) = run_as(&b, "seagent-test-tool", &format!("seagent-broker '{}'", priv_req));
    let r = reply(&out);
    assert_eq!(r["ok"], true, "{out}");
    assert_eq!(r["payload"]["status"], "ran", "{out}");
    assert_eq!(r["payload"]["stdout"], "from-the-daemon\n", "{out}");

    // Anything not on the allowlist is queued for the operator instead of running, and the
    // guest is told to carry on with the reversible part (§0-2 #04).
    let off_list = json!({"kind": "priv.exec", "payload": {"cmd": "sh", "args": ["-c", "id"]}});
    let (out, _) = run_as(&b, "shell", &format!("seagent-broker '{}'", off_list));
    let r = reply(&out);
    assert_eq!(r["payload"]["status"], "queued", "off-list work queues for the operator instead of failing the task: {out}");
    assert!(r["payload"]["fallback"].as_str().unwrap_or("").contains("do not retry"), "and the guest is told what to do instead of blocking: {out}");
    // The queue entry and the audit line belong to the VM's session, not to "daemon": the
    // operator sees which task is waiting, and that task's envelope is the one that applies.
    let log = std::fs::read_to_string(data.join("audit").join("broker.jsonl")).unwrap_or_default();
    // The backend's scope key for a host (non-sandboxed) session is `host-<session>`.
    assert!(log.contains("\"session\":\"host-s-broker\""), "the broker files the request under the VM's session: {log}");
    assert!(log.contains("\"component\":\"shell\""), "and under the tool that asked: {log}");
    assert!(log.contains("\"verdict\":\"queued\""), "{log}");
    // A shell *string* cannot be smuggled through the argv channel at all.
    let smuggle = json!({"kind": "priv.exec", "payload": {"cmd": "sh", "args": ["-c", "id; rm -rf /"]}});
    let (out, _) = run_as(&b, "shell", &format!("seagent-broker '{}'", smuggle));
    assert!(out.contains("may not contain shell syntax"), "argv only, never a shell string: {out}");

    // ── A5: the manifest of the tool that acted is what is checked ────────────────────────
    // An unregistered third-party component has no manifest: its request is refused at the
    // broker, with a message the operator can act on.
    let (out, _) = run_as(&b, "acme-unregistered-skill", &format!("seagent-broker '{}'", egress));
    assert!(out.contains("no capability manifest"), "undeclared component refused (A5): {out}");
    // The built-in `shell` may run commands and reach **public** hosts; loopback is not covered
    // by `net: "*"`, so a shell command inside the VM cannot use the broker to reach the host's
    // own services either (the second layer behind `url_safety`).
    let (out, _) = run_as(&b, "shell", &format!("seagent-broker '{}'", egress));
    assert!(out.contains("lacks the `net:127.0.0.1") && out.contains("public hosts only"), "`net: \"*\"` is public-only: {out}");
    // Ordinary work is untouched: no manifest, no prompt, no new step. §0.
    let (out, _) = run_as(&b, "shell", "echo still-works");
    assert!(out.contains("still-works"), "{out}");

    // A4: a secret is injected by the daemon and never appears in the guest's output.
    let with_secret = json!({"kind": "egress.http", "payload": {"scheme": "http", "host": "127.0.0.1", "port": port, "method": "GET", "path": "/s", "headers": {"authorization": "secret:TEST_TOKEN"}}});
    let (out, _) = run_as(&b, "seagent-test-tool", &format!("seagent-broker '{}'", with_secret));
    assert!(!out.contains("tok-do-not-leak"), "the secret value never returns to the guest: {out}");
    // A component that did not declare the secret name may not have it injected at all: the
    // test component above declared hosts and commands, not `secret:TEST_TOKEN`.
    assert!(out.contains("lacks the `secret:TEST_TOKEN`"), "an undeclared secret is refused: {out}");

    b.cleanup();
    let _ = std::fs::remove_file(&socket);
    drop(broker);
    drop(tmp); // removes the tree
}
