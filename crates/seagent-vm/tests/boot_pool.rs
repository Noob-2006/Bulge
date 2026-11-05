//! End-to-end pool tests against a **real microVM** (Firecracker, KVM).
//!
//! Ignored by default because they need `/dev/kvm`, the `firecracker` binary and
//! a built guest image. Run them once after building the image:
//!
//! ```text
//! export CARGO_INCREMENTAL=0 TMPDIR=$HOME/.cache/seagent-build/r5-b
//! packaging/vm/build-image.sh --out $TMPDIR/seagent-vm-image
//! SEAGENT_VM_IMAGE_DIR=$TMPDIR/seagent-vm-image FIRECRACKER=$TMPDIR/dl/firecracker \
//!   cargo test -p seagent-vm --test boot_pool -- --ignored --nocapture
//! ```
//!
//! What they prove (each is a plan item):
//! * B1/B2 — a command really runs inside a microVM, as the unprivileged agent
//!   user, on a copy of the workspace;
//! * B4/H1 — a destructive command is snapshotted first and `restore` brings the
//!   files back;
//! * B5 — owner and stranger work get separate VMs;
//! * A4/H11 — a secret in the caller's environment never appears in the guest's
//!   `/proc/<pid>/environ`, and `{{secret:…}}` is never resolved there;
//! * B3/A3 — an in-VM program can only reach the outside through `seagent-broker`,
//!   which lands in the host broker.

use seagent_vm::pool::{Broker, VmExec, VmManager};
use seagent_vm::trust::TrustTier;
use seagent_vm::VmConfig;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct RecordingBroker {
    calls: AtomicUsize,
}

impl Broker for RecordingBroker {
    fn handle(&self, kind: &str, payload: Value) -> Result<Value, String> {
        match kind {
            "egress.http" => {
                // Only *allowed* requests count as handled by the daemon; a
                // refused one never reaches the network (A3).
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"status": 200, "host": payload["host"], "by": "host-broker"}))
            }
            other => Err(format!("kind `{other}` is not on the allow-list")),
        }
    }
}

fn image_dir() -> Option<PathBuf> {
    let d = std::env::var("SEAGENT_VM_IMAGE_DIR").map(PathBuf::from).ok()?;
    (d.join("manifest.json").exists() && d.join("vmlinux").exists()).then_some(d)
}

fn firecracker() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FIRECRACKER") {
        return Path::new(&p).is_file().then(|| PathBuf::from(p));
    }
    seagent_vm::isolation::which("firecracker")
}

fn scratch(tag: &str) -> PathBuf {
    let d = seagent_core::tmp::scratch_path(format!("seagent-vm-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn manager(image: &Path, data: &Path) -> VmManager {
    let cfg = VmConfig {
        provider: "firecracker".into(),
        kernel: image.join("vmlinux").display().to_string(),
        initramfs: image.join("initramfs.cpio.gz").display().to_string(),
        image_dir: data.join("vm").display().to_string(),
        firecracker: firecracker().unwrap().display().to_string(),
        memory_mb: 256,
        vcpu: 1,
        snapshot_keep: 4,
        ..Default::default()
    };
    VmManager::new(cfg, data.to_path_buf())
}

fn setup(tag: &str) -> Option<(VmManager, PathBuf, PathBuf, PathBuf)> {
    let image = match image_dir() {
        Some(i) => i,
        None => {
            println!("skipping: SEAGENT_VM_IMAGE_DIR is unset or has no manifest.json");
            return None;
        }
    };
    if firecracker().is_none() {
        println!("skipping: no firecracker binary (set FIRECRACKER=…)");
        return None;
    }
    if std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_err() {
        println!("skipping: /dev/kvm is not writable");
        return None;
    }
    let root = scratch(tag);
    let data = root.join("data");
    let ws = root.join("ws");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("notes.txt"), "hello from the host\n").unwrap();
    let m = manager(&image, &data);
    Some((m, data, ws, root))
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn a_command_runs_inside_the_microvm_as_the_agent_user() {
    let Some((m, data, ws, root)) = setup("exec") else { return };
    let broker = Arc::new(RecordingBroker { calls: AtomicUsize::new(0) });
    m.set_broker(broker.clone());
    let t = std::time::Instant::now();
    let out = m
        .exec(&VmExec::new("s1", TrustTier::Owner, &ws, "id -u; uname -r; cat notes.txt; echo makings > made.txt; test -e /dev/kvm && echo KVM_VISIBLE || echo no-kvm"))
        .unwrap();
    println!("boot+exec took {:?}\n--- guest output ---\n{}--- end ---", t.elapsed(), out.text());
    assert_eq!(out.code, Some(0), "{}", out.text());
    assert!(out.text().contains("1000"), "the agent user, not root: {}", out.text());
    assert!(out.text().contains("hello from the host"), "the workspace was synced in: {}", out.text());
    assert!(out.text().contains("no-kvm"), "the guest has no /dev/kvm of its own");
    assert!(out.text().contains("5.10"), "the guest runs its own kernel: {}", out.text());
    assert_eq!(std::fs::read_to_string(ws.join("made.txt")).unwrap().trim(), "makings", "guest writes come back");
    assert_eq!(out.isolation, seagent_vm::IsolationLevel::MicroVm);
    // The VM is listed, running, and can be stopped.
    let st = m.status();
    assert_eq!(st.len(), 1);
    assert!(st[0].running);
    assert_eq!(st[0].tier, "owner");
    m.stop_all();
    let _ = std::fs::remove_dir_all(&root);
    let _ = data;
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn secrets_never_cross_into_the_vm() {
    let Some((m, _data, ws, root)) = setup("secrets") else { return };
    let mut e = VmExec::new("s1", TrustTier::Owner, &ws, "env | sort; echo ---; cat /proc/self/environ | tr '\\0' '\\n' | sort");
    e.env = vec![
        ("OPENAI_API_KEY".into(), "sk-should-not-be-here".into()),
        ("GITHUB_TOKEN".into(), "ghp_should_not_be_here".into()),
        ("FROM_TEMPLATE".into(), "{{secret:PROD_DB_PASSWORD}}".into()),
        ("NORMAL_VAR".into(), "fine".into()),
    ];
    let out = m.exec(&e).unwrap();
    let text = out.text();
    println!("--- guest env ---\n{text}--- end ---");
    assert!(!text.contains("sk-should-not-be-here"), "A4: no API key in the VM");
    assert!(!text.contains("ghp_should_not_be_here"), "H11: no token in the VM");
    assert!(!text.contains("PROD_DB_PASSWORD"), "A4: placeholders are not resolved in the VM");
    assert!(text.contains("NORMAL_VAR=fine"), "ordinary variables do arrive");
    assert!(out.dropped.iter().any(|d| d.name == "OPENAI_API_KEY"), "the drop is reported, not silent");
    m.stop_all();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn a_destructive_command_leaves_an_undo_point() {
    let Some((m, _data, ws, root)) = setup("undo") else { return };
    std::fs::write(ws.join("precious.txt"), "do not lose me\n").unwrap();
    let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "rm -rf * ; echo wiped")).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.text());
    let snap = out.snapshot.expect("destructive commands are snapshotted, not blocked");
    println!("undo point: {} ({} files, {} bytes, reason {})", snap.name, snap.files, snap.bytes, snap.reason);
    // H1: deletions inside the VM never reach the host.
    assert!(ws.join("precious.txt").exists());
    // The operator's accident is recoverable either way.
    std::fs::remove_file(ws.join("precious.txt")).unwrap();
    let r = m.restore("s1", TrustTier::Owner, &ws, None).unwrap();
    assert_eq!(std::fs::read_to_string(ws.join("precious.txt")).unwrap(), "do not lose me\n");
    assert_eq!(r.name, snap.name);
    m.stop_all();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn owners_and_strangers_get_different_vms() {
    let Some((m, _data, ws, root)) = setup("tiers") else { return };
    let o = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "hostname; echo $$")).unwrap();
    let s = m.exec(&VmExec::new("s1", TrustTier::Stranger, &ws, "hostname; echo $$")).unwrap();
    assert_eq!(o.code, Some(0));
    assert_eq!(s.code, Some(0));
    assert_ne!(o.text(), s.text(), "different VMs for different trust tiers (B5): {} vs {}", o.text(), s.text());
    let status = m.status();
    assert_eq!(status.len(), 2, "{status:?}");
    assert!(status.iter().any(|x| x.tier == "owner") && status.iter().any(|x| x.tier == "stranger"));
    m.stop_all();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn the_vm_can_only_reach_the_outside_through_the_broker() {
    let Some((m, _data, ws, root)) = setup("broker") else { return };
    let broker = Arc::new(RecordingBroker { calls: AtomicUsize::new(0) });
    m.set_broker(broker.clone());
    // `seagent-broker` is the only route out of the guest (no NIC, no host socket).
    let script = r#"seagent-broker '{"kind":"egress.http","payload":{"host":"crates.io","path":"/"}}' ;
        seagent-broker '{"kind":"priv.exec","payload":{"cmd":"apt install evil"}}' ; echo "exit=$?""#;
    let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, script)).unwrap();
    println!("--- broker round trip ---\n{}--- end ---", out.text());
    assert!(out.text().contains("crates.io"), "the allowed request reached the host broker: {}", out.text());
    assert!(out.text().contains("allow-list"), "the denied request was refused by the host: {}", out.text());
    assert_eq!(broker.calls.load(Ordering::SeqCst), 1, "only the allowed request was handled");
    // And there is no direct egress at all.
    let probe = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "ip route 2>/dev/null | head -3; ls /sys/class/net")).unwrap();
    println!("--- guest network ---\n{}", probe.text());
    assert!(!probe.text().contains("eth0"), "no NIC in the guest: {}", probe.text());
    m.stop_all();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[ignore = "boots a real microVM (KVM + firecracker + guest image)"]
fn resource_limits_and_idle_reaping_work() {
    let Some((m, _data, ws, root)) = setup("limits") else { return };
    // 512 processes is the default ceiling (`exec.vm.max_processes`), applied by
    // the agent as RLIMIT_NPROC for the unprivileged user.
    let ulimits = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "ulimit -u; ulimit -n")).unwrap();
    println!("guest ulimits: {}", ulimits.text().replace('\n', " "));
    assert!(ulimits.text().starts_with("512"), "RLIMIT_NPROC reached the guest: {}", ulimits.text());
    let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "i=0; while [ $i -lt 2000 ]; do (sleep 5 &) 2>/dev/null || { echo FORK_LIMIT_$i; break; } ; i=$((i+1)); done")).unwrap();
    println!("fork attempt: {:?} {}", out.code, out.text());
    assert!(out.text().contains("FORK_LIMIT_"), "the process ceiling bit inside the VM: {}", out.text());
    let n: usize = out.text().split("FORK_LIMIT_").nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    assert!(n <= 600, "stopped near the ceiling, not after {n} forks");
    // Idle reaping.
    let st = m.status();
    assert_eq!(st.len(), 1, "one VM: {st:?}");
    assert_eq!(m.gc_idle(), 0, "a warm VM is not reaped");
    m.stop_all();
    assert!(m.status().is_empty());
    let _ = std::fs::remove_dir_all(&root);
    let _ = Duration::from_secs(0);
}
