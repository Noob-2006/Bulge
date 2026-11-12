//! The built-in VM exactly as an installer ships it, on whichever desktop OS this runs: a bundle
//! staged by `packaging/vm/bundle.sh` (guest image + that OS's hypervisor front-end — QEMU for
//! Windows with WHPX or TCG, vfkit on macOS, Firecracker on Linux), found through
//! `SEAGENT_VM_BUNDLE` the way the desktop app hands it to the agent, booted through the pool
//! with the *default* config: no QEMU / VirtualBox install, no configured paths.
//!
//! ```text
//! packaging/vm/bundle.sh --os <windows|macos|linux> --image <build-image.sh out> --out <DIR>
//! SEAGENT_VM_BUNDLE=<DIR> cargo test -p seagent-vm --test boot_bundle -- --nocapture
//! ```
//!
//! Without `SEAGENT_VM_BUNDLE` it prints SKIP and returns (CI stages a bundle and sets it). On
//! Linux the boot also needs a writable `/dev/kvm` (Firecracker has no software fallback).

use seagent_vm::bundle::Bundle;
use seagent_vm::config::VmConfig;
use seagent_vm::pool::{VmExec, VmManager};
use seagent_vm::trust::TrustTier;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn bundle() -> Option<Bundle> {
    let dir = std::env::var_os("SEAGENT_VM_BUNDLE").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty());
    let Some(dir) = dir else {
        eprintln!("SKIP: set SEAGENT_VM_BUNDLE to a directory staged by packaging/vm/bundle.sh");
        return None;
    };
    Some(Bundle::open(&dir).unwrap_or_else(|e| panic!("SEAGENT_VM_BUNDLE={}: {e}", dir.display())))
}

#[test]
fn the_bundled_vm_boots_with_the_default_config_and_runs_uname() {
    let Some(b) = bundle() else { return };
    assert_eq!(b.info.os, std::env::consts::OS, "a bundle staged for {} on a {} host", b.info.os, std::env::consts::OS);
    b.verify_runtime().expect("every bundled runtime file matches bundle.json");
    let img = b.image().expect("the bundled image verifies");
    let exe = b.runtime_exe().expect("the bundled hypervisor executable");
    if cfg!(target_os = "linux") && !seagent_vm::host::kvm_usable() {
        eprintln!("SKIP boot: /dev/kvm is missing or not writable for this user (Firecracker needs KVM); the bundle itself verified");
        return;
    }

    let data = seagent_core::tmp::TempDir::new("seagent-boot-bundle-data");
    let ws = seagent_core::tmp::TempDir::new("seagent-boot-bundle-ws");
    std::fs::write(ws.path().join("from-host.txt"), "hello from the host\n").unwrap();
    let mgr = VmManager::new(VmConfig::default(), data.path().to_path_buf());

    // The pool runs the bundled binary — not whatever QEMU / Firecracker / vfkit is on PATH.
    let cfg = mgr.config();
    let used = match b.info.runtime.kind.as_str() {
        "qemu" => &cfg.qemu,
        "vfkit" => &cfg.vfkit,
        "firecracker" => &cfg.firecracker,
        other => panic!("unknown bundled runtime {other}"),
    };
    assert_eq!(PathBuf::from(used), exe, "the default config resolves to the bundled {}", b.info.runtime.kind);
    let caps = mgr.capabilities();
    assert_eq!(caps.kernel.as_deref(), Some(img.kernel().as_path()), "capabilities see the bundled image");
    let (kind, warning) = mgr.selection();
    assert!(kind.is_vm(), "the bundle makes a microVM available: {kind:?} {warning:?}");
    eprintln!("provider {} ({:?}); note: {}", kind.name(), seagent_vm::provider::accel_of(kind, &caps), warning.unwrap_or_default());

    let mut req = VmExec::new("bundle-test", TrustTier::Owner, ws.path(), "uname -a; id -u; cat /workspace/from-host.txt");
    req.timeout = Duration::from_secs(180);
    let t = Instant::now();
    let out = mgr.exec(&req).unwrap_or_else(|e| panic!("{} VM: {e}", kind.name()));
    eprintln!("first command incl. boot: {:.0} ms\n{}", t.elapsed().as_secs_f64() * 1000.0, out.text());
    mgr.shutdown_all(Duration::from_secs(15));
    assert_eq!(out.code, Some(0), "{}", out.text());
    let text = out.text();
    assert!(text.starts_with("Linux ") && text.contains("seagent"), "the guest kernel answered: {text}");
    assert!(text.contains("\n1000\n"), "tools run as the unprivileged guest user: {text}");
    assert!(text.contains("hello from the host"), "the workspace was synced in: {text}");
}
