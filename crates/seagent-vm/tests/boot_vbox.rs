//! The VirtualBox provider against a real VirtualBox (Windows / macOS / Linux): the guest
//! *disk* (`disk.raw` from `packaging/vm/build-image.sh --format disk`, converted once to an
//! immutable VDI) booted through UEFI, the channel on COM2 (`/dev/ttyS1` in the guest, a named
//! pipe on Windows, a unix socket elsewhere).
//!
//! `#[ignore]`, gated like `boot_qemu_windows.rs`: it needs `VBoxManage` (PATH, or the
//! installer's directory) and `SEAGENT_VM_IMAGE_DIR` with `vmlinux` and `disk.raw`; without
//! them it prints why and returns.
//!
//! ```text
//! SEAGENT_VM_IMAGE_DIR=… cargo test -p seagent-vm --test boot_vbox -- --ignored --nocapture
//! ```
//!
//! On a Windows host where Hyper-V / WHPX is active, VirtualBox runs its guests through the
//! Windows Hypervisor Platform ("NEM" backend) instead of its own VT-x driver; the test prints
//! the boot time so the difference is visible.

use base64::Engine as _;
use seagent_vm::channel::{Channel, Transport};
use seagent_vm::config::VmConfig;
use seagent_vm::limits::Limits;
use seagent_vm::proto::{self, GuestMsg, HostMsg};
use seagent_vm::provider::vbox::VboxProvider;
use seagent_vm::provider::{VmProvider, VmSpec, Workspace};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const BOOT_WAIT: Duration = Duration::from_secs(60);
/// The kernel must have started (the agent logs on COM1) within this: a firmware that hangs
/// (VirtualBox NEM + SMP, `EFI: debug point DXE_AP`) fails here, fast, not after a long wait.
const KERNEL_WAIT: Duration = Duration::from_secs(45);

/// Wait until the guest agent wrote to the console, else fail with the VirtualBox log tail.
fn wait_for_kernel(spec: &VmSpec, t0: Instant) -> Result<(), String> {
    while t0.elapsed() < KERNEL_WAIT {
        if std::fs::read_to_string(spec.console_log()).is_ok_and(|c| c.contains("seagent-vm-guest:")) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let vbox_log = spec.run_dir.join(seagent_vm::provider::vbox::vm_name(spec)).join("Logs").join("VBox.log");
    let tail: Vec<String> = std::fs::read_to_string(&vbox_log).unwrap_or_default().lines().rev().take(8).map(str::to_string).collect();
    Err(format!(
        "the guest kernel did not start within {KERNEL_WAIT:?} (console {} has no agent line): the firmware never handed over. VBox.log tail:\n{}",
        spec.console_log().display(),
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    ))
}
const FRAME_WAIT: Duration = Duration::from_secs(30);

fn until_exit(ch: &Channel, id: u64) -> (String, Option<i32>) {
    let mut out = Vec::new();
    loop {
        match ch.recv(FRAME_WAIT).unwrap() {
            Some(GuestMsg::Out { id: i, data }) if i == id => out.extend(base64::engine::general_purpose::STANDARD.decode(data.as_bytes()).unwrap()),
            Some(GuestMsg::Exit { id: i, code, .. }) if i == id => return (String::from_utf8_lossy(&out).into_owned(), code),
            Some(GuestMsg::Err { id: i, message }) if i == id => panic!("exec {id}: {message}"),
            Some(_) => continue,
            None => panic!("exec {id}: no Exit within {FRAME_WAIT:?}"),
        }
    }
}

#[test]
#[ignore = "boots a real VM: needs VirtualBox and SEAGENT_VM_IMAGE_DIR with disk.raw"]
fn boots_virtualbox_from_the_guest_disk_and_runs_a_command() {
    let Some(image) = std::env::var_os("SEAGENT_VM_IMAGE_DIR").map(PathBuf::from).filter(|d| d.join("vmlinux").is_file() && d.join("disk.raw").is_file()) else {
        eprintln!("SKIP: set SEAGENT_VM_IMAGE_DIR to an image built with --format disk");
        return;
    };
    let cfg = VmConfig::default();
    if seagent_vm::host::find_tool(&cfg.vboxmanage).is_none() {
        eprintln!("SKIP: VBoxManage not found (install Oracle VirtualBox)");
        return;
    }
    let scratch = seagent_core::tmp::TempDir::new("seagent-vbox");
    let run = scratch.path().to_path_buf();
    let spec = VmSpec {
        id: format!("vbox-{}", std::process::id()),
        tier: "owner".into(),
        kernel: image.join("vmlinux"),
        initramfs: image.join("initramfs.cpio.gz"),
        run_dir: run.clone(),
        vcpu: 2,
        mem_mb: 512,
        workspace: Some(Workspace { host: run.join("ws"), guest: proto::GUEST_WORKSPACE.into(), read_only: false }),
        limits: Limits::default(),
        transport: Transport::Uart,
        firecracker: None,
        qemu: None,
        extra_args: vec![],
        guest_cid: 3,
    };
    println!("VirtualBox on NEM (Windows hypervisor running): {}", seagent_vm::provider::vbox::nem_host());
    let t0 = Instant::now();
    let mut inst = VboxProvider::new(&cfg).start(&spec).unwrap_or_else(|e| panic!("{e}"));
    let started = t0.elapsed();
    // Whatever happens below, the VM is powered off and unregistered before the test ends.
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    if let Err(e) = wait_for_kernel(&spec, t0) {
        panic!("{e}");
    }
    println!("VirtualBox: kernel running after {} ms", t0.elapsed().as_millis());
    // Windows: COM2 is a named pipe any local process can open, so the guest holds a per-boot
    // key (its SMBIOS serial). Play the squatter first: it sees the challenge, its command is
    // refused, a forged proof fails — then the real host authenticates.
    if cfg!(windows) {
        let rogue = Channel::connect(&spec.channel_path(), Transport::Uart, BOOT_WAIT).unwrap_or_else(|e| panic!("squatter connect: {e}"));
        let deadline = Instant::now() + BOOT_WAIT;
        loop {
            match rogue.recv(Duration::from_secs(1)).unwrap() {
                Some(GuestMsg::Hello { nonce, .. }) => {
                    assert!(nonce.is_some_and(|n| n.len() == 32), "a keyed guest offers a challenge");
                    break;
                }
                Some(_) => {}
                None => {
                    assert!(Instant::now() < deadline, "no Hello on the pipe");
                    rogue.send(&HostMsg::Ping { id: 0 }).unwrap();
                }
            }
        }
        println!("VirtualBox: Hello (to the squatter) after {} ms", t0.elapsed().as_millis());
        rogue.send(&HostMsg::Exec { id: 77, script: "echo pwned > /tmp/pwned".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 10 }).unwrap();
        let refused = loop {
            match rogue.expect(FRAME_WAIT, "refusal").unwrap() {
                GuestMsg::Err { id: 77, message } => break message,
                GuestMsg::Exit { id: 77, .. } | GuestMsg::Out { id: 77, .. } => panic!("an unauthenticated Exec ran"),
                _ => continue,
            }
        };
        assert!(refused.contains("not authenticated"), "{refused}");
        rogue.send(&HostMsg::Auth { nonce: "00".repeat(16), mac: "11".repeat(32) }).unwrap();
        loop {
            match rogue.expect(FRAME_WAIT, "auth refusal").unwrap() {
                GuestMsg::Err { message, .. } if message.contains("authentication failed") => break,
                GuestMsg::Auth { .. } => panic!("the guest accepted a forged proof"),
                _ => continue,
            }
        }
        rogue.shutdown();
        drop(rogue);
        std::thread::sleep(Duration::from_millis(500));
    }
    let ch = inst.connect(BOOT_WAIT).unwrap_or_else(|e| panic!("{e}\n--- console ---\n{}", std::fs::read_to_string(spec.console_log()).unwrap_or_default()));
    let hello = ch.expect(BOOT_WAIT, "Hello").unwrap();
    let boot = t0.elapsed();
    match &hello {
        GuestMsg::Hello { uid, transport, .. } => assert_eq!((*uid, transport.as_str()), (proto::AGENT_UID, "uart"), "COM2 channel, agent uid"),
        other => panic!("{other:?}"),
    }
    println!("VirtualBox: VM configured+started in {} ms, Hello after {} ms", started.as_millis(), boot.as_millis());
    ch.send(&HostMsg::Exec { id: 1, script: "id -u; uname -r; exit 4".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 30 }).unwrap();
    let (out, code) = until_exit(&ch, 1);
    assert!(out.contains("1000"), "{out}");
    assert_eq!(code, Some(4), "the exit code comes back over COM2");
    if cfg!(windows) {
        ch.send(&HostMsg::Exec { id: 2, script: format!("test -e /tmp/pwned; echo rc=$?; cat {} 2>&1 | head -c 300; echo", proto::DMI_KEY_FILE), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 10 }).unwrap();
        let (out, _) = until_exit(&ch, 2);
        assert!(out.contains("rc=1") && out.contains("Permission denied"), "the squatter's command never ran, and uid 1000 cannot read the key: {out}");
    }
    let mut rt = Vec::new();
    for i in 0..10 {
        let t = Instant::now();
        ch.send(&HostMsg::Exec { id: 10 + i, script: "true".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 10 }).unwrap();
        assert_eq!(until_exit(&ch, 10 + i).1, Some(0));
        rt.push(t.elapsed());
    }
    rt.sort();
    println!("VirtualBox exec round trip: median {:?}", rt[rt.len() / 2]);
    let t = Instant::now();
    ch.shutdown();
    while inst.is_running() && t.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let clean = !inst.is_running();
    if !clean {
        let c = std::fs::read_to_string(spec.console_log()).unwrap_or_default();
        let lines: Vec<&str> = c.lines().filter(|l| !l.trim().is_empty()).collect();
        println!("--- console tail ---\n{}", lines[lines.len().saturating_sub(12)..].join("\n"));
    }
    println!("VirtualBox shutdown: {} in {} ms", if clean { "guest powered off" } else { "NOT stopped" }, t.elapsed().as_millis());
    clean
    }));
    let t = Instant::now();
    inst.stop();
    println!("VirtualBox: poweroff + unregistervm --delete took {} ms", t.elapsed().as_millis());
    let _ = std::fs::remove_dir_all(&run);
    match body {
        Ok(clean) => assert!(clean, "Shutdown must end the VM"),
        Err(p) => std::panic::resume_unwind(p),
    }
}
