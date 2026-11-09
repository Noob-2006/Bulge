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

const BOOT_WAIT: Duration = Duration::from_secs(120);
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
    let run = std::env::temp_dir().join(format!("seagent-vbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&run);
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
    let t0 = Instant::now();
    let mut inst = VboxProvider::new(&cfg).start(&spec).unwrap_or_else(|e| panic!("{e}"));
    let started = t0.elapsed();
    let ch = inst.connect(BOOT_WAIT).unwrap_or_else(|e| {
        let console = std::fs::read_to_string(spec.console_log()).unwrap_or_default();
        inst.stop();
        panic!("{e}\n--- console ---\n{console}")
    });
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
    println!("VirtualBox shutdown: {} in {} ms", if clean { "guest powered off" } else { "NOT stopped" }, t.elapsed().as_millis());
    inst.stop();
    let _ = std::fs::remove_dir_all(&run);
    assert!(clean, "Shutdown must end the VM");
}
