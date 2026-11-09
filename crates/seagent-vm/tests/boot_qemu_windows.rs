//! The Windows counterpart of `boot_vm.rs` / `boot_pool.rs` (which are Firecracker/QEMU-KVM on
//! Linux): the same guest image booted by the Windows substitute, **QEMU + WHPX** (or QEMU under
//! TCG, warned, when the Windows Hypervisor Platform is off), with the guest channel on a
//! 127.0.0.1 TCP chardev and the VMM inside a Job Object.
//!
//! Fast tests (always run on Windows, no VM): what this host selects and why (Hyper-V on a Home
//! edition, WHPX probed through `WinHvPlatform.dll`).
//!
//! Slow tests (`#[ignore]`, need QEMU for Windows and a built x86_64 image with a PCI kernel —
//! `packaging/vm/build-image.sh --build-kernel`):
//!
//! ```text
//! set SEAGENT_VM_IMAGE_DIR=C:\path\to\seagent-vm-image     (vmlinux, initramfs.cpio.gz, manifest.json)
//! cargo test -p seagent-vm --test boot_qemu_windows -- --ignored --nocapture
//! ```
//!
//! Without `SEAGENT_VM_IMAGE_DIR` or without `qemu-system-x86_64` (PATH or
//! `C:\Program Files\qemu`) they print why and return.
#![cfg(windows)]

use base64::Engine as _;
use seagent_vm::channel::{Channel, Transport};
use seagent_vm::config::VmConfig;
use seagent_vm::host::{self, Accel};
use seagent_vm::isolation::{Capabilities, ProviderKind};
use seagent_vm::limits::Limits;
use seagent_vm::pool::{VmExec, VmManager};
use seagent_vm::proto::{self, FileBlob, GuestMsg, HostMsg};
use seagent_vm::provider::qemu::QemuProvider;
use seagent_vm::provider::{self, VmProvider, VmSpec, Workspace};
use seagent_vm::trust::TrustTier;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;
/// TCG boots this kernel in about a second, WHPX in half of that; this is the failure line.
const BOOT_WAIT: Duration = Duration::from_secs(60);
const FRAME_WAIT: Duration = Duration::from_secs(30);

// ── fast: this host's selection ─────────────────────────────────────────────

#[test]
fn this_windows_host_picks_qemu_with_whpx_or_tcg_and_explains_hyperv() {
    let caps = Capabilities::detect(None, None);
    assert_eq!(caps.os, host::HostOs::Windows);
    assert_eq!(caps.whpx, host::whpx_available());
    assert!(caps.firecracker.is_none() && !caps.kvm, "no Linux VMM is ever reported on Windows");
    // Hyper-V is either installed or comes with its reason (never a bare "missing").
    assert_eq!(caps.hyperv.is_none(), caps.hyperv_blocker.is_some(), "{:?}", caps.hyperv_blocker);
    if host::windows_edition().as_deref().is_some_and(host::is_home_edition) {
        assert!(caps.hyperv.is_none() && caps.hyperv_blocker.as_deref().unwrap().contains("Windows Home"));
    }
    // With an image, QEMU is usable whenever it is installed — under WHPX when the platform
    // feature is on, otherwise TCG — and `auto` takes it first when it is hardware-backed.
    let with_image = Capabilities { kernel: Some("C:\\img\\vmlinux".into()), initramfs: Some("C:\\img\\initramfs.cpio.gz".into()), ..caps };
    match &with_image.qemu {
        Some(q) => {
            let want = if with_image.whpx { Accel::Whpx } else { Accel::Tcg };
            assert_eq!(with_image.usable(ProviderKind::Qemu), Some(want), "{}", q.display());
            let (k, note) = provider::select(&VmConfig::default(), &with_image);
            if want == Accel::Whpx {
                assert_eq!(k, ProviderKind::Qemu);
                assert!(note.unwrap().contains("127.0.0.1"), "the loopback channel is disclosed");
            } else if with_image.hyperv.is_none() && with_image.vbox.is_none() {
                assert_eq!(k, ProviderKind::Qemu);
                assert!(note.unwrap().contains("WITHOUT hardware acceleration"));
            }
        }
        None => assert_eq!(with_image.usable(ProviderKind::Qemu), None),
    }
}

// ── slow: a real VM ─────────────────────────────────────────────────────────

fn image_dir() -> Option<PathBuf> {
    let d = std::env::var_os("SEAGENT_VM_IMAGE_DIR").map(PathBuf::from)?;
    (d.join("vmlinux").is_file() && d.join("initramfs.cpio.gz").is_file()).then_some(d)
}

fn ready() -> Option<PathBuf> {
    let Some(img) = image_dir() else {
        eprintln!("SKIP: set SEAGENT_VM_IMAGE_DIR to a built x86_64 image (packaging/vm/build-image.sh --build-kernel)");
        return None;
    };
    if host::find_tool(host::native_qemu()).is_none() {
        eprintln!("SKIP: qemu-system-x86_64 not found (winget install SoftwareFreedomConservancy.QEMU)");
        return None;
    }
    Some(img)
}

/// A self-cleaning run dir; keep the guard alive for the whole test.
fn scratch(tag: &str) -> (seagent_core::tmp::TempDir, PathBuf) {
    let g = seagent_core::tmp::TempDir::new(&format!("seagent-winvm-{tag}"));
    let d = g.path().to_path_buf();
    (g, d)
}

fn spec(id: &str, image: &Path, run_dir: PathBuf) -> VmSpec {
    VmSpec {
        id: id.into(),
        tier: "owner".into(),
        kernel: image.join("vmlinux"),
        initramfs: image.join("initramfs.cpio.gz"),
        run_dir,
        vcpu: 2,
        mem_mb: 512,
        workspace: Some(Workspace { host: PathBuf::from(r"C:\nonexistent\seagent"), guest: proto::GUEST_WORKSPACE.into(), read_only: false }),
        limits: Limits::default(),
        transport: Transport::Serial,
        firecracker: None,
        qemu: None,
        extra_args: vec![],
        guest_cid: 3,
    }
}

fn until_exit(ch: &Channel, id: u64) -> (String, Option<i32>, Option<i32>) {
    let mut out = Vec::new();
    loop {
        match ch.recv(FRAME_WAIT).unwrap() {
            Some(GuestMsg::Out { id: i, data }) if i == id => out.extend(B64.decode(data.as_bytes()).unwrap()),
            Some(GuestMsg::Exit { id: i, code, signal }) if i == id => return (String::from_utf8_lossy(&out).into_owned(), code, signal),
            Some(GuestMsg::Err { id: i, message }) if i == id => panic!("exec {id}: {message}"),
            Some(_) => continue,
            None => panic!("exec {id}: no Exit within {FRAME_WAIT:?}"),
        }
    }
}

fn exec(id: u64, script: &str, timeout_secs: u64) -> HostMsg {
    HostMsg::Exec { id, script: script.into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs }
}

/// The provider alone: boot, `Hello` as uid 1000, commands with stdout and exit codes, file sync
/// both ways, the guest's own timeout, and `Shutdown` → the guest powers off and QEMU exits.
#[test]
#[ignore = "boots a real VM: needs QEMU for Windows and SEAGENT_VM_IMAGE_DIR"]
fn boots_qemu_whpx_and_runs_a_command() {
    let Some(image) = ready() else { return };
    let cfg = VmConfig::default();
    let p = QemuProvider::new(&cfg);
    println!("accelerator: {} ({})", p.accel().name(), p.accel().label());
    let (_scratch, run) = scratch("provider");
    let sp = spec("winvm-1", &image, run.clone());
    let t0 = Instant::now();
    let mut inst = p.start(&sp).unwrap_or_else(|e| panic!("{e}"));
    assert!(inst.pid().is_some_and(host::pid_alive), "the VMM runs");
    // The endpoint record names a loopback port, never a unix socket.
    let rec = std::fs::read_to_string(sp.channel_path()).unwrap();
    assert!(rec.starts_with("tcp:127.0.0.1:"), "{rec}");

    // A squatter: another local process reaches the loopback port first. It gets the guest's
    // challenge, but the agent refuses to run anything for it, and a forged proof fails.
    let boot;
    {
        let rogue = Channel::connect(&sp.channel_path(), Transport::Serial, BOOT_WAIT).unwrap();
        match rogue.expect(BOOT_WAIT, "Hello").unwrap_or_else(|e| panic!("{e}\n{}", std::fs::read_to_string(sp.console_log()).unwrap_or_default())) {
            GuestMsg::Hello { nonce, .. } => assert!(nonce.is_some_and(|n| n.len() == 32), "a keyed guest offers a challenge"),
            other => panic!("{other:?}"),
        }
        boot = t0.elapsed();
        rogue.send(&exec(77, "echo pwned > /tmp/pwned", 10)).unwrap();
        match rogue.expect(FRAME_WAIT, "refusal").unwrap() {
            GuestMsg::Err { id: 77, message } => assert!(message.contains("not authenticated"), "{message}"),
            other => panic!("an unauthenticated Exec was answered with {other:?}"),
        }
        rogue.send(&HostMsg::Auth { nonce: "00".repeat(16), mac: "11".repeat(32) }).unwrap();
        let refused = loop {
            match rogue.expect(FRAME_WAIT, "auth refusal").unwrap() {
                GuestMsg::Err { message, .. } if message.contains("authentication failed") => break message,
                GuestMsg::Auth { .. } => panic!("the guest accepted a forged proof"),
                _ => continue,
            }
        };
        println!("squatter refused: {refused}");
        rogue.shutdown();
    }
    std::thread::sleep(Duration::from_millis(200));
    // The real host: authenticates (the guest repeats its challenge for the new peer).
    let t = Instant::now();
    let ch = inst.connect(BOOT_WAIT).unwrap_or_else(|e| panic!("{e}\n{}", std::fs::read_to_string(sp.console_log()).unwrap_or_default()));
    println!("authenticated after the squatter left in {} ms", t.elapsed().as_millis());
    let hello = ch.expect(BOOT_WAIT, "Hello").unwrap_or_else(|e| panic!("{e}\n{}", std::fs::read_to_string(sp.console_log()).unwrap_or_default()));
    assert!(!proto::FW_CFG_KEY.is_empty() && !seagent_vm::provider::qemu::channel_key_path(&sp).exists(), "the key file is gone once the channel is authenticated");
    match &hello {
        GuestMsg::Hello { version, uid, transport, kernel, .. } => {
            assert_eq!((*version, *uid, transport.as_str()), (proto::VERSION, proto::AGENT_UID, "virtio-serial"), "{kernel}");
        }
        other => panic!("first frame {other:?}"),
    }
    println!("Hello after {} ms", boot.as_millis());

    ch.send(&exec(1, "echo SEAGENT_GUEST_OK; id -u; hostname; pwd; ls /dev/kvm 2>&1 | tail -1; exit 3", 30)).unwrap();
    let (out, code, _) = until_exit(&ch, 1);
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(&lines[..4], &["SEAGENT_GUEST_OK", "1000", "winvm-1", proto::GUEST_WORKSPACE], "{out}");
    assert!(out.contains("No such file"), "no /dev/kvm in the guest: {out}");
    assert_eq!(code, Some(3), "the guest command's exit code comes back");
    ch.send(&exec(70, &format!("test -e /tmp/pwned; echo rc=$?; cat {} 2>&1 | head -c 300; echo", proto::FW_CFG_KEY), 10)).unwrap();
    let (out, _, _) = until_exit(&ch, 70);
    assert!(out.contains("rc=1"), "the squatter's command never ran: {out}");
    assert!(out.contains("Permission denied"), "the agent user cannot read the channel key: {out}");

    ch.send(&HostMsg::Push { id: 2, files: vec![FileBlob { path: "src/a.txt".into(), data: B64.encode(b"from windows\r\n"), mode: 0o644 }] }).unwrap();
    assert!(matches!(ch.expect(FRAME_WAIT, "push ack").unwrap(), GuestMsg::Ok { id: 2, .. }));
    ch.send(&exec(3, "cat src/a.txt | od -c | head -1; echo back > b.txt", 30)).unwrap();
    let (out, code, _) = until_exit(&ch, 3);
    assert_eq!(code, Some(0));
    assert!(out.contains(r"\r  \n"), "bytes arrive unchanged (no newline translation on the way): {out}");
    ch.send(&HostMsg::Pull { id: 4, paths: vec!["b.txt".into()] }).unwrap();
    match ch.expect(FRAME_WAIT, "files").unwrap() {
        GuestMsg::Files { id: 4, files } => assert_eq!(B64.decode(files[0].data.as_bytes()).unwrap(), b"back\n"),
        other => panic!("{other:?}"),
    }

    // Round-trip latency of a trivial command over the TCP chardev.
    let mut rt = Vec::new();
    for i in 0..20 {
        let t = Instant::now();
        ch.send(&exec(100 + i, "true", 10)).unwrap();
        assert_eq!(until_exit(&ch, 100 + i).1, Some(0));
        rt.push(t.elapsed());
    }
    rt.sort();
    println!("exec round trip: median {:?}, max {:?}", rt[rt.len() / 2], rt[rt.len() - 1]);
    assert!(rt[rt.len() / 2] < Duration::from_millis(150), "no Nagle / delayed-ACK stall on the channel: {rt:?}");

    ch.send(&exec(5, "sleep 30", 1)).unwrap();
    assert_eq!(until_exit(&ch, 5).2, Some(15), "the guest enforces timeout_secs with SIGTERM");

    // Orderly shutdown: the agent powers the VM off and QEMU (-no-reboot) exits by itself.
    let t = Instant::now();
    ch.shutdown();
    while inst.is_running() && t.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(25));
    }
    let clean = !inst.is_running();
    println!("shutdown: {} in {} ms", if clean { "guest powered off" } else { "NOT stopped" }, t.elapsed().as_millis());
    inst.stop();
    assert!(clean, "Shutdown must end the VM");
    assert!(!sp.channel_path().exists(), "stop() removes the endpoint record");
    let _ = std::fs::remove_dir_all(&run);
}

/// The pool on Windows (`boot_pool.rs` counterpart): a workspace copy in and out, an undo point
/// before a destructive command and its restore, separate VMs per trust tier, and an orderly
/// `shutdown_all`.
#[test]
#[ignore = "boots real VMs: needs QEMU for Windows and SEAGENT_VM_IMAGE_DIR"]
fn the_pool_syncs_snapshots_and_separates_tiers_under_qemu_whpx() {
    let Some(image) = ready() else { return };
    let (_scratch, root) = scratch("pool");
    let (data, ws) = (root.join("data"), root.join("ws"));
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("precious.txt"), "do not lose me\n").unwrap();
    let cfg = VmConfig {
        provider: "qemu".into(),
        allow_fallback: false,
        kernel: image.join("vmlinux").display().to_string(),
        initramfs: image.join("initramfs.cpio.gz").display().to_string(),
        image_dir: data.join("vm").display().to_string(),
        memory_mb: 512,
        vcpu: 2,
        snapshot_keep: 4,
        ..Default::default()
    };
    let m = VmManager::new(cfg, data.clone());
    let (kind, note) = m.selection();
    assert_eq!(kind, ProviderKind::Qemu, "{note:?}");
    let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "id -u; cat precious.txt; echo made > made.txt")).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.text());
    assert!(out.text().contains("1000") && out.text().contains("do not lose me"), "{}", out.text());
    assert_eq!(std::fs::read_to_string(ws.join("made.txt")).unwrap().trim(), "made", "guest writes come home");

    let out = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "rm -rf * ; echo wiped")).unwrap();
    let snap = out.snapshot.expect("a destructive command is snapshotted first");
    assert!(ws.join("precious.txt").exists(), "H1: deletions in the VM never reach the host");
    std::fs::remove_file(ws.join("precious.txt")).unwrap();
    let r = m.restore("s1", TrustTier::Owner, &ws, None).unwrap();
    assert_eq!((r.name.as_str(), std::fs::read_to_string(ws.join("precious.txt")).unwrap().as_str()), (snap.name.as_str(), "do not lose me\n"));

    let o = m.exec(&VmExec::new("s1", TrustTier::Owner, &ws, "hostname")).unwrap();
    let s = m.exec(&VmExec::new("s1", TrustTier::Stranger, &ws, "hostname")).unwrap();
    assert_ne!(o.text(), s.text(), "B5: one VM per trust tier");
    assert_eq!(m.status().len(), 2);
    let ended = m.shutdown_all(Duration::from_secs(15));
    assert_eq!(ended.len(), 2);
    assert!(ended.iter().all(|(_, clean)| *clean), "both guests powered off on Shutdown: {ended:?}");
    assert!(m.status().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

/// The VirtualBox / Hyper-V channel shape, reproduced with QEMU so it runs on any Windows host
/// with QEMU (VirtualBox is not needed): UEFI boots `disk.raw` (baked command line,
/// `seagent.channel=uart`), COM2 is a **named pipe** served by the VMM, and the per-boot key
/// arrives as the SMBIOS system serial (`sgk-<hex>`, what `provider::vbox::key_command` /
/// the Hyper-V script set). A squatter on the pipe is refused; the real host authenticates.
#[test]
#[ignore = "boots a real VM: needs QEMU for Windows (with its edk2 firmware) and SEAGENT_VM_IMAGE_DIR with disk.raw"]
fn a_named_pipe_uart_channel_is_keyed_through_the_dmi_serial() {
    let Some(image) = ready() else { return };
    let Some(qemu) = host::find_tool(host::native_qemu()) else { return };
    let code = qemu.parent().unwrap().join("share").join("edk2-x86_64-code.fd");
    if !image.join("disk.raw").is_file() || !code.is_file() {
        eprintln!("SKIP: needs disk.raw and {}", code.display());
        return;
    }
    let accel = if host::whpx_available() { "whpx,kernel-irqchip=off" } else { "tcg" };
    let key = proto::random_hex(16);
    // One VM per phase: QEMU's Windows pipe chardev accepts a single client per boot (after a
    // squatter lets go the pipe stays busy — a denial of service, never an impersonation).
    let boot = |tag: &str| {
        let (_scratch, run) = scratch(tag);
        let vars = run.join("vars.fd");
        std::fs::copy(qemu.parent().unwrap().join("share").join("edk2-i386-vars.fd"), &vars).unwrap();
        let pipe = format!("seagent-dmitest-{tag}-{}", std::process::id());
        let rec = run.join("chan.sock");
        seagent_vm::channel::Endpoint::allocate_pipe(&rec, &pipe).unwrap();
        let child = std::process::Command::new(&qemu)
            .args(["-M", "q35", "-accel", accel, "-cpu", "max", "-smp", "2", "-m", "512", "-display", "none", "-nodefaults", "-no-reboot", "-net", "none"])
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={}", code.display()))
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()))
            .arg("-drive")
            .arg(format!("file={},format=raw,if=virtio,readonly=on", image.join("disk.raw").display()))
            .arg("-smbios")
            .arg(format!("type=1,serial={}{key}", proto::DMI_KEY_PREFIX))
            .arg("-serial")
            .arg(format!("file:{}", run.join("console.log").display()))
            .args(["-chardev", &format!("pipe,id=com2,path={pipe}"), "-serial", "chardev:com2"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        (child, rec, run)
    };
    let hello_on = |ch: &Channel, run: &Path| {
        let deadline = Instant::now() + BOOT_WAIT;
        loop {
            match ch.recv(Duration::from_secs(1)).unwrap() {
                Some(m @ GuestMsg::Hello { .. }) => return m,
                Some(_) => {}
                None => {
                    assert!(Instant::now() < deadline, "no Hello on the pipe\n{}", std::fs::read_to_string(run.join("console.log")).unwrap_or_default());
                    ch.send(&HostMsg::Ping { id: 0 }).unwrap();
                }
            }
        }
    };
    let finish = |mut child: std::process::Child, run: PathBuf, result: std::thread::Result<()>, wait_exit: bool| {
        let t = Instant::now();
        while wait_exit && matches!(child.try_wait(), Ok(None)) && t.elapsed() < Duration::from_secs(15) {
            std::thread::sleep(Duration::from_millis(25));
        }
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&run);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        exited
    };

    // Phase 1: a squatter holds the pipe. It sees the challenge; its command and its forged
    // proof are refused, and its leaving does not power the VM off.
    let (child, rec, run) = boot("dmisquat");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rogue = Channel::connect(&rec, Transport::Uart, BOOT_WAIT).unwrap_or_else(|e| panic!("{e}"));
        match hello_on(&rogue, &run) {
            GuestMsg::Hello { nonce, transport, .. } => assert!(transport == "uart" && nonce.is_some(), "the DMI serial made the guest keyed"),
            _ => unreachable!(),
        }
        rogue.send(&exec(77, "echo pwned > /tmp/pwned", 10)).unwrap();
        loop {
            match rogue.expect(FRAME_WAIT, "refusal").unwrap() {
                GuestMsg::Err { id: 77, message } => break assert!(message.contains("not authenticated"), "{message}"),
                GuestMsg::Exit { id: 77, .. } => panic!("an unauthenticated Exec ran"),
                _ => continue,
            }
        }
        rogue.send(&HostMsg::Auth { nonce: "00".repeat(16), mac: "11".repeat(32) }).unwrap();
        loop {
            match rogue.expect(FRAME_WAIT, "auth refusal").unwrap() {
                GuestMsg::Err { message, .. } if message.contains("authentication failed") => break,
                GuestMsg::Auth { .. } => panic!("the guest accepted a forged proof"),
                _ => continue,
            }
        }
        drop(rogue);
        std::thread::sleep(Duration::from_secs(1));
    }));
    let exited = finish(child, run, r, false);
    assert!(!exited, "an unauthenticated peer leaving must not power the VM off");

    // Phase 2: the real host, with the key the provider set as the serial.
    let t0 = Instant::now();
    let (child, rec, run) = boot("dmihost");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ch = Channel::connect(&rec, Transport::Uart, BOOT_WAIT).unwrap_or_else(|e| panic!("{e}"));
        ch.authenticate(key.as_bytes(), BOOT_WAIT).unwrap_or_else(|e| panic!("{e}\n{}", std::fs::read_to_string(run.join("console.log")).unwrap_or_default()));
        println!("UEFI disk + named-pipe COM2 ({accel}): authenticated Hello after {} ms", t0.elapsed().as_millis());
        assert!(matches!(ch.expect(FRAME_WAIT, "Hello").unwrap(), GuestMsg::Hello { .. }));
        ch.send(&exec(1, &format!("id -u; cat {} 2>&1 | head -c 200; echo; exit 5", proto::DMI_KEY_FILE), 10)).unwrap();
        let (out, code, _) = until_exit(&ch, 1);
        assert!(out.contains("1000") && out.contains("Permission denied"), "uid 1000 cannot read the key: {out}");
        assert_eq!(code, Some(5));
        let mut rt = Vec::new();
        for i in 0..10 {
            let t = Instant::now();
            ch.send(&exec(10 + i, "true", 10)).unwrap();
            until_exit(&ch, 10 + i);
            rt.push(t.elapsed());
        }
        rt.sort();
        println!("uart-over-pipe exec round trip: median {:?}", rt[rt.len() / 2]);
        ch.shutdown();
    }));
    assert!(finish(child, run, r, true), "Shutdown powers the guest off");
}