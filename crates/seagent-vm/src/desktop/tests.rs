//! Desktop VM lifecycle, frames and input against a fake `qemu-system-x86_64` on disk and a
//! fake QMP server — no KVM, no image download.

use super::fake::{fake_qemu, FakeQmp};
use super::*;

struct Env {
    dir: seagent_core::tmp::TempDir,
    vms: DesktopVms,
}

fn env(tag: &str) -> Env {
    let dir = seagent_core::tmp::TempDir::new(&format!("seagent-dvm-{tag}"));
    let (q, img) = fake_qemu(&dir.join("bin"));
    let cfg = DesktopConfig { qemu: q.display().to_string(), qemu_img: img.display().to_string(), stop_timeout_secs: 1, ..Default::default() };
    let vms = DesktopVms::new(cfg, &dir.join("data"), &dir.join("cache"), &dir.join("run"));
    Env { dir, vms }
}

fn fake_image(v: &DesktopVms) {
    std::fs::create_dir_all(v.image_dir()).unwrap();
    std::fs::write(v.image_path(), b"qcow2").unwrap();
    std::fs::write(v.image_path().with_extension("json"), "{}").unwrap();
}

/// Bind the fake QMP server once the fake qemu "daemonized" (as the real one creates the socket).
fn qmp_after_spawn(e: &Env, w: u32, h: u32) -> std::thread::JoinHandle<FakeQmp> {
    let (marker, sock) = (e.dir.join("bin/spawned"), e.vms.qmp_path("desk"));
    std::thread::spawn(move || {
        let t0 = Instant::now();
        while !marker.exists() && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        FakeQmp::start(&sock, w, h)
    })
}

#[test]
fn lifecycle_frames_and_input_over_qmp() {
    let e = env("life");
    let v = &e.vms;
    assert!(v.start("desk").unwrap_err().contains("seagent vm desktop build"), "no image yet");
    assert!(v.start("Bad Name").is_err());
    fake_image(v);
    let th = qmp_after_spawn(&e, 1024, 768);
    let st = v.start("desk").unwrap();
    let qmp = th.join().unwrap();
    assert!(st.running && st.pid.is_some() && st.disk_exists, "{st:?}");
    assert_eq!((st.width, st.height), (1280, 800), "configured size until a frame says otherwise");
    let args = std::fs::read_to_string(e.dir.join("bin/qemu.args")).unwrap();
    for want in ["q35,accel=", "usb-tablet,bus=xhci.0", "VGA,xres=1280,yres=800,edid=on", "-daemonize", "user,id=n0", "seagent-res=1280x800", &format!("unix:{},server=on,wait=off", v.qmp_path("desk").display()), &format!("unix:{}", v.vnc_path("desk").display())] {
        assert!(args.contains(want), "missing {want} in {args}");
    }
    assert!(v.start("desk").unwrap().running, "start is idempotent");
    assert_eq!(v.list().iter().filter(|s| s.running).count(), 1);

    // Frames: PNG via screendump; the real framebuffer size is learnt from it.
    let png = v.screenshot("desk").unwrap();
    assert_eq!(qmp::png_size(&png), Some((1024, 768)));
    assert_eq!(v.status("desk").width, 1024);
    assert!(std::fs::read_dir(v.run_dir("desk")).unwrap().flatten().all(|f| !f.file_name().to_string_lossy().starts_with("frame-")), "the temp frame is removed");

    // Input in screen pixels → absolute tablet coordinates + button / key events.
    v.input("desk", &Input::from_json(&json!({"type": "click", "x": 1023, "y": 0, "button": "right"})).unwrap()).unwrap();
    let r = v.input("desk", &Input::from_json(&json!({"type": "type", "text": "Hi!"})).unwrap()).unwrap();
    assert_eq!(r["typed"], 3);
    v.input("desk", &Input::from_json(&json!({"type": "key", "key": "Control+a"})).unwrap()).unwrap();
    v.input("desk", &Input::from_json(&json!({"type": "scroll", "x": 10, "y": 10, "dy": -2})).unwrap()).unwrap();
    let ev = qmp.events();
    assert!(ev.contains(&json!({"type": "abs", "data": {"axis": "x", "value": qmp::ABS_MAX}})), "{ev:?}");
    assert!(ev.contains(&json!({"type": "abs", "data": {"axis": "y", "value": 0}})));
    assert!(ev.contains(&json!({"type": "btn", "data": {"down": true, "button": "right"}})) && ev.contains(&json!({"type": "btn", "data": {"down": false, "button": "right"}})));
    let keys: Vec<(String, bool)> = ev.iter().filter(|e| e["type"] == "key").map(|e| (e["data"]["key"]["data"].as_str().unwrap().to_string(), e["data"]["down"].as_bool().unwrap())).collect();
    let k = |s: &str, d: bool| (s.to_string(), d);
    assert_eq!(&keys[..4], &[k("shift", true), k("h", true), k("h", false), k("shift", false)], "upper-case = shift + key");
    assert!(keys.windows(2).any(|w| w == [k("ctrl", true), k("a", true)]), "{keys:?}");
    assert_eq!(ev.iter().filter(|e| e["data"]["button"] == "wheel-up" && e["data"]["down"] == true).count(), 2);
    // Non-ASCII text goes over the guest text channel (base64 line), not key events.
    assert!(v.input("desk", &Input::Type { text: "日本".into() }).unwrap_err().contains("text channel"), "no guest port yet");
    let l = std::os::unix::net::UnixListener::bind(v.text_path("desk")).unwrap();
    // The guest helper: read one line, answer "ok".
    let guest = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(&c), &mut line).unwrap();
        std::io::Write::write_all(&mut &c, b"ok\n").unwrap();
        line
    });
    let r = v.input("desk", &Input::Type { text: "繁體中文 ok".into() }).unwrap();
    assert_eq!((r["typed"].as_u64(), r["via"].as_str()), (Some(7), Some("text-channel")));
    let line = guest.join().unwrap();
    use base64::Engine as _;
    assert_eq!(base64::engine::general_purpose::STANDARD.decode(line.trim()).unwrap(), "繁體中文 ok".as_bytes());
    // A newline in pasted text is an Enter key press (pasting it would not submit a form or an
    // address bar): each line over the channel, Enter over QMP in between.
    let _ = std::fs::remove_file(v.text_path("desk"));
    let l = std::os::unix::net::UnixListener::bind(v.text_path("desk")).unwrap();
    let guest = std::thread::spawn(move || {
        let mut lines = vec![];
        for _ in 0..2 {
            let (c, _) = l.accept().unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&c), &mut line).unwrap();
            std::io::Write::write_all(&mut &c, b"ok\n").unwrap();
            lines.push(base64::engine::general_purpose::STANDARD.decode(line.trim()).unwrap());
        }
        lines
    });
    let before = qmp.events().iter().filter(|e| e["type"] == "key" && e["data"]["key"]["data"] == "ret").count();
    let r = v.input("desk", &Input::Type { text: "瑞士\n中文".into() }).unwrap();
    assert_eq!(r["typed"].as_u64(), Some(5), "{r}");
    assert_eq!(guest.join().unwrap(), vec!["瑞士".as_bytes().to_vec(), "中文".as_bytes().to_vec()]);
    let after = qmp.events().iter().filter(|e| e["type"] == "key" && e["data"]["key"]["data"] == "ret").count();
    assert_eq!(after - before, 2, "one Enter (down + up) between the lines");
    assert!(args.contains("virtserialport,chardev=seagenttext,name=org.seagent.text"), "{args}");
    // The guest Chromium's DevTools relay is forwarded to host loopback only, and named for
    // seagent's browser tools while the VM runs.
    let cdp = v.status("desk").cdp.expect("a running VM offers its browser");
    let port = cdp.strip_prefix("http://127.0.0.1:").unwrap();
    assert!(args.contains(&format!("user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:9223")), "{args}");
    assert_eq!(std::fs::read_to_string(v.vm_dir("desk").join(super::CDP_FILE)).unwrap().trim(), cdp);

    // Stop: ACPI power-off, then quit, then the process is gone and the run dir is clean.
    assert!(v.stop("desk").unwrap());
    let cmds = qmp.commands();
    assert!(cmds.contains(&"system_powerdown".to_string()) && cmds.contains(&"quit".to_string()), "{cmds:?}");
    assert!(!v.status("desk").running);
    assert!(!v.vm_dir("desk").join(super::CDP_FILE).exists(), "a stopped VM offers no browser");
    assert!(!v.qmp_path("desk").with_file_name("qemu.pid").exists());
    assert!(!v.stop("desk").unwrap(), "stopping a stopped VM is a no-op");
    assert!(v.screenshot("desk").unwrap_err().contains("not running"));
    assert!(v.vm_dir("desk").join("disk.qcow2").is_file(), "the disk overlay persists");
    drop(qmp);
}

#[test]
fn reap_cleans_dead_vms_and_stops_idle_ones() {
    let mut e = env("reap");
    e.vms.cfg.idle_timeout_secs = 1;
    fake_image(&e.vms);
    let th = qmp_after_spawn(&e, 800, 600);
    e.vms.start("desk").unwrap();
    let _qmp = th.join().unwrap();
    assert_eq!(e.vms.reap(), 0, "just used");
    std::fs::write(e.vms.run_dir("desk").join("last_used"), (now_s() - 5).to_string()).unwrap();
    assert_eq!(e.vms.reap(), 1, "idle past the timeout");
    assert!(!e.vms.is_running("desk"));
    // A stale pid file of a dead VM is cleared without counting as a stop.
    std::fs::write(e.vms.run_dir("desk").join("qemu.pid"), "999999").unwrap();
    assert_eq!(e.vms.reap(), 0);
    assert!(!e.vms.run_dir("desk").join("qemu.pid").exists());
}

#[test]
fn names_and_status_without_a_vm() {
    let e = env("names");
    assert_eq!(e.vms.names(), ["desk"]);
    let s = e.vms.status("desk");
    assert!(!s.running && !s.image_built && !s.disk_exists && s.pid.is_none(), "{s:?}");
    assert!(valid_name("a-1").is_ok() && valid_name("-a").is_err() && valid_name("A").is_err() && valid_name(&"a".repeat(33)).is_err());
    std::fs::create_dir_all(e.vms.vm_dir("work")).unwrap();
    assert_eq!(e.vms.names(), ["desk", "work"]);
}

/// A fake in-VM agent on the VM's channel socket: Hello on every connection, `Exec` answered
/// with `ran:<script>` and exit 0, `Ping` with `Pong`. Serves `conns` connections.
fn fake_agent_on(sock: &std::path::Path, conns: usize) -> std::thread::JoinHandle<()> {
    use crate::proto::{decode, encode, GuestMsg, HostMsg};
    use base64::Engine as _;
    use std::io::{Read, Write};
    let l = crate::channel::Endpoint::allocate(sock).unwrap().listen().unwrap();
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok(mut s) = l.accept() else { return };
            let hello = GuestMsg::Hello { version: 1, agent: "fake (service)".into(), kernel: "k".into(), cid: None, transport: "virtio-serial".into(), uid: 1000, nonce: None };
            let _ = s.write_all(&encode(&hello).unwrap());
            let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
            loop {
                let n = match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let (frames, used) = decode::<HostMsg>(&buf).unwrap();
                buf.drain(..used);
                for f in frames {
                    let out = match f {
                        HostMsg::Exec { id, script, .. } => {
                            let mut o = encode(&GuestMsg::Out { id, data: base64::engine::general_purpose::STANDARD.encode(format!("ran:{script}")) }).unwrap();
                            o.extend(encode(&GuestMsg::Exit { id, code: Some(0), signal: None }).unwrap());
                            o
                        }
                        HostMsg::Ping { id } => encode(&GuestMsg::Pong { id }).unwrap(),
                        _ => continue,
                    };
                    if s.write_all(&out).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

#[test]
fn the_agent_channel_is_on_the_vm_and_shared_by_every_caller() {
    let e = env("chan");
    let v = &e.vms;
    fake_image(v);
    let th = qmp_after_spawn(&e, 800, 600);
    v.start("desk").unwrap();
    let _qmp = th.join().unwrap();
    let args = std::fs::read_to_string(e.dir.join("bin/qemu.args")).unwrap();
    // Exactly the microVM provider's channel, on the VM's one virtio-serial bus.
    assert!(args.contains(&format!("socket,id=seagent0,path={},server=on,wait=off", v.chan_path("desk").display())), "{args}");
    assert!(args.contains("virtserialport,chardev=seagent0,name=seagent0"), "{args}");
    assert_eq!(args.matches("virtio-serial-pci").count(), 1, "one bus carries both ports");
    assert!(!args.contains("opt/seagent/key"), "a unix socket in the 0700 run dir needs no key");
    assert!(v.channel("nope", Duration::from_secs(1)).unwrap_err().contains("not running"));
    let guest = fake_agent_on(&v.chan_path("desk"), 2);
    let m = v.channel("desk", Duration::from_secs(5)).unwrap();
    assert!(matches!(m.hello(), Some(crate::proto::GuestMsg::Hello { uid: 1000, .. })));
    let out = m.run("uname -a", None, &[], None, Duration::from_secs(5)).unwrap();
    assert_eq!((out.code, String::from_utf8(out.output).unwrap().as_str()), (Some(0), "ran:uname -a"));
    assert!(Arc::ptr_eq(&m, &v.channel("desk", Duration::from_secs(5)).unwrap()), "one connection per running VM");
    // The connection goes away: the next caller gets a new one.
    m.shutdown();
    let m2 = v.channel("desk", Duration::from_secs(5)).unwrap();
    assert!(!Arc::ptr_eq(&m, &m2));
    assert_eq!(m2.run("id", None, &[], None, Duration::from_secs(5)).unwrap().output, b"ran:id");
    assert!(v.stop("desk").unwrap());
    assert!(!v.chan_path("desk").exists() && !m2.alive(), "stopping the VM drops its channel");
    drop(guest);
}

#[test]
fn a_windows_style_channel_carries_its_key_and_the_agent_by_fw_cfg() {
    let tcp = crate::channel::Endpoint::Tcp("127.0.0.1:40123".parse().unwrap());
    let a = channel_args(&tcp, std::path::Path::new("/r/chan.key"), Some(std::path::Path::new("/r/agent.bin")));
    let after = |flag: &str, n: usize| a.iter().enumerate().filter(|(_, x)| *x == flag).nth(n).map(|(i, _)| a[i + 1].clone()).unwrap();
    assert_eq!(after("-chardev", 0), "socket,id=seagent0,host=127.0.0.1,port=40123,server=on,wait=off,nodelay=on");
    assert_eq!(after("-device", 0), "virtserialport,chardev=seagent0,name=seagent0");
    assert_eq!(after("-fw_cfg", 0), "name=opt/seagent/key,file=/r/chan.key", "the key is a file, never a command-line value");
    assert_eq!(after("-fw_cfg", 1), "name=opt/seagent/agent,file=/r/agent.bin");
    let unix = channel_args(&crate::channel::Endpoint::Unix("/r/chan.sock".into()), std::path::Path::new("/r/chan.key"), None);
    assert!(!unix.iter().any(|x| x == "-fw_cfg"), "{unix:?}");
}

#[test]
fn an_overlay_from_an_image_without_the_agent_is_set_aside_once() {
    let e = env("stale");
    let v = &e.vms;
    fake_image(v);
    std::fs::write(v.image_path().with_extension("json"), r#"{"guest_agent": {"service": true}}"#).unwrap();
    assert!(v.image_has_agent());
    // A disk made from an older image (no agent service in its manifest).
    std::fs::create_dir_all(v.vm_dir("desk")).unwrap();
    let old = v.image_dir().join("desktop-old.qcow2");
    std::fs::write(&old, b"old").unwrap();
    std::fs::write(old.with_extension("json"), "{}").unwrap();
    std::fs::write(v.vm_dir("desk").join("disk.qcow2"), b"overlay").unwrap();
    std::fs::write(v.vm_dir("desk").join("state.json"), json!({"image": old.display().to_string()}).to_string()).unwrap();
    assert_eq!(v.stale_overlay("desk"), Some(old.clone()));
    let th = qmp_after_spawn(&e, 800, 600);
    let st = v.start("desk").unwrap();
    let _q = th.join().unwrap();
    assert_eq!(std::fs::read(v.vm_dir("desk").join("disk.qcow2.prev")).unwrap(), b"overlay", "the old disk is kept");
    assert!(st.warning.unwrap_or_default().contains("disk.qcow2.prev"));
    assert_eq!(v.stale_overlay("desk"), None, "now on the current image");
    v.stop("desk").unwrap();
    // An image without the agent never sets a disk aside.
    std::fs::write(v.image_path().with_extension("json"), "{}").unwrap();
    std::fs::write(v.vm_dir("desk").join("state.json"), json!({"image": old.display().to_string()}).to_string()).unwrap();
    assert_eq!(v.stale_overlay("desk"), None);
}
