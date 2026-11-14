//! Test support (used by this crate's and seagent-app's tests): a fake QMP server on a unix
//! socket that answers like QEMU — greeting, `qmp_capabilities`, `screendump` (writes a PNG
//! header of the configured size to the requested file), `input-send-event`,
//! `system_powerdown` / `quit` — and records every command it received; plus a fake
//! `qemu-system-x86_64` script for lifecycle tests.

use serde_json::{json, Value};
use crate::channel::Endpoint;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A minimal PNG (signature + IHDR) of `w`×`h`: enough for size sniffing.
pub fn png_header(w: u32, h: u32) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    v.extend(w.to_be_bytes());
    v.extend(h.to_be_bytes());
    v.extend([8, 2, 0, 0, 0, 0, 0, 0, 0]);
    v
}

pub struct FakeQmp {
    pub path: PathBuf,
    /// Every command received (`{"execute": …, "arguments": …}`), in order.
    pub log: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl FakeQmp {
    pub fn start(path: &Path, w: u32, h: u32) -> FakeQmp {
        let _ = std::fs::remove_file(path);
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        // A unix socket at `path` (Windows: a loopback port recorded there), like real QEMU.
        let l = Endpoint::allocate(path).and_then(|e| e.listen().map_err(|e| e.to_string())).expect("bind fake QMP socket");
        l.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(vec![]));
        let stop = Arc::new(AtomicBool::new(false));
        let (lg, st) = (log.clone(), stop.clone());
        let th = std::thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                let Ok(c) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                let _ = c.set_nonblocking(false);
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let mut w_ = c.try_clone().unwrap();
                let _ = w_.write_all(b"{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 2, \"major\": 10}, \"package\": \"fake\"}, \"capabilities\": [\"oob\"]}}\r\n");
                for line in BufReader::new(c).lines() {
                    let Ok(line) = line else { break };
                    let Ok(m) = serde_json::from_str::<Value>(&line) else { break };
                    lg.lock().unwrap().push(m.clone());
                    let reply = match m["execute"].as_str().unwrap_or("") {
                        "qmp_capabilities" | "input-send-event" | "system_powerdown" | "quit" | "stop" | "cont" => json!({"return": {}}),
                        "screendump" => {
                            let f = m["arguments"]["filename"].as_str().unwrap_or("");
                            match std::fs::write(f, png_header(w, h)) {
                                Ok(_) => json!({"return": {}}),
                                Err(e) => json!({"error": {"class": "GenericError", "desc": e.to_string()}}),
                            }
                        }
                        o => json!({"error": {"class": "CommandNotFound", "desc": format!("The command {o} has not been found")}}),
                    };
                    // Like QEMU, an event may precede a reply.
                    if m["execute"] == "quit" {
                        let _ = w_.write_all(b"{\"event\": \"SHUTDOWN\", \"data\": {\"guest\": false}}\r\n");
                    }
                    let _ = w_.write_all(format!("{reply}\r\n").as_bytes());
                }
            }
        });
        FakeQmp { path: path.to_path_buf(), log, stop, th: Some(th) }
    }

    /// The commands received, by name.
    pub fn commands(&self) -> Vec<String> {
        self.log.lock().unwrap().iter().map(|m| m["execute"].as_str().unwrap_or("").to_string()).collect()
    }

    /// All `input-send-event` events, flattened.
    pub fn events(&self) -> Vec<Value> {
        self.log.lock().unwrap().iter().filter(|m| m["execute"] == "input-send-event").flat_map(|m| m["arguments"]["events"].as_array().cloned().unwrap_or_default()).collect()
    }
}

impl Drop for FakeQmp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A fake `qemu-system-x86_64` / `qemu-img` pair in `dir`: `qemu-img create … <file>` touches
/// the file; the qemu script records its argv to `<dir>/qemu.args`, writes `-pidfile` with
/// the pid of a background loop whose command line still names the QMP socket (as a real
/// daemonized QEMU's does), touches `<dir>/spawned`, and exits 0 (`-daemonize`).
#[cfg(unix)]
pub fn fake_qemu(dir: &Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let q = dir.join("qemu-system-x86_64");
    let img = dir.join("qemu-img");
    let d = dir.display();
    std::fs::write(
        &q,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{d}/qemu.args'\npf=''\nprev=''\nfor a in \"$@\"; do [ \"$prev\" = -pidfile ] && pf=\"$a\"; prev=\"$a\"; done\n( trap 'exit 0' TERM; while :; do sleep 0.2; done ) </dev/null >/dev/null 2>&1 &\necho $! > \"$pf\"\n: > '{d}/spawned'\nexit 0\n"
        ),
    )
    .unwrap();
    // `create … <file>` or `create … <file> <size>`: touch the file argument.
    std::fs::write(&img, "#!/bin/sh\nf=''\nfor a in \"$@\"; do case \"$a\" in *G) ;; *) f=\"$a\" ;; esac; done\n[ \"$1\" = create ] && : > \"$f\"\nexit 0\n").unwrap();
    for p in [&q, &img] {
        crate::host::make_executable(p).unwrap();
    }
    (q, img)
}

/// Desktop VMs under `dir` whose QEMU is [`fake_qemu`] and whose image is a placeholder file
/// (`build` is not run): `start` works and the QMP side is up to the caller. (unix: the fake
/// QEMU is a shell script.)
#[cfg(unix)]
pub fn fake_vms(dir: &Path) -> super::DesktopVms {
    let (q, img) = fake_qemu(&dir.join("bin"));
    let cfg = super::DesktopConfig { qemu: q.display().to_string(), qemu_img: img.display().to_string(), stop_timeout_secs: 1, ..Default::default() };
    let v = super::DesktopVms::new(cfg, &dir.join("data"), &dir.join("cache"), &dir.join("run"));
    std::fs::create_dir_all(v.image_dir()).unwrap();
    std::fs::write(v.image_path(), b"qcow2").unwrap();
    std::fs::write(v.image_path().with_extension("json"), "{}").unwrap();
    v
}

/// Start VM `name` of [`fake_vms`] (rooted at `dir`) with a fake QMP server of `w`×`h` behind it.
#[cfg(unix)]
pub fn start_fake(v: &super::DesktopVms, dir: &Path, name: &str, w: u32, h: u32) -> FakeQmp {
    let (marker, sock) = (dir.join("bin/spawned"), v.qmp_path(name));
    let _ = std::fs::remove_file(&marker);
    let th = std::thread::spawn(move || {
        let t0 = std::time::Instant::now();
        while !marker.exists() && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        FakeQmp::start(&sock, w, h)
    });
    v.start(name).expect("fake VM start");
    th.join().unwrap()
}

/// A stand-in for the in-VM agent (`seagent-vm-guest service`) on VM `name`'s channel socket:
/// it really runs each `Exec` with bash on this machine, with the guest home
/// (`agent::GUEST_HOME`) rewritten to `home` in the script, the cwd and the environment, and
/// streams output / exit status back with stdin, `Eof` and `Signal` handled — enough for the
/// exec backend and the workspace mirror to be tested without a VM. (unix only.)
#[cfg(unix)]
pub fn fake_agent(v: &super::DesktopVms, name: &str, home: &Path) -> std::thread::JoinHandle<()> {
    use crate::proto::{decode, encode, GuestMsg, HostMsg};
    use base64::Engine as _;
    use std::collections::HashMap;
    use std::io::Read;
    use std::process::{Command, Stdio};
    let l = Endpoint::allocate(&v.chan_path(name)).unwrap().listen().unwrap();
    let home = home.to_path_buf();
    std::thread::spawn(move || {
        let fix = |s: &str| s.replace(super::agent::GUEST_HOME, &home.display().to_string());
        while let Ok(s) = l.accept() {
            let w = Arc::new(Mutex::new(s.try_clone().unwrap()));
            let put = {
                let w = w.clone();
                move |m: &GuestMsg| w.lock().unwrap().write_all(&encode(m).unwrap()).is_ok()
            };
            put(&GuestMsg::Hello { version: crate::proto::VERSION, agent: "fake (service)".into(), kernel: "fake".into(), cid: None, transport: "virtio-serial".into(), uid: 1000, nonce: None });
            let mut stdins: HashMap<u64, std::process::ChildStdin> = HashMap::new();
            let pids: Arc<Mutex<HashMap<u64, u32>>> = Default::default();
            let (mut r, mut buf, mut chunk) = (s, Vec::new(), vec![0u8; 65536]);
            loop {
                let n = match r.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let (frames, used) = decode::<HostMsg>(&buf).unwrap();
                buf.drain(..used);
                for f in frames {
                    match f {
                        HostMsg::Exec { id, script, cwd, env, stdin, .. } => {
                            let mut c = crate::host::command("bash");
                            c.arg("-c").arg(format!("exec 2>&1\n{}", fix(&script))).env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin").env("HOME", &home);
                            for (k, val) in env {
                                c.env(k, fix(&val));
                            }
                            c.current_dir(cwd.map(|d| fix(&d)).unwrap_or_else(|| home.display().to_string()));
                            c.stdin(if stdin { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
                            let mut child = match c.spawn() {
                                Ok(ch) => ch,
                                Err(e) => {
                                    put(&GuestMsg::Err { id, message: e.to_string() });
                                    continue;
                                }
                            };
                            if let Some(i) = child.stdin.take() {
                                stdins.insert(id, i);
                            }
                            pids.lock().unwrap().insert(id, child.id());
                            let (put, pids) = (put.clone(), pids.clone());
                            std::thread::spawn(move || {
                                let mut out = child.stdout.take().unwrap();
                                let mut b = vec![0u8; 16384];
                                while let Ok(n) = out.read(&mut b) {
                                    if n == 0 || !put(&GuestMsg::Out { id, data: base64::engine::general_purpose::STANDARD.encode(&b[..n]) }) {
                                        break;
                                    }
                                }
                                let st = child.wait().ok();
                                pids.lock().unwrap().remove(&id);
                                use std::os::unix::process::ExitStatusExt;
                                put(&GuestMsg::Exit { id, code: st.and_then(|s| s.code()), signal: st.and_then(|s| s.signal()) });
                            });
                        }
                        HostMsg::Stdin { id, data } => {
                            if let Some(i) = stdins.get_mut(&id) {
                                let _ = i.write_all(&base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default());
                            }
                        }
                        HostMsg::Eof { id } => {
                            stdins.remove(&id);
                        }
                        HostMsg::Signal { id, force } => {
                            if let Some(p) = pids.lock().unwrap().get(&id) {
                                crate::host::kill_pid(*p, force);
                            }
                        }
                        HostMsg::Ping { id } => {
                            put(&GuestMsg::Pong { id });
                        }
                        _ => {}
                    }
                }
            }
        }
    })
}
