//! Test support (used by this crate's and seagent-app's tests): a fake QMP server on a unix
//! socket that answers like QEMU — greeting, `qmp_capabilities`, `screendump` (writes a PNG
//! header of the configured size to the requested file), `input-send-event`,
//! `system_powerdown` / `quit` — and records every command it received; plus a fake
//! `qemu-system-x86_64` script for lifecycle tests.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
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
        let l = UnixListener::bind(path).expect("bind fake QMP socket");
        l.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(vec![]));
        let stop = Arc::new(AtomicBool::new(false));
        let (lg, st) = (log.clone(), stop.clone());
        let th = std::thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                let Ok((c, _)) = l.accept() else {
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
pub fn fake_qemu(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
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
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (q, img)
}

/// Desktop VMs under `dir` whose QEMU is [`fake_qemu`] and whose image is a placeholder file
/// (`build` is not run): `start` works and the QMP side is up to the caller.
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
