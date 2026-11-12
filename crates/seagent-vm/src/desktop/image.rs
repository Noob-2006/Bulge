//! The desktop guest image: a pinned, sha256-verified Debian cloud image, provisioned once
//! with Xfce + LightDM auto-login + Chromium by cloud-init. seagent serves the NoCloud seed over
//! HTTP on the host loopback and points the guest at it through SMBIOS
//! (`ds=nocloud;s=http://10.0.2.2:PORT/` — 10.0.2.2 is the host under QEMU user-mode NAT),
//! so nothing beyond `qemu-system-x86_64` and `qemu-img` is needed on the host: no ISO
//! tools, no libguestfs, no root.
//!
//! Layout under `<cache>/desktop-vm/`: the downloaded base image (by its file name), the
//! provisioned `desktop-<recipe>.qcow2` and its `desktop-<recipe>.json` manifest. The recipe
//! hash covers the base image sha256, the cloud-config template and the package list, so a
//! config change builds a new image and an unchanged one is a no-op.

use super::{DesktopConfig, DesktopVms};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const USER_DATA: &str = include_str!("user-data.yaml");

/// The cloud-config the guest provisions itself from.
pub fn user_data(cfg: &DesktopConfig) -> String {
    USER_DATA.replace("{{PACKAGES}}", &cfg.packages().join(" "))
}

/// Short hash naming the provisioned image (changes with anything that changes its content).
pub fn recipe(cfg: &DesktopConfig) -> String {
    let h = seagent_net::crypto::sha256(format!("{}\n{}\n{}", cfg.image_sha256, user_data(cfg), super::IMAGE_LAYOUT).as_bytes());
    seagent_net::crypto::hex(&h)[..12].to_string()
}

fn base_name(url: &str) -> String {
    let n = url.rsplit('/').next().unwrap_or("").split(['?', '#']).next().unwrap_or("");
    if n.is_empty() || n.starts_with('.') || !n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) {
        "base.qcow2".into()
    } else {
        n.to_string()
    }
}

/// The base cloud image, downloaded (or copied from a `file://` / absolute path, e.g. the
/// offline bundle) and verified against the pinned sha256. A cached copy is re-verified.
pub fn ensure_base(cfg: &DesktopConfig, dir: &Path, log: &mut dyn FnMut(&str)) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let dst = dir.join(base_name(&cfg.image_url));
    let want = cfg.image_sha256.to_ascii_lowercase();
    if dst.is_file() {
        let got = seagent_net::crypto::sha256_file_hex(&dst).map_err(|e| format!("read {}: {e}", dst.display()))?;
        if got == want {
            log(&format!("base image {} (sha256 ok)", dst.display()));
            return Ok(dst);
        }
        log(&format!("cached {} has sha256 {got}, expected {want}: fetching again", dst.display()));
        let _ = std::fs::remove_file(&dst);
    }
    let part = dst.with_extension("part");
    let mut h = seagent_net::crypto::Sha256Stream::default();
    let mut out = std::fs::File::create(&part).map_err(|e| format!("create {}: {e}", part.display()))?;
    let url = cfg.image_url.trim();
    let local = url.strip_prefix("file://").or_else(|| url.starts_with('/').then_some(url));
    let mut src: Box<dyn Read> = match local {
        Some(p) => {
            log(&format!("copying base image from {p}"));
            Box::new(std::fs::File::open(p).map_err(|e| format!("open {p}: {e}"))?)
        }
        None => {
            seagent_net::http::ensure_online("desktop VM image download")?;
            log(&format!("downloading {url}"));
            let resp = seagent_net::http::agent_for(Duration::from_secs(3600), Duration::from_secs(30), url).get(url).call().map_err(|e| format!("download {url}: {e}"))?;
            if resp.status().as_u16() != 200 {
                let _ = std::fs::remove_file(&part);
                return Err(format!("download {url}: HTTP {}", resp.status().as_u16()));
            }
            Box::new(resp.into_body().into_reader())
        }
    };
    let mut buf = vec![0u8; 1 << 20];
    let (mut n, mut next_log) = (0u64, 64u64 << 20);
    loop {
        let k = src.read(&mut buf).map_err(|e| format!("read {url}: {e}"))?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        out.write_all(&buf[..k]).map_err(|e| format!("write {}: {e}", part.display()))?;
        n += k as u64;
        if n >= next_log {
            log(&format!("  {} MiB", n >> 20));
            next_log += 64 << 20;
        }
    }
    out.sync_all().ok();
    let got = h.finish_hex();
    if got != want {
        let _ = std::fs::remove_file(&part);
        return Err(format!("{url}: sha256 {got} does not match the pinned {want} (refusing to use it)"));
    }
    std::fs::rename(&part, &dst).map_err(|e| e.to_string())?;
    log(&format!("verified {} ({} MiB, sha256 {want})", dst.display(), n >> 20));
    Ok(dst)
}

/// A one-shot NoCloud seed server on 127.0.0.1 (the guest reaches it as 10.0.2.2).
pub struct SeedServer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    pub hits: Arc<std::sync::Mutex<Vec<String>>>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl SeedServer {
    pub fn start(files: Vec<(&'static str, String)>) -> Result<SeedServer, String> {
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("seed server: {e}"))?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(std::sync::Mutex::new(vec![]));
        let (s2, h2) = (stop.clone(), hits.clone());
        let th = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((mut c, _)) => {
                        let _ = c.set_nonblocking(false);
                        let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut req = Vec::new();
                        let mut b = [0u8; 2048];
                        while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16384 {
                            match c.read(&mut b) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => req.extend_from_slice(&b[..n]),
                            }
                        }
                        let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_string();
                        let path = line.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').split('?').next().unwrap_or("").to_string();
                        h2.lock().unwrap().push(path.clone());
                        let body = files.iter().find(|(n, _)| *n == path).map(|(_, b)| b.clone());
                        let resp = match body {
                            Some(b) => format!("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()),
                            None => "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                        };
                        let _ = c.write_all(resp.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(SeedServer { port, stop, hits, th: Some(th) })
    }
}

impl Drop for SeedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

fn tail(s: &str, n: usize) -> String {
    let ls: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    ls[ls.len().saturating_sub(n)..].join("\n")
}

/// Build (or reuse) the provisioned desktop image. Returns its path.
pub fn build(vms: &DesktopVms, force: bool, log: &mut dyn FnMut(&str)) -> Result<PathBuf, String> {
    let cfg = &vms.cfg;
    let dir = vms.image_dir();
    let target = vms.image_path();
    let manifest = target.with_extension("json");
    if !force && target.is_file() && manifest.is_file() {
        log(&format!("desktop image is up to date: {}", target.display()));
        return Ok(target);
    }
    let qemu_img = super::resolve_bin(&cfg.qemu_img)?;
    let qemu = super::resolve_bin(&cfg.qemu)?;
    let base = ensure_base(cfg, &dir, log)?;
    let work = dir.join(format!("build-{}", recipe(cfg)));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("create {}: {e}", work.display()))?;
    let disk = work.join("disk.qcow2");
    super::run_tool(&qemu_img, &["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", &base.display().to_string(), &disk.display().to_string(), &format!("{}G", cfg.disk_gb)])?;
    let instance = format!("seagent-desktop-{}", recipe(cfg));
    let seed = SeedServer::start(vec![
        ("meta-data", format!("instance-id: {instance}\nlocal-hostname: seagent-desktop\n")),
        ("user-data", user_data(cfg)),
        ("vendor-data", String::new()),
    ])?;
    let (accel, warn) = super::accel(cfg);
    if let Some(w) = warn {
        log(&format!("warning: {w}"));
    }
    let console = work.join("console.log");
    let args: Vec<String> = vec![
        "-name".into(),
        format!("seagent-desktop-build-{}", recipe(cfg)),
        "-machine".into(),
        format!("q35,accel={accel}"),
        "-cpu".into(),
        if accel == "kvm" { "host".into() } else { "max".into() },
        "-smp".into(),
        cfg.cpus.max(2).to_string(),
        "-m".into(),
        cfg.memory_mb.max(2048).to_string(),
        "-drive".into(),
        format!("file={},if=virtio,format=qcow2", disk.display()),
        "-netdev".into(),
        "user,id=n0".into(),
        "-device".into(),
        "virtio-net-pci,netdev=n0".into(),
        "-smbios".into(),
        format!("type=1,serial=ds=nocloud;s=http://10.0.2.2:{}/", seed.port),
        // Keep the default VGA: the Debian guest resets during early boot with `-vga none`.
        "-display".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{}", console.display()),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
    ];
    log(&format!("provisioning the desktop in a {accel} VM (Xfce, LightDM auto-login, Chromium; this takes a few minutes) …"));
    let mut child = crate::host::command(&qemu).args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("start {}: {e}", qemu.display()))?;
    let t0 = Instant::now();
    let limit = Duration::from_secs(cfg.build_timeout_secs.max(60));
    let mut last_note = Instant::now();
    let status = loop {
        if let Ok(Some(st)) = child.try_wait() {
            break st;
        }
        if t0.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("provisioning did not finish in {}s; console tail:\n{}", limit.as_secs(), tail(&std::fs::read_to_string(&console).unwrap_or_default(), 8)));
        }
        if last_note.elapsed() > Duration::from_secs(30) {
            last_note = Instant::now();
            let c = std::fs::read_to_string(&console).unwrap_or_default();
            let line = c.lines().rev().find(|l| l.contains("Setting up") || l.contains("Unpacking") || l.contains("SEAGENT_") || l.contains("Get:")).unwrap_or("booting");
            log(&format!("  [{:>4}s] {}", t0.elapsed().as_secs(), line.trim().chars().take(120).collect::<String>()));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    drop(seed);
    let c = std::fs::read_to_string(&console).unwrap_or_default();
    if !status.success() {
        return Err(format!("qemu exited with {status} while provisioning: {}\nconsole tail:\n{}", err.trim(), tail(&c, 8)));
    }
    if !c.contains("SEAGENT_PROVISION_OK") {
        let why = if c.contains("SEAGENT_PROVISION_FAIL") { "the provisioning script failed" } else if !c.contains("SEAGENT_PROVISION_START") { "cloud-init never ran the provisioning script (seed not reached?)" } else { "the guest powered off before provisioning finished" };
        return Err(format!("{why}; console log kept at {}\n{}", console.display(), tail(&c, 10)));
    }
    log("provisioned; flattening the image …");
    let part = target.with_extension("part");
    super::run_tool(&qemu_img, &["convert", "-q", "-O", "qcow2", &disk.display().to_string(), &part.display().to_string()])?;
    std::fs::rename(&part, &target).map_err(|e| e.to_string())?;
    let size = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    let sha = seagent_net::crypto::sha256_file_hex(&target).map_err(|e| e.to_string())?;
    let m: Value = json!({
        "recipe": recipe(cfg),
        "source_url": cfg.image_url,
        "source_sha256": cfg.image_sha256,
        "image": target.display().to_string(),
        "sha256": sha,
        "size": size,
        "packages": cfg.packages(),
        "built_at": super::now_s(),
        "provision_secs": t0.elapsed().as_secs(),
        "accel": accel,
    });
    std::fs::write(&manifest, serde_json::to_string_pretty(&m).unwrap()).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&work);
    log(&format!("desktop image ready: {} ({} MiB, sha256 {sha})", target.display(), size >> 20));
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guest_browser_offers_devtools_through_the_relay_only() {
        let ud = user_data(&DesktopConfig::default());
        let launch = ud.lines().find(|l| l.contains("--remote-debugging-port=")).unwrap();
        assert!(launch.contains("--remote-debugging-port=9222") && launch.contains("--user-data-dir="), "{launch}");
        assert!(!ud.contains("--remote-debugging-address"), "DevTools stays on guest loopback");
        assert!(ud.contains("TCP-LISTEN:9223,fork,reuseaddr TCP:127.0.0.1:9222") && ud.contains("systemctl enable seagent-cdp-relay.service"));
        assert!(DesktopConfig::default().packages().iter().any(|p| p == "socat"));
    }

    #[test]
    fn the_text_helper_survives_and_never_leaks_the_port() {
        // Found on a real VM: xclip stayed in the background holding the virtio port (one
        // opener only), so every text after the first timed out; a SIGPIPE or a failed `exec`
        // also killed the helper for good.
        let ud = user_data(&DesktopConfig::default());
        let helper = &ud[ud.find("seagent-text-input").unwrap()..];
        assert!(helper.contains("trap '' PIPE"), "SIGPIPE must not kill the helper");
        assert!(helper.contains("exec 3<>\"$port\" || exit 0") && helper.contains("&& ("), "the port is opened in a subshell");
        for tool in ["xclip -selection clipboard -i", "xdotool key --clearmodifiers ctrl+v"] {
            let line = helper.lines().find(|l| l.contains(tool)).unwrap();
            assert!(line.contains("3>&-"), "{tool} must not inherit the port: {line}");
        }
    }

    #[test]
    fn user_data_and_recipe_follow_the_config() {
        let mut c = DesktopConfig::default();
        let u = user_data(&c);
        assert!(u.starts_with("#cloud-config"));
        assert!(u.contains("chromium") && u.contains("autologin-user=seagent") && u.contains("SEAGENT_PROVISION_OK") && !u.contains("{{"), "{u}");
        let r = recipe(&c);
        c.extra_packages.push("vim".into());
        assert!(user_data(&c).contains(" vim"));
        assert_ne!(recipe(&c), r, "a package change is a new image");
        c.width = 1920;
        assert_eq!(recipe(&c), recipe(&DesktopConfig { width: 1920, ..c.clone() }), "screen size is a boot setting, not an image one");
        assert_eq!(base_name(DEFAULT_URL), "debian-13-generic-amd64-20261026-2643.qcow2");
        assert_eq!(base_name("https://x/../"), "base.qcow2");
    }

    const DEFAULT_URL: &str = super::super::config::DEFAULT_IMAGE_URL;

    #[test]
    fn seed_server_serves_the_nocloud_files() {
        let s = SeedServer::start(vec![("meta-data", "instance-id: x\n".into()), ("user-data", "#cloud-config\n".into())]).unwrap();
        let get = |p: &str| {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", s.port)).unwrap();
            c.write_all(format!("GET /{p} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            out
        };
        assert!(get("meta-data").ends_with("instance-id: x\n"));
        assert!(get("user-data").contains("200 OK"));
        assert!(get("network-config").contains("404"));
        assert_eq!(s.hits.lock().unwrap().as_slice(), ["meta-data", "user-data", "network-config"]);
    }

    #[test]
    fn a_local_base_image_is_verified_before_use() {
        let d = seagent_core::tmp::TempDir::new("seagent-dvm-base");
        let src = d.join("src.qcow2");
        std::fs::write(&src, b"not really qcow2").unwrap();
        let sha = seagent_net::crypto::sha256_file_hex(&src).unwrap();
        let mut c = DesktopConfig { image_url: format!("file://{}", src.display()), image_sha256: "0".repeat(64), ..Default::default() };
        let mut lines = vec![];
        let e = ensure_base(&c, &d.join("cache"), &mut |l| lines.push(l.to_string())).unwrap_err();
        assert!(e.contains("does not match"), "{e}");
        assert!(!d.join("cache/src.part").exists(), "a bad download is not kept");
        c.image_sha256 = sha;
        let p = ensure_base(&c, &d.join("cache"), &mut |l| lines.push(l.to_string())).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"not really qcow2");
        ensure_base(&c, &d.join("cache"), &mut |l| lines.push(l.to_string())).unwrap();
        assert!(lines.last().unwrap().contains("sha256 ok"), "{lines:?}");
    }
}
