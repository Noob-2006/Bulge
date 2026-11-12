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

/// The cloud-config the guest provisions itself from, with the mirror still a placeholder
/// (which mirror served the packages does not change the image, so it is not in the recipe).
pub fn user_data(cfg: &DesktopConfig) -> String {
    USER_DATA.replace("{{PACKAGES}}", &cfg.packages().join(" "))
}

/// [`user_data`] as served to the guest: `mirror` is a checked archive URL or empty.
pub fn seed_user_data(cfg: &DesktopConfig, mirror: &str) -> String {
    let m = if super::config::valid_mirror(mirror) && mirror != "auto" { mirror.trim_end_matches('/') } else { "" };
    user_data(cfg).replace("{{APT_MIRROR}}", m)
}

/// The Debian archive the provisioning guest installs from: `apt_mirror` as configured, or for
/// `auto` the fastest of [`super::config::APT_MIRRORS`] (each asked for the first MiB of its
/// `ls-lR.gz`, all at once, ~10 s at most). Empty = the image's own deb.debian.org.
pub fn pick_mirror(cfg: &DesktopConfig, log: &mut dyn FnMut(&str)) -> String {
    if cfg.apt_mirror != "auto" {
        return cfg.apt_mirror.trim_end_matches('/').to_string();
    }
    let (tx, rx) = std::sync::mpsc::channel();
    for m in super::config::APT_MIRRORS {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send((*m, mirror_speed(m)));
        });
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut best: Option<(&str, f64)> = None;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((m, Some(bps))) if best.is_none_or(|(_, b)| bps > b) => best = Some((m, bps)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    match best {
        Some((m, bps)) => {
            log(&format!("Debian mirror: {m} (fastest here, {:.1} MB/s)", bps / 1e6));
            if m == super::config::APT_MIRRORS[0] { String::new() } else { m.to_string() }
        }
        None => {
            log("Debian mirror: none answered the speed test; using deb.debian.org");
            String::new()
        }
    }
}

/// Bytes per second for the first MiB of `<mirror>/ls-lR.gz`, `None` when it fails.
fn mirror_speed(mirror: &str) -> Option<f64> {
    const PROBE: u64 = 1 << 20;
    let url = format!("{mirror}/ls-lR.gz");
    let t0 = Instant::now();
    let resp = seagent_net::http::agent_for(Duration::from_secs(10), Duration::from_secs(5), &url).get(&url).header("Range", format!("bytes=0-{}", PROBE - 1)).call().ok()?;
    if !matches!(resp.status().as_u16(), 200 | 206) {
        return None;
    }
    let mut r = resp.into_body().into_reader().take(PROBE);
    let n = std::io::copy(&mut r, &mut std::io::sink()).ok()?;
    (n >= PROBE / 4).then(|| n as f64 / t0.elapsed().as_secs_f64().max(1e-3))
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
    let url = cfg.image_url.trim();
    let local = local_source(url);
    match local {
        Some(p) => {
            log(&format!("copying base image from {p}"));
            let _ = std::fs::remove_file(&part);
            let mut src = std::fs::File::open(p).map_err(|e| format!("open {p}: {e}"))?;
            let mut out = std::fs::File::create(&part).map_err(|e| format!("create {}: {e}", part.display()))?;
            copy_logged(&mut src, &mut out, 0, log).map_err(|e| format!("copy {p}: {e}"))?;
            out.sync_all().ok();
        }
        None => {
            seagent_net::http::ensure_online("desktop VM image download")?;
            download_resumable(url, &part, log)?;
        }
    }
    let n = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let got = seagent_net::crypto::sha256_file_hex(&part).map_err(|e| format!("read {}: {e}", part.display()))?;
    if got != want {
        let _ = std::fs::remove_file(&part);
        return Err(format!("{url}: sha256 {got} does not match the pinned {want} (refusing to use it)"));
    }
    std::fs::rename(&part, &dst).map_err(|e| e.to_string())?;
    log(&format!("verified {} ({} MiB, sha256 {want})", dst.display(), n >> 20));
    Ok(dst)
}

/// The local file an `image_url` names: `file://…` or an absolute path of this OS
/// (`/srv/x.qcow2`, `C:\Downloads\x.qcow2`; `file:///C:/x.qcow2` drops the slash before the drive).
fn local_source(url: &str) -> Option<&str> {
    if let Some(p) = url.strip_prefix("file://") {
        let b = p.as_bytes();
        let drive = cfg!(windows) && b.len() > 3 && b[0] == b'/' && b[1].is_ascii_alphabetic() && b[2] == b':';
        return Some(if drive { &p[1..] } else { p });
    }
    (url.starts_with('/') || Path::new(url).is_absolute()).then_some(url)
}

/// Attempts in a row that add no bytes before [`download_resumable`] gives up.
const DOWNLOAD_RETRIES: u32 = 6;

/// Download `url` into `part`. A dropped connection (common for a ~400 MB image on a slow or
/// flaky link) is resumed with an HTTP Range request, and a `.part` an interrupted build left
/// behind is continued the same way; a server without Range support starts over. The caller
/// checks the pinned sha256, so a wrong resume can never be accepted.
pub(crate) fn download_resumable(url: &str, part: &Path, log: &mut dyn FnMut(&str)) -> Result<(), String> {
    let agent = seagent_net::http::agent_for(Duration::from_secs(3600), Duration::from_secs(30), url);
    let len = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let mut fails = 0u32;
    loop {
        let have = len(part);
        if have == 0 {
            log(&format!("downloading {url}"));
        } else {
            log(&format!("resuming {url} at {} MiB", have >> 20));
        }
        let mut req = agent.get(url);
        if have > 0 {
            req = req.header("Range", format!("bytes={have}-"));
        }
        let err = match req.call() {
            Err(e) => e.to_string(),
            Ok(resp) => {
                let status = resp.status().as_u16();
                let header = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
                // The full size, when the server says it: a body that ends early is a drop too.
                let total = match status {
                    206 => header("content-range").and_then(|r| r.rsplit('/').next().and_then(|t| t.trim().parse::<u64>().ok())),
                    _ => header("content-length").and_then(|l| l.trim().parse::<u64>().ok()),
                };
                let mut out = match status {
                    416 if have > 0 => return Ok(()),
                    206 => std::fs::OpenOptions::new().append(true).open(part),
                    200 => std::fs::File::create(part),
                    s => return Err(format!("download {url}: HTTP {s}")),
                }
                .map_err(|e| format!("open {}: {e}", part.display()))?;
                let start = if status == 206 { have } else { 0 };
                let r = copy_logged(&mut resp.into_body().into_reader(), &mut out, start, log);
                out.sync_all().ok();
                match r {
                    Ok(n) if total.is_none_or(|t| n >= t) => return Ok(()),
                    Ok(n) => format!("the connection closed at {} of {} MiB", n >> 20, total.unwrap_or(0) >> 20),
                    Err(e) => e.to_string(),
                }
            }
        };
        let now = len(part);
        fails = if now > have { 0 } else { fails + 1 };
        if fails >= DOWNLOAD_RETRIES {
            return Err(format!("download {url}: {err} ({DOWNLOAD_RETRIES} attempts without progress; building again continues from {} MiB)", now >> 20));
        }
        let wait = 1u64 << fails.min(5);
        log(&format!("  download interrupted at {} MiB ({err}); retrying in {wait}s", now >> 20));
        std::thread::sleep(Duration::from_secs(wait));
    }
}

/// Copy `src` to the end of `out` (which already holds `start` bytes), logging every 64 MiB.
/// Returns the total size.
fn copy_logged(src: &mut dyn Read, out: &mut std::fs::File, start: u64, log: &mut dyn FnMut(&str)) -> std::io::Result<u64> {
    const STEP: u64 = 64 << 20;
    let mut buf = vec![0u8; 1 << 20];
    let (mut n, mut next) = (start, (start / STEP + 1) * STEP);
    loop {
        let k = src.read(&mut buf)?;
        if k == 0 {
            return Ok(n);
        }
        out.write_all(&buf[..k])?;
        n += k as u64;
        if n >= next {
            log(&format!("  {} MiB", n >> 20));
            next += STEP;
        }
    }
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
    let mirror = pick_mirror(cfg, log);
    let seed = SeedServer::start(vec![
        ("meta-data", format!("instance-id: {instance}\nlocal-hostname: seagent-desktop\n")),
        ("user-data", seed_user_data(cfg, &mirror)),
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
        // Same machine as the running desktop (WHPX needs the userspace irqchip, see mod.rs).
        if accel == "whpx" { "q35,accel=whpx,kernel-irqchip=off".into() } else { format!("q35,accel={accel}") },
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
        let u = seed_user_data(&c, "");
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

    #[test]
    fn local_image_sources() {
        assert_eq!(local_source("file:///srv/x.qcow2"), Some("/srv/x.qcow2"));
        assert_eq!(local_source("/srv/x.qcow2"), Some("/srv/x.qcow2"));
        assert_eq!(local_source("https://cloud.debian.org/x.qcow2"), None);
        assert_eq!(local_source("x.qcow2"), None);
        if cfg!(windows) {
            assert_eq!(local_source(r"C:\Downloads\x.qcow2"), Some(r"C:\Downloads\x.qcow2"));
            assert_eq!(local_source("file:///C:/Downloads/x.qcow2"), Some("C:/Downloads/x.qcow2"));
        }
    }

    #[test]
    fn the_mirror_is_filled_into_the_seed_but_not_the_recipe() {
        let c = DesktopConfig::default();
        let ud = seed_user_data(&c, "https://linux.cs.nycu.edu.tw/debian/debian/");
        assert!(ud.contains("m='https://linux.cs.nycu.edu.tw/debian/debian'"), "trailing / dropped");
        assert!(!ud.contains("{{"), "no placeholder left");
        assert!(seed_user_data(&c, "").contains("m=''"));
        assert!(seed_user_data(&c, "http://x/a'b").contains("m=''"), "an unsafe URL is never inserted");
        let other = DesktopConfig { apt_mirror: "http://ftp.jp.debian.org/debian".into(), ..Default::default() };
        assert_eq!(recipe(&c), recipe(&other));
        assert_eq!(pick_mirror(&other, &mut |_| {}), "http://ftp.jp.debian.org/debian");
    }

    /// The guest's sed line, run on both apt source formats: the main archive moves to the
    /// mirror, debian-security stays.
    #[cfg(unix)]
    #[test]
    fn the_guest_sed_rewrites_only_the_main_archive() {
        let line = USER_DATA.lines().find(|l| l.contains("sed -i -E")).unwrap().trim().trim_start_matches("[ -f \"$f\" ] && ");
        let d = seagent_core::tmp::TempDir::new("seagent-dvm-sed");
        let f = d.path().join("debian.sources");
        std::fs::write(&f, "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie\n\nTypes: deb\nURIs: http://deb.debian.org/debian-security\n\ndeb https://deb.debian.org/debian/ trixie main\n").unwrap();
        let st = std::process::Command::new("sh").arg("-c").arg(line).env("f", &f).env("m", "https://m.example/debian").status().unwrap();
        assert!(st.success());
        let out = std::fs::read_to_string(&f).unwrap();
        assert!(out.contains("URIs: https://m.example/debian\n"), "{out}");
        assert!(out.contains("URIs: http://deb.debian.org/debian-security\n"), "{out}");
        assert!(out.contains("deb https://m.example/debian trixie main"), "{out}");
        // The cloud image's /etc/apt/mirrors/debian.list and debian-security.list.
        for (src, want) in [("https://deb.debian.org/debian\n", "https://m.example/debian\n"), ("https://deb.debian.org/debian-security\n", "https://deb.debian.org/debian-security\n")] {
            std::fs::write(&f, src).unwrap();
            assert!(std::process::Command::new("sh").arg("-c").arg(line).env("f", &f).env("m", "https://m.example/debian").status().unwrap().success());
            assert_eq!(std::fs::read_to_string(&f).unwrap(), want);
        }
    }

    /// A server that drops the first response half-way; the download resumes with a Range
    /// request and ends byte-identical.
    #[test]
    fn a_dropped_download_resumes_with_a_range_request() {
        use std::io::{BufRead, BufReader};
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let b = body.clone();
        let server = std::thread::spawn(move || {
            let mut ranges = vec![];
            for (i, s) in l.incoming().take(2).enumerate() {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut range = None;
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        range = v.trim().trim_end_matches('-').parse::<usize>().ok();
                    }
                }
                ranges.push(range);
                if i == 0 {
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len());
                    let _ = s.write_all(&b[..b.len() / 2]);
                } else {
                    let from = range.unwrap_or(0);
                    let _ = write!(s, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {from}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len() - 1, b.len(), b.len() - from);
                    let _ = s.write_all(&b[from..]);
                }
            }
            ranges
        });
        let d = seagent_core::tmp::TempDir::new("seagent-dvm-resume");
        let part = d.path().join("base.part");
        let mut lines = vec![];
        download_resumable(&format!("http://127.0.0.1:{port}/base.qcow2"), &part, &mut |l| lines.push(l.to_string())).unwrap();
        let ranges = server.join().unwrap();
        assert_eq!(ranges[0], None);
        assert_eq!(ranges[1], Some(body.len() / 2), "{lines:?}");
        assert_eq!(std::fs::read(&part).unwrap(), body);
        assert!(lines.iter().any(|l| l.contains("resuming")), "{lines:?}");
    }
}
