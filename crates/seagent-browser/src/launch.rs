//! Starting browsers seagent manages (MIT ports):
//! - Chromium-family discovery and launch flags (OpenClaw `chrome.executables.ts`,
//!   `buildOpenClawChromeLaunchArgs`), DevToolsActivePort reuse, stale-lock cleanup;
//! - the user's real profile copied for browsing with their logins, and
//!   `close-profile` (Hermes `browser_tool_real_profile.py`, `hermes browser close-profile`);
//! - Lightpanda `serve` (Hermes `browser_lightpanda.py`).

use crate::util;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Fallback install locations (OpenClaw's Linux search list), tried after the `PATH_NAMES` on `$PATH`.
/// Windows / macOS: `launch_os::install_paths`.
#[cfg(not(any(windows, target_os = "macos")))]
const LINUX_PATHS: &[&str] = &[
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chrome",
    "/opt/google/chrome/chrome",
    "/usr/bin/brave-browser",
    "/usr/bin/brave-browser-stable",
    "/usr/bin/brave",
    "/snap/bin/brave",
    "/opt/brave.com/brave/brave-browser",
    "/usr/bin/microsoft-edge",
    "/usr/bin/microsoft-edge-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/lib/chromium/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
    "/snap/bin/chromium",
];
const PATH_NAMES: &[&str] = &["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "brave", "microsoft-edge", "microsoft-edge-stable", "chrome"];

pub fn kind_of(exe: &Path) -> &'static str {
    let s = exe.to_string_lossy().to_ascii_lowercase();
    if s.contains("brave") {
        "brave"
    } else if s.contains("edge") || s.contains("msedge") {
        "edge"
    } else if s.contains("chromium") {
        "chromium"
    } else if s.contains("headless_shell") || s.contains("chrome-headless") {
        "chrome-headless-shell"
    } else {
        "chrome"
    }
}

/// Find a Chromium-family executable: explicit / `SEAGENT_BROWSER_EXECUTABLE` → default browser → PATH → known paths → Playwright cache.
pub fn find_executable(explicit: &str) -> Result<PathBuf, String> {
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        let p = util::which(explicit).unwrap_or_else(|| PathBuf::from(explicit));
        return if p.is_file() { Ok(p) } else { Err(format!("browser.executable not found: {explicit}")) };
    }
    if let Ok(e) = std::env::var("SEAGENT_BROWSER_EXECUTABLE") {
        if Path::new(&e).is_file() {
            return Ok(e.into());
        }
    }
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return Err(crate::launch_os::MOBILE_NOTE.into());
    }
    if let Some(p) = default_browser_exe() {
        return Ok(p);
    }
    // $PATH first (distro, Nix, Homebrew, custom prefixes), the well-known install locations
    // only as a fallback for a service started with a minimal PATH.
    for n in PATH_NAMES {
        if let Some(p) = util::which(n) {
            return Ok(p);
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    for p in LINUX_PATHS {
        if Path::new(p).is_file() {
            return Ok(p.into());
        }
    }
    #[cfg(any(windows, target_os = "macos"))]
    if let Some((_, p)) = crate::launch_os::install_paths().into_iter().find(|(_, p)| p.is_file()) {
        return Ok(p);
    }
    if let Some(p) = playwright_chromium() {
        return Ok(p);
    }
    if let Some(p) = bundled_chrome() {
        return Ok(p);
    }
    Err("No Chromium-based browser executable was found on this host. Install Chrome/Chromium/Brave/Edge, run `seagent browser install` (downloads a pinned Chrome for Testing build into this seagent home), or set browser.executable.".into())
}

/// `find_executable`, then (once per process) a Chrome for Testing install when
/// `browser.auto_install` is on — Hermes `_maybe_autoinstall_chromium`.
pub fn ensure_executable(cfg: &crate::config::BrowserConfig, explicit: &str) -> Result<PathBuf, String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static TRIED: AtomicBool = AtomicBool::new(false);
    // `browser.prefer_bundled`: the Chrome for Testing build shipped with seagent (install.sh
    // --with-browser, the offline bundle, `seagent browser install`) wins over host browsers.
    if cfg.prefer_bundled && explicit.trim().is_empty() && std::env::var_os("SEAGENT_BROWSER_EXECUTABLE").is_none() {
        if let Some(p) = bundled_chrome() {
            return Ok(p);
        }
    }
    let first = find_executable(explicit);
    if first.is_ok() || !cfg.auto_install || TRIED.swap(true, Ordering::SeqCst) {
        return first;
    }
    eprintln!("seagent: browser: no Chromium found — installing a pinned Chrome for Testing build (browser.auto_install)");
    let mut say = |l: &str| eprintln!("seagent: {}", l.trim_start());
    match install_chromium(cfg, &data_dir(), None, &mut say) {
        Ok(_) => find_executable(explicit),
        Err(e) => {
            eprintln!("seagent: browser: {e}");
            first
        }
    }
}

/// seagent's data directory (the same `seagent_core::layout` the kernel's `Paths` uses).
pub fn data_dir() -> PathBuf {
    seagent_core::layout::data_dir()
}

/// The Chrome for Testing build `seagent browser install` put in this home, if any.
pub fn installed_chrome() -> Option<PathBuf> {
    installed_chrome_in(&data_dir().join("browsers"))
}

pub fn installed_chrome_in(root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.into_iter().find_map(|d| {
        let p = d.join(crate::launch_os::cft_exe_rel());
        (p.is_file()).then_some(p)
    })
}

/// The Chrome for Testing build seagent ships / installs by default (pinned: version, URL, sha256).
/// packaging/install.sh (`--with-browser`) and the offline bundle carry the same three values.
pub const PINNED_CFT_VERSION: &str = "157.0.8103.38";
pub const PINNED_CFT_URL: &str = "https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.38/linux64/chrome-linux64.zip";
pub const PINNED_CFT_SHA256: &str = "8cdeb344e9b2cefe59f4aea8d1d93d5d93054c03cde217665c16fc1f62e72a66";

/// The same pinned version for every Chrome for Testing platform: `(platform, sha256 of
/// chrome-<platform>.zip)`. Each hash was taken from Google's own download, the linux64 one
/// matching [`PINNED_CFT_SHA256`].
pub const PINNED_CFT_SHA256S: &[(&str, &str)] = &[
    ("linux64", PINNED_CFT_SHA256),
    ("win64", "ae0deef27d449e1d7529df7705d609bab102de48464da13567ed3dd2ee1a0586"),
    ("win32", "be61f767e50b6d94586710afa138535306084b438d9e30bee600a538e16a278a"),
    ("mac-arm64", "3406b38b52b7d341d74450eb7b369be038c9fec9894c8b8a9e9e9f97333caf2f"),
    ("mac-x64", "c6fcc2869b0d5a421e880d7bcdabe96e4261c4100e125fc4e4daf6346474efa6"),
];

/// The pinned build's `(url, sha256)` for a Chrome for Testing `platform` (linux64:
/// [`PINNED_CFT_URL`]).
pub fn pinned_cft(platform: &str) -> Option<(String, &'static str)> {
    let sha = PINNED_CFT_SHA256S.iter().find(|(p, _)| *p == platform)?.1;
    let url = if platform == "linux64" { PINNED_CFT_URL.to_string() } else { format!("https://storage.googleapis.com/chrome-for-testing-public/{PINNED_CFT_VERSION}/{platform}/chrome-{platform}.zip") };
    Some((url, sha))
}

/// `body` downloaded from `url`: `Ok(true)` when `url` is a pinned build and its sha256
/// matches, `Ok(false)` for an unpinned URL, an error for a pinned one that does not match.
pub fn verify_pinned(url: &str, body: &[u8]) -> Result<bool, String> {
    let Some(pinned) = PINNED_CFT_SHA256S.iter().filter_map(|(p, _)| pinned_cft(p)).find(|(u, _)| u == url).map(|(_, s)| s) else { return Ok(false) };
    let got = seagent_net::crypto::hex(&seagent_net::crypto::sha256(body));
    if got != pinned {
        return Err(format!("{url}: sha256 {got} does not match the pinned {pinned} (refusing to install it)"));
    }
    Ok(true)
}

/// The Chrome for Testing build bundled with seagent: `<share>/browsers/chrome-linux64/chrome`
/// (install.sh --with-browser, offline bundle), else `<data>/browsers/*/chrome` (`seagent browser
/// install`), else `<cache>/browsers/chrome-linux64/chrome`. Other OSes: the same places with
/// their Chrome for Testing directory and executable (`launch_os::cft_dir` / `cft_exe_rel`).
pub fn bundled_chrome() -> Option<PathBuf> {
    let rel = format!("browsers/{}/{}", crate::launch_os::cft_dir(), crate::launch_os::cft_exe_rel());
    seagent_core::share::share_path(&rel)
        .filter(|p| p.is_file())
        .or_else(installed_chrome)
        .or_else(|| Some(seagent_core::layout::cache_dir().join(&rel)).filter(|p| p.is_file()))
}

/// Where the download index lives (Google's Chrome for Testing "last known good versions").
pub const CFT_INDEX: &str = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

/// The zip `install_chromium` downloads: `--url`, a `.zip` in `browser.install_base_url`, else
/// this platform's pinned Chrome for Testing build ([`pinned_cft`], sha256-verified); `--url latest`
/// asks Google's index for the current stable build instead.
pub fn chromium_download_url(cfg: &crate::config::BrowserConfig, explicit: Option<&str>) -> Result<String, String> {
    let explicit = explicit.map(str::trim).filter(|u| !u.is_empty());
    if let Some(u) = explicit.filter(|u| *u != "latest") {
        return Ok(u.to_string());
    }
    let base = cfg.install_base_url.trim();
    let platform = crate::launch_os::cft_platform().ok_or_else(|| format!("Chrome for Testing has no build for this OS. {}", crate::launch_os::MOBILE_NOTE))?;
    // The pinned build of this platform (linux64, win64 / win32, mac-arm64 / mac-x64).
    if explicit.is_none() {
        if base.ends_with(".zip") {
            return Ok(base.to_string());
        }
        if let Some((url, _)) = pinned_cft(platform) {
            return Ok(url);
        }
    }
    let body = seagent_net::http::agent().get(CFT_INDEX)
        .call()
        .map_err(|e| format!("Chrome for Testing index: {e}. Pass --url, or set browser.install_base_url to a zip URL."))?
        .body_mut()
        .with_config()
        .limit(4 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("Chrome for Testing index: {e}"))?;
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| format!("Chrome for Testing index is not JSON: {e}"))?;
    v["channels"]["Stable"]["downloads"]["chrome"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["platform"] == platform)
        .and_then(|d| d["url"].as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("the Chrome for Testing index has no {platform} chrome build; pass --url"))
}

/// Download + unpack a Chrome for Testing zip into `<home>/browsers/chrome-linux64`.
/// Every step is logged through `log` (the CLI prints it). Lazy installs are skipped when
/// `SEAGENT_DISABLE_LAZY_INSTALLS` is set (Hermes' `lazy_installs_allowed`).
pub fn install_chromium(cfg: &crate::config::BrowserConfig, home: &Path, explicit_url: Option<&str>, log: &mut dyn FnMut(&str)) -> Result<PathBuf, String> {
    if std::env::var("SEAGENT_DISABLE_LAZY_INSTALLS").is_ok_and(|v| !matches!(v.trim(), "" | "0" | "false")) {
        return Err("lazy installs are disabled (SEAGENT_DISABLE_LAZY_INSTALLS); install Chrome/Chromium yourself or unset it".into());
    }
    let url = chromium_download_url(cfg, explicit_url)?;
    log(&format!("   downloading {url}"));
    let mut resp = seagent_net::http::agent().get(&url).call().map_err(|e| format!("download {url}: {e}"))?;
    let body = resp.body_mut().with_config().limit(512 * 1024 * 1024).read_to_vec().map_err(|e| format!("download {url}: {e}"))?;
    if !body.starts_with(b"PK\x03\x04") {
        return Err(format!("{url} did not return a zip archive"));
    }
    if verify_pinned(&url, &body)? {
        log(&format!("   sha256 ok (Chrome for Testing {PINNED_CFT_VERSION})"));
    }
    let stage = home.join("pm").join("chrome");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let zip = stage.join("chrome.zip");
    std::fs::write(&zip, &body).map_err(|e| e.to_string())?;
    log(&format!("   unpacking {} bytes", body.len()));
    unpack_zip(&zip, &stage)?;
    let _ = std::fs::remove_file(&zip);
    let exe = find_file(&stage, crate::launch_os::cft_exe_name(), 4).ok_or("the archive has no chrome binary")?;
    // macOS: move the whole unpacked folder (the executable sits deep inside an .app bundle).
    #[cfg(target_os = "macos")]
    let top = stage.join(exe.strip_prefix(&stage).ok().and_then(|r| r.components().next()).ok_or("the archive has no chrome directory")?);
    #[cfg(target_os = "macos")]
    let src = top.as_path();
    #[cfg(not(target_os = "macos"))]
    let src = exe.parent().ok_or("the archive has no chrome directory")?;
    let dst = home.join("browsers").join(crate::launch_os::cft_dir());
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::create_dir_all(dst.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(src, &dst).or_else(|_| copy_tree(src, &dst)).map_err(|e| e.to_string())?;
    let exe = dst.join(crate::launch_os::cft_exe_rel());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for b in ["chrome", "chrome_crashpad_handler", "chrome_sandbox"] {
            let p = dst.join(b);
            if p.is_file() {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            }
        }
    }
    std::fs::write(dst.join(".seagent-source"), format!("{url}\n")).map_err(|e| e.to_string())?;
    log(&format!("   installed {}", exe.display()));
    Ok(exe)
}

fn unpack_zip(zip: &Path, into: &Path) -> Result<(), String> {
    let z = zip.display().to_string();
    let d = into.display().to_string();
    if let Some(unzip) = util::which("unzip") {
        let (code, _, err) = util::run(&[&unzip.to_string_lossy(), "-q", "-o", &z, "-d", &d], Duration::from_secs(180), None, &[])?;
        if code == 0 {
            return Ok(());
        }
        return Err(format!("unzip failed: {}", err.trim()));
    }
    // Windows 10+ ships bsdtar (System32\tar.exe), which reads zip archives.
    #[cfg(windows)]
    if let Some(tar) = util::which("tar") {
        let (code, _, err) = util::run(&[&tar.to_string_lossy(), "-xf", &z, "-C", &d], Duration::from_secs(180), None, &[])?;
        if code == 0 {
            return Ok(());
        }
        return Err(format!("tar -xf failed: {}", err.trim()));
    }
    // No unzip: python3 ships zipfile everywhere seagent runs.
    let (code, _, err) = util::run(&["python3", "-c", "import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])", &z, &d], Duration::from_secs(180), None, &[])?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("unpacking needs `unzip` or python3: {}", err.trim()))
    }
}

fn find_file(dir: &Path, name: &str, depth: u32) -> Option<PathBuf> {
    let mut dirs = vec![];
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_file() && p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
        if p.is_dir() {
            dirs.push(p);
        }
    }
    if depth == 0 {
        return None;
    }
    dirs.into_iter().find_map(|d| find_file(&d, name, depth - 1))
}

fn playwright_chromium() -> Option<PathBuf> {
    #[cfg(not(any(windows, target_os = "macos")))]
    let (base, rel) = (std::env::var_os("PLAYWRIGHT_BROWSERS_PATH").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/ms-playwright")))?, "chrome-linux/chrome");
    #[cfg(any(windows, target_os = "macos"))]
    let (base, rel) = crate::launch_os::playwright_layout()?;
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(base).ok()?.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("chromium-"))).collect();
    dirs.sort();
    dirs.into_iter().rev().map(|d| d.join(rel)).find(|p| p.is_file())
}

/// `xdg-settings get default-web-browser` → its .desktop Exec when Chromium-family.
fn default_browser_exe() -> Option<PathBuf> {
    // xdg-settings is a freedesktop tool; Windows / macOS go straight to the install paths.
    if cfg!(any(windows, target_vendor = "apple")) {
        return None;
    }
    let (_, out, _) = util::run(&["xdg-settings", "get", "default-web-browser"], Duration::from_secs(2), None, &[]).ok()?;
    let desktop = out.trim();
    if desktop.is_empty() {
        return None;
    }
    let low = desktop.to_ascii_lowercase();
    if !["chrome", "chromium", "brave", "edge"].iter().any(|k| low.contains(k)) {
        return None;
    }
    let dirs = [std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| format!("{}/.local/share", std::env::var("HOME").unwrap_or_default())), "/usr/share".into(), "/usr/local/share".into(), "/var/lib/snapd/desktop".into()];
    for d in dirs {
        let f = Path::new(&d).join("applications").join(desktop);
        let Ok(s) = std::fs::read_to_string(&f) else { continue };
        let exec = s.lines().find_map(|l| l.strip_prefix("Exec="))?;
        let bin = exec.split_whitespace().find(|t| !t.contains('=') && *t != "env")?;
        if let Some(p) = util::which(bin) {
            return Some(p);
        }
    }
    None
}

pub struct LaunchOpts<'a> {
    pub exe: &'a Path,
    pub user_data_dir: &'a Path,
    pub headless: bool,
    pub no_sandbox: bool,
    pub extra_args: &'a [String],
    /// 0 = let Chrome pick (read back from DevToolsActivePort).
    pub port: u16,
    /// Managed launch adds OpenClaw's isolation flags; a real-profile copy keeps the keyring.
    pub managed: bool,
    pub env: Vec<(String, String)>,
}

pub struct Launched {
    pub pid: i32,
    pub http: String,
    pub ws: String,
    /// We started it (and should stop it).
    pub owned: bool,
}

/// OpenClaw `buildOpenClawChromeLaunchArgs` (+ Hermes real-profile flags).
pub fn chrome_args(o: &LaunchOpts) -> Vec<String> {
    let mut a = vec![format!("--remote-debugging-port={}", o.port), format!("--user-data-dir={}", o.user_data_dir.display()), "--no-first-run".into(), "--no-default-browser-check".into(), "--disable-sync".into(), "--disable-background-networking".into(), "--disable-component-update".into()];
    if o.managed {
        a.extend(["--disable-features=Translate,MediaRouter", "--disable-session-crashed-bubble", "--hide-crash-restore-bubble", "--password-store=basic"].map(String::from));
    } else {
        a.extend(["--disable-default-apps", "--disable-hang-monitor", "--disable-popup-blocking", "--disable-prompt-on-repost", "--disable-features=Translate"].map(String::from));
    }
    if o.headless {
        a.push("--headless=new".into());
        a.push("--disable-gpu".into());
    }
    if o.no_sandbox {
        a.push("--no-sandbox".into());
    }
    a.push("--disable-dev-shm-usage".into());
    if o.managed && !o.extra_args.iter().any(|x| x.starts_with("--proxy-server") || x.starts_with("--proxy-pac-url") || x == "--no-proxy-server") {
        a.push("--no-proxy-server".into());
    }
    a.extend(o.extra_args.iter().cloned());
    a.push("about:blank".into());
    a
}

/// `DevToolsActivePort`: (port, browser ws path).
pub fn active_port(udd: &Path) -> Option<(u16, String)> {
    let s = std::fs::read_to_string(udd.join("DevToolsActivePort")).ok()?;
    let mut l = s.lines();
    let port = l.next()?.trim().parse().ok()?;
    Some((port, l.next().unwrap_or("").trim().to_string()))
}

/// The pid in `SingletonLock` (a `host-pid` symlink).
pub fn singleton_pid(udd: &Path) -> Option<i32> {
    let t = std::fs::read_link(udd.join("SingletonLock")).ok()?;
    t.to_string_lossy().rsplit('-').next()?.parse().ok()
}

/// Remove Chrome's singleton files when their owner is gone.
pub fn clear_stale_locks(udd: &Path) {
    if singleton_pid(udd).is_some_and(util::pid_alive) {
        return;
    }
    for f in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        let _ = std::fs::remove_file(udd.join(f));
    }
}

/// A browser already running on this profile directory (a previous seagent process, or the
/// user's Chrome after they enabled remote debugging).
pub fn running_on(udd: &Path) -> Option<Launched> {
    let (port, path) = active_port(udd)?;
    let pid = singleton_pid(udd).filter(|p| util::pid_alive(*p))?;
    std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500)).ok()?;
    let ws = if path.is_empty() { crate::cdp::resolve_ws(&format!("http://127.0.0.1:{port}"), None, Duration::from_secs(3)).ok()? } else { format!("ws://127.0.0.1:{port}{path}") };
    Some(Launched { pid, http: format!("http://127.0.0.1:{port}"), ws, owned: false })
}

/// Launch (or reuse) a Chromium on `user_data_dir` and wait for its DevTools endpoint.
pub fn launch(o: &LaunchOpts, timeout: Duration) -> Result<Launched, String> {
    util::private_dir(o.user_data_dir).map_err(|e| format!("{}: {e}", o.user_data_dir.display()))?;
    if let Some(l) = running_on(o.user_data_dir) {
        return Ok(l);
    }
    clear_stale_locks(o.user_data_dir);
    let _ = std::fs::remove_file(o.user_data_dir.join("DevToolsActivePort"));
    let log = std::fs::File::create(o.user_data_dir.join("seagent-browser.log")).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(o.exe);
    cmd.args(chrome_args(o)).stdin(Stdio::null()).stdout(log.try_clone().map_err(|e| e.to_string())?).stderr(log);
    // Chrome's SingletonSocket lives under $TMPDIR; deep dirs overflow AF_UNIX paths.
    #[cfg(unix)]
    cmd.env("TMPDIR", "/tmp");
    for (k, v) in &o.env {
        cmd.env(k, v);
    }
    // Own session (one `kill(-pgid)` reaches the renderers) and tied to seagent: when seagent dies —
    // crash, SIGKILL, an interrupted test run — the kernel sends Chrome SIGTERM (new-001).
    let mut child = seagent_core::proc::spawn_tied(cmd, true).map_err(|e| format!("failed to start {}: {e}", o.exe.display()))?;
    let pid = child.id() as i32;
    let until = Instant::now() + timeout;
    loop {
        if let Some((port, path)) = active_port(o.user_data_dir) {
            if !path.is_empty() {
                // Reap in the background so it never turns into a zombie.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(Launched { pid, http: format!("http://127.0.0.1:{port}"), ws: format!("ws://127.0.0.1:{port}{path}"), owned: true });
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            let tail = std::fs::read_to_string(o.user_data_dir.join("seagent-browser.log")).unwrap_or_default();
            let tail: Vec<&str> = tail.lines().rev().take(6).collect();
            return Err(format!("{} exited ({st}) before DevTools was ready{}", o.exe.display(), if tail.is_empty() { String::new() } else { format!(": {}", tail.into_iter().rev().collect::<Vec<_>>().join(" | ")) }));
        }
        if Instant::now() >= until {
            util::kill_group(pid, Duration::from_secs(2));
            return Err(format!("{} did not expose DevTools within {}s (see {})", o.exe.display(), timeout.as_secs(), o.user_data_dir.join("seagent-browser.log").display()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Chrome-family process names (Hermes close-profile).
fn chromey(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["chrome", "chromium", "brave", "msedge", "microsoft-edge"].iter().any(|k| n.contains(k))
}

/// Pids of browser processes using `dir` as user-data-dir (including the default dir
/// when the process passes none and `default_dir` is set).
#[cfg(any(windows, target_os = "macos"))]
pub fn processes_on(dir: &Path, default_dir: bool) -> Vec<i32> {
    crate::launch_os::processes_on(dir, default_dir, chromey)
}

/// iOS: no other processes are visible to an app.
#[cfg(target_os = "ios")]
pub fn processes_on(_dir: &Path, _default_dir: bool) -> Vec<i32> {
    let _ = chromey;
    vec![]
}

/// Pids of browser processes using `dir` as user-data-dir (including the default dir
/// when the process passes none and `default_dir` is set).
#[cfg(not(any(windows, target_vendor = "apple")))]
pub fn processes_on(dir: &Path, default_dir: bool) -> Vec<i32> {
    let want = dir.to_string_lossy().trim_end_matches('/').to_string();
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else { continue };
        let args: Vec<String> = raw.split(|b| *b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let Some(argv0) = args.first() else { continue };
        if !chromey(Path::new(argv0).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default().as_str()) {
            continue;
        }
        let udd = args.iter().find_map(|a| a.strip_prefix("--user-data-dir=")).map(|d| d.trim_end_matches('/').to_string());
        let hit = match udd {
            Some(d) => d == want,
            None => default_dir,
        };
        if hit {
            out.push(pid);
        }
    }
    out
}

/// Terminate the browser holding a profile and wait for its lock (Hermes `close-profile`).
pub fn close_profile(dir: &Path, default_dir: bool) -> Result<String, String> {
    let pids = processes_on(dir, default_dir);
    if pids.is_empty() {
        clear_stale_locks(dir);
        return Ok(format!("no browser is using {}", dir.display()));
    }
    for p in &pids {
        #[cfg(unix)]
        unsafe {
            libc::kill(*p, libc::SIGTERM)
        };
        #[cfg(windows)]
        crate::launch_os::ask_exit(*p);
    }
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until && pids.iter().any(|p| util::pid_alive(*p)) {
        std::thread::sleep(Duration::from_millis(200));
    }
    for p in pids.iter().filter(|p| util::pid_alive(**p)) {
        #[cfg(unix)]
        unsafe {
            libc::kill(*p, libc::SIGKILL)
        };
        #[cfg(windows)]
        crate::launch_os::force_exit(*p);
    }
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until && singleton_pid(dir).is_some_and(util::pid_alive) {
        std::thread::sleep(Duration::from_millis(500));
    }
    if singleton_pid(dir).is_some_and(util::pid_alive) {
        return Err(format!("the browser on {} did not release its profile lock", dir.display()));
    }
    clear_stale_locks(dir);
    Ok(format!("closed {} browser process(es) using {}", pids.len(), dir.display()))
}

// ---- real profile (Hermes browser_tool_real_profile.py) ----

pub struct RealBrowser {
    pub name: &'static str,
    pub data_dir: PathBuf,
    pub exe: PathBuf,
}

/// Default browser → (name, data dir, binary). Channels (beta/dev/canary) are unsupported.
pub fn detect_real_browser() -> Result<RealBrowser, String> {
    let (_, out, _) = util::run(&["xdg-settings", "get", "default-web-browser"], Duration::from_secs(2), None, &[]).unwrap_or_default();
    let d = out.trim().to_ascii_lowercase();
    for ch in ["google-chrome-beta", "google-chrome-unstable", "google-chrome-canary", "microsoft-edge-beta", "microsoft-edge-dev", "brave-browser-beta", "brave-browser-nightly"] {
        if d.contains(ch) {
            return Err(format!("the default browser ({d}) is a pre-release channel, which real-profile browsing does not support"));
        }
    }
    let name = if d.contains("google-chrome") || d.contains("com.google.chrome") {
        "chrome"
    } else if d.contains("chromium") {
        "chromium"
    } else if d.contains("brave") {
        "brave"
    } else if d.contains("microsoft-edge") || d.contains("msedge") {
        "edge"
    } else {
        // No (Chromium) default: take the first installed one.
        ["chrome", "chromium", "brave", "edge"].into_iter().find(|n| real_binary(n).is_some()).ok_or("No supported Chromium default browser detected.")?
    };
    let data_dir = real_data_dir(name).ok_or_else(|| format!("Could not resolve the {name} profile directory."))?;
    let exe = real_binary(name).ok_or_else(|| format!("the {name} binary was not found"))?;
    Ok(RealBrowser { name, data_dir, exe })
}

#[cfg(any(windows, target_os = "macos"))]
pub fn real_data_dir(name: &str) -> Option<PathBuf> {
    crate::launch_os::real_data_dir(name)
}

#[cfg(any(windows, target_os = "macos"))]
fn real_binary(name: &str) -> Option<PathBuf> {
    crate::launch_os::real_binary(name)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn real_data_dir(name: &str) -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let cfg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
    let (native, snap, flatpak): (&str, Option<&str>, &str) = match name {
        "chrome" => ("google-chrome", None, "com.google.Chrome"),
        "chromium" => ("chromium", Some("snap/chromium/common/chromium"), "org.chromium.Chromium"),
        "brave" => ("BraveSoftware/Brave-Browser", Some("snap/brave/current/.config/BraveSoftware/Brave-Browser"), "com.brave.Browser"),
        "edge" => ("microsoft-edge", None, "com.microsoft.Edge"),
        _ => return None,
    };
    let mut c = vec![cfg.join(native)];
    if let Some(s) = snap {
        c.push(home.join(s));
    }
    c.push(home.join(".var/app").join(flatpak).join("config").join(native));
    c.iter().find(|p| p.is_dir()).cloned().or(Some(c[0].clone()))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn real_binary(name: &str) -> Option<PathBuf> {
    let (names, abs): (&[&str], &[&str]) = match name {
        "chrome" => (&["google-chrome", "google-chrome-stable"], &["/opt/google/chrome/chrome", "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"]),
        "chromium" => (&["chromium-browser", "chromium"], &["/usr/bin/chromium-browser", "/usr/bin/chromium", "/snap/bin/chromium"]),
        "brave" => (&["brave-browser", "brave-browser-stable", "brave"], &["/usr/bin/brave-browser", "/snap/bin/brave", "/opt/brave.com/brave/brave-browser", "/opt/brave.com/brave/brave", "/opt/brave-bin/brave"]),
        "edge" => (&["microsoft-edge", "microsoft-edge-stable"], &["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable", "/opt/microsoft/msedge/microsoft-edge", "/opt/microsoft/msedge/msedge"]),
        _ => return None,
    };
    names.iter().find_map(|n| util::which(n)).or_else(|| abs.iter().map(PathBuf::from).find(|p| p.is_file()))
}

const SKIP: &[&str] = &["Extensions", "Local Extension Settings", "Service Worker", "IndexedDB", "Crash Reports", "Crashpad", "Snapshots", "optimization_guide_model_store", "Safe Browsing", "SafetyTips", "OnDeviceHeadSuggestModel", "segmentation_platform", "Sync Data", "Shared Dictionary", "RunningChromeVersion", "SingletonSocket", "Cookies", "Login Data", "Login Data For Account", "Web Data", "BrowserMetrics-spare.pma"];
#[cfg(feature = "personal")]
const AUTH_FILES: &[&str] = &["Cookies", "Network/Cookies", "Login Data", "Login Data For Account", "Web Data", "Preferences"];

fn skip(name: &str) -> bool {
    SKIP.contains(&name) || name.contains("Cache") || name.starts_with("Extension") || name.starts_with("BrowserMetrics") || name.starts_with("OptimizationGuide") || name.starts_with("History") || name.starts_with("Favicons") || name.starts_with("Singleton") || name.ends_with(".tmp") || name.ends_with("-journal") || name.ends_with("-wal") || name.ends_with("-shm")
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if skip(&name) {
            continue;
        }
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            copy_tree(&e.path(), &dst.join(&name))?;
        } else {
            std::fs::copy(e.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

/// Default build (gen1-306): importing the user's real Chrome profile (cookies, logins) is a
/// personal-desktop feature compiled only with `--features personal`.
#[cfg(not(feature = "personal"))]
pub fn snapshot_real_profile(_rb: &RealBrowser, _dst: &Path, _pin: &str) -> Result<String, String> {
    Err("importing your real Chrome profile is not part of this build (a personal-desktop feature): rebuild seagent with `--features personal`.".into())
}

/// Copy the real profile into `dst` (first time: the tree; every launch: cookies/logins).
/// Returns the source profile name.
#[cfg(feature = "personal")]
pub fn snapshot_real_profile(rb: &RealBrowser, dst: &Path, pin: &str) -> Result<String, String> {
    let src_root = &rb.data_dir;
    let local_state: serde_json::Value = std::fs::read_to_string(src_root.join("Local State")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let profile = if !pin.is_empty() {
        if !src_root.join(pin).is_dir() {
            return Err(format!("browser.real_profile_pin `{pin}` does not exist (ls '{}')", src_root.display()));
        }
        pin.to_string()
    } else {
        local_state["profile"]["last_used"].as_str().filter(|p| src_root.join(p).is_dir()).unwrap_or("Default").to_string()
    };
    let src = src_root.join(&profile);
    if !src.is_dir() {
        return Err(format!("no {} profile at {}", rb.name, src.display()));
    }
    let marker = dst.join(".seagent-snapshot-complete");
    if std::fs::read_to_string(&marker).is_ok_and(|m| m.trim() != profile) {
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_dir_all(dst.join("Default"));
    }
    util::private_dir(dst).map_err(|e| e.to_string())?;
    let mut ls = local_state.clone();
    if ls.is_object() {
        let entry = ls["profile"]["info_cache"][&profile].clone();
        ls["profile"]["info_cache"] = serde_json::json!({"Default": entry});
        ls["profile"]["last_used"] = "Default".into();
        ls["profile"]["last_active_profiles"] = serde_json::json!(["Default"]);
        util::write_private(&dst.join("Local State"), ls.to_string().as_bytes()).map_err(|e| e.to_string())?;
    }
    if !marker.exists() {
        copy_tree(&src, &dst.join("Default")).map_err(|e| format!("copying {}: {e}", src.display()))?;
    }
    for f in AUTH_FILES {
        let from = src.join(f);
        if from.is_file() {
            let to = dst.join("Default").join(f);
            if let Some(p) = to.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            std::fs::copy(&from, &to).map_err(|e| if f.ends_with("Cookies") { format!("could not read the {} cookies ({e}); the browser may hold a write lock — close it with `seagent browser close-profile`", rb.name) } else { e.to_string() })?;
        }
    }
    for f in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        let _ = std::fs::remove_file(dst.join(f));
    }
    util::write_private(&marker, profile.as_bytes()).map_err(|e| e.to_string())?;
    Ok(profile)
}

// ---- Lightpanda (Hermes browser_lightpanda.py) ----

pub fn lightpanda_binary() -> Option<PathBuf> {
    if let Some(p) = util::which("lightpanda") {
        return Some(p);
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    [home.join(".lightpanda/lightpanda"), home.join(".local/bin/lightpanda")].into_iter().find(|p| p.is_file())
}

/// `lightpanda serve --host 127.0.0.1 --port P`; waits for `/json/version` (10 s).
pub fn lightpanda_serve(state_dir: &Path, block_private: bool) -> Result<Launched, String> {
    let bin = lightpanda_binary().ok_or("browser.engine is 'lightpanda' but no lightpanda binary was found on PATH, ~/.lightpanda or ~/.local/bin. Install Lightpanda from https://lightpanda.io/docs/run-locally/installation/one-liner and make sure `lightpanda` is on PATH, or set browser.engine to auto.")?;
    let port = util::free_port();
    let mut args = vec!["serve".to_string(), "--host".into(), "127.0.0.1".into(), "--port".into(), port.to_string()];
    let help = util::run(&[&bin.to_string_lossy(), "help"], Duration::from_secs(3), None, &[]).map(|(_, o, e)| o + &e).unwrap_or_default();
    if help.contains("--http-cache-dir") {
        args.extend(["--http-cache-dir".into(), state_dir.join("http-cache").display().to_string()]);
    }
    if block_private {
        args.push("--block-private-networks".into());
    }
    util::private_dir(state_dir).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(state_dir.join("lightpanda.log")).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&bin);
    cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(log);
    let mut child = seagent_core::proc::spawn_tied(cmd, true).map_err(|e| format!("lightpanda: {e}"))?;
    let pid = child.id() as i32;
    let http = format!("http://127.0.0.1:{port}");
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(ws) = crate::cdp::resolve_ws(&http, None, Duration::from_millis(500)) {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(Launched { pid, http, ws, owned: true });
        }
        if let Ok(Some(st)) = child.try_wait() {
            return Err(format!("lightpanda serve exited with code {} before {http}/json/version answered", st.code().unwrap_or(-1)));
        }
        if Instant::now() >= until {
            util::kill_group(pid, Duration::from_secs(1));
            return Err(format!("lightpanda serve did not expose {http}/json/version within 10s"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default install is the pinned, sha256-checked Chrome for Testing build; the shell
    /// installers carry the same pin.
    #[test]
    fn default_browser_install_is_the_pinned_build() {
        let cfg = crate::config::BrowserConfig::default();
        // Every desktop OS installs its own platform's build of the one pinned version (no
        // network call); a `.zip` base URL is used as is.
        #[cfg(target_os = "linux")]
        assert_eq!(chromium_download_url(&cfg, None).unwrap(), PINNED_CFT_URL);
        #[cfg(target_os = "macos")]
        {
            let p = crate::launch_os::cft_platform().unwrap();
            assert!(p.starts_with("mac-"));
            assert_eq!(chromium_download_url(&cfg, None).unwrap(), format!("https://storage.googleapis.com/chrome-for-testing-public/{PINNED_CFT_VERSION}/{p}/chrome-{p}.zip"));
        }
        #[cfg(windows)]
        {
            assert_eq!(crate::launch_os::cft_platform(), Some("win64"));
            assert_eq!(chromium_download_url(&cfg, None).unwrap(), format!("https://storage.googleapis.com/chrome-for-testing-public/{PINNED_CFT_VERSION}/win64/chrome-win64.zip"));
            let local = crate::config::BrowserConfig { install_base_url: "https://mirror.example/chrome-win64.zip".into(), ..Default::default() };
            assert_eq!(chromium_download_url(&local, None).unwrap(), "https://mirror.example/chrome-win64.zip");
        }
        for (p, sha) in PINNED_CFT_SHA256S {
            let (url, s) = pinned_cft(p).unwrap();
            assert!(url.contains(PINNED_CFT_VERSION) && url.ends_with(&format!("/{p}/chrome-{p}.zip")) && s == *sha && sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "{p}");
        }
        assert_eq!(pinned_cft("linux64").unwrap(), (PINNED_CFT_URL.to_string(), PINNED_CFT_SHA256));
        assert!(pinned_cft("android").is_none());
        assert_eq!(chromium_download_url(&cfg, Some("https://x/y.zip")).unwrap(), "https://x/y.zip");
        assert!(PINNED_CFT_URL.contains(PINNED_CFT_VERSION) && PINNED_CFT_SHA256.len() == 64);
        for f in ["packaging/install.sh", "packaging/offline/make-offline-bundle.sh"] {
            let s = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(f)).unwrap();
            assert!(s.contains(&format!("CFT_VERSION={PINNED_CFT_VERSION}")) && s.contains(&format!("CFT_SHA256={PINNED_CFT_SHA256}")), "{f} pins a different build");
        }
    }

    #[test]
    fn launch_flags_follow_openclaw() {
        let o = LaunchOpts { exe: Path::new("/usr/bin/chromium"), user_data_dir: Path::new("/tmp/p"), headless: true, no_sandbox: true, extra_args: &["--proxy-server=x".to_string()], port: 0, managed: true, env: vec![] };
        let a = chrome_args(&o);
        assert_eq!(&a[..2], &["--remote-debugging-port=0".to_string(), "--user-data-dir=/tmp/p".to_string()]);
        for f in ["--password-store=basic", "--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--hide-crash-restore-bubble"] {
            assert!(a.contains(&f.to_string()), "{f}");
        }
        assert!(!a.contains(&"--no-proxy-server".to_string()), "user proxy wins");
        assert_eq!(kind_of(Path::new("/snap/bin/chromium")), "chromium");
        assert_eq!(kind_of(Path::new("/usr/bin/brave-browser")), "brave");
    }

    #[cfg(unix)]
    #[test]
    fn devtools_port_file_and_stale_locks() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-launch-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("DevToolsActivePort"), "9333\n/devtools/browser/abc\n").unwrap();
        assert_eq!(active_port(&d), Some((9333, "/devtools/browser/abc".into())));
        let _ = std::fs::remove_file(d.join("SingletonLock"));
        std::os::unix::fs::symlink("host-999999999", d.join("SingletonLock")).unwrap();
        assert_eq!(singleton_pid(&d), Some(999999999));
        assert!(running_on(&d).is_none());
        clear_stale_locks(&d);
        assert!(std::fs::symlink_metadata(d.join("SingletonLock")).is_err());
        assert!(close_profile(&d, false).unwrap().contains("no browser"));
    }

    #[test]
    #[cfg(feature = "personal")]
    fn real_profile_copy_skips_caches_and_resyncs_auth() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-rp-{}", std::process::id()));
        let src = root.join("src");
        std::fs::create_dir_all(src.join("Profile 1/Cache")).unwrap();
        std::fs::create_dir_all(src.join("Profile 1/Network")).unwrap();
        std::fs::write(src.join("Local State"), r#"{"profile":{"last_used":"Profile 1","info_cache":{"Profile 1":{"name":"Me"}}}}"#).unwrap();
        std::fs::write(src.join("Profile 1/Preferences"), "{}").unwrap();
        std::fs::write(src.join("Profile 1/Network/Cookies"), "c1").unwrap();
        std::fs::write(src.join("Profile 1/Cache/x"), "big").unwrap();
        std::fs::write(src.join("Profile 1/History"), "h").unwrap();
        let rb = RealBrowser { name: "chrome", data_dir: src.clone(), exe: "/bin/true".into() };
        let dst = root.join("dst");
        assert_eq!(snapshot_real_profile(&rb, &dst, "").unwrap(), "Profile 1");
        assert!(dst.join("Default/Preferences").is_file() && !dst.join("Default/Cache").exists() && !dst.join("Default/History").exists());
        let ls: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dst.join("Local State")).unwrap()).unwrap();
        assert_eq!(ls["profile"]["last_used"], "Default");
        assert_eq!(ls["profile"]["info_cache"]["Default"]["name"], "Me");
        std::fs::write(src.join("Profile 1/Network/Cookies"), "c2").unwrap();
        snapshot_real_profile(&rb, &dst, "").unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("Default/Network/Cookies")).unwrap(), "c2");
        assert!(snapshot_real_profile(&rb, &dst, "Nope").unwrap_err().contains("does not exist"));
    }
}
