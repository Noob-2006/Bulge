//! Starting browsers ark manages (MIT ports):
//! - Chromium-family discovery and launch flags (OpenClaw `chrome.executables.ts`,
//!   `buildOpenClawChromeLaunchArgs`), DevToolsActivePort reuse, stale-lock cleanup;
//! - the user's real profile copied for browsing with their logins, and
//!   `close-profile` (Hermes `browser_tool_real_profile.py`, `hermes browser close-profile`);
//! - Lightpanda `serve` (Hermes `browser_lightpanda.py`).

use crate::util;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// OpenClaw's Linux search list, then PATH names.
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

/// Find a Chromium-family executable: explicit → default browser → known paths → PATH → Playwright cache.
pub fn find_executable(explicit: &str) -> Result<PathBuf, String> {
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        let p = util::which(explicit).unwrap_or_else(|| PathBuf::from(explicit));
        return if p.is_file() { Ok(p) } else { Err(format!("browser.executable not found: {explicit}")) };
    }
    if let Ok(e) = std::env::var("ARK_BROWSER_EXECUTABLE") {
        if Path::new(&e).is_file() {
            return Ok(e.into());
        }
    }
    if let Some(p) = default_browser_exe() {
        return Ok(p);
    }
    for p in LINUX_PATHS {
        if Path::new(p).is_file() {
            return Ok(p.into());
        }
    }
    for n in PATH_NAMES {
        if let Some(p) = util::which(n) {
            return Ok(p);
        }
    }
    if let Some(p) = playwright_chromium() {
        return Ok(p);
    }
    if let Some(p) = installed_chrome() {
        return Ok(p);
    }
    Err("No Chromium-based browser executable was found on this host. Install Chrome/Chromium/Brave/Edge, run `ark browser install` (downloads a pinned Chrome for Testing build into this ark home), or set browser.executable.".into())
}

/// `find_executable`, then (once per process) a Chrome for Testing install when
/// `browser.auto_install` is on — Hermes `_maybe_autoinstall_chromium`.
pub fn ensure_executable(cfg: &crate::config::BrowserConfig, explicit: &str) -> Result<PathBuf, String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static TRIED: AtomicBool = AtomicBool::new(false);
    let first = find_executable(explicit);
    if first.is_ok() || !cfg.auto_install || TRIED.swap(true, Ordering::SeqCst) {
        return first;
    }
    eprintln!("ark: browser: no Chromium found — installing a pinned Chrome for Testing build (browser.auto_install)");
    let mut say = |l: &str| eprintln!("ark: {}", l.trim_start());
    match install_chromium(cfg, &data_dir(), None, &mut say) {
        Ok(_) => find_executable(explicit),
        Err(e) => {
            eprintln!("ark: browser: {e}");
            first
        }
    }
}

/// ark's data directory (mirrors `ark_kernel::config::Paths::from_env().data`: launch.rs is
/// below the kernel, so it reads the same environment itself).
pub fn data_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("ARK_HOME") {
        return PathBuf::from(h).join("data");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(".local/share")).join("ark")
}

/// The Chrome for Testing build `ark browser install` put in this home, if any.
pub fn installed_chrome() -> Option<PathBuf> {
    installed_chrome_in(&data_dir().join("browsers"))
}

pub fn installed_chrome_in(root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.into_iter().find_map(|d| {
        let p = d.join("chrome");
        (p.is_file()).then_some(p)
    })
}

/// Where the download index lives (Google's Chrome for Testing "last known good versions").
pub const CFT_INDEX: &str = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

/// The zip `install_chromium` downloads: `--url`, a `.zip` in `browser.install_base_url`, else
/// the current stable Chrome for Testing build for this host.
pub fn chromium_download_url(cfg: &crate::config::BrowserConfig, explicit: Option<&str>) -> Result<String, String> {
    if let Some(u) = explicit.map(str::trim).filter(|u| !u.is_empty()) {
        return Ok(u.to_string());
    }
    let base = cfg.install_base_url.trim();
    if base.ends_with(".zip") {
        return Ok(base.to_string());
    }
    let body = ureq::get(CFT_INDEX)
        .call()
        .map_err(|e| format!("Chrome for Testing index: {e}. Pass --url, or set browser.install_base_url to a zip URL."))?
        .body_mut()
        .with_config()
        .limit(4 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("Chrome for Testing index: {e}"))?;
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| format!("Chrome for Testing index is not JSON: {e}"))?;
    let platform = "linux64";
    v["channels"]["Stable"]["downloads"]["chrome"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["platform"] == platform)
        .and_then(|d| d["url"].as_str())
        .map(str::to_string)
        .ok_or_else(|| "the Chrome for Testing index has no linux64 chrome build; pass --url".to_string())
}

/// Download + unpack a Chrome for Testing zip into `<home>/browsers/chrome-linux64`.
/// Every step is logged through `log` (the CLI prints it). Lazy installs are skipped when
/// `ARK_DISABLE_LAZY_INSTALLS` is set (Hermes' `lazy_installs_allowed`).
pub fn install_chromium(cfg: &crate::config::BrowserConfig, home: &Path, explicit_url: Option<&str>, log: &mut dyn FnMut(&str)) -> Result<PathBuf, String> {
    if std::env::var("ARK_DISABLE_LAZY_INSTALLS").is_ok_and(|v| !matches!(v.trim(), "" | "0" | "false")) {
        return Err("lazy installs are disabled (ARK_DISABLE_LAZY_INSTALLS); install Chrome/Chromium yourself or unset it".into());
    }
    let url = chromium_download_url(cfg, explicit_url)?;
    log(&format!("   downloading {url}"));
    let mut resp = ureq::get(&url).call().map_err(|e| format!("download {url}: {e}"))?;
    let body = resp.body_mut().with_config().limit(512 * 1024 * 1024).read_to_vec().map_err(|e| format!("download {url}: {e}"))?;
    if !body.starts_with(b"PK\x03\x04") {
        return Err(format!("{url} did not return a zip archive"));
    }
    let stage = home.join("pm").join("chrome");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let zip = stage.join("chrome.zip");
    std::fs::write(&zip, &body).map_err(|e| e.to_string())?;
    log(&format!("   unpacking {} bytes", body.len()));
    unpack_zip(&zip, &stage)?;
    let _ = std::fs::remove_file(&zip);
    let exe = find_file(&stage, "chrome", 4).ok_or("the archive has no chrome binary")?;
    let src = exe.parent().ok_or("the archive has no chrome directory")?;
    let dst = home.join("browsers").join("chrome-linux64");
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::create_dir_all(dst.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::rename(src, &dst).or_else(|_| copy_tree(src, &dst)).map_err(|e| e.to_string())?;
    let exe = dst.join("chrome");
    use std::os::unix::fs::PermissionsExt;
    for b in ["chrome", "chrome_crashpad_handler", "chrome_sandbox"] {
        let p = dst.join(b);
        if p.is_file() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
        }
    }
    std::fs::write(dst.join(".ark-source"), format!("{url}\n")).map_err(|e| e.to_string())?;
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
    // No unzip: python3 ships zipfile everywhere ark runs.
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
    let base = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/ms-playwright")))?;
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(base).ok()?.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("chromium-"))).collect();
    dirs.sort();
    dirs.into_iter().rev().map(|d| d.join("chrome-linux/chrome")).find(|p| p.is_file())
}

/// `xdg-settings get default-web-browser` → its .desktop Exec when Chromium-family.
fn default_browser_exe() -> Option<PathBuf> {
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

/// A browser already running on this profile directory (a previous ark process, or the
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
    let log = std::fs::File::create(o.user_data_dir.join("ark-browser.log")).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(o.exe);
    cmd.args(chrome_args(o)).stdin(Stdio::null()).stdout(log.try_clone().map_err(|e| e.to_string())?).stderr(log);
    // Chrome's SingletonSocket lives under $TMPDIR; deep dirs overflow AF_UNIX paths.
    cmd.env("TMPDIR", "/tmp");
    for (k, v) in &o.env {
        cmd.env(k, v);
    }
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("failed to start {}: {e}", o.exe.display()))?;
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
            let tail = std::fs::read_to_string(o.user_data_dir.join("ark-browser.log")).unwrap_or_default();
            let tail: Vec<&str> = tail.lines().rev().take(6).collect();
            return Err(format!("{} exited ({st}) before DevTools was ready{}", o.exe.display(), if tail.is_empty() { String::new() } else { format!(": {}", tail.into_iter().rev().collect::<Vec<_>>().join(" | ")) }));
        }
        if Instant::now() >= until {
            util::kill_group(pid, Duration::from_secs(2));
            return Err(format!("{} did not expose DevTools within {}s (see {})", o.exe.display(), timeout.as_secs(), o.user_data_dir.join("ark-browser.log").display()));
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
        unsafe { libc::kill(*p, libc::SIGTERM) };
    }
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until && pids.iter().any(|p| util::pid_alive(*p)) {
        std::thread::sleep(Duration::from_millis(200));
    }
    for p in pids.iter().filter(|p| util::pid_alive(**p)) {
        unsafe { libc::kill(*p, libc::SIGKILL) };
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

/// Copy the real profile into `dst` (first time: the tree; every launch: cookies/logins).
/// Returns the source profile name.
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
    let marker = dst.join(".ark-snapshot-complete");
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
            std::fs::copy(&from, &to).map_err(|e| if f.ends_with("Cookies") { format!("could not read the {} cookies ({e}); the browser may hold a write lock — close it with `ark browser close-profile`", rb.name) } else { e.to_string() })?;
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
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("lightpanda: {e}"))?;
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

    #[test]
    fn devtools_port_file_and_stale_locks() {
        let d = std::env::temp_dir().join(format!("ark-launch-{}", std::process::id()));
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
    fn real_profile_copy_skips_caches_and_resyncs_auth() {
        let root = std::env::temp_dir().join(format!("ark-rp-{}", std::process::id()));
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
