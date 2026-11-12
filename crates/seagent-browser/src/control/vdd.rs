//! The virtual display for the Windows Bot Desktop: the open-source IddCx "Virtual Display
//! Driver" (VirtualDrivers/Virtual-Display-Driver, MttVDD, MIT, signed by SignPath Foundation;
//! review notes in `packaging/release/DEPENDENCY-REVIEW.md`), bundled with the Windows app and
//! installed by `apps/desktop/src-tauri/windows/vdd/install-vdd.ps1` (elevated).
//!
//! Why: Windows composes only the displayed desktop. The isolated `CreateDesktopW` Bot Desktop
//! ([`super::screen_windows`]) is never composed, so GPU apps there can only be pictured with
//! `PrintWindow` (≈10 fps) and Windows.Graphics.Capture refuses them (0×0, `ERROR_INVALID_STATE`).
//! No driver changes that. What a virtual monitor gives instead is a real, composed screen that
//! nobody looks at: with it attached, the Bot Desktop is *hosted* there — its apps open on the
//! interactive desktop but on the virtual monitor only (moved there and kept off the taskbar), and
//! the live view reads that monitor with DXGI Desktop Duplication at its refresh rate (60 Hz).
//! The monitor sits outside the bottom-right corner of the real screens (corner contact only), so
//! the pointer practically never wanders onto it and the user's own screens are untouched.
//!
//! Without the driver (or with `SEAGENT_BOT_DISPLAY=isolated`) everything stays as before: the
//! isolated desktop, the `PrintWindow` window tracker, and [`Status::reason`] for the UI.
//!
//! Everything here except the [`sys`] probes is plain data and logic, compiled and tested on
//! every platform.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The driver's hardware id (its INF's `Root\MttVDD`).
pub const HARDWARE_ID: &str = "Root\\MttVDD";
/// The upstream release the bundled files come from, and the driver version inside it.
pub const RELEASE: &str = "25.7.23";
pub const DRIVER_VERSION: &str = "11.30.4.434";
/// The one mode the installer configures: 1920×1080 at 60 Hz.
pub const MODE: (i32, i32, u32) = (1920, 1080, 60);
/// The installer script's file name (beside the driver files in the app's `vdd` resources).
pub const SCRIPT: &str = "install-vdd.ps1";
/// `SEAGENT_BOT_DISPLAY=isolated` keeps the isolated Bot Desktop even with the driver present.
pub const ENV: &str = "SEAGENT_BOT_DISPLAY";

/// A screen rectangle in desktop coordinates (physical pixels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub fn contains(&self, o: &Rect) -> bool {
        o.x >= self.x && o.y >= self.y && o.right() <= self.right() && o.bottom() <= self.bottom()
    }
    /// Do the two share more than a corner point (overlap, or a common edge of some length)?
    pub fn touches_along_an_edge(&self, o: &Rect) -> bool {
        let span = |a0: i32, a1: i32, b0: i32, b1: i32| a1.min(b1) - a0.max(b0);
        let (sx, sy) = (span(self.x, self.right(), o.x, o.right()), span(self.y, self.bottom(), o.y, o.bottom()));
        (sx >= 0 && sy > 0) || (sx > 0 && sy >= 0)
    }
    pub fn to_json(&self) -> Value {
        json!({"x": self.x, "y": self.y, "width": self.w, "height": self.h})
    }
}

/// One display of the desktop (`EnumDisplayDevicesW` + its current mode).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Screen {
    /// `\\.\DISPLAYn`.
    pub name: String,
    /// The adapter's description and PnP id.
    pub adapter: String,
    pub id: String,
    pub attached: bool,
    pub primary: bool,
    pub rect: Rect,
    pub hz: u32,
}

impl Screen {
    pub fn is_virtual(&self) -> bool {
        is_vdd_adapter(&self.adapter, &self.id)
    }
}

/// Is this display adapter the virtual display driver? (its INF names the device "Virtual Display
/// Driver"; the PnP id carries `MttVDD`).
pub fn is_vdd_adapter(description: &str, id: &str) -> bool {
    description.contains("Virtual Display Driver") || id.to_ascii_uppercase().contains("MTTVDD")
}

/// The installed driver version, from the display class's driver keys as
/// (`MatchingDeviceId`, `DriverVersion`) pairs.
pub fn installed_version(keys: &[(String, String)]) -> Option<String> {
    keys.iter().find(|(id, _)| id.eq_ignore_ascii_case(HARDWARE_ID)).map(|(_, v)| v.clone())
}

/// The attached virtual monitor, if any.
pub fn virtual_monitor(screens: &[Screen]) -> Option<&Screen> {
    screens.iter().find(|s| s.attached && s.is_virtual() && s.rect.w > 0 && s.rect.h > 0)
}

/// Where the virtual monitor goes: the bottom-right outside corner of the real screens' bounds,
/// touching them at one point only. The primary screen and every real screen stay where they are.
pub fn corner_origin(real: &[Rect]) -> (i32, i32) {
    (real.iter().map(Rect::right).max().unwrap_or(0), real.iter().map(Rect::bottom).max().unwrap_or(0))
}

/// Is the virtual monitor out of the pointer's way (no common edge with any real screen)?
pub fn out_of_the_way(v: &Rect, real: &[Rect]) -> bool {
    real.iter().all(|r| !v.touches_along_an_edge(r))
}

/// Keep a hosted window on the virtual monitor: `None` when it is inside already, else its new
/// rectangle — its offset kept when it fits, at most the monitor's size.
pub fn herd(win: Rect, mon: Rect) -> Option<Rect> {
    if mon.contains(&win) {
        return None;
    }
    let (w, h) = (win.w.clamp(1, mon.w), win.h.clamp(1, mon.h));
    let x = win.x.clamp(mon.x, mon.right() - w);
    let y = win.y.clamp(mon.y, mon.bottom() - h);
    Some(Rect { x, y, w, h })
}

/// Is hosting on the virtual monitor allowed (`SEAGENT_BOT_DISPLAY`, default: yes)?
pub fn hosting_allowed(env: Option<&str>) -> bool {
    !matches!(env.map(str::trim), Some("isolated" | "off" | "0"))
}

/// What the agent knows about the virtual display.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    /// Windows at all (the driver is Windows-only; elsewhere the Bot Desktop has no such limit).
    pub windows: bool,
    /// The installed driver version (`None`: not installed).
    pub version: Option<String>,
    /// The attached virtual monitor.
    pub monitor: Option<Screen>,
    /// The installer script the settings page runs (`None`: not bundled with this build).
    pub script: Option<PathBuf>,
    /// `SEAGENT_BOT_DISPLAY=isolated`.
    pub forced_isolated: bool,
}

impl Status {
    pub fn installed(&self) -> bool {
        self.version.is_some()
    }

    /// Is the Bot Desktop hosted on the virtual monitor?
    pub fn active(&self) -> bool {
        self.windows && self.monitor.is_some() && !self.forced_isolated
    }

    /// Why native (non-Chromium) apps on the Bot Desktop stream slower, and what fixes it:
    /// (code, message). `None` when the virtual display is in use or not needed.
    pub fn reason(&self) -> Option<(&'static str, String)> {
        if !self.windows || self.active() {
            return None;
        }
        let fix = if self.script.is_some() { "到「設定 → 虛擬顯示器」按「安裝」（需要系統管理員同意）" } else { "這個版本沒有附帶驅動程式，請用 Windows 安裝程式重新安裝" };
        Some(if self.forced_isolated {
            ("isolated", format!("{ENV}=isolated：Bot Desktop 固定使用隔離桌面，原生 App 的即時畫面只能用 PrintWindow（約 10 fps）。"))
        } else if !self.installed() {
            ("not_installed", format!("沒有安裝虛擬顯示器驅動程式：Windows 不會繪製隔離的 Bot Desktop，GPU 繪製的原生 App（記事本、小畫家、檔案總管…）只能用 PrintWindow 擷取，約 10 fps。{fix}。"))
        } else {
            ("no_monitor", format!("虛擬顯示器驅動程式 {} 已安裝，但虛擬螢幕沒有接在桌面上（被停用或設定被改）。到「設定 → 虛擬顯示器」按「修復」。", self.version.as_deref().unwrap_or("?")))
        })
    }

    pub fn to_json(&self) -> Value {
        let reason = self.reason();
        json!({
            "supported": self.windows,
            "installed": self.installed(),
            "version": self.version,
            "bundled": {"release": RELEASE, "driverVersion": DRIVER_VERSION, "available": self.script.is_some()},
            "active": self.active(),
            "monitor": self.monitor.as_ref().map(|m| json!({"name": m.name, "rect": m.rect.to_json(), "hz": m.hz})),
            "mode": if self.active() { "virtual-display" } else { "isolated" },
            "reason": reason.as_ref().map(|r| r.0),
            "message": reason.map(|r| r.1),
        })
    }
}

/// Where the installer script is: `$SEAGENT_VDD_DIR`, the app's resources beside the binary
/// (`<exe dir>/vdd`), or this checkout's copy (development builds).
pub fn script_in(env: Option<PathBuf>, exe: Option<&Path>) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = env.into_iter().collect();
    if let Some(d) = exe.and_then(Path::parent) {
        dirs.push(d.join("vdd"));
    }
    dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/windows/vdd"));
    dirs.into_iter().map(|d| d.join(SCRIPT)).find(|p| p.is_file())
}

/// What the settings page can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Install, or repair an existing install (the script is idempotent).
    Install,
    Uninstall,
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "install" | "repair" => Some(Action::Install),
            "uninstall" => Some(Action::Uninstall),
            _ => None,
        }
    }
}

/// The elevated command line for `action` (`powershell.exe` arguments).
pub fn script_args(action: Action, script: &Path) -> String {
    let base = format!("-NoProfile -ExecutionPolicy Bypass -File \"{}\"", script.display());
    match action {
        Action::Install => base,
        Action::Uninstall => format!("{base} -Uninstall"),
    }
}

/// The region the Bot Desktop is hosted on in this process (set by `WinDesktop::start` / read
/// from its state; `None`: isolated mode). Input and screenshots of the host target use it.
static HOSTED: Mutex<Option<Rect>> = Mutex::new(None);

pub fn hosted() -> Option<Rect> {
    *HOSTED.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn set_hosted(r: Option<Rect>) {
    *HOSTED.lock().unwrap_or_else(|e| e.into_inner()) = r;
}

/// Desktop-relative → screen coordinates on the hosted region (identity when not hosted).
pub fn to_screen(x: i64, y: i64) -> (i64, i64) {
    hosted().map_or((x, y), |r| (x + i64::from(r.x), y + i64::from(r.y)))
}

/// The `hosted` state file of the Bot Desktop: `x y w h`.
pub fn parse_hosted(s: &str) -> Option<Rect> {
    let v: Vec<i32> = s.split_whitespace().map(|x| x.parse().ok()).collect::<Option<_>>()?;
    match v[..] {
        [x, y, w, h] if w > 0 && h > 0 => Some(Rect { x, y, w, h }),
        _ => None,
    }
}

/// Where a Bot Desktop starting now is hosted: the attached virtual monitor (moved out of the
/// way first), unless `SEAGENT_BOT_DISPLAY=isolated`.
#[cfg(windows)]
pub fn host_region() -> Option<Rect> {
    if !hosting_allowed(std::env::var(ENV).ok().as_deref()) {
        return None;
    }
    ensure_out_of_the_way()
}

#[cfg(windows)]
pub use sys::{adopt_pid, close_hosted, elevate, ensure_out_of_the_way, grab_region, launch_native, probe, screens};

#[cfg(not(windows))]
pub fn probe() -> Status {
    Status::default()
}

#[cfg(windows)]
mod sys;

#[cfg(test)]
mod tests {
    use super::*;

    fn r(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }

    fn screen(adapter: &str, id: &str, attached: bool, rect: Rect) -> Screen {
        Screen { name: "\\\\.\\DISPLAY3".into(), adapter: adapter.into(), id: id.into(), attached, primary: false, rect, hz: 60 }
    }

    #[test]
    fn the_driver_is_recognised_by_its_adapter_name_or_id_and_its_class_key() {
        assert!(is_vdd_adapter("Virtual Display Driver", ""));
        assert!(is_vdd_adapter("", "ROOT\\MTTVDD"));
        assert!(is_vdd_adapter("", "Root\\MttVDD"));
        assert!(!is_vdd_adapter("NVIDIA GeForce RTX 4060 Ti", "PCI\\VEN_10DE&DEV_2803"));
        let keys = vec![("pci\\ven_10de&dev_2803".to_string(), "32.0.15.6094".to_string()), ("root\\mttvdd".to_string(), "11.30.4.434".to_string())];
        assert_eq!(installed_version(&keys).as_deref(), Some("11.30.4.434"));
        assert_eq!(installed_version(&keys[..1]), None);
        let detached = screen("Virtual Display Driver", "", false, r(0, 0, 0, 0));
        let attached = screen("Virtual Display Driver", "", true, r(3840, 1080, 1920, 1080));
        let gpu = Screen { adapter: "NVIDIA".into(), attached: true, rect: r(0, 0, 1920, 1080), ..Default::default() };
        assert_eq!(virtual_monitor(&[gpu.clone(), detached.clone()]), None, "a detached virtual screen is not a monitor");
        assert_eq!(virtual_monitor(&[gpu, detached, attached.clone()]), Some(&attached));
    }

    #[test]
    fn the_monitor_goes_to_the_outside_corner_and_never_shares_an_edge() {
        // The user's layout here: two 1080p screens side by side.
        let real = [r(0, 0, 1920, 1080), r(1920, 0, 1920, 1080)];
        let (x, y) = corner_origin(&real);
        assert_eq!((x, y), (3840, 1080));
        let v = r(x, y, 1920, 1080);
        assert!(out_of_the_way(&v, &real));
        assert!(!out_of_the_way(&r(3840, 0, 1920, 1080), &real), "right of the second screen: a shared edge");
        assert!(!out_of_the_way(&r(0, 1080, 1920, 1080), &real), "below the first screen: a shared edge");
        assert!(!out_of_the_way(&r(100, 100, 1920, 1080), &real), "overlapping");
        // Uneven heights and negative coordinates (a screen left of the primary).
        let real = [r(-2560, -360, 2560, 1440), r(0, 0, 1920, 1080)];
        let (x, y) = corner_origin(&real);
        assert_eq!((x, y), (1920, 1080));
        assert!(out_of_the_way(&r(x, y, 1920, 1080), &real));
        assert_eq!(corner_origin(&[]), (0, 0));
    }

    #[test]
    fn hosted_windows_are_kept_on_the_monitor() {
        let mon = r(3840, 1080, 1920, 1080);
        assert_eq!(herd(r(3900, 1100, 800, 600), mon), None, "inside: left alone");
        assert_eq!(herd(r(100, 100, 800, 600), mon), Some(r(3840, 1080, 800, 600)), "opened on the user's screen: moved over");
        assert_eq!(herd(r(5500, 1500, 800, 600), mon), Some(r(4960, 1500, 800, 600)), "hanging off the right edge: pulled in");
        assert_eq!(herd(r(0, 0, 2560, 1440), mon), Some(r(3840, 1080, 1920, 1080)), "too big: at most the monitor");
    }

    #[test]
    fn status_says_why_fps_is_low_and_what_to_do() {
        let script = Some(PathBuf::from("C:\\x\\vdd\\install-vdd.ps1"));
        let none = Status { windows: true, script: script.clone(), ..Default::default() };
        let (code, msg) = none.reason().unwrap();
        assert_eq!(code, "not_installed");
        assert!(msg.contains("10 fps") && msg.contains("安裝"), "{msg}");
        assert_eq!(none.to_json()["mode"], "isolated");
        let unbundled = Status { windows: true, ..Default::default() };
        assert!(unbundled.reason().unwrap().1.contains("重新安裝"));
        let detached = Status { windows: true, version: Some(DRIVER_VERSION.into()), script: script.clone(), ..Default::default() };
        assert_eq!(detached.reason().unwrap().0, "no_monitor");
        let mon = Screen { adapter: "Virtual Display Driver".into(), attached: true, rect: r(3840, 1080, 1920, 1080), hz: 60, ..Default::default() };
        let on = Status { windows: true, version: Some(DRIVER_VERSION.into()), monitor: Some(mon), script, forced_isolated: false };
        assert!(on.active() && on.reason().is_none());
        let j = on.to_json();
        assert_eq!((j["mode"].as_str(), j["monitor"]["rect"]["x"].as_i64(), j["monitor"]["hz"].as_u64()), (Some("virtual-display"), Some(3840), Some(60)));
        let forced = Status { forced_isolated: true, ..on };
        assert_eq!(forced.reason().unwrap().0, "isolated");
        assert!(Status::default().reason().is_none(), "not Windows: nothing to explain");
        assert!(hosting_allowed(None) && hosting_allowed(Some("virtual")));
        assert!(!hosting_allowed(Some("isolated")) && !hosting_allowed(Some(" off ")));
    }

    #[test]
    fn settings_actions_map_to_the_script() {
        assert_eq!(Action::parse("repair"), Some(Action::Install));
        assert_eq!(Action::parse("uninstall"), Some(Action::Uninstall));
        assert_eq!(Action::parse("rm -rf"), None);
        let p = Path::new("C:\\Program Files\\SE Agent\\vdd\\install-vdd.ps1");
        assert_eq!(script_args(Action::Install, p), "-NoProfile -ExecutionPolicy Bypass -File \"C:\\Program Files\\SE Agent\\vdd\\install-vdd.ps1\"");
        assert!(script_args(Action::Uninstall, p).ends_with("\" -Uninstall"));
        let found = script_in(None, None).expect("the checkout's install-vdd.ps1");
        assert!(found.ends_with(SCRIPT));
        let root = seagent_core::tmp::TempDir::new("seagent-vdd");
        std::fs::write(root.path().join(SCRIPT), "#").unwrap();
        assert_eq!(script_in(Some(root.path().to_path_buf()), None), Some(root.path().join(SCRIPT)), "$SEAGENT_VDD_DIR first");
    }

    /// The installer script and this module agree: hardware id, mode, the pinned SHA-256 of
    /// every bundled file (the same as the fetch script and DEPENDENCY-REVIEW.md), and it never
    /// touches test signing, Secure Boot or the certificate stores.
    #[test]
    fn the_installer_script_matches_the_reviewed_driver() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/windows/vdd");
        let ps = std::fs::read_to_string(dir.join(SCRIPT)).unwrap();
        assert!(ps.starts_with('\u{feff}'), "UTF-8 with BOM: Windows PowerShell 5.1 reads BOM-less files in the ANSI code page");
        assert!(ps.contains(&format!("$HwId     = '{HARDWARE_ID}'")));
        assert!(ps.contains(&format!("<width>{}</width><height>{}</height><refresh_rate>{}</refresh_rate>", MODE.0, MODE.1, MODE.2)));
        let fetch = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/scripts/fetch-vdd.sh")).unwrap();
        let review = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/release/DEPENDENCY-REVIEW.md")).unwrap();
        for (file, sha) in [("MttVDD.inf", "550d211fe481e74dfe3f9d724ed78be48b3a9113405965d683d9373e8d672f5d"), ("MttVDD.dll", "c9ca837f57a98fbd43bc416a7f535a95843626e7759eaf85cf0cd7ce334dbb05"), ("mttvdd.cat", "08a0093fc9b2e32b287a6f8a77ca4de0a31830d29fc33d2b13a918dc859468f6")] {
            assert!(ps.contains(&format!("'{file}' = '{sha}'")), "{file} pinned in the script");
            assert!(fetch.contains(sha) && review.contains(sha), "{file}: the same hash in fetch-vdd.sh and the review");
        }
        assert!(fetch.contains(RELEASE) && review.contains(DRIVER_VERSION));
        let lower = ps.to_lowercase();
        for banned in ["bcdedit", "testsigning", "cert:\\", "trustedpublisher", "import-certificate", "certutil"] {
            assert!(!lower.contains(banned), "the installer must not use {banned}");
        }
    }

    #[test]
    fn the_hosted_state_file_round_trips() {
        assert_eq!(parse_hosted("3840 1080 1920 1080"), Some(r(3840, 1080, 1920, 1080)));
        assert_eq!(parse_hosted("-1920 0 1920 1080\n"), Some(r(-1920, 0, 1920, 1080)));
        for bad in ["", "1 2 3", "1 2 0 5", "a b c d", "1 2 3 4 5"] {
            assert_eq!(parse_hosted(bad), None, "{bad:?}");
        }
    }

    /// Runs on every Windows host, driver or not: the probe is self-consistent, and without an
    /// attached virtual monitor the Bot Desktop stays isolated and the status says why fps is
    /// low and offers the install.
    #[cfg(windows)]
    #[test]
    fn probe_is_consistent_and_explains_the_fallback() {
        let s = probe();
        assert!(s.windows);
        assert_eq!(s.active(), s.monitor.is_some() && !s.forced_isolated);
        assert!(s.script.is_some(), "the checkout's installer is found");
        let attached: Vec<Screen> = screens().into_iter().filter(|x| x.attached).collect();
        eprintln!("vdd probe: version {:?}, monitor {:?}, {} attached screens", s.version, s.monitor.as_ref().map(|m| m.rect), attached.len());
        match s.reason() {
            None => assert!(s.active()),
            Some((code, msg)) => {
                assert!(!s.active());
                assert!(["not_installed", "no_monitor", "isolated"].contains(&code), "{code}");
                assert!(!msg.is_empty());
                assert_eq!(s.to_json()["mode"], "isolated");
                if s.monitor.is_none() {
                    assert_eq!(host_region(), None, "no monitor: the Bot Desktop stays isolated");
                }
            }
        }
    }

    /// With the driver installed: Notepad, Paint and an Explorer window launched on the hosted
    /// Bot Desktop land on the virtual monitor, off the taskbar, and the monitor's duplication
    /// delivers ≥ 30 fps while each one changes (not run by default: it opens windows on the
    /// virtual monitor of this session):
    /// `SEAGENT_REAL_TESTS=1 cargo test -p seagent-browser real_vdd -- --ignored --nocapture`.
    /// Skipped, saying so, when the driver is not installed.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn real_vdd_native_apps_stream_at_30_fps() {
        use crate::control::dxgi_dup::Duplication;
        use crate::control::screen_windows::{TrackUpdate, WinDesktop};
        use std::time::{Duration, Instant};
        if std::env::var_os("SEAGENT_REAL_TESTS").is_none() {
            eprintln!("real_vdd: set SEAGENT_REAL_TESTS=1 to run");
            return;
        }
        let s = probe();
        let Some(mon) = s.monitor.clone().filter(|_| s.active()) else {
            eprintln!("real_vdd: SKIPPED — the virtual display driver is not installed / attached ({:?}); install it with apps/desktop/src-tauri/windows/vdd/install-vdd.ps1 in an elevated PowerShell", s.reason().map(|r| r.0));
            return;
        };
        let root = seagent_core::tmp::TempDir::new("seagent-vdd");
        let d = WinDesktop::new(root.path(), &format!("vdd{}", std::process::id()), "1920x1080");
        d.start().expect("the Bot Desktop");
        let region = d.hosted().expect("hosted on the virtual monitor");
        assert_eq!((region.w, region.h), (mon.rect.w, mon.rect.h));
        let folder = root.path().join("folder");
        std::fs::create_dir_all(&folder).unwrap();
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        let apps: [(&str, PathBuf, Vec<String>); 3] = [("Notepad", Path::new(&windir).join("System32\\notepad.exe"), vec![]), ("Paint", Path::new(&windir).join("System32\\mspaint.exe"), vec![]), ("Explorer", Path::new(&windir).join("explorer.exe"), vec![folder.display().to_string()])];
        let mut dup = Duplication::open(&mon.name).expect("DXGI duplication of the virtual monitor");
        let mut failures = vec![];
        for (name, exe, args) in apps {
            let pid = launch_native(&exe, &args).expect("launched");
            std::thread::sleep(Duration::from_secs(4));
            let wins = sys::windows_in(region);
            eprintln!("real_vdd: {name} (pid {pid}): {} windows on the virtual monitor", wins.len());
            let Some(&w) = wins.last() else {
                failures.push(format!("{name}: no window on the virtual monitor"));
                continue;
            };
            // Change the picture continuously (a 1-px nudge every 8 ms) and count the frames the
            // monitor delivers: what the live view gets while the app is in use.
            let (t0, mut frames) = (Instant::now(), 0u32);
            let mut flip = false;
            while t0.elapsed() < Duration::from_secs(3) {
                sys::nudge(w, if flip { 1 } else { -1 });
                flip = !flip;
                if !matches!(dup.next(8).expect("a frame"), TrackUpdate::Same) {
                    frames += 1;
                }
            }
            let fps = f64::from(frames) / t0.elapsed().as_secs_f64();
            eprintln!("real_vdd: {name}: {frames} frames in 3 s = {fps:.1} fps");
            if fps < 30.0 {
                failures.push(format!("{name}: {fps:.1} fps"));
            }
        }
        d.stop();
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn the_hosted_region_offsets_coordinates() {
        set_hosted(Some(r(3840, 1080, 1920, 1080)));
        assert_eq!(to_screen(10, 20), (3850, 1100));
        set_hosted(None);
        assert_eq!(to_screen(10, 20), (10, 20));
    }
}
