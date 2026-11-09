//! SE Agent app shell.
//!
//! - **Desktop** (Windows / macOS / Linux): runs the bundled `seagent` sidecar, makes sure the
//!   background daemon is up, then shows the agent's own web setup wizard (first run) or console
//!   in the window. Tray: open console, pause, restart service, start at login, updates, quit.
//! - **Android**: either the same thing with the agent running under a Foreground Service
//!   ("this phone"), or a client of another host on the LAN.
//! - **iOS**: client only (no VM, no local shell, no subprocesses — platform policy): discover a
//!   host via Bonjour, pair by QR or 8-character code, pin its TLS certificate, open its console.

mod agent;
mod boot;
mod commands;
#[cfg(desktop)]
mod desktop;
mod pair;
mod tls;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use tauri::{Manager, Runtime, Url, WebviewUrl, WebviewWindowBuilder};

pub const MAIN: &str = "main";

/// The UI language for native strings (tray, dialogs): Chinese when the system locale is zh-*.
pub fn zh() -> bool {
    sys_locale::get_locale().is_some_and(|l| l.to_ascii_lowercase().starts_with("zh"))
}

pub fn t(zh_s: &'static str, en: &'static str) -> &'static str {
    if zh() {
        zh_s
    } else {
        en
    }
}

/// How this install is used (persisted in `<app data>/mode.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The agent runs on this device (desktop always; Android when chosen).
    Local,
    /// Client of a paired host (iOS always; Android when chosen).
    Remote,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub boot: Mutex<boot::Snapshot>,
    pub booting: AtomicBool,
    pub agent: Mutex<Option<agent::Agent>>,
    /// `http://127.0.0.1:8640` of the local agent, once known.
    pub base: Mutex<Option<String>>,
    pub tunnel: tokio::sync::Mutex<Option<tls::Tunnel>>,
    pub background: bool,
}

impl AppState {
    pub fn mode(&self) -> Option<Mode> {
        if cfg!(target_os = "ios") {
            return Some(Mode::Remote);
        }
        if cfg!(desktop) {
            return Some(Mode::Local);
        }
        std::fs::read_to_string(self.data_dir.join("mode.json")).ok().and_then(|s| serde_json::from_str(&s).ok())
    }
    pub fn set_mode(&self, m: Mode) -> Result<(), String> {
        std::fs::create_dir_all(&self.data_dir).map_err(|e| e.to_string())?;
        std::fs::write(self.data_dir.join("mode.json"), serde_json::to_string(&m).unwrap_or_default()).map_err(|e| e.to_string())
    }
    pub fn hosts(&self) -> pair::Store {
        pair::Store::new(&self.data_dir)
    }
}

/// Pages the main window may show: the app's own, and the console on loopback (the local agent,
/// or the pinned-TLS tunnel to a paired host). Anything else opens in the system browser.
pub fn navigation_allowed(url: &Url) -> bool {
    match url.scheme() {
        "tauri" | "about" | "blob" | "data" => true,
        "http" | "https" => matches!(url.host_str(), Some("tauri.localhost" | "127.0.0.1" | "localhost" | "[::1]" | "::1")),
        _ => false,
    }
}

pub fn main_window<R: Runtime>(app: &tauri::AppHandle<R>) -> Option<tauri::WebviewWindow<R>> {
    app.get_webview_window(MAIN)
}

/// Point the main window at `url` (and show it unless we were started in the background).
pub fn open_url<R: Runtime>(app: &tauri::AppHandle<R>, url: &str, show: bool) -> Result<(), String> {
    let w = main_window(app).ok_or("no main window")?;
    let u: Url = url.parse().map_err(|e| format!("{url}: {e}"))?;
    w.navigate(u).map_err(|e| e.to_string())?;
    if show {
        let _ = w.show();
        let _ = w.set_focus();
    }
    Ok(())
}

fn build_window<R: Runtime>(app: &tauri::App<R>, visible: bool) -> tauri::Result<()> {
    let handle = app.handle().clone();
    let b = WebviewWindowBuilder::new(app, MAIN, WebviewUrl::App("index.html".into())).on_navigation(move |url| {
        if navigation_allowed(url) {
            return true;
        }
        if matches!(url.scheme(), "http" | "https" | "mailto") {
            use tauri_plugin_opener::OpenerExt;
            let _ = handle.opener().open_url(url.as_str(), None::<&str>);
        }
        false
    });
    #[cfg(desktop)]
    let b = b.title("SE Agent").inner_size(1200.0, 820.0).min_inner_size(820.0, 560.0).center().visible(visible);
    #[cfg(not(desktop))]
    let _ = visible;
    let w = b.build()?;
    #[cfg(desktop)]
    {
        // Closing the window keeps the app (and its tray) running: the agent works in the background.
        let w2 = w.clone();
        w.on_window_event(move |e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = w2.hide();
            }
        });
    }
    #[cfg(not(desktop))]
    let _ = w;
    Ok(())
}

/// AppImage only: nothing pulls in a CJK font for it (the .deb/.rpm Recommend Noto CJK), so it
/// carries Noto Sans TC (`usr/share/seagent-desktop/fonts`, see `scripts/fetch-cjk-font.sh`). When
/// the system has no CJK font at all, point fontconfig at the bundled `fonts.conf` (= the system
/// configuration plus that font). It is copied to `$XDG_DATA_HOME/seagent-desktop/fonts` first: the
/// AppImage mount disappears when the app quits, while processes that inherit FONTCONFIG_FILE (the
/// agent daemon, a browser opened from the console) live on — a dangling path would leave them
/// with no fonts at all. Systems that have a CJK font are left alone (their fonts keep priority).
#[cfg(target_os = "linux")]
fn appimage_cjk_font() {
    use std::path::Path;
    let Some(appdir) = std::env::var_os("APPDIR") else { return };
    if std::env::var_os("FONTCONFIG_FILE").is_some() {
        return;
    }
    let src = Path::new(&appdir).join("usr/share/seagent-desktop/fonts");
    if !src.join("fonts.conf").is_file() {
        return;
    }
    let has_cjk = std::process::Command::new("fc-list")
        .args([":lang=zh", "family"])
        .output()
        .map(|o| o.status.success() && !o.stdout.iter().all(u8::is_ascii_whitespace))
        .unwrap_or(false);
    if has_cjk {
        return;
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    let Some(dst) = data.map(|d| d.join("seagent-desktop/fonts")) else { return };
    let copied = std::fs::create_dir_all(&dst).is_ok()
        && ["NotoSansTC-VF.ttf", "OFL.txt", "fonts.conf"].iter().all(|f| {
            let (s, d) = (src.join(f), dst.join(f));
            let same = matches!((std::fs::metadata(&s), std::fs::metadata(&d)), (Ok(a), Ok(b)) if a.len() == b.len());
            same || std::fs::copy(&s, &d).is_ok()
        });
    // Fall back to the mount itself rather than showing boxes.
    let conf = if copied { dst.join("fonts.conf") } else { src.join("fonts.conf") };
    eprintln!("seagent-desktop: no system CJK font; using the bundled Noto Sans TC ({})", conf.display());
    std::env::set_var("FONTCONFIG_FILE", conf);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Before any thread or GTK/WebKit process starts (they read FONTCONFIG_FILE once).
    #[cfg(target_os = "linux")]
    appimage_cjk_font();
    let background = std::env::args().any(|a| a == "--background");
    let mut builder = tauri::Builder::default();
    #[cfg(desktop)]
    {
        // First: a second launch only brings the existing window forward.
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| desktop::show_main(app)))
            .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--background"])))
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_dialog::init());
    }
    #[cfg(mobile)]
    {
        builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    }
    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_seagent_mobile::init())
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::boot_start,
            commands::boot_state,
            commands::set_mode,
            commands::autostart_get,
            commands::autostart_set,
            commands::discover_hosts,
            commands::parse_setup_code,
            commands::probe_host,
            commands::pair_host,
            commands::hosts_list,
            commands::host_open,
            commands::host_forget,
            commands::show_local,
        ])
        .setup(move |app| {
            let data_dir = app.path().app_data_dir().unwrap_or_else(|_| std::env::temp_dir().join("seagent-app"));
            let _ = std::fs::create_dir_all(&data_dir);
            app.manage(AppState { data_dir, boot: Mutex::new(boot::Snapshot::default()), booting: AtomicBool::new(false), agent: Mutex::new(None), base: Mutex::new(None), tunnel: tokio::sync::Mutex::new(None), background });
            build_window(app, !background)?;
            #[cfg(desktop)]
            {
                desktop::tray(app)?;
                // In the background (login item) nobody is looking at the splash: boot right away
                // so the daemon is up. Otherwise the splash page calls `boot_start` itself.
                if background {
                    boot::start(app.handle().clone());
                }
                #[cfg(target_os = "linux")]
                if !background {
                    desktop::cjk_font_check(app.handle());
                }
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the SE Agent app")
        .run(|_app, _event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                desktop::show_main(_app);
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn navigation_policy() {
        let ok = |u: &str| super::navigation_allowed(&u.parse().unwrap());
        assert!(ok("tauri://localhost/index.html"));
        assert!(ok("http://tauri.localhost/index.html"));
        assert!(ok("http://127.0.0.1:8640/setup#token=x"));
        assert!(ok("http://[::1]:8640/"));
        assert!(!ok("https://example.com/"));
        assert!(!ok("http://127.0.0.1.evil.example/"));
        assert!(!ok("file:///etc/passwd"));
    }
}
