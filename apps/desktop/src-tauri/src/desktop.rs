//! Desktop only: tray menu, login item, updates.

use crate::{boot, t, AppState};
use std::time::Duration;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

pub struct TrayItems<R: Runtime> {
    pub pause: CheckMenuItem<R>,
    pub autostart: CheckMenuItem<R>,
}

pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = crate::main_window(app) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn tray<R: Runtime>(app: &tauri::App<R>) -> tauri::Result<()> {
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let open = MenuItem::with_id(app, "open", t("開啟主控台", "Open console"), true, None::<&str>)?;
    let pause = CheckMenuItem::with_id(app, "pause", t("暫停 Agent", "Pause agent"), true, false, None::<&str>)?;
    let restart = MenuItem::with_id(app, "restart", t("重新啟動服務", "Restart service"), true, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(app, "autostart", t("登入時啟動", "Start at login"), true, autostart_on, None::<&str>)?;
    let update = MenuItem::with_id(app, "update", t("檢查更新…", "Check for updates…"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", t("結束（Agent 繼續在背景執行）", "Quit (agent keeps running)"), true, None::<&str>)?;
    let stop_quit = MenuItem::with_id(app, "stop-quit", t("停止 Agent 並結束", "Stop agent and quit"), true, None::<&str>)?;
    let s1 = PredefinedMenuItem::separator(app)?;
    let s2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &s1, &pause, &restart, &autostart, &update, &s2, &quit, &stop_quit])?;
    app.manage(TrayItems { pause, autostart });

    let mut tb = TrayIconBuilder::with_id("main").tooltip("SE Agent").menu(&menu).show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        tb = tb.icon(icon.clone());
    }
    tb.on_menu_event(|app, ev| on_menu(app, ev.id().as_ref()))
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn agent_bg<R: Runtime>(app: &AppHandle<R>, f: impl FnOnce(&AppHandle<R>, &crate::agent::Agent) + Send + 'static) {
    let app = app.clone();
    std::thread::spawn(move || match boot::locate(&app) {
        Ok(a) => f(&app, &a),
        Err(e) => error(&app, &e),
    });
}

/// Linux: the UI is mostly Chinese, and a minimal desktop (WSLg, server installs, the AppImage on a
/// fresh distro) may have no CJK font at all — then every Chinese character is a box. The .deb /
/// .rpm recommend Noto CJK; the AppImage cannot pull it in, so say so once per install (in English:
/// a Chinese message would be unreadable for the same reason).
#[cfg(target_os = "linux")]
pub fn cjk_font_check<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    std::thread::spawn(move || {
        let out = match std::process::Command::new("fc-list").args([":lang=zh", "family"]).output() {
            Ok(o) if o.status.success() => o,
            _ => return, // no fontconfig tools: nothing reliable to say
        };
        if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            return;
        }
        eprintln!("seagent-desktop: no Chinese (CJK) font installed; Chinese text will show as boxes. Install fonts-noto-cjk (Debian/Ubuntu) or google-noto-sans-cjk-ttc-fonts (Fedora).");
        let stamp = app.state::<AppState>().data_dir.join("cjk-font-warned");
        if stamp.exists() {
            return;
        }
        let _ = std::fs::write(&stamp, b"");
        app.dialog()
            .message(
                "No Chinese (CJK) font is installed, so Chinese text in SE Agent will show as boxes.\n\n\
                 Install one and restart the app:\n  Debian/Ubuntu: sudo apt install fonts-noto-cjk\n  \
                 Fedora: sudo dnf install google-noto-sans-cjk-ttc-fonts\n  Arch: sudo pacman -S noto-fonts-cjk",
            )
            .title("SE Agent")
            .kind(MessageDialogKind::Warning)
            .show(|_| {});
    });
}

fn error<R: Runtime>(app: &AppHandle<R>, msg: &str) {
    app.dialog().message(msg).title("SE Agent").kind(MessageDialogKind::Error).show(|_| {});
}

fn on_menu<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
        "open" => open_console(app),
        "pause" => {
            let want = app.state::<TrayItems<R>>().pause.is_checked().unwrap_or(false);
            agent_bg(app, move |app, a| {
                let args: &[&str] = if want { &["pause", "paused from the SE Agent app"] } else { &["resume"] };
                let ok = a.run(args, Duration::from_secs(20)).map(|o| o.ok()).unwrap_or(false);
                if !ok {
                    let _ = app.state::<TrayItems<R>>().pause.set_checked(!want);
                    error(app, t("無法變更暫停狀態", "Could not change the pause state"));
                }
            });
        }
        "restart" => agent_bg(app, |app, a| {
            let _ = a.run(&["service", "restart"], Duration::from_secs(120));
            let base = app.state::<AppState>().base.lock().unwrap().clone();
            match base {
                Some(b) if boot::wait_healthy(&b, Duration::from_secs(90)) => {
                    // Reload whatever the window shows (wizard or console) on the restarted server.
                    if let Some(w) = crate::main_window(app) {
                        let _ = w.eval("location.reload()");
                    }
                }
                Some(_) => error(app, t("服務重新啟動後沒有回應", "The service did not come back after the restart")),
                None => boot::start(app.clone()),
            }
        }),
        "autostart" => {
            let on = app.state::<TrayItems<R>>().autostart.is_checked().unwrap_or(false);
            if let Err(e) = set_autostart(app, on) {
                error(app, &e);
            }
        }
        "update" => check_updates(app.clone(), true),
        "quit" => app.exit(0),
        "stop-quit" => {
            let app2 = app.clone();
            app.dialog()
                .message(t("停止背景的 SE Agent？排程工作、頻道與目標都會暫停，直到下次開啟 App。", "Stop the background SE Agent? Scheduled jobs, channels and goals stop until you open the app again."))
                .title("SE Agent")
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(t("停止並結束", "Stop and quit").into(), t("取消", "Cancel").into()))
                .show(move |yes| {
                    if yes {
                        app2.state::<AppState>().quitting.store(true, std::sync::atomic::Ordering::SeqCst);
                        if let Ok(a) = boot::locate(&app2) {
                            let _ = a.run(&["daemon", "stop"], Duration::from_secs(30));
                        }
                        app2.exit(0);
                    }
                });
        }
        _ => {}
    }
}

/// Show the console (or the wizard, if setup is still pending) with a fresh login.
pub fn open_console<R: Runtime>(app: &AppHandle<R>) {
    show_main(app);
    let base = app.state::<AppState>().base.lock().unwrap().clone();
    let Some(base) = base else {
        boot::start(app.clone());
        return;
    };
    agent_bg(app, move |app, a| {
        match boot::route(app, a, &base) {
            Ok(u) => {
                let _ = crate::open_url(app, &u, true);
            }
            Err(_) => boot::start(app.clone()),
        }
    });
}

pub fn set_autostart<R: Runtime>(app: &AppHandle<R>, on: bool) -> Result<(), String> {
    let al = app.autolaunch();
    let r = if on { al.enable() } else { al.disable() };
    r.map_err(|e| e.to_string())?;
    if let Some(items) = app.try_state::<TrayItems<R>>() {
        let _ = items.autostart.set_checked(on);
    }
    Ok(())
}

pub fn autostart<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.autolaunch().is_enabled().unwrap_or(false)
}

/// After a successful boot: sync the pause checkbox and look for updates (once per launch).
pub fn after_boot<R: Runtime>(app: &AppHandle<R>) {
    agent_bg(app, |app, a| {
        if let Ok(o) = a.run(&["pause", "status"], Duration::from_secs(15)) {
            let paused = o.stdout.trim_start().starts_with("paused");
            let _ = app.state::<TrayItems<R>>().pause.set_checked(paused);
        }
    });
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| check_updates(app.clone(), false));
}

fn updater_configured<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.config().plugins.0.get("updater").and_then(|u| u.get("pubkey")).and_then(|v| v.as_str()).is_some_and(|k| !k.trim().is_empty())
}

/// Check GitHub releases (`latest.json`). Builds without an updater key (local / unsigned CI
/// builds) skip this silently, or say so when the user asked.
pub fn check_updates<R: Runtime>(app: AppHandle<R>, interactive: bool) {
    use tauri_plugin_updater::UpdaterExt;
    if !updater_configured(&app) {
        if interactive {
            app.dialog().message(t("這個版本沒有設定自動更新；請到 GitHub Releases 下載新版。", "This build has no update key configured; download new versions from GitHub Releases.")).title("SE Agent").show(|_| {});
        }
        return;
    }
    tauri::async_runtime::spawn(async move {
        let found = match app.updater() {
            Ok(u) => u.check().await,
            Err(e) => Err(e),
        };
        match found {
            Ok(Some(update)) => {
                let app2 = app.clone();
                let msg = format!("{} {} → {}", t("有新版本的 SE Agent：", "A new version of SE Agent is available:"), update.current_version, update.version);
                app.dialog()
                    .message(msg)
                    .title("SE Agent")
                    .buttons(MessageDialogButtons::OkCancelCustom(t("安裝並重新啟動", "Install and restart").into(), t("稍後", "Later").into()))
                    .show(move |yes| {
                        if !yes {
                            return;
                        }
                        tauri::async_runtime::spawn(async move {
                            // The installer replaces the sidecar too: on Windows a running
                            // seagent.exe is locked, so stop the daemon first. The relaunched app
                            // starts it again with the new binary.
                            app2.state::<AppState>().quitting.store(true, std::sync::atomic::Ordering::SeqCst);
                            if let Ok(a) = boot::locate(&app2) {
                                let _ = tauri::async_runtime::spawn_blocking(move || a.run(&["daemon", "stop"], Duration::from_secs(30))).await;
                            }
                            match update.download_and_install(|_, _| {}, || {}).await {
                                Ok(()) => app2.restart(),
                                Err(e) => error(&app2, &format!("{}: {e}", t("更新失敗", "Update failed"))),
                            }
                        });
                    });
            }
            Ok(None) => {
                if interactive {
                    app.dialog().message(t("已是最新版本。", "SE Agent is up to date.")).title("SE Agent").show(|_| {});
                }
            }
            Err(e) => {
                if interactive {
                    error(&app, &format!("{}: {e}", t("檢查更新失敗", "Could not check for updates")));
                }
            }
        }
    });
}
