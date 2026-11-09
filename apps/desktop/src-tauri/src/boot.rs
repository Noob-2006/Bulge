//! First run and every launch with a local agent: locate `seagent`, make sure its config can
//! serve the console, start the background service, wait for the App Server, then open the
//! setup wizard (not set up yet) or the console. Progress goes to the splash page as `boot`
//! events (and `boot_state` for a page that loads late).

use crate::agent::{self, Agent};
use crate::{t, AppState};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, Runtime};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub step: String,
    pub progress: u8,
    pub title: String,
    pub error: Option<String>,
    /// Everything that ran, for "Copy details" (tokens are never logged).
    pub log: Vec<String>,
    pub url: Option<String>,
    pub running: bool,
}

fn update<R: Runtime>(app: &AppHandle<R>, f: impl FnOnce(&mut Snapshot)) {
    let st = app.state::<AppState>();
    let snap = {
        let mut s = st.boot.lock().unwrap();
        f(&mut s);
        s.clone()
    };
    let _ = app.emit("boot", snap);
}

fn step<R: Runtime>(app: &AppHandle<R>, id: &str, progress: u8, title: &str) {
    update(app, |s| {
        s.step = id.into();
        s.progress = progress;
        s.title = title.into();
    });
}

fn log<R: Runtime>(app: &AppHandle<R>, line: String) {
    update(app, |s| s.log.push(line));
}

/// Start the boot sequence once (no-op while one is running).
pub fn start<R: Runtime>(app: AppHandle<R>) {
    let st = app.state::<AppState>();
    if st.booting.swap(true, Ordering::SeqCst) {
        return;
    }
    {
        let mut s = st.boot.lock().unwrap();
        *s = Snapshot { running: true, ..Default::default() };
        s.log.push(format!("SE Agent app {} · {} {} · {}", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH, env!("SEAGENT_TARGET_TRIPLE")));
    }
    std::thread::spawn(move || {
        let r = run(&app);
        let st = app.state::<AppState>();
        match r {
            Ok(url) => {
                update(&app, |s| {
                    s.step = "done".into();
                    s.progress = 100;
                    s.url = Some(url.clone());
                    s.running = false;
                });
                let show = !st.background || url.contains("/setup#");
                if let Err(e) = crate::open_url(&app, &url, show) {
                    update(&app, |s| s.error = Some(e));
                }
                let _ = std::fs::write(st.data_dir.join("installed.json"), "{\"ok\":true}");
                #[cfg(desktop)]
                crate::desktop::after_boot(&app);
            }
            Err(e) => {
                update(&app, |s| {
                    s.error = Some(e);
                    s.running = false;
                });
                #[cfg(desktop)]
                crate::desktop::show_main(&app);
            }
        }
        st.booting.store(false, Ordering::SeqCst);
    });
}

/// The bundled agent for this platform.
pub fn locate<R: Runtime>(app: &AppHandle<R>) -> Result<Agent, String> {
    let st = app.state::<AppState>();
    if let Some(a) = st.agent.lock().unwrap().clone() {
        return Ok(a);
    }
    #[cfg(target_os = "android")]
    let a = {
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        let info = app.seagent_mobile().info()?;
        Agent { exe: info.exe.into(), env: info.env.into_iter().map(|(k, v)| (k, v.into())).collect() }
    };
    #[cfg(target_os = "ios")]
    let a: Agent = {
        let _ = &st;
        Err(t("iOS 不能在本機執行 SE Agent（沒有 VM 與本機 shell），請連線到區域網路中的主機。", "SE Agent cannot run on iOS itself (no VM, no local shell); connect to a host on your network.").to_string())?
    };
    #[cfg(desktop)]
    let a = {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let share = app.path().resource_dir().ok().map(|d| d.join("share"));
        Agent::locate(&exe, env!("SEAGENT_TARGET_TRIPLE"), share)?
    };
    *st.agent.lock().unwrap() = Some(a.clone());
    Ok(a)
}

fn call<R: Runtime>(app: &AppHandle<R>, a: &Agent, args: &[&str], secs: u64) -> Result<agent::Out, String> {
    let out = a.run(args, Duration::from_secs(secs))?;
    log(app, out.summary(args));
    Ok(out)
}

fn start_daemon<R: Runtime>(app: &AppHandle<R>, a: &Agent) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = a;
        use tauri_plugin_seagent_mobile::SeagentMobileExt;
        log(app, "starting the Android foreground service".into());
        return app.seagent_mobile().start_agent();
    }
    #[cfg(not(target_os = "android"))]
    {
        let out = call(app, a, &["daemon", "start"], 60)?;
        if !out.ok() {
            return Err(format!("{} (seagent daemon start: exit {:?})", t("背景服務無法啟動", "the background service did not start"), out.code));
        }
        Ok(())
    }
}

/// Wait for GET /health on the App Server.
pub fn wait_healthy(base: &str, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if agent::health(base, Duration::from_secs(2)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    false
}

/// The console URL with a login token in the fragment (never sent to servers or logs).
pub fn console_url<R: Runtime>(app: &AppHandle<R>, a: &Agent, base: &str) -> Result<String, String> {
    let out = call(app, a, &["app", "token"], 20)?;
    let tok = agent::parse_token(&out.stdout).ok_or_else(|| t("找不到主控台權杖（seagent app token）", "no console token is configured (seagent app token)").to_string())?;
    Ok(format!("{base}/#token={tok}"))
}

fn run<R: Runtime>(app: &AppHandle<R>) -> Result<String, String> {
    let st = app.state::<AppState>();
    let first = !st.data_dir.join("installed.json").exists();
    step(app, "locate", 5, t("準備 SE Agent…", "Preparing SE Agent…"));
    let a = locate(app)?;
    log(app, format!("agent: {}", a.exe.display()));

    step(app, "bootstrap", 15, t("準備主控台設定…", "Preparing the console…"));
    let out = call(app, &a, &["setup", "bootstrap"], 60)?;
    if !out.ok() {
        return Err(t("無法寫入初始設定（seagent setup bootstrap）", "could not write the initial configuration (seagent setup bootstrap)").into());
    }
    let base = match agent::parse_console_line(&out.stderr).or_else(|| agent::parse_console_line(&out.stdout)) {
        Some(b) => b,
        None => call(app, &a, &["app", "status"], 20).ok().and_then(|o| agent::parse_app_status(&o.stdout)).unwrap_or_else(|| "http://127.0.0.1:8640".into()),
    };
    *st.base.lock().unwrap() = Some(base.clone());

    let running = call(app, &a, &["daemon", "status"], 15)?.ok();
    if !running {
        step(app, "service", 35, if first { t("安裝背景服務…", "Installing background service…") } else { t("啟動背景服務…", "Starting the background service…") });
        start_daemon(app, &a)?;
    }

    // The daemon may have moved off a busy default port (and saved the one it serves): ask for
    // the address it really uses instead of trusting bootstrap's answer or assuming 8640 —
    // otherwise another program, or another SE Agent (e.g. the Linux one in WSL, whose localhost
    // ports Windows forwards), would answer the health check below.
    let base = match call(app, &a, &["setup", "status", "--json"], 20).ok().filter(|o| o.ok()).and_then(|o| agent::parse_status_json(&o.stdout)) {
        Some(b) if b != base => {
            log(app, format!("console address: {b} (was {base})"));
            *st.base.lock().unwrap() = Some(b.clone());
            b
        }
        _ => base,
    };

    step(app, "health", 60, t("等待 SE Agent 回應…", "Waiting for SE Agent to answer…"));
    if !wait_healthy(&base, Duration::from_secs(90)) {
        let _ = call(app, &a, &["daemon", "status"], 15);
        return Err(format!("{} {base}/health", t("SE Agent 沒有回應：", "SE Agent did not answer at")));
    }

    step(app, "route", 85, t("開啟中…", "Opening…"));
    // Not set up yet → a fresh one-time wizard link. Once setup is done the command refuses
    // (the wizard is locked) and we open the console instead.
    let link = call(app, &a, &["setup", "link", "--json"], 20)?;
    if link.ok() {
        if let Some(u) = agent::parse_link_json(&link.stdout) {
            return Ok(u);
        }
    }
    console_url(app, &a, &base)
}
