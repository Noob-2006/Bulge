//! First run and every launch with a local agent: locate `seagent`, make sure its config can
//! serve the console, start the background service, wait for the App Server, then open the
//! setup wizard (not set up yet) or the console. Progress goes to the splash page as `boot`
//! events (and `boot_state` for a page that loads late).
//!
//! iOS has no `seagent` program to run (no child processes): there the agent starts inside this
//! process (`seagent::embed` through the mobile plugin), and the steps are the same from the
//! splash page's point of view.
// The sidecar steps below are what desktop and Android run; iOS uses `run` (embedded) only.
#![cfg_attr(target_os = "ios", allow(dead_code, unused_imports))]

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
                #[cfg(desktop)]
                supervise(app.clone());
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
        Err(t("iOS 上的 SE Agent 在 App 內執行，沒有可啟動的 seagent 程式。", "On iOS SE Agent runs inside the app; there is no seagent program to start.").to_string())?
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
        // `daemon start` itself waits up to a minute for a daemon that is still starting.
        let out = call(app, a, &["daemon", "start"], 90)?;
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

/// iOS: the agent in this process — Application Support as `SEAGENT_HOME`, the vault key from
/// the Keychain, the bundled `share/` (skills, WASI tools); the App Server on 127.0.0.1.
#[cfg(target_os = "ios")]
fn run<R: Runtime>(app: &AppHandle<R>) -> Result<String, String> {
    use tauri_plugin_seagent_mobile::SeagentMobileExt;
    let st = app.state::<AppState>();
    step(app, "locate", 10, t("準備 SE Agent…", "Preparing SE Agent…"));
    log(app, "iOS: the agent runs inside this app; commands use the WebAssembly sandbox (no VMs, no native shell on iOS)".into());
    step(app, "service", 40, t("在這支手機上啟動 SE Agent…", "Starting SE Agent on this device…"));
    let c = app.seagent_mobile().start_local()?;
    log(app, format!("console: {} ({})", c.base, if c.setup { "setup wizard" } else { "console" }));
    *st.base.lock().unwrap() = Some(c.base.clone());
    step(app, "route", 90, t("開啟中…", "Opening…"));
    Ok(c.url)
}

#[cfg(not(target_os = "ios"))]
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
    route(app, &a, &base)
}

/// Not set up yet → a fresh one-time wizard link. Once setup is done the command refuses (the
/// wizard is locked) and the console opens instead, with a fresh login.
pub fn route<R: Runtime>(app: &AppHandle<R>, a: &Agent, base: &str) -> Result<String, String> {
    let link = call(app, a, &["setup", "link", "--json"], 20)?;
    if link.ok() {
        if let Some(u) = agent::parse_link_json(&link.stdout) {
            return Ok(u);
        }
    }
    console_url(app, a, base)
}

/// The address the daemon really serves (it may have moved off a busy default port).
fn refresh_base<R: Runtime>(app: &AppHandle<R>, a: &Agent) {
    if let Some(b) = call(app, a, &["setup", "status", "--json"], 20).ok().filter(|o| o.ok()).and_then(|o| agent::parse_status_json(&o.stdout)) {
        *app.state::<AppState>().base.lock().unwrap() = Some(b);
    }
}

/// Desktop: from the first successful boot on, the app watches the daemon it owns
/// ([`crate::supervise`]): a daemon that stops — the setup wizard's restart, a crash — comes
/// back, and the window shows "restarting…" instead of a refused connection.
#[cfg(desktop)]
pub fn supervise<R: Runtime>(app: AppHandle<R>) {
    if app.state::<AppState>().supervising.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let Ok(a) = locate(&app) else { return };
        let mut h = AppHost { app, a };
        crate::supervise::run(&mut h, crate::supervise::Policy::default());
    });
}

#[cfg(desktop)]
struct AppHost<R: Runtime> {
    app: AppHandle<R>,
    a: Agent,
}

#[cfg(desktop)]
impl<R: Runtime> crate::supervise::Host for AppHost<R> {
    fn healthy(&mut self) -> bool {
        let base = self.app.state::<AppState>().base.lock().unwrap().clone();
        base.is_some_and(|b| agent::health(&b, Duration::from_secs(2)))
    }
    fn show_restarting(&mut self) {
        update(&self.app, |s| {
            s.step = "restarting".into();
            s.progress = 50;
            s.title = t("SE Agent 正在重新啟動…", "SE Agent is restarting…").into();
            s.error = None;
            s.url = None;
            s.running = true;
        });
        // The app's own page instead of the WebView's "refused to connect"; the window keeps
        // its visibility (a hidden window stays hidden).
        let _ = crate::open_url(&self.app, &crate::app_page("index.html#restarting"), false);
        refresh_base(&self.app, &self.a);
    }
    fn start_daemon(&mut self) -> Result<(), String> {
        start_daemon(&self.app, &self.a)?;
        refresh_base(&self.app, &self.a);
        Ok(())
    }
    fn reopen(&mut self) {
        refresh_base(&self.app, &self.a);
        let base = self.app.state::<AppState>().base.lock().unwrap().clone().unwrap_or_default();
        match route(&self.app, &self.a, &base) {
            Ok(url) => {
                update(&self.app, |s| {
                    s.step = "done".into();
                    s.progress = 100;
                    s.url = Some(url.clone());
                    s.running = false;
                    s.error = None;
                });
                let _ = crate::open_url(&self.app, &url, false);
            }
            Err(e) => self.give_up(e),
        }
    }
    fn give_up(&mut self, why: String) {
        update(&self.app, |s| {
            s.error = Some(why);
            s.running = false;
        });
        let _ = crate::open_url(&self.app, &crate::app_page("index.html#restarting"), false);
    }
    fn stopped(&self) -> bool {
        self.app.state::<AppState>().quitting.load(Ordering::SeqCst)
    }
    fn log(&mut self, line: String) {
        log(&self.app, line);
    }
}
