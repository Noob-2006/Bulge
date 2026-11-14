//! Which browser a call runs in, and its lifecycle (Hermes `browser_tool_session.py`
//! / `browser_tool_lifecycle.py`, OpenClaw profiles + control service, MIT):
//! managed profiles seagent launches, the user's CDP endpoint or running Chrome
//! (existing-session), cloud sessions per seagent session (with a local sidecar for
//! private URLs), Lightpanda, the docker sandbox browser and the extension relay.
//! Idle browsers are closed after `inactivity_timeout`; recordings are encoded on close.

use crate::cdp::{self, Conn};
use crate::cloud;
use crate::config::{BrowserConfig, ProfileConfig};
use crate::engine::Browser;
use crate::launch;
use crate::util;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub type SecretFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Everything a browser call needs from its caller.
#[derive(Clone)]
pub struct Env {
    pub cfg: BrowserConfig,
    /// seagent home (~/.local/share/seagent); browser state lives in `<home>/browser`.
    pub home: PathBuf,
    pub secrets: SecretFn,
}

/// Where a desktop VM keeps its state (`seagent_vm::desktop::DesktopVms::vm_dir`): the takeover
/// lease lives under it, and while it runs, `cdp.url` names its Chromium's DevTools endpoint.
pub fn vm_home(home: &std::path::Path, vm: &str) -> PathBuf {
    home.join("vm").join("desktop").join(vm)
}
pub const VM_CDP_FILE: &str = "cdp.url";

/// The lease that governs browser `key`: a VM's own for its Chromium, else the Bot Desktop's.
pub fn lease_home(home: &std::path::Path, key: &str) -> PathBuf {
    match key.strip_prefix("vm:") {
        Some(vm) => vm_home(home, vm),
        None => home.to_path_buf(),
    }
}

impl Env {
    pub fn dir(&self) -> PathBuf {
        self.home.join("browser")
    }
    pub fn secret(&self, name: &str) -> Option<String> {
        cloud::secret(&*self.secrets, name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Sess {
    pub key: String,
    pub target: Option<String>,
    pub context: Option<String>,
    pub navigated: bool,
}

/// A resolved CDP endpoint, plus what seagent owns behind it.
struct Endpoint<'a> {
    /// Kind recorded on the browser (`cdp`, `local`, `lightpanda`, a cloud provider, …).
    kind: &'a str,
    ws: String,
    http: Option<String>,
    auth: Option<String>,
    pid: Option<i32>,
    /// seagent launched this browser, so closing the connection must also stop it.
    owned: bool,
    /// The endpoint is a cloud bridge: keep private (localhost) URLs local.
    bridge: bool,
}

#[derive(Default)]
pub struct Manager {
    browsers: Mutex<HashMap<String, Arc<Browser>>>,
    sessions: Mutex<HashMap<String, Sess>>,
    starting: Mutex<()>,
    pub camofox: crate::camofox::Camofox,
    idle_secs: AtomicU64,
}

pub fn global() -> &'static Manager {
    static M: OnceLock<Manager> = OnceLock::new();
    static REAPER: OnceLock<()> = OnceLock::new();
    let m = M.get_or_init(Manager::default);
    REAPER.get_or_init(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_secs(30));
            global().reap();
        });
    });
    m
}

/// Profiles: configured ones plus OpenClaw's implicit `user` (attach to your running Chrome).
pub fn profiles(cfg: &BrowserConfig) -> Vec<(String, ProfileConfig)> {
    let mut v: Vec<(String, ProfileConfig)> = cfg.profiles.iter().map(|(k, p)| (k.clone(), p.clone())).collect();
    if !cfg.profiles.contains_key(&cfg.default_profile) {
        v.insert(0, (cfg.default_profile.clone(), ProfileConfig { driver: "managed".into(), ..Default::default() }));
    }
    if !cfg.profiles.contains_key("user") {
        v.push(("user".into(), ProfileConfig { driver: "existing-session".into(), ..Default::default() }));
    }
    v
}

pub fn profile(cfg: &BrowserConfig, name: &str) -> Result<ProfileConfig, String> {
    crate::config::valid_profile_name(name)?;
    profiles(cfg).into_iter().find(|(n, _)| n == name).map(|(_, p)| p).ok_or_else(|| format!("unknown browser profile `{name}`; profiles: {}", profiles(cfg).iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")))
}

/// Bot Desktop display env (`<home>/bot-desktop/env`, written by `seagent screen start`)
/// so headed browsers open on the agent's own screen.
pub fn desktop_env(home: &Path) -> Vec<(String, String)> {
    let d = home.join("bot-desktop");
    let alive = std::fs::read_to_string(d.join("launcher.pid")).ok().and_then(|s| s.split_whitespace().next().and_then(|p| p.parse::<i32>().ok())).is_some_and(util::pid_alive);
    if !alive {
        return vec![];
    }
    let _ = std::fs::write(d.join("activity"), util::now_ms().to_string());
    std::fs::read_to_string(d.join("env")).unwrap_or_default().lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn has_display(env: &[(String, String)]) -> bool {
    // Windows / macOS: the logged-in desktop session is the display (no DISPLAY variable).
    if cfg!(any(windows, target_os = "macos")) {
        return true;
    }
    env.iter().any(|(k, _)| k == "DISPLAY") || std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

impl Manager {
    pub fn browsers(&self) -> Vec<Arc<Browser>> {
        self.browsers.lock().unwrap().values().cloned().collect()
    }

    pub fn get(&self, key: &str) -> Option<Arc<Browser>> {
        self.browsers.lock().unwrap().get(key).filter(|b| !b.conn.is_closed()).cloned()
    }

    pub fn session(&self, sid: &str) -> Sess {
        self.sessions.lock().unwrap().get(sid).cloned().unwrap_or_default()
    }

    /// Test-only: hand out `b` for `key` instead of launching one (the lightpanda fallback,
    /// the sidecar Chrome and the cloud providers all go through this lookup).
    #[cfg(test)]
    pub fn put_for_test(&self, key: &str, b: std::sync::Arc<Browser>) {
        self.browsers.lock().unwrap().insert(key.into(), b);
    }

    pub fn set_session(&self, sid: &str, s: Sess) {
        self.sessions.lock().unwrap().insert(sid.into(), s);
    }

    /// The browser key a call uses (Hermes precedence; `profile` = OpenClaw profile).
    pub fn key_for(&self, env: &Env, profile: Option<&str>, sid: &str, url: Option<&str>) -> String {
        if let Some(p) = profile.filter(|p| !p.is_empty()) {
            return format!("profile:{p}");
        }
        let backend = env.cfg.backend();
        match backend.as_str() {
            "cdp" => "cdp".into(),
            "vm" => format!("vm:{}", env.cfg.desktop_vm.trim()),
            "lightpanda" => "lightpanda".into(),
            "sandbox" => "sandbox".into(),
            "extension" => "extension".into(),
            "browserbase" | "browser-use" | "firecrawl" => {
                if env.cfg.auto_local_for_private_urls && env.cfg.allow_private_urls != Some(false) && url.is_some_and(|u| crate::policy::is_private(u) && !crate::policy::always_blocked(u)) {
                    "sidecar".into()
                } else {
                    format!("cloud:{backend}:{sid}")
                }
            }
            _ => format!("profile:{}", env.cfg.default_profile),
        }
    }

    /// The browser for `key`, started on first use.
    pub fn browser(&self, env: &Env, key: &str) -> Result<Arc<Browser>, String> {
        self.idle_secs.store(env.cfg.inactivity().as_secs(), Ordering::Relaxed);
        if let Some(b) = self.get(key) {
            b.touch();
            return Ok(b);
        }
        let _g = self.starting.lock().unwrap();
        if let Some(b) = self.get(key) {
            return Ok(b);
        }
        let b = self.start(env, key)?;
        self.browsers.lock().unwrap().insert(key.into(), b.clone());
        Ok(b)
    }

    fn wrap(&self, env: &Env, key: &str, ep: Endpoint<'_>) -> Result<Arc<Browser>, String> {
        let headers: Vec<(&str, &str)> = ep.auth.as_deref().map(|a| vec![("Authorization", a)]).unwrap_or_default();
        let conn = Conn::connect(&ep.ws, &headers, Duration::from_secs(15))?;
        let dir = env.dir().join("state").join(key.replace([':', '/'], "_"));
        Ok(Browser::new(key, ep.kind, conn, ep.http, ep.auth, ep.pid, ep.owned, dir, env.cfg.command_timeout(), &env.cfg.dialog_policy, env.cfg.dialog_timeout_s, ep.bridge))
    }

    fn start(&self, env: &Env, key: &str) -> Result<Arc<Browser>, String> {
        let cfg = &env.cfg;
        let dir = env.dir();
        util::private_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if key == "cdp" {
            let url = cfg.cdp_override();
            let auth = basic_from_url(&url);
            let ws = cdp::resolve_ws(&strip_userinfo(&url), auth.as_deref(), Duration::from_secs(10)).map_err(|e| format!("{e}. Start a Chromium-family browser with --remote-debugging-port and check browser.cdp_url."))?;
            let http = (!url.starts_with("ws")).then(|| strip_userinfo(&url));
            return self.wrap(env, key, Endpoint { kind: "cdp", ws, http, auth, pid: None, owned: false, bridge: false });
        }
        if let Some(vm) = key.strip_prefix("vm:") {
            let url = std::fs::read_to_string(vm_home(&env.home, vm).join(VM_CDP_FILE)).map(|s| s.trim().to_string()).unwrap_or_default();
            if url.is_empty() {
                // The daemon's supervisor (`[desktop_vm] autostart`) publishes why the VM is not up yet.
                let state: serde_json::Value = std::fs::read(env.home.join("vm").join("desktop").join("agent-vm.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
                return Err(match state["phase"].as_str() {
                    Some("building") => format!("desktop VM `{vm}` is being built for its first use ({}); it starts by itself when the build finishes — tell the user it is getting ready and retry in a few minutes", state["message"].as_str().unwrap_or("")),
                    Some("starting") => format!("desktop VM `{vm}` is booting; retry in a few seconds"),
                    Some("failed") => format!("desktop VM `{vm}` could not be brought up: {}", state["message"].as_str().unwrap_or("")),
                    _ => format!("desktop VM `{vm}` is not running (or was started before it offered its browser): start it with `seagent vm desktop start {vm}` or from the console (工作區 / 代理電腦), then retry"),
                });
            }
            let ws = cdp::resolve_ws(&url, None, Duration::from_secs(10)).map_err(|e| format!("the Chromium on desktop VM `{vm}` does not answer yet ({e}); it starts about 10 s after the VM boots — retry shortly"))?;
            return self.wrap(env, key, Endpoint { kind: "vm", ws, http: Some(url), auth: None, pid: None, owned: false, bridge: false });
        }
        if key == "lightpanda" {
            let l = launch::lightpanda_serve(&dir.join("lightpanda"), !cfg.private_allowed())?;
            return self.wrap(env, key, Endpoint { kind: "lightpanda", ws: l.ws, http: Some(l.http), auth: None, pid: Some(l.pid), owned: true, bridge: false });
        }
        if key == "sandbox" {
            return crate::sandbox::start(self, env);
        }
        if key == "extension" {
            let (ws, token) = crate::extension::relay(&env.cfg, &dir)?;
            return self.wrap(env, key, Endpoint { kind: "extension", ws, http: None, auth: Some(format!("Bearer {token}")), pid: None, owned: false, bridge: false });
        }
        if let Some(rest) = key.strip_prefix("cloud:") {
            let provider = rest.split(':').next().unwrap_or("");
            let s = cloud::create(provider, &*env.secrets, rest.split(':').nth(1).unwrap_or(""))?;
            let b = match self.wrap(env, key, Endpoint { kind: provider, ws: s.cdp_url.clone(), http: None, auth: None, pid: None, owned: false, bridge: provider == "browserbase" }) {
                Ok(b) => b,
                Err(e) => {
                    cloud::release(&s);
                    return Err(e);
                }
            };
            {
                let mut i = b.info.lock().unwrap();
                i.insert("cloud_session_id".into(), s.id.clone().into());
                i.insert("features".into(), s.features.clone());
                if let Some(x) = &s.expires_at {
                    i.insert("expires_at".into(), x.clone().into());
                }
            }
            *b.on_close.lock().unwrap() = Some(Box::new(move || {
                cloud::release(&s);
            }));
            return Ok(b);
        }
        let name = if key == "sidecar" { "sidecar".to_string() } else { key.strip_prefix("profile:").unwrap_or(key).to_string() };
        let p = if key == "sidecar" { ProfileConfig { driver: "managed".into(), ..Default::default() } } else { profile(cfg, &name)? };
        match p.driver.as_str() {
            "existing-session" => {
                let udd = if p.user_data_dir.is_empty() { launch::detect_real_browser()?.data_dir } else { PathBuf::from(&p.user_data_dir) };
                let l = launch::running_on(&udd).ok_or_else(|| format!("Existing-session attach for profile \"{name}\" could not connect to Chrome. Enable remote debugging in the browser inspect page (chrome://inspect/#remote-debugging), keep the browser open, approve the attach prompt, and retry. If you do not need your signed-in browser session, use the managed \"{}\" profile instead.", cfg.default_profile))?;
                self.wrap(env, key, Endpoint { kind: "existing-session", ws: l.ws, http: Some(l.http), auth: None, pid: Some(l.pid), owned: false, bridge: false })
            }
            "remote" => {
                let auth = basic_from_url(&p.cdp_url);
                let ws = cdp::resolve_ws(&strip_userinfo(&p.cdp_url), auth.as_deref(), Duration::from_secs(10))?;
                self.wrap(env, key, Endpoint { kind: "remote", ws, http: Some(strip_userinfo(&p.cdp_url)), auth, pid: None, owned: false, bridge: false })
            }
            "" | "managed" => {
                let desk = desktop_env(&env.home);
                let headless = p.headless.unwrap_or(cfg.headless);
                if !headless && !has_display(&desk) {
                    return Err(format!("profile \"{name}\" is headed but no DISPLAY or WAYLAND_DISPLAY is set (no_display_for_headed_profile); set browser.headless = true or start a screen with `seagent screen start`"));
                }
                let real = cfg.use_real_profile && name == cfg.default_profile && key != "sidecar";
                let (exe, udd, managed, note) = if real {
                    match launch::detect_real_browser().and_then(|rb| {
                        let udd = dir.join("real-profile").join(rb.name);
                        launch::snapshot_real_profile(&rb, &udd, &cfg.real_profile_pin)?;
                        Ok((rb.exe, udd))
                    }) {
                        Ok((e, u)) => (e, u, false, None),
                        Err(e) => {
                            let exe = launch::ensure_executable(cfg, if p.executable.is_empty() { &cfg.executable } else { &p.executable })?;
                            (exe, dir.join("profiles").join(&name), true, Some(format!("{e} Using a fresh browser without the user's logins for this session instead; tell the user if the task needs their accounts.")))
                        }
                    }
                } else {
                    let exe = launch::ensure_executable(cfg, if p.executable.is_empty() { &cfg.executable } else { &p.executable })?;
                    let udd = if p.user_data_dir.is_empty() { dir.join("profiles").join(&name) } else { PathBuf::from(&p.user_data_dir) };
                    (exe, udd, true, None)
                };
                let mut extra = cfg.extra_args.clone();
                if !p.color.is_empty() {
                    extra.push(format!("--app-name=seagent-{name}"));
                }
                let on_desktop = !headless && !desk.is_empty();
                let o = launch::LaunchOpts { exe: &exe, user_data_dir: &udd, headless, no_sandbox: cfg.no_sandbox(), extra_args: &extra, port: p.cdp_port, managed, env: desk };
                let l = launch::launch(&o, Duration::from_secs(60))?;
                let b = self.wrap(env, key, Endpoint { kind: if real { "real-profile" } else { "local" }, ws: l.ws, http: Some(l.http), auth: None, pid: Some(l.pid), owned: l.owned, bridge: false })?;
                {
                    let mut i = b.info.lock().unwrap();
                    i.insert("executable".into(), exe.display().to_string().into());
                    i.insert("user_data_dir".into(), udd.display().to_string().into());
                    i.insert("headless".into(), headless.into());
                    if on_desktop {
                        i.insert("bot_desktop".into(), true.into());
                    }
                    if real {
                        i.insert("used_real_profile".into(), true.into());
                    }
                    if let Some(n) = note {
                        i.insert("real_profile_unavailable".into(), n.into());
                    }
                }
                Ok(b)
            }
            other => Err(format!("profile \"{name}\": unknown driver `{other}` (managed, existing-session, remote)")),
        }
    }

    /// An app on the Bot Desktop that is Chromium or Electron underneath, started as a headed
    /// CDP target (`launch::launch_app`: loopback DevTools port, its own user-data-dir under
    /// `<home>/browser/apps/<name>`) and kept as browser `app:<name>`, marked `bot_desktop` and
    /// `desk_app`. The live view then streams its page in patch mode like the agent's own
    /// browser, under the same live-view token and Bot Desktop lease; viewer input goes through
    /// the lease like any other desktop input. Needs a running Bot Desktop (macOS: the login
    /// session, which is the host target there). Idle reaping skips it: it runs until stopped.
    pub fn launch_app(&self, env: &Env, name: &str, exe: &Path, args: &[String]) -> Result<Arc<Browser>, String> {
        if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err(format!("app name {name:?}: use letters, digits, '.', '_' or '-'"));
        }
        let key = format!("app:{name}");
        if let Some(b) = self.get(&key) {
            return Ok(b);
        }
        let desk = desktop_env(&env.home);
        if desk.is_empty() && !cfg!(target_os = "macos") {
            return Err("no Bot Desktop is running: start it with `seagent screen start`".into());
        }
        let _g = self.starting.lock().unwrap();
        let udd = env.dir().join("apps").join(name);
        util::private_dir(&env.dir()).map_err(|e| e.to_string())?;
        let kind = launch::app_kind(exe).unwrap_or("app");
        let l = launch::launch_app(exe, &udd, args, &desk, Duration::from_secs(60))?;
        let b = match self.wrap(env, &key, Endpoint { kind: "app", ws: l.ws, http: Some(l.http), auth: None, pid: Some(l.pid), owned: l.owned, bridge: false }) {
            Ok(b) => b,
            Err(e) => {
                util::kill_group(l.pid, Duration::from_secs(2));
                return Err(e);
            }
        };
        {
            let mut i = b.info.lock().unwrap();
            i.insert("executable".into(), exe.display().to_string().into());
            i.insert("user_data_dir".into(), udd.display().to_string().into());
            i.insert("headless".into(), false.into());
            i.insert("bot_desktop".into(), true.into());
            i.insert("desk_app".into(), kind.into());
        }
        self.browsers.lock().unwrap().insert(key, b.clone());
        Ok(b)
    }

    /// The seagent session's current tab in `b` (created on first use).
    pub fn tab(&self, env: &Env, sid: &str, b: &Browser) -> Result<String, String> {
        let mut s = self.session(sid);
        if s.key == b.key {
            if let Some(t) = &s.target {
                let alive = b.tabs(None).map(|ts| ts.iter().any(|x| x["targetId"] == t.as_str())).unwrap_or(false);
                if alive {
                    return Ok(t.clone());
                }
            }
        }
        s.key = b.key.clone();
        let claimed: Vec<String> = self.sessions.lock().unwrap().values().filter_map(|x| x.target.clone()).collect();
        let t = if env.cfg.isolate_sessions && b.kind != "existing-session" && b.kind != "extension" {
            let ctx = match &s.context {
                Some(c) => c.clone(),
                None => b.call("Target.createBrowserContext", json!({"disposeOnDetach": false}))?["browserContextId"].as_str().ok_or("no browserContextId")?.to_string(),
            };
            s.context = Some(ctx.clone());
            b.new_tab("about:blank", Some(&ctx))?
        } else {
            let free = b.tabs(None)?.into_iter().find(|t| t["url"] == "about:blank" && !claimed.iter().any(|c| t["targetId"] == c.as_str()));
            match free.and_then(|t| t["targetId"].as_str().map(str::to_string)) {
                Some(t) => t,
                None => b.new_tab("about:blank", None)?,
            }
        };
        b.attach(&t)?;
        if env.cfg.record_sessions {
            start_recording(env, b, &t, sid);
        }
        s.target = Some(t.clone());
        self.set_session(sid, s);
        Ok(t)
    }

    /// Point the session at a tab (OpenClaw focus / targetId routing).
    pub fn focus(&self, sid: &str, b: &Browser, target: &str) {
        let mut s = self.session(sid);
        s.key = b.key.clone();
        s.target = Some(target.into());
        self.set_session(sid, s);
    }

    pub fn stop(&self, key: &str) -> bool {
        let b = self.browsers.lock().unwrap().remove(key);
        self.sessions.lock().unwrap().retain(|_, s| s.key != key);
        match b {
            Some(b) => {
                finish_recordings(&b);
                b.close();
                true
            }
            None => false,
        }
    }

    /// End of an seagent session: drop its tab, and its cloud browser.
    pub fn release_session(&self, env: &Env, sid: &str) {
        let s = self.sessions.lock().unwrap().remove(sid);
        if let Some(s) = s {
            if s.key.starts_with("cloud:") {
                self.stop(&s.key);
            } else if let (Some(b), Some(t)) = (self.get(&s.key), s.target) {
                if s.context.is_some() {
                    let _ = b.call("Target.disposeBrowserContext", json!({"browserContextId": s.context}));
                }
                let _ = t;
            }
        }
        self.camofox.soft_close(&env.cfg, sid);
    }

    pub fn stop_all(&self) {
        let keys: Vec<String> = self.browsers.lock().unwrap().keys().cloned().collect();
        for k in keys {
            self.stop(&k);
        }
    }

    /// Close browsers idle past `inactivity_timeout` (and expired cloud sessions).
    pub fn reap(&self) {
        let idle = Duration::from_secs(self.idle_secs.load(Ordering::Relaxed).max(30));
        let stale: Vec<String> = self.browsers.lock().unwrap().iter().filter(|(k, b)| b.conn.is_closed() || (b.idle_for() > idle && !k.starts_with("app:"))).map(|(k, _)| k.clone()).collect();
        for k in stale {
            self.stop(&k);
        }
    }

    pub fn status(&self) -> Value {
        let v: Vec<Value> = self
            .browsers
            .lock()
            .unwrap()
            .values()
            .map(|b| {
                let mut o = json!({"key": b.key, "kind": b.kind, "running": !b.conn.is_closed(), "pid": b.pid, "cdpUrl": b.http.as_deref().map(cdp::redact_url), "idleSeconds": b.idle_for().as_secs()});
                for (k, v) in b.info.lock().unwrap().iter() {
                    o[k] = v.clone();
                }
                o
            })
            .collect();
        json!(v)
    }
}

fn strip_userinfo(u: &str) -> String {
    match u.split_once("://") {
        Some((s, rest)) => match rest.split_once('@') {
            Some((auth, host)) if !auth.contains('/') => format!("{s}://{host}"),
            _ => u.to_string(),
        },
        None => u.to_string(),
    }
}

fn basic_from_url(u: &str) -> Option<String> {
    let rest = u.split_once("://")?.1;
    let (auth, _) = rest.split_once('@')?;
    if auth.contains('/') {
        return None;
    }
    Some(format!("Basic {}", seagent_net::crypto::b64(seagent_net::urldecode(auth).as_bytes())))
}

pub(crate) fn start_recording(env: &Env, b: &Browser, target: &str, sid: &str) {
    let rec = env.dir().join("recordings");
    util::prune(&rec, "session_", Duration::from_secs(72 * 3600));
    let short: String = sid.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    let d = rec.join(format!("session_{}_{short}", util::now_ms() / 1000));
    if std::fs::create_dir_all(&d).is_err() {
        return;
    }
    if let Ok(psid) = b.attach(target) {
        // A console viewer may already run this page's screencast: share it (the recording
        // takes over the acks, so any frame the viewers were holding is released now).
        let watched = {
            let mut s = b.state.lock().unwrap();
            s.recording.insert(psid.clone(), (d, 0));
            s.live.get(&psid).map(|c| c.take_unacked())
        };
        match watched {
            Some(ids) => {
                for id in ids {
                    b.conn.send_nowait("Page.screencastFrameAck", json!({"sessionId": id}), Some(&psid));
                }
            }
            None => {
                let _ = b.session_call(target, &psid, "Page.startScreencast", json!({"format": "jpeg", "quality": 60, "everyNthFrame": 2}), Duration::from_secs(5));
            }
        }
    }
}

/// Encode recorded frames (`ffmpeg` → webm; without ffmpeg the JPEG frames stay).
pub fn finish_recordings(b: &Browser) {
    let (recs, watched) = {
        let mut s = b.state.lock().unwrap();
        let recs: Vec<(String, (PathBuf, u64))> = s.recording.drain().collect();
        let watched: Vec<String> = s.live.keys().cloned().collect();
        (recs, watched)
    };
    for (sid, (dir, n)) in recs {
        // A console viewer keeps the screencast (its acks pace it again from the next frame).
        if !watched.contains(&sid) {
            let _ = b.conn.call_with("Page.stopScreencast", json!({}), Some(&sid), Duration::from_secs(3), &|| None);
        }
        if n == 0 {
            let _ = std::fs::remove_dir(&dir);
            continue;
        }
        if util::which("ffmpeg").is_some() {
            let out = dir.with_extension("webm");
            let pattern = dir.join("frame_%06d.jpg");
            if util::run(&["ffmpeg", "-y", "-loglevel", "error", "-framerate", "5", "-i", &pattern.to_string_lossy(), "-c:v", "libvpx-vp9", "-b:v", "1M", &out.to_string_lossy()], Duration::from_secs(300), None, &[]).is_ok_and(|(c, _, _)| c == 0) {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn env(cfg: BrowserConfig) -> Env {
        Env { cfg, home: seagent_core::tmp::scratch_path(format!("seagent-mgr-{}-{}", std::process::id(), seagent_net::crypto::random_token(4))), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    #[test]
    fn keys_profiles_and_urls() {
        let mut cfg = BrowserConfig { backend: "browserbase".into(), ..Default::default() };
        let m = Manager::default();
        let e = env(cfg.clone());
        assert_eq!(m.key_for(&e, None, "s1", Some("https://example.com")), "cloud:browserbase:s1");
        assert_eq!(m.key_for(&e, None, "s1", Some("http://127.0.0.1:3000/")), "sidecar");
        assert_eq!(m.key_for(&e, Some("work"), "s1", None), "profile:work");
        cfg.backend = "local".into();
        assert_eq!(m.key_for(&env(cfg.clone()), None, "s1", None), "profile:seagent");
        let names: Vec<String> = profiles(&cfg).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["seagent", "user"]);
        assert!(profile(&cfg, "nope").unwrap_err().contains("unknown browser profile"));
        assert_eq!(strip_userinfo("http://seagent:tok@127.0.0.1:9/x"), "http://127.0.0.1:9/x");
        assert_eq!(basic_from_url("http://seagent:tok@127.0.0.1:9").unwrap(), format!("Basic {}", seagent_net::crypto::b64(b"seagent:tok")));
        assert!(basic_from_url("http://127.0.0.1:9").is_none());
    }

    #[test]
    fn attaches_to_a_cdp_endpoint_and_tracks_session_tabs() {
        let f = crate::cdp::fake::start(Arc::new(|m, p, _| match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "P1", "type": "page", "url": "about:blank", "title": ""}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": format!("S{}", p["targetId"].as_str().unwrap())}), vec![]),
            "Target.createTarget" => (json!({"targetId": "P2"}), vec![]),
            _ => (json!({}), vec![]),
        }));
        let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), ..Default::default() };
        let e = env(cfg);
        let m = Manager::default();
        let key = m.key_for(&e, None, "s1", None);
        let b = m.browser(&e, &key).unwrap();
        assert_eq!(b.kind, "cdp");
        assert_eq!(m.tab(&e, "s1", &b).unwrap(), "P1");
        assert_eq!(m.tab(&e, "s1", &b).unwrap(), "P1", "sticky");
        assert_eq!(m.tab(&e, "s2", &b).unwrap(), "P2", "the blank tab is taken");
        assert!(m.status()[0]["cdpUrl"].as_str().unwrap().starts_with("http://127.0.0.1:"));
        assert!(m.stop("cdp") && m.get("cdp").is_none());
    }
}
