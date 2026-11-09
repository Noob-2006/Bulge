//! A small Chrome DevTools Protocol client for meeting tabs: list/open/close targets over
//! the DevTools HTTP endpoints, `Runtime.evaluate` (await + by value) on a page, and
//! `Browser.grantPermissions` for the meeting origin. Launches a dedicated Chromium profile
//! (`--use-fake-ui-for-media-stream` auto-accepts the mic/camera prompt) when nothing listens.

use crate::http::Http;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Tab {
    pub id: String,
    pub url: String,
    pub title: String,
    pub ws: String,
}

pub struct Cdp {
    pub base: String,
    http: Http,
}

fn tab(v: &Value) -> Option<Tab> {
    Some(Tab {
        id: v["id"].as_str()?.into(),
        url: v["url"].as_str().unwrap_or("").into(),
        title: v["title"].as_str().unwrap_or("").into(),
        ws: v["webSocketDebuggerUrl"].as_str().unwrap_or("").into(),
    })
}

impl Cdp {
    pub fn new(base: &str) -> Cdp {
        Cdp {
            base: base.trim_end_matches('/').to_string(),
            http: Http::new(Duration::from_secs(10)),
        }
    }

    /// `/json/version`, validated: any HTTP server answers `/json/version` with *something*
    /// (`{}`, an HTML error page, …), so a parsed body alone does not mean a browser is there —
    /// only a `webSocketDebuggerUrl` (plus the `Browser` banner) does.
    pub fn version(&self) -> Result<Value, String> {
        let v = self
            .http
            .get_json(&format!("{}/json/version", self.base), &[])?;
        let ws = v["webSocketDebuggerUrl"].as_str().unwrap_or("");
        let browser = v["Browser"].as_str().unwrap_or("");
        if !ws.starts_with("ws") || browser.is_empty() {
            return Err(format!(
                "{} is not a Chrome DevTools endpoint (no /json/version banner)",
                self.base
            ));
        }
        Ok(v)
    }

    /// The page socket of target `id` — Chrome's layout is fixed, so it can be derived even
    /// when an answer omitted `webSocketDebuggerUrl`.
    fn page_ws(&self, id: &str) -> String {
        let host = self
            .base
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(&self.base)
            .trim_end_matches('/');
        let scheme = if self.base.starts_with("https://") {
            "wss"
        } else {
            "ws"
        };
        format!("{scheme}://{host}/devtools/page/{id}")
    }

    /// Fill in what an answer left out: the page socket from `/json/list` (then from the
    /// derived URL) and the URL when the browser reports an empty one.
    fn complete(&self, mut t: Tab, want: &str) -> Tab {
        if t.ws.is_empty() {
            if let Some(x) = self.tabs().ok().unwrap_or_default().into_iter().find(|x| x.id == t.id) {
                t.ws = x.ws;
            }
        }
        if t.ws.is_empty() {
            t.ws = self.page_ws(&t.id);
        }
        if t.url.is_empty() {
            t.url = want.into();
        }
        t
    }

    /// `Target.createTarget` on the browser socket: the version-independent way to get a tab.
    fn create_target(&self, url: &str) -> Result<Tab, String> {
        let v = self.version()?;
        let ws = v["webSocketDebuggerUrl"]
            .as_str()
            .ok_or("no browser DevTools socket")?;
        let r = Self::command(
            ws,
            "Target.createTarget",
            json!({"url": url}),
            Duration::from_secs(10),
        )?;
        let id = r["targetId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Target.createTarget returned no targetId")?;
        let known = self
            .tabs()
            .ok()
            .unwrap_or_default()
            .into_iter()
            .find(|t| t.id == id)
            .unwrap_or(Tab {
                id: id.into(),
                url: String::new(),
                title: String::new(),
                ws: String::new(),
            });
        Ok(self.complete(known, url))
    }

    pub fn tabs(&self) -> Result<Vec<Tab>, String> {
        let v = self
            .http
            .get_json(&format!("{}/json/list", self.base), &[])?;
        Ok(v.as_array()
            .into_iter()
            .flatten()
            .filter(|t| t["type"] == "page")
            .filter_map(tab)
            .collect())
    }

    /// Open `url` in a new tab. Chrome ≥ 111 only accepts `PUT /json/new?<url>` (older builds
    /// only `GET`), and the HTTP endpoint is best-effort by nature, so the plain CDP way
    /// (`Target.createTarget` over the browser socket) is the fallback — then the tab is
    /// completed from `/json/list` when the answer is thin.
    pub fn open(&self, url: &str) -> Result<Tab, String> {
        let u = format!("{}/json/new?{}", self.base, seagent_net::urlencode(url));
        let mut errs: Vec<String> = Vec::new();
        for attempt in 0..2u64 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(200 * attempt));
            }
            for (method, body) in [
                ("PUT", Some(("text/plain", b"".as_slice()))),
                ("GET", None),
            ] {
                match self.http.send(method, &u, &[], body) {
                    Ok(r) if r.ok() => match tab(&r.json().unwrap_or(Value::Null)) {
                        Some(t) => return Ok(self.complete(t, url)),
                        None => errs.push(format!(
                            "{method} /json/new answered without a tab ({})",
                            crate::http::excerpt(r.text().trim(), 120)
                        )),
                    },
                    Ok(r) => errs.push(format!(
                        "{method} /json/new: HTTP {} ({})",
                        r.status,
                        crate::http::excerpt(r.text().trim(), 120)
                    )),
                    Err(e) => errs.push(format!("{method} /json/new: {e}")),
                }
            }
            match self.create_target(url) {
                Ok(t) => return Ok(t),
                Err(e) => errs.push(format!("Target.createTarget: {e}")),
            }
        }
        errs.dedup();
        Err(format!(
            "could not open a tab at {url}: {}",
            errs.join("; ")
        ))
    }

    pub fn close(&self, id: &str) {
        let _ = self
            .http
            .send("GET", &format!("{}/json/close/{id}", self.base), &[], None);
    }

    pub fn activate(&self, id: &str) {
        let _ = self.http.send(
            "GET",
            &format!("{}/json/activate/{id}", self.base),
            &[],
            None,
        );
    }

    /// One CDP command on `ws` (page or browser target) → its `result`.
    pub fn command(
        ws_url: &str,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let (mut ws, _) = seagent_net::ws::WebSocket::connect(ws_url, &[], Duration::from_secs(10))
            .map_err(|e| format!("DevTools connect: {e}"))?;
        ws.set_max_message(64 << 20);
        let _ = ws.set_read_timeout(Some(Duration::from_millis(250)));
        ws.send_text(&json!({"id": 1, "method": method, "params": params}).to_string())
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match ws.recv() {
                Ok(Some(seagent_net::ws::Message::Text(t))) => {
                    let v: Value = serde_json::from_str(&t).unwrap_or_default();
                    if v["id"] != 1 {
                        continue;
                    }
                    if let Some(e) = v.get("error") {
                        return Err(format!(
                            "{method}: {}",
                            e["message"].as_str().unwrap_or("error")
                        ));
                    }
                    return Ok(v["result"].clone());
                }
                Ok(Some(seagent_net::ws::Message::Close(_))) => {
                    return Err("DevTools closed the connection".into())
                }
                Ok(_) => {}
                Err(e) => return Err(format!("DevTools: {e}")),
            }
        }
        Err(format!("{method} timed out after {}s", timeout.as_secs()))
    }

    /// Evaluate an async-arrow `script` in the tab; returns its JSON value.
    pub fn eval(&self, t: &Tab, script: &str, timeout: Duration) -> Result<Value, String> {
        let r = Self::command(
            &t.ws,
            "Runtime.evaluate",
            json!({"expression": format!("({script})()"), "awaitPromise": true, "returnByValue": true, "userGesture": true}),
            timeout,
        )?;
        if let Some(ex) = r.get("exceptionDetails") {
            return Err(format!(
                "page script failed: {}",
                ex["exception"]["description"]
                    .as_str()
                    .or(ex["text"].as_str())
                    .unwrap_or("exception")
            ));
        }
        Ok(r["result"]["value"].clone())
    }

    /// Grant microphone/camera (and notifications/clipboard) to `origin`.
    pub fn grant(&self, origin: &str, permissions: &[&str]) -> Result<(), String> {
        let v = self.version()?;
        let ws = v["webSocketDebuggerUrl"]
            .as_str()
            .ok_or("no browser DevTools socket")?;
        Self::command(
            ws,
            "Browser.grantPermissions",
            json!({"origin": origin, "permissions": permissions}),
            Duration::from_secs(5),
        )
        .map(|_| ())
    }
}

/// A Chromium-family executable on this host.
pub fn find_chrome(explicit: &str) -> Option<std::path::PathBuf> {
    if !explicit.is_empty() {
        return Some(explicit.into()).filter(|p: &std::path::PathBuf| p.exists());
    }
    let found = crate::proc::which_any(&[
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
    ]);
    #[cfg(any(windows, target_os = "macos"))]
    let found = found.or_else(installed_chrome);
    found
}

/// Windows / macOS install their browsers outside `PATH`: Chrome, Edge (always present on
/// Windows 10+), Brave and Chromium in their standard locations.
#[cfg(any(windows, target_os = "macos"))]
fn installed_chrome() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    #[cfg(windows)]
    let candidates: Vec<PathBuf> = {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let mut v = vec![];
        for base in [env("ProgramFiles"), env("ProgramFiles(x86)"), env("LOCALAPPDATA")].into_iter().flatten() {
            v.push(base.join("Google\\Chrome\\Application\\chrome.exe"));
            v.push(base.join("Microsoft\\Edge\\Application\\msedge.exe"));
            v.push(base.join("BraveSoftware\\Brave-Browser\\Application\\brave.exe"));
            v.push(base.join("Chromium\\Application\\chrome.exe"));
        }
        v
    };
    #[cfg(target_os = "macos")]
    let candidates: Vec<PathBuf> = ["Google Chrome.app/Contents/MacOS/Google Chrome", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "Brave Browser.app/Contents/MacOS/Brave Browser", "Chromium.app/Contents/MacOS/Chromium"].iter().map(|a| PathBuf::from("/Applications").join(a)).collect();
    candidates.into_iter().find(|p| p.is_file())
}

/// Browsers [`launch`] started, by DevTools port → process-group id (tests stop exactly theirs).
static LAUNCHED: std::sync::Mutex<std::collections::BTreeMap<u16, i32>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// The process group of the meeting browser this process launched on `port`, if any.
pub fn launched_pgid(port: u16) -> Option<i32> {
    LAUNCHED.lock().unwrap_or_else(|e| e.into_inner()).get(&port).copied()
}

/// Start a meeting Chromium on `port` with a persistent profile in `profile_dir`.
pub fn launch(exe: &Path, port: u16, profile_dir: &Path, headless: bool) -> Result<String, String> {
    std::fs::create_dir_all(profile_dir).map_err(|e| e.to_string())?;
    let base = format!("http://127.0.0.1:{port}");
    // Never adopt (or later close) somebody else's browser: the caller reuses a running
    // meeting browser before calling us, so an endpoint here is a port clash, not our browser.
    if Cdp::new(&base).version().is_ok() {
        return Err(format!(
            "a DevTools browser is already listening on {base}; refusing to start a second one"
        ));
    }
    let mut args = vec![
        format!("--remote-debugging-port={port}"),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--use-fake-ui-for-media-stream".into(),
        "--autoplay-policy=no-user-gesture-required".into(),
        "--disable-features=Translate".into(),
        "--disable-dev-shm-usage".into(),
        "--lang=en-US".into(),
    ];
    if headless {
        args.push("--headless=new".into());
        args.push("--disable-gpu".into());
    }
    // Chrome refuses to sandbox as root on unix; an elevated Windows token is no such case.
    if cfg!(unix) && seagent_core::platform::sysinfo::is_root() {
        args.push("--no-sandbox".into());
    }
    // Our own log: if the browser refuses to start (broken snap, taken port, missing sandbox)
    // the reason is in here instead of /dev/null.
    let log_path = profile_dir.join("browser.log");
    let log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    // Chrome drops its own scratch (`com.google.Chrome.*`, fetcher and crash files) into $TMPDIR;
    // keep it inside the profile so it goes away with the profile instead of the shared dir.
    let chrome_tmp = profile_dir.join("tmp");
    std::fs::create_dir_all(&chrome_tmp).map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.env("TMPDIR", &chrome_tmp);
    cmd.args(&args)
        .arg("about:blank")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log));
    // Own process group, and tied to seagent: the meeting browser outlives a call, never seagent
    // itself (new-001: interrupted test runs left headless meeting browsers for days).
    let mut child = seagent_core::proc::spawn_tied(cmd, false)
        .map_err(|e| format!("could not start {}: {e}", exe.display()))?;
    let c = Cdp::new(&base);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Liveness first: a browser that died (taken port, sandbox refusal) must never be
        // "confirmed" by whatever else answers on that port.
        if let Ok(Some(st)) = child.try_wait() {
            return Err(format!(
                "{} exited ({st}) before DevTools came up{}",
                exe.display(),
                log_tail(&log_path)
            ));
        }
        // Our browser prints the address it bound. Anything but 127.0.0.1:`port` means the
        // IPv4 port was already taken (Chrome silently falls back to another address) and
        // `base` therefore belongs to a process we did not start.
        if let Some((host, p)) = listening_addr(&log_path) {
            if p != port || !matches!(host.as_str(), "127.0.0.1" | "localhost") {
                stop(&mut child);
                return Err(format!(
                    "the meeting browser bound DevTools on {host}:{p}, not 127.0.0.1:{port} — that port is taken by another process{}",
                    log_tail(&log_path)
                ));
            }
        }
        if c.version().is_ok() {
            // Ours: keep it running (a meeting browser outlives the call), reap it when it exits.
            LAUNCHED.lock().unwrap_or_else(|e| e.into_inner()).insert(port, child.id() as i32);
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(base);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    stop(&mut child);
    Err(format!(
        "the meeting browser did not open DevTools on {base} within 30s{}",
        log_tail(&log_path)
    ))
}

/// Terminate the browser *we* spawned and nothing else: `process_group(0)` made it the leader
/// of its own group, so `-pid` reaches exactly its renderers/zygotes. SIGTERM first so a
/// persistent profile is closed cleanly, SIGKILL only if it hangs.
#[cfg(unix)]
fn stop(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    let signal = |s: i32| {
        if pid > 0 {
            unsafe { libc::kill(-pid, s) };
        }
    };
    signal(libc::SIGTERM);
    for _ in 0..30 {
        match child.try_wait() {
            Ok(Some(_)) => return,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    signal(libc::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
}

/// Windows: the browser's Job Object (from `spawn_tied`) is the group — CTRL_BREAK, a 3 s
/// grace for the profile to close, then the whole tree is terminated.
#[cfg(not(unix))]
fn stop(child: &mut std::process::Child) {
    seagent_core::platform::proc::kill_group(child.id() as i32, Duration::from_secs(3));
    let _ = child.kill();
    let _ = child.wait();
}

/// The address our browser's log says it bound (`DevTools listening on ws://127.0.0.1:9333/…`).
fn listening_addr(log: &Path) -> Option<(String, u16)> {
    let s = std::fs::read_to_string(log).ok()?;
    let line = s.lines().find(|l| l.contains("DevTools listening on ws://"))?;
    let hostport = line.split("ws://").nth(1)?.split('/').next()?;
    let (host, port) = hostport.rsplit_once(':')?;
    Some((host.trim_matches(['[', ']']).to_string(), port.parse().ok()?))
}

/// The last few log lines, for an error message that says *why* the browser did not start.
fn log_tail(log: &Path) -> String {
    let s = match std::fs::read_to_string(log) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let tail: Vec<&str> = s
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if tail.is_empty() {
        String::new()
    } else {
        format!(": {}", crate::http::excerpt(&tail.join(" | "), 600))
    }
}
