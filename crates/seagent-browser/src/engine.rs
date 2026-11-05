//! One controlled browser: its CDP connection plus the supervisor state built from
//! events (Hermes `browser_supervisor*.py`: dialogs, frames; OpenClaw page state:
//! console / errors / requests / downloads / file chooser, tab handles). MIT ports.

use crate::cdp::Conn;
use crate::snapshot::Ref;
use crate::util::{self, now_ms, now_s};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const CONSOLE_MAX: usize = 500;
pub const ERRORS_MAX: usize = 200;
pub const REQUESTS_MAX: usize = 500;
pub const RECENT_DIALOGS_MAX: usize = 20;
pub const FRAME_TREE_MAX: usize = 30;
pub const BLOCKED_BY_DIALOG: &str = "Browser action blocked by a modal dialog.";
/// Hermes dialog bridge: XHR to a magic host intercepted by Fetch (for cloud browsers
/// that auto-dismiss native dialogs server-side).
pub const BRIDGE_HOST: &str = "seagent-dialog-bridge.invalid";
pub const BRIDGE_SCRIPT: &str = r#"(() => {
  if (window.__arkDialogBridgeInstalled) return;
  window.__arkDialogBridgeInstalled = true;
  const ENDPOINT = "http://seagent-dialog-bridge.invalid/";
  function ask(kind, message, defaultPrompt) {
    try {
      const xhr = new XMLHttpRequest();
      const params = new URLSearchParams({kind: String(kind || ""), message: String(message == null ? "" : message), default_prompt: String(defaultPrompt == null ? "" : defaultPrompt)});
      xhr.open("GET", ENDPOINT + "?" + params.toString(), false);
      xhr.send(null);
      if (xhr.status !== 200) return null;
      let parsed; try { parsed = JSON.parse(xhr.responseText || ""); } catch (e) { return null; }
      if (kind === "alert") return undefined;
      if (kind === "confirm") return Boolean(parsed && parsed.accept);
      if (kind === "prompt") { if (!parsed || !parsed.accept) return null; return parsed.prompt_text == null ? "" : String(parsed.prompt_text); }
      return null;
    } catch (e) { return null; }
  }
  window.alert = function(message) { ask("alert", message, ""); };
  window.confirm = function(message) { const r = ask("confirm", message, ""); return r === null ? false : Boolean(r); };
  window.prompt = function(message, def) { const r = ask("prompt", message, def == null ? "" : def); return r === null ? null : String(r); };
})();"#;

#[derive(Debug, Clone)]
pub struct Dialog {
    pub id: String,
    pub kind: String,
    pub message: String,
    pub default_prompt: String,
    pub opened_at: f64,
    pub session: String,
    pub frame_id: Option<String>,
    pub bridge_request: Option<String>,
}

impl Dialog {
    pub fn to_json(&self) -> Value {
        json!({"id": self.id, "type": self.kind, "message": crate::policy::redact(&self.message), "default_prompt": crate::policy::redact(&self.default_prompt), "opened_at": self.opened_at, "frame_id": self.frame_id})
    }
}

#[derive(Debug, Clone, Default)]
pub struct Frame {
    pub id: String,
    pub parent: Option<String>,
    pub url: String,
    pub name: String,
    pub session: Option<String>,
    pub oopif: bool,
}

#[derive(Default)]
pub struct Page {
    pub session: Option<String>,
    pub url: String,
    pub title: String,
    pub console: VecDeque<Value>,
    pub errors: VecDeque<Value>,
    pub requests: VecDeque<Value>,
    pub req_index: HashMap<String, String>,
    pub req_seq: u64,
    pub dialogs: Vec<Dialog>,
    pub recent_dialogs: VecDeque<Value>,
    pub dialog_seq: u64,
    pub armed_dialog: Option<(bool, Option<String>, Instant)>,
    pub nav_seq: u64,
    pub load_seq: u64,
    pub inflight: i64,
    pub last_net: Option<Instant>,
    pub network_idle: bool,
    pub frames: HashMap<String, Frame>,
    pub main_frame: String,
    pub chooser: Option<(i64, bool, u64)>,
    pub chooser_seq: u64,
    pub armed_upload: Option<Vec<String>>,
    pub refs: HashMap<String, Ref>,
    pub prev_keys: Option<HashSet<String>>,
    pub context: Option<String>,
    pub closed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Download {
    pub guid: String,
    pub url: String,
    pub suggested: String,
    pub state: String,
    pub target: String,
    pub begun: u64,
}

#[derive(Default)]
pub struct State {
    pub pages: HashMap<String, Page>,
    /// CDP session → (page target, frame target when it is an OOPIF session).
    pub sessions: HashMap<String, (String, Option<String>)>,
    pub tab_seq: u64,
    pub tab_ids: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    pub downloads: HashMap<String, Download>,
    pub dialog_policy: String,
    pub dialog_timeout: f64,
    /// Screencast recordings: page session → (frame dir, frames written).
    pub recording: HashMap<String, (PathBuf, u64)>,
}

pub struct Browser {
    pub key: String,
    pub kind: String,
    pub conn: Conn,
    pub http: Option<String>,
    pub auth: Option<String>,
    pub pid: Option<i32>,
    pub owned: bool,
    pub state: Arc<Mutex<State>>,
    pub dir: PathBuf,
    pub last_used: Mutex<Instant>,
    pub timeout: Duration,
    /// Extra facts for status (cloud session id, noVNC url, container…).
    pub info: Mutex<serde_json::Map<String, Value>>,
    pub bridge: bool,
    pub on_close: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

fn push_ring(q: &mut VecDeque<Value>, v: Value, max: usize) {
    q.push_back(v);
    while q.len() > max {
        q.pop_front();
    }
}

fn console_text(args: &Value) -> String {
    args.as_array()
        .map(|a| {
            a.iter()
                .map(|x| match &x["value"] {
                    Value::String(s) => s.clone(),
                    Value::Null => x["description"].as_str().or(x["unserializableValue"].as_str()).unwrap_or(x["type"].as_str().unwrap_or("")).to_string(),
                    v => v.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (d, s) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
    let z = d + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y + i64::from(m <= 2), m, day, s / 3600, s % 3600 / 60, s % 60, ms % 1000)
}

/// Supervisor: fold one CDP event into the state (runs on the I/O thread).
pub fn handle_event(st: &Mutex<State>, conn: &Conn, method: &str, p: &Value, sid: Option<&str>) {
    let mut s = st.lock().unwrap();
    let page_of = |s: &State, sid: Option<&str>| sid.and_then(|x| s.sessions.get(x)).map(|(t, _)| t.clone());
    match method {
        "Target.attachedToTarget" => {
            let child = p["sessionId"].as_str().unwrap_or("").to_string();
            let info = &p["targetInfo"];
            let ty = info["type"].as_str().unwrap_or("");
            if let Some(parent) = page_of(&s, sid) {
                if ty == "iframe" {
                    let fid = info["targetId"].as_str().unwrap_or("").to_string();
                    s.sessions.insert(child.clone(), (parent.clone(), Some(fid.clone())));
                    if let Some(pg) = s.pages.get_mut(&parent) {
                        let f = pg.frames.entry(fid.clone()).or_insert_with(|| Frame { id: fid.clone(), ..Default::default() });
                        f.session = Some(child.clone());
                        f.oopif = true;
                        f.url = info["url"].as_str().unwrap_or("").to_string();
                    }
                    for m in ["Runtime.enable", "Page.enable", "DOM.enable"] {
                        conn.send_nowait(m, json!({}), Some(&child));
                    }
                }
                conn.send_nowait("Runtime.runIfWaitingForDebugger", json!({}), Some(&child));
            }
        }
        "Target.detachedFromTarget" => {
            if let Some(x) = p["sessionId"].as_str() {
                if let Some((t, None)) = s.sessions.remove(x) {
                    if let Some(pg) = s.pages.get_mut(&t) {
                        pg.session = None;
                    }
                }
            }
        }
        "Target.targetDestroyed" | "Target.targetCrashed" => {
            if let Some(t) = p["targetId"].as_str() {
                if let Some(pg) = s.pages.get_mut(t) {
                    pg.closed = true;
                }
            }
        }
        "Target.targetInfoChanged" => {
            let i = &p["targetInfo"];
            if let (Some(t), true) = (i["targetId"].as_str(), i["type"] == "page") {
                if let Some(pg) = s.pages.get_mut(t) {
                    pg.url = i["url"].as_str().unwrap_or("").into();
                    pg.title = i["title"].as_str().unwrap_or("").into();
                }
            }
        }
        "Browser.downloadWillBegin" => {
            let g = p["guid"].as_str().unwrap_or("").to_string();
            s.downloads.insert(g.clone(), Download { guid: g, url: p["url"].as_str().unwrap_or("").into(), suggested: p["suggestedFilename"].as_str().unwrap_or("").into(), state: "inProgress".into(), target: p["frameId"].as_str().unwrap_or("").into(), begun: now_ms() });
        }
        "Browser.downloadProgress" => {
            if let Some(d) = p["guid"].as_str().and_then(|g| s.downloads.get_mut(g)) {
                d.state = p["state"].as_str().unwrap_or("").into();
            }
        }
        "Page.screencastFrame" => {
            if let Some((dir, n)) = sid.and_then(|x| s.recording.get_mut(x)) {
                if let Some(b) = p["data"].as_str().and_then(seagent_net::crypto::b64_decode) {
                    *n += 1;
                    let _ = std::fs::write(dir.join(format!("frame_{:06}.jpg", n)), b);
                }
            }
            conn.send_nowait("Page.screencastFrameAck", json!({"sessionId": p["sessionId"]}), sid);
            return;
        }
        _ => {}
    }
    let Some(target) = page_of(&s, sid) else { return };
    let frame_session = sid.map(str::to_string).unwrap_or_default();
    let policy = s.dialog_policy.clone();
    let Some(pg) = s.pages.get_mut(&target) else { return };
    match method {
        "Page.frameNavigated" => {
            let f = &p["frame"];
            let id = f["id"].as_str().unwrap_or("").to_string();
            let parent = f["parentId"].as_str().map(str::to_string);
            if parent.is_none() && s_is_page_session(pg, sid) {
                pg.nav_seq += 1;
                pg.main_frame = id.clone();
                pg.url = f["url"].as_str().unwrap_or("").to_string() + f["urlFragment"].as_str().unwrap_or("");
                pg.network_idle = false;
                pg.frames.retain(|_, fr| fr.oopif);
            }
            let e = pg.frames.entry(id.clone()).or_insert_with(|| Frame { id: id.clone(), ..Default::default() });
            e.url = f["url"].as_str().unwrap_or("").into();
            e.name = f["name"].as_str().unwrap_or("").into();
            e.parent = parent;
        }
        "Page.navigatedWithinDocument" => {
            if p["frameId"].as_str() == Some(pg.main_frame.as_str()) {
                pg.url = p["url"].as_str().unwrap_or("").into();
            }
        }
        "Page.frameAttached" => {
            let id = p["frameId"].as_str().unwrap_or("").to_string();
            pg.frames.entry(id.clone()).or_insert_with(|| Frame { id, parent: p["parentFrameId"].as_str().map(str::to_string), ..Default::default() });
        }
        "Page.frameDetached" => {
            if let Some(id) = p["frameId"].as_str() {
                pg.frames.remove(id);
            }
        }
        "Page.loadEventFired" => pg.load_seq += 1,
        "Page.lifecycleEvent" => {
            if p["name"] == "networkIdle" && p["frameId"].as_str() == Some(pg.main_frame.as_str()) {
                pg.network_idle = true;
            }
        }
        "Page.javascriptDialogOpening" => {
            admit_dialog(pg, conn, &policy, p["type"].as_str().unwrap_or("alert"), p["message"].as_str().unwrap_or(""), p["defaultPrompt"].as_str().unwrap_or(""), &frame_session, p["frameId"].as_str(), None);
        }
        "Page.javascriptDialogClosed" => {
            if let Some(i) = pg.dialogs.iter().position(|d| d.session == frame_session && d.bridge_request.is_none()) {
                let d = pg.dialogs.remove(i);
                archive(pg, &d, "remote");
            }
        }
        "Fetch.requestPaused" => {
            let url = p["request"]["url"].as_str().unwrap_or("");
            let rid = p["requestId"].as_str().unwrap_or("").to_string();
            if !url.contains(BRIDGE_HOST) {
                conn.send_nowait("Fetch.continueRequest", json!({"requestId": rid}), sid);
                return;
            }
            let q: HashMap<String, String> = seagent_net::parse_query(url.split_once('?').map(|x| x.1).unwrap_or("")).into_iter().collect();
            admit_dialog(pg, conn, &policy, q.get("kind").map(String::as_str).unwrap_or("alert"), q.get("message").map(String::as_str).unwrap_or(""), q.get("default_prompt").map(String::as_str).unwrap_or(""), &frame_session, p["frameId"].as_str(), Some(rid));
        }
        "Page.fileChooserOpened" => {
            let backend = p["backendNodeId"].as_i64().unwrap_or(0);
            pg.chooser_seq += 1;
            if let Some(files) = pg.armed_upload.take() {
                conn.send_nowait("DOM.setFileInputFiles", json!({"files": files, "backendNodeId": backend}), sid);
                pg.chooser = None;
            } else {
                pg.chooser = Some((backend, p["mode"] == "selectMultiple", pg.chooser_seq));
            }
        }
        "Runtime.consoleAPICalled" => {
            let frame = &p["stackTrace"]["callFrames"][0];
            let text = crate::util::cut(&console_text(&p["args"]), 2048).to_string();
            push_ring(&mut pg.console, json!({"type": p["type"].as_str().unwrap_or("log"), "text": text, "timestamp": iso(p["timestamp"].as_f64().map(|t| t as u64).unwrap_or_else(now_ms)), "location": {"url": frame["url"], "lineNumber": frame["lineNumber"], "columnNumber": frame["columnNumber"]}}), CONSOLE_MAX);
        }
        "Log.entryAdded" => {
            let e = &p["entry"];
            let t = match e["level"].as_str() {
                Some("warning") => "warning",
                Some("error") => "error",
                Some("verbose") => "debug",
                _ => "info",
            };
            push_ring(&mut pg.console, json!({"type": t, "text": crate::util::cut(e["text"].as_str().unwrap_or(""), 2048), "timestamp": iso(now_ms()), "location": {"url": e["url"]}}), CONSOLE_MAX);
        }
        "Runtime.exceptionThrown" => {
            let d = &p["exceptionDetails"];
            let ex = &d["exception"];
            let desc = ex["description"].as_str().unwrap_or(d["text"].as_str().unwrap_or("Uncaught exception"));
            let (first, stack) = desc.split_once('\n').map(|(a, b)| (a.to_string(), Some(b.to_string()))).unwrap_or((desc.to_string(), None));
            push_ring(&mut pg.errors, json!({"message": crate::util::cut(&first, 2048), "name": ex["className"], "stack": stack.map(|s| crate::util::cut(&s, 4096).to_string()), "timestamp": iso(now_ms())}), ERRORS_MAX);
        }
        "Network.requestWillBeSent" => {
            pg.req_seq += 1;
            let id = format!("r{}", pg.req_seq);
            let rid = p["requestId"].as_str().unwrap_or("").to_string();
            pg.req_index.insert(rid.clone(), id.clone());
            pg.inflight += 1;
            pg.last_net = Some(Instant::now());
            push_ring(&mut pg.requests, json!({"id": id, "requestId": rid, "timestamp": iso(now_ms()), "method": p["request"]["method"], "url": crate::util::cut(p["request"]["url"].as_str().unwrap_or(""), 2048), "resourceType": p["type"]}), REQUESTS_MAX);
            if pg.req_index.len() > REQUESTS_MAX * 2 {
                let live: HashSet<String> = pg.requests.iter().filter_map(|r| r["requestId"].as_str().map(str::to_string)).collect();
                pg.req_index.retain(|k, _| live.contains(k));
            }
        }
        "Network.responseReceived" => {
            let rid = p["requestId"].as_str().unwrap_or("");
            let st = p["response"]["status"].as_i64().unwrap_or(0);
            if let Some(r) = pg.requests.iter_mut().rev().find(|r| r["requestId"] == rid) {
                r["status"] = st.into();
                r["ok"] = (200..400).contains(&st).into();
            }
        }
        "Network.loadingFinished" | "Network.loadingFailed" => {
            pg.inflight = (pg.inflight - 1).max(0);
            pg.last_net = Some(Instant::now());
            if method == "Network.loadingFailed" {
                let rid = p["requestId"].as_str().unwrap_or("");
                if let Some(r) = pg.requests.iter_mut().rev().find(|r| r["requestId"] == rid) {
                    r["failureText"] = p["errorText"].clone();
                    r["ok"] = false.into();
                }
            }
        }
        _ => {}
    }
}

fn s_is_page_session(pg: &Page, sid: Option<&str>) -> bool {
    pg.session.as_deref() == sid
}

#[allow(clippy::too_many_arguments)]
fn admit_dialog(pg: &mut Page, conn: &Conn, policy: &str, kind: &str, message: &str, default_prompt: &str, session: &str, frame: Option<&str>, bridge: Option<String>) {
    pg.dialog_seq += 1;
    let d = Dialog { id: format!("d{}", pg.dialog_seq), kind: kind.into(), message: message.into(), default_prompt: default_prompt.into(), opened_at: now_s(), session: session.into(), frame_id: frame.map(str::to_string), bridge_request: bridge };
    // An armed response (OpenClaw dialog arm) wins, then the auto policies.
    let armed = pg.armed_dialog.take().filter(|(_, _, until)| Instant::now() < *until);
    let auto = match (armed, policy) {
        (Some((a, t, _)), _) => Some((a, t.unwrap_or_default(), "armed")),
        (None, "auto_dismiss") => Some((false, String::new(), "auto_policy")),
        (None, "auto_accept") => Some((true, default_prompt.to_string(), "auto_policy")),
        _ => None,
    };
    if let Some((accept, text, by)) = auto {
        archive(pg, &d, by);
        respond_nowait(conn, &d, accept, Some(&text));
        return;
    }
    pg.dialogs.push(d);
}

pub fn archive(pg: &mut Page, d: &Dialog, by: &str) {
    let mut v = d.to_json();
    v["closed_at"] = now_s().into();
    v["closed_by"] = by.into();
    push_ring(&mut pg.recent_dialogs, v, RECENT_DIALOGS_MAX);
}

/// Answer a dialog: bridge XHRs via Fetch.fulfillRequest, native ones via Page.handleJavaScriptDialog.
pub fn respond_nowait(conn: &Conn, d: &Dialog, accept: bool, prompt: Option<&str>) {
    let sid = (!d.session.is_empty()).then_some(d.session.as_str());
    if let Some(rid) = &d.bridge_request {
        let body = json!({"accept": accept, "dialog_id": d.id, "prompt_text": if d.kind == "prompt" { prompt.unwrap_or("") } else { "" }}).to_string();
        conn.send_nowait("Fetch.fulfillRequest", json!({"requestId": rid, "responseCode": 200, "responseHeaders": [{"name": "Content-Type", "value": "application/json"}, {"name": "Access-Control-Allow-Origin", "value": "*"}], "body": seagent_net::crypto::b64(body.as_bytes())}), sid);
        return;
    }
    let mut params = json!({"accept": accept});
    if let (Some(t), "prompt") = (prompt, d.kind.as_str()) {
        params["promptText"] = t.into();
    }
    conn.send_nowait("Page.handleJavaScriptDialog", params, sid);
}

impl Browser {
    /// Wrap a connection: install the supervisor, discover targets, downloads into `dir`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(key: &str, kind: &str, conn: Conn, http: Option<String>, auth: Option<String>, pid: Option<i32>, owned: bool, dir: PathBuf, timeout: Duration, policy: &str, dialog_timeout: u64, bridge: bool) -> Arc<Browser> {
        let state = Arc::new(Mutex::new(State { dialog_policy: policy.into(), dialog_timeout: dialog_timeout.max(1) as f64, ..Default::default() }));
        let st = state.clone();
        conn.on_event(Arc::new(move |c, m, p, s| handle_event(&st, c, m, p, s)));
        let b = Arc::new(Browser { key: key.into(), kind: kind.into(), conn, http, auth, pid, owned, state, dir, last_used: Mutex::new(Instant::now()), timeout, info: Mutex::new(Default::default()), bridge, on_close: Mutex::new(None) });
        let _ = b.conn.call_with("Target.setDiscoverTargets", json!({"discover": true}), None, Duration::from_secs(5), &|| None);
        let dl = b.dir.join("downloads");
        let _ = std::fs::create_dir_all(&dl);
        let _ = b.conn.call_with("Browser.setDownloadBehavior", json!({"behavior": "allowAndName", "downloadPath": dl.display().to_string(), "eventsEnabled": true}), None, Duration::from_secs(5), &|| None);
        // Dialog watchdog (Hermes: auto-dismiss after dialog_timeout_s).
        let weak = Arc::downgrade(&b);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            let Some(b) = weak.upgrade() else { return };
            if b.conn.is_closed() {
                return;
            }
            let mut s = b.state.lock().unwrap();
            let limit = s.dialog_timeout;
            for pg in s.pages.values_mut() {
                let expired: Vec<Dialog> = pg.dialogs.iter().filter(|d| now_s() - d.opened_at > limit).cloned().collect();
                for d in expired {
                    pg.dialogs.retain(|x| x.id != d.id);
                    archive(pg, &d, "watchdog");
                    respond_nowait(&b.conn, &d, false, None);
                }
            }
        });
        b
    }

    pub fn touch(&self) {
        *self.last_used.lock().unwrap() = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_used.lock().unwrap().elapsed()
    }

    pub fn close(&self) {
        self.conn.close();
        if self.owned {
            if let Some(p) = self.pid {
                util::kill_group(p, Duration::from_secs(3));
            }
        }
        if let Some(f) = self.on_close.lock().unwrap().take() {
            f();
        }
    }

    /// Browser-level call.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.touch();
        self.conn.call_with(method, params, None, self.timeout, &|| None)
    }

    /// Page-session call that gives up when a modal dialog blocks the page.
    pub fn page_call(&self, target: &str, method: &str, params: Value) -> Result<Value, String> {
        let sid = self.attach(target)?;
        self.session_call(target, &sid, method, params, self.timeout)
    }

    pub fn session_call(&self, target: &str, sid: &str, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        self.touch();
        let st = self.state.clone();
        let t = target.to_string();
        let blocked = move || {
            let s = st.lock().unwrap();
            s.pages.get(&t).filter(|p| !p.dialogs.is_empty()).map(|_| BLOCKED_BY_DIALOG.to_string())
        };
        if blocked().is_some() && !method.starts_with("Page.handleJavaScriptDialog") && !method.starts_with("Fetch.") {
            return Err(BLOCKED_BY_DIALOG.into());
        }
        let r = self.conn.call_with(method, params, Some(sid), timeout, &blocked);
        if r.as_ref().is_err_and(|e| e.contains("Session with given id not found") || e.contains("No session with given id")) {
            let mut s = self.state.lock().unwrap();
            s.sessions.remove(sid);
            if let Some(p) = s.pages.get_mut(target) {
                p.session = None;
            }
        }
        r
    }

    /// Attach (once) to a page target and enable the domains the supervisor needs.
    pub fn attach(&self, target: &str) -> Result<String, String> {
        if let Some(sid) = self.state.lock().unwrap().pages.get(target).and_then(|p| p.session.clone()) {
            return Ok(sid);
        }
        let r = self.call("Target.attachToTarget", json!({"targetId": target, "flatten": true}))?;
        let sid = r["sessionId"].as_str().ok_or("Target.attachToTarget did not return a sessionId")?.to_string();
        {
            let mut s = self.state.lock().unwrap();
            s.sessions.insert(sid.clone(), (target.to_string(), None));
            let pg = s.pages.entry(target.to_string()).or_default();
            pg.session = Some(sid.clone());
            pg.closed = false;
        }
        let quiet = |m: &str, p: Value| {
            let _ = self.conn.call_with(m, p, Some(&sid), Duration::from_secs(5), &|| None);
        };
        for m in ["Page.enable", "Runtime.enable", "Network.enable", "DOM.enable", "Log.enable"] {
            quiet(m, json!({}));
        }
        quiet("Page.setLifecycleEventsEnabled", json!({"enabled": true}));
        quiet("Page.setInterceptFileChooserDialog", json!({"enabled": true}));
        quiet("Target.setAutoAttach", json!({"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}));
        if self.bridge {
            quiet("Page.addScriptToEvaluateOnNewDocument", json!({"source": BRIDGE_SCRIPT, "runImmediately": true}));
            quiet("Fetch.enable", json!({"patterns": [{"urlPattern": format!("http://{BRIDGE_HOST}/*"), "requestStage": "Request"}], "handleAuthRequests": false}));
            quiet("Runtime.evaluate", json!({"expression": BRIDGE_SCRIPT, "returnByValue": true}));
        }
        if let Ok(f) = self.conn.call_with("Page.getFrameTree", json!({}), Some(&sid), Duration::from_secs(5), &|| None) {
            let mut s = self.state.lock().unwrap();
            if let Some(pg) = s.pages.get_mut(target) {
                pg.main_frame = f["frameTree"]["frame"]["id"].as_str().unwrap_or("").into();
                pg.url = f["frameTree"]["frame"]["url"].as_str().unwrap_or("").into();
            }
        }
        Ok(sid)
    }

    /// Page targets (optionally inside one browser context), with stable `tN` handles.
    pub fn tabs(&self, context: Option<&str>) -> Result<Vec<Value>, String> {
        let r = self.call("Target.getTargets", json!({}))?;
        let mut s = self.state.lock().unwrap();
        let mut out = vec![];
        for t in r["targetInfos"].as_array().into_iter().flatten() {
            if t["type"] != "page" {
                continue;
            }
            if context.is_some_and(|c| t["browserContextId"].as_str() != Some(c)) {
                continue;
            }
            let id = t["targetId"].as_str().unwrap_or("").to_string();
            if !s.tab_ids.contains_key(&id) {
                s.tab_seq += 1;
                let h = format!("t{}", s.tab_seq);
                s.tab_ids.insert(id.clone(), h);
            }
            let tab = s.tab_ids[&id].clone();
            let label = s.labels.iter().find(|(_, v)| **v == id).map(|(k, _)| k.clone());
            let mut v = json!({"suggestedTargetId": label.clone().unwrap_or_else(|| tab.clone()), "tabId": tab, "title": t["title"], "url": t["url"], "type": "page", "targetId": id});
            if let Some(l) = label {
                v["label"] = l.into();
            }
            out.push(v);
        }
        Ok(out)
    }

    /// Resolve a tab reference: exact targetId / tN / label, else a unique targetId prefix.
    pub fn resolve_tab(&self, r: &str, context: Option<&str>) -> Result<String, String> {
        let r = r.trim();
        let tabs = self.tabs(context)?;
        for t in &tabs {
            for k in ["targetId", "tabId", "label", "suggestedTargetId"] {
                if t[k].as_str() == Some(r) {
                    return Ok(t["targetId"].as_str().unwrap().to_string());
                }
            }
        }
        let low = r.to_ascii_lowercase();
        let pre: Vec<&Value> = tabs.iter().filter(|t| t["targetId"].as_str().is_some_and(|id| id.to_ascii_lowercase().starts_with(&low))).collect();
        match pre.len() {
            1 => Ok(pre[0]["targetId"].as_str().unwrap().to_string()),
            0 if r.bytes().all(|b| b.is_ascii_digit()) => Err(format!("tab not found: browser tab \"{r}\" not found. Numeric values are not tab targets; use action=tabs and pass suggestedTargetId, tabId (t1), label, or raw targetId.")),
            0 => Err(format!("tab not found: browser tab \"{r}\" not found. Use action=tabs and pass suggestedTargetId, tabId, label, or raw targetId.")),
            _ => Err("ambiguous browser tab reference".into()),
        }
    }

    pub fn set_label(&self, target: &str, label: &str) -> Result<(), String> {
        if label.is_empty() || label.len() > 64 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)) {
            return Err("tab label must be 1-64 chars and use only letters, numbers, _, ., :, or -".into());
        }
        let mut s = self.state.lock().unwrap();
        s.labels.retain(|_, v| v != target);
        s.labels.insert(label.into(), target.into());
        Ok(())
    }

    /// New tab (optionally in a browser context).
    pub fn new_tab(&self, url: &str, context: Option<&str>) -> Result<String, String> {
        let mut p = json!({"url": url});
        if let Some(c) = context {
            p["browserContextId"] = c.into();
        }
        let r = self.call("Target.createTarget", p)?;
        let t = r["targetId"].as_str().ok_or("Target.createTarget returned no targetId")?.to_string();
        self.state.lock().unwrap().pages.entry(t.clone()).or_default().context = context.map(str::to_string);
        self.attach(&t)?;
        Ok(t)
    }

    pub fn close_tab(&self, target: &str) -> Result<(), String> {
        self.call("Target.closeTarget", json!({"targetId": target}))?;
        let mut s = self.state.lock().unwrap();
        if let Some(p) = s.pages.remove(target) {
            if let Some(sid) = p.session {
                s.sessions.remove(&sid);
            }
        }
        s.labels.retain(|_, v| v != target);
        Ok(())
    }

    /// Evaluate in the page; JSON value or the page exception.
    pub fn eval(&self, target: &str, expr: &str) -> Result<Value, String> {
        let r = self.page_call(target, "Runtime.evaluate", json!({"expression": expr, "returnByValue": true, "awaitPromise": true, "userGesture": true}))?;
        if let Some(e) = r.get("exceptionDetails") {
            let msg = e["exception"]["description"].as_str().or(e["text"].as_str()).unwrap_or("exception");
            if msg.contains("reference chain is too long") || msg.contains("Object reference chain") {
                return Err("Expression returned a live DOM node / NodeList / Window, which can't be serialized. Extract a primitive value (e.g. .innerText, .href, .src, .value) or use JSON.stringify() / a snapshot tool instead.".into());
            }
            return Err(format!("page script failed: {}", crate::util::cut(msg, 600)));
        }
        Ok(r["result"]["value"].clone())
    }

    pub fn url_title(&self, target: &str) -> (String, String) {
        match self.eval(target, "[location.href, document.title]") {
            Ok(Value::Array(a)) => (a[0].as_str().unwrap_or("").into(), a.get(1).and_then(|t| t.as_str()).unwrap_or("").into()),
            _ => {
                let s = self.state.lock().unwrap();
                s.pages.get(target).map(|p| (p.url.clone(), p.title.clone())).unwrap_or_default()
            }
        }
    }

    pub fn page<R>(&self, target: &str, f: impl FnOnce(&mut Page) -> R) -> R {
        let mut s = self.state.lock().unwrap();
        f(s.pages.entry(target.to_string()).or_default())
    }

    /// Wait until the main frame finished loading after `since` (load event), or timeout.
    pub fn wait_load(&self, target: &str, load_before: u64, nav_before: u64, timeout: Duration) {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            let (load, nav, blocked) = self.page(target, |p| (p.load_seq, p.nav_seq, !p.dialogs.is_empty()));
            if blocked || (load > load_before && nav >= nav_before) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait for network quiet (no requests for 500 ms) or the `networkIdle` lifecycle event.
    pub fn wait_network_idle(&self, target: &str, timeout: Duration) -> bool {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            let (idle, inflight, last) = self.page(target, |p| (p.network_idle, p.inflight, p.last_net));
            if idle || (inflight <= 0 && last.is_none_or(|l| l.elapsed() > Duration::from_millis(500))) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Supervisor view for snapshots (Hermes `SupervisorSnapshot.to_dict`).
    pub fn supervisor_view(&self, target: &str) -> Value {
        self.page(target, |p| {
            let mut frames: Vec<&Frame> = p.frames.values().filter(|f| f.id != p.main_frame).collect();
            frames.sort_by(|a, b| a.id.cmp(&b.id));
            let children: Vec<Value> = frames.iter().take(FRAME_TREE_MAX).map(|f| json!({"frame_id": f.id, "parent_frame_id": f.parent, "url": crate::policy::redact(&f.url), "name": f.name, "is_oopif": f.oopif, "session_id": f.session})).collect();
            json!({
                "pending_dialogs": p.dialogs.iter().map(Dialog::to_json).collect::<Vec<_>>(),
                "recent_dialogs": p.recent_dialogs.iter().cloned().collect::<Vec<_>>(),
                "frame_tree": {"top": {"frame_id": p.main_frame, "url": crate::policy::redact(&p.url)}, "children": children, "truncated": frames.len() > FRAME_TREE_MAX},
            })
        })
    }

    /// Respond to a pending dialog (Hermes browser_dialog / OpenClaw dialog).
    pub fn respond_dialog(&self, target: &str, accept: bool, prompt: Option<&str>, id: Option<&str>) -> Result<Value, String> {
        let d = self.page(target, |p| {
            let i = match id {
                Some(id) => p.dialogs.iter().position(|d| d.id == id).ok_or_else(|| format!("Dialog \"{id}\" is not pending."))?,
                None if p.dialogs.len() > 1 => return Err("Multiple dialogs are pending; pass dialogId.".to_string()),
                None => p.dialogs.first().map(|_| 0).ok_or("No dialog is pending.")?,
            };
            let d = p.dialogs.remove(i);
            archive(p, &d, "agent");
            Ok(d)
        })?;
        respond_nowait(&self.conn, &d, accept, prompt);
        Ok(d.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::fake;

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    }

    fn browser(policy: &str) -> (Arc<Browser>, fake::Fake) {
        let f = fake::start(Arc::new(|m, p, _s| match m {
            "Target.attachToTarget" => (json!({"sessionId": format!("S-{}", p["targetId"].as_str().unwrap())}), vec![]),
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "AAA1", "type": "page", "title": "One", "url": "https://one.example/"}, {"targetId": "BBB2", "type": "page", "title": "Two", "url": "https://two.example/"}, {"targetId": "W", "type": "service_worker"}]}), vec![]),
            "Runtime.evaluate" => (json!({"result": {"value": "ok"}}), vec![]),
            _ => (json!({}), vec![]),
        }));
        let ws = crate::cdp::resolve_ws(&f.http, None, Duration::from_secs(5)).unwrap();
        let c = Conn::connect(&ws, &[], Duration::from_secs(5)).unwrap();
        let dir = seagent_core::tmp::scratch_path(format!("seagent-engine-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
        (Browser::new("t", "cdp", c, Some(f.http.clone()), None, None, false, dir, Duration::from_secs(5), policy, 300, false), f)
    }

    #[test]
    fn tabs_handles_labels_and_resolution() {
        let (b, _f) = browser("must_respond");
        let t = b.tabs(None).unwrap();
        assert_eq!((t.len(), t[0]["tabId"].as_str(), t[1]["tabId"].as_str()), (2, Some("t1"), Some("t2")));
        assert_eq!(b.resolve_tab("t2", None).unwrap(), "BBB2");
        assert_eq!(b.resolve_tab("aaa", None).unwrap(), "AAA1");
        b.set_label("AAA1", "docs").unwrap();
        assert_eq!(b.resolve_tab("docs", None).unwrap(), "AAA1");
        assert_eq!(b.tabs(None).unwrap()[0]["suggestedTargetId"], "docs");
        assert!(b.set_label("AAA1", "bad label").is_err());
        assert!(b.resolve_tab("zzz", None).unwrap_err().contains("tab not found"));
        assert!(b.resolve_tab("5", None).unwrap_err().contains("Numeric"));
    }

    #[test]
    fn supervisor_records_events_and_dialogs() {
        let (b, _f) = browser("must_respond");
        let sid = b.attach("AAA1").unwrap();
        let ev = |m: &str, p: Value| handle_event(&b.state, &b.conn, m, &p, Some(&sid));
        ev("Runtime.consoleAPICalled", json!({"type": "warning", "args": [{"type": "string", "value": "careful"}, {"type": "number", "value": 3}], "timestamp": 1_700_000_000_000.0_f64}));
        ev("Runtime.exceptionThrown", json!({"exceptionDetails": {"text": "Uncaught", "exception": {"className": "TypeError", "description": "TypeError: x is undefined\n    at f (a.js:1)"}}}));
        ev("Network.requestWillBeSent", json!({"requestId": "9", "type": "XHR", "request": {"method": "GET", "url": "https://api.example/x"}}));
        ev("Network.responseReceived", json!({"requestId": "9", "response": {"status": 404}}));
        ev("Page.frameNavigated", json!({"frame": {"id": "F1", "url": "https://one.example/next"}}));
        b.page("AAA1", |p| {
            assert_eq!(p.console[0]["text"], "careful 3");
            assert_eq!(p.errors[0]["message"], "TypeError: x is undefined");
            assert_eq!((p.requests[0]["id"].as_str(), p.requests[0]["status"].as_i64(), p.requests[0]["ok"].as_bool()), (Some("r1"), Some(404), Some(false)));
            assert_eq!((p.nav_seq, p.url.as_str()), (1, "https://one.example/next"));
        });
        ev("Page.javascriptDialogOpening", json!({"type": "confirm", "message": "Leave?", "frameId": "F1"}));
        assert_eq!(b.supervisor_view("AAA1")["pending_dialogs"][0]["id"], "d1");
        assert_eq!(b.page_call("AAA1", "Runtime.evaluate", json!({"expression": "1"})).unwrap_err(), BLOCKED_BY_DIALOG);
        assert!(b.respond_dialog("AAA1", true, None, Some("d9")).unwrap_err().contains("not pending"));
        b.respond_dialog("AAA1", true, None, None).unwrap();
        let v = b.supervisor_view("AAA1");
        assert_eq!((v["pending_dialogs"].as_array().unwrap().len(), v["recent_dialogs"][0]["closed_by"].as_str()), (0, Some("agent")));
        assert!(b.respond_dialog("AAA1", true, None, None).unwrap_err().contains("No dialog"));
        // armed response, then auto policy
        b.page("AAA1", |p| p.armed_dialog = Some((false, None, Instant::now() + Duration::from_secs(5))));
        ev("Page.javascriptDialogOpening", json!({"type": "alert", "message": "hi"}));
        assert_eq!(b.supervisor_view("AAA1")["recent_dialogs"][1]["closed_by"], "armed");
        std::thread::sleep(Duration::from_millis(100));
        assert!(_f.seen.lock().unwrap().iter().filter(|m| m["method"] == "Page.handleJavaScriptDialog").count() >= 2);
    }

    #[test]
    fn auto_policy_and_bridge_dialogs() {
        let (b, f) = browser("auto_accept");
        let sid = b.attach("AAA1").unwrap();
        handle_event(&b.state, &b.conn, "Page.javascriptDialogOpening", &json!({"type": "prompt", "message": "Name?", "defaultPrompt": "seagent"}), Some(&sid));
        assert_eq!(b.supervisor_view("AAA1")["recent_dialogs"][0]["closed_by"], "auto_policy");
        b.state.lock().unwrap().dialog_policy = "must_respond".into();
        handle_event(&b.state, &b.conn, "Fetch.requestPaused", &json!({"requestId": "R7", "request": {"url": format!("http://{BRIDGE_HOST}/?kind=confirm&message=Sure%3F&default_prompt=")}}), Some(&sid));
        let v = b.supervisor_view("AAA1");
        assert_eq!((v["pending_dialogs"][0]["type"].as_str(), v["pending_dialogs"][0]["message"].as_str()), (Some("confirm"), Some("Sure?")));
        b.respond_dialog("AAA1", true, None, None).unwrap();
        handle_event(&b.state, &b.conn, "Fetch.requestPaused", &json!({"requestId": "R8", "request": {"url": "https://other.example/"}}), Some(&sid));
        std::thread::sleep(Duration::from_millis(150));
        let seen = f.seen.lock().unwrap();
        let ff = seen.iter().find(|m| m["method"] == "Fetch.fulfillRequest").unwrap();
        let body = String::from_utf8(seagent_net::crypto::b64_decode(ff["params"]["body"].as_str().unwrap()).unwrap()).unwrap();
        assert!(body.contains("\"accept\":true") && ff["params"]["requestId"] == "R7");
        assert!(seen.iter().any(|m| m["method"] == "Fetch.continueRequest" && m["params"]["requestId"] == "R8"));
        assert!(seen.iter().any(|m| m["method"] == "Page.handleJavaScriptDialog" && m["params"]["promptText"] == "seagent"));
    }
}
