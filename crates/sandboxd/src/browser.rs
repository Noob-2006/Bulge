//! The `browser` command: a headless Firefox inside the guest, driven over
//! WebDriver BiDi (Firefox's built-in Remote Agent, no geckodriver).
//!
//! Firefox is started on first use as the unprivileged agent user, with its
//! Remote Agent on a loopback port inside the guest (never a host port), and
//! its proxy pointed at the guest's egress bridge, so pages load through the
//! same two-key gateway and allowlists as every other outbound connection.
//! HTTPS-only mode is on because that bridge carries CONNECT tunnels only.
//!
//! The model perceives a page as a text snapshot: the URL, title, every
//! visible interactive element with a short `[eN]` ref, its role and
//! accessible name, then the visible text. It acts by ref: `click` and `type`
//! send real pointer and key events (`input.performActions` with the element
//! as the origin), not synthetic DOM calls.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::runtime::{HandlerError, InvocationContext};

/// Loopback port of Firefox's Remote Agent inside the guest.
const REMOTE_PORT: u16 = 9222;
/// How long Firefox may take to start and accept the BiDi session.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a page may take to finish loading after an action that navigated.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long after an action a navigation may still start (a form submit or a
/// script-driven redirect begins asynchronously).
const NAVIGATION_GRACE: Duration = Duration::from_millis(1200);
/// How long a snapshot waits for script-rendered content to settle, and how
/// often it looks.
const CONTENT_TIMEOUT: Duration = Duration::from_secs(6);
const CONTENT_POLL: Duration = Duration::from_millis(300);
/// Snapshot bounds handed to the page script: interactive elements listed and
/// visible-text characters (the whole result is then bounded like any tool
/// output, with the full text spilled to a file).
const MAX_ELEMENTS: u32 = 400;
const MAX_TEXT_CHARS: u32 = 6000;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Session {
    child: Child,
    ws: Ws,
    next_id: u64,
    context: String,
    shots: u32,
    /// Event method names received since the last `take_events`.
    events: Vec<String>,
}

fn session_slot() -> &'static Mutex<Option<Session>> {
    static SLOT: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

fn err(code: &str, message: impl std::fmt::Display) -> HandlerError {
    HandlerError::new(code, message.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Params {
    /// Load a URL and return its snapshot.
    Navigate { url: String },
    /// The current page as text (refs are renumbered each time).
    Snapshot,
    /// Click an element by ref, or a viewport point.
    Click {
        #[serde(default)]
        r#ref: Option<String>,
        #[serde(default)]
        x: Option<i64>,
        #[serde(default)]
        y: Option<i64>,
    },
    /// Focus an element by ref and type text into it; `submit` presses Enter.
    Type {
        r#ref: String,
        text: String,
        #[serde(default)]
        clear: bool,
        #[serde(default)]
        submit: bool,
    },
    /// Press one key (Enter, Tab, Escape, Backspace, ArrowDown, PageDown, …).
    Press { key: String },
    /// Scroll the page by a number of viewport heights (negative = up).
    Scroll {
        #[serde(default = "one")]
        pages: f64,
    },
    Back,
    /// Save a PNG of the viewport; returns its path.
    Screenshot,
    /// Close the browser (it restarts on the next action).
    Close,
}

fn one() -> f64 {
    1.0
}

pub async fn browser(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: Params = serde_json::from_value(cx.invocation.params.clone()).map_err(|e| err("INVALID_PARAMS", e))?;
    let mut slot = session_slot().lock().await;
    if let Params::Close = params {
        if let Some(mut session) = slot.take() {
            let _ = session.child.kill().await;
        }
        return Ok(json!({ "closed": true }));
    }
    // (Re)start when there is no live browser.
    let alive = match slot.as_mut() {
        Some(session) => session.child.try_wait().map(|status| status.is_none()).unwrap_or(false),
        None => false,
    };
    if !alive {
        *slot = Some(launch().await?);
    }
    let session = slot.as_mut().ok_or_else(|| err("BROWSER_FAILED", "browser did not start"))?;
    let work = run(session, params);
    tokio::select! {
        result = work => result,
        () = cx.cancellation.cancelled() => Err(err("CANCELLED", "browser action cancelled")),
    }
}

async fn run(session: &mut Session, params: Params) -> Result<Value, HandlerError> {
    // Only events caused by this action count when it settles.
    session.events.clear();
    match params {
        Params::Navigate { url } => {
            let url = if url.contains("://") { url } else { format!("https://{url}") };
            let context = session.context.clone();
            match session.call("browsingContext.navigate", json!({ "context": context, "url": url, "wait": "complete" })).await {
                Ok(_) => {}
                // A redirect (or a script) started another navigation before
                // this one finished: follow it instead of failing.
                Err(e) if e.to_string().contains("NS_BINDING_ABORTED") => {
                    session.wait_event("browsingContext.load", SETTLE_TIMEOUT).await;
                }
                Err(e) => return Err(e),
            }
            snapshot_value(session).await
        }
        Params::Snapshot => snapshot_value(session).await,
        Params::Click { r#ref, x, y } => {
            let origin_and_point = match (r#ref, x, y) {
                (Some(r), _, _) => (json!({ "type": "element", "element": { "sharedId": element(session, &r).await? } }), 0, 0),
                (None, Some(x), Some(y)) => (json!("viewport"), x, y),
                _ => return Err(err("INVALID_PARAMS", "click needs a `ref` from the snapshot, or `x` and `y`")),
            };
            let (origin, x, y) = origin_and_point;
            let context = session.context.clone();
            let actions = json!([{
                "type": "pointer", "id": "mouse", "parameters": { "pointerType": "mouse" },
                "actions": [
                    { "type": "pointerMove", "x": x, "y": y, "origin": origin },
                    { "type": "pointerDown", "button": 0 },
                    { "type": "pointerUp", "button": 0 }
                ]
            }]);
            session.call("input.performActions", json!({ "context": context, "actions": actions })).await?;
            settle(session).await;
            snapshot_value(session).await
        }
        Params::Type { r#ref, text, clear, submit } => {
            let shared = element(session, &r#ref).await?;
            let context = session.context.clone();
            // Click into the field first, as a user would, so it has focus.
            let pointer = json!({ "type": "pointer", "id": "mouse", "parameters": { "pointerType": "mouse" }, "actions": [
                { "type": "pointerMove", "x": 0, "y": 0, "origin": { "type": "element", "element": { "sharedId": shared } } },
                { "type": "pointerDown", "button": 0 },
                { "type": "pointerUp", "button": 0 }
            ] });
            session.call("input.performActions", json!({ "context": context, "actions": [pointer] })).await?;
            if clear {
                // Select everything in the field and delete it, as a user would.
                session.call("script.callFunction", json!({
                    "functionDeclaration": "(el) => { if (el.select) el.select(); else document.getSelection().selectAllChildren(el); }",
                    "target": { "context": context }, "awaitPromise": false,
                    "arguments": [{ "sharedId": shared }]
                })).await?;
                key_actions(session, &["\u{E003}".to_string()]).await?;
            }
            let mut sequence: Vec<String> = text.chars().map(|c| if c == '\n' { "\u{E007}".to_string() } else { c.to_string() }).collect();
            if submit {
                sequence.push("\u{E007}".into());
            }
            key_actions(session, &sequence).await?;
            settle(session).await;
            snapshot_value(session).await
        }
        Params::Press { key } => {
            let code = key_code(&key).ok_or_else(|| err("INVALID_PARAMS", format!("unknown key {key:?}")))?;
            key_actions(session, &[code]).await?;
            settle(session).await;
            snapshot_value(session).await
        }
        Params::Scroll { pages } => {
            evaluate(session, "(p) => { window.scrollBy(0, p * window.innerHeight); return true; }", vec![json!({ "type": "number", "value": pages })]).await?;
            snapshot_value(session).await
        }
        Params::Back => {
            let context = session.context.clone();
            session.call("browsingContext.traverseHistory", json!({ "context": context, "delta": -1 })).await?;
            settle(session).await;
            snapshot_value(session).await
        }
        Params::Screenshot => {
            let context = session.context.clone();
            let result = session.call("browsingContext.captureScreenshot", json!({ "context": context })).await?;
            let data = result.get("data").and_then(Value::as_str).ok_or_else(|| err("BROWSER_FAILED", "no screenshot data"))?;
            let bytes = base64::engine::general_purpose::STANDARD.decode(data).map_err(|e| err("BROWSER_FAILED", e))?;
            session.shots += 1;
            let dir = PathBuf::from(crate::setup::AGENT_HOME).join("screenshots");
            std::fs::create_dir_all(&dir).map_err(|e| err("IO", e))?;
            let path = dir.join(format!("shot-{}.png", session.shots));
            std::fs::write(&path, bytes).map_err(|e| err("IO", e))?;
            Ok(json!({ "path": path.display().to_string() }))
        }
        Params::Close => unreachable!("handled before launch"),
    }
}

/// Start Firefox and open the BiDi session.
async fn launch() -> Result<Session, HandlerError> {
    let home = PathBuf::from(crate::setup::AGENT_HOME);
    let profile = home.join(format!("firefox-profile-{}", std::process::id()));
    std::fs::create_dir_all(&profile).map_err(|e| err("IO", e))?;
    std::fs::write(profile.join("user.js"), user_prefs(crate::EGRESS_PROXY.get().map(String::as_str))).map_err(|e| err("IO", e))?;
    let child = Command::new("firefox")
        .args(["--headless", "--no-remote", "--profile"])
        .arg(&profile)
        .args(["--remote-debugging-port", &REMOTE_PORT.to_string()])
        .env("HOME", &home)
        .env("MOZ_CRASHREPORTER_DISABLE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| err("BROWSER_UNAVAILABLE", format!("cannot start firefox (is it installed in the rootfs?): {e}")))?;

    let url = format!("ws://127.0.0.1:{REMOTE_PORT}/session");
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    let ws = loop {
        match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((ws, _)) => break ws,
            Err(e) if tokio::time::Instant::now() >= deadline => return Err(err("BROWSER_FAILED", format!("firefox remote agent not reachable: {e}"))),
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    };
    let mut session = Session { child, ws, next_id: 1, context: String::new(), shots: 0, events: Vec::new() };
    session.call("session.new", json!({ "capabilities": {} })).await?;
    session.call("session.subscribe", json!({ "events": ["browsingContext.navigationStarted", "browsingContext.load"] })).await?;
    let tree = session.call("browsingContext.getTree", json!({ "maxDepth": 0 })).await?;
    session.context = tree
        .pointer("/contexts/0/context")
        .and_then(Value::as_str)
        .ok_or_else(|| err("BROWSER_FAILED", "no top-level browsing context"))?
        .to_owned();
    Ok(session)
}

/// Profile preferences: route traffic through the guest's egress bridge (or
/// nowhere), HTTPS-only, and no background traffic of Firefox's own.
fn user_prefs(proxy: Option<&str>) -> String {
    let mut prefs = vec![
        ("dom.security.https_only_mode", "true".to_string()),
        ("browser.shell.checkDefaultBrowser", "false".into()),
        ("app.update.enabled", "false".into()),
        ("datareporting.policy.dataSubmissionEnabled", "false".into()),
        ("toolkit.telemetry.enabled", "false".into()),
        ("browser.safebrowsing.malware.enabled", "false".into()),
        ("browser.safebrowsing.phishing.enabled", "false".into()),
        ("extensions.update.enabled", "false".into()),
        ("network.captive-portal-service.enabled", "false".into()),
        ("browser.startup.homepage_override.mstone", "\"ignore\"".into()),
    ];
    match proxy.and_then(|p| p.strip_prefix("http://")).and_then(|hostport| hostport.rsplit_once(':')) {
        Some((host, port)) => {
            prefs.push(("network.proxy.type", "1".into()));
            prefs.push(("network.proxy.ssl", format!("\"{host}\"")));
            prefs.push(("network.proxy.ssl_port", port.to_string()));
            prefs.push(("network.proxy.no_proxies_on", "\"localhost, 127.0.0.1, ::1\"".into()));
        }
        // No egress in this VM: keep Firefox from trying the (absent) network.
        None => prefs.push(("network.proxy.type", "0".into())),
    }
    prefs.iter().map(|(k, v)| format!("user_pref(\"{k}\", {v});\n")).collect()
}

impl Session {
    /// Wait until `event` has been received (or was already, since the last
    /// clear), up to `timeout`. Returns whether it arrived.
    async fn wait_event(&mut self, event: &str, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(at) = self.events.iter().position(|e| e == event) {
                self.events.drain(..=at);
                return true;
            }
            let text = match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => text,
                Ok(Some(Ok(_))) => continue,
                // Timed out, or the connection is gone (the next call reports it).
                Err(_) | Ok(None) | Ok(Some(Err(_))) => return false,
            };
            if let Ok(reply) = serde_json::from_str::<Value>(text.as_str())
                && reply.get("type").and_then(Value::as_str) == Some("event")
                && let Some(method) = reply.get("method").and_then(Value::as_str)
            {
                self.events.push(method.to_owned());
            }
        }
    }

    /// Send one BiDi command and wait for its result (events are skipped).
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, HandlerError> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "id": id, "method": method, "params": params }).to_string();
        self.ws.send(Message::text(message)).await.map_err(|e| err("BROWSER_FAILED", e))?;
        while let Some(frame) = self.ws.next().await {
            let frame = frame.map_err(|e| err("BROWSER_FAILED", e))?;
            let Message::Text(text) = frame else { continue };
            let Ok(reply) = serde_json::from_str::<Value>(text.as_str()) else { continue };
            if reply.get("type").and_then(Value::as_str) == Some("event") {
                if let Some(event) = reply.get("method").and_then(Value::as_str) {
                    self.events.push(event.to_owned());
                }
                continue;
            }
            if reply.get("id").and_then(Value::as_u64) != Some(id) {
                continue; // a reply to something else
            }
            if reply.get("type").and_then(Value::as_str) == Some("error") {
                let code = reply.get("error").and_then(Value::as_str).unwrap_or("error");
                let message = reply.get("message").and_then(Value::as_str).unwrap_or("");
                return Err(err("BROWSER_ERROR", format!("{method}: {code}: {message}")));
            }
            return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
        }
        Err(err("BROWSER_FAILED", "browser connection closed"))
    }
}

/// Call a function in the page; returns the RemoteValue it produced.
async fn evaluate(session: &mut Session, function: &str, arguments: Vec<Value>) -> Result<Value, HandlerError> {
    let context = session.context.clone();
    let result = session
        .call("script.callFunction", json!({
            "functionDeclaration": function,
            "target": { "context": context },
            "arguments": arguments,
            "awaitPromise": true,
            "userActivation": true,
        }))
        .await?;
    if result.get("type").and_then(Value::as_str) == Some("exception") {
        let text = result.pointer("/exceptionDetails/text").and_then(Value::as_str).unwrap_or("page script failed");
        return Err(err("BROWSER_ERROR", text));
    }
    Ok(result.get("result").cloned().unwrap_or(Value::Null))
}

/// The element behind a snapshot ref, scrolled into view, as a BiDi shared id.
async fn element(session: &mut Session, r#ref: &str) -> Result<String, HandlerError> {
    let value = evaluate(
        session,
        "(ref) => { const el = window.__bulge && window.__bulge.get(ref); if (!el || !el.isConnected) throw new Error('unknown or stale ref ' + ref + '; take a new snapshot'); el.scrollIntoView({ block: 'center', inline: 'center' }); return el; }",
        vec![json!({ "type": "string", "value": r#ref })],
    )
    .await?;
    value.get("sharedId").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| err("BROWSER_ERROR", "ref is not an element"))
}

async fn key_actions(session: &mut Session, keys: &[String]) -> Result<(), HandlerError> {
    let actions: Vec<Value> = keys.iter().flat_map(|k| [json!({ "type": "keyDown", "value": k }), json!({ "type": "keyUp", "value": k })]).collect();
    let context = session.context.clone();
    session.call("input.performActions", json!({ "context": context, "actions": [{ "type": "key", "id": "keyboard", "actions": actions }] })).await?;
    Ok(())
}

/// WebDriver key codes for named keys.
fn key_code(name: &str) -> Option<String> {
    let code = match name.to_ascii_lowercase().as_str() {
        "enter" | "return" => '\u{E007}',
        "tab" => '\u{E004}',
        "escape" | "esc" => '\u{E00C}',
        "backspace" => '\u{E003}',
        "delete" => '\u{E017}',
        "space" => ' ',
        "arrowleft" | "left" => '\u{E012}',
        "arrowup" | "up" => '\u{E013}',
        "arrowright" | "right" => '\u{E014}',
        "arrowdown" | "down" => '\u{E015}',
        "pageup" => '\u{E00E}',
        "pagedown" => '\u{E00F}',
        "home" => '\u{E011}',
        "end" => '\u{E010}',
        _ => return None,
    };
    Some(code.to_string())
}

/// After an action that may navigate: if a navigation starts within the
/// grace period, wait for the new page's load event before the snapshot.
async fn settle(session: &mut Session) {
    if session.wait_event("browsingContext.navigationStarted", NAVIGATION_GRACE).await {
        session.wait_event("browsingContext.load", SETTLE_TIMEOUT).await;
    }
}

/// Wait until the page stops changing: many pages (search results above
/// all) render their content with scripts after the load event. Polls the
/// amount of visible text and elements until two readings agree.
async fn wait_for_content(session: &mut Session) {
    let deadline = tokio::time::Instant::now() + CONTENT_TIMEOUT;
    let mut last: Option<String> = None;
    while tokio::time::Instant::now() < deadline {
        let reading = evaluate(session, "() => `${document.readyState}:${document.body ? document.body.innerText.length : 0}:${document.getElementsByTagName('*').length}`", vec![])
            .await
            .ok()
            .and_then(|v| v.get("value").and_then(Value::as_str).map(str::to_owned));
        if let (Some(now), Some(before)) = (&reading, &last)
            && now == before
            && now.starts_with("complete:")
            && !now.starts_with("complete:0:")
        {
            return;
        }
        last = reading;
        tokio::time::sleep(CONTENT_POLL).await;
    }
}

async fn snapshot_value(session: &mut Session) -> Result<Value, HandlerError> {
    wait_for_content(session).await;
    let value = evaluate(
        session,
        SNAPSHOT_JS,
        vec![json!({ "type": "number", "value": MAX_ELEMENTS }), json!({ "type": "number", "value": MAX_TEXT_CHARS })],
    )
    .await?;
    let text = value.get("value").and_then(Value::as_str).unwrap_or_default();
    crate::tools::handlers::bounded(text)
}

/// Page script: number every visible interactive element (refs kept on
/// `window.__bulge` for click/type), then the visible text.
const SNAPSHOT_JS: &str = r#"(maxElements, maxText) => {
  const refs = new Map(); window.__bulge = refs;
  const visible = (e) => { const r = e.getBoundingClientRect(); if (r.width === 0 && r.height === 0) return false;
    const s = getComputedStyle(e); return s.visibility !== 'hidden' && s.display !== 'none'; };
  const clean = (t) => (t || '').replace(/\s+/g, ' ').trim();
  const nameOf = (e) => {
    const aria = e.getAttribute('aria-label'); if (aria) return aria;
    const by = e.getAttribute('aria-labelledby');
    if (by) { const t = by.split(/\s+/).map((id) => (document.getElementById(id) || {}).innerText || '').join(' '); if (clean(t)) return t; }
    if (e.labels && e.labels.length) { const t = Array.from(e.labels).map((l) => l.innerText).join(' '); if (clean(t)) return t; }
    if (e.alt) return e.alt;
    const own = e.tagName === 'INPUT' ? '' : e.innerText; if (clean(own)) return own;
    return e.getAttribute('placeholder') || e.getAttribute('title') || e.getAttribute('name') || (e.tagName === 'INPUT' ? e.value : '') || '';
  };
  const roleOf = (e) => {
    const r = e.getAttribute('role'); if (r) return r;
    if (e.tagName === 'INPUT') return ({ checkbox: 'checkbox', radio: 'radio', submit: 'button', button: 'button', reset: 'button', range: 'slider', search: 'searchbox' })[e.type] || 'textbox';
    if (e.isContentEditable) return 'textbox';
    return ({ A: 'link', BUTTON: 'button', SELECT: 'combobox', TEXTAREA: 'textbox', SUMMARY: 'button' })[e.tagName] || e.tagName.toLowerCase();
  };
  const selector = 'a[href],button,input:not([type=hidden]),select,textarea,summary,[contenteditable=""],[contenteditable=true],' +
    '[role=button],[role=link],[role=checkbox],[role=radio],[role=tab],[role=menuitem],[role=option],[role=switch],[role=textbox],[role=combobox],[role=searchbox],[onclick]';
  const lines = []; let total = 0;
  for (const e of document.querySelectorAll(selector)) {
    if (e.disabled || !visible(e)) continue;
    total += 1; if (lines.length >= maxElements) continue;
    const ref = 'e' + total; refs.set(ref, e);
    let extra = '';
    if (e.tagName === 'INPUT' && ['checkbox', 'radio'].includes(e.type)) extra = e.checked ? ' [checked]' : '';
    else if ((e.tagName === 'INPUT' && !['submit', 'button', 'reset'].includes(e.type)) || e.tagName === 'TEXTAREA') extra = ' value="' + clean(e.value).slice(0, 60) + '"';
    else if (e.tagName === 'SELECT') extra = ' selected="' + clean((e.selectedOptions[0] || {}).text).slice(0, 60) + '"';
    if (e.tagName === 'A') extra += ' -> ' + (e.getAttribute('href') || '').slice(0, 100);
    lines.push('[' + ref + '] ' + roleOf(e) + ' "' + clean(nameOf(e)).slice(0, 80) + '"' + extra);
  }
  if (total > lines.length) lines.push('(' + (total - lines.length) + ' more elements not listed; scroll and snapshot again)');
  let text = (document.body ? document.body.innerText : '').replace(/\n\s*\n+/g, '\n').trim();
  const cut = text.length > maxText; text = text.slice(0, maxText);
  return 'URL: ' + location.href + '\nTitle: ' + document.title + '\n\nInteractive elements (act on them by [ref]):\n' +
    (lines.join('\n') || '(none)') + '\n\nVisible text' + (cut ? ' (first ' + maxText + ' characters; scroll for more)' : '') + ':\n' + text;
}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_route_through_the_bridge_or_nowhere() {
        let with = user_prefs(Some("http://127.0.0.1:3128"));
        assert!(with.contains("user_pref(\"network.proxy.ssl\", \"127.0.0.1\");"));
        assert!(with.contains("user_pref(\"network.proxy.ssl_port\", 3128);"));
        assert!(with.contains("user_pref(\"dom.security.https_only_mode\", true);"));
        let without = user_prefs(None);
        assert!(without.contains("user_pref(\"network.proxy.type\", 0);"));
        assert!(!without.contains("network.proxy.ssl\""));
    }

    #[test]
    fn params_parse_and_reject_unknown_fields() {
        let p: Params = serde_json::from_value(json!({ "action": "click", "ref": "e3" })).unwrap();
        assert!(matches!(p, Params::Click { r#ref: Some(ref r), .. } if r == "e3"));
        let p: Params = serde_json::from_value(json!({ "action": "type", "ref": "e1", "text": "你好", "submit": true })).unwrap();
        assert!(matches!(p, Params::Type { submit: true, .. }));
        assert!(serde_json::from_value::<Params>(json!({ "action": "navigate", "url": "x", "evil": 1 })).is_err());
        assert!(serde_json::from_value::<Params>(json!({ "action": "format_disk" })).is_err());
        assert_eq!(key_code("Enter").as_deref(), Some("\u{E007}"));
        assert_eq!(key_code("nope"), None);
    }
}
