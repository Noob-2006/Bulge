//! Live view of the agent's browsers for the web UI (OpenClaw `ui/src/components/browser`
//! browser panel + `extensions/browser/src/*browser-dashboard*`, and the sandbox noVNC
//! observer of `src/agents/sandbox/novnc-auth.ts` + `bridge-server.ts`, MIT): per-session
//! tab list, the current URL/title, polled JPEG frames, viewer input while the viewer holds
//! the Bot Desktop lease, and one-time noVNC observer tickets.
//!
//! Frames use `Page.captureScreenshot` on the page session without touching the browser's
//! idle clock, so a watching UI never keeps an otherwise idle browser alive.

use crate::config::BrowserConfig;
use crate::engine::{Browser, BLOCKED_BY_DIALOG};
use crate::manager::Manager;
use crate::{actions, policy};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default frame width cap (CSS px are scaled down to this) and JPEG quality.
pub const MAX_WIDTH: u32 = 1280;
pub const QUALITY: u8 = 60;
const FRAME_TIMEOUT: Duration = Duration::from_secs(8);

/// One captured frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub mime: &'static str,
    pub key: String,
    pub target: String,
    pub url: String,
    pub title: String,
    /// CSS viewport size the frame shows (input coordinates are fractions of it).
    pub css_width: f64,
    pub css_height: f64,
}

impl Frame {
    /// The ARP shape: metadata plus base64 data (the UI renders a data: URL).
    pub fn to_json(&self) -> Value {
        json!({"key": self.key, "targetId": self.target, "url": self.url, "title": self.title, "mime": self.mime, "cssWidth": self.css_width, "cssHeight": self.css_height, "data": ark_net::crypto::b64(&self.data)})
    }
}

fn live(m: &Manager) -> Vec<Arc<Browser>> {
    let mut v: Vec<Arc<Browser>> = m.browsers().into_iter().filter(|b| !b.conn.is_closed()).collect();
    v.sort_by(|a, b| a.key.cmp(&b.key));
    v
}

/// Same rule as the tools: local routes may open private URLs.
fn local_route(b: &Browser) -> bool {
    b.key == "sidecar" || matches!(b.kind.as_str(), "local" | "real-profile" | "cdp" | "existing-session" | "remote" | "extension")
}

/// Browsers and their tabs; `sid` marks the ark session's browser + current tab.
pub fn list(m: &Manager, sid: Option<&str>) -> Value {
    let s = sid.map(|sid| (sid, m.session(sid)));
    let browsers: Vec<Value> = live(m)
        .iter()
        .map(|b| {
            let info = b.info.lock().unwrap().clone();
            let mine = s.as_ref().filter(|(_, x)| x.key == b.key).and_then(|(_, x)| x.target.clone());
            let mut o = json!({"key": b.key, "kind": b.kind, "headless": info.get("headless").cloned().unwrap_or(Value::Null), "botDesktop": info.contains_key("bot_desktop"), "novnc": novnc_target(b).is_some(), "session": mine.is_some()});
            match b.tabs(None) {
                Ok(tabs) => {
                    o["tabs"] = tabs
                        .into_iter()
                        .map(|t| {
                            let id = t["targetId"].as_str().unwrap_or("").to_string();
                            let mut x = json!({"targetId": id, "tabId": t["tabId"], "url": policy::redact(t["url"].as_str().unwrap_or("")), "title": policy::redact(t["title"].as_str().unwrap_or("")), "session": mine.as_deref() == Some(id.as_str())});
                            if let Some(l) = t.get("label") {
                                x["label"] = l.clone();
                            }
                            x
                        })
                        .collect();
                }
                Err(e) => {
                    o["tabs"] = json!([]);
                    o["error"] = policy::redact(&e).into();
                }
            }
            o
        })
        .collect();
    let session = s.map(|(sid, x)| json!({"id": sid, "key": (!x.key.is_empty()).then_some(x.key), "targetId": x.target}));
    json!({"session": session, "browsers": browsers})
}

/// Which browser + tab to show: an explicit key (+ target), else the session's current tab.
pub fn resolve(m: &Manager, sid: Option<&str>, key: Option<&str>, target: Option<&str>) -> Result<(Arc<Browser>, String), String> {
    let s = sid.map(|sid| m.session(sid)).unwrap_or_default();
    let key = key.filter(|k| !k.is_empty()).map(str::to_string).or_else(|| (!s.key.is_empty()).then(|| s.key.clone())).ok_or("This session has no browser yet (the agent has not opened one).")?;
    let b = m.get(&key).ok_or_else(|| format!("browser `{key}` is not running"))?;
    let tabs = b.tabs(None)?;
    let has = |t: &str| tabs.iter().any(|x| x["targetId"] == t);
    let t = match target.filter(|t| !t.is_empty()) {
        Some(t) if has(t) => t.to_string(),
        Some(t) => return Err(format!("tab `{t}` is not open in browser `{key}`")),
        None => match s.target.filter(|t| s.key == key && has(t)) {
            Some(t) => t,
            None => tabs.first().and_then(|x| x["targetId"].as_str()).map(str::to_string).ok_or_else(|| format!("browser `{key}` has no open tabs"))?,
        },
    };
    Ok((b, t))
}

/// The page session for `target` (attaching once if nothing has yet).
fn page_session(b: &Browser, target: &str) -> Result<String, String> {
    if let Some(sid) = b.state.lock().unwrap().pages.get(target).and_then(|p| p.session.clone()) {
        return Ok(sid);
    }
    b.attach(target)
}

fn dialog_open(b: &Browser, target: &str) -> bool {
    b.state.lock().unwrap().pages.get(target).is_some_and(|p| !p.dialogs.is_empty())
}

/// CSS viewport (x, y, width, height) of the page.
fn viewport(b: &Browser, sid: &str) -> Result<(f64, f64, f64, f64), String> {
    let m = b.conn.call_with("Page.getLayoutMetrics", json!({}), Some(sid), FRAME_TIMEOUT, &|| None)?;
    let v = if m["cssVisualViewport"].is_object() { &m["cssVisualViewport"] } else { &m["visualViewport"] };
    let f = |k: &str| v[k].as_f64().unwrap_or(0.0);
    Ok((f("pageX"), f("pageY"), f("clientWidth"), f("clientHeight")))
}

/// Capture one JPEG frame of `target`, scaled to at most `max_width` px wide.
pub fn capture(b: &Browser, target: &str, max_width: u32, quality: u8) -> Result<Frame, String> {
    if dialog_open(b, target) {
        return Err(BLOCKED_BY_DIALOG.into());
    }
    let sid = page_session(b, target)?;
    let (x, y, w, h) = viewport(b, &sid).unwrap_or((0.0, 0.0, 0.0, 0.0));
    let mut p = json!({"format": "jpeg", "quality": quality.clamp(10, 100), "optimizeForSpeed": true});
    let max = f64::from(max_width.clamp(160, 4000));
    if w > max && h > 0.0 {
        p["clip"] = json!({"x": x, "y": y, "width": w, "height": h, "scale": max / w});
    }
    let (st, t) = (b.state.clone(), target.to_string());
    let blocked = move || st.lock().unwrap().pages.get(&t).filter(|p| !p.dialogs.is_empty()).map(|_| BLOCKED_BY_DIALOG.to_string());
    let r = b.conn.call_with("Page.captureScreenshot", p, Some(&sid), FRAME_TIMEOUT, &blocked)?;
    let data = ark_net::crypto::b64_decode(r["data"].as_str().ok_or("Page.captureScreenshot returned no data")?).ok_or("bad screenshot data")?;
    let info = b.conn.call_with("Target.getTargetInfo", json!({"targetId": target}), None, FRAME_TIMEOUT, &|| None).unwrap_or_default();
    let (url, title) = match info["targetInfo"].as_object() {
        Some(i) => (i.get("url").and_then(Value::as_str).unwrap_or("").to_string(), i.get("title").and_then(Value::as_str).unwrap_or("").to_string()),
        None => b.state.lock().unwrap().pages.get(target).map(|p| (p.url.clone(), p.title.clone())).unwrap_or_default(),
    };
    Ok(Frame { data, mime: "image/jpeg", key: b.key.clone(), target: target.into(), url: policy::redact(&url), title: policy::redact(&title), css_width: w, css_height: h })
}

/// Viewer input (OpenClaw browser panel interact mode). Coordinates are fractions (0..1)
/// of the shown frame. `type`: click | dblclick | scroll | text | key | navigate | back |
/// forward | reload | activate. The caller checks the viewer holds the lease.
pub fn input(cfg: &BrowserConfig, b: &Browser, target: &str, ev: &Value) -> Result<Value, String> {
    let ty = ev["type"].as_str().unwrap_or("");
    let at = || -> Result<(f64, f64), String> {
        let (fx, fy) = (ev["x"].as_f64().ok_or("x is required")?, ev["y"].as_f64().ok_or("y is required")?);
        if !(0.0..=1.0).contains(&fx) || !(0.0..=1.0).contains(&fy) {
            return Err("x and y are fractions of the frame (0..1)".into());
        }
        let (_, _, w, h) = viewport(b, &page_session(b, target)?)?;
        Ok(((fx * w).round(), (fy * h).round()))
    };
    match ty {
        "click" | "dblclick" => {
            let (x, y) = at()?;
            let button = match ev["button"].as_str().unwrap_or("left") {
                s @ ("left" | "right" | "middle") => s,
                s => return Err(format!("unknown mouse button `{s}`")),
            };
            actions::click_at(b, target, x, y, actions::Click { button, count: if ty == "dblclick" { 2 } else { 1 }, modifiers: 0 }, Duration::ZERO)?;
        }
        "scroll" => {
            let (x, y) = at()?;
            let (dx, dy) = (ev["dx"].as_f64().unwrap_or(0.0).clamp(-5000.0, 5000.0), ev["dy"].as_f64().unwrap_or(0.0).clamp(-5000.0, 5000.0));
            b.page_call(target, "Input.dispatchMouseEvent", json!({"type": "mouseWheel", "x": x, "y": y, "deltaX": dx, "deltaY": dy}))?;
        }
        "text" => {
            let t = ev["text"].as_str().ok_or("text is required")?;
            if t.chars().count() > 10_000 {
                return Err("text is limited to 10000 characters".into());
            }
            actions::insert_text(b, target, t)?;
        }
        "key" => actions::press(b, target, ev["key"].as_str().ok_or("key is required")?)?,
        "navigate" => {
            let url = policy::check_navigation(cfg, ev["url"].as_str().unwrap_or(""), local_route(b))?;
            b.page_call(target, "Page.navigate", json!({"url": url}))?;
            return Ok(json!({"ok": true, "url": url}));
        }
        "back" | "forward" => {
            let h = b.page_call(target, "Page.getNavigationHistory", json!({}))?;
            let i = h["currentIndex"].as_i64().unwrap_or(0) + if ty == "back" { -1 } else { 1 };
            let entry = h["entries"].as_array().and_then(|e| usize::try_from(i).ok().and_then(|i| e.get(i))).ok_or_else(|| format!("no page to go {ty} to"))?;
            if let Some(u) = entry["url"].as_str() {
                if let Some(e) = policy::check_final_url(cfg, u, local_route(b)) {
                    return Err(e);
                }
            }
            b.page_call(target, "Page.navigateToHistoryEntry", json!({"entryId": entry["id"]}))?;
        }
        "reload" => {
            b.page_call(target, "Page.reload", json!({}))?;
        }
        "activate" => {
            b.call("Target.activateTarget", json!({"targetId": target}))?;
        }
        other => return Err(format!("unknown input type `{other}` (click, dblclick, scroll, text, key, navigate, back, forward, reload, activate)")),
    }
    Ok(json!({"ok": true}))
}

// ── sandbox noVNC observer (novnc-auth.ts) ──

/// Observer tickets live at most this long and are redeemable once.
pub const NOVNC_TICKET_TTL_MS: u64 = 60_000;

/// Where a browser's noVNC listens on loopback, and its VNC password. Reads the
/// sandbox's `info` (`novnc_port` + `novnc_password`, or the `novnc_url` it publishes).
pub fn novnc_target(b: &Browser) -> Option<(u16, Option<String>)> {
    let i = b.info.lock().unwrap();
    if let Some(p) = i.get("novnc_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()) {
        return Some((p, i.get("novnc_password").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)));
    }
    let url = i.get("novnc_url")?.as_str()?;
    let rest = url.strip_prefix("http://127.0.0.1:").or_else(|| url.strip_prefix("http://localhost:"))?;
    let port: u16 = rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    let pw = rest.split(['?', '#', '&']).find_map(|kv| kv.strip_prefix("password=")).map(|s| ark_net::urldecode(s.split('&').next().unwrap_or(s))).filter(|s| !s.is_empty());
    Some((port, pw))
}

type Ticket = ((u16, Option<String>), u64);
static TICKETS: Mutex<Option<HashMap<String, Ticket>>> = Mutex::new(None);

/// Mint a one-time observer ticket (ttl capped at [`NOVNC_TICKET_TTL_MS`]).
pub fn issue_ticket(port: u16, password: Option<String>, ttl_ms: Option<u64>, now_ms: u64) -> String {
    let ttl = ttl_ms.filter(|t| (1..=NOVNC_TICKET_TTL_MS).contains(t)).unwrap_or(NOVNC_TICKET_TTL_MS);
    let tok = ark_net::crypto::random_token(24);
    let mut g = TICKETS.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    m.retain(|_, (_, exp)| *exp > now_ms);
    m.insert(tok.clone(), ((port, password), now_ms + ttl));
    tok
}

/// Redeem a ticket (once): the noVNC port and password.
pub fn consume_ticket(token: &str, now_ms: u64) -> Option<(u16, Option<String>)> {
    let mut g = TICKETS.lock().unwrap();
    let (v, exp) = g.as_mut()?.remove(token)?;
    (exp > now_ms).then_some(v)
}

/// The noVNC page on loopback (password in the fragment, never sent to a server).
pub fn novnc_url(port: u16, password: Option<&str>) -> String {
    let mut h = String::from("autoconnect=1&resize=remote");
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        h.push_str(&format!("&password={}", ark_net::urlencode(p)));
    }
    format!("http://127.0.0.1:{port}/vnc.html#{h}")
}

/// The bootstrap page served for a redeemed ticket (bridge-server.ts `buildNoVncBootstrapHtml`).
pub fn novnc_bootstrap_html(port: u16, password: Option<&str>) -> String {
    let target = serde_json::to_string(&novnc_url(port, password)).unwrap_or_default().replace('<', "\\u003c");
    format!("<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n  <meta name=\"referrer\" content=\"no-referrer\" />\n  <title>ark noVNC Observer</title>\n</head>\n<body>\n  <p>Opening sandbox observer...</p>\n  <script>\n    const target = {target};\n    window.location.replace(target);\n  </script>\n</body>\n</html>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::Env;

    fn fake() -> crate::cdp::fake::Fake {
        crate::cdp::fake::start(Arc::new(|m, p, _| match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "P1", "type": "page", "url": "https://example.com/", "title": "Example"}, {"targetId": "P2", "type": "page", "url": "about:blank", "title": ""}, {"targetId": "W1", "type": "service_worker", "url": "x", "title": ""}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": format!("S{}", p["targetId"].as_str().unwrap())}), vec![]),
            "Target.getTargetInfo" => (json!({"targetInfo": {"targetId": p["targetId"], "url": "https://example.com/", "title": "Example"}}), vec![]),
            "Page.getLayoutMetrics" => (json!({"cssVisualViewport": {"pageX": 0, "pageY": 10, "clientWidth": 2560, "clientHeight": 1440}}), vec![]),
            "Page.captureScreenshot" => (json!({"data": ark_net::crypto::b64(b"\xff\xd8JPEG")}), vec![]),
            "Page.getNavigationHistory" => (json!({"currentIndex": 1, "entries": [{"id": 7, "url": "https://a.example/"}, {"id": 8, "url": "https://example.com/"}]}), vec![]),
            _ => (json!({}), vec![]),
        }))
    }

    fn setup() -> (crate::cdp::fake::Fake, Manager, Env) {
        let f = fake();
        let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), ..Default::default() };
        let env = Env { cfg, home: std::env::temp_dir().join(format!("ark-view-{}-{}", std::process::id(), ark_net::crypto::random_token(4))), secrets: Arc::new(|s: &str| s.to_string()) };
        (f, Manager::default(), env)
    }

    fn sent(f: &crate::cdp::fake::Fake, method: &str) -> Vec<Value> {
        f.seen.lock().unwrap().iter().filter(|v| v["method"] == method).cloned().collect()
    }

    #[test]
    fn lists_session_tabs_and_resolves_targets() {
        let (_f, m, env) = setup();
        assert!(resolve(&m, Some("s1"), None, None).err().unwrap().contains("no browser yet"));
        let b = m.browser(&env, "cdp").unwrap();
        m.focus("s1", &b, "P2");
        let v = list(&m, Some("s1"));
        assert_eq!(v["session"]["key"], "cdp");
        assert_eq!(v["session"]["targetId"], "P2");
        let br = &v["browsers"][0];
        assert_eq!((br["key"].as_str(), br["session"].as_bool(), br["novnc"].as_bool()), (Some("cdp"), Some(true), Some(false)));
        assert_eq!(br["tabs"].as_array().unwrap().len(), 2, "pages only");
        assert_eq!(br["tabs"][0]["title"], "Example");
        assert_eq!(br["tabs"][1]["session"], true);
        assert_eq!(list(&m, None)["session"], Value::Null);
        assert_eq!(resolve(&m, Some("s1"), None, None).unwrap().1, "P2", "the session's tab");
        assert_eq!(resolve(&m, None, Some("cdp"), Some("P1")).unwrap().1, "P1");
        assert_eq!(resolve(&m, None, Some("cdp"), None).unwrap().1, "P1", "first tab");
        assert!(resolve(&m, None, Some("cdp"), Some("NOPE")).err().unwrap().contains("not open"));
        assert!(resolve(&m, None, Some("other"), None).err().unwrap().contains("not running"));
    }

    #[test]
    fn captures_scaled_jpeg_frames_without_touching_idle_clock() {
        let (f, m, env) = setup();
        let b = m.browser(&env, "cdp").unwrap();
        b.attach("P1").unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let fr = capture(&b, "P1", 1280, 60).unwrap();
        assert!(b.idle_for() >= Duration::from_millis(60), "watching does not keep the browser alive");
        assert_eq!((fr.mime, fr.data.as_slice(), fr.url.as_str(), fr.title.as_str()), ("image/jpeg", &b"\xff\xd8JPEG"[..], "https://example.com/", "Example"));
        assert_eq!((fr.css_width, fr.css_height), (2560.0, 1440.0));
        let shot = sent(&f, "Page.captureScreenshot").pop().unwrap();
        assert_eq!(shot["sessionId"], "SP1");
        assert_eq!(shot["params"]["format"], "jpeg");
        assert_eq!(shot["params"]["clip"]["scale"], 0.5);
        assert_eq!(shot["params"]["clip"]["y"], 10.0);
        let j = fr.to_json();
        assert_eq!(ark_net::crypto::b64_decode(j["data"].as_str().unwrap()).unwrap(), b"\xff\xd8JPEG");
        // A small viewport is not clipped; an open dialog refuses the frame.
        capture(&b, "P1", 4000, 60).unwrap();
        assert!(sent(&f, "Page.captureScreenshot").pop().unwrap()["params"].get("clip").is_none());
        b.page("P1", |p| p.dialogs.push(crate::engine::Dialog { id: "d1".into(), kind: "alert".into(), message: "hi".into(), default_prompt: String::new(), opened_at: 0.0, session: "SP1".into(), frame_id: None, bridge_request: None }));
        assert_eq!(capture(&b, "P1", 1280, 60).unwrap_err(), BLOCKED_BY_DIALOG);
    }

    #[test]
    fn viewer_input_maps_fractions_and_checks_policy() {
        let (f, m, env) = setup();
        let b = m.browser(&env, "cdp").unwrap();
        input(&env.cfg, &b, "P1", &json!({"type": "click", "x": 0.5, "y": 0.25})).unwrap();
        let ms = sent(&f, "Input.dispatchMouseEvent");
        assert_eq!(ms.iter().map(|v| v["params"]["type"].as_str().unwrap()).collect::<Vec<_>>(), ["mouseMoved", "mousePressed", "mouseReleased"]);
        assert_eq!((ms[1]["params"]["x"].as_f64(), ms[1]["params"]["y"].as_f64()), (Some(1280.0), Some(360.0)));
        assert!(input(&env.cfg, &b, "P1", &json!({"type": "click", "x": 2, "y": 0})).unwrap_err().contains("fractions"));
        input(&env.cfg, &b, "P1", &json!({"type": "scroll", "x": 0.1, "y": 0.1, "dy": 300})).unwrap();
        assert_eq!(sent(&f, "Input.dispatchMouseEvent").pop().unwrap()["params"]["deltaY"], 300.0);
        input(&env.cfg, &b, "P1", &json!({"type": "text", "text": "héllo"})).unwrap();
        assert_eq!(sent(&f, "Input.insertText")[0]["params"]["text"], "héllo");
        input(&env.cfg, &b, "P1", &json!({"type": "key", "key": "Enter"})).unwrap();
        assert!(!sent(&f, "Input.dispatchKeyEvent").is_empty());
        let r = input(&env.cfg, &b, "P1", &json!({"type": "navigate", "url": "example.org"})).unwrap();
        assert_eq!(r["url"], "https://example.org");
        assert!(input(&env.cfg, &b, "P1", &json!({"type": "navigate", "url": "http://169.254.169.254/"})).unwrap_err().contains("metadata"));
        assert!(input(&env.cfg, &b, "P1", &json!({"type": "navigate", "url": "file:///etc/passwd"})).unwrap_err().contains("unsupported protocol"));
        input(&env.cfg, &b, "P1", &json!({"type": "back"})).unwrap();
        assert_eq!(sent(&f, "Page.navigateToHistoryEntry")[0]["params"]["entryId"], 7);
        assert!(input(&env.cfg, &b, "P1", &json!({"type": "forward"})).unwrap_err().contains("no page"));
        input(&env.cfg, &b, "P1", &json!({"type": "activate"})).unwrap();
        assert_eq!(sent(&f, "Target.activateTarget")[0]["params"]["targetId"], "P1");
        assert!(input(&env.cfg, &b, "P1", &json!({"type": "rm -rf"})).unwrap_err().contains("unknown input type"));
    }

    #[test]
    fn novnc_tickets_are_one_time_and_short_lived() {
        let t = issue_ticket(50123, Some("abcd1234".into()), Some(100), 1000);
        assert_eq!(consume_ticket(&t, 1050), Some((50123, Some("abcd1234".into()))));
        assert_eq!(consume_ticket(&t, 1050), None, "one-shot");
        let long = issue_ticket(50123, None, Some(60_001), 1000);
        assert_eq!(consume_ticket(&long, 61_001), None, "ttl capped at 60s");
        let ok = issue_ticket(1, None, None, 1000);
        assert_eq!(consume_ticket(&ok, 60_999), Some((1, None)));
        assert_eq!(novnc_url(6080, Some("a b")), "http://127.0.0.1:6080/vnc.html#autoconnect=1&resize=remote&password=a%20b");
        let html = novnc_bootstrap_html(6080, Some("pw</script>"));
        assert!(html.contains("window.location.replace(target)") && html.contains("no-referrer") && !html.contains("</script>\";"));
    }

    #[test]
    fn reads_novnc_target_from_sandbox_info() {
        let (_f, m, env) = setup();
        let b = m.browser(&env, "cdp").unwrap();
        assert!(novnc_target(&b).is_none());
        b.info.lock().unwrap().insert("novnc_url".into(), "http://127.0.0.1:49200/vnc.html?autoconnect=1&password=Xy12ab34".into());
        assert_eq!(novnc_target(&b), Some((49200, Some("Xy12ab34".into()))));
        b.info.lock().unwrap().insert("novnc_port".into(), 49201.into());
        b.info.lock().unwrap().insert("novnc_password".into(), "pw".into());
        assert_eq!(novnc_target(&b), Some((49201, Some("pw".into()))));
        assert_eq!(list(&m, None)["browsers"][0]["novnc"], true);
    }
}
