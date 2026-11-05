//! Browser view / desktop view for the web UI (OpenClaw `ui/src/components/browser`,
//! `ui/src/components/desktop`, `extensions/browser/src/*browser-dashboard*` and the sandbox
//! noVNC observer, MIT). The app server runs inside the daemon, so the browser manager the
//! tools drive is this process's [`ark_browser::manager::global`].
//!
//! ARP methods ([`METHODS`]) and the same as HTTP routes under `/view/` — all behind the
//! app token (the routes are dispatched after the token check):
//!
//! - `view.browser.list {session?}` / `GET /view/browser?session=`: browsers, tabs, the
//!   session's current tab.
//! - `view.browser.frame {session?, key?, targetId?, maxWidth?, quality?}` → JPEG (base64 over
//!   ARP; raw `image/jpeg` from `GET /view/browser/frame?…`).
//! - `view.browser.input {viewer, session?, key?, targetId?, event}` / `POST /view/browser/input`:
//!   viewer input; only from the viewer holding the Bot Desktop lease.
//! - `view.desktop.state {viewer?}` / `GET /view/desktop`: the lease (who controls the screen).
//! - `view.desktop.frame` → PNG of the display computer_use acts on (`GET /view/desktop/frame`).
//! - `view.desktop.takeover {viewer, reason?}` / `view.desktop.handback {viewer}` (`POST
//!   /view/desktop/takeover|handback`): the Bot Desktop control lease.
//! - `view.novnc {key, open?}` / `POST /view/novnc`: a one-time 60 s ticket for the sandbox
//!   browser's noVNC (`GET /view/novnc?ticket=` serves the bootstrap page); `open: true`
//!   redeems it at once and returns the loopback noVNC URL for the UI to open.

use crate::server::App;
use ark_browser::manager::{self, Manager};
use ark_browser::{lease, view, BrowserConfig};
use ark_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::path::Path;

pub const METHODS: &[&str] = &["view.browser.list", "view.browser.frame", "view.browser.input", "view.desktop.state", "view.desktop.frame", "view.desktop.takeover", "view.desktop.handback", "view.novnc"];

type R = Result<Value, (i64, String)>;

/// What a call needs: ark home (lease, Bot Desktop), browser config (navigation policy), the manager.
pub struct Ctx<'a> {
    pub home: &'a Path,
    pub cfg: &'a BrowserConfig,
    pub m: &'a Manager,
}

fn s<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p[k].as_str().map(str::trim).filter(|x| !x.is_empty())
}

/// Viewer ids are client-chosen random handles (the lease stores them; only a hash is shown).
fn viewer(p: &Value) -> Result<&str, (i64, String)> {
    let v = s(p, "viewer").ok_or((-32602, "viewer is required (a random id this UI keeps for its tab)".to_string()))?;
    if !(8..=128).contains(&v.len()) || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err((-32602, "viewer must be 8-128 characters of [A-Za-z0-9_-]".into()));
    }
    Ok(v)
}

fn frame(c: &Ctx, p: &Value) -> Result<view::Frame, (i64, String)> {
    let (b, t) = view::resolve(c.m, s(p, "session"), s(p, "key"), s(p, "targetId")).map_err(|e| (-32001, e))?;
    let w = p["maxWidth"].as_u64().map_or(view::MAX_WIDTH, |w| w.clamp(160, 4000) as u32);
    let q = p["quality"].as_u64().map_or(view::QUALITY, |q| q.clamp(10, 100) as u8);
    view::capture(&b, &t, w, q).map_err(|e| (-32000, e))
}

fn desktop_png(home: &Path) -> Result<Vec<u8>, (i64, String)> {
    crate::computer::screenshot_png(home).map_err(|e| (-32000, e))
}

fn desktop_state(home: &Path, p: &Value) -> Value {
    let mut v = json!({"lease": lease::public_view(home), "botDesktop": home.join("bot-desktop").exists()});
    if let Ok(id) = viewer(p) {
        v["viewerHolds"] = lease::viewer_may_send_input(home, id).into();
    }
    v
}

/// One view method.
pub fn call(c: &Ctx, method: &str, p: &Value) -> R {
    match method {
        "view.browser.list" => Ok(view::list(c.m, s(p, "session"))),
        "view.browser.frame" => frame(c, p).map(|f| f.to_json()),
        "view.browser.input" => {
            let id = viewer(p)?;
            if !lease::viewer_may_send_input(c.home, id) {
                return Err((-32003, "Take control first (view.desktop.takeover): browser input is only accepted from the viewer holding the desktop lease.".into()));
            }
            let (b, t) = view::resolve(c.m, s(p, "session"), s(p, "key"), s(p, "targetId")).map_err(|e| (-32001, e))?;
            view::input(c.cfg, &b, &t, &p["event"]).map_err(|e| (-32000, e))
        }
        "view.desktop.state" => Ok(desktop_state(c.home, p)),
        "view.desktop.frame" => desktop_png(c.home).map(|png| json!({"mime": "image/png", "data": ark_net::crypto::b64(&png), "lease": lease::public_view(c.home)})),
        "view.desktop.takeover" => {
            let id = viewer(p)?;
            let reason: String = s(p, "reason").unwrap_or("").chars().take(200).collect();
            lease::acquire(c.home, id, &reason).map_err(|e| (-32000, e))?;
            Ok(desktop_state(c.home, p))
        }
        "view.desktop.handback" => {
            let id = viewer(p)?;
            lease::release(c.home, Some(id), false).map_err(|e| (-32000, e))?;
            Ok(desktop_state(c.home, p))
        }
        "view.novnc" => {
            let key = s(p, "key").ok_or((-32602, "key is required (the sandbox browser's key from view.browser.list)".to_string()))?;
            let b = c.m.get(key).ok_or_else(|| (-32001, format!("browser `{key}` is not running")))?;
            let (port, pw) = view::novnc_target(&b).ok_or_else(|| (-32001, format!("browser `{key}` has no noVNC observer (only the sandbox browser, headed, with sandbox.novnc on)")))?;
            let now = ark_browser::util::now_ms();
            if p["open"] == true {
                return Ok(json!({"url": view::novnc_url(port, pw.as_deref())}));
            }
            let t = view::issue_ticket(port, pw, None, now);
            Ok(json!({"ticket": t, "path": format!("/view/novnc?ticket={t}"), "expiresAtMs": now + view::NOVNC_TICKET_TTL_MS}))
        }
        m => Err((-32601, format!("unknown method {m}"))),
    }
}

fn with_app<T>(app: &App, f: impl FnOnce(&Ctx) -> T) -> T {
    let home = app.d.k.paths.data.clone();
    let cfg = BrowserConfig::parse(&app.d.k.cfg.browser).unwrap_or_default();
    f(&Ctx { home: &home, cfg: &cfg, m: manager::global() })
}

/// ARP entry point (`App::rpc`).
pub fn rpc(app: &App, method: &str, p: &Value) -> R {
    with_app(app, |c| call(c, method, p))
}

fn no_store(r: Response) -> Response {
    r.with_header("cache-control", "no-store").with_header("x-content-type-options", "nosniff").with_header("referrer-policy", "no-referrer")
}

fn err(code: i64, msg: &str) -> Response {
    let st = match code {
        -32602 => 400,
        -32003 => 403,
        -32001 | -32601 => 404,
        _ => 502,
    };
    no_store(Response::json(st, &json!({"error": msg}).to_string()))
}

/// The self-contained live view panel (vanilla JS, no external resources): browsers and tabs,
/// the browser frame + input, the desktop frame + lease, and the sandbox noVNC button.
const PANEL_HTML: &str = include_str!("browser_view_panel.html");

/// `GET /view/` and `GET /view/ui`: the panel page, with a per-response script nonce.
fn panel() -> Response {
    let nonce = ark_net::crypto::random_token(16);
    let csp = format!("default-src 'none'; img-src 'self' data: blob:; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    no_store(Response::html(&PANEL_HTML.replace("{{NONCE}}", &nonce))).with_header("content-security-policy", &csp)
}

/// `/view/…` HTTP routes; the server calls this only for authorized requests.
pub fn handle(app: &App, r: &Request) -> Response {
    with_app(app, |c| route(c, r))
}

pub fn route(c: &Ctx, r: &Request) -> Response {
    let q: Value = r.query.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>().into();
    let body = || serde_json::from_slice::<Value>(&r.body).unwrap_or(json!({}));
    let num = |v: &Value, k: &str| v[k].as_str().and_then(|x| x.parse::<u64>().ok()).map(Value::from).unwrap_or(Value::Null);
    let j = |res: R| match res {
        Ok(v) => no_store(Response::json(200, &v.to_string())),
        Err((code, m)) => err(code, &m),
    };
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/view/") | ("GET", "/view/ui") => panel(),
        ("GET", "/view/browser") => j(call(c, "view.browser.list", &q)),
        ("GET", "/view/browser/frame") => {
            let mut p = q.clone();
            p["maxWidth"] = num(&q, "maxWidth");
            p["quality"] = num(&q, "quality");
            match frame(c, &p) {
                Ok(f) => no_store(Response::new(200, f.mime, f.data)),
                Err((code, m)) => err(code, &m),
            }
        }
        ("POST", "/view/browser/input") => j(call(c, "view.browser.input", &body())),
        ("GET", "/view/desktop") => j(call(c, "view.desktop.state", &q)),
        ("GET", "/view/desktop/frame") => match desktop_png(c.home) {
            Ok(png) => no_store(Response::new(200, "image/png", png)),
            Err((code, m)) => err(code, &m),
        },
        ("POST", "/view/desktop/takeover") => j(call(c, "view.desktop.takeover", &body())),
        ("POST", "/view/desktop/handback") => j(call(c, "view.desktop.handback", &body())),
        ("POST", "/view/novnc") => j(call(c, "view.novnc", &body())),
        // bridge-server.ts `/sandbox/novnc`: authenticated + a one-time ticket.
        ("GET", "/view/novnc") => {
            let Some(t) = s(&q, "ticket") else { return no_store(Response::text(400, "Missing ticket")) };
            match view::consume_ticket(t, ark_browser::util::now_ms()) {
                Some((port, pw)) => no_store(Response::new(200, "text/html; charset=utf-8", view::novnc_bootstrap_html(port, pw.as_deref())))
                    .with_header("content-security-policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
                    .with_header("pragma", "no-cache")
                    .with_header("expires", "0"),
                None => no_store(Response::text(404, "Invalid or expired ticket")),
            }
        }
        _ => no_store(Response::json(404, &json!({"error": "not found"}).to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppConfig;
    use ark_kernel::config::{Config, Paths};
    use ark_kernel::daemon::Daemon;
    use std::sync::Arc;
    use std::time::Duration;

    struct NoRes;
    impl ark_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn app(home: &Path) -> Arc<App> {
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        let cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() };
        Arc::new(App { d, cfg, token: "view-test-token".into(), host_methods: vec![], routes: vec![] })
    }

    fn get(base: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, String, String) {
        let a: ureq::Agent = ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
        let url = format!("{base}{path}");
        let auth = token.map(|t| format!("Bearer {t}"));
        let r = match body {
            Some(b) => {
                let mut rq = a.post(&url).header("content-type", "application/json");
                if let Some(h) = &auth {
                    rq = rq.header("authorization", h);
                }
                rq.send(b.to_string())
            }
            None => {
                let mut rq = a.get(&url);
                if let Some(h) = &auth {
                    rq = rq.header("authorization", h);
                }
                rq.call()
            }
        };
        let mut r = r.unwrap_or_else(|e| panic!("{e}"));
        let st = r.status().as_u16();
        let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        (st, ct, r.body_mut().read_to_string().unwrap_or_default())
    }

    #[test]
    fn view_routes_need_the_token_and_return_json() {
        let home = ark_core::tmp::scratch_path(format!("ark-bview-{}-{}", std::process::id(), ark_net::crypto::random_token(4)));
        let srv = crate::server::start(app(&home)).unwrap();
        let base = format!("http://{}", srv.local_addr());
        for p in ["/view/browser", "/view/browser/frame", "/view/desktop", "/view/desktop/frame", "/view/novnc?ticket=x"] {
            assert_eq!(get(&base, p, None, None).0, 401, "{p} without token");
            assert_eq!(get(&base, p, Some("wrong"), None).0, 401, "{p} wrong token");
        }
        assert_eq!(get(&base, "/view/desktop/takeover", None, Some(json!({"viewer": "viewer-0001"}))).0, 401);
        let (st, ct, body) = get(&base, "/view/browser?session=nope", Some("view-test-token"), None);
        assert_eq!((st, ct.as_str()), (200, "application/json"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v["browsers"].is_array() && v["session"]["id"] == "nope" && v["session"]["key"].is_null(), "{v}");
        let (st, _, body) = get(&base, "/view/browser/frame?session=nope", Some("view-test-token"), None);
        assert!(st == 404 && body.contains("no browser yet"), "{st} {body}");
        // The lease: take over, input from another viewer refused, hand back.
        let (st, _, body) = get(&base, "/view/desktop/takeover", Some("view-test-token"), Some(json!({"viewer": "viewer-0001", "reason": "typing a password"})));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((st, v["lease"]["holder"].as_str(), v["viewerHolds"].as_bool()), (200, Some("human"), Some(true)), "{body}");
        assert_eq!(v["lease"]["reason"], "typing a password");
        let (st, _, body) = get(&base, "/view/browser/input", Some("view-test-token"), Some(json!({"viewer": "viewer-0002", "session": "nope", "event": {"type": "reload"}})));
        assert!(st == 403 && body.contains("Take control first"), "{st} {body}");
        let (st, _, body) = get(&base, "/view/browser/input", Some("view-test-token"), Some(json!({"viewer": "viewer-0001", "session": "nope", "event": {"type": "reload"}})));
        assert!(st == 404 && body.contains("no browser yet"), "holder passes the lease check: {st} {body}");
        assert_eq!(get(&base, "/view/desktop/takeover", Some("view-test-token"), Some(json!({"viewer": "bad id!"}))).0, 400);
        let (_, _, body) = get(&base, "/view/desktop/handback", Some("view-test-token"), Some(json!({"viewer": "viewer-0002"})));
        assert!(body.contains("\"holder\":\"human\""), "only the holder hands back: {body}");
        let (_, _, body) = get(&base, "/view/desktop/handback", Some("view-test-token"), Some(json!({"viewer": "viewer-0001"})));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((v["lease"]["holder"].as_str(), v["lease"]["epoch"].as_u64()), (Some("agent"), Some(2)));
        let (_, _, body) = get(&base, "/view/desktop?viewer=viewer-0001", Some("view-test-token"), None);
        assert!(body.contains("\"viewerHolds\":false"), "{body}");
        // noVNC: unknown browser, bad ticket, one good one-time ticket.
        let (st, _, body) = get(&base, "/view/novnc", Some("view-test-token"), Some(json!({"key": "sandbox"})));
        assert!(st == 404 && body.contains("not running"), "{body}");
        assert_eq!(get(&base, "/view/novnc?ticket=bogus", Some("view-test-token"), None).0, 404);
        assert_eq!(get(&base, "/view/novnc", Some("view-test-token"), None).0, 400);
        let t = view::issue_ticket(45678, Some("pw123456".into()), None, ark_browser::util::now_ms());
        let (st, ct, body) = get(&base, &format!("/view/novnc?ticket={t}"), Some("view-test-token"), None);
        assert!(st == 200 && ct.starts_with("text/html") && body.contains("http://127.0.0.1:45678/vnc.html#autoconnect=1&resize=remote&password=pw123456"), "{body}");
        assert_eq!(get(&base, &format!("/view/novnc?ticket={t}"), Some("view-test-token"), None).0, 404, "one-time");
        assert_eq!(get(&base, "/view/nothing", Some("view-test-token"), None).0, 404);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A GET that also returns the response headers (lower-case names), for the panel's CSP.
    fn get_headers(base: &str, path: &str, token: Option<&str>) -> (u16, Vec<(String, String)>, String) {
        let a: ureq::Agent = ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
        let mut rq = a.get(&format!("{base}{path}"));
        if let Some(t) = token {
            rq = rq.header("authorization", &format!("Bearer {t}"));
        }
        let mut r = rq.call().unwrap_or_else(|e| panic!("{e}"));
        let st = r.status().as_u16();
        let hs: Vec<(String, String)> = r.headers().iter().map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string())).collect();
        (st, hs, r.body_mut().read_to_string().unwrap_or_default())
    }

    #[test]
    fn view_panel_is_a_self_contained_page() {
        let home = ark_core::tmp::scratch_path(format!("ark-bview-panel-{}-{}", std::process::id(), ark_net::crypto::random_token(4)));
        let srv = crate::server::start(app(&home)).unwrap();
        let base = format!("http://{}", srv.local_addr());
        for p in ["/view/", "/view/ui"] {
            let (st, hs, body) = get_headers(&base, p, Some("view-test-token"));
            assert_eq!(st, 200, "{p}");
            let h = |k: &str| hs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("");
            assert!(h("content-type").starts_with("text/html"), "{p}: {}", h("content-type"));
            assert_eq!((h("cache-control"), h("x-content-type-options"), h("referrer-policy")), ("no-store", "nosniff", "no-referrer"), "{p}");
            let csp = h("content-security-policy");
            assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'nonce-"), "{p}: {csp}");
            assert!(csp.contains("connect-src 'self'") && csp.contains("frame-ancestors 'none'"), "{p}: {csp}");
            // The nonce the policy allows is the one on the page's script tag.
            let nonce = csp.split("script-src 'nonce-").nth(1).and_then(|x| x.split('\'').next()).unwrap_or("");
            assert!(nonce.len() >= 16 && body.contains(&format!("<script nonce=\"{nonce}\">")), "{p}: nonce {nonce}");
            for needle in [
                "location.search",
                "/view/browser",
                "view/browser/frame",
                "view/browser/input",
                "view/desktop/frame",
                "view/desktop/takeover",
                "view/desktop/handback",
                "view/novnc",
            ] {
                assert!(body.contains(needle), "{p} is missing {needle}");
            }
            // Self-contained: every fetch is a relative /view/… path, no remote scripts or images.
            assert!(!body.contains("http://") && !body.contains("https://"), "{p} references an external resource");
            assert!(!body.contains("onclick=") && !body.contains("onload="), "{p} uses inline event handler attributes");
        }
        assert_eq!(get(&base, "/view/", None, None).0, 401, "no token");
        assert_eq!(get(&base, "/view/ui", Some("wrong"), None).0, 401, "wrong token");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn arp_methods_are_advertised_and_dispatched() {
        let home = ark_core::tmp::scratch_path(format!("ark-bview-arp-{}-{}", std::process::id(), ark_net::crypto::random_token(4)));
        let a = app(&home);
        let caps = a.capabilities();
        assert!(METHODS.iter().all(|m| caps["methods"].as_array().unwrap().iter().any(|x| x == m)), "{caps}");
        let r = a.rpc(&json!({"jsonrpc": "2.0", "id": 1, "method": "view.browser.list", "params": {}}));
        assert!(r["result"]["browsers"].is_array() && r["result"]["session"].is_null(), "{r}");
        let r = a.rpc(&json!({"jsonrpc": "2.0", "id": 2, "method": "view.desktop.state", "params": {"viewer": "viewer-0009"}}));
        assert_eq!((r["result"]["lease"]["holder"].as_str(), r["result"]["viewerHolds"].as_bool()), (Some("agent"), Some(false)), "{r}");
        let r = a.rpc(&json!({"jsonrpc": "2.0", "id": 3, "method": "view.browser.input", "params": {"viewer": "short"}}));
        assert_eq!(r["error"]["code"], -32602);
        let r = a.rpc(&json!({"jsonrpc": "2.0", "id": 4, "method": "view.novnc", "params": {}}));
        assert!(r["error"]["message"].as_str().unwrap().contains("key is required"));
        let _ = std::fs::remove_dir_all(&home);
    }
}
