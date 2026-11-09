//! Browser view / desktop view for the web UI (OpenClaw `ui/src/components/browser`,
//! `ui/src/components/desktop`, `extensions/browser/src/*browser-dashboard*` and the sandbox
//! noVNC observer, MIT). The app server runs inside the daemon, so the browser manager the
//! tools drive is this process's [`seagent_browser::manager::global`].
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
//! - `view.desktop.list` / `GET /view/desktop/list`: the desktop targets — the host's Bot
//!   Desktop and every desktop VM (`[desktop_vm]`, `seagent vm desktop`):
//!   `[{id: "host"|"vm:<name>", kind: "host"|"vm", label, running, width, height,
//!   controller: "agent"|"human", lease}]` (VMs also carry `accel`, `imageBuilt`).
//! - `view.desktop.state {viewer?, target?}` / `GET /view/desktop?target=`: the target's lease
//!   (who controls that screen) → `{target, lease, viewerHolds?, botDesktop | running}`.
//!   `target` is `"host"` (default everywhere below) or `"vm:<name>"`.
//! - `view.desktop.frame {target?}` → `{mime: "image/png", data (base64), target, lease}`
//!   (raw `image/png` from `GET /view/desktop/frame?target=`). For a VM: QMP `screendump`.
//! - `view.desktop.takeover {viewer, target?, reason?}` / `view.desktop.handback {viewer,
//!   target?}` (`POST /view/desktop/takeover|handback`) → the state shape. Each target has
//!   its own lease: `host` = the Bot Desktop's, `vm:<name>` =
//!   `<data>/vm/desktop/<name>/bot-desktop/lease.json`. While a human holds a target's lease
//!   the agent's computer-use calls on that target are refused.
//! - `view.desktop.input {viewer, target?, event}` / `POST /view/desktop/input`: one input
//!   event in screen pixels, accepted only from the viewer holding that target's lease:
//!   `{type: "move"|"click"|"dblclick"|"down"|"up"|"scroll"|"key"|"type"|"drag", x, y,
//!   button: "left"|"middle"|"right", count, dx, dy (wheel ticks, +dy = down), key ("Enter",
//!   "Backspace", "ArrowUp", "Control+a", "ctrl+shift+t"), text, toX, toY}` →
//!   `{ok, type, width?, height?, typed?, via?}`. VMs: QMP `input-send-event` (US keyboard;
//!   text with non-ASCII characters such as CJK goes over the guest text channel, `via:
//!   "text-channel"`);
//!   `host`: xdotool / ydotool on the Bot Desktop.
//! - `view.vm.start {name?}` → the VM's status `{name, running, pid, width, height, accel,
//!   memory_mb, cpus, disk, image_built, qmp, vnc, warning, …}`; `view.vm.stop {name}` →
//!   `{name, stopped}` (`POST /view/vm/start|stop`). Admin scope (exposure.rs).
//! - `view.novnc {key, open?}` / `POST /view/novnc`: a one-time 60 s ticket for the sandbox
//!   browser's noVNC (`GET /view/novnc?ticket=` serves the bootstrap page); `open: true`
//!   redeems it at once and returns the loopback noVNC URL for the UI to open.
//!
//! The console does not poll these frames any more: `GET /view/live` (WebSocket,
//! [`crate::live_view`]) pushes the browser screencast, desktop frames and the agent's live
//! terminal as they happen; the frame methods stay for other clients and as the fallback.

use crate::server::App;
use seagent_browser::manager::{self, Manager};
use seagent_browser::{lease, view, BrowserConfig};
use seagent_net::httpd::{Request, Response};
use seagent_vm::desktop::{DesktopConfig, DesktopVms};
use serde_json::{json, Value};
use std::path::Path;

pub const METHODS: &[&str] = &[
    "view.browser.list",
    "view.browser.frame",
    "view.browser.input",
    "view.desktop.list",
    "view.desktop.state",
    "view.desktop.frame",
    "view.desktop.takeover",
    "view.desktop.handback",
    "view.desktop.input",
    "view.vm.start",
    "view.vm.stop",
    "view.novnc",
];

type R = Result<Value, (i64, String)>;

/// What a call needs: seagent home (lease, Bot Desktop), browser config (navigation policy), the manager.
pub struct Ctx<'a> {
    pub home: &'a Path,
    pub cfg: &'a BrowserConfig,
    pub m: &'a Manager,
    /// Desktop VMs of this home (`[desktop_vm]`).
    pub vms: &'a DesktopVms,
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

/// A desktop target: the host Bot Desktop or a desktop VM.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Host,
    Vm(String),
}

impl Target {
    pub fn id(&self) -> String {
        match self {
            Target::Host => "host".into(),
            Target::Vm(n) => format!("vm:{n}"),
        }
    }
}

pub(crate) fn target(c: &Ctx, p: &Value) -> Result<Target, (i64, String)> {
    match s(p, "target") {
        None | Some("host") => Ok(Target::Host),
        Some(t) => {
            let n = t.strip_prefix("vm:").ok_or_else(|| (-32602, format!("target `{t}`: use \"host\" or \"vm:<name>\"")))?;
            seagent_vm::desktop::valid_name(n).map_err(|e| (-32602, e))?;
            if !c.vms.cfg.enabled {
                return Err((-32001, "desktop VMs are disabled ([desktop_vm] enabled = false)".into()));
            }
            Ok(Target::Vm(n.to_string()))
        }
    }
}

/// Where a target's control lease lives (`<home>/bot-desktop/lease.json`).
fn lease_home(c: &Ctx, t: &Target) -> std::path::PathBuf {
    match t {
        Target::Host => c.home.to_path_buf(),
        Target::Vm(n) => c.vms.lease_home(n),
    }
}

fn desktop_png(c: &Ctx, t: &Target) -> Result<Vec<u8>, (i64, String)> {
    match t {
        Target::Host => crate::computer::screenshot_png(c.home).map_err(|e| (-32000, e)),
        Target::Vm(n) if !c.vms.is_running(n) => Err((-32001, format!("desktop VM `{n}` is not running (view.vm.start)"))),
        Target::Vm(n) => c.vms.screenshot(n).map_err(|e| (-32000, e)),
    }
}

fn desktop_state(c: &Ctx, t: &Target, p: &Value) -> Value {
    let home = lease_home(c, t);
    let mut v = json!({"target": t.id(), "lease": lease::public_view(&home)});
    match t {
        Target::Host => v["botDesktop"] = c.home.join("bot-desktop").exists().into(),
        Target::Vm(n) => v["running"] = c.vms.is_running(n).into(),
    }
    if let Ok(id) = viewer(p) {
        v["viewerHolds"] = lease::viewer_may_send_input(&home, id).into();
    }
    v
}

fn host_geometry(home: &Path) -> (u32, u32) {
    let g = seagent_browser::control::screen::Desktop::new(home).geometry;
    g.split_once('x').and_then(|(w, h)| Some((w.trim().parse().ok()?, h.trim().parse().ok()?))).unwrap_or((1440, 900))
}

/// `view.desktop.list`: the host first, then the desktop VMs.
fn desktop_list(c: &Ctx) -> Value {
    let (w, h) = host_geometry(c.home);
    let host_up = !seagent_browser::control::screen::Desktop::new(c.home).published_env().is_empty();
    let mut v = vec![json!({"id": "host", "kind": "host", "label": "Bot Desktop (host)", "running": host_up, "width": w, "height": h, "controller": lease::get(c.home).holder, "lease": lease::public_view(c.home)})];
    if c.vms.cfg.enabled {
        c.vms.reap();
        for st in c.vms.list() {
            let home = c.vms.lease_home(&st.name);
            v.push(json!({"id": format!("vm:{}", st.name), "kind": "vm", "label": format!("Desktop VM {}", st.name), "running": st.running, "width": st.width, "height": st.height, "controller": lease::get(&home).holder, "lease": lease::public_view(&home), "accel": st.accel, "imageBuilt": st.image_built}));
        }
    }
    Value::Array(v)
}

/// A desktop input event on the host's Bot Desktop, through xdotool / ydotool.
fn host_input(home: &Path, e: &Value) -> Result<Value, (i64, String)> {
    use seagent_vm::desktop::Input as I;
    let ev = I::from_json(e).map_err(|m| (-32602, m))?;
    let btn = |b: &str| match b {
        "right" | "3" => "right_click",
        "middle" | "2" => "middle_click",
        _ => "left_click",
    };
    let p = match &ev {
        I::Move { x, y } => json!({"action": "mouse_move", "x": x, "y": y}),
        I::Click { x, y, button, count } => json!({"action": if *count >= 2 { "double_click" } else { btn(button) }, "x": x, "y": y}),
        I::Down { x, y, .. } => json!({"action": "left_mouse_down", "x": x, "y": y}),
        I::Up { x, y, .. } => json!({"action": "left_mouse_up", "x": x, "y": y}),
        I::Scroll { x, y, dx, dy } => {
            let (dir, n) = if *dy != 0 { (if *dy > 0 { "down" } else { "up" }, dy.unsigned_abs()) } else { (if *dx > 0 { "right" } else { "left" }, dx.unsigned_abs()) };
            json!({"action": "scroll", "x": x, "y": y, "scrollDirection": dir, "scrollAmount": n.max(1)})
        }
        I::Key { keys } => json!({"action": "key", "keys": keys}),
        I::Type { text } => json!({"action": "type", "text": text}),
        I::Drag { from, to, .. } => json!({"action": "left_click_drag", "fromX": from.0, "fromY": from.1, "x": to.0, "y": to.1}),
    };
    let env = seagent_browser::control::screen::Desktop::new(home).published_env();
    use crate::computer::native;
    let t = std::time::Duration::from_secs(10);
    match native::input_tool("auto", &env) {
        Some(tool) => crate::node::with_env(&env, || native::run_steps(tool, &p, t)).map_err(|m| (-32000, m))?,
        // Windows / macOS: SendInput / CGEvent.
        None if native::os_input() => native::run_os(&p, t).map_err(|m| (-32000, m))?,
        None => return Err((-32001, native::NO_INPUT.to_string())),
    };
    Ok(json!({"ok": true, "type": ev.kind()}))
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
        "view.desktop.list" => Ok(desktop_list(c)),
        "view.desktop.state" => {
            let t = target(c, p)?;
            Ok(desktop_state(c, &t, p))
        }
        "view.desktop.frame" => {
            let t = target(c, p)?;
            desktop_png(c, &t).map(|png| json!({"mime": "image/png", "data": seagent_net::crypto::b64(&png), "target": t.id(), "lease": lease::public_view(&lease_home(c, &t))}))
        }
        "view.desktop.takeover" => {
            let id = viewer(p)?;
            let t = target(c, p)?;
            let reason: String = s(p, "reason").unwrap_or("").chars().take(200).collect();
            lease::acquire(&lease_home(c, &t), id, &reason).map_err(|e| (-32000, e))?;
            Ok(desktop_state(c, &t, p))
        }
        "view.desktop.handback" => {
            let id = viewer(p)?;
            let t = target(c, p)?;
            lease::release(&lease_home(c, &t), Some(id), false).map_err(|e| (-32000, e))?;
            Ok(desktop_state(c, &t, p))
        }
        "view.desktop.input" => {
            let id = viewer(p)?;
            let t = target(c, p)?;
            if !lease::viewer_may_send_input(&lease_home(c, &t), id) {
                return Err((-32003, format!("Take control first (view.desktop.takeover, target {}): desktop input is only accepted from the viewer holding that desktop's lease.", t.id())));
            }
            if !p["event"].is_object() {
                return Err((-32602, "event is required ({type, x, y, …})".into()));
            }
            match &t {
                Target::Host => host_input(c.home, &p["event"]),
                Target::Vm(n) => {
                    let ev = seagent_vm::desktop::Input::from_json(&p["event"]).map_err(|m| (-32602, m))?;
                    if !c.vms.is_running(n) {
                        return Err((-32001, format!("desktop VM `{n}` is not running (view.vm.start)")));
                    }
                    c.vms.input(n, &ev).map_err(|m| (-32000, m))
                }
            }
        }
        "view.vm.start" => {
            if !c.vms.cfg.enabled {
                return Err((-32001, "desktop VMs are disabled ([desktop_vm] enabled = false)".into()));
            }
            let name = s(p, "name").unwrap_or(&c.vms.cfg.default).to_string();
            seagent_vm::desktop::valid_name(&name).map_err(|e| (-32602, e))?;
            c.vms.start(&name).map(|st| serde_json::to_value(st).unwrap_or_default()).map_err(|e| (-32000, e))
        }
        "view.vm.stop" => {
            let name = s(p, "name").ok_or((-32602, "name is required".to_string()))?;
            seagent_vm::desktop::valid_name(name).map_err(|e| (-32602, e))?;
            c.vms.stop(name).map(|stopped| json!({"name": name, "stopped": stopped})).map_err(|e| (-32000, e))
        }
        "view.novnc" => {
            let key = s(p, "key").ok_or((-32602, "key is required (the sandbox browser's key from view.browser.list)".to_string()))?;
            let b = c.m.get(key).ok_or_else(|| (-32001, format!("browser `{key}` is not running")))?;
            let (port, pw) = view::novnc_target(&b).ok_or_else(|| (-32001, format!("browser `{key}` has no noVNC observer (only the sandbox browser, headed, with sandbox.novnc on)")))?;
            let now = seagent_browser::util::now_ms();
            if p["open"] == true {
                return Ok(json!({"url": view::novnc_url(port, pw.as_deref())}));
            }
            let t = view::issue_ticket(port, pw, None, now);
            Ok(json!({"ticket": t, "path": format!("/view/novnc?ticket={t}"), "expiresAtMs": now + view::NOVNC_TICKET_TTL_MS}))
        }
        m => Err((-32601, format!("unknown method {m}"))),
    }
}

pub(crate) fn with_app<T>(app: &App, f: impl FnOnce(&Ctx) -> T) -> T {
    let home = app.d.k.paths.data.clone();
    let k = &app.d.k.cfg;
    let cfg = BrowserConfig::parse(&crate::computer::browser_table(&k.browser, &k.computer_use, &k.desktop_vm)).unwrap_or_default();
    let vms = desktop_vms(app);
    f(&Ctx { home: &home, cfg: &cfg, m: manager::global(), vms: &vms })
}

/// The desktop VMs of the daemon's home (an invalid `[desktop_vm]` disables them; the config
/// validator reports why).
pub fn desktop_vms(app: &App) -> DesktopVms {
    let paths = &app.d.k.paths;
    let dcfg = DesktopConfig::parse(&app.d.k.cfg.desktop_vm).unwrap_or_else(|_| DesktopConfig { enabled: false, ..Default::default() });
    DesktopVms::new(dcfg, &paths.data, &paths.cache_dir(), &paths.runtime)
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
    let nonce = seagent_net::crypto::random_token(16);
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
        ("GET", "/view/desktop/list") => j(call(c, "view.desktop.list", &q)),
        ("GET", "/view/desktop/frame") => match target(c, &q).and_then(|t| desktop_png(c, &t)) {
            Ok(png) => no_store(Response::new(200, "image/png", png)),
            Err((code, m)) => err(code, &m),
        },
        ("POST", "/view/desktop/takeover") => j(call(c, "view.desktop.takeover", &body())),
        ("POST", "/view/desktop/handback") => j(call(c, "view.desktop.handback", &body())),
        ("POST", "/view/desktop/input") => j(call(c, "view.desktop.input", &body())),
        ("POST", "/view/vm/start") => j(call(c, "view.vm.start", &body())),
        ("POST", "/view/vm/stop") => j(call(c, "view.vm.stop", &body())),
        ("POST", "/view/novnc") => j(call(c, "view.novnc", &body())),
        // bridge-server.ts `/sandbox/novnc`: authenticated + a one-time ticket.
        ("GET", "/view/novnc") => {
            let Some(t) = s(&q, "ticket") else { return no_store(Response::text(400, "Missing ticket")) };
            match view::consume_ticket(t, seagent_browser::util::now_ms()) {
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
    use seagent_kernel::config::{Config, Paths};
    use seagent_kernel::daemon::Daemon;
    use std::sync::Arc;
    use std::time::Duration;

    struct NoRes;
    impl seagent_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn app(home: &Path) -> Arc<App> {
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = seagent_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = seagent_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(seagent_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        let cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() };
        Arc::new(App { d, cfg, token: "view-test-token".into(), host_methods: vec![], routes: vec![] })
    }

    fn get(base: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, String, String) {
        let a: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
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
        let home = seagent_core::tmp::scratch_path(format!("seagent-bview-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
        let srv = crate::server::start(app(&home)).unwrap();
        let base = format!("http://{}", srv.local_addr());
        for p in ["/view/browser", "/view/browser/frame", "/view/desktop", "/view/desktop/list", "/view/desktop/frame", "/view/novnc?ticket=x"] {
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
        let t = view::issue_ticket(45678, Some("pw123456".into()), None, seagent_browser::util::now_ms());
        let (st, ct, body) = get(&base, &format!("/view/novnc?ticket={t}"), Some("view-test-token"), None);
        assert!(st == 200 && ct.starts_with("text/html") && body.contains("http://127.0.0.1:45678/vnc.html#autoconnect=1&resize=remote&password=pw123456"), "{body}");
        assert_eq!(get(&base, &format!("/view/novnc?ticket={t}"), Some("view-test-token"), None).0, 404, "one-time");
        assert_eq!(get(&base, "/view/nothing", Some("view-test-token"), None).0, 404);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A GET that also returns the response headers (lower-case names), for the panel's CSP.
    fn get_headers(base: &str, path: &str, token: Option<&str>) -> (u16, Vec<(String, String)>, String) {
        let a: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
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
        let home = seagent_core::tmp::scratch_path(format!("seagent-bview-panel-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
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
            // Silent, endless renewal of device access tokens (the devauth.js contract, which the
            // page also loads by nonce when the host serves it), and no token left in the URL.
            for needle in ["/ui/devauth.js", "/pair/refresh", "/pair/info", "seagent-device-refresh|v1|", "seagent-devkey", "* 0.8", "60000", "history.replaceState", "sessionStorage", "seagent.token", "seagent.deviceId", "r.status === 401"] {
                assert!(body.contains(needle), "{p}: the token renewal lacks {needle}");
            }
            assert!(!body.contains("?token=\" +") && !body.contains("&token="), "{p}: no request carries the token in its URL");
            // Self-contained: every fetch is a relative /view/… path, no remote scripts or images.
            assert!(!body.contains("http://") && !body.contains("https://"), "{p} references an external resource");
            assert!(!body.contains("onclick=") && !body.contains("onload="), "{p} uses inline event handler attributes");
        }
        assert_eq!(get(&base, "/view/", None, None).0, 401, "no token");
        assert_eq!(get(&base, "/view/ui", Some("wrong"), None).0, 401, "wrong token");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    /// Desktop targets: `view.desktop.list` shape, per-target leases, `view.desktop.input` only
    /// from the lease holder, frames and input reaching the VM over (fake) QMP, start/stop.
    #[test]
    fn desktop_vm_targets_frames_input_and_leases() {
        use seagent_vm::desktop::fake;
        let d = seagent_core::tmp::TempDir::new("seagent-bview-vm");
        let vms = fake::fake_vms(&d);
        let bcfg = BrowserConfig::default();
        let home = d.join("data");
        let c = Ctx { home: &home, cfg: &bcfg, m: manager::global(), vms: &vms };
        let l = call(&c, "view.desktop.list", &json!({})).unwrap();
        let ids: Vec<&str> = l.as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["host", "vm:desk"]);
        let vm = &l[1];
        assert_eq!((vm["kind"].as_str(), vm["running"].as_bool(), vm["width"].as_u64(), vm["height"].as_u64(), vm["controller"].as_str()), (Some("vm"), Some(false), Some(1280), Some(800), Some("agent")), "{vm}");
        assert!(l[0]["label"].is_string() && l[0]["width"].is_u64() && l[0]["controller"] == "agent", "{l}");
        assert_eq!(call(&c, "view.desktop.frame", &json!({"target": "vm:desk"})).unwrap_err().0, -32001, "not running");
        assert_eq!(call(&c, "view.desktop.state", &json!({"target": "bogus"})).unwrap_err().0, -32602);
        assert_eq!(call(&c, "view.desktop.state", &json!({"target": "vm:../x"})).unwrap_err().0, -32602);
        assert_eq!(call(&c, "view.vm.stop", &json!({})).unwrap_err().0, -32602, "name is required");

        let marker = d.join("bin/spawned");
        let sock = vms.qmp_path("desk");
        let th = std::thread::spawn(move || {
            while !marker.exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            fake::FakeQmp::start(&sock, 1024, 768)
        });
        let st = call(&c, "view.vm.start", &json!({})).unwrap();
        let qmp = th.join().unwrap();
        assert_eq!((st["name"].as_str(), st["running"].as_bool()), (Some("desk"), Some(true)), "{st}");
        let f = call(&c, "view.desktop.frame", &json!({"target": "vm:desk"})).unwrap();
        assert_eq!((f["mime"].as_str(), f["target"].as_str()), (Some("image/png"), Some("vm:desk")));
        let png = seagent_net::crypto::b64_decode(f["data"].as_str().unwrap()).unwrap();
        assert_eq!(seagent_vm::desktop::qmp::png_size(&png), Some((1024, 768)));
        let l = call(&c, "view.desktop.list", &json!({})).unwrap();
        assert_eq!((l[1]["running"].as_bool(), l[1]["width"].as_u64()), (Some(true), Some(1024)), "the live framebuffer size");

        // Input needs the VM's lease; the host lease is separate.
        let click = json!({"viewer": "viewer-vm-01", "target": "vm:desk", "event": {"type": "click", "x": 512, "y": 384}});
        assert_eq!(call(&c, "view.desktop.input", &click).unwrap_err().0, -32003);
        let s = call(&c, "view.desktop.takeover", &json!({"viewer": "viewer-vm-01", "target": "vm:desk", "reason": "login"})).unwrap();
        assert_eq!((s["target"].as_str(), s["lease"]["holder"].as_str(), s["viewerHolds"].as_bool()), (Some("vm:desk"), Some("human"), Some(true)), "{s}");
        assert_eq!(call(&c, "view.desktop.state", &json!({})).unwrap()["lease"]["holder"], "agent", "host lease untouched");
        assert_eq!(call(&c, "view.desktop.list", &json!({})).unwrap()[1]["controller"], "human");
        let other = json!({"viewer": "viewer-vm-02", "target": "vm:desk", "event": {"type": "key", "key": "Enter"}});
        assert_eq!(call(&c, "view.desktop.input", &other).unwrap_err().0, -32003, "only the holder");
        let r = call(&c, "view.desktop.input", &click).unwrap();
        assert_eq!((r["ok"].as_bool(), r["type"].as_str()), (Some(true), Some("click")));
        let r = call(&c, "view.desktop.input", &json!({"viewer": "viewer-vm-01", "target": "vm:desk", "event": {"type": "type", "text": "hello"}})).unwrap();
        assert_eq!(r["typed"], 5);
        assert_eq!(call(&c, "view.desktop.input", &json!({"viewer": "viewer-vm-01", "target": "vm:desk", "event": {"type": "warp"}})).unwrap_err().0, -32602);
        assert_eq!(call(&c, "view.desktop.input", &json!({"viewer": "viewer-vm-01", "target": "vm:desk"})).unwrap_err().0, -32602);
        let ev = qmp.events();
        assert!(ev.iter().any(|e| e["data"]["button"] == "left" && e["data"]["down"] == true), "{ev:?}");
        assert!(ev.iter().any(|e| e["type"] == "key" && e["data"]["key"]["data"] == "h"));
        call(&c, "view.desktop.handback", &json!({"viewer": "viewer-vm-01", "target": "vm:desk"})).unwrap();
        assert_eq!(call(&c, "view.desktop.input", &click).unwrap_err().0, -32003, "handed back");
        let s = call(&c, "view.vm.stop", &json!({"name": "desk"})).unwrap();
        assert_eq!(s, json!({"name": "desk", "stopped": true}));
        assert!(qmp.commands().contains(&"system_powerdown".to_string()));
        drop(qmp);
    }

    /// Real desktop VM through the RPC layer (not run by default): `SEAGENT_REAL_DVM_HOME=<seagent home
    /// with a built image> SEAGENT_REAL_DVM_OUT=<dir> cargo test -p seagent-app real_desktop_vm -- --ignored`.
    /// Starts `desk`, takes the lease, clicks Chromium's address bar, types a URL and saves
    /// before/after frames.
    #[test]
    #[ignore]
    fn real_desktop_vm_over_rpc() {
        let root = std::path::PathBuf::from(std::env::var("SEAGENT_REAL_DVM_HOME").expect("SEAGENT_REAL_DVM_HOME"));
        let out = std::path::PathBuf::from(std::env::var("SEAGENT_REAL_DVM_OUT").expect("SEAGENT_REAL_DVM_OUT"));
        let vms = DesktopVms::new(DesktopConfig::default(), &root.join("data"), &root.join("cache"), &root.join("run"));
        let bcfg = BrowserConfig::default();
        let home = root.join("data");
        let c = Ctx { home: &home, cfg: &bcfg, m: manager::global(), vms: &vms };
        call(&c, "view.vm.start", &json!({"name": "desk"})).unwrap();
        let list = call(&c, "view.desktop.list", &json!({})).unwrap();
        std::fs::write(out.join("rpc-desktop-list.json"), serde_json::to_string_pretty(&list).unwrap()).unwrap();
        let save = |name: &str| {
            let f = call(&c, "view.desktop.frame", &json!({"target": "vm:desk"})).unwrap();
            std::fs::write(out.join(name), seagent_net::crypto::b64_decode(f["data"].as_str().unwrap()).unwrap()).unwrap();
        };
        save("rpc-01-before.png");
        let v = |e: Value| json!({"viewer": "proof-viewer-1", "target": "vm:desk", "event": e});
        assert_eq!(call(&c, "view.desktop.input", &v(json!({"type": "click", "x": 600, "y": 90}))).unwrap_err().0, -32003, "no lease yet");
        call(&c, "view.desktop.takeover", &json!({"viewer": "proof-viewer-1", "target": "vm:desk", "reason": "proof"})).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "click", "x": 600, "y": 90}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "key", "key": "Control+a"}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "type", "text": "data:text/html,<h1 style='font-size:64px'>Hello from seagent RPC</h1>"}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "key", "key": "Enter"}))).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        save("rpc-02-after.png");
        // CJK: a page with Traditional Chinese (fonts) and a textarea typed into over the text channel.
        call(&c, "view.desktop.input", &v(json!({"type": "click", "x": 600, "y": 90}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "key", "key": "Control+a"}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "type", "text": "data:text/html;charset=utf-8,<h1 style='font-size:48px'>%E7%B9%81%E9%AB%94%E4%B8%AD%E6%96%87 CJK</h1><textarea autofocus style='font-size:40px;width:90%;height:200px'></textarea>"}))).unwrap();
        call(&c, "view.desktop.input", &v(json!({"type": "key", "key": "Enter"}))).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        call(&c, "view.desktop.input", &v(json!({"type": "click", "x": 640, "y": 300}))).unwrap();
        let r = call(&c, "view.desktop.input", &v(json!({"type": "type", "text": "你好，這是 seagent 輸入的繁體中文。"}))).unwrap();
        assert_eq!(r["via"], "text-channel", "{r}");
        std::thread::sleep(Duration::from_secs(4));
        save("rpc-03-cjk.png");
        call(&c, "view.desktop.handback", &json!({"viewer": "proof-viewer-1", "target": "vm:desk"})).unwrap();
    }

    #[test]
    fn arp_methods_are_advertised_and_dispatched() {
        let home = seagent_core::tmp::scratch_path(format!("seagent-bview-arp-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
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
