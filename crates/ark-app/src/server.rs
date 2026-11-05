//! The app server: HTTP listener in front of the daemon.
//!
//! - `GET /` and `/ui/*`: the web UI (also installable as a desktop/mobile PWA).
//! - `GET /arp` (WebSocket): ARP, the same JSON-RPC 2.0 protocol the unix socket speaks,
//!   with concurrent requests and live subscriptions on one connection.
//! - `POST /arp`: one ARP request per HTTP call (scripts, curl).
//! - `/v1/models`, `/v1/chat/completions`, `/v1/responses`: OpenAI-compatible API (`openai_api`, off by default).
//! - `/a2a/v1` + `/.well-known/agent-card.json`: Agent2Agent (see `a2a`).
//! - `/plugins/<name>/…`: HTTP routes registered by plugins (see [`mount`]), proxied to the
//!   plugin process; routes the plugin marks public skip the token (they verify themselves).
//! - `/view/…`: browser / desktop live view for the UI (see `browser_view`).
//! - `GET /health`.
//!
//! Every route except the UI shell, health and the agent card needs a credential
//! (`Authorization: Bearer`, the `ark.token.<t>` subprotocol, or `?token=` on a WebSocket
//! upgrade — never on a plain HTTP request), and the scope it needs depends on what it does
//! (see [`crate::exposure`]). A token in the URL is refused everywhere else, a foreign
//! `Origin` is refused on every state-changing request, and `POST /arp` must say
//! `content-type: application/json`.

use crate::exposure::{self, Scope};
use crate::{a2a, openai, ui, AppConfig};
use ark_kernel::daemon::Daemon;
use ark_net::httpd::{self, Request, Response};
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const ARP_VERSION: &str = "ark/2";

/// Something mounted at `/plugins/<name>/` (a plugin's HTTP routes).
pub trait Mount: Send + Sync {
    /// `None`: no route for this method + sub-path; `Some(public)`: served, `public` skips the app token.
    fn route(&self, method: &str, sub: &str) -> Option<bool>;
    fn serve(&self, r: &Request, sub: &str) -> Response;
}

static MOUNTS: RwLock<Vec<(String, Arc<dyn Mount>)>> = RwLock::new(Vec::new());

/// Mount `m` at `/plugins/<name>/` (replacing an earlier mount of that name).
pub fn mount(name: &str, m: Arc<dyn Mount>) {
    let mut all = MOUNTS.write().unwrap();
    all.retain(|(n, _)| n != name);
    all.push((name.to_string(), m));
}

pub fn mounts() -> Vec<String> {
    MOUNTS.read().unwrap().iter().map(|(n, _)| n.clone()).collect()
}

pub struct App {
    pub d: Arc<Daemon>,
    pub cfg: AppConfig,
    pub token: String,
    /// Extra method names hosts registered (shown in `initialize`).
    pub host_methods: Vec<String>,
    /// Host routes by path prefix, served before the token check: they authenticate
    /// themselves (MCP event webhooks verify Standard Webhooks signatures).
    pub routes: Vec<(String, httpd::Handler)>,
}

impl App {
    /// Which scope the request's credential carries, if it presents one.
    ///
    /// A token may come from `Authorization: Bearer`, the `ark.token.<t>` subprotocol, or —
    /// **only on a WebSocket upgrade whose Origin is ours** — `?token=`: a URL leaks into
    /// history, `Referer` headers, proxy logs and screenshots, so a plain HTTP request has to
    /// put the token in a header (A11, the OpenClaw CVE-2026-25253 shape).
    pub fn credential(&self, r: &Request) -> Option<Scope> {
        // A dashboard login session is the owner in person: admin.
        if self.cfg.auth.enabled && crate::dashboard_auth::session_from(self, r).is_some() {
            return Some(Scope::Admin);
        }
        let subproto = r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find_map(|x| x.strip_prefix("ark.token.")).map(str::to_string));
        let from_query = if r.is_upgrade() && self.origin_ok(r) { r.query("token").map(str::to_string) } else { None };
        let given = r.bearer().map(str::to_string).or(subproto).or(from_query)?;
        self.scope_of(&given)
    }

    /// Constant-time token → scope lookup; the single `[app] token` is admin. `{{secret:NAME}}`
    /// references are resolved exactly like the daemon resolves `token`; an unresolvable one
    /// never matches anything.
    fn scope_of(&self, given: &str) -> Option<Scope> {
        let mut found = None;
        if !self.token.trim().is_empty() && ark_net::crypto::ct_eq(given.as_bytes(), self.token.as_bytes()) {
            found = Some(Scope::Admin);
        }
        if !self.cfg.tokens.is_empty() {
            let subst = self.d.k.vault_substitute();
            for t in &self.cfg.tokens {
                let value = subst(&t.token);
                if value.is_empty() || value.contains("{{secret:") {
                    continue; // an unresolved reference is not a credential
                }
                if ark_net::crypto::ct_eq(given.as_bytes(), value.as_bytes()) {
                    found = Some(Scope::parse(&t.scope).unwrap_or(Scope::Admin));
                }
            }
        }
        found
    }

    /// The request carries *a* credential (any scope).
    pub fn authorized(&self, r: &Request) -> bool {
        self.credential(r).is_some()
    }

    /// Browsers send Origin on WebSocket upgrades: only our own page (or listed origins) may connect.
    fn origin_ok(&self, r: &Request) -> bool {
        match r.header("origin") {
            None => true,
            Some(o) => exposure::origin_allowed(o, r.header("host").unwrap_or(""), &self.cfg.allow_origins),
        }
    }

    pub fn capabilities(&self) -> Value {
        let mut methods: Vec<String> = Daemon::METHODS.iter().map(|s| s.to_string()).collect();
        methods.extend(self.host_methods.iter().cloned());
        methods.extend(crate::browser_view::METHODS.iter().map(|s| s.to_string()));
        methods.extend(["initialize", "subscribe", "unsubscribe"].map(String::from));
        json!({
            "protocol": ARP_VERSION,
            "server": {"name": "ark", "version": env!("CARGO_PKG_VERSION")},
            "methods": methods,
            "events": ["event", "delta", "pending", "heartbeat"],
            "features": {"openai": self.cfg.openai_api, "a2a": self.cfg.a2a.enabled, "nodes": self.cfg.nodes, "ui": self.cfg.ui},
        })
    }

    fn handle(self: &Arc<Self>, r: Request) -> Response {
        let path = r.path.clone();
        if let Some((_, h)) = self.routes.iter().find(|(pre, _)| path.starts_with(pre.as_str())) {
            return h(r);
        }
        // A page on another site must not be able to make this server *do* anything (A11):
        // every state-changing request has to come from our own page or a listed origin.
        if r.method != "GET" && r.method != "HEAD" && !self.origin_ok(&r) {
            return Response::json(403, &json!({"error": "forbidden: cross-origin request (Origin not allowed)"}).to_string());
        }
        if !crate::exposure::rate_ok(&self.cfg.exposure, r.peer) {
            return Response::json(429, &json!({"error": "too many requests"}).to_string()).with_header("retry-after", "60");
        }
        // A page on another site must not even learn whether a credential is present.
        if r.path == "/arp" && r.is_upgrade() && !self.origin_ok(&r) {
            return Response::text(403, "origin not allowed");
        }
        match (r.method.as_str(), path.as_str()) {
            ("GET", "/health") => Response::json(200, &json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}).to_string()),
            ("GET", p) if self.cfg.ui && (p == "/" || p.starts_with("/ui/") || p == "/manifest.webmanifest" || p == "/sw.js") => ui::serve(p),
            ("GET", "/.well-known/agent-card.json") | ("GET", "/.well-known/agent.json") if self.cfg.a2a.enabled => a2a::card(self, &r),
            // Devices prove themselves with an Ed25519 key and operator-approved pairing.
            (_, p) if p.starts_with("/node") && self.cfg.nodes && r.is_upgrade() => {
                let me = self.clone();
                Response::upgrade(Box::new(move |s, head, rest| crate::node::session(&me, s, &head, rest)))
            }
            (_, p) if p.starts_with("/plugins/") => self.plugin_route(&r),
            // A2A authenticates its own peers (per-peer tokens) before anything else.
            (_, p) if p.starts_with("/a2a") && self.cfg.a2a.enabled => a2a::handle(self, r),
            (_, p) if p.starts_with("/auth/") && self.cfg.auth.enabled => crate::dashboard_auth::handle(self, &r),
            // Everything below needs a credential; how much depends on what is asked for.
            _ => match self.credential(&r) {
                Some(scope) => self.routed(r, scope),
                None => Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer"),
            },
        }
    }

    /// The routes behind a credential, with the scope each one needs (A10).
    fn routed(self: &Arc<Self>, r: Request, scope: Scope) -> Response {
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/arp") if r.is_upgrade() => {
                if !self.origin_ok(&r) {
                    return Response::text(403, "origin not allowed");
                }
                let me = self.clone();
                let proto = r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find(|x| x.starts_with("ark.token.") || *x == "arp").map(str::to_string));
                // Subscriptions are reads; every request inside the socket is checked on its own.
                Response::upgrade(Box::new(move |s, head, rest| me.ws_session(s, &head, rest, proto, scope)))
            }
            (_, p) if p.starts_with("/view/") => {
                let need = exposure::required_scope_http(&r.method, p);
                if !scope.allows(need) {
                    return forbidden(need, scope, "the live view");
                }
                crate::browser_view::handle(self, &r)
            }
            ("POST", "/arp") => {
                // A cross-site HTML form can post a `<form>` body without asking the browser
                // anything; JSON-only means the caller had to opt in (and needs CORS).
                if !exposure::is_json_content_type(r.header("content-type")) {
                    return Response::json(415, &json!({"error": "POST /arp needs `content-type: application/json`"}).to_string());
                }
                let req: Value = match serde_json::from_slice(&r.body) {
                    Ok(v) => v,
                    Err(e) => return Response::json(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}}).to_string()),
                };
                let method = req["method"].as_str().unwrap_or("");
                let need = exposure::required_scope(method);
                if !scope.allows(need) {
                    return forbidden(need, scope, method);
                }
                Response::json(200, &self.rpc(&req).to_string())
            }
            (_, p) if p.starts_with("/v1/") && self.cfg.openai_api => {
                let need = exposure::required_scope_http(&r.method, p);
                if !scope.allows(need) {
                    return forbidden(need, scope, "the OpenAI-compatible API");
                }
                openai::handle(self, r)
            }
            _ => Response::json(404, &json!({"error": "not found"}).to_string()),
        }
    }

    fn plugin_route(&self, r: &Request) -> Response {
        let rest = &r.path["/plugins/".len()..];
        let (name, sub) = rest.split_once('/').map(|(n, s)| (n, format!("/{s}"))).unwrap_or((rest, "/".into()));
        let m = MOUNTS.read().unwrap().iter().find(|(n, _)| n == name).map(|(_, m)| m.clone());
        let Some(m) = m else { return Response::json(404, &json!({"error": "no such plugin route"}).to_string()) };
        match m.route(&r.method, &sub) {
            None => Response::json(404, &json!({"error": "no such plugin route"}).to_string()),
            // A plugin route that is not public needs the same scope a built-in route of that
            // shape would: reads for GET, writes for anything else.
            Some(public) if !public => {
                let need = exposure::required_scope_http(&r.method, &r.path);
                match self.credential(r) {
                    None => Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer"),
                    Some(scope) if !scope.allows(need) => forbidden(need, scope, "this plugin route"),
                    Some(_) => m.serve(r, &sub).with_header("content-security-policy", "sandbox").with_header("x-content-type-options", "nosniff"),
                }
            }
            // Plugin pages share our origin: sandbox them so they cannot read the UI's token.
            Some(_) => m.serve(r, &sub).with_header("content-security-policy", "sandbox").with_header("x-content-type-options", "nosniff"),
        }
    }

    /// Where sessions created through the app server run: `[app] workspace`, else the daemon's directory.
    pub fn default_workspace(&self) -> std::path::PathBuf {
        self.cfg.workspace.clone().map(std::path::PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/")))
    }

    /// One JSON-RPC request → response (no streaming methods).
    pub fn rpc(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req["method"].as_str().unwrap_or("");
        let mut params = req.get("params").cloned().unwrap_or(json!({}));
        // Remote clients rarely know a good directory on this machine: use `[app] workspace`.
        if method == "session.create" && params["workspace"].as_str().is_none_or(|w| w.trim().is_empty()) {
            params["workspace"] = self.default_workspace().display().to_string().into();
        }
        let r = match method {
            "initialize" => Ok(self.capabilities()),
            "session.attach" | "events.subscribe" | "subscribe" => Err((-32601, "streaming methods need the WebSocket endpoint (GET /arp)".to_string())),
            m if m.starts_with("view.") => crate::browser_view::rpc(self, m, &params).map_err(|(c, e)| (c as i32, e)),
            m => self.d.call(m, &params),
        };
        match r {
            Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
            Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        }
    }

    /// ARP over WebSocket: one thread owns the socket; requests run on workers,
    /// subscriptions on their own threads; everything outbound funnels through `out`.
    fn ws_session(self: Arc<Self>, s: TcpStream, head: &str, rest: Vec<u8>, proto: Option<String>, scope: Scope) {
        let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
        let accepted = match &proto {
            // Echo the chosen subprotocol so browsers accept the upgrade.
            Some(p) => accept_with_protocol(s, head, rest, p),
            None => WebSocket::accept(s, head, rest),
        };
        let Ok(mut ws) = accepted else { return };
        ws.set_max_message(8 * 1024 * 1024);
        let (out_tx, out_rx) = mpsc::channel::<Value>();
        let closed = Arc::new(AtomicBool::new(false));
        let mut subs: Vec<(Value, Arc<AtomicBool>)> = Vec::new();
        let _ = out_tx.send(json!({"jsonrpc": "2.0", "method": "ready", "params": self.capabilities()}));
        loop {
            for m in out_rx.try_iter() {
                if ws.send_text(&m.to_string()).is_err() {
                    closed.store(true, Ordering::SeqCst);
                }
            }
            if closed.load(Ordering::SeqCst) {
                break;
            }
            let msg = match ws.recv() {
                Ok(None) => continue,
                Ok(Some(Message::Text(t))) => t,
                Ok(Some(Message::Close(_))) | Err(_) => break,
                Ok(Some(_)) => continue,
            };
            let req: Value = match serde_json::from_str(&msg) {
                Ok(v) => v,
                Err(e) => {
                    let _ = out_tx.send(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}}));
                    continue;
                }
            };
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let method_name = req["method"].as_str().unwrap_or("");
            // The socket carries the credential of the upgrade; each request still has to fit
            // what that scope may do (a `read` token cannot answer a gate or start a turn).
            let need = exposure::required_scope(method_name);
            if !scope.allows(need) {
                let msg = format!("forbidden: this token has scope `{}`; `{method_name}` needs `{}`", scope.as_str(), need.as_str());
                let _ = out_tx.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32003, "message": msg}}));
                continue;
            }
            match method_name {
                "subscribe" | "events.subscribe" | "session.attach" => {
                    let stop = Arc::new(AtomicBool::new(false));
                    subs.push((id.clone(), stop.clone()));
                    let (me, tx, cl) = (self.clone(), out_tx.clone(), closed.clone());
                    // `subscribe` with a session id replays that session's log first, like `session.attach`.
                    let method = if req["method"] == "session.attach" || (req["method"] == "subscribe" && req["params"].get("id").is_some()) { "session.attach" } else { "events.subscribe" };
                    let params = req.get("params").cloned().unwrap_or(json!({}));
                    std::thread::spawn(move || {
                        let mut sink = |v: &Value| -> std::io::Result<()> {
                            // Tag stream messages with the subscription id so clients can demultiplex.
                            let mut v = v.clone();
                            if v.get("method").is_some() {
                                v["params"]["subscription"] = id.clone();
                            }
                            tx.send(v).map_err(|_| std::io::Error::other("closed"))
                        };
                        me.d.stream_to(&mut sink, id.clone(), method, &params, &|| stop.load(Ordering::SeqCst) || cl.load(Ordering::SeqCst));
                    });
                }
                "unsubscribe" => {
                    let target = req["params"]["subscription"].clone();
                    for (sid, stop) in &subs {
                        if *sid == target {
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                    let _ = out_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}}));
                }
                _ => {
                    let (me, tx) = (self.clone(), out_tx.clone());
                    std::thread::spawn(move || {
                        let _ = tx.send(me.rpc(&req));
                    });
                }
            }
        }
        closed.store(true, Ordering::SeqCst);
        for (_, s) in subs {
            s.store(true, Ordering::SeqCst);
        }
    }
}

/// 403 that names the required scope (A10).
fn forbidden(need: Scope, have: Scope, what: &str) -> Response {
    Response::json(403, &json!({"error": format!("forbidden: this token has scope `{}`; `{what}` needs `{}`", have.as_str(), need.as_str())}).to_string())
}

fn accept_with_protocol(mut s: TcpStream, head: &str, rest: Vec<u8>, proto: &str) -> std::io::Result<WebSocket<TcpStream>> {
    use std::io::Write;
    let key = ark_net::ws::header(head, "sec-websocket-key").ok_or_else(|| std::io::Error::other("missing key"))?;
    write!(s, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n", ark_net::ws::accept_key(key))?;
    s.flush()?;
    // Bytes that arrived with the upgrade request belong to the first frame.
    Ok(WebSocket::from_stream(s, false).with_leftover(rest))
}

/// Start the HTTP listener. The returned server stops when dropped.
pub fn start(app: Arc<App>) -> Result<httpd::Server, String> {
    if app.token.trim().is_empty() {
        return Err("[app] needs a token (`ark secrets set APP_TOKEN …` and `token = \"{{secret:APP_TOKEN}}\"`)".into());
    }
    // A8/A9: refusing here means a misconfigured public bind never listens, not even briefly.
    crate::exposure::check_start(&app.cfg).map_err(|e| format!("app server: {e}"))?;
    let a = app.clone();
    let h: httpd::Handler = Arc::new(move |r| a.handle(r));
    let opts = httpd::Opts { max_body: 16 * 1024 * 1024, max_conns: app.cfg.max_conns, read_timeout: Duration::from_secs(30) };
    httpd::Server::bind(&app.cfg.listen, opts, h).map_err(|e| format!("app server: cannot listen on {}: {e}", app.cfg.listen))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard_auth::AuthConfig;
    use ark_kernel::config::{Config, Paths};
    use ark_net::httpd::Body;
    use ark_net::parse_query;
    use std::sync::Arc;

    struct NoRes;
    impl ark_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn app(cfg: AppConfig) -> Arc<App> {
        app_with(cfg, ark_kernel::vault::Vault::empty())
    }

    fn app_with(cfg: AppConfig, vault: ark_kernel::vault::Vault) -> Arc<App> {
        let home = std::env::temp_dir().join(format!("ark-app-srv-{}", ark_kernel::util::random_hex(8)));
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run") };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(vault), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        Arc::new(App { d, cfg, token: "admin-token".into(), host_methods: vec![], routes: vec![] })
    }

    fn default_app() -> Arc<App> {
        app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), openai_api: true, ..AppConfig::default() })
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn req(method: &str, target: &str, hs: &[(&str, &str)], body: &str) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request { method: method.into(), path: path.into(), query: parse_query(q), raw_query: q.into(), headers: headers(hs), body: body.as_bytes().to_vec(), peer: None, head: String::new() }
    }

    fn json_req(target: &str, hs: &[(&str, &str)], body: &str) -> Request {
        let mut hs = hs.to_vec();
        hs.push(("content-type", "application/json"));
        req("POST", target, &hs, body)
    }

    fn upgrade_req(target: &str, hs: &[(&str, &str)]) -> Request {
        let mut hs = hs.to_vec();
        hs.extend([("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="), ("sec-websocket-version", "13")]);
        req("GET", target, &hs, "")
    }

    fn body_text(r: &Response) -> String {
        match &r.body {
            Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        }
    }

    fn rpc(method: &str) -> String {
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string()
    }

    /// A11 / H7: the OpenClaw CVE-2026-25253 shape — an evil page with a stolen token in the
    /// URL must not be able to open the WebSocket or post to /arp, while the same-origin page
    /// keeps working.
    #[test]
    fn cross_origin_and_url_tokens_are_refused_a11() {
        let a = default_app();
        let evil = [("origin", "https://evil.example"), ("host", "box.lan:8640")];
        let ws = a.clone().handle(upgrade_req("/arp?token=admin-token", &evil));
        assert_eq!(ws.status, 403, "cross-site WS upgrade with ?token= must be refused");

        let post = a.clone().handle(json_req("/arp?token=admin-token", &evil, &rpc("session.list")));
        assert_eq!(post.status, 403, "cross-site POST /arp must be refused even with a good token");
        assert!(body_text(&post).contains("cross-origin"), "{}", body_text(&post));

        // A plain HTTP request never takes the token from the URL (it leaks into logs/history).
        let no_origin_url_token = a.clone().handle(json_req("/arp?token=admin-token", &[], &rpc("session.list")));
        assert_eq!(no_origin_url_token.status, 401, "{}", body_text(&no_origin_url_token));
        // Nothing in the rejection echoes the token back (it would land in a log or a screenshot).
        for r in [&post, &no_origin_url_token, &ws] {
            assert!(!body_text(r).contains("admin-token"), "{}", body_text(r));
        }

        // The UI's own page: same origin, query token on the WS upgrade is fine.
        let own = [("origin", "http://box.lan:8640"), ("host", "box.lan:8640")];
        let ws = a.clone().handle(upgrade_req("/arp?token=admin-token", &own));
        assert_eq!(ws.status, 101, "same-origin WS must upgrade: {}", body_text(&ws));

        // Same-origin HTTP works with a header token.
        let own_auth = [("origin", "http://box.lan:8640"), ("host", "box.lan:8640"), ("authorization", "Bearer admin-token")];
        let ok = a.clone().handle(json_req("/arp", &own_auth, &rpc("session.list")));
        assert_eq!(ok.status, 200, "{}", body_text(&ok));
        assert!(body_text(&ok).contains("\"result\""), "{}", body_text(&ok));

        // The subprotocol token the web UI itself uses still works.
        let proto = [("sec-websocket-protocol", "arp, ark.token.admin-token")];
        assert_eq!(a.clone().handle(upgrade_req("/arp", &proto)).status, 101);
        // ... and a wrong one gets nowhere.
        let proto = [("sec-websocket-protocol", "arp, ark.token.nope")];
        assert_eq!(a.clone().handle(upgrade_req("/arp", &proto)).status, 401);
    }

    /// A11: JSON-only POST bodies (a cross-site `<form>` cannot send one) and a real CSP on
    /// everything the UI serves.
    #[test]
    fn post_needs_json_and_ui_has_a_real_csp_a11() {
        let a = default_app();
        let form = req("POST", "/arp", &[("authorization", "Bearer admin-token"), ("content-type", "application/x-www-form-urlencoded")], "a=b");
        let r = a.clone().handle(form);
        assert_eq!(r.status, 415, "{}", body_text(&r));
        let text = req("POST", "/arp", &[("authorization", "Bearer admin-token"), ("content-type", "text/plain")], &rpc("ping"));
        assert_eq!(a.clone().handle(text).status, 415);

        for path in ["/", "/ui/app.js", "/sw.js"] {
            let r = a.clone().handle(req("GET", path, &[], ""));
            assert_eq!(r.status, 200, "{path}");
            let csp = r.headers.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap_or_default();
            assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'") && csp.contains("base-uri 'none'"), "{path}: {csp}");
            assert_ne!(csp.trim(), "sandbox", "{path} must not fall back to the plugin sandbox policy");
            assert!(r.headers.iter().any(|(k, v)| k == "x-content-type-options" && v == "nosniff"), "{path}");
        }
    }

    /// A10: read < write < approve < admin, enforced per method and per route.
    #[test]
    fn scoped_tokens_limit_what_a_route_can_do_a10() {
        let cfg = AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            openai_api: true,
            tokens: vec![
                crate::exposure::TokenConfig { token: "read-token".into(), scope: "read".into(), name: Some("status".into()) },
                crate::exposure::TokenConfig { token: "write-token".into(), scope: "write".into(), name: None },
                crate::exposure::TokenConfig { token: "approve-token".into(), scope: "approve".into(), name: None },
            ],
            // Never the real cwd: a `session.create` here must not touch the repo.
            workspace: Some(std::env::temp_dir().join(format!("ark-app-ws-{}", ark_kernel::util::random_hex(8))).display().to_string()),
            ..AppConfig::default()
        };
        let a = app(cfg);
        let call = |tok: &str, method: &str| {
            let auth = format!("Bearer {tok}");
            a.clone().handle(json_req("/arp", &[("authorization", &auth)], &rpc(method)))
        };

        // read: reads pass, everything that changes state needs more.
        assert_eq!(call("read-token", "session.list").status, 200);
        assert_eq!(call("read-token", "initialize").status, 200);
        let r = call("read-token", "session.submit");
        assert_eq!(r.status, 403);
        assert!(body_text(&r).contains("needs `write`") && body_text(&r).contains("scope `read`"), "{}", body_text(&r));
        let r = call("read-token", "gate.answer");
        assert_eq!(r.status, 403);
        assert!(body_text(&r).contains("needs `approve`"), "{}", body_text(&r));
        let r = call("read-token", "config.set");
        assert_eq!(r.status, 403);
        assert!(body_text(&r).contains("needs `admin`"), "{}", body_text(&r));

        // write: may start turns, may not approve or reconfigure.
        assert_eq!(call("write-token", "session.create").status, 200);
        assert!(body_text(&call("write-token", "gate.answer")).contains("needs `approve`"));
        assert!(body_text(&call("write-token", "plugin.install")).contains("needs `admin`"));

        // approve: answering a gate is allowed; admin work still is not.
        assert!(call("approve-token", "gate.answer").status != 403, "approve may answer gates");
        assert!(body_text(&call("approve-token", "config.set")).contains("needs `admin`"));

        // admin: the legacy single token keeps full access (backwards compatible).
        assert!(call("admin-token", "config.set").status != 403, "{}", body_text(&call("admin-token", "config.set")));

        // HTTP routes carry the same ladder.
        let auth = [("authorization", "Bearer read-token")];
        assert_eq!(a.clone().handle(req("GET", "/v1/models", &auth, "")).status, 200);
        let r = a.clone().handle(json_req("/v1/chat/completions", &auth, "{}"));
        assert_eq!(r.status, 403, "{}", body_text(&r));
        assert!(body_text(&r).contains("needs `write`"), "{}", body_text(&r));
        assert_eq!(a.clone().handle(req("GET", "/v1/models", &[("authorization", "Bearer nope")], "")).status, 401);
    }

    /// A10: a disabled feature registers no route at all.
    #[test]
    fn disabled_endpoints_register_no_routes_a10() {
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), openai_api: false, ui: false, ..AppConfig::default() });
        let auth = [("authorization", "Bearer admin-token")];
        assert_eq!(a.clone().handle(json_req("/v1/chat/completions", &auth, "{}")).status, 404);
        assert_eq!(a.clone().handle(req("GET", "/v1/models", &auth, "")).status, 404);
        assert_eq!(a.clone().handle(req("GET", "/", &auth, "")).status, 404);
        assert_eq!(a.clone().handle(req("GET", "/ui/app.js", &auth, "")).status, 404);
        // a2a and nodes are off by default too.
        assert_eq!(a.clone().handle(req("GET", "/.well-known/agent-card.json", &auth, "")).status, 404);
        let node = upgrade_req("/node", &auth);
        assert_eq!(a.clone().handle(node).status, 404);
        assert!(a.capabilities()["features"]["openai"] == json!(false));

        // With the flag on, the same route exists (proof it is the flag, not the token).
        let on = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), openai_api: true, ..AppConfig::default() });
        assert_eq!(on.clone().handle(req("GET", "/v1/models", &auth, "")).status, 200);
    }

    /// A8/A9: a public bind is refused before the socket exists, and the error names the fixes.
    #[test]
    fn start_refuses_a_public_bind_without_the_layers_a8_a9() {
        let bare = app(AppConfig { enabled: true, listen: "0.0.0.0:0".into(), ..AppConfig::default() });
        let err = match start(bare) {
            Ok(_) => panic!("a public bind without the layers must be refused"),
            Err(e) => e,
        };
        for key in ["not loopback", "allow_public", "behind_proxy", "app.auth", "allow_origins"] {
            assert!(err.contains(key), "{key} missing from {err}");
        }
        // ... and the rate limit is one of the layers too, once it is turned off.
        let no_limit = app(AppConfig { enabled: true, listen: "0.0.0.0:0".into(), exposure: crate::exposure::ExposureConfig { rate_limit_per_min: 0, ..Default::default() }, ..AppConfig::default() });
        let err = match start(no_limit) {
            Ok(_) => panic!("no rate limit on a public bind must be refused"),
            Err(e) => e,
        };
        assert!(err.contains("rate_limit_per_min"), "{err}");
        // Loopback binds still start (and we drop the listener immediately).
        let ok = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() });
        let srv = start(ok).unwrap();
        assert!(srv.local_addr().ip().is_loopback());
    }

    /// A10: a scoped token written as `{{secret:NAME}}` resolves through the vault, exactly
    /// like `[app] token`; an unresolvable reference is never a credential.
    #[test]
    fn secret_referenced_tokens_resolve_a10() {
        let vault = ark_kernel::vault::Vault::empty();
        vault.set("WEB_READ", "s3cret-read-value").unwrap();
        let cfg = AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            tokens: vec![
                crate::exposure::TokenConfig { token: "{{secret:WEB_READ}}".into(), scope: "read".into(), name: None },
                crate::exposure::TokenConfig { token: "{{secret:MISSING}}".into(), scope: "admin".into(), name: None },
            ],
            ..AppConfig::default()
        };
        let a = app_with(cfg, vault);
        let call = |tok: &str, method: &str| {
            let auth = format!("Bearer {tok}");
            a.clone().handle(json_req("/arp", &[("authorization", &auth)], &rpc(method)))
        };
        assert_eq!(call("s3cret-read-value", "session.list").status, 200);
        assert_eq!(call("s3cret-read-value", "session.submit").status, 403);
        assert_eq!(call("{{secret:MISSING}}", "session.list").status, 401, "an unresolved reference is not a credential");
        assert_eq!(call("{{secret:WEB_READ}}", "session.list").status, 401, "the placeholder itself is not the secret");
    }

    /// The default posture: loopback listen, openai API off, dashboard login off.
    #[test]
    fn app_defaults_are_minimal() {
        let d = AppConfig::default();
        assert_eq!(d.listen, "127.0.0.1:8640");
        assert!(!d.openai_api && d.ui, "static assets stay on, the /v1 API does not");
        assert!(!d.nodes && !d.terminal && !d.a2a.enabled);
        assert_eq!(d.auth, AuthConfig::default());
        assert!(!d.exposure.allow_public && d.exposure.rate_limit_per_min > 0);
        assert!(!d.enabled);
    }
}

