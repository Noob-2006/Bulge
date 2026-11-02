//! The app server: HTTP listener in front of the daemon.
//!
//! - `GET /` and `/ui/*`: the web UI (also installable as a desktop/mobile PWA).
//! - `GET /arp` (WebSocket): ARP, the same JSON-RPC 2.0 protocol the unix socket speaks,
//!   with concurrent requests and live subscriptions on one connection.
//! - `POST /arp`: one ARP request per HTTP call (scripts, curl).
//! - `/v1/models`, `/v1/chat/completions`, `/v1/responses`: OpenAI-compatible API.
//! - `/a2a/v1` + `/.well-known/agent-card.json`: Agent2Agent (see `a2a`).
//! - `/plugins/<name>/…`: HTTP routes registered by plugins (see [`mount`]), proxied to the
//!   plugin process; routes the plugin marks public skip the token (they verify themselves).
//! - `GET /health`.
//!
//! Every route except the UI shell, health and the agent card needs the bearer token
//! (`Authorization: Bearer`, `?token=` for WebSocket, or the `ark.token.<t>` subprotocol).

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
    pub fn authorized(&self, r: &Request) -> bool {
        if self.token.is_empty() {
            return false;
        }
        let given = r
            .bearer()
            .map(str::to_string)
            .or_else(|| r.query("token").map(str::to_string))
            .or_else(|| r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find_map(|x| x.strip_prefix("ark.token.")).map(str::to_string)));
        given.is_some_and(|g| ark_net::crypto::ct_eq(g.as_bytes(), self.token.as_bytes()))
    }

    /// Browsers send Origin on WebSocket upgrades: only our own page (or listed origins) may connect.
    fn origin_ok(&self, r: &Request) -> bool {
        let Some(o) = r.header("origin") else { return true };
        let host = r.header("host").unwrap_or("");
        let own = o.split_once("://").map(|(_, h)| h) == Some(host);
        own || self.cfg.allow_origins.iter().any(|a| a == o)
    }

    pub fn capabilities(&self) -> Value {
        let mut methods: Vec<String> = Daemon::METHODS.iter().map(|s| s.to_string()).collect();
        methods.extend(self.host_methods.iter().cloned());
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
            _ if !self.authorized(&r) => Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer"),
            ("GET", "/arp") if r.is_upgrade() => {
                if !self.origin_ok(&r) {
                    return Response::text(403, "origin not allowed");
                }
                let me = self.clone();
                let proto = r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find(|x| x.starts_with("ark.token.") || *x == "arp").map(str::to_string));
                Response::upgrade(Box::new(move |s, head, rest| me.ws_session(s, &head, rest, proto)))
            }
            ("POST", "/arp") => {
                let req: Value = match serde_json::from_slice(&r.body) {
                    Ok(v) => v,
                    Err(e) => return Response::json(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}}).to_string()),
                };
                Response::json(200, &self.rpc(&req).to_string())
            }
            (_, p) if p.starts_with("/v1/") && self.cfg.openai_api => openai::handle(self, r),
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
            Some(false) if !self.authorized(r) => Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer"),
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
            m => self.d.call(m, &params),
        };
        match r {
            Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
            Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        }
    }

    /// ARP over WebSocket: one thread owns the socket; requests run on workers,
    /// subscriptions on their own threads; everything outbound funnels through `out`.
    fn ws_session(self: Arc<Self>, s: TcpStream, head: &str, rest: Vec<u8>, proto: Option<String>) {
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
            match req["method"].as_str().unwrap_or("") {
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
    let a = app.clone();
    let h: httpd::Handler = Arc::new(move |r| a.handle(r));
    let opts = httpd::Opts { max_body: 16 * 1024 * 1024, max_conns: app.cfg.max_conns, read_timeout: Duration::from_secs(30) };
    httpd::Server::bind(&app.cfg.listen, opts, h).map_err(|e| format!("app server: cannot listen on {}: {e}", app.cfg.listen))
}
