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
use crate::identity::{self, Access, Principal};
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
    /// 503 from an HA standby, naming the leader (`ha.status` has the details).
    fn standby_reply(&self) -> Response {
        let leader = self.d.ha().and_then(|h| h.leader()).map(|l| json!({"node": l.node, "epoch": l.epoch, "advertise": l.advertise}));
        Response::json(503, &json!({"error": "this ark node is an HA standby; send work to the leader", "leader": leader}).to_string()).with_header("retry-after", "2")
    }

    /// The token a request presents, if any: `Authorization: Bearer`, the `ark.token.<t>`
    /// subprotocol, or — **only on a WebSocket upgrade whose Origin is ours** — `?token=`: a
    /// URL leaks into history, `Referer` headers, proxy logs and screenshots, so a plain HTTP
    /// request has to put the token in a header (A11, the OpenClaw CVE-2026-25253 shape).
    fn presented(&self, r: &Request) -> Option<String> {
        let subproto = r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find_map(|x| x.strip_prefix("ark.token.")).map(str::to_string));
        let from_query = if r.is_upgrade() && self.origin_ok(r) { r.query("token").map(str::to_string) } else { None };
        r.bearer().map(str::to_string).or(subproto).or(from_query)
    }

    /// The request's verified workload identity when it is one `[app.exposure] node_identities`
    /// allows (ent-059). Only the TLS terminator can set the header (it strips client copies),
    /// so without native TLS there is none.
    pub fn workload_identity(&self, r: &Request) -> Option<String> {
        if !self.cfg.exposure.tls {
            return None;
        }
        let id = r.header(ark_net::tlsd::H_CLIENT)?;
        self.cfg.exposure.node_identities.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => p == id,
        }).then(|| id.to_string())
    }

    /// The real client address (trusted-proxy aware, ent-120).
    pub fn client_ip(&self, r: &Request) -> Option<std::net::IpAddr> {
        exposure::client_ip(&self.cfg.exposure, r.peer, r.header("x-forwarded-for"))
    }

    /// Who is calling (ent-053): a dashboard login (with its roles), an issued service account,
    /// or a configured token. `None` = no valid credential.
    pub fn principal(&self, r: &Request) -> Option<Principal> {
        let ip = self.client_ip(r).map(|i| i.to_string()).unwrap_or_default();
        if self.cfg.auth.enabled {
            if let Some(l) = crate::dashboard_auth::login_from(self, r) {
                return Some(Principal { kind: l.kind, name: l.name, access: Access::Roles(l.roles), ip, tenant: l.tenant });
            }
        }
        // SSO behind a legacy front end: a listed reverse proxy (by its TCP address) asserts
        // the user and groups in headers; they map through the same `[app.rbac]` as OIDC.
        let pa = &self.cfg.exposure.proxy_auth;
        if let Some(id) = pa.identity(r.peer, &|h: &str| r.header(h).map(str::to_string)) {
            let facts = identity::LoginFacts { provider: "header", subject: &id.user, email: &id.email, groups: id.groups.clone(), provider_admin: false };
            return match identity::login_roles(self.cfg.rbac.as_ref(), &self.d.k.paths, &facts) {
                Ok(roles) => {
                    let tenant = crate::tenant::login_viewer(self, &id.user, &id.email, &roles, &crate::tenant::login_team(self, &id.groups));
                    Some(Principal { kind: "header".into(), name: id.user, access: Access::Roles(roles), ip, tenant })
                }
                Err(e) => {
                    ark_security::audit::record(&self.d.k.paths.data, ark_security::audit::Event::new("auth.denied", ark_security::audit::Actor::new("header", &id.user).with_ip(&ip), "proxy_auth", "deny").detail(json!({"reason": e})));
                    None
                }
            };
        }
        // ent-121/059: a verified client certificate (mTLS; only the TLS terminator can set this
        // header — it strips every client-sent copy) maps through `client_identities`.
        if self.cfg.exposure.tls {
            if let Some(id) = r.header(ark_net::tlsd::H_CLIENT) {
                if let Some((c, access)) = self.cfg.exposure.client_access(id) {
                    let access = match access {
                        Ok(s) => Access::Scope(s),
                        Err(role) => Access::Roles(vec![role]),
                    };
                    let name = c.name.clone().unwrap_or_else(|| id.to_string());
                    let tenant = crate::tenant::credential_viewer(self, &c.org, &c.team, access.has(identity::Role::Admin) || access == Access::Scope(Scope::Admin), &name);
                    return Some(Principal { kind: "mtls".into(), name, access, ip, tenant });
                }
            }
        }
        let given = self.presented(r)?;
        if let Some(a) = identity::lookup(&self.d.k.paths.data, &given) {
            let access = a.access().ok()?;
            let tenant = crate::tenant::credential_viewer(self, &a.org, &a.team, access.has(identity::Role::Admin) || access == Access::Scope(Scope::Admin), &a.name);
            return Some(Principal { kind: "service".into(), name: a.name, access, ip, tenant });
        }
        let (access, name, org, team) = self.scope_of(&given)?;
        let tenant = crate::tenant::credential_viewer(self, &org, &team, access.has(identity::Role::Admin) || access == Access::Scope(Scope::Admin), &name);
        Some(Principal { kind: "token".into(), name, access, ip, tenant })
    }

    /// Is a principal captured earlier (an open WebSocket) still valid? A login whose profile
    /// was disabled (`ark users disable`, SCIM `active: false`) or a revoked / expired service
    /// account stops at once, even mid-connection (ent-049).
    pub fn still_valid(&self, p: &Principal) -> bool {
        match p.kind.as_str() {
            "service" => identity::accounts(&self.d.k.paths.data).iter().any(|a| a.name == p.name && a.active(ark_security::audit::now_ms())),
            "sso" | "saml" | "basic" | "plugin" | "header" => !ark_kernel::agents::find_login(&self.d.k.paths, &p.name, &p.name).is_some_and(|u| u.disabled),
            _ => true,
        }
    }

    /// Which scope the request's credential carries, if it presents one (roles are mapped onto
    /// the nearest scope; use [`App::principal`] for the real decision).
    pub fn credential(&self, r: &Request) -> Option<Scope> {
        self.principal(r).map(|p| match p.access {
            Access::Scope(s) => s,
            Access::Roles(r) if r.contains(&identity::Role::Admin) => Scope::Admin,
            Access::Roles(r) if r.contains(&identity::Role::User) => Scope::Approve,
            Access::Roles(_) => Scope::Read,
        })
    }

    /// Constant-time token → access lookup; the single `[app] token` is admin. `{{secret:NAME}}`
    /// references are resolved exactly like the daemon resolves `token`; an unresolvable one
    /// never matches anything. The name is the token's `name` (or `app-token` / `tokens[i]`).
    fn scope_of(&self, given: &str) -> Option<(Access, String, String, String)> {
        let mut found = None;
        if !self.token.trim().is_empty() && ark_net::crypto::ct_eq(given.as_bytes(), self.token.as_bytes()) {
            found = Some((Access::Scope(Scope::Admin), "app-token".to_string(), String::new(), String::new()));
        }
        if !self.cfg.tokens.is_empty() {
            let subst = self.d.k.vault_substitute();
            for (i, t) in self.cfg.tokens.iter().enumerate() {
                let value = subst(&t.token);
                if value.is_empty() || value.contains("{{secret:") {
                    continue; // an unresolved reference is not a credential
                }
                if ark_net::crypto::ct_eq(given.as_bytes(), value.as_bytes()) {
                    let access = match Scope::parse(&t.scope) {
                        Ok(s) => Access::Scope(s),
                        Err(_) => identity::Role::parse(&t.scope).map(|r| Access::Roles(vec![r])).unwrap_or(Access::Scope(Scope::Admin)),
                    };
                    found = Some((access, t.name.clone().unwrap_or_else(|| format!("tokens[{i}]")), t.org.clone(), t.team.clone()));
                }
            }
        }
        found
    }

    /// The request carries *a* credential (any scope).
    pub fn authorized(&self, r: &Request) -> bool {
        self.principal(r).is_some()
    }

    /// One audit record for a request decision (ent-073). Reads that expose no content are
    /// only recorded with `[audit] log_reads`.
    fn audit_request(&self, p: &Principal, target: &str, outcome: &str, detail: Value) {
        let quiet = matches!(target, "ping" | "initialize" | "unsubscribe" | "heartbeat");
        let read_only = exposure::required_scope(target) == Scope::Read && !identity::is_content_method(target);
        if outcome == "allow" && (quiet || (read_only && !self.d.k.cfg.audit.log_reads)) {
            return;
        }
        let ev = crate::tenant::tag(ark_security::audit::Event::new(if outcome == "allow" { "app.request" } else { "auth.denied" }, p.actor(), target, outcome).detail(detail), p);
        if ark_security::audit::emit(&self.d.k.paths.data, ev).is_err() {
            crate::metrics::audit_error();
        }
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
        methods.extend(["initialize", "subscribe", "unsubscribe", "whoami", "audit.query", "audit.verify", "audit.report", "usage.query", "tenancy.show"].map(String::from));
        json!({
            "protocol": ARP_VERSION,
            "server": {"name": "ark", "version": env!("CARGO_PKG_VERSION")},
            "methods": methods,
            "events": ["event", "delta", "pending", "heartbeat"],
            "features": {"openai": self.cfg.openai_api, "a2a": self.cfg.a2a.enabled, "nodes": self.cfg.nodes, "ui": self.cfg.ui},
        })
    }

    pub(crate) fn handle(self: &Arc<Self>, r: Request) -> Response {
        let path = r.path.clone();
        if let Some((_, h)) = self.routes.iter().find(|(pre, _)| path.starts_with(pre.as_str())) {
            return h(r);
        }
        // A page on another site must not be able to make this server *do* anything (A11):
        // every state-changing request has to come from our own page or a listed origin.
        // The one exception is the SAML ACS: the IdP's page posts the signed response there
        // (HTTP-POST binding); the audience-bound, single-use, signed assertion is the credential.
        if r.method != "GET" && r.method != "HEAD" && !self.origin_ok(&r) && !(r.method == "POST" && r.path == "/auth/saml/acs") {
            return Response::json(403, &json!({"error": "forbidden: cross-origin request (Origin not allowed)"}).to_string());
        }
        if !crate::exposure::rate_ok_ip(&self.cfg.exposure, self.client_ip(&r)) {
            crate::metrics::inc("http_rate_limited", "");
            return Response::json(429, &json!({"error": "too many requests"}).to_string()).with_header("retry-after", "60");
        }
        // A page on another site must not even learn whether a credential is present.
        if r.path == "/arp" && r.is_upgrade() && !self.origin_ok(&r) {
            return Response::text(403, "origin not allowed");
        }
        match (r.method.as_str(), path.as_str()) {
            ("GET", "/health") => Response::json(200, &json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}).to_string()),
            // Readiness (ent-098): the status code is public (load balancers), details need a credential.
            ("GET", "/ready") | ("GET", "/readyz") => {
                let (ok, body) = crate::metrics::readiness_json(&self.d);
                let body = if self.authorized(&r) { body } else { json!({"ready": ok}) };
                Response::json(if ok { 200 } else { 503 }, &body.to_string()).with_header("cache-control", "no-store")
            }
            // Prometheus (ent-099): any authenticated principal (metrics carry no content), or
            // everyone with `[app] metrics_public = true`.
            ("GET", "/metrics") => {
                if !self.cfg.metrics_public && !self.authorized(&r) {
                    return Response::json(401, &json!({"error": "unauthorized"}).to_string()).with_header("www-authenticate", "Bearer");
                }
                Response::text(200, &crate::metrics::render(&self.d)).with_header("content-type", "text/plain; version=0.0.4").with_header("cache-control", "no-store")
            }
            ("GET", p) if self.cfg.ui && (p == "/" || p.starts_with("/ui/") || p == "/manifest.webmanifest" || p == "/sw.js" || p == "/setup") => ui::serve(p),
            ("GET", "/.well-known/agent-card.json") | ("GET", "/.well-known/agent.json") if self.cfg.a2a.enabled => a2a::card(self, &r),
            // Devices prove themselves with an Ed25519 key and operator-approved pairing.
            (_, p) if p.starts_with("/node") && self.cfg.nodes && r.is_upgrade() => {
                let me = self.clone();
                // ent-059: a verified, allowed workload identity (mTLS SVID) replaces the token.
                let workload = self.workload_identity(&r);
                Response::upgrade(Box::new(move |s, head, rest| crate::node::session(&me, s, &head, rest, workload)))
            }
            (_, p) if p.starts_with("/plugins/") => self.plugin_route(&r),
            // A2A authenticates its own peers (per-peer tokens) before anything else.
            // ent-095: an HA standby starts no turns (its store is fenced anyway); say where to go.
            (m, p) if p.starts_with("/a2a") && self.cfg.a2a.enabled && m == "POST" && !self.d.is_leader() => self.standby_reply(),
            (_, p) if p.starts_with("/a2a") && self.cfg.a2a.enabled => a2a::handle(self, r),
            (_, p) if p.starts_with("/auth/") && self.cfg.auth.enabled => crate::dashboard_auth::handle(self, &r),
            // SCIM provisioning (ent-049): bearer credential, admin only, audited.
            (_, p) if (p == "/scim/v2" || p.starts_with("/scim/v2/")) && self.cfg.scim => match self.principal(&r) {
                Some(p) => crate::scim::handle(self, &r, &p),
                None => Response::json(401, &json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "401", "detail": "unauthorized"}).to_string()).with_header("www-authenticate", "Bearer"),
            },
            // Everything below needs a credential; how much depends on what is asked for.
            _ => match self.principal(&r) {
                Some(p) => self.routed(r, p),
                None => {
                    crate::metrics::inc("http_unauthorized", "");
                    // A credential that matches nothing is worth a record (guessing, a revoked
                    // or expired token); a bare request without one is not.
                    if self.presented(&r).is_some() {
                        let ip = self.client_ip(&r).map(|i| i.to_string()).unwrap_or_default();
                        ark_security::audit::record(&self.d.k.paths.data, ark_security::audit::Event::new("auth.failed", ark_security::audit::Actor::new("anonymous", "").with_ip(&ip), &r.path, "deny"));
                    }
                    Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer")
                }
            },
        }
    }

    /// The routes behind a credential, with the scope each one needs (A10).
    fn routed(self: &Arc<Self>, r: Request, p: Principal) -> Response {
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/arp") if r.is_upgrade() => {
                if !self.origin_ok(&r) {
                    return Response::text(403, "origin not allowed");
                }
                let me = self.clone();
                let proto = r.header("sec-websocket-protocol").and_then(|p| p.split(',').map(str::trim).find(|x| x.starts_with("ark.token.") || *x == "arp").map(str::to_string));
                // Subscriptions are reads; every request inside the socket is checked on its own.
                Response::upgrade(Box::new(move |s, head, rest| me.ws_session(s, &head, rest, proto, p)))
            }
            (_, path) if path.starts_with("/view/") => {
                // The live browser / desktop belong to the whole installation, not to a tenant
                // (ent-050): tenant-bound callers get the same refusal as over ARP (`view.*`).
                if crate::tenant::bound(self, &p) {
                    self.audit_request(&p, &r.path, "deny", json!({"http": r.method, "reason": "tenant"}));
                    return forbidden_msg("the live browser / desktop view is installation-wide; tenant-bound accounts cannot open it");
                }
                if let Err(e) = p.access.permits_http(&r.method, &r.path) {
                    self.audit_request(&p, &r.path, "deny", json!({"http": r.method}));
                    return forbidden_msg(&e);
                }
                self.audit_request(&p, "view.http", "allow", json!({"http": r.method, "path": r.path}));
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
                crate::metrics::inc("arp_requests", &format!("method=\"{}\"", crate::metrics::method_label(method)));
                if let Err(e) = p.access.permits(method) {
                    crate::metrics::inc("arp_forbidden", "");
                    self.audit_request(&p, method, "deny", json!({"transport": "http"}));
                    return forbidden_msg(&e);
                }
                self.audit_request(&p, method, "allow", json!({"transport": "http"}));
                Response::json(200, &self.rpc_as(&req, Some(&p)).to_string())
            }
            (_, path) if path.starts_with("/v1/") && self.cfg.openai_api => {
                if let Err(e) = p.access.permits_http(&r.method, path) {
                    self.audit_request(&p, path, "deny", json!({"http": r.method}));
                    return forbidden_msg(&e);
                }
                if r.method != "GET" {
                    self.audit_request(&p, "openai.request", "allow", json!({"path": path}));
                }
                if r.method != "GET" && !self.d.is_leader() {
                    return self.standby_reply();
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
                match self.principal(r) {
                    None => Response::json(401, &json!({"error": "unauthorized: send the app token (Authorization: Bearer …)"}).to_string()).with_header("www-authenticate", "Bearer"),
                    Some(p) => match p.access.permits_http(&r.method, &r.path) {
                        Err(e) => forbidden_msg(&e),
                        Ok(()) => m.serve(r, &sub).with_header("content-security-policy", "sandbox").with_header("x-content-type-options", "nosniff"),
                    },
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

    /// One JSON-RPC request → response (no streaming methods), with no principal (in-process
    /// callers: A2A, the OpenAI shim, plugins).
    pub fn rpc(&self, req: &Value) -> Value {
        self.rpc_as(req, None)
    }

    /// One JSON-RPC request on behalf of `who`: approvals carry the principal (ent-061),
    /// sessions are charged to it (ent-070) and the identity/audit methods answer for it.
    pub fn rpc_as(&self, req: &Value, who: Option<&Principal>) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req["method"].as_str().unwrap_or("");
        let mut params = req.get("params").cloned().unwrap_or(json!({}));
        // Identity fields are ours to set: a client never chooses who it is.
        if let Some(o) = params.as_object_mut() {
            o.remove("_by");
            o.remove("_by_role");
            o.remove("_via");
        }
        if let (Some(p), Some(o)) = (who, params.as_object_mut()) {
            if matches!(method, "gate.answer" | "approval.answer" | "approvals.answer" | "question.answer" | "session.review.set") {
                o.insert("_by".into(), p.label().into());
                o.insert("_by_role".into(), p.access.label().into());
                o.insert("_via".into(), "app".into());
            }
        }
        // ent-050: an organization-bound principal only reaches its own tenant.
        if let Some(o) = params.as_object_mut() {
            o.remove("_tenant");
            o.remove("_viewer");
        }
        if let Some(p) = who {
            if let Err((code, message)) = crate::tenant::guard(self, p, method, &mut params) {
                return json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
            }
        }
        if let Some(r) = self.identity_rpc(method, &params, who) {
            return match r {
                Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
                Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
            };
        }
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
        let mut r = r;
        if let (Some(p), Ok(v)) = (who, r.as_mut()) {
            crate::tenant::after(self, p, method, &params, v);
        }
        if let (Some(p), Ok(v)) = (who, &r) {
            let sid = match method {
                "session.create" => v["id"].as_str().map(str::to_string),
                "session.submit" => params["id"].as_str().map(str::to_string),
                _ => None,
            };
            if let Some(sid) = sid {
                ark_kernel::governance::note_owner(&self.d.k.paths.data, &sid, &p.label());
            }
        }
        match r {
            Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
            Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        }
    }

    /// `whoami`, `audit.query`, `audit.verify` — answered by the app server itself because
    /// they are about the caller and the stream the server writes.
    fn identity_rpc(&self, method: &str, params: &Value, who: Option<&Principal>) -> Option<Result<Value, (i32, String)>> {
        let data = &self.d.k.paths.data;
        Some(match method {
            "whoami" => Ok(match who {
                // `can`: what the UI may offer this caller (gen2-518: a read-only role sees no
                // write controls). The server still checks every method on its own.
                Some(p) => json!({"kind": p.kind, "name": p.name, "access": p.access.label(), "ip": p.ip, "can": {"write": p.access.permits("session.submit").is_ok(), "approve": p.access.permits("gate.answer").is_ok()}}),
                None => json!({"kind": "in-process", "can": {"write": true, "approve": true}}),
            }),
            "audit.query" => {
                let s = |k: &str| params[k].as_str().map(str::to_string);
                // A bound principal's query is pinned to its own organization (and team).
                let (org, team) = match who {
                    Some(p) if crate::tenant::bound(self, p) => crate::tenant::audit_scope(self, p),
                    _ => (s("org"), s("team")),
                };
                let q = ark_security::audit::Query { kind: s("kind"), actor: s("actor"), session: s("session"), outcome: s("outcome"), after_ms: params["after_ms"].as_u64(), before_ms: params["before_ms"].as_u64(), limit: params["limit"].as_u64().unwrap_or(100).min(1000) as usize, org, team };
                Ok(json!(ark_security::audit::query(data, &q)))
            }
            "usage.query" => crate::tenant::usage(self, who, params),
            "tenancy.show" => {
                let v = who.map(|p| p.tenant.clone()).unwrap_or_default();
                let reg = ark_kernel::tenancy::registry(data);
                let active = ark_kernel::tenancy::active(data);
                // The caller's own organization and the teams / projects it may see.
                let teams: Vec<&ark_kernel::tenancy::Team> = reg.teams.iter().filter(|t| v.global || (v.sees_team(&ark_kernel::tenancy::team_org(&reg, &t.id), &t.id) && (v.org_admin || t.id == v.team))).collect();
                let projects: Vec<&ark_kernel::tenancy::Project> = reg.projects.iter().filter(|p| teams.iter().any(|t| t.id == p.team)).collect();
                Ok(json!({"active": active, "viewer": v, "teams": teams, "projects": projects}))
            }
            "audit.verify" if who.is_some_and(|p| crate::tenant::bound(self, p)) => Err((-32003, "forbidden: the whole-chain verification is installation-wide".to_string())),
            "audit.verify" => Ok(serde_json::to_value(ark_security::audit::verify(data, params["anchor"].as_str())).unwrap_or(Value::Null)),
            "audit.report" if who.is_some_and(|p| crate::tenant::bound(self, p)) => Err((-32003, "forbidden: the audit report covers the whole installation".to_string())),
            "audit.report" => {
                let subst = self.d.k.vault_substitute();
                let pubkey = self.d.k.cfg.audit.seal_public(&|s: &str| subst(s));
                let r = ark_security::audit_report::build(data, params["from_ms"].as_u64().unwrap_or(0), params["to_ms"].as_u64().unwrap_or(0), pubkey.as_deref().map(str::as_bytes));
                let actor = who.map(|p| p.actor()).unwrap_or_else(ark_security::audit::Actor::local);
                ark_security::audit::record(data, ark_security::audit::Event::new("audit.report", actor, "audit", "ok").detail(json!({"from_ms": r.from_ms, "to_ms": r.to_ms, "records": r.records, "head": r.verify.head})));
                match params["format"].as_str().unwrap_or("json") {
                    "json" => Ok(serde_json::to_value(&r).unwrap_or(Value::Null)),
                    "md" | "markdown" => Ok(json!({"format": "md", "text": ark_security::audit_report::markdown(&r)})),
                    "html" => Ok(json!({"format": "html", "text": ark_security::audit_report::html(&r)})),
                    f => Err((-32602, format!("format `{f}`: use json, md or html"))),
                }
            }
            _ => return None,
        })
    }

    /// ARP over WebSocket: one thread owns the socket; requests run on workers,
    /// subscriptions on their own threads; everything outbound funnels through `out`.
    fn ws_session(self: Arc<Self>, s: TcpStream, head: &str, rest: Vec<u8>, proto: Option<String>, principal: Principal) {
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
        let mut checked = std::time::Instant::now();
        loop {
            // ent-049: a principal disabled or revoked while connected loses the socket (and its
            // subscriptions) within a second.
            if checked.elapsed() >= Duration::from_secs(1) {
                checked = std::time::Instant::now();
                if !self.still_valid(&principal) {
                    ark_security::audit::record(&self.d.k.paths.data, crate::tenant::tag(ark_security::audit::Event::new("auth.revoked", principal.actor(), "ws", "deny"), &principal));
                    let _ = ws.send_text(&json!({"jsonrpc": "2.0", "method": "revoked", "params": {"reason": "credential disabled or revoked"}}).to_string());
                    break;
                }
            }
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
            crate::metrics::inc("arp_requests", &format!("method=\"{}\"", crate::metrics::method_label(method_name)));
            if let Err(msg) = principal.access.permits(method_name) {
                crate::metrics::inc("arp_forbidden", "");
                self.audit_request(&principal, method_name, "deny", json!({"transport": "ws"}));
                let _ = out_tx.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32003, "message": msg}}));
                continue;
            }
            self.audit_request(&principal, method_name, "allow", json!({"transport": "ws"}));
            match method_name {
                "subscribe" | "events.subscribe" | "session.attach" => {
                    let mut gp = req.get("params").cloned().unwrap_or(json!({}));
                    if let Err((code, message)) = crate::tenant::guard(&self, &principal, method_name, &mut gp) {
                        let _ = out_tx.send(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}));
                        continue;
                    }
                    let stop = Arc::new(AtomicBool::new(false));
                    subs.push((id.clone(), stop.clone()));
                    let (me, tx, cl, who) = (self.clone(), out_tx.clone(), closed.clone(), principal.clone());
                    // `subscribe` with a session id replays that session's log first, like `session.attach`.
                    let method = if req["method"] == "session.attach" || (req["method"] == "subscribe" && req["params"].get("id").is_some()) { "session.attach" } else { "events.subscribe" };
                    let params = req.get("params").cloned().unwrap_or(json!({}));
                    std::thread::spawn(move || {
                        let mut sink = |v: &Value| -> std::io::Result<()> {
                            // ent-050: other tenants' events never reach this socket.
                            if !crate::tenant::stream_visible(&me, &who, v) {
                                return Ok(());
                            }
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
                    let (me, tx, who) = (self.clone(), out_tx.clone(), principal.clone());
                    std::thread::spawn(move || {
                        let _ = tx.send(me.rpc_as(&req, Some(&who)));
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

/// 403 that names what was missing (A10).
fn forbidden_msg(msg: &str) -> Response {
    Response::json(403, &json!({"error": msg}).to_string())
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
    crate::metrics::started();
    let a = app.clone();
    let h: httpd::Handler = Arc::new(move |r| a.handle(r));
    let opts = httpd::Opts { max_body: 16 * 1024 * 1024, max_conns: app.cfg.max_conns, read_timeout: Duration::from_secs(30) };
    match app.cfg.exposure.server_tls() {
        // ent-121: native TLS / mTLS; the handler sees the real peer and the verified identity.
        Some(t) => httpd::Server::bind_tls(&app.cfg.listen, opts, h, &t),
        None => httpd::Server::bind(&app.cfg.listen, opts, h),
    }
    .map_err(|e| format!("app server: cannot listen on {}: {e}", app.cfg.listen))
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
        // Removed when the test's thread ends (never left behind in TMPDIR).
        let home = ark_core::tmp::scratch("ark-app-srv");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
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

    /// ent-121: native TLS with required client certificates; the verified SPIFFE ID maps to
    /// an access level through `client_identities` (RBAC), no bearer token involved.
    #[test]
    fn native_mtls_maps_client_certificates_to_access_ent121() {
        let td = |f: &str| format!("{}/../ark-net/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"));
        let mut cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() };
        cfg.exposure.tls = true;
        cfg.exposure.cert = Some(td("server.pem"));
        cfg.exposure.key = Some(td("server.key"));
        cfg.exposure.client_auth = "require".into();
        cfg.exposure.client_ca = Some(td("ca.pem"));
        cfg.exposure.client_identities = vec![crate::exposure::ClientIdentity { id: "spiffe://example.org/ark/node/*".into(), scope: "read".into(), name: Some("node fleet".into()), org: String::new(), team: String::new() }];
        let srv = start(app(cfg)).unwrap();
        assert!(srv.is_tls());
        let url = format!("https://localhost:{}/arp", srv.local_addr().port());
        let net = ark_net::http::NetConfig { ca_file: Some(td("ca.pem")), client_cert: Some(td("client.pem")), client_key: Some(td("client.key")), ..Default::default() };
        let call = |net: ark_net::http::NetConfig, method: &str| {
            ark_net::http::with_config(net, || {
                let a: ureq::Agent = ark_net::http::builder().http_status_as_error(false).build().into();
                a.post(&url).header("content-type", "application/json").send(rpc(method)).map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default())).map_err(|e| e.to_string())
            })
        };
        let (st, body) = call(net.clone(), "session.list").unwrap();
        assert_eq!(st, 200, "{body}");
        assert!(body.contains("\"result\""), "{body}");
        let (_, body) = call(net.clone(), "config.get").unwrap();
        assert!(body.contains("forbidden"), "a read-scoped certificate may not call admin methods: {body}");
        // No client certificate: the handshake itself fails.
        assert!(call(ark_net::http::NetConfig { client_cert: None, client_key: None, ..net }, "session.list").is_err());
    }

    /// ent-059: the node route only trusts a workload identity behind native TLS, and only one
    /// listed in `node_identities`.
    #[test]
    fn workload_identity_needs_native_tls_and_the_allowlist() {
        let h = [("x-ark-tls-client", "spiffe://example.org/ark/node/n1")];
        let mut cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() };
        cfg.exposure.node_identities = vec!["spiffe://example.org/ark/node/*".into()];
        assert_eq!(app(cfg.clone()).workload_identity(&req("GET", "/node", &h, "")), None, "plain HTTP: a forged header");
        cfg.exposure.tls = true;
        assert_eq!(app(cfg.clone()).workload_identity(&req("GET", "/node", &h, "")).as_deref(), Some("spiffe://example.org/ark/node/n1"));
        cfg.exposure.node_identities = vec!["spiffe://example.org/ark/ci/*".into()];
        assert_eq!(app(cfg).workload_identity(&req("GET", "/node", &h, "")), None);
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
                crate::exposure::TokenConfig { token: "read-token".into(), scope: "read".into(), name: Some("status".into()), org: String::new(), team: String::new() },
                crate::exposure::TokenConfig { token: "write-token".into(), scope: "write".into(), name: None, org: String::new(), team: String::new() },
                crate::exposure::TokenConfig { token: "approve-token".into(), scope: "approve".into(), name: None, org: String::new(), team: String::new() },
            ],
            // Never the real cwd: a `session.create` here must not touch the repo.
            workspace: Some(ark_core::tmp::scratch_path(format!("ark-app-ws-{}", ark_kernel::util::random_hex(8))).display().to_string()),
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
                crate::exposure::TokenConfig { token: "{{secret:WEB_READ}}".into(), scope: "read".into(), name: None, org: String::new(), team: String::new() },
                crate::exposure::TokenConfig { token: "{{secret:MISSING}}".into(), scope: "admin".into(), name: None, org: String::new(), team: String::new() },
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

    /// SSO behind a legacy front end (Kerberos / `mod_auth_gssapi`, a web access manager):
    /// identity headers count only from a listed proxy's own address, map through
    /// `[app.rbac]`, and a disabled registry profile is refused.
    #[test]
    fn trusted_proxy_identity_headers_map_into_rbac() {
        let home = ark_core::tmp::scratch("ark-app-proxyauth");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        let mut rbac = crate::identity::RbacConfig { default_role: "none".into(), ..Default::default() };
        rbac.groups.insert("ark-auditors".into(), "auditor".into());
        rbac.groups.insert("ark-users".into(), "user".into());
        let pa = crate::exposure::ProxyAuthConfig { enabled: true, proxies: vec!["10.20.0.5/32".into()], user_header: "X-Remote-User".into(), groups_header: "X-Remote-Groups".into(), email_header: String::new(), strip_realm: true };
        assert!(pa.validate().is_ok());
        assert!(crate::exposure::ProxyAuthConfig { proxies: vec!["0.0.0.0/0".into()], ..pa.clone() }.validate().is_err());
        assert!(crate::exposure::ProxyAuthConfig { proxies: vec![], ..pa.clone() }.validate().is_err());
        let cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), rbac: Some(rbac), exposure: crate::exposure::ExposureConfig { proxy_auth: pa, ..Default::default() }, ..AppConfig::default() };
        let a = Arc::new(App { d: d.clone(), cfg, token: "admin-token".into(), host_methods: vec![], routes: vec![] });
        let call = |peer: &str, headers: &[(&str, &str)], method: &str| {
            let mut r = json_req("/arp", headers, &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string());
            r.peer = Some(peer.parse().unwrap());
            let resp = a.clone().handle(r);
            (resp.status, serde_json::from_str::<Value>(&body_text(&resp)).unwrap_or(json!({})))
        };
        let (st, who) = call("10.20.0.5:40000", &[("x-remote-user", "alice@CORP.EXAMPLE"), ("x-remote-groups", "staff; ark-auditors")], "whoami");
        assert_eq!(st, 200);
        assert_eq!((who["result"]["kind"].as_str(), who["result"]["name"].as_str(), who["result"]["access"].as_str()), (Some("header"), Some("alice"), Some("auditor")), "{who}");
        assert_eq!(call("10.20.0.5:40000", &[("x-remote-user", "alice"), ("x-remote-groups", "ark-auditors")], "session.submit").0, 403, "an auditor stays read-only");
        assert_eq!(call("10.20.0.5:40000", &[("x-remote-user", "bob"), ("x-remote-groups", "ark-users")], "session.list").0, 200);
        // The same headers from anyone else are ignored: no credential at all.
        assert_eq!(call("10.20.0.6:40000", &[("x-remote-user", "alice"), ("x-remote-groups", "ark-auditors")], "whoami").0, 401);
        assert_eq!(call("127.0.0.1:40000", &[("x-remote-user", "admin")], "whoami").0, 401);
        // Unmapped (default_role = none): refused and audited.
        assert_eq!(call("10.20.0.5:40000", &[("x-remote-user", "mallory")], "whoami").0, 401);
        assert!(ark_security::audit::all(&d.k.paths.data).iter().any(|r| r["kind"] == "auth.denied" && r["actor"]["name"] == "mallory" && r["actor"]["kind"] == "header"));
        // A disabled registry profile is refused even though the proxy vouches for it.
        let u = ark_kernel::agents::user_add(&d.k.paths, "bob").unwrap();
        ark_kernel::agents::user_update(&d.k.paths, &u.id, |u| {
            u.disabled = true;
            Ok(())
        })
        .unwrap();
        assert_eq!(call("10.20.0.5:40000", &[("x-remote-user", "bob"), ("x-remote-groups", "ark-users")], "session.list").0, 401);
    }

    /// Audit coverage: every mutating ARP method the server knows — the daemon's, the app
    /// server's own and the scope table — leaves an audit record naming the method and the
    /// principal, both when it is allowed and when it is refused. Read-only methods are on an
    /// explicit allowlist (recorded only with `[audit] log_reads`); `shutdown` is exercised
    /// through the refusal path only (allowing it would stop the daemon under test).
    #[test]
    fn every_mutating_arp_method_is_audited() {
        let home = ark_core::tmp::scratch("ark-app-auditcov");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_millis(50));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        std::fs::create_dir_all(home.join("ws")).unwrap();
        let cfg = AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            tokens: vec![crate::exposure::TokenConfig { token: "ro-tok".into(), scope: "read".into(), name: Some("ro".into()), org: String::new(), team: String::new() }],
            workspace: Some(home.join("ws").display().to_string()),
            ..AppConfig::default()
        };
        let a = Arc::new(App { d: d.clone(), cfg, token: "admin-token".into(), host_methods: vec![], routes: vec![] });
        let data = d.k.paths.data.clone();
        let call = |tok: &str, method: &str| {
            let auth = format!("Bearer {tok}");
            let mut r = json_req("/arp", &[("authorization", &auth)], &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {"id": "nope"}}).to_string());
            r.peer = Some("127.0.0.1:4000".parse().unwrap());
            a.clone().handle(r)
        };
        let mut methods: std::collections::BTreeSet<String> = a.capabilities()["methods"].as_array().unwrap().iter().filter_map(|m| m.as_str().map(String::from)).collect();
        methods.extend(crate::exposure::method_scope_table().into_iter().map(|(m, _)| m.to_string()));
        // Read-only: no record unless `[audit] log_reads` (content reads are always recorded).
        let read_only = |m: &str| crate::exposure::required_scope(m) == Scope::Read && !crate::identity::is_content_method(m);
        // Allowed calls not exercised here, with the reason.
        const NOT_ALLOWED_HERE: &[(&str, &str)] = &[("shutdown", "would stop the daemon under test; its refusal path is checked below")];
        let streaming = ["session.attach", "events.subscribe", "subscribe"];
        let mut checked = 0;
        for m in &methods {
            if read_only(m) || streaming.contains(&m.as_str()) {
                continue;
            }
            let has = |kind: &str, actor: &str| ark_security::audit::all(&data).iter().any(|r| r["kind"] == kind && r["target"] == m.as_str() && r["actor"]["name"] == actor);
            // Refused (a read-only token): `auth.denied` with the method and the principal.
            // (Content reads are allowed to it — and recorded as such.)
            call("ro-tok", m);
            if crate::exposure::required_scope(m) == Scope::Read {
                assert!(has("app.request", "ro"), "content read `{m}` left no audit record");
            } else {
                assert!(has("auth.denied", "ro"), "refused `{m}` left no audit record");
            }
            if NOT_ALLOWED_HERE.iter().any(|(x, _)| x == m) {
                continue;
            }
            // Allowed (the admin token): `app.request` before it runs, whatever it then returns.
            call("admin-token", m);
            assert!(has("app.request", "app-token"), "allowed `{m}` left no audit record");
            checked += 1;
        }
        assert!(checked >= 20, "the enumeration found only {checked} mutating methods");
        for m in ["gate.answer", "session.review.set", "session.submit", "config.set", "audit.report"] {
            assert!(methods.contains(m) || crate::exposure::required_scope(m) > Scope::Read, "{m} is enumerated");
        }
        assert!(ark_security::audit::verify(&data, None).ok);
    }

    /// Four eyes, session review and the auditor report over ARP: the server stamps the
    /// authenticated principal *and its roles* on every answer, a dual-controlled approval
    /// needs two different people, an auditor can read but not vote or mark.
    #[test]
    fn dual_control_review_and_report_over_arp() {
        let home = ark_core::tmp::scratch("ark-app-dual");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(10));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending.clone()));
        std::fs::create_dir_all(home.join("ws")).unwrap();
        let tok = |t: &str, scope: &str, name: &str| crate::exposure::TokenConfig { token: t.into(), scope: scope.into(), name: Some(name.into()), org: String::new(), team: String::new() };
        let cfg = AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            tokens: vec![tok("ann-tok", "user", "ann"), tok("bob-tok", "user", "bob"), tok("au-tok", "auditor", "audrey"), tok("req-tok", "user", "req")],
            workspace: Some(home.join("ws").display().to_string()),
            ..AppConfig::default()
        };
        let a = Arc::new(App { d: d.clone(), cfg, token: "admin-token".into(), host_methods: vec![], routes: vec![] });
        let data = d.k.paths.data.clone();
        let call = |tok: &str, method: &str, params: Value| -> Value {
            let auth = format!("Bearer {tok}");
            let mut r = json_req("/arp", &[("authorization", &auth)], &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string());
            r.peer = Some("127.0.0.1:4000".parse().unwrap());
            let resp = a.clone().handle(r);
            let mut v: Value = serde_json::from_str(&body_text(&resp)).unwrap_or(json!({}));
            v["status"] = resp.status.into();
            v
        };
        // A session created by `req` (the server records it as the owner).
        let sid = call("req-tok", "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        let dc = ark_security::dual_control::DualControlConfig { enabled: true, tools: vec!["sh".into()], approver_roles: vec!["user".into()], ..Default::default() };
        let req = ark_kernel::approver::ApprovalRequest { id: "dc-1".into(), tool_use_id: String::new(), session: sid.clone(), tool: "sh".into(), summary: "sudo reboot".into(), input: Value::Null, gate: ark_kernel::gate::GateKind::Privilege, reason: "sudo".into(), tier: 2 };
        let owner = ark_kernel::governance::owner_label_in(&d.k.paths, &d.k.store, &sid);
        assert_eq!(owner, "token:req");
        ark_kernel::approver::open_quorum(ark_security::dual_control::Quorum::new(&dc, "dc-1", &sid, "sh", &owner, ark_security::audit::now_ms()));
        let p2 = pending.clone();
        let h = std::thread::spawn(move || ark_kernel::approver::Approver::approve_within(&*p2, &req, Duration::from_secs(10)));
        while pending.list().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(call("au-tok", "gate.answer", json!({"id": "dc-1", "answer": "once"}))["status"], 403, "auditors never approve");
        assert_eq!(call("req-tok", "gate.answer", json!({"id": "dc-1", "answer": "once"}))["error"]["code"], -32003, "the requester cannot approve");
        let r = call("ann-tok", "gate.answer", json!({"id": "dc-1", "answer": "once", "_by": "sso:forged", "_by_role": "admin"}));
        assert_eq!(r["result"], json!({"ok": true, "final": false, "approvals": 1, "required": 2}), "{r}");
        let p = call("au-tok", "gate.pending", json!({}));
        assert_eq!(p["result"][0]["dual_control"]["approvals"], json!(["token:ann"]), "the client cannot choose who it is: {p}");
        assert_eq!(p["result"][0]["dual_control"]["requester"], "token:req");
        assert!(call("ann-tok", "gate.answer", json!({"id": "dc-1", "answer": "once"}))["error"]["message"].as_str().unwrap().contains("already answered"));
        assert_eq!(call("bob-tok", "gate.answer", json!({"id": "dc-1", "answer": "once"}))["result"]["final"], true);
        assert_eq!(h.join().unwrap(), ark_kernel::approver::Approval::Once);
        // Session review: the owner cannot review itself, an auditor cannot mark, ann can.
        assert_eq!(call("req-tok", "session.review.set", json!({"id": sid, "status": "reviewed"}))["error"]["code"], -32003);
        assert_eq!(call("au-tok", "session.review.set", json!({"id": sid, "status": "reviewed"}))["status"], 403);
        let r = call("ann-tok", "session.review.set", json!({"id": sid, "status": "flagged", "note": "check the reboot"}));
        assert_eq!(r["result"]["by"], "token:ann", "{r}");
        let l = call("au-tok", "session.review.list", json!({"status": "flagged"}));
        assert_eq!(l["result"][0]["session"], sid.as_str());
        assert_eq!(call("au-tok", "session.review.get", json!({"id": sid}))["result"]["current"]["note"], "check the reboot");
        // The auditor's report: one artefact with the approvers and the head hash.
        let rep = call("au-tok", "audit.report", json!({"format": "md"}));
        let text = rep["result"]["text"].as_str().unwrap_or_default().to_string();
        assert!(text.contains("token:ann + token:bob") && text.contains("requested by token:req") && text.contains("Session reviews (1)"), "{rep}");
        assert!(ark_security::audit::all(&data).iter().any(|r| text.contains(&format!("Head hash: `{}`", r["hash"].as_str().unwrap()))), "the report names a real chain head");
        let j = call("au-tok", "audit.report", json!({}));
        assert_eq!(j["result"]["verify"]["ok"], true);
        assert!(ark_security::audit::all(&data).iter().any(|r| r["kind"] == "audit.report" && r["actor"]["name"] == "audrey"));
    }

    /// ent-053/058/061/073/098/099/120 through the real request path.
    #[test]
    fn roles_service_accounts_approver_identity_and_audit() {
        let home = ark_core::tmp::scratch("ark-app-rbac");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(5));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending.clone()));
        std::fs::create_dir_all(home.join("ws")).unwrap();
        let cfg = AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            tokens: vec![
                crate::exposure::TokenConfig { token: "op-token".into(), scope: "operator".into(), name: Some("ops-bot".into()), org: String::new(), team: String::new() },
                crate::exposure::TokenConfig { token: "au-token".into(), scope: "auditor".into(), name: Some("auditor".into()), org: String::new(), team: String::new() },
                crate::exposure::TokenConfig { token: "ap-token".into(), scope: "approve".into(), name: Some("approver".into()), org: String::new(), team: String::new() },
            ],
            exposure: crate::exposure::ExposureConfig { behind_proxy: true, ..Default::default() },
            workspace: Some(home.join("ws").display().to_string()),
            ..AppConfig::default()
        };
        let a = Arc::new(App { d: d.clone(), cfg, token: "admin-token".into(), host_methods: vec![], routes: vec![] });
        let data = d.k.paths.data.clone();
        let call = |tok: &str, method: &str, params: Value| {
            let auth = format!("Bearer {tok}");
            let mut r = json_req("/arp", &[("authorization", &auth), ("x-forwarded-for", "198.51.100.7, 203.0.113.5")], &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string());
            r.peer = Some("127.0.0.1:4000".parse().unwrap());
            a.clone().handle(r)
        };
        // Operator: metadata yes, content no, lifecycle yes.
        assert_eq!(call("op-token", "session.list", json!({})).status, 200);
        let r = call("op-token", "session.history", json!({"id": "x"}));
        assert_eq!(r.status, 403, "{}", body_text(&r));
        assert!(body_text(&r).contains("role operator"));
        assert_eq!(call("op-token", "channels.restart", json!({})).status, 200);
        assert_eq!(call("op-token", "session.submit", json!({})).status, 403);
        // gen2-518: whoami tells the UI which controls to offer (it mirrors the checks above).
        let can = |tok: &str| serde_json::from_str::<Value>(&body_text(&call(tok, "whoami", json!({})))).unwrap()["result"]["can"].clone();
        assert_eq!(can("op-token"), json!({"write": false, "approve": false}));
        assert_eq!(can("au-token"), json!({"write": false, "approve": false}));
        assert_eq!(can("ap-token"), json!({"write": true, "approve": true}));
        assert_eq!(can("admin-token"), json!({"write": true, "approve": true}));
        // Auditor: the audit stream, never content.
        let r = call("au-token", "audit.query", json!({"kind": "auth.denied"}));
        assert_eq!(r.status, 200);
        let recs: Value = serde_json::from_str(&body_text(&r)).unwrap();
        let denied = &recs["result"][0];
        assert_eq!(denied["actor"]["name"], "ops-bot");
        assert_eq!(denied["actor"]["kind"], "token");
        assert_eq!(denied["actor"]["ip"], "203.0.113.5", "client address from a trusted proxy's X-Forwarded-For");
        assert_eq!(denied["target"], "session.history");
        assert_eq!(call("au-token", "session.view", json!({})).status, 403);
        assert_eq!(call("ap-token", "audit.query", json!({})).status, 403, "scoped tokens below admin cannot read the audit stream");
        let v: Value = serde_json::from_str(&body_text(&call("au-token", "audit.verify", json!({})))).unwrap();
        assert_eq!(v["result"]["ok"], true, "{v}");
        // A service account is a named principal with a role.
        let (_, sa) = crate::identity::issue(&data, "ci", "user", 1, "", &ark_security::audit::Actor::local()).unwrap();
        let who: Value = serde_json::from_str(&body_text(&call(&sa, "whoami", json!({})))).unwrap();
        assert_eq!((who["result"]["kind"].as_str(), who["result"]["name"].as_str(), who["result"]["access"].as_str()), (Some("service"), Some("ci"), Some("user")));
        assert_eq!(call(&sa, "config.set", json!({})).status, 403);
        let created: Value = serde_json::from_str(&body_text(&call(&sa, "session.create", json!({})))).unwrap();
        let sid = created["result"]["id"].as_str().unwrap_or_else(|| panic!("{created}")).to_string();
        assert_eq!(ark_kernel::governance::owner_of(&d.k, &sid).user, "service:ci", "the session is charged to its creator");
        // A pending approval answered over ARP records who approved (ent-061).
        let areq = ark_kernel::approver::ApprovalRequest { id: "ap1".into(), tool_use_id: "t".into(), session: sid.clone(), tool: "bash".into(), summary: "deploy".into(), input: Value::Null, gate: ark_kernel::gate::GateKind::Privilege, reason: "deploy [tier 2: prod]".into(), tier: 2 };
        let p2 = pending.clone();
        let h = std::thread::spawn(move || ark_kernel::approver::Approver::approve(&*p2, &areq));
        while ark_kernel::approver::Approver::pending(&*pending).is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        // A client cannot claim to be someone else.
        let r = call("ap-token", "gate.answer", json!({"id": "ap1", "answer": "once", "_by": "sso:ceo@corp.example"}));
        assert_eq!(r.status, 200, "{}", body_text(&r));
        assert_eq!(h.join().unwrap(), ark_kernel::approver::Approval::Once);
        let rec = ark_security::audit::query(&data, &ark_security::audit::Query { kind: Some("approval".into()), ..Default::default() });
        assert_eq!(rec[0]["actor"]["name"], "approver");
        assert_eq!(rec[0]["detail"]["approved_by"], "token:approver");
        assert_eq!(rec[0]["detail"]["tier"], 2);
        // Bad credentials are recorded with the client address.
        assert_eq!(call("nope", "session.list", json!({})).status, 401);
        assert!(ark_security::audit::query(&data, &ark_security::audit::Query { kind: Some("auth.failed".into()), ..Default::default() }).len() == 1);
        assert!(ark_security::audit::verify(&data, None).ok);
        // Readiness: public status code only; a NoRes resolver means the model is not reachable.
        let r = a.clone().handle(req("GET", "/ready", &[], ""));
        assert_eq!(r.status, 503);
        assert_eq!(body_text(&r), "{\"ready\":false}");
        let r = a.clone().handle(req("GET", "/ready", &[("authorization", "Bearer au-token")], ""));
        let body: Value = serde_json::from_str(&body_text(&r)).unwrap();
        assert!(body["checks"].as_array().unwrap().iter().any(|c| c["name"] == "model" && c["ok"] == false), "{body}");
        crate::metrics::register_check("test:ok", Arc::new(|| Ok("fine".into())));
        // Metrics need a credential unless public.
        assert_eq!(a.clone().handle(req("GET", "/metrics", &[], "")).status, 401);
        let m = body_text(&a.clone().handle(req("GET", "/metrics", &[("authorization", "Bearer op-token")], "")));
        assert!(m.contains("ark_up 1") && m.contains("ark_arp_forbidden_total") && m.contains("ark_arp_requests_total{method=\"session.list\"}") && m.contains("ark_ready{check=\"test:ok\"} 1"), "{m}");
        assert!(m.contains("ark_audit_seq "));
    }
}
