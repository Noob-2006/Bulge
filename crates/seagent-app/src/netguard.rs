//! The app server's perimeter (docs/SECURITY.md §8): who is calling from where, before any
//! credential is looked at, and the headers every answer carries.
//!
//! | layer | rule |
//! |---|---|
//! | **source** | [`source`]: this machine (loopback, no forwarding headers), a LAN address, or a public one. A loopback request that carries `X-Forwarded-For` & co. without `behind_proxy` came through a tunnel (cloudflared, Tailscale Funnel, ngrok, an SSH forward): it is **not** treated as this machine |
//! | **public sources** | a console request from a public address is refused unless `[app.exposure] allow_public = true` (and then the daemon says so loudly at start) |
//! | **allowlist** | `[app.exposure] allow_sources` (IPs / CIDRs) for every source but this machine |
//! | **DNS rebinding** | a browser request (Origin / `Sec-Fetch-*` / WebSocket) to a console route must name this server in `Host`: an IP literal, `localhost`, a single-label or private-suffix name (`.local`, `.lan`, `.home.arpa`, `.internal` …), this machine's name, `allowed_hosts`, `[surfaces] public_url` or an `allow_origins` host |
//! | **CSRF** | a state-changing request that rides the dashboard cookie needs an allowed `Origin` or `Sec-Fetch-Site: same-origin` |
//! | **lockout** | 10 failed credentials / pairing claims / refreshes / logins from one address in 10 min lock it out for 1 min, doubling per repeat (max 1 h) — never this machine |
//! | **CORS** | preflights answered only for listed `allow_origins`; never `*` with credentials, never `Access-Control-Allow-Private-Network` |
//! | **headers** | `nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, a `default-src 'none'` CSP on API answers, HSTS on a public TLS listener (automation routes: `nosniff` only) |
//!
//! What it deliberately does **not** touch (autonomy): signed webhooks and other host routes,
//! public plugin routes, A2A and `/health` ("automation routes") are judged by their own
//! credentials, so channels and agent-to-agent work through a tunnel without a human; and the
//! local owner on loopback never meets a lockout or an extra prompt.

use crate::App;
use seagent_net::httpd::{Request, Response};
use seagent_security::exposure::{classify_ip, AddrClass};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Where a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// This machine: a loopback peer without forwarding headers, or an in-process call.
    Local,
    /// A private-range address (LAN, VPN / tailnet).
    Lan(IpAddr),
    /// Anything else; `None` when a tunnel reported no usable address.
    Public(Option<IpAddr>),
}

impl Source {
    pub fn ip(self) -> Option<IpAddr> {
        match self {
            Source::Local => None,
            Source::Lan(ip) => Some(ip),
            Source::Public(ip) => ip,
        }
    }
}

/// Headers a reverse proxy or tunnel adds. Their presence on a loopback connection means the
/// real client is somewhere else.
const FORWARD_HEADERS: &[&str] = &["forwarded", "x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip", "fly-client-ip", "x-client-ip", "x-forwarded-host", "tailscale-user-login", "cf-ray", "ngrok-trace-id"];

pub fn forwarded(r: &Request) -> bool {
    FORWARD_HEADERS.iter().any(|h| r.header(h).is_some())
}

/// Every client address the forwarding headers report.
fn forwarded_ips(r: &Request) -> Vec<IpAddr> {
    let parse = |h: &str| {
        let h = h.trim().trim_matches('"');
        let h = h.strip_prefix("for=").unwrap_or(h).trim_matches('"');
        let h = h.trim_start_matches('[');
        let h = h.split(']').next().unwrap_or(h);
        h.parse::<IpAddr>().ok().or_else(|| h.parse::<std::net::SocketAddr>().ok().map(|s| s.ip())).or_else(|| h.rsplit_once(':').and_then(|(a, _)| a.parse().ok()))
    };
    let mut out = vec![];
    for h in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip", "fly-client-ip", "x-client-ip"] {
        if let Some(v) = r.header(h) {
            out.extend(v.split(',').filter_map(parse));
        }
    }
    if let Some(v) = r.header("forwarded") {
        out.extend(v.split([',', ';']).filter(|p| p.trim().to_ascii_lowercase().starts_with("for=")).filter_map(parse));
    }
    out
}

/// Where `r` comes from (see the module docs).
pub fn source(app: &App, r: &Request) -> Source {
    let Some(peer) = r.peer else { return Source::Local };
    let judge = |ip: IpAddr, peer_ip: IpAddr| match classify_ip(ip) {
        AddrClass::Private => Source::Lan(ip),
        // A network peer never becomes "this machine", whatever a proxy says.
        AddrClass::Loopback | AddrClass::Unspecified => Source::Lan(peer_ip),
        AddrClass::Public => Source::Public(Some(ip)),
    };
    if classify_ip(peer.ip()) == AddrClass::Loopback {
        if !forwarded(r) {
            return Source::Local;
        }
        if app.cfg.exposure.behind_proxy {
            // A configured local proxy: its X-Forwarded-For is believed (ent-120).
            let ip = app.client_ip(r).unwrap_or(peer.ip());
            return if classify_ip(ip) == AddrClass::Loopback { Source::Local } else { judge(ip, peer.ip()) };
        }
        // An unexpected forwarder: judge by every address it reports; none = public.
        let ips = forwarded_ips(r);
        if let Some(p) = ips.iter().find(|ip| classify_ip(**ip) == AddrClass::Public) {
            return Source::Public(Some(*p));
        }
        return match ips.iter().find(|ip| classify_ip(**ip) == AddrClass::Private) {
            Some(ip) => Source::Lan(*ip),
            None if ips.is_empty() => Source::Public(None),
            None => Source::Lan(peer.ip()),
        };
    }
    judge(app.client_ip(r).unwrap_or(peer.ip()), peer.ip())
}

/// Routes that authenticate themselves and serve automation (signed webhooks and the other
/// host routes, plugin routes, A2A, health): no source / Host / allowlist rules.
pub fn automation_route(app: &App, path: &str) -> bool {
    app.routes.iter().any(|(pre, _)| path.starts_with(pre.as_str())) || path.starts_with("/plugins/") || path.starts_with("/a2a") || path.starts_with("/.well-known/agent") || matches!(path, "/health" | "/ready" | "/readyz")
}

/// Did a browser send this? (DNS rebinding and CSRF are browser attacks.)
fn browserish(r: &Request) -> bool {
    r.header("origin").is_some() || r.header("sec-fetch-site").is_some() || r.header("sec-fetch-mode").is_some() || r.is_upgrade()
}

fn host_name(h: &str) -> String {
    let h = h.trim().to_ascii_lowercase();
    if let Some(v6) = h.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("").to_string();
    }
    match h.rsplit_once(':') {
        Some((n, p)) if p.chars().all(|c| c.is_ascii_digit()) && !n.contains(':') => n.trim_end_matches('.').to_string(),
        _ => h.trim_end_matches('.').to_string(),
    }
}

fn url_host(u: &str) -> Option<String> {
    let rest = u.trim().split_once("://").map(|(_, r)| r)?;
    Some(host_name(rest.split(['/', '?', '#']).next().unwrap_or("")))
}

/// DNS suffixes that are never delegated in public DNS (RFC 6762 `.local`, RFC 8375
/// `.home.arpa`, ICANN's `.internal`, and the customary router names).
const PRIVATE_SUFFIXES: &[&str] = &[".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".intranet", ".corp", ".private"];

/// Is `host` (a `Host` header) a name of this server? IP literals always are: a browser that
/// typed an address is not being rebound.
pub fn host_allowed(app: &App, host: &str) -> bool {
    let h = host_name(host);
    if h.is_empty() || h.parse::<IpAddr>().is_ok() || h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    // Names only this network's own resolver can answer: single labels (`studio`) and the
    // private-use suffixes. A rebinding attacker needs a name in public DNS; these are not.
    if !h.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| h.ends_with(s)) {
        return true;
    }
    let me = seagent_net::x509::dns_label(&crate::lan::display_name());
    let raw = crate::lan::display_name().to_ascii_lowercase();
    if (!me.is_empty() && (h == me || h == format!("{me}.local"))) || h == raw || h == format!("{raw}.local") {
        return true;
    }
    let listed = |pat: &str| {
        let p = host_name(pat);
        match p.strip_prefix("*.") {
            Some(suffix) => h.ends_with(&format!(".{suffix}")),
            None => p == h,
        }
    };
    if app.cfg.exposure.allowed_hosts.iter().any(|a| listed(a)) {
        return true;
    }
    let public = app.d.k.cfg.surfaces.get("public_url").and_then(|v| v.as_str()).and_then(url_host);
    let a2a = app.cfg.a2a.public_url.as_deref().and_then(url_host);
    // The sign-in URLs the operator configured name this server too (OIDC redirect, SAML ACS).
    let oidc = url_host(&app.cfg.auth.self_hosted.redirect_uri);
    let saml = url_host(&app.cfg.auth.saml.acs_url);
    public.into_iter().chain(a2a).chain(oidc).chain(saml).chain(app.cfg.allow_origins.iter().filter_map(|o| url_host(o))).any(|n| n == h)
}

/// The perimeter check for one request; `Some(response)` refuses it.
pub fn check(app: &App, r: &Request) -> Option<Response> {
    let src = source(app, r);
    let automation = automation_route(app, &r.path);
    // A locked-out address is refused everywhere but the automation routes, which carry their
    // own signatures (a tunnel shares one address; its webhooks keep flowing).
    if !automation {
        if let Some(wait) = locked(app, r) {
            return Some(locked_reply(wait));
        }
    }
    // Automation routes check their own signatures / one-time tokens, which a rebinding page
    // does not have; Telegram's Mini App and the setup wizard are browsers on those routes.
    // The SAML ACS is posted by the IdP's page; its signed, audience-bound assertion is the
    // credential (same exception as the Origin rule in `server`).
    if browserish(r) && !automation && r.path != "/auth/saml/acs" {
        if let Some(h) = r.header("host").filter(|h| !host_allowed(app, h)) {
            refused(app, r, "host");
            return Some(forbidden(&format!("forbidden: `Host: {}` is not a name of this server (DNS rebinding protection). Open it by IP address or localhost, or add the name to [app.exposure] allowed_hosts", host_name(h))));
        }
        if csrf_suspect(app, r) {
            refused(app, r, "csrf");
            return Some(forbidden("forbidden: a state-changing request with the session cookie needs an allowed Origin (cross-site request refused)"));
        }
    }
    if automation || src == Source::Local {
        return None;
    }
    if let Source::Public(ip) = src {
        // Public clients are fine when the operator said so: `allow_public`, or `behind_proxy`
        // (a reverse proxy / tunnel they run in front of us). An unannounced tunnel is not.
        if !app.cfg.exposure.allow_public && !app.cfg.exposure.behind_proxy {
            refused(app, r, "public");
            let from = ip.map(|i| i.to_string()).unwrap_or_else(|| "an unknown address (tunnel)".into());
            return Some(forbidden(&format!("forbidden: request from {from}, outside this network. Public access is off: set [app.exposure] behind_proxy = true for a reverse proxy / tunnel you run, or allow_public = true, to expose the console on purpose")));
        }
        static NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !NOTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let from = ip.map(|i| i.to_string()).unwrap_or_default();
            eprintln!("seagentd: WARNING: the console is being reached from a public address ({from}) through the proxy; it is exposed to the internet");
            seagent_security::audit::record(&app.d.k.paths.data, seagent_security::audit::Event::new("exposure.public", seagent_security::audit::Actor::new("anonymous", "").with_ip(&from), &r.path, "warn").detail(json!({"behindProxy": app.cfg.exposure.behind_proxy, "allowPublic": app.cfg.exposure.allow_public})));
        }
    }
    let rules = &app.cfg.exposure.allow_sources;
    if !rules.is_empty() && !src.ip().is_some_and(|ip| rules.iter().any(|rule| crate::exposure::ip_in(ip, rule))) {
        refused(app, r, "allowlist");
        return Some(forbidden("forbidden: this address is not in [app.exposure] allow_sources"));
    }
    None
}

fn forbidden(msg: &str) -> Response {
    Response::json(403, &json!({"error": msg}).to_string())
}

/// The dashboard cookie on a state-changing request without proof it came from our page.
fn csrf_suspect(app: &App, r: &Request) -> bool {
    if !app.cfg.auth.enabled || r.path == "/auth/saml/acs" {
        return false;
    }
    let changes = r.is_upgrade() || !matches!(r.method.as_str(), "GET" | "HEAD" | "OPTIONS");
    let name = app.cfg.auth.cookie_name();
    let has_cookie = r.header("cookie").is_some_and(|c| c.split(';').any(|kv| kv.trim().split_once('=').is_some_and(|(k, _)| k.trim() == name)));
    if !changes || !has_cookie {
        return false;
    }
    let origin_ok = r.header("origin").is_some_and(|o| crate::exposure::origin_allowed(o, r.header("host").unwrap_or(""), &app.cfg.allow_origins));
    let same_site = r.header("sec-fetch-site").is_some_and(|s| matches!(s.trim(), "same-origin" | "none"));
    !(origin_ok || same_site)
}

// ───────────────────────── lockout ─────────────────────────

/// Failures from one address (in [`FAIL_WINDOW`]) that lock it out.
pub const FAIL_LIMIT: usize = 10;
pub const FAIL_WINDOW: Duration = Duration::from_secs(600);
/// First lockout; each repeat within a day doubles it, up to [`LOCK_MAX`].
pub const LOCK_BASE: Duration = Duration::from_secs(60);
pub const LOCK_MAX: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Strikes {
    fails: Vec<Instant>,
    until: Option<Instant>,
    level: u32,
    last_lock: Option<Instant>,
}

type Key = (PathBuf, IpAddr);

fn strikes() -> &'static Mutex<HashMap<Key, Strikes>> {
    static S: OnceLock<Mutex<HashMap<Key, Strikes>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// The lockout bucket: the client address (a tunnel without `behind_proxy` is one bucket, its
/// loopback peer, since what it reports is not trustworthy). `None` for this machine.
fn bucket(app: &App, r: &Request) -> Option<Key> {
    let peer = r.peer?;
    let ip = match source(app, r) {
        Source::Local => return None,
        _ if classify_ip(peer.ip()) == AddrClass::Loopback && !app.cfg.exposure.behind_proxy => peer.ip(),
        s => s.ip().unwrap_or(peer.ip()),
    };
    Some((app.d.k.paths.data.clone(), ip))
}

/// How long the request's address is still locked out.
pub fn locked(app: &App, r: &Request) -> Option<Duration> {
    let key = bucket(app, r)?;
    let all = strikes().lock().unwrap_or_else(|e| e.into_inner());
    let until = all.get(&key)?.until?;
    until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

pub fn locked_reply(wait: Duration) -> Response {
    let secs = (wait.as_millis().div_ceil(1000) as u64).max(1);
    Response::json(429, &json!({"error": format!("too many failed attempts from this address; try again in {secs} s"), "retryAfterS": secs}).to_string()).with_header("retry-after", &secs.to_string()).with_header("cache-control", "no-store")
}

/// One failed credential / pairing claim / refresh / login (`what`) from the request's address.
pub fn auth_failed(app: &App, r: &Request, what: &str) {
    let Some(key) = bucket(app, r) else { return };
    let now = Instant::now();
    let locked_for = {
        let mut all = strikes().lock().unwrap_or_else(|e| e.into_inner());
        if all.len() > 8192 {
            all.retain(|_, s| s.until.is_some_and(|u| u > now) || s.fails.last().is_some_and(|t| now.duration_since(*t) < FAIL_WINDOW));
        }
        let s = all.entry(key.clone()).or_default();
        s.fails.retain(|t| now.duration_since(*t) < FAIL_WINDOW);
        s.fails.push(now);
        if s.fails.len() < FAIL_LIMIT {
            None
        } else {
            if s.last_lock.is_some_and(|t| now.duration_since(t) > Duration::from_secs(86_400)) {
                s.level = 0;
            }
            s.level = (s.level + 1).min(16);
            let d = LOCK_BASE.saturating_mul(1 << (s.level - 1)).min(LOCK_MAX);
            s.until = Some(now + d);
            s.last_lock = Some(now);
            s.fails.clear();
            Some((d, s.level))
        }
    };
    if let Some((d, level)) = locked_for {
        let ip = key.1.to_string();
        crate::metrics::inc("http_lockouts", "");
        seagent_security::audit::record(&app.d.k.paths.data, seagent_security::audit::Event::new("auth.lockout", seagent_security::audit::Actor::new("anonymous", "").with_ip(&ip), what, "deny").detail(json!({"seconds": d.as_secs(), "level": level, "failures": FAIL_LIMIT})));
        alert_owner(app, &format!("lockout:{ip}:{level}:{}", now_ms() / 3_600_000), &format!("{FAIL_LIMIT} failed sign-in / pairing attempts from {ip}; locked out for {} s", d.as_secs()));
    }
}

/// A credential from the request's address verified: its failure count starts over (the
/// lockout level is kept, so an attacker cannot reset the backoff with one good login).
pub fn auth_ok(app: &App, r: &Request) {
    let Some(key) = bucket(app, r) else { return };
    if let Some(s) = strikes().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&key) {
        s.fails.clear();
    }
}

/// Tests: let a lockout run out now (the level, and so the next backoff, is kept).
#[cfg(test)]
pub(crate) fn expire_lock(app: &App, ip: IpAddr) {
    if let Some(s) = strikes().lock().unwrap_or_else(|e| e.into_inner()).get_mut(&(app.d.k.paths.data.clone(), ip)) {
        s.until = None;
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Tell the owner: the daemon log, the audit stream and every `[alerts] targets` entry
/// (channels / webhooks), once per `key`. Delivery runs on its own thread.
pub fn alert_owner(app: &App, key: &str, text: &str) {
    eprintln!("seagentd: SECURITY: {text}");
    let (k, key, text) = (app.d.k.clone(), format!("security:{key}"), text.to_string());
    std::thread::spawn(move || {
        seagent_kernel::governance::alert_as(&k, "security.alert", &key, &text);
    });
}

/// One `net.refused` audit record per address and reason every ten minutes (scanners would
/// otherwise fill the log), plus a metric for every refusal.
fn refused(app: &App, r: &Request, reason: &str) {
    crate::metrics::inc("http_perimeter_refused", &format!("reason=\"{reason}\""));
    static SEEN: OnceLock<Mutex<HashMap<(String, String), Instant>>> = OnceLock::new();
    let ip = source(app, r).ip().or(r.peer.map(|p| p.ip())).map(|i| i.to_string()).unwrap_or_default();
    let mut seen = SEEN.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if seen.len() > 4096 {
        seen.retain(|_, t| now.duration_since(*t) < FAIL_WINDOW);
    }
    let k = (format!("{}|{ip}", app.d.k.paths.data.display()), reason.to_string());
    if seen.get(&k).is_some_and(|t| now.duration_since(*t) < FAIL_WINDOW) {
        return;
    }
    seen.insert(k, now);
    seagent_security::audit::record(&app.d.k.paths.data, seagent_security::audit::Event::new("net.refused", seagent_security::audit::Actor::new("anonymous", "").with_ip(&ip), &r.path, "deny").detail(json!({"reason": reason, "host": r.header("host"), "origin": r.header("origin"), "forwarded": forwarded(r)})));
}

// ───────────────────────── CORS and headers ─────────────────────────

/// What [`finish`] needs from the request (the request itself has moved on by then).
pub struct Meta {
    cors_origin: Option<String>,
    automation: bool,
}

impl Meta {
    pub fn of(app: &App, r: &Request) -> Meta {
        Meta { cors_origin: cors_origin(app, r), automation: automation_route(app, &r.path) }
    }
}

/// The Origin to answer with CORS headers: a listed `allow_origins` entry (cross-origin — our
/// own page needs none). `*` is honoured only for this machine.
fn cors_origin(app: &App, r: &Request) -> Option<String> {
    let o = r.header("origin")?.trim();
    let same = o.split_once("://").is_some_and(|(_, h)| r.header("host").is_some_and(|host| h.eq_ignore_ascii_case(host.trim())));
    if o.is_empty() || o == "null" || same {
        return None;
    }
    let listed = app.cfg.allow_origins.iter().any(|a| a.trim().trim_end_matches('/').eq_ignore_ascii_case(o.trim_end_matches('/')));
    let wildcard = app.cfg.allow_origins.iter().any(|a| a.trim() == "*") && source(app, r) == Source::Local;
    (listed || wildcard).then(|| o.to_string())
}

/// `OPTIONS` (a CORS preflight): allowed origins get the methods and headers ARP needs; every
/// other origin a bare 403. `Access-Control-Allow-Private-Network` is never sent, so a public
/// web page cannot reach a private-network server through Chrome's PNA preflight either.
pub fn preflight(app: &App, r: &Request) -> Response {
    match cors_origin(app, r) {
        Some(_) => Response::empty(204).with_header("access-control-allow-methods", "GET, POST").with_header("access-control-allow-headers", "authorization, content-type, a2a-version").with_header("access-control-max-age", "600"),
        None => {
            if r.header("origin").is_some() {
                refused(app, r, "cors");
            }
            Response::empty(403)
        }
    }
}

fn has(resp: &Response, name: &str) -> bool {
    resp.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Add the security headers (and CORS for a listed origin) a response does not set itself.
pub fn finish(app: &App, meta: &Meta, mut resp: Response) -> Response {
    if resp.status == 101 {
        return resp;
    }
    let api = resp.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && (v.starts_with("application/json") || v.starts_with("text/plain") || v.starts_with("text/event-stream"))) || resp.headers.is_empty();
    if !has(&resp, "x-content-type-options") {
        resp.headers.push(("x-content-type-options".into(), "nosniff".into()));
    }
    // Host / plugin routes and A2A set their own framing and CSP (a Telegram Mini App is framed
    // by web.telegram.org, a plugin page is sandboxed): only nosniff is added there.
    if meta.automation {
        return resp;
    }
    let mut add = |k: &str, v: &str| {
        if !has(&resp, k) {
            resp.headers.push((k.to_string(), v.to_string()));
        }
    };
    // Plugin panels and the live view are framed by our own page; nobody else may frame us.
    add("x-frame-options", "SAMEORIGIN");
    add("referrer-policy", "no-referrer");
    add("cross-origin-resource-policy", "same-origin");
    if api {
        add("content-security-policy", "default-src 'none'; frame-ancestors 'self'");
    }
    // HSTS only where a browser can rely on a real certificate: a public TLS listener. On the
    // LAN's self-signed certificate it would turn a click-through warning into a dead end.
    if app.cfg.exposure.allow_public && app.cfg.exposure.tls {
        add("strict-transport-security", "max-age=31536000");
    }
    if let Some(o) = &meta.cors_origin {
        add("access-control-allow-origin", o);
        add("vary", "Origin");
    }
    resp
}

/// The warning `seagentd` prints (and `lan.status` shows) while public exposure is on.
pub fn public_warning(cfg: &crate::AppConfig) -> Option<String> {
    cfg.exposure.allow_public.then(|| {
        format!(
            "PUBLIC EXPOSURE IS ON ([app.exposure] allow_public = true, listen {}): the console accepts requests from the internet. Keep it behind TLS and a real sign-in, pair devices instead of sharing the app token, and turn it off (allow_public = false) when you do not need it",
            cfg.listen
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_are_parsed_like_browsers_send_them() {
        assert_eq!(host_name("Evil.Example:8640"), "evil.example");
        assert_eq!(host_name("[::1]:8640"), "::1");
        assert_eq!(host_name("192.168.1.5"), "192.168.1.5");
        assert_eq!(host_name("studio.local."), "studio.local");
        assert_eq!(url_host("https://seagent.example.com/x").as_deref(), Some("seagent.example.com"));
    }

    #[test]
    fn forwarded_addresses_are_collected_from_every_header() {
        let r = |hs: &[(&str, &str)]| Request { method: "GET".into(), path: "/".into(), query: vec![], raw_query: String::new(), headers: hs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: vec![], peer: None, head: String::new() };
        let ips = forwarded_ips(&r(&[("x-forwarded-for", "10.0.0.1, 8.8.8.8"), ("forwarded", "for=\"[2001:db8::1]:4711\";proto=https"), ("cf-connecting-ip", "1.1.1.1")]));
        let s: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
        assert_eq!(s, ["10.0.0.1", "8.8.8.8", "1.1.1.1", "2001:db8::1"]);
        assert!(forwarded(&r(&[("tailscale-user-login", "a@b")])) && !forwarded(&r(&[("host", "x")])));
    }
}
