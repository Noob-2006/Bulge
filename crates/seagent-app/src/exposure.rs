//! App-side exposure helpers (GAPS-next A8–A12): the `[app.exposure]` / `[app.tokens]`
//! config, the per-request scope ladder and the small pure predicates the server needs.
//!
//! The judgement itself lives in [`seagent_security::exposure`] so the daemon, `seagent security
//! audit` and `seagent doctor` cannot drift apart; this module only maps an [`AppConfig`] onto a
//! [`Surface`] and enforces the result before the listener binds.
//!
//! ```toml
//! [app]
//! listen = "127.0.0.1:8640"          # the default: loopback only
//! token = "{{secret:APP_TOKEN}}"     # admin
//! tokens = [                          # scoped, additive; the token above stays admin
//!   { token = "{{secret:WEB_READ}}",    scope = "read",    name = "status page" },
//!   { token = "{{secret:WEB_WRITE}}",   scope = "write",   name = "chat bot" },
//!   { token = "{{secret:APPROVE}}",     scope = "approve", name = "approval console" },
//! ]
//! [app.exposure]
//! allow_public = false               # a non-loopback listen needs this
//! behind_proxy = false               # an https reverse proxy terminates TLS for us
//! tls = false                        # seagent terminates TLS itself (ent-121): needs cert + key
//! cert = "/etc/seagent/tls/server.pem"   # PEM chain
//! key = "/etc/seagent/tls/server.key"    # PEM private key
//! client_auth = "off"                # mTLS: "optional" | "require" (needs client_ca)
//! client_ca = "/etc/seagent/tls/clients-ca.pem"
//! client_identities = [              # verified certificate → access (scope or RBAC role)
//!   { id = "spiffe://corp.example/ops/*", scope = "operator" },
//! ]
//! rate_limit_per_min = 1200          # per client IP; 0 turns it off (never for public binds)
//! ```
//!
//! Scope ladder — a token may do what its scope and every lower one allows:
//!
//! | scope     | what it covers |
//! |-----------|----------------|
//! | `read`    | `GET`/WS subscriptions, `*.list`, `*.get`, `session.list|history|view`, `gate.pending`, `models.list`, `tools.list`, `view.*.frame` |
//! | `write`   | `session.create|submit|command|interrupt`, `goal.start`, chat, approvals-free `view` input |
//! | `approve` | `gate.answer`, `approval(s).answer`, `question.answer` |
//! | `admin`   | `shutdown`, `config.*`, `plugin(s).*`, `daemon.*`, `secret(s).*`, `vault.*`, `hook(s).*`, `skill(s).*`, `channel(s).*`, `node(s).*`/`device(s).*` pairing — and **anything unrecognised** (fail closed) |
//!
//! Rationale for the two oddities: `send`-style chat counts as `write` because a chat
//! message starts a session turn, and an unknown method costs `admin` because a future
//! method must not be reachable by a token that was scoped before it existed.

use crate::AppConfig;
use seagent_security::exposure as policy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `[app.exposure]` — what it takes to expose a surface beyond loopback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExposureConfig {
    /// Written on purpose by the operator: a non-loopback `listen` needs this.
    pub allow_public: bool,
    /// An https reverse proxy (or tunnel) terminates TLS in front of seagent.
    pub behind_proxy: bool,
    /// seagent terminates TLS itself (`cert` + `key`; ent-121).
    pub tls: bool,
    /// PEM certificate chain for `tls`.
    pub cert: Option<String>,
    /// PEM private key for `tls`.
    pub key: Option<String>,
    /// Mutual TLS: `off` (default), `optional` (verify when sent) or `require`.
    pub client_auth: String,
    /// PEM roots client certificates must chain to (mTLS).
    pub client_ca: Option<String>,
    /// Verified client certificates and what they may do. `id` is the certificate's identity —
    /// its SPIFFE ID, another SAN URI, `dns:<name>` or `sha256:<fingerprint>` — exactly, or as a
    /// prefix with a trailing `*`. `scope` takes a token scope or an RBAC role.
    pub client_identities: Vec<ClientIdentity>,
    /// Workload identities (SPIFFE IDs, exact or `prefix*`) that may connect as nodes without a
    /// device token or operator approval (ent-059); needs `tls` with `client_auth`.
    pub node_identities: Vec<String>,
    /// Requests per minute per client IP; 0 = off (refused when public).
    pub rate_limit_per_min: u32,
    /// With `behind_proxy`: the proxies whose `X-Forwarded-For` is believed (IPs or CIDRs).
    /// Empty = loopback only. A header from any other peer is ignored (ent-120).
    pub trusted_proxies: Vec<String>,
    /// SSO done by a legacy front end (Apache `mod_auth_gssapi` / Kerberos SPNEGO, an
    /// mTLS-terminating proxy, a web access manager): the user arrives in a header.
    #[serde(skip_serializing_if = "ProxyAuthConfig::is_default")]
    pub proxy_auth: ProxyAuthConfig,
}

/// `[app.exposure.proxy_auth]` — trusted reverse-proxy identity headers.
///
/// ```toml
/// [app.exposure.proxy_auth]
/// enabled = true
/// proxies = ["10.20.0.5/32"]          # the TCP peer must be one of these (never X-Forwarded-For)
/// user_header = "X-Remote-User"       # e.g. Apache: RequestHeader set X-Remote-User %{REMOTE_USER}s
/// groups_header = "X-Remote-Groups"   # optional; split on `,` / `;`, mapped by [app.rbac] groups
/// email_header = "X-Remote-Email"     # optional
/// strip_realm = true                  # "alice@CORP.EXAMPLE" (Kerberos) → "alice"
/// ```
///
/// The header is believed **only** when the connection itself comes from a listed proxy; from
/// any other peer it is ignored (and the request needs another credential). The proxy must
/// overwrite (not append to) the header, or a client could send its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyAuthConfig {
    pub enabled: bool,
    pub proxies: Vec<String>,
    pub user_header: String,
    pub groups_header: String,
    pub email_header: String,
    pub strip_realm: bool,
}

impl Default for ProxyAuthConfig {
    fn default() -> Self {
        ProxyAuthConfig { enabled: false, proxies: vec![], user_header: "X-Remote-User".into(), groups_header: String::new(), email_header: String::new(), strip_realm: false }
    }
}

/// What a trusted proxy asserted about the caller.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProxyIdentity {
    pub user: String,
    pub email: String,
    pub groups: Vec<String>,
}

impl ProxyAuthConfig {
    /// Untouched defaults (left out of config dumps).
    pub fn is_default(&self) -> bool {
        *self == ProxyAuthConfig::default()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.proxies.is_empty() {
            return Err("[app.exposure.proxy_auth] needs `proxies` (the reverse proxies allowed to assert identities)".into());
        }
        if self.proxies.iter().any(|p| matches!(p.trim(), "" | "0.0.0.0/0" | "::/0" | "*")) {
            return Err("[app.exposure.proxy_auth] proxies: name the proxy hosts; an any-address entry would let every client choose its identity".into());
        }
        if self.user_header.trim().is_empty() {
            return Err("[app.exposure.proxy_auth] user_header is empty".into());
        }
        Ok(())
    }

    /// The identity a request carries, if the TCP peer is a listed proxy and it set the user
    /// header. `header` looks a request header up (case-insensitively).
    pub fn identity(&self, peer: Option<SocketAddr>, header: &dyn Fn(&str) -> Option<String>) -> Option<ProxyIdentity> {
        if !self.enabled {
            return None;
        }
        let ip = peer?.ip();
        if !self.proxies.iter().any(|r| ip_in(ip, r)) {
            return None;
        }
        let mut user = header(&self.user_header)?.trim().to_string();
        if self.strip_realm {
            if let Some((u, _realm)) = user.split_once('@') {
                user = u.to_string();
            }
        }
        // `DOMAIN\user` from Windows front ends keeps its form; control characters never pass.
        if user.is_empty() || user.len() > 256 || user.chars().any(|c| c.is_control()) {
            return None;
        }
        let groups = if self.groups_header.is_empty() { vec![] } else { header(&self.groups_header).unwrap_or_default().split([',', ';']).map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect() };
        let email = if self.email_header.is_empty() { String::new() } else { header(&self.email_header).unwrap_or_default().trim().to_string() };
        Some(ProxyIdentity { user, email, groups })
    }
}

/// `[[app.exposure.client_identities]]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentity {
    pub id: String,
    #[serde(default = "d_scope")]
    pub scope: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Tenant of the certificate holder (ent-050), like a token's `org` / `team`.
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub team: String,
}

impl ClientIdentity {
    pub fn matches(&self, id: &str) -> bool {
        match self.id.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => self.id == id,
        }
    }
}

impl Default for ExposureConfig {
    fn default() -> Self {
        ExposureConfig { allow_public: false, behind_proxy: false, tls: false, cert: None, key: None, client_auth: "off".into(), client_ca: None, client_identities: vec![], node_identities: vec![], rate_limit_per_min: 1200, trusted_proxies: vec![], proxy_auth: ProxyAuthConfig::default() }
    }
}

impl ExposureConfig {
    pub fn client_auth_mode(&self) -> Result<seagent_net::tlsd::ClientAuth, String> {
        seagent_net::tlsd::ClientAuth::parse(&self.client_auth).map_err(|e| format!("[app.exposure] {e}"))
    }
    /// The listener's TLS settings, when `tls = true`.
    pub fn server_tls(&self) -> Option<seagent_net::tlsd::ServerTls> {
        self.tls.then(|| seagent_net::tlsd::ServerTls {
            cert: self.cert.clone().unwrap_or_default(),
            key: self.key.clone().unwrap_or_default(),
            client_ca: self.client_ca.clone(),
            client_auth: self.client_auth_mode().unwrap_or_default(),
        })
    }
    /// The access a verified client certificate identity maps to (first match wins).
    pub fn client_access(&self, id: &str) -> Option<(&ClientIdentity, Result<Scope, crate::identity::Role>)> {
        let c = self.client_identities.iter().find(|c| c.matches(id))?;
        Some((c, Scope::parse(&c.scope).map_err(|_| crate::identity::Role::parse(&c.scope).unwrap_or(crate::identity::Role::Auditor))))
    }
}

fn ip_in(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim();
    let (net, bits) = match rule.split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().ok()),
        None => (rule, None),
    };
    let Ok(net) = net.parse::<IpAddr>() else { return false };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let b = bits.unwrap_or(32).min(32);
            let mask = if b == 0 { 0 } else { u32::MAX << (32 - b) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let b = bits.unwrap_or(128).min(128);
            let mask = if b == 0 { 0 } else { u128::MAX << (128 - b) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        // An IPv4-mapped IPv6 peer against an IPv4 rule.
        (IpAddr::V6(a), IpAddr::V4(_)) => a.to_ipv4_mapped().is_some_and(|v4| ip_in(IpAddr::V4(v4), rule)),
        _ => false,
    }
}

fn trusted(cfg: &ExposureConfig, ip: IpAddr) -> bool {
    if cfg.trusted_proxies.is_empty() {
        return ip.is_loopback() || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v| v.is_loopback()));
    }
    cfg.trusted_proxies.iter().any(|r| ip_in(ip, r))
}

/// The real client address (ent-120). Without `behind_proxy`, or when the TCP peer is not a
/// trusted proxy, it is the peer. Otherwise `X-Forwarded-For` is walked from the right, skipping
/// trusted proxies, and the first untrusted hop is the client — so a client cannot pick its own
/// address by prepending entries.
pub fn client_ip(cfg: &ExposureConfig, peer: Option<SocketAddr>, xff: Option<&str>) -> Option<IpAddr> {
    let peer = peer?.ip();
    if !cfg.behind_proxy || !trusted(cfg, peer) {
        return Some(peer);
    }
    let Some(xff) = xff else { return Some(peer) };
    let hops: Vec<IpAddr> = xff.split(',').filter_map(|h| {
        let h = h.trim().trim_matches(['[', ']']);
        h.parse::<IpAddr>().ok().or_else(|| h.parse::<SocketAddr>().ok().map(|s| s.ip()))
    }).collect();
    let mut client = peer;
    for ip in hops.iter().rev() {
        client = *ip;
        if !trusted(cfg, *ip) {
            break;
        }
    }
    Some(client)
}

/// `[app] tokens = [{ token = "…", scope = "read" }]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub token: String,
    #[serde(default = "d_scope")]
    pub scope: String,
    /// Free-text label for logs/audit (never the token).
    #[serde(default)]
    pub name: Option<String>,
    /// Organization / team the token is limited to (ent-050); unset = installation-wide.
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub team: String,
}

fn d_scope() -> String {
    "read".into()
}

/// What a credential may do. Ordered: a larger scope may do everything a smaller one may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Read,
    Write,
    Approve,
    Admin,
}

impl Scope {
    pub fn parse(s: &str) -> Result<Scope, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "read" => Ok(Scope::Read),
            "write" => Ok(Scope::Write),
            "approve" => Ok(Scope::Approve),
            "admin" => Ok(Scope::Admin),
            other => Err(format!("unknown token scope `{other}` (expected read, write, approve or admin)")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Approve => "approve",
            Scope::Admin => "admin",
        }
    }
    pub fn allows(self, need: Scope) -> bool {
        self >= need
    }
}

const ADMIN_PREFIXES: &[&str] = &[
    "config.", "plugin.", "plugins.", "daemon.", "secret.", "secrets.", "vault.", "hook.", "hooks.", "skill.", "skills.", "provider.", "providers.", "channel.", "channels.", "node.", "nodes.", "device.", "devices.", "auth.", "policy.", "system.", "backup.", "view.vm.",
];
const APPROVE_METHODS: &[&str] = &["gate.answer", "approval.answer", "approvals.answer", "question.answer", "session.review.set"];
const READ_METHODS: &[&str] = &[
    "ping", "initialize", "session.list", "session.history", "session.view", "gate.pending", "goal.list", "schedule.list", "models.list", "tools.list", "events.subscribe", "session.attach", "subscribe", "unsubscribe", "view.browser.list", "view.browser.frame", "view.desktop.state", "logbook.list", "whoami",
];
const WRITE_METHODS: &[&str] = &[
    "session.create", "session.submit", "session.command", "session.interrupt", "goal.start", "goal.stop", "goal.cancel", "schedule.run", "view.browser.input", "view.desktop.takeover", "view.desktop.handback", "view.desktop.input", "view.novnc", "chat.send", "message.send",
];
/// Suffixes that only ever report state (`surfaces.list`, `logs.tail`, `usage.status` …).
const READ_SUFFIXES: &[&str] = &[".list", ".get", ".state", ".history", ".status", ".show", ".info", ".search", ".query", ".view", ".tail", ".describe"];

/// The scope an ARP method needs; unknown methods cost `admin` (fail closed).
pub fn required_scope(method: &str) -> Scope {
    let m = method.trim();
    if m.is_empty() {
        return Scope::Admin;
    }
    if m == "shutdown" || ADMIN_PREFIXES.iter().any(|p| m.starts_with(p)) {
        return Scope::Admin;
    }
    if APPROVE_METHODS.contains(&m) {
        return Scope::Approve;
    }
    if WRITE_METHODS.contains(&m) {
        return Scope::Write;
    }
    if READ_METHODS.contains(&m) || READ_SUFFIXES.iter().any(|s| m.ends_with(s)) {
        return Scope::Read;
    }
    // `initialize` and friends aside, an unrecognised name is treated as configuration-grade.
    Scope::Admin
}

/// Every ARP method the server knows what to do with, for tests and docs.
pub fn method_scope_table() -> Vec<(&'static str, Scope)> {
    let mut v: Vec<(&'static str, Scope)> = READ_METHODS.iter().map(|m| (*m, Scope::Read)).collect();
    v.extend(WRITE_METHODS.iter().map(|m| (*m, Scope::Write)));
    v.extend(APPROVE_METHODS.iter().map(|m| (*m, Scope::Approve)));
    v.push(("shutdown", Scope::Admin));
    v
}

/// Scope for a plain HTTP route of the app server (`/v1/*`, `/view/*`, `/plugins/*`).
pub fn required_scope_http(method: &str, path: &str) -> Scope {
    let get = method == "GET" || method == "HEAD";
    if let Some(rest) = path.strip_prefix("/view/") {
        return match rest {
            _ if rest.starts_with("vm/") => Scope::Admin,
            _ if get && (rest.starts_with("browser/frame") || rest.starts_with("browser/list") || rest.starts_with("desktop/state") || rest.starts_with("desktop/list")) => Scope::Read,
            _ => Scope::Write,
        };
    }
    if path == "/v1/models" {
        return Scope::Read;
    }
    if path.starts_with("/v1/") {
        // chat/completions and responses start turns.
        return if get { Scope::Read } else { Scope::Write };
    }
    if path.starts_with("/plugins/") {
        return if get { Scope::Read } else { Scope::Write };
    }
    Scope::Write
}

/// The app server as a [`policy::Surface`], with the auth strength the config actually gives it.
pub fn surface(cfg: &AppConfig) -> policy::Surface<'_> {
    policy::Surface {
        name: "app server",
        listen: &cfg.listen,
        tls: cfg.exposure.tls,
        behind_proxy: cfg.exposure.behind_proxy,
        allow_public: cfg.exposure.allow_public,
        auth: auth_strength(cfg),
        origins: &cfg.allow_origins,
        rate_limit: cfg.exposure.rate_limit_per_min > 0,
        enabled: cfg.enabled,
    }
}

/// What callers can prove. A bare token — even several, even scoped — is one shared string.
pub fn auth_strength(cfg: &AppConfig) -> policy::AuthStrength {
    // Required mutual TLS: every caller holds a device-bound key before any token is looked at.
    if cfg.exposure.tls && cfg.exposure.client_auth_mode() == Ok(seagent_net::tlsd::ClientAuth::Require) && cfg.exposure.client_ca.is_some() {
        return policy::AuthStrength::Device;
    }
    if cfg.auth.enabled {
        let provider = cfg.auth.provider.trim().to_ascii_lowercase();
        return if provider.is_empty() || provider == "basic" { policy::AuthStrength::DashboardBasic } else { policy::AuthStrength::Provider };
    }
    let has_token = cfg.token.as_deref().is_some_and(|t| !t.trim().is_empty()) || !cfg.tokens.is_empty();
    if has_token {
        policy::AuthStrength::Token
    } else {
        policy::AuthStrength::None
    }
}

/// Why the app server may not start, or `Ok(())`. Called before the socket is bound, so a
/// misconfigured public bind never listens even briefly (A9: refuse, not warn).
pub fn check_start(cfg: &AppConfig) -> Result<(), String> {
    // `start` only runs for an enabled server; the surface is enabled by the time we judge it.
    let mut s = surface(cfg);
    s.enabled = true;
    // Native TLS (ent-121): `tls = true` only counts when the listener really can speak it —
    // a certificate and key that load, and a client CA when mTLS is asked for.
    cfg.exposure.client_auth_mode()?;
    if let Some(t) = cfg.exposure.server_tls() {
        t.config().map_err(|e| format!("[app.exposure] tls = true: {e}"))?;
    }
    match policy::refusal(&s) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}

/// Is `origin` allowed to drive this server from `host`? Same-origin always is; a listed
/// origin may be; `*` in the list is honoured only for loopback (for a public bind
/// [`check_start`] refuses the wildcard outright).
pub fn origin_allowed(origin: &str, host: &str, allow: &[String]) -> bool {
    let origin = origin.trim();
    if origin.is_empty() {
        return true; // not a browser
    }
    if let Some((_, oh)) = origin.split_once("://") {
        if !host.trim().is_empty() && oh.eq_ignore_ascii_case(host.trim()) {
            return true;
        }
    }
    allow.iter().any(|a| {
        let a = a.trim();
        a == "*" || a.eq_ignore_ascii_case(origin) || a.trim_end_matches('/').eq_ignore_ascii_case(origin.trim_end_matches('/'))
    })
}

/// A request body is JSON if its media type says so (`application/json`, `…+json`).
pub fn is_json_content_type(header: Option<&str>) -> bool {
    let Some(h) = header else { return false };
    let m = h.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    m == "application/json" || (m.starts_with("application/") && m.ends_with("+json"))
}

static HITS: Mutex<Option<HashMap<IpAddr, Vec<Instant>>>> = Mutex::new(None);
const WINDOW: Duration = Duration::from_secs(60);
const MAX_PEERS: usize = 4096;

/// Per-IP sliding-window limiter (A9 layer 4). In-process callers (`peer == None`:
/// plugins, tests, host routes) are never limited; nothing here waits for a human.
pub fn rate_ok(cfg: &ExposureConfig, peer: Option<SocketAddr>) -> bool {
    rate_ok_ip(cfg, peer.map(|p| p.ip()))
}

/// [`rate_ok`] keyed by the resolved client address ([`client_ip`]).
pub fn rate_ok_ip(cfg: &ExposureConfig, client: Option<IpAddr>) -> bool {
    let per_min = cfg.rate_limit_per_min;
    if per_min == 0 {
        return true;
    }
    let Some(ip) = client else { return true };
    let now = Instant::now();
    let mut guard = HITS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > MAX_PEERS {
        map.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < WINDOW));
    }
    let q = map.entry(ip).or_default();
    while q.first().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
        q.remove(0);
    }
    if q.len() as u32 >= per_min {
        return false;
    }
    q.push(now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn cfg_with(toml_src: &str) -> AppConfig {
        AppConfig::parse(&toml::from_str(toml_src).unwrap()).unwrap()
    }

    #[test]
    fn scope_ladder_and_method_mapping() {
        assert!(Scope::Admin >= Scope::Approve && Scope::Approve >= Scope::Write && Scope::Write >= Scope::Read);
        assert!(!Scope::Read.allows(Scope::Write) && Scope::Write.allows(Scope::Read));
        assert_eq!(Scope::parse("ADMIN").unwrap(), Scope::Admin);
        assert!(Scope::parse("root").is_err());
        for (m, want) in [
            ("session.list", Scope::Read),
            ("session.view", Scope::Read),
            ("surfaces.list", Scope::Read),
            ("view.browser.frame", Scope::Read),
            ("session.submit", Scope::Write),
            ("session.create", Scope::Write),
            ("chat.send", Scope::Write),
            ("view.browser.input", Scope::Write),
            ("view.desktop.input", Scope::Write),
            ("view.desktop.list", Scope::Read),
            ("view.vm.start", Scope::Admin),
            ("view.vm.stop", Scope::Admin),
            ("gate.answer", Scope::Approve),
            ("shutdown", Scope::Admin),
            ("config.get", Scope::Admin),
            ("plugin.restart", Scope::Admin),
            ("something.new", Scope::Admin),
            ("", Scope::Admin),
        ] {
            assert_eq!(required_scope(m), want, "{m}");
        }
        for (m, s) in method_scope_table() {
            assert_eq!(required_scope(m), s, "{m}");
        }
        assert_eq!(required_scope_http("GET", "/v1/models"), Scope::Read);
        assert_eq!(required_scope_http("POST", "/v1/chat/completions"), Scope::Write);
        assert_eq!(required_scope_http("GET", "/view/browser/frame"), Scope::Read);
        assert_eq!(required_scope_http("GET", "/view/desktop/frame"), Scope::Write);
        assert_eq!(required_scope_http("GET", "/view/desktop/list"), Scope::Read);
        assert_eq!(required_scope_http("POST", "/view/vm/start"), Scope::Admin);
        assert_eq!(required_scope_http("POST", "/view/desktop/input"), Scope::Write);
        assert_eq!(required_scope_http("POST", "/plugins/x/hook"), Scope::Write);
    }

    #[test]
    fn default_config_is_loopback_with_rate_limit_and_no_public_opt_in() {
        let c = AppConfig::default();
        assert_eq!(c.listen, "127.0.0.1:8640");
        assert!(!c.exposure.allow_public && c.exposure.rate_limit_per_min > 0);
        assert!(check_start(&c).is_ok());
        assert_eq!(auth_strength(&c), policy::AuthStrength::None);
        let c = cfg_with("listen = \"127.0.0.1:1\"\ntoken = \"t\"");
        assert_eq!(auth_strength(&c), policy::AuthStrength::Token);
    }

    #[test]
    fn public_bind_is_refused_until_every_layer_is_configured() {
        let bare = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"{{secret:APP_TOKEN}}\"");
        let err = check_start(&bare).unwrap_err();
        assert!(err.contains("missing layer(s)") && err.contains("behind_proxy") && err.contains("app.auth") && err.contains("allow_origins"), "{err}");

        let tls_ok = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\nbehind_proxy = true");
        let err = check_start(&tls_ok).unwrap_err();
        assert!(err.contains("strong auth") && !err.contains("TLS"), "{err}");
        // Rate limiting is on by default; turning it off is what breaks a public bind.
        let no_limit = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\nbehind_proxy = true\nrate_limit_per_min = 0\n[auth]\nenabled = true\nprovider = \"self_hosted\"\nsecret = \"x\"");
        assert!(check_start(&no_limit).unwrap_err().contains("rate_limit_per_min"));

        let full = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\nbehind_proxy = true\n[auth]\nenabled = true\nprovider = \"self_hosted\"\nsecret = \"x\"");
        assert!(check_start(&full).is_ok(), "{:?}", check_start(&full));

        // `tls = true` without a loadable certificate is refused: it would be a plaintext
        // listener wearing a TLS label.
        let fake_tls = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\ntls = true\n[auth]\nenabled = true\nprovider = \"self_hosted\"\nsecret = \"x\"");
        assert!(check_start(&fake_tls).unwrap_err().contains("certificate"), "{:?}", check_start(&fake_tls));
        // Native TLS with a real certificate passes; required mTLS counts as strong auth on its
        // own (A9 layer 2: a device-bound key), with no IdP in front.
        let td = |f: &str| format!("{}/../seagent-net/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"));
        let real_tls = cfg_with(&format!("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\ntls = true\ncert = {:?}\nkey = {:?}\nclient_auth = \"require\"\nclient_ca = {:?}", td("server.pem"), td("server.key"), td("ca.pem")));
        assert_eq!(auth_strength(&real_tls), policy::AuthStrength::Device);
        assert!(check_start(&real_tls).is_ok(), "{:?}", check_start(&real_tls));
        let no_ca = cfg_with(&format!("listen = \"127.0.0.1:8640\"\ntoken = \"t\"\n[exposure]\ntls = true\ncert = {:?}\nkey = {:?}\nclient_auth = \"require\"", td("server.pem"), td("server.key")));
        assert!(check_start(&no_ca).unwrap_err().contains("client_ca"));
        let bad_mode = cfg_with("token = \"t\"\n[exposure]\nclient_auth = \"sometimes\"");
        assert!(check_start(&bad_mode).unwrap_err().contains("client_auth"));

        // "basic" is a shared password: still one string, so still weak.
        let basic = cfg_with("listen = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"https://seagent.example\"]\n[exposure]\nallow_public = true\nbehind_proxy = true\n[auth]\nenabled = true\nprovider = \"basic\"\nsecret = \"x\"");
        assert!(check_start(&basic).unwrap_err().contains("strong auth"));
    }

    #[test]
    fn origins_and_content_type() {
        let allow = vec!["https://seagent.example".to_string()];
        assert!(origin_allowed("https://seagent.example", "box:8640", &allow));
        assert!(origin_allowed("http://box:8640", "box:8640", &[]), "same origin");
        assert!(!origin_allowed("https://evil.example", "box:8640", &allow));
        assert!(origin_allowed("", "box:8640", &[]), "not a browser");
        // `*` is honoured (a loopback-only convenience), but `check` refuses it on a public bind.
        assert!(origin_allowed("https://any.example", "box:8640", &["*".into()]));
        assert!(is_json_content_type(Some("application/json")));
        assert!(is_json_content_type(Some("Application/JSON; charset=utf-8")));
        assert!(is_json_content_type(Some("application/jsonrpc+json")));
        assert!(!is_json_content_type(Some("text/plain")));
        assert!(!is_json_content_type(Some("application/x-www-form-urlencoded")));
        assert!(!is_json_content_type(None));
    }

    #[test]
    fn rate_limit_counts_per_peer_and_ignores_in_process_callers() {
        let cfg = ExposureConfig { rate_limit_per_min: 2, ..ExposureConfig::default() };
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 5555));
        assert!(rate_ok(&cfg, None) && rate_ok(&cfg, None), "no peer, no limit");
        assert!(rate_ok(&cfg, Some(peer)) && rate_ok(&cfg, Some(peer)));
        assert!(!rate_ok(&cfg, Some(peer)), "third request in the window is refused");
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 5555));
        assert!(rate_ok(&cfg, Some(other)), "another client is unaffected");
        let off = ExposureConfig { rate_limit_per_min: 0, ..ExposureConfig::default() };
        for _ in 0..5 {
            assert!(rate_ok(&off, Some(peer)));
        }
    }

    #[test]
    fn scoped_tokens_parse_from_toml() {
        let c = cfg_with("token = \"admin-token\"\ntokens = [{ token = \"r\", scope = \"read\" }, { token = \"w\", scope = \"write\", name = \"bot\" }]");
        assert_eq!(c.tokens.len(), 2);
        assert_eq!(Scope::parse(&c.tokens[0].scope).unwrap(), Scope::Read);
        assert_eq!(c.tokens[1].name.as_deref(), Some("bot"));
        assert!(AppConfig::parse(&toml::from_str("tokens = [{ token = \"x\", scope = \"root\" }]").unwrap()).is_err());
        assert!(AppConfig::parse(&toml::from_str("tokens = [{ token = \"x\", extra = 1 }]").unwrap()).is_err());
    }

    #[test]
    fn forwarded_for_is_only_believed_from_trusted_proxies_ent120() {
        let peer = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
        let off = ExposureConfig::default();
        assert_eq!(client_ip(&off, peer("127.0.0.1:5"), Some("1.2.3.4")).unwrap().to_string(), "127.0.0.1", "not behind a proxy: header ignored");
        let lo = ExposureConfig { behind_proxy: true, ..Default::default() };
        assert_eq!(client_ip(&lo, peer("127.0.0.1:5"), Some("1.2.3.4")).unwrap().to_string(), "1.2.3.4");
        assert_eq!(client_ip(&lo, peer("10.0.0.9:5"), Some("1.2.3.4")).unwrap().to_string(), "10.0.0.9", "untrusted peer: header ignored");
        let net = ExposureConfig { behind_proxy: true, trusted_proxies: vec!["10.0.0.0/8".into(), "192.168.1.1".into()], ..Default::default() };
        // Client spoofs a leading entry; the proxy chain appends the real one.
        assert_eq!(client_ip(&net, peer("10.1.1.1:5"), Some("6.6.6.6, 5.5.5.5, 192.168.1.1")).unwrap().to_string(), "5.5.5.5");
        assert_eq!(client_ip(&net, peer("10.1.1.1:5"), Some("garbage")).unwrap().to_string(), "10.1.1.1");
        assert_eq!(client_ip(&net, peer("10.1.1.1:5"), None).unwrap().to_string(), "10.1.1.1");
        assert!(ip_in("::ffff:10.2.3.4".parse().unwrap(), "10.0.0.0/8"));
        assert!(!ip_in("11.0.0.1".parse().unwrap(), "10.0.0.0/8"));
        assert!(ip_in("fd00::1".parse().unwrap(), "fd00::/8"));
        // Rate limiting follows the resolved client, so two clients behind one proxy are separate.
        let cfg = ExposureConfig { behind_proxy: true, rate_limit_per_min: 1, ..Default::default() };
        let a = client_ip(&cfg, peer("127.0.0.1:1"), Some("203.0.113.10"));
        let b = client_ip(&cfg, peer("127.0.0.1:1"), Some("203.0.113.11"));
        assert!(rate_ok_ip(&cfg, a) && rate_ok_ip(&cfg, b));
        assert!(!rate_ok_ip(&cfg, a));
    }
}
