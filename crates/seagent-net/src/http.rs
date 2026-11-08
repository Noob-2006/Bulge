//! The one place an outbound HTTP client is built (ent-036/037/039).
//!
//! Every `ureq::Agent` in the workspace starts from [`builder`] (or [`agent`] / [`agent_for`]),
//! so the enterprise network policy applies to all traffic, not only the model client:
//!
//! - **proxy**: `[network] proxy`, else `$HTTPS_PROXY` / `$HTTP_PROXY` / `$ALL_PROXY`;
//! - **NO_PROXY**: `[network] no_proxy` + `$NO_PROXY` — exact hosts, `.suffix`, `*.suffix`, IPs,
//!   CIDR ranges, `host:port`, `*` (Hermes `agent/proxy_bypass.py`). [`agent_for`] decides per
//!   URL exactly; [`builder`] (URL not known yet) hands ureq an equivalent host list, with CIDR
//!   ranges expanded to address prefixes;
//! - **custom CA**: `[network] ca_file`, else `$SEAGENT_CA_BUNDLE` / `$SSL_CERT_FILE` /
//!   `$REQUESTS_CA_BUNDLE` / `$CURL_CA_BUNDLE` — replaces the bundled roots, for ureq *and* the
//!   raw TLS streams in [`crate::stream`] (WebSocket gateways, IRC, SMTP/IMAP);
//! - **offline**: `[network] offline = true` or `SEAGENT_NETWORK_OFFLINE=1` — every request to a public
//!   host is refused here (second line behind the per-feature switches: update check, price
//!   table, skills hub, telemetry, web tools). Loopback, private ranges, `*.localhost`, the
//!   NO_PROXY hosts and `[network] offline_allow` stay reachable (an air-gapped LAN model).
//!
//! `crates/seagent/tests/http_client_lint.rs` fails the build when a new `ureq` agent is created
//! anywhere else.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub use ureq;

/// The builder type every call site configures (timeouts, redirects, status handling).
pub type Builder = ureq::config::ConfigBuilder<ureq::typestate::AgentScope>;

/// `[network]` in config. Everything optional; env vars fill the gaps.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Proxy URL for all outbound HTTP (`http://`, `socks5://`). Default: $HTTPS_PROXY / $HTTP_PROXY / $ALL_PROXY.
    pub proxy: Option<String>,
    /// Hosts that bypass the proxy: exact, `.suffix`, `*.suffix`, IPs, CIDR, `host:port`, `*`.
    /// Added to $NO_PROXY.
    pub no_proxy: Vec<String>,
    /// PEM bundle of trusted roots (replaces the built-in roots). Default: $SEAGENT_CA_BUNDLE /
    /// $SSL_CERT_FILE / $REQUESTS_CA_BUNDLE / $CURL_CA_BUNDLE.
    pub ca_file: Option<String>,
    /// When non-empty, model providers may only be reached on these hosts (suffix match).
    pub provider_hosts: Vec<String>,
    /// Provider hosts that are refused (suffix match), e.g. filled by compliance profiles.
    pub deny_hosts: Vec<String>,
    /// Fully offline: no update check, price table, skills hub, telemetry or web tools, and
    /// no request to a public host from any client. Also `SEAGENT_NETWORK_OFFLINE=1`.
    pub offline: bool,
    /// Extra hosts (same forms as `no_proxy`) still reachable when offline: an internal model
    /// gateway, an on-prem Vault.
    pub offline_allow: Vec<String>,
    /// Client certificate (PEM chain) presented to servers that ask for one — e.g. a SPIFFE
    /// X.509-SVID for a mesh. Paired with `client_key`.
    pub client_cert: Option<String>,
    /// Private key (PEM) for `client_cert`.
    pub client_key: Option<String>,
}

fn state() -> &'static RwLock<NetConfig> {
    static S: OnceLock<RwLock<NetConfig>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(NetConfig::default()))
}

fn agents() -> &'static Mutex<HashMap<(bool, u64), ureq::Agent>> {
    static A: OnceLock<Mutex<HashMap<(bool, u64), ureq::Agent>>> = OnceLock::new();
    A.get_or_init(Default::default)
}

type Roots = Option<(String, Arc<Vec<ureq::tls::Certificate<'static>>>)>;
fn roots_cache() -> &'static Mutex<Roots> {
    static R: OnceLock<Mutex<Roots>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Install the process-wide network config (call once at startup, after loading config).
pub fn configure(c: NetConfig) {
    *state().write().unwrap() = c;
    agents().lock().unwrap().clear();
    *roots_cache().lock().unwrap() = None;
    crate::stream::reset_tls();
}

thread_local! {
    /// [`with_config`]'s per-thread override: tests exercise the policy without racing the
    /// process-wide config other tests read.
    static LOCAL: std::cell::RefCell<Option<NetConfig>> = const { std::cell::RefCell::new(None) };
}

/// Whether this thread runs under [`with_config`] (caches are bypassed then).
pub(crate) fn overridden() -> bool {
    LOCAL.with(|l| l.borrow().is_some())
}

pub fn current() -> NetConfig {
    LOCAL.with(|l| l.borrow().clone()).unwrap_or_else(|| state().read().unwrap().clone())
}

fn truthy(v: &str) -> bool {
    !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no" | "off")
}

/// Environment form of the offline switch (containers, systemd `Environment=`).
pub const OFFLINE_ENV: &str = "SEAGENT_NETWORK_OFFLINE";

/// The single offline switch: `[network] offline = true` (or `SEAGENT_NETWORK_OFFLINE=1`).
///
/// Not to be confused with `SEAGENT_OFFLINE=1`, the older and narrower test/CI knob that only stops
/// *automatic background* downloads (the price-table auto-refresh): the whole test suite runs
/// under it and still talks to its local fake servers.
pub fn offline() -> bool {
    offline_source().is_some()
}

/// Where the offline switch came from, for `seagent doctor`.
pub fn offline_source() -> Option<&'static str> {
    if current().offline {
        Some("[network] offline = true")
    } else if std::env::var(OFFLINE_ENV).is_ok_and(|v| truthy(&v)) {
        Some("SEAGENT_NETWORK_OFFLINE")
    } else {
        None
    }
}

/// `SEAGENT_OFFLINE=1` (or the full offline switch): skip automatic background downloads.
pub fn no_background_fetch() -> bool {
    offline() || std::env::var("SEAGENT_OFFLINE").is_ok_and(|v| truthy(&v))
}

/// `Err` with a uniform message when `feature` must not run because seagent is offline.
pub fn ensure_online(feature: &str) -> Result<(), String> {
    match offline_source() {
        Some(src) => Err(format!("{feature} is disabled: seagent is in offline mode ({src})")),
        None => Ok(()),
    }
}

const PROXY_ENV: &[&str] = &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];

/// The configured proxy URL, if any.
pub fn proxy_url(c: &NetConfig) -> Option<String> {
    c.proxy.clone().filter(|p| !p.trim().is_empty()).or_else(|| PROXY_ENV.iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty())))
}

/// `[network] no_proxy` + `$NO_PROXY`.
pub fn no_proxy_list(c: &NetConfig) -> Vec<String> {
    let mut v = c.no_proxy.clone();
    for k in ["NO_PROXY", "no_proxy"] {
        if let Ok(s) = std::env::var(k) {
            v.extend(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()));
        }
    }
    v
}

/// `(host, port)` of a URL (lowercased host, IPv6 brackets stripped).
pub fn host_port(url: &str) -> (String, Option<u16>) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
    if let Some(v6) = auth.strip_prefix('[') {
        let (h, r) = v6.split_once(']').unwrap_or((v6, ""));
        return (h.to_lowercase(), r.strip_prefix(':').and_then(|p| p.parse().ok()));
    }
    match auth.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.to_lowercase().trim_end_matches('.').to_string(), p.parse().ok()),
        _ => (auth.to_lowercase().trim_end_matches('.').to_string(), None),
    }
}

pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

/// Whether `url` matches a NO_PROXY list.
pub fn bypass_matches(list: &[String], url: &str) -> bool {
    let (host, port) = host_port(url);
    if host.is_empty() {
        return false;
    }
    let ip = host.parse::<IpAddr>().ok();
    list.iter().any(|raw| {
        let e = raw.trim().to_lowercase();
        if e == "*" {
            return true;
        }
        if let Some(ip) = ip {
            if e.contains('/') {
                return cidr_contains(&e, ip);
            }
        }
        let (eh, ep) = if e.starts_with('[') || e.matches(':').count() > 1 {
            (e.trim_matches(['[', ']']).to_string(), None)
        } else {
            match e.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().ok()),
                _ => (e.clone(), None),
            }
        };
        if ep.is_some() && ep != port {
            return false;
        }
        let suffix = eh.trim_start_matches("*.").trim_start_matches('.');
        host == suffix || host.ends_with(&format!(".{suffix}"))
    })
}

/// A NO_PROXY list in the forms ureq's own matcher understands (exact host, `*.suffix`,
/// `prefix.`), for agents built before the URL is known. `host:port` keeps the host (ureq has
/// no port matching: the bypass is the wider, still-correct choice for an internal host), and
/// an IPv4 CIDR becomes the dotted prefixes it covers (`172.16.0.0/12` → `172.16.` … `172.31.`).
/// An IPv6 CIDR is only expressible when its prefix ends on a hextet: other ranges are honoured
/// by [`agent_for`] (exact per-URL decision) only.
pub fn ureq_no_proxy(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in list {
        let e = raw.trim().to_lowercase();
        if e.is_empty() {
            continue;
        }
        if e == "*" {
            out.push("*".into());
            continue;
        }
        if let Some((net, bits)) = e.split_once('/') {
            let Ok(bits) = bits.parse::<u32>() else { continue };
            match net.parse::<IpAddr>() {
                Ok(IpAddr::V4(n)) if bits <= 32 => {
                    if bits == 0 {
                        out.push("*".into());
                        continue;
                    }
                    if bits == 32 {
                        out.push(n.to_string());
                        continue;
                    }
                    let octets = bits.div_ceil(8) as usize; // octets that the prefix touches
                    let free = octets as u32 * 8 - bits; // host bits inside the last touched octet
                    let base = u32::from(n) & (u32::MAX << (32 - bits));
                    for i in 0..(1u32 << free) {
                        let a = (base + (i << (32 - octets as u32 * 8))).to_be_bytes();
                        let p: Vec<String> = a[..octets].iter().map(|o| o.to_string()).collect();
                        out.push(format!("{}.", p.join(".")));
                    }
                }
                Ok(IpAddr::V6(n)) if bits <= 128 && bits % 16 == 0 => {
                    if bits == 128 {
                        out.push(format!("[{n}]"));
                        continue;
                    }
                    let seg = n.segments();
                    let p: Vec<String> = seg[..(bits / 16) as usize].iter().map(|s| format!("{s:x}")).collect();
                    if !p.is_empty() {
                        out.push(format!("[{}:*", p.join(":")));
                    }
                }
                _ => {}
            }
            continue;
        }
        let host = if e.starts_with('[') || e.matches(':').count() > 1 {
            let h = e.trim_matches(['[', ']']).to_string();
            out.push(format!("[{h}]"));
            continue;
        } else {
            match e.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
                _ => e,
            }
        };
        let suffix = host.trim_start_matches("*.").trim_start_matches('.').to_string();
        out.push(suffix.clone());
        out.push(format!("*.{suffix}"));
    }
    out.sort();
    out.dedup();
    out
}

/// The CA bundle path in effect, if any.
pub fn ca_path(c: &NetConfig) -> Option<String> {
    c.ca_file.clone().filter(|p| !p.is_empty()).or_else(|| ["SEAGENT_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty())))
}

/// Parse a PEM bundle into certificates.
pub fn load_ca(path: &str) -> Result<Vec<ureq::tls::Certificate<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("CA bundle {path}: {e}"))?;
    let out: Vec<_> = ureq::tls::parse_pem(&pem)
        .filter_map(|i| match i {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if out.is_empty() {
        return Err(format!("CA bundle {path}: no certificates found"));
    }
    Ok(out)
}

/// The custom roots in effect (cached per path), or `None` for the bundled Mozilla roots.
pub fn custom_roots() -> Option<Arc<Vec<ureq::tls::Certificate<'static>>>> {
    let path = ca_path(&current())?;
    if overridden() {
        return load_ca(&path).ok().map(Arc::new);
    }
    let mut cache = roots_cache().lock().unwrap();
    if let Some((p, r)) = cache.as_ref() {
        if *p == path {
            return Some(r.clone());
        }
    }
    match load_ca(&path) {
        Ok(certs) => {
            let r = Arc::new(certs);
            *cache = Some((path, r.clone()));
            Some(r)
        }
        Err(e) => {
            eprintln!("seagent: warning: {e}; using built-in roots");
            None
        }
    }
}

/// Parse a PEM certificate chain and private key (a client certificate, an app-server cert).
pub fn load_cert_and_key(cert: &str, key: &str) -> Result<(Vec<ureq::tls::Certificate<'static>>, ureq::tls::PrivateKey<'static>), String> {
    let chain = load_ca(cert).map_err(|e| e.replace("CA bundle", "certificate"))?;
    let pem = std::fs::read(key).map_err(|e| format!("private key {key}: {e}"))?;
    let k = ureq::tls::parse_pem(&pem)
        .find_map(|i| match i {
            Ok(ureq::tls::PemItem::PrivateKey(k)) => Some(k),
            _ => None,
        })
        .ok_or_else(|| format!("private key {key}: no PEM private key found"))?;
    Ok((chain, k))
}

fn tls_config(c: &NetConfig) -> Option<ureq::tls::TlsConfig> {
    let roots = custom_roots();
    let client = match (&c.client_cert, &c.client_key) {
        (Some(cert), Some(key)) => match load_cert_and_key(cert, key) {
            Ok((chain, k)) => Some(ureq::tls::ClientCert::new_with_certs(&chain, k)),
            Err(e) => {
                eprintln!("seagent: warning: [network] client_cert: {e}");
                None
            }
        },
        _ => None,
    };
    if roots.is_none() && client.is_none() {
        return None;
    }
    let mut t = ureq::tls::TlsConfig::builder();
    if let Some(r) = roots {
        t = t.root_certs(ureq::tls::RootCerts::Specific(r));
    }
    Some(t.client_cert(client).build())
}

fn make_proxy(url: &str, no_proxy: &[String]) -> Option<ureq::Proxy> {
    let p = ureq::Proxy::new(url).map_err(|e| eprintln!("seagent: warning: proxy {url}: {e}")).ok()?;
    let mut b = ureq::Proxy::builder(p.protocol()).host(p.host()).port(p.port()).resolve_target(p.resolve_target());
    if let Some(u) = p.username() {
        b = b.username(u);
    }
    if let Some(pw) = p.password() {
        b = b.password(pw);
    }
    let mut list = no_proxy.to_vec();
    list.extend(always_direct());
    for e in ureq_no_proxy(&list) {
        b = b.no_proxy(&e);
    }
    b.build().ok()
}

/// Whether `host` may be reached in offline mode.
pub fn offline_allows(c: &NetConfig, host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        let private = match ip {
            IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_unspecified(),
            IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback() || m.is_private()),
        };
        if private {
            return true;
        }
    }
    let url = format!("http://{}/", if h.contains(':') { format!("[{h}]") } else { h.clone() });
    let mut allow: Vec<String> = no_proxy_list(c).into_iter().filter(|e| e.trim() != "*").collect();
    allow.extend(c.offline_allow.iter().cloned());
    bypass_matches(&allow, &url)
}

fn offline_guard(req: ureq::http::Request<ureq::SendBody>, next: ureq::middleware::MiddlewareNext) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    if offline() {
        let host = req.uri().host().unwrap_or("").to_string();
        if !offline_allows(&current(), &host) {
            let src = offline_source().unwrap_or(OFFLINE_ENV);
            return Err(ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("offline mode ({src}): request to {host} refused"))));
        }
    }
    next.handle(req)
}

fn base(c: &NetConfig, proxy: Option<ureq::Proxy>) -> Builder {
    #[allow(clippy::disallowed_methods)]
    let mut b = ureq::Agent::config_builder().proxy(proxy);
    if let Some(t) = tls_config(c) {
        b = b.tls_config(t);
    }
    b.middleware(offline_guard)
}

/// A client builder with the process-wide proxy (NO_PROXY applied per request), CA bundle,
/// client certificate and offline guard. Call sites add their timeouts and `.build().into()`.
pub fn builder() -> Builder {
    let c = current();
    let proxy = proxy_url(&c).and_then(|p| make_proxy(&p, &no_proxy_list(&c)));
    base(&c, proxy)
}

/// A builder that never uses a proxy (loopback helpers, a call that must go direct).
pub fn builder_direct() -> Builder {
    base(&current(), None)
}

/// `builder()` with ureq's defaults otherwise — the stand-in for `ureq::get(..)`.
pub fn agent() -> ureq::Agent {
    builder().build().into()
}

/// Whether a request to `url` goes direct (no proxy configured, or NO_PROXY matches).
/// Loopback is always direct: a local model server, a CDP port or a test fake never sits
/// behind the corporate proxy.
pub fn is_direct(url: &str) -> bool {
    let c = current();
    proxy_url(&c).is_none() || bypass_matches(&no_proxy_list(&c), url) || bypass_matches(&always_direct(), url)
}

fn always_direct() -> Vec<String> {
    ["localhost", "127.0.0.0/8", "::1/128"].iter().map(|s| s.to_string()).collect()
}

/// A shared (cached) agent for a request to `url`: the proxy decision is the exact per-URL one
/// (CIDR, `host:port`), with `global`/`connect` timeouts and 4xx/5xx returned as responses.
pub fn agent_for(global: Duration, connect: Duration, url: &str) -> ureq::Agent {
    let direct = is_direct(url);
    let build = || {
        let c = current();
        let proxy = if direct { None } else { proxy_url(&c).and_then(|p| ureq::Proxy::new(&p).ok()) };
        base(&c, proxy).http_status_as_error(false).timeout_connect(Some(connect)).timeout_global(Some(global)).build().into()
    };
    if overridden() {
        return build();
    }
    let key = (direct, global.as_millis() as u64 ^ ((connect.as_millis() as u64) << 40));
    let mut m = agents().lock().unwrap();
    m.entry(key).or_insert_with(build).clone()
}

/// One-line summary of the policy in effect, for `seagent doctor`.
pub fn describe() -> Vec<(String, String)> {
    let c = current();
    let mut v = vec![];
    v.push(("proxy".into(), proxy_url(&c).map(|p| redact_userinfo(&p)).unwrap_or_else(|| "none (direct)".into())));
    let np = no_proxy_list(&c);
    v.push(("no_proxy".into(), if np.is_empty() { "-".into() } else { np.join(",") }));
    v.push((
        "ca".into(),
        match ca_path(&c) {
            Some(p) => match load_ca(&p) {
                Ok(certs) => format!("{p} ({} certificates)", certs.len()),
                Err(e) => format!("{e} — falling back to built-in roots"),
            },
            None => "built-in Mozilla roots".into(),
        },
    ));
    v.push((
        "offline".into(),
        match offline_source() {
            Some(s) => format!("on ({s}) — update check, price table, skills hub, telemetry and web tools are off; public hosts are refused"),
            None => "off ([network] offline = true to cut all outbound traffic)".into(),
        },
    ));
    v
}

fn redact_userinfo(u: &str) -> String {
    match (u.split_once("://"), u.rfind('@')) {
        (Some((s, rest)), Some(_)) => format!("{s}://***@{}", rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest)),
        _ => u.to_string(),
    }
}

/// Run `f` with `c` as this thread's network config (tests: the process-wide config, which
/// other threads read, is untouched). Restored on return and on panic.
pub fn with_config<T>(c: NetConfig, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<NetConfig>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            LOCAL.with(|l| *l.borrow_mut() = prev);
        }
    }
    let prev = LOCAL.with(|l| l.borrow_mut().replace(c));
    let _r = Restore(prev);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn l(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_proxy_forms() {
        let list = l(&["example.com", "*.corp.test", ".internal", "10.0.0.0/8", "fd00::/8", "api.local:8443", "[::1]"]);
        assert!(bypass_matches(&list, "https://example.com/v1"));
        assert!(bypass_matches(&list, "https://api.example.com/v1"));
        assert!(!bypass_matches(&list, "https://notexample.com"));
        assert!(bypass_matches(&list, "http://x.corp.test"));
        assert!(bypass_matches(&list, "http://db.internal:5432"));
        assert!(bypass_matches(&list, "http://10.1.2.3:8000/v1"));
        assert!(!bypass_matches(&list, "http://11.1.2.3:8000/v1"));
        assert!(bypass_matches(&list, "http://[fd12::1]:80/"));
        assert!(bypass_matches(&list, "https://api.local:8443/x"));
        assert!(!bypass_matches(&list, "https://api.local:443/x"));
        assert!(bypass_matches(&l(&["*"]), "https://anything"));
        assert!(!bypass_matches(&l(&[]), "https://anything"));
    }

    #[test]
    fn host_parsing() {
        assert_eq!(host_port("https://user:pw@API.X.com:8443/v1?q"), ("api.x.com".into(), Some(8443)));
        assert_eq!(host_port("http://[::1]:11434/v1"), ("::1".into(), Some(11434)));
        assert_eq!(host_port("https://a.b."), ("a.b".into(), None));
    }

    #[test]
    fn cidr_math() {
        assert!(cidr_contains("192.168.0.0/16", "192.168.4.4".parse().unwrap()));
        assert!(!cidr_contains("192.168.0.0/16", "192.169.0.1".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
        assert!(!cidr_contains("bad", "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_expands_to_ureq_prefixes() {
        let v = ureq_no_proxy(&l(&["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "1.2.3.4/32", "*.corp.test", "api.local:8443", "fd00:1::/32"]));
        assert!(v.contains(&"10.".to_string()));
        for i in 16..=31 {
            assert!(v.contains(&format!("172.{i}.")), "172.{i}.");
        }
        assert!(!v.contains(&"172.32.".to_string()) && !v.contains(&"172.15.".to_string()));
        assert!(v.contains(&"192.168.1.".to_string()));
        assert!(v.contains(&"1.2.3.4".to_string()));
        assert!(v.contains(&"corp.test".to_string()) && v.contains(&"*.corp.test".to_string()));
        assert!(v.contains(&"api.local".to_string()));
        assert!(v.contains(&"[fd00:1:*".to_string()));
        // Every expanded prefix agrees with the exact matcher on a sample of addresses.
        for ip in ["10.9.9.9", "172.20.1.1", "172.32.1.1", "192.168.1.7", "192.168.2.7", "8.8.8.8"] {
            let exact = bypass_matches(&l(&["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"]), &format!("http://{ip}/"));
            let pref = v.iter().any(|p| p.ends_with('.') && ip.starts_with(p.as_str()));
            assert_eq!(exact, pref, "{ip}");
        }
    }

    #[test]
    fn ca_bundle_errors_are_clear() {
        // A readable file with no PEM in it (this crate's manifest exists on every OS), and a
        // missing one: no scratch files needed.
        assert!(load_ca(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap_err().contains("no certificates"));
        assert!(load_ca("/nonexistent/ca.pem").is_err());
    }

    /// A one-shot HTTP server (also a minimal proxy: it accepts `CONNECT` and then serves the
    /// tunnelled request itself) that answers `200 ok` and reports the first request line.
    fn one_shot() -> (u16, std::sync::mpsc::Receiver<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let read_head = |s: &mut std::net::TcpStream| {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).unwrap_or(0) == 1 {
                        head.push(b[0]);
                    }
                    String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string()
                };
                let head = read_head(&mut s);
                if head.starts_with("CONNECT ") {
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    read_head(&mut s);
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
                let _ = tx.send(head);
            }
        });
        (port, rx)
    }

    #[test]
    fn every_builder_goes_through_the_configured_proxy() {
        // The "proxy" is a plain HTTP server: a proxied request arrives with an absolute URI.
        let (pport, seen) = one_shot();
        let c = NetConfig { proxy: Some(format!("http://127.0.0.1:{pport}")), ..Default::default() };
        with_config(c, || {
            let a: ureq::Agent = builder().timeout_global(Some(Duration::from_secs(5))).build().into();
            let r = a.get("http://10.255.255.1/x").call().unwrap();
            assert_eq!(r.status(), 200);
            let line = seen.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(line.contains("10.255.255.1"), "the request went through the proxy: {line}");
        });
    }

    #[test]
    fn no_proxy_cidr_goes_direct_even_without_a_url_up_front() {
        // Proxy points at a closed port: only a direct request can succeed.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (port, seen) = one_shot();
        let c = NetConfig { proxy: Some(format!("http://127.0.0.1:{dead}")), no_proxy: vec!["127.0.0.0/8".into()], ..Default::default() };
        with_config(c, || {
            let a: ureq::Agent = builder().timeout_global(Some(Duration::from_secs(5))).build().into();
            assert_eq!(a.get(&format!("http://127.0.0.1:{port}/d")).call().unwrap().status(), 200);
            assert!(seen.recv_timeout(Duration::from_secs(5)).unwrap().starts_with("GET /d"));
            assert!(is_direct(&format!("http://127.0.0.1:{port}/")));
            assert!(!is_direct("https://api.example.com/"));
        });
    }

    #[test]
    fn offline_refuses_public_hosts_and_keeps_the_lan() {
        let c = NetConfig { offline: true, offline_allow: vec!["gateway.corp".into()], ..Default::default() };
        assert!(offline_allows(&c, "127.0.0.1") && offline_allows(&c, "10.1.2.3") && offline_allows(&c, "[::1]") && offline_allows(&c, "ollama.localhost"));
        assert!(offline_allows(&c, "llm.gateway.corp"));
        assert!(!offline_allows(&c, "api.openai.com") && !offline_allows(&c, "8.8.8.8"));
        let (port, _seen) = one_shot();
        with_config(c, || {
            assert!(offline());
            assert!(ensure_online("the update check").unwrap_err().contains("offline mode"));
            let e = agent().get("https://api.openai.com/v1/models").call().unwrap_err().to_string();
            assert!(e.contains("offline mode"), "{e}");
            assert_eq!(agent().get(&format!("http://127.0.0.1:{port}/")).call().unwrap().status(), 200);
        });
    }

    #[test]
    fn describe_redacts_proxy_credentials() {
        with_config(NetConfig { proxy: Some("http://u:secret@proxy.corp:3128".into()), ..Default::default() }, || {
            let d = describe();
            let p = &d.iter().find(|(k, _)| k == "proxy").unwrap().1;
            assert!(!p.contains("secret") && p.contains("proxy.corp:3128"), "{p}");
        });
    }
}
