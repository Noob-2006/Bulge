//! Network policy for every model/auth request: proxy with a NO_PROXY matcher that
//! understands CIDR ranges and `*.domain` (Hermes `agent/proxy_bypass.py`), a custom CA
//! bundle (`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` idiom, Hermes `agent/ssl_verify.py`)
//! and a provider host policy (OpenClaw `provider-network-policy.ts`: cloud metadata
//! endpoints are never a model provider; optional host allowlist; deny list).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

/// `[network]` in config. Everything optional; env vars fill the gaps.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Proxy URL for provider traffic (`http://`, `socks5://`). Default: $HTTPS_PROXY / $HTTP_PROXY / $ALL_PROXY.
    pub proxy: Option<String>,
    /// Hosts that bypass the proxy: exact, `.suffix`, `*.suffix`, IPs, CIDR, `host:port`, `*`.
    /// Added to $NO_PROXY.
    pub no_proxy: Vec<String>,
    /// PEM bundle of trusted roots (replaces the built-in roots). Default: $ARK_CA_BUNDLE /
    /// $SSL_CERT_FILE / $REQUESTS_CA_BUNDLE.
    pub ca_file: Option<String>,
    /// When non-empty, model providers may only be reached on these hosts (suffix match).
    pub provider_hosts: Vec<String>,
    /// Provider hosts that are refused (suffix match), e.g. filled by compliance profiles.
    pub deny_hosts: Vec<String>,
}

fn state() -> &'static RwLock<NetConfig> {
    static S: OnceLock<RwLock<NetConfig>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(NetConfig::default()))
}

fn agents() -> &'static Mutex<HashMap<(bool, u64), ureq::Agent>> {
    static A: OnceLock<Mutex<HashMap<(bool, u64), ureq::Agent>>> = OnceLock::new();
    A.get_or_init(Default::default)
}

/// Install the process-wide network config (call once at startup).
pub fn configure(c: NetConfig) {
    *state().write().unwrap() = c;
    agents().lock().unwrap().clear();
}

pub fn current() -> NetConfig {
    state().read().unwrap().clone()
}

const PROXY_ENV: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

fn proxy_url(c: &NetConfig) -> Option<String> {
    c.proxy
        .clone()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| {
            PROXY_ENV
                .iter()
                .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
        })
}

fn no_proxy_list(c: &NetConfig) -> Vec<String> {
    let mut v = c.no_proxy.clone();
    for k in ["NO_PROXY", "no_proxy"] {
        if let Ok(s) = std::env::var(k) {
            v.extend(
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty()),
            );
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
        return (
            h.to_lowercase(),
            r.strip_prefix(':').and_then(|p| p.parse().ok()),
        );
    }
    match auth.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (
            h.to_lowercase().trim_end_matches('.').to_string(),
            p.parse().ok(),
        ),
        _ => (auth.to_lowercase().trim_end_matches('.').to_string(), None),
    }
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
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
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), p.parse::<u16>().ok())
                }
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

/// Cloud metadata / link-local targets are never a model provider (SSRF guard). The
/// classification is `ark_security::url_safety`'s (A14): the model client, the web tools, the
/// browser and the media fetchers share one metadata floor and one address classifier.
/// `metadata` / `instance-data` are the shorthand names provider configs use; they stay here
/// because no HTTP client should ever resolve them either.
pub fn is_metadata_host(host: &str) -> bool {
    let host = ark_security::url_safety::normalize_host(host);
    if ark_security::url_safety::BLOCKED_HOSTNAMES.contains(&host.as_str()) || host == "metadata" || host.split('.').any(|l| l == "instance-data") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ark_security::url_safety::is_always_blocked_ip(ip) || is_link_local(ip),
        Err(_) => false,
    }
}

/// Link-local (`169.254.0.0/16`, `fe80::/10`) is never a provider, but is not part of the
/// shared *metadata* floor (`is_always_blocked_ip`): a provider on the LAN is legitimate, one
/// on the autoconfiguration range is not.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn suffix_match(host: &str, pat: &str) -> bool {
    let p = pat
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_lowercase();
    !p.is_empty() && (host == p || host.ends_with(&format!(".{p}")))
}

/// Provider host policy for `url`.
pub fn check_host(url: &str) -> Result<(), String> {
    let c = state().read().unwrap();
    let (host, _) = host_port(url);
    if is_metadata_host(&host) {
        return Err(format!(
            "{host}: cloud metadata / link-local addresses are not allowed as model providers"
        ));
    }
    if let Some(d) = c.deny_hosts.iter().find(|d| suffix_match(&host, d)) {
        return Err(format!("{host}: blocked by network policy ({d})"));
    }
    if !c.provider_hosts.is_empty()
        && !c.provider_hosts.iter().any(|a| suffix_match(&host, a))
        && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
    {
        return Err(format!("{host}: not in network.provider_hosts"));
    }
    Ok(())
}

fn ca_path(c: &NetConfig) -> Option<String> {
    c.ca_file.clone().filter(|p| !p.is_empty()).or_else(|| {
        [
            "ARK_CA_BUNDLE",
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    })
}

/// Parse a PEM bundle into certificates.
pub fn load_ca(path: &str) -> Result<Vec<ureq::tls::Certificate<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("CA bundle {path}: {e}"))?;
    let mut out = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        if let Ok(ureq::tls::PemItem::Certificate(c)) = item {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(format!("CA bundle {path}: no certificates found"));
    }
    Ok(out)
}

fn build_agent(direct: bool, global: Duration, connect: Duration) -> ureq::Agent {
    let c = state().read().unwrap().clone();
    let mut b = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(connect))
        .timeout_global(Some(global));
    b = if direct {
        b.proxy(None)
    } else {
        match proxy_url(&c).and_then(|p| ureq::Proxy::new(&p).ok()) {
            Some(p) => b.proxy(Some(p)),
            None => b.proxy(None),
        }
    };
    if let Some(p) = ca_path(&c) {
        match load_ca(&p) {
            Ok(certs) => {
                b = b.tls_config(
                    ureq::tls::TlsConfig::builder()
                        .root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)))
                        .build(),
                );
            }
            Err(e) => eprintln!("ark: warning: {e}; using built-in roots"),
        }
    }
    b.build().into()
}

/// A shared agent for a request to `url` with `global` timeout (proxy chosen per host).
pub fn agent(global: Duration, url: &str) -> ureq::Agent {
    agent_with(global, Duration::from_secs(30), url)
}

pub fn agent_with(global: Duration, connect: Duration, url: &str) -> ureq::Agent {
    let c = current();
    let direct = proxy_url(&c).is_none() || bypass_matches(&no_proxy_list(&c), url);
    let key = (
        direct,
        global.as_millis() as u64 ^ ((connect.as_millis() as u64) << 40),
    );
    let mut m = agents().lock().unwrap();
    m.entry(key)
        .or_insert_with(|| build_agent(direct, global, connect))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_proxy_forms() {
        let list = l(&[
            "example.com",
            "*.corp.test",
            ".internal",
            "10.0.0.0/8",
            "fd00::/8",
            "api.local:8443",
            "[::1]",
        ]);
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
        assert_eq!(
            host_port("https://user:pw@API.X.com:8443/v1?q"),
            ("api.x.com".into(), Some(8443))
        );
        assert_eq!(
            host_port("http://[::1]:11434/v1"),
            ("::1".into(), Some(11434))
        );
        assert_eq!(host_port("https://a.b."), ("a.b".into(), None));
    }

    #[test]
    fn metadata_and_policy() {
        assert!(is_metadata_host("169.254.169.254"));
        assert!(is_metadata_host("metadata.google.internal"));
        assert!(is_metadata_host("fe80::1"));
        assert!(!is_metadata_host("127.0.0.1"));
        assert!(check_host("http://169.254.169.254/latest").is_err());
        assert!(check_host("https://api.openai.com/v1").is_ok());
    }

    #[test]
    fn ssrf_classification_is_the_shared_one() {
        // A14: the model client's metadata floor is `ark_security::url_safety`'s, so a range
        // only has to be taught once for the model, web, browser and media fetchers.
        for s in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "::ffff:169.254.169.254", "fd00:ec2::254"] {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(ark_security::url_safety::is_always_blocked_ip(ip), "{s}: the shared floor");
            assert!(is_metadata_host(s), "{s}: the model client agrees");
        }
        // Metadata names are the shared list (case/suffix handling included).
        for name in ["metadata.google.internal", "metadata.goog", "METADATA.GOOG"] {
            assert!(ark_security::url_safety::BLOCKED_HOSTNAMES.contains(&ark_security::url_safety::normalize_host(name).as_str()), "{name}");
            assert!(is_metadata_host(name), "{name}: the model client agrees");
        }
        // A LAN provider (local LLM, llama.cpp on a NAS) stays usable: private is not metadata.
        for host in ["127.0.0.1", "10.0.0.5", "192.168.1.9", "api.anthropic.com"] {
            assert!(!is_metadata_host(host), "{host}");
        }
        // Nothing that is not metadata may be refused by the floor.
        assert!(ark_security::url_safety::is_blocked_ip("10.0.0.5".parse().unwrap()) && !is_metadata_host("10.0.0.5"));
    }

    #[test]
    fn cidr_math() {
        assert!(cidr_contains(
            "192.168.0.0/16",
            "192.168.4.4".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "192.168.0.0/16",
            "192.169.0.1".parse().unwrap()
        ));
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
        assert!(!cidr_contains("bad", "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ca_bundle_errors_are_clear() {
        let p = std::env::temp_dir().join(format!("ark-ca-{}.pem", std::process::id()));
        std::fs::write(&p, "not a pem").unwrap();
        assert!(load_ca(p.to_str().unwrap())
            .unwrap_err()
            .contains("no certificates"));
        assert!(load_ca("/nonexistent/ca.pem").is_err());
    }
}
