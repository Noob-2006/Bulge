//! URL policy layer: SSRF classification (Hermes `tools/url_safety.py`) and the
//! user website blocklist (Hermes `tools/website_policy.py`).
//!
//! This module decides; fetchers (web_fetch, browser, media downloads) call it before
//! connecting and again for every redirect hop, and should dial the vetted address
//! ([`resolve_safe`]) to close the DNS-rebinding window.
//!
//! It is the only implementation of the host-level rules too: metadata host names, local
//! names (`localhost`, `*.local`, `*.internal`), legacy/shorthand IPv4 literals, non-canonical
//! IPv6, literal-IP classification and the per-answer DNS check. The web tools keep their
//! policy table (`web::ssrf::SsrfPolicy`) but delegate every decision to [`check_host`],
//! [`check_resolved`] and [`block_reason_with`].

use crate::glob::fnmatch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

/// Shared blocklist files are re-read at most this often (Hermes `_CACHE_TTL_SECONDS`).
const RULES_TTL: Duration = Duration::from_secs(30);

/// `[security]` URL keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UrlPolicy {
    /// Allow private / loopback / CGNAT targets. Cloud metadata stays blocked regardless.
    pub allow_private_urls: bool,
    /// CIDR blocks a local fake-ip TUN proxy answers DNS with (Clash/Mihomo, Surge).
    pub fake_ip_ranges: Vec<String>,
}

/// `[security.website_blocklist]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebsiteBlocklist {
    pub enabled: bool,
    /// Hosts, `*.example.com` globs, or URLs (their host is used).
    pub domains: Vec<String>,
    /// Files with one rule per line (`#` comments); relative paths are under the config dir.
    pub shared_files: Vec<String>,
}

/// Host names that always mean a cloud-metadata endpoint, whatever `allow_private_urls` says
/// (the one list: the web tools, the browser and the media fetchers all read it).
pub const BLOCKED_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata.goog"];
/// Local-only names: refused unless private targets are allowed (OpenClaw `BLOCKED_HOSTNAMES`).
const LOCAL_HOSTS: &[&str] = &["localhost", "localhost.localdomain"];
const LOCAL_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal"];
/// Refusal prefix of a blocked target, shared with the web tools (`ssrf::BLOCKED_MSG`).
pub const BLOCKED_MSG: &str = "Blocked: URL targets a private or internal network address";
const METADATA_V4: &[[u8; 4]] = &[[169, 254, 169, 254], [169, 254, 170, 2], [169, 254, 169, 253], [100, 100, 100, 200]];
const TRUSTED_PRIVATE_HOSTS: &[&str] = &["multimedia.nt.qq.com.cn"];
const PROXY_VARS: &[&str] = &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
const SENSITIVE_QUERY: &[&str] = &[
    "access_token", "api_key", "apikey", "auth_token", "authorization", "awsaccesskeyid", "client_secret", "credential", "credentials", "jwt", "password", "passwd", "secret", "session_id", "signature", "token",
    "x_amz_security_token", "x_amz_signature", "x-amz-security-token", "x-amz-signature",
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (a, p) = s.split_once('/').unwrap_or((s, ""));
        let net: IpAddr = a.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = if p.is_empty() { max } else { p.parse().ok()? };
        (prefix <= max).then_some(Cidr { net, prefix })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let m = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(n) & m) == (u32::from(i) & m)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let m = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from(n) & m) == (u128::from(i) & m)
            }
            _ => false,
        }
    }
    fn overlaps(&self, o: &Cidr) -> bool {
        if self.net.is_ipv4() != o.net.is_ipv4() {
            return false;
        }
        let small = if self.prefix <= o.prefix { self } else { o };
        let big = if self.prefix <= o.prefix { o } else { self };
        small.contains(big.net)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// The IPv4 address an IPv4-mapped (`::ffff:a.b.c.d`) or -translated (`::ffff:0:a.b.c.d`) IPv6 stands for.
pub fn embedded_v4(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
        let s = v6.segments();
        if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
            return IpAddr::V4(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32));
        }
    }
    ip
}

fn in_v4(ip: Ipv4Addr, nets: &[(u32, u8)]) -> bool {
    nets.iter().any(|(n, p)| {
        let m = if *p == 0 { 0 } else { u32::MAX << (32 - p) };
        (u32::from(ip) & m) == (n & m)
    })
}

/// Cloud metadata floor: always blocked, `allow_private_urls` or not.
pub fn is_always_blocked_ip(ip: IpAddr) -> bool {
    match embedded_v4(ip) {
        IpAddr::V4(v4) => METADATA_V4.iter().any(|m| v4.octets() == *m) || in_v4(v4, &[(0xA9FE_0000, 16)]),
        IpAddr::V6(v6) => v6 == "fd00:ec2::254".parse::<Ipv6Addr>().unwrap(),
    }
}

/// Private / internal / reserved classes (Python `ipaddress` is_private|loopback|link_local|reserved|multicast|unspecified, plus CGNAT).
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match embedded_v4(ip) {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || in_v4(v4, &[(0, 8), (0x6440_0000, 10), (0xC000_0000, 24), (0xC612_0000, 15), (0xF000_0000, 4)])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // NAT64 well-known prefix 64:ff9b::/96 (OpenClaw `infra/net/ssrf.ts`): judged by the IPv4 it carries.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return is_blocked_ip(IpAddr::V4(Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32)));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xffc0) == 0xfec0 // site-local (reserved)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol assignments 2001::/23
                || s[0] == 0x2002 // 6to4 2002::/16 can tunnel to any IPv4 (OpenClaw)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // local-use NAT64 64:ff9b:1::/48
                || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // discard 100::/64
                || s[0] < 0x0100 // ::/8 reserved
        }
    }
}

/// Address classes a fake-ip declaration can never excuse (Hermes `_FAKE_IP_UNDECLARABLE_NETWORKS`).
const UNDECLARABLE: &[&str] = &["0.0.0.0/32", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "::/128", "::1/128", "fc00::/7", "fe80::/10"];

/// Declared fake-ip CIDRs that may be dialed: unparseable entries and any overlapping real
/// private space are dropped (`(kept, rejected entries)`). Shared by the security layer and web tools.
pub fn fake_ip_ranges(raw: &[String]) -> (Vec<Cidr>, Vec<String>) {
    let undeclarable: Vec<Cidr> = UNDECLARABLE.iter().filter_map(|c| Cidr::parse(c)).collect();
    let (mut kept, mut rejected) = (vec![], vec![]);
    for r in raw {
        match Cidr::parse(r) {
            Some(c) if !undeclarable.iter().any(|u| u.overlaps(&c)) => kept.push(c),
            _ => rejected.push(r.clone()),
        }
    }
    (kept, rejected)
}

fn fake_ranges(policy: &UrlPolicy) -> Vec<Cidr> {
    fake_ip_ranges(&policy.fake_ip_ranges).0
}

/// Why `ip` must not be dialed, or None.
pub fn block_reason(ip: IpAddr, host: &str, scheme: &str, policy: &UrlPolicy) -> Option<&'static str> {
    block_reason_with(ip, host, scheme, policy, &[])
}

/// Same, plus hosts explicitly allowed to resolve privately (`web.fetch.allowed_hostnames`).
pub fn block_reason_with(ip: IpAddr, host: &str, scheme: &str, policy: &UrlPolicy, allowed_hostnames: &[String]) -> Option<&'static str> {
    if is_always_blocked_ip(ip) {
        return Some("cloud metadata address");
    }
    let allow = policy.allow_private_urls || (scheme == "https" && TRUSTED_PRIVATE_HOSTS.contains(&host)) || allowed_hostnames.iter().any(|h| h == host);
    if !allow && is_blocked_ip(ip) && !fake_ranges(policy).iter().any(|c| c.contains(embedded_v4(ip))) {
        return Some("private/internal address");
    }
    None
}

/// Parsed pieces of an http(s) URL: lower-cased host without brackets or a trailing dot,
/// the port (scheme default applied), path + query without the fragment, and the query alone.
#[derive(Debug, Clone, PartialEq)]
pub struct Parts {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub query: String,
    /// Path + query (no fragment), at least `/`.
    pub path: String,
}

/// Lenient parse for the policy layer (any `scheme://`; it reports its own refusals).
/// None when the URL has no authority or its port is not a number.
pub fn parse(url: &str) -> Option<Parts> {
    split(url, false).ok()
}

/// Same, refusing everything but http(s) with the messages URL-capable tools show the model.
pub fn parse_http(url: &str) -> Result<Parts, String> {
    split(url, true)
}

fn split(url: &str, http_only: bool) -> Result<Parts, String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").ok_or_else(|| "Invalid URL: must be http or https".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if http_only && scheme != "http" && scheme != "https" {
        return Err(format!("Invalid URL: must be http or https (got {scheme}://)"));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let mut path = rest[end..].split('#').next().unwrap_or("").to_string();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or_else(|| "Invalid URL: unterminated IPv6 literal".to_string())?;
        (h.to_string(), Some(after.strip_prefix(':').unwrap_or("").to_string()))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.to_string())),
            None => (hostport.to_string(), None),
        }
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("Invalid URL: no host".into());
    }
    let port = match port.as_deref() {
        None | Some("") => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
        Some(p) => p.parse().map_err(|_| format!("Invalid URL: bad port `{p}`"))?,
    };
    let query = rest.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("").to_string()).unwrap_or_default();
    Ok(Parts { scheme, host, port, query, path })
}

pub type Resolve<'a> = &'a dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String>;

pub fn system_resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    (host, port).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).map_err(|e| e.to_string())
}

/// Is a proxy configured that resolves host names for us? (The web tools delegate here.)
pub fn proxy_configured() -> bool {
    PROXY_VARS.iter().any(|v| std::env::var(v).is_ok_and(|x| !x.is_empty()))
}

/// Validate `url` and return the vetted addresses to dial (every answer is checked).
pub fn resolve_safe(url: &str, policy: &UrlPolicy, resolve: Resolve) -> Result<Vec<IpAddr>, String> {
    let p = parse(url).ok_or_else(|| format!("Blocked request — not a valid URL: {url}"))?;
    if p.scheme != "http" && p.scheme != "https" {
        return Err(format!("Blocked request — unsupported URL scheme: {}", if p.scheme.is_empty() { "<empty>" } else { &p.scheme }));
    }
    if p.host.is_empty() {
        return Err("Blocked request with empty hostname".into());
    }
    // Host names and literal addresses are judged by the same rules the web tools use.
    check_host(&p.host, &p.scheme, &HostPolicy { url: policy, allowed_hostnames: &[], hostname_allowlist: &[], blocked_hostnames: &[] })?;
    let ips = match p.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match resolve(&p.host, p.port) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return Err(format!("Blocked request - DNS returned no results for: {}", p.host)),
            Err(_) if proxy_configured() => return Ok(vec![]), // the proxy resolves
            Err(_) => return Err(format!("Blocked request — DNS resolution failed for: {}", p.host)),
        },
    };
    for ip in &ips {
        if let Some(r) = block_reason(*ip, &p.host, &p.scheme, policy) {
            return Err(format!("Blocked request to {r}: {} -> {ip}", p.host));
        }
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in ips {
        if !out.contains(&ip) && out.len() < 8 {
            out.push(ip);
        }
    }
    Ok(out)
}

pub fn is_safe_url(url: &str, policy: &UrlPolicy) -> Result<(), String> {
    resolve_safe(url, policy, &system_resolve).map(|_| ())
}

/// Metadata floor only (for callers that deliberately allow private targets).
pub fn is_always_blocked_url(url: &str, resolve: Resolve) -> bool {
    let Some(p) = parse(url) else { return false };
    if BLOCKED_HOSTNAMES.contains(&p.host.as_str()) {
        return true;
    }
    match p.host.parse::<IpAddr>() {
        Ok(ip) => is_always_blocked_ip(ip),
        Err(_) => resolve(&p.host, p.port).map(|v| v.into_iter().any(is_always_blocked_ip)).unwrap_or(false),
    }
}

// ───────────── host-level policy (the one SSRF host decision) ─────────────

/// Lower-case a host as it appears in a URL or a config list: no brackets, no trailing dot.
pub fn normalize_host(h: &str) -> String {
    let h = h.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    h.trim_end_matches('.').to_string()
}

/// Does `host` match a domain-policy pattern? `x.com` is exact, `*.x.com` is a subdomain only.
pub fn host_matches(host: &str, pattern: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => !suffix.is_empty() && host != suffix && host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

/// `localhost`, `x.localhost`, `*.local`, `*.internal`: local-only names.
pub fn is_local_hostname(host: &str) -> bool {
    let h = normalize_host(host);
    LOCAL_HOSTS.contains(&h.as_str()) || LOCAL_SUFFIXES.iter().any(|s| h.ends_with(s))
}

/// Legacy / shorthand IPv4 literals (`0x7f.1`, `017700000001`, `2130706433`, `127.1`) are refused
/// outright: resolvers expand them to addresses the canonical parser never sees.
pub fn is_legacy_ipv4_literal(h: &str) -> bool {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() > 4 || h.parse::<Ipv4Addr>().is_ok() {
        return false;
    }
    if parts.iter().any(|p| p.is_empty()) {
        return parts.iter().all(|p| p.is_empty() || p.chars().all(|c| c.is_ascii_digit()) || p.to_ascii_lowercase().starts_with("0x"));
    }
    parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()) || (p.to_ascii_lowercase().starts_with("0x") && p[2..].chars().all(|c| c.is_ascii_hexdigit())))
}

/// Everything a host-level verdict depends on: the address policy plus the three domain lists.
#[derive(Debug, Clone, Copy)]
pub struct HostPolicy<'a> {
    pub url: &'a UrlPolicy,
    /// Exact hosts that may resolve privately.
    pub allowed_hostnames: &'a [String],
    /// Non-empty: only these hosts (`x.com` exact, `*.x.com` subdomains).
    pub hostname_allowlist: &'a [String],
    /// Always refused (`x.com` exact, `*.x.com` subdomains only).
    pub blocked_hostnames: &'a [String],
}

/// Why `ip` (an answer for `host`) may not be dialled, as the message tools show the model.
pub fn ip_block_message(ip: IpAddr, host: &str, scheme: &str, url: &UrlPolicy, allowed_hostnames: &[String]) -> Option<String> {
    let r = block_reason_with(ip, host, scheme, url, allowed_hostnames)?;
    Some(if r == "cloud metadata address" { format!("{BLOCKED_MSG} ({r} {ip})") } else { format!("{BLOCKED_MSG} ({host} -> {ip})") })
}

/// Host-level verdict (no DNS): metadata names, domain lists, literal IPs, local names.
pub fn check_host(host: &str, scheme: &str, p: &HostPolicy) -> Result<(), String> {
    let h = normalize_host(host);
    if h.is_empty() {
        return Err("Blocked: URL has no host".into());
    }
    if BLOCKED_HOSTNAMES.contains(&h.as_str()) {
        return Err(format!("{BLOCKED_MSG} (cloud metadata host {h})"));
    }
    if p.blocked_hostnames.iter().any(|b| host_matches(&h, b)) {
        return Err(format!("Domain policy: Blocked hostname (configured blocklist): {h}. Try a URL on a different domain or ask the operator to review blocked_hostnames."));
    }
    if !p.hostname_allowlist.is_empty() && !p.hostname_allowlist.iter().any(|a| host_matches(&h, a)) {
        return Err(format!("Domain policy: {h} is not in web.fetch.hostname_allowlist"));
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip_block_message(ip, &h, scheme, p.url, p.allowed_hostnames).map_or(Ok(()), Err);
    }
    if h.contains(':') {
        return Err(format!("{BLOCKED_MSG} (malformed IPv6 literal {h})"));
    }
    if is_legacy_ipv4_literal(&h) {
        return Err(format!("{BLOCKED_MSG} (non-canonical IPv4 literal {h})"));
    }
    if is_local_hostname(&h) && !p.url.allow_private_urls && !p.allowed_hostnames.iter().any(|a| a == &h) {
        return Err(format!("{BLOCKED_MSG} (local host name {h})"));
    }
    Ok(())
}

/// Verdict for every address a host resolved to (each DNS answer, each redirect hop).
pub fn check_resolved(host: &str, ips: &[IpAddr], scheme: &str, p: &HostPolicy) -> Result<(), String> {
    for ip in ips {
        if let Some(e) = ip_block_message(*ip, host, scheme, p.url, p.allowed_hostnames) {
            return Err(e);
        }
    }
    Ok(())
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// First credential-named query parameter carrying a value (magic links, OAuth codes, signed URLs).
pub fn sensitive_query_param_name(url: &str) -> Option<String> {
    let p = parse(url)?;
    if (p.scheme != "http" && p.scheme != "https") || p.query.is_empty() {
        return None;
    }
    p.query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, v)| !v.is_empty() && SENSITIVE_QUERY.contains(&pct_decode(k).to_lowercase().as_str())).map(|(k, _)| k.to_string())
}

fn normalize_rule(rule: &str) -> Option<String> {
    let v = rule.trim().to_lowercase();
    if v.is_empty() || v.starts_with('#') {
        return None;
    }
    let v = match v.split_once("://") {
        Some((_, rest)) => rest.split(['/', '?', '#']).next().unwrap_or("").to_string(),
        None => v,
    };
    let v = v.split('/').next().unwrap_or("").trim().trim_end_matches('.');
    let v = v.strip_prefix("www.").unwrap_or(v);
    (!v.is_empty()).then(|| v.to_string())
}

/// (pattern, source) pairs of an enabled blocklist; unreadable shared files are skipped.
pub fn website_rules(bl: &WebsiteBlocklist, config_dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = bl.domains.iter().filter_map(|d| normalize_rule(d)).map(|p| (p, "config".to_string())).collect();
    for f in &bl.shared_files {
        if f.trim().is_empty() {
            continue;
        }
        let path = crate::glob::expand_home(f.trim());
        let path = if Path::new(&path).is_absolute() { std::path::PathBuf::from(path) } else { config_dir.join(path) };
        let src = path.display().to_string();
        out.extend(shared_rules(&path).into_iter().map(|r| (r, src.clone())));
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert(r.clone()));
    out
}

/// Rules of one shared file, cached for [`RULES_TTL`] (a 50-URL batch must not re-read it 50 times).
fn shared_rules(path: &Path) -> Vec<String> {
    /// `path -> (fetched-at, rules)`.
    type RuleCache = HashMap<PathBuf, (Instant, Vec<String>)>;
    static CACHE: Mutex<Option<RuleCache>> = Mutex::new(None);
    let mut g = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    if let Some((t, v)) = map.get(path) {
        if t.elapsed() < RULES_TTL {
            return v.clone();
        }
    }
    let v: Vec<String> = match std::fs::read_to_string(path) {
        Ok(t) => t.trim_start_matches('\u{feff}').lines().filter_map(normalize_rule).collect(),
        Err(e) => {
            eprintln!("ark: website blocklist file {} skipped: {e}", path.display());
            vec![]
        }
    };
    map.insert(path.to_path_buf(), (Instant::now(), v.clone()));
    v
}

/// Process-wide URL policy for fetchers that have no config handle (redirect hops in
/// web_fetch, the egress proxy). Set by `SecurityConfig::activate` / `activate_net`.
#[derive(Debug, Clone, Default)]
struct Global {
    policy: UrlPolicy,
    blocklist: WebsiteBlocklist,
    config_dir: PathBuf,
}

static GLOBAL: RwLock<Option<Global>> = RwLock::new(None);

/// Install the process-wide policy (`config_dir` None keeps the previous one).
pub fn configure(policy: &UrlPolicy, blocklist: &WebsiteBlocklist, config_dir: Option<&Path>) {
    let mut g = GLOBAL.write().unwrap_or_else(|p| p.into_inner());
    let prev_dir = g.as_ref().map(|x| x.config_dir.clone()).unwrap_or_default();
    *g = Some(Global { policy: policy.clone(), blocklist: blocklist.clone(), config_dir: config_dir.map(Path::to_path_buf).unwrap_or(prev_dir) });
}

/// The process-wide SSRF policy (secure default when never configured).
pub fn global_policy() -> UrlPolicy {
    GLOBAL.read().unwrap_or_else(|p| p.into_inner()).as_ref().map(|g| g.policy.clone()).unwrap_or_default()
}

/// Website blocklist check against the process-wide policy.
pub fn check_website_global(url: &str) -> Option<String> {
    let g = GLOBAL.read().unwrap_or_else(|p| p.into_inner()).clone()?;
    check_website_access(url, &g.blocklist, &g.config_dir)
}

/// Hermes' agent-facing message for an SSRF refusal (`why` = [`resolve_safe`]'s error).
pub fn ssrf_message(why: &str) -> String {
    if why.contains("private") || why.contains("metadata") || why.contains("internal") {
        format!("Blocked: URL targets a private or internal network address ({why}). Do not retry this URL; set security.allow_private_urls = true only for trusted local services.")
    } else {
        format!("Blocked: {why}")
    }
}

/// Full check of one URL (initial request or redirect hop) against the process-wide
/// policy: website blocklist, then SSRF (every resolved address; DNS failure fails closed).
pub fn check_url_global(url: &str, resolve: Resolve) -> Result<(), String> {
    if let Some(m) = check_website_global(url) {
        return Err(m);
    }
    resolve_safe(url, &global_policy(), resolve).map(|_| ()).map_err(|e| ssrf_message(&e))
}

/// Blocklist rule match (Hermes `website_policy`): an exact rule also covers its subdomains,
/// `*.x.com` is a glob.
fn rule_matches(host: &str, pattern: &str) -> bool {
    if host.is_empty() || pattern.is_empty() {
        return false;
    }
    if pattern.starts_with("*.") {
        return fnmatch(pattern, host);
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// Block message when `url`'s host matches the user blocklist.
pub fn check_website_access(url: &str, bl: &WebsiteBlocklist, config_dir: &Path) -> Option<String> {
    if !bl.enabled {
        return None;
    }
    let host = match parse(url) {
        Some(p) if !p.host.is_empty() => p.host,
        _ => parse(&format!("http://{url}"))?.host,
    };
    let host = host.strip_prefix("www.").map(String::from).unwrap_or(host);
    website_rules(bl, config_dir).into_iter().find(|(p, _)| rule_matches(&host, p)).map(|(p, src)| format!("Blocked by website policy: '{host}' matched rule '{p}' from {src}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(map: &'static [(&'static str, &'static str)]) -> impl Fn(&str, u16) -> Result<Vec<IpAddr>, String> {
        move |h: &str, _| map.iter().filter(|(n, _)| *n == h).map(|(_, ip)| ip.parse().map_err(|_| "bad".to_string())).collect::<Result<Vec<_>, _>>().and_then(|v| if v.is_empty() { Err("NXDOMAIN".into()) } else { Ok(v) })
    }

    #[test]
    fn private_and_metadata_targets_are_blocked() {
        let r = fake(&[("example.com", "93.184.216.34"), ("intranet.corp", "10.1.2.3"), ("rebind.evil", "93.1.1.1"), ("rebind.evil", "127.0.0.1"), ("cg.nat", "100.72.1.1"), ("mapped.evil", "::ffff:169.254.169.254")]);
        let p = UrlPolicy::default();
        assert!(resolve_safe("https://example.com/x", &p, &r).is_ok());
        for u in ["http://127.0.0.1:8080/", "http://intranet.corp/", "http://rebind.evil/", "http://[::1]/", "http://cg.nat/", "http://169.254.169.254/latest/meta-data", "http://metadata.google.internal/", "http://mapped.evil/", "http://[::ffff:10.0.0.1]/", "http://0.0.0.0/", "ftp://example.com/", "http://nxdomain.test/"] {
            assert!(resolve_safe(u, &p, &r).is_err(), "{u}");
        }
        let open = UrlPolicy { allow_private_urls: true, ..Default::default() };
        assert!(resolve_safe("http://intranet.corp/", &open, &r).is_ok());
        assert!(resolve_safe("http://169.254.169.254/", &open, &r).unwrap_err().contains("cloud metadata"), "metadata floor ignores allow_private_urls");
        assert!(is_always_blocked_url("http://mapped.evil/", &r) && !is_always_blocked_url("http://intranet.corp/", &r));
        // NAT64 is judged by the embedded IPv4; 6to4 and local-use NAT64 are always internal.
        for (ip, blocked) in [("64:ff9b::a00:1", true), ("64:ff9b::808:808", false), ("2002:808:808::1", true), ("64:ff9b:1::1", true), ("2606:4700::1111", false)] {
            assert_eq!(is_blocked_ip(ip.parse().unwrap()), blocked, "{ip}");
        }
        let (kept, rejected) = fake_ip_ranges(&["198.18.0.0/15".into(), "10.0.0.0/8".into(), "junk".into()]);
        assert_eq!((kept.len(), rejected), (1, vec!["10.0.0.0/8".to_string(), "junk".to_string()]));
    }

    #[test]
    fn fake_ip_ranges_are_dialable_but_cannot_cover_real_private_space() {
        let r = fake(&[("proxied.example", "198.18.0.7")]);
        assert!(resolve_safe("https://proxied.example/", &UrlPolicy::default(), &r).is_err(), "benchmark range is private");
        let p = UrlPolicy { fake_ip_ranges: vec!["198.18.0.0/15".into(), "10.0.0.0/8".into(), "0.0.0.0/0".into()], ..Default::default() };
        assert!(resolve_safe("https://proxied.example/", &p, &r).is_ok());
        assert!(resolve_safe("http://10.0.0.1/", &p, &r).is_err(), "undeclarable ranges are dropped");
    }

    #[test]
    fn url_parsing_and_sensitive_params() {
        assert_eq!(
            parse("https://u:p@API.Example.com:8443/x?y=1#f").unwrap(),
            Parts { scheme: "https".into(), host: "api.example.com".into(), port: 8443, query: "y=1".into(), path: "/x?y=1".into() }
        );
        assert_eq!(parse("http://[fe80::1]:81/").unwrap().host, "fe80::1");
        assert_eq!(parse("http://a.b").unwrap().path, "/", "a bare host still has a path");
        assert!(parse("http://a.com:x/").is_none() && parse("ftp://x").is_some(), "lenient about the scheme, not the port");
        assert!(parse_http("ftp://x").unwrap_err().contains("must be http or https"));
        assert_eq!(sensitive_query_param_name("https://x.io/cb?code=1&access_token=abc").as_deref(), Some("access_token"));
        assert_eq!(sensitive_query_param_name("https://x.io/?api%5Fkey=v").as_deref(), Some("api%5Fkey"));
        assert!(sensitive_query_param_name("https://x.io/?key=1&code=2").is_none(), "facet words are not credentials");
        assert!(sensitive_query_param_name("https://x.io/?token=").is_none());
    }

    #[test]
    fn website_blocklist_rules() {
        let dir = ark_core::tmp::scratch_path(format!("ark-wb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("shared.txt"), "# comment\nhttps://www.Tracker.io/path\n\n").unwrap();
        let bl = WebsiteBlocklist { enabled: true, domains: vec!["evil.com".into(), "*.ads.net".into()], shared_files: vec!["shared.txt".into(), "missing.txt".into()] };
        assert!(check_website_access("https://evil.com/a", &bl, &dir).unwrap().contains("'evil.com' matched rule 'evil.com' from config"));
        assert!(check_website_access("https://sub.evil.com", &bl, &dir).is_some(), "parent domain");
        assert!(check_website_access("x.ads.net/p", &bl, &dir).is_some(), "schemeless input");
        assert!(check_website_access("https://ads.net", &bl, &dir).is_none(), "*. needs a subdomain");
        assert!(check_website_access("https://tracker.io", &bl, &dir).unwrap().contains("shared.txt"));
        assert!(check_website_access("https://notevil.com", &bl, &dir).is_none());
        assert!(check_website_access("https://evil.com", &WebsiteBlocklist { enabled: false, ..bl.clone() }, &dir).is_none());
    }
}
