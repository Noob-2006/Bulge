//! SSRF protection for URLs the model chooses (Hermes `tools/url_safety.py`, OpenClaw
//! `infra/net/ssrf.ts`). Blocks private / loopback / link-local / CGNAT / reserved /
//! multicast / special-use targets by name, by literal IP and after DNS resolution.
//! Cloud metadata endpoints are blocked even with `allow_private_urls`. The check runs
//! again at connect time (`GuardResolver`, closing DNS rebinding) and on every redirect.
//!
//! Every decision is made by `ark_security::url_safety` (host tables, literal-IP
//! classification, address classes). This module only holds the web tools' policy
//! (`SsrfPolicy`), the connect-time guard and redirect handling.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

pub use ark_security::url_safety::Cidr;
pub use ark_security::url_safety::{normalize_host, BLOCKED_MSG};
use ark_security::url_safety as safety;
use ark_security::url_safety::{HostPolicy, UrlPolicy};

#[derive(Debug, Clone, Default)]
pub struct SsrfPolicy {
    /// `web.allow_private_urls` (or `ARK_ALLOW_PRIVATE_URLS=1`): private ranges allowed, metadata still blocked.
    pub allow_private: bool,
    /// Declared fake-ip blocks (overlaps with real private space are dropped).
    pub fake_ip: Vec<Cidr>,
    /// Exact hosts that may resolve privately.
    pub allowed_hostnames: Vec<String>,
    /// Non-empty: only these hosts (`x.com` exact, `*.x.com` subdomains).
    pub hostname_allowlist: Vec<String>,
    /// Always refused (`x.com` exact, `*.x.com` subdomains only).
    pub blocked_hostnames: Vec<String>,
}

impl SsrfPolicy {
    pub fn from_config(cfg: &super::WebConfig) -> SsrfPolicy {
        // `[security]` (the process-wide policy) and `[web]` both count: either may open private space.
        let global = safety::global_policy();
        let env_allow = std::env::var("ARK_ALLOW_PRIVATE_URLS").ok().map(|v| v.trim().to_ascii_lowercase());
        let allow_private = match env_allow.as_deref() {
            Some("1" | "true" | "yes") => true,
            Some("0" | "false" | "no") => false,
            _ => cfg.allow_private_urls || global.allow_private_urls,
        };
        let mut fake = cfg.fake_ip_ranges.clone();
        fake.extend(global.fake_ip_ranges.iter().filter(|r| !cfg.fake_ip_ranges.contains(r)).cloned());
        let norm = |v: &[String]| v.iter().map(|h| normalize_host(h)).filter(|h| !h.is_empty() && h != "*" && h != "*.").collect::<Vec<_>>();
        SsrfPolicy {
            allow_private,
            fake_ip: parse_fake_ip_ranges(&fake),
            allowed_hostnames: norm(&cfg.fetch.allowed_hostnames),
            hostname_allowlist: norm(&cfg.fetch.hostname_allowlist),
            blocked_hostnames: norm(&cfg.fetch.blocked_hostnames),
        }
    }
    /// Policy for operator-configured self-hosted endpoints (SearXNG, Firecrawl self-host, Ollama).
    pub fn self_hosted() -> SsrfPolicy {
        SsrfPolicy { allow_private: true, ..Default::default() }
    }
    /// The shared policy `ark_security::url_safety` judges with (one classifier for the runtime).
    fn url_policy(&self) -> UrlPolicy {
        UrlPolicy { allow_private_urls: self.allow_private, fake_ip_ranges: self.fake_ip.iter().map(|c| c.to_string()).collect() }
    }
    /// Run `f` with this policy's host-level rules (`HostPolicy`).
    fn with_hosts<R>(&self, f: impl FnOnce(&HostPolicy) -> R) -> R {
        let url = self.url_policy();
        f(&HostPolicy { url: &url, allowed_hostnames: &self.allowed_hostnames, hostname_allowlist: &self.hostname_allowlist, blocked_hostnames: &self.blocked_hostnames })
    }
}

pub fn parse_fake_ip_ranges(raw: &[String]) -> Vec<Cidr> {
    let (kept, rejected) = safety::fake_ip_ranges(raw);
    for e in rejected {
        eprintln!("ark: ignoring fake_ip_ranges entry {e:?}: unparseable, or it overlaps a private range, which stays blocked");
    }
    kept
}

/// Cloud metadata floor (blocked even with `allow_private_urls`).
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    safety::is_always_blocked_ip(ip)
}

/// Private / internal / special-use: not a public internet target.
pub fn is_private_ip(ip: IpAddr) -> bool {
    safety::is_blocked_ip(ip)
}

/// Why `ip` (an answer for `host`) may not be dialled, or None.
pub fn ip_block_reason(ip: IpAddr, host: &str, https: bool, p: &SsrfPolicy) -> Option<String> {
    p.with_hosts(|hp| safety::ip_block_message(ip, host, if https { "https" } else { "http" }, hp.url, hp.allowed_hostnames))
}

/// Host-level verdict (no DNS): names, literal IPs, allow/block lists.
pub fn check_host(host: &str, https: bool, p: &SsrfPolicy) -> Result<(), String> {
    p.with_hosts(|hp| safety::check_host(host, if https { "https" } else { "http" }, hp))
}

/// Parsed pieces of an http(s) URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path + query (no fragment), at least `/`.
    pub path: String,
}

pub fn parse_url(url: &str) -> Result<UrlParts, String> {
    let p = safety::parse_http(url)?;
    Ok(UrlParts { scheme: p.scheme, host: p.host, port: p.port, path: p.path })
}

/// Full pre-flight check: scheme, host policy, then every DNS answer.
/// With a proxy configured and DNS failing, resolution is delegated to the proxy (Hermes).
pub fn check_url(url: &str, p: &SsrfPolicy) -> Result<UrlParts, String> {
    let u = parse_url(url)?;
    let https = u.scheme == "https";
    check_host(&u.host, https, p)?;
    if u.host.parse::<IpAddr>().is_ok() {
        return Ok(u);
    }
    match (u.host.as_str(), u.port).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                return Err(format!("Blocked: DNS returned no results for {}", u.host));
            }
            p.with_hosts(|hp| safety::check_resolved(&u.host, &ips, &u.scheme, hp))?;
            Ok(u)
        }
        Err(_) if proxy_configured() => Ok(u),
        Err(e) => Err(format!("Blocked: DNS resolution failed for {}: {e}", u.host)),
    }
}

/// Is a proxy configured? (`ark_security::url_safety` owns the variable list.)
pub use ark_security::url_safety::proxy_configured;

/// Connect-time guard: resolves, validates every answer, dials only vetted addresses.
#[derive(Debug, Clone)]
pub struct GuardResolver {
    pub policy: Arc<SsrfPolicy>,
    /// Proxy host: resolved without checks (the proxy resolves the real target).
    pub proxy_host: Option<String>,
}

impl ureq::unversioned::resolver::Resolver for GuardResolver {
    fn resolve(&self, uri: &ureq::http::Uri, config: &ureq::config::Config, timeout: ureq::unversioned::transport::NextTimeout) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let inner = ureq::unversioned::resolver::DefaultResolver::default();
        let host = normalize_host(uri.host().unwrap_or(""));
        if self.proxy_host.as_deref() == Some(host.as_str()) {
            return inner.resolve(uri, config, timeout);
        }
        let scheme = if uri.scheme_str() == Some("https") { "https" } else { "http" };
        let policy = &self.policy;
        policy.with_hosts(|hp| safety::check_host(&host, scheme, hp)).map_err(blocked)?;
        let addrs = inner.resolve(uri, config, timeout)?;
        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        policy.with_hosts(|hp| safety::check_resolved(&host, &ips, scheme, hp)).map_err(blocked)?;
        Ok(addrs)
    }
}

fn blocked(msg: String) -> ureq::Error {
    ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg))
}

/// A ureq agent whose every connection passes the SSRF guard. Redirects are not followed
/// (callers follow them by hand so each hop meets the host policy too).
pub fn guarded_agent(policy: Arc<SsrfPolicy>, timeout_secs: u64) -> ureq::Agent {
    let cfg = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(timeout_secs.max(1)))).http_status_as_error(false).max_redirects(0).build();
    let proxy_host = cfg.proxy().map(|p| normalize_host(p.host()));
    ureq::Agent::with_parts(cfg, ureq::unversioned::transport::DefaultConnector::default(), GuardResolver { policy, proxy_host })
}

/// Follow redirects with HEAD requests under the guard; the final URL (OpenClaw
/// `resolveCitationRedirectUrl`). Any failure returns the input unchanged.
pub fn resolve_redirect(url: &str, policy: Arc<SsrfPolicy>, timeout_secs: u64) -> String {
    let agent = guarded_agent(policy.clone(), timeout_secs);
    let mut cur = url.to_string();
    for _ in 0..5 {
        let Ok(u) = parse_url(&cur) else { return url.to_string() };
        if check_host(&u.host, u.scheme == "https", &policy).is_err() {
            return url.to_string();
        }
        let Ok(r) = agent.head(&cur).call() else { return url.to_string() };
        if !r.status().is_redirection() {
            return cur;
        }
        let Some(loc) = r.headers().get("location").and_then(|l| l.to_str().ok()) else { return cur };
        cur = join_url(&cur, loc);
    }
    url.to_string()
}

/// Text of a ureq error, unwrapping our own block messages.
pub fn error_text(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => io.to_string(),
        other => other.to_string(),
    }
}

pub fn is_block_error(e: &ureq::Error) -> bool {
    matches!(e, ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied && io.to_string().contains("Blocked"))
}

/// Resolve `location` against `base` (absolute, scheme-relative, absolute-path, relative).
pub fn join_url(base: &str, location: &str) -> String {
    let loc = location.trim();
    if loc.contains("://") {
        return loc.to_string();
    }
    let Ok(b) = parse_url(base) else { return loc.to_string() };
    let default_port = if b.scheme == "https" { 443 } else { 80 };
    let host = if b.host.contains(':') { format!("[{}]", b.host) } else { b.host.clone() };
    let origin = if b.port == default_port { format!("{}://{host}", b.scheme) } else { format!("{}://{host}:{}", b.scheme, b.port) };
    if let Some(r) = loc.strip_prefix("//") {
        return format!("{}://{r}", b.scheme);
    }
    if loc.starts_with('/') {
        return format!("{origin}{loc}");
    }
    let dir = b.path.split('?').next().unwrap_or("/");
    let dir = &dir[..dir.rfind('/').map(|i| i + 1).unwrap_or(1)];
    if loc.starts_with('?') {
        return format!("{origin}{}{loc}", b.path.split('?').next().unwrap_or("/"));
    }
    format!("{origin}{dir}{loc}")
}

// ── URL hygiene (Hermes normalize_url_for_request / sensitive params / secret prefixes) ──

/// ASCII-safe URL: repairs `https:// host`, IDNA-encodes the host, percent-encodes non-ASCII
/// path/query/fragment text while keeping existing escapes.
pub fn normalize_url_for_request(url: &str) -> String {
    let raw = url.trim();
    let raw = match raw.find("://") {
        Some(i) => format!("{}://{}", &raw[..i], raw[i + 3..].trim_start()),
        None => return raw.to_string(),
    };
    let Some(i) = raw.find("://") else { return raw };
    let scheme = &raw[..i];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return raw;
    }
    let rest = &raw[i + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = match authority.rsplit_once('@') {
        Some((user, hp)) => format!("{user}@{}", idna_host_port(hp)),
        None => idna_host_port(authority),
    };
    let mut out = format!("{scheme}://{authority}");
    for c in tail.chars() {
        if c.is_ascii() && !c.is_ascii_control() && c != ' ' {
            out.push(c);
        } else {
            let mut b = [0u8; 4];
            for byte in c.encode_utf8(&mut b).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

fn idna_host_port(hp: &str) -> String {
    if hp.starts_with('[') || hp.is_ascii() {
        return hp.to_string();
    }
    let (h, p) = match hp.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (hp, None),
    };
    let host = h.split('.').map(|l| if l.is_ascii() { l.to_string() } else { format!("xn--{}", punycode(&l.to_lowercase())) }).collect::<Vec<_>>().join(".");
    match p {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// RFC 3492 Punycode encoder.
pub fn punycode(input: &str) -> String {
    let (base, tmin, tmax, skew, damp) = (36u32, 1u32, 26u32, 38u32, 700u32);
    let cps: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut out: String = input.chars().filter(|c| c.is_ascii()).collect();
    let b = out.len() as u32;
    if b > 0 {
        out.push('-');
    }
    let digit = |d: u32| -> char { if d < 26 { (b'a' + d as u8) as char } else { (b'0' + (d - 26) as u8) as char } };
    let adapt = |mut delta: u32, num: u32, first: bool| -> u32 {
        delta = if first { delta / damp } else { delta / 2 };
        delta += delta / num;
        let mut k = 0;
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= base - tmin;
            k += base;
        }
        k + (base - tmin + 1) * delta / (delta + skew)
    };
    let (mut n, mut delta, mut bias, mut h) = (128u32, 0u32, 72u32, b);
    while (h as usize) < cps.len() {
        let m = cps.iter().copied().filter(|&c| c >= n).min().unwrap_or(n);
        delta = delta.saturating_add((m - n).saturating_mul(h + 1));
        n = m;
        for &c in &cps {
            if c < n {
                delta += 1;
            }
            if c == n {
                let mut q = delta;
                let mut k = base;
                loop {
                    let t = if k <= bias { tmin } else if k >= bias + tmax { tmax } else { k - bias };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (base - t)));
                    q = (q - t) / (base - t);
                    k += base;
                }
                out.push(digit(q));
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    out
}

/// First credential-named query parameter (with a value), decoded and lower-cased
/// (the list lives in `ark_security::url_safety`).
pub fn sensitive_query_param(url: &str) -> Option<String> {
    safety::sensitive_query_param_name(url).map(|k| percent_decode(&k).to_ascii_lowercase())
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%'));
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Known credential prefixes (Hermes `agent/redact.py` `_PREFIX_PATTERNS`).
pub fn contains_secret(s: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        let pats = [
            r"sk-[A-Za-z0-9_-](?:\.?[A-Za-z0-9_-]){9,}", r"ghp_[A-Za-z0-9]{10,}", r"github_pat_[A-Za-z0-9_]{10,}", r"gh[ousr]_[A-Za-z0-9]{10,}", r"xapp-\d+-[A-Za-z0-9-]{10,}", r"xox[baprs]-[A-Za-z0-9-]{10,}",
            r"AIza[A-Za-z0-9_-]{30,}", r"pplx-[A-Za-z0-9]{10,}", r"fal_[A-Za-z0-9_-]{10,}", r"fc-[A-Za-z0-9]{10,}", r"bb_live_[A-Za-z0-9_-]{10,}", r"gAAAA[A-Za-z0-9_=-]{20,}", r"AKIA[A-Z0-9]{16}",
            r"[sr]k_live_[A-Za-z0-9]{10,}", r"sk_test_[A-Za-z0-9]{10,}", r"SG\.[A-Za-z0-9_-]{10,}", r"hf_[A-Za-z0-9]{10,}", r"r8_[A-Za-z0-9]{10,}", r"npm_[A-Za-z0-9]{10,}", r"pypi-[A-Za-z0-9_-]{10,}",
            r"do[po]_v1_[A-Za-z0-9]{10,}", r"am_(?:org_)?[A-Za-z0-9]{20,}", r"sk_[A-Za-z0-9_]{10,}", r"tvly-[A-Za-z0-9]{10,}", r"exa_[A-Za-z0-9]{10,}", r"gsk_[A-Za-z0-9]{10,}", r"syt_[A-Za-z0-9]{10,}",
            r"xai-[A-Za-z0-9]{30,}", r"ntn_[A-Za-z0-9]{10,}", r"fw[-_][A-Za-z0-9]{30,}", r"fpk_[A-Za-z0-9]{30,}", r"glpat-[A-Za-z0-9_-]{20,}", r"BSA[A-Za-z0-9_-]{20,}",
        ];
        regex::Regex::new(&format!(r"(?:^|[^A-Za-z0-9_-])(?:{})(?:$|[^A-Za-z0-9_-])", pats.join("|"))).unwrap()
    });
    re.is_match(s)
}

/// Whole-call refusal for URLs carrying secrets (raw, decoded and normalised forms).
pub fn url_secret_refusal(url: &str) -> Option<String> {
    let norm = normalize_url_for_request(url);
    if [url.to_string(), percent_decode(url), norm.clone(), percent_decode(&norm)].iter().any(|u| contains_secret(u)) {
        return Some("Blocked: URL contains what appears to be an API key or token. Secrets must not be sent in URLs.".into());
    }
    None
}

/// Loopback/private/LAN hosts by name only (cache freshness, not security).
pub fn is_local_dev_url(url: &str) -> bool {
    let Ok(u) = parse_url(url) else { return true };
    let h = u.host;
    if safety::is_local_hostname(&h) || (!h.contains('.') && !h.contains(':')) {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => is_private_ip(ip) || is_metadata_ip(ip),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> SsrfPolicy {
        SsrfPolicy::default()
    }

    #[test]
    fn private_and_metadata_ips() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0", "198.18.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:0:10.0.0.1", "64:ff9b::a00:1"] {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "64:ff9b::808:808"] {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["169.254.169.254", "169.254.1.1", "::ffff:169.254.169.254", "fd00:ec2::254", "100.100.100.200"] {
            assert!(is_metadata_ip(ip.parse().unwrap()), "{ip}");
        }
        // Metadata stays blocked with allow_private; plain private does not.
        let open = SsrfPolicy { allow_private: true, ..p() };
        assert!(ip_block_reason("169.254.169.254".parse().unwrap(), "x", false, &open).unwrap().contains("metadata"));
        assert!(ip_block_reason("10.0.0.1".parse().unwrap(), "x", false, &open).is_none());
        assert!(ip_block_reason("10.0.0.1".parse().unwrap(), "x", false, &p()).is_some());
        assert!(ip_block_reason("198.18.0.5".parse().unwrap(), "multimedia.nt.qq.com.cn", true, &p()).is_none());
        assert!(ip_block_reason("198.18.0.5".parse().unwrap(), "multimedia.nt.qq.com.cn", false, &p()).is_some());
    }

    #[test]
    fn host_policy() {
        for h in ["localhost", "a.localhost", "printer.local", "db.internal", "metadata.google.internal", "127.0.0.1", "[::1]", "0x7f.1", "2130706433", "127.1", "017700000001", "1.2.3.4.5:x"] {
            assert!(check_host(h, false, &p()).is_err(), "{h}");
        }
        assert!(check_host("example.com", false, &p()).is_ok());
        let open = SsrfPolicy { allow_private: true, ..p() };
        assert!(check_host("localhost", false, &open).is_ok());
        assert!(check_host("metadata.google.internal", false, &open).is_err());
        let lists = SsrfPolicy { blocked_hostnames: vec!["*.evil.com".into(), "bad.org".into()], hostname_allowlist: vec![], ..p() };
        assert!(check_host("a.evil.com", false, &lists).unwrap_err().contains("blocklist"));
        assert!(check_host("evil.com", false, &lists).is_ok(), "*. excludes the apex");
        assert!(check_host("bad.org", false, &lists).is_err());
        let allow = SsrfPolicy { hostname_allowlist: vec!["docs.rs".into(), "*.rust-lang.org".into()], ..p() };
        assert!(check_host("docs.rs", false, &allow).is_ok() && check_host("www.rust-lang.org", false, &allow).is_ok());
        assert!(check_host("example.com", false, &allow).is_err());
        let named = SsrfPolicy { allowed_hostnames: vec!["localhost".into()], ..p() };
        assert!(check_host("localhost", false, &named).is_ok());
    }

    /// Reason class of a refusal, so the web layer and the policy layer can be compared
    /// without pinning either message wording.
    fn reason_class(msg: &str) -> &'static str {
        if msg.contains("metadata") {
            "metadata"
        } else if msg.contains("non-canonical") || msg.contains("legacy") {
            "literal"
        } else if msg.contains("local host") {
            "local"
        } else if msg.contains("private") || msg.contains("internal") {
            "private"
        } else {
            "other"
        }
    }

    /// The web tools and the policy layer (`ark_security::url_safety`) must reach the same
    /// verdict *and* the same reason class for the same URL — one implementation, no drift.
    /// Literal hosts and local names only, so no DNS is involved.
    #[test]
    fn web_and_policy_layer_agree_on_the_same_urls() {
        let no_dns = |_h: &str, _p: u16| -> Result<Vec<IpAddr>, String> { Err("NXDOMAIN".into()) };
        let strict = UrlPolicy::default();
        let cases: &[(&str, bool, &str)] = &[
            ("http://127.0.0.1/", false, "private"),
            ("http://10.1.2.3/x", false, "private"),
            ("http://192.168.0.1/", false, "private"),
            ("http://100.64.0.1/", false, "private"),
            ("http://169.254.169.254/latest/meta-data", false, "metadata"),
            ("http://169.254.170.2/", false, "metadata"),
            ("http://[fd00:ec2::254]/", false, "metadata"),
            ("http://[::ffff:169.254.169.254]/", false, "metadata"),
            ("http://localhost:9/", false, "local"),
            ("http://printer.local/", false, "local"),
            ("http://db.internal/", false, "local"),
            ("http://metadata.google.internal/", false, "metadata"),
            ("http://0x7f.1/", false, "literal"),
            ("http://2130706433/", false, "literal"),
            ("http://017700000001/", false, "literal"),
            ("http://[fe80::1]/", false, "private"),
            ("http://93.184.216.34/", true, ""),
            ("https://[2606:4700::1111]/", true, ""),
        ];
        for (url, allow, class) in cases {
            let web = check_url(url, &p());
            let pol = safety::resolve_safe(url, &strict, &no_dns);
            assert_eq!(web.is_ok(), *allow, "{url}: web {web:?}");
            assert_eq!(pol.is_ok(), *allow, "{url}: policy {pol:?}");
            if !allow {
                assert_eq!(reason_class(&web.unwrap_err()), *class, "{url}: web");
                assert_eq!(reason_class(&pol.unwrap_err()), *class, "{url}: policy");
            }
        }
        // `allow_private` opens the same set on both sides; the metadata floor never opens.
        let open = SsrfPolicy { allow_private: true, ..p() };
        let open_pol = UrlPolicy { allow_private_urls: true, ..UrlPolicy::default() };
        for (url, allow) in [("http://127.0.0.1/", true), ("http://10.0.0.1/", true), ("http://169.254.169.254/", false), ("http://[fd00:ec2::254]/", false)] {
            assert_eq!(check_url(url, &open).is_ok(), allow, "{url}: web (allow_private)");
            assert_eq!(safety::resolve_safe(url, &open_pol, &no_dns).is_ok(), allow, "{url}: policy (allow_private_urls)");
        }
        // The website blocklist is one gate too: `[web.blocklist]` and `[security.website_blocklist]`
        // produce the identical refusal, because both call `url_safety::check_website_access`.
        let home = crate::testutil::tmpdir("ssrf-blocklist");
        let web_cfg = super::super::config::BlocklistConfig { enabled: true, domains: vec!["evil.com".into(), "*.ads.net".into()], shared_files: vec![] };
        let sec_bl = safety::WebsiteBlocklist { enabled: true, domains: vec!["evil.com".into(), "*.ads.net".into()], shared_files: vec![] };
        for url in ["https://sub.evil.com/x", "https://x.ads.net/y"] {
            let web = super::super::policy::check(&web_cfg, &home, url);
            assert_eq!(web, safety::check_website_access(url, &sec_bl, &home), "{url}");
            assert!(web.is_some(), "{url} must be blocked by both");
        }
        assert!(super::super::policy::check(&web_cfg, &home, "https://example.com/").is_none());
    }

    #[test]
    fn fake_ip_ranges() {
        let r = parse_fake_ip_ranges(&["198.18.0.0/15".into(), "10.0.0.0/8".into(), "0.0.0.0/0".into(), "junk".into()]);
        assert_eq!(r.len(), 1);
        let pol = SsrfPolicy { fake_ip: r, ..p() };
        assert!(ip_block_reason("198.18.3.4".parse().unwrap(), "x.com", false, &pol).is_none());
        assert!(ip_block_reason("10.0.0.1".parse().unwrap(), "x.com", false, &pol).is_some());
        assert!(Cidr::parse("fc00::/7").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
    }

    #[test]
    fn urls() {
        let u = parse_url("https://user:pw@Example.COM:8443/p?q=1#frag").unwrap();
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port, u.path.as_str()), ("https", "example.com", 8443, "/p?q=1"));
        assert_eq!(parse_url("http://[::1]/").unwrap().host, "::1");
        assert_eq!(parse_url("http://a.b").unwrap().path, "/");
        assert!(parse_url("ftp://x").is_err() && parse_url("http:///x").is_err());
        assert!(check_url("http://127.0.0.1:9/", &p()).is_err());
        assert!(check_url("http://localhost:9/", &p()).is_err());
        assert!(check_url("http://127.0.0.1:9/", &SsrfPolicy { allow_private: true, ..p() }).is_ok());
        assert_eq!(join_url("https://a.com/x/y?z", "/r"), "https://a.com/r");
        assert_eq!(join_url("https://a.com/x/y", "z"), "https://a.com/x/z");
        assert_eq!(join_url("https://a.com:8443/x", "//b.com/q"), "https://b.com/q");
        assert_eq!(join_url("http://a.com:81/x", "?q"), "http://a.com:81/x?q");
        assert_eq!(join_url("https://a.com/", "http://b/"), "http://b/");
    }

    #[test]
    fn hygiene() {
        assert_eq!(punycode("bücher"), "bcher-kva");
        assert_eq!(punycode("例え"), "r8jz45g");
        assert_eq!(normalize_url_for_request("https:// wttr.in/Köln"), "https://wttr.in/K%C3%B6ln");
        assert_eq!(normalize_url_for_request("https://bücher.de/a%20b"), "https://xn--bcher-kva.de/a%20b");
        assert_eq!(sensitive_query_param("https://x.com/cb?code=1&access_token=abc").as_deref(), Some("access_token"));
        assert!(sensitive_query_param("https://x.com/?token=").is_none());
        assert!(sensitive_query_param("https://x.com/?key=v").is_none());
        assert!(url_secret_refusal("https://x.com/?k=sk-abcdefghijklmnop").is_some());
        assert!(url_secret_refusal("https://x.com/?k=tvly%2Dabcdefghijkl").is_some());
        assert!(url_secret_refusal("https://example.com/sk-short").is_none());
        assert_eq!(percent_decode("a%20b+c%zz"), "a b c%zz");
        assert!(is_local_dev_url("http://localhost:3000/") && is_local_dev_url("http://nas/") && is_local_dev_url("http://10.0.0.2/"));
        assert!(!is_local_dev_url("https://example.com/"));
    }

    #[test]
    fn guard_resolver_blocks_at_connect() {
        let agent = guarded_agent(Arc::new(p()), 5);
        let e = agent.get("http://127.0.0.1:9/").call().unwrap_err();
        assert!(is_block_error(&e), "{e}");
        assert!(error_text(&e).contains("Blocked"));
    }
}
