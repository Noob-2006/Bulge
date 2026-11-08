//! Public-exposure guard (GAPS-next A8–A12): every listening surface must be loopback by
//! default and, when it is not, carry two independent layers (transport + strong auth),
//! an origin restriction and a rate limit — or seagent refuses to start it.
//!
//! The rules are IO-free and take primitives only, so the app server (which refuses to
//! start), `seagent security audit` (which reports) and `seagent doctor` (which warns) all judge a
//! surface with the exact same [`check`].
//!
//! How this stays out of the way of unattended work (GAPS-next §0): none of it asks a
//! human anything at runtime. A loopback surface — the default for every surface — passes
//! untouched; only an operator who has already written a non-loopback bind address in the
//! config sees an error, and the fix is a config key, not a prompt. Rate limiting throttles
//! abusers, it does not stop a task that is working normally.
//!
//! ```text
//! non-loopback  →  allow_public = true            (A8: explicit opt-in)
//!               →  tls || behind_proxy            (A9 layer 1: encrypted transport)
//!               →  Provider | Device              (A9 layer 2: beyond a bearer string)
//!               →  origins, no "*"                (A9 layer 3: origin restriction)
//!               →  rate_limit                     (A9 layer 4: rate limiting)
//!
//! LAN mode (`[app.exposure] lan = true`, docs/cross-platform.md): a private-range bind
//!               →  native tls (no proxy shortcut)  paired-device credentials only (the app
//!               →  rate_limit, no "*" origin       server refuses every other credential from
//!                                                  a LAN peer and every non-private peer)
//! ```
//!
//! The address classification ([`classify_ip`], [`classify_host`]) is the one source of truth
//! for "is this a private network": the LAN bind rule, the pairing URL (`wss://` only off
//! loopback) and the discovery code all call it.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Where an address lives, for the LAN rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrClass {
    /// 127.0.0.0/8, ::1.
    Loopback,
    /// RFC 1918, link-local (169.254/16, fe80::/10), ULA (fc00::/7), CGNAT (100.64/10).
    Private,
    /// 0.0.0.0 / :: — every interface.
    Unspecified,
    /// Anything else (including multicast and documentation ranges).
    Public,
}

/// Classify one address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is judged as its IPv4 address.
pub fn classify_ip(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_loopback() {
                AddrClass::Loopback
            } else if v4.is_unspecified() {
                AddrClass::Unspecified
            } else if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 100 && (64..=127).contains(&b)) {
                AddrClass::Private
            } else {
                AddrClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_ip(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            if v6.is_loopback() {
                AddrClass::Loopback
            } else if v6.is_unspecified() {
                AddrClass::Unspecified
            } else if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
                AddrClass::Private
            } else {
                AddrClass::Public
            }
        }
    }
}

/// Classify a host as written in a URL or listen string: an IP (with or without `[]`, a
/// `%zone` is ignored) or a name. `localhost` is loopback; `*.local` (mDNS) is private; any
/// other name is public — it could resolve anywhere, so it gets the full set of layers.
pub fn classify_host(host: &str) -> AddrClass {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    let h = h.split('%').next().unwrap_or("");
    if h.is_empty() {
        return AddrClass::Unspecified;
    }
    if h == "localhost" {
        return AddrClass::Loopback;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    if h.ends_with(".local") {
        return AddrClass::Private;
    }
    AddrClass::Public
}

/// Loopback or a private range: what a LAN client may be.
pub fn is_local_network(ip: IpAddr) -> bool {
    matches!(classify_ip(ip), AddrClass::Loopback | AddrClass::Private)
}

/// How callers prove who they are. Ordered weakest → strongest for documentation only;
/// [`Surface::auth`] is compared against the two strong variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrength {
    /// No credential at all.
    #[default]
    None,
    /// One shared bearer string (the app token, a webhook secret, a channel token).
    Token,
    /// A dashboard login backed by the local password list (`[app.auth] provider = "basic"`).
    DashboardBasic,
    /// A dashboard login through a real identity provider (OIDC / plugin provider).
    Provider,
    /// Device-bound keys: mTLS or a paired device's signing key.
    Device,
}

impl AuthStrength {
    /// Beyond "present a string": what A9 layer 2 asks for.
    pub fn is_strong(self) -> bool {
        matches!(self, AuthStrength::Provider | AuthStrength::Device)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            AuthStrength::None => "none",
            AuthStrength::Token => "token",
            AuthStrength::DashboardBasic => "dashboard-basic",
            AuthStrength::Provider => "provider",
            AuthStrength::Device => "device",
        }
    }
}

/// One required layer that a non-loopback surface is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    /// A non-loopback bind without `allow_public = true` (A8).
    AllowPublic,
    /// No TLS in front of the surface (A9 layer 1).
    Tls,
    /// Nothing beyond a shared bearer string (A9 layer 2).
    StrongAuth,
    /// No origin allowlist (A9 layer 3).
    OriginsMissing,
    /// An allowlist containing `*` (A9 layer 3).
    OriginsWildcard,
    /// No rate limit (A9 layer 4).
    RateLimit,
    /// LAN mode without native TLS (a reverse proxy does not count: LAN clients pin our cert).
    LanTls,
}

impl Missing {
    /// Audit finding id (A12).
    pub fn id(self) -> &'static str {
        match self {
            Missing::AllowPublic => "exposure.allow_public_missing",
            Missing::Tls => "exposure.tls_missing",
            Missing::StrongAuth => "exposure.weak_auth",
            Missing::OriginsMissing => "exposure.origins_missing",
            Missing::OriginsWildcard => "exposure.origins_wildcard",
            Missing::RateLimit => "exposure.no_rate_limit",
            Missing::LanTls => "exposure.lan_tls_missing",
        }
    }
    /// Audit severity: a missing origin list or wildcard is critical — that is the
    /// OpenClaw CVE-2026-25253 shape (any web page drives the gateway).
    pub fn severity(self) -> &'static str {
        match self {
            Missing::AllowPublic | Missing::Tls | Missing::StrongAuth | Missing::RateLimit | Missing::LanTls => "high",
            Missing::OriginsMissing | Missing::OriginsWildcard => "critical",
        }
    }
    /// Short human name used in error messages.
    pub fn what(self) -> &'static str {
        match self {
            Missing::AllowPublic => "an explicit opt-in",
            Missing::Tls => "TLS",
            Missing::StrongAuth => "strong auth",
            Missing::OriginsMissing => "an origin allowlist",
            Missing::OriginsWildcard => "a real origin allowlist (no \"*\")",
            Missing::RateLimit => "a rate limit",
            Missing::LanTls => "native TLS (LAN mode)",
        }
    }
    /// The config key that fixes it, with a value that passes.
    pub fn fix(self) -> &'static str {
        match self {
            Missing::AllowPublic => "[app.exposure] allow_public = true",
            Missing::Tls => "[app.exposure] behind_proxy = true (an https reverse proxy terminates TLS) or tls = true",
            Missing::StrongAuth => "[app.auth] enabled = true with a real provider (provider = \"self_hosted\" or a plugin provider, not \"basic\"), or device-bound keys",
            Missing::OriginsMissing => "[app] allow_origins = [\"https://your-ui.example\"]",
            Missing::OriginsWildcard => "[app] allow_origins: remove \"*\" and list the origins you use",
            Missing::RateLimit => "[app.exposure] rate_limit_per_min = 120",
            Missing::LanTls => "[app.exposure] tls = true (LAN mode generates its own certificate in <data>/tls/; leave cert/key unset)",
        }
    }
}

/// A listening surface, as the operator configured it.
#[derive(Debug, Clone)]
pub struct Surface<'a> {
    /// Human name used in messages: "app server", "channels.slack", "mcp-relay".
    pub name: &'a str,
    /// The configured listen string (`127.0.0.1:8640`, `0.0.0.0:8640`, `[::1]:1`).
    pub listen: &'a str,
    /// seagent terminates TLS itself.
    pub tls: bool,
    /// An https reverse proxy / tunnel in front, explicitly acknowledged.
    pub behind_proxy: bool,
    /// The operator wrote the non-loopback bind on purpose (`allow_public = true`).
    pub allow_public: bool,
    pub auth: AuthStrength,
    /// Browser origins allowed to drive the surface; empty = none listed.
    pub origins: &'a [String],
    pub rate_limit: bool,
    /// A disabled surface is never started, so it is never exposed.
    pub enabled: bool,
    /// LAN mode: a private-range (or every-interface) bind that only paired devices on the
    /// local network may use. Judged by [`lan_check`] instead of the public rules.
    pub lan: bool,
}

impl<'a> Surface<'a> {
    /// A loopback surface with nothing else set: the shape every default should have.
    pub fn loopback(name: &'a str, listen: &'a str) -> Surface<'a> {
        Surface { name, listen, tls: false, behind_proxy: false, allow_public: false, auth: AuthStrength::None, origins: &[], rate_limit: false, enabled: true, lan: false }
    }

    /// LAN mode applies: `lan` is on, `allow_public` is off, and the bind is a private address
    /// or every interface (the app server then drops every non-private peer itself).
    pub fn is_lan_bind(&self) -> bool {
        self.lan && !self.allow_public && matches!(classify_host(host_of(self.listen)), AddrClass::Private | AddrClass::Unspecified)
    }
}

/// LAN-mode layers: native TLS (clients pin its certificate, so a proxy in front would break
/// the identity) and a rate limit; a wildcard origin is still refused. Credentials are not a
/// configurable layer here: in LAN mode the app server accepts only paired-device tokens from
/// LAN peers, whatever else is configured.
fn lan_check(s: &Surface) -> Vec<Missing> {
    let mut missing = Vec::new();
    if !s.tls {
        missing.push(Missing::LanTls);
    }
    if s.origins.iter().map(|o| o.trim()).any(|o| o == "*" || o.ends_with("://*")) {
        missing.push(Missing::OriginsWildcard);
    }
    if !s.rate_limit {
        missing.push(Missing::RateLimit);
    }
    missing
}

/// True when `listen` keeps the socket on this machine.
///
/// `localhost`, `127.0.0.0/8`, `::1`; an empty host (`:8640`) or an unparseable host name
/// is **not** loopback — `":8640"` binds every interface, so it must be treated as public.
pub fn is_loopback(listen: &str) -> bool {
    let listen = listen.trim();
    // A bare address (`::1`, `127.0.0.1`, `0.0.0.0`) has no port to strip.
    if let Ok(ip) = listen.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let host = match listen.rsplit_once(':') {
        // `[::1]:8640` → `::1`.
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) || port.is_empty() => h.trim_matches(['[', ']']),
        _ => listen,
    };
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Where a listen string separates host from port, for error messages.
pub fn host_of(listen: &str) -> &str {
    if listen.trim().parse::<std::net::IpAddr>().is_ok() {
        return listen.trim();
    }
    match listen.trim().rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) || port.is_empty() => h.trim_matches(['[', ']']),
        _ => listen.trim(),
    }
}

/// Every layer a surface is missing (empty = it may start).
///
/// A disabled surface or a loopback bind passes with no requirements at all: this is the
/// default path, so the guard costs unattended work nothing.
pub fn check(s: &Surface) -> Result<(), Vec<Missing>> {
    if !s.enabled || is_loopback(s.listen) {
        return Ok(());
    }
    if s.is_lan_bind() {
        let missing = lan_check(s);
        return if missing.is_empty() { Ok(()) } else { Err(missing) };
    }
    let mut missing = Vec::new();
    if !s.allow_public {
        missing.push(Missing::AllowPublic);
    }
    if !(s.tls || s.behind_proxy) {
        missing.push(Missing::Tls);
    }
    if !s.auth.is_strong() {
        missing.push(Missing::StrongAuth);
    }
    let origins: Vec<&str> = s.origins.iter().map(|o| o.trim()).filter(|o| !o.is_empty()).collect();
    if origins.is_empty() {
        missing.push(Missing::OriginsMissing);
    } else if origins.contains(&"*") || origins.iter().any(|o| *o == "*" || o.ends_with("://*")) {
        missing.push(Missing::OriginsWildcard);
    }
    if !s.rate_limit {
        missing.push(Missing::RateLimit);
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// The error text for a surface that may not start: names every missing layer and the
/// config key that fixes it (A9: refuse, not warn).
pub fn refusal(s: &Surface) -> Option<String> {
    let missing = check(s).err()?;
    let layers: Vec<String> = missing.iter().map(|m| format!("{} — fix with {}", m.what(), fix(s, *m))).collect();
    // LAN mode on a public address: say why the LAN shortcut did not apply.
    let why = if s.lan && !s.is_lan_bind() && !s.allow_public { " (LAN mode only covers private addresses: 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, fc00::/7, fe80::/10, or 0.0.0.0)" } else { "" };
    Some(format!(
        "{} listens on {} (not loopback){why}; refusing to start it: {} missing layer(s): {}",
        s.name,
        s.listen,
        missing.len(),
        layers.join("; ")
    ))
}

/// One audit finding (A12), shaped like `seagent security audit`'s own type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub fix: Option<String>,
}

/// Findings for one surface: an enabled endpoint (info) plus one per missing layer.
pub fn findings(s: &Surface) -> Vec<Finding> {
    if !s.enabled {
        return Vec::new();
    }
    let mut out = vec![Finding {
        id: "exposure.endpoint_enabled",
        severity: "info",
        title: format!("{} is enabled", s.name),
        detail: format!("listen = {} ({})", s.listen, if is_loopback(s.listen) { "loopback" } else { "network" }),
        fix: None,
    }];
    if is_loopback(s.listen) {
        return out;
    }
    if s.is_lan_bind() {
        out.push(Finding {
            id: "exposure.lan_mode",
            severity: "info",
            title: format!("{} is in LAN mode", s.name),
            detail: format!("listen = {}; only private-network peers with a paired-device token get in", s.listen),
            fix: Some("[app.exposure] lan = false to go back to loopback-only".into()),
        });
        for m in check(s).err().unwrap_or_default() {
            out.push(Finding { id: m.id(), severity: m.severity(), title: format!("{}: {}", s.name, m.what()), detail: format!("listen = {} (LAN mode)", s.listen), fix: Some(fix(s, m)) });
        }
        return out;
    }
    out.push(Finding {
        id: "exposure.non_loopback",
        severity: "warn",
        title: format!("{} is reachable from the network", s.name),
        detail: format!("listen = {}", s.listen),
        fix: Some(format!("bind loopback ({}) and put a tunnel or reverse proxy in front", loopback_hint(s.listen))),
    });
    for m in check(s).err().unwrap_or_default() {
        out.push(Finding { id: m.id(), severity: m.severity(), title: format!("{}: {}", s.name, m.what()), detail: format!("listen = {}, auth = {}", s.listen, s.auth.as_str()), fix: Some(fix(s, m)) });
    }
    out
}

/// The config key that fixes `m` *on this surface*: channel callbacks live under
/// `[channels.<id>]`, so an `[app.exposure]` key would send the operator to the wrong table.
pub fn fix(s: &Surface, m: Missing) -> String {
    let Some(name) = s.name.strip_prefix("channels.") else { return m.fix().to_string() };
    match m {
        Missing::RateLimit => format!("`[channels.{name}] rate_limit = 30`"),
        Missing::Tls | Missing::LanTls => format!("front it with https (`[channels.{name}] webhook_url = \"https://…\"`) and keep `listen` on loopback"),
        Missing::StrongAuth => format!("`[channels.{name}] secret`/signature verification, or keep the listener on loopback"),
        Missing::OriginsMissing => format!("`[channels.{name}] allowed_source_cidrs = [\"…\"]`"),
        Missing::OriginsWildcard => format!("`[channels.{name}] allowed_source_cidrs`: list the real ranges"),
        Missing::AllowPublic => format!("bind loopback: `[channels.{name}] listen = \"127.0.0.1:PORT\"`"),
    }
}

/// The same bind with the host swapped for `127.0.0.1`.
pub fn loopback_hint(listen: &str) -> String {
    let port = listen.rsplit_once(':').map(|(_, p)| p).filter(|p| !p.is_empty()).unwrap_or("0");
    format!("127.0.0.1:{port}")
}

/// One line for `seagent doctor`: `None` when every enabled surface is fine.
pub fn warning(s: &Surface) -> Option<String> {
    let mut missing = check(s).err()?;
    missing.sort_by_key(|m| m.id());
    let first = missing[0];
    Some(format!(
        "⚠ {} listens on {} without the public-exposure layers ({}); fix: {}",
        s.name,
        s.listen,
        missing.iter().map(|m| m.what()).collect::<Vec<_>>().join(", "),
        fix(s, first)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public<'a>(listen: &'a str) -> Surface<'a> {
        Surface {
            name: "app server",
            listen,
            tls: true,
            behind_proxy: false,
            allow_public: true,
            auth: AuthStrength::Provider,
            origins: &[],
            rate_limit: true,
            enabled: true,
            lan: false,
        }
    }

    #[test]
    fn private_range_classification() {
        let c = |h: &str| classify_host(h);
        for p in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.20", "169.254.3.4", "100.64.0.1", "100.127.255.254", "fd00::1", "fc12::1", "fe80::1", "[fe80::1%eth0]", "::ffff:192.168.0.2", "studio.local", "Studio.Local."] {
            assert_eq!(c(p), AddrClass::Private, "{p}");
        }
        for p in ["8.8.8.8", "172.32.0.1", "172.15.0.1", "100.128.0.1", "100.63.0.1", "2001:db8::1", "example.com", "192.169.0.1"] {
            assert_eq!(c(p), AddrClass::Public, "{p}");
        }
        assert_eq!(c("127.0.0.1"), AddrClass::Loopback);
        assert_eq!(c("::1"), AddrClass::Loopback);
        assert_eq!(c("localhost"), AddrClass::Loopback);
        assert_eq!(c("0.0.0.0"), AddrClass::Unspecified);
        assert_eq!(c("[::]"), AddrClass::Unspecified);
        assert!(is_local_network("192.168.1.2".parse().unwrap()) && !is_local_network("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn lan_mode_allows_private_binds_with_native_tls_only() {
        let lan = |listen: &'static str| Surface { lan: true, allow_public: false, auth: AuthStrength::Token, ..public(listen) };
        for ok in ["192.168.1.20:8640", "10.1.2.3:8640", "0.0.0.0:8640", "[fd00::5]:8640", "[::]:8640"] {
            assert_eq!(check(&lan(ok)), Ok(()), "{ok}");
            assert!(findings(&lan(ok)).iter().any(|f| f.id == "exposure.lan_mode"));
        }
        // A reverse proxy is not native TLS: LAN clients pin our certificate.
        let proxied = Surface { tls: false, behind_proxy: true, ..lan("192.168.1.20:8640") };
        assert_eq!(check(&proxied), Err(vec![Missing::LanTls]));
        let wild = vec!["*".to_string()];
        assert_eq!(check(&Surface { origins: &wild, ..lan("10.0.0.2:1") }), Err(vec![Missing::OriginsWildcard]));
        assert_eq!(check(&Surface { rate_limit: false, ..lan("10.0.0.2:1") }), Err(vec![Missing::RateLimit]));
        // A public address in LAN mode gets the full set of layers, and the message says why.
        let public_ip = lan("203.0.113.5:8640");
        let e = check(&public_ip).unwrap_err();
        assert!(e.contains(&Missing::AllowPublic) && e.contains(&Missing::StrongAuth), "{e:?}");
        assert!(refusal(&public_ip).unwrap().contains("LAN mode only covers private addresses"));
        // A host name could resolve anywhere: public rules.
        assert!(check(&lan("seagent.example:8640")).is_err());
    }

    const ORIGINS: [&str; 1] = ["https://seagent.example"];

    fn origins() -> Vec<String> {
        ORIGINS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn loopback_detection() {
        for ok in ["127.0.0.1:8640", "127.1.2.3:1", "localhost:8640", "[::1]:8640", "::1"] {
            assert!(is_loopback(ok), "{ok}");
        }
        for bad in ["0.0.0.0:8640", "[::]:8640", ":8640", "", "seagent.example:8640", "10.0.0.5:1"] {
            assert!(!is_loopback(bad), "{bad}");
        }
        assert_eq!(loopback_hint("0.0.0.0:8640"), "127.0.0.1:8640");
    }

    #[test]
    fn loopback_and_disabled_surfaces_pass_with_nothing() {
        let s = Surface::loopback("app server", "127.0.0.1:8640");
        assert_eq!(check(&s), Ok(()));
        assert!(refusal(&s).is_none() && warning(&s).is_none());
        let mut off = s;
        off.listen = "0.0.0.0:8640";
        off.enabled = false;
        assert_eq!(check(&off), Ok(()));
    }

    #[test]
    fn all_good_public_surface_passes() {
        let o = origins();
        let s = Surface { origins: &o, ..public("0.0.0.0:8640") };
        assert_eq!(check(&s), Ok(()), "{:?}", check(&s));
        let findings = findings(&s);
        assert_eq!(findings[0].id, "exposure.endpoint_enabled");
        assert!(findings.iter().any(|x| x.id == "exposure.non_loopback"), "{findings:?}");
        assert!(findings.iter().all(|x| x.severity == "info" || x.severity == "warn"), "{findings:?}");
    }

    /// One test per single missing layer: the other three are in place.
    #[test]
    fn each_single_missing_layer_is_named() {
        let o = origins();
        let cases: [(Missing, Surface); 5] = [
            (Missing::AllowPublic, Surface { allow_public: false, origins: &o, ..public("0.0.0.0:8640") }),
            (Missing::Tls, Surface { tls: false, behind_proxy: false, origins: &o, ..public("0.0.0.0:8640") }),
            (Missing::StrongAuth, Surface { auth: AuthStrength::Token, origins: &o, ..public("0.0.0.0:8640") }),
            (Missing::RateLimit, Surface { rate_limit: false, origins: &o, ..public("0.0.0.0:8640") }),
            (Missing::OriginsMissing, public("0.0.0.0:8640")),
        ];
        for (want, s) in cases {
            let e = check(&s).unwrap_err();
            assert_eq!(e, vec![want], "{want:?}");
            let text = refusal(&s).unwrap();
            assert!(text.contains(want.what()) && text.contains(want.fix()), "{text}");
            let ids: Vec<&str> = findings(&s).iter().map(|f| f.id).collect();
            assert!(ids.contains(&want.id()), "{want:?}: {ids:?}");
            assert!(warning(&s).is_some());
        }
    }

    #[test]
    fn wildcard_origins_are_refused_and_dashboard_basic_is_not_strong() {
        let wild = vec!["*".to_string()];
        let s = Surface { origins: &wild, ..public("0.0.0.0:8640") };
        assert_eq!(check(&s), Err(vec![Missing::OriginsWildcard]));
        assert_eq!(Missing::OriginsWildcard.severity(), "critical");
        let o = origins();
        let basic = Surface { auth: AuthStrength::DashboardBasic, origins: &o, ..public("0.0.0.0:8640") };
        assert_eq!(check(&basic), Err(vec![Missing::StrongAuth]));
        // behind_proxy is an accepted transport acknowledgement, device auth an accepted credential.
        let proxy = Surface { tls: false, behind_proxy: true, auth: AuthStrength::Device, origins: &o, ..public("0.0.0.0:8640") };
        assert_eq!(check(&proxy), Ok(()));
    }

    #[test]
    fn every_layer_missing_is_reported_at_once() {
        let s = Surface { listen: "0.0.0.0:8640", auth: AuthStrength::None, ..Surface::loopback("app server", "0.0.0.0:8640") };
        let e = check(&s).unwrap_err();
        assert_eq!(e.len(), 5, "{e:?}");
        let text = refusal(&s).unwrap();
        assert!(text.contains("5 missing layer(s)"), "{text}");
        for key in ["allow_public", "behind_proxy", "app.auth", "allow_origins", "rate_limit_per_min"] {
            assert!(text.contains(key), "{key} missing from {text}");
        }
    }
}
