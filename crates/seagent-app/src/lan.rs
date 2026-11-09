//! LAN mode (docs/cross-platform.md, 區域網路互聯): the server's long-lived self-signed TLS
//! identity, mDNS advertising, the `wss://` pairing URL and the status the CLI, console and
//! `seagent security audit` show. No upstream: SE Agent's own design.
//!
//! - **Identity**: `<data>/tls/lan-cert.pem` + `lan-key.pem` (owner-only), generated on first
//!   start in LAN mode by [`seagent_net::x509::self_signed`] (ECDSA P-256), with SANs for the
//!   host name, `<host>.local`, the current LAN address and `127.0.0.1`. Its fingerprint (SHA-256
//!   of the DER leaf, lower-case hex) is the host's identity: setup codes pin it, mDNS carries
//!   its first 16 hex digits, both screens show the short form (four groups of four). It is
//!   replaced only by `seagent tls rotate` — every paired client then has to pair again.
//! - **Host id**: a random 16-hex id in `<data>/tls/host-id`, stable across renames.
//! - **Discovery**: [`advertise`] starts the `_seagent._tcp.local` responder (IPv4 and IPv6,
//!   every interface; which addresses it advertises follows the listen address:
//!   [`advertised_families`]); TXT carries only `v`, `id`, `fp` and `name`. [`discover`]
//!   lists hosts with every address (`addresses`) and the best one to dial (`address`/`url`).

use crate::AppConfig;
use seagent_net::{mdns, x509};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const PROTOCOL: &str = "seagent/2";

/// The LAN TLS identity on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub fingerprint: String,
    pub created_ms: u64,
    pub not_after_ms: u64,
}

impl Identity {
    /// What both screens show: the first 16 hex digits in four groups.
    pub fn sas(&self) -> String {
        x509::short_fingerprint(&self.fingerprint)
    }
    pub fn json(&self) -> Value {
        json!({"fingerprint": self.fingerprint, "sas": self.sas(), "createdAtMs": self.created_ms, "notAfterMs": self.not_after_ms, "cert": self.cert})
    }
}

pub fn tls_dir(data: &Path) -> PathBuf {
    data.join("tls")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    seagent_core::platform::fs_private::write_private(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))
}

/// This machine's name as users know it.
pub fn display_name() -> String {
    let h = seagent_core::platform::sysinfo::hostname();
    let h = h.trim();
    if h.is_empty() { "seagent".into() } else { h.to_string() }
}

/// The stable host id (created on first use).
pub fn host_id(data: &Path) -> String {
    let p = tls_dir(data).join("host-id");
    if let Some(id) = std::fs::read_to_string(&p).ok().map(|s| s.trim().to_string()).filter(|s| s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())) {
        return id;
    }
    let id = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8));
    let _ = seagent_core::platform::fs_private::create_dir_private(&tls_dir(data));
    let _ = write_private(&p, id.as_bytes());
    id
}

/// The identity if it exists (no generation).
pub fn load_identity(data: &Path) -> Option<Identity> {
    let dir = tls_dir(data);
    let (cert, key) = (dir.join("lan-cert.pem"), dir.join("lan-key.pem"));
    if !cert.is_file() || !key.is_file() {
        return None;
    }
    let id = seagent_net::tlsd::identity_of_pem(&cert.to_string_lossy()).ok()?;
    let meta: Value = std::fs::read(dir.join("lan-identity.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let created = meta["createdAtMs"].as_u64().unwrap_or_else(|| std::fs::metadata(&cert).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0));
    Some(Identity { cert, key, fingerprint: id.fingerprint, created_ms: created, not_after_ms: meta["notAfterMs"].as_u64().unwrap_or(0) })
}

/// Generate a new identity, replacing any old one (`seagent tls rotate`).
pub fn generate_identity(data: &Path) -> Result<Identity, String> {
    let dir = tls_dir(data);
    seagent_core::platform::fs_private::create_dir_private(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let host = x509::dns_label(&display_name());
    let mut dns = vec!["localhost".to_string()];
    if !host.is_empty() {
        dns.insert(0, format!("{host}.local"));
        dns.insert(0, host);
    }
    let mut ips: Vec<std::net::IpAddr> = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
    if let Some(ip) = mdns::lan_ipv4() {
        ips.insert(0, ip.into());
    }
    let now = now_ms();
    let id = x509::self_signed(&format!("SE Agent {}", display_name()), &dns, &ips, now / 1000)?;
    let (cert, key) = (dir.join("lan-cert.pem"), dir.join("lan-key.pem"));
    write_private(&key, x509::pem("PRIVATE KEY", &id.key_pkcs8).as_bytes())?;
    write_private(&cert, x509::pem("CERTIFICATE", &id.cert_der).as_bytes())?;
    let fp = x509::fingerprint(&id.cert_der);
    let meta = json!({"fingerprint": fp, "createdAtMs": now, "notAfterMs": id.not_after_ms, "sans": {"dns": dns, "ip": ips}});
    write_private(&dir.join("lan-identity.json"), serde_json::to_vec_pretty(&meta).unwrap_or_default().as_slice())?;
    Ok(Identity { cert, key, fingerprint: fp, created_ms: now, not_after_ms: id.not_after_ms })
}

/// The identity, generated on first use.
pub fn ensure_identity(data: &Path) -> Result<Identity, String> {
    match load_identity(data) {
        Some(i) => Ok(i),
        None => generate_identity(data),
    }
}

/// LAN mode on "every interface" means both address families: `0.0.0.0:<port>` (what older
/// wizards wrote) becomes `[::]:<port>`, which `seagent_net::listen` binds as one dual-stack
/// socket (or `[::]` + `0.0.0.0` where the system has no dual-stack). Any specific address —
/// and every listen outside LAN mode — is left exactly as written.
pub fn dual_stack_listen(listen: &str) -> String {
    match listen.trim().strip_prefix("0.0.0.0:") {
        Some(port) if port.parse::<u16>().is_ok() => format!("[::]:{port}"),
        _ => listen.to_string(),
    }
}

/// The config the server really runs with: LAN mode turns native TLS on, listens on both
/// address families ([`dual_stack_listen`]) and, unless the operator gave `cert`/`key`, points
/// TLS at the generated identity (created now if missing).
pub fn effective(cfg: &AppConfig, data: &Path) -> Result<AppConfig, String> {
    let mut c = cfg.clone();
    if !c.exposure.lan {
        return Ok(c);
    }
    c.exposure.tls = true;
    c.listen = dual_stack_listen(&c.listen);
    if c.exposure.cert.is_none() && c.exposure.key.is_none() {
        let id = ensure_identity(data)?;
        c.exposure.cert = Some(id.cert.display().to_string());
        c.exposure.key = Some(id.key.display().to_string());
    }
    Ok(c)
}

/// The fingerprint of the certificate the server presents (`None` without TLS).
pub fn served_fingerprint(cfg: &AppConfig) -> Option<String> {
    let cert = cfg.exposure.cert.as_deref().filter(|_| cfg.exposure.tls)?;
    seagent_net::tlsd::identity_of_pem(cert).ok().map(|i| i.fingerprint)
}

/// `[app] discovery`: on when `"mdns"`, or by default in LAN mode.
pub fn discovery_enabled(cfg: &AppConfig) -> bool {
    match cfg.discovery.trim() {
        "mdns" => true,
        "off" => false,
        _ => cfg.exposure.lan,
    }
}

fn port_of(listen: &str) -> u16 {
    listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(8640)
}

/// The host this server is reached at from the LAN: the listen address when it names one, else
/// this machine's LAN address.
pub fn lan_host(cfg: &AppConfig) -> Option<String> {
    let h = seagent_security::exposure::host_of(&cfg.listen);
    match seagent_security::exposure::classify_host(h) {
        seagent_security::exposure::AddrClass::Private => Some(h.to_string()),
        seagent_security::exposure::AddrClass::Unspecified => mdns::lan_ipv4().map(|i| i.to_string()),
        _ => None,
    }
}

/// Which addresses mDNS advertises for a listen address: `(fixed, auto_v4, auto_v6)`. A
/// specific private address is advertised alone. `0.0.0.0` (an IPv4-only listener; LAN mode
/// turns it into `[::]`, see [`dual_stack_listen`]): every interface's IPv4 addresses.
/// `[::]` (dual-stack, or `[::]` + `0.0.0.0`): IPv4 and IPv6 (global, ULA, link-local).
pub fn advertised_families(listen: &str) -> (Vec<std::net::IpAddr>, bool, bool) {
    let h = seagent_security::exposure::host_of(listen);
    match seagent_security::exposure::classify_host(h) {
        seagent_security::exposure::AddrClass::Private => match h.parse() {
            Ok(ip) => (vec![ip], false, false),
            Err(_) => (vec![], true, false), // `<name>.local`
        },
        seagent_security::exposure::AddrClass::Unspecified if h.contains(':') => (vec![], true, true),
        _ => (vec![], true, false),
    }
}

/// The service record we advertise. Never carries a token: only protocol, id, fingerprint
/// prefix and the display name.
pub fn service(cfg: &AppConfig, data: &Path, fingerprint: &str) -> mdns::Service {
    let name = display_name();
    let host = x509::dns_label(&name);
    let (addrs, auto_v4, auto_v6) = advertised_families(&cfg.listen);
    mdns::Service {
        instance: format!("SE Agent on {name}").chars().filter(|c| *c != '.').take(60).collect(),
        host: format!("{}.local", if host.is_empty() { "seagent" } else { &host }),
        port: port_of(&cfg.listen),
        txt: vec![("v".into(), PROTOCOL.into()), ("id".into(), host_id(data)), ("fp".into(), fingerprint.chars().take(16).collect()), ("name".into(), name.chars().take(60).collect())],
        addrs,
        auto_v4,
        auto_v6,
    }
}

/// What discovery is doing on this host, for `lan.status`: `off`, `advertising` (with the
/// interfaces and addresses), `limited` (UDP 5353 could not be shared: announce-only, or
/// one family missing — `detail` says which) or `idle` (on, but the responder runs in the
/// daemon's app server and none runs in this process).
pub fn discovery_state(cfg: &AppConfig) -> Value {
    if !discovery_enabled(cfg) || !cfg.enabled {
        return json!({"state": "off"});
    }
    match mdns::responder_status() {
        // IPv4 is the baseline every peer speaks: without its 5353 socket discovery is limited.
        Some(s) => json!({"state": if s.limited || !s.ipv4 { "limited" } else { "advertising" }, "detail": s.detail, "ipv4": s.ipv4, "ipv6": s.ipv6, "interfaces": s.interfaces, "addresses": s.addrs}),
        None => match mdns::port_shareable() {
            Ok(()) => json!({"state": "idle", "detail": "advertised by the daemon's app server while it runs"}),
            Err(e) => json!({"state": "limited", "detail": e}),
        },
    }
}

/// Start advertising when discovery is on and the server speaks TLS. The error explains why
/// this host is not discoverable (devices can still pair by address / QR).
pub fn advertise(cfg: &AppConfig, data: &Path) -> Result<Option<mdns::Responder>, String> {
    if !discovery_enabled(cfg) || !cfg.enabled {
        return Ok(None);
    }
    let fp = served_fingerprint(cfg).ok_or("discovery needs the app server's TLS certificate ([app.exposure] lan = true or tls = true)")?;
    mdns::Responder::start(service(cfg, data, &fp)).map(Some)
}

/// Hosts on the LAN (other than this one), as JSON for `seagent nodes discover` /
/// `discovery.list`.
pub fn discover(data: &Path, timeout: std::time::Duration) -> Result<Vec<Value>, String> {
    let me = host_id(data);
    let found = mdns::browse(timeout)?;
    Ok(found
        .into_iter()
        .filter(|f| f.txt.get("v").is_some_and(|v| v.starts_with("seagent/")))
        .map(|f| {
            // The best-ranked address (private IPv4, then routable IPv6, then link-local with
            // its zone); the `.local` name when no address came back.
            let (authority, url) = match f.best() {
                Some(a) => (a.authority(f.port), a.url("https", f.port)),
                None => {
                    let a = format!("{}:{}", f.host.trim_end_matches('.'), f.port);
                    (a.clone(), format!("https://{a}"))
                }
            };
            json!({
                "id": f.txt.get("id").cloned().unwrap_or_default(),
                "name": f.txt.get("name").cloned().unwrap_or_else(|| f.instance.clone()),
                "instance": f.instance,
                "host": f.host,
                "address": authority,
                "addresses": f.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "url": url,
                "fpPrefix": f.txt.get("fp").cloned().unwrap_or_default(),
                "sas": x509::short_fingerprint(f.txt.get("fp").map(String::as_str).unwrap_or("")),
                "protocol": f.txt.get("v").cloned().unwrap_or_default(),
                "self": f.txt.get("id").is_some_and(|i| *i == me),
            })
        })
        .collect())
}

/// The `/node` URL (and certificate pin) a device should dial. Off loopback it is always
/// `wss://` with the fingerprint; `ws://` is only ever produced for a loopback-only server.
/// `public_url`: `[surfaces] public_url` (a tunnel / reverse proxy), which must be https.
pub fn pairing_url(cfg: &AppConfig, public_url: Option<&str>) -> Result<(String, Option<String>), String> {
    if let Some(u) = public_url.map(|u| u.trim().trim_end_matches('/')).filter(|u| !u.is_empty()) {
        let ws = u.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
        let host = ws.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
        let host = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
        if ws.starts_with("ws://") && seagent_security::exposure::classify_host(host) != seagent_security::exposure::AddrClass::Loopback {
            return Err(SECURE_FIX.into());
        }
        return Ok((format!("{ws}/node"), None));
    }
    let port = port_of(&cfg.listen);
    if cfg.exposure.tls || cfg.exposure.lan {
        let host = lan_host(cfg).or_else(|| Some(seagent_security::exposure::host_of(&cfg.listen).to_string()).filter(|h| seagent_security::exposure::classify_host(h) != seagent_security::exposure::AddrClass::Unspecified)).unwrap_or_else(|| "127.0.0.1".into());
        let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        return Ok((format!("wss://{authority}/node"), served_fingerprint(cfg)));
    }
    if seagent_security::exposure::is_loopback(&cfg.listen) {
        let host = seagent_security::exposure::host_of(&cfg.listen);
        let host = if host.eq_ignore_ascii_case("localhost") { "127.0.0.1" } else { host };
        return Ok((format!("ws://{host}:{port}/node"), None));
    }
    Err(SECURE_FIX.into())
}

pub const SECURE_FIX: &str = "Pairing from another device needs TLS (wss://). Fix: turn on LAN mode (`[app.exposure] lan = true`, or the setup wizard's \"Allow devices on this network to connect\"), or set `[surfaces] public_url` to an https:// URL (Tailscale Serve/Funnel or a reverse proxy). ws:// is only used for this machine (loopback).";

/// What `lan.status` reports.
pub fn status(cfg: &AppConfig, data: &Path) -> Value {
    let id = load_identity(data);
    json!({
        "lan": cfg.exposure.lan,
        "lanOnly": crate::exposure::lan_only(cfg),
        "listen": cfg.listen,
        "discovery": discovery_enabled(cfg),
        "discoveryState": discovery_state(cfg),
        "hostId": host_id(data),
        "name": display_name(),
        "address": lan_host(cfg),
        "identity": id.as_ref().map(Identity::json),
        "pairingUrl": pairing_url(cfg, None).ok().map(|(u, _)| u),
        "devices": crate::devices::list(data).len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lan_cfg(listen: &str) -> AppConfig {
        let mut c = AppConfig { enabled: true, listen: listen.into(), ..AppConfig::default() };
        c.exposure.lan = true;
        c
    }

    #[test]
    fn identity_is_generated_once_kept_and_rotated_on_request() {
        let home = seagent_core::tmp::TempDir::new("seagent-lan-id");
        let data = home.path().to_path_buf();
        let a = ensure_identity(&data).unwrap();
        assert_eq!(a.fingerprint.len(), 64);
        assert!(a.fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(ensure_identity(&data).unwrap().fingerprint, a.fingerprint, "kept across starts");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a.key).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let b = generate_identity(&data).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint, "rotation changes the identity");
        assert_eq!(host_id(&data), host_id(&data));
        // LAN mode switches TLS on with the generated pair; the policy then lets it start.
        let eff = effective(&lan_cfg("0.0.0.0:8640"), &data).unwrap();
        assert!(eff.exposure.tls && eff.exposure.cert.is_some());
        assert_eq!(served_fingerprint(&eff).as_deref(), Some(b.fingerprint.as_str()));
        assert!(crate::exposure::check_start(&AppConfig { token: Some("t".into()), ..eff }).is_ok());
    }

    #[test]
    fn pairing_urls_are_wss_off_loopback() {
        let home = seagent_core::tmp::TempDir::new("seagent-lan-url");
        let eff = effective(&lan_cfg("192.168.7.9:9000"), home.path()).unwrap();
        let (url, fp) = pairing_url(&eff, None).unwrap();
        assert_eq!(url, "wss://192.168.7.9:9000/node");
        assert_eq!(fp.unwrap().len(), 64);
        let lo = AppConfig::default();
        assert_eq!(pairing_url(&lo, None).unwrap().0, "ws://127.0.0.1:8640/node");
        // A non-loopback plain-HTTP server has no pairing URL at all (no cleartext LAN codes).
        let plain = AppConfig { listen: "192.168.7.9:8640".into(), ..AppConfig::default() };
        assert_eq!(pairing_url(&plain, None).unwrap_err(), SECURE_FIX);
        assert_eq!(pairing_url(&lo, Some("https://seagent.example.com/")).unwrap().0, "wss://seagent.example.com/node");
        assert_eq!(pairing_url(&lo, Some("http://192.168.1.5:8640")).unwrap_err(), SECURE_FIX);
        assert!(discovery_enabled(&eff) && !discovery_enabled(&lo));
        assert!(!discovery_enabled(&AppConfig { discovery: "off".into(), ..eff.clone() }));
        assert!(discovery_enabled(&AppConfig { discovery: "mdns".into(), ..lo }));
    }

    #[test]
    fn advertised_txt_has_no_secrets() {
        let home = seagent_core::tmp::TempDir::new("seagent-lan-txt");
        let eff = effective(&lan_cfg("192.168.7.9:8640"), home.path()).unwrap();
        let fp = served_fingerprint(&eff).unwrap();
        let s = service(&eff, home.path(), &fp);
        let keys: Vec<&str> = s.txt.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["v", "id", "fp", "name"]);
        assert_eq!(s.txt[2].1, fp[..16]);
        let wire = String::from_utf8_lossy(&mdns::encode_response(&s, 0, None, false)).to_string();
        assert!(!wire.contains(&fp), "only the 16-digit prefix travels");
        for secret in ["token", "Token", "bootstrap", "consoleToken"] {
            assert!(!wire.contains(secret), "{secret}");
        }
        assert_eq!(s.port, 8640);
        assert_eq!(s.addrs, vec!["192.168.7.9".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn advertised_addresses_follow_the_listen_address() {
        assert_eq!(advertised_families("0.0.0.0:8640"), (vec![], true, false), "IPv4-only server: no AAAA");
        assert_eq!(advertised_families("[::]:8640"), (vec![], true, true), "dual-stack: A + AAAA");
        // LAN mode reads the old wizard's 0.0.0.0 as both families; explicit addresses stay.
        assert_eq!(dual_stack_listen("0.0.0.0:8640"), "[::]:8640");
        for keep in ["127.0.0.1:8640", "192.168.1.5:9000", "[fd00::5]:8640", "[::]:8640", "0.0.0.0:x"] {
            assert_eq!(dual_stack_listen(keep), keep);
        }
        let home = seagent_core::tmp::TempDir::new("seagent-lan-ds");
        assert_eq!(effective(&lan_cfg("0.0.0.0:8640"), home.path()).unwrap().listen, "[::]:8640");
        assert_eq!(effective(&lan_cfg("192.168.1.5:8640"), home.path()).unwrap().listen, "192.168.1.5:8640");
        let off = AppConfig { listen: "0.0.0.0:8640".into(), ..AppConfig::default() };
        assert_eq!(effective(&off, home.path()).unwrap().listen, "0.0.0.0:8640", "outside LAN mode nothing changes");
        assert_eq!(effective(&AppConfig::default(), home.path()).unwrap().listen, AppConfig::default().listen);
        assert_eq!(advertised_families("[fd00::5]:8640"), (vec!["fd00::5".parse().unwrap()], false, false));
        assert_eq!(advertised_families("studio.local:8640"), (vec![], true, false));
        // Discovery off: the state says so without touching the network.
        assert_eq!(discovery_state(&AppConfig::default())["state"], "off");
    }
}
