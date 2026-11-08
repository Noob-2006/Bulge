//! Pairing with an SE Agent host on the LAN (phones, and "connect to another computer").
//!
//! Inputs:
//! - a QR / link setup code: base64url JSON `{url, bootstrapToken, expiresAtMs?, tlsFingerprint?}`
//!   (`crates/seagent-app/src/node.rs` `SetupCode`), bare or as `seagent-pair://…` / `oc-pair://…`;
//! - or a discovered/typed address plus the 8-character code the host shows.
//!
//! The host's identity is the SHA-256 of its TLS certificate: pinned from the setup code, or
//! trust-on-first-use with both sides showing the short fingerprint for the user to compare.
//! No Tauri types here (unit-testable).

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupCode {
    pub url: String,
    pub bootstrap_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
}

/// `sha256:` prefix and colons stripped, lower-case hex; `None` unless a SHA-256 fingerprint.
/// Same rules as the agent's `normalize_fingerprint`.
pub fn normalize_fingerprint(f: &str) -> Option<String> {
    let v = f.trim();
    let v = v.strip_prefix("sha256:").or_else(|| v.strip_prefix("SHA256:")).unwrap_or(v).replace([':', ' '], "").to_ascii_lowercase();
    (v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())).then_some(v)
}

/// What both screens show for a human comparison: the first 16 hex digits in groups of four.
pub fn short_fingerprint(fp: &str) -> String {
    let n = normalize_fingerprint(fp).unwrap_or_else(|| fp.to_ascii_lowercase());
    n.chars().take(16).collect::<Vec<_>>().chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ").to_ascii_uppercase()
}

impl SetupCode {
    pub fn decode(input: &str, now_ms: u64) -> Result<SetupCode, String> {
        let t = input.trim();
        // The host's QR code is a link a phone camera opens (`https://<ip>:<port>/#setup=<code>`).
        let t = t.split_once("#setup=").map(|(_, c)| c.split('&').next().unwrap_or("")).unwrap_or(t);
        let code = ["seagent-pair://", "oc-pair://"].iter().find_map(|p| t.get(..p.len()).filter(|h| h.eq_ignore_ascii_case(p)).map(|_| &t[p.len()..])).unwrap_or(t);
        let code = code.trim_end_matches('/');
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=') {
            return Err("invalid setup code".into());
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code.trim_end_matches('=')).map_err(|_| "invalid setup code".to_string())?;
        let mut sc: SetupCode = serde_json::from_slice(&raw).map_err(|_| "invalid setup payload".to_string())?;
        if !(sc.url.starts_with("ws://") || sc.url.starts_with("wss://")) || sc.bootstrap_token.trim().is_empty() {
            return Err("invalid setup payload".into());
        }
        if sc.expires_at_ms.is_some_and(|e| e <= now_ms) {
            return Err("this setup code has expired; show a new one on the host".into());
        }
        if let Some(f) = &sc.tls_fingerprint {
            sc.tls_fingerprint = Some(normalize_fingerprint(f).ok_or("invalid setup payload: tlsFingerprint")?);
        }
        Ok(sc)
    }

    /// `wss://host:port/node` → `host:port` (the App Server; the console lives at its root).
    pub fn address(&self) -> Result<Address, String> {
        Address::parse(&self.url)
    }
}

/// A host's App Server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Address {
    /// `wss://h:p/x`, `https://h:p`, `h:p`, `[v6]:p`, `h` (default port 8640, TLS).
    pub fn parse(s: &str) -> Result<Address, String> {
        let s = s.trim();
        let (tls, rest) = match s.split_once("://") {
            Some((scheme, r)) => match scheme.to_ascii_lowercase().as_str() {
                "wss" | "https" => (true, r),
                "ws" | "http" => (false, r),
                o => return Err(format!("unsupported address scheme `{o}`")),
            },
            None => (true, s),
        };
        let hp = rest.split(['/', '?', '#']).next().unwrap_or("");
        let (host, port) = if let Some(v6) = hp.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("bad IPv6 address")?;
            (h.to_string(), after.strip_prefix(':').map(|p| p.parse::<u16>()).transpose().map_err(|_| "bad port")?)
        } else if hp.matches(':').count() > 1 {
            (hp.to_string(), None) // bare IPv6 without a port
        } else {
            match hp.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p.parse::<u16>().map_err(|_| "bad port")?)),
                None => (hp.to_string(), None),
            }
        };
        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || "/@\\".contains(c)) {
            return Err("enter a host name or IP address".into());
        }
        Ok(Address { host, port: port.unwrap_or(8640), tls })
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn is_loopback(&self) -> bool {
        matches!(self.host.as_str(), "127.0.0.1" | "localhost" | "::1")
    }
}

/// A paired host, kept in `<app data>/hosts.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub address: Address,
    /// Pinned SHA-256 of the host certificate (lower-case hex).
    pub fingerprint: String,
    /// Per-device console credential issued by the host (revocable there).
    pub token: String,
    /// Loopback port of the local tunnel; kept stable so the console's origin (and its
    /// per-origin storage) stays the same between launches.
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub paired_at_ms: u64,
}

impl Host {
    /// What the UI may see (never the token).
    pub fn public(&self) -> Value {
        serde_json::json!({"id": self.id, "name": self.name, "address": self.address.authority(), "fingerprint": short_fingerprint(&self.fingerprint), "pairedAtMs": self.paired_at_ms})
    }
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Store {
        Store { path: dir.join("hosts.json") }
    }
    pub fn load(&self) -> Vec<Host> {
        std::fs::read_to_string(&self.path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, hosts: &[Host]) -> Result<(), String> {
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(hosts).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }
    /// Insert or replace by id (and by address+fingerprint: re-pairing the same host).
    pub fn upsert(&self, h: Host) -> Result<(), String> {
        let mut all = self.load();
        all.retain(|x| x.id != h.id && !(x.address == h.address && x.fingerprint == h.fingerprint));
        all.insert(0, h);
        self.save(&all)
    }
    pub fn forget(&self, id: &str) -> Result<(), String> {
        let mut all = self.load();
        all.retain(|x| x.id != id);
        self.save(&all)
    }
    pub fn get(&self, id: &str) -> Option<Host> {
        self.load().into_iter().find(|h| h.id == id)
    }
}

/// The body of `POST /pair/client` on the host's App Server (`crates/seagent-app/src/devices.rs`).
/// A code claim answers `202 {"status":"pending","requestId",…}` until the host approves it;
/// poll with the same body plus that `requestId` (see [`with_request_id`]).
pub fn claim_body(bootstrap_token: Option<&str>, code: Option<&str>, device_id: &str, device_name: &str, platform: &str) -> Value {
    let mut v = serde_json::json!({"device": {"id": device_id, "name": device_name, "platform": platform}});
    if let Some(t) = bootstrap_token {
        v["bootstrapToken"] = t.into();
    }
    if let Some(c) = code {
        v["code"] = c.trim().to_ascii_uppercase().replace(['-', ' '], "").into();
    }
    v
}

/// The poll body after a `202`: the claim plus the host's `requestId`.
pub fn with_request_id(mut body: Value, request_id: &str) -> Value {
    body["requestId"] = request_id.into();
    body
}

/// The 8-character pairing alphabet of the agent (`node.rs` `add_pending`): no 0/O/1/I.
pub fn valid_pair_code(c: &str) -> bool {
    let c: String = c.trim().to_ascii_uppercase().replace(['-', ' '], "");
    c.len() == 8 && c.chars().all(|ch| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(ch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    }

    #[test]
    fn decodes_setup_codes_like_the_agent() {
        let fp = "AB:".repeat(31) + "AB";
        let code = enc(&serde_json::json!({"url": "wss://192.168.1.20:8640/node", "bootstrapToken": "tok", "expiresAtMs": 2000, "tlsFingerprint": fp}));
        let sc = SetupCode::decode(&code, 1000).unwrap();
        assert_eq!(sc.tls_fingerprint.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(sc.address().unwrap(), Address { host: "192.168.1.20".into(), port: 8640, tls: true });
        assert_eq!(SetupCode::decode(&format!("seagent-pair://{code}"), 1000).unwrap(), sc);
        assert_eq!(SetupCode::decode(&format!("SEAGENT-PAIR://{code}"), 1000).unwrap(), sc);
        assert_eq!(SetupCode::decode(&format!("https://192.168.1.20:8640/#setup={code}"), 1000).unwrap(), sc);
        assert!(SetupCode::decode(&code, 3000).unwrap_err().contains("expired"));
        assert!(SetupCode::decode("not base64!", 0).is_err());
        assert!(SetupCode::decode(&enc(&serde_json::json!({"url": "http://x", "bootstrapToken": "t"})), 0).is_err());
        assert!(SetupCode::decode(&enc(&serde_json::json!({"url": "wss://x", "bootstrapToken": "t", "tlsFingerprint": "zz"})), 0).is_err());
        // the agent's own encoder: b64url of the serde JSON (round trip)
        let again = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&sc).unwrap());
        assert_eq!(SetupCode::decode(&again, 0).unwrap(), sc);
    }

    #[test]
    fn addresses() {
        assert_eq!(Address::parse("studio.local").unwrap(), Address { host: "studio.local".into(), port: 8640, tls: true });
        assert_eq!(Address::parse("10.0.0.2:9000").unwrap().authority(), "10.0.0.2:9000");
        assert_eq!(Address::parse("https://[fe80::1]:8640/x").unwrap().authority(), "[fe80::1]:8640");
        assert_eq!(Address::parse("fe80::1").unwrap().port, 8640);
        assert!(!Address::parse("http://127.0.0.1:8640").unwrap().tls);
        assert!(Address::parse("ftp://x").is_err());
        assert!(Address::parse("a b").is_err());
        assert!(Address::parse("h:99999").is_err());
    }

    #[test]
    fn fingerprints_and_codes() {
        let fp = "0123456789abcdef".repeat(4);
        assert_eq!(short_fingerprint(&fp), "0123 4567 89AB CDEF");
        assert_eq!(normalize_fingerprint(&format!("sha256:{}", fp.to_uppercase())).as_deref(), Some(fp.as_str()));
        assert!(valid_pair_code("abcd-2345") && valid_pair_code("ABCD2345"));
        assert!(!valid_pair_code("ABCD0O1I") && !valid_pair_code("ABC"));
        let b = claim_body(None, Some("abcd-2345"), "dev1", "iPhone", "ios");
        assert_eq!(b["code"], "ABCD2345");
        assert!(b.get("bootstrapToken").is_none());
    }

    #[test]
    fn store_round_trip_without_leaking_tokens() {
        let dir = std::env::temp_dir().join(format!("seagent-desktop-store-{}", std::process::id()));
        let s = Store::new(&dir);
        let h = Host { id: "h1".into(), name: "Studio".into(), address: Address::parse("10.0.0.2").unwrap(), fingerprint: "ab".repeat(32), token: "secret-token".into(), local_port: 0, paired_at_ms: 1 };
        s.upsert(h.clone()).unwrap();
        s.upsert(Host { id: "h2".into(), ..h.clone() }).unwrap(); // same host re-paired: replaces
        assert_eq!(s.load().len(), 1);
        assert_eq!(s.get("h2").unwrap().token, "secret-token");
        assert!(!s.get("h2").unwrap().public().to_string().contains("secret-token"));
        s.forget("h2").unwrap();
        assert!(s.load().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
