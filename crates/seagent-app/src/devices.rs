//! Paired devices: phones, tablets, browsers and other PCs that use this host's console over
//! the LAN (docs/cross-platform.md; the client side is `apps/desktop/src-tauri/src/pair.rs`).
//!
//! **Store** — `<data>/devices.json` (owner-only): per device `{id, name, platform, scope,
//! salt, tokenHash, pairedAtMs, lastSeenMs, via}`. The console token is shown to the device
//! once and kept only as a salted SHA-256; revoking deletes the record, and an open WebSocket
//! of that device is closed within a second (`App::still_valid`).
//!
//! **Pairing** — `POST /pair/client` (LAN mode, served before the credential check, rate
//! limited per address, every outcome audited):
//!
//! ```text
//! {"bootstrapToken": "…", "device": {"id", "name", "platform"}}
//!     → 200 {"consoleToken", "hostId", "name", "deviceId", "scope"}      (QR / link: single use)
//! {"code": "ABCD2345", "device": {…}}
//!     → 202 {"status": "pending", "requestId", "retryAfterMs", "expiresAtMs", "sas"}
//! {"code": "ABCD2345", "requestId": "…", "device": {…}}                   (poll; long-polls 15 s)
//!     → 202 again, 200 as above once an admin approved it, 403 if rejected
//! errors: 4xx {"error": "…"}  (400 bad request, 403 unknown/used/expired, 409 code taken, 429)
//! ```
//!
//! The 8-character code comes from `seagent pair code` / the console's "Pair a device" card and
//! is short-lived (10 min by default); typing it in only *requests* pairing — an admin approves
//! the request on the host (`seagent devices approve CODE`, the console's Approve button) after
//! checking the short fingerprint the device shows matches the host's.

use crate::exposure::Scope;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub platform: String,
    pub scope: Scope,
    pub salt: String,
    pub token_hash: String,
    pub paired_at_ms: u64,
    #[serde(default)]
    pub last_seen_ms: u64,
    /// `bootstrap` (QR / link) or `code` (approved 8-character code).
    #[serde(default)]
    pub via: String,
}

impl Device {
    /// Everything but the credential.
    pub fn public(&self) -> Value {
        json!({"id": self.id, "name": self.name, "platform": self.platform, "scope": self.scope.as_str(), "pairedAtMs": self.paired_at_ms, "lastSeenMs": self.last_seen_ms, "via": self.via})
    }
}

/// What a device says about itself when pairing.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
}

impl DeviceInfo {
    pub fn from_json(v: &Value) -> Result<DeviceInfo, String> {
        let s = |k: &str| v[k].as_str().unwrap_or("").trim().to_string();
        let id = s("id");
        if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("device.id must be 1–64 letters, digits, - or _".into());
        }
        let clean = |t: String, max: usize| t.chars().filter(|c| !c.is_control()).take(max).collect::<String>();
        let name = clean(s("name"), 80);
        Ok(DeviceInfo { name: if name.is_empty() { id.clone() } else { name }, platform: clean(s("platform"), 24), id })
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Decision {
    Pending,
    Approved(String),
    Rejected,
}

#[derive(Debug, Clone)]
struct Claim {
    request_id: String,
    device: DeviceInfo,
    ip: String,
    at_ms: u64,
    decision: Decision,
}

#[derive(Debug, Clone)]
struct Offer {
    code: String,
    expires_ms: u64,
    scope: Scope,
    claim: Option<Claim>,
}

#[derive(Default)]
struct State {
    loaded: bool,
    devices: Vec<Device>,
    offers: Vec<Offer>,
    saved_ms: u64,
    hits: HashMap<IpAddr, (Vec<Instant>, Vec<Instant>)>,
}

fn reg() -> &'static Mutex<HashMap<PathBuf, State>> {
    static R: OnceLock<Mutex<HashMap<PathBuf, State>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn store_path(data: &Path) -> PathBuf {
    data.join("devices.json")
}

fn hash(salt: &str, token: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(format!("seagent-device|{salt}|{token}").as_bytes()))
}

/// Run `f` on the (lazily loaded) state of `data`.
fn with<R>(data: &Path, f: impl FnOnce(&mut State) -> R) -> R {
    let mut all = reg().lock().unwrap_or_else(|e| e.into_inner());
    let st = all.entry(data.to_path_buf()).or_default();
    if !st.loaded {
        st.devices = std::fs::read(store_path(data)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        st.loaded = true;
    }
    let t = now_ms();
    st.offers.retain(|o| o.expires_ms > t || o.claim.as_ref().is_some_and(|c| matches!(c.decision, Decision::Approved(_))) && o.expires_ms + 600_000 > t);
    f(st)
}

fn save(data: &Path, st: &mut State) -> Result<(), String> {
    let p = store_path(data);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let tmp = p.with_extension("json.tmp");
    seagent_core::platform::fs_private::write_private(&tmp, serde_json::to_vec_pretty(&st.devices).unwrap_or_default()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
    st.saved_ms = now_ms();
    Ok(())
}

fn audit(data: &Path, kind: &str, actor: seagent_security::audit::Actor, target: &str, outcome: &str, detail: Value) {
    seagent_security::audit::record(data, seagent_security::audit::Event::new(kind, actor, target, outcome).detail(detail));
}

/// Paired devices (public view, never the credential).
pub fn list(data: &Path) -> Vec<Value> {
    with(data, |st| st.devices.iter().map(Device::public).collect())
}

/// Issue a console token for `info` (re-pairing the same device id replaces its old token).
pub fn issue(data: &Path, info: &DeviceInfo, scope: Scope, via: &str) -> Result<String, String> {
    let token = format!("sed1_{}", seagent_net::crypto::random_token(32));
    let salt = seagent_net::crypto::random_token(12);
    with(data, |st| {
        if st.devices.len() >= 200 && !st.devices.iter().any(|d| d.id == info.id) {
            return Err("too many paired devices (200); revoke some first (seagent devices revoke ID)".to_string());
        }
        st.devices.retain(|d| d.id != info.id);
        let t = now_ms();
        st.devices.push(Device { id: info.id.clone(), name: info.name.clone(), platform: info.platform.clone(), scope, token_hash: hash(&salt, &token), salt, paired_at_ms: t, last_seen_ms: t, via: via.into() });
        save(data, st)
    })?;
    Ok(token)
}

/// Remove a device; its token stops working at once.
pub fn revoke(data: &Path, id: &str) -> Result<bool, String> {
    with(data, |st| {
        let n = st.devices.len();
        st.devices.retain(|d| d.id != id);
        if st.devices.len() == n {
            return Ok(false);
        }
        save(data, st).map(|_| true)
    })
}

/// Is `id` still paired?
pub fn is_active(data: &Path, id: &str) -> bool {
    with(data, |st| st.devices.iter().any(|d| d.id == id))
}

/// The device a console token belongs to: `(id, scope)`. Constant-time per record.
pub fn authenticate(data: &Path, token: &str) -> Option<(String, Scope)> {
    if !token.starts_with("sed1_") {
        return None;
    }
    with(data, |st| {
        let t = now_ms();
        let i = st.devices.iter().position(|d| seagent_net::crypto::ct_eq(hash(&d.salt, token).as_bytes(), d.token_hash.as_bytes()))?;
        let d = &mut st.devices[i];
        d.last_seen_ms = t;
        let out = (d.id.clone(), d.scope);
        // `lastSeen` is informational: persist it at most every ten minutes.
        if t.saturating_sub(st.saved_ms) > 600_000 {
            let _ = save(data, st);
        }
        Some(out)
    })
}

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Normalise a typed code: upper case, without `-` and spaces.
pub fn normalize_code(c: &str) -> String {
    c.trim().to_ascii_uppercase().replace(['-', ' '], "")
}

/// A new short-lived 8-character pairing code.
pub fn create_offer(data: &Path, ttl: Duration, scope: Scope) -> Result<(String, u64), String> {
    with(data, |st| {
        if st.offers.iter().filter(|o| o.claim.is_none()).count() >= 10 {
            return Err("too many open pairing codes; wait for them to expire".to_string());
        }
        let code: String = seagent_net::crypto::random_bytes(8).iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect();
        let exp = now_ms() + ttl.as_millis() as u64;
        st.offers.push(Offer { code: code.clone(), expires_ms: exp, scope, claim: None });
        Ok((code, exp))
    })
}

/// Requests waiting for an admin.
pub fn pending(data: &Path) -> Vec<Value> {
    with(data, |st| {
        st.offers
            .iter()
            .filter_map(|o| o.claim.as_ref().filter(|c| c.decision == Decision::Pending).map(|c| json!({"code": o.code, "deviceId": c.device.id, "name": c.device.name, "platform": c.device.platform, "ip": c.ip, "requestedAtMs": c.at_ms, "expiresAtMs": o.expires_ms, "scope": o.scope.as_str()})))
            .collect()
    })
}

/// Approve the request made with `code`: the device gets its token on its next poll.
pub fn approve(data: &Path, code: &str) -> Result<Value, String> {
    let code = normalize_code(code);
    let (info, scope, ip) = with(data, |st| {
        let o = st.offers.iter().find(|o| o.code == code).ok_or("no pairing request with that code (unknown or expired)")?;
        let c = o.claim.as_ref().filter(|c| c.decision == Decision::Pending).ok_or("no device has asked to pair with that code yet")?;
        Ok::<_, String>((c.device.clone(), o.scope, c.ip.clone()))
    })?;
    let token = issue(data, &info, scope, "code")?;
    with(data, |st| {
        if let Some(c) = st.offers.iter_mut().find(|o| o.code == code).and_then(|o| o.claim.as_mut()) {
            c.decision = Decision::Approved(token);
        }
    });
    audit(data, "device.approve", seagent_security::audit::Actor::local(), &info.id, "ok", json!({"name": info.name, "platform": info.platform, "ip": ip, "scope": scope.as_str()}));
    Ok(json!({"approved": info.id, "name": info.name}))
}

/// Refuse the request made with `code` (the code is spent).
pub fn reject(data: &Path, code: &str) -> bool {
    let code = normalize_code(code);
    let hit = with(data, |st| match st.offers.iter_mut().find(|o| o.code == code) {
        Some(o) => {
            match o.claim.as_mut() {
                Some(c) => c.decision = Decision::Rejected,
                None => o.expires_ms = 0,
            }
            true
        }
        None => false,
    });
    if hit {
        audit(data, "device.reject", seagent_security::audit::Actor::local(), &code, "ok", Value::Null);
    }
    hit
}

/// One code claim / poll.
#[derive(Debug, PartialEq)]
pub enum ClaimResult {
    Paired(String, Scope),
    Pending { request_id: String, expires_ms: u64 },
    Refused(u16, String),
}

pub fn claim_code(data: &Path, code: &str, request_id: Option<&str>, device: &DeviceInfo, ip: &str) -> ClaimResult {
    let code = normalize_code(code);
    with(data, |st| {
        let Some(o) = st.offers.iter_mut().find(|o| o.code == code) else {
            return ClaimResult::Refused(403, "unknown or expired pairing code; show a new one on the host (seagent pair code)".into());
        };
        match (&mut o.claim, request_id) {
            (None, _) => {
                let rid = seagent_net::crypto::random_token(18);
                o.claim = Some(Claim { request_id: rid.clone(), device: device.clone(), ip: ip.into(), at_ms: now_ms(), decision: Decision::Pending });
                eprintln!("seagentd: device `{}` ({}) asks to pair from {ip}; approve with `seagent devices approve {code}`", device.name, device.platform);
                ClaimResult::Pending { request_id: rid, expires_ms: o.expires_ms }
            }
            (Some(c), Some(rid)) if seagent_net::crypto::ct_eq(c.request_id.as_bytes(), rid.as_bytes()) && c.device.id == device.id => match c.decision.clone() {
                Decision::Pending => ClaimResult::Pending { request_id: rid.to_string(), expires_ms: o.expires_ms },
                Decision::Approved(token) => {
                    let scope = o.scope;
                    o.expires_ms = 0; // delivered once
                    o.claim = None;
                    ClaimResult::Paired(token, scope)
                }
                Decision::Rejected => {
                    o.expires_ms = 0;
                    ClaimResult::Refused(403, "the host refused this pairing request".into())
                }
            },
            (Some(_), _) => ClaimResult::Refused(409, "this pairing code is already being used by another device; show a new one on the host".into()),
        }
    })
}

/// Per-address limits for `/pair/client`: 30 requests a minute, 10 failed claims in 10 minutes.
fn limited(data: &Path, ip: Option<IpAddr>, failed: bool) -> bool {
    let Some(ip) = ip else { return false };
    with(data, |st| {
        let now = Instant::now();
        if st.hits.len() > 4096 {
            st.hits.clear();
        }
        let (reqs, fails) = st.hits.entry(ip).or_default();
        reqs.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        fails.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
        if failed {
            fails.push(now);
            return false;
        }
        if reqs.len() >= 30 || fails.len() >= 10 {
            return true;
        }
        reqs.push(now);
        false
    })
}

fn reply(status: u16, v: Value) -> seagent_net::httpd::Response {
    seagent_net::httpd::Response::json(status, &v.to_string()).with_header("cache-control", "no-store")
}

/// How long one `/pair/client` code poll waits for the admin before answering 202.
pub const LONG_POLL: Duration = Duration::from_secs(15);

/// `POST /pair/client` (see the module docs).
pub fn handle_pair_client(app: &crate::App, r: &seagent_net::httpd::Request) -> seagent_net::httpd::Response {
    handle_pair_client_with(app, r, LONG_POLL)
}

pub fn handle_pair_client_with(app: &crate::App, r: &seagent_net::httpd::Request, wait: Duration) -> seagent_net::httpd::Response {
    let data = &app.d.k.paths.data;
    let ip = app.client_ip(r);
    let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
    let actor = || seagent_security::audit::Actor::new("device", "").with_ip(&ip_s);
    if limited(data, ip, false) {
        return reply(429, json!({"error": "too many pairing attempts from this address; wait a few minutes"})).with_header("retry-after", "60");
    }
    if !crate::exposure::is_json_content_type(r.header("content-type")) {
        return reply(415, json!({"error": "send JSON (content-type: application/json)"}));
    }
    let Ok(body) = serde_json::from_slice::<Value>(&r.body) else { return reply(400, json!({"error": "the body is not JSON"})) };
    let device = match DeviceInfo::from_json(&body["device"]) {
        Ok(d) => d,
        Err(e) => return reply(400, json!({"error": e})),
    };
    let ok = |token: String, scope: Scope, via: &str| {
        audit(data, "device.pair", seagent_security::audit::Actor::new("device", &device.name).with_ip(&ip_s), &device.id, "ok", json!({"platform": device.platform, "via": via, "scope": scope.as_str()}));
        reply(200, json!({"consoleToken": token, "hostId": crate::lan::host_id(data), "name": crate::lan::display_name(), "deviceId": device.id, "scope": scope.as_str()}))
    };
    let fail = |status: u16, msg: String| {
        if status == 403 {
            limited(data, ip, true);
        }
        audit(data, "device.pair", actor(), &device.id, "deny", json!({"reason": msg, "name": device.name}));
        reply(status, json!({"error": msg}))
    };
    if let Some(bt) = body["bootstrapToken"].as_str().filter(|t| !t.trim().is_empty()) {
        return match crate::node::consume_bootstrap(bt) {
            Ok(()) => match issue(data, &device, Scope::Write, "bootstrap") {
                Ok(t) => ok(t, Scope::Write, "bootstrap"),
                Err(e) => fail(409, e),
            },
            Err(e) => fail(403, e),
        };
    }
    let Some(code) = body["code"].as_str().map(normalize_code).filter(|c| c.len() == 8 && c.bytes().all(|b| ALPHABET.contains(&b))) else {
        return reply(400, json!({"error": "send bootstrapToken (from a setup code) or code (the 8 characters shown on the host)"}));
    };
    let sas = crate::lan::served_fingerprint(&app.cfg).map(|f| seagent_net::x509::short_fingerprint(&f)).unwrap_or_default();
    let mut rid = body["requestId"].as_str().map(str::to_string);
    let until = Instant::now() + wait;
    loop {
        match claim_code(data, &code, rid.as_deref(), &device, &ip_s) {
            ClaimResult::Paired(t, scope) => return ok(t, scope, "code"),
            ClaimResult::Refused(s, m) => return fail(s, m),
            ClaimResult::Pending { request_id, expires_ms } => {
                if rid.is_none() {
                    audit(data, "device.pair.request", actor(), &device.id, "pending", json!({"name": device.name, "platform": device.platform}));
                }
                rid = Some(request_id.clone());
                if Instant::now() >= until {
                    return reply(202, json!({"status": "pending", "requestId": request_id, "retryAfterMs": 1000, "expiresAtMs": expires_ms, "sas": sas, "message": "waiting for the host to approve this device — check that the short fingerprint matches on both screens"}));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// A pairing offer for the CLI / console: setup code (QR / link, single use), the 8-character
/// code, the short fingerprint and the QR code as SVG. `public_url`: `[surfaces] public_url`.
pub fn offer(cfg: &crate::AppConfig, data: &Path, ttl: Duration, scope: Scope, public_url: Option<&str>) -> Result<Value, String> {
    let (url, fp) = crate::lan::pairing_url(cfg, public_url)?;
    let (token, exp) = crate::node::bootstrap_token(ttl);
    let sc = crate::node::SetupCode { url: url.clone(), bootstrap_token: token, expires_at_ms: Some(exp), tls_fingerprint: fp.clone() };
    let setup = sc.encode();
    let (code, _) = create_offer(data, ttl, scope)?;
    let base = url.replacen("wss://", "https://", 1).replacen("ws://", "http://", 1);
    let base = base.strip_suffix("/node").unwrap_or(&base).to_string();
    let link = format!("{base}/#setup={setup}");
    let qr = crate::qr::Qr::encode(link.as_bytes());
    audit(data, "device.offer", seagent_security::audit::Actor::local(), "pair", "ok", json!({"expiresAtMs": exp, "scope": scope.as_str()}));
    Ok(json!({
        "setupCode": setup,
        "pairUri": format!("seagent-pair://{setup}"),
        "link": link,
        "url": url,
        "address": base,
        "code": code,
        "expiresAtMs": exp,
        "fingerprint": fp,
        "sas": fp.as_deref().map(seagent_net::x509::short_fingerprint),
        "qrSvg": qr.as_ref().map(|q| q.svg(4)),
        "qrText": qr.as_ref().map(|q| q.render(2)),
        "scope": scope.as_str(),
    }))
}

/// ARP methods (all `devices.*` need admin; `discovery.list` and `lan.status` are reads).
pub fn methods(data: PathBuf, cfg: crate::AppConfig, public_url: Option<String>) -> seagent_kernel::daemon::MethodExt {
    std::sync::Arc::new(move |m: &str, p: &Value| {
        let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
        let r = match m {
            "devices.list" => Ok(json!({"devices": list(&data), "pending": pending(&data)})),
            "devices.pending" => Ok(json!(pending(&data))),
            "devices.approve" => approve(&data, &s("code")).map_err(|e| (-32001, e)),
            "devices.reject" => Ok(json!({"rejected": reject(&data, &s("code"))})),
            "devices.revoke" => {
                let id = s("id");
                match revoke(&data, &id) {
                    Ok(had) => {
                        audit(&data, "device.revoke", seagent_security::audit::Actor::local(), &id, if had { "ok" } else { "noop" }, Value::Null);
                        Ok(json!({"revoked": had}))
                    }
                    Err(e) => Err((-32000, e)),
                }
            }
            "devices.pair.create" => {
                let ttl = Duration::from_secs(p["ttlMin"].as_u64().unwrap_or(10).clamp(1, 24 * 60) * 60);
                let scope = match Scope::parse(p["scope"].as_str().unwrap_or("write")) {
                    Ok(sc) => sc,
                    Err(e) => return Some(Err((-32602, e))),
                };
                offer(&cfg, &data, ttl, scope, public_url.as_deref()).map_err(|e| (-32000, e))
            }
            "discovery.list" => {
                let t = Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(2500).clamp(500, 10_000));
                crate::lan::discover(&data, t).map(|v| json!({"hosts": v, "advertising": crate::lan::discovery_enabled(&cfg)})).map_err(|e| (-32000, e))
            }
            "lan.status" => Ok(crate::lan::status(&cfg, &data)),
            _ => return None,
        };
        Some(r)
    })
}

pub const METHODS: &[&str] = &["devices.list", "devices.pending", "devices.approve", "devices.reject", "devices.revoke", "devices.pair.create", "discovery.list", "lan.status"];

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str) -> DeviceInfo {
        DeviceInfo { id: id.into(), name: format!("phone {id}"), platform: "ios".into() }
    }

    #[test]
    fn tokens_are_hashed_scoped_and_revocable() {
        let home = seagent_core::tmp::TempDir::new("seagent-devices");
        let data = home.path();
        let t = issue(data, &info("d1"), Scope::Write, "bootstrap").unwrap();
        assert!(t.starts_with("sed1_"));
        let raw = std::fs::read_to_string(data.join("devices.json")).unwrap();
        assert!(!raw.contains(&t) && !raw.contains(&t[5..]), "only the salted hash is stored");
        assert_eq!(authenticate(data, &t), Some(("d1".into(), Scope::Write)));
        assert_eq!(authenticate(data, "sed1_nope"), None);
        assert_eq!(authenticate(data, "admin-token"), None);
        // Re-pairing the same device replaces its token.
        let t2 = issue(data, &info("d1"), Scope::Admin, "code").unwrap();
        assert_eq!(authenticate(data, &t), None);
        assert_eq!(authenticate(data, &t2), Some(("d1".into(), Scope::Admin)));
        assert_eq!(list(data).len(), 1);
        assert!(!list(data)[0].to_string().contains("tokenHash"));
        assert!(revoke(data, "d1").unwrap());
        assert!(!is_active(data, "d1") && authenticate(data, &t2).is_none());
        assert!(!revoke(data, "d1").unwrap());
    }

    #[test]
    fn code_flow_waits_for_approval_and_delivers_once() {
        let home = seagent_core::tmp::TempDir::new("seagent-devices-code");
        let data = home.path();
        let (code, _) = create_offer(data, Duration::from_secs(60), Scope::Write).unwrap();
        assert!(code.len() == 8 && code.bytes().all(|b| ALPHABET.contains(&b)));
        let ClaimResult::Pending { request_id, .. } = claim_code(data, &code.to_lowercase(), None, &info("p1"), "192.168.1.5") else { panic!() };
        // Another device cannot hijack a claimed code, nor poll with the wrong request id.
        assert!(matches!(claim_code(data, &code, None, &info("evil"), "192.168.1.6"), ClaimResult::Refused(409, _)));
        assert!(matches!(claim_code(data, &code, Some("wrong"), &info("p1"), "192.168.1.5"), ClaimResult::Refused(409, _)));
        assert!(matches!(claim_code(data, &code, Some(&request_id), &info("p1"), "x"), ClaimResult::Pending { .. }));
        assert_eq!(pending(data).len(), 1);
        approve(data, &code).unwrap();
        let ClaimResult::Paired(token, Scope::Write) = claim_code(data, &code, Some(&request_id), &info("p1"), "x") else { panic!() };
        assert_eq!(authenticate(data, &token).unwrap().0, "p1");
        assert!(matches!(claim_code(data, &code, Some(&request_id), &info("p1"), "x"), ClaimResult::Refused(403, _)), "delivered once");
        // Rejection.
        let (c2, _) = create_offer(data, Duration::from_secs(60), Scope::Write).unwrap();
        let ClaimResult::Pending { request_id: r2, .. } = claim_code(data, &c2, None, &info("p2"), "x") else { panic!() };
        assert!(reject(data, &c2));
        assert!(matches!(claim_code(data, &c2, Some(&r2), &info("p2"), "x"), ClaimResult::Refused(403, _)));
        assert!(approve(data, "ZZZZZZZZ").is_err());
        // Expired codes are gone.
        let (c3, _) = create_offer(data, Duration::from_millis(1), Scope::Write).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(claim_code(data, &c3, None, &info("p3"), "x"), ClaimResult::Refused(403, _)));
    }
}
