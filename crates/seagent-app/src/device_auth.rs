//! Device-bound credentials for paired devices (docs/SECURITY.md §8): a stolen console token
//! alone is not enough.
//!
//! A device that pairs with `device.publicKey` (WebCrypto / ring ECDSA P-256, the private key
//! never leaves the device; in browsers it is a non-extractable `CryptoKey`) is **key-bound**.
//! Its long-lived console token (`sed1_…`) is then refused as a bearer everywhere except here,
//! where it buys a short-lived access token (`sea1_…`, `[app.exposure] device_access_ttl_secs`,
//! default 3600) together with a fresh signature:
//!
//! ```text
//! GET  /pair/info   → {"hostId", "nowMs", "protocol"}       (public: what to sign for)
//! POST /pair/refresh            Authorization: Bearer sed1_…
//! {"deviceId", "ts": <unix ms>, "nonce": "<16–64 url-safe chars>", "sig": "<b64url r‖s>",
//!  "publicKey"?: "<b64url 65-byte point>"}        (publicKey: only to bind a legacy device)
//!   → 200 {"accessToken", "expiresAtMs", "scope", "keyBound": true}
//!   → 401 {"error"} bad token / signature / stale ts / replayed nonce, 429 locked out
//! sig = ECDSA-P256-SHA256 over "seagent-device-refresh|v1|<hostId>|<deviceId>|<ts>|<nonce>"
//! ```
//!
//! `ts` must be within [`SKEW`] of the host clock and each nonce is accepted once inside that
//! window, so a captured refresh cannot be replayed; the host id in the message stops a
//! signature for one host being used at another. **Migration**: a device paired before keys
//! existed sends its console token plus `publicKey` once (the apps and the web console do it on
//! their next start); from then on it is key-bound. Access tokens live in memory only, so a
//! daemon restart costs each device one silent refresh.
//!
//! **Across restarts** the nonce memory is not written to disk: a refresh must also be signed
//! after this process started ([`started_ms`]; clients sign with the host clock from
//! `/pair/info`), so a refresh captured before a restart cannot be replayed after it, and the
//! nonces of the current run cover the rest of the window. No disk write per refresh.

use crate::devices;
use serde_json::{json, Value};
use std::time::Duration;

/// Accepted clock difference (and the nonce memory) for refresh signatures.
pub const SKEW: Duration = Duration::from_secs(300);

/// When this process started serving refreshes (the replay floor across restarts).
pub fn started_ms() -> u64 {
    static S: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *S.get_or_init(now_ms)
}

/// What the device signs.
pub fn refresh_message(host_id: &str, device_id: &str, ts: u64, nonce: &str) -> String {
    format!("seagent-device-refresh|v1|{host_id}|{device_id}|{ts}|{nonce}")
}

/// `[app.exposure] device_access_ttl_secs` as a duration.
pub fn access_ttl(app: &crate::App) -> Duration {
    Duration::from_secs(u64::from(app.cfg.exposure.device_access_ttl_secs.clamp(2, 86_400)))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn reply(status: u16, v: Value) -> seagent_net::httpd::Response {
    seagent_net::httpd::Response::json(status, &v.to_string()).with_header("cache-control", "no-store")
}

/// Check one refresh request. `Ok((device, bind))`: `bind` is the key to bind (migration).
/// `floor`: refreshes signed before it (an earlier run of the daemon) are refused.
pub fn verify(data: &std::path::Path, token: &str, body: &Value, now: u64, floor: u64) -> Result<(devices::Device, Option<String>), String> {
    let dev = devices::by_console_token(data, token).ok_or("unknown or revoked device token")?;
    if body["deviceId"].as_str() != Some(dev.id.as_str()) {
        return Err("deviceId does not match the token".into());
    }
    let ts = body["ts"].as_u64().ok_or("ts (unix ms) missing")?;
    if ts.abs_diff(now) > SKEW.as_millis() as u64 {
        return Err("ts is outside the replay window; check this device's clock".into());
    }
    if ts < floor {
        return Err("signed before this host started; sign again with GET /pair/info's clock".into());
    }
    let nonce = body["nonce"].as_str().unwrap_or("");
    if !(16..=64).contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("nonce must be 16–64 url-safe characters".into());
    }
    let offered = match body["publicKey"].as_str().filter(|k| !k.trim().is_empty()) {
        Some(k) => Some(devices::parse_public_key(k)?),
        None => None,
    };
    let (key, bind) = match (&dev.public_key, offered) {
        (Some(have), Some(k)) if *have != k => return Err("this device is bound to another key; pair it again".into()),
        (Some(have), _) => (have.clone(), None),
        (None, Some(k)) => (k.clone(), Some(k)),
        (None, None) => return Err("send publicKey to bind this device to a key".into()),
    };
    let pk = seagent_net::crypto::b64url_decode(&key).ok_or("bad stored key")?;
    let sig = body["sig"].as_str().and_then(|s| seagent_net::crypto::b64url_decode(s.trim_end_matches('='))).ok_or("sig missing")?;
    let msg = refresh_message(&crate::lan::host_id(data), &dev.id, ts, nonce);
    if !seagent_net::crypto::p256_verify(&pk, msg.as_bytes(), &sig) {
        return Err("bad device signature".into());
    }
    // Only a valid signature spends the nonce (an attacker cannot burn a device's nonces).
    if !devices::take_nonce(data, &dev.id, nonce, SKEW * 2) {
        return Err("replayed nonce".into());
    }
    Ok((dev, bind))
}

/// `GET /pair/info`: what a device signs for — the host id (public: mDNS carries it too) and the
/// host clock, so a device with a wrong clock can still sign a timestamp inside [`SKEW`].
pub fn info(app: &crate::App) -> seagent_net::httpd::Response {
    started_ms(); // a timestamp from this clock is never below the floor
    reply(200, json!({"hostId": crate::lan::host_id(&app.d.k.paths.data), "nowMs": now_ms(), "protocol": crate::lan::PROTOCOL, "refresh": true}))
}

/// `POST /pair/refresh` (see the module docs).
pub fn handle_refresh(app: &crate::App, r: &seagent_net::httpd::Request) -> seagent_net::httpd::Response {
    let data = &app.d.k.paths.data;
    let ip = app.client_ip(r).map(|i| i.to_string()).unwrap_or_default();
    if let Some(wait) = crate::netguard::locked(app, r) {
        return crate::netguard::locked_reply(wait);
    }
    if !crate::exposure::is_json_content_type(r.header("content-type")) {
        return reply(415, json!({"error": "send JSON (content-type: application/json)"}));
    }
    let Ok(body) = serde_json::from_slice::<Value>(&r.body) else { return reply(400, json!({"error": "the body is not JSON"})) };
    let token = r.bearer().unwrap_or("");
    match verify(data, token, &body, now_ms(), started_ms()) {
        Ok((dev, bind)) => {
            let actor = seagent_security::audit::Actor::new("device", &dev.name).with_ip(&ip);
            if let Some(k) = bind {
                if let Err(e) = devices::bind_key(data, &dev.id, &k) {
                    return reply(409, json!({"error": e}));
                }
                seagent_security::audit::record(data, seagent_security::audit::Event::new("device.bind", actor, &dev.id, "ok").detail(json!({"platform": dev.platform, "migrated": true})));
            }
            crate::netguard::auth_ok(app, r);
            if let Some(ks) = body["keyStore"].as_str() {
                devices::note_key_store(data, &dev.id, ks);
            }
            if let Some(net) = devices::note_network(data, &dev.id, &ip) {
                crate::netguard::alert_owner(app, &format!("net:{}:{net}", dev.id), &format!("paired device {} ({}) appeared from a network it has not used before: {net} ({ip}); not blocked — revoke it if this was not you", dev.name, dev.platform));
            }
            match devices::mint_access(data, &dev.id, access_ttl(app)) {
                Ok((t, exp)) => reply(200, json!({"accessToken": t, "expiresAtMs": exp, "scope": dev.scope.as_str(), "keyBound": true})),
                Err(e) => reply(401, json!({"error": e})),
            }
        }
        Err(e) => {
            crate::netguard::auth_failed(app, r, "device.refresh");
            seagent_security::audit::record(data, seagent_security::audit::Event::new("device.refresh", seagent_security::audit::Actor::new("device", body["deviceId"].as_str().unwrap_or("")).with_ip(&ip), "pair/refresh", "deny").detail(json!({"reason": e})));
            reply(401, json!({"error": e}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::{issue, DeviceInfo};
    use crate::exposure::Scope;
    use seagent_net::crypto;

    fn signed(data: &std::path::Path, key: &[u8], dev: &str, ts: u64, nonce: &str) -> Value {
        let sig = crypto::p256_sign(key, refresh_message(&crate::lan::host_id(data), dev, ts, nonce).as_bytes()).unwrap();
        json!({"deviceId": dev, "ts": ts, "nonce": nonce, "sig": crypto::b64url(&sig)})
    }

    #[test]
    fn the_message_format_is_the_documented_one() {
        // The desktop / mobile app (apps/desktop/src-tauri/src/devkey.rs) and ui/web/devauth.js
        // build exactly this string.
        assert_eq!(refresh_message("h", "d", 1, "n"), "seagent-device-refresh|v1|h|d|1|n");
    }

    #[test]
    fn refresh_needs_the_key_a_fresh_timestamp_and_an_unused_nonce() {
        let home = seagent_core::tmp::TempDir::new("seagent-devauth");
        let data = home.path();
        let key = crypto::p256_generate().unwrap();
        let pk = crypto::b64url(&crypto::p256_public(&key).unwrap());
        let tok = issue(data, &DeviceInfo { id: "p1".into(), name: "phone".into(), platform: "android".into(), public_key: Some(pk) }, Scope::Write, "code").unwrap();
        let now = now_ms();
        let good = signed(data, &key, "p1", now, "nonce-0123456789ab");
        assert!(verify(data, &tok, &good, now, 0).is_ok());
        assert_eq!(verify(data, &tok, &good, now, 0).unwrap_err(), "replayed nonce");
        // A thief with the console token but another key (or none) gets nothing.
        let thief = crypto::p256_generate().unwrap();
        assert_eq!(verify(data, &tok, &signed(data, &thief, "p1", now, "nonce-thief-000001"), now, 0).unwrap_err(), "bad device signature");
        let mut forged = signed(data, &thief, "p1", now, "nonce-thief-000002");
        forged["publicKey"] = crypto::b64url(&crypto::p256_public(&thief).unwrap()).into();
        assert!(verify(data, &tok, &forged, now, 0).unwrap_err().contains("bound to another key"));
        // Stale / future timestamps, wrong device, wrong token.
        assert!(verify(data, &tok, &signed(data, &key, "p1", now - 600_000, "nonce-old-00000001"), now, 0).unwrap_err().contains("replay window"));
        assert!(verify(data, &tok, &signed(data, &key, "p1", now + 600_000, "nonce-new-00000001"), now, 0).unwrap_err().contains("replay window"));
        assert!(verify(data, &tok, &signed(data, &key, "p2", now, "nonce-dev-00000001"), now, 0).unwrap_err().contains("deviceId"));
        assert!(verify(data, "sed1_nope", &good, now, 0).is_err());
        // A signature for another host id is not valid here.
        let elsewhere = crypto::p256_sign(&key, refresh_message("0000000000000000", "p1", now, "nonce-host-0000001").as_bytes()).unwrap();
        assert_eq!(verify(data, &tok, &json!({"deviceId": "p1", "ts": now, "nonce": "nonce-host-0000001", "sig": crypto::b64url(&elsewhere)}), now, 0).unwrap_err(), "bad device signature");
    }

    #[test]
    fn a_refresh_signed_before_a_restart_is_refused_after_it() {
        let home = seagent_core::tmp::TempDir::new("seagent-devauth-restart");
        let data = home.path();
        let key = crypto::p256_generate().unwrap();
        let tok = issue(data, &DeviceInfo { id: "r1".into(), name: "laptop".into(), platform: "macos".into(), public_key: Some(crypto::b64url(&crypto::p256_public(&key).unwrap())) }, Scope::Write, "code").unwrap();
        let now = now_ms();
        let captured = signed(data, &key, "r1", now - 1_000, "nonce-before-restart");
        // "Restart": the nonce memory is gone, the floor is the new start time.
        assert!(verify(data, &tok, &captured, now, now - 500).unwrap_err().contains("before this host started"));
        assert!(verify(data, &tok, &signed(data, &key, "r1", now, "nonce-after-restart0"), now, now - 500).is_ok(), "a fresh one works at once");
    }

    #[test]
    fn a_legacy_device_binds_its_first_key_and_only_that_one() {
        let home = seagent_core::tmp::TempDir::new("seagent-devauth-mig");
        let data = home.path();
        let tok = issue(data, &DeviceInfo { id: "old".into(), name: "old app".into(), platform: "windows".into(), public_key: None }, Scope::Write, "bootstrap").unwrap();
        let key = crypto::p256_generate().unwrap();
        let now = now_ms();
        let mut b = signed(data, &key, "old", now, "nonce-bind-000001");
        assert!(verify(data, &tok, &b, now, 0).unwrap_err().contains("send publicKey"), "no key, no access token");
        b["publicKey"] = crypto::b64url(&crypto::p256_public(&key).unwrap()).into();
        let (dev, bind) = verify(data, &tok, &b, now, 0).unwrap();
        assert_eq!(dev.id, "old");
        crate::devices::bind_key(data, "old", &bind.unwrap()).unwrap();
        assert_eq!(crate::devices::authenticate_at(data, &tok, "", false), Err(crate::devices::AuthError::NeedsSignature));
        assert!(verify(data, &tok, &signed(data, &key, "old", now, "nonce-after-00001"), now, 0).is_ok(), "bound: no publicKey needed");
    }
}
