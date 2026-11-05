//! Inbound cron fires for the `chronos` provider (Hermes `plugins/cron_providers/chronos/verify.py`
//! and the gateway's `/api/cron/fire`): mounted at `/plugins/cron/fire`, public (it authenticates
//! itself). The caller sends `Authorization: Bearer <JWT>`; the token must be signed with an
//! asymmetric key from the configured JWKS (RS256/384/512, ES256/384 — symmetric `HS*` and
//! `none` are refused), carry the expected `aud`, a valid `exp`/`nbf` (30 s leeway), the
//! configured `iss` when set, and `purpose = "cron_fire"`. Any failure is a bare 401 (no hint
//! about which check failed). The body is `{"job_id": "…"}`.

use crate::server::{mount, Mount};
use ark_kernel::cronjob::chronos;
use ark_kernel::kernel::Kernel;
use ark_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const LEEWAY_SECS: i64 = 30;

#[derive(Debug, Clone)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub fn parse_jwks(v: &Value) -> Vec<Jwk> {
    let d = |k: &Value| k.as_str().and_then(|s| ark_net::crypto::b64url_decode(s.trim_end_matches('='))).unwrap_or_default();
    v.get("keys").and_then(|k| k.as_array()).map(|a| a.iter().map(|k| Jwk { kid: k["kid"].as_str().unwrap_or("").into(), kty: k["kty"].as_str().unwrap_or("").into(), crv: k["crv"].as_str().unwrap_or("").into(), n: d(&k["n"]), e: d(&k["e"]), x: d(&k["x"]), y: d(&k["y"]) }).collect()).unwrap_or_default()
}

/// JWKS from a URL (cached; refetched on an unknown kid at most every 30 s) or inline JSON.
pub struct Keys {
    src: String,
    cache: Mutex<(Vec<Jwk>, Option<Instant>)>,
}

impl Keys {
    pub fn new(src: &str) -> Keys {
        Keys { src: src.trim().to_string(), cache: Mutex::new((vec![], None)) }
    }
    fn fetch(&self) -> Result<Vec<Jwk>, String> {
        if self.src.starts_with('{') {
            return Ok(parse_jwks(&serde_json::from_str(&self.src).map_err(|e| e.to_string())?));
        }
        if !(self.src.starts_with("https://") || self.src.starts_with("http://")) {
            return Err("no JWKS configured".into());
        }
        let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(Duration::from_secs(15))).build().into();
        let text = agent.get(&self.src).header("Accept", "application/json").header("User-Agent", concat!("ark/", env!("CARGO_PKG_VERSION"))).call().map_err(|e| e.to_string())?.body_mut().read_to_string().map_err(|e| e.to_string())?;
        Ok(parse_jwks(&serde_json::from_str(&text).map_err(|e| e.to_string())?))
    }
    pub fn key(&self, kid: &str) -> Result<Jwk, String> {
        let mut c = self.cache.lock().unwrap();
        let pick = |keys: &[Jwk]| keys.iter().find(|k| k.kid == kid || (kid.is_empty() && keys.len() == 1)).cloned();
        if let Some(k) = pick(&c.0) {
            return Ok(k);
        }
        if c.1.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
            return Err("unknown key id".into());
        }
        c.1 = Some(Instant::now());
        c.0 = self.fetch()?;
        pick(&c.0).ok_or_else(|| "unknown key id".into())
    }
}

fn aud_ok(claims: &Value, want: &str) -> bool {
    match &claims["aud"] {
        Value::String(s) => s == want,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(want)),
        _ => false,
    }
}

/// Verify a fire token; `Ok(claims)` or an internal reason (logged, never returned to the caller).
pub fn verify(token: &str, keys: &Keys, audience: &str, issuer: Option<&str>, now: i64) -> Result<Value, String> {
    let claims = verify_with(token, keys, audience, issuer, now, LEEWAY_SECS)?;
    // A fire token, not any other kind of bearer (the dashboard auth gate wants plain ID tokens).
    if claims["purpose"].as_str() != Some(chronos::FIRE_PURPOSE) {
        return Err("missing/wrong purpose claim".into());
    }
    Ok(claims)
}

/// [`verify`] with an explicit clock-skew leeway (seconds), applied symmetrically to `exp`,
/// `nbf` and `iat` (only the claims a token carries). The dashboard auth gate uses 60 s
/// (Hermes `DEFAULT_TOKEN_LEEWAY_SECONDS`); cron fires keep [`LEEWAY_SECS`].
pub(crate) fn verify_with(token: &str, keys: &Keys, audience: &str, issuer: Option<&str>, now: i64, leeway: i64) -> Result<Value, String> {
    if token.is_empty() || audience.is_empty() {
        return Err("missing token or audience".into());
    }
    let mut parts = token.trim().split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return Err("malformed JWT".into()) };
    let header: Value = ark_net::crypto::b64url_decode(h).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("bad header")?;
    let claims: Value = ark_net::crypto::b64url_decode(p).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("bad payload")?;
    let sig = ark_net::crypto::b64url_decode(s).ok_or("bad signature encoding")?;
    let alg = header["alg"].as_str().unwrap_or("");
    let key = keys.key(header["kid"].as_str().unwrap_or(""))?;
    let msg = format!("{h}.{p}");
    use ring::signature as sg;
    let ok = match alg {
        "RS256" | "RS384" | "RS512" if key.kty == "RSA" => {
            let a: &sg::RsaParameters = match alg {
                "RS256" => &sg::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &sg::RSA_PKCS1_2048_8192_SHA384,
                _ => &sg::RSA_PKCS1_2048_8192_SHA512,
            };
            sg::RsaPublicKeyComponents { n: &key.n, e: &key.e }.verify(a, msg.as_bytes(), &sig).is_ok()
        }
        "ES256" | "ES384" if key.kty == "EC" => {
            let a: &dyn sg::VerificationAlgorithm = if alg == "ES256" { &sg::ECDSA_P256_SHA256_FIXED } else { &sg::ECDSA_P384_SHA384_FIXED };
            let mut pt = vec![4u8];
            pt.extend(&key.x);
            pt.extend(&key.y);
            sg::UnparsedPublicKey::new(a, pt).verify(msg.as_bytes(), &sig).is_ok()
        }
        other => return Err(format!("algorithm `{other}` refused")),
    };
    if !ok {
        return Err("bad signature".into());
    }
    let exp = claims["exp"].as_i64().ok_or("no exp")?;
    if now > exp + leeway {
        return Err("expired".into());
    }
    if claims["nbf"].as_i64().is_some_and(|nbf| now + leeway < nbf) {
        return Err("not yet valid".into());
    }
    if claims["iat"].as_i64().is_some_and(|iat| now + leeway < iat) {
        return Err("issued in the future".into());
    }
    if !aud_ok(&claims, audience) {
        return Err("audience mismatch".into());
    }
    if let Some(iss) = issuer {
        if claims["iss"].as_str() != Some(iss) {
            return Err("issuer mismatch".into());
        }
    }
    Ok(claims)
}

pub struct FireMount {
    pub k: Kernel,
    pub keys: Keys,
    pub cfg: chronos::ChronosConfig,
}

impl Mount for FireMount {
    fn route(&self, method: &str, sub: &str) -> Option<bool> {
        (method == "POST" && sub.trim_matches('/') == "fire").then_some(true)
    }
    fn serve(&self, r: &Request, _sub: &str) -> Response {
        let now = ark_kernel::util::unix_now();
        if let Err(e) = verify(r.bearer().unwrap_or(""), &self.keys, &self.cfg.audience, self.cfg.issuer.as_deref(), now) {
            eprintln!("arkd: cron fire: token verification failed: {e}");
            return Response::json(401, &json!({"error": "unauthorized"}).to_string());
        }
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let Some(id) = body["job_id"].as_str().filter(|s| !s.is_empty()) else {
            return Response::json(400, &json!({"error": "job_id required"}).to_string());
        };
        match chronos::fire(&self.k, id) {
            Ok(m) => Response::json(202, &json!({"ok": true, "message": m}).to_string()),
            Err(e) => Response::json(409, &json!({"ok": false, "error": e}).to_string()),
        }
    }
}

/// Activate the provider and mount the fire endpoint when `[automation] provider = "chronos"`.
pub fn install(k: &Kernel) -> bool {
    if !chronos::install(k) {
        return false;
    }
    let Some(cfg) = chronos::config() else { return false };
    mount("cron", Arc::new(FireMount { k: k.clone(), keys: Keys::new(&cfg.jwks), cfg }));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn es256() -> (EcdsaKeyPair, Value) {
        let rng = SystemRandom::new();
        let pk8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pk8.as_ref(), &rng).unwrap();
        let pt = kp.public_key().as_ref().to_vec();
        let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": ark_net::crypto::b64url(&pt[1..33]), "y": ark_net::crypto::b64url(&pt[33..65])}]});
        (kp, jwks)
    }

    fn sign(kp: &EcdsaKeyPair, header: Value, claims: Value) -> String {
        let h = ark_net::crypto::b64url(header.to_string().as_bytes());
        let p = ark_net::crypto::b64url(claims.to_string().as_bytes());
        let sig = kp.sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes()).unwrap();
        format!("{h}.{p}.{}", ark_net::crypto::b64url(sig.as_ref()))
    }

    #[test]
    fn fire_tokens_need_signature_audience_expiry_and_purpose() {
        let (kp, jwks) = es256();
        let keys = Keys::new(&jwks.to_string());
        let now = 1_800_000_000;
        let good = json!({"aud": "ark", "exp": now + 60, "purpose": "cron_fire", "iss": "https://p"});
        let hdr = json!({"alg": "ES256", "kid": "k1"});
        let t = sign(&kp, hdr.clone(), good.clone());
        assert!(verify(&t, &keys, "ark", Some("https://p"), now).is_ok());
        assert!(verify(&t, &keys, "other", None, now).unwrap_err().contains("audience"));
        assert!(verify(&t, &keys, "ark", Some("https://evil"), now).unwrap_err().contains("issuer"));
        assert!(verify(&t, &keys, "ark", None, now + 600).unwrap_err().contains("expired"));
        let mut c = good.clone();
        c["purpose"] = json!("login");
        assert!(verify(&sign(&kp, hdr.clone(), c), &keys, "ark", None, now).unwrap_err().contains("purpose"));
        let mut c = good.clone();
        c["aud"] = json!(["x", "ark"]);
        assert!(verify(&sign(&kp, hdr.clone(), c), &keys, "ark", None, now).is_ok(), "aud array");
        // Tampered payload, symmetric alg, alg=none, a different key: all refused.
        let parts: Vec<&str> = t.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], ark_net::crypto::b64url(json!({"aud": "ark", "exp": now + 9999, "purpose": "cron_fire"}).to_string().as_bytes()), parts[2]);
        assert!(verify(&forged, &keys, "ark", None, now).unwrap_err().contains("signature"));
        assert!(verify(&sign(&kp, json!({"alg": "HS256", "kid": "k1"}), good.clone()), &keys, "ark", None, now).unwrap_err().contains("refused"));
        assert!(verify(&sign(&kp, json!({"alg": "none", "kid": "k1"}), good.clone()), &keys, "ark", None, now).is_err());
        let (other, _) = es256();
        assert!(verify(&sign(&other, hdr, good), &keys, "ark", None, now).is_err());
        assert!(verify("a.b", &keys, "ark", None, now).is_err());
        assert!(Keys::new("").key("k1").is_err(), "no JWKS → refuse");
    }

    #[test]
    fn mount_routes_only_post_fire() {
        let (_, jwks) = es256();
        let m = FireMount { k: test_kernel(), keys: Keys::new(&jwks.to_string()), cfg: chronos::ChronosConfig { audience: "ark".into(), ..Default::default() } };
        assert_eq!(m.route("POST", "fire"), Some(true));
        assert_eq!(m.route("GET", "fire"), None);
        let req = |auth: &str, body: &str| Request { method: "POST".into(), path: "/plugins/cron/fire".into(), query: vec![], raw_query: String::new(), headers: vec![("authorization".into(), format!("Bearer {auth}"))], body: body.as_bytes().to_vec(), peer: None, head: String::new() };
        assert_eq!(m.serve(&req("nope", "{\"job_id\":\"x\"}"), "fire").status, 401);
        // A verified fire claims a due job (and a replay of the same fire is refused).
        let (kp, jwks) = es256();
        let m = FireMount { k: m.k.clone(), keys: Keys::new(&jwks.to_string()), cfg: m.cfg.clone() };
        let data = m.k.paths.data.clone();
        std::fs::create_dir_all(&data).unwrap();
        let job = ark_kernel::automation::add_job(&data, "@hourly", "x", &data, None, false, 0).unwrap();
        ark_kernel::automation::with_list(&ark_kernel::automation::jobs_path(&data), |v: &mut Vec<ark_kernel::automation::Job>| v[0].next_run = ark_kernel::util::unix_now() - 5).unwrap();
        let now = ark_kernel::util::unix_now();
        let tok = sign(&kp, json!({"alg": "ES256", "kid": "k1"}), json!({"aud": "ark", "exp": now + 60, "purpose": "cron_fire"}));
        assert_eq!(m.serve(&req(&tok, "{}"), "fire").status, 400);
        let body = json!({"job_id": job.id}).to_string();
        assert_eq!(m.serve(&req(&tok, &body), "fire").status, 202);
        assert_eq!(m.serve(&req(&tok, &body), "fire").status, 409, "already fired");
        let after: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&data)).unwrap();
        assert_eq!(after[0].ext.runs, 1);
    }

    fn test_kernel() -> Kernel {
        struct R;
        impl ark_kernel::kernel::Resolver for R {
            fn provider(&self, _: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
                Err("none".into())
            }
        }
        let root = std::env::temp_dir().join(format!("ark-cronfire-{}", ark_kernel::util::random_hex(8)));
        let paths = ark_kernel::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        ark_kernel::kernel::new_kernel(Default::default(), paths, Arc::new(R), vec![], Arc::new(ark_kernel::vault::Vault::empty()), Arc::new(ark_kernel::approver::Policy { allow_privilege: false, allow_egress: false }))
    }
}
