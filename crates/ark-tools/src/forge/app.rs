//! GitHub App identity: sign an RS256 JWT with the App's private key and exchange it for a
//! short-lived installation token. The token then works like any other (`Authorization: Bearer`)
//! and expires on its own, so the agent's writes are attributed to the App (`name[bot]`) and
//! limited to what the App was granted — no personal access token involved.

use crate::pro_http;
use ark_net::crypto::{b64url, hex, sha256};
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static CACHE: Mutex<Vec<(String, String, Instant)>> = Mutex::new(Vec::new());

/// DER of the first PEM block (PKCS#1 `RSA PRIVATE KEY` or PKCS#8 `PRIVATE KEY`).
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----") && !l.trim().is_empty()).map(str::trim).collect();
    if body.is_empty() {
        return Err("the private key is empty".into());
    }
    ark_net::crypto::b64_decode(&body).ok_or_else(|| "the private key is not valid PEM".to_string())
}

fn key_pair(pem: &str) -> Result<RsaKeyPair, String> {
    let der = pem_to_der(pem)?;
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        RsaKeyPair::from_der(&der).map_err(|e| format!("cannot use the RSA key: {e}"))
    } else {
        RsaKeyPair::from_pkcs8(&der).or_else(|_| RsaKeyPair::from_der(&der)).map_err(|e| format!("cannot use the RSA key (PKCS#8 or PKCS#1 PEM expected): {e}"))
    }
}

/// `header.payload.signature` valid for ten minutes (GitHub's maximum), issued 60 s in the past
/// to absorb clock drift.
pub fn app_jwt(app_id: &str, pem: &str, now_unix: u64) -> Result<String, String> {
    let kp = key_pair(pem)?;
    let head = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = b64url(json!({"iat": now_unix.saturating_sub(60), "exp": now_unix + 9 * 60, "iss": app_id}).to_string().as_bytes());
    let signing_input = format!("{head}.{claims}");
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(&RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig).map_err(|_| "signing the App JWT failed".to_string())?;
    Ok(format!("{signing_input}.{}", b64url(&sig)))
}

/// An installation access token for `installation_id` (cached for 50 minutes per key+install).
pub fn installation_token(api_base: &str, app_id: &str, installation_id: &str, pem: &str, timeout: u64) -> Result<String, String> {
    let key = hex(&sha256(format!("{api_base}|{app_id}|{installation_id}|{}", pem.len()).as_bytes()));
    {
        let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|(_, _, t)| t.elapsed() < Duration::from_secs(50 * 60));
        if let Some((_, t, _)) = c.iter().find(|(k, ..)| *k == key) {
            return Ok(t.clone());
        }
    }
    if !installation_id.chars().all(|c| c.is_ascii_digit()) || installation_id.is_empty() {
        return Err("installation_id must be numeric".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let jwt = app_jwt(app_id, pem, now)?;
    let url = format!("{}/app/installations/{installation_id}/access_tokens", api_base.trim_end_matches('/'));
    let r = pro_http::send("POST", &url, &[("Authorization", format!("Bearer {jwt}")), ("Accept", "application/vnd.github+json".into()), ("X-GitHub-Api-Version", "2022-11-28".into()), ("User-Agent", "ark".into())], None, timeout, &[&jwt])?;
    if !r.ok() {
        return Err(pro_http::api_error("GitHub App token exchange", &r, &[&jwt]));
    }
    let v: Value = r.json()?;
    let tok = v["token"].as_str().ok_or("GitHub answered without a token")?.to_string();
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).push((key, tok.clone(), Instant::now()));
    Ok(tok)
}
