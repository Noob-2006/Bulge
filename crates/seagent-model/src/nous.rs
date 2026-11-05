//! Nous Portal inference credentials: the *agent key*.
//!
//! The Nous Portal hands out an OAuth pair whose access token is itself the NAS **invoke
//! JWT** that the inference host accepts (`scope: inference:invoke`). Hermes keeps that
//! token in a separate `agent_key` slot next to the OAuth pair, with its own expiry, so a
//! refresh can rotate the OAuth pair without silently keeping a dead invoke JWT — and so
//! any surface can ask "is this key still an inference-capable JWT with enough TTL left?".
//! Ported from `hermes_cli/auth_nous.py` (`_set_nous_agent_key_from_invoke_jwt`,
//! `_nous_invoke_jwt_status`, `_agent_key_is_usable`, `_unusable_invoke_jwt_error`) and
//! `hermes_cli/auth_constants.py`.
//!
//! Flow: login/refresh → [`derive_agent_key`] fills the slots → [`agent_key_status`] says
//! whether the JWT can be used → the credential source refreshes once when it cannot, and
//! fails with Hermes' re-login message when there is nothing left to redeem.

use crate::store::Entry;
use serde_json::Value;

/// Scope the inference host requires on the invoke JWT.
pub const INFERENCE_INVOKE_SCOPE: &str = "inference:invoke";
/// Refresh this long before the invoke JWT expires (`ACCESS_TOKEN_REFRESH_SKEW_SECONDS`).
pub const MIN_TTL_SECS: u64 = 120;
/// Portal client id; Hermes pins `hermes-cli`, overridable here for self-hosted portals.
pub const DEFAULT_CLIENT_ID: &str = "hermes-cli";

pub const DEFAULT_PORTAL_URL: &str = "https://portal.nousresearch.com";
pub const DEFAULT_INFERENCE_URL: &str = "https://inference-api.nousresearch.com/v1";

/// Portal client id (`$SEAGENT_NOUS_CLIENT_ID` / `$NOUS_CLIENT_ID`, else Hermes' default).
pub fn client_id() -> String {
    ["SEAGENT_NOUS_CLIENT_ID", "NOUS_CLIENT_ID"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string())
}

/// Inference host for this account: the stored `inference_base_url`, else the production one.
pub fn inference_base_url(e: Option<&Entry>) -> String {
    e.and_then(|e| e.extra.get("inference_base_url"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| DEFAULT_INFERENCE_URL.to_string())
}

fn scopes(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s
            .split([' ', ',' , ';'])
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .flat_map(|x| scopes(Some(x)))
            .collect(),
        _ => vec![],
    }
}

/// Why an access token is not a usable inference JWT (`None` = usable).
///
/// Mirrors Hermes `_nous_invoke_jwt_status`: the token must be a JWT that carries
/// [`INFERENCE_INVOKE_SCOPE`] (its own `scope`/`scp` claim, or the login's scope) and must
/// keep more than `min_ttl` seconds of life.
pub fn jwt_status(
    token: &str,
    scope: Option<&Value>,
    expires_at_ms: Option<u64>,
    min_ttl_secs: u64,
    now_ms: u64,
) -> Option<&'static str> {
    let claims = match crate::login::jwt_claims(token) {
        Some(c) if c.is_object() => c,
        _ => return Some("access_token_not_jwt"),
    };
    let mut have: Vec<String> = scopes(scope);
    have.extend(scopes(claims.get("scope")));
    have.extend(scopes(claims.get("scp")));
    if !have.iter().any(|s| s == INFERENCE_INVOKE_SCOPE) {
        return Some("missing_inference_invoke_scope");
    }
    let skew = min_ttl_secs.saturating_mul(1000);
    match claims.get("exp").and_then(Value::as_u64) {
        Some(exp) => {
            if exp.saturating_mul(1000) <= now_ms.saturating_add(skew) {
                Some("invoke_jwt_expiring")
            } else {
                None
            }
        }
        None => {
            if expires_at_ms.is_none_or(|x| now_ms.saturating_add(skew) >= x) {
                Some("invoke_jwt_expiry_unknown_or_expiring")
            } else {
                None
            }
        }
    }
}

/// Fill the agent-key slots from the entry's access token
/// (Hermes `_set_nous_agent_key_from_invoke_jwt`). Idempotent: an unchanged token keeps its
/// original `agent_key_obtained_at` so status reads stay stable.
pub fn derive_agent_key(e: &mut Entry) {
    let Some(access) = e.key.clone().filter(|k| !k.is_empty()) else {
        return;
    };
    let prev_key = e.extra.get("agent_key").and_then(Value::as_str).map(String::from);
    let prev_at = e.extra.get("agent_key_obtained_at").and_then(Value::as_u64);
    let claims = crate::login::jwt_claims(&access).filter(Value::is_object);
    let jwt_exp = claims.as_ref().and_then(|c| c["exp"].as_u64()).map(|x| x * 1000);
    let expires_at = jwt_exp.or(e.expires_at_ms);
    let now = crate::ratelimit::now_ms();
    let reused = prev_key.as_deref() == Some(access.as_str()) && prev_at.is_some();
    e.extra.insert("agent_key".into(), Value::String(access));
    e.extra.insert("agent_key_id".into(), Value::Null);
    e.extra.insert(
        "agent_key_expires_at".into(),
        expires_at.map(Value::from).unwrap_or(Value::Null),
    );
    e.extra.insert(
        "agent_key_expires_in".into(),
        Value::from(expires_at.map(|x| x.saturating_sub(now) / 1000).unwrap_or(0)),
    );
    e.extra.insert("agent_key_reused".into(), Value::Bool(reused));
    if !reused {
        e.extra
            .insert("agent_key_obtained_at".into(), Value::from(now));
    }
    if let Some(x) = expires_at {
        e.expires_at_ms.get_or_insert(x);
    }
}

/// The stored invoke JWT (the `agent_key` slot), when it exists.
pub fn agent_key(e: &Entry) -> Option<String> {
    e.extra
        .get("agent_key")
        .and_then(Value::as_str)
        .map(String::from)
        .filter(|k| !k.is_empty())
}

/// Why the stored agent key cannot be used for inference (`None` = usable).
pub fn agent_key_status(e: &Entry, min_ttl_secs: u64) -> Option<&'static str> {
    let key = agent_key(e).or_else(|| e.key.clone())?;
    let expires = e
        .extra
        .get("agent_key_expires_at")
        .and_then(Value::as_u64)
        .or(e.expires_at_ms);
    jwt_status(
        &key,
        e.extra.get("scope"),
        expires,
        min_ttl_secs,
        crate::ratelimit::now_ms(),
    )
}

/// Hermes' terminal error for an access token that is not a usable inference JWT.
pub fn unusable_error(reason: &str, no_refresh_token: bool) -> String {
    format!(
        "Nous Portal access token is not a usable inference JWT ({reason}){}. Re-authenticate with: seagent login nous",
        if no_refresh_token {
            " and no refresh token is available"
        } else {
            ""
        }
    )
}

/// Auth error for a stored Nous credential that cannot serve inference.
pub fn auth_error(e: &Entry) -> String {
    let reason = agent_key_status(e, MIN_TTL_SECS).unwrap_or("missing_agent_key");
    unusable_error(reason, e.refresh.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: Value) -> String {
        let head = seagent_net::crypto::b64url(br#"{"alg":"none","typ":"JWT"}"#);
        let body = seagent_net::crypto::b64url(claims.to_string().as_bytes());
        format!("{head}.{body}.")
    }

    fn raw_entry(claims: Value) -> Entry {
        let mut e = Entry::new("oauth", "nous", Some(jwt(claims)));
        e.flow = Some("nous".into());
        e.refresh = Some("rt-1".into());
        e
    }

    fn nous_entry(claims: Value) -> Entry {
        let mut e = raw_entry(claims);
        derive_agent_key(&mut e);
        e
    }

    #[test]
    fn a_fresh_invoke_jwt_is_derived_into_the_agent_key_slots() {
        let now = crate::ratelimit::now_ms() / 1000;
        let mut e = raw_entry(serde_json::json!({"exp": now + 3600}));
        derive_agent_key(&mut e);
        assert_eq!(agent_key(&e).as_deref(), e.key.as_deref());
        assert!(e.extra["agent_key_expires_at"].as_u64().unwrap() > crate::ratelimit::now_ms());
        assert!(e.extra["agent_key_expires_in"].as_u64().unwrap() > 3000);
        assert_eq!(e.extra["agent_key_reused"], Value::Bool(false));
        assert!(e.extra["agent_key_obtained_at"].as_u64().is_some());
        // The login's scope counts even when the JWT has none.
        e.extra.insert("scope".into(), Value::String(INFERENCE_INVOKE_SCOPE.into()));
        assert_eq!(agent_key_status(&e, MIN_TTL_SECS), None);
        // Deriving again does not restart the obtained_at clock.
        let at = e.extra["agent_key_obtained_at"].clone();
        derive_agent_key(&mut e);
        assert_eq!(e.extra["agent_key_obtained_at"], at);
        assert_eq!(e.extra["agent_key_reused"], Value::Bool(true));
    }

    #[test]
    fn status_names_every_unusable_reason() {
        let now = crate::ratelimit::now_ms();
        // Not a JWT at all.
        assert_eq!(
            jwt_status("opaque-token", None, Some(now + 3_600_000), 120, now),
            Some("access_token_not_jwt")
        );
        // JWT without the invoke scope.
        let t = jwt(serde_json::json!({"exp": now / 1000 + 3600}));
        assert_eq!(
            jwt_status(&t, None, None, 120, now),
            Some("missing_inference_invoke_scope")
        );
        // Scope from `scp` is accepted.
        let t = jwt(serde_json::json!({"exp": now / 1000 + 3600, "scp": ["inference:invoke"]}));
        assert_eq!(jwt_status(&t, None, None, 120, now), None);
        // Inside the refresh skew.
        let t = jwt(serde_json::json!({"exp": (now / 1000) + 30, "scope": INFERENCE_INVOKE_SCOPE}));
        assert_eq!(jwt_status(&t, None, None, 120, now), Some("invoke_jwt_expiring"));
        // No exp claim: fall back to the stored expiry.
        let t = jwt(serde_json::json!({"scope": INFERENCE_INVOKE_SCOPE}));
        assert_eq!(
            jwt_status(&t, None, Some(now + 60_000), 120, now),
            Some("invoke_jwt_expiry_unknown_or_expiring")
        );
        assert_eq!(jwt_status(&t, None, Some(now + 600_000), 120, now), None);
    }

    #[test]
    fn an_expired_agent_key_reports_the_hermes_relogin_message() {
        let now = crate::ratelimit::now_ms() / 1000;
        let e = nous_entry(serde_json::json!({"exp": now - 10, "scope": INFERENCE_INVOKE_SCOPE}));
        assert_eq!(agent_key_status(&e, MIN_TTL_SECS), Some("invoke_jwt_expiring"));
        let msg = auth_error(&e);
        assert!(msg.contains("not a usable inference JWT (invoke_jwt_expiring)"), "{msg}");
        assert!(msg.contains("seagent login nous"), "{msg}");
        let mut no_rt = e.clone();
        no_rt.refresh = None;
        assert!(auth_error(&no_rt).contains("and no refresh token is available"));
    }

    #[test]
    fn client_id_and_inference_url_follow_the_environment() {
        assert_eq!(client_id(), DEFAULT_CLIENT_ID);
        std::env::set_var("NOUS_CLIENT_ID", "my-portal");
        assert_eq!(client_id(), "my-portal");
        std::env::remove_var("NOUS_CLIENT_ID");
        let mut e = Entry::new("oauth", "nous", None);
        assert_eq!(inference_base_url(Some(&e)), DEFAULT_INFERENCE_URL);
        e.extra.insert(
            "inference_base_url".into(),
            Value::String("https://welcome-api.nousresearch.com/v1".into()),
        );
        assert_eq!(
            inference_base_url(Some(&e)),
            "https://welcome-api.nousresearch.com/v1"
        );
    }
}
