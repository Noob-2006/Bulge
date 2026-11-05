//! Microsoft Graph app-only authentication and REST client (Hermes
//! `tools/microsoft_graph_auth.py` + `tools/microsoft_graph_client.py`, MIT), ported onto the
//! tree's ureq helpers (`ark_tools::web::http`).
//!
//! Credentials come from `[meetings.teams]` (`tenant_id`, `client_id`, `client_secret` — the
//! secret may be a `{{secret:NAME}}` placeholder like every other provider) and fall back to
//! `MSGRAPH_TENANT_ID` / `MSGRAPH_CLIENT_ID` / `MSGRAPH_CLIENT_SECRET`, `MSGRAPH_SCOPE`,
//! `MSGRAPH_AUTHORITY_URL`, `MSGRAPH_BASE_URL`.
//!
//! Retry policy mirrors upstream: transport errors back off exponentially (0.5 s · 2ⁿ, capped at
//! 8 s), 401 clears the token cache and refetches, 429/5xx retry (Retry-After is not surfaced by
//! the shared helper, so the backoff applies instead).

use ark_tools::web::http::{get, post_form, post_json, Resp};
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_BASE_URL: &str = "https://graph.microsoft.com/v1.0";
pub const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/.default";
pub const DEFAULT_AUTHORITY_URL: &str = "https://login.microsoftonline.com";
/// Upstream `_REQUIRED_ENV`, in the order its error message lists them.
pub const REQUIRED_ENV: [&str; 3] = ["MSGRAPH_TENANT_ID", "MSGRAPH_CLIENT_ID", "MSGRAPH_CLIENT_SECRET"];
pub const USER_AGENT: &str = "Ark-Agent/graph-client";

/// A Graph failure: `status` is `None` for transport/config problems.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphError {
    pub status: Option<u16>,
    pub message: String,
}

impl GraphError {
    pub fn new(status: Option<u16>, message: impl Into<String>) -> GraphError {
        GraphError { status, message: message.into() }
    }
    pub fn config(message: impl Into<String>) -> GraphError {
        GraphError::new(None, message)
    }
    pub fn is_permission(&self) -> bool {
        matches!(self.status, Some(401 | 403))
    }
    pub fn is_missing(&self) -> bool {
        self.status == Some(404)
    }
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for GraphError {}

/// App-only credentials for one tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
    pub authority_url: String,
}

/// `{{secret:NAME}}` resolution (the vault); values without a placeholder pass through.
pub type SecretFn = dyn Fn(&str) -> Option<String>;

fn cfg_text(t: &toml::Table, key: &str, secret: &SecretFn) -> Option<String> {
    let raw = match t.get(key)? {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let v = if raw.contains("{{secret:") {
        let name = raw.split("{{secret:").nth(1)?.split("}}").next()?.trim().to_string();
        secret(&name)?
    } else {
        raw
    };
    Some(v.trim().to_string()).filter(|s| !s.is_empty())
}

fn env_text(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|s| !s.is_empty())
}

impl Credentials {
    /// All three secrets must be present; the missing-key message is upstream's
    /// (`GraphCredentials.from_env`).
    pub fn from_parts(tenant_id: Option<String>, client_id: Option<String>, client_secret: Option<String>, scope: Option<String>, authority_url: Option<String>) -> Result<Credentials, GraphError> {
        let values = [tenant_id.clone(), client_id.clone(), client_secret.clone()];
        let missing: Vec<&str> = REQUIRED_ENV.iter().zip(values.iter()).filter(|(_, v)| v.is_none()).map(|(k, _)| *k).collect();
        if !missing.is_empty() {
            return Err(GraphError::config(format!("Missing Microsoft Graph configuration: {}", missing.join(", "))));
        }
        Ok(Credentials {
            tenant_id: tenant_id.unwrap(),
            client_id: client_id.unwrap(),
            client_secret: client_secret.unwrap(),
            scope: scope.unwrap_or_else(|| DEFAULT_SCOPE.into()),
            authority_url: authority_url.unwrap_or_else(|| DEFAULT_AUTHORITY_URL.into()),
        })
    }

    /// `[meetings.teams]` first, then `MSGRAPH_*`.
    pub fn from_config(teams: &toml::Table, secret: &SecretFn) -> Result<Credentials, GraphError> {
        let tenant_id = cfg_text(teams, "tenant_id", secret).or_else(|| env_text("MSGRAPH_TENANT_ID"));
        let client_id = cfg_text(teams, "client_id", secret).or_else(|| env_text("MSGRAPH_CLIENT_ID"));
        let client_secret = cfg_text(teams, "client_secret", secret).or_else(|| env_text("MSGRAPH_CLIENT_SECRET"));
        let scope = cfg_text(teams, "scope", secret).or_else(|| env_text("MSGRAPH_SCOPE"));
        let authority = cfg_text(teams, "authority_url", secret).or_else(|| env_text("MSGRAPH_AUTHORITY_URL"));
        Credentials::from_parts(tenant_id, client_id, client_secret, scope, authority)
    }

    /// `{authority}/{tenant}/oauth2/v2.0/token`.
    pub fn token_url(&self) -> String {
        format!("{}/{}/oauth2/v2.0/token", self.authority_url.trim().trim_end_matches('/'), self.tenant_id.trim().trim_matches('/'))
    }

    /// Base URL override for tests / sovereign clouds.
    pub fn base_url(teams: &toml::Table, secret: &SecretFn) -> String {
        cfg_text(teams, "base_url", secret).or_else(|| env_text("MSGRAPH_BASE_URL")).unwrap_or_else(|| DEFAULT_BASE_URL.into()).trim_end_matches('/').to_string()
    }
}

struct Cached {
    token: String,
    expires_at: i64,
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Bearer-token cache; the token endpoint is called at most once per `expires_in` window.
pub struct TokenProvider {
    pub creds: Credentials,
    timeout: u64,
    skew: i64,
    cached: Mutex<Option<Cached>>,
}

impl TokenProvider {
    pub fn new(creds: Credentials) -> TokenProvider {
        TokenProvider { creds, timeout: 20, skew: 120, cached: Mutex::new(None) }
    }
    pub fn clear_cache(&self) {
        *self.cached.lock().unwrap() = None;
    }

    /// `token-health` payload (upstream `inspect_token_health`).
    pub fn health(&self) -> Value {
        let c = self.cached.lock().unwrap();
        json!({
            "configured": true,
            "tenant_id": self.creds.tenant_id,
            "client_id": self.creds.client_id,
            "scope": self.creds.scope,
            "authority_url": self.creds.authority_url,
            "token_url": self.creds.token_url(),
            "cached": c.is_some(),
            "expires_in_seconds": c.as_ref().map(|c| (c.expires_at - unix_now()).max(0)),
            "is_expired": c.as_ref().map(|c| c.expires_at <= unix_now()),
            "refresh_skew_seconds": self.skew,
        })
    }

    pub fn access_token(&self, force_refresh: bool) -> Result<String, GraphError> {
        let fresh = if force_refresh {
            None
        } else {
            let c = self.cached.lock().unwrap();
            c.as_ref().filter(|c| c.expires_at > unix_now() + self.skew).map(|c| c.token.clone())
        };
        if let Some(t) = fresh {
            return Ok(t);
        }
        let form: Vec<(&str, String)> = vec![
            ("grant_type", "client_credentials".into()),
            ("client_id", self.creds.client_id.clone()),
            ("client_secret", self.creds.client_secret.clone()),
            ("scope", self.creds.scope.clone()),
        ];
        let url = self.creds.token_url();
        let r = post_form(&url, &form, &[], self.timeout).map_err(|e| GraphError::config(format!("Microsoft Graph token request failed: {e}")))?;
        if r.status >= 400 {
            return Err(GraphError::new(Some(r.status), format!("Microsoft Graph token request failed with HTTP {}: {}", r.status, token_detail(&r))));
        }
        let v: Value = r.json().map_err(|_| GraphError::config("Microsoft Graph token response was not valid JSON."))?;
        let token = v.get("access_token").and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
        if token.is_empty() {
            return Err(GraphError::config("Microsoft Graph token response did not include access_token."));
        }
        let expires_in = v.get("expires_in").and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|s| s.trim().parse().ok())));
        let Some(expires_in) = expires_in else {
            return Err(GraphError::config("Microsoft Graph token response did not include a valid expires_in."));
        };
        *self.cached.lock().unwrap() = Some(Cached { token: token.clone(), expires_at: unix_now() + expires_in.max(0) });
        Ok(token)
    }
}

/// Best human-readable detail from a token-endpoint error body (upstream `_extract_error_detail`).
fn token_detail(r: &Resp) -> String {
    let Ok(v) = r.json() else {
        return if r.body.trim().is_empty() { "unknown error".into() } else { r.body.trim().to_string() };
    };
    if let Some(d) = v.get("error_description").and_then(Value::as_str) {
        return d.to_string();
    }
    if let Some(d) = format_graph_error(v.get("error")) {
        return d;
    }
    v.to_string()
}

/// `{"error": {"code","message"}}` (or a bare string) → `"code: message"`.
pub fn format_graph_error(error: Option<&Value>) -> Option<String> {
    match error? {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => {
            let code = o.get("code").map(|c| c.as_str().map(str::to_string).unwrap_or_else(|| c.to_string()));
            let message = o.get("message").map(|m| m.as_str().map(str::to_string).unwrap_or_else(|| m.to_string()));
            match (code, message) {
                (Some(c), Some(m)) if !c.is_empty() && !m.is_empty() => Some(format!("{c}: {m}")),
                (_, Some(m)) => Some(m),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Minimal Graph REST client over [`ark_tools::web::http`].
pub struct Client {
    pub base: String,
    pub tokens: TokenProvider,
    timeout: u64,
    max_retries: u32,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the token cache or credentials.
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(creds: Credentials, base: &str) -> Client {
        Client { base: base.trim_end_matches('/').to_string(), tokens: TokenProvider::new(creds), timeout: 60, max_retries: 3 }
    }

    /// From `[meetings.teams]` (+ `MSGRAPH_*`); `Err` carries upstream's missing-key message.
    pub fn from_config(teams: &toml::Table, secret: &SecretFn) -> Result<Client, GraphError> {
        Ok(Client::new(Credentials::from_config(teams, secret)?, &Credentials::base_url(teams, secret)))
    }

    pub fn token_health(&self) -> Value {
        self.tokens.health()
    }

    fn url(&self, path_or_url: &str) -> String {
        if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            path_or_url.to_string()
        } else if path_or_url.starts_with('/') {
            format!("{}{path_or_url}", self.base)
        } else {
            format!("{}/{}", self.base, path_or_url)
        }
    }

    fn api_error(&self, method: &str, url: &str, r: &Resp) -> GraphError {
        let detail = serde_json::from_str::<Value>(&r.body).ok().and_then(|v| format_graph_error(v.get("error")));
        let message = detail.unwrap_or_else(|| if r.body.trim().is_empty() { "unknown error".into() } else { ark_kernel::util::head_tail(r.body.trim(), 2000).0 });
        GraphError::new(Some(r.status), format!("Microsoft Graph API error {} for {method} {url}: {message}", r.status))
    }

    /// One request with upstream's retry policy; `body` is JSON for POST/PATCH.
    fn send(&self, method: &str, path_or_url: &str, body: Option<&Value>, accept: &str, query: &[(&str, String)]) -> Result<Resp, GraphError> {
        let url = self.url(path_or_url);
        let mut last: Option<GraphError> = None;
        for attempt in 0..=self.max_retries {
            let force = last.as_ref().and_then(|e| e.status) == Some(401);
            let token = self.tokens.access_token(force)?;
            let headers: Vec<(&str, String)> = vec![("Authorization", format!("Bearer {token}")), ("Accept", accept.to_string()), ("User-Agent", USER_AGENT.to_string())];
            let r = match method {
                "GET" => get(&url, query, &headers, self.timeout),
                "POST" => post_json(&url, &headers, body.unwrap_or(&Value::Null), self.timeout),
                "PATCH" => patch_json(&url, &headers, body.unwrap_or(&Value::Null), self.timeout),
                "DELETE" => delete(&url, &headers, self.timeout),
                other => Err(format!("unsupported method {other}")),
            };
            match r {
                Ok(resp) if resp.status < 400 => return Ok(resp),
                Ok(resp) => {
                    let status = resp.status;
                    let err = self.api_error(method, &url, &resp);
                    if status == 401 {
                        self.tokens.clear_cache();
                    }
                    let retryable = status == 401 || status == 429 || (500..600).contains(&status);
                    last = Some(err);
                    if !retryable || attempt >= self.max_retries {
                        return Err(last.unwrap());
                    }
                }
                Err(e) => {
                    last = Some(GraphError::new(None, format!("Microsoft Graph request failed for {method} {url}: {e}")));
                    if attempt >= self.max_retries {
                        return Err(last.unwrap());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis((500u64 << attempt.min(4)).min(8000)));
        }
        Err(last.unwrap_or_else(|| GraphError::new(None, format!("Microsoft Graph request exhausted retries for {method} {url}."))))
    }

    fn json_body(r: &Resp) -> Result<Value, GraphError> {
        r.json().map_err(|_| GraphError::new(Some(r.status), format!("Microsoft Graph response was not valid JSON (HTTP {})", r.status)))
    }

    pub fn get_json(&self, path_or_url: &str, params: &[(&str, String)]) -> Result<Value, GraphError> {
        Self::json_body(&self.send("GET", path_or_url, None, "application/json", params)?)
    }

    pub fn post_json(&self, path: &str, body: &Value) -> Result<Value, GraphError> {
        Self::json_body(&self.send("POST", path, Some(body), "application/json", &[])?)
    }

    /// Decoded body, or `{}` for a 204 / bodiless response.
    pub fn patch_json(&self, path: &str, body: &Value) -> Result<Value, GraphError> {
        let r = self.send("PATCH", path, Some(body), "application/json", &[])?;
        if r.status == 204 || r.body.trim().is_empty() {
            return Ok(json!({}));
        }
        Self::json_body(&r)
    }

    /// Decoded body, or `{"deleted": true, "status_code": N}` for a bodiless response.
    pub fn delete(&self, path: &str) -> Result<Value, GraphError> {
        let r = self.send("DELETE", path, None, "application/json", &[])?;
        if r.status == 204 || r.body.trim().is_empty() {
            return Ok(json!({"deleted": true, "status_code": r.status}));
        }
        Self::json_body(&r)
    }

    /// Follow `@odata.nextLink` and concatenate every page's `value` list.
    pub fn collect_paginated(&self, path: &str, params: &[(&str, String)]) -> Result<Vec<Value>, GraphError> {
        let mut items = Vec::new();
        let mut next = self.url(path);
        let mut first = true;
        while !next.is_empty() {
            let q: &[(&str, String)] = if first { params } else { &[] };
            let v = self.get_json(&next, q)?;
            let Some(obj) = v.as_object() else {
                return Err(GraphError::config("Expected paginated Graph response dict."));
            };
            if let Some(list) = obj.get("value").and_then(Value::as_array) {
                items.extend(list.iter().cloned());
            }
            next = obj.get("@odata.nextLink").and_then(Value::as_str).unwrap_or("").to_string();
            first = false;
        }
        Ok(items)
    }

    /// Stream a resource to `dest` (via `dest.part`, renamed only on success); returns the
    /// number of bytes written.
    pub fn download_to_file(&self, path_or_url: &str, dest: &Path) -> Result<u64, GraphError> {
        let url = self.url(path_or_url);
        let mut last: Option<GraphError> = None;
        if let Some(d) = dest.parent() {
            std::fs::create_dir_all(d).map_err(|e| GraphError::config(format!("cannot create {}: {e}", d.display())))?;
        }
        let part = dest.with_file_name(format!("{}.part", dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
        for attempt in 0..=self.max_retries {
            let token = self.tokens.access_token(last.as_ref().and_then(|e| e.status) == Some(401))?;
            let agent: ureq::Agent = ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(self.timeout))).build().into();
            let r = agent.get(&url).header("Authorization", format!("Bearer {token}")).header("Accept", "*/*").header("User-Agent", USER_AGENT).call();
            match r {
                Ok(mut resp) if resp.status().as_u16() < 400 => {
                    let mut f = std::fs::File::create(&part).map_err(|e| GraphError::config(format!("cannot write {}: {e}", part.display())))?;
                    let n = std::io::copy(&mut resp.body_mut().with_config().limit(u64::MAX).reader(), &mut f).map_err(|e| GraphError::config(format!("download failed: {e}")))?;
                    drop(f);
                    std::fs::rename(&part, dest).map_err(|e| GraphError::config(format!("cannot move {} into place: {e}", dest.display())))?;
                    return Ok(n);
                }
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let mut body = String::new();
                    let _ = resp.body_mut().with_config().limit(4096).reader().read_to_string(&mut body);
                    let detail = serde_json::from_str::<Value>(&body).ok().and_then(|v| format_graph_error(v.get("error")));
                    let message = detail.unwrap_or_else(|| if body.trim().is_empty() { "unknown error".into() } else { body.trim().to_string() });
                    last = Some(GraphError::new(Some(status), format!("Microsoft Graph API error {status} for GET {url}: {message}")));
                    if status == 401 {
                        self.tokens.clear_cache();
                    }
                    if !(status == 401 || status == 429 || (500..600).contains(&status)) || attempt >= self.max_retries {
                        return Err(last.unwrap());
                    }
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&part);
                    last = Some(GraphError::new(None, format!("Microsoft Graph download failed for GET {url}: {e}")));
                    if attempt >= self.max_retries {
                        return Err(last.unwrap());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis((500u64 << attempt.min(4)).min(8000)));
        }
        Err(last.unwrap_or_else(|| GraphError::config(format!("Microsoft Graph download exhausted retries for GET {url}."))))
    }
}

/// One JSON HTTP call with an explicit method, for sinks that are not Graph
/// (`ark_tools::web::http` only exposes GET / POST / form).
pub(crate) fn http_json(method: &str, url: &str, headers: &[(&str, String)], body: Option<&Value>, timeout: u64) -> Result<Resp, String> {
    let agent = ureq_agent(timeout);
    let payload = serde_json::to_vec(body.unwrap_or(&Value::Null)).unwrap_or_default();
    fn with_headers(mut req: ureq::RequestBuilder<ureq::typestate::WithoutBody>, headers: &[(&str, String)]) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
        for (k, v) in headers {
            req = req.header(*k, v.clone());
        }
        req
    }
    fn with_body_headers(mut req: ureq::RequestBuilder<ureq::typestate::WithBody>, headers: &[(&str, String)]) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
        req = req.header("Content-Type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, v.clone());
        }
        req
    }
    match method {
        "GET" => finish(with_headers(agent.get(url), headers).call()),
        "DELETE" => finish(with_headers(agent.delete(url), headers).call()),
        "POST" => finish(with_body_headers(agent.post(url), headers).send(payload.as_slice())),
        "PATCH" => finish(with_body_headers(agent.patch(url), headers).send(payload.as_slice())),
        "PUT" => finish(with_body_headers(agent.put(url), headers).send(payload.as_slice())),
        other => Err(format!("unsupported method {other}")),
    }
}

fn ureq_agent(timeout: u64) -> ureq::Agent {
    ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(timeout.max(1)))).build().into()
}

fn finish(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Resp, String> {
    let mut resp = r.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().read_to_end(&mut raw).map_err(|e| format!("reading response failed: {e}"))?;
    Ok(Resp { status, body: String::from_utf8_lossy(&raw).into_owned(), content_type })
}

/// PATCH through ureq (`ark_tools::web::http` only exposes GET/POST/form).
fn patch_json(url: &str, headers: &[(&str, String)], body: &Value, timeout: u64) -> Result<Resp, String> {
    let mut req = ureq_agent(timeout).patch(url).header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v.clone());
    }
    finish(req.send(serde_json::to_vec(body).unwrap_or_default().as_slice()))
}

fn delete(url: &str, headers: &[(&str, String)], timeout: u64) -> Result<Resp, String> {
    let mut req = ureq_agent(timeout).delete(url);
    for (k, v) in headers {
        req = req.header(*k, v.clone());
    }
    finish(req.call())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_secret(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn missing_credentials_report_upstream_message() {
        let err = Credentials::from_parts(None, None, None, None, None).unwrap_err();
        assert_eq!(err.message, "Missing Microsoft Graph configuration: MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET");
        assert_eq!(err.status, None);
        let err = Credentials::from_parts(Some("t".into()), None, Some("s".into()), None, None).unwrap_err();
        assert_eq!(err.message, "Missing Microsoft Graph configuration: MSGRAPH_CLIENT_ID");
        // The config path uses the same message when nothing is configured and no env is set.
        if std::env::var("MSGRAPH_TENANT_ID").is_err() && std::env::var("MSGRAPH_CLIENT_ID").is_err() && std::env::var("MSGRAPH_CLIENT_SECRET").is_err() {
            let err = Credentials::from_config(&toml::Table::new(), &no_secret).unwrap_err();
            assert_eq!(err.message, "Missing Microsoft Graph configuration: MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET");
        }
    }

    #[test]
    fn credentials_resolve_secret_placeholders_and_token_url() {
        let t: toml::Table = "tenant_id = \"contoso\"\nclient_id = \"app\"\nclient_secret = \"{{secret:GRAPH_SECRET}}\"\nbase_url = \"http://127.0.0.1:9/v1.0/\"\n"
            .parse()
            .unwrap();
        let secret = |name: &str| (name == "GRAPH_SECRET").then(|| "s3cret".to_string());
        let c = Credentials::from_config(&t, &secret).unwrap();
        assert_eq!((c.tenant_id.as_str(), c.client_id.as_str(), c.client_secret.as_str()), ("contoso", "app", "s3cret"));
        assert_eq!(c.token_url(), "https://login.microsoftonline.com/contoso/oauth2/v2.0/token");
        assert_eq!(Credentials::base_url(&t, &secret), "http://127.0.0.1:9/v1.0");
        // An unresolved placeholder counts as missing, like a blank key.
        let unresolved = |_: &str| None;
        let err = Credentials::from_config(&t, &unresolved).unwrap_err();
        assert!(err.message.contains("MSGRAPH_CLIENT_SECRET"), "{}", err.message);
    }

    #[test]
    fn graph_error_formatting() {
        assert_eq!(format_graph_error(Some(&json!({"code": "Forbidden", "message": "no"}))).as_deref(), Some("Forbidden: no"));
        assert_eq!(format_graph_error(Some(&json!("plain"))).as_deref(), Some("plain"));
        assert_eq!(format_graph_error(Some(&json!({"message": "m"}))).as_deref(), Some("m"));
        assert_eq!(format_graph_error(Some(&json!({}))), None);
        assert_eq!(format_graph_error(None), None);
    }
}
