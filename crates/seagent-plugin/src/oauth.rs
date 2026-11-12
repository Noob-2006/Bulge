//! OAuth 2.1 for remote MCP servers, per the MCP authorization spec
//! (2025-06-18 / 2025-11-25):
//! - discovery: `WWW-Authenticate: Bearer resource_metadata=…` → protected
//!   resource metadata (RFC 9728) → authorization server metadata (RFC 8414,
//!   with OpenID Connect discovery as fallback); servers without metadata fall
//!   back to `/authorize`, `/token`, `/register` on the server origin (2025-03-26).
//! - client: pre-configured id/secret, a Client ID Metadata Document URL, or
//!   dynamic client registration (RFC 7591).
//! - grants: authorization code + PKCE S256 with a loopback redirect, device
//!   authorization (RFC 8628) for headless hosts, refresh tokens.
//! - every token request carries `resource` (RFC 8707) bound to the MCP URL.
//! - issuer binding: the metadata's `issuer` must be the URL it was discovered
//!   from (RFC 8414 §3.3), the redirect's `iss` must name it (RFC 9207; required
//!   when the server advertises `authorization_response_iss_parameter_supported`),
//!   and tokens remember their issuer so a later config change cannot reuse them.
//!
//! Tokens live in `<data>/mcp-oauth/<server>.json`, mode 0600.

use seagent_net::{crypto, form_encode, httpd, parse_query, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `[mcp.<name>.oauth]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// URL of a Client ID Metadata Document used as client_id (2025-11-25 spec).
    #[serde(default)]
    pub client_metadata_url: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Fixed loopback port for the redirect (some servers require a registered exact URI).
    #[serde(default)]
    pub redirect_port: Option<u16>,
    /// Override discovery.
    #[serde(default)]
    pub authorization_server: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds; 0 = unknown.
    #[serde(default)]
    pub expires_at: u64,
    #[serde(default)]
    pub scope: Option<String>,
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub resource: String,
    /// Authorization server that issued these tokens (empty for pre-binding files).
    #[serde(default)]
    pub issuer: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerMeta {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub cimd_supported: bool,
    /// RFC 9207 `authorization_response_iss_parameter_supported`.
    pub iss_param_supported: bool,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn agent() -> ureq::Agent {
    seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into()
}

fn read_json(resp: ureq::http::Response<ureq::Body>) -> Result<(u16, Value), String> {
    let status = resp.status().as_u16();
    let mut raw = String::new();
    resp.into_body().into_reader().take(1 << 20).read_to_string(&mut raw).map_err(|e| format!("reading response: {e}"))?;
    let v = serde_json::from_str(&raw).unwrap_or_else(|_| Value::String(raw.chars().take(300).collect()));
    Ok((status, v))
}

fn get_json(url: &str) -> Result<Option<Value>, String> {
    let resp = agent().get(url).header("accept", "application/json").header("mcp-protocol-version", crate::mcp::PROTOCOL).call().map_err(|e| format!("GET {url}: {e}"))?;
    let (status, v) = read_json(resp)?;
    Ok(((200..300).contains(&status) && v.is_object()).then_some(v))
}

/// The canonical resource URI for RFC 8707: scheme + host + path, no fragment/query.
pub fn canonical_resource(mcp_url: &str) -> String {
    let base = mcp_url.split(['#', '?']).next().unwrap_or(mcp_url);
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, String::new()));
    let path = if path == "/" { String::new() } else { path };
    format!("{}://{}{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase(), path)
}

fn origin(u: &str) -> Result<String, String> {
    let p = Url::parse(u)?;
    Ok(format!("{}://{}", p.scheme, p.host_header()))
}

/// `resource_metadata="…"` from a WWW-Authenticate header.
pub fn resource_metadata_from_challenge(h: &str) -> Option<String> {
    let i = h.find("resource_metadata=")?;
    let v = h[i + "resource_metadata=".len()..].trim_start();
    if let Some(q) = v.strip_prefix('"') {
        q.split('"').next().map(str::to_string)
    } else {
        v.split([',', ' ']).next().map(str::to_string)
    }
}

/// `scope="…"` from a WWW-Authenticate header (step-up / insufficient_scope).
pub fn scope_from_challenge(h: &str) -> Option<String> {
    let i = h.find("scope=")?;
    h[i + 6..].strip_prefix('"')?.split('"').next().map(str::to_string)
}

fn path_of(u: &str) -> String {
    Url::parse(u).map(|p| p.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string()).unwrap_or_default()
}

/// Send an unauthenticated initialize to learn the server's `WWW-Authenticate` challenge.
pub fn probe_challenge(mcp_url: &str) -> Option<String> {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": crate::mcp::PROTOCOL, "capabilities": {}, "clientInfo": {"name": "seagent", "version": env!("CARGO_PKG_VERSION")}}});
    let r = agent().post(mcp_url).header("content-type", "application/json").header("accept", "application/json, text/event-stream").send(body.to_string().as_bytes()).ok()?;
    if r.status().as_u16() != 401 {
        return None;
    }
    r.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// RFC 9728 discovery. `challenge` = the WWW-Authenticate header of a 401, if any.
pub fn discover(mcp_url: &str, challenge: Option<&str>, cfg: &OAuthConfig) -> Result<(ServerMeta, Vec<String>), String> {
    let mut scopes = Vec::new();
    let as_url = if let Some(a) = &cfg.authorization_server {
        a.clone()
    } else {
        let o = origin(mcp_url)?;
        let p = path_of(mcp_url);
        let mut candidates = Vec::new();
        if let Some(u) = challenge.and_then(resource_metadata_from_challenge) {
            candidates.push(u);
        }
        if !p.is_empty() {
            candidates.push(format!("{o}/.well-known/oauth-protected-resource{p}"));
        }
        candidates.push(format!("{o}/.well-known/oauth-protected-resource"));
        let mut found = None;
        for c in candidates {
            if let Some(v) = get_json(&c)? {
                found = Some(v);
                break;
            }
        }
        match found {
            Some(prm) => {
                scopes = prm.get("scopes_supported").and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default();
                prm.get("authorization_servers")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or("protected resource metadata lists no authorization_servers")?
            }
            // 2025-03-26 servers: the MCP origin is the authorization server.
            None => o,
        }
    };
    let meta = as_metadata(&as_url)?;
    if let Some(s) = challenge.and_then(scope_from_challenge) {
        scopes = s.split_whitespace().map(str::to_string).collect();
    }
    Ok((meta, scopes))
}

/// RFC 8414 then OIDC discovery, with path-insertion and path-appending variants.
pub fn as_metadata(issuer: &str) -> Result<ServerMeta, String> {
    let o = origin(issuer)?;
    let p = path_of(issuer);
    let mut urls = vec![];
    if p.is_empty() {
        urls.push(format!("{o}/.well-known/oauth-authorization-server"));
        urls.push(format!("{o}/.well-known/openid-configuration"));
    } else {
        urls.push(format!("{o}/.well-known/oauth-authorization-server{p}"));
        urls.push(format!("{o}/.well-known/openid-configuration{p}"));
        urls.push(format!("{o}{p}/.well-known/openid-configuration"));
    }
    for u in urls {
        if let Some(v) = get_json(&u)? {
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let (Some(auth), Some(token)) = (s("authorization_endpoint"), s("token_endpoint")) else { continue };
            // RFC 8414 §3.3: metadata for another issuer is an attack (mix-up), not a fallback.
            if let Some(i) = s("issuer").filter(|i| i.trim_end_matches('/') != issuer.trim_end_matches('/')) {
                return Err(format!("authorization server metadata at {u} names issuer `{i}`, expected `{issuer}`; refusing (RFC 8414 issuer mismatch)"));
            }
            let methods: Vec<&str> = v.get("code_challenge_methods_supported").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            // MCP requires PKCE; refuse servers that explicitly advertise methods without S256.
            if !methods.is_empty() && !methods.contains(&"S256") {
                return Err(format!("authorization server {issuer} does not support PKCE S256"));
            }
            return Ok(ServerMeta {
                issuer: s("issuer").unwrap_or_else(|| issuer.to_string()),
                authorization_endpoint: auth,
                token_endpoint: token,
                registration_endpoint: s("registration_endpoint"),
                device_authorization_endpoint: s("device_authorization_endpoint"),
                scopes_supported: v.get("scopes_supported").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
                cimd_supported: v.get("client_id_metadata_document_supported").and_then(Value::as_bool).unwrap_or(false),
                iss_param_supported: v.get("authorization_response_iss_parameter_supported").and_then(Value::as_bool).unwrap_or(false),
            });
        }
    }
    // No metadata: legacy default endpoints on the origin.
    Ok(ServerMeta { issuer: o.clone(), authorization_endpoint: format!("{o}/authorize"), token_endpoint: format!("{o}/token"), registration_endpoint: Some(format!("{o}/register")), ..Default::default() })
}

/// Pick or register a client. Returns (client_id, client_secret).
pub fn client_for(meta: &ServerMeta, cfg: &OAuthConfig, redirect_uri: &str) -> Result<(String, Option<String>), String> {
    if let Some(id) = &cfg.client_id {
        return Ok((id.clone(), cfg.client_secret.clone()));
    }
    if let (Some(u), true) = (&cfg.client_metadata_url, meta.cimd_supported) {
        return Ok((u.clone(), None));
    }
    let reg = meta.registration_endpoint.as_deref().ok_or("server supports no dynamic client registration; set oauth.client_id in config")?;
    let body = serde_json::json!({
        "client_name": "seagent",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "software_id": "seagent",
        "software_version": env!("CARGO_PKG_VERSION"),
    });
    let resp = agent().post(reg).header("content-type", "application/json").send(body.to_string().as_bytes()).map_err(|e| format!("client registration: {e}"))?;
    let (status, v) = read_json(resp)?;
    if !(200..300).contains(&status) {
        return Err(format!("client registration failed (HTTP {status}): {v}"));
    }
    let id = v.get("client_id").and_then(Value::as_str).ok_or("registration response has no client_id")?.to_string();
    Ok((id, v.get("client_secret").and_then(Value::as_str).map(str::to_string)))
}

fn token_request(endpoint: &str, client_id: &str, secret: Option<&str>, params: &[(&str, &str)]) -> Result<Value, String> {
    let mut p: Vec<(&str, &str)> = params.to_vec();
    let mut req = agent().post(endpoint).header("content-type", "application/x-www-form-urlencoded").header("accept", "application/json");
    match secret {
        Some(s) => {
            let basic = crypto::b64(format!("{}:{}", seagent_net::urlencode(client_id), seagent_net::urlencode(s)).as_bytes());
            req = req.header("authorization", &format!("Basic {basic}"));
        }
        None => p.push(("client_id", client_id)),
    }
    let resp = req.send(form_encode(&p).as_bytes()).map_err(|e| format!("token request: {e}"))?;
    let (status, v) = read_json(resp)?;
    if !(200..300).contains(&status) || v.get("access_token").is_none() {
        let err = v.get("error").and_then(Value::as_str).unwrap_or("");
        return Err(format!("token endpoint HTTP {status} {err}: {}", v.get("error_description").and_then(Value::as_str).unwrap_or("")).trim().to_string()).map_err(|e| if err.is_empty() { e } else { format!("{err}|{e}") });
    }
    Ok(v)
}

fn tokens_from(v: &Value, meta_token: &str, client_id: &str, secret: Option<String>, resource: &str, old_refresh: Option<String>, issuer: &str) -> Tokens {
    Tokens {
        access_token: v["access_token"].as_str().unwrap_or("").to_string(),
        refresh_token: v.get("refresh_token").and_then(Value::as_str).map(str::to_string).or(old_refresh),
        expires_at: v.get("expires_in").and_then(Value::as_u64).map(|s| now() + s).unwrap_or(0),
        scope: v.get("scope").and_then(Value::as_str).map(str::to_string),
        token_endpoint: meta_token.to_string(),
        client_id: client_id.to_string(),
        client_secret: secret,
        resource: resource.to_string(),
        issuer: issuer.to_string(),
    }
}

/// RFC 9207: the redirect's `iss` must be the issuer we sent the user to.
pub fn check_iss(meta: &ServerMeta, iss: Option<&str>) -> Result<(), String> {
    match iss {
        Some(i) if i.trim_end_matches('/') == meta.issuer.trim_end_matches('/') => Ok(()),
        Some(i) => Err(format!("authorization response came from issuer `{i}`, expected `{}`; refusing (RFC 9207 mix-up protection)", meta.issuer)),
        None if meta.iss_param_supported => Err(format!("authorization server `{}` promises an `iss` parameter but the redirect had none; refusing (RFC 9207)", meta.issuer)),
        None => Ok(()),
    }
}

/// How the user completes the browser step.
pub trait Prompter: Send + Sync {
    /// Show the authorization URL (and try to open a browser).
    fn open(&self, url: &str);
    /// Device flow: show the code and where to enter it.
    fn device(&self, verification_uri: &str, user_code: &str, complete_uri: Option<&str>);
}

/// Authorization code + PKCE with a loopback redirect listener.
pub fn login_browser(mcp_url: &str, challenge: Option<&str>, cfg: &OAuthConfig, prompt: &dyn Prompter, wait: Duration) -> Result<Tokens, String> {
    match login_browser_once(mcp_url, challenge, cfg, prompt, wait) {
        // A server that advertises CIMD but rejects our metadata document: fall back to DCR.
        Err(e) if e.contains("invalid_client") && cfg.client_metadata_url.is_some() && cfg.client_id.is_none() => {
            let dcr = OAuthConfig { client_metadata_url: None, ..cfg.clone() };
            login_browser_once(mcp_url, challenge, &dcr, prompt, wait)
        }
        r => r,
    }
}

fn login_browser_once(mcp_url: &str, challenge: Option<&str>, cfg: &OAuthConfig, prompt: &dyn Prompter, wait: Duration) -> Result<Tokens, String> {
    let (meta, discovered_scopes) = discover(mcp_url, challenge, cfg)?;
    let resource = canonical_resource(mcp_url);
    let (code_tx, code_rx) = mpsc::channel::<Vec<(String, String)>>();
    let code_tx = Arc::new(Mutex::new(Some(code_tx)));
    let handler: httpd::Handler = Arc::new(move |r: httpd::Request| {
        if r.path != "/callback" {
            return httpd::Response::text(404, "not found");
        }
        if let Some(tx) = code_tx.lock().unwrap().take() {
            let _ = tx.send(r.query.clone());
        }
        let ok = r.query("code").is_some();
        httpd::Response::html(&callback_page(ok))
    });
    let bind = format!("127.0.0.1:{}", cfg.redirect_port.unwrap_or(0));
    let srv = httpd::Server::bind(&bind, httpd::Opts::default(), handler).map_err(|e| format!("cannot listen on {bind} for the OAuth redirect: {e}"))?;
    let redirect = format!("http://127.0.0.1:{}/callback", srv.local_addr().port());
    let (client_id, secret) = client_for(&meta, cfg, &redirect)?;
    let (verifier, challenge_s) = crypto::pkce_pair();
    let state = crypto::random_token(24);
    let scopes = if cfg.scopes.is_empty() { discovered_scopes } else { cfg.scopes.clone() };
    let scope = scopes.join(" ");
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("code_challenge", challenge_s.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state.as_str()),
        ("resource", resource.as_str()),
    ];
    if !scope.is_empty() {
        q.push(("scope", scope.as_str()));
    }
    let sep = if meta.authorization_endpoint.contains('?') { '&' } else { '?' };
    let auth_url = format!("{}{sep}{}", meta.authorization_endpoint, form_encode(&q));
    prompt.open(&auth_url);
    let params = code_rx.recv_timeout(wait).map_err(|_| "timed out waiting for the browser redirect".to_string())?;
    drop(srv);
    let get = |k: &str| params.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    if let Some(e) = get("error") {
        return Err(format!("authorization denied: {e} {}", get("error_description").unwrap_or_default()));
    }
    if get("state").as_deref() != Some(state.as_str()) {
        return Err("OAuth state mismatch; possible CSRF, aborting".into());
    }
    check_iss(&meta, get("iss").as_deref())?;
    let code = get("code").ok_or("redirect carried no code")?;
    let v = token_request(&meta.token_endpoint, &client_id, secret.as_deref(), &[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", &redirect), ("code_verifier", &verifier), ("resource", &resource)])?;
    Ok(tokens_from(&v, &meta.token_endpoint, &client_id, secret, &resource, None, &meta.issuer))
}

/// Complete a login from a redirect URL the user pasted (no loopback possible).
pub fn parse_redirect(url: &str) -> Vec<(String, String)> {
    url.split_once('?').map(|(_, q)| parse_query(q.split('#').next().unwrap_or(q))).unwrap_or_default()
}

/// RFC 8628 device authorization grant.
pub fn login_device(mcp_url: &str, challenge: Option<&str>, cfg: &OAuthConfig, prompt: &dyn Prompter, wait: Duration) -> Result<Tokens, String> {
    let (meta, discovered_scopes) = discover(mcp_url, challenge, cfg)?;
    let dev = meta.device_authorization_endpoint.clone().ok_or("authorization server has no device_authorization_endpoint; use browser login")?;
    let resource = canonical_resource(mcp_url);
    let (client_id, secret) = client_for(&meta, cfg, "http://127.0.0.1/callback")?;
    let scope = if cfg.scopes.is_empty() { discovered_scopes } else { cfg.scopes.clone() }.join(" ");
    let mut p = vec![("client_id", client_id.as_str()), ("resource", resource.as_str())];
    if !scope.is_empty() {
        p.push(("scope", scope.as_str()));
    }
    let resp = agent().post(&dev).header("content-type", "application/x-www-form-urlencoded").send(form_encode(&p).as_bytes()).map_err(|e| format!("device authorization: {e}"))?;
    let (status, v) = read_json(resp)?;
    if !(200..300).contains(&status) {
        return Err(format!("device authorization failed (HTTP {status}): {v}"));
    }
    let device_code = v["device_code"].as_str().ok_or("no device_code")?.to_string();
    prompt.device(v["verification_uri"].as_str().unwrap_or(""), v["user_code"].as_str().unwrap_or(""), v.get("verification_uri_complete").and_then(Value::as_str));
    let mut interval = v.get("interval").and_then(Value::as_u64).unwrap_or(5).max(1);
    let deadline = std::time::Instant::now() + wait.min(Duration::from_secs(v.get("expires_in").and_then(Value::as_u64).unwrap_or(900)));
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        if std::time::Instant::now() > deadline {
            return Err("device code expired before the user finished".into());
        }
        match token_request(&meta.token_endpoint, &client_id, secret.as_deref(), &[("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", &device_code), ("resource", &resource)]) {
            Ok(v) => return Ok(tokens_from(&v, &meta.token_endpoint, &client_id, secret, &resource, None, &meta.issuer)),
            Err(e) if e.starts_with("authorization_pending|") => {}
            Err(e) if e.starts_with("slow_down|") => interval += 5,
            Err(e) => return Err(e),
        }
    }
}

pub fn refresh(t: &Tokens) -> Result<Tokens, String> {
    let rt = t.refresh_token.as_deref().ok_or("no refresh token; run `seagent mcp login` again")?;
    let v = token_request(&t.token_endpoint, &t.client_id, t.client_secret.as_deref(), &[("grant_type", "refresh_token"), ("refresh_token", rt), ("resource", &t.resource)])?;
    Ok(tokens_from(&v, &t.token_endpoint, &t.client_id, t.client_secret.clone(), &t.resource, t.refresh_token.clone(), &t.issuer))
}

/// Token file store with refresh-before-expiry; shared by every connection to one server.
pub struct Store {
    path: PathBuf,
    cur: Mutex<Option<Tokens>>,
}

impl Store {
    pub fn new(dir: &Path, server: &str) -> Store {
        let path = dir.join("mcp-oauth").join(format!("{server}.json"));
        let cur = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok());
        Store { path, cur: Mutex::new(cur) }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn has_tokens(&self) -> bool {
        self.cur.lock().unwrap().is_some()
    }
    /// Issuer the stored tokens are bound to (empty: unknown, older token file).
    pub fn issuer(&self) -> Option<String> {
        self.cur.lock().unwrap().as_ref().map(|t| t.issuer.clone())
    }
    /// Tokens from another authorization server than the configured one are refused.
    pub fn check_issuer(&self, expected: &str) -> Result<(), String> {
        match self.issuer().filter(|i| !i.is_empty()) {
            Some(i) if i.trim_end_matches('/') != expected.trim_end_matches('/') => Err(format!("stored tokens were issued by `{i}` but the configured authorization server is `{expected}`; run `seagent mcp login` again")),
            _ => Ok(()),
        }
    }
    pub fn save(&self, t: Tokens) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(&t).map_err(|e| e.to_string())?;
        write_private(&self.path, &data).map_err(|e| format!("saving {}: {e}", self.path.display()))?;
        *self.cur.lock().unwrap() = Some(t);
        Ok(())
    }
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
        *self.cur.lock().unwrap() = None;
    }
    /// A usable access token, refreshing when it expires within a minute.
    pub fn bearer(&self) -> Option<String> {
        let t = self.cur.lock().unwrap().clone()?;
        if t.expires_at != 0 && t.expires_at <= now() + 60 && t.refresh_token.is_some() {
            return self.force_refresh();
        }
        Some(t.access_token)
    }
    /// After a 401: refresh once. Refresh tokens are often single-use, so concurrent
    /// processes (CLI + daemon) serialise on a lock file and reuse a refresh that
    /// another process completed while we waited.
    pub fn force_refresh(&self) -> Option<String> {
        let before = self.cur.lock().unwrap().clone()?;
        let _lock = FileLock::acquire(&self.path.with_extension("refresh.lock"));
        if let Some(disk) = std::fs::read_to_string(&self.path).ok().and_then(|s| serde_json::from_str::<Tokens>(&s).ok()) {
            if disk.access_token != before.access_token {
                let a = disk.access_token.clone();
                *self.cur.lock().unwrap() = Some(disk);
                return Some(a);
            }
        }
        match refresh(&before) {
            Ok(n) => {
                let a = n.access_token.clone();
                let _ = self.save(n);
                Some(a)
            }
            Err(_) => None,
        }
    }
}

/// Exclusive lock held until drop (best effort: no lock if the file cannot be opened).
/// `std::fs::File::lock`: `flock` on unix, `LockFileEx` on Windows.
struct FileLock(Option<std::fs::File>);

impl FileLock {
    fn acquire(path: &Path) -> FileLock {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let f = o.open(path).ok();
        if let Some(f) = &f {
            let _ = f.lock();
        }
        FileLock(f)
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if let Some(f) = &self.0 {
            let _ = f.unlock();
        }
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = create_private(&tmp)?;
        std::io::Write::write_all(&mut f, data)?;
    }
    std::fs::rename(&tmp, path)
}

/// Create/truncate `path` for writing, owner-only from the first byte: mode 0600 on unix,
/// an owner-only DACL on Windows (`seagent_core::platform::fs_private`).
pub(crate) fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
    }
    #[cfg(not(unix))]
    {
        seagent_core::platform::fs_private::open_private(path, seagent_core::platform::fs_private::OpenMode::Truncate)
    }
}

fn callback_page(ok: bool) -> String {
    let (title, msg) = if ok { ("授權完成", "已取得授權，可以關閉此分頁回到 seagent。") } else { ("授權失敗", "沒有取得授權碼，請回到 seagent 查看錯誤。") };
    format!(
        r##"<!doctype html><meta charset="utf-8"><title>seagent · {title}</title>
<style>body{{margin:0;height:100vh;display:grid;place-items:center;background:radial-gradient(120% 90% at 15% 0%,#1c2c4a,#0a1020 42%,#04060d);color:#eaeef7;font:16px system-ui,"Noto Sans TC",sans-serif}}
.c{{padding:32px 40px;border:1px solid rgba(217,180,74,.4);border-radius:16px;background:rgba(10,16,32,.78);text-align:center}}
svg{{width:56px;height:56px;filter:drop-shadow(0 0 10px rgba(217,180,74,.6));animation:t 3s ease-in-out infinite}}@keyframes t{{50%{{transform:rotate(45deg) scale(1.1)}}}}@media(prefers-reduced-motion:reduce){{svg{{animation:none}}}}h1{{color:#ecd28c;font-size:22px}}</style>
<div class="c"><svg viewBox="-100 -100 200 200"><path d="M0-100C8-30 30-8 100 0C30 8 8 30 0 100C-8 30-30 8-100 0C-30-8-8-30 0-100Z" fill="#d9b44a"/></svg><h1>{title}</h1><p>{msg}</p></div>"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn challenge_and_resource_parsing() {
        let h = r#"Bearer error="invalid_token", resource_metadata="https://mcp.x.com/.well-known/oauth-protected-resource/mcp", scope="files:read files:write""#;
        assert_eq!(resource_metadata_from_challenge(h).as_deref(), Some("https://mcp.x.com/.well-known/oauth-protected-resource/mcp"));
        assert_eq!(scope_from_challenge(h).as_deref(), Some("files:read files:write"));
        assert_eq!(resource_metadata_from_challenge("Bearer resource_metadata=https://a/b, x=y").as_deref(), Some("https://a/b"));
        assert_eq!(canonical_resource("HTTPS://MCP.Example.com/mcp?x=1#f"), "https://mcp.example.com/mcp");
        assert_eq!(canonical_resource("https://mcp.example.com/"), "https://mcp.example.com");
        let q = parse_redirect("http://127.0.0.1:5/callback?code=abc&state=s%20t#frag");
        assert_eq!(q, vec![("code".into(), "abc".into()), ("state".into(), "s t".into())]);
    }

    /// A fake MCP authorization stack: PRM + AS metadata + DCR + token endpoint.
    struct Fake {
        srv: httpd::Server,
        token_calls: Arc<AtomicUsize>,
    }

    fn fake(with_prm: bool, device: bool) -> Fake {
        let calls = Arc::new(AtomicUsize::new(0));
        let addr = Arc::new(Mutex::new(String::new()));
        let (c, a) = (calls.clone(), addr.clone());
        let polls = Arc::new(AtomicUsize::new(0));
        let h: httpd::Handler = Arc::new(move |r: httpd::Request| {
            let base = a.lock().unwrap().clone();
            let form = parse_query(r.body_str());
            let f = |k: &str| form.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
            match r.path.as_str() {
                "/.well-known/oauth-protected-resource/mcp" if with_prm => httpd::Response::json(200, &serde_json::json!({"resource": format!("{base}/mcp"), "authorization_servers": [format!("{base}/as")], "scopes_supported": ["read"]}).to_string()),
                "/.well-known/oauth-authorization-server/as" => {
                    let mut m = serde_json::json!({"issuer": format!("{base}/as"), "authorization_endpoint": format!("{base}/as/authorize"), "token_endpoint": format!("{base}/as/token"), "registration_endpoint": format!("{base}/as/register"), "code_challenge_methods_supported": ["S256"]});
                    if device {
                        m["device_authorization_endpoint"] = format!("{base}/as/device").into();
                    }
                    httpd::Response::json(200, &m.to_string())
                }
                "/as/register" => {
                    let v: Value = serde_json::from_slice(&r.body).unwrap();
                    assert_eq!(v["token_endpoint_auth_method"], "none");
                    httpd::Response::json(201, &r#"{"client_id":"cid-1"}"#)
                }
                "/as/device" => httpd::Response::json(200, &r#"{"device_code":"dc","user_code":"ABCD-1234","verification_uri":"https://x/device","interval":1,"expires_in":60}"#),
                "/as/token" => {
                    c.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(f("resource"), format!("{base}/mcp"), "RFC 8707 resource on every token request");
                    match f("grant_type").as_str() {
                        "authorization_code" => {
                            assert_eq!(f("client_id"), "cid-1");
                            assert_eq!(crypto::b64url(&crypto::sha256(f("code_verifier").as_bytes())), f("code").trim_start_matches("code-for-"), "PKCE verifier matches challenge");
                            httpd::Response::json(200, &r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer"}"#)
                        }
                        "refresh_token" if f("refresh_token") == "rt-1" => httpd::Response::json(200, &r#"{"access_token":"at-2","expires_in":3600}"#),
                        "urn:ietf:params:oauth:grant-type:device_code" => {
                            if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                                httpd::Response::json(400, &r#"{"error":"authorization_pending"}"#)
                            } else {
                                httpd::Response::json(200, &r#"{"access_token":"at-dev"}"#)
                            }
                        }
                        _ => httpd::Response::json(400, &r#"{"error":"invalid_grant"}"#),
                    }
                }
                _ => httpd::Response::text(404, "no"),
            }
        });
        let srv = httpd::Server::bind("127.0.0.1:0", httpd::Opts::default(), h).unwrap();
        *addr.lock().unwrap() = format!("http://{}", srv.local_addr());
        Fake { srv, token_calls: calls }
    }

    /// Plays the browser: follows the auth URL straight to the redirect with code = challenge.
    struct Browser;
    impl Prompter for Browser {
        fn open(&self, url: &str) {
            let q = parse_redirect(url);
            let g = |k: &str| q.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap();
            assert_eq!(g("code_challenge_method"), "S256");
            // RFC 9207: the AS names itself on the redirect.
            let iss = url.split("/authorize").next().unwrap();
            let back = format!("{}?code=code-for-{}&state={}&iss={}", g("redirect_uri"), g("code_challenge"), seagent_net::urlencode(&g("state")), seagent_net::urlencode(iss));
            std::thread::spawn(move || {
                let _ = agent().get(&back).call();
            });
        }
        fn device(&self, _: &str, code: &str, _: Option<&str>) {
            assert_eq!(code, "ABCD-1234");
        }
    }

    #[test]
    fn browser_login_discovers_registers_exchanges_and_refreshes() {
        let f = fake(true, false);
        let mcp = format!("http://{}/mcp", f.srv.local_addr());
        let challenge = format!(r#"Bearer resource_metadata="http://{}/.well-known/oauth-protected-resource/mcp""#, f.srv.local_addr());
        let t = login_browser(&mcp, Some(&challenge), &OAuthConfig::default(), &Browser, Duration::from_secs(5)).unwrap();
        assert_eq!((t.access_token.as_str(), t.refresh_token.as_deref(), t.client_id.as_str()), ("at-1", Some("rt-1"), "cid-1"));
        assert_eq!(t.issuer, format!("http://{}/as", f.srv.local_addr()), "issuer bound to the tokens");
        let dir = seagent_core::tmp::scratch_path(format!("seagent-oauth-{}", std::process::id()));
        let store = Store::new(&dir, "srv");
        store.save(Tokens { expires_at: now() + 10, ..t }).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(store.bearer().as_deref(), Some("at-2"), "near-expiry token refreshed");
        assert_eq!(Store::new(&dir, "srv").bearer().as_deref(), Some("at-2"), "persisted; refresh token kept");
        assert_eq!(f.token_calls.load(Ordering::SeqCst), 2);
        // A second store (another process) whose cached token is stale reuses the
        // refresh the first one already did instead of spending the refresh token again.
        let other = Store::new(&dir, "srv");
        *other.cur.lock().unwrap() = Some(Tokens { access_token: "at-1".into(), ..Store::new(&dir, "srv").cur.lock().unwrap().clone().unwrap() });
        assert_eq!(other.force_refresh().as_deref(), Some("at-2"));
        assert_eq!(f.token_calls.load(Ordering::SeqCst), 2, "no extra token request");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn device_flow_polls_until_authorized_and_legacy_discovery_falls_back() {
        let f = fake(true, true);
        let mcp = format!("http://{}/mcp", f.srv.local_addr());
        let t = login_device(&mcp, None, &OAuthConfig::default(), &Browser, Duration::from_secs(10)).unwrap();
        assert_eq!(t.access_token, "at-dev");
        // No PRM at all: the origin is treated as the authorization server with default endpoints.
        let g = fake(false, false);
        let (m, _) = discover(&format!("http://{}/mcp", g.srv.local_addr()), None, &OAuthConfig::default()).unwrap();
        assert!(m.authorization_endpoint.ends_with("/authorize") && m.registration_endpoint.unwrap().ends_with("/register"));
        // Pre-configured client skips registration.
        let (id, sec) = client_for(&m_with_no_reg(), &OAuthConfig { client_id: Some("mine".into()), client_secret: Some("s".into()), ..Default::default() }, "x").unwrap();
        assert_eq!((id.as_str(), sec.as_deref()), ("mine", Some("s")));
        assert!(client_for(&m_with_no_reg(), &OAuthConfig::default(), "x").is_err());
    }

    #[test]
    fn issuer_binding_rfc9207_and_metadata_mismatch() {
        let m = ServerMeta { issuer: "https://as.example/t1".into(), ..Default::default() };
        assert!(check_iss(&m, Some("https://as.example/t1/")).is_ok());
        assert!(check_iss(&m, Some("https://evil.example")).unwrap_err().contains("RFC 9207"));
        assert!(check_iss(&m, None).is_ok(), "iss optional unless advertised");
        let strict = ServerMeta { iss_param_supported: true, ..m };
        assert!(check_iss(&strict, None).unwrap_err().contains("promises"));
        // Metadata naming a different issuer than the discovery URL is refused.
        let h: httpd::Handler = Arc::new(|r: httpd::Request| match r.path.as_str() {
            "/.well-known/oauth-authorization-server/as" => httpd::Response::json(200, &r#"{"issuer":"https://evil.example","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t"}"#),
            _ => httpd::Response::text(404, "no"),
        });
        let srv = httpd::Server::bind("127.0.0.1:0", httpd::Opts::default(), h).unwrap();
        let e = as_metadata(&format!("http://{}/as", srv.local_addr())).unwrap_err();
        assert!(e.contains("issuer mismatch"), "{e}");
        // Tokens remember their issuer; a different configured server is refused.
        let dir = seagent_core::tmp::scratch_path(format!("seagent-oauth-iss-{}", std::process::id()));
        let st = Store::new(&dir, "s");
        st.save(Tokens { access_token: "a".into(), issuer: "https://as.example/t1".into(), ..Default::default() }).unwrap();
        assert!(st.check_issuer("https://as.example/t1").is_ok());
        assert!(st.check_issuer("https://other.example").unwrap_err().contains("issued by"));
        std::fs::remove_dir_all(dir).ok();
    }

    fn m_with_no_reg() -> ServerMeta {
        ServerMeta { token_endpoint: "t".into(), authorization_endpoint: "a".into(), ..Default::default() }
    }
}
