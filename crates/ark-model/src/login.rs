//! Provider account logins (subscription / OAuth) and token refresh.
//!
//! Flows ported from Hermes `hermes_cli/auth_*.py` and OpenClaw `src/llm/utils/oauth/*`,
//! `extensions/*/oauth.ts`:
//! - `openai-codex`: ChatGPT account, OpenAI device-auth (or browser PKCE on :1455)
//! - `anthropic`: Claude subscription — PKCE on :53692, or a pasted `claude setup-token`
//! - `github-copilot`: GitHub device flow (token exchanged per request, see `copilot.rs`)
//! - `qwen`: Qwen portal device flow with PKCE
//! - `minimax` / `minimax-cn`: MiniMax portal user-code grant with PKCE
//! - `nous`: Nous Portal device flow
//! - `xai`: xAI account device flow (OIDC discovery)
//! - `openrouter`: PKCE that mints a permanent OpenRouter key
//! - `chutes`: Chutes PKCE ($CHUTES_CLIENT_ID)
//! - `radius`: Radius gateway device flow

use crate::auth::Cred;
use crate::store::Entry;
pub use ark_net::{form_encode, urlencode};
use serde_json::{json, Value};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// RFC 8628 device authorization (optionally with PKCE, optionally OIDC-discovered).
    Device {
        device_url: String,
        pkce: bool,
        discovery: Option<String>,
    },
    /// OpenAI's device-auth variant (user code → authorization code → token).
    CodexDevice { issuer: String },
    /// MiniMax `user_code` grant.
    MiniMax { portal: String },
    /// Authorization code + PKCE with a loopback redirect.
    Pkce {
        authorize_url: String,
        port: u16,
        path: String,
        json_token: bool,
        extra: Vec<(String, String)>,
    },
    /// OpenRouter: PKCE whose code is swapped for a permanent API key.
    OpenRouterKey { auth_url: String, keys_url: String },
    /// Paste a long-lived token (Anthropic `claude setup-token`).
    Paste { prefix: String, help: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Flow {
    pub id: String,
    /// Store key = provider id the credential belongs to.
    pub provider: String,
    pub title: String,
    pub kind: Kind,
    pub client_id: String,
    pub scope: String,
    pub token_url: String,
    /// Refresh this long before expiry.
    pub refresh_skew_ms: u64,
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| d.to_string())
}

pub const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const ANTHROPIC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const COPILOT_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
pub const QWEN_CLIENT_ID: &str = "f0304373b74a44d2b584a3fb70ca9e56";
pub const MINIMAX_CLIENT_ID: &str = "78257093-7e40-4613-99e0-527b14b39113";
pub const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";

/// All built-in flows.
pub fn flows() -> Vec<Flow> {
    let f = |id: &str,
             provider: &str,
             title: &str,
             kind: Kind,
             client: &str,
             scope: &str,
             token: &str,
             skew_s: u64| Flow {
        id: id.into(),
        provider: provider.into(),
        title: title.into(),
        kind,
        client_id: client.into(),
        scope: scope.into(),
        token_url: token.into(),
        refresh_skew_ms: skew_s * 1000,
    };
    let codex_issuer = env_or("ARK_CODEX_ISSUER", "https://auth.openai.com");
    vec![
        f("openai-codex", "openai-codex", "ChatGPT account (Codex subscription)", Kind::CodexDevice { issuer: codex_issuer.clone() }, CODEX_CLIENT_ID, "openid profile email offline_access", &format!("{codex_issuer}/oauth/token"), 120),
        f("openai-codex-browser", "openai-codex", "ChatGPT account via browser", Kind::Pkce { authorize_url: format!("{codex_issuer}/oauth/authorize"), port: 1455, path: "/auth/callback".into(), json_token: false, extra: vec![("id_token_add_organizations".into(), "true".into()), ("codex_cli_simplified_flow".into(), "true".into()), ("originator".into(), "ark".into())] }, CODEX_CLIENT_ID, "openid profile email offline_access", &format!("{codex_issuer}/oauth/token"), 120),
        f("anthropic", "anthropic", "Claude subscription (Pro/Max)", Kind::Pkce { authorize_url: "https://claude.ai/oauth/authorize".into(), port: 53692, path: "/callback".into(), json_token: true, extra: vec![("code".into(), "true".into())] }, ANTHROPIC_CLIENT_ID, "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload", "https://platform.claude.com/v1/oauth/token", 300),
        f("anthropic-setup-token", "anthropic", "Claude setup-token (`claude setup-token`)", Kind::Paste { prefix: "sk-ant-oat".into(), help: "Run `claude setup-token` in another terminal and paste the sk-ant-oat… token it prints.".into() }, "", "", "", 0),
        f("github-copilot", "github-copilot", "GitHub Copilot", Kind::Device { device_url: format!("https://{}/login/device/code", env_or("ARK_GITHUB_HOST", "github.com")), pkce: false, discovery: None }, COPILOT_CLIENT_ID, "read:user", &format!("https://{}/login/oauth/access_token", env_or("ARK_GITHUB_HOST", "github.com")), 0),
        f("qwen", "qwen", "Qwen portal (qwen.ai account)", Kind::Device { device_url: "https://chat.qwen.ai/api/v1/oauth2/device/code".into(), pkce: true, discovery: None }, QWEN_CLIENT_ID, "openid profile email model.completion", "https://chat.qwen.ai/api/v1/oauth2/token", 120),
        f("minimax", "minimax-oauth", "MiniMax portal (global)", Kind::MiniMax { portal: "https://api.minimax.io".into() }, MINIMAX_CLIENT_ID, "group_id profile model.completion", "https://api.minimax.io/oauth/token", 60),
        f("minimax-cn", "minimax-oauth-cn", "MiniMax portal (China)", Kind::MiniMax { portal: "https://api.minimaxi.com".into() }, MINIMAX_CLIENT_ID, "group_id profile model.completion", "https://api.minimaxi.com/oauth/token", 60),
        f("nous", "nous", "Nous Portal", Kind::Device { device_url: format!("{}/api/oauth/device/code", env_or("NOUS_PORTAL_BASE_URL", crate::nous::DEFAULT_PORTAL_URL)), pkce: false, discovery: None }, &crate::nous::client_id(), crate::nous::INFERENCE_INVOKE_SCOPE, &format!("{}/api/oauth/token", env_or("NOUS_PORTAL_BASE_URL", crate::nous::DEFAULT_PORTAL_URL)), 120),
        f("xai", "xai-oauth", "xAI account (Grok)", Kind::Device { device_url: "https://auth.x.ai/oauth2/device/code".into(), pkce: false, discovery: Some("https://auth.x.ai/.well-known/openid-configuration".into()) }, XAI_CLIENT_ID, "openid profile email offline_access grok-cli:access api:access", "https://auth.x.ai/oauth2/token", 3600),
        f("openrouter", "openrouter", "OpenRouter (mint a key in the browser)", Kind::OpenRouterKey { auth_url: "https://openrouter.ai/auth".into(), keys_url: "https://openrouter.ai/api/v1/auth/keys".into() }, "", "", "", 0),
        f("chutes", "chutes", "Chutes", Kind::Pkce { authorize_url: "https://api.chutes.ai/idp/authorize".into(), port: 1456, path: "/oauth-callback".into(), json_token: false, extra: vec![] }, &env_or("CHUTES_CLIENT_ID", ""), "openid profile chutes:invoke", "https://api.chutes.ai/idp/token", 120),
        f("radius", "radius", "Radius gateway", Kind::Device { device_url: "https://radius.pi.dev/v1/oauth/device".into(), pkce: false, discovery: None }, "pi-gateway", "", "https://radius.pi.dev/v1/oauth/token", 120),
    ]
}

/// A flow by id, or by the provider id it logs into.
pub fn flow(id: &str) -> Option<Flow> {
    let all = flows();
    let id = match id {
        "codex" | "chatgpt" | "openai" => "openai-codex",
        "claude" | "claude-oauth" => "anthropic",
        "setup-token" | "claude-setup-token" => "anthropic-setup-token",
        "copilot" | "github" => "github-copilot",
        "qwen-oauth" | "qwen-portal" => "qwen",
        "minimax-oauth" | "minimax-portal" => "minimax",
        "minimax-oauth-cn" => "minimax-cn",
        "xai-oauth" | "grok" => "xai",
        "nous-portal" => "nous",
        other => other,
    };
    all.iter()
        .find(|f| f.id == id)
        .or_else(|| all.iter().find(|f| f.provider == id))
        .cloned()
}

pub trait Prompter {
    /// Show where to go and which code to type.
    fn device(&self, verification_uri: &str, user_code: &str, complete_uri: Option<&str>);
    /// Ask the user to open `url` (the implementation may launch a browser).
    fn open(&self, url: &str);
    /// Read one line (pasted token / redirect URL). Empty = cancelled.
    fn read(&self, prompt: &str) -> String;
    fn info(&self, msg: &str);
}

/// Collects a flow's instructions so an in-chat `/login` can show them as chat text
/// (OpenClaw `commands-login.ts`: the chat, not the terminal, is the surface).
#[derive(Default)]
pub struct Inline {
    pub msgs: Mutex<Vec<String>>,
}

impl Inline {
    pub fn lines(&self) -> Vec<String> {
        self.msgs.lock().unwrap().clone()
    }
    fn push(&self, s: String) {
        self.msgs.lock().unwrap().push(s);
    }
}

impl Prompter for Inline {
    fn device(&self, uri: &str, code: &str, complete: Option<&str>) {
        self.push(format!(
            "Open {} and enter the code {} (waiting for authorization…)",
            complete.unwrap_or(uri),
            code
        ));
    }
    fn open(&self, url: &str) {
        self.push(format!("Open {url} (waiting for the callback…)"));
    }
    fn read(&self, _prompt: &str) -> String {
        // No keyboard inside a chat turn: flows that need a pasted value refuse up front.
        String::new()
    }
    fn info(&self, msg: &str) {
        self.push(msg.to_string());
    }
}

/// Whether this flow needs a typed value (a pasted token / redirect URL) and therefore a
/// terminal — in-chat `/login` refuses those and points at `ark login <flow>`.
pub fn needs_terminal_input(f: &Flow) -> bool {
    matches!(f.kind, Kind::Paste { .. })
}

/// Process-wide "one login per flow at a time" guard (OpenClaw `reserveProviderLoginFlow`):
/// a second chat must not fight the first one over the same device code.
pub fn reserve_flow(id: &str) -> Result<(), String> {
    static ACTIVE: Mutex<Option<std::collections::BTreeSet<String>>> = Mutex::new(None);
    let mut g = ACTIVE.lock().unwrap();
    let set = g.get_or_insert_with(Default::default);
    if !set.insert(id.to_string()) {
        return Err(format!("a `{id}` login is already in progress in this process; finish or cancel it first"));
    }
    Ok(())
}

pub fn release_flow(id: &str) {
    static ACTIVE: Mutex<Option<std::collections::BTreeSet<String>>> = Mutex::new(None);
    if let Some(set) = ACTIVE.lock().unwrap().as_mut() {
        set.remove(id);
    }
}

#[derive(Debug, Clone, Default)]
pub struct Opts {
    /// Give up waiting after this long.
    pub timeout: Option<Duration>,
    /// Do not wait for a loopback redirect; ask the user to paste the redirect URL.
    pub no_browser: bool,
}

// ───────────────────────── HTTP helpers ─────────────────────────

fn agent(url: &str) -> ureq::Agent {
    crate::net::agent(Duration::from_secs(30), url)
}

fn read(resp: ureq::http::Response<ureq::Body>) -> Result<(u16, Value), String> {
    use std::io::Read;
    let status = resp.status().as_u16();
    let mut s = String::new();
    resp.into_body()
        .into_reader()
        .take(1 << 20)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    let v = serde_json::from_str(&s).unwrap_or_else(|_| {
        // GitHub answers form-encoded unless asked for JSON; accept both.
        let q = ark_net::parse_query(s.trim());
        if q.is_empty() {
            Value::String(s.clone())
        } else {
            Value::Object(q.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
        }
    });
    Ok((status, v))
}

fn err_text(status: u16, v: &Value) -> String {
    let e = v
        .get("error_description")
        .and_then(Value::as_str)
        .or_else(|| {
            v.get("error")
                .and_then(|e| e.as_str().or_else(|| e["message"].as_str()))
        })
        .or_else(|| v.get("message").and_then(Value::as_str));
    match e {
        Some(m) => format!(
            "HTTP {status}: {m}{}",
            v.get("error")
                .and_then(Value::as_str)
                .filter(|c| Some(*c) != Some(m))
                .map(|c| format!(" ({c})"))
                .unwrap_or_default()
        ),
        None => format!(
            "HTTP {status}: {}",
            v.to_string().chars().take(300).collect::<String>()
        ),
    }
}

/// POST a form, expect 2xx JSON.
pub fn post_form(url: &str, params: &[(&str, &str)]) -> Result<Value, String> {
    let (s, v) = post_form_raw(url, params)?;
    if !(200..300).contains(&s) {
        return Err(err_text(s, &v));
    }
    Ok(v)
}

fn post_form_raw(url: &str, params: &[(&str, &str)]) -> Result<(u16, Value), String> {
    crate::net::check_host(url)?;
    let body = form_encode(params);
    let r = agent(url)
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("user-agent", concat!("ark/", env!("CARGO_PKG_VERSION")))
        .send(body.as_bytes())
        .map_err(|e| format!("POST {url}: {e}"))?;
    read(r)
}

fn post_json_raw(url: &str, body: &Value) -> Result<(u16, Value), String> {
    crate::net::check_host(url)?;
    let r = agent(url)
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", concat!("ark/", env!("CARGO_PKG_VERSION")))
        .send(body.to_string().as_bytes())
        .map_err(|e| format!("POST {url}: {e}"))?;
    read(r)
}

pub fn post_json(url: &str, body: &Value) -> Result<Value, String> {
    let (s, v) = post_json_raw(url, body)?;
    if !(200..300).contains(&s) {
        return Err(err_text(s, &v));
    }
    Ok(v)
}

pub fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<Value, String> {
    crate::net::check_host(url)?;
    let mut r = agent(url).get(url).header("accept", "application/json");
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let (s, v) = read(r.call().map_err(|e| format!("GET {url}: {e}"))?)?;
    if !(200..300).contains(&s) {
        return Err(err_text(s, &v));
    }
    Ok(v)
}

/// OAuth errors that mean the grant is gone for good (re-login needed).
pub fn is_terminal(err: &str) -> bool {
    [
        "invalid_grant",
        "token_revoked",
        "token_invalidated",
        "invalid_token",
        "unauthorized_client",
        "refresh_token_reused",
    ]
    .iter()
    .any(|t| err.contains(t))
}

fn wait_limit(o: &Opts, server: Option<u64>) -> Duration {
    o.timeout
        .unwrap_or_else(|| Duration::from_secs(server.unwrap_or(900).min(1800)))
}

/// JWT claims (no verification: only used to read account ids the server itself issued).
pub fn jwt_claims(token: &str) -> Option<Value> {
    let p = token.split('.').nth(1)?;
    serde_json::from_slice(&ark_net::crypto::b64url_decode(p)?).ok()
}

/// Turn a token response into a store entry.
pub fn entry_from(flow: &Flow, v: &Value, old: Option<&Entry>) -> Result<Entry, String> {
    let access = v["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "token response has no access_token: {}",
                v.to_string().chars().take(200).collect::<String>()
            )
        })?;
    let now = crate::ratelimit::now_ms();
    let mut e = old
        .cloned()
        .unwrap_or_else(|| Entry::new("oauth", "default", None));
    e.kind = "oauth".into();
    e.flow = Some(flow.id.clone());
    e.key = Some(access.to_string());
    if let Some(r) = v["refresh_token"].as_str().filter(|s| !s.is_empty()) {
        e.refresh = Some(r.to_string());
    }
    e.expires_at_ms = if let Some(s) = v["expires_in"]
        .as_f64()
        .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
    {
        Some(now + (s * 1000.0) as u64)
    } else if let Some(x) = v["expired_in"].as_u64() {
        // MiniMax: unix ms, or a TTL in seconds.
        Some(if x > 1_000_000_000_000 {
            x
        } else {
            now + x.max(1) * 1000
        })
    } else {
        jwt_claims(access)
            .and_then(|c| c["exp"].as_u64())
            .map(|c| c * 1000)
    };
    for k in ["id_token", "scope", "token_type", "account_id"] {
        if let Some(x) = v.get(k).filter(|x| !x.is_null()) {
            e.extra.insert(k.into(), x.clone());
        }
    }
    if let Some(r) = v["resource_url"].as_str().filter(|s| !s.is_empty()) {
        // Qwen: the API host for this account.
        let host = r.trim_start_matches("https://").trim_end_matches('/');
        e.base_url = Some(format!("https://{host}/v1"));
    }
    if flow.provider == "nous" {
        // Nous Portal: the token response may heal the inference host (the free tier's
        // `welcome-api` host is handed out per account), and the access token doubles as the
        // NAS invoke JWT, which is kept in its own slot (Hermes auth_nous.py).
        if let Some(u) = v["inference_base_url"]
            .as_str()
            .map(str::trim)
            .filter(|u| u.starts_with("https://"))
        {
            e.extra
                .insert("inference_base_url".into(), Value::String(u.to_string()));
            if !e.base_url.as_deref().is_some_and(|b| b.starts_with("http")) {
                e.base_url = Some(format!("{}/", u.trim_end_matches('/')));
            }
        }
        crate::nous::derive_agent_key(&mut e);
    }
    Ok(e)
}

/// Request headers and endpoint a stored login implies.
pub fn cred_for(e: &Entry, key: String) -> Cred {
    let mut c = Cred {
        token: Some(key.clone()),
        headers: vec![],
        base: e.base_url.clone(),
    };
    if e.flow
        .as_deref()
        .is_some_and(|f| f.starts_with("openai-codex"))
    {
        // Codex backend: account and residency headers from the ChatGPT JWT.
        if let Some(auth) = jwt_claims(&key).map(|c| c["https://api.openai.com/auth"].clone()) {
            if let Some(a) = auth["chatgpt_account_id"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                c.headers.push(("ChatGPT-Account-ID".into(), a.into()));
            }
            if let Some(r) = auth["chatgpt_data_residency"]
                .as_str()
                .or(auth["chatgpt_compute_residency"].as_str())
                .filter(|s| !s.trim().is_empty())
            {
                c.headers
                    .push(("x-openai-internal-codex-residency".into(), r.trim().into()));
            }
        }
        c.headers.push(("originator".into(), "ark".into()));
        c.headers.push((
            "user-agent".into(),
            concat!("ark/", env!("CARGO_PKG_VERSION")).into(),
        ));
    }
    c
}

// ───────────────────────── login ─────────────────────────

pub fn login(flow: &Flow, p: &dyn Prompter, o: &Opts) -> Result<Entry, String> {
    match &flow.kind {
        Kind::Device {
            device_url,
            pkce,
            discovery,
        } => device_login(flow, device_url, *pkce, discovery.as_deref(), p, o),
        Kind::CodexDevice { issuer } => codex_device(flow, issuer, p, o),
        Kind::MiniMax { portal } => minimax_login(flow, portal, p, o),
        Kind::Pkce {
            authorize_url,
            port,
            path,
            json_token,
            extra,
        } => pkce_login(flow, authorize_url, *port, path, *json_token, extra, p, o),
        Kind::OpenRouterKey { auth_url, keys_url } => openrouter_login(auth_url, keys_url, p, o),
        Kind::Paste { prefix, help } => {
            p.info(help);
            let t = p.read("token: ");
            let t = t.trim();
            if t.is_empty() {
                return Err("cancelled".into());
            }
            if !t.starts_with(prefix.as_str()) {
                return Err(format!(
                    "that does not look like a setup token (expected it to start with {prefix})"
                ));
            }
            let mut e = Entry::new("token", "setup-token", Some(t.to_string()));
            e.flow = Some(flow.id.clone());
            Ok(e)
        }
    }
}

fn device_login(
    flow: &Flow,
    device_url: &str,
    pkce: bool,
    discovery: Option<&str>,
    p: &dyn Prompter,
    o: &Opts,
) -> Result<Entry, String> {
    let (mut device_url, mut token_url) = (device_url.to_string(), flow.token_url.clone());
    if let Some(d) = discovery {
        if let Ok(v) = get_json(d, &[]) {
            // Pin endpoints to the issuer's host: a hijacked document must not receive our tokens.
            let host = crate::net::host_port(d).0;
            if let Some(u) = v["device_authorization_endpoint"]
                .as_str()
                .filter(|u| crate::net::host_port(u).0 == host)
            {
                device_url = u.to_string();
            }
            if let Some(u) = v["token_endpoint"]
                .as_str()
                .filter(|u| crate::net::host_port(u).0 == host)
            {
                token_url = u.to_string();
            }
        }
    }
    let (verifier, challenge) = ark_net::crypto::pkce_pair();
    let mut params: Vec<(&str, &str)> = vec![("client_id", &flow.client_id)];
    if !flow.scope.is_empty() {
        params.push(("scope", &flow.scope));
    }
    if pkce {
        params.push(("code_challenge", &challenge));
        params.push(("code_challenge_method", "S256"));
    }
    let d =
        post_form(&device_url, &params).map_err(|e| format!("device code request failed: {e}"))?;
    let device_code = d["device_code"]
        .as_str()
        .ok_or("device code response missing device_code")?
        .to_string();
    let user_code = d["user_code"]
        .as_str()
        .ok_or("device code response missing user_code")?;
    let uri = d["verification_uri"]
        .as_str()
        .or(d["verification_url"].as_str())
        .unwrap_or("");
    p.device(uri, user_code, d["verification_uri_complete"].as_str());
    let mut interval = d["interval"]
        .as_u64()
        .or_else(|| d["interval"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(5)
        .max(1);
    let deadline = Instant::now() + wait_limit(o, d["expires_in"].as_u64());
    loop {
        if Instant::now() >= deadline {
            return Err("timed out waiting for the device authorization".into());
        }
        std::thread::sleep(Duration::from_millis(interval * 1000 / poll_divisor()));
        let mut q: Vec<(&str, &str)> = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", &flow.client_id),
            ("device_code", &device_code),
        ];
        if pkce {
            q.push(("code_verifier", &verifier));
        }
        let (s, v) = post_form_raw(&token_url, &q)?;
        if (200..300).contains(&s) && v.get("access_token").is_some() {
            return entry_from(
                &Flow {
                    token_url,
                    ..flow.clone()
                },
                &v,
                None,
            );
        }
        match v["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some(e) => {
                return Err(format!(
                    "authorization failed: {}",
                    err_text(s, &v).replace(&format!(" ({e})"), "")
                ))
            }
            None if (200..300).contains(&s) => {}
            None => return Err(format!("authorization failed: {}", err_text(s, &v))),
        }
    }
}

/// Tests shrink poll intervals.
fn poll_divisor() -> u64 {
    std::env::var("ARK_TEST_FAST_POLL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1)
}

fn codex_device(flow: &Flow, issuer: &str, p: &dyn Prompter, o: &Opts) -> Result<Entry, String> {
    let (s, d) = post_json_raw(
        &format!("{issuer}/api/accounts/deviceauth/usercode"),
        &json!({"client_id": flow.client_id}),
    )?;
    if s == 429 {
        return Err("OpenAI is rate-limiting login requests (429); wait a minute and retry".into());
    }
    if s != 200 {
        return Err(format!("device code request returned status {s}"));
    }
    let user_code = d["user_code"]
        .as_str()
        .or(d["usercode"].as_str())
        .filter(|c| !c.is_empty())
        .ok_or("device code response missing user_code")?
        .to_string();
    let auth_id = d["device_auth_id"]
        .as_str()
        .filter(|c| !c.is_empty())
        .ok_or("device code response missing device_auth_id")?
        .to_string();
    let interval = d["interval"]
        .as_u64()
        .or_else(|| d["interval"].as_str().and_then(|x| x.parse().ok()))
        .unwrap_or(5)
        .max(3);
    p.device(&format!("{issuer}/codex/device"), &user_code, None);
    let deadline = Instant::now() + wait_limit(o, Some(900));
    let code = loop {
        if Instant::now() >= deadline {
            return Err("login timed out after 15 minutes".into());
        }
        std::thread::sleep(Duration::from_millis(interval * 1000 / poll_divisor()));
        let (s, v) = post_json_raw(
            &format!("{issuer}/api/accounts/deviceauth/token"),
            &json!({"device_auth_id": auth_id, "user_code": user_code}),
        )?;
        match s {
            200 => break v,
            403 | 404 => continue,
            _ => return Err(format!("device auth polling returned status {s}")),
        }
    };
    let ac = code["authorization_code"]
        .as_str()
        .ok_or("device auth response missing authorization_code")?;
    let cv = code["code_verifier"]
        .as_str()
        .ok_or("device auth response missing code_verifier")?;
    let redirect = format!("{issuer}/deviceauth/callback");
    let v = post_form(
        &flow.token_url,
        &[
            ("grant_type", "authorization_code"),
            ("code", ac),
            ("redirect_uri", &redirect),
            ("client_id", &flow.client_id),
            ("code_verifier", cv),
        ],
    )
    .map_err(|e| format!("token exchange failed: {e}"))?;
    let mut e = entry_from(flow, &v, None)?;
    e.base_url = None;
    Ok(e)
}

fn minimax_login(flow: &Flow, portal: &str, p: &dyn Prompter, o: &Opts) -> Result<Entry, String> {
    let (verifier, challenge) = ark_net::crypto::pkce_pair();
    let state = ark_net::crypto::random_token(16);
    let d = post_form(
        &format!("{portal}/oauth/code"),
        &[
            ("response_type", "code"),
            ("client_id", &flow.client_id),
            ("scope", &flow.scope),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
        ],
    )?;
    if d["state"].as_str().is_some_and(|s| s != state) {
        return Err("MiniMax OAuth state mismatch; aborting".into());
    }
    let user_code = d["user_code"]
        .as_str()
        .ok_or("MiniMax response missing user_code")?
        .to_string();
    p.device(
        d["verification_uri"].as_str().unwrap_or(portal),
        &user_code,
        None,
    );
    let interval = (d["interval"].as_u64().unwrap_or(2000) / 1000).max(2);
    let deadline = Instant::now() + wait_limit(o, Some(600));
    loop {
        if Instant::now() >= deadline {
            return Err("timed out waiting for MiniMax authorization".into());
        }
        std::thread::sleep(Duration::from_millis(interval * 1000 / poll_divisor()));
        let (s, v) = post_form_raw(
            &flow.token_url,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:user_code"),
                ("client_id", &flow.client_id),
                ("user_code", &user_code),
                ("code_verifier", &verifier),
            ],
        )?;
        if (200..300).contains(&s) && v["access_token"].is_string() {
            let mut e = entry_from(flow, &v, None)?;
            e.base_url = Some(format!("{portal}/anthropic"));
            return Ok(e);
        }
        let status = v["status"].as_str().unwrap_or("");
        if status == "error" || (s > 400 && s != 428) {
            return Err(format!("MiniMax authorization failed: {}", err_text(s, &v)));
        }
    }
}

/// Wait for one request on a loopback port; returns its query parameters.
fn loopback(
    port: u16,
    path: &str,
    o: &Opts,
) -> Result<
    (
        String,
        mpsc::Receiver<Vec<(String, String)>>,
        ark_net::httpd::Server,
    ),
    String,
> {
    let (tx, rx) = mpsc::channel::<Vec<(String, String)>>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let want = path.to_string();
    let handler: ark_net::httpd::Handler = Arc::new(move |r: ark_net::httpd::Request| {
        if r.path != want {
            return ark_net::httpd::Response::text(404, "not found");
        }
        if let Some(t) = tx.lock().unwrap().take() {
            let _ = t.send(r.query.clone());
        }
        let ok = r.query("code").is_some();
        ark_net::httpd::Response::html(if ok {
            "<h2>Signed in.</h2><p>You can close this tab and return to ark.</p>"
        } else {
            "<h2>Sign-in failed.</h2><p>Return to ark for details.</p>"
        })
    });
    let _ = o;
    let srv = ark_net::httpd::Server::bind(&format!("127.0.0.1:{port}"), ark_net::httpd::Opts::default(), handler).map_err(|e| format!("cannot listen on 127.0.0.1:{port} for the OAuth redirect ({e}); retry with --no-browser"))?;
    let redirect = format!("http://localhost:{}{path}", srv.local_addr().port());
    Ok((redirect, rx, srv))
}

fn parse_code_input(s: &str) -> Vec<(String, String)> {
    let s = s.trim();
    if let Some((_, q)) = s.split_once('?') {
        return ark_net::parse_query(q.split('#').next().unwrap_or(q));
    }
    // Anthropic shows `code#state` for manual copy.
    if let Some((c, st)) = s.split_once('#') {
        return vec![("code".into(), c.into()), ("state".into(), st.into())];
    }
    vec![("code".into(), s.to_string())]
}

#[allow(clippy::too_many_arguments)]
fn pkce_login(
    flow: &Flow,
    authorize: &str,
    port: u16,
    path: &str,
    json_token: bool,
    extra: &[(String, String)],
    p: &dyn Prompter,
    o: &Opts,
) -> Result<Entry, String> {
    if flow.client_id.is_empty() {
        return Err(format!(
            "{}: no OAuth client id configured (set ${}_CLIENT_ID)",
            flow.title,
            flow.id.to_uppercase().replace('-', "_")
        ));
    }
    let (verifier, challenge) = ark_net::crypto::pkce_pair();
    let state = ark_net::crypto::random_token(24);
    let server = if o.no_browser {
        None
    } else {
        Some(loopback(port, path, o)?)
    };
    let redirect = match &server {
        Some((r, _, _)) => r.clone(),
        None => format!("http://localhost:{port}{path}"),
    };
    let mut q: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &flow.client_id),
        ("redirect_uri", &redirect),
        ("scope", &flow.scope),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("state", &state),
    ];
    for (k, v) in extra {
        q.push((k, v));
    }
    let url = format!(
        "{authorize}{}{}",
        if authorize.contains('?') { '&' } else { '?' },
        form_encode(&q)
    );
    p.open(&url);
    let params = match &server {
        Some((_, rx, _)) => rx.recv_timeout(wait_limit(o, Some(300))).map_err(|_| {
            "timed out waiting for the browser redirect (retry with --no-browser to paste it)"
                .to_string()
        })?,
        None => {
            let s = p.read("Paste the redirect URL (or code) here: ");
            if s.trim().is_empty() {
                return Err("cancelled".into());
            }
            parse_code_input(&s)
        }
    };
    drop(server);
    let get = |k: &str| params.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    if let Some(e) = get("error") {
        return Err(format!(
            "authorization denied: {e} {}",
            get("error_description").unwrap_or_default()
        ));
    }
    if get("state").is_some_and(|s| s != state) {
        return Err("OAuth state mismatch; possible CSRF, aborting".into());
    }
    let code = get("code").ok_or("redirect carried no code")?;
    let v = if json_token {
        post_json(&flow.token_url, &json!({"grant_type": "authorization_code", "client_id": flow.client_id, "code": code, "state": state, "redirect_uri": redirect, "code_verifier": verifier}))
    } else {
        post_form(&flow.token_url, &[("grant_type", "authorization_code"), ("client_id", &flow.client_id), ("code", &code), ("redirect_uri", &redirect), ("code_verifier", &verifier)])
    }
    .map_err(|e| format!("token exchange failed: {e}"))?;
    entry_from(flow, &v, None)
}

fn openrouter_login(
    auth_url: &str,
    keys_url: &str,
    p: &dyn Prompter,
    o: &Opts,
) -> Result<Entry, String> {
    let (verifier, challenge) = ark_net::crypto::pkce_pair();
    let server = if o.no_browser {
        None
    } else {
        Some(loopback(3000, "/callback", o).or_else(|_| loopback(0, "/callback", o))?)
    };
    let cb = server
        .as_ref()
        .map(|s| s.0.clone())
        .unwrap_or_else(|| "http://localhost:3000/callback".into());
    let url = format!(
        "{auth_url}?{}",
        form_encode(&[
            ("callback_url", &cb),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("key_label", "ark")
        ])
    );
    p.open(&url);
    let params = match &server {
        Some((_, rx, _)) => rx
            .recv_timeout(wait_limit(o, Some(300)))
            .map_err(|_| "timed out waiting for the OpenRouter redirect".to_string())?,
        None => parse_code_input(&p.read("Paste the redirect URL (or code) here: ")),
    };
    drop(server);
    let code = params
        .iter()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.clone())
        .filter(|c| !c.is_empty())
        .ok_or("redirect carried no code")?;
    let v = post_json(
        keys_url,
        &json!({"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}),
    )
    .map_err(|e| format!("OpenRouter key exchange failed: {e}"))?;
    let key = v["key"].as_str().ok_or("OpenRouter returned no key")?;
    let mut e = Entry::new("api_key", "oauth", Some(key.to_string()));
    e.flow = Some("openrouter".into());
    Ok(e)
}

// ───────────────────────── refresh ─────────────────────────

pub fn refresh(flow: &Flow, e: &Entry) -> Result<Entry, String> {
    let rt = e.refresh.as_deref().ok_or("no refresh token")?;
    let v = match &flow.kind {
        Kind::Pkce {
            json_token: true, ..
        } => post_json(
            &flow.token_url,
            &json!({"grant_type": "refresh_token", "client_id": flow.client_id, "refresh_token": rt}),
        )?,
        _ => {
            let mut p: Vec<(&str, &str)> = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", rt),
                ("client_id", &flow.client_id),
            ];
            if flow.client_id.is_empty() {
                p.pop();
            }
            post_form(&flow.token_url, &p)?
        }
    };
    entry_from(flow, &v, Some(e))
}

// ───────────────────────── importing other CLIs' logins ─────────────────────────

fn home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/".into())
}

/// Reuse a login another tool already made (Codex CLI, Claude Code, Qwen Code, GitHub
/// Copilot CLI / VS Code). None when nothing usable is there.
pub fn import_external(flow_id: &str) -> Option<Entry> {
    let read = |p: std::path::PathBuf| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    };
    let mut e = match flow_id {
        "openai-codex" => {
            let v = read(home().join(".codex/auth.json"))?;
            let t = &v["tokens"];
            let mut e = Entry::new(
                "oauth",
                "codex-cli",
                t["access_token"].as_str().map(String::from),
            );
            e.refresh = t["refresh_token"].as_str().map(String::from);
            e.expires_at_ms = e
                .key
                .as_deref()
                .and_then(jwt_claims)
                .and_then(|c| c["exp"].as_u64())
                .map(|x| x * 1000);
            e
        }
        "anthropic" => {
            let v = read(home().join(".claude/.credentials.json"))?;
            let o = &v["claudeAiOauth"];
            let mut e = Entry::new(
                "oauth",
                "claude-code",
                o["accessToken"].as_str().map(String::from),
            );
            e.refresh = o["refreshToken"].as_str().map(String::from);
            e.expires_at_ms = o["expiresAt"].as_u64();
            e
        }
        "qwen" => {
            let v = read(home().join(".qwen/oauth_creds.json"))?;
            let mut e = Entry::new(
                "oauth",
                "qwen-code",
                v["access_token"].as_str().map(String::from),
            );
            e.refresh = v["refresh_token"].as_str().map(String::from);
            e.expires_at_ms = v["expiry_date"].as_u64();
            if let Some(r) = v["resource_url"].as_str() {
                e.base_url = Some(format!(
                    "https://{}/v1",
                    r.trim_start_matches("https://").trim_end_matches('/')
                ));
            }
            e
        }
        "github-copilot" => {
            let t = crate::copilot::cli_token()?;
            Entry::new("token", "gh-cli", Some(t))
        }
        _ => return None,
    };
    e.key.as_ref()?;
    e.flow = Some(flow_id.to_string());
    Some(e)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    pub struct FakeServer {
        pub base: String,
        log: Arc<Mutex<Vec<(String, String, Vec<(String, String)>)>>>,
    }
    impl FakeServer {
        /// (path, body) of every request so far.
        pub fn requests(&self) -> Vec<(String, String)> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(p, b, _)| (p.clone(), b.clone()))
                .collect()
        }
        pub fn headers(&self, i: usize) -> Vec<(String, String)> {
            self.log.lock().unwrap()[i].2.clone()
        }
    }

    /// Serve scripted (status, body) replies in order, one per request (last repeats).
    pub fn fake_server(replies: Vec<(u16, String)>) -> FakeServer {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            let mut i = 0;
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut len = 0;
                let mut hs = vec![];
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        hs.push((k.trim().to_lowercase(), v.trim().to_string()));
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                log2.lock()
                    .unwrap()
                    .push((path, String::from_utf8_lossy(&body).to_string(), hs));
                let (st, b) = replies.get(i).or(replies.last()).cloned().unwrap();
                i += 1;
                let _ = write!(s, "HTTP/1.1 {st} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}", b.len());
            }
        });
        FakeServer { base, log }
    }

    #[derive(Default)]
    struct P {
        codes: Mutex<Vec<String>>,
        opened: Mutex<Vec<String>>,
        paste: String,
    }
    impl Prompter for P {
        fn device(&self, _: &str, code: &str, _: Option<&str>) {
            self.codes.lock().unwrap().push(code.into());
        }
        fn open(&self, url: &str) {
            self.opened.lock().unwrap().push(url.into());
        }
        fn read(&self, _: &str) -> String {
            self.paste.clone()
        }
        fn info(&self, _: &str) {}
    }

    fn fast() {
        std::env::set_var("ARK_TEST_FAST_POLL", "1000");
    }

    #[test]
    fn rfc8628_device_flow_with_pkce_pending_then_token() {
        fast();
        let srv = fake_server(vec![
            (200, r#"{"device_code":"dc1","user_code":"ABCD-1234","verification_uri":"https://x/device","interval":1,"expires_in":60}"#.into()),
            (400, r#"{"error":"authorization_pending"}"#.into()),
            (400, r#"{"error":"slow_down"}"#.into()),
            (200, r#"{"access_token":"at1","refresh_token":"rt1","expires_in":3600,"resource_url":"portal.qwen.ai"}"#.into()),
        ]);
        let mut f = flow("qwen").unwrap();
        f.token_url = format!("{}/token", srv.base);
        f.kind = Kind::Device {
            device_url: format!("{}/device", srv.base),
            pkce: true,
            discovery: None,
        };
        let p = P::default();
        let e = login(
            &f,
            &p,
            &Opts {
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.codes.lock().unwrap()[0], "ABCD-1234");
        assert_eq!(
            (e.key.as_deref(), e.refresh.as_deref()),
            (Some("at1"), Some("rt1"))
        );
        assert_eq!(e.base_url.as_deref(), Some("https://portal.qwen.ai/v1"));
        assert!(e.expires_at_ms.unwrap() > crate::ratelimit::now_ms());
        let reqs = srv.requests();
        assert!(
            reqs[0].1.contains("code_challenge_method=S256")
                && reqs[0].1.contains("client_id=f0304373")
        );
        assert!(reqs[3].1.contains("code_verifier=") && reqs[3].1.contains("device_code=dc1"));
    }

    #[test]
    fn device_flow_denied_is_an_error() {
        fast();
        let srv = fake_server(vec![
            (
                200,
                r#"{"device_code":"d","user_code":"U","verification_uri":"v","interval":1}"#.into(),
            ),
            (
                400,
                r#"{"error":"access_denied","error_description":"user said no"}"#.into(),
            ),
        ]);
        let mut f = flow("github-copilot").unwrap();
        f.token_url = format!("{}/token", srv.base);
        f.kind = Kind::Device {
            device_url: format!("{}/device", srv.base),
            pkce: false,
            discovery: None,
        };
        let err = login(&f, &P::default(), &Opts::default()).unwrap_err();
        assert!(err.contains("user said no"), "{err}");
    }

    #[test]
    fn codex_device_auth_exchange() {
        fast();
        let claims = ark_net::crypto::b64url(br#"{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_account_id":"acct-9","chatgpt_data_residency":"eu"}}"#);
        let jwt = format!("h.{claims}.s");
        let srv = fake_server(vec![
            (
                200,
                r#"{"device_auth_id":"da","user_code":"WXYZ","interval":"3"}"#.into(),
            ),
            (404, "{}".into()),
            (
                200,
                r#"{"authorization_code":"ac","code_verifier":"cv"}"#.into(),
            ),
            (
                200,
                format!(r#"{{"access_token":"{jwt}","refresh_token":"r","id_token":"i"}}"#),
            ),
        ]);
        let mut f = flow("openai-codex").unwrap();
        f.kind = Kind::CodexDevice {
            issuer: srv.base.clone(),
        };
        f.token_url = format!("{}/oauth/token", srv.base);
        let e = login(
            &f,
            &P::default(),
            &Opts {
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            e.expires_at_ms,
            Some(4_102_444_800_000),
            "expiry from the JWT"
        );
        let reqs = srv.requests();
        assert_eq!(reqs[0].0, "/api/accounts/deviceauth/usercode");
        assert!(
            reqs[3].1.contains("grant_type=authorization_code")
                && reqs[3].1.contains("code_verifier=cv")
                && reqs[3].1.contains("deviceauth%2Fcallback")
        );
        let c = cred_for(&e, e.key.clone().unwrap());
        assert!(c
            .headers
            .contains(&("ChatGPT-Account-ID".into(), "acct-9".into())));
        assert!(c
            .headers
            .contains(&("x-openai-internal-codex-residency".into(), "eu".into())));
    }

    #[test]
    fn pkce_paste_mode_json_token_and_refresh() {
        let srv = fake_server(vec![
            (
                200,
                r#"{"access_token":"sk-ant-oat01-a","refresh_token":"r1","expires_in":28800}"#
                    .into(),
            ),
            (
                200,
                r#"{"access_token":"sk-ant-oat01-b","expires_in":28800}"#.into(),
            ),
        ]);
        let mut f = flow("anthropic").unwrap();
        f.token_url = format!("{}/v1/oauth/token", srv.base);
        let p = P {
            paste: "thecode#STATE_WILL_MISMATCH".into(),
            ..Default::default()
        };
        let err = login(
            &f,
            &p,
            &Opts {
                no_browser: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("state mismatch"), "{err}");
        let p = P {
            paste: "thecode".into(),
            ..Default::default()
        };
        let e = login(
            &f,
            &p,
            &Opts {
                no_browser: true,
                ..Default::default()
            },
        )
        .unwrap();
        let url = p.opened.lock().unwrap()[0].clone();
        assert!(
            url.starts_with("https://claude.ai/oauth/authorize?")
                && url.contains("code_challenge_method=S256")
                && url.contains("code=true")
        );
        let body: Value = serde_json::from_str(&srv.requests()[0].1).unwrap();
        assert_eq!(body["grant_type"], "authorization_code");
        assert_eq!(body["code"], "thecode");
        let r = refresh(&f, &e).unwrap();
        assert_eq!(r.key.as_deref(), Some("sk-ant-oat01-b"));
        assert_eq!(
            r.refresh.as_deref(),
            Some("r1"),
            "refresh token kept when not rotated"
        );
        assert_eq!(r.id, e.id);
    }

    #[test]
    fn pkce_loopback_receives_redirect() {
        let srv = fake_server(vec![(
            200,
            r#"{"access_token":"ch-1","refresh_token":"r","expires_in":60}"#.into(),
        )]);
        let f = Flow {
            id: "chutes".into(),
            provider: "chutes".into(),
            title: "t".into(),
            kind: Kind::Pkce {
                authorize_url: format!("{}/authorize", srv.base),
                port: 0,
                path: "/cb".into(),
                json_token: false,
                extra: vec![],
            },
            client_id: "cid".into(),
            scope: "s".into(),
            token_url: format!("{}/token", srv.base),
            refresh_skew_ms: 0,
        };
        struct Browser;
        impl Prompter for Browser {
            fn device(&self, _: &str, _: &str, _: Option<&str>) {}
            fn open(&self, url: &str) {
                let q = ark_net::parse_query(url.split_once('?').unwrap().1);
                let get = |k: &str| q.iter().find(|(a, _)| a == k).unwrap().1.clone();
                let target = format!("{}?code=abc&state={}", get("redirect_uri"), get("state"));
                std::thread::spawn(move || {
                    let _ = ark_net::http::agent().get(&target).call();
                });
            }
            fn read(&self, _: &str) -> String {
                String::new()
            }
            fn info(&self, _: &str) {}
        }
        let e = login(
            &f,
            &Browser,
            &Opts {
                timeout: Some(Duration::from_secs(10)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(e.key.as_deref(), Some("ch-1"));
        assert!(srv.requests()[0].1.contains("code=abc"));
    }

    #[test]
    fn minimax_user_code_grant() {
        fast();
        let srv = fake_server(vec![(200, r#"{"user_code":"MM1","verification_uri":"https://mm/verify","expired_in":600,"interval":2000}"#.into()), (200, r#"{"status":"pending"}"#.into()), (200, r#"{"access_token":"mm-at","refresh_token":"mm-rt","expired_in":3600}"#.into())]);
        let mut f = flow("minimax").unwrap();
        f.kind = Kind::MiniMax {
            portal: srv.base.clone(),
        };
        f.token_url = format!("{}/oauth/token", srv.base);
        let e = login(
            &f,
            &P::default(),
            &Opts {
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(e.key.as_deref(), Some("mm-at"));
        assert_eq!(e.base_url, Some(format!("{}/anthropic", srv.base)));
        assert!(srv.requests()[2]
            .1
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auser_code"));
    }

    use crate::auth::CredSource as _;

    fn jwt_fixture(exp_secs: u64) -> String {
        let head = ark_net::crypto::b64url(br#"{"alg":"none","typ":"JWT"}"#);
        let body = ark_net::crypto::b64url(
            format!(r#"{{"exp":{exp_secs},"scope":"inference:invoke"}}"#).as_bytes(),
        );
        format!("{head}.{body}.")
    }

    #[test]
    fn nous_login_mints_an_agent_key_and_the_store_refreshes_it() {
        fast();
        let now = crate::ratelimit::now_ms() / 1000;
        let fresh = jwt_fixture(now + 3600);
        let rotated = jwt_fixture(now + 7200);
        let srv = fake_server(vec![
            (200, r#"{"device_code":"dc-n","user_code":"NOUS-1","verification_uri":"https://n/device","interval":1,"expires_in":60}"#.into()),
            (200, format!(r#"{{"access_token":"{fresh}","refresh_token":"rt-n","expires_in":3600,"scope":"inference:invoke","inference_base_url":"https://welcome-api.nousresearch.com/v1"}}"#)),
            (200, format!(r#"{{"access_token":"{rotated}","refresh_token":"rt-n2","expires_in":3600,"scope":"inference:invoke"}}"#)),
        ]);
        std::env::set_var("NOUS_PORTAL_BASE_URL", &srv.base);
        let mut f = flow("nous").unwrap();
        f.kind = Kind::Device {
            device_url: format!("{}/device", srv.base),
            pkce: false,
            discovery: None,
        };
        f.token_url = format!("{}/token", srv.base);
        let e = login(
            &f,
            &P::default(),
            &Opts {
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .unwrap();
        // The invoke JWT is kept in its own slot with an expiry, and the healed inference host.
        assert_eq!(crate::nous::agent_key(&e).as_deref(), Some(fresh.as_str()));
        assert_eq!(crate::nous::agent_key_status(&e, crate::nous::MIN_TTL_SECS), None);
        assert!(e.extra["agent_key_expires_at"].as_u64().unwrap() > crate::ratelimit::now_ms());
        assert_eq!(
            crate::nous::inference_base_url(Some(&e)),
            "https://welcome-api.nousresearch.com/v1"
        );
        assert_eq!(
            e.base_url.as_deref(),
            Some("https://welcome-api.nousresearch.com/v1/")
        );
        let reqs = srv.requests();
        assert!(reqs[0].1.contains("client_id=hermes-cli"), "{}", reqs[0].1);

        // A stored login whose JWT ran out is redeemed from the refresh token before use.
        let dir = ark_core::tmp::scratch_path(format!("ark-nous-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::Store::new(dir.join("auth.json"));
        let id = store.upsert_login("nous", e).unwrap();
        let stale = jwt_fixture(now.saturating_sub(10));
        store
            .modify("nous", &id, |x| {
                x.key = Some(stale.clone());
                x.expires_at_ms = Some(crate::ratelimit::now_ms() + 3_600_000);
                x.extra.remove("agent_key");
            })
            .unwrap();
        let cred = crate::auth::Stored::new(store.clone(), "nous", &id, false)
            .get()
            .unwrap();
        assert_eq!(cred.token.as_deref(), Some(rotated.as_str()));
        assert_eq!(store.entry("nous", &id).unwrap().refresh.as_deref(), Some("rt-n2"));

        // Nothing left to redeem: Hermes' re-login message instead of a silent dead key.
        store
            .modify("nous", &id, |x| {
                x.refresh = None;
                x.key = Some(stale.clone());
            })
            .unwrap();
        let err = crate::auth::Stored::new(store, "nous", &id, false)
            .get()
            .err()
            .unwrap();
        assert_eq!(err.kind, ark_core::ProviderErrorKind::Auth);
        assert!(err.message.contains("not a usable inference JWT"), "{}", err.message);
        assert!(err.message.contains("ark login nous"), "{}", err.message);
        std::env::remove_var("NOUS_PORTAL_BASE_URL");
    }

    #[test]
    fn openrouter_key_minting_and_setup_token_paste() {
        let srv = fake_server(vec![(200, r#"{"key":"sk-or-v1-minted"}"#.into())]);
        let f = Flow {
            kind: Kind::OpenRouterKey {
                auth_url: format!("{}/auth", srv.base),
                keys_url: format!("{}/keys", srv.base),
            },
            ..flow("openrouter").unwrap()
        };
        let p = P {
            paste: "http://localhost:3000/callback?code=orc".into(),
            ..Default::default()
        };
        let e = login(
            &f,
            &p,
            &Opts {
                no_browser: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            (e.kind.as_str(), e.key.as_deref()),
            ("api_key", Some("sk-or-v1-minted"))
        );
        let st = flow("setup-token").unwrap();
        assert!(login(
            &st,
            &P {
                paste: "nope".into(),
                ..Default::default()
            },
            &Opts::default()
        )
        .is_err());
        let e = login(
            &st,
            &P {
                paste: "sk-ant-oat01-xyz".into(),
                ..Default::default()
            },
            &Opts::default(),
        )
        .unwrap();
        assert_eq!(e.kind, "token");
    }

    #[test]
    fn terminal_errors_and_aliases() {
        assert!(is_terminal(
            "HTTP 400: refresh token expired (invalid_grant)"
        ));
        assert!(!is_terminal("HTTP 503: upstream"));
        assert_eq!(flow("codex").unwrap().id, "openai-codex");
        assert_eq!(flow("minimax-oauth").unwrap().id, "minimax");
        assert_eq!(flow("xai-oauth").unwrap().provider, "xai-oauth");
        assert!(flow("nope").is_none());
        for f in flows() {
            assert!(!f.title.is_empty());
        }
    }

    #[test]
    fn imports_codex_and_claude_cli_logins() {
        let h = ark_core::tmp::scratch_path(format!("ark-imp-{}", std::process::id()));
        std::fs::create_dir_all(h.join(".codex")).unwrap();
        std::fs::create_dir_all(h.join(".claude")).unwrap();
        std::fs::write(
            h.join(".codex/auth.json"),
            r#"{"tokens":{"access_token":"a.b.c","refresh_token":"r"}}"#,
        )
        .unwrap();
        std::fs::write(h.join(".claude/.credentials.json"), r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-q","refreshToken":"rr","expiresAt":123}}"#).unwrap();
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", &h);
        let c = import_external("openai-codex").unwrap();
        let a = import_external("anthropic").unwrap();
        if let Some(o) = old {
            std::env::set_var("HOME", o);
        }
        assert_eq!(c.refresh.as_deref(), Some("r"));
        assert_eq!(
            (a.key.as_deref(), a.expires_at_ms),
            (Some("sk-ant-oat01-q"), Some(123))
        );
    }
}
