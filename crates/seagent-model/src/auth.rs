//! Credentials: where a request's key comes from (static, env, `key_cmd`, stored OAuth
//! login with refresh, Copilot token exchange, cloud identity), and the credential pool
//! that rotates several keys of one provider with cooldowns on 429/401/402.
//! Hermes `agent/credential_pool.py`, `command_token_source.py`; OpenClaw auth profiles /
//! `api-key-rotation.ts`.

use crate::store::{Entry, Store};
use crate::ProviderConfig;
use seagent_core::{
    Cancel, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError,
    ProviderErrorKind as K, StreamEvent,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What one request authenticates with.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cred {
    pub token: Option<String>,
    /// Extra headers the credential requires (Copilot editor headers, Codex account id).
    pub headers: Vec<(String, String)>,
    /// Endpoint override that comes with the credential (Copilot Enterprise, Qwen portal).
    pub base: Option<String>,
}

impl Cred {
    pub fn token(t: impl Into<String>) -> Cred {
        Cred {
            token: Some(t.into()),
            ..Default::default()
        }
    }
}

/// A pasted key as typed at a terminal: bracketed-paste markers and surrounding
/// whitespace removed. Err when what is left cannot go in an HTTP header.
pub fn clean_key(raw: &str) -> Result<String, String> {
    let k = raw.replace("\x1b[200~", "").replace("\x1b[201~", "");
    let k = k.trim();
    check_key(k)?;
    Ok(k.to_string())
}

/// Keys are visible ASCII. Anything else (an Escape from a terminal, a space, a
/// full-width character) would fail as "failed to parse header value" on every call.
pub fn check_key(k: &str) -> Result<(), String> {
    match k.chars().find(|c| !('!'..='~').contains(c)) {
        None => Ok(()),
        Some(c) => Err(format!(
            "the key contains {} (U+{:04X}), which an API key never has — it was likely mistyped or mangled by a terminal paste",
            if c.is_control() { "a control character" } else if c.is_whitespace() { "whitespace" } else { "a non-ASCII character" },
            c as u32
        )),
    }
}

pub trait CredSource: Send + Sync {
    fn get(&self) -> Result<Cred, ProviderError>;
    /// The last request was rejected (401): drop caches / force a refresh. True when a
    /// retry with a fresh credential makes sense.
    fn invalidate(&self) -> bool {
        false
    }
    fn describe(&self) -> String;
}

pub struct Static {
    key: Option<String>,
}

impl Static {
    pub fn new(key: Option<String>) -> Static {
        Static { key }
    }
}

impl CredSource for Static {
    fn get(&self) -> Result<Cred, ProviderError> {
        Ok(Cred {
            token: self.key.clone(),
            ..Default::default()
        })
    }
    fn describe(&self) -> String {
        match &self.key {
            Some(k) => format!("key {}", crate::store::mask(k)),
            None => "no key".into(),
        }
    }
}

// ───────────────────────── key_cmd ─────────────────────────

/// Treat a minted token as spent this long before its expiry.
const LEEWAY_MS: u64 = 60_000;
/// No advertised expiry: re-mint after this long (a 401 also re-mints).
const NO_TTL_MS: u64 = 900_000;
const MINT_TIMEOUT: Duration = Duration::from_secs(15);

/// Runs a command that prints a short-lived key (`apiKeyHelper` / `gcloud auth
/// print-access-token` idiom): bare token, or JSON with `access_token`/`token`/`key`
/// and `expires_in` (seconds) or `expires_at`/`expiry` (epoch or RFC 3339).
pub struct KeyCmd {
    cmd: String,
    cache: Mutex<Option<(String, u64)>>,
}

impl KeyCmd {
    pub fn new(cmd: &str) -> KeyCmd {
        KeyCmd {
            cmd: cmd.to_string(),
            cache: Mutex::new(None),
        }
    }
}

/// Parse key_cmd output into (token, expiry ms).
pub fn parse_minted(out: &str, now: u64) -> Result<(String, u64), String> {
    let t = out.trim();
    if t.is_empty() {
        return Err("key_cmd printed nothing".into());
    }
    if t.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(t).map_err(|e| format!("key_cmd printed invalid JSON: {e}"))?;
        let tok = ["access_token", "token", "key", "api_key"]
            .iter()
            .find_map(|k| v[*k].as_str())
            .ok_or("key_cmd JSON has no access_token")?;
        let exp = if let Some(s) = v["expires_in"].as_f64() {
            now + (s * 1000.0) as u64
        } else if let Some(e) = v
            .get("expires_at")
            .or_else(|| v.get("expiry"))
            .or_else(|| v.get("expiration"))
        {
            match (e.as_f64(), e.as_str()) {
                (Some(n), _) if n > 1e12 => n as u64,
                (Some(n), _) => (n * 1000.0) as u64,
                (_, Some(s)) => crate::ratelimit::parse_rfc3339(s).unwrap_or(now + NO_TTL_MS),
                _ => now + NO_TTL_MS,
            }
        } else {
            now + NO_TTL_MS
        };
        return Ok((tok.trim().to_string(), exp));
    }
    if t.lines().count() > 1 {
        return Err("key_cmd must print only the token".into());
    }
    Ok((t.to_string(), now + NO_TTL_MS))
}

pub fn run_capture(cmd: &str, timeout: Duration) -> Result<String, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run `{cmd}`: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let mut out = String::new();
                let mut err = String::new();
                child.stdout.take().map(|mut s| s.read_to_string(&mut out));
                child.stderr.take().map(|mut s| s.read_to_string(&mut err));
                if !status.success() {
                    return Err(format!(
                        "`{cmd}` exited with {status}: {}",
                        err.trim().chars().take(300).collect::<String>()
                    ));
                }
                return Ok(out);
            }
            None if start.elapsed() > timeout => {
                let _ = child.kill();
                return Err(format!("`{cmd}` timed out after {}s", timeout.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

impl CredSource for KeyCmd {
    fn get(&self) -> Result<Cred, ProviderError> {
        let now = crate::ratelimit::now_ms();
        if let Some((t, exp)) = self.cache.lock().unwrap().as_ref() {
            if now + LEEWAY_MS < *exp {
                return Ok(Cred::token(t.clone()));
            }
        }
        let out = run_capture(&self.cmd, MINT_TIMEOUT)
            .map_err(|e| ProviderError::new(K::Auth, format!("key_cmd: {e}")))?;
        let (t, exp) = parse_minted(&out, now).map_err(|e| ProviderError::new(K::Auth, e))?;
        *self.cache.lock().unwrap() = Some((t.clone(), exp));
        Ok(Cred::token(t))
    }
    fn invalidate(&self) -> bool {
        self.cache.lock().unwrap().take().is_some()
    }
    fn describe(&self) -> String {
        format!("key_cmd `{}`", self.cmd)
    }
}

// ───────────────────────── stored logins ─────────────────────────

/// A credential kept in the store: API key, long-lived token, or OAuth login that is
/// refreshed through its flow shortly before it expires (and after a 401).
pub struct Stored {
    pub store: Store,
    pub provider: String,
    pub id: String,
    /// Copilot: the stored GitHub token is exchanged for a short-lived API token.
    exchange: Option<crate::copilot::Exchange>,
}

impl Stored {
    pub fn new(store: Store, provider: &str, id: &str, copilot: bool) -> Stored {
        Stored {
            store,
            provider: provider.to_string(),
            id: id.to_string(),
            exchange: copilot.then(crate::copilot::Exchange::new),
        }
    }
    fn entry(&self) -> Result<Entry, ProviderError> {
        self.store.entry(&self.provider, &self.id).ok_or_else(|| {
            ProviderError::new(
                K::Auth,
                format!(
                    "credential {} for {} was removed (see `seagent auth list {}`)",
                    self.id, self.provider, self.provider
                ),
            )
        })
    }
    fn refresh(&self, e: &Entry) -> Result<Entry, ProviderError> {
        let flow = e
            .flow
            .as_deref()
            .and_then(crate::login::flow)
            .ok_or_else(|| {
                ProviderError::new(
                    K::Auth,
                    format!(
                        "{}: login expired and cannot be refreshed; run `seagent login {}`",
                        self.provider, self.provider
                    ),
                )
            })?;
        match crate::login::refresh(&flow, e) {
            Ok(n) => {
                let n2 = n.clone();
                let _ = self.store.modify(&self.provider, &self.id, move |x| {
                    x.key = n2.key;
                    x.refresh = n2.refresh.or(x.refresh.take());
                    x.expires_at_ms = n2.expires_at_ms;
                    x.base_url = n2.base_url.or(x.base_url.take());
                    x.extra.extend(n2.extra);
                    if x.status == "dead" {
                        x.status.clear();
                    }
                });
                Ok(n)
            }
            Err(err) => {
                let terminal = crate::login::is_terminal(&err);
                let msg = err.clone();
                let _ = self.store.modify(&self.provider, &self.id, move |x| {
                    x.last_error = Some(msg.chars().take(300).collect());
                    if terminal {
                        x.status = "dead".into();
                    }
                });
                Err(ProviderError::new(
                    K::Auth,
                    format!(
                        "{}: token refresh failed: {err}; run `seagent login {}`",
                        self.provider, self.provider
                    ),
                ))
            }
        }
    }
}

impl CredSource for Stored {
    fn get(&self) -> Result<Cred, ProviderError> {
        let mut e = self.entry()?;
        let now = crate::ratelimit::now_ms();
        let skew = e
            .flow
            .as_deref()
            .and_then(crate::login::flow)
            .map(|f| f.refresh_skew_ms)
            .unwrap_or(120_000);
        if e.kind == "oauth"
            && e.refresh.is_some()
            && e.expires_at_ms.is_some_and(|x| now + skew >= x)
        {
            e = self.refresh(&e)?;
        }
        if e.flow.as_deref() == Some("nous") {
            // Nous Portal: the access token is the NAS invoke JWT. Keep the `agent_key` slots
            // current, and redeem the refresh token once when the JWT lost its
            // `inference:invoke` scope or its TTL — a refreshed pair brings a fresh one.
            crate::nous::derive_agent_key(&mut e);
            if crate::nous::agent_key_status(&e, crate::nous::MIN_TTL_SECS).is_some()
                && e.refresh.is_some()
            {
                e = self.refresh(&e)?;
                crate::nous::derive_agent_key(&mut e);
            }
            if crate::nous::agent_key_status(&e, crate::nous::MIN_TTL_SECS).is_some() {
                return Err(ProviderError::new(K::Auth, format!("{}: {}", self.provider, crate::nous::auth_error(&e))));
            }
        }
        if e.kind == "oauth" && e.refresh.is_none() && e.expires_at_ms.is_some_and(|x| now >= x) {
            return Err(ProviderError::new(
                K::Auth,
                format!(
                    "{}: login expired; run `seagent login {}`",
                    self.provider, self.provider
                ),
            ));
        }
        let key = e.key.clone().filter(|k| !k.is_empty()).ok_or_else(|| {
            ProviderError::new(
                K::Auth,
                format!(
                    "{}: stored credential {} has no key",
                    self.provider, e.label
                ),
            )
        })?;
        if let Some(x) = &self.exchange {
            return x.get(&key, e.base_url.as_deref());
        }
        Ok(crate::login::cred_for(&e, key))
    }
    fn invalidate(&self) -> bool {
        if let Some(x) = &self.exchange {
            x.clear();
            return true;
        }
        match self.entry() {
            Ok(e) if e.kind == "oauth" && e.refresh.is_some() => self.refresh(&e).is_ok(),
            _ => false,
        }
    }
    fn describe(&self) -> String {
        match self.entry() {
            Ok(e) => format!("{} `{}` ({})", e.kind, e.label, e.masked()),
            Err(_) => format!("stored {}", self.id),
        }
    }
}

// ───────────────────────── resolution ─────────────────────────

fn from_env(names: &[String]) -> Option<String> {
    names.iter().find_map(|n| {
        std::env::var(n)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// The single credential `cfg` names (config key, env, key_cmd, cloud identity). Pools
/// and stored logins are assembled by the resolver on top of this.
pub fn source_for(
    cfg: &ProviderConfig,
    vault: Option<&dyn Fn(&str) -> Option<String>>,
) -> Result<Arc<dyn CredSource>, String> {
    match cfg.auth.as_str() {
        "none" | "aws" => return Ok(Arc::new(Static::new(None))),
        "google" => return Ok(Arc::new(crate::google::TokenSource::from_env(cfg)?)),
        "azure-ad" => return Ok(Arc::new(AzureAd::from_env()?)),
        "copilot" => {
            let gh = from_env(&cfg.key_env_names()).or_else(|| cfg.api_key.clone()).or_else(crate::copilot::cli_token).ok_or_else(|| format!("provider `{}`: no GitHub token — run `seagent login github-copilot` or set $COPILOT_GITHUB_TOKEN", cfg.id))?;
            return Ok(Arc::new(crate::copilot::FromToken::new(gh)));
        }
        _ => {}
    }
    if let Some(c) = cfg.key_cmd.as_deref().filter(|c| !c.trim().is_empty()) {
        return Ok(Arc::new(KeyCmd::new(c)));
    }
    if let Some(k) = cfg.api_key.clone().filter(|k| !k.is_empty()) {
        return Ok(Arc::new(Static::new(Some(k))));
    }
    if let Some(k) = cfg.api_keys.first() {
        return Ok(Arc::new(Static::new(Some(k.clone()))));
    }
    let names = cfg.key_env_names();
    if let Some(k) = from_env(&names) {
        return Ok(Arc::new(Static::new(Some(k))));
    }
    if let Some(v) = vault {
        if let Some(k) = names.iter().find_map(|n| v(n)) {
            return Ok(Arc::new(Static::new(Some(k))));
        }
    }
    if cfg.has_quirk("optional_key") {
        return Ok(Arc::new(Static::new(None)));
    }
    if cfg.oauth.is_some() {
        return Err(format!(
            "provider `{}`: not logged in — run `seagent login {}`",
            cfg.id,
            cfg.oauth.as_deref().unwrap_or(&cfg.id)
        ));
    }
    match names.first() {
        Some(_) => Err(missing_key_message(cfg)),
        None => Ok(Arc::new(Static::new(None))),
    }
}

/// The error a missing API key deserves: the exact variable, the agent profile
/// (when `$SEAGENT_AGENT` scopes the store), and the command that sets it — not a
/// misleading 401 after a request with an empty key.
pub fn missing_key_message(cfg: &ProviderConfig) -> String {
    let names = cfg.key_env_names();
    let env = names.first().map(String::as_str).unwrap_or("the provider key");
    let alts = if names.len() > 1 {
        format!(" (or {})", names[1..].iter().map(|n| format!("${n}")).collect::<Vec<_>>().join(", "))
    } else {
        String::new()
    };
    let profile = std::env::var("SEAGENT_AGENT")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .map(|p| format!(" for agent profile `{p}`"))
        .unwrap_or_default();
    format!(
        "provider `{}`: API key missing{profile} — set ${env}{alts}, then persist it with `seagent secrets set {env}` (or run `seagent setup`)",
        cfg.id
    )
}

// ───────────────────────── Azure Entra ID ─────────────────────────

pub const AZURE_SCOPE: &str = "https://cognitiveservices.azure.com/.default";

/// Entra ID bearer for Azure OpenAI / Foundry: client credentials ($AZURE_TENANT_ID,
/// $AZURE_CLIENT_ID, $AZURE_CLIENT_SECRET) or the Azure CLI (`az account get-access-token`).
pub struct AzureAd {
    mode: AzureMode,
    cache: Mutex<Option<(String, u64)>>,
}

enum AzureMode {
    Client {
        token_url: String,
        client_id: String,
        secret: String,
    },
    Cli,
}

impl AzureAd {
    pub fn from_env() -> Result<AzureAd, String> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let mode = match (
            get("AZURE_TENANT_ID"),
            get("AZURE_CLIENT_ID"),
            get("AZURE_CLIENT_SECRET"),
        ) {
            (Some(t), Some(c), Some(s)) => AzureMode::Client {
                token_url: get("AZURE_AUTHORITY_HOST")
                    .unwrap_or_else(|| "https://login.microsoftonline.com".into())
                    .trim_end_matches('/')
                    .to_string()
                    + &format!("/{t}/oauth2/v2.0/token"),
                client_id: c,
                secret: s,
            },
            _ => AzureMode::Cli,
        };
        Ok(AzureAd {
            mode,
            cache: Mutex::new(None),
        })
    }
    #[cfg(test)]
    pub(crate) fn client(token_url: &str) -> AzureAd {
        AzureAd {
            mode: AzureMode::Client {
                token_url: token_url.into(),
                client_id: "cid".into(),
                secret: "sec".into(),
            },
            cache: Mutex::new(None),
        }
    }
}

impl CredSource for AzureAd {
    fn get(&self) -> Result<Cred, ProviderError> {
        let now = crate::ratelimit::now_ms();
        if let Some((t, exp)) = self
            .cache
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(_, e)| now + LEEWAY_MS < *e)
        {
            let _ = exp;
            return Ok(Cred::token(t.clone()));
        }
        let (tok, exp) = match &self.mode {
            AzureMode::Client {
                token_url,
                client_id,
                secret,
            } => {
                let v = crate::login::post_form(
                    token_url,
                    &[
                        ("grant_type", "client_credentials"),
                        ("client_id", client_id),
                        ("client_secret", secret),
                        ("scope", AZURE_SCOPE),
                    ],
                )
                .map_err(|e| ProviderError::new(K::Auth, format!("Entra ID: {e}")))?;
                let t = v["access_token"]
                    .as_str()
                    .ok_or_else(|| ProviderError::new(K::Auth, "Entra ID: no access_token"))?
                    .to_string();
                (t, now + v["expires_in"].as_u64().unwrap_or(3600) * 1000)
            }
            AzureMode::Cli => {
                let out = run_capture("az account get-access-token --resource https://cognitiveservices.azure.com --output json", Duration::from_secs(30)).map_err(|e| ProviderError::new(K::Auth, format!("Entra ID via Azure CLI: {e} (or set AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET)")))?;
                let v: serde_json::Value = serde_json::from_str(&out)
                    .map_err(|e| ProviderError::new(K::Auth, format!("az output: {e}")))?;
                let t = v["accessToken"]
                    .as_str()
                    .ok_or_else(|| ProviderError::new(K::Auth, "az: no accessToken"))?
                    .to_string();
                let exp = v["expires_on"]
                    .as_u64()
                    .map(|s| s * 1000)
                    .unwrap_or(now + 3_000_000);
                (t, exp)
            }
        };
        *self.cache.lock().unwrap() = Some((tok.clone(), exp));
        Ok(Cred::token(tok))
    }
    fn invalidate(&self) -> bool {
        self.cache.lock().unwrap().take().is_some()
    }
    fn describe(&self) -> String {
        match self.mode {
            AzureMode::Client { .. } => "Entra ID client credentials".into(),
            AzureMode::Cli => "Entra ID via Azure CLI".into(),
        }
    }
}

// ───────────────────────── 401 retry ─────────────────────────

/// Retries once with a fresh credential after a 401 (expired OAuth token, rotated key_cmd).
pub struct Reauth {
    pub inner: Arc<dyn Provider>,
    pub cred: Arc<dyn CredSource>,
}

impl Provider for Reauth {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, model: &str) -> ModelCaps {
        self.inner.caps(model)
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        match self.inner.complete(req, on_event, cancel) {
            Err(e) if e.kind == K::Auth && e.status == Some(401) && self.cred.invalidate() => {
                self.inner.complete(req, on_event, cancel)
            }
            r => r,
        }
    }
}

// ───────────────────────── credential pool ─────────────────────────

pub const TTL_401_MS: u64 = 5 * 60 * 1000;
pub const TTL_429_MS: u64 = 60 * 60 * 1000;
pub const TTL_DEFAULT_MS: u64 = 60 * 60 * 1000;
pub const TTL_SOLE_MS: u64 = 60 * 1000;

/// Cooldown for a credential that failed with `err` (Hermes `_exhausted_ttl`): 401 is
/// short (the key may just need a refresh); 429 and others an hour, honouring
/// Retry-After; a pool with nothing else to rotate to caps transient failures at 60 s.
/// Billing (402 / quota) keeps the full bench regardless.
pub fn cooldown_ms(err: &ProviderError, sole: bool) -> u64 {
    let billing = err.status == Some(402)
        || err.message.to_lowercase().contains("quota")
        || err.message.to_lowercase().contains("billing");
    if err.status == Some(401) {
        return TTL_401_MS;
    }
    let base = match &err.kind {
        K::RateLimited {
            retry_after: Some(d),
        } => (d.as_millis() as u64).clamp(1000, TTL_429_MS),
        K::RateLimited { .. } => TTL_429_MS,
        _ => TTL_DEFAULT_MS,
    };
    if sole && !billing {
        base.min(TTL_SOLE_MS)
    } else {
        base
    }
}

/// Whether an error is the credential's fault (rotate) rather than the request's.
pub fn rotates_on(err: &ProviderError) -> bool {
    matches!(err.kind, K::RateLimited { .. } | K::Auth)
}

#[derive(Clone)]
pub struct Member {
    /// Store entry id, or `config`/`env` for credentials that live outside the store.
    pub key: String,
    pub label: String,
    pub provider: Arc<dyn Provider>,
}

#[derive(Default, Clone)]
struct MemState {
    until: u64,
    models: std::collections::HashMap<String, u64>,
    uses: u64,
}

pub struct Pool {
    id: String,
    members: Vec<Member>,
    strategy: String,
    store: Option<Store>,
    state: Mutex<(Vec<MemState>, usize)>,
}

pub const STRATEGIES: &[&str] = &["fill_first", "round_robin", "random", "least_used"];

impl Pool {
    pub fn new(id: &str, members: Vec<Member>, strategy: &str, store: Option<Store>) -> Pool {
        let strategy = if STRATEGIES.contains(&strategy) {
            strategy
        } else {
            "fill_first"
        };
        let n = members.len();
        Pool {
            id: id.to_string(),
            members,
            strategy: strategy.to_string(),
            store,
            state: Mutex::new((vec![MemState::default(); n], 0)),
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Indices usable for `model` right now, in strategy order.
    fn order(&self, model: &str) -> (Vec<usize>, Option<u64>) {
        let now = crate::ratelimit::now_ms();
        let stored = self
            .store
            .as_ref()
            .map(|s| s.entries(&self.id))
            .unwrap_or_default();
        let st = self.state.lock().unwrap();
        let mut soonest: Option<u64> = None;
        let mut ok: Vec<usize> = Vec::new();
        for (i, m) in self.members.iter().enumerate() {
            let mut until = st.0[i]
                .until
                .max(st.0[i].models.get(model).copied().unwrap_or(0));
            if let Some(e) = stored.iter().find(|e| e.id == m.key) {
                if let Some(u) = e.blocked(Some(model), now) {
                    until = until.max(u);
                }
            }
            if until > now {
                soonest = Some(soonest.map_or(until, |s: u64| s.min(until)));
            } else {
                ok.push(i);
            }
        }
        match self.strategy.as_str() {
            "round_robin" if !ok.is_empty() => {
                let start = st.1 % self.members.len();
                ok.sort_by_key(|i| (*i + self.members.len() - start) % self.members.len());
            }
            "least_used" => ok.sort_by_key(|i| st.0[*i].uses),
            "random" if ok.len() > 1 => {
                let r = seagent_net::crypto::random_bytes(1)[0] as usize % ok.len();
                ok.rotate_left(r);
            }
            _ => {}
        }
        (ok, soonest)
    }

    fn mark(&self, i: usize, model: &str, err: &ProviderError) {
        let sole = self.members.len() == 1;
        let until = crate::ratelimit::now_ms() + cooldown_ms(err, sole);
        // Rate limits are per model; auth/billing failures bench the whole key.
        let model_scoped = matches!(err.kind, K::RateLimited { .. });
        {
            let mut st = self.state.lock().unwrap();
            if model_scoped {
                st.0[i].models.insert(model.to_string(), until);
            } else {
                st.0[i].until = until;
            }
        }
        if let Some(s) = &self.store {
            let (msg, m) = (err.to_string(), model.to_string());
            let _ = s.modify(&self.id, &self.members[i].key, move |e| {
                if model_scoped {
                    e.model_cooldowns.insert(m, until);
                } else {
                    e.status = "exhausted".into();
                    e.exhausted_until_ms = Some(until);
                }
                e.last_error = Some(msg.chars().take(300).collect());
            });
        }
    }

    fn used(&self, i: usize) {
        {
            let mut st = self.state.lock().unwrap();
            st.0[i].uses += 1;
            st.1 = i + 1;
        }
        if let Some(s) = &self.store {
            let _ = s.modify(&self.id, &self.members[i].key, |e| e.request_count += 1);
        }
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }
}

impl Provider for Pool {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        self.members
            .first()
            .map(|m| m.provider.caps(model))
            .unwrap_or_else(|| crate::caps_for(model))
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let (order, soonest) = self.order(&req.model);
        if order.is_empty() {
            let wait = soonest
                .map(|u| Duration::from_millis(u.saturating_sub(crate::ratelimit::now_ms())));
            return Err(ProviderError::new(K::RateLimited { retry_after: wait }, format!("{}: every pooled credential is cooling down (see `seagent auth list {}`; `seagent auth reset {}` clears)", self.id, self.id, self.id)));
        }
        let mut last = None;
        for i in order {
            self.used(i);
            match self.members[i].provider.complete(req, on_event, cancel) {
                Err(e) if rotates_on(&e) => {
                    self.mark(i, &req.model, &e);
                    last = Some(e);
                }
                r => return r,
            }
        }
        Err(last.unwrap_or_else(|| ProviderError::new(K::Auth, "no credential")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{Message, Role, StopReason, Usage};

    #[test]
    fn a_pasted_key_loses_paste_markers_and_a_mangled_one_is_refused() {
        assert_eq!(clean_key("\x1b[200~sk-abc123\x1b[201~\n").unwrap(), "sk-abc123");
        assert_eq!(clean_key("  sk-abc123 \r\n").unwrap(), "sk-abc123");
        for bad in ["\x1b", "sk-ab c", "sk-ａｂｃ", "sk-\x7fx"] {
            assert!(clean_key(bad).is_err(), "{bad:?} accepted");
        }
        let e = crate::usable_key("deepseek", &Cred::token("\x1b")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.is_retryable());
        assert!(e.message.contains("control character") && e.message.contains("seagent setup"), "{}", e.message);
        assert!(crate::usable_key("deepseek", &Cred::token("sk-ok")).is_ok());
        assert!(crate::usable_key("local", &Cred::default()).is_ok());
    }

    struct Fake {
        fail: Mutex<Vec<Option<ProviderError>>>,
        calls: Mutex<u32>,
    }
    impl Provider for Fake {
        fn id(&self) -> &str {
            "f"
        }
        fn caps(&self, m: &str) -> ModelCaps {
            crate::caps_for(m)
        }
        fn complete(
            &self,
            req: &ModelRequest,
            _: &mut dyn FnMut(StreamEvent),
            _: &Cancel,
        ) -> Result<ModelResponse, ProviderError> {
            *self.calls.lock().unwrap() += 1;
            let mut f = self.fail.lock().unwrap();
            match if f.is_empty() { None } else { f.remove(0) } {
                Some(e) => Err(e),
                None => Ok(ModelResponse {
                    message: Message {
                        role: Role::Assistant,
                        content: vec![seagent_core::Block::text("ok")],
                    },
                    stop: StopReason::EndTurn,
                    usage: Usage::default(),
                    model: req.model.clone(),
                }),
            }
        }
    }
    fn fake(fails: Vec<Option<ProviderError>>) -> Arc<Fake> {
        Arc::new(Fake {
            fail: Mutex::new(fails),
            calls: Mutex::new(0),
        })
    }
    fn req(m: &str) -> ModelRequest {
        ModelRequest {
            model: m.into(),
            messages: vec![Message::user("hi")],
            max_tokens: 10,
            ..Default::default()
        }
    }
    fn e429() -> ProviderError {
        ProviderError::new(K::RateLimited { retry_after: None }, "slow down").with_status(429)
    }
    fn e401() -> ProviderError {
        ProviderError::new(K::Auth, "bad key").with_status(401)
    }

    #[test]
    fn rotates_on_429_and_cools_model_only() {
        let a = fake(vec![Some(e429())]);
        let b = fake(vec![]);
        let p = Pool::new(
            "x",
            vec![
                Member {
                    key: "a".into(),
                    label: "a".into(),
                    provider: a.clone(),
                },
                Member {
                    key: "b".into(),
                    label: "b".into(),
                    provider: b.clone(),
                },
            ],
            "fill_first",
            None,
        );
        let c = Cancel::new();
        assert!(p.complete(&req("m1"), &mut |_| {}, &c).is_ok());
        assert_eq!((*a.calls.lock().unwrap(), *b.calls.lock().unwrap()), (1, 1));
        // a is cooling for m1 only: m1 goes straight to b, m2 still tries a first.
        p.complete(&req("m1"), &mut |_| {}, &c).unwrap();
        assert_eq!(*a.calls.lock().unwrap(), 1);
        p.complete(&req("m2"), &mut |_| {}, &c).unwrap();
        assert_eq!(*a.calls.lock().unwrap(), 2);
    }

    #[test]
    fn auth_failure_benches_whole_key_and_all_cooling_reports_wait() {
        let a = fake(vec![Some(e401())]);
        let p = Pool::new(
            "x",
            vec![Member {
                key: "a".into(),
                label: "a".into(),
                provider: a.clone(),
            }],
            "fill_first",
            None,
        );
        let c = Cancel::new();
        let e = p.complete(&req("m"), &mut |_| {}, &c).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        let e = p.complete(&req("other"), &mut |_| {}, &c).unwrap_err();
        assert!(
            matches!(
                e.kind,
                K::RateLimited {
                    retry_after: Some(_)
                }
            ),
            "{e}"
        );
        assert!(e.message.contains("cooling down"));
    }

    #[test]
    fn non_credential_errors_do_not_rotate() {
        let a = fake(vec![Some(ProviderError::new(K::BadRequest, "bad"))]);
        let b = fake(vec![]);
        let p = Pool::new(
            "x",
            vec![
                Member {
                    key: "a".into(),
                    label: "a".into(),
                    provider: a,
                },
                Member {
                    key: "b".into(),
                    label: "b".into(),
                    provider: b.clone(),
                },
            ],
            "fill_first",
            None,
        );
        assert_eq!(
            p.complete(&req("m"), &mut |_| {}, &Cancel::new())
                .unwrap_err()
                .kind,
            K::BadRequest
        );
        assert_eq!(*b.calls.lock().unwrap(), 0);
    }

    #[test]
    fn round_robin_and_least_used_spread_load() {
        let a = fake(vec![]);
        let b = fake(vec![]);
        let p = Pool::new(
            "x",
            vec![
                Member {
                    key: "a".into(),
                    label: "a".into(),
                    provider: a.clone(),
                },
                Member {
                    key: "b".into(),
                    label: "b".into(),
                    provider: b.clone(),
                },
            ],
            "round_robin",
            None,
        );
        for _ in 0..4 {
            p.complete(&req("m"), &mut |_| {}, &Cancel::new()).unwrap();
        }
        assert_eq!((*a.calls.lock().unwrap(), *b.calls.lock().unwrap()), (2, 2));
        let a = fake(vec![]);
        let b = fake(vec![]);
        let p = Pool::new(
            "x",
            vec![
                Member {
                    key: "a".into(),
                    label: "a".into(),
                    provider: a.clone(),
                },
                Member {
                    key: "b".into(),
                    label: "b".into(),
                    provider: b.clone(),
                },
            ],
            "least_used",
            None,
        );
        for _ in 0..4 {
            p.complete(&req("m"), &mut |_| {}, &Cancel::new()).unwrap();
        }
        assert_eq!((*a.calls.lock().unwrap(), *b.calls.lock().unwrap()), (2, 2));
    }

    #[test]
    fn cooldowns_persist_to_store_and_reset_clears() {
        let s = crate::store::temp_store("pool");
        let id = s
            .add("x", Entry::new("api_key", "k1", Some("sk-1".into())), None)
            .unwrap();
        let a = fake(vec![Some(e401())]);
        let p = Pool::new(
            "x",
            vec![Member {
                key: id.clone(),
                label: "k1".into(),
                provider: a.clone(),
            }],
            "fill_first",
            Some(s.clone()),
        );
        let _ = p.complete(&req("m"), &mut |_| {}, &Cancel::new());
        let e = s.entry("x", &id).unwrap();
        assert_eq!(e.status, "exhausted");
        assert_eq!(e.request_count, 1);
        assert!(e.last_error.unwrap().contains("bad key"));
        // A fresh pool (another process) sees the cooldown through the store…
        let a2 = fake(vec![]);
        let p2 = Pool::new(
            "x",
            vec![Member {
                key: id.clone(),
                label: "k1".into(),
                provider: a2.clone(),
            }],
            "fill_first",
            Some(s.clone()),
        );
        assert!(p2.complete(&req("m"), &mut |_| {}, &Cancel::new()).is_err());
        // …until `seagent auth reset`.
        s.reset("x", None).unwrap();
        assert!(p2.complete(&req("m"), &mut |_| {}, &Cancel::new()).is_ok());
    }

    #[test]
    fn cooldown_rules() {
        assert_eq!(cooldown_ms(&e401(), false), TTL_401_MS);
        assert_eq!(cooldown_ms(&e429(), false), TTL_429_MS);
        assert_eq!(cooldown_ms(&e429(), true), TTL_SOLE_MS);
        let ra = ProviderError::new(
            K::RateLimited {
                retry_after: Some(Duration::from_secs(7)),
            },
            "x",
        )
        .with_status(429);
        assert_eq!(cooldown_ms(&ra, false), 7000);
        let bill = ProviderError::new(K::Auth, "Insufficient Balance").with_status(402);
        assert_eq!(
            cooldown_ms(&bill, true),
            TTL_DEFAULT_MS,
            "billing keeps the full bench"
        );
    }

    #[test]
    fn key_cmd_parsing_and_caching() {
        assert_eq!(
            parse_minted("tok123\n", 0).unwrap(),
            ("tok123".into(), NO_TTL_MS)
        );
        assert_eq!(
            parse_minted(r#"{"access_token":"a","expires_in":60}"#, 1000).unwrap(),
            ("a".into(), 61_000)
        );
        assert_eq!(
            parse_minted(r#"{"token":"b","expires_at":"1970-01-01T00:01:00Z"}"#, 0)
                .unwrap()
                .1,
            60_000
        );
        assert!(parse_minted("", 0).is_err());
        assert!(parse_minted("a\nb", 0).is_err());
        let dir = seagent_core::tmp::scratch_path(format!("seagent-keycmd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let counter = dir.join("n");
        let k = KeyCmd::new(&format!(
            "echo x >> {0}; echo minted-$(wc -l < {0})",
            counter.display()
        ));
        assert_eq!(k.get().unwrap().token.unwrap(), "minted-1");
        assert_eq!(k.get().unwrap().token.unwrap(), "minted-1", "cached");
        assert!(k.invalidate());
        assert_eq!(k.get().unwrap().token.unwrap(), "minted-2");
        let bad = KeyCmd::new("exit 3");
        assert_eq!(bad.get().unwrap_err().kind, K::Auth);
    }

    #[test]
    fn source_precedence() {
        std::env::set_var("SEAGENT_T_SRC_A", "from-env");
        let mut c = ProviderConfig {
            id: "p".into(),
            api_key_env: Some("SEAGENT_T_SRC_UNSET".into()),
            key_envs: vec!["SEAGENT_T_SRC_A".into()],
            ..Default::default()
        };
        assert_eq!(
            source_for(&c, None).unwrap().get().unwrap().token.unwrap(),
            "from-env"
        );
        c.api_key = Some("cfg".into());
        assert_eq!(
            source_for(&c, None).unwrap().get().unwrap().token.unwrap(),
            "cfg"
        );
        c.key_cmd = Some("echo cmd".into());
        assert_eq!(
            source_for(&c, None).unwrap().get().unwrap().token.unwrap(),
            "cmd"
        );
        let c = ProviderConfig {
            id: "p".into(),
            api_key_env: Some("SEAGENT_T_SRC_UNSET".into()),
            ..Default::default()
        };
        let vault = |n: &str| (n == "SEAGENT_T_SRC_UNSET").then(|| "vaulted".to_string());
        assert_eq!(
            source_for(&c, Some(&vault))
                .unwrap()
                .get()
                .unwrap()
                .token
                .unwrap(),
            "vaulted"
        );
        let c = ProviderConfig {
            id: "p".into(),
            oauth: Some("openai-codex".into()),
            ..Default::default()
        };
        assert!(source_for(&c, None).err().unwrap().contains("seagent login"));

        let c = ProviderConfig {
            id: "deepseek".into(),
            api_key_env: Some("SEAGENT_T_SRC_MISSING_KEY".into()),
            key_envs: vec!["SEAGENT_T_SRC_MISSING_ALT".into()],
            ..Default::default()
        };
        let e = missing_key_message(&c);
        assert!(e.contains("$SEAGENT_T_SRC_MISSING_KEY"), "{e}");
        assert!(e.contains("$SEAGENT_T_SRC_MISSING_ALT"), "{e}");
        assert!(e.contains("`seagent secrets set SEAGENT_T_SRC_MISSING_KEY`"), "{e}");
        assert!(e.contains("`seagent setup`"), "{e}");
        assert_eq!(source_for(&c, None).err().unwrap(), e, "the chain reports the same actionable message");
    }

    #[test]
    fn azure_client_credentials() {
        let srv = crate::login::tests::fake_server(vec![(
            200,
            r#"{"access_token":"aad-tok","expires_in":3600}"#.into(),
        )]);
        let a = AzureAd::client(&format!("{}/tenant/oauth2/v2.0/token", srv.base));
        assert_eq!(a.get().unwrap().token.unwrap(), "aad-tok");
        assert_eq!(
            a.get().unwrap().token.unwrap(),
            "aad-tok",
            "cached, one request"
        );
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].1.contains("grant_type=client_credentials")
                && reqs[0].1.contains("cognitiveservices")
        );
    }
}
