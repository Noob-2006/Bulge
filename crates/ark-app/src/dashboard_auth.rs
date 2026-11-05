//! Dashboard login (`[app.auth]`): the two built-in providers plus the HTTP surface.
//!
//! Hermes ships this as the bundled `plugins/dashboard_auth/` set — `basic` (a local
//! username/password list) and `self_hosted` (a generic OIDC relying party) — behind
//! `PluginContext.register_dashboard_auth_provider` and the `hermes_cli/dashboard_auth.py` ABC;
//! `nous` and `drain` talk to Hermes' own hosted OAuth services and have no ark counterpart (a
//! plugin may register a provider instead — see [`ark_plugin::dashboard_auth`]).
//!
//! ark keeps the upstream semantics:
//!
//! * login is **off by default** (`enabled = false`): the app token stays the only credential;
//! * a provider is used only when `[app.auth] provider` names it, and a provider that cannot be
//!   configured is skipped with an operator-facing reason (upstream `SkipRegistration`) instead
//!   of crashing the gate — the browser gets a 503 that quotes the reason, never a panic;
//! * the OAuth leg is authorization-code + **PKCE (S256)** with a `state` kept server-side
//!   (10 min TTL, 256 entries, oldest dropped);
//! * the token-endpoint exchange has a **10 s** timeout, asks for JSON (`Accept:
//!   application/json`), refuses non-bearer token types and never follows redirects (the body
//!   carries an auth code);
//! * the ID token is verified against a JWKS (RS256/384/512, ES256/384; `HS*` and `none`
//!   refused) with `exp`/`nbf`/`iat` checks and a **60 s** clock-skew leeway applied
//!   symmetrically (`crate::cron_fire::verify_with`, the same verifier the cron mount uses);
//! * the JWKS is cached and refetched on an unknown `kid` at most every 30 s
//!   ([`crate::cron_fire::Keys`]);
//! * failures are classified — an unreachable IDP is a 503, a rejected code/token a 400 — and
//!   the browser only ever sees `login failed`, never which check failed.
//!
//! The session cookie is ours, not the provider's: `base64url(claims).hex(HMAC-SHA256(secret,
//! base64url(claims)))` with `sub`, `email`, `name`, `admin` and `exp`, so a session survives a
//! provider outage and a tampered cookie is worth nothing.
//!
//! ```toml
//! [app.auth]
//! enabled = false              # off by default: the app token stays the only credential
//! provider = "basic"           # basic | self_hosted | <plugin provider id>
//! cookie = "ark_session"
//! session_ttl_secs = 43200
//! secret = "{{secret:APP_AUTH_SECRET}}"   # HMAC key for session cookies; required when enabled
//! [app.auth.basic.users]                   # user = password ({{secret:…}} substituted upstream)
//! alice = "hunter2"
//! [app.auth.self_hosted]
//! issuer = "https://id.example.test"
//! authorization_endpoint = "https://id.example.test/authorize"
//! token_endpoint = "https://id.example.test/token"
//! jwks = "https://id.example.test/.well-known/jwks.json"   # or inline JSON
//! client_id = "ark"
//! client_secret = ""           # empty = public client with PKCE
//! audience = "ark"             # optional; defaults to client_id
//! scopes = "openid profile email"
//! redirect_uri = ""            # default: the request's own origin + /auth/callback
//! ```
//!
//! Routes (served **without** the app token — they are the login): `GET /auth/login`,
//! `POST /auth/login` (form `user`/`password`), `GET /auth/callback?code&state`,
//! `GET|POST /auth/logout`, `GET /auth/whoami`.

use crate::cron_fire::Keys;
use crate::identity::{self, Role};
use crate::server::App;
use ark_net::httpd::{Request, Response};
use ark_net::{crypto, form_encode, parse_query};
use ark_plugin::dashboard_auth::{self as providers, LoginStart, Provider, Session};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Clock-skew leeway for the ID token's `exp`/`nbf`/`iat` (Hermes `DEFAULT_TOKEN_LEEWAY_SECONDS`).
pub const LEEWAY_SECS: i64 = 60;
/// Shortest session signing key we accept (upstream `len(secret) < 16` → skip registration).
pub const SECRET_MIN_LEN: usize = 16;
/// Token-endpoint budget (upstream `TOKEN_ENDPOINT_TIMEOUT_SEC`).
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a `state` may wait for its callback, and how many may wait at once.
const PKCE_TTL: Duration = Duration::from_secs(600);
const PKCE_MAX: usize = 256;
/// The one message a failed password login ever gets (upstream: no username oracle).
const INVALID_CREDENTIALS: &str = "invalid username or password";
/// The one message a failed OAuth callback ever gets.
const LOGIN_FAILED: &str = "login failed";
const DEFAULT_SCOPES: &str = "openid profile email";

// ─── config ─────────────────────────────────────────────────────────────────

/// `[app.auth]` — the dashboard login gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Off by default: the app token is the only credential.
    pub enabled: bool,
    /// `basic`, `self_hosted` or a plugin provider id.
    pub provider: String,
    /// Session cookie name.
    pub cookie: String,
    /// Lifetime of the session cookie (and of the signed session token).
    pub session_ttl_secs: i64,
    /// HMAC key for session tokens. Required when `enabled`.
    pub secret: String,
    pub basic: BasicConfig,
    pub self_hosted: SelfHostedConfig,
    /// `[app.auth.saml]` (ent-048), used with `provider = "saml"`.
    pub saml: crate::saml::SamlConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            enabled: false,
            provider: "basic".into(),
            cookie: "ark_session".into(),
            session_ttl_secs: 43_200,
            secret: String::new(),
            basic: BasicConfig::default(),
            self_hosted: SelfHostedConfig::default(),
            saml: crate::saml::SamlConfig::default(),
        }
    }
}

impl AuthConfig {
    /// The cookie name (never empty).
    pub fn cookie_name(&self) -> &str {
        let c = self.cookie.trim();
        if c.is_empty() {
            "ark_session"
        } else {
            c
        }
    }
    /// The session lifetime, never shorter than a minute (upstream `max(60, ttl)`).
    pub fn ttl(&self) -> i64 {
        self.session_ttl_secs.max(60)
    }
}

/// `[app.auth.basic]` — the local user list (`user = password`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BasicConfig {
    pub users: BTreeMap<String, String>,
}

/// `[app.auth.self_hosted]` — a generic OIDC relying party (Authentik, Keycloak, Zitadel, …).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SelfHostedConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// A JWKS URL, or the document itself (inline JSON starting with `{`).
    pub jwks: String,
    pub client_id: String,
    /// Empty = public client: PKCE only.
    pub client_secret: String,
    /// Checked against `aud` when set; defaults to `client_id`.
    pub audience: String,
    pub scopes: String,
    /// Empty = the request's own origin + `/auth/callback`.
    pub redirect_uri: String,
}

impl Default for SelfHostedConfig {
    fn default() -> Self {
        SelfHostedConfig {
            issuer: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            audience: String::new(),
            scopes: DEFAULT_SCOPES.into(),
            redirect_uri: String::new(),
        }
    }
}

impl SelfHostedConfig {
    fn scopes(&self) -> &str {
        let s = self.scopes.trim();
        if s.is_empty() {
            DEFAULT_SCOPES
        } else {
            s
        }
    }
}

// ─── session tokens (base64url(claims) "." hex(HMAC-SHA256(secret, claims))) ─

/// Mint a session token for `s`: `base64url(claims)` and the hex HMAC-SHA256 of that text.
pub fn mint(secret: &[u8], s: &Session, now: i64, ttl: i64) -> String {
    mint_with(secret, s, &[], "", now, ttl)
}

/// [`mint`] plus the RBAC roles and login kind (`basic`/`sso`/`plugin`) the session was
/// granted (ent-053): roles are decided once, at login, and travel signed in the token.
pub fn mint_with(secret: &[u8], s: &Session, roles: &[Role], kind: &str, now: i64, ttl: i64) -> String {
    mint_team(secret, s, roles, kind, "", now, ttl)
}

/// [`mint_with`] plus the team an IdP login was mapped to (ent-050, `[app.rbac] teams`).
#[allow(clippy::too_many_arguments)]
pub fn mint_team(secret: &[u8], s: &Session, roles: &[Role], kind: &str, team: &str, now: i64, ttl: i64) -> String {
    let mut claims = json!({"sub": s.subject, "exp": now + ttl.max(1), "admin": s.admin});
    if !team.is_empty() {
        claims["team"] = json!(team);
    }
    if !roles.is_empty() {
        claims["roles"] = json!(roles.iter().map(|r| r.as_str()).collect::<Vec<_>>());
    }
    if !kind.is_empty() {
        claims["kind"] = json!(kind);
    }
    if let Some(e) = &s.email {
        claims["email"] = json!(e);
    }
    if let Some(n) = &s.name {
        claims["name"] = json!(n);
    }
    let payload = crypto::b64url(claims.to_string().as_bytes());
    let sig = crypto::hex(&crypto::hmac_sha256(secret, payload.as_bytes()));
    format!("{payload}.{sig}")
}

/// Verify a session token: constant-time HMAC compare, then `exp`. `None` on any failure
/// (unknown shape, bad signature, expired) — the caller cannot tell which.
pub fn open(secret: &[u8], token: &str, now: i64) -> Option<Session> {
    open_with(secret, token, now).map(|(s, _, _)| s)
}

/// The team claim of a valid session token (empty when none was signed in).
pub fn open_team(secret: &[u8], token: &str, now: i64) -> String {
    if open_with(secret, token, now).is_none() {
        return String::new();
    }
    let payload = token.trim().split_once('.').map(|(p, _)| p).unwrap_or("");
    crypto::b64url_decode(payload).and_then(|raw| serde_json::from_slice::<Value>(&raw).ok()).and_then(|c| c["team"].as_str().map(str::to_string)).unwrap_or_default()
}

/// [`open`] plus the signed roles and kind (empty when the token predates them).
pub fn open_with(secret: &[u8], token: &str, now: i64) -> Option<(Session, Vec<Role>, String)> {
    let (payload, sig) = token.trim().split_once('.')?;
    if payload.is_empty() || sig.is_empty() {
        return None;
    }
    let expect = crypto::hex(&crypto::hmac_sha256(secret, payload.as_bytes()));
    if !crypto::ct_eq(sig.as_bytes(), expect.as_bytes()) {
        return None;
    }
    let raw = crypto::b64url_decode(payload)?;
    let claims: Value = serde_json::from_slice(&raw).ok()?;
    let subject = claims["sub"].as_str().map(str::trim).filter(|s| !s.is_empty())?.to_string();
    if claims["exp"].as_i64()? <= now {
        return None;
    }
    let text = |k: &str| claims[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let roles: Vec<Role> = claims["roles"].as_array().map(|a| a.iter().filter_map(|r| r.as_str().and_then(|r| Role::parse(r).ok())).collect()).unwrap_or_default();
    let kind = text("kind").unwrap_or_default();
    Some((
        Session {
            subject,
            email: text("email"),
            name: text("name"),
            expires_at: claims["exp"].as_i64(),
            admin: claims["admin"].as_bool().unwrap_or(false),
        },
        roles,
        kind,
    ))
}

// ─── built-in `basic` ───────────────────────────────────────────────────────

/// The `basic` provider: a local user list, stateless signed sessions (upstream
/// `BasicAuthProvider`). Login is a form, not an OAuth redirect.
pub struct Basic {
    users: Vec<(String, String)>,
    secret: Vec<u8>,
    ttl: i64,
}

/// Compared against when no configured user matches, so "no such user" costs the same compare
/// as "wrong password".
const NOBODY: &[u8] = b"no-such-user";

impl Basic {
    /// Build it, or return the operator-facing skip reason.
    pub fn new(cfg: &AuthConfig) -> Result<Basic, String> {
        let users: Vec<(String, String)> = cfg.basic.users.iter().filter(|(u, p)| !u.trim().is_empty() && !p.is_empty()).map(|(u, p)| (u.clone(), p.clone())).collect();
        if users.is_empty() {
            return Err("[app.auth.basic] users is empty: set `[app.auth.basic.users] alice = \"…\"` (a `{{secret:…}}` reference for real passwords) to enable dashboard login".into());
        }
        if cfg.secret.len() < SECRET_MIN_LEN {
            return Err(format!("[app.auth] secret is required when `enabled`: set `secret = \"{{{{secret:APP_AUTH_SECRET}}}}\"` (at least {SECRET_MIN_LEN} bytes — it signs the session cookie)"));
        }
        Ok(Basic { users, secret: cfg.secret.as_bytes().to_vec(), ttl: cfg.ttl() })
    }

    /// Check a username/password pair. The error is the same for an unknown user and a wrong
    /// password, and both paths do the same comparisons.
    pub fn login(&self, user: &str, password: &str) -> Result<Session, String> {
        let mut hit: Option<String> = None;
        for (name, stored) in &self.users {
            let ok_user = crypto::ct_eq(name.as_bytes(), user.as_bytes());
            let ok_pass = crypto::ct_eq(stored.as_bytes(), password.as_bytes());
            if ok_user && ok_pass && !password.is_empty() {
                hit = Some(name.clone());
            }
        }
        if hit.is_none() {
            let _ = crypto::ct_eq(NOBODY, password.as_bytes());
        }
        let subject = hit.ok_or_else(|| INVALID_CREDENTIALS.to_string())?;
        Ok(Session { subject: subject.clone(), email: None, name: Some(subject), expires_at: Some(unix_now() + self.ttl), admin: false })
    }
}

impl Provider for Basic {
    fn name(&self) -> &str {
        "basic"
    }
    fn available(&self) -> bool {
        true
    }
    /// There is no OAuth redirect: the URL is this app's own form page (upstream
    /// `NonInteractiveMixin` refuses `start_login`).
    fn login_start(&self, _redirect_uri: &str) -> Result<LoginStart, String> {
        Ok(LoginStart { url: "/auth/login".into(), state: String::new() })
    }
    fn exchange(&self, _code: &str, _state: &str, _redirect_uri: &str) -> Result<Session, String> {
        Err("basic is password-only; there is no OAuth callback".into())
    }
    fn verify(&self, token: &str) -> Result<Session, String> {
        open(&self.secret, token, unix_now()).ok_or_else(|| "invalid or expired session token".into())
    }
}

// ─── built-in `self_hosted` (generic OIDC, code + PKCE) ─────────────────────

#[derive(Debug, Clone)]
struct Pending {
    state: String,
    verifier: String,
    /// Only informational: the exchange re-posts the redirect_uri the route computed.
    at: Instant,
}

/// OAuth `state` → PKCE verifier, bounded and time-limited (upstream keeps it in a cookie; ark
/// keeps it in memory so a state cannot be replayed or forged).
fn pending() -> &'static Mutex<Vec<Pending>> {
    static P: std::sync::OnceLock<Mutex<Vec<Pending>>> = std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}

/// The `self_hosted` provider: a generic OIDC relying party over explicit endpoints.
pub struct Oidc {
    cfg: SelfHostedConfig,
    keys: Keys,
}

impl Oidc {
    pub fn new(cfg: &AuthConfig) -> Result<Arc<Oidc>, String> {
        let o = &cfg.self_hosted;
        let mut missing: Vec<&str> = Vec::new();
        for (key, value) in [
            ("authorization_endpoint", &o.authorization_endpoint),
            ("token_endpoint", &o.token_endpoint),
            ("jwks", &o.jwks),
            ("client_id", &o.client_id),
        ] {
            if value.trim().is_empty() {
                missing.push(key);
            }
        }
        if !missing.is_empty() {
            return Err(format!("[app.auth.self_hosted] is incomplete: set {} (issuer/audience/scopes/redirect_uri are optional)", missing.join(", ")));
        }
        if cfg.secret.len() < SECRET_MIN_LEN {
            return Err(format!("[app.auth] secret is required when `enabled`: set `secret = \"{{{{secret:APP_AUTH_SECRET}}}}\"` (at least {SECRET_MIN_LEN} bytes — it signs the session cookie)"));
        }
        Ok(Arc::new(Oidc { cfg: o.clone(), keys: Keys::new(&o.jwks) }))
    }

    pub fn login_start(&self, redirect_uri: &str) -> Result<LoginStart, String> {
        validate_redirect_uri(redirect_uri)?;
        let (verifier, challenge) = crypto::pkce_pair();
        let state = crypto::random_token(32);
        let sep = if self.cfg.authorization_endpoint.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{sep}{}",
            self.cfg.authorization_endpoint.trim(),
            form_encode(&[
                ("response_type", "code"),
                ("client_id", self.cfg.client_id.trim()),
                ("redirect_uri", redirect_uri),
                ("scope", self.cfg.scopes()),
                ("state", &state),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
        );
        remember(&state, &verifier);
        Ok(LoginStart { url, state })
    }

    pub fn exchange(&self, code: &str, state: &str, redirect_uri: &str) -> Result<Session, String> {
        self.exchange_claims(code, state, redirect_uri).map(|(s, _)| s)
    }

    /// Exchange the code and also return the verified claims (for the groups claim, ent-047).
    pub fn exchange_claims(&self, code: &str, state: &str, redirect_uri: &str) -> Result<(Session, Value), String> {
        let token = self.exchange_token(code, state, redirect_uri)?;
        self.verify_claims(&token)
    }

    /// Code + PKCE verifier → the ID token. Never follows redirects (the body carries the
    /// code), asks for JSON, 10 s budget.
    fn exchange_token(&self, code: &str, state: &str, redirect_uri: &str) -> Result<String, String> {
        let verifier = take_state(state)?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.cfg.client_id.trim()),
            ("code_verifier", &verifier),
        ];
        if !self.cfg.client_secret.trim().is_empty() {
            form.push(("client_secret", self.cfg.client_secret.trim()));
        }
        let agent: ureq::Agent = ark_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(TOKEN_TIMEOUT)).build().into();
        let resp = agent.post(self.cfg.token_endpoint.trim()).header("accept", "application/json").send_form(form).map_err(|e| format!("IDP unreachable: {e}"))?;
        let status = resp.status().as_u16();
        let mut raw = String::new();
        resp.into_body().into_reader().take(1 << 20).read_to_string(&mut raw).map_err(|e| format!("IDP unreachable: reading the token response: {e}"))?;
        if status == 400 {
            let code = serde_json::from_str::<Value>(&raw).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_else(|| "invalid_request".into());
            return Err(format!("IDP rejected the token request: {code}"));
        }
        if status != 200 {
            return Err(format!("token endpoint returned {status}"));
        }
        let payload: Value = serde_json::from_str(&raw).map_err(|_| "token endpoint returned a non-JSON body".to_string())?;
        let token_type = payload["token_type"].as_str().unwrap_or("").to_ascii_lowercase();
        if !token_type.is_empty() && token_type != "bearer" {
            return Err(format!("unexpected token_type `{token_type}`"));
        }
        ["id_token", "access_token"]
            .iter()
            .find_map(|k| payload[*k].as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string))
            .ok_or_else(|| "token response has no id_token (is the `openid` scope configured?)".to_string())
    }

    /// Verify an ID token and keep its claims.
    pub fn verify_claims(&self, token: &str) -> Result<(Session, Value), String> {
        let now = unix_now();
        let audience = if self.cfg.audience.trim().is_empty() { self.cfg.client_id.trim() } else { self.cfg.audience.trim() };
        let issuer = Some(self.cfg.issuer.trim()).filter(|i| !i.is_empty());
        let claims = crate::cron_fire::verify_with(token, &self.keys, audience, issuer, now, LEEWAY_SECS)?;
        Ok((claims_to_session(&claims, now)?, claims))
    }
}

impl Provider for Oidc {
    fn name(&self) -> &str {
        "self_hosted"
    }
    fn available(&self) -> bool {
        true
    }
    fn login_start(&self, redirect_uri: &str) -> Result<LoginStart, String> {
        Oidc::login_start(self, redirect_uri)
    }
    fn exchange(&self, code: &str, state: &str, redirect_uri: &str) -> Result<Session, String> {
        Oidc::exchange(self, code, state, redirect_uri)
    }
    fn verify(&self, token: &str) -> Result<Session, String> {
        let now = unix_now();
        let audience = if self.cfg.audience.trim().is_empty() { self.cfg.client_id.trim() } else { self.cfg.audience.trim() };
        let issuer = Some(self.cfg.issuer.trim()).filter(|i| !i.is_empty());
        let claims = crate::cron_fire::verify_with(token, &self.keys, audience, issuer, now, LEEWAY_SECS)?;
        claims_to_session(&claims, now)
    }
}

/// Map verified OIDC claims onto a session. `sub` is mandatory (upstream
/// `session_from_claims`); `email`/`name`/`exp` are best-effort.
pub fn claims_to_session(claims: &Value, now: i64) -> Result<Session, String> {
    let subject = claims["sub"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| "ID token missing 'sub' (user id) claim".to_string())?;
    let text = |k: &str| claims[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let email = text("email");
    let name = text("name").or_else(|| text("preferred_username")).or_else(|| text("nickname")).or_else(|| email.clone());
    Ok(Session { subject: subject.to_string(), email, name, expires_at: claims["exp"].as_i64().or(Some(now)), admin: false })
}

/// The cached `self_hosted` provider (the JWKS cache lives in [`Keys`], so every request must
/// see the same instance; the pending-`state` map is process-global either way).
fn oidc(cfg: &AuthConfig) -> Result<Arc<Oidc>, String> {
    static CACHE: Mutex<Option<(String, Arc<Oidc>)>> = Mutex::new(None);
    let o = &cfg.self_hosted;
    let key = format!("{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}", o.authorization_endpoint, o.token_endpoint, o.jwks, o.client_id, o.client_secret, o.audience);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((k, v)) = c.as_ref() {
        if *k == key {
            return Ok(v.clone());
        }
    }
    let built = Oidc::new(cfg)?;
    *c = Some((key, built.clone()));
    Ok(built)
}

fn remember(state: &str, verifier: &str) {
    let mut all = pending().lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|p| p.at.elapsed() < PKCE_TTL);
    all.push(Pending { state: state.to_string(), verifier: verifier.to_string(), at: Instant::now() });
    while all.len() > PKCE_MAX {
        all.remove(0);
    }
}

/// Take (single use) the verifier a `state` was minted with.
fn take_state(state: &str) -> Result<String, String> {
    let mut all = pending().lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|p| p.at.elapsed() < PKCE_TTL);
    let Some(i) = all.iter().position(|p| p.state == state) else {
        return Err("unknown or expired login state (start again at /auth/login)".into());
    };
    Ok(all.remove(i).verifier)
}

/// Reject a redirect_uri that cannot be our callback before bouncing to the IDP (whose allowlist
/// stays authoritative). Any `http://` host is allowed so dashboards behind TLS-terminating
/// proxies keep working (upstream `validate_redirect_uri`).
fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let (scheme, rest) = uri.split_once("://").ok_or_else(|| format!("redirect_uri must be http(s), got `{uri}`"))?;
    if !matches!(scheme, "https" | "http") {
        return Err(format!("redirect_uri must be http(s), got `{uri}`"));
    }
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let path = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
    if !path.trim_end_matches('/').ends_with("/auth/callback") {
        return Err(format!("redirect_uri path must end with '/auth/callback', got `{uri}`"));
    }
    Ok(())
}

// ─── provider selection ─────────────────────────────────────────────────────

/// What `[app.auth] provider` resolved to.
enum Selected {
    Basic(Basic),
    Oidc(Arc<Oidc>),
    /// SAML 2.0 SP with the IdP's verification keys (ent-048).
    Saml(Vec<crate::xmldsig::Key>),
    Plugin(Arc<dyn Provider>),
    /// A known name that cannot serve here; the string is the operator-facing reason.
    Unsupported(String),
}

/// Resolve the configured provider. Never panics: an unusable configuration becomes
/// [`Selected::Unsupported`] (upstream `SkipRegistration` → `LAST_SKIP_REASON`).
fn select(cfg: &AuthConfig) -> Selected {
    let name = cfg.provider.trim().to_ascii_lowercase();
    match name.as_str() {
        "" | "basic" => match Basic::new(cfg) {
            Ok(b) => Selected::Basic(b),
            Err(e) => Selected::Unsupported(e),
        },
        "self_hosted" | "self-hosted" | "oidc" => match oidc(cfg) {
            Ok(o) => Selected::Oidc(o),
            Err(e) => Selected::Unsupported(e),
        },
        "saml" | "saml2" => match cfg.saml.keys() {
            Ok(_) if cfg.secret.len() < SECRET_MIN_LEN => Selected::Unsupported(format!("[app.auth] secret is required when `enabled` (at least {SECRET_MIN_LEN} bytes — it signs the session cookie)")),
            Ok(k) => Selected::Saml(k),
            Err(e) => Selected::Unsupported(e),
        },
        "none" => Selected::Unsupported("dashboard login is off (`[app.auth] provider = \"none\"`); the app token is the only credential".into()),
        "nous" | "drain" => Selected::Unsupported(format!(
            "`{name}` is Hermes' own hosted OAuth service and has no ark implementation; use `basic`, `self_hosted`, or a plugin provider id"
        )),
        other => match providers::find(other) {
            Some(p) => Selected::Plugin(p),
            None => Selected::Unsupported(format!("unknown dashboard auth provider `{other}`: use `basic`, `self_hosted`, or a plugin provider id")),
        },
    }
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

/// Is the login gate on? (Everything below is a no-op otherwise.)
pub fn auth_enabled(app: &App) -> bool {
    app.cfg.auth.enabled
}

/// The session a request carries: our signed cookie, or a credential the provider verifies
/// (`Authorization: Bearer <id token>`). `None` when it carries none — callers treat that as
/// "no session", never as an error.
pub fn session_from(app: &App, r: &Request) -> Option<Session> {
    let cfg = &app.cfg.auth;
    if !cfg.enabled || cfg.secret.len() < SECRET_MIN_LEN {
        return None;
    }
    let now = unix_now();
    if let Some(token) = cookie(r, cfg.cookie_name()) {
        if let Some(s) = open(cfg.secret.as_bytes(), token, now) {
            return Some(s);
        }
    }
    // A credential presented directly: a personal token from `/auth/token`, an OIDC ID token
    // or a plugin provider's token.
    let bearer = r.bearer()?;
    if let Some(s) = open(cfg.secret.as_bytes(), bearer, now) {
        return Some(s);
    }
    match select(cfg) {
        Selected::Oidc(o) => o.verify(bearer).ok(),
        Selected::Plugin(p) => p.verify(bearer).ok(),
        Selected::Basic(_) | Selected::Saml(_) | Selected::Unsupported(_) => None,
    }
}

/// A resolved dashboard login: who, how, and which roles (ent-047 / ent-053).
#[derive(Debug, Clone, PartialEq)]
pub struct Login {
    /// `basic`, `sso` or `plugin`.
    pub kind: String,
    /// Email when known, else the subject.
    pub name: String,
    pub roles: Vec<Role>,
    /// Organization / team reach (ent-050).
    pub tenant: ark_kernel::tenancy::Viewer,
}

fn kind_of(cfg: &AuthConfig) -> &'static str {
    match cfg.provider.trim().to_ascii_lowercase().as_str() {
        "" | "basic" => "basic",
        "self_hosted" | "self-hosted" | "oidc" => "sso",
        "saml" | "saml2" => "saml",
        _ => "plugin",
    }
}

/// Map a login to roles (or refuse it), using `[app.rbac]` and the user registry.
pub fn roles_for(app: &App, kind: &str, s: &Session, groups: Vec<String>) -> Result<Vec<Role>, String> {
    let facts = identity::LoginFacts { provider: kind, subject: &s.subject, email: s.email.as_deref().unwrap_or(""), groups, provider_admin: s.admin && kind == "plugin" };
    identity::login_roles(app.cfg.rbac.as_ref(), &app.d.k.paths, &facts)
}

/// The login a request carries (cookie, personal token, or a provider token), with roles.
/// A profile disabled in `ark users` after login stops working at once.
pub fn login_from(app: &App, r: &Request) -> Option<Login> {
    let cfg = &app.cfg.auth;
    if !cfg.enabled || cfg.secret.len() < SECRET_MIN_LEN {
        return None;
    }
    let now = unix_now();
    let ours_raw = cookie(r, cfg.cookie_name()).filter(|t| open_with(cfg.secret.as_bytes(), t, now).is_some()).or_else(|| r.bearer().filter(|t| open_with(cfg.secret.as_bytes(), t, now).is_some()));
    let mut signed_team = ours_raw.map(|t| open_team(cfg.secret.as_bytes(), t, now)).unwrap_or_default();
    let ours = ours_raw.and_then(|t| open_with(cfg.secret.as_bytes(), t, now));
    let (s, roles, kind) = match ours {
        Some((s, roles, kind)) => {
            let kind = if kind.is_empty() { kind_of(cfg).to_string() } else { kind };
            // A token minted before roles existed: decide now (no groups available).
            let roles = if roles.is_empty() { roles_for(app, &kind, &s, vec![]).ok()? } else { roles };
            (s, roles, kind)
        }
        None => {
            let bearer = r.bearer()?;
            match select(cfg) {
                Selected::Oidc(o) => {
                    let (s, claims) = o.verify_claims(bearer).ok()?;
                    let groups = identity::groups_from_claims(&claims, app.cfg.rbac.as_ref().map(|r| r.groups_claim.as_str()).unwrap_or("groups"));
                    signed_team = crate::tenant::login_team(app, &groups);
                    let roles = roles_for(app, "sso", &s, groups).ok()?;
                    (s, roles, "sso".to_string())
                }
                Selected::Plugin(p) => {
                    let s = p.verify(bearer).ok()?;
                    let roles = roles_for(app, "plugin", &s, vec![]).ok()?;
                    (s, roles, "plugin".to_string())
                }
                _ => return None,
            }
        }
    };
    if ark_kernel::agents::find_login(&app.d.k.paths, &s.subject, s.email.as_deref().unwrap_or("")).is_some_and(|u| u.disabled) {
        return None;
    }
    let tenant = crate::tenant::login_viewer(app, &s.subject, s.email.as_deref().unwrap_or(""), &roles, &signed_team);
    Some(Login { kind, name: s.email.clone().unwrap_or_else(|| s.subject.clone()), roles, tenant })
}

fn audit_login(app: &App, r: &Request, kind: &str, who: &str, outcome: &str, detail: Value) {
    let ip = app.client_ip(r).map(|i| i.to_string()).unwrap_or_default();
    ark_security::audit::record(&app.d.k.paths.data, ark_security::audit::Event::new("auth.login", ark_security::audit::Actor::new(kind, who).with_ip(&ip), "/auth/login", outcome).detail(detail));
}

/// Serve one `/auth/…` request (mounted before the app-token check: this *is* the login).
pub fn handle(app: &App, r: &Request) -> Response {
    let cfg = &app.cfg.auth;
    if !cfg.enabled {
        return not_found();
    }
    let path = r.path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    match (r.method.as_str(), path) {
        ("GET", "/auth/login") => login_page(app, r),
        ("POST", "/auth/login") => login_submit(app, r),
        ("GET", "/auth/callback") => callback(app, r),
        ("GET", "/auth/logout") => logout(cfg, true),
        ("POST", "/auth/logout") => logout(cfg, false),
        ("GET", "/auth/whoami") => whoami(app, r),
        ("POST", "/auth/token") => personal_token(app, r),
        ("GET", "/auth/saml/metadata") => saml_metadata(app),
        ("POST", "/auth/saml/acs") => saml_acs(app, r),
        _ => not_found(),
    }
}

fn login_page(app: &App, r: &Request) -> Response {
    match select(&app.cfg.auth) {
        // The basic provider's "authorize URL" is this app's own form.
        Selected::Basic(_) => Response::html(&form_html(r.query("error").is_some())).with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer"),
        Selected::Oidc(o) => match o.login_start(&redirect_uri(&app.cfg.auth, r)) {
            Ok(s) => redirect(&s.url),
            Err(e) => unavailable("self_hosted", &e),
        },
        Selected::Saml(_) => {
            let c = &app.cfg.auth.saml;
            let now = unix_now();
            let id = crate::saml::new_request(now);
            let req = crate::saml::authn_request(c, c.sp_entity_id(), c.acs_url(), &id, now);
            redirect(&crate::saml::redirect_url(c, &req, &crypto::random_token(16)))
        }
        Selected::Plugin(p) => match p.login_start(&redirect_uri(&app.cfg.auth, r)) {
            Ok(s) => redirect(&s.url),
            Err(e) => {
                eprintln!("arkd: dashboard auth: provider `{}` login_start failed: {e}", p.name());
                unavailable(p.name(), &e)
            }
        },
        Selected::Unsupported(reason) => unavailable(&app.cfg.auth.provider, &reason),
    }
}

fn login_submit(app: &App, r: &Request) -> Response {
    let cfg = &app.cfg.auth;
    let Selected::Basic(b) = select(cfg) else {
        // Only the password provider takes a form; an OAuth login starts at the IDP.
        return Response::json(400, &json!({"error": "this provider has no password form"}).to_string()).with_header("cache-control", "no-store");
    };
    let form = parse_query(r.body_str());
    let field = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str()).unwrap_or("");
    match b.login(field("user"), field("password")) {
        Ok(s) => match roles_for(app, "basic", &s, vec![]) {
            Ok(roles) => {
                audit_login(app, r, "basic", &s.subject, "ok", json!({"roles": roles.iter().map(|r| r.as_str()).collect::<Vec<_>>()}));
                with_session_roles(cfg, &s, &roles, "basic", redirect("/"))
            }
            Err(e) => {
                audit_login(app, r, "basic", &s.subject, "deny", json!({"reason": e}));
                Response::json(403, &json!({"error": LOGIN_FAILED}).to_string()).with_header("cache-control", "no-store")
            }
        },
        Err(e) => {
            eprintln!("arkd: dashboard auth: password login failed: {e}");
            audit_login(app, r, "basic", field("user"), "fail", Value::Null);
            Response::json(401, &json!({"error": INVALID_CREDENTIALS}).to_string()).with_header("cache-control", "no-store")
        }
    }
}

fn callback(app: &App, r: &Request) -> Response {
    let cfg = &app.cfg.auth;
    let (Some(code), Some(state)) = (r.query("code"), r.query("state")) else {
        return failed(400);
    };
    let redirect_uri = redirect_uri(cfg, r);
    let groups_claim = app.cfg.rbac.as_ref().map(|r| r.groups_claim.clone()).unwrap_or_else(|| "groups".into());
    let (kind, outcome) = match select(cfg) {
        Selected::Oidc(o) => ("sso", o.exchange_claims(code, state, &redirect_uri).map(|(s, c)| (s, identity::groups_from_claims(&c, &groups_claim)))),
        Selected::Plugin(p) => ("plugin", p.exchange(code, state, &redirect_uri).map(|s| (s, vec![]))),
        Selected::Basic(_) | Selected::Saml(_) => return failed(400),
        Selected::Unsupported(reason) => return unavailable(&cfg.provider, &reason),
    };
    match outcome {
        Ok((s, groups)) => match roles_for(app, kind, &s, groups.clone()) {
            Ok(roles) => {
                audit_login(app, r, kind, s.email.as_deref().unwrap_or(&s.subject), "ok", json!({"subject": s.subject, "groups": groups, "roles": roles.iter().map(|r| r.as_str()).collect::<Vec<_>>()}));
                with_session_team(cfg, &s, &roles, kind, &crate::tenant::login_team(app, &groups), redirect("/"))
            }
            Err(e) => {
                audit_login(app, r, kind, s.email.as_deref().unwrap_or(&s.subject), "deny", json!({"subject": s.subject, "groups": groups, "reason": e}));
                failed(403)
            }
        },
        Err(e) => {
            // Logged in full, shown as one generic line: a caller must not learn which check
            // failed (expired / bad signature / wrong audience / unknown key).
            eprintln!("arkd: dashboard auth: login callback failed: {e}");
            failed(status_for(&e))
        }
    }
}

/// `GET /auth/saml/metadata`: the SP metadata to hand to the IdP administrator.
fn saml_metadata(app: &App) -> Response {
    let c = &app.cfg.auth.saml;
    match select(&app.cfg.auth) {
        Selected::Saml(_) => Response::text(200, &crate::saml::metadata(c, c.sp_entity_id(), c.acs_url())).with_header("content-type", "application/samlmetadata+xml").with_header("cache-control", "no-store"),
        Selected::Unsupported(reason) => unavailable("saml", &reason),
        _ => not_found(),
    }
}

/// `POST /auth/saml/acs` (HTTP-POST binding): verify the Response, then the same role mapping
/// and session cookie as an OIDC callback. Exempt from the app-wide Origin check (the IdP's page
/// posts it); the signed, audience-bound, single-use assertion is the credential.
fn saml_acs(app: &App, r: &Request) -> Response {
    let cfg = &app.cfg.auth;
    let keys = match select(cfg) {
        Selected::Saml(k) => k,
        Selected::Unsupported(reason) => return unavailable("saml", &reason),
        _ => return not_found(),
    };
    let form = parse_query(r.body_str());
    let raw = form.iter().find(|(k, _)| k == "SAMLResponse").map(|(_, v)| v.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap_or_default();
    let Some(xml) = crypto::b64_decode(&raw).and_then(|b| String::from_utf8(b).ok()) else {
        audit_login(app, r, "saml", "", "fail", json!({"reason": "no SAMLResponse"}));
        return failed(400);
    };
    let now = unix_now();
    let c = &cfg.saml;
    let exp = crate::saml::Expect { sp_entity_id: c.sp_entity_id(), acs_url: c.acs_url(), now };
    let verified = crate::saml::verify_response(&xml, &keys, c, &exp).and_then(|a| crate::saml::accept(&a, now).map(|_| a));
    match verified {
        Ok(a) => {
            let s = Session { subject: a.subject.clone(), email: a.email.clone(), name: a.name.clone(), expires_at: Some(now + cfg.ttl()), admin: false };
            let who = s.email.clone().unwrap_or_else(|| s.subject.clone());
            match roles_for(app, "saml", &s, a.groups.clone()) {
                Ok(roles) => {
                    audit_login(app, r, "saml", &who, "ok", json!({"subject": s.subject, "groups": a.groups, "roles": roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(), "assertion": a.id}));
                    with_session_team(cfg, &s, &roles, "saml", &crate::tenant::login_team(app, &a.groups), redirect("/"))
                }
                Err(e) => {
                    audit_login(app, r, "saml", &who, "deny", json!({"subject": s.subject, "groups": a.groups, "reason": e}));
                    failed(403)
                }
            }
        }
        // The browser learns nothing; the reason goes to the audit stream.
        Err(e) => {
            audit_login(app, r, "saml", "", "fail", json!({"reason": e}));
            failed(400)
        }
    }
}

fn whoami(app: &App, r: &Request) -> Response {
    match session_from(app, r) {
        Some(s) => {
            let mut v = serde_json::to_value(&s).unwrap_or(json!({}));
            if let Some(l) = login_from(app, r) {
                v["roles"] = json!(l.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>());
                v["kind"] = json!(l.kind);
            }
            Response::json(200, &v.to_string()).with_header("cache-control", "no-store")
        }
        None => Response::json(401, &json!({"error": "unauthorized"}).to_string()).with_header("www-authenticate", "Bearer").with_header("cache-control", "no-store"),
    }
}

fn logout(cfg: &AuthConfig, home: bool) -> Response {
    let clear = format!("{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0", cfg.cookie_name());
    let base = if home { redirect("/") } else { Response::json(200, &json!({"ok": true}).to_string()) };
    base.with_header("set-cookie", &clear).with_header("cache-control", "no-store")
}

/// `POST /auth/token` (with a login): a personal bearer token carrying the same identity and
/// roles, for ARP scripts and CLI clients (ent-047: SSO beyond the browser). Optional JSON
/// `{"ttl_secs": N}`, capped by the session lifetime. Same-origin only (the route is behind the
/// app-wide Origin check for non-GET requests).
fn personal_token(app: &App, r: &Request) -> Response {
    let cfg = &app.cfg.auth;
    let (Some(l), Some(s)) = (login_from(app, r), session_from(app, r)) else {
        return Response::json(401, &json!({"error": "unauthorized"}).to_string()).with_header("cache-control", "no-store");
    };
    let want = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v["ttl_secs"].as_i64()).unwrap_or(cfg.ttl());
    let now = unix_now();
    let left = s.expires_at.map(|e| e - now).unwrap_or(cfg.ttl()).max(60);
    let ttl = want.clamp(60, left.min(cfg.ttl()));
    let token = mint_team(cfg.secret.as_bytes(), &s, &l.roles, &l.kind, &l.tenant.team, now, ttl);
    ark_security::audit::record(&app.d.k.paths.data, ark_security::audit::Event::new("token.issue", ark_security::audit::Actor::new(&l.kind, &l.name), "personal", "ok").detail(json!({"ttl_secs": ttl, "roles": l.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>()})));
    Response::json(200, &json!({"token": token, "expires_at": now + ttl, "roles": l.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>()}).to_string()).with_header("cache-control", "no-store")
}

/// 302 + the session cookie with its roles.
fn with_session_roles(cfg: &AuthConfig, s: &Session, roles: &[Role], kind: &str, base: Response) -> Response {
    with_session_team(cfg, s, roles, kind, "", base)
}

/// 302 + the session cookie with its roles and the team the IdP groups mapped to.
fn with_session_team(cfg: &AuthConfig, s: &Session, roles: &[Role], kind: &str, team: &str, base: Response) -> Response {
    let ttl = cfg.ttl();
    let token = mint_team(cfg.secret.as_bytes(), s, roles, kind, team, unix_now(), ttl);
    base.with_header("set-cookie", &format!("{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl}", cfg.cookie_name())).with_header("cache-control", "no-store")
}

/// 302 + the session cookie (the only place a cookie is ever set).
#[allow(dead_code)]
fn with_session(cfg: &AuthConfig, s: &Session, base: Response) -> Response {
    let ttl = cfg.ttl();
    let token = mint(cfg.secret.as_bytes(), s, unix_now(), ttl);
    base.with_header("set-cookie", &format!("{}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl}", cfg.cookie_name())).with_header("cache-control", "no-store")
}

fn redirect(location: &str) -> Response {
    Response::empty(302).with_header("location", location).with_header("cache-control", "no-store")
}

/// The generic callback failure (400 or 503, never a reason).
fn failed(status: u16) -> Response {
    Response::json(status, &json!({"error": LOGIN_FAILED}).to_string()).with_header("cache-control", "no-store")
}

/// A configuration problem: the browser shows the operator-facing reason (it names config keys,
/// never secrets) so a broken `[app.auth]` block is diagnosable instead of a bare 401.
fn unavailable(provider: &str, reason: &str) -> Response {
    eprintln!("arkd: dashboard auth: provider `{provider}` unavailable: {reason}");
    Response::json(503, &json!({"error": "dashboard login is not available", "provider": provider, "detail": reason}).to_string()).with_header("cache-control", "no-store")
}

fn not_found() -> Response {
    Response::json(404, &json!({"error": "not found"}).to_string())
}

/// Upstream classification: an unreachable / failing IDP is a 503 (a retry may work), anything
/// about the code or the token is a 400.
fn status_for(detail: &str) -> u16 {
    let d = detail.to_ascii_lowercase();
    if d.contains("unreachable") || d.contains("token endpoint returned 5") || d.contains("non-json") {
        503
    } else {
        400
    }
}

/// The redirect_uri to send: `[app.auth.self_hosted] redirect_uri`, else this request's own
/// origin + `/auth/callback` (honouring `X-Forwarded-Proto` from a TLS-terminating proxy).
fn redirect_uri(cfg: &AuthConfig, r: &Request) -> String {
    let configured = cfg.self_hosted.redirect_uri.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }
    let host = r.header("host").map(str::trim).filter(|h| !h.is_empty()).unwrap_or("127.0.0.1:8640");
    let scheme = r.header("x-forwarded-proto").and_then(|p| p.split(',').next()).map(str::trim).filter(|p| *p == "https" || *p == "http").unwrap_or("http");
    format!("{scheme}://{host}/auth/callback")
}

/// One cookie value by name.
fn cookie<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// The password form (no scripts, no external assets, and no CSRF token: the login itself is the
/// credential, and the cookie is `SameSite=Lax`).
fn form_html(failed: bool) -> String {
    let msg = if failed { "<p class=\"err\">That username and password did not match.</p>" } else { "" };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ark — sign in</title>\
<style>body{{font:16px/1.4 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#111;color:#eee}}\
form{{background:#1b1b1b;padding:2rem;border-radius:12px;min-width:18rem;display:grid;gap:.8rem}}h1{{font-size:1.2rem;margin:0 0 .4rem}}\
label{{display:grid;gap:.3rem;font-size:.85rem;color:#bbb}}input{{padding:.6rem;border-radius:8px;border:1px solid #333;background:#0d0d0d;color:#eee;font-size:1rem}}\
button{{padding:.7rem;border:0;border-radius:8px;background:#4c8dff;color:#fff;font-size:1rem;cursor:pointer}}.err{{color:#ff8a8a;margin:0;font-size:.9rem}}</style>\
</head><body><form method=\"post\" action=\"/auth/login\"><h1>ark</h1>{msg}\
<label>User<input name=\"user\" autocomplete=\"username\" autocapitalize=\"none\" autofocus required></label>\
<label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
<button type=\"submit\">Sign in</button></form></body></html>"
    )
}

pub(crate) fn unix_now() -> i64 {
    ark_kernel::util::unix_now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppConfig;
    use ark_kernel::config::{Config, Paths};
    use ark_kernel::daemon::Daemon;
    use ark_net::httpd::Body;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    struct NoRes;
    impl ark_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn app(label: &str, auth: AuthConfig) -> Arc<App> {
        let home = ark_core::tmp::scratch(&format!("ark-auth-{label}"));
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = ark_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = ark_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(ark_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        let cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), auth, ..AppConfig::default() };
        Arc::new(App { d, cfg, token: "app-token".into(), host_methods: vec![], routes: vec![] })
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn get(target: &str, hs: &[(&str, &str)]) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request { method: "GET".into(), path: path.into(), query: parse_query(q), raw_query: q.into(), headers: headers(hs), body: vec![], peer: None, head: String::new() }
    }

    fn post(target: &str, form: &str) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request { method: "POST".into(), path: path.into(), query: parse_query(q), raw_query: q.into(), headers: headers(&[("content-type", "application/x-www-form-urlencoded")]), body: form.as_bytes().to_vec(), peer: None, head: String::new() }
    }

    fn header(r: &Response, name: &str) -> Option<String> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
    }

    fn body(r: &Response) -> Vec<u8> {
        match &r.body {
            Body::Bytes(b) => b.clone(),
            _ => vec![],
        }
    }

    fn json_body(r: &Response) -> Value {
        serde_json::from_slice(&body(r)).unwrap_or(Value::Null)
    }

    fn basic_cfg(password: &str) -> AuthConfig {
        let mut users = BTreeMap::new();
        users.insert("alice".to_string(), password.to_string());
        AuthConfig { enabled: true, provider: "basic".into(), secret: "0123456789abcdef0123".into(), basic: BasicConfig { users }, ..AuthConfig::default() }
    }

    #[test]
    fn basic_login_sets_a_session_cookie_and_authorized_accepts_it() {
        let app = app("basic", basic_cfg("hunter2"));
        // GET /auth/login is the password form for the basic provider.
        let page = handle(&app, &get("/auth/login", &[]));
        assert_eq!(page.status, 200);
        assert!(String::from_utf8_lossy(&body(&page)).contains("name=\"password\""));
        // A good password: 302 to / with an HttpOnly, SameSite, path-scoped cookie.
        let r = handle(&app, &post("/auth/login", "user=alice&password=hunter2"));
        assert_eq!(r.status, 302);
        assert_eq!(header(&r, "location").as_deref(), Some("/"));
        let set = header(&r, "set-cookie").expect("session cookie");
        assert!(set.starts_with("ark_session="), "{set}");
        for attr in ["HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=43200"] {
            assert!(set.contains(attr), "{attr} missing from {set}");
        }
        let token = set.split(';').next().unwrap().trim().split_once('=').unwrap().1.to_string();
        // The cookie is a second credential: a request without the app token passes `authorized`.
        let with_cookie = get("/arp", &[("cookie", &format!("ark_session={token}"))]);
        assert!(app.authorized(&with_cookie));
        assert!(!app.authorized(&get("/arp", &[])), "no cookie, no app token");
        assert!(!app.authorized(&get("/arp", &[("cookie", "ark_session=nonsense")])));
        // whoami describes the session.
        let me = handle(&app, &get("/auth/whoami", &[("cookie", &format!("ark_session={token}"))]));
        assert_eq!(me.status, 200);
        let v = json_body(&me);
        assert_eq!((v["subject"].as_str(), v["name"].as_str(), v["admin"].as_bool()), (Some("alice"), Some("alice"), Some(false)));
        assert!(v["email"].is_null() && v["expires_at"].as_i64().unwrap() > unix_now());
        // Wrong password and unknown user: one 401 message, never a cookie.
        for form in ["user=alice&password=nope", "user=bob&password=hunter2", "user=&password="] {
            let r = handle(&app, &post("/auth/login", form));
            assert_eq!(r.status, 401, "{form}");
            assert!(header(&r, "set-cookie").is_none());
            assert_eq!(json_body(&r)["error"].as_str(), Some(INVALID_CREDENTIALS));
        }
        // A tampered cookie fails the HMAC and authorizes nothing.
        let mut bad = token.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!app.authorized(&get("/arp", &[("cookie", &format!("ark_session={bad}"))])));
        let me = handle(&app, &get("/auth/whoami", &[("cookie", &format!("ark_session={bad}"))]));
        assert_eq!(me.status, 401);
        // Logout clears the cookie.
        for r in [handle(&app, &get("/auth/logout", &[])), handle(&app, &post("/auth/logout", ""))] {
            assert_eq!(header(&r, "set-cookie").unwrap(), "ark_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
        }
    }

    #[test]
    fn self_hosted_oidc_login_and_callback_verify_the_id_token() {
        let rng = SystemRandom::new();
        let pk8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pk8.as_ref(), &rng).unwrap();
        let pt = kp.public_key().as_ref().to_vec();
        let jwks = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": crypto::b64url(&pt[1..33]), "y": crypto::b64url(&pt[33..65])}]});
        // The fake IDP: `/jwks.json` serves the key, `/token` answers the id_token the test set.
        let served = Arc::new(Mutex::new(json!({"token": "", "jwks": jwks.clone(), "form": []})));
        let inner = served.clone();
        let idp = ark_net::httpd::Server::bind(
            "127.0.0.1:0",
            Default::default(),
            Arc::new(move |r: Request| {
                let mut s = inner.lock().unwrap();
                match (r.method.as_str(), r.path.as_str()) {
                    ("GET", "/jwks.json") => Response::json(200, &s["jwks"].to_string()),
                    ("POST", "/token") => {
                        s["form"] = json!(parse_query(r.body_str()).iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>());
                        Response::json(200, &json!({"access_token": "opaque", "token_type": "Bearer", "id_token": s["token"].clone()}).to_string())
                    }
                    _ => Response::json(404, &json!({"error": "no such route"}).to_string()),
                }
            }),
        )
        .unwrap();
        let issuer = format!("http://127.0.0.1:{}", idp.local_addr().port());
        let cfg = AuthConfig {
            enabled: true,
            provider: "self_hosted".into(),
            secret: "0123456789abcdef0123".into(),
            self_hosted: SelfHostedConfig {
                issuer: issuer.clone(),
                authorization_endpoint: format!("{issuer}/authorize"),
                token_endpoint: format!("{issuer}/token"),
                jwks: format!("{issuer}/jwks.json"),
                client_id: "ark".into(),
                ..SelfHostedConfig::default()
            },
            ..AuthConfig::default()
        };
        let app = app("oidc", cfg);
        // Sign an ES256 ID token (the same shape cron_fire's tests use).
        let sign = |claims: Value| -> String {
            let h = crypto::b64url(json!({"alg": "ES256", "kid": "k1"}).to_string().as_bytes());
            let p = crypto::b64url(claims.to_string().as_bytes());
            let sig = kp.sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes()).unwrap();
            format!("{h}.{p}.{}", crypto::b64url(sig.as_ref()))
        };
        let id_token = |exp: i64, aud: &str| {
            let now = unix_now();
            sign(json!({"sub": "u-1", "email": "u@idp.test", "name": "OIDC User", "aud": aud, "iss": issuer, "iat": now, "nbf": now - 1, "exp": exp}))
        };
        let start = |app: &Arc<App>| -> String {
            let r = handle(app, &get("/auth/login", &[("host", "ark.test")]));
            assert_eq!(r.status, 302, "{:?}", json_body(&r));
            let loc = header(&r, "location").unwrap();
            assert!(loc.starts_with(&format!("{issuer}/authorize?")), "{loc}");
            for part in ["response_type=code", "client_id=ark", "redirect_uri=http%3A%2F%2Fark.test%2Fauth%2Fcallback", "scope=openid%20profile%20email", "code_challenge_method=S256", "code_challenge="] {
                assert!(loc.contains(part), "{part} missing from {loc}");
            }
            let q = parse_query(loc.split_once('?').unwrap().1);
            q.iter().find(|(k, _)| k == "state").map(|(_, v)| v.clone()).expect("state")
        };

        // 1. The happy path: state from /auth/login, code back to /auth/callback.
        served.lock().unwrap()["token"] = json!(id_token(unix_now() + 300, "ark"));
        let state = start(&app);
        let r = handle(&app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
        assert_eq!(r.status, 302, "{}", String::from_utf8_lossy(&body(&r)));
        assert_eq!(header(&r, "location").as_deref(), Some("/"));
        let set = header(&r, "set-cookie").expect("session cookie");
        let token = set.split(';').next().unwrap().trim().split_once('=').unwrap().1.to_string();
        // The token endpoint got a form grant with the PKCE verifier and the same redirect_uri.
        let form = served.lock().unwrap()["form"].clone();
        let has = |k: &str, v: &str| form.as_array().unwrap().iter().any(|p| p[0] == k && p[1] == v);
        assert!(has("grant_type", "authorization_code") && has("code", "good") && has("client_id", "ark"));
        assert!(has("redirect_uri", "http://ark.test/auth/callback"));
        assert!(form.as_array().unwrap().iter().any(|p| p[0] == "code_verifier" && p[1].as_str().is_some_and(|v| !v.is_empty())));
        // The session the app minted describes the verified ID token.
        let me = handle(&app, &get("/auth/whoami", &[("cookie", &format!("ark_session={token}"))]));
        assert_eq!(me.status, 200);
        let v = json_body(&me);
        assert_eq!((v["subject"].as_str(), v["email"].as_str(), v["name"].as_str()), (Some("u-1"), Some("u@idp.test"), Some("OIDC User")));
        assert!(app.authorized(&get("/arp", &[("cookie", &format!("ark_session={token}"))])));
        // A verified ID token is a credential on its own (upstream `verify_session`).
        let good = served.lock().unwrap()["token"].as_str().unwrap().to_string();
        assert!(app.authorized(&get("/arp", &[("authorization", &format!("Bearer {good}"))])));
        // ent-047: an IdP login is never admin by default; it is a `user`.
        assert_eq!(v["roles"], json!(["user"]));
        let arp = |app: &Arc<App>, auth: (&str, &str), method: &str| {
            let mut r = get("/arp", &[auth, ("content-type", "application/json")]);
            r.method = "POST".into();
            r.body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string().into_bytes();
            app.clone().handle(r).status
        };
        let cookie_hdr = format!("ark_session={token}");
        assert_eq!(arp(&app, ("cookie", &cookie_hdr), "config.set"), 403, "a user login cannot reconfigure");
        assert_eq!(arp(&app, ("cookie", &cookie_hdr), "session.list"), 200);
        // Groups claim → roles with [app.rbac]; a personal token carries the same identity.
        let mut rb = crate::identity::RbacConfig::default();
        rb.groups.insert("ark-ops".into(), "operator".into());
        let ops_app = Arc::new(App { d: app.d.clone(), cfg: AppConfig { rbac: Some(rb), ..app.cfg.clone() }, token: "app-token".into(), host_methods: vec![], routes: vec![] });
        let now = unix_now();
        served.lock().unwrap()["token"] = json!(sign(json!({"sub": "u-2", "email": "ops@idp.test", "groups": ["ark-ops", "staff"], "aud": "ark", "iss": issuer, "iat": now, "nbf": now - 1, "exp": now + 300})));
        let state = start(&ops_app);
        let r = handle(&ops_app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
        assert_eq!(r.status, 302);
        let ops_cookie = format!("ark_session={}", header(&r, "set-cookie").unwrap().split(';').next().unwrap().trim().split_once('=').unwrap().1);
        assert_eq!(json_body(&handle(&ops_app, &get("/auth/whoami", &[("cookie", &ops_cookie)])))["roles"], json!(["operator"]));
        let mut tr = get("/auth/token", &[("cookie", &ops_cookie)]);
        tr.method = "POST".into();
        let pt = json_body(&handle(&ops_app, &tr));
        let bearer = format!("Bearer {}", pt["token"].as_str().unwrap());
        assert_eq!(arp(&ops_app, ("authorization", &bearer), "session.list"), 200);
        assert_eq!(arp(&ops_app, ("authorization", &bearer), "session.history"), 403, "operators never see conversation content");
        let logins = ark_security::audit::query(&app.d.k.paths.data, &ark_security::audit::Query { kind: Some("auth.login".into()), ..Default::default() });
        assert!(logins.iter().any(|r| r["actor"]["name"] == "ops@idp.test" && r["detail"]["roles"] == json!(["operator"])), "{logins:?}");
        // default_role = "none" refuses an unmapped login outright.
        let strict = crate::identity::RbacConfig { default_role: "none".into(), ..Default::default() };
        let strict_app = Arc::new(App { d: app.d.clone(), cfg: AppConfig { rbac: Some(strict), ..app.cfg.clone() }, token: "app-token".into(), host_methods: vec![], routes: vec![] });
        let state = start(&strict_app);
        let r = handle(&strict_app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
        assert_eq!(r.status, 403);
        assert!(header(&r, "set-cookie").is_none());
        served.lock().unwrap()["token"] = json!(id_token(unix_now() + 300, "ark"));

        // 2. A state can only be spent once.
        let r = handle(&app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
        assert_eq!(r.status, 400);
        assert!(header(&r, "set-cookie").is_none());

        // 3. Wrong audience, an expired token, and a tampered signature are all a generic 400.
        for (what, tok) in [
            ("audience", id_token(unix_now() + 300, "someone-else")),
            ("expired", id_token(unix_now() - 3600, "ark")),
        ] {
            served.lock().unwrap()["token"] = json!(tok);
            let state = start(&app);
            let r = handle(&app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
            assert_eq!(r.status, 400, "{what}: should be rejected");
            assert_eq!(json_body(&r)["error"].as_str(), Some(LOGIN_FAILED), "{what} must not leak the check");
            assert!(header(&r, "set-cookie").is_none(), "{what}");
        }
        let mut tampered = id_token(unix_now() + 300, "ark");
        tampered.push_str(".AAAA");
        served.lock().unwrap()["token"] = json!(tampered);
        let state = start(&app);
        let r = handle(&app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
        assert_eq!(r.status, 400, "tampered id_token");

        // 4. `none`-alg and HS256 tokens are refused outright (no algorithm confusion).
        for alg in ["none", "HS256"] {
            let h = crypto::b64url(json!({"alg": alg, "kid": "k1"}).to_string().as_bytes());
            let p = crypto::b64url(json!({"sub": "u-1", "aud": "ark", "exp": unix_now() + 300}).to_string().as_bytes());
            served.lock().unwrap()["token"] = json!(format!("{h}.{p}.{p}"));
            let state = start(&app);
            let r = handle(&app, &get(&format!("/auth/callback?code=good&state={state}"), &[("host", "ark.test")]));
            assert_eq!(r.status, 400, "{alg} must be refused");
        }
    }

    #[test]
    fn session_tokens_expire_and_are_not_forgeable() {
        let secret = b"0123456789abcdef0123";
        let now = 1_800_000_000;
        let s = Session { subject: "alice".into(), email: None, name: Some("alice".into()), expires_at: Some(now + 60), admin: false };
        let tok = mint(secret, &s, now, 60);
        assert_eq!(open(secret, &tok, now).unwrap().subject, "alice");
        assert!(open(secret, &tok, now + 59).is_some());
        assert!(open(secret, &tok, now + 61).is_none(), "expired");
        assert!(open(b"another-secret-000000", &tok, now).is_none(), "a wrong secret cannot verify");
        assert!(open(secret, &format!("{tok}0"), now).is_none(), "trailing junk");
        assert!(open(secret, "", now).is_none() && open(secret, "nonsense", now).is_none());
        // Rewriting the claims does not help: the signature covers them.
        let (_, sig) = tok.split_once('.').unwrap();
        let forged = format!("{}.{sig}", crypto::b64url(json!({"sub": "root", "exp": now + 9999}).to_string().as_bytes()));
        assert!(open(secret, &forged, now).is_none());
        // A basic login mints exactly that shape: `sub`, `email` (null), `exp`.
        let b = Basic::new(&basic_cfg("hunter2")).unwrap();
        let login = b.login("alice", "hunter2").unwrap();
        assert_eq!((login.subject.as_str(), login.email.clone(), login.admin), ("alice", None, false));
        let tok = mint(secret, &login, now, 60);
        let claims: Value = serde_json::from_slice(&crypto::b64url_decode(tok.split('.').next().unwrap()).unwrap()).unwrap();
        assert_eq!((claims["sub"].as_str(), claims["exp"].as_i64(), claims["email"].clone()), (Some("alice"), Some(now + 60), Value::Null));
        assert_eq!(open(secret, &tok, now).unwrap().expires_at, Some(now + 60));
    }

    #[test]
    fn app_config_parses_the_auth_section_and_keeps_old_configs_valid() {
        // No `[app.auth]` at all: the gate stays off, so an old `[app]` block parses unchanged.
        let doc: toml::Table = toml::from_str("[app]\nlisten = \"127.0.0.1:1\"\n").unwrap();
        let c = AppConfig::parse(doc["app"].as_table().unwrap()).unwrap();
        assert!(!c.auth.enabled);
        assert_eq!((c.auth.provider.as_str(), c.auth.cookie_name(), c.auth.ttl()), ("basic", "ark_session", 43_200));
        // The documented block parses as written.
        let doc: toml::Table = toml::from_str(
            r#"
[app.auth]
enabled = true
provider = "self_hosted"
session_ttl_secs = 600
secret = "s3cret-s3cret-s3cret"
[app.auth.basic.users]
alice = "hunter2"
[app.auth.self_hosted]
issuer = "https://id.example.test"
authorization_endpoint = "https://id.example.test/authorize"
token_endpoint = "https://id.example.test/token"
jwks = "https://id.example.test/.well-known/jwks.json"
client_id = "ark"
"#,
        )
        .unwrap();
        let c = AppConfig::parse(doc["app"].as_table().unwrap()).unwrap();
        assert!(c.auth.enabled);
        assert_eq!((c.auth.provider.as_str(), c.auth.session_ttl_secs), ("self_hosted", 600));
        assert_eq!(c.auth.basic.users.get("alice").map(String::as_str), Some("hunter2"));
        assert_eq!(c.auth.self_hosted.scopes, DEFAULT_SCOPES, "openid profile email by default");
        assert!(c.auth.self_hosted.client_secret.is_empty(), "public client (PKCE only) by default");
    }

    #[test]
    fn unusable_providers_report_a_reason_instead_of_crashing() {
        // A known-but-hosted name, an unknown name, and an incomplete basic config: each is an
        // operator-facing 503, never a panic and never a 500.
        for (provider, needle) in [("nous", "hosted OAuth"), ("drain", "hosted OAuth"), ("nosuch", "unknown dashboard auth provider")] {
            let mut cfg = basic_cfg("hunter2");
            cfg.provider = provider.into();
            let a = app("unsupported", cfg);
            let r = handle(&a, &get("/auth/login", &[]));
            assert_eq!(r.status, 503, "{provider}");
            assert!(json_body(&r)["detail"].as_str().unwrap().contains(needle), "{provider}: {}", json_body(&r));
            assert!(!a.authorized(&get("/arp", &[])), "an unusable provider grants nothing");
        }
        let mut cfg = basic_cfg("hunter2");
        cfg.basic.users.clear();
        let a = app("no-users", cfg);
        let r = handle(&a, &get("/auth/login", &[]));
        assert_eq!(r.status, 503);
        assert!(json_body(&r)["detail"].as_str().unwrap().contains("[app.auth.basic] users is empty"));
        // No secret: sessions cannot be minted or verified, and the reason says so.
        let mut cfg = basic_cfg("hunter2");
        cfg.secret.clear();
        let a = app("no-secret", cfg);
        assert_eq!(handle(&a, &get("/auth/login", &[])).status, 503);
        assert!(session_from(&a, &get("/auth/whoami", &[])).is_none());
        assert!(!a.authorized(&get("/arp", &[("cookie", "ark_session=whatever")])));
        // The gate is off by default: /auth/* is just a 404 and a cookie decides nothing.
        let a = app("off", AuthConfig::default());
        assert_eq!(handle(&a, &get("/auth/login", &[])).status, 404);
        assert!(!auth_enabled(&a));
        assert!(session_from(&a, &get("/auth/whoami", &[])).is_none());
        // Inline JWKS documents are accepted (no network at all).
        let mut cfg = basic_cfg("hunter2");
        cfg.provider = "self_hosted".into();
        cfg.self_hosted = SelfHostedConfig {
            authorization_endpoint: "https://id.test/authorize".into(),
            token_endpoint: "https://id.test/token".into(),
            jwks: "{\"keys\": []}".into(),
            client_id: "ark".into(),
            ..SelfHostedConfig::default()
        };
        let a = app("inline-jwks", cfg);
        let r = handle(&a, &get("/auth/login", &[("host", "ark.test")]));
        assert_eq!(r.status, 302);
        assert!(header(&r, "location").unwrap().starts_with("https://id.test/authorize?"));
    }
}
