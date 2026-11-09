//! seagent-app: one protocol for every face of seagent.
//!
//! ARP (agent remote protocol, JSON-RPC 2.0) is served by the daemon on its unix
//! socket and, through this crate, over WebSocket/HTTP for the web and desktop
//! UI, the terminal UI, editors (ACP bridges to the same kernel), devices
//! (nodes) and other agents (A2A, OpenAI-compatible API).
//!
//! ```toml
//! [app]
//! listen = "127.0.0.1:8640"
//! token = "{{secret:APP_TOKEN}}"
//! ```
//!
//! Beyond loopback the server refuses to start unless every layer is there (see
//! [`exposure`]): `[app.exposure] allow_public = true`, TLS or `behind_proxy = true`,
//! a real auth provider, a non-wildcard `[app] allow_origins`, and a rate limit.
//! `[app] tokens = [{ token = "…", scope = "read" }]` adds scoped credentials next to the
//! admin `token`.

pub mod a2a;
pub mod acp;
pub mod acp_client;
pub mod browser_view;
pub mod computer;
pub mod clip;
pub mod exposure;
pub mod identity;
pub mod metrics;
pub mod logbook;
pub mod conversations;
pub mod cron_fire;
pub mod dashboard_auth;
pub mod device_auth;
pub mod devices;
pub mod lan;
pub mod netguard;
pub mod node;
pub mod openai;
pub mod qr;
pub mod server;
pub mod session_share;
pub mod saml;
pub mod scim;
pub mod surfaces;
pub mod tenant;
pub mod tui;
pub mod ui;
pub mod xmldsig;

pub use server::{start, App, ARP_VERSION};

use serde::{Deserialize, Serialize};

fn d_listen() -> String {
    "127.0.0.1:8640".into()
}
fn d_conns() -> usize {
    64
}
fn yes() -> bool {
    true
}

/// `[app]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    /// Off unless set: the daemon only listens on its unix socket.
    pub enabled: bool,
    #[serde(default = "d_listen")]
    pub listen: String,
    /// Bearer token (usually `{{secret:APP_TOKEN}}`); required. Falls back to `$SEAGENT_APP_TOKEN`
    /// (containers), and `$SEAGENT_APP_ENABLED=1` turns the server on.
    pub token: Option<String>,
    /// Extra browser origins allowed to open the WebSocket.
    pub allow_origins: Vec<String>,
    #[serde(default = "yes")]
    pub ui: bool,
    /// OpenAI-compatible API (`/v1/*`). Off by default: no route is registered while off.
    pub openai_api: bool,
    /// Accept device nodes on `/node`.
    pub nodes: bool,
    pub a2a: a2a::A2aConfig,
    #[serde(default = "d_conns")]
    pub max_conns: usize,
    /// Workspace for sessions created through the API.
    pub workspace: Option<String>,
    /// Control UI terminal page (a PTY shell as the daemon's user); off by default.
    pub terminal: bool,
    /// Dashboard login (`[app.auth]`): off by default, so the app token stays the only credential.
    pub auth: dashboard_auth::AuthConfig,
    /// Scoped tokens (`{ token = "…", scope = "read" }`). `token` above stays admin.
    pub tokens: Vec<exposure::TokenConfig>,
    /// `[app.exposure]`: how far beyond loopback this server may go (A8/A9).
    pub exposure: exposure::ExposureConfig,
    /// `[app.rbac]`: login → role mapping (ent-053/047). Absent = historical behaviour.
    pub rbac: Option<identity::RbacConfig>,
    /// Serve `/metrics` without a credential (for a scraper on a private network). Off by default.
    pub metrics_public: bool,
    /// SCIM 2.0 provisioning at `/scim/v2` (ent-049). Off by default: no route while off.
    pub scim: bool,
    /// LAN discovery: `"mdns"` advertises `_seagent._tcp.local`, `"off"` does not; empty (the
    /// default) = on exactly when `[app.exposure] lan = true`.
    pub discovery: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig { enabled: false, listen: d_listen(), token: None, allow_origins: vec![], ui: true, openai_api: false, nodes: false, a2a: a2a::A2aConfig::default(), max_conns: d_conns(), workspace: None, terminal: false, auth: dashboard_auth::AuthConfig::default(), tokens: vec![], exposure: exposure::ExposureConfig::default(), rbac: None, metrics_public: false, scim: false, discovery: String::new() }
    }
}

impl AppConfig {
    pub fn parse(t: &toml::Table) -> Result<AppConfig, String> {
        let mut c = AppConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[app]: {e}"))?;
        if c.token.as_deref().is_none_or(|t| t.trim().is_empty()) {
            c.token = std::env::var("SEAGENT_APP_TOKEN").ok().filter(|t| !t.trim().is_empty());
        }
        if std::env::var("SEAGENT_APP_ENABLED").is_ok_and(|v| v == "1" || v == "true") {
            c.enabled = true;
        }
        // A scoped token that names no scope, or a scope nobody implements, is a config error
        // rather than a silently weaker or stronger credential.
        for (i, tok) in c.tokens.iter_mut().enumerate() {
            if tok.token.trim().is_empty() {
                return Err(format!("[app] tokens[{i}] has an empty token"));
            }
            // `scope` takes a scope (read/write/approve/admin) or a role (operator/auditor/user).
            let norm = match exposure::Scope::parse(&tok.scope) {
                Ok(scope) => scope.as_str().to_string(),
                Err(e) => match identity::Role::parse(&tok.scope) {
                    Ok(r) => r.as_str().to_string(),
                    Err(_) => return Err(format!("[app] tokens[{i}]: {e} (or a role: operator, auditor, user)")),
                },
            };
            if tok.name.as_deref().is_some_and(|n| n.trim().is_empty()) {
                tok.name = None;
            }
            tok.scope = norm;
        }
        if c.exposure.node_identities.iter().any(|n| n.trim().is_empty() || n.trim() == "*") {
            return Err("[app.exposure] node_identities: every entry must name an identity (a bare `*` would let any certificate pair as a node)".into());
        }
        for (i, ci) in c.exposure.client_identities.iter().enumerate() {
            if ci.id.trim().is_empty() || ci.id.trim() == "*" {
                return Err(format!("[app.exposure] client_identities[{i}]: `id` must name a certificate identity (a bare `*` would admit every certificate)"));
            }
            if exposure::Scope::parse(&ci.scope).is_err() && identity::Role::parse(&ci.scope).is_err() {
                return Err(format!("[app.exposure] client_identities[{i}]: unknown scope/role `{}`", ci.scope));
            }
        }
        if let Some(rb) = &c.rbac {
            rb.validate()?;
        }
        c.exposure.proxy_auth.validate()?;
        if let Some(bad) = c.exposure.allow_sources.iter().find(|r| !exposure::valid_rule(r)) {
            return Err(format!("[app.exposure] allow_sources: `{bad}` is not an IP address or CIDR"));
        }
        if c.exposure.device_access_ttl_min == 0 || c.exposure.device_access_ttl_min > 24 * 60 {
            return Err("[app.exposure] device_access_ttl_min must be 1–1440".into());
        }
        if !matches!(c.discovery.trim(), "" | "auto" | "mdns" | "off") {
            return Err(format!("[app] discovery = `{}`: use \"mdns\" or \"off\" (empty = on in LAN mode)", c.discovery));
        }
        Ok(c)
    }
}
