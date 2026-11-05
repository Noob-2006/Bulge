//! ark-app: one protocol for every face of ark.
//!
//! ARP (ark remote protocol, JSON-RPC 2.0) is served by the daemon on its unix
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
pub mod logbook;
pub mod conversations;
pub mod cron_fire;
pub mod dashboard_auth;
pub mod node;
pub mod openai;
pub mod qr;
pub mod server;
pub mod session_share;
pub mod surfaces;
pub mod tui;
pub mod ui;

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
    /// Bearer token (usually `{{secret:APP_TOKEN}}`); required. Falls back to `$ARK_APP_TOKEN`
    /// (containers), and `$ARK_APP_ENABLED=1` turns the server on.
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
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig { enabled: false, listen: d_listen(), token: None, allow_origins: vec![], ui: true, openai_api: false, nodes: false, a2a: a2a::A2aConfig::default(), max_conns: d_conns(), workspace: None, terminal: false, auth: dashboard_auth::AuthConfig::default(), tokens: vec![], exposure: exposure::ExposureConfig::default() }
    }
}

impl AppConfig {
    pub fn parse(t: &toml::Table) -> Result<AppConfig, String> {
        let mut c = AppConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[app]: {e}"))?;
        if c.token.as_deref().is_none_or(|t| t.trim().is_empty()) {
            c.token = std::env::var("ARK_APP_TOKEN").ok().filter(|t| !t.trim().is_empty());
        }
        if std::env::var("ARK_APP_ENABLED").is_ok_and(|v| v == "1" || v == "true") {
            c.enabled = true;
        }
        // A scoped token that names no scope, or a scope nobody implements, is a config error
        // rather than a silently weaker or stronger credential.
        for (i, tok) in c.tokens.iter_mut().enumerate() {
            if tok.token.trim().is_empty() {
                return Err(format!("[app] tokens[{i}] has an empty token"));
            }
            let scope = exposure::Scope::parse(&tok.scope).map_err(|e| format!("[app] tokens[{i}]: {e}"))?;
            if tok.name.as_deref().is_some_and(|n| n.trim().is_empty()) {
                tok.name = None;
            }
            tok.scope = scope.as_str().to_string();
        }
        Ok(c)
    }
}
