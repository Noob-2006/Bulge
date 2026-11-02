//! ark-plugin: the outward protocols. An MCP client (stdio + Streamable HTTP)
//! whose tools appear to the kernel as ordinary `ark_core::Tool`s, an MCP
//! server that exposes Ark's tools to other agents, and the plugin protocol
//! (MCP plus hooks, middleware, channels, commands, CLI, HTTP routes, UI panels,
//! model providers, context engines, memory providers, node commands and services,
//! see [`plugin`]).

pub mod bridge;
pub mod events;
pub mod mcp;
pub mod oauth;
pub mod plugin;
pub mod relay;
pub mod schema;
pub mod server;
mod transport;

pub use bridge::{LoadOpts, McpTool, PromptInfo, Registry};
pub use mcp::{CallResult, Client, ToolDef};
pub use plugin::{CliReply, CommandDecl, CommandReply, EngineDecl, HookDecision, HttpReply, NodeCommandDecl, PluginHost, PluginMemory, PluginProvider, ProviderDecl, RouteDecl, ServiceDecl, UiDecl};
pub use server::{serve, Server, ServerInfo};
pub use transport::Notify;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolves `{{secret:NAME}}` references (the vault's `substitute`).
pub type Secrets = Arc<dyn Fn(&str) -> String + Send + Sync>;

pub fn no_secrets() -> Secrets {
    Arc::new(|s: &str| s.to_string())
}

/// One MCP server (or plugin) as written in config: exactly one of `command` / `url`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServerConfig {
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub url: Option<String>,
    /// For `url`: "http" (Streamable HTTP, default) or "sse" (legacy 2024-11-05 HTTP+SSE).
    pub transport: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub enabled: bool,
    /// Per-request timeout; startup uses min(this, 10s).
    pub timeout_secs: Option<u64>,
    /// Only expose these remote tool names (`*` globs allowed).
    pub tools: Option<Vec<String>>,
    /// Never expose these remote tool names (`*` globs allowed).
    pub exclude_tools: Vec<String>,
    /// `"oauth"`: OAuth 2.1 per the MCP authorization spec (`ark mcp login <name>`).
    pub auth: Option<String>,
    pub oauth: oauth::OAuthConfig,
    /// TLS: extra CA bundle (PEM), client certificate + key for mTLS, or `false` to skip verification.
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub ssl_verify: bool,
    /// `"full"` (default) or `"untrusted"`: tools without readOnlyHint need approval.
    pub trust: Option<String>,
    /// Let the server ask our model for completions (sampling/createMessage).
    pub sampling: SamplingConfig,
    /// Let the server ask the user structured questions (elicitation/create).
    pub elicitation: bool,
    /// Directories exposed through roots/list (default: the workspace).
    pub roots: Vec<PathBuf>,
    /// Ping a live server this often; a failed ping restarts it on the next call.
    pub keepalive_secs: Option<u64>,
    /// Shut an idle server down after this long; restart it after this lifetime.
    pub idle_timeout_secs: Option<u64>,
    pub max_lifetime_secs: Option<u64>,
    /// Price per call by tool name (`*` = default), and a per-session ceiling.
    pub tool_costs: BTreeMap<String, f64>,
    pub spend_limit: Option<f64>,
    pub cost_unit: Option<String>,
    /// Protocol era: "auto" (handshake first, `server/discover` on a modern-only answer),
    /// "legacy" (2025-11-25 and older only) or "stateless" (2026-07-28 first).
    pub protocol: Option<String>,
    /// Run `taskSupport = "optional"` tools as tasks too ("required" ones always are).
    pub tasks: bool,
    /// Upper bound for one task (and a URL elicitation) to finish.
    pub task_timeout_secs: Option<u64>,
    /// MCP Apps: advertise `io.modelcontextprotocol/ui` and render `ui://` results.
    pub apps: bool,
    /// MCP events extension (`events/*`, webhook delivery); needs `events_url`.
    pub events: bool,
    /// Public HTTPS base the server POSTs events to (ark's app server `/mcp-events`).
    pub events_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamplingConfig {
    pub enabled: bool,
    /// Requests per minute (sliding window).
    pub max_rpm: u32,
    pub max_tokens_cap: u32,
    pub timeout_secs: u64,
    /// Model to use (provider/model); default: the session's aux model.
    pub model: Option<String>,
    /// Model hints the server may pick from; empty = ignore hints.
    pub allowed_models: Vec<String>,
    /// Accept `tools` / `toolChoice` in requests (advertised as `sampling.tools`).
    pub tools: bool,
    /// Assistant tool-use turns one sampling conversation may contain.
    pub max_tool_rounds: u32,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        SamplingConfig { enabled: false, max_rpm: 10, max_tokens_cap: 4096, timeout_secs: 30, model: None, allowed_models: vec![], tools: true, max_tool_rounds: 8 }
    }
}

impl Default for McpServerConfig {
    fn default() -> Self {
        McpServerConfig {
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            cwd: None,
            url: None,
            transport: None,
            headers: BTreeMap::new(),
            enabled: true,
            timeout_secs: None,
            tools: None,
            exclude_tools: vec![],
            auth: None,
            oauth: oauth::OAuthConfig::default(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            ssl_verify: true,
            trust: None,
            sampling: SamplingConfig::default(),
            elicitation: true,
            roots: vec![],
            keepalive_secs: None,
            idle_timeout_secs: None,
            max_lifetime_secs: None,
            tool_costs: BTreeMap::new(),
            spend_limit: None,
            cost_unit: None,
            protocol: None,
            tasks: false,
            task_timeout_secs: None,
            apps: true,
            events: false,
            events_url: None,
        }
    }
}

/// `*`-glob match (only `*` is special).
pub fn glob_match(pat: &str, s: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == s;
    }
    let mut rest = s;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(p) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i + 1 == parts.len() {
            return rest.ends_with(p);
        } else if let Some(j) = rest.find(p) {
            rest = &rest[j + p.len()..];
        } else {
            return false;
        }
    }
    true
}

impl McpServerConfig {
    pub fn validate(&self, name: &str) -> Result<(), String> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!("mcp server name `{name}`: use letters, digits, `_` or `-`"));
        }
        if name.contains("__") {
            return Err(format!("mcp server name `{name}` must not contain `__` (it separates tool names)"));
        }
        if let Some(p) = self.protocol.as_deref().filter(|p| !matches!(*p, "auto" | "legacy" | "handshake" | "stateless" | "modern" | mcp::MODERN)) {
            return Err(format!("[mcp.{name}] protocol `{p}`: use \"auto\", \"legacy\" or \"stateless\""));
        }
        if let Some(u) = self.events_url.as_deref().filter(|u| !u.starts_with("https://") && !u.starts_with("http://127.0.0.1") && !u.starts_with("http://localhost")) {
            return Err(format!("[mcp.{name}] events_url `{u}` must be https:// (servers refuse plain-HTTP callbacks)"));
        }
        match (&self.command, &self.url) {
            (Some(c), None) if !c.trim().is_empty() => Ok(()),
            (None, Some(u)) if u.starts_with("http://") || u.starts_with("https://") => match self.transport.as_deref() {
                None | Some("http") | Some("streamable-http") | Some("sse") => match self.auth.as_deref() {
                    None | Some("oauth") => Ok(()),
                    Some(a) => Err(format!("[mcp.{name}] auth `{a}`: only \"oauth\" is supported (use headers for static tokens)")),
                },
                Some(t) => Err(format!("[mcp.{name}] transport `{t}`: use \"http\" or \"sse\"")),
            },
            (None, Some(u)) => Err(format!("[mcp.{name}] url `{u}` must start with http:// or https://")),
            (Some(_), Some(_)) => Err(format!("[mcp.{name}] set either `command` or `url`, not both")),
            _ => Err(format!("[mcp.{name}] needs `command` (stdio) or `url` (HTTP)")),
        }
    }
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.unwrap_or(60).max(1))
    }
    pub fn uses_oauth(&self) -> bool {
        self.auth.as_deref() == Some("oauth")
    }
    pub fn untrusted(&self) -> bool {
        self.trust.as_deref() == Some("untrusted")
    }
    /// Is this remote tool exposed under `tools` / `exclude_tools`?
    pub fn exposes(&self, tool: &str) -> bool {
        let inc = self.tools.as_ref().is_none_or(|l| l.iter().any(|p| glob_match(p, tool)));
        inc && !self.exclude_tools.iter().any(|p| glob_match(p, tool))
    }
    /// Price of one call, if configured.
    pub fn cost_of(&self, tool: &str) -> Option<f64> {
        self.tool_costs.get(tool).or_else(|| self.tool_costs.iter().find(|(p, _)| p.contains('*') && glob_match(p, tool)).map(|(_, v)| v)).copied()
    }
}

/// Stable FNV-1a hash (cache keys survive rebuilds, unlike DefaultHasher).
pub(crate) fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3))
}

/// `mcp__{server}__{tool}` restricted to `[A-Za-z0-9_-]` and 64 chars; long or
/// colliding names get a short hash suffix so they stay unique and stable.
pub fn tool_name(server: &str, tool: &str, taken: &mut std::collections::HashSet<String>) -> String {
    let clean = |s: &str| s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect::<String>();
    let mut n = format!("mcp__{}__{}", clean(server), clean(tool));
    if n.len() > 64 || taken.contains(&n) {
        let suffix = format!("_{:06x}", fnv(format!("{server}\0{tool}").as_bytes()) & 0xff_ffff);
        n.truncate(64 - suffix.len());
        n.push_str(&suffix);
    }
    taken.insert(n.clone());
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_are_sanitized_capped_and_unique() {
        let mut t = HashSet::new();
        assert_eq!(tool_name("gh", "list.issues", &mut t), "mcp__gh__list_issues");
        let dup = tool_name("gh", "list issues", &mut t);
        assert_ne!(dup, "mcp__gh__list_issues");
        assert!(dup.starts_with("mcp__gh__list_issues_"));
        let long = tool_name("srv", &"x".repeat(100), &mut t);
        assert_eq!(long.len(), 64);
        assert_eq!(long, tool_name("srv", &"x".repeat(100), &mut HashSet::new()), "stable");
        assert!(tool_name("s", "日本語", &mut t).is_ascii());
    }

    #[test]
    fn config_validation() {
        let ok = McpServerConfig { command: Some("x".into()), ..Default::default() };
        assert!(ok.validate("fs").is_ok());
        assert!(ok.validate("a__b").is_err());
        assert!(ok.validate("a b").is_err());
        let both = McpServerConfig { command: Some("x".into()), url: Some("http://a".into()), ..Default::default() };
        assert!(both.validate("x").unwrap_err().contains("not both"));
        assert!(McpServerConfig::default().validate("x").unwrap_err().contains("needs"));
        let bad = McpServerConfig { url: Some("ftp://a".into()), ..Default::default() };
        assert!(bad.validate("x").is_err());
        let t: McpServerConfig = serde_json::from_value(serde_json::json!({"url": "https://a"})).unwrap();
        assert!(t.enabled, "enabled defaults to true");
        assert!(McpServerConfig::default().enabled);
        assert!(serde_json::from_value::<McpServerConfig>(serde_json::json!({"url": "https://a", "typo": 1})).is_err());
    }
}
