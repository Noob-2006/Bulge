//! ark-plugin: the outward protocols. An MCP client (stdio + Streamable HTTP)
//! whose tools appear to the kernel as ordinary `ark_core::Tool`s, an MCP
//! server that exposes Ark's tools to other agents, and the plugin protocol
//! (MCP plus hooks and channels, see [`plugin`]).

pub mod bridge;
pub mod mcp;
pub mod plugin;
pub mod server;
mod transport;

pub use bridge::{McpTool, PromptInfo, Registry};
pub use mcp::{CallResult, Client, ToolDef};
pub use plugin::{HookDecision, PluginHost};
pub use server::{serve, ServerInfo};
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
    pub headers: BTreeMap<String, String>,
    pub enabled: bool,
    /// Per-request timeout; startup uses min(this, 10s).
    pub timeout_secs: Option<u64>,
    /// Only expose these remote tool names.
    pub tools: Option<Vec<String>>,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        McpServerConfig { command: None, args: vec![], env: BTreeMap::new(), cwd: None, url: None, headers: BTreeMap::new(), enabled: true, timeout_secs: None, tools: None }
    }
}

impl McpServerConfig {
    pub fn validate(&self, name: &str) -> Result<(), String> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!("mcp server name `{name}`: use letters, digits, `_` or `-`"));
        }
        if name.contains("__") {
            return Err(format!("mcp server name `{name}` must not contain `__` (it separates tool names)"));
        }
        match (&self.command, &self.url) {
            (Some(c), None) if !c.trim().is_empty() => Ok(()),
            (None, Some(u)) if u.starts_with("http://") || u.starts_with("https://") => Ok(()),
            (None, Some(u)) => Err(format!("[mcp.{name}] url `{u}` must start with http:// or https://")),
            (Some(_), Some(_)) => Err(format!("[mcp.{name}] set either `command` or `url`, not both")),
            _ => Err(format!("[mcp.{name}] needs `command` (stdio) or `url` (HTTP)")),
        }
    }
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.unwrap_or(60).max(1))
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
