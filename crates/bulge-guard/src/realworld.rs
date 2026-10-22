//! Real-world actions: payments, orders, irreversible messages.
//!
//! MCP tools run on the host and can do anything their server does, and the
//! egress gateway can reach public payment/checkout APIs even in allow-public
//! mode. These are always marked for a human: a tool rule returns [`Effect::Ask`]
//! (which the driver fails closed on), and the gateway asks or denies by host.
//!
//! The policy is user-tunable through `~/.bulge/real_world.json`:
//! `{"tools": [glob, ...], "hosts": [suffix, ...]}`. A missing key keeps the
//! built-in defaults for that key; a malformed file is an error so the caller
//! can refuse to start rather than silently widening the boundary.

use std::path::Path;

use crate::{Effect, Rule};
use crate::wildcard::matches;

/// What counts as a real-world action.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RealWorldPolicy {
    pub tools: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialPolicy {
    #[serde(default)]
    tools: Option<Vec<String>>,
    #[serde(default)]
    hosts: Option<Vec<String>>,
}

/// Default tool globs. They target MCP tools: built-in VM tools are already
/// contained by the sandbox, while MCP servers run on the host.
const DEFAULT_TOOLS: &[&str] = &[
    "mcp__*pay*",
    "mcp__*charge*",
    "mcp__*checkout*",
    "mcp__*purchase*",
    "mcp__*order*",
    "mcp__*transfer*",
    "mcp__*refund*",
    "mcp__*invoice*",
    "mcp__*send_email*",
    "mcp__*send_mail*",
    "mcp__*send_message*",
    "mcp__*sms*",
    "mcp__*tweet*",
    "mcp__*publish*",
    "mcp__*submit*",
    "mcp__*sign*",
    "mcp__*delete_account*",
];

/// Default host suffixes: payment, checkout, and wallet services.
const DEFAULT_HOSTS: &[&str] = &[
    "stripe.com",
    "paypal.com",
    "paypalobjects.com",
    "braintreegateway.com",
    "adyen.com",
    "squareup.com",
    "checkout.com",
    "klarna.com",
    "afterpay.com",
    "alipay.com",
    "pay.weixin.qq.com",
    "razorpay.com",
    "mollie.com",
    "authorize.net",
    "worldpay.com",
    "payoneer.com",
    "wise.com",
    "coinbase.com",
    "binance.com",
];

impl RealWorldPolicy {
    /// The built-in defaults (used when the file is absent or a key is omitted).
    pub fn defaults() -> Self {
        Self {
            tools: DEFAULT_TOOLS.iter().map(|tool| (*tool).to_owned()).collect(),
            hosts: DEFAULT_HOSTS.iter().map(|host| (*host).to_owned()).collect(),
        }
    }

    /// Load the policy from `path`, or the defaults when the file does not exist.
    /// A malformed file (bad JSON, wrong types, unknown keys) is an error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::defaults()),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        let partial: PartialPolicy = serde_json::from_str(&text)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        let defaults = Self::defaults();
        Ok(Self {
            tools: partial.tools.unwrap_or(defaults.tools),
            hosts: partial.hosts.unwrap_or(defaults.hosts),
        })
    }

    /// Guard rules for real-world tool calls. Append these LAST: last-match-wins
    /// means they override an earlier allow-all rule.
    pub fn rules(&self) -> Vec<Rule> {
        self.tools
            .iter()
            .map(|tool| Rule::new(tool.clone(), "*", Effect::Ask))
            .collect()
    }

    /// Whether `host` belongs to a real-world service. The match is on a label
    /// boundary (`stripe.com` matches `api.stripe.com`, not `notstripe.com`).
    pub fn host_is_real_world(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().any(|suffix| {
            let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
            suffix == "*" || (!suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}"))))
        })
    }

    /// Whether `tool` is a real-world action by name.
    pub fn tool_is_real_world(&self, tool: &str) -> bool {
        self.tools.iter().any(|glob| matches(tool, glob))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Effect, Rule, evaluate};

    #[test]
    fn defaults_are_non_empty() {
        let policy = RealWorldPolicy::defaults();
        assert!(!policy.tools.is_empty());
        assert!(!policy.hosts.is_empty());
    }

    #[test]
    fn rules_win_after_allow_all() {
        let base = vec![Rule::new("*", "*", Effect::Allow)];
        let mut rules = base.clone();
        rules.extend(RealWorldPolicy::defaults().rules());
        assert_eq!(evaluate("mcp__shop__create_order", "", &[&rules]), Effect::Ask);
        assert_eq!(evaluate("mcp__docs__search", "", &[&rules]), Effect::Allow);
        assert_eq!(evaluate("mcp__docs__search", "", &[&base]), Effect::Allow);
    }

    #[test]
    fn hosts_match_on_a_label_boundary() {
        let policy = RealWorldPolicy::defaults();
        assert!(policy.host_is_real_world("api.stripe.com"));
        assert!(policy.host_is_real_world("stripe.com"));
        assert!(policy.host_is_real_world("API.STRIPE.COM."));
        assert!(!policy.host_is_real_world("notstripe.com"));
        assert!(!policy.host_is_real_world("stripe.com.attacker.net"));
        let all = RealWorldPolicy { tools: Vec::new(), hosts: vec!["*".into()] };
        assert!(all.host_is_real_world("anything.example"));
    }

    #[test]
    fn load_missing_keys_falls_back_and_malformed_is_err() {
        let dir = std::env::temp_dir().join(format!("bulge-realworld-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let missing = dir.join("missing.json");
        assert_eq!(RealWorldPolicy::load(&missing).unwrap(), RealWorldPolicy::defaults());

        let tools_only = dir.join("tools.json");
        std::fs::write(&tools_only, r#"{"tools":["mcp__custom__pay"]}"#).unwrap();
        let policy = RealWorldPolicy::load(&tools_only).unwrap();
        assert_eq!(policy.tools, vec!["mcp__custom__pay".to_string()]);
        assert_eq!(policy.hosts, RealWorldPolicy::defaults().hosts);

        let hosts_only = dir.join("hosts.json");
        std::fs::write(&hosts_only, r#"{"hosts":["example-pay.test"]}"#).unwrap();
        let policy = RealWorldPolicy::load(&hosts_only).unwrap();
        assert_eq!(policy.hosts, vec!["example-pay.test".to_string()]);
        assert_eq!(policy.tools, RealWorldPolicy::defaults().tools);

        let malformed = dir.join("malformed.json");
        std::fs::write(&malformed, "{not json").unwrap();
        assert!(RealWorldPolicy::load(&malformed).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
