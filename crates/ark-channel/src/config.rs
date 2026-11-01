//! `[channels.<name>]` configuration and construction.
//!
//! ```toml
//! [channels.phone]
//! kind = "telegram"
//! token = "{{secret:TG_TOKEN}}"
//! allow = ["123456789", "@amy"]
//! session_per = "chat"        # or "sender"
//! default_chat = "123456789"  # where channel_send goes when no chat is given
//!
//! [channels.hook]
//! kind = "webhook"
//! listen = "127.0.0.1:8787"
//! token = "{{secret:HOOK_TOKEN}}"
//! outbound_url = "https://example.com/ark"
//! allow = ["*"]
//!
//! [channels.slack]
//! kind = "plugin"
//! plugin = "slack"
//! ```

use crate::router::{RouterConfig, SessionPer};
use crate::telegram::Telegram;
use crate::webhook::{Webhook, WebhookOpts};
use crate::Channel;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub type Secrets = Arc<dyn Fn(&str) -> String + Send + Sync>;

fn d_poll() -> u64 {
    25
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelConfig {
    Telegram {
        token: String,
        #[serde(default)]
        base_url: Option<String>,
        #[serde(default = "d_poll")]
        poll_timeout_secs: u64,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        session_per: SessionPer,
        #[serde(default)]
        default_chat: Option<String>,
    },
    Webhook {
        #[serde(default)]
        listen: Option<String>,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        outbound_url: Option<String>,
        #[serde(default)]
        outbound_token: Option<String>,
        #[serde(default = "d_poll")]
        poll_timeout_secs: u64,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        session_per: SessionPer,
        #[serde(default)]
        default_chat: Option<String>,
    },
    /// Provided by an ark-plugin process; wired by the host, not built here.
    Plugin {
        plugin: String,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        session_per: SessionPer,
        #[serde(default)]
        default_chat: Option<String>,
    },
}

impl ChannelConfig {
    pub fn router(&self) -> RouterConfig {
        let (allow, session_per) = match self {
            ChannelConfig::Telegram { allow, session_per, .. } | ChannelConfig::Webhook { allow, session_per, .. } | ChannelConfig::Plugin { allow, session_per, .. } => (allow, session_per),
        };
        RouterConfig { allow: allow.clone(), session_per: *session_per }
    }
    pub fn default_chat(&self) -> Option<&str> {
        match self {
            ChannelConfig::Telegram { default_chat, .. } | ChannelConfig::Webhook { default_chat, .. } | ChannelConfig::Plugin { default_chat, .. } => default_chat.as_deref(),
        }
    }
}

/// Parse one `[channels.<name>]` table (any serde format via `serde_json::Value`).
pub fn parse_config(name: &str, v: &serde_json::Value) -> Result<ChannelConfig, String> {
    ChannelConfig::deserialize(v).map_err(|e| format!("[channels.{name}]: {e}"))
}

fn secret(name: &str, field: &str, raw: &str, secrets: &Secrets) -> Result<String, String> {
    let v = secrets(raw);
    if v.contains("{{secret:") {
        return Err(format!("channel {name}: the secret referenced by `{field}` is not set (ark secrets set …)"));
    }
    Ok(v)
}

/// Build a channel. `state_dir` holds per-channel state such as the Telegram offset.
pub fn build(name: &str, cfg: &ChannelConfig, state_dir: &Path, secrets: &Secrets) -> Result<Arc<dyn Channel>, String> {
    match cfg {
        ChannelConfig::Telegram { token, base_url, poll_timeout_secs, .. } => {
            let token = secret(name, "token", token, secrets)?;
            Ok(Arc::new(Telegram::new(name, &token, base_url.as_deref(), state_dir.join(format!("{name}.telegram.json")), *poll_timeout_secs)?))
        }
        ChannelConfig::Webhook { listen, token, outbound_url, outbound_token, poll_timeout_secs, .. } => {
            let token = token.as_deref().map(|t| secret(name, "token", t, secrets)).transpose()?;
            let outbound_token = outbound_token.as_deref().map(|t| secret(name, "outbound_token", t, secrets)).transpose()?;
            let outbound_url = outbound_url.as_deref().map(|u| secret(name, "outbound_url", u, secrets)).transpose()?;
            let w = Webhook::new(
                name,
                WebhookOpts { listen: listen.as_deref(), token: token.as_deref(), outbound_url: outbound_url.as_deref(), outbound_token: outbound_token.as_deref(), poll_timeout: Duration::from_secs(*poll_timeout_secs) },
            )?;
            Ok(Arc::new(w))
        }
        ChannelConfig::Plugin { plugin, .. } => Err(format!("channel {name}: provided by plugin `{plugin}`; the plugin host builds it")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use serde_json::json;

    fn secrets() -> Secrets {
        Arc::new(|s: &str| s.replace("{{secret:TG}}", "1:abc").replace("{{secret:HOOK}}", "hooktok"))
    }

    #[test]
    fn parses_all_kinds_with_defaults() {
        let t = parse_config("phone", &json!({"kind": "telegram", "token": "{{secret:TG}}", "allow": ["1"], "session_per": "sender", "default_chat": "1"})).unwrap();
        assert_eq!(t.router(), RouterConfig { allow: vec!["1".into()], session_per: SessionPer::Sender });
        assert_eq!(t.default_chat(), Some("1"));
        assert!(matches!(t, ChannelConfig::Telegram { poll_timeout_secs: 25, .. }));
        let p = parse_config("s", &json!({"kind": "plugin", "plugin": "slack"})).unwrap();
        assert_eq!(p.router().allow, Vec::<String>::new(), "deny by default");
        let e = parse_config("x", &json!({"kind": "carrier-pigeon"})).unwrap_err();
        assert!(e.contains("[channels.x]") && e.contains("carrier-pigeon"), "{e}");
        assert!(parse_config("x", &json!({"token": "t"})).unwrap_err().contains("kind"));
        assert!(parse_config("x", &json!({"kind": "telegram"})).unwrap_err().contains("token"));
        assert!(parse_config("x", &json!({"kind": "telegram", "token": "t", "session_per": "planet"})).is_err());
    }

    #[test]
    fn build_resolves_secrets_and_reports_missing_ones() {
        let d = temp_dir("cfg");
        let s = secrets();
        let t = parse_config("phone", &json!({"kind": "telegram", "token": "{{secret:TG}}"})).unwrap();
        assert_eq!(build("phone", &t, &d, &s).unwrap().id(), "phone");
        let missing = parse_config("phone", &json!({"kind": "telegram", "token": "{{secret:NOPE}}"})).unwrap();
        let e = build("phone", &missing, &d, &s).err().unwrap();
        assert!(e.contains("not set") && !e.contains("1:abc"), "{e}");
        let w = parse_config("hook", &json!({"kind": "webhook", "listen": "127.0.0.1:0", "token": "{{secret:HOOK}}"})).unwrap();
        assert_eq!(build("hook", &w, &d, &s).unwrap().id(), "hook");
        let no_tok = parse_config("hook", &json!({"kind": "webhook", "listen": "127.0.0.1:0"})).unwrap();
        assert!(build("hook", &no_tok, &d, &s).err().unwrap().contains("token"));
        let p = parse_config("s", &json!({"kind": "plugin", "plugin": "slack"})).unwrap();
        assert!(build("s", &p, &d, &s).err().unwrap().contains("plugin"));
    }
}
