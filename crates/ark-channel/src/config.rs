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

use crate::access::Policy;
use crate::router::{RouterConfig, SessionPer};
use crate::{telegram, webhook, Channel};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

pub type Secrets = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// One `[channels.<name>]` table: shared routing/policy fields, plus the
/// kind-specific `settings` each channel module parses (unknown keys are errors there).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub kind: String,
    #[serde(flatten)]
    pub policy: Policy,
    #[serde(default)]
    pub session_per: SessionPer,
    /// Where channel_send goes when no chat is given.
    #[serde(default)]
    pub default_chat: Option<String>,
    /// Sent once to each new sender before their first reply (個資法第 8 條告知).
    #[serde(default)]
    pub privacy_notice: Option<String>,
    /// Appended to every reply, e.g. "— AI 生成" (AI 基本法第 4 條揭露原則).
    #[serde(default)]
    pub ai_label: Option<String>,
    /// `kind = "plugin"`: the plugin that provides this channel.
    #[serde(default)]
    pub plugin: Option<String>,
    /// Stream replies while the model writes (edit in place / native streams) where the
    /// channel supports it. Default on.
    #[serde(default = "yes")]
    pub stream: bool,
    #[serde(flatten)]
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl ChannelConfig {
    pub fn router(&self) -> RouterConfig {
        RouterConfig { policy: self.policy.clone(), session_per: self.session_per, privacy_notice: self.privacy_notice.clone(), ai_label: self.ai_label.clone() }
    }
    pub fn default_chat(&self) -> Option<&str> {
        self.default_chat.as_deref()
    }
    pub fn is_plugin(&self) -> bool {
        self.kind == "plugin"
    }
    /// Webhook-style channels that open a listener (the CLI skips them outside the daemon).
    pub fn listens(&self) -> bool {
        self.settings.get("listen").is_some_and(|v| !v.is_null())
    }
}

fn yes() -> bool {
    true
}

/// Parse one `[channels.<name>]` table (any serde format via `serde_json::Value`).
pub fn parse_config(name: &str, v: &serde_json::Value) -> Result<ChannelConfig, String> {
    let c = ChannelConfig::deserialize(v).map_err(|e| format!("[channels.{name}]: {e}"))?;
    if c.kind != "plugin" && !registry().iter().any(|(k, _)| *k == c.kind) {
        let mut kinds: Vec<&str> = registry().iter().map(|(k, _)| *k).collect();
        kinds.push("plugin");
        return Err(format!("[channels.{name}]: unknown kind `{}`; known: {}", c.kind, kinds.join(", ")));
    }
    if c.is_plugin() && c.plugin.is_none() {
        return Err(format!("[channels.{name}]: kind = \"plugin\" needs `plugin = \"<name>\"`"));
    }
    Ok(c)
}

/// What a channel builder gets.
pub struct Ctx<'a> {
    pub name: &'a str,
    pub state_dir: &'a Path,
    pub secrets: &'a Secrets,
}

impl Ctx<'_> {
    /// Resolve `{{secret:NAME}}` references; error (without the value) when unset.
    pub fn secret(&self, field: &str, raw: &str) -> Result<String, String> {
        let v = (self.secrets)(raw);
        if v.contains("{{secret:") {
            return Err(format!("channel {}: the secret referenced by `{field}` is not set (ark secrets set …)", self.name));
        }
        Ok(v)
    }
    pub fn opt_secret(&self, field: &str, raw: &Option<String>) -> Result<Option<String>, String> {
        raw.as_deref().map(|r| self.secret(field, r)).transpose()
    }
    /// Kind-specific settings into the module's own struct (`deny_unknown_fields` catches typos).
    pub fn settings<T: serde::de::DeserializeOwned>(&self, s: &serde_json::Map<String, serde_json::Value>) -> Result<T, String> {
        T::deserialize(serde_json::Value::Object(s.clone())).map_err(|e| format!("[channels.{}]: {e}", self.name))
    }
    /// Per-channel state file.
    pub fn state(&self, suffix: &str) -> std::path::PathBuf {
        self.state_dir.join(format!("{}.{suffix}", self.name))
    }
}

pub type Builder = fn(&Ctx, &serde_json::Map<String, serde_json::Value>) -> Result<Arc<dyn Channel>, String>;

/// Every built-in channel kind.
pub fn registry() -> Vec<(&'static str, Builder)> {
    vec![
        ("telegram", telegram::build),
        ("webhook", webhook::build),
        ("discord", crate::discord::build),
        ("slack", crate::slack::build),
        ("mattermost", crate::mattermost::build),
        ("matrix", crate::matrix::build),
        ("msteams", crate::msteams::build),
        ("teams", crate::msteams::build),
        ("googlechat", crate::googlechat::build),
        ("google_chat", crate::googlechat::build),
        ("msgraph_webhook", crate::msgraph_webhook::build),
        ("feishu", crate::feishu::build),
        ("lark", lark),
        ("dingtalk", crate::dingtalk::build),
        ("wecom", crate::wecom::build),
        ("wecom_callback", crate::wecom_callback::build),
        ("weixin", crate::weixin::build),
        ("wechat", crate::weixin::build),
        ("qqbot", crate::qqbot::build),
        ("yuanbao", crate::yuanbao::build),
        ("line", crate::line::build),
        ("whatsapp_cloud", crate::whatsapp_cloud::build),
        ("whatsapp", crate::whatsapp::build),
        ("sms", crate::sms::build),
        ("twilio", crate::sms::build),
        ("signal", crate::signal::build),
        ("imessage", crate::imessage::build),
        ("imsg", crate::imessage::build),
        ("bluebubbles", crate::bluebubbles::build),
        ("photon", crate::photon::build),
        ("irc", crate::irc::build),
        ("twitch", crate::twitch::build),
        ("nostr", crate::nostr::build),
        ("buzz", crate::buzz::build),
        ("ntfy", crate::ntfy::build),
        ("simplex", crate::simplex::build),
        ("email", crate::email::build),
        ("imap", crate::email::build),
        ("nextcloud-talk", crate::nextcloud_talk::build),
        ("nextcloud_talk", crate::nextcloud_talk::build),
        ("synology-chat", crate::synology_chat::build),
        ("synology_chat", crate::synology_chat::build),
        ("zalo", crate::zalo::build),
        ("zalouser", crate::zalouser::build),
        ("tlon", crate::tlon::build),
        ("urbit", crate::tlon::build),
        ("x", crate::x::build),
        ("twitter", crate::x::build),
        ("clickclack", crate::clickclack::build),
        ("reef", crate::reef::build),
        ("raft", crate::raft::build),
        ("qa-channel", crate::qa_channel::build),
        ("qa_channel", crate::qa_channel::build),
        ("homeassistant", crate::homeassistant::build),
        ("home_assistant", crate::homeassistant::build),
        ("relay", crate::relay::build),
    ]
}

/// `kind = "lark"`: Feishu's international edition (open.larksuite.com) unless `domain` says otherwise.
fn lark(ctx: &Ctx, s: &serde_json::Map<String, serde_json::Value>) -> Result<Arc<dyn Channel>, String> {
    let mut s = s.clone();
    s.entry("domain").or_insert_with(|| "lark".into());
    crate::feishu::build(ctx, &s)
}

/// Build a channel. `state_dir` holds per-channel state such as the Telegram offset.
pub fn build(name: &str, cfg: &ChannelConfig, state_dir: &Path, secrets: &Secrets) -> Result<Arc<dyn Channel>, String> {
    if cfg.is_plugin() {
        return Err(format!("channel {name}: provided by plugin `{}`; the plugin host builds it", cfg.plugin.as_deref().unwrap_or("")));
    }
    let b = registry().into_iter().find(|(k, _)| *k == cfg.kind).map(|(_, b)| b).ok_or_else(|| format!("channel {name}: unknown kind {}", cfg.kind))?;
    b(&Ctx { name, state_dir, secrets }, &cfg.settings)
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
        let t = parse_config("phone", &json!({"kind": "telegram", "token": "{{secret:TG}}", "allow": ["1"], "session_per": "sender", "default_chat": "1", "dm_policy": "pairing", "privacy_notice": "notice"})).unwrap();
        assert_eq!(t.router(), RouterConfig { policy: Policy { allow: vec!["1".into()], dm_policy: crate::access::DmPolicy::Pairing, ..Policy::default() }, session_per: SessionPer::Sender, privacy_notice: Some("notice".into()), ai_label: None });
        assert_eq!(t.default_chat(), Some("1"));
        assert_eq!(t.settings.get("token").and_then(|v| v.as_str()), Some("{{secret:TG}}"), "kind-specific keys land in settings");
        assert!(!t.settings.contains_key("allow"), "shared keys do not");
        let p = parse_config("s", &json!({"kind": "plugin", "plugin": "slack"})).unwrap();
        assert!(p.router().policy.allow.is_empty(), "deny by default");
        assert!(parse_config("s", &json!({"kind": "plugin"})).unwrap_err().contains("plugin ="));
        let e = parse_config("x", &json!({"kind": "carrier-pigeon"})).unwrap_err();
        assert!(e.contains("[channels.x]") && e.contains("carrier-pigeon") && e.contains("telegram"), "{e}");
        assert!(parse_config("x", &json!({"token": "t"})).unwrap_err().contains("kind"));
        assert!(parse_config("x", &json!({"kind": "telegram", "token": "t", "session_per": "planet"})).is_err());
        assert!(parse_config("x", &json!({"kind": "telegram", "token": "t", "dm_policy": "sometimes"})).is_err());
    }

    #[test]
    fn lark_kind_presets_the_lark_domain() {
        let d = temp_dir("lark");
        let s = secrets();
        let c = parse_config("l", &json!({"kind": "lark", "app_id": "cli", "app_secret": "x"})).unwrap();
        assert!(c.stream, "streaming defaults on");
        assert_eq!(build("l", &c, &d, &s).unwrap().id(), "l");
        // An explicit domain still wins (and is still validated).
        let bad = parse_config("l", &json!({"kind": "lark", "app_id": "cli", "app_secret": "x", "domain": "mars"})).unwrap();
        assert!(build("l", &bad, &d, &s).err().unwrap().contains("mars"));
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
        let typo = parse_config("phone", &json!({"kind": "telegram", "token": "x", "tokn": "y"})).unwrap();
        assert!(build("phone", &typo, &d, &s).err().unwrap().contains("tokn"), "unknown kind-specific keys are rejected at build");
        let missing_tok = parse_config("phone", &json!({"kind": "telegram"})).unwrap();
        assert!(build("phone", &missing_tok, &d, &s).err().unwrap().contains("token"));
        let p = parse_config("s", &json!({"kind": "plugin", "plugin": "slack"})).unwrap();
        assert!(build("s", &p, &d, &s).err().unwrap().contains("plugin"));
    }
}
