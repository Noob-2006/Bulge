//! `channel_send`: lets the agent proactively message a human. Declared as a
//! `Send` effect so the egress gate inspects the text before it leaves.

use crate::{Channel, Outbound};
use ark_core::tool::{arg_opt_str, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct Target {
    pub channel: Arc<dyn Channel>,
    pub default_chat: Option<String>,
}

pub struct ChannelSend {
    targets: BTreeMap<String, Target>,
}

impl ChannelSend {
    pub fn new(targets: BTreeMap<String, Target>) -> Self {
        ChannelSend { targets }
    }

    fn pick(&self, input: &Value) -> Result<(&str, &Target), String> {
        let names = || self.targets.keys().cloned().collect::<Vec<_>>().join(", ");
        match arg_opt_str(input, "channel") {
            Some(n) => self.targets.get_key_value(n).map(|(k, t)| (k.as_str(), t)).ok_or_else(|| format!("unknown channel `{n}`; configured: {}", names())),
            None if self.targets.len() == 1 => Ok(self.targets.iter().next().map(|(k, t)| (k.as_str(), t)).unwrap()),
            None if self.targets.is_empty() => Err("no channels are configured".into()),
            None => Err(format!("several channels configured; pass `channel` (one of: {})", names())),
        }
    }
}

impl Tool for ChannelSend {
    fn spec(&self) -> ToolSpec {
        let names: Vec<&String> = self.targets.keys().collect();
        ToolSpec {
            name: "channel_send".into(),
            description: format!("Send a plain-text message to a human over a chat channel (configured: {names:?}). Use for progress reports or results of long unattended work; ordinary replies go back automatically."),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": "Channel name; optional when only one is configured"},
                    "chat": {"type": "string", "description": "Chat id; defaults to the channel's default_chat"},
                    "text": {"type": "string"}
                },
                "required": ["text"]
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let channel = self.pick(input).map(|(n, _)| n.to_string()).unwrap_or_else(|_| arg_opt_str(input, "channel").unwrap_or("?").to_string());
        vec![Effect::Send { channel, payload: arg_opt_str(input, "text").unwrap_or("").to_string() }]
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let text = match arg_str(&input, "text") {
            Ok(t) if !t.trim().is_empty() => t,
            Ok(_) => return ToolOutput::err("`text` is empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let (name, target) = match self.pick(&input) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let Some(chat) = arg_opt_str(&input, "chat").map(str::to_string).or_else(|| target.default_chat.clone()) else {
            return ToolOutput::err(format!("pass `chat`: channel `{name}` has no default_chat"));
        };
        // Secrets are deliberately NOT substituted: humans' chats are outside the vault's trust boundary.
        match target.channel.send(&Outbound::text(&chat, text)) {
            Ok(_) => ToolOutput::ok(format!("sent {} chars to {name}/{chat}", text.chars().count())),
            Err(e) => ToolOutput::err(format!("send to {name}/{chat} failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelError, ChannelErrorKind, Inbound};
    use ark_core::tool::SpawnRequest;
    use ark_core::{Cancel, ToolHost};
    use std::sync::Mutex;

    struct Rec(Mutex<Vec<Outbound>>, bool);
    impl Channel for Rec {
        fn id(&self) -> &str {
            "rec"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, o: &Outbound) -> Result<crate::Sent, ChannelError> {
            if self.1 {
                return Err(ChannelError::new(ChannelErrorKind::Auth, "revoked"));
            }
            self.0.lock().unwrap().push(o.clone());
            Ok(crate::Sent::default())
        }
    }
    struct NoHost;
    impl ToolHost for NoHost {
        fn spawn_agent(&self, _: SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }
    fn ctx() -> ToolCtx {
        ToolCtx { workspace: "/tmp".into(), session_id: "s".into(), artifacts: "/tmp".into(), home: "/tmp".into(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.replace("{{secret:K}}", "LEAK")) }
    }

    #[test]
    fn sends_with_defaults_and_reports_errors() {
        let ok = Arc::new(Rec(Mutex::new(vec![]), false));
        let mut t = BTreeMap::new();
        t.insert("phone".to_string(), Target { channel: ok.clone(), default_chat: Some("42".into()) });
        let tool = ChannelSend::new(t);
        assert!(!tool.spec().pinned);
        let r = tool.call(&ctx(), json!({"text": "done {{secret:K}}"}));
        assert!(!r.is_error, "{}", r.content);
        let sent = ok.0.lock().unwrap().clone();
        assert_eq!((sent[0].chat.as_str(), sent[0].text.as_str()), ("42", "done {{secret:K}}"), "default chat; secrets not expanded");
        assert_eq!(tool.effects(&ctx(), &json!({"text": "hi"})), vec![Effect::Send { channel: "phone".into(), payload: "hi".into() }]);
        assert!(tool.call(&ctx(), json!({"text": " "})).is_error);
        assert!(tool.call(&ctx(), json!({})).is_error);
        assert!(tool.call(&ctx(), json!({"channel": "nope", "text": "x"})).content.contains("phone"));

        let bad = Arc::new(Rec(Mutex::new(vec![]), true));
        let mut t = BTreeMap::new();
        t.insert("a".to_string(), Target { channel: ok, default_chat: None });
        t.insert("b".to_string(), Target { channel: bad, default_chat: Some("1".into()) });
        let tool = ChannelSend::new(t);
        assert!(tool.call(&ctx(), json!({"text": "x"})).content.contains("several channels"));
        assert!(tool.call(&ctx(), json!({"channel": "a", "text": "x"})).content.contains("default_chat"));
        let r = tool.call(&ctx(), json!({"channel": "b", "text": "x"}));
        assert!(r.is_error && r.content.contains("revoked"));
        assert!(ChannelSend::new(BTreeMap::new()).call(&ctx(), json!({"text": "x"})).content.contains("no channels"));
    }
}
