//! Where automation results go (cron runs, heartbeats, kanban notifications,
//! outbound webhooks). The kernel stays network-free: the host (the `seagent`
//! binary) installs one `Sender` that knows the configured channels and how
//! to POST a webhook; everything in the kernel just calls `deliver`.
//!
//! Target grammar (Hermes `deliver=` / OpenClaw `delivery`):
//! - `local` — keep the result in the session only (no delivery)
//! - `origin` — back to wherever the job was created from (resolved by the caller)
//! - `<channel>` — the channel's `default_chat`
//! - `<channel>:<chat>` / `<channel>:<chat>:<thread>`
//! - `webhook:<url>` or a bare `http(s)://` URL; `secret` signs the body (HMAC-SHA256)

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Local,
    Origin,
    Channel {
        name: String,
        #[serde(default)]
        chat: Option<String>,
        #[serde(default)]
        thread: Option<String>,
    },
    Webhook {
        url: String,
        /// Secret for the `X-Seagent-Signature: sha256=<hex>` header (may be a `{{secret:NAME}}` reference).
        #[serde(default)]
        secret: Option<String>,
    },
}

impl Target {
    /// Parse the textual form (see module docs).
    pub fn parse(s: &str) -> Result<Target, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty delivery target".into());
        }
        match s {
            "local" | "none" => return Ok(Target::Local),
            "origin" => return Ok(Target::Origin),
            _ => {}
        }
        let url = s.strip_prefix("webhook:").unwrap_or(s);
        if url.starts_with("http://") || url.starts_with("https://") {
            return Ok(Target::Webhook { url: url.to_string(), secret: None });
        }
        if s.starts_with("webhook:") {
            return Err(format!("webhook target needs an http(s) URL, got `{url}`"));
        }
        let mut it = s.splitn(3, ':');
        let name = it.next().unwrap_or("").trim().to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            return Err(format!("bad delivery target `{s}` (expected local, origin, <channel>[:<chat>[:<thread>]] or a webhook URL)"));
        }
        let nz = |x: Option<&str>| x.map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        Ok(Target::Channel { name, chat: nz(it.next()), thread: nz(it.next()) })
    }

    /// Back to the textual form.
    pub fn render(&self) -> String {
        match self {
            Target::Local => "local".into(),
            Target::Origin => "origin".into(),
            Target::Channel { name, chat, thread } => match (chat, thread) {
                (Some(c), Some(t)) => format!("{name}:{c}:{t}"),
                (Some(c), None) => format!("{name}:{c}"),
                _ => name.clone(),
            },
            Target::Webhook { url, .. } => url.clone(),
        }
    }
}

/// What is delivered. Channels get `text`; webhooks get the JSON
/// `{"event", "text", "data", "ts"}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    /// Dotted event name, e.g. `cron.finished`, `heartbeat`, `hook.pre_tool`.
    pub event: String,
    pub text: String,
    #[serde(default)]
    pub data: Value,
}

impl Payload {
    pub fn new(event: &str, text: impl Into<String>) -> Self {
        Payload { event: event.into(), text: text.into(), data: Value::Null }
    }
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }
}

/// Installed by the host. Returns a short receipt ("sent to telegram/42", "HTTP 200").
pub type Sender = Arc<dyn Fn(&Target, &Payload) -> Result<String, String> + Send + Sync>;

struct Host {
    sender: Sender,
    channels: Vec<String>,
}

static HOST: RwLock<Option<Host>> = RwLock::new(None);

/// Install the delivery host (once per process; a second call replaces the first).
pub fn install(sender: Sender, channels: Vec<String>) {
    *HOST.write().unwrap() = Some(Host { sender, channels });
}

/// Names of the channels the host can deliver to (empty when no host is installed).
pub fn channels() -> Vec<String> {
    HOST.read().unwrap().as_ref().map(|h| h.channels.clone()).unwrap_or_default()
}

pub fn installed() -> bool {
    HOST.read().unwrap().is_some()
}

/// Deliver `payload` to `target`. `Local` is a no-op; `Origin` must be resolved by
/// the caller first.
pub fn deliver(target: &Target, payload: &Payload) -> Result<String, String> {
    match target {
        Target::Local => return Ok("kept local".into()),
        Target::Origin => return Err("`origin` must be resolved to a concrete target before delivery".into()),
        _ => {}
    }
    let sender = HOST.read().unwrap().as_ref().map(|h| h.sender.clone());
    match sender {
        Some(s) => s(target, payload),
        None => Err("no delivery host in this process (channels and webhooks are available under `seagent daemon run`, `seagent chat`, `seagent run`)".into()),
    }
}

/// Validate a target against the installed channels (when a host is installed).
pub fn validate(target: &Target) -> Result<(), String> {
    if let Target::Channel { name, .. } = target {
        let ch = channels();
        if installed() && !ch.iter().any(|c| c == name) {
            return Err(format!("unknown channel `{name}`; configured: {}", if ch.is_empty() { "(none)".to_string() } else { ch.join(", ") }));
        }
    }
    Ok(())
}

/// `sha256=<hex>` signature of `body` (for the `X-Seagent-Signature` header); the
/// host does the actual HMAC so the kernel needs no crypto dependency.
pub const SIGNATURE_HEADER: &str = "X-Seagent-Signature";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_targets() {
        assert_eq!(Target::parse("local").unwrap(), Target::Local);
        assert_eq!(Target::parse("origin").unwrap(), Target::Origin);
        assert_eq!(Target::parse("tg").unwrap(), Target::Channel { name: "tg".into(), chat: None, thread: None });
        assert_eq!(Target::parse("tg:-100:7").unwrap(), Target::Channel { name: "tg".into(), chat: Some("-100".into()), thread: Some("7".into()) });
        assert_eq!(Target::parse("https://x.test/h").unwrap(), Target::Webhook { url: "https://x.test/h".into(), secret: None });
        assert_eq!(Target::parse("webhook:http://127.0.0.1:9/h").unwrap().render(), "http://127.0.0.1:9/h");
        assert!(Target::parse("webhook:ftp://x").is_err());
        assert!(Target::parse("").is_err());
        assert!(Target::parse("bad name").is_err());
        for s in ["local", "origin", "tg", "tg:1", "tg:1:2"] {
            assert_eq!(Target::parse(s).unwrap().render(), s);
        }
        assert!(deliver(&Target::Local, &Payload::new("x", "y")).is_ok());
        assert!(deliver(&Target::Origin, &Payload::new("x", "y")).is_err());
    }
}
