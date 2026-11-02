//! ark-channel: human chat channels (Telegram, webhook), the kernel-agnostic
//! router that maps inbound messages to sessions, and the `channel_send` tool.
//! Blocking std threads only; every network wait observes a `Cancel`.

pub mod access;
pub mod charset;
pub mod chunk;
pub mod config;
pub mod dave;
pub mod deliver;
pub mod markup;
pub mod http;
pub mod router;
pub mod telegram;
pub mod tool;
pub mod webhook;
// Ported channels (see docs/parity.md).
pub mod bluebubbles;
pub mod buzz;
pub mod clickclack;
pub mod dingtalk;
pub mod discord;
pub mod discord_voice;
pub mod email;
pub mod feishu;
pub mod googlechat;
pub mod homeassistant;
pub mod imessage;
pub mod irc;
pub mod line;
pub mod matrix;
pub mod matrix_backup;
pub mod matrix_e2ee;
pub mod matrix_sas;
pub mod matrix_trust;
pub mod mattermost;
pub mod mls;
pub mod msgraph_webhook;
pub mod msteams;
pub mod nextcloud_talk;
pub mod nostr;
pub mod olm;
pub mod ntfy;
pub mod p256;
pub mod photon;
pub mod qa_channel;
pub mod qqbot;
pub mod raft;
pub mod reef;
pub mod relay;
pub mod signal;
pub mod simplex;
pub mod secp256k1;
pub mod slack;
pub mod sms;
pub mod synology_chat;
pub mod tlon;
pub mod twitch;
pub mod wecom;
pub mod wecom_callback;
pub mod weixin;
pub mod whatsapp;
pub mod whatsapp_cloud;
pub mod x;
pub mod yuanbao;
pub mod zalo;
pub mod zalouser;

#[cfg(test)]
mod testutil;

use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

pub use config::{build, parse_config, ChannelConfig, Secrets};
pub use router::{Action, Command, Route, RouteKey, Router, RouterConfig, SessionPer};
pub use telegram::Telegram;
pub use tool::ChannelSend;
pub use webhook::Webhook;

/// Where a message was posted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatType {
    #[default]
    Direct,
    Group,
    Channel,
    Thread,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Audio,
    Voice,
    Video,
    Animation,
    Sticker,
    #[default]
    Document,
}

/// An attachment. Inbound: `url` is where to fetch it (with the channel's auth, see
/// `Channel::fetch_media`), `path` once cached locally. Outbound: a local `path` or a public `url`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Media {
    pub kind: MediaKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mime: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// Platform file id (Telegram file_id, Slack file id…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The message an inbound message replies to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRef {
    pub id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub author: String,
    /// The bot's own message (counts as an implicit mention).
    #[serde(default)]
    pub is_own: bool,
}

/// A button press / interactive callback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Callback {
    /// Platform callback id to acknowledge.
    pub id: String,
    /// The button's `data` (`appr:<id>:<choice>`, `cl:<id>:<n>`, …).
    pub data: String,
}

/// A message from a human.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbound {
    pub channel: String,
    pub chat: String,
    pub sender: String,
    #[serde(default)]
    pub sender_name: String,
    pub text: String,
    /// Channel-native id; used for replies and redelivery dedup.
    pub message_id: String,
    /// Unix seconds.
    #[serde(default)]
    pub ts: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
    #[serde(default)]
    pub chat_type: ChatType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chat_name: String,
    /// Thread / topic id inside the chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<ReplyRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<Media>,
    /// The bot was explicitly mentioned (@name, <@id>, …).
    #[serde(default)]
    pub mentioned: bool,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<Callback>,
    /// This is an edit of an earlier message.
    #[serde(default)]
    pub edited: bool,
}

impl Inbound {
    /// Mentioned explicitly, or replying to the bot.
    pub fn addressed(&self) -> bool {
        self.mentioned || self.reply.as_ref().is_some_and(|r| r.is_own) || self.chat_type == ChatType::Direct
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Button {
    pub label: String,
    /// Returned in `Callback::data` when pressed. URL buttons set `url` instead.
    #[serde(default)]
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextFormat {
    #[default]
    Plain,
    /// CommonMark from the model; each channel converts to its dialect.
    Markdown,
}

/// A message to a human.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outbound {
    pub chat: String,
    pub text: String,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<Media>,
    /// Rows of buttons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buttons: Vec<Vec<Button>>,
    #[serde(default)]
    pub format: TextFormat,
    /// No notification sound where supported.
    #[serde(default)]
    pub silent: bool,
}

impl Outbound {
    pub fn text(chat: &str, text: &str) -> Outbound {
        Outbound { chat: chat.into(), text: text.into(), ..Default::default() }
    }
}

/// Result of a send: every platform message id created (long texts become several).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sent {
    pub ids: Vec<String>,
}

impl Sent {
    pub fn one(id: impl Into<String>) -> Sent {
        Sent { ids: vec![id.into()] }
    }
    pub fn first(&self) -> Option<&str> {
        self.ids.first().map(String::as_str)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LenUnit {
    #[default]
    Chars,
    /// Telegram counts UTF-16 code units.
    Utf16,
    Bytes,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Markup {
    #[default]
    Plain,
    Markdown,
    TelegramHtml,
    SlackMrkdwn,
    DiscordMarkdown,
    MatrixHtml,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Streaming {
    #[default]
    None,
    /// Send once, then edit in place as text grows.
    Edit,
    /// Platform streaming API (Slack startStream, Telegram drafts…).
    Native,
}

/// What a channel can do; the host degrades gracefully around what it cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Caps {
    pub chat_types: Vec<ChatType>,
    pub media: bool,
    pub reply: bool,
    pub threads: bool,
    /// 0 = none, 1 = one per message per user, >1 = several.
    pub reactions: u8,
    pub edit: bool,
    pub delete: bool,
    pub typing: bool,
    pub buttons: bool,
    pub polls: bool,
    pub native_commands: bool,
    pub streaming: Streaming,
    pub max_len: usize,
    pub len_unit: LenUnit,
    pub markup: Markup,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            chat_types: vec![ChatType::Direct],
            media: false,
            reply: false,
            threads: false,
            reactions: 0,
            edit: false,
            delete: false,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: 4000,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelErrorKind {
    /// Bad or revoked credentials: stop polling, tell the operator.
    Auth,
    RateLimited { retry_after: Option<Duration> },
    /// Transient: back off and try again.
    Network,
    /// The other side answered something we did not understand or rejected the request.
    Protocol,
    /// Misconfiguration or a state retrying cannot fix.
    Fatal,
    /// The channel cannot do this (edit, reactions…).
    Unsupported,
    /// The chat/message no longer exists or the bot was removed: never retry.
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelError {
    pub kind: ChannelErrorKind,
    pub message: String,
}

impl ChannelError {
    pub fn new(kind: ChannelErrorKind, message: impl Into<String>) -> Self {
        ChannelError { kind, message: message.into() }
    }
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ChannelErrorKind::Network | ChannelErrorKind::RateLimited { .. })
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ChannelError {}

pub trait Channel: Send + Sync {
    fn id(&self) -> &str;
    /// Block until messages arrive, the poll timeout passes (→ empty), or `cancel` fires (→ empty).
    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError>;
    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError>;
    fn caps(&self) -> Caps {
        Caps::default()
    }
    fn edit(&self, _chat: &str, _message_id: &str, _text: &str) -> Result<(), ChannelError> {
        Err(unsupported("edit"))
    }
    fn delete(&self, _chat: &str, _message_id: &str) -> Result<(), ChannelError> {
        Err(unsupported("delete"))
    }
    /// Show "typing…" for a few seconds; callers refresh it.
    fn typing(&self, _chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        Err(unsupported("typing"))
    }
    fn react(&self, _chat: &str, _message_id: &str, _emoji: &str, _remove: bool) -> Result<(), ChannelError> {
        Err(unsupported("reactions"))
    }
    /// Acknowledge a button press (stops client spinners).
    fn ack_callback(&self, _cb: &Callback, _text: Option<&str>) -> Result<(), ChannelError> {
        Ok(())
    }
    /// Download an inbound attachment's bytes (handles the channel's auth).
    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        match &m.url {
            Some(u) => http::get_bytes(u, &[], 50 * 1024 * 1024),
            None => Err(unsupported("media download")),
        }
    }
    /// Native streamed reply (`Caps::streaming == Native`): open it with the first text and
    /// return a handle, or `None` to let the host fall back to send + edit in place.
    /// See `deliver::Stream`, which drives these three and throttles updates.
    fn stream_begin(&self, _out: &Outbound) -> Result<Option<String>, ChannelError> {
        Ok(None)
    }
    /// More text: `text` is everything so far, `delta` what was added since the last call
    /// (append-only APIs use `delta`, replace-style APIs use `text`).
    fn stream_update(&self, _chat: &str, _handle: &str, _text: &str, _delta: &str) -> Result<(), ChannelError> {
        Ok(())
    }
    /// Close the stream with the final text (same `text` / `delta` convention).
    fn stream_finish(&self, _chat: &str, _handle: &str, _text: &str, _delta: &str) -> Result<(), ChannelError> {
        Ok(())
    }
    /// Channel-specific agent tools (e.g. zalouser's friend / group lookup).
    fn tools(&self) -> Vec<std::sync::Arc<dyn ark_core::Tool>> {
        Vec::new()
    }
    /// Daemon services handed to every channel once all are built (webhook delivery routing).
    fn wire(&self, _w: &Wiring) {}
    /// Release sockets / child processes.
    fn stop(&self) {}
}

/// Run cron job `id` once in the background with extra per-run context.
pub type CronFire = std::sync::Arc<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;

/// What the daemon offers channels after building them (`Channel::wire`).
#[derive(Clone, Default)]
pub struct Wiring {
    /// Every configured channel: name, channel (weak: no cycles), default chat.
    pub peers: Vec<(String, std::sync::Weak<dyn Channel>, Option<String>)>,
    pub cron: Option<CronFire>,
}

pub fn unsupported(what: &str) -> ChannelError {
    ChannelError::new(ChannelErrorKind::Unsupported, format!("{what} not supported by this channel"))
}

/// Sleep in small slices so cancellation is noticed quickly. Returns false if cancelled.
pub(crate) fn sleep_cancellable(d: Duration, cancel: &Cancel) -> bool {
    let until = std::time::Instant::now() + d;
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= until {
            return true;
        }
        std::thread::sleep((until - now).min(Duration::from_millis(25)));
    }
}

/// Write via temp file + rename so a crash never leaves a half-written state file.
/// Atomic write with 0600 permissions (key material, encrypted stores).
pub(crate) fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

pub(crate) fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
