//! ark-channel: human chat channels (Telegram, webhook), the kernel-agnostic
//! router that maps inbound messages to sessions, and the `channel_send` tool.
//! Blocking std threads only; every network wait observes a `Cancel`.

pub mod access;
pub mod action_args;
pub mod charset;
pub mod chunk;
pub mod config;
pub mod dave;
pub mod deliver;
pub mod markup;
pub mod http;
pub mod message_tool;
pub mod router;
pub mod telegram;
pub mod tool;
pub mod webhook;
// Ported channels (see docs/parity.md).
// Always compiled: the core transports, and every module another crate names directly
// (`ark_channel::whatsapp` in the binary's telephony hook, `ark_channel::discord::zlib`
// in the TUI's PNG decoder, `ark_channel::msteams`/`msgraph_webhook` in the Teams
// meetings bridge, `ark_channel::dave`/`olm` in storage) or that another always-compiled
// module here uses (`line`, `sms` are the shared helpers of the WhatsApp channel).
pub mod discord;
pub mod discord_transcripts;
pub mod discord_voice;
pub mod line;
pub mod mls;
pub mod msgraph_webhook;
pub mod msteams;
pub mod olm;
pub mod p256;
pub mod sms;
pub mod whatsapp;
pub mod whatsapp_cloud;

/// Declare an optional platform module behind its cargo feature (see `docs/BUILD.md`).
///
/// Feature on: the real module. Feature off: nothing of it is compiled, and a stub keeps
/// `config::registry()` (which names every kind, in `config.rs`) compiling — configuring
/// such a kind then fails with "not compiled into this build" instead of "unknown kind".
macro_rules! optional_channels {
    ($( $feat:literal => $m:ident ),* $(,)?) => {
        $(
            #[cfg(feature = $feat)]
            pub mod $m;
            #[cfg(not(feature = $feat))]
            pub mod $m {
                use std::sync::Arc;
                /// This platform was compiled out of the build.
                pub fn build(
                    _ctx: &crate::config::Ctx<'_>,
                    _settings: &serde_json::Map<String, serde_json::Value>,
                ) -> Result<Arc<dyn crate::Channel>, String> {
                    Err(format!(
                        "channel kind `{}` is not compiled into this build (cargo feature `{}` is off; see docs/BUILD.md)",
                        stringify!($m),
                        $feat
                    ))
                }
            }
        )*
    };
}

optional_channels! {
    "bluebubbles" => bluebubbles,
    "buzz" => buzz,
    "clickclack" => clickclack,
    "dingtalk" => dingtalk,
    "email" => email,
    "feishu" => feishu,
    "googlechat" => googlechat,
    "homeassistant" => homeassistant,
    "imessage" => imessage,
    "irc" => irc,
    "matrix" => matrix,
    "matrix_backup" => matrix_backup,
    "matrix_e2ee" => matrix_e2ee,
    "matrix_sas" => matrix_sas,
    "matrix_trust" => matrix_trust,
    "mattermost" => mattermost,
    "nextcloud_talk" => nextcloud_talk,
    "nostr" => nostr,
    "ntfy" => ntfy,
    "photon" => photon,
    "qa_channel" => qa_channel,
    "qqbot" => qqbot,
    "raft" => raft,
    "reef" => reef,
    "relay" => relay,
    "signal" => signal,
    "simplex" => simplex,
    "secp256k1" => secp256k1,
    "slack" => slack,
    "synology_chat" => synology_chat,
    "tlon" => tlon,
    "twitch" => twitch,
    "wecom" => wecom,
    "wecom_callback" => wecom_callback,
    "weixin" => weixin,
    "x" => x,
    "yuanbao" => yuanbao,
    "zalo" => zalo,
    "zalouser" => zalouser,
}

/// Keeps the feature wiring above honest: every optional platform is listed in
/// `config::registry()` exactly once, the registry entry for a kind is the module's own
/// `build`, and with its feature off that entry is the stub (which errors without doing
/// any work). Cheap: no builder is ever called with real settings.
#[cfg(test)]
mod feature_wiring {
    use crate::config::{registry, Builder, Ctx};

    fn entry(kind: &str) -> Builder {
        registry().into_iter().find(|(k, _)| *k == kind).map(|(_, b)| b).unwrap_or_else(|| panic!("kind `{kind}` is not in config::registry()"))
    }

    // Only reachable when some platform feature is off; the default build calls no builder.
    #[allow(dead_code)]
    fn stub_error(kind: &str) -> String {
        let dir = crate::testutil::temp_dir("feature-wiring");
        let secrets: crate::config::Secrets = std::sync::Arc::new(|_: &str| String::new());
        let e = {
            let ctx = Ctx { name: "probe", state_dir: &dir, secrets: &secrets };
            entry(kind)(&ctx, &serde_json::Map::new()).err().unwrap_or_default()
        };
        let _ = std::fs::remove_dir_all(&dir);
        e
    }

    macro_rules! wired {
        ($( $feat:literal => $m:ident => $kind:literal ),* $(,)?) => {
            $(
                // The registry entry for a kind is always that module's own `build`; when the
                // feature is off that `build` is the stub, which errors without any work.
                #[cfg(feature = $feat)]
                {
                    let want: Builder = crate::$m::build;
                    assert_eq!(entry($kind) as usize, want as usize, "kind `{}`: feature `{}` is on but the registry entry is not `{}::build`", $kind, $feat, stringify!($m));
                }
                #[cfg(not(feature = $feat))]
                {
                    let want: Builder = crate::$m::build;
                    assert_eq!(entry($kind) as usize, want as usize, "kind `{}`: registry entry is not `{}::build`", $kind, stringify!($m));
                    assert!(stub_error($kind).contains("not compiled into this build"), "kind `{}`: feature `{}` is off but the real module is compiled", $kind, $feat);
                }
            )*
        };
    }

    #[test]
    fn registry_lists_every_kind_once() {
        let mut kinds: Vec<&str> = registry().iter().map(|(k, _)| *k).collect();
        let total = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), total, "config::registry() lists a channel kind twice");
        for required in ["telegram", "webhook", "whatsapp", "discord"] {
            assert!(kinds.contains(&required), "core kind `{required}` is missing from the registry");
        }
    }

    /// `[features]` maps names to names (cheap parse: cargo metadata is not available here).
    fn manifest_features() -> std::collections::BTreeMap<String, Vec<String>> {
        let manifest = include_str!("../Cargo.toml");
        let section = manifest.split("[features]").nth(1).expect("`[features]` in Cargo.toml");
        let body: String = section
            .lines()
            .take_while(|l| !l.trim_start().starts_with('['))
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join(" ");
        let mut map = std::collections::BTreeMap::new();
        for chunk in body.split(']') {
            let Some((name, items)) = chunk.split_once('=') else { continue };
            let list = items.split('[').nth(1).unwrap_or("");
            let list: Vec<String> = list.split(',').map(|v| v.trim().trim_matches('"').to_string()).filter(|v| !v.is_empty()).collect();
            map.insert(name.trim().to_string(), list);
        }
        map
    }

    /// Every feature the module table below uses must be reachable from `all` (and `default`
    /// must include `all`): forgetting one would silently drop a platform from the default
    /// build, which must stay equivalent to the pre-feature binary.
    #[test]
    fn all_and_default_cover_every_platform_feature() {
        let feats = manifest_features();
        let expand = |name: &str| -> Vec<String> {
            let mut seen = vec![name.to_string()];
            let mut i = 0;
            while i < seen.len() {
                for dep in feats.get(&seen[i]).into_iter().flatten() {
                    if !seen.contains(dep) {
                        seen.push(dep.clone());
                    }
                }
                i += 1;
            }
            seen
        };
        assert!(feats.get("default").is_some_and(|d| d.iter().any(|f| f == "all")), "`default` must include `all`: {feats:?}");
        let reachable = expand("all");
        let table = include_str!("lib.rs").split("optional_channels! {").nth(1).and_then(|s| s.split('}').next()).expect("optional_channels! table in lib.rs");
        let mut checked = 0;
        for line in table.lines() {
            let Some((feat, _)) = line.split_once("=>") else { continue };
            let feat = feat.trim().trim_matches('"');
            assert!(feats.contains_key(feat), "feature `{feat}` is used in lib.rs but not declared in Cargo.toml `[features]`");
            assert!(reachable.iter().any(|f| f == feat), "feature `{feat}` is not reachable from `all` in Cargo.toml");
            checked += 1;
        }
        assert_eq!(checked, 39, "the optional platform table lost or gained entries (checked {checked})");
    }

    #[test]
    fn every_platform_feature_is_wired() {
        wired! {
            "bluebubbles" => bluebubbles => "bluebubbles",
            "buzz" => buzz => "buzz",
            "clickclack" => clickclack => "clickclack",
            "dingtalk" => dingtalk => "dingtalk",
            "email" => email => "email",
            "feishu" => feishu => "feishu",
            "googlechat" => googlechat => "googlechat",
            "homeassistant" => homeassistant => "homeassistant",
            "imessage" => imessage => "imessage",
            "irc" => irc => "irc",
            "matrix" => matrix => "matrix",
            "mattermost" => mattermost => "mattermost",
            "nextcloud_talk" => nextcloud_talk => "nextcloud_talk",
            "nostr" => nostr => "nostr",
            "ntfy" => ntfy => "ntfy",
            "photon" => photon => "photon",
            "qa_channel" => qa_channel => "qa-channel",
            "qqbot" => qqbot => "qqbot",
            "raft" => raft => "raft",
            "reef" => reef => "reef",
            "relay" => relay => "relay",
            "signal" => signal => "signal",
            "simplex" => simplex => "simplex",
            "slack" => slack => "slack",
            "synology_chat" => synology_chat => "synology-chat",
            "tlon" => tlon => "tlon",
            "twitch" => twitch => "twitch",
            "wecom" => wecom => "wecom",
            "wecom_callback" => wecom_callback => "wecom_callback",
            "weixin" => weixin => "weixin",
            "x" => x => "x",
            "yuanbao" => yuanbao => "yuanbao",
            "zalo" => zalo => "zalo",
            "zalouser" => zalouser => "zalouser",
        }
    }
}

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
    /// Extended message actions for the `message` tool (OpenClaw's closed action vocabulary:
    /// `poll`, `pin`, `unpin`, `list-pins`, `read`, `reactions`, `search`, `thread-create`,
    /// `thread-list`, `member-info`, `channel-info`, `channel-list`, …). `args` is the tool
    /// input as the model sent it (camelCase keys, `target` = chat id; polls arrive normalised
    /// by `message::normalize_poll`). Returns a JSON result for the model.
    fn message_action(&self, action: &str, _args: &serde_json::Value) -> Result<serde_json::Value, ChannelError> {
        Err(unsupported(action))
    }
    /// The `message_action` names this channel implements (advertised to the model).
    fn message_actions(&self) -> Vec<&'static str> {
        Vec::new()
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
    /// Session id → its route (channel, chat, sender), for requester-bound channel tools.
    pub session_origin: Option<crate::whatsapp::SessionOrigin>,
}

static MENU: std::sync::RwLock<Vec<(String, String)>> = std::sync::RwLock::new(Vec::new());

/// Commands channels register as native menus (Telegram `setMyCommands`, Discord application
/// commands): (name, description). Set by the host from its slash-command table; empty = the
/// channel's built-in short list.
pub fn set_menu(cmds: Vec<(String, String)>) {
    *MENU.write().unwrap() = cmds;
}

pub fn menu() -> Vec<(String, String)> {
    MENU.read().unwrap().clone()
}

/// Telegram: names `[a-z0-9_]{1,32}` (hyphens become underscores), descriptions 1–256 chars, ≤100.
pub fn telegram_menu(cmds: &[(String, String)]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    cmds.iter()
        .filter_map(|(n, d)| {
            let n = n.to_lowercase().replace('-', "_");
            (n.len() <= 32 && !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') && seen.insert(n.clone())).then(|| serde_json::json!({"command": n, "description": clip_desc(d, 256)}))
        })
        .take(100)
        .collect()
}

/// Discord: CHAT_INPUT commands, names `[-_a-z0-9]{1,32}`, descriptions 1–100 chars, ≤100,
/// each with an optional free-text `args` option (delivered as `/name args`).
pub fn discord_menu(cmds: &[(String, String)]) -> Vec<serde_json::Value> {
    cmds.iter()
        .filter(|(n, _)| n.len() <= 32 && !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'))
        .take(100)
        .map(|(n, d)| serde_json::json!({"name": n, "description": clip_desc(d, 100), "type": 1, "options": [{"type": 3, "name": "args", "description": "arguments", "required": false}]}))
        .collect()
}

fn clip_desc(d: &str, max: usize) -> String {
    let d = if d.trim().is_empty() { "command" } else { d.trim() };
    if d.chars().count() <= max {
        d.to_string()
    } else {
        format!("{}…", d.chars().take(max - 1).collect::<String>())
    }
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

#[cfg(test)]
mod menu_tests {
    #[test]
    fn native_menus_follow_platform_rules() {
        let cmds: Vec<(String, String)> = vec![("help".into(), "Show commands".into()), ("export-session".into(), "x".repeat(300)), ("Bad Name".into(), "no".into()), ("help".into(), "dup".into())];
        let t = super::telegram_menu(&cmds);
        assert_eq!(t.len(), 2);
        assert_eq!(t[1]["command"], "export_session");
        assert_eq!(t[1]["description"].as_str().unwrap().chars().count(), 256);
        let d = super::discord_menu(&cmds);
        assert_eq!(d[1]["name"], "export-session");
        assert_eq!(d[1]["description"].as_str().unwrap().chars().count(), 100);
        assert_eq!(d[0]["options"][0]["name"], "args");
    }
}
