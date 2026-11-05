//! Hermes relay protocol, gateway side (ported from Hermes `gateway/relay/`,
//! MIT: `ws_transport.py`, `auth.py`, `descriptor.py`, `adapter.py`, `media.py`,
//! `adapter_discord_interaction.py`).
//!
//! seagent plays the *gateway*: it dials OUT to a relay connector (`wss://…/relay`)
//! that fronts one or more real platforms (Slack, Discord, Telegram…), so seagent
//! needs no public port. Upgrade auth is `Authorization: Bearer <token>` with
//! `token = base64url("<gateway_id>:<exp>:<hex HMAC-SHA256(secret, "<gateway_id>:<exp>")>")`
//! (unpadded, byte-identical to the connector's `relayAuthToken.ts`).
//!
//! Frames are newline-delimited JSON over WebSocket text messages:
//! - gateway → connector: `hello` (one per `{platform, botId}` identity),
//!   `outbound {requestId, action, platform?, botId?}`, `inbound_ack {bufferId}`,
//!   `interrupt`, `going_idle`.
//! - connector → gateway: `descriptor` (the `CapabilityDescriptor`, mapped onto
//!   [`Caps`]), `inbound {event, bufferId?}`, `outbound_result {requestId, result}`,
//!   `interrupt_inbound` (surfaced as a `/stop` inbound), `going_idle_ack`,
//!   `passthrough_forward` (§5.1: a forwarded Discord interaction body is decoded
//!   into an Inbound like a message — slash command → `/name args`, `hp1:` button
//!   token → callback, modal → `custom_id` + `input: value` lines; other platforms
//!   are acknowledged and dropped).
//!
//! Outbound ops: `send`, `edit`, `delete`, `typing`, `react`, `send_media`
//! (local files are first POSTed to `{base}/relay/media`), `prompt` (buttons),
//! `draft` (native streaming through `stream_*`), and the inherent
//! [`Relay::create_thread`] / [`Relay::rename_thread`] (`thread_create`,
//! `thread_rename`) and [`Relay::task_card`] / [`Relay::task_card_stop`].
//! An op the descriptor does not advertise (`supported_ops`, legacy set
//! `send/edit/typing/follow_up` when empty) is refused locally as Unsupported;
//! `draft`, `task_card`, `delete` and the thread ops never fail open.
//!
//! Draft streaming (`supports_draft_streaming` + `draft` advertised → `Streaming::Native`):
//! every frame carries the whole text so far under one `draft_id`. Slack makes the
//! stream the message, so the final is `draft(final=true)` (one retry when the ack is
//! lost — the connector's tombstone makes it idempotent); elsewhere (Telegram drafts)
//! the preview clears itself and the final goes out as an ordinary `send`.
//! Per-chat egress discriminators (`scope_id`, `user_id` for DMs, `profile`,
//! underlying platform) learnt from inbound events ride on every outbound
//! `metadata`, as the upstream adapter's `_with_scope` does.
//!
//! Delivery: buffered inbounds carry a `bufferId`; it is acknowledged only when
//! the caller polls again (at-least-once; the connector redelivers unacked
//! frames with the same message id and the router dedups). Reconnect uses capped
//! exponential backoff; a close 4401 after a successful handshake triggers one
//! immediate re-dial with a fresh token (reason `expired` just reconnects), and a
//! second 4401 on that re-dial means the credential was revoked → `Auth`.
//!
//! ```toml
//! [channels.relay]
//! kind = "relay"
//! url = "https://connector.example.com"      # → wss://connector.example.com/relay
//! gateway_id = "gw-home"
//! secret = "{{secret:RELAY_SECRET}}"
//! identities = [{ platform = "slack", bot_id = "B123" }]
//! ```

use crate::http::Http;
use crate::{
    markup, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat,
};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const CONTRACT_VERSION: u64 = 1;
const UNAUTHORIZED_CLOSE: u16 = 4401;
const EXPIRED_REASON: &str = "expired";
const MEDIA_MAX_BYTES: u64 = 25 * 1024 * 1024;
const LEGACY_OPS: [&str; 4] = ["send", "edit", "typing", "follow_up"];
const EGRESS_DECLINE_CODE: &str = "egress_declined";
const EGRESS_DECLINE_MARKER: &str = "egress declined:";

// ---------------------------------------------------------------- auth

/// `HMAC_SHA256(secret, payload)` as lowercase hex — the connector's `sign`.
pub fn sign(payload: &str, secret: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), payload.as_bytes()))
}

/// `base64url("<payload>:<exp>:<sig>")`, `exp` = unix seconds (`0` = never).
pub fn make_token(payload: &str, secret: &str, ttl_secs: u64, now: u64) -> String {
    let exp = if ttl_secs > 0 { now + ttl_secs } else { 0 };
    let signed = format!("{payload}:{exp}");
    let raw = format!("{signed}:{}", sign(&signed, secret));
    seagent_net::crypto::b64url(raw.as_bytes())
}

/// Connector-side check (multi-secret rotation list): the payload when valid and unexpired.
pub fn verify_token(token: &str, secrets: &[&str], now: u64) -> Option<String> {
    let raw = String::from_utf8(seagent_net::crypto::b64url_decode(token)?).ok()?;
    let mut it = raw.rsplitn(3, ':');
    let (sig, exp, payload) = (it.next()?, it.next()?, it.next()?);
    let exp_n: u64 = exp.parse().ok()?;
    if exp_n != 0 && exp_n < now {
        return None;
    }
    let signed = format!("{payload}:{exp}");
    secrets.iter().any(|s| seagent_net::crypto::ct_eq(sign(&signed, s).as_bytes(), sig.as_bytes())).then(|| payload.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Configured connector base → `ws(s)://…/relay` dial URL (idempotent).
pub fn dial_url(url: &str) -> String {
    let raw = url.trim();
    let raw = if let Some(r) = raw.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = raw.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        raw.to_string()
    };
    let raw = raw.trim_end_matches('/');
    if raw.ends_with("/relay") {
        raw.to_string()
    } else {
        format!("{raw}/relay")
    }
}

/// Dial URL → `http(s)://…` connector base for the `/relay/media` routes.
pub fn media_base(dial: &str) -> String {
    let raw = dial.trim().trim_end_matches('/');
    let raw = if let Some(r) = raw.strip_prefix("wss://") {
        format!("https://{r}")
    } else if let Some(r) = raw.strip_prefix("ws://") {
        format!("http://{r}")
    } else {
        raw.to_string()
    };
    raw.strip_suffix("/relay").unwrap_or(&raw).to_string()
}

// ---------------------------------------------------------------- descriptor

/// The handshake `CapabilityDescriptor` (unknown keys ignored, missing keys default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub contract_version: u64,
    pub platform: String,
    pub label: String,
    pub max_message_length: usize,
    pub supports_draft_streaming: bool,
    pub supports_edit: bool,
    pub supports_threads: bool,
    pub markdown_dialect: String,
    pub len_unit: String,
    pub supported_ops: Vec<String>,
}

impl Default for Descriptor {
    /// Placeholder used until the connector's descriptor arrives (as upstream's factory).
    fn default() -> Self {
        Descriptor {
            contract_version: CONTRACT_VERSION,
            platform: "relay".into(),
            label: "Relay".into(),
            max_message_length: 4096,
            supports_draft_streaming: false,
            supports_edit: true,
            supports_threads: false,
            markdown_dialect: "plain".into(),
            len_unit: "chars".into(),
            supported_ops: vec![],
        }
    }
}

impl Descriptor {
    /// Trust-boundary normalisation as `CapabilityDescriptor.from_json`.
    pub fn from_value(v: &Value) -> Descriptor {
        let b = |k: &str| v[k].as_bool().unwrap_or(false);
        let s = |k: &str, d: &str| v[k].as_str().unwrap_or(d).to_string();
        let max = match &v["max_message_length"] {
            Value::Number(n) => n.as_f64().filter(|f| *f >= 1.0).map(|f| f as usize).unwrap_or(4096),
            Value::String(t) => t.trim().parse::<i64>().ok().filter(|n| *n > 0).map(|n| n as usize).unwrap_or(4096),
            _ => 4096,
        };
        let ops = match &v["supported_ops"] {
            Value::Array(a) => a.iter().filter_map(|o| o.as_str()).filter(|o| !o.is_empty()).map(str::to_string).collect(),
            _ => vec![],
        };
        Descriptor {
            contract_version: v["contract_version"].as_u64().unwrap_or(CONTRACT_VERSION),
            platform: s("platform", ""),
            label: s("label", ""),
            max_message_length: max,
            supports_draft_streaming: b("supports_draft_streaming"),
            supports_edit: b("supports_edit"),
            supports_threads: b("supports_threads"),
            markdown_dialect: s("markdown_dialect", "plain"),
            len_unit: s("len_unit", "chars"),
            supported_ops: ops,
        }
    }

    /// Advertised op, or the legacy set when the connector predates `supported_ops`.
    pub fn supports_op(&self, op: &str) -> bool {
        if self.supported_ops.is_empty() {
            LEGACY_OPS.contains(&op)
        } else {
            self.supported_ops.iter().any(|o| o == op)
        }
    }

    /// Ops that did not exist before `supported_ops` (no legacy fail-open).
    pub fn advertises(&self, op: &str) -> bool {
        self.supported_ops.iter().any(|o| o == op)
    }

    /// Native draft streaming needs both the flag and an explicit `draft` op.
    pub fn drafts(&self) -> bool {
        self.supports_draft_streaming && self.advertises("draft")
    }

    /// Slack's stream is the message itself (sealed); Telegram-shaped drafts clear.
    fn stream_is_message(&self) -> bool {
        self.platform.eq_ignore_ascii_case("slack")
    }

    fn unit(&self) -> LenUnit {
        if self.len_unit.eq_ignore_ascii_case("utf16") {
            LenUnit::Utf16
        } else {
            LenUnit::Chars
        }
    }

    fn plain(&self) -> bool {
        matches!(self.markdown_dialect.as_str(), "" | "plain")
    }

    pub fn caps(&self) -> Caps {
        let edit = self.supports_edit && self.supports_op("edit");
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Channel, ChatType::Thread],
            media: self.supports_op("send_media"),
            reply: true,
            threads: self.supports_threads,
            reactions: u8::from(self.supports_op("react")),
            edit,
            delete: self.supports_op("delete"),
            typing: self.supports_op("typing"),
            buttons: self.supports_op("prompt"),
            polls: false,
            native_commands: false,
            streaming: if self.drafts() {
                Streaming::Native
            } else if edit {
                Streaming::Edit
            } else {
                Streaming::None
            },
            max_len: self.max_message_length,
            len_unit: self.unit(),
            // The connector renders the platform dialect from raw Markdown.
            markup: if self.plain() { Markup::Plain } else { Markup::Markdown },
        }
    }
}

// ---------------------------------------------------------------- inbound

/// Per-chat egress discriminators remembered from inbound events.
#[derive(Debug, Clone, Default)]
struct ChatMeta {
    platform: String,
    scope_id: String,
    user_id: String,
    chat_type: String,
    profile: String,
    /// Last chat label the text lane carried (a forwarded interaction has none).
    chat_name: String,
}

fn chat_type_of(s: &str) -> ChatType {
    match s {
        "group" => ChatType::Group,
        "channel" => ChatType::Channel,
        "thread" => ChatType::Thread,
        _ => ChatType::Direct,
    }
}

fn kind_of(mime: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" if mime == "image/gif" => MediaKind::Animation,
        "image" => MediaKind::Image,
        "audio" if mime.contains("ogg") || mime.contains("opus") => MediaKind::Voice,
        "audio" => MediaKind::Audio,
        "video" => MediaKind::Video,
        _ => MediaKind::Document,
    }
}

fn str_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The connector's normalised inbound payload (`_event_from_wire`) → Inbound.
fn inbound_of(channel: &str, ev: &Value, buffer_id: Option<&str>) -> Option<(Inbound, ChatMeta)> {
    let src = &ev["source"];
    let chat = str_of(&src["chat_id"])?;
    let media_urls: Vec<String> = ev["media_urls"].as_array().map(|a| a.iter().filter_map(|u| u.as_str().map(str::to_string)).collect()).unwrap_or_default();
    // Per-url metadata by URL lookup, never by position (the wire lists may disagree in order).
    let by_url: HashMap<String, &Value> = ev["media"].as_array().into_iter().flatten().filter_map(|m| Some((m["url"].as_str()?.to_string(), m))).collect();
    let media: Vec<Media> = media_urls
        .iter()
        .map(|u| {
            let m = by_url.get(u).copied().unwrap_or(&Value::Null);
            let mime = m["mime"].as_str().unwrap_or("").to_string();
            Media { kind: kind_of(&mime), url: Some(u.clone()), mime, name: m["filename"].as_str().unwrap_or("").to_string(), size: m["size"].as_u64().unwrap_or(0), ..Default::default() }
        })
        .collect();
    let text = ev["text"].as_str().unwrap_or("").to_string();
    let callback = ev["prompt_response"].as_object().and_then(|p| {
        let id = str_of(&p["prompt_id"])?;
        let data = str_of(&p["option_id"])?;
        Some(Callback { id, data })
    });
    if text.trim().is_empty() && media.is_empty() && callback.is_none() {
        return None;
    }
    let reply_id = str_of(&ev["reply_to_message_id"]);
    let reply = reply_id.map(|id| ReplyRef {
        id,
        text: ev["reply_to"]["text"].as_str().unwrap_or("").to_string(),
        author: ev["reply_to"]["author"].as_str().unwrap_or("").to_string(),
        is_own: ev["reply_to"]["is_own"] == true,
    });
    let message_id = str_of(&ev["message_id"]).or_else(|| str_of(&src["message_id"])).or_else(|| buffer_id.map(|b| format!("buf:{b}"))).unwrap_or_default();
    let message_id = match &callback {
        Some(cb) => format!("prompt:{}:{}", cb.id, message_id),
        None => message_id,
    };
    let chat_type = src["chat_type"].as_str().unwrap_or("dm").to_string();
    let meta = ChatMeta {
        platform: src["platform"].as_str().filter(|p| *p != "relay").unwrap_or("").to_string(),
        scope_id: str_of(&src["scope_id"]).unwrap_or_default(),
        user_id: str_of(&src["user_id"]).unwrap_or_default(),
        chat_type: chat_type.clone(),
        profile: str_of(&src["profile"]).unwrap_or_default(),
        chat_name: src["chat_name"].as_str().unwrap_or("").to_string(),
    };
    let sender_name = ["user_display_name", "user_name", "user_handle"].iter().find_map(|k| src[*k].as_str().filter(|s| !s.is_empty())).unwrap_or("").to_string();
    let inb = Inbound {
        channel: channel.to_string(),
        chat,
        sender: meta.user_id.clone(),
        sender_name,
        text,
        message_id,
        ts: ev["timestamp"].as_i64().or_else(|| ev["ts"].as_i64()).unwrap_or_else(|| now_secs() as i64),
        account: meta.platform.clone(),
        chat_type: chat_type_of(&chat_type),
        chat_name: src["chat_name"].as_str().unwrap_or("").to_string(),
        thread: str_of(&src["thread_id"]),
        reply,
        media,
        // The connector forwards only turns it admitted as addressed to the bot.
        mentioned: ev["mentioned"].as_bool().unwrap_or(true),
        is_bot: src["is_bot"] == true,
        callback,
        edited: ev["edited"] == true || ev["message_type"] == "edit",
    };
    Some((inb, meta))
}

/// `hp1:<prompt_id>:<option_id>` (the connector's promptCodec), ids `[A-Za-z0-9_.-]{1,32}`.
fn prompt_token(t: &str) -> Option<(String, String)> {
    let ok = |s: &str| (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    let p: Vec<&str> = t.split(':').collect();
    (p.len() == 3 && p[0] == "hp1" && ok(p[1]) && ok(p[2])).then(|| (p[1].to_string(), p[2].to_string()))
}

/// Slash-command options as text: scalars give their value, (sub)command groups their name.
fn interaction_options(opts: &Value, out: &mut Vec<String>) {
    for o in opts.as_array().into_iter().flatten() {
        if matches!(o["type"].as_u64(), Some(1 | 2)) {
            if let Some(n) = o["name"].as_str().map(str::trim).filter(|n| !n.is_empty()) {
                out.push(n.to_string());
            }
            interaction_options(&o["options"], out);
        } else if let Some(v) = str_of(&o["value"]).or_else(|| o["value"].as_bool().map(|b| b.to_string())) {
            if !v.trim().is_empty() {
                out.push(v.trim().to_string());
            }
        }
    }
}

/// A MODAL_SUBMIT: its custom_id, then `input_id: value` per non-empty input (depth-first).
fn modal_text(data: &Value) -> String {
    let mut lines = vec![data["custom_id"].as_str().unwrap_or("").to_string()];
    let mut stack: Vec<&Value> = data["components"].as_array().map(|a| a.iter().rev().collect()).unwrap_or_default();
    while let Some(c) = stack.pop() {
        if !c.is_object() {
            continue;
        }
        match c["components"].as_array().filter(|a| !a.is_empty()) {
            Some(a) => stack.extend(a.iter().rev()),
            None if c["component"].is_object() => stack.push(&c["component"]),
            None => {}
        }
        let v = if c.get("value").is_some() { &c["value"] } else { &c["values"] };
        let plain = |x: &Value| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string());
        let v = match v {
            Value::Array(a) => a.iter().map(plain).collect::<Vec<_>>().join(", "),
            Value::Null => continue,
            x => plain(x),
        };
        if !v.trim().is_empty() {
            lines.push(format!("{}: {v}", c["custom_id"].as_str().unwrap_or("")));
        }
    }
    lines.join("\n").trim().to_string()
}

/// A connector-forwarded passthrough request (§5.1, `{platform, botId, method, path,
/// headers, bodyB64, profile?}`) → Inbound. Only Discord interactions carry a turn; the
/// session source mirrors the connector's `interactionSessionSource` (guild channel →
/// group, thread channel types 10–12 → thread keyed by the channel id, else DM).
fn passthrough_of(channel: &str, fwd: &Value, labels: &HashMap<String, ChatMeta>) -> Option<(Inbound, ChatMeta)> {
    if fwd["platform"].as_str() != Some("discord") {
        return None;
    }
    let body = seagent_net::crypto::b64_decode(fwd["bodyB64"].as_str().unwrap_or(""))?;
    let p: Value = serde_json::from_slice(&body).ok().filter(Value::is_object)?;
    let data = &p["data"];
    let mut callback = None;
    let text = match p["type"].as_u64() {
        // APPLICATION_COMMAND → "/name opt…"
        Some(2) => {
            let name = data["name"].as_str().unwrap_or("");
            let mut parts = vec![format!("/{name}")];
            interaction_options(&data["options"], &mut parts);
            if name.is_empty() { String::new() } else { parts.join(" ").trim().to_string() }
        }
        // MESSAGE_COMPONENT: our prompt token → structured answer; foreign ids stay text.
        Some(3) => {
            let id = data["custom_id"].as_str().unwrap_or("").to_string();
            match prompt_token(&id) {
                Some((pid, opt)) => {
                    let t = format!("/{opt}");
                    callback = Some(Callback { id: pid, data: opt });
                    t
                }
                None => id,
            }
        }
        Some(5) => modal_text(data),
        _ => String::new(),
    };
    if text.trim().is_empty() {
        return None;
    }
    let member = &p["member"];
    let user = if member["user"].is_object() { &member["user"] } else { &p["user"] };
    let sender_name = [&member["nick"], &user["global_name"], &user["username"]].into_iter().find_map(str_of).unwrap_or_default();
    let chat = str_of(&p["channel_id"]).unwrap_or_default();
    let guild = str_of(&p["guild_id"]);
    let thread = guild.is_some() && matches!(p["channel"]["type"].as_u64(), Some(10..=12));
    let chat_type = if thread { "thread" } else if guild.is_some() { "group" } else { "dm" };
    let meta = ChatMeta {
        platform: "discord".into(),
        scope_id: guild.clone().unwrap_or_default(),
        user_id: str_of(&user["id"]).unwrap_or_default(),
        chat_type: chat_type.into(),
        profile: str_of(&fwd["profile"]).unwrap_or_default(),
        chat_name: labels.get(&chat).map(|m| m.chat_name.clone()).unwrap_or_default(),
    };
    let iid = str_of(&p["id"]).unwrap_or_default();
    let inb = Inbound {
        channel: channel.to_string(),
        chat: chat.clone(),
        sender: meta.user_id.clone(),
        sender_name,
        text,
        message_id: match &callback {
            Some(cb) => format!("prompt:{}:{iid}", cb.id),
            None => format!("interaction:{iid}"),
        },
        ts: now_secs() as i64,
        account: meta.platform.clone(),
        chat_type: chat_type_of(chat_type),
        chat_name: meta.chat_name.clone(),
        thread: thread.then(|| chat.clone()),
        mentioned: true,
        callback,
        ..Default::default()
    };
    Some((inb, meta))
}

// ---------------------------------------------------------------- transport

type Pending = Mutex<HashMap<String, mpsc::Sender<Value>>>;

struct Shared {
    id: String,
    url: String,
    gateway_id: String,
    secret: Option<String>,
    identities: Vec<(String, String)>,
    token_ttl: u64,
    connect_timeout: Duration,
    reconnect: bool,
    /// Reconnect backoff in ms (first delay; capped at 30×).
    backoff_ms: std::sync::atomic::AtomicU64,
    /// Writer queue of the live connection; None while disconnected.
    tx: Mutex<Option<mpsc::Sender<String>>>,
    pending: Pending,
    primary: Mutex<Option<Descriptor>>,
    by_platform: Mutex<HashMap<String, Descriptor>>,
    chats: Mutex<HashMap<String, ChatMeta>>,
    fatal: Mutex<Option<ChannelError>>,
    idle_ack: Mutex<Option<mpsc::Sender<()>>>,
    stop: AtomicBool,
    dials: AtomicUsize,
}

impl Shared {
    fn bearer(&self) -> Option<String> {
        let s = self.secret.as_deref().filter(|s| !s.is_empty())?;
        Some(make_token(&self.gateway_id, s, self.token_ttl, now_secs()))
    }

    fn send_frame(&self, frame: &Value) -> bool {
        let line = format!("{frame}\n");
        self.tx.lock().unwrap().as_ref().is_some_and(|t| t.send(line).is_ok())
    }

    fn fail_pending(&self, why: &str) {
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(json!({"success": false, "error": why, "ambiguous": true}));
        }
    }
}

enum End {
    Stopped,
    /// Socket gone: close code/reason when the peer sent a Close, whether a descriptor arrived.
    Dropped { code: Option<u16>, reason: String, handshook: bool },
}

enum DialErr {
    Auth(String),
    Other(String),
}

fn dial(sh: &Shared) -> Result<WebSocket<seagent_net::Stream>, DialErr> {
    let bearer = sh.bearer().map(|t| format!("Bearer {t}"));
    let headers: Vec<(&str, &str)> = bearer.as_deref().map(|b| vec![("Authorization", b)]).unwrap_or_default();
    sh.dials.fetch_add(1, Ordering::SeqCst);
    match WebSocket::connect(&sh.url, &headers, sh.connect_timeout) {
        Ok((ws, _)) => Ok(ws),
        Err(e) => {
            let m = e.to_string();
            if m.contains(" 401") || m.contains(" 403") {
                Err(DialErr::Auth(format!("relay connector refused the upgrade credentials ({m})")))
            } else {
                Err(DialErr::Other(format!("relay dial failed: {m}")))
            }
        }
    }
}

fn session(sh: &Shared, mut ws: WebSocket<seagent_net::Stream>, inbox: &mpsc::Sender<(Inbound, Option<String>)>) -> End {
    let (tx, rx) = mpsc::channel::<String>();
    let _ = ws.set_read_timeout(Some(Duration::from_millis(50)));
    for (p, b) in &sh.identities {
        if ws.send_text(&format!("{}\n", json!({"type": "hello", "platform": p, "botId": b}))).is_err() {
            return End::Dropped { code: None, reason: "closed during hello".into(), handshook: false };
        }
    }
    *sh.tx.lock().unwrap() = Some(tx);
    let started = Instant::now();
    let (mut last_rx, mut last_ping) = (Instant::now(), Instant::now());
    let mut handshook = false;
    let mut buf = String::new();
    let end = loop {
        if sh.stop.load(Ordering::SeqCst) {
            for f in rx.try_iter() {
                let _ = ws.send_text(&f);
            }
            let _ = ws.send(&Message::Close(Some((1000, "bye".into()))));
            break End::Stopped;
        }
        let mut write_failed = false;
        for f in rx.try_iter() {
            if ws.send_text(&f).is_err() {
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break End::Dropped { code: None, reason: "write failed".into(), handshook };
        }
        if !handshook && started.elapsed() > sh.connect_timeout {
            break End::Dropped { code: None, reason: "no descriptor".into(), handshook };
        }
        if last_ping.elapsed() >= Duration::from_secs(30) {
            last_ping = Instant::now();
            if ws.send(&Message::Ping(b"seagent".to_vec())).is_err() {
                break End::Dropped { code: None, reason: "ping failed".into(), handshook };
            }
        }
        if last_rx.elapsed() >= Duration::from_secs(90) {
            break End::Dropped { code: None, reason: "silent connector".into(), handshook };
        }
        let chunk = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Binary(b))) => String::from_utf8_lossy(&b).into_owned(),
            Ok(Some(Message::Close(c))) => {
                let (code, reason) = c.map(|(c, r)| (Some(c), r)).unwrap_or((None, String::new()));
                break End::Dropped { code, reason, handshook };
            }
            Ok(Some(_)) => {
                last_rx = Instant::now();
                continue;
            }
            Err(e) => break End::Dropped { code: None, reason: e.to_string(), handshook },
        };
        last_rx = Instant::now();
        buf.push_str(&chunk);
        // NDJSON: a message may carry several frames or a partial one.
        if !buf.contains('\n') && serde_json::from_str::<Value>(&buf).is_ok() {
            buf.push('\n');
        }
        while let Some(i) = buf.find('\n') {
            let line: String = buf.drain(..=i).collect();
            if !line.trim().is_empty() {
                handshook |= handle_frame(sh, line.trim(), inbox);
            }
        }
    };
    *sh.tx.lock().unwrap() = None;
    end
}

/// One connector frame. Returns true when it was a descriptor (handshake done).
fn handle_frame(sh: &Shared, line: &str, inbox: &mpsc::Sender<(Inbound, Option<String>)>) -> bool {
    let Ok(f) = serde_json::from_str::<Value>(line) else { return false };
    match f["type"].as_str().unwrap_or("") {
        "descriptor" => {
            let d = Descriptor::from_value(&f["descriptor"]);
            if !d.platform.is_empty() {
                sh.by_platform.lock().unwrap().insert(d.platform.clone(), d.clone());
            }
            let mut p = sh.primary.lock().unwrap();
            if p.is_none() || p.as_ref().is_some_and(|p| p.platform == d.platform) {
                *p = Some(d);
            }
            return true;
        }
        "inbound" => {
            let buffer = str_of(&f["bufferId"]);
            match inbound_of(&sh.id, &f["event"], buffer.as_deref()) {
                Some((inb, meta)) => {
                    sh.chats.lock().unwrap().insert(inb.chat.clone(), meta);
                    let _ = inbox.send((inb, buffer));
                }
                // Nothing deliverable: acknowledge so the connector does not redeliver forever.
                None => {
                    if let Some(b) = buffer {
                        sh.send_frame(&json!({"type": "inbound_ack", "bufferId": b}));
                    }
                }
            }
        }
        "outbound_result" => {
            if let Some(tx) = sh.pending.lock().unwrap().remove(f["requestId"].as_str().unwrap_or("")) {
                let _ = tx.send(if f["result"].is_object() { f["result"].clone() } else { json!({}) });
            }
        }
        "going_idle_ack" => {
            if let Some(tx) = sh.idle_ack.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
        "interrupt_inbound" => {
            if let Some(chat) = str_of(&f["chat_id"]) {
                let key = f["session_key"].as_str().unwrap_or("");
                let nonce = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(4));
                let meta = sh.chats.lock().unwrap().get(&chat).cloned().unwrap_or_default();
                let inb = Inbound {
                    channel: sh.id.clone(),
                    chat_type: chat_type_of(if meta.chat_type.is_empty() { "dm" } else { &meta.chat_type }),
                    chat,
                    sender: meta.user_id,
                    text: "/stop".into(),
                    message_id: format!("interrupt:{key}:{nonce}"),
                    ts: now_secs() as i64,
                    mentioned: true,
                    ..Default::default()
                };
                let _ = inbox.send((inb, None));
            }
        }
        "passthrough_forward" => {
            // Acked like an inbound (on the next poll) once handed off; undecodable → at once.
            let buffer = str_of(&f["bufferId"]);
            let decoded = passthrough_of(&sh.id, &f["forward"], &sh.chats.lock().unwrap());
            match decoded {
                Some((inb, meta)) => {
                    sh.chats.lock().unwrap().insert(inb.chat.clone(), meta);
                    let _ = inbox.send((inb, buffer));
                }
                None => {
                    if let Some(b) = buffer {
                        sh.send_frame(&json!({"type": "inbound_ack", "bufferId": b}));
                    }
                }
            }
        }
        _ => {}
    }
    false
}

fn set_fatal(sh: &Shared, e: ChannelError) {
    *sh.fatal.lock().unwrap() = Some(e);
}

fn sleep_unless_stopped(sh: &Shared, d: Duration) -> bool {
    let until = Instant::now() + d;
    while Instant::now() < until {
        if sh.stop.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20).min(until - Instant::now()));
    }
    !sh.stop.load(Ordering::SeqCst)
}

/// Dial → session → reconnect supervisor (one thread per channel).
fn run(sh: Arc<Shared>, inbox: mpsc::Sender<(Inbound, Option<String>)>) {
    let base = Duration::from_millis(sh.backoff_ms.load(Ordering::SeqCst));
    let max = base * 30;
    let mut backoff = base;
    let mut ever_handshook = false;
    // The next / current dial is the one-shot fresh-token retry after a 4401.
    let mut auth_retry = false;
    while !sh.stop.load(Ordering::SeqCst) {
        let ws = match dial(&sh) {
            Ok(ws) => ws,
            Err(DialErr::Auth(m)) => {
                if auth_retry || !ever_handshook || !sh.reconnect {
                    set_fatal(&sh, ChannelError::new(K::Auth, m));
                    return;
                }
                auth_retry = true;
                continue;
            }
            Err(DialErr::Other(m)) => {
                if !sh.reconnect && !ever_handshook {
                    set_fatal(&sh, ChannelError::new(K::Network, m));
                    return;
                }
                if !sleep_unless_stopped(&sh, backoff) {
                    return;
                }
                backoff = (backoff * 2).min(max);
                continue;
            }
        };
        let end = session(&sh, ws, &inbox);
        sh.fail_pending("relay transport connection lost");
        let (code, reason, handshook) = match end {
            End::Stopped => return,
            End::Dropped { code, reason, handshook } => (code, reason, handshook),
        };
        ever_handshook |= handshook;
        if handshook {
            backoff = base;
        }
        if code == Some(UNAUTHORIZED_CLOSE) {
            if !ever_handshook {
                set_fatal(&sh, ChannelError::new(K::Auth, "relay connector closed 4401 (unauthorized): check gateway_id / secret"));
                return;
            }
            if reason != EXPIRED_REASON {
                if auth_retry {
                    set_fatal(&sh, ChannelError::new(K::Auth, "relay credential revoked (4401 again with a fresh token)"));
                    return;
                }
                // Re-dial at once with a freshly minted token before calling it revoked.
                auth_retry = true;
                continue;
            }
        }
        auth_retry = false;
        if !sh.reconnect {
            set_fatal(&sh, ChannelError::new(K::Network, format!("relay connection closed: {reason}")));
            return;
        }
        if !sleep_unless_stopped(&sh, backoff) {
            return;
        }
        backoff = (backoff * 2).min(max);
    }
}

// ---------------------------------------------------------------- channel

pub struct Relay {
    sh: Arc<Shared>,
    base: String,
    rx: Mutex<mpsc::Receiver<(Inbound, Option<String>)>>,
    /// Buffer ids handed out by the last poll, acknowledged on the next one.
    unacked: Mutex<Vec<String>>,
    poll_timeout: Duration,
    pub outbound_timeout: Duration,
    started: AtomicBool,
    /// Open native streams by handle (the `draft_id` as text).
    drafts: Mutex<HashMap<String, Draft>>,
    draft_seq: AtomicU64,
}

/// One open `draft` stream: where it goes and how its final is delivered.
struct Draft {
    id: u64,
    base: Outbound,
    seal: bool,
}

/// A task-card row (`task_card.chunks[]`); the connector renders Slack plan-mode
/// `task_update` chunks (unknown status → in_progress, title ≤ 256 chars).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskItem {
    pub id: String,
    pub title: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    InProgress,
    Complete,
    Error,
}

/// No-clobber guard for `thread_rename` (enforced connector-side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameGuard<'a> {
    None,
    /// Rename only while the thread still has the name the connector created it with.
    ConnectorCreated,
    /// Legacy string guard: only while the current name equals this.
    CurrentName(&'a str),
}

pub struct Options {
    pub url: String,
    pub gateway_id: String,
    pub secret: Option<String>,
    pub identities: Vec<(String, String)>,
    pub poll_timeout_secs: u64,
    pub outbound_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub token_ttl_secs: u64,
    pub reconnect: bool,
}

impl Relay {
    pub fn new(id: &str, o: Options) -> Result<Relay, String> {
        let url = dial_url(&o.url);
        seagent_net::Url::parse(&url).map_err(|e| format!("channel {id}: relay url: {e}"))?;
        if o.secret.is_some() && o.gateway_id.trim().is_empty() {
            return Err(format!("channel {id}: relay secret needs gateway_id"));
        }
        let identities = if o.identities.is_empty() { vec![("relay".to_string(), String::new())] } else { o.identities };
        let base = media_base(&url);
        let sh = Arc::new(Shared {
            id: id.to_string(),
            url,
            gateway_id: o.gateway_id.trim().to_string(),
            secret: o.secret,
            identities,
            token_ttl: o.token_ttl_secs,
            connect_timeout: Duration::from_secs(o.connect_timeout_secs.max(1)),
            reconnect: o.reconnect,
            backoff_ms: std::sync::atomic::AtomicU64::new(1000),
            tx: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            primary: Mutex::new(None),
            by_platform: Mutex::new(HashMap::new()),
            chats: Mutex::new(HashMap::new()),
            fatal: Mutex::new(None),
            idle_ack: Mutex::new(None),
            stop: AtomicBool::new(false),
            dials: AtomicUsize::new(0),
        });
        let (_tx, rx) = mpsc::channel();
        Ok(Relay {
            sh,
            base,
            rx: Mutex::new(rx),
            unacked: Mutex::new(vec![]),
            poll_timeout: Duration::from_secs(o.poll_timeout_secs.max(1)),
            outbound_timeout: Duration::from_secs(o.outbound_timeout_secs.max(1)),
            started: AtomicBool::new(false),
            drafts: Mutex::new(HashMap::new()),
            // Random 49-bit start like upstream's counter: ids stay unique across restarts.
            draft_seq: AtomicU64::new(u64::from_be_bytes(seagent_net::crypto::random_bytes(8).try_into().unwrap_or([0; 8])) >> 15 | 1),
        })
    }

    /// Start the connection thread (idempotent; `poll` and `send` call it lazily).
    pub fn start(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        *self.rx.lock().unwrap() = rx;
        let sh = self.sh.clone();
        std::thread::Builder::new().name(format!("relay {}", sh.id)).spawn(move || run(sh, tx)).expect("spawn relay thread");
    }

    /// First reconnect delay (doubles per failure, capped at 30×).
    pub fn set_backoff(&self, base: Duration) {
        self.sh.backoff_ms.store(base.as_millis().max(1) as u64, Ordering::SeqCst);
    }

    /// Descriptor of the chat's underlying platform, else the primary one.
    fn descriptor_for(&self, chat: &str) -> Descriptor {
        let plat = self.sh.chats.lock().unwrap().get(chat).map(|m| m.platform.clone()).unwrap_or_default();
        if !plat.is_empty() {
            if let Some(d) = self.sh.by_platform.lock().unwrap().get(&plat) {
                return d.clone();
            }
        }
        self.sh.primary.lock().unwrap().clone().unwrap_or_default()
    }

    fn metadata(&self, chat: &str, mut md: serde_json::Map<String, Value>) -> Value {
        if let Some(m) = self.sh.chats.lock().unwrap().get(chat) {
            for (k, v) in [("scope_id", &m.scope_id), ("user_id", &m.user_id), ("profile", &m.profile)] {
                if !v.is_empty() && !md.contains_key(k) {
                    md.insert(k.into(), json!(v));
                }
            }
        }
        Value::Object(md)
    }

    /// Send a `going_idle` and wait for the connector's ack (buffered-only mode).
    pub fn go_idle(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        *self.sh.idle_ack.lock().unwrap() = Some(tx);
        if !self.sh.send_frame(&json!({"type": "going_idle"})) {
            return false;
        }
        rx.recv_timeout(timeout).is_ok()
    }

    /// Forward a gateway-side interrupt for a session to the connector.
    pub fn interrupt(&self, session_key: &str, reason: Option<&str>) -> Result<(), ChannelError> {
        if self.sh.send_frame(&json!({"type": "interrupt", "session_key": session_key, "reason": reason})) {
            Ok(())
        } else {
            Err(ChannelError::new(K::Network, "relay transport not connected"))
        }
    }

    /// One `outbound` frame and its `outbound_result`.
    fn request(&self, chat: &str, action: Value) -> Result<Value, ChannelError> {
        self.start();
        if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
            return Err(e);
        }
        let op = action["op"].as_str().unwrap_or("?").to_string();
        let rid = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16));
        let mut frame = json!({"type": "outbound", "requestId": rid, "action": action});
        let plat = self.sh.chats.lock().unwrap().get(chat).map(|m| m.platform.clone()).unwrap_or_default();
        if !plat.is_empty() {
            frame["platform"] = json!(plat);
            if let Some((_, b)) = self.sh.identities.iter().find(|(p, _)| *p == plat) {
                frame["botId"] = json!(b);
            }
        }
        let (tx, rx) = mpsc::channel();
        self.sh.pending.lock().unwrap().insert(rid.clone(), tx);
        if !self.sh.send_frame(&frame) {
            self.sh.pending.lock().unwrap().remove(&rid);
            return Err(ChannelError::new(K::Network, format!("relay {op}: transport not connected")));
        }
        let r = rx.recv_timeout(self.outbound_timeout);
        self.sh.pending.lock().unwrap().remove(&rid);
        let r = r.map_err(|_| ChannelError::new(K::Network, format!("relay {op}: outbound timed out (ambiguous: may have been delivered)")))?;
        if r["success"] == true {
            Ok(r)
        } else {
            Err(result_error(&op, &r))
        }
    }

    fn gated(&self, chat: &str, action: Value) -> Result<Value, ChannelError> {
        let op = action["op"].as_str().unwrap_or("");
        if !self.descriptor_for(chat).supports_op(op) {
            return Err(crate::unsupported(&format!("relay op `{op}`")));
        }
        self.request(chat, action)
    }

    /// POST a local file to `/relay/media`; the reference URL for `send_media`.
    fn upload(&self, path: &str, mime: &str, name: &str) -> Result<String, ChannelError> {
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        if data.is_empty() || data.len() as u64 > MEDIA_MAX_BYTES {
            return Err(ChannelError::new(K::Fatal, format!("attachment {path}: size {} outside (0, {MEDIA_MAX_BYTES}]", data.len())));
        }
        let fname = if name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { name.to_string() };
        let ctype = if mime.is_empty() { "application/octet-stream" } else { mime };
        let mut http = Http::new(Duration::from_secs(30)).with_header("x-media-filename", &fname.chars().take(255).collect::<String>());
        if let Some(t) = self.sh.bearer() {
            http = http.bearer(&t);
        }
        let v = http.json("POST", &format!("{}/relay/media", self.base), crate::http::Payload::Raw(ctype, &data))?;
        let id = str_of(&v["id"]).ok_or_else(|| ChannelError::new(K::Protocol, "relay media upload returned no id"))?;
        Ok(format!("{}/relay/media/{id}", self.base))
    }

    /// One `draft` frame (`final` seals a Slack stream) carrying the whole text so far.
    fn draft_frame(&self, base: &Outbound, id: u64, text: &str, last: bool) -> Result<Value, ChannelError> {
        let d = self.descriptor_for(&base.chat);
        let mut md = serde_json::Map::new();
        // Slack streams are thread replies; the trigger's ts anchors them when no thread is set.
        let anchor = base.thread.as_ref().or(if d.stream_is_message() { base.reply_to.as_ref() } else { None });
        if let Some(t) = anchor {
            md.insert("thread_id".into(), json!(t));
        }
        let metadata = self.metadata(&base.chat, md);
        let content = render(base.format, &d, text);
        self.request(&base.chat, json!({"op": "draft", "chat_id": base.chat, "draft_id": id, "content": content, "final": last, "metadata": metadata}))
    }

    /// Create a thread / forum topic under `parent` (`thread_create`; Discord channel or
    /// message-anchored thread, Telegram forum topic, Slack named seed message). The id
    /// of the new thread, to address later sends via `Outbound::thread`.
    pub fn create_thread(&self, parent: &str, name: &str, anchor: Option<&str>) -> Result<String, ChannelError> {
        if !self.descriptor_for(parent).advertises("thread_create") {
            return Err(crate::unsupported("relay op `thread_create`"));
        }
        let name = name.trim();
        let name: String = (if name.is_empty() { "handoff" } else { name }).chars().take(100).collect();
        let mut a = json!({"op": "thread_create", "chat_id": parent, "thread_name": name, "metadata": self.metadata(parent, Default::default())});
        if let Some(m) = anchor {
            a["message_id"] = json!(m);
        }
        let r = self.request(parent, a)?;
        str_of(&r["thread_id"]).or_else(|| str_of(&r["message_id"])).ok_or_else(|| ChannelError::new(K::Protocol, "relay thread_create: no thread id in result"))
    }

    /// Rename a thread (`thread_rename`); `parent` defaults to the thread id (Telegram
    /// needs the containing chat, Discord ignores it).
    pub fn rename_thread(&self, thread: &str, name: &str, parent: Option<&str>, guard: RenameGuard) -> Result<(), ChannelError> {
        let name: String = name.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(100).collect();
        if name.is_empty() || thread.is_empty() {
            return Err(ChannelError::new(K::Fatal, "relay thread_rename: empty thread id or name"));
        }
        let chat = parent.unwrap_or(thread);
        if !self.descriptor_for(chat).advertises("thread_rename") {
            return Err(crate::unsupported("relay op `thread_rename`"));
        }
        let mut a = json!({"op": "thread_rename", "chat_id": chat, "message_id": thread, "thread_name": name, "metadata": self.metadata(chat, Default::default())});
        match guard {
            RenameGuard::None => {}
            RenameGuard::ConnectorCreated => a["only_if_connector_created"] = json!(true),
            RenameGuard::CurrentName(n) => a["only_if_current_name"] = json!(n),
        }
        self.request(chat, a).map(|_| ())
    }

    /// Whether the chat's connector renders native task cards (explicit `task_card` op).
    pub fn supports_task_cards(&self, chat: &str) -> bool {
        self.descriptor_for(chat).advertises("task_card")
    }

    /// Per-turn card identity: the trigger message, else the thread, else `root`
    /// (one derivation for progress and stop, as upstream's `_card_key`).
    fn card_id(reply_to: Option<&str>, thread: Option<&str>) -> String {
        format!("turn:{}", reply_to.or(thread).filter(|s| !s.is_empty()).unwrap_or("root"))
    }

    /// Show / update the turn's task card (`task_card`, full row set each time).
    pub fn task_card(&self, chat: &str, reply_to: Option<&str>, thread: Option<&str>, tasks: &[TaskItem]) -> Result<(), ChannelError> {
        if !self.supports_task_cards(chat) {
            return Err(crate::unsupported("relay op `task_card`"));
        }
        let mut md = serde_json::Map::new();
        if let Some(t) = thread {
            md.insert("thread_id".into(), json!(t));
        }
        // Slack card streams are thread replies anchored on the trigger.
        if let Some(r) = reply_to {
            md.insert("thread_ts".into(), json!(r));
        }
        let chunks: Vec<Value> = tasks.iter().map(|t| serde_json::to_value(t).unwrap_or_default()).collect();
        let a = json!({"op": "task_card", "chat_id": chat, "card_id": Self::card_id(reply_to, thread), "chunks": chunks, "metadata": self.metadata(chat, md)});
        self.request(chat, a).map(|_| ())
    }

    /// Seal the turn's task card (`task_card_stop`, idempotent connector-side).
    pub fn task_card_stop(&self, chat: &str, reply_to: Option<&str>, thread: Option<&str>) -> Result<(), ChannelError> {
        if !self.supports_task_cards(chat) {
            return Err(crate::unsupported("relay op `task_card`"));
        }
        let mut md = serde_json::Map::new();
        if let Some(t) = thread {
            md.insert("thread_id".into(), json!(t));
        }
        let a = json!({"op": "task_card_stop", "chat_id": chat, "card_id": Self::card_id(reply_to, thread), "metadata": self.metadata(chat, md)});
        self.request(chat, a).map(|_| ())
    }
}

/// Raw Markdown is kept for rich dialects (the connector renders them); plain → stripped.
fn render(format: TextFormat, d: &Descriptor, t: &str) -> String {
    match (format, d.plain()) {
        (TextFormat::Markdown, true) => markup::convert(t, Markup::Plain),
        _ => t.to_string(),
    }
}

/// A failed `outbound_result` → error kind.
fn result_error(op: &str, r: &Value) -> ChannelError {
    let err = r["error"].as_str().unwrap_or("connector declined").to_string();
    let code = r["code"].as_str().map(str::to_string).or_else(|| r["code"].as_u64().map(|c| c.to_string())).unwrap_or_default();
    let status = r["status"].as_u64().or_else(|| code.parse().ok()).unwrap_or(0);
    let low = format!("{} {}", code.to_lowercase(), err.to_lowercase());
    let msg = format!("relay {op}: {err}");
    let kind = if r["ambiguous"] == true {
        K::Network
    } else if code == EGRESS_DECLINE_CODE || low.contains(EGRESS_DECLINE_MARKER) {
        // The connector refused this destination (not routed / opted out): never retry.
        K::NotFound
    } else if status == 401 || status == 403 || low.contains("unauthorized") || low.contains("forbidden") || low.contains("invalid_auth") || low.contains("token_revoked") {
        K::Auth
    } else if status == 429 || low.contains("rate_limit") || low.contains("rate limit") || low.contains("ratelimited") {
        let ra = r["retry_after"].as_f64().or_else(|| r["retry_after_s"].as_f64()).map(|s| Duration::from_secs_f64(s.max(0.0)));
        K::RateLimited { retry_after: ra }
    } else if status == 404 || status == 410 || low.contains("not_found") || low.contains("not found") || low.contains("channel_not_found") || low.contains("unknown channel") {
        K::NotFound
    } else if low.contains("unsupported") || low.contains("not supported") {
        K::Unsupported
    } else if status >= 500 || low.contains("timed out") || low.contains("timeout") || low.contains("not connected") || low.contains("connection lost") {
        K::Network
    } else {
        K::Protocol
    };
    ChannelError::new(kind, msg)
}

fn media_kind_str(k: MediaKind) -> &'static str {
    match k {
        MediaKind::Image | MediaKind::Animation | MediaKind::Sticker => "image",
        MediaKind::Voice | MediaKind::Audio => "voice",
        MediaKind::Video => "video",
        MediaKind::Document => "document",
    }
}

impl Channel for Relay {
    fn id(&self) -> &str {
        &self.sh.id
    }

    fn caps(&self) -> Caps {
        self.sh.primary.lock().unwrap().clone().unwrap_or_default().caps()
    }

    /// Opens a `draft` stream when this chat's platform advertises drafts; otherwise
    /// `None` and the host falls back to send + edit.
    fn stream_begin(&self, out: &Outbound) -> Result<Option<String>, ChannelError> {
        self.start();
        let d = self.descriptor_for(&out.chat);
        if !d.drafts() {
            return Ok(None);
        }
        let id = self.draft_seq.fetch_add(1, Ordering::SeqCst);
        let base = Outbound { text: String::new(), media: vec![], buttons: vec![], ..out.clone() };
        self.draft_frame(&base, id, &out.text, false)?;
        let h = id.to_string();
        self.drafts.lock().unwrap().insert(h.clone(), Draft { id, base, seal: d.stream_is_message() });
        Ok(Some(h))
    }

    fn stream_update(&self, _chat: &str, handle: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        let (id, base) = match self.drafts.lock().unwrap().get(handle) {
            Some(d) => (d.id, d.base.clone()),
            None => return Err(ChannelError::new(K::Fatal, "relay draft: unknown stream")),
        };
        self.draft_frame(&base, id, text, false).map(|_| ())
    }

    fn stream_finish(&self, _chat: &str, handle: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        let d = self.drafts.lock().unwrap().remove(handle).ok_or_else(|| ChannelError::new(K::Fatal, "relay draft: unknown stream"))?;
        if !d.seal {
            // Telegram-shaped drafts clear on the client; the final is a real message.
            return self.send(&Outbound { text: text.to_string(), ..d.base }).map(|_| ());
        }
        // Seal; a lost ack is retried once with the same frame (idempotent connector-side).
        match self.draft_frame(&d.base, d.id, text, true) {
            Err(e) if e.kind == K::Network => self.draft_frame(&d.base, d.id, text, true).map(|_| ()),
            r => r.map(|_| ()),
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.start();
        for b in std::mem::take(&mut *self.unacked.lock().unwrap()) {
            self.sh.send_frame(&json!({"type": "inbound_ack", "bufferId": b}));
        }
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(25)) {
                got.push(m);
                got.extend(rx.try_iter());
            }
        }
        let mut un = self.unacked.lock().unwrap();
        Ok(got
            .into_iter()
            .map(|(m, b)| {
                un.extend(b);
                m
            })
            .collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        self.start();
        let d = self.descriptor_for(&out.chat);
        let mut md = serde_json::Map::new();
        if let Some(t) = &out.thread {
            md.insert("thread_id".into(), json!(t));
        }
        if out.silent {
            md.insert("silent".into(), json!(true));
        }
        let metadata = self.metadata(&out.chat, md);
        let render = |t: &str| render(out.format, &d, t);
        let mut text = out.text.clone();
        let mut sent = Sent::default();
        let mut reply_to = out.reply_to.clone();
        // Media: by reference through `send_media`; local files are uploaded first.
        if !out.media.is_empty() {
            if d.supports_op("send_media") {
                let caption_fits = out.media.len() == 1 && crate::chunk::len(&text, d.unit()) <= d.max_message_length.min(1024) && out.buttons.is_empty();
                for (i, m) in out.media.iter().enumerate() {
                    let source = match (&m.path, &m.url) {
                        (Some(p), _) => self.upload(p, &m.mime, &m.name)?,
                        (None, Some(u)) => u.clone(),
                        _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
                    };
                    let caption = if caption_fits && i == 0 { render(&text) } else { m.caption.clone().unwrap_or_default() };
                    let mut a = json!({"op": "send_media", "chat_id": out.chat, "media_kind": media_kind_str(m.kind), "source_url": source, "content": caption, "reply_to": reply_to.take(), "metadata": metadata});
                    if !m.name.is_empty() {
                        a["filename"] = json!(m.name);
                    }
                    let r = self.request(&out.chat, a)?;
                    sent.ids.extend(str_of(&r["message_id"]));
                }
                if caption_fits {
                    return Ok(sent);
                }
            } else {
                let links: Vec<String> = out.media.iter().filter_map(|m| m.url.clone()).collect();
                if links.len() < out.media.len() {
                    return Err(crate::unsupported("relay file upload (connector lacks send_media)"));
                }
                text = [text, links.join("\n")].into_iter().filter(|s| !s.trim().is_empty()).collect::<Vec<_>>().join("\n\n");
            }
        }
        let prompt = !out.buttons.is_empty() && d.supports_op("prompt");
        if !out.buttons.is_empty() {
            let flat: Vec<&crate::Button> = out.buttons.iter().flatten().collect();
            let mut extra = Vec::new();
            for (i, b) in flat.iter().enumerate() {
                match (&b.url, prompt) {
                    (Some(u), _) => extra.push(format!("{}: {u}", b.label)),
                    (None, false) => extra.push(format!("{}. {}", i + 1, b.label)),
                    (None, true) => {}
                }
            }
            if !extra.is_empty() {
                text = format!("{}\n\n{}", text.trim_end(), extra.join("\n"));
            }
        }
        let pieces = crate::chunk::split(&text, d.max_message_length, d.unit());
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let last = i + 1 == n;
            let action = if last && prompt {
                let options: Vec<Value> = out.buttons.iter().flatten().filter(|b| b.url.is_none()).map(|b| json!({"id": b.data, "label": b.label.chars().take(75).collect::<String>()})).collect();
                json!({"op": "prompt", "chat_id": out.chat, "content": render(&piece), "prompt_kind": "choice", "prompt_id": seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8)), "options": options, "reply_to": reply_to.take(), "metadata": metadata})
            } else {
                json!({"op": "send", "chat_id": out.chat, "content": render(&piece), "reply_to": reply_to.take(), "metadata": metadata})
            };
            let r = self.request(&out.chat, action)?;
            sent.ids.extend(str_of(&r["message_id"]));
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let d = self.descriptor_for(chat);
        if !d.supports_edit {
            return Err(crate::unsupported("edit"));
        }
        let content = if d.plain() { markup::convert(text, Markup::Plain) } else { text.to_string() };
        let md = self.metadata(chat, Default::default());
        self.gated(chat, json!({"op": "edit", "chat_id": chat, "message_id": message_id, "content": content, "metadata": md})).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        // Explicit opt-in only: `delete` is not in the legacy op set.
        if !self.descriptor_for(chat).supported_ops.iter().any(|o| o == "delete") {
            return Err(crate::unsupported("delete"));
        }
        let md = self.metadata(chat, Default::default());
        self.request(chat, json!({"op": "delete", "chat_id": chat, "message_id": message_id, "metadata": md})).map(|_| ())
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let mut md = serde_json::Map::new();
        if let Some(t) = thread {
            md.insert("thread_id".into(), json!(t));
        }
        let md = self.metadata(chat, md);
        self.gated(chat, json!({"op": "typing", "chat_id": chat, "metadata": md})).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let md = self.metadata(chat, Default::default());
        self.gated(chat, json!({"op": "react", "chat_id": chat, "message_id": message_id, "emoji": emoji, "remove": remove, "metadata": md})).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().ok_or_else(|| crate::unsupported("media without url"))?;
        // The bearer goes only to connector re-hosts, never to public CDN URLs.
        if url.contains("/relay/media/") {
            let t = self.sh.bearer().map(|t| format!("Bearer {t}"));
            let hs: Vec<(&str, &str)> = t.as_deref().map(|t| vec![("authorization", t)]).unwrap_or_default();
            crate::http::get_bytes(url, &hs, MEDIA_MAX_BYTES)
        } else {
            crate::http::get_bytes(url, &[], MEDIA_MAX_BYTES)
        }
    }

    fn stop(&self) {
        if self.started.load(Ordering::SeqCst) && self.sh.tx.lock().unwrap().is_some() {
            self.go_idle(Duration::from_secs(2));
        }
        self.sh.stop.store(true, Ordering::SeqCst);
        self.sh.fail_pending("relay transport closed");
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.sh.stop.store(true, Ordering::SeqCst);
    }
}

fn d_poll() -> u64 {
    25
}
fn d_out() -> u64 {
    30
}
fn d_ttl() -> u64 {
    300
}
fn d_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    platform: String,
    #[serde(default)]
    bot_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Connector base (`https://…`, `wss://…` or the full `/relay` URL).
    url: String,
    #[serde(default)]
    gateway_id: Option<String>,
    /// Per-gateway upgrade secret (no `Authorization` header when unset).
    #[serde(default)]
    secret: Option<String>,
    /// Single identity shorthand…
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    bot_id: Option<String>,
    /// …or every fronted `{platform, bot_id}` (one hello each).
    #[serde(default)]
    identities: Vec<Identity>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_out")]
    outbound_timeout_secs: u64,
    #[serde(default = "d_out")]
    connect_timeout_secs: u64,
    #[serde(default = "d_ttl")]
    token_ttl_secs: u64,
    #[serde(default = "d_true")]
    reconnect: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let secret = ctx.opt_secret("secret", &st.secret)?;
    let mut identities: Vec<(String, String)> = st.identities.into_iter().map(|i| (i.platform, i.bot_id)).collect();
    if let Some(p) = st.platform {
        identities.insert(0, (p, st.bot_id.unwrap_or_default()));
    }
    let gateway_id = st.gateway_id.unwrap_or_else(|| format!("gw-{}", ctx.name));
    let r = Relay::new(
        ctx.name,
        Options {
            url: st.url,
            gateway_id,
            secret,
            identities,
            poll_timeout_secs: st.poll_timeout_secs,
            outbound_timeout_secs: st.outbound_timeout_secs,
            connect_timeout_secs: st.connect_timeout_secs,
            token_ttl_secs: st.token_ttl_secs,
            reconnect: st.reconnect,
        },
    )?;
    Ok(Arc::new(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;
    type Script = Arc<dyn Fn(usize, &mut Ws) + Send + Sync>;

    /// Fake connector: WebSocket `/relay` upgrades run `script(n, ws)`; `POST /relay/media`
    /// and `GET /relay/media/<id>` are answered inline. Every request head is recorded.
    struct Connector {
        url: String,
        heads: Arc<Mutex<Vec<String>>>,
        bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Connector {
        fn start(refuse_upgrade: Option<u16>, script: Script) -> Connector {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            let heads = Arc::new(Mutex::new(Vec::new()));
            let bodies = Arc::new(Mutex::new(Vec::new()));
            let (h2, b2) = (heads.clone(), bodies.clone());
            std::thread::spawn(move || {
                let mut n = 0;
                for s in l.incoming() {
                    let Ok(mut s) = s else { continue };
                    let Ok((head, rest)) = seagent_net::ws::read_head(&mut s, 64 * 1024) else { continue };
                    h2.lock().unwrap().push(head.clone());
                    let line = head.lines().next().unwrap_or("").to_string();
                    if line.starts_with("POST /relay/media") {
                        let len: usize = seagent_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                        let mut body = rest;
                        while body.len() < len {
                            let mut c = [0u8; 4096];
                            let k = s.read(&mut c).unwrap_or(0);
                            if k == 0 {
                                break;
                            }
                            body.extend_from_slice(&c[..k]);
                        }
                        b2.lock().unwrap().push(body);
                        let resp = r#"{"id":"m1"}"#;
                        let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp}", resp.len());
                        continue;
                    }
                    if line.starts_with("GET /relay/media/") {
                        let ok = seagent_net::ws::header(&head, "authorization").is_some();
                        let body = if ok { "BYTES" } else { "" };
                        let _ = write!(s, "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", if ok { 200 } else { 401 }, body.len());
                        continue;
                    }
                    if let Some(code) = refuse_upgrade {
                        let _ = write!(s, "HTTP/1.1 {code} Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                        continue;
                    }
                    let Ok(mut ws) = WebSocket::accept(s, &head, rest) else { continue };
                    let sc = script.clone();
                    let k = n;
                    n += 1;
                    std::thread::spawn(move || sc(k, &mut ws));
                }
            });
            Connector { url, heads, bodies }
        }
        fn upgrades(&self) -> Vec<String> {
            self.heads.lock().unwrap().iter().filter(|h| h.starts_with("GET /relay ")).cloned().collect()
        }
    }

    /// Next JSON frame from the gateway (skips pings/pongs). When the gateway hangs up,
    /// the script thread ends quietly (`resume_unwind` skips the panic hook).
    fn next(ws: &mut Ws) -> Value {
        loop {
            match ws.recv_blocking() {
                Ok(Message::Text(t)) => return serde_json::from_str(t.trim()).unwrap(),
                Ok(Message::Close(_)) | Err(_) => std::panic::resume_unwind(Box::new("gateway hung up")),
                _ => {}
            }
        }
    }

    fn put(ws: &mut Ws, v: Value) {
        ws.send_text(&format!("{v}\n")).unwrap();
    }

    fn descriptor(ops: &[&str]) -> Value {
        json!({"type": "descriptor", "descriptor": {"contract_version": 1, "platform": "slack", "label": "Slack", "max_message_length": 40, "supports_draft_streaming": false, "supports_edit": true, "supports_threads": true, "markdown_dialect": "mrkdwn", "len_unit": "chars", "supported_ops": ops, "brand_new_field": 1}})
    }

    fn relay(url: &str, secret: Option<&str>) -> Relay {
        let r = Relay::new(
            "rl",
            Options {
                url: url.into(),
                gateway_id: "gw-test".into(),
                secret: secret.map(str::to_string),
                identities: vec![("slack".into(), "B1".into()), ("discord".into(), "D1".into())],
                poll_timeout_secs: 1,
                outbound_timeout_secs: 2,
                connect_timeout_secs: 5,
                token_ttl_secs: 300,
                reconnect: true,
            },
        )
        .unwrap();
        r.set_backoff(Duration::from_millis(30));
        r
    }

    fn poll_until(r: &Relay, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(r.poll(&Cancel::new()).unwrap());
        }
        got
    }

    fn wait_connected(r: &Relay) {
        let until = Instant::now() + Duration::from_secs(10);
        while r.sh.primary.lock().unwrap().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn token_matches_connector_vector_and_verifies() {
        // Reference computed with the upstream algorithm (Python hmac/base64, ttl 0).
        assert_eq!(make_token("gw-test", "shh", 0, 123), "Z3ctdGVzdDowOmVmYWRmYThlYmE0MWVlYmIxMTUwNjQ3ZmU1OGNmODE3NDI4ZTY2NGE2ZGJjNzliYThhZGUwMTk4NDYxMWExYjE");
        let t = make_token("gw-test", "s2", 300, 1_000);
        assert!(!t.contains('='), "unpadded base64url");
        assert_eq!(verify_token(&t, &["old", "s2"], 1_200).as_deref(), Some("gw-test"), "rotation list");
        assert!(verify_token(&t, &["s2"], 1_301).is_none(), "expired");
        assert!(verify_token(&t, &["wrong"], 1_000).is_none());
        let raw = String::from_utf8(seagent_net::crypto::b64url_decode(&t).unwrap()).unwrap().replace("gw-test", "gw-evil");
        assert!(verify_token(&seagent_net::crypto::b64url(raw.as_bytes()), &["s2"], 1_000).is_none(), "tampered payload");
        assert_eq!(dial_url("https://c.example.com/"), "wss://c.example.com/relay");
        assert_eq!(dial_url("ws://h:1/relay"), "ws://h:1/relay");
        assert_eq!(media_base("wss://c.example.com/relay"), "https://c.example.com");
    }

    #[test]
    fn descriptor_normalises_and_maps_to_caps() {
        let d = Descriptor::from_value(&json!({"platform": "telegram", "max_message_length": -1, "supported_ops": "garbage", "len_unit": "utf16", "markdown_dialect": "plain", "supports_edit": true}));
        assert_eq!(d.max_message_length, 4096, "non-positive limit → default");
        assert!(d.supported_ops.is_empty() && d.supports_op("send") && d.supports_op("follow_up") && !d.supports_op("delete"), "malformed ops → legacy set");
        let c = d.caps();
        assert!(c.edit && c.typing && !c.delete && !c.media && c.reactions == 0 && !c.buttons);
        assert_eq!((c.len_unit, c.markup, c.streaming), (LenUnit::Utf16, Markup::Plain, Streaming::Edit));
        let d = Descriptor::from_value(&descriptor(&["send", "delete", "react", "prompt", "send_media"])["descriptor"]);
        let c = d.caps();
        assert!(!c.edit && c.delete && c.reactions == 1 && c.buttons && c.media && c.threads, "edit only when advertised");
        assert_eq!((c.max_len, c.markup, c.streaming), (40, Markup::Markdown, Streaming::None));
        assert_eq!(Descriptor::from_value(&json!({"max_message_length": "abc"})).max_message_length, 4096);
    }

    #[test]
    fn handshake_hello_inbound_kinds_and_deferred_acks() {
        let (ftx, frx) = mpsc::channel::<Value>();
        let ftx = Mutex::new(ftx);
        let c = Connector::start(
            None,
            Arc::new(move |_, ws| {
                let _ = ws.get_ref().set_read_timeout(Some(Duration::from_secs(10)));
                let h1 = next(ws);
                let h2 = next(ws);
                put(ws, descriptor(&["send", "edit", "typing", "react", "delete", "prompt", "send_media"]));
                let src = json!({"platform": "slack", "chat_id": "C1", "chat_type": "group", "chat_name": "general", "user_id": "U1", "user_display_name": "Amy", "scope_id": "T1", "thread_id": "171.1"});
                // Two frames in one WS message plus a split frame across two messages.
                let a = json!({"type": "inbound", "bufferId": "b1", "event": {"text": "hi bot", "message_id": "m1", "source": src, "reply_to_message_id": "m0", "reply_to": {"text": "earlier", "author": "bot", "is_own": true}, "media_urls": ["https://c/relay/media/x", "https://cdn/y.png"], "media": [{"url": "https://cdn/y.png", "mime": "image/png", "filename": "y.png"}, {"url": "https://c/relay/media/x", "mime": "audio/ogg"}]}});
                let b = json!({"type": "inbound", "event": {"text": "", "message_id": "m2", "source": {"platform": "discord", "chat_id": "D9", "chat_type": "dm", "user_id": "U2"}, "prompt_response": {"prompt_id": "p1", "option_id": "appr:1:once"}}});
                ws.send_text(&format!("{a}\n{b}\n")).unwrap();
                let empty = json!({"type": "inbound", "bufferId": "b-empty", "event": {"text": " ", "source": {"chat_id": "C1"}}}).to_string();
                ws.send_text(&empty[..10]).unwrap();
                ws.send_text(&format!("{}\n", &empty[10..])).unwrap();
                put(ws, json!({"type": "interrupt_inbound", "session_key": "agent:main:slack:C1", "chat_id": "C1"}));
                put(ws, json!({"type": "inbound", "bufferId": "b3", "event": {"text": "edited!", "message_id": "m1:e", "message_type": "edit", "source": {"chat_id": "C1", "chat_type": "thread", "is_bot": true}}}));
                for f in [h1, h2] {
                    ftx.lock().unwrap().send(f).unwrap();
                }
                loop {
                    let f = next(ws);
                    ftx.lock().unwrap().send(f).unwrap();
                }
            }),
        );
        let r = relay(&c.url, Some("sekrit"));
        let got = poll_until(&r, 4);
        assert_eq!(got.len(), 4, "{got:?}");
        let up = &c.upgrades()[0];
        let tok = seagent_net::ws::header(up, "authorization").unwrap().strip_prefix("Bearer ").unwrap();
        assert_eq!(verify_token(tok, &["sekrit"], now_secs()).as_deref(), Some("gw-test"));
        let (h1, h2) = (frx.recv().unwrap(), frx.recv().unwrap());
        assert_eq!(h1, json!({"type": "hello", "platform": "slack", "botId": "B1"}));
        assert_eq!(h2["platform"], "discord");
        let m = &got[0];
        assert_eq!((m.chat.as_str(), m.chat_type, m.chat_name.as_str(), m.sender.as_str(), m.sender_name.as_str(), m.thread.as_deref(), m.account.as_str()), ("C1", ChatType::Group, "general", "U1", "Amy", Some("171.1"), "slack"));
        assert!(m.reply.as_ref().unwrap().is_own && m.addressed());
        assert_eq!((m.media[0].mime.as_str(), m.media[0].kind), ("audio/ogg", MediaKind::Voice), "media metadata by URL, not position");
        assert_eq!((m.media[1].name.as_str(), m.media[1].kind), ("y.png", MediaKind::Image));
        let cb = got[1].callback.as_ref().unwrap();
        assert_eq!((cb.id.as_str(), cb.data.as_str(), got[1].chat_type), ("p1", "appr:1:once", ChatType::Direct));
        assert_eq!((got[2].text.as_str(), got[2].chat.as_str()), ("/stop", "C1"), "interrupt → /stop");
        assert!(got[3].edited && got[3].is_bot && got[3].chat_type == ChatType::Thread);
        // Acks so far: the undeliverable frame at once, earlier batches on later polls;
        // the last batch's buffer ids wait for the next poll.
        std::thread::sleep(Duration::from_millis(300));
        let early: Vec<String> = frx.try_iter().map(|f| f["bufferId"].as_str().unwrap().to_string()).collect();
        assert!(early.contains(&"b-empty".to_string()), "{early:?}");
        let held = r.unacked.lock().unwrap().clone();
        assert!(!held.is_empty() && held.iter().all(|b| !early.contains(b)), "{held:?} {early:?}");
        assert!(r.poll(&Cancel::new()).unwrap().is_empty());
        let mut acked: Vec<String> = early;
        acked.extend((0..held.len()).map(|_| frx.recv_timeout(Duration::from_secs(5)).unwrap()["bufferId"].as_str().unwrap().to_string()));
        acked.sort();
        assert_eq!(acked, ["b-empty", "b1", "b3"], "each buffered frame acked exactly once");
        // fetch_media: bearer only for connector re-hosts.
        let bytes = r.fetch_media(&Media { url: Some(format!("{}/relay/media/x", c.url)), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"BYTES");
        let last = c.heads.lock().unwrap().last().unwrap().clone();
        assert!(seagent_net::ws::header(&last, "authorization").unwrap().starts_with("Bearer "));
        r.stop();
    }

    /// Connector that answers every outbound with `answer(action)` and records frames.
    fn answering(ops: &'static [&'static str], answer: fn(&Value) -> Value) -> (Connector, mpsc::Receiver<Value>) {
        answering_desc(descriptor(ops), answer)
    }

    fn answering_desc(desc: Value, answer: fn(&Value) -> Value) -> (Connector, mpsc::Receiver<Value>) {
        let (ftx, frx) = mpsc::channel::<Value>();
        let ftx = Mutex::new(ftx);
        let c = Connector::start(
            None,
            Arc::new(move |_, ws| {
                let _ = ws.get_ref().set_read_timeout(Some(Duration::from_secs(20)));
                next(ws);
                next(ws);
                put(ws, desc.clone());
                put(ws, json!({"type": "inbound", "event": {"text": "hello", "message_id": "m1", "source": {"platform": "slack", "chat_id": "C1", "chat_type": "dm", "user_id": "U1", "scope_id": "T1"}}}));
                loop {
                    let f = next(ws);
                    if f["type"] == "outbound" {
                        let res = answer(&f["action"]);
                        if !res.is_null() {
                            put(ws, json!({"type": "outbound_result", "requestId": f["requestId"], "result": res}));
                        }
                    }
                    if f["type"] == "going_idle" {
                        put(ws, json!({"type": "going_idle_ack"}));
                    }
                    ftx.lock().unwrap().send(f).unwrap();
                }
            }),
        );
        (c, frx)
    }

    #[test]
    fn outbound_ops_frame_shapes_and_gating() {
        static N: AtomicUsize = AtomicUsize::new(0);
        let (c, frx) = answering(&["send", "edit", "typing", "react", "delete", "prompt", "send_media"], |_| json!({"success": true, "message_id": format!("ts{}", N.fetch_add(1, Ordering::SeqCst))}));
        let r = relay(&c.url, Some("k"));
        assert_eq!(poll_until(&r, 1).len(), 1);
        assert_eq!(r.caps().max_len, 40);
        let out = Outbound {
            reply_to: Some("m1".into()),
            thread: Some("171.1".into()),
            silent: true,
            format: TextFormat::Markdown,
            buttons: vec![vec![crate::Button { label: "Allow".into(), data: "appr:1:once".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://d".into()) }]],
            ..Outbound::text("C1", &format!("{} **end**", "word ".repeat(10)))
        };
        let s = r.send(&out).unwrap();
        assert!(s.ids.len() >= 2, "split at descriptor max_len 40");
        let frames: Vec<Value> = s.ids.iter().map(|_| frx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        let f1 = frames[0].clone();
        assert_eq!((f1["type"].as_str(), f1["platform"].as_str(), f1["botId"].as_str()), (Some("outbound"), Some("slack"), Some("B1")), "tagged with the chat's platform identity");
        let a = &f1["action"];
        assert_eq!((a["op"].as_str(), a["chat_id"].as_str(), a["reply_to"].as_str()), (Some("send"), Some("C1"), Some("m1")));
        assert_eq!(a["metadata"], json!({"thread_id": "171.1", "silent": true, "scope_id": "T1", "user_id": "U1"}), "scope discriminators");
        assert!(frames.iter().all(|f| f["action"]["content"].as_str().unwrap().chars().count() <= 40));
        assert!(frames[1..].iter().all(|f| f["action"]["reply_to"].is_null()));
        let all: String = frames.iter().map(|f| f["action"]["content"].as_str().unwrap().to_string()).collect::<Vec<_>>().join(" ");
        let a = &frames.last().unwrap()["action"];
        assert_eq!((a["op"].as_str(), a["prompt_kind"].as_str(), a["reply_to"].clone()), (Some("prompt"), Some("choice"), Value::Null), "reply only on the first piece");
        assert_eq!(a["options"], json!([{"id": "appr:1:once", "label": "Allow"}]));
        assert!(all.contains("**end**") && all.contains("Docs: https://d"), "markdown kept for a rich dialect; url buttons as text: {all}");
        // Media: local file uploaded to /relay/media, then send_media by reference with caption.
        let f = crate::testutil::temp_dir("relay").join("a.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let m = Media { kind: MediaKind::Image, path: Some(f.display().to_string()), mime: "image/png".into(), ..Default::default() };
        r.send(&Outbound { media: vec![m], ..Outbound::text("C1", "cap") }).unwrap();
        let a = frx.recv_timeout(Duration::from_secs(5)).unwrap()["action"].clone();
        assert_eq!((a["op"].as_str(), a["media_kind"].as_str(), a["content"].as_str()), (Some("send_media"), Some("image"), Some("cap")));
        assert_eq!(a["source_url"], format!("{}/relay/media/m1", c.url));
        assert_eq!(c.bodies.lock().unwrap()[0], b"PNGDATA");
        let up = c.heads.lock().unwrap().iter().find(|h| h.starts_with("POST /relay/media")).cloned().unwrap();
        assert_eq!(seagent_net::ws::header(&up, "x-media-filename"), Some("a.png"));
        assert!(seagent_net::ws::header(&up, "authorization").unwrap().starts_with("Bearer "));
        // edit / delete / typing / react.
        r.edit("C1", "ts0", "new").unwrap();
        r.delete("C1", "ts0").unwrap();
        r.typing("C1", Some("171.1")).unwrap();
        r.react("C1", "ts0", "👍", true).unwrap();
        let ops: Vec<Value> = (0..4).map(|_| frx.recv_timeout(Duration::from_secs(5)).unwrap()["action"].clone()).collect();
        assert_eq!(ops.iter().map(|a| a["op"].as_str().unwrap()).collect::<Vec<_>>(), ["edit", "delete", "typing", "react"]);
        assert_eq!((ops[0]["message_id"].as_str(), ops[0]["content"].as_str()), (Some("ts0"), Some("new")));
        assert_eq!(ops[2]["metadata"]["thread_id"], "171.1");
        assert_eq!((ops[3]["emoji"].as_str(), ops[3]["remove"].as_bool()), (Some("👍"), Some(true)));
        assert!(r.go_idle(Duration::from_secs(5)), "going_idle acked");
        r.stop();
    }

    #[test]
    fn legacy_connector_gates_ops_and_falls_back_to_text_buttons() {
        let (c, frx) = answering(&[], |_| json!({"success": true, "message_id": "1"}));
        let r = relay(&c.url, None);
        assert_eq!(poll_until(&r, 1).len(), 1);
        assert!(c.upgrades().iter().all(|h| seagent_net::ws::header(h, "authorization").is_none()), "no secret → no bearer");
        assert_eq!(r.delete("C1", "1").unwrap_err().kind, K::Unsupported);
        assert_eq!(r.react("C1", "1", "x", false).unwrap_err().kind, K::Unsupported);
        let m = Media { kind: MediaKind::Image, path: Some("/nope".into()), ..Default::default() };
        assert_eq!(r.send(&Outbound { media: vec![m], ..Outbound::text("C1", "x") }).unwrap_err().kind, K::Unsupported);
        let out = Outbound { buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("C1", "ok?") };
        r.send(&out).unwrap();
        let a = frx.recv_timeout(Duration::from_secs(5)).unwrap()["action"].clone();
        assert_eq!((a["op"].as_str(), a["content"].as_str()), (Some("send"), Some("ok?\n\n1. Yes")));
        r.stop();
    }

    #[test]
    fn outbound_result_errors_timeout_and_disconnected() {
        let (c, _frx) = answering(&["send", "edit", "typing", "react"], |a| {
            let c = a["content"].as_str().unwrap_or("");
            match c {
                "declined" => json!({"success": false, "code": "egress_declined", "error": "egress declined: target not routed"}),
                "auth" => json!({"success": false, "error": "invalid_auth"}),
                "rate" => json!({"success": false, "error": "rate limited", "status": 429, "retry_after": 7}),
                "gone" => json!({"success": false, "error": "channel_not_found"}),
                "ambig" => json!({"success": false, "error": "lost ack", "ambiguous": true}),
                "weird" => json!({"success": false, "error": "invalid_blocks"}),
                "silent" => Value::Null,
                _ => json!({"success": true}),
            }
        });
        let r = relay(&c.url, Some("k"));
        assert_eq!(poll_until(&r, 1).len(), 1);
        for (text, kind) in [("declined", K::NotFound), ("auth", K::Auth), ("rate", K::RateLimited { retry_after: Some(Duration::from_secs(7)) }), ("gone", K::NotFound), ("ambig", K::Network), ("weird", K::Protocol)] {
            let e = r.send(&Outbound::text("C1", text)).unwrap_err();
            assert_eq!(e.kind, kind, "{text}: {}", e.message);
            assert!(!e.message.contains("Bearer"), "no credentials in errors");
        }
        let start = Instant::now();
        let e = r.send(&Outbound::text("C1", "silent")).unwrap_err();
        assert!(e.kind == K::Network && e.message.contains("ambiguous") && start.elapsed() >= Duration::from_secs(2), "{e}");
        assert!(r.sh.pending.lock().unwrap().is_empty(), "pending entry cleaned up");
        r.stop();
        std::thread::sleep(Duration::from_millis(200));
        let r2 = relay("http://127.0.0.1:1", None);
        assert_eq!(r2.send(&Outbound::text("C1", "x")).unwrap_err().kind, K::Network, "not connected");
    }

    #[test]
    fn reconnects_after_drop_and_fails_pending_requests() {
        let c = Connector::start(
            None,
            Arc::new(|n, ws| {
                let _ = ws.get_ref().set_read_timeout(Some(Duration::from_secs(10)));
                next(ws);
                next(ws);
                put(ws, descriptor(&["send"]));
                if n == 0 {
                    // Swallow one outbound then drop the TCP connection without a Close.
                    let f = next(ws);
                    assert_eq!(f["type"], "outbound");
                    let _ = ws.get_ref().shutdown(std::net::Shutdown::Both);
                    return;
                }
                put(ws, json!({"type": "inbound", "bufferId": "z", "event": {"text": "after reconnect", "message_id": "m9", "source": {"chat_id": "C1"}}}));
                std::thread::sleep(Duration::from_secs(5));
            }),
        );
        let r = relay(&c.url, Some("k"));
        r.start();
        wait_connected(&r);
        let e = r.send(&Outbound::text("C1", "lost")).unwrap_err();
        assert!(e.kind == K::Network && e.message.contains("connection lost"), "{e}");
        let got = poll_until(&r, 1);
        assert_eq!(got[0].text, "after reconnect");
        assert_eq!(c.upgrades().len(), 2);
        r.stop();
    }

    #[test]
    fn close_4401_redials_once_with_fresh_token_then_revokes() {
        let c = Connector::start(
            None,
            Arc::new(|n, ws| {
                let _ = ws.get_ref().set_read_timeout(Some(Duration::from_secs(10)));
                next(ws);
                next(ws);
                put(ws, descriptor(&["send"]));
                std::thread::sleep(Duration::from_millis(100));
                // 0: token expired (normal reconnect); 1: provisional 4401; 2: 4401 again → revoked.
                let reason = if n == 0 { "expired" } else { "unauthorized" };
                let _ = ws.send(&Message::Close(Some((4401, reason.into()))));
                std::thread::sleep(Duration::from_millis(300));
            }),
        );
        let r = relay(&c.url, Some("k"));
        let until = Instant::now() + Duration::from_secs(10);
        let e = loop {
            match r.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("never revoked"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth, "{e}");
        assert!(e.message.contains("revoked"));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(c.upgrades().len(), 3, "expired → reconnect, first 4401 → one fresh-token re-dial, second → stop");
        let toks: Vec<String> = c.upgrades().iter().map(|h| seagent_net::ws::header(h, "authorization").unwrap().to_string()).collect();
        assert!(toks.iter().all(|t| verify_token(t.strip_prefix("Bearer ").unwrap(), &["k"], now_secs()).is_some()));
    }

    #[test]
    fn refused_upgrade_is_auth_and_cancel_is_prompt() {
        let c = Connector::start(Some(401), Arc::new(|_, _| {}));
        let r = relay(&c.url, Some("bad"));
        let until = Instant::now() + Duration::from_secs(5);
        let e = loop {
            match r.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no auth error"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("bad"), "{e}");
        assert_eq!(c.upgrades().len(), 1, "never retried before any handshake");
        // A live connection with nothing to say: cancel ends the blocked poll quickly.
        let (c2, _f) = answering(&["send"], |_| json!({"success": true}));
        let r2 = Relay::new("rl", Options { url: c2.url.clone(), gateway_id: "g".into(), secret: None, identities: vec![("a".into(), "1".into()), ("b".into(), "2".into())], poll_timeout_secs: 30, outbound_timeout_secs: 1, connect_timeout_secs: 5, token_ttl_secs: 0, reconnect: true }).unwrap();
        assert_eq!(poll_until(&r2, 1).len(), 1);
        let cancel = Cancel::new();
        let c3 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c3.cancel();
        });
        let start = Instant::now();
        assert!(r2.poll(&cancel).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        r2.stop();
    }

    #[test]
    fn build_validates_settings() {
        let d = crate::testutil::temp_dir("relay");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:R}}", "rs"));
        let ctx = crate::config::Ctx { name: "rl", state_dir: &d, secrets: &secrets };
        let ok = json!({"url": "https://c.example.com", "secret": "{{secret:R}}", "platform": "slack", "bot_id": "B", "identities": [{"platform": "discord", "bot_id": "D"}]});
        assert_eq!(build(&ctx, ok.as_object().unwrap()).unwrap().id(), "rl");
        assert!(build(&ctx, json!({"url": "https://c", "secrett": 1}).as_object().unwrap()).err().unwrap().contains("secrett"));
        assert!(build(&ctx, json!({"url": "https://c", "secret": "{{secret:NOPE}}"}).as_object().unwrap()).err().unwrap().contains("not set"));
        assert!(build(&ctx, json!({"url": "ftp://c"}).as_object().unwrap()).is_err());
    }
    fn drafting(platform: &str, flag: bool) -> Value {
        let mut d = descriptor(&["send", "edit", "typing", "draft"]);
        d["descriptor"]["platform"] = json!(platform);
        d["descriptor"]["supports_draft_streaming"] = json!(flag);
        d["descriptor"]["max_message_length"] = json!(4000);
        d
    }

    fn outbound_actions(frx: &mpsc::Receiver<Value>) -> Vec<Value> {
        std::thread::sleep(Duration::from_millis(200));
        frx.try_iter().filter(|f| f["type"] == "outbound").map(|f| f["action"].clone()).collect()
    }

    #[test]
    fn draft_streaming_seals_slack_and_sends_final_elsewhere() {
        static RETRIED: AtomicBool = AtomicBool::new(false);
        let (c, frx) = answering_desc(drafting("slack", true), |a| {
            if a["final"] == true && a["content"] == "retry me" && !RETRIED.swap(true, Ordering::SeqCst) {
                return json!({"success": false, "error": "ack lost", "ambiguous": true});
            }
            if a["op"] == "draft" && a["content"] == "declined draft text" {
                return json!({"success": false, "code": "egress_declined", "error": "egress declined: no"});
            }
            json!({"success": true, "message_id": "ts1"})
        });
        let r = Arc::new(relay(&c.url, Some("k")));
        assert_eq!(poll_until(&r, 1).len(), 1);
        assert_eq!(r.caps().streaming, Streaming::Native);
        // Through the host's streamer: two partial frames then the seal, no extra send.
        let base = Outbound { reply_to: Some("m1".into()), format: TextFormat::Markdown, ..Outbound::text("C1", "") };
        let mut st = crate::deliver::Stream::new(r.clone(), base.clone());
        st.interval = Duration::ZERO;
        st.update("first part of the streamed answer");
        st.update("first part of the streamed answer, and more");
        assert!(st.finish("first part of the streamed answer, and more. **Done**", &crate::deliver::Deliverer::new(None)));
        let a = outbound_actions(&frx);
        assert_eq!(a.iter().map(|a| (a["op"].as_str().unwrap(), a["final"].as_bool().unwrap())).collect::<Vec<_>>(), [("draft", false), ("draft", false), ("draft", true)]);
        assert!(a.iter().all(|x| x["draft_id"] == a[0]["draft_id"] && x["draft_id"].as_u64().unwrap() > 0), "one draft_id per stream");
        assert_eq!(a[1]["content"], "first part of the streamed answer, and more", "whole text so far, not a delta");
        assert_eq!(a[2]["content"], "first part of the streamed answer, and more. **Done**", "rich dialect keeps markdown");
        assert_eq!(a[0]["metadata"], json!({"thread_id": "m1", "scope_id": "T1", "user_id": "U1"}), "slack stream anchored on the trigger");
        // A lost seal ack is retried once with the identical frame.
        let h = r.stream_begin(&Outbound::text("C1", "streaming...")).unwrap().unwrap();
        r.stream_finish("C1", &h, "retry me", "").unwrap();
        let a = outbound_actions(&frx);
        assert_eq!(a.len(), 3);
        assert_eq!((&a[1], a[1]["final"].as_bool()), (&a[2], Some(true)));
        assert!(r.drafts.lock().unwrap().is_empty());
        // A refused draft: no stream; the streamer falls back to send + edit.
        assert!(r.stream_begin(&Outbound::text("C1", "declined draft text")).is_err());
        assert!(r.stream_update("C1", "nope", "x", "x").is_err(), "unknown handle");
        r.stop();
        // Telegram-shaped drafts: preview frames, then the final is an ordinary send.
        let (c, frx) = answering_desc(drafting("telegram", true), |_| json!({"success": true, "message_id": "9"}));
        let r = relay(&c.url, None);
        assert_eq!(poll_until(&r, 1).len(), 1);
        let h = r.stream_begin(&Outbound { thread: Some("42".into()), ..Outbound::text("C1", "draft one") }).unwrap().unwrap();
        r.stream_update("C1", &h, "draft one two", " two").unwrap();
        r.stream_finish("C1", &h, "final answer", "").unwrap();
        let a = outbound_actions(&frx);
        assert_eq!(a.iter().map(|a| a["op"].as_str().unwrap()).collect::<Vec<_>>(), ["draft", "draft", "send"]);
        assert_eq!((a[2]["content"].as_str(), a[2]["metadata"]["thread_id"].as_str()), (Some("final answer"), Some("42")));
        assert!(a[..2].iter().all(|x| x["final"] == false && x["metadata"]["thread_id"] == "42"));
        r.stop();
        // The flag without the explicit op (or the op without the flag) never streams natively.
        let mut d = drafting("slack", true);
        d["descriptor"]["supported_ops"] = json!([]);
        assert_eq!(Descriptor::from_value(&d["descriptor"]).caps().streaming, Streaming::Edit);
        let d = Descriptor::from_value(&drafting("slack", false)["descriptor"]);
        assert_eq!(d.caps().streaming, Streaming::Edit);
    }

    #[test]
    fn thread_ops_and_task_card_frames() {
        let (c, frx) = answering(&["send", "thread_create", "thread_rename", "task_card"], |a| match a["op"].as_str() {
            Some("thread_create") if a["thread_name"] == "bad" => json!({"success": true}),
            Some("thread_create") => json!({"success": true, "thread_id": "T9"}),
            _ => json!({"success": true}),
        });
        let r = relay(&c.url, Some("k"));
        assert_eq!(poll_until(&r, 1).len(), 1);
        assert_eq!(r.create_thread("C1", "   ", Some("m1")).unwrap(), "T9");
        r.create_thread("C1", &"x".repeat(150), None).unwrap();
        assert_eq!(r.create_thread("C1", "bad", None).unwrap_err().kind, K::Protocol, "no id in result");
        r.rename_thread("T9", " new \n name ", Some("C1"), RenameGuard::ConnectorCreated).unwrap();
        r.rename_thread("T9", "n2", None, RenameGuard::CurrentName("old")).unwrap();
        assert_eq!(r.rename_thread("T9", "  ", None, RenameGuard::None).unwrap_err().kind, K::Fatal);
        let tasks = [
            TaskItem { id: "call_1".into(), title: "terminal".into(), status: TaskStatus::InProgress, details: Some("ls -la".into()) },
            TaskItem { id: "call_2".into(), title: "web_search".into(), status: TaskStatus::Complete, details: None },
        ];
        assert!(r.supports_task_cards("C1"));
        r.task_card("C1", Some("m1"), None, &tasks).unwrap();
        r.task_card_stop("C1", Some("m1"), None).unwrap();
        r.task_card_stop("C1", None, None).unwrap();
        let a = outbound_actions(&frx);
        assert_eq!(a.len(), 8, "{a:?}");
        assert_eq!(a[0], json!({"op": "thread_create", "chat_id": "C1", "thread_name": "handoff", "message_id": "m1", "metadata": {"scope_id": "T1", "user_id": "U1"}}));
        assert_eq!((a[1]["thread_name"].as_str().unwrap().len(), a[1].get("message_id")), (100, None));
        assert_eq!(a[3], json!({"op": "thread_rename", "chat_id": "C1", "message_id": "T9", "thread_name": "new name", "only_if_connector_created": true, "metadata": {"scope_id": "T1", "user_id": "U1"}}));
        assert_eq!((a[4]["chat_id"].as_str(), a[4]["only_if_current_name"].as_str()), (Some("T9"), Some("old")), "parent defaults to the thread");
        assert_eq!(a[5], json!({"op": "task_card", "chat_id": "C1", "card_id": "turn:m1", "chunks": [{"id": "call_1", "title": "terminal", "status": "in_progress", "details": "ls -la"}, {"id": "call_2", "title": "web_search", "status": "complete"}], "metadata": {"thread_ts": "m1", "scope_id": "T1", "user_id": "U1"}}));
        assert_eq!(a[6], json!({"op": "task_card_stop", "chat_id": "C1", "card_id": "turn:m1", "metadata": {"scope_id": "T1", "user_id": "U1"}}));
        assert_eq!(a[7]["card_id"], "turn:root");
        r.stop();
        // Never fail-open: a legacy connector (no supported_ops) gets none of these frames.
        let (c, frx) = answering(&[], |_| json!({"success": true, "thread_id": "x"}));
        let r = relay(&c.url, None);
        assert_eq!(poll_until(&r, 1).len(), 1);
        assert_eq!(r.create_thread("C1", "t", None).unwrap_err().kind, K::Unsupported);
        assert_eq!(r.rename_thread("T", "t", None, RenameGuard::None).unwrap_err().kind, K::Unsupported);
        assert_eq!(r.task_card("C1", None, None, &tasks).unwrap_err().kind, K::Unsupported);
        assert_eq!(r.task_card_stop("C1", None, None).unwrap_err().kind, K::Unsupported);
        assert_eq!(r.stream_begin(&Outbound::text("C1", "x")).unwrap(), None);
        assert!(outbound_actions(&frx).is_empty());
        r.stop();
    }

    fn forward(platform: &str, body: &Value) -> Value {
        json!({"platform": platform, "botId": "appShared", "method": "POST", "path": "/interactions/discord/appShared", "headers": [["content-type", "application/json"]], "bodyB64": seagent_net::crypto::b64(body.to_string().as_bytes())})
    }

    #[test]
    fn passthrough_decodes_discord_interactions() {
        let labels: HashMap<String, ChatMeta> = [("TH1".to_string(), ChatMeta { chat_name: "general".into(), ..Default::default() })].into();
        // Slash command in a public thread, sub-command group + options, guild nick wins.
        let cmd = json!({"type": 2, "id": "i1", "guild_id": "G1", "channel_id": "TH1", "channel": {"type": 11, "parent_id": "P1"}, "member": {"nick": "Nick", "user": {"id": "U5", "global_name": "Glob", "username": "user"}}, "data": {"name": "model", "options": [{"type": 1, "name": "set", "options": [{"type": 3, "name": "id", "value": " opus "}, {"type": 4, "name": "n", "value": 3}, {"type": 3, "name": "e", "value": ""}]}]}});
        let mut f = forward("discord", &cmd);
        f["profile"] = json!("work");
        let (m, meta) = passthrough_of("rl", &f, &labels).unwrap();
        assert_eq!(m.text, "/model set opus 3");
        assert_eq!((m.chat.as_str(), m.chat_type, m.thread.as_deref(), m.sender.as_str(), m.sender_name.as_str(), m.account.as_str()), ("TH1", ChatType::Thread, Some("TH1"), "U5", "Nick", "discord"));
        assert_eq!((m.chat_name.as_str(), m.message_id.as_str()), ("general", "interaction:i1"), "text lane's label carried over");
        assert_eq!((meta.scope_id.as_str(), meta.profile.as_str(), meta.chat_type.as_str()), ("G1", "work", "thread"));
        // Our prompt token → structured callback; a DM user falls back to global name.
        let press = json!({"type": 3, "id": "i2", "channel_id": "D1", "user": {"id": "U6", "global_name": "Glob"}, "message": {"id": "pm"}, "data": {"custom_id": "hp1:ab12.3f:approve"}});
        let (m, _) = passthrough_of("rl", &forward("discord", &press), &labels).unwrap();
        let cb = m.callback.clone().unwrap();
        assert_eq!((cb.id.as_str(), cb.data.as_str(), m.text.as_str(), m.chat_type, m.sender_name.as_str()), ("ab12.3f", "approve", "/approve", ChatType::Direct, "Glob"));
        assert_eq!(m.message_id, "prompt:ab12.3f:i2");
        // Foreign component ids stay text; a guild non-thread channel is a group.
        let foreign = json!({"type": 3, "id": "i3", "guild_id": "G1", "channel_id": "C2", "channel": {"type": 0}, "member": {"user": {"id": "U5", "username": "user"}}, "data": {"custom_id": "hp1:bad:id:x"}});
        let (m, _) = passthrough_of("rl", &forward("discord", &foreign), &labels).unwrap();
        assert_eq!((m.text.as_str(), m.callback.is_none(), m.chat_type, m.thread.is_none(), m.sender_name.as_str()), ("hp1:bad:id:x", true, ChatType::Group, true, "user"));
        // Modal submit: action rows and label-wrapped inputs, empty optional input skipped.
        let modal = json!({"type": 5, "id": "i4", "channel_id": "D1", "user": {"id": "U6"}, "data": {"custom_id": "feedback", "components": [{"type": 1, "components": [{"type": 4, "custom_id": "title", "value": "Hi"}]}, {"type": 18, "component": {"type": 3, "custom_id": "pick", "values": ["a", "b"]}}, {"type": 1, "components": [{"type": 4, "custom_id": "opt", "value": ""}]}]}});
        assert_eq!(passthrough_of("rl", &forward("discord", &modal), &labels).unwrap().0.text, "feedback\ntitle: Hi\npick: a, b");
        // Not a turn: PING, garbage body, other platforms.
        assert!(passthrough_of("rl", &forward("discord", &json!({"type": 1})), &labels).is_none());
        assert!(passthrough_of("rl", &json!({"platform": "discord", "bodyB64": "!!"}), &labels).is_none());
        assert!(passthrough_of("rl", &forward("twilio", &cmd), &labels).is_none());
        assert_eq!(prompt_token("hp1:a:b"), Some(("a".into(), "b".into())));
        assert!(prompt_token(&format!("hp1:{}:b", "a".repeat(33))).is_none() && prompt_token("hp1:a b:c").is_none() && prompt_token("hp2:a:b").is_none());
    }

    #[test]
    fn passthrough_forward_frames_are_delivered_and_acked() {
        let (ftx, frx) = mpsc::channel::<Value>();
        let ftx = Mutex::new(ftx);
        let c = Connector::start(
            None,
            Arc::new(move |_, ws| {
                let _ = ws.get_ref().set_read_timeout(Some(Duration::from_secs(10)));
                next(ws);
                next(ws);
                let mut d = descriptor(&["send"]);
                d["descriptor"]["platform"] = json!("discord");
                put(ws, d);
                let cmd = json!({"type": 2, "id": "i1", "guild_id": "G1", "channel_id": "C7", "member": {"user": {"id": "U5", "username": "amy"}}, "data": {"name": "status"}});
                put(ws, json!({"type": "passthrough_forward", "bufferId": "pf1", "forward": forward("discord", &cmd)}));
                put(ws, json!({"type": "passthrough_forward", "bufferId": "pf-tw", "forward": forward("twilio", &cmd)}));
                loop {
                    let f = next(ws);
                    if f["type"] == "outbound" {
                        put(ws, json!({"type": "outbound_result", "requestId": f["requestId"], "result": {"success": true, "message_id": "r1"}}));
                    }
                    ftx.lock().unwrap().send(f).unwrap();
                }
            }),
        );
        let r = relay(&c.url, None);
        let got = poll_until(&r, 1);
        assert_eq!((got[0].text.as_str(), got[0].chat.as_str(), got[0].chat_type), ("/status", "C7", ChatType::Group));
        // The reply goes back over the normal send lane, tagged with the interaction's scope.
        r.send(&Outbound::text("C7", "all good")).unwrap();
        assert!(r.poll(&Cancel::new()).unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(200));
        let frames: Vec<Value> = frx.try_iter().collect();
        let acks: Vec<&str> = frames.iter().filter(|f| f["type"] == "inbound_ack").map(|f| f["bufferId"].as_str().unwrap()).collect();
        assert_eq!(acks, ["pf-tw", "pf1"], "undecodable acked at once, the turn after handoff");
        let out = frames.iter().find(|f| f["type"] == "outbound").unwrap();
        assert_eq!((out["platform"].as_str(), out["botId"].as_str()), (Some("discord"), Some("D1")));
        assert_eq!(out["action"]["metadata"], json!({"scope_id": "G1", "user_id": "U5"}));
        r.stop();
    }
}
