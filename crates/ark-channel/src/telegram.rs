//! Telegram Bot API (ported from OpenClaw `extensions/telegram` and Hermes
//! `plugins/platforms/telegram`, both MIT).
//!
//! Receive: long-poll `getUpdates`, or webhook mode (`setWebhook` with a
//! `secret_token` checked on every request). Messages, edits, channel posts,
//! button callbacks, forum topics, replies, @mentions and every media kind.
//! Send: HTML from the model's Markdown, media by URL or multipart upload,
//! inline-keyboard buttons, threads, silent sends; edit, delete, typing,
//! reactions, callback acks; `/` commands registered with `setMyCommands`.
//! Delivery is at-least-once: a batch's offset is committed to the state file
//! only when the caller polls again, so a crash redelivers (the router dedups).

use crate::http::{agent, post_cancellable, Http, Payload};
use crate::{
    markup, sleep_cancellable, write_atomic, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat,
};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_BASE: &str = "https://api.telegram.org";
/// Telegram counts message length in UTF-16 code units.
pub const MAX_MESSAGE: usize = 4096;

pub struct Telegram {
    id: String,
    token: String,
    base: String,
    state: PathBuf,
    poll_timeout: u64,
    agent: ureq::Agent,
    /// First retry delay; doubles each attempt.
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest `retry_after` honoured in place; longer waits surface as `RateLimited`.
    pub max_wait: Duration,
    offset: Mutex<Offsets>,
    /// (bot id, username) from getMe, fetched lazily.
    me: Mutex<Option<(i64, String)>>,
    /// Webhook mode: updates arrive here from the listener.
    hook: Option<Hook>,
    commands_registered: std::sync::atomic::AtomicBool,
    pub register_commands: bool,
}

struct Hook {
    _server: ark_net::httpd::Server,
    rx: Mutex<std::sync::mpsc::Receiver<Value>>,
}

struct Offsets {
    committed: i64,
    pending: Option<i64>,
}

impl Telegram {
    /// `state` is a small JSON file holding the next update offset.
    pub fn new(id: &str, token: &str, base: Option<&str>, state: PathBuf, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: telegram token is empty"));
        }
        let committed = match std::fs::read_to_string(&state) {
            Ok(s) => serde_json::from_str::<Value>(&s).ok().and_then(|v| v["offset"].as_i64()).unwrap_or(0),
            Err(_) => 0,
        };
        Ok(Telegram {
            id: id.to_string(),
            token: token.trim().to_string(),
            base: base.unwrap_or(DEFAULT_BASE).trim_end_matches('/').to_string(),
            state,
            poll_timeout: poll_timeout_secs,
            agent: agent(Duration::from_secs(poll_timeout_secs + 15)),
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            offset: Mutex::new(Offsets { committed, pending: None }),
            me: Mutex::new(None),
            hook: None,
            commands_registered: std::sync::atomic::AtomicBool::new(false),
            register_commands: false,
        })
    }

    /// Switch to webhook mode: listen on `listen`, register `public_url` with Telegram.
    /// Every request must carry `X-Telegram-Bot-Api-Secret-Token: <secret>`.
    pub fn with_webhook(mut self, listen: &str, public_url: &str, secret: &str) -> Result<Self, String> {
        if secret.len() < 16 || !secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!("channel {}: webhook_secret must be ≥16 chars of A-Z a-z 0-9 _ -", self.id));
        }
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        let tx = Mutex::new(tx);
        let want = secret.to_string();
        let path = ark_net::Url::parse(public_url).map(|u| u.path.split('?').next().unwrap_or("/").to_string()).map_err(|e| format!("channel {}: webhook_url: {e}", self.id))?;
        let handler: ark_net::httpd::Handler = std::sync::Arc::new(move |r: ark_net::httpd::Request| {
            if r.method != "POST" || r.path != path {
                return ark_net::httpd::Response::text(404, "not found");
            }
            let ok = r.header("x-telegram-bot-api-secret-token").is_some_and(|t| ark_net::crypto::ct_eq(t.as_bytes(), want.as_bytes()));
            if !ok {
                return ark_net::httpd::Response::text(401, "bad secret");
            }
            match serde_json::from_slice::<Value>(&r.body) {
                Ok(v) => {
                    let _ = tx.lock().unwrap().send(v);
                    ark_net::httpd::Response::text(200, "ok")
                }
                Err(_) => ark_net::httpd::Response::text(400, "bad json"),
            }
        });
        let server = ark_net::httpd::Server::bind(listen, ark_net::httpd::Opts::default(), handler).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.id))?;
        let body = json!({"url": public_url, "secret_token": secret, "allowed_updates": ALLOWED_UPDATES});
        self.call("setWebhook", &body, &Cancel::new()).map_err(|e| format!("channel {}: setWebhook failed: {}", self.id, e.message))?;
        self.hook = Some(Hook { _server: server, rx: Mutex::new(rx) });
        Ok(self)
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base, self.token)
    }

    /// Bot id and username, cached after the first successful getMe.
    fn me(&self) -> Option<(i64, String)> {
        if let Some(m) = self.me.lock().unwrap().clone() {
            return Some(m);
        }
        let v = self.call("getMe", &json!({}), &Cancel::new()).ok()??;
        let m = (v["id"].as_i64()?, v["username"].as_str().unwrap_or("").to_string());
        *self.me.lock().unwrap() = Some(m.clone());
        Some(m)
    }

    fn register_commands_once(&self) {
        if !self.register_commands || self.commands_registered.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let cmds = json!({"commands": [
            {"command": "new", "description": "開新對話"},
            {"command": "stop", "description": "中斷目前的工作"},
            {"command": "status", "description": "目前狀態"},
            {"command": "help", "description": "說明"},
        ]});
        let _ = self.call("setMyCommands", &cmds, &Cancel::new());
    }

    /// Multipart upload for local files (`sendPhoto`, `sendDocument`…).
    fn upload(&self, method: &str, field: &str, fields: &[(String, String)], path: &str, mime: &str) -> Result<Value, ChannelError> {
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let fname = std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let mut parts: Vec<(&str, &str, &str, &[u8])> = fields.iter().map(|(k, v)| (k.as_str(), "", "", v.as_bytes())).collect();
        parts.push((field, &fname, mime, &data));
        let http = Http { agent: self.agent.clone(), headers: vec![] };
        let r = http.call("POST", &self.url(method), &[], Payload::Multipart(&parts))?;
        tg_result(method, r.status, r.retry_after, &r.body)
    }

    /// One Bot API call with retries. `Ok(None)` = cancelled.
    fn call(&self, method: &str, body: &Value, cancel: &Cancel) -> Result<Option<Value>, ChannelError> {
        let url = self.url(method);
        let bytes = serde_json::to_vec(body).expect("json");
        let mut attempt = 0;
        loop {
            let err = match post_cancellable(&self.agent, &url, &[], bytes.clone(), cancel)? {
                None => return Ok(None),
                Some(r) => match tg_result(method, r.status, r.retry_after, &r.body) {
                    Ok(v) => return Ok(Some(v)),
                    Err(e) if e.is_retryable() => e,
                    Err(e) => return Err(e),
                },
            };
            if attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            if !sleep_cancellable(wait, cancel) {
                return Ok(None);
            }
            attempt += 1;
        }
    }

    fn commit_pending(&self) -> Result<i64, ChannelError> {
        let mut o = self.offset.lock().unwrap();
        if let Some(p) = o.pending.take() {
            write_atomic(&self.state, json!({ "offset": p }).to_string().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving telegram offset: {e}")))?;
            o.committed = p;
        }
        Ok(o.committed)
    }
}

/// Telegram's `{ok, result, description, parameters}` envelope → result or a classified error.
fn tg_result(method: &str, status: u16, retry_after: Option<Duration>, body: &str) -> Result<Value, ChannelError> {
    let v: Option<Value> = serde_json::from_str(body).ok();
    let desc = v.as_ref().and_then(|v| v["description"].as_str()).unwrap_or("").to_string();
    match status {
        200 if v.as_ref().is_some_and(|v| v["ok"] == true) => Ok(v.unwrap()["result"].clone()),
        200 => Err(ChannelError::new(K::Protocol, format!("{method}: unexpected response {}", crate::http::redact(&body.chars().take(200).collect::<String>())))),
        401 => Err(ChannelError::new(K::Auth, format!("telegram rejected the bot token ({status} {desc})"))),
        404 if method != "getFile" => Err(ChannelError::new(K::Auth, format!("telegram rejected the bot token ({status} {desc})"))),
        // Blocked by the user, kicked from the group, chat deleted: never retry.
        403 => Err(ChannelError::new(K::NotFound, format!("{method}: {desc}"))),
        400 if desc.contains("chat not found") || desc.contains("bot was kicked") || desc.contains("user is deactivated") => Err(ChannelError::new(K::NotFound, format!("{method}: {desc}"))),
        409 => Err(ChannelError::new(K::Fatal, format!("telegram conflict: {desc} (another poller or a webhook is active)"))),
        429 => {
            let ra = v.as_ref().and_then(|v| v["parameters"]["retry_after"].as_u64()).map(Duration::from_secs).or(retry_after);
            Err(ChannelError::new(K::RateLimited { retry_after: ra }, format!("{method}: rate limited {desc}")))
        }
        s if s >= 500 => Err(ChannelError::new(K::Network, format!("{method}: HTTP {s} {desc}"))),
        s => Err(ChannelError::new(K::Protocol, format!("{method}: HTTP {s} {desc}"))),
    }
}

const ALLOWED_UPDATES: [&str; 4] = ["message", "edited_message", "channel_post", "callback_query"];

fn id_str(v: &Value) -> Option<String> {
    v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string))
}

fn media_of(m: &Value) -> Vec<Media> {
    let mut out = Vec::new();
    let file = |v: &Value, kind: MediaKind| Media {
        kind,
        id: v["file_id"].as_str().map(str::to_string),
        name: v["file_name"].as_str().unwrap_or("").to_string(),
        mime: v["mime_type"].as_str().unwrap_or(if kind == MediaKind::Image { "image/jpeg" } else { "" }).to_string(),
        size: v["file_size"].as_u64().unwrap_or(0),
        ..Default::default()
    };
    if let Some(sizes) = m["photo"].as_array() {
        // Largest rendition.
        if let Some(p) = sizes.iter().max_by_key(|p| p["file_size"].as_u64().unwrap_or(0).max(p["width"].as_u64().unwrap_or(0) * p["height"].as_u64().unwrap_or(0))) {
            out.push(Media { name: "photo.jpg".into(), ..file(p, MediaKind::Image) });
        }
    }
    for (k, kind) in [("document", MediaKind::Document), ("voice", MediaKind::Voice), ("audio", MediaKind::Audio), ("video", MediaKind::Video), ("animation", MediaKind::Animation), ("sticker", MediaKind::Sticker), ("video_note", MediaKind::Video)] {
        // An animation also appears as `document`; keep only the specific kind.
        if k == "document" && m.get("animation").is_some() {
            continue;
        }
        if m[k].is_object() {
            out.push(file(&m[k], kind));
        }
    }
    out
}

/// One update → an Inbound. `me` = (bot id, username) for mention / own-reply detection.
fn inbound_of(channel: &str, u: &Value, me: Option<&(i64, String)>) -> Option<Inbound> {
    if let Some(cb) = u.get("callback_query") {
        let msg = &cb["message"];
        let from = &cb["from"];
        return Some(Inbound {
            channel: channel.to_string(),
            chat: id_str(&msg["chat"]["id"]).or_else(|| id_str(&from["id"]))?,
            chat_type: chat_type(&msg["chat"]),
            thread: msg["message_thread_id"].as_i64().filter(|_| msg["is_topic_message"] == true).map(|t| t.to_string()),
            sender: id_str(&from["id"]).unwrap_or_default(),
            sender_name: from["username"].as_str().or_else(|| from["first_name"].as_str()).unwrap_or("").to_string(),
            message_id: format!("cb:{}", cb["id"].as_str().unwrap_or("")),
            callback: Some(Callback { id: cb["id"].as_str().unwrap_or("").to_string(), data: cb["data"].as_str().unwrap_or("").to_string() }),
            reply: id_str(&msg["message_id"]).map(|id| ReplyRef { id, is_own: true, ..Default::default() }),
            ..Default::default()
        });
    }
    let (m, edited) = match (u.get("message"), u.get("edited_message"), u.get("channel_post")) {
        (Some(m), _, _) => (m, false),
        (_, Some(m), _) => (m, true),
        (_, _, Some(m)) => (m, false),
        _ => return None,
    };
    let text = m["text"].as_str().or_else(|| m["caption"].as_str()).unwrap_or("");
    let media = media_of(m);
    if text.is_empty() && media.is_empty() {
        return None;
    }
    let from = &m["from"];
    let entities = m["entities"].as_array().or_else(|| m["caption_entities"].as_array());
    let mentioned = me.is_some_and(|(id, user)| {
        entities.into_iter().flatten().any(|e| {
            let seg = utf16_slice(text, e["offset"].as_u64().unwrap_or(0) as usize, e["length"].as_u64().unwrap_or(0) as usize);
            match e["type"].as_str() {
                Some("mention") => !user.is_empty() && seg.trim_start_matches('@').eq_ignore_ascii_case(user),
                Some("text_mention") => e["user"]["id"].as_i64() == Some(*id),
                Some("bot_command") => seg.split_once('@').is_some_and(|(_, u)| u.eq_ignore_ascii_case(user)),
                _ => false,
            }
        })
    });
    let reply = m.get("reply_to_message").filter(|r| r.is_object()).and_then(|r| {
        // In forums every message "replies" to the topic's first message; that is not a real reply.
        if m["is_topic_message"] == true && r["forum_topic_created"].is_object() {
            return None;
        }
        Some(ReplyRef {
            id: id_str(&r["message_id"])?,
            text: r["text"].as_str().or_else(|| r["caption"].as_str()).unwrap_or("").to_string(),
            author: r["from"]["username"].as_str().or_else(|| r["from"]["first_name"].as_str()).unwrap_or("").to_string(),
            is_own: me.is_some_and(|(id, _)| r["from"]["id"].as_i64() == Some(*id)),
        })
    });
    Some(Inbound {
        channel: channel.to_string(),
        chat: id_str(&m["chat"]["id"])?,
        chat_type: chat_type(&m["chat"]),
        chat_name: m["chat"]["title"].as_str().unwrap_or("").to_string(),
        thread: m["message_thread_id"].as_i64().filter(|_| m["is_topic_message"] == true).map(|t| t.to_string()),
        sender: id_str(&from["id"]).or_else(|| id_str(&m["sender_chat"]["id"])).unwrap_or_default(),
        sender_name: from["username"].as_str().or_else(|| from["first_name"].as_str()).unwrap_or("").to_string(),
        is_bot: from["is_bot"] == true,
        text: text.to_string(),
        // Edits reuse the message id; suffix so dedup lets them through.
        message_id: id_str(&m["message_id"]).map(|id| if edited { format!("{id}:e{}", m["edit_date"].as_i64().unwrap_or(0)) } else { id }).unwrap_or_default(),
        ts: m["date"].as_i64().unwrap_or(0),
        media,
        mentioned,
        reply,
        edited,
        ..Default::default()
    })
}

fn chat_type(c: &Value) -> ChatType {
    match c["type"].as_str() {
        Some("group") | Some("supergroup") => ChatType::Group,
        Some("channel") => ChatType::Channel,
        _ => ChatType::Direct,
    }
}

/// Telegram entity offsets are in UTF-16 units.
fn utf16_slice(s: &str, off: usize, len: usize) -> String {
    let u: Vec<u16> = s.encode_utf16().collect();
    let end = (off + len).min(u.len());
    String::from_utf16_lossy(&u[off.min(end)..end])
}

fn keyboard(rows: &[Vec<crate::Button>]) -> Value {
    json!({"inline_keyboard": rows.iter().map(|r| r.iter().map(|b| match &b.url {
        Some(u) => json!({"text": b.label, "url": u}),
        // callback_data is limited to 64 bytes.
        None => json!({"text": b.label, "callback_data": truncate_bytes(&b.data, 64)}),
    }).collect::<Vec<_>>()).collect::<Vec<_>>()})
}

fn truncate_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn media_method(k: MediaKind) -> (&'static str, &'static str) {
    match k {
        MediaKind::Image => ("sendPhoto", "photo"),
        MediaKind::Video => ("sendVideo", "video"),
        MediaKind::Audio => ("sendAudio", "audio"),
        MediaKind::Voice => ("sendVoice", "voice"),
        MediaKind::Animation => ("sendAnimation", "animation"),
        MediaKind::Sticker => ("sendSticker", "sticker"),
        MediaKind::Document => ("sendDocument", "document"),
    }
}

impl Telegram {
    fn render(&self, out: &Outbound, text: &str) -> (String, Option<&'static str>) {
        match out.format {
            TextFormat::Markdown => (markup::convert(text, Markup::TelegramHtml), Some("HTML")),
            TextFormat::Plain => (text.to_string(), None),
        }
    }

    fn common(&self, out: &Outbound, body: &mut Value, first: bool) {
        if let Some(t) = out.thread.as_deref().and_then(|t| t.parse::<i64>().ok()) {
            body["message_thread_id"] = json!(t);
        }
        if out.silent {
            body["disable_notification"] = json!(true);
        }
        if let (true, Some(r)) = (first, out.reply_to.as_deref().and_then(|r| r.parse::<i64>().ok())) {
            body["reply_parameters"] = json!({ "message_id": r, "allow_sending_without_reply": true });
        }
    }

    fn send_media(&self, out: &Outbound, m: &Media, caption: Option<&str>, first: bool, last: bool) -> Result<String, ChannelError> {
        let (method, field) = media_method(m.kind);
        let mut body = json!({"chat_id": out.chat});
        self.common(out, &mut body, first);
        if let Some(c) = caption.or(m.caption.as_deref()) {
            let (t, mode) = self.render(out, c);
            body["caption"] = json!(t);
            if let Some(mode) = mode {
                body["parse_mode"] = json!(mode);
            }
        }
        if last && !out.buttons.is_empty() {
            body["reply_markup"] = keyboard(&out.buttons);
        }
        let r = match (&m.path, &m.url, &m.id) {
            (Some(p), _, _) => {
                let fields: Vec<(String, String)> = body.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect();
                self.upload(method, field, &fields, p, &m.mime)?
            }
            (None, Some(u), _) | (None, None, Some(u)) => {
                body[field] = json!(u);
                self.call(method, &body, &Cancel::new())?.unwrap_or_default()
            }
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path, url nor id")),
        };
        Ok(id_str(&r["message_id"]).unwrap_or_default())
    }
}

impl Channel for Telegram {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Channel, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 1,
            edit: true,
            delete: true,
            typing: true,
            buttons: true,
            polls: false,
            native_commands: true,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Utf16,
            markup: Markup::TelegramHtml,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.register_commands_once();
        let updates: Vec<Value> = if let Some(h) = &self.hook {
            let rx = h.rx.lock().unwrap();
            let until = std::time::Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
            let mut got = Vec::new();
            while got.is_empty() && !cancel.is_cancelled() && std::time::Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
            got
        } else {
            let offset = self.commit_pending()?;
            let body = json!({ "offset": offset, "timeout": self.poll_timeout, "allowed_updates": ALLOWED_UPDATES });
            let Some(result) = self.call("getUpdates", &body, cancel)? else { return Ok(vec![]) };
            let updates = result.as_array().ok_or_else(|| ChannelError::new(K::Protocol, "getUpdates: result is not an array"))?.clone();
            if let Some(m) = updates.iter().filter_map(|u| u["update_id"].as_i64()).max() {
                self.offset.lock().unwrap().pending = Some(m + 1);
            }
            updates
        };
        // Only look up our identity when a message could mention or reply to us.
        let needs_me = updates.iter().any(|u| {
            let m = u.get("message").or_else(|| u.get("edited_message")).unwrap_or(&Value::Null);
            m["chat"]["type"].as_str().is_some_and(|t| t != "private") || m.get("reply_to_message").is_some()
        });
        let me = if needs_me { self.me() } else { self.me.lock().unwrap().clone() };
        Ok(updates.iter().filter_map(|u| inbound_of(&self.id, u, me.as_ref())).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let cancel = Cancel::new();
        let mut sent = Sent::default();
        let caption_fits = out.media.len() == 1 && out.text.encode_utf16().count() <= 1024;
        for (i, m) in out.media.iter().enumerate() {
            let caption = (caption_fits && i == 0).then_some(out.text.as_str()).filter(|t| !t.is_empty());
            let last = i + 1 == out.media.len() && (caption_fits || out.text.trim().is_empty());
            sent.ids.push(self.send_media(out, m, caption, i == 0, last)?);
        }
        if caption_fits && !out.media.is_empty() {
            return Ok(sent);
        }
        let pieces = crate::chunk::split(&out.text, MAX_MESSAGE, LenUnit::Utf16);
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let (text, mode) = self.render(out, &piece);
            let mut body = json!({ "chat_id": out.chat, "text": text, "link_preview_options": {"is_disabled": false} });
            if let Some(mode) = mode {
                body["parse_mode"] = json!(mode);
            }
            self.common(out, &mut body, i == 0 && out.media.is_empty());
            if i + 1 == n && !out.buttons.is_empty() {
                body["reply_markup"] = keyboard(&out.buttons);
            }
            let r = self.call("sendMessage", &body, &cancel)?.unwrap_or_default();
            sent.ids.extend(id_str(&r["message_id"]));
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let html = markup::convert(text, Markup::TelegramHtml);
        let body = json!({"chat_id": chat, "message_id": message_id.parse::<i64>().unwrap_or(0), "text": html, "parse_mode": "HTML"});
        match self.call("editMessageText", &body, &Cancel::new()) {
            Ok(_) => Ok(()),
            Err(e) if e.message.contains("message is not modified") => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.call("deleteMessage", &json!({"chat_id": chat, "message_id": message_id.parse::<i64>().unwrap_or(0)}), &Cancel::new()).map(|_| ())
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let mut body = json!({"chat_id": chat, "action": "typing"});
        if let Some(t) = thread.and_then(|t| t.parse::<i64>().ok()) {
            body["message_thread_id"] = json!(t);
        }
        self.call("sendChatAction", &body, &Cancel::new()).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let reaction = if remove { json!([]) } else { json!([{"type": "emoji", "emoji": emoji}]) };
        self.call("setMessageReaction", &json!({"chat_id": chat, "message_id": message_id.parse::<i64>().unwrap_or(0), "reaction": reaction}), &Cancel::new()).map(|_| ())
    }

    fn ack_callback(&self, cb: &Callback, text: Option<&str>) -> Result<(), ChannelError> {
        let mut body = json!({"callback_query_id": cb.id});
        if let Some(t) = text {
            body["text"] = json!(t);
        }
        self.call("answerCallbackQuery", &body, &Cancel::new()).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let id = m.id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "telegram attachment without file_id"))?;
        let f = self.call("getFile", &json!({"file_id": id}), &Cancel::new())?.unwrap_or_default();
        let path = f["file_path"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "getFile returned no file_path (file over 20 MB?)"))?;
        crate::http::get_bytes(&format!("{}/file/bot{}/{path}", self.base, self.token), &[], 20 * 1024 * 1024)
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    token: String,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Webhook mode: public HTTPS URL Telegram posts to …
    #[serde(default)]
    webhook_url: Option<String>,
    /// … the local address that URL reaches …
    #[serde(default)]
    webhook_listen: Option<String>,
    /// … and the secret every request must carry.
    #[serde(default)]
    webhook_secret: Option<String>,
    /// Register /new /stop /status /help with setMyCommands.
    #[serde(default)]
    commands: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<std::sync::Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let mut t = Telegram::new(ctx.name, &token, st.base_url.as_deref(), ctx.state("telegram.json"), st.poll_timeout_secs)?;
    t.register_commands = st.commands;
    if let Some(url) = &st.webhook_url {
        let listen = st.webhook_listen.as_deref().ok_or_else(|| format!("channel {}: webhook_url needs webhook_listen", ctx.name))?;
        let secret = ctx.opt_secret("webhook_secret", &st.webhook_secret)?.ok_or_else(|| format!("channel {}: webhook_url needs webhook_secret", ctx.name))?;
        t = t.with_webhook(listen, url, &secret)?;
    }
    Ok(std::sync::Arc::new(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn tg(url: &str, state: PathBuf) -> Telegram {
        let mut t = Telegram::new("tg", "123:SECRET", Some(url), state, 1).unwrap();
        t.retry_base = Duration::from_millis(5);
        t
    }

    fn ok(result: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"ok": true, "result": result}).to_string())
    }

    fn me() -> (u16, Vec<(String, String)>, String) {
        ok(json!({"id": 999, "is_bot": true, "username": "ArkBot"}))
    }

    fn update(id: i64, text: &str) -> Value {
        json!({"update_id": id, "message": {"message_id": id * 10, "date": 1700000000, "chat": {"id": 1, "type": "private"}, "from": {"id": 42, "username": "amy"}, "text": text}})
    }

    #[test]
    fn polls_parses_media_and_persists_offset_across_restart() {
        let srv = FakeServer::start(|req, _| {
            let off = req.json()["offset"].as_i64().unwrap();
            match off {
                0 => ok(json!([update(5, "hi"), {"update_id": 6, "message": {"message_id": 1, "chat": {"id": 1, "type": "private"}, "from": {"id": 3}, "sticker": {"file_id": "S1"}}}, {"update_id": 7, "edited_message": {}}, {"update_id": 8, "message": {"message_id": 2, "chat": {"id": 9, "type": "private"}, "from": {"id": 3, "first_name": "Bo"}, "caption": "photo cap", "photo": [{"file_id": "small", "width": 90, "height": 90}, {"file_id": "big", "width": 800, "height": 600}]}}])),
                _ => ok(json!([])),
            }
        });
        let dir = temp_dir("tg");
        let state = dir.join("tg.json");
        let t = tg(&srv.url, state.clone());
        let got = t.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 3, "empty edit skipped; sticker and captioned photo kept");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].sender_name.as_str(), got[0].message_id.as_str(), got[0].chat_type), ("1", "42", "amy", "50", ChatType::Direct));
        assert_eq!((got[1].media[0].kind, got[1].media[0].id.as_deref()), (MediaKind::Sticker, Some("S1")));
        assert_eq!((got[2].text.as_str(), got[2].media[0].id.as_deref()), ("photo cap", Some("big")), "largest photo");
        assert!(!state.exists(), "offset is committed only on the next poll (at-least-once)");
        let t2 = tg(&srv.url, state.clone());
        assert_eq!(t2.poll(&Cancel::new()).unwrap().len(), 3);
        assert!(t2.poll(&Cancel::new()).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&state).unwrap(), r#"{"offset":9}"#);
        let t3 = tg(&srv.url, state);
        assert!(t3.poll(&Cancel::new()).unwrap().is_empty());
        let offs: Vec<i64> = srv.requests().iter().map(|r| r.json()["offset"].as_i64().unwrap()).collect();
        assert_eq!(offs, [0, 0, 9, 9], "private chats never need getMe");
        assert!(srv.requests()[0].path.ends_with("/bot123:SECRET/getUpdates"));
        assert_eq!(srv.requests()[0].json()["allowed_updates"], json!(ALLOWED_UPDATES));
    }

    #[test]
    fn groups_mentions_replies_topics_edits_and_callbacks() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/getMe") {
                return me();
            }
            ok(json!([
                {"update_id": 1, "message": {"message_id": 10, "chat": {"id": -5, "type": "supergroup", "title": "Team"}, "from": {"id": 42}, "text": "hey @arkbot do it", "entities": [{"type": "mention", "offset": 4, "length": 7}]}},
                {"update_id": 2, "message": {"message_id": 11, "chat": {"id": -5, "type": "supergroup"}, "from": {"id": 42}, "text": "😀 @other", "entities": [{"type": "mention", "offset": 3, "length": 6}]}},
                {"update_id": 3, "message": {"message_id": 12, "chat": {"id": -5, "type": "supergroup"}, "from": {"id": 42}, "text": "yes", "reply_to_message": {"message_id": 9, "from": {"id": 999}, "text": "shall I?"}}},
                {"update_id": 4, "message": {"message_id": 13, "chat": {"id": -5, "type": "supergroup", "is_forum": true}, "from": {"id": 42}, "text": "in topic", "is_topic_message": true, "message_thread_id": 77, "reply_to_message": {"message_id": 77, "forum_topic_created": {"name": "t"}, "from": {"id": 1}}}},
                {"update_id": 5, "edited_message": {"message_id": 10, "edit_date": 1700000100, "chat": {"id": -5, "type": "supergroup"}, "from": {"id": 42}, "text": "edited"}},
                {"update_id": 6, "callback_query": {"id": "CB1", "from": {"id": 42, "username": "amy"}, "data": "appr:1:once", "message": {"message_id": 20, "chat": {"id": -5, "type": "supergroup"}}}},
                {"update_id": 7, "message": {"message_id": 14, "chat": {"id": -5, "type": "supergroup"}, "from": {"id": 7, "is_bot": true}, "text": "/status@ArkBot", "entities": [{"type": "bot_command", "offset": 0, "length": 14}]}}
            ]))
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let g = t.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 7);
        assert!(g[0].mentioned && g[0].chat_type == ChatType::Group && g[0].chat_name == "Team");
        assert!(!g[1].mentioned, "UTF-16 offsets: @other is not us");
        assert!(!g[2].mentioned && g[2].reply.as_ref().unwrap().is_own && g[2].addressed(), "reply to the bot");
        assert_eq!(g[2].reply.as_ref().unwrap().text, "shall I?");
        assert_eq!(g[3].thread.as_deref(), Some("77"));
        assert!(g[3].reply.is_none(), "topic root is not a reply");
        assert!(g[4].edited && g[4].message_id == "10:e1700000100");
        assert_eq!(g[5].callback.as_ref().unwrap().data, "appr:1:once");
        assert!(g[6].is_bot && g[6].mentioned);
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("/getMe")).count(), 1, "identity cached");
        t.poll(&Cancel::new()).unwrap();
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("/getMe")).count(), 1);
    }

    #[test]
    fn send_formats_html_threads_buttons_media_and_actions() {
        let srv = FakeServer::start(|req, n| {
            if req.path.ends_with("/getFile") {
                return ok(json!({"file_path": "photos/a.jpg"}));
            }
            if req.path.contains("/file/bot") {
                return (200, vec![], "JPEGDATA".into());
            }
            ok(json!({"message_id": 100 + n}))
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let out = Outbound {
            format: TextFormat::Markdown,
            thread: Some("77".into()),
            silent: true,
            reply_to: Some("5".into()),
            buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("-5", "**粗體** <tag>")
        };
        let s = t.send(&out).unwrap();
        assert_eq!(s.ids, vec!["100"]);
        let r = srv.requests()[0].json();
        assert_eq!((r["text"].as_str(), r["parse_mode"].as_str()), (Some("<b>粗體</b> &lt;tag&gt;"), Some("HTML")));
        assert_eq!((r["message_thread_id"].as_i64(), r["disable_notification"].as_bool(), r["reply_parameters"]["message_id"].as_i64()), (Some(77), Some(true), Some(5)));
        assert_eq!(r["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "appr:x:once");
        assert_eq!(r["reply_markup"]["inline_keyboard"][0][1]["url"], "https://e.com");
        // Media by URL with the text as caption; local file as multipart upload.
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        t.send(&Outbound { media: vec![img], ..Outbound::text("1", "cap") }).unwrap();
        let r = srv.requests()[1].clone();
        assert!(r.path.ends_with("/sendPhoto"));
        assert_eq!((r.json()["photo"].as_str(), r.json()["caption"].as_str()), (Some("https://e.com/a.png"), Some("cap")));
        let f = temp_dir("tg").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let doc = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() };
        t.send(&Outbound { media: vec![doc], ..Outbound::text("1", "") }).unwrap();
        let r = srv.requests()[2].clone();
        assert!(r.path.ends_with("/sendDocument") && r.header("content-type").unwrap().starts_with("multipart/form-data"));
        assert!(r.body.contains("filename=\"report.pdf\"") && r.body.contains("%PDF-1") && r.body.contains("name=\"chat_id\""), "{}", r.body);
        // Actions.
        t.edit("1", "100", "new *text*").unwrap();
        t.delete("1", "100").unwrap();
        t.typing("1", Some("77")).unwrap();
        t.react("1", "100", "👍", false).unwrap();
        t.ack_callback(&Callback { id: "CB".into(), data: String::new() }, Some("ok")).unwrap();
        let paths: Vec<String> = srv.requests().iter().skip(3).map(|r| r.path.rsplit('/').next().unwrap().to_string()).collect();
        assert_eq!(paths, ["editMessageText", "deleteMessage", "sendChatAction", "setMessageReaction", "answerCallbackQuery"]);
        assert_eq!(srv.requests()[3].json()["text"], "new <i>text</i>");
        assert_eq!(srv.requests()[5].json()["message_thread_id"], 77);
        assert_eq!(srv.requests()[6].json()["reaction"][0]["emoji"], "👍");
        let bytes = t.fetch_media(&Media { id: Some("F".into()), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"JPEGDATA");
        assert!(srv.requests().last().unwrap().path.ends_with("/file/bot123:SECRET/photos/a.jpg"));
    }

    #[test]
    fn rate_limit_honours_retry_after_then_succeeds() {
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![], json!({"ok": false, "error_code": 429, "description": "Too Many Requests", "parameters": {"retry_after": 1}}).to_string()),
            _ => ok(json!({"message_id": 1})),
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let start = std::time::Instant::now();
        t.send(&Outbound::text("1", "x")).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(950), "waited retry_after");
        assert_eq!(srv.requests().len(), 2);
    }

    #[test]
    fn long_retry_after_surfaces_instead_of_blocking() {
        let srv = FakeServer::start(|_, _| (429, vec![], json!({"ok": false, "parameters": {"retry_after": 3600}}).to_string()));
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let e = t.send(&Outbound::text("1", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        assert!(e.is_retryable());
    }

    #[test]
    fn auth_conflict_blocked_and_bad_request_are_not_retried() {
        for (status, desc, kind) in [(401, "nope", K::Auth), (404, "nope", K::Auth), (409, "nope", K::Fatal), (400, "nope", K::Protocol), (403, "Forbidden: bot was blocked by the user", K::NotFound), (400, "Bad Request: chat not found", K::NotFound)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"ok": false, "description": desc}).to_string()));
            let t = tg(&srv.url, temp_dir("tg").join("s"));
            let e = t.poll(&Cancel::new()).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {desc}");
            assert!(!e.message.contains("SECRET"), "token never in errors: {}", e.message);
            assert_eq!(srv.requests().len(), 1, "{status} not retried");
        }
    }

    #[test]
    fn server_errors_and_garbage_retry_with_backoff_then_give_up() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let srv = FakeServer::start(move |_, _| {
            n2.fetch_add(1, Ordering::SeqCst);
            (502, vec![], "<html>bad gateway</html>".into())
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert_eq!(n.load(Ordering::SeqCst), 5, "1 + max_retries");
        let t = tg("http://127.0.0.1:1", temp_dir("tg").join("s"));
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert!(!e.message.contains("SECRET"), "{}", e.message);
    }

    #[test]
    fn cancel_interrupts_a_blocked_long_poll() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let t = tg(&url, temp_dir("tg").join("s"));
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = std::time::Instant::now();
        assert!(t.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn send_chunks_long_text_in_utf16_and_replies_once() {
        let srv = FakeServer::start(|_, n| ok(json!({"message_id": n})));
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let text = "😀".repeat(3000); // 6000 UTF-16 units, no break points
        let s = t.send(&Outbound { reply_to: Some("77".into()), ..Outbound::text("-100", &text) }).unwrap();
        assert_eq!(s.ids.len(), 2);
        let reqs = srv.requests();
        let parts: Vec<String> = reqs.iter().map(|r| r.json()["text"].as_str().unwrap().to_string()).collect();
        assert!(parts.iter().all(|p| p.encode_utf16().count() <= MAX_MESSAGE));
        assert_eq!(parts.concat(), text);
        assert_eq!(reqs[0].json()["reply_parameters"]["message_id"], 77);
        assert!(reqs[1].json().get("reply_parameters").is_none());
        t.send(&Outbound::text("1", "  \n")).unwrap();
        assert_eq!(srv.requests().len(), 2, "empty text sends nothing");
        assert!(Telegram::new("t", " ", None, temp_dir("tg").join("s"), 1).is_err());
    }

    #[test]
    fn webhook_mode_checks_secret_and_delivers_updates() {
        let srv = FakeServer::start(|_, _| ok(json!(true)));
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        assert!(tg(&srv.url, temp_dir("tg").join("s")).with_webhook(&listen, "https://bot.example.com/tg/hook", "short").is_err(), "weak secret refused");
        let t = tg(&srv.url, temp_dir("tg").join("s")).with_webhook(&listen, "https://bot.example.com/tg/hook", "s3cret-s3cret-s3cret").unwrap();
        let set = srv.requests()[0].json();
        assert_eq!((set["url"].as_str(), set["secret_token"].as_str()), (Some("https://bot.example.com/tg/hook"), Some("s3cret-s3cret-s3cret")));
        let post = |secret: &str, path: &str| {
            let a = agent(Duration::from_secs(5));
            a.post(&format!("http://{listen}{path}")).header("x-telegram-bot-api-secret-token", secret).send(update(3, "via hook").to_string().as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
        };
        assert_eq!(post("wrong", "/tg/hook"), 401);
        assert_eq!(post("s3cret-s3cret-s3cret", "/other"), 404);
        assert_eq!(post("s3cret-s3cret-s3cret", "/tg/hook"), 200);
        let got = t.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "via hook");
        assert_eq!(srv.requests().len(), 1, "no getUpdates in webhook mode");
    }
}
