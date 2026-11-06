//! LINE Messaging API (ported from OpenClaw `extensions/line` and Hermes
//! `plugins/platforms/line`, both MIT).
//!
//! Receive: webhook (`X-Line-Signature` = base64 HMAC-SHA256 of the raw body
//! with the channel secret, compared in constant time). Message events (text,
//! image, video, audio, file, sticker, location), postbacks (→ `Callback`),
//! user / group / room sources, `mention.mentionees[].isSelf` (and `@all`)
//! mentions, `quotedMessageId` replies. Lifecycle events (follow, join, leave…)
//! are acknowledged and dropped.
//! Send: the event's reply token first (free, single use, ~60 s; we keep it
//! 50 s), push API for the rest or when the token is gone/rejected; ≤5 message
//! objects per call; quote tokens for replies; template buttons (≤4 buttons and
//! short text) or quick-reply chips (≤13) for buttons; images/video/audio by
//! public HTTPS URL — local files are served by our own listener under
//! `/line/media/<token>/<file>` (needs `public_url`). Typing = loading animation
//! (DM only). Inbound media is downloaded from `api-data.line.me`.

use crate::http::{classify, Http, Payload};
use crate::{
    markup, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat,
};
use seagent_core::Cancel;
use seagent_net::httpd::{Opts, Response, Server};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.line.me";
pub const DEFAULT_DATA_API: &str = "https://api-data.line.me";
/// Characters per text bubble.
pub const MAX_MESSAGE: usize = 5000;
const MAX_PER_CALL: usize = 5;
/// LINE says ~60 s; stay below it.
const REPLY_TOKEN_TTL: Duration = Duration::from_secs(50);
const MEDIA_TTL: Duration = Duration::from_secs(1800);
pub const MEDIA_PREFIX: &str = "/line/media/";
/// 1×1 transparent PNG used as the required video preview when none is given.
const FALLBACK_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0, 1, 0, 0, 0, 5, 0, 1, 0x0d, 0x0a, 0x2d, 0xb4, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

type MediaMap = Arc<Mutex<HashMap<String, (PathBuf, Instant)>>>;

pub struct Line {
    id: String,
    token: String,
    api: String,
    data_api: String,
    public_url: Option<String>,
    poll_timeout: u64,
    http: Http,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    server: Server,
    rx: Mutex<Receiver<(Instant, Value)>>,
    /// chat → (reply token, expiry).
    reply_tokens: Mutex<HashMap<String, (String, Instant)>>,
    /// "chat|message id" → quote token (bounded).
    quote_tokens: Mutex<VecDeque<(String, String)>>,
    /// Ids of messages we sent (reply-to-bot detection).
    own: Mutex<VecDeque<String>>,
    /// Our bot user id from /v2/bot/info (self-echo filter), fetched once.
    bot_id: Mutex<Option<Option<String>>>,
    media: MediaMap,
}

/// base64(HMAC-SHA256(secret, body)), constant-time.
pub fn verify_signature(secret: &str, body: &[u8], sig: Option<&str>) -> bool {
    let Some(sig) = sig.map(str::trim).filter(|s| !s.is_empty()) else { return false };
    if secret.is_empty() {
        return false;
    }
    let want = seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), body));
    seagent_net::crypto::ct_eq(want.as_bytes(), sig.as_bytes())
}

/// Content type from a file name's extension (shared by the ported channels).
pub(crate) fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "m4a" => "audio/mp4",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "aac" => "audio/aac",
        "caf" => "audio/x-caf",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "zip" => "application/zip",
        "vcf" => "text/vcard",
        _ => "application/octet-stream",
    }
}

pub(crate) fn file_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
}

fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// LINE's `{message, details}` error body → classified error.
fn line_err(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let msg = v["message"].as_str().unwrap_or("").to_string();
    let details = v["details"].as_array().map(|d| d.iter().filter_map(|x| x["message"].as_str()).collect::<Vec<_>>().join("; ")).unwrap_or_default();
    let text = format!("{what}: HTTP {status} {msg} {details}").trim().to_string();
    match status {
        400 if msg.contains("Invalid reply token") => ChannelError::new(K::Protocol, text),
        // Unknown / unfollowed / blocked recipient.
        400 if msg.contains("'to'") || details.contains("'to'") || msg.contains("Failed to send messages") => ChannelError::new(K::NotFound, text),
        429 if msg.contains("monthly limit") => ChannelError::new(K::Fatal, text),
        429 => ChannelError::new(K::RateLimited { retry_after }, text),
        _ => {
            let mut e = classify(status, retry_after, what, body);
            if !msg.is_empty() {
                e.message = text;
            }
            e
        }
    }
}

fn source_chat(src: &Value) -> Option<(String, ChatType)> {
    match src["type"].as_str()? {
        "group" => Some((src["groupId"].as_str()?.to_string(), ChatType::Group)),
        "room" => Some((src["roomId"].as_str()?.to_string(), ChatType::Group)),
        "user" => Some((src["userId"].as_str()?.to_string(), ChatType::Direct)),
        _ => None,
    }
}

/// One webhook event → Inbound. `own` = ids of messages the bot sent.
fn inbound_of(channel: &str, ev: &Value, bot_id: Option<&str>, own: &VecDeque<String>) -> Option<Inbound> {
    let src = &ev["source"];
    let (chat, chat_type) = source_chat(src)?;
    let sender = src["userId"].as_str().unwrap_or("").to_string();
    if bot_id.is_some_and(|b| !b.is_empty() && b == sender) {
        return None;
    }
    let ts = ev["timestamp"].as_i64().unwrap_or(0) / 1000;
    let base = Inbound { channel: channel.to_string(), chat, chat_type, sender: sender.clone(), sender_name: sender, ts, ..Default::default() };
    match ev["type"].as_str()? {
        "postback" => {
            let eid = ev["webhookEventId"].as_str().unwrap_or("").to_string();
            let data = ev["postback"]["data"].as_str().unwrap_or("").to_string();
            Some(Inbound { message_id: format!("pb:{eid}"), callback: Some(Callback { id: eid, data }), ..base })
        }
        "message" => {
            let m = &ev["message"];
            let id = m["id"].as_str()?.to_string();
            let mut media = Vec::new();
            let mut mentioned = false;
            let text = match m["type"].as_str()? {
                "text" => {
                    mentioned = m["mention"]["mentionees"].as_array().is_some_and(|ms| ms.iter().any(|x| x["isSelf"] == true || x["type"] == "all"));
                    m["text"].as_str().unwrap_or("").to_string()
                }
                k @ ("image" | "video" | "audio" | "file") => {
                    let kind = match k {
                        "image" => MediaKind::Image,
                        "video" => MediaKind::Video,
                        "audio" => MediaKind::Audio,
                        _ => MediaKind::Document,
                    };
                    let name = m["fileName"].as_str().map(str::to_string).unwrap_or_else(|| format!("{id}.{}", match k { "image" => "jpg", "video" => "mp4", "audio" => "m4a", _ => "bin" }));
                    // External content (sent via the LINE API by another bot) is fetched from its own URL.
                    let url = m["contentProvider"]["type"].as_str().filter(|t| *t == "external").and_then(|_| m["contentProvider"]["originalContentUrl"].as_str()).map(str::to_string);
                    media.push(Media { kind, mime: guess_mime(&name).to_string(), name, size: m["fileSize"].as_u64().unwrap_or(0), id: Some(id.clone()), url, ..Default::default() });
                    String::new()
                }
                "sticker" => {
                    let kw: Vec<&str> = m["keywords"].as_array().map(|a| a.iter().filter_map(Value::as_str).take(5).collect()).unwrap_or_default();
                    if kw.is_empty() { "[sticker]".to_string() } else { format!("[sticker: {}]", kw.join(", ")) }
                }
                "location" => {
                    let parts: Vec<String> = [m["title"].as_str(), m["address"].as_str()].into_iter().flatten().filter(|s| !s.is_empty()).map(str::to_string).collect();
                    format!("[location: {} ({}, {})]", parts.join(" "), m["latitude"], m["longitude"]).replace(":  (", ": (")
                }
                other => format!("[unsupported LINE message: {other}]"),
            };
            let reply = m["quotedMessageId"].as_str().map(|q| ReplyRef { id: q.to_string(), is_own: own.iter().any(|o| o == q), ..Default::default() });
            Some(Inbound { message_id: id, text, media, mentioned, reply, ..base })
        }
        // follow / unfollow / join / leave / memberJoined / unsend …: nothing to answer.
        _ => None,
    }
}

fn action_of(b: &crate::Button) -> Value {
    match &b.url {
        Some(u) => json!({"type": "uri", "label": truncate_chars(&b.label, 20), "uri": u}),
        None => json!({"type": "postback", "label": truncate_chars(&b.label, 20), "data": truncate_chars(&b.data, 300), "displayText": truncate_chars(&b.label, 300)}),
    }
}

/// Template buttons when they fit (≤4 buttons, text ≤160), else quick-reply chips on the message.
fn attach_buttons(msg: Value, rows: &[Vec<crate::Button>]) -> Value {
    let all: Vec<&crate::Button> = rows.iter().flatten().collect();
    if all.is_empty() {
        return msg;
    }
    let text = msg["text"].as_str().unwrap_or("").to_string();
    if all.len() <= 4 && !text.is_empty() && text.chars().count() <= 160 && msg["type"] == "text" {
        return json!({"type": "template", "altText": truncate_chars(&text, 400), "template": {"type": "buttons", "text": text, "actions": all.iter().map(|b| action_of(b)).collect::<Vec<_>>()}});
    }
    let mut msg = msg;
    msg["quickReply"] = json!({"items": all.iter().take(13).map(|b| json!({"type": "action", "action": action_of(b)})).collect::<Vec<_>>()});
    msg
}

impl Line {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api)
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    /// Serve a local file at a public URL for LINE to fetch.
    fn serve(&self, path: &str, name: &str) -> Result<String, ChannelError> {
        let base = self.public_url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "LINE only accepts public HTTPS media URLs: set `public_url` to send local files"))?;
        let p = std::fs::canonicalize(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        if !p.is_file() {
            return Err(ChannelError::new(K::Fatal, format!("attachment {path} is not a file")));
        }
        let tok = seagent_net::crypto::random_token(24);
        let mut m = self.media.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, (_, exp)| *exp > now);
        m.insert(tok.clone(), (p, now + MEDIA_TTL));
        Ok(format!("{base}{MEDIA_PREFIX}{tok}/{}", seagent_net::urlencode(name)))
    }

    fn preview_url(&self) -> Result<String, ChannelError> {
        let p = std::env::temp_dir().join("seagent-line-preview.png");
        if !p.exists() {
            crate::write_atomic(&p, FALLBACK_PNG).map_err(|e| ChannelError::new(K::Fatal, format!("preview image: {e}")))?;
        }
        self.serve(&p.display().to_string(), "preview.png")
    }

    /// POST with retries (5xx, short 429). Push requests carry an `X-Line-Retry-Key`
    /// so a retried push is never delivered twice (409 = already accepted).
    fn post(&self, path: &str, body: &Value, retry_key: Option<&str>) -> Result<Value, ChannelError> {
        let url = self.url(path);
        let mut attempt = 0;
        loop {
            let extra: Vec<(&str, &str)> = retry_key.map(|k| vec![("x-line-retry-key", k)]).unwrap_or_default();
            let err = match self.http.call("POST", &url, &extra, Payload::Json(body)) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null)),
                Ok(r) if r.status == 409 && retry_key.is_some() && attempt > 0 => return Ok(Value::Null),
                Ok(r) => line_err(path, r.status, r.retry_after, &r.body),
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            std::thread::sleep(wait);
            attempt += 1;
        }
    }

    fn remember_sent(&self, chat: &str, r: &Value) -> Vec<String> {
        let mut ids = Vec::new();
        for m in r["sentMessages"].as_array().into_iter().flatten() {
            if let Some(id) = m["id"].as_str() {
                ids.push(id.to_string());
                let mut own = self.own.lock().unwrap();
                own.push_back(id.to_string());
                while own.len() > 500 {
                    own.pop_front();
                }
                if let Some(q) = m["quoteToken"].as_str() {
                    self.put_quote(chat, id, q);
                }
            }
        }
        ids
    }

    fn put_quote(&self, chat: &str, id: &str, q: &str) {
        let mut qt = self.quote_tokens.lock().unwrap();
        let key = format!("{chat}|{id}");
        qt.retain(|(k, _)| *k != key);
        qt.push_back((key, q.to_string()));
        while qt.len() > 1000 {
            qt.pop_front();
        }
    }

    fn quote_token(&self, chat: &str, id: &str) -> Option<String> {
        let key = format!("{chat}|{id}");
        self.quote_tokens.lock().unwrap().iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
    }

    fn take_reply_token(&self, chat: &str) -> Option<String> {
        let (tok, exp) = self.reply_tokens.lock().unwrap().remove(chat)?;
        (Instant::now() < exp).then_some(tok)
    }

    fn bot_id(&self) -> Option<String> {
        let mut g = self.bot_id.lock().unwrap();
        if g.is_none() {
            let v = self.http.json("GET", &self.url("/v2/bot/info"), Payload::None).ok();
            *g = Some(v.and_then(|v| v["userId"].as_str().map(str::to_string)));
        }
        g.clone().flatten()
    }

    fn media_message(&self, m: &Media) -> Result<Value, ChannelError> {
        let name = if m.name.is_empty() { m.path.as_deref().map(file_name).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
        let url = match (&m.path, &m.url) {
            (Some(p), _) => self.serve(p, &name)?,
            (None, Some(u)) => u.clone(),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        Ok(match m.kind {
            MediaKind::Image | MediaKind::Animation | MediaKind::Sticker => json!({"type": "image", "originalContentUrl": url, "previewImageUrl": url}),
            MediaKind::Video => json!({"type": "video", "originalContentUrl": url, "previewImageUrl": self.preview_url()?}),
            MediaKind::Audio | MediaKind::Voice => json!({"type": "audio", "originalContentUrl": url, "duration": 1000}),
            // LINE bots cannot send files: share a link instead.
            MediaKind::Document => json!({"type": "text", "text": format!("{name}: {url}")}),
        })
    }
}

impl Channel for Line {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 0,
            edit: false,
            delete: false,
            typing: true,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        {
            let rx = self.rx.lock().unwrap();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
        }
        if got.is_empty() {
            return Ok(vec![]);
        }
        let bot = self.bot_id();
        let own = self.own.lock().unwrap().clone();
        let mut out = Vec::new();
        for (at, ev) in got {
            if let (Some(tok), Some((chat, _))) = (ev["replyToken"].as_str(), source_chat(&ev["source"])) {
                self.reply_tokens.lock().unwrap().insert(chat.clone(), (tok.to_string(), at + REPLY_TOKEN_TTL));
                if let (Some(id), Some(q)) = (ev["message"]["id"].as_str(), ev["message"]["quoteToken"].as_str()) {
                    self.put_quote(&chat, id, q);
                }
            }
            out.extend(inbound_of(&self.id, &ev, bot.as_deref(), &own));
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut msgs: Vec<Value> = Vec::new();
        for m in &out.media {
            msgs.push(self.media_message(m)?);
            if let Some(c) = m.caption.as_deref().filter(|c| !c.trim().is_empty()) {
                msgs.push(json!({"type": "text", "text": truncate_chars(c, MAX_MESSAGE)}));
            }
        }
        let text = match out.format {
            TextFormat::Markdown => markup::convert(&out.text, Markup::Plain),
            TextFormat::Plain => out.text.clone(),
        };
        let mut texts: Vec<Value> = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars).into_iter().map(|t| json!({"type": "text", "text": t})).collect();
        if texts.is_empty() && !out.buttons.is_empty() {
            let labels: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}", i + 1, b.label)).collect();
            texts.push(json!({"type": "text", "text": labels.join("\n")}));
        }
        if let Some(q) = out.reply_to.as_deref().and_then(|r| self.quote_token(&out.chat, r)) {
            if let Some(t) = texts.first_mut() {
                t["quoteToken"] = json!(q);
            }
        }
        msgs.extend(texts);
        if let Some(last) = msgs.pop() {
            msgs.push(attach_buttons(last, &out.buttons));
        }
        if msgs.is_empty() {
            return Ok(Sent::default());
        }
        let mut sent = Sent::default();
        let mut batches = msgs.chunks(MAX_PER_CALL).map(<[Value]>::to_vec).peekable();
        if let Some(tok) = self.take_reply_token(&out.chat) {
            let first = batches.peek().cloned().unwrap_or_default();
            let mut body = json!({"replyToken": tok, "messages": first});
            if out.silent {
                body["notificationDisabled"] = json!(true);
            }
            match self.post("/v2/bot/message/reply", &body, None) {
                Ok(r) => {
                    sent.ids.extend(self.remember_sent(&out.chat, &r));
                    batches.next();
                }
                Err(e) if e.kind == K::Auth => return Err(e),
                // Expired / used token: push instead.
                Err(_) => {}
            }
        }
        for b in batches {
            let mut body = json!({"to": out.chat, "messages": b});
            if out.silent {
                body["notificationDisabled"] = json!(true);
            }
            let key = uuid4();
            let r = self.post("/v2/bot/message/push", &body, Some(&key))?;
            sent.ids.extend(self.remember_sent(&out.chat, &r));
        }
        Ok(sent)
    }

    /// Loading animation; LINE accepts it for user chats only (groups/rooms are a no-op).
    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        if !chat.starts_with('U') {
            return Ok(());
        }
        self.post("/v2/bot/chat/loading/start", &json!({"chatId": chat, "loadingSeconds": 20}), None).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        if let Some(u) = &m.url {
            return crate::http::get_bytes(u, &[], 200 * 1024 * 1024);
        }
        let id = m.id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "LINE attachment without message id"))?;
        // Audio/video may still be transcoding; wait (briefly) until it is ready.
        if matches!(m.kind, MediaKind::Video | MediaKind::Audio) {
            for _ in 0..20 {
                let st = self.http.json("GET", &format!("{}/v2/bot/message/{id}/content/transcoding", self.data_api), Payload::None)?;
                match st["status"].as_str() {
                    Some("processing") => std::thread::sleep(Duration::from_millis(500)),
                    Some("failed") => return Err(ChannelError::new(K::Protocol, "LINE could not prepare this media")),
                    _ => break,
                }
            }
        }
        let auth = format!("Bearer {}", self.token);
        crate::http::get_bytes_trusted(&format!("{}/v2/bot/message/{id}/content", self.data_api), &[("authorization", &auth)], 200 * 1024 * 1024, &self.data_api)
    }
}

pub(crate) fn uuid4() -> String {
    let mut b = seagent_net::crypto::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = seagent_net::crypto::hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    "/line/webhook".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Channel access token.
    #[serde(alias = "token")]
    pub channel_access_token: String,
    pub channel_secret: String,
    /// Local address of the webhook listener (also serves outbound media).
    pub listen: String,
    #[serde(default = "d_path")]
    pub webhook_path: String,
    /// Public HTTPS base that reaches `listen` (needed to send local files).
    #[serde(default)]
    pub public_url: Option<String>,
    /// Register this endpoint with LINE at start (PUT /v2/bot/channel/webhook/endpoint).
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub data_api_base: Option<String>,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl Line {
    /// `token`/`secret` already resolved.
    pub fn open(id: &str, st: &Settings, token: &str, secret: &str) -> Result<Line, String> {
        if token.trim().is_empty() || secret.trim().is_empty() {
            return Err(format!("channel {id}: LINE needs channel_access_token and channel_secret"));
        }
        let (tx, rx) = channel::<(Instant, Value)>();
        let tx = Mutex::new(tx);
        let media: MediaMap = Arc::default();
        let (path, secret_s, media2) = (st.webhook_path.clone(), secret.to_string(), media.clone());
        let handler: seagent_net::httpd::Handler = Arc::new(move |r: seagent_net::httpd::Request| {
            if r.method == "GET" && (r.path == path || r.path == format!("{path}/health")) {
                return Response::new(200, "application/json", r#"{"status":"ok","platform":"line"}"#);
            }
            if r.method == "GET" {
                if let Some(rest) = r.path.strip_prefix(MEDIA_PREFIX) {
                    let tok = rest.split('/').next().unwrap_or("");
                    let entry = media2.lock().unwrap().get(tok).cloned();
                    return match entry {
                        None => Response::text(404, "not found"),
                        Some((_, exp)) if exp < Instant::now() => Response::text(410, "gone"),
                        Some((p, _)) => match std::fs::read(&p) {
                            Ok(b) => Response::new(200, guess_mime(&p.display().to_string()), b),
                            Err(_) => Response::text(404, "not found"),
                        },
                    };
                }
            }
            if r.method != "POST" || r.path != path {
                return Response::text(404, "not found");
            }
            if !verify_signature(&secret_s, &r.body, r.header("x-line-signature")) {
                return Response::text(401, "invalid signature");
            }
            let Ok(v) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
            let now = Instant::now();
            let tx = tx.lock().unwrap();
            for ev in v["events"].as_array().into_iter().flatten() {
                let _ = tx.send((now, ev.clone()));
            }
            Response::text(200, "ok")
        });
        let server = Server::bind(&st.listen, Opts { max_body: 1024 * 1024, ..Opts::default() }, handler).map_err(|e| format!("channel {id}: cannot listen on {}: {e}", st.listen))?;
        let line = Line {
            id: id.to_string(),
            token: token.trim().to_string(),
            api: st.api_base.as_deref().unwrap_or(DEFAULT_API).trim_end_matches('/').to_string(),
            data_api: st.data_api_base.as_deref().unwrap_or(DEFAULT_DATA_API).trim_end_matches('/').to_string(),
            public_url: st.public_url.as_deref().map(|u| u.trim_end_matches('/').to_string()),
            poll_timeout: st.poll_timeout_secs,
            http: Http::new(Duration::from_secs(30)).bearer(token.trim()),
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(30),
            server,
            rx: Mutex::new(rx),
            reply_tokens: Mutex::default(),
            quote_tokens: Mutex::default(),
            own: Mutex::default(),
            bot_id: Mutex::new(None),
            media,
        };
        if let Some(u) = &st.webhook_url {
            let r = line.http.call("PUT", &line.url("/v2/bot/channel/webhook/endpoint"), &[], Payload::Json(&json!({"endpoint": u}))).map_err(|e| format!("channel {id}: {}", e.message))?;
            if !(200..300).contains(&r.status) {
                return Err(format!("channel {id}: setting the LINE webhook endpoint failed: {}", line_err("webhook endpoint", r.status, None, &r.body).message));
            }
        }
        Ok(line)
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("channel_access_token", &st.channel_access_token)?;
    let secret = ctx.secret("channel_secret", &st.channel_secret)?;
    Ok(Arc::new(Line::open(ctx.name, &st, &token, &secret)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    const SECRET: &str = "chsecret";

    fn line(api: &str, public: Option<&str>) -> Line {
        let st: Settings = serde_json::from_value(json!({"channel_access_token": "TOKEN", "channel_secret": SECRET, "listen": "127.0.0.1:0", "api_base": api, "data_api_base": api, "public_url": public, "poll_timeout_secs": 1})).unwrap();
        let mut l = Line::open("line", &st, "TOKEN", SECRET).unwrap();
        l.retry_base = Duration::from_millis(5);
        l
    }

    fn sign(body: &str) -> String {
        seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(SECRET.as_bytes(), body.as_bytes()))
    }

    fn post(l: &Line, sig: Option<&str>, body: &str) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{}/line/webhook", l.local_addr()));
        if let Some(s) = sig {
            r = r.header("x-line-signature", s);
        }
        r.send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn deliver(l: &Line, events: Value) {
        let body = json!({"destination": "Ubot", "events": events}).to_string();
        assert_eq!(post(l, Some(&sign(&body)), &body), 200);
    }

    fn ok_api() -> FakeServer {
        FakeServer::start(|req, n| {
            if req.path == "/v2/bot/info" {
                return (200, vec![], json!({"userId": "Ubot"}).to_string());
            }
            (200, vec![], json!({"sentMessages": [{"id": format!("S{n}"), "quoteToken": format!("q{n}")}]}).to_string())
        })
    }

    #[test]
    fn signature_good_bad_missing_and_health() {
        let srv = ok_api();
        let l = line(&srv.url, None);
        let body = json!({"events": []}).to_string();
        assert_eq!(post(&l, None, &body), 401, "missing");
        assert_eq!(post(&l, Some("AAAA"), &body), 401, "bad");
        assert_eq!(post(&l, Some(&sign("{\"events\":[1]}")), &body), 401, "signature of another body");
        assert_eq!(post(&l, Some(&sign(&body)), &body), 200, "good");
        assert!(verify_signature(SECRET, b"x", Some(&sign("x"))) && !verify_signature("", b"x", Some(&sign("x"))));
        let a = crate::http::agent(Duration::from_secs(5));
        assert_eq!(a.get(&format!("http://{}/line/webhook/health", l.local_addr())).call().unwrap().status().as_u16(), 200);
        assert!(l.poll(&Cancel::new()).unwrap().is_empty());
    }

    #[test]
    fn parses_every_event_kind() {
        let srv = ok_api();
        let l = line(&srv.url, None);
        let user = json!({"type": "user", "userId": "Uamy"});
        let group = json!({"type": "group", "groupId": "Cteam", "userId": "Uamy"});
        deliver(&l, json!([
            {"type": "message", "replyToken": "r1", "timestamp": 1700000000000i64, "source": user, "webhookEventId": "e1", "message": {"id": "m1", "type": "text", "text": "hi", "quoteToken": "qm1"}},
            {"type": "message", "replyToken": "r2", "source": group, "message": {"id": "m2", "type": "text", "text": "@Seagent do it", "mention": {"mentionees": [{"index": 0, "length": 4, "type": "user", "isSelf": true}]}}},
            {"type": "message", "source": group, "message": {"id": "m3", "type": "text", "text": "@Bob hey", "mention": {"mentionees": [{"index": 0, "length": 4, "type": "user", "userId": "Ubob"}]}}},
            {"type": "message", "source": {"type": "room", "roomId": "Rroom", "userId": "Uamy"}, "message": {"id": "m4", "type": "image", "contentProvider": {"type": "line"}}},
            {"type": "message", "source": user, "message": {"id": "m5", "type": "file", "fileName": "a.pdf", "fileSize": 12}},
            {"type": "message", "source": user, "message": {"id": "m6", "type": "sticker", "keywords": ["happy", "cat"]}},
            {"type": "message", "source": user, "message": {"id": "m7", "type": "location", "title": "Home", "address": "Taipei", "latitude": 25.0, "longitude": 121.5}},
            {"type": "postback", "replyToken": "r3", "source": user, "webhookEventId": "e8", "postback": {"data": "appr:1:once"}},
            {"type": "follow", "source": user, "replyToken": "r4"},
            {"type": "message", "source": {"type": "user", "userId": "Ubot"}, "message": {"id": "m9", "type": "text", "text": "echo"}},
            {"type": "message", "source": user, "message": {"id": "m10", "type": "video"}},
            {"type": "message", "source": group, "message": {"id": "m11", "type": "text", "text": "@all", "mention": {"mentionees": [{"index": 0, "length": 4, "type": "all"}]}}}
        ]));
        let g = l.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 10, "follow and own message dropped: {g:?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].text.as_str(), g[0].message_id.as_str(), g[0].ts), ("Uamy", ChatType::Direct, "Uamy", "hi", "m1", 1700000000));
        assert!(g[1].mentioned && g[1].chat == "Cteam" && g[1].chat_type == ChatType::Group);
        assert!(!g[2].mentioned);
        assert_eq!((g[3].chat.as_str(), g[3].chat_type, g[3].media[0].kind, g[3].media[0].id.as_deref()), ("Rroom", ChatType::Group, MediaKind::Image, Some("m4")));
        assert_eq!((g[4].media[0].name.as_str(), g[4].media[0].size, g[4].media[0].mime.as_str()), ("a.pdf", 12, "application/pdf"));
        assert_eq!(g[5].text, "[sticker: happy, cat]");
        assert!(g[6].text.contains("Home Taipei") && g[6].text.contains("25.0"), "{}", g[6].text);
        assert_eq!(g[7].callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(g[7].message_id, "pb:e8");
        assert_eq!(g[8].media[0].kind, MediaKind::Video);
        assert!(g[9].mentioned, "@all addresses the bot");
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/v2/bot/info").count(), 1);
        // A reply uses the stashed token and the quote token; the bot's sent id becomes "own".
        l.send(&Outbound { reply_to: Some("m1".into()), ..Outbound::text("Uamy", "answer") }).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/v2/bot/message/reply");
        assert_eq!((r.json()["replyToken"].as_str(), r.json()["messages"][0]["quoteToken"].as_str()), (Some("r4"), Some("qm1")), "latest token of the chat");
        assert_eq!(r.header("authorization"), Some("Bearer TOKEN"));
        let sent_id = format!("S{}", srv.requests().len() - 1);
        deliver(&l, json!([{"type": "message", "source": user, "message": {"id": "m12", "type": "text", "text": "thanks", "quotedMessageId": sent_id}}]));
        let g = l.poll(&Cancel::new()).unwrap();
        assert!(g[0].reply.as_ref().unwrap().is_own && g[0].addressed());
        // Token is single use: the next send pushes.
        l.send(&Outbound::text("Uamy", "again")).unwrap();
        assert_eq!(srv.requests().last().unwrap().path, "/v2/bot/message/push");
    }

    #[test]
    fn send_shapes_batches_buttons_media_and_serves_local_files() {
        let srv = ok_api();
        let l = line(&srv.url, Some("https://bot.example.com"));
        // Markdown → plain, template buttons, silent.
        let b = |l: &str, d: &str| crate::Button { label: l.into(), data: d.into(), url: None };
        let s = l.send(&Outbound { format: TextFormat::Markdown, silent: true, buttons: vec![vec![b("允許", "appr:x:once"), crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]], ..Outbound::text("Uamy", "**ok?**") }).unwrap();
        assert_eq!(s.ids, vec!["S0"]);
        let r = srv.requests()[0].json();
        assert_eq!(srv.requests()[0].path, "/v2/bot/message/push");
        assert_eq!(r["to"], "Uamy");
        assert_eq!(r["notificationDisabled"], true);
        let m = &r["messages"][0];
        assert_eq!((m["type"].as_str(), m["template"]["text"].as_str()), (Some("template"), Some("ok?")));
        assert_eq!(m["template"]["actions"][0], json!({"type": "postback", "label": "允許", "data": "appr:x:once", "displayText": "允許"}));
        assert_eq!(m["template"]["actions"][1]["uri"], "https://e.com");
        assert!(srv.requests()[0].header("x-line-retry-key").is_some_and(|k| k.len() == 36));
        // Many buttons → quick reply.
        let many: Vec<crate::Button> = (0..6).map(|i| b(&format!("o{i}"), &format!("cl:{i}"))).collect();
        l.send(&Outbound { buttons: vec![many], ..Outbound::text("Uamy", "pick") }).unwrap();
        let m = srv.requests()[1].json()["messages"][0].clone();
        assert_eq!(m["quickReply"]["items"].as_array().unwrap().len(), 6);
        // Image + 6 long chunks → two push batches (5 + 2).
        let long = "word ".repeat(5000);
        assert_eq!(crate::chunk::split(&long, MAX_MESSAGE, LenUnit::Chars).len(), 6);
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        let s = l.send(&Outbound { media: vec![img], ..Outbound::text("Cteam", &long) }).unwrap();
        assert_eq!(s.ids.len(), 2);
        let (b1, b2) = (srv.requests()[2].json(), srv.requests()[3].json());
        assert_eq!(b1["messages"].as_array().unwrap().len(), 5);
        assert_eq!(b1["messages"][0], json!({"type": "image", "originalContentUrl": "https://e.com/a.png", "previewImageUrl": "https://e.com/a.png"}));
        assert!(b1["messages"][1]["text"].as_str().unwrap().chars().count() <= MAX_MESSAGE);
        assert_eq!(b2["messages"].as_array().unwrap().len(), 2);
        // Local file served through our listener with an unguessable token (the video's fallback
        // preview image is written to a fixed name in the temp dir; remove it with the test).
        let _clean = seagent_core::tmp::scratch_path("seagent-line-preview.png");
        let f = temp_dir("line").join("clip.mp4");
        std::fs::write(&f, b"MP4DATA").unwrap();
        l.send(&Outbound { media: vec![Media { kind: MediaKind::Video, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("Uamy", "") }).unwrap();
        let m = srv.requests()[4].json()["messages"][0].clone();
        let url = m["originalContentUrl"].as_str().unwrap();
        assert!(url.starts_with("https://bot.example.com/line/media/") && url.ends_with("/clip.mp4"), "{url}");
        assert!(m["previewImageUrl"].as_str().unwrap().ends_with("/preview.png"));
        let local = url.replace("https://bot.example.com", &format!("http://{}", l.local_addr()));
        let a = crate::http::agent(Duration::from_secs(5));
        let mut resp = a.get(&local).call().unwrap();
        assert_eq!((resp.status().as_u16(), resp.headers().get("content-type").unwrap().to_str().unwrap()), (200, "video/mp4"));
        assert_eq!(resp.body_mut().read_to_vec().unwrap(), b"MP4DATA");
        assert_eq!(a.get(&format!("http://{}/line/media/nope/clip.mp4", l.local_addr())).call().unwrap().status().as_u16(), 404);
        // Without public_url local files are refused.
        let l2 = line(&srv.url, None);
        let e = l2.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("U1", "") }).unwrap_err();
        assert_eq!(e.kind, K::Fatal);
        // Typing: DM only.
        let before = srv.requests().len();
        l.typing("Uamy", None).unwrap();
        l.typing("Cteam", None).unwrap();
        assert_eq!(srv.requests().len(), before + 1);
        assert_eq!(srv.requests()[before].path, "/v2/bot/chat/loading/start");
        assert_eq!(srv.requests()[before].json(), json!({"chatId": "Uamy", "loadingSeconds": 20}));
    }

    #[test]
    fn reply_token_rejected_falls_back_to_push() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/v2/bot/message/reply" => (400, vec![], json!({"message": "Invalid reply token"}).to_string()),
            "/v2/bot/info" => (200, vec![], "{}".into()),
            _ => (200, vec![], json!({"sentMessages": [{"id": "P1"}]}).to_string()),
        });
        let l = line(&srv.url, None);
        deliver(&l, json!([{"type": "message", "replyToken": "old", "source": {"type": "user", "userId": "U1"}, "message": {"id": "m1", "type": "text", "text": "x"}}]));
        l.poll(&Cancel::new()).unwrap();
        assert_eq!(l.send(&Outbound::text("U1", "hi")).unwrap().ids, vec!["P1"]);
        let paths: Vec<String> = srv.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(&paths[1..], ["/v2/bot/message/reply", "/v2/bot/message/push"]);
    }

    #[test]
    fn error_mapping_and_idempotent_retries() {
        for (status, body, kind) in [
            (401, json!({"message": "Authentication failed"}), K::Auth),
            (400, json!({"message": "The property, 'to', in the request body is invalid (line: -, column: -)"}), K::NotFound),
            (429, json!({"message": "You have reached your monthly limit."}), K::Fatal),
            (400, json!({"message": "A message (messages[0]) in the request body is invalid"}), K::Protocol),
        ] {
            let srv = FakeServer::start(move |_, _| (status, vec![], body.to_string()));
            let e = line(&srv.url, None).send(&Outbound::text("U1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains("TOKEN"));
            assert_eq!(srv.requests().len(), 1, "not retried");
        }
        // 5xx then 429 then success: retried with the same retry key.
        let srv = FakeServer::start(|_, n| match n {
            0 => (500, vec![], "{}".into()),
            1 => (429, vec![("Retry-After".into(), "0".into())], json!({"message": "Too many requests"}).to_string()),
            _ => (200, vec![], json!({"sentMessages": [{"id": "ok"}]}).to_string()),
        });
        assert_eq!(line(&srv.url, None).send(&Outbound::text("U1", "x")).unwrap().ids, vec!["ok"]);
        let keys: Vec<String> = srv.requests().iter().map(|r| r.header("x-line-retry-key").unwrap().to_string()).collect();
        assert!(keys.len() == 3 && keys.iter().all(|k| *k == keys[0]));
        // A retried push LINE already accepted answers 409: success, not a duplicate.
        let srv = FakeServer::start(|_, n| if n == 0 { (502, vec![], String::new()) } else { (409, vec![], json!({"message": "The retry key is already accepted"}).to_string()) });
        assert!(line(&srv.url, None).send(&Outbound::text("U1", "x")).is_ok());
        let srv = FakeServer::start(|_, _| (429, vec![("Retry-After".into(), "3600".into())], "{}".into()));
        assert_eq!(line(&srv.url, None).send(&Outbound::text("U1", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
    }

    #[test]
    fn fetch_media_uses_data_api_with_bearer() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/v2/bot/message/m1/content/transcoding" => (200, vec![], json!({"status": "succeeded"}).to_string()),
            "/v2/bot/message/m1/content" if req.header("authorization") == Some("Bearer TOKEN") => (200, vec![], "VIDEO".into()),
            _ => (404, vec![], "{}".into()),
        });
        let l = line(&srv.url, None);
        assert_eq!(l.fetch_media(&Media { kind: MediaKind::Video, id: Some("m1".into()), ..Default::default() }).unwrap(), b"VIDEO");
        assert_eq!(l.fetch_media(&Media { kind: MediaKind::Image, id: Some("gone".into()), ..Default::default() }).unwrap_err().kind, K::NotFound);
    }

    #[test]
    fn cancel_returns_promptly_and_webhook_registration() {
        let srv = FakeServer::start(|_, _| (200, vec![], "{}".into()));
        let l = line(&srv.url, None);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(l.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        let st: Settings = serde_json::from_value(json!({"token": "T", "channel_secret": "s", "listen": "127.0.0.1:0", "api_base": srv.url, "webhook_url": "https://bot.example.com/line/webhook"})).unwrap();
        Line::open("l", &st, "T", "s").unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.json()["endpoint"].as_str()), ("PUT", "/v2/bot/channel/webhook/endpoint", Some("https://bot.example.com/line/webhook")));
        let st: Settings = serde_json::from_value(json!({"token": "T", "channel_secret": "", "listen": "127.0.0.1:0"})).unwrap();
        assert!(Line::open("l", &st, "T", "").is_err());
        assert!(serde_json::from_value::<Settings>(json!({"token": "T", "channel_secret": "s", "listen": "x", "typo": 1})).is_err());
    }
}
