//! WeCom (企业微信) AI Bot over the `openws` WebSocket gateway (ported from Hermes
//! `plugins/platforms/wecom/{adapter,streaming,media,send_queue}.py`, MIT).
//!
//! One background thread owns the socket: `aibot_subscribe` (bot_id / secret /
//! device_id), `ping` heartbeats every 30 s, reconnect with the upstream backoff
//! (2, 5, 10, 30, 60 s), and routing of every frame. Requests are correlated by
//! `headers.req_id`; several replies may share one inbound req_id, so acks resolve
//! FIFO per req_id. A `disconnected_event` (another connection took over) stops
//! reconnecting, as the official SDK does.
//!
//! Receive: `aibot_msg_callback` (text, image, mixed, voice transcript, file,
//! video, appmsg attachments, quotes), `aibot_event_callback`
//! (`template_card_event` → button `Callback`). Group messages only reach the bot
//! when it is @mentioned, so they carry `mentioned = true` and the leading
//! `@Bot` is stripped. Media URLs are fetched and AES-256-CBC decrypted with the
//! per-message `aeskey` (iv = key[..16], PKCS#7 padded to 32).
//!
//! Send: passive `aibot_respond_msg` markdown correlated to the chat's latest
//! inbound req_id (required in groups), falling back to proactive `aibot_send_msg`;
//! media through the chunked `aibot_upload_media_init/chunk/finish` commands
//! (512 KiB base64 chunks, md5); buttons as a `button_interaction` template card;
//! native `msgtype: stream` replies via [`WeCom::stream_frame`] (also behind
//! `stream_begin/update/finish`). Each chat is held to WeCom's 30 messages / minute
//! (errcode 846607), split as upstream into a normal pool (24) and a reserved control
//! pool (6) used once the normal one is spent: approval prompts (buttons carrying
//! `appr:` data) and stream finalize frames ride the control lane, and approval prompts
//! in DMs go out proactively so they never consume the req_id a live stream needs.
//! Stream keep-alive (Hermes Layer 1, off by default, `stream_keepalive_secs`): while a
//! turn is idle its accumulated text is re-sent as `finish: false` every interval to
//! refresh WeCom's ~6-minute reply window; then old streams are still finalized.
//! Without it the Layer 2 clock fallback declines to finalize after `stream_safe`.
//! QR setup: [`qr_start`] / [`qr_poll`] drive the console's `ai/qc/generate` /
//! `query_result` endpoints (undocumented, as upstream notes) to obtain bot id + secret.

use crate::{Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_WS_URL: &str = "wss://openws.work.weixin.qq.com";
pub const MAX_MESSAGE: usize = 4000;
/// Server-enforced byte limit of one stream frame.
pub const MAX_STREAM_BYTES: usize = 20480;
const MAX_INTERMEDIATE_FRAMES: u32 = 85;

const CMD_SUBSCRIBE: &str = "aibot_subscribe";
const CMD_CALLBACK: &str = "aibot_msg_callback";
const CMD_LEGACY_CALLBACK: &str = "aibot_callback";
const CMD_EVENT: &str = "aibot_event_callback";
const CMD_PING: &str = "ping";
const CMD_RESPOND: &str = "aibot_respond_msg";
const CMD_SEND: &str = "aibot_send_msg";
const CMD_UPLOAD_INIT: &str = "aibot_upload_media_init";
const CMD_UPLOAD_CHUNK: &str = "aibot_upload_media_chunk";
const CMD_UPLOAD_FINISH: &str = "aibot_upload_media_finish";

const ERR_RATE_LIMIT: i64 = 846607;
const ERR_STREAM_EXPIRED: i64 = 846608;
const ERR_REQUEST_EXPIRED: i64 = 846604;
const ERR_NOT_SUBSCRIBED: i64 = 846609;
const ERR_VERSION_CONFLICT: i64 = 6000;

const IMAGE_MAX: usize = 10 * 1024 * 1024;
const VIDEO_MAX: usize = 10 * 1024 * 1024;
const VOICE_MAX: usize = 2 * 1024 * 1024;
const FILE_MAX: usize = 20 * 1024 * 1024;
const CHUNK: usize = 512 * 1024;
const MAX_CHUNKS: usize = 100;
const BOUND: usize = 1000;
const THINKING: &str = "<think></think>";

/// Timings; public so tests (and operators) can shrink them.
#[derive(Debug, Clone)]
pub struct Opts {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// How long a final stream frame waits for its ack before assuming delivery.
    pub ack_timeout: Duration,
    pub heartbeat: Duration,
    pub backoff: Vec<Duration>,
    /// Older streams are not finalized (they would hit 846604/846608); the caller sends instead.
    pub stream_safe: Duration,
    /// Per-chat messages per minute (a fifth of it reserved for the control lane).
    pub rate_per_min: u32,
    /// Re-send an idle stream's text this often to keep its reply window open.
    pub keepalive: Option<Duration>,
    /// Longest local rate-limit wait honoured in place; longer surfaces as `RateLimited`.
    pub max_wait: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(15),
            ack_timeout: Duration::from_secs(15),
            heartbeat: Duration::from_secs(30),
            backoff: [2, 5, 10, 30, 60].into_iter().map(Duration::from_secs).collect(),
            stream_safe: Duration::from_secs(330),
            rate_per_min: 30,
            keepalive: None,
            max_wait: Duration::from_secs(60),
        }
    }
}

struct Cmd {
    frame: Value,
    ack: Option<Sender<Value>>,
}

/// Insertion-ordered map capped at `BOUND` entries.
#[derive(Default)]
struct Bounded {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}

impl Bounded {
    fn put(&mut self, k: &str, v: &str) {
        if self.map.insert(k.to_string(), v.to_string()).is_none() {
            self.order.push_back(k.to_string());
            while self.order.len() > BOUND {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    fn get(&self, k: &str) -> Option<String> {
        self.map.get(k).cloned()
    }
    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

struct Turn {
    req_id: String,
    stream_id: String,
    seeded: bool,
    accumulated: String,
    last_sent: String,
    frames: u32,
    start: Instant,
    /// Ack of the last non-blocking frame.
    pending: Option<Receiver<Value>>,
    last_frame: Instant,
}

#[derive(Default)]
struct State {
    /// inbound msgid → its callback req_id.
    reply_req_ids: Bounded,
    /// chat → latest inbound req_id.
    last_chat_req: Bounded,
    groups: HashSet<String>,
    expired: HashSet<String>,
    turns: HashMap<String, Turn>,
    /// chat → (normal sent, reserved sent, window start).
    buckets: HashMap<String, (u32, u32, Instant)>,
}

struct Inner {
    id: String,
    bot_id: String,
    secret: String,
    url: String,
    device_id: String,
    state: Mutex<State>,
    cmd_tx: Mutex<Sender<Cmd>>,
    inbox_tx: Mutex<Sender<Inbound>>,
    stop: AtomicBool,
    connected: AtomicBool,
    fatal: Mutex<Option<ChannelError>>,
}

pub struct WeCom {
    inner: Arc<Inner>,
    pub opts: Opts,
    poll_timeout: u64,
    started: AtomicBool,
    cmd_rx: Mutex<Option<Receiver<Cmd>>>,
    inbox: Mutex<Receiver<Inbound>>,
}

fn new_req_id(prefix: &str) -> String {
    format!("{prefix}-{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(16)))
}

fn req_id_of(v: &Value) -> String {
    v["headers"]["req_id"].as_str().unwrap_or("").to_string()
}

fn errcode(v: &Value) -> i64 {
    v["errcode"].as_i64().unwrap_or(0)
}

/// A WeCom errcode → the delivery layer's error kind.
fn code_error(op: &str, code: i64, msg: &str) -> ChannelError {
    let kind = match code {
        ERR_RATE_LIMIT => K::RateLimited { retry_after: Some(Duration::from_secs(60)) },
        ERR_NOT_SUBSCRIBED => K::Network,
        40001 | 40014 | 42001 | 40013 | 40056 => K::Auth,
        // invalid userid / chatid: the chat is gone or never existed.
        40003 | 93006 => K::NotFound,
        _ => K::Protocol,
    };
    let msg: String = msg.chars().take(200).collect();
    ChannelError::new(kind, format!("wecom {op}: errcode {code} {msg}"))
}

fn check(v: Value, op: &str) -> Result<Value, ChannelError> {
    match errcode(&v) {
        0 => Ok(v),
        c => Err(code_error(op, c, v["errmsg"].as_str().unwrap_or(""))),
    }
}

/// JSON, tolerating raw control characters inside strings (WeCom sends them; upstream uses strict=False).
fn parse_json(raw: &str) -> Option<Value> {
    let v = serde_json::from_str::<Value>(raw).ok().or_else(|| {
        let mut out = String::with_capacity(raw.len() + 16);
        let (mut in_str, mut esc) = (false, false);
        for c in raw.chars() {
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                } else if (c as u32) < 0x20 {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                    continue;
                }
            } else if c == '"' {
                in_str = true;
            }
            out.push(c);
        }
        serde_json::from_str::<Value>(&out).ok()
    })?;
    v.is_object().then_some(v)
}

fn content_of(v: &Value, key: &str) -> String {
    v[key]["content"].as_str().unwrap_or("").trim().to_string()
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// (text, quoted text) as upstream `_extract_text`.
fn extract_text(body: &Value) -> (String, Option<String>) {
    let msgtype = s(&body["msgtype"]).to_lowercase();
    let parts: Vec<String> = if msgtype == "mixed" {
        body["mixed"]["msg_item"].as_array().into_iter().flatten().filter(|i| s(&i["msgtype"]).eq_ignore_ascii_case("text")).map(|i| content_of(i, "text")).collect()
    } else {
        vec![content_of(body, "text"), if msgtype == "voice" { content_of(body, "voice") } else { String::new() }, if msgtype == "appmsg" { s(&body["appmsg"]["title"]) } else { String::new() }]
    };
    let quote = &body["quote"];
    let qt = s(&quote["msgtype"]).to_lowercase();
    let reply = if qt == "text" || qt == "voice" { Some(content_of(quote, &qt)).filter(|t| !t.is_empty()) } else { None };
    (parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n").trim().to_string(), reply)
}

/// Percent-decoding without `+` → space (base64 keys contain `+`).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn media_ref(kind: &str, m: &Value) -> Option<Media> {
    let mk = match kind {
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        _ => MediaKind::Document,
    };
    let name = s(&m["filename"]).to_string();
    let name = if name.is_empty() { s(&m["name"]) } else { name };
    if let Some(b) = m["base64"].as_str().filter(|b| !b.is_empty()) {
        let data = b.split_once(',').map(|(_, d)| d).unwrap_or(b).trim();
        return Some(Media { kind: mk, url: Some(format!("data:;base64,{data}")), name, ..Default::default() });
    }
    let url = s(&m["url"]);
    if url.is_empty() {
        return None;
    }
    let key = pct_decode(&s(&m["aeskey"]));
    // The per-message AES key travels in `id`; `fetch_media` decrypts with it.
    Some(Media { kind: mk, url: Some(url), name, id: (!key.is_empty()).then_some(key), ..Default::default() })
}

fn extract_media(body: &Value) -> Vec<Media> {
    let msgtype = s(&body["msgtype"]).to_lowercase();
    let mut out = Vec::new();
    if msgtype == "mixed" {
        for item in body["mixed"]["msg_item"].as_array().into_iter().flatten() {
            if s(&item["msgtype"]).eq_ignore_ascii_case("image") && item["image"].is_object() {
                out.extend(media_ref("image", &item["image"]));
            }
        }
    } else {
        if body["image"].is_object() {
            out.extend(media_ref("image", &body["image"]));
        }
        for k in ["file", "video"] {
            if msgtype == k && body[k].is_object() {
                out.extend(media_ref(k, &body[k]));
            }
        }
        if msgtype == "appmsg" {
            let a = &body["appmsg"];
            if a["file"].is_object() {
                out.extend(media_ref("file", &a["file"]));
            } else if a["image"].is_object() {
                out.extend(media_ref("image", &a["image"]));
            }
        }
    }
    let quote = &body["quote"];
    let qt = s(&quote["msgtype"]).to_lowercase();
    if (qt == "image" || qt == "file") && quote[&qt].is_object() {
        out.extend(media_ref(&qt, &quote[&qt]));
    }
    out
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One `aibot_msg_callback` → an Inbound (None for empty / chat-less frames and our own echo).
fn parse_callback(channel: &str, bot_id: &str, payload: &Value) -> Option<Inbound> {
    let body = &payload["body"];
    if !body.is_object() {
        return None;
    }
    let req_id = req_id_of(payload);
    let msg_id = Some(s(&body["msgid"])).filter(|m| !m.is_empty()).unwrap_or_else(|| if req_id.is_empty() { new_req_id("msg") } else { req_id.clone() });
    let sender = s(&body["from"]["userid"]);
    if !bot_id.is_empty() && sender == bot_id {
        return None;
    }
    let chat = Some(s(&body["chatid"])).filter(|c| !c.is_empty()).unwrap_or_else(|| sender.clone());
    if chat.is_empty() {
        return None;
    }
    let is_group = s(&body["chattype"]).eq_ignore_ascii_case("group");
    let (mut text, reply_text) = extract_text(body);
    if is_group && !text.is_empty() {
        // "@Bot /approve" → "/approve"
        if text.starts_with('@') {
            text = text.split_once(char::is_whitespace).map(|(_, r)| r.trim().to_string()).unwrap_or_default();
        }
    }
    let media = extract_media(body);
    let has_reply_ctx = reply_text.is_some() && (!text.is_empty() || !media.is_empty());
    if let (Some(q), false) = (&reply_text, has_reply_ctx) {
        text = q.clone();
    }
    if text.is_empty() && media.is_empty() {
        return None;
    }
    Some(Inbound {
        channel: channel.to_string(),
        chat,
        chat_type: if is_group { ChatType::Group } else { ChatType::Direct },
        sender: sender.clone(),
        sender_name: sender,
        text,
        message_id: msg_id.clone(),
        ts: body["create_time"].as_i64().unwrap_or_else(now_secs),
        media,
        // WeCom only delivers group messages that @mention the bot.
        mentioned: is_group,
        reply: if has_reply_ctx { reply_text.map(|t| ReplyRef { id: format!("quote:{msg_id}"), text: t, ..Default::default() }) } else { None },
        ..Default::default()
    })
}

/// `template_card_event` → a button Callback.
fn parse_event(channel: &str, payload: &Value) -> Option<Inbound> {
    let body = &payload["body"];
    let ev = &body["event"];
    if s(&ev["eventtype"]) != "template_card_event" {
        return None;
    }
    let card = &ev["template_card_event"];
    let sender = s(&body["from"]["userid"]);
    let chat = Some(s(&body["chatid"])).filter(|c| !c.is_empty()).unwrap_or_else(|| sender.clone());
    if chat.is_empty() {
        return None;
    }
    let is_group = s(&body["chattype"]).eq_ignore_ascii_case("group");
    let msgid = Some(s(&body["msgid"])).filter(|m| !m.is_empty()).unwrap_or_else(|| req_id_of(payload));
    Some(Inbound {
        channel: channel.to_string(),
        chat,
        chat_type: if is_group { ChatType::Group } else { ChatType::Direct },
        sender: sender.clone(),
        sender_name: sender,
        message_id: format!("cb:{msgid}"),
        ts: body["create_time"].as_i64().unwrap_or_else(now_secs),
        callback: Some(Callback { id: s(&card["task_id"]), data: s(&card["event_key"]) }),
        mentioned: is_group,
        ..Default::default()
    })
}

fn is_kick(payload: &Value) -> bool {
    let b = &payload["body"];
    s(&b["event_type"]) == "disconnected_event" || s(&b["event"]["eventtype"]) == "disconnected_event"
}

enum End {
    Stopped,
    Retry { was_connected: bool },
    Fatal(ChannelError),
}

impl Inner {
    fn remember(&self, payload: &Value, chat: &str, msg_id: &str, is_group: bool) {
        let req_id = req_id_of(payload);
        let mut st = self.state.lock().unwrap();
        if is_group {
            st.groups.insert(chat.to_string());
        }
        if !req_id.is_empty() {
            st.reply_req_ids.put(msg_id, &req_id);
            st.last_chat_req.put(chat, &req_id);
            st.expired.remove(chat);
        }
    }

    /// Route one frame. `Some(end)` ends the session.
    fn dispatch(&self, pending: &mut HashMap<String, VecDeque<Sender<Value>>>, v: Value) -> Option<End> {
        let rid = req_id_of(&v);
        let cmd = v["cmd"].as_str().unwrap_or("").to_string();
        let is_callback = cmd == CMD_CALLBACK || cmd == CMD_LEGACY_CALLBACK;
        if !rid.is_empty() && !is_callback && cmd != CMD_EVENT {
            if let Some(q) = pending.get_mut(&rid) {
                if let Some(tx) = q.pop_front() {
                    let _ = tx.send(v);
                }
                if q.is_empty() {
                    pending.remove(&rid);
                }
            }
            return None;
        }
        if is_callback {
            if let Some(inb) = parse_callback(&self.id, &self.bot_id, &v) {
                self.remember(&v, &inb.chat, &inb.message_id, inb.chat_type == ChatType::Group);
                let _ = self.inbox_tx.lock().unwrap().send(inb);
            } else {
                let b = &v["body"];
                let chat = Some(s(&b["chatid"])).filter(|c| !c.is_empty()).unwrap_or_else(|| s(&b["from"]["userid"]));
                if !chat.is_empty() {
                    self.remember(&v, &chat, &s(&b["msgid"]), s(&b["chattype"]).eq_ignore_ascii_case("group"));
                }
            }
        } else if cmd == CMD_EVENT {
            if is_kick(&v) {
                return Some(End::Fatal(ChannelError::new(K::Fatal, "wecom: kicked by the server (another connection for this bot was opened); not reconnecting")));
            }
            if let Some(inb) = parse_event(&self.id, &v) {
                self.remember(&v, &inb.chat, &inb.message_id, inb.chat_type == ChatType::Group);
                let _ = self.inbox_tx.lock().unwrap().send(inb);
            }
        }
        None
    }

    /// Layer 1 keep-alive: re-send idle turns' accumulated text as `finish: false`
    /// (skipped while the previous frame's ack is pending or the frame cap is reached).
    fn keepalive<S: std::io::Read + std::io::Write>(&self, every: Duration, pending: &mut HashMap<String, VecDeque<Sender<Value>>>, ws: &mut WebSocket<S>) -> std::io::Result<()> {
        let mut st = self.state.lock().unwrap();
        for t in st.turns.values_mut() {
            if !t.seeded || t.accumulated.trim().is_empty() || t.frames >= MAX_INTERMEDIATE_FRAMES || t.last_frame.elapsed() < every {
                continue;
            }
            if t.pending.as_ref().is_some_and(|rx| matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty))) {
                continue;
            }
            let (tx, rx) = mpsc::channel();
            pending.entry(t.req_id.clone()).or_default().push_back(tx);
            let body = json!({"msgtype": "stream", "stream": {"id": t.stream_id, "finish": false, "content": truncate_bytes(&t.accumulated, MAX_STREAM_BYTES)}});
            ws.send_text(&json!({"cmd": CMD_RESPOND, "headers": {"req_id": t.req_id}, "body": body}).to_string())?;
            t.pending = Some(rx);
            t.last_frame = Instant::now();
            t.frames += 1;
            t.last_sent = t.accumulated.clone();
        }
        Ok(())
    }

    fn session(&self, opts: &Opts, cmds: &Receiver<Cmd>, connected: &mut bool) -> End {
        let retry = End::Retry { was_connected: false };
        let Ok((mut ws, _)) = WebSocket::connect(&self.url, &[], opts.connect_timeout) else { return retry };
        if ws.set_read_timeout(Some(Duration::from_millis(50))).is_err() {
            return retry;
        }
        let sub_id = new_req_id("subscribe");
        let sub = json!({"cmd": CMD_SUBSCRIBE, "headers": {"req_id": sub_id}, "body": {"bot_id": self.bot_id, "secret": self.secret, "device_id": self.device_id}});
        if ws.send_text(&sub.to_string()).is_err() {
            return retry;
        }
        let deadline = Instant::now() + opts.connect_timeout;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return End::Stopped;
            }
            if Instant::now() >= deadline {
                return retry;
            }
            match ws.recv() {
                Ok(None) => {}
                Ok(Some(Message::Text(t))) => {
                    let Some(v) = parse_json(&t) else { continue };
                    if v["cmd"] == CMD_PING || req_id_of(&v) != sub_id {
                        continue;
                    }
                    let code = errcode(&v);
                    if code != 0 {
                        let msg: String = v["errmsg"].as_str().unwrap_or("authentication failed").chars().take(200).collect();
                        return End::Fatal(ChannelError::new(K::Auth, format!("wecom subscribe rejected: {msg} (errcode={code})")));
                    }
                    break;
                }
                Ok(Some(Message::Close(_))) | Err(_) => return retry,
                Ok(Some(_)) => {}
            }
        }
        *connected = true;
        self.connected.store(true, Ordering::SeqCst);
        let retry = End::Retry { was_connected: true };
        let mut pending: HashMap<String, VecDeque<Sender<Value>>> = HashMap::new();
        let mut last_hb = Instant::now();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                return End::Stopped;
            }
            while let Ok(c) = cmds.try_recv() {
                if let Some(tx) = c.ack {
                    pending.entry(req_id_of(&c.frame)).or_default().push_back(tx);
                }
                if ws.send_text(&c.frame.to_string()).is_err() {
                    return retry;
                }
            }
            if let Some(iv) = opts.keepalive {
                if self.keepalive(iv, &mut pending, &mut ws).is_err() {
                    return retry;
                }
            }
            if last_hb.elapsed() >= opts.heartbeat {
                last_hb = Instant::now();
                if ws.send_text(&json!({"cmd": CMD_PING, "headers": {"req_id": new_req_id("ping")}, "body": {}}).to_string()).is_err() {
                    return retry;
                }
            }
            match ws.recv() {
                Ok(None) => {}
                Ok(Some(Message::Text(t))) => {
                    if let Some(end) = parse_json(&t).and_then(|v| self.dispatch(&mut pending, v)) {
                        return end;
                    }
                }
                Ok(Some(Message::Binary(b))) => {
                    if let Some(end) = parse_json(&String::from_utf8_lossy(&b)).and_then(|v| self.dispatch(&mut pending, v)) {
                        return end;
                    }
                }
                Ok(Some(Message::Close(_))) | Err(_) => return retry,
                Ok(Some(_)) => {}
            }
        }
    }

    fn run(self: Arc<Self>, opts: Opts, cmds: Receiver<Cmd>) {
        let mut idx = 0usize;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let mut connected = false;
            let end = self.session(&opts, &cmds, &mut connected);
            self.connected.store(false, Ordering::SeqCst);
            match end {
                End::Stopped => break,
                End::Fatal(e) => {
                    *self.fatal.lock().unwrap() = Some(e);
                    break;
                }
                End::Retry { was_connected } => {
                    if was_connected {
                        idx = 0;
                    }
                    let wait = opts.backoff.get(idx.min(opts.backoff.len().saturating_sub(1))).copied().unwrap_or(Duration::from_secs(5));
                    idx += 1;
                    let until = Instant::now() + wait;
                    while Instant::now() < until && !self.stop.load(Ordering::SeqCst) {
                        // Requests made while down fail at once (their ack sender drops).
                        while cmds.try_recv().is_ok() {}
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
        // Wake any waiter.
        while cmds.try_recv().is_ok() {}
    }
}

/// MD5 (RFC 1321) — WeCom's upload init wants the file's md5 and ring has none.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in [a0, b0, c0, d0].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Decrypt an inbound attachment: AES-256-CBC, key = base64(aeskey) (unpadded, maybe
/// percent-encoded), iv = key[..16], PKCS#7 padding of up to 32 bytes.
pub fn decrypt_media(data: &[u8], aeskey: &str) -> Result<Vec<u8>, ChannelError> {
    let bad = |m: &str| ChannelError::new(K::Protocol, format!("wecom media decrypt: {m}"));
    if data.is_empty() {
        return Err(bad("empty data"));
    }
    let k = pct_decode(aeskey.trim());
    let k = k.trim_end_matches('=');
    let padded = format!("{k}{}", "=".repeat((4 - k.len() % 4) % 4));
    let key = ark_net::crypto::b64_decode(&padded).ok_or_else(|| bad("aeskey is not base64"))?;
    if key.len() != 32 {
        return Err(bad(&format!("expected a 32-byte key, got {}", key.len())));
    }
    let aes = ark_net::crypto::Aes::new(&key).ok_or_else(|| bad("bad key"))?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key[..16]);
    aes.cbc_decrypt(&iv, data).ok_or_else(|| bad("bad length or padding"))
}

fn ext_of(name: &str) -> String {
    let base = name.split(['?', '#']).next().unwrap_or("");
    base.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).filter(|e| !e.contains('/')).unwrap_or_default()
}

fn guess_mime(name: &str) -> &'static str {
    match ext_of(name).as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "amr" => "audio/amr",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "zip" => "application/zip",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

fn normalize_mime(mime: &str, name: &str) -> String {
    let m = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if m.is_empty() || m == "application/octet-stream" || m == "text/plain" {
        guess_mime(name).to_string()
    } else {
        m
    }
}

/// WeCom media type for a MIME: image / video / voice / file.
fn wecom_type(mime: &str) -> &'static str {
    if mime == "application/ogg" || mime.starts_with("audio/") {
        "voice"
    } else if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else {
        "file"
    }
}

/// Size/format policy: Err(reject reason) or (final type, downgrade note).
fn size_verdict(size: usize, detected: &str, mime: &str) -> Result<(&'static str, Option<String>), String> {
    let mb = size as f64 / (1024.0 * 1024.0);
    if size > FILE_MAX {
        return Err(format!("File too large ({mb:.2} MB); WeCom accepts at most 20 MB"));
    }
    let detected: &'static str = match detected {
        "image" => "image",
        "video" => "video",
        "voice" => "voice",
        _ => "file",
    };
    if detected == "voice" && !mime.is_empty() && mime != "audio/amr" {
        return Ok(("file", Some(format!("Voice messages must be AMR; {mime} was sent as a file"))));
    }
    let cap = match detected {
        "image" => Some((IMAGE_MAX, "Image", "10MB")),
        "video" => Some((VIDEO_MAX, "Video", "10MB")),
        "voice" => Some((VOICE_MAX, "Voice", "2MB")),
        _ => None,
    };
    match cap {
        Some((max, label, human)) if size > max => Ok(("file", Some(format!("{label} is {mb:.2} MB (over {human}); sent as a file")))),
        _ => Ok((detected, None)),
    }
}

fn truncate_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn markdown_body(content: &str) -> Value {
    let c: String = content.chars().take(MAX_MESSAGE).collect();
    json!({"msgtype": "markdown", "markdown": {"content": c}})
}

fn media_body(kind: &str, media_id: &str) -> Value {
    json!({"msgtype": kind, kind: {"media_id": media_id}})
}

impl WeCom {
    pub fn new(id: &str, bot_id: &str, secret: &str, url: Option<&str>, poll_timeout_secs: u64) -> Result<WeCom, String> {
        if bot_id.trim().is_empty() || secret.trim().is_empty() {
            return Err(format!("channel {id}: wecom needs bot_id and secret"));
        }
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (inbox_tx, inbox) = mpsc::channel();
        Ok(WeCom {
            inner: Arc::new(Inner {
                id: id.to_string(),
                bot_id: bot_id.trim().to_string(),
                secret: secret.trim().to_string(),
                url: url.unwrap_or(DEFAULT_WS_URL).trim().to_string(),
                device_id: ark_net::crypto::hex(&ark_net::crypto::random_bytes(16)),
                state: Mutex::new(State::default()),
                cmd_tx: Mutex::new(cmd_tx),
                inbox_tx: Mutex::new(inbox_tx),
                stop: AtomicBool::new(false),
                connected: AtomicBool::new(false),
                fatal: Mutex::new(None),
            }),
            opts: Opts::default(),
            poll_timeout: poll_timeout_secs,
            started: AtomicBool::new(false),
            cmd_rx: Mutex::new(Some(cmd_rx)),
            inbox: Mutex::new(inbox),
        })
    }

    /// Start the gateway thread (first poll or send).
    fn start(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(rx) = self.cmd_rx.lock().unwrap().take() else { return };
        let (inner, opts) = (self.inner.clone(), self.opts.clone());
        let _ = std::thread::Builder::new().name(format!("wecom {}", self.inner.id)).spawn(move || inner.run(opts, rx));
    }

    /// Wait (bounded) until the first subscription finishes.
    fn ensure_ready(&self) -> Result<(), ChannelError> {
        self.start();
        let until = Instant::now() + self.opts.connect_timeout.min(Duration::from_secs(5));
        loop {
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if self.inner.connected.load(Ordering::SeqCst) {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(ChannelError::new(K::Network, "wecom websocket is not connected"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Queue a frame; returns the receiver for its ack.
    fn submit(&self, cmd: &str, req_id: &str, body: Value) -> Result<Receiver<Value>, ChannelError> {
        self.ensure_ready()?;
        let (tx, rx) = mpsc::channel();
        let frame = json!({"cmd": cmd, "headers": {"req_id": req_id}, "body": body});
        self.inner.cmd_tx.lock().unwrap().send(Cmd { frame, ack: Some(tx) }).map_err(|_| ChannelError::new(K::Network, "wecom gateway thread stopped"))?;
        Ok(rx)
    }

    fn wait(rx: &Receiver<Value>, timeout: Duration, op: &str) -> Result<Value, ChannelError> {
        match rx.recv_timeout(timeout) {
            Ok(v) => Ok(v),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ChannelError::new(K::Network, format!("wecom {op}: timed out waiting for the ack"))),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ChannelError::new(K::Network, format!("wecom {op}: connection interrupted"))),
        }
    }

    fn request(&self, cmd: &str, req_id: &str, body: Value) -> Result<Value, ChannelError> {
        let rx = self.submit(cmd, req_id, body)?;
        Self::wait(&rx, self.opts.request_timeout, cmd)
    }

    /// `check` plus the 846609 bookkeeping: drop req_ids bound to the dead subscription
    /// (never close the socket — a second connection would be kicked).
    fn checked(&self, v: Value, op: &str) -> Result<Value, ChannelError> {
        if errcode(&v) == ERR_NOT_SUBSCRIBED {
            let mut st = self.inner.state.lock().unwrap();
            st.last_chat_req.clear();
            st.reply_req_ids.clear();
        }
        check(v, op)
    }

    fn reply_req_id(&self, chat: &str, reply_to: Option<&str>) -> Option<String> {
        let st = self.inner.state.lock().unwrap();
        reply_to.filter(|r| !r.is_empty() && !r.starts_with("quote:")).and_then(|r| st.reply_req_ids.get(r)).or_else(|| st.last_chat_req.get(chat))
    }

    fn is_group(&self, chat: &str) -> bool {
        self.inner.state.lock().unwrap().groups.contains(chat)
    }

    /// Per-chat token bucket (30/min, errcode 846607 otherwise); `control` may also draw on
    /// the reserved fifth.
    fn take_token(&self, chat: &str, control: bool) -> Result<(), ChannelError> {
        let reserved = self.opts.rate_per_min / 5;
        let normal = self.opts.rate_per_min - reserved;
        loop {
            let wait = {
                let mut st = self.inner.state.lock().unwrap();
                let now = Instant::now();
                let e = st.buckets.entry(chat.to_string()).or_insert((0, 0, now));
                if now.duration_since(e.2) >= Duration::from_secs(60) {
                    *e = (0, 0, now);
                }
                if e.0 < normal {
                    e.0 += 1;
                    return Ok(());
                }
                if control && e.1 < reserved {
                    e.1 += 1;
                    return Ok(());
                }
                Duration::from_secs(60).saturating_sub(now.duration_since(e.2))
            };
            if wait > self.opts.max_wait {
                return Err(ChannelError::new(K::RateLimited { retry_after: Some(wait) }, format!("wecom: {} messages/minute limit for this chat", self.opts.rate_per_min)));
            }
            std::thread::sleep(wait.max(Duration::from_millis(10)));
        }
    }

    /// Passive reply when the chat has an inbound req_id (falls back to proactive on failure),
    /// proactive `aibot_send_msg` otherwise; groups require the passive path.
    fn deliver(&self, chat: &str, reply_to: Option<&str>, body: Value) -> Result<String, ChannelError> {
        self.deliver_lane(chat, reply_to, body, false)
    }

    /// `control`: reserved token pool, and proactive in DMs (keeps the stream's req_id free).
    fn deliver_lane(&self, chat: &str, reply_to: Option<&str>, body: Value, control: bool) -> Result<String, ChannelError> {
        self.take_token(chat, control)?;
        let rid = if control && !self.is_group(chat) { None } else { self.reply_req_id(chat, reply_to) };
        let resp = match rid {
            Some(rid) => match self.request(CMD_RESPOND, &rid, body.clone()).and_then(|v| self.checked(v, "reply")) {
                Ok(v) => v,
                Err(e) if matches!(e.kind, K::RateLimited { .. }) => return Err(e),
                // A stale req_id (reconnect, expired window): proactive sends need none.
                Err(_) => self.proactive(chat, body)?,
            },
            None if self.is_group(chat) => return Err(ChannelError::new(K::Protocol, "wecom: no inbound req_id for this group chat (groups only accept passive replies)")),
            None => self.proactive(chat, body)?,
        };
        Ok(Some(req_id_of(&resp)).filter(|r| !r.is_empty()).unwrap_or_else(|| new_req_id("msg")))
    }

    fn proactive(&self, chat: &str, body: Value) -> Result<Value, ChannelError> {
        let mut b = body;
        b["chatid"] = json!(chat);
        let v = self.request(CMD_SEND, &new_req_id(CMD_SEND), b)?;
        self.checked(v, "send")
    }

    /// Chunked upload: init (type, filename, size, chunks, md5) → 512 KiB base64 chunks
    /// (0-based) → finish → media_id.
    pub fn upload_media(&self, data: &[u8], kind: &str, filename: &str) -> Result<String, ChannelError> {
        if data.is_empty() {
            return Err(ChannelError::new(K::Fatal, "wecom: cannot upload empty media"));
        }
        let chunks = data.len().div_ceil(CHUNK);
        if chunks > MAX_CHUNKS {
            return Err(ChannelError::new(K::Fatal, format!("wecom: file needs {chunks} chunks (max {MAX_CHUNKS})")));
        }
        let init = json!({"type": kind, "filename": filename, "total_size": data.len(), "total_chunks": chunks, "md5": ark_net::crypto::hex(&md5(data))});
        let r = self.request(CMD_UPLOAD_INIT, &new_req_id(CMD_UPLOAD_INIT), init).and_then(|v| self.checked(v, "media upload init"))?;
        let upload_id = s(&r["body"]["upload_id"]);
        if upload_id.is_empty() {
            return Err(ChannelError::new(K::Protocol, "wecom media upload init: missing upload_id"));
        }
        for (i, c) in data.chunks(CHUNK).enumerate() {
            let body = json!({"upload_id": upload_id, "chunk_index": i, "base64_data": ark_net::crypto::b64(c)});
            self.request(CMD_UPLOAD_CHUNK, &new_req_id(CMD_UPLOAD_CHUNK), body).and_then(|v| self.checked(v, "media upload chunk"))?;
        }
        let r = self.request(CMD_UPLOAD_FINISH, &new_req_id(CMD_UPLOAD_FINISH), json!({"upload_id": upload_id})).and_then(|v| self.checked(v, "media upload finish"))?;
        let id = s(&r["body"]["media_id"]);
        if id.is_empty() {
            return Err(ChannelError::new(K::Protocol, "wecom media upload finish: missing media_id"));
        }
        Ok(id)
    }

    fn load_media(&self, m: &Media) -> Result<(Vec<u8>, String, String), ChannelError> {
        if let Some(p) = &m.path {
            let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
            let name = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
            let mime = normalize_mime(&m.mime, &name);
            return Ok((data, mime, name));
        }
        let url = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "attachment has neither path nor url"))?;
        let data = crate::http::get_bytes(url, &[("user-agent", "ark"), ("accept", "*/*")], FILE_MAX as u64)?;
        let name = if m.name.is_empty() { url.split(['?', '#']).next().unwrap_or("").rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("file").to_string() } else { m.name.clone() };
        let mut mime = normalize_mime(&m.mime, &name);
        if mime == "application/octet-stream" {
            mime = sniff_image(&data).unwrap_or(mime);
        }
        Ok((data, mime, name))
    }

    fn send_one_media(&self, out: &Outbound, m: &Media) -> Result<String, ChannelError> {
        let (data, mime, name) = self.load_media(m)?;
        let detected = if m.kind == MediaKind::Voice && mime.starts_with("audio/") { "voice" } else { wecom_type(&mime) };
        let (kind, note) = match size_verdict(data.len(), detected, &mime) {
            Ok(v) => v,
            Err(reason) => {
                let _ = self.deliver(&out.chat, out.reply_to.as_deref(), markdown_body(&format!("⚠️ {reason}")));
                return Err(ChannelError::new(K::Protocol, format!("wecom: {reason}")));
            }
        };
        let media_id = self.upload_media(&data, kind, &name)?;
        // An active (or expired) stream owns the req_id; passive media is never acked there.
        let busy = {
            let st = self.inner.state.lock().unwrap();
            st.turns.contains_key(&out.chat) || st.expired.contains(&out.chat)
        };
        let rid = if busy { None } else { self.reply_req_id(&out.chat, out.reply_to.as_deref()) };
        self.take_token(&out.chat, false)?;
        let resp = match rid {
            Some(rid) => self.request(CMD_RESPOND, &rid, media_body(kind, &media_id)).and_then(|v| self.checked(v, "reply media"))?,
            None => self.proactive(&out.chat, media_body(kind, &media_id))?,
        };
        if let Some(n) = note {
            let _ = self.deliver(&out.chat, out.reply_to.as_deref(), markdown_body(&format!("ℹ️ {n}")));
        }
        if let Some(c) = m.caption.as_deref().filter(|c| !c.trim().is_empty()) {
            let _ = self.deliver(&out.chat, out.reply_to.as_deref(), markdown_body(c));
        }
        Ok(Some(req_id_of(&resp)).filter(|r| !r.is_empty()).unwrap_or_else(|| new_req_id("msg")))
    }

    fn card_body(buttons: &[Vec<crate::Button>]) -> Option<Value> {
        let list: Vec<Value> = buttons.iter().flatten().filter(|b| b.url.is_none()).take(6).map(|b| json!({"text": b.label.chars().take(10).collect::<String>(), "style": 1, "key": b.data})).collect();
        if list.is_empty() {
            return None;
        }
        Some(json!({"msgtype": "template_card", "template_card": {"card_type": "button_interaction", "main_title": {"title": "请选择"}, "task_id": new_req_id("task"), "button_list": list}}))
    }

    /// Native stream reply (`msgtype: stream`): the first call seeds the bubble with
    /// `<think></think>`, later calls push the cumulative text (non-blocking, skipped while
    /// the previous frame's ack is pending), `finalize` sends `finish: true` and waits for
    /// its ack. `Ok(false)`: streaming is unavailable here — send normally instead.
    pub fn stream_frame(&self, chat: &str, reply_to: Option<&str>, text: &str, finalize: bool) -> Result<bool, ChannelError> {
        let chat = chat.trim();
        if chat.is_empty() {
            return Ok(false);
        }
        let existing = self.inner.state.lock().unwrap().turns.remove(chat);
        let mut turn = match existing {
            Some(t) => t,
            None => {
                if self.inner.state.lock().unwrap().expired.contains(chat) {
                    return Ok(false);
                }
                let Some(req_id) = self.reply_req_id(chat, reply_to) else { return Ok(false) };
                Turn { req_id, stream_id: format!("stream_{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(6))), seeded: false, accumulated: String::new(), last_sent: String::new(), frames: 0, start: Instant::now(), pending: None, last_frame: Instant::now() }
            }
        };
        let r = self.stream_step(chat, &mut turn, text, finalize);
        match r {
            Ok(StepEnd::Keep(b)) => {
                self.inner.state.lock().unwrap().turns.insert(chat.to_string(), turn);
                Ok(b)
            }
            Ok(StepEnd::Done(b)) => Ok(b),
            Ok(StepEnd::Expire) => {
                self.inner.state.lock().unwrap().expired.insert(chat.to_string());
                Ok(false)
            }
            Err(e) => {
                if finalize {
                    Ok(false)
                } else {
                    let _ = e;
                    // Intermediate frames are overwritten by the next one anyway.
                    self.inner.state.lock().unwrap().turns.insert(chat.to_string(), turn);
                    Ok(true)
                }
            }
        }
    }

    fn stream_body(turn: &Turn, content: &str, finish: bool) -> Value {
        json!({"msgtype": "stream", "stream": {"id": turn.stream_id, "finish": finish, "content": truncate_bytes(content, MAX_STREAM_BYTES)}})
    }

    /// Fire-and-forget frame; skipped while the previous ack is pending.
    fn stream_nonblocking(&self, turn: &mut Turn, content: &str) -> Result<(), ChannelError> {
        if let Some(rx) = &turn.pending {
            if matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                return Ok(());
            }
        }
        let rx = self.submit(CMD_RESPOND, &turn.req_id.clone(), Self::stream_body(turn, content, false))?;
        turn.pending = Some(rx);
        turn.last_frame = Instant::now();
        Ok(())
    }

    fn stream_step(&self, chat: &str, turn: &mut Turn, text: &str, finalize: bool) -> Result<StepEnd, ChannelError> {
        if !turn.seeded {
            self.stream_nonblocking(turn, THINKING)?;
            turn.seeded = true;
            if text.is_empty() && !finalize {
                return Ok(StepEnd::Keep(true));
            }
        }
        if finalize {
            // Layer 2: without keep-alive an old stream would fail with 846604/846608.
            if self.opts.keepalive.is_none() && turn.start.elapsed() >= self.opts.stream_safe {
                return Ok(StepEnd::Expire);
            }
            if let Some(rx) = turn.pending.take() {
                let _ = rx.recv_timeout(self.opts.ack_timeout);
            }
            // A final frame identical to the last one is dropped by WeCom: differ by a ZWSP.
            let final_text = if !text.is_empty() && text == turn.last_sent { format!("{text}\u{200b}") } else { text.to_string() };
            self.take_token(chat, true)?;
            let rx = self.submit(CMD_RESPOND, &turn.req_id.clone(), Self::stream_body(turn, &final_text, true))?;
            let resp = match rx.recv_timeout(self.opts.ack_timeout) {
                Ok(v) => v,
                // Bytes went out; WeCom already rendered them. Re-sending would duplicate.
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(StepEnd::Done(true)),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "wecom stream: connection interrupted")),
            };
            return match errcode(&resp) {
                ERR_STREAM_EXPIRED | ERR_REQUEST_EXPIRED => Ok(StepEnd::Expire),
                ERR_VERSION_CONFLICT => Ok(StepEnd::Done(true)),
                _ => self.checked(resp, "stream reply").map(|_| StepEnd::Done(true)),
            };
        }
        turn.accumulated = text.to_string();
        if turn.frames >= MAX_INTERMEDIATE_FRAMES || text == turn.last_sent {
            return Ok(StepEnd::Keep(true));
        }
        self.stream_nonblocking(turn, text)?;
        turn.frames += 1;
        turn.last_sent = text.to_string();
        Ok(StepEnd::Keep(true))
    }
}

enum StepEnd {
    Keep(bool),
    Done(bool),
    Expire,
}

fn sniff_image(d: &[u8]) -> Option<String> {
    if d.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png".into())
    } else if d.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg".into())
    } else if d.starts_with(b"GIF87a") || d.starts_with(b"GIF89a") {
        Some("image/gif".into())
    } else if d.len() >= 12 && d.starts_with(b"RIFF") && &d[8..12] == b"WEBP" {
        Some("image/webp".into())
    } else {
        None
    }
}

impl Drop for WeCom {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

impl Channel for WeCom {
    fn id(&self) -> &str {
        &self.inner.id
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
            typing: false,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: Streaming::Native,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.start();
        let rx = self.inbox.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    got.push(m);
                    got.extend(rx.try_iter());
                }
                Err(_) => {
                    if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                        return Err(e);
                    }
                }
            }
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        if out.chat.trim().is_empty() {
            return Err(ChannelError::new(K::Fatal, "wecom: chat id is required"));
        }
        let mut sent = Sent::default();
        for m in &out.media {
            match self.send_one_media(out, m) {
                Ok(id) => sent.ids.push(id),
                // An image URL that cannot be sent natively goes out as a link.
                Err(e) if m.path.is_none() && m.kind == MediaKind::Image && m.url.is_some() && e.kind != K::Auth => {
                    let u = m.url.clone().unwrap_or_default();
                    let t = match m.caption.as_deref() {
                        Some(c) => format!("{c}\n{u}"),
                        None => u,
                    };
                    sent.ids.push(self.deliver(&out.chat, out.reply_to.as_deref(), markdown_body(&t))?);
                }
                Err(e) => return Err(e),
            }
        }
        let mut text = out.text.clone();
        let links: Vec<String> = out.buttons.iter().flatten().filter_map(|b| b.url.as_ref().map(|u| format!("[{}]({u})", b.label))).collect();
        if !links.is_empty() {
            text = format!("{}\n\n{}", text.trim_end(), links.join("  "));
        }
        // Approval prompts: control lane (reserved quota, proactive in DMs).
        let control = out.buttons.iter().flatten().any(|b| b.data.starts_with("appr:"));
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            sent.ids.push(self.deliver_lane(&out.chat, out.reply_to.as_deref(), markdown_body(&piece), control)?);
        }
        if let Some(card) = Self::card_body(&out.buttons) {
            match self.deliver_lane(&out.chat, out.reply_to.as_deref(), card, control) {
                Ok(id) => sent.ids.push(id),
                Err(e) if e.kind == K::Protocol => {
                    // No card support here: numbered text options instead.
                    let opts: Vec<String> = out.buttons.iter().flatten().filter(|b| b.url.is_none()).enumerate().map(|(i, b)| format!("{}. {}", i + 1, b.label)).collect();
                    sent.ids.push(self.deliver_lane(&out.chat, out.reply_to.as_deref(), markdown_body(&opts.join("\n")), control)?);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(sent)
    }

    fn stream_begin(&self, out: &Outbound) -> Result<Option<String>, ChannelError> {
        Ok(self.stream_frame(&out.chat, out.reply_to.as_deref(), &out.text, false)?.then(|| out.chat.clone()))
    }

    fn stream_update(&self, chat: &str, _handle: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        self.stream_frame(chat, None, text, false).map(|_| ())
    }

    fn stream_finish(&self, chat: &str, _handle: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        // Declined (expired / too old): deliver the text as a normal message instead.
        if !self.stream_frame(chat, None, text, true)? && !text.trim().is_empty() {
            self.send(&Outbound { format: crate::TextFormat::Markdown, ..Outbound::text(chat, text) })?;
        }
        Ok(())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "wecom attachment without url"))?;
        if let Some(d) = url.strip_prefix("data:") {
            let b64 = d.split_once(',').map(|(_, b)| b).unwrap_or("");
            return ark_net::crypto::b64_decode(b64).ok_or_else(|| ChannelError::new(K::Protocol, "wecom: bad inline base64 media"));
        }
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(ChannelError::new(K::Fatal, "wecom: refusing a non-http media url"));
        }
        let raw = crate::http::get_bytes(url, &[("user-agent", "ark"), ("accept", "*/*")], FILE_MAX as u64)?;
        match m.id.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => decrypt_media(&raw, k),
            None => Ok(raw),
        }
    }

    fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------- QR setup

pub const QR_BASE: &str = "https://work.weixin.qq.com";

/// A setup QR code: render `auth_url`, or open `page_url` in WeCom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrSetup {
    pub scode: String,
    pub auth_url: String,
    pub page_url: String,
}

fn qr_get(url: &str) -> Result<Value, ChannelError> {
    let b = crate::http::get_bytes(url, &[("user-agent", "ark")], 1024 * 1024)?;
    serde_json::from_slice(&b).map_err(|_| ChannelError::new(K::Protocol, "wecom QR: bad JSON"))
}

/// Step 1 (`ai/qc/generate`): a scan code for creating / binding an AI bot.
pub fn qr_start(base: Option<&str>) -> Result<QrSetup, ChannelError> {
    let base = base.unwrap_or(QR_BASE).trim_end_matches('/');
    let v = qr_get(&format!("{base}/ai/qc/generate?source=ark"))?;
    let (scode, auth_url) = (s(&v["data"]["scode"]).trim().to_string(), s(&v["data"]["auth_url"]).trim().to_string());
    if scode.is_empty() || auth_url.is_empty() {
        return Err(ChannelError::new(K::Protocol, "wecom QR: unexpected response format"));
    }
    let page_url = format!("{base}/ai/qc/gen?source=ark&scode={}", ark_net::urlencode(&scode));
    Ok(QrSetup { scode, auth_url, page_url })
}

/// Step 2 (`ai/qc/query_result`, poll every few seconds): `Some((bot_id, secret))` once
/// scanned, `None` while waiting; success without credentials is an error.
pub fn qr_poll(base: Option<&str>, scode: &str) -> Result<Option<(String, String)>, ChannelError> {
    let base = base.unwrap_or(QR_BASE).trim_end_matches('/');
    let v = qr_get(&format!("{base}/ai/qc/query_result?scode={}", ark_net::urlencode(scode)))?;
    let d = &v["data"];
    if !s(&d["status"]).eq_ignore_ascii_case("success") {
        return Ok(None);
    }
    let b = &d["bot_info"];
    let bot = Some(s(&b["botid"])).filter(|x| !x.trim().is_empty()).unwrap_or_else(|| s(&b["bot_id"]));
    let secret = s(&b["secret"]);
    if bot.trim().is_empty() || secret.trim().is_empty() {
        return Err(ChannelError::new(K::Protocol, "wecom QR: scan succeeded but no bot credentials were returned (bot not created?)"));
    }
    Ok(Some((bot.trim().to_string(), secret.trim().to_string())))
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    bot_id: String,
    secret: String,
    #[serde(default)]
    websocket_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Streams older than this are not finalized (WeCom's reply window is ~6 minutes).
    #[serde(default)]
    stream_safe_duration_secs: Option<u64>,
    /// Stream keep-alive interval (upstream: 120 s; off unless set).
    #[serde(default)]
    stream_keepalive_secs: Option<u64>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let bot_id = ctx.secret("bot_id", &st.bot_id)?;
    let secret = ctx.secret("secret", &st.secret)?;
    let mut w = WeCom::new(ctx.name, &bot_id, &secret, st.websocket_url.as_deref(), st.poll_timeout_secs)?;
    if let Some(sd) = st.stream_safe_duration_secs {
        w.opts.stream_safe = Duration::from_secs(sd);
    }
    w.opts.keepalive = st.stream_keepalive_secs.filter(|s| *s > 0).map(Duration::from_secs);
    Ok(Arc::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;

    type Responder = dyn Fn(&Value) -> Option<Value> + Send + Sync;

    enum Ctl {
        Frame(Value),
        Drop,
    }

    struct FakeWs {
        url: String,
        seen: Arc<Mutex<Vec<Value>>>,
        ctl: Arc<Mutex<Option<Sender<Ctl>>>>,
        conns: Arc<AtomicUsize>,
    }

    fn ack(v: &Value, errcode: i64, body: Value) -> Value {
        json!({"headers": {"req_id": req_id_of(v)}, "errcode": errcode, "errmsg": if errcode == 0 { "ok" } else { "boom" }, "body": body})
    }

    fn default_responder(v: &Value) -> Option<Value> {
        Some(match v["cmd"].as_str().unwrap_or("") {
            CMD_UPLOAD_INIT => ack(v, 0, json!({"upload_id": "UP1"})),
            CMD_UPLOAD_FINISH => ack(v, 0, json!({"media_id": "MEDIA1", "type": v["body"]["type"]})),
            _ => ack(v, 0, json!({})),
        })
    }

    impl FakeWs {
        fn start(auth_code: i64, responder: Arc<Responder>) -> FakeWs {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("ws://{}", l.local_addr().unwrap());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let ctl: Arc<Mutex<Option<Sender<Ctl>>>> = Arc::new(Mutex::new(None));
            let conns = Arc::new(AtomicUsize::new(0));
            let (s2, c2, n2) = (seen.clone(), ctl.clone(), conns.clone());
            std::thread::spawn(move || {
                for stream in l.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let (seen, ctl, resp) = (s2.clone(), c2.clone(), responder.clone());
                    n2.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let Ok((head, rest)) = ark_net::ws::read_head(&mut stream, 65536) else { return };
                        let tcp: TcpStream = stream.try_clone().unwrap();
                        let Ok(mut ws) = WebSocket::accept(stream, &head, rest) else { return };
                        tcp.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
                        let (tx, rx) = mpsc::channel();
                        *ctl.lock().unwrap() = Some(tx);
                        loop {
                            while let Ok(c) = rx.try_recv() {
                                match c {
                                    Ctl::Frame(v) => {
                                        let _ = ws.send_text(&v.to_string());
                                    }
                                    Ctl::Drop => {
                                        let _ = tcp.shutdown(std::net::Shutdown::Both);
                                        return;
                                    }
                                }
                            }
                            match ws.recv() {
                                Ok(None) => {}
                                Ok(Some(Message::Text(t))) => {
                                    let v: Value = serde_json::from_str(&t).unwrap();
                                    seen.lock().unwrap().push(v.clone());
                                    let reply = if v["cmd"] == CMD_SUBSCRIBE { Some(ack(&v, auth_code, json!({}))) } else { resp(&v) };
                                    if let Some(r) = reply {
                                        let _ = ws.send_text(&r.to_string());
                                    }
                                }
                                Ok(Some(_)) => {}
                                Err(_) => return,
                            }
                        }
                    });
                }
            });
            FakeWs { url, seen, ctl, conns }
        }
        fn push(&self, v: Value) {
            self.ctl.lock().unwrap().as_ref().unwrap().send(Ctl::Frame(v)).unwrap();
        }
        fn drop_conn(&self) {
            self.ctl.lock().unwrap().as_ref().unwrap().send(Ctl::Drop).unwrap();
        }
        fn frames(&self, cmd: &str) -> Vec<Value> {
            self.seen.lock().unwrap().iter().filter(|v| v["cmd"] == cmd).cloned().collect()
        }
        fn wait_for(&self, cmd: &str, n: usize) -> Vec<Value> {
            let until = Instant::now() + Duration::from_secs(5);
            while self.frames(cmd).len() < n && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            self.frames(cmd)
        }
    }

    fn wc(url: &str) -> WeCom {
        let mut w = WeCom::new("wc", "BOT1", "TOPSECRET", Some(url), 2).unwrap();
        w.opts.backoff = vec![Duration::from_millis(50)];
        w.opts.request_timeout = Duration::from_secs(3);
        w.opts.ack_timeout = Duration::from_secs(2);
        w
    }

    fn callback(req: &str, body: Value) -> Value {
        json!({"cmd": CMD_CALLBACK, "headers": {"req_id": req}, "body": body})
    }

    fn text_cb(req: &str, msgid: &str, chat: Option<&str>, user: &str, text: &str) -> Value {
        let mut b = json!({"msgid": msgid, "from": {"userid": user}, "msgtype": "text", "text": {"content": text}, "chattype": if chat.is_some() { "group" } else { "single" }});
        if let Some(c) = chat {
            b["chatid"] = json!(c);
        }
        callback(req, b)
    }

    fn poll_one(w: &WeCom) -> Inbound {
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        got.into_iter().next().unwrap()
    }

    #[test]
    fn parses_every_message_kind() {
        let p = |b: Value| parse_callback("wc", "BOT1", &callback("r1", b));
        let dm = p(json!({"msgid": "m1", "from": {"userid": "amy"}, "chattype": "single", "msgtype": "text", "text": {"content": " hi "}, "create_time": 1700000000})).unwrap();
        assert_eq!((dm.chat.as_str(), dm.sender.as_str(), dm.text.as_str(), dm.message_id.as_str(), dm.chat_type, dm.mentioned, dm.ts), ("amy", "amy", "hi", "m1", ChatType::Direct, false, 1700000000));
        let g = p(json!({"msgid": "m2", "chatid": "G1", "chattype": "group", "from": {"userid": "amy"}, "msgtype": "text", "text": {"content": "@Ark /approve now"}})).unwrap();
        assert_eq!((g.chat.as_str(), g.chat_type, g.text.as_str(), g.mentioned), ("G1", ChatType::Group, "/approve now", true));
        let img = p(json!({"msgid": "m3", "from": {"userid": "amy"}, "msgtype": "image", "image": {"url": "https://cdn/x", "aeskey": "AAEC%2BwQF"}})).unwrap();
        assert_eq!((img.media[0].kind, img.media[0].url.as_deref(), img.media[0].id.as_deref(), img.text.as_str()), (MediaKind::Image, Some("https://cdn/x"), Some("AAEC+wQF"), ""));
        let mixed = p(json!({"msgid": "m4", "from": {"userid": "amy"}, "msgtype": "mixed", "mixed": {"msg_item": [{"msgtype": "text", "text": {"content": "look"}}, {"msgtype": "image", "image": {"url": "https://cdn/a"}}, {"msgtype": "text", "text": {"content": "here"}}]}})).unwrap();
        assert_eq!((mixed.text.as_str(), mixed.media.len()), ("look\nhere", 1));
        let voice = p(json!({"msgid": "m5", "from": {"userid": "amy"}, "msgtype": "voice", "voice": {"content": "語音轉文字"}})).unwrap();
        assert_eq!(voice.text, "語音轉文字");
        let file = p(json!({"msgid": "m6", "from": {"userid": "amy"}, "msgtype": "file", "file": {"url": "https://cdn/f", "aeskey": "k", "filename": "a.pdf"}})).unwrap();
        assert_eq!((file.media[0].kind, file.media[0].name.as_str()), (MediaKind::Document, "a.pdf"));
        let video = p(json!({"msgid": "m7", "from": {"userid": "amy"}, "msgtype": "video", "video": {"url": "https://cdn/v"}})).unwrap();
        assert_eq!(video.media[0].kind, MediaKind::Video);
        let app = p(json!({"msgid": "m8", "from": {"userid": "amy"}, "msgtype": "appmsg", "appmsg": {"title": "report.docx", "file": {"url": "https://cdn/d"}}})).unwrap();
        assert_eq!((app.text.as_str(), app.media[0].kind), ("report.docx", MediaKind::Document));
        let quoted = p(json!({"msgid": "m9", "from": {"userid": "amy"}, "msgtype": "text", "text": {"content": "agree"}, "quote": {"msgtype": "text", "text": {"content": "earlier"}}})).unwrap();
        let r = quoted.reply.unwrap();
        assert_eq!((r.id.as_str(), r.text.as_str(), quoted.text.as_str()), ("quote:m9", "earlier", "agree"));
        let quote_only = p(json!({"msgid": "m10", "from": {"userid": "amy"}, "msgtype": "text", "quote": {"msgtype": "text", "text": {"content": "just this"}}})).unwrap();
        assert_eq!((quote_only.text.as_str(), quote_only.reply.is_none()), ("just this", true));
        let inline = p(json!({"msgid": "m11", "from": {"userid": "amy"}, "msgtype": "image", "image": {"base64": "data:image/png;base64,aGk="}})).unwrap();
        assert_eq!(inline.media[0].url.as_deref(), Some("data:;base64,aGk="));
        assert!(p(json!({"msgid": "m12", "from": {"userid": "amy"}, "msgtype": "text", "text": {"content": "  "}})).is_none(), "empty");
        assert!(p(json!({"msgid": "m13", "from": {}, "msgtype": "text", "text": {"content": "x"}})).is_none(), "no chat");
        assert!(p(json!({"msgid": "m14", "from": {"userid": "BOT1"}, "msgtype": "text", "text": {"content": "echo"}})).is_none(), "own message");
        assert_eq!(p(json!({"from": {"userid": "amy"}, "msgtype": "text", "text": {"content": "x"}})).unwrap().message_id, "r1", "msgid falls back to req_id");
        // Events.
        let ev = |e: Value| parse_event("wc", &json!({"cmd": CMD_EVENT, "headers": {"req_id": "e1"}, "body": {"msgid": "ev1", "chatid": "G1", "chattype": "group", "from": {"userid": "amy"}, "msgtype": "event", "event": e}}));
        let cb = ev(json!({"eventtype": "template_card_event", "template_card_event": {"card_type": "button_interaction", "event_key": "appr:1:once", "task_id": "T1"}})).unwrap();
        assert_eq!((cb.callback.clone().unwrap(), cb.message_id.as_str(), cb.chat.as_str()), (Callback { id: "T1".into(), data: "appr:1:once".into() }, "cb:ev1", "G1"));
        assert!(ev(json!({"eventtype": "enter_chat"})).is_none());
        assert!(is_kick(&json!({"body": {"event_type": "disconnected_event"}})));
    }

    #[test]
    fn tolerates_raw_control_chars_in_json() {
        let v = parse_json("{\"a\": \"line1\nline2\"}").unwrap();
        assert_eq!(v["a"], "line1\nline2");
        assert!(parse_json("[1]").is_none() && parse_json("nope").is_none());
    }

    #[test]
    fn crypto_known_answers() {
        assert_eq!(ark_net::crypto::hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(ark_net::crypto::hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(ark_net::crypto::hex(&md5(&[b'a'; 1000])), "cabe45dcc9ae5b66ba86600cca6b8ba8");
        // Fixed vector (openssl enc -aes-256-cbc, key = 00..1f, iv = key[..16], PKCS#7 to 32).
        let cipher = ark_net::crypto::hex_decode("12dff1a19c59ce72334abdea8e4bfa73f67ca9fe121cf5aa3dfc1e5ed99ceb31").unwrap();
        let key_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(decrypt_media(&cipher, key_b64).unwrap(), b"hello wecom media");
        // Unpadded and percent-encoded, as WeCom sends it.
        let enc = ark_net::urlencode(key_b64.trim_end_matches('='));
        assert_eq!(decrypt_media(&cipher, &enc).unwrap(), b"hello wecom media");
        // Encrypt-then-decrypt with 16-byte PKCS#7 (as the upstream test does).
        let key: Vec<u8> = (100..132).collect();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&key[..16]);
        let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[0u8; 40]].concat();
        let c = ark_net::crypto::Aes::new(&key).unwrap().cbc_encrypt(&iv, &png);
        assert_eq!(decrypt_media(&c, &ark_net::crypto::b64(&key)).unwrap(), png);
        assert!(decrypt_media(&c, "c2hvcnQ").is_err(), "short key");
        assert!(decrypt_media(&c[..20], &ark_net::crypto::b64(&key)).is_err(), "bad length");
        assert!(decrypt_media(&[], key_b64).is_err());
    }

    #[test]
    fn subscribes_receives_and_replies_passively_then_proactively() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let w = wc(&srv.url);
        let _ = w.poll(&Cancel::new()).unwrap();
        let sub = srv.wait_for(CMD_SUBSCRIBE, 1);
        assert_eq!((sub[0]["body"]["bot_id"].as_str(), sub[0]["body"]["secret"].as_str()), (Some("BOT1"), Some("TOPSECRET")));
        assert_eq!(sub[0]["body"]["device_id"].as_str().unwrap().len(), 32);
        srv.push(text_cb("req-1", "msg-1", None, "amy", "hello"));
        let m = poll_one(&w);
        assert_eq!((m.chat.as_str(), m.text.as_str()), ("amy", "hello"));
        // Passive reply correlated to the inbound req_id.
        let s = w.send(&Outbound { reply_to: Some("msg-1".into()), ..Outbound::text("amy", "**hi**") }).unwrap();
        assert_eq!(s.ids, vec!["req-1"]);
        let r = &srv.frames(CMD_RESPOND)[0];
        assert_eq!((r["headers"]["req_id"].as_str(), r["body"]["msgtype"].as_str(), r["body"]["markdown"]["content"].as_str()), (Some("req-1"), Some("markdown"), Some("**hi**")));
        // Unknown DM: proactive send.
        w.send(&Outbound::text("bob", "ping")).unwrap();
        let p = &srv.frames(CMD_SEND)[0];
        assert_eq!((p["body"]["chatid"].as_str(), p["body"]["markdown"]["content"].as_str()), (Some("bob"), Some("ping")));
        assert!(p["headers"]["req_id"].as_str().unwrap().starts_with("aibot_send_msg-"));
        // Group: passive only.
        srv.push(text_cb("req-g", "msg-g", Some("G1"), "amy", "@Ark hi"));
        let g = poll_one(&w);
        assert!(g.mentioned && g.text == "hi");
        w.send(&Outbound::text("G1", "group reply")).unwrap();
        assert_eq!(srv.frames(CMD_RESPOND).last().unwrap()["headers"]["req_id"], "req-g");
        // Long text is chunked at 4000 chars.
        let long = "字".repeat(4500);
        assert_eq!(w.send(&Outbound::text("bob", &long)).unwrap().ids.len(), 2);
        let n = srv.frames(CMD_SEND).len();
        assert!(srv.frames(CMD_SEND)[n - 2]["body"]["markdown"]["content"].as_str().unwrap().chars().count() <= MAX_MESSAGE);
        w.stop();
    }

    #[test]
    fn group_without_req_id_and_passive_failure_fallback() {
        let srv = FakeWs::start(
            0,
            Arc::new(|v: &Value| match v["cmd"].as_str() {
                Some(CMD_RESPOND) => Some(ack(v, ERR_STREAM_EXPIRED, json!({}))),
                _ => default_responder(v),
            }),
        );
        let w = wc(&srv.url);
        w.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-1", "msg-1", None, "amy", "hello"));
        poll_one(&w);
        w.send(&Outbound::text("amy", "answer")).unwrap();
        assert_eq!(srv.frames(CMD_RESPOND).len(), 1);
        assert_eq!(srv.frames(CMD_SEND)[0]["body"]["chatid"], "amy", "fell back to proactive");
        // A group the bot saw (an empty callback still teaches us it is a group) with a req_id works, one without fails.
        w.inner.state.lock().unwrap().groups.insert("G9".into());
        let e = w.send(&Outbound::text("G9", "x")).unwrap_err();
        assert_eq!(e.kind, K::Protocol);
        assert_eq!(srv.frames(CMD_SEND).len(), 1, "nothing sent to the group");
    }

    #[test]
    fn errcodes_map_to_error_kinds() {
        let code = Arc::new(Mutex::new(0i64));
        let c2 = code.clone();
        let srv = FakeWs::start(0, Arc::new(move |v: &Value| if v["cmd"] == CMD_PING { None } else { Some(ack(v, *c2.lock().unwrap(), json!({}))) }));
        let w = wc(&srv.url);
        w.poll(&Cancel::new()).unwrap();
        for (c, kind) in [(ERR_RATE_LIMIT, K::RateLimited { retry_after: Some(Duration::from_secs(60)) }), (93006, K::NotFound), (40003, K::NotFound), (40014, K::Auth), (ERR_NOT_SUBSCRIBED, K::Network), (12345, K::Protocol)] {
            *code.lock().unwrap() = c;
            let e = w.send(&Outbound::text("bob", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "errcode {c}");
            assert!(!e.message.contains("TOPSECRET"));
        }
        // 846609 drops cached req_ids: the next send to a known chat goes proactive.
        *code.lock().unwrap() = 0;
        srv.push(text_cb("req-1", "msg-1", None, "amy", "hello"));
        poll_one(&w);
        *code.lock().unwrap() = ERR_NOT_SUBSCRIBED;
        let _ = w.send(&Outbound::text("amy", "x"));
        assert!(w.reply_req_id("amy", None).is_none());
        // No ack at all → Network after the request timeout.
        let srv2 = FakeWs::start(0, Arc::new(|_: &Value| None));
        let mut w2 = wc(&srv2.url);
        w2.opts.request_timeout = Duration::from_millis(300);
        let e = w2.send(&Outbound::text("bob", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network);
    }

    #[test]
    fn local_rate_limit_surfaces_retry_after() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let mut w = wc(&srv.url);
        w.opts.rate_per_min = 2;
        w.opts.max_wait = Duration::ZERO;
        w.send(&Outbound::text("bob", "1")).unwrap();
        w.send(&Outbound::text("bob", "2")).unwrap();
        let e = w.send(&Outbound::text("bob", "3")).unwrap_err();
        assert!(matches!(e.kind, K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(50)), "{e:?}");
        w.send(&Outbound::text("carl", "other chat has its own bucket")).unwrap();
    }

    #[test]
    fn bad_credentials_are_auth_errors() {
        let srv = FakeWs::start(40001, Arc::new(default_responder));
        let w = wc(&srv.url);
        let e = w.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("TOPSECRET"), "{}", e.message);
        assert_eq!(w.send(&Outbound::text("bob", "x")).unwrap_err().kind, K::Auth);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(srv.conns.load(Ordering::SeqCst), 1, "auth failures do not reconnect");
    }

    #[test]
    fn buttons_become_a_template_card() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let w = wc(&srv.url);
        let out = Outbound {
            buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("bob", "Run it?")
        };
        assert_eq!(w.send(&out).unwrap().ids.len(), 2);
        let f = srv.frames(CMD_SEND);
        assert_eq!(f[0]["body"]["markdown"]["content"], "Run it?\n\n[docs](https://e.com)");
        let card = &f[1]["body"]["template_card"];
        assert_eq!((f[1]["body"]["msgtype"].as_str(), card["card_type"].as_str()), (Some("template_card"), Some("button_interaction")));
        assert_eq!((card["button_list"][0]["text"].as_str(), card["button_list"][0]["key"].as_str()), (Some("允許"), Some("appr:x:once")));
        assert_eq!(card["button_list"].as_array().unwrap().len(), 1);
        // Pressing it arrives as a Callback.
        srv.push(json!({"cmd": CMD_EVENT, "headers": {"req_id": "ev-req"}, "body": {"msgid": "e1", "from": {"userid": "bob"}, "chattype": "single", "msgtype": "event", "event": {"eventtype": "template_card_event", "template_card_event": {"event_key": "appr:x:once", "task_id": card["task_id"]}}}}));
        let cb = poll_one(&w);
        assert_eq!(cb.callback.unwrap().data, "appr:x:once");
        assert_eq!(w.reply_req_id("bob", None).as_deref(), Some("ev-req"), "event req_id usable for the reply");
        w.ack_callback(&Callback::default(), None).unwrap();
    }

    #[test]
    fn media_uploads_in_chunks_then_sends() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let w = wc(&srv.url);
        let dir = crate::testutil::temp_dir("wecom");
        let f = dir.join("report.pdf");
        let data: Vec<u8> = (0..(CHUNK + 1000)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&f, &data).unwrap();
        let doc = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), caption: Some("the report".into()), ..Default::default() };
        let s = w.send(&Outbound { media: vec![doc], ..Outbound::text("bob", "") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let init = &srv.frames(CMD_UPLOAD_INIT)[0]["body"];
        assert_eq!((init["type"].as_str(), init["filename"].as_str(), init["total_size"].as_u64(), init["total_chunks"].as_u64()), (Some("file"), Some("report.pdf"), Some(data.len() as u64), Some(2)));
        assert_eq!(init["md5"].as_str().unwrap(), ark_net::crypto::hex(&md5(&data)));
        let chunks = srv.frames(CMD_UPLOAD_CHUNK);
        assert_eq!(chunks.iter().map(|c| c["body"]["chunk_index"].as_u64().unwrap()).collect::<Vec<_>>(), [0, 1]);
        let joined: Vec<u8> = chunks.iter().flat_map(|c| ark_net::crypto::b64_decode(c["body"]["base64_data"].as_str().unwrap()).unwrap()).collect();
        assert_eq!(joined, data);
        assert_eq!(srv.frames(CMD_UPLOAD_FINISH)[0]["body"]["upload_id"], "UP1");
        let sends = srv.frames(CMD_SEND);
        assert_eq!((sends[0]["body"]["msgtype"].as_str(), sends[0]["body"]["file"]["media_id"].as_str(), sends[0]["body"]["chatid"].as_str()), (Some("file"), Some("MEDIA1"), Some("bob")));
        assert_eq!(sends[1]["body"]["markdown"]["content"], "the report", "caption follows");
        // With a cached req_id an image goes as a passive reply; mp3 voice is downgraded to a file with a note.
        srv.push(text_cb("req-1", "msg-1", None, "amy", "send pic"));
        poll_one(&w);
        let png = dir.join("a.png");
        std::fs::write(&png, b"\x89PNG\r\n\x1a\nxxxx").unwrap();
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(png.display().to_string()), ..Default::default() }], ..Outbound::text("amy", "") }).unwrap();
        let r = srv.frames(CMD_RESPOND);
        assert_eq!((r[0]["headers"]["req_id"].as_str(), r[0]["body"]["msgtype"].as_str(), r[0]["body"]["image"]["media_id"].as_str()), (Some("req-1"), Some("image"), Some("MEDIA1")));
        let mp3 = dir.join("v.mp3");
        std::fs::write(&mp3, b"ID3xxxx").unwrap();
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(mp3.display().to_string()), ..Default::default() }], ..Outbound::text("bob", "") }).unwrap();
        assert_eq!(srv.frames(CMD_UPLOAD_INIT).last().unwrap()["body"]["type"], "file");
        assert!(srv.frames(CMD_SEND).last().unwrap()["body"]["markdown"]["content"].as_str().unwrap().contains("AMR"));
        // Size policy.
        assert!(size_verdict(FILE_MAX + 1, "file", "application/pdf").is_err());
        assert_eq!(size_verdict(IMAGE_MAX + 1, "image", "image/png").unwrap().0, "file");
        assert_eq!(size_verdict(100, "voice", "audio/amr").unwrap(), ("voice", None));
        assert_eq!(size_verdict(100, "video", "video/mp4").unwrap(), ("video", None));
        assert_eq!(wecom_type(&normalize_mime("", "clip.mp4")), "video");
        assert_eq!(wecom_type("application/ogg"), "voice");
    }

    #[test]
    fn native_stream_seed_intermediate_finalize() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let w = wc(&srv.url);
        assert!(!w.stream_frame("amy", None, "x", false).unwrap(), "no req_id yet → unavailable");
        w.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-1", "msg-1", None, "amy", "tell me"));
        poll_one(&w);
        assert!(w.stream_frame("amy", None, "", false).unwrap());
        srv.wait_for(CMD_RESPOND, 1);
        assert!(w.stream_frame("amy", None, "Hello", false).unwrap());
        srv.wait_for(CMD_RESPOND, 2);
        assert!(w.stream_frame("amy", None, "Hello", true).unwrap());
        let f = srv.frames(CMD_RESPOND);
        assert_eq!(f.len(), 3);
        assert_eq!((f[0]["body"]["stream"]["content"].as_str(), f[0]["body"]["stream"]["finish"].as_bool()), (Some(THINKING), Some(false)));
        assert_eq!(f[1]["body"]["stream"]["content"], "Hello");
        assert_eq!((f[2]["body"]["stream"]["content"].as_str(), f[2]["body"]["stream"]["finish"].as_bool()), (Some("Hello\u{200b}"), Some(true)), "final differs from the last frame");
        assert!(f.iter().all(|x| x["headers"]["req_id"] == "req-1" && x["body"]["stream"]["id"] == f[0]["body"]["stream"]["id"]));
        assert!(w.inner.state.lock().unwrap().turns.is_empty());
        // A stream older than the safe window is not finalized; the chat falls back to send().
        let mut w2 = wc(&srv.url);
        w2.opts.stream_safe = Duration::ZERO;
        w2.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-2", "msg-2", None, "amy", "again"));
        poll_one(&w2);
        assert!(!w2.stream_frame("amy", None, "done", true).unwrap());
        assert!(!w2.stream_frame("amy", None, "more", false).unwrap(), "expired chat");
        srv.push(text_cb("req-3", "msg-3", None, "amy", "new turn"));
        poll_one(&w2);
        assert!(w2.stream_frame("amy", None, "", false).unwrap(), "a fresh req_id revives streaming");
        assert_eq!(truncate_bytes("日本語", 4), "日");
    }

    #[test]
    fn stream_keepalive_refreshes_idle_turns_and_trait_wiring() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let mut w = wc(&srv.url);
        w.opts.keepalive = Some(Duration::from_millis(150));
        w.opts.stream_safe = Duration::ZERO;
        w.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-k", "msg-k", None, "amy", "long job"));
        poll_one(&w);
        let h = w.stream_begin(&Outbound::text("amy", "")).unwrap();
        assert_eq!(h.as_deref(), Some("amy"));
        w.stream_update("amy", "amy", "partial", "partial").unwrap();
        let f = srv.wait_for(CMD_RESPOND, 4);
        assert!(f.len() >= 4, "keep-alive frames while idle: {f:?}");
        assert!(f[2..].iter().all(|x| x["body"]["stream"]["content"] == "partial" && x["body"]["stream"]["finish"] == false && x["headers"]["req_id"] == "req-k"));
        // With keep-alive on, an "old" stream is still finalized (Layer 2 is off).
        w.stream_finish("amy", "amy", "partial done", "").unwrap();
        let last = srv.frames(CMD_RESPOND).last().unwrap().clone();
        assert_eq!((last["body"]["stream"]["content"].as_str(), last["body"]["stream"]["finish"].as_bool()), (Some("partial done"), Some(true)));
        let n = srv.frames(CMD_RESPOND).len();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(srv.frames(CMD_RESPOND).len(), n, "finished turns are not kept alive");
        // Without keep-alive, a declined finalize is delivered as a normal message.
        let mut w2 = wc(&srv.url);
        w2.opts.stream_safe = Duration::ZERO;
        w2.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-l", "msg-l", None, "amy", "again"));
        poll_one(&w2);
        w2.stream_begin(&Outbound::text("amy", "x")).unwrap();
        w2.stream_finish("amy", "amy", "final words", "").unwrap();
        let last = srv.frames(CMD_RESPOND).last().unwrap().clone();
        assert_eq!((last["body"]["msgtype"].as_str(), last["body"]["markdown"]["content"].as_str()), (Some("markdown"), Some("final words")));
    }

    #[test]
    fn approval_prompts_use_the_control_lane() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let mut w = wc(&srv.url);
        w.opts.rate_per_min = 5;
        w.opts.max_wait = Duration::ZERO;
        w.poll(&Cancel::new()).unwrap();
        srv.push(text_cb("req-a", "msg-a", None, "amy", "do it"));
        poll_one(&w);
        for i in 0..4 {
            w.send(&Outbound::text("amy", &format!("n{i}"))).unwrap();
        }
        assert!(matches!(w.send(&Outbound::text("amy", "n5")).unwrap_err().kind, K::RateLimited { .. }), "normal pool is 4 of 5");
        assert_eq!(srv.frames(CMD_RESPOND).len(), 4, "ordinary replies are passive");
        let b = crate::Button { label: "允許".into(), data: "appr:7:once".into(), url: None };
        let e = w.send(&Outbound { buttons: vec![vec![b.clone()]], ..Outbound::text("amy", "") }).unwrap();
        assert_eq!(e.ids.len(), 1);
        let sent = srv.wait_for(CMD_SEND, 1);
        assert_eq!(sent[0]["body"]["template_card"]["button_list"][0]["key"], "appr:7:once", "approval prompt went proactive on the reserved quota");
        assert_eq!(srv.frames(CMD_RESPOND).len(), 4, "the stream's req_id was not consumed");
        assert!(matches!(w.send(&Outbound { buttons: vec![vec![b]], ..Outbound::text("amy", "") }).unwrap_err().kind, K::RateLimited { .. }), "reserved pool is 1");
    }

    #[test]
    fn qr_setup_generate_and_poll() {
        let srv = crate::testutil::FakeServer::start(|r, n| {
            let body = if r.path.starts_with("/ai/qc/generate") {
                json!({"data": {"scode": "SC 1", "auth_url": "https://work.weixin.qq.com/x?a=1"}})
            } else if n < 2 {
                json!({"data": {"status": "waiting"}})
            } else {
                json!({"data": {"status": "success", "bot_info": {"botid": "aibXYZ", "secret": "S3"}}})
            };
            (200, vec![], body.to_string())
        });
        let q = qr_start(Some(&srv.url)).unwrap();
        assert_eq!((q.scode.as_str(), q.auth_url.as_str()), ("SC 1", "https://work.weixin.qq.com/x?a=1"));
        assert!(q.page_url.ends_with("/ai/qc/gen?source=ark&scode=SC%201"));
        assert_eq!(qr_poll(Some(&srv.url), &q.scode).unwrap(), None);
        assert_eq!(qr_poll(Some(&srv.url), &q.scode).unwrap(), Some(("aibXYZ".into(), "S3".into())));
        assert_eq!(srv.requests()[1].path, "/ai/qc/query_result?scode=SC%201");
        let bad = crate::testutil::FakeServer::start(|_, _| (200, vec![], json!({"data": {"status": "success", "bot_info": {}}}).to_string()));
        assert!(qr_poll(Some(&bad.url), "x").is_err());
        assert!(qr_start(Some(&bad.url)).is_err());
    }

    #[test]
    fn heartbeats_and_reconnect_after_dropped_socket() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let mut w = wc(&srv.url);
        w.opts.heartbeat = Duration::from_millis(100);
        w.poll(&Cancel::new()).unwrap();
        assert!(srv.wait_for(CMD_PING, 2).len() >= 2);
        srv.drop_conn();
        assert_eq!(srv.wait_for(CMD_SUBSCRIBE, 2).len(), 2, "resubscribed");
        assert_eq!(srv.conns.load(Ordering::SeqCst), 2);
        // The new connection delivers.
        let until = Instant::now() + Duration::from_secs(3);
        while !w.inner.connected.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        srv.push(text_cb("req-9", "msg-9", None, "amy", "after reconnect"));
        assert_eq!(poll_one(&w).text, "after reconnect");
        w.send(&Outbound::text("amy", "ok")).unwrap();
    }

    #[test]
    fn kicked_by_server_stops_reconnecting() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let w = wc(&srv.url);
        w.poll(&Cancel::new()).unwrap();
        srv.push(json!({"cmd": CMD_EVENT, "headers": {"req_id": "k"}, "body": {"event_type": "disconnected_event"}}));
        let e = w.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Fatal);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(srv.conns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancel_returns_promptly_and_unreachable_gateway_is_network() {
        let srv = FakeWs::start(0, Arc::new(default_responder));
        let mut w = wc(&srv.url);
        w.poll_timeout = 30;
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
        let mut dead = wc("ws://127.0.0.1:1");
        dead.opts.connect_timeout = Duration::from_millis(300);
        assert_eq!(dead.send(&Outbound::text("bob", "x")).unwrap_err().kind, K::Network);
        assert!(dead.poll(&Cancel::new().with_deadline(Instant::now() + Duration::from_millis(100))).unwrap().is_empty());
    }

    #[test]
    fn fetch_media_downloads_and_decrypts() {
        let key: Vec<u8> = (1..33).collect();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&key[..16]);
        let plain = b"secret image bytes".to_vec();
        let cipher = ark_net::crypto::Aes::new(&key).unwrap().cbc_encrypt(&iv, &plain);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/img", l.local_addr().unwrap());
        let body = cipher.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = ark_net::ws::read_head(&mut s, 65536);
                let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                out.extend_from_slice(&body);
                let _ = std::io::Write::write_all(&mut s, &out);
            }
        });
        let w = WeCom::new("wc", "B", "S", Some("ws://127.0.0.1:1"), 1).unwrap();
        let key_param = ark_net::urlencode(ark_net::crypto::b64(&key).trim_end_matches('='));
        let payload = callback("r", json!({"msgid": "m", "from": {"userid": "amy"}, "msgtype": "image", "image": {"url": url, "aeskey": key_param}}));
        let m = parse_callback("wc", "B", &payload).unwrap().media.remove(0);
        assert_eq!(w.fetch_media(&m).unwrap(), plain);
        assert_eq!(w.fetch_media(&Media { url: Some(url.clone()), ..Default::default() }).unwrap(), cipher, "no key: raw bytes");
        assert_eq!(w.fetch_media(&Media { url: Some("data:;base64,aGk=".into()), ..Default::default() }).unwrap(), b"hi");
        assert!(w.fetch_media(&Media { url: Some("file:///etc/passwd".into()), ..Default::default() }).is_err());
    }

    #[test]
    fn build_validates_settings() {
        let d = crate::testutil::temp_dir("wecom");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:WS}}", "sek"));
        let ctx = crate::config::Ctx { name: "wc", state_dir: &d, secrets: &secrets };
        let ok = json!({"bot_id": "B", "secret": "{{secret:WS}}", "websocket_url": "ws://127.0.0.1:1"});
        let c = build(&ctx, ok.as_object().unwrap()).unwrap();
        assert_eq!(c.id(), "wc");
        assert!(c.caps().buttons && c.caps().streaming == Streaming::Native && !c.caps().edit);
        assert!(build(&ctx, json!({"bot_id": "B", "secret": "{{secret:NOPE}}"}).as_object().unwrap()).err().unwrap().contains("not set"));
        assert!(build(&ctx, json!({"bot_id": "B", "secret": "x", "sekret": 1}).as_object().unwrap()).err().unwrap().contains("sekret"));
        assert!(build(&ctx, json!({"bot_id": "", "secret": "x"}).as_object().unwrap()).is_err());
    }
}
