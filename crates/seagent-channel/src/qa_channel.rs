//! qa-channel: a synthetic channel for tests and demos (shapes mirror OpenClaw's
//! `qa-channel` bus protocol, MIT).
//!
//! Inbound, from either source:
//! - `inbox`: a JSONL file tailed from the last read offset (offset persisted in
//!   `<name>.qa-channel.json`, so a restart does not replay);
//! - `listen` (loopback only) + `token`: `POST /v1/inbound` with
//!   `Authorization: Bearer <token>` and one message or an array.
//!
//! A line/body is a `QaBusInboundMessageInput`
//! (`{"conversation":{"id","kind":"direct|group|channel","title"},"senderId","senderName","text",
//!   "threadId","replyToId","attachments":[{"id","kind","mimeType","fileName","url","contentBase64"}],
//!   "nativeCommand":{"name"}}`), optionally wrapped as `{"kind":"inbound-message","message":{…}}`,
//! with seagent extensions `id`, `mentioned`, `isBot`, `edited`, `callback:{id,data}`.
//! A control line `{"kind":"fail","op":"send","error":"rate_limited","retryAfterSecs":2,"count":1}`
//! makes the next `count` calls of `op` (or `*`) fail with that error kind, so host retry,
//! auth and not-found paths can be exercised. `POST /v1/fail` takes the same body.
//!
//! Outbound: every operation (send, edit, delete, typing, react, ack_callback,
//! fetch_media) is appended to the `outbox` JSONL as a QaBusEvent-like record
//! `{"cursor","kind":"outbound-message|message-edited|message-deleted|typing|reaction-added|
//! reaction-removed|callback-acked|media-fetched","accountId","message":{…}}` and kept in memory
//! (`GET /v1/outbox?after=<cursor>`). Targets use the qa grammar: `dm:<id>`, `group:<id>`,
//! `channel:<id>`, `thread:<conv>/<thread>`; a bare id is a DM.
//! `GET /health` needs no auth. Caps advertise everything so host features run end to end.

use crate::{write_atomic, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use seagent_core::Cancel;
use seagent_net::httpd::{Opts, Request, Response, Server};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    op: String,
    kind: K,
    count: u32,
    message: String,
}

fn parse_failure(v: &Value) -> Result<Failure, String> {
    let ra = v["retryAfterSecs"].as_f64().or_else(|| v["retry_after_secs"].as_f64()).map(Duration::from_secs_f64);
    let kind = match v["error"].as_str().unwrap_or("network") {
        "auth" => K::Auth,
        "rate_limited" | "rate_limit" => K::RateLimited { retry_after: ra },
        "network" => K::Network,
        "protocol" => K::Protocol,
        "fatal" => K::Fatal,
        "unsupported" => K::Unsupported,
        "not_found" => K::NotFound,
        other => return Err(format!("unknown error kind `{other}`")),
    };
    Ok(Failure { op: v["op"].as_str().unwrap_or("*").to_string(), kind, count: v["count"].as_u64().unwrap_or(1) as u32, message: v["message"].as_str().unwrap_or("injected failure").to_string() })
}

struct State {
    cursor: u64,
    events: Vec<Value>,
    failures: Vec<Failure>,
    /// Ids of messages we sent (for `reply.is_own`).
    own: HashSet<String>,
    /// Inline attachment bytes by attachment id (`contentBase64`).
    blobs: HashMap<String, Vec<u8>>,
    next_id: u64,
}

struct Shared {
    account: String,
    bot_id: String,
    bot_name: String,
    outbox: PathBuf,
    st: Mutex<State>,
}

pub struct QaChannel {
    id: String,
    shared: Arc<Shared>,
    inbox: Option<PathBuf>,
    offset_file: PathBuf,
    offset: Mutex<u64>,
    poll_timeout: u64,
    max_len: usize,
    rx: Mutex<Receiver<Value>>,
    tx: Sender<Value>,
    _server: Option<Server>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `dm:x` / `group:x` / `channel:x` / `thread:conv/thread` → (kind, conversation, thread).
fn parse_target(raw: &str) -> Result<(&'static str, String, Option<String>), ChannelError> {
    let t = raw.trim();
    let bad = || ChannelError::new(K::Fatal, format!("invalid qa-channel target: {raw}"));
    if t.is_empty() {
        return Err(bad());
    }
    match t.split_once(':') {
        Some(("thread", rest)) => {
            let rest = rest.trim();
            if let Some(v) = rest.strip_prefix("/v1/") {
                let p: Vec<&str> = v.split('/').collect();
                if p.len() != 3 || !(p[0] == "dm" || p[0] == "group") || p[1].is_empty() || p[2].is_empty() {
                    return Err(bad());
                }
                return Ok((if p[0] == "dm" { "direct" } else { "group" }, seagent_net::urldecode(p[1]), Some(seagent_net::urldecode(p[2]))));
            }
            let (c, th) = rest.split_once('/').ok_or_else(bad)?;
            if c.trim().is_empty() || th.trim().is_empty() || th.contains('/') {
                return Err(bad());
            }
            Ok(("channel", c.trim().into(), Some(th.trim().into())))
        }
        Some(("dm", r)) if !r.trim().is_empty() => Ok(("direct", r.trim().into(), None)),
        Some(("group", r)) if !r.trim().is_empty() => Ok(("group", r.trim().into(), None)),
        Some(("channel", r)) if !r.trim().is_empty() => Ok(("channel", r.trim().into(), None)),
        Some((p, _)) if ["dm", "group", "channel", "thread"].contains(&p.to_ascii_lowercase().as_str()) => Err(bad()),
        _ => Ok(("direct", t.into(), None)),
    }
}

fn target_of(kind: &str, conv: &str) -> String {
    format!("{}:{conv}", if kind == "direct" { "dm" } else { kind })
}

fn media_kind(k: &str, mime: &str) -> MediaKind {
    match k {
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" if mime.contains("ogg") => MediaKind::Voice,
        "audio" => MediaKind::Audio,
        _ => MediaKind::Document,
    }
}

fn kind_name(k: MediaKind) -> &'static str {
    match k {
        MediaKind::Image | MediaKind::Sticker | MediaKind::Animation => "image",
        MediaKind::Video => "video",
        MediaKind::Audio | MediaKind::Voice => "audio",
        MediaKind::Document => "file",
    }
}

impl Shared {
    /// Record one event in memory and the outbox file.
    fn record(&self, kind: &str, message: Value, extra: Value) -> u64 {
        let mut st = self.st.lock().unwrap();
        st.cursor += 1;
        let mut ev = json!({"cursor": st.cursor, "kind": kind, "accountId": self.account, "timestamp": now(), "message": message});
        if let Some(o) = extra.as_object() {
            for (k, v) in o {
                ev[k] = v.clone();
            }
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.outbox) {
            let _ = writeln!(f, "{ev}");
        }
        st.events.push(ev);
        st.cursor
    }

    /// Consume an injected failure for `op`, if any.
    fn check(&self, op: &str) -> Result<(), ChannelError> {
        let mut st = self.st.lock().unwrap();
        let Some(i) = st.failures.iter().position(|f| f.op == op || f.op == "*") else { return Ok(()) };
        let f = st.failures[i].clone();
        if f.count <= 1 {
            st.failures.remove(i);
        } else {
            st.failures[i].count -= 1;
        }
        Err(ChannelError::new(f.kind, format!("qa-channel {op}: {}", f.message)))
    }

    fn inject_failure(&self, v: &Value) -> Result<(), String> {
        let f = parse_failure(v)?;
        self.st.lock().unwrap().failures.push(f);
        Ok(())
    }

    fn new_id(&self, prefix: &str) -> String {
        let mut st = self.st.lock().unwrap();
        st.next_id += 1;
        format!("{prefix}-{}-{}", st.next_id, now())
    }

    /// QaBus inbound input → Inbound. `fallback_id` keeps file redeliveries stable.
    fn inbound_of(&self, channel: &str, v: &Value, fallback_id: &str) -> Option<Inbound> {
        let m = if v["kind"] == "inbound-message" { &v["message"] } else { v };
        let sender = m["senderId"].as_str().unwrap_or("").to_string();
        if sender.is_empty() || sender == self.bot_id {
            return None;
        }
        let conv = m["conversation"]["id"].as_str()?.to_string();
        let kind = m["conversation"]["kind"].as_str().unwrap_or("direct");
        let text = m["text"].as_str().unwrap_or("").to_string();
        let mut media = Vec::new();
        for a in m["attachments"].as_array().into_iter().flatten() {
            let id = a["id"].as_str().map(str::to_string).unwrap_or_else(|| self.new_id("att"));
            if let Some(b) = a["contentBase64"].as_str().and_then(seagent_net::crypto::b64_decode) {
                self.st.lock().unwrap().blobs.insert(id.clone(), b);
            }
            let mime = a["mimeType"].as_str().unwrap_or("").to_string();
            media.push(Media { kind: media_kind(a["kind"].as_str().unwrap_or("file"), &mime), id: Some(id), url: a["url"].as_str().map(str::to_string), name: a["fileName"].as_str().unwrap_or("").into(), mime, caption: a["altText"].as_str().map(str::to_string), ..Default::default() });
        }
        let callback = m["callback"].as_object().map(|c| Callback { id: c.get("id").and_then(Value::as_str).unwrap_or("").into(), data: c.get("data").and_then(Value::as_str).unwrap_or("").into() });
        if text.is_empty() && media.is_empty() && callback.is_none() && m["nativeCommand"].is_null() {
            return None;
        }
        let text = match (&text[..], m["nativeCommand"]["name"].as_str()) {
            ("", Some(cmd)) => format!("/{}", cmd.trim_start_matches('/')),
            _ => text,
        };
        let lower = text.to_lowercase();
        let mentioned = m["mentioned"].as_bool().unwrap_or_else(|| [&self.bot_id, &self.bot_name].iter().any(|h| !h.is_empty() && lower.contains(&format!("@{}", h.to_lowercase()))));
        let reply = m["replyToId"].as_str().map(|r| ReplyRef { id: r.into(), is_own: self.st.lock().unwrap().own.contains(r), ..Default::default() });
        let thread = m["threadId"].as_str().filter(|t| !t.is_empty()).map(str::to_string);
        let chat_type = match (kind, &thread) {
            ("direct", _) => ChatType::Direct,
            (_, Some(_)) => ChatType::Thread,
            ("channel", _) => ChatType::Channel,
            _ => ChatType::Group,
        };
        let ts = m["timestamp"].as_i64().map(|t| if t > 100_000_000_000 { t / 1000 } else { t }).unwrap_or(now() / 1000);
        Some(Inbound {
            channel: channel.into(),
            account: self.account.clone(),
            chat: target_of(kind, &conv),
            chat_type,
            chat_name: m["conversation"]["title"].as_str().unwrap_or("").into(),
            thread,
            sender_name: m["senderName"].as_str().unwrap_or("").into(),
            sender,
            is_bot: m["isBot"] == true,
            message_id: m["id"].as_str().map(str::to_string).or_else(|| callback.as_ref().map(|c| format!("cb:{}", c.id))).unwrap_or_else(|| fallback_id.to_string()),
            ts,
            text,
            media,
            mentioned,
            reply,
            callback,
            edited: m["edited"] == true,
        })
    }
}

impl QaChannel {
    /// `outbox` receives every outbound operation; `inbox` (optional) is tailed for input.
    pub fn new(id: &str, outbox: PathBuf, inbox: Option<PathBuf>, offset_file: PathBuf, poll_timeout_secs: u64) -> QaChannel {
        let (tx, rx) = channel();
        let offset = std::fs::read_to_string(&offset_file).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| v["offset"].as_u64()).unwrap_or(0);
        if let Some(d) = outbox.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        QaChannel {
            id: id.into(),
            shared: Arc::new(Shared {
                account: id.into(),
                bot_id: "seagent".into(),
                bot_name: "seagent".into(),
                outbox,
                st: Mutex::new(State { cursor: 0, events: vec![], failures: vec![], own: HashSet::new(), blobs: HashMap::new(), next_id: 0 }),
            }),
            inbox,
            offset_file,
            offset: Mutex::new(offset),
            poll_timeout: poll_timeout_secs,
            max_len: 4000,
            rx: Mutex::new(rx),
            tx,
            _server: None,
        }
    }

    pub fn with_bot(mut self, id: &str, name: &str) -> Self {
        let s = Arc::get_mut(&mut self.shared).expect("configure before listen");
        s.bot_id = id.into();
        s.bot_name = name.into();
        self
    }

    /// Queue failures up front (same shape as the `fail` control record).
    pub fn with_failures(self, fails: &[Value]) -> Result<Self, String> {
        for f in fails {
            self.shared.inject_failure(f)?;
        }
        Ok(self)
    }

    /// Loopback HTTP injection. Non-loopback addresses are refused.
    pub fn with_listener(mut self, listen: &str, token: &str) -> Result<Self, String> {
        let host = listen.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])).unwrap_or("");
        if !(host == "localhost" || host == "::1" || host.starts_with("127.")) {
            return Err(format!("channel {}: qa-channel listen must be a loopback address", self.id));
        }
        if token.len() < 8 {
            return Err(format!("channel {}: qa-channel token must be at least 8 characters", self.id));
        }
        let (tx, shared, want) = (Mutex::new(self.tx.clone()), self.shared.clone(), token.to_string());
        let handler: seagent_net::httpd::Handler = Arc::new(move |r: Request| {
            if r.method == "GET" && r.path == "/health" {
                return Response::new(200, "application/json", json!({"ok": true}).to_string());
            }
            if !r.bearer().is_some_and(|t| seagent_net::crypto::ct_eq(t.as_bytes(), want.as_bytes())) {
                return Response::text(401, "unauthorized");
            }
            match (r.method.as_str(), r.path.as_str()) {
                ("POST", "/v1/inbound") => {
                    let Ok(v) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
                    let items = match v {
                        Value::Array(a) => a,
                        v => vec![v],
                    };
                    let tx = tx.lock().unwrap();
                    for it in &items {
                        if it["conversation"]["id"].as_str().is_none() && it["message"]["conversation"]["id"].as_str().is_none() {
                            return Response::text(400, "conversation.id is required");
                        }
                    }
                    let n = items.len();
                    for it in items {
                        let _ = tx.send(it);
                    }
                    Response::new(200, "application/json", json!({"accepted": n}).to_string())
                }
                ("POST", "/v1/fail") => match serde_json::from_slice::<Value>(&r.body).map_err(|e| e.to_string()).and_then(|v| shared.inject_failure(&v)) {
                    Ok(()) => Response::new(200, "application/json", "{\"ok\":true}"),
                    Err(e) => Response::text(400, &e),
                },
                ("GET", "/v1/outbox") => {
                    let after: u64 = r.query("after").and_then(|a| a.parse().ok()).unwrap_or(0);
                    let st = shared.st.lock().unwrap();
                    let evs: Vec<&Value> = st.events.iter().filter(|e| e["cursor"].as_u64().unwrap_or(0) > after).collect();
                    Response::new(200, "application/json", json!({"cursor": st.cursor, "events": evs}).to_string())
                }
                _ => Response::text(404, "not found"),
            }
        });
        let server = Server::bind(listen, Opts::default(), handler).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.id))?;
        self._server = Some(server);
        Ok(self)
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self._server.as_ref().map(|s| s.local_addr())
    }

    /// Everything recorded so far (tests and demos).
    pub fn outbox(&self) -> Vec<Value> {
        self.shared.st.lock().unwrap().events.clone()
    }

    /// New complete lines from the inbox file: (value, byte offset) pairs.
    fn read_inbox(&self) -> Vec<(Value, u64)> {
        let Some(p) = &self.inbox else { return vec![] };
        let mut off = self.offset.lock().unwrap();
        let Ok(mut f) = std::fs::File::open(p) else { return vec![] };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < *off {
            // Truncated / rotated: start over.
            *off = 0;
        }
        if len == *off || f.seek(SeekFrom::Start(*off)).is_err() {
            return vec![];
        }
        let mut buf = Vec::new();
        let _ = f.take(16 * 1024 * 1024).read_to_end(&mut buf);
        let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') else { return vec![] };
        let mut out = Vec::new();
        let mut pos = *off;
        for line in buf[..=last_nl].split(|b| *b == b'\n') {
            let start = pos;
            pos += line.len() as u64 + 1;
            let l = String::from_utf8_lossy(line);
            if l.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(l.trim()) {
                Ok(v) => out.push((v, start)),
                Err(_) => {
                    self.shared.record("inbox-error", json!({"line": l.trim(), "offset": start}), json!({}));
                }
            }
        }
        *off += last_nl as u64 + 1;
        let _ = write_atomic(&self.offset_file, json!({"offset": *off}).to_string().as_bytes());
        out
    }

    fn handle(&self, v: Value, fallback: String) -> Option<Inbound> {
        if v["kind"] == "fail" {
            let _ = self.shared.inject_failure(&v);
            return None;
        }
        self.shared.inbound_of(&self.id, &v, &fallback)
    }

    fn message(&self, chat: &str, thread: Option<&str>, id: &str, text: &str) -> Result<Value, ChannelError> {
        let (kind, conv, t) = parse_target(chat)?;
        let thread = thread.map(str::to_string).or(t);
        let mut m = json!({"id": id, "accountId": self.shared.account, "direction": "outbound", "conversation": {"id": conv, "kind": kind}, "senderId": self.shared.bot_id, "senderName": self.shared.bot_name, "text": text, "timestamp": now(), "reactions": []});
        if let Some(t) = thread {
            m["threadId"] = json!(t);
        }
        Ok(m)
    }
}

impl Channel for QaChannel {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Channel, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 8,
            edit: true,
            delete: true,
            typing: true,
            buttons: true,
            polls: true,
            native_commands: true,
            streaming: Streaming::Edit,
            max_len: self.max_len,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.shared.check("poll")?;
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let rx = self.rx.lock().unwrap();
        loop {
            let mut got = Vec::new();
            for (v, off) in self.read_inbox() {
                got.extend(self.handle(v, format!("inbox:{off}")));
            }
            for v in rx.try_iter() {
                let id = self.shared.new_id("in");
                got.extend(self.handle(v, id));
            }
            if !got.is_empty() || cancel.is_cancelled() || Instant::now() >= until {
                return Ok(got);
            }
            if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                let id = self.shared.new_id("in");
                got.extend(self.handle(v, id));
                if !got.is_empty() {
                    return Ok(got);
                }
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        self.shared.check("send")?;
        let pieces = crate::chunk::split(&out.text, self.max_len, LenUnit::Chars);
        let n = pieces.len().max(usize::from(!out.media.is_empty()));
        let mut sent = Sent::default();
        for i in 0..n {
            let id = self.shared.new_id("out");
            let mut m = self.message(&out.chat, out.thread.as_deref(), &id, pieces.get(i).map(String::as_str).unwrap_or(""))?;
            if i == 0 {
                if let Some(r) = &out.reply_to {
                    m["replyToId"] = json!(r);
                }
                if !out.media.is_empty() {
                    m["attachments"] = Value::Array(
                        out.media
                            .iter()
                            .enumerate()
                            .map(|(j, md)| {
                                let size = md.path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|x| x.len()).unwrap_or(md.size);
                                json!({"id": format!("{id}-a{j}"), "kind": kind_name(md.kind), "mimeType": md.mime, "fileName": md.name, "path": md.path, "url": md.url, "byteSize": size, "caption": md.caption})
                            })
                            .collect(),
                    );
                }
            }
            if i + 1 == n && !out.buttons.is_empty() {
                m["buttons"] = json!(out.buttons);
            }
            m["format"] = json!(out.format);
            m["silent"] = json!(out.silent);
            self.shared.record("outbound-message", m, json!({}));
            self.shared.st.lock().unwrap().own.insert(id.clone());
            sent.ids.push(id);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.shared.check("edit")?;
        if !self.shared.st.lock().unwrap().own.contains(message_id) {
            return Err(ChannelError::new(K::NotFound, format!("qa-channel edit: unknown message {message_id}")));
        }
        let mut m = self.message(chat, None, message_id, text)?;
        m["editedAt"] = json!(now());
        self.shared.record("message-edited", m, json!({}));
        Ok(())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.shared.check("delete")?;
        if !self.shared.st.lock().unwrap().own.remove(message_id) {
            return Err(ChannelError::new(K::NotFound, format!("qa-channel delete: unknown message {message_id}")));
        }
        let mut m = self.message(chat, None, message_id, "")?;
        m["deleted"] = json!(true);
        self.shared.record("message-deleted", m, json!({}));
        Ok(())
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        self.shared.check("typing")?;
        let m = self.message(chat, thread, "", "")?;
        self.shared.record("typing", m, json!({}));
        Ok(())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        self.shared.check("react")?;
        let m = self.message(chat, None, message_id, "")?;
        self.shared.record(if remove { "reaction-removed" } else { "reaction-added" }, m, json!({"emoji": emoji, "senderId": self.shared.bot_id}));
        Ok(())
    }

    fn ack_callback(&self, cb: &Callback, text: Option<&str>) -> Result<(), ChannelError> {
        self.shared.check("ack_callback")?;
        self.shared.record("callback-acked", json!({"id": cb.id, "data": cb.data, "text": text}), json!({}));
        Ok(())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        self.shared.check("fetch_media")?;
        let blob = m.id.as_ref().and_then(|id| self.shared.st.lock().unwrap().blobs.get(id).cloned());
        let bytes = match (blob, m.url.as_deref(), m.path.as_deref()) {
            (Some(b), _, _) => b,
            (None, Some(u), _) if u.starts_with("file://") => std::fs::read(&u[7..]).map_err(|e| ChannelError::new(K::NotFound, format!("qa-channel media {u}: {e}")))?,
            (None, Some(u), _) => crate::http::get_bytes(u, &[], 50 * 1024 * 1024)?,
            (None, None, Some(p)) => std::fs::read(p).map_err(|e| ChannelError::new(K::NotFound, format!("qa-channel media {p}: {e}")))?,
            _ => return Err(ChannelError::new(K::NotFound, "qa-channel attachment has no content")),
        };
        self.shared.record("media-fetched", json!({"id": m.id, "url": m.url, "byteSize": bytes.len()}), json!({}));
        Ok(bytes)
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    inbox: Option<String>,
    #[serde(default)]
    outbox: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    bot_user_id: Option<String>,
    #[serde(default)]
    bot_display_name: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default)]
    max_len: Option<usize>,
    /// Failures queued at start: `[{op, error, retryAfterSecs, count, message}]`.
    #[serde(default)]
    fail: Vec<Value>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let outbox = st.outbox.map(PathBuf::from).unwrap_or_else(|| ctx.state("qa-outbox.jsonl"));
    let mut q = QaChannel::new(ctx.name, outbox, st.inbox.map(PathBuf::from), ctx.state("qa-channel.json"), st.poll_timeout_secs);
    let bot_id = st.bot_user_id.unwrap_or_else(|| "seagent".into());
    let bot_name = st.bot_display_name.unwrap_or_else(|| bot_id.clone());
    q = q.with_bot(&bot_id, &bot_name).with_failures(&st.fail).map_err(|e| format!("channel {}: fail: {e}", ctx.name))?;
    if let Some(m) = st.max_len {
        q.max_len = m.max(16);
    }
    if let Some(l) = &st.listen {
        let tok = ctx.opt_secret("token", &st.token)?.ok_or_else(|| format!("channel {}: qa-channel listen needs token", ctx.name))?;
        q = q.with_listener(l, &tok)?;
    } else if q.inbox.is_none() {
        return Err(format!("channel {}: qa-channel needs `inbox` and/or `listen`", ctx.name));
    }
    Ok(Arc::new(q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use crate::http::agent;

    fn qa(dir: &std::path::Path) -> QaChannel {
        QaChannel::new("qa", dir.join("out.jsonl"), Some(dir.join("in.jsonl")), dir.join("off.json"), 1).with_bot("seagent", "Seagent")
    }

    fn append(p: &std::path::Path, lines: &[Value]) {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    #[test]
    fn inbox_parses_every_kind_and_persists_offset() {
        let d = temp_dir("qa");
        let q = qa(&d);
        let sent = q.send(&Outbound::text("group:g1", "earlier")).unwrap();
        append(&d.join("in.jsonl"), &[
            json!({"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "senderName": "Amy", "text": "hi", "timestamp": 1700000000000i64}),
            json!({"kind": "inbound-message", "message": {"id": "m2", "conversation": {"id": "g1", "kind": "group", "title": "Team"}, "senderId": "u2", "text": "hey @seagent", "threadId": "t1"}}),
            json!({"conversation": {"id": "g1", "kind": "group"}, "senderId": "u2", "text": "re", "replyToId": sent.ids[0]}),
            json!({"conversation": {"id": "c1", "kind": "channel"}, "senderId": "u3", "text": "", "attachments": [{"id": "a1", "kind": "image", "mimeType": "image/png", "fileName": "x.png", "contentBase64": seagent_net::crypto::b64(b"PNG")}]}),
            json!({"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "fixed", "id": "m1", "edited": true}),
            json!({"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "", "callback": {"id": "cb1", "data": "appr:1:once"}}),
            json!({"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "", "nativeCommand": {"name": "status"}}),
            json!({"conversation": {"id": "g1", "kind": "group"}, "senderId": "seagent", "text": "own echo"}),
            json!({"conversation": {"id": "g1", "kind": "group"}, "senderId": "bot9", "isBot": true, "text": "beep"}),
        ]);
        std::fs::OpenOptions::new().append(true).open(d.join("in.jsonl")).unwrap().write_all(b"not json\n{\"partial\":").unwrap();
        let g = q.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 8, "own message dropped: {g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender_name.as_str(), g[0].ts), ("dm:u1", ChatType::Direct, "Amy", 1700000000));
        assert_eq!(g[0].message_id, "inbox:0", "stable id from file offset");
        assert_eq!((g[1].chat.as_str(), g[1].thread.as_deref(), g[1].chat_type, g[1].chat_name.as_str(), g[1].message_id.as_str()), ("group:g1", Some("t1"), ChatType::Thread, "Team", "m2"));
        assert!(g[1].mentioned);
        assert!(g[2].reply.as_ref().unwrap().is_own && g[2].addressed());
        assert_eq!((g[3].chat_type, g[3].media[0].kind), (ChatType::Channel, MediaKind::Image));
        assert_eq!(q.fetch_media(&g[3].media[0]).unwrap(), b"PNG");
        assert!(g[4].edited);
        assert_eq!(g[5].callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(g[6].text, "/status");
        assert!(g[7].is_bot);
        assert!(q.outbox().iter().any(|e| e["kind"] == "inbox-error"), "bad line reported, partial line kept");
        // Restart: nothing replayed; the completed partial line arrives.
        let q2 = qa(&d);
        std::fs::OpenOptions::new().append(true).open(d.join("in.jsonl")).unwrap().write_all(b"\"x\"}\n").unwrap();
        append(&d.join("in.jsonl"), &[json!({"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "after restart"})]);
        let g = q2.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].text, "after restart");
    }

    #[test]
    fn outbox_records_every_operation() {
        let d = temp_dir("qa");
        let q = qa(&d);
        let out = Outbound {
            reply_to: Some("in-1".into()),
            buttons: vec![vec![crate::Button { label: "OK".into(), data: "ok".into(), url: None }]],
            media: vec![Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() }],
            silent: true,
            format: crate::TextFormat::Markdown,
            ..Outbound::text("thread:c1/t9", "**hi**")
        };
        let s = q.send(&out).unwrap();
        q.edit("thread:c1/t9", &s.ids[0], "edited").unwrap();
        q.typing("dm:u1", Some("t2")).unwrap();
        q.react("group:g1", &s.ids[0], "👍", false).unwrap();
        q.react("group:g1", &s.ids[0], "👍", true).unwrap();
        q.ack_callback(&Callback { id: "cb".into(), data: "d".into() }, Some("done")).unwrap();
        q.delete("thread:c1/t9", &s.ids[0]).unwrap();
        assert_eq!(q.edit("dm:u1", &s.ids[0], "x").unwrap_err().kind, K::NotFound, "deleted");
        let lines: Vec<Value> = std::fs::read_to_string(d.join("out.jsonl")).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let kinds: Vec<&str> = lines.iter().map(|l| l["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["outbound-message", "message-edited", "typing", "reaction-added", "reaction-removed", "callback-acked", "message-deleted"]);
        let m = &lines[0]["message"];
        assert_eq!((m["conversation"]["id"].as_str(), m["conversation"]["kind"].as_str(), m["threadId"].as_str(), m["replyToId"].as_str()), (Some("c1"), Some("channel"), Some("t9"), Some("in-1")));
        assert_eq!((m["format"].as_str(), m["silent"].as_bool(), m["buttons"][0][0]["data"].as_str(), m["attachments"][0]["url"].as_str()), (Some("markdown"), Some(true), Some("ok"), Some("https://e.com/a.png")));
        assert_eq!(lines[1]["message"]["text"], "edited");
        assert_eq!(lines[2]["message"]["threadId"], "t2");
        assert_eq!(lines[3]["emoji"], "👍");
        assert_eq!(lines.iter().map(|l| l["cursor"].as_u64().unwrap()).collect::<Vec<_>>(), (1..=7).collect::<Vec<_>>());
        let mut q = qa(&d);
        q.max_len = 50;
        assert!(q.send(&Outbound::text("dm:u", &"word ".repeat(40))).unwrap().ids.len() >= 4, "split at max_len");
        assert!(q.outbox().iter().all(|e| e["message"]["text"].as_str().unwrap().chars().count() <= 50));
        assert!(q.send(&Outbound::text("thread:nope", "x")).is_err());
        assert!(q.send(&Outbound::text("DM:x", "x")).is_err(), "prefixes are lowercase");
        assert!(q.caps().edit && q.caps().buttons && q.caps().polls && q.caps().reactions > 1);
    }

    #[test]
    fn failure_injection_drives_host_error_paths() {
        let d = temp_dir("qa");
        let q = qa(&d).with_failures(&[json!({"op": "send", "error": "rate_limited", "retryAfterSecs": 2, "count": 2})]).unwrap();
        for _ in 0..2 {
            assert_eq!(q.send(&Outbound::text("dm:u", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(2)) });
        }
        assert!(q.send(&Outbound::text("dm:u", "x")).is_ok(), "count consumed");
        append(&d.join("in.jsonl"), &[json!({"kind": "fail", "op": "*", "error": "auth"})]);
        assert!(q.poll(&Cancel::new()).unwrap().is_empty());
        assert_eq!(q.typing("dm:u", None).unwrap_err().kind, K::Auth);
        assert!(q.typing("dm:u", None).is_ok());
        assert!(qa(&d).with_failures(&[json!({"error": "gremlins"})]).is_err());
    }

    #[test]
    fn http_inject_requires_bearer_and_feeds_poll() {
        let d = temp_dir("qa");
        assert!(QaChannel::new("qa", d.join("o"), None, d.join("f"), 1).with_listener("0.0.0.0:0", "tok-tok-tok").is_err(), "loopback only");
        let q = QaChannel::new("qa", d.join("o"), None, d.join("f"), 1).with_listener("127.0.0.1:0", "tok-tok-tok").unwrap();
        let base = format!("http://{}", q.local_addr().unwrap());
        let a = agent(Duration::from_secs(5));
        let post = |path: &str, auth: Option<&str>, body: &str| {
            let mut r = a.post(&format!("{base}{path}"));
            if let Some(t) = auth {
                r = r.header("authorization", &format!("Bearer {t}"));
            }
            r.send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
        };
        let body = json!([{"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "one"}, {"conversation": {"id": "u1", "kind": "direct"}, "senderId": "u1", "text": "two"}]).to_string();
        assert_eq!(post("/v1/inbound", None, &body), 401, "missing");
        assert_eq!(post("/v1/inbound", Some("wrong"), &body), 401, "bad");
        assert_eq!(post("/v1/inbound", Some("tok-tok-tok"), "{oops"), 400);
        assert_eq!(post("/v1/inbound", Some("tok-tok-tok"), "{\"text\":\"no conv\"}"), 400);
        assert_eq!(post("/v1/inbound", Some("tok-tok-tok"), &body), 200, "good");
        let g = q.poll(&Cancel::new()).unwrap();
        assert_eq!(g.iter().map(|i| i.text.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        assert_ne!(g[0].message_id, g[1].message_id);
        assert_eq!(post("/v1/fail", Some("tok-tok-tok"), &json!({"op": "edit", "error": "not_found"}).to_string()), 200);
        q.send(&Outbound::text("dm:u1", "reply")).unwrap();
        let id = q.outbox()[0]["message"]["id"].as_str().unwrap().to_string();
        assert_eq!(q.edit("dm:u1", &id, "x").unwrap_err().kind, K::NotFound);
        let r = a.get(&format!("{base}/v1/outbox?after=0")).header("authorization", "Bearer tok-tok-tok").call().unwrap().body_mut().read_to_string().unwrap();
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["events"][0]["message"]["text"], "reply");
        assert_eq!(a.get(&format!("{base}/health")).call().unwrap().status().as_u16(), 200);
        assert_eq!(a.get(&format!("{base}/v1/outbox")).call().unwrap().status().as_u16(), 401);
    }

    #[test]
    fn cancel_returns_promptly_and_build_validates() {
        let d = temp_dir("qa");
        let q = QaChannel::new("qa", d.join("o"), Some(d.join("in")), d.join("f"), 30);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(q.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "qa", state_dir: &d, secrets: &secrets };
        assert!(build(&ctx, json!({}).as_object().unwrap()).err().unwrap().contains("inbox"));
        assert!(build(&ctx, json!({"listen": "127.0.0.1:0"}).as_object().unwrap()).err().unwrap().contains("token"));
        assert!(build(&ctx, json!({"inbox": d.join("i").display().to_string(), "fail": [{"op": "send", "error": "network"}]}).as_object().unwrap()).is_ok());
        assert!(build(&ctx, json!({"inbox": "x", "inboxx": 1}).as_object().unwrap()).is_err());
    }
}
