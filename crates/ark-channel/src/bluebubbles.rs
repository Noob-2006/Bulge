//! iMessage through a BlueBubbles server (ported from Hermes
//! `plugins/platforms/bluebubbles`, MIT).
//!
//! Every REST call carries the server password as the `password` query
//! parameter (redacted from errors). Receive: a webhook we register with the
//! server at start (`GET`/`POST /api/v1/webhook`, events `new-message` and
//! `updated-message`) and that must present the password (`?password=` or an
//! `x-password` / `x-guid` header, constant-time). New messages (text,
//! attachments, group vs DM, `threadOriginatorGuid` replies) and edits
//! (`updated-message` with `dateEdited`); own messages, tapbacks and receipts are
//! dropped. Send: `POST /api/v1/message/text` (`chatGuid`, `tempGuid`,
//! `selectedMessageGuid` replies through the private API), multipart
//! `/api/v1/message/attachment`, `/api/v1/message/react`, `…/{guid}/edit`,
//! `…/{guid}/unsend`, `/api/v1/chat/{guid}/typing` and `/read`; new DMs via
//! `/api/v1/chat/new`. Downloads: `/api/v1/attachment/{guid}/download`.
//! Reply, typing, reactions, edit and unsend need BlueBubbles' private API
//! (`private_api = true`).

use crate::http::{classify, Http, Payload};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::httpd::{Opts, Response, Server};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 4000;
const EVENTS: [&str; 2] = ["new-message", "updated-message"];

fn kind_of(mime: &str, uti: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" if mime.contains("gif") => MediaKind::Animation,
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Voice,
        _ if uti.ends_with("caf") => MediaKind::Voice,
        _ => MediaKind::Document,
    }
}

/// Emoji → BlueBubbles reaction name.
fn reaction_name(emoji: &str) -> String {
    match emoji.trim_end_matches('\u{fe0f}') {
        "❤" | "♥" | "😍" | "love" => "love",
        "👍" | "like" => "like",
        "👎" | "dislike" => "dislike",
        "😂" | "🤣" | "😆" | "laugh" => "laugh",
        "‼" | "❗" | "!!" | "emphasize" => "emphasize",
        "❓" | "?" | "question" => "question",
        other => return other.to_string(),
    }
    .to_string()
}

fn first_str<'a>(cands: &[&'a Value]) -> Option<&'a str> {
    cands.iter().find_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty()))
}

pub struct BlueBubbles {
    id: String,
    server: String,
    password: String,
    private_api: bool,
    read_receipts: bool,
    mention: Vec<String>,
    poll_timeout: u64,
    http: Http,
    listener: Server,
    rx: Mutex<Receiver<Value>>,
    own: Mutex<VecDeque<String>>,
}

impl BlueBubbles {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}{}password={}", self.server, if path.contains('?') { '&' } else { '?' }, ark_net::urlencode(&self.password))
    }

    fn redact(&self, s: &str) -> String {
        let mut out = s.to_string();
        if !self.password.is_empty() {
            out = out.replace(&ark_net::urlencode(&self.password), "***").replace(&self.password, "***");
        }
        crate::sms::redact_phones_in(&out)
    }

    fn call(&self, method: &str, path: &str, body: Payload) -> Result<Value, ChannelError> {
        let r = self.http.call(method, &self.url(path), &[], body).map_err(|e| ChannelError::new(e.kind, self.redact(&e.message)))?;
        let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        let msg = self.redact(first_str(&[&v["error"]["message"], &v["message"], &v["error"]]).unwrap_or(""));
        let what = path.split('?').next().unwrap_or(path);
        if !(200..300).contains(&r.status) || v["status"].as_u64().is_some_and(|s| s >= 400) {
            let status = if (200..300).contains(&r.status) { v["status"].as_u64().unwrap_or(500) as u16 } else { r.status };
            let low = msg.to_ascii_lowercase();
            let mut e = classify(status, r.retry_after, what, "");
            if low.contains("does not exist") || low.contains("not found") {
                e.kind = K::NotFound;
            } else if low.contains("private api") {
                e.kind = K::Unsupported;
            }
            e.message = format!("bluebubbles {what}: HTTP {status} {msg}");
            return Err(e);
        }
        Ok(v)
    }

    fn remember(&self, v: &Value) -> String {
        let id = first_str(&[&v["data"]["guid"], &v["data"]["messageGuid"]]).unwrap_or("").to_string();
        if !id.is_empty() {
            let mut o = self.own.lock().unwrap();
            o.push_back(id.clone());
            while o.len() > 1000 {
                o.pop_front();
            }
        }
        id
    }

    /// A chat GUID: chats are GUIDs already; a bare address becomes its iMessage DM GUID.
    fn guid(chat: &str) -> String {
        if chat.contains(';') {
            chat.to_string()
        } else {
            format!("iMessage;-;{chat}")
        }
    }

    fn enc(s: &str) -> String {
        ark_net::urlencode(s)
    }

    fn inbound_of(&self, payload: &Value) -> Option<Inbound> {
        let ev = first_str(&[&payload["type"], &payload["event"]]).unwrap_or("");
        if !ev.is_empty() && !matches!(ev, "new-message" | "updated-message" | "message") {
            return None;
        }
        let rec = if payload["data"].is_object() {
            &payload["data"]
        } else if payload["data"].is_array() {
            &payload["data"][0]
        } else if payload["message"].is_object() {
            &payload["message"]
        } else {
            payload
        };
        if rec["isFromMe"] == true || rec["fromMe"] == true || rec["is_from_me"] == true {
            return None;
        }
        // Tapbacks arrive as messages with an associated type (2000-2005 add, 3000-3005 remove).
        if rec["associatedMessageType"].as_i64().is_some_and(|t| (2000..=3006).contains(&t)) {
            return None;
        }
        let edited_at = rec["dateEdited"].as_i64().filter(|d| *d > 0);
        if ev == "updated-message" && edited_at.is_none() {
            // Delivered / read / unsent updates.
            return None;
        }
        let chat = first_str(&[&rec["chats"][0]["guid"], &rec["chatGuid"], &payload["chatGuid"], &rec["chat_guid"]]).map(str::to_string);
        let sender = first_str(&[&rec["handle"]["address"], &rec["sender"], &rec["from"], &rec["address"]]).unwrap_or("").to_string();
        let chat = chat.or_else(|| first_str(&[&rec["chatIdentifier"], &rec["identifier"]]).map(str::to_string)).unwrap_or_else(|| sender.clone());
        if chat.is_empty() {
            return None;
        }
        let guid = first_str(&[&rec["guid"], &rec["messageGuid"]]).map(str::to_string).or_else(|| rec["id"].as_i64().map(|i| i.to_string()))?;
        let text = first_str(&[&rec["text"], &rec["message"], &rec["body"]]).unwrap_or("").to_string();
        let media: Vec<Media> = rec["attachments"].as_array().into_iter().flatten().filter_map(|a| {
            let g = a["guid"].as_str()?.to_string();
            let mime = a["mimeType"].as_str().unwrap_or("").to_lowercase();
            Some(Media { kind: kind_of(&mime, a["uti"].as_str().unwrap_or("")), name: a["transferName"].as_str().unwrap_or("").to_string(), mime, size: a["totalBytes"].as_u64().unwrap_or(0), id: Some(g), ..Default::default() })
        }).collect();
        if text.trim().is_empty() && media.is_empty() {
            return None;
        }
        let group = rec["isGroup"] == true || chat.contains(";+;") || rec["chats"][0]["participants"].as_array().is_some_and(|p| p.len() > 1);
        let low = text.to_lowercase();
        let reply = first_str(&[&rec["threadOriginatorGuid"], &rec["replyToGuid"]]).map(|r| ReplyRef { id: r.to_string(), is_own: self.own.lock().unwrap().iter().any(|o| o == r), ..Default::default() });
        Some(Inbound {
            channel: self.id.clone(),
            chat_type: if group { ChatType::Group } else { ChatType::Direct },
            chat_name: rec["chats"][0]["displayName"].as_str().unwrap_or("").to_string(),
            chat,
            sender_name: rec["handle"]["displayName"].as_str().unwrap_or("").to_string(),
            sender,
            mentioned: self.mention.iter().any(|n| !n.is_empty() && low.contains(&n.to_lowercase())),
            text,
            message_id: match edited_at {
                Some(d) => format!("{guid}:e{d}"),
                None => guid,
            },
            edited: edited_at.is_some(),
            ts: rec["dateCreated"].as_i64().map(|ms| ms / 1000).unwrap_or(0),
            media,
            reply,
            ..Default::default()
        })
    }

    fn send_text(&self, chat: &str, text: &str, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let mut p = json!({"chatGuid": Self::guid(chat), "tempGuid": crate::line::uuid4(), "message": text});
        if let (Some(r), true) = (reply_to, self.private_api) {
            p["method"] = json!("private-api");
            p["selectedMessageGuid"] = json!(r);
            p["partIndex"] = json!(0);
        }
        match self.call("POST", "/api/v1/message/text", Payload::Json(&p)) {
            Ok(v) => Ok(self.remember(&v)),
            // A DM that does not exist yet: create it with this message (private API).
            Err(e) if e.kind == K::NotFound && !chat.contains(';') && self.private_api => {
                let v = self.call("POST", "/api/v1/chat/new", Payload::Json(&json!({"addresses": [chat], "message": text, "tempGuid": crate::line::uuid4()})))?;
                Ok(self.remember(&v))
            }
            Err(e) => Err(e),
        }
    }

    fn send_attachment(&self, chat: &str, m: &Media, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let (data, name) = match (&m.path, &m.url) {
            (Some(p), _) => (std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?, crate::line::file_name(p)),
            (None, Some(u)) => (crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?, u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let name = if m.name.is_empty() { name } else { m.name.clone() };
        let mime = if m.mime.is_empty() { crate::line::guess_mime(&name).to_string() } else { m.mime.clone() };
        let (guid, temp) = (Self::guid(chat), crate::line::uuid4());
        let mut parts: Vec<(&str, &str, &str, &[u8])> = vec![("chatGuid", "", "", guid.as_bytes()), ("name", "", "", name.as_bytes()), ("tempGuid", "", "", temp.as_bytes())];
        if m.kind == MediaKind::Voice {
            parts.push(("isAudioMessage", "", "", b"true"));
        }
        if let (Some(r), true) = (reply_to, self.private_api) {
            parts.push(("method", "", "", b"private-api"));
            parts.push(("selectedMessageGuid", "", "", r.as_bytes()));
        }
        parts.push(("attachment", &name, &mime, &data));
        let v = self.call("POST", "/api/v1/message/attachment", Payload::Multipart(&parts))?;
        Ok(self.remember(&v))
    }

    fn need_private(&self, what: &str) -> Result<(), ChannelError> {
        if self.private_api {
            Ok(())
        } else {
            Err(ChannelError::new(K::Unsupported, format!("bluebubbles {what} needs the private API (set private_api = true)")))
        }
    }

    /// Mark a chat read (private API).
    pub fn mark_read(&self, chat: &str) -> Result<(), ChannelError> {
        self.need_private("read receipts")?;
        self.call("POST", &format!("/api/v1/chat/{}/read", Self::enc(&Self::guid(chat))), Payload::None).map(|_| ())
    }

    /// `GET /api/v1/ping`.
    pub fn ping(&self) -> Result<(), ChannelError> {
        self.call("GET", "/api/v1/ping", Payload::None).map(|_| ())
    }

    /// Register `url` for new/updated messages unless the server already has it.
    pub fn register_webhook(&self, url: &str) -> Result<(), ChannelError> {
        let list = self.call("GET", "/api/v1/webhook", Payload::None)?;
        if list["data"].as_array().into_iter().flatten().any(|w| w["url"].as_str() == Some(url)) {
            return Ok(());
        }
        self.call("POST", "/api/v1/webhook", Payload::Json(&json!({"url": url, "events": EVENTS}))).map(|_| ())
    }
}

impl Channel for BlueBubbles {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        let p = self.private_api;
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: p,
            threads: false,
            reactions: if p { 1 } else { 0 },
            edit: p,
            delete: p,
            typing: p,
            buttons: false,
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
        let out: Vec<Inbound> = got.iter().filter_map(|p| self.inbound_of(p)).collect();
        if self.read_receipts && self.private_api {
            for i in out.iter().filter(|i| !i.edited) {
                let _ = self.mark_read(&i.chat);
            }
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut text = match out.format {
            TextFormat::Markdown => crate::markup::convert(&out.text, Markup::Plain),
            TextFormat::Plain => out.text.clone(),
        };
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let mut sent = Sent::default();
        let mut reply = out.reply_to.as_deref();
        for m in &out.media {
            sent.ids.push(self.send_attachment(&out.chat, m, reply.take())?);
        }
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            sent.ids.push(self.send_text(&out.chat, &piece, reply.take())?);
        }
        Ok(sent)
    }

    fn edit(&self, _chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.need_private("edit")?;
        let t = crate::markup::convert(text, Markup::Plain);
        self.call("POST", &format!("/api/v1/message/{}/edit", Self::enc(message_id)), Payload::Json(&json!({"editedMessage": t, "backwardsCompatibilityMessage": t, "partIndex": 0}))).map(|_| ())
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.need_private("unsend")?;
        self.call("POST", &format!("/api/v1/message/{}/unsend", Self::enc(message_id)), Payload::Json(&json!({"partIndex": 0}))).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        self.need_private("typing")?;
        self.call("POST", &format!("/api/v1/chat/{}/typing", Self::enc(&Self::guid(chat))), Payload::None).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        self.need_private("reactions")?;
        let name = reaction_name(emoji);
        let reaction = if remove { format!("-{name}") } else { name };
        self.call("POST", "/api/v1/message/react", Payload::Json(&json!({"chatGuid": Self::guid(chat), "selectedMessageGuid": message_id, "reaction": reaction, "partIndex": 0}))).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let g = m.id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "bluebubbles attachment without guid"))?;
        crate::http::get_bytes(&self.url(&format!("/api/v1/attachment/{}/download", Self::enc(g))), &[], 100 * 1024 * 1024).map_err(|e| ChannelError::new(e.kind, self.redact(&e.message)))
    }
}

fn d_path() -> String {
    "/bluebubbles-webhook".into()
}
fn d_poll() -> u64 {
    25
}
fn d_true() -> bool {
    true
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// BlueBubbles server, e.g. `http://192.168.1.10:1234`.
    pub server_url: String,
    pub password: String,
    /// Local address of our webhook listener.
    pub listen: String,
    #[serde(default = "d_path")]
    pub webhook_path: String,
    /// URL the server should post to (default `http://<listen><webhook_path>`).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Register the webhook with the server at start.
    #[serde(default = "d_true")]
    pub register_webhook: bool,
    /// The server has the private API helper (replies, typing, reactions, edit, unsend).
    #[serde(default)]
    pub private_api: bool,
    #[serde(default)]
    pub read_receipts: bool,
    /// Words that count as mentioning the bot in groups (case-insensitive).
    #[serde(default)]
    pub mention_names: Vec<String>,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl BlueBubbles {
    /// `st.password` already resolved.
    pub fn open(id: &str, st: &Settings) -> Result<BlueBubbles, String> {
        if st.server_url.trim().is_empty() || st.password.is_empty() {
            return Err(format!("channel {id}: bluebubbles needs server_url and password"));
        }
        let (tx, rx) = channel::<Value>();
        let tx = Mutex::new(tx);
        let (path, pw) = (st.webhook_path.clone(), st.password.clone());
        let handler: ark_net::httpd::Handler = Arc::new(move |r: ark_net::httpd::Request| {
            if r.path != path {
                return Response::text(404, "not found");
            }
            if r.method != "POST" {
                return Response::text(405, "method not allowed");
            }
            let token = r.query("password").or_else(|| r.query("guid")).or_else(|| r.header("x-password")).or_else(|| r.header("x-guid")).or_else(|| r.header("x-bluebubbles-guid"));
            if !token.is_some_and(|t| ark_net::crypto::ct_eq(t.as_bytes(), pw.as_bytes())) {
                return Response::new(401, "application/json", r#"{"error":"unauthorized"}"#);
            }
            // JSON, or a form with a JSON `payload` / `data` field.
            let v = serde_json::from_slice::<Value>(&r.body).ok().or_else(|| {
                let f = ark_net::parse_query(r.body_str());
                f.into_iter().find(|(k, _)| matches!(k.as_str(), "payload" | "data" | "message")).and_then(|(_, v)| serde_json::from_str(&v).ok())
            });
            match v {
                Some(v) => {
                    let _ = tx.lock().unwrap().send(v);
                    Response::new(200, "application/json", r#"{"status":"ok"}"#)
                }
                None => Response::new(400, "application/json", r#"{"error":"invalid payload"}"#),
            }
        });
        let listener = Server::bind(&st.listen, Opts { max_body: 1024 * 1024, ..Opts::default() }, handler).map_err(|e| format!("channel {id}: cannot listen on {}: {e}", st.listen))?;
        let bb = BlueBubbles {
            id: id.to_string(),
            server: st.server_url.trim().trim_end_matches('/').to_string(),
            password: st.password.clone(),
            private_api: st.private_api,
            read_receipts: st.read_receipts,
            mention: st.mention_names.clone(),
            poll_timeout: st.poll_timeout_secs,
            http: Http::new(Duration::from_secs(120)),
            listener,
            rx: Mutex::new(rx),
            own: Mutex::default(),
        };
        if st.register_webhook {
            let base = st.webhook_url.clone().unwrap_or_else(|| {
                let a = bb.local_addr();
                let host = if a.ip().is_unspecified() { "localhost".to_string() } else { a.ip().to_string() };
                format!("http://{host}:{}{}", a.port(), st.webhook_path)
            });
            let url = format!("{base}{}password={}", if base.contains('?') { '&' } else { '?' }, ark_net::urlencode(&st.password));
            bb.register_webhook(&url).map_err(|e| format!("channel {id}: registering the BlueBubbles webhook failed: {}", e.message))?;
        }
        Ok(bb)
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let mut st: Settings = ctx.settings(s)?;
    st.password = ctx.secret("password", &st.password)?;
    Ok(Arc::new(BlueBubbles::open(ctx.name, &st)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    const PW: &str = "s3cr&t";

    fn ok_server() -> FakeServer {
        FakeServer::start(|req, n| {
            if req.path.starts_with("/api/v1/webhook") && req.method == "GET" {
                return (200, vec![], json!({"status": 200, "data": []}).to_string());
            }
            if req.path.starts_with("/api/v1/attachment/") {
                return (200, vec![], "ATT".into());
            }
            (200, vec![], json!({"status": 200, "message": "Success", "data": {"guid": format!("OUT-{n}")}}).to_string())
        })
    }

    fn bb(url: &str, private_api: bool) -> BlueBubbles {
        let st: Settings = serde_json::from_value(json!({"server_url": url, "password": PW, "listen": "127.0.0.1:0", "private_api": private_api, "mention_names": ["@ark"], "poll_timeout_secs": 1, "register_webhook": false})).unwrap();
        BlueBubbles::open("bb", &st).unwrap()
    }

    fn post(b: &BlueBubbles, q: &str, header: Option<&str>, body: &str) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{}/bluebubbles-webhook{q}", b.local_addr())).header("content-type", "application/json");
        if let Some(h) = header {
            r = r.header("x-password", h);
        }
        r.send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn msg(data: Value) -> String {
        json!({"type": "new-message", "data": data}).to_string()
    }

    #[test]
    fn webhook_auth_and_registration() {
        let srv = ok_server();
        let b = bb(&srv.url, false);
        let body = msg(json!({"guid": "M1", "text": "hi", "handle": {"address": "+886912345678"}, "chats": [{"guid": "iMessage;-;+886912345678"}], "dateCreated": 1700000000000i64}));
        let q = format!("?password={}", ark_net::urlencode(PW));
        assert_eq!(post(&b, "", None, &body), 401, "missing");
        assert_eq!(post(&b, "?password=nope", None, &body), 401, "bad");
        assert_eq!(post(&b, "", Some("nope"), &body), 401, "bad header");
        assert!(b.poll(&Cancel::new()).unwrap().is_empty());
        assert_eq!(post(&b, &q, None, &body), 200);
        assert_eq!(post(&b, "", Some(PW), &body.replace("M1", "M2")), 200, "header form");
        assert_eq!(post(&b, &q, None, "not json"), 400);
        assert_eq!(b.poll(&Cancel::new()).unwrap().len(), 2);
        // Registration: listed first, registered once with the password in the URL.
        let st: Settings = serde_json::from_value(json!({"server_url": srv.url, "password": PW, "listen": "127.0.0.1:0", "webhook_url": "http://ark.lan:8645/bluebubbles-webhook"})).unwrap();
        BlueBubbles::open("bb", &st).unwrap();
        let reqs = srv.requests();
        assert_eq!((reqs[0].method.as_str(), reqs[0].path.as_str()), ("GET", format!("/api/v1/webhook?password={}", ark_net::urlencode(PW)).as_str()));
        assert_eq!(reqs[1].json(), json!({"url": format!("http://ark.lan:8645/bluebubbles-webhook?password={}", ark_net::urlencode(PW)), "events": ["new-message", "updated-message"]}));
        let srv2 = FakeServer::start(|_, _| (200, vec![], json!({"status": 200, "data": [{"id": 1, "url": "http://h/x?password=s3cr%26t"}]}).to_string()));
        let st: Settings = serde_json::from_value(json!({"server_url": srv2.url, "password": PW, "listen": "127.0.0.1:0", "webhook_url": "http://h/x"})).unwrap();
        BlueBubbles::open("bb", &st).unwrap();
        assert_eq!(srv2.requests().len(), 1, "already registered");
    }

    #[test]
    fn parses_messages_edits_and_drops_noise() {
        let srv = ok_server();
        let b = bb(&srv.url, true);
        let q = format!("?password={}", ark_net::urlencode(PW));
        let own = b.send(&Outbound::text("iMessage;+;chat9", "q?")).unwrap().ids[0].clone();
        for body in [
            msg(json!({"guid": "M1", "text": "hi", "handle": {"address": "+886912345678", "displayName": "Amy"}, "chats": [{"guid": "iMessage;-;+886912345678"}], "dateCreated": 1700000000000i64})),
            msg(json!({"guid": "M2", "text": "@Ark run", "handle": {"address": "bob@x.com"}, "chats": [{"guid": "iMessage;+;chat9", "displayName": "Team", "participants": [{}, {}]}], "isGroup": true})),
            msg(json!({"guid": "M3", "text": "", "handle": {"address": "bob@x.com"}, "chats": [{"guid": "iMessage;+;chat9"}], "attachments": [{"guid": "A1", "mimeType": "image/jpeg", "transferName": "p.jpg", "totalBytes": 3}]})),
            msg(json!({"guid": "M4", "text": "yes", "handle": {"address": "bob@x.com"}, "chats": [{"guid": "iMessage;+;chat9"}], "threadOriginatorGuid": own})),
            msg(json!({"guid": "M5", "text": "mine", "isFromMe": true, "chats": [{"guid": "iMessage;+;chat9"}]})),
            msg(json!({"guid": "M6", "text": "Loved “q?”", "associatedMessageType": 2000, "handle": {"address": "bob@x.com"}, "chats": [{"guid": "iMessage;+;chat9"}]})),
            json!({"type": "updated-message", "data": {"guid": "M1", "text": "hi!", "dateEdited": 1700000005000i64, "handle": {"address": "+886912345678"}, "chats": [{"guid": "iMessage;-;+886912345678"}]}}).to_string(),
            json!({"type": "updated-message", "data": {"guid": "M1", "text": "hi!", "dateDelivered": 1, "handle": {"address": "+886912345678"}, "chats": [{"guid": "iMessage;-;+886912345678"}]}}).to_string(),
            json!({"type": "typing-indicator", "data": {"display": true}}).to_string(),
        ] {
            assert_eq!(post(&b, &q, None, &body), 200);
        }
        let g = b.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 5, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].chat_type, g[0].ts), ("iMessage;-;+886912345678", "+886912345678", "Amy", ChatType::Direct, 1700000000));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group && g[1].chat_name == "Team");
        assert_eq!((g[2].media[0].id.as_deref(), g[2].media[0].kind), (Some("A1"), MediaKind::Image));
        assert_eq!(b.fetch_media(&g[2].media[0]).unwrap(), b"ATT");
        assert!(srv.requests().last().unwrap().path.starts_with("/api/v1/attachment/A1/download?password="));
        assert!(g[3].reply.as_ref().unwrap().is_own);
        assert!(g[4].edited && g[4].message_id == "M1:e1700000005000" && g[4].text == "hi!");
    }

    #[test]
    fn send_shapes_and_private_api_actions() {
        let srv = ok_server();
        let b = bb(&srv.url, true);
        b.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("M1".into()), ..Outbound::text("iMessage;-;+886912345678", "**hi**") }).unwrap();
        let r = srv.requests()[0].clone();
        assert_eq!(r.path, format!("/api/v1/message/text?password={}", ark_net::urlencode(PW)));
        let j = r.json();
        assert_eq!((j["chatGuid"].as_str(), j["message"].as_str(), j["method"].as_str(), j["selectedMessageGuid"].as_str(), j["partIndex"].as_i64()), (Some("iMessage;-;+886912345678"), Some("hi"), Some("private-api"), Some("M1"), Some(0)));
        assert_eq!(j["tempGuid"].as_str().unwrap().len(), 36);
        let f = temp_dir("bb").join("v.caf");
        std::fs::write(&f, b"CAF").unwrap();
        b.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("+886912345678", "") }).unwrap();
        let r = srv.requests()[1].clone();
        assert!(r.path.starts_with("/api/v1/message/attachment?password="));
        assert!(r.body.contains("name=\"chatGuid\"\r\n\r\niMessage;-;+886912345678") && r.body.contains("name=\"isAudioMessage\"") && r.body.contains("filename=\"v.caf\"") && r.body.contains("CAF"), "{}", r.body);
        b.react("iMessage;+;chat9", "M2", "😂", false).unwrap();
        b.react("iMessage;+;chat9", "M2", "😂", true).unwrap();
        b.edit("iMessage;+;chat9", "OUT-1", "fixed").unwrap();
        b.delete("iMessage;+;chat9", "OUT-1").unwrap();
        b.typing("iMessage;+;chat9", None).unwrap();
        b.mark_read("iMessage;+;chat9").unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[2].json(), json!({"chatGuid": "iMessage;+;chat9", "selectedMessageGuid": "M2", "reaction": "laugh", "partIndex": 0}));
        assert_eq!(reqs[3].json()["reaction"], "-laugh");
        assert!(reqs[4].path.starts_with("/api/v1/message/OUT-1/edit?") && reqs[4].json()["editedMessage"] == "fixed");
        assert!(reqs[5].path.starts_with("/api/v1/message/OUT-1/unsend?"));
        assert!(reqs[6].path.starts_with("/api/v1/chat/iMessage%3B%2B%3Bchat9/typing?"));
        assert!(reqs[7].path.starts_with("/api/v1/chat/iMessage%3B%2B%3Bchat9/read?"));
        // Without the private API: plain sends, no reply metadata, honest caps.
        let plain = bb(&srv.url, false);
        plain.send(&Outbound { reply_to: Some("M1".into()), ..Outbound::text("iMessage;-;x", "hey") }).unwrap();
        assert!(srv.requests().last().unwrap().json().get("selectedMessageGuid").is_none());
        assert_eq!(plain.typing("iMessage;-;x", None).unwrap_err().kind, K::Unsupported);
        assert!(!plain.caps().reply && plain.caps().reactions == 0 && b.caps().edit);
    }

    #[test]
    fn errors_are_classified_and_password_redacted() {
        for (status, body, kind) in [
            (401, json!({"status": 401, "message": "Unauthorized", "error": {"message": "password s3cr&t rejected"}}), K::Auth),
            (400, json!({"status": 400, "message": "Chat does not exist"}), K::NotFound),
            (500, json!({"status": 500, "message": "iMessage is not signed in"}), K::Network),
            (200, json!({"status": 500, "message": "Failed to send: private API helper not connected"}), K::Unsupported),
        ] {
            let srv = FakeServer::start(move |_, _| (status, vec![], body.to_string()));
            let e = bb(&srv.url, false).send(&Outbound::text("iMessage;-;x", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains(PW) && !e.message.contains("s3cr%26t"), "{}", e.message);
        }
        let e = bb("http://127.0.0.1:1", false).send(&Outbound::text("iMessage;-;x", "x")).unwrap_err();
        assert!(e.kind == K::Network && !e.message.contains("s3cr"), "{}", e.message);
        // A DM without a chat yet is created through chat/new (private API).
        let srv = FakeServer::start(|req, _| if req.path.starts_with("/api/v1/message/text") { (400, vec![], json!({"status": 400, "message": "Chat does not exist"}).to_string()) } else { (200, vec![], json!({"status": 200, "data": {"guid": "NEW"}}).to_string()) });
        assert_eq!(bb(&srv.url, true).send(&Outbound::text("+886912345678", "hi")).unwrap().ids, vec!["NEW"]);
        assert_eq!(srv.requests()[1].json()["addresses"], json!(["+886912345678"]));
    }

    #[test]
    fn cancel_returns_promptly() {
        let b = bb("http://127.0.0.1:1", false);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(b.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
    }
}
