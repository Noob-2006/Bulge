//! WhatsApp Business Cloud API (ported from Hermes `plugins/platforms/whatsapp_cloud`, MIT).
//!
//! Receive: webhook. `GET ?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…`
//! handshake (constant-time token compare); `POST` bodies must carry
//! `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(app secret, raw body)>`, checked
//! before parsing. Only `entry[].changes[field=messages]` for our phone number id
//! (and WABA id when configured) are used: text, image, video, audio/voice,
//! document, sticker, location, contacts, interactive `button_reply` /
//! `list_reply` and template `button` taps (→ `Callback`), `context.id` replies.
//! `statuses` receipts and inbound reactions are ignored.
//! Send: Graph `/{phone_number_id}/messages` — text (`preview_url`), reply
//! `context`, interactive reply buttons (≤3), lists (≤10), a CTA URL button,
//! media by `link` or uploaded `/media` id, reactions; typing indicator + read
//! receipt for the latest inbound message. Error 131047 (outside the 24-hour
//! customer-service window) is reported plainly.

use crate::http::{classify, Http, Payload};
use crate::{markup, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::httpd::{Opts, Response, Server};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_GRAPH: &str = "https://graph.facebook.com";
pub const DEFAULT_API_VERSION: &str = "v20.0";
pub const MAX_MESSAGE: usize = 4096;

/// CommonMark → WhatsApp's own markup (`*bold*`, `_italic_`, `~strike~`, ```` ``` ````);
/// links become `label (url)` since WhatsApp only auto-links bare URLs.
pub(crate) fn to_whatsapp(md: &str) -> String {
    let s = markup::convert(md, Markup::SlackMrkdwn);
    // Slack links `<url|label>` / `<url>` → plain.
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(i) = rest.find("<http") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('>') {
            Some(j) => {
                let inner = &tail[..j];
                match inner.split_once('|') {
                    Some((url, label)) if label != url => out.push_str(&format!("{label} ({url})")),
                    Some((url, _)) => out.push_str(url),
                    None => out.push_str(inner),
                }
                rest = &tail[j + 1..];
            }
            None => {
                out.push('<');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

pub(crate) fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// `sha256=<hex>` HMAC of the raw body keyed by the app secret, constant-time.
pub fn verify_signature(app_secret: &str, body: &[u8], header: Option<&str>) -> bool {
    let Some(hex) = header.and_then(|h| h.trim().strip_prefix("sha256=")).map(|h| h.trim().to_ascii_lowercase()) else { return false };
    if app_secret.is_empty() || hex.is_empty() {
        return false;
    }
    let want = ark_net::crypto::hex(&ark_net::crypto::hmac_sha256(app_secret.as_bytes(), body));
    ark_net::crypto::ct_eq(want.as_bytes(), hex.as_bytes())
}

/// Graph `{error: {message, code, error_subcode, error_data}}` → classified error.
fn graph_err(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let e = &v["error"];
    let code = e["code"].as_i64().unwrap_or(0);
    let msg = e["message"].as_str().unwrap_or("");
    let detail = e["error_data"]["details"].as_str().unwrap_or("");
    let text = format!("{what}: graph error {code} (HTTP {status}): {msg} {detail}").trim().to_string();
    let kind = match code {
        131047 => return ChannelError::new(K::Protocol, format!("{what}: more than 24 hours since the user last wrote (error 131047): WhatsApp only allows approved template messages until they write again")),
        190 | 10 | 200 | 102 => K::Auth,
        4 | 80007 | 130429 | 131056 | 131048 => K::RateLimited { retry_after },
        131026 | 131030 | 131021 => K::NotFound,
        133010 => K::Fatal,
        1 | 2 | 131000 | 131016 => K::Network,
        _ if code != 0 => match status {
            401 | 403 => K::Auth,
            429 => K::RateLimited { retry_after },
            s if s >= 500 => K::Network,
            404 => K::NotFound,
            _ => K::Protocol,
        },
        _ => return classify(status, retry_after, what, body),
    };
    ChannelError::new(kind, text)
}

fn media_kind(t: &str) -> Option<MediaKind> {
    Some(match t {
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Audio,
        "voice" => MediaKind::Voice,
        "document" => MediaKind::Document,
        "sticker" => MediaKind::Sticker,
        _ => return None,
    })
}

/// One `messages[]` entry → Inbound. `names` = wa_id → profile name; `own` = our sent wamids.
fn inbound_of(channel: &str, m: &Value, names: &HashMap<String, String>, our_number: &str, own: &VecDeque<String>) -> Option<Inbound> {
    let from = m["from"].as_str()?.to_string();
    let id = m["id"].as_str()?.to_string();
    // Group-shaped messages are not part of the 1:1 Cloud API contract; drop like Hermes.
    if m.get("group_id").is_some() || m.get("chat").is_some() || (!our_number.is_empty() && digits(&from) == digits(our_number)) {
        return None;
    }
    let t = m["type"].as_str().unwrap_or("text");
    let mut callback = None;
    let mut media = Vec::new();
    let text = match t {
        "text" => m["text"]["body"].as_str().unwrap_or("").to_string(),
        "interactive" => {
            let inner = if m["interactive"]["button_reply"].is_object() { &m["interactive"]["button_reply"] } else { &m["interactive"]["list_reply"] };
            callback = Some(Callback { id: id.clone(), data: inner["id"].as_str().unwrap_or("").to_string() });
            inner["title"].as_str().unwrap_or("").to_string()
        }
        "button" => {
            callback = Some(Callback { id: id.clone(), data: m["button"]["payload"].as_str().unwrap_or("").to_string() });
            m["button"]["text"].as_str().unwrap_or("").to_string()
        }
        "location" => {
            let l = &m["location"];
            let label: Vec<&str> = [l["name"].as_str(), l["address"].as_str()].into_iter().flatten().filter(|s| !s.is_empty()).collect();
            format!("[location: {}{}({}, {})]", label.join(" "), if label.is_empty() { "" } else { " " }, l["latitude"], l["longitude"])
        }
        "contacts" => {
            let names: Vec<&str> = m["contacts"].as_array().into_iter().flatten().filter_map(|c| c["name"]["formatted_name"].as_str()).collect();
            format!("[contact: {}]", names.join(", "))
        }
        k => {
            // reaction, system, unsupported, unknown, ephemeral, order… → None.
            let kind = media_kind(k)?;
            let b = &m[k];
            let kind = if kind == MediaKind::Audio && b["voice"] == true { MediaKind::Voice } else { kind };
            let mime = b["mime_type"].as_str().unwrap_or("").split(';').next().unwrap_or("").trim().to_string();
            media.push(Media { kind, id: b["id"].as_str().map(str::to_string), name: b["filename"].as_str().unwrap_or("").to_string(), mime, caption: b["caption"].as_str().map(str::to_string), ..Default::default() });
            b["caption"].as_str().unwrap_or("").to_string()
        }
    };
    if text.is_empty() && media.is_empty() && callback.is_none() {
        return None;
    }
    let ctx = &m["context"];
    let reply = ctx["id"].as_str().filter(|_| callback.is_none()).map(|rid| ReplyRef {
        id: rid.to_string(),
        is_own: own.iter().any(|o| o == rid) || (!our_number.is_empty() && ctx["from"].as_str().is_some_and(|f| digits(f) == digits(our_number))),
        ..Default::default()
    });
    Some(Inbound {
        channel: channel.to_string(),
        chat: from.clone(),
        chat_type: ChatType::Direct,
        sender_name: names.get(&from).cloned().unwrap_or_default(),
        sender: from,
        text,
        message_id: id,
        ts: m["timestamp"].as_str().and_then(|s| s.parse().ok()).or_else(|| m["timestamp"].as_i64()).unwrap_or(0),
        media,
        reply,
        callback,
        ..Default::default()
    })
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Buttons → an interactive object (≤3 reply buttons, ≤10 list rows, or a single URL button).
fn interactive_of(body: &str, rows: &[Vec<crate::Button>]) -> Option<Value> {
    let all: Vec<&crate::Button> = rows.iter().flatten().collect();
    let urls: Vec<&&crate::Button> = all.iter().filter(|b| b.url.is_some()).collect();
    let taps: Vec<&&crate::Button> = all.iter().filter(|b| b.url.is_none()).collect();
    let body = truncate_chars(if body.trim().is_empty() { "…" } else { body }, 1024);
    if taps.is_empty() && urls.len() == 1 {
        let b = urls[0];
        return Some(json!({"type": "cta_url", "body": {"text": body}, "action": {"name": "cta_url", "parameters": {"display_text": truncate_chars(&b.label, 20), "url": b.url}}}));
    }
    if !urls.is_empty() || taps.is_empty() || taps.len() > 10 {
        return None;
    }
    if taps.len() <= 3 {
        let buttons: Vec<Value> = taps.iter().map(|b| json!({"type": "reply", "reply": {"id": truncate_chars(&b.data, 256), "title": truncate_chars(&b.label, 20)}})).collect();
        return Some(json!({"type": "button", "body": {"text": body}, "action": {"buttons": buttons}}));
    }
    let list: Vec<Value> = taps.iter().map(|b| json!({"id": truncate_chars(&b.data, 200), "title": truncate_chars(&b.label, 24), "description": if b.label.chars().count() > 24 { truncate_chars(&b.label, 72) } else { String::new() }})).collect();
    Some(json!({"type": "list", "body": {"text": body}, "action": {"button": "選擇", "sections": [{"title": "選項", "rows": list}]}}))
}

/// Text fallback for buttons WhatsApp cannot render natively.
fn numbered(rows: &[Vec<crate::Button>]) -> String {
    rows.iter().flatten().enumerate().map(|(i, b)| match &b.url {
        Some(u) => format!("{}. {} {u}", i + 1, b.label),
        None => format!("{}. {}", i + 1, b.label),
    }).collect::<Vec<_>>().join("\n")
}

pub struct WhatsAppCloud {
    id: String,
    token: String,
    phone_id: String,
    graph: String,
    poll_timeout: u64,
    http: Http,
    pub retry_base: Duration,
    pub max_retries: u32,
    server: Server,
    rx: Mutex<Receiver<Value>>,
    /// chat → latest inbound wamid (typing indicator / read receipt).
    last_in: Mutex<HashMap<String, String>>,
    own: Mutex<VecDeque<String>>,
}

impl WhatsAppCloud {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.graph)
    }

    fn call(&self, method: &str, url: &str, body: Payload) -> Result<Value, ChannelError> {
        let mut attempt = 0;
        loop {
            let err = match self.http.call(method, url, &[], match &body {
                Payload::Json(v) => Payload::Json(v),
                Payload::Multipart(p) => Payload::Multipart(p),
                _ => Payload::None,
            }) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null)),
                Ok(r) => graph_err(url.rsplit('/').next().unwrap_or(""), r.status, r.retry_after, &r.body),
                Err(e) => e,
            };
            let short = !matches!(err.kind, K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(30));
            if !err.is_retryable() || !short || attempt >= self.max_retries {
                return Err(err);
            }
            std::thread::sleep(match err.kind {
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            });
            attempt += 1;
        }
    }

    fn post_message(&self, to: &str, kind: &str, block: Value, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let mut p = json!({"messaging_product": "whatsapp", "recipient_type": "individual", "to": to, "type": kind, kind: block});
        if let Some(r) = reply_to {
            p["context"] = json!({"message_id": r});
        }
        let r = self.call("POST", &self.url(&format!("{}/messages", self.phone_id)), Payload::Json(&p))?;
        let id = r["messages"][0]["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            let mut own = self.own.lock().unwrap();
            own.push_back(id.clone());
            while own.len() > 1000 {
                own.pop_front();
            }
        }
        Ok(id)
    }

    /// Upload a local file to `/{phone_id}/media`; returns the media id.
    fn upload(&self, path: &str, mime: &str) -> Result<String, ChannelError> {
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let name = crate::line::file_name(path);
        let mime = if mime.is_empty() { crate::line::guess_mime(&name) } else { mime };
        let parts: Vec<(&str, &str, &str, &[u8])> = vec![("messaging_product", "", "", b"whatsapp"), ("type", "", "", mime.as_bytes()), ("file", &name, mime, &data)];
        let r = self.call("POST", &self.url(&format!("{}/media", self.phone_id)), Payload::Multipart(&parts))?;
        r["id"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "media upload: response has no id"))
    }

    fn send_media(&self, out: &Outbound, m: &Media, caption: Option<&str>, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let kind = match m.kind {
            MediaKind::Image | MediaKind::Animation => "image",
            MediaKind::Video => "video",
            MediaKind::Audio | MediaKind::Voice => "audio",
            MediaKind::Sticker => "sticker",
            MediaKind::Document => "document",
        };
        let mut block = match (&m.path, &m.url, &m.id) {
            (Some(p), _, _) => json!({"id": self.upload(p, &m.mime)?}),
            (None, Some(u), _) => json!({"link": u}),
            (None, None, Some(id)) => json!({"id": id}),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path, url nor id")),
        };
        if let Some(c) = caption.or(m.caption.as_deref()).filter(|c| !c.is_empty() && matches!(kind, "image" | "video" | "document")) {
            block["caption"] = json!(self.render(out, c));
        }
        if kind == "document" {
            let name = if m.name.is_empty() { m.path.as_deref().map(crate::line::file_name).unwrap_or_default() } else { m.name.clone() };
            if !name.is_empty() {
                block["filename"] = json!(name);
            }
        }
        self.post_message(&out.chat, kind, block, reply_to)
    }

    fn render(&self, out: &Outbound, t: &str) -> String {
        match out.format {
            TextFormat::Markdown => to_whatsapp(t),
            TextFormat::Plain => t.to_string(),
        }
    }

    /// Blue ticks for one inbound message.
    pub fn mark_read(&self, wamid: &str) -> Result<(), ChannelError> {
        let p = json!({"messaging_product": "whatsapp", "status": "read", "message_id": wamid});
        self.call("POST", &self.url(&format!("{}/messages", self.phone_id)), Payload::Json(&p)).map(|_| ())
    }
}

impl Channel for WhatsAppCloud {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct],
            media: true,
            reply: true,
            threads: false,
            reactions: 1,
            edit: false,
            delete: false,
            typing: true,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
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
        let own = self.own.lock().unwrap().clone();
        let mut out = Vec::new();
        for value in got {
            let names: HashMap<String, String> = value["contacts"].as_array().into_iter().flatten().filter_map(|c| Some((c["wa_id"].as_str()?.to_string(), c["profile"]["name"].as_str().unwrap_or("").to_string()))).collect();
            let our = value["metadata"]["display_phone_number"].as_str().unwrap_or("");
            for m in value["messages"].as_array().into_iter().flatten() {
                if let Some(i) = inbound_of(&self.id, m, &names, our, &own) {
                    self.last_in.lock().unwrap().insert(i.chat.clone(), i.message_id.clone());
                    out.push(i);
                }
            }
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut sent = Sent::default();
        let mut reply_to = out.reply_to.as_deref();
        let caption_fits = out.media.len() == 1 && out.text.chars().count() <= 1024 && out.buttons.is_empty() && !matches!(out.media[0].kind, MediaKind::Audio | MediaKind::Voice | MediaKind::Sticker);
        for (i, m) in out.media.iter().enumerate() {
            let cap = (caption_fits && i == 0).then_some(out.text.as_str()).filter(|t| !t.trim().is_empty());
            sent.ids.push(self.send_media(out, m, cap, reply_to.take())?);
        }
        if caption_fits {
            return Ok(sent);
        }
        let text = self.render(out, &out.text);
        let mut pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        // Buttons ride on an interactive message whose body is the last piece (≤1024).
        let mut inter = None;
        if !out.buttons.is_empty() {
            let last = pieces.last().filter(|p| p.chars().count() <= 1024).cloned();
            match interactive_of(last.as_deref().unwrap_or(""), &out.buttons) {
                Some(i) => {
                    if last.is_some() {
                        pieces.pop();
                    }
                    inter = Some(i);
                }
                None => pieces.push(numbered(&out.buttons)),
            }
        }
        for p in pieces {
            sent.ids.push(self.post_message(&out.chat, "text", json!({"body": p, "preview_url": true}), reply_to.take())?);
        }
        if let Some(i) = inter {
            sent.ids.push(self.post_message(&out.chat, "interactive", i, reply_to.take())?);
        }
        Ok(sent)
    }

    /// Typing indicator (+ read receipt) on the chat's latest inbound message; a no-op before any.
    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let Some(wamid) = self.last_in.lock().unwrap().get(chat).cloned() else { return Ok(()) };
        let p = json!({"messaging_product": "whatsapp", "status": "read", "message_id": wamid, "typing_indicator": {"type": "text"}});
        self.call("POST", &self.url(&format!("{}/messages", self.phone_id)), Payload::Json(&p)).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let e = if remove { "" } else { emoji };
        self.post_message(chat, "reaction", json!({"message_id": message_id, "emoji": e}), None).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let id = m.id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "WhatsApp attachment without media id"))?;
        let meta = self.call("GET", &self.url(id), Payload::None)?;
        let url = meta["url"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "media lookup returned no url"))?;
        let auth = format!("Bearer {}", self.token);
        crate::http::get_bytes(url, &[("authorization", &auth)], 100 * 1024 * 1024)
    }
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    "/whatsapp/webhook".into()
}
fn d_ver() -> String {
    DEFAULT_API_VERSION.into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub phone_number_id: String,
    #[serde(alias = "token")]
    pub access_token: String,
    /// HMAC key for X-Hub-Signature-256.
    pub app_secret: String,
    /// Echoed back in the subscription handshake.
    pub verify_token: String,
    pub listen: String,
    #[serde(default = "d_path")]
    pub webhook_path: String,
    /// When set, webhooks for other business accounts are ignored.
    #[serde(default)]
    pub waba_id: Option<String>,
    #[serde(default = "d_ver")]
    pub api_version: String,
    #[serde(default)]
    pub graph_base: Option<String>,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl WhatsAppCloud {
    /// Secrets in `st` already resolved.
    pub fn open(id: &str, st: &Settings) -> Result<WhatsAppCloud, String> {
        if st.phone_number_id.trim().is_empty() || st.access_token.trim().is_empty() || st.app_secret.is_empty() || st.verify_token.is_empty() {
            return Err(format!("channel {id}: whatsapp_cloud needs phone_number_id, access_token, app_secret and verify_token"));
        }
        let (tx, rx) = channel::<Value>();
        let tx = Mutex::new(tx);
        let (path, secret, verify, phone, waba) = (st.webhook_path.clone(), st.app_secret.clone(), st.verify_token.clone(), st.phone_number_id.trim().to_string(), st.waba_id.clone());
        let handler: ark_net::httpd::Handler = Arc::new(move |r: ark_net::httpd::Request| {
            if r.path != path {
                return Response::text(404, "not found");
            }
            if r.method == "GET" {
                let ok = r.query("hub.mode") == Some("subscribe") && r.query("hub.verify_token").is_some_and(|t| ark_net::crypto::ct_eq(t.as_bytes(), verify.as_bytes()));
                return match (ok, r.query("hub.challenge").filter(|c| !c.is_empty())) {
                    (true, Some(c)) => Response::text(200, c),
                    (true, None) => Response::text(400, "missing challenge"),
                    _ => Response::text(403, "forbidden"),
                };
            }
            if r.method != "POST" {
                return Response::text(405, "method not allowed");
            }
            if !verify_signature(&secret, &r.body, r.header("x-hub-signature-256")) {
                return Response::text(401, "invalid signature");
            }
            let Ok(v) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
            if v["object"] != "whatsapp_business_account" {
                return Response::text(200, "ignored");
            }
            let tx = tx.lock().unwrap();
            for entry in v["entry"].as_array().into_iter().flatten() {
                if waba.as_deref().is_some_and(|w| entry["id"].as_str() != Some(w)) {
                    continue;
                }
                for ch in entry["changes"].as_array().into_iter().flatten() {
                    if ch["field"] == "messages" && ch["value"]["metadata"]["phone_number_id"].as_str() == Some(phone.as_str()) && ch["value"]["messages"].is_array() {
                        let _ = tx.send(ch["value"].clone());
                    }
                }
            }
            // Always 200 once verified: Meta retries non-200 for days.
            Response::text(200, "ok")
        });
        let server = Server::bind(&st.listen, Opts { max_body: 3 * 1024 * 1024, ..Opts::default() }, handler).map_err(|e| format!("channel {id}: cannot listen on {}: {e}", st.listen))?;
        let base = st.graph_base.as_deref().unwrap_or(DEFAULT_GRAPH).trim_end_matches('/');
        Ok(WhatsAppCloud {
            id: id.to_string(),
            token: st.access_token.trim().to_string(),
            phone_id: st.phone_number_id.trim().to_string(),
            graph: format!("{base}/{}", st.api_version.trim_matches('/')),
            poll_timeout: st.poll_timeout_secs,
            http: Http::new(Duration::from_secs(60)).bearer(st.access_token.trim()),
            retry_base: Duration::from_millis(500),
            max_retries: 2,
            server,
            rx: Mutex::new(rx),
            last_in: Mutex::default(),
            own: Mutex::default(),
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let mut st: Settings = ctx.settings(s)?;
    st.access_token = ctx.secret("access_token", &st.access_token)?;
    st.app_secret = ctx.secret("app_secret", &st.app_secret)?;
    st.verify_token = ctx.secret("verify_token", &st.verify_token)?;
    Ok(Arc::new(WhatsAppCloud::open(ctx.name, &st)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    fn wa(graph: &str) -> WhatsAppCloud {
        let st: Settings = serde_json::from_value(json!({"phone_number_id": "PN1", "access_token": "TOKEN", "app_secret": "appsecret", "verify_token": "vtok", "listen": "127.0.0.1:0", "graph_base": graph, "poll_timeout_secs": 1})).unwrap();
        let mut w = WhatsAppCloud::open("wa", &st).unwrap();
        w.retry_base = Duration::from_millis(5);
        w
    }

    fn sig(body: &str) -> String {
        format!("sha256={}", ark_net::crypto::hex(&ark_net::crypto::hmac_sha256(b"appsecret", body.as_bytes())))
    }

    fn post(w: &WhatsAppCloud, sig: Option<&str>, body: &str) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{}/whatsapp/webhook", w.local_addr()));
        if let Some(s) = sig {
            r = r.header("x-hub-signature-256", s);
        }
        r.send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn hook(phone: &str, messages: Value) -> String {
        json!({"object": "whatsapp_business_account", "entry": [{"id": "WABA", "changes": [{"field": "messages", "value": {
            "messaging_product": "whatsapp", "metadata": {"display_phone_number": "15550001111", "phone_number_id": phone},
            "contacts": [{"wa_id": "886912345678", "profile": {"name": "Amy"}}], "messages": messages,
            "statuses": [{"id": "wamid.S", "status": "delivered"}]}}]}]}).to_string()
    }

    fn ok_graph() -> FakeServer {
        FakeServer::start(|_, n| (200, vec![], json!({"messaging_product": "whatsapp", "messages": [{"id": format!("wamid.OUT{n}")}], "id": "MEDIA9"}).to_string()))
    }

    #[test]
    fn handshake_and_signature_checks() {
        let w = wa("http://127.0.0.1:1");
        let a = crate::http::agent(Duration::from_secs(5));
        let get = |q: &str| {
            let mut r = a.get(&format!("http://{}/whatsapp/webhook?{q}", w.local_addr())).call().unwrap();
            (r.status().as_u16(), r.body_mut().read_to_string().unwrap())
        };
        assert_eq!(get("hub.mode=subscribe&hub.verify_token=vtok&hub.challenge=12345"), (200, "12345".into()));
        assert_eq!(get("hub.mode=subscribe&hub.verify_token=nope&hub.challenge=12345").0, 403);
        assert_eq!(get("hub.mode=unsubscribe&hub.verify_token=vtok&hub.challenge=1").0, 403);
        let body = hook("PN1", json!([{"from": "886912345678", "id": "wamid.A", "timestamp": "1700000000", "type": "text", "text": {"body": "hi"}}]));
        assert_eq!(post(&w, None, &body), 401, "missing");
        assert_eq!(post(&w, Some("sha256=00ff"), &body), 401, "bad");
        assert_eq!(post(&w, Some(&sig("other")), &body), 401, "other body");
        assert_eq!(post(&w, Some(&sig(&body).replace("sha256=", "sha1=")), &body), 401, "wrong scheme");
        assert!(w.poll(&Cancel::new()).unwrap().is_empty(), "rejected bodies never reach poll");
        assert_eq!(post(&w, Some(&sig(&body).to_uppercase().replace("SHA256=", "sha256=")), &body), 200, "hex case-insensitive");
        assert_eq!(w.poll(&Cancel::new()).unwrap()[0].text, "hi");
        // Signed but for another phone number id: acknowledged, ignored.
        let other = hook("PN2", json!([{"from": "1", "id": "x", "type": "text", "text": {"body": "no"}}]));
        assert_eq!(post(&w, Some(&sig(&other)), &other), 200);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty());
    }

    #[test]
    fn parses_every_message_kind() {
        let srv = ok_graph();
        let w = wa(&srv.url);
        // Our own sent id, so a quote of it is a reply to the bot.
        let own = w.send(&Outbound::text("886912345678", "q?")).unwrap().ids[0].clone();
        let body = hook("PN1", json!([
            {"from": "886912345678", "id": "wamid.1", "timestamp": "1700000000", "type": "text", "text": {"body": "hello"}},
            {"from": "886912345678", "id": "wamid.2", "type": "image", "image": {"id": "IMG1", "mime_type": "image/jpeg", "caption": "look"}},
            {"from": "886912345678", "id": "wamid.3", "type": "document", "document": {"id": "DOC1", "mime_type": "application/pdf", "filename": "r.pdf"}},
            {"from": "886912345678", "id": "wamid.4", "type": "audio", "audio": {"id": "AUD1", "mime_type": "audio/ogg; codecs=opus", "voice": true}},
            {"from": "886912345678", "id": "wamid.5", "type": "sticker", "sticker": {"id": "ST1", "mime_type": "image/webp"}},
            {"from": "886912345678", "id": "wamid.6", "type": "interactive", "interactive": {"type": "button_reply", "button_reply": {"id": "appr:1:once", "title": "允許"}}, "context": {"id": own}},
            {"from": "886912345678", "id": "wamid.7", "type": "interactive", "interactive": {"type": "list_reply", "list_reply": {"id": "cl:9:2", "title": "3"}}},
            {"from": "886912345678", "id": "wamid.8", "type": "text", "text": {"body": "re"}, "context": {"from": "15550001111", "id": own}},
            {"from": "886912345678", "id": "wamid.9", "type": "text", "text": {"body": "re other"}, "context": {"from": "886900000000", "id": "wamid.X"}},
            {"from": "886912345678", "id": "wamid.10", "type": "reaction", "reaction": {"message_id": own, "emoji": "👍"}},
            {"from": "886912345678", "id": "wamid.11", "type": "location", "location": {"latitude": 25.0, "longitude": 121.5, "name": "Office"}},
            {"from": "886912345678", "id": "wamid.12", "type": "button", "button": {"text": "Yes", "payload": "tpl:yes"}},
            {"from": "886912345678", "id": "wamid.13", "type": "unsupported", "errors": [{"code": 131051}]},
            {"from": "15550001111", "id": "wamid.14", "type": "text", "text": {"body": "echo"}}
        ]));
        assert_eq!(post(&w, Some(&sig(&body)), &body), 200);
        let g = w.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 11, "reaction, unsupported and own echo dropped: {g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].sender_name.as_str(), g[0].ts, g[0].chat_type), ("886912345678", "Amy", 1700000000, ChatType::Direct));
        assert_eq!((g[1].text.as_str(), g[1].media[0].id.as_deref(), g[1].media[0].kind), ("look", Some("IMG1"), MediaKind::Image));
        assert_eq!((g[2].media[0].name.as_str(), g[2].media[0].mime.as_str()), ("r.pdf", "application/pdf"));
        assert_eq!((g[3].media[0].kind, g[3].media[0].mime.as_str()), (MediaKind::Voice, "audio/ogg"));
        assert_eq!(g[4].media[0].kind, MediaKind::Sticker);
        assert_eq!((g[5].callback.as_ref().unwrap().data.as_str(), g[5].text.as_str()), ("appr:1:once", "允許"));
        assert_eq!(g[6].callback.as_ref().unwrap().data, "cl:9:2");
        assert!(g[7].reply.as_ref().unwrap().is_own && !g[8].reply.as_ref().unwrap().is_own);
        assert!(g[9].text.contains("Office") && g[9].text.contains("121.5"));
        assert_eq!(g[10].callback.as_ref().unwrap().data, "tpl:yes");
        // Typing / read receipt targets the latest inbound message.
        w.typing("886912345678", None).unwrap();
        let r = srv.requests().last().unwrap().json();
        assert_eq!(r, json!({"messaging_product": "whatsapp", "status": "read", "message_id": "wamid.12", "typing_indicator": {"type": "text"}}));
        let n = srv.requests().len();
        w.typing("999", None).unwrap();
        assert_eq!(srv.requests().len(), n, "no inbound yet: nothing to do");
    }

    #[test]
    fn send_shapes_text_buttons_media_and_reactions() {
        let srv = ok_graph();
        let w = wa(&srv.url);
        let b = |l: &str, d: &str| crate::Button { label: l.into(), data: d.into(), url: None };
        let s = w.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("wamid.IN".into()), buttons: vec![vec![b("允許", "appr:x:once"), b("拒絕", "appr:x:deny")]], ..Outbound::text("886912345678", "**Run** [docs](https://e.com) a<b") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let r = srv.requests()[0].clone();
        assert_eq!(r.path, "/v20.0/PN1/messages");
        assert_eq!(r.header("authorization"), Some("Bearer TOKEN"));
        let j = r.json();
        assert_eq!((j["type"].as_str(), j["context"]["message_id"].as_str(), j["to"].as_str()), (Some("interactive"), Some("wamid.IN"), Some("886912345678")));
        assert_eq!(j["interactive"]["body"]["text"], "*Run* docs (https://e.com) a<b");
        assert_eq!(j["interactive"]["action"]["buttons"][1], json!({"type": "reply", "reply": {"id": "appr:x:deny", "title": "拒絕"}}));
        // 5 choices → list; 12 → numbered text; one URL → CTA.
        w.send(&Outbound { buttons: vec![(0..5).map(|i| b(&format!("choice {i}"), &format!("cl:1:{i}"))).collect()], ..Outbound::text("1", "pick") }).unwrap();
        assert_eq!(srv.requests()[1].json()["interactive"]["action"]["sections"][0]["rows"].as_array().unwrap().len(), 5);
        w.send(&Outbound { buttons: vec![(0..12).map(|i| b(&format!("o{i}"), "d")).collect()], ..Outbound::text("1", "pick") }).unwrap();
        let reqs = srv.requests();
        assert_eq!((reqs[2].json()["text"]["body"].as_str(), reqs[2].json()["text"]["preview_url"].as_bool()), (Some("pick"), Some(true)));
        assert!(reqs[3].json()["text"]["body"].as_str().unwrap().starts_with("1. o0\n2. o1"));
        w.send(&Outbound { buttons: vec![vec![crate::Button { label: "Open".into(), data: String::new(), url: Some("https://e.com".into()) }]], ..Outbound::text("1", "see") }).unwrap();
        assert_eq!(srv.requests()[4].json()["interactive"]["action"]["parameters"]["url"], "https://e.com");
        // Long text is chunked; only the first chunk quotes.
        let s = w.send(&Outbound { reply_to: Some("wamid.Q".into()), ..Outbound::text("1", &"x ".repeat(3000)) }).unwrap();
        assert_eq!(s.ids.len(), 2);
        let reqs = srv.requests();
        assert!(reqs[5].json()["context"].is_object() && reqs[6].json().get("context").is_none());
        // Media: link with caption; local file uploaded then sent by id.
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Image, url: Some("https://e.com/a.jpg".into()), ..Default::default() }], ..Outbound::text("1", "cap") }).unwrap();
        assert_eq!(srv.requests()[7].json()["image"], json!({"link": "https://e.com/a.jpg", "caption": "cap"}));
        let f = temp_dir("wac").join("r.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("1", "") }).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[8].path, "/v20.0/PN1/media");
        assert!(reqs[8].body.contains("name=\"messaging_product\"") && reqs[8].body.contains("filename=\"r.pdf\"") && reqs[8].body.contains("application/pdf"));
        assert_eq!(reqs[9].json()["document"], json!({"id": "MEDIA9", "filename": "r.pdf"}));
        w.react("1", "wamid.IN", "👍", false).unwrap();
        w.react("1", "wamid.IN", "👍", true).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[10].json()["reaction"], json!({"message_id": "wamid.IN", "emoji": "👍"}));
        assert_eq!(reqs[11].json()["reaction"]["emoji"], "");
        w.mark_read("wamid.IN").unwrap();
        assert_eq!(srv.requests()[12].json()["status"], "read");
    }

    #[test]
    fn error_mapping() {
        let e = |code: i64, status: u16| {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"error": {"message": "boom", "type": "OAuthException", "code": code}}).to_string()));
            let err = wa(&srv.url).send(&Outbound::text("1", "x")).unwrap_err();
            assert!(!err.message.contains("TOKEN"));
            (err, srv.requests().len())
        };
        let (err, n) = e(131047, 400);
        assert_eq!((err.kind.clone(), n), (K::Protocol, 1));
        assert!(err.message.contains("24 hours"), "{}", err.message);
        assert_eq!(e(190, 401).0.kind, K::Auth);
        assert_eq!(e(131026, 400).0.kind, K::NotFound);
        assert_eq!(e(100, 400).0.kind, K::Protocol);
        let (err, n) = e(131000, 500);
        assert_eq!((err.kind, n), (K::Network, 3), "retried");
        let (err, n) = e(130429, 400);
        assert!(matches!(err.kind, K::RateLimited { .. }) && n == 3);
        let srv = FakeServer::start(|_, n| if n == 0 { (503, vec![], "oops".into()) } else { (200, vec![], json!({"messages": [{"id": "ok"}]}).to_string()) });
        assert_eq!(wa(&srv.url).send(&Outbound::text("1", "x")).unwrap().ids, vec!["ok"]);
    }

    #[test]
    fn fetch_media_resolves_url_then_downloads_with_bearer() {
        let srv = FakeServer::start(|req, _| {
            let base = format!("http://{}", req.header("host").unwrap());
            match req.path.as_str() {
                "/v20.0/IMG1" => (200, vec![], json!({"url": format!("{base}/dl/img"), "mime_type": "image/jpeg"}).to_string()),
                "/dl/img" if req.header("authorization") == Some("Bearer TOKEN") => (200, vec![], "JPEG".into()),
                _ => (404, vec![], json!({"error": {"code": 100, "message": "no"}}).to_string()),
            }
        });
        let w = wa(&srv.url);
        assert_eq!(w.fetch_media(&Media { id: Some("IMG1".into()), ..Default::default() }).unwrap(), b"JPEG");
        assert_eq!(w.fetch_media(&Media { id: Some("NOPE".into()), ..Default::default() }).unwrap_err().kind, K::NotFound);
    }

    #[test]
    fn cancel_and_config() {
        let w = wa("http://127.0.0.1:1");
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        let st: Settings = serde_json::from_value(json!({"phone_number_id": "1", "access_token": "t", "app_secret": "", "verify_token": "v", "listen": "127.0.0.1:0"})).unwrap();
        assert!(WhatsAppCloud::open("w", &st).is_err(), "app secret required");
        assert_eq!(to_whatsapp("# T\n~~x~~ _i_ <http://a|b>"), "*T*\n~x~ _i_ <http://a|b>");
    }
}
