//! LINE through the Messaging API. LINE only delivers by webhook, so this is
//! the one channel that listens — and it keeps bulge's two-key rule:
//!
//!   1. the URL path carries a 256-bit secret (`/line/<path secret>`), compared
//!      in constant time; any other path gets a bare 404;
//!   2. the body must carry LINE's signature, `x-line-signature` =
//!      base64(HMAC-SHA256(channel secret, raw body)), also constant time.
//!
//! Nothing is parsed before both hold. The listener binds loopback by default;
//! the owner exposes it with a tunnel of their choice (Cloudflare Tunnel,
//! Tailscale Funnel), which terminates TLS. Headers must arrive within a
//! deadline, bodies are capped, connections are bounded, and redelivered
//! events (same `webhookEventId`) run once. Replies use the push API: a job
//! outlives LINE's short-lived reply tokens.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// How long a fetched display name is trusted before it is fetched again
/// (people rename themselves).
const NAME_TTL: Duration = Duration::from_secs(3600);

use base64::Engine;
use futures::future::BoxFuture;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};

use crate::{Attachment, Channel, ChannelError, Inbound, download_capped};

pub const DEFAULT_API: &str = "https://api.line.me";
/// Message content (images, files) is served from a separate host.
const DEFAULT_DATA_API: &str = "https://api-data.line.me";
/// LINE's text message limit.
const TEXT_LIMIT: usize = 5000;
/// Webhook bodies above this are refused before they are read in full
/// (openclaw caps at the same size).
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER: usize = 8 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 64;
/// Event ids remembered for de-duplication of redeliveries.
const SEEN_EVENTS: usize = 4096;
/// How long `poll` waits for a message before returning an empty batch.
const POLL_WAIT: Duration = Duration::from_secs(30);

pub struct Line {
    name: String,
    api: String,
    data_api: String,
    /// The bot's own display name, to strip `@name` from mentions.
    bot_name: String,
    /// user id → display name (looked up once).
    /// Display names by (chat, user) — a member's name can differ per group
    /// — with the time they were fetched; see [`NAME_TTL`].
    names: Mutex<HashMap<(String, String), (String, std::time::Instant)>>,
    access_token: String,
    http: reqwest::Client,
    inbox: Mutex<mpsc::Receiver<Inbound>>,
    local_addr: SocketAddr,
}

/// What the listener needs to admit a request.
struct Keys {
    path: String,
    channel_secret: Vec<u8>,
}

struct Seen {
    ids: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    /// True the first time an id is seen.
    fn insert(&mut self, id: &str) -> bool {
        if !self.ids.insert(id.to_owned()) {
            return false;
        }
        self.order.push_back(id.to_owned());
        if self.order.len() > SEEN_EVENTS
            && let Some(old) = self.order.pop_front()
        {
            self.ids.remove(&old);
        }
        true
    }
}

/// `base64(HMAC-SHA256(secret, body))`, LINE's signature.
pub fn signature(channel_secret: &[u8], body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(channel_secret).expect("HMAC takes any key length");
    mac.update(body);
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

impl Line {
    /// Check the access token, then start listening on `listen` for webhooks
    /// at `/line/<path_secret>`.
    pub async fn start(account: &str, channel_secret: &str, access_token: &str, path_secret: &str, listen: SocketAddr, api: &str) -> Result<Self, ChannelError> {
        let name = format!("line:{account}");
        let other = |message: String| ChannelError::Other { channel: name.clone(), message };
        if path_secret.len() < 32 {
            return Err(other("the webhook path secret must be at least 32 characters (use `bulge channels genkey`)".into()));
        }
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| other(e.to_string()))?;
        let api = api.trim_end_matches('/').to_owned();
        // Validate the token before opening a port.
        let response = http
            .get(format!("{api}/v2/bot/info"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ChannelError::Transient { channel: name.clone(), message: format!("bot/info: {}", e.without_url()), retry_after_secs: None })?;
        let status = response.status().as_u16();
        let info: Value = if status == 200 { response.json().await.unwrap_or(Value::Null) } else { Value::Null };
        match status {
            200 => {}
            401 | 403 => return Err(ChannelError::Auth { channel: name, message: "bot/info: the channel access token was refused".into() }),
            code => return Err(ChannelError::Transient { channel: name, message: format!("bot/info: HTTP {code}"), retry_after_secs: None }),
        }
        let listener = TcpListener::bind(listen).await.map_err(|e| other(format!("listen on {listen}: {e}")))?;
        let local_addr = listener.local_addr().map_err(|e| other(e.to_string()))?;
        let (tx, rx) = mpsc::channel(256);
        let keys = Arc::new(Keys { path: format!("/line/{path_secret}"), channel_secret: channel_secret.as_bytes().to_vec() });
        let seen = Arc::new(Mutex::new(Seen { ids: HashSet::new(), order: VecDeque::new() }));
        tokio::spawn(serve(listener, keys, seen, tx, name.clone()));
        let data_api = if api == DEFAULT_API { DEFAULT_DATA_API.to_owned() } else { api.clone() };
        let bot_name = info.get("displayName").and_then(Value::as_str).unwrap_or("").to_owned();
        Ok(Self { name, api, data_api, bot_name, names: Mutex::new(HashMap::new()), access_token: access_token.to_owned(), http, inbox: Mutex::new(rx), local_addr })
    }

    /// The bound address (useful when listening on port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The sender's display name: from the group/room member profile in
    /// groups, the user profile in one-to-one chats. Best effort, cached.
    async fn display_name(&self, message: &Inbound) -> String {
        if message.sender_id.is_empty() {
            return String::new();
        }
        let key = (if message.is_group { message.chat_id.clone() } else { String::new() }, message.sender_id.clone());
        if let Some((name, at)) = self.names.lock().await.get(&key)
            && at.elapsed() < NAME_TTL
        {
            return name.clone();
        }
        let path = match (message.is_group, message.chat_id.chars().next()) {
            (true, Some('C')) => format!("/v2/bot/group/{}/member/{}", message.chat_id, message.sender_id),
            (true, _) => format!("/v2/bot/room/{}/member/{}", message.chat_id, message.sender_id),
            (false, _) => format!("/v2/bot/profile/{}", message.sender_id),
        };
        let name = match self.http.get(format!("{}{path}", self.api)).bearer_auth(&self.access_token).send().await {
            Ok(response) if response.status().is_success() => response.json::<Value>().await.ok().and_then(|v| v.get("displayName").and_then(Value::as_str).map(str::to_owned)),
            _ => None,
        };
        match name {
            Some(name) => {
                let mut names = self.names.lock().await;
                // Expired entries go when a new one comes, so the cache holds
                // only the people seen within the last NAME_TTL.
                names.retain(|_, (_, at)| at.elapsed() < NAME_TTL);
                names.insert(key, (name.clone(), std::time::Instant::now()));
                name
            }
            None => String::new(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<(), ChannelError> {
        let response = self
            .http
            .post(format!("{}{path}", self.api))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChannelError::Transient { channel: self.name.clone(), message: format!("{path}: {}", e.without_url()), retry_after_secs: None })?;
        let status = response.status().as_u16();
        match status {
            200 => Ok(()),
            401 | 403 => Err(ChannelError::Auth { channel: self.name.clone(), message: format!("{path}: the channel access token was refused") }),
            429 => Err(ChannelError::Transient { channel: self.name.clone(), message: format!("{path}: rate limited (or the monthly push quota is used up)"), retry_after_secs: None }),
            _ => {
                let detail = response.text().await.unwrap_or_default();
                Err(ChannelError::Other { channel: self.name.clone(), message: format!("{path}: HTTP {status} {}", detail.chars().take(200).collect::<String>()) })
            }
        }
    }
}

async fn serve(listener: TcpListener, keys: Arc<Keys>, seen: Arc<Mutex<Seen>>, tx: mpsc::Sender<Inbound>, name: String) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(stream); // over the connection bound: refuse, never queue
            continue;
        };
        let (keys, seen, tx, name) = (keys.clone(), seen.clone(), tx.clone(), name.clone());
        tokio::spawn(async move {
            let _ = handle(stream, &keys, &seen, &tx, &name).await;
            drop(permit);
        });
    }
}

async fn respond(stream: &mut TcpStream, status: &str) -> std::io::Result<()> {
    stream.write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes()).await
}

/// One webhook request: path key, size, signature key, then the events.
async fn handle(mut stream: TcpStream, keys: &Keys, seen: &Mutex<Seen>, tx: &mpsc::Sender<Inbound>, name: &str) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let header_end = match tokio::time::timeout(HEADER_TIMEOUT, read_headers(&mut stream, &mut buf)).await {
        Ok(Ok(Some(end))) => end,
        Ok(Ok(None)) => return respond(&mut stream, "431 Request Header Fields Too Large").await,
        Ok(Err(e)) => return Err(e),
        Err(_) => return respond(&mut stream, "408 Request Timeout").await,
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or("").split(' ');
    let (method, path) = (request.next().unwrap_or(""), request.next().unwrap_or(""));
    // Key 1: the secret path. Wrong path or method looks like nothing is here.
    if method != "POST" || !ct_eq(path.as_bytes(), keys.path.as_bytes()) {
        return respond(&mut stream, "404 Not Found").await;
    }
    let header = |wanted: &str| {
        head.split("\r\n").skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(wanted).then(|| value.trim().to_owned())
        })
    };
    let Some(length) = header("content-length").and_then(|v| v.parse::<usize>().ok()) else {
        return respond(&mut stream, "411 Length Required").await;
    };
    if length > MAX_BODY {
        return respond(&mut stream, "413 Payload Too Large").await;
    }
    let mut body = buf[header_end + 4..].to_vec();
    let read_body = async {
        while body.len() < length {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, std::io::Error>(())
    };
    if tokio::time::timeout(HEADER_TIMEOUT, read_body).await.is_err() || body.len() < length {
        return respond(&mut stream, "408 Request Timeout").await;
    }
    body.truncate(length);
    // Key 2: LINE's signature over the raw body.
    let given = header("x-line-signature").unwrap_or_default();
    if !ct_eq(given.as_bytes(), signature(&keys.channel_secret, &body).as_bytes()) {
        return respond(&mut stream, "401 Unauthorized").await;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return respond(&mut stream, "400 Bad Request").await;
    };
    for event in payload.get("events").and_then(Value::as_array).into_iter().flatten() {
        let id = event.get("webhookEventId").and_then(Value::as_str).unwrap_or("");
        if !id.is_empty() && !seen.lock().await.insert(id) {
            continue; // a redelivery of something already queued
        }
        if let Some(message) = inbound(event, name) {
            // A full queue means bulge is far behind: drop with a log rather than block LINE.
            if tx.try_send(message).is_err() {
                eprintln!("{name}: inbox full, a message was dropped");
            }
        }
    }
    respond(&mut stream, "200 OK").await
}

/// Read until the end of the headers; `None` when they exceed the cap.
async fn read_headers(stream: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<Option<usize>> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Some(end));
        }
        if buf.len() > MAX_HEADER {
            return Ok(None);
        }
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed before the headers ended"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A message event (text, or an image/video/audio/file sent through LINE) →
/// Inbound. Other events, stickers, locations and media hosted elsewhere
/// (`contentProvider` other than `line`) are ignored.
fn inbound(event: &Value, name: &str) -> Option<Inbound> {
    if event.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let message_id = event.pointer("/message/id").and_then(Value::as_str).unwrap_or("").to_owned();
    let (text, attachments) = match event.pointer("/message/type").and_then(Value::as_str)? {
        "text" => (event.pointer("/message/text")?.as_str()?.to_owned(), Vec::new()),
        kind @ ("image" | "video" | "audio" | "file") => {
            let provider = event.pointer("/message/contentProvider/type").and_then(Value::as_str).unwrap_or("line");
            if provider != "line" || message_id.is_empty() {
                return None;
            }
            let attachment = Attachment {
                kind: kind.to_owned(),
                name: event.pointer("/message/fileName").and_then(Value::as_str).map(str::to_owned),
                source: message_id.clone(),
                size: event.pointer("/message/fileSize").and_then(Value::as_u64),
            };
            (String::new(), vec![attachment])
        }
        _ => return None,
    };
    let source = event.get("source")?;
    let sender = source.get("userId").and_then(Value::as_str).unwrap_or("").to_owned();
    let (chat_id, is_group) = match source.get("type").and_then(Value::as_str)? {
        "user" => (sender.clone(), false),
        "group" => (source.get("groupId")?.as_str()?.to_owned(), true),
        "room" => (source.get("roomId")?.as_str()?.to_owned(), true),
        _ => return None,
    };
    let mentioned = !is_group
        || event
            .pointer("/message/mention/mentionees")
            .and_then(Value::as_array)
            .is_some_and(|m| m.iter().any(|x| x.get("isSelf").and_then(Value::as_bool) == Some(true)));
    Some(Inbound {
        channel: name.to_owned(),
        chat_id,
        sender_id: sender,
        sender_name: String::new(),
        is_group,
        mentioned,
        text,
        message_id,
        attachments,
    })
}

impl Channel for Line {
    fn name(&self) -> &str {
        &self.name
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let mut inbox = self.inbox.lock().await;
            let mut batch = Vec::new();
            match tokio::time::timeout(POLL_WAIT, inbox.recv()).await {
                Ok(Some(message)) => batch.push(message),
                Ok(None) => return Err(ChannelError::Other { channel: self.name.clone(), message: "the webhook listener stopped".into() }),
                Err(_) => return Ok(batch),
            }
            while let Ok(message) = inbox.try_recv() {
                batch.push(message);
            }
            drop(inbox);
            for message in &mut batch {
                message.sender_name = self.display_name(message).await;
                // "@Bot do this" → "do this".
                if message.is_group && message.mentioned && !self.bot_name.is_empty() {
                    message.text = message.text.replacen(&format!("@{}", self.bot_name), "", 1).trim().to_owned();
                }
            }
            Ok(batch)
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let body = json!({ "to": chat_id, "messages": [{ "type": "text", "text": text }] });
        Box::pin(async move { self.post("/v2/bot/message/push", body).await })
    }

    fn send_mention<'a>(&'a self, message: &'a Inbound, text: &'a str) -> BoxFuture<'a, Result<(), ChannelError>> {
        // textV2 with a mention substitution: LINE shows "@name" and notifies them.
        // Escaping doubles every brace; when that would pass LINE's limit,
        // the reply goes as plain text with the name in front instead.
        let escaped_len = text.chars().count() + text.matches(['{', '}']).count() + "{user} ".len();
        let body = if message.sender_id.starts_with('U') && escaped_len <= TEXT_LIMIT {
            json!({ "to": message.chat_id, "messages": [{
                "type": "textV2",
                "text": format!("{{user}} {}", text.replace('{', "{{").replace('}', "}}")),
                "substitution": { "user": { "type": "mention", "mentionee": { "type": "user", "userId": message.sender_id } } }
            }] })
        } else {
            let name = if message.sender_name.is_empty() { "" } else { message.sender_name.as_str() };
            let plain = if name.is_empty() { text.to_owned() } else { format!("{name}：\n{text}") };
            json!({ "to": message.chat_id, "messages": [{ "type": "text", "text": plain }] })
        };
        Box::pin(async move { self.post("/v2/bot/message/push", body).await })
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            if !attachment.source.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(ChannelError::Other { channel: self.name.clone(), message: "bad message id".into() });
            }
            let request = self.http.get(format!("{}/v2/bot/message/{}/content", self.data_api, attachment.source)).bearer_auth(&self.access_token).timeout(Duration::from_secs(120));
            download_capped(request, max_bytes, &self.name).await
        })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        // The loading animation exists for one-to-one chats only (user ids).
        let body = json!({ "chatId": chat_id, "loadingSeconds": 20 });
        let one_to_one = chat_id.starts_with('U');
        Box::pin(async move {
            if one_to_one {
                let _ = self.post("/v2/bot/chat/loading/start", body).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "channel-secret";
    const PATH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A fake LINE API: 200 for everything, recording paths and bodies.
    async fn fake_api() -> (String, Arc<std::sync::Mutex<Vec<(String, Value)>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = Vec::new();
                let end = read_headers(&mut socket, &mut buf).await.unwrap().unwrap();
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                let mut body = buf[end + 4..].to_vec();
                while body.len() < length {
                    let mut chunk = [0u8; 4096];
                    let n = socket.read(&mut chunk).await.unwrap();
                    body.extend_from_slice(&chunk[..n]);
                }
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                seen.lock().unwrap().push((path, serde_json::from_slice(&body).unwrap_or(Value::Null)));
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await;
            }
        });
        (format!("http://{addr}"), log)
    }

    async fn start() -> (Line, Arc<std::sync::Mutex<Vec<(String, Value)>>>) {
        let (api, log) = fake_api().await;
        let line = Line::start("main", SECRET, "TOKEN", PATH, "127.0.0.1:0".parse().unwrap(), &api).await.unwrap();
        (line, log)
    }

    async fn post(addr: SocketAddr, path: &str, body: &[u8], signature: Option<String>) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let sig = signature.map(|s| format!("x-line-signature: {s}\r\n")).unwrap_or_default();
        let head = format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{sig}\r\n", body.len());
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply.lines().next().unwrap_or("").to_owned()
    }

    fn event(id: &str, text: &str, group: bool, self_mentioned: bool) -> Value {
        let source = if group { json!({ "type": "group", "groupId": "Cgroup", "userId": "Uowner" }) } else { json!({ "type": "user", "userId": "Uowner" }) };
        let mention = if self_mentioned { json!({ "mentionees": [{ "index": 0, "length": 6, "isSelf": true }] }) } else { Value::Null };
        json!({ "type": "message", "webhookEventId": id, "replyToken": "r", "source": source, "message": { "type": "text", "id": "m1", "text": text, "mention": mention } })
    }

    #[tokio::test]
    async fn both_keys_are_required_before_anything_is_parsed() {
        let (line, _) = start().await;
        let addr = line.local_addr();
        let body = serde_json::to_vec(&json!({ "events": [event("e1", "hi", false, false)] })).unwrap();
        let good = signature(SECRET.as_bytes(), &body);
        assert!(post(addr, "/line/wrong-path-wrong-path-wrong-path-xx", &body, Some(good.clone())).await.contains("404"), "key 1");
        assert!(post(addr, &format!("/line/{PATH}"), &body, Some(signature(b"other", &body))).await.contains("401"), "key 2");
        assert!(post(addr, &format!("/line/{PATH}"), &body, None).await.contains("401"));
        assert!(post(addr, &format!("/line/{PATH}"), &body, Some(good)).await.contains("200"));
        let batch = line.poll().await.unwrap();
        assert_eq!(batch.len(), 1, "only the request with both keys produced a message");
        assert_eq!((batch[0].chat_id.as_str(), batch[0].text.as_str(), batch[0].is_group), ("Uowner", "hi", false));
    }

    #[tokio::test]
    async fn redeliveries_run_once_and_groups_need_a_self_mention() {
        let (line, _) = start().await;
        let addr = line.local_addr();
        let body = serde_json::to_vec(&json!({ "events": [event("e1", "do it", true, true), event("e2", "chatter", true, false)] })).unwrap();
        let sig = signature(SECRET.as_bytes(), &body);
        post(addr, &format!("/line/{PATH}"), &body, Some(sig.clone())).await;
        post(addr, &format!("/line/{PATH}"), &body, Some(sig)).await; // LINE redelivery
        let batch = line.poll().await.unwrap();
        assert_eq!(batch.len(), 2);
        assert!(batch[0].mentioned && batch[0].is_group && batch[0].chat_id == "Cgroup");
        assert!(!batch[1].mentioned);
        assert!(tokio::time::timeout(Duration::from_millis(200), line.poll()).await.is_err(), "nothing more queued");
    }

    #[tokio::test]
    async fn oversize_bodies_and_slow_headers_are_refused() {
        let (line, _) = start().await;
        let addr = line.local_addr();
        // Refused from the Content-Length alone, before any of the body is read.
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let head = format!("POST /line/{PATH} HTTP/1.1\r\ncontent-length: {}\r\nx-line-signature: s\r\n\r\n", MAX_BODY + 1);
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 413"), "{reply}");
        // A client that never finishes its headers is cut off (the test only
        // checks the connection does not stay open forever).
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"POST /line/").await.unwrap();
        let mut reply = String::new();
        let closed = tokio::time::timeout(HEADER_TIMEOUT + Duration::from_secs(5), stream.read_to_string(&mut reply)).await;
        assert!(closed.is_ok() && reply.contains("408"), "{reply:?}");
    }

    #[tokio::test]
    async fn replies_use_push_and_the_token_is_never_in_errors() {
        let (line, log) = start().await;
        crate::send_long(&line, "Uowner", &"字".repeat(TEXT_LIMIT + 10)).await.unwrap();
        let pushes: Vec<Value> = log.lock().unwrap().iter().filter(|(p, _)| p == "/v2/bot/message/push").map(|(_, b)| b.clone()).collect();
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0]["to"], "Uowner");
        let Err(error) = Line::start("main", SECRET, "TOKEN", "short", "127.0.0.1:0".parse().unwrap(), "http://127.0.0.1:9").await else { panic!() };
        assert!(error.to_string().contains("at least 32"));
        assert!(!error.to_string().contains("TOKEN"));
    }

    #[tokio::test]
    async fn group_replies_mention_the_sender() {
        let (line, log) = start().await;
        let message = Inbound { channel: "line:main".into(), chat_id: "Cg".into(), sender_id: "Uamy".into(), sender_name: "Amy".into(), is_group: true, mentioned: true, text: "q".into(), message_id: "1".into(), attachments: Vec::new() };
        crate::reply_long(&line, &message, "答案 {x}").await.unwrap();
        let pushes: Vec<Value> = log.lock().unwrap().iter().filter(|(p, _)| p == "/v2/bot/message/push").map(|(_, b)| b.clone()).collect();
        let sent = &pushes[0]["messages"][0];
        assert_eq!(sent["type"], "textV2");
        assert_eq!(sent["text"], "{user} 答案 {{x}}", "literal braces are escaped");
        assert_eq!(sent["substitution"]["user"]["mentionee"]["userId"], "Uamy");
        assert_eq!(pushes[0]["to"], "Cg");
    }

    #[tokio::test]
    async fn brace_heavy_replies_that_would_overflow_go_as_plain_text() {
        let (line, log) = start().await;
        let message = Inbound { channel: "line:main".into(), chat_id: "Cg".into(), sender_id: "Uamy".into(), sender_name: "Amy".into(), is_group: true, mentioned: true, text: "q".into(), message_id: "1".into(), attachments: Vec::new() };
        let code = "{}".repeat(2400);
        line.send_mention(&message, &code).await.unwrap();
        let pushes: Vec<Value> = log.lock().unwrap().iter().filter(|(p, _)| p == "/v2/bot/message/push").map(|(_, b)| b.clone()).collect();
        assert_eq!(pushes[0]["messages"][0]["type"], "text");
        assert!(pushes[0]["messages"][0]["text"].as_str().unwrap().starts_with("Amy：\n{}"));
    }

    #[test]
    fn media_messages_carry_attachments_and_foreign_media_is_skipped() {
        let source = json!({ "type": "group", "groupId": "Cg", "userId": "Uamy" });
        let image = json!({ "type": "message", "source": source, "message": { "type": "image", "id": "5551", "contentProvider": { "type": "line" } } });
        let got = inbound(&image, "line:main").unwrap();
        assert_eq!(got.text, "");
        assert_eq!(got.attachments, vec![Attachment { kind: "image".into(), name: None, source: "5551".into(), size: None }]);
        assert!(!got.mentioned, "a photo in a group is not a request");
        let file = json!({ "type": "message", "source": source, "message": { "type": "file", "id": "5552", "fileName": "講義.pdf", "fileSize": 2048 } });
        let got = inbound(&file, "line:main").unwrap();
        assert_eq!(got.attachments[0].name.as_deref(), Some("講義.pdf"));
        assert_eq!(got.attachments[0].size, Some(2048));
        let external = json!({ "type": "message", "source": source, "message": { "type": "image", "id": "5553", "contentProvider": { "type": "external", "originalContentUrl": "https://x/y.jpg" } } });
        assert!(inbound(&external, "line:main").is_none());
        let sticker = json!({ "type": "message", "source": source, "message": { "type": "sticker", "id": "5554" } });
        assert!(inbound(&sticker, "line:main").is_none());
    }
}
