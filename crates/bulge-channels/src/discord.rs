//! Discord as a bot: messages arrive over the Gateway (a client websocket the
//! host opens), replies go out through the REST API. Outbound only, no
//! interactions endpoint, no listening port.
//!
//! A background task owns the websocket: it answers HELLO with heartbeats and
//! IDENTIFY (or RESUME after a drop), follows RECONNECT / INVALID_SESSION, and
//! feeds normalized messages into a queue that [`Channel::poll`] drains.

use std::sync::Mutex;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::{Attachment, Channel, ChannelError, Inbound, download_capped, https_on, kind_from_mime};

/// Discord's per-message limit.
const TEXT_LIMIT: usize = 2000;
/// How long one `poll` waits for the first message.
const POLL_SECS: u64 = 30;
/// How long a fresh connection may take to say HELLO.
const HELLO_SECS: u64 = 20;
/// GUILD_MESSAGES | DIRECT_MESSAGES | MESSAGE_CONTENT.
const INTENTS: u64 = (1 << 9) | (1 << 12) | (1 << 15);

pub const DEFAULT_API: &str = "https://discord.com/api/v10";

pub struct Discord {
    rest: Rest,
    events: tokio::sync::Mutex<mpsc::UnboundedReceiver<Event>>,
    /// Set once the gateway task stopped for good: (is auth failure, why).
    fatal: Mutex<Option<(bool, String)>>,
    task: tokio::task::JoinHandle<()>,
}

/// What the gateway task reports to `poll`.
enum Event {
    Message(Inbound),
    /// Connecting keeps failing; the task retries by itself.
    Trouble(String),
    /// The gateway refused us for good; the task has stopped.
    Fatal { auth: bool, message: String },
}

/// How one gateway connection ended (network failures are `Err`).
enum End {
    Reconnect,
    Fatal { auth: bool, message: String },
}

struct Rest {
    name: String,
    api: String,
    token: String,
    http: reqwest::Client,
}

impl Rest {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, ChannelError> {
        let what = path.trim_start_matches('/');
        let transient = |message: String| ChannelError::Transient { channel: self.name.clone(), message, retry_after_secs: None };
        let mut request = self.http.request(method, format!("{}{path}", self.api)).header("Authorization", format!("Bot {}", self.token));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|e| transient(format!("{what}: network error: {}", e.without_url())))?;
        let status = response.status();
        let retry_header = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<f64>().ok());
        // Some endpoints (typing) answer 204 with no body.
        let reply: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(reply);
        }
        let detail = reply.get("message").and_then(Value::as_str).unwrap_or_else(|| status.canonical_reason().unwrap_or("request failed"));
        let message = format!("{what}: {detail} (HTTP {})", status.as_u16());
        Err(match status.as_u16() {
            401 => ChannelError::Auth { channel: self.name.clone(), message },
            429 => ChannelError::Transient {
                channel: self.name.clone(),
                message,
                retry_after_secs: reply.get("retry_after").and_then(Value::as_f64).or(retry_header).map(|s| s.max(0.0).ceil() as u64),
            },
            500.. => transient(message),
            _ => ChannelError::Other { channel: self.name.clone(), message },
        })
    }
}

impl Discord {
    /// Connect: find the gateway (`GET /gateway/bot`, which also checks the
    /// token) unless `gateway_override` names one, and start the gateway task.
    /// The bot's own id arrives with READY.
    pub async fn connect(account: &str, token: &str, api: &str, gateway_override: Option<&str>) -> Result<Self, ChannelError> {
        let name = format!("discord:{account}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ChannelError::Other { channel: name.clone(), message: e.to_string() })?;
        let rest = Rest { name, api: api.trim_end_matches('/').to_owned(), token: token.to_owned(), http };
        let url = match gateway_override {
            Some(url) => url.to_owned(),
            None => {
                let reply = rest.call(reqwest::Method::GET, "/gateway/bot", None).await?;
                reply.get("url").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| ChannelError::Other {
                    channel: rest.name.clone(),
                    message: "gateway/bot: no gateway url in the reply".into(),
                })?
            }
        };
        let (events, rx) = mpsc::unbounded_channel();
        let gateway = Gateway {
            name: rest.name.clone(),
            url,
            token: token.to_owned(),
            bot_id: String::new(),
            session_id: None,
            resume_url: None,
            seq: None,
            healthy: false,
            events,
        };
        Ok(Self { rest, events: tokio::sync::Mutex::new(rx), fatal: Mutex::new(None), task: tokio::spawn(gateway.run()) })
    }

    fn stopped(&self) -> ChannelError {
        let fatal = self.fatal.lock().ok().and_then(|f| f.clone());
        let name = self.rest.name.clone();
        match fatal {
            Some((true, message)) => ChannelError::Auth { channel: name, message },
            Some((false, message)) => ChannelError::Other { channel: name, message },
            None => ChannelError::Other { channel: name, message: "gateway task stopped".into() },
        }
    }
}

impl Drop for Discord {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Channel for Discord {
    fn name(&self) -> &str {
        &self.rest.name
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            // Attachment URLs are signed CDN links; nothing else is fetched.
            if !https_on(&attachment.source, &["cdn.discordapp.com", "media.discordapp.net"]) {
                return Err(ChannelError::Other { channel: self.rest.name.clone(), message: "attachment is not on Discord's CDN".into() });
            }
            download_capped(self.rest.http.get(&attachment.source), max_bytes, &self.rest.name).await
        })
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let mut events = self.events.lock().await;
            let first = match tokio::time::timeout(Duration::from_secs(POLL_SECS), events.recv()).await {
                Err(_) => return Ok(Vec::new()),
                Ok(None) => return Err(self.stopped()),
                Ok(Some(event)) => event,
            };
            let mut batch = Vec::new();
            let mut next = Some(first);
            while let Some(event) = next {
                match event {
                    Event::Message(message) => batch.push(message),
                    Event::Trouble(message) if batch.is_empty() => {
                        return Err(ChannelError::Transient { channel: self.rest.name.clone(), message, retry_after_secs: None });
                    }
                    Event::Trouble(_) => {}
                    Event::Fatal { auth, message } => {
                        if let Ok(mut fatal) = self.fatal.lock() {
                            *fatal = Some((auth, message));
                        }
                        // Deliver what came before; the next poll reports it.
                        return if batch.is_empty() { Err(self.stopped()) } else { Ok(batch) };
                    }
                }
                next = events.try_recv().ok();
            }
            Ok(batch)
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let path = format!("/channels/{chat_id}/messages");
        let body = json!({ "content": text, "allowed_mentions": { "parse": [] } });
        Box::pin(async move { self.rest.call(reqwest::Method::POST, &path, Some(body)).await.map(|_| ()) })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        let path = format!("/channels/{chat_id}/typing");
        Box::pin(async move {
            let _ = self.rest.call(reqwest::Method::POST, &path, None).await;
        })
    }
}

/// The gateway task's state, kept across reconnects for RESUME.
struct Gateway {
    name: String,
    url: String,
    token: String,
    bot_id: String,
    session_id: Option<String>,
    resume_url: Option<String>,
    seq: Option<u64>,
    /// The current connection got READY / RESUMED.
    healthy: bool,
    events: mpsc::UnboundedSender<Event>,
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

impl Gateway {
    async fn run(mut self) {
        let mut backoff = 1u64;
        loop {
            self.healthy = false;
            let outcome = self.session().await;
            if self.events.is_closed() {
                return;
            }
            match outcome {
                Ok(End::Fatal { auth, message }) => {
                    let _ = self.events.send(Event::Fatal { auth, message });
                    return;
                }
                Ok(End::Reconnect) => {}
                // A working connection that dropped is routine; only report
                // connections that never got going.
                Err(message) if !self.healthy => {
                    let _ = self.events.send(Event::Trouble(message));
                }
                Err(_) => {}
            }
            if self.healthy {
                backoff = 1;
            } else {
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }

    /// One websocket connection, until it ends.
    async fn session(&mut self) -> Result<End, String> {
        let base = match (&self.session_id, &self.resume_url) {
            (Some(_), Some(resume)) => resume.as_str(),
            _ => self.url.as_str(),
        };
        let url = if base.contains('?') { base.to_owned() } else { format!("{}/?v=10&encoding=json", base.trim_end_matches('/')) };
        let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str()).await.map_err(|e| format!("gateway: connect failed: {e}"))?;
        let mut interval: Option<Duration> = None;
        let mut next_beat = Instant::now() + Duration::from_secs(HELLO_SECS);
        let mut acked = true;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(next_beat) => {
                    let Some(every) = interval else { return Err("gateway: no HELLO".into()) };
                    if !acked {
                        // No ACK for the last heartbeat: the connection is a zombie.
                        return Ok(End::Reconnect);
                    }
                    self.heartbeat(&mut ws).await?;
                    acked = false;
                    next_beat = Instant::now() + every;
                }
                frame = ws.next() => {
                    let text = match frame {
                        Some(Ok(Message::Text(text))) => text,
                        Some(Ok(Message::Close(frame))) => return Ok(self.closed(frame.map(|f| u16::from(f.code)))),
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => return Err(format!("gateway: {e}")),
                        None => return Err("gateway: connection closed".into()),
                    };
                    let Ok(payload) = serde_json::from_str::<Value>(&text) else { continue };
                    if let Some(seq) = payload.get("s").and_then(Value::as_u64) {
                        self.seq = Some(seq);
                    }
                    match payload.get("op").and_then(Value::as_u64) {
                        // HELLO: first heartbeat after a random part of the interval.
                        Some(10) => {
                            let every = Duration::from_millis(payload.pointer("/d/heartbeat_interval").and_then(Value::as_u64).unwrap_or(41_250));
                            interval = Some(every);
                            next_beat = Instant::now() + every.mul_f64(jitter());
                            self.hello(&mut ws).await?;
                        }
                        Some(11) => acked = true,
                        Some(1) => self.heartbeat(&mut ws).await?,
                        Some(0) => self.dispatch(&payload),
                        Some(7) => return Ok(End::Reconnect),
                        Some(9) => {
                            if !payload.get("d").and_then(Value::as_bool).unwrap_or(false) {
                                self.forget_session();
                            }
                            // Discord asks for a 1–5 s pause before identifying again.
                            tokio::time::sleep(Duration::from_secs_f64(1.0 + 4.0 * jitter())).await;
                            self.healthy = true;
                            return Ok(End::Reconnect);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn send_json(ws: &mut Socket, payload: Value) -> Result<(), String> {
        ws.send(Message::Text(payload.to_string().into())).await.map_err(|e| format!("gateway: {e}"))
    }

    async fn heartbeat(&self, ws: &mut Socket) -> Result<(), String> {
        Self::send_json(ws, json!({ "op": 1, "d": self.seq })).await
    }

    /// RESUME when there is a session to pick up, IDENTIFY otherwise.
    async fn hello(&self, ws: &mut Socket) -> Result<(), String> {
        let payload = match (&self.session_id, self.seq) {
            (Some(session), Some(seq)) => json!({ "op": 6, "d": { "token": self.token, "session_id": session, "seq": seq } }),
            _ => json!({ "op": 2, "d": {
                "token": self.token,
                "intents": INTENTS,
                "properties": { "os": std::env::consts::OS, "browser": "bulge", "device": "bulge" },
            } }),
        };
        Self::send_json(ws, payload).await
    }

    fn forget_session(&mut self) {
        self.session_id = None;
        self.resume_url = None;
        self.seq = None;
    }

    fn closed(&mut self, code: Option<u16>) -> End {
        let fatal = |auth: bool, why: &str| End::Fatal { auth, message: format!("gateway closed the connection ({}): {why}", code.unwrap_or(0)) };
        match code {
            Some(4004) => fatal(true, "the bot token was refused"),
            Some(4010 | 4011) => fatal(false, "sharding is required for this bot"),
            Some(4012) => fatal(false, "unsupported gateway version"),
            Some(4013) => fatal(false, "invalid intents"),
            Some(4014) => fatal(false, "disallowed intents (enable MESSAGE CONTENT INTENT for the bot in the Developer Portal)"),
            // Bad sequence / session timed out: start a new session.
            Some(4007 | 4009) => {
                self.forget_session();
                End::Reconnect
            }
            _ => End::Reconnect,
        }
    }

    fn dispatch(&mut self, payload: &Value) {
        let data = payload.get("d").unwrap_or(&Value::Null);
        match payload.get("t").and_then(Value::as_str) {
            Some("READY") => {
                self.bot_id = data.pointer("/user/id").and_then(Value::as_str).unwrap_or("").to_owned();
                self.session_id = data.get("session_id").and_then(Value::as_str).map(str::to_owned);
                self.resume_url = data.get("resume_gateway_url").and_then(Value::as_str).map(str::to_owned);
                self.healthy = true;
            }
            Some("RESUMED") => self.healthy = true,
            Some("MESSAGE_CREATE") => {
                if let Some(message) = inbound(&self.name, &self.bot_id, data) {
                    let _ = self.events.send(Event::Message(message));
                }
            }
            _ => {}
        }
    }
}

/// A random fraction in [0, 1).
fn jitter() -> f64 {
    let mut bytes = [0u8; 4];
    let _ = getrandom::fill(&mut bytes);
    f64::from(u32::from_le_bytes(bytes)) / (f64::from(u32::MAX) + 1.0)
}

/// Normalize one MESSAGE_CREATE; `None` for bots (ourselves included),
/// system messages and messages without text.
fn inbound(channel: &str, bot_id: &str, message: &Value) -> Option<Inbound> {
    let author = message.get("author")?;
    let author_id = author.get("id")?.as_str()?;
    if author.get("bot").and_then(Value::as_bool).unwrap_or(false) || author_id == bot_id || message.get("webhook_id").is_some() {
        return None;
    }
    let mut text = message.get("content")?.as_str()?.to_owned();
    let is_group = message.get("guild_id").is_some();
    let mut mentioned = !is_group
        || message.pointer("/referenced_message/author/id").and_then(Value::as_str) == Some(bot_id)
        || message.get("mentions").and_then(Value::as_array).is_some_and(|m| m.iter().any(|u| u.get("id").and_then(Value::as_str) == Some(bot_id)));
    if !bot_id.is_empty() {
        for handle in [format!("<@{bot_id}>"), format!("<@!{bot_id}>")] {
            if text.contains(&handle) {
                mentioned = true;
                text = text.replace(&handle, "");
            }
        }
    }
    let text = text.trim().to_owned();
    let attachments: Vec<Attachment> = message
        .get("attachments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| {
            Some(Attachment {
                kind: kind_from_mime(a.get("content_type").and_then(Value::as_str).unwrap_or("")).to_owned(),
                name: a.get("filename").and_then(Value::as_str).map(str::to_owned),
                source: a.get("url")?.as_str()?.to_owned(),
                size: a.get("size").and_then(Value::as_u64),
            })
        })
        .collect();
    if text.is_empty() && attachments.is_empty() {
        return None;
    }
    let username = author.get("username").and_then(Value::as_str).unwrap_or("");
    let sender_name = match author.get("global_name").and_then(Value::as_str) {
        Some(display) if display != username => format!("{display} (@{username})"),
        _ => username.to_owned(),
    };
    Some(Inbound {
        channel: channel.to_owned(),
        chat_id: message.get("channel_id")?.as_str()?.to_owned(),
        sender_id: author_id.to_owned(),
        sender_name,
        is_group,
        mentioned,
        text,
        message_id: message.get("id").and_then(Value::as_str).unwrap_or("").to_owned(),
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

    /// A fake REST API: answers by path suffix from `replies` (status, body),
    /// and records (path, authorization header, body).
    async fn fake_api(replies: Vec<(&'static str, u16, Value)>) -> (String, Seen) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                // Read headers + body (Content-Length).
                loop {
                    let n = socket.read(&mut buf[len..]).await.unwrap_or(0);
                    if n == 0 { break; }
                    len += n;
                    let text = String::from_utf8_lossy(&buf[..len]).to_string();
                    if let Some(split) = text.find("\r\n\r\n") {
                        let want = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                        if len >= split + 4 + want { break; }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                let auth = text.lines().find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: "))).unwrap_or("").to_owned();
                let body: Value = text.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or(Value::Null);
                log.lock().unwrap().push((path.clone(), auth, body));
                let (status, reply) = replies.iter().find(|(p, _, _)| path.ends_with(p)).map(|(_, s, r)| (*s, r.clone())).unwrap_or((200, json!({ "id": "1" })));
                let payload = reply.to_string();
                let extra = if status == 429 { "retry-after: 3\r\n" } else { "" };
                let head = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n", payload.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(payload.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    /// A fake gateway: accepts connections and hands each one to the test,
    /// along with the requested path.
    async fn fake_gateway() -> (String, mpsc::UnboundedReceiver<(String, Ws)>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                let path = Arc::new(Mutex::new(String::new()));
                let record = path.clone();
                // The handshake API's own error type is large; nothing to do about it here.
                #[allow(clippy::result_large_err)]
                let callback = move |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    *record.lock().unwrap() = request.uri().to_string();
                    Ok(response)
                };
                let Ok(ws) = tokio_tungstenite::accept_hdr_async(socket, callback).await else { continue };
                let path = path.lock().unwrap().clone();
                let _ = tx.send((path, ws));
            }
        });
        (format!("ws://{addr}"), rx)
    }

    async fn send(ws: &mut Ws, payload: Value) {
        ws.send(Message::Text(payload.to_string().into())).await.unwrap();
    }

    /// The next JSON frame from the client (skipping heartbeats unless `op` is 1).
    async fn expect_op(ws: &mut Ws, op: u64) -> Value {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("client went quiet").unwrap().unwrap();
            let Message::Text(text) = frame else { continue };
            let payload: Value = serde_json::from_str(&text).unwrap();
            if payload["op"] == op {
                return payload;
            }
            if payload["op"] == 1 {
                send(ws, json!({ "op": 11 })).await;
            }
        }
    }

    fn hello(interval_ms: u64) -> Value {
        json!({ "op": 10, "d": { "heartbeat_interval": interval_ms } })
    }

    fn ready(resume_url: &str) -> Value {
        json!({ "op": 0, "s": 1, "t": "READY", "d": { "user": { "id": "900", "username": "bulge", "bot": true }, "session_id": "sess-1", "resume_gateway_url": resume_url } })
    }

    fn message(seq: u64, id: &str, author: Value, content: &str, extra: Value) -> Value {
        let mut d = json!({ "id": id, "channel_id": "C1", "author": author, "content": content, "mentions": [] });
        d.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({ "op": 0, "s": seq, "t": "MESSAGE_CREATE", "d": d })
    }

    fn person() -> Value {
        json!({ "id": "42", "username": "owner", "global_name": "Owner" })
    }

    #[tokio::test]
    async fn identifies_heartbeats_and_normalizes_messages() {
        let (url, mut conns) = fake_gateway().await;
        let discord = Discord::connect("main", "TOKEN", "http://127.0.0.1:9", Some(&url)).await.unwrap();
        let (path, mut ws) = conns.recv().await.unwrap();
        assert!(path.contains("v=10") && path.contains("encoding=json"), "{path}");
        send(&mut ws, hello(50)).await;
        let identify = expect_op(&mut ws, 2).await;
        assert_eq!(identify["d"]["token"], "TOKEN");
        assert_eq!(identify["d"]["intents"], 37376);
        // Heartbeats come at the interval and carry the last sequence number.
        let beat = expect_op(&mut ws, 1).await;
        assert!(beat["d"].is_null());
        send(&mut ws, json!({ "op": 11 })).await;
        send(&mut ws, ready(&url)).await;
        let bot = json!({ "id": "77", "username": "otherbot", "bot": true });
        send(&mut ws, message(2, "m1", person(), "幫我整理報告", json!({}))).await;
        send(&mut ws, message(3, "m2", person(), "<@900> summarize this", json!({ "guild_id": "G", "mentions": [{ "id": "900" }] }))).await;
        send(&mut ws, message(4, "m3", person(), "<@!900>   look", json!({ "guild_id": "G" }))).await;
        send(&mut ws, message(5, "m4", person(), "just chatting", json!({ "guild_id": "G" }))).await;
        send(&mut ws, message(6, "m5", bot, "<@900> beep", json!({ "guild_id": "G" }))).await;
        send(&mut ws, message(7, "m6", person(), "yes do it", json!({ "guild_id": "G", "referenced_message": { "author": { "id": "900" } } }))).await;
        // A server-requested heartbeat is answered at once with the latest seq.
        send(&mut ws, json!({ "op": 1 })).await;
        // (Periodic beats sent before the request may come first.)
        while expect_op(&mut ws, 1).await["d"] != 7 {
            send(&mut ws, json!({ "op": 11 })).await;
        }
        let mut batch = Vec::new();
        while batch.len() < 5 {
            batch.extend(discord.poll().await.unwrap());
        }
        assert_eq!(batch.len(), 5, "bot messages are skipped");
        assert_eq!((batch[0].is_group, batch[0].mentioned, batch[0].text.as_str()), (false, true, "幫我整理報告"));
        assert_eq!(batch[0].sender_name, "Owner (@owner)");
        assert_eq!((batch[0].chat_id.as_str(), batch[0].sender_id.as_str(), batch[0].message_id.as_str()), ("C1", "42", "m1"));
        assert_eq!((batch[1].is_group, batch[1].mentioned, batch[1].text.as_str()), (true, true, "summarize this"));
        assert_eq!((batch[2].mentioned, batch[2].text.as_str()), (true, "look"));
        assert!(!batch[3].mentioned);
        assert!(batch[4].mentioned, "a reply to the bot addresses it");
    }

    #[tokio::test]
    async fn reconnect_resumes_the_session() {
        let (url, mut conns) = fake_gateway().await;
        let discord = Discord::connect("main", "TOKEN", "http://127.0.0.1:9", Some(&url)).await.unwrap();
        let (_, mut ws) = conns.recv().await.unwrap();
        send(&mut ws, hello(60_000)).await;
        expect_op(&mut ws, 2).await;
        send(&mut ws, ready(&url)).await;
        // With a long interval, a heartbeat now can only be the answer to a request.
        send(&mut ws, json!({ "op": 1 })).await;
        assert_eq!(expect_op(&mut ws, 1).await["d"], 1);
        send(&mut ws, message(2, "m1", person(), "first", json!({}))).await;
        assert_eq!(discord.poll().await.unwrap()[0].text, "first");
        send(&mut ws, json!({ "op": 7 })).await;
        let (_, mut ws) = tokio::time::timeout(Duration::from_secs(5), conns.recv()).await.unwrap().unwrap();
        send(&mut ws, hello(60_000)).await;
        let resume = expect_op(&mut ws, 6).await;
        assert_eq!((resume["d"]["session_id"].as_str(), resume["d"]["seq"].as_u64()), (Some("sess-1"), Some(2)));
        send(&mut ws, json!({ "op": 0, "s": 3, "t": "RESUMED", "d": {} })).await;
        send(&mut ws, message(4, "m2", person(), "second", json!({}))).await;
        assert_eq!(discord.poll().await.unwrap()[0].text, "second");
    }

    #[tokio::test]
    async fn fatal_close_codes_surface_from_poll() {
        for (code, auth) in [(4004u16, true), (4014, false)] {
            let (url, mut conns) = fake_gateway().await;
            let discord = Discord::connect("main", "TOKEN", "http://127.0.0.1:9", Some(&url)).await.unwrap();
            let (_, mut ws) = conns.recv().await.unwrap();
            send(&mut ws, hello(60_000)).await;
            expect_op(&mut ws, 2).await;
            let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame { code: code.into(), reason: "".into() };
            ws.send(Message::Close(Some(frame))).await.unwrap();
            let error = discord.poll().await.unwrap_err();
            assert_eq!(error.is_fatal(), auth, "{error}");
            assert!(!error.to_string().contains("TOKEN"));
            // It stays reported on later polls.
            assert_eq!(discord.poll().await.unwrap_err().is_fatal(), auth);
        }
    }

    #[tokio::test]
    async fn rest_sends_chunks_and_classifies_errors() {
        let (api, seen) = fake_api(vec![("/gateway/bot", 200, json!({ "url": "ws://127.0.0.1:9" }))]).await;
        let discord = Discord::connect("main", "TOKEN", &api, None).await.unwrap();
        let long = "段落一。".repeat(700);
        crate::send_long(&discord, "C1", &long).await.unwrap();
        discord.typing("C1").await;
        let log = seen.lock().unwrap().clone();
        assert!(log.iter().all(|(_, auth, _)| auth == "Bot TOKEN"));
        let sends: Vec<&Value> = log.iter().filter(|(p, _, _)| p == "/channels/C1/messages").map(|(_, _, b)| b).collect();
        assert_eq!(sends.len(), 2);
        assert!(sends.iter().all(|b| b["content"].as_str().unwrap().chars().count() <= TEXT_LIMIT));
        assert!(log.iter().any(|(p, _, _)| p == "/channels/C1/typing"));

        let (api, _) = fake_api(vec![("/gateway/bot", 401, json!({ "message": "401: Unauthorized", "code": 0 }))]).await;
        let Err(error) = Discord::connect("main", "TOKEN", &api, None).await else { panic!("must fail") };
        assert!(error.is_fatal());
        assert!(!error.to_string().contains("TOKEN"));

        let (api, _) = fake_api(vec![("/messages", 429, json!({ "message": "You are being rate limited.", "retry_after": 1.2, "global": false }))]).await;
        let discord = Discord::connect("main", "TOKEN", &api, Some("ws://127.0.0.1:9")).await.unwrap();
        match discord.send("C1", "hi").await {
            Err(ChannelError::Transient { retry_after_secs: Some(2), message, .. }) => assert!(!message.contains("TOKEN")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn attachments_are_carried_even_without_text() {
        let message = json!({ "id": "m1", "channel_id": "C1", "author": { "id": "U1", "username": "amy" }, "content": "",
            "attachments": [{ "url": "https://cdn.discordapp.com/attachments/1/2/photo.jpg", "filename": "photo.jpg", "size": 1234, "content_type": "image/jpeg" }] });
        let got = inbound("discord:main", "BOT", &message).unwrap();
        assert_eq!(got.text, "");
        assert_eq!(got.attachments, vec![Attachment { kind: "image".into(), name: Some("photo.jpg".into()), source: "https://cdn.discordapp.com/attachments/1/2/photo.jpg".into(), size: Some(1234) }]);
        let empty = json!({ "id": "m2", "channel_id": "C1", "author": { "id": "U1", "username": "amy" }, "content": "" });
        assert!(inbound("discord:main", "BOT", &empty).is_none());
    }
}
