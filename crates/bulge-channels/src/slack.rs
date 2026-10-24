//! Slack through Socket Mode: events arrive over a client websocket the host
//! opens (`apps.connections.open` with the app-level `xapp-` token), replies
//! go out through the Web API with the bot token. Outbound only, no Events
//! API request URL, no listening port.
//!
//! A background task owns the websocket: it ACKs every envelope at once,
//! reconnects on `disconnect` or a drop, and feeds normalized messages into
//! a queue that [`Channel::poll`] drains.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::{Attachment, Channel, ChannelError, Inbound, download_capped, https_on, kind_from_mime};

/// chat.postMessage truncates past 40k; keep messages readable as openclaw does.
const TEXT_LIMIT: usize = 8000;
/// How long one `poll` waits for the first message.
const POLL_SECS: u64 = 30;
/// We ping the socket this often, and give up on it after `SILENCE_SECS`
/// without any frame.
const PING_SECS: u64 = 30;
const SILENCE_SECS: u64 = 90;
/// How many recent (channel, ts) pairs to remember so a message delivered as
/// both `message` and `app_mention` runs once.
const SEEN: usize = 512;

pub const DEFAULT_API: &str = "https://slack.com/api";

pub struct Slack {
    rest: Rest,
    bot_token: String,
    bot_user_id: String,
    events: tokio::sync::Mutex<mpsc::UnboundedReceiver<Event>>,
    /// Set once the socket task stopped for good: (is auth failure, why).
    fatal: Mutex<Option<(bool, String)>>,
    task: tokio::task::JoinHandle<()>,
}

/// What the socket task reports to `poll`.
enum Event {
    Message(Inbound),
    /// Connecting keeps failing; the task retries by itself.
    Trouble(String),
    /// A token was refused; the task has stopped.
    Fatal { auth: bool, message: String },
}

#[derive(Clone)]
struct Rest {
    name: String,
    api: String,
    http: reqwest::Client,
}

impl Rest {
    /// Call one Web API method. Slack answers most failures with HTTP 200 and
    /// `{"ok": false, "error": "..."}`.
    async fn call(&self, token: &str, method: &str, body: Option<Value>) -> Result<Value, ChannelError> {
        let transient = |message: String, retry_after_secs| ChannelError::Transient { channel: self.name.clone(), message, retry_after_secs };
        let mut request = self.http.post(format!("{}/{method}", self.api)).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|e| transient(format!("{method}: network error: {}", e.without_url()), None))?;
        let status = response.status();
        if status.as_u16() == 429 {
            let retry = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
            return Err(transient(format!("{method}: ratelimited"), retry));
        }
        if status.is_server_error() {
            return Err(transient(format!("{method}: HTTP {}", status.as_u16()), None));
        }
        let reply: Value = response.json().await.map_err(|e| transient(format!("{method}: unreadable reply: {}", e.without_url()), None))?;
        if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            return Ok(reply);
        }
        let error = reply.get("error").and_then(Value::as_str).unwrap_or("request failed");
        let message = format!("{method}: {error}");
        Err(match error {
            "invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive" | "not_allowed_token_type" => {
                ChannelError::Auth { channel: self.name.clone(), message }
            }
            "ratelimited" => transient(message, None),
            "internal_error" | "fatal_error" | "service_unavailable" | "request_timeout" => transient(message, None),
            _ => ChannelError::Other { channel: self.name.clone(), message },
        })
    }

    /// A fresh Socket Mode URL (each one is good for one connection).
    async fn socket_url(&self, app_token: &str) -> Result<String, ChannelError> {
        let reply = self.call(app_token, "apps.connections.open", None).await?;
        reply.get("url").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| ChannelError::Other {
            channel: self.name.clone(),
            message: "apps.connections.open: no url in the reply".into(),
        })
    }
}

/// Split an error into what the `fatal` slot keeps.
fn fatal_parts(error: ChannelError) -> (bool, String) {
    match error {
        ChannelError::Auth { message, .. } => (true, message),
        ChannelError::Transient { message, .. } | ChannelError::Other { message, .. } => (false, message),
    }
}

impl Slack {
    /// Connect: learn the bot's own user id (`auth.test` with the bot token),
    /// open the first socket (`apps.connections.open` with the app token), and
    /// start the socket task.
    pub async fn connect(account: &str, app_token: &str, bot_token: &str, api: &str) -> Result<Self, ChannelError> {
        let name = format!("slack:{account}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ChannelError::Other { channel: name.clone(), message: e.to_string() })?;
        let rest = Rest { name, api: api.trim_end_matches('/').to_owned(), http };
        let me = rest.call(bot_token, "auth.test", None).await?;
        let bot_user_id = me.get("user_id").and_then(Value::as_str).unwrap_or("").to_owned();
        let url = rest.socket_url(app_token).await?;
        let (events, rx) = mpsc::unbounded_channel();
        let socket = Socket {
            rest: rest.clone(),
            app_token: app_token.to_owned(),
            bot_user_id: bot_user_id.clone(),
            next_url: Some(url),
            seen: VecDeque::new(),
            healthy: false,
            events,
        };
        Ok(Self {
            rest,
            bot_token: bot_token.to_owned(),
            bot_user_id,
            events: tokio::sync::Mutex::new(rx),
            fatal: Mutex::new(None),
            task: tokio::spawn(socket.run()),
        })
    }

    pub fn bot_user_id(&self) -> &str {
        &self.bot_user_id
    }

    fn stopped(&self) -> ChannelError {
        let fatal = self.fatal.lock().ok().and_then(|f| f.clone());
        let name = self.rest.name.clone();
        match fatal {
            Some((true, message)) => ChannelError::Auth { channel: name, message },
            Some((false, message)) => ChannelError::Other { channel: name, message },
            None => ChannelError::Other { channel: name, message: "socket task stopped".into() },
        }
    }
}

impl Drop for Slack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Channel for Slack {
    fn name(&self) -> &str {
        &self.rest.name
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            // Private file URLs need the bot token; it is only ever sent to Slack's file host.
            if !https_on(&attachment.source, &["files.slack.com"]) {
                return Err(ChannelError::Other { channel: self.rest.name.clone(), message: "file is not on files.slack.com".into() });
            }
            download_capped(self.rest.http.get(&attachment.source).bearer_auth(&self.bot_token), max_bytes, &self.rest.name).await
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
        let body = json!({ "channel": chat_id, "text": text, "unfurl_links": false, "unfurl_media": false });
        Box::pin(async move { self.rest.call(&self.bot_token, "chat.postMessage", Some(body)).await.map(|_| ()) })
    }
}

/// The files shared with a message.
fn files(event: &Value) -> Vec<Attachment> {
    event
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| {
            Some(Attachment {
                kind: kind_from_mime(f.get("mimetype").and_then(Value::as_str).unwrap_or("")).to_owned(),
                name: f.get("name").and_then(Value::as_str).map(str::to_owned),
                source: f.get("url_private_download").or_else(|| f.get("url_private"))?.as_str()?.to_owned(),
                size: f.get("size").and_then(Value::as_u64),
            })
        })
        .collect()
}

/// The socket task's state.
struct Socket {
    rest: Rest,
    app_token: String,
    bot_user_id: String,
    /// The URL for the next connection, when one is already open.
    next_url: Option<String>,
    seen: VecDeque<String>,
    /// The current connection got `hello`.
    healthy: bool,
    events: mpsc::UnboundedSender<Event>,
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

impl Socket {
    async fn run(mut self) {
        let mut backoff = 1u64;
        loop {
            self.healthy = false;
            let url = match self.next_url.take() {
                Some(url) => Ok(url),
                None => self.rest.socket_url(&self.app_token).await,
            };
            let outcome = match url {
                Ok(url) => self.session(&url).await,
                Err(error) if error.is_fatal() => {
                    let (auth, message) = fatal_parts(error);
                    let _ = self.events.send(Event::Fatal { auth, message });
                    return;
                }
                Err(error) => Err(fatal_parts(error).1),
            };
            if self.events.is_closed() {
                return;
            }
            // A working connection that dropped is routine; only report
            // connections that never got going.
            if let Err(message) = outcome
                && !self.healthy
            {
                let _ = self.events.send(Event::Trouble(message));
            }
            if self.healthy {
                backoff = 1;
            } else {
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }

    /// One websocket connection, until Slack asks us to reconnect or it drops.
    async fn session(&mut self, url: &str) -> Result<(), String> {
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.map_err(|e| format!("socket: connect failed: {e}"))?;
        let mut ping = tokio::time::interval(Duration::from_secs(PING_SECS));
        ping.tick().await;
        let mut last_frame = Instant::now();
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if last_frame.elapsed() > Duration::from_secs(SILENCE_SECS) {
                        return Err("socket: no frames from Slack".into());
                    }
                    ws.send(Message::Ping(Vec::new().into())).await.map_err(|e| format!("socket: {e}"))?;
                }
                frame = ws.next() => {
                    last_frame = Instant::now();
                    let text = match frame {
                        Some(Ok(Message::Text(text))) => text,
                        Some(Ok(Message::Close(_))) => return Ok(()),
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => return Err(format!("socket: {e}")),
                        None => return Err("socket: connection closed".into()),
                    };
                    let Ok(envelope) = serde_json::from_str::<Value>(&text) else { continue };
                    match envelope.get("type").and_then(Value::as_str) {
                        Some("hello") => self.healthy = true,
                        Some("disconnect") => return Ok(()),
                        kind => {
                            // Every envelope must be ACKed within 3 s or Slack retries it.
                            if let Some(id) = envelope.get("envelope_id").and_then(Value::as_str) {
                                Self::ack(&mut ws, id).await?;
                            }
                            if kind == Some("events_api")
                                && let Some(event) = envelope.pointer("/payload/event")
                                && let Some(message) = self.inbound(event)
                            {
                                let _ = self.events.send(Event::Message(message));
                            }
                        }
                    }
                }
            }
        }
    }

    async fn ack(ws: &mut Ws, envelope_id: &str) -> Result<(), String> {
        ws.send(Message::Text(json!({ "envelope_id": envelope_id }).to_string().into())).await.map_err(|e| format!("socket: {e}"))
    }

    /// Normalize a `message` or `app_mention` event; `None` for edits, joins
    /// and other subtypes, bots (ourselves included), and repeats.
    fn inbound(&mut self, event: &Value) -> Option<Inbound> {
        let kind = event.get("type").and_then(Value::as_str)?;
        // `file_share` is a message with files; other subtypes (edits, joins, bots) are not requests.
        let subtype = event.get("subtype").and_then(Value::as_str);
        if !matches!(kind, "message" | "app_mention") || subtype.is_some_and(|s| s != "file_share") || event.get("bot_id").is_some() {
            return None;
        }
        let user = event.get("user")?.as_str()?;
        if user == self.bot_user_id {
            return None;
        }
        let channel = event.get("channel")?.as_str()?;
        let ts = event.get("ts")?.as_str()?;
        let key = format!("{channel}:{ts}");
        if self.seen.contains(&key) {
            return None;
        }
        if self.seen.len() >= SEEN {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        let is_group = event.get("channel_type").and_then(Value::as_str) != Some("im");
        let mut text = event.get("text").and_then(Value::as_str).unwrap_or("").to_owned();
        let mut mentioned = !is_group || kind == "app_mention";
        let handle = format!("<@{}>", self.bot_user_id);
        if !self.bot_user_id.is_empty() && text.contains(&handle) {
            mentioned = true;
            text = text.replace(&handle, "");
        }
        let text = text.trim().to_owned();
        let attachments = files(event);
        if text.is_empty() && attachments.is_empty() {
            return None;
        }
        Some(Inbound {
            channel: self.rest.name.clone(),
            chat_id: channel.to_owned(),
            sender_id: user.to_owned(),
            // Events carry no display name; the id is stable and unambiguous.
            sender_name: user.to_owned(),
            is_group,
            mentioned,
            text,
            message_id: ts.to_owned(),
            attachments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

    /// A fake Web API: answers by method name from `replies` (status, body),
    /// and records (method, authorization header, body).
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
                let method = path.rsplit('/').next().unwrap_or("").to_owned();
                let auth = text.lines().find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: "))).unwrap_or("").to_owned();
                let body: Value = text.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or(Value::Null);
                log.lock().unwrap().push((method.clone(), auth, body));
                let (status, reply) = replies.iter().find(|(m, _, _)| *m == method).map(|(_, s, r)| (*s, r.clone())).unwrap_or((200, json!({ "ok": true })));
                let payload = reply.to_string();
                let extra = if status == 429 { "retry-after: 4\r\n" } else { "" };
                let head = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n", payload.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(payload.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    type ServerWs = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    /// A fake Socket Mode endpoint: hands each accepted connection to the test.
    async fn fake_socket() -> (String, mpsc::UnboundedReceiver<ServerWs>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                let Ok(ws) = tokio_tungstenite::accept_async(socket).await else { continue };
                let _ = tx.send(ws);
            }
        });
        (format!("ws://{addr}/link"), rx)
    }

    fn apis(socket_url: &str) -> Vec<(&'static str, u16, Value)> {
        vec![
            ("auth.test", 200, json!({ "ok": true, "user_id": "UBOT", "bot_id": "BBOT" })),
            ("apps.connections.open", 200, json!({ "ok": true, "url": socket_url })),
        ]
    }

    async fn send(ws: &mut ServerWs, payload: Value) {
        ws.send(Message::Text(payload.to_string().into())).await.unwrap();
    }

    fn envelope(id: &str, event: Value) -> Value {
        json!({ "envelope_id": id, "type": "events_api", "accepts_response_payload": false, "payload": { "type": "event_callback", "event": event } })
    }

    async fn next_text(ws: &mut ServerWs) -> Value {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("client went quiet").unwrap().unwrap();
            if let Message::Text(text) = frame {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn acks_envelopes_and_normalizes_messages() {
        let (url, mut conns) = fake_socket().await;
        let (api, seen) = fake_api(apis(&url)).await;
        let slack = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await.unwrap();
        assert_eq!(slack.bot_user_id(), "UBOT");
        let log = seen.lock().unwrap().clone();
        assert_eq!((log[0].0.as_str(), log[0].1.as_str()), ("auth.test", "Bearer xoxb-BOT"));
        assert_eq!((log[1].0.as_str(), log[1].1.as_str()), ("apps.connections.open", "Bearer xapp-APP"));
        let mut ws = conns.recv().await.unwrap();
        send(&mut ws, json!({ "type": "hello", "num_connections": 1 })).await;
        let events = [
            json!({ "type": "message", "channel": "D1", "channel_type": "im", "user": "U42", "text": "幫我整理報告", "ts": "1.1" }),
            json!({ "type": "message", "channel": "C1", "channel_type": "channel", "user": "U7", "text": "<@UBOT> summarize this", "ts": "2.1" }),
            // The same message again as app_mention: handled once.
            json!({ "type": "app_mention", "channel": "C1", "user": "U7", "text": "<@UBOT> summarize this", "ts": "2.1" }),
            json!({ "type": "message", "channel": "C1", "channel_type": "channel", "user": "U7", "text": "just chatting", "ts": "3.1" }),
            json!({ "type": "message", "channel": "C1", "channel_type": "channel", "bot_id": "B9", "user": "U9", "text": "beep", "ts": "4.1" }),
            json!({ "type": "message", "channel": "C1", "channel_type": "channel", "user": "UBOT", "text": "my own reply", "ts": "5.1" }),
            json!({ "type": "message", "subtype": "message_changed", "channel": "C1", "channel_type": "channel", "ts": "6.1" }),
            json!({ "type": "app_mention", "channel": "C2", "user": "U7", "text": "<@UBOT> only a mention event", "ts": "7.1" }),
        ];
        for (i, event) in events.into_iter().enumerate() {
            let id = format!("env-{i}");
            send(&mut ws, envelope(&id, event)).await;
            // ACKed before anything else happens.
            assert_eq!(next_text(&mut ws).await, json!({ "envelope_id": id }));
        }
        let mut batch = Vec::new();
        while batch.len() < 4 {
            batch.extend(slack.poll().await.unwrap());
        }
        assert_eq!(batch.len(), 4, "bots, ourselves, subtypes and repeats are skipped");
        assert_eq!((batch[0].is_group, batch[0].mentioned, batch[0].text.as_str()), (false, true, "幫我整理報告"));
        assert_eq!((batch[0].chat_id.as_str(), batch[0].sender_id.as_str(), batch[0].message_id.as_str()), ("D1", "U42", "1.1"));
        assert_eq!((batch[1].is_group, batch[1].mentioned, batch[1].text.as_str()), (true, true, "summarize this"));
        assert!(batch[2].is_group && !batch[2].mentioned);
        assert_eq!((batch[3].chat_id.as_str(), batch[3].mentioned, batch[3].text.as_str()), ("C2", true, "only a mention event"));
    }

    #[tokio::test]
    async fn disconnect_opens_a_new_socket() {
        let (url, mut conns) = fake_socket().await;
        let (api, seen) = fake_api(apis(&url)).await;
        let slack = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await.unwrap();
        let mut ws = conns.recv().await.unwrap();
        send(&mut ws, json!({ "type": "hello" })).await;
        send(&mut ws, json!({ "type": "disconnect", "reason": "refresh_requested" })).await;
        let mut ws = tokio::time::timeout(Duration::from_secs(5), conns.recv()).await.unwrap().unwrap();
        let opens = seen.lock().unwrap().iter().filter(|(m, _, _)| m == "apps.connections.open").count();
        assert_eq!(opens, 2, "each connection gets a fresh URL");
        send(&mut ws, json!({ "type": "hello" })).await;
        send(&mut ws, envelope("e1", json!({ "type": "message", "channel": "D1", "channel_type": "im", "user": "U42", "text": "still here?", "ts": "9.1" }))).await;
        assert_eq!(slack.poll().await.unwrap()[0].text, "still here?");
    }

    #[tokio::test]
    async fn sends_chunks_and_classifies_errors() {
        let (url, _conns) = fake_socket().await;
        let (api, seen) = fake_api(apis(&url)).await;
        let slack = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await.unwrap();
        let long = "段落一。".repeat(2500);
        crate::send_long(&slack, "C1", &long).await.unwrap();
        let log = seen.lock().unwrap().clone();
        let sends: Vec<&(String, String, Value)> = log.iter().filter(|(m, _, _)| m == "chat.postMessage").collect();
        assert_eq!(sends.len(), 2);
        assert!(sends.iter().all(|(_, auth, b)| auth == "Bearer xoxb-BOT" && b["channel"] == "C1" && b["text"].as_str().unwrap().chars().count() <= TEXT_LIMIT));

        let (api, _) = fake_api(vec![("auth.test", 200, json!({ "ok": false, "error": "invalid_auth" }))]).await;
        let Err(error) = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await else { panic!("must fail") };
        assert!(error.is_fatal());
        assert!(!error.to_string().contains("xoxb-BOT") && !error.to_string().contains("xapp-APP"));

        let mut replies = apis(&url);
        replies[1] = ("apps.connections.open", 200, json!({ "ok": false, "error": "not_authed" }));
        let (api, _) = fake_api(replies).await;
        let Err(error) = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await else { panic!("must fail") };
        assert!(error.is_fatal() && !error.to_string().contains("xapp-APP"));

        let mut replies = apis(&url);
        replies.push(("chat.postMessage", 429, json!({ "ok": false, "error": "ratelimited" })));
        let (api, _) = fake_api(replies).await;
        let slack = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await.unwrap();
        match slack.send("C1", "hi").await {
            Err(ChannelError::Transient { retry_after_secs: Some(4), .. }) => {}
            other => panic!("{other:?}"),
        }
        let mut replies = apis(&url);
        replies.push(("chat.postMessage", 200, json!({ "ok": false, "error": "token_revoked" })));
        let (api, _) = fake_api(replies).await;
        let slack = Slack::connect("main", "xapp-APP", "xoxb-BOT", &api).await.unwrap();
        assert!(slack.send("C1", "hi").await.unwrap_err().is_fatal());
    }

    #[test]
    fn shared_files_become_attachments() {
        let event = json!({ "type": "message", "subtype": "file_share", "files": [
            { "name": "data.csv", "mimetype": "text/csv", "size": 10, "url_private_download": "https://files.slack.com/files-pri/T1-F1/download/data.csv" },
            { "name": "no-url.txt" }
        ] });
        let got = files(&event);
        assert_eq!(got, vec![Attachment { kind: "file".into(), name: Some("data.csv".into()), source: "https://files.slack.com/files-pri/T1-F1/download/data.csv".into(), size: Some(10) }]);
    }
}
