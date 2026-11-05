//! ntfy push topics (ported from Hermes `plugins/platforms/ntfy`, MIT).
//!
//! Receive: a background thread holds `GET <server>/<topic>/json` open (HTTP
//! streaming, chunked or not) and parses one JSON event per line; `open` and
//! `keepalive` events are ignored, `message` events become `Inbound`. The last
//! delivered message id is persisted (committed on the next poll, at-least-once)
//! and sent as `since=<id>` after a reconnect or restart. Reconnects back off
//! 2/5/10/30/60 s; 401/403 stop with `Auth`, 404 with `NotFound`.
//! Send: `POST <server>/<publish_topic>` with the text as body, `X-Tags` carrying
//! an echo tag (our own messages are dropped when they come back on the stream),
//! optional `X-Title`/`X-Priority`/`X-Markdown`, URL buttons as `X-Actions` view
//! actions, attachments by URL (`X-Attach`) or as a `PUT` file upload.
//! ntfy has no user identity: each topic is one trusted chat (sender = topic);
//! the publisher-controlled `title` is never used as identity.
//! Auth: a token is sent as `Bearer`, `user:pass` as `Basic`.

use crate::http::{classify, Http, Payload};
use crate::{markup, write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::stream::{is_timeout, Stream};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_SERVER: &str = "https://ntfy.sh";
/// ntfy's message body limit.
pub const MAX_MESSAGE: usize = 4096;
/// Tag on everything we publish so the subscription can skip our own echoes.
pub const ECHO_TAG: &str = "ark-agent";
const BACKOFF: [u64; 5] = [2, 5, 10, 30, 60];
/// ntfy sends a keepalive every 55 s by default; give it margin.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_LINE: usize = 1024 * 1024;

enum Ev {
    Msg(Box<Inbound>),
    Fatal(ChannelError),
}

struct Shared {
    stop: AtomicBool,
    /// Newest message id seen on the stream (resume point for in-process reconnects).
    since: Mutex<Option<String>>,
    /// Ids of messages we published (second echo guard besides the tag).
    sent: Mutex<VecDeque<String>>,
}

pub struct Ntfy {
    id: String,
    server: String,
    topic: String,
    publish_topic: String,
    auth: Option<String>,
    markdown: bool,
    title: Option<String>,
    priority: Option<String>,
    tags: Vec<String>,
    poll_timeout: u64,
    state: PathBuf,
    http: Http,
    /// Reconnect delays; the last repeats. Reset after a stream that lived ≥ 60 s.
    pub backoff: Vec<Duration>,
    /// Reconnect when nothing (not even a keepalive) arrived for this long.
    pub idle_timeout: Duration,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    shared: Arc<Shared>,
    rx: Mutex<Option<Receiver<Ev>>>,
    /// Delivered but not yet committed resume id.
    pending: Mutex<Option<String>>,
    fatal: Mutex<Option<ChannelError>>,
}

/// `Authorization` value: `user:pass` → Basic, anything else → Bearer; empty → none.
pub fn auth_header(token: &str) -> Option<String> {
    let t = token.trim();
    if t.is_empty() {
        None
    } else if t.contains(':') {
        Some(format!("Basic {}", ark_net::crypto::b64(t.as_bytes())))
    } else {
        Some(format!("Bearer {t}"))
    }
}

/// Replay one recorded stream event (see `tests/real/vectors/ntfy_stream_event.json`)
/// as ark would turn it into an `Inbound`. Public for the vector tests; the hot path
/// is `poll`.
pub fn recorded_inbound(channel: &str, topic: &str, ev: &Value) -> Option<Inbound> {
    inbound_of(channel, topic, ev, &VecDeque::new())
}

/// Header-safe value: plain ASCII as is, anything else RFC 2047 encoded (ntfy decodes it).
fn header_value(s: &str) -> String {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        s.to_string()
    } else {
        format!("=?UTF-8?B?{}?=", ark_net::crypto::b64(s.as_bytes()))
    }
}

fn kind_of(mime: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" => MediaKind::Image,
        "audio" => MediaKind::Audio,
        "video" => MediaKind::Video,
        _ => MediaKind::Document,
    }
}

/// One stream event → Inbound (None for open/keepalive/poll_request, our echoes, empty bodies).
fn inbound_of(channel: &str, default_topic: &str, ev: &Value, sent: &VecDeque<String>) -> Option<Inbound> {
    if ev["event"].as_str() != Some("message") {
        return None;
    }
    let id = ev["id"].as_str().unwrap_or("").to_string();
    if id.is_empty() || sent.contains(&id) {
        return None;
    }
    if ev["tags"].as_array().is_some_and(|t| t.iter().any(|t| t.as_str() == Some(ECHO_TAG))) {
        return None;
    }
    let text = ev["message"].as_str().unwrap_or("").trim().to_string();
    let att = &ev["attachment"];
    let media: Vec<Media> = att["url"]
        .as_str()
        .map(|u| {
            let mime = att["type"].as_str().unwrap_or("").to_string();
            Media { kind: kind_of(&mime), url: Some(u.to_string()), name: att["name"].as_str().unwrap_or("").to_string(), size: att["size"].as_u64().unwrap_or(0), mime, ..Default::default() }
        })
        .into_iter()
        .collect();
    if text.is_empty() && media.is_empty() {
        return None;
    }
    let topic = ev["topic"].as_str().filter(|t| !t.is_empty()).unwrap_or(default_topic).to_string();
    Some(Inbound {
        channel: channel.to_string(),
        chat: topic.clone(),
        chat_name: topic.clone(),
        chat_type: ChatType::Direct,
        sender: topic.clone(),
        sender_name: topic,
        // A file-only message carries the file name as its body; keep it as text too.
        text,
        message_id: id,
        ts: ev["time"].as_i64().unwrap_or(0),
        media,
        ..Default::default()
    })
}

/// Settings the stream thread needs.
#[derive(Clone)]
struct StreamCfg {
    channel: String,
    host: String,
    port: u16,
    tls: bool,
    host_header: String,
    path: String,
    topic: String,
    auth: Option<String>,
    backoff: Vec<Duration>,
    idle: Duration,
}

/// Why one stream attempt ended.
enum End {
    Stopped,
    Retry,
    Fatal(ChannelError),
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// One streaming connection: send the GET, check the status, dispatch lines until it drops.
fn stream_once(cfg: &StreamCfg, sh: &Shared, tx: &Sender<Ev>) -> End {
    let mut s = match Stream::connect(&cfg.host, cfg.port, cfg.tls, Duration::from_secs(15)) {
        Ok(s) => s,
        Err(_) => return End::Retry,
    };
    let since = sh.since.lock().unwrap().clone();
    let mut path = format!("{}/{}/json", cfg.path, cfg.topic);
    if let Some(id) = since {
        path.push_str(&format!("?since={}", ark_net::urlencode(&id)));
    }
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ark\r\nAccept: application/x-ndjson\r\n", cfg.host_header);
    if let Some(a) = &cfg.auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    if s.write_all(req.as_bytes()).and_then(|_| s.flush()).is_err() {
        return End::Retry;
    }
    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
    let mut raw: Vec<u8> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut head: Option<bool> = None; // Some(chunked) once the head is parsed
    let mut last = Instant::now();
    let mut chunk = [0u8; 8192];
    loop {
        if sh.stop.load(Ordering::SeqCst) {
            s.shutdown();
            return End::Stopped;
        }
        match s.read(&mut chunk) {
            Ok(0) => return End::Retry,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                last = Instant::now();
            }
            Err(e) if is_timeout(&e) => {
                if last.elapsed() > cfg.idle {
                    return End::Retry;
                }
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return End::Retry,
        }
        if head.is_none() {
            let Some(i) = find(&raw, b"\r\n\r\n") else {
                if raw.len() > 64 * 1024 {
                    return End::Retry;
                }
                continue;
            };
            let h = String::from_utf8_lossy(&raw[..i]).into_owned();
            raw.drain(..i + 4);
            let status: u16 = h.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            match status {
                200..=299 => {}
                401 | 403 => return End::Fatal(ChannelError::new(K::Auth, format!("ntfy rejected the credentials for topic {} (HTTP {status}); check token", cfg.topic))),
                404 => return End::Fatal(ChannelError::new(K::NotFound, format!("ntfy topic {} not found (HTTP 404)", cfg.topic))),
                _ => return End::Retry,
            }
            let chunked = ark_net::ws::header(&h, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
            head = Some(chunked);
        }
        if head == Some(true) {
            // De-chunk whatever complete chunks are buffered.
            while let Some(i) = find(&raw, b"\r\n") {
                let size_line = String::from_utf8_lossy(&raw[..i]).into_owned();
                let Ok(size) = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16) else { return End::Retry };
                if size == 0 {
                    return End::Retry;
                }
                if raw.len() < i + 2 + size + 2 {
                    break;
                }
                body.extend_from_slice(&raw[i + 2..i + 2 + size]);
                raw.drain(..i + 2 + size + 2);
            }
        } else {
            body.append(&mut raw);
        }
        while let Some(i) = body.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = body.drain(..=i).collect();
            let Ok(ev) = serde_json::from_slice::<Value>(&line) else { continue };
            if ev["event"].as_str() != Some("message") {
                continue;
            }
            let inbound = inbound_of(&cfg.channel, &cfg.topic, &ev, &sh.sent.lock().unwrap());
            if let Some(id) = ev["id"].as_str() {
                *sh.since.lock().unwrap() = Some(id.to_string());
            }
            if let Some(m) = inbound {
                if tx.send(Ev::Msg(Box::new(m))).is_err() {
                    return End::Stopped;
                }
            }
        }
        if body.len() > MAX_LINE {
            body.clear();
        }
    }
}

fn stream_loop(cfg: StreamCfg, sh: Arc<Shared>, tx: Sender<Ev>) {
    let mut attempt = 0usize;
    while !sh.stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        match stream_once(&cfg, &sh, &tx) {
            End::Stopped => return,
            End::Fatal(e) => {
                let _ = tx.send(Ev::Fatal(e));
                return;
            }
            End::Retry => {}
        }
        if started.elapsed() >= Duration::from_secs(60) {
            attempt = 0;
        }
        let d = cfg.backoff.get(attempt.min(cfg.backoff.len().saturating_sub(1))).copied().unwrap_or(Duration::from_secs(5));
        attempt += 1;
        let until = Instant::now() + d;
        while Instant::now() < until {
            if sh.stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Ntfy {
    /// `token` is a Bearer token or `user:pass`. `state` holds the resume id.
    pub fn new(id: &str, server: Option<&str>, topic: &str, publish_topic: Option<&str>, token: Option<&str>, state: PathBuf, poll_timeout_secs: u64) -> Result<Ntfy, String> {
        let topic = topic.trim().trim_matches('/').to_string();
        if topic.is_empty() || topic.contains(['/', '?', '#', ' ']) {
            return Err(format!("channel {id}: ntfy `topic` must be a non-empty topic name"));
        }
        let server = server.unwrap_or(DEFAULT_SERVER).trim().trim_end_matches('/').to_string();
        let u = ark_net::Url::parse(&server).map_err(|e| format!("channel {id}: ntfy server: {e}"))?;
        if !matches!(u.scheme.as_str(), "http" | "https") {
            return Err(format!("channel {id}: ntfy server must be http(s)"));
        }
        let since = std::fs::read_to_string(&state).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| v["since"].as_str().map(str::to_string));
        Ok(Ntfy {
            id: id.to_string(),
            server,
            publish_topic: publish_topic.map(|t| t.trim().trim_matches('/').to_string()).filter(|t| !t.is_empty()).unwrap_or_else(|| topic.clone()),
            topic,
            auth: token.and_then(auth_header),
            markdown: false,
            title: None,
            priority: None,
            tags: Vec::new(),
            poll_timeout: poll_timeout_secs,
            state,
            http: Http::new(Duration::from_secs(60)),
            backoff: BACKOFF.iter().map(|s| Duration::from_secs(*s)).collect(),
            idle_timeout: IDLE_TIMEOUT,
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
            shared: Arc::new(Shared { stop: AtomicBool::new(false), since: Mutex::new(since), sent: Mutex::new(VecDeque::new()) }),
            rx: Mutex::new(None),
            pending: Mutex::new(None),
            fatal: Mutex::new(None),
        })
    }

    fn ensure_started(&self) {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_some() {
            return;
        }
        let u = ark_net::Url::parse(&self.server).expect("validated in new");
        let base = u.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
        let cfg = StreamCfg {
            channel: self.id.clone(),
            tls: u.tls(),
            host_header: u.host_header(),
            host: u.host,
            port: u.port,
            path: base,
            topic: self.topic.clone(),
            auth: self.auth.clone(),
            backoff: self.backoff.clone(),
            idle: self.idle_timeout,
        };
        let (tx, r) = mpsc::channel();
        let sh = self.shared.clone();
        std::thread::spawn(move || stream_loop(cfg, sh, tx));
        *rx = Some(r);
    }

    fn commit(&self) -> Result<(), ChannelError> {
        if let Some(id) = self.pending.lock().unwrap().take() {
            write_atomic(&self.state, json!({ "since": id }).to_string().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving ntfy resume id: {e}")))?;
        }
        Ok(())
    }

    fn topic_for(&self, chat: &str) -> String {
        let c = chat.trim().trim_matches('/');
        if c.is_empty() || c == self.topic {
            self.publish_topic.clone()
        } else {
            c.to_string()
        }
    }

    fn remember_sent(&self, id: &str) {
        if id.is_empty() {
            return;
        }
        let mut s = self.shared.sent.lock().unwrap();
        s.push_back(id.to_string());
        while s.len() > 500 {
            s.pop_front();
        }
    }

    /// One publish with retries on 429/5xx/network. Returns ntfy's message id.
    fn publish(&self, method: &str, topic: &str, headers: &[(String, String)], body: Payload) -> Result<String, ChannelError> {
        let url = format!("{}/{}", self.server, ark_net::urlencode(topic));
        let mut hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if let Some(a) = &self.auth {
            hs.push(("authorization", a));
        }
        let mut attempt = 0;
        loop {
            let body_again = match &body {
                Payload::Raw(t, b) => Payload::Raw(t, b),
                _ => Payload::None,
            };
            let err = match self.http.call(method, &url, &hs, body_again) {
                Ok(r) if (200..300).contains(&r.status) => {
                    let id = serde_json::from_str::<Value>(&r.body).ok().and_then(|v| v["id"].as_str().map(str::to_string)).unwrap_or_default();
                    self.remember_sent(&id);
                    return Ok(id);
                }
                Ok(r) => classify(r.status, r.retry_after, "ntfy publish", &r.body),
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

    fn headers(&self, out: &Outbound, first: bool, last: bool) -> Vec<(String, String)> {
        let mut tags = vec![ECHO_TAG.to_string()];
        tags.extend(self.tags.iter().cloned());
        let mut h = vec![("x-tags".to_string(), header_value(&tags.join(",")))];
        if out.format == TextFormat::Markdown && self.markdown {
            h.push(("x-markdown".into(), "true".into()));
        }
        if let (true, Some(t)) = (first, &self.title) {
            h.push(("x-title".into(), header_value(t)));
        }
        if out.silent {
            h.push(("x-priority".into(), "low".into()));
        } else if let Some(p) = &self.priority {
            h.push(("x-priority".into(), p.clone()));
        }
        if last {
            // ntfy has URL "view" actions only (max 3); callback buttons become text options.
            let acts: Vec<String> = out.buttons.iter().flatten().filter_map(|b| b.url.as_ref().map(|u| format!("view, {}, {}", b.label.replace([',', ';'], " "), u))).take(3).collect();
            if !acts.is_empty() {
                h.push(("x-actions".into(), header_value(&acts.join("; "))));
            }
        }
        h
    }

    fn render(&self, out: &Outbound) -> String {
        let mut text = match out.format {
            TextFormat::Markdown if !self.markdown => markup::convert(&out.text, Markup::Plain),
            _ => out.text.clone(),
        };
        let options: Vec<&str> = out.buttons.iter().flatten().filter(|b| b.url.is_none()).map(|b| b.label.as_str()).collect();
        if !options.is_empty() {
            text.push_str("\n\n");
            for (i, l) in options.iter().enumerate() {
                text.push_str(&format!("{}. {l}\n", i + 1));
            }
            text = text.trim_end().to_string();
        }
        text
    }
}

impl Channel for Ntfy {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct],
            media: true,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: if self.markdown { Markup::Markdown } else { Markup::Plain },
            ..Caps::default()
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if let Some(e) = self.fatal.lock().unwrap().clone() {
            return Err(e);
        }
        self.ensure_started();
        self.commit()?;
        let guard = self.rx.lock().unwrap();
        let rx = guard.as_ref().expect("started");
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(ev) => {
                    for ev in std::iter::once(ev).chain(rx.try_iter()) {
                        match ev {
                            Ev::Msg(m) => got.push(*m),
                            Ev::Fatal(e) => {
                                *self.fatal.lock().unwrap() = Some(e.clone());
                                if got.is_empty() {
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        if let Some(m) = got.last() {
            *self.pending.lock().unwrap() = Some(m.message_id.clone());
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let topic = self.topic_for(&out.chat);
        let text = self.render(out);
        let mut sent = Sent::default();
        let mut text_used = false;
        let n_media = out.media.len();
        for (i, m) in out.media.iter().enumerate() {
            let last = i + 1 == n_media && text.trim().is_empty();
            let mut h = self.headers(out, i == 0, last);
            let caption = m.caption.clone().or_else(|| (!text_used && text.chars().count() <= 1024).then(|| text.clone())).filter(|t| !t.trim().is_empty());
            if caption.is_some() && m.caption.is_none() {
                text_used = true;
            }
            let id = match (&m.path, &m.url) {
                (Some(p), _) => {
                    let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                    let fname = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
                    h.push(("x-filename".into(), header_value(&fname)));
                    if let Some(c) = &caption {
                        h.push(("x-message".into(), header_value(c)));
                    }
                    let ct = if m.mime.is_empty() { "application/octet-stream" } else { m.mime.as_str() };
                    self.publish("PUT", &topic, &h, Payload::Raw(ct, &data))?
                }
                (None, Some(u)) => {
                    h.push(("x-attach".into(), u.clone()));
                    if !m.name.is_empty() {
                        h.push(("x-filename".into(), header_value(&m.name)));
                    }
                    let body = caption.unwrap_or_default();
                    self.publish("POST", &topic, &h, Payload::Raw("text/plain; charset=utf-8", body.as_bytes()))?
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            };
            sent.ids.push(id);
        }
        if text_used {
            return Ok(sent);
        }
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let h = self.headers(out, i == 0 && out.media.is_empty(), i + 1 == n);
            sent.ids.push(self.publish("POST", &topic, &h, Payload::Raw("text/plain; charset=utf-8", piece.as_bytes()))?);
        }
        Ok(sent)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "ntfy attachment without url"))?;
        // Only our own server gets the credentials.
        let ours = u.starts_with(&format!("{}/", self.server));
        match (&self.auth, ours) {
            (Some(a), true) => crate::http::get_bytes(u, &[("authorization", a)], 50 * 1024 * 1024),
            _ => crate::http::get_bytes(u, &[], 50 * 1024 * 1024),
        }
    }

    fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Ntfy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Default https://ntfy.sh.
    #[serde(default)]
    server: Option<String>,
    topic: String,
    /// Where replies go (defaults to `topic`).
    #[serde(default)]
    publish_topic: Option<String>,
    /// Access token (Bearer) or `user:pass` (Basic).
    #[serde(default)]
    token: Option<String>,
    /// Send Markdown replies with `X-Markdown: true`.
    #[serde(default)]
    markdown: bool,
    /// `X-Title` on replies.
    #[serde(default)]
    title: Option<String>,
    /// `X-Priority` on replies (1-5 or min/low/default/high/max).
    #[serde(default)]
    priority: Option<String>,
    /// Extra `X-Tags` on replies (emoji short codes etc.).
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.opt_secret("token", &st.token)?;
    let mut n = Ntfy::new(ctx.name, st.server.as_deref(), &st.topic, st.publish_topic.as_deref(), token.as_deref(), ctx.state("ntfy.json"), st.poll_timeout_secs)?;
    n.markdown = st.markdown;
    n.title = st.title.filter(|t| !t.trim().is_empty());
    if let Some(p) = &st.priority {
        let ok = matches!(p.as_str(), "1" | "2" | "3" | "4" | "5" | "min" | "low" | "default" | "high" | "max" | "urgent");
        if !ok {
            return Err(format!("channel {}: ntfy priority must be 1-5 or min/low/default/high/max", ctx.name));
        }
    }
    n.priority = st.priority;
    n.tags = st.tags.into_iter().filter(|t| !t.trim().is_empty() && !t.contains(',')).collect();
    Ok(Arc::new(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;

    /// A fake ntfy subscribe endpoint: each connection's request line is recorded, then
    /// `script(n, request_head)` decides what to stream.
    struct FakeNtfy {
        url: String,
        heads: Arc<Mutex<Vec<String>>>,
    }

    enum Script {
        /// Status line + chunked lines, then hold the connection open for `hold`.
        Chunked(&'static str, Vec<String>, Duration),
        /// Plain body lines then close.
        Plain(Vec<String>),
        Status(u16),
    }

    fn fake(script: impl Fn(usize, &str) -> Script + Send + 'static) -> FakeNtfy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let h2 = heads.clone();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let Ok((head, _)) = ark_net::ws::read_head(&mut s, 65536) else { continue };
                h2.lock().unwrap().push(head.clone());
                let sc = script(n, &head);
                std::thread::spawn(move || serve(&mut s, sc));
            }
        });
        FakeNtfy { url, heads }
    }

    fn serve(s: &mut TcpStream, sc: Script) {
        match sc {
            Script::Status(code) => {
                let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
            }
            Script::Plain(lines) => {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n");
                for l in lines {
                    let _ = s.write_all(format!("{l}\n").as_bytes());
                }
            }
            Script::Chunked(status, lines, hold) => {
                let _ = s.write_all(format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-ndjson\r\n\r\n").as_bytes());
                for l in lines {
                    let data = format!("{l}\n");
                    // Split each line across two chunks to exercise reassembly.
                    let (a, b) = data.split_at(data.len() / 2);
                    let _ = s.write_all(format!("{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n", a.len(), b.len()).as_bytes());
                    let _ = s.flush();
                    std::thread::sleep(Duration::from_millis(5));
                }
                std::thread::sleep(hold);
            }
        }
    }

    fn msg(id: &str, text: &str) -> String {
        json!({"id": id, "time": 1700000000, "event": "message", "topic": "inbox", "message": text, "title": "spoofed"}).to_string()
    }

    fn mk(url: &str, token: Option<&str>, state: PathBuf) -> Ntfy {
        let mut n = Ntfy::new("nt", Some(url), "inbox", Some("outbox"), token, state, 1).unwrap();
        n.backoff = vec![Duration::from_millis(20)];
        n.retry_base = Duration::from_millis(5);
        n
    }

    #[test]
    fn auth_header_bearer_basic_and_rfc2047() {
        assert_eq!(auth_header(" tk_abc\n").as_deref(), Some("Bearer tk_abc"));
        assert_eq!(auth_header("amy:pw").as_deref(), Some(format!("Basic {}", ark_net::crypto::b64(b"amy:pw")).as_str()));
        assert_eq!(auth_header("  "), None);
        assert_eq!(header_value("plain"), "plain");
        assert_eq!(header_value("中"), format!("=?UTF-8?B?{}?=", ark_net::crypto::b64("中".as_bytes())));
    }

    #[test]
    fn stream_parses_messages_skips_keepalive_echo_and_resumes_after_restart() {
        let srv = fake(|n, _| match n {
            0 => Script::Chunked(
                "200 OK",
                vec![
                    json!({"id": "o1", "event": "open", "topic": "inbox"}).to_string(),
                    msg("m1", "hello"),
                    json!({"id": "k1", "event": "keepalive", "topic": "inbox"}).to_string(),
                    json!({"id": "e1", "event": "message", "topic": "inbox", "message": "my reply", "tags": [ECHO_TAG]}).to_string(),
                    "not json".into(),
                    msg("m2", "   "),
                    json!({"id": "m3", "event": "message", "topic": "inbox", "message": "photo.jpg", "attachment": {"name": "photo.jpg", "type": "image/jpeg", "size": 12, "url": "https://ntfy.example/file/m3.jpg"}}).to_string(),
                ],
                Duration::from_secs(3),
            ),
            _ => Script::Chunked("200 OK", vec![msg("m4", "after restart")], Duration::from_secs(3)),
        });
        let dir = temp_dir("ntfy");
        let state = dir.join("nt.json");
        let n = mk(&srv.url, Some("tk_SECRET"), state.clone());
        let mut got = Vec::new();
        for _ in 0..5 {
            got.extend(n.poll(&Cancel::new()).unwrap());
            if got.len() >= 2 {
                break;
            }
        }
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].text.as_str(), got[0].message_id.as_str(), got[0].ts, got[0].chat_type), ("inbox", "inbox", "hello", "m1", 1700000000, ChatType::Direct));
        assert_eq!(got[0].sender_name, "inbox", "publisher-controlled title is not identity");
        assert_eq!((got[1].media[0].kind, got[1].media[0].url.as_deref(), got[1].media[0].size), (MediaKind::Image, Some("https://ntfy.example/file/m3.jpg"), 12));
        let head0 = srv.heads.lock().unwrap()[0].clone();
        assert!(head0.starts_with("GET /inbox/json HTTP/1.1"), "{head0}");
        assert!(head0.contains("Authorization: Bearer tk_SECRET"));
        assert!(!std::fs::read_to_string(&state).unwrap_or_default().contains("m3"), "the last batch is committed only on the next poll");
        n.poll(&Cancel::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&state).unwrap(), r#"{"since":"m3"}"#);
        n.stop();
        drop(n);
        // A new process resumes from the persisted id.
        let n2 = mk(&srv.url, Some("tk_SECRET"), state);
        let mut got = Vec::new();
        for _ in 0..5 {
            got.extend(n2.poll(&Cancel::new()).unwrap());
            if !got.is_empty() {
                break;
            }
        }
        assert_eq!(got[0].text, "after restart");
        let heads = srv.heads.lock().unwrap().clone();
        assert!(heads.last().unwrap().starts_with("GET /inbox/json?since=m3 "), "{heads:?}");
        n2.stop();
    }

    #[test]
    fn reconnects_after_drop_with_since_and_plain_bodies() {
        let srv = fake(|n, _| match n {
            0 => Script::Plain(vec![msg("a1", "one")]),
            1 => Script::Status(502),
            _ => Script::Plain(vec![msg("a2", "two")]),
        });
        let n = mk(&srv.url, None, temp_dir("ntfy").join("s.json"));
        let mut got = Vec::new();
        for _ in 0..10 {
            got.extend(n.poll(&Cancel::new()).unwrap());
            if got.len() >= 2 {
                break;
            }
        }
        assert_eq!(got.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        let heads = srv.heads.lock().unwrap().clone();
        assert!(heads[0].starts_with("GET /inbox/json HTTP"));
        assert!(heads[1].starts_with("GET /inbox/json?since=a1 "), "resume after drop: {heads:?}");
        assert!(!heads[0].contains("Authorization"), "no token, no header");
        n.stop();
    }

    #[test]
    fn unauthorized_and_missing_topic_are_fatal() {
        let srv = fake(|_, _| Script::Status(401));
        let n = mk(&srv.url, Some("u:p"), temp_dir("ntfy").join("s.json"));
        let mut err = None;
        for _ in 0..5 {
            match n.poll(&Cancel::new()) {
                Err(e) => {
                    err = Some(e);
                    break;
                }
                Ok(v) => assert!(v.is_empty()),
            }
        }
        let e = err.expect("auth error");
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("u:p"));
        assert_eq!(n.poll(&Cancel::new()).unwrap_err().kind, K::Auth, "sticky");
        assert!(srv.heads.lock().unwrap()[0].contains(&format!("Authorization: Basic {}", ark_net::crypto::b64(b"u:p"))));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(srv.heads.lock().unwrap().len(), 1, "no reconnect after 401");
        let srv = fake(|_, _| Script::Status(404));
        let n = mk(&srv.url, None, temp_dir("ntfy").join("s.json"));
        let e = (0..5).find_map(|_| n.poll(&Cancel::new()).err()).unwrap();
        assert_eq!(e.kind, K::NotFound);
    }

    #[test]
    fn cancel_returns_promptly_and_idle_stream_reconnects() {
        let srv = fake(|_, _| Script::Chunked("200 OK", vec![], Duration::from_secs(5)));
        let mut n = mk(&srv.url, None, temp_dir("ntfy").join("s.json"));
        n.poll_timeout = 30;
        n.idle_timeout = Duration::from_millis(300);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(n.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600), "{:?}", t.elapsed());
        std::thread::sleep(Duration::from_millis(700));
        assert!(srv.heads.lock().unwrap().len() >= 2, "silent stream (no keepalive) is reopened");
        n.stop();
    }

    #[test]
    fn publish_shape_headers_media_buttons_and_echo_ids() {
        let srv = FakeServer::start(|_, n| (200, vec![], json!({"id": format!("p{n}"), "event": "message"}).to_string()));
        let mut n = mk(&srv.url, Some("tk_X"), temp_dir("ntfy").join("s.json"));
        n.markdown = true;
        n.title = Some("Ark 助手".into());
        n.priority = Some("high".into());
        n.tags = vec!["robot".into()];
        let out = Outbound {
            format: TextFormat::Markdown,
            buttons: vec![vec![crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://e.com/d".into()) }, crate::Button { label: "Approve".into(), data: "appr:1".into(), url: None }]],
            ..Outbound::text("inbox", "**hi**")
        };
        assert_eq!(n.send(&out).unwrap().ids, ["p0"]);
        let r = &srv.requests()[0];
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/outbox"), "inbound topic maps to publish_topic");
        assert_eq!(r.header("authorization"), Some("Bearer tk_X"));
        assert_eq!(r.header("x-tags"), Some("ark-agent,robot"));
        assert_eq!(r.header("x-markdown"), Some("true"));
        assert_eq!(r.header("x-priority"), Some("high"));
        assert_eq!(r.header("x-title"), Some(format!("=?UTF-8?B?{}?=", ark_net::crypto::b64("Ark 助手".as_bytes())).as_str()));
        assert_eq!(r.header("x-actions"), Some("view, Docs, https://e.com/d"));
        assert_eq!(r.body, "**hi**\n\n1. Approve");
        assert!(r.header("content-type").unwrap().starts_with("text/plain"));
        // Plain mode: markdown is flattened, no X-Markdown; explicit chat = other topic; silent = low.
        n.markdown = false;
        n.send(&Outbound { format: TextFormat::Markdown, silent: true, ..Outbound::text("alerts", "**bold**") }).unwrap();
        let r = &srv.requests()[1];
        assert_eq!((r.path.as_str(), r.body.as_str(), r.header("x-markdown"), r.header("x-priority")), ("/alerts", "bold", None, Some("low")));
        // Attachment by URL: X-Attach + caption body.
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), name: "a.png".into(), ..Default::default() };
        assert_eq!(n.send(&Outbound { media: vec![img], ..Outbound::text("inbox", "look") }).unwrap().ids, ["p2"]);
        let r = &srv.requests()[2];
        assert_eq!((r.header("x-attach"), r.header("x-filename"), r.body.as_str()), (Some("https://e.com/a.png"), Some("a.png"), "look"));
        // Local file: PUT upload with Filename and the caption as X-Message.
        let f = temp_dir("ntfy").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let doc = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() };
        n.send(&Outbound { media: vec![doc], ..Outbound::text("inbox", "報告") }).unwrap();
        let r = &srv.requests()[3];
        assert_eq!((r.method.as_str(), r.body.as_str(), r.header("x-filename"), r.header("content-type")), ("PUT", "%PDF-1", Some("report.pdf"), Some("application/pdf")));
        assert_eq!(r.header("x-message"), Some(format!("=?UTF-8?B?{}?=", ark_net::crypto::b64("報告".as_bytes())).as_str()));
        // Long text splits at 4096 chars.
        let long = "word ".repeat(1200);
        assert_eq!(n.send(&Outbound::text("inbox", &long)).unwrap().ids.len(), 2);
        // Published ids are dropped if they come back without the tag.
        let sent = n.shared.sent.lock().unwrap().clone();
        assert!(sent.contains(&"p0".to_string()));
        assert!(inbound_of("nt", "inbox", &json!({"id": "p0", "event": "message", "message": "x"}), &sent).is_none());
        assert!(inbound_of("nt", "inbox", &json!({"id": "zz", "event": "message", "message": "x"}), &sent).is_some());
    }

    #[test]
    fn publish_errors_map_and_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let srv = FakeServer::start(move |req, _| {
            c2.fetch_add(1, Ordering::SeqCst);
            match req.path.as_str() {
                "/bad" => (401, vec![], r#"{"code":40101,"error":"unauthorized"}"#.into()),
                "/gone" => (404, vec![], "{}".into()),
                "/slow" => (429, vec![("Retry-After".into(), "120".into())], r#"{"code":42901}"#.into()),
                "/flaky" if c2.load(Ordering::SeqCst) < 6 => (503, vec![], "".into()),
                _ => (200, vec![], r#"{"id":"ok1"}"#.into()),
            }
        });
        let n = mk(&srv.url, Some("tk_SECRET"), temp_dir("ntfy").join("s.json"));
        let e = n.send(&Outbound::text("bad", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("tk_SECRET"));
        assert_eq!(n.send(&Outbound::text("gone", "x")).unwrap_err().kind, K::NotFound);
        let e = n.send(&Outbound::text("slow", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(120)) }, "long retry_after surfaces");
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(n.send(&Outbound::text("flaky", "x")).unwrap().ids, ["ok1"], "5xx retried");
        assert!(calls.load(Ordering::SeqCst) - before >= 2);
    }

    #[test]
    fn fetch_media_sends_auth_only_to_own_server_and_build_validates() {
        let srv = FakeServer::start(|req, _| (200, vec![], format!("auth={}", req.header("authorization").unwrap_or("-"))));
        let n = mk(&srv.url, Some("tk_Z"), temp_dir("ntfy").join("s.json"));
        let m = Media { url: Some(format!("{}/file/x.png", srv.url)), ..Default::default() };
        assert_eq!(n.fetch_media(&m).unwrap(), b"auth=Bearer tk_Z");
        let other = srv.url.replace("127.0.0.1", "localhost");
        let m = Media { url: Some(format!("{other}/file/x.png")), ..Default::default() };
        assert_eq!(n.fetch_media(&m).unwrap(), b"auth=-");
        let d = temp_dir("ntfy");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:NT}}", "tk_1"));
        let ctx = crate::config::Ctx { name: "nt", state_dir: &d, secrets: &secrets };
        let mk_s = |v: Value| v.as_object().unwrap().clone();
        let ch = build(&ctx, &mk_s(json!({"topic": "inbox", "token": "{{secret:NT}}", "markdown": true}))).unwrap();
        assert_eq!(ch.caps().markup, Markup::Markdown);
        assert!(build(&ctx, &mk_s(json!({}))).err().unwrap().contains("topic"));
        assert!(build(&ctx, &mk_s(json!({"topic": "a/b"}))).err().unwrap().contains("topic"));
        assert!(build(&ctx, &mk_s(json!({"topic": "a", "priority": "9"}))).err().unwrap().contains("priority"));
        assert!(build(&ctx, &mk_s(json!({"topic": "a", "tokn": "x"}))).err().unwrap().contains("tokn"));
        assert!(build(&ctx, &mk_s(json!({"topic": "a", "token": "{{secret:NOPE}}"}))).err().unwrap().contains("not set"));
    }
}
