//! Signal through signal-cli (ported from OpenClaw `extensions/signal` and Hermes
//! `plugins/platforms/signal`, both MIT).
//!
//! Two transports, chosen by `mode`:
//! - `native` (default): the signal-cli HTTP daemon (`signal-cli daemon --http`).
//!   Receive: SSE `GET /api/v1/events?account=…` (chunked or plain, reconnect
//!   with backoff). Send: JSON-RPC `POST /api/v1/rpc` — `send` (recipient or
//!   groupId, `quoteTimestamp`/`quoteAuthor` replies, attachments as base64
//!   data URIs or local paths, `text-style` ranges from Markdown,
//!   `editTimestamp` edits), `sendTyping`, `sendReaction`, `remoteDelete`,
//!   `sendReceipt`, `getAttachment`; health `GET /api/v1/check`.
//! - `container`: the bbernhard `signal-cli-rest-api` container (json-rpc mode).
//!   Receive: WebSocket `/v1/receive/{account}`. Send `POST /v2/send`
//!   (`group.<base64>` recipients, `base64_attachments`, styled text),
//!   `/v1/typing-indicator`, `/v1/reactions`, `/v1/remote-delete`,
//!   `/v1/receipts`, `/v1/attachments/{id}`, health `/v1/about`.
//!
//! Chats: a DM is the peer's number (or uuid), a group is `group:<groupId>`.
//! Message ids are Signal timestamps (ms). Mentions of our number/uuid, quotes
//! (→ replies, ours when the quoted author is us), edits, attachments and
//! Note-to-Self are parsed; stories, typing, receipts, reactions and deletes
//! are ignored. Phone numbers are redacted in errors.

use crate::http::{classify, Http, Payload};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";
pub const MAX_MESSAGE: usize = 4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Native,
    Container,
}

// ---------------------------------------------------------------------------
// Markdown → Signal text styles.

const BOLD: u8 = 1;
const ITALIC: u8 = 2;
const STRIKE: u8 = 4;
const MONO: u8 = 8;
const SPOILER: u8 = 16;
const STYLES: [(u8, &str, &str); 5] = [(BOLD, "BOLD", "**"), (ITALIC, "ITALIC", "*"), (STRIKE, "STRIKETHROUGH", "~"), (MONO, "MONOSPACE", "`"), (SPOILER, "SPOILER", "||")];

fn push_seg(out: &mut Vec<(String, u8)>, text: &str, style: u8) {
    if text.is_empty() {
        return;
    }
    match out.last_mut() {
        Some((t, s)) if *s == style => t.push_str(text),
        _ => out.push((text.to_string(), style)),
    }
}

fn find_close(s: &str, marker: &str) -> Option<usize> {
    let mut i = 0;
    while let Some(j) = s[i..].find(marker) {
        let at = i + j;
        if at > 0 && !s[..at].ends_with(char::is_whitespace) {
            return Some(at);
        }
        i = at + marker.len();
    }
    None
}

fn inline(s: &str, style: u8, out: &mut Vec<(String, u8)>) {
    let mut lit = String::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < s.len() {
        let rest = &s[i..];
        let prev_alnum = s[..i].chars().last().is_some_and(char::is_alphanumeric);
        if let Some(r) = rest.strip_prefix('\\') {
            if let Some(c) = r.chars().next().filter(|c| c.is_ascii_punctuation()) {
                lit.push(c);
                i += 1 + c.len_utf8();
                continue;
            }
        }
        if let Some(r) = rest.strip_prefix('`') {
            if let Some(j) = r.find('`') {
                push_seg(out, &std::mem::take(&mut lit), style);
                push_seg(out, &r[..j], style | MONO);
                i += j + 2;
                continue;
            }
        }
        if rest.starts_with('[') {
            if let Some(close) = rest.find("](") {
                if let Some(end) = rest[close + 2..].find(')') {
                    let (label, url) = (&rest[1..close], &rest[close + 2..close + 2 + end]);
                    push_seg(out, &std::mem::take(&mut lit), style);
                    inline(label, style, out);
                    if label != url {
                        push_seg(out, &format!(" ({url})"), style);
                    }
                    i += close + 3 + end;
                    continue;
                }
            }
        }
        let mut matched = false;
        for (m, st) in [("**", BOLD), ("__", BOLD), ("~~", STRIKE), ("||", SPOILER), ("*", ITALIC), ("_", ITALIC)] {
            let Some(r) = rest.strip_prefix(m) else { continue };
            let single = m.len() == 1 || m == "__";
            if r.starts_with(char::is_whitespace) || r.is_empty() || (single && prev_alnum) {
                continue;
            }
            if let Some(j) = find_close(r, m) {
                let after = r[j + m.len()..].chars().next();
                if single && after.is_some_and(char::is_alphanumeric) {
                    continue;
                }
                push_seg(out, &std::mem::take(&mut lit), style);
                inline(&r[..j], style | st, out);
                i += m.len() + j + m.len();
                matched = true;
                break;
            }
        }
        if matched {
            continue;
        }
        let c = rest.chars().next().unwrap_or(b[i] as char);
        lit.push(c);
        i += c.len_utf8();
    }
    push_seg(out, &lit, style);
}

/// CommonMark → styled segments.
fn segments(md: &str) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    let mut lines = md.lines().peekable();
    let mut first = true;
    while let Some(line) = lines.next() {
        if !first {
            push_seg(&mut out, "\n", 0);
        }
        first = false;
        let t = line.trim_start();
        if t.starts_with("```") {
            let mut body = Vec::new();
            for l in lines.by_ref() {
                if l.trim_start().starts_with("```") {
                    break;
                }
                body.push(l);
            }
            push_seg(&mut out, &body.join("\n"), MONO);
            continue;
        }
        let hashes = t.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
            inline(t[hashes..].trim(), BOLD, &mut out);
            continue;
        }
        let indent = &line[..line.len() - t.len()];
        if let Some(r) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).or_else(|| t.strip_prefix("+ ")) {
            push_seg(&mut out, &format!("{indent}• "), 0);
            inline(r, 0, &mut out);
            continue;
        }
        push_seg(&mut out, indent, 0);
        inline(t, 0, &mut out);
    }
    out
}

/// (plain text, `start:length:STYLE` ranges in UTF-16 units) for signal-cli.
pub fn to_styles(md: &str) -> (String, Vec<String>) {
    let mut text = String::new();
    let mut ranges = Vec::new();
    let mut pos = 0usize;
    for (t, st) in segments(md) {
        let len = t.encode_utf16().count();
        for (bit, name, _) in STYLES {
            if st & bit != 0 {
                ranges.push(format!("{pos}:{len}:{name}"));
            }
        }
        pos += len;
        text.push_str(&t);
    }
    (text, ranges)
}

/// Markdown → the container's `text_mode: "styled"` markup (literal markers escaped).
pub fn to_container_styled(md: &str) -> String {
    let mut out = String::new();
    for (t, st) in segments(md) {
        let marks: Vec<&str> = STYLES.iter().filter(|(b, _, _)| st & b != 0).map(|(_, _, m)| *m).collect();
        for m in &marks {
            out.push_str(m);
        }
        for c in t.chars() {
            if matches!(c, '*' | '~' | '`' | '|') {
                out.push('\\');
            }
            out.push(c);
        }
        for m in marks.iter().rev() {
            out.push_str(m);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Receive transports (background thread → mpsc).

#[derive(Default)]
struct Chunked {
    buf: Vec<u8>,
    remaining: usize,
    crlf: bool,
}

impl Chunked {
    /// Decode what is complete; false once the terminal chunk arrives.
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> bool {
        self.buf.extend_from_slice(data);
        loop {
            if self.remaining > 0 {
                let n = self.remaining.min(self.buf.len());
                if n == 0 {
                    return true;
                }
                out.extend(self.buf.drain(..n));
                self.remaining -= n;
                self.crlf = self.remaining == 0;
            } else if self.crlf {
                if self.buf.len() < 2 {
                    return true;
                }
                self.buf.drain(..2);
                self.crlf = false;
            } else {
                let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") else { return true };
                let line = String::from_utf8_lossy(&self.buf[..i]).to_string();
                self.buf.drain(..i + 2);
                let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
                if size == 0 {
                    return false;
                }
                self.remaining = size;
            }
        }
    }
}

#[derive(Default)]
struct Sse {
    line: Vec<u8>,
    data: Vec<String>,
}

impl Sse {
    fn feed(&mut self, bytes: &[u8], tx: &Sender<Value>) {
        for &b in bytes {
            if b != b'\n' {
                self.line.push(b);
                continue;
            }
            let l = String::from_utf8_lossy(&self.line).trim_end_matches('\r').to_string();
            self.line.clear();
            if l.is_empty() {
                if !self.data.is_empty() {
                    if let Ok(v) = serde_json::from_str::<Value>(&self.data.join("\n")) {
                        let _ = tx.send(v);
                    }
                    self.data.clear();
                }
            } else if let Some(d) = l.strip_prefix("data:") {
                self.data.push(d.strip_prefix(' ').unwrap_or(d).to_string());
            }
        }
    }
}

/// GET a long-lived streaming body (chunked or plain) and hand decoded bytes to `on_bytes`
/// until EOF, an error, or `stop`. `ok` is set once the server answered 200.
pub(crate) fn http_stream(base: &seagent_net::Url, path: &str, headers: &[(&str, &str)], stop: &AtomicBool, ok: &mut bool, on_bytes: &mut dyn FnMut(&[u8])) -> Result<(), String> {
    let mut s = seagent_net::Stream::connect(&base.host, base.port, base.tls(), Duration::from_secs(10)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: seagent\r\nCache-Control: no-cache\r\n", base.host_header());
    for (k, v) in headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            return Err("header contains a newline".into());
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let (head, rest) = seagent_net::ws::read_head(&mut s, 64 * 1024).map_err(|e| e.to_string())?;
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(format!("{path}: HTTP {status}"));
    }
    *ok = true;
    let chunked = seagent_net::ws::header(&head, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    s.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
    let (mut dec, mut body) = (Chunked::default(), Vec::new());
    let mut feed = |data: &[u8]| -> bool {
        let more = if chunked { dec.feed(data, &mut body) } else {
            body.extend_from_slice(data);
            true
        };
        on_bytes(&body);
        body.clear();
        more
    };
    if !feed(&rest) {
        return Ok(());
    }
    let mut buf = [0u8; 16 * 1024];
    while !stop.load(Ordering::SeqCst) {
        match s.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if !feed(&buf[..n]) {
                    return Ok(());
                }
            }
            Err(e) if seagent_net::stream::is_timeout(&e) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn sse_session(base: &seagent_net::Url, path: &str, stop: &AtomicBool, tx: &Sender<Value>, ok: &mut bool) -> Result<(), String> {
    let mut sse = Sse::default();
    http_stream(base, path, &[("Accept", "text/event-stream")], stop, ok, &mut |b| sse.feed(b, tx))
}

fn ws_session(url: &str, stop: &AtomicBool, tx: &Sender<Value>, ok: &mut bool) -> Result<(), String> {
    use seagent_net::ws::{Message, WebSocket};
    let (mut ws, _) = WebSocket::connect(url, &[], Duration::from_secs(10)).map_err(|e| e.to_string())?;
    *ok = true;
    ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
    let mut last = Instant::now();
    while !stop.load(Ordering::SeqCst) {
        match ws.recv() {
            Ok(Some(Message::Text(t))) => {
                last = Instant::now();
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    let _ = tx.send(v);
                }
            }
            Ok(Some(Message::Close(_))) => return Ok(()),
            Ok(Some(_)) => last = Instant::now(),
            Ok(None) => {
                // Keepalive so a dead peer is noticed.
                if last.elapsed() > Duration::from_secs(30) {
                    ws.send(&Message::Ping(b"seagent".to_vec())).map_err(|e| e.to_string())?;
                    last = Instant::now();
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn receiver(mode: Mode, base: String, account: String, stop: Arc<AtomicBool>, tx: Sender<Value>) {
    let mut backoff = Duration::from_millis(300);
    while !stop.load(Ordering::SeqCst) {
        let mut ok = false;
        let _ = match mode {
            Mode::Native => match seagent_net::Url::parse(&base) {
                Ok(u) => {
                    let prefix = u.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
                    sse_session(&u, &format!("{prefix}/api/v1/events?account={}", seagent_net::urlencode(&account)), &stop, &tx, &mut ok)
                }
                Err(e) => Err(e),
            },
            Mode::Container => {
                let ws = base.replacen("http", "ws", 1);
                ws_session(&format!("{ws}/v1/receive/{}", seagent_net::urlencode(&account)), &stop, &tx, &mut ok)
            }
        };
        if ok {
            backoff = Duration::from_millis(300);
        }
        let until = Instant::now() + backoff;
        while Instant::now() < until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

// ---------------------------------------------------------------------------
// The channel.

/// signal-cli JSON-RPC error → classified error (phone numbers redacted).
fn rpc_err(method: &str, e: &Value) -> ChannelError {
    let msg = crate::sms::redact_phones_in(e["message"].as_str().unwrap_or("signal-cli error"));
    let code = e["code"].as_i64().unwrap_or(0);
    let text = format!("signal {method}: {msg} ({code})");
    let low = msg.to_ascii_lowercase();
    let kind = if low.contains("ratelimit") || low.contains("rate limit") || low.contains("429") {
        K::RateLimited { retry_after: None }
    } else if low.contains("unregistered") || low.contains("not a member") || low.contains("group not found") || low.contains("invalid group") || low.contains("unknown group") {
        K::NotFound
    } else if low.contains("authorization") || low.contains("not registered") || low.contains("account does not exist") || low.contains("no account") {
        K::Auth
    } else if code == -32601 {
        K::Unsupported
    } else if low.contains("network") || low.contains("timeout") || low.contains("ioexception") {
        K::Network
    } else {
        K::Protocol
    };
    ChannelError::new(kind, text)
}

/// Per-recipient `results[]` of a send: all failed → the first failure's kind.
fn check_results(r: &Value) -> Result<(), ChannelError> {
    let Some(rs) = r["results"].as_array().filter(|a| !a.is_empty()) else { return Ok(()) };
    if rs.iter().any(|x| x["type"] == "SUCCESS") {
        return Ok(());
    }
    let t = rs[0]["type"].as_str().unwrap_or("");
    let kind = match t {
        "UNREGISTERED_FAILURE" => K::NotFound,
        "RATE_LIMIT_FAILURE" => K::RateLimited { retry_after: None },
        "NETWORK_FAILURE" => K::Network,
        _ => K::Protocol,
    };
    Err(ChannelError::new(kind, format!("signal send: {t}")))
}

fn media_kind(mime: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" if mime.contains("gif") => MediaKind::Animation,
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Voice,
        _ => MediaKind::Document,
    }
}

/// `\u{FFFC}` placeholders → `@number` (UTF-16 offsets, from the end).
fn render_mentions(text: &str, mentions: &[Value]) -> String {
    if mentions.is_empty() || !text.contains('\u{FFFC}') {
        return text.to_string();
    }
    let mut u: Vec<u16> = text.encode_utf16().collect();
    let mut ms: Vec<&Value> = mentions.iter().collect();
    ms.sort_by_key(|m| std::cmp::Reverse(m["start"].as_u64().unwrap_or(0)));
    for m in ms {
        let (start, len) = (m["start"].as_u64().unwrap_or(0) as usize, m["length"].as_u64().unwrap_or(1) as usize);
        if start + len > u.len() {
            continue;
        }
        let who = m["number"].as_str().or_else(|| m["uuid"].as_str()).or_else(|| m["name"].as_str()).unwrap_or("user");
        let rep: Vec<u16> = format!("@{who}").encode_utf16().collect();
        u.splice(start..start + len, rep);
    }
    String::from_utf16_lossy(&u)
}

pub struct Signal {
    id: String,
    account: String,
    account_uuid: Option<String>,
    base: String,
    mode: Mode,
    http: Http,
    poll_timeout: u64,
    attach_paths: bool,
    attachments_dir: Option<PathBuf>,
    read_receipts: bool,
    /// Feeds the receive queue (the receiver thread holds a clone; tests inject envelopes).
    #[cfg_attr(not(test), allow(dead_code))]
    tx: Sender<Value>,
    rx: Mutex<Receiver<Value>>,
    stop: Arc<AtomicBool>,
    /// (chat, timestamp, author, text) of recent messages, for quotes and reactions.
    seen: Mutex<VecDeque<(String, String, String, String)>>,
}

impl Drop for Signal {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Signal {
    fn is_me(&self, who: &str) -> bool {
        !who.is_empty() && (who == self.account || self.account_uuid.as_deref().is_some_and(|u| u == who || who.strip_prefix("uuid:") == Some(u)))
    }

    fn remember(&self, chat: &str, ts: &str, author: &str, text: &str) {
        let mut s = self.seen.lock().unwrap();
        s.push_back((chat.to_string(), ts.to_string(), author.to_string(), text.chars().take(200).collect()));
        while s.len() > 2000 {
            s.pop_front();
        }
    }

    fn lookup(&self, chat: &str, ts: &str) -> Option<(String, String)> {
        self.seen.lock().unwrap().iter().rev().find(|(c, t, _, _)| c == chat && t == ts).map(|(_, _, a, x)| (a.clone(), x.clone()))
    }

    /// One envelope (`{envelope: …}` or bare) → Inbound.
    fn inbound_of(&self, v: &Value) -> Option<Inbound> {
        let env = if v["envelope"].is_object() { &v["envelope"] } else { v };
        if v["account"].as_str().is_some_and(|a| a != self.account) {
            return None;
        }
        let sender = env["sourceNumber"].as_str().or_else(|| env["sourceUuid"].as_str()).or_else(|| env["source"].as_str()).unwrap_or("").to_string();
        if sender.is_empty() || env.get("storyMessage").is_some() {
            return None;
        }
        let mut edited = false;
        let mut edit_target = None;
        let mut note_to_self = false;
        let dm = if env["dataMessage"].is_object() {
            &env["dataMessage"]
        } else if env["editMessage"]["dataMessage"].is_object() {
            edited = true;
            edit_target = env["editMessage"]["targetSentTimestamp"].as_i64();
            &env["editMessage"]["dataMessage"]
        } else if env["syncMessage"]["sentMessage"].is_object() {
            // Note to Self typed on another device; our own sends echo back here too.
            let sm = &env["syncMessage"]["sentMessage"];
            let dest = sm["destinationNumber"].as_str().or_else(|| sm["destination"].as_str()).unwrap_or("");
            let ts = sm["timestamp"].as_i64().unwrap_or(0).to_string();
            if !self.is_me(dest) || self.lookup(&self.account, &ts).is_some_and(|(a, _)| self.is_me(&a)) {
                return None;
            }
            note_to_self = true;
            sm
        } else {
            return None;
        };
        if self.is_me(&sender) && !note_to_self {
            return None;
        }
        if dm.get("reaction").is_some() || dm.get("remoteDelete").is_some() {
            return None;
        }
        let group = dm["groupInfo"]["groupId"].as_str().or_else(|| dm["groupV2"]["id"].as_str());
        let chat = match group {
            Some(g) => format!("group:{g}"),
            None if note_to_self => self.account.clone(),
            None => sender.clone(),
        };
        let mentions: Vec<Value> = dm["mentions"].as_array().cloned().unwrap_or_default();
        let mentioned = mentions.iter().any(|m| m["number"].as_str().is_some_and(|n| self.is_me(n)) || m["uuid"].as_str().is_some_and(|n| self.is_me(n)));
        let mut text = render_mentions(dm["message"].as_str().unwrap_or(""), &mentions);
        let media: Vec<Media> = dm["attachments"].as_array().into_iter().flatten().filter_map(|a| {
            let mime = a["contentType"].as_str().unwrap_or("application/octet-stream").to_string();
            Some(Media { kind: media_kind(&mime), id: Some(a["id"].as_str()?.to_string()), name: a["filename"].as_str().unwrap_or("").to_string(), mime, size: a["size"].as_u64().unwrap_or(0), caption: a["caption"].as_str().map(str::to_string), ..Default::default() })
        }).collect();
        if dm["sticker"].is_object() && text.is_empty() {
            text = "[sticker]".into();
        }
        if text.trim().is_empty() && media.is_empty() {
            return None;
        }
        let ts = dm["timestamp"].as_i64().or_else(|| env["timestamp"].as_i64()).unwrap_or(0);
        let q = &dm["quote"];
        let reply = q["id"].as_i64().map(|qid| {
            let author = ["authorNumber", "author", "authorUuid", "authorAci", "authorServiceId"].iter().find_map(|k| q[*k].as_str().filter(|s| !s.is_empty())).unwrap_or("").to_string();
            let is_own = self.is_me(&author) || self.lookup(&chat, &qid.to_string()).is_some_and(|(a, _)| self.is_me(&a));
            ReplyRef { id: qid.to_string(), text: q["text"].as_str().unwrap_or("").to_string(), author, is_own }
        });
        let base_id = edit_target.unwrap_or(ts).to_string();
        self.remember(&chat, &base_id, &sender, &text);
        Some(Inbound {
            channel: self.id.clone(),
            chat_type: if group.is_some() { ChatType::Group } else { ChatType::Direct },
            chat_name: dm["groupInfo"]["groupName"].as_str().unwrap_or("").to_string(),
            chat,
            sender_name: env["sourceName"].as_str().unwrap_or("").to_string(),
            sender,
            text,
            message_id: if edited { format!("{base_id}:e{ts}") } else { base_id },
            ts: ts / 1000,
            media,
            mentioned,
            reply,
            edited,
            ..Default::default()
        })
    }

    fn rpc(&self, method: &str, mut params: Value) -> Result<Value, ChannelError> {
        params["account"] = json!(self.account);
        let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": crate::line::uuid4()});
        let r = self.http.call("POST", &format!("{}/api/v1/rpc", self.base), &[], Payload::Json(&body)).map_err(|e| ChannelError::new(e.kind, crate::sms::redact_phones_in(&e.message)))?;
        if r.status == 201 || (r.status == 200 && r.body.trim().is_empty()) {
            return Ok(Value::Null);
        }
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, &format!("signal {method}"), &crate::sms::redact_phones_in(&r.body)));
        }
        let v: Value = serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("signal {method}: bad JSON: {e}")))?;
        if v["error"].is_object() {
            return Err(rpc_err(method, &v["error"]));
        }
        Ok(v["result"].clone())
    }

    fn rest(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ChannelError> {
        let r = self.http.call(method, &format!("{}{path}", self.base), &[], body.map(Payload::Json).unwrap_or(Payload::None)).map_err(|e| ChannelError::new(e.kind, crate::sms::redact_phones_in(&e.message)))?;
        if (200..300).contains(&r.status) {
            return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null));
        }
        let msg = serde_json::from_str::<Value>(&r.body).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_else(|| r.body.chars().take(200).collect());
        let mut e = rpc_err(path, &json!({"message": msg}));
        if e.kind == K::Protocol {
            e = classify(r.status, r.retry_after, &format!("signal {path}"), "");
            e.message = format!("signal {path}: HTTP {} {}", r.status, crate::sms::redact_phones_in(&msg));
        }
        Err(e)
    }

    fn acct(&self) -> String {
        seagent_net::urlencode(&self.account)
    }

    /// Container recipient: number/uuid as is, groups as `group.<base64(id)>`.
    fn container_recipient(chat: &str) -> String {
        match chat.strip_prefix("group:") {
            Some(g) if g.starts_with("group.") => g.to_string(),
            Some(g) => format!("group.{}", seagent_net::crypto::b64(g.as_bytes())),
            None => chat.strip_prefix("uuid:").unwrap_or(chat).to_string(),
        }
    }

    fn target(chat: &str, params: &mut Value) {
        match chat.strip_prefix("group:") {
            Some(g) => params["groupId"] = json!(g),
            None => params["recipient"] = json!([chat]),
        }
    }

    fn attachment(&self, m: &Media, data_uri: bool) -> Result<String, ChannelError> {
        if let (Some(p), false) = (&m.path, data_uri) {
            return std::fs::canonicalize(p).map(|p| p.display().to_string()).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")));
        }
        let (bytes, name) = match (&m.path, &m.url) {
            (Some(p), _) => (std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?, crate::line::file_name(p)),
            (None, Some(u)) => (crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?, u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let name = if m.name.is_empty() { name } else { m.name.clone() };
        let mime = if m.mime.is_empty() { crate::line::guess_mime(&name).to_string() } else { m.mime.clone() };
        Ok(format!("data:{mime};filename={};base64,{}", name.replace([',', ';', '#'], "_"), seagent_net::crypto::b64(&bytes)))
    }

    /// One message: text (Markdown already handled by the caller), attachments, quote, edit.
    fn send_one(&self, chat: &str, md: &str, markdown: bool, attachments: &[String], quote: Option<(i64, String, String)>, edit: Option<i64>) -> Result<String, ChannelError> {
        let ts = match self.mode {
            Mode::Native => {
                let (text, styles) = if markdown { to_styles(md) } else { (md.to_string(), vec![]) };
                let mut p = json!({"message": text});
                if !styles.is_empty() {
                    p["text-style"] = json!(styles);
                }
                if !attachments.is_empty() {
                    p["attachments"] = json!(attachments);
                }
                if let Some(e) = edit {
                    p["editTimestamp"] = json!(e);
                }
                Self::target(chat, &mut p);
                let mut with_quote = p.clone();
                if let Some((qt, qa, qm)) = &quote {
                    with_quote["quoteTimestamp"] = json!(qt);
                    with_quote["quoteAuthor"] = json!(qa);
                    with_quote["quoteMessage"] = json!(qm);
                }
                let r = match self.rpc("send", with_quote) {
                    // signal-cli rejects quotes it cannot resolve; send without one.
                    Err(e) if quote.is_some() && e.kind == K::Protocol && e.message.to_ascii_lowercase().contains("quote") => self.rpc("send", p)?,
                    r => r?,
                };
                check_results(&r)?;
                r["timestamp"].as_i64()
            }
            Mode::Container => {
                let mut p = json!({"number": self.account, "recipients": [Self::container_recipient(chat)]});
                if markdown {
                    p["message"] = json!(to_container_styled(md));
                    p["text_mode"] = json!("styled");
                } else {
                    p["message"] = json!(md);
                }
                if !attachments.is_empty() {
                    p["base64_attachments"] = json!(attachments);
                }
                if let Some((qt, qa, qm)) = &quote {
                    p["quote_timestamp"] = json!(qt);
                    p["quote_author"] = json!(qa.strip_prefix("uuid:").unwrap_or(qa));
                    p["quote_message"] = json!(qm);
                }
                if let Some(e) = edit {
                    p["edit_timestamp"] = json!(e);
                }
                let r = self.rest("POST", "/v2/send", Some(&p))?;
                r["timestamp"].as_i64().or_else(|| r["timestamp"].as_str().and_then(|s| s.parse().ok()))
            }
        };
        let id = ts.map(|t| t.to_string()).unwrap_or_default();
        if !id.is_empty() {
            self.remember(chat, &id, &self.account, md);
        }
        Ok(id)
    }

    /// Health: `GET /api/v1/check` (native) or `/v1/about` (container).
    pub fn check(&self) -> Result<(), ChannelError> {
        let path = if self.mode == Mode::Native { "/api/v1/check" } else { "/v1/about" };
        self.rest("GET", path, None).map(|_| ())
    }

    fn send_receipts(&self, msgs: &[Inbound]) {
        let targets: Vec<(String, i64)> = msgs.iter().filter(|m| m.chat_type == ChatType::Direct && !m.edited && m.callback.is_none()).filter_map(|m| Some((m.sender.clone(), m.message_id.parse().ok()?))).collect();
        for (to, ts) in targets {
            let _ = match self.mode {
                Mode::Native => self.rpc("sendReceipt", json!({"recipient": [to], "targetTimestamp": [ts], "type": "read"})),
                Mode::Container => self.rest("POST", &format!("/v1/receipts/{}", self.acct()), Some(&json!({"recipient": to, "timestamp": ts, "receipt_type": "read"}))),
            };
        }
    }
}

impl Channel for Signal {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 1,
            edit: true,
            delete: true,
            typing: true,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::Edit,
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
        let out: Vec<Inbound> = got.iter().filter_map(|v| self.inbound_of(v)).collect();
        if self.read_receipts && !out.is_empty() {
            self.send_receipts(&out);
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let markdown = out.format == TextFormat::Markdown;
        let mut text = out.text.clone();
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let data_uri = self.mode == Mode::Container || !self.attach_paths;
        let atts: Vec<String> = out.media.iter().map(|m| self.attachment(m, data_uri)).collect::<Result<_, _>>()?;
        let quote = out.reply_to.as_deref().and_then(|r| {
            let ts: i64 = r.split(':').next()?.parse().ok()?;
            let (author, body) = self.lookup(&out.chat, &ts.to_string()).or_else(|| (!out.chat.starts_with("group:")).then(|| (out.chat.clone(), String::new())))?;
            Some((ts, author, body))
        });
        let mut pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        if pieces.is_empty() && !atts.is_empty() {
            pieces.push(String::new());
        }
        let mut sent = Sent::default();
        for (i, p) in pieces.iter().enumerate() {
            let first = i == 0;
            sent.ids.push(self.send_one(&out.chat, p, markdown, if first { &atts } else { &[] }, if first { quote.clone() } else { None }, None)?);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let ts: i64 = message_id.split(':').next().and_then(|s| s.parse().ok()).ok_or_else(|| ChannelError::new(K::Protocol, "signal message ids are timestamps"))?;
        self.send_one(chat, text, true, &[], None, Some(ts)).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let ts: i64 = message_id.split(':').next().and_then(|s| s.parse().ok()).ok_or_else(|| ChannelError::new(K::Protocol, "signal message ids are timestamps"))?;
        match self.mode {
            Mode::Native => {
                let mut p = json!({"targetTimestamp": ts});
                Self::target(chat, &mut p);
                self.rpc("remoteDelete", p).map(|_| ())
            }
            Mode::Container => self.rest("DELETE", &format!("/v1/remote-delete/{}", self.acct()), Some(&json!({"recipient": Self::container_recipient(chat), "timestamp": ts}))).map(|_| ()),
        }
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        match self.mode {
            Mode::Native => {
                let mut p = json!({});
                Self::target(chat, &mut p);
                self.rpc("sendTyping", p).map(|_| ())
            }
            Mode::Container => self.rest("PUT", &format!("/v1/typing-indicator/{}", self.acct()), Some(&json!({"recipient": Self::container_recipient(chat)}))).map(|_| ()),
        }
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let ts: i64 = message_id.split(':').next().and_then(|s| s.parse().ok()).ok_or_else(|| ChannelError::new(K::Protocol, "signal message ids are timestamps"))?;
        let author = self.lookup(chat, &ts.to_string()).map(|(a, _)| a).or_else(|| (!chat.starts_with("group:")).then(|| chat.to_string())).ok_or_else(|| ChannelError::new(K::NotFound, "signal: unknown author of the message to react to"))?;
        match self.mode {
            Mode::Native => {
                let mut p = json!({"emoji": emoji, "targetAuthor": author, "targetTimestamp": ts});
                if remove {
                    p["remove"] = json!(true);
                }
                Self::target(chat, &mut p);
                self.rpc("sendReaction", p).map(|_| ())
            }
            Mode::Container => {
                let rec = Self::container_recipient(chat);
                let mut p = json!({"recipient": rec, "reaction": emoji, "target_author": author.strip_prefix("uuid:").unwrap_or(&author), "timestamp": ts});
                if chat.starts_with("group:") {
                    p["group_id"] = json!(rec);
                }
                self.rest(if remove { "DELETE" } else { "POST" }, &format!("/v1/reactions/{}", self.acct()), Some(&p)).map(|_| ())
            }
        }
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let id = m.id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "signal attachment without id"))?;
        if id.contains('/') || id.contains("..") {
            return Err(ChannelError::new(K::Protocol, "bad attachment id"));
        }
        if let Some(d) = &self.attachments_dir {
            if let Ok(b) = std::fs::read(d.join(id)) {
                return Ok(b);
            }
        }
        match self.mode {
            Mode::Native => {
                let r = self.rpc("getAttachment", json!({"id": id}))?;
                let b64 = r["data"].as_str().or_else(|| r.as_str()).ok_or_else(|| ChannelError::new(K::NotFound, "signal getAttachment returned no data"))?;
                seagent_net::crypto::b64_decode(b64).ok_or_else(|| ChannelError::new(K::Protocol, "signal getAttachment: bad base64"))
            }
            Mode::Container => crate::http::get_bytes_trusted(&format!("{}/v1/attachments/{}", self.base, seagent_net::urlencode(id)), &[], 100 * 1024 * 1024, &self.base),
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn d_url() -> String {
    DEFAULT_URL.into()
}
fn d_mode() -> String {
    "native".into()
}
fn d_attach() -> String {
    "data_uri".into()
}
fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Our number (E.164) registered with signal-cli.
    pub account: String,
    #[serde(default)]
    pub account_uuid: Option<String>,
    /// signal-cli daemon (`--http`) or signal-cli-rest-api base URL.
    #[serde(default = "d_url", alias = "http_url")]
    pub url: String,
    /// `native` (signal-cli daemon) or `container` (bbernhard signal-cli-rest-api).
    #[serde(default = "d_mode")]
    pub mode: String,
    /// `data_uri` (works with a remote daemon) or `path` (daemon on this host).
    #[serde(default = "d_attach")]
    pub attachments: String,
    /// signal-cli's attachment directory, read directly when it is local.
    #[serde(default)]
    pub attachments_dir: Option<String>,
    #[serde(default)]
    pub read_receipts: bool,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl Signal {
    pub fn open(id: &str, st: &Settings) -> Result<Signal, String> {
        if st.account.trim().is_empty() {
            return Err(format!("channel {id}: signal needs `account` (your number)"));
        }
        let mode = match st.mode.as_str() {
            "native" | "signal-cli" | "daemon" => Mode::Native,
            "container" | "rest" | "bbernhard" => Mode::Container,
            m => return Err(format!("channel {id}: unknown signal mode `{m}` (native or container)")),
        };
        let attach_paths = match st.attachments.as_str() {
            "path" | "paths" => true,
            "data_uri" | "base64" => false,
            a => return Err(format!("channel {id}: attachments must be `data_uri` or `path`, not `{a}`")),
        };
        let base = st.url.trim().trim_end_matches('/').to_string();
        let base = if base.starts_with("http://") || base.starts_with("https://") { base } else { format!("http://{base}") };
        seagent_net::Url::parse(&base).map_err(|e| format!("channel {id}: signal url: {e}"))?;
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let (b, a, s, t) = (base.clone(), st.account.trim().to_string(), stop.clone(), tx.clone());
        std::thread::Builder::new().name(format!("signal receive {id}")).spawn(move || receiver(mode, b, a, s, t)).map_err(|e| e.to_string())?;
        Ok(Signal {
            id: id.to_string(),
            account: st.account.trim().to_string(),
            account_uuid: st.account_uuid.clone(),
            base,
            mode,
            http: Http::new(Duration::from_secs(60)),
            poll_timeout: st.poll_timeout_secs,
            attach_paths,
            attachments_dir: st.attachments_dir.as_deref().map(crate::whatsapp::expand_home),
            read_receipts: st.read_receipts,
            tx,
            rx: Mutex::new(rx),
            stop,
            seen: Mutex::default(),
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    Ok(Arc::new(Signal::open(ctx.name, &st)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::net::TcpListener;

    const ME: &str = "+15550001111";

    fn sig(url: &str, mode: &str) -> Signal {
        Signal::open("sig", &serde_json::from_value(json!({"account": ME, "account_uuid": "u-me", "url": url, "mode": mode, "poll_timeout_secs": 1})).unwrap()).unwrap()
    }

    fn rpc_ok(result: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"jsonrpc": "2.0", "result": result, "id": "1"}).to_string())
    }

    fn env(v: Value) -> Value {
        json!({"envelope": v, "account": ME})
    }

    fn rpcs(srv: &FakeServer) -> Vec<Value> {
        srv.requests().iter().filter(|r| r.path == "/api/v1/rpc").map(|r| r.json()).collect()
    }

    #[test]
    fn markdown_to_signal_styles() {
        let (t, s) = to_styles("**粗** and *it* `c` ~~x~~ [docs](https://e.com) snake_case 2*3*4");
        assert_eq!(t, "粗 and it c x docs (https://e.com) snake_case 2*3*4");
        assert_eq!(s, vec!["0:1:BOLD", "6:2:ITALIC", "9:1:MONOSPACE", "11:1:STRIKETHROUGH"]);
        let (t, s) = to_styles("# Title\n- 😀 **b**");
        assert_eq!(t, "Title\n• 😀 b");
        assert_eq!(s, vec!["0:5:BOLD", "11:1:BOLD"], "UTF-16 offsets");
        assert_eq!(to_container_styled("**b** a*b"), "**b** a\\*b");
        assert_eq!(render_mentions("hi \u{FFFC} there", &[json!({"start": 3, "length": 1, "number": ME})]), format!("hi @{ME} there"));
    }

    #[test]
    fn parses_envelopes() {
        let srv = FakeServer::start(|_, _| (404, vec![], String::new()));
        let s = sig(&srv.url, "native");
        let tx = s.tx.clone();
        for e in [
            json!({"source": "+886912345678", "sourceNumber": "+886912345678", "sourceName": "Amy", "timestamp": 1700000000123i64, "dataMessage": {"timestamp": 1700000000123i64, "message": "hi"}}),
            json!({"sourceNumber": "+886900000001", "sourceUuid": "u-bob", "timestamp": 2, "dataMessage": {"timestamp": 2000, "message": "\u{FFFC} do it", "groupInfo": {"groupId": "G1==", "groupName": "Team"}, "mentions": [{"start": 0, "length": 1, "uuid": "u-me"}]}}),
            json!({"sourceNumber": "+886900000001", "timestamp": 3, "dataMessage": {"timestamp": 3000, "message": "yes", "groupInfo": {"groupId": "G1=="}, "quote": {"id": 999, "authorNumber": ME, "text": "shall I?"}}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 4, "dataMessage": {"timestamp": 4000, "message": "", "attachments": [{"id": "att1.jpg", "contentType": "image/jpeg", "filename": "a.jpg", "size": 10}]}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 5, "editMessage": {"targetSentTimestamp": 1700000000123i64, "dataMessage": {"timestamp": 5000, "message": "hi (edited)"}}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 6, "storyMessage": {"text": "story"}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 7, "typingMessage": {"action": "STARTED"}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 8, "dataMessage": {"timestamp": 8000, "reaction": {"emoji": "👍", "targetSentTimestamp": 1}}}),
            json!({"sourceNumber": ME, "timestamp": 9, "dataMessage": {"timestamp": 9000, "message": "own"}}),
            json!({"sourceNumber": ME, "timestamp": 10, "syncMessage": {"sentMessage": {"destinationNumber": ME, "timestamp": 10000, "message": "note to self"}}}),
            json!({"sourceNumber": ME, "timestamp": 11, "syncMessage": {"sentMessage": {"destinationNumber": "+886912345678", "timestamp": 11000, "message": "sent from phone"}}}),
            json!({"sourceNumber": "+886912345678", "timestamp": 12, "receiptMessage": {"isRead": true}}),
        ] {
            tx.send(env(e)).unwrap();
        }
        tx.send(json!({"envelope": {"sourceNumber": "+1", "dataMessage": {"timestamp": 1, "message": "other account"}}, "account": "+19998887777"})).unwrap();
        let g = s.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 6, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].sender_name.as_str(), g[0].message_id.as_str(), g[0].ts, g[0].chat_type), ("+886912345678", "Amy", "1700000000123", 1700000000, ChatType::Direct));
        assert!(g[1].mentioned && g[1].chat == "group:G1==" && g[1].chat_type == ChatType::Group && g[1].chat_name == "Team");
        assert_eq!(g[1].text, "@u-me do it");
        let r = g[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "999" && r.text == "shall I?" && g[2].addressed());
        assert_eq!((g[3].media[0].id.as_deref(), g[3].media[0].kind, g[3].media[0].name.as_str()), (Some("att1.jpg"), MediaKind::Image, "a.jpg"));
        assert!(g[4].edited && g[4].message_id == "1700000000123:e5000" && g[4].text == "hi (edited)");
        assert_eq!((g[5].chat.as_str(), g[5].text.as_str()), (ME, "note to self"));
    }

    #[test]
    fn native_send_shapes_and_actions() {
        let srv = FakeServer::start(|req, n| {
            if req.path != "/api/v1/rpc" {
                return (404, vec![], String::new());
            }
            let m = req.json()["method"].as_str().unwrap_or("").to_string();
            match m.as_str() {
                "send" => rpc_ok(json!({"timestamp": 1700000001000i64 + n as i64, "results": [{"type": "SUCCESS"}]})),
                "getAttachment" => rpc_ok(json!({"data": seagent_net::crypto::b64(b"IMG")})),
                _ => rpc_ok(json!({})),
            }
        });
        let s = sig(&srv.url, "native");
        s.tx.send(env(json!({"sourceNumber": "+886900000001", "dataMessage": {"timestamp": 5000, "message": "q", "groupInfo": {"groupId": "G1=="}}}))).unwrap();
        s.poll(&Cancel::new()).unwrap();
        let f = temp_dir("sig").join("r.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        let id = s.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("5000".into()), media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("group:G1==", "**done**") }).unwrap().ids[0].clone();
        let p = rpcs(&srv)[0]["params"].clone();
        assert_eq!(rpcs(&srv)[0]["method"], "send");
        assert_eq!((p["account"].as_str(), p["groupId"].as_str(), p["message"].as_str()), (Some(ME), Some("G1=="), Some("done")));
        assert_eq!(p["text-style"], json!(["0:4:BOLD"]));
        assert_eq!((p["quoteTimestamp"].as_i64(), p["quoteAuthor"].as_str(), p["quoteMessage"].as_str()), (Some(5000), Some("+886900000001"), Some("q")));
        assert_eq!(p["attachments"][0], format!("data:application/pdf;filename=r.pdf;base64,{}", seagent_net::crypto::b64(b"%PDF")));
        assert!(p.get("recipient").is_none());
        // DM text: recipient list; a reply to an unknown DM message quotes the peer.
        s.send(&Outbound { reply_to: Some("42".into()), ..Outbound::text("+886912345678", "hi") }).unwrap();
        let p = rpcs(&srv)[1]["params"].clone();
        assert_eq!((p["recipient"].clone(), p["quoteAuthor"].clone(), p.get("text-style").is_none()), (json!(["+886912345678"]), json!("+886912345678"), true));
        s.edit("group:G1==", &id, "fixed").unwrap();
        s.delete("group:G1==", &id).unwrap();
        s.typing("+886912345678", None).unwrap();
        s.react("group:G1==", "5000", "👍", false).unwrap();
        s.react("+886912345678", "77", "👍", true).unwrap();
        let r = rpcs(&srv);
        assert_eq!((r[2]["params"]["editTimestamp"].as_str().map(str::to_string), r[2]["params"]["editTimestamp"].as_i64()), (None, id.parse().ok()));
        assert_eq!((r[3]["method"].as_str(), r[3]["params"]["targetTimestamp"].as_i64()), (Some("remoteDelete"), id.parse().ok()));
        assert_eq!((r[4]["method"].as_str(), r[4]["params"]["recipient"].clone()), (Some("sendTyping"), json!(["+886912345678"])));
        assert_eq!(r[5]["params"], json!({"account": ME, "emoji": "👍", "targetAuthor": "+886900000001", "targetTimestamp": 5000, "groupId": "G1=="}));
        assert_eq!((r[6]["params"]["remove"].as_bool(), r[6]["params"]["targetAuthor"].as_str()), (Some(true), Some("+886912345678")));
        assert_eq!(s.fetch_media(&Media { id: Some("att1".into()), ..Default::default() }).unwrap(), b"IMG");
        // Local attachment dir wins over RPC.
        let d = temp_dir("sig-att");
        std::fs::write(d.join("att2"), b"LOCAL").unwrap();
        let s2 = Signal::open("s2", &serde_json::from_value(json!({"account": ME, "url": srv.url, "attachments_dir": d.display().to_string(), "attachments": "path"})).unwrap()).unwrap();
        assert_eq!(s2.fetch_media(&Media { id: Some("att2".into()), ..Default::default() }).unwrap(), b"LOCAL");
        assert!(s2.fetch_media(&Media { id: Some("../etc/passwd".into()), ..Default::default() }).is_err());
        s2.send(&Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("+1", "") }).unwrap();
        assert_eq!(rpcs(&srv).last().unwrap()["params"]["attachments"][0], std::fs::canonicalize(&f).unwrap().display().to_string());
    }

    #[test]
    fn native_errors_are_classified_and_redacted() {
        for (err, kind) in [
            (json!({"code": -1, "message": "Failed to send message: +886912345678 UnregisteredUserException"}), K::NotFound),
            (json!({"code": -5, "message": "RateLimitException: Rate limit exceeded"}), K::RateLimited { retry_after: None }),
            (json!({"code": -1, "message": "User +15550001111 is not registered."}), K::Auth),
            (json!({"code": -32601, "message": "Method not implemented"}), K::Unsupported),
            (json!({"code": -32602, "message": "Invalid params"}), K::Protocol),
        ] {
            let e2 = err.clone();
            let srv = FakeServer::start(move |req, _| if req.path == "/api/v1/rpc" { (200, vec![], json!({"jsonrpc": "2.0", "error": e2, "id": "1"}).to_string()) } else { (404, vec![], String::new()) });
            let e = sig(&srv.url, "native").send(&Outbound::text("+886912345678", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{err}");
            assert!(!e.message.contains("912345678") && !e.message.contains("5550001111"), "{}", e.message);
        }
        let srv = FakeServer::start(|req, _| if req.path == "/api/v1/rpc" { rpc_ok(json!({"timestamp": 1, "results": [{"type": "UNREGISTERED_FAILURE"}]})) } else { (404, vec![], String::new()) });
        assert_eq!(sig(&srv.url, "native").send(&Outbound::text("+1", "x")).unwrap_err().kind, K::NotFound);
        let srv = FakeServer::start(|_, _| (401, vec![], "nope".into()));
        assert_eq!(sig(&srv.url, "native").send(&Outbound::text("+1", "x")).unwrap_err().kind, K::Auth);
        // A quote signal-cli cannot resolve is dropped, the message still goes out.
        let srv = FakeServer::start(|req, n| match (req.path.as_str(), n) {
            ("/api/v1/rpc", _) if req.json()["params"].get("quoteTimestamp").is_some() => (200, vec![], json!({"jsonrpc": "2.0", "error": {"code": -1, "message": "Invalid quote: message not found"}, "id": "1"}).to_string()),
            ("/api/v1/rpc", _) => rpc_ok(json!({"timestamp": 7})),
            _ => (404, vec![], String::new()),
        });
        assert_eq!(sig(&srv.url, "native").send(&Outbound { reply_to: Some("1".into()), ..Outbound::text("+1", "x") }).unwrap().ids, vec!["7"]);
        let srv = FakeServer::start(|req, _| if req.path == "/api/v1/check" { (200, vec![], String::new()) } else { (404, vec![], String::new()) });
        sig(&srv.url, "native").check().unwrap();
    }

    #[test]
    fn container_mode_rest_shapes() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/v2/send" => (201, vec![], json!({"timestamp": "1700000002000"}).to_string()),
            "/v1/attachments/att9" => (200, vec![], "BYTES".into()),
            "/v1/about" => (200, vec![], json!({"versions": ["v1", "v2"]}).to_string()),
            p if p.starts_with("/v1/receive/") => (404, vec![], String::new()),
            "/v1/reactions/%2B15550001111" if req.json()["recipient"] == "+2" => (400, vec![], json!({"error": "Unregistered user +2000000000"}).to_string()),
            _ => (204, vec![], String::new()),
        });
        let s = sig(&srv.url, "container");
        let reqs = || srv.requests().into_iter().filter(|r| !r.path.starts_with("/v1/receive")).collect::<Vec<_>>();
        let id = s.send(&Outbound { format: TextFormat::Markdown, media: vec![Media { url: Some(format!("{}/v1/attachments/att9", srv.url)), name: "a.jpg".into(), ..Default::default() }], ..Outbound::text("group:G1==", "**hi** a*b") }).unwrap().ids[0].clone();
        assert_eq!(id, "1700000002000");
        let r = reqs().into_iter().find(|r| r.path == "/v2/send").unwrap().json();
        assert_eq!((r["number"].as_str(), r["recipients"][0].as_str(), r["text_mode"].as_str(), r["message"].as_str()), (Some(ME), Some(format!("group.{}", seagent_net::crypto::b64(b"G1==")).as_str()), Some("styled"), Some("**hi** a\\*b")));
        assert!(r["base64_attachments"][0].as_str().unwrap().starts_with("data:image/jpeg;filename=a.jpg;base64,"));
        s.typing("+886912345678", None).unwrap();
        s.react("+886912345678", "1700000002000", "👍", false).unwrap();
        s.delete("+886912345678", "1700000002000").unwrap();
        s.edit("+886912345678", "1700000002000", "new").unwrap();
        let rs = reqs();
        let n = rs.len();
        assert_eq!((rs[n - 4].method.as_str(), rs[n - 4].path.as_str(), rs[n - 4].json()), ("PUT", "/v1/typing-indicator/%2B15550001111", json!({"recipient": "+886912345678"})));
        assert_eq!((rs[n - 3].method.as_str(), rs[n - 3].json()["target_author"].as_str(), rs[n - 3].json()["reaction"].as_str()), ("POST", Some("+886912345678"), Some("👍")));
        assert_eq!((rs[n - 2].method.as_str(), rs[n - 2].path.as_str()), ("DELETE", "/v1/remote-delete/%2B15550001111"));
        assert_eq!(rs[n - 1].json()["edit_timestamp"], 1700000002000i64);
        assert_eq!(s.fetch_media(&Media { id: Some("att9".into()), ..Default::default() }).unwrap(), b"BYTES");
        let e = s.react("+2", "5", "👍", false).unwrap_err();
        assert!(e.kind == K::NotFound && !e.message.contains("2000000000"), "{e:?}");
        s.check().unwrap();
    }

    /// signal-cli SSE: the first connection is chunked and then dropped, the second is plain.
    #[test]
    fn sse_stream_reconnects_after_drop() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let paths = Arc::new(Mutex::new(Vec::new()));
        let p2 = paths.clone();
        std::thread::spawn(move || {
            for (i, conn) in l.incoming().enumerate() {
                let mut c = conn.unwrap();
                let (head, _) = seagent_net::ws::read_head(&mut c, 8192).unwrap();
                p2.lock().unwrap().push(head.lines().next().unwrap_or("").to_string());
                let ev = |ts: i64, t: &str| format!("event: receive\ndata: {}\n\n", json!({"envelope": {"sourceNumber": "+886912345678", "dataMessage": {"timestamp": ts, "message": t}}, "account": ME}));
                if i == 0 {
                    c.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
                    let body = format!(":keepalive\n\n{}", ev(1000, "one"));
                    let (a, b) = body.split_at(body.len() / 2);
                    for part in [a, b] {
                        c.write_all(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes()).unwrap();
                        c.flush().unwrap();
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    // Dropped without the terminal chunk.
                } else {
                    c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n{}", ev(2000, "two")).as_bytes()).unwrap();
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        });
        let s = sig(&url, "native");
        let mut got = Vec::new();
        let t = Instant::now();
        while got.len() < 2 && t.elapsed() < Duration::from_secs(5) {
            got.extend(s.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(got.iter().map(|i| i.text.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        let p = paths.lock().unwrap().clone();
        assert!(p.len() >= 2 && p[0] == format!("GET /api/v1/events?account={} HTTP/1.1", seagent_net::urlencode(ME)), "{p:?}");
    }

    /// signal-cli-rest-api WebSocket receive, reconnecting after the server closes.
    #[test]
    fn container_websocket_reconnects() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for (i, conn) in l.incoming().enumerate() {
                let mut c = conn.unwrap();
                let (head, rest) = seagent_net::ws::read_head(&mut c, 8192).unwrap();
                assert!(head.starts_with(&format!("GET /v1/receive/{} ", seagent_net::urlencode(ME))), "{head}");
                let mut ws = seagent_net::ws::WebSocket::accept(c, &head, rest).unwrap();
                ws.send_text(&json!({"envelope": {"sourceNumber": "+886912345678", "dataMessage": {"timestamp": 1000 + i, "message": format!("ws{i}")}}, "account": ME}).to_string()).unwrap();
                if i == 0 {
                    ws.send(&seagent_net::ws::Message::Close(Some((1000, "bye".into())))).unwrap();
                } else {
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        });
        let s = sig(&url, "container");
        let mut got = Vec::new();
        let t = Instant::now();
        while got.len() < 2 && t.elapsed() < Duration::from_secs(5) {
            got.extend(s.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(got.iter().map(|i| i.text.as_str()).collect::<Vec<_>>(), ["ws0", "ws1"]);
    }

    #[test]
    fn cancel_returns_promptly() {
        let srv = FakeServer::start(|_, _| (404, vec![], String::new()));
        let s = Signal::open("s", &serde_json::from_value(json!({"account": ME, "url": srv.url, "poll_timeout_secs": 30})).unwrap()).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(s.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        assert!(Signal::open("s", &serde_json::from_value(json!({"account": ME, "mode": "carrier"})).unwrap()).is_err());
    }
}
