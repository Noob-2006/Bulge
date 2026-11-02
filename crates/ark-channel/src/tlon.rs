//! Tlon / Urbit (ported from OpenClaw `extensions/tlon`, MIT).
//!
//! Auth: `POST /~/login` with the ship's `+code` (`password=<code>`) → `urbauth-~ship`
//! cookie; any 401/403 later triggers a fresh login. Transport is an Eyre HTTP channel
//! `/~/channel/<uid>`: `PUT` carries subscribe / poke / ack / delete actions, a long
//! `GET` streams Server-Sent Events. Events are acked (`{"action":"ack","event-id":N}`)
//! once more than `ack_threshold` are outstanding so Eyre's queue stays bounded. When the
//! stream ends or stalls (no bytes for 60 s; Eyre heartbeats every 20 s) the same channel
//! is reopened, keeping unacked events; a 404 means Eyre reaped it, so a new uid is
//! created and every subscription re-sent. A `quit` re-subscribes.
//!
//! Receive: the `channels /v2` firehose (group chat posts and thread replies, filtered to
//! `group_channels` when set) and the `chat /v3` firehose (DMs, group DMs / clubs, and
//! DM-invite snapshots, optionally auto-accepted with `chat-dm-rsvp`). Story content is
//! rendered to text (inline styles, ship mentions, code, quotes, citations) and image
//! blocks become media. Mentions: `@all`, the bot's `~ship`, or its contacts nickname
//! (scried from `/contacts/v1/self.json`). A thread reply is addressed to the bot when the
//! bot authored the thread root (scry `/channels/v4/<nest>/posts/post/id/<ud>.json`) or
//! has already replied in it. Club authors are unverified, so their sender id is
//! `club:<id>:<ship>` and replies go to the author's DM, as upstream.
//! Send: Markdown → Story (`chat-dm-action` for DMs, `channel-action-1` for group posts
//! and thread replies), media URLs as image blocks or links, buttons as numbered options.
//! Local files are uploaded to the ship's `%storage` bucket first (SigV4-presigned S3
//! `PUT`, or Tlon's Memex service for hosted ships) and sent by their public URL.
//! Targets: `~ship`, `dm/~ship`, `chat/~host/name`, `group:~host/name` (`tlon:` prefix ok).

use crate::http::{classify, Http, Payload};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, TextFormat};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 8000;
const MAX_EVENT: usize = 16 * 1024 * 1024;
const SUB_CHANNELS: u64 = 1;
const SUB_CHAT: u64 = 2;

pub struct Tlon {
    id: String,
    inner: Arc<Inner>,
    poll_timeout: u64,
    rx: Mutex<Receiver<Inbound>>,
    tx: Mutex<Option<Sender<Inbound>>>,
}

struct Inner {
    channel: String,
    base: String,
    ship: String,
    code: String,
    http: Http,
    cookie: Mutex<Option<String>>,
    uid: Mutex<String>,
    next_id: AtomicU64,
    /// (last heard, last acked) event ids on the current channel uid.
    acks: Mutex<(i64, i64)>,
    nickname: Mutex<Option<String>>,
    root_authors: Mutex<HashMap<String, Option<String>>>,
    participated: Mutex<HashSet<String>>,
    /// Thread-reply id → its root, so a reply to a reply lands in the same thread.
    parents: Mutex<(HashMap<String, String>, VecDeque<String>)>,
    group_channels: Vec<String>,
    auto_accept_dm_invites: bool,
    accepted_invites: Mutex<HashSet<String>>,
    stop: AtomicBool,
    fatal: Mutex<Option<ChannelError>>,
    retry_base: Duration,
    max_retries: u32,
    stall: Duration,
    ack_threshold: i64,
}

pub struct Options {
    pub group_channels: Vec<String>,
    pub auto_accept_dm_invites: bool,
    /// First reconnect / retry delay; doubles each attempt (capped at 30 s).
    pub retry_base: Duration,
    pub max_retries: u32,
    pub stall: Duration,
    pub ack_threshold: i64,
}

impl Default for Options {
    fn default() -> Self {
        Options { group_channels: vec![], auto_accept_dm_invites: false, retry_base: Duration::from_secs(1), max_retries: 3, stall: Duration::from_secs(60), ack_threshold: 20 }
    }
}

pub fn normalize_ship(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() || t.starts_with('~') {
        t.to_string()
    } else {
        format!("~{t}")
    }
}

fn is_ship(s: &str) -> bool {
    let b = s.strip_prefix('~').unwrap_or(s);
    !b.is_empty() && b.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

fn now_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// `@da` for a unix-millisecond time, as Urbit's `da.fromUnix`.
pub fn da_from_unix_ms(ms: u128) -> u128 {
    const EPOCH: u128 = 170141184475152167957503069145530368000;
    EPOCH + (ms << 64) / 1000
}

/// `@ud` rendering: digits grouped by dots (`170.141.184…`). Non-numeric input passes through.
pub fn format_ud(s: &str) -> String {
    let d = s.trim();
    if d.is_empty() || !d.chars().all(|c| c.is_ascii_digit()) {
        return s.to_string();
    }
    let d = d.trim_start_matches('0');
    let d = if d.is_empty() { "0" } else { d };
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(c);
    }
    out
}

/// Outbound target: a DM ship or a chat channel nest.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Dm(String),
    Group { host: String, name: String },
}

pub fn parse_target(raw: &str) -> Option<Target> {
    let t = raw.trim();
    let t = t.strip_prefix("tlon:").or_else(|| t.strip_prefix("TLON:")).unwrap_or(t);
    if let Some(s) = t.strip_prefix("dm/").or_else(|| t.strip_prefix("dm:")) {
        return Some(Target::Dm(normalize_ship(s)));
    }
    let g = ["group:", "group/", "room:", "room/"].iter().find_map(|p| t.strip_prefix(p)).unwrap_or(t);
    let g = g.strip_prefix("chat/").unwrap_or(g);
    if let Some((host, name)) = g.split_once('/') {
        if is_ship(host) && !name.is_empty() && !name.contains('/') {
            return Some(Target::Group { host: normalize_ship(host), name: name.to_string() });
        }
        return None;
    }
    is_ship(t).then(|| Target::Dm(normalize_ship(t)))
}

// ---------- story → text ----------

fn inline_text(item: &Value, top: bool, depth: usize) -> String {
    if let Some(s) = item.as_str() {
        return s.to_string();
    }
    let Some(o) = item.as_object() else { return String::new() };
    if let Some(s) = o.get("ship").and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(sect) = o.get("sect") {
        return match sect.as_str() {
            Some(s) if !s.is_empty() => format!("@{s}"),
            _ => "@all".into(),
        };
    }
    if top && o.contains_key("break") {
        return "\n".into();
    }
    if let Some(c) = o.get("inline-code").or_else(|| o.get("code")).and_then(Value::as_str) {
        return format!("`{c}`");
    }
    if let Some(href) = o.get("link").and_then(|l| l["href"].as_str()) {
        let content = o["link"]["content"].as_str().unwrap_or("");
        return if top || content.is_empty() { href.to_string() } else { content.to_string() };
    }
    if depth >= 16 {
        return String::new();
    }
    for (k, wrap) in [("bold", "**"), ("italics", "*"), ("strike", "~~")] {
        if let Some(a) = o.get(k).and_then(Value::as_array) {
            let inner: String = a.iter().map(|i| inline_text(i, false, depth + 1)).collect();
            return format!("{wrap}{inner}{wrap}");
        }
    }
    if let (true, Some(a)) = (top, o.get("blockquote").and_then(Value::as_array)) {
        let inner: String = a.iter().map(|i| inline_text(i, false, depth + 1)).collect();
        return format!("> {inner}");
    }
    String::new()
}

/// Render Story content (`[{inline: […]}, {block: {…}}]`) to Markdown-ish text.
pub fn story_text(content: &Value) -> String {
    let Some(verses) = content.as_array() else { return String::new() };
    let parts: Vec<String> = verses
        .iter()
        .map(|v| {
            if let Some(inl) = v["inline"].as_array() {
                return inl.iter().map(|i| inline_text(i, true, 0)).collect();
            }
            let b = &v["block"];
            if let Some(src) = b["image"]["src"].as_str() {
                let alt = b["image"]["alt"].as_str().filter(|a| !a.is_empty()).map(|a| format!(" ({a})")).unwrap_or_default();
                return format!("\n{src}{alt}\n");
            }
            if b["code"].is_object() {
                let code = b["code"]["code"].as_str().unwrap_or("");
                let mut n = 3;
                let mut run = 0;
                for c in code.chars() {
                    run = if c == '`' { run + 1 } else { 0 };
                    n = n.max(run + 1);
                }
                let fence = "`".repeat(n);
                return format!("\n{fence}{}\n{code}\n{fence}\n", b["code"]["lang"].as_str().unwrap_or(""));
            }
            if let Some(h) = b["header"]["content"].as_array() {
                return format!("\n## {}\n", h.iter().map(|i| inline_text(i, false, 0)).collect::<String>());
            }
            let cite = &b["cite"];
            if cite.is_object() {
                if let Some(nest) = cite["chan"]["nest"].as_str() {
                    let author = cite["chan"]["where"].as_str().and_then(|w| w.strip_prefix("/msg/")).and_then(|w| w.split('/').next()).filter(|a| a.starts_with('~'));
                    return match author {
                        Some(a) => format!("\n> [quoted: {a} in {nest}]\n"),
                        None => format!("\n> [quoted from {nest}]\n"),
                    };
                }
                if let Some(g) = cite["group"].as_str() {
                    return format!("\n> [ref: group {g}]\n");
                }
                if let Some(f) = cite["desk"]["flag"].as_str() {
                    return format!("\n> [ref: {f}]\n");
                }
                return "\n> [quoted message]\n".into();
            }
            String::new()
        })
        .collect();
    parts.join("\n").trim().to_string()
}

fn story_media(content: &Value) -> Vec<Media> {
    content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["block"]["image"]["src"].as_str())
        .map(|src| Media { kind: MediaKind::Image, url: Some(src.to_string()), name: src.rsplit('/').next().unwrap_or("image").to_string(), ..Default::default() })
        .collect()
}

/// `@all`, the bot's ship as a word, or its nickname followed by a boundary/punctuation.
pub fn is_mentioned(text: &str, ship: &str, nickname: Option<&str>) -> bool {
    let lower = text.to_lowercase();
    let word_at = |needle: &str, extra: &[char]| {
        let needle = needle.to_lowercase();
        lower.match_indices(&needle).any(|(i, _)| {
            let before_ok = lower[..i].chars().next_back().is_none_or(char::is_whitespace);
            let after = lower[i + needle.len()..].chars().next();
            before_ok && after.is_none_or(|c| c.is_whitespace() || extra.contains(&c))
        })
    };
    if lower.match_indices("@all").any(|(i, _)| !lower[i + 4..].chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_')) {
        return true;
    }
    (!ship.is_empty() && word_at(&normalize_ship(ship), &[])) || nickname.filter(|n| !n.trim().is_empty()).is_some_and(|n| word_at(n.trim(), &[',', '!', '?', '.']))
}

// ---------- Markdown → story ----------

fn push_str(out: &mut Vec<Value>, s: &str) {
    if s.is_empty() {
        return;
    }
    if let Some(Value::String(last)) = out.last_mut() {
        last.push_str(s);
    } else {
        out.push(json!(s));
    }
}

fn bare_url(t: &str) -> Option<usize> {
    if !(t.starts_with("http://") || t.starts_with("https://")) {
        return None;
    }
    let mut end = t.find(|c: char| c.is_whitespace() || "<>\"]".contains(c)).unwrap_or(t.len());
    while end > 0 {
        let u = &t[..end];
        let unbalanced = u.matches(')').count() as i64 - u.matches('(').count() as i64;
        let last = u.chars().next_back().unwrap();
        if ".,;:!?(".contains(last) || (last == ')' && unbalanced > 0) {
            end -= 1;
        } else {
            break;
        }
    }
    (end > t.find("://").unwrap() + 3).then_some(end)
}

/// `[text](dest)` → (consumed, text, dest), with balanced parens in dest.
fn md_link(t: &str) -> Option<(usize, &str, &str)> {
    let rest = t.strip_prefix('[')?;
    let close = rest.find("](")?;
    let label = &rest[..close];
    if label.is_empty() || label.contains(']') {
        return None;
    }
    let start = 1 + close + 2;
    let mut depth = 0;
    let bytes = t.as_bytes();
    let mut i = start;
    while i < t.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' if depth == 0 => return (i > start).then(|| (i + 1, label, &t[start..i])),
            b')' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

fn delimited<'a>(t: &'a str, open: &str, close: &str) -> Option<(usize, &'a str)> {
    let rest = t.strip_prefix(open)?;
    let end = rest.find(close)?;
    (end > 0).then(|| (open.len() + end + close.len(), &rest[..end]))
}

/// Inline Markdown → story inlines; images are hoisted into `images` (stories carry them as blocks).
fn parse_inline(text: &str, images: &mut Vec<Value>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut t = text;
    while let Some(c) = t.chars().next() {
        if c == '\n' {
            out.push(json!({"break": null}));
            t = &t[1..];
            continue;
        }
        if c == '~' && t[1..].starts_with(|c: char| c.is_ascii_lowercase()) {
            let end = 1 + t[1..].find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')).unwrap_or(t.len() - 1);
            out.push(json!({"ship": &t[..end]}));
            t = &t[end..];
            continue;
        }
        let styled = delimited(t, "**", "**").map(|(n, b)| (n, "bold", b)).or_else(|| delimited(t, "__", "__").map(|(n, b)| (n, "bold", b))).or_else(|| delimited(t, "~~", "~~").map(|(n, b)| (n, "strike", b))).or_else(|| {
            delimited(t, "*", "*").filter(|(_, b)| !b.contains('*')).map(|(n, b)| (n, "italics", b)).or_else(|| delimited(t, "_", "_").filter(|(n, b)| !b.contains('_') && !t[*n..].starts_with(|c: char| c.is_ascii_alphanumeric())).map(|(n, b)| (n, "italics", b)))
        });
        if let Some((n, kind, body)) = styled {
            let inner = parse_inline(body, images);
            if !inner.is_empty() {
                out.push(json!({ kind: inner }));
            }
            t = &t[n..];
            continue;
        }
        if let Some((n, code)) = delimited(t, "`", "`").filter(|(_, c)| !c.contains('`')) {
            out.push(json!({"inline-code": code}));
            t = &t[n..];
            continue;
        }
        if let Some((n, label, href)) = md_link(t) {
            out.push(json!({"link": {"href": href, "content": label}}));
            t = &t[n..];
            continue;
        }
        if let Some((n, alt, src)) = t.strip_prefix('!').and_then(|r| r.strip_prefix('[').map(|_| r)).and_then(|r| {
            // `![](src)` has an empty label, which md_link refuses.
            let close = r.find("](")?;
            let alt = &r[1..close];
            let rest = &r[close + 2..];
            let end = rest.find(')')?;
            Some((1 + close + 2 + end + 1, alt, &rest[..end]))
        }) {
            images.push(json!({"block": {"image": {"src": src, "height": 0, "width": 0, "alt": alt}}}));
            t = &t[n..];
            continue;
        }
        if let Some(n) = bare_url(t) {
            out.push(json!({"link": {"href": &t[..n], "content": &t[..n]}}));
            t = &t[n..];
            continue;
        }
        let n = t.char_indices().skip(1).find(|(i, ch)| "*_`~[!\nh".contains(*ch) && (*ch != 'h' || bare_url(&t[*i..]).is_some())).map(|(i, _)| i).unwrap_or(t.len());
        push_str(&mut out, &t[..n]);
        t = &t[n..];
    }
    out
}

/// Markdown → Story verses (code fences, headers, rules, quotes, paragraphs with breaks).
pub fn markdown_to_story(md: &str) -> Vec<Value> {
    let lines: Vec<&str> = md.split('\n').collect();
    let mut story = Vec::new();
    let mut i = 0;
    let starts_block = |l: &str| l.starts_with("```") || l.starts_with("> ") || header(l).is_some() || is_rule(l);
    while i < lines.len() {
        let line = lines[i];
        if let Some(lang) = line.strip_prefix("```") {
            let lang = if lang.trim().is_empty() { "plaintext" } else { lang.trim() };
            let mut code = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].starts_with("```") {
                code.push(lines[i]);
                i += 1;
            }
            story.push(json!({"block": {"code": {"code": code.join("\n"), "lang": lang}}}));
            i += 1;
            continue;
        }
        let mut images = Vec::new();
        if let Some((level, body)) = header(line) {
            let content = parse_inline(body, &mut images);
            if !content.is_empty() {
                story.push(json!({"block": {"header": {"tag": format!("h{level}"), "content": content}}}));
            }
            story.append(&mut images);
            i += 1;
            continue;
        }
        if is_rule(line) {
            story.push(json!({"block": {"rule": null}}));
            i += 1;
            continue;
        }
        if line.starts_with("> ") {
            let mut q = Vec::new();
            while i < lines.len() && lines[i].starts_with("> ") {
                q.push(&lines[i][2..]);
                i += 1;
            }
            let inner = parse_inline(&q.join("\n"), &mut images);
            if !inner.is_empty() {
                story.push(json!({"inline": [{"blockquote": inner}]}));
            }
            story.append(&mut images);
            continue;
        }
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let mut para = Vec::new();
        while i < lines.len() && !lines[i].trim().is_empty() && (para.is_empty() || !starts_block(lines[i])) {
            para.push(lines[i]);
            i += 1;
        }
        let inl = parse_inline(&para.join("\n"), &mut images);
        if !inl.is_empty() {
            story.push(json!({ "inline": inl }));
        }
        story.append(&mut images);
    }
    story
}

fn header(l: &str) -> Option<(usize, &str)> {
    let n = l.chars().take_while(|c| *c == '#').count();
    let body = l[n..].strip_prefix(' ')?.trim();
    ((1..=6).contains(&n) && !body.is_empty()).then_some((n, body))
}

fn is_rule(l: &str) -> bool {
    let t = l.trim();
    t.len() >= 3 && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '*'))
}

fn is_image_url(u: &str) -> bool {
    let p = u.split(['?', '#']).next().unwrap_or(u).to_ascii_lowercase();
    [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"].iter().any(|e| p.ends_with(e))
}

fn plain_story(text: &str) -> Vec<Value> {
    text.split("\n\n").filter(|p| !p.trim().is_empty()).map(|p| {
        let mut inl = Vec::new();
        for (i, l) in p.lines().enumerate() {
            if i > 0 {
                inl.push(json!({"break": null}));
            }
            push_str(&mut inl, l);
        }
        json!({ "inline": inl })
    }).collect()
}

// ---------- HTTP plumbing ----------

/// Minimal incremental `Transfer-Encoding: chunked` decoder.
#[derive(Default)]
pub struct Chunked {
    raw: Vec<u8>,
    remaining: usize,
    crlf: bool,
    pub done: bool,
}

impl Chunked {
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        self.raw.extend_from_slice(data);
        loop {
            if self.done {
                return Ok(());
            }
            if self.remaining > 0 {
                let n = self.remaining.min(self.raw.len());
                out.extend(self.raw.drain(..n));
                self.remaining -= n;
                if self.remaining > 0 {
                    return Ok(());
                }
                self.crlf = true;
            }
            if self.crlf {
                if self.raw.len() < 2 {
                    return Ok(());
                }
                self.raw.drain(..2);
                self.crlf = false;
            }
            let Some(p) = self.raw.windows(2).position(|w| w == b"\r\n") else {
                return if self.raw.len() > 1024 { Err("bad chunk header".into()) } else { Ok(()) };
            };
            let line = String::from_utf8_lossy(&self.raw[..p]).to_string();
            self.raw.drain(..p + 2);
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| format!("bad chunk size {line:?}"))?;
            if size == 0 {
                self.done = true;
            } else {
                self.remaining = size;
            }
        }
    }
}

/// SSE framing: blank-line separated events; returns (id, data) pairs.
#[derive(Default)]
pub struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<(Option<i64>, String)>, String> {
        self.buf.extend(data.iter().copied().filter(|b| *b != b'\r'));
        let mut out = Vec::new();
        while let Some(p) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let ev: Vec<u8> = self.buf.drain(..p + 2).collect();
            let ev = String::from_utf8_lossy(&ev[..p]);
            let mut id = None;
            let mut lines = Vec::new();
            for l in ev.split('\n') {
                if let Some(v) = l.strip_prefix("id:") {
                    id = v.trim().parse::<i64>().ok();
                } else if let Some(v) = l.strip_prefix("data:") {
                    lines.push(v.strip_prefix(' ').unwrap_or(v));
                }
            }
            if id.is_some() || !lines.is_empty() {
                out.push((id, lines.join("\n")));
            }
        }
        if self.buf.len() > MAX_EVENT {
            return Err("SSE event exceeds 16 MiB".into());
        }
        Ok(out)
    }
}

fn auth_err(what: &str) -> ChannelError {
    ChannelError::new(K::Auth, format!("tlon: {what}"))
}

impl Inner {
    fn login(&self) -> Result<String, ChannelError> {
        let body = ark_net::form_encode(&[("password", &self.code)]);
        let r = self.http.agent.post(&format!("{}/~/login", self.base)).header("content-type", "application/x-www-form-urlencoded").send(body.as_bytes());
        let mut r = r.map_err(|e| ChannelError::new(K::Network, format!("tlon login: {e}")))?;
        let status = r.status().as_u16();
        let cookies: Vec<String> = r.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()).map(|v| v.split(';').next().unwrap_or("").trim().to_string()).collect();
        let _ = r.body_mut().with_config().limit(64 * 1024).read_to_vec();
        match status {
            200..=399 => {}
            400 | 401 | 403 => return Err(auth_err(&format!("login rejected the +code (HTTP {status})"))),
            s => return Err(classify(s, None, "tlon login", "")),
        }
        let c = cookies.iter().find(|c| c.starts_with("urbauth-")).or_else(|| cookies.first()).filter(|c| !c.is_empty()).cloned().ok_or_else(|| auth_err("login returned no session cookie"))?;
        *self.cookie.lock().unwrap() = Some(c.clone());
        Ok(c)
    }

    fn cookie(&self) -> Result<String, ChannelError> {
        let cached = self.cookie.lock().unwrap().clone();
        match cached {
            Some(c) => Ok(c),
            None => self.login(),
        }
    }

    fn channel_url(&self) -> String {
        format!("{}/~/channel/{}", self.base, self.uid.lock().unwrap())
    }

    fn id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Authenticated request; re-login once on 401/403; retry 5xx/429 with backoff.
    fn request(&self, method: &str, url: &str, body: Option<&Value>, what: &str) -> Result<String, ChannelError> {
        let mut relogged = false;
        let mut attempt = 0;
        loop {
            let cookie = self.cookie()?;
            let payload = body.map(Payload::Json).unwrap_or(Payload::None);
            let err = match self.http.call(method, url, &[("cookie", &cookie)], payload) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(r.body),
                Ok(r) if (r.status == 401 || r.status == 403) && !relogged => {
                    relogged = true;
                    *self.cookie.lock().unwrap() = None;
                    continue;
                }
                Ok(r) if r.status == 401 || r.status == 403 => return Err(auth_err(&format!("{what}: HTTP {} after re-login", r.status))),
                Ok(r) => classify(r.status, r.retry_after, what, &r.body.replace(&cookie, "***")),
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(60) => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            std::thread::sleep(wait);
            attempt += 1;
        }
    }

    fn put(&self, actions: Value, what: &str) -> Result<(), ChannelError> {
        self.request("PUT", &self.channel_url(), Some(&actions), what).map(|_| ())
    }

    fn poke(&self, app: &str, mark: &str, j: Value) -> Result<u64, ChannelError> {
        let id = self.id();
        self.put(json!([{"id": id, "action": "poke", "ship": self.ship.trim_start_matches('~'), "app": app, "mark": mark, "json": j}]), &format!("poke {app} {mark}"))?;
        Ok(id)
    }

    pub fn scry(&self, path: &str) -> Result<Value, ChannelError> {
        let body = self.request("GET", &format!("{}/~/scry{path}", self.base), None, &format!("scry {path}"))?;
        serde_json::from_str(&body).map_err(|e| ChannelError::new(K::Protocol, format!("scry {path}: bad JSON ({e})")))
    }

    fn subs(&self) -> Value {
        let ship = self.ship.trim_start_matches('~');
        json!([
            {"id": SUB_CHANNELS, "action": "subscribe", "ship": ship, "app": "channels", "path": "/v2"},
            {"id": SUB_CHAT, "action": "subscribe", "ship": ship, "app": "chat", "path": "/v3"},
        ])
    }

    /// Create (or re-create) the channel: subscriptions, then a `helm-hi` poke to activate it.
    fn open_channel(&self) -> Result<(), ChannelError> {
        *self.acks.lock().unwrap() = (-1, -1);
        self.put(self.subs(), "channel creation")?;
        self.poke("hood", "helm-hi", json!("Opening API channel")).map(|_| ())
    }

    fn reset_uid(&self) {
        *self.uid.lock().unwrap() = new_uid();
    }

    fn ack_if_needed(&self, id: Option<i64>) {
        let Some(id) = id else { return };
        let target = {
            let mut a = self.acks.lock().unwrap();
            if id <= a.1 {
                return;
            }
            a.0 = a.0.max(id);
            if a.0 - a.1 <= self.ack_threshold {
                return;
            }
            a.0
        };
        if self.put(json!([{"id": self.id(), "action": "ack", "event-id": target}]), "ack").is_ok() {
            let mut a = self.acks.lock().unwrap();
            a.1 = a.1.max(target);
        }
    }

    fn root_author(&self, nest: &str, parent: &str) -> Option<String> {
        if let Some(a) = self.root_authors.lock().unwrap().get(parent) {
            return a.clone();
        }
        let a = self.scry(&format!("/channels/v4/{nest}/posts/post/id/{}.json", format_ud(parent))).ok().and_then(|v| v["essay"]["author"].as_str().map(normalize_ship));
        let mut m = self.root_authors.lock().unwrap();
        if m.len() > 1000 {
            m.clear();
        }
        m.insert(parent.to_string(), a.clone());
        a
    }

    fn remember_parent(&self, reply: &str, parent: &str) {
        let mut p = self.parents.lock().unwrap();
        if p.0.insert(reply.to_string(), parent.to_string()).is_none() {
            p.1.push_back(reply.to_string());
        }
        while p.1.len() > 2000 {
            if let Some(old) = p.1.pop_front() {
                p.0.remove(&old);
            }
        }
    }

    /// One firehose fact → inbound messages (or side effects such as DM-invite acceptance).
    fn handle(&self, sub: u64, j: &Value) -> Option<Inbound> {
        match sub {
            SUB_CHANNELS => self.channels_event(j),
            SUB_CHAT if j.is_array() => {
                self.invites(j);
                None
            }
            SUB_CHAT => self.chat_event(j),
            _ => None,
        }
    }

    fn invites(&self, j: &Value) {
        if !self.auto_accept_dm_invites {
            return;
        }
        for ship in j.as_array().into_iter().flatten().filter_map(|i| i["ship"].as_str()).map(normalize_ship) {
            if self.accepted_invites.lock().unwrap().contains(&ship) {
                continue;
            }
            if self.poke("chat", "chat-dm-rsvp", json!({"ship": ship, "ok": true})).is_ok() {
                self.accepted_invites.lock().unwrap().insert(ship);
            }
        }
    }

    fn channels_event(&self, j: &Value) -> Option<Inbound> {
        let nest = j["nest"].as_str()?;
        if !nest.starts_with("chat/") || (!self.group_channels.is_empty() && !self.group_channels.iter().any(|g| g.trim_start_matches("chat/") == nest.trim_start_matches("chat/"))) {
            return None;
        }
        let post = &j["response"]["post"];
        let rpost = &post["r-post"];
        let reply = &rpost["reply"];
        let reply_set = &reply["r-reply"]["set"];
        let (id, content, seal, parent) = if reply_set["memo"].is_object() {
            let parent = reply_set["seal"]["parent-id"].as_str().or_else(|| reply_set["seal"]["parent"].as_str()).or_else(|| post["id"].as_str()).map(str::to_string);
            (reply["id"].as_str()?, &reply_set["memo"], &reply_set["seal"], parent)
        } else if rpost["set"]["essay"].is_object() {
            (post["id"].as_str()?, &rpost["set"]["essay"], &rpost["set"]["seal"], None)
        } else {
            return None;
        };
        let _ = seal;
        let author = normalize_ship(content["author"].as_str().unwrap_or(""));
        if author.is_empty() || author == self.ship {
            return None;
        }
        let text = story_text(&content["content"]);
        let media = story_media(&content["content"]);
        if text.is_empty() && media.is_empty() {
            return None;
        }
        let nick = self.nickname.lock().unwrap().clone();
        let mentioned = is_mentioned(&text, &self.ship, nick.as_deref());
        let reply_ref = parent.as_ref().map(|p| {
            self.remember_parent(id, p);
            let participated = self.participated.lock().unwrap().contains(p);
            let root = if mentioned && !participated { None } else { self.root_author(nest, p) };
            ReplyRef { id: p.clone(), author: root.clone().unwrap_or_default(), is_own: participated || root.as_deref() == Some(self.ship.as_str()), ..Default::default() }
        });
        Some(Inbound {
            channel: self.channel.clone(),
            chat: nest.to_string(),
            chat_type: ChatType::Group,
            chat_name: nest.to_string(),
            thread: parent,
            sender: author.clone(),
            sender_name: author,
            text,
            message_id: id.to_string(),
            ts: (content["sent"].as_i64().unwrap_or(0) / 1000),
            media,
            mentioned,
            reply: reply_ref,
            ..Default::default()
        })
    }

    fn chat_event(&self, j: &Value) -> Option<Inbound> {
        let id = j["id"].as_str()?;
        let essay = &j["response"]["add"]["essay"];
        if !essay.is_object() {
            return None;
        }
        let author = normalize_ship(essay["author"].as_str().unwrap_or(""));
        if author.is_empty() || author == self.ship {
            return None;
        }
        let whom = j["whom"].as_str().or_else(|| j["whom"]["ship"].as_str()).unwrap_or("");
        let partner = Some(normalize_ship(whom)).filter(|w| is_ship(w));
        let club = if partner.is_some() { None } else { Some(if whom.is_empty() { "unknown".to_string() } else { whom.to_string() }) };
        let text = story_text(&essay["content"]);
        let media = story_media(&essay["content"]);
        if text.is_empty() && media.is_empty() {
            return None;
        }
        let nick = self.nickname.lock().unwrap().clone();
        Some(Inbound {
            channel: self.channel.clone(),
            // Clubs reply through the author's DM, as upstream does.
            chat: partner.clone().unwrap_or_else(|| author.clone()),
            chat_type: ChatType::Direct,
            chat_name: club.clone().unwrap_or_default(),
            sender: match &club {
                Some(c) => format!("club:{c}:{author}"),
                None => author.clone(),
            },
            sender_name: author.clone(),
            mentioned: is_mentioned(&text, &self.ship, nick.as_deref()),
            text,
            message_id: id.to_string(),
            ts: essay["sent"].as_i64().unwrap_or(0) / 1000,
            media,
            ..Default::default()
        })
    }

    /// Process one SSE event payload; malformed payloads are permanent, so they are acked too.
    fn on_event(&self, id: Option<i64>, data: &str, tx: &Sender<Inbound>) {
        if let Ok(v) = serde_json::from_str::<Value>(data) {
            let sub = v["id"].as_u64().unwrap_or(0);
            match v["response"].as_str() {
                Some("quit") if sub == SUB_CHANNELS || sub == SUB_CHAT => {
                    let s = self.subs()[(sub - 1) as usize].clone();
                    let _ = self.put(json!([s]), "resubscribe");
                }
                Some("diff") | None => {
                    if let Some(m) = self.handle(sub, &v["json"]) {
                        let _ = tx.send(m);
                    }
                }
                _ => {}
            }
        }
        self.ack_if_needed(id);
    }

    /// Open the SSE stream and pump it until it ends, stalls or we stop. Err carries the HTTP status.
    fn stream(&self, tx: &Sender<Inbound>) -> Result<bool, (Option<u16>, String)> {
        let cookie = self.cookie().map_err(|e| (if e.kind == K::Auth { Some(401) } else { None }, e.message))?;
        let url = ark_net::Url::parse(&self.channel_url()).map_err(|e| (None, e))?;
        let mut s = ark_net::Stream::connect(&url.host, url.port, url.tls(), Duration::from_secs(15)).map_err(|e| (None, format!("connect: {e}")))?;
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nCookie: {cookie}\r\nUser-Agent: ark\r\nConnection: close\r\n\r\n", url.path, url.host_header());
        s.write_all(req.as_bytes()).and_then(|_| s.flush()).map_err(|e| (None, format!("write: {e}")))?;
        s.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| (None, e.to_string()))?;
        let (head, rest) = ark_net::ws::read_head(&mut s, 64 * 1024).map_err(|e| (None, format!("read head: {e}")))?;
        let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        if status != 200 {
            return Err((Some(status), format!("stream HTTP {status}")));
        }
        let chunked = ark_net::ws::header(&head, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let mut left: Option<usize> = if chunked { None } else { ark_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()) };
        let mut dec = Chunked::default();
        let mut sse = SseParser::default();
        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
        let mut got_any = false;
        let mut last = Instant::now();
        let mut feed = |bytes: &[u8], got_any: &mut bool| -> Result<bool, (Option<u16>, String)> {
            let mut body = Vec::new();
            let mut ended = false;
            if chunked {
                dec.feed(bytes, &mut body).map_err(|e| (None, e))?;
                ended = dec.done;
            } else {
                let n = left.map_or(bytes.len(), |l| l.min(bytes.len()));
                body.extend_from_slice(&bytes[..n]);
                if let Some(l) = left.as_mut() {
                    *l -= n;
                    ended = *l == 0;
                }
            }
            for (id, data) in sse.feed(&body).map_err(|e| (None, e))? {
                *got_any = true;
                self.on_event(id, &data, tx);
            }
            Ok(ended)
        };
        if feed(&rest, &mut got_any)? {
            return Ok(got_any);
        }
        let mut buf = [0u8; 16 * 1024];
        while !self.stop.load(Ordering::SeqCst) {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    last = Instant::now();
                    if feed(&buf[..n], &mut got_any)? {
                        break;
                    }
                }
                Err(e) if ark_net::stream::is_timeout(&e) => {
                    if last.elapsed() > self.stall {
                        return Err((None, "stream stalled".into()));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err((None, format!("read: {e}"))),
            }
        }
        Ok(got_any)
    }

    fn sleep(&self, d: Duration) {
        let until = Instant::now() + d;
        while Instant::now() < until && !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn run(self: Arc<Self>, tx: Sender<Inbound>) {
        let mut attempt: u32 = 0;
        let mut open = false;
        let mut greeted = false;
        while !self.stop.load(Ordering::SeqCst) {
            let backoff = (self.retry_base * 2u32.saturating_pow(attempt.min(5))).min(Duration::from_secs(30));
            if !open {
                match self.open_channel() {
                    Ok(()) => open = true,
                    Err(e) if e.kind == K::Auth => {
                        *self.fatal.lock().unwrap() = Some(e);
                        return;
                    }
                    Err(_) => {
                        attempt += 1;
                        self.sleep(backoff);
                        continue;
                    }
                }
                if !greeted {
                    greeted = true;
                    if let Ok(v) = self.scry("/contacts/v1/self.json") {
                        *self.nickname.lock().unwrap() = v["nickname"]["value"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
                    }
                }
            }
            match self.stream(&tx) {
                Ok(true) => attempt = 0,
                Ok(false) => attempt += 1,
                // Eyre reaped the channel: new uid, re-create every subscription.
                Err((Some(404), _)) => {
                    self.reset_uid();
                    open = false;
                    continue;
                }
                Err((Some(401 | 403), _)) => {
                    *self.cookie.lock().unwrap() = None;
                    if let Err(e) = self.login() {
                        if e.kind == K::Auth {
                            *self.fatal.lock().unwrap() = Some(e);
                            return;
                        }
                    }
                    attempt += 1;
                }
                Err(_) => attempt += 1,
            }
            if attempt > 0 {
                self.sleep(backoff);
            }
        }
    }
}

fn new_uid() -> String {
    format!("{}-{}", now_ms() / 1000, ark_net::crypto::hex(&ark_net::crypto::random_bytes(8)))
}

// ---------------------------------------------------------------------------
// Storage upload (OpenClaw `tlon-api.ts` `uploadFile`). The ship's `%storage` agent holds
// the bucket configuration and, for custom S3, the credentials. Hosted ships
// (`*.tlon.network`) without custom credentials upload through Tlon's Memex service;
// everything else gets a SigV4-presigned path-style `PUT` (`x-amz-acl=public-read`,
// one hour), as the AWS SDK presigner does upstream.

/// AWS Signature Version 4, hand-written on ring's SHA-256 / HMAC-SHA256.
pub mod sigv4 {
    use ark_net::crypto::{hex, hmac_sha256, sha256};

    pub const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

    pub struct Key<'a> {
        pub access_key: &'a str,
        pub secret: &'a str,
        pub region: &'a str,
        pub service: &'a str,
    }

    #[derive(Debug)]
    pub struct Signed {
        pub canonical_request: String,
        pub string_to_sign: String,
        pub signed_headers: String,
        pub signature: String,
    }

    /// RFC 3986 encoding (unreserved kept, uppercase hex); `/` kept in paths.
    pub fn encode(s: &str, path: bool) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || (path && b == b'/') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    /// Encoded `k=v` pairs sorted by key, then value.
    pub fn canonical_query(q: &[(String, String)]) -> String {
        let mut v: Vec<(String, String)> = q.iter().map(|(k, v)| (encode(k, false), encode(v, false))).collect();
        v.sort();
        v.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
    }

    /// `amz_date` is `YYYYMMDDTHHMMSSZ`; `path` is unencoded (S3-style single encoding).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(key: &Key, method: &str, path: &str, query: &[(String, String)], headers: &[(&str, &str)], payload_hash: &str, amz_date: &str) -> Signed {
        let mut hs: Vec<(String, String)> = Vec::new();
        let mut sorted: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.trim().to_ascii_lowercase(), v.split_whitespace().collect::<Vec<_>>().join(" "))).collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v) in sorted {
            match hs.last_mut() {
                Some(last) if last.0 == k => {
                    last.1.push(',');
                    last.1.push_str(&v);
                }
                _ => hs.push((k, v)),
            }
        }
        let signed_headers = hs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let canonical_request = format!("{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}", encode(path, true), canonical_query(query));
        let date = &amz_date[..8.min(amz_date.len())];
        let scope = format!("{date}/{}/{}/aws4_request", key.region, key.service);
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex(&sha256(canonical_request.as_bytes())));
        let k = [date, key.region, key.service, "aws4_request"].iter().fold(format!("AWS4{}", key.secret).into_bytes(), |k, part| hmac_sha256(&k, part.as_bytes()).to_vec());
        let signature = hex(&hmac_sha256(&k, string_to_sign.as_bytes()));
        Signed { canonical_request, string_to_sign, signed_headers, signature }
    }

    /// Query-string presigned URL (only `host` signed, payload unsigned).
    pub fn presign(key: &Key, method: &str, url: &ark_net::Url, extra: &[(&str, &str)], expires: u64, amz_date: &str) -> String {
        let path = url.path.split('?').next().unwrap_or("/");
        let host = url.host_header();
        let mut q: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            ("X-Amz-Credential".into(), format!("{}/{}/{}/{}/aws4_request", key.access_key, &amz_date[..8], key.region, key.service)),
            ("X-Amz-Date".into(), amz_date.into()),
            ("X-Amz-Expires".into(), expires.to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ];
        q.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let s = sign(key, method, path, &q, &[("host", &host)], UNSIGNED, amz_date);
        format!("{}://{host}{}?{}&X-Amz-Signature={}", url.scheme, encode(path, true), canonical_query(&q), s.signature)
    }

    /// Unix seconds → `YYYYMMDDTHHMMSSZ`.
    pub fn amz_date(t: u64) -> String {
        let (days, secs) = ((t / 86400) as i64, t % 86400);
        // Howard Hinnant's civil_from_days.
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
    }
}

const MEMEX_BASE: &str = "https://memex.tlon.network";
const MAX_UPLOAD: u64 = 50 * 1024 * 1024;

fn host_in(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn is_hosted_tlon_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    host_in(&h, "tlon.network") || host_in(&h, "test.tlon.systems")
}

/// Memex URLs must be https on a hosted Tlon domain, default port.
fn trusted_memex_url(raw: &str, what: &str) -> Result<String, ChannelError> {
    let bad = || ChannelError::new(K::Protocol, format!("tlon: {what} must be an https URL on a hosted Tlon domain"));
    let u = ark_net::Url::parse(raw).map_err(|_| bad())?;
    if u.scheme != "https" || u.port != 443 || !is_hosted_tlon_host(&u.host) {
        return Err(bad());
    }
    Ok(raw.to_string())
}

/// `new URL(key, base)`: a base without a trailing `/` loses its last path segment.
fn resolve_public_url(base: &str, key: &str) -> String {
    let base = base.trim();
    let after_scheme = base.find("://").map(|i| i + 3).unwrap_or(0);
    match base[after_scheme..].find('/') {
        None => format!("{base}/{key}"),
        Some(_) if base.ends_with('/') => format!("{base}{key}"),
        Some(_) => format!("{}/{key}", &base[..base.rfind('/').unwrap_or(base.len())]),
    }
}

/// Unwrap `{"storage-update": {<field>: …}}` or accept the bare object.
fn storage_field<'a>(v: &'a Value, field: &str, probe: &str) -> Option<&'a Value> {
    match v.get("storage-update") {
        Some(u) => u.get(field).filter(|x| x.is_object()),
        None => v.get(probe).is_some().then_some(v),
    }
}

fn uuid4() -> String {
    let mut b = ark_net::crypto::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = ark_net::crypto::hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

impl Inner {
    /// Upload bytes to the ship's configured storage; returns the public URL.
    fn upload(&self, data: &[u8], file_name: &str, content_type: &str) -> Result<String, ChannelError> {
        let cfg_v = self.scry("/storage/configuration.json")?;
        let creds_v = self.scry("/storage/credentials.json")?;
        let cfg = storage_field(&cfg_v, "configuration", "currentBucket").ok_or_else(|| ChannelError::new(K::Protocol, "tlon: invalid storage configuration response"))?;
        let creds = storage_field(&creds_v, "credentials", "accessKeyId").and_then(|c| {
            let f = |k: &str| c[k].as_str().filter(|s| !s.is_empty()).map(str::to_string);
            Some((f("endpoint")?, f("accessKeyId")?, f("secretAccessKey")?))
        });
        let file = file_name.rsplit(['/', '\\']).next().filter(|f| !f.is_empty()).unwrap_or("upload.bin");
        let key = format!("{}/{}-{}-{file}", self.ship.trim_start_matches('~'), now_ms(), uuid4());
        let hosted = ark_net::Url::parse(&self.base).map(|u| is_hosted_tlon_host(&u.host)).unwrap_or(false);
        let http = Http::new(Duration::from_secs(300));
        let put = |url: &str, headers: &[(&str, &str)]| -> Result<(), ChannelError> {
            let r = http.call("PUT", url, headers, Payload::Raw(content_type, data))?;
            if !(200..300).contains(&r.status) {
                return Err(classify(r.status, r.retry_after, "tlon upload", &r.body.chars().take(300).collect::<String>()));
            }
            Ok(())
        };
        let cache = [("cache-control", "public, max-age=3600")];
        if hosted && (cfg["service"].as_str() == Some("presigned-url") || creds.is_none()) {
            let tok = self.scry("/genuine/secret.json")?;
            let token = tok.as_str().or_else(|| tok["secret"].as_str()).filter(|t| !t.is_empty()).ok_or_else(|| ChannelError::new(K::Auth, "tlon: missing genuine secret for Memex upload"))?;
            let ship = self.ship.trim_start_matches('~');
            let body = json!({"token": token, "contentLength": data.len(), "contentType": content_type, "fileName": key});
            let v = Http::new(Duration::from_secs(30)).json("PUT", &format!("{MEMEX_BASE}/v1/{ship}/upload"), Payload::Json(&body))?;
            let (Some(url), Some(hosted_url)) = (v["url"].as_str(), v["filePath"].as_str()) else {
                return Err(ChannelError::new(K::Protocol, "tlon: invalid response from Memex"));
            };
            put(&trusted_memex_url(url, "Memex upload URL")?, &cache)?;
            return trusted_memex_url(hosted_url, "Memex hosted URL");
        }
        let (endpoint, access_key, secret) = creds.ok_or_else(|| ChannelError::new(K::Unsupported, "tlon: no storage credentials configured on the ship (%storage)"))?;
        let endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") { endpoint } else { format!("https://{endpoint}") };
        let bucket = cfg["currentBucket"].as_str().filter(|b| !b.is_empty()).ok_or_else(|| ChannelError::new(K::Unsupported, "tlon: no current storage bucket configured"))?;
        let region = cfg["region"].as_str().filter(|r| !r.is_empty()).unwrap_or("us-east-1");
        let object = format!("{}/{bucket}/{key}", endpoint.trim_end_matches('/'));
        let url = ark_net::Url::parse(&object).map_err(|e| ChannelError::new(K::Fatal, format!("tlon: storage endpoint: {e}")))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let sk = sigv4::Key { access_key: &access_key, secret: &secret, region, service: "s3" };
        let signed = sigv4::presign(&sk, "PUT", &url, &[("x-amz-acl", "public-read")], 3600, &sigv4::amz_date(now));
        put(&signed, &cache)?;
        Ok(match cfg["publicUrlBase"].as_str().filter(|b| !b.trim().is_empty()) {
            Some(base) => resolve_public_url(base, &key),
            None => signed.split('?').next().unwrap_or("").to_string(),
        })
    }
}

impl Tlon {
    pub fn new(id: &str, url: &str, ship: &str, code: &str, poll_timeout_secs: u64, opts: Options) -> Result<Tlon, String> {
        if code.trim().is_empty() {
            return Err(format!("channel {id}: tlon code is empty"));
        }
        let ship = normalize_ship(ship);
        if !is_ship(&ship) {
            return Err(format!("channel {id}: tlon ship must be a @p like ~zod"));
        }
        ark_net::Url::parse(url).map_err(|e| format!("channel {id}: tlon url: {e}"))?;
        let (tx, rx) = std::sync::mpsc::channel();
        let inner = Inner {
            channel: id.to_string(),
            base: url.trim_end_matches('/').to_string(),
            ship,
            code: code.trim().to_string(),
            http: Http::new(Duration::from_secs(30)),
            cookie: Mutex::new(None),
            uid: Mutex::new(new_uid()),
            next_id: AtomicU64::new(now_ms() as u64),
            acks: Mutex::new((-1, -1)),
            nickname: Mutex::new(None),
            root_authors: Mutex::new(HashMap::new()),
            participated: Mutex::new(HashSet::new()),
            parents: Mutex::new((HashMap::new(), VecDeque::new())),
            group_channels: opts.group_channels.iter().map(|g| g.trim().to_string()).collect(),
            auto_accept_dm_invites: opts.auto_accept_dm_invites,
            accepted_invites: Mutex::new(HashSet::new()),
            stop: AtomicBool::new(false),
            fatal: Mutex::new(None),
            retry_base: opts.retry_base,
            max_retries: opts.max_retries,
            stall: opts.stall,
            ack_threshold: opts.ack_threshold,
        };
        Ok(Tlon { id: id.to_string(), inner: Arc::new(inner), poll_timeout: poll_timeout_secs, rx: Mutex::new(rx), tx: Mutex::new(Some(tx)) })
    }

    /// Read-only Urbit scry (`GET /~/scry<path>`), JSON.
    pub fn scry(&self, path: &str) -> Result<Value, ChannelError> {
        self.inner.scry(path)
    }

    fn render(&self, out: &Outbound, text: &str) -> Vec<Value> {
        match out.format {
            TextFormat::Markdown => markdown_to_story(text),
            TextFormat::Plain => plain_story(text),
        }
    }

    fn send_story(&self, target: &Target, story: Vec<Value>, parent: Option<&str>) -> Result<String, ChannelError> {
        let me = &self.inner.ship;
        let sent = now_ms();
        match target {
            Target::Dm(ship) => {
                let id = format!("{me}/{}", format_ud(&da_from_unix_ms(sent).to_string()));
                let delta = json!({"add": {"memo": {"content": story, "author": me, "sent": sent as u64}, "kind": null, "time": null}});
                self.inner.poke("chat", "chat-dm-action", json!({"ship": ship, "diff": {"id": id, "delta": delta}}))?;
                Ok(id)
            }
            Target::Group { host, name } => {
                let memo = json!({"content": story, "author": me, "sent": sent as u64});
                let post = match parent {
                    Some(p) => json!({"reply": {"id": format_ud(p), "action": {"add": memo}}}),
                    None => {
                        let mut m = memo;
                        m["kind"] = json!("/chat");
                        m["blob"] = Value::Null;
                        m["meta"] = Value::Null;
                        json!({ "add": m })
                    }
                };
                self.inner.poke("channels", "channel-action-1", json!({"channel": {"nest": format!("chat/{host}/{name}"), "action": {"post": post}}}))?;
                if let Some(p) = parent {
                    self.inner.participated.lock().unwrap().insert(p.to_string());
                }
                Ok(format!("{me}/{sent}"))
            }
        }
    }
}

impl Channel for Tlon {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Thread], media: true, reply: true, threads: true, max_len: MAX_MESSAGE, len_unit: LenUnit::Chars, markup: Markup::Markdown, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if let Some(tx) = self.tx.lock().unwrap().take() {
            let inner = self.inner.clone();
            std::thread::Builder::new().name(format!("tlon {}", self.id)).spawn(move || inner.run(tx)).map_err(|e| ChannelError::new(K::Fatal, format!("spawn: {e}")))?;
        }
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        while !cancel.is_cancelled() && Instant::now() < until {
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                let mut got = vec![m];
                got.extend(rx.try_iter());
                return Ok(got);
            }
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
        }
        Ok(vec![])
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let target = parse_target(&out.chat).ok_or_else(|| ChannelError::new(K::Fatal, format!("tlon: bad target {:?} (want ~ship or chat/~host/name)", out.chat)))?;
        let parent = match &target {
            Target::Group { .. } => out.thread.clone().or_else(|| out.reply_to.clone()).map(|p| self.inner.parents.lock().unwrap().0.get(&p).cloned().unwrap_or(p)),
            Target::Dm(_) => None,
        };
        let mut text = out.text.clone();
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| match &b.url {
                Some(u) => format!("{}. {} {u}", i + 1, b.label),
                None => format!("{}. {}", i + 1, b.label),
            }).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let mut sent = Sent::default();
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let mut media_story = Vec::new();
        for m in &out.media {
            let url = match (&m.url, &m.path) {
                (Some(u), _) => u.clone(),
                (None, Some(p)) => {
                    let len = std::fs::metadata(p).map_err(|e| ChannelError::new(K::Fatal, format!("tlon: attachment {p}: {e}")))?.len();
                    if len > MAX_UPLOAD {
                        return Err(ChannelError::new(K::Fatal, format!("tlon: attachment larger than {MAX_UPLOAD} bytes")));
                    }
                    let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("tlon: attachment {p}: {e}")))?;
                    let name = if m.name.is_empty() { p.as_str() } else { m.name.as_str() };
                    let ct = if m.mime.is_empty() { crate::msteams::guess_mime(name) } else { m.mime.as_str() };
                    self.inner.upload(&data, name, ct)?
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            };
            if is_image_url(&url) || m.kind == MediaKind::Image {
                media_story.push(json!({"block": {"image": {"src": url, "height": 0, "width": 0, "alt": m.caption.clone().unwrap_or_default()}}}));
            } else {
                media_story.push(json!({"inline": [{"link": {"href": url, "content": if m.name.is_empty() { url.clone() } else { m.name.clone() }}}]}));
            }
        }
        let n = pieces.len();
        for (i, p) in pieces.iter().enumerate() {
            let mut story = self.render(out, p);
            if i + 1 == n {
                story.append(&mut media_story);
            }
            sent.ids.push(self.send_story(&target, story, parent.as_deref())?);
        }
        if !media_story.is_empty() {
            sent.ids.push(self.send_story(&target, media_story, parent.as_deref())?);
        }
        Ok(sent)
    }

    fn stop(&self) {
        if self.inner.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.inner.cookie.lock().unwrap().is_some() {
            let _ = self.inner.put(json!([{"id": self.inner.id(), "action": "delete"}]), "channel close");
        }
    }
}

impl Drop for Tlon {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Ship URL, e.g. `https://zod.tlon.network` or `http://127.0.0.1:8080`.
    url: String,
    ship: String,
    /// The ship's `+code`.
    code: String,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Only these chat channels (`chat/~host/name`); empty = every chat channel.
    #[serde(default)]
    group_channels: Vec<String>,
    #[serde(default)]
    auto_accept_dm_invites: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let code = ctx.secret("code", &st.code)?;
    let opts = Options { group_channels: st.group_channels, auto_accept_dm_invites: st.auto_accept_dm_invites, ..Options::default() };
    Ok(Arc::new(Tlon::new(ctx.name, &st.url, &st.ship, &code, st.poll_timeout_secs, opts)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;
    use std::sync::atomic::AtomicUsize;

    fn opts() -> Options {
        Options { retry_base: Duration::from_millis(10), ack_threshold: 0, stall: Duration::from_secs(5), ..Options::default() }
    }

    fn login_ok() -> (u16, Vec<(String, String)>, String) {
        (204, vec![("set-cookie".into(), "urbauth-~bot=0vSESSION; Path=/; Max-Age=604800".into())], String::new())
    }

    fn sse(events: &[(i64, Value)]) -> String {
        events.iter().map(|(id, v)| format!("id: {id}\ndata: {v}\n\n")).collect()
    }

    fn dm(id: &str, from: &str, text: &str) -> Value {
        json!({"id": 2, "response": "diff", "json": {"id": id, "whom": from, "response": {"add": {"essay": {"author": from, "sent": 1700000000000u64, "content": [{"inline": [text]}]}}}}})
    }

    fn post(nest: &str, id: &str, author: &str, content: Value) -> Value {
        json!({"id": 1, "response": "diff", "json": {"nest": nest, "response": {"post": {"id": id, "r-post": {"set": {"essay": {"author": author, "sent": 1700000001000u64, "content": content, "kind": "/chat"}, "seal": {"id": id}}}}}}})
    }

    fn reply(nest: &str, parent: &str, id: &str, author: &str, text: &str) -> Value {
        json!({"id": 1, "response": "diff", "json": {"nest": nest, "response": {"post": {"id": parent, "r-post": {"reply": {"id": id, "r-reply": {"set": {"memo": {"author": author, "sent": 1700000002000u64, "content": [{"inline": [text]}]}, "seal": {"id": id, "parent-id": parent}}}}}}}}})
    }

    fn poll_until(t: &Tlon, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(t.poll(&Cancel::new()).unwrap());
        }
        got
    }

    #[test]
    fn story_text_and_mentions() {
        let content = json!([
            {"inline": ["hi ", {"ship": "~bot"}, " ", {"bold": ["b"]}, {"italics": ["i"]}, {"break": null}, {"link": {"href": "https://x.y", "content": "x"}}, {"inline-code": "c"}, {"sect": null}]},
            {"block": {"code": {"code": "a```b", "lang": "rs"}}},
            {"block": {"image": {"src": "https://img/a.png", "alt": "pic"}}},
            {"block": {"cite": {"chan": {"nest": "chat/~h/c", "where": "/msg/~amy/170.1"}}}},
        ]);
        let t = story_text(&content);
        assert!(t.starts_with("hi ~bot **b***i*\nhttps://x.y`c`@all"), "{t}");
        assert!(t.contains("````rs\na```b\n````"), "fence longer than content: {t}");
        assert!(t.contains("https://img/a.png (pic)") && t.contains("[quoted: ~amy in chat/~h/c]"));
        assert_eq!(story_media(&content)[0].url.as_deref(), Some("https://img/a.png"));
        assert!(is_mentioned("hey ~bot do it", "bot", None));
        assert!(!is_mentioned("hey ~bottle", "~bot", None));
        assert!(is_mentioned("@all look", "~bot", None) && !is_mentioned("@allison", "~bot", None));
        assert!(is_mentioned("Arky, help", "~bot", Some("arky")) && !is_mentioned("arkys", "~bot", Some("arky")));
    }

    #[test]
    fn markdown_to_story_shapes() {
        let s = markdown_to_story("# Title\n\n**bold** and *it* `c` ~zod [l](https://a.b/(x)) https://e.com/p.\nline2\n\n```rs\nlet x;\n```\n> quote\n---\n![alt](https://i/x.png)");
        assert_eq!(s[0], json!({"block": {"header": {"tag": "h1", "content": ["Title"]}}}));
        let inl = s[1]["inline"].as_array().unwrap();
        assert_eq!(inl[0], json!({"bold": ["bold"]}));
        assert_eq!(inl[2], json!({"italics": ["it"]}));
        assert!(inl.contains(&json!({"inline-code": "c"})) && inl.contains(&json!({"ship": "~zod"})));
        assert!(inl.contains(&json!({"link": {"href": "https://a.b/(x)", "content": "l"}})));
        assert!(inl.contains(&json!({"link": {"href": "https://e.com/p", "content": "https://e.com/p"}})), "{inl:?}");
        assert!(inl.contains(&json!({"break": null})));
        assert_eq!(s[2], json!({"block": {"code": {"code": "let x;", "lang": "rs"}}}));
        assert_eq!(s[3], json!({"inline": [{"blockquote": ["quote"]}]}));
        assert_eq!(s[4], json!({"block": {"rule": null}}));
        assert_eq!(s[5]["block"]["image"]["src"], "https://i/x.png");
    }

    #[test]
    fn targets_ud_and_da() {
        assert_eq!(parse_target("~zod"), Some(Target::Dm("~zod".into())));
        assert_eq!(parse_target("tlon:dm/sampel-palnet"), Some(Target::Dm("~sampel-palnet".into())));
        assert_eq!(parse_target("chat/~host/general"), Some(Target::Group { host: "~host".into(), name: "general".into() }));
        assert_eq!(parse_target("group:host/general"), Some(Target::Group { host: "~host".into(), name: "general".into() }));
        assert_eq!(parse_target("not a target!"), None);
        assert_eq!(format_ud("1234567"), "1.234.567");
        assert_eq!(format_ud("170.141.5"), "170.141.5");
        assert_eq!(da_from_unix_ms(0), 170141184475152167957503069145530368000);
        assert_eq!(da_from_unix_ms(1000) - da_from_unix_ms(0), 1u128 << 64);
    }

    #[test]
    fn chunked_and_sse_framing() {
        let mut c = Chunked::default();
        let mut out = Vec::new();
        for piece in [&b"5\r\nid: 1"[..], b"\r\n", b"b;ext=1\r\n\ndata: {}\n\n\r\n0\r\n\r\n"] {
            c.feed(piece, &mut out).unwrap();
        }
        assert!(c.done);
        assert_eq!(out, b"id: 1\ndata: {}\n\n");
        let mut p = SseParser::default();
        assert!(p.feed(b"id: 7\r\ndata: {\"a\":").unwrap().is_empty());
        let ev = p.feed(b"1}\r\n\r\n:keepalive\n\nid:8\ndata:x\ndata: y\n\n").unwrap();
        assert_eq!(ev, vec![(Some(7), "{\"a\":1}".to_string()), (Some(8), "x\ny".to_string())]);
    }

    #[test]
    fn login_subscribe_stream_parse_ack_and_reconnect() {
        let gets = Arc::new(AtomicUsize::new(0));
        let g2 = gets.clone();
        let srv = FakeServer::start(move |req, _| {
            if req.path == "/~/login" {
                return login_ok();
            }
            if req.path.starts_with("/~/scry/contacts") {
                return (200, vec![], json!({"nickname": {"value": "Arky"}}).to_string());
            }
            if req.path.starts_with("/~/scry/channels/v4/chat/~host/general/posts/post/id/170.141.5") {
                return (200, vec![], json!({"essay": {"author": "~bot"}}).to_string());
            }
            if req.method == "PUT" {
                return (204, vec![], String::new());
            }
            match g2.fetch_add(1, Ordering::SeqCst) {
                0 => (200, vec![], sse(&[
                    (0, dm("~amy/170.1", "~amy", "hello")),
                    (1, {
                        let mut v = dm("~bot/170.2", "~amy", "my own echo");
                        v["json"]["response"]["add"]["essay"]["author"] = json!("~bot");
                        v
                    }),
                    (2, post("chat/~host/general", "170.141.3", "~amy", json!([{"inline": ["hey Arky!"]}, {"block": {"image": {"src": "https://i/p.png", "alt": ""}}}]))),
                    (3, reply("chat/~host/general", "170.141.5", "170.141.6", "~amy", "in thread")),
                    (4, post("heap/~host/links", "170.141.7", "~amy", json!([{"inline": ["not chat"]}]))),
                    (5, json!({"id": 2, "response": "diff", "json": {"id": "0v1", "whom": "0v4.club", "response": {"add": {"essay": {"author": "~cara", "sent": 1, "content": [{"inline": ["club msg"]}]}}}}})),
                ])),
                // The channel was reaped: a new uid is created with fresh subscriptions.
                1 => (404, vec![], String::new()),
                2 => (200, vec![], sse(&[(0, dm("~amy/170.9", "~amy", "after reconnect"))])),
                _ => (200, vec![], String::new()),
            }
        });
        let t = Tlon::new("tl", &srv.url, "bot", "lidlut-tabwed", 1, opts()).unwrap();
        let got = poll_until(&t, 5);
        assert_eq!(got.len(), 5, "{got:#?}");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].message_id.as_str(), got[0].chat_type, got[0].ts), ("~amy", "~amy", "~amy/170.1", ChatType::Direct, 1700000000));
        let g = &got[1];
        assert_eq!((g.chat.as_str(), g.chat_type, g.text.as_str()), ("chat/~host/general", ChatType::Group, "hey Arky!\n\nhttps://i/p.png"));
        assert!(g.mentioned, "nickname from /contacts/v1/self.json");
        assert_eq!(g.media[0].url.as_deref(), Some("https://i/p.png"));
        let r = &got[2];
        assert_eq!((r.thread.as_deref(), r.message_id.as_str()), (Some("170.141.5"), "170.141.6"));
        assert!(r.reply.as_ref().unwrap().is_own && r.addressed(), "bot authored the thread root");
        assert_eq!((got[3].sender.as_str(), got[3].chat.as_str(), got[3].chat_name.as_str()), ("club:0v4.club:~cara", "~cara", "0v4.club"));
        assert_eq!(got[4].text, "after reconnect");
        let reqs = srv.requests();
        let puts: Vec<_> = reqs.iter().filter(|r| r.method == "PUT").collect();
        assert_eq!(puts[0].json()[0]["action"], "subscribe");
        assert_eq!(puts[0].json()[1]["app"], "chat");
        assert_eq!(puts[1].json()[0]["mark"], "helm-hi");
        assert!(puts.iter().all(|p| p.header("cookie") == Some("urbauth-~bot=0vSESSION")));
        assert!(puts.iter().any(|p| p.json()[0]["action"] == "ack" && p.json()[0]["event-id"] == 5), "acks the last event");
        let get_paths: Vec<&str> = reqs.iter().filter(|r| r.method == "GET" && r.path.starts_with("/~/channel/")).map(|r| r.path.as_str()).collect();
        assert_eq!(get_paths[0], get_paths[1], "reopens the same channel first");
        assert_ne!(get_paths[1], get_paths[2], "new uid after 404");
        assert_eq!(puts.iter().filter(|p| p.json()[0]["action"] == "subscribe").count(), 2, "subscriptions re-sent");
        assert_eq!(reqs.iter().filter(|r| r.path == "/~/login").count(), 1);
        t.stop();
        assert_eq!(srv.requests().last().unwrap().json()[0]["action"], "delete");
    }

    #[test]
    fn send_dm_group_thread_and_media_shapes() {
        let srv = FakeServer::start(|req, _| if req.path == "/~/login" { login_ok() } else { (204, vec![], String::new()) });
        let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, opts()).unwrap();
        let s = t.send(&Outbound { format: TextFormat::Markdown, ..Outbound::text("~amy", "**hi**") }).unwrap();
        assert!(s.ids[0].starts_with("~bot/170.141."), "{:?}", s.ids);
        let reqs = srv.requests();
        assert_eq!((reqs[0].path.as_str(), reqs[0].body.as_str()), ("/~/login", "password=code"));
        let p = reqs[1].json()[0].clone();
        assert_eq!((p["action"].as_str(), p["app"].as_str(), p["mark"].as_str(), p["ship"].as_str()), (Some("poke"), Some("chat"), Some("chat-dm-action"), Some("bot")));
        assert_eq!(p["json"]["ship"], "~amy");
        assert_eq!(p["json"]["diff"]["id"], s.ids[0]);
        assert_eq!(p["json"]["diff"]["delta"]["add"]["memo"]["content"], json!([{"inline": [{"bold": ["hi"]}]}]));
        // Group top-level post with buttons as numbered options and an image by URL.
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        t.send(&Outbound { media: vec![img], buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("chat/~host/general", "pick") }).unwrap();
        let p = srv.requests()[2].json()[0]["json"].clone();
        assert_eq!(p["channel"]["nest"], "chat/~host/general");
        let add = &p["channel"]["action"]["post"]["add"];
        assert_eq!((add["kind"].as_str(), add["author"].as_str()), (Some("/chat"), Some("~bot")));
        assert_eq!(add["content"][0], json!({"inline": ["pick"]}));
        assert_eq!(add["content"][1], json!({"inline": ["1. Yes"]}));
        assert_eq!(add["content"][2]["block"]["image"]["src"], "https://e.com/a.png");
        // Thread reply: parent formatted as @ud.
        t.send(&Outbound { thread: Some("170141184506".into()), ..Outbound::text("group:~host/general", "re") }).unwrap();
        let p = srv.requests()[3].json()[0]["json"].clone();
        assert_eq!(p["channel"]["action"]["post"]["reply"]["id"], "170.141.184.506");
        assert_eq!(p["channel"]["action"]["post"]["reply"]["action"]["add"]["content"], json!([{"inline": ["re"]}]));
        // A local file needs %storage; a ship without credentials says so.
        let local = Media { path: Some("/nonexistent/x.png".into()), ..Default::default() };
        assert_eq!(t.send(&Outbound { media: vec![local], ..Outbound::text("~amy", "x") }).unwrap_err().kind, K::Fatal);
        assert_eq!(t.send(&Outbound::text("bad target!", "x")).unwrap_err().kind, K::Fatal);
    }

    // AWS SigV4 test suite (aws-sig-v4-test-suite) and the S3 developer-guide examples.
    const AK: &str = "AKIDEXAMPLE";
    const SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn suite(method: &str, query: &[(&str, &str)]) -> sigv4::Signed {
        let key = sigv4::Key { access_key: AK, secret: SK, region: "us-east-1", service: "service" };
        let q: Vec<(String, String)> = query.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        sigv4::sign(&key, method, "/", &q, &[("Host", "example.amazonaws.com"), ("X-Amz-Date", "20150830T123600Z")], EMPTY, "20150830T123600Z")
    }

    #[test]
    fn sigv4_test_suite_vectors() {
        let s = suite("GET", &[]);
        assert_eq!(s.canonical_request, format!("GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n{EMPTY}"));
        assert_eq!(s.string_to_sign, "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63");
        assert_eq!(s.signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
        assert_eq!(s.signed_headers, "host;x-amz-date");
        // get-vanilla-query: an empty query signs like get-vanilla.
        assert_eq!(suite("GET", &[]).signature, s.signature);
        let p = suite("POST", &[]);
        assert!(p.string_to_sign.ends_with("553f88c9e4d10fc9e109e2aeb65f030801b70c2f6468faca261d401ae622fc87"), "{}", p.string_to_sign);
        assert_eq!(p.signature, "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b");
        // get-vanilla-query-order-key-case: parameters are sorted by encoded key.
        let o = suite("GET", &[("Param2", "value2"), ("Param1", "value1")]);
        assert!(o.canonical_request.starts_with("GET\n/\nParam1=value1&Param2=value2\n"));
        assert_eq!(o.signature, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
        assert_eq!(sigv4::amz_date(1440938160), "20150830T123600Z");
        assert_eq!(sigv4::amz_date(1369353600), "20130524T000000Z");
        assert_eq!(sigv4::encode("a b/ü~", true), "a%20b/%C3%BC~");
    }

    #[test]
    fn sigv4_s3_examples() {
        let key = sigv4::Key { access_key: "AKIAIOSFODNN7EXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3" };
        // GET Object with a Range header (header-based signing).
        let s = sigv4::sign(&key, "GET", "/test.txt", &[], &[("Host", "examplebucket.s3.amazonaws.com"), ("Range", "bytes=0-9"), ("x-amz-content-sha256", EMPTY), ("x-amz-date", "20130524T000000Z")], EMPTY, "20130524T000000Z");
        assert_eq!(s.signed_headers, "host;range;x-amz-content-sha256;x-amz-date");
        assert_eq!(s.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
        // Presigned GET (query-string auth), 86400 s.
        let url = ark_net::Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let p = sigv4::presign(&key, "GET", &url, &[], 86400, "20130524T000000Z");
        assert_eq!(p, "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404");
    }

    #[test]
    fn storage_helpers() {
        assert_eq!(resolve_public_url("https://cdn.e.com", "zod/a.png"), "https://cdn.e.com/zod/a.png");
        assert_eq!(resolve_public_url("https://cdn.e.com/pub/", "zod/a.png"), "https://cdn.e.com/pub/zod/a.png");
        assert_eq!(resolve_public_url("https://cdn.e.com/pub", "zod/a.png"), "https://cdn.e.com/zod/a.png");
        assert!(trusted_memex_url("https://memex.tlon.network/x", "u").is_ok());
        for bad in ["http://memex.tlon.network/x", "https://evil.network/x", "https://tlon.network.evil.com/x", "https://a.tlon.network:8443/x"] {
            assert!(trusted_memex_url(bad, "u").is_err(), "{bad}");
        }
        assert!(is_hosted_tlon_host("zod.tlon.network") && is_hosted_tlon_host("x.test.tlon.systems") && !is_hosted_tlon_host("nottlon.network"));
        let wrapped = json!({"storage-update": {"configuration": {"currentBucket": "b"}}});
        assert_eq!(storage_field(&wrapped, "configuration", "currentBucket").unwrap()["currentBucket"], "b");
        assert!(storage_field(&json!({"storage-update": {"credentials": null}}), "credentials", "accessKeyId").is_none());
        assert!(storage_field(&json!({"accessKeyId": "a"}), "credentials", "accessKeyId").is_some());
        let u = uuid4();
        assert_eq!((u.len(), &u[14..15]), (36, "4"));
    }

    #[test]
    fn local_media_uploads_to_s3_then_sends_image_block() {
        let srv = FakeServer::start(|req, _| {
            let p = req.path.as_str();
            if p == "/~/login" {
                return login_ok();
            }
            if p == "/~/scry/storage/configuration.json" {
                return (200, vec![], json!({"storage-update": {"configuration": {"buckets": ["media"], "currentBucket": "media", "region": "", "publicUrlBase": "", "presignedUrl": "", "service": "credentials"}}}).to_string());
            }
            if p == "/~/scry/storage/credentials.json" {
                let host = req.header("host").unwrap().to_string();
                return (200, vec![], json!({"storage-update": {"credentials": {"endpoint": format!("http://{host}"), "accessKeyId": "AK", "secretAccessKey": "SK"}}}).to_string());
            }
            if req.method == "PUT" && p.starts_with("/media/") {
                // Verify the presigned URL the way S3 would.
                let (path, query) = p.split_once('?').unwrap();
                let mut q: Vec<(String, String)> = query.split('&').map(|kv| kv.split_once('=').unwrap()).map(|(k, v)| (k.to_string(), v.replace("%2F", "/"))).collect();
                let sig = q.iter().position(|(k, _)| k == "X-Amz-Signature").map(|i| q.remove(i).1).unwrap();
                let date = q.iter().find(|(k, _)| k == "X-Amz-Date").unwrap().1.clone();
                assert!(q.iter().any(|(k, v)| k == "x-amz-acl" && v == "public-read"));
                assert!(q.iter().any(|(k, v)| k == "X-Amz-Credential" && v.starts_with("AK/") && v.ends_with("/us-east-1/s3/aws4_request")));
                let key = sigv4::Key { access_key: "AK", secret: "SK", region: "us-east-1", service: "s3" };
                let s = sigv4::sign(&key, "PUT", &path.replace("%20", " "), &q, &[("host", req.header("host").unwrap())], sigv4::UNSIGNED, &date);
                assert_eq!(s.signature, sig);
                assert_eq!(req.header("content-type"), Some("image/png"));
                assert_eq!(req.raw, b"PNGDATA");
                return (200, vec![], String::new());
            }
            (204, vec![], String::new())
        });
        let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, opts()).unwrap();
        let f = crate::testutil::temp_dir("tlon").join("cat pic.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let m = Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() };
        t.send(&Outbound { media: vec![m], ..Outbound::text("~amy", "look") }).unwrap();
        let reqs = srv.requests();
        let put = reqs.iter().find(|r| r.method == "PUT" && r.path.starts_with("/media/")).unwrap();
        assert!(put.path.starts_with("/media/bot/") && put.path.contains("-cat%20pic.png?"), "{}", put.path);
        let poke = reqs.iter().rev().find(|r| r.path.starts_with("/~/channel/")).unwrap().json();
        let content = &poke[0]["json"]["diff"]["delta"]["add"]["memo"]["content"];
        let src = content[1]["block"]["image"]["src"].as_str().unwrap();
        assert!(src.starts_with(&format!("{}/media/bot/", srv.url)) && src.ends_with("-cat%20pic.png") && !src.contains('?'), "{src}");
        // A ship with no credentials (self-hosted) is a clear Unsupported error.
        let srv2 = FakeServer::start(|req, _| match req.path.as_str() {
            "/~/login" => login_ok(),
            "/~/scry/storage/configuration.json" => (200, vec![], json!({"currentBucket": "", "region": "", "publicUrlBase": "", "presignedUrl": "", "service": "credentials", "buckets": []}).to_string()),
            "/~/scry/storage/credentials.json" => (200, vec![], json!({"storage-update": {"credentials": null}}).to_string()),
            _ => (204, vec![], String::new()),
        });
        let t2 = Tlon::new("tl", &srv2.url, "~bot", "code", 1, opts()).unwrap();
        let m = Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() };
        assert_eq!(t2.send(&Outbound { media: vec![m], ..Outbound::text("~amy", "x") }).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn errors_relogin_and_auth_failures() {
        // A stale cookie: one 401, re-login, retry succeeds.
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let srv = FakeServer::start(move |req, _| {
            if req.path == "/~/login" {
                return login_ok();
            }
            if n2.fetch_add(1, Ordering::SeqCst) == 0 { (401, vec![], String::new()) } else { (204, vec![], String::new()) }
        });
        let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, opts()).unwrap();
        t.send(&Outbound::text("~amy", "x")).unwrap();
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/~/login").count(), 2);
        for (status, kind) in [(429, K::RateLimited { retry_after: Some(Duration::from_secs(120)) }), (502, K::Network), (404, K::NotFound), (400, K::Protocol), (403, K::Auth)] {
            let srv = FakeServer::start(move |req, _| if req.path == "/~/login" { login_ok() } else { (status, vec![("retry-after".into(), "120".into())], "urbauth-~bot=0vSESSION".into()) });
            let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, opts()).unwrap();
            let e = t.send(&Outbound::text("~amy", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains("0vSESSION"), "cookie never in errors: {}", e.message);
        }
        // A bad +code surfaces as Auth from poll, and from send.
        let srv = FakeServer::start(|_, _| (400, vec![], String::new()));
        let t = Tlon::new("tl", &srv.url, "~bot", "wrong", 1, opts()).unwrap();
        assert_eq!(t.poll(&Cancel::new()).unwrap_err().kind, K::Auth);
        assert_eq!(t.send(&Outbound::text("~amy", "x")).unwrap_err().kind, K::Auth);
        let srv = FakeServer::start(|_, _| (204, vec![], String::new()));
        let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, opts()).unwrap();
        assert!(t.send(&Outbound::text("~amy", "x")).unwrap_err().message.contains("cookie"));
        assert!(Tlon::new("tl", &srv.url, "~bot", " ", 1, opts()).is_err());
        assert!(Tlon::new("tl", &srv.url, "not a ship", "c", 1, opts()).is_err());
    }

    #[test]
    fn stream_401_relogs_dm_invites_and_quit_resubscribe() {
        let gets = Arc::new(AtomicUsize::new(0));
        let g2 = gets.clone();
        let srv = FakeServer::start(move |req, _| {
            if req.path == "/~/login" {
                return login_ok();
            }
            if req.method == "PUT" || req.path.starts_with("/~/scry") {
                return (204, vec![], String::new());
            }
            match g2.fetch_add(1, Ordering::SeqCst) {
                0 => (401, vec![], String::new()),
                1 => (200, vec![], sse(&[(0, json!({"id": 2, "response": "diff", "json": [{"ship": "~amy"}]})), (1, json!({"id": 1, "response": "quit"})), (2, dm("~amy/1", "~amy", "x"))])),
                _ => (200, vec![], String::new()),
            }
        });
        let mut o = opts();
        o.auto_accept_dm_invites = true;
        let t = Tlon::new("tl", &srv.url, "~bot", "code", 1, o).unwrap();
        assert_eq!(poll_until(&t, 1).len(), 1);
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.path == "/~/login").count(), 2, "401 on the stream re-logs in");
        let puts: Vec<Value> = reqs.iter().filter(|r| r.method == "PUT").map(|r| r.json()[0].clone()).collect();
        assert!(puts.iter().any(|p| p["mark"] == "chat-dm-rsvp" && p["json"] == json!({"ship": "~amy", "ok": true})));
        assert!(puts.iter().filter(|p| p["action"] == "subscribe" && p["app"] == "channels").count() >= 2, "quit → resubscribe");
    }

    #[test]
    fn cancel_returns_promptly_and_stall_reconnects() {
        // A server that sends the stream head then goes silent.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let gets = Arc::new(AtomicUsize::new(0));
        let g2 = gets.clone();
        std::thread::spawn(move || {
            let mut keep = Vec::new();
            for s in l.incoming() {
                let mut s = s.unwrap();
                let (head, rest) = ark_net::ws::read_head(&mut s, 65536).unwrap();
                let len: usize = ark_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut body = rest;
                while body.len() < len {
                    let mut b = [0u8; 4096];
                    let n = s.read(&mut b).unwrap();
                    body.extend_from_slice(&b[..n]);
                }
                if head.starts_with("POST /~/login") {
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nset-cookie: urbauth-~bot=0v1; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                } else if head.starts_with("GET /~/channel/") {
                    g2.fetch_add(1, Ordering::SeqCst);
                    let ev = format!("id: 1\ndata: {}\n\n", dm("~amy/1", "~amy", "chunked"));
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{ev}\r\n", ev.len()).as_bytes());
                    keep.push(s);
                } else {
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            }
        });
        let mut o = opts();
        o.stall = Duration::from_millis(500);
        let t = Tlon::new("tl", &url, "~bot", "code", 30, o).unwrap();
        let got = poll_until(&t, 1);
        assert_eq!(got[0].text, "chunked");
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        let _ = t.poll(&c).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2), "cancel honoured");
        let until = Instant::now() + Duration::from_secs(5);
        while gets.load(Ordering::SeqCst) < 2 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(gets.load(Ordering::SeqCst) >= 2, "stalled stream is reopened");
        t.stop();
    }
}
