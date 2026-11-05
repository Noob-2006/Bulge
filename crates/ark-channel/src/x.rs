//! X (Twitter API v2) mentions channel (ported from OpenClaw `extensions/x`, MIT).
//!
//! Auth: OAuth 2.0 user context. The configured refresh token is exchanged at
//! `POST /2/oauth2/token`; X rotates refresh tokens, so the rotated token is
//! written (mode 0600) to the state file *before* the new access token is used.
//! A changed configured token (re-authorization) discards the stored lineage.
//! A 401 invalidates the access token, refreshes once and retries.
//!
//! Receive: `GET /2/users/{id}/mentions` polled every `poll_seconds` with a
//! persisted `since_id` high-water mark (committed only on the next poll, so a
//! crash redelivers; the router dedups by post id), paginated with
//! `pagination_token`. Optional `events = "stream"` reads the Activity API
//! (`GET /2/activity/stream`, NDJSON `post.mention.create`, app-only bearer)
//! on a background thread after ensuring the subscription exists, falling back
//! to polling when the stream is unavailable; a slower mentions backfill poll
//! still runs to cover stream gaps. The bot's own posts and retweets are dropped.
//! Each conversation (`conversation_id`) is one chat; the post id is the message id.
//!
//! Send: replies only (as upstream): `POST /2/tweets` with
//! `reply.in_reply_to_tweet_id` = `reply_to` (or the thread/chat post id, `x:<id>`
//! or a `https://x.com/<h>/status/<id>` URL). Text is split at 280 *weighted*
//! characters (CJK/emoji count 2, URLs 23) on whitespace and posted as a
//! self-reply chain; `reply_signature` (default "🤖 automated reply") is appended
//! to the last post. Media (≤4 images or one GIF/video) is uploaded with
//! `/2/media/upload/initialize`, `/{id}/append` (4 MiB segments), `/{id}/finalize`
//! and STATUS polling, then attached to the first post. Delete = `DELETE /2/tweets/{id}`;
//! react = like/unlike. 429 maps `x-rate-limit-reset` to `retry_after`.
//! Author allowlists are applied by the host (`allow`).

use crate::{markup, sleep_cancellable, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_BASE: &str = "https://api.x.com";
pub const MAX_WEIGHT: usize = 280;
pub const DEFAULT_SIGNATURE: &str = "🤖 automated reply";
/// Longest reply chain one `send` posts (the host splits beyond this).
const MAX_THREAD_POSTS: usize = 10;
const CHUNK_BYTES: usize = 4 * 1024 * 1024;
const POST_FIELDS: &str = "author_id,conversation_id,created_at,in_reply_to_user_id,referenced_tweets,entities,attachments";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct State {
    /// sha256 of the configured refresh token this lineage started from.
    #[serde(default)]
    seed: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    access_token: String,
    /// Unix seconds.
    #[serde(default)]
    expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since_id: Option<String>,
}

struct Resp {
    status: u16,
    reset: Option<i64>,
    retry_after: Option<Duration>,
    body: String,
}

enum Body {
    None,
    Json(Value),
    Multipart(Vec<(String, String, String, Vec<u8>)>),
}

pub struct X {
    id: String,
    base: String,
    client_id: String,
    client_secret: Option<String>,
    bearer: Option<String>,
    state_path: PathBuf,
    st: Mutex<State>,
    pending_since: Mutex<Option<String>>,
    refresh_lock: Mutex<()>,
    agent: ureq::Agent,
    /// (user id, username).
    me: Mutex<Option<(String, String)>>,
    poll_every: Duration,
    poll_timeout: Duration,
    next_poll: Mutex<Instant>,
    signature: String,
    stream: Option<StreamRx>,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    /// Media processing STATUS poll ceiling.
    pub processing_timeout: Duration,
}

struct StreamRx {
    rx: Mutex<mpsc::Receiver<Value>>,
    stop: Arc<AtomicBool>,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn fingerprint(s: &str) -> String {
    ark_net::crypto::hex(&ark_net::crypto::sha256(s.as_bytes()))
}

/// Write a secret-bearing file with mode 0600 from the start (temp + rename).
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

fn agent(timeout: Option<Duration>, per_read: Option<Duration>) -> ureq::Agent {
    ark_net::http::builder().http_status_as_error(false).timeout_connect(Some(Duration::from_secs(15))).timeout_global(timeout).timeout_per_read(per_read).build().into()
}

fn multipart(parts: &[(String, String, String, Vec<u8>)]) -> (String, Vec<u8>) {
    let boundary = format!("arkx{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(12)));
    let mut b = Vec::new();
    for (name, file, ct, data) in parts {
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if file.is_empty() {
            b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
        } else {
            b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", file.replace(['"', '\r', '\n'], "")).as_bytes());
        }
        b.extend_from_slice(data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), b)
}

/// One request; never echoes tokens (they live only in headers).
fn raw(agent: &ureq::Agent, method: &str, url: &str, headers: &[(String, String)], body: Body) -> Result<Resp, ChannelError> {
    let (ctype, bytes) = match body {
        Body::None => (None, Vec::new()),
        Body::Json(v) => (Some("application/json".to_string()), serde_json::to_vec(&v).unwrap_or_default()),
        Body::Multipart(p) => {
            let (c, b) = multipart(&p);
            (Some(c), b)
        }
    };
    let r = match method {
        "GET" | "DELETE" => {
            let mut r = if method == "GET" { agent.get(url) } else { agent.delete(url) };
            for (k, v) in headers {
                r = r.header(k.as_str(), v.as_str());
            }
            r.call()
        }
        _ => {
            let mut r = agent.post(url);
            if let Some(c) = &ctype {
                r = r.header("content-type", c.as_str());
            }
            for (k, v) in headers {
                r = r.header(k.as_str(), v.as_str());
            }
            r.send(&bytes[..])
        }
    };
    let mut r = r.map_err(|e| ChannelError::new(K::Network, format!("X request failed: {e}")))?;
    let h = |k: &str| r.headers().get(k).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
    let reset = h("x-rate-limit-reset").and_then(|v| v.parse::<i64>().ok());
    let retry_after = h("retry-after").and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs);
    let status = r.status().as_u16();
    let mut raw = Vec::new();
    r.body_mut().with_config().limit(u64::MAX).reader().take(4 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("reading X response: {e}")))?;
    Ok(Resp { status, reset, retry_after, body: String::from_utf8_lossy(&raw).into_owned() })
}

/// Run `f` on a worker so a blocked socket never delays cancellation. `None` = cancelled.
fn cancellable<T: Send + 'static>(cancel: &Cancel, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(v) => return Some(v),
            Err(mpsc::RecvTimeoutError::Timeout) if cancel.is_cancelled() => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// X error body → one short detail string (secrets are never in X error bodies we echo).
fn detail(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let e = &v["errors"][0];
    [&e["message"], &e["detail"], &e["title"], &v["detail"], &v["title"], &v["error_description"], &v["error"]]
        .iter()
        .find_map(|x| x.as_str().filter(|s| !s.trim().is_empty()))
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect())
        .unwrap_or_default()
}

fn x_error(what: &str, r: &Resp) -> ChannelError {
    let d = detail(&r.body);
    let low = d.to_ascii_lowercase();
    let kind = match r.status {
        401 => K::Auth,
        403 if low.contains("deleted") || low.contains("not visible") || low.contains("not found") || low.contains("suspended") => K::NotFound,
        403 if low.contains("duplicate") || low.contains("not allowed to reply") || low.contains("conversation") => K::Protocol,
        403 => K::Auth,
        404 | 410 => K::NotFound,
        429 => K::RateLimited { retry_after: r.reset.map(|t| Duration::from_secs((t - now()).max(1) as u64)).or(r.retry_after) },
        408 | 500..=599 => K::Network,
        _ => K::Protocol,
    };
    let hint = if what.starts_with("/2/media") && matches!(r.status, 401 | 403) { " (reauthorize with the media.write scope)" } else { "" };
    ChannelError::new(kind, format!("X API {what}: HTTP {} {d}{hint}", r.status))
}

/// Accept `123`, `x:123`, or `https://x.com/<h>/status/123` (also twitter.com).
pub fn normalize_target(t: &str) -> Option<String> {
    let t = t.trim();
    let id = t.strip_prefix("x:").or_else(|| t.strip_prefix("X:")).unwrap_or(t);
    if !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()) {
        return Some(id.to_string());
    }
    let rest = t.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    if !matches!(host, "x.com" | "www.x.com" | "twitter.com" | "www.twitter.com" | "mobile.twitter.com") {
        return None;
    }
    let path = path.split(['?', '#']).next()?.trim_end_matches('/');
    let mut seg = path.split('/');
    let (_, s, id) = (seg.next()?, seg.next()?, seg.next()?);
    (s == "status" && seg.next().is_none() && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())).then(|| id.to_string())
}

// ---- weighted length (twitter-text style) ----

fn char_weight(c: char) -> usize {
    let u = c as u32;
    if u <= 0x10ff || (0x2000..=0x200d).contains(&u) || (0x2010..=0x201f).contains(&u) || (0x2032..=0x2037).contains(&u) {
        1
    } else {
        2
    }
}

fn is_extender(c: char) -> bool {
    let u = c as u32;
    (0x300..=0x36f).contains(&u) || (0xfe00..=0xfe0f).contains(&u) || (0x1f3fb..=0x1f3ff).contains(&u) || (0xe0020..=0xe007f).contains(&u) || u == 0x20e3
}

fn is_regional(c: char) -> bool {
    (0x1f1e6..=0x1f1ff).contains(&(c as u32))
}

/// Text → (token, weight): URLs weigh 23, an emoji sequence 2, otherwise per code point.
fn weighted_tokens(text: &str) -> Vec<(String, usize)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let at_word = i == 0 || !chars[i - 1].is_alphanumeric();
        if at_word {
            let rest: String = chars[i..chars.len().min(i + 8)].iter().collect::<String>().to_ascii_lowercase();
            if rest.starts_with("http://") || rest.starts_with("https://") {
                let mut j = i;
                while j < chars.len() && !chars[j].is_whitespace() {
                    j += 1;
                }
                while j > i && matches!(chars[j - 1], '.' | ',' | '!' | '?' | ';' | ':' | ')' | '\'' | '"') {
                    j -= 1;
                }
                out.push((chars[i..j].iter().collect(), 23));
                i = j;
                continue;
            }
        }
        let start = i;
        i += 1;
        let mut emoji = (chars[start] as u32) >= 0x1f000 || (0x2600..=0x27bf).contains(&(chars[start] as u32));
        if is_regional(chars[start]) && i < chars.len() && is_regional(chars[i]) {
            i += 1;
            emoji = true;
        }
        loop {
            if i < chars.len() && is_extender(chars[i]) {
                emoji |= !(0x300..=0x36f).contains(&(chars[i] as u32));
                i += 1;
            } else if i + 1 < chars.len() && chars[i] == '\u{200d}' {
                emoji = true;
                i += 2;
            } else {
                break;
            }
        }
        let seg: String = chars[start..i].iter().collect();
        let w = if emoji { 2 } else { seg.chars().map(char_weight).sum() };
        out.push((seg, w));
    }
    out
}

pub fn weighted_len(text: &str) -> usize {
    weighted_tokens(text).iter().map(|t| t.1).sum()
}

/// Split into ≤280-weight posts on whitespace; append the signature to the last one.
pub fn chunk_reply(text: &str, signature: &str, has_media: bool) -> Result<Vec<String>, ChannelError> {
    let text = text.trim();
    let suffix = signature.trim();
    if text.is_empty() && !has_media {
        return Ok(vec![]);
    }
    if weighted_len(suffix) > MAX_WEIGHT {
        return Err(ChannelError::new(K::Fatal, "X reply_signature exceeds 280 weighted characters"));
    }
    if text.is_empty() {
        return Ok(if suffix.is_empty() { vec![String::new()] } else { vec![suffix.to_string()] });
    }
    let tokens = weighted_tokens(text);
    let mut chunks: Vec<String> = Vec::new();
    let mut off = 0;
    while off < tokens.len() {
        let (mut end, mut weight, mut boundary) = (off, 0, None);
        while end < tokens.len() && weight + tokens[end].1 <= MAX_WEIGHT {
            weight += tokens[end].1;
            if tokens[end].0.chars().all(char::is_whitespace) {
                boundary = Some(end);
            }
            end += 1;
        }
        if end == off {
            return Err(ChannelError::new(K::Fatal, "X reply contains a sequence longer than one post"));
        }
        if let (true, Some(b)) = (end < tokens.len(), boundary.filter(|&b| b > off)) {
            end = b;
        }
        let chunk: String = tokens[off..end].iter().map(|t| t.0.as_str()).collect::<String>().trim().to_string();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        off = end;
        while off < tokens.len() && tokens[off].0.chars().all(char::is_whitespace) {
            off += 1;
        }
    }
    if !suffix.is_empty() {
        let last = chunks.last().cloned().unwrap_or_default();
        let joined = format!("{last}\n{suffix}");
        if weighted_len(&joined) <= MAX_WEIGHT {
            *chunks.last_mut().unwrap() = joined;
        } else {
            chunks.push(suffix.to_string());
        }
    }
    Ok(chunks)
}

fn media_category(mime: &str) -> Option<&'static str> {
    match mime {
        "video/mp4" => Some("tweet_video"),
        "image/gif" => Some("tweet_gif"),
        "image/jpeg" | "image/png" | "image/webp" => Some("tweet_image"),
        _ => None,
    }
}

fn guess_mime(name: &str, kind: MediaKind) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "mp4" => "video/mp4",
        _ if kind == MediaKind::Video => "video/mp4",
        _ if kind == MediaKind::Animation => "image/gif",
        _ => "image/jpeg",
    }
    .to_string()
}

/// A mentions page / stream event → Inbound list (own posts and retweets dropped).
fn inbound_of(channel: &str, post: &Value, users: &HashMap<String, (String, String)>, media: &HashMap<String, Media>, me: &str) -> Option<Inbound> {
    let id = post["id"].as_str()?;
    let author = post["author_id"].as_str()?;
    if author == me {
        return None;
    }
    let refs = post["referenced_tweets"].as_array().cloned().unwrap_or_default();
    if refs.iter().any(|r| r["type"] == "retweeted") {
        return None;
    }
    let (uname, name) = users.get(author).cloned().unwrap_or_default();
    let reply = refs.iter().find(|r| r["type"] == "replied_to").and_then(|r| {
        Some(ReplyRef { id: r["id"].as_str()?.to_string(), is_own: post["in_reply_to_user_id"].as_str() == Some(me), ..Default::default() })
    });
    let ts = post["created_at"].as_str().and_then(parse_rfc3339).unwrap_or(0);
    let media: Vec<Media> = post["attachments"]["media_keys"].as_array().into_iter().flatten().filter_map(|k| media.get(k.as_str()?).cloned()).collect();
    let conv = post["conversation_id"].as_str().unwrap_or(id);
    Some(Inbound {
        channel: channel.to_string(),
        chat: conv.to_string(),
        chat_type: ChatType::Group,
        chat_name: if uname.is_empty() { String::new() } else { format!("@{uname} conversation") },
        sender: author.to_string(),
        sender_name: if uname.is_empty() { name } else { uname },
        text: post["text"].as_str().unwrap_or("").to_string(),
        message_id: id.to_string(),
        ts,
        reply,
        media,
        // The mentions timeline only carries posts addressed to the bot.
        mentioned: true,
        ..Default::default()
    })
}

/// Minimal RFC 3339 (`2024-01-02T03:04:05.000Z`) → Unix seconds.
fn parse_rfc3339(s: &str) -> Option<i64> {
    let (d, t) = s.split_once('T')?;
    let mut dp = d.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (dp.next()??, dp.next()??, dp.next()??);
    let t = t.trim_end_matches('Z');
    let mut tp = t.split(':');
    let (hh, mm) = (tp.next()?.parse::<i64>().ok()?, tp.next()?.parse::<i64>().ok()?);
    let ss = tp.next()?.split('.').next()?.parse::<i64>().ok()?;
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

fn includes(v: &Value) -> (HashMap<String, (String, String)>, HashMap<String, Media>) {
    let users = v["users"].as_array().into_iter().flatten().filter_map(|u| Some((u["id"].as_str()?.to_string(), (u["username"].as_str().unwrap_or("").to_string(), u["name"].as_str().unwrap_or("").to_string())))).collect();
    let media = v["media"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let key = m["media_key"].as_str()?.to_string();
            let kind = match m["type"].as_str() {
                Some("photo") => MediaKind::Image,
                Some("animated_gif") => MediaKind::Animation,
                Some("video") => MediaKind::Video,
                _ => MediaKind::Document,
            };
            let url = m["url"].as_str().or_else(|| m["preview_image_url"].as_str())?.to_string();
            Some((key.clone(), Media { kind, url: Some(url), id: Some(key), mime: if kind == MediaKind::Image { "image/jpeg".into() } else { String::new() }, ..Default::default() }))
        })
        .collect();
    (users, media)
}

fn later(a: Option<&str>, b: &str) -> bool {
    match a {
        None => true,
        Some(a) => b.len() > a.len() || (b.len() == a.len() && b > a),
    }
}

impl X {
    #[allow(clippy::too_many_arguments)]
    pub fn new(id: &str, base: Option<&str>, client_id: &str, client_secret: Option<&str>, refresh_token: &str, state_path: PathBuf, poll_seconds: u64, poll_timeout_secs: u64) -> Result<Self, String> {
        if client_id.trim().is_empty() || refresh_token.trim().is_empty() {
            return Err(format!("channel {id}: x needs client_id and refresh_token"));
        }
        let seed = fingerprint(refresh_token.trim());
        let stored: Option<State> = std::fs::read_to_string(&state_path).ok().and_then(|s| serde_json::from_str(&s).ok());
        let st = match stored {
            Some(s) if s.seed == seed && !s.refresh_token.is_empty() => s,
            // New or re-authorized lineage: keep only the mentions cursor.
            other => State { seed, refresh_token: refresh_token.trim().to_string(), since_id: other.and_then(|s| s.since_id), ..Default::default() },
        };
        Ok(X {
            id: id.to_string(),
            base: base.unwrap_or(DEFAULT_BASE).trim_end_matches('/').to_string(),
            client_id: client_id.trim().to_string(),
            client_secret: client_secret.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            bearer: None,
            state_path,
            st: Mutex::new(st),
            pending_since: Mutex::new(None),
            refresh_lock: Mutex::new(()),
            agent: agent(Some(Duration::from_secs(60)), None),
            me: Mutex::new(None),
            poll_every: Duration::from_secs(poll_seconds.max(1)),
            poll_timeout: Duration::from_secs(poll_timeout_secs.max(1)),
            next_poll: Mutex::new(Instant::now()),
            signature: DEFAULT_SIGNATURE.to_string(),
            stream: None,
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
            processing_timeout: Duration::from_secs(300),
        })
    }

    pub fn with_identity(self, user_id: Option<&str>, username: Option<&str>) -> Self {
        if let Some(u) = user_id.filter(|u| !u.is_empty()) {
            *self.me.lock().unwrap() = Some((u.to_string(), username.unwrap_or("").trim_start_matches('@').to_string()));
        }
        self
    }

    pub fn with_signature(mut self, s: &str) -> Self {
        self.signature = s.to_string();
        self
    }

    pub fn with_bearer(mut self, b: Option<&str>) -> Self {
        self.bearer = b.map(str::to_string).filter(|s| !s.is_empty());
        self
    }

    fn save(&self, st: &State) -> Result<(), ChannelError> {
        write_private(&self.state_path, serde_json::to_string(st).unwrap_or_default().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving X token state: {e}")))
    }

    /// Exchange the refresh token. `rejected` = the access token that just got a 401.
    fn refresh(&self, rejected: Option<&str>, cancel: &Cancel) -> Result<Option<String>, ChannelError> {
        let _g = self.refresh_lock.lock().unwrap();
        {
            let st = self.st.lock().unwrap();
            if !st.access_token.is_empty() && Some(st.access_token.as_str()) != rejected && now() < st.expires_at {
                return Ok(Some(st.access_token.clone()));
            }
        }
        let rt = self.st.lock().unwrap().refresh_token.clone();
        let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", rt.as_str())];
        let mut headers = vec![("content-type".to_string(), "application/x-www-form-urlencoded".to_string())];
        match &self.client_secret {
            Some(sec) => headers.push(("authorization".into(), format!("Basic {}", ark_net::crypto::b64(format!("{}:{}", ark_net::urlencode(&self.client_id), ark_net::urlencode(sec)).as_bytes())))),
            None => form.push(("client_id", self.client_id.as_str())),
        }
        let body = ark_net::form_encode(&form).into_bytes();
        let (a, url) = (self.agent.clone(), format!("{}/2/oauth2/token", self.base));
        let Some(r) = cancellable(cancel, move || {
            let mut req = a.post(&url);
            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }
            req.send(&body[..]).map_err(|e| ChannelError::new(K::Network, format!("X token refresh failed: {e}"))).and_then(|mut r| {
                let status = r.status().as_u16();
                let mut s = String::new();
                r.body_mut().with_config().limit(256 * 1024).reader().read_to_string(&mut s).map_err(|e| ChannelError::new(K::Network, format!("X token refresh: {e}")))?;
                Ok((status, s))
            })
        }) else {
            return Ok(None);
        };
        let (status, text) = r?;
        let v: Value = serde_json::from_str(&text).unwrap_or_default();
        if status != 200 {
            let err = v["error"].as_str().unwrap_or("");
            let kind = match status {
                400 | 401 | 403 if err == "invalid_grant" || err == "invalid_client" || err == "unauthorized_client" || status != 400 => K::Auth,
                429 => K::RateLimited { retry_after: None },
                s if s >= 500 => K::Network,
                _ => K::Protocol,
            };
            // Never echo the response (it could reflect the token); only the OAuth error code.
            return Err(ChannelError::new(kind, format!("X token refresh rejected (HTTP {status} {err}); reauthorize the X account")));
        }
        let Some(access) = v["access_token"].as_str().filter(|s| !s.trim().is_empty()) else {
            return Err(ChannelError::new(K::Protocol, "X token refresh returned no access_token"));
        };
        let mut st = self.st.lock().unwrap().clone();
        if let Some(n) = v["refresh_token"].as_str().filter(|s| !s.trim().is_empty()) {
            st.refresh_token = n.to_string();
        }
        st.access_token = access.to_string();
        st.expires_at = now() + v["expires_in"].as_i64().map(|e| (e - 30).max(0)).unwrap_or(7170);
        // Persist the rotated refresh token before anything uses the new access token.
        self.save(&st)?;
        *self.st.lock().unwrap() = st;
        Ok(Some(access.to_string()))
    }

    fn token(&self, cancel: &Cancel) -> Result<Option<String>, ChannelError> {
        {
            let st = self.st.lock().unwrap();
            if !st.access_token.is_empty() && now() < st.expires_at {
                return Ok(Some(st.access_token.clone()));
            }
        }
        self.refresh(None, cancel)
    }

    /// One API call (user context unless `app_only`) with 401-refresh and retries. `Ok(None)` = cancelled.
    fn api(&self, method: &str, path: &str, body: impl Fn() -> Body, cancel: &Cancel, app_only: bool) -> Result<Option<Value>, ChannelError> {
        let url = format!("{}{path}", self.base);
        let what = path.split('?').next().unwrap_or(path).to_string();
        let idempotent = matches!(method, "GET" | "DELETE");
        let (mut attempt, mut refreshed) = (0, false);
        loop {
            let tok = if app_only {
                self.bearer.clone().ok_or_else(|| ChannelError::new(K::Fatal, "X Activity API needs bearer_token"))?
            } else {
                match self.token(cancel)? {
                    Some(t) => t,
                    None => return Ok(None),
                }
            };
            let (a, u, m, b) = (self.agent.clone(), url.clone(), method.to_string(), body());
            let hs = vec![("authorization".to_string(), format!("Bearer {tok}"))];
            let Some(r) = cancellable(cancel, move || raw(&a, &m, &u, &hs, b)) else { return Ok(None) };
            let err = match r {
                Ok(r) if (200..300).contains(&r.status) => {
                    if r.body.trim().is_empty() {
                        return Ok(Some(Value::Null));
                    }
                    return serde_json::from_str(&r.body).map(Some).map_err(|_| ChannelError::new(K::Protocol, format!("X API {what}: unreadable JSON")));
                }
                Ok(r) if r.status == 401 && !app_only && !refreshed => {
                    refreshed = true;
                    if self.refresh(Some(&tok), cancel)?.is_none() {
                        return Ok(None);
                    }
                    continue;
                }
                Ok(r) => x_error(&what, &r),
                Err(e) => e,
            };
            let retry = matches!(err.kind, K::RateLimited { .. }) || (idempotent && err.is_retryable());
            if !retry || attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            if !sleep_cancellable(wait, cancel) {
                return Ok(None);
            }
            attempt += 1;
        }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, ChannelError> {
        let b = move || body.clone().map(Body::Json).unwrap_or(Body::None);
        Ok(self.api(method, path, b, &Cancel::new(), false)?.unwrap_or_default())
    }

    fn me(&self, cancel: &Cancel) -> Result<Option<(String, String)>, ChannelError> {
        if let Some(m) = self.me.lock().unwrap().clone() {
            return Ok(Some(m));
        }
        let Some(v) = self.api("GET", "/2/users/me?user.fields=username", || Body::None, cancel, false)? else { return Ok(None) };
        let m = (v["data"]["id"].as_str().unwrap_or("").to_string(), v["data"]["username"].as_str().unwrap_or("").to_string());
        if m.0.is_empty() {
            return Err(ChannelError::new(K::Protocol, "X /2/users/me returned no id"));
        }
        *self.me.lock().unwrap() = Some(m.clone());
        Ok(Some(m))
    }

    fn commit_since(&self) -> Result<Option<String>, ChannelError> {
        let p = self.pending_since.lock().unwrap().take();
        let mut st = self.st.lock().unwrap();
        if let Some(p) = p {
            let mut next = st.clone();
            next.since_id = Some(p);
            self.save(&next)?;
            *st = next;
        }
        Ok(st.since_id.clone())
    }

    /// One mentions sweep (all pages since the cursor), oldest first.
    fn poll_mentions(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let Some((me, _)) = self.me(cancel)? else { return Ok(vec![]) };
        let since = self.commit_since()?;
        let mut posts: Vec<Value> = Vec::new();
        let (mut users, mut media) = (HashMap::new(), HashMap::new());
        let mut token: Option<String> = None;
        for _ in 0..10 {
            let mut q = vec![("tweet.fields", POST_FIELDS.to_string()), ("expansions", "author_id,attachments.media_keys".into()), ("user.fields", "username,name,protected".into()), ("media.fields", "url,preview_image_url,type".into()), ("max_results", "10".into())];
            if let Some(s) = &since {
                q.push(("since_id", s.clone()));
            }
            if let Some(t) = &token {
                q.push(("pagination_token", t.clone()));
            }
            let qs: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", ark_net::urlencode(v))).collect();
            let path = format!("/2/users/{}/mentions?{}", ark_net::urlencode(&me), qs.join("&"));
            let page = match self.api("GET", &path, || Body::None, cancel, false) {
                Ok(Some(p)) => p,
                Ok(None) => return Ok(vec![]),
                // An expired continuation token: keep what we have; the cursor covers the rest next time.
                Err(e) if token.is_some() && e.kind == K::Protocol => break,
                Err(e) => return Err(e),
            };
            if !page["data"].is_null() && !page["data"].is_array() {
                return Err(ChannelError::new(K::Protocol, "X mentions: invalid page"));
            }
            posts.extend(page["data"].as_array().cloned().unwrap_or_default());
            let (u, m) = includes(&page["includes"]);
            users.extend(u);
            media.extend(m);
            match page["meta"]["next_token"].as_str() {
                Some(t) if token.as_deref() != Some(t) => token = Some(t.to_string()),
                _ => break,
            }
        }
        posts.sort_by(|a, b| {
            let (a, b) = (a["id"].as_str().unwrap_or(""), b["id"].as_str().unwrap_or(""));
            (a.len(), a).cmp(&(b.len(), b))
        });
        let mut newest = since.clone();
        for p in &posts {
            if let Some(id) = p["id"].as_str() {
                if later(newest.as_deref(), id) {
                    newest = Some(id.to_string());
                }
            }
        }
        if newest != since {
            *self.pending_since.lock().unwrap() = newest;
        }
        Ok(posts.iter().filter_map(|p| inbound_of(&self.id, p, &users, &media, &me)).collect())
    }

    /// Activity-stream mode: ensure the `post.mention.create` subscription and start the reader.
    pub fn with_stream(mut self, backfill_secs: u64) -> Result<Self, ChannelError> {
        let bearer = self.bearer.clone().ok_or_else(|| ChannelError::new(K::Fatal, "events = \"stream\" needs bearer_token"))?;
        let cancel = Cancel::new();
        let (me, _) = self.me(&cancel)?.unwrap_or_default();
        let subs = self.api("GET", "/2/activity/subscriptions", || Body::None, &cancel, true)?.unwrap_or_default();
        let have = subs["data"].as_array().into_iter().flatten().any(|s| s["event_type"] == "post.mention.create" && s["filter"]["user_id"].as_str() == Some(me.as_str()));
        if !have {
            let body = json!({"event_type": "post.mention.create", "filter": {"user_id": me}});
            self.api("POST", "/2/activity/subscriptions", move || Body::Json(body.clone()), &cancel, false)?;
        }
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let (st2, url, name) = (stop.clone(), format!("{}/2/activity/stream", self.base), self.id.clone());
        std::thread::Builder::new().name(format!("x stream {name}")).spawn(move || stream_loop(&url, &bearer, &tx, &st2)).map_err(|e| ChannelError::new(K::Fatal, format!("spawning X stream reader: {e}")))?;
        self.stream = Some(StreamRx { rx: Mutex::new(rx), stop });
        self.poll_every = Duration::from_secs(backfill_secs.max(15));
        *self.next_poll.lock().unwrap() = Instant::now() + self.poll_every;
        Ok(self)
    }

    fn upload(&self, m: &Media) -> Result<String, ChannelError> {
        let (data, name) = match (&m.path, &m.url) {
            (Some(p), _) => (std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?, std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())),
            (None, Some(u)) => (crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?, u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let mime = if m.mime.is_empty() { guess_mime(&name, m.kind) } else { m.mime.clone() };
        let cat = media_category(&mime).ok_or_else(|| ChannelError::new(K::Fatal, "X attachments must be JPEG, PNG, WebP, GIF, or MP4 video"))?;
        let max = match cat {
            "tweet_video" => 100,
            "tweet_gif" => 15,
            _ => 5,
        } * 1024 * 1024;
        if data.len() > max {
            return Err(ChannelError::new(K::Fatal, format!("X {cat} exceeds the {} MiB limit", max / (1024 * 1024))));
        }
        let init = self.call("POST", "/2/media/upload/initialize", Some(json!({"media_type": mime, "total_bytes": data.len(), "media_category": cat})))?;
        let id = init["data"]["id"].as_str().filter(|s| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit())).ok_or_else(|| ChannelError::new(K::Protocol, "X media upload returned no media id"))?.to_string();
        let data = Arc::new(data);
        for (seg, off) in (0..data.len()).step_by(CHUNK_BYTES).enumerate() {
            let (d, mime, name) = (data.clone(), mime.clone(), name.clone());
            let part = move || Body::Multipart(vec![("segment_index".into(), String::new(), String::new(), seg.to_string().into_bytes()), ("media".into(), name.clone(), mime.clone(), d[off..(off + CHUNK_BYTES).min(d.len())].to_vec())]);
            self.api("POST", &format!("/2/media/upload/{id}/append"), part, &Cancel::new(), false)?;
        }
        let mut v = self.call("POST", &format!("/2/media/upload/{id}/finalize"), None)?;
        let deadline = Instant::now() + self.processing_timeout;
        let mut polling = false;
        loop {
            let d = &v["data"];
            if d["id"].as_str() != Some(id.as_str()) {
                return Err(ChannelError::new(K::Protocol, "X media upload returned an invalid media result"));
            }
            let p = &d["processing_info"];
            if p.is_null() && !polling {
                return Ok(id);
            }
            match p["state"].as_str() {
                Some("succeeded") => return Ok(id),
                Some("failed") => return Err(ChannelError::new(K::Fatal, "X media processing failed; check the file format")),
                Some("pending") | Some("in_progress") => {}
                _ => return Err(ChannelError::new(K::Protocol, "X media upload returned an invalid processing state")),
            }
            let wait = Duration::from_secs(p["check_after_secs"].as_u64().unwrap_or(1).max(1));
            if Instant::now() + wait >= deadline {
                return Err(ChannelError::new(K::Network, "X media processing timed out"));
            }
            std::thread::sleep(wait);
            v = self.call("GET", &format!("/2/media/upload?command=STATUS&media_id={id}"), None)?;
            polling = true;
        }
    }
}

fn stream_loop(url: &str, bearer: &str, tx: &mpsc::Sender<Value>, stop: &AtomicBool) {
    // X sends keep-alive newlines; no bytes for 90 s means the stream is dead.
    let a = agent(None, Some(Duration::from_secs(90)));
    let mut backoff = Duration::from_secs(1);
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        if let Ok(mut r) = a.get(url).header("authorization", &format!("Bearer {bearer}")).call() {
            if r.status().as_u16() == 200 {
                let reader = std::io::BufReader::new(r.body_mut().with_config().limit(u64::MAX).reader());
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if line.trim().is_empty() || line.len() > 1024 * 1024 {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(&line) {
                        if v["data"]["event_type"] == "post.mention.create" && tx.send(v).is_err() {
                            return;
                        }
                    }
                }
            } else if r.status().as_u16() == 429 {
                backoff = backoff.max(Duration::from_secs(60));
            }
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        let until = Instant::now() + backoff;
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        backoff = (backoff * 2).min(Duration::from_secs(300));
    }
}

/// Buttons have no X equivalent: numbered text options.
fn with_options(text: &str, rows: &[Vec<crate::Button>]) -> String {
    let mut t = text.to_string();
    for (i, b) in rows.iter().flatten().enumerate() {
        t.push_str(&match &b.url {
            Some(u) => format!("\n{}. {} {u}", i + 1, b.label),
            None => format!("\n{}. {}", i + 1, b.label),
        });
    }
    t
}

impl Channel for X {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 1,
            edit: false,
            delete: true,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            // `send` threads long text into ≤280-weight posts itself.
            max_len: MAX_WEIGHT * MAX_THREAD_POSTS / 2,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + self.poll_timeout;
        loop {
            if let Some(s) = &self.stream {
                let rx = s.rx.lock().unwrap();
                let got: Vec<Value> = rx.try_iter().collect();
                if !got.is_empty() {
                    let me = self.me.lock().unwrap().clone().unwrap_or_default().0;
                    return Ok(got
                        .iter()
                        .filter_map(|v| {
                            let (u, m) = includes(&v["data"]["includes"]);
                            inbound_of(&self.id, &v["data"]["payload"], &u, &m, &me)
                        })
                        .collect());
                }
            }
            let due = *self.next_poll.lock().unwrap();
            if Instant::now() >= due {
                *self.next_poll.lock().unwrap() = Instant::now() + self.poll_every;
                let got = self.poll_mentions(cancel)?;
                if !got.is_empty() || self.stream.is_none() {
                    return Ok(got);
                }
            }
            if cancel.is_cancelled() || Instant::now() >= until {
                return Ok(vec![]);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let target = [out.reply_to.as_deref(), out.thread.as_deref(), Some(out.chat.as_str())]
            .into_iter()
            .flatten()
            .find_map(normalize_target)
            .ok_or_else(|| ChannelError::new(K::Fatal, "X requires a reply target: x:<postId> or https://x.com/<handle>/status/<postId>"))?;
        if out.media.len() > 4 {
            return Err(ChannelError::new(K::Fatal, "X supports up to four images or one video/GIF per reply"));
        }
        let text = with_options(&markup::convert(&out.text, Markup::Plain), &out.buttons);
        let chunks = chunk_reply(&text, &self.signature, !out.media.is_empty())?;
        if chunks.is_empty() {
            return Ok(Sent::default());
        }
        // Failed uploads never degrade to a caption-only post.
        let media_ids = out.media.iter().map(|m| self.upload(m)).collect::<Result<Vec<_>, _>>()?;
        let mut sent = Sent::default();
        for (i, chunk) in chunks.iter().enumerate() {
            let mut body = json!({"reply": {"in_reply_to_tweet_id": sent.ids.last().cloned().unwrap_or_else(|| target.clone())}});
            if !chunk.is_empty() {
                body["text"] = json!(chunk);
            }
            if i == 0 && !media_ids.is_empty() {
                body["media"] = json!({"media_ids": media_ids});
            }
            match self.call("POST", "/2/tweets", Some(body)) {
                Ok(v) => sent.ids.push(v["data"]["id"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "X returned no post id; delivery outcome unknown"))?.to_string()),
                Err(e) if !sent.ids.is_empty() => return Err(ChannelError::new(e.kind, format!("{} (after posting {})", e.message, sent.ids.join(",")))),
                Err(e) => return Err(e),
            }
        }
        Ok(sent)
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let id = normalize_target(message_id).ok_or_else(|| ChannelError::new(K::Fatal, "X delete needs a post id"))?;
        self.call("DELETE", &format!("/2/tweets/{id}"), None).map(|_| ())
    }

    /// X has one reaction: like.
    fn react(&self, _chat: &str, message_id: &str, _emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let id = normalize_target(message_id).ok_or_else(|| ChannelError::new(K::Fatal, "X like needs a post id"))?;
        let (me, _) = self.me(&Cancel::new())?.unwrap_or_default();
        let me = ark_net::urlencode(&me);
        if remove {
            self.call("DELETE", &format!("/2/users/{me}/likes/{id}"), None).map(|_| ())
        } else {
            self.call("POST", &format!("/2/users/{me}/likes"), Some(json!({"tweet_id": id}))).map(|_| ())
        }
    }

    fn stop(&self) {
        if let Some(s) = &self.stream {
            s.stop.store(true, Ordering::SeqCst);
        }
    }
}

fn d_poll_secs() -> u64 {
    60
}
fn d_timeout() -> u64 {
    25
}
fn d_backfill() -> u64 {
    900
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    refresh_token: String,
    /// Bot account id (looked up with /2/users/me when unset).
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    /// App-only bearer for the Activity API (`events = "stream"`).
    #[serde(default)]
    bearer_token: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    /// "poll" (default), "stream", or "auto" (stream when bearer_token is set, else poll).
    #[serde(default)]
    events: Option<String>,
    #[serde(default = "d_poll_secs")]
    poll_seconds: u64,
    /// Stream mode: mentions backfill interval.
    #[serde(default = "d_backfill")]
    backfill_seconds: u64,
    #[serde(default = "d_timeout")]
    poll_timeout_secs: u64,
    /// Appended to every reply chain; "" disables.
    #[serde(default)]
    reply_signature: Option<String>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    if st.poll_seconds < 15 {
        return Err(format!("channel {}: x poll_seconds must be ≥ 15", ctx.name));
    }
    let secret = ctx.opt_secret("client_secret", &st.client_secret)?;
    let refresh = ctx.secret("refresh_token", &st.refresh_token)?;
    let bearer = ctx.opt_secret("bearer_token", &st.bearer_token)?;
    let mut x = X::new(ctx.name, st.base_url.as_deref(), &st.client_id, secret.as_deref(), &refresh, ctx.state("x.json"), st.poll_seconds, st.poll_timeout_secs)?
        .with_identity(st.user_id.as_deref(), st.username.as_deref())
        .with_bearer(bearer.as_deref())
        .with_signature(st.reply_signature.as_deref().unwrap_or(DEFAULT_SIGNATURE));
    let stream = match st.events.as_deref().unwrap_or("poll") {
        "poll" => false,
        "stream" => true,
        "auto" => x.bearer.is_some(),
        o => return Err(format!("channel {}: x events must be poll, stream or auto (got {o})", ctx.name)),
    };
    if stream {
        x = x.with_stream(st.backfill_seconds).map_err(|e| format!("channel {}: X activity stream: {}", ctx.name, e.message))?;
    }
    Ok(Arc::new(x))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    type Reply = (u16, Vec<(String, String)>, String);

    fn ok(v: Value) -> Reply {
        (200, vec![], v.to_string())
    }

    fn token_ok(n: usize) -> Reply {
        ok(json!({"token_type": "bearer", "access_token": format!("AT{n}"), "refresh_token": format!("RT{n}"), "expires_in": 7200}))
    }

    fn mk(url: &str, state: PathBuf) -> X {
        let mut x = X::new("x", Some(url), "cid", Some("csecret"), "RT0", state, 15, 1).unwrap().with_identity(Some("999"), Some("arkbot"));
        x.retry_base = Duration::from_millis(5);
        x
    }

    fn post(id: &str, author: &str, text: &str) -> Value {
        json!({"id": id, "text": text, "author_id": author, "conversation_id": "100", "created_at": "2024-01-02T03:04:05.000Z"})
    }

    #[test]
    fn refresh_rotates_token_persists_0600_and_retries_after_401() {
        let srv = FakeServer::start(|req, n| {
            if req.path == "/2/oauth2/token" {
                return token_ok(n);
            }
            if req.header("authorization") == Some("Bearer AT0") {
                return (401, vec![], json!({"title": "Unauthorized"}).to_string());
            }
            ok(json!({"data": {"id": "555", "text": "hi"}}))
        });
        let dir = temp_dir("x");
        let state = dir.join("x.json");
        let x = mk(&srv.url, state.clone());
        let s = x.send(&Outbound { reply_to: Some("42".into()), ..Outbound::text("100", "hello") }).unwrap();
        assert_eq!(s.ids, ["555"]);
        let reqs = srv.requests();
        assert_eq!(reqs[0].path, "/2/oauth2/token");
        assert_eq!(reqs[0].header("authorization"), Some(format!("Basic {}", ark_net::crypto::b64(b"cid:csecret")).as_str()));
        assert!(reqs[0].body.contains("grant_type=refresh_token") && reqs[0].body.contains("refresh_token=RT0"), "{}", reqs[0].body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The first post with AT0 got a 401 → one more refresh (rotating to RT2) → retry.
        let tok2 = reqs.iter().filter(|r| r.path == "/2/oauth2/token").count();
        assert_eq!(tok2, 2, "401 forced exactly one more refresh");
        let saved: State = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved.refresh_token, "RT2", "rotated token persisted");
        let last = reqs.last().unwrap();
        assert_eq!((last.path.as_str(), last.header("authorization")), ("/2/tweets", Some("Bearer AT2")));
        assert_eq!(last.json()["reply"]["in_reply_to_tweet_id"], "42");
        assert!(last.json()["text"].as_str().unwrap().ends_with(DEFAULT_SIGNATURE));
        // Restart: stored lineage reused (no refresh); a re-authorized config token discards it.
        let x2 = mk(&srv.url, state.clone());
        assert_eq!(x2.st.lock().unwrap().refresh_token, "RT2");
        let x3 = X::new("x", Some(&srv.url), "cid", None, "NEW", state, 15, 1).unwrap();
        assert_eq!(x3.st.lock().unwrap().refresh_token, "NEW");
    }

    #[test]
    fn invalid_grant_is_auth_and_never_leaks_tokens() {
        let srv = FakeServer::start(|_, _| (400, vec![], json!({"error": "invalid_grant", "error_description": "Value passed for the token was invalid: RT0"}).to_string()));
        let x = mk(&srv.url, temp_dir("x").join("s"));
        let e = x.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("RT0") && !e.message.contains("csecret"), "{}", e.message);
        // Public client (no secret): client_id goes in the form, no Basic header.
        let srv = FakeServer::start(|_, n| token_ok(n));
        let x = X::new("x", Some(&srv.url), "cid", None, "RT0", temp_dir("x").join("s"), 15, 1).unwrap();
        x.token(&Cancel::new()).unwrap();
        let r = &srv.requests()[0];
        assert!(r.header("authorization").is_none() && r.body.contains("client_id=cid"));
    }

    #[test]
    fn mentions_poll_parses_paginates_and_persists_since_id() {
        let srv = FakeServer::start(|req, n| {
            if req.path == "/2/oauth2/token" {
                return token_ok(n);
            }
            if req.path.contains("since_id=300") {
                return ok(json!({"meta": {"result_count": 0}}));
            }
            if req.path.contains("pagination_token=P2") {
                return ok(json!({"data": [post("200", "7", "@arkbot older")], "includes": {"users": [{"id": "7", "username": "bo"}]}, "meta": {}}));
            }
            ok(json!({
                "data": [
                    {"id": "300", "text": "@arkbot look", "author_id": "42", "conversation_id": "100", "in_reply_to_user_id": "999", "referenced_tweets": [{"type": "replied_to", "id": "250"}], "attachments": {"media_keys": ["3_1"]}},
                    post("299", "999", "my own post"),
                    {"id": "298", "text": "RT @x: @arkbot", "author_id": "8", "conversation_id": "298", "referenced_tweets": [{"type": "retweeted", "id": "1"}]}
                ],
                "includes": {"users": [{"id": "42", "username": "amy", "name": "Amy"}], "media": [{"media_key": "3_1", "type": "photo", "url": "https://pbs.twimg.com/a.jpg"}]},
                "meta": {"next_token": "P2"}
            }))
        });
        let dir = temp_dir("x");
        let state = dir.join("x.json");
        let x = mk(&srv.url, state.clone());
        let got = x.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2, "own post and retweet dropped");
        assert_eq!((got[0].message_id.as_str(), got[0].sender_name.as_str(), got[0].ts), ("200", "bo", 1704164645), "oldest first");
        let g = &got[1];
        assert_eq!((g.chat.as_str(), g.sender.as_str(), g.sender_name.as_str(), g.chat_type), ("100", "42", "amy", ChatType::Group));
        assert!(g.mentioned && g.reply.as_ref().unwrap().is_own && g.reply.as_ref().unwrap().id == "250");
        assert_eq!(g.media[0].url.as_deref(), Some("https://pbs.twimg.com/a.jpg"));
        let first = srv.requests().iter().find(|r| r.path.starts_with("/2/users/999/mentions")).unwrap().clone();
        assert!(first.path.contains("expansions=author_id") && !first.path.contains("since_id"), "{}", first.path);
        assert_eq!(first.header("authorization"), Some("Bearer AT0"));
        // at-least-once: cursor committed on the next poll, then survives restart.
        assert!(std::fs::read_to_string(&state).map(|s| !s.contains("since_id")).unwrap_or(true));
        *x.next_poll.lock().unwrap() = Instant::now();
        assert!(x.poll(&Cancel::new()).unwrap().is_empty());
        let saved: State = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved.since_id.as_deref(), Some("300"));
        let x2 = mk(&srv.url, state);
        x2.poll(&Cancel::new()).unwrap();
        assert!(srv.requests().last().unwrap().path.contains("since_id=300"));
    }

    #[test]
    fn rate_limit_reset_header_maps_to_retry_after() {
        let reset = now() + 1;
        let srv = FakeServer::start(move |req, n| {
            if req.path == "/2/oauth2/token" {
                return token_ok(n);
            }
            if n == 1 {
                return (429, vec![("x-rate-limit-reset".into(), reset.to_string())], json!({"title": "Too Many Requests"}).to_string());
            }
            ok(json!({"data": {"id": "9"}}))
        });
        let x = mk(&srv.url, temp_dir("x").join("s"));
        let t0 = Instant::now();
        x.send(&Outbound { reply_to: Some("1".into()), ..Outbound::text("1", "x") }).unwrap();
        assert!(t0.elapsed() >= Duration::from_millis(500), "waited for the reset");
        // A far reset surfaces as RateLimited with the remaining time.
        let far = now() + 3600;
        let srv = FakeServer::start(move |req, n| if req.path == "/2/oauth2/token" { token_ok(n) } else { (429, vec![("x-rate-limit-reset".into(), far.to_string())], "{}".into()) });
        let x = mk(&srv.url, temp_dir("x").join("s"));
        let e = x.send(&Outbound::text("12", "x")).unwrap_err();
        match e.kind {
            K::RateLimited { retry_after: Some(d) } => assert!(d > Duration::from_secs(3500)),
            k => panic!("{k:?}"),
        }
    }

    #[test]
    fn error_mapping() {
        for (status, body, kind) in [
            (403, json!({"detail": "You attempted to reply to a Tweet that is deleted or not visible to you."}), K::NotFound),
            (403, json!({"detail": "You are not allowed to create a Tweet with duplicate content."}), K::Protocol),
            (403, json!({"title": "Forbidden"}), K::Auth),
            (404, json!({}), K::NotFound),
            (400, json!({"title": "Invalid Request"}), K::Protocol),
            (503, json!({}), K::Network),
        ] {
            let b = body.to_string();
            let srv = FakeServer::start(move |req, n| if req.path == "/2/oauth2/token" { token_ok(n) } else { (status, vec![], b.clone()) });
            let x = mk(&srv.url, temp_dir("x").join("s"));
            let e = x.send(&Outbound::text("12", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {body}");
            assert_eq!(srv.requests().len(), 2, "POST never retried on {status}");
        }
        // Idempotent GETs retry 5xx with backoff.
        let srv = FakeServer::start(|req, n| if req.path == "/2/oauth2/token" { token_ok(n) } else { (502, vec![], "bad".into()) });
        let x = mk(&srv.url, temp_dir("x").join("s"));
        assert_eq!(x.poll(&Cancel::new()).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len(), 1 + 4);
        // Missing reply target.
        assert_eq!(x.send(&Outbound::text("not-a-post", "hi")).unwrap_err().kind, K::Fatal);
    }

    #[test]
    fn weighted_chunking_threads_replies() {
        assert_eq!(weighted_len("abc"), 3);
        assert_eq!(weighted_len("中文"), 4);
        assert_eq!(weighted_len("👍🏽"), 2, "skin tone sequence counts once");
        assert_eq!(weighted_len("👨‍👩‍👧"), 2, "ZWJ family");
        assert_eq!(weighted_len("see https://example.com/a/very/long/path?x=1."), 4 + 23 + 1);
        let words = "word ".repeat(120);
        let parts = chunk_reply(&words, "sig", false).unwrap();
        assert!(parts.len() >= 3);
        assert!(parts.iter().all(|p| weighted_len(p) <= MAX_WEIGHT));
        assert!(parts.last().unwrap().ends_with("\nsig"));
        assert!(parts.iter().all(|p| !p.starts_with(' ')));
        let cjk = "中".repeat(200); // 400 weight, no whitespace
        let p = chunk_reply(&cjk, "", false).unwrap();
        assert_eq!((p.len(), p[0].chars().count()), (2, 140));
        assert_eq!(chunk_reply("", "sig", true).unwrap(), ["sig"]);
        assert!(chunk_reply(" ", "sig", false).unwrap().is_empty());

        let srv = FakeServer::start(|req, n| if req.path == "/2/oauth2/token" { token_ok(n) } else { ok(json!({"data": {"id": format!("{}", 1000 + n)}})) });
        let x = mk(&srv.url, temp_dir("x").join("s")).with_signature("");
        let s = x.send(&Outbound::text("https://x.com/amy/status/77", &"word ".repeat(120))).unwrap();
        let reqs: Vec<_> = srv.requests().into_iter().filter(|r| r.path == "/2/tweets").collect();
        assert_eq!(s.ids.len(), reqs.len());
        assert_eq!(reqs[0].json()["reply"]["in_reply_to_tweet_id"], "77");
        assert_eq!(reqs[1].json()["reply"]["in_reply_to_tweet_id"], s.ids[0].as_str(), "chain replies to the previous post");
    }

    #[test]
    fn media_upload_sequence_then_reply_with_media_ids() {
        let srv = FakeServer::start(|req, n| {
            let p = req.path.as_str();
            if p == "/2/oauth2/token" {
                return token_ok(n);
            }
            if p == "/2/media/upload/initialize" {
                return ok(json!({"data": {"id": "1234567890"}}));
            }
            if p.ends_with("/append") {
                return (204, vec![], String::new());
            }
            if p.ends_with("/finalize") {
                return ok(json!({"data": {"id": "1234567890", "processing_info": {"state": "pending", "check_after_secs": 1}}}));
            }
            if p.starts_with("/2/media/upload?command=STATUS") {
                return ok(json!({"data": {"id": "1234567890", "processing_info": {"state": "succeeded"}}}));
            }
            ok(json!({"data": {"id": "8"}}))
        });
        let f = temp_dir("x").join("clip.mp4");
        std::fs::write(&f, b"MP4DATA").unwrap();
        let x = mk(&srv.url, temp_dir("x").join("s"));
        let m = Media { kind: MediaKind::Video, path: Some(f.display().to_string()), ..Default::default() };
        x.send(&Outbound { media: vec![m], reply_to: Some("5".into()), ..Outbound::text("5", "**look**") }).unwrap();
        let reqs = srv.requests();
        let paths: Vec<&str> = reqs.iter().map(|r| r.path.split('?').next().unwrap()).filter(|p| *p != "/2/oauth2/token").collect();
        assert_eq!(paths, ["/2/media/upload/initialize", "/2/media/upload/1234567890/append", "/2/media/upload/1234567890/finalize", "/2/media/upload", "/2/tweets"]);
        let init = reqs.iter().find(|r| r.path.ends_with("initialize")).unwrap().json();
        assert_eq!((init["media_type"].as_str(), init["total_bytes"].as_u64(), init["media_category"].as_str()), (Some("video/mp4"), Some(7), Some("tweet_video")));
        let app = reqs.iter().find(|r| r.path.ends_with("append")).unwrap();
        assert!(app.header("content-type").unwrap().starts_with("multipart/form-data") && app.body.contains("name=\"segment_index\"\r\n\r\n0") && app.body.contains("filename=\"clip.mp4\"") && app.body.contains("MP4DATA"));
        let tw = reqs.last().unwrap().json();
        assert_eq!(tw["media"]["media_ids"], json!(["1234567890"]));
        assert!(tw["text"].as_str().unwrap().starts_with("look"), "markdown stripped: {tw}");
        // Unsupported type refuses before any post.
        let n = srv.requests().len();
        let bad = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() };
        assert_eq!(x.send(&Outbound { media: vec![bad], ..Outbound::text("5", "x") }).unwrap_err().kind, K::Fatal);
        assert_eq!(srv.requests().len(), n);
    }

    #[test]
    fn delete_like_unlike_and_targets() {
        let srv = FakeServer::start(|req, n| if req.path == "/2/oauth2/token" { token_ok(n) } else { ok(json!({"data": {"deleted": true}})) });
        let x = mk(&srv.url, temp_dir("x").join("s"));
        x.delete("1", "x:55").unwrap();
        x.react("1", "55", "❤️", false).unwrap();
        x.react("1", "55", "❤️", true).unwrap();
        let r: Vec<_> = srv.requests().into_iter().skip(1).map(|r| (r.method, r.path, r.body)).collect();
        assert_eq!((r[0].0.as_str(), r[0].1.as_str()), ("DELETE", "/2/tweets/55"));
        assert_eq!((r[1].0.as_str(), r[1].1.as_str(), r[1].2.as_str()), ("POST", "/2/users/999/likes", r#"{"tweet_id":"55"}"#));
        assert_eq!((r[2].0.as_str(), r[2].1.as_str()), ("DELETE", "/2/users/999/likes/55"));
        assert_eq!(normalize_target("https://twitter.com/a/status/9?s=20").as_deref(), Some("9"));
        assert_eq!(normalize_target("http://x.com/a/status/9"), None);
        assert_eq!(normalize_target("https://x.com/a/status/9/photo/1"), None);
    }

    #[test]
    fn cancel_interrupts_a_blocked_poll() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let x = mk(&url, temp_dir("x").join("s"));
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t0 = Instant::now();
        assert!(x.poll(&c).unwrap().is_empty());
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn activity_stream_subscribes_delivers_and_reconnects() {
        let srv = FakeServer::start(|req, n| {
            match req.path.as_str() {
                "/2/oauth2/token" => token_ok(n),
                "/2/activity/subscriptions" if req.method == "GET" => ok(json!({"data": []})),
                "/2/activity/subscriptions" => ok(json!({"data": {"id": "s1"}})),
                "/2/activity/stream" => {
                    let ev = json!({"data": {"event_type": "post.mention.create", "payload": post(&format!("{}", 500 + n), "42", "@arkbot via stream"), "includes": {"users": [{"id": "42", "username": "amy"}]}}});
                    let own = json!({"data": {"event_type": "post.mention.create", "payload": post("1", "999", "own")}});
                    (200, vec![], format!("\n{ev}\n{own}\n{}\n", json!({"data": {"event_type": "other"}})))
                }
                _ => ok(json!({"meta": {}})),
            }
        });
        let x = mk(&srv.url, temp_dir("x").join("s")).with_bearer(Some("APPBEARER")).with_stream(900).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[0].header("authorization"), Some("Bearer APPBEARER"), "subscriptions listed app-only");
        let create = reqs.iter().find(|r| r.method == "POST" && r.path == "/2/activity/subscriptions").unwrap();
        assert_eq!(create.json(), json!({"event_type": "post.mention.create", "filter": {"user_id": "999"}}));
        let mut got = Vec::new();
        let t0 = Instant::now();
        while got.len() < 2 && t0.elapsed() < Duration::from_secs(8) {
            got.extend(x.poll(&Cancel::new()).unwrap());
        }
        assert!(got.len() >= 2, "stream reconnected after EOF: {got:?}");
        assert!(got.iter().all(|g| g.sender == "42" && g.text == "@arkbot via stream"));
        x.stop();
        assert!(!srv.requests().iter().any(|r| r.path.contains("/mentions")), "backfill not yet due");
    }

    #[test]
    fn build_validates_settings() {
        let d = temp_dir("x");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "tw", state_dir: &d, secrets: &secrets };
        let ok = json!({"client_id": "c", "refresh_token": "r", "user_id": "1"});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        for bad in [json!({"client_id": "c", "refresh_token": "r", "poll_seconds": 5}), json!({"client_id": "c", "refresh_token": "r", "events": "push"}), json!({"client_id": "c", "refresh_token": "r", "tokn": 1}), json!({"client_id": "c", "refresh_token": "r", "events": "stream"})] {
            assert!(build(&ctx, bad.as_object().unwrap()).is_err(), "{bad}");
        }
    }
}
