//! Mattermost bot (ported from OpenClaw `extensions/mattermost` and Hermes
//! `plugins/platforms/mattermost`, both MIT).
//!
//! Receive: WebSocket `/api/v4/websocket` (bearer header plus the
//! `authentication_challenge` action), `posted` / `post_edited` events whose
//! `post` is a JSON string inside `data`, optional `reaction_added/removed`;
//! DMs (`D`), group DMs (`G`), public/private channels (`O`/`P`), threads
//! (`root_id`), `@username` mentions, replies in the bot's threads, files.
//! Reconnects with exponential backoff and jitter; our pings detect dead links.
//! Send: REST v4 `POST /posts` (root_id threads, `file_ids` after
//! `POST /files`), `PUT /posts/{id}/patch`, `DELETE /posts/{id}`, reactions,
//! typing over the socket (`user_typing`) or `POST /users/me/typing`.
//! Buttons: interactive message attachments whose `integration.url` points at
//! our listener; each button's context is HMAC-signed so forged clicks are
//! refused. Custom slash commands (`/seagent_new` …) are registered per team and
//! their callbacks verified by the command token.

use crate::http::{Http, Payload};
use crate::{
    sleep_cancellable, Button, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming,
};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Mattermost's post limit (runes).
pub const MAX_MESSAGE: usize = 16383;
/// Files per post.
const MAX_FILES: usize = 5;
const COMMANDS: [(&str, &str); 4] = [("new", "開新對話"), ("stop", "中斷目前的工作"), ("status", "目前狀態"), ("help", "說明")];
const TRIGGER_PREFIX: &str = "seagent_";

#[derive(Debug, Clone)]
pub struct Config {
    pub id: String,
    /// Server base URL, e.g. `https://chat.example.com`.
    pub base_url: String,
    pub token: String,
    pub poll_timeout_secs: u64,
    /// Public base URL of our listener (buttons + slash commands).
    pub callback_url: Option<String>,
    /// Register `/seagent_new /seagent_stop /seagent_status /seagent_help` in every team.
    pub slash_commands: bool,
    /// Extra accepted slash-command tokens (commands created by hand).
    pub slash_tokens: Vec<String>,
    /// Deliver reaction_added/removed as messages.
    pub reaction_events: bool,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub ping_every: Duration,
}

impl Config {
    pub fn new(id: &str, base_url: &str, token: &str) -> Config {
        Config {
            id: id.into(),
            base_url: base_url.trim().trim_end_matches('/').into(),
            token: token.trim().into(),
            poll_timeout_secs: 25,
            callback_url: None,
            slash_commands: false,
            slash_tokens: vec![],
            reaction_events: false,
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            reconnect_base: Duration::from_secs(2),
            reconnect_max: Duration::from_secs(60),
            ping_every: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Me {
    id: String,
    username: String,
}

/// Bounded post id → author cache (thread roots, our own posts).
#[derive(Default)]
struct Authors {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}

impl Authors {
    fn put(&mut self, post: &str, user: &str) {
        if self.map.insert(post.into(), user.into()).is_none() {
            self.order.push_back(post.into());
            if self.order.len() > 4096 {
                if let Some(o) = self.order.pop_front() {
                    self.map.remove(&o);
                }
            }
        }
    }
}

struct Inner {
    cfg: Config,
    http: Http,
    me: Mutex<Option<Me>>,
    /// post id → (author, root id).
    posts: Mutex<Authors>,
    roots: Mutex<HashMap<String, String>>,
    /// Outgoing socket frames (typing) while connected.
    ws_out: Mutex<Option<mpsc::Sender<String>>>,
    ws_seq: Mutex<u64>,
    fatal: Mutex<Option<ChannelError>>,
    /// "team/trigger" → command token.
    slash: Mutex<HashMap<String, String>>,
    /// trigger_id → (user, channel) for ephemeral callback answers.
    clicks: Mutex<HashMap<String, (String, String)>>,
    /// Key for signing button contexts (derived from the bot token).
    secret: [u8; 32],
}

pub struct Mattermost {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Inbound>>,
    tx: Mutex<Option<mpsc::Sender<Inbound>>>,
    stop: Cancel,
    _server: Option<seagent_net::httpd::Server>,
}

fn mm_error(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let id = v["id"].as_str().unwrap_or("");
    let msg = v["message"].as_str().map(str::to_string).unwrap_or_else(|| body.chars().take(200).collect());
    let kind = match status {
        401 => K::Auth,
        403 if id.contains("session") || id.contains("token") => K::Auth,
        // No permission in that channel (bot removed / archived) or gone.
        403 | 404 | 410 => K::NotFound,
        429 => K::RateLimited { retry_after },
        408 | 500..=599 => K::Network,
        _ => K::Protocol,
    };
    ChannelError::new(kind, format!("mattermost {what}: HTTP {status} {msg} {id}"))
}

impl Inner {
    fn url(&self, path: &str) -> String {
        format!("{}/api/v4{path}", self.cfg.base_url)
    }

    fn rest(&self, method: &str, path: &str, body: Payload) -> Result<Value, ChannelError> {
        let url = self.url(path);
        let what = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let mut attempt = 0;
        loop {
            let payload = match &body {
                Payload::Json(v) => Payload::Json(v),
                Payload::Form(f) => Payload::Form(f),
                Payload::None => Payload::None,
                Payload::Raw(t, b) => Payload::Raw(t, b),
                Payload::Multipart(p) => Payload::Multipart(p),
            };
            let err = match self.http.call(method, &url, &[], payload) {
                Ok(r) if (200..300).contains(&r.status) => {
                    return if r.body.trim().is_empty() { Ok(Value::Null) } else { serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("mattermost {what}: bad JSON ({e})"))) };
                }
                Ok(r) => mm_error(&what, r.status, r.retry_after, &r.body),
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.cfg.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.cfg.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.cfg.retry_base * 2u32.pow(attempt),
            };
            std::thread::sleep(wait);
            attempt += 1;
        }
    }

    fn me(&self) -> Result<Me, ChannelError> {
        if let Some(m) = self.me.lock().unwrap().clone() {
            return Ok(m);
        }
        let v = self.rest("GET", "/users/me", Payload::None)?;
        let m = Me { id: v["id"].as_str().unwrap_or("").into(), username: v["username"].as_str().unwrap_or("").into() };
        *self.me.lock().unwrap() = Some(m.clone());
        Ok(m)
    }

    /// Author of a post (cached; REST on a miss).
    fn author(&self, post: &str) -> Option<String> {
        if let Some(a) = self.posts.lock().unwrap().map.get(post) {
            return Some(a.clone());
        }
        let v = self.rest("GET", &format!("/posts/{post}"), Payload::None).ok()?;
        let a = v["user_id"].as_str()?.to_string();
        self.posts.lock().unwrap().put(post, &a);
        if let Some(r) = v["root_id"].as_str().filter(|r| !r.is_empty()) {
            self.roots.lock().unwrap().insert(post.into(), r.into());
        }
        Some(a)
    }

    /// A reply's own id is not a valid `root_id`: walk up to the thread root.
    fn root_of(&self, post: &str) -> String {
        if let Some(r) = self.roots.lock().unwrap().get(post) {
            return r.clone();
        }
        if self.posts.lock().unwrap().map.contains_key(post) {
            return post.to_string();
        }
        match self.rest("GET", &format!("/posts/{post}"), Payload::None) {
            Ok(v) => {
                if let Some(a) = v["user_id"].as_str() {
                    self.posts.lock().unwrap().put(post, a);
                }
                match v["root_id"].as_str().filter(|r| !r.is_empty()) {
                    Some(r) => {
                        self.roots.lock().unwrap().insert(post.into(), r.into());
                        r.to_string()
                    }
                    None => post.to_string(),
                }
            }
            Err(_) => post.to_string(),
        }
    }

    fn sign(&self, data: &str) -> String {
        seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(&self.secret, data.as_bytes()))
    }

    /// Create (or adopt) our slash commands in every team; remember their tokens.
    fn register_slash(&self, me: &Me) {
        let (true, Some(base)) = (self.cfg.slash_commands, self.cfg.callback_url.as_deref()) else { return };
        if !self.slash.lock().unwrap().is_empty() {
            return;
        }
        let url = format!("{}/slash", base.trim_end_matches('/'));
        let Ok(teams) = self.rest("GET", &format!("/users/{}/teams", me.id), Payload::None) else { return };
        for team in teams.as_array().into_iter().flatten().filter_map(|t| t["id"].as_str()) {
            let existing = self.rest("GET", &format!("/commands?team_id={}&custom_only=true", seagent_net::urlencode(team)), Payload::None).unwrap_or_default();
            for (name, desc) in COMMANDS {
                let trigger = format!("{TRIGGER_PREFIX}{name}");
                let found = existing.as_array().into_iter().flatten().find(|c| c["trigger"] == trigger.as_str());
                let token = match found {
                    Some(c) if c["url"] == url.as_str() => c["token"].as_str().map(str::to_string),
                    // Someone else's command: leave it alone.
                    Some(_) => None,
                    None => {
                        let body = json!({"team_id": team, "trigger": trigger, "method": "P", "url": url, "auto_complete": true, "auto_complete_desc": desc, "display_name": format!("seagent {name}"), "description": desc});
                        self.rest("POST", "/commands", Payload::Json(&body)).ok().and_then(|c| c["token"].as_str().map(str::to_string))
                    }
                };
                if let Some(t) = token {
                    self.slash.lock().unwrap().insert(format!("{team}/{trigger}"), t);
                }
            }
        }
    }
}

// ---------------------------------------------------------------- websocket

fn rand01() -> f64 {
    let b = seagent_net::crypto::random_bytes(4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 / u32::MAX as f64
}

fn ws_url(base: &str) -> String {
    let b = if let Some(r) = base.strip_prefix("https://") { format!("wss://{r}") } else if let Some(r) = base.strip_prefix("http://") { format!("ws://{r}") } else { base.to_string() };
    format!("{b}/api/v4/websocket")
}

enum Outcome {
    Stopped,
    Fatal(ChannelError),
    Reconnect { healthy: bool },
}

fn ws_loop(inner: &Inner, tx: &mpsc::Sender<Inbound>, stop: &Cancel) {
    let mut attempts: u32 = 0;
    while !stop.is_cancelled() {
        let outcome = match inner.me() {
            Ok(me) => {
                inner.register_slash(&me);
                run_ws(inner, tx, stop, &me)
            }
            Err(e) if e.kind == K::Auth => Outcome::Fatal(e),
            Err(_) => Outcome::Reconnect { healthy: false },
        };
        *inner.ws_out.lock().unwrap() = None;
        match outcome {
            Outcome::Stopped => return,
            Outcome::Fatal(e) => {
                *inner.fatal.lock().unwrap() = Some(e);
                return;
            }
            Outcome::Reconnect { healthy } => {
                if healthy {
                    attempts = 0;
                }
                attempts += 1;
                let d = (inner.cfg.reconnect_base * 2u32.pow(attempts.min(6) - 1)).min(inner.cfg.reconnect_max);
                if !sleep_cancellable(d.mul_f64(1.0 + 0.2 * rand01()), stop) {
                    return;
                }
            }
        }
    }
}

fn run_ws(inner: &Inner, tx: &mpsc::Sender<Inbound>, stop: &Cancel, me: &Me) -> Outcome {
    let auth = format!("Bearer {}", inner.cfg.token);
    let mut ws = match WebSocket::connect(&ws_url(&inner.cfg.base_url), &[("Authorization", &auth)], Duration::from_secs(15)) {
        Ok((ws, _)) => ws,
        Err(e) if e.to_string().contains(" 401 ") => return Outcome::Fatal(ChannelError::new(K::Auth, "mattermost websocket: token rejected (401)")),
        Err(_) => return Outcome::Reconnect { healthy: false },
    };
    if ws.set_read_timeout(Some(Duration::from_millis(100))).is_err() {
        return Outcome::Reconnect { healthy: false };
    }
    let seq = {
        let mut s = inner.ws_seq.lock().unwrap();
        *s += 1;
        *s
    };
    if ws.send_text(&json!({"seq": seq, "action": "authentication_challenge", "data": {"token": inner.cfg.token}}).to_string()).is_err() {
        return Outcome::Reconnect { healthy: false };
    }
    let (out_tx, out_rx) = mpsc::channel::<String>();
    *inner.ws_out.lock().unwrap() = Some(out_tx);
    let mut healthy = false;
    let mut next_ping = Instant::now() + inner.cfg.ping_every;
    let mut pong_due: Option<Instant> = None;
    loop {
        if stop.is_cancelled() {
            let _ = ws.send(&Message::Close(Some((1000, String::new()))));
            return Outcome::Stopped;
        }
        for frame in out_rx.try_iter() {
            if ws.send_text(&frame).is_err() {
                return Outcome::Reconnect { healthy };
            }
        }
        let now = Instant::now();
        if pong_due.is_some_and(|d| now >= d) {
            return Outcome::Reconnect { healthy };
        }
        if now >= next_ping {
            if ws.send(&Message::Ping(b"seagent".to_vec())).is_err() {
                return Outcome::Reconnect { healthy };
            }
            next_ping = now + inner.cfg.ping_every;
            pong_due.get_or_insert(now + inner.cfg.ping_every);
        }
        let text = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Pong(_))) => {
                pong_due = None;
                continue;
            }
            Ok(Some(Message::Close(_))) | Err(_) => return Outcome::Reconnect { healthy },
            Ok(Some(_)) => continue,
        };
        pong_due = None;
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        if v["seq_reply"] == seq {
            if v["status"] == "OK" {
                healthy = true;
            } else {
                return Outcome::Fatal(ChannelError::new(K::Auth, format!("mattermost websocket authentication failed: {}", v["error"]["message"].as_str().unwrap_or(""))));
            }
            continue;
        }
        match v["event"].as_str() {
            Some("hello") => healthy = true,
            Some("posted" | "post_edited") => {
                if let Some(m) = post_of(inner, &v, me) {
                    let _ = tx.send(m);
                }
            }
            Some("reaction_added" | "reaction_removed") if inner.cfg.reaction_events => {
                if let Some(m) = reaction_of(inner, &v, me) {
                    let _ = tx.send(m);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- inbound

fn chat_type_of(t: &str) -> ChatType {
    match t {
        "D" => ChatType::Direct,
        _ => ChatType::Group,
    }
}

/// `data` fields arrive as JSON strings ("post", "mentions", "reaction").
fn embedded(v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        other => other.clone(),
    }
}

fn mentions_name(text: &str, username: &str) -> bool {
    if username.is_empty() {
        return false;
    }
    let lower = text.to_lowercase();
    let tag = format!("@{}", username.to_lowercase());
    lower.match_indices(&tag).any(|(i, _)| {
        let after = lower[i + tag.len()..].chars().next();
        let before = lower[..i].chars().next_back();
        !after.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') && !before.is_some_and(|c| c.is_alphanumeric())
    })
}

fn media_of(base: &str, post: &Value) -> Vec<Media> {
    let kind = |mime: &str| match mime {
        "image/gif" => MediaKind::Animation,
        m if m.starts_with("image/") => MediaKind::Image,
        m if m.starts_with("video/") => MediaKind::Video,
        m if m.starts_with("audio/") => MediaKind::Audio,
        _ => MediaKind::Document,
    };
    let infos = post["metadata"]["files"].as_array();
    let mut out: Vec<Media> = infos
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let id = f["id"].as_str()?;
            let mime = f["mime_type"].as_str().unwrap_or("").to_string();
            Some(Media { kind: kind(&mime), url: Some(format!("{base}/api/v4/files/{id}")), id: Some(id.into()), name: f["name"].as_str().unwrap_or("").into(), size: f["size"].as_u64().unwrap_or(0), mime, ..Default::default() })
        })
        .collect();
    let known: HashSet<String> = out.iter().filter_map(|m| m.id.clone()).collect();
    for id in post["file_ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !known.contains(id) {
            out.push(Media { url: Some(format!("{base}/api/v4/files/{id}")), id: Some(id.into()), ..Default::default() });
        }
    }
    out
}

fn post_of(inner: &Inner, ev: &Value, me: &Me) -> Option<Inbound> {
    let data = &ev["data"];
    let post = embedded(&data["post"]);
    let edited = ev["event"] == "post_edited";
    let pid = post["id"].as_str()?.to_string();
    let user = post["user_id"].as_str().unwrap_or("").to_string();
    if user == me.id {
        return None;
    }
    // System posts (joins, header changes…) carry a type.
    if !post["type"].as_str().unwrap_or("").is_empty() {
        return None;
    }
    let channel = post["channel_id"].as_str().or_else(|| ev["broadcast"]["channel_id"].as_str())?.to_string();
    let root = post["root_id"].as_str().filter(|r| !r.is_empty()).map(str::to_string);
    inner.posts.lock().unwrap().put(&pid, &user);
    if let Some(r) = &root {
        inner.roots.lock().unwrap().insert(pid.clone(), r.clone());
    }
    let media = media_of(&inner.cfg.base_url, &post);
    let text = post["message"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let ctype = data["channel_type"].as_str().unwrap_or("O");
    let mut chat_type = chat_type_of(ctype);
    if root.is_some() && chat_type != ChatType::Direct {
        chat_type = ChatType::Thread;
    }
    let mentioned = embedded(&data["mentions"]).as_array().is_some_and(|m| m.iter().any(|u| u.as_str() == Some(me.id.as_str()))) || mentions_name(&text, &me.username);
    let reply = root.as_ref().map(|r| ReplyRef { id: r.clone(), is_own: inner.author(r).as_deref() == Some(me.id.as_str()), ..Default::default() });
    let created = post["create_at"].as_i64().unwrap_or(0);
    Some(Inbound {
        channel: inner.cfg.id.clone(),
        chat: channel,
        chat_type,
        chat_name: data["channel_display_name"].as_str().unwrap_or("").to_string(),
        thread: root,
        sender: user,
        sender_name: data["sender_name"].as_str().unwrap_or("").trim_start_matches('@').to_string(),
        is_bot: post["props"]["from_bot"] == "true" || post["props"]["from_bot"] == true,
        text,
        message_id: if edited { format!("{pid}:e{}", post["edit_at"].as_i64().unwrap_or(0)) } else { pid },
        ts: created / 1000,
        account: data["team_id"].as_str().unwrap_or("").to_string(),
        media,
        mentioned,
        reply,
        edited,
        ..Default::default()
    })
}

fn reaction_of(inner: &Inner, ev: &Value, me: &Me) -> Option<Inbound> {
    let r = embedded(&ev["data"]["reaction"]);
    let (user, post, emoji) = (r["user_id"].as_str()?, r["post_id"].as_str()?, r["emoji_name"].as_str()?);
    if user == me.id {
        return None;
    }
    let channel = ev["broadcast"]["channel_id"].as_str().or_else(|| r["channel_id"].as_str())?.to_string();
    let added = ev["event"] == "reaction_added";
    let thread = inner.roots.lock().unwrap().get(post).cloned();
    Some(Inbound {
        channel: inner.cfg.id.clone(),
        chat: channel,
        chat_type: if thread.is_some() { ChatType::Thread } else { ChatType::Group },
        thread,
        sender: user.to_string(),
        text: format!(":{emoji}: {}", if added { "reaction added" } else { "reaction removed" }),
        message_id: format!("r:{post}:{user}:{emoji}:{}", if added { "+" } else { "-" }),
        ts: r["create_at"].as_i64().unwrap_or(0) / 1000,
        reply: Some(ReplyRef { id: post.to_string(), is_own: inner.author(post).as_deref() == Some(me.id.as_str()), ..Default::default() }),
        ..Default::default()
    })
}

// ---------------------------------------------------------------- listener (buttons, slash)

fn listener(inner: Arc<Inner>, prefix: String, tx: mpsc::Sender<Inbound>) -> seagent_net::httpd::Handler {
    use seagent_net::httpd::Response;
    let tx = Mutex::new(tx);
    Arc::new(move |r: seagent_net::httpd::Request| {
        if r.method != "POST" {
            return Response::text(405, "POST only");
        }
        let push = |m: Inbound| {
            let _ = tx.lock().unwrap().send(m);
        };
        if r.path == format!("{prefix}/actions") {
            let Ok(p) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
            let ctx = &p["context"];
            let (Some(data), Some(sig)) = (ctx["seagent"].as_str(), ctx["_token"].as_str()) else { return Response::json(403, &r#"{"error":"missing token"}"#) };
            if !seagent_net::crypto::ct_eq(sig.as_bytes(), inner.sign(data).as_bytes()) {
                return Response::json(403, &r#"{"error":"invalid token"}"#);
            }
            let user = p["user_id"].as_str().unwrap_or("").to_string();
            let channel = p["channel_id"].as_str().unwrap_or("").to_string();
            let trigger = p["trigger_id"].as_str().map(str::to_string).unwrap_or_else(|| seagent_net::crypto::random_token(12));
            let post = p["post_id"].as_str().unwrap_or("").to_string();
            {
                let mut c = inner.clicks.lock().unwrap();
                if c.len() > 1024 {
                    c.clear();
                }
                c.insert(trigger.clone(), (user.clone(), channel.clone()));
            }
            let thread = inner.roots.lock().unwrap().get(&post).cloned();
            push(Inbound {
                channel: inner.cfg.id.clone(),
                chat: channel,
                chat_type: if thread.is_some() { ChatType::Thread } else { ChatType::Group },
                thread,
                sender: user,
                sender_name: p["user_name"].as_str().unwrap_or("").to_string(),
                message_id: format!("cb:{trigger}"),
                account: p["team_id"].as_str().unwrap_or("").to_string(),
                callback: Some(Callback { id: trigger, data: data.to_string() }),
                reply: (!post.is_empty()).then(|| ReplyRef { id: post, is_own: true, ..Default::default() }),
                mentioned: true,
                ..Default::default()
            });
            return Response::json(200, &"{}");
        }
        if r.path == format!("{prefix}/slash") {
            let f: HashMap<String, String> = if r.header("content-type").is_some_and(|c| c.starts_with("application/json")) {
                serde_json::from_slice::<HashMap<String, Value>>(&r.body).unwrap_or_default().into_iter().map(|(k, v)| (k, v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect()
            } else {
                seagent_net::parse_query(r.body_str()).into_iter().collect()
            };
            let get = |k: &str| f.get(k).map(String::as_str).unwrap_or("");
            let trigger = get("command").trim_start_matches('/');
            let want = inner.slash.lock().unwrap().get(&format!("{}/{trigger}", get("team_id"))).cloned();
            let token = get("token");
            let ok = !token.is_empty() && (want.is_some_and(|w| seagent_net::crypto::ct_eq(w.as_bytes(), token.as_bytes())) || inner.cfg.slash_tokens.iter().any(|t| seagent_net::crypto::ct_eq(t.as_bytes(), token.as_bytes())));
            if !ok {
                return Response::text(401, "Unauthorized: invalid command token.");
            }
            let name = trigger.strip_prefix(TRIGGER_PREFIX).unwrap_or(trigger);
            let args = get("text").trim();
            push(Inbound {
                channel: inner.cfg.id.clone(),
                chat: get("channel_id").to_string(),
                chat_type: if get("channel_name").contains("__") { ChatType::Direct } else { ChatType::Group },
                sender: get("user_id").to_string(),
                sender_name: get("user_name").to_string(),
                text: if args.is_empty() { format!("/{name}") } else { format!("/{name} {args}") },
                message_id: format!("sc:{}", if get("trigger_id").is_empty() { seagent_net::crypto::random_token(12) } else { get("trigger_id").to_string() }),
                account: get("team_id").to_string(),
                mentioned: true,
                ..Default::default()
            });
            return Response::json(200, &r#"{"response_type":"ephemeral","text":"✓"}"#);
        }
        Response::text(404, "not found")
    })
}

// ---------------------------------------------------------------- outbound

fn emoji_name(e: &str) -> String {
    let e = e.trim();
    let named = [
        ("👍", "+1"), ("👎", "-1"), ("👀", "eyes"), ("✅", "white_check_mark"), ("❌", "x"), ("🎉", "tada"), ("❤️", "heart"), ("❤", "heart"), ("😂", "joy"), ("🙏", "pray"), ("🔥", "fire"),
        ("🤔", "thinking_face"), ("⏳", "hourglass_flowing_sand"), ("⌛", "hourglass"), ("😀", "grinning"), ("😄", "smile"), ("🚀", "rocket"), ("⚠️", "warning"), ("⚠", "warning"), ("💯", "100"),
        ("👋", "wave"), ("😢", "cry"), ("🤖", "robot_face"), ("✨", "sparkles"), ("🙂", "slightly_smiling_face"), ("😅", "sweat_smile"), ("👌", "ok_hand"), ("👏", "clap"), ("📝", "memo"),
    ];
    named.iter().find(|(c, _)| *c == e).map(|(_, n)| n.to_string()).unwrap_or_else(|| e.trim_matches(':').to_string())
}

impl Mattermost {
    pub fn new(cfg: Config) -> Result<Mattermost, String> {
        if cfg.token.is_empty() {
            return Err(format!("channel {}: mattermost token is empty", cfg.id));
        }
        seagent_net::Url::parse(&cfg.base_url).map_err(|e| format!("channel {}: mattermost url: {e}", cfg.id))?;
        let (tx, rx) = mpsc::channel();
        let http = Http::new(Duration::from_secs(60)).bearer(&cfg.token);
        let secret = seagent_net::crypto::hmac_sha256(b"seagent-mattermost-interactions", cfg.token.as_bytes());
        Ok(Mattermost {
            inner: Arc::new(Inner {
                cfg,
                http,
                me: Mutex::new(None),
                posts: Mutex::new(Authors::default()),
                roots: Mutex::new(HashMap::new()),
                ws_out: Mutex::new(None),
                ws_seq: Mutex::new(0),
                fatal: Mutex::new(None),
                slash: Mutex::new(HashMap::new()),
                clicks: Mutex::new(HashMap::new()),
                secret,
            }),
            rx: Mutex::new(rx),
            tx: Mutex::new(Some(tx)),
            stop: Cancel::new(),
            _server: None,
        })
    }

    /// Listen for button clicks (`<callback_url>/actions`) and slash commands (`<callback_url>/slash`).
    pub fn with_listener(mut self, listen: &str) -> Result<Mattermost, String> {
        let cb = self.inner.cfg.callback_url.clone().ok_or_else(|| format!("channel {}: listen needs callback_url", self.inner.cfg.id))?;
        let prefix = seagent_net::Url::parse(&cb).map_err(|e| format!("channel {}: callback_url: {e}", self.inner.cfg.id))?.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
        let tx = self.tx.lock().unwrap().clone().ok_or("listener after start")?;
        let server = seagent_net::httpd::Server::bind(listen, seagent_net::httpd::Opts::default(), listener(self.inner.clone(), prefix, tx)).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.inner.cfg.id))?;
        self._server = Some(server);
        Ok(self)
    }

    fn ensure_started(&self) {
        let Some(tx) = self.tx.lock().unwrap().take() else { return };
        let (inner, stop) = (self.inner.clone(), self.stop.clone());
        let _ = std::thread::Builder::new().name(format!("mattermost {}", inner.cfg.id)).spawn(move || ws_loop(&inner, &tx, &stop));
    }

    /// `user:<id>` / `@username` → the DM channel with that user.
    fn target(&self, chat: &str) -> Result<String, ChannelError> {
        let user = if let Some(u) = chat.strip_prefix("user:") {
            u.to_string()
        } else if let Some(name) = chat.strip_prefix('@') {
            let v = self.inner.rest("GET", &format!("/users/username/{}", seagent_net::urlencode(name)), Payload::None)?;
            v["id"].as_str().ok_or_else(|| ChannelError::new(K::NotFound, format!("mattermost: no user @{name}")))?.to_string()
        } else {
            return Ok(chat.to_string());
        };
        let me = self.inner.me()?;
        let v = self.inner.rest("POST", "/channels/direct", Payload::Json(&json!([me.id, user])))?;
        v["id"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "mattermost: direct channel without id"))
    }

    fn upload(&self, channel: &str, m: &Media) -> Result<String, ChannelError> {
        let path = m.path.as_deref().unwrap_or_default();
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let name = if m.name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
        let parts: [(&str, &str, &str, &[u8]); 2] = [("channel_id", "", "", channel.as_bytes()), ("files", &name, &m.mime, &data)];
        let v = self.inner.rest("POST", "/files", Payload::Multipart(&parts))?;
        v["file_infos"][0]["id"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "mattermost upload: no file id"))
    }

    fn buttons(&self, rows: &[Vec<Button>]) -> Option<Value> {
        let base = self.inner.cfg.callback_url.as_deref()?;
        let url = format!("{}/actions", base.trim_end_matches('/'));
        let actions: Vec<Value> = rows
            .iter()
            .flatten()
            .enumerate()
            .filter(|(_, b)| b.url.is_none())
            .map(|(i, b)| json!({"id": format!("seagent{i}"), "name": b.label, "type": "button", "style": "default", "integration": {"url": url, "context": {"seagent": b.data, "_token": self.inner.sign(&b.data)}}}))
            .collect();
        let links: Vec<String> = rows.iter().flatten().filter_map(|b| b.url.as_ref().map(|u| format!("[{}]({u})", b.label))).collect();
        let mut att = json!({"actions": actions});
        if !links.is_empty() {
            att["text"] = json!(links.join(" · "));
        }
        Some(json!([att]))
    }

    /// No callback URL: numbered options in the text (URL buttons as links).
    fn button_text(rows: &[Vec<Button>]) -> String {
        rows.iter()
            .flatten()
            .enumerate()
            .map(|(i, b)| match &b.url {
                Some(u) => format!("{}. [{}]({u})", i + 1, b.label),
                None => format!("{}. {}", i + 1, b.label),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn create_post(&self, body: &mut Value) -> Result<String, ChannelError> {
        let v = match self.inner.rest("POST", "/posts", Payload::Json(body)) {
            // A stale or invalid root: post at top level instead of failing.
            Err(e) if e.kind == K::Protocol && e.message.contains("root_id") && body.get("root_id").is_some() => {
                body.as_object_mut().unwrap().remove("root_id");
                self.inner.rest("POST", "/posts", Payload::Json(body))?
            }
            r => r?,
        };
        let id = v["id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "mattermost: post without id"))?.to_string();
        if let Some(me) = self.inner.me.lock().unwrap().clone() {
            self.inner.posts.lock().unwrap().put(&id, &me.id);
        }
        if let Some(r) = body["root_id"].as_str() {
            self.inner.roots.lock().unwrap().insert(id.clone(), r.to_string());
        }
        Ok(id)
    }
}

impl Drop for Mattermost {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Channel for Mattermost {
    fn id(&self) -> &str {
        &self.inner.cfg.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 20,
            edit: true,
            delete: true,
            typing: true,
            buttons: self.inner.cfg.callback_url.is_some(),
            polls: false,
            native_commands: self.inner.cfg.slash_commands && self.inner.cfg.callback_url.is_some(),
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started();
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.inner.cfg.poll_timeout_secs.max(1));
        loop {
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if cancel.is_cancelled() || Instant::now() >= until {
                return Ok(vec![]);
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    let mut got = vec![m];
                    got.extend(rx.try_iter());
                    return Ok(got);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.inner.fatal.lock().unwrap().clone().unwrap_or_else(|| ChannelError::new(K::Network, "mattermost receiver stopped"))),
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let channel = self.target(&out.chat)?;
        let root = match (out.thread.as_deref(), out.reply_to.as_deref()) {
            (Some(t), _) if !t.is_empty() => Some(t.to_string()),
            (_, Some(r)) if !r.is_empty() => Some(self.inner.root_of(r)),
            _ => None,
        };
        let mut text = out.text.clone();
        let mut file_ids = Vec::new();
        for m in &out.media {
            match (&m.path, &m.url) {
                (Some(_), _) => file_ids.push(self.upload(&channel, m)?),
                (None, Some(u)) => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&if m.kind == MediaKind::Image { format!("![{}]({u})", m.name) } else { u.clone() });
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            }
        }
        let attachments = if out.buttons.is_empty() { None } else { self.buttons(&out.buttons) };
        if !out.buttons.is_empty() && attachments.is_none() {
            text = format!("{}\n\n{}", text.trim_end(), Self::button_text(&out.buttons)).trim_start().to_string();
        }
        let mut pieces = if text.trim().is_empty() { vec![] } else { crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) };
        let batches: Vec<Vec<String>> = file_ids.chunks(MAX_FILES).map(<[String]>::to_vec).collect();
        while pieces.len() < batches.len().max(usize::from(attachments.is_some())) {
            pieces.push(String::new());
        }
        let n = pieces.len();
        let mut sent = Sent::default();
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut body = json!({"channel_id": channel, "message": piece});
            if let Some(r) = &root {
                body["root_id"] = json!(r);
            }
            if let Some(files) = batches.get(i) {
                body["file_ids"] = json!(files);
            }
            if let (true, Some(a)) = (i + 1 == n, &attachments) {
                body["props"] = json!({"attachments": a});
            }
            sent.ids.push(self.create_post(&mut body)?);
        }
        Ok(sent)
    }

    fn edit(&self, _chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let body = json!({"message": text.chars().take(MAX_MESSAGE).collect::<String>()});
        self.inner.rest("PUT", &format!("/posts/{message_id}/patch"), Payload::Json(&body)).map(|_| ())
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.inner.rest("DELETE", &format!("/posts/{message_id}"), Payload::None).map(|_| ())
    }

    /// Over the socket when connected (as the web client does), else REST.
    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let parent = thread.unwrap_or("");
        if let Some(tx) = self.inner.ws_out.lock().unwrap().as_ref() {
            let seq = {
                let mut s = self.inner.ws_seq.lock().unwrap();
                *s += 1;
                *s
            };
            if tx.send(json!({"action": "user_typing", "seq": seq, "data": {"channel_id": chat, "parent_id": parent}}).to_string()).is_ok() {
                return Ok(());
            }
        }
        let mut body = json!({"channel_id": chat});
        if !parent.is_empty() {
            body["parent_id"] = json!(parent);
        }
        self.inner.rest("POST", "/users/me/typing", Payload::Json(&body)).map(|_| ())
    }

    fn react(&self, _chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let me = self.inner.me()?;
        let name = emoji_name(emoji);
        if remove {
            self.inner.rest("DELETE", &format!("/users/{}/posts/{message_id}/reactions/{}", me.id, seagent_net::urlencode(&name)), Payload::None).map(|_| ())
        } else {
            self.inner.rest("POST", "/reactions", Payload::Json(&json!({"user_id": me.id, "post_id": message_id, "emoji_name": name}))).map(|_| ())
        }
    }

    /// The click was answered at once; text goes to the presser as an ephemeral post.
    fn ack_callback(&self, cb: &Callback, text: Option<&str>) -> Result<(), ChannelError> {
        let Some(t) = text else { return Ok(()) };
        let Some((user, channel)) = self.inner.clicks.lock().unwrap().remove(&cb.id) else { return Ok(()) };
        self.inner.rest("POST", "/posts/ephemeral", Payload::Json(&json!({"user_id": user, "post": {"channel_id": channel, "message": t}}))).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = match (&m.url, &m.id) {
            (Some(u), _) => u.clone(),
            (None, Some(id)) => self.inner.url(&format!("/files/{id}")),
            _ => return Err(ChannelError::new(K::Fatal, "mattermost file without id")),
        };
        let auth = format!("Bearer {}", self.inner.cfg.token);
        crate::http::get_bytes_trusted(&url, &[("authorization", &auth)], 100 * 1024 * 1024, &self.inner.cfg.base_url)
    }

    fn stop(&self) {
        self.stop.cancel();
    }
}

// ---------------------------------------------------------------- config

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Server base URL.
    url: String,
    /// Bot access token (or personal access token).
    token: String,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Local address for button/slash callbacks …
    #[serde(default)]
    listen: Option<String>,
    /// … and the public URL Mattermost reaches it at.
    #[serde(default)]
    callback_url: Option<String>,
    #[serde(default)]
    slash_commands: bool,
    #[serde(default)]
    slash_tokens: Vec<String>,
    #[serde(default)]
    reaction_events: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let mut cfg = Config::new(ctx.name, &st.url, &ctx.secret("token", &st.token)?);
    cfg.poll_timeout_secs = st.poll_timeout_secs;
    cfg.callback_url = st.callback_url;
    cfg.slash_commands = st.slash_commands;
    cfg.slash_tokens = st.slash_tokens.iter().map(|t| ctx.secret("slash_tokens", t)).collect::<Result<_, _>>()?;
    cfg.reaction_events = st.reaction_events;
    if cfg.slash_commands && cfg.callback_url.is_none() {
        return Err(format!("channel {}: slash_commands needs callback_url and listen", ctx.name));
    }
    let mut m = Mattermost::new(cfg)?;
    match st.listen {
        Some(l) => m = m.with_listener(&l)?,
        None if m.inner.cfg.callback_url.is_some() => return Err(format!("channel {}: callback_url needs listen", ctx.name)),
        None => {}
    }
    Ok(Arc::new(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer, Req};
    use seagent_net::ws::{header, read_head};
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;
    type Reply = (u16, Vec<(String, String)>, String);

    /// One port serving both the REST API (via `rest`) and the websocket (via `script`).
    fn server(rest: impl Fn(&Req, usize) -> Reply + Send + Sync + 'static, script: impl Fn(usize, String, Ws) + Send + Sync + 'static) -> (String, FakeServer) {
        let api = FakeServer::start(rest);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let api_addr = api.url.trim_start_matches("http://").to_string();
        let script = Arc::new(script);
        std::thread::spawn(move || {
            let mut n = 0;
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let Ok((head, rest)) = read_head(&mut s, 65536) else { continue };
                if head.starts_with("GET /api/v4/websocket") {
                    let script = script.clone();
                    let k = n;
                    n += 1;
                    std::thread::spawn(move || {
                        let ws = WebSocket::accept(s, &head, rest).unwrap();
                        script(k, head, ws);
                    });
                } else {
                    // Proxy plain HTTP to the recording fake API.
                    let api_addr = api_addr.clone();
                    std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        let mut up = TcpStream::connect(&api_addr).unwrap();
                        up.write_all(head.as_bytes()).unwrap();
                        up.write_all(&rest).unwrap();
                        let len: usize = header(&head, "content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
                        let mut body = vec![0; len.saturating_sub(rest.len())];
                        s.read_exact(&mut body).unwrap();
                        up.write_all(&body).unwrap();
                        let mut resp = Vec::new();
                        up.read_to_end(&mut resp).unwrap();
                        s.write_all(&resp).unwrap();
                    });
                }
            }
        });
        (format!("http://{addr}"), api)
    }

    fn me_or(req: &Req, n: usize, f: impl Fn(&Req, usize) -> Reply) -> Reply {
        match req.path.as_str() {
            "/api/v4/users/me" => (200, vec![], json!({"id": "BOT", "username": "seagent"}).to_string()),
            _ => f(req, n),
        }
    }

    fn cfg(base: &str) -> Config {
        let mut c = Config::new("mm", base, "SECRET-TOKEN");
        c.poll_timeout_secs = 1;
        c.retry_base = Duration::from_millis(5);
        c.reconnect_base = Duration::from_millis(5);
        c
    }

    fn auth(ws: &mut Ws) -> Value {
        let Message::Text(t) = ws.recv_blocking().unwrap() else { panic!("expected challenge") };
        let v: Value = serde_json::from_str(&t).unwrap();
        ws.send_text(&json!({"status": "OK", "seq_reply": v["seq"]}).to_string()).unwrap();
        ws.send_text(&json!({"event": "hello", "data": {"server_version": "9.0"}, "broadcast": {}, "seq": 0}).to_string()).unwrap();
        v
    }

    fn posted(event: &str, post: Value, data: Value) -> String {
        let mut d = data;
        d["post"] = json!(post.to_string());
        json!({"event": event, "data": d, "broadcast": {"channel_id": post["channel_id"]}, "seq": 1}).to_string()
    }

    fn idle(ws: &mut Ws) -> Vec<Value> {
        let mut seen = vec![];
        while let Ok(m) = ws.recv_blocking() {
            match m {
                Message::Close(_) => break,
                Message::Text(t) => seen.push(serde_json::from_str(&t).unwrap()),
                _ => {}
            }
        }
        seen
    }

    fn collect(m: &Mattermost, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(8);
        while got.len() < n && Instant::now() < until {
            got.extend(m.poll(&Cancel::new()).unwrap());
        }
        got
    }

    fn post(id: &str, channel: &str, user: &str, msg: &str) -> Value {
        json!({"id": id, "channel_id": channel, "user_id": user, "message": msg, "type": "", "root_id": "", "create_at": 1700000000123i64, "props": {}})
    }

    #[test]
    fn websocket_auth_and_every_inbound_kind() {
        let (tx, rx) = mpsc::channel::<String>();
        let tx = Mutex::new(tx);
        let (base, api) = server(
            |req, n| me_or(req, n, |req, _| match req.path.as_str() {
                "/api/v4/posts/ROOT2" => (200, vec![], json!({"id": "ROOT2", "user_id": "BOT", "root_id": ""}).to_string()),
                "/api/v4/posts/ROOT3" => (200, vec![], json!({"id": "ROOT3", "user_id": "U2", "root_id": ""}).to_string()),
                _ => (404, vec![], "{}".into()),
            }),
            move |_, head, mut ws| {
                tx.lock().unwrap().send(header(&head, "authorization").unwrap_or("").to_string()).unwrap();
                let ch = auth(&mut ws);
                tx.lock().unwrap().send(ch.to_string()).unwrap();
                let d = |t: &str| json!({"channel_type": t, "sender_name": "@amy", "channel_display_name": "Town Square", "team_id": "T1"});
                let mut thread = post("P3", "C1", "U1", "yes");
                thread["root_id"] = json!("ROOT2");
                let mut other_thread = post("P4", "C1", "U1", "no");
                other_thread["root_id"] = json!("ROOT3");
                let mut file = post("P5", "D1", "U1", "");
                file["file_ids"] = json!(["F1"]);
                file["metadata"] = json!({"files": [{"id": "F1", "name": "a.png", "mime_type": "image/png", "size": 9}]});
                let mut sys = post("P7", "C1", "U1", "amy joined");
                sys["type"] = json!("system_join_channel");
                let mut bot = post("P8", "C1", "U3", "beep");
                bot["props"] = json!({"from_bot": "true"});
                let mut edited = post("P2", "C1", "U1", "edited @seagent");
                edited["edit_at"] = json!(1700000099000i64);
                for e in [
                    posted("posted", post("P1", "D1", "U1", "hi"), d("D")),
                    posted("posted", post("P2", "C1", "U1", "hey"), json!({"channel_type": "O", "mentions": "[\"BOT\"]", "sender_name": "@amy"})),
                    posted("posted", post("P2b", "G1", "U1", "ping @SEAGENT, ok?"), d("G")),
                    posted("posted", post("P2c", "C1", "U1", "mail seagent@ex.com or @arkade"), d("P")),
                    posted("posted", thread, d("O")),
                    posted("posted", other_thread, d("O")),
                    posted("posted", file, d("D")),
                    posted("posted", post("P6", "C1", "BOT", "my own"), d("O")),
                    posted("posted", sys, d("O")),
                    posted("posted", bot, d("O")),
                    posted("post_edited", edited, d("O")),
                    json!({"event": "reaction_added", "data": {"reaction": json!({"user_id": "U1", "post_id": "P9", "emoji_name": "+1"}).to_string()}, "broadcast": {"channel_id": "C1"}}).to_string(),
                ] {
                    ws.send_text(&e).unwrap();
                }
                idle(&mut ws);
            },
        );
        let mut c = cfg(&base);
        c.reaction_events = true;
        let m = Mattermost::new(c).unwrap();
        let g = collect(&m, 10);
        assert_eq!(rx.recv().unwrap(), "Bearer SECRET-TOKEN");
        let ch: Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        assert_eq!((ch["action"].as_str(), ch["data"]["token"].as_str()), (Some("authentication_challenge"), Some("SECRET-TOKEN")));
        assert_eq!(g.len(), 10, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].ts, g[0].chat_name.as_str()), ("D1", ChatType::Direct, "U1", "amy", 1700000000, "Town Square"));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group, "mentions list");
        assert!(g[2].mentioned && g[2].chat_type == ChatType::Group, "@username, case-insensitive");
        assert!(!g[3].mentioned, "not an email or a longer name");
        assert_eq!((g[4].chat_type, g[4].thread.as_deref()), (ChatType::Thread, Some("ROOT2")));
        assert!(g[4].reply.as_ref().unwrap().is_own, "root by the bot");
        assert!(!g[5].reply.as_ref().unwrap().is_own);
        assert_eq!((g[6].media[0].kind, g[6].media[0].url.clone(), g[6].media[0].name.as_str()), (MediaKind::Image, Some(format!("{base}/api/v4/files/F1")), "a.png"));
        assert!(g[7].is_bot && g[7].text == "beep", "own and system posts dropped");
        assert!(g[8].edited && g[8].message_id == "P2:e1700000099000" && g[8].mentioned);
        assert_eq!((g[9].text.as_str(), g[9].reply.as_ref().unwrap().id.as_str()), (":+1: reaction added", "P9"));
        assert!(api.requests().iter().any(|r| r.path == "/api/v4/posts/ROOT2"));
        m.stop();
    }

    #[test]
    fn reconnects_after_drop_and_types_over_the_socket() {
        let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
        let s2 = seen.clone();
        let (base, api) = server(
            |req, n| me_or(req, n, |_, _| (200, vec![], "{}".into())),
            move |n, _, mut ws| {
                auth(&mut ws);
                if n == 0 {
                    std::thread::sleep(Duration::from_millis(50));
                    ws.get_ref().shutdown(std::net::Shutdown::Both).unwrap();
                    return;
                }
                ws.send_text(&posted("posted", post("P1", "D1", "U1", "back"), json!({"channel_type": "D"}))).unwrap();
                ws.get_ref().set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let got = idle(&mut ws);
                s2.lock().unwrap().extend(got);
            },
        );
        let m = Mattermost::new(cfg(&base)).unwrap();
        assert_eq!(collect(&m, 1)[0].text, "back");
        m.typing("C1", Some("ROOT")).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        m.stop();
        let until = Instant::now() + Duration::from_secs(3);
        while seen.lock().unwrap().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let s = seen.lock().unwrap().clone();
        let t = s.iter().find(|v| v["action"] == "user_typing").unwrap_or_else(|| panic!("{s:?}"));
        assert_eq!((t["data"]["channel_id"].as_str(), t["data"]["parent_id"].as_str()), (Some("C1"), Some("ROOT")));
        assert!(!api.requests().iter().any(|r| r.path == "/api/v4/users/me/typing"), "socket used, not REST");
    }

    #[test]
    fn bad_token_is_auth_and_cancel_is_prompt() {
        let srv = FakeServer::start(|_, _| (401, vec![], json!({"id": "api.context.session_expired.app_error", "message": "Invalid or expired session"}).to_string()));
        let m = Mattermost::new(cfg(&srv.url)).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let e = loop {
            match m.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no auth error"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("SECRET"));
        // Websocket upgrade refused with 401.
        let (base, _api) = server(|req, n| me_or(req, n, |_, _| (200, vec![], "{}".into())), |_, _, _| {});
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let api_url = base.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                if head.starts_with("GET /api/v4/websocket") {
                    let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
                } else {
                    let mut up = TcpStream::connect(api_url.trim_start_matches("http://")).unwrap();
                    up.write_all(&buf[..n]).unwrap();
                    let mut resp = Vec::new();
                    up.read_to_end(&mut resp).unwrap();
                    let _ = s.write_all(&resp);
                }
            }
        });
        let m = Mattermost::new(cfg(&format!("http://{addr}"))).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let e = loop {
            match m.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no auth error"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth);
        // Cancel while the socket handshake hangs.
        let (base, _api) = server(|req, n| me_or(req, n, |_, _| (200, vec![], "{}".into())), |_, _, _| std::thread::sleep(Duration::from_secs(10)));
        let mut c = cfg(&base);
        c.poll_timeout_secs = 20;
        let m = Mattermost::new(c).unwrap();
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(m.poll(&cancel).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn send_shapes_threads_files_buttons_and_actions() {
        let srv = FakeServer::start(|req, n| match req.path.as_str() {
            "/api/v4/users/me" => (200, vec![], json!({"id": "BOT", "username": "seagent"}).to_string()),
            "/api/v4/posts/REPLY" => (200, vec![], json!({"id": "REPLY", "user_id": "U1", "root_id": "ROOT"}).to_string()),
            "/api/v4/files" => (201, vec![], json!({"file_infos": [{"id": format!("F{n}")}]}).to_string()),
            "/api/v4/channels/direct" => (201, vec![], json!({"id": "DM1"}).to_string()),
            "/api/v4/users/username/bob" => (200, vec![], json!({"id": "U9"}).to_string()),
            "/api/v4/files/F1" => (200, vec![], "BYTES".into()),
            p if p.starts_with("/api/v4/posts") && req.method == "POST" && !p.contains("ephemeral") => (201, vec![], json!({"id": format!("P{n}")}).to_string()),
            _ => (200, vec![], json!({"status": "OK"}).to_string()),
        });
        let mut c = cfg(&srv.url);
        c.callback_url = Some("https://bot.example.com/mm".into());
        let m = Mattermost::new(c).unwrap();
        let btns = vec![vec![Button { label: "Allow".into(), data: "appr:x:once".into(), url: None }, Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]];
        let s = m.send(&Outbound { reply_to: Some("REPLY".into()), buttons: btns.clone(), format: crate::TextFormat::Markdown, ..Outbound::text("C1", "**hi**") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let reqs = srv.requests();
        let p = reqs.iter().find(|r| r.path == "/api/v4/posts").unwrap();
        assert_eq!(p.header("authorization"), Some("Bearer SECRET-TOKEN"));
        let b = p.json();
        assert_eq!((b["channel_id"].as_str(), b["message"].as_str(), b["root_id"].as_str()), (Some("C1"), Some("**hi**"), Some("ROOT")), "reply resolved to the thread root");
        let a = &b["props"]["attachments"][0];
        assert_eq!(a["actions"][0]["integration"]["url"], "https://bot.example.com/mm/actions");
        assert_eq!(a["actions"][0]["integration"]["context"]["seagent"], "appr:x:once");
        assert_eq!(a["actions"][0]["integration"]["context"]["_token"].as_str().unwrap(), m.inner.sign("appr:x:once"));
        assert!(a["text"].as_str().unwrap().contains("[docs](https://e.com)"));
        // No callback URL: numbered options in the text.
        let plain = Mattermost::new(cfg(&srv.url)).unwrap();
        assert!(!plain.caps().buttons && m.caps().buttons);
        plain.send(&Outbound { thread: Some("ROOT".into()), buttons: btns, ..Outbound::text("C1", "pick") }).unwrap();
        let b = srv.requests().last().unwrap().json();
        assert_eq!((b["message"].as_str(), b["root_id"].as_str()), (Some("pick\n\n1. Allow\n2. [docs](https://e.com)"), Some("ROOT")));
        assert!(b.get("props").is_none());
        // Local file → POST /files, then the post carries file_ids; DM by @username.
        let f = temp_dir("mm").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let start = srv.requests().len();
        m.send(&Outbound { media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() }], ..Outbound::text("@bob", "report") }).unwrap();
        let reqs = srv.requests();
        let paths: Vec<&str> = reqs[start..].iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/api/v4/users/username/bob", "/api/v4/users/me", "/api/v4/channels/direct", "/api/v4/files", "/api/v4/posts"]);
        assert_eq!(reqs[start + 2].json(), json!(["BOT", "U9"]));
        let up = &reqs[start + 3];
        assert!(up.header("content-type").unwrap().starts_with("multipart/form-data") && up.body.contains("name=\"files\"; filename=\"report.pdf\"") && up.body.contains("name=\"channel_id\"\r\n\r\nDM1"), "{}", up.body);
        let fid = format!("F{}", start + 3);
        assert_eq!((reqs[start + 4].json()["file_ids"][0].as_str(), reqs[start + 4].json()["channel_id"].as_str()), (Some(fid.as_str()), Some("DM1")));
        // Long text splits at 16383.
        let start = srv.requests().len();
        assert_eq!(m.send(&Outbound::text("C1", &"y".repeat(20000))).unwrap().ids.len(), 2);
        assert!(srv.requests()[start..].iter().all(|r| r.json()["message"].as_str().unwrap().chars().count() <= MAX_MESSAGE));
        // Actions (no socket yet → REST typing).
        let start = srv.requests().len();
        m.edit("C1", "P1", "new").unwrap();
        m.delete("C1", "P1").unwrap();
        m.react("C1", "P1", "👍", false).unwrap();
        m.react("C1", "P1", ":eyes:", true).unwrap();
        m.typing("C1", Some("ROOT")).unwrap();
        let got: Vec<(String, String)> = srv.requests()[start..].iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        let want = [("PUT", "/api/v4/posts/P1/patch"), ("DELETE", "/api/v4/posts/P1"), ("POST", "/api/v4/reactions"), ("DELETE", "/api/v4/users/BOT/posts/P1/reactions/eyes"), ("POST", "/api/v4/users/me/typing")];
        assert_eq!(got, want.map(|(a, b)| (a.to_string(), b.to_string())));
        let reqs = srv.requests();
        assert_eq!(reqs[start].json(), json!({"message": "new"}));
        assert_eq!(reqs[start + 2].json(), json!({"user_id": "BOT", "post_id": "P1", "emoji_name": "+1"}));
        assert_eq!(reqs[start + 4].json(), json!({"channel_id": "C1", "parent_id": "ROOT"}));
        assert_eq!(m.fetch_media(&Media { id: Some("F1".into()), ..Default::default() }).unwrap(), b"BYTES");
        assert_eq!(srv.requests().last().unwrap().header("authorization"), Some("Bearer SECRET-TOKEN"));
    }

    #[test]
    fn error_mapping_retries_and_stale_root() {
        for (status, id, kind) in [(401, "api.context.session_expired.app_error", K::Auth), (403, "api.context.permissions.app_error", K::NotFound), (404, "app.channel.get.existing.app_error", K::NotFound), (400, "api.post.create_post.bad_message", K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"id": id, "message": "nope", "status_code": status}).to_string()));
            let e = Mattermost::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {id}");
            assert!(!e.message.contains("SECRET"));
            assert_eq!(srv.requests().len(), 1, "{status} not retried");
        }
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![("retry-after".into(), "1".into())], json!({"message": "too many"}).to_string()),
            1 => (500, vec![], "oops".into()),
            _ => (201, vec![], json!({"id": "P1"}).to_string()),
        });
        let t = Instant::now();
        Mattermost::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(950));
        assert_eq!(srv.requests().len(), 3);
        let srv = FakeServer::start(|_, _| (503, vec![], "down".into()));
        assert_eq!(Mattermost::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len(), 5);
        // Invalid root_id: retried once at top level.
        let srv = FakeServer::start(|req, _| if req.json().get("root_id").is_some() { (400, vec![], json!({"id": "api.post.create_post.root_id.app_error", "message": "Invalid RootId parameter."}).to_string()) } else { (201, vec![], json!({"id": "P2"}).to_string()) });
        let s = Mattermost::new(cfg(&srv.url)).unwrap().send(&Outbound { thread: Some("GONE".into()), ..Outbound::text("C1", "x") }).unwrap();
        assert_eq!(s.ids, ["P2"]);
        assert_eq!(srv.requests().len(), 2);
    }

    #[test]
    fn interactions_and_slash_commands_are_verified() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/api/v4/users/me" => (200, vec![], json!({"id": "BOT", "username": "seagent"}).to_string()),
            "/api/v4/users/BOT/teams" => (200, vec![], json!([{"id": "T1"}]).to_string()),
            p if p.starts_with("/api/v4/commands?") => (200, vec![], json!([{"trigger": "seagent_new", "url": "https://bot.example.com/mm/slash", "token": "TOKNEW"}, {"trigger": "seagent_stop", "url": "https://other.example.com", "token": "THEIRS"}]).to_string()),
            "/api/v4/commands" => (201, vec![], json!({"token": format!("TOK-{}", req.json()["trigger"].as_str().unwrap())}).to_string()),
            _ => (201, vec![], "{}".into()),
        });
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        let mut c = cfg(&srv.url);
        c.callback_url = Some("https://bot.example.com/mm".into());
        c.slash_commands = true;
        let m = Mattermost::new(c).unwrap().with_listener(&listen).unwrap();
        let me = m.inner.me().unwrap();
        m.inner.register_slash(&me);
        let created: Vec<String> = srv.requests().iter().filter(|r| r.path == "/api/v4/commands").map(|r| r.json()["trigger"].as_str().unwrap().to_string()).collect();
        assert_eq!(created, ["seagent_status", "seagent_help"], "ours adopted, someone else's left alone");
        let reg = srv.requests().iter().find(|r| r.path == "/api/v4/commands").unwrap().json();
        assert_eq!((reg["team_id"].as_str(), reg["method"].as_str(), reg["url"].as_str()), (Some("T1"), Some("P"), Some("https://bot.example.com/mm/slash")));
        let post = |path: &str, ctype: &str, body: &str| -> u16 {
            let a = crate::http::agent(Duration::from_secs(5));
            a.post(&format!("http://{listen}{path}")).header("content-type", ctype).send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
        };
        let click = |data: &str, tok: &str| json!({"user_id": "U1", "user_name": "amy", "channel_id": "C1", "team_id": "T1", "post_id": "P1", "trigger_id": "TRIG", "type": "button", "context": {"seagent": data, "_token": tok}}).to_string();
        assert_eq!(post("/mm/actions", "application/json", &click("appr:1:once", &m.inner.sign("appr:1:once"))), 200);
        assert_eq!(post("/mm/actions", "application/json", &click("appr:1:always", &m.inner.sign("appr:1:once"))), 403, "context bound to its signature");
        assert_eq!(post("/mm/actions", "application/json", &json!({"context": {"seagent": "x"}}).to_string()), 403, "unsigned");
        let form = |cmd: &str, tok: &str| seagent_net::form_encode(&[("token", tok), ("team_id", "T1"), ("channel_id", "C1"), ("channel_name", "town-square"), ("user_id", "U1"), ("user_name", "amy"), ("command", cmd), ("text", "now"), ("trigger_id", "TR2")]);
        assert_eq!(post("/mm/slash", "application/x-www-form-urlencoded", &form("/seagent_new", "TOKNEW")), 200);
        assert_eq!(post("/mm/slash", "application/x-www-form-urlencoded", &form("/seagent_status", "TOK-seagent_status")), 200);
        assert_eq!(post("/mm/slash", "application/x-www-form-urlencoded", &form("/seagent_new", "TOK-seagent_status")), 401, "token of another command");
        assert_eq!(post("/mm/slash", "application/x-www-form-urlencoded", &form("/seagent_stop", "THEIRS")), 401);
        assert_eq!(post("/mm/other", "application/json", "{}"), 404);
        let g = collect(&m, 3);
        let cb = g[0].callback.as_ref().unwrap();
        assert_eq!((cb.id.as_str(), cb.data.as_str(), g[0].chat.as_str(), g[0].reply.as_ref().unwrap().id.as_str()), ("TRIG", "appr:1:once", "C1", "P1"));
        assert_eq!(g[1..].iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["/new now", "/status now"]);
        m.ack_callback(cb, Some("done")).unwrap();
        let r = srv.requests().into_iter().find(|r| r.path == "/api/v4/posts/ephemeral").unwrap();
        assert_eq!(r.json(), json!({"user_id": "U1", "post": {"channel_id": "C1", "message": "done"}}));
        assert!(m.caps().native_commands);
        m.stop();
    }
}
