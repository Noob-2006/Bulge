//! Slack app (ported from OpenClaw `extensions/slack` and Hermes
//! `plugins/platforms/slack`, both MIT).
//!
//! Receive, either:
//! - Socket Mode: `apps.connections.open` with the app-level token (`xapp-…`)
//!   → WebSocket; every envelope is acknowledged by `envelope_id` at once;
//!   `hello` / `disconnect` (refresh) / dropped sockets reconnect with backoff,
//!   our own pings detect dead links; or
//! - HTTP Events API: a listener verifying `X-Slack-Signature`
//!   (`v0=` HMAC-SHA256 of `v0:<ts>:<body>`, requests older than 5 min refused),
//!   answering `url_verification`, and taking interactivity / slash-command posts.
//!
//! Messages in DMs (`im`), group DMs, channels and threads (`thread_ts`),
//! `app_mention`, edits (`message_changed`), files, replies in threads the bot
//! started (`parent_user_id`); the bot's own messages are dropped. Button
//! presses (`block_actions`) become `Callback`s, slash commands `/cmd text`.
//! Send: `chat.postMessage` with mrkdwn, threads and Block Kit buttons; files
//! via upload v2 (`files.getUploadURLExternal` → upload → `files.completeUploadExternal`);
//! `chat.update`, `chat.delete`, `reactions.add/remove`, `assistant.threads.setStatus`
//! as typing, native streaming (`chat.startStream/appendStream/stopStream`).
//!
//! Interactivity: a button row longer than five becomes a `static_select`
//! (`external_select` past 100 options, answered from a local store on
//! `block_suggestion`, as upstream's slash-argument menus do); a lone button whose
//! data is `slack:users_select[:tag]` (also `channels_select`, `conversations_select`)
//! renders that picker and returns `<data>=<ids>`. Buttons with data `modal:<name>`
//! open the configured view (`views.open`, or `views.push` inside a modal);
//! `view_submission` / `view_closed` of those views come back as messages
//! summarising the inputs. `assistant_thread_started` gets suggested prompts;
//! the first addressed message in a thread carries the thread's earlier
//! messages (`conversations.replies`); senders without a profile are named via
//! a cached `users.info`; callback answers fall back to `chat.postEphemeral`.

use crate::http::{Http, Payload};
use crate::{
    markup, sleep_cancellable, Button, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat,
};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "slack_actions.rs"]
mod actions;

pub const DEFAULT_API: &str = "https://slack.com/api";
/// Slack accepts 40k chars but truncates rendering; section blocks hold 3000.
pub const MAX_MESSAGE: usize = 4000;
const MAX_SECTION: usize = 3000;
/// Slack refuses signed requests older than this (replay protection).
const MAX_SKEW_SECS: i64 = 300;
/// Rows longer than this become a select menu (upstream's button row size).
const BUTTON_ROW: usize = 5;
const SELECT_MAX: usize = 100;
const OPTION_VALUE_MAX: usize = 150;
const MENU_PREFIX: &str = "seagent_menu:";
const MENU_TTL: Duration = Duration::from_secs(30 * 60);
const USER_TTL: Duration = Duration::from_secs(3600);
/// conversations.replies pages fetched for thread history (upstream caps at three).
const HISTORY_PAGES: usize = 3;
const PICKERS: [&str; 6] = ["users_select", "channels_select", "conversations_select", "multi_users_select", "multi_channels_select", "multi_conversations_select"];

#[derive(Debug, Clone)]
pub struct Config {
    pub id: String,
    pub bot_token: String,
    /// Socket Mode app-level token (`xapp-…`).
    pub app_token: Option<String>,
    pub api_base: String,
    pub poll_timeout_secs: u64,
    /// Advertise `Streaming::Native` (chat.startStream needs an "Agents & AI Apps" app).
    pub native_streaming: bool,
    pub typing_status: String,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// Socket Mode: send a ping this often and reconnect when no pong comes back.
    pub ping_every: Duration,
    /// name → Block Kit view (`type`, `callback_id`, `private_metadata` are filled in).
    pub modals: HashMap<String, Value>,
    /// (title, message) shown when an assistant thread starts; empty = don't set.
    pub suggested_prompts: Vec<(String, String)>,
    pub suggested_prompts_title: String,
    /// Earlier thread messages attached to the first addressed message of a thread (0 = off).
    pub thread_history: usize,
}

impl Config {
    pub fn new(id: &str, bot_token: &str) -> Config {
        Config {
            id: id.into(),
            bot_token: bot_token.trim().into(),
            app_token: None,
            api_base: DEFAULT_API.into(),
            poll_timeout_secs: 25,
            native_streaming: false,
            typing_status: "is typing…".into(),
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
            ping_every: Duration::from_secs(30),
            modals: HashMap::new(),
            suggested_prompts: [("What can you do?", "What can you help me with?"), ("Summarize this channel", "Summarize the recent activity in this channel."), ("Draft a reply", "Help me draft a reply.")].iter().map(|(t, m)| (t.to_string(), m.to_string())).collect(),
            suggested_prompts_title: "Try asking".into(),
            thread_history: 20,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Me {
    user_id: String,
    bot_id: String,
    name: String,
}

/// Stored `external_select` options: (created, [(label, value)]).
type Menu = (Instant, Vec<(String, String)>);

/// Where to answer a callback privately.
#[derive(Debug, Clone, Default)]
struct Answer {
    url: Option<String>,
    user: String,
    channel: String,
    thread: Option<String>,
}

struct Inner {
    cfg: Config,
    http: Http,
    me: Mutex<Option<Me>>,
    /// action_ts → response_url / user, for ephemeral callback answers.
    responses: Mutex<HashMap<String, Answer>>,
    /// external_select token → (created, [(label, value)]).
    menus: Mutex<HashMap<String, Menu>>,
    /// users.info cache: user → (fetched, display name).
    users: Mutex<HashMap<String, (Instant, String)>>,
    /// Threads whose history was already attached (bounded).
    threads: Mutex<(HashSet<String>, VecDeque<String>)>,
    fatal: Mutex<Option<ChannelError>>,
}

pub struct Slack {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Value>>,
    tx: Mutex<Option<mpsc::Sender<Value>>>,
    stop: Cancel,
    /// HTTP Events mode listener (kept alive while the channel lives).
    _server: Option<seagent_net::httpd::Server>,
}

/// Slack `error` codes → error kinds.
fn slack_error(method: &str, status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let code = v["error"].as_str().unwrap_or("");
    let kind = match (status, code) {
        (429, _) | (_, "ratelimited") => K::RateLimited { retry_after },
        (_, "invalid_auth" | "not_authed" | "token_revoked" | "token_expired" | "account_inactive" | "no_permission" | "missing_scope" | "not_allowed_token_type" | "invalid_token") => K::Auth,
        (_, "channel_not_found" | "not_in_channel" | "is_archived" | "message_not_found" | "thread_not_found" | "user_not_found" | "cant_update_message" | "cant_delete_message" | "file_not_found" | "user_disabled" | "team_access_not_granted") => K::NotFound,
        (s, _) if s >= 500 => K::Network,
        (_, "internal_error" | "fatal_error" | "service_unavailable" | "request_timeout") => K::Network,
        (401 | 403, _) => K::Auth,
        (404 | 410, _) => K::NotFound,
        _ => K::Protocol,
    };
    let what = if code.is_empty() { format!("HTTP {status} {}", body.chars().take(200).collect::<String>()) } else { code.to_string() };
    ChannelError::new(kind, format!("slack {method}: {what}"))
}

impl Inner {
    /// One Web API call (JSON or form body) with retries for 5xx / 429.
    fn call(&self, method: &str, body: Payload, token: Option<&str>) -> Result<Value, ChannelError> {
        let url = format!("{}/{method}", self.cfg.api_base);
        let http = match token {
            Some(t) => Http { agent: self.http.agent.clone(), headers: vec![] }.bearer(t),
            None => self.http.clone(),
        };
        let mut attempt = 0;
        loop {
            let payload = match &body {
                Payload::Json(v) => Payload::Json(v),
                Payload::Form(f) => Payload::Form(f),
                Payload::None => Payload::None,
                Payload::Raw(t, b) => Payload::Raw(t, b),
                Payload::Multipart(p) => Payload::Multipart(p),
            };
            let err = match http.call("POST", &url, &[], payload) {
                Ok(r) => {
                    let v: Option<Value> = serde_json::from_str(&r.body).ok();
                    match v {
                        Some(v) if r.status == 200 && v["ok"] == true => return Ok(v),
                        _ => slack_error(method, r.status, r.retry_after, &r.body),
                    }
                }
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

    fn api(&self, method: &str, body: &Value) -> Result<Value, ChannelError> {
        self.call(method, Payload::Json(body), None)
    }

    /// Bot identity from `auth.test`, cached.
    fn me(&self) -> Result<Me, ChannelError> {
        if let Some(m) = self.me.lock().unwrap().clone() {
            return Ok(m);
        }
        let v = self.api("auth.test", &json!({}))?;
        let m = Me { user_id: v["user_id"].as_str().unwrap_or("").into(), bot_id: v["bot_id"].as_str().unwrap_or("").into(), name: v["user"].as_str().unwrap_or("").into() };
        *self.me.lock().unwrap() = Some(m.clone());
        Ok(m)
    }

    /// Display name via `users.info`, cached for an hour (failures cache "" too).
    fn user_name(&self, user: &str) -> String {
        if user.is_empty() {
            return String::new();
        }
        if let Some((at, n)) = self.users.lock().unwrap().get(user) {
            if at.elapsed() < USER_TTL {
                return n.clone();
            }
        }
        let name = match self.call("users.info", Payload::Form(&[("user", user)]), None) {
            Ok(v) => {
                let u = &v["user"];
                let p = &u["profile"];
                [&p["display_name"], &p["real_name"], &u["real_name"], &u["name"]].iter().filter_map(|x| x.as_str()).find(|x| !x.trim().is_empty()).unwrap_or("").to_string()
            }
            Err(_) => String::new(),
        };
        let mut c = self.users.lock().unwrap();
        if c.len() > 2000 {
            c.clear();
        }
        c.insert(user.to_string(), (Instant::now(), name.clone()));
        name
    }

    /// Store options for an `external_select`; returns its token.
    fn store_menu(&self, options: Vec<(String, String)>) -> String {
        let token = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8));
        let mut m = self.menus.lock().unwrap();
        m.retain(|_, (at, _)| at.elapsed() < MENU_TTL);
        while m.len() >= 256 {
            let Some(old) = m.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone()) else { break };
            m.remove(&old);
        }
        m.insert(token.clone(), (Instant::now(), options));
        token
    }

    /// `block_suggestion` answer: stored options whose label contains the typed text.
    fn suggest(&self, p: &Value) -> Value {
        let block = p["block_id"].as_str().or_else(|| p["actions"][0]["block_id"].as_str()).unwrap_or("");
        let q = p["value"].as_str().unwrap_or("").trim().to_lowercase();
        let menus = self.menus.lock().unwrap();
        let opts: Vec<Value> = block
            .strip_prefix(MENU_PREFIX)
            .and_then(|t| menus.get(t))
            .filter(|(at, _)| at.elapsed() < MENU_TTL)
            .map(|(_, o)| o.iter().filter(|(l, _)| q.is_empty() || l.to_lowercase().contains(&q)).take(SELECT_MAX).map(|(l, v)| option(l, v)).collect())
            .unwrap_or_default();
        json!({"options": opts})
    }

    /// Earlier messages of a thread, oldest first, as "name: text" lines (`conversations.replies`
    /// before `latest`, at most `limit`, three pages like upstream).
    fn thread_history(&self, chat: &str, thread_ts: &str, latest: &str, limit: usize, me: &Me) -> Vec<String> {
        let mut kept: Vec<(String, String)> = vec![];
        let mut cursor = String::new();
        for _ in 0..HISTORY_PAGES {
            let mut form = vec![("channel", chat), ("ts", thread_ts), ("limit", "200"), ("inclusive", "false")];
            if !latest.is_empty() {
                form.push(("latest", latest));
            }
            if !cursor.is_empty() {
                form.push(("cursor", &cursor));
            }
            let Ok(v) = self.call("conversations.replies", Payload::Form(&form), None) else { return vec![] };
            for m in v["messages"].as_array().into_iter().flatten() {
                let ts = m["ts"].as_str().unwrap_or("");
                let text = m["text"].as_str().unwrap_or("").trim();
                let files = m["files"].as_array().map_or(0, |f| f.len());
                if ts.is_empty() || ts == latest || (!latest.is_empty() && ts.parse::<f64>().unwrap_or(0.0) >= latest.parse::<f64>().unwrap_or(f64::MAX)) || (text.is_empty() && files == 0) || kept.iter().any(|(t, _)| t == ts) {
                    continue;
                }
                let user = m["user"].as_str().unwrap_or("");
                let who = if (!me.user_id.is_empty() && user == me.user_id) || (!me.bot_id.is_empty() && m["bot_id"].as_str() == Some(me.bot_id.as_str())) {
                    if me.name.is_empty() { "assistant".to_string() } else { me.name.clone() }
                } else if let Some(n) = m["user_profile"]["display_name"].as_str().filter(|n| !n.is_empty()).or_else(|| m["username"].as_str()) {
                    n.to_string()
                } else {
                    let n = self.user_name(user);
                    if n.is_empty() { user.to_string() } else { n }
                };
                let mut line = format!("{who}:");
                if !text.is_empty() {
                    line.push(' ');
                    line.push_str(&text.replace('\n', " "));
                }
                if files > 0 {
                    line.push_str(&format!(" [{files} file(s)]"));
                }
                kept.push((ts.to_string(), line));
            }
            cursor = v["response_metadata"]["next_cursor"].as_str().unwrap_or("").trim().to_string();
            if cursor.is_empty() {
                if v["has_more"] == true {
                    return vec![];
                }
                break;
            }
        }
        // An over-long thread is not truncated silently mid-way: upstream drops it.
        if !cursor.is_empty() {
            return vec![];
        }
        let skip = kept.len().saturating_sub(limit);
        kept.into_iter().skip(skip).map(|(_, l)| l).collect()
    }

    /// First time we see an addressed message in this thread?
    fn first_in_thread(&self, key: String) -> bool {
        let mut g = self.threads.lock().unwrap();
        if !g.0.insert(key.clone()) {
            return false;
        }
        g.1.push_back(key);
        while g.1.len() > 4096 {
            if let Some(old) = g.1.pop_front() {
                g.0.remove(&old);
            }
        }
        true
    }

    fn set_suggested_prompts(&self, chat: &str, thread: &str) -> Result<(), ChannelError> {
        let prompts: Vec<Value> = self.cfg.suggested_prompts.iter().map(|(t, m)| (t.trim(), m.trim())).filter(|(t, m)| !t.is_empty() && !m.is_empty()).take(4).map(|(t, m)| json!({"title": t, "message": m})).collect();
        if prompts.is_empty() {
            return Ok(());
        }
        let mut body = json!({"channel_id": chat, "thread_ts": thread, "prompts": prompts});
        if !self.cfg.suggested_prompts_title.trim().is_empty() {
            body["title"] = json!(self.cfg.suggested_prompts_title.trim());
        }
        self.api("assistant.threads.setSuggestedPrompts", &body).map(|_| ())
    }
}

fn option(label: &str, value: &str) -> Value {
    json!({"text": {"type": "plain_text", "text": truncate_chars(label, 75), "emoji": true}, "value": value})
}

// ---------------------------------------------------------------- Socket Mode

fn rand01() -> f64 {
    let b = seagent_net::crypto::random_bytes(4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 / u32::MAX as f64
}

enum Outcome {
    Stopped,
    Fatal(ChannelError),
    Reconnect { healthy: bool },
}

fn socket_loop(inner: &Inner, tx: &mpsc::Sender<Value>, stop: &Cancel) {
    let mut attempts: u32 = 0;
    // Identity first, so a bad bot token stops here.
    if let Err(e) = inner.me() {
        if e.kind == K::Auth {
            *inner.fatal.lock().unwrap() = Some(e);
            return;
        }
    }
    while !stop.is_cancelled() {
        let app = inner.cfg.app_token.clone().unwrap_or_default();
        let outcome = match inner.call("apps.connections.open", Payload::None, Some(&app)) {
            Ok(v) => match v["url"].as_str() {
                Some(u) => run_socket(inner, tx, stop, u),
                None => Outcome::Reconnect { healthy: false },
            },
            Err(e) if e.kind == K::Auth || e.kind == K::NotFound => Outcome::Fatal(ChannelError::new(K::Auth, format!("{} (check app_token / Socket Mode)", e.message))),
            Err(_) => Outcome::Reconnect { healthy: false },
        };
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
                let d = (inner.cfg.reconnect_base * 2u32.pow(attempts.min(5) - 1)).min(inner.cfg.reconnect_max);
                if !sleep_cancellable(d.mul_f64(1.0 + 0.2 * rand01()), stop) {
                    return;
                }
            }
        }
    }
}

fn run_socket(inner: &Inner, tx: &mpsc::Sender<Value>, stop: &Cancel, url: &str) -> Outcome {
    let Ok((mut ws, _)) = WebSocket::connect(url, &[], Duration::from_secs(15)) else { return Outcome::Reconnect { healthy: false } };
    if ws.set_read_timeout(Some(Duration::from_millis(100))).is_err() {
        return Outcome::Reconnect { healthy: false };
    }
    let mut healthy = false;
    let mut next_ping = Instant::now() + inner.cfg.ping_every;
    let mut pong_due: Option<Instant> = None;
    loop {
        if stop.is_cancelled() {
            let _ = ws.send(&Message::Close(Some((1000, String::new()))));
            return Outcome::Stopped;
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
        let Ok(env) = serde_json::from_str::<Value>(&text) else { continue };
        // Acknowledge before doing anything else: Slack redelivers after 3 s.
        // `block_suggestion` is answered in the acknowledgement itself.
        let suggestion = env["type"] == "interactive" && env["payload"]["type"] == "block_suggestion";
        if let Some(id) = env["envelope_id"].as_str() {
            let mut ack = json!({"envelope_id": id});
            if suggestion {
                ack["payload"] = inner.suggest(&env["payload"]);
            }
            if ws.send_text(&ack.to_string()).is_err() {
                return Outcome::Reconnect { healthy };
            }
        }
        match env["type"].as_str() {
            Some("hello") => healthy = true,
            Some("disconnect") => {
                if env["reason"] == "link_disabled" {
                    return Outcome::Fatal(ChannelError::new(K::Fatal, "slack socket mode was disabled for this app"));
                }
                return Outcome::Reconnect { healthy: true };
            }
            Some("events_api" | "interactive" | "slash_commands") if !suggestion => {
                let _ = tx.send(json!({"type": env["type"], "payload": env["payload"]}));
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- HTTP Events API

/// Check `X-Slack-Signature` over `v0:<ts>:<body>` and the timestamp window.
fn verify_signature(secret: &str, ts: Option<&str>, sig: Option<&str>, body: &[u8], now: i64) -> bool {
    let (Some(ts), Some(sig)) = (ts, sig) else { return false };
    let Ok(t) = ts.trim().parse::<i64>() else { return false };
    if (now - t).abs() > MAX_SKEW_SECS {
        return false;
    }
    let mut base = format!("v0:{ts}:").into_bytes();
    base.extend_from_slice(body);
    let want = format!("v0={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), &base)));
    seagent_net::crypto::ct_eq(sig.trim().as_bytes(), want.as_bytes())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn events_handler(secret: String, path: String, tx: mpsc::Sender<Value>, inner: Arc<Inner>) -> seagent_net::httpd::Handler {
    use seagent_net::httpd::Response;
    let tx = Mutex::new(tx);
    Arc::new(move |r: seagent_net::httpd::Request| {
        if r.method != "POST" || r.path != path {
            return Response::text(404, "not found");
        }
        if !verify_signature(&secret, r.header("x-slack-request-timestamp"), r.header("x-slack-signature"), &r.body, unix_now()) {
            return Response::text(401, "bad signature");
        }
        let form = r.header("content-type").is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
        let push = |v: Value| {
            let _ = tx.lock().unwrap().send(v);
        };
        if form {
            let fields: HashMap<String, String> = seagent_net::parse_query(r.body_str()).into_iter().collect();
            if let Some(p) = fields.get("payload") {
                // Interactivity (block_actions…).
                return match serde_json::from_str::<Value>(p) {
                    Ok(v) if v["type"] == "block_suggestion" => Response::new(200, "application/json", inner.suggest(&v).to_string().into_bytes()),
                    Ok(v) => {
                        push(json!({"type": "interactive", "payload": v}));
                        Response::empty(200)
                    }
                    Err(_) => Response::text(400, "bad payload"),
                };
            }
            if fields.contains_key("command") {
                push(json!({"type": "slash_commands", "payload": fields}));
                return Response::empty(200);
            }
            return Response::text(400, "unknown form");
        }
        let Ok(v) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
        match v["type"].as_str() {
            Some("url_verification") => Response::new(200, "text/plain", v["challenge"].as_str().unwrap_or("").as_bytes().to_vec()),
            Some("event_callback") => {
                push(json!({"type": "events_api", "payload": v}));
                Response::empty(200)
            }
            _ => Response::empty(200),
        }
    })
}

// ---------------------------------------------------------------- inbound

fn ts_secs(ts: &str) -> i64 {
    ts.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn chat_type_of(channel: &str, channel_type: Option<&str>) -> ChatType {
    match channel_type {
        Some("im") => ChatType::Direct,
        Some(_) => ChatType::Group,
        None if channel.starts_with('D') => ChatType::Direct,
        None => ChatType::Group,
    }
}

fn media_of(files: &Value) -> Vec<Media> {
    files
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["mode"] != "tombstone")
        .map(|f| {
            let mime = f["mimetype"].as_str().unwrap_or("").to_string();
            let kind = match mime.as_str() {
                _ if f["subtype"] == "slack_audio" => MediaKind::Voice,
                "image/gif" => MediaKind::Animation,
                m if m.starts_with("image/") => MediaKind::Image,
                m if m.starts_with("video/") => MediaKind::Video,
                m if m.starts_with("audio/") => MediaKind::Audio,
                _ => MediaKind::Document,
            };
            Media {
                kind,
                url: f["url_private_download"].as_str().or_else(|| f["url_private"].as_str()).map(str::to_string),
                id: f["id"].as_str().map(str::to_string),
                name: f["name"].as_str().unwrap_or("").to_string(),
                size: f["size"].as_u64().unwrap_or(0),
                mime,
                ..Default::default()
            }
        })
        .collect()
}

/// Subtypes that are a person speaking; joins, topic changes, deletions… are not.
fn conversational(subtype: Option<&str>) -> bool {
    matches!(subtype, None | Some("" | "file_share" | "thread_broadcast" | "me_message" | "bot_message"))
}

fn inbound_of(id: &str, payload: &Value, me: &Me) -> Option<Inbound> {
    let ev = &payload["event"];
    let ty = ev["type"].as_str()?;
    if ty != "message" && ty != "app_mention" {
        return None;
    }
    let channel = ev["channel"].as_str()?.to_string();
    let (m, edited) = if ev["subtype"] == "message_changed" {
        let m = &ev["message"];
        // Link unfurls and bot edits re-send the same text: not a new utterance.
        if m["text"] == ev["previous_message"]["text"] && m["files"] == ev["previous_message"]["files"] {
            return None;
        }
        (m, true)
    } else {
        (ev, false)
    };
    if !conversational(m["subtype"].as_str()) {
        return None;
    }
    let user = m["user"].as_str().unwrap_or("");
    let bot_id = m["bot_id"].as_str().unwrap_or("");
    if (!me.user_id.is_empty() && user == me.user_id) || (!me.bot_id.is_empty() && bot_id == me.bot_id) {
        return None;
    }
    let ts = m["ts"].as_str()?.to_string();
    let media = media_of(&m["files"]);
    let mut text = m["text"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let tag = format!("<@{}>", me.user_id);
    let mentioned = ty == "app_mention" || (!me.user_id.is_empty() && text.contains(&tag));
    if !me.user_id.is_empty() && !me.name.is_empty() {
        text = text.replace(&tag, &format!("@{}", me.name));
    }
    let thread = m["thread_ts"].as_str().filter(|t| *t != ts).map(str::to_string);
    let mut chat_type = chat_type_of(&channel, ev["channel_type"].as_str());
    if thread.is_some() && chat_type != ChatType::Direct {
        chat_type = ChatType::Thread;
    }
    // In a thread the bot started (or replied in), the parent author tells us it is "ours".
    let reply = thread.as_ref().map(|t| ReplyRef { id: t.clone(), is_own: !me.user_id.is_empty() && m["parent_user_id"].as_str() == Some(me.user_id.as_str()), ..Default::default() });
    let profile = &m["user_profile"];
    Some(Inbound {
        channel: id.to_string(),
        chat: channel,
        chat_type,
        thread,
        sender: if user.is_empty() { bot_id.to_string() } else { user.to_string() },
        sender_name: profile["display_name"].as_str().filter(|s| !s.is_empty()).or_else(|| profile["real_name"].as_str()).or_else(|| m["username"].as_str()).unwrap_or("").to_string(),
        is_bot: !bot_id.is_empty() || m["subtype"] == "bot_message",
        text,
        message_id: if edited { format!("{ts}:e{}", m["edited"]["ts"].as_str().unwrap_or("")) } else { ts.clone() },
        ts: ts_secs(&ts),
        account: payload["team_id"].as_str().unwrap_or("").to_string(),
        media,
        mentioned,
        reply,
        edited,
        ..Default::default()
    })
}

/// A block action → callback data: buttons and option menus give the chosen value (the
/// button data it stands for), pickers `<action_id>=<ids>`; anything else is not reported.
fn action_data(a: &Value) -> Option<String> {
    let ty = a["type"].as_str()?;
    let values = |k: &str| a[k].as_array().into_iter().flatten().filter_map(|o| o["value"].as_str().or_else(|| o.as_str())).collect::<Vec<_>>();
    match ty {
        "button" => Some(a["value"].as_str().unwrap_or("").to_string()),
        "static_select" | "external_select" | "overflow" | "radio_buttons" => a["selected_option"]["value"].as_str().map(str::to_string),
        "multi_static_select" | "multi_external_select" | "checkboxes" => Some(values("selected_options").join(",")).filter(|s| !s.is_empty()),
        t if PICKERS.contains(&t) => {
            let mut ids: Vec<&str> = ["selected_user", "selected_channel", "selected_conversation"].iter().filter_map(|k| a[*k].as_str()).collect();
            for k in ["selected_users", "selected_channels", "selected_conversations"] {
                ids.extend(values(k));
            }
            Some(format!("{}={}", a["action_id"].as_str().unwrap_or(t), ids.join(",")))
        }
        _ => None,
    }
}

/// A view state value as text (selected labels, ids, dates, typed text).
fn input_value(a: &Value) -> String {
    let mut parts: Vec<String> = vec![];
    let label = |o: &Value| o["text"]["text"].as_str().or_else(|| o["value"].as_str()).unwrap_or("").to_string();
    if a["selected_option"].is_object() {
        parts.push(label(&a["selected_option"]));
    }
    parts.extend(a["selected_options"].as_array().into_iter().flatten().map(label));
    for k in ["selected_user", "selected_channel", "selected_conversation", "selected_date", "selected_time"] {
        parts.extend(a[k].as_str().map(str::to_string));
    }
    for k in ["selected_users", "selected_channels", "selected_conversations"] {
        parts.extend(a[k].as_array().into_iter().flatten().filter_map(|v| v.as_str()).map(str::to_string));
    }
    if let Some(t) = a["selected_date_time"].as_i64() {
        parts.push(t.to_string());
    }
    if let Some(v) = a["value"].as_str() {
        parts.push(v.to_string());
    }
    if a["rich_text_value"].is_object() {
        let mut out = vec![];
        fn walk(v: &Value, out: &mut Vec<String>) {
            if let Some(t) = v["text"].as_str() {
                out.push(t.to_string());
            }
            for c in v["elements"].as_array().into_iter().flatten() {
                walk(c, out);
            }
        }
        walk(&a["rich_text_value"], &mut out);
        parts.push(out.join(" ").split_whitespace().collect::<Vec<_>>().join(" "));
    }
    parts.join(", ")
}

/// `view_submission` / `view_closed` of a view we opened (`callback_id = seagent:<name>`) → a message
/// to the chat recorded in `private_metadata`, listing the inputs by their labels.
fn view_of(id: &str, p: &Value) -> Option<Inbound> {
    let view = &p["view"];
    let name = view["callback_id"].as_str()?.strip_prefix("seagent:")?;
    let meta: Value = serde_json::from_str(view["private_metadata"].as_str().unwrap_or("")).unwrap_or_default();
    let user = p["user"]["id"].as_str().unwrap_or("").to_string();
    let chat = meta["c"].as_str().filter(|c| !c.is_empty()).unwrap_or(&user).to_string();
    let thread = meta["t"].as_str().filter(|t| !t.is_empty()).map(str::to_string);
    let submitted = p["type"] == "view_submission";
    let mut text = format!("[Slack modal {name} {}]", if submitted { "submitted" } else if p["is_cleared"] == true { "cleared" } else { "closed" });
    if submitted {
        let blocks = view["blocks"].as_array().cloned().unwrap_or_default();
        for (block_id, actions) in view["state"]["values"].as_object().into_iter().flatten() {
            let label = blocks.iter().find(|b| b["block_id"] == block_id.as_str()).and_then(|b| b["label"]["text"].as_str());
            for (action_id, a) in actions.as_object().into_iter().flatten() {
                text.push_str(&format!("\n- {}: {}", label.unwrap_or(action_id), input_value(a)));
            }
        }
    }
    let mut chat_type = if chat == user || chat.starts_with('D') { ChatType::Direct } else { ChatType::Group };
    if thread.is_some() && chat_type != ChatType::Direct {
        chat_type = ChatType::Thread;
    }
    Some(Inbound {
        channel: id.to_string(),
        chat,
        chat_type,
        thread,
        sender: user,
        sender_name: p["user"]["username"].as_str().or_else(|| p["user"]["name"].as_str()).unwrap_or("").to_string(),
        text,
        message_id: format!("view:{}:{}", view["id"].as_str().unwrap_or(""), p["type"].as_str().unwrap_or("")),
        ts: unix_now(),
        account: p["team"]["id"].as_str().unwrap_or("").to_string(),
        mentioned: true,
        ..Default::default()
    })
}

fn command_of(id: &str, p: &Value) -> Option<Inbound> {
    let cmd = p["command"].as_str()?;
    let text = p["text"].as_str().unwrap_or("").trim();
    let channel = p["channel_id"].as_str().unwrap_or("").to_string();
    Some(Inbound {
        channel: id.to_string(),
        chat_type: if p["channel_name"] == "directmessage" { ChatType::Direct } else { chat_type_of(&channel, None) },
        chat: channel,
        sender: p["user_id"].as_str().unwrap_or("").to_string(),
        sender_name: p["user_name"].as_str().unwrap_or("").to_string(),
        text: if text.is_empty() { cmd.to_string() } else { format!("{cmd} {text}") },
        message_id: format!("sc:{}", p["trigger_id"].as_str().unwrap_or("")),
        ts: unix_now(),
        account: p["team_id"].as_str().unwrap_or("").to_string(),
        mentioned: true,
        ..Default::default()
    })
}

// ---------------------------------------------------------------- outbound

/// Slack reactions take names, not characters.
fn emoji_name(e: &str) -> String {
    let e = e.trim();
    let named = [
        ("👍", "+1"), ("👎", "-1"), ("👀", "eyes"), ("✅", "white_check_mark"), ("❌", "x"), ("🎉", "tada"), ("❤️", "heart"), ("❤", "heart"), ("😂", "joy"), ("🙏", "pray"), ("🔥", "fire"),
        ("🤔", "thinking_face"), ("⏳", "hourglass_flowing_sand"), ("⌛", "hourglass"), ("😀", "grinning"), ("😄", "smile"), ("🚀", "rocket"), ("⚠️", "warning"), ("⚠", "warning"), ("💯", "100"),
        ("👋", "wave"), ("😢", "cry"), ("🤖", "robot_face"), ("✨", "sparkles"), ("🙂", "slightly_smiling_face"), ("😅", "sweat_smile"), ("👌", "ok_hand"), ("🛑", "octagonal_sign"), ("✍️", "writing_hand"),
        ("🧠", "brain"), ("📝", "memo"), ("👏", "clap"), ("😮", "open_mouth"), ("🆗", "ok"),
    ];
    named.iter().find(|(c, _)| *c == e).map(|(_, n)| n.to_string()).unwrap_or_else(|| e.trim_matches(':').to_string())
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn button(i: usize, j: usize, b: &Button) -> Value {
    let mut e = json!({"type": "button", "action_id": format!("seagent_{i}_{j}"), "text": {"type": "plain_text", "text": truncate_chars(&b.label, 75), "emoji": true}});
    match &b.url {
        Some(u) => e["url"] = json!(u),
        None => e["value"] = json!(truncate_chars(&b.data, 2000)),
    }
    e
}

/// Button rows → Block Kit: ≤ 5 → buttons; longer rows of plain buttons → a select menu
/// (`external_select` with stored options past 100); `slack:<picker>[:tag]` → that picker.
fn control_blocks(inner: &Inner, rows: &[Vec<Button>]) -> Vec<Value> {
    rows.iter()
        .enumerate()
        .filter(|(_, r)| !r.is_empty())
        .map(|(i, r)| {
            let block_id = format!("seagent_row_{i}");
            if let [b] = r.as_slice() {
                let kind = b.data.strip_prefix("slack:").map(|k| k.split(':').next().unwrap_or(""));
                if let Some(k) = kind.filter(|k| b.url.is_none() && PICKERS.contains(k)) {
                    let el = json!({"type": k, "action_id": truncate_chars(&b.data, 255), "placeholder": {"type": "plain_text", "text": truncate_chars(&b.label, 150)}});
                    return json!({"type": "actions", "block_id": block_id, "elements": [el]});
                }
            }
            let selectable = r.len() > BUTTON_ROW && r.iter().all(|b| b.url.is_none() && !b.data.is_empty() && b.data.chars().count() <= OPTION_VALUE_MAX);
            if !selectable {
                return json!({"type": "actions", "block_id": block_id, "elements": r.iter().take(25).enumerate().map(|(j, b)| button(i, j, b)).collect::<Vec<_>>()});
            }
            let placeholder = json!({"type": "plain_text", "text": "Choose…"});
            if r.len() <= SELECT_MAX {
                let options: Vec<Value> = r.iter().map(|b| option(&b.label, &b.data)).collect();
                json!({"type": "actions", "block_id": block_id, "elements": [{"type": "static_select", "action_id": format!("seagent_sel_{i}"), "placeholder": placeholder, "options": options}]})
            } else {
                let token = inner.store_menu(r.iter().map(|b| (b.label.clone(), b.data.clone())).collect());
                json!({"type": "actions", "block_id": format!("{MENU_PREFIX}{token}"), "elements": [{"type": "external_select", "action_id": format!("seagent_sel_{i}"), "placeholder": {"type": "plain_text", "text": "Search…"}, "min_query_length": 0}]})
            }
        })
        .collect()
}

impl Slack {
    pub fn new(cfg: Config) -> Result<Slack, String> {
        if cfg.bot_token.is_empty() {
            return Err(format!("channel {}: slack bot_token is empty", cfg.id));
        }
        let mut cfg = cfg;
        cfg.api_base = cfg.api_base.trim_end_matches('/').to_string();
        let (tx, rx) = mpsc::channel();
        let http = Http::new(Duration::from_secs(60)).bearer(&cfg.bot_token);
        Ok(Slack {
            inner: Arc::new(Inner { cfg, http, me: Mutex::new(None), responses: Mutex::new(HashMap::new()), menus: Mutex::new(HashMap::new()), users: Mutex::new(HashMap::new()), threads: Mutex::new((HashSet::new(), VecDeque::new())), fatal: Mutex::new(None) }),
            rx: Mutex::new(rx),
            tx: Mutex::new(Some(tx)),
            stop: Cancel::new(),
            _server: None,
        })
    }

    /// HTTP Events API mode: listen on `listen`, accept signed posts on `path`.
    pub fn with_events_api(mut self, listen: &str, path: &str, signing_secret: &str) -> Result<Slack, String> {
        if signing_secret.trim().is_empty() {
            return Err(format!("channel {}: slack signing_secret is empty", self.inner.cfg.id));
        }
        let tx = self.tx.lock().unwrap().take().ok_or("events mode already set")?;
        let server = seagent_net::httpd::Server::bind(listen, seagent_net::httpd::Opts::default(), events_handler(signing_secret.trim().to_string(), path.to_string(), tx, self.inner.clone())).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.inner.cfg.id))?;
        self._server = Some(server);
        Ok(self)
    }

    fn ensure_started(&self) {
        let Some(tx) = self.tx.lock().unwrap().take() else { return };
        if self.inner.cfg.app_token.is_none() {
            // Neither mode configured (send-only): nothing will arrive.
            *self.tx.lock().unwrap() = Some(tx);
            return;
        }
        let (inner, stop) = (self.inner.clone(), self.stop.clone());
        let _ = std::thread::Builder::new().name(format!("slack {}", inner.cfg.id)).spawn(move || socket_loop(&inner, &tx, &stop));
    }

    fn render(&self, format: TextFormat, text: &str) -> String {
        match format {
            TextFormat::Markdown => markup::convert(text, Markup::SlackMrkdwn),
            // Slack still parses &, <, > in plain text.
            TextFormat::Plain => text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"),
        }
    }

    /// Files upload v2: reserve an upload URL, POST the bytes, then share into the channel.
    fn upload(&self, chat: &str, thread: Option<&str>, m: &Media, comment: Option<&str>) -> Result<String, ChannelError> {
        let path = m.path.as_deref().unwrap_or_default();
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let name = if m.name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
        let len = data.len().to_string();
        let v = self.inner.call("files.getUploadURLExternal", Payload::Form(&[("filename", &name), ("length", &len)]), None)?;
        let (Some(url), Some(fid)) = (v["upload_url"].as_str(), v["file_id"].as_str()) else { return Err(ChannelError::new(K::Protocol, "files.getUploadURLExternal: no upload_url")) };
        let ctype = if m.mime.is_empty() { "application/octet-stream" } else { m.mime.as_str() };
        let r = self.inner.http.call("POST", url, &[], Payload::Raw(ctype, &data))?;
        if !(200..300).contains(&r.status) {
            return Err(crate::http::classify(r.status, r.retry_after, "slack file upload", &r.body));
        }
        let files = json!([{"id": fid, "title": m.caption.clone().unwrap_or_else(|| name.clone())}]).to_string();
        let mut form: Vec<(&str, &str)> = vec![("files", &files), ("channel_id", chat)];
        if let Some(t) = thread {
            form.push(("thread_ts", t));
        }
        if let Some(c) = comment {
            form.push(("initial_comment", c));
        }
        self.inner.call("files.completeUploadExternal", Payload::Form(&form), None)?;
        Ok(fid.to_string())
    }

    /// A configured modal, completed: `callback_id = seagent:<name>`, origin in `private_metadata`.
    pub fn modal_view(&self, name: &str, meta: &Value) -> Option<Value> {
        let mut v = self.inner.cfg.modals.get(name)?.clone();
        v["type"] = json!("modal");
        v["callback_id"] = json!(truncate_chars(&format!("seagent:{name}"), 255));
        v["private_metadata"] = json!(meta.to_string());
        if v.get("title").is_none() {
            v["title"] = json!({"type": "plain_text", "text": truncate_chars(name, 24)});
        }
        if v.get("submit").is_none() && v["blocks"].as_array().is_some_and(|b| b.iter().any(|b| b["type"] == "input")) {
            v["submit"] = json!({"type": "plain_text", "text": "Submit"});
        }
        if v.get("notify_on_close").is_none() {
            v["notify_on_close"] = json!(true);
        }
        Some(v)
    }

    /// `views.open` (trigger ids live 3 s); returns the view id.
    pub fn open_view(&self, trigger_id: &str, view: &Value) -> Result<String, ChannelError> {
        let v = self.inner.api("views.open", &json!({"trigger_id": trigger_id, "view": view}))?;
        Ok(v["view"]["id"].as_str().unwrap_or("").to_string())
    }

    /// `views.push`: stack a view on the open modal.
    pub fn push_view(&self, trigger_id: &str, view: &Value) -> Result<String, ChannelError> {
        let v = self.inner.api("views.push", &json!({"trigger_id": trigger_id, "view": view}))?;
        Ok(v["view"]["id"].as_str().unwrap_or("").to_string())
    }

    /// `views.update`; `hash` guards against racing a newer version.
    pub fn update_view(&self, view_id: &str, hash: Option<&str>, view: &Value) -> Result<(), ChannelError> {
        let mut body = json!({"view_id": view_id, "view": view});
        if let Some(h) = hash {
            body["hash"] = json!(h);
        }
        self.inner.api("views.update", &body).map(|_| ())
    }

    /// `chat.postEphemeral`: only `user` sees it; returns its message_ts.
    pub fn post_ephemeral(&self, chat: &str, user: &str, text: &str, thread: Option<&str>) -> Result<String, ChannelError> {
        let mut body = json!({"channel": chat, "user": user, "text": markup::convert(&truncate_chars(text, MAX_MESSAGE), Markup::SlackMrkdwn)});
        if let Some(t) = thread.filter(|t| !t.is_empty()) {
            body["thread_ts"] = json!(t);
        }
        let v = self.inner.api("chat.postEphemeral", &body)?;
        Ok(v["message_ts"].as_str().unwrap_or("").to_string())
    }

    /// `assistant.threads.setSuggestedPrompts` with the configured prompts.
    pub fn suggest_prompts(&self, chat: &str, thread: &str) -> Result<(), ChannelError> {
        self.inner.set_suggested_prompts(chat, thread)
    }

    /// A display name, via cached `users.info`.
    pub fn user_name(&self, user: &str) -> String {
        self.inner.user_name(user)
    }

    /// Earlier messages of a thread before `latest` ("name: text" lines, oldest first).
    pub fn thread_history(&self, chat: &str, thread_ts: &str, latest: &str, limit: usize) -> Result<Vec<String>, ChannelError> {
        let me = self.inner.me()?;
        Ok(self.inner.thread_history(chat, thread_ts, latest, limit, &me))
    }

    /// An Events API event → Inbound (thread history, users.info names, assistant threads).
    fn event(&self, payload: &Value, me: &Me) -> Option<Inbound> {
        let ev = &payload["event"];
        if ev["type"] == "assistant_thread_started" {
            let t = &ev["assistant_thread"];
            if let (Some(c), Some(ts)) = (t["channel_id"].as_str(), t["thread_ts"].as_str()) {
                if let Err(e) = self.inner.set_suggested_prompts(c, ts) {
                    eprintln!("seagent: {}: suggested prompts: {e}", self.inner.cfg.id);
                }
            }
            return None;
        }
        let mut m = inbound_of(&self.inner.cfg.id, payload, me)?;
        if m.sender_name.is_empty() && !m.is_bot {
            m.sender_name = self.inner.user_name(&m.sender);
        }
        let limit = self.inner.cfg.thread_history;
        if let Some(t) = m.thread.clone() {
            if limit > 0 && !m.edited && m.addressed() && !m.text.trim_start().starts_with('/') && self.inner.first_in_thread(format!("{}\u{1f}{t}", m.chat)) {
                let lines = self.inner.thread_history(&m.chat, &t, &m.message_id, limit, me);
                if !lines.is_empty() {
                    m.text = format!("[Slack thread history]\n{}\n[/Slack thread history]\n\n{}", lines.join("\n"), m.text);
                }
            }
        }
        Some(m)
    }

    fn remember_answer(&self, key: &str, a: Answer) {
        let mut r = self.inner.responses.lock().unwrap();
        if r.len() > 1024 {
            r.clear();
        }
        r.insert(key.to_string(), a);
    }

    /// Interactivity payloads: block actions (buttons, menus, pickers, modal openers) and
    /// our views' submissions.
    fn interactive(&self, p: &Value) -> Vec<Inbound> {
        let id = &self.inner.cfg.id;
        match p["type"].as_str() {
            Some("view_submission" | "view_closed") => return view_of(id, p).into_iter().collect(),
            Some("block_actions") => {}
            _ => return vec![],
        }
        let actions: Vec<&Value> = p["actions"].as_array().into_iter().flatten().collect();
        let trigger = p["trigger_id"].as_str().unwrap_or("");
        let modal = |a: &Value| a["type"] == "button" && a["value"].as_str().and_then(|v| v.strip_prefix("modal:")).is_some_and(|n| self.inner.cfg.modals.contains_key(n));
        if p["container"]["type"] == "view" {
            // Inside a modal the state arrives on submit; only openers stack another view.
            for a in actions.iter().filter(|a| modal(a)) {
                let name = a["value"].as_str().unwrap_or("").trim_start_matches("modal:");
                let meta: Value = serde_json::from_str(p["view"]["private_metadata"].as_str().unwrap_or("")).unwrap_or_default();
                if let Some(v) = self.modal_view(name, &meta) {
                    if let Err(e) = self.push_view(trigger, &v) {
                        eprintln!("seagent: {id}: views.push {name}: {e}");
                    }
                }
            }
            return vec![];
        }
        let channel = p["channel"]["id"].as_str().or_else(|| p["container"]["channel_id"].as_str()).unwrap_or("").to_string();
        let msg_ts = p["container"]["message_ts"].as_str().or_else(|| p["message"]["ts"].as_str()).unwrap_or("").to_string();
        let thread = p["message"]["thread_ts"].as_str().or_else(|| p["container"]["thread_ts"].as_str()).filter(|t| *t != msg_ts).map(str::to_string);
        let mut chat_type = chat_type_of(&channel, None);
        if thread.is_some() && chat_type != ChatType::Direct {
            chat_type = ChatType::Thread;
        }
        let user = p["user"]["id"].as_str().unwrap_or("").to_string();
        let mut out = vec![];
        for a in actions {
            if modal(a) {
                let name = a["value"].as_str().unwrap_or("").trim_start_matches("modal:");
                let meta = json!({"c": channel, "t": thread.clone().unwrap_or_default()});
                if let Some(v) = self.modal_view(name, &meta) {
                    if let Err(e) = self.open_view(trigger, &v) {
                        eprintln!("seagent: {id}: views.open {name}: {e}");
                    }
                }
                continue;
            }
            let Some(data) = action_data(a) else { continue };
            let ats = a["action_ts"].as_str().unwrap_or("").to_string();
            self.remember_answer(&ats, Answer { url: p["response_url"].as_str().map(str::to_string), user: user.clone(), channel: channel.clone(), thread: thread.clone() });
            out.push(Inbound {
                channel: id.to_string(),
                chat: channel.clone(),
                chat_type,
                thread: thread.clone(),
                sender: user.clone(),
                sender_name: p["user"]["username"].as_str().or_else(|| p["user"]["name"].as_str()).unwrap_or("").to_string(),
                message_id: format!("cb:{ats}"),
                ts: ts_secs(&ats),
                account: p["team"]["id"].as_str().unwrap_or("").to_string(),
                callback: Some(Callback { id: ats, data }),
                reply: (!msg_ts.is_empty()).then(|| ReplyRef { id: msg_ts.clone(), is_own: true, ..Default::default() }),
                mentioned: true,
                ..Default::default()
            });
        }
        out
    }

    /// Native streaming (`chat.startStream`): returns the stream message ts.
    /// Slack requires a thread and, outside DMs, the recipient user/team.
    pub fn stream_start(&self, chat: &str, thread_ts: &str, text: &str, recipient_user: Option<&str>, recipient_team: Option<&str>) -> Result<String, ChannelError> {
        let mut body = json!({"channel": chat, "thread_ts": thread_ts});
        if !text.is_empty() {
            body["markdown_text"] = json!(text);
        }
        if let Some(u) = recipient_user {
            body["recipient_user_id"] = json!(u);
        }
        if let Some(t) = recipient_team {
            body["recipient_team_id"] = json!(t);
        }
        let v = self.inner.api("chat.startStream", &body)?;
        v["ts"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "chat.startStream: no ts"))
    }

    pub fn stream_append(&self, chat: &str, ts: &str, text: &str) -> Result<(), ChannelError> {
        self.inner.api("chat.appendStream", &json!({"channel": chat, "ts": ts, "markdown_text": text})).map(|_| ())
    }

    pub fn stream_stop(&self, chat: &str, ts: &str, text: Option<&str>) -> Result<(), ChannelError> {
        let mut body = json!({"channel": chat, "ts": ts});
        if let Some(t) = text.filter(|t| !t.is_empty()) {
            body["markdown_text"] = json!(t);
        }
        self.inner.api("chat.stopStream", &body).map(|_| ())
    }
}

impl Drop for Slack {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Channel for Slack {
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
            buttons: true,
            polls: false,
            native_commands: true,
            streaming: if self.inner.cfg.native_streaming { Streaming::Native } else { Streaming::Edit },
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::SlackMrkdwn,
        }
    }

    /// Native streaming needs a thread (the triggering message's ts works).
    fn stream_begin(&self, out: &Outbound) -> Result<Option<String>, ChannelError> {
        match out.thread.as_deref().or(out.reply_to.as_deref()) {
            Some(t) if self.inner.cfg.native_streaming => self.stream_start(&out.chat, t, &out.text, None, None).map(Some),
            _ => Ok(None),
        }
    }
    fn stream_update(&self, chat: &str, ts: &str, _text: &str, delta: &str) -> Result<(), ChannelError> {
        if delta.is_empty() { Ok(()) } else { self.stream_append(chat, ts, delta) }
    }
    fn stream_finish(&self, chat: &str, ts: &str, _text: &str, delta: &str) -> Result<(), ChannelError> {
        self.stream_stop(chat, ts, Some(delta))
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started();
        let raw: Vec<Value> = {
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
                    Ok(v) => {
                        let mut got = vec![v];
                        got.extend(rx.try_iter());
                        break got;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.inner.fatal.lock().unwrap().clone().unwrap_or_else(|| ChannelError::new(K::Network, "slack receiver stopped"))),
                }
            }
        };
        let me = self.inner.me()?;
        let id = &self.inner.cfg.id;
        let mut out = Vec::new();
        for v in raw {
            match v["type"].as_str() {
                Some("events_api") => out.extend(self.event(&v["payload"], &me)),
                Some("interactive") => out.extend(self.interactive(&v["payload"])),
                Some("slash_commands") => out.extend(command_of(id, &v["payload"])),
                _ => {}
            }
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let thread = out.thread.as_deref().or(out.reply_to.as_deref()).filter(|t| !t.is_empty());
        let mut sent = Sent::default();
        let mut text = out.text.clone();
        let mut images = Vec::new();
        let uploads: Vec<&Media> = out.media.iter().filter(|m| m.path.is_some()).collect();
        for m in out.media.iter().filter(|m| m.path.is_none()) {
            match &m.url {
                Some(u) if m.kind == MediaKind::Image => images.push(json!({"type": "image", "image_url": u, "alt_text": m.caption.clone().unwrap_or_else(|| if m.name.is_empty() { "image".into() } else { m.name.clone() })})),
                Some(u) => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(u);
                }
                None => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            }
        }
        // One file with a short caption: the text rides along as the file comment.
        let as_comment = uploads.len() == 1 && images.is_empty() && out.buttons.is_empty() && text.chars().count() <= MAX_SECTION && !text.trim().is_empty();
        for (i, m) in uploads.iter().enumerate() {
            let comment = (as_comment && i == 0).then(|| self.render(out.format, &text));
            sent.ids.push(self.upload(&out.chat, thread, m, comment.as_deref())?);
        }
        if as_comment {
            return Ok(sent);
        }
        let limit = if out.buttons.is_empty() { MAX_MESSAGE } else { MAX_SECTION };
        let mut pieces = if text.trim().is_empty() { vec![] } else { crate::chunk::split(&text, limit, LenUnit::Chars) };
        if pieces.is_empty() && (!images.is_empty() || !out.buttons.is_empty()) {
            pieces.push(String::new());
        }
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let rendered = self.render(out.format, &piece);
            let mut body = json!({"channel": out.chat, "text": if rendered.is_empty() { " ".to_string() } else { rendered.clone() }, "mrkdwn": out.format == TextFormat::Markdown, "unfurl_links": false});
            if let Some(t) = thread {
                body["thread_ts"] = json!(t);
            }
            let mut blocks = Vec::new();
            if i == 0 && !images.is_empty() {
                if !rendered.is_empty() {
                    blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": rendered}}));
                }
                blocks.append(&mut images);
            }
            if i + 1 == n && !out.buttons.is_empty() {
                if blocks.is_empty() && !rendered.is_empty() {
                    blocks.push(json!({"type": "section", "text": {"type": if out.format == TextFormat::Markdown { "mrkdwn" } else { "plain_text" }, "text": if out.format == TextFormat::Markdown { rendered.clone() } else { piece.clone() }}}));
                }
                blocks.extend(control_blocks(&self.inner, &out.buttons));
            }
            if !blocks.is_empty() {
                body["blocks"] = Value::Array(blocks);
            }
            let v = self.inner.api("chat.postMessage", &body)?;
            sent.ids.push(v["ts"].as_str().unwrap_or("").to_string());
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let body = json!({"channel": chat, "ts": message_id, "text": markup::convert(&truncate_chars(text, MAX_MESSAGE), Markup::SlackMrkdwn)});
        self.inner.api("chat.update", &body).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        // Upload ids (F…) are files; message ids are timestamps.
        if message_id.starts_with('F') {
            return self.inner.api("files.delete", &json!({"file": message_id})).map(|_| ());
        }
        self.inner.api("chat.delete", &json!({"channel": chat, "ts": message_id})).map(|_| ())
    }

    /// Slack has no bot typing indicator outside assistant threads.
    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let Some(t) = thread.filter(|t| !t.is_empty()) else { return Err(crate::unsupported("typing outside a thread")) };
        self.inner.api("assistant.threads.setStatus", &json!({"channel_id": chat, "thread_ts": t, "status": self.inner.cfg.typing_status})).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let method = if remove { "reactions.remove" } else { "reactions.add" };
        match self.inner.api(method, &json!({"channel": chat, "timestamp": message_id, "name": emoji_name(emoji)})) {
            Ok(_) => Ok(()),
            Err(e) if e.message.ends_with("already_reacted") || e.message.ends_with("no_reaction") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The envelope / HTTP 200 already acknowledged the press; text answers ephemerally
    /// through the response_url, else `chat.postEphemeral` (as upstream falls back).
    fn ack_callback(&self, cb: &Callback, text: Option<&str>) -> Result<(), ChannelError> {
        let Some(t) = text else { return Ok(()) };
        let Some(a) = self.inner.responses.lock().unwrap().remove(&cb.id) else { return Ok(()) };
        let via_url = a.url.as_deref().map(|url| {
            let body = json!({"text": t, "response_type": "ephemeral", "replace_original": false});
            let r = Http { agent: self.inner.http.agent.clone(), headers: vec![] }.call("POST", url, &[], Payload::Json(&body))?;
            if !(200..300).contains(&r.status) {
                return Err(crate::http::classify(r.status, r.retry_after, "slack response_url", &r.body));
            }
            Ok(())
        });
        match via_url {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) | None if !a.user.is_empty() && !a.channel.is_empty() => self.post_ephemeral(&a.channel, &a.user, t, a.thread.as_deref()).map(|_| ()),
            Some(Err(e)) => Err(e),
            None => Ok(()),
        }
    }

    /// `url_private` needs the bot token.
    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "slack file without url"))?;
        let auth = format!("Bearer {}", self.inner.cfg.bot_token);
        let data = crate::http::get_bytes(u, &[("authorization", &auth)], 100 * 1024 * 1024)?;
        // A missing files:read scope yields Slack's HTML login page instead of the file.
        if data.starts_with(b"<!DOCTYPE html") || data.starts_with(b"<html") {
            return Err(ChannelError::new(K::Auth, "slack returned a login page for the file (missing files:read scope?)"));
        }
        Ok(data)
    }

    fn message_action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
        self.action(action, args)
    }

    fn message_actions(&self) -> Vec<&'static str> {
        actions::ACTIONS.to_vec()
    }

    fn stop(&self) {
        self.stop.cancel();
    }
}

// ---------------------------------------------------------------- config

fn d_poll() -> u64 {
    25
}

fn d_path() -> String {
    "/slack/events".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    bot_token: String,
    /// Socket Mode (`xapp-…`, connections:write).
    #[serde(default)]
    app_token: Option<String>,
    /// HTTP Events API mode: signing secret, local listen address and request path.
    #[serde(default)]
    signing_secret: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default = "d_path")]
    events_path: String,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default)]
    native_streaming: bool,
    #[serde(default)]
    typing_status: Option<String>,
    /// name → Block Kit view (a table or a JSON string); buttons `modal:<name>` open it.
    #[serde(default)]
    modals: HashMap<String, Value>,
    /// Assistant-thread suggested prompts; `[]` turns them off.
    #[serde(default)]
    suggested_prompts: Option<Vec<Prompt>>,
    #[serde(default)]
    suggested_prompts_title: Option<String>,
    /// Earlier thread messages attached when the bot is first addressed in a thread; 0 = off.
    #[serde(default)]
    thread_history: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Prompt {
    title: String,
    message: String,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let mut cfg = Config::new(ctx.name, &ctx.secret("bot_token", &st.bot_token)?);
    cfg.app_token = ctx.opt_secret("app_token", &st.app_token)?.filter(|t| !t.trim().is_empty());
    if let Some(a) = st.api_base {
        cfg.api_base = a;
    }
    cfg.poll_timeout_secs = st.poll_timeout_secs;
    cfg.native_streaming = st.native_streaming;
    if let Some(t) = st.typing_status {
        cfg.typing_status = t;
    }
    for (name, v) in st.modals {
        let v = match v {
            Value::String(j) => serde_json::from_str(&j).map_err(|e| format!("channel {}: modal {name}: {e}", ctx.name))?,
            v @ Value::Object(_) => v,
            _ => return Err(format!("channel {}: modal {name} must be a table or a JSON string", ctx.name)),
        };
        cfg.modals.insert(name, v);
    }
    if let Some(p) = st.suggested_prompts {
        cfg.suggested_prompts = p.into_iter().map(|p| (p.title, p.message)).collect();
    }
    if let Some(t) = st.suggested_prompts_title {
        cfg.suggested_prompts_title = t;
    }
    if let Some(n) = st.thread_history {
        cfg.thread_history = n;
    }
    let secret = ctx.opt_secret("signing_secret", &st.signing_secret)?;
    let socket = cfg.app_token.is_some();
    let mut slack = Slack::new(cfg)?;
    match (socket, st.listen, secret) {
        (true, None, _) => {}
        (true, Some(_), _) => return Err(format!("channel {}: set either app_token (Socket Mode) or listen + signing_secret (Events API), not both", ctx.name)),
        (false, Some(l), Some(sec)) => slack = slack.with_events_api(&l, &st.events_path, &sec)?,
        (false, Some(_), None) => return Err(format!("channel {}: listen needs signing_secret", ctx.name)),
        (false, None, _) => return Err(format!("channel {}: slack needs app_token (Socket Mode) or listen + signing_secret (Events API)", ctx.name)),
    }
    Ok(Arc::new(slack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use seagent_net::ws::read_head;
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;

    fn socket_server(script: impl Fn(usize, Ws) + Send + Sync + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/link", l.local_addr().unwrap());
        let script = Arc::new(script);
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let script = script.clone();
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let Ok((head, rest)) = read_head(&mut s, 65536) else { return };
                    script(n, WebSocket::accept(s, &head, rest).unwrap());
                });
            }
        });
        url
    }

    fn ok(v: Value) -> (u16, Vec<(String, String)>, String) {
        let mut v = v;
        v["ok"] = json!(true);
        (200, vec![], v.to_string())
    }

    /// Fake Web API: auth.test, apps.connections.open → `ws`, everything else ok with a ts.
    fn api(ws: String) -> FakeServer {
        FakeServer::start(move |req, n| match req.path.as_str() {
            "/auth.test" => ok(json!({"user_id": "UBOT", "bot_id": "BBOT", "user": "seagent", "team_id": "T1"})),
            "/apps.connections.open" => ok(json!({"url": ws})),
            "/files.getUploadURLExternal" => ok(json!({"upload_url": format!("{ws}/upload"), "file_id": "F123"})),
            "/upload" | "/resp" | "/file" => (200, vec![], "FILEBYTES".into()),
            _ => ok(json!({"ts": format!("1700000000.{n:06}"), "channel": "C1"})),
        })
    }

    fn cfg(api: &str) -> Config {
        let mut c = Config::new("sl", "xoxb-SECRET");
        c.api_base = api.into();
        c.app_token = Some("xapp-1".into());
        c.poll_timeout_secs = 1;
        c.retry_base = Duration::from_millis(5);
        c.reconnect_base = Duration::from_millis(5);
        c
    }

    fn collect(s: &Slack, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(8);
        while got.len() < n && Instant::now() < until {
            got.extend(s.poll(&Cancel::new()).unwrap());
        }
        got
    }

    fn envelope(id: usize, event: Value) -> String {
        json!({"envelope_id": format!("E{id}"), "type": "events_api", "accepts_response_payload": false, "payload": {"type": "event_callback", "team_id": "T1", "event": event}}).to_string()
    }

    fn idle(ws: &mut Ws) {
        while let Ok(m) = ws.recv_blocking() {
            if matches!(m, Message::Close(_)) {
                return;
            }
        }
    }

    #[test]
    fn socket_mode_acks_envelopes_and_parses_every_kind() {
        let acks = Arc::new(Mutex::new(Vec::<String>::new()));
        let a2 = acks.clone();
        let resp_url = Arc::new(Mutex::new(String::new()));
        let r2 = resp_url.clone();
        let ws = socket_server(move |n, mut ws| {
            ws.send_text(r#"{"type":"hello","num_connections":1}"#).unwrap();
            let events = if n == 0 {
                let ts = |s: &str| format!("1700000000.000{s}");
                vec![
                    envelope(1, json!({"type": "message", "channel": "D1", "channel_type": "im", "user": "U1", "text": "hi", "ts": ts("100"), "user_profile": {"display_name": "Amy"}})),
                    envelope(2, json!({"type": "app_mention", "channel": "C1", "user": "U1", "text": "<@UBOT> do it", "ts": ts("200")})),
                    envelope(3, json!({"type": "message", "channel": "C1", "channel_type": "channel", "user": "U1", "text": "yes", "ts": ts("300"), "thread_ts": ts("250"), "parent_user_id": "UBOT"})),
                    envelope(4, json!({"type": "message", "subtype": "file_share", "channel": "D1", "channel_type": "im", "user": "U1", "text": "", "ts": ts("400"), "files": [{"id": "F1", "name": "a.png", "mimetype": "image/png", "size": 3, "url_private_download": "https://files.slack.com/a.png"}]})),
                    envelope(5, json!({"type": "message", "channel": "C1", "channel_type": "channel", "user": "UBOT", "text": "my echo", "ts": ts("500")})),
                    envelope(6, json!({"type": "message", "subtype": "bot_message", "channel": "C1", "channel_type": "channel", "bot_id": "BBOT", "text": "my bot echo", "ts": ts("510")})),
                    envelope(7, json!({"type": "message", "subtype": "bot_message", "channel": "C1", "channel_type": "channel", "bot_id": "B2", "username": "otherbot", "text": "beep", "ts": ts("520")})),
                    envelope(8, json!({"type": "message", "subtype": "message_changed", "channel": "C1", "channel_type": "channel", "message": {"user": "U1", "text": "edited <@UBOT>", "ts": ts("200"), "edited": {"user": "U1", "ts": ts("900")}}, "previous_message": {"text": "<@UBOT> do it"}, "ts": ts("901")})),
                    envelope(9, json!({"type": "message", "subtype": "message_changed", "channel": "C1", "message": {"user": "U1", "text": "same", "ts": ts("600"), "attachments": [{}]}, "previous_message": {"text": "same"}})),
                    envelope(10, json!({"type": "message", "subtype": "channel_join", "channel": "C1", "user": "U2", "text": "<@U2> has joined", "ts": ts("700")})),
                    json!({"envelope_id": "E11", "type": "interactive", "payload": {"type": "block_actions", "team": {"id": "T1"}, "user": {"id": "U1", "username": "amy"}, "channel": {"id": "C1"}, "container": {"type": "message", "message_ts": ts("800"), "channel_id": "C1"}, "message": {"ts": ts("800"), "thread_ts": ts("250")}, "response_url": *r2.lock().unwrap(), "actions": [{"type": "button", "action_id": "seagent_0_0", "value": "appr:1:once", "action_ts": "1700000001.111"}]}}).to_string(),
                    json!({"envelope_id": "E12", "type": "slash_commands", "payload": {"command": "/status", "text": " now ", "channel_id": "D1", "channel_name": "directmessage", "user_id": "U1", "user_name": "amy", "trigger_id": "TR1"}}).to_string(),
                    json!({"type": "disconnect", "reason": "refresh_requested"}).to_string(),
                ]
            } else {
                vec![envelope(13, json!({"type": "message", "channel": "D1", "channel_type": "im", "user": "U1", "text": "after refresh", "ts": "1700000002.000100"}))]
            };
            for e in events {
                ws.send_text(&e).unwrap();
            }
            ws.get_ref().set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            while let Ok(Message::Text(t)) = ws.recv_blocking() {
                a2.lock().unwrap().push(serde_json::from_str::<Value>(&t).unwrap()["envelope_id"].as_str().unwrap().to_string());
            }
            idle(&mut ws);
        });
        let srv = api(ws);
        *resp_url.lock().unwrap() = format!("{}/resp", srv.url);
        let s = Slack::new(cfg(&srv.url)).unwrap();
        let g = collect(&s, 9);
        assert_eq!(g.len(), 9, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].message_id.as_str(), g[0].ts, g[0].account.as_str()), ("D1", ChatType::Direct, "U1", "Amy", "1700000000.000100", 1700000000, "T1"));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group && g[1].text == "@seagent do it");
        assert_eq!((g[2].chat_type, g[2].thread.as_deref()), (ChatType::Thread, Some("1700000000.000250")));
        assert!(g[2].reply.as_ref().unwrap().is_own && g[2].addressed(), "reply in the bot's thread");
        assert_eq!((g[3].media[0].kind, g[3].media[0].url.as_deref(), g[3].media[0].id.as_deref()), (MediaKind::Image, Some("https://files.slack.com/a.png"), Some("F1")));
        assert!(g[4].is_bot && g[4].text == "beep" && g[4].sender == "B2", "own user and own bot_id dropped");
        assert!(g[5].edited && g[5].mentioned && g[5].message_id == "1700000000.000200:e1700000000.000900" && g[5].text == "edited @seagent");
        let cb = g[6].callback.as_ref().unwrap();
        assert_eq!((cb.data.as_str(), g[6].chat.as_str(), g[6].thread.as_deref(), g[6].reply.as_ref().unwrap().id.as_str()), ("appr:1:once", "C1", Some("1700000000.000250"), "1700000000.000800"));
        assert_eq!((g[7].text.as_str(), g[7].chat_type, g[7].message_id.as_str()), ("/status now", ChatType::Direct, "sc:TR1"));
        assert_eq!(g[8].text, "after refresh", "reconnected after disconnect");
        std::thread::sleep(Duration::from_millis(400));
        let mut a = acks.lock().unwrap().clone();
        a.sort_by_key(|x| x[1..].parse::<u32>().unwrap());
        assert_eq!(a, (1..=13).map(|i| format!("E{i}")).collect::<Vec<_>>(), "every envelope acknowledged");
        let reqs = srv.requests();
        let opens: Vec<_> = reqs.iter().filter(|r| r.path == "/apps.connections.open").collect();
        assert_eq!(opens.len(), 2);
        assert_eq!(opens[0].header("authorization"), Some("Bearer xapp-1"));
        assert_eq!(reqs[0].header("authorization"), Some("Bearer xoxb-SECRET"));
        // Ephemeral answer through the response_url.
        s.ack_callback(cb, Some("noted")).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/resp");
        assert_eq!(r.json(), json!({"text": "noted", "response_type": "ephemeral", "replace_original": false}));
        s.stop();
    }

    #[test]
    fn dropped_socket_and_missing_pong_reconnect() {
        let ws = socket_server(|n, mut ws| {
            ws.send_text(r#"{"type":"hello"}"#).unwrap();
            match n {
                0 => ws.get_ref().shutdown(std::net::Shutdown::Both).unwrap(),
                // Never read, so pings go unanswered.
                1 => std::thread::sleep(Duration::from_secs(3)),
                _ => {
                    ws.send_text(&envelope(1, json!({"type": "message", "channel": "D1", "channel_type": "im", "user": "U1", "text": "third time", "ts": "1.2"}))).unwrap();
                    idle(&mut ws);
                }
            }
        });
        let srv = api(ws);
        let mut c = cfg(&srv.url);
        c.ping_every = Duration::from_millis(100);
        let s = Slack::new(c).unwrap();
        let g = collect(&s, 1);
        assert_eq!(g[0].text, "third time");
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/apps.connections.open").count(), 3);
    }

    fn sign(secret: &str, ts: i64, body: &str) -> String {
        format!("v0={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), format!("v0:{ts}:{body}").as_bytes())))
    }

    #[test]
    fn events_api_verifies_signatures_and_handshake() {
        let srv = api(String::new());
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        let mut c = cfg(&srv.url);
        c.app_token = None;
        let s = Slack::new(c).unwrap().with_events_api(&listen, "/slack/events", "shh").unwrap();
        let post = |body: &str, ctype: &str, ts: Option<i64>, sig: Option<String>| -> (u16, String) {
            let a = crate::http::agent(Duration::from_secs(5));
            let mut r = a.post(&format!("http://{listen}/slack/events")).header("content-type", ctype);
            if let Some(t) = ts {
                r = r.header("x-slack-request-timestamp", &t.to_string());
            }
            if let Some(sg) = sig {
                r = r.header("x-slack-signature", &sg);
            }
            let mut resp = r.send(body.as_bytes()).unwrap();
            (resp.status().as_u16(), resp.body_mut().read_to_string().unwrap_or_default())
        };
        let now = unix_now();
        let hs = r#"{"type":"url_verification","challenge":"c4ll3ng3","token":"x"}"#;
        assert_eq!(post(hs, "application/json", Some(now), Some(sign("shh", now, hs))), (200, "c4ll3ng3".into()));
        assert_eq!(post(hs, "application/json", Some(now), Some(sign("wrong", now, hs))).0, 401, "bad signature");
        assert_eq!(post(hs, "application/json", None, None).0, 401, "missing headers");
        assert_eq!(post(hs, "application/json", Some(now - 400), Some(sign("shh", now - 400, hs))).0, 401, "replayed (too old)");
        let ev = json!({"type": "event_callback", "team_id": "T1", "event": {"type": "message", "channel": "C1", "channel_type": "channel", "user": "U1", "text": "via http", "ts": "1700000000.1"}}).to_string();
        assert_eq!(post(&ev, "application/json", Some(now), Some(sign("shh", now, &ev))).0, 200);
        let tampered = ev.replace("via http", "via evil");
        assert_eq!(post(&tampered, "application/json", Some(now), Some(sign("shh", now, &ev))).0, 401, "body bound to signature");
        let payload = json!({"type": "block_actions", "user": {"id": "U1"}, "channel": {"id": "C1"}, "container": {"message_ts": "5.5"}, "actions": [{"type": "button", "value": "cl:1:2", "action_ts": "9.9"}]}).to_string();
        let form = seagent_net::form_encode(&[("payload", &payload)]);
        assert_eq!(post(&form, "application/x-www-form-urlencoded", Some(now), Some(sign("shh", now, &form))).0, 200);
        let cmd = seagent_net::form_encode(&[("command", "/new"), ("text", ""), ("channel_id", "C1"), ("user_id", "U1"), ("trigger_id", "TR")]);
        assert_eq!(post(&cmd, "application/x-www-form-urlencoded", Some(now), Some(sign("shh", now, &cmd))).0, 200);
        let g = collect(&s, 3);
        assert_eq!(g.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["via http", "", "/new"]);
        assert_eq!(g[1].callback.as_ref().unwrap().data, "cl:1:2");
        assert!(!srv.requests().iter().any(|r| r.path == "/apps.connections.open"), "no socket in events mode");
    }

    #[test]
    fn send_shapes_uploads_actions_and_streaming() {
        // The upload URL points back at the fake server itself.
        let me = Arc::new(Mutex::new(String::new()));
        let me2 = me.clone();
        let srv = FakeServer::start(move |req, n| match req.path.as_str() {
            "/files.getUploadURLExternal" => ok(json!({"upload_url": format!("{}/upload", me2.lock().unwrap()), "file_id": "F123"})),
            "/upload" | "/file" => (200, vec![], "FILEBYTES".into()),
            _ => ok(json!({"ts": format!("1700000000.{n:06}")})),
        });
        *me.lock().unwrap() = srv.url.clone();
        let s = Slack::new(cfg(&srv.url)).unwrap();
        let out = Outbound {
            format: TextFormat::Markdown,
            thread: Some("1.5".into()),
            buttons: vec![vec![Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("C1", "**bold** [t](http://u)")
        };
        let sent = s.send(&out).unwrap();
        assert_eq!(sent.ids, ["1700000000.000000"]);
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/chat.postMessage", Some("Bearer xoxb-SECRET")));
        let b = r.json();
        assert_eq!((b["channel"].as_str(), b["text"].as_str(), b["thread_ts"].as_str(), b["mrkdwn"].as_bool()), (Some("C1"), Some("*bold* <http://u|t>"), Some("1.5"), Some(true)));
        assert_eq!(b["blocks"][0]["text"]["text"], "*bold* <http://u|t>");
        assert_eq!((b["blocks"][1]["type"].as_str(), b["blocks"][1]["elements"][0]["value"].as_str(), b["blocks"][1]["elements"][1]["url"].as_str()), (Some("actions"), Some("appr:x:once"), Some("https://e.com")));
        // Plain text is escaped; reply_to without thread becomes the thread; long text chunks.
        let long = format!("a<b & c {}", "x".repeat(5000));
        assert_eq!(s.send(&Outbound { reply_to: Some("2.5".into()), ..Outbound::text("C1", &long) }).unwrap().ids.len(), 2);
        let b = srv.requests()[1].json();
        assert!(b["text"].as_str().unwrap().starts_with("a&lt;b &amp; c") && b["thread_ts"] == "2.5" && b["mrkdwn"] == false);
        // Image URL → image block; local file → upload v2 with the text as comment.
        s.send(&Outbound { media: vec![Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() }], ..Outbound::text("C1", "pic") }).unwrap();
        assert_eq!(srv.requests()[3].json()["blocks"][1], json!({"type": "image", "image_url": "https://e.com/a.png", "alt_text": "image"}));
        let f = temp_dir("sl").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let ids = s.send(&Outbound { thread: Some("1.5".into()), media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() }], ..Outbound::text("C1", "the report") }).unwrap().ids;
        assert_eq!(ids, ["F123"]);
        let reqs = srv.requests();
        assert_eq!(reqs[4].path, "/files.getUploadURLExternal");
        assert_eq!(reqs[4].body, "filename=report.pdf&length=6");
        assert_eq!((reqs[5].path.as_str(), reqs[5].body.as_str(), reqs[5].header("content-type")), ("/upload", "%PDF-1", Some("application/pdf")));
        let done: HashMap<String, String> = seagent_net::parse_query(&reqs[6].body).into_iter().collect();
        assert_eq!(reqs[6].path, "/files.completeUploadExternal");
        assert_eq!((done["channel_id"].as_str(), done["thread_ts"].as_str(), done["initial_comment"].as_str()), ("C1", "1.5", "the report"));
        assert_eq!(serde_json::from_str::<Value>(&done["files"]).unwrap()[0]["id"], "F123");
        // Actions.
        let start = srv.requests().len();
        s.edit("C1", "1.1", "**new**").unwrap();
        s.delete("C1", "1.1").unwrap();
        s.delete("C1", "F123").unwrap();
        s.react("C1", "1.1", "👍", false).unwrap();
        s.react("C1", "1.1", ":eyes:", true).unwrap();
        s.typing("C1", Some("1.5")).unwrap();
        assert_eq!(s.typing("C1", None).unwrap_err().kind, K::Unsupported);
        let ts = s.stream_start("C1", "1.5", "Hel", Some("U1"), Some("T1")).unwrap();
        s.stream_append("C1", &ts, "lo").unwrap();
        s.stream_stop("C1", &ts, None).unwrap();
        let reqs = srv.requests();
        let paths: Vec<&str> = reqs[start..].iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/chat.update", "/chat.delete", "/files.delete", "/reactions.add", "/reactions.remove", "/assistant.threads.setStatus", "/chat.startStream", "/chat.appendStream", "/chat.stopStream"]);
        assert_eq!(reqs[start].json(), json!({"channel": "C1", "ts": "1.1", "text": "*new*"}));
        assert_eq!(reqs[start + 3].json(), json!({"channel": "C1", "timestamp": "1.1", "name": "+1"}));
        assert_eq!(reqs[start + 4].json()["name"], "eyes");
        assert_eq!(reqs[start + 5].json(), json!({"channel_id": "C1", "thread_ts": "1.5", "status": "is typing…"}));
        assert_eq!(reqs[start + 6].json(), json!({"channel": "C1", "thread_ts": "1.5", "markdown_text": "Hel", "recipient_user_id": "U1", "recipient_team_id": "T1"}));
        assert_eq!(reqs[start + 7].json(), json!({"channel": "C1", "ts": ts, "markdown_text": "lo"}));
        let bytes = s.fetch_media(&Media { url: Some(format!("{}/file", srv.url)), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"FILEBYTES");
        assert_eq!(srv.requests().last().unwrap().header("authorization"), Some("Bearer xoxb-SECRET"));
        assert_eq!(s.caps().streaming, Streaming::Edit);
        let mut c = cfg(&srv.url);
        c.native_streaming = true;
        assert_eq!(Slack::new(c).unwrap().caps().streaming, Streaming::Native);
    }

    #[test]
    fn error_mapping_and_rate_limits() {
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![("retry-after".into(), "1".into())], json!({"ok": false, "error": "ratelimited"}).to_string()),
            _ => ok(json!({"ts": "1.1"})),
        });
        let s = Slack::new(cfg(&srv.url)).unwrap();
        let t = Instant::now();
        s.send(&Outbound::text("C1", "x")).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(950), "honoured Retry-After");
        assert_eq!(srv.requests().len(), 2);
        let srv = FakeServer::start(|_, _| (429, vec![("retry-after".into(), "3600".into())], json!({"ok": false, "error": "ratelimited"}).to_string()));
        let e = Slack::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        for (code, kind) in [("invalid_auth", K::Auth), ("token_revoked", K::Auth), ("channel_not_found", K::NotFound), ("not_in_channel", K::NotFound), ("is_archived", K::NotFound), ("invalid_blocks", K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (200, vec![], json!({"ok": false, "error": code}).to_string()));
            let e = Slack::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{code}");
            assert!(!e.message.contains("SECRET"));
            assert_eq!(srv.requests().len(), 1, "{code} not retried");
        }
        let srv = FakeServer::start(|_, _| (503, vec![], "upstream down".into()));
        assert_eq!(Slack::new(cfg(&srv.url)).unwrap().send(&Outbound::text("C1", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len(), 5, "1 + max_retries");
        // A revoked bot token stops Socket Mode with Auth.
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"ok": false, "error": "invalid_auth"}).to_string()));
        let s = Slack::new(cfg(&srv.url)).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let e = loop {
            match s.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no auth error"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth);
    }

    #[test]
    fn cancel_returns_promptly_from_a_blocked_poll() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("ws://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let srv = api(dead);
        let mut c = cfg(&srv.url);
        c.poll_timeout_secs = 20;
        let s = Slack::new(c).unwrap();
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(s.poll(&cancel).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    /// Events API mode on a free port; returns (channel, listen address).
    fn events_mode(c: Config) -> (Slack, String) {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        let mut c = c;
        c.app_token = None;
        (Slack::new(c).unwrap().with_events_api(&listen, "/slack/events", "shh").unwrap(), listen)
    }

    fn post_signed(listen: &str, body: &str, form: bool) -> (u16, String) {
        let now = unix_now();
        let a = crate::http::agent(Duration::from_secs(5));
        let ctype = if form { "application/x-www-form-urlencoded" } else { "application/json" };
        let mut resp = a.post(&format!("http://{listen}/slack/events")).header("content-type", ctype).header("x-slack-request-timestamp", &now.to_string()).header("x-slack-signature", &sign("shh", now, body)).send(body.as_bytes()).unwrap();
        (resp.status().as_u16(), resp.body_mut().read_to_string().unwrap_or_default())
    }

    fn interactive(listen: &str, payload: Value) -> (u16, String) {
        post_signed(listen, &seagent_net::form_encode(&[("payload", &payload.to_string())]), true)
    }

    #[test]
    fn menus_pickers_modals_and_ephemeral_fallback() {
        let srv = FakeServer::start(|req, n| match req.path.as_str() {
            "/views.open" | "/views.push" => ok(json!({"view": {"id": "V1"}})),
            "/chat.postEphemeral" => ok(json!({"message_ts": "9.9"})),
            _ => ok(json!({"ts": format!("1700000000.{n:06}")})),
        });
        let mut c = cfg(&srv.url);
        c.modals.insert("form".into(), json!({"blocks": [{"type": "input", "block_id": "b1", "label": {"type": "plain_text", "text": "Title"}, "element": {"type": "plain_text_input", "action_id": "t"}}, {"type": "input", "block_id": "b2", "label": {"type": "plain_text", "text": "Owner"}, "element": {"type": "users_select", "action_id": "o"}}]}));
        let (s, listen) = events_mode(c);
        // Rows: 7 buttons → static_select, 150 → external_select, picker, short row stays buttons.
        let many: Vec<Button> = (0..150).map(|i| Button { label: format!("Item {i}"), data: format!("pick:{i}"), url: None }).collect();
        let rows = vec![many[..7].to_vec(), many.clone(), vec![Button { label: "Assign to".into(), data: "slack:users_select:assign".into(), url: None }], vec![Button { label: "Fill form".into(), data: "modal:form".into(), url: None }]];
        s.send(&Outbound { buttons: rows, ..Outbound::text("C1", "choose") }).unwrap();
        let b = srv.requests()[0].json();
        let blocks = b["blocks"].as_array().unwrap();
        assert_eq!((blocks[1]["elements"][0]["type"].as_str(), blocks[1]["elements"][0]["options"].as_array().unwrap().len(), blocks[1]["elements"][0]["options"][6]["value"].as_str()), (Some("static_select"), 7, Some("pick:6")));
        let ext = &blocks[2];
        assert_eq!(ext["elements"][0]["type"], "external_select");
        let block_id = ext["block_id"].as_str().unwrap().to_string();
        assert!(block_id.starts_with(MENU_PREFIX));
        assert_eq!(blocks[3]["elements"][0], json!({"type": "users_select", "action_id": "slack:users_select:assign", "placeholder": {"type": "plain_text", "text": "Assign to"}}));
        assert_eq!((blocks[4]["elements"][0]["type"].as_str(), blocks[4]["elements"][0]["value"].as_str()), (Some("button"), Some("modal:form")));
        // block_suggestion is answered synchronously from the stored options.
        let (st, body) = interactive(&listen, json!({"type": "block_suggestion", "block_id": block_id, "action_id": "seagent_sel_1", "value": "item 14", "user": {"id": "U1"}}));
        let opts: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(st, 200);
        assert_eq!(opts["options"].as_array().unwrap().iter().map(|o| o["value"].as_str().unwrap()).collect::<Vec<_>>(), ["pick:14", "pick:140", "pick:141", "pick:142", "pick:143", "pick:144", "pick:145", "pick:146", "pick:147", "pick:148", "pick:149"]);
        let (_, body) = interactive(&listen, json!({"type": "block_suggestion", "block_id": "seagent_menu:nope", "value": ""}));
        assert_eq!(body, r#"{"options":[]}"#);
        // Selections become callbacks carrying the chosen button data / picked ids.
        let act = |a: Value| json!({"type": "block_actions", "trigger_id": "TRIG", "user": {"id": "U1", "username": "amy"}, "team": {"id": "T1"}, "channel": {"id": "C1"}, "container": {"type": "message", "message_ts": "5.5", "channel_id": "C1"}, "actions": [a]});
        interactive(&listen, act(json!({"type": "static_select", "action_id": "seagent_sel_0", "selected_option": {"text": {"text": "Item 3"}, "value": "pick:3"}, "action_ts": "10.1"})));
        interactive(&listen, act(json!({"type": "users_select", "action_id": "slack:users_select:assign", "selected_user": "U9", "action_ts": "10.2"})));
        interactive(&listen, act(json!({"type": "multi_conversations_select", "action_id": "slack:multi_conversations_select", "selected_conversations": ["C7", "D8"], "action_ts": "10.3"})));
        // A modal opener calls views.open instead of reporting a press.
        interactive(&listen, act(json!({"type": "button", "action_id": "seagent_3_0", "value": "modal:form", "action_ts": "10.4"})));
        let g = collect(&s, 3);
        assert_eq!(g.iter().map(|m| m.callback.as_ref().unwrap().data.as_str()).collect::<Vec<_>>(), ["pick:3", "slack:users_select:assign=U9", "slack:multi_conversations_select=C7,D8"]);
        let open = srv.requests().into_iter().find(|r| r.path == "/views.open").unwrap().json();
        assert_eq!((open["trigger_id"].as_str(), open["view"]["type"].as_str(), open["view"]["callback_id"].as_str(), open["view"]["submit"]["text"].as_str(), open["view"]["notify_on_close"].as_bool()), (Some("TRIG"), Some("modal"), Some("seagent:form"), Some("Submit"), Some(true)));
        let meta: Value = serde_json::from_str(open["view"]["private_metadata"].as_str().unwrap()).unwrap();
        assert_eq!(meta, json!({"c": "C1", "t": ""}));
        // Submission / close come back as messages to the originating chat.
        let view = json!({"id": "V1", "callback_id": "seagent:form", "private_metadata": json!({"c": "C1", "t": "4.4"}).to_string(), "blocks": open["view"]["blocks"], "state": {"values": {"b1": {"t": {"type": "plain_text_input", "value": "Fix the build"}}, "b2": {"o": {"type": "users_select", "selected_user": "U9"}}}}});
        assert_eq!(interactive(&listen, json!({"type": "view_submission", "user": {"id": "U1", "username": "amy"}, "team": {"id": "T1"}, "view": view})).0, 200);
        interactive(&listen, json!({"type": "view_closed", "user": {"id": "U1"}, "view": {"id": "V1", "callback_id": "seagent:form", "private_metadata": "{}"}, "is_cleared": false}));
        interactive(&listen, json!({"type": "view_submission", "user": {"id": "U1"}, "view": {"id": "V2", "callback_id": "someone_else"}}));
        let g = collect(&s, 2);
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].chat.as_str(), g[0].thread.as_deref(), g[0].chat_type, g[0].callback.is_none()), ("C1", Some("4.4"), ChatType::Thread, true));
        assert_eq!(g[0].text, "[Slack modal form submitted]\n- Title: Fix the build\n- Owner: U9");
        assert_eq!((g[1].text.as_str(), g[1].chat.as_str(), g[1].chat_type), ("[Slack modal form closed]", "U1", ChatType::Direct));
        // Inside a modal, an opener pushes a view; no inbound.
        interactive(&listen, json!({"type": "block_actions", "trigger_id": "TRIG2", "user": {"id": "U1"}, "container": {"type": "view", "view_id": "V1"}, "view": {"private_metadata": "{\"c\":\"C1\"}"}, "actions": [{"type": "button", "value": "modal:form", "action_ts": "11.1"}]}));
        std::thread::sleep(Duration::from_millis(300));
        assert!(s.poll(&Cancel::new()).unwrap().is_empty());
        let push = srv.requests().into_iter().find(|r| r.path == "/views.push").unwrap().json();
        assert_eq!(push["trigger_id"], "TRIG2");
        // Callback answers without a response_url go through chat.postEphemeral.
        s.ack_callback(&Callback { id: "10.1".into(), data: String::new() }, Some("**done**")).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!((r.path.as_str(), r.json()), ("/chat.postEphemeral", json!({"channel": "C1", "user": "U1", "text": "*done*"})));
        s.update_view("V1", Some("h1"), &json!({"type": "modal"})).unwrap();
        assert_eq!(srv.requests().last().unwrap().json(), json!({"view_id": "V1", "hash": "h1", "view": {"type": "modal"}}));
    }

    #[test]
    fn socket_mode_answers_block_suggestion_in_the_ack() {
        let acks = Arc::new(Mutex::new(Vec::<Value>::new()));
        let a2 = acks.clone();
        let token = Arc::new(Mutex::new(String::new()));
        let t2 = token.clone();
        let ws = socket_server(move |_, mut ws| {
            ws.send_text(r#"{"type":"hello"}"#).unwrap();
            while t2.lock().unwrap().is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
            let bid = format!("{MENU_PREFIX}{}", t2.lock().unwrap());
            ws.send_text(&json!({"envelope_id": "S1", "type": "interactive", "payload": {"type": "block_suggestion", "block_id": bid, "value": "beta"}}).to_string()).unwrap();
            if let Ok(Message::Text(t)) = ws.recv_blocking() {
                a2.lock().unwrap().push(serde_json::from_str(&t).unwrap());
            }
            idle(&mut ws);
        });
        let srv = api(ws);
        let s = Slack::new(cfg(&srv.url)).unwrap();
        *token.lock().unwrap() = s.inner.store_menu(vec![("Alpha".into(), "a".into()), ("Beta".into(), "b".into())]);
        let until = Instant::now() + Duration::from_secs(5);
        while acks.lock().unwrap().is_empty() && Instant::now() < until {
            assert!(s.poll(&Cancel::new()).unwrap().is_empty(), "suggestions are not inbound messages");
        }
        assert_eq!(acks.lock().unwrap()[0], json!({"envelope_id": "S1", "payload": {"options": [{"text": {"type": "plain_text", "text": "Beta", "emoji": true}, "value": "b"}]}}));
        s.stop();
    }

    #[test]
    fn thread_history_user_names_and_suggested_prompts() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/auth.test" => ok(json!({"user_id": "UBOT", "bot_id": "BBOT", "user": "seagent"})),
            "/users.info" => {
                let q: HashMap<String, String> = seagent_net::parse_query(&req.body).into_iter().collect();
                match q["user"].as_str() {
                    "U1" => ok(json!({"user": {"name": "amy.l", "profile": {"display_name": "", "real_name": "Amy Lee"}}})),
                    _ => (200, vec![], json!({"ok": false, "error": "user_not_found"}).to_string()),
                }
            }
            "/conversations.replies" => ok(json!({"messages": [
                {"ts": "100.1", "user": "U2", "text": "root question", "user_profile": {"display_name": "Bob"}},
                {"ts": "100.2", "bot_id": "BBOT", "user": "UBOT", "text": "an answer"},
                {"ts": "100.3", "user": "U1", "text": "", "files": [{"id": "F1"}]},
                {"ts": "100.4", "user": "U1", "text": "<@UBOT> follow up"}
            ], "has_more": false})),
            _ => ok(json!({})),
        });
        let mut c = cfg(&srv.url);
        c.suggested_prompts = vec![("Hi".into(), "Say hi".into())];
        let (s, listen) = events_mode(c);
        let ev = |e: Value| json!({"type": "event_callback", "team_id": "T1", "event": e}).to_string();
        post_signed(&listen, &ev(json!({"type": "app_mention", "channel": "C1", "user": "U1", "text": "<@UBOT> follow up", "ts": "100.4", "thread_ts": "100.1"})), false);
        post_signed(&listen, &ev(json!({"type": "app_mention", "channel": "C1", "user": "U1", "text": "<@UBOT> again", "ts": "100.5", "thread_ts": "100.1"})), false);
        post_signed(&listen, &ev(json!({"type": "assistant_thread_started", "assistant_thread": {"channel_id": "D1", "thread_ts": "7.7"}})), false);
        let g = collect(&s, 2);
        assert_eq!(g[0].text, "[Slack thread history]\nBob: root question\nseagent: an answer\nAmy Lee: [1 file(s)]\n[/Slack thread history]\n\n@seagent follow up");
        assert_eq!(g[0].sender_name, "Amy Lee", "users.info fills the name");
        assert_eq!(g[1].text, "@seagent again", "history only once per thread");
        std::thread::sleep(Duration::from_millis(200));
        let reqs = srv.requests();
        let replies: Vec<_> = reqs.iter().filter(|r| r.path == "/conversations.replies").collect();
        assert_eq!(replies.len(), 1);
        let q: HashMap<String, String> = seagent_net::parse_query(&replies[0].body).into_iter().collect();
        assert_eq!((q["channel"].as_str(), q["ts"].as_str(), q["latest"].as_str()), ("C1", "100.1", "100.4"));
        assert_eq!(reqs.iter().filter(|r| r.path == "/users.info").count(), 1, "names cached");
        let sp = reqs.iter().find(|r| r.path == "/assistant.threads.setSuggestedPrompts").unwrap().json();
        assert_eq!(sp, json!({"channel_id": "D1", "thread_ts": "7.7", "title": "Try asking", "prompts": [{"title": "Hi", "message": "Say hi"}]}));
        assert_eq!(s.user_name("UX"), "", "lookup failures degrade to no name");
    }
}
