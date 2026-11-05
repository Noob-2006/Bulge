//! Discord bot (ported from OpenClaw `extensions/discord` — its own gateway
//! client in `src/internal/gateway.ts` — and Hermes `plugins/platforms/discord`,
//! both MIT).
//!
//! Receive: Gateway v10 over WebSocket (`GET /gateway/bot` → Hello → heartbeat
//! with initial jitter and ACK tracking, a missed ACK is a zombie connection →
//! reconnect and Resume with `session_id`/`seq` on `resume_gateway_url`;
//! Reconnect (op 7) and Invalid Session (op 9) handled; fatal close codes stop
//! with `Auth`/`Fatal`). Identify asks for GUILDS, GUILD_MESSAGES,
//! DIRECT_MESSAGES and MESSAGE_CONTENT. Parses MESSAGE_CREATE / MESSAGE_UPDATE
//! (DMs, guild channels, threads → `thread`, `<@id>` mentions, replies,
//! attachments) and INTERACTION_CREATE (button components → `Callback`, slash
//! commands → `/name args` text).
//! Send: REST v10 — content with `message_reference`, button components,
//! `allowed_mentions`, silent flag, multipart uploads (`payload_json` +
//! `files[n]`), 2000-char chunks; edit, delete, typing, reactions, interaction
//! callbacks; per-route `X-RateLimit-*` buckets and 429 `retry_after` from the
//! JSON body. Optional `/new /stop /status /help` registration
//! (`PUT /applications/{app}/commands`).
//! Voice (`voice = true`, see `discord_voice`): adds GUILD_VOICE_STATES, tracks who
//! sits in which voice channel, `/voice join|leave|status` (text or slash command)
//! joins the caller's channel via gateway op 4 and binds it to the text channel;
//! transcripts arrive as `Inbound`s there and replies to that chat are spoken.
//! Sharding: `shards = N | "auto"` (count from `GET /gateway/bot`), one gateway
//! thread per shard, Identify gated per `shard % max_concurrency` bucket every
//! 5 s (OpenClaw `gateway-identify-limiter`), voice op 4 routed to the guild's
//! shard. `compress = true` uses `compress=zlib-stream` (hand-written inflate in
//! `zlib.rs`). Components: string/user/role/mentionable/channel selects and
//! modals (OpenClaw `components.modal.ts`/`modal-fields.ts`: Label-wrapped
//! fields, trigger button → type 9 response, MODAL_SUBMIT → `Callback`); a
//! button row longer than 5 becomes a string select. Polls (send, end, voters;
//! vote add/remove and the result message → `Callback`), threads (from a
//! message or not, forum posts — sends to a forum channel open a post like
//! Hermes `_send_to_forum`; `auto_thread` like Hermes), role mentions (`<@&id>`
//! → `@role`, the bot's managed role counts as a mention, Hermes-style
//! `allow_mentions` → `allowed_mentions`, `@role` written back as `<@&id>` for
//! allowed roles).

use crate::discord_voice::{self, Binding, VoiceConfig, VoiceManager};
use crate::{
    sleep_cancellable, Button, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming,
};
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "zlib.rs"]
pub mod zlib;
#[path = "discord_actions.rs"]
mod actions;
#[path = "discord_tools.rs"]
mod tools;

pub const DEFAULT_API: &str = "https://discord.com/api/v10";
pub const MAX_MESSAGE: usize = 2000;

/// GUILDS | GUILD_MESSAGES | DIRECT_MESSAGES | MESSAGE_CONTENT | GUILD_MESSAGE_POLLS | DIRECT_MESSAGE_POLLS.
pub const DEFAULT_INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15) | (1 << 24) | (1 << 25);
pub const GUILD_VOICE_STATES: u64 = 1 << 7;

const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;
const SUPPRESS_NOTIFICATIONS: u64 = 1 << 12;
const EPHEMERAL: u64 = 1 << 6;
const IS_VOICE_MESSAGE: u64 = 1 << 13;

/// Everything `Discord::new` needs; the timing fields exist so tests run fast.
#[derive(Debug, Clone)]
pub struct Config {
    pub id: String,
    pub token: String,
    pub api_base: String,
    /// Skip `GET /gateway/bot` and connect here.
    pub gateway_url: Option<String>,
    pub poll_timeout_secs: u64,
    pub intents: u64,
    /// Register /new /stop /status /help as slash commands after READY.
    pub commands: bool,
    /// Register them in one guild (instant) instead of globally.
    pub command_guild: Option<String>,
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest rate-limit wait honoured in place; longer surfaces as `RateLimited`.
    pub max_wait: Duration,
    /// Reconnect backoff unit (Discord: 1 s, doubling up to 30 s).
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// Voice channels (None = off).
    pub voice: Option<VoiceConfig>,
    /// `compress=zlib-stream` transport compression.
    pub compress: bool,
    pub shards: Shards,
    /// Run only these shard ids (one bot split over several processes); None = all.
    pub shard_ids: Option<Vec<u32>>,
    /// Identify buckets; None = `session_start_limit.max_concurrency` (or 1).
    pub max_concurrency: Option<u32>,
    /// One Identify per bucket per this long (Discord: 5 s).
    pub identify_interval: Duration,
    /// Answer a mention in a text channel in a new thread started from it.
    pub auto_thread: bool,
    pub mentions: Mentions,
    /// Allowlist for the `discord` / `discord_admin` tools (Hermes `discord.server_actions`); None = all.
    pub server_actions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shards {
    Count(u32),
    /// The count Discord recommends in `GET /gateway/bot`.
    Auto,
}

/// What outgoing messages may ping (Hermes `allow_mentions`; roles and @everyone off by default).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Mentions {
    pub users: bool,
    pub roles: bool,
    pub everyone: bool,
    pub replied_user: bool,
    /// Pingable roles when `roles` is off.
    pub role_ids: Vec<String>,
}

impl Default for Mentions {
    fn default() -> Self {
        Mentions { users: true, roles: false, everyone: false, replied_user: true, role_ids: vec![] }
    }
}

impl Mentions {
    fn allowed(&self) -> Value {
        let parse: Vec<&str> = [(self.users, "users"), (self.roles, "roles"), (self.everyone, "everyone")].into_iter().filter(|(on, _)| *on).map(|(_, k)| k).collect();
        let mut v = json!({"parse": parse, "replied_user": self.replied_user});
        if !self.roles && !self.role_ids.is_empty() {
            v["roles"] = json!(self.role_ids.iter().take(100).collect::<Vec<_>>());
        }
        v
    }

    fn role_ok(&self, id: &str) -> bool {
        self.roles || self.role_ids.iter().any(|r| r == id)
    }
}

impl Config {
    pub fn new(id: &str, token: &str) -> Config {
        Config {
            id: id.into(),
            token: token.trim().into(),
            api_base: DEFAULT_API.into(),
            gateway_url: None,
            poll_timeout_secs: 25,
            intents: DEFAULT_INTENTS,
            commands: false,
            command_guild: None,
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
            voice: None,
            compress: false,
            shards: Shards::Count(1),
            shard_ids: None,
            max_concurrency: None,
            identify_interval: Duration::from_secs(5),
            auto_thread: false,
            mentions: Mentions::default(),
            server_actions: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Me {
    id: String,
    username: String,
    app_id: String,
}

#[derive(Debug, Clone, Default)]
struct ChanInfo {
    kind: u64,
    parent: Option<String>,
    name: String,
    guild: Option<String>,
}

impl ChanInfo {
    fn is_thread(&self) -> bool {
        matches!(self.kind, 10..=12)
    }

    fn is_forum(&self) -> bool {
        matches!(self.kind, 15 | 16)
    }
}

#[derive(Debug, Clone)]
struct Role {
    guild: String,
    name: String,
    /// Managed role of this bot user (`tags.bot_id`).
    bot: Option<String>,
}

/// A poll we sent: question and (answer id, text, callback data).
#[derive(Debug, Clone)]
struct PollMeta {
    question: String,
    answers: Vec<(u64, String, Option<String>)>,
}

/// One Identify per `shard % max_concurrency` bucket per interval, shared by all shards.
struct IdentifyGate {
    max_concurrency: AtomicU32,
    next: Mutex<HashMap<u32, Instant>>,
}

impl IdentifyGate {
    fn wait(&self, shard: u32, interval: Duration, stop: &Cancel) -> bool {
        loop {
            let wait = {
                let mut next = self.next.lock().unwrap();
                let key = shard % self.max_concurrency.load(Ordering::SeqCst).max(1);
                let now = Instant::now();
                match next.get(&key) {
                    Some(t) if *t > now => *t - now,
                    _ => {
                        next.insert(key, now + interval);
                        return true;
                    }
                }
            };
            if !sleep_cancellable(wait, stop) {
                return false;
            }
        }
    }

    /// `session_start_limit.remaining == 0`: nobody identifies before the reset.
    fn block_until(&self, t: Instant) {
        let mut next = self.next.lock().unwrap();
        for k in 0..self.max_concurrency.load(Ordering::SeqCst).max(1) {
            next.insert(k, t);
        }
    }
}

/// Bounded insertion-ordered map for registries (modals, polls).
struct Lru<V> {
    map: HashMap<String, V>,
    order: VecDeque<String>,
}

impl<V: Clone> Lru<V> {
    fn new() -> Self {
        Lru { map: HashMap::new(), order: VecDeque::new() }
    }
    fn put(&mut self, k: &str, v: V) {
        if self.map.insert(k.to_string(), v).is_none() {
            self.order.push_back(k.to_string());
            if self.order.len() > 1024 {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
    fn get(&self, k: &str) -> Option<V> {
        self.map.get(k).cloned()
    }
}

/// Bounded message id → channel id map so edit/delete/react find messages in threads.
#[derive(Default)]
struct Locs {
    map: HashMap<String, String>,
    order: VecDeque<String>,
}

impl Locs {
    fn put(&mut self, msg: &str, chan: &str) {
        if self.map.insert(msg.to_string(), chan.to_string()).is_none() {
            self.order.push_back(msg.to_string());
            if self.order.len() > 4096 {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

struct Inner {
    cfg: Config,
    agent: ureq::Agent,
    me: Mutex<Option<Me>>,
    chans: Mutex<HashMap<String, ChanInfo>>,
    locs: Mutex<Locs>,
    dms: Mutex<HashMap<String, String>>,
    /// Route → blocked until (bucket exhausted or global 429).
    buckets: Mutex<HashMap<String, Instant>>,
    fatal: Mutex<Option<ChannelError>>,
    commands_done: AtomicBool,
    voice: Option<Arc<VoiceManager>>,
    /// Gateway payloads queued by other threads (voice op 4), sent by the guild's shard.
    gw_out: Arc<Mutex<Vec<Value>>>,
    shard_count: AtomicU32,
    gate: IdentifyGate,
    roles: Mutex<HashMap<String, Role>>,
    roles_fetched: Mutex<std::collections::HashSet<String>>,
    modals: Mutex<Lru<Modal>>,
    polls: Mutex<Lru<Option<PollMeta>>>,
    /// Bot presence (version, op 3 `d`) from `set-presence`; every shard sends a newer version.
    presence: Mutex<(u64, Option<Value>)>,
}

pub struct Discord {
    inner: Arc<Inner>,
    rx: Mutex<mpsc::Receiver<Inbound>>,
    tx: Mutex<Option<mpsc::Sender<Inbound>>>,
    stop: Cancel,
}

impl Discord {
    /// The voice manager this channel runs (`[channels.<name>.voice]`), if any: the media
    /// layer's `discord-voice` transcript source and the hosts talk to the bot through it.
    pub fn voice_manager(&self) -> Option<Arc<VoiceManager>> {
        self.inner.voice.clone()
    }

    pub fn new(cfg: Config) -> Result<Discord, String> {
        if cfg.token.is_empty() {
            return Err(format!("channel {}: discord token is empty", cfg.id));
        }
        let (tx, rx) = mpsc::channel();
        let mut cfg = cfg;
        cfg.api_base = cfg.api_base.trim_end_matches('/').to_string();
        if cfg.voice.is_some() {
            cfg.intents |= GUILD_VOICE_STATES;
        }
        let voice = cfg.voice.clone().map(|v| VoiceManager::new(&cfg.id, v));
        // The `transcripts` tool's `discord-voice` source reads this manager (G8): without this
        // the media layer has no Discord back-end and every capture says "not available".
        if let Some(v) = &voice {
            crate::discord_transcripts::install(v.clone());
        }
        let gw_out = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(Inner {
                agent: crate::http::agent(Duration::from_secs(60)),
                cfg,
                me: Mutex::new(None),
                chans: Mutex::new(HashMap::new()),
                locs: Mutex::new(Locs::default()),
                dms: Mutex::new(HashMap::new()),
                buckets: Mutex::new(HashMap::new()),
                fatal: Mutex::new(None),
                commands_done: AtomicBool::new(false),
                voice,
                gw_out: gw_out.clone(),
                shard_count: AtomicU32::new(1),
                gate: IdentifyGate { max_concurrency: AtomicU32::new(1), next: Mutex::new(HashMap::new()) },
                roles: Mutex::new(HashMap::new()),
                roles_fetched: Mutex::new(Default::default()),
                modals: Mutex::new(Lru::new()),
                polls: Mutex::new(Lru::new()),
                presence: Mutex::new((0, None)),
            });
        if let Some(v) = &inner.voice {
            let w = Arc::downgrade(&inner);
            v.set_hooks(
                Box::new(move |p| gw_out.lock().unwrap().push(p)),
                Box::new(move |channel, text| {
                    if let Some(i) = w.upgrade() {
                        let body = json!({"content": text, "allowed_mentions": {"parse": []}});
                        let _ = i.rest("POST", &format!("/channels/{channel}/messages"), Body::Json(&body));
                    }
                }),
            );
        }
        Ok(Discord {
            inner,
            rx: Mutex::new(rx),
            tx: Mutex::new(Some(tx)),
            stop: Cancel::new(),
        })
    }

    /// Start the gateway thread on first poll (send-only use never connects).
    fn ensure_started(&self) {
        let Some(tx) = self.tx.lock().unwrap().take() else { return };
        if let Some(v) = &self.inner.voice {
            v.set_inbound(tx.clone());
        }
        let (inner, stop) = (self.inner.clone(), self.stop.clone());
        let _ = std::thread::Builder::new().name(format!("discord {}", inner.cfg.id)).spawn(move || run_shards(&inner, &tx, &stop));
    }
}

impl Drop for Discord {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(v) = &self.inner.voice {
            v.shutdown();
        }
    }
}

// ---------------------------------------------------------------- REST

struct RawResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl RawResp {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

enum Body<'a> {
    None,
    Json(&'a Value),
    /// payload_json + files: (filename, mime, bytes).
    Files(&'a Value, Vec<(String, String, Vec<u8>)>),
    /// Pre-encoded body: (content type, bytes).
    Raw(String, Vec<u8>),
}

fn multipart(payload: &Value, files: &[(String, String, Vec<u8>)]) -> (String, Vec<u8>) {
    let boundary = format!("arkdc{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(12)));
    let mut b = Vec::new();
    b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n").as_bytes());
    b.extend_from_slice(payload.to_string().as_bytes());
    b.extend_from_slice(b"\r\n");
    for (i, (name, mime, data)) in files.iter().enumerate() {
        let ct = if mime.is_empty() { "application/octet-stream" } else { mime };
        b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"files[{i}]\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", name.replace(['"', '\r', '\n'], "")).as_bytes());
        b.extend_from_slice(data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), b)
}

fn raw_call(agent: &ureq::Agent, method: &str, url: &str, headers: &[(&str, &str)], ctype: Option<&str>, body: &[u8]) -> Result<RawResp, ChannelError> {
    let resp = match method {
        "GET" | "DELETE" => {
            let mut r = if method == "GET" { agent.get(url) } else { agent.delete(url) };
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        }
        _ => {
            let mut r = match method {
                "PUT" => agent.put(url),
                "PATCH" => agent.patch(url),
                _ => agent.post(url),
            };
            if let Some(ct) = ctype {
                r = r.header("content-type", ct);
            }
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(body)
        }
    };
    let mut r = resp.map_err(|e| ChannelError::new(K::Network, format!("discord {method} failed: {e}")))?;
    let status = r.status().as_u16();
    let headers = r.headers().iter().filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string()))).collect();
    let mut raw = Vec::new();
    r.body_mut().with_config().limit(u64::MAX).reader().take(16 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("reading discord response: {e}")))?;
    Ok(RawResp { status, headers, body: String::from_utf8_lossy(&raw).into_owned() })
}

/// Discord's JSON error `{code, message, retry_after, global}` → classified error.
fn dc_error(what: &str, r: &RawResp) -> ChannelError {
    let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
    let code = v["code"].as_u64().unwrap_or(0);
    let msg = v["message"].as_str().map(str::to_string).unwrap_or_else(|| r.body.chars().take(200).collect());
    let text = format!("{what}: HTTP {} {msg} (code {code})", r.status);
    let kind = match r.status {
        401 => K::Auth,
        // Unknown channel/message/user, missing access, cannot DM this user, missing permissions.
        403 | 404 => K::NotFound,
        _ if matches!(code, 10003 | 10008 | 10013 | 50001 | 50007) => K::NotFound,
        429 => {
            let ra = v["retry_after"].as_f64().or_else(|| r.header("retry-after").and_then(|s| s.trim().parse().ok())).map(|s| Duration::from_secs_f64(s.max(0.0)));
            K::RateLimited { retry_after: ra }
        }
        408 | 500..=599 => K::Network,
        _ => K::Protocol,
    };
    ChannelError::new(kind, text)
}

impl Inner {
    fn rest(&self, method: &str, path: &str, body: Body) -> Result<Value, ChannelError> {
        self.rest_h(method, path, body, &[])
    }

    /// `rest` with extra request headers (`X-Audit-Log-Reason`).
    fn rest_h(&self, method: &str, path: &str, body: Body, extra: &[(&str, &str)]) -> Result<Value, ChannelError> {
        let url = format!("{}{path}", self.cfg.api_base);
        let route = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let auth = format!("Bot {}", self.cfg.token);
        let (ctype, bytes): (Option<String>, Vec<u8>) = match &body {
            Body::None => (None, Vec::new()),
            Body::Json(v) => (Some("application/json".into()), v.to_string().into_bytes()),
            Body::Files(p, f) => {
                let (c, b) = multipart(p, f);
                (Some(c), b)
            }
            Body::Raw(c, b) => (Some(c.clone()), b.clone()),
        };
        let mut attempt = 0;
        loop {
            self.wait_bucket(&route)?;
            let mut headers = vec![("authorization", auth.as_str()), ("user-agent", "DiscordBot (https://github.com/ark, 1) ark")];
            headers.extend_from_slice(extra);
            let err = match raw_call(&self.agent, method, &url, &headers, ctype.as_deref(), &bytes) {
                Ok(r) => {
                    self.note_bucket(&route, &r);
                    if (200..300).contains(&r.status) {
                        if r.body.trim().is_empty() {
                            return Ok(Value::Null);
                        }
                        return serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("{route}: bad JSON ({e})")));
                    }
                    let e = dc_error(&route, &r);
                    if let K::RateLimited { retry_after: Some(d) } = e.kind {
                        // A global limit blocks every route.
                        let key = if serde_json::from_str::<Value>(&r.body).ok().is_some_and(|v| v["global"] == true) { "*".to_string() } else { route.clone() };
                        self.buckets.lock().unwrap().insert(key, Instant::now() + d);
                    }
                    e
                }
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.cfg.max_retries {
                return Err(err);
            }
            match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.cfg.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(_) } => {}
                _ => std::thread::sleep(self.cfg.retry_base * 2u32.pow(attempt)),
            }
            attempt += 1;
        }
    }

    /// Sleep until the route's (or the global) bucket refills.
    fn wait_bucket(&self, route: &str) -> Result<(), ChannelError> {
        let until = {
            let b = self.buckets.lock().unwrap();
            [b.get(route), b.get("*")].into_iter().flatten().max().copied()
        };
        if let Some(t) = until {
            let now = Instant::now();
            if t > now {
                let d = t - now;
                if d > self.cfg.max_wait {
                    return Err(ChannelError::new(K::RateLimited { retry_after: Some(d) }, format!("{route}: rate limited")));
                }
                std::thread::sleep(d);
            }
        }
        Ok(())
    }

    fn note_bucket(&self, route: &str, r: &RawResp) {
        let remaining = r.header("x-ratelimit-remaining").and_then(|v| v.trim().parse::<u64>().ok());
        let reset = r.header("x-ratelimit-reset-after").and_then(|v| v.trim().parse::<f64>().ok());
        if let (Some(0), Some(s)) = (remaining, reset) {
            self.buckets.lock().unwrap().insert(route.to_string(), Instant::now() + Duration::from_secs_f64(s.max(0.0)));
        }
    }

    fn gateway_base(&self) -> Result<String, ChannelError> {
        if let Some(u) = &self.cfg.gateway_url {
            return Ok(u.clone());
        }
        let v = self.rest("GET", "/gateway/bot", Body::None)?;
        v["url"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "GET /gateway/bot: no url"))
    }

    /// Shards to run: (count, ids). `GET /gateway/bot` when the count is `auto` or the
    /// identify concurrency is unknown for several shards; an exhausted
    /// `session_start_limit` holds every Identify until its reset.
    fn shard_plan(&self) -> Result<(u32, Vec<u32>), ChannelError> {
        let fixed = match self.cfg.shards {
            Shards::Count(n) => Some(n.max(1)),
            Shards::Auto => None,
        };
        let mut count = fixed.unwrap_or(1);
        let mut maxc = self.cfg.max_concurrency.unwrap_or(1);
        if fixed.is_none() || (count > 1 && self.cfg.max_concurrency.is_none() && self.cfg.gateway_url.is_none()) {
            let v = self.rest("GET", "/gateway/bot", Body::None)?;
            if fixed.is_none() {
                count = v["shards"].as_u64().unwrap_or(1).clamp(1, 65_536) as u32;
            }
            let lim = &v["session_start_limit"];
            if self.cfg.max_concurrency.is_none() {
                maxc = lim["max_concurrency"].as_u64().unwrap_or(1).max(1) as u32;
            }
            self.gate.max_concurrency.store(maxc, Ordering::SeqCst);
            if lim["remaining"].as_u64() == Some(0) {
                self.gate.block_until(Instant::now() + Duration::from_millis(lim["reset_after"].as_u64().unwrap_or(0)));
            }
        }
        self.gate.max_concurrency.store(maxc, Ordering::SeqCst);
        let ids = match &self.cfg.shard_ids {
            Some(ids) => ids.iter().copied().filter(|i| *i < count).collect(),
            None => (0..count).collect(),
        };
        Ok((count, ids))
    }

    /// The shard that owns a guild: `(guild_id >> 22) % shard_count`.
    fn shard_of(&self, guild: &Value) -> u32 {
        let id = guild.as_str().and_then(|g| g.parse::<u64>().ok()).unwrap_or(0);
        ((id >> 22) % self.shard_count.load(Ordering::SeqCst).max(1) as u64) as u32
    }

    fn note_role(&self, guild: &str, r: &Value) {
        if let Some(id) = r["id"].as_str() {
            let role = Role { guild: guild.to_string(), name: r["name"].as_str().unwrap_or("").to_string(), bot: r["tags"]["bot_id"].as_str().map(str::to_string) };
            self.roles.lock().unwrap().insert(id.to_string(), role);
        }
    }

    /// Role by id; an unknown role in a guild fetches that guild's roles once.
    fn role(&self, id: &str, guild: Option<&str>) -> Option<Role> {
        if let Some(r) = self.roles.lock().unwrap().get(id) {
            return Some(r.clone());
        }
        let g = guild?;
        if !self.roles_fetched.lock().unwrap().insert(g.to_string()) {
            return None;
        }
        let v = self.rest("GET", &format!("/guilds/{g}/roles"), Body::None).ok()?;
        for r in v.as_array().into_iter().flatten() {
            self.note_role(g, r);
        }
        self.roles.lock().unwrap().get(id).cloned()
    }

    fn chan(&self, id: &str, guild: bool) -> Option<ChanInfo> {
        if let Some(c) = self.chans.lock().unwrap().get(id) {
            return Some(c.clone());
        }
        if !guild {
            return None;
        }
        // Unknown guild channel (thread created before we connected): ask once.
        let v = self.rest("GET", &format!("/channels/{id}"), Body::None).ok()?;
        let c = chan_info(&v);
        self.chans.lock().unwrap().insert(id.to_string(), c.clone());
        Some(c)
    }

    fn remember(&self, msg: &str, chan: &str) {
        self.locs.lock().unwrap().put(msg, chan);
    }

    fn register_commands(&self) {
        if !self.cfg.commands || self.commands_done.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(app) = self.me.lock().unwrap().clone().map(|m| m.app_id).filter(|a| !a.is_empty()) else { return };
        let menu = crate::menu();
        let mut cmds = if menu.is_empty() {
            json!([
                {"name": "new", "description": "開新對話", "type": 1},
                {"name": "stop", "description": "中斷目前的工作", "type": 1},
                {"name": "status", "description": "目前狀態", "type": 1},
                {"name": "help", "description": "說明", "type": 1},
            ])
        } else {
            json!(crate::discord_menu(&menu).into_iter().filter(|c| c["name"] != "voice").collect::<Vec<_>>())
        };
        if self.voice.is_some() {
            let choices: Vec<Value> = ["join", "leave", "status"].iter().map(|c| json!({"name": c, "value": c})).collect();
            cmds.as_array_mut().unwrap().push(json!({"name": "voice", "description": "語音頻道", "type": 1, "dm_permission": false, "options": [{"type": 3, "name": "mode", "description": "join / leave / status", "required": false, "choices": choices}]}));
        }
        let path = match &self.cfg.command_guild {
            Some(g) => format!("/applications/{app}/guilds/{g}/commands"),
            None => format!("/applications/{app}/commands"),
        };
        if self.rest("PUT", &path, Body::Json(&cmds)).is_err() {
            self.commands_done.store(false, Ordering::SeqCst);
        }
    }
}

fn chan_info(v: &Value) -> ChanInfo {
    ChanInfo { kind: v["type"].as_u64().unwrap_or(0), parent: v["parent_id"].as_str().map(str::to_string), name: v["name"].as_str().unwrap_or("").to_string(), guild: v["guild_id"].as_str().map(str::to_string) }
}

// ---------------------------------------------------------------- gateway

#[derive(Default)]
struct Session {
    id: Option<String>,
    seq: Option<u64>,
    resume_url: Option<String>,
    resume_failures: u32,
}

impl Session {
    fn reset(&mut self) {
        *self = Session::default();
    }
}

enum Outcome {
    Stopped,
    Fatal(ChannelError),
    /// `healthy`: READY/RESUMED arrived on this connection (resets the backoff).
    Reconnect { resume: bool, min_delay: Duration, healthy: bool },
}

fn rand01() -> f64 {
    let b = ark_net::crypto::random_bytes(4);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 / u32::MAX as f64
}

fn with_params(base: &str, compress: bool) -> String {
    let b = base.trim_end_matches('/');
    if b.contains('?') {
        b.to_string()
    } else if compress {
        format!("{b}/?v=10&encoding=json&compress=zlib-stream")
    } else {
        format!("{b}/?v=10&encoding=json")
    }
}

/// Work out the shards, then run one gateway thread per shard.
fn run_shards(inner: &Arc<Inner>, tx: &mpsc::Sender<Inbound>, stop: &Cancel) {
    let mut attempts = 0u32;
    let (count, ids) = loop {
        match inner.shard_plan() {
            Ok(p) => break p,
            Err(e) if e.kind == K::Auth => {
                *inner.fatal.lock().unwrap() = Some(e);
                return;
            }
            Err(_) => {
                attempts += 1;
                if !sleep_cancellable((inner.cfg.reconnect_base * 2u32.pow(attempts.min(5))).min(inner.cfg.reconnect_max), stop) {
                    return;
                }
            }
        }
    };
    inner.shard_count.store(count, Ordering::SeqCst);
    let shard = move |id: u32| (count > 1).then_some((id, count));
    let mut rest = ids.into_iter();
    let Some(first) = rest.next() else {
        *inner.fatal.lock().unwrap() = Some(ChannelError::new(K::Fatal, format!("discord: shard_ids select none of the {count} shards")));
        return;
    };
    let threads: Vec<_> = rest
        .filter_map(|id| {
            let (inner, tx, stop) = (inner.clone(), tx.clone(), stop.clone());
            std::thread::Builder::new().name(format!("discord {} shard {id}", inner.cfg.id)).spawn(move || gateway_loop(&inner, &tx, &stop, shard(id))).ok()
        })
        .collect();
    gateway_loop(inner, tx, stop, shard(first));
    for t in threads {
        let _ = t.join();
    }
}

/// One shard's connection loop; `shard` = (id, count) when sharded.
fn gateway_loop(inner: &Inner, tx: &mpsc::Sender<Inbound>, stop: &Cancel, shard: Option<(u32, u32)>) {
    let mut sess = Session::default();
    let mut attempts: u32 = 0;
    let mut resume = false;
    while !stop.is_cancelled() {
        if !resume && !inner.gate.wait(shard.map_or(0, |s| s.0), inner.cfg.identify_interval, stop) {
            return;
        }
        let base = match (resume, &sess.resume_url) {
            (true, Some(u)) => Ok(u.clone()),
            _ => inner.gateway_base(),
        };
        let outcome = match base {
            Ok(b) => run_connection(inner, tx, stop, &with_params(&b, inner.cfg.compress), &mut sess, resume, shard),
            Err(e) if e.kind == K::Auth => Outcome::Fatal(e),
            Err(_) => Outcome::Reconnect { resume: false, min_delay: Duration::ZERO, healthy: false },
        };
        let (want_resume, min_delay, healthy) = match outcome {
            Outcome::Stopped => return,
            Outcome::Fatal(e) => {
                *inner.fatal.lock().unwrap() = Some(e);
                return;
            }
            Outcome::Reconnect { resume, min_delay, healthy } => (resume, min_delay, healthy),
        };
        if healthy {
            attempts = 0;
        }
        attempts += 1;
        resume = want_resume && sess.id.is_some() && sess.seq.is_some();
        // A session that keeps failing to resume is poisoned: start over with IDENTIFY.
        if resume && sess.resume_failures >= 3 {
            sess.reset();
            resume = false;
        }
        if !resume && !want_resume {
            sess.reset();
        }
        if resume {
            sess.resume_failures += 1;
        } else {
            sess.resume_failures = 0;
        }
        let backoff = (inner.cfg.reconnect_base * 2u32.pow(attempts.min(5))).min(inner.cfg.reconnect_max);
        if !sleep_cancellable(backoff.max(min_delay), stop) {
            return;
        }
    }
}

fn send_json(ws: &mut WebSocket<ark_net::Stream>, v: &Value) -> bool {
    ws.send_text(&v.to_string()).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn run_connection(inner: &Inner, tx: &mpsc::Sender<Inbound>, stop: &Cancel, url: &str, sess: &mut Session, resume: bool, shard: Option<(u32, u32)>) -> Outcome {
    let again = |healthy| Outcome::Reconnect { resume: true, min_delay: Duration::ZERO, healthy };
    let Ok((mut ws, _)) = WebSocket::connect(url, &[], Duration::from_secs(15)) else { return again(false) };
    if ws.set_read_timeout(Some(Duration::from_millis(100))).is_err() {
        return again(false);
    }
    let mut heartbeat: Option<(Duration, Instant)> = None;
    let mut acked = true;
    let mut healthy = false;
    let mut presence_sent = 0u64;
    let mut z = inner.cfg.compress.then(zlib::ZlibStream::default);
    loop {
        if stop.is_cancelled() {
            let _ = ws.send(&Message::Close(Some((1000, "shutdown".into()))));
            return Outcome::Stopped;
        }
        if let Some((every, next)) = heartbeat {
            if Instant::now() >= next {
                if !acked {
                    // Zombie: the last heartbeat was never acknowledged.
                    let _ = ws.send(&Message::Close(Some((4000, "zombie".into()))));
                    return again(healthy);
                }
                if !send_json(&mut ws, &json!({"op": 1, "d": sess.seq})) {
                    return again(healthy);
                }
                acked = false;
                heartbeat = Some((every, Instant::now() + every));
            }
        }
        if healthy {
            let me = shard.map_or(0, |s| s.0);
            let queued: Vec<Value> = {
                let mut q = inner.gw_out.lock().unwrap();
                let (mine, rest): (Vec<Value>, Vec<Value>) = q.drain(..).partition(|v| inner.shard_of(&v["d"]["guild_id"]) == me);
                *q = rest;
                mine
            };
            for v in &queued {
                if !send_json(&mut ws, v) {
                    return again(healthy);
                }
            }
            let presence = inner.presence.lock().unwrap().clone();
            if let (true, Some(d)) = (presence.0 > presence_sent, presence.1) {
                if !send_json(&mut ws, &json!({"op": 3, "d": d})) {
                    return again(healthy);
                }
                presence_sent = presence.0;
            }
        }
        let text = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Binary(b))) => match z.as_mut().map(|z| z.push(&b)) {
                Some(Ok(Some(m))) => String::from_utf8_lossy(&m).into_owned(),
                Some(Ok(None)) => continue,
                // A corrupt stream cannot continue; a new connection starts a new zlib context.
                Some(Err(_)) => {
                    let _ = ws.send(&Message::Close(Some((4000, "zlib".into()))));
                    return again(healthy);
                }
                None => String::from_utf8_lossy(&b).into_owned(),
            },
            Ok(Some(Message::Close(c))) => {
                let code = c.map(|(c, _)| c).unwrap_or(1006);
                return match code {
                    4004 => Outcome::Fatal(ChannelError::new(K::Auth, "discord gateway: authentication failed (4004)")),
                    4011 => Outcome::Fatal(ChannelError::new(K::Fatal, "discord gateway: sharding required (4011); set `shards = \"auto\"`")),
                    4010 | 4012 => Outcome::Fatal(ChannelError::new(K::Fatal, format!("discord gateway: invalid shard or API version ({code})"))),
                    4013 | 4014 => Outcome::Fatal(ChannelError::new(K::Fatal, format!("discord gateway: invalid or disallowed intents ({code}); enable MESSAGE CONTENT INTENT in the developer portal"))),
                    4003 | 4005 | 4007 | 4009 => Outcome::Reconnect { resume: false, min_delay: Duration::ZERO, healthy },
                    _ => again(healthy),
                };
            }
            Ok(Some(_)) => continue,
            Err(_) => return again(healthy),
        };
        let Ok(p) = serde_json::from_str::<Value>(&text) else { continue };
        if let Some(s) = p["s"].as_u64() {
            sess.seq = Some(s);
        }
        match p["op"].as_u64() {
            Some(10) => {
                let every = Duration::from_millis(p["d"]["heartbeat_interval"].as_u64().unwrap_or(45_000).max(1));
                heartbeat = Some((every, Instant::now() + every.mul_f64(rand01())));
                acked = true;
                let msg = match (&sess.id, sess.seq, resume) {
                    (Some(id), Some(seq), true) => json!({"op": 6, "d": {"token": inner.cfg.token, "session_id": id, "seq": seq}}),
                    _ => {
                        let mut m = json!({"op": 2, "d": {"token": inner.cfg.token, "intents": inner.cfg.intents, "properties": {"os": std::env::consts::OS, "browser": "ark", "device": "ark"}}});
                        if let Some((id, n)) = shard {
                            m["d"]["shard"] = json!([id, n]);
                        }
                        let (version, presence) = inner.presence.lock().unwrap().clone();
                        if let Some(p) = presence {
                            m["d"]["presence"] = p;
                            presence_sent = version;
                        }
                        m
                    }
                };
                if !send_json(&mut ws, &msg) {
                    return again(healthy);
                }
            }
            Some(11) => acked = true,
            Some(1) => {
                if !send_json(&mut ws, &json!({"op": 1, "d": sess.seq})) {
                    return again(healthy);
                }
            }
            Some(7) => {
                let _ = ws.send(&Message::Close(Some((4000, "reconnect".into()))));
                return again(healthy);
            }
            Some(9) => {
                let resumable = p["d"] == true;
                if !resumable {
                    sess.reset();
                }
                let min_delay = inner.cfg.reconnect_base.mul_f64(1.0 + 4.0 * rand01());
                return Outcome::Reconnect { resume: resumable, min_delay, healthy };
            }
            Some(0) => {
                let t = p["t"].as_str().unwrap_or("");
                let d = &p["d"];
                match t {
                    "READY" => {
                        sess.id = d["session_id"].as_str().map(str::to_string);
                        sess.resume_url = d["resume_gateway_url"].as_str().filter(|u| !u.is_empty()).map(str::to_string);
                        sess.resume_failures = 0;
                        healthy = true;
                        *inner.me.lock().unwrap() = Some(Me {
                            id: d["user"]["id"].as_str().unwrap_or("").to_string(),
                            username: d["user"]["username"].as_str().unwrap_or("").to_string(),
                            app_id: d["application"]["id"].as_str().unwrap_or("").to_string(),
                        });
                        if let Some(v) = &inner.voice {
                            v.on_ready(d["user"]["id"].as_str().unwrap_or(""));
                        }
                        inner.register_commands();
                    }
                    "RESUMED" => {
                        sess.resume_failures = 0;
                        healthy = true;
                    }
                    "GUILD_CREATE" | "THREAD_LIST_SYNC" => {
                        if let (Some(v), "GUILD_CREATE") = (&inner.voice, t) {
                            v.on_guild_create(d);
                        }
                        let guild = d["guild_id"].as_str().or_else(|| d["id"].as_str()).map(str::to_string);
                        if let (Some(g), "GUILD_CREATE") = (&guild, t) {
                            for r in d["roles"].as_array().into_iter().flatten() {
                                inner.note_role(g, r);
                            }
                        }
                        let mut c = inner.chans.lock().unwrap();
                        for ch in d["channels"].as_array().into_iter().flatten().chain(d["threads"].as_array().into_iter().flatten()) {
                            if let Some(id) = ch["id"].as_str() {
                                let mut info = chan_info(ch);
                                info.guild = info.guild.or_else(|| guild.clone());
                                c.insert(id.to_string(), info);
                            }
                        }
                    }
                    "GUILD_ROLE_CREATE" | "GUILD_ROLE_UPDATE" => inner.note_role(d["guild_id"].as_str().unwrap_or(""), &d["role"]),
                    "GUILD_ROLE_DELETE" => {
                        inner.roles.lock().unwrap().remove(d["role_id"].as_str().unwrap_or(""));
                    }
                    "MESSAGE_POLL_VOTE_ADD" | "MESSAGE_POLL_VOTE_REMOVE" => {
                        if let Some(m) = poll_vote_of(inner, d, t == "MESSAGE_POLL_VOTE_ADD") {
                            let _ = tx.send(m);
                        }
                    }
                    "CHANNEL_CREATE" | "CHANNEL_UPDATE" | "THREAD_CREATE" | "THREAD_UPDATE" => {
                        if let Some(id) = d["id"].as_str() {
                            inner.chans.lock().unwrap().insert(id.to_string(), chan_info(d));
                        }
                    }
                    "MESSAGE_CREATE" | "MESSAGE_UPDATE" => {
                        if let Some(m) = inbound_of(inner, d, t == "MESSAGE_UPDATE") {
                            if !voice_command(inner, &m, d) {
                                let _ = tx.send(m);
                            }
                        }
                    }
                    "INTERACTION_CREATE" => {
                        if let Some(m) = interaction_of(inner, d) {
                            if !voice_command(inner, &m, d) {
                                let _ = tx.send(m);
                            }
                        }
                    }
                    "VOICE_STATE_UPDATE" => {
                        if let Some(v) = &inner.voice {
                            v.on_voice_state(d);
                        }
                    }
                    "VOICE_SERVER_UPDATE" => {
                        if let Some(v) = &inner.voice {
                            v.on_voice_server(d);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- inbound

/// `/voice …` in a guild is handled here (joining blocks, so on its own thread); true = consumed.
fn voice_command(inner: &Inner, m: &Inbound, d: &Value) -> bool {
    let Some(v) = &inner.voice else { return false };
    let text = m.text.trim();
    let Some(args) = text.strip_prefix("/voice").filter(|r| r.is_empty() || r.starts_with(char::is_whitespace)) else { return false };
    if m.edited || m.is_bot {
        return true;
    }
    let reply_to = m.thread.clone().unwrap_or_else(|| m.chat.clone());
    let Some(guild) = d["guild_id"].as_str().and_then(|g| g.parse::<u64>().ok()) else {
        v.post(&reply_to, "語音頻道只能在伺服器裡使用。");
        return true;
    };
    let (v, args, user) = (v.clone(), args.trim().to_string(), m.sender.parse::<u64>().unwrap_or(0));
    let binding = Binding { chat: m.chat.clone(), thread: m.thread.clone(), chat_name: m.chat_name.clone() };
    let _ = std::thread::Builder::new().name("discord /voice".into()).spawn(move || {
        let reply = v.command(guild, user, binding, &args);
        v.post(&reply_to, &reply);
    });
    true
}

fn snowflake_secs(id: &str) -> i64 {
    id.parse::<u64>().map(|n| ((n >> 22) + DISCORD_EPOCH_MS) / 1000).unwrap_or(0) as i64
}

fn media_kind(mime: &str, flags: u64) -> MediaKind {
    match mime {
        m if m.starts_with("audio/") && flags & IS_VOICE_MESSAGE != 0 => MediaKind::Voice,
        "image/gif" => MediaKind::Animation,
        m if m.starts_with("image/") => MediaKind::Image,
        m if m.starts_with("video/") => MediaKind::Video,
        m if m.starts_with("audio/") => MediaKind::Audio,
        _ => MediaKind::Document,
    }
}

fn display_name(user: &Value, member: &Value) -> String {
    member["nick"].as_str().or_else(|| user["global_name"].as_str()).or_else(|| user["username"].as_str()).unwrap_or("").to_string()
}

/// Where a message lives: (chat, thread, chat_type, chat_name).
fn place(inner: &Inner, channel_id: &str, guild: bool) -> (String, Option<String>, ChatType, String) {
    let info = inner.chan(channel_id, guild);
    match info {
        Some(c) if c.is_thread() => {
            let parent = c.parent.clone().unwrap_or_else(|| channel_id.to_string());
            let pname = inner.chans.lock().unwrap().get(&parent).map(|p| p.name.clone()).unwrap_or_default();
            (parent, Some(channel_id.to_string()), ChatType::Thread, if pname.is_empty() { c.name } else { pname })
        }
        Some(c) if c.kind == 3 => (channel_id.to_string(), None, ChatType::Group, c.name),
        Some(c) if c.kind == 5 => (channel_id.to_string(), None, ChatType::Channel, c.name),
        Some(c) if guild => (channel_id.to_string(), None, ChatType::Group, c.name),
        _ if guild => (channel_id.to_string(), None, ChatType::Group, String::new()),
        _ => (channel_id.to_string(), None, ChatType::Direct, String::new()),
    }
}

fn inbound_of(inner: &Inner, d: &Value, update: bool) -> Option<Inbound> {
    let me = inner.me.lock().unwrap().clone().unwrap_or_default();
    let author = &d["author"];
    let sender = author["id"].as_str()?.to_string();
    // POLL_RESULT: posted under the poll author's name when one of our polls ends.
    if d["type"].as_u64() == Some(46) {
        return poll_result_of(inner, d, &me);
    }
    if !me.id.is_empty() && sender == me.id {
        return None;
    }
    // System messages (joins, pins, thread created…) are not people talking. 0 = default, 19 = reply, 20 = slash command.
    if !matches!(d["type"].as_u64().unwrap_or(0), 0 | 19 | 20 | 23) {
        return None;
    }
    // A MESSAGE_UPDATE without content/edited_timestamp is an embed unfurl, not an edit.
    let edited_at = d["edited_timestamp"].as_str();
    if update && (d.get("content").is_none() || edited_at.is_none()) {
        return None;
    }
    let mid = d["id"].as_str()?.to_string();
    let channel_id = d["channel_id"].as_str()?.to_string();
    let guild_id = d["guild_id"].as_str();
    let guild = guild_id.is_some();
    let (chat, mut thread, mut chat_type, chat_name) = place(inner, &channel_id, guild);
    let flags = d["flags"].as_u64().unwrap_or(0);
    let mut media: Vec<Media> = d["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let mime = a["content_type"].as_str().unwrap_or("").to_string();
            Media {
                kind: media_kind(&mime, flags),
                url: a["url"].as_str().map(str::to_string),
                id: a["id"].as_str().map(str::to_string),
                name: a["filename"].as_str().unwrap_or("").to_string(),
                size: a["size"].as_u64().unwrap_or(0),
                caption: a["description"].as_str().map(str::to_string),
                mime,
                ..Default::default()
            }
        })
        .collect();
    for s in d["sticker_items"].as_array().into_iter().flatten() {
        if let Some(id) = s["id"].as_str() {
            media.push(Media { kind: MediaKind::Sticker, url: Some(format!("https://media.discordapp.net/stickers/{id}.png")), id: Some(id.into()), name: s["name"].as_str().unwrap_or("").to_string(), mime: "image/png".into(), ..Default::default() });
        }
    }
    let mut text = d["content"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let raw = text.clone();
    let mut mentioned = !me.id.is_empty() && (d["mentions"].as_array().into_iter().flatten().any(|u| u["id"].as_str() == Some(me.id.as_str())) || text.contains(&format!("<@{}>", me.id)) || text.contains(&format!("<@!{}>", me.id)));
    // `<@&id>` → `@role`; pinging the bot's own managed role addresses the bot.
    for rid in d["mention_roles"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if let Some(r) = inner.role(rid, guild_id) {
            mentioned |= !me.id.is_empty() && r.bot.as_deref() == Some(me.id.as_str());
            if !r.name.is_empty() {
                text = text.replace(&format!("<@&{rid}>"), &format!("@{}", r.name.trim_start_matches('@')));
            }
        }
    }
    // `<@id>` → `@name` so the model reads names, not snowflakes.
    for u in d["mentions"].as_array().into_iter().flatten() {
        if let Some(id) = u["id"].as_str() {
            let name = if id == me.id && !me.username.is_empty() { me.username.clone() } else { display_name(u, &u["member"]) };
            if !name.is_empty() {
                text = text.replace(&format!("<@{id}>"), &format!("@{name}")).replace(&format!("<@!{id}>"), &format!("@{name}"));
            }
        }
    }
    let reply = d["message_reference"]["message_id"].as_str().filter(|_| d["message_reference"]["type"].as_u64().unwrap_or(0) == 0).map(|rid| {
        let r = &d["referenced_message"];
        ReplyRef {
            id: rid.to_string(),
            text: r["content"].as_str().unwrap_or("").to_string(),
            author: r["author"]["username"].as_str().unwrap_or("").to_string(),
            is_own: !me.id.is_empty() && r["author"]["id"].as_str() == Some(me.id.as_str()),
        }
    });
    // Hermes auto_thread: a mention in a text channel gets its own thread.
    if inner.cfg.auto_thread && guild && !update && thread.is_none() && chat_type == ChatType::Group && mentioned && reply.is_none() && author["bot"] != true {
        let body = json!({"name": thread_name(&raw), "auto_archive_duration": 1440});
        if let Ok(v) = inner.rest("POST", &format!("/channels/{channel_id}/messages/{mid}/threads"), Body::Json(&body)) {
            if let Some(tid) = v["id"].as_str() {
                let mut info = chan_info(&v);
                info.parent = info.parent.or_else(|| Some(channel_id.clone()));
                inner.chans.lock().unwrap().insert(tid.to_string(), info);
                thread = Some(tid.to_string());
                chat_type = ChatType::Thread;
            }
        }
    }
    inner.remember(&mid, &channel_id);
    Some(Inbound {
        channel: inner.cfg.id.clone(),
        chat,
        chat_type,
        chat_name,
        thread,
        sender,
        sender_name: display_name(author, &d["member"]),
        is_bot: author["bot"] == true,
        text,
        message_id: match (update, edited_at) {
            (true, Some(e)) => format!("{mid}:e{e}"),
            _ => mid.clone(),
        },
        ts: snowflake_secs(&mid),
        media,
        mentioned,
        reply,
        edited: update,
        ..Default::default()
    })
}

fn command_text(data: &Value) -> String {
    let mut s = format!("/{}", data["name"].as_str().unwrap_or(""));
    fn opts(v: &Value, s: &mut String) {
        for o in v.as_array().into_iter().flatten() {
            match &o["value"] {
                Value::Null => {
                    s.push(' ');
                    s.push_str(o["name"].as_str().unwrap_or(""));
                    opts(&o["options"], s);
                }
                Value::String(x) => {
                    s.push(' ');
                    s.push_str(x);
                }
                x => {
                    s.push(' ');
                    s.push_str(&x.to_string());
                }
            }
        }
    }
    opts(&data["options"], &mut s);
    s
}

fn interaction_of(inner: &Inner, d: &Value) -> Option<Inbound> {
    let iid = d["id"].as_str()?;
    let token = d["token"].as_str()?;
    let user = if d["member"]["user"].is_object() { &d["member"]["user"] } else { &d["user"] };
    let channel_id = d["channel_id"].as_str().or_else(|| d["channel"]["id"].as_str())?.to_string();
    let guild = d["guild_id"].is_string();
    let (chat, thread, chat_type, chat_name) = place(inner, &channel_id, guild);
    let base = Inbound {
        channel: inner.cfg.id.clone(),
        chat,
        chat_type,
        chat_name,
        thread,
        sender: user["id"].as_str().unwrap_or("").to_string(),
        sender_name: display_name(user, &d["member"]),
        is_bot: user["bot"] == true,
        ts: snowflake_secs(iid),
        ..Default::default()
    };
    let msg_id = d["message"]["id"].as_str().unwrap_or("").to_string();
    if !msg_id.is_empty() {
        inner.remember(&msg_id, &channel_id);
    }
    let custom_id = d["data"]["custom_id"].as_str().unwrap_or("");
    let callback = |data: String| Inbound {
        message_id: format!("cb:{iid}"),
        callback: Some(Callback { id: format!("{iid}:{token}"), data }),
        reply: (!msg_id.is_empty()).then(|| ReplyRef { id: msg_id.clone(), is_own: true, ..Default::default() }),
        mentioned: true,
        ..base.clone()
    };
    let respond = |body: Value| {
        let _ = inner.rest("POST", &format!("/interactions/{iid}/{token}/callback"), Body::Json(&body));
    };
    match d["type"].as_u64() {
        // A modal's trigger button: answer with the modal itself (type 9) within the 3 s window.
        Some(3) if custom_id.starts_with(MODAL_PREFIX) => {
            match inner.modals.lock().unwrap().get(&custom_id[MODAL_PREFIX.len()..]) {
                Some(m) => respond(json!({"type": 9, "data": modal_json(&custom_id[MODAL_PREFIX.len()..], &m)})),
                None => respond(json!({"type": 4, "data": {"content": "這個表單已失效。", "flags": EPHEMERAL}})),
            }
            None
        }
        // MESSAGE_COMPONENT: button (2) or select (3 string, 5 user, 6 role, 7 mentionable, 8 channel);
        // the host acks via `ack_callback`.
        Some(3) => {
            let data = &d["data"];
            let kind = data["component_type"].as_u64().unwrap_or(2);
            let values: Vec<&str> = data["values"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let text = match kind {
                2 => custom_id.to_string(),
                // Our button-row selects carry the button data as the option value.
                3 if custom_id.starts_with(VALUE_SELECT) => values.join(","),
                _ => format!("{custom_id}: {}", values.iter().map(|v| resolved_name(inner, &data["resolved"], kind, v)).collect::<Vec<_>>().join(", ")),
            };
            Some(callback(text))
        }
        // MODAL_SUBMIT: the modal's callback data, then `label: value` per field.
        Some(5) => {
            let id = custom_id.strip_prefix(MODAL_PREFIX).unwrap_or(custom_id);
            let modal = inner.modals.lock().unwrap().get(id);
            let mut text = modal.as_ref().map(|m| m.data.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| id.to_string());
            for (fid, kind, vals) in modal_values(&d["data"]["components"]) {
                let label = modal.as_ref().and_then(|m| m.fields.iter().find(|f| f.id == fid)).map(|f| f.label.clone()).unwrap_or_else(|| fid.clone());
                let shown: Vec<String> = vals.iter().map(|v| resolved_name(inner, &d["data"]["resolved"], kind, v)).collect();
                text.push_str(&format!("\n{label}: {}", shown.join(", ")));
            }
            Some(callback(text))
        }
        // APPLICATION_COMMAND: must be answered within 3 s, so acknowledge now (ephemeral)
        // and deliver the command as text; the reply arrives as a normal message.
        Some(2) => {
            let text = command_text(&d["data"]);
            let _ = inner.rest("POST", &format!("/interactions/{iid}/{token}/callback"), Body::Json(&json!({"type": 4, "data": {"content": format!("✓ {text}"), "flags": EPHEMERAL}})));
            Some(Inbound { message_id: format!("ix:{iid}"), text, mentioned: true, ..base })
        }
        _ => None,
    }
}

const MODAL_PREFIX: &str = "arkm:";
const VALUE_SELECT: &str = "arkv:";

/// A selected id as a person reads it: `@user`, `@role`, `#channel` (from `resolved`).
fn resolved_name(inner: &Inner, resolved: &Value, kind: u64, v: &str) -> String {
    let user = || {
        let u = &resolved["users"][v];
        u.is_object().then(|| format!("@{}", display_name(u, &resolved["members"][v])))
    };
    let role = || resolved["roles"][v]["name"].as_str().map(|n| format!("@{n}")).or_else(|| inner.roles.lock().unwrap().get(v).map(|r| format!("@{}", r.name)));
    let chan = || resolved["channels"][v]["name"].as_str().map(|n| format!("#{n}"));
    match kind {
        5 => user(),
        6 => role(),
        7 => user().or_else(role),
        8 => chan(),
        _ => None,
    }
    .unwrap_or_else(|| v.to_string())
}

/// Submitted modal fields: (custom_id, component type, values). Legacy action rows and
/// Label (type 18) wrappers both flatten (OpenClaw `extractModalFields`).
fn modal_values(components: &Value) -> Vec<(String, u64, Vec<String>)> {
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<(String, u64, Vec<String>)>) {
        for c in v.as_array().into_iter().flatten() {
            if c["component"].is_object() {
                walk(&Value::Array(vec![c["component"].clone()]), out);
            }
            walk(&c["components"], out);
            let Some(id) = c["custom_id"].as_str() else { continue };
            let kind = c["type"].as_u64().unwrap_or(0);
            if let Some(vals) = c["values"].as_array() {
                out.push((id.to_string(), kind, vals.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()));
            } else if let Some(s) = c["value"].as_str() {
                out.push((id.to_string(), kind, vec![s.to_string()]));
            } else if let Some(b) = c["value"].as_bool() {
                out.push((id.to_string(), kind, vec![b.to_string()]));
            }
        }
    }
    walk(components, &mut out);
    out
}

/// Our poll on this message (a REST lookup once per unknown message: only polls the bot posted count).
fn poll_meta(inner: &Inner, channel: &str, message: &str) -> Option<PollMeta> {
    if let Some(p) = inner.polls.lock().unwrap().get(message) {
        return p;
    }
    let me = inner.me.lock().unwrap().clone().unwrap_or_default();
    let v = inner.rest("GET", &format!("/channels/{channel}/messages/{message}"), Body::None).ok()?;
    let meta = (!me.id.is_empty() && v["author"]["id"].as_str() == Some(me.id.as_str()) && v["poll"].is_object()).then(|| PollMeta {
        question: v["poll"]["question"]["text"].as_str().unwrap_or("").to_string(),
        answers: v["poll"]["answers"].as_array().into_iter().flatten().map(|a| (a["answer_id"].as_u64().unwrap_or(0), a["poll_media"]["text"].as_str().unwrap_or("").to_string(), None)).collect(),
    });
    inner.polls.lock().unwrap().put(message, meta.clone());
    meta
}

/// MESSAGE_POLL_VOTE_ADD/REMOVE on one of our polls → `Callback` (the answer's data, like a button).
fn poll_vote_of(inner: &Inner, d: &Value, add: bool) -> Option<Inbound> {
    let (user, channel_id, mid) = (d["user_id"].as_str()?, d["channel_id"].as_str()?, d["message_id"].as_str()?);
    let me = inner.me.lock().unwrap().clone().unwrap_or_default();
    if user == me.id {
        return None;
    }
    let answer = d["answer_id"].as_u64()?;
    let poll = poll_meta(inner, channel_id, mid)?;
    let (text, data) = poll.answers.iter().find(|a| a.0 == answer).map(|a| (a.1.clone(), a.2.clone())).unwrap_or_else(|| (format!("#{answer}"), None));
    let choice = data.unwrap_or_else(|| format!("投票：{} → {text}", poll.question));
    let (chat, thread, chat_type, chat_name) = place(inner, channel_id, d["guild_id"].is_string());
    let n = ark_net::crypto::hex(&ark_net::crypto::random_bytes(4));
    Some(Inbound {
        channel: inner.cfg.id.clone(),
        chat,
        chat_type,
        chat_name,
        thread,
        sender: user.to_string(),
        message_id: format!("pv:{mid}:{user}:{answer}:{}:{n}", if add { "+" } else { "-" }),
        ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        callback: Some(Callback { id: format!("poll:{mid}:{answer}"), data: if add { choice } else { format!("撤回{choice}") } }),
        reply: Some(ReplyRef { id: mid.to_string(), is_own: true, ..Default::default() }),
        mentioned: true,
        ..Default::default()
    })
}

/// The POLL_RESULT system message (type 46) for one of our polls → `Callback` with the outcome.
fn poll_result_of(inner: &Inner, d: &Value, me: &Me) -> Option<Inbound> {
    if me.id.is_empty() || d["author"]["id"].as_str() != Some(me.id.as_str()) {
        return None;
    }
    let e = d["embeds"].as_array()?.iter().find(|e| e["type"] == "poll_result")?;
    let field = |k: &str| e["fields"].as_array().into_iter().flatten().find(|f| f["name"] == k).and_then(|f| f["value"].as_str()).unwrap_or("").to_string();
    let poll_msg = d["message_reference"]["message_id"].as_str().unwrap_or("").to_string();
    let channel_id = d["channel_id"].as_str()?;
    let winner = field("victor_answer_text");
    let text = if winner.is_empty() {
        format!("投票結束：{}（沒有勝出選項，共 {} 票）", field("poll_question_text"), field("total_votes"))
    } else {
        format!("投票結束：{} → {winner}（{}/{} 票）", field("poll_question_text"), field("victor_answer_votes"), field("total_votes"))
    };
    let (chat, thread, chat_type, chat_name) = place(inner, channel_id, d["guild_id"].is_string());
    let mid = d["id"].as_str()?;
    Some(Inbound {
        channel: inner.cfg.id.clone(),
        chat,
        chat_type,
        chat_name,
        thread,
        sender: me.id.clone(),
        sender_name: me.username.clone(),
        message_id: format!("pr:{mid}"),
        ts: snowflake_secs(mid),
        callback: Some(Callback { id: format!("poll:{poll_msg}:end"), data: text }),
        mentioned: true,
        ..Default::default()
    })
}

/// Hermes `_derive_auto_thread_name`: mentions dropped, whitespace collapsed, ≤ 80 chars.
fn thread_name(content: &str) -> String {
    let words: Vec<&str> = content.split_whitespace().filter(|w| !((w.starts_with("<@") || w.starts_with("<#")) && w.ends_with('>'))).collect();
    let s = words.join(" ");
    match s.chars().count() {
        0 => "對話".into(),
        n if n > 80 => format!("{}...", s.chars().take(77).collect::<String>()),
        _ => s,
    }
}

/// Hermes `_derive_forum_thread_name`: the first line without leading `#`, ≤ 100 chars.
fn forum_title(text: &str) -> String {
    let first = text.trim().lines().next().unwrap_or("").trim().trim_start_matches('#').trim();
    if first.is_empty() {
        "新貼文".into()
    } else {
        first.chars().take(100).collect()
    }
}

// ---------------------------------------------------------------- components, polls

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectKind {
    #[default]
    String,
    User,
    Role,
    Mentionable,
    Channel,
}

impl SelectKind {
    fn component_type(self) -> u64 {
        match self {
            SelectKind::String => 3,
            SelectKind::User => 5,
            SelectKind::Role => 6,
            SelectKind::Mentionable => 7,
            SelectKind::Channel => 8,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct SelectOption {
    pub label: String,
    pub value: String,
    pub description: Option<String>,
    pub default: bool,
}

/// A select menu; the choice comes back as `Callback { data: "<custom_id>: <names>" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct SelectMenu {
    pub kind: SelectKind,
    pub custom_id: String,
    pub placeholder: Option<String>,
    pub min_values: Option<u32>,
    pub max_values: Option<u32>,
    pub options: Vec<SelectOption>,
    /// Channel selects: allowed channel types.
    pub channel_types: Vec<u8>,
    pub required: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    #[default]
    Short,
    Paragraph,
    Select,
    User,
    Role,
    Mentionable,
    Channel,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct ModalField {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
    pub kind: FieldKind,
    pub placeholder: Option<String>,
    pub required: Option<bool>,
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub options: Vec<SelectOption>,
    pub min_values: Option<u32>,
    pub max_values: Option<u32>,
}

/// A form; its submission comes back as `Callback { data: "<data>\n<label>: <value>…" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct Modal {
    pub title: String,
    pub data: String,
    pub fields: Vec<ModalField>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct PollAnswer {
    pub text: String,
    /// Unicode emoji or `<:name:id>`.
    pub emoji: Option<String>,
    /// Returned as the vote's `Callback::data` (default: question → answer).
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct Poll {
    pub question: String,
    pub answers: Vec<PollAnswer>,
    /// 1–768 hours (default 24).
    pub duration_hours: u32,
    pub multiselect: bool,
}

fn options_json(opts: &[SelectOption]) -> Value {
    Value::Array(
        opts.iter()
            .take(25)
            .map(|o| {
                let mut v = json!({"label": truncate_chars(&o.label, 100), "value": truncate_bytes(&o.value, 100)});
                if let Some(d) = &o.description {
                    v["description"] = json!(truncate_chars(d, 100));
                }
                if o.default {
                    v["default"] = json!(true);
                }
                v
            })
            .collect(),
    )
}

pub fn select_json(m: &SelectMenu) -> Value {
    let mut v = json!({"type": m.kind.component_type(), "custom_id": truncate_bytes(&m.custom_id, 100)});
    if m.kind == SelectKind::String {
        v["options"] = options_json(&m.options);
    }
    if let Some(p) = &m.placeholder {
        v["placeholder"] = json!(truncate_chars(p, 150));
    }
    if let Some(n) = m.min_values {
        v["min_values"] = json!(n.min(25));
    }
    if let Some(n) = m.max_values {
        v["max_values"] = json!(n.clamp(1, 25));
    }
    if m.kind == SelectKind::Channel && !m.channel_types.is_empty() {
        v["channel_types"] = json!(m.channel_types);
    }
    if let Some(r) = m.required {
        v["required"] = json!(r);
    }
    v
}

/// Modal payload (≤ 5 Label-wrapped fields: text inputs or selects).
pub fn modal_json(id: &str, m: &Modal) -> Value {
    let fields: Vec<Value> = m
        .fields
        .iter()
        .take(5)
        .map(|f| {
            let inner = match f.kind {
                FieldKind::Short | FieldKind::Paragraph => {
                    let mut t = json!({"type": 4, "custom_id": truncate_bytes(&f.id, 100), "style": if f.kind == FieldKind::Short { 1 } else { 2 }});
                    if let Some(p) = &f.placeholder {
                        t["placeholder"] = json!(truncate_chars(p, 100));
                    }
                    if let Some(n) = f.min_length {
                        t["min_length"] = json!(n.min(4000));
                    }
                    if let Some(n) = f.max_length {
                        t["max_length"] = json!(n.clamp(1, 4000));
                    }
                    if let Some(r) = f.required {
                        t["required"] = json!(r);
                    }
                    t
                }
                k => select_json(&SelectMenu {
                    kind: match k {
                        FieldKind::User => SelectKind::User,
                        FieldKind::Role => SelectKind::Role,
                        FieldKind::Mentionable => SelectKind::Mentionable,
                        FieldKind::Channel => SelectKind::Channel,
                        _ => SelectKind::String,
                    },
                    custom_id: f.id.clone(),
                    placeholder: f.placeholder.clone(),
                    min_values: f.min_values,
                    max_values: f.max_values,
                    options: f.options.clone(),
                    required: f.required,
                    ..Default::default()
                }),
            };
            let mut label = json!({"type": 18, "label": truncate_chars(&f.label, 45), "component": inner});
            if let Some(d) = &f.description {
                label["description"] = json!(truncate_chars(d, 100));
            }
            label
        })
        .collect();
    json!({"custom_id": format!("{MODAL_PREFIX}{id}"), "title": truncate_chars(&m.title, 45), "components": fields})
}

pub fn poll_json(p: &Poll) -> Value {
    let answers: Vec<Value> = p
        .answers
        .iter()
        .take(10)
        .map(|a| {
            let mut media = json!({"text": truncate_chars(&a.text, 55)});
            if let Some(e) = a.emoji.as_deref().filter(|e| !e.is_empty()) {
                let custom = e.trim_start_matches('<').trim_end_matches('>').trim_start_matches("a:").trim_start_matches(':').split_once(':').map(|(n, id)| (n.to_string(), id.to_string()));
                media["emoji"] = match custom {
                    Some((_, id)) if e.starts_with('<') => json!({"id": id}),
                    _ => json!({"name": e}),
                };
            }
            json!({"poll_media": media})
        })
        .collect();
    let hours = if p.duration_hours == 0 { 24 } else { p.duration_hours.min(768) };
    json!({"question": {"text": truncate_chars(&p.question, 300)}, "answers": answers, "duration": hours, "allow_multiselect": p.multiselect, "layout_type": 1})
}

// ---------------------------------------------------------------- outbound

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn truncate_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Rows of buttons → action rows (max 5×5). URL buttons use style 5. A row of more
/// than 5 plain buttons becomes a string select (≤ 25 options) whose values are the button data.
fn components(rows: &[Vec<Button>]) -> Value {
    Value::Array(
        rows.iter()
            .filter(|r| !r.is_empty())
            .take(5)
            .enumerate()
            .map(|(i, r)| {
                if r.len() > 5 && r.iter().all(|b| b.url.is_none()) {
                    let opts: Vec<SelectOption> = r.iter().map(|b| SelectOption { label: b.label.clone(), value: b.data.clone(), ..Default::default() }).collect();
                    return json!({"type": 1, "components": [select_json(&SelectMenu { custom_id: format!("{VALUE_SELECT}{i}"), placeholder: Some("選擇…".into()), options: opts, ..Default::default() })]});
                }
                json!({"type": 1, "components": r.iter().take(5).map(|b| match &b.url {
                    Some(u) => json!({"type": 2, "style": 5, "label": truncate_chars(&b.label, 80), "url": u}),
                    None => json!({"type": 2, "style": 2, "label": truncate_chars(&b.label, 80), "custom_id": truncate_bytes(&b.data, 100)}),
                }).collect::<Vec<_>>()})
            })
            .collect(),
    )
}

fn emoji_path(e: &str) -> String {
    // `<:name:id>` / `<a:name:id>` → `name:id`; unicode emoji percent-encoded.
    let e = e.trim().trim_start_matches('<').trim_end_matches('>');
    let e = e.strip_prefix("a:").unwrap_or(e).trim_start_matches(':');
    ark_net::urlencode(e).replace("%3A", ":")
}

impl Discord {
    fn target(&self, chat: &str, thread: Option<&str>) -> Result<String, ChannelError> {
        if let Some(t) = thread.filter(|t| !t.is_empty()) {
            return Ok(t.to_string());
        }
        let Some(user) = chat.strip_prefix("user:") else { return Ok(chat.to_string()) };
        if let Some(c) = self.inner.dms.lock().unwrap().get(user) {
            return Ok(c.clone());
        }
        let v = self.inner.rest("POST", "/users/@me/channels", Body::Json(&json!({"recipient_id": user})))?;
        let id = v["id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "open DM: no channel id"))?.to_string();
        self.inner.dms.lock().unwrap().insert(user.to_string(), id.clone());
        Ok(id)
    }

    fn located(&self, chat: &str, message_id: &str) -> Result<String, ChannelError> {
        match self.inner.locs.lock().unwrap().map.get(message_id) {
            Some(c) => Ok(c.clone()),
            None => self.target(chat, None),
        }
    }

    /// A message with select menus (one row each) and optionally a button that opens `modal`.
    pub fn send_components(&self, chat: &str, thread: Option<&str>, text: &str, selects: &[SelectMenu], modal: Option<(&str, &Modal)>) -> Result<String, ChannelError> {
        let channel = self.target(chat, thread)?;
        let mut rows: Vec<Value> = selects.iter().take(5).map(|m| json!({"type": 1, "components": [select_json(m)]})).collect();
        if let Some((label, m)) = modal {
            let id = self.register_modal(m);
            rows.truncate(4);
            rows.push(json!({"type": 1, "components": [{"type": 2, "style": 1, "label": truncate_chars(label, 80), "custom_id": format!("{MODAL_PREFIX}{id}")}]}));
        }
        let body = json!({"content": truncate_chars(&self.rewrite_roles(&channel, text), MAX_MESSAGE), "components": rows, "allowed_mentions": self.inner.cfg.mentions.allowed()});
        self.post_message(&channel, &body, vec![])
    }

    fn register_modal(&self, m: &Modal) -> String {
        let id = ark_net::crypto::hex(&ark_net::crypto::random_bytes(8));
        self.inner.modals.lock().unwrap().put(&id, m.clone());
        id
    }

    /// Answer an interaction (button/select `Callback`, before `ack_callback`) with a modal.
    pub fn open_modal(&self, cb: &Callback, m: &Modal) -> Result<(), ChannelError> {
        let (iid, token) = cb.id.split_once(':').ok_or_else(|| ChannelError::new(K::Protocol, "discord callback id is not <id>:<token>"))?;
        let id = self.register_modal(m);
        self.inner.rest("POST", &format!("/interactions/{iid}/{token}/callback"), Body::Json(&json!({"type": 9, "data": modal_json(&id, m)}))).map(|_| ())
    }

    /// A native poll; votes come back as `Callback`s carrying each answer's `data`.
    pub fn send_poll(&self, chat: &str, thread: Option<&str>, poll: &Poll) -> Result<String, ChannelError> {
        if poll.question.trim().is_empty() || poll.answers.is_empty() {
            return Err(ChannelError::new(K::Fatal, "a poll needs a question and 1–10 answers"));
        }
        let channel = self.target(chat, thread)?;
        let v = self.inner.rest("POST", &format!("/channels/{channel}/messages"), Body::Json(&json!({"poll": poll_json(poll), "allowed_mentions": {"parse": []}})))?;
        let id = v["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            self.inner.remember(&id, &channel);
            // Discord numbers answers from 1 in order; prefer the ids it echoes back.
            let echoed: Vec<u64> = v["poll"]["answers"].as_array().into_iter().flatten().filter_map(|a| a["answer_id"].as_u64()).collect();
            let answers = poll.answers.iter().take(10).enumerate().map(|(i, a)| (echoed.get(i).copied().unwrap_or(i as u64 + 1), a.text.clone(), a.data.clone())).collect();
            self.inner.polls.lock().unwrap().put(&id, Some(PollMeta { question: poll.question.clone(), answers }));
        }
        Ok(id)
    }

    /// Close a poll now (Discord then posts the result message).
    pub fn end_poll(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let c = self.located(chat, message_id)?;
        self.inner.rest("POST", &format!("/channels/{c}/polls/{message_id}/expire"), Body::None).map(|_| ())
    }

    /// User ids that voted for `answer_id` (first 100).
    pub fn poll_voters(&self, chat: &str, message_id: &str, answer_id: u64) -> Result<Vec<String>, ChannelError> {
        let c = self.located(chat, message_id)?;
        let v = self.inner.rest("GET", &format!("/channels/{c}/polls/{message_id}/answers/{answer_id}?limit=100"), Body::None)?;
        Ok(v["users"].as_array().into_iter().flatten().filter_map(|u| u["id"].as_str().map(str::to_string)).collect())
    }

    /// A thread from `from_message`, or a standalone (optionally private) one; returns its id.
    pub fn create_thread(&self, chat: &str, name: &str, from_message: Option<&str>, private: bool) -> Result<String, ChannelError> {
        let name = truncate_chars(if name.trim().is_empty() { "對話" } else { name.trim() }, 100);
        let v = match from_message {
            Some(m) => {
                let c = self.located(chat, m)?;
                self.inner.rest("POST", &format!("/channels/{c}/messages/{m}/threads"), Body::Json(&json!({"name": name, "auto_archive_duration": 1440})))?
            }
            None => {
                let c = self.target(chat, None)?;
                self.inner.rest("POST", &format!("/channels/{c}/threads"), Body::Json(&json!({"name": name, "type": if private { 12 } else { 11 }, "auto_archive_duration": 1440})))?
            }
        };
        let id = v["id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "create thread: no id"))?.to_string();
        self.inner.chans.lock().unwrap().insert(id.clone(), chan_info(&v));
        Ok(id)
    }

    /// A forum/media channel post: (thread id, starter message id).
    pub fn create_forum_post(&self, forum: &str, title: &str, text: &str, tags: &[String]) -> Result<(String, String), ChannelError> {
        let msg = json!({"content": truncate_chars(&self.rewrite_roles(forum, text), MAX_MESSAGE), "allowed_mentions": self.inner.cfg.mentions.allowed()});
        self.forum_post(forum, title, msg, tags, vec![])
    }

    fn forum_post(&self, forum: &str, title: &str, msg: Value, tags: &[String], files: Vec<(String, String, Vec<u8>)>) -> Result<(String, String), ChannelError> {
        let mut body = json!({"name": truncate_chars(title, 100), "message": msg, "auto_archive_duration": 1440});
        if !tags.is_empty() {
            body["applied_tags"] = json!(tags.iter().take(5).collect::<Vec<_>>());
        }
        let path = format!("/channels/{forum}/threads");
        let v = if files.is_empty() { self.inner.rest("POST", &path, Body::Json(&body))? } else { self.inner.rest("POST", &path, Body::Files(&body, files))? };
        let tid = v["id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "forum post: no thread id"))?.to_string();
        // The starter message shares the thread's id.
        let mid = v["message"]["id"].as_str().unwrap_or(&tid).to_string();
        let mut info = chan_info(&v);
        info.parent = info.parent.or_else(|| Some(forum.to_string()));
        self.inner.chans.lock().unwrap().insert(tid.clone(), info);
        self.inner.remember(&mid, &tid);
        Ok((tid, mid))
    }

    /// `@name` → `<@&id>` for roles that may be pinged (in the channel's guild when known).
    fn rewrite_roles(&self, channel: &str, text: &str) -> String {
        let m = &self.inner.cfg.mentions;
        if !m.roles && m.role_ids.is_empty() {
            return text.to_string();
        }
        let guild = self.inner.chans.lock().unwrap().get(channel).and_then(|c| c.guild.clone());
        let mut roles: Vec<(String, String)> = self.inner.roles.lock().unwrap().iter().filter(|(id, r)| m.role_ok(id) && **id != r.guild && !r.name.is_empty() && guild.as_ref().is_none_or(|g| *g == r.guild)).map(|(id, r)| (id.clone(), r.name.clone())).collect();
        roles.sort_by_key(|r| std::cmp::Reverse(r.1.len()));
        let mut out = text.to_string();
        for (id, name) in roles {
            let pat = format!("@{name}");
            let mut res = String::new();
            let mut rest = out.as_str();
            while let Some(i) = rest.find(&pat) {
                let after = &rest[i + pat.len()..];
                let boundary = after.chars().next().is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
                let before_ok = rest[..i].chars().last().is_none_or(|c| c != '<' && c != '&');
                res.push_str(&rest[..i]);
                res.push_str(if boundary && before_ok { format!("<@&{id}>") } else { pat.clone() }.as_str());
                rest = after;
            }
            res.push_str(rest);
            out = res;
        }
        out
    }

    pub fn post_message(&self, channel: &str, body: &Value, files: Vec<(String, String, Vec<u8>)>) -> Result<String, ChannelError> {
        let path = format!("/channels/{channel}/messages");
        let v = if files.is_empty() { self.inner.rest("POST", &path, Body::Json(body))? } else { self.inner.rest("POST", &path, Body::Files(body, files))? };
        let id = v["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            self.inner.remember(&id, channel);
        }
        Ok(id)
    }
}

impl Channel for Discord {
    fn id(&self) -> &str {
        &self.inner.cfg.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Channel, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 20,
            edit: true,
            delete: true,
            typing: true,
            buttons: true,
            polls: true,
            native_commands: self.inner.cfg.commands,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::DiscordMarkdown,
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
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.inner.fatal.lock().unwrap().clone().unwrap_or_else(|| ChannelError::new(K::Network, "discord gateway stopped"))),
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut channel = self.target(&out.chat, out.thread.as_deref())?;
        let voice = self.inner.voice.as_ref().and_then(|v| v.bound(&out.chat, out.thread.as_deref()).map(|s| (v.clone(), s.guild)));
        // URL media: images embed, everything else as a link Discord unfurls.
        let mut text = self.rewrite_roles(&channel, &out.text);
        let mut embeds = Vec::new();
        let mut uploads = Vec::new();
        for m in &out.media {
            // In a chat bound to a voice session, audio plays in the voice channel (Hermes play_tts).
            if let (Some((v, guild)), MediaKind::Audio | MediaKind::Voice, Some(p)) = (&voice, m.kind, &m.path) {
                let (v, guild, p) = (v.clone(), *guild, p.clone());
                let _ = std::thread::Builder::new().name("discord voice play".into()).spawn(move || v.play_file(guild, &p));
                continue;
            }
            match (&m.path, &m.url) {
                (Some(p), _) => {
                    let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                    let name = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
                    uploads.push((name, m.mime.clone(), data));
                }
                (None, Some(u)) if m.kind == MediaKind::Image && embeds.len() < 10 => embeds.push(json!({"image": {"url": u}})),
                (None, Some(u)) => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(u);
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            }
        }
        let mut pieces = if text.trim().is_empty() { vec![] } else { crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) };
        let mut file_batches: Vec<Vec<(String, String, Vec<u8>)>> = Vec::new();
        while !uploads.is_empty() {
            let rest = uploads.split_off(uploads.len().min(10));
            file_batches.push(std::mem::replace(&mut uploads, rest));
        }
        if pieces.is_empty() && (!file_batches.is_empty() || !embeds.is_empty() || !out.buttons.is_empty()) {
            pieces.push(String::new());
        }
        // Extra upload batches go out as their own messages after the first.
        while file_batches.len() > pieces.len() {
            pieces.push(String::new());
        }
        let n = pieces.len();
        let mut sent = Sent::default();
        let mut batches = file_batches.into_iter();
        // Forum channels take no plain messages: the first piece opens a post (Hermes `_send_to_forum`).
        let forum = self.inner.chans.lock().unwrap().get(&channel).is_some_and(|c| c.is_forum());
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut body = json!({"content": piece, "allowed_mentions": self.inner.cfg.mentions.allowed()});
            if out.silent {
                body["flags"] = json!(SUPPRESS_NOTIFICATIONS);
            }
            if i == 0 {
                if let Some(r) = out.reply_to.as_deref().filter(|r| !r.is_empty()) {
                    body["message_reference"] = json!({"message_id": r, "fail_if_not_exists": false});
                }
                if !embeds.is_empty() {
                    body["embeds"] = Value::Array(std::mem::take(&mut embeds));
                }
            }
            if i + 1 == n && !out.buttons.is_empty() {
                body["components"] = components(&out.buttons);
            }
            let files = batches.next().unwrap_or_default();
            if !files.is_empty() {
                body["attachments"] = Value::Array(files.iter().enumerate().map(|(k, (name, _, _))| json!({"id": k, "filename": name})).collect());
            }
            if forum && i == 0 {
                body.as_object_mut().unwrap().remove("message_reference");
                let (tid, mid) = self.forum_post(&channel, &forum_title(&out.text), body, &[], files)?;
                channel = tid;
                sent.ids.push(mid);
                continue;
            }
            sent.ids.push(self.post_message(&channel, &body, files)?);
        }
        if let (Some((v, _)), Some(id)) = (&voice, sent.first()) {
            v.reply(&out.chat, out.thread.as_deref(), id, &out.text);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        if let Some(v) = &self.inner.voice {
            v.edited(message_id, text);
        }
        let c = self.located(chat, message_id)?;
        let body = json!({"content": truncate_chars(text, MAX_MESSAGE)});
        self.inner.rest("PATCH", &format!("/channels/{c}/messages/{message_id}"), Body::Json(&body)).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let c = self.located(chat, message_id)?;
        self.inner.rest("DELETE", &format!("/channels/{c}/messages/{message_id}"), Body::None).map(|_| ())
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let c = self.target(chat, thread)?;
        self.inner.rest("POST", &format!("/channels/{c}/typing"), Body::None).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let c = self.located(chat, message_id)?;
        let path = format!("/channels/{c}/messages/{message_id}/reactions/{}/@me", emoji_path(emoji));
        self.inner.rest(if remove { "DELETE" } else { "PUT" }, &path, Body::None).map(|_| ())
    }

    /// Type 6 (deferred update: stops the button spinner) or, with text, an ephemeral reply.
    fn ack_callback(&self, cb: &Callback, text: Option<&str>) -> Result<(), ChannelError> {
        // Poll votes and results are gateway events, not interactions.
        if cb.id.starts_with("poll:") {
            return Ok(());
        }
        let (iid, token) = cb.id.split_once(':').ok_or_else(|| ChannelError::new(K::Protocol, "discord callback id is not <id>:<token>"))?;
        let body = match text {
            Some(t) => json!({"type": 4, "data": {"content": truncate_chars(t, MAX_MESSAGE), "flags": EPHEMERAL}}),
            None => json!({"type": 6}),
        };
        self.inner.rest("POST", &format!("/interactions/{iid}/{token}/callback"), Body::Json(&body)).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "discord attachment without url"))?;
        crate::http::get_bytes(u, &[], 100 * 1024 * 1024)
    }

    fn message_action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
        self.action(action, args)
    }

    fn message_actions(&self) -> Vec<&'static str> {
        actions::ACTIONS.to_vec()
    }

    fn tools(&self) -> Vec<Arc<dyn ark_core::Tool>> {
        tools::tools(&self.inner)
    }

    fn stop(&self) {
        self.stop.cancel();
        if let Some(v) = &self.inner.voice {
            v.shutdown();
        }
    }
}

// ---------------------------------------------------------------- config

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    token: String,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    gateway_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Override the Identify intents bitfield.
    #[serde(default)]
    intents: Option<u64>,
    /// Register /new /stop /status /help as slash commands.
    #[serde(default)]
    commands: bool,
    #[serde(default)]
    command_guild: Option<String>,
    /// Join voice channels with `/voice join` (needs ffmpeg with libopus).
    #[serde(default)]
    voice: bool,
    /// OpenAI-compatible speech-to-text for voice channels.
    #[serde(default)]
    stt: Option<discord_voice::Speech>,
    /// OpenAI-compatible text-to-speech for spoken replies.
    #[serde(default)]
    tts: Option<discord_voice::Speech>,
    #[serde(default)]
    ffmpeg: Option<String>,
    /// Leave a voice channel after this many idle seconds (0 = never; default 300).
    #[serde(default)]
    voice_idle_secs: Option<u64>,
    /// Echo transcripts into the bound text channel (default true).
    #[serde(default)]
    voice_echo: Option<bool>,
    /// Keep the DAVE signature key in the state dir (0600) so pairwise codes stay stable (default true).
    #[serde(default)]
    dave_persistent_key: Option<bool>,
    /// zlib-stream gateway compression.
    #[serde(default)]
    compress: bool,
    /// Shard count or `"auto"`.
    #[serde(default)]
    shards: Option<ShardSetting>,
    #[serde(default)]
    shard_ids: Option<Vec<u32>>,
    #[serde(default)]
    max_concurrency: Option<u32>,
    /// Answer mentions in text channels inside a new thread.
    #[serde(default)]
    auto_thread: bool,
    #[serde(default)]
    allow_mentions: Option<Mentions>,
    /// Actions the `discord` / `discord_admin` tools may use (default: all).
    #[serde(default)]
    server_actions: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ShardSetting {
    Count(u32),
    Name(String),
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let mut cfg = Config::new(ctx.name, &token);
    if let Some(a) = st.api_base {
        cfg.api_base = a;
    }
    cfg.gateway_url = st.gateway_url;
    cfg.poll_timeout_secs = st.poll_timeout_secs;
    cfg.intents = st.intents.unwrap_or(DEFAULT_INTENTS);
    cfg.commands = st.commands;
    cfg.command_guild = st.command_guild;
    cfg.compress = st.compress;
    cfg.shards = match st.shards {
        None => Shards::Count(1),
        Some(ShardSetting::Count(n)) if n >= 1 => Shards::Count(n),
        Some(ShardSetting::Name(a)) if a == "auto" => Shards::Auto,
        Some(_) => return Err(format!("[channels.{}]: shards must be a positive number or \"auto\"", ctx.name)),
    };
    cfg.shard_ids = st.shard_ids;
    cfg.max_concurrency = st.max_concurrency.filter(|n| *n > 0);
    cfg.auto_thread = st.auto_thread;
    cfg.mentions = st.allow_mentions.unwrap_or_default();
    cfg.server_actions = st.server_actions;
    if st.voice {
        let mut v = VoiceConfig::default();
        let resolve = |field: &str, sp: Option<discord_voice::Speech>| -> Result<Option<discord_voice::Speech>, String> {
            sp.map(|mut sp| {
                sp.key = ctx.opt_secret(field, &sp.key)?;
                Ok(sp)
            })
            .transpose()
        };
        v.stt = resolve("stt.key", st.stt)?;
        v.tts = resolve("tts.key", st.tts)?;
        if let Some(f) = st.ffmpeg {
            v.ffmpeg = f;
        }
        if let Some(i) = st.voice_idle_secs {
            v.idle = Duration::from_secs(i);
        }
        if let Some(e) = st.voice_echo {
            v.echo = e;
        }
        if st.dave_persistent_key.unwrap_or(true) {
            let path = ctx.state_dir.join(format!("{}.dave-signature.jwk", ctx.name));
            v.dave_signer = Some(Arc::new(crate::dave::load_or_create_signer(&path).map_err(|e| format!("[channels.{}]: DAVE key: {e}", ctx.name))?));
        }
        cfg.voice = Some(v);
    } else if st.stt.is_some() || st.tts.is_some() {
        return Err(format!("[channels.{}]: stt/tts need `voice = true`", ctx.name));
    }
    Ok(Arc::new(Discord::new(cfg)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use ark_net::ws::read_head;
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;

    /// A scripted gateway: `script(connection_index, request_head, socket)` per connection.
    fn gateway(script: impl Fn(usize, String, Ws) + Send + Sync + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let script = Arc::new(script);
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let script = script.clone();
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let Ok((head, rest)) = read_head(&mut s, 65536) else { return };
                    let ws = WebSocket::accept(s, &head, rest).unwrap();
                    script(n, head, ws);
                });
            }
        });
        url
    }

    fn send(ws: &mut Ws, v: Value) {
        ws.send_text(&v.to_string()).unwrap();
    }

    fn hello(ws: &mut Ws, ms: u64) {
        send(ws, json!({"op": 10, "d": {"heartbeat_interval": ms}, "s": null}));
    }

    fn dispatch(ws: &mut Ws, s: u64, t: &str, d: Value) {
        send(ws, json!({"op": 0, "s": s, "t": t, "d": d}));
    }

    /// Next payload with `op` (heartbeats are acknowledged when `ack`).
    fn expect(ws: &mut Ws, op: u64, ack: bool) -> Value {
        loop {
            let Message::Text(t) = ws.recv_blocking().expect("gateway message") else { continue };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["op"] == op {
                return v;
            }
            if v["op"] == 1 && ack {
                send(ws, json!({"op": 11}));
            }
        }
    }

    /// Keep acknowledging heartbeats until the client goes away.
    fn idle(ws: &mut Ws) {
        while let Ok(m) = ws.recv_blocking() {
            if matches!(m, Message::Close(_)) {
                return;
            }
            if let Message::Text(t) = m {
                if t.contains("\"op\":1") {
                    send(ws, json!({"op": 11}));
                }
            }
        }
    }

    fn ready(ws: &mut Ws, s: u64, resume_url: &str) {
        dispatch(ws, s, "READY", json!({"v": 10, "session_id": "S1", "resume_gateway_url": resume_url, "user": {"id": "B", "username": "ark", "bot": true}, "application": {"id": "APP"}, "guilds": []}));
    }

    fn cfg(api: &str, gw: Option<&str>) -> Config {
        let mut c = Config::new("dc", "TOKEN");
        c.api_base = api.into();
        c.gateway_url = gw.map(str::to_string);
        c.poll_timeout_secs = 1;
        c.retry_base = Duration::from_millis(5);
        c.reconnect_base = Duration::from_millis(5);
        c.identify_interval = Duration::from_millis(10);
        c
    }

    fn collect(d: &Discord, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(8);
        while got.len() < n && Instant::now() < until {
            got.extend(d.poll(&Cancel::new()).unwrap());
        }
        got
    }

    fn msg(id: &str, channel: &str, guild: bool, author: Value, content: &str) -> Value {
        let mut m = json!({"id": id, "type": 0, "channel_id": channel, "author": author, "content": content, "mentions": [], "attachments": []});
        if guild {
            m["guild_id"] = json!("G");
        }
        m
    }

    fn amy() -> Value {
        json!({"id": "U1", "username": "amy", "global_name": "Amy"})
    }

    #[test]
    fn gateway_identify_and_every_inbound_kind() {
        let (idtx, idrx) = mpsc::channel();
        let idtx = Mutex::new(idtx);
        let gw = gateway(move |_, head, mut ws| {
            idtx.lock().unwrap().send(head.lines().next().unwrap().to_string()).unwrap();
            hello(&mut ws, 45_000);
            let ident = expect(&mut ws, 2, true);
            idtx.lock().unwrap().send(ident.to_string()).unwrap();
            ready(&mut ws, 1, "ws://unused");
            dispatch(&mut ws, 2, "GUILD_CREATE", json!({"id": "G", "channels": [{"id": "C1", "type": 0, "name": "general"}], "threads": [{"id": "T1", "type": 11, "parent_id": "C1", "name": "topic"}]}));
            let events = [
                ("MESSAGE_CREATE", msg("175928847299117063", "D1", false, amy(), "hi")),
                ("MESSAGE_CREATE", json!({"id": "2", "type": 0, "channel_id": "C1", "guild_id": "G", "author": amy(), "member": {"nick": "Ames"}, "content": "<@B> do it, cc <@!U9>", "mentions": [{"id": "B", "username": "ark"}, {"id": "U9", "username": "bob"}]})),
                ("MESSAGE_CREATE", json!({"id": "3", "type": 19, "channel_id": "C1", "guild_id": "G", "author": amy(), "content": "yes", "message_reference": {"message_id": "M0", "channel_id": "C1"}, "referenced_message": {"id": "M0", "author": {"id": "B", "username": "ark"}, "content": "shall I?"}})),
                ("MESSAGE_CREATE", msg("4", "T1", true, amy(), "in thread")),
                ("MESSAGE_CREATE", msg("5", "T2", true, amy(), "in unknown thread")),
                ("MESSAGE_CREATE", json!({"id": "6", "type": 0, "channel_id": "D1", "author": amy(), "content": "", "attachments": [{"id": "A1", "filename": "a.png", "content_type": "image/png", "size": 12, "url": "https://cdn.discordapp.com/a.png"}, {"id": "A2", "filename": "v.ogg", "content_type": "audio/ogg", "url": "https://cdn/v.ogg"}], "flags": 8192})),
                ("MESSAGE_CREATE", msg("7", "C1", true, json!({"id": "B", "username": "ark", "bot": true}), "my own echo")),
                ("MESSAGE_CREATE", msg("8", "C1", true, json!({"id": "X", "username": "otherbot", "bot": true}), "beep")),
                ("MESSAGE_UPDATE", json!({"id": "2", "type": 0, "channel_id": "C1", "guild_id": "G", "author": amy(), "content": "edited", "edited_timestamp": "2026-01-01T00:00:00Z", "mentions": []})),
                ("MESSAGE_UPDATE", json!({"id": "2", "channel_id": "C1", "guild_id": "G", "embeds": []})),
                ("MESSAGE_CREATE", json!({"id": "9", "type": 7, "channel_id": "C1", "guild_id": "G", "author": amy(), "content": ""})),
                ("INTERACTION_CREATE", json!({"id": "I1", "token": "TOK", "type": 3, "channel_id": "T1", "guild_id": "G", "member": {"user": {"id": "U1", "username": "amy"}}, "message": {"id": "M5"}, "data": {"custom_id": "appr:1:once", "component_type": 2}})),
            ];
            for (i, (t, d)) in events.into_iter().enumerate() {
                dispatch(&mut ws, 3 + i as u64, t, d);
            }
            idle(&mut ws);
        });
        // GET /gateway/bot on the fake API returns our gateway.
        let gw2 = gw.clone();
        let http2 = FakeServer::start(move |req, _| match req.path.as_str() {
            "/gateway/bot" => (200, vec![], json!({"url": gw2, "shards": 1}).to_string()),
            p if p.starts_with("/channels/T2") => (200, vec![], json!({"id": "T2", "type": 12, "parent_id": "C1", "name": "secret"}).to_string()),
            _ => (200, vec![], json!({"id": "R"}).to_string()),
        });
        let d = Discord::new(cfg(&http2.url, None)).unwrap();
        let g = collect(&d, 9);
        assert!(idrx.recv().unwrap().starts_with("GET /?v=10&encoding=json "), "gateway params");
        let ident: Value = serde_json::from_str(&idrx.recv().unwrap()).unwrap();
        assert_eq!(ident["d"]["token"], "TOKEN");
        let intents = ident["d"]["intents"].as_u64().unwrap();
        assert!(intents & (1 << 15) != 0 && intents & (1 << 9) != 0 && intents & (1 << 12) != 0, "MESSAGE_CONTENT, GUILD_MESSAGES, DIRECT_MESSAGES");
        assert_eq!(http2.requests()[0].path, "/gateway/bot");
        assert_eq!(http2.requests()[0].header("authorization"), Some("Bot TOKEN"));
        assert_eq!(g.len(), 9, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].ts), ("D1", ChatType::Direct, "U1", "Amy", 1462015105));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group && g[1].chat_name == "general" && g[1].sender_name == "Ames");
        assert_eq!(g[1].text, "@ark do it, cc @bob");
        let r = g[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "M0" && r.text == "shall I?" && !g[2].mentioned && g[2].addressed());
        assert_eq!((g[3].chat.as_str(), g[3].thread.as_deref(), g[3].chat_type, g[3].chat_name.as_str()), ("C1", Some("T1"), ChatType::Thread, "general"));
        assert_eq!((g[4].chat.as_str(), g[4].thread.as_deref()), ("C1", Some("T2")), "thread resolved over REST");
        assert!(http2.requests().iter().any(|r| r.path == "/channels/T2"));
        assert_eq!((g[5].media[0].kind, g[5].media[0].url.as_deref(), g[5].media[0].name.as_str()), (MediaKind::Image, Some("https://cdn.discordapp.com/a.png"), "a.png"));
        assert_eq!(g[5].media[1].kind, MediaKind::Voice);
        assert!(g[6].is_bot && g[6].text == "beep", "other bots kept and flagged, own dropped");
        assert!(g[7].edited && g[7].message_id == "2:e2026-01-01T00:00:00Z" && g[7].text == "edited");
        let cb = g[8].callback.as_ref().unwrap();
        assert_eq!((cb.id.as_str(), cb.data.as_str(), g[8].thread.as_deref()), ("I1:TOK", "appr:1:once", Some("T1")));
        // The thread message is reacted to in its thread channel, not the parent.
        d.react("C1", "4", "👍", false).unwrap();
        assert_eq!(http2.requests().last().unwrap().path, "/channels/T1/messages/4/reactions/%F0%9F%91%8D/@me");
        d.stop();
    }

    #[test]
    fn heartbeat_zombie_resume_reconnect_and_invalid_session() {
        let (tx, rx) = mpsc::channel::<String>();
        let tx = Mutex::new(tx);
        let base = Arc::new(Mutex::new(String::new()));
        let b2 = base.clone();
        let gw = gateway(move |n, head, mut ws| {
            let log = |s: String| tx.lock().unwrap().send(s).unwrap();
            log(format!("conn{n} {}", head.split_whitespace().nth(1).unwrap()));
            hello(&mut ws, 150);
            match n {
                0 => {
                    expect(&mut ws, 2, false);
                    log("identify".into());
                    ready(&mut ws, 1, &format!("{}/resume", b2.lock().unwrap()));
                    dispatch(&mut ws, 2, "MESSAGE_CREATE", msg("10", "D1", false, amy(), "first"));
                    let hb = expect(&mut ws, 1, false);
                    log(format!("hb {}", hb["d"]));
                    // Never ACK: the client must notice the zombie and leave.
                    while ws.recv_blocking().is_ok() {}
                    log("zombie dropped".into());
                }
                1 => {
                    let r = expect(&mut ws, 6, true);
                    log(format!("resume {} {}", r["d"]["session_id"], r["d"]["seq"]));
                    dispatch(&mut ws, 3, "RESUMED", json!({}));
                    send(&mut ws, json!({"op": 7, "d": null}));
                    idle(&mut ws);
                }
                2 => {
                    let r = expect(&mut ws, 6, true);
                    log(format!("resume {}", r["d"]["seq"]));
                    send(&mut ws, json!({"op": 9, "d": false}));
                    idle(&mut ws);
                }
                _ => {
                    expect(&mut ws, 2, true);
                    log("identify".into());
                    ready(&mut ws, 1, "ws://unused");
                    dispatch(&mut ws, 2, "MESSAGE_CREATE", msg("11", "D1", false, amy(), "after"));
                    idle(&mut ws);
                }
            }
        });
        *base.lock().unwrap() = gw.clone();
        let d = Discord::new(cfg("http://127.0.0.1:1", Some(&gw))).unwrap();
        let g = collect(&d, 2);
        assert_eq!(g.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["first", "after"]);
        d.stop();
        let log: Vec<String> = rx.try_iter().collect();
        let want = ["conn0 /?v=10&encoding=json", "identify", "hb 2", "zombie dropped", "conn1 /resume/?v=10&encoding=json", "resume \"S1\" 2", "conn2 /resume/?v=10&encoding=json", "resume 3", "conn3 /?v=10&encoding=json", "identify"];
        let mut it = log.iter();
        for w in want {
            assert!(it.any(|l| l == w), "missing {w:?} in order: {log:#?}");
        }
    }

    #[test]
    fn dropped_socket_resumes_and_auth_close_is_fatal() {
        let (tx, rx) = mpsc::channel::<Value>();
        let tx = Mutex::new(tx);
        let gw = gateway(move |n, _, mut ws| {
            hello(&mut ws, 45_000);
            if n == 0 {
                expect(&mut ws, 2, true);
                ready(&mut ws, 1, "");
                dispatch(&mut ws, 2, "MESSAGE_CREATE", msg("10", "D1", false, amy(), "before drop"));
                std::thread::sleep(Duration::from_millis(100));
                // Abrupt TCP close, no close frame.
                ws.get_ref().shutdown(std::net::Shutdown::Both).unwrap();
            } else {
                tx.lock().unwrap().send(expect(&mut ws, 6, true)).unwrap();
                ws.send(&Message::Close(Some((4004, "Authentication failed".into())))).unwrap();
            }
        });
        let d = Discord::new(cfg("http://127.0.0.1:1", Some(&gw))).unwrap();
        assert_eq!(collect(&d, 1)[0].text, "before drop");
        let until = Instant::now() + Duration::from_secs(5);
        let err = loop {
            match d.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no fatal error"),
                Ok(_) => {}
            }
        };
        assert_eq!(err.kind, K::Auth);
        assert!(!err.message.contains("TOKEN"));
        let r = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!((r["d"]["session_id"].as_str(), r["d"]["seq"].as_u64()), (Some("S1"), Some(2)), "resumed after the drop");
        // The bad token also surfaces from GET /gateway/bot.
        let http = FakeServer::start(|_, _| (401, vec![], json!({"message": "401: Unauthorized", "code": 0}).to_string()));
        let d = Discord::new(cfg(&http.url, None)).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let e = loop {
            match d.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) if Instant::now() > until => panic!("no auth error"),
                Ok(_) => {}
            }
        };
        assert_eq!(e.kind, K::Auth);
    }

    #[test]
    fn cancel_returns_promptly_from_a_blocked_poll() {
        // Accepts TCP but never answers the upgrade.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let mut c = cfg("http://127.0.0.1:1", Some(&url));
        c.poll_timeout_secs = 20;
        let d = Discord::new(c).unwrap();
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(d.poll(&cancel).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
    }

    #[test]
    fn send_shapes_uploads_dm_and_actions() {
        let srv = FakeServer::start(|req, n| match req.path.as_str() {
            "/users/@me/channels" => (200, vec![], json!({"id": "DM9", "type": 1}).to_string()),
            "/file.bin" => (200, vec![], "BYTES".into()),
            p if p.ends_with("/typing") || p.contains("/reactions/") || p.contains("/callback") || req.method == "DELETE" => (204, vec![], String::new()),
            _ => (200, vec![], json!({"id": format!("M{n}")}).to_string()),
        });
        let d = Discord::new(cfg(&srv.url, None)).unwrap();
        let out = Outbound {
            format: crate::TextFormat::Markdown,
            reply_to: Some("77".into()),
            silent: true,
            buttons: vec![vec![Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("C1", "**bold** <@123>")
        };
        assert_eq!(d.send(&out).unwrap().ids, ["M0"]);
        let r = &srv.requests()[0];
        assert_eq!((r.method.as_str(), r.path.as_str(), r.header("authorization")), ("POST", "/channels/C1/messages", Some("Bot TOKEN")));
        let b = r.json();
        assert_eq!(b["content"], "**bold** <@123>");
        assert_eq!((b["message_reference"]["message_id"].as_str(), b["flags"].as_u64()), (Some("77"), Some(4096)));
        assert_eq!(b["allowed_mentions"]["parse"], json!(["users"]));
        assert_eq!(b["components"][0]["type"], 1);
        assert_eq!((b["components"][0]["components"][0]["custom_id"].as_str(), b["components"][0]["components"][0]["style"].as_u64()), (Some("appr:x:once"), Some(2)));
        assert_eq!((b["components"][0]["components"][1]["url"].as_str(), b["components"][0]["components"][1]["style"].as_u64()), (Some("https://e.com"), Some(5)));
        // Long text: 2000-char chunks, reply on the first, buttons on the last; thread target.
        let long = "x".repeat(4500);
        let s = d.send(&Outbound { thread: Some("T1".into()), reply_to: Some("5".into()), buttons: out.buttons.clone(), ..Outbound::text("C1", &long) }).unwrap();
        assert_eq!(s.ids.len(), 3);
        let reqs = srv.requests();
        assert!(reqs[1..4].iter().all(|r| r.path == "/channels/T1/messages"));
        assert!(reqs[1..4].iter().all(|r| r.json()["content"].as_str().unwrap().chars().count() <= MAX_MESSAGE));
        assert!(reqs[1].json().get("message_reference").is_some() && reqs[2].json().get("message_reference").is_none());
        assert!(reqs[1].json().get("components").is_none() && reqs[3].json().get("components").is_some());
        // Local file → multipart payload_json + files[0]; image URL → embed.
        let f = temp_dir("dc").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let media = vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() }, Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() }];
        d.send(&Outbound { media, ..Outbound::text("C1", "see attached") }).unwrap();
        let r = &srv.requests()[4];
        assert!(r.header("content-type").unwrap().starts_with("multipart/form-data"));
        assert!(r.body.contains("name=\"payload_json\"") && r.body.contains("name=\"files[0]\"; filename=\"report.pdf\"") && r.body.contains("%PDF-1"), "{}", r.body);
        assert!(r.body.contains(r#""attachments":[{"filename":"report.pdf","id":0}]"#) && r.body.contains(r#""embeds":[{"image":{"url":"https://e.com/a.png"}}]"#) && r.body.contains("see attached"), "{}", r.body);
        // DM by user id opens (and caches) the DM channel.
        d.send(&Outbound::text("user:42", "psst")).unwrap();
        d.send(&Outbound::text("user:42", "again")).unwrap();
        let paths: Vec<String> = srv.requests()[5..].iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, ["/users/@me/channels", "/channels/DM9/messages", "/channels/DM9/messages"]);
        assert_eq!(srv.requests()[5].json()["recipient_id"], "42");
        // Actions.
        let start = srv.requests().len();
        d.edit("C1", "M0", "new").unwrap();
        d.delete("C1", "M0").unwrap();
        d.typing("C1", Some("T1")).unwrap();
        d.react("C1", "M0", "👍", false).unwrap();
        d.react("C1", "M0", "<:party:123>", true).unwrap();
        d.ack_callback(&Callback { id: "I1:TOK".into(), data: String::new() }, None).unwrap();
        d.ack_callback(&Callback { id: "I2:TOK2".into(), data: String::new() }, Some("done")).unwrap();
        let got: Vec<(String, String)> = srv.requests()[start..].iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        let want = [
            ("PATCH", "/channels/C1/messages/M0"),
            ("DELETE", "/channels/C1/messages/M0"),
            ("POST", "/channels/T1/typing"),
            ("PUT", "/channels/C1/messages/M0/reactions/%F0%9F%91%8D/@me"),
            ("DELETE", "/channels/C1/messages/M0/reactions/party:123/@me"),
            ("POST", "/interactions/I1/TOK/callback"),
            ("POST", "/interactions/I2/TOK2/callback"),
        ];
        assert_eq!(got, want.map(|(a, b)| (a.to_string(), b.to_string())));
        assert_eq!(srv.requests()[start].json()["content"], "new");
        assert_eq!(srv.requests()[start + 5].json(), json!({"type": 6}));
        assert_eq!(srv.requests()[start + 6].json(), json!({"type": 4, "data": {"content": "done", "flags": 64}}));
        let bytes = d.fetch_media(&Media { url: Some(format!("{}/file.bin", srv.url)), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"BYTES");
        assert_eq!(d.caps().max_len, 2000);
    }

    #[test]
    fn rate_limits_buckets_and_error_mapping() {
        // 429 with retry_after in the JSON body, then success.
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![("retry-after".into(), "9".into())], json!({"message": "You are being rate limited.", "retry_after": 0.3, "global": false}).to_string()),
            1 => (200, vec![("x-ratelimit-remaining".into(), "0".into()), ("x-ratelimit-reset-after".into(), "0.3".into())], json!({"id": "1"}).to_string()),
            _ => (200, vec![], json!({"id": "2"}).to_string()),
        });
        let d = Discord::new(cfg(&srv.url, None)).unwrap();
        let t = Instant::now();
        d.send(&Outbound::text("C1", "x")).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(290) && t.elapsed() < Duration::from_secs(5), "body retry_after (0.3 s) beats the header (9 s): {:?}", t.elapsed());
        let t = Instant::now();
        d.send(&Outbound::text("C1", "y")).unwrap();
        assert!(t.elapsed() >= Duration::from_millis(280), "exhausted bucket waited for reset: {:?}", t.elapsed());
        assert_eq!(srv.requests().len(), 3);
        // Long waits surface instead of blocking.
        let srv = FakeServer::start(|_, _| (429, vec![], json!({"retry_after": 3600.0, "global": true}).to_string()));
        let d = Discord::new(cfg(&srv.url, None)).unwrap();
        let e = d.send(&Outbound::text("C1", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        let e = d.typing("C2", None).unwrap_err();
        assert!(matches!(e.kind, K::RateLimited { .. }), "global limit blocks other routes too");
        assert_eq!(srv.requests().len(), 1);
        for (status, code, kind) in [(401, 0, K::Auth), (404, 10003, K::NotFound), (404, 10008, K::NotFound), (403, 50001, K::NotFound), (400, 50007, K::NotFound), (400, 50035, K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"message": "nope", "code": code}).to_string()));
            let d = Discord::new(cfg(&srv.url, None)).unwrap();
            let e = d.send(&Outbound::text("C1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {code}");
            assert!(!e.message.contains("TOKEN"), "{}", e.message);
            assert_eq!(srv.requests().len(), 1, "{status} not retried");
        }
        let srv = FakeServer::start(|_, _| (502, vec![], "<html>bad gateway</html>".into()));
        let d = Discord::new(cfg(&srv.url, None)).unwrap();
        assert_eq!(d.send(&Outbound::text("C1", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len(), 5, "1 + max_retries");
    }

    #[test]
    fn slash_commands_registered_and_dispatched() {
        let srv = FakeServer::start(|_, _| (200, vec![], "[]".into()));
        let gw = gateway(|_, _, mut ws| {
            hello(&mut ws, 45_000);
            expect(&mut ws, 2, true);
            ready(&mut ws, 1, "");
            dispatch(&mut ws, 2, "INTERACTION_CREATE", json!({"id": "I2", "token": "T2", "type": 2, "channel_id": "D1", "user": {"id": "U1", "username": "amy"}, "data": {"name": "status", "options": [{"name": "verbose", "type": 5, "value": true}]}}));
            idle(&mut ws);
        });
        let mut c = cfg(&srv.url, Some(&gw));
        c.commands = true;
        let d = Discord::new(c).unwrap();
        assert!(d.caps().native_commands);
        let g = collect(&d, 1);
        assert_eq!((g[0].text.as_str(), g[0].chat.as_str(), g[0].chat_type, g[0].message_id.as_str()), ("/status true", "D1", ChatType::Direct, "ix:I2"));
        let reqs = srv.requests();
        assert_eq!((reqs[0].method.as_str(), reqs[0].path.as_str()), ("PUT", "/applications/APP/commands"));
        let cmds = reqs[0].json();
        let names: Vec<&str> = cmds.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["new", "stop", "status", "help"]);
        assert_eq!(reqs[1].path, "/interactions/I2/T2/callback");
        assert_eq!(reqs[1].json()["type"], 4, "answered within the 3 s window");
        d.stop();
    }

    /// `/voice join` from a guild text channel → gateway op 4 → voice connection; the human's
    /// speech comes back as an Inbound in that channel, the reply is spoken, `/voice leave` leaves.
    #[test]
    fn voice_join_transcribe_reply_and_leave() {
        use crate::discord_voice::tests::{fake_voice, have_ffmpeg, speech_server};
        if !have_ffmpeg() {
            eprintln!("ffmpeg missing; skipped");
            return;
        }
        let fv = fake_voice(vec!["aead_aes256_gcm_rtpsize"], false);
        let (speech_url, seen) = speech_server();
        let vurl = fv.url.clone();
        let (gtx, grx) = mpsc::channel::<Value>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (gtx, go_rx) = (Mutex::new(gtx), Mutex::new(go_rx));
        let gw = gateway(move |_, _, mut ws| {
            hello(&mut ws, 45_000);
            gtx.lock().unwrap().send(expect(&mut ws, 2, true)).unwrap();
            dispatch(&mut ws, 1, "READY", json!({"v": 10, "session_id": "S1", "user": {"id": "1", "username": "ark", "bot": true}, "application": {"id": "APP"}, "guilds": []}));
            dispatch(&mut ws, 2, "GUILD_CREATE", json!({"id": "5", "channels": [{"id": "C1", "type": 0, "name": "general"}, {"id": "999", "type": 2, "name": "Lounge"}], "voice_states": [{"user_id": "77", "channel_id": "999", "member": {"nick": "Amy"}}]}));
            dispatch(&mut ws, 3, "MESSAGE_CREATE", json!({"id": "10", "type": 0, "channel_id": "C1", "guild_id": "5", "author": {"id": "77", "username": "amy"}, "content": "/voice join", "mentions": []}));
            gtx.lock().unwrap().send(expect(&mut ws, 4, true)).unwrap();
            dispatch(&mut ws, 4, "VOICE_STATE_UPDATE", json!({"guild_id": "5", "user_id": "1", "channel_id": "999", "session_id": "VSESS"}));
            dispatch(&mut ws, 5, "VOICE_SERVER_UPDATE", json!({"guild_id": "5", "token": "VTOKEN", "endpoint": vurl}));
            go_rx.lock().unwrap().recv().unwrap();
            dispatch(&mut ws, 6, "MESSAGE_CREATE", json!({"id": "11", "type": 0, "channel_id": "C1", "guild_id": "5", "author": {"id": "77", "username": "amy"}, "content": "/voice leave", "mentions": []}));
            gtx.lock().unwrap().send(expect(&mut ws, 4, true)).unwrap();
            idle(&mut ws);
        });
        let srv = FakeServer::start(|_, n| (200, vec![], json!({"id": format!("M{n}")}).to_string()));
        let mut c = cfg(&srv.url, Some(&gw));
        let speech = discord_voice::Speech { url: speech_url, format: Some("wav".into()), ..Default::default() };
        c.voice = Some(VoiceConfig { stt: Some(speech.clone()), tts: Some(speech), silence: Duration::from_millis(400), ..Default::default() });
        let d = Discord::new(c).unwrap();
        let got = collect(&d, 1);
        let ident = grx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(ident["d"]["intents"].as_u64().unwrap() & GUILD_VOICE_STATES != 0);
        assert_eq!(grx.recv_timeout(Duration::from_secs(5)).unwrap(), json!({"op": 4, "d": {"guild_id": "5", "channel_id": "999", "self_mute": false, "self_deaf": false}}));
        assert_eq!(got.len(), 1, "/voice itself is not forwarded: {got:#?}");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].sender_name.as_str(), got[0].text.as_str(), got[0].chat_name.as_str()), ("C1", "77", "Amy", "hello ark", "general"));
        let posts: Vec<String> = srv.requests().iter().filter(|r| r.path == "/channels/C1/messages").map(|r| r.json()["content"].as_str().unwrap_or("").to_string()).collect();
        assert!(posts.iter().any(|p| p.starts_with("已加入 <#999>")) && posts.contains(&"🎙️ <@77>: hello ark".to_string()), "{posts:?}");
        // The agent's reply goes to the text channel and, once settled, into the voice channel.
        d.send(&Outbound::text("C1", "Hi there")).unwrap();
        let until = Instant::now() + Duration::from_secs(15);
        while fv.speaking.lock().unwrap().len() < 2 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(*fv.speaking.lock().unwrap(), [1, 0]);
        assert!(fv.heard.lock().unwrap().len() >= 20);
        assert!(seen.lock().unwrap().iter().any(|(p, b)| p == "/v1/audio/speech" && String::from_utf8_lossy(b).contains("Hi there")));
        go_tx.send(()).unwrap();
        assert_eq!(grx.recv_timeout(Duration::from_secs(5)).unwrap()["d"]["channel_id"], Value::Null);
        let until = Instant::now() + Duration::from_secs(5);
        while !srv.requests().iter().any(|r| r.json()["content"] == "已離開語音頻道。") && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(srv.requests().iter().any(|r| r.json()["content"] == "已離開語音頻道。"));
        d.stop();
    }

    /// Selects, modal trigger + submit, role mentions (incl. the bot's managed role and a REST
    /// role lookup), auto_thread, poll votes on our own and an older poll, and the poll result.
    #[test]
    fn components_modals_roles_threads_and_poll_events() {
        let srv = FakeServer::start(|req, n| match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/channels/C1/messages") if req.body.contains("\"poll\"") => (200, vec![], json!({"id": "P1", "poll": {"answers": [{"answer_id": 1}, {"answer_id": 2}]}}).to_string()),
            ("GET", "/guilds/G/roles") => (200, vec![], json!([{"id": "R9", "name": "ops"}]).to_string()),
            ("GET", "/channels/C1/messages/P0") => (200, vec![], json!({"id": "P0", "author": {"id": "B"}, "poll": {"question": {"text": "Lunch?"}, "answers": [{"answer_id": 1, "poll_media": {"text": "noodles"}}]}}).to_string()),
            ("POST", p) if p.ends_with("/threads") => (201, vec![], json!({"id": "T7", "type": 11, "parent_id": "C1", "name": "ping", "guild_id": "G"}).to_string()),
            (_, p) if p.contains("/callback") => (204, vec![], String::new()),
            _ => (200, vec![], json!({"id": format!("M{n}")}).to_string()),
        });
        let mut c = cfg(&srv.url, None);
        c.auto_thread = true;
        let modal_id = Arc::new(Mutex::new(String::new()));
        let mid2 = modal_id.clone();
        let gw = gateway(move |_, _, mut ws| {
            hello(&mut ws, 45_000);
            expect(&mut ws, 2, true);
            ready(&mut ws, 1, "");
            let roles = json!([{"id": "G", "name": "@everyone"}, {"id": "R1", "name": "admins"}, {"id": "RB", "name": "ark", "tags": {"bot_id": "B"}}]);
            dispatch(&mut ws, 2, "GUILD_CREATE", json!({"id": "G", "roles": roles, "channels": [{"id": "C1", "type": 0, "name": "general"}, {"id": "F1", "type": 15, "name": "ideas"}]}));
            let user = json!({"user": {"id": "U1", "username": "amy"}});
            let trigger = format!("arkm:{}", mid2.lock().unwrap());
            let ix = |id: &str, t: u64, data: Value| json!({"id": id, "token": format!("tok{id}"), "type": t, "channel_id": "C1", "guild_id": "G", "member": user, "message": {"id": "M0"}, "data": data});
            let events = [
                ("INTERACTION_CREATE", ix("I1", 3, json!({"custom_id": trigger, "component_type": 2}))),
                ("INTERACTION_CREATE", ix("I2", 5, json!({"custom_id": trigger, "components": [{"type": 18, "component": {"type": 4, "custom_id": "name", "value": "Amy"}}, {"type": 1, "components": [{"type": 6, "custom_id": "team", "values": ["R1"]}]}], "resolved": {"roles": {"R1": {"id": "R1", "name": "admins"}}}}))),
                ("INTERACTION_CREATE", ix("I3", 3, json!({"custom_id": "who", "component_type": 5, "values": ["U9"], "resolved": {"users": {"U9": {"id": "U9", "username": "bob"}}, "members": {"U9": {"nick": "Bobby"}}}}))),
                ("INTERACTION_CREATE", ix("I4", 3, json!({"custom_id": "arkv:0", "component_type": 3, "values": ["appr:1:once"]}))),
                ("INTERACTION_CREATE", ix("I5", 3, json!({"custom_id": "where", "component_type": 8, "values": ["C1"], "resolved": {"channels": {"C1": {"id": "C1", "name": "general"}}}}))),
                ("MESSAGE_CREATE", json!({"id": "20", "type": 0, "channel_id": "C1", "guild_id": "G", "author": amy(), "content": "<@&RB> ping <@&R1> <@&R9>", "mentions": [], "mention_roles": ["RB", "R1", "R9"]})),
                ("MESSAGE_POLL_VOTE_ADD", json!({"user_id": "U1", "channel_id": "C1", "message_id": "P1", "guild_id": "G", "answer_id": 2})),
                ("MESSAGE_POLL_VOTE_REMOVE", json!({"user_id": "U1", "channel_id": "C1", "message_id": "P1", "guild_id": "G", "answer_id": 2})),
                ("MESSAGE_POLL_VOTE_ADD", json!({"user_id": "U1", "channel_id": "C1", "message_id": "P0", "guild_id": "G", "answer_id": 1})),
                ("MESSAGE_POLL_VOTE_ADD", json!({"user_id": "B", "channel_id": "C1", "message_id": "P1", "guild_id": "G", "answer_id": 1})),
                ("MESSAGE_CREATE", json!({"id": "21", "type": 46, "channel_id": "C1", "guild_id": "G", "author": {"id": "B", "username": "ark"}, "content": "", "message_reference": {"message_id": "P1"}, "embeds": [{"type": "poll_result", "fields": [{"name": "poll_question_text", "value": "Ship it?"}, {"name": "victor_answer_text", "value": "yes"}, {"name": "victor_answer_votes", "value": "3"}, {"name": "total_votes", "value": "4"}]}]})),
            ];
            for (i, (t, d)) in events.into_iter().enumerate() {
                dispatch(&mut ws, 3 + i as u64, t, d);
            }
            idle(&mut ws);
        });
        c.gateway_url = Some(gw);
        let d = Discord::new(c).unwrap();
        // Outbound first (no gateway needed): a select + modal trigger, and a poll.
        let modal = Modal { title: "報名".into(), data: "form-1".into(), fields: vec![ModalField { id: "name".into(), label: "名字".into(), ..Default::default() }, ModalField { id: "team".into(), label: "團隊".into(), kind: FieldKind::Role, ..Default::default() }] };
        let pick = SelectMenu { kind: SelectKind::User, custom_id: "who".into(), placeholder: Some("誰？".into()), ..Default::default() };
        d.send_components("C1", None, "填表", &[pick], Some(("開啟表單", &modal))).unwrap();
        let body = srv.requests()[0].json();
        assert_eq!(body["components"][0]["components"][0], json!({"type": 5, "custom_id": "who", "placeholder": "誰？"}));
        let trigger = body["components"][1]["components"][0]["custom_id"].as_str().unwrap().to_string();
        *modal_id.lock().unwrap() = trigger.trim_start_matches("arkm:").to_string();
        let poll = Poll { question: "Ship it?".into(), answers: vec![PollAnswer { text: "no".into(), ..Default::default() }, PollAnswer { text: "yes".into(), emoji: Some("✅".into()), data: Some("ship:yes".into()) }], ..Default::default() };
        assert_eq!(d.send_poll("C1", None, &poll).unwrap(), "P1");
        let g = collect(&d, 10);
        let datas: Vec<&str> = g.iter().map(|m| m.callback.as_ref().map_or(m.text.as_str(), |c| c.data.as_str())).collect();
        assert_eq!(datas, ["form-1\n名字: Amy\n團隊: @admins", "who: @Bobby", "appr:1:once", "where: #general", "@ark ping @admins @ops", "ship:yes", "撤回ship:yes", "投票：Lunch? → noodles", "投票結束：Ship it? → yes（3/4 票）"], "{g:#?}");
        // The trigger button was answered with the modal (type 9), never forwarded.
        let reqs = srv.requests();
        let open = reqs.iter().find(|r| r.path == "/interactions/I1/tokI1/callback").unwrap().json();
        assert_eq!((open["type"].as_u64(), open["data"]["custom_id"].as_str(), open["data"]["title"].as_str()), (Some(9), Some(trigger.as_str()), Some("報名")));
        assert_eq!(open["data"]["components"][0], json!({"type": 18, "label": "名字", "component": {"type": 4, "custom_id": "name", "style": 1}}));
        assert_eq!(open["data"]["components"][1]["component"], json!({"type": 6, "custom_id": "team"}));
        assert_eq!(g[0].callback.as_ref().unwrap().id, "I2:tokI2");
        // Role mention: the bot's managed role addresses it, R9 came from GET /guilds/G/roles,
        // and auto_thread moved the conversation into a new thread named without mentions.
        let m = &g[4];
        assert!(m.mentioned);
        assert_eq!((m.thread.as_deref(), m.chat_type), (Some("T7"), ChatType::Thread));
        let th = reqs.iter().find(|r| r.path == "/channels/C1/messages/20/threads").unwrap().json();
        assert_eq!(th, json!({"name": "ping", "auto_archive_duration": 1440}));
        assert_eq!(reqs.iter().filter(|r| r.path == "/guilds/G/roles").count(), 1);
        // Votes are callbacks whose ack is a no-op.
        assert_eq!(g[5].callback.as_ref().unwrap().id, "poll:P1:2");
        let before = srv.requests().len();
        d.ack_callback(g[5].callback.as_ref().unwrap(), None).unwrap();
        assert_eq!(srv.requests().len(), before);
        let pb = reqs.iter().find(|r| r.body.contains("\"poll\"")).unwrap().json();
        assert_eq!(pb["poll"]["answers"][1], json!({"poll_media": {"text": "yes", "emoji": {"name": "✅"}}}));
        assert_eq!((pb["poll"]["duration"].as_u64(), pb["poll"]["allow_multiselect"].as_bool()), (Some(24), Some(false)));
        d.stop();
    }

    #[test]
    fn send_select_rows_polls_threads_forum_and_role_pings() {
        let srv = FakeServer::start(|req, n| match req.path.as_str() {
            p if p.ends_with("/threads") && p.starts_with("/channels/F1") => (201, vec![], json!({"id": "T9", "type": 11, "parent_id": "F1", "message": {"id": "T9"}}).to_string()),
            p if p.ends_with("/threads") => (201, vec![], json!({"id": format!("T{n}"), "type": 11, "parent_id": "C1"}).to_string()),
            p if p.contains("/answers/") => (200, vec![], json!({"users": [{"id": "U1"}, {"id": "U2"}]}).to_string()),
            p if p.ends_with("/expire") => (200, vec![], json!({"id": "P1"}).to_string()),
            _ => (200, vec![], json!({"id": format!("M{n}")}).to_string()),
        });
        let mut c = cfg(&srv.url, None);
        c.mentions = Mentions { role_ids: vec!["R1".into()], ..Default::default() };
        let d = Discord::new(c).unwrap();
        {
            let i = &d.inner;
            i.chans.lock().unwrap().insert("F1".into(), ChanInfo { kind: 15, name: "ideas".into(), guild: Some("G".into()), ..Default::default() });
            i.chans.lock().unwrap().insert("C1".into(), ChanInfo { kind: 0, name: "general".into(), guild: Some("G".into()), ..Default::default() });
            for (id, name) in [("R1", "on-call"), ("R2", "everyone-else"), ("G", "@everyone")] {
                i.note_role("G", &json!({"id": id, "name": name}));
            }
        }
        // Seven tap buttons in a row → a string select carrying the button data.
        let row: Vec<Button> = (0..7).map(|k| Button { label: format!("選項{k}"), data: format!("cl:x:{k}"), url: None }).collect();
        d.send(&Outbound { buttons: vec![row], ..Outbound::text("C1", "pick one, cc @on-call and @everyone-else") }).unwrap();
        let b = srv.requests()[0].json();
        let sel = &b["components"][0]["components"][0];
        assert_eq!((sel["type"].as_u64(), sel["custom_id"].as_str(), sel["options"].as_array().unwrap().len()), (Some(3), Some("arkv:0"), 7));
        assert_eq!(sel["options"][6], json!({"label": "選項6", "value": "cl:x:6"}));
        // Only the allowed role is written as a ping, and allowed_mentions names it.
        assert_eq!(b["content"], "pick one, cc <@&R1> and @everyone-else");
        assert_eq!(b["allowed_mentions"], json!({"parse": ["users"], "replied_user": true, "roles": ["R1"]}));
        // A send to a forum channel opens a post titled by the first line; the rest goes into it.
        let long = format!("# Weekly notes\n{}", "y".repeat(2500));
        let s = d.send(&Outbound { reply_to: Some("5".into()), ..Outbound::text("F1", &long) }).unwrap();
        assert_eq!(s.ids, ["T9", "M2"]);
        let reqs = srv.requests();
        assert_eq!(reqs[1].path, "/channels/F1/threads");
        let fp = reqs[1].json();
        assert_eq!((fp["name"].as_str(), fp["message"].get("message_reference")), (Some("Weekly notes"), None));
        assert_eq!(reqs[2].path, "/channels/T9/messages");
        // Threads with and without a starter message; explicit forum post with tags.
        assert_eq!(d.create_thread("C1", "topic", Some("M0"), false).unwrap(), "T3");
        assert_eq!(d.create_thread("C1", "", None, true).unwrap(), "T4");
        assert_eq!(d.create_forum_post("F1", "Idea", "body", &["tag1".into()]).unwrap(), ("T9".to_string(), "T9".to_string()));
        let reqs = srv.requests();
        assert_eq!((reqs[3].path.as_str(), reqs[3].json()), ("/channels/C1/messages/M0/threads", json!({"name": "topic", "auto_archive_duration": 1440})));
        assert_eq!((reqs[4].path.as_str(), reqs[4].json()), ("/channels/C1/threads", json!({"name": "對話", "type": 12, "auto_archive_duration": 1440})));
        assert_eq!(reqs[5].json()["applied_tags"], json!(["tag1"]));
        // Polls: validation, end, voters.
        assert!(d.send_poll("C1", None, &Poll { question: "q".into(), ..Default::default() }).is_err());
        d.end_poll("C1", "P1").unwrap();
        assert_eq!(d.poll_voters("C1", "P1", 2).unwrap(), ["U1", "U2"]);
        let reqs = srv.requests();
        assert_eq!((reqs[6].method.as_str(), reqs[6].path.as_str()), ("POST", "/channels/C1/polls/P1/expire"));
        assert!(reqs[7].path.starts_with("/channels/C1/polls/P1/answers/2"));
        assert!(d.caps().polls);
        assert_eq!(thread_name(&format!("<@1> {}", "word ".repeat(30))).chars().count(), 80);
        let p = poll_json(&Poll { question: "q".into(), answers: vec![PollAnswer { text: "a".into(), emoji: Some("<:party:123>".into()), data: None }], duration_hours: 9999, multiselect: true });
        assert_eq!((p["duration"].as_u64(), &p["answers"][0]["poll_media"]["emoji"]), (Some(768), &json!({"id": "123"})));
    }

    /// `shards = "auto"`: count and max_concurrency from GET /gateway/bot, one connection per
    /// shard with `shard: [id, n]`, Identify spaced by the bucket interval, voice op 4 sent by
    /// the shard that owns the guild.
    #[test]
    fn auto_shards_identify_gate_and_guild_routing() {
        let (tx, rx) = mpsc::channel::<(u64, Value, Instant)>();
        let tx = Mutex::new(tx);
        let gw = gateway(move |_, _, mut ws| {
            hello(&mut ws, 45_000);
            let ident = expect(&mut ws, 2, true);
            let shard = ident["d"]["shard"][0].as_u64().unwrap();
            tx.lock().unwrap().send((shard, ident["d"]["shard"].clone(), Instant::now())).unwrap();
            ready(&mut ws, 1, "");
            let op4 = expect(&mut ws, 4, true);
            tx.lock().unwrap().send((shard, op4["d"]["guild_id"].clone(), Instant::now())).unwrap();
            idle(&mut ws);
        });
        let gw2 = gw.clone();
        let http = FakeServer::start(move |_, _| (200, vec![], json!({"url": gw2, "shards": 2, "session_start_limit": {"total": 1000, "remaining": 999, "reset_after": 0, "max_concurrency": 1}}).to_string()));
        let mut c = cfg(&http.url, None);
        c.shards = Shards::Auto;
        c.identify_interval = Duration::from_millis(300);
        let d = Discord::new(c).unwrap();
        // Guild 5 lives on shard 0, guild 1<<22 on shard 1.
        for g in ["5", "4194304"] {
            d.inner.gw_out.lock().unwrap().push(json!({"op": 4, "d": {"guild_id": g, "channel_id": null}}));
        }
        let _ = d.poll(&Cancel::new());
        let got: Vec<(u64, Value, Instant)> = (0..4).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        let idents: Vec<&(u64, Value, Instant)> = got.iter().filter(|g| g.1.is_array()).collect();
        let mut shards: Vec<Value> = idents.iter().map(|g| g.1.clone()).collect();
        shards.sort_by_key(|v| v[0].as_u64());
        assert_eq!(shards, [json!([0, 2]), json!([1, 2])]);
        let gap = if idents[0].2 > idents[1].2 { idents[0].2 - idents[1].2 } else { idents[1].2 - idents[0].2 };
        assert!(gap >= Duration::from_millis(250), "one identify per bucket per interval: {gap:?}");
        let mut routed: Vec<(u64, String)> = got.iter().filter(|g| g.1.is_string()).map(|g| (g.0, g.1.as_str().unwrap().to_string())).collect();
        routed.sort();
        assert_eq!(routed, [(0, "5".to_string()), (1, "4194304".to_string())]);
        assert_eq!(d.inner.shard_count.load(Ordering::SeqCst), 2);
        d.stop();
    }

    /// zlib-stream transport compression: python3 zlib frames (one context, Z_SYNC_FLUSH per
    /// message, a message split across two frames) decode into normal dispatches.
    #[test]
    fn zlib_stream_compressed_gateway() {
        let v: Value = serde_json::from_str(include_str!("testdata/zlib/discord-stream.json")).unwrap();
        let frames: Vec<Vec<u8>> = v["gateway"]["frames"].as_array().unwrap().iter().map(|f| ark_net::crypto::b64_decode(f.as_str().unwrap()).unwrap()).collect();
        let (htx, hrx) = mpsc::channel::<String>();
        let htx = Mutex::new(htx);
        let gw = gateway(move |_, head, mut ws| {
            htx.lock().unwrap().send(head.lines().next().unwrap().to_string()).unwrap();
            ws.send(&Message::Binary(frames[0].clone())).unwrap();
            expect(&mut ws, 2, true);
            for f in &frames[1..] {
                ws.send(&Message::Binary(f.clone())).unwrap();
            }
            idle(&mut ws);
        });
        let mut c = cfg("http://127.0.0.1:1", Some(&gw));
        c.compress = true;
        let d = Discord::new(c).unwrap();
        let g = collect(&d, 1);
        assert!(hrx.recv().unwrap().starts_with("GET /?v=10&encoding=json&compress=zlib-stream "));
        assert_eq!((g.len(), g[0].text.as_str(), g[0].sender.as_str()), (1, "compressed hello", "U1"));
        d.stop();
    }

    #[test]
    fn shard_mention_and_dave_key_settings() {
        use std::os::unix::fs::PermissionsExt;
        let secrets: crate::Secrets = Arc::new(|s: &str| s.to_string());
        let dir = temp_dir("dcs");
        let ctx = crate::config::Ctx { name: "dc", state_dir: &dir, secrets: &secrets };
        let ok = json!({"token": "T", "shards": "auto", "compress": true, "auto_thread": true, "allow_mentions": {"roles": true, "everyone": false}, "voice": true});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        let key = dir.join("dc.dave-signature.jwk");
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(build(&ctx, json!({"token": "T", "shards": 4, "shard_ids": [0, 1], "max_concurrency": 2}).as_object().unwrap()).is_ok());
        for bad in [json!({"token": "T", "shards": 0}), json!({"token": "T", "shards": "many"}), json!({"token": "T", "allow_mentions": {"rolez": true}})] {
            assert!(build(&ctx, bad.as_object().unwrap()).is_err(), "{bad}");
        }
        let m = Mentions { roles: true, everyone: true, ..Default::default() };
        assert_eq!(m.allowed(), json!({"parse": ["users", "roles", "everyone"], "replied_user": true}));
    }

    #[test]
    fn voice_settings_parse() {
        let secrets: crate::Secrets = Arc::new(|s: &str| s.replace("{{secret:K}}", "sk-1"));
        let dir = temp_dir("dcv");
        let ctx = crate::config::Ctx { name: "dc", state_dir: &dir, secrets: &secrets };
        let s = json!({"token": "T", "voice": true, "stt": {"url": "https://api.openai.com/v1", "key": "{{secret:K}}", "language": "zh"}, "tts": {"url": "http://127.0.0.1:8880/v1", "voice": "nova"}, "voice_idle_secs": 0});
        assert!(build(&ctx, s.as_object().unwrap()).is_ok());
        let bad = json!({"token": "T", "stt": {"url": "x"}});
        assert!(build(&ctx, bad.as_object().unwrap()).err().unwrap().contains("voice = true"));
        let typo = json!({"token": "T", "voice": true, "stt": {"url": "x", "modle": "y"}});
        assert!(build(&ctx, typo.as_object().unwrap()).is_err());
    }
}
