//! QQ Bot (official open platform; ported from Hermes `plugins/platforms/qqbot`, MIT).
//!
//! Auth: `POST https://bots.qq.com/app/getAppAccessToken {appId, clientSecret}` →
//! `access_token` (cached until 60 s before expiry, refreshed once on a 401), sent as
//! `Authorization: QQBot <token>`.
//! Receive: `GET /gateway` → WebSocket. Hello (op 10) → Identify (op 2) or Resume (op 6)
//! when a session id + seq are known (persisted in the state file, so a restart resumes);
//! heartbeats (op 1) at 80 % of the Hello interval; Reconnect (op 7), Invalid Session
//! (op 9), close codes (4004 token → refresh, 4006/4007/49xx → re-identify, 4008 → rate
//! limited, 4001…4014/4914/4915 → fatal). Events: C2C_MESSAGE_CREATE,
//! GROUP_AT_MESSAGE_CREATE (always a mention), GROUP_MESSAGE_CREATE,
//! (GUILD_)AT_MESSAGE_CREATE, (GUILD_)MESSAGE_CREATE, DIRECT_MESSAGE_CREATE,
//! INTERACTION_CREATE (keyboard button → `Callback`, ACKed at once with
//! `PUT /interactions/{id}`); attachments → media; quoted messages → `reply`.
//! Send: `/v2/users/{openid}/messages`, `/v2/groups/{group_openid}/messages` (markdown
//! msg_type 2 or text msg_type 0, `msg_id` + per-message `msg_seq` for passive replies —
//! the last inbound id of the chat is reused when no `reply_to` is given, since QQ
//! restricts proactive messages), `/channels/{id}/messages`, `/dms/{guild_id}/messages`;
//! inline keyboards from buttons; media via `/files` (URL, base64 `file_data`, or the
//! chunked `upload_prepare` → COS PUT → `upload_part_finish` → `/files {upload_id}` flow
//! for large files) then a msg_type 7 rich-media message; typing (`input_notify`, C2C);
//! recall (DELETE). Chat ids: `c2c:<openid>`, `group:<group_openid>`,
//! `channel:<channel_id>`, `dm:<guild_id>` (an optional `qqbot:` prefix is accepted;
//! a bare id is a C2C openid).
//! Webhook mode (`listen`): QQ POSTs the same payloads to our URL instead of the
//! gateway. Every request carries `X-Signature-Ed25519` over `X-Signature-Timestamp +
//! body`, verified with the key derived from the client secret (repeated to 32 bytes
//! as the Ed25519 seed, as botgo does); op 13 (URL validation) is answered with
//! `{plain_token, signature = sign(event_ts + plain_token)}`, op 0 dispatches are
//! queued and acknowledged with op 12; QQ's retries (same event id) are dropped.
//! Voice (Hermes decodes with pilk, falling back to ffmpeg): QQ's own transcript
//! (`asr_refer_text`) is the caption and its pre-converted `voice_wav_url` is
//! preferred; otherwise, with `silk_decoder` set, downloaded SILK v3 is decoded by that
//! external program (`silk_v3_decoder` convention: SILK in, 16-bit mono PCM out) and
//! wrapped as WAV. With `silk_encoder`, outbound voice is turned into PCM (WAV parsed
//! here, anything else through ffmpeg) and encoded to Tencent-flavoured SILK.

use crate::http::{classify, Http, Payload};
use crate::{markup, sleep_cancellable, write_atomic, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.sgroup.qq.com";
pub const DEFAULT_TOKEN_URL: &str = "https://bots.qq.com/app/getAppAccessToken";
pub const MAX_MESSAGE: usize = 4000;
/// GROUP_AND_C2C_EVENT | PUBLIC_GUILD_MESSAGES | DIRECT_MESSAGE | INTERACTION (as upstream).
pub const DEFAULT_INTENTS: u64 = (1 << 25) | (1 << 30) | (1 << 12) | (1 << 26);
const UA: &str = "seagent-qqbot/1.1.0";
const MSG_TYPE_TEXT: u8 = 0;
const MSG_TYPE_MARKDOWN: u8 = 2;
const MSG_TYPE_INPUT_NOTIFY: u8 = 6;
const MSG_TYPE_MEDIA: u8 = 7;
const BIZ_DAILY_LIMIT: i64 = 40093002;
const BIZ_PART_RETRYABLE: i64 = 40093001;
const MD5_10M_SIZE: u64 = 10_002_432;
const FATAL_CLOSE: [(u16, &str); 9] = [
    (4001, "invalid opcode"),
    (4002, "invalid payload"),
    (4010, "invalid shard"),
    (4011, "sharding required"),
    (4012, "invalid API version"),
    (4013, "invalid intent"),
    (4014, "intent not authorized"),
    (4914, "offline/sandbox-only"),
    (4915, "banned"),
];

/// Tunables; `QqBot::new` takes them so tests can point everything at fake servers.
#[derive(Clone)]
pub struct Config {
    pub id: String,
    pub app_id: String,
    pub secret: String,
    pub api_base: String,
    pub token_url: String,
    /// JSON file with `{session_id, seq, bot_id}` for Resume across restarts.
    pub state: PathBuf,
    /// Send markdown (msg_type 2) for Markdown text and keyboards.
    pub markdown: bool,
    pub intents: u64,
    pub poll_timeout: Duration,
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest `retry_after` honoured in place; longer waits surface as `RateLimited`.
    pub max_wait: Duration,
    /// Reconnect delays (upstream: 2, 5, 10, 30, 60 s).
    pub backoff: Vec<Duration>,
    /// Wait after close code 4008.
    pub rate_limit_delay: Duration,
    pub max_reconnects: usize,
    /// Local files at least this large use the chunked upload flow (else base64 `file_data`).
    pub chunk_threshold: u64,
    pub part_finish_interval: Duration,
    pub part_finish_timeout: Duration,
    /// Webhook mode: `(listen address, path)`; no gateway connection then.
    pub webhook: Option<(String, String)>,
    pub silk: silk::Codec,
}

impl Config {
    pub fn new(id: &str, app_id: &str, secret: &str, state: PathBuf) -> Config {
        Config {
            id: id.into(),
            app_id: app_id.trim().into(),
            secret: secret.trim().into(),
            api_base: DEFAULT_API.into(),
            token_url: DEFAULT_TOKEN_URL.into(),
            state,
            markdown: true,
            intents: DEFAULT_INTENTS,
            poll_timeout: Duration::from_secs(25),
            retry_base: Duration::from_millis(1000),
            max_retries: 2,
            max_wait: Duration::from_secs(60),
            backoff: [2, 5, 10, 30, 60].iter().map(|s| Duration::from_secs(*s)).collect(),
            rate_limit_delay: Duration::from_secs(60),
            max_reconnects: 100,
            chunk_threshold: 5 * 1024 * 1024,
            part_finish_interval: Duration::from_secs(1),
            part_finish_timeout: Duration::from_secs(120),
            webhook: None,
            silk: silk::Codec::default(),
        }
    }
}

#[derive(Default, Clone)]
struct Session {
    session_id: Option<String>,
    seq: Option<i64>,
    bot_id: String,
}

struct Inner {
    cfg: Config,
    http: Http,
    token: Mutex<Option<(String, Instant)>>,
    session: Mutex<Session>,
    /// chat → (last inbound message id, when) for passive replies and typing.
    last_msg: Mutex<HashMap<String, (String, Instant)>>,
    seqs: Mutex<HashMap<String, u32>>,
    typing_at: Mutex<HashMap<String, Instant>>,
    fatal: Mutex<Option<ChannelError>>,
    tx: Mutex<Sender<Inbound>>,
    /// Webhook event ids already queued (QQ retries unanswered callbacks).
    seen: Mutex<HashMap<String, Instant>>,
}

pub struct QqBot {
    inner: Arc<Inner>,
    rx: Mutex<Receiver<Inbound>>,
    stop: Cancel,
    started: AtomicBool,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    webhook: Mutex<Option<seagent_net::httpd::Server>>,
    webhook_addr: Option<std::net::SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    C2c(String),
    Group(String),
    Channel(String),
    Dm(String),
}

fn parse_target(chat: &str) -> Result<Target, ChannelError> {
    let c = chat.trim();
    let c = c.strip_prefix("qqbot:").unwrap_or(c);
    let t = match c.split_once(':') {
        Some(("c2c" | "user", id)) => Target::C2c(id.into()),
        Some(("group", id)) => Target::Group(id.into()),
        Some(("channel" | "guild", id)) => Target::Channel(id.into()),
        Some(("dm", id)) => Target::Dm(id.into()),
        Some((k, _)) => return Err(ChannelError::new(K::Fatal, format!("qqbot: unknown target kind `{k}` (use c2c:, group:, channel: or dm:)"))),
        None => Target::C2c(c.into()),
    };
    match &t {
        Target::C2c(id) | Target::Group(id) | Target::Channel(id) | Target::Dm(id) if id.is_empty() || id.contains(['/', '?', '#']) => Err(ChannelError::new(K::Fatal, format!("qqbot: bad chat id `{chat}`"))),
        _ => Ok(t),
    }
}

impl Target {
    fn base(&self) -> String {
        match self {
            Target::C2c(id) => format!("/v2/users/{id}"),
            Target::Group(id) => format!("/v2/groups/{id}"),
            Target::Channel(id) => format!("/channels/{id}"),
            Target::Dm(id) => format!("/dms/{id}"),
        }
    }
    fn is_v2(&self) -> bool {
        matches!(self, Target::C2c(_) | Target::Group(_))
    }
    fn chat(&self) -> String {
        match self {
            Target::C2c(id) => format!("c2c:{id}"),
            Target::Group(id) => format!("group:{id}"),
            Target::Channel(id) => format!("channel:{id}"),
            Target::Dm(id) => format!("dm:{id}"),
        }
    }
    /// How long QQ accepts a passive reply to an inbound message.
    fn passive_window(&self) -> Duration {
        match self {
            Target::C2c(_) => Duration::from_secs(60 * 60),
            _ => Duration::from_secs(5 * 60),
        }
    }
}

/// QQ's `{code, message}` error body → classified error.
fn qq_error(status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let code = v["code"].as_i64().or_else(|| v["err_code"].as_i64()).unwrap_or(0);
    let msg = v["message"].as_str().unwrap_or("");
    match code {
        22009 => ChannelError::new(K::RateLimited { retry_after }, format!("{what}: rate limited ({code} {msg})")),
        BIZ_DAILY_LIMIT => ChannelError::new(K::Fatal, format!("{what}: QQ daily upload limit exceeded ({code} {msg})")),
        _ => classify(status, retry_after, what, body),
    }
}

fn biz_code(e: &ChannelError, code: i64) -> bool {
    e.message.contains(&code.to_string())
}

impl QqBot {
    pub fn new(cfg: Config) -> Result<QqBot, String> {
        if cfg.app_id.is_empty() || cfg.secret.is_empty() {
            return Err(format!("channel {}: qqbot needs app_id and client_secret", cfg.id));
        }
        let mut session = Session::default();
        if let Ok(s) = std::fs::read_to_string(&cfg.state) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                session.session_id = v["session_id"].as_str().map(str::to_string);
                session.seq = v["seq"].as_i64();
                session.bot_id = v["bot_id"].as_str().unwrap_or("").to_string();
            }
        }
        let (tx, rx) = channel();
        let http = Http::new(Duration::from_secs(120));
        let mut cfg = cfg;
        cfg.api_base = cfg.api_base.trim_end_matches('/').to_string();
        let hook = cfg.webhook.clone();
        let inner = Arc::new(Inner {
            cfg,
            http,
            token: Mutex::new(None),
            session: Mutex::new(session),
            last_msg: Mutex::new(HashMap::new()),
            seqs: Mutex::new(HashMap::new()),
            typing_at: Mutex::new(HashMap::new()),
            fatal: Mutex::new(None),
            tx: Mutex::new(tx),
            seen: Mutex::new(HashMap::new()),
        });
        let server = match hook {
            Some((listen, path)) => {
                let me = inner.clone();
                let h: seagent_net::httpd::Handler = Arc::new(move |r| me.webhook(&path, r));
                let opts = seagent_net::httpd::Opts { max_body: 1024 * 1024, ..Default::default() };
                Some(seagent_net::httpd::Server::bind(&listen, opts, h).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", inner.cfg.id))?)
            }
            None => None,
        };
        Ok(QqBot {
            inner,
            rx: Mutex::new(rx),
            stop: Cancel::new(),
            started: AtomicBool::new(false),
            worker: Mutex::new(None),
            webhook_addr: server.as_ref().map(|s| s.local_addr()),
            webhook: Mutex::new(server),
        })
    }

    pub fn webhook_addr(&self) -> Option<std::net::SocketAddr> {
        self.webhook_addr
    }

    fn ensure_started(&self) {
        if self.inner.cfg.webhook.is_some() || self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let (inner, stop) = (self.inner.clone(), self.stop.clone());
        let h = std::thread::Builder::new().name(format!("qqbot {}", self.inner.cfg.id)).spawn(move || inner.run(&stop)).ok();
        *self.worker.lock().unwrap() = h;
    }
}

impl Drop for QqBot {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

enum End {
    Stop,
    Reconnect,
    Close(u16),
    Error(ChannelError),
}

impl Inner {
    fn token(&self) -> Result<String, ChannelError> {
        let mut g = self.token.lock().unwrap();
        if let Some((t, exp)) = g.as_ref() {
            if Instant::now() + Duration::from_secs(60) < *exp {
                return Ok(t.clone());
            }
        }
        let body = json!({"appId": self.cfg.app_id, "clientSecret": self.cfg.secret});
        let r = self.http.call("POST", &self.cfg.token_url, &[("accept", "application/json"), ("user-agent", UA)], Payload::Json(&body))?;
        if !(200..300).contains(&r.status) {
            return Err(qq_error(r.status, r.retry_after, "getAppAccessToken", &r.body));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let Some(tok) = v["access_token"].as_str().filter(|t| !t.is_empty()) else {
            let msg: String = v["message"].as_str().unwrap_or("no access_token in response").chars().take(200).collect();
            return Err(ChannelError::new(K::Auth, format!("qqbot rejected app_id/client_secret (code {} {msg})", v["code"])));
        };
        let exp = v["expires_in"].as_u64().or_else(|| v["expires_in"].as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(7200);
        *g = Some((tok.to_string(), Instant::now() + Duration::from_secs(exp)));
        Ok(tok.to_string())
    }

    fn invalidate_token(&self) {
        *self.token.lock().unwrap() = None;
    }

    /// One REST call with retries; a 401 refreshes the token once.
    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ChannelError> {
        let url = format!("{}{path}", self.cfg.api_base);
        let what = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let (mut attempt, mut refreshed) = (0u32, false);
        loop {
            let tok = self.token()?;
            let auth = format!("QQBot {tok}");
            let payload = body.map(Payload::Json).unwrap_or(Payload::None);
            let err = match self.http.call(method, &url, &[("authorization", &auth), ("accept", "application/json"), ("user-agent", UA)], payload) {
                Err(e) => e,
                Ok(r) if (200..300).contains(&r.status) => {
                    if r.body.trim().is_empty() {
                        return Ok(Value::Null);
                    }
                    return serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("{what}: bad JSON ({e})")));
                }
                Ok(r) if r.status == 401 && !refreshed => {
                    refreshed = true;
                    self.invalidate_token();
                    continue;
                }
                Ok(r) => qq_error(r.status, r.retry_after, &what, &r.body),
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

    fn next_seq(&self, key: &str) -> u32 {
        let mut g = self.seqs.lock().unwrap();
        if g.len() > 4096 {
            g.clear();
        }
        let e = g.entry(key.to_string()).or_insert_with(|| {
            let r = seagent_net::crypto::random_bytes(2);
            (u16::from_be_bytes([r[0], r[1]]) % 60000) as u32
        });
        *e = *e % 65535 + 1;
        *e
    }

    fn save_session(&self) {
        let s = self.session.lock().unwrap().clone();
        let _ = write_atomic(&self.cfg.state, json!({"session_id": s.session_id, "seq": s.seq, "bot_id": s.bot_id}).to_string().as_bytes());
    }

    fn set_fatal(&self, e: ChannelError) {
        *self.fatal.lock().unwrap() = Some(e);
    }

    /// Gateway loop with reconnect/backoff; runs on its own thread until `stop`.
    fn run(self: &Arc<Self>, stop: &Cancel) {
        let mut failures = 0usize;
        while !stop.is_cancelled() {
            let mut ready = false;
            let end = self.session_once(stop, &mut ready);
            self.save_session();
            if ready {
                failures = 0;
            }
            match end {
                End::Stop => return,
                End::Reconnect => {}
                End::Close(code) => {
                    if let Some((_, desc)) = FATAL_CLOSE.iter().find(|(c, _)| *c == code) {
                        self.set_fatal(ChannelError::new(K::Fatal, format!("qqbot gateway closed {code}: bot is {desc}; check the QQ open platform")));
                        return;
                    }
                    if code == 4004 {
                        self.invalidate_token();
                    }
                    if code == 4006 || code == 4007 || (4900..4914).contains(&code) {
                        let mut s = self.session.lock().unwrap();
                        s.session_id = None;
                        s.seq = None;
                    }
                    if code == 4008 && !sleep_cancellable(self.cfg.rate_limit_delay, stop) {
                        return;
                    }
                    failures += 1;
                }
                End::Error(e) if e.kind == K::Auth || e.kind == K::Fatal => {
                    self.set_fatal(e);
                    return;
                }
                End::Error(_) => failures += 1,
            }
            if failures > self.cfg.max_reconnects {
                self.set_fatal(ChannelError::new(K::Network, "qqbot: too many failed gateway reconnects"));
                return;
            }
            if failures > 0 {
                let d = self.cfg.backoff.get((failures - 1).min(self.cfg.backoff.len().saturating_sub(1))).copied().unwrap_or(Duration::from_secs(5));
                if !sleep_cancellable(d, stop) {
                    return;
                }
            }
        }
    }

    fn session_once(self: &Arc<Self>, stop: &Cancel, ready: &mut bool) -> End {
        let url = match self.api("GET", "/gateway", None) {
            Ok(v) => match v["url"].as_str() {
                Some(u) => u.to_string(),
                None => return End::Error(ChannelError::new(K::Protocol, "qqbot /gateway returned no url")),
            },
            Err(e) => return End::Error(e),
        };
        let mut ws = match WebSocket::connect(&url, &[], Duration::from_secs(20)) {
            Ok((ws, _)) => ws,
            Err(e) => return End::Error(ChannelError::new(K::Network, format!("qqbot gateway connect: {e}"))),
        };
        let _ = ws.set_read_timeout(Some(Duration::from_millis(200)));
        let mut hb: Option<Duration> = None;
        let mut last_hb = Instant::now();
        let mut unacked = 0u32;
        loop {
            if stop.is_cancelled() {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                return End::Stop;
            }
            if let Some(iv) = hb {
                if last_hb.elapsed() >= iv {
                    if unacked >= 3 {
                        return End::Error(ChannelError::new(K::Network, "qqbot heartbeat not acknowledged"));
                    }
                    let seq = self.session.lock().unwrap().seq;
                    if ws.send_text(&json!({"op": 1, "d": seq}).to_string()).is_err() {
                        return End::Error(ChannelError::new(K::Network, "qqbot heartbeat send failed"));
                    }
                    unacked += 1;
                    last_hb = Instant::now();
                }
            }
            let msg = match ws.recv() {
                Ok(None) => continue,
                Ok(Some(m)) => m,
                Err(e) => return End::Error(ChannelError::new(K::Network, format!("qqbot gateway: {e}"))),
            };
            let text = match msg {
                Message::Text(t) => t,
                Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                Message::Close(c) => return End::Close(c.map(|(code, _)| code).unwrap_or(1005)),
                _ => continue,
            };
            let Ok(p) = serde_json::from_str::<Value>(&text) else { continue };
            if let Some(s) = p["s"].as_i64() {
                let mut g = self.session.lock().unwrap();
                if g.seq.is_none_or(|old| s > old) {
                    g.seq = Some(s);
                }
            }
            match p["op"].as_i64() {
                Some(10) => {
                    let ms = p["d"]["heartbeat_interval"].as_u64().unwrap_or(30000);
                    hb = Some(Duration::from_millis(ms * 8 / 10));
                    last_hb = Instant::now();
                    let tok = match self.token() {
                        Ok(t) => t,
                        Err(e) => return End::Error(e),
                    };
                    let s = self.session.lock().unwrap().clone();
                    let frame = match (s.session_id, s.seq) {
                        (Some(id), Some(seq)) => json!({"op": 6, "d": {"token": format!("QQBot {tok}"), "session_id": id, "seq": seq}}),
                        _ => json!({"op": 2, "d": {"token": format!("QQBot {tok}"), "intents": self.cfg.intents, "shard": [0, 1], "properties": {"$os": std::env::consts::OS, "$browser": "seagent", "$device": "seagent"}}}),
                    };
                    if ws.send_text(&frame.to_string()).is_err() {
                        return End::Error(ChannelError::new(K::Network, "qqbot identify send failed"));
                    }
                }
                Some(11) => unacked = 0,
                Some(7) => return End::Reconnect,
                Some(9) => {
                    if !p["d"].as_bool().unwrap_or(false) {
                        let mut s = self.session.lock().unwrap();
                        s.session_id = None;
                        s.seq = None;
                    }
                    return End::Reconnect;
                }
                Some(0) => {
                    let t = p["t"].as_str().unwrap_or("");
                    let d = &p["d"];
                    match t {
                        "READY" => {
                            {
                                let mut s = self.session.lock().unwrap();
                                s.session_id = d["session_id"].as_str().map(str::to_string);
                                if let Some(id) = d["user"]["id"].as_str() {
                                    s.bot_id = id.to_string();
                                }
                            }
                            *ready = true;
                            self.save_session();
                        }
                        "RESUMED" => *ready = true,
                        _ => self.dispatch(t, d),
                    }
                }
                _ => {}
            }
        }
    }

    /// One op-0 event (gateway or webhook) → the queue.
    fn dispatch(self: &Arc<Self>, t: &str, d: &Value) {
        if t == "INTERACTION_CREATE" {
            if let Some(id) = d["id"].as_str().filter(|s| !s.is_empty()) {
                // QQ shows an error on the button unless it is ACKed promptly.
                let (me, id) = (self.clone(), id.to_string());
                std::thread::spawn(move || {
                    let _ = me.api("PUT", &format!("/interactions/{id}"), Some(&json!({"code": 0})));
                });
            }
            if let Some(ib) = interaction_of(&self.cfg.id, d) {
                let _ = self.tx.lock().unwrap().send(ib);
            }
            return;
        }
        let bot = self.session.lock().unwrap().bot_id.clone();
        if let Some(mut ib) = inbound_of(&self.cfg.id, t, d, &bot) {
            if self.cfg.silk.decoder.is_some() {
                // fetch_media hands back decoded WAV for SILK voice.
                for m in ib.media.iter_mut().filter(|m| m.kind == MediaKind::Voice && !m.mime.contains("wav")) {
                    let stem = m.name.rsplit_once('.').map(|(a, _)| a.to_string()).unwrap_or_else(|| m.name.clone());
                    m.name = format!("{}.wav", if stem.is_empty() { "voice" } else { &stem });
                    m.mime = "audio/wav".into();
                }
            }
            self.last_msg.lock().unwrap().insert(ib.chat.clone(), (ib.message_id.clone(), Instant::now()));
            let _ = self.tx.lock().unwrap().send(ib);
        }
    }

    /// Ed25519 seed: the client secret repeated to 32 bytes (botgo `GenerateSignature`).
    fn webhook_seed(&self) -> [u8; 32] {
        let mut seed = self.cfg.secret.clone().into_bytes();
        while !seed.is_empty() && seed.len() < 32 {
            seed = seed.repeat(2);
        }
        seed.resize(32, 0);
        let mut out = [0u8; 32];
        out.copy_from_slice(&seed[..32]);
        out
    }

    fn webhook(self: &Arc<Self>, path: &str, r: seagent_net::httpd::Request) -> seagent_net::httpd::Response {
        use seagent_net::crypto;
        use seagent_net::httpd::Response;
        if r.path != path {
            return Response::text(404, "not found");
        }
        if r.method != "POST" {
            return Response::text(405, "method not allowed");
        }
        let seed = self.webhook_seed();
        let sig = r.header("x-signature-ed25519").and_then(crypto::hex_decode).filter(|s| s.len() == 64 && s[63] & 224 == 0);
        let ts = r.header("x-signature-timestamp").unwrap_or("");
        let Some(sig) = sig.filter(|_| !ts.is_empty()) else { return Response::text(401, "missing signature") };
        let mut msg = ts.as_bytes().to_vec();
        msg.extend_from_slice(&r.body);
        if !crypto::ed25519_verify(&crypto::ed25519_public(&seed), &msg, &sig) {
            return Response::text(401, "invalid signature");
        }
        let Ok(p) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "invalid json") };
        let ack = || Response::new(200, "application/json", json!({"op": 12, "d": 0}).to_string());
        match p["op"].as_i64() {
            Some(13) => {
                let plain = s(&p["d"]["plain_token"]);
                let event_ts = s(&p["d"]["event_ts"]);
                let signature = crypto::hex(&crypto::ed25519_sign(&seed, format!("{event_ts}{plain}").as_bytes()));
                Response::new(200, "application/json", json!({"plain_token": plain, "signature": signature}).to_string())
            }
            Some(0) => {
                let id = s(&p["id"]);
                if !id.is_empty() {
                    let mut seen = self.seen.lock().unwrap();
                    seen.retain(|_, t| t.elapsed() < Duration::from_secs(600));
                    if seen.insert(id, Instant::now()).is_some() {
                        return ack();
                    }
                }
                self.dispatch(p["t"].as_str().unwrap_or(""), &p["d"]);
                ack()
            }
            _ => ack(),
        }
    }
}

fn s(v: &Value) -> String {
    v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())).unwrap_or_default()
}

fn media_of(atts: &Value) -> Vec<Media> {
    let mut out = Vec::new();
    for a in atts.as_array().into_iter().flatten() {
        let mut url = s(&a["url"]).trim().to_string();
        if url.is_empty() {
            continue;
        }
        if url.starts_with("//") {
            url = format!("https:{url}");
        }
        let ct = s(&a["content_type"]).trim().to_ascii_lowercase();
        let name = s(&a["filename"]);
        let lower = name.to_ascii_lowercase();
        let voice_ext = [".silk", ".amr", ".slk", ".wav", ".mp3", ".ogg", ".m4a", ".aac", ".opus"].iter().any(|e| lower.ends_with(e));
        let kind = if ct == "voice" || ct.starts_with("audio/") || (ct != "file" && !ct.starts_with("image/") && !ct.starts_with("video/") && voice_ext) {
            MediaKind::Voice
        } else if ct.starts_with("image/") {
            MediaKind::Image
        } else if ct.starts_with("video/") {
            MediaKind::Video
        } else {
            MediaKind::Document
        };
        let caption = a["asr_refer_text"].as_str().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
        // QQ's own WAV rendition of a SILK voice note needs no decoding.
        let wav = s(&a["voice_wav_url"]).trim().to_string();
        let (url, name, ct) = if kind == MediaKind::Voice && !wav.is_empty() {
            let stem = name.rsplit_once('.').map(|(a, _)| a.to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "voice".into());
            (if wav.starts_with("//") { format!("https:{wav}") } else { wav }, format!("{stem}.wav"), "audio/wav".to_string())
        } else {
            (url, name, ct)
        };
        out.push(Media {
            kind,
            url: Some(url),
            mime: if ct.contains('/') { ct.clone() } else { String::new() },
            name,
            size: a["size"].as_u64().unwrap_or(0),
            caption,
            ..Default::default()
        });
    }
    out
}

/// Drop a leading `@name` (group @ messages carry the bot's name first).
fn strip_leading_at(t: &str) -> String {
    let t = t.trim();
    match t.strip_prefix('@') {
        Some(rest) => rest.split_once(char::is_whitespace).map(|(_, r)| r.trim_start().to_string()).unwrap_or_default(),
        None => t.to_string(),
    }
}

/// Remove `<@!id>` / `<@id>` mention tokens for the bot; returns (text, was_mentioned).
fn strip_guild_mentions(t: &str, bot: &str) -> (String, bool) {
    let mut found = false;
    let mut out = t.to_string();
    if !bot.is_empty() {
        for tok in [format!("<@!{bot}>"), format!("<@{bot}>")] {
            if out.contains(&tok) {
                found = true;
                out = out.replace(&tok, "");
            }
        }
    }
    (out.trim().to_string(), found)
}

/// One dispatch event → an Inbound (None for unknown kinds, empty or own messages).
fn inbound_of(channel: &str, t: &str, d: &Value, bot: &str) -> Option<Inbound> {
    let author = &d["author"];
    let content = s(&d["content"]);
    let (chat, chat_type, sender, text, mentioned) = match t {
        "C2C_MESSAGE_CREATE" => {
            let u = s(&author["user_openid"]);
            let u = if u.is_empty() { s(&author["id"]) } else { u };
            (Target::C2c(u.clone()), ChatType::Direct, u, content.trim().to_string(), false)
        }
        "GROUP_AT_MESSAGE_CREATE" | "GROUP_MESSAGE_CREATE" => {
            let m = s(&author["member_openid"]);
            let m = if m.is_empty() { s(&author["id"]) } else { m };
            let at = t == "GROUP_AT_MESSAGE_CREATE" || d["mentions"].as_array().into_iter().flatten().any(|x| x["is_you"] == true || x["bot"] == true && (bot.is_empty() || s(&x["id"]) == bot));
            let text = if at { strip_leading_at(&content) } else { content.trim().to_string() };
            (Target::Group(s(&d["group_openid"])), ChatType::Group, m, text, at)
        }
        "AT_MESSAGE_CREATE" | "GUILD_AT_MESSAGE_CREATE" | "MESSAGE_CREATE" | "GUILD_MESSAGE_CREATE" => {
            let (text, tok) = strip_guild_mentions(&content, bot);
            let listed = !bot.is_empty() && d["mentions"].as_array().into_iter().flatten().any(|x| s(&x["id"]) == bot);
            let at = t.contains("AT_MESSAGE") || tok || listed;
            (Target::Channel(s(&d["channel_id"])), ChatType::Group, s(&author["id"]), text, at)
        }
        "DIRECT_MESSAGE_CREATE" => (Target::Dm(s(&d["guild_id"])), ChatType::Direct, s(&author["id"]), content.trim().to_string(), false),
        _ => return None,
    };
    if !bot.is_empty() && sender == bot {
        return None;
    }
    let id = s(&d["id"]);
    let media = media_of(&d["attachments"]);
    if id.is_empty() || (text.is_empty() && media.is_empty()) {
        return None;
    }
    if matches!(&chat, Target::C2c(x) | Target::Group(x) | Target::Channel(x) | Target::Dm(x) if x.is_empty()) {
        return None;
    }
    let reply = {
        let quote = d["message_type"].as_i64() == Some(103) || d["message_type"].as_str() == Some("103");
        let qtext: Vec<String> = if quote { d["msg_elements"].as_array().into_iter().flatten().map(|e| s(&e["content"]).trim().to_string()).filter(|t| !t.is_empty()).collect() } else { vec![] };
        let rid = s(&d["message_reference"]["message_id"]);
        (!rid.is_empty() || !qtext.is_empty()).then(|| ReplyRef { id: rid, text: qtext.join(" "), author: String::new(), is_own: false })
    };
    let nick = s(&d["member"]["nick"]);
    Some(Inbound {
        channel: channel.to_string(),
        chat: chat.chat(),
        chat_type,
        sender,
        sender_name: if nick.is_empty() { s(&author["username"]) } else { nick },
        is_bot: author["bot"] == true,
        text,
        message_id: id,
        ts: parse_ts(&s(&d["timestamp"])),
        media,
        mentioned,
        reply,
        ..Default::default()
    })
}

/// INTERACTION_CREATE (keyboard button) → Inbound with a Callback.
fn interaction_of(channel: &str, d: &Value) -> Option<Inbound> {
    let id = s(&d["id"]);
    if id.is_empty() {
        return None;
    }
    let resolved = &d["data"]["resolved"];
    let (chat, chat_type) = match d["chat_type"].as_i64().unwrap_or(0) {
        1 => (Target::Group(s(&d["group_openid"])), ChatType::Group),
        2 => (Target::C2c(s(&d["user_openid"])), ChatType::Direct),
        _ => (Target::Channel(s(&d["channel_id"])), ChatType::Group),
    };
    let sender = [s(&d["group_member_openid"]), s(&d["user_openid"]), s(&resolved["user_id"])].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
    let mid = s(&resolved["message_id"]);
    Some(Inbound {
        channel: channel.to_string(),
        chat: chat.chat(),
        chat_type,
        sender,
        message_id: format!("cb:{id}"),
        ts: parse_ts(&s(&d["timestamp"])),
        callback: Some(Callback { id, data: s(&resolved["button_data"]) }),
        reply: (!mid.is_empty()).then(|| ReplyRef { id: mid, is_own: true, ..Default::default() }),
        ..Default::default()
    })
}

/// ISO 8601 (`2023-11-06T13:37:18+08:00`) or legacy integer milliseconds → Unix seconds.
fn parse_ts(raw: &str) -> i64 {
    let r = raw.trim();
    if let Ok(ms) = r.parse::<i64>() {
        return ms / 1000;
    }
    let num = |a: usize, b: usize| r.get(a..b).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19)) else { return 0 };
    let rest = r.get(19..).unwrap_or("").trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let off = match rest.chars().next() {
        Some(sign @ ('+' | '-')) => {
            let digits: String = rest[1..].chars().filter(|c| c.is_ascii_digit()).collect();
            let hh = digits.get(0..2).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
            let mm = digits.get(2..4).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
            (hh * 3600 + mm * 60) * if sign == '-' { -1 } else { 1 }
        }
        _ => 0,
    };
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + h * 3600 + mi * 60 + se - off
}

fn keyboard(rows: &[Vec<crate::Button>]) -> Value {
    let rows: Vec<Value> = rows
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let buttons: Vec<Value> = row
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    let action = match &b.url {
                        Some(u) => json!({"type": 0, "data": u, "permission": {"type": 2}, "click_limit": 1}),
                        None => json!({"type": 1, "data": b.data, "permission": {"type": 2}, "click_limit": 1}),
                    };
                    json!({"id": format!("{r}_{i}"), "render_data": {"label": b.label, "visited_label": b.label, "style": 1}, "action": action, "group_id": "default"})
                })
                .collect();
            json!({"buttons": buttons})
        })
        .collect();
    json!({"content": {"rows": rows}})
}

/// Platforms without keyboards: numbered options appended to the text.
fn numbered_options(rows: &[Vec<crate::Button>]) -> String {
    let mut out = String::new();
    for (n, b) in rows.iter().flatten().enumerate() {
        match &b.url {
            Some(u) => out.push_str(&format!("\n{}. {} ({u})", n + 1, b.label)),
            None => out.push_str(&format!("\n{}. {}", n + 1, b.label)),
        }
    }
    out
}

fn file_type(k: MediaKind) -> u8 {
    match k {
        MediaKind::Image | MediaKind::Sticker | MediaKind::Animation => 1,
        MediaKind::Video => 2,
        MediaKind::Voice | MediaKind::Audio => 3,
        MediaKind::Document => 4,
    }
}

impl Inner {
    fn passive_id(&self, t: &Target, out: &Outbound) -> Option<String> {
        if let Some(r) = out.reply_to.as_deref().filter(|r| !r.is_empty()) {
            return Some(r.to_string());
        }
        let g = self.last_msg.lock().unwrap();
        g.get(&t.chat()).filter(|(_, at)| at.elapsed() < t.passive_window()).map(|(id, _)| id.clone())
    }

    fn post_message(&self, t: &Target, body: &Value) -> Result<String, ChannelError> {
        let r = self.api("POST", &format!("{}/messages", t.base()), Some(body))?;
        Ok(s(&r["id"]))
    }

    fn send_text_piece(&self, t: &Target, text: &str, out: &Outbound, msg_id: Option<&str>, quote: bool, buttons: bool) -> Result<String, ChannelError> {
        let mut text = text.to_string();
        let kb = buttons && t.is_v2() && self.cfg.markdown;
        let md = t.is_v2() && self.cfg.markdown && (out.format == TextFormat::Markdown || kb);
        if !md && out.format == TextFormat::Markdown {
            text = markup::convert(&text, Markup::Plain);
        }
        if buttons && !kb {
            text.push_str(&numbered_options(&out.buttons));
        }
        let mut body = if !t.is_v2() {
            json!({"content": text})
        } else if md {
            json!({"markdown": {"content": text}, "msg_type": MSG_TYPE_MARKDOWN})
        } else {
            json!({"content": text, "msg_type": MSG_TYPE_TEXT})
        };
        if let Some(id) = msg_id {
            body["msg_id"] = json!(id);
            if quote && !md {
                body["message_reference"] = json!({"message_id": id});
            }
        }
        if t.is_v2() {
            body["msg_seq"] = json!(self.next_seq(msg_id.unwrap_or(&t.chat())));
        }
        if kb {
            body["keyboard"] = keyboard(&out.buttons);
        }
        self.post_message(t, &body)
    }

    /// `/files` upload → `file_info` (URL, base64, or chunked for large local files).
    fn upload(&self, t: &Target, m: &Media) -> Result<Value, ChannelError> {
        let ft = file_type(m.kind);
        let files = format!("{}/files", t.base());
        let r = match (&m.path, &m.url) {
            (Some(p), _) => {
                let meta = std::fs::metadata(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                let name = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
                if meta.len() >= self.cfg.chunk_threshold {
                    self.chunked_upload(t, p, meta.len(), ft, &name)?
                } else {
                    let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                    let mut body = json!({"file_type": ft, "file_data": seagent_net::crypto::b64(&data), "srv_send_msg": false});
                    if ft == 4 {
                        body["file_name"] = json!(name);
                    }
                    self.api("POST", &files, Some(&body))?
                }
            }
            (None, Some(u)) => {
                let mut body = json!({"file_type": ft, "url": u, "srv_send_msg": false});
                if ft == 4 {
                    let name = if m.name.is_empty() { u.split(['?', '#']).next().unwrap_or("").rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("media").to_string() } else { m.name.clone() };
                    body["file_name"] = json!(name);
                }
                self.api("POST", &files, Some(&body))?
            }
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let fi = if r["file_info"].is_string() { r["file_info"].clone() } else { r["data"]["file_info"].clone() };
        if !fi.is_string() {
            return Err(ChannelError::new(K::Protocol, "qqbot upload returned no file_info"));
        }
        Ok(fi)
    }

    fn chunked_upload(&self, t: &Target, path: &str, size: u64, ft: u8, name: &str) -> Result<Value, ChannelError> {
        let io = |e: std::io::Error| ChannelError::new(K::Fatal, format!("reading {path}: {e}"));
        let (md5, sha1, md5_10m) = file_hashes(path, size).map_err(io)?;
        let base = t.base();
        let body = json!({"file_type": ft, "file_name": name, "file_size": size, "md5": md5, "sha1": sha1, "md5_10m": md5_10m});
        let raw = self.api("POST", &format!("{base}/upload_prepare"), Some(&body)).map_err(|e| if biz_code(&e, BIZ_DAILY_LIMIT) { ChannelError::new(K::Fatal, format!("qqbot daily upload limit exceeded for {name}")) } else { e })?;
        let src = if raw["data"].is_object() { &raw["data"] } else { &raw };
        let upload_id = s(&src["upload_id"]);
        let block = src["block_size"].as_u64().unwrap_or(0);
        let parts = src["parts"].as_array().or_else(|| src["part_list"].as_array()).cloned().unwrap_or_default();
        if upload_id.is_empty() || parts.is_empty() {
            return Err(ChannelError::new(K::Protocol, "qqbot upload_prepare returned no upload_id/parts"));
        }
        let timeout = src["retry_timeout"].as_f64().filter(|x| *x > 0.0).map(|x| Duration::from_secs_f64(x.min(600.0))).unwrap_or(self.cfg.part_finish_timeout);
        let mut f = std::fs::File::open(path).map_err(io)?;
        for p in &parts {
            let idx = p["part_index"].as_u64().or_else(|| p["index"].as_u64()).unwrap_or(0).max(1);
            let url = p["presigned_url"].as_str().or_else(|| p["url"].as_str()).unwrap_or("").to_string();
            let pbs = p["block_size"].as_u64().filter(|b| *b > 0).unwrap_or(block);
            let off = (idx - 1) * block;
            let len = pbs.min(size.saturating_sub(off));
            let mut data = vec![0u8; len as usize];
            f.seek(SeekFrom::Start(off)).map_err(io)?;
            f.read_exact(&mut data).map_err(io)?;
            let mut put_ok = Err(ChannelError::new(K::Network, "COS PUT not attempted"));
            for attempt in 0..3u32 {
                put_ok = self.http.agent.put(&url).send(&data[..]).map_err(|e| ChannelError::new(K::Network, format!("COS PUT part {idx}: {e}"))).and_then(|r| {
                    let st = r.status().as_u16();
                    if (200..300).contains(&st) {
                        Ok(())
                    } else {
                        Err(classify(st, None, &format!("COS PUT part {idx}"), ""))
                    }
                });
                if put_ok.is_ok() {
                    break;
                }
                if attempt < 2 {
                    std::thread::sleep(self.cfg.retry_base * 2u32.pow(attempt));
                }
            }
            put_ok?;
            let fin = json!({"upload_id": upload_id, "part_index": idx, "block_size": len, "md5": hex(&Md5::digest(&data))});
            let start = Instant::now();
            loop {
                match self.api("POST", &format!("{base}/upload_part_finish"), Some(&fin)) {
                    Ok(_) => break,
                    Err(e) if biz_code(&e, BIZ_PART_RETRYABLE) && start.elapsed() < timeout => std::thread::sleep(self.cfg.part_finish_interval),
                    Err(e) => return Err(e),
                }
            }
        }
        self.api("POST", &format!("{base}/files"), Some(&json!({"upload_id": upload_id})))
    }

    fn send_media(&self, t: &Target, m: &Media, caption: Option<&str>, msg_id: Option<&str>) -> Result<String, ChannelError> {
        if t.is_v2() {
            // QQ voice messages must be SILK; transcode when an encoder is configured.
            let encoded = match (m.kind, &self.cfg.silk.encoder) {
                (MediaKind::Voice | MediaKind::Audio, Some(_)) => {
                    let src = match (&m.path, &m.url) {
                        (Some(p), _) => silk::Temp::copy_of(p)?,
                        (None, Some(u)) => silk::Temp::with(&crate::http::get_bytes(u, &[], 50 * 1024 * 1024)?, "in")?,
                        _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
                    };
                    Some(self.cfg.silk.encode(&src)?)
                }
                _ => None,
            };
            let voice;
            let m = match &encoded {
                Some(f) => {
                    voice = Media { kind: MediaKind::Voice, path: Some(f.path_str()), url: None, name: "voice.silk".into(), mime: "audio/silk".into(), ..m.clone() };
                    &voice
                }
                None => m,
            };
            let fi = self.upload(t, m)?;
            let mut body = json!({"msg_type": MSG_TYPE_MEDIA, "media": {"file_info": fi}});
            if let Some(c) = caption.or(m.caption.as_deref()).filter(|c| !c.trim().is_empty()) {
                body["content"] = json!(c);
            }
            if let Some(id) = msg_id {
                body["msg_id"] = json!(id);
            }
            body["msg_seq"] = json!(self.next_seq(msg_id.unwrap_or(&t.chat())));
            return self.post_message(t, &body);
        }
        // Guild channels / DMs: images only, by URL (`image`) or multipart `file_image`.
        if !matches!(m.kind, MediaKind::Image | MediaKind::Sticker | MediaKind::Animation) {
            return match &m.url {
                Some(u) => self.post_message(t, &json!({"content": format!("{}{u}", caption.map(|c| format!("{c}\n")).unwrap_or_default()), "msg_id": msg_id})),
                None => Err(ChannelError::new(K::Unsupported, "qqbot guild channels accept only image uploads")),
            };
        }
        match (&m.path, &m.url) {
            (Some(p), _) => {
                let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                let name = std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "image.png".into());
                let mut parts: Vec<(&str, &str, &str, &[u8])> = vec![];
                if let Some(c) = caption {
                    parts.push(("content", "", "", c.as_bytes()));
                }
                if let Some(id) = msg_id {
                    parts.push(("msg_id", "", "", id.as_bytes()));
                }
                parts.push(("file_image", &name, &m.mime, &data));
                let tok = self.token()?;
                let r = self.http.call("POST", &format!("{}{}/messages", self.cfg.api_base, t.base()), &[("authorization", &format!("QQBot {tok}")), ("user-agent", UA)], Payload::Multipart(&parts))?;
                if !(200..300).contains(&r.status) {
                    return Err(qq_error(r.status, r.retry_after, "POST messages", &r.body));
                }
                Ok(serde_json::from_str::<Value>(&r.body).map(|v| s(&v["id"])).unwrap_or_default())
            }
            (None, Some(u)) => {
                let mut body = json!({"image": u});
                if let Some(c) = caption {
                    body["content"] = json!(c);
                }
                if let Some(id) = msg_id {
                    body["msg_id"] = json!(id);
                }
                self.post_message(t, &body)
            }
            _ => Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        }
    }
}

impl Channel for QqBot {
    fn id(&self) -> &str {
        &self.inner.cfg.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 0,
            edit: false,
            delete: true,
            typing: true,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: if self.inner.cfg.markdown { Markup::Markdown } else { Markup::Plain },
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started();
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.inner.cfg.poll_timeout;
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                got.push(m);
                got.extend(rx.try_iter());
            }
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let t = parse_target(&out.chat)?;
        let inner = &self.inner;
        let passive = inner.passive_id(&t, out);
        let quote = out.reply_to.is_some();
        let mut sent = Sent::default();
        let caption_ok = out.media.len() == 1 && out.buttons.is_empty() && out.text.chars().count() <= MAX_MESSAGE;
        for (i, m) in out.media.iter().enumerate() {
            let cap = (caption_ok && i == 0).then_some(out.text.as_str()).filter(|t| !t.trim().is_empty());
            sent.ids.push(inner.send_media(&t, m, cap, passive.as_deref())?);
        }
        if caption_ok && !out.media.is_empty() {
            return Ok(sent);
        }
        let mut pieces = crate::chunk::split(&out.text, MAX_MESSAGE - 200, LenUnit::Chars);
        if pieces.is_empty() && !out.buttons.is_empty() {
            pieces.push("请选择：".into());
        }
        let n = pieces.len();
        for (i, p) in pieces.iter().enumerate() {
            let q = quote && i == 0 && out.media.is_empty();
            sent.ids.push(inner.send_text_piece(&t, p, out, passive.as_deref(), q, i + 1 == n && !out.buttons.is_empty())?);
        }
        Ok(sent)
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let t = parse_target(chat)?;
        let mid = seagent_net::urlencode(message_id);
        let q = if t.is_v2() { "" } else { "?hidetip=false" };
        self.inner.api("DELETE", &format!("{}/messages/{mid}{q}", t.base()), None).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let t = parse_target(chat)?;
        // Only C2C has an input indicator; it needs a recent inbound msg_id.
        if !matches!(t, Target::C2c(_)) {
            return Ok(());
        }
        let Some(mid) = self.inner.passive_id(&t, &Outbound::default()) else { return Ok(()) };
        {
            let mut g = self.inner.typing_at.lock().unwrap();
            if g.get(&t.chat()).is_some_and(|at| at.elapsed() < Duration::from_secs(50)) {
                return Ok(());
            }
            g.insert(t.chat(), Instant::now());
        }
        let body = json!({"msg_type": MSG_TYPE_INPUT_NOTIFY, "msg_id": mid, "input_notify": {"input_type": 1, "input_second": 60}, "msg_seq": self.inner.next_seq(&mid)});
        self.inner.post_message(&t, &body).map(|_| ())
    }

    /// Interactions are ACKed (`PUT /interactions/{id}`) as soon as they arrive.
    fn ack_callback(&self, _cb: &Callback, _text: Option<&str>) -> Result<(), ChannelError> {
        Ok(())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "qqbot attachment without url"))?;
        let u = if u.starts_with("//") { format!("https:{u}") } else { u.to_string() };
        if !(u.starts_with("https://") || u.starts_with("http://")) {
            return Err(ChannelError::new(K::Fatal, "qqbot attachment url is not http(s)"));
        }
        let auth = format!("QQBot {}", self.inner.token()?);
        let bytes = crate::http::get_bytes(&u, &[("authorization", &auth)], 100 * 1024 * 1024)?;
        if m.kind == MediaKind::Voice && silk::is_silk(&bytes) && self.inner.cfg.silk.decoder.is_some() {
            return self.inner.cfg.silk.decode(&bytes);
        }
        Ok(bytes)
    }

    fn stop(&self) {
        self.stop.cancel();
        self.webhook.lock().unwrap().take();
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

/// SILK v3 voice through external programs (no codec is bundled: Hermes uses the
/// `pilk` bindings, ffmpeg cannot decode SILK). Decoders/encoders following the
/// `silk_v3_decoder` / `silk_v3_encoder` conventions read/write headerless 16-bit
/// little-endian mono PCM at `rate`.
pub mod silk {
    use crate::{ChannelError, ChannelErrorKind as K};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    #[derive(Debug, Clone)]
    pub struct Codec {
        /// argv template; `{in}`, `{out}`, `{rate}` are substituted.
        pub decoder: Option<Vec<String>>,
        pub encoder: Option<Vec<String>>,
        pub ffmpeg: String,
        pub rate: u32,
    }

    impl Default for Codec {
        fn default() -> Codec {
            Codec { decoder: None, encoder: None, ffmpeg: "ffmpeg".into(), rate: 24000 }
        }
    }

    /// The argv a bare program path implies (`-tencent` adds the 0x02 byte QQ expects).
    pub fn default_argv(bin: &str, encoder: bool) -> Vec<String> {
        let mut v: Vec<String> = [bin, "{in}", "{out}"].iter().map(|s| s.to_string()).collect();
        if encoder {
            v.push("-tencent".into());
        }
        v.extend(["-Fs_API".to_string(), "{rate}".to_string()]);
        v
    }

    /// `#!SILK_V3`, optionally behind Tencent's 0x02 byte.
    pub fn is_silk(b: &[u8]) -> bool {
        b.starts_with(b"#!SILK") || b.starts_with(b"\x02#!SILK")
    }

    /// A temp file removed on drop.
    pub struct Temp(PathBuf);

    impl Temp {
        pub fn new(ext: &str) -> Temp {
            let r = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(6));
            Temp(std::env::temp_dir().join(format!("seagent-qq-{}-{r}.{ext}", std::process::id())))
        }
        pub fn with(data: &[u8], ext: &str) -> Result<Temp, ChannelError> {
            let t = Temp::new(ext);
            std::fs::write(&t.0, data).map_err(|e| ChannelError::new(K::Fatal, format!("temp file: {e}")))?;
            Ok(t)
        }
        pub fn copy_of(p: &str) -> Result<Temp, ChannelError> {
            let ext = Path::new(p).extension().and_then(|e| e.to_str()).unwrap_or("bin").to_string();
            let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
            Temp::with(&data, &ext)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
        pub fn path_str(&self) -> String {
            self.0.display().to_string()
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn run(argv: &[String], input: &Path, output: &Path, rate: u32) -> Result<(), ChannelError> {
        let sub = |a: &String| a.replace("{in}", &input.display().to_string()).replace("{out}", &output.display().to_string()).replace("{rate}", &rate.to_string());
        let args: Vec<String> = argv.iter().map(sub).collect();
        let (bin, rest) = args.split_first().ok_or_else(|| ChannelError::new(K::Fatal, "empty codec command"))?;
        let out = Command::new(bin).args(rest).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output().map_err(|e| ChannelError::new(K::Fatal, format!("cannot run {bin}: {e}")))?;
        if !out.status.success() {
            let err: String = String::from_utf8_lossy(&out.stderr).chars().take(300).collect();
            return Err(ChannelError::new(K::Protocol, format!("{bin} failed ({}): {}", out.status, err.trim())));
        }
        Ok(())
    }

    /// 16-bit mono PCM → RIFF/WAVE.
    pub fn wav(pcm: &[u8], rate: u32) -> Vec<u8> {
        let mut w = Vec::with_capacity(44 + pcm.len());
        let n = pcm.len() as u32;
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&(36 + n).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 2).to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&n.to_le_bytes());
        w.extend_from_slice(pcm);
        w
    }

    /// The PCM of a 16-bit mono WAV at `rate`, else None (→ ffmpeg resamples).
    pub fn pcm_of_wav(b: &[u8], rate: u32) -> Option<&[u8]> {
        if b.len() < 12 || &b[..4] != b"RIFF" || &b[8..12] != b"WAVE" {
            return None;
        }
        let (mut i, mut fmt_ok) = (12, false);
        while i + 8 <= b.len() {
            let id = &b[i..i + 4];
            let len = u32::from_le_bytes([b[i + 4], b[i + 5], b[i + 6], b[i + 7]]) as usize;
            let body = b.get(i + 8..(i + 8 + len).min(b.len()))?;
            if id == b"fmt " && body.len() >= 16 {
                let u16_at = |o: usize| u16::from_le_bytes([body[o], body[o + 1]]);
                fmt_ok = u16_at(0) == 1 && u16_at(2) == 1 && u32::from_le_bytes([body[4], body[5], body[6], body[7]]) == rate && u16_at(14) == 16;
            } else if id == b"data" {
                return fmt_ok.then_some(body);
            }
            i += 8 + len + (len & 1);
        }
        None
    }

    impl Codec {
        /// SILK bytes → WAV.
        pub fn decode(&self, silk: &[u8]) -> Result<Vec<u8>, ChannelError> {
            let argv = self.decoder.as_ref().ok_or_else(|| crate::unsupported("SILK decoding (set silk_decoder)"))?;
            let (src, dst) = (Temp::with(silk, "silk")?, Temp::new("pcm"));
            run(argv, src.path(), dst.path(), self.rate)?;
            let pcm = std::fs::read(dst.path()).map_err(|e| ChannelError::new(K::Protocol, format!("SILK decoder wrote nothing: {e}")))?;
            // Some decoders already emit WAV.
            Ok(if pcm.starts_with(b"RIFF") { pcm } else { wav(&pcm, self.rate) })
        }

        /// Any audio file → a SILK temp file (already-SILK input is passed through).
        pub fn encode(&self, src: &Temp) -> Result<Temp, ChannelError> {
            let data = std::fs::read(src.path()).map_err(|e| ChannelError::new(K::Fatal, format!("reading audio: {e}")))?;
            if is_silk(&data) {
                return Temp::with(&data, "silk");
            }
            let argv = self.encoder.as_ref().ok_or_else(|| crate::unsupported("SILK encoding (set silk_encoder)"))?;
            let pcm = match pcm_of_wav(&data, self.rate) {
                Some(p) => Temp::with(p, "pcm")?,
                None => {
                    let t = Temp::new("pcm");
                    let r = self.rate.to_string();
                    let args = ["-loglevel", "error", "-y", "-i", &src.path_str(), "-f", "s16le", "-acodec", "pcm_s16le", "-ar", &r, "-ac", "1", &t.path_str()];
                    let o = Command::new(&self.ffmpeg).args(args).stdin(Stdio::null()).output().map_err(|e| ChannelError::new(K::Fatal, format!("cannot run {}: {e}", self.ffmpeg)))?;
                    if !o.status.success() {
                        return Err(ChannelError::new(K::Protocol, format!("ffmpeg failed: {}", String::from_utf8_lossy(&o.stderr).chars().take(300).collect::<String>().trim())));
                    }
                    t
                }
            };
            let out = Temp::new("silk");
            run(argv, pcm.path(), out.path(), self.rate)?;
            let head = std::fs::read(out.path()).map_err(|e| ChannelError::new(K::Protocol, format!("SILK encoder wrote nothing: {e}")))?;
            if !is_silk(&head) {
                return Err(ChannelError::new(K::Protocol, "SILK encoder output is not SILK v3"));
            }
            Ok(out)
        }
    }
}

fn hex(b: &[u8]) -> String {
    seagent_net::crypto::hex(b)
}

/// (md5, sha1, md5 of the first 10 002 432 bytes) in one pass, as QQ's upload_prepare wants.
fn file_hashes(path: &str, size: u64) -> std::io::Result<(String, String, String)> {
    let mut f = std::fs::File::open(path)?;
    let (mut md5, mut m10) = (Md5::new(), Md5::new());
    let mut sha = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha.update(&buf[..n]);
        if read < MD5_10M_SIZE {
            m10.update(&buf[..n.min((MD5_10M_SIZE - read) as usize)]);
        }
        read += n as u64;
    }
    let full = hex(&md5.finish());
    let ten = if size > MD5_10M_SIZE { hex(&m10.finish()) } else { full.clone() };
    Ok((full, hex(sha.finish().as_ref()), ten))
}

/// MD5 (RFC 1321) — QQ's upload API requires it and ring does not ship it.
struct Md5 {
    s: [u32; 4],
    buf: Vec<u8>,
    len: u64,
}

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
const MD5_R: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

impl Md5 {
    fn new() -> Md5 {
        Md5 { s: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: Vec::with_capacity(64), len: 0 }
    }
    fn digest(data: &[u8]) -> [u8; 16] {
        let mut m = Md5::new();
        m.update(data);
        m.finish()
    }
    fn update(&mut self, mut data: &[u8]) {
        self.len += data.len() as u64;
        if !self.buf.is_empty() {
            let take = (64 - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == 64 {
                let b: [u8; 64] = self.buf[..].try_into().unwrap();
                self.block(&b);
                self.buf.clear();
            }
        }
        while data.len() >= 64 {
            let b: [u8; 64] = data[..64].try_into().unwrap();
            self.block(&b);
            data = &data[64..];
        }
        self.buf.extend_from_slice(data);
    }
    fn block(&mut self, b: &[u8; 64]) {
        let m: Vec<u32> = b.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let [mut a, mut bb, mut c, mut d] = self.s;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((bb & c) | (!bb & d), i),
                1 => ((d & bb) | (!d & c), (5 * i + 1) % 16),
                2 => (bb ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (bb | !d), (7 * i) % 16),
            };
            let r = MD5_R[(i / 16) * 4 + i % 4];
            let t = d;
            d = c;
            c = bb;
            bb = bb.wrapping_add(a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(m[g]).rotate_left(r));
            a = t;
        }
        for (s, v) in self.s.iter_mut().zip([a, bb, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    fn finish(mut self) -> [u8; 16] {
        let bits = self.len.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        while (self.buf.len() + pad.len()) % 64 != 56 {
            pad.push(0);
        }
        pad.extend_from_slice(&bits.to_le_bytes());
        let len = self.len;
        self.update(&pad);
        self.len = len;
        let mut out = [0u8; 16];
        for (i, w) in self.s.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

fn d_true() -> bool {
    true
}
fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    app_id: String,
    client_secret: String,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    /// Send Markdown replies and keyboards as msg_type 2 (needs the markdown permission).
    #[serde(default = "d_true")]
    markdown_support: bool,
    /// Gateway intents bitmask (default C2C/group @ + public guild @ + guild DM + interactions).
    #[serde(default)]
    intents: Option<u64>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Webhook mode: receive QQ's HTTP callbacks here instead of the gateway.
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    webhook_path: Option<String>,
    /// SILK decoder: a program path (`silk_v3_decoder` argument convention) or an argv
    /// template with `{in}`, `{out}`, `{rate}`.
    #[serde(default)]
    silk_decoder: Option<Value>,
    /// SILK encoder: a program path (`silk_v3_encoder … -tencent`) or an argv template.
    #[serde(default)]
    silk_encoder: Option<Value>,
    #[serde(default)]
    silk_rate: Option<u32>,
    #[serde(default)]
    ffmpeg: Option<String>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let app_id = ctx.secret("app_id", &st.app_id)?;
    let secret = ctx.secret("client_secret", &st.client_secret)?;
    let mut c = Config::new(ctx.name, &app_id, &secret, ctx.state("qqbot.json"));
    if let Some(b) = st.api_base {
        c.api_base = b;
    }
    if let Some(u) = st.token_url {
        c.token_url = u;
    }
    c.markdown = st.markdown_support;
    c.intents = st.intents.unwrap_or(DEFAULT_INTENTS);
    c.poll_timeout = Duration::from_secs(st.poll_timeout_secs.max(1));
    if let Some(l) = st.listen {
        c.webhook = Some((l, st.webhook_path.unwrap_or_else(|| "/qqbot/webhook".into())));
    } else if st.webhook_path.is_some() {
        return Err(format!("channel {}: webhook_path needs listen", ctx.name));
    }
    let argv = |v: &Option<Value>, enc: bool| -> Result<Option<Vec<String>>, String> {
        match v {
            None => Ok(None),
            Some(Value::String(bin)) if !bin.trim().is_empty() => Ok(Some(silk::default_argv(bin.trim(), enc))),
            Some(Value::Array(a)) if !a.is_empty() && a.iter().all(Value::is_string) => Ok(Some(a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())),
            Some(_) => Err(format!("channel {}: silk_decoder/silk_encoder must be a program path or a non-empty argv list", ctx.name)),
        }
    };
    c.silk.decoder = argv(&st.silk_decoder, false)?;
    c.silk.encoder = argv(&st.silk_encoder, true)?;
    if let Some(r) = st.silk_rate {
        c.silk.rate = r;
    }
    if let Some(f) = st.ffmpeg {
        c.silk.ffmpeg = f;
    }
    Ok(Arc::new(QqBot::new(c)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer, Req};
    use seagent_net::ws::read_head;
    use std::net::{TcpListener, TcpStream};

    type Reply = (u16, Vec<(String, String)>, String);

    fn token_ok() -> Reply {
        (200, vec![], json!({"access_token": "TOK", "expires_in": "7200"}).to_string())
    }

    /// Fake QQ REST: token endpoint, `/gateway`, and `other` for everything else.
    fn rest(gw: String, other: impl Fn(&Req, usize) -> Reply + Send + 'static) -> FakeServer {
        FakeServer::start(move |r, n| {
            if r.path == "/app/getAppAccessToken" {
                return token_ok();
            }
            if r.path == "/gateway" {
                return (200, vec![], json!({"url": gw}).to_string());
            }
            other(r, n)
        })
    }

    fn cfg(api: &str, tag: &str) -> Config {
        let mut c = Config::new("qq", "APPID", "SECRETVALUE", temp_dir(tag).join("qq.json"));
        c.api_base = api.into();
        c.token_url = format!("{api}/app/getAppAccessToken");
        c.retry_base = Duration::from_millis(5);
        c.backoff = vec![Duration::from_millis(20)];
        c.rate_limit_delay = Duration::from_millis(20);
        c.poll_timeout = Duration::from_millis(300);
        c.part_finish_interval = Duration::from_millis(5);
        c
    }

    fn bot(api: &str, tag: &str) -> QqBot {
        QqBot::new(cfg(api, tag)).unwrap()
    }

    fn ws_accept(l: &TcpListener) -> WebSocket<TcpStream> {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (head, rest) = read_head(&mut s, 65536).unwrap();
        WebSocket::accept(s, &head, rest).unwrap()
    }

    /// Next client frame with this op (skipping heartbeats etc.).
    fn expect_op(ws: &mut WebSocket<TcpStream>, op: i64, seen_hb: &mut Vec<Value>) -> Value {
        loop {
            match ws.recv_blocking().unwrap() {
                Message::Text(t) => {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    if v["op"] == op {
                        return v;
                    }
                    if v["op"] == 1 {
                        seen_hb.push(v["d"].clone());
                    }
                }
                m => panic!("unexpected {m:?}"),
            }
        }
    }

    fn send(ws: &mut WebSocket<TcpStream>, v: Value) {
        ws.send_text(&v.to_string()).unwrap();
    }

    fn poll_n(b: &QqBot, n: usize) -> Vec<Inbound> {
        let mut got = vec![];
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(b.poll(&Cancel::new()).unwrap());
        }
        got
    }

    #[test]
    fn parses_every_event_kind() {
        let c2c = json!({"id": "M1", "content": " hi ", "timestamp": "2023-11-06T13:37:18+08:00", "author": {"user_openid": "U1"}, "attachments": [
            {"content_type": "image/png", "url": "//cdn.qq/img.png", "filename": "a.png", "size": 10},
            {"content_type": "voice", "url": "https://cdn.qq/v.silk", "filename": "v.silk", "asr_refer_text": "你好"},
            {"content_type": "file", "url": "https://cdn.qq/r.wav", "filename": "r.wav"},
            {"content_type": "video/mp4", "url": "https://cdn.qq/m.mp4"},
            {"content_type": "image/png"}
        ]});
        let i = inbound_of("qq", "C2C_MESSAGE_CREATE", &c2c, "BOT").unwrap();
        assert_eq!((i.chat.as_str(), i.sender.as_str(), i.text.as_str(), i.message_id.as_str(), i.chat_type), ("c2c:U1", "U1", "hi", "M1", ChatType::Direct));
        assert_eq!(i.ts, 1699249038);
        let kinds: Vec<MediaKind> = i.media.iter().map(|m| m.kind).collect();
        assert_eq!(kinds, [MediaKind::Image, MediaKind::Voice, MediaKind::Document, MediaKind::Video], "url-less attachment dropped; explicit file stays a file");
        assert_eq!(i.media[0].url.as_deref(), Some("https://cdn.qq/img.png"));
        assert_eq!(i.media[1].caption.as_deref(), Some("你好"));
        assert!(i.addressed());

        let g = inbound_of("qq", "GROUP_AT_MESSAGE_CREATE", &json!({"id": "G1", "group_openid": "GRP", "content": "@SeagentBot  do it", "timestamp": "1700000000000", "author": {"member_openid": "MEM"}}), "BOT").unwrap();
        assert_eq!((g.chat.as_str(), g.sender.as_str(), g.text.as_str(), g.chat_type, g.mentioned, g.ts), ("group:GRP", "MEM", "do it", ChatType::Group, true, 1700000000));
        let g2 = inbound_of("qq", "GROUP_MESSAGE_CREATE", &json!({"id": "G2", "group_openid": "GRP", "content": "chatter", "author": {"member_openid": "MEM"}}), "BOT").unwrap();
        assert!(!g2.mentioned && g2.text == "chatter");

        let at = inbound_of("qq", "AT_MESSAGE_CREATE", &json!({"id": "C1", "channel_id": "CH", "guild_id": "GU", "content": "<@!BOT> status", "author": {"id": "A1", "username": "amy"}, "member": {"nick": "Amy"}}), "BOT").unwrap();
        assert_eq!((at.chat.as_str(), at.text.as_str(), at.sender_name.as_str(), at.mentioned), ("channel:CH", "status", "Amy", true));
        let plain = inbound_of("qq", "MESSAGE_CREATE", &json!({"id": "C2", "channel_id": "CH", "content": "just talk", "author": {"id": "A1"}}), "BOT").unwrap();
        assert!(!plain.mentioned);
        let tagged = inbound_of("qq", "GUILD_MESSAGE_CREATE", &json!({"id": "C3", "channel_id": "CH", "content": "hey <@BOT>", "author": {"id": "A1"}}), "BOT").unwrap();
        assert!(tagged.mentioned && tagged.text == "hey");
        assert!(inbound_of("qq", "MESSAGE_CREATE", &json!({"id": "C4", "channel_id": "CH", "content": "mine", "author": {"id": "BOT", "bot": true}}), "BOT").is_none(), "own message dropped");
        let other_bot = inbound_of("qq", "MESSAGE_CREATE", &json!({"id": "C5", "channel_id": "CH", "content": "beep", "author": {"id": "B2", "bot": true}}), "BOT").unwrap();
        assert!(other_bot.is_bot);

        let dm = inbound_of("qq", "DIRECT_MESSAGE_CREATE", &json!({"id": "D1", "guild_id": "DG", "channel_id": "x", "content": "secret", "author": {"id": "A2"}}), "BOT").unwrap();
        assert_eq!((dm.chat.as_str(), dm.chat_type), ("dm:DG", ChatType::Direct));

        let quote = inbound_of("qq", "C2C_MESSAGE_CREATE", &json!({"id": "Q1", "content": "and this?", "author": {"user_openid": "U1"}, "message_type": 103, "message_reference": {"message_id": "OLD"}, "msg_elements": [{"content": "earlier"}, {"content": "text"}]}), "").unwrap();
        let r = quote.reply.unwrap();
        assert_eq!((r.id.as_str(), r.text.as_str()), ("OLD", "earlier text"));

        assert!(inbound_of("qq", "C2C_MESSAGE_CREATE", &json!({"id": "E", "content": "  ", "author": {"user_openid": "U1"}}), "").is_none(), "empty dropped");
        assert!(inbound_of("qq", "GUILD_MEMBER_ADD", &json!({"id": "X"}), "").is_none());

        let cb = interaction_of("qq", &json!({"id": "I1", "chat_type": 1, "group_openid": "GRP", "group_member_openid": "MEM", "data": {"type": 11, "resolved": {"button_data": "appr:1:once", "button_id": "0_0", "message_id": "BM"}}})).unwrap();
        assert_eq!((cb.chat.as_str(), cb.sender.as_str(), cb.message_id.as_str()), ("group:GRP", "MEM", "cb:I1"));
        assert_eq!(cb.callback.unwrap(), Callback { id: "I1".into(), data: "appr:1:once".into() });
        assert!(cb.reply.unwrap().is_own);
        let c2 = interaction_of("qq", &json!({"id": "I2", "chat_type": 2, "user_openid": "U9", "data": {"resolved": {"button_data": "x"}}})).unwrap();
        assert_eq!((c2.chat.as_str(), c2.chat_type), ("c2c:U9", ChatType::Direct));
    }

    #[test]
    fn targets_and_timestamps() {
        assert_eq!(parse_target("qqbot:group:G").unwrap(), Target::Group("G".into()));
        assert_eq!(parse_target("OPENID").unwrap(), Target::C2c("OPENID".into()));
        assert_eq!(parse_target("channel:1").unwrap().base(), "/channels/1");
        assert_eq!(parse_target("dm:9").unwrap().base(), "/dms/9");
        assert!(parse_target("planet:x").is_err());
        assert!(parse_target("c2c:../x").is_err());
        assert_eq!(parse_ts("2024-02-29T00:00:00Z"), 1709164800);
        assert_eq!(parse_ts("2024-02-29T00:00:00.123-01:30"), 1709164800 + 5400);
        assert_eq!(parse_ts("garbage"), 0);
    }

    #[test]
    fn md5_known_answers() {
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&Md5::digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(&Md5::digest(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")), "57edf4a22be3c955ac49da2e2107b67a");
        let mut m = Md5::new();
        for _ in 0..1000 {
            m.update(&[b'a'; 1000]);
        }
        assert_eq!(hex(&m.finish()), "7707d6ae4e027c70eea2a935c2296f21", "one million 'a'");
        let p = temp_dir("qqmd5").join("f");
        std::fs::write(&p, b"abc").unwrap();
        let (md5, sha1, ten) = file_hashes(p.to_str().unwrap(), 3).unwrap();
        assert_eq!((md5.as_str(), sha1.as_str(), ten.as_str()), ("900150983cd24fb0d6963f7d28e17f72", "a9993e364706816aba3e25717850c26c9cd0d89d", "900150983cd24fb0d6963f7d28e17f72"));
    }

    #[test]
    fn gateway_identify_heartbeat_resume_and_reidentify() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let gw = format!("ws://{}/ws", l.local_addr().unwrap());
        let srv = rest(gw, |_, _| (200, vec![], "{}".into()));
        let state = temp_dir("qqgw").join("qq.json");
        let mut c = cfg(&srv.url, "qqgw");
        c.state = state.clone();
        let b = QqBot::new(c).unwrap();
        let server = std::thread::spawn(move || {
            let mut hbs = vec![];
            // 1st connection: Identify → READY → messages → dropped without a close frame.
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 100}}));
            let id = expect_op(&mut ws, 2, &mut hbs);
            send(&mut ws, json!({"op": 0, "s": 1, "t": "READY", "d": {"session_id": "S1", "user": {"id": "BOT"}}}));
            send(&mut ws, json!({"op": 0, "s": 2, "t": "C2C_MESSAGE_CREATE", "d": {"id": "M1", "content": "hello", "author": {"user_openid": "U1"}}}));
            send(&mut ws, json!({"op": 0, "s": 3, "t": "INTERACTION_CREATE", "d": {"id": "I1", "chat_type": 2, "user_openid": "U1", "data": {"resolved": {"button_data": "cl:1:2"}}}}));
            expect_op(&mut ws, 1, &mut hbs);
            let hb = expect_op(&mut ws, 1, &mut hbs);
            send(&mut ws, json!({"op": 11}));
            drop(ws);
            // 2nd: Resume with the stored session + seq, then Invalid Session (not resumable).
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            let resume = expect_op(&mut ws, 6, &mut hbs);
            send(&mut ws, json!({"op": 0, "s": 4, "t": "RESUMED", "d": {}}));
            send(&mut ws, json!({"op": 0, "s": 5, "t": "GROUP_AT_MESSAGE_CREATE", "d": {"id": "G1", "group_openid": "GRP", "content": "@bot yo", "author": {"member_openid": "MEM"}}}));
            send(&mut ws, json!({"op": 9, "d": false}));
            std::thread::sleep(Duration::from_millis(100));
            drop(ws);
            // 3rd: fresh Identify.
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            let again = expect_op(&mut ws, 2, &mut hbs);
            send(&mut ws, json!({"op": 0, "s": 1, "t": "READY", "d": {"session_id": "S2", "user": {"id": "BOT"}}}));
            send(&mut ws, json!({"op": 7}));
            std::thread::sleep(Duration::from_millis(100));
            drop(ws);
            // 4th: op 7 reconnect resumes S2.
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            let r2 = expect_op(&mut ws, 6, &mut hbs);
            (id, hb, resume, again, r2, ws)
        });
        let got = poll_n(&b, 3);
        let (id, hb, resume, again, r2, _ws) = server.join().unwrap();
        assert_eq!(id["d"]["token"], "QQBot TOK");
        assert_eq!(id["d"]["intents"], DEFAULT_INTENTS);
        assert_eq!(id["d"]["shard"], json!([0, 1]));
        assert_eq!(hb["d"], 3, "heartbeat carries the latest seq");
        assert_eq!(resume["d"], json!({"token": "QQBot TOK", "session_id": "S1", "seq": 3}));
        assert_eq!(again["op"], 2, "op 9 false clears the session");
        assert_eq!((r2["d"]["session_id"].as_str(), r2["d"]["seq"].as_i64()), (Some("S2"), Some(1)));
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].chat.as_str(), got[0].text.as_str()), ("c2c:U1", "hello"));
        assert_eq!(got[1].callback.as_ref().unwrap().data, "cl:1:2");
        assert!(got[2].mentioned && got[2].text == "yo");
        // Interaction was ACKed at once.
        let until = Instant::now() + Duration::from_secs(3);
        while !srv.requests().iter().any(|r| r.path == "/interactions/I1") && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let ack = srv.requests().into_iter().find(|r| r.path == "/interactions/I1").expect("ack");
        assert_eq!((ack.method.as_str(), ack.json()["code"].as_i64(), ack.header("authorization")), ("PUT", Some(0), Some("QQBot TOK")));
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/app/getAppAccessToken").count(), 1, "token cached");
        b.stop();
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((saved["session_id"].as_str(), saved["bot_id"].as_str()), (Some("S2"), Some("BOT")), "session persisted for resume after restart");
        // A restarted channel resumes from the state file.
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let srv2 = rest(format!("ws://{}/", l2.local_addr().unwrap()), |_, _| (200, vec![], "{}".into()));
        let mut c = cfg(&srv2.url, "qqgw");
        c.state = state;
        let b2 = QqBot::new(c).unwrap();
        let t = std::thread::spawn(move || {
            let mut ws = ws_accept(&l2);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            expect_op(&mut ws, 6, &mut vec![])
        });
        let _ = b2.poll(&Cancel::new());
        let r = t.join().unwrap();
        assert_eq!(r["d"]["session_id"], "S2");
        b2.stop();
    }

    #[test]
    fn fatal_close_code_surfaces_and_bad_token_closes_refresh() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let srv = rest(format!("ws://{}/", l.local_addr().unwrap()), |_, _| (200, vec![], "{}".into()));
        let b = bot(&srv.url, "qqfatal");
        std::thread::spawn(move || {
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            expect_op(&mut ws, 2, &mut vec![]);
            ws.send(&Message::Close(Some((4004, "invalid token".into())))).unwrap();
            let mut ws = ws_accept(&l);
            send(&mut ws, json!({"op": 10, "d": {"heartbeat_interval": 30000}}));
            expect_op(&mut ws, 2, &mut vec![]);
            ws.send(&Message::Close(Some((4914, "offline".into())))).unwrap();
        });
        let until = Instant::now() + Duration::from_secs(10);
        let err = loop {
            match b.poll(&Cancel::new()) {
                Err(e) => break e,
                Ok(_) => assert!(Instant::now() < until, "fatal close never surfaced"),
            }
        };
        assert_eq!(err.kind, K::Fatal);
        assert!(err.message.contains("4914"), "{}", err.message);
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/app/getAppAccessToken").count(), 2, "4004 refreshed the token");
    }

    #[test]
    fn bad_credentials_are_auth_without_leaking_secret() {
        let srv = FakeServer::start(|r, _| {
            if r.path == "/app/getAppAccessToken" {
                return (200, vec![], json!({"code": 100016, "message": "invalid appid or secret"}).to_string());
            }
            (500, vec![], "".into())
        });
        let b = bot(&srv.url, "qqauth");
        let e = b.poll(&Cancel::new()).err().or_else(|| b.poll(&Cancel::new()).err()).expect("auth error");
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("SECRETVALUE"));
        let e = b.send(&Outbound::text("c2c:U", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert_eq!(srv.requests()[0].json(), json!({"appId": "APPID", "clientSecret": "SECRETVALUE"}));
    }

    #[test]
    fn cancel_returns_promptly_while_gateway_is_silent() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let srv = rest(format!("ws://{}/", l.local_addr().unwrap()), |_, _| (200, vec![], "{}".into()));
        let mut c = cfg(&srv.url, "qqcancel");
        c.poll_timeout = Duration::from_secs(30);
        let b = QqBot::new(c).unwrap();
        let _keep = std::thread::spawn(move || {
            let _ws = ws_accept(&l);
            std::thread::sleep(Duration::from_secs(5));
        });
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(b.poll(&cancel).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        let start = Instant::now();
        b.stop();
        assert!(start.elapsed() < Duration::from_secs(2), "worker stops promptly");
    }

    #[test]
    fn send_shapes_for_every_target() {
        let srv = rest(String::new(), |_, n| (200, vec![], json!({"id": format!("R{n}"), "timestamp": "x"}).to_string()));
        let b = bot(&srv.url, "qqsend");
        let s = b.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("M1".into()), ..Outbound::text("c2c:U1", "**hi**") }).unwrap();
        assert_eq!(s.ids, ["R1"]);
        let r = srv.requests()[1].clone();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.header("authorization")), ("POST", "/v2/users/U1/messages", Some("QQBot TOK")));
        let j = r.json();
        assert_eq!((j["markdown"]["content"].as_str(), j["msg_type"].as_i64(), j["msg_id"].as_str()), (Some("**hi**"), Some(2), Some("M1")));
        let seq1 = j["msg_seq"].as_u64().unwrap();
        // Second reply to the same message needs a new msg_seq.
        b.send(&Outbound { reply_to: Some("M1".into()), ..Outbound::text("c2c:U1", "again") }).unwrap();
        let j = srv.requests()[2].json();
        assert_eq!((j["content"].as_str(), j["msg_type"].as_i64(), j["message_reference"]["message_id"].as_str()), (Some("again"), Some(0), Some("M1")));
        assert_ne!(j["msg_seq"].as_u64().unwrap(), seq1);
        // Group with buttons → markdown + keyboard.
        let buttons = vec![vec![crate::Button { label: "允许".into(), data: "appr:x:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]];
        b.send(&Outbound { buttons: buttons.clone(), reply_to: Some("G1".into()), ..Outbound::text("group:GRP", "pick") }).unwrap();
        let r = srv.requests()[3].clone();
        assert_eq!(r.path, "/v2/groups/GRP/messages");
        let kb = &r.json()["keyboard"]["content"]["rows"][0]["buttons"];
        assert_eq!((kb[0]["action"]["type"].as_i64(), kb[0]["action"]["data"].as_str(), kb[0]["render_data"]["label"].as_str()), (Some(1), Some("appr:x:once"), Some("允许")));
        assert_eq!((kb[1]["action"]["type"].as_i64(), kb[1]["action"]["data"].as_str()), (Some(0), Some("https://e.com")));
        assert_eq!(r.json()["msg_type"], 2);
        // Guild channel: plain content, no keyboard → numbered options.
        b.send(&Outbound { buttons, format: TextFormat::Markdown, reply_to: Some("C1".into()), ..Outbound::text("channel:CH", "**pick**") }).unwrap();
        let r = srv.requests()[4].clone();
        assert_eq!(r.path, "/channels/CH/messages");
        assert_eq!(r.json()["content"], "pick\n1. 允许\n2. docs (https://e.com)");
        assert_eq!(r.json()["msg_id"], "C1");
        assert!(r.json().get("msg_seq").is_none() && r.json().get("keyboard").is_none());
        b.send(&Outbound::text("dm:DG", "psst")).unwrap();
        assert_eq!(srv.requests()[5].path, "/dms/DG/messages");
        // No reply_to: the last inbound message id is reused for a passive reply.
        b.inner.last_msg.lock().unwrap().insert("group:GRP".into(), ("LAST".into(), Instant::now()));
        b.send(&Outbound::text("group:GRP", "follow-up")).unwrap();
        let j = srv.requests()[6].json();
        assert_eq!(j["msg_id"], "LAST");
        assert!(j.get("message_reference").is_none());
        // Long text is chunked; every piece carries msg_id.
        let long = "字".repeat(MAX_MESSAGE * 2);
        let s = b.send(&Outbound { reply_to: Some("M9".into()), ..Outbound::text("c2c:U1", &long) }).unwrap();
        assert!(s.ids.len() >= 2);
        let reqs = srv.requests();
        let parts: Vec<String> = reqs[7..].iter().map(|r| r.json()["content"].as_str().unwrap().to_string()).collect();
        assert_eq!(parts.concat(), long);
        assert!(reqs[7..].iter().all(|r| r.json()["msg_id"] == "M9"));
        assert!(reqs[8].json().get("message_reference").is_none(), "only the first piece quotes");
        assert!(b.send(&Outbound::text("c2c:U1", " ")).unwrap().ids.is_empty());
    }

    #[test]
    fn media_url_base64_and_chunked_upload() {
        let put_server = FakeServer::start(|_, _| (200, vec![], String::new()));
        let cos = put_server.url.clone();
        let finished = Arc::new(Mutex::new(0usize));
        let f2 = finished.clone();
        let srv = rest(String::new(), move |r, _| match r.path.rsplit('/').next().unwrap() {
            "files" if r.json().get("upload_id").is_some() => (200, vec![], json!({"file_info": "FI-CHUNK"}).to_string()),
            "files" => (200, vec![], json!({"file_uuid": "u", "file_info": "FI", "ttl": 0}).to_string()),
            "upload_prepare" => (200, vec![], json!({"data": {"upload_id": "UP", "block_size": 4, "parts": [{"part_index": 1, "presigned_url": format!("{cos}/p1")}, {"part_index": 2, "presigned_url": format!("{cos}/p2")}]}}).to_string()),
            "upload_part_finish" => {
                let mut g = f2.lock().unwrap();
                *g += 1;
                if *g == 1 {
                    (400, vec![], json!({"code": 40093001, "message": "retry"}).to_string())
                } else {
                    (200, vec![], "{}".into())
                }
            }
            _ => (200, vec![], json!({"id": "MSG"}).to_string()),
        });
        let mut c = cfg(&srv.url, "qqmedia");
        c.chunk_threshold = 6;
        let b = QqBot::new(c).unwrap();
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        let s = b.send(&Outbound { media: vec![img.clone()], reply_to: Some("G1".into()), ..Outbound::text("group:GRP", "cap") }).unwrap();
        assert_eq!(s.ids, ["MSG"]);
        let r = srv.requests();
        assert_eq!(r[1].path, "/v2/groups/GRP/files");
        assert_eq!(r[1].json(), json!({"file_type": 1, "url": "https://e.com/a.png", "srv_send_msg": false}));
        assert_eq!(r[2].path, "/v2/groups/GRP/messages");
        assert_eq!((r[2].json()["msg_type"].as_i64(), r[2].json()["media"]["file_info"].as_str(), r[2].json()["content"].as_str(), r[2].json()["msg_id"].as_str()), (Some(7), Some("FI"), Some("cap"), Some("G1")));
        // Small local file → base64 file_data with file_name.
        let dir = temp_dir("qqmedia");
        let small = dir.join("r.pdf");
        std::fs::write(&small, b"%PDF").unwrap();
        b.send(&Outbound { media: vec![Media { kind: MediaKind::Document, path: Some(small.display().to_string()), ..Default::default() }], ..Outbound::text("c2c:U1", "") }).unwrap();
        let r = srv.requests();
        assert_eq!(r[3].path, "/v2/users/U1/files");
        assert_eq!(r[3].json(), json!({"file_type": 4, "file_data": "JVBERg==", "srv_send_msg": false, "file_name": "r.pdf"}));
        // Large local file → chunked: prepare, 2 COS PUTs, part_finish (one retryable miss), complete.
        let big = dir.join("v.mp4");
        std::fs::write(&big, b"abcdefg").unwrap();
        b.send(&Outbound { media: vec![Media { kind: MediaKind::Video, path: Some(big.display().to_string()), ..Default::default() }], ..Outbound::text("c2c:U1", "") }).unwrap();
        let r = srv.requests();
        let prep = r.iter().find(|q| q.path.ends_with("/upload_prepare")).unwrap().json();
        assert_eq!(prep, json!({"file_type": 2, "file_name": "v.mp4", "file_size": 7, "md5": hex(&Md5::digest(b"abcdefg")), "sha1": hex(&seagent_net::crypto::sha1(b"abcdefg")), "md5_10m": hex(&Md5::digest(b"abcdefg"))}));
        let puts = put_server.requests();
        assert_eq!((puts.len(), puts[0].path.as_str(), puts[0].body.as_str(), puts[1].body.as_str()), (2, "/p1", "abcd", "efg"));
        let fins: Vec<Value> = r.iter().filter(|q| q.path.ends_with("/upload_part_finish")).map(|q| q.json()).collect();
        assert_eq!(fins.len(), 3, "40093001 is retried");
        assert_eq!(fins[2], json!({"upload_id": "UP", "part_index": 2, "block_size": 3, "md5": hex(&Md5::digest(b"efg"))}));
        let last = r.last().unwrap();
        assert_eq!((last.path.as_str(), last.json()["media"]["file_info"].as_str()), ("/v2/users/U1/messages", Some("FI-CHUNK")));
        // Guild channel image by URL.
        b.send(&Outbound { media: vec![img], ..Outbound::text("channel:CH", "") }).unwrap();
        let last = srv.requests().last().unwrap().clone();
        assert_eq!((last.path.as_str(), last.json()["image"].as_str()), ("/channels/CH/messages", Some("https://e.com/a.png")));
        let doc = Media { kind: MediaKind::Document, path: Some(small.display().to_string()), ..Default::default() };
        assert_eq!(b.send(&Outbound { media: vec![doc], ..Outbound::text("channel:CH", "") }).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn error_mapping_and_retries() {
        let cases: Vec<(u16, Value, K, usize)> = vec![
            (404, json!({"code": 11255, "message": "not found"}), K::NotFound, 1),
            (400, json!({"code": 40034006, "message": "bad"}), K::Protocol, 1),
            (500, json!({"message": "oops"}), K::Network, 3),
            (429, json!({"code": 22009, "message": "msg limit exceed"}), K::RateLimited { retry_after: None }, 3),
            (400, json!({"code": 40093002, "message": "daily"}), K::Fatal, 1),
            (403, json!({"message": "forbidden"}), K::Auth, 1),
        ];
        for (status, body, kind, calls) in cases {
            let b2 = body.clone();
            let srv = rest(String::new(), move |_, _| (status, vec![], b2.to_string()));
            let b = bot(&srv.url, "qqerr");
            let e = b.send(&Outbound::text("c2c:U", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {body}");
            assert!(!e.message.contains("TOK") && !e.message.contains("SECRETVALUE"));
            assert_eq!(srv.requests().len() - 1, calls, "{status} attempts");
        }
        // 429 with Retry-After is honoured then succeeds.
        let srv = rest(String::new(), |_, n| if n == 1 { (429, vec![("Retry-After".into(), "1".into())], "{}".into()) } else { (200, vec![], json!({"id": "OK"}).to_string()) });
        let b = bot(&srv.url, "qqerr");
        let start = Instant::now();
        assert_eq!(b.send(&Outbound::text("c2c:U", "x")).unwrap().ids, ["OK"]);
        assert!(start.elapsed() >= Duration::from_millis(950));
        let srv = rest(String::new(), |_, _| (429, vec![("Retry-After".into(), "3600".into())], "{}".into()));
        let e = bot(&srv.url, "qqerr").send(&Outbound::text("c2c:U", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        // 401 refreshes the token once, then gives up as Auth.
        let srv = rest(String::new(), |_, _| (401, vec![], json!({"code": 11244, "message": "token invalid"}).to_string()));
        let e = bot(&srv.url, "qqerr").send(&Outbound::text("c2c:U", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        let paths: Vec<String> = srv.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, ["/app/getAppAccessToken", "/v2/users/U/messages", "/app/getAppAccessToken", "/v2/users/U/messages"]);
        // Unreachable host → Network.
        let mut c = cfg("http://127.0.0.1:1", "qqerr");
        c.max_retries = 0;
        assert_eq!(QqBot::new(c).unwrap().send(&Outbound::text("c2c:U", "x")).unwrap_err().kind, K::Network);
    }

    #[test]
    fn typing_delete_and_fetch_media() {
        let srv = rest(String::new(), |r, _| if r.path == "/cdn/f.png" { (200, vec![], "PNG".into()) } else { (200, vec![], json!({"id": "X"}).to_string()) });
        let b = bot(&srv.url, "qqmisc");
        b.typing("c2c:U1", None).unwrap();
        assert_eq!(srv.requests().len(), 0, "no inbound msg_id yet → no typing call");
        b.inner.last_msg.lock().unwrap().insert("c2c:U1".into(), ("M1".into(), Instant::now()));
        b.typing("c2c:U1", None).unwrap();
        b.typing("c2c:U1", None).unwrap();
        b.typing("group:G", None).unwrap();
        let r = srv.requests();
        assert_eq!(r.len(), 2, "debounced, group ignored");
        assert_eq!(r[1].path, "/v2/users/U1/messages");
        assert_eq!((r[1].json()["msg_type"].as_i64(), r[1].json()["msg_id"].as_str(), r[1].json()["input_notify"]["input_second"].as_i64()), (Some(6), Some("M1"), Some(60)));
        b.delete("group:G", "MID").unwrap();
        b.delete("channel:C", "MID").unwrap();
        let r = srv.requests();
        assert_eq!((r[2].method.as_str(), r[2].path.as_str()), ("DELETE", "/v2/groups/G/messages/MID"));
        assert_eq!(r[3].path, "/channels/C/messages/MID?hidetip=false");
        assert!(b.edit("c2c:U1", "M", "x").is_err());
        let bytes = b.fetch_media(&Media { url: Some(format!("{}/cdn/f.png", srv.url)), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"PNG");
        assert_eq!(srv.requests().last().unwrap().header("authorization"), Some("QQBot TOK"));
        assert!(b.fetch_media(&Media { url: Some("file:///etc/passwd".into()), ..Default::default() }).is_err());
        assert!(b.caps().buttons && b.caps().delete && !b.caps().edit);
    }

    fn hook_post(addr: std::net::SocketAddr, path: &str, seed: &[u8; 32], body: &str, sign: bool) -> (u16, String) {
        let ts = "1725442341";
        let mut msg = ts.as_bytes().to_vec();
        msg.extend_from_slice(body.as_bytes());
        let sig = seagent_net::crypto::hex(&seagent_net::crypto::ed25519_sign(seed, &msg));
        let a = crate::http::agent(Duration::from_secs(5));
        let mut req = a.post(&format!("http://{addr}{path}")).header("X-Signature-Timestamp", ts);
        if sign {
            req = req.header("X-Signature-Ed25519", &sig);
        }
        match req.send(body.as_bytes()) {
            Ok(mut r) => (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()),
            Err(ureq::Error::StatusCode(c)) => (c, String::new()),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn webhook_validation_signatures_dispatch_and_dedup() {
        let srv = rest(String::new(), |_, _| (200, vec![], "{}".into()));
        let mut c = cfg(&srv.url, "qqhook");
        c.webhook = Some(("127.0.0.1:0".into(), "/qq".into()));
        let b = QqBot::new(c).unwrap();
        let a = b.webhook_addr().unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&b"SECRETVALUE".repeat(3)[..32]);
        // op 13: echo plain_token with sign(event_ts + plain_token).
        let (st, body) = hook_post(a, "/qq", &seed, &json!({"op": 13, "d": {"plain_token": "Arq0D5A61EgUu4OxUvOp", "event_ts": "1725442341"}}).to_string(), true);
        assert_eq!(st, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["plain_token"], "Arq0D5A61EgUu4OxUvOp");
        let sig = seagent_net::crypto::hex_decode(v["signature"].as_str().unwrap()).unwrap();
        assert!(seagent_net::crypto::ed25519_verify(&seagent_net::crypto::ed25519_public(&seed), b"1725442341Arq0D5A61EgUu4OxUvOp", &sig));
        // Unsigned, wrongly signed, wrong path.
        let ev = json!({"op": 0, "id": "EV1", "s": 3, "t": "C2C_MESSAGE_CREATE", "d": {"id": "M1", "content": "hi", "timestamp": "2024-01-01T00:00:00+08:00", "author": {"user_openid": "U1"}}}).to_string();
        assert_eq!(hook_post(a, "/qq", &seed, &ev, false).0, 401);
        assert_eq!(hook_post(a, "/qq", &[7u8; 32], &ev, true).0, 401);
        assert_eq!(hook_post(a, "/other", &seed, &ev, true).0, 404);
        // Dispatch → queued once, acknowledged with op 12 each time.
        let (st, body) = hook_post(a, "/qq", &seed, &ev, true);
        assert_eq!((st, serde_json::from_str::<Value>(&body).unwrap()), (200, json!({"op": 12, "d": 0})));
        assert_eq!(hook_post(a, "/qq", &seed, &ev, true).0, 200);
        let inter = json!({"op": 0, "id": "EV2", "t": "INTERACTION_CREATE", "d": {"id": "I9", "chat_type": 2, "user_openid": "U1", "data": {"type": 11, "resolved": {"button_data": "appr:1:once"}}}}).to_string();
        hook_post(a, "/qq", &seed, &inter, true);
        let got = poll_n(&b, 2);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!((got[0].chat.as_str(), got[0].text.as_str()), ("c2c:U1", "hi"));
        assert_eq!(got[1].callback.as_ref().unwrap().data, "appr:1:once");
        assert!(b.poll(&Cancel::new()).unwrap().is_empty(), "retried event id not queued twice");
        let until = Instant::now() + Duration::from_secs(3);
        while !srv.requests().iter().any(|r| r.path == "/interactions/I9") && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(srv.requests().iter().any(|r| r.method == "PUT" && r.path == "/interactions/I9"));
        assert!(!srv.requests().iter().any(|r| r.path == "/gateway"), "webhook mode opens no gateway");
        b.stop();
    }

    fn sh(script: &str) -> Vec<String> {
        ["sh", "-c", script, "sh", "{in}", "{out}", "{rate}"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn silk_voice_decode_encode_and_wav_url() {
        // QQ's pre-converted WAV wins over the SILK original.
        let m = media_of(&json!([{"content_type": "voice", "url": "https://cdn/v.silk", "filename": "v.silk", "voice_wav_url": "//cdn/v.wav", "asr_refer_text": "你好"}]));
        assert_eq!((m[0].url.as_deref(), m[0].name.as_str(), m[0].mime.as_str(), m[0].caption.as_deref()), (Some("https://cdn/v.wav"), "v.wav", "audio/wav", Some("你好")));
        // Fake decoder: drops the 10-byte `\x02#!SILK_V3` header, the rest is "PCM".
        let srv = rest(String::new(), |r, _| match r.path.as_str() {
            "/cdn/v.silk" => (200, vec![], "\u{2}#!SILK_V3abcd".into()),
            "/cdn/n.amr" => (200, vec![], "#!AMR\nxx".into()),
            _ => (200, vec![], json!({"file_info": "FI", "id": "MSG"}).to_string()),
        });
        let mut c = cfg(&srv.url, "qqsilk");
        c.silk.decoder = Some(sh("tail -c +11 \"$1\" > \"$2\""));
        c.silk.rate = 16000;
        let b = QqBot::new(c.clone()).unwrap();
        let wav = b.fetch_media(&Media { kind: MediaKind::Voice, url: Some(format!("{}/cdn/v.silk", srv.url)), ..Default::default() }).unwrap();
        assert_eq!(wav, silk::wav(b"abcd", 16000));
        assert_eq!(silk::pcm_of_wav(&wav, 16000), Some(&b"abcd"[..]));
        assert_eq!(silk::pcm_of_wav(&wav, 24000), None);
        // Not SILK → bytes untouched.
        assert_eq!(b.fetch_media(&Media { kind: MediaKind::Voice, url: Some(format!("{}/cdn/n.amr", srv.url)), ..Default::default() }).unwrap(), b"#!AMR\nxx");
        // A failing decoder surfaces.
        let mut bad = c.clone();
        bad.silk.decoder = Some(sh("echo nope >&2; exit 3"));
        let e = QqBot::new(bad).unwrap().fetch_media(&Media { kind: MediaKind::Voice, url: Some(format!("{}/cdn/v.silk", srv.url)), ..Default::default() }).unwrap_err();
        assert!(e.message.contains("nope"), "{e}");

        // Encoder: WAV at the codec rate is parsed here; anything else goes through ffmpeg.
        let dir = temp_dir("qqsilk-enc");
        let ff = dir.join("ffmpeg");
        std::fs::write(&ff, "#!/bin/sh\nfor a; do last=$a; done\nprintf FFPCM > \"$last\"\n").unwrap();
        std::fs::set_permissions(&ff, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        c.silk.encoder = Some(sh("[ \"$3\" = 16000 ] || exit 9; printf '\\002#!SILK_V3' > \"$2\"; cat \"$1\" >> \"$2\""));
        c.silk.ffmpeg = ff.display().to_string();
        let b = QqBot::new(c).unwrap();
        let w = dir.join("a.wav");
        std::fs::write(&w, silk::wav(b"PCM1", 16000)).unwrap();
        let o = dir.join("a.ogg");
        std::fs::write(&o, b"OggS....").unwrap();
        for (p, want) in [(&w, &b"PCM1"[..]), (&o, &b"FFPCM"[..])] {
            b.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(p.display().to_string()), ..Default::default() }], ..Outbound::text("c2c:U1", "") }).unwrap();
            let up = srv.requests().into_iter().rfind(|r| r.path == "/v2/users/U1/files").unwrap().json();
            assert_eq!(up["file_type"], 3);
            let mut expect = b"\x02#!SILK_V3".to_vec();
            expect.extend_from_slice(want);
            assert_eq!(seagent_net::crypto::b64_decode(up["file_data"].as_str().unwrap()).unwrap(), expect);
        }
        // Already SILK: passed through untouched.
        let sk = dir.join("b.silk");
        std::fs::write(&sk, b"#!SILK_V3zz").unwrap();
        b.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(sk.display().to_string()), ..Default::default() }], ..Outbound::text("c2c:U1", "") }).unwrap();
        let up = srv.requests().into_iter().rfind(|r| r.path == "/v2/users/U1/files").unwrap().json();
        assert_eq!(seagent_net::crypto::b64_decode(up["file_data"].as_str().unwrap()).unwrap(), b"#!SILK_V3zz");
        assert_eq!(silk::default_argv("enc", true), ["enc", "{in}", "{out}", "-tencent", "-Fs_API", "{rate}"]);
    }

    #[test]
    fn build_parses_settings() {
        let d = temp_dir("qqbuild");
        let secrets: crate::Secrets = Arc::new(|s: &str| s.replace("{{secret:QQ}}", "sek"));
        let ctx = crate::config::Ctx { name: "qq", state_dir: &d, secrets: &secrets };
        let ok = json!({"app_id": "1", "client_secret": "{{secret:QQ}}", "markdown_support": false, "api_base": "http://x"});
        let c = build(&ctx, ok.as_object().unwrap()).unwrap();
        assert_eq!(c.caps().markup, Markup::Plain);
        let missing = json!({"app_id": "1", "client_secret": "{{secret:NOPE}}"});
        assert!(build(&ctx, missing.as_object().unwrap()).err().unwrap().contains("not set"));
        let typo = json!({"app_id": "1", "client_secret": "s", "intens": 1});
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("intens"));
        let empty = json!({"app_id": "", "client_secret": "s"});
        assert!(build(&ctx, empty.as_object().unwrap()).is_err());
        let hook = json!({"app_id": "1", "client_secret": "s", "listen": "127.0.0.1:0", "silk_decoder": "/opt/silk_v3_decoder", "silk_encoder": ["enc", "{in}", "{out}"], "silk_rate": 16000});
        assert!(build(&ctx, hook.as_object().unwrap()).is_ok());
        let bad = json!({"app_id": "1", "client_secret": "s", "silk_decoder": 5});
        assert!(build(&ctx, bad.as_object().unwrap()).err().unwrap().contains("silk_decoder"));
        let orphan = json!({"app_id": "1", "client_secret": "s", "webhook_path": "/q"});
        assert!(build(&ctx, orphan.as_object().unwrap()).err().unwrap().contains("needs listen"));
    }
}
