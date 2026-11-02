//! Twitch chat (ported from OpenClaw `extensions/twitch`, MIT).
//!
//! Chat is IRC over WebSocket (`wss://irc-ws.chat.twitch.tv:443`): `CAP REQ
//! :twitch.tv/tags twitch.tv/commands`, `PASS oauth:<token>`, `NICK <login>`,
//! JOIN the configured channels, PING/PONG, and an immediate reconnect on the
//! server's `RECONNECT`. PRIVMSG tags give the display name, stable user id,
//! message id, send time and the reply parent (a reply to the bot counts as
//! addressed); `@botname` is a mention. Replies go out with the
//! `@reply-parent-msg-id` tag; messages are cut to 500 characters and pass a
//! 20-per-30-seconds flood limiter. The token is validated against
//! `GET id.twitch.tv/oauth2/validate` before every connect and hourly; with a
//! client id/secret and refresh token it is refreshed (`refresh_token` grant)
//! when invalid or about to expire, and the new pair is persisted (0600) so a
//! restart keeps working after Twitch rotates the refresh token.
//!
//! Whispers (`whispers = true`, needs `client_id` and the `user:manage:whispers`
//! scope): inbound `WHISPER` lines from `twitch.tv/commands` become DMs whose
//! chat is `whisper:<login>`; sending to `whisper:<login>` resolves the login
//! with `GET /helix/users?login=` (cached) and posts
//! `POST /helix/whispers?from_user_id=&to_user_id=` with `Client-Id` + Bearer,
//! in 500-character pieces (the limit for a first whisper to someone).
//! OpenClaw has no whisper support; this follows the Helix reference.

use crate::http::{classify, Http, Payload};
use crate::irc::{escape_tag, now_millis, now_secs, parse_line, render_body, sanitize_text, split_text, Backoff, Flood, Line};
use crate::{sleep_cancellable, write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use ark_net::stream::Stream;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_WS: &str = "wss://irc-ws.chat.twitch.tv:443";
pub const DEFAULT_ID: &str = "https://id.twitch.tv";
pub const DEFAULT_HELIX: &str = "https://api.twitch.tv/helix";
/// Twitch chat message limit (characters).
pub const MAX_MESSAGE: usize = 500;
const LIVENESS: Duration = Duration::from_secs(420);
const STABLE: Duration = Duration::from_secs(60);
const GONE_FOR: Duration = Duration::from_secs(600);
/// Refresh this long before the token expires.
const REFRESH_MARGIN: i64 = 300;

#[derive(Debug, Clone)]
pub struct Cfg {
    pub ws_url: String,
    pub id_base: String,
    pub helix_base: String,
    /// Receive `WHISPER`s and send to `whisper:<login>` via Helix.
    pub whispers: bool,
    /// Bot login; empty = learn it from the validate endpoint.
    pub login: String,
    /// Channel logins, lower case, without `#`.
    pub channels: Vec<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub state: PathBuf,
    pub validate_every: Duration,
    pub connect_timeout: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub send_wait: Duration,
    pub flood_burst: u32,
    pub flood_interval: Duration,
}

impl Cfg {
    pub fn new(login: &str, channels: &[&str], state: PathBuf) -> Cfg {
        Cfg {
            ws_url: DEFAULT_WS.into(),
            id_base: DEFAULT_ID.into(),
            helix_base: DEFAULT_HELIX.into(),
            whispers: false,
            login: login.trim().to_ascii_lowercase(),
            channels: channels.iter().filter_map(|c| normalize_channel(c)).collect(),
            client_id: None,
            client_secret: None,
            state,
            validate_every: Duration::from_secs(3600),
            connect_timeout: Duration::from_secs(15),
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            send_wait: Duration::from_secs(10),
            flood_burst: 20,
            flood_interval: Duration::from_millis(1500),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Tokens {
    access: String,
    refresh: Option<String>,
    expires_at: Option<i64>,
}

struct Shared {
    id: String,
    cfg: Cfg,
    ws: Mutex<Option<WebSocket<Stream>>>,
    want_write: AtomicUsize,
    ready: AtomicBool,
    login: Mutex<String>,
    tokens: Mutex<Tokens>,
    /// Fingerprint of the configured token; persisted tokens are used only while it matches.
    seed: String,
    last_validate: Mutex<Option<Instant>>,
    fatal: Mutex<Option<ChannelError>>,
    gone: Mutex<HashMap<String, (String, Instant)>>,
    stop: Cancel,
    flood: Flood,
    seq: AtomicU64,
    tx: Mutex<Sender<Inbound>>,
    http: Http,
    /// Bot user id (from validate), for `from_user_id`.
    user_id: Mutex<String>,
    /// login → user id.
    user_ids: Mutex<HashMap<String, String>>,
}

enum End {
    Retry(String),
    /// Server-requested reconnect: no backoff.
    Reconnect,
    /// IRC login rejected the token.
    AuthFailed(String),
    Fatal(ChannelError),
    Stopped,
}

/// `#Chan`, `twitch:chan` → `chan`; `None` unless a valid Twitch login.
pub fn normalize_channel(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    if t.len() > 7 && t[..7].eq_ignore_ascii_case("twitch:") {
        t = &t[7..];
    }
    let t = t.trim_start_matches('#').to_ascii_lowercase();
    (!t.is_empty() && t.len() <= 25 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some(t)
}

fn seed_of(token: &str) -> String {
    ark_net::crypto::hex(&ark_net::crypto::sha256(token.as_bytes()))[..16].to_string()
}

impl Shared {
    fn write_raw(&self, line: &str) -> std::io::Result<()> {
        let clean: String = line.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        self.want_write.fetch_add(1, Ordering::SeqCst);
        let r = {
            let mut g = self.ws.lock().unwrap();
            match g.as_mut() {
                Some(ws) => ws.send_text(&clean),
                None => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected")),
            }
        };
        self.want_write.fetch_sub(1, Ordering::SeqCst);
        r
    }

    fn login(&self) -> String {
        self.login.lock().unwrap().clone()
    }

    fn can_refresh(&self) -> bool {
        self.cfg.client_id.is_some() && self.cfg.client_secret.is_some() && self.tokens.lock().unwrap().refresh.is_some()
    }

    fn validate(&self) -> Result<(), ChannelError> {
        let tok = self.tokens.lock().unwrap().access.clone();
        let auth = format!("OAuth {tok}");
        let r = self.http.call("GET", &format!("{}/oauth2/validate", self.cfg.id_base), &[("authorization", &auth)], Payload::None)?;
        match r.status {
            200 => {
                let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
                if let Some(l) = v["login"].as_str().filter(|l| !l.is_empty()) {
                    let mut me = self.login.lock().unwrap();
                    if me.is_empty() {
                        *me = l.to_ascii_lowercase();
                    }
                }
                if let Some(u) = v["user_id"].as_str().filter(|u| !u.is_empty()) {
                    *self.user_id.lock().unwrap() = u.to_string();
                }
                if let Some(e) = v["expires_in"].as_i64().filter(|e| *e > 0) {
                    self.tokens.lock().unwrap().expires_at = Some(now_secs() + e);
                }
                *self.last_validate.lock().unwrap() = Some(Instant::now());
                Ok(())
            }
            401 => Err(ChannelError::new(K::Auth, "twitch rejected the access token (invalid or expired)")),
            s => Err(classify(s, r.retry_after, "twitch token validate", &r.body)),
        }
    }

    fn refresh(&self) -> Result<(), ChannelError> {
        let (Some(cid), Some(secret)) = (self.cfg.client_id.as_deref(), self.cfg.client_secret.as_deref()) else {
            return Err(ChannelError::new(K::Auth, "twitch token refresh needs client_id and client_secret"));
        };
        let Some(rt) = self.tokens.lock().unwrap().refresh.clone() else {
            return Err(ChannelError::new(K::Auth, "twitch token refresh needs a refresh_token"));
        };
        let form = [("grant_type", "refresh_token"), ("refresh_token", rt.as_str()), ("client_id", cid), ("client_secret", secret)];
        let r = self.http.call("POST", &format!("{}/oauth2/token", self.cfg.id_base), &[], Payload::Form(&form))?;
        match r.status {
            200 => {}
            400 | 401 | 403 => return Err(ChannelError::new(K::Auth, format!("twitch refused the refresh token (HTTP {}); re-authorize the bot", r.status))),
            s => return Err(classify(s, r.retry_after, "twitch token refresh", "")),
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let access = v["access_token"].as_str().filter(|a| !a.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "twitch token refresh returned no access_token"))?;
        let t = {
            let mut t = self.tokens.lock().unwrap();
            t.access = access.to_string();
            if let Some(n) = v["refresh_token"].as_str().filter(|n| !n.is_empty()) {
                t.refresh = Some(n.to_string());
            }
            t.expires_at = v["expires_in"].as_i64().filter(|e| *e > 0).map(|e| now_secs() + e);
            t.clone()
        };
        self.persist(&t)
    }

    fn persist(&self, t: &Tokens) -> Result<(), ChannelError> {
        let body = json!({"seed": self.seed, "access_token": t.access, "refresh_token": t.refresh, "expires_at": t.expires_at}).to_string();
        let err = |e: std::io::Error| ChannelError::new(K::Fatal, format!("saving twitch tokens: {e}"));
        write_atomic(&self.cfg.state, body.as_bytes()).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.cfg.state, std::fs::Permissions::from_mode(0o600)).map_err(err)?;
        }
        Ok(())
    }

    /// Helix call with `Client-Id` + Bearer; one refresh-and-retry on 401.
    fn helix(&self, method: &str, path: &str, body: Payload) -> Result<crate::http::Resp, ChannelError> {
        let cid = self.cfg.client_id.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "twitch whispers need client_id"))?;
        let mut retried = false;
        loop {
            let auth = format!("Bearer {}", self.tokens.lock().unwrap().access);
            let r = self.http.call(method, &format!("{}{path}", self.cfg.helix_base), &[("client-id", cid), ("authorization", &auth)], body)?;
            if r.status == 401 && !retried && self.can_refresh() {
                retried = true;
                self.refresh()?;
                continue;
            }
            return Ok(r);
        }
    }

    fn user_id_of(&self, login: &str) -> Result<String, ChannelError> {
        if let Some(id) = self.user_ids.lock().unwrap().get(login) {
            return Ok(id.clone());
        }
        let r = self.helix("GET", &format!("/users?{}", ark_net::form_encode(&[("login", login)])), Payload::None)?;
        if r.status != 200 {
            return Err(classify(r.status, r.retry_after, "twitch user lookup", &r.body));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let id = v["data"][0]["id"].as_str().filter(|i| !i.is_empty()).ok_or_else(|| ChannelError::new(K::NotFound, format!("twitch user {login} does not exist")))?;
        self.user_ids.lock().unwrap().insert(login.to_string(), id.to_string());
        Ok(id.to_string())
    }

    fn whisper(&self, login: &str, text: &str) -> Result<Sent, ChannelError> {
        if self.user_id.lock().unwrap().is_empty() {
            self.validate()?;
        }
        let from = self.user_id.lock().unwrap().clone();
        if from.is_empty() {
            return Err(ChannelError::new(K::Fatal, "twitch whispers need a user access token (validate gave no user_id)"));
        }
        let to = self.user_id_of(login)?;
        let q = ark_net::form_encode(&[("from_user_id", &from), ("to_user_id", &to)]);
        let mut sent = Sent::default();
        for piece in split_text(text, usize::MAX, MAX_MESSAGE) {
            if !self.flood.take(&self.stop) {
                return Err(ChannelError::new(K::Network, "twitch: channel stopped"));
            }
            let r = self.helix("POST", &format!("/whispers?{q}"), Payload::Json(&json!({"message": piece})))?;
            match r.status {
                200 | 204 => sent.ids.push(format!("twitch-whisper:{}", self.seq.fetch_add(1, Ordering::SeqCst))),
                // 403: no verified phone, or the recipient blocks whispers from strangers.
                403 => return Err(ChannelError::new(K::NotFound, format!("twitch refused the whisper to {login}: {}", crate::http::redact(&r.body).chars().take(200).collect::<String>()))),
                s => return Err(classify(s, r.retry_after, "twitch whisper", &r.body)),
            }
        }
        Ok(sent)
    }

    /// Refresh when about to expire, then validate (refreshing once on 401).
    fn ensure_token(&self) -> Result<(), ChannelError> {
        let expiring = self.tokens.lock().unwrap().expires_at.is_some_and(|e| now_secs() + REFRESH_MARGIN >= e);
        if expiring && self.can_refresh() {
            self.refresh()?;
        }
        match self.validate() {
            Err(e) if e.kind == K::Auth && self.can_refresh() => {
                self.refresh()?;
                self.validate()
            }
            r => r,
        }
    }
}

pub struct Twitch {
    sh: Arc<Shared>,
    rx: Mutex<Receiver<Inbound>>,
    poll_timeout: u64,
}

impl Twitch {
    /// `token` with or without `oauth:`. Persisted refreshed tokens win while the configured token is unchanged.
    pub fn start(id: &str, cfg: Cfg, token: &str, refresh_token: Option<String>, poll_timeout_secs: u64) -> Result<Twitch, String> {
        let token = token.trim().trim_start_matches("oauth:").to_string();
        if token.is_empty() {
            return Err(format!("channel {id}: twitch token is empty"));
        }
        if cfg.channels.is_empty() {
            return Err(format!("channel {id}: twitch needs at least one channel"));
        }
        let seed = seed_of(&token);
        let mut tokens = Tokens { access: token, refresh: refresh_token.filter(|r| !r.trim().is_empty()), expires_at: None };
        if let Ok(s) = std::fs::read_to_string(&cfg.state) {
            let v: Value = serde_json::from_str(&s).unwrap_or_default();
            if v["seed"].as_str() == Some(seed.as_str()) {
                if let Some(a) = v["access_token"].as_str().filter(|a| !a.is_empty()) {
                    tokens = Tokens { access: a.to_string(), refresh: v["refresh_token"].as_str().map(str::to_string).or(tokens.refresh), expires_at: v["expires_at"].as_i64() };
                }
            }
        }
        let (tx, rx) = channel();
        let sh = Arc::new(Shared {
            id: id.to_string(),
            login: Mutex::new(cfg.login.clone()),
            flood: Flood::new(cfg.flood_burst, cfg.flood_interval),
            http: Http::new(cfg.connect_timeout),
            cfg,
            ws: Mutex::new(None),
            want_write: AtomicUsize::new(0),
            ready: AtomicBool::new(false),
            tokens: Mutex::new(tokens),
            seed,
            last_validate: Mutex::new(None),
            fatal: Mutex::new(None),
            gone: Mutex::new(HashMap::new()),
            stop: Cancel::new(),
            seq: AtomicU64::new(1),
            tx: Mutex::new(tx),
            user_id: Mutex::new(String::new()),
            user_ids: Mutex::new(HashMap::new()),
        });
        let s2 = sh.clone();
        std::thread::Builder::new().name(format!("twitch-{id}")).spawn(move || run(s2)).map_err(|e| format!("channel {id}: cannot start twitch thread: {e}"))?;
        Ok(Twitch { sh, rx: Mutex::new(rx), poll_timeout: poll_timeout_secs })
    }

    fn wait_ready(&self) -> Result<(), ChannelError> {
        let until = Instant::now() + self.sh.cfg.send_wait;
        loop {
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if self.sh.ready.load(Ordering::SeqCst) {
                return Ok(());
            }
            if Instant::now() >= until || self.sh.stop.is_cancelled() {
                return Err(ChannelError::new(K::Network, "twitch: not connected"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Twitch {
    fn drop(&mut self) {
        self.sh.stop.cancel();
    }
}

fn run(sh: Arc<Shared>) {
    let mut backoff = Backoff::new(sh.cfg.reconnect_base, sh.cfg.reconnect_max);
    let mut auth_failures = 0;
    while !sh.stop.is_cancelled() {
        // Network trouble at id.twitch.tv must not keep chat down; only a definite Auth answer stops us.
        if let Err(e) = sh.ensure_token() {
            if e.kind == K::Auth {
                *sh.fatal.lock().unwrap() = Some(e);
                break;
            }
        }
        let started = Instant::now();
        let end = session(&sh);
        sh.ready.store(false, Ordering::SeqCst);
        if let Some(ws) = sh.ws.lock().unwrap().take() {
            if let Ok(h) = ws.shutdown_handle() {
                let _ = h.shutdown(std::net::Shutdown::Both);
            }
        }
        match end {
            End::Stopped => break,
            End::Fatal(e) => {
                *sh.fatal.lock().unwrap() = Some(e);
                break;
            }
            End::AuthFailed(why) => {
                auth_failures += 1;
                if auth_failures > 1 || !sh.can_refresh() || sh.refresh().is_err() {
                    *sh.fatal.lock().unwrap() = Some(ChannelError::new(K::Auth, format!("twitch chat login failed: {why}")));
                    break;
                }
                continue;
            }
            End::Reconnect => {
                backoff.reset();
                continue;
            }
            End::Retry(_why) => {}
        }
        if started.elapsed() >= STABLE {
            backoff.reset();
            auth_failures = 0;
        }
        if !sleep_cancellable(backoff.next_delay(), &sh.stop) {
            break;
        }
    }
}

fn session(sh: &Arc<Shared>) -> End {
    let c = &sh.cfg;
    let login = sh.login();
    if login.is_empty() {
        return End::Retry("bot login unknown (validate failed)".into());
    }
    let ws = match WebSocket::connect(&c.ws_url, &[], c.connect_timeout) {
        Ok((ws, _)) => ws,
        Err(e) => return End::Retry(format!("connect: {e}")),
    };
    let _ = ws.set_read_timeout(Some(Duration::from_millis(100)));
    *sh.ws.lock().unwrap() = Some(ws);
    let tok = sh.tokens.lock().unwrap().access.clone();
    for l in ["CAP REQ :twitch.tv/tags twitch.tv/commands".to_string(), format!("PASS oauth:{tok}"), format!("NICK {login}")] {
        if let Err(e) = sh.write_raw(&l) {
            return End::Retry(format!("write: {e}"));
        }
    }
    let started = Instant::now();
    let mut last_rx = Instant::now();
    let mut pinged = false;
    loop {
        if sh.stop.is_cancelled() {
            if let Some(ws) = sh.ws.lock().unwrap().as_mut() {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
            }
            return End::Stopped;
        }
        let ready = sh.ready.load(Ordering::SeqCst);
        if !ready && started.elapsed() > c.connect_timeout * 2 {
            return End::Retry("login timed out".into());
        }
        if ready && last_rx.elapsed() >= LIVENESS {
            return End::Retry("server went silent".into());
        }
        if ready && !pinged && last_rx.elapsed() >= LIVENESS / 2 {
            pinged = true;
            let _ = sh.write_raw("PING :tmi.twitch.tv");
        }
        if ready && sh.last_validate.lock().unwrap().is_none_or(|t| t.elapsed() >= c.validate_every) {
            match sh.ensure_token() {
                Err(e) if e.kind == K::Auth => return End::Fatal(e),
                // Retry the hourly check later rather than on every loop.
                Err(_) => *sh.last_validate.lock().unwrap() = Some(Instant::now()),
                Ok(()) => {}
            }
        }
        while sh.want_write.load(Ordering::SeqCst) > 0 {
            std::thread::yield_now();
        }
        let r = {
            let mut g = sh.ws.lock().unwrap();
            match g.as_mut() {
                Some(ws) => ws.recv(),
                None => return End::Retry("connection gone".into()),
            }
        };
        let text = match r {
            Ok(None) => continue,
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Close(_))) => return End::Retry("server closed the websocket".into()),
            Ok(Some(_)) => continue,
            Err(e) => return End::Retry(format!("read: {e}")),
        };
        last_rx = Instant::now();
        pinged = false;
        for raw in text.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            let Some(line) = parse_line(raw) else { continue };
            if let Some(end) = handle(sh, &line, &login) {
                return end;
            }
        }
    }
}

fn handle(sh: &Arc<Shared>, l: &Line, login: &str) -> Option<End> {
    let ready = sh.ready.load(Ordering::SeqCst);
    match l.command.as_str() {
        "PING" => {
            let _ = sh.write_raw(&format!("PONG :{}", l.last()));
        }
        "RECONNECT" => return Some(End::Reconnect),
        "001" => {
            sh.ready.store(true, Ordering::SeqCst);
            for ch in &sh.cfg.channels {
                let _ = sh.write_raw(&format!("JOIN #{ch}"));
            }
        }
        "NOTICE" => {
            let text = l.last();
            let lower = text.to_ascii_lowercase();
            if !ready && (lower.contains("authentication failed") || lower.contains("improperly formatted auth") || lower.contains("invalid nick")) {
                return Some(End::AuthFailed(text.to_string()));
            }
            let id = l.tag("msg-id").unwrap_or("");
            if matches!(id, "msg_banned" | "msg_channel_suspended" | "msg_channel_blocked" | "msg_suspended" | "tos_ban") {
                let ch = l.param(0).trim_start_matches('#').to_ascii_lowercase();
                sh.gone.lock().unwrap().insert(ch, (format!("{id}: {text}"), Instant::now()));
            }
        }
        "JOIN" if l.nick().eq_ignore_ascii_case(login) => {
            sh.gone.lock().unwrap().remove(&l.param(0).trim_start_matches('#').to_ascii_lowercase());
        }
        "WHISPER" if sh.cfg.whispers => {
            if let Some(m) = whisper_of(&sh.id, l, login) {
                let _ = sh.tx.lock().unwrap().send(m);
            }
        }
        "PRIVMSG" => {
            let fallback = format!("{}-{}", now_millis(), sh.seq.fetch_add(1, Ordering::SeqCst));
            if let Some(m) = inbound_of(&sh.id, l, login, &fallback) {
                let _ = sh.tx.lock().unwrap().send(m);
            }
        }
        _ => {}
    }
    None
}

/// `@word` tokens naming the bot.
fn mentions_bot(text: &str, login: &str) -> bool {
    text.split('@').skip(1).any(|rest| {
        let w: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
        !w.is_empty() && w.eq_ignore_ascii_case(login)
    })
}

fn inbound_of(channel_id: &str, l: &Line, login: &str, fallback_id: &str) -> Option<Inbound> {
    let user = l.nick().to_ascii_lowercase();
    if user.is_empty() || user == login {
        return None;
    }
    let chan = l.param(0).trim_start_matches('#').to_ascii_lowercase();
    if chan.is_empty() || l.params.len() < 2 {
        return None;
    }
    let display = l.tag("display-name").filter(|d| !d.is_empty()).unwrap_or(&user).to_string();
    let raw = l.last();
    let text = match raw.strip_prefix('\x01') {
        Some(ctcp) => {
            let ctcp = ctcp.strip_suffix('\x01').unwrap_or(ctcp);
            let arg = ctcp.strip_prefix("ACTION ")?;
            format!("* {display} {arg}")
        }
        None => raw.to_string(),
    };
    if text.trim().is_empty() {
        return None;
    }
    let reply = l.tag("reply-parent-msg-id").filter(|r| !r.is_empty()).map(|id| {
        let parent = l.tag("reply-parent-user-login").unwrap_or("");
        ReplyRef {
            id: id.to_string(),
            text: l.tag("reply-parent-msg-body").unwrap_or("").to_string(),
            author: l.tag("reply-parent-display-name").filter(|d| !d.is_empty()).unwrap_or(parent).to_string(),
            is_own: parent.eq_ignore_ascii_case(login),
        }
    });
    Some(Inbound {
        channel: channel_id.to_string(),
        chat: chan.clone(),
        chat_type: ChatType::Group,
        chat_name: chan,
        sender: l.tag("user-id").filter(|u| !u.is_empty()).map(str::to_string).unwrap_or_else(|| user.clone()),
        sender_name: display,
        mentioned: mentions_bot(&text, login),
        text,
        message_id: l.tag("id").filter(|i| !i.is_empty()).unwrap_or(fallback_id).to_string(),
        ts: l.tag("tmi-sent-ts").and_then(|t| t.parse::<i64>().ok()).map(|ms| ms / 1000).unwrap_or_else(now_secs),
        reply,
        ..Default::default()
    })
}

/// `WHISPER <bot> :text` → a DM keyed `whisper:<login>`.
fn whisper_of(channel_id: &str, l: &Line, login: &str) -> Option<Inbound> {
    let user = l.nick().to_ascii_lowercase();
    if user.is_empty() || user == login || normalize_channel(&user).is_none() || l.params.len() < 2 || l.last().trim().is_empty() {
        return None;
    }
    let id = l.tag("message-id").filter(|i| !i.is_empty()).map(|i| format!("w{}-{i}", l.tag("thread-id").unwrap_or("")));
    Some(Inbound {
        channel: channel_id.to_string(),
        chat: format!("whisper:{user}"),
        chat_type: ChatType::Direct,
        sender: l.tag("user-id").filter(|u| !u.is_empty()).map(str::to_string).unwrap_or_else(|| user.clone()),
        sender_name: l.tag("display-name").filter(|d| !d.is_empty()).unwrap_or(&user).to_string(),
        text: l.last().to_string(),
        message_id: id.unwrap_or_else(|| format!("w{}", now_millis())),
        ts: now_secs(),
        ..Default::default()
    })
}

/// `whisper:<login>` → the login.
fn whisper_target(chat: &str) -> Option<String> {
    let t = chat.trim();
    let rest = t.get(..8).filter(|p| p.eq_ignore_ascii_case("whisper:")).map(|_| &t[8..])?;
    normalize_channel(rest)
}

impl Channel for Twitch {
    fn id(&self) -> &str {
        &self.sh.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: if self.sh.cfg.whispers { vec![ChatType::Direct, ChatType::Group] } else { vec![ChatType::Group] },
            media: true,
            reply: true,
            threads: false,
            reactions: 0,
            edit: false,
            delete: false,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let rx = self.rx.lock().unwrap();
        loop {
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    let mut v = vec![m];
                    v.extend(rx.try_iter());
                    return Ok(v);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if cancel.is_cancelled() || Instant::now() >= until {
                        return Ok(vec![]);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "twitch worker stopped")),
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        if let Some(login) = whisper_target(&out.chat) {
            if !self.sh.cfg.whispers {
                return Err(ChannelError::new(K::Unsupported, "twitch whispers are off (set whispers = true)"));
            }
            let text = render_body(out)?.lines().map(sanitize_text).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
            if text.is_empty() {
                return Err(ChannelError::new(K::Protocol, "twitch: message is empty"));
            }
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            return self.sh.whisper(&login, &text);
        }
        let chan = normalize_channel(&out.chat).ok_or_else(|| ChannelError::new(K::Protocol, format!("invalid Twitch channel {:?}", out.chat)))?;
        // Twitch messages are single lines.
        let text = render_body(out)?.lines().map(sanitize_text).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ");
        if text.is_empty() {
            return Err(ChannelError::new(K::Protocol, "twitch: message is empty"));
        }
        self.wait_ready()?;
        if let Some((why, at)) = self.sh.gone.lock().unwrap().get(&chan) {
            if at.elapsed() < GONE_FOR {
                return Err(ChannelError::new(K::NotFound, format!("twitch: cannot send to #{chan}: {why}")));
            }
        }
        let tag = out.reply_to.as_deref().filter(|r| !r.is_empty()).map(|r| format!("@reply-parent-msg-id={} ", escape_tag(r))).unwrap_or_default();
        let mut sent = Sent::default();
        for (i, piece) in split_text(&text, usize::MAX, MAX_MESSAGE).iter().enumerate() {
            if !self.sh.flood.take(&self.sh.stop) {
                return Err(ChannelError::new(K::Network, "twitch: channel stopped"));
            }
            let t = if i == 0 { tag.as_str() } else { "" };
            self.sh.write_raw(&format!("{t}PRIVMSG #{chan} :{piece}")).map_err(|e| ChannelError::new(K::Network, format!("twitch send: {e}")))?;
            sent.ids.push(format!("twitch:{}", self.sh.seq.fetch_add(1, Ordering::SeqCst)));
        }
        Ok(sent)
    }

    fn stop(&self) {
        self.sh.stop.cancel();
    }
}

// ---------------------------------------------------------------- settings

fn d_poll() -> u64 {
    25
}
fn d_validate() -> u64 {
    3600
}
fn d_burst() -> u32 {
    20
}
fn d_interval() -> u64 {
    1500
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Bot login; learned from the token when omitted.
    #[serde(default)]
    username: Option<String>,
    /// OAuth access token with chat:read + chat:write (`oauth:` prefix optional).
    token: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    channels: Vec<String>,
    #[serde(default)]
    ws_url: Option<String>,
    #[serde(default)]
    id_base_url: Option<String>,
    #[serde(default)]
    helix_base_url: Option<String>,
    /// Receive WHISPERs and send to `whisper:<login>` (needs client_id, user:manage:whispers).
    #[serde(default)]
    whispers: bool,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_validate")]
    validate_interval_secs: u64,
    /// 20 messages / 30 s for regular accounts; moderators may raise this.
    #[serde(default = "d_burst")]
    flood_burst: u32,
    #[serde(default = "d_interval")]
    flood_interval_ms: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let mut chans: Vec<&str> = st.channels.iter().map(String::as_str).collect();
    if let Some(c) = st.channel.as_deref() {
        chans.insert(0, c);
    }
    for c in &chans {
        if normalize_channel(c).is_none() {
            return Err(format!("channel {}: `{c}` is not a Twitch channel name", ctx.name));
        }
    }
    let mut c = Cfg::new(st.username.as_deref().unwrap_or(""), &chans, ctx.state("twitch.json"));
    c.client_id = st.client_id.filter(|c| !c.trim().is_empty());
    c.client_secret = ctx.opt_secret("client_secret", &st.client_secret)?;
    if let Some(u) = st.ws_url {
        c.ws_url = u;
    }
    if let Some(u) = st.id_base_url {
        c.id_base = u.trim_end_matches('/').to_string();
    }
    if let Some(u) = st.helix_base_url {
        c.helix_base = u.trim_end_matches('/').to_string();
    }
    c.whispers = st.whispers;
    if c.whispers && c.client_id.is_none() {
        return Err(format!("channel {}: whispers need client_id (Helix)", ctx.name));
    }
    c.validate_every = Duration::from_secs(st.validate_interval_secs.max(60));
    c.flood_burst = st.flood_burst;
    c.flood_interval = Duration::from_millis(st.flood_interval_ms);
    let refresh = ctx.opt_secret("refresh_token", &st.refresh_token)?;
    if refresh.is_some() && (c.client_id.is_none() || c.client_secret.is_none()) {
        return Err(format!("channel {}: refresh_token needs client_id and client_secret", ctx.name));
    }
    Ok(Arc::new(Twitch::start(ctx.name, c, &token, refresh, st.poll_timeout_secs)?))
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::collections::VecDeque;
    use std::net::{TcpListener, TcpStream};

    struct WsPeer {
        ws: WebSocket<TcpStream>,
        pending: VecDeque<String>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl WsPeer {
        fn line(&mut self) -> Option<String> {
            loop {
                if let Some(l) = self.pending.pop_front() {
                    self.log.lock().unwrap().push(l.clone());
                    return Some(l);
                }
                match self.ws.recv_blocking() {
                    Ok(Message::Text(t)) => self.pending.extend(t.split("\r\n").filter(|l| !l.is_empty()).map(str::to_string)),
                    Ok(Message::Close(_)) | Err(_) => return None,
                    Ok(_) => {}
                }
            }
        }
        fn expect(&mut self, prefix: &str) -> String {
            loop {
                let l = self.line().unwrap_or_else(|| panic!("closed waiting for {prefix}"));
                if l.starts_with(prefix) {
                    return l;
                }
            }
        }
        fn send(&mut self, l: &str) {
            let _ = self.ws.send_text(&format!("{l}\r\n"));
        }
        fn login(&mut self, tok: &str) {
            assert_eq!(self.expect("CAP"), "CAP REQ :twitch.tv/tags twitch.tv/commands");
            assert_eq!(self.line().unwrap(), format!("PASS oauth:{tok}"));
            assert_eq!(self.line().unwrap(), "NICK arkbot");
            self.send(":tmi.twitch.tv 001 arkbot :Welcome, GLHF!");
            assert_eq!(self.expect("JOIN"), "JOIN #chan");
        }
    }

    fn fake_ws(script: impl Fn(usize, &mut WsPeer) + Send + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let (head, rest) = ark_net::ws::read_head(&mut s, 65536).unwrap();
                let ws = WebSocket::accept(s, &head, rest).unwrap();
                let mut p = WsPeer { ws, pending: VecDeque::new(), log: log2.clone() };
                script(n, &mut p);
            }
        });
        (url, log)
    }

    fn validate_ok() -> FakeServer {
        FakeServer::start(|_, _| (200, vec![], json!({"client_id": "cid", "login": "arkbot", "user_id": "99", "expires_in": 5000}).to_string()))
    }

    fn cfg(ws: &str, id: &str, state: PathBuf) -> Cfg {
        let mut c = Cfg::new("", &["#Chan"], state);
        c.ws_url = ws.into();
        c.id_base = id.into();
        c.reconnect_base = Duration::from_millis(20);
        c.reconnect_max = Duration::from_millis(100);
        c.flood_interval = Duration::ZERO;
        c.send_wait = Duration::from_secs(5);
        c
    }

    fn poll_n(t: &Twitch, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(t.poll(&Cancel::new()).unwrap());
        }
        got
    }

    #[test]
    fn login_tags_mentions_replies_actions_and_ping() {
        let id = validate_ok();
        let (ws, log) = fake_ws(|_, p| {
            p.login("tok");
            p.send("PING :tmi.twitch.tv");
            assert_eq!(p.expect("PONG"), "PONG :tmi.twitch.tv");
            p.send("@badge-info=;badges=moderator/1;color=#FF0000;display-name=Amy;id=m1;mod=1;room-id=1;tmi-sent-ts=1700000000123;user-id=42 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :hey @ArkBot, help");
            p.send("@display-name=Bob;id=m2;reply-parent-display-name=ArkBot;reply-parent-msg-body=shall\\sI?;reply-parent-msg-id=p1;reply-parent-user-login=arkbot;user-id=7 :bob!bob@bob.tmi.twitch.tv PRIVMSG #chan :@ArkBot yes");
            p.send(":arkbot!arkbot@arkbot.tmi.twitch.tv PRIVMSG #chan :my echo");
            p.send("@display-name=Amy;id=m3;user-id=42 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :\x01ACTION dances\x01");
            p.send("@id=m4;user-id=42 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :hi @arkbotfan");
            p.send("@msg-id=subgift :tmi.twitch.tv USERNOTICE #chan :gift");
            let _ = p.line();
        });
        let t = Twitch::start("tw", cfg(&ws, &id.url, temp_dir("tw").join("s.json")), "oauth:tok", None, 1).unwrap();
        let g = poll_n(&t, 4);
        assert_eq!(g.len(), 4, "{g:?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].message_id.as_str(), g[0].ts), ("chan", ChatType::Group, "42", "Amy", "m1", 1700000000));
        assert!(g[0].mentioned && g[0].text == "hey @ArkBot, help");
        let r = g[1].reply.as_ref().unwrap();
        assert_eq!((r.id.as_str(), r.text.as_str(), r.author.as_str(), r.is_own), ("p1", "shall I?", "ArkBot", true));
        assert!(g[1].addressed());
        assert_eq!(g[2].text, "* Amy dances");
        assert!(!g[3].mentioned, "@arkbotfan is someone else");
        let v = &id.requests()[0];
        assert_eq!((v.path.as_str(), v.header("authorization")), ("/oauth2/validate", Some("OAuth tok")));
        assert!(log.lock().unwrap().iter().any(|l| l == "NICK arkbot"), "login learned from validate");
    }

    #[test]
    fn send_uses_reply_tag_chunks_and_maps_errors() {
        let id = validate_ok();
        let (ws, log) = fake_ws(|_, p| {
            p.login("tok");
            p.send("@msg-id=msg_banned :tmi.twitch.tv NOTICE #banned :You are permanently banned from talking in banned.");
            while p.line().is_some() {}
        });
        let mut c = cfg(&ws, &id.url, temp_dir("tw").join("s.json"));
        c.login = "arkbot".into();
        let t = Twitch::start("tw", c, "tok", None, 1).unwrap();
        let long = format!("**hello**\n{}", "word ".repeat(220));
        let s = t.send(&Outbound { reply_to: Some("m1".into()), format: crate::TextFormat::Markdown, media: vec![crate::Media { url: Some("https://e.com/c.gif".into()), ..Default::default() }], ..Outbound::text("#Chan", &long) }).unwrap();
        assert_eq!(s.ids.len(), 3);
        std::thread::sleep(Duration::from_millis(300));
        let lines: Vec<String> = log.lock().unwrap().iter().filter(|l| l.contains("PRIVMSG #chan")).cloned().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("@reply-parent-msg-id=m1 PRIVMSG #chan :hello word"), "{}", lines[0]);
        assert!(lines[1].starts_with("PRIVMSG #chan :"));
        assert!(lines.iter().all(|l| l.split_once(" :").unwrap().1.chars().count() <= MAX_MESSAGE));
        assert!(lines[2].ends_with("https://e.com/c.gif"));
        assert_eq!(t.send(&Outbound::text("#banned", "hi")).unwrap_err().kind, K::NotFound);
        assert_eq!(t.send(&Outbound::text("not a channel", "hi")).unwrap_err().kind, K::Protocol);
        assert!(t.caps().reply && t.caps().chat_types == vec![ChatType::Group]);
    }

    #[test]
    fn reconnect_command_and_dropped_socket_reconnect() {
        let id = validate_ok();
        let (ws, log) = fake_ws(|n, p| {
            p.login("tok");
            match n {
                0 => p.send(":tmi.twitch.tv RECONNECT"),
                1 => {} // drop without a close frame
                _ => {
                    p.send("@id=after;user-id=1 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :back");
                    while p.line().is_some() {}
                }
            }
        });
        let t = Twitch::start("tw", cfg(&ws, &id.url, temp_dir("tw").join("s.json")), "tok", None, 1).unwrap();
        let g = poll_n(&t, 1);
        assert_eq!(g[0].message_id, "after");
        assert_eq!(log.lock().unwrap().iter().filter(|l| l.starts_with("JOIN")).count(), 3);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        let mut t2 = t;
        t2.poll_timeout = 30;
        assert!(t2.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn invalid_token_without_refresh_is_auth() {
        let id = FakeServer::start(|_, _| (401, vec![], json!({"status": 401, "message": "invalid access token"}).to_string()));
        let t = Twitch::start("tw", cfg("ws://127.0.0.1:1", &id.url, temp_dir("tw").join("s.json")), "badtok", None, 2).unwrap();
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert!(e.kind == K::Auth && !e.message.contains("badtok"), "{e:?}");
        assert_eq!(t.send(&Outbound::text("chan", "x")).unwrap_err().kind, K::Auth);
        // Validate passes but chat login is refused.
        let id = validate_ok();
        let (ws, _) = fake_ws(|_, p| {
            p.expect("NICK");
            p.send(":tmi.twitch.tv NOTICE * :Login authentication failed");
        });
        let t = Twitch::start("tw", cfg(&ws, &id.url, temp_dir("tw").join("s.json")), "tok", None, 2).unwrap();
        assert_eq!(t.poll(&Cancel::new()).unwrap_err().kind, K::Auth);
    }

    #[test]
    fn refreshes_expired_token_and_persists_it_privately() {
        let id = FakeServer::start(|req, _| {
            if req.path == "/oauth2/token" {
                return (200, vec![], json!({"access_token": "newtok", "refresh_token": "r2", "expires_in": 14000, "scope": ["chat:read", "chat:edit"], "token_type": "bearer"}).to_string());
            }
            match req.header("authorization") {
                Some("OAuth newtok") => (200, vec![], json!({"login": "arkbot", "expires_in": 14000}).to_string()),
                _ => (401, vec![], json!({"status": 401}).to_string()),
            }
        });
        let (ws, _) = fake_ws(|_, p| {
            p.login("newtok");
            p.send("@id=x;user-id=1 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :hi");
            while p.line().is_some() {}
        });
        let dir = temp_dir("tw");
        let state = dir.join("tw.twitch.json");
        let mut c = cfg(&ws, &id.url, state.clone());
        c.client_id = Some("cid".into());
        c.client_secret = Some("csecret".into());
        let t = Twitch::start("tw", c.clone(), "oldtok", Some("r1".into()), 1).unwrap();
        assert_eq!(poll_n(&t, 1)[0].text, "hi");
        let reqs = id.requests();
        let r = reqs.iter().find(|r| r.path == "/oauth2/token").unwrap();
        let form = ark_net::parse_query(&r.body);
        assert!(form.contains(&("grant_type".into(), "refresh_token".into())) && form.contains(&("refresh_token".into(), "r1".into())) && form.contains(&("client_secret".into(), "csecret".into())));
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((saved["access_token"].as_str(), saved["refresh_token"].as_str()), (Some("newtok"), Some("r2")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
        }
        drop(t);
        // A restart with the same configured token picks up the rotated pair without refreshing again.
        let before = id.requests().iter().filter(|r| r.path == "/oauth2/token").count();
        let t2 = Twitch::start("tw", c, "oldtok", Some("r1".into()), 1).unwrap();
        assert_eq!(t2.sh.tokens.lock().unwrap().refresh.as_deref(), Some("r2"));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(id.requests().iter().filter(|r| r.path == "/oauth2/token").count(), before);
        assert_eq!(id.requests().last().unwrap().header("authorization"), Some("OAuth newtok"));
    }

    #[test]
    fn whispers_in_via_irc_and_out_via_helix() {
        let api = FakeServer::start(|req, _| {
            let p = req.path.as_str();
            if p.starts_with("/oauth2/validate") {
                return (200, vec![], json!({"client_id": "cid", "login": "arkbot", "user_id": "99", "expires_in": 5000}).to_string());
            }
            if p == "/helix/users?login=amy" {
                return (200, vec![], json!({"data": [{"id": "42", "login": "amy"}]}).to_string());
            }
            if p == "/helix/users?login=ghost" {
                return (200, vec![], json!({"data": []}).to_string());
            }
            if p == "/helix/users?login=locked" {
                return (200, vec![], json!({"data": [{"id": "7"}]}).to_string());
            }
            if p.starts_with("/helix/whispers?") && p.contains("to_user_id=7") {
                return (403, vec![], json!({"error": "Forbidden", "message": "the user is not allowed to receive whispers"}).to_string());
            }
            if p.starts_with("/helix/whispers?") {
                return (204, vec![], String::new());
            }
            (500, vec![], String::new())
        });
        let (ws, _) = fake_ws(|_, p| {
            p.login("tok");
            p.send("@badges=;color=;display-name=Amy;emotes=;message-id=3;thread-id=42_99;turbo=0;user-id=42;user-type= :amy!amy@amy.tmi.twitch.tv WHISPER arkbot :psst, help");
            while p.line().is_some() {}
        });
        let mut c = cfg(&ws, &api.url, temp_dir("tw").join("s.json"));
        c.helix_base = format!("{}/helix", api.url);
        c.whispers = true;
        c.client_id = Some("cid".into());
        let t = Twitch::start("tw", c, "tok", None, 1).unwrap();
        let g = poll_n(&t, 1);
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].text.as_str(), g[0].message_id.as_str()), ("whisper:amy", ChatType::Direct, "42", "Amy", "psst, help", "w42_99-3"));
        assert!(g[0].addressed() && t.caps().chat_types.contains(&ChatType::Direct));
        let s = t.send(&Outbound::text(&g[0].chat, &"x".repeat(600))).unwrap();
        assert_eq!(s.ids.len(), 2, "split at 500 characters");
        t.send(&Outbound::text("whisper:Amy", "again")).unwrap();
        let reqs = api.requests();
        assert_eq!(reqs.iter().filter(|r| r.path.starts_with("/helix/users")).count(), 1, "user id cached");
        let w: Vec<&crate::testutil::Req> = reqs.iter().filter(|r| r.path.starts_with("/helix/whispers")).collect();
        assert_eq!(w.len(), 3);
        assert_eq!((w[0].method.as_str(), w[0].path.as_str(), w[0].header("client-id"), w[0].header("authorization")), ("POST", "/helix/whispers?from_user_id=99&to_user_id=42", Some("cid"), Some("Bearer tok")));
        assert_eq!(w[2].json()["message"], "again");
        assert_eq!(t.send(&Outbound::text("whisper:ghost", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(t.send(&Outbound::text("whisper:locked", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(whisper_target("WHISPER:Bad Name"), None);
    }

    #[test]
    fn whispers_off_by_default() {
        let id = validate_ok();
        let (ws, _) = fake_ws(|_, p| {
            p.login("tok");
            p.send("@user-id=42 :amy!amy@amy.tmi.twitch.tv WHISPER arkbot :ignored");
            p.send("@id=z;user-id=42 :amy!amy@amy.tmi.twitch.tv PRIVMSG #chan :seen");
            while p.line().is_some() {}
        });
        let t = Twitch::start("tw", cfg(&ws, &id.url, temp_dir("tw").join("s.json")), "tok", None, 1).unwrap();
        assert_eq!(poll_n(&t, 1)[0].text, "seen");
        assert_eq!(t.send(&Outbound::text("whisper:amy", "x")).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn build_validates_settings() {
        let d = temp_dir("tw");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:TW}}", "tok"));
        let ctx = crate::config::Ctx { name: "tw", state_dir: &d, secrets: &secrets };
        let ok = json!({"token": "{{secret:TW}}", "username": "ArkBot", "channel": "#Chan", "ws_url": "ws://127.0.0.1:1", "id_base_url": "http://127.0.0.1:1"});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        assert!(build(&ctx, json!({"token": "t", "channel": "bad name"}).as_object().unwrap()).is_err());
        assert!(build(&ctx, json!({"token": "t"}).as_object().unwrap()).err().unwrap().contains("channel"));
        assert!(build(&ctx, json!({"token": "t", "channel": "c", "refresh_token": "r"}).as_object().unwrap()).err().unwrap().contains("client_id"));
        assert!(build(&ctx, json!({"token": "t", "channel": "c", "chanel": "x"}).as_object().unwrap()).err().unwrap().contains("chanel"));
        assert!(build(&ctx, json!({"token": "t", "channel": "c", "whispers": true}).as_object().unwrap()).err().unwrap().contains("client_id"));
        assert_eq!(normalize_channel("twitch:#Foo_1").as_deref(), Some("foo_1"));
        assert!(mentions_bot("yo @ARKBOT!", "arkbot") && !mentions_bot("mail a@arkbotx", "arkbot") && !mentions_bot("arkbot", "arkbot"));
    }
}
