//! Feishu / Lark open platform bots (ported from Hermes `plugins/platforms/feishu`
//! and OpenClaw `extensions/feishu`, both MIT). Kinds `feishu` and `lark`
//! (`domain = "lark"` selects open.larksuite.com).
//!
//! Receive, two transports feeding one queue:
//! - WebSocket long connection (default): `POST /callback/ws/endpoint` with the
//!   app credentials → `wss://…` URL; binary protobuf `Frame`s (pbbs.proto:
//!   control ping/pong with `ClientConfig`, data frames of type `event` / `card`,
//!   fragmented via `sum`/`seq` headers, each answered with `{"code":200}`).
//! - Webhook (`listen = "…"`): `url_verification` challenge, verification token,
//!   `X-Lark-Signature = sha256(timestamp + nonce + encrypt_key + body)` with a
//!   freshness window, `{"encrypt": …}` bodies (AES-256-CBC, key = sha256(encrypt_key),
//!   iv = first 16 bytes).
//!
//! Events: `im.message.receive_v1` (text, post, image, file, audio, media, sticker,
//! interactive / share / forward placeholders; @mentions of our open_id; p2p vs group;
//! `thread_id` topics; `parent_id` replies, looked up to detect replies to the bot) and
//! `card.action.trigger` button presses (→ `Callback`).
//! Send: `im/v1/messages` (receive_id_type from the id prefix), `…/reply` with
//! `reply_in_thread`, `post` for Markdown, interactive cards for buttons, image/file
//! upload then send; edit (PUT, PATCH for cards), delete, reactions, resource download.
//! The tenant_access_token is cached until shortly before expiry and refreshed on
//! "token invalid" answers.
//! Names (`resolve_names`): sender display names via `contact/v3/users` (bots via
//! `bot/v3/bots/basic_batch`) cached 10 minutes, group names via `im/v1/chats` cached
//! until the bot is added to / removed from the chat.
//! Also: approval cards ([`approval`]), cloud-document comments ([`comment`]), meeting
//! invitations ([`meeting`]) and QR app registration ([`onboard`]). Typing: Feishu has
//! no typing indicator API.

mod approval;
mod comment;
mod meeting;
pub mod onboard;
mod tools;

use crate::http::{Http, Payload};
use crate::{
    sleep_cancellable, Button, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat,
};
use ark_core::Cancel;
use ark_net::crypto;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const FEISHU_BASE: &str = "https://open.feishu.cn";
pub const LARK_BASE: &str = "https://open.larksuite.com";
/// Client-side chunk size used by both upstreams (the server limit is far larger).
pub const MAX_MESSAGE: usize = 4000;
/// Signed webhook timestamps older/newer than this are replays (OpenClaw: 1 h).
const MAX_SKEW_SECS: i64 = 3600;
const MAX_MEDIA: u64 = 30 * 1024 * 1024;

/// Feishu business codes meaning "credentials/token bad".
const AUTH_CODES: [i64; 9] = [10003, 10014, 99991661, 99991663, 99991664, 99991665, 99991668, 99991671, 99991672];
/// Codes after which a fresh tenant token is worth one retry.
const TOKEN_CODES: [i64; 3] = [99991661, 99991663, 99991668];
const RATE_CODES: [i64; 3] = [99991400, 230020, 11232];
/// Bot not in chat, message withdrawn / deleted, user outside the app's range.
const GONE_CODES: [i64; 4] = [230002, 230011, 231003, 230013];
/// Reply target gone → post a fresh message instead (Hermes `_FEISHU_REPLY_FALLBACK_CODES`).
const REPLY_FALLBACK_CODES: [i64; 2] = [230011, 231003];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Bot {
    open_id: String,
    name: String,
}

/// What both receive transports push and the background WS thread reports.
struct Shared {
    tx: Sender<Value>,
    stop: AtomicBool,
    fatal: Mutex<Option<ChannelError>>,
}

#[derive(Clone)]
struct WsCfg {
    base: String,
    app_id: String,
    app_secret: String,
    http: Http,
    backoff: Duration,
}

pub struct Feishu {
    id: String,
    app_id: String,
    app_secret: String,
    base: String,
    poll_timeout: u64,
    http: Http,
    /// First retry delay; doubles each attempt.
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest `retry_after` honoured in place.
    pub max_wait: Duration,
    /// First WebSocket reconnect delay; doubles up to a minute.
    pub ws_backoff: Duration,
    token: Mutex<Option<(String, Instant)>>,
    bot: Mutex<Option<Bot>>,
    shared: Arc<Shared>,
    rx: Mutex<Receiver<Value>>,
    ws_started: AtomicBool,
    webhook: Option<ark_net::httpd::Server>,
    /// message id → msg_type of what we sent (edit picks PUT vs PATCH).
    sent_types: Mutex<HashMap<String, &'static str>>,
    /// (message id, emoji_type) → reaction_id, so removals need no lookup.
    reactions: Mutex<HashMap<(String, String), String>>,
    /// chat id → type seen on inbound messages (card callbacks carry no chat type).
    chat_types: Mutex<HashMap<String, ChatType>>,
    /// parent message id → (text, sent by us).
    parents: Mutex<HashMap<String, (String, bool)>>,
    /// Look up sender and group names (off for bare `new`, on in config).
    pub resolve_names: bool,
    /// open_id → (name, valid until); "" = known nameless.
    names: Mutex<HashMap<String, (String, Instant)>>,
    chat_names: Mutex<HashMap<String, String>>,
    approvals: Mutex<HashMap<String, approval::Card>>,
    pub approval_timeout: Duration,
    /// Handle document comment notices; restrict to `comment_docs` (`type:token`, token, `*`) when set.
    pub comments: bool,
    pub comment_docs: Vec<String>,
    pub comment_retries: u32,
    pub comment_retry_delay: Duration,
    /// Non-message event ids already handled (comment / meeting redeliveries).
    seen_events: Mutex<HashMap<String, Instant>>,
    /// Agent tool families (`tools = { doc = true, perm = false, … }`; see [`tools`]).
    pub tool_families: std::collections::BTreeMap<String, bool>,
    pub media_max_mb: u64,
    /// Session → route lookup (trusted requester for `feishu_doc` create grants).
    origin: Arc<Mutex<Option<crate::whatsapp::SessionOrigin>>>,
}

const NAME_TTL: Duration = Duration::from_secs(600);

/// Webhook verification settings.
#[derive(Clone)]
struct HookCfg {
    path: String,
    encrypt_key: Option<String>,
    verification_token: Option<String>,
}

#[derive(Clone, Copy)]
enum Body<'a> {
    None,
    Json(&'a Value),
    Multi(&'a [(&'a str, &'a str, &'a str, &'a [u8])]),
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn err(kind: K, msg: impl Into<String>) -> ChannelError {
    ChannelError::new(kind, msg)
}

/// Feishu's `{code, msg, data}` envelope → value or a classified error.
fn fs_result(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> Result<Value, ChannelError> {
    let v: Option<Value> = serde_json::from_str(body).ok();
    let code = v.as_ref().and_then(|v| v["code"].as_i64());
    let msg = v.as_ref().and_then(|v| v["msg"].as_str()).unwrap_or("").chars().take(200).collect::<String>();
    if (200..300).contains(&status) && code.unwrap_or(0) == 0 {
        return v.ok_or_else(|| err(K::Protocol, format!("{what}: response is not JSON")));
    }
    let Some(code) = code else {
        return Err(crate::http::classify(status, retry_after, what, body));
    };
    let m = format!("{what}: code={code} {msg}");
    let kind = if AUTH_CODES.contains(&code) {
        K::Auth
    } else if RATE_CODES.contains(&code) || status == 429 {
        K::RateLimited { retry_after }
    } else if GONE_CODES.contains(&code) {
        K::NotFound
    } else if status >= 500 {
        K::Network
    } else if !(200..300).contains(&status) {
        crate::http::classify(status, retry_after, what, "").kind
    } else {
        K::Protocol
    };
    Err(err(kind, m))
}

fn has_code(e: &ChannelError, codes: &[i64]) -> bool {
    codes.iter().any(|c| e.message.contains(&format!("code={c} ")))
}

impl Feishu {
    /// `base` overrides the open-platform origin (tests, private deployments); `domain`
    /// is `feishu` or `lark`.
    pub fn new(id: &str, app_id: &str, app_secret: &str, domain: &str, base: Option<&str>, poll_timeout_secs: u64) -> Result<Feishu, String> {
        if app_id.trim().is_empty() || app_secret.trim().is_empty() {
            return Err(format!("channel {id}: feishu app_id and app_secret are required"));
        }
        let default = match domain {
            "feishu" | "" => FEISHU_BASE,
            "lark" | "larksuite" => LARK_BASE,
            other => return Err(format!("channel {id}: domain must be \"feishu\" or \"lark\", not {other:?}")),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        Ok(Feishu {
            id: id.to_string(),
            app_id: app_id.trim().to_string(),
            app_secret: app_secret.trim().to_string(),
            base: base.unwrap_or(default).trim_end_matches('/').to_string(),
            poll_timeout: poll_timeout_secs,
            http: Http::new(Duration::from_secs(60)),
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
            ws_backoff: Duration::from_secs(1),
            token: Mutex::new(None),
            bot: Mutex::new(None),
            shared: Arc::new(Shared { tx, stop: AtomicBool::new(false), fatal: Mutex::new(None) }),
            rx: Mutex::new(rx),
            ws_started: AtomicBool::new(false),
            webhook: None,
            sent_types: Mutex::new(HashMap::new()),
            reactions: Mutex::new(HashMap::new()),
            chat_types: Mutex::new(HashMap::new()),
            parents: Mutex::new(HashMap::new()),
            resolve_names: false,
            names: Mutex::new(HashMap::new()),
            chat_names: Mutex::new(HashMap::new()),
            approvals: Mutex::new(HashMap::new()),
            approval_timeout: Duration::from_secs(600),
            comments: true,
            comment_docs: Vec::new(),
            comment_retries: 6,
            comment_retry_delay: Duration::from_secs(1),
            seen_events: Mutex::new(HashMap::new()),
            tool_families: Default::default(),
            media_max_mb: 30,
            origin: Arc::new(Mutex::new(None)),
        })
    }

    /// Known bot identity (skips the `/bot/v3/info` lookup).
    pub fn with_bot(self, open_id: &str, name: &str) -> Feishu {
        *self.bot.lock().unwrap() = Some(Bot { open_id: open_id.into(), name: name.into() });
        self
    }

    /// Webhook mode: listen on `listen`, accept POSTs on `path`. At least one of
    /// `encrypt_key` (signature + encryption) or `verification_token` is required.
    pub fn with_webhook(mut self, listen: &str, path: &str, encrypt_key: Option<&str>, verification_token: Option<&str>) -> Result<Feishu, String> {
        let nz = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let cfg = HookCfg { path: if path.starts_with('/') { path.to_string() } else { format!("/{path}") }, encrypt_key: nz(encrypt_key), verification_token: nz(verification_token) };
        if cfg.encrypt_key.is_none() && cfg.verification_token.is_none() {
            return Err(format!("channel {}: webhook mode needs encrypt_key or verification_token", self.id));
        }
        let tx = Mutex::new(self.shared.tx.clone());
        let handler: ark_net::httpd::Handler = Arc::new(move |r: ark_net::httpd::Request| {
            let (resp, ev) = handle_webhook(&cfg, &r, now_secs());
            if let Some(ev) = ev {
                let _ = tx.lock().unwrap().send(ev);
            }
            resp
        });
        let opts = ark_net::httpd::Opts { max_body: 1024 * 1024, ..Default::default() };
        let server = ark_net::httpd::Server::bind(listen, opts, handler).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.id))?;
        self.webhook = Some(server);
        Ok(self)
    }

    /// Route lookup for requester-bound tool behaviour (see [`crate::whatsapp::SessionOrigin`]).
    pub fn set_session_origin(&self, f: crate::whatsapp::SessionOrigin) {
        *self.origin.lock().unwrap() = Some(f);
    }

    /// Bound webhook address (tests bind port 0).
    pub fn webhook_addr(&self) -> Option<std::net::SocketAddr> {
        self.webhook.as_ref().map(|s| s.local_addr())
    }

    fn tenant_token(&self) -> Result<String, ChannelError> {
        if let Some((t, until)) = self.token.lock().unwrap().clone() {
            if Instant::now() < until {
                return Ok(t);
            }
        }
        let body = json!({"app_id": self.app_id, "app_secret": self.app_secret});
        let r = self.http.call("POST", &format!("{}/open-apis/auth/v3/tenant_access_token/internal", self.base), &[], Payload::Json(&body))?;
        let v = fs_result("tenant_access_token", r.status, r.retry_after, &r.body)?;
        let t = v["tenant_access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| err(K::Protocol, "tenant_access_token missing in response"))?.to_string();
        let ttl = v["expire"].as_u64().unwrap_or(7200).saturating_sub(300).max(60);
        *self.token.lock().unwrap() = Some((t.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(t)
    }

    /// One authenticated open-platform call with retries; returns the whole envelope.
    fn api(&self, method: &str, path: &str, body: Body) -> Result<Value, ChannelError> {
        let url = format!("{}{path}", self.base);
        let what = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let mut attempt = 0;
        let mut refreshed = false;
        loop {
            let tok = self.tenant_token()?;
            let auth = format!("Bearer {tok}");
            let payload = match body {
                Body::None => Payload::None,
                Body::Json(v) => Payload::Json(v),
                Body::Multi(p) => Payload::Multipart(p),
            };
            let res = self.http.call(method, &url, &[("authorization", &auth)], payload).and_then(|r| fs_result(&what, r.status, r.retry_after, &r.body));
            let e = match res {
                Ok(v) => return Ok(v),
                Err(e) if !refreshed && has_code(&e, &TOKEN_CODES) => {
                    refreshed = true;
                    *self.token.lock().unwrap() = None;
                    continue;
                }
                Err(e) if e.is_retryable() => e,
                Err(e) => return Err(e),
            };
            if attempt >= self.max_retries {
                return Err(e);
            }
            let wait = match e.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(e),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            sleep_cancellable(wait, &Cancel::new());
            attempt += 1;
        }
    }

    fn bot(&self) -> Bot {
        if let Some(b) = self.bot.lock().unwrap().clone() {
            return b;
        }
        match self.api("GET", "/open-apis/bot/v3/info", Body::None) {
            Ok(v) => {
                let b = &v["bot"];
                let bot = Bot { open_id: b["open_id"].as_str().unwrap_or("").into(), name: b["app_name"].as_str().or_else(|| b["bot_name"].as_str()).unwrap_or("").into() };
                *self.bot.lock().unwrap() = Some(bot.clone());
                bot
            }
            // Unknown identity: mentions are not detected, but messages still flow.
            Err(_) => Bot::default(),
        }
    }

    /// Display name of a user (or bot) open_id; "" when unknown. Failures are cached too.
    fn user_name(&self, id: &str, is_bot: bool) -> String {
        if id.is_empty() {
            return String::new();
        }
        if let Some((n, until)) = self.names.lock().unwrap().get(id) {
            if Instant::now() < *until {
                return n.clone();
            }
        }
        let name = if is_bot {
            self.api("GET", &format!("/open-apis/bot/v3/bots/basic_batch?bot_ids={}", ark_net::urlencode(id)), Body::None).ok().and_then(|v| v["data"]["bots"][id]["name"].as_str().map(|n| n.trim().to_string()))
        } else {
            let ty = if id.starts_with("ou_") { "open_id" } else if id.starts_with("on_") { "union_id" } else { "user_id" };
            self.api("GET", &format!("/open-apis/contact/v3/users/{}?user_id_type={ty}", ark_net::urlencode(id)), Body::None).ok().and_then(|v| {
                let u = &v["data"]["user"];
                ["name", "display_name", "nickname", "en_name"].iter().filter_map(|k| u[*k].as_str()).map(str::trim).find(|n| !n.is_empty()).map(str::to_string)
            })
        }
        .unwrap_or_default();
        let mut g = self.names.lock().unwrap();
        if g.len() > 4096 {
            g.clear();
        }
        g.insert(id.to_string(), (name.clone(), Instant::now() + NAME_TTL));
        name
    }

    /// Group name; "" when unknown.
    fn chat_name(&self, chat: &str) -> String {
        if let Some(n) = self.chat_names.lock().unwrap().get(chat) {
            return n.clone();
        }
        let name = self.api("GET", &format!("/open-apis/im/v1/chats/{}", ark_net::urlencode(chat)), Body::None).ok().and_then(|v| v["data"]["name"].as_str().map(str::to_string)).unwrap_or_default();
        let mut g = self.chat_names.lock().unwrap();
        if g.len() > 4096 {
            g.clear();
        }
        g.insert(chat.to_string(), name.clone());
        name
    }

    /// First sighting of a non-message event id.
    fn first_seen(&self, id: &str) -> bool {
        let mut g = self.seen_events.lock().unwrap();
        g.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
        g.insert(id.to_string(), Instant::now()).is_none()
    }

    /// Events other than messages and card clicks; `None` = not one of these.
    fn other_event(&self, v: &Value) -> Option<Option<Inbound>> {
        let ty = v["header"]["event_type"].as_str()?;
        let id = v["header"]["event_id"].as_str().unwrap_or("");
        let fresh = || id.is_empty() || self.first_seen(id);
        Some(match ty {
            "drive.notice.comment_add_v1" if fresh() => self.comment_inbound(v),
            "vc.bot.meeting_invited_v1" if fresh() => meeting::inbound_of(&self.id, v),
            "im.chat.member.bot.added_v1" | "im.chat.member.bot.deleted_v1" => {
                if let Some(c) = v["event"]["chat_id"].as_str() {
                    self.chat_names.lock().unwrap().remove(c);
                }
                None
            }
            "drive.notice.comment_add_v1" | "vc.bot.meeting_invited_v1" => None,
            _ => return None,
        })
    }

    /// (text, sent by us) of a replied-to message.
    fn parent(&self, mid: &str) -> Option<(String, bool)> {
        if let Some(p) = self.parents.lock().unwrap().get(mid) {
            return Some(p.clone());
        }
        let v = self.api("GET", &format!("/open-apis/im/v1/messages/{}", ark_net::urlencode(mid)), Body::None).ok()?;
        let item = &v["data"]["items"][0];
        let own = matches!(item["sender"]["sender_type"].as_str(), Some("app") | Some("bot")) && item["sender"]["id"].as_str() == Some(self.app_id.as_str());
        let content: Value = item["body"]["content"].as_str().and_then(|c| serde_json::from_str(c).ok()).unwrap_or(Value::Null);
        let text = match item["msg_type"].as_str() {
            Some("text") => content["text"].as_str().unwrap_or("").to_string(),
            Some("post") => parse_post(&content, &HashMap::new()).0,
            Some("interactive") => card_text(&content),
            _ => String::new(),
        };
        let mut p = self.parents.lock().unwrap();
        if p.len() > 512 {
            p.clear();
        }
        p.insert(mid.to_string(), (text.clone(), own));
        Some((text, own))
    }

    fn ensure_ws(&self) {
        if self.webhook.is_some() || self.ws_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let cfg = WsCfg { base: self.base.clone(), app_id: self.app_id.clone(), app_secret: self.app_secret.clone(), http: Http::new(Duration::from_secs(20)), backoff: self.ws_backoff };
        let sh = self.shared.clone();
        let _ = std::thread::Builder::new().name(format!("feishu-ws {}", self.id)).spawn(move || ws_loop(cfg, sh));
    }

    fn remember_sent(&self, id: &str, ty: &'static str) {
        let mut m = self.sent_types.lock().unwrap();
        if m.len() > 2048 {
            m.clear();
        }
        m.insert(id.to_string(), ty);
    }

    /// Send one message (reply when `reply_to`), returns its message_id.
    fn send_raw(&self, chat: &str, thread: Option<&str>, reply_to: Option<&str>, msg_type: &'static str, content: &str) -> Result<String, ChannelError> {
        // Same uuid on every retry: Feishu dedups it for an hour, so retries never double-post.
        let uuid = crypto::hex(&crypto::random_bytes(16));
        let reply_target = reply_to.or(thread.filter(|t| t.starts_with("om_")));
        if let Some(r) = reply_target {
            let body = json!({"content": content, "msg_type": msg_type, "reply_in_thread": thread.is_some(), "uuid": uuid});
            match self.api("POST", &format!("/open-apis/im/v1/messages/{}/reply", ark_net::urlencode(r)), Body::Json(&body)) {
                Ok(v) => return self.sent_id(&v, msg_type),
                // Withdrawn reply target: post into the chat — but never out of a thread.
                Err(e) if has_code(&e, &REPLY_FALLBACK_CODES) && thread.is_none() => {}
                Err(e) => return Err(e),
            }
        }
        let (id_type, receive_id) = match thread.filter(|t| t.starts_with("omt_")) {
            Some(t) => ("thread_id", t),
            None => receive_target(chat),
        };
        let body = json!({"receive_id": receive_id, "msg_type": msg_type, "content": content, "uuid": uuid});
        let v = self.api("POST", &format!("/open-apis/im/v1/messages?receive_id_type={id_type}"), Body::Json(&body))?;
        self.sent_id(&v, msg_type)
    }

    fn sent_id(&self, v: &Value, ty: &'static str) -> Result<String, ChannelError> {
        let id = v["data"]["message_id"].as_str().ok_or_else(|| err(K::Protocol, "send: no message_id in response"))?.to_string();
        self.remember_sent(&id, ty);
        Ok(id)
    }

    fn upload_image(&self, name: &str, mime: &str, data: &[u8]) -> Result<String, ChannelError> {
        let parts: [(&str, &str, &str, &[u8]); 2] = [("image_type", "", "", b"message"), ("image", name, mime, data)];
        let v = self.api("POST", "/open-apis/im/v1/images", Body::Multi(&parts))?;
        v["data"]["image_key"].as_str().map(str::to_string).ok_or_else(|| err(K::Protocol, "image upload: no image_key"))
    }

    fn upload_file(&self, file_type: &str, name: &str, mime: &str, data: &[u8], duration_ms: u64) -> Result<String, ChannelError> {
        let dur = duration_ms.to_string();
        let mut parts: Vec<(&str, &str, &str, &[u8])> = vec![("file_type", "", "", file_type.as_bytes()), ("file_name", "", "", name.as_bytes())];
        if duration_ms > 0 {
            parts.push(("duration", "", "", dur.as_bytes()));
        }
        parts.push(("file", name, mime, data));
        let v = self.api("POST", "/open-apis/im/v1/files", Body::Multi(&parts))?;
        v["data"]["file_key"].as_str().map(str::to_string).ok_or_else(|| err(K::Protocol, "file upload: no file_key"))
    }

    /// Upload (or reuse a key) and return (msg_type, content) for one attachment.
    fn media_message(&self, m: &Media) -> Result<(&'static str, String), ChannelError> {
        let (data, name) = match (&m.path, &m.url, &m.id) {
            (Some(p), _, _) => {
                let d = std::fs::read(p).map_err(|e| err(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                (d, std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()))
            }
            (None, Some(u), _) => {
                // Feishu cannot send by URL: fetch, then upload.
                let d = crate::http::get_bytes(u, &[], MAX_MEDIA)?;
                let n = u.split(['?', '#']).next().unwrap_or("").rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("file").to_string();
                (d, n)
            }
            (None, None, Some(key)) => {
                // A key from an earlier upload / inbound message.
                return Ok(match m.kind {
                    MediaKind::Image => ("image", json!({"image_key": key}).to_string()),
                    MediaKind::Voice => ("audio", json!({"file_key": key}).to_string()),
                    MediaKind::Video => ("media", json!({"file_key": key}).to_string()),
                    MediaKind::Sticker => ("sticker", json!({"file_key": key}).to_string()),
                    _ => ("file", json!({"file_key": key}).to_string()),
                });
            }
            _ => return Err(err(K::Fatal, "attachment has neither path, url nor id")),
        };
        let name = if m.name.is_empty() { name } else { m.name.clone() };
        if m.kind == MediaKind::Image || (m.kind == MediaKind::Animation && name.to_lowercase().ends_with(".gif")) {
            let key = self.upload_image(&name, &m.mime, &data)?;
            return Ok(("image", json!({"image_key": key}).to_string()));
        }
        let (file_type, msg_type) = file_routing(&name, m.kind);
        let dur = if file_type == "opus" { ogg_duration_ms(&data) } else { 0 };
        let key = self.upload_file(file_type, &name, &m.mime, &data, dur)?;
        Ok((msg_type, json!({"file_key": key}).to_string()))
    }
}

/// Upload `file_type` and message type for a file (Hermes `_resolve_outbound_file_routing`).
fn file_routing(name: &str, kind: MediaKind) -> (&'static str, &'static str) {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "ogg" | "opus" if kind == MediaKind::Voice => ("opus", "audio"),
        "mp4" | "mov" | "avi" | "m4v" => ("mp4", "media"),
        "pdf" => ("pdf", "file"),
        "doc" | "docx" => ("doc", "file"),
        "xls" | "xlsx" => ("xls", "file"),
        "ppt" | "pptx" => ("ppt", "file"),
        _ => ("stream", "file"),
    }
}

/// OGG/Opus duration: last granule position / 48 kHz (Hermes `_get_audio_duration_ms`).
fn ogg_duration_ms(d: &[u8]) -> u64 {
    let mut pos = 0;
    let mut last = 0i64;
    while pos + 27 <= d.len() {
        let Some(i) = d[pos..].windows(4).position(|w| w == b"OggS") else { break };
        pos += i;
        if pos + 27 > d.len() {
            break;
        }
        let g = i64::from_le_bytes(d[pos + 6..pos + 14].try_into().unwrap());
        if g > 0 {
            last = g;
        }
        let n = d[pos + 26] as usize;
        if pos + 27 + n > d.len() {
            break;
        }
        pos += 27 + n + d[pos + 27..pos + 27 + n].iter().map(|&b| b as usize).sum::<usize>();
    }
    if last > 0 {
        (last as u64) * 1000 / 48000
    } else {
        0
    }
}

/// `receive_id_type` from the id's shape: `oc_` chat, `ou_` open_id, `on_` union_id,
/// emails, and explicit `user_id:` / `open_id:` / `chat_id:` / `union_id:` / `email:` prefixes.
fn receive_target(chat: &str) -> (&'static str, &str) {
    for (p, t) in [("user_id:", "user_id"), ("open_id:", "open_id"), ("chat_id:", "chat_id"), ("union_id:", "union_id"), ("email:", "email")] {
        if let Some(rest) = chat.strip_prefix(p) {
            return (t, rest);
        }
    }
    if chat.starts_with("ou_") {
        ("open_id", chat)
    } else if chat.starts_with("on_") {
        ("union_id", chat)
    } else if chat.contains('@') {
        ("email", chat)
    } else {
        ("chat_id", chat)
    }
}

/// Post rows with each fenced code block in its own `md` row (Hermes `_build_markdown_post_rows`).
fn post_rows(md: &str) -> Vec<Value> {
    let row = |t: &str| json!([{"tag": "md", "text": t}]);
    if !md.contains("```") {
        return vec![row(md)];
    }
    let mut rows = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    let mut in_code = false;
    let flush = |cur: &mut Vec<&str>, rows: &mut Vec<Value>| {
        let seg = cur.join("\n");
        if !seg.trim().is_empty() {
            rows.push(row(&seg));
        }
        cur.clear();
    };
    for line in md.lines() {
        let t = line.trim();
        let fence = if in_code { t == "```" } else { t.strip_prefix("```").is_some_and(|l| !l.contains('`')) };
        if fence && !in_code {
            flush(&mut cur, &mut rows);
        }
        cur.push(line);
        if fence {
            in_code = !in_code;
            if !in_code {
                flush(&mut cur, &mut rows);
            }
        }
    }
    flush(&mut cur, &mut rows);
    if rows.is_empty() {
        rows.push(row(md));
    }
    rows
}

fn post_content(md: &str) -> String {
    json!({"zh_cn": {"content": post_rows(md)}}).to_string()
}

/// Interactive card: the text plus one `action` row per button row.
fn card(text: &str, format: TextFormat, rows: &[Vec<Button>]) -> Value {
    let mut elements = vec![match format {
        TextFormat::Markdown => json!({"tag": "markdown", "content": text}),
        TextFormat::Plain => json!({"tag": "div", "text": {"tag": "plain_text", "content": text}}),
    }];
    for r in rows {
        let actions: Vec<Value> = r
            .iter()
            .map(|b| match &b.url {
                Some(u) => json!({"tag": "button", "text": {"tag": "plain_text", "content": b.label}, "type": "default", "url": u}),
                None => json!({"tag": "button", "text": {"tag": "plain_text", "content": b.label}, "type": "primary", "value": {"data": b.data}}),
            })
            .collect();
        elements.push(json!({"tag": "action", "actions": actions}));
    }
    json!({"config": {"wide_screen_mode": true, "update_multi": true}, "elements": elements})
}

fn emoji_type(e: &str) -> String {
    let t = match e.trim_end_matches('\u{fe0f}') {
        "👍" => "THUMBSUP",
        "👎" => "ThumbsDown",
        "👌" => "OK",
        "😀" | "😄" | "🙂" | "😊" => "SMILE",
        "😂" => "LAUGH",
        "❤" => "HEART",
        "👏" => "APPLAUSE",
        "🔥" => "Fire",
        "✅" => "DONE",
        "❌" => "CrossMark",
        "🤔" => "THINKING",
        "👀" => "GLANCE",
        "🎉" => "PARTY",
        "⌨" | "✍" => "Typing",
        other => other,
    };
    t.to_string()
}

// ---------------------------------------------------------------- webhook

/// Signature check: `sha256(timestamp + nonce + encrypt_key + body)` hex, fresh timestamp.
fn signature_ok(key: &str, ts: &str, nonce: &str, sig: &str, body: &[u8], now: i64) -> bool {
    let Ok(t) = ts.trim().parse::<i64>() else { return false };
    let t = if t > 100_000_000_000 { t / 1000 } else { t };
    if (now - t).abs() > MAX_SKEW_SECS {
        return false;
    }
    let mut m = Vec::with_capacity(ts.len() + nonce.len() + key.len() + body.len());
    m.extend_from_slice(ts.as_bytes());
    m.extend_from_slice(nonce.as_bytes());
    m.extend_from_slice(key.as_bytes());
    m.extend_from_slice(body);
    crypto::ct_eq(crypto::hex(&crypto::sha256(&m)).as_bytes(), sig.trim().to_ascii_lowercase().as_bytes())
}

/// `{"encrypt": base64(iv ‖ AES-256-CBC(sha256(key), iv, json))}` → plaintext.
pub fn decrypt(key: &str, encrypted: &str) -> Option<String> {
    let raw = crypto::b64_decode(encrypted)?;
    if raw.len() < 32 {
        return None;
    }
    let aes = crypto::Aes::new(&crypto::sha256(key.as_bytes()))?;
    let iv: [u8; 16] = raw[..16].try_into().ok()?;
    String::from_utf8(aes.cbc_decrypt(&iv, &raw[16..])?).ok()
}

/// Inverse of [`decrypt`] (tests, and anyone simulating Feishu).
pub fn encrypt(key: &str, plain: &str, iv: [u8; 16]) -> String {
    let aes = crypto::Aes::new(&crypto::sha256(key.as_bytes())).expect("32-byte key");
    let mut out = iv.to_vec();
    out.extend(aes.cbc_encrypt(&iv, plain.as_bytes()));
    crypto::b64(&out)
}

fn is_card_action(v: &Value) -> bool {
    v["header"]["event_type"] == "card.action.trigger" || (v["action"].is_object() && v.get("open_message_id").is_some())
}

/// One webhook request → (response, event to queue).
fn handle_webhook(cfg: &HookCfg, r: &ark_net::httpd::Request, now: i64) -> (ark_net::httpd::Response, Option<Value>) {
    use ark_net::httpd::Response;
    let deny = |s: u16, m: &str| (Response::text(s, m), None);
    if r.path != cfg.path {
        return deny(404, "not found");
    }
    if r.method != "POST" {
        return deny(405, "method not allowed");
    }
    // Signed requests are verified before anything is parsed.
    if let Some(key) = &cfg.encrypt_key {
        let h = |n: &str| r.header(n).unwrap_or("");
        let (ts, nonce, sig) = (h("x-lark-request-timestamp"), h("x-lark-request-nonce"), h("x-lark-signature"));
        if ts.is_empty() || nonce.is_empty() || sig.is_empty() {
            return deny(401, "missing signature");
        }
        if !signature_ok(key, ts, nonce, sig, &r.body, now) {
            return deny(401, "invalid signature");
        }
    }
    let Ok(mut v) = serde_json::from_slice::<Value>(&r.body) else { return deny(400, "invalid json") };
    if let Some(enc) = v["encrypt"].as_str() {
        let Some(key) = &cfg.encrypt_key else { return deny(400, "encrypted payload but no encrypt_key configured") };
        match decrypt(key, enc).and_then(|p| serde_json::from_str::<Value>(&p).ok()) {
            Some(d) => v = d,
            None => return deny(401, "cannot decrypt payload"),
        }
    }
    if let Some(want) = &cfg.verification_token {
        let got = v["header"]["token"].as_str().or_else(|| v["token"].as_str()).unwrap_or("");
        // Without an encrypt key the token is the only proof of origin; with one, the
        // signature already authenticated the request and a present token must still match.
        let ok = if got.is_empty() { cfg.encrypt_key.is_some() } else { crypto::ct_eq(got.as_bytes(), want.as_bytes()) };
        // Legacy (v1) card callbacks put the action token in `token`, not the verification
        // token; accept them only when the signature already authenticated the request.
        let card_v1 = is_card_action(&v) && v["header"].is_null() && cfg.encrypt_key.is_some();
        if !ok && !card_v1 {
            return deny(401, "invalid verification token");
        }
    }
    if v["type"] == "url_verification" {
        let body = json!({"challenge": v["challenge"].as_str().unwrap_or("")}).to_string();
        return (Response::new(200, "application/json", body.into_bytes()), None);
    }
    let reply = if is_card_action(&v) { "{}".to_string() } else { json!({"code": 0, "msg": "ok"}).to_string() };
    (Response::new(200, "application/json", reply.into_bytes()), Some(v))
}

// ---------------------------------------------------------------- inbound parsing

/// Mention placeholder key → (display name, is us).
type Mentions = HashMap<String, (String, bool)>;

fn mentions_of(m: &Value, bot: &Bot) -> Mentions {
    let mut out = HashMap::new();
    for x in m["mentions"].as_array().into_iter().flatten() {
        let Some(key) = x["key"].as_str() else { continue };
        let open_id = x["id"]["open_id"].as_str().or_else(|| x["id"].as_str()).unwrap_or("");
        let name = x["name"].as_str().unwrap_or("").trim().to_string();
        let me = if !bot.open_id.is_empty() { open_id == bot.open_id } else { !bot.name.is_empty() && name == bot.name };
        out.insert(key.to_string(), (if name.is_empty() { open_id.to_string() } else { name }, me));
    }
    out
}

/// Replace `@_user_N` with names; drop leading/trailing self-mentions; tidy whitespace.
fn render_mentions(text: &str, ms: &Mentions) -> String {
    const SELF: char = '\u{1}';
    let mut keys: Vec<&String> = ms.keys().collect();
    // Longest first so @_user_10 is not eaten by @_user_1.
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    let mut s = text.to_string();
    for k in keys {
        let (name, me) = &ms[k];
        s = s.replace(k.as_str(), &if *me { SELF.to_string() } else { format!("@{name}") });
    }
    let s = s.replace("@_all", "@all");
    let s = s.trim_matches(|c: char| c == SELF || c.is_whitespace());
    let self_name = ms.values().find(|(_, me)| *me).map(|(n, _)| format!("@{n}")).unwrap_or_default();
    let s = s.replace(SELF, &self_name);
    s.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

/// Post (rich text) → (markdown-ish text, image keys, (file_key, name, kind) refs).
fn parse_post(content: &Value, ms: &Mentions) -> (String, Vec<String>, Vec<(String, String, MediaKind)>) {
    // `{"zh_cn": {...}}`, `{"post": {"zh_cn": …}}` or the locale body itself.
    let pick = |v: &Value| -> Option<Value> {
        if v["content"].is_array() {
            return Some(v.clone());
        }
        let o = v.as_object()?;
        ["zh_cn", "en_us"].iter().filter_map(|k| o.get(*k)).chain(o.values()).find(|x| x["content"].is_array()).cloned()
    };
    let Some(p) = pick(content).or_else(|| pick(&content["post"])) else { return (String::new(), vec![], vec![]) };
    let mut images = Vec::new();
    let mut files = Vec::new();
    let mut lines = Vec::new();
    if let Some(t) = p["title"].as_str().filter(|t| !t.trim().is_empty()) {
        lines.push(t.trim().to_string());
    }
    for row in p["content"].as_array().into_iter().flatten() {
        let mut line = String::new();
        for el in row.as_array().into_iter().flatten() {
            let s = |k: &str| el[k].as_str().unwrap_or("").to_string();
            match el["tag"].as_str().unwrap_or("") {
                "text" | "md" => line.push_str(&s("text")),
                "a" => {
                    let (t, h) = (s("text"), s("href"));
                    line.push_str(&if h.is_empty() { t } else { format!("[{}]({h})", if t.is_empty() { h.clone() } else { t }) });
                }
                "at" => {
                    let k = s("user_id");
                    match ms.get(&k) {
                        Some((_, true)) => line.push_str(&k),
                        Some((n, false)) => line.push_str(&format!("@{n}")),
                        None if k == "@_all" => line.push_str("@_all"),
                        None => line.push_str(&format!("@{}", el["user_name"].as_str().unwrap_or("user"))),
                    }
                }
                "img" | "image" => {
                    let k = s("image_key");
                    if !k.is_empty() && !images.contains(&k) {
                        images.push(k);
                    }
                }
                "media" | "file" | "audio" | "video" => {
                    let k = s("file_key");
                    if !k.is_empty() {
                        let kind = match el["tag"].as_str() {
                            Some("audio") => MediaKind::Audio,
                            Some("media") | Some("video") => MediaKind::Video,
                            _ => MediaKind::Document,
                        };
                        files.push((k, s("file_name"), kind));
                    }
                }
                "emotion" => line.push_str(&format!(":{}:", s("emoji_type"))),
                "code_block" => line.push_str(&format!("\n```{}\n{}\n```\n", s("language").to_lowercase(), s("text"))),
                "hr" => line.push_str("\n---\n"),
                "br" => line.push('\n'),
                _ => line.push_str(&s("text")),
            }
        }
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }
    (lines.join("\n"), images, files)
}

/// Readable text from an interactive card's JSON (titles, markdown, plain text, button labels).
fn card_text(v: &Value) -> String {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    match (k.as_str(), x) {
                        ("content" | "text" | "title", Value::String(s)) if !s.trim().is_empty() => out.push(s.trim().to_string()),
                        ("tag" | "url" | "href" | "image_key" | "file_key" | "value" | "template", _) => {}
                        _ => walk(x, out),
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    // JSON objects iterate in key order; the header title reads first.
    walk(&v["header"], &mut out);
    match v {
        Value::Object(o) => o.iter().filter(|(k, _)| *k != "header").for_each(|(_, x)| walk(x, &mut out)),
        other => walk(other, &mut out),
    }
    out.dedup();
    if out.is_empty() {
        "[Interactive message]".into()
    } else {
        out.join("\n")
    }
}

fn resource_url(base: &str, mid: &str, key: &str, ty: &str) -> String {
    format!("{base}/open-apis/im/v1/messages/{}/resources/{}?type={ty}", ark_net::urlencode(mid), ark_net::urlencode(key))
}

fn card_inbound(channel: &str, v: &Value, chat_types: &HashMap<String, ChatType>) -> Option<Inbound> {
    // v2 (`card.action.trigger`) nests under `event`; v1 card callbacks are flat.
    let e = if v["event"].is_object() { &v["event"] } else { v };
    let chat = e["context"]["open_chat_id"].as_str().or_else(|| e["open_chat_id"].as_str()).unwrap_or("").to_string();
    let msg = e["context"]["open_message_id"].as_str().or_else(|| e["open_message_id"].as_str()).unwrap_or("").to_string();
    let sender = e["operator"]["open_id"].as_str().or_else(|| e["open_id"].as_str()).unwrap_or("").to_string();
    if chat.is_empty() || sender.is_empty() {
        return None;
    }
    let token = e["token"].as_str().unwrap_or("").to_string();
    let value = &e["action"]["value"];
    let data = value["data"].as_str().map(str::to_string).or_else(|| value.as_str().map(str::to_string)).unwrap_or_else(|| if value.is_null() { String::new() } else { value.to_string() });
    let id = if token.is_empty() { format!("{msg}:{}", crypto::hex(&crypto::sha256(data.as_bytes()))[..12].to_owned()) } else { token };
    Some(Inbound {
        channel: channel.to_string(),
        chat_type: chat_types.get(&chat).copied().unwrap_or(ChatType::Group),
        chat,
        sender,
        message_id: format!("cb:{id}"),
        ts: now_secs(),
        callback: Some(Callback { id, data }),
        reply: (!msg.is_empty()).then(|| ReplyRef { id: msg, is_own: true, ..Default::default() }),
        ..Default::default()
    })
}

/// One event envelope → an Inbound. `base` builds resource download URLs.
fn inbound_of(channel: &str, base: &str, v: &Value, bot: &Bot, chat_types: &HashMap<String, ChatType>) -> Option<Inbound> {
    if is_card_action(v) {
        return card_inbound(channel, v, chat_types);
    }
    if v["header"]["event_type"] != "im.message.receive_v1" {
        return None;
    }
    let e = &v["event"];
    let m = &e["message"];
    let s = &e["sender"];
    let sender = s["sender_id"]["open_id"].as_str().or_else(|| s["sender_id"]["user_id"].as_str()).unwrap_or("").to_string();
    if !bot.open_id.is_empty() && sender == bot.open_id {
        return None;
    }
    let mid = m["message_id"].as_str()?.to_string();
    let ms = mentions_of(m, bot);
    let raw = m["content"].as_str().unwrap_or("");
    let content: Value = serde_json::from_str(raw).unwrap_or_else(|_| json!({"text": raw}));
    let mut media = Vec::new();
    let file = |key: &str, name: &str, kind: MediaKind| Media {
        kind,
        id: Some(key.to_string()),
        url: Some(resource_url(base, &mid, key, if kind == MediaKind::Image { "image" } else { "file" })),
        name: name.to_string(),
        mime: if kind == MediaKind::Image { "image/jpeg".into() } else { String::new() },
        ..Default::default()
    };
    let s_ = |k: &str| content[k].as_str().unwrap_or("").to_string();
    let text = match m["message_type"].as_str().unwrap_or("") {
        "text" => render_mentions(&s_("text"), &ms),
        "post" => {
            let (t, imgs, files) = parse_post(&content, &ms);
            media.extend(imgs.iter().map(|k| file(k, "image.jpg", MediaKind::Image)));
            media.extend(files.iter().map(|(k, n, kind)| file(k, n, *kind)));
            render_mentions(&t, &ms)
        }
        "image" => {
            media.push(file(&s_("image_key"), "image.jpg", MediaKind::Image));
            String::new()
        }
        "file" => {
            media.push(file(&s_("file_key"), &s_("file_name"), MediaKind::Document));
            String::new()
        }
        "audio" => {
            media.push(Media { mime: "audio/opus".into(), ..file(&s_("file_key"), "voice.opus", MediaKind::Voice) });
            String::new()
        }
        "media" => {
            let n = s_("file_name");
            media.push(Media { mime: "video/mp4".into(), ..file(&s_("file_key"), if n.is_empty() { "video.mp4" } else { &n }, MediaKind::Video) });
            String::new()
        }
        "sticker" => {
            // Stickers cannot be downloaded through the resources API.
            media.push(Media { kind: MediaKind::Sticker, id: Some(s_("file_key")), ..Default::default() });
            String::new()
        }
        "interactive" => card_text(&content),
        "share_chat" => "[Shared chat]".into(),
        "share_user" => "[Shared contact]".into(),
        "merge_forward" => "[Merged forward message]".into(),
        "location" => format!("[Location: {} {},{}]", s_("name"), s_("latitude"), s_("longitude")),
        _ => return None,
    };
    media.retain(|x| x.id.as_deref().is_some_and(|k| !k.is_empty()));
    if text.is_empty() && media.is_empty() {
        return None;
    }
    let chat_type = match m["chat_type"].as_str() {
        Some("p2p") => ChatType::Direct,
        _ => ChatType::Group,
    };
    let parent = m["parent_id"].as_str().filter(|p| !p.is_empty());
    Some(Inbound {
        channel: channel.to_string(),
        chat: m["chat_id"].as_str()?.to_string(),
        chat_type,
        // Only a native thread_id marks a topic: root_id is set on every quoted reply too.
        thread: m["thread_id"].as_str().filter(|t| !t.is_empty()).map(str::to_string),
        sender,
        is_bot: matches!(s["sender_type"].as_str(), Some("bot") | Some("app")),
        text,
        message_id: mid,
        ts: m["create_time"].as_str().and_then(|t| t.parse::<i64>().ok()).or_else(|| m["create_time"].as_i64()).map(|t| t / 1000).unwrap_or(0),
        media,
        mentioned: ms.values().any(|(_, me)| *me) || raw.contains("@_all"),
        reply: parent.map(|p| ReplyRef { id: p.to_string(), ..Default::default() }),
        ..Default::default()
    })
}

// ---------------------------------------------------------------- WebSocket long connection

/// pbbs.proto `Frame` of the Lark long-connection protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub seq_id: u64,
    pub log_id: u64,
    pub service: i32,
    /// 0 = control (ping/pong), 1 = data (event/card).
    pub method: i32,
    pub headers: Vec<(String, String)>,
    pub payload_encoding: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub log_id_new: String,
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    put_varint(out, ((field << 3) | 2) as u64);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn get_varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*i)?;
        *i += 1;
        v |= ((x & 0x7f) as u64) << shift;
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Iterate (field, wire type, varint value, bytes) over a protobuf message.
fn fields(b: &[u8]) -> Option<Vec<(u32, u64, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let tag = get_varint(b, &mut i)?;
        let (field, wt) = ((tag >> 3) as u32, tag & 7);
        match wt {
            0 => out.push((field, get_varint(b, &mut i)?, &b[0..0])),
            2 => {
                let n = get_varint(b, &mut i)? as usize;
                let end = i.checked_add(n).filter(|e| *e <= b.len())?;
                out.push((field, 0, &b[i..end]));
                i = end;
            }
            1 => i += 8,
            5 => i += 4,
            _ => return None,
        }
        if i > b.len() {
            return None;
        }
    }
    Some(out)
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        for (f, v) in [(1u32, self.seq_id), (2, self.log_id), (3, self.service as i64 as u64), (4, self.method as i64 as u64)] {
            put_varint(&mut o, (f << 3) as u64);
            put_varint(&mut o, v);
        }
        for (k, v) in &self.headers {
            let mut h = Vec::new();
            put_bytes(&mut h, 1, k.as_bytes());
            put_bytes(&mut h, 2, v.as_bytes());
            put_bytes(&mut o, 5, &h);
        }
        for (f, s) in [(6u32, &self.payload_encoding), (7, &self.payload_type)] {
            if !s.is_empty() {
                put_bytes(&mut o, f, s.as_bytes());
            }
        }
        if !self.payload.is_empty() {
            put_bytes(&mut o, 8, &self.payload);
        }
        if !self.log_id_new.is_empty() {
            put_bytes(&mut o, 9, self.log_id_new.as_bytes());
        }
        o
    }

    pub fn decode(b: &[u8]) -> Option<Frame> {
        let mut f = Frame::default();
        let s = |x: &[u8]| String::from_utf8_lossy(x).into_owned();
        for (field, n, bytes) in fields(b)? {
            match field {
                1 => f.seq_id = n,
                2 => f.log_id = n,
                3 => f.service = n as i32,
                4 => f.method = n as i32,
                5 => {
                    let mut kv = (String::new(), String::new());
                    for (hf, _, hb) in fields(bytes)? {
                        match hf {
                            1 => kv.0 = s(hb),
                            2 => kv.1 = s(hb),
                            _ => {}
                        }
                    }
                    f.headers.push(kv);
                }
                6 => f.payload_encoding = s(bytes),
                7 => f.payload_type = s(bytes),
                8 => f.payload = bytes.to_vec(),
                9 => f.log_id_new = s(bytes),
                _ => {}
            }
        }
        Some(f)
    }

    pub fn header(&self, k: &str) -> &str {
        self.headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

/// `POST /callback/ws/endpoint` → (wss URL, ping interval).
fn ws_endpoint(cfg: &WsCfg) -> Result<(String, Duration), ChannelError> {
    let body = json!({"AppID": cfg.app_id, "AppSecret": cfg.app_secret});
    let r = cfg.http.call("POST", &format!("{}/callback/ws/endpoint", cfg.base), &[("locale", "zh")], Payload::Json(&body))?;
    let v: Value = serde_json::from_str(&r.body).map_err(|_| crate::http::classify(r.status, r.retry_after, "ws endpoint", &r.body))?;
    let code = v["code"].as_i64().unwrap_or(-1);
    if code != 0 || !(200..300).contains(&r.status) {
        let msg = format!("ws endpoint: code={code} {}", v["msg"].as_str().unwrap_or(""));
        return Err(match code {
            403 | 514 => err(K::Auth, msg),
            1000040350 => err(K::RateLimited { retry_after: None }, msg),
            _ if (200..300).contains(&r.status) => err(K::Network, msg),
            _ => crate::http::classify(r.status, r.retry_after, "ws endpoint", &msg),
        });
    }
    let url = v["data"]["URL"].as_str().filter(|u| !u.is_empty()).ok_or_else(|| err(K::Protocol, "ws endpoint: no URL"))?.to_string();
    let ping = v["data"]["ClientConfig"]["PingInterval"].as_u64().unwrap_or(120).max(1);
    Ok((url, Duration::from_secs(ping)))
}

fn ws_loop(cfg: WsCfg, sh: Arc<Shared>) {
    let mut attempt = 0u32;
    while !sh.stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let e = match ws_session(&cfg, &sh) {
            Ok(()) => return,
            Err(e) => e,
        };
        if e.kind == K::Auth {
            *sh.fatal.lock().unwrap() = Some(e);
            return;
        }
        if started.elapsed() > Duration::from_secs(60) {
            attempt = 0;
        }
        let wait = match e.kind {
            K::RateLimited { retry_after: Some(d) } => d,
            _ => (cfg.backoff * 2u32.saturating_pow(attempt.min(6))).min(Duration::from_secs(60)),
        };
        attempt += 1;
        let until = Instant::now() + wait;
        while Instant::now() < until && !sh.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Partial payloads of one fragmented message, and when the first arrived.
type Fragments = (Vec<Option<Vec<u8>>>, Instant);

fn ws_session(cfg: &WsCfg, sh: &Shared) -> Result<(), ChannelError> {
    use ark_net::ws::{Message, WebSocket};
    let net = |e: std::io::Error| err(K::Network, format!("feishu ws: {e}"));
    let (url, mut ping_every) = ws_endpoint(cfg)?;
    let service: i32 = url.split_once('?').map(|(_, q)| ark_net::parse_query(q)).unwrap_or_default().into_iter().find(|(k, _)| k == "service_id").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let (mut ws, _) = WebSocket::connect(&url, &[], Duration::from_secs(15)).map_err(net)?;
    ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(net)?;
    let mut next_ping = Instant::now();
    let mut parts: HashMap<String, Fragments> = HashMap::new();
    loop {
        if sh.stop.load(Ordering::SeqCst) {
            let _ = ws.send(&Message::Close(Some((1000, String::new()))));
            return Ok(());
        }
        if Instant::now() >= next_ping {
            let ping = Frame { service, method: 0, headers: vec![("type".into(), "ping".into())], ..Default::default() };
            ws.send(&Message::Binary(ping.encode())).map_err(net)?;
            next_ping = Instant::now() + ping_every;
        }
        let f = match ws.recv().map_err(net)? {
            None => continue,
            Some(Message::Binary(b)) => Frame::decode(&b).ok_or_else(|| err(K::Protocol, "feishu ws: undecodable frame"))?,
            Some(Message::Close(c)) => return Err(err(K::Network, format!("feishu ws closed by server {c:?}"))),
            Some(_) => continue,
        };
        let ty = f.header("type").to_string();
        if f.method == 0 {
            if ty == "pong" {
                if let Some(p) = serde_json::from_slice::<Value>(&f.payload).ok().and_then(|v| v["PingInterval"].as_u64()) {
                    ping_every = Duration::from_secs(p.max(1));
                }
            }
            continue;
        }
        let started = Instant::now();
        let sum: usize = f.header("sum").parse().unwrap_or(1).clamp(1, 64);
        let payload = if sum == 1 {
            f.payload.clone()
        } else {
            let seq: usize = f.header("seq").parse().unwrap_or(0);
            parts.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(10));
            let e = parts.entry(f.header("message_id").to_string()).or_insert_with(|| (vec![None; sum], Instant::now()));
            if seq < e.0.len() {
                e.0[seq] = Some(f.payload.clone());
            }
            if e.0.iter().any(Option::is_none) {
                continue;
            }
            let chunks = parts.remove(f.header("message_id")).map(|(c, _)| c).unwrap_or_default();
            chunks.into_iter().flatten().flatten().collect()
        };
        if let Ok(v) = serde_json::from_slice::<Value>(&payload) {
            let _ = sh.tx.send(v);
        }
        let mut resp = json!({"code": 200});
        if ty == "card" {
            resp["data"] = json!(crypto::b64(b"{}"));
        }
        let mut ack = f.clone();
        ack.headers.push(("biz_rt".into(), started.elapsed().as_millis().to_string()));
        ack.payload = resp.to_string().into_bytes();
        ws.send(&Message::Binary(ack.encode())).map_err(net)?;
    }
}

// ---------------------------------------------------------------- Channel

impl Channel for Feishu {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 2,
            edit: true,
            delete: true,
            typing: false,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_ws();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        {
            let rx = self.rx.lock().unwrap();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Some(e) = self.shared.fatal.lock().unwrap().take() {
                    return Err(e);
                }
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
        }
        self.sweep_approvals();
        if got.is_empty() {
            return Ok(vec![]);
        }
        let needs_bot = got.iter().any(|v| v["event"]["message"]["chat_type"].as_str().is_some_and(|t| t != "p2p"));
        let bot = if needs_bot { self.bot() } else { self.bot.lock().unwrap().clone().unwrap_or_default() };
        let mut out = Vec::new();
        for v in &got {
            if let Some(ev) = self.other_event(v) {
                out.extend(ev.map(|mut ib| {
                    if self.resolve_names && ib.sender_name.is_empty() {
                        ib.sender_name = self.user_name(&ib.sender, false);
                    }
                    ib
                }));
                continue;
            }
            let types = self.chat_types.lock().unwrap().clone();
            let Some(mut ib) = inbound_of(&self.id, &self.base, v, &bot, &types) else { continue };
            if self.resolve_names {
                ib.sender_name = self.user_name(&ib.sender, ib.is_bot);
                if ib.chat_type == ChatType::Group {
                    ib.chat_name = self.chat_name(&ib.chat);
                }
            }
            if ib.callback.is_some() && !self.approval_click(&ib) {
                continue;
            }
            if ib.callback.is_none() {
                let mut t = self.chat_types.lock().unwrap();
                if t.len() > 4096 {
                    t.clear();
                }
                t.insert(ib.chat.clone(), ib.chat_type);
                if let Some(r) = ib.reply.as_mut() {
                    if let Some((text, own)) = self.parent(&r.id) {
                        r.text = text;
                        r.is_own = own;
                    }
                }
            }
            out.push(ib);
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        if out.chat.starts_with("doc:") {
            return self.comment_send(&out.chat, out.thread.as_deref(), &out.text);
        }
        let mut sent = Sent::default();
        let thread = out.thread.as_deref().filter(|t| !t.is_empty());
        // Inside a thread every piece replies so it stays there; elsewhere only the first.
        let reply_for = |first: bool| if first || thread.is_some() { out.reply_to.as_deref() } else { None };
        for (i, m) in out.media.iter().enumerate() {
            let (ty, content) = self.media_message(m)?;
            sent.ids.push(self.send_raw(&out.chat, thread, reply_for(i == 0), ty, &content)?);
            if let Some(c) = m.caption.as_deref().filter(|c| !c.trim().is_empty()) {
                sent.ids.push(self.send_raw(&out.chat, thread, reply_for(false), "text", &json!({"text": c}).to_string())?);
            }
        }
        if out.text.trim().is_empty() {
            return Ok(sent);
        }
        let pieces = crate::chunk::split(&out.text, MAX_MESSAGE, LenUnit::Chars);
        let n = pieces.len();
        let appr = approval::id_of(&out.buttons);
        for (i, p) in pieces.iter().enumerate() {
            let first = i == 0 && out.media.is_empty();
            if let (Some(id), true) = (&appr, i + 1 == n) {
                let mid = self.send_raw(&out.chat, thread, reply_for(first), "interactive", &approval::prompt_card(p, &out.buttons).to_string())?;
                self.track_approval(id, &out.chat, &mid, p);
                sent.ids.push(mid);
                continue;
            }
            let (ty, content) = if i + 1 == n && !out.buttons.is_empty() {
                ("interactive", card(p, out.format, &out.buttons).to_string())
            } else {
                match out.format {
                    TextFormat::Markdown => ("post", post_content(p)),
                    TextFormat::Plain => ("text", json!({"text": p}).to_string()),
                }
            };
            sent.ids.push(self.send_raw(&out.chat, thread, reply_for(first), ty, &content)?);
        }
        Ok(sent)
    }

    fn edit(&self, _chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let path = format!("/open-apis/im/v1/messages/{}", ark_net::urlencode(message_id));
        let ty = self.sent_types.lock().unwrap().get(message_id).copied();
        if ty == Some("interactive") {
            // Cards keep their buttons only if re-sent; edits replace them with plain content.
            let body = json!({"content": card(text, TextFormat::Markdown, &[]).to_string()});
            return self.api("PATCH", &path, Body::Json(&body)).map(|_| ());
        }
        let body = json!({"msg_type": "post", "content": post_content(text)});
        self.api("PUT", &path, Body::Json(&body)).map(|_| ())
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.api("DELETE", &format!("/open-apis/im/v1/messages/{}", ark_net::urlencode(message_id)), Body::None).map(|_| ())
    }

    fn react(&self, _chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let ty = emoji_type(emoji);
        let base = format!("/open-apis/im/v1/messages/{}/reactions", ark_net::urlencode(message_id));
        let key = (message_id.to_string(), ty.clone());
        if !remove {
            let v = self.api("POST", &base, Body::Json(&json!({"reaction_type": {"emoji_type": ty}})))?;
            if let Some(id) = v["data"]["reaction_id"].as_str() {
                self.reactions.lock().unwrap().insert(key, id.to_string());
            }
            return Ok(());
        }
        let ids: Vec<String> = match self.reactions.lock().unwrap().remove(&key) {
            Some(id) => vec![id],
            None => {
                // Not added by this process: find our own (operator_type app) reactions of that type.
                let v = self.api("GET", &format!("{base}?reaction_type={}", ark_net::urlencode(&ty)), Body::None)?;
                v["data"]["items"].as_array().into_iter().flatten().filter(|x| x["operator"]["operator_type"] == "app").filter_map(|x| x["reaction_id"].as_str().map(str::to_string)).collect()
            }
        };
        for id in ids {
            self.api("DELETE", &format!("{base}/{}", ark_net::urlencode(&id)), Body::None)?;
        }
        Ok(())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().ok_or_else(|| crate::unsupported("downloading this attachment"))?;
        let auth = format!("Bearer {}", self.tenant_token()?);
        crate::http::get_bytes(url, &[("authorization", &auth)], MAX_MEDIA)
    }

    fn wire(&self, w: &crate::Wiring) {
        if let Some(o) = &w.session_origin {
            self.set_session_origin(o.clone());
        }
    }

    fn message_action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
        tools::message_action(self, action, args)
    }

    fn message_actions(&self) -> Vec<&'static str> {
        tools::MESSAGE_ACTIONS.to_vec()
    }

    /// `feishu_doc_read`, `feishu_doc`, `feishu_wiki`, `feishu_drive`, `feishu_chat`,
    /// `feishu_app_scopes`, `feishu_bitable_*` (and `feishu_perm` when enabled).
    fn tools(&self) -> Vec<Arc<dyn ark_core::Tool>> {
        tools::tools(self, &self.tool_families, self.media_max_mb, self.origin.clone())
    }

    fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Feishu {
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
    app_id: String,
    app_secret: String,
    /// `feishu` (open.feishu.cn, default) or `lark` (open.larksuite.com).
    #[serde(default)]
    domain: Option<String>,
    /// Override of the API origin (private deployments, tests).
    #[serde(default)]
    base_url: Option<String>,
    /// `websocket` (default) or `webhook` (implied by `listen`).
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    webhook_path: Option<String>,
    #[serde(default)]
    encrypt_key: Option<String>,
    #[serde(default)]
    verification_token: Option<String>,
    /// Skip the `/bot/v3/info` lookup.
    #[serde(default)]
    bot_open_id: Option<String>,
    #[serde(default)]
    bot_name: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Look up sender / group display names.
    #[serde(default = "d_true")]
    resolve_names: bool,
    /// Approval cards still pending after this are marked expired.
    #[serde(default = "d_approval")]
    approval_timeout_secs: u64,
    /// Answer cloud-document comments that @mention the bot.
    #[serde(default = "d_true")]
    comments: bool,
    /// Only these documents (`docx:<token>`, `<token>` or `*`); empty = all.
    #[serde(default)]
    comment_documents: Vec<String>,
    /// Agent tool families: doc, chat, wiki, drive, scopes, bitable (default on), perm (default off).
    #[serde(default)]
    tools: std::collections::BTreeMap<String, bool>,
    /// Upload limit for `feishu_doc` images/files.
    #[serde(default = "d_media_mb")]
    media_max_mb: u64,
}

fn d_media_mb() -> u64 {
    30
}

fn d_true() -> bool {
    true
}
fn d_approval() -> u64 {
    600
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let secret = ctx.secret("app_secret", &st.app_secret)?;
    let mut f = Feishu::new(ctx.name, &st.app_id, &secret, st.domain.as_deref().unwrap_or("feishu"), st.base_url.as_deref(), st.poll_timeout_secs)?;
    if let Some(o) = st.bot_open_id.as_deref().filter(|o| !o.is_empty()) {
        f = f.with_bot(o, st.bot_name.as_deref().unwrap_or(""));
    }
    f.resolve_names = st.resolve_names;
    f.approval_timeout = Duration::from_secs(st.approval_timeout_secs.max(1));
    f.comments = st.comments;
    f.comment_docs = st.comment_documents.clone();
    f.tool_families = st.tools.clone();
    f.media_max_mb = st.media_max_mb;
    let mode = st.mode.as_deref().unwrap_or(if st.listen.is_some() { "webhook" } else { "websocket" });
    match mode {
        "webhook" => {
            let listen = st.listen.as_deref().ok_or_else(|| format!("channel {}: webhook mode needs listen", ctx.name))?;
            let ek = ctx.opt_secret("encrypt_key", &st.encrypt_key)?;
            let vt = ctx.opt_secret("verification_token", &st.verification_token)?;
            f = f.with_webhook(listen, st.webhook_path.as_deref().unwrap_or("/feishu/webhook"), ek.as_deref(), vt.as_deref())?;
        }
        "websocket" | "ws" => {
            if st.listen.is_some() {
                return Err(format!("channel {}: listen is only used in webhook mode", ctx.name));
            }
        }
        other => return Err(format!("channel {}: mode must be websocket or webhook, not {other:?}", ctx.name)),
    }
    Ok(Arc::new(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeServer, Req};

    type Reply = (u16, Vec<(String, String)>, String);

    fn ok(data: Value) -> Reply {
        (200, vec![], json!({"code": 0, "msg": "ok", "data": data}).to_string())
    }

    fn token_reply() -> Reply {
        (200, vec![], json!({"code": 0, "msg": "ok", "tenant_access_token": "t-SECRET", "expire": 7200}).to_string())
    }

    fn is_token(r: &Req) -> bool {
        r.path.ends_with("/tenant_access_token/internal")
    }

    fn fs(url: &str) -> Feishu {
        let mut f = Feishu::new("fs", "cli_app", "APPSECRET", "feishu", Some(url), 1).unwrap().with_bot("ou_bot", "Ark");
        f.retry_base = Duration::from_millis(5);
        f.ws_backoff = Duration::from_millis(20);
        f
    }

    fn api_calls(srv: &FakeServer) -> Vec<Req> {
        srv.requests().into_iter().filter(|r| !is_token(r)).collect()
    }

    fn msg_event(mid: &str, chat_type: &str, msg_type: &str, content: Value, extra: Value) -> Value {
        let mut m = json!({"message_id": mid, "chat_id": "oc_chat", "chat_type": chat_type, "message_type": msg_type, "content": content.to_string(), "create_time": "1700000000123"});
        if let Some(o) = extra.as_object() {
            for (k, v) in o {
                m[k] = v.clone();
            }
        }
        json!({"schema": "2.0", "header": {"event_id": format!("ev-{mid}"), "event_type": "im.message.receive_v1", "token": "vt", "app_id": "cli_app"},
               "event": {"sender": {"sender_id": {"open_id": "ou_amy", "union_id": "on_amy"}, "sender_type": "user"}, "message": m}})
    }

    fn parse(v: &Value) -> Option<Inbound> {
        inbound_of("fs", "http://h", v, &Bot { open_id: "ou_bot".into(), name: "Ark".into() }, &HashMap::new())
    }

    #[test]
    fn parses_every_message_kind_mentions_threads_and_callbacks() {
        let mention = json!({"mentions": [{"key": "@_user_1", "id": {"open_id": "ou_bot"}, "name": "Ark"}, {"key": "@_user_2", "id": {"open_id": "ou_bob"}, "name": "Bob"}]});
        let t = parse(&msg_event("om_1", "group", "text", json!({"text": "@_user_1  ask @_user_2 now"}), mention.clone())).unwrap();
        assert_eq!((t.text.as_str(), t.mentioned, t.chat_type, t.chat.as_str(), t.sender.as_str(), t.ts), ("ask @Bob now", true, ChatType::Group, "oc_chat", "ou_amy", 1700000000));
        let other = parse(&msg_event("om_2", "group", "text", json!({"text": "@_user_2 hi"}), json!({"mentions": [{"key": "@_user_2", "id": {"open_id": "ou_bob"}, "name": "Bob"}]}))).unwrap();
        assert!(!other.mentioned && other.text == "@Bob hi");
        let dm = parse(&msg_event("om_3", "p2p", "text", json!({"text": "hello"}), json!({}))).unwrap();
        assert_eq!(dm.chat_type, ChatType::Direct);
        assert!(parse(&msg_event("om_4", "group", "text", json!({"text": "hi @_all"}), json!({}))).unwrap().mentioned, "@all counts");
        // Topic thread + reply parent.
        let th = parse(&msg_event("om_5", "group", "text", json!({"text": "in topic"}), json!({"thread_id": "omt_9", "root_id": "om_r", "parent_id": "om_p"}))).unwrap();
        assert_eq!((th.thread.as_deref(), th.reply.as_ref().map(|r| r.id.as_str())), (Some("omt_9"), Some("om_p")));
        let quote = parse(&msg_event("om_6", "group", "text", json!({"text": "q"}), json!({"root_id": "om_r", "parent_id": "om_r"}))).unwrap();
        assert!(quote.thread.is_none(), "root_id alone is not a topic");
        // Post with title, at, link, image and file.
        let post = json!({"zh_cn": {"title": "T", "content": [[{"tag": "at", "user_id": "@_user_1"}, {"tag": "text", "text": " see "}, {"tag": "a", "text": "doc", "href": "https://e.com"}], [{"tag": "img", "image_key": "img_1"}], [{"tag": "media", "file_key": "file_v", "file_name": "v.mp4"}]]}});
        let p = parse(&msg_event("om_7", "group", "post", post, mention)).unwrap();
        assert!(p.mentioned);
        assert_eq!(p.text, "T\n@Ark see [doc](https://e.com)", "self-mentions are only stripped at the text edges");
        assert_eq!(p.media.len(), 2);
        assert_eq!((p.media[0].kind, p.media[0].url.as_deref()), (MediaKind::Image, Some("http://h/open-apis/im/v1/messages/om_7/resources/img_1?type=image")));
        assert_eq!((p.media[1].kind, p.media[1].name.as_str()), (MediaKind::Video, "v.mp4"));
        let img = parse(&msg_event("om_8", "p2p", "image", json!({"image_key": "img_2"}), json!({}))).unwrap();
        assert_eq!((img.text.as_str(), img.media[0].id.as_deref()), ("", Some("img_2")));
        let file = parse(&msg_event("om_9", "p2p", "file", json!({"file_key": "f_1", "file_name": "a.pdf"}), json!({}))).unwrap();
        assert_eq!((file.media[0].kind, file.media[0].name.as_str(), file.media[0].url.as_deref().unwrap().ends_with("/resources/f_1?type=file")), (MediaKind::Document, "a.pdf", true));
        let audio = parse(&msg_event("om_10", "p2p", "audio", json!({"file_key": "f_a", "duration": 2000}), json!({}))).unwrap();
        assert_eq!(audio.media[0].kind, MediaKind::Voice);
        let video = parse(&msg_event("om_11", "p2p", "media", json!({"file_key": "f_v", "image_key": "img_t", "file_name": "c.mp4"}), json!({}))).unwrap();
        assert_eq!((video.media[0].kind, video.media[0].id.as_deref()), (MediaKind::Video, Some("f_v")));
        let card = parse(&msg_event("om_12", "group", "interactive", json!({"header": {"title": {"tag": "plain_text", "content": "Deploy"}}, "elements": [{"tag": "markdown", "content": "done"}]}), json!({}))).unwrap();
        assert_eq!(card.text, "Deploy\ndone");
        // Own messages dropped; other bots flagged; unknown kinds and empty texts skipped.
        let mut own = msg_event("om_13", "group", "text", json!({"text": "me"}), json!({}));
        own["event"]["sender"]["sender_id"]["open_id"] = json!("ou_bot");
        assert!(parse(&own).is_none());
        let mut bot = msg_event("om_14", "group", "text", json!({"text": "beep"}), json!({}));
        bot["event"]["sender"]["sender_type"] = json!("app");
        assert!(parse(&bot).unwrap().is_bot);
        assert!(parse(&msg_event("om_15", "group", "system", json!({}), json!({}))).is_none());
        assert!(parse(&msg_event("om_16", "group", "text", json!({"text": "@_user_1"}), json!({"mentions": [{"key": "@_user_1", "id": {"open_id": "ou_bot"}, "name": "Ark"}]}))).is_none(), "bare @bot is empty");
        // Card actions, v2 and v1 shapes.
        let v2 = json!({"schema": "2.0", "header": {"event_type": "card.action.trigger", "token": "vt"}, "event": {"operator": {"open_id": "ou_amy"}, "token": "c-tok", "action": {"tag": "button", "value": {"data": "appr:1:once"}}, "context": {"open_message_id": "om_card", "open_chat_id": "oc_chat"}}});
        let c = parse(&v2).unwrap();
        assert_eq!((c.callback.as_ref().unwrap().data.as_str(), c.callback.as_ref().unwrap().id.as_str(), c.message_id.as_str(), c.sender.as_str()), ("appr:1:once", "c-tok", "cb:c-tok", "ou_amy"));
        assert!(c.reply.as_ref().unwrap().is_own && c.chat_type == ChatType::Group);
        let v1 = json!({"open_id": "ou_amy", "open_message_id": "om_card", "open_chat_id": "oc_dm", "token": "c-2", "action": {"value": {"k": 1}, "tag": "button"}});
        let mut types = HashMap::new();
        types.insert("oc_dm".to_string(), ChatType::Direct);
        let c1 = inbound_of("fs", "http://h", &v1, &Bot::default(), &types).unwrap();
        assert_eq!((c1.callback.unwrap().data.as_str(), c1.chat_type), (r#"{"k":1}"#, ChatType::Direct));
    }

    #[test]
    fn crypto_known_answers_and_signature() {
        // Fixed vector made with `openssl enc -aes-256-cbc -K sha256("encrypt_key") -iv 000102…0f`.
        let enc = "AAECAwQFBgcICQoLDA0OD53vTxQxzdifYG54AaWPu2RVRgbTm/kqchcX1irN9yj2fk5OOqAehj+z/F1I2pWjGw78Xx46DXWz46Je59iLChPM1ZnrUdOkyKQBXttXL2+h";
        let plain = r#"{"type":"url_verification","challenge":"kat-challenge","token":"vt"}"#;
        assert_eq!(decrypt("encrypt_key", enc).as_deref(), Some(plain));
        let iv: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(encrypt("encrypt_key", plain, iv), enc);
        // Feishu documentation example: key "test key" → "hello world".
        assert_eq!(decrypt("test key", "P37w+VZImNgPEO1RBhJ6RtKl7n6zymIbEG1pReEzghk=").as_deref(), Some("hello world"));
        assert!(decrypt("wrong", enc).is_none_or(|p| p != plain));
        assert!(decrypt("encrypt_key", "AAEC").is_none());
        // sha256("1700000000" + "nonce-test" + "encrypt_key" + body), from openssl dgst.
        let sig = "cfa5b24a1778b7e90d315f36c45e9d30e755a14d8368961ea5d5bc1d53138813";
        assert!(signature_ok("encrypt_key", "1700000000", "nonce-test", sig, br#"{"a":1}"#, 1700000100));
        assert!(!signature_ok("encrypt_key", "1700000000", "nonce-test", sig, br#"{"a":2}"#, 1700000100));
        assert!(!signature_ok("encrypt_key", "1700000000", "nonce-test", sig, br#"{"a":1}"#, 1700000000 + MAX_SKEW_SECS + 1), "replay");
    }

    fn post_hook(addr: std::net::SocketAddr, path: &str, body: &str, headers: &[(&str, String)]) -> (u16, String) {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{addr}{path}")).header("content-type", "application/json");
        for (k, v) in headers {
            r = r.header(*k, v.as_str());
        }
        match r.send(body.as_bytes()) {
            Ok(mut resp) => (resp.status().as_u16(), resp.body_mut().read_to_string().unwrap_or_default()),
            Err(_) => (0, String::new()),
        }
    }

    fn signed(key: &str, body: &str, ts: i64) -> Vec<(&'static str, String)> {
        let sig = crypto::hex(&crypto::sha256(format!("{ts}nonce{key}{body}").as_bytes()));
        vec![("x-lark-request-timestamp", ts.to_string()), ("x-lark-request-nonce", "nonce".into()), ("x-lark-signature", sig)]
    }

    #[test]
    fn webhook_token_mode_challenge_and_events() {
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { ok(json!({})) });
        let f = fs(&srv.url).with_webhook("127.0.0.1:0", "/fs/hook", None, Some("vt")).unwrap();
        let a = f.webhook_addr().unwrap();
        assert!(fs(&srv.url).with_webhook("127.0.0.1:0", "/x", None, None).is_err(), "unauthenticated webhook refused");
        let (s, b) = post_hook(a, "/fs/hook", r#"{"type":"url_verification","challenge":"abc","token":"vt"}"#, &[]);
        assert_eq!((s, b.as_str()), (200, r#"{"challenge":"abc"}"#));
        assert_eq!(post_hook(a, "/fs/hook", r#"{"type":"url_verification","challenge":"abc","token":"bad"}"#, &[]).0, 401);
        assert_eq!(post_hook(a, "/fs/hook", r#"{"type":"url_verification","challenge":"abc"}"#, &[]).0, 401, "missing token");
        assert_eq!(post_hook(a, "/other", "{}", &[]).0, 404);
        assert_eq!(post_hook(a, "/fs/hook", "not json", &[]).0, 400);
        let ev = msg_event("om_w", "p2p", "text", json!({"text": "via hook"}), json!({}));
        assert_eq!(post_hook(a, "/fs/hook", &ev.to_string(), &[]).0, 200);
        let mut bad = ev.clone();
        bad["header"]["token"] = json!("nope");
        assert_eq!(post_hook(a, "/fs/hook", &bad.to_string(), &[]).0, 401);
        let got = f.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "via hook");
        assert!(srv.requests().is_empty(), "DM text needs no API calls");
    }

    fn hooked(srv: &FakeServer) -> (Feishu, std::net::SocketAddr) {
        let f = fs(&srv.url).with_webhook("127.0.0.1:0", "/h", None, Some("vt")).unwrap();
        let a = f.webhook_addr().unwrap();
        (f, a)
    }

    fn poll_all(f: &Feishu) -> Vec<Inbound> {
        f.poll(&Cancel::new()).unwrap()
    }

    #[test]
    fn names_are_looked_up_and_cached() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            if r.path.starts_with("/open-apis/contact/v3/users/ou_amy") {
                return ok(json!({"user": {"name": "", "nickname": "Amy"}}));
            }
            if r.path.starts_with("/open-apis/bot/v3/bots/basic_batch") {
                return ok(json!({"bots": {"ou_otherbot": {"name": "Helper"}}}));
            }
            if r.path == "/open-apis/im/v1/chats/oc_chat" {
                return ok(json!({"name": "Ops room"}));
            }
            ok(json!({}))
        });
        let (mut f, a) = hooked(&srv);
        f.resolve_names = true;
        let ev = msg_event("om_n1", "group", "text", json!({"text": "hi"}), json!({}));
        post_hook(a, "/h", &ev.to_string(), &[]);
        let g = poll_all(&f);
        assert_eq!((g[0].sender_name.as_str(), g[0].chat_name.as_str()), ("Amy", "Ops room"));
        let calls: Vec<String> = api_calls(&srv).iter().map(|r| r.path.clone()).collect();
        assert_eq!(calls, ["/open-apis/contact/v3/users/ou_amy?user_id_type=open_id", "/open-apis/im/v1/chats/oc_chat"]);
        // Cached; a bot sender goes through basic_batch.
        let mut b = msg_event("om_n2", "group", "text", json!({"text": "beep"}), json!({}));
        b["event"]["sender"] = json!({"sender_id": {"open_id": "ou_otherbot"}, "sender_type": "bot"});
        post_hook(a, "/h", &ev.to_string().replace("om_n1", "om_n3"), &[]);
        post_hook(a, "/h", &b.to_string(), &[]);
        let g = poll_all(&f);
        assert_eq!(g.iter().map(|m| m.sender_name.as_str()).collect::<Vec<_>>(), ["Amy", "Helper"]);
        assert_eq!(api_calls(&srv).len(), 3);
        // The bot joining/leaving the chat invalidates its name.
        post_hook(a, "/h", &json!({"schema": "2.0", "header": {"event_type": "im.chat.member.bot.added_v1", "token": "vt"}, "event": {"chat_id": "oc_chat"}}).to_string(), &[]);
        post_hook(a, "/h", &ev.to_string().replace("om_n1", "om_n4"), &[]);
        let mut g = vec![];
        while g.is_empty() {
            g = poll_all(&f);
        }
        assert_eq!(api_calls(&srv).last().unwrap().path, "/open-apis/im/v1/chats/oc_chat");
    }

    fn appr_buttons(id: &str) -> Vec<Vec<Button>> {
        let b = |l: &str, c: &str| Button { label: l.into(), data: format!("appr:{id}:{c}"), url: None };
        vec![vec![b("允許一次", "once"), b("永遠允許", "always"), b("拒絕", "deny")]]
    }

    fn click(chat: &str, data: &str, tok: &str) -> String {
        json!({"schema": "2.0", "header": {"event_type": "card.action.trigger", "token": "vt"}, "event": {"operator": {"open_id": "ou_amy"}, "token": tok, "action": {"tag": "button", "value": {"data": data}}, "context": {"open_message_id": "om_card", "open_chat_id": chat}}}).to_string()
    }

    #[test]
    fn approval_cards_resolve_once_and_expire() {
        let srv = FakeServer::start(|r, n| if is_token(r) { token_reply() } else { ok(json!({"message_id": format!("om_{n}")})) });
        let (mut f, a) = hooked(&srv);
        f.approval_timeout = Duration::from_millis(300);
        let sent = f.send(&Outbound { buttons: appr_buttons("A1"), ..Outbound::text("oc_chat", "Run `sudo reboot`?") }).unwrap();
        let req = api_calls(&srv).pop().unwrap();
        let card: Value = serde_json::from_str(req.json()["content"].as_str().unwrap()).unwrap();
        assert_eq!((req.json()["msg_type"].as_str(), card["header"]["template"].as_str()), (Some("interactive"), Some("orange")));
        assert_eq!(card["elements"][0], json!({"tag": "markdown", "content": "Run `sudo reboot`?"}));
        let types: Vec<&str> = card["elements"][1]["actions"].as_array().unwrap().iter().map(|b| b["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["primary", "default", "danger"]);
        assert_eq!(card["elements"][1]["actions"][2]["value"]["data"], "appr:A1:deny");
        // Click from another chat: ignored. Click in the chat: passed on, card rewritten.
        post_hook(a, "/h", &click("oc_other", "appr:A1:once", "t0"), &[]);
        post_hook(a, "/h", &click("oc_chat", "appr:A1:always", "t1"), &[]);
        let g = poll_all(&f);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].callback.as_ref().unwrap().data, "appr:A1:always");
        let patch = api_calls(&srv).pop().unwrap();
        assert_eq!((patch.method.as_str(), patch.path.as_str()), ("PATCH", format!("/open-apis/im/v1/messages/{}", sent.ids[0]).as_str()));
        let done: Value = serde_json::from_str(patch.json()["content"].as_str().unwrap()).unwrap();
        assert_eq!((done["header"]["template"].as_str(), done["header"]["title"]["content"].as_str()), (Some("green"), Some("✅ 已永久批准")));
        assert_eq!(done["elements"].as_array().unwrap().len(), 1, "buttons removed");
        assert!(done["elements"][0]["content"].as_str().unwrap().ends_with("✅ **已永久批准**，由 ou_amy 操作"));
        // A second click on the resolved card is swallowed.
        let before = api_calls(&srv).len();
        post_hook(a, "/h", &click("oc_chat", "appr:A1:deny", "t2"), &[]);
        assert!(poll_all(&f).is_empty());
        assert_eq!(api_calls(&srv).len(), before);
        // Unanswered → expired on the card; a late approve gets a notice and goes nowhere.
        f.send(&Outbound { buttons: appr_buttons("A2"), ..Outbound::text("oc_chat", "Again?") }).unwrap();
        std::thread::sleep(Duration::from_millis(350));
        assert!(poll_all(&f).is_empty());
        let exp: Value = serde_json::from_str(api_calls(&srv).pop().unwrap().json()["content"].as_str().unwrap()).unwrap();
        assert_eq!(exp["header"]["template"], "grey");
        post_hook(a, "/h", &click("oc_chat", "appr:A2:once", "t3"), &[]);
        assert!(poll_all(&f).is_empty());
        let notice = api_calls(&srv).pop().unwrap().json();
        assert!(notice["content"].as_str().unwrap().contains("批准已逾期"));
        // Approvals we did not send (e.g. before a restart) still pass through.
        post_hook(a, "/h", &click("oc_chat", "appr:ZZ:once", "t4"), &[]);
        assert_eq!(poll_all(&f).len(), 1);
        assert_eq!(approval::parse("appr:x:y:once"), Some(("x:y", "once")));
        assert_eq!(approval::id_of(&[vec![Button { label: "a".into(), data: "go".into(), url: None }]]), None);
    }

    fn reply(id: &str, user: &str, elements: Value) -> Value {
        json!({"reply_id": id, "user_id": user, "content": {"elements": elements}})
    }

    #[test]
    fn document_comments_prompt_reply_and_fallback() {
        let srv = FakeServer::start(|r, n| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.as_str();
            if p.starts_with("/open-apis/drive/v1/metas/batch_query") {
                return ok(json!({"metas": [{"title": "週報", "url": "https://x.feishu.cn/docx/DOCTOKEN123"}]}));
            }
            if p.contains("/comments/batch_query") {
                // The first query races the notice: not there yet.
                return if n < 4 { ok(json!({"items": []})) } else { ok(json!({"items": [{"comment_id": "c1", "is_whole": false, "quote": "Q3 revenue"}]})) };
            }
            if p.contains("/comments/c1/replies") && r.method == "GET" {
                return ok(json!({"items": [
                    reply("r1", "ou_amy", json!([{"type": "text_run", "text_run": {"text": "is this right?"}}])),
                    reply("r2", "ou_bot", json!([{"type": "text_run", "text_run": {"text": "yes"}}])),
                    reply("r3", "ou_amy", json!([{"type": "person", "person": {"user_id": "ou_bot"}}, {"type": "text_run", "text_run": {"text": "  summarize   please "}}, {"type": "docs_link", "docs_link": {"url": "https://x.feishu.cn/wiki/WIKITOKEN1234"}}])),
                ]}));
            }
            if p.contains("/comments/c1/replies") {
                return if r.body.contains("second") { (200, vec![], json!({"code": 1069302, "msg": "reply not allowed"}).to_string()) } else { ok(json!({"reply_id": "r9"})) };
            }
            if p.contains("/new_comments") {
                return ok(json!({"comment_id": "c2"}));
            }
            ok(json!({}))
        });
        let (mut f, a) = hooked(&srv);
        f.comment_retry_delay = Duration::from_millis(5);
        let ev = |from: &str, to: &str, eid: &str| json!({"schema": "2.0", "header": {"event_id": eid, "event_type": "drive.notice.comment_add_v1", "token": "vt"}, "event": {"comment_id": "c1", "reply_id": "r3", "is_mentioned": true, "notice_meta": {"file_token": "DOCTOKEN123", "file_type": "docx", "notice_type": "add_reply", "from_user_id": {"open_id": from}, "to_user_id": {"open_id": to}}}}).to_string();
        post_hook(a, "/h", &ev("ou_bot", "ou_bot", "e0"), &[]);
        post_hook(a, "/h", &ev("ou_amy", "ou_someone", "e1"), &[]);
        post_hook(a, "/h", &ev("ou_amy", "ou_bot", "e2"), &[]);
        post_hook(a, "/h", &ev("ou_amy", "ou_bot", "e2"), &[]);
        let g = poll_all(&f);
        assert_eq!(g.len(), 1, "self-authored, foreign and redelivered notices dropped");
        let m = &g[0];
        assert_eq!((m.chat.as_str(), m.thread.as_deref(), m.message_id.as_str(), m.sender.as_str(), m.chat_name.as_str()), ("doc:docx:DOCTOKEN123", Some("l:c1:r3"), "cm:r3", "ou_amy", "週報"));
        assert!(m.mentioned && m.addressed());
        for want in ["The user added a reply in \"週報\".", "Current user comment text: \"summarize please https://x.feishu.cn/wiki/WIKITOKEN1234\"", "Original comment text: \"is this right?\"", "Quoted content: \"Q3 revenue\"", "- comment_id=c1", "Current comment card timeline (3/3 entries):", "[ou_bot] yes <-- YOU", "- wiki:WIKITOKEN1234", "If no reply is needed, output exactly NO_REPLY."] {
            assert!(m.text.contains(want), "{want} missing in:\n{}", m.text);
        }
        let calls = api_calls(&srv);
        let react = calls.iter().find(|r| r.path.contains("/comments/reaction")).unwrap();
        assert_eq!((react.path.as_str(), react.json()["action"].as_str(), react.json()["reply_id"].as_str()), ("/open-apis/drive/v2/files/DOCTOKEN123/comments/reaction?file_type=docx", Some("add"), Some("r3")));
        assert_eq!(calls.iter().filter(|r| r.path.contains("/comments/batch_query")).count(), 2, "retried until the comment exists");
        // Reply: thread first; a refusing thread falls back to a whole comment; reaction removed.
        let s = f.send(&Outbound { thread: m.thread.clone(), format: TextFormat::Markdown, ..Outbound::text(&m.chat, "**first** <b>") }).unwrap();
        assert_eq!(s.ids, ["r9"]);
        let calls = api_calls(&srv);
        let post = calls.iter().rfind(|r| r.method == "POST" && r.path.contains("/comments/c1/replies")).unwrap();
        assert_eq!(post.json()["content"]["elements"][0]["text_run"]["text"], "first &lt;b&gt;");
        assert_eq!(calls.last().unwrap().json()["action"], "delete");
        let s = f.send(&Outbound { thread: m.thread.clone(), ..Outbound::text(&m.chat, "second") }).unwrap();
        assert_eq!(s.ids, ["c2"]);
        let whole = api_calls(&srv).into_iter().rfind(|r| r.path.contains("/new_comments")).unwrap();
        assert_eq!((whole.path.as_str(), whole.json()["file_type"].as_str(), whole.json()["reply_elements"][0]["text"].as_str()), ("/open-apis/drive/v1/files/DOCTOKEN123/new_comments", Some("docx"), Some("second")));
        // NO_REPLY posts nothing; whole-document threads go straight to new_comments.
        let n = api_calls(&srv).len();
        assert!(f.send(&Outbound { thread: m.thread.clone(), ..Outbound::text(&m.chat, "NO_REPLY") }).unwrap().ids.is_empty());
        assert!(api_calls(&srv)[n..].iter().all(|r| r.path.contains("/reaction")));
        f.send(&Outbound { thread: Some("w:c7:".into()), ..Outbound::text(&m.chat, "whole") }).unwrap();
        assert!(api_calls(&srv).last().unwrap().path.ends_with("/new_comments"));
        assert!(f.send(&Outbound::text("doc:docx:T", "x")).is_err(), "no thread");
        // Disabled or outside the allowed documents: ignored.
        f.comment_docs = vec!["docx:OTHER".into()];
        post_hook(a, "/h", &ev("ou_amy", "ou_bot", "e3"), &[]);
        assert!(poll_all(&f).is_empty());
    }

    #[test]
    fn comment_prompt_helpers_match_upstream() {
        let t: Vec<(String, String, bool)> = (0..30).map(|i| (format!("u{i}"), format!("t{i}"), false)).collect();
        let sel = comment::select(&t, 5, 10, &[0, 29]);
        assert_eq!(sel.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["u0", "u9", "u10", "u11", "u29"]);
        assert_eq!(comment::select(&t[..3].to_vec(), 5, 1, &[]).len(), 3);
        let r = reply("r", "u", json!([{"type": "person", "person": {"user_id": "ou_me"}}, {"type": "text_run", "text_run": {"text": "a  b"}}, {"type": "person", "person": {}}]));
        assert_eq!(comment::reply_text(&r, false, "ou_me"), "@ou_mea  b@unknown");
        assert_eq!(comment::reply_text(&r, true, "ou_me"), "a b@");
        let d = comment::Doc { title: "T", url: "", file_type: "docx", file_token: "tok" };
        let replies = vec![reply("1", "ou_amy", json!([{"type": "text_run", "text_run": {"text": "hello"}}])), reply("2", "ou_me", json!([{"type": "text_run", "text_run": {"text": "hi"}}]))];
        let p = comment::whole_prompt(&d, &replies, "ou_amy", "ou_me");
        assert!(p.contains("This is a whole-document comment.") && p.contains("Current user comment text: \"hello\"") && p.contains("[ou_me] hi <-- YOU") && p.contains("Whole-document comment timeline (2/2 entries):"), "{p}");
        let e = comment::Event { from: "a".into(), to: "b".into(), file_token: "t".into(), file_type: "docx".into(), comment_id: "c".into(), notice_type: "resolve_comment".into(), ..Default::default() };
        assert_eq!(comment::skip_reason(&e, "b"), Some("notice type"));
    }

    #[test]
    fn meeting_invites_become_dms_from_the_inviter() {
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { ok(json!({})) });
        let (f, a) = hooked(&srv);
        let ev = json!({"schema": "2.0", "header": {"event_id": "vc1", "event_type": "vc.bot.meeting_invited_v1", "token": "vt"},
            "event": {"meeting": {"id": "m1", "topic": "Standup", "meeting_no": "123456789", "host_user": {"id": {"open_id": "ou_host"}, "user_name": "Hana"}}, "inviter": {"id": {"open_id": "ou_inv"}, "user_name": "Ivan"}, "invite_time": "1700000000"}});
        post_hook(a, "/h", &ev.to_string(), &[]);
        post_hook(a, "/h", &ev.to_string(), &[]);
        let g = poll_all(&f);
        assert_eq!(g.len(), 1);
        let m = &g[0];
        assert_eq!((m.chat.as_str(), m.chat_type, m.sender_name.as_str(), m.message_id.as_str(), m.ts), ("ou_inv", ChatType::Direct, "Ivan", "vc_invite:vc1", 1700000000));
        assert!(m.text.starts_with("You have been invited to join a meeting: Standup\n\nMeeting Number: 123456789\nTopic: Standup\nInviter: Ivan\nHost: Hana"), "{}", m.text);
        let bad = json!({"header": {"event_type": "vc.bot.meeting_invited_v1"}, "event": {"meeting": {"id": "m"}, "inviter": {"id": {"open_id": "ou_x"}}}});
        assert!(meeting::inbound_of("fs", &bad).is_none(), "no meeting number");
    }

    #[test]
    fn qr_registration_device_flow() {
        let srv = FakeServer::start(|r, n| {
            let body = r.body.clone();
            let v = if body.contains("action=init") {
                json!({"supported_auth_methods": ["client_secret"]})
            } else if body.contains("action=begin") {
                json!({"device_code": "DC", "verification_uri_complete": "https://accounts.feishu.cn/x?code=U1", "user_code": "U1", "interval": 2, "expire_in": 300})
            } else if n < 3 {
                return (400, vec![], json!({"error": "authorization_pending"}).to_string());
            } else if n == 3 {
                json!({"user_info": {"tenant_brand": "lark"}, "error": "authorization_pending"})
            } else {
                json!({"client_id": "cli_new", "client_secret": "sek", "user_info": {"open_id": "ou_owner", "tenant_brand": "lark"}})
            };
            (200, vec![], v.to_string())
        });
        onboard::init("feishu", Some(&srv.url)).unwrap();
        let r = onboard::begin("feishu", Some(&srv.url)).unwrap();
        assert_eq!((r.device_code.as_str(), r.qr_url.as_str(), r.interval, r.expire_in), ("DC", "https://accounts.feishu.cn/x?code=U1&from=ark&tp=ark", 2, 300));
        let req = &srv.requests()[1];
        assert_eq!(req.path, "/oauth/v1/app/registration");
        assert!(req.body.contains("archetype=PersonalAgent") && req.body.contains("auth_method=client_secret"));
        assert_eq!(onboard::poll("feishu", Some(&srv.url), "DC").unwrap(), onboard::Poll::Pending);
        assert_eq!(onboard::poll("feishu", Some(&srv.url), "DC").unwrap(), onboard::Poll::SwitchDomain("lark".into()));
        assert_eq!(onboard::poll("lark", Some(&srv.url), "DC").unwrap(), onboard::Poll::Done { app_id: "cli_new".into(), app_secret: "sek".into(), domain: "lark".into(), open_id: "ou_owner".into() });
        assert!(srv.requests()[2].body.contains("device_code=DC") && srv.requests()[2].body.contains("tp=ob_app"));
        let denied = FakeServer::start(|_, _| (400, vec![], json!({"error": "access_denied", "supported_auth_methods": ["device"]}).to_string()));
        assert_eq!(onboard::poll("feishu", Some(&denied.url), "DC").unwrap(), onboard::Poll::Failed("access_denied".into()));
        assert!(onboard::init("feishu", Some(&denied.url)).is_err());
    }

    #[test]
    fn webhook_encrypted_and_signed() {
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { ok(json!({})) });
        let f = fs(&srv.url).with_webhook("127.0.0.1:0", "/hook", Some("ekey"), Some("vt")).unwrap();
        let a = f.webhook_addr().unwrap();
        let now = now_secs();
        let wrap = |v: &Value| json!({"encrypt": encrypt("ekey", &v.to_string(), [7; 16])}).to_string();
        let ch = wrap(&json!({"type": "url_verification", "challenge": "enc-ch", "token": "vt"}));
        assert_eq!(post_hook(a, "/hook", &ch, &signed("ekey", &ch, now)), (200, r#"{"challenge":"enc-ch"}"#.to_string()));
        assert_eq!(post_hook(a, "/hook", &ch, &[]).0, 401, "unsigned");
        assert_eq!(post_hook(a, "/hook", &ch, &signed("other", &ch, now)).0, 401, "bad signature");
        assert_eq!(post_hook(a, "/hook", &ch, &signed("ekey", &ch, now - 2 * MAX_SKEW_SECS)).0, 401, "replayed timestamp");
        let garbage = json!({"encrypt": encrypt("wrong-key", "{}", [1; 16])}).to_string();
        assert_eq!(post_hook(a, "/hook", &garbage, &signed("ekey", &garbage, now)).0, 401, "undecryptable");
        let card = wrap(&json!({"schema": "2.0", "header": {"event_type": "card.action.trigger", "token": "vt"}, "event": {"operator": {"open_id": "ou_amy"}, "token": "c-1", "action": {"value": {"data": "go"}}, "context": {"open_chat_id": "oc_chat", "open_message_id": "om_c"}}}));
        assert_eq!(post_hook(a, "/hook", &card, &signed("ekey", &card, now)), (200, "{}".to_string()));
        let got = f.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].callback.as_ref().unwrap().data, "go");
    }

    #[test]
    fn poll_resolves_reply_to_bot_and_bot_identity() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            if r.path.ends_with("/bot/v3/info") {
                return (200, vec![], json!({"code": 0, "bot": {"open_id": "ou_me", "app_name": "Ark"}}).to_string());
            }
            ok(json!({"items": [{"message_id": "om_p", "msg_type": "text", "sender": {"id": "cli_app", "id_type": "app_id", "sender_type": "app"}, "body": {"content": "{\"text\":\"shall I?\"}"}}]}))
        });
        let mut f = Feishu::new("fs", "cli_app", "APPSECRET", "lark", Some(&srv.url), 1).unwrap().with_webhook("127.0.0.1:0", "/h", None, Some("vt")).unwrap();
        f.retry_base = Duration::from_millis(5);
        let a = f.webhook_addr().unwrap();
        let ev = msg_event("om_r", "group", "text", json!({"text": "@_user_1 yes"}), json!({"parent_id": "om_p", "mentions": [{"key": "@_user_1", "id": {"open_id": "ou_me"}, "name": "Ark"}]}));
        post_hook(a, "/h", &ev.to_string(), &[]);
        let g = f.poll(&Cancel::new()).unwrap();
        assert!(g[0].mentioned && g[0].text == "yes", "{:?}", g[0]);
        let r = g[0].reply.as_ref().unwrap();
        assert!(r.is_own && r.text == "shall I?");
        assert!(g[0].addressed());
        let calls = api_calls(&srv);
        assert_eq!(calls[0].path, "/open-apis/bot/v3/info");
        assert_eq!(calls[1].path, "/open-apis/im/v1/messages/om_p");
        assert_eq!(calls[0].header("authorization"), Some("Bearer t-SECRET"));
        let tok = srv.requests().into_iter().find(is_token).unwrap();
        assert_eq!((tok.json()["app_id"].as_str(), tok.json()["app_secret"].as_str()), (Some("cli_app"), Some("APPSECRET")));
        // Second poll: identity and parent are cached, token reused.
        post_hook(a, "/h", &ev.to_string(), &[]);
        f.poll(&Cancel::new()).unwrap();
        assert_eq!(srv.requests().len(), 3);
    }

    #[test]
    fn send_shapes_text_markdown_reply_thread_buttons_media() {
        let srv = FakeServer::start(|r, n| {
            if is_token(r) {
                return token_reply();
            }
            if r.path.ends_with("/images") {
                return ok(json!({"image_key": "img_up"}));
            }
            if r.path.ends_with("/files") {
                return ok(json!({"file_key": "file_up"}));
            }
            ok(json!({"message_id": format!("om_{n}")}))
        });
        let f = fs(&srv.url);
        f.send(&Outbound::text("oc_chat", "plain")).unwrap();
        let c = &api_calls(&srv)[0];
        assert_eq!(c.path, "/open-apis/im/v1/messages?receive_id_type=chat_id");
        assert_eq!(c.header("authorization"), Some("Bearer t-SECRET"));
        let b = c.json();
        assert_eq!((b["receive_id"].as_str(), b["msg_type"].as_str(), b["content"].as_str()), (Some("oc_chat"), Some("text"), Some(r#"{"text":"plain"}"#)));
        assert!(b["uuid"].as_str().unwrap().len() == 32);
        // Markdown → post with the code fence in its own row; open_id target.
        f.send(&Outbound { format: TextFormat::Markdown, ..Outbound::text("ou_amy", "**hi**\n```rs\nx\n```\nafter") }).unwrap();
        let c = &api_calls(&srv)[1];
        assert!(c.path.ends_with("receive_id_type=open_id"));
        let post: Value = serde_json::from_str(c.json()["content"].as_str().unwrap()).unwrap();
        assert_eq!(post["zh_cn"]["content"], json!([[{"tag": "md", "text": "**hi**"}], [{"tag": "md", "text": "```rs\nx\n```"}], [{"tag": "md", "text": "after"}]]));
        // Reply in a thread with buttons → interactive card via /reply.
        let out = Outbound {
            reply_to: Some("om_src".into()),
            thread: Some("omt_t".into()),
            buttons: vec![vec![Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("oc_chat", "approve?")
        };
        let s = f.send(&out).unwrap();
        let c = &api_calls(&srv)[2];
        assert_eq!(c.path, "/open-apis/im/v1/messages/om_src/reply");
        assert_eq!((c.json()["reply_in_thread"].as_bool(), c.json()["msg_type"].as_str()), (Some(true), Some("interactive")));
        let cardv: Value = serde_json::from_str(c.json()["content"].as_str().unwrap()).unwrap();
        assert_eq!(cardv["elements"][1]["actions"][0]["value"]["data"], "appr:x:once");
        assert_eq!(cardv["elements"][1]["actions"][1]["url"], "https://e.com");
        // Thread without reply target → create with receive_id_type=thread_id.
        f.send(&Outbound { thread: Some("omt_t".into()), ..Outbound::text("oc_chat", "t") }).unwrap();
        let c = &api_calls(&srv)[3];
        assert!(c.path.ends_with("receive_id_type=thread_id") && c.json()["receive_id"] == "omt_t");
        // Local image upload, then the image message; a PDF as file.
        let dir = crate::testutil::temp_dir("fs");
        let img = dir.join("a.png");
        std::fs::write(&img, b"PNGDATA").unwrap();
        let pdf = dir.join("r.pdf");
        std::fs::write(&pdf, b"%PDF-1").unwrap();
        let media = vec![
            Media { kind: MediaKind::Image, path: Some(img.display().to_string()), mime: "image/png".into(), ..Default::default() },
            Media { kind: MediaKind::Document, path: Some(pdf.display().to_string()), ..Default::default() },
        ];
        let r = f.send(&Outbound { media, ..Outbound::text("oc_chat", "") }).unwrap();
        assert_eq!(r.ids.len(), 2);
        let calls = api_calls(&srv);
        let up = &calls[4];
        assert!(up.path == "/open-apis/im/v1/images" && up.header("content-type").unwrap().starts_with("multipart/form-data"));
        assert!(up.body.contains("name=\"image_type\"\r\n\r\nmessage") && up.body.contains("filename=\"a.png\"") && up.body.contains("PNGDATA"));
        assert_eq!((calls[5].json()["msg_type"].as_str(), calls[5].json()["content"].as_str()), (Some("image"), Some(r#"{"image_key":"img_up"}"#)));
        assert!(calls[6].path == "/open-apis/im/v1/files" && calls[6].body.contains("name=\"file_type\"\r\n\r\npdf") && calls[6].body.contains("%PDF-1"));
        assert_eq!(calls[7].json()["msg_type"], "file");
        // Edit: cards PATCH, others PUT post; delete; reactions; resource download with auth.
        f.edit("oc_chat", &s.ids[0], "updated").unwrap();
        f.edit("oc_chat", "om_0", "updated *md*").unwrap();
        f.delete("oc_chat", "om_0").unwrap();
        let calls = api_calls(&srv);
        assert_eq!((calls[8].method.as_str(), calls[8].path.as_str()), ("PATCH", format!("/open-apis/im/v1/messages/{}", s.ids[0]).as_str()));
        assert_eq!((calls[9].method.as_str(), calls[9].json()["msg_type"].as_str()), ("PUT", Some("post")));
        assert_eq!((calls[10].method.as_str(), calls[10].path.as_str()), ("DELETE", "/open-apis/im/v1/messages/om_0"));
        assert_eq!(srv.requests().iter().filter(|r| is_token(r)).count(), 1, "token cached");
        assert_eq!(f.caps().max_len, MAX_MESSAGE);
    }

    #[test]
    fn reactions_and_media_download() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            if r.path.contains("/resources/") {
                return (200, vec![], "BYTES".into());
            }
            if r.method == "GET" {
                return ok(json!({"items": [{"reaction_id": "r_app", "operator": {"operator_type": "app"}}, {"reaction_id": "r_user", "operator": {"operator_type": "user"}}]}));
            }
            ok(json!({"reaction_id": "r_new"}))
        });
        let f = fs(&srv.url);
        f.react("oc", "om_1", "👍", false).unwrap();
        f.react("oc", "om_1", "👍", true).unwrap();
        f.react("oc", "om_2", "OK", true).unwrap();
        let c = api_calls(&srv);
        assert_eq!((c[0].path.as_str(), c[0].json()["reaction_type"]["emoji_type"].as_str()), ("/open-apis/im/v1/messages/om_1/reactions", Some("THUMBSUP")));
        assert_eq!((c[1].method.as_str(), c[1].path.as_str()), ("DELETE", "/open-apis/im/v1/messages/om_1/reactions/r_new"));
        assert_eq!(c[2].path, "/open-apis/im/v1/messages/om_2/reactions?reaction_type=OK");
        assert_eq!((c[3].path.as_str(), c.len()), ("/open-apis/im/v1/messages/om_2/reactions/r_app", 4), "only our own reaction removed");
        let m = Media { url: Some(resource_url(&srv.url, "om_9", "img_1", "image")), ..Default::default() };
        assert_eq!(f.fetch_media(&m).unwrap(), b"BYTES");
        let last = srv.requests().pop().unwrap();
        assert_eq!((last.path.as_str(), last.header("authorization")), ("/open-apis/im/v1/messages/om_9/resources/img_1?type=image", Some("Bearer t-SECRET")));
    }

    #[test]
    fn error_mapping_retries_and_fallbacks() {
        // Bad credentials at the token endpoint.
        let srv = FakeServer::start(|_, _| (400, vec![], json!({"code": 10014, "msg": "app secret invalid"}).to_string()));
        let e = fs(&srv.url).send(&Outbound::text("oc", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("APPSECRET") && !e.message.contains("t-SECRET"), "{}", e.message);
        // Rate limit with Retry-After, then success.
        let srv = FakeServer::start(|r, n| match (is_token(r), n) {
            (true, _) => token_reply(),
            (_, 1) => (429, vec![("Retry-After".into(), "1".into())], json!({"code": 99991400, "msg": "too many"}).to_string()),
            _ => ok(json!({"message_id": "om_ok"})),
        });
        let t0 = Instant::now();
        assert_eq!(fs(&srv.url).send(&Outbound::text("oc", "x")).unwrap().ids, ["om_ok"]);
        assert!(t0.elapsed() >= Duration::from_millis(950));
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { (429, vec![("Retry-After".into(), "3600".into())], json!({"code": 99991400}).to_string()) });
        assert_eq!(fs(&srv.url).send(&Outbound::text("oc", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        // 5xx retried with backoff then Network.
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { (502, vec![], "<html>bad gateway</html>".into()) });
        let f = fs(&srv.url);
        assert_eq!(f.send(&Outbound::text("oc", "x")).unwrap_err().kind, K::Network);
        assert_eq!(api_calls(&srv).len(), 4, "1 + max_retries");
        // Bot removed from chat → NotFound, not retried.
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { (400, vec![], json!({"code": 230002, "msg": "Bot is not in the chat"}).to_string()) });
        assert_eq!(fs(&srv.url).send(&Outbound::text("oc", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(api_calls(&srv).len(), 1);
        // Expired token → refresh once and retry.
        let srv = FakeServer::start(|r, n| match (is_token(r), n) {
            (true, _) => token_reply(),
            (_, 1) => (400, vec![], json!({"code": 99991663, "msg": "token invalid"}).to_string()),
            _ => ok(json!({"message_id": "om_2"})),
        });
        fs(&srv.url).send(&Outbound::text("oc", "x")).unwrap();
        assert_eq!(srv.requests().iter().filter(|r| is_token(r)).count(), 2);
        // Withdrawn reply target → new message in the chat.
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                token_reply()
            } else if r.path.ends_with("/reply") {
                (400, vec![], json!({"code": 230011, "msg": "message withdrawn"}).to_string())
            } else {
                ok(json!({"message_id": "om_new"}))
            }
        });
        let s = fs(&srv.url).send(&Outbound { reply_to: Some("om_gone".into()), ..Outbound::text("oc_chat", "x") }).unwrap();
        assert_eq!(s.ids, ["om_new"]);
        assert!(api_calls(&srv)[1].path.contains("receive_id_type=chat_id"));
    }

    #[test]
    fn frame_protobuf_roundtrip_and_known_bytes() {
        let f = Frame { seq_id: 1, log_id: 2, service: 3, method: 1, headers: vec![("type".into(), "event".into())], payload: b"{}".to_vec(), ..Default::default() };
        let b = f.encode();
        assert_eq!(b, [0x08, 1, 0x10, 2, 0x18, 3, 0x20, 1, 0x2a, 13, 0x0a, 4, b't', b'y', b'p', b'e', 0x12, 5, b'e', b'v', b'e', b'n', b't', 0x42, 2, b'{', b'}']);
        assert_eq!(Frame::decode(&b).unwrap(), f);
        let big = Frame { seq_id: u64::MAX, service: -1, log_id_new: "L".into(), payload_type: "json".into(), ..Default::default() };
        assert_eq!(Frame::decode(&big.encode()).unwrap(), big);
        assert!(Frame::decode(&[0x2a, 50, 1]).is_none(), "truncated");
    }

    /// Fake Lark WS gateway: first connection is dropped, second sends a fragmented
    /// event and records what the client sends.
    fn ws_gateway() -> (String, Arc<Mutex<Vec<Frame>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/ws?device_id=d1&service_id=42", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for (n, conn) in l.incoming().enumerate() {
                let mut c = conn.unwrap();
                let (head, rest) = ark_net::ws::read_head(&mut c, 65536).unwrap();
                let mut ws = ark_net::ws::WebSocket::accept(c.try_clone().unwrap(), &head, rest).unwrap();
                if n == 0 {
                    drop(ws);
                    let _ = c.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let ev = msg_event("om_ws", "p2p", "text", json!({"text": "over ws"}), json!({})).to_string().into_bytes();
                let (a, b) = ev.split_at(ev.len() / 2);
                for (i, part) in [a, b].iter().enumerate() {
                    let fr = Frame { seq_id: 9, service: 42, method: 1, headers: vec![("type".into(), "event".into()), ("message_id".into(), "m1".into()), ("sum".into(), "2".into()), ("seq".into(), i.to_string())], payload: part.to_vec(), ..Default::default() };
                    ws.send(&ark_net::ws::Message::Binary(fr.encode())).unwrap();
                }
                c.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                loop {
                    match ws.recv() {
                        Ok(Some(ark_net::ws::Message::Binary(b))) => s2.lock().unwrap().push(Frame::decode(&b).unwrap()),
                        Ok(Some(ark_net::ws::Message::Close(_))) | Err(_) => break,
                        _ => {}
                    }
                }
            }
        });
        (url, seen)
    }

    #[test]
    fn websocket_mode_reconnects_reassembles_and_acks() {
        let (ws_url, seen) = ws_gateway();
        let srv = FakeServer::start(move |r, _| {
            assert_eq!(r.path, "/callback/ws/endpoint");
            assert_eq!(r.json()["AppID"], "cli_app");
            (200, vec![], json!({"code": 0, "data": {"URL": ws_url, "ClientConfig": {"PingInterval": 120}}}).to_string())
        });
        let f = fs(&srv.url);
        let mut got = Vec::new();
        let t0 = Instant::now();
        while got.is_empty() && t0.elapsed() < Duration::from_secs(10) {
            got = f.poll(&Cancel::new()).unwrap();
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "over ws");
        assert_eq!(srv.requests().len(), 2, "endpoint fetched again after the drop");
        let t0 = Instant::now();
        while seen.lock().unwrap().iter().filter(|f| f.method == 1).count() == 0 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let frames = seen.lock().unwrap().clone();
        let ping = frames.iter().find(|f| f.method == 0).expect("ping");
        assert_eq!((ping.header("type"), ping.service), ("ping", 42));
        let acks: Vec<&Frame> = frames.iter().filter(|f| f.method == 1).collect();
        assert_eq!(acks.len(), 1, "one ack for the reassembled message");
        assert_eq!((acks[0].seq_id, acks[0].header("message_id"), acks[0].payload.as_slice()), (9, "m1", br#"{"code":200}"#.as_slice()));
        assert!(!acks[0].header("biz_rt").is_empty());
        f.stop();
    }

    #[test]
    fn websocket_auth_failure_surfaces_and_cancel_is_prompt() {
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"code": 514, "msg": "auth failed"}).to_string()));
        let f = fs(&srv.url);
        let t0 = Instant::now();
        let mut res = f.poll(&Cancel::new());
        while matches!(res, Ok(ref v) if v.is_empty()) && t0.elapsed() < Duration::from_secs(5) {
            res = f.poll(&Cancel::new());
        }
        let e = res.unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("APPSECRET"));
        // A gateway that accepts but never speaks: cancel returns within ~100 ms.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ws_url = format!("ws://{}/ws?service_id=1", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let mut keep = Vec::new();
            for c in l.incoming().take(3) {
                let mut c = c.unwrap();
                let (head, rest) = ark_net::ws::read_head(&mut c, 65536).unwrap();
                keep.push(ark_net::ws::WebSocket::accept(c, &head, rest).unwrap());
            }
            std::thread::sleep(Duration::from_secs(30));
        });
        let srv = FakeServer::start(move |_, _| (200, vec![], json!({"code": 0, "data": {"URL": ws_url}}).to_string()));
        let mut f = fs(&srv.url);
        f.poll_timeout = 30;
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.cancel();
        });
        let t0 = Instant::now();
        assert!(f.poll(&c).unwrap().is_empty());
        assert!(t0.elapsed() < Duration::from_millis(600), "{:?}", t0.elapsed());
    }

    #[test]
    fn build_validates_settings() {
        let secrets: crate::Secrets = Arc::new(|s: &str| s.replace("{{secret:FS}}", "sek"));
        let d = crate::testutil::temp_dir("fs");
        let ctx = crate::config::Ctx { name: "fs", state_dir: &d, secrets: &secrets };
        let m = |v: Value| v.as_object().unwrap().clone();
        assert!(build(&ctx, &m(json!({"app_id": "cli", "app_secret": "{{secret:FS}}"}))).is_ok());
        assert!(build(&ctx, &m(json!({"app_id": "cli", "app_secret": "{{secret:NOPE}}"}))).err().unwrap().contains("not set"));
        assert!(build(&ctx, &m(json!({"app_id": "cli", "app_secret": "x", "domian": "lark"}))).err().unwrap().contains("domian"));
        assert!(build(&ctx, &m(json!({"app_id": "cli", "app_secret": "x", "domain": "mars"}))).is_err());
        assert!(build(&ctx, &m(json!({"app_id": "cli", "app_secret": "x", "listen": "127.0.0.1:0"}))).err().unwrap().contains("encrypt_key"));
        let w = build(&ctx, &m(json!({"app_id": "cli", "app_secret": "x", "listen": "127.0.0.1:0", "verification_token": "vt", "domain": "lark"}))).unwrap();
        assert_eq!(w.id(), "fs");
        let f = Feishu::new("x", "a", "b", "lark", None, 1).unwrap();
        assert_eq!(f.base, LARK_BASE);
    }

    #[test]
    fn helpers_targets_routing_and_ogg() {
        assert_eq!(receive_target("oc_1"), ("chat_id", "oc_1"));
        assert_eq!(receive_target("ou_1"), ("open_id", "ou_1"));
        assert_eq!(receive_target("on_1"), ("union_id", "on_1"));
        assert_eq!(receive_target("a@b.com"), ("email", "a@b.com"));
        assert_eq!(receive_target("user_id:u1"), ("user_id", "u1"));
        assert_eq!(file_routing("v.ogg", MediaKind::Voice), ("opus", "audio"));
        assert_eq!(file_routing("v.ogg", MediaKind::Document), ("stream", "file"));
        assert_eq!(file_routing("c.MP4", MediaKind::Video), ("mp4", "media"));
        assert_eq!(file_routing("s.xlsx", MediaKind::Document), ("xls", "file"));
        // One OGG page with granule 96000 (2 s at 48 kHz) and an empty segment table.
        let mut ogg = b"OggS\0\0".to_vec();
        ogg.extend(96000i64.to_le_bytes());
        ogg.extend([0u8; 12]);
        ogg.push(0);
        assert_eq!(ogg_duration_ms(&ogg), 2000);
        assert_eq!(ogg_duration_ms(b"not ogg"), 0);
        assert_eq!(emoji_type("❤️"), "HEART");
    }

    /// OpenClaw `docx.test.ts`, `wiki.test.ts`, `drive.test.ts`, `perm.test.ts`, `chat.test.ts`,
    /// `bitable.test.ts` and Hermes `test_feishu_doc_tool.py` against a fake open platform.
    #[test]
    fn agent_tools_docs_wiki_drive_chat_bitable_and_message_actions() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            let m = r.method.as_str();
            let b = r.json();
            match (m, p) {
                ("GET", "/docx/v1/documents/D1/raw_content") => ok(json!({"content": "Hello doc"})),
                ("GET", "/docx/v1/documents/D1") => ok(json!({"document": {"title": "Spec", "revision_id": 7}})),
                ("GET", p) if p.starts_with("/docx/v1/documents/D1/blocks?") => ok(json!({"items": [
                    {"block_id": "D1", "block_type": 1, "parent_id": ""},
                    {"block_id": "b1", "block_type": 2, "parent_id": "D1"},
                    {"block_id": "t1", "block_type": 31, "parent_id": "D1"}
                ], "has_more": false})),
                ("POST", "/docx/v1/documents/blocks/convert") => {
                    let md = b["content"].as_str().unwrap_or("");
                    if md.contains("FAILBIG") && md.len() > 300 {
                        return (400, vec![], json!({"code": 1770001, "msg": "content too large"}).to_string());
                    }
                    let img = md.contains("![");
                    let mut blocks = vec![json!({"block_id": "c2", "block_type": 2, "parent_id": "c1", "text": {"elements": [{"text_run": {"content": "child"}}]}}), json!({"block_id": "c1", "block_type": 3, "children": ["c2"]})];
                    let mut roots = vec!["c1"];
                    if img {
                        blocks.push(json!({"block_id": "ci", "block_type": 27, "image": {}}));
                        roots.push("ci");
                    }
                    ok(json!({"blocks": blocks, "first_level_block_ids": roots}))
                }
                ("DELETE", "/docx/v1/documents/D1/blocks/D1/children/batch_delete") => {
                    assert!(b == json!({"start_index": 0, "end_index": 2}) || b == json!({"start_index": 1, "end_index": 2}), "{b}");
                    ok(json!({}))
                }
                ("POST", "/docx/v1/documents/D1/blocks/D1/descendant") => {
                    assert_eq!(b["descendants"][0]["block_id"], "c1", "pre-order: roots first");
                    assert!(b["descendants"][1].get("parent_id").is_none(), "parent_id stripped");
                    let mut kids = vec![json!({"block_id": "n1", "block_type": 3})];
                    if b["children_id"].as_array().unwrap().len() == 2 {
                        kids.push(json!({"block_id": "nimg", "block_type": 27}));
                    }
                    ok(json!({"children": kids}))
                }
                ("POST", "/drive/v1/medias/upload_all") => {
                    assert!(r.body.contains("docx_image") || r.body.contains("docx_file"));
                    ok(json!({"file_token": "FT1"}))
                }
                ("PATCH", p) if p.starts_with("/docx/v1/documents/D1/blocks/") => ok(json!({"block": {"block_id": p.rsplit('/').next().unwrap()}})),
                ("GET", "/docx/v1/documents/D1/blocks/b1") => ok(json!({"block": {"block_id": "b1", "parent_id": "D1"}})),
                ("GET", p) if p.starts_with("/docx/v1/documents/D1/blocks/D1/children") => ok(json!({"items": [{"block_id": "b0"}, {"block_id": "b1"}], "has_more": false})),
                ("POST", "/docx/v1/documents") => ok(json!({"document": {"document_id": "NEW1", "title": b["title"]}})),
                ("POST", p) if p.starts_with("/drive/v1/permissions/NEW1/members") => {
                    assert_eq!(b, json!({"member_type": "openid", "member_id": "ou_req", "perm": "edit"}));
                    ok(json!({"member": {}}))
                }
                ("GET", "/application/v6/scopes") => ok(json!({"scopes": [{"scope_name": "docx:document", "scope_type": "tenant", "grant_status": 1}, {"scope_name": "wiki:wiki", "scope_type": "tenant", "grant_status": 2}]})),
                ("GET", p) if p.starts_with("/wiki/v2/spaces?") => ok(json!({"items": [], "has_more": false})),
                ("GET", "/wiki/v2/spaces/get_node?token=WK1") => ok(json!({"node": {"node_token": "WK1", "obj_type": "bitable", "obj_token": "APP9", "title": "Tracker"}})),
                ("POST", "/wiki/v2/spaces/7123/nodes") => ok(json!({"node": {"node_token": "N2", "obj_token": "O2", "obj_type": b["obj_type"], "title": b["title"]}})),
                ("GET", p) if p == "/drive/v1/files" || p.starts_with("/drive/v1/files?") => ok(json!({"files": [{"token": "F1", "name": "a.docx", "type": "docx"}], "next_page_token": null})),
                ("POST", "/drive/v1/metas/batch_query") => (200, vec![], json!({"code": 99991672, "msg": "no scope"}).to_string()),
                ("GET", p) if p.starts_with("/drive/v1/files/F1/comments?") => ok(json!({"items": [{"comment_id": "C1", "user_id": "ou_a", "is_whole": true, "reply_list": {"replies": [{"reply_id": "R1", "content": {"elements": [{"type": "text_run", "text_run": {"text": "looks good"}}]}}]}}], "has_more": false})),
                ("POST", "/drive/v1/files/F1/new_comments") => {
                    assert_eq!(b["anchor"]["block_id"], "b1");
                    ok(json!({"comment_id": "C9"}))
                }
                ("GET", "/im/v1/chats/oc_g") => ok(json!({"name": "Team", "chat_mode": "group", "user_count": "3"})),
                ("GET", p) if p.starts_with("/im/v1/chats/oc_g/members") => ok(json!({"items": [{"member_id": "ou_a", "name": "Amy"}], "has_more": false})),
                ("GET", p) if p.starts_with("/contact/v3/users/ou_a") => ok(json!({"user": {"open_id": "ou_a", "name": "Amy"}})),
                ("GET", "/bitable/v1/apps/APP9") => ok(json!({"app": {"name": "Tracker"}})),
                ("GET", "/bitable/v1/apps/APP9/tables") => ok(json!({"items": [{"table_id": "tbl1", "name": "Tasks"}]})),
                ("GET", "/bitable/v1/apps/APP9/tables/tbl1/fields") => ok(json!({"items": [{"field_id": "f1", "field_name": "Name", "type": 1, "is_primary": true}, {"field_id": "f2", "field_name": "When", "type": 5}]})),
                ("POST", "/bitable/v1/apps/APP9/tables/tbl1/records") => ok(json!({"record": {"record_id": "rec1", "fields": b["fields"]}})),
                ("POST", "/im/v1/pins") => ok(json!({"pin": {"message_id": b["message_id"]}})),
                ("GET", p) if p.starts_with("/im/v1/pins?") => ok(json!({"items": [{"message_id": "om_1", "chat_id": "oc_g"}], "has_more": false})),
                ("GET", p) if p.starts_with("/im/v1/messages/om_1") => ok(json!({"items": [{"message_id": "om_1", "chat_id": "oc_g", "msg_type": "text", "body": {"content": "{\"text\":\"hi\"}"}}]})),
                _ => (404, vec![], json!({"code": 404, "msg": format!("unexpected {m} {p}")}).to_string()),
            }
        });
        let mut f = fs(&srv.url);
        f.tool_families.insert("perm".into(), true);
        let tools = f.tools();
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        assert_eq!(names.len(), 15, "{names:?}");
        assert!(names.iter().all(|n| n.ends_with("_fs")), "non-default channel names are suffixed");
        let tool = |n: &str| tools.iter().find(|t| t.spec().name == format!("{n}_fs")).unwrap().clone();
        let ctx = crate::testutil::tool_ctx();
        let run = |n: &str, a: Value| {
            let o = tool(n).call(&ctx, a);
            (o.is_error, serde_json::from_str::<Value>(&o.content).unwrap_or(Value::String(o.content.clone())))
        };
        assert_eq!(run("feishu_doc_read", json!({"doc_token": "D1"})).1, json!({"success": true, "content": "Hello doc"}));
        let (_, v) = run("feishu_doc", json!({"action": "read", "doc_token": "D1"}));
        assert_eq!((v["title"].as_str(), v["block_count"].as_u64(), v["block_types"]["Table"].as_u64()), (Some("Spec"), Some(3), Some(1)));
        assert!(v["hint"].as_str().unwrap().contains("Table"));
        // write: convert first, then clear the two body blocks, then insert pre-ordered descendants.
        let (e, v) = run("feishu_doc", json!({"action": "write", "doc_token": "D1", "content": "# Title\n\nchild\n\n![pic](data/x.png)"}));
        assert!(!e, "{v}");
        assert_eq!((v["blocks_deleted"].as_u64(), v["blocks_added"].as_u64()), (Some(2), Some(3)));
        let (e, v) = run("feishu_doc", json!({"action": "insert", "doc_token": "D1", "after_block_id": "b1", "content": "x"}));
        assert!(!e && v["block_ids"] == json!(["n1"]), "{v}");
        let calls = api_calls(&srv);
        let ins = calls.iter().rev().find(|r| r.path.ends_with("/descendant")).unwrap();
        assert_eq!(ins.json()["index"], 2, "after b1 (index 1) → 2");
        // Oversized chunk: convert fails, halves retried.
        let big = format!("FAILBIG\n\n{}\n\n{}", "a".repeat(200), "b".repeat(200));
        assert!(!run("feishu_doc", json!({"action": "append", "doc_token": "D1", "content": big})).0);
        let (_, v) = run("feishu_doc", json!({"action": "create", "title": "T", "content": "x"}));
        assert!(v["error"].as_str().unwrap().contains("does not support content"));
        let (_, v) = run("feishu_doc", json!({"action": "create", "title": "T"}));
        assert_eq!(v["requester_permission_skipped_reason"], "trusted requester identity unavailable");
        f.set_session_origin(Arc::new(|_: &str| Some(crate::router::RouteKey { channel: "fs".into(), chat: "oc_g".into(), sender: Some("ou_req".into()) })));
        let (_, v) = run("feishu_doc", json!({"action": "create", "title": "T"}));
        assert_eq!((v["url"].as_str(), v["requester_permission_added"].as_bool()), (Some("https://feishu.cn/docx/NEW1"), Some(true)));
        let (e, v) = run("feishu_doc", json!({"action": "delete_block", "doc_token": "D1", "block_id": "b1"}));
        assert!(!e && v["deleted_block_id"] == "b1", "{v}");
        let (_, v) = run("feishu_doc", json!({"action": "color_text", "doc_token": "D1", "block_id": "b1", "content": "Revenue [green bold]+15%[/green] YoY [Q1]"}));
        assert_eq!(v["segments"], 5);
        let (e, v) = run("feishu_doc", json!({"action": "upload_image", "doc_token": "D1", "image": "data:image/png;base64,iVBORw0KGgo="}));
        assert!(e, "image block creation is not faked: {v}");
        let (_, v) = run("feishu_doc", json!({"action": "delete_table_rows", "doc_token": "D1", "block_id": "t1", "row_start": 1, "row_count": 2}));
        assert_eq!(v["rows_deleted"], 2);
        let patch = api_calls(&srv).into_iter().rev().find(|r| r.method == "PATCH").unwrap().json();
        assert_eq!(patch, json!({"delete_table_rows": {"row_start_index": 1, "row_end_index": 3}}));
        assert!(run("feishu_doc", json!({"action": "bogus"})).0);

        let (_, v) = run("feishu_app_scopes", json!({}));
        assert_eq!(v["summary"], "1 granted, 1 pending");
        let (_, v) = run("feishu_wiki", json!({"action": "spaces"}));
        assert!(v["hint"].as_str().unwrap().contains("Add the bot"));
        let (e, v) = run("feishu_wiki", json!({"action": "create", "space_id": 7123}));
        assert!(e && v["error"].as_str().unwrap().contains("must be a string"), "{v}");
        let (_, v) = run("feishu_wiki", json!({"action": "create", "space_id": "7123", "title": "Notes"}));
        assert_eq!((v["node_token"].as_str(), v["obj_type"].as_str()), (Some("N2"), Some("docx")));
        assert!(run("feishu_wiki", json!({"action": "nodes", "space_id": "7123", "page_size": 99})).0);
        // drive info falls back to the root listing without the metadata scope.
        let (_, v) = run("feishu_drive", json!({"action": "info", "file_token": "F1", "type": "docx"}));
        assert_eq!(v["name"], "a.docx");
        let (_, v) = run("feishu_drive", json!({"action": "list_comments", "file_token": "F1"}));
        assert_eq!(v["comments"][0]["replies"][0]["text"], "looks good");
        assert!(run("feishu_drive", json!({"action": "add_comment", "file_token": "F1", "file_type": "doc", "block_id": "b1", "content": "x"})).1["error"].as_str().unwrap().contains("only supported for docx"));
        assert_eq!(run("feishu_drive", json!({"action": "add_comment", "file_token": "F1", "block_id": "b1", "content": "x"})).1["comment_id"], "C9");
        assert!(run("feishu_drive", json!({"action": "list", "page_size": 5})).0, "paging needs folder_token");
        let (_, v) = run("feishu_chat", json!({"action": "member_info", "chat_id": "oc_g", "member_id": "ou_a"}));
        assert_eq!(v["name"], "Amy");
        let (e, v) = run("feishu_chat", json!({"action": "member_info", "chat_id": "oc_g", "member_id": "ou_stranger"}));
        assert!(e && v["error"].as_str().unwrap().contains("not a member"), "{v}");
        assert_eq!(run("feishu_chat", json!({"action": "info"})).1["error"], "chat_id is required for action info");
        let (_, v) = run("feishu_bitable_get_meta", json!({"url": "https://x.feishu.cn/wiki/WK1"}));
        assert_eq!((v["app_token"].as_str(), v["url_type"].as_str(), v["tables"][0]["table_id"].as_str()), (Some("APP9"), Some("wiki"), Some("tbl1")));
        let (_, v) = run("feishu_bitable_list_fields", json!({"app_token": "APP9", "table_id": "tbl1"}));
        assert_eq!(v["fields"][1]["type_name"], "DateTime");
        let (_, v) = run("feishu_bitable_create_record", json!({"app_token": "APP9", "table_id": "tbl1", "fields": {"Name": "x"}}));
        assert_eq!(v["record"]["record_id"], "rec1");
        assert!(tool("feishu_bitable_create_record").effects(&ctx, &json!({})).iter().any(|e| matches!(e, ark_core::Effect::Net { .. })));
        assert!(tool("feishu_drive").effects(&ctx, &json!({"action": "list"})).is_empty());
        assert_eq!(tools::parse_bitable_url("https://a.feishu.cn/base/AbC1?table=tblX&view=v"), Some(("AbC1".into(), Some("tblX".into()), false)));
        // perm is off unless enabled.
        assert_eq!(fs(&srv.url).tools().len(), 14);

        // Message actions for the `message` tool.
        assert!(f.message_actions().contains(&"list-pins"));
        let v = f.message_action("read", &json!({"messageId": "om_1"})).unwrap();
        assert_eq!(v["message"]["chat_id"], "oc_g");
        assert_eq!(f.message_action("pin", &json!({"messageId": "om_1"})).unwrap()["pin"]["message_id"], "om_1");
        assert_eq!(f.message_action("list-pins", &json!({"chatId": "oc_g"})).unwrap()["pins"][0]["messageId"], "om_1");
        let v = f.message_action("channel-info", &json!({"chatId": "oc_g", "includeMembers": true})).unwrap();
        assert_eq!((v["channel"]["name"].as_str(), v["members"]["members"][0]["name"].as_str()), (Some("Team"), Some("Amy")));
        assert!(f.message_action("member-info", &json!({"chatId": "oc_g", "memberId": "ou_nobody"})).is_err());
        assert!(f.message_action("list-pins", &json!({})).unwrap_err().message.contains("requires chatId"));
        assert!(f.message_action("poll", &json!({})).is_err());
        assert_eq!(tools::color_elements("[red]a[/red]b[")[0]["text_run"]["text_element_style"]["text_color"], 1);
    }
}
