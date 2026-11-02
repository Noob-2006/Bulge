//! DingTalk (钉钉) Stream Mode robot (ported from Hermes
//! `plugins/platforms/dingtalk`, MIT; wire protocol of the `dingtalk-stream` SDK).
//!
//! Receive: `POST /v1.0/gateway/connections/open` (clientId/clientSecret +
//! subscriptions) returns a WebSocket endpoint and a one-time ticket. Every
//! frame (`{specVersion, type, headers, data}`) is ACKed with its `messageId`;
//! `SYSTEM` `ping` frames are echoed, `disconnect` triggers a reconnect, and
//! `CALLBACK` frames on `/v1.0/im/bot/messages/get` carry chatbot messages
//! (text, richText, picture, file, audio, video, doc cards). `isInAtList` sets
//! `mentioned`; group gating is the host's job.
//! Send: reply through the message's `sessionWebhook` (markdown, valid until
//! `sessionWebhookExpiredTime`, 5-minute safety margin); when it is missing or
//! expired, fall back to the robot OpenAPI with a cached `oauth2/accessToken`
//! (`robot/oToMessages/batchSend` for DMs, `robot/groupMessages/send` for
//! groups). Local files are uploaded with `oapi media/upload` and sent as
//! image/file messages. With `card_template_id`, replies are AI Cards
//! (create → deliver → `card/streaming`), edits stream into the card, and open
//! cards are finalized on the next send, after `card_idle_finalize_secs`, or on stop.
//! Reactions use the robot emotion reply/recall API; attachments download via
//! `robot/messageFiles/download`.
//! Typing has no API: as Hermes does, the inbound message gets a "🤔思考中" emotion,
//! swapped for "🥳完成" when the reply goes out. Buttons: with `button_template_id`
//! (an interactive card template whose `buttons` variable is a JSON list of
//! `{text, data, url}` and whose actions return `data` in their params), the last
//! piece goes out as that card; presses arrive on the Stream topic
//! `/v1.0/card/instances/callback` and become `Callback`s. Without it buttons are
//! numbered options. Delete recalls robot-API messages (`groupMessages/recall`,
//! `otoMessages/batchRecall`); session-webhook replies cannot be recalled.

use crate::http::{Http, Payload};
use crate::{unsupported, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.dingtalk.com";
pub const DEFAULT_OAPI: &str = "https://oapi.dingtalk.com";
pub const BOT_TOPIC: &str = "/v1.0/im/bot/messages/get";
pub const CARD_TOPIC: &str = "/v1.0/card/instances/callback";
pub const MAX_MESSAGE: usize = 20000;
/// Upstream reconnect schedule (seconds, multiplied by `Opts::reconnect_base`).
const BACKOFF: [u32; 5] = [2, 5, 10, 30, 60];
const EMOTION_ID: &str = "2659900";
const EMOTION_BG: &str = "im_bg_1";
const THINKING: &str = "🤔思考中";
const DONE: &str = "🥳完成";

/// Tunables; `Default` is production behaviour.
#[derive(Clone)]
pub struct Opts {
    pub robot_code: Option<String>,
    pub card_template_id: Option<String>,
    /// Interactive card template for button rows (see module docs).
    pub button_template_id: Option<String>,
    pub api_base: String,
    pub oapi_base: String,
    pub poll_timeout_secs: u64,
    pub card_idle_finalize: Duration,
    /// One unit of the reconnect backoff (production: 1 s → 2, 5, 10, 30, 60 s).
    pub reconnect_base: Duration,
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest `retry_after` honoured in place; longer waits surface as `RateLimited`.
    pub max_wait: Duration,
    pub ping_every: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            robot_code: None,
            card_template_id: None,
            button_template_id: None,
            api_base: DEFAULT_API.into(),
            oapi_base: DEFAULT_OAPI.into(),
            poll_timeout_secs: 25,
            card_idle_finalize: Duration::from_secs(10),
            reconnect_base: Duration::from_secs(1),
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
            ping_every: Duration::from_secs(20),
        }
    }
}

/// What the last inbound message told us about a conversation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ChatCtx {
    webhook: String,
    /// Unix ms; 0 = unknown.
    expires_ms: i64,
    group: bool,
    staff: String,
    conversation: String,
    /// Last inbound message (for the thinking/done emotions) and where that cycle is.
    msg_id: String,
    mood: Mood,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Mood {
    #[default]
    None,
    Thinking,
    Done,
}

struct Card {
    chat: String,
    content: String,
    touched: Instant,
}

type Item = Result<Inbound, ChannelError>;

struct Inner {
    id: String,
    client_id: String,
    secret: String,
    robot_code: String,
    o: Opts,
    http: Http,
    token: Mutex<Option<(String, Instant)>>,
    chats: Mutex<HashMap<String, ChatCtx>>,
    cards: Mutex<HashMap<String, Card>>,
    /// Button cards we sent: outTrackId → chat.
    button_cards: Mutex<HashMap<String, String>>,
    tx: Mutex<Sender<Item>>,
    stop: AtomicBool,
    running: AtomicBool,
    /// Successful WebSocket sessions (diagnostics/tests).
    conns: AtomicUsize,
    sock: Mutex<Option<std::net::TcpStream>>,
}

pub struct DingTalk {
    inner: Arc<Inner>,
    rx: Mutex<Receiver<Item>>,
    pending_err: Mutex<Option<ChannelError>>,
}

impl Drop for DingTalk {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn err(kind: K, msg: impl Into<String>) -> ChannelError {
    ChannelError::new(kind, msg)
}

/// Map an HTTP response (OpenAPI `{code, message}` or oapi/webhook `{errcode, errmsg}`) to a value or a classified error.
fn check(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> Result<Value, ChannelError> {
    let v: Value = if body.trim().is_empty() { Value::Null } else { serde_json::from_str(body).unwrap_or(Value::Null) };
    let code = v["code"].as_str().unwrap_or("").to_string();
    let msg = v["message"].as_str().or_else(|| v["errmsg"].as_str()).unwrap_or("").to_string();
    if (200..300).contains(&status) {
        if v.is_null() && !body.trim().is_empty() {
            return Err(err(K::Protocol, format!("{what}: bad JSON: {}", body.chars().take(200).collect::<String>())));
        }
        return match v["errcode"].as_i64().unwrap_or(0) {
            0 => Ok(v),
            88 | 40001 | 40014 | 42001 | 33012 => Err(err(K::Auth, format!("{what}: access token rejected ({msg})"))),
            130101 | 130102 | 90018 | 90002 => Err(err(K::RateLimited { retry_after }, format!("{what}: rate limited ({msg})"))),
            300001 | 400013 | 410100 => Err(err(K::NotFound, format!("{what}: {msg}"))),
            n => Err(err(K::Protocol, format!("{what}: errcode {n} {msg}"))),
        };
    }
    let lc = code.to_ascii_lowercase();
    let kind = if lc.contains("qpslimit") || lc.contains("throttl") || lc.contains("flowcontrol") {
        K::RateLimited { retry_after }
    } else if lc.contains("invalidauthentication") || lc.contains("unauthorized") || lc.contains("invalidclient") || lc.contains("appsecret") {
        K::Auth
    } else if lc.contains("notfound") || lc.contains("not.found") || lc.contains("notexist") || lc.contains("not_exist") || lc.contains("robot.notin") || lc.contains("nopermission.chat") {
        K::NotFound
    } else {
        return Err(crate::http::classify(status, retry_after, what, &format!("{code} {msg}")));
    };
    Err(err(kind, format!("{what}: HTTP {status} {code} {msg}")))
}

impl Inner {
    fn api_url(&self, path: &str) -> String {
        format!("{}{path}", self.o.api_base)
    }

    /// One request with retries for transient failures. `secret` is scrubbed from transport errors.
    fn request(&self, what: &str, method: &str, url: &str, headers: &[(&str, &str)], body: Payload, secret: &str) -> Result<Value, ChannelError> {
        let mut attempt = 0;
        loop {
            let r = self.http.call(method, url, headers, clone_payload(&body)).and_then(|r| check(what, r.status, r.retry_after, &r.body));
            let e = match r {
                Ok(v) => return Ok(v),
                Err(mut e) => {
                    if !secret.is_empty() {
                        e.message = e.message.replace(secret, "***");
                    }
                    if !e.is_retryable() || attempt >= self.o.max_retries {
                        return Err(e);
                    }
                    e
                }
            };
            let wait = match e.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.o.max_wait => return Err(e),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.o.retry_base * 2u32.pow(attempt),
            };
            std::thread::sleep(wait);
            attempt += 1;
        }
    }

    /// Cached app access token (refreshed 5 minutes before expiry).
    fn token(&self) -> Result<String, ChannelError> {
        if let Some((t, exp)) = self.token.lock().unwrap().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let body = json!({"appKey": self.client_id, "appSecret": self.secret});
        let v = self.request("oauth2/accessToken", "POST", &self.api_url("/v1.0/oauth2/accessToken"), &[], Payload::Json(&body), &self.secret).map_err(|e| match e.kind {
            K::Protocol | K::Auth => err(K::Auth, format!("dingtalk rejected client_id/client_secret ({})", e.message)),
            _ => e,
        })?;
        let t = v["accessToken"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| err(K::Protocol, "oauth2/accessToken: no accessToken in response"))?.to_string();
        let ttl = v["expireIn"].as_u64().unwrap_or(7200);
        *self.token.lock().unwrap() = Some((t.clone(), Instant::now() + Duration::from_secs(ttl.saturating_sub(300).max(60))));
        Ok(t)
    }

    /// Authenticated OpenAPI call; a rejected token is refreshed once.
    fn api(&self, method: &str, path: &str, body: &Value) -> Result<Value, ChannelError> {
        let mut retried = false;
        loop {
            let tok = self.token()?;
            match self.request(path, method, &self.api_url(path), &[("x-acs-dingtalk-access-token", &tok)], Payload::Json(body), &tok) {
                Err(e) if e.kind == K::Auth && !retried => {
                    *self.token.lock().unwrap() = None;
                    retried = true;
                }
                r => return r,
            }
        }
    }

    fn webhook_ok(&self, url: &str) -> bool {
        [&self.o.api_base, &self.o.oapi_base].iter().any(|b| url.strip_prefix(b.as_str()).is_some_and(|rest| rest.starts_with('/')))
    }

    /// Context with a usable (unexpired, 5-minute margin) session webhook, or the bare context.
    fn ctx(&self, chat: &str) -> Option<ChatCtx> {
        let mut g = self.chats.lock().unwrap();
        let c = g.get_mut(chat)?;
        if c.expires_ms > 0 && now_ms() + 5 * 60 * 1000 >= c.expires_ms {
            c.webhook.clear();
        }
        Some(c.clone())
    }

    fn remember(&self, chat: &str, c: ChatCtx) {
        let mut g = self.chats.lock().unwrap();
        if g.len() >= 500 && !g.contains_key(chat) {
            if let Some(k) = g.keys().next().cloned() {
                g.remove(&k);
            }
        }
        g.insert(chat.to_string(), c);
    }

    // ---- stream gateway -------------------------------------------------

    fn run(self: Arc<Self>) {
        let mut fails = 0usize;
        while !self.stop.load(Ordering::SeqCst) {
            let delay = match self.session() {
                Ok(()) => {
                    fails = 0;
                    self.o.reconnect_base
                }
                Err(e) if e.kind == K::Auth || e.kind == K::Fatal => {
                    let _ = self.tx.lock().unwrap().send(Err(e));
                    break;
                }
                Err(_) => {
                    fails += 1;
                    self.o.reconnect_base * BACKOFF[(fails - 1).min(BACKOFF.len() - 1)]
                }
            };
            let until = Instant::now() + delay;
            while Instant::now() < until && !self.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// One WebSocket session. `Ok` = clean disconnect (reconnect soon), `Err` = failure (back off).
    fn session(&self) -> Result<(), ChannelError> {
        let body = json!({
            "clientId": self.client_id,
            "clientSecret": self.secret,
            "subscriptions": [{"type": "CALLBACK", "topic": BOT_TOPIC}, {"type": "CALLBACK", "topic": CARD_TOPIC}],
            "ua": "ark-dingtalk/1",
            "localIp": "",
        });
        let v = self.request("gateway/connections/open", "POST", &self.api_url("/v1.0/gateway/connections/open"), &[], Payload::Json(&body), &self.secret).map_err(|e| match e.kind {
            K::Protocol => err(K::Auth, format!("dingtalk rejected client_id/client_secret ({})", e.message)),
            _ => e,
        })?;
        let (Some(endpoint), Some(ticket)) = (v["endpoint"].as_str(), v["ticket"].as_str()) else {
            return Err(err(K::Protocol, "gateway/connections/open: missing endpoint or ticket"));
        };
        let sep = if endpoint.contains('?') { '&' } else { '?' };
        let url = format!("{endpoint}{sep}ticket={}", ark_net::urlencode(ticket));
        let (mut ws, _) = WebSocket::connect(&url, &[], Duration::from_secs(15)).map_err(|e| err(K::Network, format!("dingtalk stream connect: {e}")))?;
        ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| err(K::Network, e.to_string()))?;
        *self.sock.lock().unwrap() = ws.shutdown_handle().ok();
        self.conns.fetch_add(1, Ordering::SeqCst);
        let mut last_ping = Instant::now();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                return Ok(());
            }
            if last_ping.elapsed() >= self.o.ping_every {
                ws.send(&Message::Ping(Vec::new())).map_err(|e| err(K::Network, e.to_string()))?;
                last_ping = Instant::now();
            }
            let frame = match ws.recv() {
                Ok(None) => continue,
                Ok(Some(Message::Text(t))) => t,
                Ok(Some(Message::Binary(b))) => String::from_utf8_lossy(&b).into_owned(),
                Ok(Some(Message::Close(_))) => return Ok(()),
                Ok(Some(_)) => continue,
                Err(e) => return Err(err(K::Network, format!("dingtalk stream: {e}"))),
            };
            if !self.on_frame(&mut ws, &frame)? {
                return Ok(());
            }
        }
    }

    /// Handle one frame; `false` = the server asked us to disconnect.
    fn on_frame<S: std::io::Read + std::io::Write>(&self, ws: &mut WebSocket<S>, frame: &str) -> Result<bool, ChannelError> {
        let Ok(f) = serde_json::from_str::<Value>(frame) else { return Ok(true) };
        let headers = &f["headers"];
        let mid = headers["messageId"].as_str().unwrap_or("").to_string();
        let topic = headers["topic"].as_str().unwrap_or("");
        let send = |ws: &mut WebSocket<S>, v: Value| ws.send_text(&v.to_string()).map_err(|e| err(K::Network, e.to_string()));
        let ack = |code: u16, data: &str| json!({"code": code, "headers": {"contentType": "application/json", "messageId": mid}, "message": if code == 200 { "OK" } else { "error" }, "data": data});
        match f["type"].as_str().unwrap_or("") {
            "SYSTEM" => match topic {
                "ping" => send(ws, json!({"code": 200, "headers": headers, "message": "OK", "data": f["data"]}))?,
                "disconnect" => {
                    send(ws, ack(200, ""))?;
                    return Ok(false);
                }
                _ => send(ws, ack(200, ""))?,
            },
            "CALLBACK" => {
                let data = f["data"].as_str().map(|s| serde_json::from_str::<Value>(s).unwrap_or(Value::Null)).unwrap_or_else(|| f["data"].clone());
                if data.is_null() {
                    send(ws, ack(500, "{\"response\":null}"))?;
                    return Ok(true);
                }
                send(ws, ack(200, "{\"response\":null}"))?;
                if topic == BOT_TOPIC {
                    if let Some((msg, ctx)) = inbound_of(&self.id, &data) {
                        let ctx = ChatCtx { webhook: if self.webhook_ok(&ctx.webhook) { ctx.webhook } else { String::new() }, ..ctx };
                        self.remember(&msg.chat, ctx);
                        let _ = self.tx.lock().unwrap().send(Ok(msg));
                    }
                } else if topic == CARD_TOPIC {
                    let known = self.button_cards.lock().unwrap().get(&s(&data["outTrackId"])).cloned();
                    if let Some(msg) = card_callback_of(&self.id, &data, known, &mid) {
                        let _ = self.tx.lock().unwrap().send(Ok(msg));
                    }
                }
            }
            _ => send(ws, ack(200, "{\"status\":\"SUCCESS\",\"message\":\"success\"}"))?,
        }
        Ok(true)
    }

    // ---- outbound ---------------------------------------------------------

    /// (is_group, target id) for robot OpenAPI sends.
    fn target(&self, chat: &str, ctx: Option<&ChatCtx>) -> Result<(bool, String), ChannelError> {
        if let Some(g) = chat.strip_prefix("group:") {
            return Ok((true, g.into()));
        }
        if let Some(u) = chat.strip_prefix("user:") {
            return Ok((false, u.into()));
        }
        match ctx {
            Some(c) if c.group => Ok((true, if c.conversation.is_empty() { chat.into() } else { c.conversation.clone() })),
            Some(c) if !c.staff.is_empty() => Ok((false, c.staff.clone())),
            Some(_) => Err(err(K::Fatal, format!("dingtalk: no staff id known for DM {chat}; cannot send proactively"))),
            None => Ok((chat.starts_with("cid"), chat.into())),
        }
    }

    fn proactive(&self, chat: &str, ctx: Option<&ChatCtx>, key: &str, param: Value) -> Result<String, ChannelError> {
        let (group, target) = self.target(chat, ctx)?;
        let v = if group {
            self.api("POST", "/v1.0/robot/groupMessages/send", &json!({"robotCode": self.robot_code, "openConversationId": target, "msgKey": key, "msgParam": param.to_string()}))?
        } else {
            self.api("POST", "/v1.0/robot/oToMessages/batchSend", &json!({"robotCode": self.robot_code, "userIds": [target], "msgKey": key, "msgParam": param.to_string()}))?
        };
        if v["invalidStaffIdList"].as_array().is_some_and(|a| !a.is_empty()) {
            return Err(err(K::NotFound, format!("dingtalk: user {target} is not reachable by this robot")));
        }
        Ok(v["processQueryKey"].as_str().unwrap_or("").to_string())
    }

    fn post_webhook(&self, url: &str, body: &Value) -> Result<(), ChannelError> {
        // The session webhook URL is itself a credential; keep it out of errors.
        self.request("sessionWebhook", "POST", url, &[], Payload::Json(body), url).map(|_| ())
    }

    fn upload(&self, path: &str, kind: &str) -> Result<String, ChannelError> {
        let data = std::fs::read(path).map_err(|e| err(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let name = file_name(path);
        let tok = self.token()?;
        let url = format!("{}/media/upload?access_token={}&type={kind}", self.o.oapi_base, ark_net::urlencode(&tok));
        let parts: [(&str, &str, &str, &[u8]); 1] = [("media", &name, "", &data)];
        let v = self.request("media/upload", "POST", &url, &[], Payload::Multipart(&parts), &tok)?;
        v["media_id"].as_str().map(str::to_string).ok_or_else(|| err(K::Protocol, "media/upload: no media_id"))
    }

    fn card_stream(&self, track: &str, content: &str, finalize: bool) -> Result<(), ChannelError> {
        let content: String = content.chars().take(MAX_MESSAGE).collect();
        let guid = ark_net::crypto::hex(&ark_net::crypto::random_bytes(16));
        self.api("PUT", "/v1.0/card/streaming", &json!({"outTrackId": track, "guid": guid, "key": "content", "content": content, "isFull": true, "isFinalize": finalize, "isError": false})).map(|_| ())
    }

    fn card_create(&self, chat: &str, ctx: Option<&ChatCtx>, template: &str, content: &str, finalize: bool) -> Result<String, ChannelError> {
        let (group, target) = self.target(chat, ctx)?;
        let track = format!("ark_{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(6)));
        self.api("POST", "/v1.0/card/instances", &json!({
            "cardTemplateId": template,
            "outTrackId": track,
            "callbackType": "STREAM",
            "cardData": {"cardParamMap": {"content": ""}},
            "imGroupOpenSpaceModel": {"supportForward": true},
            "imRobotOpenSpaceModel": {"supportForward": true},
        }))?;
        let deliver = if group {
            json!({"outTrackId": track, "userIdType": 1, "openSpaceId": format!("dtv1.card//IM_GROUP.{target}"), "imGroupOpenDeliverModel": {"robotCode": self.robot_code}})
        } else {
            json!({"outTrackId": track, "userIdType": 1, "openSpaceId": format!("dtv1.card//IM_ROBOT.{target}"), "imRobotOpenDeliverModel": {"spaceType": "IM_ROBOT"}})
        };
        self.api("POST", "/v1.0/card/instances/deliver", &deliver)?;
        self.card_stream(&track, content, finalize)?;
        if !finalize {
            self.cards.lock().unwrap().insert(track.clone(), Card { chat: chat.into(), content: content.into(), touched: Instant::now() });
        }
        Ok(track)
    }

    /// An interactive card with button rows (`button_template_id`), finalized at once.
    fn button_card(&self, chat: &str, ctx: Option<&ChatCtx>, template: &str, content: &str, rows: &[Vec<crate::Button>]) -> Result<String, ChannelError> {
        let (group, target) = self.target(chat, ctx)?;
        let track = format!("arkb_{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(6)));
        let buttons: Vec<Value> = rows.iter().flatten().map(|b| json!({"text": b.label, "data": b.data, "url": b.url.clone().unwrap_or_default()})).collect();
        let (space, model) = if group {
            (format!("dtv1.card//IM_GROUP.{target}"), json!({"imGroupOpenDeliverModel": {"robotCode": self.robot_code}}))
        } else {
            (format!("dtv1.card//IM_ROBOT.{target}"), json!({"imRobotOpenDeliverModel": {"spaceType": "IM_ROBOT"}}))
        };
        let mut body = json!({
            "cardTemplateId": template,
            "outTrackId": track,
            "callbackType": "STREAM",
            "cardData": {"cardParamMap": {"content": content, "buttons": Value::Array(buttons).to_string()}},
            "imGroupOpenSpaceModel": {"supportForward": false},
            "imRobotOpenSpaceModel": {"supportForward": false},
            "openSpaceId": space,
            "userIdType": 1,
        });
        if let (Some(b), Some(m)) = (body.as_object_mut(), model.as_object()) {
            b.extend(m.clone());
        }
        self.api("POST", "/v1.0/card/instances/createAndDeliver", &body)?;
        let mut g = self.button_cards.lock().unwrap();
        if g.len() > 512 {
            g.clear();
        }
        g.insert(track.clone(), chat.to_string());
        Ok(track)
    }

    fn emotion(&self, chat: &str, msg: &str, name: &str, remove: bool) -> Result<(), ChannelError> {
        let cid = self.ctx(chat).map(|c| c.conversation).filter(|c| !c.is_empty()).unwrap_or_else(|| chat.trim_start_matches("group:").to_string());
        let path = if remove { "/v1.0/robot/emotion/recall" } else { "/v1.0/robot/emotion/reply" };
        let body = json!({
            "robotCode": self.robot_code, "openMsgId": msg, "openConversationId": cid,
            "emotionType": 2, "emotionName": name,
            "textEmotion": {"emotionId": EMOTION_ID, "emotionName": name, "text": name, "backgroundId": EMOTION_BG},
        });
        self.api("POST", path, &body).map(|_| ())
    }

    /// Move the chat's thinking/done cycle; returns the message id when the step applies.
    fn set_mood(&self, chat: &str, from: Mood, to: Mood) -> Option<String> {
        let mut g = self.chats.lock().unwrap();
        let c = g.get_mut(chat).filter(|c| c.mood == from && !c.msg_id.is_empty())?;
        c.mood = to;
        Some(c.msg_id.clone())
    }

    /// Finalize open cards matching `pick`.
    fn finalize_cards(&self, pick: impl Fn(&Card) -> bool) {
        let open: Vec<(String, String)> = {
            let mut g = self.cards.lock().unwrap();
            let ids: Vec<String> = g.iter().filter(|(_, c)| pick(c)).map(|(k, _)| k.clone()).collect();
            ids.into_iter().filter_map(|k| g.remove(&k).map(|c| (k, c.content))).collect()
        };
        for (track, content) in open {
            let _ = self.card_stream(&track, &content, true);
        }
    }
}

fn clone_payload<'a>(p: &Payload<'a>) -> Payload<'a> {
    match p {
        Payload::None => Payload::None,
        Payload::Json(v) => Payload::Json(v),
        Payload::Form(f) => Payload::Form(f),
        Payload::Raw(t, b) => Payload::Raw(t, b),
        Payload::Multipart(m) => Payload::Multipart(m),
    }
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
}

fn mime_of(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).as_deref() {
        Some("pdf") => "application/pdf",
        Some("doc") => "application/msword",
        Some("xls") => "application/vnd.ms-excel",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("md") => "text/markdown",
        Some("txt") => "text/plain",
        Some("csv") => "text/csv",
        Some("zip") => "application/zip",
        Some("mp4") => "video/mp4",
        _ => "application/octet-stream",
    }
}

fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Doc-share cards: `[文档] title url`.
fn card_text(d: &Value) -> String {
    let card = &d["card"];
    let title = s(&card["title"]);
    let raw = &card["content"];
    let url = match raw {
        Value::Object(_) => s(&raw["url"]).chars().chain(s(&raw["docUrl"]).chars()).collect::<String>(),
        Value::String(t) if !t.trim().is_empty() => serde_json::from_str::<Value>(t.trim()).ok().map(|j| if j["url"].is_string() { s(&j["url"]) } else { s(&j["docUrl"]) }).unwrap_or_else(|| t.clone()),
        _ => String::new(),
    };
    let mut parts = Vec::new();
    if !title.is_empty() {
        parts.push(format!("[文档] {title}"));
    }
    if !url.is_empty() {
        parts.push(url);
    }
    parts.join(" ")
}

/// One chatbot callback payload → Inbound plus what we need to reply to it.
fn inbound_of(channel: &str, d: &Value) -> Option<(Inbound, ChatCtx)> {
    let bot = s(&d["chatbotUserId"]);
    let sender_id = s(&d["senderId"]);
    if !bot.is_empty() && sender_id == bot {
        return None;
    }
    let msgtype = d["msgtype"].as_str().unwrap_or("text");
    let content = &d["content"];
    let mut text = s(&d["text"]["content"]).trim().to_string();
    let mut media = Vec::new();
    let code_of = |v: &Value| Some(s(&v["downloadCode"])).filter(|c| !c.is_empty()).or_else(|| Some(s(&v["pictureDownloadCode"])).filter(|c| !c.is_empty()));
    let item = |code: String, kind: MediaKind, name: String| {
        let mime = if name.is_empty() {
            match kind {
                MediaKind::Image => "image/jpeg".to_string(),
                MediaKind::Video => "video/mp4".to_string(),
                _ => String::new(),
            }
        } else {
            mime_of(&name).to_string()
        };
        Media { kind, id: Some(code), name, mime, ..Default::default() }
    };
    match msgtype {
        "richText" => {
            let mut parts = Vec::new();
            for it in content["richText"].as_array().or_else(|| d["richText"].as_array()).into_iter().flatten() {
                let t = s(&it["text"]);
                if !t.is_empty() {
                    parts.push(t);
                }
                if let Some(code) = code_of(it) {
                    let kind = match it["type"].as_str().unwrap_or("") {
                        "picture" | "image" => MediaKind::Image,
                        "voice" => MediaKind::Voice,
                        "audio" => MediaKind::Audio,
                        "video" => MediaKind::Video,
                        "" if it.get("pictureDownloadCode").is_some() => MediaKind::Image,
                        _ => MediaKind::Document,
                    };
                    media.push(item(code, kind, s(&it["fileName"])));
                }
            }
            if text.is_empty() {
                text = parts.join(" ").trim().to_string();
            }
        }
        "picture" | "image" => media.extend(code_of(content).map(|c| item(c, MediaKind::Image, s(&content["fileName"])))),
        "file" => {
            let name = s(&content["fileName"]);
            let kind = if mime_of(&name).starts_with("image/") { MediaKind::Image } else { MediaKind::Document };
            media.extend(code_of(content).map(|c| item(c, kind, name)));
        }
        "audio" => {
            if text.is_empty() {
                text = s(&content["recognition"]).trim().to_string();
            }
            media.extend(code_of(content).map(|c| item(c, MediaKind::Voice, String::new())));
        }
        "video" => media.extend(code_of(content).map(|c| item(c, MediaKind::Video, String::new()))),
        "card" if text.is_empty() => text = card_text(d),
        "interactiveCard" if text.is_empty() => {
            let (url, title) = (s(&content["biz_custom_action_url"]), s(&content["title"]));
            if !url.is_empty() || !title.is_empty() {
                text = [if title.is_empty() { "[文档卡片]".to_string() } else { format!("[文档卡片] {title}") }, url].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ");
            }
        }
        _ => {}
    }
    if text.is_empty() && media.is_empty() {
        return None;
    }
    let group = s(&d["conversationType"]) == "2";
    let conversation = s(&d["conversationId"]);
    let staff = s(&d["senderStaffId"]);
    let chat = if conversation.is_empty() { sender_id.clone() } else { conversation.clone() };
    if chat.is_empty() {
        return None;
    }
    let reply = (d["text"]["isReplyMsg"] == true).then(|| &d["text"]["repliedMsg"]).filter(|r| r.is_object()).map(|r| ReplyRef {
        id: s(&r["msgId"]),
        text: if r["content"].is_object() { s(&r["content"]["text"]) } else { s(&r["content"]) },
        author: s(&r["senderNick"]),
        is_own: !bot.is_empty() && s(&r["senderId"]) == bot,
    });
    let msg_id = s(&d["msgId"]);
    let inbound = Inbound {
        channel: channel.to_string(),
        chat: chat.clone(),
        chat_type: if group { ChatType::Group } else { ChatType::Direct },
        chat_name: s(&d["conversationTitle"]),
        sender: if staff.is_empty() { sender_id.clone() } else { staff.clone() },
        sender_name: Some(s(&d["senderNick"])).filter(|n| !n.is_empty()).unwrap_or_else(|| sender_id.clone()),
        text,
        message_id: if msg_id.is_empty() { format!("dt:{}:{}", chat, s(&d["createAt"])) } else { msg_id },
        ts: d["createAt"].as_i64().or_else(|| s(&d["createAt"]).parse().ok()).map(|ms| ms / 1000).unwrap_or(0),
        media,
        mentioned: d["isInAtList"] == true,
        reply,
        ..Default::default()
    };
    let ctx = ChatCtx { webhook: s(&d["sessionWebhook"]), expires_ms: d["sessionWebhookExpiredTime"].as_i64().unwrap_or(0), group, staff, conversation: chat, msg_id: s(&d["msgId"]), mood: Mood::None };
    Some((inbound, ctx))
}

/// A card button press (`/v1.0/card/instances/callback`) → `Callback`. `content` carries
/// `cardPrivateData {actionIds, params}`; our button cards put the data in `params.data`.
fn card_callback_of(channel: &str, d: &Value, known_chat: Option<String>, frame_id: &str) -> Option<Inbound> {
    let track = s(&d["outTrackId"]);
    let user = s(&d["userId"]);
    if user.is_empty() {
        return None;
    }
    let content = match &d["content"] {
        Value::String(t) => serde_json::from_str::<Value>(t).unwrap_or(Value::Null),
        v => v.clone(),
    };
    let pd = &content["cardPrivateData"];
    let params = &pd["params"];
    let data = [&params["data"], &params["action"], &pd["actionIds"][0], &d["value"]].into_iter().map(s).find(|x| !x.is_empty())?;
    let space = s(&d["spaceId"]);
    let group_space = s(&d["spaceType"]).to_ascii_uppercase().contains("GROUP") || space.starts_with("cid");
    let chat = known_chat.unwrap_or_else(|| if group_space && !space.is_empty() { space.clone() } else { user.clone() });
    let id = if track.is_empty() { frame_id.to_string() } else { format!("{track}:{}", &ark_net::crypto::hex(&ark_net::crypto::sha256(data.as_bytes()))[..8]) };
    Some(Inbound {
        channel: channel.to_string(),
        chat_type: if chat.starts_with("cid") || group_space { ChatType::Group } else { ChatType::Direct },
        chat,
        sender: user.clone(),
        sender_name: user,
        message_id: format!("cb:{id}:{frame_id}"),
        ts: now_ms() / 1000,
        reply: (!track.is_empty()).then(|| ReplyRef { id: track.clone(), is_own: true, ..Default::default() }),
        callback: Some(crate::Callback { id, data }),
        ..Default::default()
    })
}

/// DingTalk renderer quirks: blank line before a numbered list, dedented ``` fences.
fn normalize_markdown(text: &str) -> String {
    let numbered = |l: &str| {
        let t = l.trim();
        let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
        digits > 0 && t[digits..].starts_with(". ")
    };
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let prev = if i > 0 { lines[i - 1].trim() } else { "" };
        if !prev.is_empty() && numbered(line) && !numbered(prev) {
            out.push(String::new());
        }
        out.push(if line.trim().starts_with("```") { line.trim_start().to_string() } else { line.to_string() });
    }
    out.join("\n")
}

fn title_of(text: &str) -> String {
    let first = text.lines().map(|l| l.trim().trim_start_matches(['#', '*', '>', ' '])).find(|l| !l.is_empty()).unwrap_or("ark");
    first.chars().take(30).collect()
}

impl DingTalk {
    pub fn new(id: &str, client_id: &str, client_secret: &str, o: Opts) -> Result<DingTalk, String> {
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            return Err(format!("channel {id}: dingtalk client_id and client_secret are required"));
        }
        let (tx, rx) = mpsc::channel();
        let o = Opts { api_base: o.api_base.trim_end_matches('/').into(), oapi_base: o.oapi_base.trim_end_matches('/').into(), ..o };
        let inner = Inner {
            id: id.into(),
            client_id: client_id.trim().into(),
            secret: client_secret.trim().into(),
            robot_code: o.robot_code.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| client_id.trim().into()),
            http: Http::new(Duration::from_secs(30)),
            o,
            token: Mutex::new(None),
            chats: Mutex::new(HashMap::new()),
            cards: Mutex::new(HashMap::new()),
            button_cards: Mutex::new(HashMap::new()),
            tx: Mutex::new(tx),
            stop: AtomicBool::new(false),
            running: AtomicBool::new(false),
            conns: AtomicUsize::new(0),
            sock: Mutex::new(None),
        };
        Ok(DingTalk { inner: Arc::new(inner), rx: Mutex::new(rx), pending_err: Mutex::new(None) })
    }

    fn ensure_worker(&self) {
        if self.inner.stop.load(Ordering::SeqCst) || self.inner.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let inner = self.inner.clone();
        if std::thread::Builder::new().name(format!("dingtalk {}", self.inner.id)).spawn(move || inner.run()).is_err() {
            self.inner.running.store(false, Ordering::SeqCst);
        }
    }

    /// Finalize AI cards nobody has touched for `card_idle_finalize`.
    fn sweep_cards(&self) {
        let idle = self.inner.o.card_idle_finalize;
        if !self.inner.cards.lock().unwrap().is_empty() {
            self.inner.finalize_cards(|c| c.touched.elapsed() >= idle);
        }
    }

    fn send_text(&self, out: &Outbound, ctx: Option<&ChatCtx>, piece: &str, markdown: bool, last: bool) -> Result<String, ChannelError> {
        let inner = &self.inner;
        if let Some(t) = &inner.o.card_template_id {
            match inner.card_create(&out.chat, ctx, t, piece, out.reply_to.is_some() || !last) {
                Ok(id) => return Ok(id),
                Err(e) if matches!(e.kind, K::Auth | K::RateLimited { .. }) => return Err(e),
                Err(_) => {} // fall back to webhook / robot message
            }
        }
        let md = normalize_markdown(piece);
        if let Some(wh) = ctx.map(|c| c.webhook.as_str()).filter(|w| !w.is_empty()) {
            let body = if markdown { json!({"msgtype": "markdown", "markdown": {"title": title_of(piece), "text": md}}) } else { json!({"msgtype": "text", "text": {"content": piece}}) };
            match inner.post_webhook(wh, &body) {
                Ok(()) => return Ok(format!("wh:{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(6)))),
                Err(e) if matches!(e.kind, K::Protocol | K::NotFound | K::Auth) => {} // webhook expired early: try the robot API
                Err(e) => return Err(e),
            }
        }
        if markdown {
            inner.proactive(&out.chat, ctx, "sampleMarkdown", json!({"title": title_of(piece), "text": md}))
        } else {
            inner.proactive(&out.chat, ctx, "sampleText", json!({"content": piece}))
        }
    }
}

impl Channel for DingTalk {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn caps(&self) -> Caps {
        let cards = self.inner.o.card_template_id.is_some();
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: false,
            threads: false,
            reactions: 1,
            edit: cards,
            delete: true,
            typing: true,
            buttons: self.inner.o.button_template_id.is_some(),
            polls: false,
            native_commands: false,
            streaming: if cards { Streaming::Edit } else { Streaming::None },
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if let Some(e) = self.pending_err.lock().unwrap().take() {
            return Err(e);
        }
        self.ensure_worker();
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.inner.o.poll_timeout_secs.max(1));
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            self.sweep_cards();
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(m)) => {
                    got.push(m);
                    for more in rx.try_iter() {
                        match more {
                            Ok(m) => got.push(m),
                            Err(e) => {
                                *self.pending_err.lock().unwrap() = Some(e);
                                break;
                            }
                        }
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let inner = &self.inner;
        if let Some(m) = inner.set_mood(&out.chat, Mood::Thinking, Mood::Done) {
            let _ = inner.emotion(&out.chat, &m, THINKING, true);
            let _ = inner.emotion(&out.chat, &m, DONE, false);
        }
        let ctx = inner.ctx(&out.chat);
        if inner.o.card_template_id.is_some() {
            let chat = out.chat.clone();
            inner.finalize_cards(|c| c.chat == chat);
        }
        let mut sent = Sent::default();
        let mut extra = Vec::new();
        for m in &out.media {
            match (&m.path, &m.url) {
                (Some(p), _) => {
                    let name = if m.name.is_empty() { file_name(p) } else { m.name.clone() };
                    let id = if m.kind == MediaKind::Image {
                        let mid = inner.upload(p, "image")?;
                        inner.proactive(&out.chat, ctx.as_ref(), "sampleImageMsg", json!({"photoURL": mid}))?
                    } else {
                        let mid = inner.upload(p, if matches!(m.kind, MediaKind::Voice) { "voice" } else { "file" })?;
                        let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_else(|| "file".into());
                        inner.proactive(&out.chat, ctx.as_ref(), "sampleFile", json!({"mediaId": mid, "fileName": name, "fileType": ext}))?
                    };
                    sent.ids.push(id);
                    if let Some(c) = &m.caption {
                        extra.push(c.clone());
                    }
                }
                (None, Some(u)) => {
                    let label = if m.name.is_empty() { m.caption.clone().unwrap_or_else(|| "file".into()) } else { m.name.clone() };
                    extra.push(if m.kind == MediaKind::Image { format!("![{label}]({u})") } else { format!("[{label}]({u})") });
                }
                _ => return Err(err(K::Fatal, "attachment has neither path nor url")),
            }
        }
        let mut text = out.text.clone();
        let mut markdown = out.format == TextFormat::Markdown;
        if !extra.is_empty() {
            markdown = true;
            text = [text].into_iter().chain(extra).filter(|t| !t.trim().is_empty()).collect::<Vec<_>>().join("\n\n");
        }
        let card_buttons = inner.o.button_template_id.clone().filter(|_| out.buttons.iter().flatten().any(|b| b.url.is_none()));
        // No interactive buttons over webhooks / robot messages: numbered options, URL buttons as links.
        let mut n = 0;
        let mut opts = Vec::new();
        for b in out.buttons.iter().flatten().filter(|_| card_buttons.is_none()) {
            match &b.url {
                Some(u) => {
                    markdown = true;
                    opts.push(format!("[{}]({u})", b.label));
                }
                None => {
                    n += 1;
                    opts.push(format!("{n}. {}", b.label));
                }
            }
        }
        if !opts.is_empty() {
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n"));
        }
        if text.trim().is_empty() {
            return Ok(sent);
        }
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let count = pieces.len();
        for (i, p) in pieces.iter().enumerate() {
            if let (Some(t), true) = (&card_buttons, i + 1 == count) {
                match inner.button_card(&out.chat, ctx.as_ref(), t, &normalize_markdown(p), &out.buttons) {
                    Ok(id) => {
                        sent.ids.push(id);
                        continue;
                    }
                    Err(e) if matches!(e.kind, K::Auth | K::RateLimited { .. }) => return Err(e),
                    // Template rejected: numbered options instead.
                    Err(_) => {
                        let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(n, b)| format!("{}. {}", n + 1, b.label)).collect();
                        sent.ids.push(self.send_text(out, ctx.as_ref(), &format!("{}\n\n{}", p.trim_end(), opts.join("\n")), markdown, true)?);
                        continue;
                    }
                }
            }
            sent.ids.push(self.send_text(out, ctx.as_ref(), p, markdown, i + 1 == count)?);
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        match self.inner.set_mood(chat, Mood::None, Mood::Thinking) {
            Some(m) => self.inner.emotion(chat, &m, THINKING, false),
            None => Ok(()),
        }
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        if message_id.starts_with("wh:") || message_id.starts_with("ark") || message_id.is_empty() {
            return Err(unsupported("delete of session-webhook replies and cards (only robot-API messages can be recalled)"));
        }
        let inner = &self.inner;
        let (group, target) = inner.target(chat, inner.ctx(chat).as_ref())?;
        if group {
            inner.api("POST", "/v1.0/robot/groupMessages/recall", &json!({"robotCode": inner.robot_code, "openConversationId": target, "processQueryKeys": [message_id]}))?;
        } else {
            inner.api("POST", "/v1.0/robot/otoMessages/batchRecall", &json!({"robotCode": inner.robot_code, "processQueryKeys": [message_id]}))?;
        }
        Ok(())
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        if self.inner.o.card_template_id.is_none() || message_id.starts_with("wh:") || message_id.is_empty() {
            return Err(unsupported("edit (needs card_template_id and an AI Card message)"));
        }
        self.inner.card_stream(message_id, text, false)?;
        self.inner.cards.lock().unwrap().insert(message_id.into(), Card { chat: chat.into(), content: text.into(), touched: Instant::now() });
        Ok(())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        self.inner.emotion(chat, message_id, emoji, remove)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let code = m.id.as_deref().ok_or_else(|| err(K::Fatal, "dingtalk attachment without downloadCode"))?;
        let v = self.inner.api("POST", "/v1.0/robot/messageFiles/download", &json!({"downloadCode": code, "robotCode": self.inner.robot_code}))?;
        let url = v["downloadUrl"].as_str().ok_or_else(|| err(K::Protocol, "messageFiles/download: no downloadUrl"))?;
        crate::http::get_bytes(url, &[], 50 * 1024 * 1024)
    }

    fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(s) = self.inner.sock.lock().unwrap().take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.inner.finalize_cards(|_| true);
    }
}

fn d_poll() -> u64 {
    25
}

fn d_idle() -> u64 {
    10
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    client_id: String,
    client_secret: String,
    /// Robot code for OpenAPI sends (defaults to client_id).
    #[serde(default)]
    robot_code: Option<String>,
    /// AI Card template: replies become streaming cards (enables edit).
    #[serde(default)]
    card_template_id: Option<String>,
    /// Interactive card template rendering `content` + a `buttons` JSON list.
    #[serde(default)]
    button_template_id: Option<String>,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    oapi_base: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_idle")]
    card_idle_finalize_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let id = ctx.secret("client_id", &st.client_id)?;
    let secret = ctx.secret("client_secret", &st.client_secret)?;
    let o = Opts {
        robot_code: ctx.opt_secret("robot_code", &st.robot_code)?,
        card_template_id: st.card_template_id.filter(|t| !t.is_empty()),
        button_template_id: st.button_template_id.filter(|t| !t.is_empty()),
        api_base: st.api_base.unwrap_or_else(|| DEFAULT_API.into()),
        oapi_base: st.oapi_base.unwrap_or_else(|| DEFAULT_OAPI.into()),
        poll_timeout_secs: st.poll_timeout_secs,
        card_idle_finalize: Duration::from_secs(st.card_idle_finalize_secs.max(1)),
        ..Opts::default()
    };
    Ok(Arc::new(DingTalk::new(ctx.name, &id, &secret, o)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use ark_net::ws::read_head;
    use std::net::TcpListener;

    fn opts(url: &str) -> Opts {
        Opts {
            api_base: url.into(),
            oapi_base: url.into(),
            poll_timeout_secs: 2,
            reconnect_base: Duration::from_millis(20),
            retry_base: Duration::from_millis(5),
            ping_every: Duration::from_secs(60),
            ..Opts::default()
        }
    }

    fn dt(url: &str) -> DingTalk {
        DingTalk::new("dt", "APPKEY", "APPSECRET", opts(url)).unwrap()
    }

    fn ok(v: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], v.to_string())
    }

    fn token_reply() -> (u16, Vec<(String, String)>, String) {
        ok(json!({"accessToken": "TOK123", "expireIn": 7200}))
    }

    fn msg(id: &str, text: &str) -> Value {
        json!({
            "conversationId": "cidDM1", "chatbotUserId": "$:bot:$", "msgId": id, "senderNick": "Amy",
            "senderStaffId": "staff42", "senderId": "$:amy:$", "conversationType": "1", "createAt": 1700000000123i64,
            "msgtype": "text", "text": {"content": text}, "robotCode": "APPKEY",
        })
    }

    #[test]
    fn parses_every_message_kind() {
        let (m, c) = inbound_of("dt", &msg("m1", "  hi ")).unwrap();
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.sender_name.as_str(), m.text.as_str(), m.message_id.as_str(), m.ts, m.chat_type), ("cidDM1", "staff42", "Amy", "hi", "m1", 1700000000, ChatType::Direct));
        assert_eq!((c.staff.as_str(), c.group), ("staff42", false));
        // Group with @mention, title, webhook context.
        let mut g = msg("m2", "@ark do it");
        g["conversationType"] = json!("2");
        g["conversationId"] = json!("cidG");
        g["conversationTitle"] = json!("Team");
        g["isInAtList"] = json!(true);
        g["sessionWebhook"] = json!("https://oapi.dingtalk.com/robot/sendBySession?session=x");
        g["sessionWebhookExpiredTime"] = json!(1900000000000i64);
        let (m, c) = inbound_of("dt", &g).unwrap();
        assert!(m.mentioned && m.chat_type == ChatType::Group && m.chat_name == "Team" && c.group && c.expires_ms == 1900000000000);
        g["isInAtList"] = json!(false);
        assert!(!inbound_of("dt", &g).unwrap().0.mentioned);
        // Rich text with a picture.
        let rt = json!({"conversationId": "c", "senderId": "u", "msgId": "r", "msgtype": "richText", "content": {"richText": [{"text": "look"}, {"pictureDownloadCode": "PC1", "downloadCode": "DC1", "type": "picture"}, {"text": "here"}, {"downloadCode": "V1", "type": "voice"}]}});
        let (m, _) = inbound_of("dt", &rt).unwrap();
        assert_eq!(m.text, "look here");
        assert_eq!((m.media[0].kind, m.media[0].id.as_deref(), m.media[1].kind), (MediaKind::Image, Some("DC1"), MediaKind::Voice));
        // Picture, file, audio (recognition text), video.
        let pic = json!({"conversationId": "c", "senderId": "u", "msgId": "p", "msgtype": "picture", "content": {"downloadCode": "IMG"}});
        assert_eq!(inbound_of("dt", &pic).unwrap().0.media[0], Media { kind: MediaKind::Image, id: Some("IMG".into()), mime: "image/jpeg".into(), ..Default::default() });
        let file = json!({"conversationId": "c", "senderId": "u", "msgId": "f", "msgtype": "file", "content": {"downloadCode": "F1", "fileName": "report.pdf"}});
        let f = inbound_of("dt", &file).unwrap().0;
        assert_eq!((f.media[0].kind, f.media[0].name.as_str(), f.media[0].mime.as_str()), (MediaKind::Document, "report.pdf", "application/pdf"));
        let png = json!({"conversationId": "c", "senderId": "u", "msgId": "f2", "msgtype": "file", "content": {"downloadCode": "F2", "fileName": "shot.PNG"}});
        assert_eq!(inbound_of("dt", &png).unwrap().0.media[0].kind, MediaKind::Image);
        let audio = json!({"conversationId": "c", "senderId": "u", "msgId": "a", "msgtype": "audio", "content": {"downloadCode": "A1", "recognition": "你好", "duration": 3}});
        let a = inbound_of("dt", &audio).unwrap().0;
        assert_eq!((a.text.as_str(), a.media[0].kind), ("你好", MediaKind::Voice));
        let video = json!({"conversationId": "c", "senderId": "u", "msgId": "v", "msgtype": "video", "content": {"downloadCode": "VD", "videoType": "mp4"}});
        assert_eq!(inbound_of("dt", &video).unwrap().0.media[0].kind, MediaKind::Video);
        // Doc cards.
        let card = json!({"conversationId": "c", "senderId": "u", "msgId": "k", "msgtype": "card", "card": {"title": "Plan", "content": "{\"url\": \"https://docs.dingtalk.com/x\"}"}});
        assert_eq!(inbound_of("dt", &card).unwrap().0.text, "[文档] Plan https://docs.dingtalk.com/x");
        let ic = json!({"conversationId": "c", "senderId": "u", "msgId": "k2", "msgtype": "interactiveCard", "content": {"title": "Doc", "biz_custom_action_url": "https://d/1"}});
        assert_eq!(inbound_of("dt", &ic).unwrap().0.text, "[文档卡片] Doc https://d/1");
        // Reply to the bot.
        let mut r = msg("m3", "yes");
        r["text"]["isReplyMsg"] = json!(true);
        r["text"]["repliedMsg"] = json!({"msgId": "orig", "senderId": "$:bot:$", "content": {"text": "shall I?"}});
        let rr = inbound_of("dt", &r).unwrap().0.reply.unwrap();
        assert!(rr.is_own && rr.id == "orig" && rr.text == "shall I?");
        // Own messages and empty messages are dropped.
        let mut own = msg("m4", "echo");
        own["senderId"] = json!("$:bot:$");
        assert!(inbound_of("dt", &own).is_none());
        assert!(inbound_of("dt", &msg("m5", "   ")).is_none());
        assert!(inbound_of("dt", &json!({"conversationId": "c", "senderId": "u", "msgtype": "picture", "content": {}})).is_none());
    }

    /// Fake gateway: HTTP `connections/open` plus a scripted WebSocket server.
    /// Returns (ws url, frames the client sent per connection).
    type Shared<T> = Arc<Mutex<Vec<T>>>;

    fn ws_server(script: Vec<Vec<Value>>) -> (String, Shared<Vec<Value>>, Shared<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/connect", l.local_addr().unwrap());
        let got = Arc::new(Mutex::new(Vec::new()));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let (g2, p2) = (got.clone(), paths.clone());
        std::thread::spawn(move || {
            for frames in script {
                let Ok((mut s, _)) = l.accept() else { return };
                let (head, rest) = read_head(&mut s, 65536).unwrap();
                p2.lock().unwrap().push(head.lines().next().unwrap_or("").to_string());
                let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                ws.get_ref().set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut seen = Vec::new();
                for f in frames {
                    if f == json!("DROP") {
                        break;
                    }
                    ws.send_text(&f.to_string()).unwrap();
                    // Every frame must be answered (ACK / ping echo).
                    loop {
                        match ws.recv() {
                            Ok(Some(Message::Text(t))) => {
                                seen.push(serde_json::from_str::<Value>(&t).unwrap());
                                break;
                            }
                            Ok(Some(_)) => continue,
                            _ => break,
                        }
                    }
                }
                g2.lock().unwrap().push(seen);
                drop(ws); // dropped WebSocket: the client must reconnect
            }
            std::thread::sleep(Duration::from_secs(5));
        });
        (url, got, paths)
    }

    fn cb_frame(mid: &str, data: &Value) -> Value {
        json!({"specVersion": "1.0", "type": "CALLBACK", "headers": {"messageId": mid, "topic": BOT_TOPIC, "contentType": "application/json", "time": "1"}, "data": data.to_string()})
    }

    #[test]
    fn stream_acks_every_frame_echoes_ping_and_reconnects_after_drop() {
        let ping = json!({"specVersion": "1.0", "type": "SYSTEM", "headers": {"messageId": "p1", "topic": "ping", "contentType": "application/json"}, "data": "{\"opaque\":\"abc\"}"});
        let event = json!({"type": "EVENT", "headers": {"messageId": "e1", "topic": "chat_update_title"}, "data": "{}"});
        let disconnect = json!({"type": "SYSTEM", "headers": {"messageId": "d1", "topic": "disconnect"}, "data": "{}"});
        let (ws_url, got, paths) = ws_server(vec![
            vec![ping, cb_frame("f1", &msg("m1", "first")), event, json!("DROP")],
            vec![cb_frame("f2", &msg("m2", "second")), disconnect],
            vec![cb_frame("f3", &msg("m3", "third"))],
        ]);
        let wsu = ws_url.clone();
        let srv = FakeServer::start(move |req, n| {
            assert!(req.path.ends_with("/v1.0/gateway/connections/open"), "{}", req.path);
            ok(json!({"endpoint": wsu, "ticket": format!("T/{n}+")}))
        });
        let t = dt(&srv.url);
        let mut texts = Vec::new();
        let start = Instant::now();
        while texts.len() < 3 && start.elapsed() < Duration::from_secs(10) {
            texts.extend(t.poll(&Cancel::new()).unwrap().into_iter().map(|m| m.text));
        }
        assert_eq!(texts, ["first", "second", "third"]);
        let open = srv.requests()[0].json();
        assert_eq!((open["clientId"].as_str(), open["clientSecret"].as_str(), open["subscriptions"][0]["topic"].as_str(), open["subscriptions"][0]["type"].as_str()), (Some("APPKEY"), Some("APPSECRET"), Some(BOT_TOPIC), Some("CALLBACK")));
        std::thread::sleep(Duration::from_millis(100));
        let g = got.lock().unwrap().clone();
        assert_eq!(g[0][0]["data"], "{\"opaque\":\"abc\"}", "ping echoed with its data");
        assert_eq!((g[0][0]["code"].as_i64(), g[0][0]["headers"]["messageId"].as_str()), (Some(200), Some("p1")));
        assert_eq!((g[0][1]["headers"]["messageId"].as_str(), g[0][1]["code"].as_i64(), g[0][1]["data"].as_str()), (Some("f1"), Some(200), Some("{\"response\":null}")));
        assert_eq!((g[0][2]["headers"]["messageId"].as_str(), g[0][2]["data"].as_str()), (Some("e1"), Some("{\"status\":\"SUCCESS\",\"message\":\"success\"}")), "events ACKed too");
        assert_eq!(g[1][1]["headers"]["messageId"], "d1", "disconnect ACKed before reconnecting");
        assert!(paths.lock().unwrap()[0].starts_with("GET /connect?ticket=T%2F0%2B "), "{:?}", paths.lock().unwrap());
        assert!(t.inner.conns.load(Ordering::SeqCst) >= 3);
        assert!(srv.requests().len() >= 3, "fresh ticket per connection");
        t.stop();
    }

    #[test]
    fn button_cards_callbacks_thinking_emotions_and_recall() {
        let srv = FakeServer::start(|req, n| {
            if req.path.ends_with("/oauth2/accessToken") {
                return token_reply();
            }
            if req.path.ends_with("/createAndDeliver") && req.body.contains("tpl.bad") {
                return (400, vec![], json!({"code": "param.invalid", "message": "bad template"}).to_string());
            }
            ok(json!({"processQueryKey": format!("PQ{n}"), "success": true}))
        });
        let t = DingTalk::new("dt", "APPKEY", "APPSECRET", Opts { button_template_id: Some("tpl.btn".into()), ..opts(&srv.url) }).unwrap();
        assert!(t.caps().buttons && t.caps().typing && t.caps().delete);
        t.inner.remember("cidG", ChatCtx { group: true, conversation: "cidG".into(), msg_id: "msgIn".into(), ..Default::default() });
        // typing → one thinking emotion per inbound message.
        t.typing("cidG", None).unwrap();
        t.typing("cidG", None).unwrap();
        let b = |l: &str, d: &str| crate::Button { label: l.into(), data: d.into(), url: None };
        let out = Outbound { buttons: vec![vec![b("允許", "appr:1:once"), b("拒絕", "appr:1:deny")]], ..Outbound::text("cidG", "Run `rm`?") };
        let id = t.send(&out).unwrap().ids[0].clone();
        let r: Vec<_> = srv.requests().into_iter().filter(|r| !r.path.ends_with("/oauth2/accessToken")).collect();
        assert_eq!((r[0].path.as_str(), r[0].json()["emotionName"].as_str(), r[0].json()["openMsgId"].as_str()), ("/v1.0/robot/emotion/reply", Some(THINKING), Some("msgIn")));
        assert_eq!((r[1].path.as_str(), r[1].json()["emotionName"].as_str()), ("/v1.0/robot/emotion/recall", Some(THINKING)));
        assert_eq!((r[2].path.as_str(), r[2].json()["emotionName"].as_str()), ("/v1.0/robot/emotion/reply", Some(DONE)));
        let c = r[3].json();
        assert_eq!(r[3].path, "/v1.0/card/instances/createAndDeliver");
        assert_eq!((c["cardTemplateId"].as_str(), c["outTrackId"].as_str(), c["openSpaceId"].as_str(), c["callbackType"].as_str()), (Some("tpl.btn"), Some(id.as_str()), Some("dtv1.card//IM_GROUP.cidG"), Some("STREAM")));
        assert_eq!(c["cardData"]["cardParamMap"]["content"], "Run `rm`?");
        let btns: Value = serde_json::from_str(c["cardData"]["cardParamMap"]["buttons"].as_str().unwrap()).unwrap();
        assert_eq!(btns[1], json!({"text": "拒絕", "data": "appr:1:deny", "url": ""}));
        assert_eq!(r.len(), 4, "done swap happens once");
        t.send(&Outbound::text("cidG", "more")).ok();
        assert!(!srv.requests().iter().skip(5).any(|r| r.path.contains("emotion")));

        // A press on that card → Callback in the card's chat.
        let press = json!({"outTrackId": id, "userId": "staff7", "corpId": "ding1", "type": "actionCallback", "spaceType": "IM_GROUP", "spaceId": "cidG",
                           "content": json!({"cardPrivateData": {"actionIds": ["btn_0"], "params": {"data": "appr:1:deny"}}}).to_string()});
        let known = t.inner.button_cards.lock().unwrap().get(&id).cloned();
        let m = card_callback_of("dt", &press, known, "f9").unwrap();
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.chat_type, m.callback.as_ref().unwrap().data.as_str()), ("cidG", "staff7", ChatType::Group, "appr:1:deny"));
        assert!(m.reply.as_ref().unwrap().is_own);
        // Unknown card in a DM: falls back to the user; actionIds when no params.
        let dm = json!({"outTrackId": "other", "userId": "u1", "spaceType": "IM_ROBOT", "content": {"cardPrivateData": {"actionIds": ["ok"]}}});
        let m = card_callback_of("dt", &dm, None, "f10").unwrap();
        assert_eq!((m.chat.as_str(), m.chat_type, m.callback.unwrap().data.as_str()), ("u1", ChatType::Direct, "ok"));
        assert!(card_callback_of("dt", &json!({"outTrackId": "x", "content": "{}"}), None, "f").is_none());

        // Recall: robot-API messages only.
        t.delete("cidG", "PQ5").unwrap();
        let last = srv.requests().last().unwrap().clone();
        assert_eq!((last.path.as_str(), last.json()["processQueryKeys"][0].as_str(), last.json()["openConversationId"].as_str()), ("/v1.0/robot/groupMessages/recall", Some("PQ5"), Some("cidG")));
        t.inner.remember("cidDM", ChatCtx { staff: "s9".into(), ..Default::default() });
        t.delete("cidDM", "PQ6").unwrap();
        assert_eq!(srv.requests().last().unwrap().path, "/v1.0/robot/otoMessages/batchRecall");
        assert_eq!(t.delete("cidG", "wh:abc").unwrap_err().kind, K::Unsupported);

        // A rejected template degrades to numbered options.
        let t2 = DingTalk::new("dt", "APPKEY", "APPSECRET", Opts { button_template_id: Some("tpl.bad".into()), ..opts(&srv.url) }).unwrap();
        t2.inner.remember("cidG", ChatCtx { group: true, conversation: "cidG".into(), ..Default::default() });
        t2.send(&out).unwrap();
        let p: Value = serde_json::from_str(srv.requests().last().unwrap().json()["msgParam"].as_str().unwrap()).unwrap();
        assert_eq!(p["content"], "Run `rm`?\n\n1. 允許\n2. 拒絕");
    }

    #[test]
    fn card_callback_frames_arrive_over_the_stream() {
        let press = json!({"outTrackId": "t1", "userId": "u1", "content": "{\"cardPrivateData\":{\"params\":{\"data\":\"go\"}}}"});
        let frame = json!({"specVersion": "1.0", "type": "CALLBACK", "headers": {"messageId": "c1", "topic": CARD_TOPIC}, "data": press.to_string()});
        let (ws_url, got, _) = ws_server(vec![vec![frame]]);
        let srv = FakeServer::start(move |_, _| ok(json!({"endpoint": ws_url, "ticket": "T"})));
        let t = dt(&srv.url);
        let mut msgs = Vec::new();
        let start = Instant::now();
        while msgs.is_empty() && start.elapsed() < Duration::from_secs(5) {
            msgs.extend(t.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(msgs[0].callback.as_ref().unwrap().data, "go");
        assert_eq!(srv.requests()[0].json()["subscriptions"][1], json!({"type": "CALLBACK", "topic": CARD_TOPIC}));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(got.lock().unwrap()[0][0]["headers"]["messageId"], "c1", "card callbacks ACKed");
        t.stop();
    }

    #[test]
    fn bad_credentials_surface_as_auth_from_poll() {
        let srv = FakeServer::start(|_, _| (400, vec![], json!({"code": "InvalidClientIdOrSecret", "message": "bad appkey"}).to_string()));
        let t = dt(&srv.url);
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("APPSECRET"), "{}", e.message);
        assert_eq!(srv.requests().len(), 1, "auth errors are not retried");
    }

    #[test]
    fn cancel_interrupts_a_blocked_poll() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let t = DingTalk::new("dt", "A", "S", Opts { poll_timeout_secs: 30, ..opts(&url) }).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(t.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        t.stop();
    }

    /// Seed a chat context as an inbound message would.
    fn seed(t: &DingTalk, chat: &str, webhook: &str, expires_ms: i64, group: bool) {
        t.inner.remember(chat, ChatCtx { webhook: webhook.into(), expires_ms, group, staff: "staff42".into(), conversation: chat.into(), ..Default::default() });
    }

    #[test]
    fn replies_via_session_webhook_then_falls_back_to_robot_api() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/oauth2/accessToken") {
                return token_reply();
            }
            if req.path.starts_with("/robot/sendBySession") {
                return ok(json!({"errcode": 0, "errmsg": "ok"}));
            }
            ok(json!({"processQueryKey": "PQK"}))
        });
        let t = dt(&srv.url);
        let wh = format!("{}/robot/sendBySession?session=abc", srv.url);
        seed(&t, "cidDM1", &wh, now_ms() + 3_600_000, false);
        let out = Outbound { format: TextFormat::Markdown, reply_to: Some("m1".into()), ..Outbound::text("cidDM1", "# Title\nsteps:\n1. one\n2. two\n  ```rust\n  x\n  ```") };
        let s = t.send(&out).unwrap();
        assert!(s.ids[0].starts_with("wh:"));
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/robot/sendBySession?session=abc");
        let b = r.json();
        assert_eq!((b["msgtype"].as_str(), b["markdown"]["title"].as_str()), (Some("markdown"), Some("Title")));
        assert_eq!(b["markdown"]["text"], "# Title\nsteps:\n\n1. one\n2. two\n```rust\n  x\n```", "blank line before list, dedented fences");
        // Plain text keeps msgtype text.
        t.send(&Outbound::text("cidDM1", "plain *x*")).unwrap();
        assert_eq!(srv.requests()[1].json(), json!({"msgtype": "text", "text": {"content": "plain *x*"}}));
        // Expiring webhook (inside the 5-minute margin) → robot API with a cached token.
        seed(&t, "cidDM1", &wh, now_ms() + 60_000, false);
        assert_eq!(t.send(&Outbound::text("cidDM1", "later")).unwrap().ids, ["PQK"]);
        assert_eq!(t.send(&Outbound::text("cidDM1", "again")).unwrap().ids, ["PQK"]);
        let reqs = srv.requests();
        assert_eq!(reqs[2].path, "/v1.0/oauth2/accessToken");
        assert_eq!(reqs[2].json(), json!({"appKey": "APPKEY", "appSecret": "APPSECRET"}));
        assert_eq!(reqs[3].path, "/v1.0/robot/oToMessages/batchSend");
        assert_eq!(reqs[3].header("x-acs-dingtalk-access-token"), Some("TOK123"));
        let b = reqs[3].json();
        assert_eq!((b["robotCode"].as_str(), b["userIds"][0].as_str(), b["msgKey"].as_str()), (Some("APPKEY"), Some("staff42"), Some("sampleText")));
        assert_eq!(serde_json::from_str::<Value>(b["msgParam"].as_str().unwrap()).unwrap(), json!({"content": "later"}));
        assert_eq!(reqs[4].path, "/v1.0/robot/oToMessages/batchSend", "token cached");
        // Groups (known or by cid prefix) use groupMessages/send; buttons become numbered options.
        let out = Outbound { buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:1:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]], ..Outbound::text("cidGroup", "ok?") };
        t.send(&out).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/v1.0/robot/groupMessages/send");
        let b = r.json();
        assert_eq!((b["openConversationId"].as_str(), b["msgKey"].as_str()), (Some("cidGroup"), Some("sampleMarkdown")));
        assert_eq!(serde_json::from_str::<Value>(b["msgParam"].as_str().unwrap()).unwrap()["text"], "ok?\n\n1. 允許\n[docs](https://e.com)");
        t.send(&Outbound::text("user:staff7", "dm")).unwrap();
        assert_eq!(srv.requests().last().unwrap().json()["userIds"][0], "staff7");
    }

    #[test]
    fn foreign_session_webhooks_are_ignored() {
        let t = dt("http://127.0.0.1:9");
        assert!(t.inner.webhook_ok("http://127.0.0.1:9/robot/sendBySession?x"));
        assert!(!t.inner.webhook_ok("http://127.0.0.1:9.evil.com/robot"));
        assert!(!t.inner.webhook_ok("https://evil.example/robot"));
    }

    #[test]
    fn media_upload_url_media_download_and_reactions() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/oauth2/accessToken") {
                return token_reply();
            }
            if req.path.starts_with("/media/upload") {
                return ok(json!({"errcode": 0, "media_id": "@MEDIA1", "type": "image"}));
            }
            if req.path.ends_with("/messageFiles/download") {
                return ok(json!({"downloadUrl": format!("http://{}/blob/1", req.header("host").unwrap())}));
            }
            if req.path == "/blob/1" {
                return (200, vec![], "BYTES".into());
            }
            ok(json!({"processQueryKey": "PQ"}))
        });
        let t = dt(&srv.url);
        seed(&t, "cidG", "", 0, true);
        let f = temp_dir("dt").join("pic.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let img = Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() };
        let s = t.send(&Outbound { media: vec![img], ..Outbound::text("cidG", "") }).unwrap();
        assert_eq!(s.ids, ["PQ"]);
        let reqs = srv.requests();
        assert_eq!(reqs[1].path, "/media/upload?access_token=TOK123&type=image");
        assert!(reqs[1].body.contains("name=\"media\"; filename=\"pic.png\"") && reqs[1].body.contains("PNGDATA"));
        assert_eq!(reqs[2].path, "/v1.0/robot/groupMessages/send");
        assert_eq!((reqs[2].json()["msgKey"].as_str(), reqs[2].json()["msgParam"].as_str()), (Some("sampleImageMsg"), Some("{\"photoURL\":\"@MEDIA1\"}")));
        // URL media rides along as markdown.
        let u = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        t.send(&Outbound { media: vec![u], ..Outbound::text("cidG", "see") }).unwrap();
        let p: Value = serde_json::from_str(srv.requests()[3].json()["msgParam"].as_str().unwrap()).unwrap();
        assert_eq!(p["text"], "see\n\n![file](https://e.com/a.png)");
        // Download by code.
        assert_eq!(t.fetch_media(&Media { id: Some("DC1".into()), ..Default::default() }).unwrap(), b"BYTES");
        let dl = srv.requests()[4].json();
        assert_eq!((dl["downloadCode"].as_str(), dl["robotCode"].as_str()), (Some("DC1"), Some("APPKEY")));
        // Reactions.
        t.react("cidG", "msg9", "🤔Thinking", false).unwrap();
        t.react("cidG", "msg9", "🤔Thinking", true).unwrap();
        let r = srv.requests();
        assert_eq!((r[6].path.as_str(), r[7].path.as_str()), ("/v1.0/robot/emotion/reply", "/v1.0/robot/emotion/recall"));
        let b = r[6].json();
        assert_eq!((b["openMsgId"].as_str(), b["openConversationId"].as_str(), b["textEmotion"]["emotionId"].as_str()), (Some("msg9"), Some("cidG"), Some(EMOTION_ID)));
        assert_eq!(t.edit("cidG", "PQ", "x").unwrap_err().kind, K::Unsupported, "no edits without AI Cards");
        assert!(!t.caps().edit);
    }

    #[test]
    fn ai_cards_create_deliver_stream_and_finalize() {
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/oauth2/accessToken") { token_reply() } else { ok(json!({"success": true})) });
        let t = DingTalk::new("dt", "APPKEY", "APPSECRET", Opts { card_template_id: Some("tpl.schema".into()), card_idle_finalize: Duration::from_millis(50), ..opts(&srv.url) }).unwrap();
        assert!(t.caps().edit && t.caps().streaming == Streaming::Edit);
        seed(&t, "cidG", "", 0, true);
        // Intermediate send: card stays open.
        let id = t.send(&Outbound::text("cidG", "thinking…")).unwrap().ids[0].clone();
        let r = srv.requests();
        assert_eq!(r[1].path, "/v1.0/card/instances");
        assert_eq!((r[1].json()["cardTemplateId"].as_str(), r[1].json()["outTrackId"].as_str(), r[1].json()["callbackType"].as_str()), (Some("tpl.schema"), Some(id.as_str()), Some("STREAM")));
        assert_eq!(r[2].path, "/v1.0/card/instances/deliver");
        assert_eq!((r[2].json()["openSpaceId"].as_str(), r[2].json()["imGroupOpenDeliverModel"]["robotCode"].as_str()), (Some("dtv1.card//IM_GROUP.cidG"), Some("APPKEY")));
        assert_eq!((r[3].path.as_str(), r[3].method.as_str()), ("/v1.0/card/streaming", "PUT"));
        assert_eq!((r[3].json()["content"].as_str(), r[3].json()["isFinalize"].as_bool(), r[3].json()["isFull"].as_bool()), (Some("thinking…"), Some(false), Some(true)));
        // Edit streams into it; the idle sweep finalizes it.
        t.edit("cidG", &id, "partial answer").unwrap();
        assert_eq!(srv.requests()[4].json()["isFinalize"], false);
        std::thread::sleep(Duration::from_millis(80));
        t.sweep_cards();
        let f = srv.requests()[5].json();
        assert_eq!((f["outTrackId"].as_str(), f["content"].as_str(), f["isFinalize"].as_bool()), (Some(id.as_str()), Some("partial answer"), Some(true)));
        // Final reply (reply_to set): finalized at creation; DMs open in IM_ROBOT.<staff>.
        seed(&t, "cidDM", "", 0, false);
        t.edit("cidDM", "open1", "x").unwrap();
        t.send(&Outbound { reply_to: Some("m1".into()), ..Outbound::text("cidDM", "done") }).unwrap();
        let r = srv.requests();
        assert_eq!((r[7].json()["outTrackId"].as_str(), r[7].json()["isFinalize"].as_bool()), (Some("open1"), Some(true)), "open sibling closed by the next send");
        assert_eq!(r[9].json()["openSpaceId"], "dtv1.card//IM_ROBOT.staff42");
        assert_eq!(r[10].json()["isFinalize"], true);
        // Stop finalizes leftovers.
        t.edit("cidDM", "open2", "y").unwrap();
        t.stop();
        assert_eq!(srv.requests().last().unwrap().json()["outTrackId"], "open2");
        assert_eq!(srv.requests().last().unwrap().json()["isFinalize"], true);
    }

    #[test]
    fn card_failure_falls_back_to_webhook() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/oauth2/accessToken") {
                return token_reply();
            }
            if req.path.starts_with("/v1.0/card") {
                return (400, vec![], json!({"code": "param.invalid", "message": "bad template"}).to_string());
            }
            ok(json!({"errcode": 0}))
        });
        let t = DingTalk::new("dt", "APPKEY", "APPSECRET", Opts { card_template_id: Some("tpl".into()), ..opts(&srv.url) }).unwrap();
        seed(&t, "cidG", &format!("{}/robot/sendBySession?s=1", srv.url), 0, true);
        assert!(t.send(&Outbound::text("cidG", "hi")).unwrap().ids[0].starts_with("wh:"));
        assert!(srv.requests().last().unwrap().path.starts_with("/robot/sendBySession"));
    }

    #[test]
    fn error_mapping_rate_limits_retries_and_token_refresh() {
        // 429 with retry-after is honoured, then succeeds.
        let srv = FakeServer::start(|req, n| {
            if req.path.ends_with("/oauth2/accessToken") {
                return token_reply();
            }
            if n == 1 {
                return (429, vec![("Retry-After".into(), "1".into())], json!({"code": "Forbidden.AccessDenied.QpsLimitForApi", "message": "slow down"}).to_string());
            }
            ok(json!({"processQueryKey": "K"}))
        });
        let t = dt(&srv.url);
        let start = Instant::now();
        t.send(&Outbound::text("user:s1", "x")).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(950));
        assert_eq!(srv.requests().len(), 3);
        // Long retry-after surfaces; QPS-limit 403 is a rate limit, not auth.
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/oauth2/accessToken") { token_reply() } else { (403, vec![("Retry-After".into(), "3600".into())], json!({"code": "Forbidden.AccessDenied.QpsLimitForAppkeyAndApi"}).to_string()) });
        let e = dt(&srv.url).send(&Outbound::text("user:s1", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        // 5xx retried with backoff then Network.
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/oauth2/accessToken") { token_reply() } else { (502, vec![], "bad gateway".into()) });
        let e = dt(&srv.url).send(&Outbound::text("user:s1", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert_eq!(srv.requests().len(), 1 + 4, "1 + max_retries");
        // Robot removed / chat gone → NotFound; unreachable staff id → NotFound.
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/oauth2/accessToken") { token_reply() } else { (400, vec![], json!({"code": "resource.not.found", "message": "robot not in conversation"}).to_string()) });
        let e = dt(&srv.url).send(&Outbound::text("cidGone", "x")).unwrap_err();
        assert_eq!((e.kind, srv.requests().len()), (K::NotFound, 2));
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/oauth2/accessToken") { token_reply() } else { ok(json!({"processQueryKey": "K", "invalidStaffIdList": ["s1"]})) });
        assert_eq!(dt(&srv.url).send(&Outbound::text("user:s1", "x")).unwrap_err().kind, K::NotFound);
        // A rejected token is refreshed once; a bad app secret is Auth.
        let srv = FakeServer::start(|req, n| {
            if req.path.ends_with("/oauth2/accessToken") {
                return ok(json!({"accessToken": format!("TOK{n}"), "expireIn": 7200}));
            }
            if req.header("x-acs-dingtalk-access-token") == Some("TOK0") {
                return (401, vec![], json!({"code": "InvalidAuthentication", "message": "token expired"}).to_string());
            }
            ok(json!({"processQueryKey": "K"}))
        });
        dt(&srv.url).send(&Outbound::text("user:s1", "x")).unwrap();
        let p: Vec<String> = srv.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(p, ["/v1.0/oauth2/accessToken", "/v1.0/robot/oToMessages/batchSend", "/v1.0/oauth2/accessToken", "/v1.0/robot/oToMessages/batchSend"]);
        let srv = FakeServer::start(|_, _| (400, vec![], json!({"code": "invalidClientIdOrSecret", "message": "无效的appKey或appSecret"}).to_string()));
        let e = dt(&srv.url).send(&Outbound::text("user:s1", "x")).unwrap_err();
        assert!(e.kind == K::Auth && !e.message.contains("APPSECRET"), "{e}");
        // Upload failure never leaks the access token (it rides in the query string).
        let t = dt("http://127.0.0.1:1");
        *t.inner.token.lock().unwrap() = Some(("SECRETTOKEN".into(), Instant::now() + Duration::from_secs(60)));
        let f = temp_dir("dt").join("a.txt");
        std::fs::write(&f, b"x").unwrap();
        let e = t.send(&Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("user:s", "") }).unwrap_err();
        assert!(e.kind == K::Network && !e.message.contains("SECRETTOKEN"), "{e}");
    }

    #[test]
    fn build_validates_settings() {
        let d = temp_dir("dt");
        let secrets: crate::Secrets = Arc::new(|s: &str| s.replace("{{secret:DT}}", "sek"));
        let ctx = crate::config::Ctx { name: "ding", state_dir: &d, secrets: &secrets };
        let ok = json!({"client_id": "id", "client_secret": "{{secret:DT}}", "card_template_id": "t", "api_base": "http://x/"});
        let c = build(&ctx, ok.as_object().unwrap()).unwrap();
        assert_eq!(c.id(), "ding");
        assert!(c.caps().edit);
        assert!(build(&ctx, json!({"client_id": "id", "client_secret": "{{secret:NOPE}}"}).as_object().unwrap()).err().unwrap().contains("not set"));
        assert!(build(&ctx, json!({"client_id": "id", "client_secret": "s", "clientsecret": "x"}).as_object().unwrap()).err().unwrap().contains("clientsecret"));
        assert!(build(&ctx, json!({"client_id": "", "client_secret": "s"}).as_object().unwrap()).is_err());
    }
}
