//! Nextcloud Talk bots (ported from OpenClaw `extensions/nextcloud-talk`, MIT).
//!
//! Receive: Talk posts ActivityStreams JSON to our webhook, signed with
//! `X-Nextcloud-Talk-Signature = hex(HMAC-SHA256(secret, X-Nextcloud-Talk-Random + body))`.
//! Bad/missing signatures get 401 before parsing; a reused random is a replay and
//! is acknowledged without being delivered; `allowed_backends` pins
//! `X-Nextcloud-Talk-Backend`. `Create` notes (plain or Talk's rich
//! `{message, parameters}` JSON, mentions resolved), file-share `Activity`
//! events (attachment metadata) and `inReplyTo` quotes are parsed. With
//! `api_user`/`api_password` (an app password) the room kind is looked up
//! (`/ocs/v2.php/apps/spreed/api/v4/room/{token}`: one-to-one → direct) and
//! attachments are downloaded over WebDAV.
//!
//! Send: `POST /ocs/v2.php/apps/spreed/api/v1/bot/{token}/message` signed over the
//! message text (`replyTo`, `silent`, `referenceId`); reactions add/remove via
//! `/bot/{token}/reaction/{messageId}`. Local files (with API credentials) are
//! uploaded over WebDAV into `/Ark/ark-<rand>/` and shared into the room
//! (`files_sharing` share type 10 with `talkMetaData` caption/replyTo/silent).
//! Talk renders Markdown itself; there are no bot buttons, edits or typing.

use crate::http::{classify, Resp};
use crate::{chunk, sleep_cancellable, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use ark_net::crypto;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::sync::mpsc::Receiver;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_PATH: &str = "/nextcloud-talk-webhook";
/// Talk's chat message limit (characters).
pub const MAX_MESSAGE: usize = 32000;
const ROOM_TTL: Duration = Duration::from_secs(300);
const ROOM_ERR_TTL: Duration = Duration::from_secs(30);
const REPLAY_CAP: usize = 4096;
/// How long an uploaded file's name is remembered as our own share echo.
const UPLOAD_TTL: Duration = Duration::from_secs(900);

pub struct Config {
    pub id: String,
    pub base_url: String,
    pub secret: String,
    pub listen: String,
    pub path: String,
    /// Nextcloud user + app password for room lookups, WebDAV media and shares.
    pub api: Option<(String, String)>,
    /// The bot's display name: `@name` mentions and own-message detection.
    pub bot_name: String,
    /// Accepted `X-Nextcloud-Talk-Backend` values (empty = any).
    pub allowed_backends: Vec<String>,
    pub poll_timeout_secs: u64,
}

pub struct NextcloudTalk {
    id: String,
    base: String,
    secret: String,
    api: Option<(String, String)>,
    bot_name: String,
    agent: ureq::Agent,
    poll_timeout: u64,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    rx: Mutex<Receiver<Value>>,
    server: Mutex<Option<ark_net::httpd::Server>>,
    rooms: Mutex<HashMap<String, (Option<ChatType>, Instant)>>,
    /// File names we shared into a conversation (name → forget-at): Talk sends the
    /// resulting message back through our own webhook, authored by the API user.
    uploads: Mutex<HashMap<String, Instant>>,
    uid: Mutex<Option<String>>,
}

/// Seen webhook randoms (bounded) for replay rejection.
#[derive(Default)]
struct Replay {
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl Replay {
    /// False when `r` was already used.
    fn insert(&mut self, r: &str) -> bool {
        if !self.seen.insert(r.to_string()) {
            return false;
        }
        self.order.push_back(r.to_string());
        if self.order.len() > REPLAY_CAP {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

pub fn sign(secret: &str, random: &str, body: &[u8]) -> String {
    let mut data = random.as_bytes().to_vec();
    data.extend_from_slice(body);
    crypto::hex(&crypto::hmac_sha256(secret.as_bytes(), &data))
}

fn verify(secret: &str, random: &str, body: &[u8], sig: &str) -> bool {
    !secret.is_empty() && !random.is_empty() && crypto::ct_eq(sign(secret, random, body).as_bytes(), sig.trim().to_ascii_lowercase().as_bytes())
}

impl NextcloudTalk {
    pub fn start(c: Config) -> Result<Self, String> {
        if c.secret.trim().is_empty() {
            return Err(format!("channel {}: nextcloud-talk bot_secret is empty", c.id));
        }
        let base = c.base_url.trim().trim_end_matches('/').to_string();
        ark_net::Url::parse(&base).map_err(|e| format!("channel {}: base_url: {e}", c.id))?;
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        let tx = Mutex::new(tx);
        let secret = c.secret.trim().to_string();
        let want = secret.clone();
        let path = if c.path.starts_with('/') { c.path.clone() } else { format!("/{}", c.path) };
        let backends: Vec<String> = c.allowed_backends.iter().map(|b| b.trim().trim_end_matches('/').to_ascii_lowercase()).collect();
        let replay = Mutex::new(Replay::default());
        let handler: ark_net::httpd::Handler = std::sync::Arc::new(move |r: ark_net::httpd::Request| {
            use ark_net::httpd::Response;
            if r.path != path {
                return Response::text(404, "not found");
            }
            if r.method != "POST" {
                return Response::text(405, "method not allowed");
            }
            let (Some(sig), Some(random)) = (r.header("x-nextcloud-talk-signature"), r.header("x-nextcloud-talk-random")) else {
                return Response::text(401, "missing signature");
            };
            if !verify(&want, random, &r.body, sig) {
                return Response::text(401, "invalid signature");
            }
            if !backends.is_empty() {
                let b = r.header("x-nextcloud-talk-backend").unwrap_or("").trim().trim_end_matches('/').to_ascii_lowercase();
                if !backends.contains(&b) {
                    return Response::text(403, "backend not allowed");
                }
            }
            if !replay.lock().unwrap().insert(random) {
                // Already delivered: acknowledge so Talk does not retry, but drop it.
                return Response::text(200, "duplicate");
            }
            match serde_json::from_slice::<Value>(&r.body) {
                Ok(v) if v.is_object() => {
                    let _ = tx.lock().unwrap().send(v);
                    Response::text(200, "ok")
                }
                _ => Response::text(400, "bad json"),
            }
        });
        let server = ark_net::httpd::Server::bind(&c.listen, ark_net::httpd::Opts::default(), handler).map_err(|e| format!("channel {}: cannot listen on {}: {e}", c.id, c.listen))?;
        Ok(NextcloudTalk {
            id: c.id,
            base,
            secret,
            api: c.api.filter(|(u, p)| !u.trim().is_empty() && !p.is_empty()),
            bot_name: c.bot_name.trim().to_string(),
            agent: crate::http::agent(Duration::from_secs(60)),
            poll_timeout: c.poll_timeout_secs,
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
            rx: Mutex::new(rx),
            server: Mutex::new(Some(server)),
            rooms: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
            uid: Mutex::new(None),
        })
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.server.lock().unwrap().as_ref().map(|s| s.local_addr())
    }

    /// One HTTP request with any method (WebDAV MKCOL/PROPFIND, DELETE with body).
    fn raw(&self, method: &str, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<Resp, ChannelError> {
        let m = ureq::http::Method::from_bytes(method.as_bytes()).map_err(|_| ChannelError::new(K::Fatal, format!("bad method {method}")))?;
        let mut b = ureq::http::Request::builder().method(m).uri(url);
        for (k, v) in headers {
            b = b.header(*k, v.as_str());
        }
        let req = b.body(body).map_err(|e| ChannelError::new(K::Fatal, format!("bad request: {e}")))?;
        let req = self.agent.configure_request(req).allow_non_standard_methods(true).build();
        let mut r = self.agent.run(req).map_err(|e| ChannelError::new(K::Network, format!("{method} request failed: {e}")))?;
        let status = r.status().as_u16();
        let mut resp = Resp::new(status, "");
        resp.retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<f64>().ok()).map(|s| Duration::from_secs_f64(s.max(0.0)));
        resp.headers = r.headers().iter().filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string()))).collect();
        let mut raw = Vec::new();
        r.body_mut().with_config().limit(u64::MAX).reader().take(16 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("reading response: {e}")))?;
        resp.body = String::from_utf8_lossy(&raw).into_owned();
        Ok(resp)
    }

    fn basic(&self) -> Result<String, ChannelError> {
        let (u, p) = self.api.as_ref().ok_or_else(|| ChannelError::new(K::Unsupported, "nextcloud-talk: this needs api_user/api_password"))?;
        Ok(format!("Basic {}", crypto::b64(format!("{u}:{p}").as_bytes())))
    }

    /// OCS / WebDAV call as the API user.
    fn api_call(&self, method: &str, path: &str, extra: &[(&str, String)], body: Vec<u8>) -> Result<Resp, ChannelError> {
        let mut h = vec![("authorization", self.basic()?), ("ocs-apirequest", "true".to_string()), ("accept", "application/json".to_string())];
        h.extend(extra.iter().cloned());
        self.raw(method, &format!("{}{path}", self.base), &h, body)
    }

    fn api_json(&self, method: &str, path: &str, extra: &[(&str, String)], body: Vec<u8>) -> Result<Value, ChannelError> {
        let r = self.api_call(method, path, extra, body)?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, &format!("nextcloud {method}"), &r.body));
        }
        serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, format!("nextcloud {method}: bad JSON")))
    }

    /// Signed bot API call, retried on 5xx / short rate limits.
    fn bot(&self, method: &str, path: &str, payload: &Value, signed: &str) -> Result<Value, ChannelError> {
        let url = format!("{}/ocs/v2.php/apps/spreed/api/v1/bot/{path}", self.base);
        let body = serde_json::to_vec(payload).expect("json");
        let mut attempt = 0;
        loop {
            let random = crypto::hex(&crypto::random_bytes(32));
            let sig = sign(&self.secret, &random, signed.as_bytes());
            let h = [("content-type", "application/json".to_string()), ("accept", "application/json".to_string()), ("ocs-apirequest", "true".to_string()), ("x-nextcloud-talk-bot-random", random), ("x-nextcloud-talk-bot-signature", sig)];
            let err = match self.raw(method, &url, &h, body.clone()) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null)),
                Ok(r) => bot_error(r.status, r.retry_after, &r.body),
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            if !sleep_cancellable(wait, &Cancel::new()) {
                return Err(err);
            }
            attempt += 1;
        }
    }

    /// Room kind from the API (cached); `None` without credentials or on lookup failure.
    fn room_kind(&self, token: &str) -> Option<ChatType> {
        self.api.as_ref()?;
        if let Some((k, at)) = self.rooms.lock().unwrap().get(token) {
            if Instant::now() < *at {
                return *k;
            }
        }
        let r = self.api_json("GET", &format!("/ocs/v2.php/apps/spreed/api/v4/room/{}", ark_net::urlencode(token)), &[], vec![]);
        let kind = r.ok().and_then(|v| v["ocs"]["data"]["type"].as_i64().or_else(|| v["ocs"]["data"]["type"].as_str().and_then(|s| s.parse().ok()))).map(|t| if matches!(t, 1 | 5 | 6) { ChatType::Direct } else { ChatType::Group });
        let ttl = if kind.is_some() { ROOM_TTL } else { ROOM_ERR_TTL };
        self.rooms.lock().unwrap().insert(token.to_string(), (kind, Instant::now() + ttl));
        kind
    }

    fn user_id(&self) -> Result<String, ChannelError> {
        if let Some(u) = self.uid.lock().unwrap().clone() {
            return Ok(u);
        }
        let v = self.api_json("GET", "/ocs/v1.php/cloud/user?format=json", &[], vec![])?;
        let id = v["ocs"]["data"]["id"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "nextcloud cloud/user returned no id"))?.to_string();
        *self.uid.lock().unwrap() = Some(id.clone());
        Ok(id)
    }

    fn dav_root(&self, uid: &str) -> String {
        format!("/remote.php/dav/files/{}", ark_net::urlencode(uid))
    }

    /// WebDAV upload into a private folder, then share it into the room with a caption.
    fn upload_share(&self, room: &str, m: &Media, caption: &str, out: &Outbound) -> Result<String, ChannelError> {
        let path = m.path.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "attachment without path"))?;
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let uid = self.user_id()?;
        let root = self.dav_root(&uid);
        let r = self.api_call("MKCOL", &format!("{root}/Ark"), &[], vec![])?;
        if r.status != 201 && r.status != 405 {
            return Err(classify(r.status, r.retry_after, "nextcloud MKCOL", &r.body));
        }
        let folder = format!("ark-{}", crypto::hex(&crypto::random_bytes(8)));
        let r = self.api_call("MKCOL", &format!("{root}/Ark/{folder}"), &[], vec![])?;
        if r.status != 201 {
            return Err(classify(r.status, r.retry_after, "nextcloud MKCOL", &r.body));
        }
        let name = if m.name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "attachment.bin".into()) } else { m.name.clone() };
        let name: String = name.chars().filter(|c| !matches!(c, '/' | '\\' | '\0')).take(200).collect();
        let mime = if m.mime.is_empty() { "application/octet-stream".to_string() } else { m.mime.clone() };
        let r = self.api_call("PUT", &format!("{root}/Ark/{folder}/{}", ark_net::urlencode(&name)), &[("if-none-match", "*".into()), ("content-type", mime.clone())], data)?;
        if r.status != 201 && r.status != 204 {
            return Err(classify(r.status, r.retry_after, "nextcloud upload", &r.body));
        }
        let mut meta = json!({ "caption": caption });
        if m.kind == MediaKind::Voice && (mime == "audio/mpeg" || mime == "audio/wav") {
            meta["messageType"] = json!("voice-message");
        }
        if out.silent {
            meta["silent"] = json!(true);
        }
        if let Some(r) = out.reply_to.as_deref().and_then(|r| r.parse::<i64>().ok()) {
            meta["replyTo"] = json!(r);
        }
        let file_path = format!("/Ark/{folder}/{name}");
        let meta_s = meta.to_string();
        let form = ark_net::form_encode(&[("path", &file_path), ("shareType", "10"), ("shareWith", room), ("permissions", "1"), ("talkMetaData", &meta_s)]);
        let v = self.api_json("POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json", &[("content-type", "application/x-www-form-urlencoded".into())], form.into_bytes())?;
        let mut up = self.uploads.lock().unwrap();
        up.retain(|_, at| Instant::now() < *at);
        up.insert(name, Instant::now() + UPLOAD_TTL);
        Ok(id_str(&v["ocs"]["data"]["id"]).unwrap_or_default())
    }

    fn post_message(&self, room: &str, text: &str, reply_to: Option<i64>, silent: bool) -> Result<Option<String>, ChannelError> {
        let mut body = json!({ "message": text, "referenceId": crypto::hex(&crypto::sha256(&crypto::random_bytes(32))) });
        if let Some(r) = reply_to {
            body["replyTo"] = json!(r);
        }
        if silent {
            body["silent"] = json!(true);
        }
        let v = self.bot("POST", &format!("{}/message", ark_net::urlencode(room)), &body, text)?;
        Ok(id_str(&v["ocs"]["data"]["id"]))
    }

    /// Our own file share echoing back through the webhook: authored by the API user
    /// and carrying only files we uploaded (Talk copies them to `Talk/<name>` and the
    /// share link is `/s/<token>`, so the name is what identifies them).
    fn is_own_share(&self, m: &Inbound) -> bool {
        let Some((u, _)) = self.api.as_ref() else { return false };
        if m.media.is_empty() || !m.sender.eq_ignore_ascii_case(u) {
            return false;
        }
        let now = Instant::now();
        let up = self.uploads.lock().unwrap();
        m.media.iter().all(|x| up.get(&x.name).is_some_and(|at| now < *at) || x.name.starts_with("ark-") || x.url.as_deref().is_some_and(|u| u.contains("/Ark/")))
    }

    fn inbound_of(&self, v: &Value) -> Option<Inbound> {
        let mut m = parse(&self.id, v, &self.bot_name)?;
        if self.is_own_share(&m) {
            return None;
        }
        if let Some(k) = self.room_kind(&m.chat) {
            m.chat_type = k;
        }
        Some(m)
    }
}

/// Bot API status → error kind. 403 = the bot is not (or no longer) in this room.
fn bot_error(status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    match status {
        401 => ChannelError::new(K::Auth, "nextcloud-talk rejected the bot signature (check bot_secret and that the bot has the `response` feature)"),
        403 | 404 => ChannelError::new(K::NotFound, format!("nextcloud-talk: room not found or bot not enabled there (HTTP {status})")),
        _ => classify(status, retry_after, "nextcloud-talk bot", body),
    }
}

fn id_str(v: &Value) -> Option<String> {
    v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().filter(|s| !s.is_empty()).map(str::to_string))
}

fn media_kind(mime: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" if mime == "image/gif" => MediaKind::Animation,
        "image" => MediaKind::Image,
        "audio" => MediaKind::Audio,
        "video" => MediaKind::Video,
        _ => MediaKind::Document,
    }
}

/// Replace `{key}` placeholders: users/guests/bots → `@name`, other objects → their name.
fn render_rich(message: &str, params: &serde_json::Map<String, Value>) -> String {
    let mut out = String::new();
    let mut rest = message;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('}') {
            Some(j) if !tail[..j].contains('{') => {
                let key = &tail[..j];
                match params.get(key) {
                    Some(p) if p["name"].is_string() => {
                        let name = p["name"].as_str().unwrap_or("");
                        let person = matches!(p["type"].as_str(), Some("user" | "guest" | "bot" | "app" | "call" | "user-group" | "email"));
                        if key == "file" && p["type"] == "file" {
                            // A bare "{file}" caption is no text at all.
                        } else if person {
                            out.push('@');
                            out.push_str(name);
                        } else {
                            out.push_str(name);
                        }
                    }
                    _ => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &tail[j + 1..];
            }
            _ => {
                out.push('{');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out.trim().to_string()
}

/// Talk's `content` is either plain text or `{"message": …, "parameters": {…}}`.
fn decode_content(content: &str) -> (String, serde_json::Map<String, Value>) {
    if content.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let Some(msg) = v["message"].as_str() {
                let params = v["parameters"].as_object().cloned().unwrap_or_default();
                return (render_rich(msg, &params), params);
            }
        }
    }
    (content.to_string(), Default::default())
}

fn strip_actor(id: &str) -> String {
    id.strip_prefix("users/").unwrap_or(id).to_string()
}

fn mentions(text: &str, bot: &str) -> bool {
    if bot.is_empty() {
        return false;
    }
    let t = text.to_lowercase();
    let needle = format!("@{}", bot.to_lowercase());
    t.match_indices(&needle).any(|(i, _)| t[i + needle.len()..].chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_' && c != '-'))
}

/// One webhook envelope → Inbound (room kind defaults to group; refined by lookup).
fn parse(channel: &str, v: &Value, bot: &str) -> Option<Inbound> {
    let kind = v["type"].as_str()?;
    let obj = &v["object"];
    if obj.get("type").is_some_and(|t| t != "Note") {
        return None;
    }
    let actor = &v["actor"];
    let (text, params) = match kind {
        "Create" => {
            let content = obj["content"].as_str().filter(|s| !s.is_empty()).or_else(|| obj["name"].as_str()).unwrap_or("");
            decode_content(content)
        }
        "Activity" => {
            let (t, p) = decode_content(obj["content"].as_str().unwrap_or(""));
            if !p.contains_key("file") || !matches!(obj["name"].as_str(), Some("file_shared" | "message" | "")) {
                return None;
            }
            (t, p)
        }
        _ => return None,
    };
    let room = v["target"]["id"].as_str().filter(|s| !s.is_empty())?;
    let msg_id = id_str(&obj["id"])?;
    let is_bot = actor["type"] == "Application";
    if is_bot && !bot.is_empty() && actor["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(bot)) {
        return None;
    }
    let mut media = Vec::new();
    if let Some(f) = params.get("file").filter(|f| f["type"] == "file") {
        let mime = f["mimetype"].as_str().unwrap_or("").to_string();
        let file_id = id_str(&f["id"]).unwrap_or_default();
        media.push(Media {
            kind: if f["messageType"] == "voice-message" { MediaKind::Voice } else { media_kind(&mime) },
            url: f["link"].as_str().map(str::to_string),
            name: f["name"].as_str().unwrap_or("").to_string(),
            size: f["size"].as_u64().or_else(|| f["size"].as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(0),
            mime,
            // room:message:file lets fetch_media find the file in the chat history.
            id: Some(format!("{room}:{msg_id}:{file_id}")),
            ..Default::default()
        });
    }
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let q = &obj["inReplyTo"];
    let reply = (q["type"] == "Note" && q["object"]["type"] == "Note").then(|| {
        let id = id_str(&q["object"]["id"])?;
        let qa = &q["actor"];
        Some(ReplyRef {
            id,
            text: decode_content(q["object"]["content"].as_str().unwrap_or("")).0,
            author: qa["name"].as_str().unwrap_or("").to_string(),
            is_own: qa["type"] == "Application" && (bot.is_empty() || qa["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(bot))),
        })
    });
    Some(Inbound {
        channel: channel.to_string(),
        chat: room.to_string(),
        chat_type: ChatType::Group,
        chat_name: v["target"]["name"].as_str().unwrap_or("").to_string(),
        sender: strip_actor(actor["id"].as_str().unwrap_or("")),
        sender_name: actor["name"].as_str().unwrap_or("").to_string(),
        is_bot,
        mentioned: mentions(&text, bot),
        text,
        message_id: msg_id,
        ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        media,
        reply: reply.flatten(),
        ..Default::default()
    })
}

/// Buttons → numbered text options (Talk bots have no interactive buttons).
fn with_options(text: &str, rows: &[Vec<crate::Button>]) -> String {
    let buttons: Vec<&crate::Button> = rows.iter().flatten().collect();
    if buttons.is_empty() {
        return text.to_string();
    }
    let mut s = text.trim_end().to_string();
    s.push('\n');
    for (i, b) in buttons.iter().enumerate() {
        match &b.url {
            Some(u) => s.push_str(&format!("\n- [{}]({u})", b.label)),
            None => s.push_str(&format!("\n{}. {}", i + 1, b.label)),
        }
    }
    s
}

impl Channel for NextcloudTalk {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: self.api.is_some(),
            reply: true,
            threads: false,
            reactions: 8,
            edit: false,
            delete: false,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let got: Vec<Value> = {
            let rx = self.rx.lock().unwrap();
            let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
            let mut got = Vec::new();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
            got
        };
        Ok(got.iter().filter_map(|v| self.inbound_of(v)).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let room = out.chat.trim().trim_start_matches("nextcloud-talk:").trim_start_matches("room:");
        if room.is_empty() {
            return Err(ChannelError::new(K::Fatal, "nextcloud-talk: room token is required"));
        }
        let mut text = with_options(&out.text, &out.buttons);
        let mut sent = Sent::default();
        let uploads: Vec<&Media> = out.media.iter().filter(|m| m.path.is_some()).collect();
        // By-reference media are linked in the text.
        for m in out.media.iter().filter(|m| m.path.is_none()) {
            if let Some(u) = &m.url {
                text.push_str(&format!("\n{u}"));
            }
        }
        let caption_on_file = uploads.len() == 1 && chunk::len(&text, LenUnit::Chars) <= 1000 && !text.trim().is_empty();
        for (i, m) in uploads.iter().enumerate() {
            let cap = if caption_on_file && i == 0 { text.trim() } else { m.caption.as_deref().unwrap_or("") };
            let id = self.upload_share(room, m, cap, out)?;
            if !id.is_empty() {
                sent.ids.push(format!("share:{id}"));
            }
        }
        if caption_on_file {
            return Ok(sent);
        }
        let reply = out.reply_to.as_deref().and_then(|r| r.parse::<i64>().ok());
        for (i, piece) in chunk::split(&text, MAX_MESSAGE, LenUnit::Chars).into_iter().enumerate() {
            let first = i == 0 && uploads.is_empty();
            sent.ids.extend(self.post_message(room, &piece, reply.filter(|_| first), out.silent)?);
        }
        Ok(sent)
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let path = format!("{}/reaction/{}", ark_net::urlencode(chat), ark_net::urlencode(message_id));
        self.bot(if remove { "DELETE" } else { "POST" }, &path, &json!({ "reaction": emoji }), emoji).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        const MAX: u64 = 50 * 1024 * 1024;
        let parts: Vec<&str> = m.id.as_deref().unwrap_or("").splitn(3, ':').collect();
        if self.api.is_some() && parts.len() == 3 && !parts[1].is_empty() {
            let (room, msg) = (parts[0], parts[1]);
            // The file path as the API user sees it comes from the chat history.
            let v = self.api_json("GET", &format!("/ocs/v2.php/apps/spreed/api/v1/chat/{}/{}/context?limit=1", ark_net::urlencode(room), ark_net::urlencode(msg)), &[], vec![])?;
            let path = v["ocs"]["data"].as_array().into_iter().flatten().find(|x| id_str(&x["id"]).as_deref() == Some(msg)).and_then(|x| x["messageParameters"]["file"]["path"].as_str().map(str::to_string));
            if let Some(p) = path {
                let uid = self.user_id()?;
                let enc: Vec<String> = p.trim_start_matches('/').split('/').map(ark_net::urlencode).collect();
                let r = self.basic()?;
                return crate::http::get_bytes(&format!("{}{}/{}", self.base, self.dav_root(&uid), enc.join("/")), &[("authorization", &r)], MAX);
            }
        }
        match &m.url {
            Some(u) => crate::http::get_bytes(&format!("{}/download", u.trim_end_matches('/')), &[], MAX),
            None => Err(crate::unsupported("media download")),
        }
    }

    fn stop(&self) {
        self.server.lock().unwrap().take();
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    base_url: String,
    bot_secret: String,
    /// Local address the Talk bot webhook URL reaches.
    listen: String,
    #[serde(default)]
    webhook_path: Option<String>,
    #[serde(default)]
    api_user: Option<String>,
    #[serde(default)]
    api_password: Option<String>,
    #[serde(default)]
    bot_name: Option<String>,
    #[serde(default)]
    allowed_backends: Vec<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<std::sync::Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let secret = ctx.secret("bot_secret", &st.bot_secret)?;
    let pw = ctx.opt_secret("api_password", &st.api_password)?;
    let api = match (st.api_user, pw) {
        (Some(u), Some(p)) => Some((u, p)),
        (None, None) => None,
        _ => return Err(format!("channel {}: api_user and api_password go together", ctx.name)),
    };
    let t = NextcloudTalk::start(Config {
        id: ctx.name.to_string(),
        base_url: st.base_url,
        secret,
        listen: st.listen,
        path: st.webhook_path.unwrap_or_else(|| DEFAULT_PATH.into()),
        api,
        bot_name: st.bot_name.unwrap_or_default(),
        allowed_backends: st.allowed_backends,
        poll_timeout_secs: st.poll_timeout_secs,
    })?;
    Ok(std::sync::Arc::new(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    const SECRET: &str = "nextcloud-secret-value";

    fn talk(base: &str, api: bool) -> NextcloudTalk {
        let mut t = NextcloudTalk::start(Config {
            id: "nc".into(),
            base_url: base.into(),
            secret: SECRET.into(),
            listen: "127.0.0.1:0".into(),
            path: DEFAULT_PATH.into(),
            api: api.then(|| ("arkapi".to_string(), "app-pass".to_string())),
            bot_name: "Ark".into(),
            allowed_backends: vec!["https://nextcloud.example".into()],
            poll_timeout_secs: 1,
        })
        .unwrap();
        t.retry_base = Duration::from_millis(5);
        t
    }

    fn post(t: &NextcloudTalk, body: &str, headers: &[(&str, &str)]) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{}{DEFAULT_PATH}", t.local_addr().unwrap()));
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.send(body.as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn signed(t: &NextcloudTalk, body: &str) -> u16 {
        let random = crypto::hex(&crypto::random_bytes(32));
        let sig = sign(SECRET, &random, body.as_bytes());
        post(t, body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &sig), ("x-nextcloud-talk-backend", "https://nextcloud.example/")])
    }

    fn create(id: &str, content: &str) -> String {
        json!({"type": "Create", "actor": {"type": "Person", "id": "users/alice", "name": "Alice"}, "object": {"type": "Note", "id": id, "name": "message", "content": content, "mediaType": "text/markdown"}, "target": {"type": "Collection", "id": "room1", "name": "Room 1"}}).to_string()
    }

    #[test]
    fn webhook_signature_good_bad_missing_replay_and_backend() {
        let t = talk("http://127.0.0.1:1", false);
        let body = create("1", "hello");
        let random = "a".repeat(64);
        let sig = sign(SECRET, &random, body.as_bytes());
        let be = ("x-nextcloud-talk-backend", "https://nextcloud.example");
        assert_eq!(post(&t, &body, &[]), 401, "missing headers");
        assert_eq!(post(&t, &body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &"0".repeat(64)), be]), 401, "bad signature");
        let other = sign("wrong-secret", &random, body.as_bytes());
        assert_eq!(post(&t, &body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &other), be]), 401);
        assert_eq!(post(&t, &body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &sig), ("x-nextcloud-talk-backend", "https://evil.example")]), 403, "backend pinned");
        assert_eq!(post(&t, &body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &sig.to_uppercase()), be]), 200, "hex case-insensitive");
        assert_eq!(post(&t, &body, &[("x-nextcloud-talk-random", &random), ("x-nextcloud-talk-signature", &sig), be]), 200, "replay acknowledged…");
        let rs = "b".repeat(64);
        assert_eq!(post(&t, "not json", &[("x-nextcloud-talk-random", &rs), ("x-nextcloud-talk-signature", &sign(SECRET, &rs, b"not json")), be]), 400);
        let got = t.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1, "…but delivered once");
        assert_eq!((got[0].text.as_str(), got[0].chat.as_str(), got[0].sender.as_str(), got[0].sender_name.as_str()), ("hello", "room1", "alice", "Alice"));
        assert_eq!(got[0].chat_type, ChatType::Group, "no API creds: rooms are groups");
    }

    #[test]
    fn parses_rich_mentions_files_quotes_and_drops_own_and_system_events() {
        let t = talk("http://127.0.0.1:1", false);
        let rich = json!({"message": "hi {mention-user1} and {mention-call1}", "parameters": {"mention-user1": {"type": "user", "id": "ark", "name": "Ark"}, "mention-call1": {"type": "call", "id": "room1", "name": "Room"}}}).to_string();
        assert_eq!(signed(&t, &create("10", &rich)), 200);
        let file = json!({"type": "Activity", "actor": {"type": "Person", "id": "users/alice", "name": "Alice"}, "object": {"type": "Note", "id": "4242", "name": "message", "content": json!({"message": "{file}", "parameters": {"actor": {"type": "user", "id": "alice", "name": "Alice"}, "file": {"type": "file", "id": "9001", "name": "receipt.pdf", "size": "24576", "path": "receipt.pdf", "link": "https://nextcloud.example/s/tok", "mimetype": "application/pdf"}}}).to_string(), "mediaType": "text/markdown"}, "target": {"type": "Collection", "id": "room1", "name": "Receipts"}});
        assert_eq!(signed(&t, &file.to_string()), 200);
        let quote = json!({"type": "Create", "actor": {"type": "Person", "id": "users/bob", "name": "Bob"}, "object": {"type": "Note", "id": "11", "content": "yes", "inReplyTo": {"type": "Note", "actor": {"type": "Application", "id": "bots/x", "name": "Ark"}, "object": {"type": "Note", "id": "9", "content": "shall I?"}}}, "target": {"id": "room1", "name": "Room 1"}});
        assert_eq!(signed(&t, &quote.to_string()), 200);
        let own = json!({"type": "Create", "actor": {"type": "Application", "id": "bots/x", "name": "Ark"}, "object": {"type": "Note", "id": "12", "content": "my reply"}, "target": {"id": "room1"}});
        assert_eq!(signed(&t, &own.to_string()), 200);
        let other_bot = json!({"type": "Create", "actor": {"type": "Application", "id": "bots/y", "name": "Other"}, "object": {"type": "Note", "id": "13", "content": "beep"}, "target": {"id": "room1"}});
        assert_eq!(signed(&t, &other_bot.to_string()), 200);
        let join = json!({"type": "Join", "actor": {"type": "Application", "id": "bots/x"}, "object": {"type": "Note", "id": "14"}, "target": {"id": "room1"}});
        assert_eq!(signed(&t, &join.to_string()), 200);
        let system = json!({"type": "Activity", "actor": {"id": "users/alice"}, "object": {"type": "Note", "id": "15", "name": "call_started", "content": "{\"message\":\"call\",\"parameters\":{}}"}, "target": {"id": "room1"}});
        assert_eq!(signed(&t, &system.to_string()), 200);
        let mut got = Vec::new();
        while got.len() < 4 {
            let batch = t.poll(&Cancel::new()).unwrap();
            assert!(!batch.is_empty());
            got.extend(batch);
        }
        assert_eq!(got.len(), 4, "own message, join and system activity dropped");
        assert_eq!(got[0].text, "hi @Ark and @Room");
        assert!(got[0].mentioned && got[0].message_id == "10");
        assert!(got[1].text.is_empty() && !got[1].mentioned);
        let m = &got[1].media[0];
        assert_eq!((m.kind, m.name.as_str(), m.size, m.mime.as_str(), m.id.as_deref()), (MediaKind::Document, "receipt.pdf", 24576, "application/pdf", Some("room1:4242:9001")));
        assert_eq!(got[1].chat_name, "Receipts");
        let r = got[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "9" && r.text == "shall I?" && got[2].addressed());
        assert!(!got[2].mentioned);
        assert!(got[3].is_bot && got[3].text == "beep");
        assert!(!mentions("mail @arkbot", "Ark") && mentions("hey @ark!", "Ark"));
    }

    #[test]
    fn room_kind_lookup_with_api_credentials_is_cached() {
        let srv = FakeServer::start(|req, _| {
            assert_eq!(req.header("authorization"), Some(format!("Basic {}", crypto::b64(b"arkapi:app-pass")).as_str()));
            assert_eq!(req.header("ocs-apirequest"), Some("true"));
            (200, vec![], json!({"ocs": {"data": {"type": 1}}}).to_string())
        });
        let t = talk(&srv.url, true);
        assert_eq!(signed(&t, &create("1", "dm")), 200);
        assert_eq!(signed(&t, &create("2", "dm2")), 200);
        let mut got = t.poll(&Cancel::new()).unwrap();
        if got.len() < 2 {
            got.extend(t.poll(&Cancel::new()).unwrap());
        }
        assert!(got.iter().all(|m| m.chat_type == ChatType::Direct));
        assert_eq!(srv.requests().len(), 1, "cached");
        assert_eq!(srv.requests()[0].path, "/ocs/v2.php/apps/spreed/api/v4/room/room1");
        assert!(t.caps().media);
    }

    #[test]
    fn send_signs_message_with_reply_silent_buttons_and_chunks() {
        let srv = FakeServer::start(|req, n| {
            let random = req.header("x-nextcloud-talk-bot-random").unwrap().to_string();
            let msg = req.json()["message"].as_str().or(req.json()["reaction"].as_str()).unwrap().to_string();
            assert_eq!(req.header("x-nextcloud-talk-bot-signature").unwrap(), sign(SECRET, &random, msg.as_bytes()), "signed over the message value");
            assert_eq!(req.header("ocs-apirequest"), Some("true"));
            (201, vec![], json!({"ocs": {"data": {"id": 100 + n}}}).to_string())
        });
        let t = talk(&srv.url, false);
        let out = Outbound {
            reply_to: Some("42".into()),
            silent: true,
            buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:1:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("room1", "**pick**")
        };
        assert_eq!(t.send(&out).unwrap().ids, vec!["100"]);
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/ocs/v2.php/apps/spreed/api/v1/bot/room1/message");
        let b = r.json();
        assert_eq!(b["message"], "**pick**\n\n1. 允許\n- [docs](https://e.com)");
        assert_eq!((b["replyTo"].as_i64(), b["silent"].as_bool(), b["referenceId"].as_str().map(str::len)), (Some(42), Some(true), Some(64)));
        let long = format!("{}\n\n{}", "a".repeat(30000), "b".repeat(30000));
        assert_eq!(t.send(&Outbound { reply_to: Some("7".into()), ..Outbound::text("room1", &long) }).unwrap().ids.len(), 2);
        assert_eq!(srv.requests()[1].json()["replyTo"], 7);
        assert!(srv.requests()[2].json().get("replyTo").is_none(), "reply only on the first piece");
        t.react("room1", "55", "👍", false).unwrap();
        t.react("room1", "55", "👍", true).unwrap();
        let reqs = srv.requests();
        assert_eq!((reqs[3].method.as_str(), reqs[3].path.as_str()), ("POST", "/ocs/v2.php/apps/spreed/api/v1/bot/room1/reaction/55"));
        assert_eq!((reqs[4].method.as_str(), reqs[4].json()["reaction"].as_str()), ("DELETE", Some("👍")));
        assert!(t.edit("room1", "1", "x").is_err() && !t.caps().media);
        assert!(t.send(&Outbound::text(" ", "x")).is_err());
    }

    #[test]
    fn local_media_upload_over_webdav_and_share_into_room() {
        let srv = FakeServer::start(|req, _| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/ocs/v1.php/cloud/user?format=json") => (200, vec![], json!({"ocs": {"data": {"id": "arkapi"}}}).to_string()),
            ("MKCOL", "/remote.php/dav/files/arkapi/Ark") => (405, vec![], String::new()),
            ("MKCOL", _) => (201, vec![], String::new()),
            ("PUT", _) => (201, vec![], String::new()),
            ("POST", p) if p.starts_with("/ocs/v2.php/apps/files_sharing") => (200, vec![], json!({"ocs": {"data": {"id": 77}}}).to_string()),
            _ => (500, vec![], String::new()),
        });
        let t = talk(&srv.url, true);
        let f = temp_dir("nc").join("report.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let m = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() };
        let s = t.send(&Outbound { media: vec![m], reply_to: Some("9".into()), silent: true, ..Outbound::text("room1", "see attached") }).unwrap();
        assert_eq!(s.ids, vec!["share:77"]);
        let reqs = srv.requests();
        let seq: Vec<&str> = reqs.iter().map(|r| r.method.as_str()).collect();
        assert_eq!(seq, ["GET", "MKCOL", "MKCOL", "PUT", "POST"]);
        assert!(reqs[2].path.starts_with("/remote.php/dav/files/arkapi/Ark/ark-"));
        assert!(reqs[3].path.ends_with("/report.pdf") && reqs[3].body == "%PDF-1" && reqs[3].header("if-none-match") == Some("*"));
        let form = ark_net::parse_query(&reqs[4].body);
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!((get("shareType").as_str(), get("shareWith").as_str()), ("10", "room1"));
        assert!(get("path").starts_with("/Ark/ark-") && get("path").ends_with("/report.pdf"));
        let meta: Value = serde_json::from_str(&get("talkMetaData")).unwrap();
        assert_eq!(meta, json!({"caption": "see attached", "replyTo": 9, "silent": true}));
        let no_api = talk(&srv.url, false);
        let m = Media { path: Some(f.display().to_string()), ..Default::default() };
        assert_eq!(no_api.send(&Outbound { media: vec![m], ..Outbound::text("room1", "x") }).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn fetch_media_via_chat_context_and_webdav() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/ocs/v2.php/apps/spreed/api/v1/chat/room1/4242/context?limit=1" => (200, vec![], json!({"ocs": {"data": [{"id": 4241}, {"id": 4242, "messageParameters": {"file": {"path": "Talk/receipt 1.pdf"}}}]}}).to_string()),
            "/ocs/v1.php/cloud/user?format=json" => (200, vec![], json!({"ocs": {"data": {"id": "arkapi"}}}).to_string()),
            "/remote.php/dav/files/arkapi/Talk/receipt%201.pdf" => (200, vec![], "PDFBYTES".into()),
            "/s/tok/download" => (200, vec![], "PUBLIC".into()),
            _ => (404, vec![], String::new()),
        });
        let t = talk(&srv.url, true);
        let m = Media { id: Some("room1:4242:9001".into()), url: Some(format!("{}/s/tok", srv.url)), ..Default::default() };
        assert_eq!(t.fetch_media(&m).unwrap(), b"PDFBYTES");
        assert!(srv.requests().last().unwrap().header("authorization").unwrap().starts_with("Basic "));
        assert_eq!(talk(&srv.url, false).fetch_media(&m).unwrap(), b"PUBLIC", "public share fallback");
    }

    /// A file we shared comes back through the webhook authored by the API user.
    /// Talk copies it to `Talk/<name>` and the link is `/s/<token>`, so only the
    /// uploaded name (remembered for a while) identifies it as our own share.
    #[test]
    fn own_file_share_echo_from_the_api_user_is_dropped() {
        let t = talk("http://127.0.0.1:1", true);
        let note = |sender: &str, name: &str| {
            json!({"type": "Activity", "actor": {"type": "Person", "id": sender, "name": "Ark API"}, "object": {"type": "Note", "id": "77", "name": "message", "content": json!({"message": "{file}", "parameters": {"file": {"type": "file", "id": "9", "name": name, "size": "8", "link": "https://cloud.example/s/tok", "mimetype": "text/plain"}}}).to_string()}, "target": {"type": "Collection", "id": "room1", "name": "Room"}})
        };
        // Not ours: a file the API user shared from somewhere else.
        assert!(t.inbound_of(&note("users/arkapi", "notes.txt")).is_some());
        t.uploads.lock().unwrap().insert("notes.txt".into(), Instant::now() + UPLOAD_TTL);
        assert!(t.inbound_of(&note("users/arkapi", "notes.txt")).is_none(), "our own share echo");
        // Only the API user's messages are ours; a peer sharing the same name is not.
        assert!(t.inbound_of(&note("users/alice", "notes.txt")).is_some());
        // And the memory expires.
        t.uploads.lock().unwrap().insert("notes.txt".into(), Instant::now() - Duration::from_secs(1));
        assert!(t.inbound_of(&note("users/arkapi", "notes.txt")).is_some(), "expired entries no longer match");
        // Media-less messages from the API user are delivered (a person, not an echo).
        let text = json!({"type": "Create", "actor": {"type": "Person", "id": "users/arkapi", "name": "Ark API"}, "object": {"type": "Note", "id": "78", "content": "hi"}, "target": {"id": "room1"}});
        assert_eq!(t.inbound_of(&text).map(|m| m.text), Some("hi".to_string()));
    }

    #[test]
    fn error_mapping_retries_and_never_leaks_secret() {
        for (status, kind, tries) in [(401, K::Auth, 1), (403, K::NotFound, 1), (404, K::NotFound, 1), (400, K::Protocol, 1), (503, K::Network, 4)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], "{\"ocs\":{}}".into()));
            let t = talk(&srv.url, false);
            let e = t.send(&Outbound::text("room1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains(SECRET));
            assert_eq!(srv.requests().len(), tries, "{status}");
        }
        let srv = FakeServer::start(|_, n| if n == 0 { (429, vec![("Retry-After".into(), "1".into())], String::new()) } else { (201, vec![], String::new()) });
        let t = talk(&srv.url, false);
        let start = Instant::now();
        assert!(t.send(&Outbound::text("room1", "x")).unwrap().ids.is_empty(), "no id in the response");
        assert!(start.elapsed() >= Duration::from_millis(950));
        let srv = FakeServer::start(|_, _| (429, vec![("Retry-After".into(), "3600".into())], String::new()));
        let e = talk(&srv.url, false).send(&Outbound::text("room1", "x")).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        let e = talk("http://127.0.0.1:1", false).send(&Outbound::text("room1", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network);
    }

    #[test]
    fn cancel_returns_promptly_and_build_validates_settings() {
        let t = talk("http://127.0.0.1:1", false);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(t.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_millis(600));
        t.stop();
        assert!(t.local_addr().is_none());
        let d = temp_dir("nc");
        let secrets: crate::config::Secrets = std::sync::Arc::new(|s: &str| s.replace("{{secret:NC}}", "sekrit"));
        let ctx = crate::config::Ctx { name: "nc", state_dir: &d, secrets: &secrets };
        let ok = json!({"base_url": "https://cloud.example", "bot_secret": "{{secret:NC}}", "listen": "127.0.0.1:0", "bot_name": "Ark"});
        assert_eq!(build(&ctx, ok.as_object().unwrap()).unwrap().id(), "nc");
        let typo = json!({"base_url": "https://cloud.example", "bot_secret": "x", "listen": "127.0.0.1:0", "botname": "Ark"});
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("botname"));
        let half = json!({"base_url": "https://cloud.example", "bot_secret": "x", "listen": "127.0.0.1:0", "api_user": "u"});
        assert!(build(&ctx, half.as_object().unwrap()).err().unwrap().contains("api_password"));
        let missing = json!({"base_url": "https://cloud.example", "bot_secret": "{{secret:NOPE}}", "listen": "127.0.0.1:0"});
        assert!(build(&ctx, missing.as_object().unwrap()).err().unwrap().contains("not set"));
    }
}
