//! Matrix client-server API (ported from OpenClaw `extensions/matrix` and Hermes
//! `plugins/platforms/matrix`, both MIT).
//!
//! Auth: an access token, or `m.login.password` (the device id is persisted so
//! restarts reuse one device; an `M_UNKNOWN_TOKEN` triggers one re-login).
//! Receive: `/sync` long-poll with an inline filter; `next_batch` is committed to
//! the state file only on the following poll (at-least-once, the router dedups).
//! The first sync only learns state (no history replay). Invites are auto-joined
//! (DM invites recorded in `m.direct`); `m.room.message` text/notice/emote/image/
//! file/audio/video and stickers, replies (reply fallback stripped), threads
//! (`m.thread`), edits (`m.replace`), intentional mentions (`m.mentions`) or our
//! id / display name in the body, DM detection (`m.direct` or ≤2 members), read
//! receipts, and reactions on our numbered button prompts (→ `Callback`).
//! Send: HTML from Markdown (`org.matrix.custom.html`), replies, threads,
//! `m.mentions`, media upload (`/_matrix/media/v3/upload`), edits, redactions,
//! typing, reactions; every send uses a fresh transaction id that is reused on
//! retry, so retries are idempotent. Rate limits honour `retry_after_ms`.
//! End-to-end encryption (Olm/Megolm, see [`crate::matrix_e2ee`]): device keys
//! and one-time/fallback keys are uploaded on first use; to-device room keys and
//! `m.room.encrypted` timeline events are decrypted (events whose key has not
//! arrived yet wait up to 10 minutes); every event sent to a room with
//! `m.room.encryption` is Megolm-encrypted (keys shared over Olm with all member
//! devices, TOFU, blacklist) and attachments are uploaded as `EncryptedFile`s.
//! Sending to an encrypted room fails closed when E2EE is unavailable. With
//! `e2ee = false`, encrypted rooms get one plain notice instead. Cross-signing,
//! SAS verification (in-room and to-device), secret storage and key backup are
//! in [`crate::matrix_trust`]; their notices (SAS codes) go to the log and, with
//! `verify_notify`, to that room or user. Sender names come from
//! `m.room.member` display names (profile lookup as fallback, cached 1 h,
//! disambiguated with the user id when two members share one). A `user:@x:hs`
//! target reuses the `m.direct` room or creates one (`trusted_private_chat`,
//! encrypted when E2EE is on, invite + `m.direct`). Presence is set with
//! `/sync?set_presence=` and `PUT presence` at start, `offline` on stop.

use crate::http::{classify, Http, Payload, Resp};
use crate::matrix_e2ee::{self as e2ee, DecryptError, E2ee};
use crate::{markup, sleep_cancellable, write_atomic, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use seagent_net::urlencode as enc;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 4000;
pub const ENCRYPTED_NOTICE: &str = "🔒 This room is end-to-end encrypted, and this bot cannot read encrypted messages yet. Please message me in an unencrypted room or DM.";
const KEYCAPS: [&str; 10] = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"];
const MAX_MEDIA: u64 = 50 * 1024 * 1024;
const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 500;
const PROFILE_TTL: Duration = Duration::from_secs(3600);
const VERIFICATION_TYPES: [&str; 7] = ["m.key.verification.ready", "m.key.verification.start", "m.key.verification.accept", "m.key.verification.key", "m.key.verification.mac", "m.key.verification.cancel", "m.key.verification.done"];

/// Owned request body (requests may run on a worker thread).
#[derive(Clone)]
enum Body {
    None,
    Json(Value),
    Raw(String, Vec<u8>),
}

#[derive(Default, Clone)]
struct Auth {
    token: Option<String>,
    user_id: Option<String>,
    device_id: Option<String>,
}

#[derive(Default)]
struct SyncState {
    committed: Option<String>,
    pending: Option<String>,
    warned: HashSet<String>,
}

#[derive(Default, Clone)]
struct RoomInfo {
    name: String,
    members: Option<u64>,
}

pub struct Matrix {
    id: String,
    hs: String,
    auth: Mutex<Auth>,
    login_user: Option<String>,
    password: Option<String>,
    device_name: String,
    http: Http,
    sync_http: Http,
    state: PathBuf,
    sync: Mutex<SyncState>,
    dm_rooms: Mutex<HashSet<String>>,
    /// User → their DM rooms (`m.direct`).
    dm_map: Mutex<HashMap<String, Vec<String>>>,
    rooms: Mutex<HashMap<String, RoomInfo>>,
    /// (room, user) → display name from `m.room.member` ("" = none set).
    names: Mutex<HashMap<(String, String), String>>,
    /// User → profile display name, with when we asked.
    profiles: Mutex<HashMap<String, (String, Instant)>>,
    display_name: Mutex<Option<String>>,
    /// Our button prompts: event id → callback data per keycap.
    prompts: Mutex<HashMap<String, Vec<String>>>,
    /// (room, event, key) → our reaction event id.
    my_reactions: Mutex<HashMap<(String, String, String), String>>,
    sent: Mutex<(HashSet<String>, VecDeque<String>)>,
    txn_prefix: String,
    txn: AtomicU64,
    poll_timeout: u64,
    pub auto_join: bool,
    pub process_notices: bool,
    pub read_receipts: bool,
    pub encrypted_notice: bool,
    /// Olm/Megolm support (on by default).
    pub e2ee: bool,
    pub e2ee_passphrase: Option<String>,
    /// Devices never sent room keys nor trusted: `DEVICE`, `@user:hs` or `@user:hs/DEVICE`.
    pub blacklist: Vec<String>,
    /// Trust / cross-signing / backup / verification policy.
    pub e2ee_opts: e2ee::Opts,
    /// Room id or `@user` that gets verification notices (SAS codes).
    pub verify_notify: Option<String>,
    /// `online` / `unavailable` / `offline`; empty = leave presence alone.
    pub presence: String,
    e2ee_path: PathBuf,
    /// Ready E2EE state, or when setting it up last failed.
    crypto: Mutex<Option<Result<Arc<E2ee>, Instant>>>,
    /// Room → `m.room.encryption` content (`None` = known unencrypted).
    enc_rooms: Mutex<HashMap<String, Option<Value>>>,
    /// Encrypted events whose room key has not arrived yet.
    pending: Mutex<Vec<(String, Value, Instant)>>,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
}

pub struct MatrixOpts<'a> {
    pub homeserver: &'a str,
    pub access_token: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub password: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub device_name: Option<&'a str>,
    pub state: PathBuf,
    pub poll_timeout_secs: u64,
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// Run a request on a worker thread so a blocked long-poll never delays cancel.
fn exec(http: &Http, method: &str, url: &str, body: &Body, token: Option<&str>, cancel: &Cancel) -> Result<Option<Resp>, ChannelError> {
    let (tx, rx) = mpsc::channel();
    let (h, m, u, b) = (match token {
        Some(t) => http.clone().bearer(t),
        None => http.clone(),
    }, method.to_string(), url.to_string(), body.clone());
    std::thread::spawn(move || {
        let payload = match &b {
            Body::None => Payload::None,
            Body::Json(v) => Payload::Json(v),
            Body::Raw(ct, bytes) => Payload::Raw(ct, bytes),
        };
        let _ = tx.send(h.call(&m, &u, &[], payload));
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(r) => return r.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) if cancel.is_cancelled() => return Ok(None),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "matrix request worker died")),
        }
    }
}

/// Matrix `{errcode, error, retry_after_ms}` → classified error. `login` = credentials check.
fn mx_error(status: u16, retry_after: Option<Duration>, what: &str, body: &str, login: bool) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let code = str_of(&v["errcode"]);
    let msg = format!("matrix {what}: HTTP {status} {code} {}", str_of(&v["error"]).chars().take(200).collect::<String>());
    match code {
        "M_UNKNOWN_TOKEN" | "M_MISSING_TOKEN" | "M_USER_DEACTIVATED" => ChannelError::new(K::Auth, msg),
        "M_LIMIT_EXCEEDED" => ChannelError::new(K::RateLimited { retry_after: v["retry_after_ms"].as_u64().map(Duration::from_millis).or(retry_after) }, msg),
        "M_FORBIDDEN" if login => ChannelError::new(K::Auth, msg),
        // Not in the room / banned / room gone: never retry.
        "M_FORBIDDEN" | "M_NOT_FOUND" => ChannelError::new(K::NotFound, msg),
        _ if status == 403 && login => ChannelError::new(K::Auth, msg),
        _ if status == 403 => ChannelError::new(K::NotFound, msg),
        _ => classify(status, retry_after, &format!("matrix {what}"), &format!("{code} {}", str_of(&v["error"]))),
    }
}

/// Inline reply fallback: `> <@user:srv> quoted\n> more\n\nreply` → (quote, author, rest).
fn split_fallback(body: &str) -> (Option<String>, Option<String>, String) {
    if !body.starts_with("> ") {
        return (None, None, body.to_string());
    }
    let lines: Vec<&str> = body.split('\n').collect();
    let mut i = 0;
    let mut quoted = vec![];
    let mut author = None;
    while i < lines.len() && (lines[i].starts_with("> ") || lines[i] == ">") {
        let mut c = lines[i].strip_prefix("> ").unwrap_or("");
        if i == 0 {
            if let Some(rest) = c.strip_prefix("* <").or_else(|| c.strip_prefix('<')) {
                if let Some((who, after)) = rest.split_once('>') {
                    if who.starts_with('@') {
                        author = Some(who.to_string());
                        c = after.trim_start();
                    }
                }
            }
        }
        quoted.push(c);
        i += 1;
    }
    if i < lines.len() && lines[i].is_empty() {
        i += 1;
    }
    let rest = lines[i..].join("\n");
    let q = quoted.join("\n").trim().to_string();
    (Some(q).filter(|q| !q.is_empty()), author, if rest.is_empty() { body.to_string() } else { rest })
}

/// `@user:server.tld` tokens in outbound text, for `m.mentions`.
fn outbound_mentions(text: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for (i, _) in text.match_indices('@') {
        if i > 0 && text[..i].chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let tail = &text[i + 1..];
        let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || "._=-/+:".contains(c))).unwrap_or(tail.len());
        let cand = tail[..end].trim_end_matches(['.', ':', '-']);
        if let Some((local, server)) = cand.split_once(':') {
            if !local.is_empty() && server.contains('.') && !out.iter().any(|o| o == &format!("@{cand}")) {
                out.push(format!("@{cand}"));
            }
        }
    }
    out
}

fn msgtype_for(k: MediaKind) -> &'static str {
    match k {
        MediaKind::Image | MediaKind::Animation | MediaKind::Sticker => "m.image",
        MediaKind::Video => "m.video",
        MediaKind::Audio | MediaKind::Voice => "m.audio",
        MediaKind::Document => "m.file",
    }
}

/// Replay one recorded room event (see `tests/real/vectors/synapse_sync_slice.json`)
/// as seagent would turn it into an `Inbound`. Public for the vector tests.
pub fn recorded_inbound(channel: &str, me: &str, room: &str, room_name: &str, is_dm: bool, ev: &Value) -> Option<Inbound> {
    let none = |_: &str| -> Option<Vec<String>> { None };
    let empty = |_: &str| String::new();
    let no_sent = |_: &str| false;
    event_inbound(&Ctx { channel, me, display_name: None, room, room_name, is_dm, process_notices: false, sent: &no_sent, prompt: &none, name_of: &empty }, ev)
}

/// What inbound parsing needs to know about us and the room.
struct Ctx<'a> {
    channel: &'a str,
    me: &'a str,
    display_name: Option<&'a str>,
    room: &'a str,
    room_name: &'a str,
    is_dm: bool,
    process_notices: bool,
    sent: &'a dyn Fn(&str) -> bool,
    prompt: &'a dyn Fn(&str) -> Option<Vec<String>>,
    name_of: &'a dyn Fn(&str) -> String,
}

fn mentions_me(c: &Ctx, content: &Value, body: &str) -> bool {
    if content["m.mentions"]["user_ids"].as_array().is_some_and(|a| a.iter().any(|u| u == c.me)) {
        return true;
    }
    if body.contains(c.me) || str_of(&content["formatted_body"]).contains(&format!("matrix.to/#/{}", c.me)) || str_of(&content["formatted_body"]).contains(&format!("matrix.to/#/{}", enc(c.me))) {
        return true;
    }
    let lower = body.to_lowercase();
    c.display_name.iter().filter(|n| n.chars().count() >= 2).any(|n| {
        let n = n.to_lowercase();
        lower.match_indices(&n).any(|(i, _)| {
            let before = lower[..i].chars().last();
            let after = lower[i + n.len()..].chars().next();
            before.is_none_or(|b| !b.is_alphanumeric()) && after.is_none_or(|a| !a.is_alphanumeric())
        })
    })
}

fn event_inbound(c: &Ctx, ev: &Value) -> Option<Inbound> {
    let sender = str_of(&ev["sender"]);
    if sender == c.me || sender.is_empty() {
        return None;
    }
    let event_id = str_of(&ev["event_id"]).to_string();
    let content = &ev["content"];
    let base = Inbound {
        channel: c.channel.to_string(),
        chat: c.room.to_string(),
        chat_type: if c.is_dm { ChatType::Direct } else { ChatType::Group },
        chat_name: c.room_name.to_string(),
        sender: sender.to_string(),
        sender_name: (c.name_of)(sender),
        ts: ev["origin_server_ts"].as_i64().unwrap_or(0) / 1000,
        ..Default::default()
    };
    let rel = &content["m.relates_to"];
    match str_of(&ev["type"]) {
        "m.reaction" => {
            if rel["rel_type"] != "m.annotation" {
                return None;
            }
            let data = (c.prompt)(str_of(&rel["event_id"]))?;
            let key = str_of(&rel["key"]).replace('\u{fe0f}', "");
            let idx = KEYCAPS.iter().position(|k| k.replace('\u{fe0f}', "") == key)?;
            let data = data.get(idx)?.clone();
            Some(Inbound {
                message_id: format!("cb:{event_id}"),
                callback: Some(Callback { id: event_id.clone(), data }),
                reply: Some(ReplyRef { id: str_of(&rel["event_id"]).to_string(), is_own: true, ..Default::default() }),
                ..base
            })
        }
        typ @ ("m.room.message" | "m.sticker") => {
            let edited = rel["rel_type"] == "m.replace";
            let content = if edited && content["m.new_content"].is_object() { &content["m.new_content"] } else { content };
            let msgtype = if typ == "m.sticker" { "m.sticker" } else { str_of(&content["msgtype"]) };
            if msgtype == "m.notice" && !c.process_notices {
                return None; // the bot-reply msgtype; ignoring it prevents bot loops
            }
            let raw_body = str_of(&content["body"]);
            let reply_id = rel["m.in_reply_to"]["event_id"].as_str().filter(|_| !(rel["rel_type"] == "m.thread" && rel["is_falling_back"] == true));
            let (quote, author, body) = if reply_id.is_some() || rel["m.in_reply_to"].is_object() { split_fallback(raw_body) } else { (None, None, raw_body.to_string()) };
            let mut media = vec![];
            let mut text = body.clone();
            // Encrypted attachments carry the mxc url in `file` (decrypted in fetch_media).
            if let Some(url) = content["url"].as_str().or(content["file"]["url"].as_str()).filter(|u| u.starts_with("mxc://")) {
                let kind = match msgtype {
                    "m.image" => MediaKind::Image,
                    "m.video" => MediaKind::Video,
                    "m.audio" if content.get("org.matrix.msc3245.voice").is_some() => MediaKind::Voice,
                    "m.audio" => MediaKind::Audio,
                    "m.sticker" => MediaKind::Sticker,
                    _ => MediaKind::Document,
                };
                // MSC2530: with `filename`, `body` is a caption; without, it is the file name.
                let (name, caption) = match content["filename"].as_str() {
                    Some(f) if f != body => (f.to_string(), Some(body.clone())),
                    _ => (body.clone(), None),
                };
                text = caption.clone().unwrap_or_default();
                media.push(Media { kind, url: Some(url.to_string()), mime: str_of(&content["info"]["mimetype"]).to_string(), size: content["info"]["size"].as_u64().unwrap_or(0), name, caption, id: Some(url.to_string()), path: None });
            } else if !matches!(msgtype, "m.text" | "m.notice" | "m.emote") {
                return None;
            }
            if msgtype == "m.emote" {
                text = format!("* {} {text}", base.sender_name);
            }
            if text.trim().is_empty() && media.is_empty() {
                return None;
            }
            let thread = (rel["rel_type"] == "m.thread").then(|| str_of(&rel["event_id"]).to_string()).filter(|t| !t.is_empty());
            let reply = reply_id.map(|r| ReplyRef { id: r.to_string(), text: quote.unwrap_or_default(), is_own: (c.sent)(r) || author.as_deref() == Some(c.me), author: author.unwrap_or_default() });
            let mentioned = mentions_me(c, content, &text);
            Some(Inbound { text, message_id: event_id, media, mentioned, reply, thread, edited, ..base })
        }
        _ => None,
    }
}

impl Matrix {
    pub fn new(id: &str, o: MatrixOpts) -> Result<Matrix, String> {
        let hs = o.homeserver.trim().trim_end_matches('/').to_string();
        if !(hs.starts_with("https://") || hs.starts_with("http://")) {
            return Err(format!("channel {id}: matrix homeserver must be an http(s) URL"));
        }
        let token = o.access_token.map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
        let password = o.password.filter(|p| !p.is_empty()).map(str::to_string);
        if token.is_none() && (password.is_none() || o.user_id.is_none()) {
            return Err(format!("channel {id}: matrix needs access_token, or user_id + password"));
        }
        let saved: Value = std::fs::read_to_string(&o.state).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let sync = SyncState {
            committed: saved["next_batch"].as_str().map(str::to_string),
            pending: None,
            warned: saved["warned_encrypted"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        };
        let device_id = o.device_id.map(str::to_string).or_else(|| saved["device_id"].as_str().map(str::to_string));
        let enc_rooms = saved["encrypted_rooms"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), Some(v.clone()))).collect();
        let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        Ok(Matrix {
            id: id.to_string(),
            hs,
            auth: Mutex::new(Auth { token, user_id: o.user_id.map(str::to_string).filter(|u| u.starts_with('@')), device_id }),
            login_user: o.user_id.map(str::to_string),
            password,
            device_name: o.device_name.unwrap_or("seagent").to_string(),
            http: Http::new(Duration::from_secs(60)),
            sync_http: Http::new(Duration::from_secs(o.poll_timeout_secs + 30)),
            e2ee_path: o.state.with_extension("e2ee"),
            state: o.state,
            sync: Mutex::new(sync),
            dm_rooms: Mutex::new(HashSet::new()),
            dm_map: Mutex::new(HashMap::new()),
            rooms: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
            profiles: Mutex::new(HashMap::new()),
            display_name: Mutex::new(None),
            prompts: Mutex::new(serde_json::from_value(saved["prompts"].clone()).unwrap_or_default()),
            my_reactions: Mutex::new(HashMap::new()),
            sent: Mutex::new((HashSet::new(), VecDeque::new())),
            txn_prefix: format!("seagent{start}"),
            txn: AtomicU64::new(0),
            poll_timeout: o.poll_timeout_secs,
            auto_join: true,
            process_notices: false,
            read_receipts: true,
            encrypted_notice: true,
            e2ee: true,
            e2ee_passphrase: None,
            blacklist: vec![],
            e2ee_opts: e2ee::Opts::default(),
            verify_notify: None,
            presence: "online".into(),
            crypto: Mutex::new(None),
            enc_rooms: Mutex::new(enc_rooms),
            pending: Mutex::new(vec![]),
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
        })
    }

    fn set_presence(&self) -> String {
        if self.presence.is_empty() {
            String::new()
        } else {
            format!("&set_presence={}", enc(&self.presence))
        }
    }

    fn txn(&self) -> String {
        format!("{}.{}", self.txn_prefix, self.txn.fetch_add(1, Ordering::SeqCst))
    }

    fn save_state(&self, s: &SyncState) -> Result<(), ChannelError> {
        let a = self.auth.lock().unwrap().clone();
        let mut warned: Vec<&String> = s.warned.iter().collect();
        warned.sort();
        let prompts = self.prompts.lock().unwrap().clone();
        let enc_rooms: serde_json::Map<String, Value> = self.enc_rooms.lock().unwrap().iter().filter_map(|(k, v)| Some((k.clone(), v.clone()?))).collect();
        let v = json!({"next_batch": s.committed, "device_id": a.device_id, "user_id": a.user_id, "warned_encrypted": warned, "prompts": prompts, "encrypted_rooms": enc_rooms});
        write_atomic(&self.state, v.to_string().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving matrix state: {e}")))
    }

    fn login(&self, cancel: &Cancel) -> Result<(), ChannelError> {
        let (user, pw) = (self.login_user.clone().unwrap_or_default(), self.password.clone().unwrap_or_default());
        let device = self.auth.lock().unwrap().device_id.clone();
        let mut body = json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": pw, "initial_device_display_name": self.device_name});
        if let Some(d) = device {
            body["device_id"] = json!(d);
        }
        let url = format!("{}/_matrix/client/v3/login", self.hs);
        let r = exec(&self.http, "POST", &url, &Body::Json(body), None, cancel)?.ok_or_else(|| ChannelError::new(K::Network, "cancelled"))?;
        if !(200..300).contains(&r.status) {
            return Err(mx_error(r.status, r.retry_after, "login", &r.body, true));
        }
        let v: Value = serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, "matrix login: bad JSON"))?;
        let mut a = self.auth.lock().unwrap();
        a.token = Some(v["access_token"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "matrix login: no access_token"))?.to_string());
        a.user_id = v["user_id"].as_str().map(str::to_string).or(a.user_id.take());
        a.device_id = v["device_id"].as_str().map(str::to_string).or(a.device_id.take());
        drop(a);
        let s = self.sync.lock().unwrap();
        self.save_state(&s)
    }

    /// (token, our user id), logging in / asking whoami when needed.
    fn session(&self, cancel: &Cancel) -> Result<(String, String), ChannelError> {
        let a = self.auth.lock().unwrap().clone();
        let token = match a.token {
            Some(t) => t,
            None => {
                self.login(cancel)?;
                self.auth.lock().unwrap().token.clone().unwrap_or_default()
            }
        };
        if let Some(u) = self.auth.lock().unwrap().user_id.clone() {
            return Ok((token, u));
        }
        let r = exec(&self.http, "GET", &format!("{}/_matrix/client/v3/account/whoami", self.hs), &Body::None, Some(&token), cancel)?.ok_or_else(|| ChannelError::new(K::Network, "cancelled"))?;
        if !(200..300).contains(&r.status) {
            return Err(mx_error(r.status, r.retry_after, "whoami", &r.body, false));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let u = v["user_id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "matrix whoami: no user_id"))?.to_string();
        let mut g = self.auth.lock().unwrap();
        g.user_id = Some(u.clone());
        if g.device_id.is_none() {
            g.device_id = v["device_id"].as_str().map(str::to_string);
        }
        Ok((token, u))
    }

    /// Authorised client-server call with retries. `Ok(None)` = cancelled.
    fn call_c(&self, method: &str, path: &str, body: Body, cancel: &Cancel, long: bool) -> Result<Option<Value>, ChannelError> {
        let mut attempt = 0;
        let mut relogged = false;
        loop {
            let (token, _) = match self.session(cancel) {
                Err(_) if cancel.is_cancelled() => return Ok(None),
                r => r?,
            };
            let url = format!("{}{path}", self.hs);
            let err = match exec(if long { &self.sync_http } else { &self.http }, method, &url, &body, Some(&token), cancel) {
                Ok(None) => return Ok(None),
                Ok(Some(r)) if (200..300).contains(&r.status) => return Ok(Some(serde_json::from_str(&r.body).unwrap_or(Value::Null))),
                Ok(Some(r)) => {
                    let e = mx_error(r.status, r.retry_after, method, &r.body, false);
                    if e.kind == K::Auth && self.password.is_some() && !relogged && r.body.contains("M_UNKNOWN_TOKEN") {
                        relogged = true;
                        self.auth.lock().unwrap().token = None;
                        continue;
                    }
                    e
                }
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
            if !sleep_cancellable(wait, cancel) {
                return Ok(None);
            }
            attempt += 1;
        }
    }

    fn call(&self, method: &str, path: &str, body: Body) -> Result<Value, ChannelError> {
        self.call_c(method, path, body, &Cancel::new(), false).map(Option::unwrap_or_default)
    }

    fn api(&self) -> impl Fn(&str, &str, Value) -> Result<Value, ChannelError> + '_ {
        move |m, p, b| {
            if p == "/_matrix/client/v3/keys/device_signing/upload" {
                return self.call_uia(m, p, b);
            }
            self.call(m, p, if b.is_null() { Body::None } else { Body::Json(b) })
        }
    }

    /// A call behind user-interactive auth: answered with `m.login.dummy` or, when
    /// configured, the account password.
    fn call_uia(&self, method: &str, path: &str, body: Value) -> Result<Value, ChannelError> {
        let cancel = Cancel::new();
        let (token, me) = self.session(&cancel)?;
        let r = exec(&self.http, method, &format!("{}{path}", self.hs), &Body::Json(body.clone()), Some(&token), &cancel)?.ok_or_else(|| ChannelError::new(K::Network, "cancelled"))?;
        if (200..300).contains(&r.status) {
            return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        if r.status != 401 || !v["flows"].is_array() {
            return Err(mx_error(r.status, r.retry_after, method, &r.body, false));
        }
        let has = |stage: &str| v["flows"].as_array().into_iter().flatten().any(|f| f["stages"] == json!([stage]));
        let auth = match &self.password {
            _ if has("m.login.dummy") => json!({"type": "m.login.dummy", "session": v["session"]}),
            Some(pw) if has("m.login.password") => json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": me}, "password": pw, "session": v["session"]}),
            _ => return Err(ChannelError::new(K::Auth, format!("matrix {path} needs interactive auth ({}); configure password or approve it from another client", v["flows"]))),
        };
        let mut b = body;
        b["auth"] = auth;
        self.call(method, path, Body::Json(b))
    }

    /// Ask `user` to verify this device by SAS: in `room` (in-room flow) or to-device.
    /// Returns the flow id (the request event id in a room).
    pub fn request_verification(&self, user: &str, room: Option<&str>) -> Result<String, ChannelError> {
        let c = self.crypto().ok_or_else(|| ChannelError::new(K::Fatal, "matrix E2EE is unavailable"))?;
        match room {
            None => c.request_verification(user, &self.api()),
            Some(r) => {
                let room = self.resolve_chat(r)?;
                let id = self.send_event(&room, "m.room.message", c.room_request(user))?;
                c.room_request_sent(&room, &id, user);
                Ok(id)
            }
        }
    }

    /// Room events and notices produced by the E2EE layer.
    fn deliver_out(&self, outs: Vec<e2ee::Out>) {
        for o in outs {
            let r = match o {
                e2ee::Out::Room { room, typ, content, .. } => self.send_event(&room, &typ, content).map(|_| ()),
                e2ee::Out::Notice(m) => match &self.verify_notify {
                    Some(t) => {
                        let to = if t.starts_with('@') { format!("user:{t}") } else { t.clone() };
                        self.send(&Outbound { silent: true, ..Outbound::text(&to, &format!("🔐 {m}")) }).map(|_| ())
                    }
                    None => Ok(()),
                },
            };
            if let Err(e) = r {
                eprintln!("matrix {}: {e}", self.id);
            }
        }
    }

    /// `user:@x:hs` → its DM room (an existing `m.direct` room we are in, or a new one).
    fn resolve_chat(&self, chat: &str) -> Result<String, ChannelError> {
        let Some(user) = chat.strip_prefix("user:") else { return Ok(chat.to_string()) };
        if !user.starts_with('@') || !user.contains(':') {
            return Err(ChannelError::new(K::Fatal, format!("matrix user target must look like user:@name:server, not {chat}")));
        }
        let known = self.dm_map.lock().unwrap().get(user).cloned().unwrap_or_default();
        if let Some(r) = known.iter().rev().find(|r| self.rooms.lock().unwrap().contains_key(*r)) {
            return Ok(r.clone());
        }
        let (_, me) = self.session(&Cancel::new())?;
        let encrypted = self.e2ee && self.crypto().is_some();
        let mut body = json!({"preset": "trusted_private_chat", "is_direct": true, "invite": [user]});
        if encrypted {
            body["initial_state"] = json!([{"type": "m.room.encryption", "state_key": "", "content": {"algorithm": e2ee::MEGOLM}}]);
        }
        let r = self.call("POST", "/_matrix/client/v3/createRoom", Body::Json(body))?;
        let room = r["room_id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "matrix createRoom: no room_id"))?.to_string();
        self.rooms.lock().unwrap().insert(room.clone(), RoomInfo { name: String::new(), members: Some(2) });
        if encrypted {
            self.set_encryption(&room, Some(json!({"algorithm": e2ee::MEGOLM})));
        }
        self.record_dm(&me, &room, user);
        Ok(room)
    }

    /// A member's display name in `room` (profile as fallback), disambiguated by user id.
    fn name_of(&self, room: &str, user: &str) -> String {
        let local = user.trim_start_matches('@').split(':').next().unwrap_or("").to_string();
        let names = self.names.lock().unwrap();
        let n = match names.get(&(room.to_string(), user.to_string())) {
            Some(n) => n.clone(),
            None => {
                drop(names);
                let cached = self.profiles.lock().unwrap().get(user).filter(|(_, t)| t.elapsed() < PROFILE_TTL).map(|(n, _)| n.clone());
                let n = cached.unwrap_or_else(|| {
                    let n = match self.call("GET", &format!("/_matrix/client/v3/profile/{}/displayname", enc(user)), Body::None) {
                        Ok(v) => str_of(&v["displayname"]).to_string(),
                        Err(_) => String::new(),
                    };
                    let mut p = self.profiles.lock().unwrap();
                    if p.len() > 1000 {
                        p.clear();
                    }
                    p.insert(user.to_string(), (n.clone(), Instant::now()));
                    n
                });
                return if n.is_empty() { local } else { n };
            }
        };
        if n.is_empty() {
            return local;
        }
        let clash = names.iter().any(|((r, u), m)| r == room && u != user && *m == n);
        if clash {
            format!("{n} ({user})")
        } else {
            n
        }
    }

    /// The E2EE state (keys uploaded), set up on first use; `None` when disabled or unavailable.
    fn crypto(&self) -> Option<Arc<E2ee>> {
        if !self.e2ee {
            return None;
        }
        let mut g = self.crypto.lock().unwrap();
        match &*g {
            Some(Ok(c)) => return Some(c.clone()),
            Some(Err(t)) if t.elapsed() < Duration::from_secs(300) => return None,
            _ => {}
        }
        match self.init_crypto() {
            Ok(c) => {
                *g = Some(Ok(c.clone()));
                Some(c)
            }
            Err(e) => {
                eprintln!("matrix {}: end-to-end encryption unavailable: {e}", self.id);
                *g = Some(Err(Instant::now()));
                None
            }
        }
    }

    fn init_crypto(&self) -> Result<Arc<E2ee>, String> {
        let (_, me) = self.session(&Cancel::new()).map_err(|e| e.to_string())?;
        let known = self.auth.lock().unwrap().device_id.clone();
        let device = match known {
            Some(d) => d,
            None => {
                let v = self.call("GET", "/_matrix/client/v3/account/whoami", Body::None).map_err(|e| e.to_string())?;
                let d = v["device_id"].as_str().ok_or("whoami returned no device_id (E2EE needs a device)")?.to_string();
                self.auth.lock().unwrap().device_id = Some(d.clone());
                d
            }
        };
        let mut c = E2ee::open(&self.id, &self.e2ee_path, self.e2ee_passphrase.as_deref(), &me, &device)?;
        c.blacklist = self.blacklist.clone();
        c.opts = self.e2ee_opts.clone();
        c.ensure_uploaded(&self.api()).map_err(|e| format!("uploading device keys: {e}"))?;
        c.setup(&self.api());
        Ok(Arc::new(c))
    }

    fn set_encryption(&self, room: &str, v: Option<Value>) {
        let mut g = self.enc_rooms.lock().unwrap();
        if matches!(g.get(room), Some(Some(_))) && v.is_none() {
            return; // encryption cannot be turned off
        }
        let persist = v.is_some() && g.get(room) != Some(&v);
        g.insert(room.to_string(), v);
        drop(g);
        if persist {
            let s = self.sync.lock().unwrap();
            let _ = self.save_state(&s);
        }
    }

    /// The room's `m.room.encryption` content, asked from the server once per unknown room.
    fn room_encryption(&self, room: &str) -> Result<Option<Value>, ChannelError> {
        if !self.e2ee {
            return Ok(None);
        }
        if let Some(v) = self.enc_rooms.lock().unwrap().get(room) {
            return Ok(v.clone());
        }
        let v = match self.call("GET", &format!("/_matrix/client/v3/rooms/{}/state/m.room.encryption/", enc(room)), Body::None) {
            Ok(v) if v["algorithm"].is_string() => Some(v),
            Ok(_) => None,
            Err(e) if e.kind == K::NotFound => None,
            Err(e) => return Err(e),
        };
        self.set_encryption(room, v.clone());
        Ok(v)
    }

    fn send_event(&self, room: &str, typ: &str, content: Value) -> Result<String, ChannelError> {
        let (typ, content) = match self.room_encryption(room)? {
            Some(settings) => {
                let c = self.crypto().ok_or_else(|| ChannelError::new(K::Fatal, format!("matrix room {room} is end-to-end encrypted but E2EE is unavailable; not sending")))?;
                ("m.room.encrypted", c.encrypt_room(room, &settings, typ, &content, &self.api())?)
            }
            None => (typ, content),
        };
        let path = format!("/_matrix/client/v3/rooms/{}/send/{typ}/{}", enc(room), enc(&self.txn()));
        let r = self.call("PUT", &path, Body::Json(content))?;
        let id = str_of(&r["event_id"]).to_string();
        if !id.is_empty() {
            let mut g = self.sent.lock().unwrap();
            if g.0.insert(id.clone()) {
                g.1.push_back(id.clone());
                if g.1.len() > 2000 {
                    if let Some(old) = g.1.pop_front() {
                        g.0.remove(&old);
                    }
                }
            }
        }
        Ok(id)
    }

    /// Our display name (for body mentions), fetched once.
    fn learn_display_name(&self, me: &str, cancel: &Cancel) {
        if self.display_name.lock().unwrap().is_some() {
            return;
        }
        let r = self.call_c("GET", &format!("/_matrix/client/v3/profile/{}/displayname", enc(me)), Body::None, cancel, false);
        let n = match r {
            Ok(Some(v)) => v["displayname"].as_str().unwrap_or("").to_string(),
            Ok(None) => return,
            Err(e) if e.kind == K::NotFound => String::new(),
            Err(_) => return,
        };
        *self.display_name.lock().unwrap() = Some(n);
    }

    fn filter() -> String {
        let mut types = vec!["m.room.message", "m.room.encrypted", "m.reaction", "m.sticker", "m.room.name", "m.room.member", "m.room.encryption", "m.room.history_visibility"];
        types.extend(VERIFICATION_TYPES);
        json!({
            "presence": {"not_types": ["*"]},
            "account_data": {"types": ["m.direct"]},
            "room": {
                "timeline": {"limit": 50, "types": types},
                "state": {"lazy_load_members": true, "types": ["m.room.name", "m.room.canonical_alias", "m.room.member", "m.room.encryption", "m.room.history_visibility"]},
                "ephemeral": {"not_types": ["*"]},
                "account_data": {"not_types": ["*"]}
            }
        })
        .to_string()
    }

    fn join(&self, room: &str) -> Result<(), ChannelError> {
        self.call("POST", &format!("/_matrix/client/v3/join/{}", enc(room)), Body::Json(json!({}))).map(|_| ())
    }

    /// Record a DM invite in `m.direct` account data.
    fn record_dm(&self, me: &str, room: &str, inviter: &str) {
        let path = format!("/_matrix/client/v3/user/{}/account_data/m.direct", enc(me));
        let mut cur = self.call("GET", &path, Body::None).ok().filter(|v| v.is_object()).unwrap_or_else(|| json!({}));
        let list = cur[inviter].as_array().cloned().unwrap_or_default();
        if !list.iter().any(|r| r == room) {
            let mut l = list;
            l.push(json!(room));
            cur[inviter] = json!(l);
            let _ = self.call("PUT", &path, Body::Json(cur));
        }
        self.dm_rooms.lock().unwrap().insert(room.to_string());
        let mut m = self.dm_map.lock().unwrap();
        let l = m.entry(inviter.to_string()).or_default();
        if !l.iter().any(|r| r == room) {
            l.push(room.to_string());
        }
    }

    /// Parse one timeline event with the room's context.
    fn with_ctx<R>(&self, me: &str, room: &str, f: impl FnOnce(&Ctx) -> R) -> R {
        let info = self.rooms.lock().unwrap().get(room).cloned().unwrap_or_default();
        // Spec (and Hermes): `m.direct` is what marks a DM. Without it, only a
        // nameless two-person room counts — a *named* room with two members is a
        // group room (mention gating applies) even if it is not in `m.direct`.
        let is_dm = self.dm_rooms.lock().unwrap().contains(room) || (info.members.is_some_and(|n| n <= 2) && info.name.is_empty());
        let dn = self.display_name.lock().unwrap().clone().filter(|n| !n.is_empty());
        let sent = self.sent.lock().unwrap().0.clone();
        let prompts = self.prompts.lock().unwrap().clone();
        f(&Ctx { channel: &self.id, me, display_name: dn.as_deref(), room, room_name: &info.name, is_dm, process_notices: self.process_notices, sent: &|id| sent.contains(id), prompt: &|id| prompts.get(id).cloned(), name_of: &|u| self.name_of(room, u) })
    }

    /// Learn room names / member counts / DMs, join invites. `deliver` = parse timelines.
    fn absorb(&self, sync: &Value, me: &str, deliver: bool) -> Vec<Inbound> {
        let crypto = self.crypto();
        if let Some(c) = &crypto {
            c.on_sync(sync, &self.api());
        }
        for ev in sync["account_data"]["events"].as_array().into_iter().flatten() {
            if ev["type"] == "m.direct" {
                let map: HashMap<String, Vec<String>> = ev["content"].as_object().into_iter().flatten().map(|(u, v)| (u.clone(), v.as_array().into_iter().flatten().filter_map(|r| r.as_str().map(str::to_string)).collect())).collect();
                *self.dm_rooms.lock().unwrap() = map.values().flatten().cloned().collect();
                *self.dm_map.lock().unwrap() = map;
            }
        }
        if self.auto_join {
            for (room, inv) in sync["rooms"]["invite"].as_object().into_iter().flatten() {
                let me_ev = inv["invite_state"]["events"].as_array().into_iter().flatten().find(|e| e["type"] == "m.room.member" && e["state_key"] == me);
                if self.join(room).is_ok() {
                    if let Some(e) = me_ev.filter(|e| e["content"]["is_direct"] == true) {
                        self.record_dm(me, room, str_of(&e["sender"]));
                    }
                }
            }
        }
        let mut out = vec![];
        let mut receipts: Vec<(String, String)> = vec![];
        let mut warn: Vec<String> = vec![];
        let mut pending = vec![];
        // Encrypted events from earlier syncs whose keys may have arrived now.
        if let Some(c) = &crypto {
            for (room, ev, t) in std::mem::take(&mut *self.pending.lock().unwrap()) {
                match c.decrypt_room(&room, &ev) {
                    Ok(d) => out.extend(self.with_ctx(me, &room, |ctx| event_inbound(ctx, &d))),
                    Err(DecryptError::MissingSession) if t.elapsed() < PENDING_TTL => pending.push((room, ev, t)),
                    Err(e) => eprintln!("matrix {}: cannot decrypt {} in {room}: {e:?}", self.id, str_of(&ev["event_id"])),
                }
            }
        }
        for (room, r) in sync["rooms"]["join"].as_object().into_iter().flatten() {
            let mut encryption = None;
            {
                let mut rooms = self.rooms.lock().unwrap();
                let info = rooms.entry(room.clone()).or_default();
                if let Some(n) = r["summary"]["m.joined_member_count"].as_u64() {
                    info.members = Some(n);
                }
                for e in r["state"]["events"].as_array().into_iter().flatten().chain(r["timeline"]["events"].as_array().into_iter().flatten()) {
                    match str_of(&e["type"]) {
                        "m.room.member" => {
                            let key = (room.clone(), str_of(&e["state_key"]).to_string());
                            let mut names = self.names.lock().unwrap();
                            if matches!(str_of(&e["content"]["membership"]), "join" | "invite") {
                                names.insert(key, str_of(&e["content"]["displayname"]).to_string());
                            } else {
                                names.remove(&key);
                            }
                        }
                        "m.room.name" => info.name = str_of(&e["content"]["name"]).to_string(),
                        "m.room.canonical_alias" if info.name.is_empty() => info.name = str_of(&e["content"]["alias"]).to_string(),
                        "m.room.encryption" if e["content"]["algorithm"].is_string() => encryption = Some(e["content"].clone()),
                        _ => {}
                    }
                }
            }
            if encryption.is_some() {
                self.set_encryption(room, encryption);
            }
            if !deliver {
                continue;
            }
            let last = self.with_ctx(me, room, |ctx| {
                let mut last = None;
                for ev in r["timeline"]["events"].as_array().into_iter().flatten() {
                    let decrypted;
                    let ev = if ev["type"] == "m.room.encrypted" {
                        if str_of(&ev["sender"]) == me {
                            continue;
                        }
                        let Some(c) = &crypto else {
                            warn.push(room.clone());
                            continue;
                        };
                        let mut r = c.decrypt_room(room, ev);
                        if r == Err(DecryptError::MissingSession) && c.on_missing(room, ev, &self.api()) {
                            r = c.decrypt_room(room, ev);
                        }
                        match r {
                            Ok(d) => {
                                decrypted = d;
                                &decrypted
                            }
                            Err(DecryptError::MissingSession) => {
                                pending.push((room.clone(), ev.clone(), Instant::now()));
                                continue;
                            }
                            Err(DecryptError::Rejected(e)) => {
                                eprintln!("matrix {}: rejected encrypted event {} in {room}: {e}", self.id, str_of(&ev["event_id"]));
                                continue;
                            }
                        }
                    } else {
                        ev
                    };
                    if crypto.as_ref().is_some_and(|c| c.on_room_event(room, ev, &self.api())) {
                        continue;
                    }
                    if let Some(m) = event_inbound(ctx, ev) {
                        last = Some(str_of(&ev["event_id"]).to_string());
                        out.push(m);
                    }
                }
                last
            });
            if let Some(e) = last {
                receipts.push((room.clone(), e));
            }
        }
        if let Some(c) = &crypto {
            let mut p = self.pending.lock().unwrap();
            p.extend(pending);
            let extra = p.len().saturating_sub(MAX_PENDING);
            p.drain(..extra);
            c.flush();
            self.deliver_out(c.take_out());
        }
        for room in warn {
            let mut s = self.sync.lock().unwrap();
            if s.warned.insert(room.clone()) {
                eprintln!("matrix {}: room {room} is end-to-end encrypted; seagent cannot decrypt it (E2EE disabled or unavailable)", self.id);
                let _ = self.save_state(&s);
                drop(s);
                if self.encrypted_notice && !self.e2ee {
                    let _ = self.send_event(&room, "m.room.message", json!({"msgtype": "m.notice", "body": ENCRYPTED_NOTICE, "m.mentions": {}}));
                }
            }
        }
        if self.read_receipts && !receipts.is_empty() {
            let (hs, http, token) = (self.hs.clone(), self.http.clone(), self.auth.lock().unwrap().token.clone());
            std::thread::spawn(move || {
                for (room, ev) in receipts {
                    let url = format!("{hs}/_matrix/client/v3/rooms/{}/receipt/m.read/{}", enc(&room), enc(&ev));
                    let _ = exec(&http, "POST", &url, &Body::Json(json!({})), token.as_deref(), &Cancel::new());
                }
            });
        }
        out
    }

    fn upload(&self, data: Vec<u8>, name: &str, mime: &str) -> Result<String, ChannelError> {
        let path = format!("/_matrix/media/v3/upload?filename={}", enc(name));
        let r = self.call("POST", &path, Body::Raw(if mime.is_empty() { "application/octet-stream".into() } else { mime.to_string() }, data))?;
        r["content_uri"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(K::Protocol, "matrix upload: no content_uri"))
    }

    fn relations(&self, out: &Outbound, content: &mut Value, first: bool) {
        let reply = out.reply_to.as_deref().filter(|_| first);
        if let Some(t) = &out.thread {
            content["m.relates_to"] = match reply {
                Some(r) => json!({"rel_type": "m.thread", "event_id": t, "is_falling_back": false, "m.in_reply_to": {"event_id": r}}),
                None => json!({"rel_type": "m.thread", "event_id": t, "is_falling_back": true, "m.in_reply_to": {"event_id": t}}),
            };
        } else if let Some(r) = reply {
            content["m.relates_to"] = json!({"m.in_reply_to": {"event_id": r}});
        }
    }

    fn text_content(&self, out: &Outbound, text: &str, md: bool) -> Value {
        let msgtype = if out.silent { "m.notice" } else { "m.text" };
        let mut c = json!({"msgtype": msgtype, "body": text, "m.mentions": {"user_ids": outbound_mentions(text)}});
        if md {
            let html = markup::convert(text, Markup::MatrixHtml);
            if html != markup::escape_html(text) {
                c["format"] = json!("org.matrix.custom.html");
                c["formatted_body"] = json!(html);
            }
        }
        c
    }

    fn media_content(&self, m: &Media, room: &str) -> Result<Value, ChannelError> {
        let (data_name, data, mime) = match (&m.path, &m.url) {
            (Some(p), _) => {
                let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                let name = std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
                let mime = if m.mime.is_empty() { crate::msteams::guess_mime(&name).to_string() } else { m.mime.clone() };
                (name, Some(data), mime)
            }
            (None, Some(u)) if u.starts_with("mxc://") => (if m.name.is_empty() { "file".into() } else { m.name.clone() }, None, m.mime.clone()),
            (None, Some(u)) => {
                let data = crate::http::get_bytes(u, &[], MAX_MEDIA)?;
                let name = u.split('?').next().unwrap_or(u).rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("file").to_string();
                let mime = if m.mime.is_empty() { crate::msteams::guess_mime(&name).to_string() } else { m.mime.clone() };
                (name, Some(data), mime)
            }
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let name = if m.name.is_empty() { data_name.clone() } else { m.name.clone() };
        let mut c = json!({"msgtype": msgtype_for(m.kind), "body": name, "filename": name, "info": {"mimetype": mime, "size": m.size}, "m.mentions": {}});
        match data {
            None => c["url"] = json!(m.url),
            Some(d) => {
                c["info"]["size"] = json!(d.len());
                if self.room_encryption(room)?.is_some() {
                    // EncryptedFile: the server only ever sees AES-CTR ciphertext.
                    let (ct, mut file) = e2ee::encrypt_attachment(&d);
                    file["url"] = json!(self.upload(ct, &data_name, "application/octet-stream")?);
                    c["file"] = file;
                } else {
                    c["url"] = json!(self.upload(d, &data_name, &mime)?);
                }
            }
        }
        if m.kind == MediaKind::Voice {
            c["org.matrix.msc3245.voice"] = json!({});
        }
        Ok(c)
    }
}

impl Channel for Matrix {
    fn id(&self) -> &str {
        &self.id
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
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::MatrixHtml,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let (_, me) = match self.session(cancel) {
            Err(_) if cancel.is_cancelled() => return Ok(vec![]),
            r => r?,
        };
        let since = {
            let mut s = self.sync.lock().unwrap();
            if let Some(p) = s.pending.take() {
                s.committed = Some(p);
                self.save_state(&s)?;
            }
            s.committed.clone()
        };
        let filter = enc(&Self::filter());
        self.crypto(); // keys must be on the server before anyone can claim them
        let Some(since) = since else {
            // First start: learn state, skip history.
            let Some(v) = self.call_c("GET", &format!("/_matrix/client/v3/sync?timeout=0&filter={filter}{}", self.set_presence()), Body::None, cancel, true)? else { return Ok(vec![]) };
            self.learn_display_name(&me, cancel);
            if !self.presence.is_empty() {
                if let Err(e) = self.call("PUT", &format!("/_matrix/client/v3/presence/{}/status", enc(&me)), Body::Json(json!({"presence": self.presence}))) {
                    eprintln!("matrix {}: setting presence: {e}", self.id);
                }
            }
            self.absorb(&v, &me, false);
            let mut s = self.sync.lock().unwrap();
            s.committed = v["next_batch"].as_str().map(str::to_string);
            self.save_state(&s)?;
            return Ok(vec![]);
        };
        self.learn_display_name(&me, cancel);
        let path = format!("/_matrix/client/v3/sync?timeout={}&since={}&filter={filter}{}", self.poll_timeout * 1000, enc(&since), self.set_presence());
        let Some(v) = self.call_c("GET", &path, Body::None, cancel, true)? else { return Ok(vec![]) };
        let next = v["next_batch"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "matrix sync: no next_batch"))?.to_string();
        let out = self.absorb(&v, &me, true);
        self.sync.lock().unwrap().pending = Some(next);
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let out = &Outbound { chat: self.resolve_chat(&out.chat)?, ..out.clone() };
        let md = out.format == TextFormat::Markdown;
        let mut sent = Sent::default();
        let mut text = out.text.trim_end().to_string();
        // No native buttons: numbered options, answered by reacting with the keycap.
        let mut prompt_data = vec![];
        if !out.buttons.is_empty() {
            let mut lines = vec![];
            for b in out.buttons.iter().flatten() {
                match &b.url {
                    Some(u) => lines.push(format!("• {}: {u}", b.label)),
                    None if prompt_data.len() < KEYCAPS.len() => {
                        prompt_data.push(b.data.clone());
                        lines.push(format!("{} {}", KEYCAPS[prompt_data.len() - 1], b.label));
                    }
                    None => {}
                }
            }
            text = format!("{text}\n\n{}", lines.join("\n")).trim_start().to_string();
        }
        let caption = out.media.len() == 1 && !text.is_empty() && text.chars().count() <= MAX_MESSAGE && prompt_data.is_empty();
        for (i, m) in out.media.iter().enumerate() {
            let mut c = self.media_content(m, &out.chat)?;
            if caption {
                let t = self.text_content(out, &text, md);
                c["body"] = t["body"].clone();
                c["m.mentions"] = t["m.mentions"].clone();
                if let Some(f) = t.get("formatted_body") {
                    c["format"] = json!("org.matrix.custom.html");
                    c["formatted_body"] = f.clone();
                }
            }
            self.relations(out, &mut c, i == 0);
            sent.ids.push(self.send_event(&out.chat, "m.room.message", c)?);
        }
        if caption {
            return Ok(sent);
        }
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut c = self.text_content(out, &piece, md);
            self.relations(out, &mut c, i == 0 && out.media.is_empty());
            let id = self.send_event(&out.chat, "m.room.message", c)?;
            if i + 1 == n && !prompt_data.is_empty() {
                let count = prompt_data.len();
                {
                    let mut p = self.prompts.lock().unwrap();
                    if p.len() >= 200 {
                        if let Some(k) = p.keys().next().cloned() {
                            p.remove(&k);
                        }
                    }
                    p.insert(id.clone(), prompt_data.clone());
                }
                // Persist so a button press after a restart still maps to its data.
                let st = self.sync.lock().unwrap();
                let _ = self.save_state(&st);
                drop(st);
                for key in KEYCAPS.iter().take(count) {
                    let _ = self.react(&out.chat, &id, key, false);
                }
            }
            sent.ids.push(id);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let chat = &self.resolve_chat(chat)?;
        let new = self.text_content(&Outbound::text(chat, text), text, true);
        let mut c = json!({"msgtype": "m.text", "body": format!("* {text}"), "m.new_content": new, "m.relates_to": {"rel_type": "m.replace", "event_id": message_id}, "m.mentions": {}});
        if let Some(h) = new["formatted_body"].as_str() {
            c["format"] = json!("org.matrix.custom.html");
            c["formatted_body"] = json!(format!("* {h}"));
        }
        self.send_event(chat, "m.room.message", c).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let chat = &self.resolve_chat(chat)?;
        self.call("PUT", &format!("/_matrix/client/v3/rooms/{}/redact/{}/{}", enc(chat), enc(message_id), enc(&self.txn())), Body::Json(json!({}))).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let chat = &self.resolve_chat(chat)?;
        let (_, me) = self.session(&Cancel::new())?;
        self.call("PUT", &format!("/_matrix/client/v3/rooms/{}/typing/{}", enc(chat), enc(&me)), Body::Json(json!({"typing": true, "timeout": 30000}))).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let chat = &self.resolve_chat(chat)?;
        let key = (chat.to_string(), message_id.to_string(), emoji.to_string());
        if !remove {
            let id = self.send_event(chat, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": message_id, "key": emoji}}))?;
            self.my_reactions.lock().unwrap().insert(key, id);
            return Ok(());
        }
        let known = self.my_reactions.lock().unwrap().remove(&key);
        let target = match known {
            Some(id) => Some(id),
            None => {
                let (_, me) = self.session(&Cancel::new())?;
                let v = self.call("GET", &format!("/_matrix/client/v1/rooms/{}/relations/{}/m.annotation/m.reaction?limit=100", enc(chat), enc(message_id)), Body::None)?;
                v["chunk"].as_array().into_iter().flatten().find(|e| e["sender"] == me.as_str() && e["content"]["m.relates_to"]["key"] == emoji).map(|e| str_of(&e["event_id"]).to_string())
            }
        };
        match target {
            Some(id) => self.delete(chat, &id),
            None => Ok(()),
        }
    }

    fn stop(&self) {
        let (token, user) = {
            let a = self.auth.lock().unwrap();
            (a.token.clone(), a.user_id.clone())
        };
        if let (false, Some(t), Some(u)) = (self.presence.is_empty(), token, user) {
            let url = format!("{}/_matrix/client/v3/presence/{}/status", self.hs, enc(&u));
            let _ = Http::new(Duration::from_secs(5)).bearer(&t).call("PUT", &url, &[], Payload::Json(&json!({"presence": "offline"})));
        }
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().or(m.id.as_deref()).ok_or_else(|| ChannelError::new(K::Fatal, "matrix attachment without mxc url"))?;
        let rest = url.strip_prefix("mxc://").ok_or_else(|| ChannelError::new(K::Protocol, "not an mxc:// url"))?;
        let (server, media) = rest.split_once('/').ok_or_else(|| ChannelError::new(K::Protocol, "bad mxc url"))?;
        let (token, _) = self.session(&Cancel::new())?;
        let auth = format!("Bearer {token}");
        let authed = format!("{}/_matrix/client/v1/media/download/{}/{}", self.hs, enc(server), enc(media));
        let data = match crate::http::get_bytes_trusted(&authed, &[("authorization", &auth)], MAX_MEDIA, &self.hs) {
            // Homeservers older than v1.11 only have the legacy endpoint.
            Err(e) if matches!(e.kind, K::NotFound | K::Protocol) => crate::http::get_bytes_trusted(&format!("{}/_matrix/media/v3/download/{}/{}", self.hs, enc(server), enc(media)), &[("authorization", &auth)], MAX_MEDIA, &self.hs),
            r => r,
        }?;
        match self.crypto().and_then(|c| c.file_for(url)) {
            Some(file) => e2ee::decrypt_attachment(&data, &file),
            None => Ok(data),
        }
    }
}

fn d_poll() -> u64 {
    25
}
fn yes() -> bool {
    true
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    homeserver: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "yes")]
    auto_join: bool,
    /// Also handle `m.notice` (other bots' replies); off by default to avoid loops.
    #[serde(default)]
    process_notices: bool,
    #[serde(default = "yes")]
    read_receipts: bool,
    /// With `e2ee = false`: tell encrypted rooms (once) that seagent cannot read them.
    #[serde(default = "yes")]
    encrypted_notice: bool,
    /// Olm/Megolm end-to-end encryption.
    #[serde(default = "yes")]
    e2ee: bool,
    /// Encrypts the E2EE store (PBKDF2); without it a random key file sits next to the store.
    #[serde(default)]
    e2ee_passphrase: Option<String>,
    /// Devices that never get room keys and whose messages are not trusted.
    #[serde(default)]
    blacklist_devices: Vec<String>,
    /// `tofu`, or `cross_signed`: devices of users with cross-signing keys must be cross-signed (or verified).
    #[serde(default)]
    trust: e2ee::Trust,
    /// Create cross-signing keys when the account has none; sign this device.
    #[serde(default = "yes")]
    cross_signing: bool,
    /// Use (or create) the server-side key backup.
    #[serde(default = "yes")]
    key_backup: bool,
    /// Secret-storage recovery key (or passphrase): opens existing cross-signing keys and the backup.
    #[serde(default)]
    recovery_key: Option<String>,
    /// Users whose SAS verification requests are answered (`self`, `*`, or user ids).
    #[serde(default = "d_verify_from")]
    verify_from: Vec<String>,
    /// Room id or `@user` that gets verification notices (SAS codes to compare).
    #[serde(default)]
    verify_notify: Option<String>,
    /// `if-unverified` (ask our other sessions to verify this device) or `off`.
    #[serde(default = "d_startup_verification")]
    startup_verification: String,
    #[serde(default = "d_cooldown")]
    startup_verification_cooldown_hours: u64,
    /// `online`, `unavailable`, `offline`, or "" to leave it alone.
    #[serde(default = "d_presence")]
    presence: String,
}

fn d_verify_from() -> Vec<String> {
    vec!["self".into()]
}
fn d_startup_verification() -> String {
    "if-unverified".into()
}
fn d_cooldown() -> u64 {
    24
}
fn d_presence() -> String {
    "online".into()
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.opt_secret("access_token", &st.access_token)?;
    let password = ctx.opt_secret("password", &st.password)?;
    let mut m = Matrix::new(
        ctx.name,
        MatrixOpts {
            homeserver: &st.homeserver,
            access_token: token.as_deref(),
            user_id: st.user_id.as_deref(),
            password: password.as_deref(),
            device_id: st.device_id.as_deref(),
            device_name: st.device_name.as_deref(),
            state: ctx.state("matrix.json"),
            poll_timeout_secs: st.poll_timeout_secs,
        },
    )?;
    m.auto_join = st.auto_join;
    m.process_notices = st.process_notices;
    m.read_receipts = st.read_receipts;
    m.encrypted_notice = st.encrypted_notice;
    m.e2ee = st.e2ee;
    m.e2ee_passphrase = ctx.opt_secret("e2ee_passphrase", &st.e2ee_passphrase)?;
    m.blacklist = st.blacklist_devices;
    if !matches!(st.presence.as_str(), "online" | "unavailable" | "offline" | "") {
        return Err(format!("channel {}: matrix presence must be online, unavailable, offline or empty", ctx.name));
    }
    if !matches!(st.startup_verification.as_str(), "if-unverified" | "off") {
        return Err(format!("channel {}: matrix startup_verification must be if-unverified or off", ctx.name));
    }
    m.presence = st.presence;
    m.verify_notify = st.verify_notify;
    m.e2ee_opts = e2ee::Opts {
        trust: st.trust,
        cross_signing: st.cross_signing,
        key_backup: st.key_backup,
        recovery_key: ctx.opt_secret("recovery_key", &st.recovery_key)?,
        verify_from: st.verify_from,
        startup_verification: st.startup_verification == "if-unverified",
        startup_verification_cooldown_ms: st.startup_verification_cooldown_hours * 3_600_000,
    };
    Ok(Arc::new(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer, Req};
    use std::time::Instant;

    type Reply = (u16, Vec<(String, String)>, String);
    const ME: &str = "@seagent:hs.test";

    fn jr(v: Value) -> Reply {
        (200, vec![("content-type".into(), "application/json".into())], v.to_string())
    }
    fn err(status: u16, code: &str, extra: Value) -> Reply {
        let mut v = json!({"errcode": code, "error": "nope"});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        (status, vec![], v.to_string())
    }

    fn mx(url: &str, state: PathBuf, password: bool) -> Matrix {
        let mut m = Matrix::new(
            "mx",
            MatrixOpts {
                homeserver: url,
                access_token: (!password).then_some("SECRETTOKEN"),
                user_id: Some(ME),
                password: password.then_some("hunter2"),
                device_id: None,
                device_name: None,
                state,
                poll_timeout_secs: 1,
            },
        )
        .unwrap();
        m.retry_base = Duration::from_millis(5);
        m.e2ee = false;
        m
    }

    fn msg(id: &str, sender: &str, content: Value) -> Value {
        json!({"type": "m.room.message", "event_id": id, "sender": sender, "origin_server_ts": 1700000000123i64, "content": content})
    }

    fn sent_path(r: &Req) -> bool {
        r.method == "PUT" && r.path.contains("/send/m.room.message/")
    }

    #[test]
    fn login_sync_join_and_parse_every_message_kind() {
        let prompt = Arc::new(Mutex::new(String::new()));
        let p2 = prompt.clone();
        let srv = FakeServer::start(move |req, n| {
            let p = req.path.as_str();
            if p == "/_matrix/client/v3/login" {
                return jr(json!({"access_token": "TOK1", "user_id": ME, "device_id": "DEV1"}));
            }
            if p.starts_with("/_matrix/client/v3/profile/") {
                return jr(json!({"displayname": "Seagent Bot"}));
            }
            if p.contains("/account_data/m.direct") {
                return if req.method == "GET" { err(404, "M_NOT_FOUND", json!({})) } else { jr(json!({})) };
            }
            if p.starts_with("/_matrix/client/v3/join/") || p.contains("/receipt/") {
                return jr(json!({"room_id": "!inv:hs.test"}));
            }
            if p.contains("/send/") {
                return jr(json!({"event_id": format!("$sent{n}")}));
            }
            if p.starts_with("/_matrix/client/v3/sync") && !p.contains("since=") {
                return jr(json!({"next_batch": "s1",
                    "account_data": {"events": [{"type": "m.direct", "content": {"@amy:hs.test": ["!dm:hs.test"]}}]},
                    "rooms": {
                        "join": {"!old:hs.test": {"timeline": {"events": [msg("$old", "@amy:hs.test", json!({"msgtype": "m.text", "body": "history"}))]}}},
                        "invite": {"!inv:hs.test": {"invite_state": {"events": [{"type": "m.room.member", "state_key": ME, "sender": "@bob:hs.test", "content": {"membership": "invite", "is_direct": true}}]}}}}}));
            }
            if p.contains("since=s1") {
                let prompt_id = p2.lock().unwrap().clone();
                return jr(json!({"next_batch": "s2", "rooms": {"join": {
                    "!dm:hs.test": {"summary": {"m.joined_member_count": 2}, "timeline": {"events": [msg("$dm1", "@amy:hs.test", json!({"msgtype": "m.text", "body": "hello"}))]}},
                    "!enc:hs.test": {"timeline": {"events": [{"type": "m.room.encrypted", "event_id": "$x1", "sender": "@amy:hs.test", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}]}},
                    "!grp:hs.test": {"summary": {"m.joined_member_count": 5}, "state": {"events": [{"type": "m.room.name", "state_key": "", "content": {"name": "Team"}}]}, "timeline": {"events": [
                        msg("$g1", "@amy:hs.test", json!({"msgtype": "m.text", "body": "hey bot", "m.mentions": {"user_ids": [ME]}})),
                        msg("$g2", "@amy:hs.test", json!({"msgtype": "m.text", "body": "Seagent Bot, can you?"})),
                        msg("$g3", "@amy:hs.test", json!({"msgtype": "m.text", "body": "nothing for you", "m.mentions": {}})),
                        msg("$g4", "@amy:hs.test", json!({"msgtype": "m.text", "body": "> <@seagent:hs.test> shall I?\n\nyes", "m.relates_to": {"m.in_reply_to": {"event_id": "$earlier"}}})),
                        msg("$g5", "@amy:hs.test", json!({"msgtype": "m.text", "body": "in thread", "m.relates_to": {"rel_type": "m.thread", "event_id": "$root", "is_falling_back": true, "m.in_reply_to": {"event_id": "$root"}}})),
                        msg("$g6", "@amy:hs.test", json!({"msgtype": "m.text", "body": "* fixed", "m.new_content": {"msgtype": "m.text", "body": "fixed"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$g3"}})),
                        msg("$g7", "@amy:hs.test", json!({"msgtype": "m.image", "body": "cat.png", "url": "mxc://hs.test/abc", "info": {"mimetype": "image/png", "size": 10}})),
                        msg("$g8", "@amy:hs.test", json!({"msgtype": "m.file", "body": "see this", "filename": "r.pdf", "url": "mxc://hs.test/pdf", "info": {"mimetype": "application/pdf"}})),
                        msg("$g9", "@other-bot:hs.test", json!({"msgtype": "m.notice", "body": "beep"})),
                        msg("$g10", ME, json!({"msgtype": "m.text", "body": "my own"})),
                        {"type": "m.reaction", "event_id": "$r1", "sender": "@amy:hs.test", "content": {"m.relates_to": {"rel_type": "m.annotation", "event_id": prompt_id, "key": "2️⃣"}}},
                        {"type": "m.reaction", "event_id": "$r2", "sender": "@amy:hs.test", "content": {"m.relates_to": {"rel_type": "m.annotation", "event_id": "$unrelated", "key": "👍"}}},
                        msg("$g11", "@amy:hs.test", json!({"msgtype": "m.audio", "body": "voice.ogg", "url": "mxc://hs.test/v", "org.matrix.msc3245.voice": {}}))
                    ]}}}}}));
            }
            if p.contains("since=s2") {
                return jr(json!({"next_batch": "s3", "rooms": {"join": {"!enc:hs.test": {"timeline": {"events": [{"type": "m.room.encrypted", "event_id": "$x2", "sender": "@amy:hs.test", "content": {}}]}}}}}));
            }
            jr(json!({"next_batch": "s3"}))
        });
        let dir = temp_dir("mx");
        let state = dir.join("mx.json");
        let m = mx(&srv.url, state.clone(), true);
        assert!(m.poll(&Cancel::new()).unwrap().is_empty(), "first sync learns state only");
        let reqs = srv.requests();
        let login = reqs[0].json();
        assert_eq!((login["type"].as_str(), login["identifier"]["user"].as_str(), login["password"].as_str()), (Some("m.login.password"), Some(ME), Some("hunter2")));
        assert!(reqs.iter().any(|r| r.path == format!("/_matrix/client/v3/join/{}", enc("!inv:hs.test"))), "invite auto-joined");
        assert!(reqs.iter().any(|r| r.method == "PUT" && r.path.contains("/account_data/m.direct") && r.json()["@bob:hs.test"] == json!(["!inv:hs.test"])), "DM invite recorded in m.direct");
        let sync = reqs.iter().find(|r| r.path.starts_with("/_matrix/client/v3/sync")).unwrap();
        assert_eq!(sync.header("authorization"), Some("Bearer TOK1"));
        assert!(sync.path.contains("filter=") && sync.path.contains("timeout=0"));
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((saved["next_batch"].as_str(), saved["device_id"].as_str()), (Some("s1"), Some("DEV1")));
        // A button prompt the user can answer by reacting.
        let s = m.send(&Outbound { buttons: vec![vec![crate::Button { label: "Yes".into(), data: "appr:1:once".into(), url: None }, crate::Button { label: "No".into(), data: "appr:1:deny".into(), url: None }]], ..Outbound::text("!grp:hs.test", "Run it?") }).unwrap();
        *prompt.lock().unwrap() = s.ids[0].clone();
        let got = m.poll(&Cancel::new()).unwrap();
        let by = |id: &str| got.iter().find(|g| g.message_id == id).unwrap_or_else(|| panic!("{id} missing from {got:#?}"));
        assert_eq!(got.len(), 11, "notice, own message and unrelated reaction dropped: {got:#?}");
        let dm = by("$dm1");
        assert_eq!((dm.chat.as_str(), dm.chat_type, dm.sender.as_str(), dm.text.as_str(), dm.ts), ("!dm:hs.test", ChatType::Direct, "@amy:hs.test", "hello", 1700000000));
        assert!(by("$g1").mentioned && by("$g1").chat_type == ChatType::Group && by("$g1").chat_name == "Team");
        assert!(by("$g2").mentioned, "display name in body");
        assert!(!by("$g3").mentioned);
        let r = by("$g4");
        assert_eq!(r.text, "yes", "reply fallback stripped");
        let rr = r.reply.as_ref().unwrap();
        assert!(rr.is_own && rr.text == "shall I?" && rr.id == "$earlier" && r.addressed());
        let t = by("$g5");
        assert_eq!((t.thread.as_deref(), t.reply.is_none()), (Some("$root"), true), "thread fallback is not a reply");
        assert!(by("$g6").edited && by("$g6").text == "fixed");
        let img = by("$g7");
        assert_eq!((img.text.as_str(), img.media[0].kind, img.media[0].url.as_deref(), img.media[0].name.as_str(), img.media[0].mime.as_str()), ("", MediaKind::Image, Some("mxc://hs.test/abc"), "cat.png", "image/png"));
        let f = by("$g8");
        assert_eq!((f.text.as_str(), f.media[0].name.as_str(), f.media[0].kind), ("see this", "r.pdf", MediaKind::Document));
        assert_eq!(by("$g11").media[0].kind, MediaKind::Voice);
        let cb = by("cb:$r1");
        assert_eq!(cb.callback.as_ref().unwrap().data, "appr:1:deny", "2️⃣ = second button");
        // E2EE: one notice to the room, persisted so it is never repeated.
        let notices: Vec<Req> = srv.requests().into_iter().filter(|r| sent_path(r) && r.path.contains(&enc("!enc:hs.test")) && r.json()["body"] == ENCRYPTED_NOTICE).collect();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].json()["msgtype"], "m.notice");
        let receipts = srv.requests().iter().filter(|r| r.path.contains("/receipt/m.read/")).count();
        let start = Instant::now();
        while srv.requests().iter().filter(|r| r.path.contains("/receipt/m.read/")).count() < 2 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(receipts <= 2 && srv.requests().iter().any(|r| r.path.contains(&format!("/rooms/{}/receipt/m.read/{}", enc("!dm:hs.test"), enc("$dm1")))), "read receipt per room");
        assert_eq!(serde_json::from_str::<Value>(&std::fs::read_to_string(&state).unwrap()).unwrap()["next_batch"], "s1", "s2 committed only on the next poll");
        // Restart: resumes from the committed token (redelivers s1), keeps the device, no second E2EE notice.
        drop(m);
        let m2 = mx(&srv.url, state.clone(), true);
        assert_eq!(m2.poll(&Cancel::new()).unwrap().len(), 11, "at-least-once after a crash");
        assert_eq!(srv.requests().iter().rfind(|r| r.path == "/_matrix/client/v3/login").unwrap().json()["device_id"], "DEV1", "device reused");
        assert!(m2.poll(&Cancel::new()).unwrap().is_empty());
        let notices = srv.requests().into_iter().filter(|r| sent_path(r) && r.json()["body"] == ENCRYPTED_NOTICE).count();
        assert_eq!(notices, 1, "warned once per room, across restarts");
    }

    #[test]
    fn send_shapes_html_relations_media_and_actions() {
        let srv = FakeServer::start(|req, n| {
            let p = req.path.as_str();
            match req.method.as_str() {
                "POST" if p.starts_with("/_matrix/media/v3/upload") => jr(json!({"content_uri": format!("mxc://hs.test/up{n}")})),
                "GET" if p == "/dl/pic.png" => (200, vec![], "PNG".into()),
                "GET" if p.contains("/relations/") => jr(json!({"chunk": [{"event_id": "$theirs", "sender": "@amy:hs.test", "content": {"m.relates_to": {"key": "👍"}}}, {"event_id": "$mine", "sender": ME, "content": {"m.relates_to": {"key": "👍"}}}]})),
                "GET" if p.starts_with("/_matrix/client/v1/media/download/hs.test/old") => err(404, "M_UNRECOGNIZED", json!({})),
                "GET" if p.contains("/media/") => (200, vec![], format!("BYTES:{p}")),
                _ => jr(json!({"event_id": format!("$e{n}")})),
            }
        });
        let m = mx(&srv.url, temp_dir("mx").join("s.json"), false);
        let out = Outbound { format: TextFormat::Markdown, reply_to: Some("$q".into()), thread: Some("$root".into()), ..Outbound::text("!r:hs.test", "**hi** @amy:hs.test") };
        assert_eq!(m.send(&out).unwrap().ids, vec!["$e0"]);
        let r = &srv.requests()[0];
        assert!(r.path.starts_with(&format!("/_matrix/client/v3/rooms/{}/send/m.room.message/seagent", enc("!r:hs.test"))), "{}", r.path);
        assert_eq!(r.header("authorization"), Some("Bearer SECRETTOKEN"));
        let b = r.json();
        assert_eq!((b["msgtype"].as_str(), b["body"].as_str(), b["format"].as_str(), b["formatted_body"].as_str()), (Some("m.text"), Some("**hi** @amy:hs.test"), Some("org.matrix.custom.html"), Some("<b>hi</b> @amy:hs.test")));
        assert_eq!(b["m.relates_to"], json!({"rel_type": "m.thread", "event_id": "$root", "is_falling_back": false, "m.in_reply_to": {"event_id": "$q"}}));
        assert_eq!(b["m.mentions"]["user_ids"], json!(["@amy:hs.test"]));
        m.send(&Outbound { silent: true, reply_to: Some("$q".into()), ..Outbound::text("!r:hs.test", "quiet") }).unwrap();
        let b = srv.requests()[1].json();
        assert_eq!((b["msgtype"].as_str(), b.get("format")), (Some("m.notice"), None));
        assert_eq!(b["m.relates_to"], json!({"m.in_reply_to": {"event_id": "$q"}}));
        let txns: HashSet<String> = srv.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(txns.len(), 2, "fresh txn id per send");
        // Local file: upload then m.file with the text as caption.
        let f = temp_dir("mx").join("r.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        m.send(&Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("!r:hs.test", "the report") }).unwrap();
        let reqs = srv.requests();
        let up = &reqs[2];
        assert_eq!((up.path.as_str(), up.header("content-type"), up.body.as_str()), ("/_matrix/media/v3/upload?filename=r.pdf", Some("application/pdf"), "%PDF"));
        let b = reqs[3].json();
        assert_eq!((b["msgtype"].as_str(), b["url"].as_str(), b["body"].as_str(), b["filename"].as_str(), b["info"]["size"].as_u64()), (Some("m.file"), Some("mxc://hs.test/up2"), Some("the report"), Some("r.pdf"), Some(4)));
        // Remote URL: downloaded, re-uploaded, sent as m.image; then the text separately.
        m.send(&Outbound { media: vec![Media { kind: MediaKind::Image, url: Some(format!("{}/dl/pic.png", srv.url)), ..Default::default() }, Media { kind: MediaKind::Image, url: Some("mxc://hs.test/already".into()), ..Default::default() }], ..Outbound::text("!r:hs.test", "two pics") }).unwrap();
        let reqs = srv.requests();
        let kinds: Vec<String> = reqs[4..].iter().map(|r| format!("{} {}", r.method, r.path.split('?').next().unwrap())).collect();
        assert_eq!(kinds.len(), 5, "{kinds:?}");
        assert!(kinds[0] == "GET /dl/pic.png" && kinds[1] == "POST /_matrix/media/v3/upload");
        assert_eq!((reqs[6].json()["msgtype"].as_str(), reqs[6].json()["url"].as_str()), (Some("m.image"), Some("mxc://hs.test/up5")));
        assert_eq!(reqs[7].json()["url"], "mxc://hs.test/already");
        assert_eq!(reqs[8].json()["body"], "two pics");
        // Buttons: numbered options plus pre-placed keycap reactions.
        let before = srv.requests().len();
        m.send(&Outbound { buttons: vec![vec![crate::Button { label: "A".into(), data: "x:1".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://e.com".into()) }]], ..Outbound::text("!r:hs.test", "Pick") }).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[before].json()["body"], "Pick\n\n1️⃣ A\n• Docs: https://e.com");
        assert!(reqs[before + 1].path.contains("/send/m.reaction/"));
        assert_eq!(reqs[before + 1].json()["m.relates_to"], json!({"rel_type": "m.annotation", "event_id": format!("$e{before}"), "key": "1️⃣"}));
        // Actions.
        m.edit("!r:hs.test", "$e0", "new **t**").unwrap();
        let e = srv.requests().last().unwrap().json();
        assert_eq!((e["body"].as_str(), e["m.new_content"]["body"].as_str(), e["m.new_content"]["formatted_body"].as_str()), (Some("* new **t**"), Some("new **t**"), Some("new <b>t</b>")));
        assert_eq!(e["m.relates_to"], json!({"rel_type": "m.replace", "event_id": "$e0"}));
        m.delete("!r:hs.test", "$e0").unwrap();
        assert!(srv.requests().last().unwrap().path.starts_with(&format!("/_matrix/client/v3/rooms/{}/redact/{}/seagent", enc("!r:hs.test"), enc("$e0"))));
        m.typing("!r:hs.test", None).unwrap();
        let t = srv.requests().last().unwrap().clone();
        assert_eq!((t.path.clone(), t.json()), (format!("/_matrix/client/v3/rooms/{}/typing/{}", enc("!r:hs.test"), enc(ME)), json!({"typing": true, "timeout": 30000})));
        m.react("!r:hs.test", "$e0", "🎉", false).unwrap();
        let rid = format!("$e{}", srv.requests().len() - 1);
        m.react("!r:hs.test", "$e0", "🎉", true).unwrap();
        assert!(srv.requests().last().unwrap().path.contains(&format!("/redact/{}/", enc(&rid))), "removes the reaction we sent");
        m.react("!r:hs.test", "$e9", "👍", true).unwrap();
        let reqs = srv.requests();
        assert!(reqs[reqs.len() - 2].path.contains("/_matrix/client/v1/rooms/") && reqs[reqs.len() - 2].path.contains("/relations/"));
        assert!(reqs.last().unwrap().path.contains(&format!("/redact/{}/", enc("$mine"))), "found ours via relations");
        // Authenticated media download, with the legacy fallback.
        let b = m.fetch_media(&Media { url: Some("mxc://hs.test/abc".into()), ..Default::default() }).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "BYTES:/_matrix/client/v1/media/download/hs.test/abc");
        assert_eq!(srv.requests().last().unwrap().header("authorization"), Some("Bearer SECRETTOKEN"));
        let b = m.fetch_media(&Media { url: Some("mxc://hs.test/old".into()), ..Default::default() }).unwrap();
        assert_eq!(String::from_utf8(b).unwrap(), "BYTES:/_matrix/media/v3/download/hs.test/old");
        assert_eq!(outbound_mentions("hi @a:b.c and @x:y.org, not me@mail.com or @nohost"), vec!["@a:b.c", "@x:y.org"]);
    }

    #[test]
    fn errors_rate_limits_and_relogin() {
        // Bad access token → Auth, never retried, token not in the message.
        let srv = FakeServer::start(|_, _| err(401, "M_UNKNOWN_TOKEN", json!({})));
        let m = mx(&srv.url, temp_dir("mx").join("s.json"), false);
        let e = m.send(&Outbound::text("!r:hs.test", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("SECRETTOKEN"));
        assert_eq!(srv.requests().len(), 1);
        // Soft logout with a password: log in again once and carry on.
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/_matrix/client/v3/login" => jr(json!({"access_token": "TNEW", "user_id": ME, "device_id": "D"})),
            _ if req.header("authorization") == Some("Bearer T7") => err(401, "M_UNKNOWN_TOKEN", json!({"soft_logout": true})),
            _ => jr(json!({"event_id": "$ok"})),
        });
        let m = mx(&srv.url, temp_dir("mx").join("s.json"), true);
        *m.auth.lock().unwrap() = Auth { token: Some("T7".into()), user_id: Some(ME.into()), device_id: None };
        assert_eq!(m.send(&Outbound::text("!r:hs.test", "x")).unwrap().ids, vec!["$ok"]);
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("/login")).count(), 1);
        // Wrong password at login → Auth.
        let srv = FakeServer::start(|_, _| err(403, "M_FORBIDDEN", json!({})));
        let m = mx(&srv.url, temp_dir("mx").join("s.json"), true);
        let e = m.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("hunter2"));
        // 429 M_LIMIT_EXCEEDED: wait retry_after_ms and resend with the same txn id.
        let srv = FakeServer::start(|req, n| match n {
            0 => err(429, "M_LIMIT_EXCEEDED", json!({"retry_after_ms": 1000})),
            _ if req.path.contains("forbidden") => err(403, "M_FORBIDDEN", json!({})),
            _ if req.path.contains("long") => err(429, "M_LIMIT_EXCEEDED", json!({"retry_after_ms": 3_600_000})),
            _ if req.path.contains("down") => (502, vec![], "<html>".into()),
            _ => jr(json!({"event_id": "$ok"})),
        });
        let m = mx(&srv.url, temp_dir("mx").join("s.json"), false);
        let start = Instant::now();
        m.send(&Outbound::text("!r:hs.test", "x")).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(950));
        let reqs = srv.requests();
        assert_eq!(reqs[0].path, reqs[1].path, "retry reuses the transaction id (idempotent)");
        assert_eq!(m.send(&Outbound::text("!forbidden:hs.test", "x")).unwrap_err().kind, K::NotFound, "not in room");
        assert_eq!(m.send(&Outbound::text("!long:hs.test", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        let before = srv.requests().len();
        assert_eq!(m.send(&Outbound::text("!down:hs.test", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len() - before, 5, "1 + max_retries");
        assert!(Matrix::new("m", MatrixOpts { homeserver: "hs.test", access_token: Some("t"), user_id: None, password: None, device_id: None, device_name: None, state: temp_dir("mx").join("s"), poll_timeout_secs: 1 }).is_err());
        assert!(Matrix::new("m", MatrixOpts { homeserver: "https://hs.test", access_token: None, user_id: Some(ME), password: None, device_id: None, device_name: None, state: temp_dir("mx").join("s"), poll_timeout_secs: 1 }).is_err());
    }

    #[test]
    fn cancel_interrupts_a_blocked_sync() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(4).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let state = temp_dir("mx").join("s.json");
        std::fs::write(&state, r#"{"next_batch":"s9"}"#).unwrap();
        let mut m = mx(&url, state, false);
        m.poll_timeout = 30;
        *m.display_name.lock().unwrap() = Some(String::new());
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(m.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn e2ee_round_trip_between_two_seagent_devices() {
        use crate::matrix_e2ee::fake_hs::FakeHs;
        const A: &str = "@a:hs.test";
        const B: &str = "@b:hs.test";
        let room = "!r:hs.test";
        let hs = Arc::new(FakeHs::new(room, &[A, B, "@x:hs.test"], json!({"algorithm": "m.megolm.v1.aes-sha2"})));
        let h2 = hs.clone();
        let srv = FakeServer::start_raw(move |req, _| {
            let (u, d) = match req.header("authorization") {
                Some("Bearer TA") => (A, "ADEV"),
                Some("Bearer TB") => (B, "BDEV"),
                _ => ("@x:hs.test", "XDEV"),
            };
            let ok = |v: Value| (200, vec![("content-type".to_string(), "application/json".to_string())], v.to_string().into_bytes());
            if req.path.starts_with("/_matrix/media/v3/upload") {
                return ok(json!({"content_uri": h2.upload_media(req.raw.clone())}));
            }
            if let Some(id) = req.path.strip_prefix("/_matrix/client/v1/media/download/hs.test/") {
                return (200, vec![], h2.media(id.parse().unwrap()).unwrap());
            }
            match h2.handle(u, d, &req.method, &req.path, &req.json()) {
                Ok(v) => ok(v),
                Err(_) => (404, vec![], br#"{"errcode":"M_NOT_FOUND","error":"no"}"#.to_vec()),
            }
        });
        let dir = temp_dir("mxe");
        let dev = |tok: &str, user: &str, name: &str| {
            let mut m = Matrix::new("mx", MatrixOpts { homeserver: &srv.url, access_token: Some(tok), user_id: Some(user), password: None, device_id: None, device_name: None, state: dir.join(format!("{name}.json")), poll_timeout_secs: 1 }).unwrap();
            m.read_receipts = false;
            m.retry_base = Duration::from_millis(5);
            *m.display_name.lock().unwrap() = Some(String::new());
            m
        };
        let (a, b) = (dev("TA", A, "a"), dev("TB", B, "b"));
        assert!(a.poll(&Cancel::new()).unwrap().is_empty() && b.poll(&Cancel::new()).unwrap().is_empty());
        let f = dir.join("photo.png");
        let png: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&f, &png).unwrap();
        let s1 = a.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text(room, "a picture, **secret**") }).unwrap();
        a.send(&Outbound::text(room, "plain words")).unwrap();
        // Nothing readable reaches the server: events are m.room.encrypted, media is ciphertext.
        let tl = hs.timeline();
        assert!(tl.iter().all(|e| e["type"] == "m.room.encrypted" && !e.to_string().contains("secret") && !e.to_string().contains("plain words")), "{tl:#?}");
        assert!(hs.media(0).unwrap() != png && hs.media(0).unwrap().len() == png.len());
        let got = b.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|g| g.text.as_str()).collect::<Vec<_>>(), vec!["a picture, **secret**", "plain words"]);
        let img = &got[0].media[0];
        assert_eq!((img.kind, img.name.as_str(), img.mime.as_str()), (MediaKind::Image, "photo.png", "image/png"));
        assert_eq!(b.fetch_media(img).unwrap(), png, "EncryptedFile decrypted on download");
        // Replies, edits and reactions in both directions.
        b.send(&Outbound { reply_to: Some(s1.ids[0].clone()), ..Outbound::text(room, "nice") }).unwrap();
        let got = a.poll(&Cancel::new()).unwrap();
        assert_eq!((got[0].text.as_str(), got[0].reply.as_ref().map(|r| r.id.as_str())), ("nice", Some(s1.ids[0].as_str())));
        a.edit(room, &s1.ids[0], "fixed caption").unwrap();
        a.react(room, &got[0].message_id, "👍", false).unwrap();
        let raw = hs.timeline();
        assert_eq!(raw[raw.len() - 1]["content"]["m.relates_to"]["rel_type"], "m.annotation", "relation copied outside the ciphertext");
        let got = b.poll(&Cancel::new()).unwrap();
        assert!(got[0].edited && got[0].text == "fixed caption", "{got:#?}");
        // A member leaves → a rotates; the new key reaches b only after the event: it waits.
        hs.handle("@x:hs.test", "XDEV", "PUT", &format!("/_matrix/client/v3/rooms/{}/send/m.room.member/t1", enc(room)), &json!({"membership": "leave"})).unwrap();
        assert!(a.poll(&Cancel::new()).unwrap().is_empty());
        hs.hold.store(true, Ordering::SeqCst);
        a.send(&Outbound::text(room, "key comes later")).unwrap();
        let tl = hs.timeline();
        assert_ne!(tl[tl.len() - 1]["content"]["session_id"], tl[0]["content"]["session_id"], "rotated");
        assert!(b.poll(&Cancel::new()).unwrap().is_empty(), "no key yet");
        hs.hold.store(false, Ordering::SeqCst);
        assert_eq!(b.poll(&Cancel::new()).unwrap().into_iter().map(|g| g.text).collect::<Vec<_>>(), vec!["key comes later"]);
        // Unencrypted rooms stay plain.
        a.send(&Outbound::text("!plain:hs.test", "hello plain")).unwrap();
        assert_eq!(hs.timeline().last().unwrap()["content"]["body"], "hello plain");
        // Fail closed: E2EE unavailable (unreadable store) → no send to the encrypted room.
        std::fs::write(dir.join("x.e2ee"), "not a store").unwrap();
        let x = dev("TX", "@x:hs.test", "x");
        let before = hs.timeline().len();
        assert_eq!(x.send(&Outbound::text(room, "leak?")).unwrap_err().kind, K::Fatal);
        assert_eq!(hs.timeline().len(), before);
        // Restart keeps the device identity: b can still read new messages from a.
        drop(b);
        let b = dev("TB", B, "b");
        a.send(&Outbound::text(room, "after restart")).unwrap();
        let got: Vec<String> = (0..2).flat_map(|_| b.poll(&Cancel::new()).unwrap()).map(|g| g.text).collect();
        assert!(got.contains(&"after restart".to_string()), "{got:?}");
    }

    /// Interop with matrix-rust-sdk crypto (vodozemac, as used by Element) through the
    /// node harness in `tests/matrix_interop.mjs`:
    /// `MATRIX_SDK_CRYPTO_WASM=…/matrix-sdk-crypto-wasm/node.mjs cargo test -p seagent-channel interop -- --ignored`
    /// (with `MATRIX_JS_SDK=…/node_modules/matrix-js-sdk` secret storage and the recovery
    /// key are checked against matrix-js-sdk too).
    #[test]
    #[ignore]
    fn interop_with_matrix_sdk_crypto() {
        use std::io::BufRead;
        struct Kill(std::process::Child);
        impl Drop for Kill {
            fn drop(&mut self) {
                let _ = self.0.kill();
            }
        }
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/matrix_interop.mjs");
        let mut child = Kill(std::process::Command::new("node").arg(script).stdout(std::process::Stdio::piped()).spawn().expect("node"));
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let url = format!("http://127.0.0.1:{}", line.trim().strip_prefix("PORT ").unwrap_or_else(|| panic!("harness said {line:?}")));
        let ctl = |path: &str, body: Value| -> Value {
            let r = Http::new(Duration::from_secs(30)).call("POST", &format!("{url}{path}"), &[], Payload::Json(&body)).unwrap();
            assert_eq!(r.status, 200, "{}", r.body);
            serde_json::from_str(&r.body).unwrap()
        };
        let dir = temp_dir("mxi");
        let mut m = Matrix::new("mx", MatrixOpts { homeserver: &url, access_token: Some("SEAGENTTOKEN"), user_id: Some("@seagent:hs.test"), password: None, device_id: None, device_name: None, state: dir.join("s.json"), poll_timeout_secs: 1 }).unwrap();
        m.read_receipts = false;
        assert!(m.poll(&Cancel::new()).unwrap().is_empty(), "first sync: keys uploaded, state learned");
        assert!(ctl("/_test/read?who=carol", json!({})).as_array().unwrap().is_empty(), "carol uploads her keys");
        let room = "!e2e:hs.test";
        let bin: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        // vodozemac → seagent: Olm pre-key message carrying the Megolm key, then two Megolm events.
        ctl("/_test/send?who=bob", json!({"body": "hello from bob", "file_b64": seagent_net::crypto::b64(&bin)}));
        let got = m.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2, "{got:#?}");
        assert_eq!((got[0].text.as_str(), got[0].chat.as_str(), got[0].sender.as_str()), ("hello from bob", room, "@bob:hs.test"));
        assert_eq!(got[1].media[0].name, "from-bob.bin");
        assert_eq!(m.fetch_media(&got[1].media[0]).unwrap(), bin, "EncryptedFile from vodozemac decrypted");
        // seagent → vodozemac: Olm pre-key (seagent's outbound session) + Megolm text, edit, reaction, encrypted file.
        let f = dir.join("to-bob.bin");
        std::fs::write(&f, &bin[..777]).unwrap();
        let sent = m.send(&Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text(room, "file for bob") }).unwrap();
        m.send(&Outbound::text(room, "hi **bob**")).unwrap();
        m.edit(room, &sent.ids[0], "edited").unwrap();
        m.react(room, &sent.ids[0], "👍", false).unwrap();
        let read = ctl("/_test/read?who=bob", json!({}));
        let read = read.as_array().unwrap();
        assert_eq!(read.len(), 4, "{read:#?}");
        assert!(read.iter().all(|r| r.get("error").is_none() && r.get("plain").is_none()), "{read:#?}");
        assert_eq!(read[0]["content"]["body"], "file for bob");
        assert_eq!(seagent_net::crypto::b64_decode(read[0]["file_b64"].as_str().unwrap()).unwrap(), &bin[..777], "seagent EncryptedFile decrypted by vodozemac");
        assert_eq!(read[1]["content"]["body"], "hi **bob**");
        assert_eq!(read[2]["content"]["m.new_content"]["body"], "edited");
        assert_eq!((read[3]["type"].as_str(), read[3]["content"]["m.relates_to"]["key"].as_str()), (Some("m.reaction"), Some("👍")));
        // Carol never messaged seagent: seagent claimed her one-time key and sent an Olm pre-key message.
        let carol = ctl("/_test/read?who=carol", json!({}));
        assert_eq!(carol.as_array().unwrap().iter().map(|r| r["content"]["body"].as_str().unwrap_or("?")).collect::<Vec<_>>(), vec!["file for bob", "hi **bob**", "* edited", "?"], "{carol:#?}");
        // Second round on established sessions (normal Olm messages / same Megolm sessions).
        ctl("/_test/send?who=bob", json!({"body": "again"}));
        let got = m.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|g| g.text.as_str()).collect::<Vec<_>>(), vec!["again"]);
        m.send(&Outbound::text(room, "still here")).unwrap();
        let read = ctl("/_test/read?who=bob", json!({}));
        assert_eq!(read[0]["content"]["body"], "still here", "{read:#?}");
        // Restart from the encrypted store: same device keys, sessions still work.
        drop(m);
        let mut m2 = Matrix::new("mx", MatrixOpts { homeserver: &url, access_token: Some("SEAGENTTOKEN"), user_id: Some("@seagent:hs.test"), password: None, device_id: None, device_name: None, state: dir.join("s.json"), poll_timeout_secs: 1 }).unwrap();
        m2.read_receipts = false;
        m2.e2ee_opts.verify_from = vec!["*".into()];
        ctl("/_test/send?who=bob", json!({"body": "after restart"}));
        let got = m2.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|g| g.text.as_str()).collect::<Vec<_>>(), vec!["again", "after restart"], "uncommitted batch redelivered (same event id: not a replay)");
        m2.send(&Outbound::text(room, "back")).unwrap();
        assert_eq!(ctl("/_test/read?who=bob", json!({}))[0]["content"]["body"], "back");
        // Both sides rotated (rotation_period_msgs 4 / 2): every key share went over Olm.
        let olm: Vec<String> = serde_json::from_value(ctl("/_test/olm", json!({}))).unwrap();
        eprintln!("olm message types: {olm:?}");
        assert!(olm.iter().filter(|t| t.starts_with("@seagent")).count() >= 2 && olm.iter().filter(|t| t.starts_with("@bob")).count() >= 2, "{olm:?}");

        // Cross-signing: seagent bootstrapped through user-interactive auth (m.login.dummy) and
        // signed its device; vodozemac sees the device cross-signed by its owner.
        const BOB: &str = "@bob:hs.test";
        let st = ctl("/_test/state", json!({}));
        assert_eq!((st["uia"].as_u64(), st["backup_versions"].as_u64()), (Some(1), Some(1)), "{st}");
        ctl("/_test/xsign?who=bob", json!({}));
        let t = ctl("/_test/trust?who=bob", json!({}));
        assert_eq!((t["cross_signed_by_owner"].as_bool(), t["device_verified"].as_bool()), (Some(true), Some(false)), "{t}");
        let c = m2.crypto().unwrap();
        {
            let mut st = c.st.lock().unwrap();
            st.outdated.insert(BOB.into());
            c.ensure_devices(&mut st, &[BOB.into()], &m2.api()).unwrap();
            assert!(st.devices[BOB]["BOBDEV"].cross_signed, "vodozemac's self-signing signature checks out");
        }
        // SAS, vodozemac requesting and starting, seagent answering: same emoji / numbers.
        let sas_of = |flow: &str| c.mem.lock().unwrap().flows.get(flow).and_then(|f| f.sas).unwrap();
        let flow = ctl("/_test/verify?who=bob", json!({"action": "request"}))["flow"].as_str().unwrap().to_string();
        let mut last = json!({});
        for _ in 0..8 {
            assert!(m2.poll(&Cancel::new()).unwrap().is_empty());
            last = ctl("/_test/verify?who=bob", json!({"action": "step"}));
            if last["done"] == true {
                break;
            }
        }
        assert_eq!(last["done"], true, "{last}");
        let sas = sas_of(&flow);
        assert_eq!(last["emoji"], json!(crate::matrix_sas::emoji_indices(&sas)), "{last}");
        assert_eq!(last["decimals"], json!(crate::matrix_sas::decimals(&sas)));
        assert_eq!(last["symbols"], json!(crate::matrix_sas::emoji_indices(&sas).iter().map(|&i| crate::matrix_sas::EMOJI[i as usize].0).collect::<Vec<_>>()), "emoji table");
        assert!(c.devices(BOB)["BOBDEV"].verified && c.st.lock().unwrap().identities[BOB].verified);
        let t = ctl("/_test/trust?who=bob", json!({}));
        assert_eq!((t["device_verified"].as_bool(), t["identity_verified"].as_bool()), (Some(true), Some(true)), "vodozemac verified seagent's device and master key from seagent's MAC: {t}");
        let usk = c.st.lock().unwrap().identities["@seagent:hs.test"].user_signing.clone().unwrap();
        let st = ctl("/_test/state", json!({}));
        assert!(st["cross"][BOB]["master_key"]["signatures"]["@seagent:hs.test"][format!("ed25519:{usk}")].is_string(), "seagent signed bob's master key: {st}");
        // SAS the other way: seagent requests (to-device) and starts, vodozemac accepts.
        let flow2 = m2.request_verification(BOB, None).unwrap();
        for _ in 0..8 {
            last = ctl("/_test/verify?who=bob", json!({"action": "step"}));
            assert!(m2.poll(&Cancel::new()).unwrap().is_empty());
            if last["done"] == true && last["flow"] == flow2.as_str() {
                break;
            }
        }
        assert_eq!((last["flow"].as_str(), last["done"].as_bool()), (Some(flow2.as_str()), Some(true)), "{last}");
        assert_eq!(last["emoji"], json!(crate::matrix_sas::emoji_indices(&sas_of(&flow2))));
        // Key backup: vodozemac decrypts every session seagent backed up…
        let secret = c.st.lock().unwrap().backup.as_ref().unwrap().secret;
        let bd = ctl("/_test/backup_decrypt", json!({"key": seagent_net::crypto::b64(&secret)}));
        let sessions = bd["sessions"].as_array().unwrap();
        assert!(bd["public_ok"] == true && sessions.len() >= 4, "{bd:#}");
        assert!(sessions.iter().all(|x| x["algorithm"] == "m.megolm.v1.aes-sha2" && x["session_key"].is_string() && x["room"] == room));
        let seagent_curve = c.identity().1;
        assert!(sessions.iter().any(|x| x["sender_key"] == seagent_curve.as_str()) && sessions.iter().any(|x| x["sender_key"] != seagent_curve.as_str()), "own and received sessions");
        // …and seagent restores a session vodozemac encrypted to seagent's backup key.
        let before = ctl("/_test/state", json!({}))["restores"].as_u64().unwrap();
        ctl("/_test/send?who=bob", json!({"body": "from the backup", "hold_seagent": true, "backup_to_seagent": true}));
        let got = m2.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|g| g.text.as_str()).collect::<Vec<_>>(), vec!["from the backup"]);
        assert!(ctl("/_test/state", json!({}))["restores"].as_u64().unwrap() > before, "decrypted via the backup, not a to-device key");
        // Secret storage + recovery key, checked by matrix-js-sdk when available.
        let rk = std::fs::read_to_string(dir.join("s.recovery-key")).unwrap();
        let ss = ctl("/_test/ssss", json!({"recovery_key": rk.trim()}));
        assert!(std::env::var("MATRIX_JS_SDK").is_err() || ss["skipped"] != true);
        if ss["skipped"] != true {
            assert_eq!((ss["mac_ok"].as_bool(), ss["reencoded"].as_str()), (Some(true), Some(rk.trim())), "{ss}");
            assert_eq!(ss["secrets"]["m.megolm_backup.v1"], crate::olm::b64(&secret));
            let st = c.st.lock().unwrap();
            let cross = st.cross.as_ref().unwrap();
            assert_eq!(ss["secrets"]["m.cross_signing.self_signing"], crate::olm::b64(&cross.self_signing.unwrap()));
        }
        drop(child);
    }

    #[test]
    fn display_names_dm_creation_presence_and_uia() {
        let srv = FakeServer::start(move |req, n| {
            let p = req.path.as_str();
            if p == "/_matrix/client/v3/login" {
                return jr(json!({"access_token": "T", "user_id": ME, "device_id": "D"}));
            }
            if p.starts_with("/_matrix/client/v3/profile/") {
                return if p.contains(&enc("@zed:hs.test")) { jr(json!({"displayname": "Zed Profile"})) } else { err(404, "M_NOT_FOUND", json!({})) };
            }
            if p == "/_matrix/client/v3/createRoom" {
                return jr(json!({"room_id": "!new:hs.test"}));
            }
            if p.contains("/account_data/m.direct") {
                return if req.method == "GET" { jr(json!({"@old:hs.test": ["!olddm:hs.test"]})) } else { jr(json!({})) };
            }
            if p == "/_matrix/client/v3/keys/device_signing/upload" {
                return if req.json()["auth"]["type"] == "m.login.password" { jr(json!({})) } else { (401, vec![], json!({"session": "S1", "flows": [{"stages": ["m.login.password"]}], "params": {}}).to_string()) };
            }
            if p.contains("/send/") {
                return jr(json!({"event_id": format!("$s{n}")}));
            }
            if p.starts_with("/_matrix/client/v3/sync") && !p.contains("since=") {
                return jr(json!({"next_batch": "s1", "rooms": {"join": {"!g:hs.test": {"summary": {"m.joined_member_count": 4}}}}}));
            }
            if p.starts_with("/_matrix/client/v3/sync") && p.contains("since=s1") {
                let member = |u: &str, name: Option<&str>| json!({"type": "m.room.member", "state_key": u, "sender": u, "content": {"membership": "join", "displayname": name}});
                return jr(json!({"next_batch": "s2", "rooms": {"join": {"!g:hs.test": {"state": {"events": [member("@amy:hs.test", Some("Amy")), member("@amy2:hs.test", Some("Amy")), member("@bo:hs.test", None)]},
                    "timeline": {"events": [msg("$1", "@amy:hs.test", json!({"msgtype": "m.text", "body": "a"})), msg("$2", "@amy2:hs.test", json!({"msgtype": "m.text", "body": "b"})),
                        msg("$3", "@bo:hs.test", json!({"msgtype": "m.text", "body": "c"})), msg("$4", "@zed:hs.test", json!({"msgtype": "m.text", "body": "d"})), msg("$5", "@zed:hs.test", json!({"msgtype": "m.emote", "body": "waves"}))]}}}}}));
            }
            jr(json!({"next_batch": "s2"}))
        });
        let mut m = mx(&srv.url, temp_dir("mxn").join("s.json"), true);
        m.read_receipts = false;
        m.presence = "unavailable".into();
        m.poll(&Cancel::new()).unwrap();
        let got = m.poll(&Cancel::new()).unwrap();
        let names: Vec<&str> = got.iter().map(|g| g.sender_name.as_str()).collect();
        assert_eq!(names, ["Amy (@amy:hs.test)", "Amy (@amy2:hs.test)", "bo", "Zed Profile", "Zed Profile"], "member names, disambiguation, localpart, profile");
        assert_eq!(got[4].text, "* Zed Profile waves");
        assert_eq!(srv.requests().iter().filter(|r| r.path.contains("/profile/") && r.path.contains(&enc("@zed:hs.test"))).count(), 1, "profile cached");
        let reqs = srv.requests();
        assert!(reqs.iter().filter(|r| r.path.starts_with("/_matrix/client/v3/sync")).all(|r| r.path.contains("set_presence=unavailable")));
        assert!(reqs.iter().any(|r| r.method == "PUT" && r.path == format!("/_matrix/client/v3/presence/{}/status", enc(ME)) && r.json()["presence"] == "unavailable"));
        // user: target without a DM room → createRoom (+ m.direct), then reused.
        m.send(&Outbound::text("user:@zed:hs.test", "hello zed")).unwrap();
        m.send(&Outbound::text("user:@zed:hs.test", "again")).unwrap();
        let reqs = srv.requests();
        let created: Vec<&Req> = reqs.iter().filter(|r| r.path == "/_matrix/client/v3/createRoom").collect();
        assert_eq!(created.len(), 1);
        let c = created[0].json();
        assert_eq!((c["preset"].as_str(), c["is_direct"].as_bool(), c["invite"].clone()), (Some("trusted_private_chat"), Some(true), json!(["@zed:hs.test"])));
        assert!(c.get("initial_state").is_none(), "e2ee off: unencrypted DM");
        assert!(reqs.iter().any(|r| r.method == "PUT" && r.path.contains("/account_data/m.direct") && r.json()["@zed:hs.test"] == json!(["!new:hs.test"]) && r.json()["@old:hs.test"] == json!(["!olddm:hs.test"])));
        assert_eq!(reqs.iter().filter(|r| sent_path(r) && r.path.contains(&enc("!new:hs.test"))).count(), 2);
        assert_eq!(m.send(&Outbound::text("user:zed", "x")).unwrap_err().kind, K::Fatal);
        // User-interactive auth answered with the password.
        m.api()("POST", "/_matrix/client/v3/keys/device_signing/upload", json!({"master_key": {}})).unwrap();
        let ui = srv.requests().into_iter().filter(|r| r.path.ends_with("/device_signing/upload")).collect::<Vec<_>>();
        assert_eq!(ui.len(), 2);
        assert_eq!(ui[1].json()["auth"], json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": ME}, "password": "hunter2", "session": "S1"}));
        // Stop: offline.
        m.stop();
        assert_eq!(srv.requests().last().unwrap().json()["presence"], "offline");
    }

    #[test]
    fn reply_fallback_parsing() {
        assert_eq!(split_fallback("> <@a:b> hi\n> there\n\nok\nmore"), (Some("hi\nthere".into()), Some("@a:b".into()), "ok\nmore".into()));
        assert_eq!(split_fallback("plain"), (None, None, "plain".into()));
        assert_eq!(split_fallback("> just a quote").2, "> just a quote", "no reply part: body kept");
    }
}
