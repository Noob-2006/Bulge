//! Microsoft Teams via the Bot Framework (ported from OpenClaw `extensions/msteams`
//! and Hermes `plugins/platforms/teams`, both MIT).
//!
//! Receive: Bot Framework POSTs activities to `listen` + `path` (default
//! `/api/messages`). Every request carries `Authorization: Bearer <JWT>` signed
//! RS256 by Bot Framework; the key comes from the OpenID metadata's `jwks_uri`
//! (cached, refetched on an unknown `kid`), and `iss`, `aud` (= app id),
//! `exp`/`nbf` (5 min skew), the key's channel endorsement and the `serviceUrl`
//! claim are all checked before the body is parsed. Messages, edits
//! (`messageUpdate`), @mentions, attachments, replies, channel threads and
//! Adaptive Card button presses (`Action.Submit` → message with `value`,
//! `Action.Execute` → `invoke adaptiveCard/action`) become `Inbound`s.
//! Send: client-credentials token (cached), `POST {serviceUrl}v3/conversations/
//! {id}/activities[/{replyToId}]`, update (PUT), delete, typing, Adaptive Card
//! buttons and attachments (URL by reference, local files as data URIs).
//! The serviceUrl of each conversation is persisted so proactive sends work after
//! a restart; `user:<id>` creates the personal conversation (`POST /v3/conversations`).
//! Personal-chat files that are not small images go through a FileConsentCard
//! (`fileConsent/invoke` → PUT to the upload URL → file info card), as upstream.
//! `messageReaction` → messages (`reaction_events`); SSO (`sso_connection`):
//! `signin/tokenExchange` / `signin/verifyState` against the Bot Framework token
//! service, OAuthCard via `send_signin_card`; native streaming in personal chats
//! (typing activities with `streaminfo`, then a `final` message).
//!
//! Also home of the small JWT/JWKS helpers Google Chat shares.

use crate::http::{classify, Http, Payload};
use crate::{sleep_cancellable, write_atomic, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_OPENID: &str = "https://login.botframework.com/v1/.well-known/openidconfiguration";
pub const DEFAULT_LOGIN: &str = "https://login.microsoftonline.com";
pub const DEFAULT_SERVICE_URL: &str = "https://smba.trafficmanager.net/teams/";
pub const BF_ISSUER: &str = "https://api.botframework.com";
pub const BF_SCOPE: &str = "https://api.botframework.com/.default";
pub const MAX_MESSAGE: usize = 4000;
pub const DEFAULT_TOKEN_SERVICE: &str = "https://token.botframework.com";
const SKEW: i64 = 300;
/// Personal-chat files at least this big (or not images) go through a FileConsentCard.
const CONSENT_THRESHOLD: usize = 4 * 1024 * 1024;
const CONSENT_TTL: Duration = Duration::from_secs(5 * 60);
/// Hosts Teams hands out as consent upload targets (upstream's allowlist).
const CONSENT_HOSTS: [&str; 9] = ["sharepoint.com", "sharepoint-df.com", "sharepoint.us", "sharepoint.de", "sharepoint.cn", "storage.live.com", "onedrive.com", "1drv.ms", "graph.microsoft.com"];

// ---------------------------------------------------------------------------
// Shared JWT / JWKS / time helpers (also used by googlechat.rs).
// ---------------------------------------------------------------------------

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `2024-01-02T03:04:05.678Z` / `+01:00` offsets → unix seconds.
pub(crate) fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<i64>().ok());
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let off = match rest {
        "" | "Z" | "z" => 0,
        r if r.len() == 6 && (r.starts_with('+') || r.starts_with('-')) => {
            let sign = if r.starts_with('-') { -1 } else { 1 };
            sign * (r[1..3].parse::<i64>().ok()? * 3600 + r[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se - off)
}

/// PEM (any label) → DER bytes.
pub(crate) fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem.lines().map(str::trim).filter(|l| !l.starts_with("-----") && !l.is_empty()).collect();
    ark_net::crypto::b64_decode(&body)
}

/// Compact JWS, RS256, with a PKCS#8 private key.
pub(crate) fn sign_rs256(pkcs8_der: &[u8], header: &Value, claims: &Value) -> Result<String, String> {
    let kp = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_der).map_err(|e| format!("bad RSA private key: {e}"))?;
    let input = format!("{}.{}", ark_net::crypto::b64url(header.to_string().as_bytes()), ark_net::crypto::b64url(claims.to_string().as_bytes()));
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig).map_err(|_| "RSA signing failed".to_string())?;
    Ok(format!("{input}.{}", ark_net::crypto::b64url(&sig)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Jwk {
    pub kid: String,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    /// Bot Framework: channel ids this key may sign for.
    pub endorsements: Vec<String>,
}

struct KeyState {
    keys: Vec<Jwk>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
}

/// A JWKS endpoint (direct, or discovered from OpenID metadata), cached.
pub(crate) struct JwksCache {
    url: String,
    openid: bool,
    http: Http,
    state: Mutex<KeyState>,
    /// Keys are refetched after this long…
    pub max_age: Duration,
    /// …or on an unknown kid, at most this often.
    pub min_refresh: Duration,
}

impl JwksCache {
    pub fn new(url: &str, openid: bool) -> JwksCache {
        JwksCache {
            url: url.to_string(),
            openid,
            http: Http::new(Duration::from_secs(15)),
            state: Mutex::new(KeyState { keys: vec![], fetched: None, attempted: None }),
            max_age: Duration::from_secs(24 * 3600),
            min_refresh: Duration::from_secs(30),
        }
    }

    fn fetch(&self) -> Result<Vec<Jwk>, String> {
        let jwks_url = if self.openid {
            let meta = self.http.json("GET", &self.url, Payload::None).map_err(|e| format!("openid metadata: {}", e.message))?;
            meta["jwks_uri"].as_str().ok_or("openid metadata has no jwks_uri")?.to_string()
        } else {
            self.url.clone()
        };
        let v = self.http.json("GET", &jwks_url, Payload::None).map_err(|e| format!("jwks: {}", e.message))?;
        let keys = v["keys"].as_array().ok_or("jwks has no keys")?;
        Ok(keys
            .iter()
            .filter(|k| k["kty"].as_str().is_none_or(|t| t == "RSA"))
            .filter_map(|k| {
                Some(Jwk {
                    kid: k["kid"].as_str().unwrap_or("").to_string(),
                    n: ark_net::crypto::b64url_decode(k["n"].as_str()?.trim_end_matches('='))?,
                    e: ark_net::crypto::b64url_decode(k["e"].as_str()?.trim_end_matches('='))?,
                    endorsements: k["endorsements"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
                })
            })
            .collect())
    }

    pub fn key(&self, kid: &str) -> Result<Jwk, String> {
        let mut st = self.state.lock().unwrap();
        let fresh = st.fetched.is_some_and(|f| f.elapsed() < self.max_age);
        if fresh {
            if let Some(k) = st.keys.iter().find(|k| k.kid == kid) {
                return Ok(k.clone());
            }
        }
        if !fresh || st.attempted.is_none_or(|a| a.elapsed() >= self.min_refresh) {
            st.attempted = Some(Instant::now());
            match self.fetch() {
                Ok(keys) => {
                    st.keys = keys;
                    st.fetched = Some(Instant::now());
                }
                Err(e) if st.keys.is_empty() => return Err(e),
                Err(_) => {}
            }
        }
        st.keys.iter().find(|k| k.kid == kid).cloned().ok_or_else(|| format!("unknown signing key {kid:?}"))
    }
}

/// Verify a compact RS256 JWT: signature, `exp` (required) and `nbf` with `skew`.
/// Returns (claims, signing key); the caller checks iss/aud/extra claims.
pub(crate) fn verify_rs256(token: &str, jwks: &JwksCache, now: i64, skew: i64) -> Result<(Value, Jwk), String> {
    let mut parts = token.trim().split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return Err("malformed JWT".into()) };
    let header: Value = ark_net::crypto::b64url_decode(h).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("bad JWT header")?;
    if header["alg"] != "RS256" {
        return Err(format!("unexpected JWT alg {}", header["alg"]));
    }
    let claims: Value = ark_net::crypto::b64url_decode(p).and_then(|b| serde_json::from_slice(&b).ok()).ok_or("bad JWT payload")?;
    let sig = ark_net::crypto::b64url_decode(s).ok_or("bad JWT signature encoding")?;
    let key = jwks.key(header["kid"].as_str().unwrap_or(""))?;
    let pk = ring::signature::RsaPublicKeyComponents { n: &key.n, e: &key.e };
    pk.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, format!("{h}.{p}").as_bytes(), &sig).map_err(|_| "bad JWT signature".to_string())?;
    let exp = claims["exp"].as_i64().ok_or("JWT has no exp")?;
    if now > exp + skew {
        return Err("JWT expired".into());
    }
    if claims["nbf"].as_i64().is_some_and(|nbf| now + skew < nbf) {
        return Err("JWT not yet valid".into());
    }
    Ok((claims, key))
}

/// `aud` may be a string or an array.
pub(crate) fn aud_matches(claims: &Value, want: &str) -> bool {
    match &claims["aud"] {
        Value::String(s) => s == want,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(want)),
        _ => false,
    }
}

/// Wait on an mpsc queue for up to `timeout`; returns everything queued once something arrives.
pub(crate) fn drain<T>(rx: &Mutex<Receiver<T>>, timeout: Duration, cancel: &Cancel) -> Vec<T> {
    let rx = rx.lock().unwrap();
    let until = Instant::now() + timeout;
    while !cancel.is_cancelled() && Instant::now() < until {
        if let Ok(v) = rx.recv_timeout(Duration::from_millis(25)) {
            let mut got = vec![v];
            got.extend(rx.try_iter());
            return got;
        }
    }
    vec![]
}

pub(crate) fn kind_of_mime(mime: &str) -> MediaKind {
    let m = mime.to_ascii_lowercase();
    if m.starts_with("image/gif") {
        MediaKind::Animation
    } else if m.starts_with("image/") {
        MediaKind::Image
    } else if m.starts_with("video/") {
        MediaKind::Video
    } else if m.starts_with("audio/") {
        MediaKind::Audio
    } else {
        MediaKind::Document
    }
}

pub(crate) fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// Teams channel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ConvRef {
    service_url: String,
    #[serde(default)]
    conv_type: String,
}

/// Retry policy for connector calls: (base, max retries, longest Retry-After honoured).
#[derive(Debug, Clone, Copy)]
struct Retry(Duration, u32, Duration);

/// A local file waiting for the user to accept a FileConsentCard.
struct PendingUpload {
    conv: String,
    name: String,
    mime: String,
    data: Vec<u8>,
    card: Option<String>,
    at: Instant,
}

struct Shared {
    channel: String,
    app_id: String,
    jwks: JwksCache,
    convs: Mutex<HashMap<String, ConvRef>>,
    /// user → personal conversation created proactively.
    users: Mutex<HashMap<String, String>>,
    /// Tenant last seen on an inbound activity (proactive conversation creation).
    tenant_seen: Mutex<String>,
    state: PathBuf,
    tx: Mutex<Sender<Inbound>>,
    /// Activity ids the bot sent (reply-to-bot detection), bounded.
    sent: Mutex<(HashSet<String>, VecDeque<String>)>,
    app_password: String,
    tenant: String,
    login_base: String,
    default_service_url: String,
    http: Http,
    token: Mutex<Option<(String, Instant)>>,
    retry: Mutex<Retry>,
    uploads: Mutex<HashMap<String, PendingUpload>>,
    /// stream handle (streamId) → next streamSequence.
    streams: Mutex<HashMap<String, u32>>,
    native_streaming: bool,
    reaction_events: bool,
    sso: Option<Sso>,
}

/// Bot Framework OAuth (SSO) settings and the tokens obtained.
struct Sso {
    connection: String,
    token_url: String,
    /// (connection, user) → (token, expiration).
    tokens: Mutex<HashMap<String, (String, String)>>,
    path: PathBuf,
}

impl Shared {
    fn remember_sent(&self, id: &str) {
        let mut g = self.sent.lock().unwrap();
        if g.0.insert(id.to_string()) {
            g.1.push_back(id.to_string());
            while g.1.len() > 2000 {
                if let Some(old) = g.1.pop_front() {
                    g.0.remove(&old);
                }
            }
        }
    }
    fn is_sent(&self, id: &str) -> bool {
        self.sent.lock().unwrap().0.contains(id)
    }
    fn remember_conv(&self, id: &str, r: ConvRef) {
        let mut g = self.convs.lock().unwrap();
        if g.get(id) != Some(&r) {
            g.insert(id.to_string(), r);
            drop(g);
            self.save();
        }
    }
    fn save(&self) {
        let convs = self.convs.lock().unwrap().clone();
        let users = self.users.lock().unwrap().clone();
        let tenant = self.tenant_seen.lock().unwrap().clone();
        let _ = write_atomic(&self.state, json!({ "conversations": convs, "users": users, "tenant": tenant }).to_string().as_bytes());
    }
    fn remember_tenant(&self, t: &str) {
        let mut g = self.tenant_seen.lock().unwrap();
        if !t.is_empty() && *g != t {
            *g = t.to_string();
            drop(g);
            self.save();
        }
    }
}

pub struct Teams {
    sh: Arc<Shared>,
    rx: Mutex<Receiver<Inbound>>,
    server: Option<ark_net::httpd::Server>,
    poll_timeout: Duration,
}

pub struct TeamsOpts<'a> {
    pub app_id: &'a str,
    pub app_password: &'a str,
    pub tenant: Option<&'a str>,
    pub listen: Option<&'a str>,
    pub path: &'a str,
    pub openid_url: &'a str,
    pub login_base: &'a str,
    pub service_url: &'a str,
    pub state: PathBuf,
    pub poll_timeout: Duration,
    /// Teams streaming protocol (streaminfo) in personal chats.
    pub native_streaming: bool,
    /// Deliver `messageReaction` activities as messages.
    pub reaction_events: bool,
    /// Bot Framework OAuth connection name for SSO (`signin/tokenExchange`, `signin/verifyState`).
    pub sso_connection: Option<&'a str>,
    pub token_service: &'a str,
}

fn with_slash(u: &str) -> String {
    if u.ends_with('/') {
        u.to_string()
    } else {
        format!("{u}/")
    }
}

/// `19:x@thread.tacv2;messageid=123` → ("19:x@thread.tacv2", Some("123")).
fn split_conv(id: &str) -> (&str, Option<&str>) {
    match id.split_once(";messageid=") {
        Some((c, m)) => (c, Some(m)),
        None => (id, None),
    }
}

fn strip_at_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("<at>") {
        out.push_str(&rest[..i]);
        match rest[i..].find("</at>") {
            Some(j) => rest = rest[i + j + 5..].trim_start(),
            None => {
                rest = &rest[i..];
                break;
            }
        }
    }
    out.push_str(rest);
    out.trim().to_string()
}

/// Button `data` from an Action.Submit / Action.Execute payload.
fn card_data(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => Some(o.get("ark").and_then(|x| x.as_str()).map(str::to_string).unwrap_or_else(|| v.to_string())),
        other => Some(other.to_string()),
    }
}

fn attachments_of(act: &Value) -> Vec<Media> {
    let mut out = vec![];
    for a in act["attachments"].as_array().into_iter().flatten() {
        let ct = a["contentType"].as_str().unwrap_or("").to_ascii_lowercase();
        let url = a["contentUrl"].as_str();
        let name = a["name"].as_str().unwrap_or("").to_string();
        if ct.starts_with("application/vnd.microsoft.card") || (ct.starts_with("text/") && url.is_none()) {
            continue;
        }
        if ct == "application/vnd.microsoft.teams.file.download.info" {
            let Some(dl) = a["content"]["downloadUrl"].as_str() else { continue };
            let mime = guess_mime(&name).to_string();
            out.push(Media { kind: kind_of_mime(&mime), url: Some(dl.to_string()), mime, name, id: a["content"]["uniqueId"].as_str().map(str::to_string), ..Default::default() });
            continue;
        }
        if let Some(u) = url {
            let mime = if ct.is_empty() || ct == "image/*" { guess_mime(&name).to_string() } else { ct.clone() };
            let mime = if ct == "image/*" && mime == "application/octet-stream" { "image/png".to_string() } else { mime };
            out.push(Media { kind: kind_of_mime(&mime), url: Some(u.to_string()), mime, name, ..Default::default() });
        }
    }
    out
}

/// One Bot Framework activity → Inbound. `bot_ids` = every spelling of our id.
fn inbound_of(channel: &str, act: &Value, bot_ids: &[String], is_sent: &dyn Fn(&str) -> bool) -> Option<Inbound> {
    let typ = act["type"].as_str().unwrap_or("");
    let from = &act["from"];
    let from_id = from["id"].as_str().unwrap_or("");
    if bot_ids.iter().any(|b| b == from_id) {
        return None;
    }
    let conv = &act["conversation"];
    let (chat, conv_thread) = split_conv(conv["id"].as_str()?);
    let chat_type = match conv["conversationType"].as_str() {
        Some("groupChat") => ChatType::Group,
        Some("channel") => ChatType::Channel,
        _ => ChatType::Direct,
    };
    let id = act["id"].as_str().unwrap_or("").to_string();
    let base = Inbound {
        channel: channel.to_string(),
        chat: chat.to_string(),
        chat_type,
        chat_name: conv["name"].as_str().or_else(|| act["channelData"]["channel"]["name"].as_str()).unwrap_or("").to_string(),
        thread: conv_thread.map(str::to_string),
        sender: from["aadObjectId"].as_str().filter(|s| !s.is_empty()).unwrap_or(from_id).to_string(),
        sender_name: from["name"].as_str().unwrap_or("").to_string(),
        is_bot: from["role"] == "bot",
        ts: act["timestamp"].as_str().and_then(parse_rfc3339).unwrap_or(0),
        ..Default::default()
    };
    // Adaptive Card Action.Execute.
    if typ == "invoke" {
        if act["name"] != "adaptiveCard/action" {
            return None;
        }
        let data = card_data(&act["value"]["action"]["data"])?;
        return Some(Inbound {
            message_id: format!("cb:{id}"),
            callback: Some(Callback { id: id.clone(), data }),
            reply: act["replyToId"].as_str().map(|r| ReplyRef { id: r.to_string(), is_own: true, ..Default::default() }),
            ..base
        });
    }
    if typ != "message" && typ != "messageUpdate" {
        return None;
    }
    let raw = act["text"].as_str().unwrap_or("");
    // Action.Submit: a message whose `value` carries the card data.
    if typ == "message" && act["value"].is_object() && raw.trim().is_empty() {
        let data = card_data(&act["value"])?;
        return Some(Inbound {
            message_id: format!("cb:{id}"),
            callback: Some(Callback { id: id.clone(), data }),
            reply: act["replyToId"].as_str().map(|r| ReplyRef { id: r.to_string(), is_own: true, ..Default::default() }),
            ..base
        });
    }
    let mentions: Vec<&Value> = act["entities"].as_array().into_iter().flatten().filter(|e| e["type"] == "mention").collect();
    let mentioned = if mentions.is_empty() { raw.contains("<at>") && chat_type != ChatType::Direct } else { mentions.iter().any(|e| e["mentioned"]["id"].as_str().is_some_and(|m| bot_ids.iter().any(|b| b == m))) };
    let text = strip_at_tags(raw);
    let media = attachments_of(act);
    if text.is_empty() && media.is_empty() {
        return None;
    }
    let edited = typ == "messageUpdate";
    let reply = act["replyToId"].as_str().filter(|r| Some(*r) != conv_thread || is_sent(r)).map(|r| ReplyRef { id: r.to_string(), is_own: is_sent(r), ..Default::default() });
    Some(Inbound {
        text,
        message_id: if edited { format!("{id}:e{}", act["localTimestamp"].as_str().or(act["timestamp"].as_str()).and_then(parse_rfc3339).unwrap_or(0)) } else { id },
        media,
        mentioned,
        reply,
        edited,
        ..base
    })
}

impl Teams {
    pub fn new(id: &str, o: TeamsOpts) -> Result<Teams, String> {
        if o.app_id.trim().is_empty() || o.app_password.trim().is_empty() {
            return Err(format!("channel {id}: msteams needs app_id and app_password"));
        }
        let saved: Value = std::fs::read_to_string(&o.state).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let convs: HashMap<String, ConvRef> = serde_json::from_value(saved["conversations"].clone()).unwrap_or_default();
        let users: HashMap<String, String> = serde_json::from_value(saved["users"].clone()).unwrap_or_default();
        let sso = o.sso_connection.map(str::trim).filter(|c| !c.is_empty()).map(|c| {
            let path = o.state.with_extension("sso.json");
            let tokens = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            Sso { connection: c.to_string(), token_url: o.token_service.trim_end_matches('/').to_string(), tokens: Mutex::new(tokens), path }
        });
        let (tx, rx) = mpsc::channel();
        let sh = Arc::new(Shared {
            channel: id.to_string(),
            app_id: o.app_id.trim().to_string(),
            jwks: JwksCache::new(o.openid_url, true),
            convs: Mutex::new(convs),
            users: Mutex::new(users),
            tenant_seen: Mutex::new(saved["tenant"].as_str().unwrap_or("").to_string()),
            state: o.state,
            tx: Mutex::new(tx),
            sent: Mutex::new((HashSet::new(), VecDeque::new())),
            app_password: o.app_password.trim().to_string(),
            tenant: o.tenant.filter(|t| !t.trim().is_empty()).unwrap_or("botframework.com").trim().to_string(),
            login_base: o.login_base.trim_end_matches('/').to_string(),
            default_service_url: with_slash(o.service_url),
            http: Http::new(Duration::from_secs(30)),
            token: Mutex::new(None),
            retry: Mutex::new(Retry(Duration::from_millis(500), 3, Duration::from_secs(60))),
            uploads: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            native_streaming: o.native_streaming,
            reaction_events: o.reaction_events,
            sso,
        });
        let server = match o.listen {
            None => None,
            Some(listen) => {
                let (sh2, path) = (sh.clone(), o.path.to_string());
                let handler: ark_net::httpd::Handler = Arc::new(move |r| handle(&sh2, &path, r));
                let opts = ark_net::httpd::Opts { max_body: 1024 * 1024, ..Default::default() };
                Some(ark_net::httpd::Server::bind(listen, opts, handler).map_err(|e| format!("channel {id}: cannot listen on {listen}: {e}"))?)
            }
        };
        Ok(Teams { sh, rx: Mutex::new(rx), server, poll_timeout: o.poll_timeout })
    }

    /// Retry base delay for connector calls (tests shorten it).
    pub fn set_retry_base(&self, d: Duration) {
        self.sh.retry.lock().unwrap().0 = d;
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.server.as_ref().map(|s| s.local_addr())
    }

}

impl Shared {
    fn access_token(&self) -> Result<String, ChannelError> {
        if let Some((t, exp)) = self.token.lock().unwrap().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let url = format!("{}/{}/oauth2/v2.0/token", self.login_base, ark_net::urlencode(&self.tenant));
        let form = [("grant_type", "client_credentials"), ("client_id", self.app_id.as_str()), ("client_secret", self.app_password.as_str()), ("scope", BF_SCOPE)];
        let r = self.http.call("POST", &url, &[], Payload::Form(&form))?;
        if !(200..300).contains(&r.status) {
            let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
            let err = v["error"].as_str().unwrap_or("");
            if matches!(r.status, 400 | 401) && matches!(err, "invalid_client" | "unauthorized_client" | "invalid_request" | "invalid_grant") || matches!(r.status, 401 | 403) {
                return Err(ChannelError::new(K::Auth, format!("msteams token request rejected ({} {err})", r.status)));
            }
            return Err(classify(r.status, r.retry_after, "msteams token", &format!("{err} {}", v["error_description"].as_str().unwrap_or(""))));
        }
        let v: Value = serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, "msteams token: bad JSON"))?;
        let tok = v["access_token"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "msteams token: no access_token"))?.to_string();
        let ttl = v["expires_in"].as_u64().unwrap_or(3600).saturating_sub(120).max(30);
        *self.token.lock().unwrap() = Some((tok.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(tok)
    }

    fn service_url(&self, chat: &str) -> String {
        self.convs.lock().unwrap().get(chat).map(|c| c.service_url.clone()).unwrap_or_else(|| self.default_service_url.clone())
    }

    fn activities_url(&self, chat: &str, thread: Option<&str>, suffix: Option<&str>) -> String {
        let (base, t0) = split_conv(chat);
        let conv = match thread.or(t0) {
            Some(t) => format!("{base};messageid={t}"),
            None => base.to_string(),
        };
        let mut u = format!("{}v3/conversations/{}/activities", self.service_url(base), ark_net::urlencode(&conv));
        if let Some(s) = suffix {
            u.push('/');
            u.push_str(&ark_net::urlencode(s));
        }
        u
    }

    /// Connector call: bearer token (refreshed once on 401), retries on 429/5xx.
    fn connector(&self, method: &str, url: &str, body: Option<&Value>) -> Result<Value, ChannelError> {
        let mut attempt = 0;
        let mut refreshed = false;
        loop {
            let tok = self.access_token()?;
            let http = self.http.clone().bearer(&tok);
            let err = match http.call(method, url, &[], body.map_or(Payload::None, Payload::Json)) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null)),
                Ok(r) if r.status == 401 && !refreshed => {
                    refreshed = true;
                    *self.token.lock().unwrap() = None;
                    continue;
                }
                Ok(r) => teams_error(r.status, r.retry_after, method, &r.body),
                Err(e) => e,
            };
            let Retry(base, max, max_wait) = *self.retry.lock().unwrap();
            if !err.is_retryable() || attempt >= max {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => base * 2u32.pow(attempt),
            };
            sleep_cancellable(wait, &Cancel::new());
            attempt += 1;
        }
    }

    fn post_activity(&self, out: &Outbound, act: &Value, reply_to: Option<&str>) -> Result<String, ChannelError> {
        let r = match reply_to {
            Some(rt) => match self.connector("POST", &self.activities_url(&out.chat, out.thread.as_deref(), Some(rt)), Some(act)) {
                // Group chats reject threaded replies; fall back to a plain send.
                Err(e) if e.kind == K::Protocol => self.connector("POST", &self.activities_url(&out.chat, out.thread.as_deref(), None), Some(act))?,
                r => r?,
            },
            None => self.connector("POST", &self.activities_url(&out.chat, out.thread.as_deref(), None), Some(act))?,
        };
        let id = r["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            self.remember_sent(&id);
        }
        Ok(id)
    }

    fn is_personal(&self, chat: &str) -> bool {
        let c = split_conv(chat).0;
        match self.convs.lock().unwrap().get(c) {
            Some(r) if !r.conv_type.is_empty() => r.conv_type == "personal",
            _ => c.starts_with("a:"),
        }
    }

    /// `user:<id>` → the bot's personal conversation with that user, created once with
    /// `POST /v3/conversations` (proactive messaging) and remembered. `<id>` is a Bot
    /// Framework id (`29:…`) or an AAD object id.
    fn resolve_chat(&self, chat: &str) -> Result<String, ChannelError> {
        let Some(user) = chat.strip_prefix("user:").map(str::trim).filter(|u| !u.is_empty()) else { return Ok(chat.to_string()) };
        if let Some(c) = self.users.lock().unwrap().get(user) {
            return Ok(c.clone());
        }
        let seen = self.tenant_seen.lock().unwrap().clone();
        let tenant = if !seen.is_empty() { seen } else if self.tenant != "botframework.com" { self.tenant.clone() } else { String::new() };
        let member = if user.contains(':') { json!({"id": user}) } else { json!({"id": format!("8:orgid:{user}"), "aadObjectId": user}) };
        let mut body = json!({"bot": {"id": format!("28:{}", self.app_id)}, "members": [member], "isGroup": false});
        if !tenant.is_empty() {
            body["tenantId"] = json!(tenant);
            body["channelData"] = json!({"tenant": {"id": tenant}});
        }
        let r = self.connector("POST", &format!("{}v3/conversations", self.default_service_url), Some(&body))?;
        let id = r["id"].as_str().filter(|i| !i.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "msteams create conversation: no id"))?.to_string();
        let svc = r["serviceUrl"].as_str().map(with_slash).unwrap_or_else(|| self.default_service_url.clone());
        self.users.lock().unwrap().insert(user.to_string(), id.clone());
        self.remember_conv(&id, ConvRef { service_url: svc, conv_type: "personal".into() });
        self.save();
        Ok(id)
    }

    /// Park a file and post a FileConsentCard; the bytes go up when the user accepts.
    fn consent_card(&self, chat: &str, name: &str, mime: &str, data: Vec<u8>) -> Result<String, ChannelError> {
        let upload_id = ark_net::crypto::hex(&ark_net::crypto::random_bytes(12));
        let ctx = json!({"filename": name, "uploadId": upload_id});
        let card = json!({"contentType": "application/vnd.microsoft.teams.card.file.consent", "name": name,
            "content": {"description": format!("File: {name}"), "sizeInBytes": data.len(), "acceptContext": ctx, "declineContext": ctx}});
        {
            let mut u = self.uploads.lock().unwrap();
            u.retain(|_, p| p.at.elapsed() < CONSENT_TTL);
            u.insert(upload_id.clone(), PendingUpload { conv: split_conv(chat).0.to_string(), name: name.to_string(), mime: mime.to_string(), data, card: None, at: Instant::now() });
        }
        let out = Outbound::text(chat, "");
        let id = self.post_activity(&out, &json!({"type": "message", "attachments": [card]}), None)?;
        if let Some(p) = self.uploads.lock().unwrap().get_mut(&upload_id) {
            p.card = Some(id.clone());
        }
        Ok(id)
    }

    /// `fileConsent/invoke`: on accept PUT the parked bytes to the upload URL Teams gave
    /// and replace the consent card with a file info card.
    fn file_consent(&self, act: &Value) {
        let v = &act["value"];
        if v["type"] != "fileUpload" {
            return;
        }
        let conv = split_conv(act["conversation"]["id"].as_str().unwrap_or("")).0.to_string();
        let upload_id = v["context"]["uploadId"].as_str().unwrap_or("");
        let pending = self.uploads.lock().unwrap().remove(upload_id).filter(|p| p.at.elapsed() < CONSENT_TTL);
        if v["action"] != "accept" {
            return;
        }
        let out = Outbound::text(&conv, "");
        let say = |t: &str| {
            let _ = self.post_activity(&out, &json!({"type": "message", "text": t}), None);
        };
        let info = &v["uploadInfo"];
        let (Some(p), Some(url)) = (pending.filter(|p| p.conv == conv), info["uploadUrl"].as_str()) else {
            return say("The file upload request has expired. Please try sending the file again.");
        };
        let put = || -> Result<(), ChannelError> {
            consent_url_ok(url).map_err(|e| ChannelError::new(K::Protocol, e))?;
            let range = format!("bytes 0-{}/{}", p.data.len().saturating_sub(1), p.data.len());
            let ctype = if p.mime.is_empty() { "application/octet-stream" } else { p.mime.as_str() };
            let r = Http::new(Duration::from_secs(120)).call("PUT", url, &[("content-range", &range)], Payload::Raw(ctype, &p.data))?;
            if !(200..300).contains(&r.status) {
                return Err(classify(r.status, r.retry_after, "msteams consent upload", ""));
            }
            Ok(())
        };
        if let Err(e) = put() {
            eprintln!("ark: {}: file upload for {} failed: {e}", self.channel, p.name);
            return say("File upload failed. Please try again.");
        }
        let card = json!({"contentType": "application/vnd.microsoft.teams.card.file.info", "contentUrl": info["contentUrl"], "name": info["name"].as_str().unwrap_or(&p.name),
            "content": {"uniqueId": info["uniqueId"], "fileType": info["fileType"]}});
        let mut act = json!({"type": "message", "attachments": [card]});
        let updated = p.card.as_deref().is_some_and(|id| {
            act["id"] = json!(id);
            self.connector("PUT", &self.activities_url(&conv, None, Some(id)), Some(&act)).is_ok()
        });
        if !updated {
            if let Some(o) = act.as_object_mut() {
                o.remove("id");
            }
            let _ = self.post_activity(&out, &act, None);
        }
    }

    /// Bot Framework token service call (bot token); `Ok(None)` when it has no token.
    fn user_token_call(&self, method: &str, url: &str, body: Option<&Value>) -> Result<Option<(String, String)>, ChannelError> {
        let r = self.http.clone().bearer(&self.access_token()?).call(method, url, &[], body.map_or(Payload::None, Payload::Json))?;
        if !(200..300).contains(&r.status) {
            return if matches!(r.status, 400 | 404 | 412) { Ok(None) } else { Err(classify(r.status, r.retry_after, "msteams token service", "")) };
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        Ok(v["token"].as_str().filter(|t| !t.is_empty()).map(|t| (t.to_string(), v["expiration"].as_str().unwrap_or("").to_string())))
    }

    /// `signin/tokenExchange` / `signin/verifyState`: ask the token service (cached token,
    /// then exchange / magic code) and keep the user's token. 412 / 404 tell Teams to fall
    /// back to the sign-in card, as the Bot Framework SDK answers.
    fn signin(&self, act: &Value) -> ark_net::httpd::Response {
        use ark_net::httpd::Response;
        let Some(sso) = &self.sso else { return Response::json(200, &"{}") };
        let user = act["from"]["id"].as_str().unwrap_or("");
        let conn = act["value"]["connectionName"].as_str().filter(|c| !c.is_empty()).unwrap_or(&sso.connection).to_string();
        let channel_id = act["channelId"].as_str().unwrap_or("msteams");
        let q = format!("userId={}&connectionName={}&channelId={}", ark_net::urlencode(user), ark_net::urlencode(&conn), ark_net::urlencode(channel_id));
        let exchange = act["name"] == "signin/tokenExchange";
        let mut got = self.user_token_call("GET", &format!("{}/api/usertoken/GetToken?{q}", sso.token_url), None);
        if matches!(got, Ok(None)) {
            got = if exchange {
                let body = json!({"token": act["value"]["token"]});
                self.user_token_call("POST", &format!("{}/api/usertoken/exchange?{q}", sso.token_url), Some(&body))
            } else {
                let code = act["value"]["state"].as_str().unwrap_or("");
                self.user_token_call("GET", &format!("{}/api/usertoken/GetToken?{q}&code={}", sso.token_url, ark_net::urlencode(code)), None)
            };
        }
        match got {
            Ok(Some((token, exp))) => {
                let mut t = sso.tokens.lock().unwrap();
                for u in [Some(user), act["from"]["aadObjectId"].as_str()].into_iter().flatten().filter(|u| !u.is_empty()) {
                    t.insert(format!("{conn}\u{1f}{u}"), (token.clone(), exp.clone()));
                }
                let _ = crate::write_private(&sso.path, serde_json::to_string(&*t).unwrap_or_default().as_bytes());
                Response::json(200, &"{}")
            }
            Ok(None) | Err(_) if exchange => Response::json(412, &json!({"id": act["value"]["id"], "connectionName": conn, "failureDetail": "The bot is unable to exchange token. Proceed with regular login."}).to_string()),
            _ => Response::json(404, &"{}"),
        }
    }
}

/// Consent upload targets must be https on a Microsoft storage host resolving to public
/// addresses (upstream's SSRF guard).
fn consent_url_ok(url: &str) -> Result<(), String> {
    let u = ark_net::Url::parse(url).map_err(|_| "consent upload URL is not a valid URL".to_string())?;
    let host = u.host.to_ascii_lowercase();
    if cfg!(test) && host == "127.0.0.1" {
        return Ok(());
    }
    if !url.starts_with("https://") {
        return Err("consent upload URL must use https".into());
    }
    if !CONSENT_HOSTS.iter().any(|h| host == *h || host.ends_with(&format!(".{h}"))) {
        return Err(format!("consent upload host {host} is not allowed"));
    }
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::IpAddr> = (host.as_str(), 443).to_socket_addrs().map_err(|_| format!("cannot resolve {host}"))?.map(|a| a.ip()).collect();
    consent_addresses_ok(&host, &addrs)
}

/// The address half of [`consent_url_ok`]: no private, loopback, link-local or metadata
/// answer. Delegates to `ark_security::url_safety` (A14) so the Teams consent upload cannot
/// drift away from the one SSRF table the rest of the tree uses.
fn consent_addresses_ok(host: &str, addrs: &[std::net::IpAddr]) -> Result<(), String> {
    if let Some(bad) = addrs.iter().find(|ip| ark_security::url_safety::is_blocked_ip(**ip)) {
        return Err(format!("consent upload host {host} resolves to a private address ({bad})"));
    }
    Ok(())
}

fn teams_error(status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let code = v["error"]["code"].as_str().unwrap_or("");
    const GONE: [&str; 6] = ["ConversationNotFound", "BotNotInConversationRoster", "BotDisabledByAdmin", "ConversationBlockedByUser", "UserNotFound", "MessageNotFound"];
    if GONE.contains(&code) || status == 403 && code != "Unauthorized" {
        return ChannelError::new(K::NotFound, format!("msteams {what}: HTTP {status} {code}"));
    }
    classify(status, retry_after, &format!("msteams {what}"), &format!("{code} {}", v["error"]["message"].as_str().unwrap_or("")))
}

/// `messageReaction` → one message per reaction (`reaction_events`), like upstream's system events.
fn reactions_of(channel: &str, act: &Value, is_sent: &dyn Fn(&str) -> bool) -> Vec<Inbound> {
    let conv = act["conversation"]["id"].as_str().unwrap_or("");
    let (chat, thread) = split_conv(conv);
    let from = &act["from"];
    let sender = from["aadObjectId"].as_str().filter(|s| !s.is_empty()).or(from["id"].as_str()).unwrap_or("").to_string();
    let name = from["name"].as_str().unwrap_or(&sender).to_string();
    let target = act["replyToId"].as_str().unwrap_or("").to_string();
    let chat_type = match act["conversation"]["conversationType"].as_str() {
        Some("groupChat") => ChatType::Group,
        Some("channel") => ChatType::Channel,
        _ => ChatType::Direct,
    };
    let mut out = vec![];
    for (key, added) in [("reactionsAdded", true), ("reactionsRemoved", false)] {
        for r in act[key].as_array().into_iter().flatten() {
            let ty = r["type"].as_str().unwrap_or("unknown");
            let emoji = match ty.trim().to_ascii_lowercase().as_str() {
                "like" => "👍",
                "heart" => "❤️",
                "laugh" => "😆",
                "surprised" => "😮",
                "sad" => "😢",
                "angry" => "😡",
                _ => ty,
            };
            out.push(Inbound {
                channel: channel.to_string(),
                chat: chat.to_string(),
                chat_type,
                thread: thread.map(str::to_string),
                sender: sender.clone(),
                sender_name: name.clone(),
                text: if added { format!("Teams reaction {emoji} added by {name} on message {target}") } else { format!("Teams reaction {emoji} removed by {name} from message {target}") },
                message_id: format!("r:{target}:{sender}:{ty}:{}", if added { "+" } else { "-" }),
                ts: act["timestamp"].as_str().and_then(parse_rfc3339).unwrap_or(0),
                reply: (!target.is_empty()).then(|| ReplyRef { id: target.clone(), is_own: is_sent(&target), ..Default::default() }),
                ..Default::default()
            });
        }
    }
    out
}

fn handle(sh: &Arc<Shared>, path: &str, r: ark_net::httpd::Request) -> ark_net::httpd::Response {
    use ark_net::httpd::Response;
    if r.path != path {
        return Response::text(404, "not found");
    }
    if r.method != "POST" {
        return Response::text(405, "use POST");
    }
    let Some(tok) = r.bearer() else { return Response::text(401, "missing bearer token") };
    let (claims, key) = match verify_rs256(tok, &sh.jwks, now_secs(), SKEW) {
        Ok(c) => c,
        Err(e) => return Response::text(401, &format!("bad token: {e}")),
    };
    if claims["iss"] != BF_ISSUER || !aud_matches(&claims, &sh.app_id) {
        return Response::text(401, "bad token issuer or audience");
    }
    let act: Value = match serde_json::from_slice(&r.body) {
        Ok(v @ Value::Object(_)) => v,
        _ => return Response::text(400, "bad activity"),
    };
    let service_url = act["serviceUrl"].as_str().unwrap_or("");
    if let Some(claimed) = claims["serviceurl"].as_str().or(claims["serviceUrl"].as_str()) {
        if with_slash(claimed) != with_slash(service_url) {
            return Response::text(401, "serviceUrl does not match token");
        }
    }
    let channel_id = act["channelId"].as_str().unwrap_or("");
    if !key.endorsements.is_empty() && !key.endorsements.iter().any(|e| e == channel_id) {
        return Response::text(401, "signing key not endorsed for this channel");
    }
    if let (Some(conv), false) = (act["conversation"]["id"].as_str(), service_url.is_empty()) {
        sh.remember_conv(split_conv(conv).0, ConvRef { service_url: with_slash(service_url), conv_type: act["conversation"]["conversationType"].as_str().unwrap_or("").to_string() });
    }
    sh.remember_tenant(act["conversation"]["tenantId"].as_str().or(act["channelData"]["tenant"]["id"].as_str()).unwrap_or(""));
    match (act["type"].as_str(), act["name"].as_str()) {
        (Some("invoke"), Some("fileConsent/invoke")) => {
            // Answer at once; the upload runs after the acknowledgement, as upstream does.
            let sh2 = sh.clone();
            std::thread::spawn(move || sh2.file_consent(&act));
            return Response::json(200, &"{}");
        }
        (Some("invoke"), Some("signin/tokenExchange" | "signin/verifyState")) => return sh.signin(&act),
        (Some("messageReaction"), _) => {
            if sh.reaction_events {
                for m in reactions_of(&sh.channel, &act, &|id| sh.is_sent(id)) {
                    if sh.tx.lock().unwrap().send(m).is_err() {
                        return Response::text(503, "channel closed");
                    }
                }
            }
            return Response::text(200, "");
        }
        _ => {}
    }
    let mut bot_ids = vec![sh.app_id.clone(), format!("28:{}", sh.app_id)];
    if let Some(rid) = act["recipient"]["id"].as_str() {
        bot_ids.push(rid.to_string());
    }
    let is_invoke = act["type"] == "invoke";
    if let Some(m) = inbound_of(&sh.channel, &act, &bot_ids, &|id| sh.is_sent(id)) {
        if sh.tx.lock().unwrap().send(m).is_err() {
            return Response::text(503, "channel closed");
        }
    }
    if is_invoke {
        return Response::json(200, &json!({"statusCode": 200, "type": "application/vnd.microsoft.activity.message", "value": "OK"}).to_string());
    }
    Response::text(200, "")
}

fn adaptive_card(rows: &[Vec<crate::Button>]) -> Value {
    let actions: Vec<Value> = rows
        .iter()
        .flatten()
        .map(|b| match &b.url {
            Some(u) => json!({"type": "Action.OpenUrl", "title": b.label, "url": u}),
            None => json!({"type": "Action.Submit", "title": b.label, "data": {"ark": b.data}}),
        })
        .collect();
    json!({"contentType": "application/vnd.microsoft.card.adaptive", "content": {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.4", "body": [], "actions": actions}})
}

fn media_attachment(m: &Media) -> Result<Value, ChannelError> {
    match (&m.path, &m.url) {
        (Some(p), _) => {
            let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
            let name = std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
            let mime = if m.mime.is_empty() { guess_mime(&name).to_string() } else { m.mime.clone() };
            Ok(json!({"contentType": mime, "contentUrl": format!("data:{mime};base64,{}", ark_net::crypto::b64(&data)), "name": if m.name.is_empty() { name } else { m.name.clone() }}))
        }
        (None, Some(u)) => {
            let name = if m.name.is_empty() { u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string() } else { m.name.clone() };
            let mime = if m.mime.is_empty() { guess_mime(&name).to_string() } else { m.mime.clone() };
            Ok(json!({"contentType": mime, "contentUrl": u, "name": name}))
        }
        _ => Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
    }
}

impl Teams {
    /// Post an OAuthCard for the configured SSO connection (sign-in resource from the
    /// Bot Framework token service; Teams tries silent token exchange first).
    pub fn send_signin_card(&self, chat: &str, text: &str) -> Result<String, ChannelError> {
        let sh = &self.sh;
        let sso = sh.sso.as_ref().ok_or_else(|| ChannelError::new(K::Fatal, "msteams: sso_connection is not configured"))?;
        let chat = sh.resolve_chat(chat)?;
        let conv = split_conv(&chat).0;
        let state = json!({"ConnectionName": sso.connection, "Conversation": {"channelId": "msteams", "serviceUrl": sh.service_url(conv), "conversation": {"id": conv}, "bot": {"id": format!("28:{}", sh.app_id)}}, "MsAppId": sh.app_id});
        let url = format!("{}/api/botsignin/GetSignInResource?state={}", sso.token_url, ark_net::urlencode(&ark_net::crypto::b64(state.to_string().as_bytes())));
        let r = sh.http.clone().bearer(&sh.access_token()?).call("GET", &url, &[], Payload::None)?;
        if !(200..300).contains(&r.status) {
            return Err(teams_error(r.status, r.retry_after, "sign-in resource", &r.body));
        }
        let res: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let link = res["signInLink"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "msteams sign-in resource: no signInLink"))?;
        let mut content = json!({"text": text, "connectionName": sso.connection, "buttons": [{"type": "signin", "title": "Sign in", "value": link}]});
        if res["tokenExchangeResource"].is_object() {
            content["tokenExchangeResource"] = res["tokenExchangeResource"].clone();
        }
        if res["tokenPostResource"].is_object() {
            content["tokenPostResource"] = res["tokenPostResource"].clone();
        }
        let act = json!({"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.oauth", "content": content}]});
        sh.post_activity(&Outbound::text(&chat, ""), &act, None)
    }

    /// The SSO token stored for a user (Bot Framework or AAD object id) and its expiration.
    pub fn user_token(&self, user: &str) -> Option<(String, String)> {
        let sso = self.sh.sso.as_ref()?;
        sso.tokens.lock().unwrap().get(&format!("{}\u{1f}{user}", sso.connection)).cloned()
    }

    fn streaminfo(&self, chat: &str, act: Value) -> Result<Value, ChannelError> {
        self.sh.connector("POST", &self.sh.activities_url(chat, None, None), Some(&act))
    }
}

impl Channel for Teams {
    fn id(&self) -> &str {
        &self.sh.channel
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Channel],
            media: true,
            reply: true,
            threads: true,
            reactions: 0,
            edit: true,
            delete: true,
            typing: true,
            buttons: true,
            polls: false,
            native_commands: false,
            streaming: if self.sh.native_streaming { Streaming::Native } else { Streaming::Edit },
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    /// Teams streaming (personal chats only): typing activities carrying `streaminfo`
    /// (`streamType: streaming`, rising `streamSequence`, cumulative text), closed by a
    /// message with `streamType: final`. Elsewhere the host falls back to edit-in-place.
    fn stream_begin(&self, out: &Outbound) -> Result<Option<String>, ChannelError> {
        if !self.sh.native_streaming || !self.sh.is_personal(&out.chat) || out.thread.is_some() {
            return Ok(None);
        }
        let r = self.streaminfo(&out.chat, json!({"type": "typing", "text": out.text, "entities": [{"type": "streaminfo", "streamType": "streaming", "streamSequence": 1}]}))?;
        let Some(id) = r["id"].as_str().filter(|i| !i.is_empty()) else { return Ok(None) };
        self.sh.streams.lock().unwrap().insert(id.to_string(), 2);
        Ok(Some(id.to_string()))
    }
    fn stream_update(&self, chat: &str, h: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        let seq = {
            let mut g = self.sh.streams.lock().unwrap();
            let n = g.entry(h.to_string()).or_insert(2);
            *n += 1;
            *n - 1
        };
        self.streaminfo(chat, json!({"type": "typing", "text": text, "entities": [{"type": "streaminfo", "streamId": h, "streamType": "streaming", "streamSequence": seq}]})).map(|_| ())
    }
    fn stream_finish(&self, chat: &str, h: &str, text: &str, _delta: &str) -> Result<(), ChannelError> {
        self.sh.streams.lock().unwrap().remove(h);
        self.streaminfo(chat, json!({"type": "message", "text": text, "textFormat": "markdown", "entities": [{"type": "streaminfo", "streamId": h, "streamType": "final"}]}))?;
        self.sh.remember_sent(h);
        Ok(())
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if self.server.is_none() {
            sleep_cancellable(self.poll_timeout, cancel);
            return Ok(vec![]);
        }
        Ok(drain(&self.rx, self.poll_timeout, cancel))
    }

    /// `chat` may be `user:<id>` (a personal conversation is created). Local files in
    /// personal chats that are not small images go through a FileConsentCard (as upstream);
    /// everywhere else they ride inline as data URIs.
    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let sh = &self.sh;
        let chat = sh.resolve_chat(&out.chat)?;
        let out = &Outbound { chat, ..out.clone() };
        let mut sent = Sent::default();
        let fmt = if out.format == TextFormat::Markdown { "markdown" } else { "plain" };
        let personal = sh.is_personal(&out.chat);
        let mut attachments: Vec<Value> = vec![];
        let mut consent: Vec<(String, String, Vec<u8>)> = vec![];
        for m in &out.media {
            if let (true, Some(p)) = (personal, &m.path) {
                let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                let name = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
                let mime = if m.mime.is_empty() { guess_mime(&name).to_string() } else { m.mime.clone() };
                if !mime.starts_with("image/") || data.len() >= CONSENT_THRESHOLD {
                    consent.push((name, mime, data));
                    continue;
                }
            }
            attachments.push(media_attachment(m)?);
        }
        let pieces = if out.text.trim().is_empty() { vec![String::new()] } else { crate::chunk::split(&out.text, MAX_MESSAGE, LenUnit::Chars) };
        let n = pieces.len();
        for (i, piece) in pieces.into_iter().enumerate() {
            let last = i + 1 == n;
            let mut atts: Vec<Value> = if i == 0 { attachments.clone() } else { vec![] };
            if last && !out.buttons.is_empty() {
                atts.push(adaptive_card(&out.buttons));
            }
            if piece.is_empty() && atts.is_empty() {
                continue;
            }
            let mut act = json!({"type": "message", "text": piece, "textFormat": fmt});
            if !atts.is_empty() {
                act["attachments"] = json!(atts);
            }
            if out.silent {
                act["channelData"] = json!({"notification": {"alert": false}});
            }
            let id = sh.post_activity(out, &act, if i == 0 { out.reply_to.as_deref() } else { None })?;
            sent.ids.push(id);
        }
        for (name, mime, data) in consent {
            sent.ids.push(sh.consent_card(&out.chat, &name, &mime, data)?);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let act = json!({"type": "message", "id": message_id, "text": text, "textFormat": "markdown"});
        self.sh.connector("PUT", &self.sh.activities_url(chat, None, Some(message_id)), Some(&act)).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.sh.connector("DELETE", &self.sh.activities_url(chat, None, Some(message_id)), None).map(|_| ())
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let chat = self.sh.resolve_chat(chat)?;
        self.sh.connector("POST", &self.sh.activities_url(&chat, thread, None), Some(&json!({"type": "typing"}))).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "attachment without url"))?;
        if let Some(rest) = url.strip_prefix("data:") {
            let (_, b64) = rest.split_once(";base64,").ok_or_else(|| ChannelError::new(K::Protocol, "unsupported data URI"))?;
            return ark_net::crypto::b64_decode(b64).ok_or_else(|| ChannelError::new(K::Protocol, "bad data URI"));
        }
        // Connector-hosted attachments need the bot token; SharePoint download URLs are pre-authorised.
        let host = ark_net::Url::parse(url).map(|u| u.host).unwrap_or_default();
        let known = self.sh.convs.lock().unwrap().values().any(|c| ark_net::Url::parse(&c.service_url).is_ok_and(|s| s.host == host));
        let needs_auth = known || host.ends_with("botframework.com") || host.ends_with("trafficmanager.net") || host == ark_net::Url::parse(&self.sh.default_service_url).map(|u| u.host).unwrap_or_default();
        if needs_auth {
            let tok = self.sh.access_token()?;
            let auth = format!("Bearer {tok}");
            crate::http::get_bytes(url, &[("authorization", &auth)], 50 * 1024 * 1024)
        } else {
            crate::http::get_bytes(url, &[], 50 * 1024 * 1024)
        }
    }
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    "/api/messages".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(alias = "client_id", alias = "appId")]
    app_id: String,
    #[serde(alias = "client_secret", alias = "appPassword")]
    app_password: String,
    #[serde(default, alias = "tenant_id", alias = "tenantId")]
    tenant: Option<String>,
    /// Local address Bot Framework's messaging endpoint reaches.
    #[serde(default)]
    listen: Option<String>,
    #[serde(default = "d_path")]
    path: String,
    #[serde(default)]
    openid_url: Option<String>,
    #[serde(default)]
    login_url: Option<String>,
    /// For proactive sends to conversations not seen yet.
    #[serde(default)]
    service_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Teams streaming protocol in personal chats (default on); elsewhere edit-in-place.
    #[serde(default = "d_true")]
    native_streaming: bool,
    #[serde(default)]
    reaction_events: bool,
    /// Bot Framework OAuth connection name: enables SSO token exchange / verifyState.
    #[serde(default)]
    sso_connection: Option<String>,
    #[serde(default)]
    token_service_url: Option<String>,
}

fn d_true() -> bool {
    true
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let app_id = ctx.secret("app_id", &st.app_id)?;
    let pw = ctx.secret("app_password", &st.app_password)?;
    let tenant = ctx.opt_secret("tenant", &st.tenant)?;
    let t = Teams::new(
        ctx.name,
        TeamsOpts {
            app_id: &app_id,
            app_password: &pw,
            tenant: tenant.as_deref(),
            listen: st.listen.as_deref(),
            path: &st.path,
            openid_url: st.openid_url.as_deref().unwrap_or(DEFAULT_OPENID),
            login_base: st.login_url.as_deref().unwrap_or(DEFAULT_LOGIN),
            service_url: st.service_url.as_deref().unwrap_or(DEFAULT_SERVICE_URL),
            state: ctx.state("msteams.json"),
            poll_timeout: Duration::from_secs(st.poll_timeout_secs),
            native_streaming: st.native_streaming,
            reaction_events: st.reaction_events,
            sso_connection: st.sso_connection.as_deref(),
            token_service: st.token_service_url.as_deref().unwrap_or(DEFAULT_TOKEN_SERVICE),
        },
    )?;
    Ok(Arc::new(t))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    /// Throwaway 2048-bit key generated for these tests only.
    pub(crate) const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2/KHw1aH2MxNI\n\
UJ9kFXv0ub7/brvLHDeq6R12StyuxBpGGyKNrjvvRSaA2XUx3ZKnwnFCopVu9zg7\n\
bwscPKgWc1nhteYUfeZtjcw7A4voC+E68frqs4y8R+tWb7UwXSS3oLQHYSmEybz5\n\
C2yUyB1Ohn2w0+g4xoewLtI/i/LkJEN3OZmy8EjxoUh5wdVCp7VVCAfMS7sEUnvp\n\
iAS2GxmSfL8peaJLhliH9UaU+Yi2IFaWK5oEuk0dl0EQwC5LSGpfFX+NIfsg0Nr+\n\
E66VKLFtjIMboiCzRB8gNUtUebESK9Hiy//aS7m/jGVBjd4LVyV9swNXJcW659ST\n\
K2dt+xxfAgMBAAECggEAPVMaRJecAWIpnq0iVczbb29Got0uA4pP36/jZ078eXeQ\n\
JJmYcWoIfQ4sMrduDsmmiiFgisfpE7i3eDelPg/X9zouT7YBxzFQZbvFS6vLGffN\n\
Qk9xW3HUAw+JP70NOImmsgGiA+0cmHtxoPciqxQLulLZUccaxthGBhYS8SgKPUmV\n\
UvmmGZr+h353zKw/608g73+9RYDS901I44xI5bXjRnFk0G9EIn+nl3Ev5meZtD5Z\n\
Yr0YbI9oxUYTIldC3iaiaAhQF+EBXHfOM5kElqarBw2sxEPQZzUDVDsIUUkOubl4\n\
BjEQi9Y5c0o8vZF6kfk0axqqKoz5IUzHhrAvPN0r/QKBgQD6aFU2XyOkWANhPPJ7\n\
2dQaGZFkJtSFRnJRwudHlpwf50rkW+p4eMKI7hTSR5Y1cSteFReck9QeRZEQrTve\n\
Pg+iwXwWtjZOXHKQ8PpqVh87wkl4z0divAPO8WO5oJLKvynZE23gu1Rq3pdz5bfy\n\
j7KxMULei8EtbaMnMNzZKqWX0wKBgQC7EtUDZGJk03bOfyXW3WyAxbio6XJJJx4t\n\
NOX077jGq9J6msk7NGa9NoypzoWBHPE4zsT2YzMnQ/gsko39hkQnsQ5PFYK05y6U\n\
m6U25IWIUkSrFWKeja+/Q8P6YP8UTvv1426SIQCtC4PyPbJ/Hteiv7BMpJDxWSQC\n\
JQfG/yA9xQKBgQCostF1p/LjLUhZoi3aso3qZ39D8cULZMJvwtb9q8HS3IfgAOyd\n\
7P1iMsNkR0YzCuMkpyEZI56sJkHs8kh7GWR/ScrHokpD0JR+gVqzeQHhyKqm8T4u\n\
jmwiZw3AaSV74f3XePd1h77/oKZ4NjMO/zBrn7xlIdIrQMnCBXFD/S9CcQKBgAwd\n\
SBYUJhsJZqQwr66eYCxmoXKuy2vZUKb0yf92lqym69Zst6NR3WVbZviIGzUlPqnD\n\
GhYqjmF4kVWxl+hXDYrUeGy+o9w7LFULT0OiwNL3IONDW0ORQVRNex93sI0MIFzo\n\
AX0NDhImsMC7Jhf9U1GCwFP2RDyc3SwWYc6NLvVRAoGARVZHx/EaXvh4wNncaa3p\n\
dcdQ8Dk5dDjcC7zOdcg090oTTduj+U6DZUp2xPSOAR1VUfLzVLaFWiw0XUTydk5z\n\
NnXEYUY0PQGN3NA6Dij0cKSyOxgdTrGH3SDzQ+5bXgUcAwdinAmGwL3cfydreVWd\n\
rBfXU4bsOl7nzb+HXQM2ROw=\n\
-----END PRIVATE KEY-----\n\
";

    pub(crate) fn test_der() -> Vec<u8> {
        pem_to_der(TEST_KEY_PEM).unwrap()
    }

    /// JWKS JSON for the test key under `kid`.
    pub(crate) fn test_jwk(kid: &str, endorsements: &[&str]) -> Value {
        let kp = ring::signature::RsaKeyPair::from_pkcs8(&test_der()).unwrap();
        let c: ring::rsa::PublicKeyComponents<Vec<u8>> = kp.public().into();
        json!({"kty": "RSA", "kid": kid, "n": ark_net::crypto::b64url(&c.n), "e": ark_net::crypto::b64url(&c.e), "endorsements": endorsements})
    }

    pub(crate) fn jwt(kid: &str, claims: Value) -> String {
        sign_rs256(&test_der(), &json!({"alg": "RS256", "typ": "JWT", "kid": kid}), &claims).unwrap()
    }

    type Reply = (u16, Vec<(String, String)>, String);

    fn json_reply(v: Value) -> Reply {
        (200, vec![("content-type".into(), "application/json".into())], v.to_string())
    }

    /// Fake Bot Framework: OpenID metadata, JWKS, token endpoint and connector.
    fn fake(connector: impl Fn(&crate::testutil::Req, usize) -> Reply + Send + 'static) -> (FakeServer, Arc<Mutex<String>>) {
        let me = Arc::new(Mutex::new(String::new()));
        let m2 = me.clone();
        let srv = FakeServer::start(move |req, n| {
            let base = m2.lock().unwrap().clone();
            match req.path.as_str() {
                "/openid" => json_reply(json!({"issuer": BF_ISSUER, "jwks_uri": format!("{base}/keys")})),
                "/keys" => json_reply(json!({"keys": [test_jwk("k1", &["msteams"])]})),
                p if p.ends_with("/oauth2/v2.0/token") => json_reply(json!({"access_token": "BFTOKEN", "expires_in": 3600, "token_type": "Bearer"})),
                _ => connector(req, n),
            }
        });
        *me.lock().unwrap() = srv.url.clone();
        (srv, me)
    }

    fn teams(srv: &str, listen: Option<&str>, state: PathBuf) -> Teams {
        let t = Teams::new(
            "teams",
            TeamsOpts {
                app_id: "APPID",
                app_password: "SECRETPW",
                tenant: Some("contoso"),
                listen,
                path: "/api/messages",
                openid_url: &format!("{srv}/openid"),
                login_base: srv,
                service_url: &format!("{srv}/svc"),
                state,
                poll_timeout: Duration::from_millis(300),
                native_streaming: true,
                reaction_events: true,
                sso_connection: Some("graph"),
                token_service: &format!("{srv}/ts"),
            },
        )
        .unwrap();
        t.set_retry_base(Duration::from_millis(5));
        t
    }

    fn claims(service_url: &str) -> Value {
        let now = now_secs();
        json!({"iss": BF_ISSUER, "aud": "APPID", "exp": now + 600, "nbf": now - 10, "serviceurl": service_url})
    }

    fn post(addr: std::net::SocketAddr, token: Option<&str>, body: &Value) -> (u16, String) {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut req = a.post(&format!("http://{addr}/api/messages"));
        if let Some(t) = token {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        match req.send(body.to_string().as_bytes()) {
            Ok(mut r) => (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()),
            Err(_) => (0, String::new()),
        }
    }

    fn activity(svc: &str, typ: &str, conv: Value, extra: Value) -> Value {
        let mut a = json!({"type": typ, "id": "1700000000001", "timestamp": "2024-01-02T03:04:05.123Z", "channelId": "msteams", "serviceUrl": svc,
            "from": {"id": "29:user", "name": "Amy", "aadObjectId": "aad-amy"}, "recipient": {"id": "28:APPID", "name": "Ark"}, "conversation": conv});
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        a
    }

    #[test]
    fn inbound_requires_a_valid_bot_framework_jwt() {
        let (srv, _) = fake(|_, _| (404, vec![], String::new()));
        let t = teams(&srv.url, Some("127.0.0.1:0"), temp_dir("teams").join("s.json"));
        let a = t.local_addr().unwrap();
        let svc = "https://smba.trafficmanager.net/emea/";
        let act = activity(svc, "message", json!({"id": "a:1", "conversationType": "personal"}), json!({"text": "hi"}));
        assert_eq!(post(a, None, &act).0, 401, "missing");
        assert_eq!(post(a, Some("not.a.jwt"), &act).0, 401, "garbage");
        let mut tampered = jwt("k1", claims(svc));
        tampered.replace_range(tampered.len() - 6.., "AAAAAA");
        assert_eq!(post(a, Some(&tampered), &act).0, 401, "bad signature");
        let now = now_secs();
        let expired = json!({"iss": BF_ISSUER, "aud": "APPID", "exp": now - 400, "serviceurl": svc});
        assert_eq!(post(a, Some(&jwt("k1", expired)), &act).0, 401, "expired beyond skew");
        let skewed = json!({"iss": BF_ISSUER, "aud": "APPID", "exp": now - 100, "serviceurl": svc});
        assert_eq!(post(a, Some(&jwt("k1", skewed)), &act).0, 200, "within 5 min skew");
        let future = json!({"iss": BF_ISSUER, "aud": "APPID", "exp": now + 900, "nbf": now + 600, "serviceurl": svc});
        assert_eq!(post(a, Some(&jwt("k1", future)), &act).0, 401, "nbf in the future");
        let mut wrong_aud = claims(svc);
        wrong_aud["aud"] = json!("OTHER");
        assert_eq!(post(a, Some(&jwt("k1", wrong_aud)), &act).0, 401);
        let mut wrong_iss = claims(svc);
        wrong_iss["iss"] = json!("https://evil.example");
        assert_eq!(post(a, Some(&jwt("k1", wrong_iss)), &act).0, 401);
        assert_eq!(post(a, Some(&jwt("k1", claims("https://evil.example/"))), &act).0, 401, "serviceUrl claim must match");
        assert_eq!(post(a, Some(&jwt("unknown-kid", claims(svc))), &act).0, 401, "unknown kid after refresh");
        let mut skype = act.clone();
        skype["channelId"] = json!("skype");
        assert_eq!(post(a, Some(&jwt("k1", claims(svc))), &skype).0, 401, "key not endorsed for channel");
        assert_eq!(post(a, Some(&jwt("k1", claims(svc))), &act).0, 200);
        let got = t.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2, "only the two accepted posts: {got:?}");
        let keys_fetches = srv.requests().iter().filter(|r| r.path == "/keys").count();
        assert!(keys_fetches <= 2, "keys cached ({keys_fetches})");
    }

    #[test]
    fn parses_dm_group_channel_threads_mentions_edits_cards_and_attachments() {
        let (srv, _) = fake(|_, _| json_reply(json!({"id": "OWN1"})));
        let state = temp_dir("teams").join("s.json");
        let t = teams(&srv.url, Some("127.0.0.1:0"), state.clone());
        let a = t.local_addr().unwrap();
        let svc = format!("{}/svc2/", srv.url);
        let tok = jwt("k1", claims(&svc));
        let dm = json!({"id": "a:dm", "conversationType": "personal"});
        let group = json!({"id": "19:g@thread.v2", "conversationType": "groupChat", "name": "Crew"});
        let chan = json!({"id": "19:c@thread.tacv2;messageid=1699", "conversationType": "channel"});
        // The bot posts first so a later reply to it is recognised.
        assert_eq!(t.send(&Outbound::text("19:g@thread.v2", "pick one")).unwrap().ids, vec!["OWN1"]);
        let acts = [
            activity(&svc, "message", dm.clone(), json!({"text": "hello"})),
            activity(&svc, "message", group.clone(), json!({"text": "<at>Ark</at> do it", "entities": [{"type": "mention", "mentioned": {"id": "28:APPID", "name": "Ark"}, "text": "<at>Ark</at>"}]})),
            activity(&svc, "message", group.clone(), json!({"text": "<at>Bob</at> hey", "entities": [{"type": "mention", "mentioned": {"id": "29:bob"}}]})),
            activity(&svc, "message", chan.clone(), json!({"text": "in thread", "replyToId": "1699"})),
            activity(&svc, "messageUpdate", dm.clone(), json!({"text": "edited"})),
            activity(&svc, "message", dm.clone(), json!({"value": {"ark": "appr:1:once"}, "replyToId": "OWN0"})),
            activity(&svc, "message", dm.clone(), json!({"from": {"id": "28:APPID"}, "text": "my own"})),
            activity(&svc, "message", dm.clone(), json!({"text": "", "attachments": [
                {"contentType": "image/png", "contentUrl": format!("{}/att/1", srv.url), "name": "a.png"},
                {"contentType": "text/html", "content": "<p>x</p>"},
                {"contentType": "application/vnd.microsoft.teams.file.download.info", "name": "r.pdf", "content": {"downloadUrl": "https://sp.example/r.pdf", "uniqueId": "U1"}}]})),
            activity(&svc, "conversationUpdate", group.clone(), json!({"membersAdded": [{"id": "28:APPID"}]})),
            activity(&svc, "message", group.clone(), json!({"text": "yes", "replyToId": "OWN1"})),
        ];
        for act in &acts {
            assert_eq!(post(a, Some(&tok), act).0, 200, "{act}");
        }
        let (st, body) = post(a, Some(&tok), &activity(&svc, "invoke", dm.clone(), json!({"name": "adaptiveCard/action", "value": {"action": {"type": "Action.Execute", "data": {"ark": "cl:9:2"}}}})));
        assert_eq!(st, 200);
        assert!(body.contains("statusCode"), "invoke response: {body}");
        std::thread::sleep(Duration::from_millis(50));
        let g = t.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 9, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].text.as_str()), ("a:dm", ChatType::Direct, "aad-amy", "Amy", "hello"));
        assert_eq!(g[0].ts, 1704164645);
        assert!(g[1].mentioned && g[1].text == "do it" && g[1].chat_type == ChatType::Group && g[1].chat_name == "Crew");
        assert!(!g[2].mentioned, "mention of someone else");
        assert_eq!((g[3].chat.as_str(), g[3].thread.as_deref(), g[3].chat_type), ("19:c@thread.tacv2", Some("1699"), ChatType::Channel));
        assert!(g[3].reply.is_none(), "thread root is not a reply");
        assert!(g[4].edited && g[4].message_id.starts_with("1700000000001:e"));
        assert_eq!(g[5].callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(g[6].media.len(), 2);
        assert_eq!((g[6].media[0].kind, g[6].media[0].mime.as_str()), (MediaKind::Image, "image/png"));
        assert_eq!((g[6].media[1].kind, g[6].media[1].name.as_str(), g[6].media[1].url.as_deref()), (MediaKind::Document, "r.pdf", Some("https://sp.example/r.pdf")));
        assert!(g[7].reply.as_ref().unwrap().is_own && g[7].addressed() && !g[7].mentioned, "reply to the bot");
        assert_eq!(g[8].callback.as_ref().unwrap().data, "cl:9:2");
        // The conversation's serviceUrl is persisted and used for replies, across restarts.
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved["conversations"]["19:c@thread.tacv2"]["service_url"], json!(svc));
        drop(t);
        let t2 = teams(&srv.url, None, state);
        let before = srv.requests().len();
        t2.send(&Outbound { thread: Some("1699".into()), ..Outbound::text("19:c@thread.tacv2", "reply") }).unwrap();
        let r = &srv.requests()[before + 1];
        assert_eq!(r.path, format!("/svc2/v3/conversations/{}/activities", ark_net::urlencode("19:c@thread.tacv2;messageid=1699")));
        // Bytes of the image are fetched with the bot token (connector host).
        let bytes = t2.fetch_media(&g[6].media[0]).unwrap();
        assert!(bytes.windows(4).any(|w| w == b"OWN1") || !bytes.is_empty());
        assert_eq!(srv.requests().last().unwrap().header("authorization"), Some("Bearer BFTOKEN"));
    }

    #[test]
    fn send_shapes_replies_cards_media_and_actions() {
        let (srv, _) = fake(|req, n| match req.method.as_str() {
            "POST" => json_reply(json!({"id": format!("A{n}")})),
            _ => json_reply(json!({})),
        });
        let t = teams(&srv.url, None, temp_dir("teams").join("s.json"));
        let out = Outbound {
            format: TextFormat::Markdown,
            reply_to: Some("1699".into()),
            buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:x:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("a:dm", "**hi**")
        };
        let s = t.send(&out).unwrap();
        assert_eq!(s.ids.len(), 1);
        let reqs = srv.requests();
        let tokreq = &reqs[0];
        assert_eq!(tokreq.path, "/contoso/oauth2/v2.0/token");
        assert!(tokreq.body.contains("grant_type=client_credentials") && tokreq.body.contains("client_id=APPID") && tokreq.body.contains("scope=https%3A%2F%2Fapi.botframework.com%2F.default"), "{}", tokreq.body);
        let r = &reqs[1];
        assert_eq!(r.path, "/svc/v3/conversations/a%3Adm/activities/1699");
        assert_eq!(r.header("authorization"), Some("Bearer BFTOKEN"));
        let b = r.json();
        assert_eq!((b["type"].as_str(), b["text"].as_str(), b["textFormat"].as_str()), (Some("message"), Some("**hi**"), Some("markdown")));
        let card = &b["attachments"][0];
        assert_eq!(card["contentType"], "application/vnd.microsoft.card.adaptive");
        assert_eq!(card["content"]["actions"][0], json!({"type": "Action.Submit", "title": "允許", "data": {"ark": "appr:x:once"}}));
        assert_eq!(card["content"]["actions"][1]["type"], "Action.OpenUrl");
        // Media by URL and by local file (data URI outside personal chats).
        let f = temp_dir("teams").join("r.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        t.send(&Outbound { media: vec![Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() }, Media { path: Some(f.display().to_string()), ..Default::default() }], silent: true, ..Outbound::text("19:g@thread.v2", "cap") }).unwrap();
        let b = srv.requests().last().unwrap().json();
        assert_eq!(b["attachments"][0], json!({"contentType": "image/png", "contentUrl": "https://e.com/a.png", "name": "a.png"}));
        assert_eq!(b["attachments"][1]["contentUrl"], format!("data:application/pdf;base64,{}", ark_net::crypto::b64(b"%PDF")));
        assert_eq!(b["channelData"]["notification"]["alert"], false);
        t.edit("a:dm", "A1", "new").unwrap();
        t.delete("a:dm", "A1").unwrap();
        t.typing("19:c@thread.tacv2", Some("1699")).unwrap();
        let reqs = srv.requests();
        let tail: Vec<(String, String)> = reqs[reqs.len() - 3..].iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        assert_eq!(tail[0], ("PUT".into(), "/svc/v3/conversations/a%3Adm/activities/A1".into()));
        assert_eq!(tail[1], ("DELETE".into(), "/svc/v3/conversations/a%3Adm/activities/A1".into()));
        assert_eq!(tail[2].1, format!("/svc/v3/conversations/{}/activities", ark_net::urlencode("19:c@thread.tacv2;messageid=1699")));
        assert_eq!(reqs.last().unwrap().json()["type"], "typing");
        assert_eq!(reqs.iter().filter(|r| r.path.ends_with("/token")).count(), 1, "token cached");
        assert_eq!(t.react("a:dm", "A1", "👍", false).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn errors_map_and_retry() {
        // Token endpoint rejects the secret.
        let srv = FakeServer::start(|_, _| (401, vec![], json!({"error": "invalid_client", "error_description": "AADSTS7000215 bad secret"}).to_string()));
        let t = teams(&srv.url, None, temp_dir("teams").join("s.json"));
        let e = t.send(&Outbound::text("a:dm", "x")).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("SECRETPW"));
        // Connector: 403 bot removed, 404 conversation gone, 429 then ok, 5xx exhausted, 401 → token refresh.
        let (srv, _) = fake(|req, n| match req.path.as_str() {
            p if p.contains("removed") => (403, vec![], json!({"error": {"code": "BotNotInConversationRoster", "message": "gone"}}).to_string()),
            p if p.contains("gone") => (404, vec![], json!({"error": {"code": "ConversationNotFound"}}).to_string()),
            p if p.contains("slow") && n % 2 == 1 => (429, vec![("Retry-After".into(), "1".into())], String::new()),
            p if p.contains("down") => (502, vec![], "bad gateway".into()),
            p if p.contains("stale") && n < 3 => (401, vec![], String::new()),
            _ => json_reply(json!({"id": "OK"})),
        });
        let t = teams(&srv.url, None, temp_dir("teams").join("s.json"));
        assert_eq!(t.send(&Outbound::text("removed", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(t.send(&Outbound::text("gone", "x")).unwrap_err().kind, K::NotFound);
        let start = Instant::now();
        assert_eq!(t.send(&Outbound::text("slow", "x")).unwrap().ids, vec!["OK"]);
        assert!(start.elapsed() >= Duration::from_millis(900), "honoured Retry-After");
        let before = srv.requests().len();
        assert_eq!(t.send(&Outbound::text("down", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len() - before, 4, "1 + 3 retries");
        let (srv, _) = fake(|req, _| if req.header("authorization") == Some("Bearer BFTOKEN") && req.path.contains("stale") { (401, vec![], String::new()) } else { json_reply(json!({"id": "OK"})) });
        let t = teams(&srv.url, None, temp_dir("teams").join("s.json"));
        assert_eq!(t.send(&Outbound::text("stale", "x")).unwrap_err().kind, K::Auth, "401 after a fresh token is Auth");
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("/token")).count(), 2, "token refreshed once on 401");
    }

    #[test]
    fn poll_cancels_promptly_and_helpers() {
        let (srv, _) = fake(|_, _| json_reply(json!({})));
        let mut t = teams(&srv.url, Some("127.0.0.1:0"), temp_dir("teams").join("s.json"));
        t.poll_timeout = Duration::from_secs(30);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(t.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2024-01-02T03:04:05.123+01:00"), Some(1704164645 - 3600));
        assert_eq!(parse_rfc3339("garbage"), None);
        assert_eq!(strip_at_tags("<at>Ark</at> hi <at>Bo</at>there"), "hi there");
        assert!(Teams::new("t", TeamsOpts { app_id: "", app_password: "x", tenant: None, listen: None, path: "/", openid_url: "", login_base: "", service_url: "", state: temp_dir("teams").join("s"), poll_timeout: Duration::ZERO, native_streaming: false, reaction_events: false, sso_connection: None, token_service: "" }).is_err());
    }

    fn wait_for(srv: &FakeServer, f: impl Fn(&crate::testutil::Req) -> bool) -> crate::testutil::Req {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(r) = srv.requests().into_iter().find(|r| f(r)) {
                return r;
            }
            assert!(Instant::now() < until, "request never came");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn consent_upload_uses_the_shared_address_classifier() {
        // A14: the Teams consent upload names Microsoft hosts, so the only thing left to decide
        // is the address — and that decision is `ark_security::url_safety`'s, not a local copy
        // of the private-range table.
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for blocked in ["127.0.0.1", "10.1.2.3", "192.168.0.7", "169.254.169.254", "100.100.100.200", "::1", "fe80::1", "fd00:ec2::254"] {
            let e = consent_addresses_ok("files.example", &[ip(blocked)]).unwrap_err();
            assert!(e.contains("private address") && e.contains(blocked), "{blocked}: {e}");
            assert!(ark_security::url_safety::is_blocked_ip(ip(blocked)), "{blocked}: the shared verdict");
        }
        for ok in ["8.8.8.8", "20.190.151.7", "2603:1020::1"] {
            assert!(consent_addresses_ok("files.example", &[ip(ok)]).is_ok(), "{ok}");
        }
        // One bad answer among good ones still refuses (no "first answer wins").
        assert!(consent_addresses_ok("files.example", &[ip("8.8.8.8"), ip("10.0.0.1")]).is_err());
        // The URL rules stay: https only, Microsoft hosts only.
        assert!(consent_url_ok("http://files.example/x").unwrap_err().contains("https"));
        assert!(consent_url_ok("https://evil.example/x").unwrap_err().contains("not allowed"));
    }

    #[test]
    fn file_consent_flow_in_personal_chats() {
        let (srv, _) = fake(|req, n| match (req.method.as_str(), req.path.as_str()) {
            ("PUT", "/upload") => (201, vec![], String::new()),
            ("POST", _) => json_reply(json!({"id": format!("A{n}")})),
            _ => json_reply(json!({})),
        });
        let t = teams(&srv.url, Some("127.0.0.1:0"), temp_dir("teams").join("s.json"));
        let a = t.local_addr().unwrap();
        let svc = format!("{}/svc/", srv.url);
        let tok = jwt("k1", claims(&svc));
        let dm = json!({"id": "a:dm", "conversationType": "personal", "tenantId": "TEN"});
        assert_eq!(post(a, Some(&tok), &activity(&svc, "message", dm.clone(), json!({"text": "hi"}))).0, 200);
        let f = temp_dir("teams").join("report.pdf");
        std::fs::write(&f, b"%PDF-1.7 body").unwrap();
        let png = temp_dir("teams").join("small.png");
        std::fs::write(&png, b"\x89PNG").unwrap();
        let sent = t.send(&Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }, Media { path: Some(png.display().to_string()), ..Default::default() }], ..Outbound::text("a:dm", "here") }).unwrap();
        assert_eq!(sent.ids.len(), 2, "text (+ inline small image) and the consent card");
        let posts: Vec<Value> = srv.requests().iter().filter(|r| r.path == "/svc/v3/conversations/a%3Adm/activities").map(|r| r.json()).collect();
        assert_eq!(posts[0]["attachments"][0]["contentType"], "image/png", "small images stay inline");
        let card = &posts[1]["attachments"][0];
        assert_eq!((card["contentType"].as_str(), card["name"].as_str(), card["content"]["sizeInBytes"].as_u64()), (Some("application/vnd.microsoft.teams.card.file.consent"), Some("report.pdf"), Some(13)));
        let upload_id = card["content"]["acceptContext"]["uploadId"].as_str().unwrap().to_string();
        let card_id = sent.ids[1].clone();
        // Accept → PUT the bytes with Content-Range, then the card becomes a file info card.
        let invoke = |action: &str, id: &str| {
            activity(&svc, "invoke", dm.clone(), json!({"name": "fileConsent/invoke", "value": {"type": "fileUpload", "action": action, "context": {"uploadId": id},
                "uploadInfo": {"name": "report.pdf", "uploadUrl": format!("{}/upload", srv.url), "contentUrl": "https://contoso.sharepoint.com/r.pdf", "uniqueId": "UQ1", "fileType": "pdf"}}}))
        };
        assert_eq!(post(a, Some(&tok), &invoke("accept", &upload_id)).0, 200);
        let put = wait_for(&srv, |r| r.path == "/upload");
        assert_eq!((put.method.as_str(), put.body.as_str(), put.header("content-range"), put.header("content-type")), ("PUT", "%PDF-1.7 body", Some("bytes 0-12/13"), Some("application/pdf")));
        let upd = wait_for(&srv, |r| r.method == "PUT" && r.path == format!("/svc/v3/conversations/a%3Adm/activities/{card_id}"));
        assert_eq!(upd.json()["attachments"][0], json!({"contentType": "application/vnd.microsoft.teams.card.file.info", "contentUrl": "https://contoso.sharepoint.com/r.pdf", "name": "report.pdf", "content": {"uniqueId": "UQ1", "fileType": "pdf"}}));
        // A second accept of the same upload has expired.
        assert_eq!(post(a, Some(&tok), &invoke("accept", &upload_id)).0, 200);
        let expired = wait_for(&srv, |r| r.json()["text"].as_str().is_some_and(|t| t.contains("expired")));
        assert_eq!(expired.path, "/svc/v3/conversations/a%3Adm/activities");
        assert!(t.poll(&Cancel::new()).unwrap().iter().all(|m| m.text == "hi"), "invokes are not messages");
        assert!(consent_url_ok("http://contoso.sharepoint.com/x").is_err());
        assert!(consent_url_ok("https://evil.example/x").is_err());
    }

    #[test]
    fn proactive_conversations_reactions_and_streaming() {
        let (srv, _) = fake(|req, n| match req.path.as_str() {
            "/svc/v3/conversations" => json_reply(json!({"id": "a:new-conv"})),
            _ => json_reply(json!({"id": format!("S{n}")})),
        });
        let t = teams(&srv.url, Some("127.0.0.1:0"), temp_dir("teams").join("s.json"));
        let a = t.local_addr().unwrap();
        let svc = format!("{}/svc/", srv.url);
        let tok = jwt("k1", claims(&svc));
        let group = json!({"id": "19:g@thread.v2", "conversationType": "groupChat", "tenantId": "TEN"});
        // Reactions arrive as messages naming the emoji and target.
        let react = activity(&svc, "messageReaction", group.clone(), json!({"replyToId": "S9", "reactionsAdded": [{"type": "like"}], "reactionsRemoved": [{"type": "heart"}]}));
        assert_eq!(post(a, Some(&tok), &react).0, 200);
        let g = t.poll(&Cancel::new()).unwrap();
        assert_eq!(g.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["Teams reaction 👍 added by Amy on message S9", "Teams reaction ❤️ removed by Amy from message S9"]);
        assert_eq!((g[0].sender.as_str(), g[0].chat_type, g[0].reply.as_ref().unwrap().id.as_str()), ("aad-amy", ChatType::Group, "S9"));
        // user:<aad id> creates a personal conversation once (tenant learnt from inbound).
        t.send(&Outbound::text("user:aad-bob", "hello bob")).unwrap();
        t.send(&Outbound::text("user:aad-bob", "again")).unwrap();
        let reqs = srv.requests();
        let creates: Vec<_> = reqs.iter().filter(|r| r.path == "/svc/v3/conversations").collect();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].json(), json!({"bot": {"id": "28:APPID"}, "members": [{"id": "8:orgid:aad-bob", "aadObjectId": "aad-bob"}], "isGroup": false, "tenantId": "TEN", "channelData": {"tenant": {"id": "TEN"}}}));
        assert_eq!(reqs.iter().filter(|r| r.path == "/svc/v3/conversations/a%3Anew-conv/activities").count(), 2);
        // Native streaming in the (personal) conversation; group chats fall back.
        let base = Outbound::text("a:new-conv", "Hel");
        let h = t.stream_begin(&base).unwrap().unwrap();
        t.stream_update("a:new-conv", &h, "Hello wor", "lo wor").unwrap();
        t.stream_update("a:new-conv", &h, "Hello world, more", ", more").unwrap();
        t.stream_finish("a:new-conv", &h, "Hello world, more.", ".").unwrap();
        let acts: Vec<Value> = srv.requests().iter().filter(|r| r.path == "/svc/v3/conversations/a%3Anew-conv/activities").skip(2).map(|r| r.json()).collect();
        assert_eq!(acts[0], json!({"type": "typing", "text": "Hel", "entities": [{"type": "streaminfo", "streamType": "streaming", "streamSequence": 1}]}));
        assert_eq!(acts[1]["entities"][0], json!({"type": "streaminfo", "streamId": h, "streamType": "streaming", "streamSequence": 2}));
        assert_eq!((acts[2]["text"].as_str(), acts[2]["entities"][0]["streamSequence"].as_u64()), (Some("Hello world, more"), Some(3)));
        assert_eq!(acts[3], json!({"type": "message", "text": "Hello world, more.", "textFormat": "markdown", "entities": [{"type": "streaminfo", "streamId": h, "streamType": "final"}]}));
        assert_eq!(t.stream_begin(&Outbound::text("19:g@thread.v2", "x")).unwrap(), None);
        assert_eq!(t.caps().streaming, Streaming::Native);
        // Survives a restart: the user's conversation and the tenant are persisted.
        let state = temp_dir("teams").join("p.json");
        let t2 = teams(&srv.url, None, state.clone());
        t2.sh.users.lock().unwrap().insert("x".into(), "a:x".into());
        t2.sh.save();
        let t3 = teams(&srv.url, None, state);
        assert_eq!(t3.sh.resolve_chat("user:x").unwrap(), "a:x");
    }

    #[test]
    fn sso_token_exchange_verify_state_and_signin_card() {
        let (srv, _) = fake(|req, _| match req.path.as_str() {
            p if p.starts_with("/ts/api/usertoken/GetToken") && p.contains("code=good") => json_reply(json!({"channelId": "msteams", "connectionName": "graph", "token": "TOK-STATE", "expiration": "2030-01-01T00:00:00Z"})),
            p if p.starts_with("/ts/api/usertoken/GetToken") => (404, vec![], String::new()),
            p if p.starts_with("/ts/api/usertoken/exchange") => {
                if req.json()["token"] == "sso-good" {
                    json_reply(json!({"connectionName": "graph", "token": "TOK-EX", "expiration": "2030-01-01T00:00:00Z"}))
                } else {
                    (400, vec![], "{}".into())
                }
            }
            p if p.starts_with("/ts/api/botsignin/GetSignInResource") => json_reply(json!({"signInLink": "https://login.example/si", "tokenExchangeResource": {"id": "TX1", "uri": "api://bot/x"}})),
            _ => json_reply(json!({"id": "C1"})),
        });
        let t = teams(&srv.url, Some("127.0.0.1:0"), temp_dir("teams").join("s.json"));
        let a = t.local_addr().unwrap();
        let svc = format!("{}/svc/", srv.url);
        let tok = jwt("k1", claims(&svc));
        let dm = json!({"id": "a:dm", "conversationType": "personal"});
        let ex = |token: &str| activity(&svc, "invoke", dm.clone(), json!({"name": "signin/tokenExchange", "value": {"id": "X1", "connectionName": "graph", "token": token}}));
        assert_eq!(post(a, Some(&tok), &ex("sso-good")).0, 200);
        assert_eq!(t.user_token("29:user"), Some(("TOK-EX".into(), "2030-01-01T00:00:00Z".into())));
        assert_eq!(t.user_token("aad-amy").unwrap().0, "TOK-EX", "stored under the AAD id too");
        let reqs = srv.requests();
        let ts: Vec<&crate::testutil::Req> = reqs.iter().filter(|r| r.path.starts_with("/ts/")).collect();
        assert_eq!(ts[0].path, "/ts/api/usertoken/GetToken?userId=29%3Auser&connectionName=graph&channelId=msteams");
        assert_eq!((ts[1].method.as_str(), ts[1].path.as_str(), ts[1].header("authorization")), ("POST", "/ts/api/usertoken/exchange?userId=29%3Auser&connectionName=graph&channelId=msteams", Some("Bearer BFTOKEN")));
        let (st, body) = post(a, Some(&tok), &ex("sso-bad"));
        assert_eq!(st, 412, "failed exchange asks Teams to show the sign-in card");
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["id"], "X1");
        let vs = |state: &str| activity(&svc, "invoke", dm.clone(), json!({"name": "signin/verifyState", "value": {"state": state}}));
        assert_eq!(post(a, Some(&tok), &vs("good")).0, 200);
        assert_eq!(t.user_token("29:user").unwrap().0, "TOK-STATE");
        assert_eq!(post(a, Some(&tok), &vs("bad")).0, 404);
        assert!(t.poll(&Cancel::new()).unwrap().is_empty(), "sign-in invokes are not messages");
        // OAuthCard with the sign-in link and token exchange resource.
        t.send_signin_card("a:dm", "Please sign in").unwrap();
        let reqs = srv.requests();
        let res = reqs.iter().find(|r| r.path.starts_with("/ts/api/botsignin/GetSignInResource?state=")).unwrap();
        let state = ark_net::crypto::b64_decode(&ark_net::parse_query(res.path.split_once('?').unwrap().1)[0].1).unwrap();
        let state: Value = serde_json::from_slice(&state).unwrap();
        assert_eq!((state["ConnectionName"].as_str(), state["Conversation"]["conversation"]["id"].as_str(), state["MsAppId"].as_str()), (Some("graph"), Some("a:dm"), Some("APPID")));
        let card = &reqs.last().unwrap().json()["attachments"][0];
        assert_eq!(card["contentType"], "application/vnd.microsoft.card.oauth");
        assert_eq!(card["content"], json!({"text": "Please sign in", "connectionName": "graph", "buttons": [{"type": "signin", "title": "Sign in", "value": "https://login.example/si"}], "tokenExchangeResource": {"id": "TX1", "uri": "api://bot/x"}}));
    }
}
