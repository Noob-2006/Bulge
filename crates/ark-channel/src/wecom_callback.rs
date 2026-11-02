//! WeCom (企业微信) self-built app in callback mode (ported from Hermes
//! `plugins/platforms/wecom/callback_adapter.py` + `wecom_crypto.py`, MIT).
//!
//! Receive: WeCom calls our URL. `GET` is the URL-verification handshake
//! (`msg_signature = sha1(sort(token, timestamp, nonce, echostr))`, answer the
//! decrypted echostr); `POST` carries `<xml><Encrypt>…</Encrypt></xml>` whose
//! payload is WXBizMsgCrypt AES-256-CBC (key = base64(EncodingAESKey + "="),
//! iv = key[..16], PKCS#7 to 32 bytes, `random16 | len(4, BE) | xml | corpid`).
//! Signatures are checked before the payload is decrypted, the corp id must
//! match, stale timestamps are refused and WeCom's retries (same signature) are
//! acknowledged without being queued twice. We always answer `success` at once
//! and reply later with the proactive API.
//! Send: `gettoken` (cached, refreshed on 40001/42001) + `message/send` text /
//! markdown / image / voice / video / file (`media/upload` first); delete =
//! `message/recall`; inbound media via `media/get`.
//! Several apps (`[[…apps]]`, each with its own corp id / secret / agent id / token /
//! AES key) can share one listener: a request goes to the apps on its path whose
//! token verifies the signature and whose key/corp id decrypt it; apps sharing those
//! are told apart by the decrypted `AgentID`. With more than one app chat ids are
//! `<app>:<user>` (Hermes keys them `corp_id:user_id`, also accepted when unique).

use crate::http::{classify, Http, Payload};
use crate::{Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::crypto;
use ark_net::httpd::{Handler, Opts, Request, Response, Server};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://qyapi.weixin.qq.com";
pub const DEFAULT_PATH: &str = "/wecom/callback";
/// `message/send` keeps only the first 2048 bytes of `text.content`.
pub const MAX_MESSAGE: usize = 2048;
/// Callbacks are small encrypted XML envelopes.
const MAX_BODY: usize = 64 * 1024;

// ---------------------------------------------------------------- crypto

/// WXBizMsgCrypt-compatible envelope crypto.
pub struct BizMsgCrypt {
    token: String,
    key: [u8; 32],
    receive_id: String,
}

fn lenient_b64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::{general_purpose::GeneralPurpose, general_purpose::GeneralPurposeConfig, DecodePaddingMode, Engine};
    // EncodingAESKey is 43 chars whose last symbol carries non-zero spare bits; Python's decoder tolerates that.
    let eng = GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent));
    eng.decode(s.trim()).ok()
}

pub fn signature(token: &str, timestamp: &str, nonce: &str, encrypt: &str) -> String {
    let mut parts = [token, timestamp, nonce, encrypt];
    parts.sort_unstable();
    crypto::hex(&crypto::sha1(parts.concat().as_bytes()))
}

impl BizMsgCrypt {
    pub fn new(token: &str, encoding_aes_key: &str, receive_id: &str) -> Result<BizMsgCrypt, String> {
        if token.is_empty() {
            return Err("token is required".into());
        }
        if encoding_aes_key.len() != 43 {
            return Err("encoding_aes_key must be 43 chars".into());
        }
        if receive_id.is_empty() {
            return Err("corp_id is required".into());
        }
        let k = lenient_b64(&format!("{encoding_aes_key}=")).filter(|k| k.len() == 32).ok_or("encoding_aes_key is not valid base64")?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&k);
        Ok(BizMsgCrypt { token: token.into(), key, receive_id: receive_id.into() })
    }

    fn iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&self.key[..16]);
        iv
    }

    pub fn verify(&self, msg_signature: &str, timestamp: &str, nonce: &str, encrypt: &str) -> bool {
        crypto::ct_eq(signature(&self.token, timestamp, nonce, encrypt).as_bytes(), msg_signature.trim().to_ascii_lowercase().as_bytes())
    }

    /// Decrypt a (signature-checked) payload; checks the trailing receive id.
    pub fn decrypt(&self, encrypt: &str) -> Result<Vec<u8>, String> {
        let raw = crypto::b64_decode(encrypt).ok_or("invalid base64 payload")?;
        let aes = crypto::Aes::new(&self.key).ok_or("bad key")?;
        let plain = aes.cbc_decrypt(&self.iv(), &raw).ok_or("decrypt failed (length or padding)")?;
        if plain.len() < 20 {
            return Err("decrypted payload too short".into());
        }
        let n = u32::from_be_bytes([plain[16], plain[17], plain[18], plain[19]]) as usize;
        let body = plain.get(20..20 + n).ok_or("bad message length")?;
        let rid = &plain[20 + n..];
        if !crypto::ct_eq(rid, self.receive_id.as_bytes()) {
            return Err("receive_id mismatch".into());
        }
        Ok(body.to_vec())
    }

    /// Encrypt with an explicit 16-byte random prefix (tests use a fixed one).
    pub fn encrypt_with(&self, random16: &[u8; 16], msg: &[u8]) -> String {
        let mut p = Vec::with_capacity(msg.len() + 64);
        p.extend_from_slice(random16);
        p.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        p.extend_from_slice(msg);
        p.extend_from_slice(self.receive_id.as_bytes());
        // PKCS#7 to a 32-byte block (WeCom), then raw CBC: Aes::cbc_encrypt would add its own 16-byte padding.
        let pad = 32 - p.len() % 32;
        p.extend(std::iter::repeat_n(pad as u8, pad));
        let aes = crypto::Aes::new(&self.key).expect("32-byte key");
        let mut prev = self.iv();
        for chunk in p.chunks_mut(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            for (x, y) in b.iter_mut().zip(prev.iter()) {
                *x ^= y;
            }
            aes.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            prev = b;
        }
        crypto::b64(&p)
    }

    pub fn encrypt(&self, msg: &[u8]) -> String {
        let r = crypto::random_bytes(16);
        let mut a = [0u8; 16];
        a.copy_from_slice(&r);
        self.encrypt_with(&a, msg)
    }

    /// Full encrypted reply envelope (passive-reply format), as the SDK builds it.
    pub fn envelope(&self, msg: &str, timestamp: &str, nonce: &str) -> String {
        let enc = self.encrypt(msg.as_bytes());
        let sig = signature(&self.token, timestamp, nonce, &enc);
        format!("<xml><Encrypt><![CDATA[{enc}]]></Encrypt><MsgSignature><![CDATA[{sig}]]></MsgSignature><TimeStamp>{timestamp}</TimeStamp><Nonce><![CDATA[{nonce}]]></Nonce></xml>")
    }
}

// ---------------------------------------------------------------- xml

/// Untrusted XML: refuse DTDs/entities outright (XXE, billion laughs).
pub(crate) fn xml_safe(x: &str) -> bool {
    let u = x.to_ascii_uppercase();
    !u.contains("<!DOCTYPE") && !u.contains("<!ENTITY")
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Text of the first `<tag>…</tag>` (CDATA or escaped text). Flat WeCom XML only.
pub(crate) fn xml_tag(x: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = x.find(&open)? + open.len();
    let end = start + x[start..].find(&close)?;
    let inner = x[start..end].trim();
    Some(match inner.strip_prefix("<![CDATA[").and_then(|r| r.strip_suffix("]]>")) {
        Some(c) => c.to_string(),
        None => unescape(inner),
    })
}

// ---------------------------------------------------------------- channel

/// One self-built app.
#[derive(Debug, Clone, Default)]
pub struct AppConfig {
    pub name: String,
    /// Callback path; apps may share one.
    pub path: String,
    pub token: String,
    pub encoding_aes_key: String,
    pub corp_id: String,
    pub corp_secret: String,
    pub agent_id: i64,
}

struct App {
    cfg: AppConfig,
    crypt: BizMsgCrypt,
    token: Mutex<Option<(String, Instant)>>,
}

pub struct WecomCallback {
    id: String,
    apps: Arc<Vec<App>>,
    api: String,
    poll_timeout: u64,
    http: Http,
    rx: Mutex<mpsc::Receiver<Inbound>>,
    server: Mutex<Option<Server>>,
    addr: std::net::SocketAddr,
}

struct Ingress {
    apps: Arc<Vec<App>>,
    channel: String,
    api: String,
    max_skew: i64,
    /// msg_signature → first seen; WeCom retries a timed-out callback with the same envelope.
    seen: Mutex<HashMap<String, Instant>>,
    tx: Mutex<mpsc::Sender<Inbound>>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Ingress {
    fn params(r: &Request) -> (String, String, String) {
        let q = |k: &str| r.query(k).unwrap_or("").to_string();
        (q("msg_signature"), q("timestamp"), q("nonce"))
    }

    fn fresh(&self, ts: &str) -> bool {
        if self.max_skew <= 0 {
            return true;
        }
        ts.parse::<i64>().is_ok_and(|t| (now_secs() - t).abs() <= self.max_skew)
    }

    fn handle(&self, r: Request) -> Response {
        let here: Vec<usize> = (0..self.apps.len()).filter(|&i| self.apps[i].cfg.path == r.path).collect();
        if here.is_empty() {
            return Response::text(404, "not found");
        }
        let (sig, ts, nonce) = Self::params(&r);
        if sig.is_empty() || ts.is_empty() || nonce.is_empty() {
            return Response::text(401, "missing signature");
        }
        let multi = self.apps.len() > 1;
        match r.method.as_str() {
            "GET" => {
                // base64 never contains spaces: a '+' decoded as space by the query parser goes back.
                let echostr = r.query("echostr").unwrap_or("").replace(' ', "+");
                let signed: Vec<&App> = here.iter().map(|&i| &self.apps[i]).filter(|a| a.crypt.verify(&sig, &ts, &nonce, &echostr)).collect();
                if signed.is_empty() {
                    return Response::text(401, "signature verification failed");
                }
                match signed.iter().find_map(|a| a.crypt.decrypt(&echostr).ok()) {
                    Some(p) => Response::new(200, "text/plain", p),
                    None => Response::text(400, "bad echostr"),
                }
            }
            "POST" => {
                let body = r.body_str();
                if !xml_safe(body) {
                    return Response::text(400, "DTD not allowed");
                }
                let Some(enc) = xml_tag(body, "Encrypt") else { return Response::text(400, "missing Encrypt") };
                let signed: Vec<usize> = here.into_iter().filter(|&i| self.apps[i].crypt.verify(&sig, &ts, &nonce, &enc)).collect();
                if signed.is_empty() {
                    return Response::text(401, "signature verification failed");
                }
                if !self.fresh(&ts) {
                    return Response::text(401, "stale timestamp");
                }
                {
                    let mut seen = self.seen.lock().unwrap();
                    let window = Duration::from_secs(self.max_skew.max(300) as u64 * 2);
                    seen.retain(|_, t| t.elapsed() < window);
                    if seen.insert(sig.clone(), Instant::now()).is_some() {
                        return Response::text(200, "success");
                    }
                }
                let opened: Vec<(usize, String)> = signed.into_iter().filter_map(|i| self.apps[i].crypt.decrypt(&enc).ok().map(|b| (i, String::from_utf8_lossy(&b).into_owned()))).collect();
                let Some((first, xml)) = opened.first().cloned() else { return Response::text(400, "invalid callback payload") };
                if !xml_safe(&xml) {
                    return Response::text(400, "DTD not allowed");
                }
                // Apps sharing token, key and corp id: the decrypted AgentID decides.
                let agent = xml_tag(&xml, "AgentID").and_then(|a| a.trim().parse::<i64>().ok());
                let app = agent.and_then(|a| opened.iter().map(|(i, _)| *i).find(|&i| self.apps[i].cfg.agent_id == a)).unwrap_or(first);
                let prefix = if multi { Some(self.apps[app].cfg.name.as_str()) } else { None };
                if let Some(m) = inbound_of(&self.channel, &self.api, prefix, &xml) {
                    let _ = self.tx.lock().unwrap().send(m);
                }
                Response::text(200, "success")
            }
            _ => Response::text(405, "method not allowed"),
        }
    }
}

/// Decrypted message XML → Inbound. Lifecycle events are acknowledged and dropped.
/// `app` (multi-app mode) prefixes the chat id and tags media URLs.
fn inbound_of(channel: &str, api: &str, app: Option<&str>, x: &str) -> Option<Inbound> {
    let t = |k: &str| xml_tag(x, k).unwrap_or_default();
    let msg_type = t("MsgType").to_ascii_lowercase();
    let user = t("FromUserName");
    if user.is_empty() {
        return None;
    }
    let ts = t("CreateTime").parse::<i64>().unwrap_or(0);
    let msg_id = xml_tag(x, "MsgId").filter(|s| !s.is_empty()).unwrap_or_else(|| format!("{user}:{ts}"));
    let chat = match app {
        Some(a) => format!("{a}:{user}"),
        None => user.clone(),
    };
    let tag = app.map(|a| format!("&app={}", ark_net::urlencode(a))).unwrap_or_default();
    let base = Inbound { channel: channel.to_string(), chat, chat_type: ChatType::Direct, sender: user.clone(), sender_name: user.clone(), message_id: msg_id, ts, ..Default::default() };
    let media = |kind: MediaKind, mime: &str, name: String| {
        let mid = t("MediaId");
        Media {
            kind,
            id: Some(mid.clone()).filter(|s| !s.is_empty()),
            url: (!mid.is_empty()).then(|| format!("{api}/cgi-bin/media/get?media_id={}{tag}", ark_net::urlencode(&mid))).or_else(|| xml_tag(x, "PicUrl")),
            mime: mime.into(),
            name,
            ..Default::default()
        }
    };
    match msg_type.as_str() {
        "text" => Some(Inbound { text: t("Content").trim().to_string(), ..base }).filter(|m| !m.text.is_empty()),
        "image" => Some(Inbound { media: vec![media(MediaKind::Image, "image/jpeg", "image.jpg".into())], ..base }),
        "voice" => {
            let fmt = t("Format").to_ascii_lowercase();
            let fmt = if fmt.is_empty() { "amr".to_string() } else { fmt };
            // `Recognition` is WeCom's own speech-to-text when enabled.
            Some(Inbound { text: t("Recognition"), media: vec![media(MediaKind::Voice, &format!("audio/{fmt}"), format!("voice.{fmt}"))], ..base })
        }
        "video" => Some(Inbound { media: vec![media(MediaKind::Video, "video/mp4", "video.mp4".into())], ..base }),
        "file" => {
            let name = xml_tag(x, "FileName").unwrap_or_else(|| "file".into());
            Some(Inbound { media: vec![media(MediaKind::Document, "", name)], ..base })
        }
        "location" => Some(Inbound { text: format!("[location] {} ({}, {})", t("Label"), t("Location_X"), t("Location_Y")), ..base }),
        "link" => Some(Inbound { text: format!("{}\n{}\n{}", t("Title"), t("Description"), t("Url")).trim().to_string(), ..base }),
        "event" => {
            let ev = t("Event").to_ascii_lowercase();
            match ev.as_str() {
                // Menu clicks and template-card buttons become callbacks.
                "click" | "template_card_event" => {
                    let key = t("EventKey");
                    let cb_id = xml_tag(x, "TaskId").filter(|s| !s.is_empty()).unwrap_or_else(|| format!("{user}:{ts}:{key}"));
                    Some(Inbound { message_id: format!("cb:{cb_id}"), callback: Some(Callback { id: cb_id, data: key }), ..base })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn redact_tok(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("access_token=") {
        out.push_str(&rest[..i + 13]);
        let tail = &rest[i + 13..];
        let end = tail.find(['&', ' ', '"', '\'']).unwrap_or(tail.len());
        out.push_str("***");
        rest = &tail[end..];
    }
    out.push_str(rest);
    crate::http::redact(&out)
}

fn scrub(mut e: ChannelError) -> ChannelError {
    e.message = redact_tok(&e.message);
    e
}

/// WeCom `errcode` → error kind.
fn errcode_error(what: &str, v: &Value) -> ChannelError {
    let code = v["errcode"].as_i64().unwrap_or(-1);
    let msg = format!("{what}: errcode {code} {}", v["errmsg"].as_str().unwrap_or(""));
    let kind = match code {
        40001 | 40013 | 40014 | 40091 | 41001 | 42001 | 40056 | 60020 => K::Auth,
        -1 => K::Network,
        45009 | 45033 | 45047 => K::RateLimited { retry_after: Some(Duration::from_secs(60)) },
        // Invalid user / not in the app's visible range / user left.
        60111 | 81013 | 40003 | 60011 | 82001 | 46004 => K::NotFound,
        _ => K::Protocol,
    };
    ChannelError::new(kind, redact_tok(&msg))
}

impl WecomCallback {
    #[allow(clippy::too_many_arguments)]
    pub fn new(id: &str, listen: &str, path: &str, token: &str, aes_key: &str, corp_id: &str, corp_secret: &str, agent_id: i64, api: Option<&str>, poll_timeout: u64, max_skew: i64) -> Result<Self, String> {
        let app = AppConfig { name: "default".into(), path: path.into(), token: token.into(), encoding_aes_key: aes_key.into(), corp_id: corp_id.into(), corp_secret: corp_secret.into(), agent_id };
        Self::with_apps(id, listen, vec![app], api, poll_timeout, max_skew)
    }

    pub fn with_apps(id: &str, listen: &str, apps: Vec<AppConfig>, api: Option<&str>, poll_timeout: u64, max_skew: i64) -> Result<Self, String> {
        if apps.is_empty() {
            return Err(format!("channel {id}: no apps configured"));
        }
        let mut built = Vec::new();
        for a in apps {
            if a.name.is_empty() || a.name.contains(':') || built.iter().any(|b: &App| b.cfg.name == a.name) {
                return Err(format!("channel {id}: app names must be unique, non-empty and without ':' ({:?})", a.name));
            }
            let crypt = BizMsgCrypt::new(&a.token, &a.encoding_aes_key, &a.corp_id).map_err(|e| format!("channel {id}: app {}: {e}", a.name))?;
            built.push(App { cfg: a, crypt, token: Mutex::new(None) });
        }
        let apps = Arc::new(built);
        let api = api.unwrap_or(DEFAULT_API).trim_end_matches('/').to_string();
        let (tx, rx) = mpsc::channel();
        let ing = Arc::new(Ingress { apps: apps.clone(), channel: id.to_string(), api: api.clone(), max_skew, seen: Mutex::new(HashMap::new()), tx: Mutex::new(tx) });
        let handler: Handler = Arc::new(move |r: Request| ing.handle(r));
        let server = Server::bind(listen, Opts { max_body: MAX_BODY, ..Opts::default() }, handler).map_err(|e| format!("channel {id}: cannot listen on {listen}: {e}"))?;
        Ok(WecomCallback { id: id.into(), apps, api, poll_timeout, http: Http::new(Duration::from_secs(30)), rx: Mutex::new(rx), addr: server.local_addr(), server: Mutex::new(Some(server)) })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// (app, user) for a chat id: `<app>:<user>`, `<corp_id>:<user>` when one app has that corp,
    /// else the first app.
    fn route<'a>(&self, chat: &'a str) -> (&App, &'a str) {
        if let Some((pre, user)) = chat.split_once(':') {
            if let Some(a) = self.apps.iter().find(|a| a.cfg.name == pre) {
                return (a, user);
            }
            let by_corp: Vec<&App> = self.apps.iter().filter(|a| a.cfg.corp_id == pre).collect();
            if by_corp.len() == 1 {
                return (by_corp[0], user);
            }
        }
        (&self.apps[0], chat)
    }

    fn access_token(&self, app: &App, force: bool) -> Result<String, ChannelError> {
        if !force {
            if let Some((t, exp)) = app.token.lock().unwrap().clone() {
                if Instant::now() < exp {
                    return Ok(t);
                }
            }
        }
        let url = format!("{}/cgi-bin/gettoken?corpid={}&corpsecret={}", self.api, ark_net::urlencode(&app.cfg.corp_id), ark_net::urlencode(&app.cfg.corp_secret));
        let r = self.http.call("GET", &url, &[], Payload::None).map_err(|e| ChannelError::new(e.kind, "gettoken: request failed"))?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, "gettoken", ""));
        }
        let v: Value = serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, "gettoken: bad JSON"))?;
        if v["errcode"].as_i64().unwrap_or(0) != 0 || v["access_token"].as_str().is_none() {
            let e = errcode_error("gettoken", &v);
            // Wrong corp id / secret is an auth problem whatever the code.
            return Err(if e.kind == K::Protocol { ChannelError::new(K::Auth, e.message) } else { e });
        }
        let t = v["access_token"].as_str().unwrap_or("").to_string();
        let ttl = v["expires_in"].as_u64().unwrap_or(7200).saturating_sub(60).max(1);
        *app.token.lock().unwrap() = Some((t.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(t)
    }

    /// One API call with the access token; a rejected token is refreshed once.
    fn api_call(&self, app: &App, method: &str, path: &str, extra_q: &str, body: Payload) -> Result<Value, ChannelError> {
        let body_bytes: Option<Value> = match &body {
            Payload::Json(v) => Some((*v).clone()),
            _ => None,
        };
        let mut payload = Some(body);
        for attempt in 0..2 {
            let tok = self.access_token(app, attempt > 0)?;
            let url = format!("{}{path}?access_token={}{extra_q}", self.api, ark_net::urlencode(&tok));
            let p = match (&body_bytes, payload.take()) {
                (Some(v), _) => Payload::Json(v),
                (None, Some(p)) => p,
                (None, None) => return Err(ChannelError::new(K::Fatal, "cannot replay request body")),
            };
            let r = self.http.call(method, &url, &[], p).map_err(scrub)?;
            if !(200..300).contains(&r.status) {
                return Err(scrub(classify(r.status, r.retry_after, path, &r.body)));
            }
            let v: Value = serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, format!("{path}: bad JSON")))?;
            match v["errcode"].as_i64().unwrap_or(0) {
                0 => return Ok(v),
                40001 | 42001 | 40014 if attempt == 0 && body_bytes.is_some() => {
                    *app.token.lock().unwrap() = None;
                    continue;
                }
                _ => return Err(errcode_error(path, &v)),
            }
        }
        Err(ChannelError::new(K::Auth, format!("{path}: access token rejected after refresh")))
    }

    fn send_msg(&self, app: &App, to: &str, msgtype: &str, content: Value) -> Result<String, ChannelError> {
        let mut body = json!({"touser": to, "msgtype": msgtype, "agentid": app.cfg.agent_id, "safe": 0});
        body[msgtype] = content;
        let v = self.api_call(app, "POST", "/cgi-bin/message/send", "", Payload::Json(&body))?;
        // Partial delivery: the user is invalid / out of the app's range.
        if v["invaliduser"].as_str().is_some_and(|s| !s.is_empty()) {
            return Err(ChannelError::new(K::NotFound, format!("message/send: invalid user {}", v["invaliduser"].as_str().unwrap_or(""))));
        }
        Ok(v["msgid"].as_str().map(str::to_string).unwrap_or_default())
    }

    fn upload(&self, app: &App, m: &Media) -> Result<(String, &'static str), ChannelError> {
        let kind = match m.kind {
            MediaKind::Image | MediaKind::Sticker | MediaKind::Animation => "image",
            MediaKind::Voice => "voice",
            MediaKind::Video => "video",
            _ => "file",
        };
        let (data, name) = match (&m.path, &m.url) {
            (Some(p), _) => (
                std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?,
                std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()),
            ),
            (None, Some(u)) => (crate::http::get_bytes(u, &[], 20 * 1024 * 1024)?, u.rsplit('/').next().and_then(|s| s.split('?').next()).filter(|s| !s.is_empty()).unwrap_or("file").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let name = if m.name.is_empty() { name } else { m.name.clone() };
        let parts: [(&str, &str, &str, &[u8]); 1] = [("media", &name, &m.mime, &data)];
        let v = self.api_call(app, "POST", "/cgi-bin/media/upload", &format!("&type={kind}"), Payload::Multipart(&parts))?;
        let id = v["media_id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "media/upload: no media_id"))?;
        Ok((id.to_string(), kind))
    }
}

fn button_text(rows: &[Vec<crate::Button>]) -> String {
    let mut s = String::new();
    for (i, b) in rows.iter().flatten().enumerate() {
        match &b.url {
            Some(u) => s.push_str(&format!("\n{}. {} {u}", i + 1, b.label)),
            None => s.push_str(&format!("\n{}. {}", i + 1, b.label)),
        }
    }
    s
}

impl Channel for WecomCallback {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], media: true, reply: false, threads: false, reactions: 0, edit: false, delete: true, typing: false, buttons: false, polls: false, native_commands: false, streaming: Streaming::None, max_len: MAX_MESSAGE, len_unit: LenUnit::Bytes, markup: Markup::Markdown }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                got.push(v);
                got.extend(rx.try_iter());
            }
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let (app, to) = self.route(&out.chat);
        let mut sent = Sent::default();
        for m in &out.media {
            let (id, kind) = self.upload(app, m)?;
            sent.ids.push(self.send_msg(app, to, kind, json!({"media_id": id}))?);
        }
        let mut text = out.text.clone();
        if !out.buttons.is_empty() {
            text.push_str(&button_text(&out.buttons));
        }
        if text.trim().is_empty() {
            return Ok(sent);
        }
        let msgtype = if out.format == TextFormat::Markdown { "markdown" } else { "text" };
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Bytes) {
            sent.ids.push(self.send_msg(app, to, msgtype, json!({"content": piece}))?);
        }
        Ok(sent)
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.api_call(self.route(chat).0, "POST", "/cgi-bin/message/recall", "", Payload::Json(&json!({"msgid": message_id}))).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let tagged = m.url.as_deref().and_then(|u| u.split_once('?')).and_then(|(_, q)| ark_net::parse_query(q).into_iter().find(|(k, _)| k == "app").map(|(_, v)| v));
        let app = tagged.and_then(|n| self.apps.iter().find(|a| a.cfg.name == n)).unwrap_or(&self.apps[0]);
        let Some(id) = m.id.as_deref() else {
            return match &m.url {
                Some(u) => crate::http::get_bytes(u, &[], 50 * 1024 * 1024),
                None => Err(crate::unsupported("media without id")),
            };
        };
        for attempt in 0..2 {
            let tok = self.access_token(app, attempt > 0)?;
            let url = format!("{}/cgi-bin/media/get?access_token={}&media_id={}", self.api, ark_net::urlencode(&tok), ark_net::urlencode(id));
            let bytes = crate::http::get_bytes(&url, &[], 50 * 1024 * 1024).map_err(scrub)?;
            // Errors come back as a JSON body with 200.
            if bytes.first() == Some(&b'{') {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(code) = v["errcode"].as_i64().filter(|c| *c != 0) {
                        if attempt == 0 && matches!(code, 40001 | 42001 | 40014) {
                            *app.token.lock().unwrap() = None;
                            continue;
                        }
                        return Err(errcode_error("media/get", &v));
                    }
                }
            }
            return Ok(bytes);
        }
        Err(ChannelError::new(K::Auth, "media/get: token rejected"))
    }

    fn stop(&self) {
        self.server.lock().unwrap().take();
    }
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    DEFAULT_PATH.into()
}
fn d_skew() -> i64 {
    600
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AppSettings {
    name: String,
    /// Defaults to the channel's `path`.
    #[serde(default)]
    path: Option<String>,
    corp_id: String,
    corp_secret: String,
    agent_id: Value,
    token: String,
    encoding_aes_key: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    listen: String,
    #[serde(default = "d_path")]
    path: String,
    /// Single-app form; or list the apps in `apps`.
    #[serde(default)]
    corp_id: Option<String>,
    #[serde(default)]
    corp_secret: Option<String>,
    #[serde(default)]
    agent_id: Option<Value>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    encoding_aes_key: Option<String>,
    #[serde(default)]
    apps: Vec<AppSettings>,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Reject callbacks whose timestamp is further than this from now (0 = off).
    #[serde(default = "d_skew")]
    max_skew_secs: i64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let agent = |v: &Value| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).ok_or_else(|| format!("channel {}: agent_id must be a number", ctx.name));
    let single = [st.corp_id.is_some(), st.corp_secret.is_some(), st.agent_id.is_some(), st.token.is_some(), st.encoding_aes_key.is_some()];
    let mut apps = Vec::new();
    if single.iter().any(|x| *x) {
        if !st.apps.is_empty() {
            return Err(format!("channel {}: use either corp_id/corp_secret/agent_id/token/encoding_aes_key or apps, not both", ctx.name));
        }
        let need = |v: &Option<String>, k: &str| v.clone().ok_or_else(|| format!("channel {}: missing {k}", ctx.name));
        apps.push(AppConfig {
            name: "default".into(),
            path: st.path.clone(),
            corp_id: need(&st.corp_id, "corp_id")?,
            corp_secret: ctx.secret("corp_secret", &need(&st.corp_secret, "corp_secret")?)?,
            agent_id: agent(st.agent_id.as_ref().ok_or_else(|| format!("channel {}: missing agent_id", ctx.name))?)?,
            token: ctx.secret("token", &need(&st.token, "token")?)?,
            encoding_aes_key: ctx.secret("encoding_aes_key", &need(&st.encoding_aes_key, "encoding_aes_key")?)?,
        });
    }
    for a in &st.apps {
        apps.push(AppConfig {
            name: a.name.clone(),
            path: a.path.clone().unwrap_or_else(|| st.path.clone()),
            corp_id: a.corp_id.clone(),
            corp_secret: ctx.secret("corp_secret", &a.corp_secret)?,
            agent_id: agent(&a.agent_id)?,
            token: ctx.secret("token", &a.token)?,
            encoding_aes_key: ctx.secret("encoding_aes_key", &a.encoding_aes_key)?,
        });
    }
    let c = WecomCallback::with_apps(ctx.name, &st.listen, apps, st.api_base.as_deref(), st.poll_timeout_secs, st.max_skew_secs)?;
    Ok(Arc::new(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;

    const KEY: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    const CORP: &str = "ww1234567890";
    const TOK: &str = "QDG6eK";

    fn crypt() -> BizMsgCrypt {
        BizMsgCrypt::new(TOK, KEY, CORP).unwrap()
    }

    fn chan(api: &str) -> WecomCallback {
        WecomCallback::new("wc", "127.0.0.1:0", DEFAULT_PATH, TOK, KEY, CORP, "SEKRIT", 1000002, Some(api), 1, 600).unwrap()
    }

    fn ok(v: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], v.to_string())
    }

    fn api_server() -> FakeServer {
        FakeServer::start(|req, n| {
            if req.path.starts_with("/cgi-bin/gettoken") {
                return ok(json!({"errcode": 0, "access_token": format!("AT{n}"), "expires_in": 7200}));
            }
            if req.path.starts_with("/cgi-bin/media/upload") {
                return ok(json!({"errcode": 0, "type": "image", "media_id": "MID1"}));
            }
            if req.path.starts_with("/cgi-bin/media/get") {
                return (200, vec![], "IMGBYTES".into());
            }
            ok(json!({"errcode": 0, "errmsg": "ok", "msgid": format!("m{n}")}))
        })
    }

    #[test]
    fn known_answer_vector_matches_python_wxbizmsgcrypt() {
        // Generated with the `cryptography` package following wecom_crypto.py: random16 = "0123456789abcdef".
        let c = crypt();
        assert_eq!(crypto::hex(&c.key), "69b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3d0010831051");
        let enc = c.encrypt_with(b"0123456789abcdef", b"<xml><Content>hello</Content></xml>");
        let want = "Q3stYC6hdFzMh9T8HCvyDMcJoZqH77JLLihyfUJHFtaQDaMkuCR40Frpevlcp2SZYDzX5AFXH5id4a/cROBB4SkTPzqAWPeyAMic8QkhHnYnEG1fKUHg8QrkdXLj6YQ8";
        assert_eq!(enc, want);
        assert_eq!(signature(TOK, "1409659813", "263014780", want), "f242fded9da967069ceea653e6fa7539910db560");
        assert!(c.verify("F242FDED9DA967069CEEA653E6FA7539910DB560", "1409659813", "263014780", want));
        assert_eq!(c.decrypt(want).unwrap(), b"<xml><Content>hello</Content></xml>");
        // Round trip for every padding length, incl. a full 32-byte pad block.
        for n in 0..70 {
            let msg = vec![b'x'; n];
            assert_eq!(c.decrypt(&c.encrypt(&msg)).unwrap(), msg, "len {n}");
        }
        // Wrong corp id refused; bad keys refused.
        let other = BizMsgCrypt::new(TOK, KEY, "wwOTHER").unwrap();
        assert!(other.decrypt(want).unwrap_err().contains("receive_id"));
        assert!(BizMsgCrypt::new(TOK, "short", CORP).is_err());
        assert!(c.decrypt("not base64!!").is_err());
        let env = c.envelope("<xml/>", "1", "n");
        let e = xml_tag(&env, "Encrypt").unwrap();
        assert!(c.verify(&xml_tag(&env, "MsgSignature").unwrap(), "1", "n", &e));
    }

    #[test]
    fn xml_extractor_handles_cdata_entities_and_refuses_dtds() {
        let x = "<xml><A><![CDATA[a<b>]]></A><B>x &amp; y</B><C></C></xml>";
        assert_eq!(xml_tag(x, "A").as_deref(), Some("a<b>"));
        assert_eq!(xml_tag(x, "B").as_deref(), Some("x & y"));
        assert_eq!(xml_tag(x, "C").as_deref(), Some(""));
        assert_eq!(xml_tag(x, "D"), None);
        assert!(!xml_safe("<!DOCTYPE x [<!ENTITY a \"b\">]><xml/>"));
        assert!(!xml_safe("<!entity a>"));
        assert!(xml_safe(x));
    }

    fn post(ch: &WecomCallback, query: &str, body: &str) -> (u16, String) {
        let a = crate::http::agent(Duration::from_secs(5));
        match a.post(&format!("http://{}{DEFAULT_PATH}?{query}", ch.local_addr())).send(body.as_bytes()) {
            Ok(mut r) => (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()),
            Err(_) => (0, String::new()),
        }
    }

    fn get(ch: &WecomCallback, path_q: &str) -> (u16, String) {
        let a = crate::http::agent(Duration::from_secs(5));
        match a.get(&format!("http://{}{path_q}", ch.local_addr())).call() {
            Ok(mut r) => (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()),
            Err(_) => (0, String::new()),
        }
    }

    fn signed(inner: &str, ts: i64, nonce: &str) -> (String, String) {
        let c = crypt();
        let enc = c.encrypt(inner.as_bytes());
        let sig = signature(TOK, &ts.to_string(), nonce, &enc);
        (format!("msg_signature={sig}&timestamp={ts}&nonce={nonce}"), format!("<xml><ToUserName><![CDATA[{CORP}]]></ToUserName><Encrypt><![CDATA[{enc}]]></Encrypt><AgentID>1000002</AgentID></xml>"))
    }

    #[test]
    fn url_verification_handshake() {
        let api = api_server();
        let ch = chan(&api.url);
        let c = crypt();
        let echo = c.encrypt(b"1616140317555161061");
        let sig = signature(TOK, "1700000000", "nn", &echo);
        let q = |s: &str| format!("{DEFAULT_PATH}?msg_signature={s}&timestamp=1700000000&nonce=nn&echostr={}", ark_net::urlencode(&echo));
        assert_eq!(get(&ch, &q(&sig)), (200, "1616140317555161061".into()));
        assert_eq!(get(&ch, &q("deadbeef")).0, 401, "bad signature");
        assert_eq!(get(&ch, &format!("{DEFAULT_PATH}?echostr=x")).0, 401, "missing signature");
        assert_eq!(get(&ch, "/elsewhere?msg_signature=a&timestamp=1&nonce=2").0, 404);
        // An echostr encrypted for another corp passes the signature but fails the receive id.
        let foreign = BizMsgCrypt::new(TOK, KEY, "wwOTHER").unwrap().encrypt(b"x");
        let fsig = signature(TOK, "1700000000", "nn", &foreign);
        assert_eq!(get(&ch, &format!("{DEFAULT_PATH}?msg_signature={fsig}&timestamp=1700000000&nonce=nn&echostr={}", ark_net::urlencode(&foreign))).0, 400);
    }

    #[test]
    fn callbacks_parse_every_kind_and_reject_bad_signed_stale_and_replayed() {
        let api = api_server();
        let ch = chan(&api.url);
        let now = now_secs();
        let msgs = [
            "<xml><ToUserName><![CDATA[ww1234567890]]></ToUserName><FromUserName><![CDATA[amy]]></FromUserName><CreateTime>1700000000</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[ hello <b> ]]></Content><MsgId>111</MsgId><AgentID>1000002</AgentID></xml>",
            "<xml><FromUserName><![CDATA[amy]]></FromUserName><CreateTime>1700000001</CreateTime><MsgType><![CDATA[image]]></MsgType><PicUrl><![CDATA[http://p/x.jpg]]></PicUrl><MediaId><![CDATA[MEDIA_1]]></MediaId><MsgId>112</MsgId></xml>",
            "<xml><FromUserName><![CDATA[amy]]></FromUserName><CreateTime>1700000002</CreateTime><MsgType><![CDATA[voice]]></MsgType><MediaId><![CDATA[V1]]></MediaId><Format><![CDATA[amr]]></Format><Recognition><![CDATA[你好]]></Recognition><MsgId>113</MsgId></xml>",
            "<xml><FromUserName><![CDATA[amy]]></FromUserName><CreateTime>1700000003</CreateTime><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[enter_agent]]></Event></xml>",
            "<xml><FromUserName><![CDATA[amy]]></FromUserName><CreateTime>1700000004</CreateTime><MsgType><![CDATA[event]]></MsgType><Event><![CDATA[click]]></Event><EventKey><![CDATA[appr:1:once]]></EventKey></xml>",
            "<xml><FromUserName><![CDATA[bob]]></FromUserName><CreateTime>1700000005</CreateTime><MsgType><![CDATA[video]]></MsgType><MediaId><![CDATA[VID]]></MediaId><MsgId>115</MsgId></xml>",
            "<xml><FromUserName><![CDATA[bob]]></FromUserName><CreateTime>1700000006</CreateTime><MsgType><![CDATA[location]]></MsgType><Location_X>23.1</Location_X><Location_Y>113.3</Location_Y><Label><![CDATA[廣州]]></Label><MsgId>116</MsgId></xml>",
        ];
        for (i, m) in msgs.iter().enumerate() {
            let (q, b) = signed(m, now, &format!("n{i}"));
            assert_eq!(post(&ch, &q, &b), (200, "success".into()), "msg {i}");
        }
        let got = ch.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 6, "enter_agent is dropped");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].text.as_str(), got[0].message_id.as_str(), got[0].chat_type, got[0].ts), ("amy", "amy", "hello <b>", "111", ChatType::Direct, 1700000000));
        assert_eq!((got[1].media[0].kind, got[1].media[0].id.as_deref()), (MediaKind::Image, Some("MEDIA_1")));
        assert_eq!((got[2].text.as_str(), got[2].media[0].kind, got[2].media[0].mime.as_str()), ("你好", MediaKind::Voice, "audio/amr"));
        assert_eq!(got[3].callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(got[4].media[0].kind, MediaKind::Video);
        assert!(got[5].text.contains("廣州"));
        // Bad signature: 401 and nothing queued.
        let (q, b) = signed(msgs[0], now, "zz");
        let bad = q.replace("msg_signature=", "msg_signature=00");
        assert_eq!(post(&ch, &bad, &b).0, 401);
        assert_eq!(post(&ch, "timestamp=1&nonce=2", &b).0, 401, "missing signature");
        // Stale timestamp (validly signed) refused.
        let (q, b) = signed(msgs[0], now - 3600, "old");
        assert_eq!(post(&ch, &q, &b).0, 401);
        // Replay of an accepted envelope: acknowledged, not queued again.
        let (q, b) = signed(msgs[0], now, "rp");
        assert_eq!(post(&ch, &q, &b).0, 200);
        assert_eq!(post(&ch, &q, &b), (200, "success".into()));
        assert_eq!(ch.poll(&Cancel::new()).unwrap().len(), 1);
        // DTD in the envelope refused before anything else.
        assert_eq!(post(&ch, &q, "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><xml><Encrypt>&e;</Encrypt></xml>").0, 400);
        // Payload for another corp, correctly signed: rejected.
        let enc = BizMsgCrypt::new(TOK, KEY, "wwOTHER").unwrap().encrypt(msgs[0].as_bytes());
        let sig = signature(TOK, &now.to_string(), "fc", &enc);
        assert_eq!(post(&ch, &format!("msg_signature={sig}&timestamp={now}&nonce=fc"), &format!("<xml><Encrypt>{enc}</Encrypt></xml>")).0, 400);
        assert!(api.requests().is_empty(), "receiving needs no API calls");
    }

    #[test]
    fn send_text_markdown_media_buttons_delete_and_fetch() {
        let api = api_server();
        let ch = chan(&api.url);
        let s = ch.send(&Outbound::text("amy", "hi")).unwrap();
        assert_eq!(s.ids, vec!["m1"]);
        let r = api.requests();
        assert!(r[0].path.starts_with("/cgi-bin/gettoken?corpid=ww1234567890&corpsecret=SEKRIT"));
        assert_eq!(r[1].path, "/cgi-bin/message/send?access_token=AT0");
        assert_eq!(r[1].json(), json!({"touser": "amy", "msgtype": "text", "agentid": 1000002, "safe": 0, "text": {"content": "hi"}}));
        let b = vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://e.com".into()) }]];
        ch.send(&Outbound { format: TextFormat::Markdown, buttons: b, ..Outbound::text("amy", "**pick**") }).unwrap();
        let r = api.requests().last().unwrap().json();
        assert_eq!(r["msgtype"], "markdown");
        assert_eq!(r["markdown"]["content"], "**pick**\n1. Yes\n2. Docs https://e.com");
        assert_eq!(api.requests().iter().filter(|r| r.path.starts_with("/cgi-bin/gettoken")).count(), 1, "token cached");
        let f = crate::testutil::temp_dir("wc").join("a.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let s = ch.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), mime: "image/png".into(), ..Default::default() }], ..Outbound::text("amy", "") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let rs = api.requests();
        let up = &rs[rs.len() - 2];
        assert!(up.path.starts_with("/cgi-bin/media/upload?access_token=AT0&type=image"));
        assert!(up.body.contains("name=\"media\"; filename=\"a.png\"") && up.body.contains("PNGDATA"));
        assert_eq!(rs[rs.len() - 1].json()["image"]["media_id"], "MID1");
        // Long text splits on bytes.
        let long = "字".repeat(1500);
        let s = ch.send(&Outbound::text("amy", &long)).unwrap();
        assert_eq!(s.ids.len(), 3);
        ch.delete("amy", "m1").unwrap();
        let rs = api.requests();
        assert_eq!((rs.last().unwrap().path.as_str(), rs.last().unwrap().json()["msgid"].as_str()), ("/cgi-bin/message/recall?access_token=AT0", Some("m1")));
        let bytes = ch.fetch_media(&Media { id: Some("MEDIA_1".into()), ..Default::default() }).unwrap();
        assert_eq!(bytes, b"IMGBYTES");
        assert_eq!(api.requests().last().unwrap().path, "/cgi-bin/media/get?access_token=AT0&media_id=MEDIA_1");
    }

    #[test]
    fn errors_map_and_expired_tokens_refresh_once() {
        // Token expired on first send: refreshed then retried.
        let api = FakeServer::start(|req, n| {
            if req.path.starts_with("/cgi-bin/gettoken") {
                return ok(json!({"errcode": 0, "access_token": format!("AT{n}"), "expires_in": 7200}));
            }
            if req.path.ends_with("AT0") {
                return ok(json!({"errcode": 42001, "errmsg": "access_token expired"}));
            }
            ok(json!({"errcode": 0, "msgid": "ok"}))
        });
        let ch = chan(&api.url);
        assert_eq!(ch.send(&Outbound::text("amy", "x")).unwrap().ids, vec!["ok"]);
        let paths: Vec<String> = api.requests().iter().map(|r| r.path.split('?').next().unwrap().to_string()).collect();
        assert_eq!(paths, ["/cgi-bin/gettoken", "/cgi-bin/message/send", "/cgi-bin/gettoken", "/cgi-bin/message/send"]);
        for (body, kind) in [
            (json!({"errcode": 81013, "errmsg": "user & party & tag all invalid"}), K::NotFound),
            (json!({"errcode": 45009, "errmsg": "api freq out of limit"}), K::RateLimited { retry_after: Some(Duration::from_secs(60)) }),
            (json!({"errcode": -1, "errmsg": "system busy"}), K::Network),
            (json!({"errcode": 0, "invaliduser": "ghost"}), K::NotFound),
            (json!({"errcode": 40008, "errmsg": "invalid message type"}), K::Protocol),
        ] {
            let b = body.clone();
            let api = FakeServer::start(move |req, _| if req.path.starts_with("/cgi-bin/gettoken") { ok(json!({"errcode": 0, "access_token": "SECRETTOKEN"})) } else { ok(b.clone()) });
            let e = chan(&api.url).send(&Outbound::text("amy", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{body}");
            assert!(!e.message.contains("SECRETTOKEN"), "{}", e.message);
        }
        // Bad corp secret → Auth; HTTP 5xx → Network; 429 → RateLimited.
        let api = FakeServer::start(|_, _| ok(json!({"errcode": 40001, "errmsg": "invalid credential"})));
        assert_eq!(chan(&api.url).send(&Outbound::text("amy", "x")).unwrap_err().kind, K::Auth);
        let api = FakeServer::start(|req, _| if req.path.starts_with("/cgi-bin/gettoken") { ok(json!({"errcode": 0, "access_token": "SECRETTOKEN"})) } else { (502, vec![], "bad gateway".into()) });
        let e = chan(&api.url).send(&Outbound::text("amy", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert!(!e.message.contains("SECRETTOKEN"));
        let api = FakeServer::start(|req, _| if req.path.starts_with("/cgi-bin/gettoken") { ok(json!({"errcode": 0, "access_token": "T"})) } else { (429, vec![("Retry-After".into(), "7".into())], "{}".into()) });
        assert_eq!(chan(&api.url).send(&Outbound::text("amy", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(7)) });
    }

    #[test]
    fn several_apps_route_by_path_signature_and_agent_id() {
        let api = api_server();
        const KEY2: &str = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvut";
        let app = |name: &str, path: &str, tok: &str, key: &str, corp: &str, agent: i64| AppConfig { name: name.into(), path: path.into(), token: tok.into(), encoding_aes_key: key.into(), corp_id: corp.into(), corp_secret: format!("S-{name}"), agent_id: agent };
        let ch = WecomCallback::with_apps(
            "wc",
            "127.0.0.1:0",
            vec![app("sales", "/wecom/a", TOK, KEY, CORP, 1), app("ops", "/wecom/b", "T2", KEY2, "wwB", 2), app("hr", "/wecom/b", "T2", KEY2, "wwB", 3)],
            Some(&api.url),
            1,
            600,
        )
        .unwrap();
        let post_to = |path: &str, tok: &str, c: &BizMsgCrypt, inner: &str, nonce: &str| {
            let now = now_secs();
            let enc = c.encrypt(inner.as_bytes());
            let sig = signature(tok, &now.to_string(), nonce, &enc);
            let a = crate::http::agent(Duration::from_secs(5));
            match a.post(&format!("http://{}{path}?msg_signature={sig}&timestamp={now}&nonce={nonce}", ch.local_addr())).send(format!("<xml><Encrypt><![CDATA[{enc}]]></Encrypt></xml>").as_bytes()) {
                Ok(r) => r.status().as_u16(),
                Err(_) => 0,
            }
        };
        let b = BizMsgCrypt::new("T2", KEY2, "wwB").unwrap();
        let msg = |user: &str, agent: i64, id: u32| format!("<xml><FromUserName><![CDATA[{user}]]></FromUserName><CreateTime>1700000000</CreateTime><MsgType><![CDATA[image]]></MsgType><MediaId><![CDATA[M{id}]]></MediaId><MsgId>{id}</MsgId><AgentID>{agent}</AgentID></xml>");
        assert_eq!(post_to("/wecom/b", "T2", &b, &msg("amy", 3, 1), "n1"), 200);
        assert_eq!(post_to("/wecom/b", "T2", &b, &msg("amy", 2, 2), "n2"), 200);
        assert_eq!(post_to("/wecom/a", TOK, &crypt(), &msg("bob", 1, 3), "n3"), 200);
        // Signed for app b but posted on a's path: a's token does not verify it.
        assert_eq!(post_to("/wecom/a", "T2", &b, &msg("eve", 2, 4), "n4"), 401);
        assert_eq!(post_to("/wecom/c", TOK, &crypt(), &msg("eve", 1, 5), "n5"), 404);
        let got = ch.poll(&Cancel::new()).unwrap();
        let chats: Vec<&str> = got.iter().map(|m| m.chat.as_str()).collect();
        assert_eq!(chats, ["hr:amy", "ops:amy", "sales:bob"]);
        assert_eq!(got[0].sender, "amy");
        assert!(got[0].media[0].url.as_deref().unwrap().ends_with("media_id=M1&app=hr"));
        // Replies go out through the app the chat names (or a unique corp id) with its token and agent id.
        ch.send(&Outbound::text("hr:amy", "hi")).unwrap();
        ch.send(&Outbound::text("wwww1234567890:bob", "x")).ok();
        ch.send(&Outbound::text("ww1234567890:bob", "yo")).unwrap();
        let rs = api.requests();
        let sends: Vec<Value> = rs.iter().filter(|r| r.path.starts_with("/cgi-bin/message/send")).map(|r| r.json()).collect();
        assert_eq!((sends[0]["touser"].as_str(), sends[0]["agentid"].as_i64()), (Some("amy"), Some(3)));
        assert_eq!((sends[2]["touser"].as_str(), sends[2]["agentid"].as_i64()), (Some("bob"), Some(1)));
        let toks: Vec<&str> = rs.iter().filter(|r| r.path.starts_with("/cgi-bin/gettoken")).map(|r| r.path.as_str()).collect();
        assert!(toks[0].contains("corpid=wwB&corpsecret=S-hr") && toks[1].contains("corpsecret=S-sales"), "{toks:?}");
        ch.fetch_media(&got[1].media[0]).unwrap();
        assert!(api.requests().iter().filter(|r| r.path.starts_with("/cgi-bin/gettoken")).any(|r| r.path.contains("S-ops")));
        // Duplicate or malformed app names are refused.
        assert!(WecomCallback::with_apps("wc", "127.0.0.1:0", vec![app("x", "/a", TOK, KEY, CORP, 1), app("x", "/b", TOK, KEY, CORP, 2)], None, 1, 0).is_err());
        assert!(WecomCallback::with_apps("wc", "127.0.0.1:0", vec![app("a:b", "/a", TOK, KEY, CORP, 1)], None, 1, 0).is_err());
    }

    #[test]
    fn cancel_returns_promptly_and_build_validates_settings() {
        let ch = chan("http://127.0.0.1:1");
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        let mut ch = ch;
        ch.poll_timeout = 30;
        assert!(ch.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
        ch.stop();
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:K}}", KEY));
        let d = crate::testutil::temp_dir("wc");
        let ctx = crate::config::Ctx { name: "wc", state_dir: &d, secrets: &secrets };
        let ok_s = json!({"listen": "127.0.0.1:0", "corp_id": CORP, "corp_secret": "s", "agent_id": "1000002", "token": TOK, "encoding_aes_key": "{{secret:K}}"});
        assert!(build(&ctx, ok_s.as_object().unwrap()).is_ok());
        let mut bad = ok_s.clone();
        bad["encoding_aes_key"] = json!("short");
        assert!(build(&ctx, bad.as_object().unwrap()).err().unwrap().contains("43"));
        let mut typo = ok_s.clone();
        typo["agentid"] = json!(1);
        assert!(build(&ctx, typo.as_object().unwrap()).is_err());
        let mut missing = ok_s.clone();
        missing["encoding_aes_key"] = json!("{{secret:NOPE}}");
        assert!(build(&ctx, missing.as_object().unwrap()).err().unwrap().contains("not set"));
        let multi = json!({"listen": "127.0.0.1:0", "apps": [
            {"name": "a", "corp_id": CORP, "corp_secret": "s", "agent_id": 1, "token": TOK, "encoding_aes_key": "{{secret:K}}"},
            {"name": "b", "path": "/wecom/b", "corp_id": CORP, "corp_secret": "s", "agent_id": "2", "token": TOK, "encoding_aes_key": KEY}]});
        assert!(build(&ctx, multi.as_object().unwrap()).is_ok());
        let mut both = multi.clone();
        both["corp_id"] = json!(CORP);
        assert!(build(&ctx, both.as_object().unwrap()).err().unwrap().contains("not both"));
        let mut partial = ok_s;
        partial.as_object_mut().unwrap().remove("token");
        assert!(build(&ctx, partial.as_object().unwrap()).err().unwrap().contains("missing token"));
        assert!(build(&ctx, json!({"listen": "127.0.0.1:0"}).as_object().unwrap()).err().unwrap().contains("no apps"));
    }
}
