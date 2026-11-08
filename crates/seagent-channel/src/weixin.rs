//! Weixin (personal WeChat) over Tencent's iLink Bot API (ported from Hermes
//! `plugins/platforms/weixin/adapter.py`, MIT).
//!
//! Receive: long-poll `ilink/bot/getupdates` with the opaque `get_updates_buf`
//! cursor, committed to the state file only when the caller polls again
//! (at-least-once, like Telegram). Every inbound `context_token` is remembered
//! per peer (persisted) and echoed on replies. Text, quoted messages, image /
//! video / file / voice items; media lives on an AES-128-ECB encrypted CDN and
//! `fetch_media` downloads + decrypts it.
//! Send: `sendmessage` text items (split at 2000 chars), media via
//! `getuploadurl` → encrypted CDN `POST` (`x-encrypted-param`) → media item,
//! typing via `getconfig` (typing_ticket, cached 10 min) + `sendtyping`.
//! A stale session (`-14`, or `-2` "unknown error"/"prepare failed") is retried
//! once without `context_token`; an expired bot session is `Auth` (re-login).
//! Login: `qr_login_start` / `qr_login_poll` drive `get_bot_qrcode` /
//! `get_qrcode_status`; `save_account` stores the result where `build` finds it.

use crate::http::{agent, classify, post_cancellable};
use crate::{sleep_cancellable, write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use seagent_core::Cancel;
use seagent_net::crypto;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_BASE: &str = "https://ilinkai.weixin.qq.com";
pub const DEFAULT_CDN: &str = "https://novac2c.cdn.weixin.qq.com/c2c";
pub const MAX_MESSAGE: usize = 2000;
const APP_ID: &str = "bot";
const CHANNEL_VERSION: &str = "2.2.0";
/// (2 << 16) | (2 << 8) | 0
const CLIENT_VERSION: u32 = (2 << 16) | (2 << 8);
const SESSION_EXPIRED: i64 = -14;
const RATE_LIMIT: i64 = -2;
const ITEM_TEXT: i64 = 1;
const ITEM_IMAGE: i64 = 2;
const ITEM_VOICE: i64 = 3;
const ITEM_FILE: i64 = 4;
const ITEM_VIDEO: i64 = 5;
const MSG_TYPE_BOT: i64 = 2;
const TYPING_TTL: Duration = Duration::from_secs(600);
const CDN_ALLOW: [&str; 7] = ["novac2c.cdn.weixin.qq.com", "ilinkai.weixin.qq.com", "wx.qlogo.cn", "thirdwx.qlogo.cn", "res.wx.qq.com", "mmbiz.qpic.cn", "mmbiz.qlogo.cn"];

// ---------------------------------------------------------------- crypto

/// AES-128-ECB with PKCS#7 (the CDN's scheme).
pub fn ecb_encrypt(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let aes = crypto::Aes::new(key).expect("16-byte key");
    let pad = 16 - plain.len() % 16;
    let mut d = plain.to_vec();
    d.extend(std::iter::repeat_n(pad as u8, pad));
    for c in d.chunks_mut(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(c);
        aes.encrypt_block(&mut b);
        c.copy_from_slice(&b);
    }
    d
}

/// Decrypt; strips PKCS#7 only when well-formed (as upstream). `None` on a ragged length.
pub fn ecb_decrypt(key: &[u8; 16], cipher: &[u8]) -> Option<Vec<u8>> {
    if !cipher.len().is_multiple_of(16) {
        return None;
    }
    let aes = crypto::Aes::new(key)?;
    let mut d = cipher.to_vec();
    for c in d.chunks_mut(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(c);
        aes.decrypt_block(&mut b);
        c.copy_from_slice(&b);
    }
    if let Some(&p) = d.last() {
        let p = p as usize;
        if (1..=16).contains(&p) && d.len() >= p && d[d.len() - p..].iter().all(|&x| x as usize == p) {
            d.truncate(d.len() - p);
        }
    }
    Some(d)
}

/// `aes_key` arrives as base64(raw 16 bytes) or base64(32 hex chars).
pub fn parse_aes_key(b64: &str) -> Option<[u8; 16]> {
    let d = crypto::b64_decode(b64)?;
    let raw = match d.len() {
        16 => d,
        32 => crypto::hex_decode(std::str::from_utf8(&d).ok()?)?,
        _ => return None,
    };
    let mut k = [0u8; 16];
    k.copy_from_slice(raw.get(..16)?);
    Some(k)
}

/// MD5 (RFC 1321) — iLink wants `rawfilemd5`; `ring` has no MD5.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, v) in [a0, b0, c0, d0].iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------- http

/// Headers exactly as adapter.py `_headers` (Content-Type is set by the transport, Content-Length by ureq).
fn headers(token: Option<&str>) -> Vec<(String, String)> {
    let r = crypto::random_bytes(4);
    let uin = u32::from_be_bytes([r[0], r[1], r[2], r[3]]).to_string();
    let mut h = vec![
        ("AuthorizationType".to_string(), "ilink_bot_token".to_string()),
        ("X-WECHAT-UIN".to_string(), crypto::b64(uin.as_bytes())),
        ("iLink-App-Id".to_string(), APP_ID.to_string()),
        ("iLink-App-ClientVersion".to_string(), CLIENT_VERSION.to_string()),
    ];
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        h.push(("Authorization".to_string(), format!("Bearer {t}")));
    }
    h
}

fn ret_codes(v: &Value) -> (i64, i64, String) {
    (v["ret"].as_i64().unwrap_or(0), v["errcode"].as_i64().unwrap_or(0), v["errmsg"].as_str().or_else(|| v["msg"].as_str()).unwrap_or("").to_string())
}

fn is_stale(ret: i64, errcode: i64, msg: &str) -> bool {
    (ret == RATE_LIMIT || errcode == RATE_LIMIT) && matches!(msg.to_ascii_lowercase().as_str(), "unknown error" | "prepare failed")
}

fn is_expired(ret: i64, errcode: i64, msg: &str) -> bool {
    ret == SESSION_EXPIRED || errcode == SESSION_EXPIRED || is_stale(ret, errcode, msg)
}

/// iLink's `{ret, errcode, errmsg}` → error kind.
fn ret_error(what: &str, v: &Value) -> Option<ChannelError> {
    let (ret, errcode, msg) = ret_codes(v);
    if ret == 0 && errcode == 0 {
        return None;
    }
    let text = format!("{what}: ret={ret} errcode={errcode} {msg}");
    Some(if ret == SESSION_EXPIRED || errcode == SESSION_EXPIRED {
        ChannelError::new(K::Auth, format!("{text} (iLink session expired: log in again with the QR code)"))
    } else if is_stale(ret, errcode, &msg) {
        ChannelError::new(K::Fatal, format!("{text} — the user must send the bot a message first (or re-pair)"))
    } else if ret == RATE_LIMIT || errcode == RATE_LIMIT {
        ChannelError::new(K::RateLimited { retry_after: Some(Duration::from_secs(3)) }, text)
    } else {
        ChannelError::new(K::Protocol, text)
    })
}

fn parse_body(what: &str, status: u16, retry_after: Option<Duration>, body: &str) -> Result<Value, ChannelError> {
    if !(200..300).contains(&status) {
        return Err(classify(status, retry_after, what, body));
    }
    serde_json::from_str(body).map_err(|_| ChannelError::new(K::Protocol, format!("{what}: bad JSON")))
}

fn api_get(base: &str, endpoint: &str, timeout: Duration) -> Result<Value, ChannelError> {
    let a = agent(timeout);
    let mut r = a.get(format!("{}/{endpoint}", base.trim_end_matches('/'))).header("iLink-App-Id", APP_ID).header("iLink-App-ClientVersion", CLIENT_VERSION.to_string()).call().map_err(|e| ChannelError::new(K::Network, format!("{endpoint}: {e}")))?;
    let status = r.status().as_u16();
    let body = r.body_mut().read_to_string().unwrap_or_default();
    parse_body(endpoint, status, None, &body)
}

// ---------------------------------------------------------------- login

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrCode {
    /// Token for `qr_login_poll`.
    pub qrcode: String,
    /// What WeChat must scan (render this as the QR image).
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub account_id: String,
    pub token: String,
    pub base_url: String,
    #[serde(default)]
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrStatus {
    Wait,
    Scanned,
    /// Keep polling against this base URL.
    Redirect(String),
    /// Fetch a new code with `qr_login_start`.
    Expired,
    Confirmed(Account),
}

/// Step 1: fetch a login QR code (`bot_type` "3" as upstream).
pub fn qr_login_start(base: Option<&str>, bot_type: &str) -> Result<QrCode, ChannelError> {
    let v = api_get(base.unwrap_or(DEFAULT_BASE), &format!("ilink/bot/get_bot_qrcode?bot_type={}", seagent_net::urlencode(bot_type)), Duration::from_secs(35))?;
    let qrcode = v["qrcode"].as_str().unwrap_or("").to_string();
    if qrcode.is_empty() {
        return Err(ChannelError::new(K::Protocol, "get_bot_qrcode: response missing qrcode"));
    }
    Ok(QrCode { qrcode, url: v["qrcode_img_content"].as_str().unwrap_or("").to_string() })
}

/// Step 2: poll (server long-polls up to ~35 s; call again on `Wait`/`Scanned`/`Redirect`).
pub fn qr_login_poll(base: Option<&str>, qrcode: &str) -> Result<QrStatus, ChannelError> {
    let base = base.unwrap_or(DEFAULT_BASE);
    let v = match api_get(base, &format!("ilink/bot/get_qrcode_status?qrcode={}", seagent_net::urlencode(qrcode)), Duration::from_secs(40)) {
        Ok(v) => v,
        Err(e) if e.kind == K::Network && e.message.to_ascii_lowercase().contains("timeout") => return Ok(QrStatus::Wait),
        Err(e) => return Err(e),
    };
    Ok(match v["status"].as_str().unwrap_or("wait") {
        "scaned" => QrStatus::Scanned,
        "scaned_but_redirect" => match v["redirect_host"].as_str().filter(|h| !h.is_empty()) {
            Some(h) => QrStatus::Redirect(format!("https://{h}")),
            None => QrStatus::Wait,
        },
        "expired" => QrStatus::Expired,
        "confirmed" => {
            let a = Account {
                account_id: v["ilink_bot_id"].as_str().unwrap_or("").to_string(),
                token: v["bot_token"].as_str().unwrap_or("").to_string(),
                base_url: v["baseurl"].as_str().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_BASE).to_string(),
                user_id: v["ilink_user_id"].as_str().unwrap_or("").to_string(),
            };
            if a.account_id.is_empty() || a.token.is_empty() {
                return Err(ChannelError::new(K::Protocol, "QR confirmed but the credential payload was incomplete"));
            }
            QrStatus::Confirmed(a)
        }
        _ => QrStatus::Wait,
    })
}

/// Where `build` looks for QR-login credentials of channel `name`.
pub fn account_path(state_dir: &Path, name: &str) -> PathBuf {
    state_dir.join(format!("{name}.weixin-account.json"))
}

/// Persist login credentials (mode 0600).
pub fn save_account(state_dir: &Path, name: &str, a: &Account) -> std::io::Result<()> {
    let p = account_path(state_dir, name);
    write_atomic(&p, serde_json::to_string(a).unwrap_or_default().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = seagent_core::platform::fs_private::set_private(&p);
    Ok(())
}

// ---------------------------------------------------------------- channel

pub struct Weixin {
    id: String,
    account_id: String,
    token: String,
    base: String,
    cdn: String,
    state: PathBuf,
    poll_timeout: u64,
    agent: ureq::Agent,
    pub retry_base: Duration,
    pub max_retries: u32,
    st: Mutex<State>,
    typing: Mutex<HashMap<String, (String, Instant)>>,
}

struct State {
    committed: String,
    pending: Option<String>,
    /// peer → latest context_token.
    tokens: HashMap<String, String>,
}

fn s_of(v: &Value) -> String {
    v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())).or_else(|| v.as_u64().map(|n| n.to_string())).unwrap_or_default().trim().to_string()
}

fn item_text(items: &[Value]) -> (String, Option<ReplyRef>) {
    for it in items {
        if it["type"].as_i64() == Some(ITEM_TEXT) {
            let text = it["text_item"]["text"].as_str().unwrap_or("").to_string();
            let r = &it["ref_msg"];
            let reply = r.is_object().then(|| {
                let ri = &r["message_item"];
                let quoted = if [ITEM_IMAGE, ITEM_VIDEO, ITEM_FILE, ITEM_VOICE].contains(&ri["type"].as_i64().unwrap_or(0)) {
                    "[media]".to_string()
                } else {
                    item_text(std::slice::from_ref(ri)).0
                };
                let title = r["title"].as_str().unwrap_or("");
                ReplyRef { id: s_of(&ri["message_id"]), text: [title, quoted.as_str()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" | "), ..Default::default() }
            });
            return (text, reply);
        }
    }
    for it in items {
        if it["type"].as_i64() == Some(ITEM_VOICE) {
            let v = &it["voice_item"];
            let t = v["text"].as_str().unwrap_or("");
            // Tencent's STT is poor for non-Chinese audio; prefer the raw audio when it exists.
            if !v["media"].is_object() && !t.is_empty() {
                return (format!("[Voice transcription provided by Weixin]\n{t}"), None);
            }
        }
    }
    (String::new(), None)
}

fn media_of(it: &Value, cdn: &str) -> Option<Media> {
    let (key, kind, mime, name) = match it["type"].as_i64()? {
        ITEM_IMAGE => ("image_item", MediaKind::Image, "image/jpeg", "image.jpg"),
        ITEM_VIDEO => ("video_item", MediaKind::Video, "video/mp4", "video.mp4"),
        ITEM_FILE => ("file_item", MediaKind::Document, "", "document.bin"),
        ITEM_VOICE => ("voice_item", MediaKind::Voice, "audio/silk", "voice.silk"),
        _ => return None,
    };
    let p = &it[key];
    let m = &p["media"];
    let url = match (m["encrypt_query_param"].as_str().filter(|s| !s.is_empty()), m["full_url"].as_str().filter(|s| !s.is_empty())) {
        (Some(q), _) => format!("{}/download?encrypted_query_param={}", cdn.trim_end_matches('/'), seagent_net::urlencode(q)),
        (None, Some(u)) => u.to_string(),
        _ => return None,
    };
    // image_item may carry a raw hex `aeskey` beside the media block; it wins.
    let aes = p["aeskey"].as_str().and_then(crypto::hex_decode).map(|k| crypto::b64(&k)).or_else(|| m["aes_key"].as_str().map(str::to_string));
    Some(Media {
        kind,
        url: Some(url),
        id: aes,
        mime: mime.to_string(),
        name: p["file_name"].as_str().unwrap_or(name).to_string(),
        size: p["len"].as_str().and_then(|s| s.parse().ok()).or_else(|| p["len"].as_u64()).unwrap_or(0),
        caption: p["text"].as_str().filter(|s| !s.is_empty()).map(str::to_string),
        ..Default::default()
    })
}

/// One `msgs[]` entry → Inbound. Drops our own and bot messages.
fn inbound_of(channel: &str, account: &str, cdn: &str, m: &Value) -> Option<Inbound> {
    let sender = s_of(&m["from_user_id"]);
    if sender.is_empty() || sender == account || m["message_type"].as_i64() == Some(MSG_TYPE_BOT) {
        return None;
    }
    let items = m["item_list"].as_array().cloned().unwrap_or_default();
    let (text, reply) = item_text(&items);
    let mut media = Vec::new();
    for it in &items {
        media.extend(media_of(it, cdn));
        if it["ref_msg"]["message_item"].is_object() {
            media.extend(media_of(&it["ref_msg"]["message_item"], cdn));
        }
    }
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let room = s_of(&m["room_id"]);
    let room = if room.is_empty() { s_of(&m["chat_room_id"]) } else { room };
    let to = s_of(&m["to_user_id"]);
    let (chat_type, chat) = if !room.is_empty() || (!to.is_empty() && !account.is_empty() && to != account && m["msg_type"].as_i64() == Some(1)) {
        (ChatType::Group, if room.is_empty() { to } else { room })
    } else {
        (ChatType::Direct, sender.clone())
    };
    let ts = m["create_time_ms"].as_i64().map(|t| t / 1000).or_else(|| m["create_time"].as_i64()).unwrap_or(0);
    Some(Inbound { channel: channel.to_string(), chat, chat_type, sender: sender.clone(), sender_name: sender, text, message_id: s_of(&m["message_id"]), ts, media, reply, ..Default::default() })
}

/// Collapse blank-line runs outside fenced code (upstream `_normalize_markdown_blocks`).
fn normalize(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let (mut code, mut blank) = (false, 0);
    for line in text.lines() {
        let l = line.trim_end();
        let fence = l.trim_start().starts_with("```");
        if !fence && !code && l.trim().is_empty() {
            blank += 1;
            if blank <= 1 {
                out.push("");
            }
            continue;
        }
        blank = 0;
        out.push(l);
        if fence {
            code = !code;
        }
    }
    out.join("\n").trim().to_string()
}

fn button_text(rows: &[Vec<crate::Button>]) -> String {
    rows.iter().flatten().enumerate().map(|(i, b)| match &b.url { Some(u) => format!("\n{}. {} {u}", i + 1, b.label), None => format!("\n{}. {}", i + 1, b.label) }).collect()
}

impl Weixin {
    pub fn new(id: &str, account_id: &str, token: &str, base: Option<&str>, cdn: Option<&str>, state: PathBuf, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: weixin token is empty (log in with the QR code first)"));
        }
        if account_id.trim().is_empty() {
            return Err(format!("channel {id}: weixin account_id is required"));
        }
        let saved: Value = std::fs::read_to_string(&state).ok().and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok()).unwrap_or_default();
        let tokens = saved["context_tokens"].as_object().map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str().filter(|s| !s.is_empty())?.to_string()))).collect()).unwrap_or_default();
        Ok(Weixin {
            id: id.into(),
            account_id: account_id.trim().into(),
            token: token.trim().into(),
            base: base.unwrap_or(DEFAULT_BASE).trim_end_matches('/').into(),
            cdn: cdn.unwrap_or(DEFAULT_CDN).trim_end_matches('/').into(),
            state,
            poll_timeout: poll_timeout_secs.max(1),
            agent: agent(Duration::from_secs(poll_timeout_secs.max(1) + 15)),
            retry_base: Duration::from_secs(1),
            max_retries: 4,
            st: Mutex::new(State { committed: saved["get_updates_buf"].as_str().unwrap_or("").to_string(), pending: None, tokens }),
            typing: Mutex::new(HashMap::new()),
        })
    }

    fn persist(&self, st: &State) -> Result<(), ChannelError> {
        let v = json!({"get_updates_buf": st.committed, "context_tokens": st.tokens});
        write_atomic(&self.state, v.to_string().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving weixin state: {e}")))
    }

    fn context_token(&self, peer: &str) -> Option<String> {
        self.st.lock().unwrap().tokens.get(peer).cloned()
    }

    fn drop_context_token(&self, peer: &str) {
        let mut st = self.st.lock().unwrap();
        if st.tokens.remove(peer).is_some() {
            let _ = self.persist(&st);
        }
    }

    /// POST an iLink endpoint (adds `base_info`). `Ok(None)` = cancelled / deadline.
    fn post(&self, endpoint: &str, payload: &Value, cancel: &Cancel) -> Result<Option<Value>, ChannelError> {
        let mut body = payload.clone();
        body["base_info"] = json!({"channel_version": CHANNEL_VERSION});
        let url = format!("{}/{endpoint}", self.base);
        let r = post_cancellable(&self.agent, &url, &headers(Some(&self.token)), serde_json::to_vec(&body).unwrap_or_default(), cancel)?;
        match r {
            None => Ok(None),
            Some(r) => parse_body(endpoint, r.status, r.retry_after, &r.body).map(Some),
        }
    }

    /// POST with retries for transient errors and rate limits.
    fn post_retry(&self, endpoint: &str, payload: &Value) -> Result<Value, ChannelError> {
        let cancel = Cancel::new();
        let mut attempt = 0;
        loop {
            let e = match self.post(endpoint, payload, &cancel) {
                Ok(v) => return Ok(v.unwrap_or_default()),
                Err(e) if e.is_retryable() => e,
                Err(e) => return Err(e),
            };
            if attempt >= self.max_retries {
                return Err(e);
            }
            sleep_cancellable(self.retry_base * 2u32.pow(attempt), &cancel);
            attempt += 1;
        }
    }

    /// `sendmessage` one item list to `to`, handling the stale-session fallback and rate limits.
    fn send_items(&self, to: &str, items: Value) -> Result<String, ChannelError> {
        let client_id = format!("seagent-weixin-{}", crypto::hex(&crypto::random_bytes(16)));
        let mut ctx = self.context_token(to);
        let mut attempt = 0;
        loop {
            let mut msg = json!({"from_user_id": "", "to_user_id": to, "client_id": client_id, "message_type": MSG_TYPE_BOT, "message_state": 2, "item_list": items});
            if let Some(t) = &ctx {
                msg["context_token"] = json!(t);
            }
            let v = self.post_retry("ilink/bot/sendmessage", &json!({"msg": msg}))?;
            let (ret, errcode, m) = ret_codes(&v);
            // Retry once without the (stale) context token: iLink accepts tokenless sends as a fallback.
            if ctx.is_some() && is_expired(ret, errcode, &m) {
                ctx = None;
                self.drop_context_token(to);
                continue;
            }
            match ret_error("sendmessage", &v) {
                None => return Ok(client_id),
                Some(e) if matches!(e.kind, K::RateLimited { .. }) && attempt < self.max_retries => {
                    attempt += 1;
                    sleep_cancellable(self.retry_base * 3, &Cancel::new());
                }
                Some(e) => return Err(e),
            }
        }
    }

    fn typing_ticket(&self, peer: &str) -> Option<String> {
        if let Some((t, at)) = self.typing.lock().unwrap().get(peer) {
            if at.elapsed() < TYPING_TTL {
                return Some(t.clone());
            }
        }
        let mut p = json!({"ilink_user_id": peer});
        if let Some(c) = self.context_token(peer) {
            p["context_token"] = json!(c);
        }
        let v = self.post("ilink/bot/getconfig", &p, &Cancel::new().with_deadline(Instant::now() + Duration::from_secs(10))).ok()??;
        let t = v["typing_ticket"].as_str().filter(|s| !s.is_empty())?.to_string();
        self.typing.lock().unwrap().insert(peer.to_string(), (t.clone(), Instant::now()));
        Some(t)
    }

    fn upload(&self, to: &str, m: &Media) -> Result<Value, ChannelError> {
        let (plain, name) = match (&m.path, &m.url) {
            (Some(p), _) => (std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?, Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())),
            (None, Some(u)) => (crate::http::get_bytes(u, &[], 50 * 1024 * 1024)?, u.split('?').next().unwrap_or("").rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("file").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let name = if m.name.is_empty() { name } else { m.name.clone() };
        let silk = name.to_ascii_lowercase().ends_with(".silk");
        let (media_type, item_type) = match m.kind {
            MediaKind::Image | MediaKind::Sticker | MediaKind::Animation => (1, ITEM_IMAGE),
            MediaKind::Video => (2, ITEM_VIDEO),
            MediaKind::Voice if silk => (4, ITEM_VOICE),
            // Other audio ships as a file attachment (native voice bubbles need SILK).
            _ => (3, ITEM_FILE),
        };
        let filekey = crypto::hex(&crypto::random_bytes(16));
        let mut key = [0u8; 16];
        key.copy_from_slice(&crypto::random_bytes(16));
        let md5hex = crypto::hex(&md5(&plain));
        let req = json!({"filekey": filekey, "media_type": media_type, "to_user_id": to, "rawsize": plain.len(), "rawfilemd5": md5hex, "filesize": (plain.len() + 16) / 16 * 16, "no_need_thumb": true, "aeskey": crypto::hex(&key)});
        let v = self.post_retry("ilink/bot/getuploadurl", &req)?;
        if let Some(e) = ret_error("getuploadurl", &v) {
            return Err(e);
        }
        let cipher = ecb_encrypt(&key, &plain);
        let url = match (v["upload_full_url"].as_str().filter(|s| !s.is_empty()), v["upload_param"].as_str().filter(|s| !s.is_empty())) {
            (Some(u), _) => u.to_string(),
            (None, Some(p)) => format!("{}/upload?encrypted_query_param={}&filekey={}", self.cdn, seagent_net::urlencode(p), seagent_net::urlencode(&filekey)),
            _ => return Err(ChannelError::new(K::Protocol, "getuploadurl returned neither upload_param nor upload_full_url")),
        };
        // POST, not PUT (PUT 404s on the CDN); the media handle comes back in a header.
        let a = agent(Duration::from_secs(120));
        let mut r = a.post(&url).header("Content-Type", "application/octet-stream").send(&cipher[..]).map_err(|e| ChannelError::new(K::Network, format!("CDN upload failed: {e}")))?;
        let status = r.status().as_u16();
        let param = r.headers().get("x-encrypted-param").and_then(|h| h.to_str().ok()).map(str::to_string);
        let body = r.body_mut().read_to_string().unwrap_or_default();
        let eqp = match (status, param) {
            (200, Some(p)) if !p.is_empty() => p,
            (200, _) => return Err(ChannelError::new(K::Protocol, "CDN upload missing x-encrypted-param header")),
            (s, _) => return Err(classify(s, None, "CDN upload", &body)),
        };
        // iLink wants aes_key = base64(hex string), not base64(raw bytes).
        let media = json!({"encrypt_query_param": eqp, "aes_key": crypto::b64(crypto::hex(&key).as_bytes()), "encrypt_type": 1});
        Ok(match item_type {
            ITEM_IMAGE => json!({"type": ITEM_IMAGE, "image_item": {"media": media, "mid_size": cipher.len()}}),
            ITEM_VIDEO => json!({"type": ITEM_VIDEO, "video_item": {"media": media, "video_size": cipher.len(), "play_length": 0, "video_md5": md5hex}}),
            ITEM_VOICE => json!({"type": ITEM_VOICE, "voice_item": {"media": media, "encode_type": 6, "bits_per_sample": 16, "sample_rate": 24000, "playtime": 0}}),
            _ => json!({"type": ITEM_FILE, "file_item": {"media": media, "file_name": name, "len": plain.len().to_string()}}),
        })
    }

    fn url_allowed(&self, u: &str) -> bool {
        if u.starts_with(&format!("{}/", self.cdn)) || u.starts_with(&format!("{}/", self.base)) {
            return true;
        }
        match seagent_net::Url::parse(u) {
            Ok(p) => (u.starts_with("https://") || u.starts_with("http://")) && CDN_ALLOW.contains(&p.host.as_str()),
            Err(_) => false,
        }
    }
}

impl Channel for Weixin {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct, ChatType::Group], media: true, reply: false, threads: false, reactions: 0, edit: false, delete: false, typing: true, buttons: false, polls: false, native_commands: false, streaming: Streaming::None, max_len: MAX_MESSAGE, len_unit: LenUnit::Chars, markup: Markup::Markdown }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let buf = {
            let mut st = self.st.lock().unwrap();
            if let Some(p) = st.pending.take() {
                st.committed = p;
                self.persist(&st)?;
            }
            st.committed.clone()
        };
        let deadline = cancel.with_deadline(Instant::now() + Duration::from_secs(self.poll_timeout));
        let v = match self.post("ilink/bot/getupdates", &json!({"get_updates_buf": buf}), &deadline) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        if let Some(e) = ret_error("getupdates", &v) {
            return Err(e);
        }
        let msgs = v["msgs"].as_array().cloned().unwrap_or_default();
        let mut st = self.st.lock().unwrap();
        if let Some(nb) = v["get_updates_buf"].as_str().filter(|b| !b.is_empty() && *b != buf) {
            st.pending = Some(nb.to_string());
        }
        let mut changed = false;
        let mut out = Vec::new();
        for m in &msgs {
            let Some(i) = inbound_of(&self.id, &self.account_id, &self.cdn, m) else { continue };
            let ct = s_of(&m["context_token"]);
            if !ct.is_empty() {
                for peer in [i.sender.clone(), i.chat.clone()] {
                    if st.tokens.get(&peer) != Some(&ct) {
                        st.tokens.insert(peer, ct.clone());
                        changed = true;
                    }
                }
            }
            out.push(i);
        }
        if changed {
            self.persist(&st)?;
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut sent = Sent::default();
        for m in &out.media {
            let item = self.upload(&out.chat, m)?;
            sent.ids.push(self.send_items(&out.chat, json!([item]))?);
        }
        let mut text = normalize(&out.text);
        if !out.buttons.is_empty() {
            text.push_str(&button_text(&out.buttons));
        }
        if text.trim().is_empty() {
            return Ok(sent);
        }
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            if piece.trim().is_empty() {
                continue;
            }
            sent.ids.push(self.send_items(&out.chat, json!([{"type": ITEM_TEXT, "text_item": {"text": piece}}]))?);
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let Some(ticket) = self.typing_ticket(chat) else { return Ok(()) };
        let v = self.post("ilink/bot/sendtyping", &json!({"ilink_user_id": chat, "typing_ticket": ticket, "status": 1}), &Cancel::new().with_deadline(Instant::now() + Duration::from_secs(10)))?.unwrap_or_default();
        ret_error("sendtyping", &v).map_or(Ok(()), Err)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| crate::unsupported("media without url"))?;
        if !self.url_allowed(u) {
            return Err(ChannelError::new(K::Fatal, "media URL is not on the WeChat CDN allowlist"));
        }
        let raw = crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?;
        match m.id.as_deref().filter(|s| !s.is_empty()) {
            None => Ok(raw),
            Some(k) => {
                let key = parse_aes_key(k).ok_or_else(|| ChannelError::new(K::Protocol, "unexpected aes_key format"))?;
                ecb_decrypt(&key, &raw).ok_or_else(|| ChannelError::new(K::Protocol, "media ciphertext is not block aligned"))
            }
        }
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Bot token from QR login; omit to use the credentials `save_account` stored.
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    cdn_base_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<std::sync::Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.opt_secret("token", &st.token)?;
    let saved: Option<Account> = std::fs::read_to_string(account_path(ctx.state_dir, ctx.name)).ok().and_then(|s| serde_json::from_str(&s).ok());
    let (token, account, base) = match (token, saved) {
        (Some(t), saved) => (t, st.account_id.clone().or(saved.map(|a| a.account_id)).unwrap_or_default(), st.base_url.clone()),
        (None, Some(a)) => (a.token, st.account_id.clone().unwrap_or(a.account_id), st.base_url.clone().or(Some(a.base_url))),
        (None, None) => return Err(format!("channel {}: weixin needs `token` (or log in with the QR code first)", ctx.name)),
    };
    let w = Weixin::new(ctx.name, &account, &token, base.as_deref(), st.cdn_base_url.as_deref(), ctx.state("weixin.json"), st.poll_timeout_secs)?;
    Ok(std::sync::Arc::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    fn wx(url: &str, state: PathBuf) -> Weixin {
        let mut w = Weixin::new("wx", "bot@im.bot", "TOKSECRET", Some(url), Some(&format!("{url}/c2c")), state, 1).unwrap();
        w.retry_base = Duration::from_millis(5);
        w
    }

    fn ok(v: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], v.to_string())
    }

    fn text_msg(id: &str, from: &str, text: &str, ctx: &str) -> Value {
        json!({"message_id": id, "from_user_id": from, "to_user_id": "bot@im.bot", "message_type": 1, "context_token": ctx, "create_time_ms": 1700000000123i64, "item_list": [{"type": 1, "text_item": {"text": text}}]})
    }

    #[test]
    fn crypto_known_answers() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        // Generated with the `cryptography` package: AES-128-ECB + PKCS#7.
        let c = ecb_encrypt(&key, b"hello weixin cdn!");
        assert_eq!(crypto::hex(&c), "9846510d6a2bb68de59ef14d1f1a4bcbec19c77a6de4cfedcef118e23f0be27e");
        assert_eq!(ecb_decrypt(&key, &c).unwrap(), b"hello weixin cdn!");
        for n in [0, 1, 15, 16, 17, 100] {
            let p = vec![7u8; n];
            assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &p)).unwrap(), p);
        }
        assert!(ecb_decrypt(&key, &[1, 2, 3]).is_none());
        assert_eq!(crypto::hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(crypto::hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(crypto::hex(&md5(&[b'a'; 1000])), "cabe45dcc9ae5b66ba86600cca6b8ba8");
        // Both aes_key encodings.
        assert_eq!(parse_aes_key(&crypto::b64(&key)), Some(key));
        assert_eq!(parse_aes_key(&crypto::b64(crypto::hex(&key).as_bytes())), Some(key));
        assert_eq!(parse_aes_key(&crypto::b64(b"short")), None);
    }

    #[test]
    fn poll_parses_kinds_persists_cursor_and_context_tokens() {
        let srv = FakeServer::start(|req, _| {
            let buf = req.json()["get_updates_buf"].as_str().unwrap_or("").to_string();
            match buf.as_str() {
                "" => ok(json!({"ret": 0, "get_updates_buf": "B1", "msgs": [
                    text_msg("m1", "amy", "hi", "CT-amy"),
                    {"message_id": "m2", "from_user_id": "bob", "context_token": "CT-bob", "item_list": [{"type": 2, "image_item": {"aeskey": "000102030405060708090a0b0c0d0e0f", "media": {"encrypt_query_param": "EQP+1", "aes_key": "ignored"}}}]},
                    {"message_id": "m3", "from_user_id": "bob", "item_list": [{"type": 3, "voice_item": {"text": "你好"}}]},
                    {"message_id": "m4", "from_user_id": "bob", "item_list": [{"type": 4, "file_item": {"file_name": "a.pdf", "len": "12", "media": {"encrypt_query_param": "F", "aes_key": "AAAAAAAAAAAAAAAAAAAAAA=="}}}]},
                    {"message_id": "m5", "from_user_id": "amy", "room_id": "grp@chatroom", "item_list": [{"type": 1, "text_item": {"text": "yes"}, "ref_msg": {"title": "earlier", "message_item": {"type": 1, "text_item": {"text": "shall I?"}}}}]},
                    {"message_id": "m6", "from_user_id": "bot@im.bot", "item_list": [{"type": 1, "text_item": {"text": "own echo"}}]},
                    {"message_id": "m7", "from_user_id": "other-bot", "message_type": 2, "item_list": [{"type": 1, "text_item": {"text": "bot"}}]},
                    {"message_id": "m8", "from_user_id": "amy", "item_list": []}
                ]})),
                _ => ok(json!({"ret": 0, "get_updates_buf": buf, "msgs": []})),
            }
        });
        let dir = temp_dir("wx");
        let state = dir.join("wx.json");
        let w = wx(&srv.url, state.clone());
        let g = w.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 5, "own, bot and empty messages dropped");
        assert_eq!((g[0].chat.as_str(), g[0].sender.as_str(), g[0].text.as_str(), g[0].message_id.as_str(), g[0].ts, g[0].chat_type), ("amy", "amy", "hi", "m1", 1700000000, ChatType::Direct));
        let img = &g[1].media[0];
        assert_eq!((img.kind, img.url.as_deref()), (MediaKind::Image, Some(format!("{}/c2c/download?encrypted_query_param=EQP%2B1", srv.url).as_str())));
        assert_eq!(parse_aes_key(img.id.as_deref().unwrap()), Some(core::array::from_fn(|i| i as u8)), "hex aeskey wins");
        assert!(g[2].text.contains("你好") && g[2].media.is_empty());
        assert_eq!((g[3].media[0].name.as_str(), g[3].media[0].size), ("a.pdf", 12));
        assert_eq!((g[4].chat.as_str(), g[4].chat_type), ("grp@chatroom", ChatType::Group));
        assert_eq!(g[4].reply.as_ref().unwrap().text, "earlier | shall I?");
        // Context tokens persist immediately; the cursor only on the next poll.
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((saved["context_tokens"]["amy"].as_str(), saved["get_updates_buf"].as_str()), (Some("CT-amy"), Some("")));
        let w2 = wx(&srv.url, state.clone());
        assert_eq!(w2.poll(&Cancel::new()).unwrap().len(), 5, "crash before commit redelivers");
        assert!(w2.poll(&Cancel::new()).unwrap().is_empty());
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(saved["get_updates_buf"], "B1");
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/ilink/bot/getupdates");
        assert_eq!((r.header("AuthorizationType"), r.header("Authorization"), r.header("iLink-App-Id"), r.header("iLink-App-ClientVersion")), (Some("ilink_bot_token"), Some("Bearer TOKSECRET"), Some("bot"), Some("131584")));
        let uin = String::from_utf8(crypto::b64_decode(r.header("X-WECHAT-UIN").unwrap()).unwrap()).unwrap();
        assert!(uin.parse::<u32>().is_ok());
        assert_eq!(r.json()["base_info"]["channel_version"], "2.2.0");
        assert!(r.header("content-type").unwrap().starts_with("application/json"));
    }

    #[test]
    fn send_echoes_context_token_splits_and_falls_back_without_token() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/getupdates") {
                return ok(json!({"ret": 0, "msgs": [text_msg("m1", "amy", "hi", "CT1")]}));
            }
            let msg = &req.json()["msg"];
            if msg["to_user_id"] == "stale" && msg.get("context_token").is_some() {
                return ok(json!({"ret": -14, "errmsg": "session timeout"}));
            }
            ok(json!({"ret": 0}))
        });
        let dir = temp_dir("wx");
        let w = wx(&srv.url, dir.join("s.json"));
        w.poll(&Cancel::new()).unwrap();
        let b = vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]];
        let s = w.send(&Outbound { buttons: b, ..Outbound::text("amy", "line1\n\n\n\nline2") }).unwrap();
        assert!(s.ids[0].starts_with("seagent-weixin-"));
        let r = srv.requests()[1].json();
        assert_eq!(srv.requests()[1].path, "/ilink/bot/sendmessage");
        let m = &r["msg"];
        assert_eq!((m["to_user_id"].as_str(), m["context_token"].as_str(), m["message_type"].as_i64(), m["message_state"].as_i64(), m["from_user_id"].as_str()), (Some("amy"), Some("CT1"), Some(2), Some(2), Some("")));
        assert_eq!(m["item_list"][0], json!({"type": 1, "text_item": {"text": "line1\n\nline2\n1. Yes"}}));
        assert_eq!(m["client_id"].as_str(), s.ids.first().map(String::as_str));
        let s = w.send(&Outbound::text("amy", &"x".repeat(4500))).unwrap();
        assert_eq!(s.ids.len(), 3);
        // Stale context token: dropped (and persisted), retried tokenless.
        w.st.lock().unwrap().tokens.insert("stale".into(), "OLD".into());
        let n0 = srv.requests().len();
        w.send(&Outbound::text("stale", "ping")).unwrap();
        let rs = srv.requests();
        assert_eq!(rs.len() - n0, 2);
        assert!(rs[n0 + 1].json()["msg"].get("context_token").is_none());
        assert!(w.context_token("stale").is_none());
    }

    #[test]
    fn error_mapping_session_expired_rate_limit_stale_and_http() {
        let cases: Vec<(Value, K)> = vec![
            (json!({"ret": -14, "errmsg": "session timeout"}), K::Auth),
            (json!({"ret": -2, "errmsg": "prepare failed"}), K::Fatal),
            (json!({"ret": -2, "errmsg": "freq limit"}), K::RateLimited { retry_after: Some(Duration::from_secs(3)) }),
            (json!({"ret": 5, "errmsg": "bad"}), K::Protocol),
        ];
        for (body, kind) in cases {
            let b = body.clone();
            let srv = FakeServer::start(move |_, _| ok(b.clone()));
            let mut w = wx(&srv.url, temp_dir("wx").join("s"));
            w.max_retries = 1;
            let e = w.send(&Outbound::text("amy", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{body}");
            assert!(!e.message.contains("TOKSECRET"));
        }
        // Polling with an expired session is Auth (operator must re-login).
        let srv = FakeServer::start(|_, _| ok(json!({"ret": -14, "errcode": -14, "errmsg": "session expired"})));
        assert_eq!(wx(&srv.url, temp_dir("wx").join("s")).poll(&Cancel::new()).unwrap_err().kind, K::Auth);
        // HTTP: 401 → Auth, 5xx retried then Network, rate limit then success.
        let srv = FakeServer::start(|_, _| (401, vec![], "{}".into()));
        assert_eq!(wx(&srv.url, temp_dir("wx").join("s")).send(&Outbound::text("a", "x")).unwrap_err().kind, K::Auth);
        let srv = FakeServer::start(|_, _| (502, vec![], "bad".into()));
        let e = wx(&srv.url, temp_dir("wx").join("s")).send(&Outbound::text("a", "x")).unwrap_err();
        assert_eq!((e.kind, srv.requests().len()), (K::Network, 5));
        let srv = FakeServer::start(|_, n| if n == 0 { ok(json!({"ret": -2, "errmsg": "too frequent"})) } else { ok(json!({"ret": 0})) });
        assert_eq!(wx(&srv.url, temp_dir("wx").join("s")).send(&Outbound::text("a", "x")).unwrap().ids.len(), 1);
        assert_eq!(srv.requests().len(), 2);
    }

    #[test]
    fn media_upload_download_and_typing() {
        let key: [u8; 16] = [9; 16];
        let enc = ecb_encrypt(&key, b"SECRET IMAGE BYTES");
        let enc_hex = crypto::hex(&enc);
        let srv = FakeServer::start(move |req, _| {
            if req.path.ends_with("/getuploadurl") {
                return ok(json!({"ret": 0, "upload_param": "UP/1"}));
            }
            if req.path.starts_with("/c2c/upload") {
                return (200, vec![("x-encrypted-param".into(), "DLPARAM".into())], String::new());
            }
            if req.path.starts_with("/c2c/download") {
                // FakeServer bodies are strings; ship hex and let the test decode.
                return (200, vec![], enc_hex.clone());
            }
            if req.path.ends_with("/getconfig") {
                return ok(json!({"ret": 0, "typing_ticket": "TT"}));
            }
            ok(json!({"ret": 0}))
        });
        let w = wx(&srv.url, temp_dir("wx").join("s"));
        let f = temp_dir("wx").join("pic.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let s = w.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("amy", "caption") }).unwrap();
        assert_eq!(s.ids.len(), 2, "media then caption text");
        let rs = srv.requests();
        let up = rs[0].json();
        assert_eq!((up["media_type"].as_i64(), up["to_user_id"].as_str(), up["rawsize"].as_u64(), up["filesize"].as_u64(), up["no_need_thumb"].as_bool()), (Some(1), Some("amy"), Some(7), Some(16), Some(true)));
        assert_eq!(up["rawfilemd5"].as_str().unwrap(), crypto::hex(&md5(b"PNGDATA")));
        let aes = crypto::hex_decode(up["aeskey"].as_str().unwrap()).unwrap();
        assert!(rs[1].path.starts_with("/c2c/upload?encrypted_query_param=UP%2F1&filekey="));
        assert_eq!(rs[1].header("content-type"), Some("application/octet-stream"));
        let item = &rs[2].json()["msg"]["item_list"][0];
        assert_eq!(item["type"], 2);
        assert_eq!(item["image_item"]["media"]["encrypt_query_param"], "DLPARAM");
        assert_eq!(item["image_item"]["mid_size"], 16);
        let k = parse_aes_key(item["image_item"]["media"]["aes_key"].as_str().unwrap()).unwrap();
        assert_eq!(k.to_vec(), aes, "aes_key = base64(hex(key))");
        assert_eq!(rs[3].json()["msg"]["item_list"][0]["text_item"]["text"], "caption");
        // Download + decrypt (hex body from the fake server, so decode via a raw media with no key first).
        let m = Media { url: Some(format!("{}/c2c/download?encrypted_query_param=X", srv.url)), ..Default::default() };
        let raw = w.fetch_media(&m).unwrap();
        let cipher = crypto::hex_decode(std::str::from_utf8(&raw).unwrap()).unwrap();
        assert_eq!(ecb_decrypt(&key, &cipher).unwrap(), b"SECRET IMAGE BYTES");
        assert!(w.fetch_media(&Media { url: Some("http://169.254.169.254/latest".into()), ..Default::default() }).is_err(), "SSRF allowlist");
        // Typing: getconfig once (ticket cached), sendtyping each time.
        w.typing("amy", None).unwrap();
        w.typing("amy", None).unwrap();
        let rs = srv.requests();
        let paths: Vec<&str> = rs.iter().map(|r| r.path.as_str()).filter(|p| p.contains("config") || p.contains("typing")).collect();
        assert_eq!(paths, ["/ilink/bot/getconfig", "/ilink/bot/sendtyping", "/ilink/bot/sendtyping"]);
        let t = rs.iter().rev().find(|r| r.path.ends_with("/sendtyping")).unwrap().json();
        assert_eq!((t["ilink_user_id"].as_str(), t["typing_ticket"].as_str(), t["status"].as_i64()), (Some("amy"), Some("TT"), Some(1)));
    }

    #[test]
    fn qr_login_flow() {
        let srv = FakeServer::start(|req, n| {
            if req.path.starts_with("/ilink/bot/get_bot_qrcode?bot_type=3") {
                return ok(json!({"qrcode": "QR1", "qrcode_img_content": "https://liteapp/qr"}));
            }
            match n {
                1 => ok(json!({"status": "wait"})),
                2 => ok(json!({"status": "scaned"})),
                3 => ok(json!({"status": "expired"})),
                4 => ok(json!({"status": "scaned_but_redirect", "redirect_host": "sz.ilink"})),
                _ => ok(json!({"status": "confirmed", "ilink_bot_id": "b@im.bot", "bot_token": "NEWTOK", "baseurl": "https://x", "ilink_user_id": "u"})),
            }
        });
        let q = qr_login_start(Some(&srv.url), "3").unwrap();
        assert_eq!(q, QrCode { qrcode: "QR1".into(), url: "https://liteapp/qr".into() });
        let st: Vec<QrStatus> = (0..5).map(|_| qr_login_poll(Some(&srv.url), "QR1").unwrap()).collect();
        assert_eq!(&st[..4], &[QrStatus::Wait, QrStatus::Scanned, QrStatus::Expired, QrStatus::Redirect("https://sz.ilink".into())]);
        let QrStatus::Confirmed(a) = &st[4] else { panic!("{st:?}") };
        assert_eq!((a.account_id.as_str(), a.token.as_str(), a.base_url.as_str()), ("b@im.bot", "NEWTOK", "https://x"));
        let r = &srv.requests()[1];
        assert_eq!((r.path.as_str(), r.header("iLink-App-Id")), ("/ilink/bot/get_qrcode_status?qrcode=QR1", Some("bot")));
        // build picks up saved credentials.
        let d = temp_dir("wx");
        save_account(&d, "wx", a).unwrap();
        let secrets: crate::config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "wx", state_dir: &d, secrets: &secrets };
        assert_eq!(build(&ctx, json!({}).as_object().unwrap()).unwrap().id(), "wx");
        let ctx2 = crate::config::Ctx { name: "nobody", state_dir: &d, secrets: &secrets };
        assert!(build(&ctx2, json!({}).as_object().unwrap()).err().unwrap().contains("token"));
        assert!(build(&ctx, json!({"tokn": "x"}).as_object().unwrap()).is_err());
    }

    #[test]
    fn cancel_interrupts_blocked_long_poll_and_timeout_returns_empty() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let mut w = wx(&url, temp_dir("wx").join("s"));
        w.poll_timeout = 30;
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        // poll_timeout bounds a server that never answers.
        w.poll_timeout = 1;
        let start = Instant::now();
        assert!(w.poll(&Cancel::new()).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
