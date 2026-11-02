//! SimpleX Chat via a local `simplex-chat -p 5225` daemon (ported from Hermes
//! `plugins/platforms/simplex`, MIT).
//!
//! One background thread owns the daemon WebSocket (default ws://127.0.0.1:5225):
//! JSON `{"corrId", "cmd"}` commands out, events in; reconnects with jittered
//! exponential backoff (2 s → 60 s). Events: `newChatItems` / `newChatItem`
//! (contacts and groups; our own `directSnd`/`groupSnd` items dropped),
//! `chatItemUpdated` (edits), `contactRequest` (auto-accepted with `/accept`
//! unless `auto_accept = false`), `rcvFileDescrReady` (→ `/freceive`), voice
//! notes deferred until `rcvFileComplete` delivers the downloaded path.
//! Chats: a contact is its numeric `contactId`, a group is `group:<groupId>`.
//! Send: structured `/_send @<id>|#<id> json [...]` (by id, never by display
//! name), quotes via `quotedItemId`, files/images/voice notes from local paths
//! (URLs are downloaded to the state dir first — the daemon must see the file);
//! edit (`/_update item … text`), delete (`/_delete item … broadcast`) and
//! reactions (`/_reaction … on|off`). Group allow-listing is the host's
//! `groups`/`group_policy` job.

use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming};
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_URL: &str = "ws://127.0.0.1:5225";
/// SimpleX has no hard limit; chunk for sanity (as upstream).
pub const MAX_MESSAGE: usize = 8000;
/// Marks commands we sent so their un-awaited echoes are ignored.
const CORR_PREFIX: &str = "ark-";
const IMAGE_EXTS: [&str; 5] = ["jpg", "jpeg", "png", "gif", "webp"];
const AUDIO_EXTS: [&str; 6] = ["mp3", "wav", "ogg", "m4a", "aac", "opus"];
const VOICE_EXTS: [&str; 5] = ["ogg", "mp3", "wav", "m4a", "opus"];
const TEXT_BEARING: [&str; 6] = ["text", "file", "image", "voice", "link", "video"];

struct Cmd {
    corr: String,
    cmd: String,
    reply: Option<Sender<Value>>,
}

struct Shared {
    stop: AtomicBool,
    connected: AtomicBool,
    counter: AtomicU64,
}

pub struct Simplex {
    id: String,
    url: String,
    auto_accept: bool,
    poll_timeout: u64,
    out_dir: PathBuf,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// How long `send` waits for the daemon's reply to a command.
    pub cmd_timeout: Duration,
    /// How long `send` waits for the WebSocket to come up.
    pub connect_wait: Duration,
    shared: Arc<Shared>,
    rx: Mutex<Option<Receiver<Inbound>>>,
    cmd_tx: Mutex<Option<Sender<Cmd>>>,
}

fn ext_of(p: &str) -> String {
    Path::new(p).extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn mime_for_ext(ext: &str) -> String {
    if IMAGE_EXTS.contains(&ext) {
        format!("image/{ext}")
    } else if AUDIO_EXTS.contains(&ext) {
        format!("audio/{ext}")
    } else {
        "application/octet-stream".into()
    }
}

/// `localDisplayName`, else the nested profile's `displayName`.
fn display_name(obj: &Value, profile_key: &str) -> String {
    obj["localDisplayName"].as_str().filter(|s| !s.is_empty()).or_else(|| obj[profile_key]["displayName"].as_str()).unwrap_or("").to_string()
}

/// `group:<id>` → `#<id>`, contact id → `@<id>`.
fn target(chat: &str) -> String {
    match chat.strip_prefix("group:") {
        Some(g) => format!("#{g}"),
        None => format!("@{chat}"),
    }
}

fn send_cmd(chat: &str, items: &Value) -> String {
    format!("/_send {} json {items}", target(chat))
}

/// `2024-03-01T12:34:56.789Z` (or `+hh:mm`) → unix seconds.
pub(crate) fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[10] != b'T' && b[10] != b' ' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let mut t = days * 86400 + h * 3600 + mi * 60 + se;
    let tail = &s[19..];
    let tz = tail.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if let Some(sign) = tz.chars().next().filter(|c| *c == '+' || *c == '-') {
        let hh = tz.get(1..3).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
        let mm = tz.get(4..6).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
        let off = hh * 3600 + mm * 60;
        t -= if sign == '+' { off } else { -off };
    }
    Some(t)
}

enum Item {
    Deliver(Box<Inbound>),
    /// Voice note still downloading: `/freceive <fileId>` and wait for `rcvFileComplete`.
    Defer(i64),
    Skip,
}

/// One AChatItem (`{chatInfo, chatItem}`) → what to do with it.
fn chat_item(channel: &str, item: &Value, edited: bool) -> Item {
    let info = &item["chatInfo"];
    let ci = &item["chatItem"];
    let dir = &ci["chatDir"];
    let dir_type = dir["type"].as_str().unwrap_or("");
    if matches!(dir_type, "directSnd" | "groupSnd") {
        return Item::Skip;
    }
    let content = &ci["content"];
    if content["type"].as_str() != Some("rcvMsgContent") {
        return Item::Skip;
    }
    let mc = &content["msgContent"];
    let mtype = mc["type"].as_str().unwrap_or("");
    let text = if TEXT_BEARING.contains(&mtype) { mc["text"].as_str().unwrap_or("") } else { "" };
    if text.is_empty() && !matches!(mtype, "image" | "file" | "voice") {
        return Item::Skip;
    }
    let (chat, chat_name, chat_type, sender, sender_name) = match info["type"].as_str() {
        Some("direct") => {
            let c = &info["contact"];
            let id = c["contactId"].as_i64().map(|i| i.to_string()).unwrap_or_default();
            let name = display_name(c, "profile");
            (id.clone(), name.clone(), ChatType::Direct, id, name)
        }
        Some("group") => {
            let g = &info["groupInfo"];
            let gid = g["groupId"].as_i64().map(|i| i.to_string()).unwrap_or_default();
            if gid.is_empty() {
                return Item::Skip;
            }
            let m = &dir["groupMember"];
            let sid = m["memberId"].as_str().map(str::to_string).or_else(|| m["groupMemberId"].as_i64().map(|i| i.to_string())).unwrap_or_default();
            let chat = format!("group:{gid}");
            let gname = display_name(g, "groupProfile");
            (chat.clone(), if gname.is_empty() { chat } else { gname }, ChatType::Group, sid, display_name(m, "memberProfile"))
        }
        _ => return Item::Skip,
    };
    if sender.is_empty() || chat.is_empty() {
        return Item::Skip;
    }
    let mut media = Vec::new();
    let file = &ci["file"];
    if file.is_object() {
        let path = file["fileSource"]["filePath"].as_str().filter(|p| !p.is_empty());
        let name = file["fileName"].as_str().unwrap_or("");
        let ext = path.map(ext_of).filter(|e| !e.is_empty()).unwrap_or_else(|| ext_of(name));
        if path.is_none() && AUDIO_EXTS.contains(&ext.as_str()) {
            if let Some(fid) = file["fileId"].as_i64() {
                return Item::Defer(fid);
            }
        }
        if let Some(p) = path {
            let mime = mime_for_ext(&ext);
            let kind = if mtype == "voice" {
                MediaKind::Voice
            } else if mime.starts_with("image/") {
                MediaKind::Image
            } else if mime.starts_with("audio/") {
                MediaKind::Audio
            } else if mtype == "video" {
                MediaKind::Video
            } else {
                MediaKind::Document
            };
            media.push(Media { kind, path: Some(p.to_string()), mime, name: name.to_string(), size: file["fileSize"].as_u64().unwrap_or(0), id: file["fileId"].as_i64().map(|i| i.to_string()), ..Default::default() });
        }
    }
    let meta = &ci["meta"];
    let item_id = meta["itemId"].as_i64().map(|i| i.to_string()).unwrap_or_default();
    if item_id.is_empty() {
        return Item::Skip;
    }
    let ts = meta["itemTs"].as_str().or_else(|| meta["createdAt"].as_str()).and_then(parse_iso).unwrap_or(0);
    let q = &ci["quotedItem"];
    let reply = q.is_object().then(|| ReplyRef {
        id: q["itemId"].as_i64().map(|i| i.to_string()).unwrap_or_default(),
        text: q["content"]["text"].as_str().unwrap_or("").to_string(),
        author: String::new(),
        is_own: q["chatDir"]["type"].as_str().is_some_and(|t| t.ends_with("Snd")),
    });
    let message_id = if edited {
        let at = meta["updatedAt"].as_str().and_then(parse_iso).unwrap_or(ts);
        format!("{item_id}:e{at}")
    } else {
        item_id
    };
    Item::Deliver(Box::new(Inbound {
        channel: channel.to_string(),
        chat,
        chat_name,
        chat_type,
        sender_name: if sender_name.is_empty() { sender.clone() } else { sender_name },
        sender,
        text: text.to_string(),
        message_id,
        ts,
        media,
        reply,
        mentioned: meta["userMention"] == true,
        edited,
        ..Default::default()
    }))
}

/// Per-connection state of the worker.
struct Conn<'a> {
    channel: &'a str,
    auto_accept: bool,
    shared: &'a Shared,
    pending: HashMap<String, Sender<Value>>,
    deferred: HashMap<i64, Value>,
}

impl Conn<'_> {
    fn corr(&self) -> String {
        format!("{CORR_PREFIX}{}", self.shared.counter.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// Handle one daemon event; returns fire-and-forget commands to send.
    fn event(&mut self, ev: &Value, out: &Sender<Inbound>) -> Vec<String> {
        // Usually {"corrId", "resp": {...}}; some daemons put the fields at top level.
        let resp = if ev["resp"].is_object() { &ev["resp"] } else { ev };
        if let Some(c) = ev["corrId"].as_str() {
            if let Some(tx) = self.pending.remove(c) {
                let _ = tx.send(resp.clone());
                return vec![];
            }
            if c.starts_with(CORR_PREFIX) {
                return vec![];
            }
        }
        let mut cmds = Vec::new();
        let deliver = |item: &Value, edited: bool, this: &mut Self, cmds: &mut Vec<String>| match chat_item(this.channel, item, edited) {
            Item::Deliver(m) => {
                let _ = out.send(*m);
            }
            Item::Defer(fid) => {
                this.deferred.insert(fid, item.clone());
                if this.deferred.len() > 200 {
                    let k = *this.deferred.keys().next().unwrap();
                    this.deferred.remove(&k);
                }
                cmds.push(format!("/freceive {fid}"));
            }
            Item::Skip => {}
        };
        match resp["type"].as_str().or_else(|| ev["type"].as_str()).unwrap_or("") {
            "contactRequest" | "receivedContactRequest" if self.auto_accept => {
                if let Some(id) = resp["contactRequest"]["contactRequestId"].as_i64() {
                    cmds.push(format!("/accept {id}"));
                }
            }
            "rcvFileDescrReady" => {
                if let Some(fid) = resp["rcvFileTransfer"]["fileId"].as_i64() {
                    cmds.push(format!("/freceive {fid}"));
                }
            }
            "newChatItems" => {
                let items = match &resp["chatItems"] {
                    Value::Array(a) => a.clone(),
                    Value::Null => vec![],
                    v => vec![v.clone()],
                };
                for it in &items {
                    deliver(it, false, self, &mut cmds);
                }
            }
            "newChatItem" => {
                let it = if resp["chatItem"]["chatInfo"].is_object() { resp["chatItem"].clone() } else { resp.clone() };
                deliver(&it, false, self, &mut cmds);
            }
            "chatItemUpdated" => {
                let it = resp["chatItem"].clone();
                deliver(&it, true, self, &mut cmds);
            }
            "rcvFileComplete" => {
                let file = &resp["chatItem"]["chatItem"]["file"];
                let path = file["fileSource"]["filePath"].as_str().filter(|p| !p.is_empty());
                if let (Some(fid), Some(p)) = (file["fileId"].as_i64(), path) {
                    if let Some(mut it) = self.deferred.remove(&fid) {
                        it["chatItem"]["file"]["fileSource"] = json!({"filePath": p});
                        deliver(&it, false, self, &mut cmds);
                    }
                }
            }
            _ => {}
        }
        cmds
    }
}

struct WorkerCfg {
    channel: String,
    url: String,
    auto_accept: bool,
    backoff_initial: Duration,
    backoff_max: Duration,
}

fn worker(cfg: WorkerCfg, sh: Arc<Shared>, out: Sender<Inbound>, cmds: Receiver<Cmd>) {
    let mut backoff = cfg.backoff_initial;
    while !sh.stop.load(Ordering::SeqCst) {
        if let Ok((mut ws, _)) = WebSocket::connect(&cfg.url, &[], Duration::from_secs(10)) {
            backoff = cfg.backoff_initial;
            let _ = ws.set_read_timeout(Some(Duration::from_millis(100)));
            sh.connected.store(true, Ordering::SeqCst);
            let mut conn = Conn { channel: &cfg.channel, auto_accept: cfg.auto_accept, shared: &sh, pending: HashMap::new(), deferred: HashMap::new() };
            let mut last_ping = Instant::now();
            'conn: loop {
                if sh.stop.load(Ordering::SeqCst) {
                    let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                    sh.connected.store(false, Ordering::SeqCst);
                    return;
                }
                for c in cmds.try_iter() {
                    if ws.send_text(&json!({"corrId": c.corr, "cmd": c.cmd}).to_string()).is_err() {
                        break 'conn;
                    }
                    if let Some(r) = c.reply {
                        conn.pending.insert(c.corr, r);
                    }
                }
                if last_ping.elapsed() > Duration::from_secs(20) {
                    last_ping = Instant::now();
                    if ws.send(&Message::Ping(Vec::new())).is_err() {
                        break;
                    }
                }
                match ws.recv() {
                    Ok(Some(Message::Text(t))) => {
                        let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
                        for c in conn.event(&v, &out) {
                            let corr = conn.corr();
                            if ws.send_text(&json!({"corrId": corr, "cmd": c}).to_string()).is_err() {
                                break 'conn;
                            }
                        }
                    }
                    Ok(Some(Message::Close(_))) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            // Dropping `conn.pending` wakes every waiting `send` with an error.
            sh.connected.store(false, Ordering::SeqCst);
        }
        let jitter = backoff.mul_f64(0.2 * (ark_net::crypto::random_bytes(1)[0] as f64 / 255.0));
        let until = Instant::now() + backoff + jitter;
        while Instant::now() < until {
            if sh.stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        backoff = (backoff * 2).min(cfg.backoff_max);
    }
}

/// A daemon reply → error when it reports one.
fn check_reply(what: &str, r: &Value) -> Result<(), ChannelError> {
    let t = r["type"].as_str().unwrap_or("");
    if !matches!(t, "chatCmdError" | "chatError" | "error") {
        return Ok(());
    }
    let e = if r["chatError"].is_object() { &r["chatError"] } else { r };
    let et = e["errorType"]["type"].as_str().or_else(|| e["type"].as_str()).unwrap_or("unknown");
    let kind = if et.ends_with("NotFound") || matches!(et, "contactDeleted" | "groupUserRemoved" | "chatItemNotFound" | "groupMemberNotActive") { K::NotFound } else { K::Protocol };
    Err(ChannelError::new(kind, format!("simplex {what}: {et}")))
}

fn item_ids(r: &Value) -> Vec<String> {
    r["chatItems"].as_array().into_iter().flatten().filter_map(|c| c["chatItem"]["meta"]["itemId"].as_i64().map(|i| i.to_string())).collect()
}

impl Simplex {
    pub fn new(id: &str, url: Option<&str>, auto_accept: bool, out_dir: PathBuf, poll_timeout_secs: u64) -> Result<Simplex, String> {
        let url = url.unwrap_or(DEFAULT_URL).trim().trim_end_matches('/').to_string();
        let u = ark_net::Url::parse(&url).map_err(|e| format!("channel {id}: simplex ws_url: {e}"))?;
        if !matches!(u.scheme.as_str(), "ws" | "wss") {
            return Err(format!("channel {id}: simplex ws_url must be ws:// or wss://"));
        }
        Ok(Simplex {
            id: id.to_string(),
            url,
            auto_accept,
            poll_timeout: poll_timeout_secs,
            out_dir,
            backoff_initial: Duration::from_secs(2),
            backoff_max: Duration::from_secs(60),
            cmd_timeout: Duration::from_secs(30),
            connect_wait: Duration::from_secs(5),
            shared: Arc::new(Shared { stop: AtomicBool::new(false), connected: AtomicBool::new(false), counter: AtomicU64::new(0) }),
            rx: Mutex::new(None),
            cmd_tx: Mutex::new(None),
        })
    }

    fn ensure_started(&self) {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_some() {
            return;
        }
        let (tx, r) = mpsc::channel();
        let (ctx, crx) = mpsc::channel();
        let cfg = WorkerCfg { channel: self.id.clone(), url: self.url.clone(), auto_accept: self.auto_accept, backoff_initial: self.backoff_initial, backoff_max: self.backoff_max };
        let sh = self.shared.clone();
        std::thread::spawn(move || worker(cfg, sh, tx, crx));
        *rx = Some(r);
        *self.cmd_tx.lock().unwrap() = Some(ctx);
    }

    /// Send a command and wait for its corrId reply. `Ok(None)` = no reply in time.
    fn command(&self, cmd: &str) -> Result<Option<Value>, ChannelError> {
        self.ensure_started();
        let until = Instant::now() + self.connect_wait;
        while !self.shared.connected.load(Ordering::SeqCst) {
            if Instant::now() >= until {
                return Err(ChannelError::new(K::Network, format!("simplex daemon at {} not connected", self.url)));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let corr = format!("{CORR_PREFIX}{}", self.shared.counter.fetch_add(1, Ordering::SeqCst) + 1);
        let (tx, rx) = mpsc::channel();
        let q = self.cmd_tx.lock().unwrap().clone().expect("started");
        q.send(Cmd { corr, cmd: cmd.to_string(), reply: Some(tx) }).map_err(|_| ChannelError::new(K::Network, "simplex worker stopped"))?;
        match rx.recv_timeout(self.cmd_timeout) {
            Ok(v) => Ok(Some(v)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ChannelError::new(K::Network, "simplex connection dropped before the reply")),
        }
    }

    /// Local path for an outbound attachment (URLs are downloaded first).
    fn local_path(&self, m: &Media) -> Result<String, ChannelError> {
        if let Some(p) = &m.path {
            if !Path::new(p).exists() {
                return Err(ChannelError::new(K::Fatal, format!("attachment not found: {p}")));
            }
            return Ok(p.clone());
        }
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "attachment has neither path nor url"))?;
        let data = crate::http::get_bytes(u, &[], 50 * 1024 * 1024)?;
        let base = if m.name.is_empty() { u.split(['?', '#']).next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string() } else { m.name.clone() };
        let base: String = base.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')).collect();
        let base = if base.trim_matches('.').is_empty() { "file".to_string() } else { base };
        let dir = self.out_dir.join(ark_net::crypto::random_token(6));
        std::fs::create_dir_all(&dir).map_err(|e| ChannelError::new(K::Fatal, format!("simplex: cannot create {}: {e}", dir.display())))?;
        let p = dir.join(base);
        std::fs::write(&p, data).map_err(|e| ChannelError::new(K::Fatal, format!("simplex: cannot save attachment: {e}")))?;
        Ok(p.display().to_string())
    }

    fn media_item(&self, m: &Media, caption: &str) -> Result<Value, ChannelError> {
        let p = self.local_path(m)?;
        let ext = ext_of(&p);
        Ok(if m.kind == MediaKind::Voice || (m.kind == MediaKind::Audio && VOICE_EXTS.contains(&ext.as_str())) {
            json!({"msgContent": {"type": "voice", "text": caption, "duration": 0}, "fileSource": {"filePath": p}})
        } else if m.kind == MediaKind::Image || IMAGE_EXTS.contains(&ext.as_str()) {
            // No image library here: upstream's no-Pillow fallback sends an empty thumbnail.
            json!({"filePath": p, "msgContent": {"type": "image", "image": "", "text": caption}})
        } else {
            json!({"filePath": p, "msgContent": {"type": "file", "text": caption}})
        })
    }

    fn send_items(&self, chat: &str, items: Value, required: bool) -> Result<Vec<String>, ChannelError> {
        match self.command(&send_cmd(chat, &items))? {
            Some(r) => {
                check_reply("send", &r)?;
                Ok(item_ids(&r))
            }
            // Daemons do not always answer chat commands; text is fire-and-forget upstream.
            None if !required => Ok(vec![]),
            None => Err(ChannelError::new(K::Network, "simplex: no reply to file send")),
        }
    }

    fn simple(&self, what: &str, cmd: &str) -> Result<(), ChannelError> {
        match self.command(cmd)? {
            Some(r) => check_reply(what, &r),
            None => Err(ChannelError::new(K::Network, format!("simplex {what}: no reply"))),
        }
    }
}

fn numeric(what: &str, id: &str) -> Result<i64, ChannelError> {
    id.split(':').next().unwrap_or("").parse().map_err(|_| ChannelError::new(K::Protocol, format!("simplex {what}: message id {id} is not numeric")))
}

impl Channel for Simplex {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 3,
            edit: true,
            delete: true,
            typing: false,
            buttons: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
            ..Caps::default()
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started();
        let g = self.rx.lock().unwrap();
        let rx = g.as_ref().expect("started");
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        while !cancel.is_cancelled() && Instant::now() < until {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => return Ok(std::iter::once(m).chain(rx.try_iter()).collect()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Fatal, "simplex worker stopped")),
            }
        }
        Ok(vec![])
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let chat = out.chat.trim();
        if chat.is_empty() {
            return Err(ChannelError::new(K::Fatal, "simplex: empty chat id"));
        }
        let quote = out.reply_to.as_deref().and_then(|r| r.split(':').next()?.parse::<i64>().ok());
        let mut text = out.text.clone();
        // No buttons on SimpleX: numbered options.
        let labels: Vec<&str> = out.buttons.iter().flatten().map(|b| b.label.as_str()).collect();
        if !labels.is_empty() {
            text = format!("{}\n\n{}", text.trim_end(), labels.iter().enumerate().map(|(i, l)| format!("{}. {l}", i + 1)).collect::<Vec<_>>().join("\n"));
        }
        let mut sent = Sent::default();
        let mut first = true;
        let caption_fits = out.media.len() == 1 && text.chars().count() <= 1000;
        for m in &out.media {
            let cap = if caption_fits { text.as_str() } else { m.caption.as_deref().unwrap_or("") };
            let mut item = self.media_item(m, cap)?;
            if let (true, Some(q)) = (first, quote) {
                item["quotedItemId"] = json!(q);
            }
            first = false;
            sent.ids.extend(self.send_items(chat, json!([item]), true)?);
        }
        if caption_fits {
            return Ok(sent);
        }
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            let mut item = json!({"msgContent": {"type": "text", "text": piece}});
            if let (true, Some(q)) = (first, quote) {
                item["quotedItemId"] = json!(q);
            }
            first = false;
            sent.ids.extend(self.send_items(chat, json!([item]), false)?);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        let id = numeric("edit", message_id)?;
        self.simple("edit", &format!("/_update item {} {id} text {text}", target(chat)))
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let id = numeric("delete", message_id)?;
        self.simple("delete", &format!("/_delete item {} {id} broadcast", target(chat)))
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let id = numeric("reaction", message_id)?;
        let r = json!({"type": "emoji", "emoji": emoji});
        self.simple("reaction", &format!("/_reaction {} {id} {} {r}", target(chat), if remove { "off" } else { "on" }))
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        match &m.path {
            // Files land on the daemon's filesystem.
            Some(p) => std::fs::read(p).map_err(|e| ChannelError::new(K::NotFound, format!("simplex file {p}: {e}"))),
            None => Err(ChannelError::new(K::NotFound, "simplex file not downloaded yet")),
        }
    }

    fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Simplex {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
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
    /// simplex-chat daemon WebSocket (default ws://127.0.0.1:5225).
    #[serde(default)]
    ws_url: Option<String>,
    /// Accept incoming contact requests automatically (default true).
    #[serde(default = "d_true")]
    auto_accept: bool,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let c = Simplex::new(ctx.name, st.ws_url.as_deref(), st.auto_accept, ctx.state("simplex-out"), st.poll_timeout_secs)?;
    Ok(Arc::new(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use std::net::{TcpListener, TcpStream};

    type Ws = WebSocket<TcpStream>;

    /// Fake daemon: `script(n, ws, seen)` runs per connection; commands the client sent are pushed to `seen`.
    struct Fake {
        url: String,
        seen: Arc<Mutex<Vec<Value>>>,
    }

    fn fake(script: impl Fn(usize, &mut Ws, &Arc<Mutex<Vec<Value>>>) + Send + Sync + 'static) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let script = Arc::new(script);
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let (seen, script) = (s2.clone(), script.clone());
                std::thread::spawn(move || {
                    let Ok((head, rest)) = ark_net::ws::read_head(&mut s, 65536) else { return };
                    let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                    ws.get_ref().set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    script(n, &mut ws, &seen);
                });
            }
        });
        Fake { url, seen }
    }

    /// Read client commands for `d`, recording them; answer `/_send` etc. via `answer`.
    fn pump(ws: &mut Ws, seen: &Arc<Mutex<Vec<Value>>>, d: Duration, answer: &dyn Fn(&Value) -> Option<Value>) {
        let until = Instant::now() + d;
        while Instant::now() < until {
            match ws.recv() {
                Ok(Some(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    seen.lock().unwrap().push(v.clone());
                    if let Some(mut r) = answer(&v) {
                        r["corrId"] = v["corrId"].clone();
                        let _ = ws.send_text(&r.to_string());
                    }
                }
                Ok(Some(Message::Close(_))) | Err(_) => return,
                _ => {}
            }
        }
    }

    fn contact_item(item_id: i64, contact: i64, text: &str) -> Value {
        json!({"chatInfo": {"type": "direct", "contact": {"contactId": contact, "localDisplayName": "amy"}},
               "chatItem": {"chatDir": {"type": "directRcv"}, "meta": {"itemId": item_id, "itemTs": "2024-03-01T12:00:00.250Z"},
                            "content": {"type": "rcvMsgContent", "msgContent": {"type": "text", "text": text}}}})
    }

    fn evt(resp: Value) -> String {
        json!({"resp": resp}).to_string()
    }

    fn mk(url: &str) -> Simplex {
        let mut s = Simplex::new("sx", Some(url), true, temp_dir("sx"), 1).unwrap();
        s.backoff_initial = Duration::from_millis(20);
        s.backoff_max = Duration::from_millis(50);
        s.cmd_timeout = Duration::from_secs(2);
        s.connect_wait = Duration::from_secs(2);
        s
    }

    fn poll_n(s: &Simplex, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        for _ in 0..10 {
            got.extend(s.poll(&Cancel::new()).unwrap());
            if got.len() >= n {
                break;
            }
        }
        got
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso("2024-03-01T12:00:00.250Z"), Some(1709294400));
        assert_eq!(parse_iso("2024-03-01T14:00:00+02:00"), Some(1709294400));
        assert_eq!(parse_iso("garbage"), None);
    }

    #[test]
    fn inbound_contacts_groups_files_quotes_edits_and_requests() {
        let srv = fake(|_, ws, seen| {
            let group = json!({"chatInfo": {"type": "group", "groupInfo": {"groupId": 7, "groupProfile": {"displayName": "Team"}}},
                "chatItem": {"chatDir": {"type": "groupRcv", "groupMember": {"memberId": "bWVt", "memberProfile": {"displayName": "bob"}}},
                    "meta": {"itemId": 21, "itemTs": "2024-03-01T12:00:00Z", "userMention": true},
                    "content": {"type": "rcvMsgContent", "msgContent": {"type": "text", "text": "@ark hi"}},
                    "quotedItem": {"chatDir": {"type": "groupSnd"}, "itemId": 20, "content": {"type": "text", "text": "earlier"}}}});
            let own = json!({"chatInfo": {"type": "direct", "contact": {"contactId": 3}}, "chatItem": {"chatDir": {"type": "directSnd"}, "meta": {"itemId": 22}, "content": {"type": "sndMsgContent", "msgContent": {"type": "text", "text": "mine"}}}});
            let image = json!({"chatInfo": {"type": "direct", "contact": {"contactId": 3, "profile": {"displayName": "Amy P"}}},
                "chatItem": {"chatDir": {"type": "directRcv"}, "meta": {"itemId": 23}, "file": {"fileId": 4, "fileName": "cat.png", "fileSize": 10, "fileSource": {"filePath": "/files/cat.png"}},
                    "content": {"type": "rcvMsgContent", "msgContent": {"type": "image", "text": "", "image": "data:..."}}}});
            let voice = json!({"chatInfo": {"type": "direct", "contact": {"contactId": 3}},
                "chatItem": {"chatDir": {"type": "directRcv"}, "meta": {"itemId": 24}, "file": {"fileId": 8, "fileName": "voice.m4a"},
                    "content": {"type": "rcvMsgContent", "msgContent": {"type": "voice", "text": "", "duration": 3}}}});
            let _ = ws.send_text("not json");
            let _ = ws.send_text(&json!({"corrId": "ark-999", "resp": {"type": "newChatItems", "chatItems": [contact_item(1, 3, "echo of ours")]}}).to_string());
            let _ = ws.send_text(&evt(json!({"type": "newChatItems", "chatItems": [contact_item(10, 3, "hello"), own, group, image, voice]})));
            let _ = ws.send_text(&evt(json!({"type": "contactRequest", "contactRequest": {"contactRequestId": 5}})));
            let _ = ws.send_text(&evt(json!({"type": "rcvFileDescrReady", "rcvFileTransfer": {"fileId": 9}})));
            let mut upd = contact_item(10, 3, "hello (edited)");
            upd["chatItem"]["meta"]["updatedAt"] = json!("2024-03-01T12:00:05Z");
            let _ = ws.send_text(&evt(json!({"type": "chatItemUpdated", "chatItem": upd})));
            let _ = ws.send_text(&evt(json!({"type": "somethingElse"})));
            pump(ws, seen, Duration::from_millis(400), &|_| None);
            let _ = ws.send_text(&evt(json!({"type": "rcvFileComplete", "chatItem": {"chatItem": {"file": {"fileId": 8, "fileSource": {"filePath": "/files/voice.m4a"}}}}})));
            pump(ws, seen, Duration::from_secs(3), &|_| None);
        });
        let s = mk(&srv.url);
        let got = poll_n(&s, 5);
        assert_eq!(got.len(), 5, "{got:#?}");
        let m = &got[0];
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.sender_name.as_str(), m.text.as_str(), m.message_id.as_str(), m.ts, m.chat_type), ("3", "3", "amy", "hello", "10", 1709294400, ChatType::Direct));
        let g = &got[1];
        assert_eq!((g.chat.as_str(), g.chat_name.as_str(), g.sender.as_str(), g.sender_name.as_str(), g.chat_type), ("group:7", "Team", "bWVt", "bob", ChatType::Group));
        assert!(g.mentioned);
        let r = g.reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "20" && r.text == "earlier");
        let i = &got[2];
        assert_eq!((i.sender_name.as_str(), i.media[0].kind, i.media[0].path.as_deref(), i.media[0].mime.as_str()), ("Amy P", MediaKind::Image, Some("/files/cat.png"), "image/png"));
        assert!(got[3].edited && got[3].message_id == "10:e1709294405" && got[3].text == "hello (edited)");
        let v = &got[4];
        assert_eq!((v.message_id.as_str(), v.media[0].kind, v.media[0].path.as_deref()), ("24", MediaKind::Voice, Some("/files/voice.m4a")), "voice delivered after rcvFileComplete");
        let cmds: Vec<String> = srv.seen.lock().unwrap().iter().map(|c| c["cmd"].as_str().unwrap().to_string()).collect();
        assert!(cmds.contains(&"/freceive 8".to_string()) && cmds.contains(&"/accept 5".to_string()) && cmds.contains(&"/freceive 9".to_string()), "{cmds:?}");
        assert!(srv.seen.lock().unwrap().iter().all(|c| c["corrId"].as_str().unwrap().starts_with(CORR_PREFIX)));
        s.stop();
    }

    #[test]
    fn auto_accept_off_ignores_contact_requests() {
        let srv = fake(|_, ws, seen| {
            let _ = ws.send_text(&evt(json!({"type": "contactRequest", "contactRequest": {"contactRequestId": 5}})));
            let _ = ws.send_text(&evt(json!({"type": "newChatItems", "chatItems": [contact_item(1, 3, "hi")]})));
            pump(ws, seen, Duration::from_secs(2), &|_| None);
        });
        let mut s = mk(&srv.url);
        s.auto_accept = false;
        assert_eq!(poll_n(&s, 1).len(), 1);
        std::thread::sleep(Duration::from_millis(100));
        assert!(srv.seen.lock().unwrap().is_empty());
        s.stop();
    }

    #[test]
    fn send_commands_quotes_files_actions_and_errors() {
        let srv = fake(|_, ws, seen| {
            pump(ws, seen, Duration::from_secs(5), &|v| {
                let cmd = v["cmd"].as_str().unwrap();
                if cmd.starts_with("/_send @404 ") {
                    return Some(json!({"resp": {"type": "chatCmdError", "chatError": {"type": "error", "errorType": {"type": "contactNotFound"}}}}));
                }
                if cmd.starts_with("/_send @9 ") {
                    return None; // daemon stays silent
                }
                if cmd.starts_with("/_reaction") && cmd.contains("💩") {
                    return Some(json!({"resp": {"type": "chatCmdError", "chatError": {"type": "error", "errorType": {"type": "invalidReaction"}}}}));
                }
                if cmd.starts_with("/_send") {
                    return Some(json!({"resp": {"type": "newChatItems", "chatItems": [{"chatItem": {"meta": {"itemId": 101}}}]}}));
                }
                Some(json!({"resp": {"type": "cmdOk"}}))
            });
        });
        let s = mk(&srv.url);
        let out = Outbound {
            reply_to: Some("55".into()),
            buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "No".into(), data: "n".into(), url: None }]],
            ..Outbound::text("3", "pick \"one\"")
        };
        assert_eq!(s.send(&out).unwrap().ids, ["101"]);
        assert_eq!(s.send(&Outbound::text("group:7", "to group")).unwrap().ids, ["101"]);
        let f = temp_dir("sx").join("report.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        let doc = Media { kind: MediaKind::Document, path: Some(f.display().to_string()), ..Default::default() };
        s.send(&Outbound { media: vec![doc], ..Outbound::text("3", "the report") }).unwrap();
        let v = temp_dir("sx").join("note.ogg");
        std::fs::write(&v, b"OggS").unwrap();
        s.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(v.display().to_string()), ..Default::default() }], ..Outbound::text("3", "") }).unwrap();
        let e = s.send(&Outbound::text("404", "x")).unwrap_err();
        assert_eq!(e.kind, K::NotFound);
        assert_eq!(s.send(&Outbound::text("9", "fire and forget")).unwrap().ids, Vec::<String>::new(), "text without reply still succeeds");
        let missing = Media { kind: MediaKind::Document, path: Some("/nope/x.bin".into()), ..Default::default() };
        assert_eq!(s.send(&Outbound { media: vec![missing], ..Outbound::text("3", "") }).unwrap_err().kind, K::Fatal);
        s.edit("3", "101", "fixed text").unwrap();
        s.delete("group:7", "101").unwrap();
        s.react("3", "101:e5", "👍", false).unwrap();
        s.react("3", "101", "👍", true).unwrap();
        assert_eq!(s.react("3", "101", "💩", false).unwrap_err().kind, K::Protocol);
        assert_eq!(s.edit("3", "abc", "x").unwrap_err().kind, K::Protocol);
        let cmds: Vec<String> = srv.seen.lock().unwrap().iter().map(|c| c["cmd"].as_str().unwrap().to_string()).collect();
        let items = |c: &str| -> Value { serde_json::from_str(c.split_once(" json ").unwrap().1).unwrap() };
        assert!(cmds[0].starts_with("/_send @3 json "), "{}", cmds[0]);
        assert_eq!(items(&cmds[0]), json!([{"msgContent": {"type": "text", "text": "pick \"one\"\n\n1. Yes\n2. No"}, "quotedItemId": 55}]));
        assert!(cmds[1].starts_with("/_send #7 json "));
        assert_eq!(items(&cmds[2]), json!([{"filePath": f.display().to_string(), "msgContent": {"type": "file", "text": "the report"}}]));
        assert_eq!(items(&cmds[3]), json!([{"msgContent": {"type": "voice", "text": "", "duration": 0}, "fileSource": {"filePath": v.display().to_string()}}]));
        let rest: Vec<&String> = cmds.iter().filter(|c| !c.starts_with("/_send")).collect();
        assert_eq!(rest[0], "/_update item @3 101 text fixed text");
        assert_eq!(rest[1], "/_delete item #7 101 broadcast");
        assert_eq!(rest[2], r#"/_reaction @3 101 on {"emoji":"👍","type":"emoji"}"#);
        assert!(rest[3].starts_with("/_reaction @3 101 off "));
        s.stop();
    }

    #[test]
    fn reconnects_after_drop_and_send_fails_fast_when_daemon_down() {
        let srv = fake(|n, ws, seen| {
            let _ = ws.send_text(&evt(json!({"type": "newChatItems", "chatItems": [contact_item(n as i64 + 1, 3, &format!("conn {n}"))]})));
            if n == 0 {
                let _ = ws.get_ref().shutdown(std::net::Shutdown::Both);
                return;
            }
            pump(ws, seen, Duration::from_secs(3), &|_| None);
        });
        let s = mk(&srv.url);
        let got = poll_n(&s, 2);
        assert_eq!(got.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["conn 0", "conn 1"]);
        s.stop();
        // Nothing listening: Network error within connect_wait.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        drop(l);
        let mut s = mk(&url);
        s.connect_wait = Duration::from_millis(200);
        let t = Instant::now();
        assert_eq!(s.send(&Outbound::text("3", "x")).unwrap_err().kind, K::Network);
        assert!(t.elapsed() < Duration::from_secs(2));
        s.stop();
    }

    #[test]
    fn cancel_returns_promptly() {
        let srv = fake(|_, ws, seen| pump(ws, seen, Duration::from_secs(5), &|_| None));
        let mut s = mk(&srv.url);
        s.poll_timeout = 30;
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(s.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
        s.stop();
    }

    #[test]
    fn build_validates_settings() {
        let d = temp_dir("sx");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "sx", state_dir: &d, secrets: &secrets };
        let m = |v: Value| v.as_object().unwrap().clone();
        let c = build(&ctx, &m(json!({}))).unwrap();
        assert!(c.caps().chat_types.contains(&ChatType::Group));
        assert!(build(&ctx, &m(json!({"ws_url": "http://x"}))).err().unwrap().contains("ws://"));
        assert!(build(&ctx, &m(json!({"wsurl": "ws://x"}))).err().unwrap().contains("wsurl"));
        assert!(build(&ctx, &m(json!({"ws_url": "ws://127.0.0.1:1", "auto_accept": false}))).is_ok());
    }
}
