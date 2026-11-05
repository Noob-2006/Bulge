//! ClickClack (ported from OpenClaw `extensions/clickclack`, MIT).
//!
//! Receive: a background thread resolves the workspace (`wsp_…` id, slug or
//! name via `GET /api/workspaces`) and the bot (`GET /api/me`), takes the event
//! tail cursor (`GET /api/realtime/events?include_tail=true`) on first start,
//! replays the backlog after a persisted cursor (`after_cursor`, 500 per page),
//! then follows `WS /api/realtime/ws?workspace_id=…&after_cursor=…` (Bearer).
//! `message.created` / `thread.reply_created` events are only routing hints:
//! the authoritative message is re-fetched with `GET /api/messages/{id}` before
//! it is delivered. The cursor advances only after an event was handled, so a
//! failure reconnects and replays it. Pings every 30 s; silence → reconnect.
//!
//! Send: `channel:<id|name>` → `POST /api/channels/{id}/messages`,
//! `thread:<root>` or `Outbound::thread` → `POST /api/messages/{root}/thread/replies`,
//! `dm:<user>` → `POST /api/dms` then `POST /api/dms/{conv}/messages`;
//! `reply_to` → `quoted_message_id`. Media: `POST /api/uploads` (multipart)
//! then `POST /api/messages/{id}/attachments`. Edit: `PATCH /api/messages/{id}`.
//! Typing: `POST /api/realtime/ephemeral` (`typing.started`). Commands menu:
//! `PUT /api/bots/self/commands`. Bodies are Markdown natively.
//!
//! Setup: `setup_url` (`…/api/bot-setup-codes/claim`) + `setup_code` claims a
//! one-time code (no credential sent; HTTP only on loopback) and persists the
//! returned bot token to the channel state dir (0600).

#[path = "clickclack_discussion.rs"]
mod discussion;

use crate::http::{Http, Payload};
use crate::{
    sleep_cancellable, write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming,
};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 16000;
const EVENT_PAGE_LIMIT: usize = 500;
const MAX_UPLOAD: u64 = 64 * 1024 * 1024;
pub const SETUP_CLAIM_PATH: &str = "/api/bot-setup-codes/claim";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ident {
    workspace: String,
    bot_id: String,
    handle: String,
}

/// Shared between the channel and its realtime thread.
struct Core {
    id: String,
    base: String,
    http: Http,
    workspace_sel: String,
    bot_id_cfg: Option<String>,
    state: PathBuf,
    ident: Mutex<Option<Ident>>,
    stop: Cancel,
    reconnect: Duration,
    /// Seconds of WS silence before the connection is considered dead.
    idle: Duration,
    ping_every: Duration,
    /// `ws(s)://host[:port][/prefix]`, derived from `base`.
    ws_base: String,
}

pub struct ClickClack {
    core: Arc<Core>,
    poll_timeout: u64,
    started: AtomicBool,
    tx: Mutex<Option<Sender<Result<Inbound, ChannelError>>>>,
    rx: Mutex<Receiver<Result<Inbound, ChannelError>>>,
    /// user id → direct conversation id.
    dms: Mutex<HashMap<String, String>>,
    /// (command, description, args_hint) registered once on start.
    pub commands: Vec<(String, String, String)>,
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn enc(s: &str) -> String {
    seagent_net::urlencode(s)
}

impl Core {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn api(&self, method: &str, path: &str, body: Payload) -> Result<Value, ChannelError> {
        let r = self.http.call(method, &self.url(path), &[("accept", "application/json")], body)?;
        if !(200..300).contains(&r.status) {
            let e = crate::http::classify(r.status, r.retry_after, &format!("clickclack {method} {}", path.split('?').next().unwrap_or("")), &r.body);
            return Err(e);
        }
        if r.body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("clickclack {path}: bad JSON ({e})")))
    }

    fn ident(&self) -> Result<Ident, ChannelError> {
        if let Some(i) = self.ident.lock().unwrap().clone() {
            return Ok(i);
        }
        let workspace = if self.workspace_sel.starts_with("wsp_") {
            self.workspace_sel.clone()
        } else {
            let v = self.api("GET", "/api/workspaces", Payload::None)?;
            v["workspaces"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|w| [&w["id"], &w["slug"], &w["name"]].iter().any(|f| f.as_str() == Some(self.workspace_sel.as_str())))
                .map(|w| s(&w["id"]))
                .ok_or_else(|| ChannelError::new(K::Fatal, format!("clickclack workspace not found: {}", self.workspace_sel)))?
        };
        let me = self.api("GET", "/api/me", Payload::None)?;
        let i = Ident { workspace, bot_id: self.bot_id_cfg.clone().unwrap_or_else(|| s(&me["user"]["id"])), handle: s(&me["user"]["handle"]) };
        *self.ident.lock().unwrap() = Some(i.clone());
        Ok(i)
    }

    fn load_cursor(&self) -> Option<String> {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&self.state).ok()?).ok()?;
        v["cursor"].as_str().map(str::to_string)
    }

    fn save_cursor(&self, c: &str) {
        let _ = write_atomic(&self.state, json!({ "cursor": c }).to_string().as_bytes());
    }

    fn event_page(&self, ws: &str, after: Option<&str>, tail: bool) -> Result<(Vec<Value>, Option<String>), ChannelError> {
        let mut q = format!("/api/realtime/events?workspace_id={}", enc(ws));
        if let Some(a) = after {
            q.push_str(&format!("&after_cursor={}&limit={EVENT_PAGE_LIMIT}", enc(a)));
        }
        if tail {
            q.push_str("&include_tail=true");
        }
        let v = self.api("GET", &q, Payload::None)?;
        let events = v["events"].as_array().cloned().unwrap_or_default();
        Ok((events, v["tail_cursor"].as_str().map(str::to_string)))
    }

    /// `None` when the message is gone (404).
    fn message(&self, id: &str) -> Result<Option<Value>, ChannelError> {
        match self.api("GET", &format!("/api/messages/{}", enc(id)), Payload::None) {
            Ok(v) => Ok(Some(v["message"].clone()).filter(|m| m.is_object())),
            Err(e) if e.kind == K::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// One realtime event → maybe an Inbound. Errors leave the cursor where it was.
    fn process(&self, ev: &Value, me: &Ident) -> Result<Option<Inbound>, ChannelError> {
        let t = ev["type"].as_str().unwrap_or("");
        if t != "message.created" && t != "thread.reply_created" {
            return Ok(None);
        }
        if ev["payload"]["author_id"].as_str() == Some(me.bot_id.as_str()) {
            return Ok(None);
        }
        let Some(mid) = ev["payload"]["message_id"].as_str().filter(|m| !m.is_empty()) else { return Ok(None) };
        let Some(m) = self.message(mid)? else { return Ok(None) };
        Ok(inbound_of(&self.id, &self.base, &m, me))
    }

    fn ws_url(&self, ws: &str, after: &str) -> String {
        let mut u = format!("{}/api/realtime/ws?workspace_id={}", self.ws_base, enc(ws));
        if !after.is_empty() {
            u.push_str(&format!("&after_cursor={}", enc(after)));
        }
        u
    }

    /// One connect cycle: identity, backlog, then the socket until it drops.
    fn cycle(&self, cursor: &mut Option<String>, tx: &Sender<Result<Inbound, ChannelError>>) -> Result<(), ChannelError> {
        let me = self.ident()?;
        match cursor.clone() {
            None => {
                let (events, tail) = self.event_page(&me.workspace, None, true)?;
                // Older servers omit tail_cursor: skip the first page of history.
                let c = tail.or_else(|| events.iter().rev().find_map(|e| e["cursor"].as_str().filter(|c| !c.is_empty()).map(str::to_string))).unwrap_or_default();
                self.save_cursor(&c);
                *cursor = Some(c);
            }
            Some(_) => loop {
                if self.stop.is_cancelled() {
                    return Ok(());
                }
                let after = cursor.clone().unwrap_or_default();
                let (events, _) = self.event_page(&me.workspace, Some(&after).filter(|a| !a.is_empty()).map(|s| s.as_str()), false)?;
                if events.is_empty() {
                    break;
                }
                for ev in &events {
                    let c = s(&ev["cursor"]);
                    if c.is_empty() || Some(&c) == cursor.as_ref() {
                        return Err(ChannelError::new(K::Protocol, "clickclack event backlog returned a non-advancing cursor"));
                    }
                    if let Some(i) = self.process(ev, &me)? {
                        let _ = tx.send(Ok(i));
                    }
                    self.save_cursor(&c);
                    *cursor = Some(c);
                }
            },
        }
        let token_hdr = self.http.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap_or_default();
        let url = self.ws_url(&me.workspace, cursor.as_deref().unwrap_or(""));
        let (mut ws, _) = WebSocket::connect(&url, &[("Authorization", &token_hdr)], Duration::from_secs(30)).map_err(|e| {
            let m = e.to_string();
            let kind = if m.contains(" 401") || m.contains(" 403") { K::Auth } else { K::Network };
            ChannelError::new(kind, format!("clickclack websocket: {m}"))
        })?;
        ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| ChannelError::new(K::Network, e.to_string()))?;
        let (mut last_rx, mut last_ping) = (Instant::now(), Instant::now());
        loop {
            if self.stop.is_cancelled() {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                return Ok(());
            }
            if last_rx.elapsed() > self.idle {
                return Err(ChannelError::new(K::Network, "clickclack websocket heartbeat timed out"));
            }
            if last_ping.elapsed() >= self.ping_every {
                ws.send(&Message::Ping(b"seagent".to_vec())).map_err(|e| ChannelError::new(K::Network, e.to_string()))?;
                last_ping = Instant::now();
            }
            match ws.recv() {
                Ok(None) => {}
                Ok(Some(Message::Text(t))) => {
                    last_rx = Instant::now();
                    let Ok(ev) = serde_json::from_str::<Value>(&t) else { continue };
                    if let Some(i) = self.process(&ev, &me)? {
                        let _ = tx.send(Ok(i));
                    }
                    if let Some(c) = ev["cursor"].as_str().filter(|c| !c.is_empty()) {
                        self.save_cursor(c);
                        *cursor = Some(c.to_string());
                    }
                }
                Ok(Some(Message::Close(_))) => return Ok(()),
                Ok(Some(_)) => last_rx = Instant::now(),
                Err(e) => return Err(ChannelError::new(K::Network, format!("clickclack websocket: {e}"))),
            }
        }
    }

    fn run(self: Arc<Self>, tx: Sender<Result<Inbound, ChannelError>>) {
        let mut cursor = self.load_cursor();
        let mut backoff = self.reconnect;
        while !self.stop.is_cancelled() {
            match self.cycle(&mut cursor, &tx) {
                Ok(()) => backoff = self.reconnect,
                Err(e) if matches!(e.kind, K::Auth | K::Fatal) => {
                    let _ = tx.send(Err(e));
                    return;
                }
                Err(_) => backoff = (backoff * 2).min(Duration::from_secs(30)),
            }
            if !sleep_cancellable(backoff, &self.stop) {
                return;
            }
        }
    }
}

/// Lower-case `@handle` tokens in a body (ClickClack's mention grammar).
fn mention_handles(body: &str) -> Vec<String> {
    let b = body.to_lowercase();
    let chars: Vec<char> = b.chars().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut out = Vec::new();
    for i in 0..chars.len() {
        if chars[i] != '@' || (i > 0 && (word(chars[i - 1]) || chars[i - 1] == '@')) {
            continue;
        }
        let h: String = chars[i + 1..].iter().take_while(|c| word(**c)).collect();
        if h.len() >= 2 && h.len() <= 32 && h.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
            out.push(h);
        }
    }
    out
}

fn kind_of(ct: &str) -> MediaKind {
    match ct.split('/').next().unwrap_or("") {
        "image" => MediaKind::Image,
        "audio" => MediaKind::Audio,
        "video" => MediaKind::Video,
        _ => MediaKind::Document,
    }
}

fn inbound_of(channel: &str, base: &str, m: &Value, me: &Ident) -> Option<Inbound> {
    let author = s(&m["author_id"]);
    if author.is_empty() || author == me.bot_id {
        return None;
    }
    let (chat, chat_type) = match (m["channel_id"].as_str().filter(|c| !c.is_empty()), m["direct_conversation_id"].as_str().filter(|c| !c.is_empty())) {
        (Some(c), _) => (format!("channel:{c}"), ChatType::Group),
        (None, Some(_)) => (format!("dm:{author}"), ChatType::Direct),
        _ => return None,
    };
    let body = s(&m["body"]);
    let media: Vec<Media> = m["attachments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let ct = a["content_type"].as_str().unwrap_or("");
            let url = a["url"].as_str().map(|u| if u.starts_with('/') { format!("{base}{u}") } else { u.to_string() });
            Media { kind: kind_of(ct), id: a["id"].as_str().map(str::to_string), url, mime: ct.into(), name: s(&a["filename"]), size: a["byte_size"].as_u64().unwrap_or(0), ..Default::default() }
        })
        .collect();
    if body.trim().is_empty() && media.is_empty() {
        return None;
    }
    let thread = m["parent_message_id"].as_str().filter(|p| !p.is_empty()).map(|_| s(&m["thread_root_id"])).filter(|t| !t.is_empty());
    let reply = m["quoted_message_id"].as_str().filter(|q| !q.is_empty()).map(|q| ReplyRef {
        id: q.into(),
        text: s(&m["quoted_message"]["body"]),
        author: s(&m["quoted_message"]["author_id"]),
        is_own: m["quoted_message"]["author_id"].as_str() == Some(me.bot_id.as_str()),
    });
    let ts = m["created_at"].as_str().and_then(parse_rfc3339).unwrap_or(0);
    let edited = m["edited_at"].as_str().is_some_and(|e| !e.is_empty());
    Some(Inbound {
        channel: channel.into(),
        chat,
        chat_type: if thread.is_some() && chat_type == ChatType::Group { ChatType::Thread } else { chat_type },
        chat_name: s(&m["channel_name"]),
        thread,
        sender_name: m["author"]["display_name"].as_str().filter(|n| !n.is_empty()).map(str::to_string).unwrap_or_else(|| author.clone()),
        is_bot: m["author"]["kind"] == "bot",
        mentioned: !me.handle.is_empty() && mention_handles(&body).contains(&me.handle.to_lowercase()),
        sender: author,
        text: body,
        message_id: match (edited, m["edited_at"].as_str()) {
            (true, Some(e)) => format!("{}:e{e}", s(&m["id"])),
            _ => s(&m["id"]),
        },
        ts,
        media,
        reply,
        edited,
        ..Default::default()
    })
}

/// `2024-01-02T03:04:05[.fff](Z|±hh:mm)` → unix seconds.
fn parse_rfc3339(t: &str) -> Option<i64> {
    let (date, time) = t.split_once(['T', ' '])?;
    let mut d = date.split('-').map(|x| x.parse::<i64>());
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let hh: i64 = time.get(0..2)?.parse().ok()?;
    let mm: i64 = time.get(3..5)?.parse().ok()?;
    let ss: i64 = time.get(6..8)?.parse().ok()?;
    let rest = &time[8..];
    let tz = rest.find(['Z', '+', '-']).map(|i| &rest[i..]).unwrap_or("Z");
    let off = if tz == "Z" || tz.len() < 6 { 0 } else { (tz[1..3].parse::<i64>().ok()? * 3600 + tz[4..6].parse::<i64>().ok()? * 60) * if tz.starts_with('-') { -1 } else { 1 } };
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss - off)
}

enum Target {
    Channel(String),
    Thread(String),
    Dm(String),
}

fn parse_target(raw: &str) -> Result<Target, ChannelError> {
    let v = raw.trim();
    if v.is_empty() {
        return Err(ChannelError::new(K::Fatal, "clickclack target is required"));
    }
    match v.split_once(':') {
        Some(("channel", b)) if !b.trim().is_empty() => Ok(Target::Channel(b.trim().into())),
        Some(("thread", b)) if !b.trim().is_empty() => Ok(Target::Thread(b.trim().into())),
        Some(("dm", b)) if !b.trim().is_empty() => Ok(Target::Dm(b.trim().into())),
        None => Ok(Target::Channel(v.into())),
        _ => Err(ChannelError::new(K::Fatal, format!("unsupported clickclack target: {raw}"))),
    }
}

impl ClickClack {
    pub fn new(id: &str, base: &str, token: &str, workspace: &str, state: PathBuf, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: clickclack token is empty"));
        }
        if workspace.trim().is_empty() {
            return Err(format!("channel {id}: clickclack workspace is required"));
        }
        seagent_net::Url::parse(base).map_err(|e| format!("channel {id}: base_url: {e}"))?;
        let (tx, rx) = channel();
        let b = base.trim_end_matches('/');
        let ws_base = if let Some(r) = b.strip_prefix("https://") { format!("wss://{r}") } else { format!("ws://{}", b.trim_start_matches("http://")) };
        Ok(ClickClack {
            core: Arc::new(Core {
                id: id.into(),
                base: base.trim_end_matches('/').into(),
                http: Http::new(Duration::from_secs(60)).bearer(token.trim()),
                workspace_sel: workspace.trim().into(),
                bot_id_cfg: None,
                state,
                ident: Mutex::new(None),
                stop: Cancel::new(),
                reconnect: Duration::from_millis(1500),
                idle: Duration::from_secs(90),
                ping_every: Duration::from_secs(30),
                ws_base,
            }),
            poll_timeout: poll_timeout_secs,
            started: AtomicBool::new(false),
            tx: Mutex::new(Some(tx)),
            rx: Mutex::new(rx),
            dms: Mutex::new(HashMap::new()),
            commands: Vec::new(),
        })
    }

    fn core_mut(&mut self) -> &mut Core {
        Arc::get_mut(&mut self.core).expect("configure before start")
    }

    pub fn with_reconnect(mut self, d: Duration) -> Self {
        self.core_mut().reconnect = d;
        self
    }

    pub fn with_bot_id(mut self, id: Option<String>) -> Self {
        self.core_mut().bot_id_cfg = id;
        self
    }

    #[cfg(test)]
    fn with_ws(mut self, addr: &str) -> Self {
        self.core_mut().ws_base = format!("ws://{addr}");
        self
    }

    #[cfg(test)]
    fn with_heartbeat(mut self, ping: Duration, idle: Duration) -> Self {
        let c = self.core_mut();
        c.ping_every = ping;
        c.idle = idle;
        self
    }

    fn start(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        if !self.commands.is_empty() {
            let cmds: Vec<Value> = self.commands.iter().map(|(c, d, a)| json!({"command": c, "description": d, "args_hint": a})).collect();
            // 403/404: the server has no command menu for this bot; not fatal.
            let _ = self.core.api("PUT", "/api/bots/self/commands", Payload::Json(&json!({ "commands": cmds })));
        }
        if let Some(tx) = self.tx.lock().unwrap().take() {
            let core = self.core.clone();
            let _ = std::thread::Builder::new().name(format!("clickclack {}", self.core.id)).spawn(move || core.run(tx));
        }
    }

    fn channel_id(&self, ws: &str, sel: &str) -> Result<String, ChannelError> {
        if sel.starts_with("chn_") {
            return Ok(sel.into());
        }
        let v = self.core.api("GET", &format!("/api/workspaces/{}/channels", enc(ws)), Payload::None)?;
        v["channels"].as_array().into_iter().flatten().find(|c| c["id"].as_str() == Some(sel) || c["name"].as_str() == Some(sel)).map(|c| s(&c["id"])).ok_or_else(|| ChannelError::new(K::NotFound, format!("clickclack channel not found: {sel}")))
    }

    fn dm_conversation(&self, ws: &str, user: &str) -> Result<String, ChannelError> {
        if let Some(c) = self.dms.lock().unwrap().get(user) {
            return Ok(c.clone());
        }
        let v = self.core.api("POST", "/api/dms", Payload::Json(&json!({"workspace_id": ws, "member_ids": [user]})))?;
        let c = s(&v["conversation"]["id"]);
        if c.is_empty() {
            return Err(ChannelError::new(K::Protocol, "clickclack /api/dms returned no conversation id"));
        }
        self.dms.lock().unwrap().insert(user.into(), c.clone());
        Ok(c)
    }

    fn create(&self, ws: &str, out: &Outbound, body: &str, first: bool) -> Result<String, ChannelError> {
        let target = parse_target(&out.chat)?;
        let quoted = out.reply_to.as_deref().filter(|_| first).filter(|r| !r.is_empty());
        let mut b = json!({ "body": body });
        let path = match (&out.thread, &target) {
            (Some(t), _) if !t.is_empty() => format!("/api/messages/{}/thread/replies", enc(t)),
            (_, Target::Thread(t)) => format!("/api/messages/{}/thread/replies", enc(t)),
            (_, Target::Dm(u)) => {
                let c = self.dm_conversation(ws, u)?;
                format!("/api/dms/{}/messages", enc(&c))
            }
            (_, Target::Channel(c)) => format!("/api/channels/{}/messages", enc(&self.channel_id(ws, c)?)),
        };
        if let (Some(q), false) = (quoted, path.contains("/thread/replies")) {
            b["quoted_message_id"] = json!(q);
        }
        let v = self.core.api("POST", &path, Payload::Json(&b))?;
        Ok(s(&v["message"]["id"]))
    }

    fn upload(&self, ws: &str, m: &Media) -> Result<(String, String), ChannelError> {
        let (data, name) = match (&m.path, &m.url) {
            (Some(p), _) => {
                let d = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                (d, std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default())
            }
            (None, Some(u)) => (crate::http::get_bytes(u, &[], MAX_UPLOAD)?, u.rsplit('/').next().unwrap_or("").split('?').next().unwrap_or("").to_string()),
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        if data.len() as u64 > MAX_UPLOAD {
            return Err(ChannelError::new(K::Fatal, "attachment larger than 64 MiB"));
        }
        let name = if !m.name.is_empty() { m.name.clone() } else if name.is_empty() { "attachment".into() } else { name };
        let ct = if m.mime.is_empty() { "application/octet-stream" } else { m.mime.as_str() };
        let r = self.core.http.call("POST", &self.core.url(&format!("/api/uploads?workspace_id={}", enc(ws))), &[("accept", "application/json")], Payload::Multipart(&[("file", &name, ct, &data)]))?;
        if !(200..300).contains(&r.status) {
            return Err(crate::http::classify(r.status, r.retry_after, "clickclack upload", &r.body));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        let id = s(&v["upload"]["id"]);
        if id.is_empty() {
            return Err(ChannelError::new(K::Protocol, "clickclack upload returned no id"));
        }
        Ok((id, name))
    }
}

impl Channel for ClickClack {
    fn id(&self) -> &str {
        &self.core.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 0,
            edit: true,
            delete: false,
            typing: true,
            buttons: false,
            polls: false,
            native_commands: true,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.start();
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(r) => {
                    got.push(r?);
                    for r in rx.try_iter() {
                        got.push(r?);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // The realtime thread ended (auth failure already reported, or stopped).
                    if !sleep_cancellable(Duration::from_millis(100), cancel) {
                        break;
                    }
                }
            }
        }
        Ok(got)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let ws = self.core.ident()?.workspace;
        let mut sent = Sent::default();
        // Buttons are not part of the ClickClack API: numbered text options.
        let mut text = out.text.clone();
        let opts: Vec<&crate::Button> = out.buttons.iter().flatten().collect();
        if !opts.is_empty() {
            text.push('\n');
            for (i, b) in opts.iter().enumerate() {
                text.push_str(&match &b.url {
                    Some(u) => format!("\n{}. [{}]({u})", i + 1, b.label),
                    None => format!("\n{}. {}", i + 1, b.label),
                });
            }
        }
        let mut first = true;
        for (i, m) in out.media.iter().enumerate() {
            // Upload first so a crash leaves an identifiable upload, then the carrying message.
            let (upload, name) = self.upload(&ws, m)?;
            let body = if i == 0 && out.media.len() == 1 && !text.trim().is_empty() && text.chars().count() <= MAX_MESSAGE { std::mem::take(&mut text) } else { m.caption.clone().unwrap_or(name) };
            let mid = self.create(&ws, out, &body, first)?;
            first = false;
            let attach = json!({"upload_id": upload});
            if let Err(e) = self.core.api("POST", &format!("/api/messages/{}/attachments", enc(&mid)), Payload::Json(&attach)) {
                // Idempotent: check for a lost success, then retry once.
                let has = self.core.message(&mid).ok().flatten().is_some_and(|v| v["attachments"].as_array().into_iter().flatten().any(|a| a["id"].as_str() == Some(upload.as_str())));
                if !has {
                    self.core.api("POST", &format!("/api/messages/{}/attachments", enc(&mid)), Payload::Json(&attach)).map_err(|_| e)?;
                }
            }
            sent.ids.push(mid);
        }
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            sent.ids.push(self.create(&ws, out, &piece, first)?);
            first = false;
        }
        Ok(sent)
    }

    fn edit(&self, _chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.core.api("PATCH", &format!("/api/messages/{}", enc(message_id)), Payload::Json(&json!({ "body": text }))).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let ws = self.core.ident()?.workspace;
        let mut b = json!({"workspace_id": ws, "type": "typing.started", "payload": {}});
        match parse_target(chat)? {
            Target::Channel(c) => b["channel_id"] = json!(self.channel_id(&ws, &c)?),
            Target::Dm(u) => b["direct_conversation_id"] = json!(self.dm_conversation(&ws, &u)?),
            Target::Thread(_) => return Ok(()),
        }
        self.core.api("POST", "/api/realtime/ephemeral", Payload::Json(&b)).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Unsupported, "clickclack attachment has no url"))?;
        // Only send the bot token to our own server.
        if u.starts_with(&self.core.base) {
            let auth = self.core.http.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap_or_default();
            crate::http::get_bytes(u, &[("authorization", &auth)], MAX_UPLOAD)
        } else {
            crate::http::get_bytes(u, &[], MAX_UPLOAD)
        }
    }

    /// The session `discussion` tool (see [`discussion`]).
    fn tools(&self) -> Vec<Arc<dyn seagent_core::Tool>> {
        vec![discussion::tool(&self.core)]
    }

    fn stop(&self) {
        self.core.stop.cancel();
    }
}

impl Drop for ClickClack {
    fn drop(&mut self) {
        self.core.stop.cancel();
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Claim a one-time setup code (no existing credential is sent). Returns the claim JSON
/// (`token`, `bot`, `workspace`, `defaults`, optional `api_base_url`).
pub fn claim_setup_code(claim_url: &str, code: &str) -> Result<Value, String> {
    let u = seagent_net::Url::parse(claim_url).map_err(|e| format!("clickclack setup_url: {e}"))?;
    let path = u.path.clone();
    if !(u.scheme == "http" || u.scheme == "https") || path.contains('?') || path.contains('#') || !path.ends_with(SETUP_CLAIM_PATH) || claim_url.split("://").nth(1).is_some_and(|r| r.split('/').next().unwrap_or("").contains('@')) {
        return Err("ClickClack setup code claim URL must be a valid HTTP(S) endpoint".into());
    }
    if u.scheme == "http" && !is_loopback(&u.host) {
        return Err("ClickClack setup codes require HTTPS unless the server is on loopback".into());
    }
    let http = Http::new(Duration::from_secs(30));
    let r = http.call("POST", claim_url, &[("accept", "application/json")], Payload::Json(&json!({ "code": code }))).map_err(|e| e.message)?;
    if !(200..300).contains(&r.status) {
        return Err(format!("ClickClack setup code claim failed ({}): {}", r.status, r.body.chars().take(200).collect::<String>()));
    }
    let v: Value = serde_json::from_str(&r.body).map_err(|_| "ClickClack setup code claim returned invalid JSON".to_string())?;
    for (obj, key) in [(&v, "token"), (&v["bot"], "id"), (&v["bot"], "handle"), (&v["workspace"], "id")] {
        if obj[key].as_str().is_none_or(|x| x.trim().is_empty()) {
            return Err(format!("ClickClack setup code claim returned invalid {key}"));
        }
    }
    if let Some(api) = v.get("api_base_url") {
        if v["contract_version"] != 1 || !api.is_string() {
            return Err("ClickClack setup code claim returned invalid v1 contract metadata".into());
        }
        let api = api.as_str().unwrap().trim_end_matches('/');
        if format!("{api}{SETUP_CLAIM_PATH}") != claim_url {
            return Err("ClickClack setup code claim returned an API base that does not match the claim URL".into());
        }
    }
    Ok(v)
}

fn save_secret(path: &std::path::Path, v: &Value) -> std::io::Result<()> {
    write_atomic(path, v.to_string().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn d_poll() -> u64 {
    25
}
fn d_reconnect() -> u64 {
    1500
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    base_url: String,
    /// REST/WS endpoint when it differs from `base_url`.
    #[serde(default)]
    api_base_url: Option<String>,
    #[serde(default)]
    token: Option<String>,
    /// `wsp_…` id, slug or name. Defaults to the workspace a setup code was claimed for.
    #[serde(default)]
    workspace: Option<String>,
    #[serde(default)]
    bot_user_id: Option<String>,
    #[serde(default)]
    setup_url: Option<String>,
    #[serde(default)]
    setup_code: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_reconnect")]
    reconnect_ms: u64,
    /// Publish /new /stop /status /help to the ClickClack command menu.
    #[serde(default)]
    commands: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let creds = ctx.state("clickclack-credentials.json");
    let saved: Value = std::fs::read_to_string(&creds).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let (token, claimed_ws) = match ctx.opt_secret("token", &st.token)? {
        Some(t) => (t, None),
        None if saved["token"].is_string() => (s_of(&saved["token"]), saved["workspace"]["id"].as_str().map(str::to_string)),
        None => {
            let (Some(url), Some(code)) = (&st.setup_url, ctx.opt_secret("setup_code", &st.setup_code)?) else {
                return Err(format!("channel {}: clickclack needs `token` or `setup_url` + `setup_code`", ctx.name));
            };
            let v = claim_setup_code(url, &code).map_err(|e| format!("channel {}: {e}", ctx.name))?;
            save_secret(&creds, &v).map_err(|e| format!("channel {}: saving clickclack credentials: {e}", ctx.name))?;
            (s_of(&v["token"]), v["workspace"]["id"].as_str().map(str::to_string))
        }
    };
    let ws = st.workspace.clone().or(claimed_ws).ok_or_else(|| format!("channel {}: clickclack `workspace` is required", ctx.name))?;
    let base = st.api_base_url.as_deref().unwrap_or(&st.base_url);
    let mut c = ClickClack::new(ctx.name, base, &token, &ws, ctx.state("clickclack.json"), st.poll_timeout_secs)?.with_reconnect(Duration::from_millis(st.reconnect_ms.max(50))).with_bot_id(st.bot_user_id);
    if st.commands {
        c.commands = [("new", "開新對話"), ("stop", "中斷目前的工作"), ("status", "目前狀態"), ("help", "說明")].iter().map(|(a, b)| (a.to_string(), b.to_string(), String::new())).collect();
    }
    Ok(Arc::new(c))
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[cfg(test)]
fn discussion_hash_for_tests(s: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::net::TcpListener;

    type Reply = (u16, Vec<(String, String)>, String);

    fn ok(v: Value) -> Reply {
        (200, vec![], v.to_string())
    }

    fn msg(id: &str, extra: Value) -> Value {
        let mut m = json!({"id": id, "workspace_id": "wsp_1", "channel_id": "chn_1", "author_id": "usr_amy", "thread_root_id": id, "body": "hello", "body_format": "markdown", "created_at": "2024-01-02T03:04:05Z", "author": {"id": "usr_amy", "display_name": "Amy", "handle": "amy", "kind": "human"}});
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        m
    }

    /// REST side shared by the realtime tests.
    fn rest(req: &crate::testutil::Req, msgs: &HashMap<String, Value>, backlog: &[Value]) -> Reply {
        let p = req.path.as_str();
        if p == "/api/me" {
            return ok(json!({"user": {"id": "usr_bot", "handle": "seagentbot", "display_name": "Seagent"}}));
        }
        if p == "/api/workspaces" {
            return ok(json!({"workspaces": [{"id": "wsp_1", "slug": "team", "name": "Team"}]}));
        }
        if p.starts_with("/api/realtime/events") {
            if p.contains("include_tail=true") {
                return ok(json!({"events": [{"id": "e0", "cursor": "c0", "type": "message.created", "payload": {"message_id": "old"}}], "tail_cursor": "c0"}));
            }
            if p.contains("after_cursor=c0") {
                return ok(json!({"events": backlog}));
            }
            return ok(json!({"events": []}));
        }
        if let Some(id) = p.strip_prefix("/api/messages/") {
            return match msgs.get(id) {
                Some(m) => ok(json!({ "message": m })),
                None => (404, vec![], "{\"error\":\"not found\"}".into()),
            };
        }
        (500, vec![], "unexpected".into())
    }

    fn ev(cursor: &str, ty: &str, mid: &str, author: &str) -> Value {
        json!({"id": format!("ev{cursor}"), "cursor": cursor, "type": ty, "workspace_id": "wsp_1", "payload": {"message_id": mid, "author_id": author}})
    }

    fn cc(url: &str, state: PathBuf) -> ClickClack {
        ClickClack::new("cc", url, "TOKSECRET", "team", state, 1).unwrap().with_reconnect(Duration::from_millis(30))
    }

    /// A WS server that accepts `conns` connections; each gets the frames from `script(n)` then drops.
    fn ws_server(script: impl Fn(usize) -> Vec<String> + Send + 'static, hold: Duration) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let h2 = heads.clone();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let (head, rest) = seagent_net::ws::read_head(&mut s, 65536).unwrap();
                h2.lock().unwrap().push(head.clone());
                let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                for f in script(n) {
                    ws.send_text(&f).unwrap();
                }
                std::thread::sleep(hold);
                drop(ws);
            }
        });
        (format!("127.0.0.1:{}", addr.port()), heads)
    }

    #[test]
    fn realtime_backlog_refetch_filters_and_reconnects_after_drop() {
        let mut msgs = HashMap::new();
        msgs.insert("m1".to_string(), msg("m1", json!({"body": "hey @SeagentBot look", "attachments": [{"id": "upl_1", "filename": "a.png", "content_type": "image/png", "byte_size": 3, "url": "/api/uploads/upl_1/content"}]})));
        msgs.insert("m2".to_string(), msg("m2", json!({"parent_message_id": "m1", "thread_root_id": "m1", "body": "in thread", "quoted_message_id": "b1", "quoted_message": {"author_id": "usr_bot", "body": "bot said"}})));
        msgs.insert("m3".to_string(), msg("m3", json!({"channel_id": null, "direct_conversation_id": "dmc_9", "author_id": "usr_bo", "author": {"display_name": "Bo", "kind": "bot"}, "body": "dm @seagentbotx"})));
        msgs.insert("own".to_string(), msg("own", json!({"author_id": "usr_bot"})));
        msgs.insert("m4".to_string(), msg("m4", json!({"body": "after reconnect", "edited_at": "2024-01-02T03:05:00Z"})));
        let (ws_addr, heads) = ws_server(
            |n| match n {
                0 => vec![ev("c1", "message.created", "m1", "usr_amy").to_string(), ev("c2", "thread.reply_created", "m2", "usr_amy").to_string(), "not json".into(), ev("c3", "reaction.added", "m1", "usr_amy").to_string(), ev("c4", "message.created", "own", "usr_bot").to_string(), ev("c5", "message.created", "gone", "usr_amy").to_string(), ev("c6", "message.created", "m3", "usr_bo").to_string()],
                _ => vec![ev("c7", "message.created", "m4", "usr_amy").to_string()],
            },
            Duration::from_millis(100),
        );
        let srv = FakeServer::start(move |req, _| rest(req, &msgs, &[]));
        let dir = temp_dir("cc");
        let c = cc(&srv.url, dir.join("s.json")).with_ws(&ws_addr);
        let mut got = Vec::new();
        let start = Instant::now();
        while got.len() < 5 && start.elapsed() < Duration::from_secs(10) {
            got.extend(c.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(got.len(), 5, "4 messages; the fake resends m4 on every reconnect: {got:#?}");
        let a = &got[0];
        assert_eq!((a.chat.as_str(), a.chat_type, a.sender.as_str(), a.sender_name.as_str(), a.ts), ("channel:chn_1", ChatType::Group, "usr_amy", "Amy", 1704164645));
        assert!(a.mentioned, "case-insensitive @handle");
        assert_eq!((a.media[0].kind, a.media[0].url.as_deref()), (MediaKind::Image, Some(format!("{}/api/uploads/upl_1/content", srv.url).as_str())));
        let t = &got[1];
        assert_eq!((t.thread.as_deref(), t.chat_type), (Some("m1"), ChatType::Thread));
        assert!(t.reply.as_ref().unwrap().is_own && t.addressed());
        let d = &got[2];
        assert_eq!((d.chat.as_str(), d.chat_type, d.is_bot, d.mentioned), ("dm:usr_bo", ChatType::Direct, true, false));
        assert!(got[3].text == "hello" || got[3].text == "after reconnect");
        let e = got.iter().find(|i| i.edited).unwrap();
        assert_eq!(e.message_id, "m4:e2024-01-02T03:05:00Z");
        let heads = heads.lock().unwrap().clone();
        assert!(heads.len() >= 2, "reconnected after drop");
        assert!(heads[0].starts_with("GET /api/realtime/ws?workspace_id=wsp_1&after_cursor=c0 "), "{}", heads[0]);
        assert!(heads[1].contains("after_cursor=c7") || heads[1].contains("after_cursor=c6"), "resumes from last cursor: {}", heads[1]);
        assert!(heads[0].to_lowercase().contains("authorization: bearer toksecret"));
        let st = std::fs::read_to_string(dir.join("s.json")).unwrap();
        assert!(st.contains("\"cursor\":\"c"), "{st}");
        c.stop();
    }

    #[test]
    fn send_shapes_channel_thread_dm_quote_media_edit_typing() {
        let srv = FakeServer::start(|req, n| {
            let p = req.path.as_str();
            match (req.method.as_str(), p) {
                (_, "/api/me") => ok(json!({"user": {"id": "usr_bot", "handle": "seagentbot"}})),
                (_, "/api/workspaces") => ok(json!({"workspaces": [{"id": "wsp_1", "slug": "team", "name": "Team"}]})),
                (_, "/api/workspaces/wsp_1/channels") => ok(json!({"channels": [{"id": "chn_gen", "name": "general"}]})),
                ("POST", "/api/dms") => ok(json!({"conversation": {"id": "dmc_5"}})),
                ("POST", p) if p.starts_with("/api/uploads") => ok(json!({"upload": {"id": "upl_7", "filename": "r.pdf"}})),
                ("POST", p) if p.ends_with("/attachments") => ok(json!({"ok": true})),
                ("POST", "/api/realtime/ephemeral") => (204, vec![], String::new()),
                ("PATCH", _) => ok(json!({"message": {"id": "m"}})),
                _ => ok(json!({"message": {"id": format!("msg_{n}")}})),
            }
        });
        let c = cc(&srv.url, temp_dir("cc").join("s"));
        let out = Outbound { reply_to: Some("q1".into()), buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("channel:general", "**hi**") };
        let s1 = c.send(&out).unwrap();
        assert_eq!(s1.ids.len(), 1);
        let reqs = srv.requests();
        let post = reqs.iter().find(|r| r.path == "/api/channels/chn_gen/messages").unwrap();
        assert_eq!(post.json()["body"], "**hi**\n\n1. Yes");
        assert_eq!(post.json()["quoted_message_id"], "q1");
        assert_eq!(post.header("authorization"), Some("Bearer TOKSECRET"));
        c.send(&Outbound { thread: Some("root1".into()), reply_to: Some("x".into()), ..Outbound::text("channel:chn_gen", "t") }).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/api/messages/root1/thread/replies");
        assert!(r.json().get("quoted_message_id").is_none());
        c.send(&Outbound::text("thread:root2", "t2")).unwrap();
        assert_eq!(srv.requests().last().unwrap().path, "/api/messages/root2/thread/replies");
        c.send(&Outbound::text("dm:usr_amy", "d1")).unwrap();
        c.send(&Outbound::text("dm:usr_amy", "d2")).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.iter().filter(|r| r.path == "/api/dms").count(), 1, "conversation cached");
        assert_eq!(reqs.iter().find(|r| r.path == "/api/dms").unwrap().json(), json!({"workspace_id": "wsp_1", "member_ids": ["usr_amy"]}));
        assert_eq!(reqs.iter().filter(|r| r.path == "/api/dms/dmc_5/messages").count(), 2);
        let f = temp_dir("cc").join("r.pdf");
        std::fs::write(&f, b"%PDF-1").unwrap();
        let before = srv.requests().len();
        let s = c.send(&Outbound { media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), mime: "application/pdf".into(), ..Default::default() }], ..Outbound::text("chn_gen", "report") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let reqs: Vec<_> = srv.requests().into_iter().skip(before).collect();
        assert!(reqs[0].path == "/api/uploads?workspace_id=wsp_1" && reqs[0].body.contains("filename=\"r.pdf\"") && reqs[0].body.contains("%PDF-1"));
        assert_eq!(reqs[1].json()["body"], "report", "caption carried by the message");
        assert_eq!(reqs[2].path, format!("/api/messages/{}/attachments", s.ids[0]));
        assert_eq!(reqs[2].json()["upload_id"], "upl_7");
        c.edit("channel:chn_gen", "m9", "new").unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.json()["body"].as_str()), ("PATCH", "/api/messages/m9", Some("new")));
        c.typing("channel:general", None).unwrap();
        let r = srv.requests().last().unwrap().json();
        assert_eq!((r["type"].as_str(), r["channel_id"].as_str(), r["workspace_id"].as_str()), (Some("typing.started"), Some("chn_gen"), Some("wsp_1")));
        assert_eq!(c.delete("x", "y").unwrap_err().kind, K::Unsupported);
        assert_eq!(c.react("x", "y", "👍", false).unwrap_err().kind, K::Unsupported);
        assert!(c.send(&Outbound::text("bogus:x", "t")).is_err());
        let long = "word ".repeat(4000);
        let n = c.send(&Outbound::text("chn_gen", &long)).unwrap().ids.len();
        assert_eq!(n, 2, "split at MAX_MESSAGE");
    }

    #[test]
    fn error_mapping_and_auth_failure_surfaces_from_poll() {
        for (status, kind) in [(401, K::Auth), (403, K::Auth), (404, K::NotFound), (429, K::RateLimited { retry_after: Some(Duration::from_secs(7)) }), (502, K::Network), (400, K::Protocol)] {
            let srv = FakeServer::start(move |req, _| match req.path.as_str() {
                "/api/me" => ok(json!({"user": {"id": "usr_bot", "handle": "b"}})),
                _ => (status, vec![("Retry-After".into(), "7".into())], "{\"error\":\"TOKSECRET nope\"}".into()),
            });
            let c = ClickClack::new("cc", &srv.url, "TOKSECRET", "wsp_1", temp_dir("cc").join("s"), 1).unwrap();
            let e = c.send(&Outbound::text("chn_x", "hi")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
        }
        let srv = FakeServer::start(|_, _| (401, vec![], "{}".into()));
        let c = cc(&srv.url, temp_dir("cc").join("s"));
        let start = Instant::now();
        let mut err = None;
        while err.is_none() && start.elapsed() < Duration::from_secs(5) {
            err = c.poll(&Cancel::new()).err();
        }
        assert_eq!(err.unwrap().kind, K::Auth, "bad token stops the realtime loop and reaches poll");
    }

    #[test]
    fn cancel_returns_promptly_and_stop_ends_thread() {
        let srv = FakeServer::start(|req, _| rest(req, &HashMap::new(), &[]));
        let (ws_addr, _) = ws_server(|_| vec![], Duration::from_secs(30));
        let c = ClickClack::new("cc", &srv.url, "T", "wsp_1", temp_dir("cc").join("s"), 30).unwrap().with_ws(&ws_addr);
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(c.poll(&cancel).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        c.stop();
    }

    #[test]
    fn heartbeat_silence_reconnects() {
        let srv = FakeServer::start(|req, _| rest(req, &HashMap::new(), &[]));
        // The fake server holds each silent connection for 2 s before accepting the next.
        let (ws_addr, heads) = ws_server(|_| vec![], Duration::from_secs(2));
        let c = ClickClack::new("cc", &srv.url, "T", "wsp_1", temp_dir("cc").join("s"), 1).unwrap().with_reconnect(Duration::from_millis(20)).with_heartbeat(Duration::from_millis(50), Duration::from_millis(300)).with_ws(&ws_addr);
        let start = Instant::now();
        while heads.lock().unwrap().len() < 2 && start.elapsed() < Duration::from_secs(10) {
            c.poll(&Cancel::new()).unwrap();
        }
        assert!(heads.lock().unwrap().len() >= 2, "idle socket replaced");
        c.stop();
    }

    #[test]
    fn backlog_replays_after_persisted_cursor() {
        let mut msgs = HashMap::new();
        msgs.insert("b1".to_string(), msg("b1", json!({"body": "missed while down"})));
        let backlog = vec![ev("c1", "message.created", "b1", "usr_amy")];
        let srv = FakeServer::start(move |req, _| rest(req, &msgs, &backlog));
        let (ws_addr, heads) = ws_server(|_| vec![], Duration::from_secs(2));
        let dir = temp_dir("cc");
        std::fs::write(dir.join("s.json"), r#"{"cursor":"c0"}"#).unwrap();
        let c = cc(&srv.url, dir.join("s.json")).with_ws(&ws_addr);
        let mut got = Vec::new();
        let start = Instant::now();
        while got.is_empty() && start.elapsed() < Duration::from_secs(5) {
            got.extend(c.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(got[0].text, "missed while down");
        let start = Instant::now();
        while heads.lock().unwrap().is_empty() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(heads.lock().unwrap()[0].contains("after_cursor=c1"));
        assert!(!srv.requests().iter().any(|r| r.path.contains("include_tail")), "persisted cursor skips tail lookup");
        c.stop();
    }

    #[test]
    fn setup_code_claim_validates_and_persists() {
        assert!(claim_setup_code("http://example.com/api/bot-setup-codes/claim", "c").unwrap_err().contains("HTTPS"));
        assert!(claim_setup_code("https://example.com/api/other", "c").is_err());
        let srv = FakeServer::start(|req, _| {
            assert!(req.header("authorization").is_none(), "no credential sent");
            match req.json()["code"].as_str() {
                Some("good") => ok(json!({"token": "NEWTOK", "bot": {"id": "usr_b", "handle": "seagent", "display_name": "Seagent"}, "workspace": {"id": "wsp_9", "route_id": "r", "slug": "s", "name": "n"}, "defaults": {}})),
                Some("bad-shape") => ok(json!({"token": "", "bot": {}, "workspace": {}})),
                _ => (410, vec![], "expired".into()),
            }
        });
        let url = format!("{}{SETUP_CLAIM_PATH}", srv.url);
        assert_eq!(claim_setup_code(&url, "good").unwrap()["token"], "NEWTOK");
        assert!(claim_setup_code(&url, "bad-shape").unwrap_err().contains("invalid"));
        assert!(claim_setup_code(&url, "old").unwrap_err().contains("410"));
        let dir = temp_dir("cc");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "cc", state_dir: &dir, secrets: &secrets };
        let set = json!({"base_url": srv.url, "setup_url": url, "setup_code": "good"});
        let ch = build(&ctx, set.as_object().unwrap()).unwrap();
        assert_eq!(ch.id(), "cc");
        let p = ctx.state("clickclack-credentials.json");
        assert!(std::fs::read_to_string(&p).unwrap().contains("NEWTOK"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Second start reuses the saved token without claiming again.
        let n = srv.requests().len();
        build(&ctx, json!({"base_url": srv.url, "setup_url": url, "setup_code": "good"}).as_object().unwrap()).unwrap();
        assert_eq!(srv.requests().len(), n);
        assert!(build(&ctx, json!({"base_url": srv.url, "tokn": "x"}).as_object().unwrap()).is_err());
    }

    #[test]
    fn mention_grammar_and_timestamps() {
        assert_eq!(mention_handles("hi @Seagent-Bot, and x@nope @a @@b (@ok_1)"), vec!["seagent-bot", "ok_1"]);
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2024-01-02T03:04:05.123+01:00"), Some(1704164645 - 3600));
    }

    /// OpenClaw `discussions/tool.test.ts` + `service.test.ts`: open creates a managed public
    /// channel bound to the session (adopted on re-open), read merges roots and complete
    /// threads into the latest-N window as one record per line, close archives it.
    #[test]
    fn discussion_tool_opens_reads_and_closes() {
        let archived = Arc::new(AtomicBool::new(false));
        let a2 = archived.clone();
        let srv = FakeServer::start(move |req, _| {
            let p = req.path.as_str();
            match (req.method.as_str(), p) {
                ("GET", "/api/me") => ok(json!({"user": {"id": "usr_bot", "handle": "seagentbot"}})),
                ("GET", "/api/workspaces") => ok(json!({"workspaces": [{"id": "wsp_1", "slug": "team", "name": "Team"}]})),
                ("GET", "/api/workspaces/wsp_1/channels") => ok(json!({"channels": [{"id": "chn_x", "name": "fix-parser"}]})),
                ("POST", "/api/workspaces/wsp_1/channels") => {
                    let b = req.json();
                    assert_eq!((b["kind"].as_str(), b["external_managed"].as_bool(), b["name"].as_str()), (Some("public"), Some(true), Some("fix-parser-2")));
                    ok(json!({"channel": {"id": "chn_d", "name": b["name"], "external_ref": b["external_ref"], "route_id": "r1"}}))
                }
                ("GET", "/api/channels/chn_d") => {
                    let xr = format!("seagent-discussion:{}", &super::discussion_hash_for_tests("sess-1")[..32]);
                    ok(json!({"channel": {"id": "chn_d", "external_ref": xr, "archived": a2.load(Ordering::SeqCst)}}))
                }
                ("GET", p) if p.starts_with("/api/channels/chn_d/messages") => {
                    if p.contains("before_seq=10") {
                        ok(json!({"messages": [msg("m1", json!({"body": "first", "created_at": "2024-01-01T00:00:01Z", "author": {"display_name": "Amy"}}))], "oldest_seq": 9, "has_older": false}))
                    } else {
                        ok(json!({"messages": [
                            msg("m3", json!({"body": "line\u{2028}two", "created_at": "2024-01-01T00:00:03Z", "author_id": "usr_bob", "author": {"handle": "bob"}})),
                            msg("m2", json!({"body": "root", "created_at": "2024-01-01T00:00:02Z", "thread_state": {"reply_count": 1, "last_reply_at": "2024-01-01T00:00:04Z"}}))
                        ], "oldest_seq": 10, "has_older": true}))
                    }
                }
                ("GET", "/api/messages/m2/thread?limit=200") => ok(json!({"replies": [msg("r1", json!({"body": "reply", "created_at": "2024-01-01T00:00:04Z"}))]})),
                ("PATCH", "/api/channels/chn_d") => {
                    assert_eq!(req.json()["archived"], true);
                    a2.store(true, Ordering::SeqCst);
                    ok(json!({"channel": {"id": "chn_d"}}))
                }
                _ => (500, vec![], format!("unexpected {} {p}", req.method)),
            }
        });
        let dir = temp_dir("ccd");
        let c = cc(&srv.url, dir.join("cursor.json"));
        let tools = c.tools();
        assert_eq!(tools[0].spec().name, "discussion_cc");
        let mut ctx = crate::testutil::tool_ctx();
        ctx.session_id = "sess-1".into();
        let r = tools[0].call(&ctx, json!({}));
        assert!(r.content.starts_with("No discussion is bound"), "{}", r.content);
        let r = tools[0].call(&ctx, json!({"action": "open", "title": "Fix parser"}));
        assert!(!r.is_error && r.content.contains("chn_d"), "{}", r.content);
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("cursor.json.discussions.json")).unwrap()).unwrap();
        assert_eq!(saved["sess-1"]["channel_id"], "chn_d");
        let r = tools[0].call(&ctx, json!({"limit": 3}));
        assert!(!r.is_error, "{}", r.content);
        let lines: Vec<&str> = r.content.split("\n\n").next().unwrap().lines().collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert_eq!(lines[0], "timestamp=\"2024-01-01T00:00:02Z\" [Author \"Amy\" id=\"usr_amy\"] text=\"root\"");
        assert!(lines[1].contains("[Author \"bob\" id=\"usr_bob\"] text=\"line\\u2028two\""), "{}", lines[1]);
        assert!(lines[2].ends_with("text=\"reply\""));
        // Another session sees nothing; close archives and unbinds.
        let mut other = crate::testutil::tool_ctx();
        other.session_id = "sess-2".into();
        assert!(tools[0].call(&other, json!({"action": "read"})).content.starts_with("No discussion"));
        assert!(tools[0].call(&ctx, json!({"action": "close"})).content.starts_with("Archived"));
        assert!(tools[0].call(&ctx, json!({})).content.starts_with("No discussion"));
        assert!(tools[0].call(&ctx, json!({"action": "nuke"})).is_error);
    }
}

