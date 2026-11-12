//! Zalo personal accounts through the `bridges/zalouser` Node sidecar around
//! `zca-js` (ported from OpenClaw `extensions/zalouser`, MIT). The sidecar owns
//! the Zalo session: QR login, cookie persistence (0600 in its data dir), the
//! zca-js listener; seagent talks to it over a bearer-protected loopback HTTP API
//! (see `bridges/zalouser/README.md`):
//!
//! - `GET /messages?after=<seq>&epoch=<id>&wait=<s>` long-poll for listener events.
//!   Events carry a sequence number; the bridge keeps a ring buffer, so a poll that
//!   is abandoned (cancel) loses nothing and a bridge restart (new epoch) resets the cursor.
//! - `POST /send`, `/send-media`, `/react`, `/typing`, `/delete`; `GET /qr`, `/health`,
//!   `/friends`, `/groups`, `/me` (the last three back the `zalouser` agent tool).
//!
//! Chats: a DM is the peer's user id, a group is `g:<groupId>` (zca-js needs the
//! thread type on every call). Inbound: text, links, photos, videos, voice, files,
//! stickers, @mentions of our own id (stripped from the text like upstream),
//! quotes (replies, `is_own` when quoting us), group names. Outbound: Markdown as
//! Zalo rich text (`styles` ranges), in 2000-unit pieces with quote replies, media by
//! local path or URL (audio goes out as a voice message, as upstream), typing,
//! reactions (mapped to Zalo's reaction icons), delete (recall own / admin-delete).
//! Zalo has no edits or buttons; buttons become numbered text.
//!
//! Optionally `command = ["node", "/path/to/bridges/zalouser/bridge.mjs"]` makes
//! seagent supervise the sidecar: it is spawned with `ZALOUSER_BRIDGE_TOKEN`,
//! `ZALOUSER_BRIDGE_PORT`, `ZALOUSER_DATA_DIR`, `ZALOUSER_PROFILE` and restarted
//! with backoff when it exits; `stop()` kills it. Nothing is ever installed.

use crate::http::{Http, Payload, Resp};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent};
use seagent_core::tool::arg_opt_str;
use seagent_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_BRIDGE: &str = "http://127.0.0.1:3920";
pub const MAX_MESSAGE: usize = 2000;
/// Remembered (msgId → cliMsgId) pairs for reactions.
const MAX_REMEMBERED: usize = 2000;

pub struct ZaloUser {
    id: String,
    base: String,
    http: Http,
    poll_timeout: u64,
    /// (bridge epoch, last seen seq).
    cursor: Mutex<(String, u64)>,
    own_id: Mutex<Option<String>>,
    cli: Mutex<(HashMap<String, String>, VecDeque<String>)>,
    sup: Option<Supervisor>,
}

struct Supervisor {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<std::process::Child>>>,
}

impl ZaloUser {
    pub fn new(id: &str, base: &str, token: &str, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: zalouser bridge token is empty"));
        }
        Ok(ZaloUser {
            id: id.to_string(),
            base: base.trim_end_matches('/').to_string(),
            http: Http::new(Duration::from_secs(poll_timeout_secs + 30)).bearer(token.trim()),
            poll_timeout: poll_timeout_secs,
            cursor: Mutex::new((String::new(), 0)),
            own_id: Mutex::new(None),
            cli: Mutex::new((HashMap::new(), VecDeque::new())),
            sup: None,
        })
    }

    /// Spawn and keep the sidecar running. `env` is added to the child's environment.
    pub fn supervise(mut self, command: &[String], env: Vec<(String, String)>) -> Result<Self, String> {
        let (prog, args) = command.split_first().ok_or_else(|| format!("channel {}: zalouser command is empty", self.id))?;
        let (prog, args) = (prog.clone(), args.to_vec());
        let stop = Arc::new(AtomicBool::new(false));
        let child: Arc<Mutex<Option<std::process::Child>>> = Arc::default();
        let spawn = {
            let (prog, args, env) = (prog.clone(), args.clone(), env.clone());
            move || seagent_core::platform::proc::command(&prog).args(&args).envs(env.iter().map(|(k, v)| (k, v))).stdin(std::process::Stdio::null()).spawn()
        };
        // Fail fast on a missing binary instead of looping forever.
        *child.lock().unwrap() = Some(spawn().map_err(|e| format!("channel {}: cannot start zalouser bridge `{prog}`: {e}", self.id))?);
        let (st, ch, name) = (stop.clone(), child.clone(), self.id.clone());
        std::thread::Builder::new()
            .name(format!("zalouser supervisor {name}"))
            .spawn(move || {
                let mut backoff = Duration::from_millis(500);
                while !st.load(Ordering::SeqCst) {
                    let exited = {
                        let mut g = ch.lock().unwrap();
                        match g.as_mut().map(|c| c.try_wait()) {
                            Some(Ok(None)) => false,
                            _ => {
                                *g = None;
                                true
                            }
                        }
                    };
                    if !exited {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    eprintln!("channel {name}: zalouser bridge exited; restarting in {backoff:?}");
                    let until = std::time::Instant::now() + backoff;
                    while std::time::Instant::now() < until && !st.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    // Check the stop flag under the lock `stop()` takes, so no child outlives it.
                    let mut g = ch.lock().unwrap();
                    if st.load(Ordering::SeqCst) {
                        break;
                    }
                    match spawn() {
                        Ok(c) => *g = Some(c),
                        Err(e) => eprintln!("channel {name}: zalouser bridge restart failed: {e}"),
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        self.sup = Some(Supervisor { stop, child });
        Ok(self)
    }

    fn remember(&self, msg_id: &str, cli_id: &str) {
        if msg_id.is_empty() || cli_id.is_empty() {
            return;
        }
        let mut g = self.cli.lock().unwrap();
        if g.0.insert(msg_id.to_string(), cli_id.to_string()).is_none() {
            g.1.push_back(msg_id.to_string());
        }
        while g.1.len() > MAX_REMEMBERED {
            if let Some(old) = g.1.pop_front() {
                g.0.remove(&old);
            }
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, ChannelError> {
        let r = self.http.call("POST", &format!("{}{path}", self.base), &[], Payload::Json(body))?;
        bridge_result(path, &r)
    }

    /// GET on a worker thread so `cancel` is observed; `Ok(None)` = cancelled.
    fn get_cancellable(&self, url: String, cancel: &Cancel) -> Result<Option<Resp>, ChannelError> {
        let (tx, rx) = std::sync::mpsc::channel();
        let http = self.http.clone();
        std::thread::spawn(move || {
            let _ = tx.send(http.call("GET", &url, &[], Payload::None));
        });
        loop {
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok(r) => return r.map(Some),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if cancel.is_cancelled() => return Ok(None),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err(ChannelError::new(K::Network, "http worker died")),
            }
        }
    }

    /// QR login state from the sidecar: `{status, qr}` (qr = PNG data URL while pending).
    pub fn qr(&self) -> Result<Value, ChannelError> {
        bridge_get(&self.http, &self.base, "/qr")
    }

    pub fn health(&self) -> Result<Value, ChannelError> {
        bridge_get(&self.http, &self.base, "/health")
    }
}

/// Bridge JSON → value or a classified error. `{error}` bodies carry zca-js messages.
fn bridge_result(what: &str, r: &Resp) -> Result<Value, ChannelError> {
    let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
    if (200..300).contains(&r.status) {
        return Ok(v);
    }
    let msg = v["error"].as_str().unwrap_or("").to_string();
    let lower = msg.to_ascii_lowercase();
    let kind = match r.status {
        401 | 403 => K::Auth,
        409 if lower.contains("not_logged_in") || lower.contains("login") => K::Auth,
        404 | 410 => K::NotFound,
        _ if lower.contains("blocked") || lower.contains("not exist") || lower.contains("not found") || lower.contains("không tồn tại") => K::NotFound,
        429 => K::RateLimited { retry_after: r.retry_after },
        408 | 500..=599 => K::Network,
        _ => K::Protocol,
    };
    let hint = if kind == K::Auth && r.status == 409 { " (scan the QR code: GET /qr on the bridge)" } else { "" };
    Err(ChannelError::new(kind, format!("zalouser bridge {what}: HTTP {} {}{hint}", r.status, msg.chars().take(300).collect::<String>())))
}

fn s(v: &Value) -> String {
    v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())).or_else(|| v.as_u64().map(|n| n.to_string())).unwrap_or_default()
}

fn split_chat(chat: &str) -> (&str, bool) {
    match chat.strip_prefix("g:") {
        Some(g) => (g, true),
        None => (chat, false),
    }
}

/// Remove our own @mention spans (positions are UTF-16 units, as in JS).
fn strip_spans(text: &str, mentions: &Value, own: &str) -> String {
    let u: Vec<u16> = text.encode_utf16().collect();
    let mut spans: Vec<(usize, usize)> = mentions
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| s(&m["uid"]) == own)
        .filter_map(|m| {
            let start = m["pos"].as_u64().or_else(|| m["start"].as_u64()).or_else(|| m["offset"].as_u64())? as usize;
            let len = m["len"].as_u64().or_else(|| m["length"].as_u64())? as usize;
            (len > 0).then(|| (start.min(u.len()), (start + len).min(u.len())))
        })
        .collect();
    if spans.is_empty() {
        return text.to_string();
    }
    spans.sort();
    let mut out = Vec::new();
    let mut cur = 0;
    for (a, b) in spans {
        if a > cur {
            out.extend_from_slice(&u[cur..a]);
        }
        cur = cur.max(b);
    }
    out.extend_from_slice(&u[cur.min(u.len())..]);
    String::from_utf16_lossy(&out).split_whitespace().collect::<Vec<_>>().join(" ")
}

fn ts_secs(v: &Value) -> i64 {
    let n = v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok()).map(|f| f as i64)).unwrap_or(0);
    if n > 100_000_000_000 {
        n / 1000
    } else {
        n
    }
}

/// One listener event (zca-js `Message`: {type, threadId, isSelf, data}) → Inbound.
fn inbound_of(channel: &str, ev: &Value, own: Option<&str>) -> Option<Inbound> {
    if ev["kind"].as_str().unwrap_or("message") != "message" || ev["isSelf"] == true {
        return None;
    }
    let d = &ev["data"];
    let sender = s(&d["uidFrom"]);
    if sender.is_empty() || own.is_some_and(|o| o == sender) {
        return None;
    }
    let is_group = ev["type"].as_i64() == Some(1);
    let thread = Some(s(&ev["threadId"])).filter(|t| !t.is_empty()).unwrap_or_else(|| if is_group { s(&d["idTo"]) } else { sender.clone() });
    let msg_type = d["msgType"].as_str().unwrap_or("webchat");
    let content = &d["content"];
    let mut media = Vec::new();
    let mut text = match content {
        Value::String(t) => t.clone(),
        Value::Object(_) => {
            let href = content["href"].as_str().unwrap_or("").trim().to_string();
            let title = content["title"].as_str().unwrap_or("").trim().to_string();
            let desc = content["description"].as_str().unwrap_or("").trim().to_string();
            let kind = match msg_type {
                "chat.photo" => Some(MediaKind::Image),
                "chat.video.msg" => Some(MediaKind::Video),
                "chat.voice" => Some(MediaKind::Voice),
                "chat.gif" => Some(MediaKind::Animation),
                "chat.sticker" => Some(MediaKind::Sticker),
                "share.file" => Some(MediaKind::Document),
                _ => None,
            };
            match kind {
                Some(k) => {
                    let url = Some(href.clone()).filter(|h| h.starts_with("http")).or_else(|| content["thumb"].as_str().filter(|t| t.starts_with("http")).map(str::to_string));
                    let id = content["id"].as_i64().map(|n| n.to_string()).or_else(|| (k == MediaKind::Sticker).then(|| s(&content["id"])).filter(|x| !x.is_empty()));
                    let name = if k == MediaKind::Document { title.clone() } else { String::new() };
                    let size = content["params"].as_str().and_then(|p| serde_json::from_str::<Value>(p).ok()).and_then(|p| p["fileSize"].as_str().and_then(|x| x.parse().ok()).or_else(|| p["fileSize"].as_u64())).unwrap_or(0);
                    media.push(Media { kind: k, url, id, name, size, ..Default::default() });
                    if k == MediaKind::Document { desc } else { [title, desc].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join("\n") }
                }
                // Links and cards: upstream joins title, description and href.
                None => [title, desc, href].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join("\n"),
            }
        }
        _ => String::new(),
    };
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let mentioned = own.is_some_and(|o| d["mentions"].as_array().into_iter().flatten().any(|m| s(&m["uid"]) == o));
    if mentioned {
        text = strip_spans(&text, &d["mentions"], own.unwrap_or(""));
    }
    let reply = d["quote"].as_object().map(|q| {
        let owner = s(&q.get("ownerId").cloned().unwrap_or_default());
        ReplyRef {
            id: s(q.get("globalMsgId").unwrap_or(&Value::Null)),
            text: q.get("msg").and_then(Value::as_str).unwrap_or("").to_string(),
            is_own: own.is_some_and(|o| !owner.is_empty() && o == owner),
            author: owner,
        }
    });
    let chat_name = if is_group { ["groupName", "gName", "idToName", "threadName", "roomName"].iter().find_map(|k| d[*k].as_str().filter(|x| !x.trim().is_empty())).unwrap_or("").to_string() } else { String::new() };
    Some(Inbound {
        channel: channel.to_string(),
        chat: if is_group { format!("g:{thread}") } else { thread },
        chat_type: if is_group { ChatType::Group } else { ChatType::Direct },
        chat_name,
        sender,
        sender_name: d["dName"].as_str().unwrap_or("").trim().to_string(),
        text,
        message_id: s(&d["msgId"]),
        ts: ts_secs(&d["ts"]),
        media,
        mentioned,
        reply,
        ..Default::default()
    })
}

/// Zalo reaction icons (upstream `normalizeZaloReactionIcon`).
pub fn reaction_icon(emoji: &str) -> String {
    let e = emoji.trim();
    match e.to_lowercase().as_str() {
        "" | "like" | "👍" | ":+1:" => "/-strong",
        "heart" | "❤️" | "❤" | "<3" => "/-heart",
        "haha" | "laugh" | "😂" => ":>",
        "wow" | "😮" => ":o",
        "cry" | "😢" => ":-((",
        "angry" | "😡" => ":-h",
        _ => e,
    }
    .to_string()
}

fn media_kind(k: MediaKind) -> &'static str {
    match k {
        MediaKind::Image | MediaKind::Sticker | MediaKind::Animation => "image",
        MediaKind::Video => "video",
        MediaKind::Audio | MediaKind::Voice => "audio",
        MediaKind::Document => "document",
    }
}

// ---------------------------------------------------------------------------
// Rich text (upstream `parseZalouserTextStyles`, simplified): Markdown → plain text plus
// zca-js `styles` ranges in UTF-16 units. Inline `**`/`__` bold, `*`/`_` italic, `~~`
// strike, upstream's `{red}…{/red}`-style tags (red, orange, yellow, green, big, small,
// underline); line-level headings (bold + big), `>` quotes (indent), `-`/`*`/`+` and
// `1.` lists (Zalo's own list styles, markers removed); code fences are dropped and their
// lines kept literal; inline code keeps its backticks, as upstream.

/// One zca-js text style range.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Style {
    pub start: usize,
    pub len: usize,
    pub st: &'static str,
    #[serde(rename = "indentSize", skip_serializing_if = "Option::is_none")]
    pub indent_size: Option<u32>,
}

const TAGS: [(&str, &str); 7] = [("red", "c_db342e"), ("orange", "c_f27806"), ("yellow", "c_f7b503"), ("green", "c_15a85f"), ("big", "f_18"), ("small", ""), ("underline", "u")];

fn u16len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn wrap(inner: &str, st: &'static str, out: &mut String, styles: &mut Vec<Style>) {
    let start = u16len(out);
    inline(inner, out, styles);
    let len = u16len(out) - start;
    if len > 0 && !st.is_empty() {
        styles.push(Style { start, len, st, indent_size: None });
    }
}

fn inline(src: &str, out: &mut String, styles: &mut Vec<Style>) {
    let mut i = 0;
    'outer: while i < src.len() {
        let rest = &src[i..];
        if let Some(j) = rest.strip_prefix('`').and_then(|r| r.find('`')) {
            out.push_str(&rest[..j + 2]);
            i += j + 2;
            continue;
        }
        if rest.starts_with('{') {
            for (name, st) in TAGS {
                let (open, close) = (format!("{{{name}}}"), format!("{{/{name}}}"));
                if let Some(j) = rest.strip_prefix(open.as_str()).and_then(|r| r.find(close.as_str())) {
                    wrap(&rest[open.len()..open.len() + j], st, out, styles);
                    i += open.len() + j + close.len();
                    continue 'outer;
                }
            }
        }
        // A run of three delimiters: the first is literal, the rest opens bold (upstream `***x**`).
        if rest.starts_with("***") || rest.starts_with("___") {
            out.push_str(&rest[..1]);
            i += 1;
            continue;
        }
        for (d, st) in [("**", "b"), ("__", "b"), ("~~", "s"), ("*", "i"), ("_", "i")] {
            let Some(after) = rest.strip_prefix(d) else { continue };
            let under = d.starts_with('_');
            if after.chars().next().is_none_or(char::is_whitespace) || (under && src[..i].chars().next_back().is_some_and(char::is_alphanumeric)) {
                continue;
            }
            let close = after.match_indices(d).map(|(k, _)| k).find(|&k| k > 0 && !after[..k].ends_with(char::is_whitespace) && !(under && after[k + d.len()..].starts_with(char::is_alphanumeric)));
            if let Some(k) = close {
                wrap(&after[..k], st, out, styles);
                i += 2 * d.len() + k;
                continue 'outer;
            }
        }
        let c = rest.chars().next().unwrap_or(' ');
        out.push(c);
        i += c.len_utf8();
    }
}

/// Markdown → (text, styles).
pub fn rich_text(md: &str) -> (String, Vec<Style>) {
    let md = md.replace("\r\n", "\n");
    let (mut out, mut styles, mut in_code, mut first) = (String::new(), Vec::new(), false, true);
    for line in md.split('\n') {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        if in_code {
            out.push_str(line);
            continue;
        }
        let t = line.trim_start();
        let hashes = line.len() - line.trim_start_matches('#').len();
        let digits = t.len() - t.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let (body, block): (&str, &[(&'static str, Option<u32>)]) = if (1..=6).contains(&hashes) && (line.len() == hashes || line[hashes..].starts_with(' ')) {
            (line.get(hashes + 1..).unwrap_or(""), &[("b", None), ("f_18", None)])
        } else if let Some(q) = line.strip_prefix('>') {
            (q.strip_prefix(' ').unwrap_or(q), &[("ind_$", Some(1))])
        } else if let Some(b) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).or_else(|| t.strip_prefix("+ ")) {
            (b.trim_start(), &[("lst_1", None)])
        } else if let Some(b) = (digits > 0).then(|| t[digits..].strip_prefix(". ").or_else(|| t[digits..].strip_prefix(") "))).flatten() {
            (b.trim_start(), &[("lst_2", None)])
        } else {
            (line, &[])
        };
        let start = u16len(&out);
        inline(body, &mut out, &mut styles);
        let len = u16len(&out) - start;
        if len > 0 {
            styles.extend(block.iter().map(|&(st, indent_size)| Style { start, len, st, indent_size }));
        }
    }
    (out, styles)
}

/// Split into ≤ `MAX_MESSAGE` pieces, re-basing the style ranges onto each piece.
fn split_styled(text: &str, styles: &[Style]) -> Vec<(String, Vec<Style>)> {
    if u16len(text) <= MAX_MESSAGE {
        return vec![(text.to_string(), styles.to_vec())];
    }
    let mut cur = 0;
    crate::chunk::split(text, MAX_MESSAGE, LenUnit::Utf16)
        .into_iter()
        .map(|piece| {
            let Some(at) = text[cur..].find(piece.as_str()).map(|i| cur + i) else { return (piece, vec![]) };
            let (ps, pe) = (u16len(&text[..at]), u16len(&text[..at + piece.len()]));
            cur = at + piece.len();
            let st = styles
                .iter()
                .filter_map(|s| {
                    let (a, b) = (s.start.max(ps), (s.start + s.len).min(pe));
                    (b > a).then(|| Style { start: a - ps, len: b - a, ..s.clone() })
                })
                .collect();
            (piece, st)
        })
        .collect()
}

fn bridge_get(http: &Http, base: &str, path: &str) -> Result<Value, ChannelError> {
    let r = http.call("GET", &format!("{base}{path}"), &[], Payload::None)?;
    bridge_result(path.split('?').next().unwrap_or(path), &r)
}

/// Agent tool (upstream `createZalouserTool`, its lookup actions): find friends and groups
/// to address (`friends` / `groups` with an optional `query`), the logged-in profile
/// (`me`) and the session state (`status`). Sending stays with `channel_send`.
pub struct ZaloUserTool {
    name: String,
    channel: String,
    base: String,
    http: Http,
}

impl ZaloUserTool {
    fn run(&self, input: &Value) -> Result<String, String> {
        let q = arg_opt_str(input, "query").map(str::trim).filter(|q| !q.is_empty()).map(|q| format!("?query={}", seagent_net::urlencode(q))).unwrap_or_default();
        let path = match arg_opt_str(input, "action").unwrap_or("") {
            "friends" => format!("/friends{q}"),
            "groups" => format!("/groups{q}"),
            "me" => "/me".to_string(),
            "status" => "/health".to_string(),
            other => return Err(format!("unknown action `{other}`; use friends, groups, me or status")),
        };
        let v = bridge_get(&self.http, &self.base, &path).map_err(|e| e.to_string())?;
        Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
    }
}

impl Tool for ZaloUserTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.clone(),
            description: format!("Zalo personal account of channel `{}`: list or search friends (user ids for DMs) and groups (chat `g:<groupId>`), show the logged-in profile, or check the session status.", self.channel),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["friends", "groups", "me", "status"]},
                    "query": {"type": "string", "description": "Filter friends / groups by id or name"}
                },
                "required": ["action"]
            }),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        Vec::new()
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(&input) {
            Ok(s) => ToolOutput::ok(s),
            Err(e) => ToolOutput::err(e),
        }
    }
}

impl Channel for ZaloUser {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            reactions: 1,
            delete: true,
            typing: true,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Utf16,
            markup: Markup::Markdown,
            ..Caps::default()
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let (epoch, after) = self.cursor.lock().unwrap().clone();
        let url = format!("{}/messages?after={after}&epoch={}&wait={}", self.base, seagent_net::urlencode(&epoch), self.poll_timeout);
        let Some(r) = self.get_cancellable(url, cancel)? else { return Ok(vec![]) };
        let v = bridge_result("/messages", &r)?;
        if v["status"].as_str() == Some("logged_out") {
            return Err(ChannelError::new(K::Auth, "zalouser: the Zalo session was logged out; scan a new QR code (GET /qr on the bridge)"));
        }
        if let Some(o) = v["ownId"].as_str().filter(|o| !o.is_empty()) {
            *self.own_id.lock().unwrap() = Some(o.to_string());
        }
        let own = self.own_id.lock().unwrap().clone();
        let events = v["events"].as_array().cloned().unwrap_or_default();
        {
            let mut c = self.cursor.lock().unwrap();
            let new_epoch = v["epoch"].as_str().unwrap_or("").to_string();
            let max = events.iter().filter_map(|e| e["seq"].as_u64()).max();
            if new_epoch != c.0 {
                *c = (new_epoch, max.unwrap_or(0));
            } else if let Some(m) = max {
                c.1 = c.1.max(m);
            }
        }
        let mut out = Vec::new();
        for e in &events {
            if let Some(i) = inbound_of(&self.id, e, own.as_deref()) {
                self.remember(&i.message_id, &s(&e["data"]["cliMsgId"]));
                out.push(i);
            }
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let (thread, is_group) = split_chat(&out.chat);
        let (mut text, styles) = match out.format {
            crate::TextFormat::Markdown => rich_text(&out.text),
            crate::TextFormat::Plain => (out.text.clone(), Vec::new()),
        };
        let mut n = 0;
        for b in out.buttons.iter().flatten() {
            n += 1;
            text.push_str(&match &b.url {
                Some(u) => format!("\n{n}. {} — {u}", b.label),
                None => format!("\n{n}. {}", b.label),
            });
        }
        let mut sent = Sent::default();
        let caption_fits = out.media.len() == 1 && text.encode_utf16().count() <= MAX_MESSAGE;
        for (i, m) in out.media.iter().enumerate() {
            let mut body = json!({"threadId": thread, "isGroup": is_group, "kind": media_kind(m.kind)});
            match (&m.path, &m.url) {
                (Some(p), _) => body["path"] = json!(p),
                (None, Some(u)) => body["url"] = json!(u),
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            }
            if !m.name.is_empty() {
                body["filename"] = json!(m.name);
            }
            let own = (caption_fits && i == 0).then_some(text.as_str()).filter(|t| !t.is_empty());
            if let Some(c) = own.or(m.caption.as_deref()) {
                body["caption"] = json!(c);
            }
            if own.is_some() && !styles.is_empty() {
                body["styles"] = json!(styles);
            }
            if let (0, Some(r)) = (i, &out.reply_to) {
                body["replyTo"] = json!(r);
            }
            let r = self.post("/send-media", &body)?;
            sent.ids.push(s(&r["msgId"]));
        }
        if caption_fits {
            return Ok(sent);
        }
        for (i, (piece, st)) in split_styled(&text, &styles).into_iter().enumerate() {
            let mut body = json!({"threadId": thread, "isGroup": is_group, "text": piece});
            if !st.is_empty() {
                body["styles"] = json!(st);
            }
            if let (0, true, Some(r)) = (i, out.media.is_empty(), &out.reply_to) {
                body["replyTo"] = json!(r);
            }
            let r = self.post("/send", &body)?;
            sent.ids.push(s(&r["msgId"]));
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        let (thread, is_group) = split_chat(chat);
        self.post("/typing", &json!({"threadId": thread, "isGroup": is_group})).map(|_| ())
    }

    /// Our own messages are recalled (zca-js `undo`); other people's only in groups
    /// where we are an admin (`deleteMessage` for everyone). The bridge decides.
    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let (thread, is_group) = split_chat(chat);
        self.post("/delete", &json!({"threadId": thread, "isGroup": is_group, "msgId": message_id})).map(|_| ())
    }

    fn tools(&self) -> Vec<Arc<dyn Tool>> {
        let safe: String = self.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
        let name = if safe == "zalouser" { safe } else { format!("zalouser_{safe}") };
        vec![Arc::new(ZaloUserTool { name, channel: self.id.clone(), base: self.base.clone(), http: self.http.clone() })]
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let (thread, is_group) = split_chat(chat);
        let cli = self.cli.lock().unwrap().0.get(message_id).cloned().ok_or_else(|| ChannelError::new(K::NotFound, format!("zalouser: message {message_id} is not known (reactions need its cliMsgId)")))?;
        self.post("/react", &json!({"threadId": thread, "isGroup": is_group, "msgId": message_id, "cliMsgId": cli, "icon": reaction_icon(emoji), "remove": remove})).map(|_| ())
    }

    fn stop(&self) {
        if let Some(sup) = &self.sup {
            sup.stop.store(true, Ordering::SeqCst);
            if let Some(mut c) = sup.child.lock().unwrap().take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

fn d_poll() -> u64 {
    25
}

fn d_bridge() -> String {
    DEFAULT_BRIDGE.into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Shared bearer secret between seagent and the sidecar.
    token: String,
    #[serde(default = "d_bridge")]
    bridge_url: String,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Supervise the sidecar: e.g. ["node", "/opt/seagent/bridges/zalouser/bridge.mjs"].
    #[serde(default)]
    command: Option<Vec<String>>,
    /// Where the sidecar keeps its cookies (default: the channel's state dir).
    #[serde(default)]
    data_dir: Option<String>,
    /// zca-js profile name inside the data dir.
    #[serde(default)]
    profile: Option<String>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let u = seagent_net::Url::parse(&st.bridge_url).map_err(|e| format!("channel {}: bridge_url: {e}", ctx.name))?;
    let mut z = ZaloUser::new(ctx.name, &st.bridge_url, &token, st.poll_timeout_secs)?;
    if let Some(cmd) = &st.command {
        let data = st.data_dir.clone().unwrap_or_else(|| ctx.state("zalouser").display().to_string());
        let env = vec![
            ("ZALOUSER_BRIDGE_TOKEN".to_string(), token.clone()),
            ("ZALOUSER_BRIDGE_PORT".to_string(), u.port.to_string()),
            ("ZALOUSER_DATA_DIR".to_string(), data),
            ("ZALOUSER_PROFILE".to_string(), st.profile.clone().unwrap_or_else(|| "default".into())),
        ];
        z = z.supervise(cmd, env)?;
    }
    Ok(Arc::new(z))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    fn zu(url: &str) -> ZaloUser {
        ZaloUser::new("zu", url, "BRIDGE-SECRET", 1).unwrap()
    }

    fn ev(seq: u64, ty: i64, thread: &str, data: Value) -> Value {
        json!({"seq": seq, "kind": "message", "type": ty, "threadId": thread, "isSelf": false, "data": data})
    }

    fn events() -> Vec<Value> {
        vec![
            ev(1, 0, "u1", json!({"msgId": "m1", "cliMsgId": "c1", "uidFrom": "u1", "idTo": "ME", "dName": "Amy", "ts": "1700000000123", "msgType": "webchat", "content": "xin chào"})),
            ev(2, 1, "G1", json!({"msgId": "m2", "cliMsgId": "c2", "uidFrom": "u2", "idTo": "G1", "groupName": "Team", "msgType": "webchat", "content": "@Seagent /status", "mentions": [{"uid": "ME", "pos": 0, "len": 8}]})),
            ev(3, 1, "G1", json!({"msgId": "m3", "cliMsgId": "c3", "uidFrom": "u2", "msgType": "webchat", "content": "yes", "quote": {"ownerId": "ME", "globalMsgId": 99, "msg": "shall I?"}})),
            ev(4, 0, "u1", json!({"msgId": "m4", "cliMsgId": "c4", "uidFrom": "u1", "msgType": "chat.photo", "content": {"href": "https://f.zdn.vn/p.jpg", "title": "look", "thumb": "https://f.zdn.vn/t.jpg"}})),
            ev(5, 0, "u1", json!({"msgId": "m5", "cliMsgId": "c5", "uidFrom": "u1", "msgType": "share.file", "content": {"href": "https://f.zdn.vn/r.pdf", "title": "r.pdf", "params": "{\"fileSize\":\"1234\"}"}})),
            ev(6, 0, "u1", json!({"msgId": "m6", "cliMsgId": "c6", "uidFrom": "u1", "msgType": "chat.recommended", "content": {"title": "Seagent", "description": "agent", "href": "https://seagent.dev"}})),
            ev(7, 1, "G1", json!({"msgId": "m7", "uidFrom": "ME", "msgType": "webchat", "content": "own echo"})),
            json!({"seq": 8, "kind": "message", "type": 0, "threadId": "u1", "isSelf": true, "data": {"msgId": "m8", "uidFrom": "ME", "content": "self"}}),
            ev(9, 0, "u1", json!({"msgId": "m9", "uidFrom": "u1", "msgType": "chat.voice", "content": {"href": "https://f.zdn.vn/v.aac"}})),
        ]
    }

    #[test]
    fn polls_events_with_cursor_and_parses_every_kind() {
        let srv = FakeServer::start(|req, n| {
            assert_eq!(req.header("authorization"), Some("Bearer BRIDGE-SECRET"));
            match n {
                0 => (200, vec![], json!({"epoch": "E1", "ownId": "ME", "events": events()}).to_string()),
                1 => (200, vec![], json!({"epoch": "E1", "events": []}).to_string()),
                // Bridge restarted: new epoch, seq starts over.
                _ => (200, vec![], json!({"epoch": "E2", "events": [ev(1, 0, "u1", json!({"msgId": "n1", "uidFrom": "u1", "content": "after restart"}))]}).to_string()),
            }
        });
        let z = zu(&srv.url);
        let g = z.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 7, "own and isSelf dropped");
        assert_eq!((g[0].chat.as_str(), g[0].sender.as_str(), g[0].sender_name.as_str(), g[0].message_id.as_str(), g[0].ts, g[0].chat_type), ("u1", "u1", "Amy", "m1", 1700000000, ChatType::Direct));
        assert!(g[1].mentioned && g[1].chat == "g:G1" && g[1].chat_name == "Team" && g[1].chat_type == ChatType::Group);
        assert_eq!(g[1].text, "/status", "own mention stripped");
        let r = g[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "99" && r.text == "shall I?" && g[2].addressed() && !g[2].mentioned);
        assert_eq!((g[3].media[0].kind, g[3].media[0].url.as_deref(), g[3].text.as_str()), (MediaKind::Image, Some("https://f.zdn.vn/p.jpg"), "look"));
        assert_eq!((g[4].media[0].kind, g[4].media[0].name.as_str(), g[4].media[0].size), (MediaKind::Document, "r.pdf", 1234));
        assert_eq!(g[5].text, "Seagent\nagent\nhttps://seagent.dev");
        assert_eq!(g[6].media[0].kind, MediaKind::Voice);
        assert!(z.poll(&Cancel::new()).unwrap().is_empty());
        let g = z.poll(&Cancel::new()).unwrap();
        assert_eq!(g[0].text, "after restart");
        let paths: Vec<String> = srv.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, ["/messages?after=0&epoch=&wait=1", "/messages?after=9&epoch=E1&wait=1", "/messages?after=9&epoch=E1&wait=1"]);
        assert_eq!(*z.cursor.lock().unwrap(), ("E2".to_string(), 1));
    }

    #[test]
    fn send_shapes_replies_media_typing_and_reactions() {
        let srv = FakeServer::start(|req, n| {
            if req.path == "/messages?after=0&epoch=&wait=1" {
                return (200, vec![], json!({"epoch": "E", "ownId": "ME", "events": events()}).to_string());
            }
            (200, vec![], json!({"msgId": format!("s{n}")}).to_string())
        });
        let z = zu(&srv.url);
        z.poll(&Cancel::new()).unwrap();
        let out = Outbound {
            format: crate::TextFormat::Markdown,
            reply_to: Some("m2".into()),
            buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]],
            ..Outbound::text("g:G1", "**hi**")
        };
        assert_eq!(z.send(&out).unwrap().ids, ["s1"]);
        let r = srv.requests()[1].clone();
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/send", Some("Bearer BRIDGE-SECRET")));
        assert_eq!(r.json(), json!({"threadId": "G1", "isGroup": true, "text": "hi\n1. Yes", "replyTo": "m2", "styles": [{"start": 0, "len": 2, "st": "b"}]}));
        let f = temp_dir("zu").join("a.ogg");
        std::fs::write(&f, b"OGG").unwrap();
        let voice = Media { kind: MediaKind::Voice, path: Some(f.display().to_string()), ..Default::default() };
        z.send(&Outbound { media: vec![voice], ..Outbound::text("u1", "listen") }).unwrap();
        let r = srv.requests()[2].clone();
        assert_eq!(r.path, "/send-media");
        assert_eq!(r.json(), json!({"threadId": "u1", "isGroup": false, "kind": "audio", "path": f.display().to_string(), "caption": "listen"}));
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        let long = "x".repeat(2500);
        let s = z.send(&Outbound { media: vec![img], ..Outbound::text("u1", &long) }).unwrap();
        assert_eq!(s.ids.len(), 3, "media without caption, then two text pieces");
        assert!(srv.requests()[3].json().get("caption").is_none());
        assert_eq!(srv.requests()[3].json()["url"], "https://e.com/a.png");
        z.typing("g:G1", None).unwrap();
        assert_eq!(srv.requests().last().unwrap().json(), json!({"threadId": "G1", "isGroup": true}));
        z.react("u1", "m1", "❤️", false).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/react");
        assert_eq!(r.json(), json!({"threadId": "u1", "isGroup": false, "msgId": "m1", "cliMsgId": "c1", "icon": "/-heart", "remove": false}));
        assert_eq!(z.react("u1", "unknown", "👍", false).unwrap_err().kind, K::NotFound);
        assert_eq!(z.edit("u1", "m1", "x").unwrap_err().kind, K::Unsupported);
        z.delete("g:G1", "s1").unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!((r.path.as_str(), r.json()), ("/delete", json!({"threadId": "G1", "isGroup": true, "msgId": "s1"})));
        // Plain text is sent as is, without styles.
        z.send(&Outbound::text("u1", "**raw**")).unwrap();
        assert_eq!(srv.requests().last().unwrap().json(), json!({"threadId": "u1", "isGroup": false, "text": "**raw**"}));
        assert_eq!(reaction_icon("😂"), ":>");
        assert_eq!(reaction_icon("/-ok"), "/-ok");
    }

    fn st(start: usize, len: usize, st: &'static str) -> Style {
        Style { start, len, st, indent_size: None }
    }

    #[test]
    fn markdown_to_zalo_styles() {
        assert_eq!(rich_text("\n**x**"), ("\nx".into(), vec![st(1, 1, "b")]));
        assert_eq!(rich_text("before `inline *code*` after\n2 * 3 * 4"), ("before `inline *code*` after\n2 * 3 * 4".into(), vec![]));
        assert_eq!(rich_text("***bold**"), ("*bold".into(), vec![st(1, 4, "b")]));
        assert_eq!(rich_text("__foo_bar__"), ("foo_bar".into(), vec![st(0, 7, "b")]));
        assert_eq!(rich_text("snake_case_name"), ("snake_case_name".into(), vec![]));
        assert_eq!(rich_text("[**label**](https://example.com)"), ("[label](https://example.com)".into(), vec![st(1, 5, "b")]));
        let (t, s) = rich_text("# Title\n> quoted\n  - nested\n2. two");
        assert_eq!(t, "Title\nquoted\nnested\ntwo");
        assert_eq!(s, vec![st(0, 5, "b"), st(0, 5, "f_18"), Style { start: 6, len: 6, st: "ind_$", indent_size: Some(1) }, st(13, 6, "lst_1"), st(20, 3, "lst_2")]);
        assert_eq!(rich_text("```\ncode *x*\n\n```\n**next**"), ("code *x*\n\nnext".into(), vec![st(10, 4, "b")]));
        // UTF-16 offsets, tags and strike-through.
        assert_eq!(rich_text("😀 {red}đỏ{/red} ~~x~~ {small}s{/small}"), ("😀 đỏ x s".into(), vec![st(3, 2, "c_db342e"), st(6, 1, "s")]));
        assert_eq!(serde_json::to_value(Style { start: 0, len: 1, st: "ind_$", indent_size: Some(1) }).unwrap(), json!({"start": 0, "len": 1, "st": "ind_$", "indentSize": 1}));
        // Long text: styles are cut and re-based per piece.
        let long = format!("**{}end** tail", "word ".repeat(500));
        let (t, s) = rich_text(&long);
        let parts = split_styled(&t, &s);
        assert!(parts.len() >= 2);
        assert_eq!(parts[0].1, vec![st(0, u16len(&parts[0].0).min(2499), "b")]);
        assert_eq!(parts[1].1[0].start, 0);
        assert!(parts.iter().all(|(p, ss)| ss.iter().all(|x| x.start + x.len <= u16len(p))));
    }

    #[test]
    fn tool_lists_friends_groups_profile_and_status() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/friends?query=amy%20n" => (200, vec![], json!([{"userId": "u1", "displayName": "Amy N"}]).to_string()),
            "/groups" => (200, vec![], json!([{"groupId": "G1", "name": "Team", "memberCount": 3}]).to_string()),
            "/me" => (200, vec![], json!({"userId": "ME", "displayName": "Seagent"}).to_string()),
            "/health" => (200, vec![], json!({"status": "logged_in"}).to_string()),
            _ => (409, vec![], json!({"error": "not_logged_in"}).to_string()),
        });
        let z = ZaloUser::new("zalo-home", &srv.url, "BRIDGE-SECRET", 1).unwrap();
        let tools = z.tools();
        assert_eq!(tools[0].spec().name, "zalouser_zalo-home");
        let t = ZaloUserTool { name: "zalouser".into(), channel: "zu".into(), base: srv.url.clone(), http: z.http.clone() };
        let v: Value = serde_json::from_str(&t.run(&json!({"action": "friends", "query": " amy n "})).unwrap()).unwrap();
        assert_eq!(v[0]["userId"], "u1");
        assert!(t.run(&json!({"action": "groups", "query": ""})).unwrap().contains("Team"));
        assert!(t.run(&json!({"action": "me"})).unwrap().contains("\"ME\""));
        assert!(t.run(&json!({"action": "status"})).unwrap().contains("logged_in"));
        assert!(t.run(&json!({"action": "send"})).unwrap_err().contains("unknown action"));
        assert_eq!(srv.requests()[0].header("authorization"), Some("Bearer BRIDGE-SECRET"));
        let srv2 = FakeServer::start(|_, _| (409, vec![], json!({"error": "not_logged_in"}).to_string()));
        let t2 = ZaloUserTool { base: srv2.url.clone(), ..t };
        assert!(t2.run(&json!({"action": "friends"})).unwrap_err().contains("not_logged_in"));
    }

    #[test]
    fn bridge_errors_map_to_kinds() {
        for (status, body, kind) in [
            (401, json!({"error": "unauthorized"}), K::Auth),
            (409, json!({"error": "not_logged_in"}), K::Auth),
            (404, json!({"error": "no such route"}), K::NotFound),
            (502, json!({"error": "User blocked you"}), K::NotFound),
            (502, json!({"error": "socket hang up"}), K::Network),
            (429, json!({"error": "slow"}), K::RateLimited { retry_after: Some(Duration::from_secs(7)) }),
            (400, json!({"error": "threadId required"}), K::Protocol),
        ] {
            let srv = FakeServer::start(move |_, _| (status, vec![("Retry-After".into(), "7".into())], body.to_string()));
            let e = zu(&srv.url).send(&Outbound::text("u1", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains("BRIDGE-SECRET"));
        }
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"epoch": "E", "status": "logged_out", "events": []}).to_string()));
        assert_eq!(zu(&srv.url).poll(&Cancel::new()).unwrap_err().kind, K::Auth);
        let srv = FakeServer::start(|req, _| (200, vec![], json!({"status": if req.path == "/qr" { "qr_pending" } else { "ok" }, "qr": "data:image/png;base64,AAA"}).to_string()));
        assert_eq!(zu(&srv.url).qr().unwrap()["status"], "qr_pending");
        assert_eq!(zu(&srv.url).health().unwrap()["status"], "ok");
        assert_eq!(zu("http://127.0.0.1:1").poll(&Cancel::new()).unwrap_err().kind, K::Network);
        assert!(ZaloUser::new("z", "http://x", " ", 1).is_err());
    }

    #[test]
    fn cancel_interrupts_a_blocked_poll() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let z = zu(&url);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = std::time::Instant::now();
        assert!(z.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(z.cursor.lock().unwrap().1, 0, "cursor untouched by an abandoned poll");
    }

    #[cfg(unix)]
    #[test]
    fn supervises_restarts_and_stops_the_sidecar() {
        let d = temp_dir("zu");
        let log = d.join("starts");
        // Stub sidecar: record the token, live briefly, exit → supervisor restarts it.
        let script = format!("echo \"$ZALOUSER_BRIDGE_TOKEN $ZALOUSER_BRIDGE_PORT\" >> {}; sleep 0.3", log.display());
        let cmd = vec!["sh".to_string(), "-c".to_string(), script];
        let z = zu("http://127.0.0.1:3999").supervise(&cmd, vec![("ZALOUSER_BRIDGE_TOKEN".into(), "BRIDGE-SECRET".into()), ("ZALOUSER_BRIDGE_PORT".into(), "3999".into())]).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(&log).unwrap_or_default().lines().count() < 2 && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let starts = std::fs::read_to_string(&log).unwrap();
        assert!(starts.lines().count() >= 2, "restarted after exit: {starts}");
        assert!(starts.lines().all(|l| l == "BRIDGE-SECRET 3999"));
        z.stop();
        let n = std::fs::read_to_string(&log).unwrap().lines().count();
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), n, "no restarts after stop");
        // A long-running child is killed by stop().
        let z = zu("http://127.0.0.1:3999").supervise(&["sleep".to_string(), "30".to_string()], vec![]).unwrap();
        let pid = z.sup.as_ref().unwrap().child.lock().unwrap().as_ref().unwrap().id() as i32;
        z.stop();
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "child gone");
        assert!(zu("http://x").supervise(&["/nonexistent/zalouser-bridge".to_string()], vec![]).is_err());
    }
}
