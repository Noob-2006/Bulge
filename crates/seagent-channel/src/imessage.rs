//! iMessage through `imsg` (kinds `imessage`, `imsg`; ported from OpenClaw
//! `extensions/imessage`, MIT).
//!
//! seagent spawns `imsg rpc --json [--db <chat.db>]` and speaks its line-delimited
//! JSON-RPC 2.0 over stdio exactly as OpenClaw's `client.ts`: requests
//! `{jsonrpc, id, method, params}`, responses matched by id, notifications
//! (`method: "message"` with `params.message`, `method: "error"`). After every
//! (re)start it calls `watch.subscribe {attachments}`. Send uses `send`
//! (`to` / `chat_id` / `chat_guid` / `chat_identifier`, `text`, `service`,
//! `reply_to`, `file`) and `send.attachment`; `message.edit`,
//! `message.unsend`, `tapback` (reactions), `typing`, `chats.list`.
//! The child is supervised: restart with backoff when it exits, process-group
//! kill on drop, `PR_SET_PDEATHSIG` on Linux. imsg itself is macOS-only.
//!
//! Chats: the chat GUID when imsg reports one (`iMessage;-;+886…`,
//! `iMessage;+;chat…`), else `chat_id:<n>`, else the sender handle.
//! Message ids are message GUIDs. Own messages (`is_from_me`) and tapbacks are
//! dropped; `reply_to_guid` / `thread_originator_guid` become replies.
//!
//! Catch-up (OpenClaw `monitor/recovery-cursor.ts`): the highest delivered
//! chat.db rowid is persisted per database identity and every
//! `watch.subscribe` passes `since_rowid`, so imsg replays what arrived while
//! seagent was down; replayed rows older than `catchup_max_age_minutes` are
//! dropped and GUIDs are de-duplicated. The cursor commits on the next poll.
//! Private API (`probe.ts`): `imsg status --json` decides whether the bridge
//! is up (`advanced_features && v2_ready`) and which `rpc_methods` exist;
//! edit / unsend / tapback fail Unsupported with imsg's reason when it is not,
//! typing is skipped, replies go out plain.
//! Remote host (`remote-host.ts`, `remote-file.ts`): `cli` may be an ssh
//! wrapper (`exec ssh [-T] host imsg "$@"`, host detected) or `remote_host`
//! set; outbound files are staged with ssh + scp into a private
//! `/tmp/seagent-imessage-<random>` on the Mac and removed afterwards, inbound
//! attachments are fetched with scp.

use crate::whatsapp::{expand_home, Attach, ChildSpec, Supervisor};
use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ChildStdin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 8000;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// An unavailable bridge is re-probed after this long (`imsg launch` may fix it).
const PROBE_RETRY: Duration = Duration::from_secs(60);
const SCP_TIMEOUT: Duration = Duration::from_secs(120);

type Pending = Arc<Mutex<HashMap<u64, Sender<Result<Value, Value>>>>>;

/// The live stdio connection to the current imsg child.
#[derive(Default)]
struct Conn {
    stdin: Mutex<Option<ChildStdin>>,
    pending: Pending,
    next: AtomicU64,
    /// Bumped on every (re)start.
    generation: AtomicU64,
}

impl Conn {
    fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, ChannelError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = channel();
        self.pending.lock().unwrap().insert(id, tx);
        let line = format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let wrote = {
            let mut g = self.stdin.lock().unwrap();
            match g.as_mut() {
                Some(s) => s.write_all(line.as_bytes()).and_then(|_| s.flush()).is_ok(),
                None => false,
            }
        };
        if !wrote {
            self.pending.lock().unwrap().remove(&id);
            return Err(ChannelError::new(K::Network, "imsg rpc not running"));
        }
        match rx.recv_timeout(timeout) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(rpc_err(method, &e)),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(ChannelError::new(K::Network, format!("imsg rpc timeout ({method})")))
            }
        }
    }
}

fn rpc_err(method: &str, e: &Value) -> ChannelError {
    let msg = e["message"].as_str().unwrap_or("imsg rpc error");
    let data = match &e["data"] {
        Value::Null => String::new(),
        Value::String(s) => format!(": {s}"),
        d => format!(": {d}"),
    };
    let text = crate::sms::redact_phones_in(&format!("imsg {method}: {msg}{data}"));
    let low = text.to_ascii_lowercase();
    let kind = if low.contains("full disk access") || low.contains("not permitted") || low.contains("authorization denied") {
        K::Fatal
    } else if e["code"].as_i64() == Some(-32601) || low.contains("requires bridge") || low.contains("private api") || low.contains("not supported") {
        K::Unsupported
    } else if low.contains("not found") || low.contains("unknown chat") || low.contains("no such") {
        K::NotFound
    } else if low.contains("timeout") || low.contains("timed out") || low.contains("closed") {
        K::Network
    } else {
        K::Protocol
    };
    ChannelError::new(kind, text)
}

/// `2024-05-01T10:00:00.123Z` / `+08:00` → unix seconds.
pub(crate) fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', ' '])?;
    let mut d = date.split('-').map(|p| p.parse::<i64>());
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let tz_at = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (time, tz) = rest.split_at(tz_at);
    let mut t = time.split(':');
    let (h, mi) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let sec = t.next().map(|x| x.split('.').next().unwrap_or("0").parse::<i64>().unwrap_or(0)).unwrap_or(0);
    let off = match tz.chars().next() {
        Some(c @ ('+' | '-')) => {
            let z = tz[1..].replace(':', "");
            let (oh, om) = (z.get(0..2)?.parse::<i64>().ok()?, z.get(2..4).unwrap_or("0").parse::<i64>().unwrap_or(0));
            let o = oh * 3600 + om * 60;
            if c == '+' { o } else { -o }
        }
        _ => 0,
    };
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + sec - off)
}

/// Emoji → tapback kind.
fn tapback_kind(emoji: &str) -> String {
    match emoji.trim_end_matches('\u{fe0f}') {
        "❤" | "♥" | "😍" | "love" => "love",
        "👍" | "like" => "like",
        "👎" | "dislike" => "dislike",
        "😂" | "🤣" | "😆" | "laugh" => "laugh",
        "‼" | "❗" | "!!" | "emphasize" => "emphasize",
        "❓" | "?" | "question" => "question",
        other => return other.to_string(),
    }
    .to_string()
}

fn kind_of(mime: &str) -> MediaKind {
    match mime.split('/').next().unwrap_or("") {
        "image" if mime.contains("gif") => MediaKind::Animation,
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Voice,
        _ => MediaKind::Document,
    }
}

// ---------------------------------------------------------------- remote host

/// OpenClaw `remote-file.ts` ssh/scp options.
const SSH_OPTIONS: [&str; 12] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no"];

fn ssh_token(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `[user@]host` safe for the ssh/scp host position (OpenClaw `normalizeScpRemoteHost`).
pub(crate) fn normalize_scp_host(v: &str) -> Option<String> {
    let t = v.trim();
    if t.is_empty() || t.chars().any(|c| c.is_ascii_control() || c.is_whitespace()) || t.starts_with('-') {
        return None;
    }
    let (user, host) = match t.split_once('@') {
        Some((u, h)) if !h.contains('@') && !u.is_empty() && !h.is_empty() => (Some(u), h),
        Some(_) => return None,
        None => (None, t),
    };
    if user.is_some_and(|u| !ssh_token(u)) {
        return None;
    }
    let v6 = host.len() > 2 && host.starts_with('[') && host.ends_with(']') && host[1..host.len() - 1].chars().all(|c| c.is_ascii_hexdigit() || ":.%".contains(c));
    if host.starts_with('-') || (!ssh_token(host) && !v6) {
        return None;
    }
    Some(t.to_string())
}

/// Remote attachment path safe for scp: absolute (or `~/…`, relative to the
/// remote home), no control or shell metacharacters.
pub(crate) fn normalize_scp_path(v: &str) -> Option<String> {
    let t = v.trim();
    let p = t.strip_prefix("~/").unwrap_or(t);
    let ok = (t.starts_with('/') || t.starts_with("~/")) && !p.is_empty() && !p.chars().any(|c| c.is_control() || "\\'\"`$;|&<>".contains(c));
    ok.then(|| p.to_string())
}

fn unwrap_exec_token(t: &str) -> Option<&str> {
    let b = t.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        return Some(&t[1..t.len() - 1]);
    }
    (!t.contains(['"', '\''])).then_some(t)
}

fn is_exec(t: &str, name: &str) -> bool {
    unwrap_exec_token(t).is_some_and(|e| e == name || (e.starts_with('/') && e.rsplit('/').next() == Some(name)))
}

/// Conservative token scan (`"…"`, `'…'`, or runs without shell punctuation).
fn scan_tokens(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            if let Some(j) = s[i + 1..].find([c as char, '\r', '\n']) {
                if b[i + 1 + j] == c {
                    out.push(&s[i..i + j + 2]);
                    i += j + 2;
                    continue;
                }
            }
            i += 1;
        } else if c.is_ascii_whitespace() || b"`;&|()<>\\".contains(&c) {
            i += 1;
        } else {
            let j = s[i..].find(|x: char| x.is_whitespace() || "\"'`;&|()<>\\".contains(x)).map(|j| i + j).unwrap_or(s.len());
            out.push(&s[i..j]);
            i = j;
        }
    }
    out
}

fn looks_like_ssh_wrapper(content: &str) -> bool {
    scan_tokens(content).iter().any(|t| is_exec(t, "ssh"))
}

/// Whitespace-separated words of the form `"[^"]+"`, `'[^']+'` or `[^\s"']+`.
fn shell_words(line: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        let end = match rest.as_bytes()[0] {
            q @ (b'"' | b'\'') => rest[1..].find(q as char).filter(|j| *j > 0)? + 2,
            _ => rest.find(char::is_whitespace).unwrap_or(rest.len()),
        };
        let w = &rest[..end];
        if !w.starts_with(['"', '\'']) && w.contains(['"', '\'']) {
            return None;
        }
        if rest[end..].chars().next().is_some_and(|c| !c.is_whitespace()) {
            return None;
        }
        out.push(w);
        rest = rest[end..].trim_start();
    }
    Some(out)
}

/// Host of a transparent ssh wrapper `cli` (OpenClaw `parseRemoteHost`):
/// `Ok(Some(host))` for `exec ssh [-T] <host> imsg "$@"`, `Ok(None)` when the
/// file is not an ssh wrapper, `Err` when it calls ssh in any other shape.
pub(crate) fn parse_remote_host(content: &str) -> Result<Option<String>, ()> {
    let ambiguous = || if looks_like_ssh_wrapper(content) { Err(()) } else { Ok(None) };
    if content.contains("\\\n") || content.contains("\\\r\n") {
        return ambiguous();
    }
    let mut lines: Vec<&str> = content.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.first().is_some_and(|l| l.starts_with("#!")) {
        lines.remove(0);
    }
    if lines.len() != 1 {
        return ambiguous();
    }
    let Some(w) = shell_words(lines[0]) else { return ambiguous() };
    let (ssh, dest, imsg) = match w.as_slice() {
        ["exec", s, "-T", d, i, "\"$@\""] | ["exec", s, d, i, "\"$@\""] => (*s, *d, *i),
        _ => return ambiguous(),
    };
    if !is_exec(ssh, "ssh") || !is_exec(imsg, "imsg") {
        return ambiguous();
    }
    normalize_scp_host(dest).map(Some).ok_or(())
}

/// Configured `remote_host`, else the host of an ssh-wrapper `cli`.
pub(crate) fn resolve_remote_host(cli: &str, configured: Option<&str>) -> Result<Option<String>, String> {
    if let Some(c) = configured.map(str::trim).filter(|c| !c.is_empty()) {
        return normalize_scp_host(c).map(Some).ok_or_else(|| format!("remote_host {c:?} is not a safe [user@]host"));
    }
    let path = expand_home(cli.trim());
    if !path.to_string_lossy().contains('/') {
        return Ok(None);
    }
    match std::fs::read(&path) {
        // A binary (Mach-O / ELF) is never a wrapper.
        Ok(b) => match std::str::from_utf8(&b) {
            Ok(s) => parse_remote_host(s).map_err(|_| "the cli ssh wrapper is not the simple `exec ssh [-T] host imsg \"$@\"` form; set remote_host explicitly".to_string()),
            Err(_) => Ok(None),
        },
        Err(_) => Ok(None),
    }
}

/// Run argv (never a shell) with optional stdin; `(exit code, stdout, stderr)`.
fn run(argv: &[String], stdin: Option<&str>, timeout: Duration) -> Result<(i32, String, String), String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut cmd = seagent_core::platform::layout::program_command(&argv[0]);
    cmd.args(&argv[1..]).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("cannot run {}: {e}", argv[0]))?;
    if let (Some(t), Some(mut si)) = (stdin, child.stdin.take()) {
        let _ = si.write_all(t.as_bytes());
    }
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let he = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let until = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{} timed out", argv[0]));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok((status.code().unwrap_or(-1), ho.join().unwrap_or_default(), he.join().unwrap_or_default()))
}

fn safe_file_name(p: &str) -> String {
    let n: String = crate::line::file_name(p).chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    if n.trim_matches(['.', '_']).is_empty() { "file".into() } else { n }
}

// ---------------------------------------------------------------- private API

/// `imsg status --json` (OpenClaw `probeIMessagePrivateApi`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PrivateApi {
    /// Exit 0, `advanced_features` and `v2_ready`.
    pub available: bool,
    pub rpc_methods: Vec<String>,
    /// imsg's explanation when the bridge is off (SIP, library validation…).
    pub message: Option<String>,
    pub error: Option<String>,
}

/// Methods every imsg rpc had before `rpc_methods` was reported.
const FOUNDATIONAL_RPC: [&str; 5] = ["chats.list", "messages.history", "watch.subscribe", "watch.unsubscribe", "send"];

impl PrivateApi {
    pub fn supports(&self, method: &str) -> bool {
        self.available && if self.rpc_methods.is_empty() { FOUNDATIONAL_RPC.contains(&method) } else { self.rpc_methods.iter().any(|m| m == method) }
    }

    pub fn probe(cli: &str, timeout: Duration) -> PrivateApi {
        let argv = vec![expand_home(cli.trim()).display().to_string(), "status".into(), "--json".into()];
        let (code, out, err) = match run(&argv, None, timeout) {
            Ok(r) => r,
            Err(e) => return PrivateApi { error: Some(e), ..Default::default() },
        };
        let combined = format!("{out}\n{err}").trim().to_lowercase();
        if code != 0 && combined.contains("unknown subcommand") && combined.contains("status") {
            return PrivateApi { error: Some("imsg CLI has no `status` subcommand; update imsg on the Messages Mac".into()), ..Default::default() };
        }
        let payload = out.lines().rev().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok()).find(Value::is_object);
        let p = payload.clone().unwrap_or_default();
        let rpc_methods = p["rpc_methods"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
        let error = if code != 0 {
            Some(crate::sms::redact_phones_in(&format!("imsg status --json failed (code {code}): {}", format!("{out}\n{err}").trim())).chars().take(300).collect())
        } else if payload.is_none() {
            Some("imsg status --json returned no parseable JSON".into())
        } else {
            None
        };
        PrivateApi { available: code == 0 && p["advanced_features"] == true && p["v2_ready"] == true, rpc_methods, message: p["message"].as_str().map(str::to_string), error }
    }
}

// ---------------------------------------------------------------- catch-up cursor

/// Watch replay after downtime (OpenClaw `recovery-cursor.ts`): the highest
/// delivered chat.db rowid per (channel, database) seeds `since_rowid`.
#[derive(Default)]
struct Cursor {
    path: PathBuf,
    /// Database identity; a cursor from another chat.db is never reused.
    db: String,
    committed: Option<i64>,
    /// Highest rowid handed to the caller, committed on the next poll.
    pending: Option<i64>,
    /// Highest rowid received from the current process (in-process restarts).
    seen: Option<i64>,
}

impl Cursor {
    fn load(path: PathBuf, db: String) -> Cursor {
        let v: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let committed = if v["db"].as_str() == Some(db.as_str()) { v["last_rowid"].as_i64() } else { None };
        Cursor { path, db, committed, pending: None, seen: None }
    }

    /// `since_rowid` for watch.subscribe; imsg reserves 0 for "tail from now".
    fn since(&self) -> Option<i64> {
        self.seen.max(self.committed).map(|s| if s == 0 { -1 } else { s })
    }

    fn commit(&mut self) {
        let Some(p) = self.pending.take() else { return };
        if self.committed.is_some_and(|c| c >= p) {
            return;
        }
        self.committed = Some(p);
        let _ = crate::write_atomic(&self.path, json!({"db": self.db, "last_rowid": p}).to_string().as_bytes());
    }
}

/// OpenClaw `resolveIMessageRecoveryCursorDbIdentity`.
fn db_identity(cli: &str, db: Option<&str>, remote: Option<&str>) -> String {
    let db = db.map(str::trim).filter(|d| !d.is_empty());
    if let Some(h) = remote {
        return format!("remote:{h}:{}", db.unwrap_or("default"));
    }
    if let Some(d) = db {
        return format!("local:{}", expand_home(d).display());
    }
    let cli = cli.trim();
    if cli.is_empty() || cli == "imsg" || cli.rsplit('/').next() == Some("imsg") {
        return format!("local:{}", expand_home("~/Library/Messages/chat.db").display());
    }
    format!("local:cli:{cli}")
}

pub struct IMessage {
    id: String,
    cli: String,
    /// `[user@]host` of the Messages Mac when imsg runs over ssh.
    pub remote: Option<String>,
    pub ssh: String,
    pub scp: String,
    papi: Arc<Mutex<Option<(PrivateApi, Instant)>>>,
    cursor: Arc<Mutex<Cursor>>,
    /// Drop (replayed) messages older than this.
    max_age: Option<Duration>,
    recent: Mutex<VecDeque<String>>,
    conn: Arc<Conn>,
    sup: Supervisor,
    service: String,
    mention: Vec<String>,
    poll_timeout: u64,
    pub timeout: Duration,
    rx: Mutex<Receiver<Value>>,
    tmp: std::path::PathBuf,
    /// chat → chat GUID (for tapback / edit / unsend when the chat is a chat_id or handle).
    guids: Mutex<HashMap<String, String>>,
    own: Mutex<VecDeque<String>>,
}

impl IMessage {
    fn inbound_of(&self, p: &Value) -> Option<Inbound> {
        let m = &p["message"];
        if !m.is_object() || m["is_from_me"] == true || m["is_reaction"] == true || m["is_tapback"] == true || m["associated_message_type"].as_i64().is_some_and(|t| t >= 2000) {
            return None;
        }
        let sender = m["sender"].as_str().unwrap_or("").to_string();
        let guid = m["guid"].as_str().map(str::to_string).or_else(|| m["id"].as_i64().map(|i| i.to_string()))?;
        let ts = m["created_at"].as_str().and_then(parse_iso).unwrap_or(0);
        if let Some(max) = self.max_age {
            if ts > 0 && crate::irc::now_secs() - ts > max.as_secs() as i64 {
                return None;
            }
        }
        {
            let mut r = self.recent.lock().unwrap();
            if r.contains(&guid) {
                return None;
            }
            r.push_back(guid.clone());
            while r.len() > 2000 {
                r.pop_front();
            }
        }
        let chat = m["chat_guid"].as_str().filter(|s| !s.is_empty()).map(str::to_string).or_else(|| m["chat_id"].as_i64().map(|i| format!("chat_id:{i}"))).unwrap_or_else(|| sender.clone());
        if chat.is_empty() {
            return None;
        }
        if let (Some(g), Some(cid)) = (m["chat_guid"].as_str(), m["chat_id"].as_i64()) {
            self.guids.lock().unwrap().insert(format!("chat_id:{cid}"), g.to_string());
        }
        let text = m["text"].as_str().unwrap_or("").to_string();
        let media: Vec<Media> = m["attachments"].as_array().into_iter().flatten().filter(|a| a["missing"] != true).filter_map(|a| {
            let raw = a["original_path"].as_str()?;
            // Remote paths live on the Mac: fetched with scp, never expanded here.
            let path = if self.remote.is_some() { raw.to_string() } else { expand_home(raw).display().to_string() };
            let mime = a["mime_type"].as_str().unwrap_or("").to_string();
            let name = a["transfer_name"].as_str().map(str::to_string).unwrap_or_else(|| crate::line::file_name(&path));
            Some(Media { kind: kind_of(&mime), mime, name, id: Some(path.clone()), path: Some(path), ..Default::default() })
        }).collect();
        if text.trim().is_empty() && media.is_empty() {
            return None;
        }
        let low = text.to_lowercase();
        let mentioned = self.mention.iter().any(|n| !n.is_empty() && low.contains(&n.to_lowercase()));
        let reply = m["reply_to_guid"].as_str().or_else(|| m["thread_originator_guid"].as_str()).filter(|s| !s.is_empty()).map(|r| ReplyRef {
            id: r.to_string(),
            text: m["reply_to_text"].as_str().unwrap_or("").to_string(),
            author: m["reply_to_sender"].as_str().unwrap_or("").to_string(),
            is_own: self.own.lock().unwrap().iter().any(|o| o == r),
        });
        let group = m["is_group"] == true || m["participants"].as_array().is_some_and(|p| p.len() > 1) || chat.contains(";+;");
        Some(Inbound {
            channel: self.id.clone(),
            chat,
            chat_type: if group { ChatType::Group } else { ChatType::Direct },
            chat_name: m["chat_name"].as_str().unwrap_or("").to_string(),
            sender_name: m["sender_name"].as_str().unwrap_or("").to_string(),
            sender,
            text,
            message_id: guid,
            ts,
            media,
            mentioned,
            reply,
            ..Default::default()
        })
    }

    /// Target params for a chat id.
    fn target(chat: &str) -> Value {
        if let Some(n) = chat.strip_prefix("chat_id:").and_then(|n| n.parse::<i64>().ok()) {
            json!({"chat_id": n})
        } else if let Some(i) = chat.strip_prefix("chat_identifier:") {
            json!({"chat_identifier": i})
        } else if let Some(g) = chat.strip_prefix("chat_guid:") {
            json!({"chat_guid": g})
        } else if chat.contains(';') {
            json!({"chat_guid": chat})
        } else {
            json!({"to": chat})
        }
    }

    fn guid_of(&self, chat: &str) -> Result<String, ChannelError> {
        if let Some(g) = chat.strip_prefix("chat_guid:") {
            return Ok(g.to_string());
        }
        if chat.contains(';') {
            return Ok(chat.to_string());
        }
        self.guids.lock().unwrap().get(chat).cloned().ok_or_else(|| ChannelError::new(K::NotFound, "imsg: unknown chat GUID for this chat (wait for a message from it)"))
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ChannelError> {
        // A restarting child gets a moment to come back.
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            match self.conn.request(method, params.clone(), self.timeout) {
                Err(e) if e.message == "imsg rpc not running" && Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
                Err(e) if e.message == "imsg rpc not running" => return Err(ChannelError::new(K::Network, format!("imsg rpc not running: {}", crate::sms::redact_phones_in(&self.sup.last_log(3))))),
                Err(e) if e.kind == K::Unsupported && (e.message.contains("bridge") || e.message.to_lowercase().contains("private api")) => {
                    // The bridge stopped answering: the cached verdict is stale.
                    *self.papi.lock().unwrap() = None;
                    return Err(e);
                }
                r => return r,
            }
        }
    }

    /// Cached `imsg status --json` (an available bridge stays cached until a bridge error).
    pub fn private_api(&self) -> PrivateApi {
        if let Some((p, at)) = self.papi.lock().unwrap().clone() {
            if p.available || at.elapsed() < PROBE_RETRY {
                return p;
            }
        }
        let p = PrivateApi::probe(&self.cli, PROBE_TIMEOUT);
        *self.papi.lock().unwrap() = Some((p.clone(), Instant::now()));
        p
    }

    fn require_private(&self, action: &str, method: &str) -> Result<(), ChannelError> {
        let p = self.private_api();
        if p.available && (p.rpc_methods.is_empty() || p.supports(method)) {
            return Ok(());
        }
        let why = p.message.or(p.error).map(|m| format!(" imsg reports: {m}")).unwrap_or_default();
        let what = if p.available { format!("this imsg build has no `{method}`; update imsg") } else { "the imsg private API bridge is unavailable; run `imsg launch` on the Mac".to_string() };
        Err(ChannelError::new(K::Unsupported, format!("iMessage {action}: {what}.{why}")))
    }

    fn ssh_argv(&self, host: &str) -> Vec<String> {
        let mut a = vec![self.ssh.clone()];
        a.extend(SSH_OPTIONS.iter().map(|s| s.to_string()));
        a.extend(["-T", "--", host, "sh -s"].map(str::to_string));
        a
    }

    fn checked(&self, label: &str, argv: &[String], stdin: Option<&str>) -> Result<(), ChannelError> {
        match run(argv, stdin, SCP_TIMEOUT) {
            Ok((0, ..)) => Ok(()),
            Ok((code, out, err)) => {
                let d = if err.trim().is_empty() { out } else { err };
                Err(ChannelError::new(K::Network, format!("iMessage {label} failed (code {code}): {}", d.trim().chars().take(300).collect::<String>())))
            }
            Err(e) => Err(ChannelError::new(K::Network, format!("iMessage {label}: {e}"))),
        }
    }

    /// Copy a local file into a private temp dir on the Mac for `f(remote_path)`, then remove it.
    fn with_remote_file<T>(&self, host: &str, local: &str, f: impl FnOnce(&str) -> Result<T, ChannelError>) -> Result<T, ChannelError> {
        let dir = format!("/tmp/seagent-imessage-{}", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16)));
        let remote = format!("{dir}/{}", safe_file_name(local));
        let create = format!("set -eu\numask 077\ndirectory={dir}\ntrap 'rm -rf -- \"$directory\"' EXIT HUP INT TERM\nmkdir -m 700 -- \"$directory\"\ntrap - EXIT HUP INT TERM\n");
        self.checked("remote temporary directory allocation", &self.ssh_argv(host), Some(&create))?;
        let r = (|| {
            let mut scp = vec![self.scp.clone()];
            scp.extend(SSH_OPTIONS.iter().map(|s| s.to_string()));
            scp.extend(["--".to_string(), local.to_string(), format!("{host}:{remote}")]);
            self.checked("remote file upload", &scp, None)?;
            f(&remote)
        })();
        let _ = self.checked("remote file cleanup", &self.ssh_argv(host), Some(&format!("set -eu\nrm -rf -- {dir}\n")));
        r
    }

    fn fetch_remote(&self, host: &str, path: &str) -> Result<Vec<u8>, ChannelError> {
        let rp = normalize_scp_path(path).ok_or_else(|| ChannelError::new(K::Fatal, "unsafe remote attachment path"))?;
        let tmp = self.tmp.join(format!("in-{}", seagent_net::crypto::random_token(8)));
        let _ = std::fs::create_dir_all(&self.tmp);
        let argv: Vec<String> = [self.scp.as_str(), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", &format!("{host}:{rp}"), &tmp.display().to_string()].iter().map(|s| s.to_string()).collect();
        let r = self.checked("remote attachment download", &argv, None).and_then(|_| std::fs::read(&tmp).map_err(|e| ChannelError::new(K::NotFound, format!("iMessage attachment {path}: {e}"))));
        let _ = std::fs::remove_file(&tmp);
        r
    }

    fn remember(&self, r: &Value) -> String {
        let id = r["guid"].as_str().or_else(|| r["message_guid"].as_str()).map(str::to_string).or_else(|| r["id"].as_i64().map(|i| i.to_string())).unwrap_or_default();
        if !id.is_empty() {
            let mut o = self.own.lock().unwrap();
            o.push_back(id.clone());
            while o.len() > 1000 {
                o.pop_front();
            }
        }
        id
    }

    fn send_text(&self, chat: &str, text: &str, reply_to: Option<&str>, file: Option<&str>) -> Result<String, ChannelError> {
        let mut p = Self::target(chat);
        p["text"] = json!(text);
        p["service"] = json!(self.service);
        if let Some(f) = file {
            p["file"] = json!(f);
        }
        if let (Some(f), Some(h)) = (file, self.remote.clone()) {
            let mut wr = p.clone();
            if let Some(r) = reply_to {
                wr["reply_to"] = json!(r);
            }
            return self.with_remote_file(&h, f, |rp| {
                wr["file"] = json!(rp);
                self.call("send", wr).map(|r| self.remember(&r))
            });
        }
        let mut with_reply = p.clone();
        // Threaded replies need the bridge; skip the doomed round trip when it is known down.
        let bridge_down = self.papi.lock().unwrap().as_ref().is_some_and(|(p, _)| !p.available);
        if let Some(r) = reply_to.filter(|_| !bridge_down) {
            with_reply["reply_to"] = json!(r);
        }
        let r = match self.call("send", with_reply) {
            // Threaded replies need imsg's bridge transport; fall back to a plain send.
            Err(e) if reply_to.is_some() && matches!(e.kind, K::Unsupported | K::Protocol) && (e.message.contains("reply") || e.message.contains("bridge")) => self.call("send", p)?,
            r => r?,
        };
        Ok(self.remember(&r))
    }

    /// `chats.list {limit}` → imsg's chat records.
    pub fn chats(&self, limit: u32) -> Result<Value, ChannelError> {
        self.call("chats.list", json!({"limit": limit}))
    }

    pub fn restarts(&self) -> u32 {
        self.sup.starts().saturating_sub(1)
    }
}

impl Channel for IMessage {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        // Unknown until the startup probe finishes: assume the bridge.
        let p = self.papi.lock().unwrap().as_ref().map(|(p, _)| p.clone());
        let has = |m: &str| p.as_ref().is_none_or(|p| p.available && (p.rpc_methods.is_empty() || p.supports(m)));
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: if has("tapback") { 1 } else { 0 },
            edit: has("message.edit"),
            delete: has("message.unsend"),
            typing: has("typing"),
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.cursor.lock().unwrap().commit();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        {
            let rx = self.rx.lock().unwrap();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
        }
        if let Some(max) = got.iter().filter_map(|p| p["message"]["id"].as_i64()).max() {
            let mut c = self.cursor.lock().unwrap();
            c.pending = c.pending.max(Some(max));
        }
        Ok(got.iter().filter_map(|p| self.inbound_of(p)).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut text = match out.format {
            TextFormat::Markdown => crate::markup::convert(&out.text, Markup::Plain),
            TextFormat::Plain => out.text.clone(),
        };
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let mut sent = Sent::default();
        let mut reply = out.reply_to.as_deref();
        for m in &out.media {
            let (path, temp) = match (&m.path, &m.url) {
                (Some(p), _) => (expand_home(p).display().to_string(), false),
                (None, Some(u)) => {
                    let bytes = crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?;
                    let name = if m.name.is_empty() { u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string() } else { m.name.clone() };
                    let p = self.tmp.join(format!("{}-{}", seagent_net::crypto::random_token(6), name.replace(['/', '\\'], "_")));
                    crate::write_atomic(&p, &bytes).map_err(|e| ChannelError::new(K::Fatal, format!("staging attachment: {e}")))?;
                    (p.display().to_string(), true)
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            };
            let target = Self::target(&out.chat);
            let r = if target.get("to").is_some() {
                // Handles have no chat yet: `send` with a file creates it.
                self.send_text(&out.chat, "", reply.take(), Some(&path))
            } else {
                let mut p = target;
                p["file"] = json!(path);
                if matches!(m.kind, MediaKind::Voice) {
                    p["audio"] = json!(true);
                }
                if let Some(r) = reply.take() {
                    p["reply_to"] = json!(r);
                }
                match self.remote.clone() {
                    Some(h) => self.with_remote_file(&h, &path, |rp| {
                        p["file"] = json!(rp);
                        self.call("send.attachment", p).map(|r| self.remember(&r))
                    }),
                    None => self.call("send.attachment", p).map(|r| self.remember(&r)),
                }
            };
            if temp {
                let _ = std::fs::remove_file(&path);
            }
            sent.ids.push(r?);
        }
        for piece in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars) {
            sent.ids.push(self.send_text(&out.chat, &piece, reply.take(), None)?);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.require_private("edit", "message.edit")?;
        let t = crate::markup::convert(text, Markup::Plain);
        self.call("message.edit", json!({"chat_guid": self.guid_of(chat)?, "message_id": message_id, "part_index": 0, "text": t, "backwards_compatibility_message": t})).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.require_private("unsend", "message.unsend")?;
        self.call("message.unsend", json!({"chat_guid": self.guid_of(chat)?, "message_id": message_id, "part_index": 0})).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        if !self.private_api().supports("typing") {
            return Ok(());
        }
        let mut p = Self::target(chat);
        p["typing"] = json!(true);
        if p.get("to").is_some() && self.service != "auto" {
            p["service"] = json!(self.service);
        }
        self.call("typing", p).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        self.require_private("tapback", "tapback")?;
        let mut p = json!({"chat_guid": self.guid_of(chat)?, "message_id": message_id, "part_index": 0, "reaction": tapback_kind(emoji)});
        if remove {
            p["remove"] = json!(true);
        }
        self.call("tapback", p).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let p = m.path.as_deref().or(m.id.as_deref()).ok_or_else(|| ChannelError::new(K::Fatal, "iMessage attachment without path"))?;
        if let Some(h) = &self.remote {
            return self.fetch_remote(h, p);
        }
        std::fs::read(expand_home(p)).map_err(|e| ChannelError::new(K::NotFound, format!("iMessage attachment {p}: {e}")))
    }

    fn stop(&self) {
        self.sup.stop();
    }
}

fn d_cli() -> String {
    "imsg".into()
}
fn d_service() -> String {
    "auto".into()
}
fn d_poll() -> u64 {
    25
}
fn d_backoff() -> u64 {
    1000
}
fn d_true() -> bool {
    true
}
fn d_age() -> u64 {
    120
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Path to the `imsg` CLI.
    #[serde(default = "d_cli", alias = "cli_path")]
    pub cli: String,
    /// Messages database (default: imsg's own, ~/Library/Messages/chat.db).
    #[serde(default, alias = "db_path")]
    pub db: Option<String>,
    /// `auto`, `imessage` or `sms`.
    #[serde(default = "d_service")]
    pub service: String,
    /// Words that count as mentioning the bot in groups (case-insensitive).
    #[serde(default)]
    pub mention_names: Vec<String>,
    #[serde(default = "d_backoff")]
    pub restart_backoff_ms: u64,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
    /// `[user@]host` of the Messages Mac when `cli` runs imsg over ssh
    /// (detected from a simple `exec ssh host imsg "$@"` wrapper otherwise).
    #[serde(default, alias = "remoteHost")]
    pub remote_host: Option<String>,
    /// Replay messages missed while seagent was down (`since_rowid` cursor).
    #[serde(default = "d_true")]
    pub catchup: bool,
    /// Drop replayed / backlogged messages older than this (0 = keep all).
    #[serde(default = "d_age")]
    pub catchup_max_age_minutes: u64,
}

impl IMessage {
    pub fn open(id: &str, st: &Settings, state_dir: &std::path::Path) -> Result<IMessage, String> {
        let remote = resolve_remote_host(&st.cli, st.remote_host.as_deref()).map_err(|e| format!("channel {id}: imessage {e}"))?;
        let conn: Arc<Conn> = Arc::default();
        let (tx, rx) = channel::<Value>();
        let mut args = vec!["rpc".to_string(), "--json".to_string()];
        if let Some(db) = &st.db {
            args.push("--db".into());
            // A remote database path belongs to the Mac.
            args.push(if remote.is_some() { db.clone() } else { expand_home(db).display().to_string() });
        }
        let cursor = Arc::new(Mutex::new(Cursor::load(state_dir.join(format!("{id}.imessage.json")), db_identity(&st.cli, st.db.as_deref(), remote.as_deref()))));
        let catchup = st.catchup;
        let cur2 = cursor.clone();
        let c2 = conn.clone();
        let tx = Mutex::new(tx);
        let attach: Attach = Arc::new(move |child: &mut std::process::Child| {
            let Some(stdout) = child.stdout.take() else { return };
            *c2.stdin.lock().unwrap() = child.stdin.take();
            let gen = c2.generation.fetch_add(1, Ordering::SeqCst) + 1;
            let (c3, tx3, cur3) = (c2.clone(), tx.lock().unwrap().clone(), cur2.clone());
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
                    let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
                    match v["id"].as_u64() {
                        Some(id) if v.get("method").is_none() => {
                            if let Some(p) = c3.pending.lock().unwrap().remove(&id) {
                                let _ = p.send(if v["error"].is_object() { Err(v["error"].clone()) } else { Ok(v["result"].clone()) });
                            }
                        }
                        _ if v["method"] == "message" => {
                            if let Some(rowid) = v["params"]["message"]["id"].as_i64() {
                                let mut c = cur3.lock().unwrap();
                                c.seen = c.seen.max(Some(rowid));
                            }
                            let _ = tx3.send(v["params"].clone());
                        }
                        _ => {}
                    }
                }
                // EOF: this child is gone; fail its requests.
                if c3.generation.load(Ordering::SeqCst) == gen {
                    *c3.stdin.lock().unwrap() = None;
                }
                for (_, p) in c3.pending.lock().unwrap().drain() {
                    let _ = p.send(Err(json!({"message": "imsg rpc closed"})));
                }
            });
            // Subscribe on every (re)start.
            let c4 = c2.clone();
            let mut sub = json!({"attachments": true, "include_reactions": false});
            if let Some(since) = cur2.lock().unwrap().since().filter(|_| catchup) {
                sub["since_rowid"] = json!(since);
            }
            std::thread::spawn(move || {
                let _ = c4.request("watch.subscribe", sub, Duration::from_secs(15));
            });
        });
        let spec = ChildSpec { label: format!("imsg ({id})"), program: expand_home(&st.cli).display().to_string(), args, env: vec![], cwd: None, stdio: true, backoff: Duration::from_millis(st.restart_backoff_ms.max(10)) };
        let sup = Supervisor::start(spec, Some(attach));
        let papi: Arc<Mutex<Option<(PrivateApi, Instant)>>> = Arc::default();
        let (p2, cli) = (papi.clone(), st.cli.clone());
        std::thread::spawn(move || {
            let p = PrivateApi::probe(&cli, PROBE_TIMEOUT);
            p2.lock().unwrap().get_or_insert((p, Instant::now()));
        });
        Ok(IMessage {
            id: id.to_string(),
            cli: st.cli.clone(),
            remote,
            ssh: "ssh".into(),
            scp: "scp".into(),
            papi,
            cursor,
            max_age: (st.catchup_max_age_minutes > 0).then(|| Duration::from_secs(st.catchup_max_age_minutes * 60)),
            recent: Mutex::default(),
            conn,
            sup,
            service: st.service.clone(),
            mention: st.mention_names.clone(),
            poll_timeout: st.poll_timeout_secs,
            timeout: Duration::from_secs(30),
            rx: Mutex::new(rx),
            tmp: state_dir.join(format!("{id}.imessage-outbox")),
            guids: Mutex::default(),
            own: Mutex::default(),
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    Ok(Arc::new(IMessage::open(ctx.name, &st, ctx.state_dir)?))
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[cfg(unix)]
    /// A fake `imsg rpc --json`: logs every request line, answers by method,
    /// emits `message` notifications after watch.subscribe, exits on `test.exit`.
    fn fake_imsg(dir: &std::path::Path) -> String {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let log = dir.join("requests.log");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "status" ]; then
  echo "STATUS" >> {dir}/status.log
  if [ -f {dir}/status.json ]; then cat {dir}/status.json; else echo '{{"advanced_features":true,"v2_ready":true,"rpc_methods":["send","typing","tapback","message.edit","message.unsend"]}}'; fi
  exit 0
fi
echo "ARGS $*" >> {log}
while IFS= read -r line; do
  printf '%s\n' "$line" >> {log}
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  method=$(printf '%s' "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
  case "$method" in
    watch.subscribe)
      printf '{{"jsonrpc":"2.0","id":%s,"result":{{"subscription":1}}}}\n' "$id"
      if [ -f {dir}/notify ]; then cat {dir}/notify; rm -f {dir}/notify; fi ;;
    send|send.attachment)
      if printf '%s' "$line" | grep -q '"reply_to":"NOREPLY"'; then
        printf '{{"jsonrpc":"2.0","id":%s,"error":{{"code":-32000,"message":"reply_to requires bridge transport"}}}}\n' "$id"
      else
        printf '{{"jsonrpc":"2.0","id":%s,"result":{{"ok":true,"guid":"OUT-%s"}}}}\n' "$id" "$id"
      fi ;;
    chats.list) printf '{{"jsonrpc":"2.0","id":%s,"result":[{{"id":5,"guid":"iMessage;+;chat5","name":"Team"}}]}}\n' "$id" ;;
    message.unsend) printf '{{"jsonrpc":"2.0","id":%s,"error":{{"code":-32000,"message":"message not found"}}}}\n' "$id" ;;
    test.exit) exit 3 ;;
    *) printf '{{"jsonrpc":"2.0","id":%s,"result":{{"ok":true}}}}\n' "$id" ;;
  esac
done
"#,
            log = log.display(),
            dir = dir.display()
        );
        let p = dir.join("imsg");
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[cfg(unix)]
    fn open(dir: &std::path::Path) -> IMessage {
        open_with(dir, json!({}))
    }

    #[cfg(unix)]
    fn open_with(dir: &std::path::Path, extra: Value) -> IMessage {
        let mut v = json!({"cli": fake_imsg(dir), "db": "/tmp/chat.db", "mention_names": ["@seagent"], "restart_backoff_ms": 50, "poll_timeout_secs": 2, "catchup_max_age_minutes": 0});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        let st: Settings = serde_json::from_value(v).unwrap();
        let mut m = IMessage::open("im", &st, dir).unwrap();
        m.timeout = Duration::from_secs(5);
        m
    }

    fn requests(dir: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join("requests.log")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    fn wait_for(dir: &std::path::Path, method: &str, n: usize) {
        let t = Instant::now();
        while requests(dir).iter().filter(|r| r["method"] == method).count() < n && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn note(m: Value) -> String {
        format!("{}\n", json!({"jsonrpc": "2.0", "method": "message", "params": {"subscription": 1, "message": m}}))
    }

    #[cfg(unix)]
    #[test]
    fn subscribes_and_parses_notifications() {
        let dir = temp_dir("imsg");
        let att = dir.join("IMG_1.heic");
        std::fs::write(&att, b"HEIC").unwrap();
        let notes = [
            note(json!({"id": 1, "guid": "G1", "chat_id": 5, "chat_guid": "iMessage;-;+886912345678", "sender": "+886912345678", "sender_name": "Amy", "is_from_me": false, "text": "hi", "created_at": "2024-05-01T10:00:00.123Z", "is_group": false})),
            note(json!({"id": 2, "guid": "G2", "chat_id": 6, "chat_guid": "iMessage;+;chat6", "chat_name": "Team", "sender": "bob@example.com", "text": "@seagent do it", "is_group": true, "participants": ["a", "b"], "created_at": "2024-05-01T18:00:00+08:00"})),
            note(json!({"id": 3, "guid": "G3", "chat_id": 6, "sender": "bob@example.com", "text": "", "attachments": [{"original_path": att.display().to_string(), "mime_type": "image/heic", "transfer_name": "IMG_1.heic"}, {"original_path": "/gone", "missing": true}], "is_group": true})),
            note(json!({"id": 4, "guid": "G4", "chat_id": 5, "sender": "+886912345678", "text": "Loved “hi”", "is_reaction": true})),
            note(json!({"id": 5, "guid": "G5", "chat_id": 5, "sender": "me", "text": "echo", "is_from_me": true})),
            note(json!({"id": 6, "guid": "G6", "chat_id": 5, "chat_guid": "iMessage;-;+886912345678", "sender": "+886912345678", "text": "re", "reply_to_guid": "OUT-PREV", "reply_to_text": "q?"})),
        ];
        std::fs::write(dir.join("notify"), notes.concat()).unwrap();
        let m = open(&dir);
        let mut g = Vec::new();
        let t = Instant::now();
        while g.len() < 4 && t.elapsed() < Duration::from_secs(5) {
            g.extend(m.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(g.len(), 4, "reaction and own message dropped: {g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].sender_name.as_str(), g[0].message_id.as_str(), g[0].chat_type, g[0].ts), ("iMessage;-;+886912345678", "Amy", "G1", ChatType::Direct, 1714557600));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group && g[1].chat_name == "Team" && g[1].ts == 1714557600);
        assert_eq!((g[2].chat.as_str(), g[2].media.len(), g[2].media[0].kind), ("chat_id:6", 1, MediaKind::Image));
        assert_eq!(m.fetch_media(&g[2].media[0]).unwrap(), b"HEIC");
        assert_eq!(g[3].reply.as_ref().unwrap().text, "q?");
        let reqs = requests(&dir);
        assert_eq!(reqs[0]["method"], "watch.subscribe");
        assert_eq!(reqs[0]["params"], json!({"attachments": true, "include_reactions": false}));
        assert_eq!(reqs[0]["jsonrpc"], "2.0");
        let args = std::fs::read_to_string(dir.join("requests.log")).unwrap();
        assert!(args.starts_with("ARGS rpc --json --db /tmp/chat.db"), "{args}");
    }

    #[cfg(unix)]
    #[test]
    fn send_actions_and_reply_fallback() {
        let dir = temp_dir("imsg");
        let m = open(&dir);
        wait_for(&dir, "watch.subscribe", 1);
        let s = m.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("G1".into()), ..Outbound::text("+886912345678", "**hi**") }).unwrap();
        assert!(s.ids[0].starts_with("OUT-"));
        let f = dir.join("a.png");
        std::fs::write(&f, b"PNG").unwrap();
        m.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("iMessage;+;chat6", "pick") }).unwrap();
        // A threaded reply the transport cannot do is retried without reply_to.
        m.send(&Outbound { reply_to: Some("NOREPLY".into()), ..Outbound::text("chat_id:5", "plain") }).unwrap();
        m.edit("iMessage;+;chat6", "OUT-1", "fixed").unwrap();
        m.react("iMessage;+;chat6", "G2", "👍", false).unwrap();
        m.react("iMessage;+;chat6", "G2", "❤️", true).unwrap();
        m.typing("+886912345678", None).unwrap();
        assert_eq!(m.delete("iMessage;+;chat6", "OUT-1").unwrap_err().kind, K::NotFound);
        assert_eq!(m.react("chat_id:99", "G", "👍", false).unwrap_err().kind, K::NotFound, "no GUID known");
        assert_eq!(m.chats(10).unwrap()[0]["guid"], "iMessage;+;chat5");
        let r: Vec<Value> = requests(&dir).into_iter().filter(|r| r["method"] != "watch.subscribe").collect();
        assert_eq!(r[0]["method"], "send");
        assert_eq!(r[0]["params"], json!({"to": "+886912345678", "text": "hi", "service": "auto", "reply_to": "G1"}));
        assert_eq!((r[1]["method"].as_str(), r[1]["params"]["chat_guid"].as_str(), r[1]["params"]["file"].as_str()), (Some("send.attachment"), Some("iMessage;+;chat6"), Some(f.to_str().unwrap())));
        assert_eq!(r[2]["params"]["text"], "pick\n\n1. Yes");
        assert_eq!((r[3]["params"]["reply_to"].as_str(), r[4]["params"].get("reply_to").is_none(), r[4]["params"]["chat_id"].as_i64()), (Some("NOREPLY"), true, Some(5)));
        assert_eq!(r[5]["params"], json!({"chat_guid": "iMessage;+;chat6", "message_id": "OUT-1", "part_index": 0, "text": "fixed", "backwards_compatibility_message": "fixed"}));
        assert_eq!((r[6]["method"].as_str(), r[6]["params"]["reaction"].as_str()), (Some("tapback"), Some("like")));
        assert_eq!((r[7]["params"]["reaction"].as_str(), r[7]["params"]["remove"].as_bool()), (Some("love"), Some(true)));
        assert_eq!(r[8]["params"], json!({"to": "+886912345678", "typing": true}));
        assert_eq!(r[9]["method"], "message.unsend");
    }

    #[cfg(unix)]
    #[test]
    fn restarts_after_exit_and_resubscribes_then_kills_on_drop() {
        let dir = temp_dir("imsg");
        let m = open(&dir);
        wait_for(&dir, "watch.subscribe", 1);
        let e = m.conn.request("test.exit", json!({}), Duration::from_secs(5)).unwrap_err();
        assert_eq!(e.kind, K::Network, "pending request fails when the child dies: {e:?}");
        wait_for(&dir, "watch.subscribe", 2);
        assert_eq!(requests(&dir).iter().filter(|r| r["method"] == "watch.subscribe").count(), 2, "resubscribed after restart");
        assert!(m.restarts() >= 1);
        // Requests work again on the new child.
        assert!(m.send(&Outbound::text("+1", "back")).is_ok());
        let pid = m.sup.pid().unwrap();
        drop(m);
        let t = Instant::now();
        // SAFETY: probing a pid with signal 0.
        while unsafe { libc::kill(pid, 0) } == 0 && t.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: as above.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0);
    }

    fn poll_n(m: &IMessage, n: usize) -> Vec<Inbound> {
        let mut g = Vec::new();
        let t = Instant::now();
        while g.len() < n && t.elapsed() < Duration::from_secs(5) {
            g.extend(m.poll(&Cancel::new()).unwrap());
        }
        g
    }

    fn iso(secs_ago: i64) -> String {
        let t = crate::irc::now_secs() - secs_ago;
        let (days, rem) = (t.div_euclid(86400), t.rem_euclid(86400));
        // civil_from_days (Howard Hinnant).
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
    }

    #[cfg(unix)]
    #[test]
    fn catchup_cursor_replays_since_rowid_dedups_and_drops_stale() {
        let dir = temp_dir("imsg");
        let m = open_with(&dir, json!({"catchup_max_age_minutes": 120}));
        wait_for(&dir, "watch.subscribe", 1);
        assert!(requests(&dir)[0]["params"].get("since_rowid").is_none(), "no cursor yet: imsg tails from now");
        std::fs::write(dir.join("notify"), [note(json!({"id": 41, "guid": "A", "chat_id": 5, "sender": "+1", "text": "one", "created_at": iso(10)})), note(json!({"id": 41, "guid": "A", "chat_id": 5, "sender": "+1", "text": "one", "created_at": iso(10)})), note(json!({"id": 42, "guid": "B", "chat_id": 5, "sender": "+1", "text": "two", "created_at": iso(20)}))].concat()).unwrap();
        // In-process restart: resubscribe from the highest rowid seen so far.
        let _ = m.conn.request("test.exit", json!({}), Duration::from_secs(5));
        wait_for(&dir, "watch.subscribe", 2);
        assert_eq!(poll_n(&m, 2).iter().map(|i| i.text.as_str()).collect::<Vec<_>>(), vec!["one", "two"], "duplicate GUID dropped");
        // Commits on the next poll.
        assert!(!dir.join("im.imessage.json").exists());
        let _ = m.poll(&Cancel::new());
        let saved: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("im.imessage.json")).unwrap()).unwrap();
        assert_eq!((saved["last_rowid"].as_i64(), saved["db"].as_str()), (Some(42), Some("local:/tmp/chat.db")));
        drop(m);
        // A new process replays from the persisted cursor; overlap and stale rows are dropped.
        std::fs::write(dir.join("notify"), [note(json!({"id": 42, "guid": "B", "chat_id": 5, "sender": "+1", "text": "two", "created_at": iso(20)})), note(json!({"id": 43, "guid": "C", "chat_id": 5, "sender": "+1", "text": "old", "created_at": iso(3 * 3600)})), note(json!({"id": 44, "guid": "D", "chat_id": 5, "sender": "+1", "text": "missed", "created_at": iso(60)}))].concat()).unwrap();
        let _ = std::fs::remove_file(dir.join("requests.log"));
        let m2 = open_with(&dir, json!({"catchup_max_age_minutes": 120}));
        wait_for(&dir, "watch.subscribe", 1);
        assert_eq!(requests(&dir)[0]["params"]["since_rowid"], 42);
        let g = poll_n(&m2, 2);
        assert_eq!(g.len(), 2, "{g:?}");
        assert_eq!((g[0].text.as_str(), g[1].text.as_str()), ("two", "missed"), "the fake ignores since_rowid (real imsg starts after 42); stale row dropped");
        let _ = m2.poll(&Cancel::new());
        drop(m2);
        // Another database never inherits this cursor.
        let _ = std::fs::remove_file(dir.join("requests.log"));
        let m3 = open_with(&dir, json!({"db": "/other/chat.db"}));
        wait_for(&dir, "watch.subscribe", 1);
        assert!(requests(&dir)[0]["params"].get("since_rowid").is_none());
        drop(m3);
        let m4 = open_with(&dir, json!({"catchup": false}));
        wait_for(&dir, "watch.subscribe", 1);
        assert!(requests(&dir).iter().filter(|r| r["method"] == "watch.subscribe").all(|r| r["params"].get("since_rowid").is_none()));
        drop(m4);
        let mut c = Cursor { committed: Some(0), ..Default::default() };
        assert_eq!(c.since(), Some(-1), "0 is imsg's tail-from-now sentinel");
        c.seen = Some(7);
        assert_eq!(c.since(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn private_api_gates_bridge_actions() {
        let dir = temp_dir("imsg");
        std::fs::write(dir.join("status.json"), "noise\n{\"advanced_features\":false,\"v2_ready\":false,\"message\":\"SIP is enabled\"}\n").unwrap();
        let m = open(&dir);
        wait_for(&dir, "watch.subscribe", 1);
        let p = m.private_api();
        assert!(!p.available && p.message.as_deref() == Some("SIP is enabled"));
        let e = m.react("iMessage;+;chat6", "G2", "👍", false).unwrap_err();
        assert!(e.kind == K::Unsupported && e.message.contains("SIP is enabled") && e.message.contains("imsg launch"), "{e:?}");
        assert_eq!(m.edit("iMessage;+;chat6", "X", "y").unwrap_err().kind, K::Unsupported);
        assert_eq!(m.delete("iMessage;+;chat6", "X").unwrap_err().kind, K::Unsupported);
        m.typing("+1", None).unwrap();
        m.send(&Outbound { reply_to: Some("G1".into()), ..Outbound::text("+1", "plain") }).unwrap();
        let caps = m.caps();
        assert!(!caps.edit && !caps.delete && caps.reactions == 0 && !caps.typing);
        let r: Vec<Value> = requests(&dir).into_iter().filter(|r| r["method"] != "watch.subscribe").collect();
        assert_eq!(r.len(), 1, "nothing but the send reached imsg: {r:?}");
        assert!(r[0]["params"].get("reply_to").is_none(), "reply dropped without the bridge");
        let n = std::fs::read_to_string(dir.join("status.log")).unwrap().lines().count();
        m.private_api();
        assert_eq!(std::fs::read_to_string(dir.join("status.log")).unwrap().lines().count(), n, "cached");
        // Older imsg without rpc_methods: only the foundational methods count.
        let old = PrivateApi { available: true, ..Default::default() };
        assert!(old.supports("send") && !old.supports("typing"));
    }

    #[test]
    fn remote_host_detection_and_validation() {
        assert_eq!(parse_remote_host("#!/bin/sh\nexec ssh -T mac@studio.local imsg \"$@\"\n"), Ok(Some("mac@studio.local".into())));
        assert_eq!(parse_remote_host("exec '/usr/bin/ssh' host /opt/homebrew/bin/imsg \"$@\""), Ok(Some("host".into())));
        assert_eq!(parse_remote_host("#!/bin/sh\nexec /usr/local/bin/imsg \"$@\""), Ok(None), "plain wrapper");
        assert_eq!(parse_remote_host("#!/bin/sh\nexec ssh -p 2222 host imsg \"$@\""), Err(()), "options are ambiguous");
        assert_eq!(parse_remote_host("exec ssh host \\\n  imsg \"$@\""), Err(()), "continuation lines");
        assert_eq!(parse_remote_host("set -e\nexec ssh host imsg \"$@\""), Err(()));
        assert_eq!(parse_remote_host("exec ssh -oProxyCommand=x imsg \"$@\""), Err(()), "bad host");
        assert_eq!(normalize_scp_host("user@[fe80::1]").as_deref(), Some("user@[fe80::1]"));
        assert!(normalize_scp_host("-oProxyCommand=x").is_none() && normalize_scp_host("a@b@c").is_none() && normalize_scp_host("h;rm").is_none() && normalize_scp_host("h st").is_none());
        assert_eq!(normalize_scp_path("~/Library/Messages/Attachments/a.jpg").as_deref(), Some("Library/Messages/Attachments/a.jpg"));
        assert!(normalize_scp_path("/x/$(id)").is_none() && normalize_scp_path("rel/x").is_none());
        let dir = temp_dir("imsg");
        let w = dir.join("imsg-remote");
        std::fs::write(&w, "#!/bin/sh\nexec ssh -p 22 h imsg \"$@\"\n").unwrap();
        assert!(resolve_remote_host(w.to_str().unwrap(), None).unwrap_err().contains("remote_host"));
        assert_eq!(resolve_remote_host(w.to_str().unwrap(), Some("mac")).unwrap().as_deref(), Some("mac"));
        assert!(resolve_remote_host("imsg", Some("bad host")).is_err());
        assert_eq!(resolve_remote_host("imsg", None), Ok(None));
        assert_eq!(db_identity("imsg", Some("/d.db"), Some("mac")), "remote:mac:/d.db");
        assert_eq!(db_identity("/opt/wrap.sh", None, None), "local:cli:/opt/wrap.sh");
    }

    #[cfg(unix)]
    #[test]
    fn remote_host_stages_outbound_files_and_fetches_inbound_with_scp() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("imsg");
        let mac = dir.join("mac");
        std::fs::create_dir_all(&mac).unwrap();
        // Fake ssh: run the script with /tmp mapped into `mac`; fake scp: copy with host: stripped and mapped.
        let ssh = dir.join("ssh");
        std::fs::write(&ssh, format!("#!/bin/sh\necho \"SSH $*\" >> {d}/remote.log\nsed 's#/tmp/#{m}/#g' | sh -s\n", d = dir.display(), m = mac.display())).unwrap();
        let scp = dir.join("scp");
        std::fs::write(&scp, format!("#!/bin/sh\necho \"SCP $*\" >> {d}/remote.log\nfor a; do src=$dst; dst=$a; done\nmap() {{ case \"$1\" in *:*) p=${{1#*:}}; case \"$p\" in /tmp/*) echo {m}/${{p#/tmp/}};; /*) echo \"$p\";; *) echo {m}/$p;; esac;; *) echo \"$1\";; esac; }}\ncp \"$(map \"$src\")\" \"$(map \"$dst\")\"\n", d = dir.display(), m = mac.display())).unwrap();
        for f in [&ssh, &scp] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut m = open_with(&dir, json!({"remote_host": "me@mac.local", "db": "~/Library/Messages/chat.db"}));
        m.ssh = ssh.display().to_string();
        m.scp = scp.display().to_string();
        wait_for(&dir, "watch.subscribe", 1);
        let args = std::fs::read_to_string(dir.join("requests.log")).unwrap();
        assert!(args.starts_with("ARGS rpc --json --db ~/Library/Messages/chat.db"), "remote db path untouched: {args}");
        let f = dir.join("my photo.png");
        std::fs::write(&f, b"PNG").unwrap();
        m.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("iMessage;+;chat6", "") }).unwrap();
        let sent: Vec<Value> = requests(&dir).into_iter().filter(|r| r["method"] == "send.attachment").collect();
        let rp = sent[0]["params"]["file"].as_str().unwrap().to_string();
        assert!(rp.starts_with("/tmp/seagent-imessage-") && rp.ends_with("/my_photo.png"), "{rp}");
        let log = std::fs::read_to_string(dir.join("remote.log")).unwrap();
        assert!(log.contains("BatchMode=yes") && log.contains("StrictHostKeyChecking=yes") && log.contains("-T -- me@mac.local sh -s"), "{log}");
        assert!(log.contains(&format!("me@mac.local:{rp}")));
        assert!(std::fs::read_dir(&mac).unwrap().next().is_none(), "remote temp dir removed");
        // Inbound attachment paths stay remote and come back over scp.
        std::fs::create_dir_all(mac.join("Library")).unwrap();
        std::fs::write(mac.join("Library/a.heic"), b"HEIC").unwrap();
        let media = Media { path: Some("~/Library/a.heic".into()), ..Default::default() };
        assert_eq!(m.fetch_media(&media).unwrap(), b"HEIC");
        assert_eq!(m.fetch_media(&Media { path: Some("/x/`id`".into()), ..Default::default() }).unwrap_err().kind, K::Fatal);
    }

    #[cfg(unix)]
    #[test]
    fn cancel_errors_and_helpers() {
        let dir = temp_dir("imsg");
        let m = open(&dir);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(m.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        assert_eq!(parse_iso("1970-01-02T00:00:00Z"), Some(86400));
        assert_eq!(parse_iso("2024-05-01 10:00:00-01:30"), Some(1714557600 + 5400));
        assert_eq!(rpc_err("send", &json!({"code": -32000, "message": "Full Disk Access required for +886912345678"})).kind, K::Fatal);
        assert!(!rpc_err("send", &json!({"message": "no chat for +886912345678"})).message.contains("912345678"));
        assert_eq!(rpc_err("x", &json!({"code": -32601, "message": "Method not found"})).kind, K::Unsupported);
        // A missing binary: requests fail as Network with the spawn error.
        let st: Settings = serde_json::from_value(json!({"cli": "/nonexistent/imsg", "restart_backoff_ms": 50})).unwrap();
        let mut bad = IMessage::open("x", &st, &dir).unwrap();
        bad.timeout = Duration::from_millis(200);
        let e = bad.send(&Outbound::text("+1", "x")).unwrap_err();
        assert!(e.kind == K::Network && e.message.contains("cannot start"), "{e:?}");
    }
}
