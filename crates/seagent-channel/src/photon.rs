//! iMessage through Photon's Spectrum cloud (ported from Hermes
//! `plugins/platforms/photon`, MIT).
//!
//! Spectrum's SDK is TypeScript-only, so a Node sidecar (`bridges/photon/`,
//! adapted from Hermes) holds the gRPC stream and exposes a loopback API that
//! seagent speaks exactly as Hermes' adapter does, authenticated with the shared
//! token (`X-Hermes-Sidecar-Token`, plus `Authorization: Bearer`):
//! `GET /inbound` (NDJSON stream, blank-line heartbeats; reconnected with
//! backoff), `POST /send`, `/send-attachment`, `/send-richlink`, `/send-poll`,
//! `/typing`, `/react`, `/unreact`, `/healthz`, `/probe`, `/shutdown`, and seagent's
//! `/unsend` (retract one of our messages via spectrum-ts `space.unsend`).
//! spectrum-ts 12.x exposes no outbound edit or quote-reply builder (Hermes marks
//! the channel non-editable too), so `edit` and `reply_to` stay unsupported.
//! Optional supervision: with `sidecar_dir`, seagent spawns `node index.mjs` there
//! (never `npm install`), restarts it with backoff, kills it on drop.
//! Inbound content: text, rich links, attachments / voice (bytes inlined by the
//! sidecar, cached to the state dir), groups, threaded replies, poll votes
//! (→ `Callback` for buttons sent as native polls). Reactions and read
//! receipts are dropped.

use crate::whatsapp::{expand_home, ChildSpec, Supervisor};
use crate::http::{classify, Http, Payload};
use crate::{Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 8000;
pub const TOKEN_HEADER: &str = "X-Hermes-Sidecar-Token";

fn inbound_loop(base: String, token: String, stop: Arc<AtomicBool>, tx: Sender<Value>) {
    let mut backoff = Duration::from_millis(300);
    while !stop.load(Ordering::SeqCst) {
        let mut ok = false;
        if let Ok(u) = seagent_net::Url::parse(&base) {
            let prefix = u.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
            let bearer = format!("Bearer {token}");
            let mut line: Vec<u8> = Vec::new();
            let _ = crate::signal::http_stream(&u, &format!("{prefix}/inbound"), &[(TOKEN_HEADER, &token), ("Authorization", &bearer), ("Accept", "application/x-ndjson")], &stop, &mut ok, &mut |bytes| {
                for &b in bytes {
                    if b == b'\n' {
                        if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                            let _ = tx.send(v);
                        }
                        line.clear();
                    } else {
                        line.push(b);
                    }
                }
            });
        }
        if ok {
            backoff = Duration::from_millis(300);
        }
        let until = Instant::now() + backoff;
        while Instant::now() < until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// The sidecar's `{ok:false, error, error_class, retryable}` → classified error.
fn sidecar_err(path: &str, status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let err = crate::sms::redact_phones_in(v["error"].as_str().unwrap_or(""));
    let class = v["error_class"].as_str().unwrap_or("");
    let text = format!("photon {path}: HTTP {status} {err} {class}").trim().to_string();
    let kind = match (status, class) {
        (_, "target_not_allowed") => return ChannelError::new(K::Fatal, format!("photon {path}: this Photon line may not start a conversation with that recipient (target not allowed for the project; shared lines can only answer people who wrote first)")),
        (_, "auth_or_config") | (401 | 403, _) => K::Auth,
        (_, "upstream_transient") => K::Network,
        (_, _) if v["retryable"] == true => K::Network,
        (400, _) if err.contains("not found") => K::NotFound,
        (400, _) if err.contains("not supported") => K::Unsupported,
        _ => classify(status, retry_after, path, "").kind,
    };
    ChannelError::new(kind, text)
}

fn kind_of(c: &Value) -> MediaKind {
    if c["type"] == "voice" {
        return MediaKind::Voice;
    }
    let mime = c["mimeType"].as_str().unwrap_or("");
    match mime.split('/').next().unwrap_or("") {
        "image" if mime.contains("gif") => MediaKind::Animation,
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Audio,
        _ => MediaKind::Document,
    }
}

pub struct Photon {
    id: String,
    base: String,
    http: Http,
    poll_timeout: u64,
    media_dir: PathBuf,
    rx: Mutex<Receiver<Value>>,
    stop: Arc<AtomicBool>,
    sup: Option<Supervisor>,
    own: Mutex<VecDeque<String>>,
    /// chat → options of the latest poll we sent for buttons: (label, data).
    polls: Mutex<HashMap<String, Vec<(String, String)>>>,
    /// (chat, message) → reaction id, for /unreact after a restart.
    reactions: Mutex<HashMap<(String, String), String>>,
}

impl Drop for Photon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Photon {
    fn post(&self, path: &str, body: &Value) -> Result<Value, ChannelError> {
        let r = self.http.call("POST", &format!("{}{path}", self.base), &[], Payload::Json(body)).map_err(|e| match &self.sup {
            Some(s) if !s.running() => ChannelError::new(K::Network, format!("photon sidecar is not running ({}): {}", e.message, crate::sms::redact_phones_in(&s.last_log(3)))),
            _ => e,
        })?;
        let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        if !(200..300).contains(&r.status) || v["ok"] == false {
            return Err(sidecar_err(path, if (200..300).contains(&r.status) { 500 } else { r.status }, r.retry_after, &r.body));
        }
        Ok(v)
    }

    fn remember(&self, v: &Value) -> String {
        let id = v["messageId"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            let mut o = self.own.lock().unwrap();
            o.push_back(id.clone());
            while o.len() > 1000 {
                o.pop_front();
            }
        }
        id
    }

    /// Sidecar health: `POST /healthz`.
    pub fn health(&self) -> Result<Value, ChannelError> {
        self.post("/healthz", &json!({}))
    }

    /// Upstream liveness: `POST /probe` (503 → Network).
    pub fn probe(&self) -> Result<bool, ChannelError> {
        Ok(self.post("/probe", &json!({}))?["alive"] == true)
    }

    pub fn send_poll(&self, chat: &str, title: &str, options: &[String]) -> Result<String, ChannelError> {
        self.post("/send-poll", &json!({"spaceId": chat, "title": title, "options": options})).map(|v| self.remember(&v))
    }

    pub fn send_richlink(&self, chat: &str, url: &str) -> Result<String, ChannelError> {
        self.post("/send-richlink", &json!({"spaceId": chat, "url": url})).map(|v| self.remember(&v))
    }

    pub fn supervisor_starts(&self) -> Option<u32> {
        self.sup.as_ref().map(Supervisor::starts)
    }

    /// Flatten content (groups, replies) into (text pieces, media, reply).
    fn content(&self, msg_id: &str, c: &Value, texts: &mut Vec<String>, media: &mut Vec<Media>, reply: &mut Option<ReplyRef>) {
        match c["type"].as_str().unwrap_or("") {
            "text" => texts.extend(c["text"].as_str().filter(|t| !t.is_empty()).map(str::to_string)),
            "richlink" => {
                let url = c["url"].as_str().unwrap_or("");
                texts.push(match c["title"].as_str() {
                    Some(t) if !t.is_empty() => format!("{t} {url}"),
                    _ => url.to_string(),
                });
            }
            "attachment" | "voice" => {
                let name = c["name"].as_str().map(str::to_string).unwrap_or_else(|| format!("{}.{}", c["id"].as_str().unwrap_or("file"), if c["type"] == "voice" { "m4a" } else { "bin" }));
                let mime = c["mimeType"].as_str().map(str::to_string).unwrap_or_else(|| crate::line::guess_mime(&name).to_string());
                let path = c["data"].as_str().and_then(seagent_net::crypto::b64_decode).and_then(|bytes| {
                    let safe: String = format!("{msg_id}-{}-{name}", media.len()).chars().map(|ch| if ch.is_alphanumeric() || matches!(ch, '.' | '-' | '_') { ch } else { '_' }).collect();
                    let p = self.media_dir.join(safe);
                    crate::write_atomic(&p, &bytes).ok().map(|_| p.display().to_string())
                });
                if path.is_none() {
                    texts.push(format!("[{} {name} too large to forward]", c["type"].as_str().unwrap_or("attachment")));
                }
                media.push(Media { kind: kind_of(c), mime, size: c["size"].as_u64().unwrap_or(0), id: path.clone(), path, name, ..Default::default() });
            }
            "group" => {
                for item in c["items"].as_array().into_iter().flatten() {
                    self.content(msg_id, &item["content"], texts, media, reply);
                }
            }
            "reply" => {
                if let Some(t) = c["targetMessageId"].as_str() {
                    *reply = Some(ReplyRef { id: t.to_string(), text: c["targetText"].as_str().unwrap_or("").to_string(), is_own: c["targetDirection"] == "outbound" || self.own.lock().unwrap().iter().any(|o| o == t), ..Default::default() });
                }
                self.content(msg_id, &c["content"], texts, media, reply);
            }
            _ => {}
        }
    }

    fn inbound_of(&self, ev: &Value) -> Option<Inbound> {
        let id = ev["messageId"].as_str()?.to_string();
        let chat = ev["space"]["id"].as_str()?.to_string();
        let sender = ev["sender"]["id"].as_str().unwrap_or("").to_string();
        let c = &ev["content"];
        let ts = ev["timestamp"].as_str().and_then(crate::imessage::parse_iso).unwrap_or(0);
        let chat_type = if ev["space"]["type"] == "group" { ChatType::Group } else { ChatType::Direct };
        let base = Inbound { channel: self.id.clone(), chat: chat.clone(), chat_type, sender: sender.clone(), sender_name: sender, message_id: id.clone(), ts, ..Default::default() };
        match c["type"].as_str().unwrap_or("") {
            // Reactions, read receipts and our own poll echoes are not prompts.
            "reaction" | "read" | "poll" | "unknown" | "" => None,
            "poll_option" => {
                if c["selected"] == false {
                    return None;
                }
                let title = c["title"].as_str().unwrap_or("").to_string();
                let data = self.polls.lock().unwrap().get(&chat).and_then(|opts| opts.iter().find(|(l, _)| *l == title).map(|(_, d)| d.clone())).unwrap_or_else(|| title.clone());
                Some(Inbound { text: title, callback: Some(Callback { id: id.clone(), data }), reply: None, ..base })
            }
            _ => {
                let (mut texts, mut media, mut reply) = (Vec::new(), Vec::new(), None);
                self.content(&id, c, &mut texts, &mut media, &mut reply);
                let text = texts.join("\n");
                if text.trim().is_empty() && media.is_empty() {
                    return None;
                }
                Some(Inbound { text, media, reply, ..base })
            }
        }
    }
}

impl Channel for Photon {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: false,
            threads: false,
            reactions: 1,
            edit: false,
            delete: true,
            typing: true,
            buttons: true,
            polls: true,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
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
        Ok(got.iter().filter_map(|e| self.inbound_of(e)).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut sent = Sent::default();
        for m in &out.media {
            let (path, temp) = match (&m.path, &m.url) {
                (Some(p), _) => (std::fs::canonicalize(expand_home(p)).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?.display().to_string(), false),
                (None, Some(u)) => {
                    let bytes = crate::http::get_bytes(u, &[], 100 * 1024 * 1024)?;
                    let name = if m.name.is_empty() { u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string() } else { m.name.clone() };
                    let p = self.media_dir.join(format!("out-{}-{}", seagent_net::crypto::random_token(6), name.replace(['/', '\\'], "_")));
                    crate::write_atomic(&p, &bytes).map_err(|e| ChannelError::new(K::Fatal, format!("staging attachment: {e}")))?;
                    (p.display().to_string(), true)
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            };
            let mut body = json!({"spaceId": out.chat, "path": path, "kind": if m.kind == MediaKind::Voice { "voice" } else { "attachment" }});
            if !m.name.is_empty() {
                body["name"] = json!(m.name);
            }
            if !m.mime.is_empty() {
                body["mimeType"] = json!(m.mime);
            }
            if let Some(c) = &m.caption {
                body["caption"] = json!(c);
            }
            let r = self.post("/send-attachment", &body);
            if temp {
                let _ = std::fs::remove_file(&path);
            }
            sent.ids.push(self.remember(&r?));
        }
        let taps: Vec<&crate::Button> = out.buttons.iter().flatten().filter(|b| b.url.is_none()).collect();
        let mut text = out.text.clone();
        for b in out.buttons.iter().flatten().filter(|b| b.url.is_some()) {
            text = format!("{}\n{} {}", text.trim_end(), b.label, b.url.as_deref().unwrap_or("")).trim().to_string();
        }
        // ≥2 tap buttons become a native poll; a single one is a numbered option.
        let poll = taps.len() >= 2;
        if taps.len() == 1 {
            text = format!("{}\n\n1. {}", text.trim_end(), taps[0].label).trim().to_string();
        }
        let format = if out.format == TextFormat::Markdown { "markdown" } else { "text" };
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let n = pieces.len();
        for (i, p) in pieces.into_iter().enumerate() {
            // The last piece doubles as the poll title when it is short.
            if poll && i + 1 == n && p.chars().count() <= 300 {
                break;
            }
            let bare_url = (p.starts_with("https://") || p.starts_with("http://")) && !p.contains(char::is_whitespace);
            let v = if bare_url { self.post("/send-richlink", &json!({"spaceId": out.chat, "url": p}))? } else { self.post("/send", &json!({"spaceId": out.chat, "text": p, "format": format}))? };
            sent.ids.push(self.remember(&v));
        }
        if poll {
            let title = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars).pop().filter(|t| t.chars().count() <= 300).unwrap_or_else(|| "選擇".into());
            let labels: Vec<String> = taps.iter().map(|b| b.label.clone()).collect();
            self.polls.lock().unwrap().insert(out.chat.clone(), taps.iter().map(|b| (b.label.clone(), b.data.clone())).collect());
            sent.ids.push(self.send_poll(&out.chat, &title, &labels)?);
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        self.post("/typing", &json!({"spaceId": chat, "state": "start"})).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let key = (chat.to_string(), message_id.to_string());
        if remove {
            let rid = self.reactions.lock().unwrap().remove(&key);
            return self.post("/unreact", &json!({"spaceId": chat, "messageId": message_id, "reactionId": rid})).map(|_| ());
        }
        let v = self.post("/react", &json!({"spaceId": chat, "messageId": message_id, "emoji": emoji}))?;
        if let Some(r) = v["reactionId"].as_str() {
            self.reactions.lock().unwrap().insert(key, r.to_string());
        }
        Ok(())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.post("/unsend", &json!({"spaceId": chat, "messageId": message_id})).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let p = m.path.as_deref().ok_or_else(|| ChannelError::new(K::NotFound, "photon attachment was too large to forward"))?;
        std::fs::read(p).map_err(|e| ChannelError::new(K::NotFound, format!("photon attachment {p}: {e}")))
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(s) = &self.sup {
            let _ = self.http.call("POST", &format!("{}/shutdown", self.base), &[], Payload::Json(&json!({})));
            s.stop();
        }
    }
}

fn d_port() -> u16 {
    8789
}
fn d_node() -> String {
    "node".into()
}
fn d_poll() -> u64 {
    25
}
fn d_true() -> bool {
    true
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Supervise `node index.mjs` from this directory (after `npm install` there).
    #[serde(default)]
    pub sidecar_dir: Option<String>,
    /// An already running sidecar (default `http://127.0.0.1:<port>`).
    #[serde(default)]
    pub sidecar_url: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default = "d_node")]
    pub node: String,
    /// Shared sidecar token (generated when supervising and unset).
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub project_secret: Option<String>,
    #[serde(default = "d_true")]
    pub read_receipts: bool,
    /// Extra environment for the supervised sidecar (`PHOTON_*`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl Photon {
    /// Secrets in `st` already resolved.
    pub fn open(id: &str, st: &Settings, state_dir: &std::path::Path) -> Result<Photon, String> {
        let mut token = st.token.clone().filter(|t| !t.is_empty());
        let mut sup = None;
        if let Some(dir) = &st.sidecar_dir {
            let dir = expand_home(dir);
            let script = dir.join("index.mjs");
            if !script.is_file() {
                return Err(format!("channel {id}: {} not found (sidecar_dir should point at bridges/photon)", script.display()));
            }
            if !dir.join("node_modules").is_dir() {
                return Err(format!("channel {id}: the Photon sidecar dependencies are missing: run `npm install` in {}", dir.display()));
            }
            let (Some(pid), Some(secret)) = (st.project_id.as_deref(), st.project_secret.as_deref()) else {
                return Err(format!("channel {id}: a supervised Photon sidecar needs project_id and project_secret"));
            };
            let tok = token.get_or_insert_with(|| seagent_net::crypto::random_token(24)).clone();
            let mut env = BTreeMap::new();
            env.insert("PHOTON_READ_RECEIPTS".to_string(), st.read_receipts.to_string());
            env.extend(st.env.clone());
            for (k, v) in [("PHOTON_PROJECT_ID", pid.to_string()), ("PHOTON_PROJECT_SECRET", secret.to_string()), ("PHOTON_SIDECAR_PORT", st.port.to_string()), ("PHOTON_SIDECAR_TOKEN", tok), ("PHOTON_SIDECAR_BIND", "127.0.0.1".into())] {
                env.insert(k.into(), v);
            }
            let spec = ChildSpec { label: format!("photon sidecar ({id})"), program: st.node.clone(), args: vec![script.display().to_string()], env: env.into_iter().collect(), cwd: Some(dir), stdio: false, backoff: Duration::from_secs(2) };
            sup = Some(Supervisor::start(spec, None));
        }
        let token = token.ok_or_else(|| format!("channel {id}: photon needs the sidecar `token` (or `sidecar_dir` to supervise one)"))?;
        let base = st.sidecar_url.clone().unwrap_or_else(|| format!("http://127.0.0.1:{}", st.port)).trim_end_matches('/').to_string();
        seagent_net::Url::parse(&base).map_err(|e| format!("channel {id}: sidecar_url: {e}"))?;
        let (tx, rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let (b, t, s) = (base.clone(), token.clone(), stop.clone());
        std::thread::Builder::new().name(format!("photon inbound {id}")).spawn(move || inbound_loop(b, t, s, tx)).map_err(|e| e.to_string())?;
        Ok(Photon {
            id: id.to_string(),
            http: Http::new(Duration::from_secs(120)).with_header(TOKEN_HEADER, &token).bearer(&token),
            base,
            poll_timeout: st.poll_timeout_secs,
            media_dir: state_dir.join(format!("{id}.photon-media")),
            rx: Mutex::new(rx),
            stop,
            sup,
            own: Mutex::default(),
            polls: Mutex::default(),
            reactions: Mutex::default(),
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let mut st: Settings = ctx.settings(s)?;
    st.token = ctx.opt_secret("token", &st.token)?;
    st.project_secret = ctx.opt_secret("project_secret", &st.project_secret)?;
    Ok(Arc::new(Photon::open(ctx.name, &st, ctx.state_dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    type Seen = Arc<Mutex<Vec<(String, String, Value, Option<String>)>>>;

    /// A fake sidecar: `/inbound` streams `events` (chunked, then the connection is
    /// dropped; the reconnect gets `later` unchunked), POSTs answer by path.
    fn fake_sidecar(events: Vec<Value>, later: Vec<Value>) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Seen = Arc::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let mut inbound_n = 0;
            for conn in l.incoming() {
                let mut c = conn.unwrap();
                let (head, mut rest) = seagent_net::ws::read_head(&mut c, 64 * 1024).unwrap();
                let line = head.lines().next().unwrap_or("").to_string();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let tok = seagent_net::ws::header(&head, "x-hermes-sidecar-token").map(str::to_string);
                if tok.as_deref() != Some("TOK") {
                    let _ = c.write_all(b"HTTP/1.1 401 X\r\nContent-Length: 34\r\n\r\n{\"ok\":false,\"error\":\"unauthorized\"}");
                    continue;
                }
                if path == "/inbound" {
                    inbound_n += 1;
                    let (evs, chunked) = if inbound_n == 1 { (events.clone(), true) } else { (later.clone(), false) };
                    let mut body = String::from("\n");
                    for e in &evs {
                        body.push_str(&format!("{e}\n"));
                    }
                    if chunked {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n");
                        let _ = c.write_all(format!("{:x}\r\n{body}\r\n", body.len()).as_bytes());
                    } else {
                        let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n{body}").as_bytes());
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_secs(10));
                            drop(c);
                        });
                    }
                    continue;
                }
                let len: usize = seagent_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                while rest.len() < len {
                    let mut b = [0u8; 4096];
                    let n = c.read(&mut b).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    rest.extend_from_slice(&b[..n]);
                }
                let body: Value = serde_json::from_slice(&rest).unwrap_or_default();
                let n = {
                    let mut g = s2.lock().unwrap();
                    g.push((line.split_whitespace().next().unwrap_or("").to_string(), path.clone(), body.clone(), seagent_net::ws::header(&head, "authorization").map(str::to_string)));
                    g.len()
                };
                let (status, reply) = match path.as_str() {
                    "/react" => (200, json!({"ok": true, "reactionId": "R1"})),
                    "/probe" => (503, json!({"ok": false, "alive": false, "outcome": "inconclusive"})),
                    "/send" if body["text"] == "blocked" => (500, json!({"ok": false, "error": "internal sidecar error", "error_class": "target_not_allowed", "retryable": false})),
                    "/send" if body["text"] == "flaky" => (500, json!({"ok": false, "error": "internal sidecar error", "error_class": "upstream_transient", "retryable": true})),
                    "/unsend" if body["messageId"] == "gone" => (400, json!({"ok": false, "error": "message not found"})),
                    "/unreact" if body["reactionId"].is_null() => (400, json!({"ok": false, "error": "no tracked reaction for message"})),
                    _ => (200, json!({"ok": true, "messageId": format!("OUT{n}")})),
                };
                let s = reply.to_string();
                let _ = c.write_all(format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{s}", s.len()).as_bytes());
            }
        });
        (url, seen)
    }

    fn photon(url: &str) -> Photon {
        let st: Settings = serde_json::from_value(json!({"sidecar_url": url, "token": "TOK", "poll_timeout_secs": 1})).unwrap();
        Photon::open("ph", &st, &temp_dir("photon")).unwrap()
    }

    fn ev(id: &str, space: &str, kind: &str, content: Value) -> Value {
        json!({"messageId": id, "platform": "iMessage", "space": {"id": space, "type": kind}, "sender": {"id": "+886912345678"}, "content": content, "timestamp": "2024-05-01T10:00:00.000Z"})
    }

    #[test]
    fn inbound_stream_parses_and_reconnects() {
        let img = seagent_net::crypto::b64(b"PNGDATA");
        let (url, _) = fake_sidecar(
            vec![
                ev("M1", "any;-;+886912345678", "dm", json!({"type": "text", "text": "hi"})),
                ev("M2", "any;+;chat1", "group", json!({"type": "group", "items": [{"id": "a", "content": {"type": "text", "text": "look"}}, {"id": "b", "content": {"type": "attachment", "name": "p.png", "mimeType": "image/png", "size": 7, "data": img, "encoding": "base64"}}]})),
                ev("M3", "any;-;+886912345678", "dm", json!({"type": "reply", "content": {"type": "text", "text": "yes"}, "targetMessageId": "OUT9", "targetDirection": "outbound", "targetText": "ok?"})),
                ev("M4", "any;-;+886912345678", "dm", json!({"type": "reaction", "emoji": "👍", "targetMessageId": "OUT9"})),
                ev("M5", "any;-;+886912345678", "dm", json!({"type": "read", "targetMessageId": "OUT9"})),
                ev("M6", "any;-;+886912345678", "dm", json!({"type": "voice", "name": "v.m4a", "mimeType": "audio/mp4", "size": 99999999})),
                ev("M7", "any;-;+886912345678", "dm", json!({"type": "richlink", "url": "https://e.com", "title": "E"})),
            ],
            vec![ev("M8", "any;-;+886912345678", "dm", json!({"type": "text", "text": "after reconnect"}))],
        );
        let p = photon(&url);
        let mut g = Vec::new();
        let t = Instant::now();
        while g.len() < 6 && t.elapsed() < Duration::from_secs(5) {
            g.extend(p.poll(&Cancel::new()).unwrap());
        }
        assert_eq!(g.len(), 6, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].ts, g[0].message_id.as_str()), ("any;-;+886912345678", ChatType::Direct, "+886912345678", 1714557600, "M1"));
        assert_eq!((g[1].chat_type, g[1].text.as_str(), g[1].media[0].kind), (ChatType::Group, "look", MediaKind::Image));
        assert_eq!(p.fetch_media(&g[1].media[0]).unwrap(), b"PNGDATA");
        let r = g[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "OUT9" && g[2].text == "yes");
        assert_eq!((g[3].media[0].kind, g[3].media[0].path.is_none()), (MediaKind::Voice, true));
        assert!(g[3].text.contains("too large"));
        assert_eq!(g[4].text, "E https://e.com");
        assert_eq!(g[5].text, "after reconnect");
    }

    #[test]
    fn send_shapes_polls_reactions_and_errors() {
        let (url, seen) = fake_sidecar(vec![], vec![]);
        let p = photon(&url);
        let posts = || seen.lock().unwrap().clone();
        let s = p.send(&Outbound { format: TextFormat::Markdown, ..Outbound::text("any;-;+1", "**hi**") }).unwrap();
        assert_eq!(s.ids.len(), 1);
        let (m, path, body, auth) = posts()[0].clone();
        assert_eq!((m.as_str(), path.as_str(), auth.as_deref()), ("POST", "/send", Some("Bearer TOK")));
        assert_eq!(body, json!({"spaceId": "any;-;+1", "text": "**hi**", "format": "markdown"}));
        // Buttons → native poll titled by the text; a vote maps back to the button data.
        let b = |l: &str, d: &str| crate::Button { label: l.into(), data: d.into(), url: None };
        p.send(&Outbound { buttons: vec![vec![b("允許", "appr:1:once"), b("拒絕", "appr:1:deny")]], ..Outbound::text("any;-;+1", "Run it?") }).unwrap();
        let (_, path, body, _) = posts()[1].clone();
        assert_eq!((path.as_str(), body), ("/send-poll", json!({"spaceId": "any;-;+1", "title": "Run it?", "options": ["允許", "拒絕"]})));
        let vote = p.inbound_of(&ev("V1", "any;-;+1", "dm", json!({"type": "poll_option", "title": "拒絕", "selected": true}))).unwrap();
        assert_eq!(vote.callback.unwrap().data, "appr:1:deny");
        assert!(p.inbound_of(&ev("V2", "any;-;+1", "dm", json!({"type": "poll_option", "title": "拒絕", "selected": false}))).is_none());
        // Attachment (local) and a bare URL as rich link.
        let f = temp_dir("photon").join("a.jpg");
        std::fs::write(&f, b"JPG").unwrap();
        p.send(&Outbound { media: vec![Media { kind: MediaKind::Voice, path: Some(f.display().to_string()), caption: Some("cap".into()), ..Default::default() }], ..Outbound::text("any;-;+1", "https://e.com/x") }).unwrap();
        let ps = posts();
        assert_eq!((ps[2].1.as_str(), ps[2].2["kind"].as_str(), ps[2].2["caption"].as_str(), ps[2].2["path"].as_str()), ("/send-attachment", Some("voice"), Some("cap"), Some(std::fs::canonicalize(&f).unwrap().to_str().unwrap())));
        assert_eq!((ps[3].1.as_str(), ps[3].2["url"].as_str()), ("/send-richlink", Some("https://e.com/x")));
        p.typing("any;-;+1", None).unwrap();
        p.react("any;-;+1", "M1", "👍", false).unwrap();
        p.react("any;-;+1", "M1", "👍", true).unwrap();
        let ps = posts();
        assert_eq!(ps[4].2, json!({"spaceId": "any;-;+1", "state": "start"}));
        assert_eq!(ps[5].2, json!({"spaceId": "any;-;+1", "messageId": "M1", "emoji": "👍"}));
        assert_eq!(ps[6].2["reactionId"], "R1", "tracked reaction id used for unreact");
        assert_eq!(p.react("any;-;+1", "M9", "👍", true).unwrap_err().kind, K::Protocol);
        assert_eq!(p.send(&Outbound::text("any;-;+2", "blocked")).unwrap_err().kind, K::Fatal);
        assert_eq!(p.send(&Outbound::text("any;-;+2", "flaky")).unwrap_err().kind, K::Network);
        assert_eq!(p.probe().unwrap_err().kind, K::Network);
        p.delete("any;-;+1", "OUT1").unwrap();
        assert_eq!(posts().last().unwrap().1, "/unsend");
        assert_eq!(posts().last().unwrap().2, json!({"spaceId": "any;-;+1", "messageId": "OUT1"}));
        assert_eq!(p.delete("any;-;+1", "gone").unwrap_err().kind, K::NotFound);
        assert_eq!(p.edit("c", "m", "x").unwrap_err().kind, K::Unsupported);
        let bad = Photon::open("ph", &serde_json::from_value(json!({"sidecar_url": url, "token": "WRONG"})).unwrap(), &temp_dir("photon")).unwrap();
        assert_eq!(bad.typing("c", None).unwrap_err().kind, K::Auth);
    }

    #[cfg(unix)]
    #[test]
    fn supervision_config_and_cancel() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("photon-sup");
        std::fs::write(dir.join("index.mjs"), "// fake").unwrap();
        let st = |extra: Value| -> Settings {
            let mut v = json!({"sidecar_dir": dir.display().to_string(), "port": 1, "poll_timeout_secs": 30});
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            serde_json::from_value(v).unwrap()
        };
        assert!(Photon::open("ph", &st(json!({})), &dir).err().unwrap().contains("npm install"));
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        assert!(Photon::open("ph", &st(json!({})), &dir).err().unwrap().contains("project_id"));
        assert!(Photon::open("ph", &serde_json::from_value(json!({"sidecar_url": "http://127.0.0.1:1"})).unwrap(), &dir).err().unwrap().contains("token"));
        let log = dir.join("env");
        let node = dir.join("fake-node");
        std::fs::write(&node, format!("#!/bin/sh\necho \"$$ $1 $PHOTON_PROJECT_ID $PHOTON_PROJECT_SECRET $PHOTON_SIDECAR_PORT $PHOTON_SIDECAR_BIND ${{#PHOTON_SIDECAR_TOKEN}}\" >> {}\nexec sleep 30\n", log.display())).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = Photon::open("ph", &st(json!({"node": node.display().to_string(), "project_id": "P1", "project_secret": "SEC"})), &dir).unwrap();
        let t = Instant::now();
        while !log.exists() && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        let line = std::fs::read_to_string(&log).unwrap();
        assert!(line.contains("index.mjs P1 SEC 1 127.0.0.1 32"), "{line}");
        assert_eq!(p.supervisor_starts(), Some(1));
        // Cancel returns promptly even with a 30 s poll window.
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(p.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        let pid: i32 = line.split_whitespace().next().unwrap().parse().unwrap();
        p.stop();
        // SAFETY: probing a pid with signal 0.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "sidecar killed on stop");
    }
}
