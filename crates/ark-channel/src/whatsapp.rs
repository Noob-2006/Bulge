//! WhatsApp Web via the Baileys bridge (ported from Hermes
//! `plugins/platforms/whatsapp` + `scripts/whatsapp-bridge`, MIT).
//!
//! The bridge (`bridges/whatsapp/bridge.js`, a Node process) owns the WhatsApp
//! session; ark speaks its loopback HTTP API exactly as Hermes does:
//! `GET /messages` (drained queue, polled), `POST /send`, `/send-media`,
//! `/edit`, `/typing`, `/read`, `/send-poll`, `/send-location`,
//! `GET /chat/:id`, `/health`, `/qr` (pairing status), plus ark's `/delete`
//! (revoke for everyone) and `/react` (one emoji per message; `""` removes). Requests carry
//! `Authorization: Bearer <token>` when a shared token is configured.
//! Optional supervision: with `bridge_dir` set, ark spawns
//! `node bridge.js --port … --session … --mode …` there (never runs `npm install`),
//! restarts it with backoff when it exits and kills its process group on drop
//! (`PR_SET_PDEATHSIG` on Linux covers a crashed ark).
//! Inbound: DMs and groups, `mentionedIds` ∩ `botIds` mentions, quoted
//! replies (`quotedParticipant` ∈ `botIds` → reply to the bot), media saved by
//! the bridge to local files. Delivery-status events and owner-typed
//! (`fromOwner`) messages are skipped.

use crate::http::{classify, Http, Payload};
use crate::{sleep_cancellable, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE: usize = 4096;

#[path = "whatsapp_qr.rs"]
pub(crate) mod qr;
#[path = "whatsapp_tools.rs"]
mod tools;
pub use tools::{set_telephony_tts, TelephonyTts};

/// Which route (channel, chat, sender) an ark session belongs to; installed by the host so
/// requester-bound tools (`whatsapp_call`) can find the current requester.
pub type SessionOrigin = Arc<dyn Fn(&str) -> Option<crate::router::RouteKey> + Send + Sync>;

/// What the agent tools share with the channel.
struct Shared {
    id: String,
    base: String,
    http: Http,
    /// Restart the supervised bridge (fresh pairing after its session was cleared).
    bounce: Option<Box<dyn Fn() + Send + Sync>>,
    session: Option<PathBuf>,
    state_dir: PathBuf,
    mode: String,
    calls: bool,
    meowcaller: String,
    origin: std::sync::RwLock<Option<SessionOrigin>>,
    login_poll: Duration,
}

impl Shared {
    fn get(&self, path: &str) -> Result<Value, ChannelError> {
        let r = self.http.call("GET", &format!("{}{path}", self.base), &[], Payload::None)?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, &format!("whatsapp bridge {path}"), &r.body));
        }
        serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("whatsapp bridge {path}: bad JSON: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Child-process supervision (shared with photon and imessage).

/// How to start a supervised child.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChildSpec {
    pub label: String,
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    /// Pipe stdin/stdout to `attach` instead of logging stdout.
    pub stdio: bool,
    /// First restart delay; doubles to 30 s, resets after a minute of uptime.
    pub backoff: Duration,
}

/// Called with each freshly spawned child (take its pipes here).
pub(crate) type Attach = Arc<dyn Fn(&mut Child) + Send + Sync>;

#[derive(Default)]
struct SupState {
    stop: AtomicBool,
    running: AtomicBool,
    starts: AtomicU32,
    pid: Mutex<Option<i32>>,
    log: Mutex<VecDeque<String>>,
}

/// Keeps one child alive: restart with backoff, process-group kill on stop/drop.
pub(crate) struct Supervisor {
    st: Arc<SupState>,
}

fn push_log(st: &SupState, line: String) {
    let mut l = st.log.lock().unwrap();
    l.push_back(line);
    while l.len() > 50 {
        l.pop_front();
    }
}

fn drain_to_log(st: Arc<SupState>, r: impl std::io::Read + Send + 'static) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(r).lines().map_while(Result::ok) {
            push_log(&st, line);
        }
    });
}

impl Supervisor {
    pub fn start(spec: ChildSpec, attach: Option<Attach>) -> Supervisor {
        let st: Arc<SupState> = Arc::default();
        let s2 = st.clone();
        // The keeper thread spawns and reaps the child and lives exactly as long as it:
        // PDEATHSIG fires when the *spawning thread* exits.
        std::thread::Builder::new()
            .name(format!("supervise {}", spec.label))
            .spawn(move || {
                let base = if spec.backoff.is_zero() { Duration::from_secs(1) } else { spec.backoff };
                let mut backoff = base;
                while !s2.stop.load(Ordering::SeqCst) {
                    let mut cmd = Command::new(&spec.program);
                    cmd.args(&spec.args).envs(spec.env.iter().map(|(k, v)| (k, v))).stdout(Stdio::piped()).stderr(Stdio::piped());
                    cmd.stdin(if spec.stdio { Stdio::piped() } else { Stdio::null() });
                    if let Some(d) = &spec.cwd {
                        cmd.current_dir(d);
                    }
                    let parent = std::process::id() as i32;
                    // SAFETY: setpgid, prctl, getppid and _exit are async-signal-safe.
                    unsafe {
                        cmd.pre_exec(move || {
                            libc::setpgid(0, 0);
                            #[cfg(target_os = "linux")]
                            {
                                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                                if libc::getppid() != parent {
                                    libc::_exit(137);
                                }
                            }
                            Ok(())
                        });
                    }
                    let started = Instant::now();
                    match cmd.spawn() {
                        Err(e) => push_log(&s2, format!("cannot start `{}`: {e}", spec.program)),
                        Ok(mut child) => {
                            *s2.pid.lock().unwrap() = Some(child.id() as i32);
                            s2.starts.fetch_add(1, Ordering::SeqCst);
                            s2.running.store(true, Ordering::SeqCst);
                            if let Some(e) = child.stderr.take() {
                                drain_to_log(s2.clone(), e);
                            }
                            match &attach {
                                Some(a) if spec.stdio => a(&mut child),
                                _ => {
                                    if let Some(o) = child.stdout.take() {
                                        drain_to_log(s2.clone(), o);
                                    }
                                }
                            }
                            let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                            *s2.pid.lock().unwrap() = None;
                            s2.running.store(false, Ordering::SeqCst);
                            push_log(&s2, format!("{} exited: {status}", spec.label));
                        }
                    }
                    if started.elapsed() > Duration::from_secs(60) {
                        backoff = base;
                    }
                    let until = Instant::now() + backoff;
                    while Instant::now() < until && !s2.stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            })
            .expect("spawn supervisor thread");
        Supervisor { st }
    }

    pub fn running(&self) -> bool {
        self.st.running.load(Ordering::SeqCst)
    }

    /// How many times the child has been started.
    pub fn starts(&self) -> u32 {
        self.st.starts.load(Ordering::SeqCst)
    }

    pub fn pid(&self) -> Option<i32> {
        *self.st.pid.lock().unwrap()
    }

    /// SIGTERM the current child's process group; the keeper restarts it after the backoff.
    pub fn bouncer(&self) -> Box<dyn Fn() + Send + Sync> {
        let st = self.st.clone();
        Box::new(move || {
            if let Some(pid) = *st.pid.lock().unwrap() {
                // SAFETY: plain kill(2) on the child's process group.
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
            }
        })
    }

    /// The child's last output lines (for error messages).
    pub fn last_log(&self, n: usize) -> String {
        let l = self.st.log.lock().unwrap();
        l.iter().skip(l.len().saturating_sub(n)).cloned().collect::<Vec<_>>().join(" | ")
    }

    /// Stop restarting; SIGTERM the process group, SIGKILL after 1.5 s.
    pub fn stop(&self) {
        self.st.stop.store(true, Ordering::SeqCst);
        let Some(pid) = self.pid() else { return };
        // SAFETY: plain kill(2) on the child's process group.
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
        let until = Instant::now() + Duration::from_millis(1500);
        while self.running() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.running() {
            // SAFETY: as above.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `~/x` → `$HOME/x`.
pub(crate) fn expand_home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(h)) => PathBuf::from(h).join(rest),
        _ => PathBuf::from(p),
    }
}

/// GET on a worker thread so a wedged peer never delays cancellation. `Ok(None)` = cancelled.
pub(crate) fn get_cancellable(http: &Http, url: &str, cancel: &Cancel) -> Result<Option<crate::http::Resp>, ChannelError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (h, u) = (http.clone(), url.to_string());
    std::thread::spawn(move || {
        let _ = tx.send(h.call("GET", &u, &[], Payload::None));
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

// ---------------------------------------------------------------------------
// The channel.

/// `123:4@lid` → `123@lid` (device-qualified ids equal their bare form).
fn norm_id(s: &str) -> String {
    let s = s.trim();
    match (s.find(':'), s.find('@')) {
        (Some(c), Some(a)) if c < a && s[c + 1..a].chars().all(|ch| ch.is_ascii_digit()) => format!("{}{}", &s[..c], &s[a..]),
        _ => s.to_string(),
    }
}

fn ts_of(v: &Value) -> i64 {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).or_else(|| v["low"].as_i64()).unwrap_or(0)
}

fn kind_of(t: &str, mime: &str) -> MediaKind {
    match t {
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "ptt" | "voice" => MediaKind::Voice,
        "audio" => MediaKind::Audio,
        "sticker" => MediaKind::Sticker,
        "gif" => MediaKind::Animation,
        _ if mime.starts_with("image/") => MediaKind::Image,
        _ => MediaKind::Document,
    }
}

/// One bridge event → Inbound.
fn inbound_of(channel: &str, d: &Value) -> Option<Inbound> {
    if d.get("event").is_some() || d["fromOwner"] == true || d["mediaType"] == "reaction" {
        return None;
    }
    let chat = d["chatId"].as_str().filter(|c| !c.is_empty())?.to_string();
    let lower = chat.to_ascii_lowercase();
    // Status broadcasts and newsletters are not conversations.
    if lower.ends_with("@broadcast") || lower.ends_with("@newsletter") {
        return None;
    }
    let bots: Vec<String> = d["botIds"].as_array().into_iter().flatten().filter_map(Value::as_str).map(norm_id).filter(|s| !s.is_empty()).collect();
    let body = d["body"].as_str().unwrap_or("").to_string();
    let mentioned = d["mentionedIds"].as_array().into_iter().flatten().filter_map(Value::as_str).any(|m| bots.contains(&norm_id(m))) || {
        let lb = body.to_lowercase();
        bots.iter().any(|b| b.split('@').next().is_some_and(|bare| !bare.is_empty() && lb.contains(&format!("@{}", bare.to_lowercase()))))
    };
    let mime = d["mime"].as_str().unwrap_or("").to_string();
    let mt = d["mediaType"].as_str().unwrap_or("");
    let media: Vec<Media> = d["mediaUrls"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|p| {
        let remote = p.starts_with("http://") || p.starts_with("https://");
        let name = d["fileName"].as_str().map(str::to_string).unwrap_or_else(|| crate::line::file_name(p));
        Media { kind: kind_of(mt, &mime), mime: if mime.is_empty() { crate::line::guess_mime(&name).to_string() } else { mime.clone() }, name, id: Some(p.to_string()), url: remote.then(|| p.to_string()), path: (!remote).then(|| p.to_string()), ..Default::default() }
    }).collect();
    // The bridge's "[image received]" placeholder adds nothing next to the attachment.
    let text = if !media.is_empty() && body == format!("[{mt} received]") { String::new() } else { body };
    let reply = (d["hasQuotedMessage"] == true || d["quotedMessageId"].is_string()).then(|| {
        let author = norm_id(d["quotedParticipant"].as_str().unwrap_or(""));
        ReplyRef { id: d["quotedMessageId"].as_str().unwrap_or("").to_string(), text: d["quotedText"].as_str().unwrap_or("").to_string(), is_own: !author.is_empty() && bots.contains(&author), author }
    }).filter(|r| !r.id.is_empty());
    let is_group = d["isGroup"] == true || lower.ends_with("@g.us");
    Some(Inbound {
        channel: channel.to_string(),
        chat,
        chat_type: if is_group { ChatType::Group } else { ChatType::Direct },
        chat_name: if is_group { d["chatName"].as_str().unwrap_or("").to_string() } else { String::new() },
        sender: d["senderId"].as_str().unwrap_or("").to_string(),
        sender_name: d["senderName"].as_str().unwrap_or("").to_string(),
        text,
        message_id: d["messageId"].as_str()?.to_string(),
        ts: ts_of(&d["timestamp"]),
        media,
        mentioned,
        reply,
        ..Default::default()
    })
}

pub struct WhatsApp {
    id: String,
    base: String,
    http: Http,
    poll_timeout: u64,
    pub poll_interval: Duration,
    read_receipts: bool,
    tmp: PathBuf,
    sup: Option<Supervisor>,
    shared: Arc<Shared>,
}

impl WhatsApp {
    fn url(&self, p: &str) -> String {
        format!("{}{p}", self.base)
    }

    fn bridge_err(&self, status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
        let msg = serde_json::from_str::<Value>(body).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_else(|| body.chars().take(200).collect());
        let mut e = classify(status, retry_after, what, "");
        e.message = format!("whatsapp bridge {what}: HTTP {status} {}", crate::sms::redact_phones_in(&msg));
        if status == 404 && msg.starts_with("File not found") {
            e.kind = K::Fatal;
        }
        e
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, ChannelError> {
        let r = self.http.call("POST", &self.url(path), &[], Payload::Json(body)).map_err(|e| self.down(e))?;
        if !(200..300).contains(&r.status) {
            return Err(self.bridge_err(r.status, r.retry_after, path, &r.body));
        }
        let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        if v["success"] == false {
            return Err(ChannelError::new(K::Network, format!("whatsapp bridge {path}: {}", v["error"].as_str().unwrap_or("failed"))));
        }
        Ok(v)
    }

    fn get(&self, path: &str) -> Result<Value, ChannelError> {
        let r = self.http.call("GET", &self.url(path), &[], Payload::None).map_err(|e| self.down(e))?;
        if !(200..300).contains(&r.status) {
            return Err(self.bridge_err(r.status, r.retry_after, path, &r.body));
        }
        serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("whatsapp bridge {path}: bad JSON: {e}")))
    }

    /// A transport error, annotated with the supervised bridge's last words.
    fn down(&self, e: ChannelError) -> ChannelError {
        match &self.sup {
            Some(s) if !s.running() => ChannelError::new(K::Network, format!("whatsapp bridge is not running ({}): {}", e.message, s.last_log(3))),
            _ => e,
        }
    }

    /// `GET /health`: `{status: "connected"|"disconnected", queueLength, qrPending, …}`.
    pub fn health(&self) -> Result<Value, ChannelError> {
        self.get("/health")
    }

    /// `GET /qr`: `{status, qr}` — `qr` is the pairing payload while a scan is needed.
    pub fn qr(&self) -> Result<Value, ChannelError> {
        self.get("/qr")
    }

    /// `GET /chat/:id`: `{name, isGroup, participants}`.
    pub fn chat_info(&self, chat: &str) -> Result<Value, ChannelError> {
        self.get(&format!("/chat/{}", ark_net::urlencode(chat)))
    }

    pub fn send_poll(&self, chat: &str, question: &str, options: &[String], selectable: u32) -> Result<String, ChannelError> {
        let v = self.post("/send-poll", &json!({"chatId": chat, "question": question, "options": options, "selectableCount": selectable.max(1)}))?;
        Ok(v["messageId"].as_str().unwrap_or("").to_string())
    }

    pub fn send_location(&self, chat: &str, lat: f64, lon: f64, name: Option<&str>, address: Option<&str>) -> Result<String, ChannelError> {
        let v = self.post("/send-location", &json!({"chatId": chat, "latitude": lat, "longitude": lon, "name": name, "address": address}))?;
        Ok(v["messageId"].as_str().unwrap_or("").to_string())
    }

    /// Route lookup for requester-bound tools (see [`SessionOrigin`]).
    pub fn set_session_origin(&self, f: SessionOrigin) {
        *self.shared.origin.write().unwrap() = Some(f);
    }

    pub fn supervisor_starts(&self) -> Option<u32> {
        self.sup.as_ref().map(Supervisor::starts)
    }

    fn send_media(&self, chat: &str, m: &Media, caption: Option<&str>) -> Result<String, ChannelError> {
        let media_type = match m.kind {
            MediaKind::Image | MediaKind::Animation | MediaKind::Sticker => "image",
            MediaKind::Video => "video",
            MediaKind::Audio | MediaKind::Voice => "audio",
            MediaKind::Document => "document",
        };
        // The bridge reads local files; remote media is fetched into a temp file first.
        let (path, temp) = match (&m.path, &m.url) {
            (Some(p), _) => (std::fs::canonicalize(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?, false),
            (None, Some(u)) => {
                let bytes = crate::http::get_bytes(u, &[], 64 * 1024 * 1024)?;
                let name = if m.name.is_empty() { u.rsplit('/').next().unwrap_or("file").split('?').next().unwrap_or("file").to_string() } else { m.name.clone() };
                let p = self.tmp.join(format!("{}-{}", ark_net::crypto::random_token(6), name.replace(['/', '\\'], "_")));
                crate::write_atomic(&p, &bytes).map_err(|e| ChannelError::new(K::Fatal, format!("staging attachment: {e}")))?;
                (p, true)
            }
            _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        };
        let mut body = json!({"chatId": chat, "filePath": path.display().to_string(), "mediaType": media_type});
        if let Some(c) = caption.or(m.caption.as_deref()).filter(|c| !c.is_empty()) {
            body["caption"] = json!(c);
        }
        if !m.name.is_empty() {
            body["fileName"] = json!(m.name);
        }
        let r = self.post("/send-media", &body);
        if temp {
            let _ = std::fs::remove_file(&path);
        }
        Ok(r?["messageId"].as_str().unwrap_or("").to_string())
    }
}

impl Channel for WhatsApp {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: false,
            reactions: 1,
            edit: true,
            delete: true,
            typing: true,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut last_err: Option<ChannelError>;
        loop {
            match get_cancellable(&self.http, &self.url("/messages"), cancel) {
                Ok(None) => return Ok(vec![]),
                Ok(Some(r)) if (200..300).contains(&r.status) => {
                    last_err = None;
                    let v: Value = serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("whatsapp bridge /messages: bad JSON: {e}")))?;
                    let got: Vec<(Inbound, Value)> = v.as_array().into_iter().flatten().filter_map(|d| inbound_of(&self.id, d).map(|i| (i, d["readReceiptKey"].clone()))).collect();
                    if !got.is_empty() {
                        if self.read_receipts {
                            let keys: Vec<Value> = got.iter().map(|(_, k)| k.clone()).filter(Value::is_object).collect();
                            let (h, u) = (self.http.clone(), self.url("/read"));
                            std::thread::spawn(move || {
                                for k in keys {
                                    let _ = h.call("POST", &u, &[], Payload::Json(&json!({"key": k})));
                                }
                            });
                        }
                        return Ok(got.into_iter().map(|(i, _)| i).collect());
                    }
                }
                Ok(Some(r)) => {
                    let e = self.bridge_err(r.status, r.retry_after, "/messages", &r.body);
                    if !e.is_retryable() {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
                // The bridge may be (re)starting: keep trying within this poll window.
                Err(e) => last_err = Some(self.down(e)),
            }
            if Instant::now() >= until {
                return match last_err {
                    Some(e) => Err(e),
                    None => Ok(vec![]),
                };
            }
            if !sleep_cancellable(self.poll_interval.min(until.saturating_duration_since(Instant::now())), cancel) {
                return Ok(vec![]);
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut sent = Sent::default();
        let render = |t: &str| match out.format {
            TextFormat::Markdown => crate::whatsapp_cloud::to_whatsapp(t),
            TextFormat::Plain => t.to_string(),
        };
        let mut text = render(&out.text);
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let caption_fits = out.media.len() == 1 && text.chars().count() <= 1024 && !matches!(out.media[0].kind, MediaKind::Audio | MediaKind::Voice);
        for (i, m) in out.media.iter().enumerate() {
            let cap = (caption_fits && i == 0).then_some(text.as_str()).filter(|t| !t.trim().is_empty());
            sent.ids.push(self.send_media(&out.chat, m, cap.map(str::to_string).as_deref())?);
        }
        if caption_fits {
            return Ok(sent);
        }
        for (i, piece) in crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars).into_iter().enumerate() {
            let mut body = json!({"chatId": out.chat, "message": piece});
            if let (0, Some(r)) = (i, out.reply_to.as_deref()) {
                if out.media.is_empty() {
                    body["replyTo"] = json!(r);
                }
            }
            let v = self.post("/send", &body)?;
            match v["messageIds"].as_array() {
                Some(ids) if !ids.is_empty() => sent.ids.extend(ids.iter().filter_map(Value::as_str).map(str::to_string)),
                _ => sent.ids.extend(v["messageId"].as_str().map(str::to_string)),
            }
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.post("/edit", &json!({"chatId": chat, "messageId": message_id, "message": crate::whatsapp_cloud::to_whatsapp(text)})).map(|_| ())
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        self.post("/typing", &json!({"chatId": chat})).map(|_| ())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.post("/delete", &json!({"chatId": chat, "messageId": message_id})).map(|_| ())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let emoji = if remove { "" } else { emoji.trim() };
        if !remove && emoji.is_empty() {
            return Err(ChannelError::new(K::Fatal, "whatsapp: empty reaction emoji"));
        }
        self.post("/react", &json!({"chatId": chat, "messageId": message_id, "emoji": emoji})).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        match (&m.path, &m.url) {
            (Some(p), _) => std::fs::read(p).map_err(|e| ChannelError::new(K::NotFound, format!("bridge media {p}: {e}"))),
            (None, Some(u)) => crate::http::get_bytes(u, &[], 64 * 1024 * 1024),
            _ => Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
        }
    }

    fn wire(&self, w: &crate::Wiring) {
        if let Some(o) = &w.session_origin {
            self.set_session_origin(o.clone());
        }
    }

    /// `whatsapp_login`, plus `whatsapp_call` when `actions.calls` is on.
    fn tools(&self) -> Vec<Arc<dyn ark_core::Tool>> {
        tools::tools(&self.shared)
    }

    fn stop(&self) {
        if let Some(s) = &self.sup {
            s.stop();
        }
    }
}

fn d_port() -> u16 {
    3000
}
fn d_node() -> String {
    "node".into()
}
fn d_mode() -> String {
    "self-chat".into()
}
fn d_poll() -> u64 {
    25
}
fn d_interval() -> u64 {
    1000
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Where the bridge listens (default `http://127.0.0.1:<port>`).
    #[serde(default)]
    pub bridge_url: Option<String>,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Supervise `node bridge.js` from this directory (after `npm install` there).
    #[serde(default)]
    pub bridge_dir: Option<String>,
    #[serde(default = "d_node")]
    pub node: String,
    #[serde(default)]
    pub session_dir: Option<String>,
    /// `self-chat` (talk to yourself) or `bot` (a dedicated number).
    #[serde(default = "d_mode")]
    pub mode: String,
    /// Shared bearer token (generated when supervising and unset).
    #[serde(default)]
    pub token: Option<String>,
    /// Extra environment for the supervised bridge (`WHATSAPP_*`).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Ask the bridge to send read receipts for accepted messages.
    #[serde(default)]
    pub read_receipts: bool,
    #[serde(default = "d_interval")]
    pub poll_interval_ms: u64,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
    /// Opt-in agent actions (OpenClaw `channels.whatsapp.actions`): `calls` enables `whatsapp_call`.
    #[serde(default)]
    pub actions: BTreeMap<String, bool>,
    /// MeowCaller binary for `whatsapp_call` (default `meowcaller` on PATH).
    #[serde(default)]
    pub meowcaller: Option<String>,
}

impl WhatsApp {
    /// `st.token` already resolved; `state_dir` holds the session and media caches.
    pub fn open(id: &str, st: &Settings, state_dir: &std::path::Path) -> Result<WhatsApp, String> {
        let mut token = st.token.clone().filter(|t| !t.is_empty());
        let mut sup = None;
        let mut session_dir = None;
        if let Some(dir) = &st.bridge_dir {
            let dir = expand_home(dir);
            let script = dir.join("bridge.js");
            if !script.is_file() {
                return Err(format!("channel {id}: {} not found (bridge_dir should point at bridges/whatsapp)", script.display()));
            }
            if !dir.join("node_modules").is_dir() {
                return Err(format!("channel {id}: the WhatsApp bridge dependencies are missing: run `npm install` in {}", dir.display()));
            }
            let tok = token.get_or_insert_with(|| ark_net::crypto::random_token(24)).clone();
            let session = st.session_dir.as_deref().map(expand_home).unwrap_or_else(|| state_dir.join(format!("{id}.whatsapp-session")));
            session_dir = Some(session.clone());
            let media = state_dir.join(format!("{id}.whatsapp-media"));
            let mut env: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in [("WHATSAPP_ALLOWED_USERS", "*"), ("WHATSAPP_DM_POLICY", "open"), ("WHATSAPP_GROUP_POLICY", "open"), ("WHATSAPP_SEND_READ_RECEIPTS", if st.read_receipts { "true" } else { "false" })] {
                env.insert(k.into(), v.into());
            }
            for (k, sub) in [("HERMES_IMAGE_CACHE_DIR", "image"), ("HERMES_DOCUMENT_CACHE_DIR", "document"), ("HERMES_AUDIO_CACHE_DIR", "audio")] {
                env.insert(k.into(), media.join(sub).display().to_string());
            }
            env.extend(st.env.clone());
            env.insert("ARK_WHATSAPP_BRIDGE_TOKEN".into(), tok);
            let spec = ChildSpec {
                label: format!("whatsapp bridge ({id})"),
                program: st.node.clone(),
                args: vec![script.display().to_string(), "--port".into(), st.port.to_string(), "--session".into(), session.display().to_string(), "--mode".into(), st.mode.clone()],
                env: env.into_iter().collect(),
                cwd: Some(dir),
                stdio: false,
                backoff: Duration::from_secs(2),
            };
            sup = Some(Supervisor::start(spec, None));
        }
        let mut http = Http::new(Duration::from_secs(90));
        if let Some(t) = &token {
            http = http.bearer(t);
        }
        let base = st.bridge_url.clone().unwrap_or_else(|| format!("http://127.0.0.1:{}", st.port)).trim_end_matches('/').to_string();
        let shared = Arc::new(Shared {
            id: id.to_string(),
            base: base.clone(),
            http: http.clone(),
            bounce: sup.as_ref().map(Supervisor::bouncer),
            session: session_dir,
            state_dir: state_dir.to_path_buf(),
            mode: st.mode.clone(),
            calls: st.actions.get("calls").copied().unwrap_or(false),
            meowcaller: st.meowcaller.clone().filter(|m| !m.trim().is_empty()).unwrap_or_else(|| tools::MEOWCALLER.into()),
            origin: std::sync::RwLock::new(None),
            login_poll: Duration::from_millis(500),
        });
        Ok(WhatsApp {
            id: id.to_string(),
            base,
            http,
            poll_timeout: st.poll_timeout_secs,
            poll_interval: Duration::from_millis(st.poll_interval_ms.max(50)),
            read_receipts: st.read_receipts,
            tmp: state_dir.join(format!("{id}.whatsapp-outbox")),
            sup,
            shared,
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let mut st: Settings = ctx.settings(s)?;
    st.token = ctx.opt_secret("token", &st.token)?;
    Ok(Arc::new(WhatsApp::open(ctx.name, &st, ctx.state_dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    fn wa(url: &str, extra: Value) -> WhatsApp {
        let mut v = json!({"bridge_url": url, "token": "BT", "poll_timeout_secs": 1, "poll_interval_ms": 50});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        WhatsApp::open("wa", &serde_json::from_value(v).unwrap(), &temp_dir("wa")).unwrap()
    }

    #[test]
    fn polls_and_parses_bridge_events() {
        let media = temp_dir("wa").join("img_1.jpg");
        std::fs::write(&media, b"JPEG").unwrap();
        let mp = media.display().to_string();
        let mp2 = mp.clone();
        let srv = FakeServer::start(move |req, n| {
            let mp = mp2.clone();
            if req.path == "/read" {
                return (200, vec![], json!({"success": true, "marked": true}).to_string());
            }
            let bots = json!(["15550001111@s.whatsapp.net", "99887766:12@lid"]);
            match n {
                0 => (200, vec![], json!([{"event": "delivery_status", "messageId": "X", "status": "read"}]).to_string()),
                _ if n == 1 || n == 2 => (200, vec![], json!([
                    {"messageId": "M1", "chatId": "886912345678@s.whatsapp.net", "senderId": "886912345678@s.whatsapp.net", "senderName": "Amy", "isGroup": false, "body": "hi", "botIds": bots, "timestamp": 1700000000, "readReceiptKey": {"id": "M1", "remoteJid": "886912345678@s.whatsapp.net"}},
                    {"messageId": "M2", "chatId": "1203@g.us", "chatName": "Team", "senderId": "886@s.whatsapp.net", "isGroup": true, "body": "@99887766 go", "mentionedIds": ["99887766:3@lid"], "botIds": bots, "timestamp": {"low": 1700000001, "high": 0}},
                    {"messageId": "M3", "chatId": "1203@g.us", "senderId": "886@s.whatsapp.net", "isGroup": true, "body": "yes", "hasQuotedMessage": true, "quotedMessageId": "OUT1", "quotedParticipant": "15550001111@s.whatsapp.net", "quotedText": "ok?", "botIds": bots},
                    {"messageId": "M4", "chatId": "1203@g.us", "senderId": "886@s.whatsapp.net", "isGroup": true, "body": "[image received]", "hasMedia": true, "mediaType": "image", "mime": "image/jpeg", "mediaUrls": [mp], "botIds": bots},
                    {"messageId": "M5", "chatId": "886912345678@s.whatsapp.net", "senderId": "x", "body": "owner typed", "fromOwner": true},
                    {"messageId": "M6", "chatId": "status@broadcast", "senderId": "x", "body": "story"},
                    {"messageId": "M7", "chatId": "1203@g.us", "senderId": "886@s.whatsapp.net", "isGroup": true, "body": "plain", "botIds": bots}
                ]).to_string()),
                _ => (200, vec![], "[]".into()),
            }
        });
        let w = wa(&srv.url, json!({"read_receipts": true}));
        let g = w.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 5, "{g:#?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender_name.as_str(), g[0].ts), ("886912345678@s.whatsapp.net", ChatType::Direct, "Amy", 1700000000));
        assert!(g[1].mentioned && g[1].chat_type == ChatType::Group && g[1].chat_name == "Team" && g[1].ts == 1700000001);
        let r = g[2].reply.as_ref().unwrap();
        assert!(r.is_own && r.id == "OUT1" && r.text == "ok?" && !g[2].mentioned);
        assert_eq!((g[3].text.as_str(), g[3].media[0].kind, g[3].media[0].path.as_deref()), ("", MediaKind::Image, Some(mp.as_str())));
        assert_eq!(w.fetch_media(&g[3].media[0]).unwrap(), b"JPEG");
        assert!(!g[4].mentioned && g[4].reply.is_none());
        let reqs = srv.requests();
        assert_eq!(reqs[0].header("authorization"), Some("Bearer BT"));
        assert_eq!((reqs[0].path.as_str(), reqs[1].path.as_str()), ("/messages", "/messages"), "empty batch → poll again");
        std::thread::sleep(Duration::from_millis(200));
        let reads: Vec<Value> = srv.requests().iter().filter(|r| r.path == "/read").map(|r| r.json()).collect();
        assert_eq!(reads, vec![json!({"key": {"id": "M1", "remoteJid": "886912345678@s.whatsapp.net"}})]);
    }

    #[test]
    fn send_edit_typing_media_and_extras() {
        let srv = FakeServer::start(|req, n| match req.path.as_str() {
            "/file.pdf" => (200, vec![], "%PDF".into()),
            "/health" => (200, vec![], json!({"status": "connected", "queueLength": 0, "qrPending": false}).to_string()),
            "/qr" => (200, vec![], json!({"status": "disconnected", "qr": "2@abc"}).to_string()),
            p if p.starts_with("/chat/") => (200, vec![], json!({"name": "Team", "isGroup": true, "participants": []}).to_string()),
            "/send-media" => {
                let fp = req.json()["filePath"].as_str().unwrap().to_string();
                assert!(std::path::Path::new(&fp).exists(), "staged file exists during the call");
                (200, vec![], json!({"success": true, "messageId": format!("MED{n}")}).to_string())
            }
            _ => (200, vec![], json!({"success": true, "messageId": format!("S{n}"), "messageIds": [format!("S{n}")]}).to_string()),
        });
        let w = wa(&srv.url, json!({}));
        let s = w.send(&Outbound { format: TextFormat::Markdown, reply_to: Some("IN1".into()), buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("886@s.whatsapp.net", "**ok** ~~x~~") }).unwrap();
        assert_eq!(s.ids, vec!["S0"]);
        let r = srv.requests()[0].clone();
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/send", Some("Bearer BT")));
        assert_eq!(r.json(), json!({"chatId": "886@s.whatsapp.net", "message": "*ok* ~x~\n\n1. Yes", "replyTo": "IN1"}));
        let f = temp_dir("wa").join("pic.png");
        std::fs::write(&f, b"PNG").unwrap();
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("c", "cap") }).unwrap();
        let j = srv.requests()[1].json();
        assert_eq!((j["mediaType"].as_str(), j["caption"].as_str(), j["filePath"].as_str()), (Some("image"), Some("cap"), Some(std::fs::canonicalize(&f).unwrap().to_str().unwrap())));
        // Remote media is staged locally, sent, then removed.
        w.send(&Outbound { media: vec![Media { kind: MediaKind::Document, url: Some(format!("{}/file.pdf", srv.url)), name: "r.pdf".into(), ..Default::default() }], ..Outbound::text("c", "") }).unwrap();
        let j = srv.requests().iter().rev().find(|r| r.path == "/send-media").unwrap().json();
        assert_eq!((j["mediaType"].as_str(), j["fileName"].as_str()), (Some("document"), Some("r.pdf")));
        assert!(!std::path::Path::new(j["filePath"].as_str().unwrap()).exists(), "staged copy cleaned up");
        // Long text is chunked; only the first chunk quotes.
        let s = w.send(&Outbound { reply_to: Some("Q".into()), ..Outbound::text("c", &"y ".repeat(3000)) }).unwrap();
        assert_eq!(s.ids.len(), 2);
        let sends: Vec<Value> = srv.requests().iter().filter(|r| r.path == "/send").map(|r| r.json()).collect();
        assert!(sends[1]["replyTo"] == "Q" && sends[2].get("replyTo").is_none());
        w.edit("c", "S0", "**new**").unwrap();
        w.typing("c", None).unwrap();
        let n = srv.requests().len();
        assert_eq!(srv.requests()[n - 2].json(), json!({"chatId": "c", "messageId": "S0", "message": "*new*"}));
        assert_eq!(srv.requests()[n - 1].json(), json!({"chatId": "c"}));
        w.delete("c", "S0").unwrap();
        w.react("c", "IN1", "👍", false).unwrap();
        w.react("c", "IN1", "👍", true).unwrap();
        assert_eq!(w.react("c", "IN1", " ", false).unwrap_err().kind, K::Fatal);
        let reqs = srv.requests();
        let n = reqs.len();
        assert_eq!((reqs[n - 3].path.as_str(), reqs[n - 3].json()), ("/delete", json!({"chatId": "c", "messageId": "S0"})));
        assert_eq!((reqs[n - 2].path.as_str(), reqs[n - 2].json()), ("/react", json!({"chatId": "c", "messageId": "IN1", "emoji": "👍"})));
        assert_eq!(reqs[n - 1].json()["emoji"], "");
        assert!(w.caps().delete && w.caps().reactions == 1);
        assert_eq!(w.health().unwrap()["status"], "connected");
        assert_eq!(w.qr().unwrap()["qr"], "2@abc");
        assert_eq!(w.chat_info("1203@g.us").unwrap()["name"], "Team");
        assert_eq!(srv.requests().last().unwrap().path, "/chat/1203%40g.us");
        w.send_poll("c", "Q?", &["a".into(), "b".into()], 1).unwrap();
        w.send_location("c", 25.0, 121.5, Some("Office"), None).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[reqs.len() - 2].json()["options"], json!(["a", "b"]));
        assert_eq!((reqs[reqs.len() - 1].path.as_str(), reqs[reqs.len() - 1].json()["latitude"].as_f64()), ("/send-location", Some(25.0)));
    }

    #[test]
    fn errors_map_and_dead_bridge_is_network() {
        for (status, kind) in [(401, K::Auth), (503, K::Network), (400, K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"error": "Not connected to WhatsApp +886912345678"}).to_string()));
            let e = wa(&srv.url, json!({})).send(&Outbound::text("c", "x")).unwrap_err();
            assert_eq!(e.kind, kind);
            assert!(e.message.contains("Not connected") && !e.message.contains("912345678"), "{}", e.message);
        }
        let srv = FakeServer::start(|_, _| (404, vec![], json!({"error": "File not found: /x"}).to_string()));
        assert_eq!(wa(&srv.url, json!({})).send(&Outbound { media: vec![Media { url: None, path: Some("/etc/hostname".into()), ..Default::default() }], ..Outbound::text("c", "") }).unwrap_err().kind, K::Fatal);
        let srv = FakeServer::start(|_, _| (401, vec![], json!({"error": "unauthorized"}).to_string()));
        assert_eq!(wa(&srv.url, json!({})).poll(&Cancel::new()).unwrap_err().kind, K::Auth, "auth is not retried in the poll window");
        let t = Instant::now();
        let e = wa("http://127.0.0.1:1", json!({})).poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert!(t.elapsed() >= Duration::from_millis(900), "retried for the poll window");
    }

    #[test]
    fn cancel_interrupts_poll() {
        let srv = FakeServer::start(|_, _| (200, vec![], "[]".into()));
        let w = wa(&srv.url, json!({"poll_timeout_secs": 30}));
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    fn fake_node(dir: &std::path::Path, script: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fake-node");
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[test]
    fn supervises_bridge_restarts_and_kills_on_drop() {
        let dir = temp_dir("wa-sup");
        std::fs::write(dir.join("bridge.js"), "// fake").unwrap();
        let state = temp_dir("wa-state");
        let st = |node: &str| -> Settings { serde_json::from_value(json!({"bridge_dir": dir.display().to_string(), "node": node, "port": 1, "mode": "bot", "poll_timeout_secs": 1})).unwrap() };
        let e = WhatsApp::open("wa", &st("node"), &state).err().unwrap();
        assert!(e.contains("npm install"), "{e}");
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        // First run fails at once; the restart stays up and records its pid, args and token.
        let log = dir.join("runs");
        let node = fake_node(&dir, &format!("echo \"$$ $* $ARK_WHATSAPP_BRIDGE_TOKEN $WHATSAPP_ALLOWED_USERS\" >> {0}\n[ $(wc -l < {0}) -ge 2 ] || exit 3\nexec sleep 30", log.display()));
        let mut s = st(&node);
        s.token = Some("SHARED".into());
        let w = WhatsApp::open("wa", &s, &state).unwrap();
        let sup = w.sup.as_ref().unwrap();
        let t = Instant::now();
        while (sup.starts() < 2 || !sup.running()) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(w.supervisor_starts(), Some(2), "restarted after exit: {}", sup.last_log(5));
        std::thread::sleep(Duration::from_millis(200));
        let runs = std::fs::read_to_string(&log).unwrap();
        let line = runs.lines().nth(1).unwrap();
        assert!(line.contains("bridge.js --port 1 --session") && line.contains("--mode bot SHARED *"), "{line}");
        let pid: i32 = line.split_whitespace().next().unwrap().parse().unwrap();
        // SAFETY: probing a pid with signal 0.
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "child alive");
        drop(w);
        let t = Instant::now();
        // SAFETY: as above.
        while unsafe { libc::kill(pid, 0) } == 0 && t.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: as above.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "child killed when the channel is dropped");
    }

    /// OpenClaw `agent-tools-login.test.ts` / `login-qr.test.ts` against a fake bridge:
    /// start returns a scannable PNG data URL, wait reports refresh and success,
    /// already-linked short-circuits, force without supervision refuses.
    #[test]
    fn login_tool_start_wait_and_relink_guard() {
        let n = Arc::new(AtomicU32::new(0));
        let n2 = n.clone();
        let srv = FakeServer::start(move |req, _| {
            assert_eq!(req.header("authorization"), Some("Bearer BT"));
            let i = n2.fetch_add(1, Ordering::SeqCst);
            let body = match i {
                0 => json!({"status": "disconnected", "qr": null}),
                1 | 2 => json!({"status": "disconnected", "qr": "2@first,KEY1,KEY2,ADV"}),
                3 => json!({"status": "disconnected", "qr": "2@second,KEY1,KEY2,ADV"}),
                _ => json!({"status": "connected", "qr": null}),
            };
            (200, vec![], body.to_string())
        });
        let w = wa(&srv.url, json!({}));
        let mut tools = w.tools();
        assert_eq!(tools.len(), 1, "whatsapp_call is opt-in");
        let login = tools.remove(0);
        assert_eq!(login.spec().name, "whatsapp_login_wa");
        assert!(matches!(login.effects(&crate::testutil::tool_ctx(), &json!({"action": "start"}))[0], ark_core::Effect::Remote { .. }));
        let ctx = crate::testutil::tool_ctx();
        // /qr #0: no code yet → polled again (#1) → QR.
        let r = login.call(&ctx, json!({"action": "start", "timeoutMs": 3000}));
        assert!(!r.is_error && r.content.starts_with("Scan this QR in WhatsApp → Linked Devices."), "{}", r.content);
        let url = r.content.split("![whatsapp-qr](").nth(1).unwrap().split(')').next().unwrap().to_string();
        assert!(url.starts_with("data:image/png;base64,iVBOR"));
        // #2 same code (keep waiting) → #3 new code → refreshed.
        let r = login.call(&ctx, json!({"action": "wait", "currentQrDataUrl": url, "timeoutMs": 3000}));
        assert!(r.content.starts_with("QR refreshed."), "{}", r.content);
        let r = login.call(&ctx, json!({"action": "wait", "timeoutMs": 3000}));
        assert!(r.content.starts_with("✅ Linked!"), "{}", r.content);
        let r = login.call(&ctx, json!({"action": "start"}));
        assert!(r.content.starts_with("WhatsApp is already linked"), "{}", r.content);
        let r = login.call(&ctx, json!({"action": "start", "force": true}));
        assert!(r.is_error && r.content.contains("not supervised"), "{}", r.content);
        assert!(login.call(&ctx, json!({"action": "nope"})).is_error);
        assert!(login.call(&ctx, json!({"action": "wait", "currentQrDataUrl": "http://x"})).is_error);
    }

    /// OpenClaw `agent-tools-call.test.ts`: requester-bound target, TTS → WAV, MeowCaller argv,
    /// status/setup report, single active call, failure codes and window math.
    #[test]
    fn call_tool_places_requester_bound_calls_through_meowcaller() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("wa-call");
        let bin = dir.join("meowcaller");
        let log = dir.join("argv.log");
        std::fs::write(&bin, format!("#!/bin/sh\necho \"$@\" > {}\nhead -c 4 \"$9\" >> {}\n[ \"$8\" = \"+15550001111\" ] && exit 0\nexit 3\n", log.display(), log.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let st: Settings = serde_json::from_value(json!({"bridge_url": "http://127.0.0.1:9", "mode": "bot", "actions": {"calls": true}, "meowcaller": bin.display().to_string()})).unwrap();
        let w = WhatsApp::open("whatsapp", &st, &dir).unwrap();
        let tools = w.tools();
        let call = tools.iter().find(|t| t.spec().name == "whatsapp_call").unwrap().clone();
        let mut ctx = crate::testutil::tool_ctx();
        ctx.session_id = "sess-a".into();
        let v: Value = serde_json::from_str(&call.call(&ctx, json!({"action": "status"})).content).unwrap();
        assert_eq!((v["binaryFound"].as_bool(), v["sessionStoreFound"].as_bool()), (Some(true), Some(false)));
        assert!(v["setupCommand"].as_str().unwrap().contains("meowcaller pair --store"));
        let e = call.call(&ctx, json!({"action": "call", "message": "hi"}));
        assert!(e.is_error && e.content.contains("no session store"), "{}", e.content);
        std::fs::create_dir_all(dir.join("whatsapp.whatsapp-calls")).unwrap();
        std::fs::write(dir.join("whatsapp.whatsapp-calls/wa-voip.db"), b"db").unwrap();
        assert!(call.call(&ctx, json!({"action": "call", "message": "hi"})).content.contains("known requester"));
        w.set_session_origin(Arc::new(|s: &str| match s {
            "sess-a" => Some(crate::router::RouteKey { channel: "whatsapp".into(), chat: "15550001111@s.whatsapp.net".into(), sender: None }),
            "sess-b" => Some(crate::router::RouteKey { channel: "whatsapp".into(), chat: "120363@g.us".into(), sender: Some("15550002222@s.whatsapp.net".into()) }),
            "sess-lid" => Some(crate::router::RouteKey { channel: "whatsapp".into(), chat: "999@lid".into(), sender: None }),
            _ => None,
        }));
        assert!(call.call(&ctx, json!({"action": "call", "message": "hi"})).content.contains("text-to-speech"));
        set_telephony_tts(Arc::new(|t: &str| Ok((vec![0u8; 16000 * 2 * (t.len().min(3))], 16000, "fake".into()))));
        let r = call.call(&ctx, json!({"action": "call", "message": "hi"}));
        assert!(!r.is_error, "{}", r.content);
        let v: Value = serde_json::from_str(&r.content).unwrap();
        assert_eq!((v["completed"].as_bool(), v["ttsProvider"].as_str(), v["callWindowSeconds"].as_u64()), (Some(true), Some("fake"), Some(117)));
        let argv = std::fs::read_to_string(&log).unwrap();
        assert!(argv.starts_with("notify --store ") && argv.contains("--answer-timeout 45s --max-duration 65s +15550001111 ") && argv.ends_with("RIFF"), "{argv}");
        assert!(std::fs::read_dir(dir.join("whatsapp.whatsapp-calls")).unwrap().count() == 1, "temp audio removed");
        ctx.session_id = "sess-b".into();
        let r = call.call(&ctx, json!({"action": "call", "message": "hi"}));
        assert!(r.is_error && r.content.contains("code 3"), "group sender is the target: {}", r.content);
        ctx.session_id = "sess-lid".into();
        assert!(call.call(&ctx, json!({"action": "call", "message": "hi"})).content.contains("phone number"));
        assert!(call.call(&ctx, json!({"action": "call", "message": ""})).content.contains("message required"));
        // Helpers.
        assert_eq!(tools::requester_e164("whatsapp:+1 555 000 1111"), Some("+15550001111".into()));
        assert_eq!(tools::requester_e164("1555000111:12@s.whatsapp.net"), Some("+1555000111".into()));
        assert!(tools::call_window_ms(16000 * 2 * 61, 16000).is_err());
        assert_eq!(tools::call_window_ms(16000 * 2 * 59, 16000).unwrap(), 174_000);
        assert!(tools::wav_pcm16_mono(&[0], 8000).is_err());
        let wsc: Settings = serde_json::from_value(json!({"bridge_url": "http://127.0.0.1:9", "actions": {"calls": true}, "meowcaller": bin.display().to_string()})).unwrap();
        let selfchat = WhatsApp::open("whatsapp", &wsc, &dir).unwrap();
        selfchat.set_session_origin(Arc::new(|_: &str| Some(crate::router::RouteKey { channel: "whatsapp".into(), chat: "15550001111@s.whatsapp.net".into(), sender: None })));
        let c2 = selfchat.tools().into_iter().find(|t| t.spec().name == "whatsapp_call").unwrap();
        assert!(c2.call(&ctx, json!({"action": "call", "message": "hi"})).content.contains("linked account itself"));
    }
}
