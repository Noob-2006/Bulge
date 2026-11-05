//! Realtime (streaming) transcription providers, ported from OpenClaw
//! `src/realtime-transcription/websocket-session.ts` and
//! `extensions/{openai,deepgram,elevenlabs,mistral,xai}/realtime-transcription-provider-factory.ts`.
//!
//! One generic session ([`Session`]) owns the socket, the ready handshake, audio
//! framing and the close/finalize drain; each provider ([`Proto`]) supplies the URL,
//! headers and protocol messages.

use super::conn::{ws_scheme, Conn, Incoming};
use super::{cfg_bool, cfg_num, cfg_str, settings, RealtimeStt, SttEvent, Wire};
use crate::Media;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// What a provider can do to the session while handling an event.
pub(crate) struct Tx<'a> {
    conn: &'a mut Conn,
    ready: &'a mut bool,
    ev: &'a mut Vec<SttEvent>,
    close_now: bool,
    connect_err: Option<String>,
    /// A write to the socket failed (the provider went away mid-session).
    send_failed: bool,
}

impl Tx<'_> {
    fn send_json(&mut self, v: Value) -> bool {
        let ok = self.conn.send_json(&v);
        self.send_failed |= !ok;
        ok
    }
    fn send_binary(&mut self, b: &[u8]) -> bool {
        let ok = self.conn.send_binary(b);
        self.send_failed |= !ok;
        ok
    }
    fn mark_ready(&mut self) {
        *self.ready = true;
    }
    fn is_ready(&self) -> bool {
        *self.ready
    }
    fn emit(&mut self, e: SttEvent) {
        self.ev.push(e);
    }
    fn fail_connect(&mut self, e: String) {
        self.connect_err = Some(e);
    }
    fn close_now(&mut self) {
        self.close_now = true;
    }
}

pub(crate) trait Proto: Send {
    fn label(&self) -> &'static str;
    fn url(&self) -> Result<String, String>;
    fn headers(&self) -> Vec<(String, String)>;
    fn wire(&self) -> Wire;
    /// The socket is usable as soon as it opens (Deepgram); others wait for a ready event.
    fn ready_on_open(&self) -> bool {
        false
    }
    fn on_open(&mut self, _tx: &mut Tx) {}
    fn on_message(&mut self, ev: &Value, tx: &mut Tx);
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx);
    /// Flush/commit/finalize before closing.
    fn on_close(&mut self, tx: &mut Tx);
    /// After [`Proto::on_close`]: every terminal transcript has arrived.
    fn finished(&self) -> bool;
    /// The close drain timed out (Deepgram keeps already-finalized text).
    fn on_drain_timeout(&mut self, _tx: &mut Tx) {}
}

pub(crate) struct Session {
    proto: Box<dyn Proto>,
    conn: Conn,
    ready: bool,
    in_rate: u32,
    ev: Vec<SttEvent>,
    close_timeout: Duration,
    closed: bool,
}

impl Session {
    pub(crate) fn open(
        m: &Media,
        mut proto: Box<dyn Proto>,
        in_rate: u32,
    ) -> Result<Session, String> {
        let s = settings(m);
        let label = proto.label();
        let url = proto.url()?;
        let mut conn = Conn::open(
            &url,
            &proto.headers(),
            s.connect_timeout,
            s.attempts,
            s.delay,
            label,
        )?;
        let mut ready = proto.ready_on_open();
        let mut ev = Vec::new();
        {
            let mut tx = Tx {
                conn: &mut conn,
                ready: &mut ready,
                ev: &mut ev,
                close_now: false,
                connect_err: None,
                send_failed: false,
            };
            proto.on_open(&mut tx);
        }
        let end = Instant::now() + s.connect_timeout;
        while !ready {
            let msgs = conn.drain();
            for msg in msgs {
                match msg {
                    Incoming::Json(v) => {
                        let mut tx = Tx {
                            conn: &mut conn,
                            ready: &mut ready,
                            ev: &mut ev,
                            close_now: false,
                            connect_err: None,
                            send_failed: false,
                        };
                        proto.on_message(&v, &mut tx);
                        if let Some(e) = tx.connect_err {
                            return Err(e);
                        }
                    }
                    Incoming::Closed(c) => {
                        let why = c
                            .map(|(code, r)| {
                                format!(
                                    " ({code}{})",
                                    if r.is_empty() {
                                        String::new()
                                    } else {
                                        format!(": {r}")
                                    }
                                )
                            })
                            .unwrap_or_default();
                        return Err(format!("{label} connection closed before ready{why}"));
                    }
                    Incoming::Binary(_) => {}
                }
                if ready {
                    break;
                }
            }
            if !ready && Instant::now() >= end {
                return Err(format!("{label} connection timeout"));
            }
            if !ready {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(Session {
            proto,
            conn,
            ready,
            in_rate,
            ev,
            close_timeout: s.close_timeout,
            closed: false,
        })
    }

    fn pump(&mut self) {
        for msg in self.conn.drain() {
            let mut tx = Tx {
                conn: &mut self.conn,
                ready: &mut self.ready,
                ev: &mut self.ev,
                close_now: false,
                connect_err: None,
                send_failed: false,
            };
            match msg {
                Incoming::Json(v) => self.proto.on_message(&v, &mut tx),
                Incoming::Binary(_) => {}
                Incoming::Closed(_) => {
                    self.closed = true;
                    break;
                }
            }
            let (close, err) = (tx.close_now, tx.connect_err.take());
            if let Some(e) = err {
                self.ev.push(SttEvent::Error(e));
            }
            if close {
                self.closed = true;
                self.conn.close();
                break;
            }
        }
    }
}

impl RealtimeStt for Session {
    fn send_audio(&mut self, pcm: &[i16]) -> Result<(), String> {
        if self.closed {
            return Err(format!("{} session is closed", self.proto.label()));
        }
        let bytes = self.proto.wire().encode(pcm, self.in_rate);
        let mut tx = Tx {
            conn: &mut self.conn,
            ready: &mut self.ready,
            ev: &mut self.ev,
            close_now: false,
            connect_err: None,
            send_failed: false,
        };
        self.proto.send_audio(&bytes, &mut tx);
        let (close_now, lost) = (tx.close_now, tx.send_failed);
        if close_now {
            self.closed = true;
            self.conn.close();
        }
        if lost {
            // The provider stopped reading: never lose audio silently. Callers fall back
            // to file transcription (stt::stream) once the session reports this.
            self.closed = true;
            self.conn.close();
            return Err(format!("{} session lost its connection", self.proto.label()));
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<SttEvent>, String> {
        self.pump();
        Ok(std::mem::take(&mut self.ev))
    }

    fn finish(&mut self) -> Result<Vec<SttEvent>, String> {
        if !self.closed {
            {
                let mut tx = Tx {
                    conn: &mut self.conn,
                    ready: &mut self.ready,
                    ev: &mut self.ev,
                    close_now: false,
                    connect_err: None,
                    send_failed: false,
                };
                self.proto.on_close(&mut tx);
                if tx.close_now {
                    self.closed = true;
                }
            }
            let end = Instant::now() + self.close_timeout;
            while !self.closed && !self.proto.finished() {
                self.pump();
                if self.closed || self.proto.finished() {
                    break;
                }
                if Instant::now() >= end {
                    let mut tx = Tx {
                        conn: &mut self.conn,
                        ready: &mut self.ready,
                        ev: &mut self.ev,
                        close_now: false,
                        connect_err: None,
                        send_failed: false,
                    };
                    self.proto.on_drain_timeout(&mut tx);
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            self.pump();
            self.closed = true;
        }
        self.conn.close();
        Ok(std::mem::take(&mut self.ev))
    }
}

fn utf8_len(s: &str) -> usize {
    s.len()
}

fn key_of(m: &Media, id: &str, envs: &[&str], default_base: &str) -> crate::Creds {
    m.creds(id, envs, default_base)
}

fn query(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", seagent_net::urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ───────────────────────── OpenAI ─────────────────────────

const OPENAI_BYTES_PER_MS_PCMU: usize = 8;
const OPENAI_MIN_COMMIT_MS: usize = 100;
const OPENAI_DEFAULT_MODEL: &str = "gpt-4o-transcribe";
const OPENAI_MAX_UNRESOLVED_ITEMS: usize = 64;
const OPENAI_MAX_ITEM_ID_BYTES: usize = 1024;
const OPENAI_MAX_RETAINED_BYTES: usize = 256 * 1024;
const OPENAI_MAX_SETTLED_ITEMS: usize = 4096;
const OPENAI_MAX_SETTLED_ID_BYTES: usize = 256 * 1024;
const OPENAI_ITEM_OVERFLOW: &str =
    "OpenAI realtime transcription exceeded the 64 unresolved item limit";
const OPENAI_IDENTITY_OVERFLOW: &str =
    "OpenAI realtime transcription exceeded the 1024-byte item identity limit";
const OPENAI_TEXT_OVERFLOW: &str =
    "OpenAI realtime transcription exceeded the 256 KiB retained transcript limit";
const OPENAI_SETTLED_OVERFLOW: &str =
    "OpenAI realtime transcription exceeded the terminal item history limit";
pub(crate) const OPENAI_KEY_REQUIRED: &str =
    "OpenAI Realtime transcription requires an OpenAI Platform API key";
const UNKEYED: &str = "__seagent_unkeyed_transcript__";

pub(crate) struct OpenAi {
    url: String,
    key: String,
    extra_headers: Vec<(String, String)>,
    wire: Wire,
    model: String,
    language: Option<String>,
    prompt: Option<String>,
    silence_ms: u64,
    vad_threshold: f64,
    pending: HashMap<String, String>,
    committed: Vec<(String, Option<String>)>,
    completed: HashMap<String, Option<String>>,
    tracked: HashSet<String>,
    settled: HashSet<String>,
    retained: usize,
    settled_bytes: usize,
    appended: usize,
    committed_bytes: usize,
    vad_boundary: Option<(String, usize)>,
    close_sent: bool,
    commit_outstanding: bool,
    failed: bool,
}

impl OpenAi {
    pub(crate) fn new(m: &Media, in_rate: u32, language: Option<&str>) -> Result<OpenAi, String> {
        let c = key_of(
            m,
            "openai",
            &["OPENAI_API_KEY"],
            "https://api.openai.com/v1",
        );
        let key = c.key.clone().ok_or(OPENAI_KEY_REQUIRED)?;
        let url = cfg_str(m, "openai", "url").unwrap_or_else(|| {
            format!(
                "{}/realtime?intent=transcription",
                ws_scheme(c.base.trim_end_matches('/'))
            )
        });
        let wire = match cfg_str(m, "openai", "encoding")
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("pcmu" | "mulaw" | "ulaw" | "g711_ulaw" | "audio/pcmu") => Wire::Mulaw,
            Some("pcm" | "pcm16" | "linear16" | "audio/pcm") => Wire::Pcm16(24000),
            Some(o) => {
                return Err(format!(
                    "Invalid OpenAI realtime transcription encoding: {o}"
                ))
            }
            None if in_rate == 8000 => Wire::Mulaw,
            None => Wire::Pcm16(24000),
        };
        let vad = cfg_num(m, "openai", "vad_threshold")
            .filter(|v| (0.0..=1.0).contains(v))
            .unwrap_or(0.5);
        Ok(OpenAi {
            url,
            key,
            extra_headers: c.headers,
            wire,
            model: cfg_str(m, "openai", "model").unwrap_or_else(|| OPENAI_DEFAULT_MODEL.into()),
            language: language
                .map(str::to_string)
                .or_else(|| cfg_str(m, "openai", "language")),
            prompt: cfg_str(m, "openai", "prompt"),
            silence_ms: cfg_num(m, "openai", "silence_duration_ms")
                .filter(|v| *v >= 0.0)
                .map(|v| v as u64)
                .unwrap_or(800),
            vad_threshold: vad,
            pending: HashMap::new(),
            committed: Vec::new(),
            completed: HashMap::new(),
            tracked: HashSet::new(),
            settled: HashSet::new(),
            retained: 0,
            settled_bytes: 0,
            appended: 0,
            committed_bytes: 0,
            vad_boundary: None,
            close_sent: false,
            commit_outstanding: false,
            failed: false,
        })
    }

    pub(crate) fn session_payload(&self) -> Value {
        let mut tr = json!({"model": self.model});
        if let Some(l) = &self.language {
            tr["language"] = json!(l);
        }
        if let Some(p) = &self.prompt {
            tr["prompt"] = json!(p);
        }
        json!({"type": "transcription", "audio": {"input": {
            "format": self.wire.openai_format(),
            "transcription": tr,
            "turn_detection": {"type": "server_vad", "threshold": self.vad_threshold, "prefix_padding_ms": 300, "silence_duration_ms": self.silence_ms}
        }}})
    }

    fn bytes_per_ms(&self) -> usize {
        match self.wire {
            Wire::Pcm16(r) => (r as usize * 2) / 1000,
            _ => OPENAI_BYTES_PER_MS_PCMU,
        }
    }

    fn fail(&mut self, msg: &str, tx: &mut Tx) {
        self.pending.clear();
        self.committed.clear();
        self.completed.clear();
        self.tracked.clear();
        self.failed = true;
        tx.emit(SttEvent::Error(msg.into()));
        tx.close_now();
    }

    fn track(&mut self, id: &str, tx: &mut Tx) -> bool {
        if self.settled.contains(id) || self.completed.contains_key(id) {
            return false;
        }
        if self.tracked.contains(id) {
            return true;
        }
        if self.tracked.len() >= OPENAI_MAX_UNRESOLVED_ITEMS {
            self.fail(OPENAI_ITEM_OVERFLOW, tx);
            return false;
        }
        if utf8_len(id) > OPENAI_MAX_ITEM_ID_BYTES {
            self.fail(OPENAI_IDENTITY_OVERFLOW, tx);
            return false;
        }
        self.tracked.insert(id.to_string());
        true
    }

    fn settle(&mut self, id: &str, tx: &mut Tx) -> bool {
        if self.settled.len() >= OPENAI_MAX_SETTLED_ITEMS
            || utf8_len(id) > OPENAI_MAX_SETTLED_ID_BYTES - self.settled_bytes
        {
            self.fail(OPENAI_SETTLED_OVERFLOW, tx);
            return false;
        }
        self.tracked.remove(id);
        for (_, prev) in self.committed.iter_mut() {
            if prev.as_deref() == Some(id) {
                *prev = None;
            }
        }
        self.settled.insert(id.to_string());
        self.settled_bytes += utf8_len(id);
        true
    }

    /// Commit order follows `previous_item_id` chains (a late commit slots in after its predecessor).
    fn commit(&mut self, id: &str, prev: Option<&str>, tx: &mut Tx) {
        if self.committed.iter().any(|(c, _)| c == id) || !self.track(id, tx) {
            return;
        }
        if prev.is_some_and(|p| utf8_len(p) > OPENAI_MAX_ITEM_ID_BYTES) {
            self.fail(OPENAI_IDENTITY_OVERFLOW, tx);
            return;
        }
        let prev = prev
            .filter(|p| !self.settled.contains(*p))
            .map(str::to_string);
        let at = prev
            .as_ref()
            .and_then(|p| self.committed.iter().position(|(c, _)| c == p))
            .map(|i| i + 1);
        // Items that named this one as predecessor move behind it.
        let followers: Vec<(String, Option<String>)> = self
            .committed
            .iter()
            .filter(|(_, p)| p.as_deref() == Some(id))
            .cloned()
            .collect();
        self.committed.retain(|(_, p)| p.as_deref() != Some(id));
        let at = at
            .map(|i| i.min(self.committed.len()))
            .unwrap_or(self.committed.len());
        self.committed.insert(at, (id.to_string(), prev));
        for (k, f) in followers.into_iter().enumerate() {
            self.committed.insert(at + 1 + k, f);
        }
    }

    fn flush(&mut self, tx: &mut Tx) -> bool {
        while let Some((id, prev)) = self.committed.first().cloned() {
            if !self.completed.contains_key(&id) {
                return true;
            }
            if let Some(p) = &prev {
                if !self.settled.contains(p) && !self.committed.iter().any(|(c, _)| c == p) {
                    return true;
                }
            }
            self.committed.remove(0);
            if !self.settle(&id, tx) {
                return false;
            }
            if let Some(Some(t)) = self.completed.remove(&id) {
                self.retained = self.retained.saturating_sub(utf8_len(&t));
                if !t.is_empty() {
                    tx.emit(SttEvent::Final(t));
                }
            }
        }
        true
    }

    fn complete(&mut self, id: Option<&str>, text: Option<String>, tx: &mut Tx) -> bool {
        let key = id.unwrap_or(UNKEYED).to_string();
        if let Some(i) = id {
            if !self.track(i, tx) {
                return false;
            }
        }
        if let Some(p) = self.pending.remove(&key) {
            self.retained = self.retained.saturating_sub(utf8_len(&p));
        }
        let n = text.as_deref().map(utf8_len).unwrap_or(0);
        if n > OPENAI_MAX_RETAINED_BYTES - self.retained.min(OPENAI_MAX_RETAINED_BYTES) {
            self.fail(OPENAI_TEXT_OVERFLOW, tx);
            return false;
        }
        let committed = id.is_some_and(|i| self.committed.iter().any(|(c, _)| c == i));
        if !committed {
            match id {
                Some(i) => {
                    if !self.settle(i, tx) {
                        return false;
                    }
                }
                None => {
                    self.tracked.remove(&key);
                }
            }
            if let Some(t) = text.filter(|t| !t.is_empty()) {
                tx.emit(SttEvent::Final(t));
            }
            return true;
        }
        self.completed.insert(key, text);
        self.retained += n;
        self.flush(tx)
    }
}

fn error_detail(v: &Value, fallback: &str) -> String {
    match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Object(o) => o
            .get("message")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| o.get("code").and_then(|x| x.as_str()))
            .unwrap_or(fallback)
            .to_string(),
        _ => fallback.to_string(),
    }
}

impl Proto for OpenAi {
    fn label(&self) -> &'static str {
        "OpenAI realtime transcription"
    }
    fn url(&self) -> Result<String, String> {
        Ok(self.url.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![("Authorization".to_string(), format!("Bearer {}", self.key))];
        h.extend(self.extra_headers.clone());
        h
    }
    fn wire(&self) -> Wire {
        self.wire
    }
    fn on_open(&mut self, tx: &mut Tx) {
        tx.send_json(json!({"type": "session.update", "session": self.session_payload()}));
    }
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx) {
        if tx.send_json(
            json!({"type": "input_audio_buffer.append", "audio": crate::store::b64(wire)}),
        ) {
            self.appended += wire.len();
        }
    }
    fn on_close(&mut self, tx: &mut Tx) {
        self.close_sent = true;
        // Server VAD owns stopped audio before its ack; shorter manual commits are rejected.
        let owned = self
            .committed_bytes
            .max(self.vad_boundary.as_ref().map(|b| b.1).unwrap_or(0));
        if self.appended.saturating_sub(owned) >= OPENAI_MIN_COMMIT_MS * self.bytes_per_ms() {
            if !tx.send_json(json!({"type": "input_audio_buffer.commit"})) {
                self.fail("OpenAI realtime transcription could not send its final audio commit; check the provider connection", tx);
                return;
            }
            self.committed_bytes = self.appended;
            self.commit_outstanding = true;
        }
    }
    fn finished(&self) -> bool {
        self.failed
            || (self.close_sent
                && !self.commit_outstanding
                && self.committed.is_empty()
                && self.tracked.is_empty())
    }
    fn on_message(&mut self, ev: &Value, tx: &mut Tx) {
        let s = |k: &str| ev.get(k).and_then(|v| v.as_str()).map(str::to_string);
        match ev["type"].as_str().unwrap_or("") {
            "session.updated" | "transcription_session.updated" => tx.mark_ready(),
            "input_audio_buffer.committed" => {
                let id = s("item_id");
                let boundary = self.vad_boundary.clone();
                if let Some(i) = &id {
                    if (self.committed.iter().any(|(c, _)| c == i) || self.settled.contains(i))
                        && boundary.as_ref().map(|b| &b.0) != Some(i)
                    {
                        return;
                    }
                }
                self.committed_bytes = match (&id, &boundary) {
                    (Some(i), Some((bi, end))) if i == bi => {
                        self.committed_bytes.max(self.appended.min(*end))
                    }
                    _ => self.appended,
                };
                if id.is_some() && boundary.as_ref().map(|b| &b.0) == id.as_ref() {
                    self.vad_boundary = None;
                }
                self.commit_outstanding = false;
                if let Some(i) = id {
                    self.commit(&i, ev["previous_item_id"].as_str(), tx);
                }
            }
            "input_audio_buffer.speech_stopped" => {
                if let (Some(i), Some(ms)) = (
                    s("item_id"),
                    ev["audio_end_ms"]
                        .as_f64()
                        .filter(|v| v.is_finite() && *v >= 0.0),
                ) {
                    self.vad_boundary = Some((i, ms as usize * self.bytes_per_ms()));
                }
                tx.emit(SttEvent::SpeechStopped);
            }
            "conversation.item.input_audio_transcription.delta" => {
                let Some(d) = s("delta").filter(|d| !d.is_empty()) else {
                    return;
                };
                let key = s("item_id").unwrap_or_else(|| UNKEYED.into());
                if !self.track(&key, tx) {
                    return;
                }
                if utf8_len(&d) > OPENAI_MAX_RETAINED_BYTES.saturating_sub(self.retained) {
                    self.fail(OPENAI_TEXT_OVERFLOW, tx);
                    return;
                }
                let p = self.pending.entry(key).or_default();
                p.push_str(&d);
                self.retained += utf8_len(&d);
                let partial = p.clone();
                tx.emit(SttEvent::Partial(partial));
            }
            "conversation.item.input_audio_transcription.completed" => {
                let id = s("item_id");
                self.complete(id.as_deref(), s("transcript"), tx);
            }
            "conversation.item.input_audio_transcription.failed" => {
                let id = s("item_id");
                if self.complete(id.as_deref(), None, tx) {
                    tx.emit(SttEvent::Error(error_detail(
                        &ev["error"],
                        "OpenAI realtime transcription failed",
                    )));
                }
            }
            "input_audio_buffer.speech_started" => {
                let key = s("item_id").unwrap_or_else(|| UNKEYED.into());
                if let Some(p) = self.pending.remove(&key) {
                    self.retained = self.retained.saturating_sub(utf8_len(&p));
                }
                if !self.committed.iter().any(|(c, _)| *c == key) {
                    self.tracked.remove(&key);
                }
                tx.emit(SttEvent::SpeechStarted);
            }
            "error" => {
                let d = error_detail(&ev["error"], "OpenAI realtime transcription error");
                if !tx.is_ready() {
                    tx.fail_connect(d);
                } else {
                    self.commit_outstanding = false;
                    tx.emit(SttEvent::Error(d));
                }
            }
            _ => {}
        }
    }
}

// ───────────────────────── Deepgram ─────────────────────────

const DEEPGRAM_DEFAULT_BASE: &str = "https://api.deepgram.com/v1";
const DEEPGRAM_DEFAULT_MODEL: &str = "nova-3";
const DEEPGRAM_MAX_RETAINED: usize = 256 * 1024;

pub(crate) struct Deepgram {
    url: String,
    key: String,
    wire: Wire,
    speech_started: bool,
    finalized: String,
    partial: String,
    finalize_requested: bool,
    finalize_done: bool,
}

fn join(a: &str, b: &str) -> String {
    let s = if !a.is_empty() && !b.is_empty() {
        format!("{a} {b}")
    } else {
        format!("{a}{b}")
    };
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn http_ws_base(raw: &str, label: &str) -> Result<String, String> {
    let scheme = raw.split("://").next().unwrap_or("");
    if !raw.contains("://") {
        return Err(format!("Invalid {label} baseUrl: value is not a valid URL"));
    }
    if !["http", "https", "ws", "wss"].contains(&scheme) {
        // Endpoint URLs can carry credentials: keep the error actionable without echoing it.
        return Err(format!("Invalid {label} baseUrl: unsupported scheme \"{scheme}:\" (expected http, https, ws, or wss)"));
    }
    Ok(ws_scheme(raw.trim_end_matches('/')))
}

impl Deepgram {
    pub(crate) fn new(m: &Media, in_rate: u32, language: Option<&str>) -> Result<Deepgram, String> {
        let env_base = std::env::var("DEEPGRAM_BASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let c = key_of(
            m,
            "deepgram",
            &["DEEPGRAM_API_KEY"],
            env_base.as_deref().unwrap_or(DEEPGRAM_DEFAULT_BASE),
        );
        let key = c.key.clone().ok_or("Deepgram API key missing")?;
        let base = http_ws_base(&c.base, "Deepgram")?;
        let enc = match cfg_str(m, "deepgram", "encoding")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => None,
            Some("pcm" | "pcm_s16le" | "linear16") => Some("linear16"),
            Some("ulaw" | "g711_ulaw" | "g711-mulaw" | "mulaw") => Some("mulaw"),
            Some("g711_alaw" | "g711-alaw" | "alaw") => Some("alaw"),
            Some(o) => {
                return Err(format!(
                    "Invalid Deepgram realtime transcription encoding: {o}"
                ))
            }
        };
        let rate = cfg_num(m, "deepgram", "sample_rate").map(|r| r as u32);
        let (enc, rate) = match (enc, rate) {
            (Some(e), Some(r)) => (e, r),
            (Some("linear16"), None) => ("linear16", in_rate),
            (Some(e), None) => (e, 8000),
            (None, Some(8000)) => ("mulaw", 8000),
            (None, Some(r)) => ("linear16", r),
            (None, None) if in_rate == 8000 => ("mulaw", 8000),
            (None, None) => ("linear16", in_rate),
        };
        let wire = match enc {
            "mulaw" => Wire::Mulaw,
            "alaw" => Wire::Alaw,
            _ => Wire::Pcm16(rate),
        };
        let mut q = vec![
            (
                "model",
                cfg_str(m, "deepgram", "model").unwrap_or_else(|| DEEPGRAM_DEFAULT_MODEL.into()),
            ),
            ("encoding", enc.to_string()),
            ("sample_rate", rate.to_string()),
            ("channels", "1".into()),
            (
                "interim_results",
                cfg_bool(m, "deepgram", "interim_results")
                    .unwrap_or(true)
                    .to_string(),
            ),
            (
                "endpointing",
                (cfg_num(m, "deepgram", "endpointing_ms").unwrap_or(800.0) as u64).to_string(),
            ),
        ];
        if let Some(l) = language
            .map(str::to_string)
            .or_else(|| cfg_str(m, "deepgram", "language"))
        {
            q.push(("language", l));
        }
        Ok(Deepgram {
            url: format!("{base}/listen?{}", query(&q)),
            key,
            wire,
            speech_started: false,
            finalized: String::new(),
            partial: String::new(),
            finalize_requested: false,
            finalize_done: false,
        })
    }

    fn update(&mut self, fin: String, partial: String, tx: &mut Tx) -> bool {
        if fin.len() + partial.len() > DEEPGRAM_MAX_RETAINED {
            self.clear();
            tx.emit(SttEvent::Error(format!(
                "Deepgram realtime retained transcript exceeded {DEEPGRAM_MAX_RETAINED} bytes"
            )));
            tx.close_now();
            return false;
        }
        self.finalized = fin;
        self.partial = partial;
        true
    }
    fn clear(&mut self) {
        self.finalized.clear();
        self.partial.clear();
        self.speech_started = false;
    }
    fn flush_turn(&mut self, include_partial: bool, tx: &mut Tx) {
        let full = join(
            &self.finalized,
            if include_partial { &self.partial } else { "" },
        );
        self.clear();
        if !full.is_empty() {
            tx.emit(SttEvent::Final(full));
        }
    }
}

impl Proto for Deepgram {
    fn label(&self) -> &'static str {
        "Deepgram realtime transcription"
    }
    fn url(&self) -> Result<String, String> {
        Ok(self.url.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Token {}", self.key))]
    }
    fn wire(&self) -> Wire {
        self.wire
    }
    fn ready_on_open(&self) -> bool {
        true
    }
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx) {
        tx.send_binary(wire);
    }
    fn on_close(&mut self, tx: &mut Tx) {
        if self.finalize_requested {
            return;
        }
        self.finalize_requested = true;
        if self.finalized.is_empty() && self.partial.is_empty() {
            self.finalize_done = true;
        }
        tx.send_json(json!({"type": "Finalize"}));
    }
    fn finished(&self) -> bool {
        self.finalize_done
    }
    fn on_drain_timeout(&mut self, tx: &mut Tx) {
        // Finalize may produce no Results when nothing is buffered: keep confirmed text.
        self.flush_turn(false, tx);
        self.finalize_done = true;
    }
    fn on_message(&mut self, ev: &Value, tx: &mut Tx) {
        match ev["type"].as_str().unwrap_or("") {
            "Results" => {
                let text = ev
                    .pointer("/channel/alternatives/0/transcript")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("")
                    .to_string();
                if !text.is_empty() && !self.speech_started {
                    self.speech_started = true;
                    tx.emit(SttEvent::SpeechStarted);
                }
                let is_final = ev["is_final"].as_bool().unwrap_or(false);
                if ev["speech_final"].as_bool().unwrap_or(false)
                    || ev["from_finalize"].as_bool().unwrap_or(false)
                {
                    let fin = if text.is_empty() {
                        self.finalized.clone()
                    } else {
                        join(&self.finalized, &text)
                    };
                    if !self.update(fin, String::new(), tx) {
                        return;
                    }
                    self.flush_turn(true, tx);
                    if self.finalize_requested {
                        self.finalize_done = true;
                    }
                    return;
                }
                if text.is_empty() {
                    return;
                }
                let fin = if is_final {
                    join(&self.finalized, &text)
                } else {
                    self.finalized.clone()
                };
                if !self.update(
                    fin.clone(),
                    if is_final {
                        String::new()
                    } else {
                        text.clone()
                    },
                    tx,
                ) {
                    return;
                }
                tx.emit(SttEvent::Partial(if is_final {
                    fin
                } else {
                    join(&fin, &text)
                }));
            }
            "SpeechStarted" => {
                self.speech_started = true;
                tx.emit(SttEvent::SpeechStarted);
            }
            "Error" | "error" => {
                let d = if ev.get("error").is_some() {
                    error_detail(&ev["error"], "Deepgram realtime transcription error")
                } else {
                    error_detail(&ev["message"], "Deepgram realtime transcription error")
                };
                tx.emit(SttEvent::Error(d));
            }
            _ => {}
        }
    }
}

// ───────────────────────── ElevenLabs ─────────────────────────

const ELEVENLABS_DEFAULT_MODEL: &str = "scribe_v2_realtime";
const ELEVENLABS_PCM_RATES: &[u32] = &[8000, 16000, 22050, 24000, 44100, 48000];

pub(crate) struct ElevenLabs {
    url: String,
    key: String,
    wire: Wire,
    rate: u32,
    manual: bool,
    echo: Option<String>,
    close_sent: bool,
    done: bool,
    audio_since_commit: bool,
}

impl ElevenLabs {
    pub(crate) fn new(
        m: &Media,
        in_rate: u32,
        language: Option<&str>,
    ) -> Result<ElevenLabs, String> {
        let c = key_of(
            m,
            "elevenlabs",
            &["ELEVENLABS_API_KEY", "XI_API_KEY"],
            "https://api.elevenlabs.io",
        );
        let key = c.key.clone().ok_or("ElevenLabs API key missing")?;
        let base = http_ws_base(&c.base, "ElevenLabs")?;
        let base = base.strip_suffix("/v1").unwrap_or(&base).to_string();
        let commit = match cfg_str(m, "elevenlabs", "commit_strategy")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => "vad".to_string(),
            Some(s @ ("manual" | "vad")) => s.to_string(),
            Some(o) => {
                return Err(format!(
                    "Invalid ElevenLabs realtime transcription commit strategy: {o}"
                ))
            }
        };
        let fmt = cfg_str(m, "elevenlabs", "audio_format").unwrap_or_else(|| {
            if in_rate == 8000 {
                "ulaw_8000".into()
            } else {
                format!(
                    "pcm_{}",
                    ELEVENLABS_PCM_RATES
                        .iter()
                        .copied()
                        .find(|r| *r == in_rate)
                        .unwrap_or(16000)
                )
            }
        });
        let wire = if fmt.starts_with("ulaw") {
            Wire::Mulaw
        } else if let Some(r) = fmt.strip_prefix("pcm_").and_then(|r| r.parse::<u32>().ok()) {
            Wire::Pcm16(r)
        } else {
            return Err(format!(
                "Invalid ElevenLabs realtime transcription audio format: {fmt}"
            ));
        };
        let rate = cfg_num(m, "elevenlabs", "sample_rate")
            .filter(|r| *r >= 1.0)
            .map(|r| r as u32)
            .unwrap_or(wire.rate());
        let mut q = vec![
            (
                "model_id",
                cfg_str(m, "elevenlabs", "model")
                    .unwrap_or_else(|| ELEVENLABS_DEFAULT_MODEL.into()),
            ),
            ("audio_format", fmt),
            ("commit_strategy", commit.clone()),
            ("include_timestamps", "false".into()),
            ("include_language_detection", "false".into()),
        ];
        if let Some(l) = language
            .map(str::to_string)
            .or_else(|| cfg_str(m, "elevenlabs", "language"))
        {
            q.push(("language_code", l));
        }
        if let Some(v) = cfg_num(m, "elevenlabs", "vad_silence_threshold_secs")
            .filter(|v| (0.3..=3.0).contains(v))
        {
            q.push(("vad_silence_threshold_secs", v.to_string()));
        }
        if let Some(v) =
            cfg_num(m, "elevenlabs", "vad_threshold").filter(|v| (0.1..=0.9).contains(v))
        {
            q.push(("vad_threshold", v.to_string()));
        }
        for k in ["min_speech_duration_ms", "min_silence_duration_ms"] {
            if let Some(v) = cfg_num(m, "elevenlabs", k)
                .filter(|v| v.fract() == 0.0 && (50.0..=2000.0).contains(v))
            {
                q.push((k, (v as u64).to_string()));
            }
        }
        Ok(ElevenLabs {
            url: format!("{base}/v1/speech-to-text/realtime?{}", query(&q)),
            key,
            wire,
            rate,
            manual: commit == "manual",
            echo: None,
            close_sent: false,
            done: false,
            audio_since_commit: false,
        })
    }
}

impl Proto for ElevenLabs {
    fn label(&self) -> &'static str {
        "ElevenLabs realtime transcription"
    }
    fn url(&self) -> Result<String, String> {
        Ok(self.url.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        vec![("xi-api-key".into(), self.key.clone())]
    }
    fn wire(&self) -> Wire {
        self.wire
    }
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx) {
        let mut v = json!({"message_type": "input_audio_chunk", "audio_base_64": crate::store::b64(wire), "sample_rate": self.rate});
        if self.manual {
            v["commit"] = json!(true);
        }
        self.audio_since_commit = true;
        tx.send_json(v);
    }
    fn on_close(&mut self, tx: &mut Tx) {
        self.close_sent = true;
        if !self.audio_since_commit {
            self.done = true;
        }
        tx.send_json(json!({"message_type": "input_audio_chunk", "audio_base_64": "", "sample_rate": self.rate, "commit": true}));
    }
    fn finished(&self) -> bool {
        self.done
    }
    fn on_message(&mut self, ev: &Value, tx: &mut Tx) {
        let mt = ev["message_type"].as_str().unwrap_or("");
        let detail = || {
            ev["error"]
                .as_str()
                .or(ev["message"].as_str())
                .or(ev["code"].as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("ElevenLabs realtime transcription error")
                .to_string()
        };
        if mt == "session_started" {
            self.echo = None;
            tx.mark_ready();
            return;
        }
        let is_error = ev["error"].is_string() || mt.contains("error");
        if !tx.is_ready() && is_error {
            tx.fail_connect(detail());
            return;
        }
        match mt {
            "partial_transcript" => {
                if let Some(t) = ev["text"].as_str().filter(|t| !t.is_empty()) {
                    tx.emit(SttEvent::Partial(t.into()));
                }
            }
            "committed_transcript" | "committed_transcript_with_timestamps" => {
                self.audio_since_commit = false;
                if self.close_sent {
                    self.done = true;
                }
                if let Some(t) = ev["text"].as_str().filter(|t| !t.is_empty()) {
                    // A committed segment can have one matching timestamp companion, never another turn.
                    let ts = mt != "committed_transcript";
                    let echo = ts && self.echo.as_deref() == Some(t);
                    self.echo = if ts { None } else { Some(t.to_string()) };
                    if !echo {
                        tx.emit(SttEvent::Final(t.into()));
                    }
                }
            }
            _ => {
                if is_error {
                    if self.close_sent {
                        self.done = true;
                    }
                    tx.emit(SttEvent::Error(detail()));
                }
            }
        }
    }
}

// ───────────────────────── Mistral ─────────────────────────

const MISTRAL_DEFAULT_BASE: &str = "wss://api.mistral.ai";
const MISTRAL_DEFAULT_MODEL: &str = "voxtral-mini-transcribe-realtime-2602";
const MISTRAL_MAX_PARTIAL: usize = 256 * 1024;
const MISTRAL_PARTIAL_OVERFLOW: &str =
    "Mistral realtime transcription exceeded the 256 KiB in-progress transcript limit";

pub(crate) struct Mistral {
    url: String,
    key: String,
    encoding: &'static str,
    rate: u32,
    wire: Wire,
    partial: String,
    has_final_segment: bool,
    terminal: bool,
}

fn has_speech(t: &str) -> bool {
    t.chars().any(|c| c.is_alphanumeric())
}

impl Mistral {
    pub(crate) fn new(m: &Media, in_rate: u32) -> Result<Mistral, String> {
        let env_base = std::env::var("MISTRAL_REALTIME_BASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let c = key_of(m, "mistral", &["MISTRAL_API_KEY"], "");
        let key = c
            .key
            .clone()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .ok_or("Mistral API key missing")?;
        let raw = cfg_str(m, "mistral", "url")
            .or(env_base)
            .or_else(|| Some(c.base.clone()).filter(|b| !b.is_empty()))
            .unwrap_or_else(|| MISTRAL_DEFAULT_BASE.into());
        let base = ws_scheme(raw.trim_end_matches('/'));
        let base = base
            .strip_suffix("/v1")
            .unwrap_or(&base)
            .trim_end_matches('/')
            .to_string();
        let enc: Option<&'static str> = match cfg_str(m, "mistral", "encoding").map(|s| s.to_ascii_lowercase()).as_deref() {
            None => None,
            Some("pcm" | "linear16" | "pcm_s16le") => Some("pcm_s16le"),
            Some("pcm_s32le") => Some("pcm_s32le"),
            Some("pcm_f32le") => Some("pcm_f32le"),
            Some("pcm_f16le") => return Err("Mistral realtime transcription encoding pcm_f16le is not supported by seagent; use pcm_s16le, pcm_f32le or pcm_mulaw".into()),
            Some("mulaw" | "ulaw" | "g711_ulaw" | "g711-mulaw" | "pcm_mulaw") => Some("pcm_mulaw"),
            Some("alaw" | "g711_alaw" | "g711-alaw" | "pcm_alaw") => Some("pcm_alaw"),
            Some(o) => return Err(format!("Invalid Mistral realtime transcription encoding: {o}")),
        };
        let cfg_rate = cfg_num(m, "mistral", "sample_rate").map(|r| r as u32);
        let (encoding, rate) = match enc {
            Some(e @ ("pcm_mulaw" | "pcm_alaw")) => (e, 8000),
            Some(e) => (e, cfg_rate.unwrap_or(in_rate)),
            None if cfg_rate.unwrap_or(in_rate) == 8000 => ("pcm_mulaw", 8000),
            None => ("pcm_s16le", cfg_rate.unwrap_or(in_rate)),
        };
        let wire = match encoding {
            "pcm_mulaw" => Wire::Mulaw,
            "pcm_alaw" => Wire::Alaw,
            "pcm_s32le" => Wire::S32le(rate),
            "pcm_f32le" => Wire::F32le(rate),
            _ => Wire::Pcm16(rate),
        };
        let q = vec![
            (
                "model",
                cfg_str(m, "mistral", "model").unwrap_or_else(|| MISTRAL_DEFAULT_MODEL.into()),
            ),
            (
                "target_streaming_delay_ms",
                (cfg_num(m, "mistral", "target_streaming_delay_ms").unwrap_or(800.0) as u64)
                    .to_string(),
            ),
        ];
        Ok(Mistral {
            url: format!("{base}/v1/audio/transcriptions/realtime?{}", query(&q)),
            key,
            encoding,
            rate,
            wire,
            partial: String::new(),
            has_final_segment: false,
            terminal: false,
        })
    }

    fn emit_final(&mut self, text: &str, source: &str, tx: &mut Tx) {
        if text.trim().is_empty() || (source == "pending" && !has_speech(text)) {
            return;
        }
        self.has_final_segment |= source == "segment";
        tx.emit(SttEvent::Final(text.to_string()));
    }

    fn fail(&mut self, e: String, tx: &mut Tx) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        self.partial.clear();
        tx.close_now();
        tx.emit(SttEvent::Error(e));
    }
}

fn mistral_error(ev: &Value) -> String {
    match &ev["error"]["message"] {
        Value::String(s) => s.clone(),
        v @ Value::Object(_) => v.to_string(),
        _ => match ev["error"]["code"].as_i64() {
            Some(c) => format!("Mistral realtime transcription error ({c})"),
            None => "Mistral realtime transcription error".into(),
        },
    }
}

impl Proto for Mistral {
    fn label(&self) -> &'static str {
        "Mistral realtime transcription"
    }
    fn url(&self) -> Result<String, String> {
        Ok(self.url.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {}", self.key))]
    }
    fn wire(&self) -> Wire {
        self.wire
    }
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx) {
        tx.send_json(json!({"type": "input_audio.append", "audio": crate::store::b64(wire)}));
    }
    fn on_close(&mut self, tx: &mut Tx) {
        tx.send_json(json!({"type": "input_audio.flush"}));
        tx.send_json(json!({"type": "input_audio.end"}));
    }
    fn finished(&self) -> bool {
        self.terminal
    }
    fn on_message(&mut self, ev: &Value, tx: &mut Tx) {
        if self.terminal {
            return;
        }
        let ty = ev["type"].as_str().unwrap_or("");
        if ty == "session.created" {
            self.partial.clear();
            self.has_final_segment = false;
            tx.send_json(json!({"type": "session.update", "session": {"audio_format": {"encoding": self.encoding, "sample_rate": self.rate}}}));
            tx.mark_ready();
            return;
        }
        if !tx.is_ready() && ty == "error" {
            tx.fail_connect(mistral_error(ev));
            return;
        }
        match ty {
            "transcription.text.delta" => {
                if let Some(t) = ev["text"].as_str().filter(|t| !t.is_empty()) {
                    if t.len() > MISTRAL_MAX_PARTIAL.saturating_sub(self.partial.len()) {
                        self.fail(MISTRAL_PARTIAL_OVERFLOW.into(), tx);
                        return;
                    }
                    self.partial.push_str(t);
                    tx.emit(SttEvent::Partial(self.partial.clone()));
                }
            }
            "transcription.segment" => {
                if let Some(t) = ev["text"].as_str().filter(|t| !t.trim().is_empty()) {
                    self.emit_final(t, "segment", tx);
                    self.partial.clear();
                }
            }
            "transcription.done" => {
                self.terminal = true;
                // Final segments already own completed speech; only later buffered deltas are new.
                let source = if self.has_final_segment {
                    "pending"
                } else {
                    "terminal"
                };
                let text = if source == "pending" {
                    self.partial.clone()
                } else {
                    ev["text"]
                        .as_str()
                        .filter(|t| !t.trim().is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| self.partial.clone())
                };
                self.partial.clear();
                self.emit_final(&text, source, tx);
                tx.close_now();
            }
            "error" => self.fail(mistral_error(ev), tx),
            _ => {}
        }
    }
}

// ───────────────────────── xAI ─────────────────────────

pub(crate) struct Xai {
    url: String,
    key: String,
    wire: Wire,
    last: Option<String>,
    speech_started: bool,
    done: bool,
}

pub(crate) const XAI_KEY_MISSING: &str =
    "xAI credentials missing for realtime STT. Set XAI_API_KEY or [media.providers.xai] api_key.";

impl Xai {
    pub(crate) fn new(m: &Media, in_rate: u32, language: Option<&str>) -> Result<Xai, String> {
        let env_base = std::env::var("XAI_BASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let c = key_of(
            m,
            "xai",
            &["XAI_API_KEY"],
            env_base.as_deref().unwrap_or("https://api.x.ai/v1"),
        );
        let key = c.key.clone().ok_or(XAI_KEY_MISSING)?;
        let base = ws_scheme(c.base.trim_end_matches('/'));
        let base = if base.starts_with("ws") {
            base
        } else {
            format!("wss://{base}")
        };
        let enc = match cfg_str(m, "xai", "encoding")
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => None,
            Some("ulaw" | "g711_ulaw" | "g711-mulaw" | "mulaw") => Some("mulaw"),
            Some("g711_alaw" | "g711-alaw" | "alaw") => Some("alaw"),
            Some("pcm") => Some("pcm"),
            Some(o) => return Err(format!("Invalid xAI realtime transcription encoding: {o}")),
        };
        let cfg_rate = cfg_num(m, "xai", "sample_rate").map(|r| r as u32);
        let (enc, rate) = match enc {
            Some(e @ ("mulaw" | "alaw")) => (e, 8000),
            Some(e) => (e, cfg_rate.unwrap_or(in_rate)),
            None if cfg_rate.unwrap_or(in_rate) == 8000 => ("mulaw", 8000),
            None => ("pcm", cfg_rate.unwrap_or(in_rate)),
        };
        let wire = match enc {
            "mulaw" => Wire::Mulaw,
            "alaw" => Wire::Alaw,
            _ => Wire::Pcm16(rate),
        };
        let mut q = vec![
            ("sample_rate", rate.to_string()),
            ("encoding", enc.to_string()),
            (
                "interim_results",
                cfg_bool(m, "xai", "interim_results")
                    .unwrap_or(true)
                    .to_string(),
            ),
            (
                "endpointing",
                (cfg_num(m, "xai", "endpointing_ms").unwrap_or(800.0) as u64).to_string(),
            ),
        ];
        if let Some(l) = language
            .map(str::to_string)
            .or_else(|| cfg_str(m, "xai", "language"))
        {
            q.push(("language", l));
        }
        Ok(Xai {
            url: format!("{base}/stt?{}", query(&q)),
            key,
            wire,
            last: None,
            speech_started: false,
            done: false,
        })
    }

    fn emit(&mut self, t: String, tx: &mut Tx) {
        if self.last.as_deref() == Some(t.as_str()) {
            return;
        }
        self.last = Some(t.clone());
        tx.emit(SttEvent::Final(t));
    }
}

impl Proto for Xai {
    fn label(&self) -> &'static str {
        "xAI realtime transcription"
    }
    fn url(&self) -> Result<String, String> {
        Ok(self.url.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {}", self.key))]
    }
    fn wire(&self) -> Wire {
        self.wire
    }
    fn send_audio(&mut self, wire: &[u8], tx: &mut Tx) {
        tx.send_binary(wire);
    }
    fn on_close(&mut self, tx: &mut Tx) {
        tx.send_json(json!({"type": "audio.done"}));
    }
    fn finished(&self) -> bool {
        self.done
    }
    fn on_message(&mut self, ev: &Value, tx: &mut Tx) {
        let ty = ev["type"].as_str().unwrap_or("");
        let detail = || {
            if ev.get("error").is_some_and(|e| !e.is_null()) {
                error_detail(&ev["error"], "xAI realtime transcription error")
            } else {
                error_detail(&ev["message"], "xAI realtime transcription error")
            }
        };
        if ty == "transcript.created" {
            tx.mark_ready();
            return;
        }
        if !tx.is_ready() && ty == "error" {
            tx.fail_connect(detail());
            return;
        }
        let text = ev["text"]
            .as_str()
            .or(ev["transcript"].as_str())
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        match ty {
            "transcript.partial" => {
                let Some(t) = text else { return };
                if !self.speech_started {
                    // Dedupe final/terminal echoes within one utterance, not identical later turns.
                    self.last = None;
                    self.speech_started = true;
                    tx.emit(SttEvent::SpeechStarted);
                }
                if ev["is_final"].as_bool().unwrap_or(false)
                    && ev["speech_final"].as_bool().unwrap_or(false)
                {
                    self.emit(t, tx);
                    self.speech_started = false;
                    return;
                }
                tx.emit(SttEvent::Partial(t));
            }
            "transcript.done" => {
                if let Some(t) = text {
                    self.emit(t, tx);
                }
                self.done = true;
                tx.close_now();
            }
            "error" => tx.emit(SttEvent::Error(detail())),
            _ => {}
        }
    }
}
