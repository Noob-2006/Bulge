//! Realtime speech-to-speech sessions, ported from OpenClaw
//! `extensions/openai/realtime-voice-{bridge,protocol,session-policy}.ts`,
//! `extensions/xai/realtime-voice-{bridge,protocol,config}.ts` and
//! `extensions/google/realtime-voice-{provider,model-contract}.ts`.
//!
//! OpenAI and xAI speak the same event vocabulary (OpenAI Realtime GA); they differ
//! in session policy, defaults and barge-in rules. Gemini Live uses its own
//! `setup` / `realtimeInput` / `serverContent` / `toolCall` protocol.

use super::conn::{ws_scheme, Conn, Incoming};
use super::{cfg_bool, cfg_num, cfg_str, settings, RealtimeVoice, VoiceEvent, VoiceOpts, Wire};
use crate::Media;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

pub const OPENAI_DEFAULT_MODEL: &str = "gpt-realtime-2.1";
pub const OPENAI_INPUT_TRANSCRIPTION_MODEL: &str = "gpt-4o-mini-transcribe";
const OPENAI_MIN_BARGE_IN_MS: u64 = 250;
pub const XAI_DEFAULT_MODEL: &str = "grok-voice-latest";
const XAI_VAD_THRESHOLD: f64 = 0.85;
const XAI_PREFIX_PADDING_MS: u64 = 333;
const XAI_SILENCE_MS: u64 = 500;
const XAI_INPUT_TRANSCRIPTION_MODEL: &str = "grok-transcribe";
const MAX_TOOL_ARGUMENT_BYTES: usize = 256_000;
const MAX_COMPLETED_TOOL_CALL_IDS: usize = 1024;
const ACTIVE_RESPONSE_ERROR_PREFIX: &str =
    "Conversation already has an active response in progress:";
const NO_ACTIVE_RESPONSE_CANCEL_ERROR: &str = "Cancellation failed: no active response found";
pub const GOOGLE_DEFAULT_MODEL: &str = "gemini-3.1-flash-live-preview";
const GOOGLE_DEFAULT_VOICE: &str = "Kore";
const GOOGLE_INPUT_RATE: u32 = 16_000;
const GOOGLE_MAX_TOOL_CALL_IDS: usize = 1024;
const GOOGLE_MAX_PENDING_TRANSCRIPT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Flavor {
    OpenAi,
    Xai,
}

fn tools_json(opts: &VoiceOpts) -> Vec<Value> {
    opts.tools.iter().map(|t| json!({"type": "function", "name": t.name, "description": t.description, "parameters": t.input_schema})).collect()
}

fn error_detail(v: &Value) -> String {
    match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Object(o) => o
            .get("message")
            .and_then(|x| x.as_str())
            .or_else(|| o.get("code").and_then(|x| x.as_str()))
            .unwrap_or("realtime voice error")
            .to_string(),
        _ => "realtime voice error".into(),
    }
}

/// OpenAI Realtime / xAI Grok Voice session.
pub(crate) struct OaiVoice {
    flavor: Flavor,
    conn: Conn,
    wire: Wire,
    rate: u32,
    response_active: bool,
    create_in_flight: bool,
    cancel_in_flight: bool,
    create_pending: bool,
    pending_tools: HashSet<String>,
    completed_tools: HashSet<String>,
    tool_buffers: HashMap<String, (String, String, String)>,
    /// (item id, bytes received, first-audio instant): the playing assistant item.
    assistant: Option<(String, usize, Instant)>,
    min_barge_in_ms: u64,
    interrupt_on_input: bool,
    ev: Vec<VoiceEvent>,
    closed: bool,
}

impl OaiVoice {
    pub(crate) fn connect(m: &Media, flavor: Flavor, opts: &VoiceOpts) -> Result<OaiVoice, String> {
        let (id, envs, base, label): (&str, &[&str], String, &str) = match flavor {
            Flavor::OpenAi => (
                "openai",
                &["OPENAI_API_KEY"],
                "https://api.openai.com/v1".into(),
                "OpenAI realtime voice",
            ),
            Flavor::Xai => (
                "xai",
                &["XAI_API_KEY"],
                std::env::var("XAI_BASE_URL")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .unwrap_or_else(|| "https://api.x.ai/v1".into()),
                "xAI realtime voice",
            ),
        };
        let c = m.creds(id, envs, &base);
        let key = c.key.clone().ok_or_else(|| match flavor {
            Flavor::OpenAi => "OpenAI Realtime voice requires an OpenAI Platform API key (OPENAI_API_KEY or [media.providers.openai] api_key)".to_string(),
            Flavor::Xai => "xAI credentials missing for realtime voice. Set XAI_API_KEY or [media.providers.xai] api_key.".to_string(),
        })?;
        let model = opts
            .model
            .clone()
            .or_else(|| cfg_str(m, id, "model"))
            .unwrap_or_else(|| {
                if flavor == Flavor::OpenAi {
                    OPENAI_DEFAULT_MODEL
                } else {
                    XAI_DEFAULT_MODEL
                }
                .into()
            });
        if flavor == Flavor::OpenAi && model.starts_with("gpt-live") {
            return Err(format!("{model} is served over WebRTC only (POST /v1/live/sessions); use a gpt-realtime model for the WebSocket transport"));
        }
        let url = cfg_str(m, &format!("{id}_voice"), "url").unwrap_or_else(|| {
            let b = ws_scheme(c.base.trim_end_matches('/'));
            let b = if b.starts_with("ws") {
                b
            } else {
                format!("wss://{b}")
            };
            format!("{b}/realtime?model={}", ark_net::urlencode(&model))
        });
        let mut headers = vec![("Authorization".to_string(), format!("Bearer {key}"))];
        headers.extend(c.headers.clone());
        let rate = if opts.sample_rate == 0 {
            24000
        } else {
            opts.sample_rate
        };
        // Telephony callers open at 8 kHz: G.711 μ-law both ways (OpenClaw default); else PCM16 24 kHz.
        let wire = match cfg_str(m, &format!("{id}_voice"), "encoding").as_deref() {
            Some("pcmu" | "g711_ulaw" | "mulaw") => Wire::Mulaw,
            Some(_) => Wire::Pcm16(24000),
            None if rate == 8000 => Wire::Mulaw,
            None => Wire::Pcm16(24000),
        };
        let s = settings(m);
        let mut conn = Conn::open(
            &url,
            &headers,
            s.connect_timeout,
            s.attempts,
            s.delay,
            label,
        )?;
        let sec = format!("{id}_voice");
        let vad = cfg_num(m, &sec, "vad_threshold");
        let prefix = cfg_num(m, &sec, "prefix_padding_ms").map(|v| v as u64);
        let silence = cfg_num(m, &sec, "silence_duration_ms").map(|v| v as u64);
        let auto = cfg_bool(m, &sec, "auto_respond").unwrap_or(true);
        let interrupt = cfg_bool(m, &sec, "interrupt_response").unwrap_or(auto);
        let tools = tools_json(opts);
        let voice = opts
            .voice
            .clone()
            .or_else(|| cfg_str(m, &sec, "voice"))
            .unwrap_or_else(|| {
                if flavor == Flavor::OpenAi {
                    "alloy"
                } else {
                    "eve"
                }
                .into()
            });
        let reasoning = cfg_str(m, &sec, "reasoning_effort");
        let language = cfg_str(m, &sec, "language");
        let session = match flavor {
            Flavor::OpenAi => {
                let mut tr = json!({"model": OPENAI_INPUT_TRANSCRIPTION_MODEL});
                if let Some(l) = &language {
                    tr["language"] = json!(l);
                }
                let mut s = json!({
                    "type": "realtime", "model": model, "instructions": opts.instructions, "output_modalities": ["audio"],
                    "audio": {
                        "input": {"format": wire.openai_format(), "noise_reduction": null, "transcription": tr,
                            "turn_detection": {"type": "server_vad", "threshold": vad.unwrap_or(0.5), "prefix_padding_ms": prefix.unwrap_or(300), "silence_duration_ms": silence.unwrap_or(500), "create_response": auto, "interrupt_response": interrupt}},
                        "output": {"format": wire.openai_format(), "voice": voice}
                    }
                });
                if let Some(r) = &reasoning {
                    s["reasoning"] = json!({"effort": r});
                }
                if !tools.is_empty() {
                    s["tools"] = json!(tools);
                    s["tool_choice"] = json!("auto");
                }
                s
            }
            Flavor::Xai => {
                let mut s = json!({
                    "instructions": opts.instructions, "voice": voice, "output_modalities": ["audio"],
                    "turn_detection": {"type": "server_vad", "threshold": vad.unwrap_or(XAI_VAD_THRESHOLD), "prefix_padding_ms": prefix.unwrap_or(XAI_PREFIX_PADDING_MS), "silence_duration_ms": silence.unwrap_or(XAI_SILENCE_MS)},
                    "audio": {"input": {"format": wire.openai_format(), "transcription": {"model": XAI_INPUT_TRANSCRIPTION_MODEL}}, "output": {"format": wire.openai_format()}}
                });
                if let Some(r) = &reasoning {
                    s["reasoning"] = json!({"effort": r});
                }
                if !tools.is_empty() {
                    s["tools"] = json!(tools);
                    s["tool_choice"] = json!("auto");
                }
                s
            }
        };
        conn.send_json(&json!({"type": "session.update", "session": session}));
        let mut err = None;
        let ready = conn.wait(s.connect_timeout, |msg| match msg {
            Incoming::Json(v) if v["type"] == "session.updated" => Some(true),
            Incoming::Json(v) if v["type"] == "error" => {
                err = Some(error_detail(&v["error"]));
                Some(false)
            }
            _ => None,
        });
        match ready {
            Some(true) => {}
            Some(false) => return Err(format!("{label}: {}", err.unwrap_or_default())),
            None if !conn.is_open() => {
                return Err(format!("{label} connection closed before ready"))
            }
            None => return Err(format!("{label} connection timeout")),
        }
        let min = cfg_num(m, &sec, "min_barge_in_audio_end_ms")
            .map(|v| v as u64)
            .unwrap_or(if flavor == Flavor::OpenAi {
                OPENAI_MIN_BARGE_IN_MS
            } else {
                0
            });
        Ok(OaiVoice {
            flavor,
            conn,
            wire,
            rate,
            response_active: false,
            create_in_flight: false,
            cancel_in_flight: false,
            create_pending: false,
            pending_tools: HashSet::new(),
            completed_tools: HashSet::new(),
            tool_buffers: HashMap::new(),
            assistant: None,
            min_barge_in_ms: min,
            interrupt_on_input: interrupt,
            ev: Vec::new(),
            closed: false,
        })
    }

    fn busy(&self) -> bool {
        self.response_active || self.create_in_flight || self.cancel_in_flight
    }

    fn request_response(&mut self) {
        if self.busy() || !self.pending_tools.is_empty() {
            self.create_pending = true;
            return;
        }
        self.create_pending = false;
        self.create_in_flight = true;
        self.conn.send_json(&json!({"type": "response.create"}));
    }

    fn flush_pending(&mut self) {
        if self.create_pending {
            self.create_pending = false;
            self.request_response();
        }
    }

    /// Milliseconds of the current assistant item the user has heard (produced audio
    /// capped by wall-clock playback since its first chunk).
    fn heard_ms(&self) -> Option<(String, u64)> {
        let (id, bytes, start) = self.assistant.as_ref()?;
        let produced = self.wire.duration_ms(*bytes);
        Some((id.clone(), produced.min(start.elapsed().as_millis() as u64)))
    }

    /// Server-VAD barge-in (OpenClaw `handleBargeIn()` without host playback options):
    /// truncate the assistant item to what was heard while it is still playing, never
    /// below the echo-guard threshold; the server's `interrupt_response` cancels generation.
    fn barge_in(&mut self) {
        let playing = self
            .assistant
            .as_ref()
            .is_some_and(|(_, b, s)| (s.elapsed().as_millis() as u64) < self.wire.duration_ms(*b));
        let item = if playing { self.heard_ms() } else { None };
        if let Some((_, ms)) = &item {
            if *ms < self.min_barge_in_ms {
                return;
            }
        }
        self.assistant = None;
        if self.response_active || self.create_in_flight {
            self.cancel_in_flight = true;
        }
        if let Some((id, ms)) = item.filter(|(id, _)| !id.is_empty()) {
            self.conn.send_json(&json!({"type": "conversation.item.truncate", "item_id": id, "content_index": 0, "audio_end_ms": ms}));
        }
        self.ev.push(VoiceEvent::Interrupted);
    }

    fn submit_now(&mut self, call_id: &str, output: &str, respond: bool) {
        self.conn.send_json(&json!({"type": "conversation.item.create", "item": {"type": "function_call_output", "call_id": call_id, "output": output}}));
        self.pending_tools.remove(call_id);
        if respond {
            self.request_response();
        }
    }

    fn deliver_tool(
        &mut self,
        item_id: Option<String>,
        call_id: String,
        name: String,
        raw: Option<String>,
    ) {
        if call_id.is_empty() || name.is_empty() || self.completed_tools.contains(&call_id) {
            return;
        }
        if self.completed_tools.len() >= MAX_COMPLETED_TOOL_CALL_IDS {
            self.ev.push(VoiceEvent::Error(format!(
                "realtime tool-call session limit exceeded ({MAX_COMPLETED_TOOL_CALL_IDS})"
            )));
            self.close();
            return;
        }
        let _ = item_id;
        self.completed_tools.insert(call_id.clone());
        self.pending_tools.insert(call_id.clone());
        let Some(raw) = raw else {
            self.submit_now(
                &call_id,
                "{\"error\":\"Invalid tool arguments: expected a JSON object.\"}",
                false,
            );
            return;
        };
        if raw.len() > MAX_TOOL_ARGUMENT_BYTES {
            self.submit_now(&call_id, &json!({"error": format!("Realtime tool arguments exceed the {MAX_TOOL_ARGUMENT_BYTES}-byte UTF-8 limit")}).to_string(), false);
            return;
        }
        match serde_json::from_str::<Value>(if raw.trim().is_empty() { "{}" } else { &raw }) {
            Ok(v) if v.is_object() => self.ev.push(VoiceEvent::ToolCall {
                id: call_id,
                name,
                args: v.to_string(),
            }),
            _ => self.submit_now(
                &call_id,
                "{\"error\":\"Invalid tool arguments: expected a JSON object.\"}",
                false,
            ),
        }
    }

    fn on_response_done(&mut self, v: &Value) {
        let status = v["response"]["status"].as_str().unwrap_or("completed");
        if status == "completed" {
            let mut seen = HashSet::new();
            for o in v["response"]["output"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                if o["type"] != "function_call"
                    || o.get("status")
                        .is_some_and(|s| s != "completed" && !s.is_null())
                {
                    continue;
                }
                let call = o["call_id"].as_str().unwrap_or("").trim().to_string();
                let item = o["id"].as_str().map(str::to_string);
                if let Some(i) = &item {
                    seen.insert(i.clone());
                }
                let raw = o["arguments"].as_str().map(str::to_string);
                self.deliver_tool(
                    item,
                    call,
                    o["name"].as_str().unwrap_or("").trim().to_string(),
                    raw,
                );
            }
            // xAI: arguments buffered from function_call_arguments.* / output_item.done.
            let buffered: Vec<(String, (String, String, String))> =
                self.tool_buffers.drain().collect();
            for (item, (name, call, args)) in buffered {
                if seen.contains(&item) {
                    continue;
                }
                let call = if call.is_empty() { item.clone() } else { call };
                self.deliver_tool(Some(item), call, name, Some(args));
            }
        }
        self.tool_buffers.clear();
        self.response_active = false;
        self.create_in_flight = false;
        self.cancel_in_flight = false;
        self.ev.push(VoiceEvent::TurnDone);
        if !self.closed {
            self.flush_pending();
        }
    }

    fn handle(&mut self, v: &Value) {
        let ty = v["type"].as_str().unwrap_or("");
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        match ty {
            "response.created" => {
                self.response_active = true;
                self.create_in_flight = false;
            }
            "conversation.output_audio.delta"
            | "response.audio.delta"
            | "response.output_audio.delta" => {
                let Some(d) = s("delta").or_else(|| s("data")) else {
                    return;
                };
                if self.cancel_in_flight {
                    return;
                }
                let Ok(bytes) = crate::store::b64_decode(&d) else {
                    self.ev.push(VoiceEvent::Error(
                        "realtime voice returned malformed base64 audio".into(),
                    ));
                    return;
                };
                match (&mut self.assistant, s("item_id")) {
                    (Some((id, n, _)), Some(item)) if *id == item => *n += bytes.len(),
                    (_, Some(item)) => self.assistant = Some((item, bytes.len(), Instant::now())),
                    (Some((_, n, _)), None) => *n += bytes.len(),
                    (None, None) => {
                        self.assistant = Some((String::new(), bytes.len(), Instant::now()))
                    }
                }
                self.response_active = true;
                self.create_in_flight = false;
                let pcm = self.wire.decode(&bytes, self.rate);
                if !pcm.is_empty() {
                    self.ev.push(VoiceEvent::Audio(pcm));
                }
            }
            "input_audio_buffer.speech_started" => {
                if self.flavor == Flavor::Xai || self.interrupt_on_input {
                    self.barge_in();
                }
            }
            "conversation.output_transcript.delta"
            | "response.text.delta"
            | "response.output_text.delta"
            | "response.audio_transcript.delta"
            | "response.output_audio_transcript.delta" => {
                if let Some(d) = s("delta").filter(|d| !d.is_empty()) {
                    self.ev.push(VoiceEvent::Transcript {
                        role: "assistant".into(),
                        text: d,
                        is_final: false,
                    });
                }
            }
            "response.text.done"
            | "response.output_text.done"
            | "response.audio_transcript.done"
            | "response.output_audio_transcript.done" => {
                if let Some(t) = s("transcript")
                    .or_else(|| s("text"))
                    .filter(|t| !t.is_empty())
                {
                    self.ev.push(VoiceEvent::Transcript {
                        role: "assistant".into(),
                        text: t,
                        is_final: true,
                    });
                }
            }
            "conversation.input_transcript.delta"
            | "conversation.item.input_audio_transcription.delta" => {
                if let Some(d) = s("delta").filter(|d| !d.is_empty()) {
                    self.ev.push(VoiceEvent::Transcript {
                        role: "user".into(),
                        text: d,
                        is_final: false,
                    });
                }
            }
            "conversation.item.input_audio_transcription.completed" => {
                if let Some(t) = s("transcript").filter(|t| !t.is_empty()) {
                    self.ev.push(VoiceEvent::Transcript {
                        role: "user".into(),
                        text: t,
                        is_final: true,
                    });
                }
            }
            "conversation.item.input_audio_transcription.failed" => {
                self.ev.push(VoiceEvent::Error(error_detail(&v["error"])))
            }
            "response.function_call_arguments.delta" if self.flavor == Flavor::Xai => {
                if let Some(item) = s("item_id") {
                    let e = self.tool_buffers.entry(item).or_insert_with(|| {
                        (
                            s("name").unwrap_or_default(),
                            s("call_id").unwrap_or_default(),
                            String::new(),
                        )
                    });
                    e.2.push_str(&s("delta").unwrap_or_default());
                }
            }
            "response.function_call_arguments.done" if self.flavor == Flavor::Xai => {
                if let Some(item) = s("item_id") {
                    let prev = self.tool_buffers.remove(&item).unwrap_or_default();
                    let name = if prev.0.is_empty() {
                        s("name").unwrap_or_default()
                    } else {
                        prev.0
                    };
                    let call = if prev.1.is_empty() {
                        s("call_id").unwrap_or_default()
                    } else {
                        prev.1
                    };
                    let args = s("arguments").unwrap_or(prev.2);
                    self.tool_buffers.insert(item, (name, call, args));
                }
            }
            "response.output_item.done" if self.flavor == Flavor::Xai => {
                let it = &v["item"];
                if it["type"] == "function_call" {
                    if let Some(item) = it["id"].as_str() {
                        self.tool_buffers.insert(
                            item.into(),
                            (
                                it["name"].as_str().unwrap_or("").into(),
                                it["call_id"].as_str().unwrap_or("").into(),
                                it["arguments"].as_str().unwrap_or("").into(),
                            ),
                        );
                    }
                }
            }
            "response.done" => self.on_response_done(v),
            "response.cancelled" => {
                self.response_active = false;
                self.cancel_in_flight = false;
            }
            "error" => {
                let d = error_detail(&v["error"]);
                if d == NO_ACTIVE_RESPONSE_CANCEL_ERROR {
                    self.response_active = false;
                    self.cancel_in_flight = false;
                    self.flush_pending();
                    return;
                }
                if d.starts_with(ACTIVE_RESPONSE_ERROR_PREFIX) {
                    self.response_active = true;
                    self.create_in_flight = false;
                    self.create_pending = true;
                    return;
                }
                self.ev.push(VoiceEvent::Error(d));
            }
            _ => {}
        }
    }
}

impl RealtimeVoice for OaiVoice {
    fn send_audio(&mut self, pcm: &[i16]) -> Result<(), String> {
        if self.closed || !self.conn.is_open() {
            return Err("realtime voice session is closed".into());
        }
        let b = self.wire.encode(pcm, self.rate);
        self.conn.send_json(
            &json!({"type": "input_audio_buffer.append", "audio": crate::store::b64(&b)}),
        );
        Ok(())
    }
    fn send_text(&mut self, text: &str) -> Result<(), String> {
        let t = text.trim();
        if t.is_empty() {
            return Ok(());
        }
        self.conn.send_json(&json!({"type": "conversation.item.create", "item": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": t}]}}));
        self.request_response();
        Ok(())
    }
    fn tool_result(&mut self, id: &str, output: &str) -> Result<(), String> {
        if !self.pending_tools.contains(id) {
            return Err(format!("no pending realtime tool call `{id}`"));
        }
        self.submit_now(id, output, true);
        Ok(())
    }
    fn poll(&mut self) -> Result<Vec<VoiceEvent>, String> {
        for msg in self.conn.drain() {
            match msg {
                Incoming::Json(v) => self.handle(&v),
                Incoming::Closed(c) => {
                    self.closed = true;
                    if let Some((code, r)) = c.filter(|(code, _)| *code != 1000) {
                        self.ev.push(VoiceEvent::Error(format!(
                            "realtime voice socket closed ({code}{})",
                            if r.is_empty() {
                                String::new()
                            } else {
                                format!(": {r}")
                            }
                        )));
                    }
                }
                Incoming::Binary(_) => {}
            }
        }
        Ok(std::mem::take(&mut self.ev))
    }
    fn close(&mut self) {
        self.closed = true;
        self.conn.close();
    }
}

// ───────────────────────── Gemini Live ─────────────────────────

pub(crate) fn is_gemini31(model: &str) -> bool {
    let m = model.strip_prefix("models/").unwrap_or(model);
    m.starts_with("gemini-3.1-") && m.contains("-live")
}

fn is_gemini38(model: &str) -> bool {
    model
        .strip_prefix("models/")
        .unwrap_or(model)
        .starts_with("gemini-3.8-live")
}

fn valid_google_tool_name(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_')
        && n.len() <= 128
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
}

/// The Live endpoint for a base URL (`https://generativelanguage.googleapis.com/v1beta`).
pub(crate) fn google_ws_url(base: &str, key: &str) -> String {
    let b = ws_scheme(base.trim_end_matches('/'));
    let b = if b.starts_with("ws") {
        b
    } else {
        format!("wss://{b}")
    };
    let (origin, path) = match b
        .find("://")
        .and_then(|i| b[i + 3..].find('/').map(|j| i + 3 + j))
    {
        Some(i) => (b[..i].to_string(), b[i..].to_string()),
        None => (b.clone(), String::new()),
    };
    let ver = path
        .rsplit('/')
        .find(|s| s.starts_with("v1"))
        .unwrap_or("v1beta");
    format!("{origin}/ws/google.ai.generativelanguage.{ver}.GenerativeService.BidiGenerateContent?key={}", ark_net::urlencode(key))
}

pub(crate) struct Gemini {
    conn: Conn,
    model: String,
    rate: u32,
    ev: Vec<VoiceEvent>,
    pending: [String; 2],
    interrupted: bool,
    seen_calls: HashSet<String>,
    names: HashMap<String, String>,
    silence_ms: u64,
    silence_limit: u64,
    stream_ended: bool,
    closed: bool,
    n: u64,
}

impl Gemini {
    pub(crate) fn connect(m: &Media, opts: &VoiceOpts) -> Result<Gemini, String> {
        let mut c = m.creds(
            "google",
            &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
            "https://generativelanguage.googleapis.com/v1beta",
        );
        if c.key.is_none() {
            c = m.creds("gemini", &["GEMINI_API_KEY", "GOOGLE_API_KEY"], &c.base);
        }
        let key = c.key.clone().ok_or("Google Live requires a Gemini API key (GEMINI_API_KEY or [media.providers.google] api_key)")?;
        let model = opts
            .model
            .clone()
            .or_else(|| cfg_str(m, "google_voice", "model"))
            .unwrap_or_else(|| GOOGLE_DEFAULT_MODEL.into());
        let url = cfg_str(m, "google_voice", "url").unwrap_or_else(|| google_ws_url(&c.base, &key));
        let s = settings(m);
        let mut conn = Conn::open(
            &url,
            &c.headers,
            s.connect_timeout,
            s.attempts,
            s.delay,
            "Google Live",
        )?;
        let decls: Vec<Value> = opts.tools.iter().filter(|t| valid_google_tool_name(&t.name)).map(|t| json!({"name": t.name, "description": t.description, "parameters": t.input_schema})).collect();
        let voice = opts
            .voice
            .clone()
            .or_else(|| cfg_str(m, "google_voice", "voice"))
            .unwrap_or_else(|| GOOGLE_DEFAULT_VOICE.into());
        let mut gen = json!({"responseModalities": ["AUDIO"], "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": voice}}}});
        if let Some(t) = cfg_num(m, "google_voice", "temperature").filter(|t| *t > 0.0) {
            gen["temperature"] = json!(t);
        }
        let mut setup = json!({
            "model": if model.starts_with("models/") { model.clone() } else { format!("models/{model}") },
            "generationConfig": gen,
            "systemInstruction": {"parts": [{"text": opts.instructions}]},
            "inputAudioTranscription": {}, "outputAudioTranscription": {}
        });
        if !decls.is_empty() {
            setup["tools"] = json!([{"functionDeclarations": decls}]);
        }
        let mut aad = serde_json::Map::new();
        if let Some(d) = cfg_bool(m, "google_voice", "automatic_activity_detection_disabled") {
            aad.insert("disabled".into(), json!(d));
        }
        if let Some(p) = cfg_num(m, "google_voice", "prefix_padding_ms") {
            aad.insert("prefixPaddingMs".into(), json!(p as u64));
        }
        if let Some(p) = cfg_num(m, "google_voice", "silence_duration_ms") {
            aad.insert("silenceDurationMs".into(), json!(p as u64));
        }
        if !aad.is_empty() {
            setup["realtimeInputConfig"] = json!({"automaticActivityDetection": aad});
        }
        conn.send_json(&json!({"setup": setup}));
        let mut err = None;
        let ok = conn.wait(s.connect_timeout, |msg| match msg {
            Incoming::Json(v) if v.get("setupComplete").is_some() => Some(true),
            Incoming::Json(v) if v.get("error").is_some() => {
                err = Some(error_detail(&v["error"]));
                Some(false)
            }
            _ => None,
        });
        match ok {
            Some(true) => {}
            Some(false) => return Err(format!("Google Live: {}", err.unwrap_or_default())),
            None if !conn.is_open() => {
                return Err("Google Live connection closed before setupComplete".into())
            }
            None => return Err("Google Live connection timeout".into()),
        }
        Ok(Gemini {
            conn,
            model,
            rate: if opts.sample_rate == 0 {
                24000
            } else {
                opts.sample_rate
            },
            ev: Vec::new(),
            pending: [String::new(), String::new()],
            interrupted: false,
            seen_calls: HashSet::new(),
            names: HashMap::new(),
            silence_ms: 0,
            silence_limit: cfg_num(m, "google_voice", "silence_duration_ms")
                .map(|v| v as u64)
                .unwrap_or(500),
            stream_ended: false,
            closed: false,
            n: 0,
        })
    }

    fn append(&mut self, role: usize, t: &Value, complete_input: bool) {
        if let Some(text) = t["text"].as_str().filter(|s| !s.is_empty()) {
            if self.pending[role].len() + text.len() > GOOGLE_MAX_PENDING_TRANSCRIPT_BYTES {
                self.pending = [String::new(), String::new()];
                self.ev.push(VoiceEvent::Error(
                    "Google Live transcript exceeded the 256 KiB pending limit".into(),
                ));
                self.close();
                return;
            }
            self.pending[role].push_str(text);
            if !complete_input {
                self.ev.push(VoiceEvent::Transcript {
                    role: ["user", "assistant"][role].into(),
                    text: text.into(),
                    is_final: false,
                });
            }
        }
        if t["finished"].as_bool().unwrap_or(false) || complete_input {
            self.flush(role);
        }
    }

    fn flush(&mut self, role: usize) {
        let t = std::mem::take(&mut self.pending[role]).trim().to_string();
        if !t.is_empty() {
            self.ev.push(VoiceEvent::Transcript {
                role: ["user", "assistant"][role].into(),
                text: t,
                is_final: true,
            });
        }
    }

    fn handle(&mut self, v: &Value) {
        if let Some(c) = v.get("serverContent") {
            if c["interrupted"].as_bool().unwrap_or(false) {
                self.interrupted = true;
                self.ev.push(VoiceEvent::Interrupted);
            }
            if c.get("inputTranscription").is_some() {
                let complete = is_gemini31(&self.model) || is_gemini38(&self.model);
                self.append(0, &c["inputTranscription"], complete);
            }
            if c.get("outputTranscription").is_some() {
                self.append(1, &c["outputTranscription"], false);
            }
            for p in c["modelTurn"]["parts"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                let Some(d) = p["inlineData"]["data"].as_str() else {
                    continue;
                };
                let Ok(bytes) = crate::store::b64_decode(d) else {
                    self.ev.push(VoiceEvent::Error(
                        "Google Live stream returned malformed base64 audio data".into(),
                    ));
                    self.close();
                    return;
                };
                let mime = p["inlineData"]["mimeType"].as_str().unwrap_or("");
                let src = mime
                    .split([';', ',', ' '])
                    .find_map(|s| s.trim().strip_prefix("rate="))
                    .and_then(|r| r.parse::<u32>().ok())
                    .filter(|r| *r > 0)
                    .unwrap_or(24000);
                let pcm =
                    crate::audio::resample(&crate::audio::pcm16_from_bytes(&bytes), src, self.rate);
                if !pcm.is_empty() {
                    self.ev.push(VoiceEvent::Audio(pcm));
                }
            }
            let done = c["generationComplete"].as_bool().unwrap_or(false)
                || c["interrupted"].as_bool().unwrap_or(false)
                || c["turnComplete"].as_bool().unwrap_or(false);
            if done {
                self.flush(1);
            }
            if c["turnComplete"].as_bool().unwrap_or(false) {
                self.interrupted = false;
                self.ev.push(VoiceEvent::TurnDone);
            }
        }
        if let Some(c) = v.get("toolCallCancellation") {
            // The server withdrew these calls: forget the pending name so a late
            // result is rejected instead of answering a cancelled call
            // (OpenClaw `handleToolCallCancellation`).
            for id in c["ids"].as_array().cloned().unwrap_or_default() {
                if let Some(id) = id.as_str() {
                    self.names.remove(id.trim());
                }
            }
        }
        if let Some(tc) = v.get("toolCall") {
            for call in tc["functionCalls"].as_array().cloned().unwrap_or_default() {
                let Some(name) = call["name"]
                    .as_str()
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                else {
                    continue;
                };
                self.n += 1;
                let id = call["id"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("google-live-{}", self.n));
                if self.seen_calls.contains(&id) {
                    continue;
                }
                // The Live protocol has no replay window: end an extreme session instead of re-admitting ids.
                if self.seen_calls.len() >= GOOGLE_MAX_TOOL_CALL_IDS {
                    self.ev.push(VoiceEvent::Error(
                        "Google Live tool-call session limit exceeded".into(),
                    ));
                    self.close();
                    return;
                }
                self.seen_calls.insert(id.clone());
                self.names.insert(id.clone(), name.to_string());
                let args = if call["args"].is_object() {
                    call["args"].to_string()
                } else {
                    "{}".into()
                };
                self.ev.push(VoiceEvent::ToolCall {
                    id,
                    name: name.into(),
                    args,
                });
            }
        }
        if let Some(g) = v.get("goAway") {
            if let Some(t) = g["timeLeft"].as_str() {
                self.ev.push(VoiceEvent::Error(format!(
                    "Google Live session goAway: {t}"
                )));
            }
        }
    }
}

impl RealtimeVoice for Gemini {
    fn send_audio(&mut self, pcm: &[i16]) -> Result<(), String> {
        if self.closed || !self.conn.is_open() {
            return Err("Google Live session is closed".into());
        }
        // Only silence that may end the audio stream counts; 3.8 needs every silent frame.
        let silent = !is_gemini38(&self.model) && !pcm.is_empty() && pcm.iter().all(|s| *s == 0);
        if silent && self.stream_ended {
            return Ok(());
        }
        let pcm16k = crate::audio::resample(pcm, self.rate, GOOGLE_INPUT_RATE);
        self.conn.send_json(&json!({"realtimeInput": {"audio": {"data": crate::store::b64(&crate::audio::pcm16_to_bytes(&pcm16k)), "mimeType": format!("audio/pcm;rate={GOOGLE_INPUT_RATE}")}}}));
        if !silent {
            self.silence_ms = 0;
            self.stream_ended = false;
            return Ok(());
        }
        self.silence_ms += pcm.len() as u64 * 1000 / self.rate.max(1) as u64;
        if !self.stream_ended && self.silence_ms >= self.silence_limit {
            self.conn
                .send_json(&json!({"realtimeInput": {"audioStreamEnd": true}}));
            self.stream_ended = true;
        }
        Ok(())
    }
    fn send_text(&mut self, text: &str) -> Result<(), String> {
        let t = text.trim();
        if t.is_empty() {
            return Ok(());
        }
        if is_gemini31(&self.model) {
            self.conn.send_json(&json!({"realtimeInput": {"text": t}}));
        } else {
            self.conn.send_json(&json!({"clientContent": {"turns": [{"role": "user", "parts": [{"text": t}]}], "turnComplete": true}}));
        }
        Ok(())
    }
    fn tool_result(&mut self, id: &str, output: &str) -> Result<(), String> {
        let Some(name) = self.names.remove(id) else {
            return Err(format!("no pending Google Live tool call `{id}`"));
        };
        let out: Value = serde_json::from_str(output).unwrap_or_else(|_| json!(output));
        self.conn.send_json(&json!({"toolResponse": {"functionResponses": [{"id": id, "name": name, "response": {"output": out}}]}}));
        Ok(())
    }
    fn poll(&mut self) -> Result<Vec<VoiceEvent>, String> {
        for msg in self.conn.drain() {
            match msg {
                Incoming::Json(v) => self.handle(&v),
                Incoming::Closed(c) => {
                    self.closed = true;
                    self.flush(0);
                    self.flush(1);
                    if let Some((code, r)) = c.filter(|(code, _)| *code != 1000) {
                        self.ev.push(VoiceEvent::Error(format!(
                            "Google Live socket closed ({code}{})",
                            if r.is_empty() {
                                String::new()
                            } else {
                                format!(": {r}")
                            }
                        )));
                    }
                }
                Incoming::Binary(_) => {}
            }
        }
        Ok(std::mem::take(&mut self.ev))
    }
    fn close(&mut self) {
        self.closed = true;
        self.conn.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ws_server;
    use ark_net::ws::{Message, WebSocket};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    fn send(ws: &mut WebSocket<TcpStream>, v: Value) {
        ws.send_text(&v.to_string()).unwrap();
    }

    fn recv(ws: &mut WebSocket<TcpStream>) -> Option<Value> {
        loop {
            match ws.recv_blocking() {
                Ok(Message::Text(t)) => return serde_json::from_str(&t).ok(),
                Ok(Message::Close(_)) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    }

    #[test]
    fn gemini_tool_call_cancellation_drops_the_pending_call() {
        let url = ws_server(|_head, ws| {
            let _ = recv(ws); // setup
            send(ws, json!({"setupComplete": {}}));
            send(
                ws,
                json!({"toolCall": {"functionCalls": [{"id": "f9", "name": "lookup", "args": {"q": "z"}}]}}),
            );
            send(ws, json!({"toolCallCancellation": {"ids": ["f9"]}}));
            // Sent after the cancellation, so observing it proves the cancel was applied.
            send(ws, json!({"serverContent": {"turnComplete": true}}));
            while recv(ws).is_some() {}
        });
        let m = Media {
            cfg: crate::MediaConfig::from_toml(&format!(
                "[realtime]\nconnect_timeout_ms = 3000\n[providers.google]\napi_key = \"gk\"\nbase_url = \"{}/v1beta\"\n",
                url.replace("ws://", "http://")
            )),
            http: Default::default(),
        };
        let opts = VoiceOpts {
            instructions: "Be brief.".into(),
            voice: None,
            model: None,
            sample_rate: 24000,
            tools: vec![],
        };
        let mut s = Gemini::connect(&m, &opts).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let mut ev = Vec::new();
        while Instant::now() < end && !ev.contains(&VoiceEvent::TurnDone) {
            ev.extend(s.poll().unwrap());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ev.iter().any(|e| matches!(e, VoiceEvent::ToolCall { .. })),
            "{ev:?}"
        );
        assert!(ev.contains(&VoiceEvent::TurnDone), "{ev:?}");
        assert!(
            s.tool_result("f9", "{\"ok\":true}").is_err(),
            "a cancelled function call must not be answered"
        );
    }
}
