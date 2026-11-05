//! Cloud speech-to-text over each vendor's documented REST API (Hermes
//! `tools/transcription_cloud.py`, OpenClaw `extensions/deepgram/audio.ts`).
//!
//! - `openai` / `groq` / `deepinfra`: OpenAI-compatible `POST {base}/audio/transcriptions`
//! - `mistral`: Voxtral `POST {base}/audio/transcriptions`
//! - `xai`: Grok STT `POST {base}/stt`
//! - `elevenlabs`: Scribe `POST {base}/speech-to-text`
//! - `deepgram`: `POST {base}/listen?model=nova-3` with the raw audio body

use super::{lang_for, section_str, SttProvider, SttRequest, Transcript};
use crate::http::{error_message, Multipart};
use crate::Media;
use seagent_core::Cancel;
use serde_json::Value;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Request failure in Hermes' wording (`<label> transcription failed: …`).
fn fail(label: &str, status: u16, body: &str) -> String {
    format!("{label} transcription failed: HTTP {status}: {}", error_message(body))
}

/// Transcript text from a provider body: plain text, `{text}` or an `{error}` object
/// (Hermes `_extract_transcript_text`, `STTResponseError`).
pub(crate) fn extract_text(ct: &str, body: &[u8]) -> Result<(String, Value), String> {
    let s = String::from_utf8_lossy(body).trim().to_string();
    if !ct.contains("json") && !s.starts_with('{') {
        return Ok((s, Value::Null));
    }
    let v: Value = serde_json::from_str(&s).map_err(|e| format!("malformed JSON response: {e}"))?;
    if let Some(t) = v.get("text").and_then(|t| t.as_str()) {
        return Ok((strip_voxtral_prefix(t).trim().to_string(), v));
    }
    if let Some(e) = v.get("error") {
        return Err(e.get("message").and_then(|m| m.as_str()).map(str::to_string).unwrap_or_else(|| e.to_string()));
    }
    Err("response carried neither text nor error".into())
}

/// Voxtral-style `language xx <asr_text> …` prefix some responses carry.
fn strip_voxtral_prefix(t: &str) -> &str {
    let tt = t.trim_start();
    if tt.starts_with("language ") {
        if let Some(i) = tt.find("<asr_text>") {
            return &tt[i + "<asr_text>".len()..];
        }
    }
    t
}

fn transcript_from(text: String, v: &Value) -> Transcript {
    let segments = v["segments"].as_array().map(|a| a.iter().map(|s| super::Segment { start: s["start"].as_f64().unwrap_or(0.0), end: s["end"].as_f64().unwrap_or(0.0), text: s["text"].as_str().unwrap_or("").trim().to_string(), speaker: s["speaker"].as_str().map(str::to_string) }).collect()).unwrap_or_default();
    Transcript { text, language: v["language"].as_str().map(str::to_string), duration: v["duration"].as_f64(), segments }
}

/// OpenAI-compatible transcription endpoint (openai, groq, deepinfra).
pub struct OpenAiCompat {
    pub id: &'static str,
    pub label: &'static str,
    pub envs: &'static [&'static str],
    pub base_env: &'static str,
    pub default_base: &'static str,
    pub default_model: &'static str,
    pub model_env: &'static str,
}

pub const OPENAI_MODELS: &[&str] = &["whisper-1", "gpt-4o-mini-transcribe", "gpt-4o-transcribe", "gpt-transcribe"];
pub const GROQ_MODELS: &[&str] = &["whisper-large-v3-turbo", "whisper-large-v3"];
/// Groq shut `distil-whisper-large-v3-en` down on 2025-08-23; configs naming it are remapped.
pub const RETIRED_GROQ_MODELS: &[&str] = &["distil-whisper-large-v3-en"];

impl OpenAiCompat {
    pub fn openai() -> Self {
        OpenAiCompat { id: "openai", label: "OpenAI", envs: &["VOICE_TOOLS_OPENAI_KEY", "OPENAI_API_KEY"], base_env: "STT_OPENAI_BASE_URL", default_base: "https://api.openai.com/v1", default_model: "whisper-1", model_env: "STT_OPENAI_MODEL" }
    }
    pub fn groq() -> Self {
        OpenAiCompat { id: "groq", label: "Groq", envs: &["GROQ_API_KEY"], base_env: "GROQ_BASE_URL", default_base: "https://api.groq.com/openai/v1", default_model: "whisper-large-v3-turbo", model_env: "STT_GROQ_MODEL" }
    }
    pub fn deepinfra() -> Self {
        OpenAiCompat { id: "deepinfra", label: "DeepInfra", envs: &["DEEPINFRA_API_KEY"], base_env: "DEEPINFRA_BASE_URL", default_base: "https://api.deepinfra.com/v1/openai", default_model: "openai/whisper-large-v3-turbo", model_env: "STT_DEEPINFRA_MODEL" }
    }
    fn model(&self, m: &Media, req: &SttRequest) -> String {
        let mut model = req.model.clone().or_else(|| section_str(m, self.id, "model")).or_else(|| env(self.model_env)).unwrap_or_else(|| self.default_model.into());
        match self.id {
            // Groq-only names on the native OpenAI path (third-party endpoints may serve them).
            "openai" if GROQ_MODELS.contains(&model.as_str()) || RETIRED_GROQ_MODELS.contains(&model.as_str()) => model = "whisper-1".into(),
            "groq" if RETIRED_GROQ_MODELS.contains(&model.as_str()) || OPENAI_MODELS.contains(&model.as_str()) => model = "whisper-large-v3-turbo".into(),
            _ => {}
        }
        model
    }
}

impl SttProvider for OpenAiCompat {
    fn id(&self) -> &str {
        self.id
    }
    fn env(&self) -> &[&str] {
        self.envs
    }
    fn max_bytes(&self) -> usize {
        25 * 1024 * 1024
    }
    fn max_seconds(&self, m: &Media, model: Option<&str>) -> Option<f64> {
        if self.id != "openai" {
            return None;
        }
        let model = model.map(str::to_string).unwrap_or_else(|| self.model(m, &SttRequest::default()));
        match model.as_str() {
            "gpt-4o-transcribe" | "gpt-4o-mini-transcribe" => Some(450.0),
            "whisper-1" => Some(600.0),
            _ => None,
        }
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, _cancel: &Cancel) -> Result<Transcript, String> {
        let base = env(self.base_env).unwrap_or_else(|| self.default_base.into());
        let c = m.creds(self.id, self.envs, &base);
        let local = super::is_local_url(&c.base);
        if c.key.is_none() && !local {
            return Err(format!("{} not set", self.envs.last().unwrap_or(&"API key")));
        }
        let model = self.model(m, req);
        let mut form = Multipart::new().file("file", &req.file_name, &req.mime, req.audio.clone()).text("model", model.clone()).text("response_format", if model == "whisper-1" { "text" } else { "json" });
        if let Some(l) = lang_for(m, self.id, req) {
            // gpt-transcribe takes a `languages` list and rejects the legacy field.
            form = if model.starts_with("gpt-transcribe") { form.text("languages[]", l) } else { form.text("language", l) };
        }
        if let Some(p) = &req.prompt {
            form = form.text("prompt", p.clone());
        }
        let mut h = c.headers.clone();
        if let Some(k) = &c.key {
            h.push(("authorization".into(), format!("Bearer {k}")));
        }
        let (ct, body) = form.encode();
        let r = m.http.send("POST", &c.url("/audio/transcriptions"), &h, Some((&ct, &body)))?;
        if !r.ok() {
            return Err(fail(self.label, r.status, &r.text()));
        }
        let (text, v) = extract_text(&r.content_type(), &r.body).map_err(|e| format!("{} transcription failed: {e}", self.label))?;
        Ok(transcript_from(text, &v))
    }
}

pub struct Mistral;

impl SttProvider for Mistral {
    fn id(&self) -> &str {
        "mistral"
    }
    fn env(&self) -> &[&str] {
        &["MISTRAL_API_KEY"]
    }
    fn max_bytes(&self) -> usize {
        500 * 1024 * 1024
    }
    fn max_seconds(&self, _m: &Media, _model: Option<&str>) -> Option<f64> {
        Some(3600.0)
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, _cancel: &Cancel) -> Result<Transcript, String> {
        let c = m.creds("mistral", self.env(), "https://api.mistral.ai/v1");
        c.key().map_err(|_| "MISTRAL_API_KEY not set".to_string())?;
        let model = req.model.clone().or_else(|| section_str(m, "mistral", "model")).or_else(|| env("STT_MISTRAL_MODEL")).unwrap_or_else(|| "voxtral-mini-latest".into());
        let mut form = Multipart::new().file("file", &req.file_name, &req.mime, req.audio.clone()).text("model", model);
        if let Some(l) = lang_for(m, "mistral", req) {
            form = form.text("language", l);
        }
        if let Some(p) = &req.prompt {
            form = form.text("prompt", p.clone());
        }
        let mut h = c.bearer();
        h.extend(c.headers.clone());
        let (ct, body) = form.encode();
        let r = m.http.send("POST", &c.url("/audio/transcriptions"), &h, Some((&ct, &body)))?;
        if !r.ok() {
            return Err(fail("Mistral", r.status, &r.text()));
        }
        let (text, v) = extract_text(&r.content_type(), &r.body).map_err(|e| format!("Mistral transcription failed: {e}"))?;
        Ok(transcript_from(text, &v))
    }
}

pub struct Xai;

/// Blank or the old `grok-stt` alias → `STT_XAI_MODEL`, else the catalog default.
pub fn normalize_xai_model(model: Option<String>) -> String {
    match model.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(s) if s != "grok-stt" => s,
        _ => env("STT_XAI_MODEL").unwrap_or_else(|| "grok-voice-transcribe-2.0".into()),
    }
}

impl SttProvider for Xai {
    fn id(&self) -> &str {
        "xai"
    }
    fn env(&self) -> &[&str] {
        &["XAI_API_KEY"]
    }
    fn max_bytes(&self) -> usize {
        500 * 1024 * 1024
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, _cancel: &Cancel) -> Result<Transcript, String> {
        let base = env("XAI_STT_BASE_URL").unwrap_or_else(|| "https://api.x.ai/v1".into());
        let c = m.creds("xai", self.env(), &base);
        let key = c.key().map_err(|_| "No xAI credentials available (set XAI_API_KEY)".to_string())?.to_string();
        let model = normalize_xai_model(req.model.clone().or_else(|| section_str(m, "xai", "model")));
        let mut form = Multipart::new().file("file", &req.file_name, &req.mime, req.audio.clone()).text("model", model);
        let lang = lang_for(m, "xai", req);
        if let Some(l) = &lang {
            form = form.text("language", l.clone());
            // `format` (inverse text normalization) requires `language` (HTTP 400 otherwise).
            form = form.text("format", "true");
        }
        form = form.text("diarize", "false");
        let mut h = vec![("authorization".to_string(), format!("Bearer {key}")), ("user-agent".into(), format!("seagent/{}", env!("CARGO_PKG_VERSION")))];
        h.extend(c.headers.clone());
        let (ct, body) = form.encode();
        let r = m.http.send("POST", &c.url("/stt"), &h, Some((&ct, &body)))?;
        if !r.ok() {
            return Err(fail("xAI", r.status, &r.text()));
        }
        let (text, v) = extract_text("application/json", &r.body).map_err(|e| format!("xAI transcription failed: {e}"))?;
        Ok(transcript_from(text, &v))
    }
}

pub struct ElevenLabs;

impl SttProvider for ElevenLabs {
    fn id(&self) -> &str {
        "elevenlabs"
    }
    fn env(&self) -> &[&str] {
        &["ELEVENLABS_API_KEY"]
    }
    fn max_bytes(&self) -> usize {
        5 * 1024 * 1024 * 1024 - 1
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, _cancel: &Cancel) -> Result<Transcript, String> {
        let base = env("ELEVENLABS_STT_BASE_URL").unwrap_or_else(|| "https://api.elevenlabs.io/v1".into());
        let c = m.creds("elevenlabs", self.env(), &base);
        let key = c.key().map_err(|_| "ELEVENLABS_API_KEY not set".to_string())?.to_string();
        let model = req.model.clone().or_else(|| section_str(m, "elevenlabs", "model_id")).or_else(|| section_str(m, "elevenlabs", "model")).or_else(|| env("STT_ELEVENLABS_MODEL")).unwrap_or_else(|| "scribe_v2".into());
        let mut form = Multipart::new().file("file", &req.file_name, &req.mime, req.audio.clone()).text("model_id", model);
        let lang = req.language.clone().or_else(|| section_str(m, "elevenlabs", "language_code")).or_else(|| lang_for(m, "elevenlabs", req));
        if let Some(l) = lang {
            form = form.text("language_code", l);
        }
        let mut h = vec![("xi-api-key".to_string(), key)];
        h.extend(c.headers.clone());
        let (ct, body) = form.encode();
        let r = m.http.send("POST", &c.url("/speech-to-text"), &h, Some((&ct, &body)))?;
        if !r.ok() {
            let detail = r.json().ok().and_then(|v| v["detail"]["message"].as_str().or(v["detail"].as_str()).map(str::to_string)).unwrap_or_else(|| error_message(&r.text()));
            return Err(format!("ElevenLabs transcription failed: HTTP {}: {detail}", r.status));
        }
        let (text, v) = extract_text("application/json", &r.body).map_err(|e| format!("ElevenLabs transcription failed: {e}"))?;
        Ok(Transcript { language: v["language_code"].as_str().map(str::to_string), ..transcript_from(text, &v) })
    }
}

pub struct Deepgram;

/// Best transcript per channel joined in provider order (OpenClaw `readDeepgramTranscript`).
pub(crate) fn deepgram_text(v: &Value) -> Result<String, String> {
    let chans = v["results"]["channels"].as_array().ok_or("Audio transcription failed: malformed JSON response")?;
    let mut out = Vec::new();
    for ch in chans {
        let t = ch["alternatives"][0]["transcript"].as_str().ok_or("Audio transcription response missing transcript")?;
        if !t.trim().is_empty() {
            out.push(t.trim().to_string());
        }
    }
    Ok(out.join("\n\n"))
}

impl SttProvider for Deepgram {
    fn id(&self) -> &str {
        "deepgram"
    }
    fn env(&self) -> &[&str] {
        &["DEEPGRAM_API_KEY"]
    }
    fn max_bytes(&self) -> usize {
        2 * 1024 * 1024 * 1024
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, _cancel: &Cancel) -> Result<Transcript, String> {
        let c = m.creds("deepgram", self.env(), "https://api.deepgram.com/v1");
        let key = c.key().map_err(|_| "DEEPGRAM_API_KEY not set".to_string())?.to_string();
        let model = req.model.clone().or_else(|| section_str(m, "deepgram", "model")).unwrap_or_else(|| "nova-3".into());
        let mut q: Vec<(String, String)> = vec![("model".into(), model)];
        if let Some(l) = lang_for(m, "deepgram", req) {
            q.push(("language".into(), l));
        }
        for (k, v) in m.cfg.table("stt.deepgram.query") {
            q.push((k, v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())));
        }
        let pairs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let mut h = vec![("authorization".to_string(), format!("Token {key}"))];
        h.extend(c.headers.clone());
        let r = m.http.send("POST", &format!("{}?{}", c.url("/listen"), seagent_net::form_encode(&pairs)), &h, Some((&req.mime, &req.audio)))?;
        if !r.ok() {
            return Err(fail("Deepgram", r.status, &r.text()));
        }
        let v = r.json()?;
        Ok(Transcript { text: deepgram_text(&v)?, duration: v["metadata"]["duration"].as_f64(), ..Default::default() })
    }
}
