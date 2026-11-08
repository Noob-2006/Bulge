//! Speech-to-text (batch): cloud providers, local faster-whisper / whisper CLI /
//! managed whisper.cpp, user command providers, plugin providers, chunking of long
//! audio, live streaming sessions, and the `transcripts` tool. [`transcribe`] is the
//! path inbound voice messages, voice mode and transcripts use (Hermes
//! `tools/transcription_tools.py` and siblings).
//!
//! ```toml
//! [media.stt]
//! enabled = true
//! provider = "auto"     # auto = local > local_command > groq > openai > mistral > xai > elevenlabs > deepinfra > deepgram
//! language = ""         # hint for every provider ([media.stt.<p>] language wins)
//! prompt = ""           # vocabulary / context hint (whisper-family keeps the last ~224 tokens)
//! streaming = false     # live partial transcripts in voice mode (see stt::stream)
//! [media.stt.openai]  model = "whisper-1"           # also groq / deepinfra / mistral / xai / elevenlabs / deepgram
//! [media.stt.local]   model = "base"                # see stt::local
//! [media.stt.providers.<name>] command = "…"        # see stt::command
//! ```
//! Credentials: `[media.providers.<id>] api_key / base_url` or the provider env vars
//! (`OPENAI_API_KEY`/`VOICE_TOOLS_OPENAI_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`,
//! `XAI_API_KEY`, `ELEVENLABS_API_KEY`, `DEEPINFRA_API_KEY`, `DEEPGRAM_API_KEY`).

pub mod chunk;
pub mod cloud;
pub mod command;
pub mod local;
pub mod stream;
pub mod transcripts;

pub use command::register;

use crate::Media;
use seagent_core::{Cancel, Tool};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SttRequest {
    pub audio: Vec<u8>,
    pub mime: String,
    pub file_name: String,
    pub language: Option<String>,
    /// Vocabulary / context hint.
    pub prompt: Option<String>,
    pub model: Option<String>,
}

impl SttRequest {
    pub fn new(audio: Vec<u8>, mime: &str) -> Self {
        let file_name = format!("audio.{}", crate::store::ext_for(mime));
        SttRequest { audio, mime: mime.into(), file_name, ..Default::default() }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Segment {
    pub start: f64,
    pub end: f64,
    pub text: String,
    pub speaker: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Transcript {
    pub text: String,
    pub language: Option<String>,
    pub duration: Option<f64>,
    pub segments: Vec<Segment>,
}

pub trait SttProvider: Send + Sync {
    fn id(&self) -> &str;
    fn env(&self) -> &[&str];
    /// Largest upload the provider accepts (bytes); longer audio is chunked.
    fn max_bytes(&self) -> usize {
        25 * 1024 * 1024
    }
    /// Longest audio one request may carry (`None` = no duration cap).
    fn max_seconds(&self, _m: &Media, _model: Option<&str>) -> Option<f64> {
        None
    }
    /// Runs on this machine (no upload cap, no silence trim).
    fn local(&self) -> bool {
        false
    }
    /// Usable right now (credentials present / engine installed). Never installs.
    fn available(&self, m: &Media) -> bool {
        self.env().is_empty() || m.cfg.configured(self.id(), self.env())
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<Transcript, String>;
}

/// Built-in provider ids (plugins and command providers may not take these names).
pub const BUILTIN: &[&str] = &["local", "local_command", "groq", "openai", "mistral", "xai", "elevenlabs", "deepinfra", "deepgram"];
/// Built-ins that upload audio.
pub const CLOUD: &[&str] = &["groq", "openai", "mistral", "xai", "elevenlabs", "deepinfra", "deepgram"];

/// Built-in providers in auto-detect priority order.
pub fn providers() -> Vec<Box<dyn SttProvider>> {
    vec![
        Box::new(local::FasterWhisper),
        Box::new(local::LocalCommand),
        Box::new(cloud::OpenAiCompat::groq()),
        Box::new(cloud::OpenAiCompat::openai()),
        Box::new(cloud::Mistral),
        Box::new(cloud::Xai),
        Box::new(cloud::ElevenLabs),
        Box::new(cloud::OpenAiCompat::deepinfra()),
        Box::new(cloud::Deepgram),
    ]
}

/// `[media.stt.<provider>].<key>` as a trimmed string.
pub(crate) fn section_str(m: &Media, provider: &str, key: &str) -> Option<String> {
    m.cfg.get(&format!("stt.{provider}.{key}")).and_then(|v| match v {
        toml::Value::String(s) => Some(m.cfg.substitute(s.trim())),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        _ => None,
    }).filter(|s| !s.is_empty())
}

/// Language hint: `[media.stt.<provider>] language` > `[media.stt] language` >
/// `SEAGENT_LOCAL_STT_LANGUAGE` / `HERMES_LOCAL_STT_LANGUAGE` > none (auto-detect).
pub fn configured_language(m: &Media, provider: &str) -> Option<String> {
    section_str(m, provider, "language").or_else(|| m.cfg.str("stt.language")).or_else(|| ["SEAGENT_LOCAL_STT_LANGUAGE", "HERMES_LOCAL_STT_LANGUAGE"].iter().find_map(|k| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())))
}

pub(crate) fn lang_for(m: &Media, provider: &str, req: &SttRequest) -> Option<String> {
    req.language.clone().filter(|l| !l.trim().is_empty()).or_else(|| configured_language(m, provider))
}

/// Loopback / private network URL (keyless self-hosted OpenAI-compatible servers).
pub(crate) fn is_local_url(url: &str) -> bool {
    let h = crate::http::host_of(url).to_ascii_lowercase();
    let h = h.rsplit_once('@').map(|(_, h)| h).unwrap_or(&h);
    let host = if h.starts_with('[') { h.split(']').next().unwrap_or("").trim_start_matches('[') } else { h.split(':').next().unwrap_or("") };
    host == "localhost" || host == "::1" || host.ends_with(".local") || host.starts_with("127.") || host.starts_with("10.") || host.starts_with("192.168.") || (host.starts_with("172.") && host.split('.').nth(1).and_then(|o| o.parse::<u8>().ok()).is_some_and(|o| (16..=31).contains(&o)))
}

fn builtin(id: &str) -> Option<Box<dyn SttProvider>> {
    providers().into_iter().find(|p| p.id() == id)
}

pub fn enabled(m: &Media) -> bool {
    m.cfg.bool_or("stt.enabled", true)
}

/// Which provider [`transcribe`] uses: an explicit `[media.stt] provider` is honoured
/// (no silent cloud fallback; `local` means faster-whisper else the local command);
/// otherwise the first available in priority order; `"none"` when nothing is.
pub fn resolve_provider(m: &Media) -> String {
    if !enabled(m) {
        return "none".into();
    }
    let p = m.cfg.str("stt.provider").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "auto".into());
    let avail = |id: &str| builtin(id).is_some_and(|p| p.available(m));
    match p.as_str() {
        "auto" => providers().iter().find(|x| x.available(m)).map(|x| x.id().to_string()).unwrap_or_else(|| "none".into()),
        "local" => ["local", "local_command"].into_iter().find(|id| avail(id)).unwrap_or("none").into(),
        "local_command" => ["local_command", "local"].into_iter().find(|id| avail(id)).unwrap_or("none").into(),
        id if CLOUD.contains(&id) => {
            // Keyless self-hosted OpenAI-compatible base URLs count as configured.
            let local_base = matches!(id, "openai" | "groq" | "deepinfra") && m.cfg.str(&format!("providers.{id}.base_url")).is_some_and(|b| is_local_url(&b));
            if avail(id) || local_base {
                id.into()
            } else {
                "none".into()
            }
        }
        other => other.into(),
    }
}

/// The provider object for `id`: built-in > `[media.stt.providers.<id>]` command > plugin.
pub fn find(m: &Media, id: &str) -> Option<Arc<dyn SttProvider>> {
    if let Some(b) = builtin(id) {
        return Some(Arc::from(b));
    }
    if let Some(c) = command::Command::from_config(m, id) {
        return Some(Arc::new(c));
    }
    command::find_plugin(id)
}

fn no_provider_error(m: &Media, provider: &str) -> String {
    if provider != "none" && !BUILTIN.contains(&provider) {
        return format!("stt.provider='{provider}' is set but no built-in, command, or plugin provider registered that name. Configure a command provider under `[media.stt.providers.{provider}] command`.");
    }
    if let Some(p) = m.cfg.str("stt.provider").filter(|p| p != "auto") {
        return format!("STT provider '{p}' configured but unavailable (missing API key or local engine)");
    }
    "No STT provider available. Install faster-whisper for free local transcription, configure SEAGENT_LOCAL_STT_COMMAND or install whisper.cpp (whisper-cli) or the whisper CLI, set GROQ_API_KEY for free Groq Whisper, set MISTRAL_API_KEY for Mistral Voxtral Transcribe, set XAI_API_KEY for xAI Grok STT, set ELEVENLABS_API_KEY for ElevenLabs Scribe, set DEEPGRAM_API_KEY for Deepgram, or set VOICE_TOOLS_OPENAI_KEY or OPENAI_API_KEY for the OpenAI Whisper API.".into()
}

/// Whisper-family models only use the final ~224 tokens of the prompt: keep the tail.
pub const WHISPER_PROMPT_TOKEN_CAP: usize = 224;
const PROMPT_CAPPED: &[&str] = &["local", "openai", "groq", "deepinfra"];

pub fn cap_prompt(prompt: Option<String>, provider: &str) -> Option<String> {
    let p = prompt.filter(|p| !p.trim().is_empty())?;
    let max = WHISPER_PROMPT_TOKEN_CAP * 4;
    if !PROMPT_CAPPED.contains(&provider) || p.chars().count() <= max {
        return Some(p);
    }
    let n = p.chars().count();
    Some(p.chars().skip(n - max).collect())
}

/// Transcribe with the resolved provider, fitting oversized audio under the cloud
/// provider's upload cap (re-encode, else split at silences). Returns the provider id.
pub fn transcribe(m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<(String, Transcript), String> {
    if !enabled(m) {
        return Err("STT is disabled in config ([media.stt] enabled = false).".into());
    }
    if req.audio.is_empty() {
        return Err("Audio file is empty".into());
    }
    let id = resolve_provider(m);
    transcribe_with(m, &id, req, cancel)
}

/// Transcribe with a specific provider id.
pub fn transcribe_with(m: &Media, id: &str, req: &SttRequest, cancel: &Cancel) -> Result<(String, Transcript), String> {
    let p = find(m, id).ok_or_else(|| no_provider_error(m, id))?;
    let mut r = req.clone();
    r.prompt = cap_prompt(r.prompt.clone().or_else(|| m.cfg.str("stt.prompt")), id);
    if r.file_name.is_empty() {
        r.file_name = format!("audio.{}", crate::store::ext_for(&r.mime));
    }
    if !p.local() {
        let limit = (p.max_bytes(), p.max_seconds(m, r.model.as_deref()));
        let over_bytes = r.audio.len() > limit.0;
        let duration = if !over_bytes && limit.1.is_some() { pcm_duration(&r) } else { None };
        if over_bytes || duration.is_some_and(|d| Some(d) > limit.1) {
            let dir = local::work_dir("big")?;
            let input = dir.join(format!("input.{}", crate::store::ext_for(&r.mime)));
            std::fs::write(&input, &r.audio).map_err(|e| e.to_string())?;
            let res = chunk::transcribe_oversized(&input, limit, cancel, |bytes, mime, name| p.transcribe(m, &SttRequest { audio: bytes, mime: mime.into(), file_name: name.into(), ..r.clone() }, cancel));
            let _ = std::fs::remove_dir_all(&dir);
            return res.map(|t| (p.id().to_string(), t));
        }
    }
    let t = p.transcribe(m, &r, cancel)?;
    Ok((p.id().to_string(), t))
}

fn pcm_duration(r: &SttRequest) -> Option<f64> {
    if let Ok(p) = crate::audio::wav_decode(&r.audio) {
        return Some(p.duration_secs());
    }
    let d = local::work_dir("dur").ok()?;
    let f = d.join(format!("a.{}", crate::store::ext_for(&r.mime)));
    std::fs::write(&f, &r.audio).ok()?;
    let out = crate::audio::duration_secs(&f, &Cancel::new());
    let _ = std::fs::remove_dir_all(&d);
    out
}

/// Transcribe a file on disk (mime from its magic bytes / extension).
pub fn transcribe_file(m: &Media, path: &Path, cancel: &Cancel) -> Result<(String, Transcript), String> {
    let audio = std::fs::read(path).map_err(|e| format!("Audio file not found: {} ({e})", path.display()))?;
    let sniffed = crate::store::sniff(&audio);
    let mime = if sniffed == "application/octet-stream" { crate::store::mime_for_path(path) } else { sniffed };
    let mut req = SttRequest::new(audio, mime);
    req.file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(req.file_name);
    transcribe(m, &req, cancel)
}

/// Passive recovery after the configured provider failed: an installed local
/// backend only, never cloud (Hermes `transcribe_audio_local_fallback`).
pub fn transcribe_local_fallback(m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<(String, Transcript), String> {
    for id in ["local", "local_command"] {
        if builtin(id).is_some_and(|p| p.available(m)) {
            return transcribe_with(m, id, req, cancel);
        }
    }
    Err("No installed local STT backend is available.".into())
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    transcripts::tools(m)
}

// Unix only: the command providers under test are `#!/bin/sh` scripts.
#[cfg(all(test, unix))]
mod tests;
