//! Text-to-speech: providers, the `text_to_speech` tool, auto voice replies on
//! channels, streaming playback for voice mode, `/tts` and `/voice` commands and
//! the `talk_voice` tool.
//!
//! Providers (id — aliases): `edge` — microsoft (free default), `openai`,
//! `deepinfra`, `openrouter`, `elevenlabs`, `xai`, `xai-oauth`, `minimax`,
//! `mistral`, `gemini` — google, `azure-speech` — azure, `inworld`,
//! `fish-audio` — fish, `gradium`, `volcengine` — bytedance/doubao, `xiaomi`,
//! `vydra`, local `neutts` / `piper` / `kittentts`, `tts-local-cli` — cli,
//! user command providers (`[media.tts.providers.<name>] command = "…"`) and
//! providers registered at runtime with [`register`] (plugins).
//!
//! ```toml
//! [media.tts]
//! provider = "edge"          # or "auto" = first configured by OpenClaw autoSelectOrder
//! fallback = []              # tried in order when the provider fails
//! speed = 1.0                # global speed (0.25–4.0); per provider `[media.tts.<p>] speed`
//! voice_notes = false        # deliver Ogg/Opus voice bubbles when no channel is known
//! auto = "off"               # channel auto replies: off | always | inbound | tagged
//! max_length = 1500          # auto replies longer than this are summarized / truncated
//! summarize = true           # summarize long auto replies with the agent's model
//! max_text_length = 4096     # hard cap for auto replies (OpenClaw maxTextLength)
//! prefs_path = ""            # default $SEAGENT_HOME/media/tts-prefs.json (~/.local/share/seagent/…)
//! player = ""                # playback command template ({path}); default paplay/pw-play/aplay/ffplay/mpv
//! timeout_secs = 60
//! [media.tts.streaming]  min_len = 20
//! [media.tts.<provider>] voice / voice_id / model / model_id / speed / max_text_length / …
//! [media.tts.personas.<id>] label, provider, voice, prompt
//! [media.talk] provider = "", voice = ""     # Talk voice (talk_voice tool, /voice)
//! ```
//! Credentials: `[media.providers.<id>] api_key / base_url` or the provider's env vars.

mod cloud;
mod command;
mod commands;
mod edge;
mod local;
mod misc;
pub mod normalize;
mod prefs;
pub mod stream;
mod tool;

pub use commands::{tts_command, voice_command, CommandCtx};
pub use normalize::{strip_directives, SentenceChunker};
pub use stream::{play, speak_streaming, speak_streaming_gated, streaming_enabled, StreamReport};

use crate::{Asset, Media};
use seagent_core::{Cancel, Tool};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TtsRequest {
    pub text: String,
    pub voice: Option<String>,
    pub model: Option<String>,
    /// Wanted container: "mp3", "opus" (ogg), "wav", "pcm", "flac", "aac". `None` = provider default.
    pub format: Option<String>,
    pub speed: Option<f32>,
    pub language: Option<String>,
    /// Style prompt (OpenAI gpt-4o-mini-tts `instructions`, Gemini style).
    pub instructions: Option<String>,
}

impl TtsRequest {
    pub fn new(text: &str) -> Self {
        TtsRequest { text: text.into(), ..Default::default() }
    }
    /// The caller wants an Ogg/Opus voice note (OpenClaw `target: "voice-note"`).
    pub fn voice_note(&self) -> bool {
        matches!(self.format.as_deref(), Some("opus" | "ogg"))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Speech {
    pub audio: Asset,
    /// Sample rate when `audio` is raw PCM16 (`audio/pcm`).
    pub sample_rate: Option<u32>,
}

pub trait TtsProvider: Send + Sync {
    fn id(&self) -> &str;
    /// Env vars holding the key; empty = no key needed (Edge, local, command).
    fn env(&self) -> &[&str];
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String>;
    fn voices(&self, _m: &Media, _cancel: &Cancel) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
    /// Other names the provider answers to.
    fn aliases(&self) -> &[&str] {
        &[]
    }
    /// Host the text is sent to (`None` = synthesized on this machine).
    fn dest(&self, _m: &Media) -> Option<String> {
        None
    }
    /// Whether this provider can run now (credentials present / engine installed).
    fn configured(&self, m: &Media) -> bool {
        self.env().is_empty() || m.cfg.configured(self.id(), self.env())
    }
    /// A user command provider: audio is a voice bubble only when it opts in.
    fn command(&self) -> bool {
        false
    }
    /// Delivered as a voice bubble even without ffmpeg conversion (command `voice_compatible`).
    fn voice_compatible(&self, _m: &Media) -> bool {
        true
    }
}

/// All built-in providers, in OpenClaw `autoSelectOrder` (used for `provider = "auto"`).
pub fn providers() -> Vec<Box<dyn TtsProvider>> {
    let mut v: Vec<Box<dyn TtsProvider>> = vec![
        Box::new(cloud::OpenAi::openai()),
        Box::new(cloud::ElevenLabs),
        Box::new(cloud::Xai { oauth: false }),
        Box::new(cloud::Xai { oauth: true }),
        Box::new(misc::FishAudio),
        Box::new(edge::Edge),
        Box::new(misc::Azure),
        Box::new(misc::Inworld),
        Box::new(misc::Gradium),
        Box::new(cloud::OpenAi::openrouter()),
        Box::new(cloud::MiniMax),
        Box::new(cloud::OpenAi::deepinfra()),
        Box::new(misc::Xiaomi),
        Box::new(cloud::Gemini),
        Box::new(cloud::Mistral),
        Box::new(misc::Volcengine),
        Box::new(misc::Vydra),
        Box::new(local::Local::neutts()),
        Box::new(local::Local::piper()),
        Box::new(local::Local::kittentts()),
        Box::new(command::LocalCli),
    ];
    v.extend(registered().into_iter().map(|p| Box::new(Shared(p)) as Box<dyn TtsProvider>));
    v
}

struct Shared(Arc<dyn TtsProvider>);

impl TtsProvider for Shared {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn env(&self) -> &[&str] {
        self.0.env()
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        self.0.synthesize(m, req, cancel)
    }
    fn voices(&self, m: &Media, cancel: &Cancel) -> Result<Vec<String>, String> {
        self.0.voices(m, cancel)
    }
    fn aliases(&self) -> &[&str] {
        self.0.aliases()
    }
    fn dest(&self, m: &Media) -> Option<String> {
        self.0.dest(m)
    }
    fn configured(&self, m: &Media) -> bool {
        self.0.configured(m)
    }
    fn voice_compatible(&self, m: &Media) -> bool {
        self.0.voice_compatible(m)
    }
}

fn plugin_registry() -> &'static Mutex<Vec<Arc<dyn TtsProvider>>> {
    static R: OnceLock<Mutex<Vec<Arc<dyn TtsProvider>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a provider at runtime (Hermes plugin TTS providers): an seagent plugin or the
/// binary wraps its backend in a [`TtsProvider`]. Built-in names and command providers win.
pub fn register(p: Arc<dyn TtsProvider>) {
    let mut r = plugin_registry().lock().unwrap();
    r.retain(|x| x.id() != p.id());
    r.push(p);
}

fn registered() -> Vec<Arc<dyn TtsProvider>> {
    plugin_registry().lock().unwrap().clone()
}

/// Built-in ids (a `[media.tts.providers.<name>]` command block cannot shadow these).
pub const BUILTIN: &[&str] = &[
    "edge", "microsoft", "openai", "deepinfra", "openrouter", "elevenlabs", "xai", "xai-oauth", "minimax", "mistral", "gemini", "google", "azure-speech", "azure", "inworld", "fish-audio", "fish", "gradium", "volcengine", "bytedance", "doubao", "xiaomi",
    "vydra", "neutts", "piper", "kittentts", "tts-local-cli", "cli",
];

/// Provider by id or alias: built-ins, then user command providers, then registered ones.
pub fn find(m: &Media, id: &str) -> Option<Arc<dyn TtsProvider>> {
    let key = id.trim().to_ascii_lowercase();
    let builtin = providers().into_iter().take(21).find(|p| p.id() == key || p.aliases().contains(&key.as_str()));
    if let Some(p) = builtin {
        return Some(Arc::from(p));
    }
    if let Some(c) = command::Command::from_config(m, &key) {
        return Some(Arc::new(c));
    }
    registered().into_iter().find(|p| p.id() == key || p.aliases().contains(&key.as_str()))
}

/// `[media.tts.<provider>].<key>` as a string (also accepts the provider's aliases' sections).
pub(crate) fn opt(m: &Media, provider: &str, key: &str) -> Option<String> {
    m.cfg.get(&format!("tts.{provider}.{key}")).and_then(|v| match v {
        toml::Value::String(s) => Some(m.cfg.substitute(s.trim())),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }).filter(|s| !s.is_empty())
}

pub(crate) fn num(m: &Media, provider: &str, key: &str) -> Option<f64> {
    opt(m, provider, key).and_then(|s| s.parse().ok())
}

pub(crate) fn flag(m: &Media, provider: &str, key: &str) -> Option<bool> {
    opt(m, provider, key).map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on" | "enabled"))
}

/// Speed for a request: per-call, then `[media.tts.<p>] speed`, then `[media.tts] speed`.
pub(crate) fn speed(m: &Media, provider: &str, req: &TtsRequest) -> Option<f64> {
    req.speed.map(|s| s as f64).or_else(|| num(m, provider, "speed")).or_else(|| m.cfg.get("tts.speed").and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))))
}

/// Largest provider response body accepted (Hermes `TTS_RESPONSE_BODY_LIMIT_BYTES`).
pub(crate) const MAX_AUDIO_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn bounded(b: Vec<u8>, label: &str) -> Result<Vec<u8>, String> {
    if b.len() > MAX_AUDIO_BYTES {
        return Err(format!("{label} response exceeds {MAX_AUDIO_BYTES} bytes"));
    }
    if b.is_empty() {
        return Err(format!("{label} returned empty audio"));
    }
    Ok(b)
}

pub(crate) fn speech(bytes: Vec<u8>, mime: &str) -> Speech {
    Speech { audio: Asset::new(bytes, mime), sample_rate: None }
}

/// Per-request character cap (Hermes `PROVIDER_MAX_TEXT_LENGTH`, ElevenLabs by model).
pub fn max_text_length(m: &Media, provider: &str) -> usize {
    if let Some(n) = num(m, provider, "max_text_length").filter(|n| *n >= 1.0) {
        return n as usize;
    }
    match provider {
        "edge" | "microsoft" => 5000,
        "openai" => 4096,
        "xai" | "xai-oauth" => 15000,
        "minimax" => 10000,
        "mistral" => 4000,
        "gemini" | "google" => 32000,
        "elevenlabs" => match opt(m, "elevenlabs", "model_id").as_deref().unwrap_or(cloud::ELEVENLABS_MODEL) {
            "eleven_v3" | "eleven_ttv_v3" => 5000,
            "eleven_flash_v2" => 30000,
            "eleven_flash_v2_5" => 40000,
            _ => 10000,
        },
        "neutts" | "kittentts" => 2000,
        "piper" => 5000,
        p if !BUILTIN.contains(&p) => m.cfg.get(&format!("tts.providers.{p}.max_text_length")).and_then(|v| v.as_integer()).filter(|n| *n > 0).map(|n| n as usize).unwrap_or(5000),
        _ => 4096,
    }
}

/// Split text under a provider cap without dropping content (Hermes `_split_text_for_tts`).
pub fn split_text(text: &str, max: usize) -> Vec<String> {
    let max = if max == 0 { 4000 } else { max };
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return vec![];
    }
    if normalized.chars().count() <= max {
        return vec![normalized];
    }
    // Sentences end after . ! ? ; : , followed by whitespace.
    let mut sentences: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = normalized.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        cur.push(c);
        if ".!?;:,".contains(c) && chars.get(i + 1) == Some(&' ') {
            sentences.push(cur.trim().to_string());
            cur.clear();
        }
    }
    if !cur.trim().is_empty() {
        sentences.push(cur.trim().to_string());
    }
    let mut pieces: Vec<String> = Vec::new();
    for s in sentences {
        if s.chars().count() <= max {
            pieces.push(s);
        } else {
            pieces.extend(pack(s.split(' ').map(str::to_string).collect(), max, true));
        }
    }
    pack(pieces, max, false)
}

fn pack(pieces: Vec<String>, max: usize, slice: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for p in pieces {
        let plen = p.chars().count();
        if slice && plen > max {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            let cs: Vec<char> = p.chars().collect();
            out.extend(cs.chunks(max).map(|c| c.iter().collect::<String>()));
            continue;
        }
        let cand = if cur.is_empty() { p.clone() } else { format!("{cur} {p}") };
        if !cur.is_empty() && cand.chars().count() > max {
            out.push(std::mem::replace(&mut cur, p));
        } else {
            cur = cand;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The configured provider id: persisted `/tts provider` choice, then `[media.tts] provider`
/// (`auto` = first configured built-in), default `edge`.
pub fn configured_provider(m: &Media) -> String {
    let p = prefs::load(m).provider.or_else(|| m.cfg.str("tts.provider")).unwrap_or_else(|| "edge".into()).to_ascii_lowercase();
    if p == "auto" {
        return providers().into_iter().find(|x| x.configured(m) && !x.command()).map(|x| x.id().to_string()).unwrap_or_else(|| "edge".into());
    }
    p
}

/// One synthesis attempt for status reporting.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attempt {
    pub provider: String,
    pub ok: bool,
    pub error: Option<String>,
    pub latency_ms: u128,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LastAttempt {
    pub at: u64,
    pub text_len: usize,
    pub summarized: bool,
    pub attempts: Vec<Attempt>,
}

fn last_slot() -> &'static Mutex<Option<LastAttempt>> {
    static L: OnceLock<Mutex<Option<LastAttempt>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(None))
}

pub fn last_attempt() -> Option<LastAttempt> {
    last_slot().lock().unwrap().clone()
}

pub(crate) fn set_last_attempt(a: LastAttempt) {
    *last_slot().lock().unwrap() = Some(a);
}

/// Provider chain: configured provider then `[media.tts] fallback`, de-duplicated.
pub fn chain(m: &Media) -> Vec<String> {
    let mut v = vec![configured_provider(m)];
    for f in m.cfg.list("tts.fallback") {
        let f = f.to_ascii_lowercase();
        if !v.contains(&f) {
            v.push(f);
        }
    }
    v
}

/// Synthesize with `[media.tts] provider` (then `fallback` providers); returns the provider id used.
pub fn synthesize(m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<(String, Speech), String> {
    synthesize_chain(m, &chain(m), req, cancel)
}

pub(crate) fn synthesize_chain(m: &Media, chain: &[String], req: &TtsRequest, cancel: &Cancel) -> Result<(String, Speech), String> {
    if req.text.trim().is_empty() {
        return Err("Text is required".into());
    }
    let mut attempts = Vec::new();
    let mut errors = Vec::new();
    for id in chain {
        let start = std::time::Instant::now();
        let r = match find(m, id) {
            Some(p) => p.synthesize(m, req, cancel).map(|s| (p.id().to_string(), s)),
            None => Err(format!("unknown TTS provider `{id}`")),
        };
        let ms = start.elapsed().as_millis();
        match r {
            Ok((pid, s)) if !s.audio.bytes.is_empty() => {
                attempts.push(Attempt { provider: pid.clone(), ok: true, error: None, latency_ms: ms });
                set_last_attempt(LastAttempt { at: unix_now(), text_len: req.text.chars().count(), summarized: false, attempts });
                return Ok((pid, s));
            }
            Ok(_) => {
                attempts.push(Attempt { provider: id.clone(), ok: false, error: Some("no audio".into()), latency_ms: ms });
                errors.push(format!("{id}: produced no audio"));
            }
            Err(e) => {
                attempts.push(Attempt { provider: id.clone(), ok: false, error: Some(e.clone()), latency_ms: ms });
                errors.push(format!("{id}: {e}"));
            }
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    set_last_attempt(LastAttempt { at: unix_now(), text_len: req.text.chars().count(), summarized: false, attempts });
    Err(format!("TTS failed ({})", errors.join("; ")))
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Platforms whose voice bubbles need Ogg/Opus (Hermes `OPUS_VOICE_PLATFORMS`).
pub const OPUS_VOICE_PLATFORMS: &[&str] = &["telegram", "matrix", "feishu", "whatsapp", "signal"];

/// Final audio for delivery: PCM wrapped as WAV, Ogg/Opus voice note when wanted
/// (ffmpeg-converted when the provider did not emit it). Returns `(asset, voice_bubble)`.
pub(crate) fn finalize(m: &Media, provider: &str, s: Speech, want_opus: bool, cancel: &Cancel) -> (Asset, bool) {
    let mut a = s.audio;
    if a.mime == "audio/pcm" || a.mime == "audio/l16" {
        a = Asset::new(crate::audio::wav_from_pcm_bytes(&a.bytes, s.sample_rate.unwrap_or(24000), 1), "audio/wav");
    }
    let real = crate::store::sniff(&a.bytes);
    if real != "application/octet-stream" && crate::store::class_of(real) == "audio" {
        a.mime = real.to_string();
    }
    let p = find(m, provider);
    let opted = p.as_ref().map(|p| !p.command() || p.voice_compatible(m)).unwrap_or(true);
    if !want_opus || !opted {
        return (a, false);
    }
    if a.mime == "audio/ogg" {
        return (a, true);
    }
    match crate::audio::to_ogg_opus(&a.bytes, &a.mime, cancel) {
        Ok(b) => (Asset::new(b, "audio/ogg"), true),
        Err(_) => (a, false),
    }
}

/// Markdown / code / URLs → speakable plain text (Hermes tts_text_normalize).
pub fn normalize(text: &str) -> String {
    normalize::prepare_spoken_text(text)
}

/// Auto voice reply for a channel (`[media.tts] auto`, plus this chat's `/tts chat` or
/// `/voice tts` override when `chat` is `<channel>:<chat>`): returns the audio file and
/// whether to send it as a voice bubble, or `None` when this reply should stay text-only.
pub fn auto_reply(m: &Media, text: &str, inbound_voice: bool, channel: &str, chat: Option<&str>, cancel: &Cancel) -> Option<(std::path::PathBuf, bool)> {
    commands::auto_reply(m, text, inbound_voice, channel, chat, cancel)
}

/// Persist one chat's auto-TTS override (`<channel>:<chat>`; `off` / `voice_only` / `all`),
/// as `/tts chat` and `/voice tts` do. `None` clears it back to the profile default.
pub fn set_chat_auto(m: &Media, chat: &str, mode: Option<&str>) -> Result<(), String> {
    prefs::set_chat_mode(m, chat, mode).map(|_| ())
}

/// The persisted override for one chat (`None` = the profile's `[media.tts] auto` applies).
pub fn chat_auto(m: &Media, chat: &str) -> Option<String> {
    prefs::chat_mode(m, chat)
}

/// The Talk voice chosen with `/voice set` / `talk_voice` (falls back to `[media.talk] voice`).
pub fn talk_voice(m: &Media) -> Option<String> {
    prefs::load(m).talk_voice.or_else(|| m.cfg.str("talk.voice"))
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(tool::TextToSpeech { m: m.clone() }), Arc::new(tool::TalkVoice { m: m.clone() })]
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    /// A config pointing `id` at a fake server plus extra TOML.
    pub fn media(id: &str, base: &str, extra: &str) -> Media {
        let dir = crate::testutil::temp_dir("tts-prefs");
        let extra = format!("[tts]\nprefs_path = '{}'\n{extra}", dir.join("p.json").display());
        Media { cfg: crate::testutil::cfg_for(id, base, &extra), http: crate::http::Http::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_never_drops_text() {
        let t = "One sentence here. Another one, with a comma; and more words to pad things out!";
        let parts = split_text(t, 20);
        assert!(parts.iter().all(|p| p.chars().count() <= 20), "{parts:?}");
        assert_eq!(parts.join(" ").split_whitespace().collect::<Vec<_>>(), t.split_whitespace().collect::<Vec<_>>());
        assert_eq!(split_text("short", 100), vec!["short"]);
        assert_eq!(split_text(&"x".repeat(25), 10).len(), 3);
        assert!(split_text("   ", 10).is_empty());
    }

    #[test]
    fn caps_and_lookup() {
        let m = Media { cfg: crate::MediaConfig::from_toml("[tts.elevenlabs]\nmodel_id = \"eleven_flash_v2_5\"\n[tts.openai]\nmax_text_length = 99\n[tts.providers.mine]\ncommand = \"say {input_path}\"\nmax_text_length = 7\n"), http: Default::default() };
        assert_eq!(max_text_length(&m, "elevenlabs"), 40000);
        assert_eq!(max_text_length(&m, "openai"), 99);
        assert_eq!(max_text_length(&m, "mine"), 7);
        assert_eq!(max_text_length(&m, "edge"), 5000);
        assert_eq!(find(&m, "google").unwrap().id(), "gemini");
        assert_eq!(find(&m, "microsoft").unwrap().id(), "edge");
        assert_eq!(find(&m, "mine").unwrap().id(), "mine");
        assert!(find(&m, "nope").is_none());
        let ids: Vec<String> = providers().iter().map(|p| p.id().to_string()).collect();
        let mut dedup = ids.clone();
        dedup.dedup();
        assert_eq!(ids.len(), 21);
        assert_eq!(dedup.len(), ids.len());
    }

    #[test]
    fn chain_falls_back_and_records_attempts() {
        let srv = crate::testutil::FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/audio/speech" => (500, vec![], b"{\"error\":{\"message\":\"boom\"}}".to_vec()),
            _ => (200, vec![("content-type".into(), "audio/mpeg".into())], b"ID3\x04mp3data".to_vec()),
        });
        let m = testkit::media("openai", &srv.url, &format!("provider = \"openai\"\nfallback = [\"elevenlabs\"]\n[providers.elevenlabs]\napi_key = \"k\"\nbase_url = \"{}\"", srv.url));
        let (p, s) = synthesize(&m, &TtsRequest::new("hello there"), &Cancel::new()).unwrap();
        assert_eq!((p.as_str(), s.audio.mime.as_str()), ("elevenlabs", "audio/mpeg"));
        let last = last_attempt().unwrap();
        assert!(last.attempts.iter().any(|a| a.provider == "openai" && !a.ok));
        let m2 = testkit::media("openai", &srv.url, "provider = \"openai\"");
        let e = synthesize(&m2, &TtsRequest::new("hi"), &Cancel::new()).unwrap_err();
        assert!(e.contains("openai") && e.contains("boom"), "{e}");
    }

    #[test]
    fn finalize_wraps_pcm() {
        let m = Media { cfg: crate::MediaConfig::default(), http: Default::default() };
        let (a, voice) = finalize(&m, "gemini", Speech { audio: Asset::new(vec![0; 480], "audio/pcm"), sample_rate: Some(24000) }, false, &Cancel::new());
        assert_eq!((a.mime.as_str(), voice), ("audio/wav", false));
        let (_, v) = finalize(&m, "openai", Speech { audio: Asset::new(b"OggS\0\0\0\0".to_vec(), "audio/ogg"), sample_rate: None }, true, &Cancel::new());
        assert!(v);
    }
}
