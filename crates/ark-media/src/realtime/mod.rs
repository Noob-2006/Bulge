//! Realtime (streaming) transcription and realtime voice-model sessions over
//! WebSocket (OpenClaw `src/realtime-transcription`, `extensions/*/realtime-*`),
//! plus the GPT-Live full-duplex voice front-end (Hermes `tools/voice_live.py`).
//!
//! Transcription providers (id — aliases, auto-select order): `openai` — openai-realtime (10),
//! `xai` — xai-realtime, grok-stt-streaming (25), `deepgram` — deepgram-realtime,
//! nova-3-streaming (35), `elevenlabs` — elevenlabs-realtime, scribe-v2-realtime (40),
//! `mistral` — mistral-realtime, voxtral-realtime (45).
//! Voice providers: `openai` — openai-realtime-voice (10), `google` — gemini, gemini-live (20),
//! `xai` — xai-realtime-voice, grok-voice (25).
//!
//! ```toml
//! [media.realtime]
//! stt_provider = "auto"        # or an id/alias above; "auto" = first with credentials
//! voice_provider = "auto"
//! connect_timeout_ms = 10000   # ready handshake budget
//! close_timeout_ms = 5000      # finalize/flush drain budget on finish()
//! reconnect_attempts = 5       # transport retries while connecting
//! reconnect_delay_ms = 1000
//! [media.realtime.openai]      model = "gpt-4o-transcribe", language, prompt, encoding = "pcmu"|"pcm",
//!                              silence_duration_ms = 800, vad_threshold = 0.5, url
//! [media.realtime.deepgram]    model = "nova-3", encoding = linear16|mulaw|alaw, sample_rate,
//!                              interim_results = true, endpointing_ms = 800, language
//! [media.realtime.elevenlabs]  model = "scribe_v2_realtime", audio_format = "ulaw_8000"|"pcm_16000"…,
//!                              commit_strategy = vad|manual, vad_silence_threshold_secs, vad_threshold,
//!                              min_speech_duration_ms, min_silence_duration_ms, language
//! [media.realtime.mistral]     model = "voxtral-mini-transcribe-realtime-2602", encoding, sample_rate,
//!                              target_streaming_delay_ms = 800, url
//! [media.realtime.xai]         encoding = pcm|mulaw|alaw, sample_rate, interim_results, endpointing_ms, language
//! [media.realtime.openai_voice] model = "gpt-realtime-2.1", voice = "alloy", vad_threshold, prefix_padding_ms,
//!                              silence_duration_ms, auto_respond, interrupt_response, reasoning_effort,
//!                              language, min_barge_in_audio_end_ms = 250, encoding, url
//! [media.realtime.xai_voice]   model = "grok-voice-latest", voice = "eve", … (same keys)
//! [media.realtime.google_voice] model = "gemini-3.1-flash-live-preview", voice = "Kore", temperature,
//!                              silence_duration_ms = 500, prefix_padding_ms, automatic_activity_detection_disabled, url
//! ```
//! Credentials: `[media.providers.<id>] api_key / base_url` (an `http(s)` base is turned into
//! `ws(s)`) or `OPENAI_API_KEY`, `DEEPGRAM_API_KEY`, `ELEVENLABS_API_KEY`/`XI_API_KEY`,
//! `MISTRAL_API_KEY`, `XAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`.

pub mod conn;
#[cfg(feature = "personal")]
pub mod live;
mod stt;
#[cfg(feature = "personal")]
mod voice;

use crate::Media;
use ark_core::ToolSchema;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum SttEvent {
    Partial(String),
    Final(String),
    /// Voice activity started / stopped (server VAD).
    SpeechStarted,
    SpeechStopped,
    Error(String),
}

/// A live transcription stream fed 16-bit mono PCM at the rate it was opened with.
pub trait RealtimeStt: Send {
    fn send_audio(&mut self, pcm: &[i16]) -> Result<(), String>;
    /// Events received so far (non-blocking).
    fn poll(&mut self) -> Result<Vec<SttEvent>, String>;
    /// Flush and close; returns trailing events.
    fn finish(&mut self) -> Result<Vec<SttEvent>, String>;
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VoiceOpts {
    pub instructions: String,
    pub voice: Option<String>,
    pub model: Option<String>,
    /// PCM rate both ways.
    pub sample_rate: u32,
    pub tools: Vec<ToolSchema>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VoiceEvent {
    Audio(Vec<i16>),
    /// `role` = "user" | "assistant".
    Transcript {
        role: String,
        text: String,
        is_final: bool,
    },
    ToolCall {
        id: String,
        name: String,
        args: String,
    },
    /// The user started talking over the reply (barge-in): stop playback.
    Interrupted,
    TurnDone,
    Error(String),
}

/// A full-duplex speech-to-speech session (OpenAI Realtime, Gemini Live, xAI).
pub trait RealtimeVoice: Send {
    fn send_audio(&mut self, pcm: &[i16]) -> Result<(), String>;
    fn send_text(&mut self, text: &str) -> Result<(), String>;
    fn tool_result(&mut self, id: &str, output: &str) -> Result<(), String>;
    fn poll(&mut self) -> Result<Vec<VoiceEvent>, String>;
    fn close(&mut self);
}

/// Audio framing on the wire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Wire {
    /// G.711 μ-law, 8 kHz.
    Mulaw,
    /// G.711 A-law, 8 kHz.
    Alaw,
    /// Signed 16-bit little-endian PCM at the given rate.
    Pcm16(u32),
    S32le(u32),
    F32le(u32),
}

impl Wire {
    pub fn rate(&self) -> u32 {
        match self {
            Wire::Mulaw | Wire::Alaw => 8000,
            Wire::Pcm16(r) | Wire::S32le(r) | Wire::F32le(r) => *r,
        }
    }
    fn bytes_per_sample(&self) -> usize {
        match self {
            Wire::Mulaw | Wire::Alaw => 1,
            Wire::Pcm16(_) => 2,
            Wire::S32le(_) | Wire::F32le(_) => 4,
        }
    }
    /// Playback length of `bytes` of this format.
    pub fn duration_ms(&self, bytes: usize) -> u64 {
        (bytes / self.bytes_per_sample()) as u64 * 1000 / self.rate().max(1) as u64
    }
    /// Mono PCM at `rate` → wire bytes.
    pub fn encode(&self, pcm: &[i16], rate: u32) -> Vec<u8> {
        let s = crate::audio::resample(pcm, rate, self.rate());
        match self {
            Wire::Mulaw => s.iter().map(|x| crate::audio::pcm_to_ulaw(*x)).collect(),
            Wire::Alaw => s.iter().map(|x| crate::audio::pcm_to_alaw(*x)).collect(),
            Wire::Pcm16(_) => crate::audio::pcm16_to_bytes(&s),
            Wire::S32le(_) => s
                .iter()
                .flat_map(|x| ((*x as i32) << 16).to_le_bytes())
                .collect(),
            Wire::F32le(_) => s
                .iter()
                .flat_map(|x| (*x as f32 / 32768.0).to_le_bytes())
                .collect(),
        }
    }
    /// Wire bytes → mono PCM at `rate`.
    pub fn decode(&self, b: &[u8], rate: u32) -> Vec<i16> {
        let s: Vec<i16> = match self {
            Wire::Mulaw => b.iter().map(|x| crate::audio::ulaw_to_pcm(*x)).collect(),
            Wire::Alaw => b.iter().map(|x| crate::audio::alaw_to_pcm(*x)).collect(),
            Wire::Pcm16(_) => crate::audio::pcm16_from_bytes(b),
            Wire::S32le(_) => b
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| (i32::from_le_bytes(*c) >> 16) as i16)
                .collect(),
            Wire::F32le(_) => b
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| (f32::from_le_bytes(*c).clamp(-1.0, 1.0) * 32767.0) as i16)
                .collect(),
        };
        crate::audio::resample(&s, self.rate(), rate)
    }
    /// OpenAI-compatible realtime `format` object.
    pub fn openai_format(&self) -> serde_json::Value {
        match self {
            Wire::Pcm16(r) => serde_json::json!({"type": "audio/pcm", "rate": r}),
            Wire::Alaw => serde_json::json!({"type": "audio/pcma"}),
            _ => serde_json::json!({"type": "audio/pcmu"}),
        }
    }
}

pub(crate) struct Settings {
    pub connect_timeout: Duration,
    pub close_timeout: Duration,
    pub attempts: u32,
    pub delay: Duration,
}

pub(crate) fn settings(m: &Media) -> Settings {
    Settings {
        connect_timeout: Duration::from_millis(
            m.cfg.int_or("realtime.connect_timeout_ms", 10_000).max(1) as u64,
        ),
        close_timeout: Duration::from_millis(
            m.cfg.int_or("realtime.close_timeout_ms", 5_000).max(0) as u64,
        ),
        attempts: m.cfg.int_or("realtime.reconnect_attempts", 5).clamp(1, 20) as u32,
        delay: Duration::from_millis(
            m.cfg.int_or("realtime.reconnect_delay_ms", 1_000).max(0) as u64
        ),
    }
}

/// `[media.realtime.<sec>].<key>` as a string (numbers/bools stringified).
pub(crate) fn cfg_str(m: &Media, sec: &str, key: &str) -> Option<String> {
    m.cfg
        .get(&format!("realtime.{sec}.{key}"))
        .and_then(|v| match v {
            toml::Value::String(s) => Some(m.cfg.substitute(s.trim())),
            toml::Value::Integer(i) => Some(i.to_string()),
            toml::Value::Float(f) => Some(f.to_string()),
            toml::Value::Boolean(b) => Some(b.to_string()),
            _ => None,
        })
        .filter(|s| !s.is_empty())
}

pub(crate) fn cfg_num(m: &Media, sec: &str, key: &str) -> Option<f64> {
    cfg_str(m, sec, key)
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

pub(crate) fn cfg_bool(m: &Media, sec: &str, key: &str) -> Option<bool> {
    cfg_str(m, sec, key)
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// A realtime provider row (for `auto`, status and CLI listings).
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub aliases: &'static [&'static str],
    pub env: &'static [&'static str],
    pub default_model: &'static str,
    pub auto_order: u32,
}

pub const STT_PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "openai",
        label: "OpenAI Realtime Transcription",
        aliases: &["openai-realtime"],
        env: &["OPENAI_API_KEY"],
        default_model: "gpt-4o-transcribe",
        auto_order: 10,
    },
    ProviderInfo {
        id: "xai",
        label: "xAI Realtime Transcription",
        aliases: &["xai-realtime", "grok-stt-streaming"],
        env: &["XAI_API_KEY"],
        default_model: "grok-stt",
        auto_order: 25,
    },
    ProviderInfo {
        id: "deepgram",
        label: "Deepgram Realtime Transcription",
        aliases: &["deepgram-realtime", "nova-3-streaming"],
        env: &["DEEPGRAM_API_KEY"],
        default_model: "nova-3",
        auto_order: 35,
    },
    ProviderInfo {
        id: "elevenlabs",
        label: "ElevenLabs Realtime Transcription",
        aliases: &["elevenlabs-realtime", "scribe-v2-realtime"],
        env: &["ELEVENLABS_API_KEY", "XI_API_KEY"],
        default_model: "scribe_v2_realtime",
        auto_order: 40,
    },
    ProviderInfo {
        id: "mistral",
        label: "Mistral Realtime Transcription",
        aliases: &["mistral-realtime", "voxtral-realtime"],
        env: &["MISTRAL_API_KEY"],
        default_model: "voxtral-mini-transcribe-realtime-2602",
        auto_order: 45,
    },
];

/// Speech-to-speech providers: personal voice front-ends only (`--features personal`, gen1-306).
#[cfg(feature = "personal")]
pub const VOICE_PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "openai",
        label: "OpenAI Realtime Voice",
        aliases: &["openai-realtime-voice", "openai-realtime"],
        env: &["OPENAI_API_KEY"],
        default_model: voice::OPENAI_DEFAULT_MODEL,
        auto_order: 10,
    },
    ProviderInfo {
        id: "google",
        label: "Google Gemini Live",
        aliases: &["gemini", "gemini-live", "google-live"],
        env: &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        default_model: voice::GOOGLE_DEFAULT_MODEL,
        auto_order: 20,
    },
    ProviderInfo {
        id: "xai",
        label: "xAI Grok Voice",
        aliases: &["xai-realtime-voice", "grok-voice"],
        env: &["XAI_API_KEY"],
        default_model: voice::XAI_DEFAULT_MODEL,
        auto_order: 25,
    },
];

fn configured(m: &Media, p: &ProviderInfo) -> bool {
    m.cfg.configured(p.id, p.env) || (p.id == "google" && m.cfg.configured("gemini", p.env))
}

/// Resolve `requested` (or the `[media.realtime] <key>` setting, `auto` = first configured).
pub(crate) fn resolve(
    m: &Media,
    list: &'static [ProviderInfo],
    requested: Option<&str>,
    key: &str,
    what: &str,
) -> Result<&'static ProviderInfo, String> {
    let want = requested
        .map(str::to_string)
        .or_else(|| m.cfg.str(&format!("realtime.{key}")))
        .unwrap_or_else(|| "auto".into())
        .to_ascii_lowercase();
    if want == "auto" {
        let mut v: Vec<&ProviderInfo> = list.iter().collect();
        v.sort_by_key(|p| p.auto_order);
        return v.into_iter().find(|p| configured(m, p)).ok_or_else(|| {
            format!(
                "no realtime {what} provider is configured (set an API key for one of: {})",
                list.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
            )
        });
    }
    list.iter()
        .find(|p| p.id == want || p.aliases.contains(&want.as_str()))
        .ok_or_else(|| {
            format!(
                "unknown realtime {what} provider `{want}` (known: {})",
                list.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
            )
        })
}

/// Open a live transcription stream (`provider` = id/alias, `None` = `[media.realtime] stt_provider`).
/// `sample_rate` is the rate of the PCM the caller will send; 8 kHz selects G.711 μ-law on the wire.
pub fn open_stt(
    m: &Media,
    provider: Option<&str>,
    sample_rate: u32,
    language: Option<&str>,
) -> Result<Box<dyn RealtimeStt>, String> {
    let p = resolve(m, STT_PROVIDERS, provider, "stt_provider", "transcription")?;
    let rate = if sample_rate == 0 { 16000 } else { sample_rate };
    let language = language.filter(|l| !l.trim().is_empty());
    let proto: Box<dyn stt::Proto> = match p.id {
        "openai" => Box::new(stt::OpenAi::new(m, rate, language)?),
        "deepgram" => Box::new(stt::Deepgram::new(m, rate, language)?),
        "elevenlabs" => Box::new(stt::ElevenLabs::new(m, rate, language)?),
        "mistral" => Box::new(stt::Mistral::new(m, rate)?),
        _ => Box::new(stt::Xai::new(m, rate, language)?),
    };
    Ok(Box::new(stt::Session::open(m, proto, rate)?))
}

#[cfg(feature = "personal")]
/// Open a speech-to-speech session (`provider` = id/alias, `None` = `[media.realtime] voice_provider`).
pub fn open_voice(
    m: &Media,
    provider: Option<&str>,
    opts: &VoiceOpts,
) -> Result<Box<dyn RealtimeVoice>, String> {
    let p = resolve(m, VOICE_PROVIDERS, provider, "voice_provider", "voice")?;
    Ok(match p.id {
        "openai" => Box::new(voice::OaiVoice::connect(m, voice::Flavor::OpenAi, opts)?),
        "xai" => Box::new(voice::OaiVoice::connect(m, voice::Flavor::Xai, opts)?),
        _ => Box::new(voice::Gemini::connect(m, opts)?),
    })
}

/// Upstream exposes realtime sessions to voice front-ends (Talk, calls, meetings, GPT-Live),
/// not as model tools.
pub fn tools(_m: &Arc<crate::Media>) -> Vec<Arc<dyn ark_core::Tool>> {
    vec![]
}

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "personal"))]
mod tests_voice;
