//! Cloud TTS with a JSON/HTTP API: OpenAI-compatible speech (OpenAI, DeepInfra,
//! OpenRouter), ElevenLabs, xAI (`/v1/tts`, API key or OAuth bearer), MiniMax
//! (`t2a_v2` hex audio or legacy raw audio), Gemini/Google (`generateContent`
//! AUDIO modality or the Interactions API for Gemini 3.8), Mistral Voxtral.

use super::{bounded, num, opt, speech, Speech, TtsProvider, TtsRequest};
use crate::http::{error_message, host_of};
use crate::Media;
use seagent_core::Cancel;
use serde_json::{json, Value};

/// OpenAI `response_format` for a wanted container.
fn openai_format(req: &TtsRequest, allowed: &[&str], default: &str) -> String {
    let f = match req.format.as_deref() {
        Some("ogg") => "opus",
        Some(f) => f,
        None => default,
    };
    if allowed.contains(&f) {
        f.to_string()
    } else {
        default.to_string()
    }
}

fn format_mime(f: &str) -> &'static str {
    match f {
        "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "pcm" => "audio/pcm",
        _ => "audio/mpeg",
    }
}

pub const OPENAI_VOICES: &[&str] = &["alloy", "ash", "ballad", "cedar", "coral", "echo", "fable", "juniper", "marin", "onyx", "nova", "sage", "shimmer", "verse"];
const OPENAI_MODELS: &[&str] = &["gpt-4o-mini-tts", "gpt-4o-mini-tts-2025-12-15", "tts-1", "tts-1-hd"];

/// OpenAI `audio/speech` and compatible servers.
pub struct OpenAi {
    id: &'static str,
    env: &'static [&'static str],
    base: &'static str,
    model: &'static str,
    voice: &'static str,
    formats: &'static [&'static str],
}

impl OpenAi {
    // Named after the provider it configures, like `deepinfra()` / `openrouter()` below.
    #[allow(clippy::self_named_constructors)]
    pub fn openai() -> Self {
        OpenAi { id: "openai", env: &["VOICE_TOOLS_OPENAI_KEY", "OPENAI_API_KEY"], base: "https://api.openai.com/v1", model: "gpt-4o-mini-tts", voice: "alloy", formats: &["mp3", "opus", "aac", "flac", "wav", "pcm"] }
    }
    pub fn deepinfra() -> Self {
        OpenAi { id: "deepinfra", env: &["DEEPINFRA_API_KEY"], base: "https://api.deepinfra.com/v1/openai", model: "hexgrad/Kokoro-82M", voice: "af_bella", formats: &["mp3", "opus", "flac", "wav", "pcm"] }
    }
    pub fn openrouter() -> Self {
        OpenAi { id: "openrouter", env: &["OPENROUTER_API_KEY"], base: "https://openrouter.ai/api/v1", model: "hexgrad/kokoro-82m", voice: "af_alloy", formats: &["mp3", "pcm"] }
    }
    fn base(&self, m: &Media) -> String {
        let env_base = (self.id == "openai").then(|| std::env::var("OPENAI_TTS_BASE_URL").ok()).flatten();
        opt(m, self.id, "base_url").or(env_base).map(|b| b.trim_end_matches('/').to_string()).unwrap_or_else(|| m.creds(self.id, self.env, self.base).base.trim_end_matches('/').to_string())
    }
}

impl TtsProvider for OpenAi {
    fn id(&self) -> &str {
        self.id
    }
    fn env(&self) -> &[&str] {
        self.env
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&self.base(m)))
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(match self.id {
            "openai" => OPENAI_VOICES.iter().map(|s| s.to_string()).collect(),
            _ => vec![self.voice.to_string()],
        })
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds(self.id, self.env, self.base);
        let key = opt(m, self.id, "api_key").or(c.key.clone()).ok_or_else(|| format!("{} not set (or [media.providers.{}] api_key)", self.env.join("/"), self.id))?;
        let base = self.base(m);
        let custom = base != self.base;
        let model = req.model.clone().or_else(|| opt(m, self.id, "model")).unwrap_or_else(|| self.model.into());
        let voice = req.voice.clone().or_else(|| opt(m, self.id, "voice")).unwrap_or_else(|| self.voice.into());
        if self.id == "openai" && !custom {
            if !OPENAI_MODELS.contains(&model.as_str()) {
                return Err(format!("Invalid OpenAI TTS model: {model}"));
            }
            if !OPENAI_VOICES.contains(&voice.as_str()) {
                return Err(format!("Invalid voice: {voice}"));
            }
        }
        let fmt = openai_format(req, self.formats, "mp3");
        let mut body = json!({"model": model, "voice": voice, "input": req.text, "response_format": fmt});
        if let Some(s) = super::speed(m, self.id, req).filter(|s| (*s - 1.0).abs() > f64::EPSILON) {
            body["speed"] = json!(if custom { s } else { s.clamp(0.25, 4.0) });
        }
        // OpenAI only honours instructions on gpt-4o-mini-tts; custom servers get them as-is.
        let instructions = req.instructions.clone().or_else(|| opt(m, self.id, "instructions"));
        if let Some(i) = instructions.filter(|i| !i.trim().is_empty() && (custom || self.id != "openai" || model.contains("gpt-4o-mini-tts"))) {
            body["instructions"] = json!(i);
        }
        if let Some(l) = req.language.clone().or_else(|| opt(m, self.id, "language")) {
            body["lang_code"] = json!(l);
        }
        if let Some(a) = opt(m, self.id, "consent_attestation") {
            body["consent_attestation"] = json!(a);
        }
        for k in ["extra_body", "provider"] {
            if let Some(toml::Value::Table(t)) = m.cfg.get(&format!("tts.{}.{k}", self.id)) {
                let v: Value = serde_json::to_value(t).unwrap_or_default();
                if k == "provider" {
                    body["provider"] = v;
                } else if let Value::Object(o) = v {
                    for (kk, vv) in o {
                        body[kk] = vv;
                    }
                }
            }
        }
        let mut h = c.headers.clone();
        h.insert(0, ("authorization".into(), format!("Bearer {key}")));
        h.push(("x-idempotency-key".into(), crate::store::stem("tts")));
        let r = m.http.post_json_bytes(&format!("{base}/audio/speech"), &h, &body).map_err(|e| format!("{} TTS API error: {e}", label(self.id)))?;
        let rate = r.header("x-audio-sample-rate").and_then(|v| v.trim().parse().ok()).or_else(|| r.content_type_full_rate());
        let mut s = speech(bounded(r.body, self.id)?, format_mime(&fmt));
        if fmt == "pcm" {
            s.audio.mime = "audio/pcm".into();
            s.sample_rate = Some(num(m, self.id, "pcm_sample_rate").map(|n| n as u32).or(rate).unwrap_or(24000));
        }
        Ok(s)
    }
}

trait RateHeader {
    fn content_type_full_rate(&self) -> Option<u32>;
}

impl RateHeader for crate::http::Resp {
    /// `rate=` in `Content-Type: audio/pcm; rate=44100`.
    fn content_type_full_rate(&self) -> Option<u32> {
        let ct = self.header("content-type")?;
        ct.split(';').find_map(|p| p.trim().strip_prefix("rate=").and_then(|v| v.trim().parse().ok()))
    }
}

fn label(id: &str) -> &str {
    match id {
        "openai" => "OpenAI",
        "deepinfra" => "DeepInfra",
        "openrouter" => "OpenRouter",
        _ => id,
    }
}

pub const ELEVENLABS_VOICE: &str = "pNInz6obpgDQGcFmaJgB"; // Adam
pub const ELEVENLABS_MODEL: &str = "eleven_multilingual_v2";

pub struct ElevenLabs;

impl ElevenLabs {
    fn base(m: &Media) -> String {
        opt(m, "elevenlabs", "base_url").unwrap_or_else(|| m.creds("elevenlabs", &["ELEVENLABS_API_KEY", "XI_API_KEY"], "https://api.elevenlabs.io").base).trim_end_matches('/').trim_end_matches("/v1").to_string()
    }
}

impl TtsProvider for ElevenLabs {
    fn id(&self) -> &str {
        "elevenlabs"
    }
    fn env(&self) -> &[&str] {
        &["ELEVENLABS_API_KEY", "XI_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&Self::base(m)))
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let c = m.creds("elevenlabs", self.env(), "https://api.elevenlabs.io");
        let v = m.http.get_json(&format!("{}/v1/voices", Self::base(m)), &c.header_key("xi-api-key")).map_err(|e| format!("ElevenLabs voices API error: {e}"))?;
        Ok(v["voices"].as_array().into_iter().flatten().filter_map(|x| {
            let id = x["voice_id"].as_str()?.trim();
            (!id.is_empty()).then(|| match x["name"].as_str() {
                Some(n) => format!("{id} ({n})"),
                None => id.to_string(),
            })
        }).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("elevenlabs", self.env(), "https://api.elevenlabs.io");
        c.key().map_err(|_| "ELEVENLABS_API_KEY not set. Get one at https://elevenlabs.io/".to_string())?;
        let voice = req.voice.clone().or_else(|| opt(m, "elevenlabs", "voice_id")).or_else(|| opt(m, "elevenlabs", "voice")).unwrap_or_else(|| ELEVENLABS_VOICE.into());
        let model = req.model.clone().or_else(|| opt(m, "elevenlabs", "model_id")).unwrap_or_else(|| ELEVENLABS_MODEL.into());
        let (out_fmt, mime) = match req.format.as_deref() {
            Some("opus" | "ogg") => ("opus_48000_64".to_string(), "audio/ogg"),
            Some("pcm") => ("pcm_24000".to_string(), "audio/pcm"),
            Some("wav") => ("wav_44100".to_string(), "audio/wav"),
            _ => (opt(m, "elevenlabs", "output_format").unwrap_or_else(|| "mp3_44100_128".into()), "audio/mpeg"),
        };
        let vs = |k: &str, d: f64| num(m, "elevenlabs", k).map(|x| x.clamp(0.0, 1.0)).unwrap_or(d);
        let mut body = json!({
            "text": req.text, "model_id": model,
            "voice_settings": {"stability": vs("stability", 0.5), "similarity_boost": vs("similarity_boost", 0.75), "style": vs("style", 0.0),
                "use_speaker_boost": super::flag(m, "elevenlabs", "use_speaker_boost").unwrap_or(true), "speed": super::speed(m, "elevenlabs", req).unwrap_or(1.0)}
        });
        if let Some(s) = num(m, "elevenlabs", "seed") {
            body["seed"] = json!(s as u64);
        }
        if let Some(n) = opt(m, "elevenlabs", "apply_text_normalization") {
            body["apply_text_normalization"] = json!(n);
        }
        if let Some(l) = req.language.clone().or_else(|| opt(m, "elevenlabs", "language_code")) {
            body["language_code"] = json!(l);
        }
        let url = format!("{}/v1/text-to-speech/{}?output_format={out_fmt}", Self::base(m), seagent_net::urlencode(&voice));
        let mut h = c.header_key("xi-api-key");
        h.push(("accept".into(), if mime == "audio/mpeg" { "audio/mpeg".into() } else { "*/*".into() }));
        let r = m.http.post_json_bytes(&url, &h, &body).map_err(|e| format!("ElevenLabs TTS failed: {e}"))?;
        let mut s = speech(bounded(r.body, "ElevenLabs")?, mime);
        if mime == "audio/pcm" {
            s.audio.mime = mime.into();
            s.sample_rate = Some(24000);
        }
        Ok(s)
    }
}

const XAI_INLINE_TAGS: &[&str] = &["pause", "long-pause", "hum-tune", "laugh", "chuckle", "giggle", "cry", "tsk", "tongue-click", "lip-smack", "breath", "inhale", "exhale", "sigh"];
const XAI_WRAP_TAGS: &[&str] = &["soft", "whisper", "loud", "build-intensity", "decrease-intensity", "higher-pitch", "lower-pitch", "slow", "fast", "sing-song", "singing", "laugh-speak", "emphasis"];

fn has_xai_tag(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    XAI_INLINE_TAGS.iter().any(|g| l.contains(&format!("[{g}]"))) || XAI_WRAP_TAGS.iter().any(|g| l.contains(&format!("<{g}>")) || l.contains(&format!("[{g}]")))
}

/// Hermes `_apply_xai_auto_speech_tags`: `[pause]` between paragraphs and after the first
/// sentence; untagged text is then offered to the agent's model for richer tags.
pub fn xai_auto_tags(text: &str, cancel: &Cancel) -> String {
    let clean = text.trim();
    if clean.is_empty() {
        return text.to_string();
    }
    let paras: Vec<&str> = clean.split("\n\n").map(str::trim).filter(|p| !p.is_empty()).collect();
    let mut local = paras.iter().map(|p| p.split_whitespace().collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join(" [pause] ");
    if !has_xai_tag(&local) {
        let cs: Vec<char> = local.chars().collect();
        if let Some(i) = (12..cs.len().min(121)).find(|&i| ".!?…".contains(cs[i - 1]) && cs.get(i) == Some(&' ') && cs.get(i + 1).is_some_and(|c| !c.is_whitespace())) {
            local = format!("{} [pause] {}", cs[..i].iter().collect::<String>(), cs[i + 1..].iter().collect::<String>());
        }
    }
    if has_xai_tag(clean) {
        return local;
    }
    let system = format!(
        "You rewrite transcripts for the xAI /v1/tts endpoint by inserting expressive speech tags.\n\nValid inline tags (use as `[tag]`): {}.\nValid wrapping tags (use as `[tag]...[/tag]`): {}.\n\n{TAG_RULES}- Use inline `[tag]` for short modifiers (laughs, sighs, pause, etc.).\n- Use wrapping `[tag]...[/tag]` for sustained effects (whisper, soft, slow, fast, loud, etc.).\n- Do not use angle-bracket tags like `<tag>...</tag>` — xAI uses BBCode-style closing tags with `[/tag]`.\n- Do not use SSML.\n{TAG_TAIL}",
        XAI_INLINE_TAGS.join(", "),
        XAI_WRAP_TAGS.join(", ")
    );
    rewrite_with_llm(&system, &format!("TRANSCRIPT TO TAG:\n{local}"), &local, cancel)
}

const TAG_RULES: &str = "Rules:\n- Preserve the spoken words, order, and meaning.\n- Do not add new spoken sentences or remove existing spoken words.\n";
const TAG_TAIL: &str = "- Do not explain or comment.\n- Return only the tagged TTS script.";

/// Ask the agent's model to rewrite a script (Hermes auxiliary `tts_audio_tags` task).
fn rewrite_with_llm(system: &str, user: &str, fallback: &str, cancel: &Cancel) -> String {
    let Some(l) = crate::llm() else { return fallback.to_string() };
    match l.complete(None, system, vec![seagent_core::Message::user(user)], 2048, cancel) {
        Ok(t) => {
            let t = t.trim();
            let t = t.strip_prefix("```").map(|r| r.split_once('\n').map(|x| x.1).unwrap_or(r).trim_end_matches("```").trim()).unwrap_or(t);
            if t.is_empty() {
                fallback.to_string()
            } else {
                t.to_string()
            }
        }
        Err(_) => fallback.to_string(),
    }
}

/// xAI `/v1/tts` (API key) and the same endpoint with an xAI OAuth bearer (`xai-oauth`).
pub struct Xai {
    pub oauth: bool,
}

impl Xai {
    fn pid(&self) -> &'static str {
        if self.oauth {
            "xai-oauth"
        } else {
            "xai"
        }
    }
    fn base(&self, m: &Media) -> String {
        opt(m, "xai", "base_url").or_else(|| std::env::var("XAI_BASE_URL").ok().filter(|s| !s.is_empty())).unwrap_or_else(|| m.creds(self.pid(), self.env(), "https://api.x.ai/v1").base).trim_end_matches('/').to_string()
    }
}

impl TtsProvider for Xai {
    fn id(&self) -> &str {
        self.pid()
    }
    fn env(&self) -> &[&str] {
        if self.oauth {
            &["XAI_OAUTH_TOKEN", "XAI_OAUTH_ACCESS_TOKEN"]
        } else {
            &["XAI_API_KEY"]
        }
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&self.base(m)))
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let c = m.creds(self.pid(), self.env(), "https://api.x.ai/v1");
        let v = m.http.get_json(&format!("{}/tts/voices", self.base(m)), &c.bearer()).map_err(|e| format!("xAI TTS voices API error: {e}"))?;
        Ok(v["voices"].as_array().into_iter().flatten().filter_map(|x| x["voice_id"].as_str().map(str::to_string)).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        // TTS is API-billed: an explicit XAI_API_KEY wins over the OAuth bearer (Hermes #87045).
        let api = m.creds("xai", &["XAI_API_KEY"], "https://api.x.ai/v1");
        let c = if self.oauth && api.key.is_none() { m.creds("xai-oauth", self.env(), "https://api.x.ai/v1") } else { api };
        if c.key.is_none() {
            return Err("No xAI credentials found. Configure xAI OAuth (XAI_OAUTH_TOKEN) or set XAI_API_KEY.".into());
        }
        let voice = req.voice.clone().or_else(|| opt(m, "xai", "voice_id")).unwrap_or_else(|| "eve".into());
        let language = req.language.clone().or_else(|| opt(m, "xai", "language")).unwrap_or_else(|| "en".into());
        let rate = num(m, "xai", "sample_rate").unwrap_or(24000.0) as u64;
        let bit = num(m, "xai", "bit_rate").unwrap_or(128000.0) as u64;
        let mut text = req.text.clone();
        if super::flag(m, "xai", "auto_speech_tags").or_else(|| super::flag(m, "xai", "speech_tags")).unwrap_or(false) {
            text = xai_auto_tags(&text, cancel);
        }
        let codec = if req.format.as_deref() == Some("wav") { "wav" } else { "mp3" };
        let mut body = json!({"text": text, "voice_id": voice, "language": language});
        if codec != "mp3" || rate != 24000 || bit != 128000 {
            let mut of = json!({"codec": codec, "sample_rate": rate});
            if codec == "mp3" {
                of["bit_rate"] = json!(bit);
            }
            body["output_format"] = of;
        }
        if let Some(s) = super::speed(m, "xai", req).map(|s| s.clamp(0.7, 1.5)).filter(|s| (*s - 1.0).abs() > f64::EPSILON) {
            body["speed"] = json!(s);
        }
        if let Some(o) = num(m, "xai", "optimize_streaming_latency").map(|o| (o as i64).clamp(0, 2)).filter(|o| *o != 0) {
            body["optimize_streaming_latency"] = json!(o);
        }
        if super::flag(m, "xai", "text_normalization").unwrap_or(false) {
            body["text_normalization"] = json!(true);
        }
        let mut h = c.bearer();
        h.push(("user-agent".into(), format!("seagent/{}", env!("CARGO_PKG_VERSION"))));
        let r = m.http.post_json_bytes(&format!("{}/tts", self.base(m)), &h, &body).map_err(|e| format!("xAI TTS failed: {e}"))?;
        Ok(speech(bounded(r.body, "xAI TTS")?, if codec == "wav" { "audio/wav" } else { "audio/mpeg" }))
    }
}

/// MiniMax `t2a_v2` (global or CN region) or the legacy `text_to_speech` endpoint.
pub struct MiniMax;

impl MiniMax {
    /// `(region, endpoint, key)`: explicit `region` wins; `cn` only when it is the sole key.
    fn runtime(m: &Media) -> Result<(String, String, String), String> {
        let g = m.creds("minimax", &["MINIMAX_API_KEY"], "");
        let cn = m.creds("minimax-cn", &["MINIMAX_CN_API_KEY"], "");
        let region = match opt(m, "minimax", "region").map(|r| r.to_ascii_lowercase()) {
            Some(r) if r == "global" || r == "cn" => r,
            Some(_) => return Err("tts.minimax.region must be 'global' or 'cn'".into()),
            None if cn.key.is_some() && g.key.is_none() => "cn".into(),
            None => "global".into(),
        };
        let (src, key) = if region == "cn" { ("MINIMAX_CN_API_KEY", cn.key) } else { ("MINIMAX_API_KEY", g.key) };
        let key = key.ok_or_else(|| format!("{src} not set for MiniMax TTS region '{region}'"))?;
        let default = if region == "cn" { "https://api.minimaxi.com/v1/t2a_v2" } else { "https://api.minimax.io/v1/t2a_v2" };
        let host_env = std::env::var("MINIMAX_API_HOST").ok().filter(|h| !h.is_empty()).map(|h| format!("{}/v1/t2a_v2", h.trim_end_matches('/')));
        let endpoint = opt(m, "minimax", "base_url").or_else(|| (!g.base.is_empty() && region == "global").then(|| g.base.clone())).or(host_env).unwrap_or_else(|| default.into());
        let host = host_of(&endpoint).to_ascii_lowercase();
        let other: &[&str] = if region == "global" { &["api.minimaxi.com"] } else { &["api.minimax.io", "api.minimax.chat"] };
        if other.contains(&host.as_str()) {
            return Err(format!("tts.minimax.base_url points to the {} MiniMax endpoint but region is '{region}'", if region == "global" { "cn" } else { "global" }));
        }
        Ok((region, endpoint, key))
    }
}

fn minimax_error(v: &Value) -> Option<String> {
    let code = v["base_resp"]["status_code"].as_i64().unwrap_or(-1);
    (code != 0).then(|| format!("MiniMax TTS API error (code {code}): {}", v["base_resp"]["status_msg"].as_str().unwrap_or("unknown error")))
}

impl TtsProvider for MiniMax {
    fn id(&self) -> &str {
        "minimax"
    }
    fn env(&self) -> &[&str] {
        &["MINIMAX_API_KEY", "MINIMAX_CN_API_KEY"]
    }
    fn configured(&self, m: &Media) -> bool {
        Self::runtime(m).is_ok()
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Self::runtime(m).ok().map(|r| host_of(&r.1))
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let (_, mut url, key) = Self::runtime(m)?;
        let model = req.model.clone().or_else(|| opt(m, "minimax", "model")).or_else(|| std::env::var("MINIMAX_TTS_MODEL").ok()).unwrap_or_else(|| "speech-02-hd".into());
        let voice = req.voice.clone().or_else(|| opt(m, "minimax", "voice_id")).or_else(|| std::env::var("MINIMAX_TTS_VOICE_ID").ok()).unwrap_or_else(|| "English_expressive_narrator".into());
        let group = opt(m, "minimax", "group_id").or_else(|| std::env::var("MINIMAX_GROUP_ID").ok().filter(|s| !s.trim().is_empty()));
        if let Some(g) = group.filter(|_| !url.contains("GroupId=")) {
            url = format!("{url}{}GroupId={g}", if url.contains('?') { '&' } else { '?' });
        }
        let v2 = url.contains("t2a_v2");
        let body = if v2 {
            json!({"model": model, "text": req.text,
                "voice_setting": {"voice_id": voice, "speed": super::speed(m, "minimax", req).unwrap_or(1.0), "vol": num(m, "minimax", "vol").unwrap_or(1.0),
                    "pitch": num(m, "minimax", "pitch").unwrap_or(0.0) as i64, "emotion": opt(m, "minimax", "emotion").unwrap_or_else(|| "neutral".into())},
                "audio_setting": {"sample_rate": num(m, "minimax", "sample_rate").unwrap_or(32000.0) as u64, "bitrate": num(m, "minimax", "bitrate").unwrap_or(128000.0) as u64, "format": "mp3", "channel": 1}})
        } else {
            json!({"model": model, "text": req.text, "voice_id": voice})
        };
        let b = serde_json::to_vec(&body).unwrap_or_default();
        let r = m.http.send("POST", &url, &[("authorization".into(), format!("Bearer {key}"))], Some(("application/json", &b)))?;
        if v2 {
            if !r.ok() {
                return Err(format!("MiniMax TTS: HTTP {}: {}", r.status, error_message(&r.text())));
            }
            let v = r.json()?;
            if let Some(e) = minimax_error(&v) {
                return Err(e);
            }
            let hex = v["data"]["audio"].as_str().unwrap_or("");
            if hex.is_empty() {
                return Err("MiniMax TTS returned empty audio data".into());
            }
            let bytes = seagent_net::crypto::hex_decode(hex.trim()).ok_or("MiniMax TTS returned malformed hex audio")?;
            return Ok(speech(bounded(bytes, "MiniMax TTS")?, "audio/mpeg"));
        }
        if r.content_type().starts_with("audio/") {
            return Ok(speech(bounded(r.body.clone(), "MiniMax TTS")?, &r.content_type()));
        }
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        if let Some(e) = minimax_error(&v).filter(|_| !v.is_null()) {
            return Err(e);
        }
        if !r.ok() {
            return Err(format!("MiniMax TTS: HTTP {}", r.status));
        }
        Err(format!("MiniMax TTS returned unexpected Content-Type '{}' ({} bytes)", r.content_type(), r.body.len()))
    }
}

pub const GEMINI_VOICES: &[&str] = &[
    "Zephyr", "Puck", "Charon", "Kore", "Fenrir", "Leda", "Orus", "Aoede", "Callirrhoe", "Autonoe", "Enceladus", "Iapetus", "Umbriel", "Algieba", "Despina", "Erinome", "Algenib", "Rasalgethi", "Laomedeia", "Achernar", "Alnilam", "Schedar", "Gacrux", "Pulcherrima", "Achird",
    "Zubenelgenubi", "Vindemiatrix", "Sadachbia", "Sadaltager", "Sulafat",
];
const GEMINI_INTERACTIONS_MODELS: &[&str] = &["gemini-3.8-flash-tts", "gemini-3.8-flash-lite-tts"];

/// Gemini / Google TTS: 24 kHz mono PCM16 (wrapped as WAV for delivery).
pub struct Gemini;

impl Gemini {
    fn base(m: &Media) -> String {
        let b = opt(m, "gemini", "base_url").or_else(|| std::env::var("GEMINI_BASE_URL").ok().filter(|s| !s.is_empty())).unwrap_or_else(|| m.creds("gemini", &["GEMINI_API_KEY", "GOOGLE_API_KEY"], "https://generativelanguage.googleapis.com/v1beta").base);
        let b = b.trim_end_matches('/').to_string();
        if b.ends_with("/v1beta") || b.ends_with("/v1") || b.contains("/v1beta/") {
            b
        } else {
            format!("{b}/v1beta")
        }
    }

    /// Persona direction + transcript (Hermes `_compose_gemini_tts_prompt`).
    fn prompt(text: &str, persona: &str) -> String {
        let t = text.trim();
        if persona.trim().is_empty() {
            return t.to_string();
        }
        let pre = "Synthesize speech from the TRANSCRIPT only. Treat AUDIO PROFILE, SCENE, DIRECTOR'S NOTES, and SAMPLE CONTEXT as performance direction; do not speak those sections aloud.";
        for ph in ["{{transcript}}", "{{ transcript }}", "{transcript}", "{ transcript }"] {
            if persona.contains(ph) {
                return format!("{pre}\n\n{}", persona.replace(ph, t)).trim().to_string();
            }
        }
        format!("{pre}\n\n{persona}\n\n#### TRANSCRIPT\n{t}").trim().to_string()
    }

    fn persona(m: &Media) -> String {
        if let Some(p) = opt(m, "gemini", "persona_prompt") {
            return p;
        }
        let Some(f) = opt(m, "gemini", "persona_prompt_file") else { return String::new() };
        std::fs::read_to_string(seagent_core::tool::expand_home(&f)).map(|s| s.trim_start_matches('\u{feff}').trim().to_string()).unwrap_or_default()
    }
}

impl TtsProvider for Gemini {
    fn id(&self) -> &str {
        "gemini"
    }
    fn aliases(&self) -> &[&str] {
        &["google"]
    }
    fn env(&self) -> &[&str] {
        &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&Self::base(m)))
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(GEMINI_VOICES.iter().map(|s| s.to_string()).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("gemini", self.env(), "https://generativelanguage.googleapis.com/v1beta");
        c.key.clone().ok_or("GEMINI_API_KEY not set. Get one at https://aistudio.google.com/app/apikey")?;
        let mut model = req.model.clone().or_else(|| opt(m, "gemini", "model")).unwrap_or_else(|| "gemini-2.5-flash-preview-tts".into());
        model = model.trim_start_matches("google/").to_string();
        if model == "gemini-3.1-flash-tts" {
            model = "gemini-3.1-flash-tts-preview".into();
        }
        let interactions = GEMINI_INTERACTIONS_MODELS.contains(&model.as_str());
        if !interactions && model.contains("gemini-3.8-") && model.contains("-tts") {
            return Err(format!("Google TTS model {model} is not supported; supported Interactions models: {}.", GEMINI_INTERACTIONS_MODELS.join(", ")));
        }
        let voice = req.voice.clone().or_else(|| opt(m, "gemini", "voice")).or_else(|| opt(m, "gemini", "voice_name")).unwrap_or_else(|| "Kore".into());
        let persona = Self::persona(m);
        let mut script = req.text.clone();
        let tags = super::flag(m, "gemini", "audio_tags").unwrap_or(false);
        if tags && model.contains("gemini-3.1") && model.contains("tts") {
            let sys = format!("You rewrite transcripts for Gemini 3.1 Flash TTS by inserting expressive audio tags.\n\nAudio tags are inline square-bracket modifiers such as [whispers], [excitedly], [very slow], [sarcastically], [laughs], [sighs], or [gasp]. There is no fixed allowlist. Use creative freeform tags generously but naturally to control tone, pace, emotional vibe, emphasis, section-level delivery, and non-verbal sounds. Use English audio tags even when the spoken transcript is not English.\n\n{TAG_RULES}- Use square brackets for every audio tag.\n- Do not use SSML or XML tags.\n{TAG_TAIL}");
            let user = format!("PERSONA AND DIRECTOR CONTEXT:\n{}\n\nTRANSCRIPT TO TAG:\n{}", if persona.trim().is_empty() { "(none)" } else { persona.trim() }, script.trim());
            script = rewrite_with_llm(&sys, &user, &script, cancel);
        }
        let audio_profile = opt(m, "gemini", "audio_profile").or_else(|| req.instructions.clone());
        let speaker = opt(m, "gemini", "speaker_name");
        let base = Self::base(m);
        let mut h = c.header_key("x-goog-api-key");
        if host_of(&base) == "generativelanguage.googleapis.com" {
            h.push(("x-goog-api-client".into(), format!("seagent/{}", env!("CARGO_PKG_VERSION"))));
        }
        let b64 = if interactions {
            let style: Vec<String> = [audio_profile.clone(), Some(persona.clone()).filter(|p| !p.trim().is_empty())].into_iter().flatten().collect();
            let mut block = json!({"type": "text", "text": script});
            if !style.is_empty() || speaker.is_some() {
                let mut meta = json!({"type": "speech_metadata"});
                if let Some(s) = &speaker {
                    meta["speaker"] = json!(s);
                }
                if !style.is_empty() {
                    meta["style"] = json!(style.join("\n\n"));
                }
                block["annotations"] = json!([meta]);
            }
            let body = json!({"model": model, "store": false, "input": [{"type": "user_input", "content": [block]}],
                "response_format": {"type": "audio", "mime_type": "audio/l16", "sample_rate": 24000},
                "generation_config": {"speech_config": [{"voice": voice}]}});
            let v = m.http.post_json(&format!("{base}/interactions"), &h, &body).map_err(|e| format!("Gemini TTS API error: {e}"))?;
            v["output_audio"]["data"].as_str().or_else(|| v["outputAudio"]["data"].as_str()).map(str::to_string).or_else(|| {
                v["steps"].as_array().into_iter().flatten().flat_map(|s| s["content"].as_array().into_iter().flatten()).find(|b| b["type"] == "audio" || b["mimeType"].as_str().or(b["mime_type"].as_str()).is_some_and(|m| m.starts_with("audio/"))).and_then(|b| b["data"].as_str().map(str::to_string))
            })
        } else {
            let mut prompt = Self::prompt(&script, &persona);
            let prefix: Vec<String> = [audio_profile, speaker.map(|s| format!("Speaker name: {s}"))].into_iter().flatten().collect();
            if !prefix.is_empty() {
                prompt = format!("{}\n\n{prompt}", prefix.join("\n\n"));
            }
            let max = super::max_text_length(m, "gemini");
            if prompt.chars().count() > max {
                return Err(format!("Gemini TTS composed prompt exceeds the provider request limit ({} > {max} chars). Reduce the persona/audio-tag prompt or lower [media.tts.gemini] max_text_length.", prompt.chars().count()));
            }
            let body = json!({"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"responseModalities": ["AUDIO"], "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": voice}}}}});
            let v = m.http.post_json(&format!("{base}/models/{model}:generateContent"), &h, &body).map_err(|e| format!("Gemini TTS API error: {e}"))?;
            let parts = v["candidates"][0]["content"]["parts"].as_array().ok_or("Gemini TTS response was malformed: no parts")?;
            let part = parts.iter().find(|p| p.get("inlineData").is_some() || p.get("inline_data").is_some()).ok_or("Gemini TTS response contained no audio data")?;
            part["inlineData"]["data"].as_str().or(part["inline_data"]["data"].as_str()).map(str::to_string)
        };
        let b64 = b64.filter(|s| !s.is_empty()).ok_or("Gemini TTS returned empty audio data")?;
        let mut pcm = crate::store::b64_decode(&b64)?;
        if crate::store::sniff(&pcm) == "audio/wav" {
            if let Ok(p) = crate::audio::wav_decode(&pcm) {
                pcm = crate::audio::pcm16_to_bytes(&p.samples);
            }
        }
        let mut s = speech(bounded(pcm, "Gemini TTS")?, "audio/pcm");
        s.audio.mime = "audio/pcm".into();
        s.sample_rate = Some(24000);
        Ok(s)
    }
}

/// Mistral Voxtral TTS (`/v1/audio/speech`, base64 `audio_data`).
pub struct Mistral;

impl TtsProvider for Mistral {
    fn id(&self) -> &str {
        "mistral"
    }
    fn env(&self) -> &[&str] {
        &["MISTRAL_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&m.creds("mistral", self.env(), "https://api.mistral.ai").base))
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("mistral", self.env(), "https://api.mistral.ai");
        c.key().map_err(|_| "MISTRAL_API_KEY not set. Get one at https://console.mistral.ai/".to_string())?;
        let base = opt(m, "mistral", "base_url").unwrap_or(c.base.clone());
        let base = base.trim_end_matches('/').trim_end_matches("/v1");
        let fmt = openai_format(req, &["mp3", "opus", "wav", "flac"], "mp3");
        let body = json!({"model": req.model.clone().or_else(|| opt(m, "mistral", "model")).unwrap_or_else(|| "voxtral-mini-tts-2603".into()),
            "input": req.text, "voice_id": req.voice.clone().or_else(|| opt(m, "mistral", "voice_id")).unwrap_or_else(|| "c69964a6-ab8b-4f8a-9465-ec0925096ec8".into()), "response_format": fmt});
        let v = m.http.post_json(&format!("{base}/v1/audio/speech"), &c.bearer(), &body).map_err(|e| format!("Mistral TTS failed: {e}"))?;
        let data = v["audio_data"].as_str().ok_or("Mistral TTS response has no audio_data")?;
        Ok(speech(bounded(crate::store::b64_decode(data)?, "Mistral TTS")?, format_mime(&fmt)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;
    use crate::tts::testkit::media;

    fn audio_server(ct: &'static str, body: &'static [u8]) -> FakeServer {
        FakeServer::start_raw(move |_, _| (200, vec![("content-type".into(), ct.into())], body.to_vec()))
    }

    #[test]
    fn openai_request_shape() {
        let srv = audio_server("audio/mpeg", b"ID3\x04abc");
        let m = media("openai", &srv.url, "[tts.openai]\nmodel = \"gpt-4o-mini-tts\"\nvoice = \"coral\"\nlanguage = \"zh\"");
        let mut req = TtsRequest::new("hello");
        req.speed = Some(9.0);
        req.instructions = Some("cheerful".into());
        let s = OpenAi::openai().synthesize(&m, &req, &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/mpeg");
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/audio/speech");
        assert_eq!(r.header("authorization"), Some("Bearer k"));
        let b = r.json();
        assert_eq!((b["voice"].as_str(), b["input"].as_str(), b["response_format"].as_str(), b["lang_code"].as_str()), (Some("coral"), Some("hello"), Some("mp3"), Some("zh")));
        // A custom base URL is not the official endpoint: speed is passed through unclamped.
        assert_eq!(b["speed"], 9.0);
        assert_eq!(b["instructions"], "cheerful");
    }

    #[test]
    fn openai_official_validation_and_pcm_rate() {
        let m = Media { cfg: crate::MediaConfig::from_toml("[providers.openai]\napi_key = \"k\"\n[tts.openai]\nvoice = \"bogus\""), http: Default::default() };
        let e = OpenAi::openai().synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap_err();
        assert!(e.contains("Invalid voice"), "{e}");
        let srv = FakeServer::start_raw(|_, _| (200, vec![("content-type".into(), "audio/pcm; rate=22050".into())], vec![1, 0, 2, 0]));
        let m = media("deepinfra", &srv.url, "");
        let mut req = TtsRequest::new("x");
        req.format = Some("pcm".into());
        let s = OpenAi::deepinfra().synthesize(&m, &req, &Cancel::new()).unwrap();
        assert_eq!((s.audio.mime.as_str(), s.sample_rate), ("audio/pcm", Some(22050)));
        assert_eq!(srv.requests()[0].json()["model"], "hexgrad/Kokoro-82M");
    }

    #[test]
    fn openrouter_extra_provider_field() {
        let srv = audio_server("audio/mpeg", b"ID3\x04abc");
        let m = media("openrouter", &srv.url, "[tts.openrouter.provider]\norder = [\"deepinfra\"]");
        OpenAi::openrouter().synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        let b = srv.requests()[0].json();
        assert_eq!((b["voice"].as_str(), b["provider"]["order"][0].as_str()), (Some("af_alloy"), Some("deepinfra")));
    }

    #[test]
    fn elevenlabs_request_shape_and_voices() {
        let srv = FakeServer::start_raw(|r, _| {
            if r.path == "/v1/voices" {
                (200, vec![], br#"{"voices":[{"voice_id":"v1","name":"Rachel"}]}"#.to_vec())
            } else {
                (200, vec![("content-type".into(), "audio/ogg".into())], b"OggS\0opus".to_vec())
            }
        });
        let m = media("elevenlabs", &srv.url, "[tts.elevenlabs]\nvoice_id = \"abc\"\nstability = 0.9");
        let mut req = TtsRequest::new("hey");
        req.format = Some("opus".into());
        let s = ElevenLabs.synthesize(&m, &req, &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/ogg");
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/v1/text-to-speech/abc?output_format=opus_48000_64");
        assert_eq!(r.header("xi-api-key"), Some("k"));
        let b = r.json();
        assert_eq!((b["model_id"].as_str(), b["voice_settings"]["stability"].as_f64()), (Some(ELEVENLABS_MODEL), Some(0.9)));
        assert_eq!(ElevenLabs.voices(&m, &Cancel::new()).unwrap(), vec!["v1 (Rachel)"]);
    }

    #[test]
    fn xai_payload_only_sends_non_defaults() {
        let srv = audio_server("audio/mpeg", b"ID3\x04abc");
        let m = media("xai", &srv.url, "[tts.xai]\nspeed = 3.0\nvoice_id = \"rex\"");
        Xai { oauth: false }.synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).unwrap();
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/tts");
        let b = r.json();
        assert_eq!((b["voice_id"].as_str(), b["language"].as_str(), b["speed"].as_f64()), (Some("rex"), Some("en"), Some(1.5)));
        assert!(b.get("output_format").is_none());
        let mut req = TtsRequest::new("hello");
        req.format = Some("wav".into());
        Xai { oauth: false }.synthesize(&m, &req, &Cancel::new()).unwrap();
        assert_eq!(srv.requests()[1].json()["output_format"]["codec"], "wav");
    }

    #[test]
    fn xai_oauth_uses_bearer_token() {
        let srv = audio_server("audio/mpeg", b"ID3\x04abc");
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[providers.xai-oauth]\napi_key = \"oauth-tok\"\nbase_url = \"{}\"\n[tts.xai]\nbase_url = \"{}\"", srv.url, srv.url)), http: Default::default() };
        if std::env::var("XAI_API_KEY").is_err() {
            Xai { oauth: true }.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
            assert_eq!(srv.requests()[0].header("authorization"), Some("Bearer oauth-tok"));
        }
    }

    #[test]
    fn xai_local_tags() {
        let t = xai_auto_tags("Hello there my friend. This is the second sentence.\n\nNew paragraph.", &Cancel::new());
        // Hermes #29417: the paragraph pass already tagged it, so no second first-sentence pause.
        assert_eq!(t, "Hello there my friend. This is the second sentence. [pause] New paragraph.");
        assert_eq!(xai_auto_tags("Bonjour Monsieur Talbot. Ceci est un test de réponse vocale.", &Cancel::new()), "Bonjour Monsieur Talbot. [pause] Ceci est un test de réponse vocale.");
    }

    #[test]
    fn minimax_v2_hex_and_errors() {
        let srv = FakeServer::start(|r, n| {
            if n == 0 {
                (200, vec![], format!("{{\"data\":{{\"audio\":\"494433\"}},\"base_resp\":{{\"status_code\":0}},\"path\":\"{}\"}}", r.path))
            } else {
                (200, vec![], "{\"base_resp\":{\"status_code\":1004,\"status_msg\":\"login fail\"}}".into())
            }
        });
        let m = media("minimax", &format!("{}/v1/t2a_v2", srv.url), "[tts.minimax]\ngroup_id = \"g1\"");
        let s = MiniMax.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.bytes, b"ID3");
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/v1/t2a_v2?GroupId=g1");
        assert_eq!(r.json()["voice_setting"]["voice_id"], "English_expressive_narrator");
        let e = MiniMax.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap_err();
        assert!(e.contains("code 1004") && e.contains("login fail"), "{e}");
        let bad = Media { cfg: crate::MediaConfig::from_toml("[providers.minimax]\napi_key = \"k\"\n[tts.minimax]\nbase_url = \"https://api.minimaxi.com/v1/t2a_v2\""), http: Default::default() };
        assert!(MiniMax.synthesize(&bad, &TtsRequest::new("x"), &Cancel::new()).unwrap_err().contains("region"));
    }

    #[test]
    fn gemini_generate_content_and_interactions() {
        let pcm = crate::store::b64(&[1, 0, 2, 0]);
        let srv = FakeServer::start(move |r, _| {
            if r.path.ends_with("/interactions") {
                (200, vec![], format!("{{\"output_audio\":{{\"data\":\"{pcm}\"}}}}"))
            } else {
                (200, vec![], format!("{{\"candidates\":[{{\"content\":{{\"parts\":[{{\"inlineData\":{{\"mimeType\":\"audio/L16\",\"data\":\"{pcm}\"}}}}]}}}}]}}"))
            }
        });
        let m = media("gemini", &format!("{}/v1beta", srv.url), "[tts.gemini]\nvoice = \"Puck\"\npersona_prompt = \"Calm narrator. {transcript}\"");
        let s = Gemini.synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).unwrap();
        assert_eq!((s.audio.mime.as_str(), s.sample_rate, s.audio.bytes.len()), ("audio/pcm", Some(24000), 4));
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/v1beta/models/gemini-2.5-flash-preview-tts:generateContent");
        assert_eq!(r.header("x-goog-api-key"), Some("k"));
        let b = r.json();
        assert_eq!(b["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"], "Puck");
        assert!(b["contents"][0]["parts"][0]["text"].as_str().unwrap().contains("Calm narrator. hello"));
        let mut req = TtsRequest::new("hi");
        req.model = Some("gemini-3.8-flash-tts".into());
        Gemini.synthesize(&m, &req, &Cancel::new()).unwrap();
        let b = srv.requests()[1].json();
        assert_eq!((b["store"].as_bool(), b["generation_config"]["speech_config"][0]["voice"].as_str()), (Some(false), Some("Puck")));
    }

    #[test]
    fn mistral_base64_audio() {
        let srv = FakeServer::start(|_, _| (200, vec![], format!("{{\"audio_data\":\"{}\"}}", crate::store::b64(b"ID3\x04x"))));
        let m = media("mistral", &srv.url, "");
        let s = Mistral.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/mpeg");
        let r = &srv.requests()[0];
        assert_eq!(r.path, "/v1/audio/speech");
        assert_eq!(r.json()["voice_id"], "c69964a6-ab8b-4f8a-9465-ec0925096ec8");
    }
}
