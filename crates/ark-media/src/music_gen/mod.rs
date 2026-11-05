//! Music generation: the `music_generate` tool (OpenClaw
//! `src/agents/tools/music-generate-tool.ts`) and its runtime
//! (`src/music-generation/runtime.ts`): candidates with fallback, reference-image
//! guard, unsupported lyrics/instrumental/duration/format dropped and reported,
//! duration clamped to the provider maximum.
//!
//! Providers (OpenClaw `extensions/*/music-generation-provider.ts`): google (Lyria 3),
//! minimax (music-2.6, hex SSE stream), fal (MiniMax Music / ACE-Step / Stable Audio),
//! openrouter (Lyria via chat-completions audio stream), comfy (ComfyUI workflow).
//!
//! ```toml
//! [media.music]
//! provider = "auto"   # or google | minimax | fal | openrouter | comfy
//! model = ""          # "provider/model"
//! fallbacks = []
//! timeout_secs = 300  # at least 120
//! background = false
//! ```

use crate::genrt::{self, Attempt, ProviderInfo, Source};
use crate::store::{self, Asset};
use crate::Media;
use ark_core::tool::arg_opt_str;
use ark_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct MusicRequest {
    pub prompt: String,
    pub model: String,
    pub lyrics: Option<String>,
    pub instrumental: Option<bool>,
    pub duration: Option<u32>,
    /// "mp3" | "wav".
    pub format: Option<String>,
    pub images: Vec<Source>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct MusicResult {
    pub tracks: Vec<Asset>,
    pub model: String,
    pub lyrics: Vec<String>,
    pub meta: Value,
}

/// Capabilities for one provider/model and mode (generate vs edit = with reference images).
#[derive(Debug, Clone, Default)]
pub struct MusicCaps {
    pub max_duration: Option<u32>,
    pub lyrics: bool,
    pub instrumental: bool,
    pub duration: bool,
    pub format: bool,
    /// Empty = any of mp3/wav.
    pub formats: Vec<&'static str>,
    /// Reference images accepted (edit mode); 0 = none.
    pub max_images: usize,
}

pub trait MusicProvider: ProviderInfo {
    fn caps(&self, model: &str) -> MusicCaps;
    fn generate(&self, m: &Media, req: &MusicRequest, cancel: &Cancel) -> Result<MusicResult, String>;
}

pub fn providers() -> Vec<Arc<dyn MusicProvider>> {
    vec![Arc::new(Google), Arc::new(Minimax), Arc::new(Fal), Arc::new(OpenRouter), Arc::new(Comfy)]
}

#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub provider: String,
    pub result: MusicResult,
    pub notes: Vec<String>,
    pub attempts: Vec<Attempt>,
}

/// OpenClaw `runMusicGeneration`.
pub fn generate(m: &Media, base: &MusicRequest, cands: &[(Arc<dyn MusicProvider>, String)], cancel: &Cancel) -> Result<RunResult, String> {
    let mut attempts = Vec::new();
    for (p, model) in cands {
        let caps = p.caps(model);
        let label = format!("{}/{model}", p.id());
        if !base.images.is_empty() && caps.max_images == 0 {
            attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: format!("{label} does not support reference image inputs; skipping") });
            continue;
        }
        if base.images.len() > caps.max_images.max(1) && caps.max_images > 0 {
            attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: format!("{label} supports at most {} reference image(s), {} requested; skipping", caps.max_images, base.images.len()) });
            continue;
        }
        let mut req = base.clone();
        req.model = model.clone();
        let mut notes = vec![];
        if req.lyrics.as_deref().is_some_and(|l| !l.trim().is_empty()) && !caps.lyrics {
            notes.push("ignored unsupported lyrics".to_string());
            req.lyrics = None;
        }
        if let Some(i) = req.instrumental.filter(|_| !caps.instrumental) {
            notes.push(format!("ignored unsupported instrumental={i}"));
            req.instrumental = None;
        }
        if let Some(d) = req.duration {
            if !caps.duration {
                notes.push(format!("ignored unsupported durationSeconds={d}"));
                req.duration = None;
            } else if let Some(max) = caps.max_duration.filter(|m| *m > 0 && d > *m) {
                notes.push(format!("durationSeconds {d} → {max} (provider maximum)"));
                req.duration = Some(max);
            }
        }
        if let Some(f) = req.format.clone() {
            if !caps.format || (!caps.formats.is_empty() && !caps.formats.contains(&f.as_str())) {
                notes.push(format!("ignored unsupported format={f}"));
                req.format = None;
            }
        }
        match p.generate(m, &req, cancel) {
            Ok(r) if r.tracks.is_empty() => attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: "Music generation provider returned no tracks.".into() }),
            Ok(r) => {
                if let Some(i) = r.tracks.iter().position(|t| t.bytes.is_empty()) {
                    attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: format!("Music generation provider returned an empty track buffer at index {i}.") });
                    continue;
                }
                return Ok(RunResult { provider: p.id().into(), result: r, notes, attempts });
            }
            Err(e) => attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: e }),
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    Err(genrt::failure("music-generation", &attempts))
}

fn bearer(c: &crate::Creds) -> Vec<(String, String)> {
    let mut v = c.headers.clone();
    v.extend(c.bearer());
    v
}

fn key(c: &crate::Creds, label: &str) -> Result<String, String> {
    c.key.clone().ok_or_else(|| format!("{label} API key missing"))
}

/// Prompt with instrumental / lyrics / duration hints (Google & OpenRouter Lyria).
fn lyria_prompt(req: &MusicRequest, with_duration: bool) -> String {
    let mut parts = vec![req.prompt.trim().to_string()];
    if req.instrumental == Some(true) {
        parts.push("Instrumental only. No vocals, no sung lyrics, no spoken word.".into());
    }
    if let Some(l) = req.lyrics.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        parts.push(format!("Lyrics:\n{l}"));
    }
    if let (true, Some(d)) = (with_duration, req.duration) {
        parts.push(format!("Target duration: about {d} seconds."));
    }
    parts.join("\n\n")
}

fn ext_name(i: usize, mime: &str, fallback: &str) -> String {
    let e = store::ext_for(mime);
    format!("track-{}.{}", i + 1, if e == "bin" || e.is_empty() { fallback } else { e })
}

// ================================================================ Google (Lyria 3)

pub struct Google;
const LYRIA_CLIP: &str = "lyria-3-clip-preview";
const LYRIA_PRO: &str = "lyria-3-pro-preview";

impl ProviderInfo for Google {
    fn id(&self) -> &'static str {
        "google"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["gemini", "lyria"]
    }
    fn label(&self) -> &'static str {
        "Google"
    }
    fn env(&self) -> &'static [&'static str] {
        &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://generativelanguage.googleapis.com/v1beta"
    }
    fn default_model(&self) -> String {
        LYRIA_CLIP.into()
    }
    fn models(&self) -> Vec<String> {
        vec![LYRIA_CLIP.into(), LYRIA_PRO.into()]
    }
}

impl MusicProvider for Google {
    fn caps(&self, model: &str) -> MusicCaps {
        MusicCaps { lyrics: true, instrumental: true, format: true, formats: if model == LYRIA_PRO { vec!["mp3", "wav"] } else { vec!["mp3"] }, max_images: 10, ..Default::default() }
    }
    fn generate(&self, m: &Media, req: &MusicRequest, cancel: &Cancel) -> Result<MusicResult, String> {
        if req.images.len() > 10 {
            return Err("Google music generation supports at most 10 reference images.".into());
        }
        let c = self.creds(m);
        let k = key(&c, "Google")?;
        let model = req.model.trim_start_matches("google/").to_string();
        if let Some(f) = &req.format {
            let ok: &[&str] = if model == LYRIA_PRO { &["mp3", "wav"] } else { &["mp3"] };
            if !ok.contains(&f.as_str()) {
                return Err(format!("Google music generation model {model} supports {} output.", ok.join(", ")));
            }
        }
        let mut parts = vec![json!({"text": lyria_prompt(req, false)})];
        parts.extend(req.images.iter().map(|i| json!({"inlineData": {"mimeType": i.asset.mime, "data": i.b64()}})));
        let meta = |lyrics: bool| {
            let mut v = json!({"inputImageCount": req.images.len(), "instrumental": req.instrumental == Some(true)});
            if lyrics {
                v["requestedLyrics"] = json!(true);
            }
            if let Some(f) = &req.format {
                v["requestedFormat"] = json!(f);
            }
            v
        };
        let body = json!({"contents": [{"role": "user", "parts": parts}], "generationConfig": {"responseModalities": ["AUDIO", "TEXT"]}});
        let mut h = c.headers.clone();
        h.push(("x-goog-api-key".into(), k));
        let url = format!("{}/models/{model}:generateContent", c.base.trim_end_matches('/'));
        for _attempt in 0..2 {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            let v = m.http.post_json(&url, &h, &body).map_err(|e| format!("Google music generation failed: {e}"))?;
            let (mut tracks, mut lyrics) = (vec![], vec![]);
            for cand in v["candidates"].as_array().cloned().unwrap_or_default() {
                for p in cand["content"]["parts"].as_array().cloned().unwrap_or_default() {
                    if let Some(t) = p["text"].as_str().map(str::trim).filter(|t| !t.is_empty()) {
                        lyrics.push(t.to_string());
                        continue;
                    }
                    let inline = if p["inlineData"].is_object() { &p["inlineData"] } else { &p["inline_data"] };
                    let Some(data) = inline["data"].as_str().filter(|d| !d.is_empty()) else { continue };
                    let mime = inline["mimeType"].as_str().or(inline["mime_type"].as_str()).unwrap_or("audio/mpeg");
                    let mut a = Asset::from_b64(data, mime).map_err(|_| "Generated music asset contains malformed base64 audio data".to_string())?;
                    a.meta = json!({"fileName": ext_name(tracks.len(), mime, if model == LYRIA_PRO { "wav" } else { "mp3" })});
                    tracks.push(a);
                }
            }
            if !tracks.is_empty() {
                let had_lyrics = req.lyrics.as_deref().map(str::trim).is_some_and(|l| !l.is_empty());
                return Ok(MusicResult { tracks, model, lyrics, meta: meta(had_lyrics) });
            }
            let block = v["promptFeedback"]["blockReason"].as_str().filter(|b| !b.ends_with("_UNSPECIFIED"));
            if let Some(b) = block {
                return Err(format!("Google music generation returned no audio: prompt blocked ({b})"));
            }
            if let Some(f) = v["candidates"].as_array().and_then(|a| a.iter().find_map(|c| c["finishReason"].as_str().filter(|f| *f != "STOP" && *f != "FINISH_REASON_UNSPECIFIED"))) {
                return Err(format!("Google music generation returned no audio: generation stopped ({f})"));
            }
        }
        Err("Google music generation response missing audio data".into())
    }
}

// ================================================================ fal

pub struct Fal;
const FAL_MM: &str = "fal-ai/minimax-music/v2.6";
const FAL_ACE: &str = "fal-ai/ace-step/prompt-to-audio";
const FAL_SA: &str = "fal-ai/stable-audio-25/text-to-audio";

impl ProviderInfo for Fal {
    fn id(&self) -> &'static str {
        "fal"
    }
    fn label(&self) -> &'static str {
        "fal"
    }
    fn env(&self) -> &'static [&'static str] {
        &["FAL_KEY", "FAL_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://fal.run"
    }
    fn default_model(&self) -> String {
        FAL_MM.into()
    }
    fn models(&self) -> Vec<String> {
        vec![FAL_MM.into(), FAL_ACE.into(), FAL_SA.into()]
    }
}

/// OpenClaw `buildFalMusicRequestBody`.
pub fn fal_body(req: &MusicRequest) -> Result<Value, String> {
    let lyrics = req.lyrics.as_deref().map(str::trim).filter(|l| !l.is_empty());
    if req.model == FAL_ACE || req.model == FAL_SA {
        let sa = req.model == FAL_SA;
        if lyrics.is_some() {
            return Err(format!("fal {} music generation does not support explicit lyrics.", if sa { "Stable Audio" } else { "ACE-Step" }));
        }
        if sa && req.instrumental == Some(true) {
            return Err("fal Stable Audio music generation does not support instrumental mode.".into());
        }
        let mut b = json!({"prompt": req.prompt});
        if req.instrumental == Some(true) {
            b["instrumental"] = json!(true);
        }
        if let Some(d) = req.duration {
            b[if sa { "seconds_total" } else { "duration" }] = json!(d);
        }
        return Ok(b);
    }
    if lyrics.is_some() && req.instrumental == Some(true) {
        return Err("fal MiniMax music generation cannot use lyrics when instrumental=true.".into());
    }
    let mut b = json!({"prompt": req.prompt, "audio_setting": {"sample_rate": 44100, "bitrate": 256000, "format": req.format.clone().unwrap_or_else(|| "mp3".into())}});
    match lyrics {
        Some(l) => b["lyrics"] = json!(l),
        None if req.instrumental != Some(true) => b["lyrics_optimizer"] = json!(true),
        None => {}
    }
    if req.instrumental == Some(true) {
        b["is_instrumental"] = json!(true);
    }
    if let Some(d) = req.duration {
        b["duration"] = json!(d);
    }
    Ok(b)
}

impl MusicProvider for Fal {
    fn caps(&self, model: &str) -> MusicCaps {
        MusicCaps {
            max_duration: Some(240),
            lyrics: model != FAL_ACE && model != FAL_SA,
            instrumental: model != FAL_SA,
            duration: true,
            format: true,
            formats: match model {
                FAL_MM => vec!["mp3"],
                FAL_ACE | FAL_SA => vec!["wav"],
                _ => vec!["mp3", "wav"],
            },
            max_images: 0,
        }
    }
    fn generate(&self, m: &Media, req: &MusicRequest, _cancel: &Cancel) -> Result<MusicResult, String> {
        if !req.images.is_empty() {
            return Err("fal music generation does not support image reference inputs.".into());
        }
        let c = self.creds(m);
        let mut h = c.headers.clone();
        h.push(("Authorization".into(), format!("Key {}", key(&c, "fal")?)));
        let v = m.http.post_json(&c.url(&req.model), &h, &fal_body(req)?).map_err(|e| format!("fal music generation failed: {e}"))?;
        let cand = ["audio", "audio_file"].iter().find_map(|k| match &v[*k] {
            Value::String(s) if !s.is_empty() => Some((s.clone(), None)),
            Value::Object(o) => o.get("url").and_then(|u| u.as_str()).filter(|u| !u.is_empty()).map(|u| (u.to_string(), o.get("content_type").and_then(|x| x.as_str()).map(str::to_string))),
            _ => None,
        });
        let (url, ct) = cand.ok_or("fal music generation response missing audio output")?;
        let a = genrt::fetch_asset(m, &url, &[], ct.as_deref().unwrap_or("audio/mpeg")).map_err(|e| format!("fal generated music download failed: {e}"))?;
        let mut meta = json!({"audioUrl": url, "instrumental": req.instrumental == Some(true), "requestedFormat": req.format, "requestedDurationSeconds": req.duration});
        for k in ["seed", "tags"] {
            if !v[k].is_null() {
                meta[k] = v[k].clone();
            }
        }
        Ok(MusicResult { tracks: vec![a], model: req.model.clone(), lyrics: v["lyrics"].as_str().filter(|s| !s.trim().is_empty()).map(|s| vec![s.to_string()]).unwrap_or_default(), meta })
    }
}

// ================================================================ MiniMax

pub struct Minimax;

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if !t.len().is_multiple_of(2) || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("MiniMax music generation returned malformed hex audio".into());
    }
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

fn mm_ok(v: &Value) -> Result<(), String> {
    match v["base_resp"]["status_code"].as_i64() {
        Some(0) | None => Ok(()),
        Some(c) => Err(format!("MiniMax music generation failed: {} (status_code {c})", v["base_resp"]["status_msg"].as_str().unwrap_or("error"))),
    }
}

impl ProviderInfo for Minimax {
    fn id(&self) -> &'static str {
        "minimax"
    }
    fn label(&self) -> &'static str {
        "MiniMax"
    }
    fn env(&self) -> &'static [&'static str] {
        &["MINIMAX_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.minimax.io"
    }
    fn default_model(&self) -> String {
        "music-2.6".into()
    }
    fn models(&self) -> Vec<String> {
        ["music-2.6", "music-2.6-free", "music-cover", "music-cover-free"].iter().map(|s| s.to_string()).collect()
    }
}

impl MusicProvider for Minimax {
    fn caps(&self, _model: &str) -> MusicCaps {
        MusicCaps { lyrics: true, instrumental: true, format: true, formats: vec!["mp3"], ..Default::default() }
    }
    fn generate(&self, m: &Media, req: &MusicRequest, _cancel: &Cancel) -> Result<MusicResult, String> {
        if !req.images.is_empty() {
            return Err("MiniMax music generation does not support image reference inputs.".into());
        }
        let lyrics = req.lyrics.as_deref().map(str::trim).filter(|l| !l.is_empty());
        if req.instrumental == Some(true) && lyrics.is_some() {
            return Err("MiniMax music generation cannot use lyrics when instrumental=true.".into());
        }
        if req.format.as_deref().is_some_and(|f| f != "mp3") {
            return Err("MiniMax music generation currently supports mp3 output only.".into());
        }
        let c = self.creds(m);
        key(&c, "MiniMax")?;
        let mut body = json!({"model": req.model, "prompt": req.prompt.trim(), "stream": true, "output_format": "hex", "audio_setting": {"sample_rate": 44100, "bitrate": 256000, "format": "mp3"}});
        if req.instrumental == Some(true) {
            body["is_instrumental"] = json!(true);
        }
        match lyrics {
            Some(l) => body["lyrics"] = json!(l),
            None if req.instrumental != Some(true) => body["lyrics_optimizer"] = json!(true),
            None => {}
        }
        let h = bearer(&c);
        let r = m.http.post_json_bytes(&c.url("/v1/music_generation"), &h, &body).map_err(|e| format!("MiniMax music generation failed: {e}"))?;
        let ct = r.content_type().to_ascii_lowercase();
        let mut meta = json!({"instrumental": req.instrumental == Some(true)});
        if lyrics.is_some() {
            meta["requestedLyrics"] = json!(true);
        }
        if ct.starts_with("audio/") {
            return Ok(MusicResult { tracks: vec![Asset::new(r.body, &ct)], model: req.model.clone(), lyrics: vec![], meta });
        }
        let text = r.text();
        if ct.contains("event-stream") || text.trim_start().starts_with("data:") {
            let (mut audio, mut done) = (Vec::new(), false);
            for line in text.lines().map(str::trim).filter_map(|l| l.strip_prefix("data:")).map(str::trim) {
                if line.is_empty() || line == "[DONE]" {
                    continue;
                }
                let f: Value = serde_json::from_str(line).map_err(|e| format!("MiniMax music stream frame: {e}"))?;
                mm_ok(&f)?;
                let st = f["data"]["status"].as_i64().map(|s| s.to_string()).or_else(|| f["data"]["status"].as_str().map(str::to_string)).unwrap_or_default();
                if st == "2" {
                    done = true;
                    if !audio.is_empty() {
                        continue;
                    }
                }
                if let Some(hx) = f["data"]["audio"].as_str().filter(|s| !s.is_empty()) {
                    audio.extend(hex_decode(hx)?);
                }
            }
            if !done {
                return Err("MiniMax music generation stream ended without completion".into());
            }
            if audio.is_empty() {
                return Err("MiniMax music generation response missing audio output".into());
            }
            return Ok(MusicResult { tracks: vec![Asset::new(audio, "audio/mpeg")], model: req.model.clone(), lyrics: vec![], meta });
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| format!("MiniMax music generation failed: {}", crate::http::excerpt(&text, 200)))?;
        mm_ok(&v)?;
        let cand = v["audio"].as_str().or(v["data"]["audio"].as_str()).filter(|s| !s.is_empty());
        let is_url = cand.is_some_and(|a| a.starts_with("http://") || a.starts_with("https://"));
        let url = v["audio_url"].as_str().or(v["data"]["audio_url"].as_str()).filter(|s| !s.is_empty()).or(cand.filter(|_| is_url));
        let lyr = v["lyrics"].as_str().or(v["data"]["lyrics"].as_str()).map(|l| hex_decode(l).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| l.to_string())).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if let Some(t) = v["task_id"].as_str().or(v["data"]["task_id"].as_str()).filter(|s| !s.is_empty()) {
            meta["taskId"] = json!(t);
        }
        if let Some(u) = url {
            meta["audioUrl"] = json!(u);
        }
        let track = match (url, cand.filter(|_| !is_url)) {
            (Some(u), _) => genrt::fetch_asset(m, u, &[], "audio/mpeg").map_err(|e| format!("MiniMax generated music download failed: {e}"))?,
            (None, Some(hx)) => Asset::new(hex_decode(hx)?, "audio/mpeg"),
            _ => return Err("MiniMax music generation response missing audio output".into()),
        };
        Ok(MusicResult { tracks: vec![track], model: req.model.clone(), lyrics: lyr.into_iter().collect(), meta })
    }
}

// ================================================================ OpenRouter

pub struct OpenRouter;

impl ProviderInfo for OpenRouter {
    fn id(&self) -> &'static str {
        "openrouter"
    }
    fn label(&self) -> &'static str {
        "OpenRouter"
    }
    fn env(&self) -> &'static [&'static str] {
        &["OPENROUTER_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://openrouter.ai/api/v1"
    }
    fn default_model(&self) -> String {
        "google/lyria-3-pro-preview".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["google/lyria-3-pro-preview".into(), "google/lyria-3-clip-preview".into()]
    }
}

impl MusicProvider for OpenRouter {
    fn caps(&self, _model: &str) -> MusicCaps {
        MusicCaps { max_duration: Some(180), lyrics: true, instrumental: true, duration: true, format: true, formats: vec!["mp3", "wav"], max_images: 1 }
    }
    fn generate(&self, m: &Media, req: &MusicRequest, _cancel: &Cancel) -> Result<MusicResult, String> {
        if req.images.len() > 1 {
            return Err("OpenRouter music generation supports at most one reference image.".into());
        }
        let c = self.creds(m);
        key(&c, "OpenRouter")?;
        let format = req.format.clone().unwrap_or_else(|| "wav".into());
        let prompt = lyria_prompt(req, true);
        let content = if req.images.is_empty() { json!(prompt) } else { json!([{"type": "text", "text": prompt}, {"type": "image_url", "image_url": {"url": req.images[0].url_or_data()}}]) };
        let body = json!({"model": req.model, "messages": [{"role": "user", "content": content}], "modalities": ["text", "audio"], "audio": {"format": format}, "stream": true});
        let r = m.http.post_json_bytes(&c.url("/chat/completions"), &bearer(&c), &body).map_err(|e| format!("OpenRouter music generation failed: {e}"))?;
        let (mut b64, mut transcript, mut finished) = (String::new(), String::new(), false);
        for line in r.text().lines().map(str::trim).filter_map(|l| l.strip_prefix("data:")).map(str::trim) {
            if line.is_empty() {
                continue;
            }
            if line == "[DONE]" {
                finished = true;
                break;
            }
            let p: Value = serde_json::from_str(line).map_err(|e| format!("OpenRouter music stream: {e}"))?;
            if p["error"].is_object() {
                return Err(format!("OpenRouter music generation failed: {}", p["error"]["message"].as_str().unwrap_or("unknown provider stream error")));
            }
            let a = &p["choices"][0]["delta"]["audio"];
            if let Some(d) = a["data"].as_str() {
                b64.push_str(d.trim());
            }
            if let Some(t) = a["transcript"].as_str() {
                transcript.push_str(t);
            }
        }
        if !finished {
            return Err("OpenRouter music generation stream ended before completion".into());
        }
        if b64.is_empty() {
            return Err("OpenRouter music generation response missing audio data".into());
        }
        let bytes = store::b64_decode(&b64).map_err(|_| "OpenRouter music generation returned malformed base64 audio data".to_string())?;
        Ok(MusicResult { tracks: vec![Asset::new(bytes, if format == "mp3" { "audio/mpeg" } else { "audio/wav" })], model: req.model.clone(), lyrics: Some(transcript).filter(|t| !t.is_empty()).into_iter().collect(), meta: json!({"inputImageCount": req.images.len(), "instrumental": req.instrumental == Some(true), "requestedFormat": format}) })
    }
}

// ================================================================ ComfyUI

pub struct Comfy;

impl ProviderInfo for Comfy {
    fn id(&self) -> &'static str {
        "comfy"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["comfyui"]
    }
    fn label(&self) -> &'static str {
        "ComfyUI"
    }
    fn env(&self) -> &'static [&'static str] {
        &[]
    }
    fn default_base(&self) -> &'static str {
        "http://127.0.0.1:8188"
    }
    fn default_model(&self) -> String {
        "workflow".into()
    }
    fn configured(&self, m: &Media) -> bool {
        let mut t = m.cfg.table("providers.comfy");
        if let Some(n) = t.get("music").and_then(|v| v.as_table()).cloned() {
            t.extend(n);
        }
        (t.contains_key("workflow") || t.contains_key("workflow_path")) && t.contains_key("prompt_node_id")
    }
}

impl MusicProvider for Comfy {
    fn caps(&self, _model: &str) -> MusicCaps {
        MusicCaps { max_images: 1, ..Default::default() }
    }
    fn generate(&self, m: &Media, req: &MusicRequest, cancel: &Cancel) -> Result<MusicResult, String> {
        if req.images.len() > 1 {
            return Err("Comfy music generation supports at most 1 reference image.".into());
        }
        let input = req.images.first().map(|s| crate::image_gen::InputImage { bytes: s.asset.bytes.clone(), mime: s.asset.mime.clone(), name: s.filename("input"), url: s.asset.url.clone() });
        let (assets, pid) = crate::image_gen::run_comfy_workflow(m, "music", &req.prompt, input.as_ref(), req.timeout, cancel)?;
        let nodes: Vec<String> = assets.iter().map(|a| a.node_id.clone()).collect();
        Ok(MusicResult { tracks: assets.into_iter().map(|a| Asset::new(a.bytes, &a.mime)).collect(), model: "workflow".into(), lyrics: vec![], meta: json!({"promptId": pid, "outputNodeIds": nodes, "inputImageCount": req.images.len()}) })
    }
}

// ================================================================ tool

pub struct MusicGenerate {
    pub m: Arc<Media>,
}

const MIN_TIMEOUT: Duration = Duration::from_secs(120);

/// OpenClaw `normalizeMediaReferenceList`: keep the first spelling, drop empties and
/// duplicates (an optional `@` prefix is not part of the identity).
fn dedupe_refs(refs: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    refs.into_iter()
        .filter(|r| {
            let k = r.strip_prefix('@').unwrap_or(r).trim().to_string();
            !k.is_empty() && seen.insert(k)
        })
        .collect()
}

fn save(m: &Media, dir: PathBuf, prompt: &str, filename: Option<&str>, r: RunResult) -> Result<String, String> {
    let base = filename.map(|f| {
        let f = f.rsplit('/').next().unwrap_or(f);
        f.rsplit_once('.').map(|(s, _)| s).unwrap_or(f).to_string()
    });
    let _ = m;
    let n = r.result.tracks.len();
    let mut paths = vec![];
    for (i, t) in r.result.tracks.iter().enumerate() {
        let stem = match &base {
            Some(b) if n > 1 => format!("{b}-{}", i + 1),
            Some(b) => b.clone(),
            None => format!("{}-{}", store::stem(&format!("{}-music", r.provider)), i + 1),
        };
        paths.push(store::save(&dir, &stem, t)?);
    }
    let out = json!({
        "success": true,
        "provider": r.provider,
        "model": r.result.model,
        "prompt": prompt,
        "tracks": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "lyrics": r.result.lyrics,
        "metadata": r.result.meta,
        "notes": r.notes,
        "attempts": if r.attempts.is_empty() { Value::Null } else { json!(r.attempts.iter().map(|a| json!({"provider": a.provider, "model": a.model, "error": a.error})).collect::<Vec<_>>()) },
    });
    Ok(format!("{}\n{}", serde_json::to_string_pretty(&out).unwrap_or_default(), store::media_tags(&paths, false)))
}

impl MusicGenerate {
    fn build(&self, ctx: &ToolCtx, input: &Value) -> Result<(MusicRequest, Vec<String>), String> {
        let m = &self.m;
        let prompt = arg_opt_str(input, "prompt").unwrap_or("").trim().to_string();
        if prompt.is_empty() {
            return Err("prompt is required for music generation".into());
        }
        let format = match genrt::arg(input, "format").map(|f| f.to_ascii_lowercase()) {
            None => None,
            Some(f) if f == "mp3" || f == "wav" => Some(f),
            Some(_) => return Err("format must be one of \"mp3\" or \"wav\"".into()),
        };
        let refs = dedupe_refs(genrt::str_list(input, &["image", "images"]));
        if refs.len() > 10 {
            return Err(format!("Too many reference images: {} provided, maximum is 10.", refs.len()));
        }
        let images = genrt::load_sources(m, ctx, &refs, &[], m.cfg.int_or("music.max_input_bytes", 20 * 1024 * 1024) as usize)?;
        if let Some(s) = images.iter().find(|s| store::class_of(&s.asset.mime) != "image") {
            return Err(format!("reference image input is not an image ({})", s.asset.mime));
        }
        let duration = match genrt::arg_int(input, "durationSeconds")? {
            Some(d) if d < 1 => return Err("durationSeconds must be a positive integer".into()),
            d => d.map(|d| d as u32),
        };
        let mut notes = vec![];
        let requested = genrt::arg_int(input, "timeoutMs")?.filter(|t| *t > 0).map(|t| Duration::from_millis(t as u64)).unwrap_or_else(|| Duration::from_secs(m.cfg.int_or("music.timeout_secs", 300).max(1) as u64));
        let timeout = if requested < MIN_TIMEOUT {
            notes.push(format!("Timeout normalized: requested {}ms; used {}ms.", requested.as_millis(), MIN_TIMEOUT.as_millis()));
            MIN_TIMEOUT
        } else {
            requested
        };
        Ok((MusicRequest { prompt, model: String::new(), lyrics: genrt::arg(input, "lyrics").map(str::to_string), instrumental: genrt::arg_bool(input, "instrumental"), duration, format, images, timeout }, notes))
    }

    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let m = self.m.clone();
        let (req, pre) = self.build(ctx, input)?;
        let list = providers();
        let cands = genrt::candidates(&m, "music", &list, arg_opt_str(input, "provider"), genrt::arg(input, "model"))?;
        let dir = m.out_dir(ctx, "music");
        let filename = genrt::arg(input, "filename").map(str::to_string);
        let work = move |cancel: &Cancel| -> Result<String, String> {
            let mut r = generate(&m, &req, &cands, cancel)?;
            r.notes.splice(0..0, pre.clone());
            save(&m, dir.clone(), &req.prompt, filename.as_deref(), r)
        };
        if genrt::arg_bool(input, "background").unwrap_or_else(|| self.m.cfg.bool_or("music.background", false)) {
            let key = genrt::request_key("music_generate", input);
            if let Some(j) = genrt::find_duplicate("music", &ctx.session_id, &key) {
                return Ok(format!("Music generation task {} is already running for this request; wait for its result (action=status).", j.id));
            }
            let id = genrt::spawn_job("music", ctx, arg_opt_str(input, "prompt").unwrap_or(""), &key, move |c, p| {
                p.set("Generating music");
                work(c)
            });
            return Ok(format!("Started music generation task {id} in the background. The track is delivered in a later message when it is ready; do not poll. Reply with a short acknowledgement and end this turn."));
        }
        ctx.host.progress("generating music…");
        work(&ctx.cancel)
    }

    fn list(&self) -> String {
        let m = &self.m;
        let mut lines = vec!["Music generation providers (✓ = configured):".to_string()];
        for p in providers() {
            let model = p.default_model();
            let c = p.caps(&model);
            let mut f = vec![];
            if c.lyrics {
                f.push("lyrics".to_string());
            }
            if c.instrumental {
                f.push("instrumental".into());
            }
            if c.duration {
                f.push(format!("duration{}", c.max_duration.map(|d| format!(" ≤{d}s")).unwrap_or_default()));
            }
            if !c.formats.is_empty() {
                f.push(format!("formats {}", c.formats.join("/")));
            }
            if c.max_images > 0 {
                f.push(format!("reference images ≤{}", c.max_images));
            }
            let auth = if p.configured(m) { "✓".to_string() } else if p.env().is_empty() { format!("✗ (configure [media.providers.{}])", p.id()) } else { format!("✗ set {}", p.env().join(" or ")) };
            lines.push(format!("- {} ({}) {auth}\n  default model: {model}\n  models: {}\n  {}", p.id(), p.label(), p.models().join(", "), f.join("; ")));
        }
        lines.join("\n")
    }
}

impl Tool for MusicGenerate {
    fn spec(&self) -> ToolSpec {
        let s = |d: &str| json!({"type": "string", "description": d});
        ToolSpec {
            name: "music_generate".into(),
            description: "Create a song, jingle, beat, loop, soundtrack or instrumental. prompt: style/genre/mood/tempo/instruments/purpose; lyrics: exact sung words (only when the user gives or asks for them); instrumental=true for no vocals; image/images condition on reference image(s). Saves the track and returns its path with a MEDIA: line (keep it in your reply). action=list shows providers/models; action=status shows background tasks. A lyrics-only request needs no tool: answer in text.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["generate", "list", "status"]},
                    "prompt": s("Music prompt: style, genre, mood, purpose."),
                    "lyrics": s("Exact sung lyrics only when the user supplies lyrics or asks for vocal words."),
                    "instrumental": {"type": "boolean", "description": "Instrumental-only toggle."},
                    "image": s("Reference image path/URL."),
                    "images": {"type": "array", "items": {"type": "string"}, "description": "Reference images; max 10."},
                    "model": s("Provider/model override, e.g. google/lyria-3-pro-preview."),
                    "provider": s("Provider id override."),
                    "durationSeconds": {"type": "integer", "minimum": 1, "description": "Target seconds; provider may clamp."},
                    "format": {"type": "string", "enum": ["mp3", "wav"]},
                    "filename": s("Output filename hint."),
                    "timeoutMs": {"type": "integer", "minimum": 1},
                    "background": {"type": "boolean", "description": "Return a task id now; the track arrives later."}
                }
            }),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if matches!(arg_opt_str(input, "action"), Some("list" | "status")) {
            return vec![];
        }
        let mut fx: Vec<Effect> = genrt::str_list(input, &["image", "images"]).into_iter().filter(|r| !(r.starts_with("http") || r.starts_with("data:"))).map(|r| Effect::Read { path: store::resolve(&r, &ctx.workspace) }).collect();
        let list = providers();
        if let Ok(c) = genrt::candidates(&self.m, "music", &list, arg_opt_str(input, "provider"), genrt::arg(input, "model")) {
            if let Some((p, _)) = c.first() {
                fx.push(Effect::Net { dest: crate::http::host_of(&p.creds(&self.m).base), payload: arg_opt_str(input, "prompt").unwrap_or("").to_string() });
            }
        }
        fx.push(Effect::Write { path: self.m.out_dir(ctx, "music") });
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match arg_opt_str(&input, "action").unwrap_or("generate") {
            "list" => ToolOutput::ok(self.list()),
            "status" => ToolOutput::ok(genrt::status_text("music", &ctx.session_id, arg_opt_str(&input, "job_id")).0),
            "generate" => match self.run(ctx, &input) {
                Ok(t) => ToolOutput::ok(t),
                Err(e) => ToolOutput::err(json!({"success": false, "error": e}).to_string()),
            },
            other => ToolOutput::err(format!("unknown action `{other}` (generate, list, status)")),
        }
    }
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(MusicGenerate { m: m.clone() })]
}

#[cfg(test)]
mod tests;
