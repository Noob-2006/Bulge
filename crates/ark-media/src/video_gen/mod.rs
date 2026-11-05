//! Video generation: the `video_generate` tool (Hermes `tools/video_generation_tool.py`
//! + OpenClaw `src/agents/tools/video-generate-tool.ts`), the xAI-only
//!   `xai_video_edit` / `xai_video_extend` tools (Hermes `tools/xai_video_tools.py`), and
//!   the provider runtime (OpenClaw `src/video-generation/runtime.ts`): per-mode
//!   capabilities, reference-count guards, providerOptions type checks, duration
//!   snapping, geometry normalization and fallback across candidates.
//!
//! Providers (17, OpenClaw `extensions/*/video-generation-provider.ts`; fal, xai,
//! openrouter and deepinfra also carry the Hermes `plugins/video_gen/*` behaviour):
//! fal, xai, openrouter, deepinfra, google, minimax, runway, byteplus, alibaba, qwen,
//! kie, pixverse, together, zai, novita, vydra, comfy.
//!
//! ```toml
//! [media.video]
//! provider = "auto"        # provider id, or auto = first configured
//! model = ""               # "provider/model" or a model id of `provider`
//! fallbacks = []           # extra "provider/model" candidates
//! auto_fallback = true     # then every configured provider's default model
//! timeout_secs = 0         # 0 = provider default
//! background = false       # true = return a job id at once; the result arrives later
//! max_bytes = 209715200    # larger downloads are kept as provider URLs
//! max_input_bytes = 52428800
//! ```

mod hosted;
mod more;

use crate::genrt::{self, Attempt, GeometryCaps, ProviderInfo, Source};
use crate::store::{self, Asset};
use crate::Media;
use ark_core::tool::arg_opt_str;
use ark_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// One generation request after the tool layer parsed it.
#[derive(Debug, Clone, Default)]
pub struct VideoRequest {
    pub prompt: String,
    /// Provider-local model id.
    pub model: String,
    /// True when the caller named the model (Hermes: config defaults may be re-routed per modality).
    pub explicit_model: bool,
    pub size: Option<String>,
    pub aspect_ratio: Option<String>,
    pub resolution: Option<String>,
    pub duration: Option<u32>,
    pub audio: Option<bool>,
    pub watermark: Option<bool>,
    /// Hermes first-class extras (OpenClaw passes them as providerOptions).
    pub negative_prompt: Option<String>,
    pub seed: Option<i64>,
    pub upscale: Option<bool>,
    pub images: Vec<Source>,
    pub videos: Vec<Source>,
    pub audios: Vec<Source>,
    /// OpenClaw `providerOptions`, forwarded as-is after type checks.
    pub options: Map<String, Value>,
    pub timeout: Duration,
}

impl VideoRequest {
    pub fn opt_str(&self, keys: &[&str]) -> Option<String> {
        keys.iter().find_map(|k| self.options.get(*k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
    }
    pub fn opt_num(&self, keys: &[&str]) -> Option<f64> {
        keys.iter().find_map(|k| self.options.get(*k).and_then(|v| v.as_f64()))
    }
    pub fn opt_bool(&self, k: &str) -> Option<bool> {
        self.options.get(k).and_then(|v| v.as_bool())
    }
    /// `providerOptions.seed`, else the Hermes `seed` argument.
    pub fn seed(&self) -> Option<i64> {
        self.options.get("seed").and_then(|v| v.as_i64()).or(self.seed)
    }
    pub fn negative(&self) -> Option<String> {
        self.opt_str(&["negative_prompt", "negativePrompt"]).or_else(|| self.negative_prompt.clone())
    }
    /// Role of image `i` (lowercased), if set.
    pub fn image_role(&self, i: usize) -> Option<String> {
        self.images.get(i).and_then(|s| s.role.clone()).map(|r| r.to_ascii_lowercase())
    }
}

/// Provider output.
#[derive(Debug, Clone, Default)]
pub struct VideoResult {
    pub videos: Vec<Asset>,
    pub model: String,
    pub meta: Value,
}

/// Limits for one mode (OpenClaw `VideoGenerationModeCapabilities`).
#[derive(Debug, Clone, Default)]
pub struct ModeCaps {
    /// Transform modes (image-to-video, video-to-video) must be enabled explicitly.
    pub enabled: bool,
    pub max_images: usize,
    pub max_videos: usize,
    pub max_audios: usize,
    pub max_duration: Option<u32>,
    /// Supported durations; the request snaps to the nearest (ties → longer).
    pub durations: Vec<u32>,
    pub sizes: Vec<String>,
    pub aspect_ratios: Vec<String>,
    pub resolutions: Vec<String>,
    pub supports_size: bool,
    pub supports_aspect: bool,
    pub supports_resolution: bool,
    pub supports_audio: bool,
    pub supports_watermark: bool,
    /// Declared providerOptions (`key`, "number" | "boolean" | "string"); `None` = undeclared (anything passes).
    pub options: Option<Vec<(&'static str, &'static str)>>,
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

impl ModeCaps {
    pub fn on() -> Self {
        ModeCaps { enabled: true, ..Default::default() }
    }
    pub fn off() -> Self {
        ModeCaps::default()
    }
    pub fn images(mut self, n: usize) -> Self {
        self.max_images = n;
        self
    }
    pub fn videos(mut self, n: usize) -> Self {
        self.max_videos = n;
        self
    }
    pub fn audios(mut self, n: usize) -> Self {
        self.max_audios = n;
        self
    }
    pub fn max_dur(mut self, n: u32) -> Self {
        self.max_duration = Some(n);
        self
    }
    pub fn durs(mut self, d: &[u32]) -> Self {
        self.durations = d.to_vec();
        self
    }
    pub fn aspects(mut self, a: &[&str]) -> Self {
        self.aspect_ratios = strs(a);
        self.supports_aspect = true;
        self
    }
    pub fn res(mut self, r: &[&str]) -> Self {
        self.resolutions = strs(r);
        self.supports_resolution = true;
        self
    }
    pub fn sizes(mut self, s: &[&str]) -> Self {
        self.sizes = strs(s);
        self.supports_size = true;
        self
    }
    pub fn size_ok(mut self) -> Self {
        self.supports_size = true;
        self
    }
    pub fn aspect_ok(mut self) -> Self {
        self.supports_aspect = true;
        self
    }
    pub fn res_ok(mut self) -> Self {
        self.supports_resolution = true;
        self
    }
    pub fn audio(mut self) -> Self {
        self.supports_audio = true;
        self
    }
    pub fn watermark(mut self) -> Self {
        self.supports_watermark = true;
        self
    }
    pub fn opts(mut self, o: &[(&'static str, &'static str)]) -> Self {
        self.options = Some(o.to_vec());
        self
    }
    fn geometry(&self) -> GeometryCaps {
        GeometryCaps { supports_size: self.supports_size, supports_aspect_ratio: self.supports_aspect, supports_resolution: self.supports_resolution, sizes: self.sizes.clone(), aspect_ratios: self.aspect_ratios.clone(), resolutions: self.resolutions.clone() }
    }
}

/// Capabilities of one provider/model.
#[derive(Debug, Clone, Default)]
pub struct VideoCaps {
    pub generate: ModeCaps,
    pub i2v: ModeCaps,
    pub v2v: ModeCaps,
    /// Catalog modes ("generate", "i2v", "v2v") when the model restricts them.
    pub modes: Option<Vec<&'static str>>,
}

pub trait VideoProvider: ProviderInfo {
    fn caps(&self, model: &str) -> VideoCaps;
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String>;
}

/// Every provider, in auto-selection order.
pub fn providers() -> Vec<Arc<dyn VideoProvider>> {
    vec![
        Arc::new(hosted::Fal),
        Arc::new(hosted::Xai),
        Arc::new(hosted::OpenRouter),
        Arc::new(hosted::DeepInfra),
        Arc::new(hosted::Google),
        Arc::new(more::Minimax),
        Arc::new(more::Runway),
        Arc::new(more::BytePlus),
        Arc::new(more::Dashscope::alibaba()),
        Arc::new(more::Dashscope::qwen()),
        Arc::new(more::Kie),
        Arc::new(more::PixVerse),
        Arc::new(more::Together),
        Arc::new(more::Zai),
        Arc::new(more::Novita),
        Arc::new(more::Vydra),
        Arc::new(more::Comfy),
    ]
}

pub fn provider(id: &str) -> Option<Arc<dyn VideoProvider>> {
    let id = id.trim().to_ascii_lowercase();
    providers().into_iter().find(|p| p.id() == id || p.aliases().contains(&id.as_str()))
}

// ---------------------------------------------------------------- shared provider helpers

/// URL a provider can fetch: the original remote URL, else a `data:` URL.
pub(crate) fn src_url(s: &Source) -> String {
    s.url_or_data()
}

pub(crate) fn remote(s: &Source) -> Option<String> {
    s.asset.url.clone().filter(|u| u.starts_with("http://") || u.starts_with("https://"))
}

/// Download a provider-hosted video; the provider's auth only travels to its own host.
pub(crate) fn download(m: &Media, url: &str, auth: &[(String, String)], base: &str) -> Result<Asset, String> {
    let same = crate::http::host_of(url) == crate::http::host_of(base);
    genrt::fetch_asset(m, url, if same { auth } else { &[] }, "video/mp4")
}

/// `{"error": "…"}` / `{"error": {"message": "…"}}` / `{"message": "…"}`.
pub(crate) fn err_of(v: &Value) -> Option<String> {
    v["error"].as_str().map(str::to_string).or_else(|| v["error"]["message"].as_str().map(str::to_string)).or_else(|| v["message"].as_str().map(str::to_string)).filter(|s| !s.trim().is_empty())
}

pub(crate) fn require_key(c: &crate::Creds, label: &str) -> Result<String, String> {
    c.key.clone().ok_or_else(|| format!("{label} API key missing"))
}

pub(crate) fn sstr(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).or_else(|| v[k].as_i64().map(|n| n.to_string()))
}

/// Nearest supported duration (ties → longer), OpenClaw `selectSupportedVideoDuration`.
pub fn snap_duration(d: u32, supported: &[u32]) -> u32 {
    let mut best = supported[0];
    for &c in supported {
        let (cd, bd) = ((c as i64 - d as i64).abs(), (best as i64 - d as i64).abs());
        if cd < bd || (cd == bd && c > best) {
            best = c;
        }
    }
    best
}

// ---------------------------------------------------------------- runtime

/// Which mode the inputs select (`None` = images and videos together).
fn mode_of(req: &VideoRequest) -> Option<&'static str> {
    match (req.images.len(), req.videos.len()) {
        (i, v) if i > 0 && v > 0 => None,
        (_, v) if v > 0 => Some("v2v"),
        (i, _) if i > 0 => Some("i2v"),
        _ => Some("generate"),
    }
}

fn mode_caps<'a>(caps: &'a VideoCaps, req: &VideoRequest) -> (Option<&'static str>, Option<&'a ModeCaps>) {
    match mode_of(req) {
        Some("v2v") => (Some("v2v"), Some(&caps.v2v)),
        Some("i2v") => (Some("i2v"), Some(&caps.i2v)),
        Some(_) => (Some("generate"), Some(&caps.generate)),
        None if caps.v2v.enabled && caps.v2v.max_images > 0 => (None, Some(&caps.v2v)),
        None => (None, None),
    }
}

/// Why `provider/model` cannot take this request (OpenClaw `buildCapabilityFailure` and the
/// providerOptions / duration guards), or `None` when it can.
pub fn capability_mismatch(label: &str, caps: &VideoCaps, req: &VideoRequest) -> Option<String> {
    let (mode, mc) = mode_caps(caps, req);
    if let (Some(mode), Some(modes)) = (mode, &caps.modes) {
        if !modes.contains(&mode) {
            let what = match mode {
                "generate" => "text-to-video generation",
                "i2v" => "image-to-video generation",
                _ => "video-to-video generation",
            };
            return Some(format!("{label} does not support {what}; skipping"));
        }
    }
    let (ni, nv, na) = (req.images.len(), req.videos.len(), req.audios.len());
    if ni > 0 || nv > 0 {
        let visual = if ni > 0 && nv > 0 {
            "combined image/video reference inputs"
        } else if ni > 0 {
            "reference image inputs"
        } else {
            "reference video inputs"
        };
        if !mc.map(|c| c.enabled).unwrap_or(false) {
            return Some(format!("{label} does not support {visual}; skipping to avoid silent reference drop"));
        }
    }
    let mc = mc.cloned().unwrap_or_default();
    for (kind, count, limit) in [("image", ni, mc.max_images), ("video", nv, mc.max_videos), ("audio", na, mc.max_audios)] {
        if count > 0 && count > limit {
            return Some(if limit == 0 { format!("{label} does not support reference {kind} inputs; skipping to avoid silent {kind} drop") } else { format!("{label} supports at most {limit} reference {kind}(s), {count} requested; skipping") });
        }
    }
    if !req.options.is_empty() {
        if let Some(decl) = &mc.options {
            let keys: Vec<&String> = req.options.keys().collect();
            if decl.is_empty() {
                return Some(format!("{label} does not accept providerOptions (caller supplied: {}); skipping", keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")));
            }
            let unknown: Vec<&str> = keys.iter().filter(|k| !decl.iter().any(|(d, _)| *d == k.as_str())).map(|k| k.as_str()).collect();
            if !unknown.is_empty() {
                return Some(format!("{label} does not accept providerOptions keys: {} (accepted: {}); skipping", unknown.join(", "), decl.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")));
            }
            for (k, v) in &req.options {
                let want = decl.iter().find(|(d, _)| d == k).map(|x| x.1).unwrap_or("");
                let actual = match v {
                    Value::Number(_) => "number",
                    Value::Bool(_) => "boolean",
                    Value::String(_) => "string",
                    Value::Null => "undefined",
                    _ => "object",
                };
                let ok = match want {
                    "number" => v.as_f64().is_some_and(f64::is_finite),
                    "boolean" => v.is_boolean(),
                    "string" => v.is_string(),
                    _ => true,
                };
                if !ok {
                    let noun = match want {
                        "number" => "a finite number",
                        "boolean" => "a boolean",
                        _ => "a string",
                    };
                    return Some(format!("{label} expects providerOptions.{k} to be {noun}, got {actual}; skipping"));
                }
            }
        }
    }
    if let (Some(d), true, Some(max)) = (req.duration, mc.durations.is_empty(), mc.max_duration) {
        if d > max {
            return Some(format!("{label} supports at most {max}s per video, {d}s requested; skipping"));
        }
    }
    None
}

/// What one successful run produced, plus notes for the caller.
#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub provider: String,
    pub result: VideoResult,
    pub notes: Vec<String>,
    pub attempts: Vec<Attempt>,
    pub duration: Option<u32>,
    pub aspect_ratio: Option<String>,
}

/// Try candidates in order (OpenClaw `runVideoGeneration`).
pub fn generate(m: &Media, base: &VideoRequest, cands: &[(Arc<dyn VideoProvider>, String)], cancel: &Cancel) -> Result<RunResult, String> {
    let mut attempts: Vec<Attempt> = Vec::new();
    for (p, model) in cands {
        let label = format!("{}/{model}", p.id());
        let caps = p.caps(model);
        if let Some(why) = capability_mismatch(&label, &caps, base) {
            attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: why });
            continue;
        }
        let (_, mc) = mode_caps(&caps, base);
        let mc = mc.cloned().unwrap_or_default();
        let g = genrt::normalize_geometry(base.size.as_deref(), base.aspect_ratio.as_deref(), base.resolution.as_deref(), &mc.geometry(), true, true);
        let mut notes = genrt::geometry_notes(&g);
        let mut req = base.clone();
        req.model = model.clone();
        req.size = g.size;
        req.aspect_ratio = g.aspect_ratio;
        req.resolution = g.resolution;
        if let Some(a) = req.audio.filter(|_| !mc.supports_audio) {
            notes.push(format!("ignored unsupported audio={a}"));
            req.audio = None;
        }
        if let Some(w) = req.watermark.filter(|_| !mc.supports_watermark) {
            notes.push(format!("ignored unsupported watermark={w}"));
            req.watermark = None;
        }
        if let (Some(d), false) = (req.duration, mc.durations.is_empty()) {
            let s = snap_duration(d, &mc.durations);
            if s != d {
                notes.push(format!("durationSeconds {d} → {s} (closest supported)"));
            }
            req.duration = Some(s);
        }
        if req.timeout.is_zero() {
            req.timeout = p.default_timeout();
        }
        match p.generate(m, &req, cancel) {
            Ok(r) if r.videos.is_empty() => attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: "Video generation provider returned no videos.".into() }),
            Ok(r) => {
                if let Some(i) = r.videos.iter().position(|v| v.bytes.is_empty() && v.url.is_none()) {
                    attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: format!("Video generation provider returned an undeliverable asset at index {i}: neither buffer nor url is set.") });
                    continue;
                }
                return Ok(RunResult { provider: p.id().into(), result: r, notes, attempts, duration: req.duration, aspect_ratio: req.aspect_ratio });
            }
            Err(e) => attempts.push(Attempt { provider: p.id().into(), model: model.clone(), error: e }),
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    Err(genrt::failure("video-generation", &attempts))
}

// ---------------------------------------------------------------- tool

pub struct VideoGenerate {
    pub m: Arc<Media>,
}

const MAX_REFS: (usize, usize, usize) = (9, 4, 3);

fn roles(input: &Value, key: &str, n: usize) -> Result<Vec<String>, String> {
    let Some(v) = genrt::arg_val(input, key) else { return Ok(vec![]) };
    let a = v.as_array().ok_or_else(|| format!("{key} must be a JSON array of role strings, parallel to the reference list."))?;
    let r: Vec<String> = a.iter().map(|x| x.as_str().unwrap_or("").trim().to_string()).collect();
    if r.len() > n {
        let kind = key.trim_end_matches("Roles");
        return Err(format!("{key} has {} entries but only {n} reference {kind}{} were provided; extra roles cannot be aligned positionally.", r.len(), if n == 1 { "" } else { "s" }));
    }
    Ok(r)
}

/// Normalize "720p" → "720P" (OpenClaw `normalizeResolution`).
fn norm_resolution(r: &str) -> String {
    let u = r.trim().to_ascii_uppercase();
    let digits = u.trim_end_matches(['P', 'K']);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) && u.len() > digits.len() {
        u
    } else {
        r.trim().to_string()
    }
}

impl VideoGenerate {
    fn refs(input: &Value) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut images = genrt::str_list(input, &["image", "images", "image_url"]);
        for r in genrt::str_list(input, &["reference_image_urls"]) {
            images.push(r);
        }
        (images, genrt::str_list(input, &["video", "videos"]), genrt::str_list(input, &["audioRef", "audioRefs", "audio_ref", "audio_refs"]))
    }

    pub fn build(&self, ctx: &ToolCtx, input: &Value) -> Result<VideoRequest, String> {
        let m = &self.m;
        let prompt = arg_opt_str(input, "prompt").unwrap_or("").trim().to_string();
        if prompt.is_empty() {
            return Err("prompt is required for video generation".into());
        }
        if input.get("operation").is_some() || input.get("video_url").is_some() {
            return Err("video_generate only supports text-to-video, image-to-video, and reference-to-video; use a provider-specific tool for video edit/extend".into());
        }
        let (imgs, vids, auds) = Self::refs(input);
        for (kind, list, max) in [("images", &imgs, MAX_REFS.0), ("videos", &vids, MAX_REFS.1), ("audioRefs", &auds, MAX_REFS.2)] {
            if list.len() > max {
                return Err(format!("Too many reference {kind}: {} provided, maximum is {max}.", list.len()));
            }
        }
        let mut image_roles = roles(input, "imageRoles", imgs.len())?;
        // Hermes `reference_image_urls` are reference images by definition.
        let n_hermes_refs = genrt::str_list(input, &["reference_image_urls"]).len();
        if n_hermes_refs > 0 {
            image_roles.resize(imgs.len() - n_hermes_refs, String::new());
            image_roles.extend(std::iter::repeat_n("reference_image".to_string(), n_hermes_refs));
        }
        let video_roles = roles(input, "videoRoles", vids.len())?;
        let audio_roles = roles(input, "audioRoles", auds.len())?;
        let max_in = m.cfg.int_or("video.max_input_bytes", 50 * 1024 * 1024) as usize;
        let images = genrt::load_sources(m, ctx, &imgs, &image_roles, max_in)?;
        let videos = genrt::load_sources(m, ctx, &vids, &video_roles, max_in)?;
        let audios = genrt::load_sources(m, ctx, &auds, &audio_roles, max_in)?;
        for (kind, list) in [("image", &images), ("video", &videos), ("audio", &audios)] {
            if let Some(s) = list.iter().find(|s| store::class_of(&s.asset.mime) != kind && s.asset.mime != "application/octet-stream") {
                return Err(format!("reference {kind} input is not a {kind} ({})", s.asset.mime));
            }
        }
        let options = match genrt::arg_val(input, "providerOptions") {
            None => Map::new(),
            Some(Value::Object(o)) => o.clone(),
            Some(_) => return Err("providerOptions must be a JSON object keyed by provider-specific option name.".into()),
        };
        let duration = match genrt::arg_int(input, "durationSeconds")?.or(genrt::arg_int(input, "duration")?) {
            Some(d) if d < 1 => return Err("durationSeconds must be a positive integer".into()),
            Some(d) => Some(d as u32),
            None => None,
        };
        let aspect = genrt::arg(input, "aspectRatio").map(genrt::hermes_aspect);
        let timeout = match genrt::arg_int(input, "timeoutMs")? {
            Some(t) if t > 0 => Duration::from_millis(t as u64),
            _ => Duration::from_secs(m.cfg.int_or("video.timeout_secs", 0).max(0) as u64),
        };
        Ok(VideoRequest {
            prompt,
            model: String::new(),
            explicit_model: genrt::arg(input, "model").is_some(),
            size: genrt::arg(input, "size").map(str::to_string),
            aspect_ratio: aspect,
            resolution: genrt::arg(input, "resolution").map(norm_resolution),
            duration,
            audio: genrt::arg_bool(input, "audio"),
            watermark: genrt::arg_bool(input, "watermark"),
            negative_prompt: genrt::arg(input, "negativePrompt").map(str::to_string),
            seed: genrt::arg_int(input, "seed")?,
            upscale: genrt::arg_bool(input, "upscale"),
            images,
            videos,
            audios,
            options,
            timeout,
        })
    }

    fn list(&self) -> String {
        let m = &self.m;
        let active = m.cfg.str_or("video.provider", "auto");
        let mut lines = vec!["Video generation providers (✓ = configured):".to_string()];
        for p in providers() {
            let model = p.default_model();
            let caps = p.caps(&model);
            let mut modes = vec!["text-to-video"];
            if caps.i2v.enabled {
                modes.push("image-to-video");
            }
            if caps.v2v.enabled {
                modes.push("video-to-video");
            }
            let g = &caps.generate;
            let mut c = vec![modes.join("/")];
            if let Some(d) = g.max_duration {
                c.push(format!("≤{d}s"));
            }
            if !g.durations.is_empty() {
                c.push(format!("durations {}", g.durations.iter().map(|d| d.to_string()).collect::<Vec<_>>().join("/")));
            }
            if !g.aspect_ratios.is_empty() {
                c.push(format!("aspect ratios {}", g.aspect_ratios.join(", ")));
            }
            if !g.resolutions.is_empty() {
                c.push(format!("resolutions {}", g.resolutions.join("/")));
            }
            if g.supports_audio {
                c.push("audio".into());
            }
            if let Some(o) = &g.options {
                if !o.is_empty() {
                    c.push(format!("providerOptions {}", o.iter().map(|(k, t)| format!("{k}:{t}")).collect::<Vec<_>>().join(", ")));
                }
            }
            let auth = if p.configured(m) {
                "✓".to_string()
            } else if p.env().is_empty() {
                format!("✗ (configure [media.providers.{}])", p.id())
            } else {
                format!("✗ set {}", p.env().join(" or "))
            };
            lines.push(format!("- {} ({}) {auth}{}\n  default model: {model}\n  models: {}\n  {}", p.id(), p.label(), if active == p.id() { " [selected]" } else { "" }, p.models().join(", "), c.join("; ")));
        }
        lines.join("\n")
    }

    fn effects_for(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut fx = Vec::new();
        let (i, v, a) = Self::refs(input);
        for r in i.iter().chain(v.iter()).chain(a.iter()) {
            if !(r.starts_with("http://") || r.starts_with("https://") || r.starts_with("data:")) {
                fx.push(Effect::Read { path: store::resolve(r, &ctx.workspace) });
            }
        }
        let list = providers();
        if let Ok(c) = genrt::candidates(&self.m, "video", &list, arg_opt_str(input, "provider"), genrt::arg(input, "model")) {
            if let Some((p, _)) = c.first() {
                fx.push(Effect::Net { dest: crate::http::host_of(&p.creds(&self.m).base), payload: arg_opt_str(input, "prompt").unwrap_or("").to_string() });
            }
        }
        fx.push(Effect::Write { path: self.m.out_dir(ctx, "videos") });
        fx
    }
}

/// Save (or keep as URL) every generated video; returns the JSON result + MEDIA lines.
pub(crate) fn deliver(m: &Media, ctx_ws: &std::path::Path, out_dir: PathBuf, prompt: &str, filename: Option<&str>, run: RunResult, modality: &str) -> Result<String, String> {
    let max = m.cfg.int_or("video.max_bytes", 200 * 1024 * 1024) as usize;
    let _ = ctx_ws;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut notes = run.notes.clone();
    let base = filename.map(|f| {
        let f = f.rsplit('/').next().unwrap_or(f);
        f.rsplit_once('.').map(|(s, _)| s).unwrap_or(f).to_string()
    });
    let n = run.result.videos.len();
    for (i, v) in run.result.videos.iter().enumerate() {
        let mut v = v.clone();
        if v.bytes.is_empty() {
            if let Some(u) = v.url.clone() {
                match genrt::fetch_asset(m, &u, &[], "video/mp4") {
                    Ok(a) if a.bytes.len() <= max => v = a,
                    Ok(_) => notes.push(format!("video {} exceeds {max} bytes; delivering the provider URL", i + 1)),
                    Err(e) => notes.push(format!("could not cache {u}: {e}")),
                }
            }
        }
        if v.bytes.is_empty() || v.bytes.len() > max {
            if let Some(u) = &v.url {
                urls.push(u.clone());
                continue;
            }
            return Err(format!("generated video {} exceeds {max} bytes and has no URL", i + 1));
        }
        if !v.mime.starts_with("video/") && store::sniff(&v.bytes).starts_with("video/") {
            v.mime = store::sniff(&v.bytes).to_string();
        }
        let stem = match &base {
            Some(b) if n > 1 => format!("{b}-{}", i + 1),
            Some(b) => b.clone(),
            None => format!("{}-{}", store::stem(&format!("{}-video", run.provider)), i + 1),
        };
        paths.push(store::save(&out_dir, &stem, &v)?);
    }
    let first = paths.first().map(|p| p.display().to_string()).or_else(|| urls.first().cloned());
    let public = run.result.videos.iter().find_map(|v| v.url.clone());
    let out = json!({
        "success": true,
        "provider": run.provider,
        "model": run.result.model,
        "prompt": prompt,
        "modality": modality,
        "video": first,
        "videos": paths.iter().map(|p| p.display().to_string()).chain(urls.iter().cloned()).collect::<Vec<_>>(),
        "public_url": public,
        "duration": run.duration,
        "aspect_ratio": run.aspect_ratio,
        "metadata": run.result.meta,
        "notes": notes,
        "attempts": if run.attempts.is_empty() { Value::Null } else { json!(run.attempts.iter().map(|a| json!({"provider": a.provider, "model": a.model, "error": a.error})).collect::<Vec<_>>()) },
    });
    let mut text = serde_json::to_string_pretty(&out).unwrap_or_default();
    if !paths.is_empty() {
        text.push('\n');
        text.push_str(&store::media_tags(&paths, false));
    }
    Ok(text)
}

fn modality(req: &VideoRequest) -> &'static str {
    if !req.videos.is_empty() {
        "video"
    } else if req.images.iter().any(|s| s.role.as_deref() == Some("reference_image")) {
        "reference"
    } else if !req.images.is_empty() {
        "image"
    } else {
        "text"
    }
}

impl VideoGenerate {
    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let m = self.m.clone();
        let req = self.build(ctx, input)?;
        let list = providers();
        let cands = genrt::candidates(&m, "video", &list, arg_opt_str(input, "provider"), genrt::arg(input, "model"))?;
        let filename = genrt::arg(input, "filename").map(str::to_string);
        let out_dir = m.out_dir(ctx, "videos");
        let ws = ctx.workspace.clone();
        let background = genrt::arg_bool(input, "background").unwrap_or_else(|| m.cfg.bool_or("video.background", false));
        if background {
            let key = genrt::request_key("video_generate", input);
            if let Some(j) = genrt::find_duplicate("video", &ctx.session_id, &key) {
                return Ok(format!("Video generation task {} is already running for this request ({}). Wait for its result instead of starting another; use action=status to check it.", j.id, j.progress));
            }
            let prompt = req.prompt.clone();
            let id = genrt::spawn_job("video", ctx, &prompt, &key, move |cancel, prog| {
                prog.set(&format!("Generating video with {}", cands[0].0.id()));
                let r = generate(&m, &req, &cands, cancel)?;
                prog.set("Saving generated video");
                deliver(&m, &ws, out_dir, &req.prompt, filename.as_deref(), r, modality(&req))
            });
            return Ok(format!("Started video generation task {id} in the background. The video is delivered in a later message when it is ready; do not poll. Reply with a short acknowledgement and end this turn (action=status shows progress)."));
        }
        ctx.host.progress(&format!("generating video with {}…", cands[0].0.id()));
        let r = generate(&m, &req, &cands, &ctx.cancel)?;
        deliver(&m, &ws, out_dir, &req.prompt, filename.as_deref(), r, modality(&req))
    }
}

fn err_json(e: &str) -> String {
    let kind = if e.starts_with("No video-generation provider") { "no_provider_configured" } else if e.contains("is required") || e.contains("must be") || e.contains("Too many") { "invalid_request" } else { "provider_error" };
    json!({"success": false, "video": null, "error": e, "error_type": kind}).to_string()
}

impl Tool for VideoGenerate {
    fn spec(&self) -> ToolSpec {
        let s = |d: &str| json!({"type": "string", "description": d});
        let arr = |d: &str| json!({"type": "array", "items": {"type": "string"}, "description": d});
        ToolSpec {
            name: "video_generate".into(),
            description: "Generate a video from a text prompt (text-to-video), animate a still image (image-to-video: `image`/`image_url`, roles first_frame/last_frame/reference_image via `imageRoles`), guide it with reference images (`reference_image_urls`), or condition on reference videos/audio. Saves the file and returns its path with a MEDIA: line (keep it in your reply so the chat delivers it). Geometry: `aspect_ratio` (16:9, 9:16, 1:1, …), `size` (WxH) or `resolution` (480P–1080P, 4K); unsupported values are normalized or ignored and reported. `durationSeconds` snaps to the provider's supported values. Generation may take 30 s to several minutes (call blocks unless background=true). `action=list` shows providers, models and readiness; `action=status` shows background tasks. Video edit/extend: use xai_video_edit / xai_video_extend.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["generate", "list", "status"], "description": "\"generate\" (default), \"status\" background tasks, \"list\" providers/models"},
                    "prompt": s("Text instruction describing the desired video: motion, subject, style, camera movement."),
                    "image": s("One reference image path/URL (image-to-video)."),
                    "image_url": s("Hermes alias of `image`: public URL or local path of a still image to animate."),
                    "images": arr("Reference images; max 9."),
                    "imageRoles": arr("`image` + `images` roles by index: first_frame, last_frame, reference_image; empty string leaves unset."),
                    "reference_image_urls": arr("Reference images for reference-to-video (style/character refs)."),
                    "video": s("One reference video path/URL."),
                    "videos": arr("Reference videos; max 4."),
                    "videoRoles": arr("`video` + `videos` roles by index: reference_video."),
                    "audioRef": s("One reference audio path/URL, e.g. music."),
                    "audioRefs": arr("Reference audios; max 3."),
                    "audioRoles": arr("`audioRef` + `audioRefs` roles by index: reference_audio."),
                    "model": s("Provider/model override, e.g. qwen/wan2.6-t2v, fal/veo3.1, google/veo-3.1-fast-generate-preview."),
                    "provider": s("Provider id override (see action=list)."),
                    "filename": s("Output filename hint (basename kept)."),
                    "size": s("Size hint, e.g. 1280x720, 1920x1080."),
                    "aspect_ratio": s("Aspect ratio: 16:9, 9:16, 1:1, 4:3, 3:4, 21:9 (landscape/portrait/square accepted)."),
                    "resolution": s("Resolution: 360P, 480P, 540P, 720P, 768P, 1080P, 4K."),
                    "durationSeconds": {"type": "integer", "minimum": 1, "description": "Target seconds; may round to the nearest supported duration."},
                    "duration": {"type": "integer", "minimum": 1, "description": "Hermes alias of durationSeconds."},
                    "audio": {"type": "boolean", "description": "Generated-audio toggle (where supported)."},
                    "watermark": {"type": "boolean", "description": "Watermark toggle (where supported)."},
                    "negative_prompt": s("Content to avoid (where supported)."),
                    "seed": {"type": "integer", "description": "Seed for reproducible outputs (where supported)."},
                    "upscale": {"type": "boolean", "description": "fal: SeedVR2 ~2x upscale pass after generation (extra cost/latency)."},
                    "providerOptions": {"type": "object", "description": "Provider JSON options, e.g. {\"seed\":42}; keys/types must match the provider (action=list), a mismatch skips that candidate."},
                    "timeoutMs": {"type": "integer", "minimum": 1, "description": "Provider timeout in ms."},
                    "background": {"type": "boolean", "description": "Return a task id immediately; the video arrives as a later message."}
                }
            }),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match arg_opt_str(input, "action").unwrap_or("generate") {
            "list" | "status" => vec![],
            _ => self.effects_for(ctx, input),
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match arg_opt_str(&input, "action").unwrap_or("generate") {
            "list" => ToolOutput::ok(self.list()),
            "status" => ToolOutput::ok(genrt::status_text("video", &ctx.session_id, arg_opt_str(&input, "job_id").or(arg_opt_str(&input, "taskId"))).0),
            "generate" => match self.run(ctx, &input) {
                Ok(t) => ToolOutput::ok(t),
                Err(e) => ToolOutput::err(err_json(&e)),
            },
            other => ToolOutput::err(format!("unknown action `{other}` (generate, list, status)")),
        }
    }
}

// ---------------------------------------------------------------- xAI edit / extend

/// `xai_video_edit` / `xai_video_extend` (Hermes `tools/xai_video_tools.py`).
pub struct XaiVideoOp {
    pub m: Arc<Media>,
    pub extend: bool,
}

impl Tool for XaiVideoOp {
    fn spec(&self) -> ToolSpec {
        let (name, verb, noun, pv) = if self.extend { ("xai_video_extend", "Extend", "extension", "continue") } else { ("xai_video_edit", "Edit", "editing", "modify") };
        let mut props = json!({
            "prompt": {"type": "string", "description": format!("Instruction for how xAI should {pv} the source video.")},
            "video_url": {"type": "string", "description": "Public HTTPS MP4 URL of the source video — the `video` or `public_url` from a prior xAI Imagine result."}
        });
        if self.extend {
            props["duration"] = json!({"type": "integer", "description": "Desired extension duration in seconds. xAI clamps this to its supported range."});
        }
        ToolSpec {
            name: name.into(),
            description: format!("{verb} an existing video with xAI Imagine. This is separate from `video_generate` because video {noun} is provider-specific. `video_url` must be the public HTTPS MP4 URL from a prior Imagine result (`video` or `public_url` on files-cdn)."),
            input_schema: json!({"type": "object", "properties": props, "required": ["prompt", "video_url"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        vec![Effect::Net { dest: crate::http::host_of(&hosted::Xai.creds(&self.m).base), payload: arg_opt_str(input, "prompt").unwrap_or("").to_string() }, Effect::Write { path: self.m.out_dir(ctx, "videos") }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let op = if self.extend { "extend" } else { "edit" };
        let prompt = arg_opt_str(&input, "prompt").map(str::trim).unwrap_or("");
        let url = arg_opt_str(&input, "video_url").map(str::trim).unwrap_or("");
        if prompt.is_empty() {
            return ToolOutput::err(json!({"success": false, "error": format!("prompt is required for xAI video {op}")}).to_string());
        }
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return ToolOutput::err(json!({"success": false, "error": "video_url must be a public HTTPS MP4 URL (the `video`/`public_url` from a prior Imagine result)"}).to_string());
        }
        if !xai_selected(&self.m) {
            return ToolOutput::err(json!({"success": false, "error": "xAI video edit/extend tools require `[media.video] provider = \"xai\"`.", "error_type": "provider_not_configured", "provider": "xai"}).to_string());
        }
        // Bools never become durations (Hermes `_coerce_int`).
        let duration = input.get("duration").filter(|v| !v.is_boolean()).and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())));
        let r = hosted::xai_mutate(&self.m, prompt, url, self.extend, duration, &ctx.cancel).and_then(|r| deliver(&self.m, &ctx.workspace, self.m.out_dir(ctx, "videos"), prompt, None, r, op));
        match r {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(json!({"success": false, "video": null, "error": e, "error_type": "api_error", "provider": "xai"}).to_string()),
        }
    }
}

fn xai_selected(m: &Media) -> bool {
    m.cfg.str("video.provider").as_deref() == Some("xai") && hosted::Xai.configured(m)
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = vec![Arc::new(VideoGenerate { m: m.clone() })];
    // Hermes registers the edit/extend tools only when xAI is the selected video backend.
    if xai_selected(m) {
        v.push(Arc::new(XaiVideoOp { m: m.clone(), extend: false }));
        v.push(Arc::new(XaiVideoOp { m: m.clone(), extend: true }));
    }
    v
}

#[cfg(test)]
mod tests;
