//! Image generation: the `image_generate` tool and its providers (Hermes
//! `plugins/image_gen/*` + `tools/image_generation_tool.py`, OpenClaw
//! `src/image-generation/*` + `extensions/*/image-generation-provider.ts`).
//!
//! Providers: fal, openai (incl. Azure OpenAI), openai-codex (ChatGPT/Codex OAuth),
//! google (Gemini image + Imagen), xai, openrouter, deepinfra, litellm, meta-ai,
//! minimax, microsoft-foundry (MAI), krea, comfy (ComfyUI local/cloud), vydra.
//!
//! Config (`[media.image]`, defaults shown):
//! ```toml
//! [media.image]
//! provider = "auto"        # provider id, or "auto" = first configured (fal, openai, google, xai, …)
//! model = ""               # "provider/model" or a model id for `provider`; "" = provider default
//! fallback = []            # extra "provider/model" candidates tried in order after a failure
//! timeout_secs = 300       # per provider call
//! max_bytes = 20971520     # saved images larger than this are re-encoded as JPEG to fit
//! max_input_bytes = 26214400 # largest reference image accepted
//! poll_ms = 0              # async-job poll interval override (0 = provider default)
//! ```
//! Credentials: `[media.providers.<id>] api_key / base_url / headers` or each provider's env vars.
//! Provider-specific keys (`[media.providers.<id>]`): fal `queue = true`, `upscale = false`;
//! openai `azure_api_version = "2024-12-01-preview"`; openai-codex `transport = "images"|"responses"`,
//! `auth_file = "~/.codex/auth.json"`; xai `resolution = "1k"`; krea `creativity = "medium"`,
//! `upscale = false`; comfy `mode = "local"|"cloud"`, `workflow_path`, `workflow` (inline JSON),
//! `prompt_node_id`, `prompt_input_name = "text"`, `input_image_node_id`, `input_image_input_name = "image"`,
//! `seed_node_id`, `seed_input_name = "seed"`, `output_node_id`; microsoft-foundry `base_url` = resource endpoint.

mod catalog;
mod comfy;
mod common;
mod compat;
mod fal;
mod foundry;
mod google;
mod krea;
mod minimax;
mod openai;
mod openrouter;
mod vydra;
mod xai;

pub use comfy::run_workflow as run_comfy_workflow;

use crate::store::{self, Asset};
use crate::Media;
use ark_core::tool::{arg_opt_str, arg_opt_u64};
use ark_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A reference image for editing / style transfer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InputImage {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub name: String,
    /// The original remote URL, when the caller passed one (some APIs take URLs directly).
    pub url: Option<String>,
}

impl InputImage {
    pub fn data_url(&self) -> String {
        store::data_url(&self.mime, &self.bytes)
    }
    /// Remote URL when available, else an inline data URL.
    pub fn url_or_data(&self) -> String {
        self.url.clone().unwrap_or_else(|| self.data_url())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImageRequest {
    pub prompt: String,
    /// Provider-local model id; `None` = provider default.
    pub model: Option<String>,
    pub count: u32,
    /// `WIDTHxHEIGHT` or "auto".
    pub size: Option<String>,
    /// Ratio such as "16:9".
    pub aspect_ratio: Option<String>,
    /// Hermes semantic aspect: "landscape" | "square" | "portrait".
    pub semantic_aspect: String,
    /// "1K" | "2K" | "4K".
    pub resolution: Option<String>,
    pub quality: Option<String>,
    pub output_format: Option<String>,
    pub background: Option<String>,
    pub inputs: Vec<InputImage>,
    pub seed: Option<i64>,
    pub upscale: Option<bool>,
    /// Remaining provider options: `openai{…}`, `fal{creativity}`, krea sliders, steps…
    pub options: Value,
    pub timeout: Duration,
    pub poll: Option<Duration>,
}

impl Default for ImageRequest {
    fn default() -> Self {
        ImageRequest {
            prompt: String::new(),
            model: None,
            count: 1,
            size: None,
            aspect_ratio: None,
            semantic_aspect: "square".into(),
            resolution: None,
            quality: None,
            output_format: None,
            background: None,
            inputs: vec![],
            seed: None,
            upscale: None,
            options: json!({}),
            timeout: Duration::from_secs(300),
            poll: None,
        }
    }
}

impl ImageRequest {
    pub fn is_edit(&self) -> bool {
        !self.inputs.is_empty()
    }
    pub fn opt(&self, path: &str) -> Option<&Value> {
        let mut v = &self.options;
        for p in path.split('.') {
            v = v.get(p)?;
        }
        (!v.is_null()).then_some(v)
    }
    pub fn opt_str(&self, path: &str) -> Option<String> {
        self.opt(path).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
    }
    pub fn opt_i64(&self, path: &str) -> Option<i64> {
        self.opt(path).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
    }
    pub fn poll_or(&self, default_ms: u64) -> Duration {
        self.poll.unwrap_or(Duration::from_millis(default_ms))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageResult {
    pub images: Vec<Asset>,
    pub model: String,
    pub meta: Value,
}

/// What one provider/model accepts (OpenClaw `ImageGenerationProviderCapabilities`).
#[derive(Debug, Clone, PartialEq)]
pub struct Caps {
    pub max_count: u32,
    pub edit: bool,
    pub max_inputs: usize,
    pub supports_size: bool,
    pub supports_aspect: bool,
    pub supports_resolution: bool,
    /// Empty = any value accepted.
    pub sizes: Vec<&'static str>,
    pub aspect_ratios: Vec<&'static str>,
    pub resolutions: Vec<&'static str>,
    pub qualities: Vec<&'static str>,
    pub formats: Vec<&'static str>,
    pub backgrounds: Vec<&'static str>,
}

impl Default for Caps {
    fn default() -> Self {
        Caps { max_count: 1, edit: false, max_inputs: 0, supports_size: false, supports_aspect: false, supports_resolution: false, sizes: vec![], aspect_ratios: vec![], resolutions: vec![], qualities: vec![], formats: vec![], backgrounds: vec![] }
    }
}

pub trait ImageProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    /// Env vars holding the key (empty = none needed).
    fn env(&self) -> &'static [&'static str];
    fn default_base(&self) -> &'static str;
    fn default_model(&self, m: &Media) -> String;
    fn models(&self) -> Vec<String>;
    fn caps(&self, model: &str) -> Caps;
    fn configured(&self, m: &Media) -> bool {
        !self.env().is_empty() && m.cfg.configured(self.id(), self.env())
    }
    fn generate(&self, m: &Media, req: &ImageRequest, cancel: &Cancel) -> Result<ImageResult, String>;
}

/// Every built-in provider, in auto-selection order (FAL first, as Hermes defaults to it).
pub fn providers() -> Vec<Box<dyn ImageProvider>> {
    vec![
        Box::new(fal::Fal),
        Box::new(openai::OpenAi),
        Box::new(google::Google),
        Box::new(xai::Xai),
        Box::new(openrouter::OpenRouter),
        Box::new(krea::Krea),
        Box::new(compat::DeepInfra),
        Box::new(minimax::Minimax),
        Box::new(compat::MetaAi),
        Box::new(vydra::Vydra),
        Box::new(foundry::Foundry),
        Box::new(compat::Litellm),
        Box::new(openai::Codex),
        Box::new(comfy::Comfy),
    ]
}

pub fn provider(id: &str) -> Option<Box<dyn ImageProvider>> {
    let id = id.trim().to_ascii_lowercase();
    let id = match id.as_str() {
        "gemini" | "imagen" | "google-gemini" => "google",
        "grok" | "x-ai" => "xai",
        "codex" | "chatgpt" => "openai-codex",
        "meta" | "muse" => "meta-ai",
        "foundry" | "azure-foundry" | "mai" => "microsoft-foundry",
        "comfyui" => "comfy",
        "fal-ai" | "falai" => "fal",
        other => other,
    }
    .to_string();
    providers().into_iter().find(|p| p.id() == id)
}

/// One `(provider, model)` to try.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub provider: String,
    pub model: Option<String>,
}

fn split_ref(r: &str) -> (Option<String>, Option<String>) {
    let r = r.trim();
    if r.is_empty() {
        return (None, None);
    }
    if let Some((p, rest)) = r.split_once('/') {
        if provider(p).is_some() {
            return (Some(p.to_string()), Some(rest.to_string()).filter(|s| !s.is_empty()));
        }
    }
    (None, Some(r.to_string()))
}

/// Candidates in order: explicit `model`/`provider` args, then `[media.image] provider/model`,
/// then `fallback`; "auto" expands to every configured provider (OpenClaw runMediaGenerationCandidates).
pub fn candidates(m: &Media, provider_arg: Option<&str>, model_arg: Option<&str>) -> Result<Vec<Candidate>, String> {
    let mut out: Vec<Candidate> = Vec::new();
    let push = |c: Candidate, out: &mut Vec<Candidate>| {
        if !out.contains(&c) {
            out.push(c);
        }
    };
    let (mp, mm) = split_ref(model_arg.unwrap_or(""));
    let explicit_provider = provider_arg.map(str::to_string).filter(|s| !s.trim().is_empty() && s != "auto").or(mp);
    if let Some(p) = &explicit_provider {
        let pv = provider(p).ok_or_else(|| format!("unknown image provider `{p}` (known: {})", providers().iter().map(|p| p.id()).collect::<Vec<_>>().join(", ")))?;
        push(Candidate { provider: pv.id().into(), model: mm.clone() }, &mut out);
        return Ok(out);
    }
    let cfg_provider = m.cfg.str_or("image.provider", "auto");
    let (cp, cm) = split_ref(&m.cfg.str_or("image.model", ""));
    let model = mm.or(cm);
    let primary = cp.unwrap_or(cfg_provider);
    if primary != "auto" {
        let pv = provider(&primary).ok_or_else(|| format!("[media.image] provider `{primary}` is not a known image provider"))?;
        push(Candidate { provider: pv.id().into(), model: model.clone() }, &mut out);
    }
    for f in m.cfg.list("image.fallback") {
        let (fp, fm) = split_ref(&f);
        if let Some(pv) = fp.as_deref().and_then(provider) {
            push(Candidate { provider: pv.id().into(), model: fm }, &mut out);
        }
    }
    if primary == "auto" {
        for p in providers() {
            if p.configured(m) {
                push(Candidate { provider: p.id().into(), model: model.clone().filter(|_| out.is_empty()) }, &mut out);
            }
        }
    }
    if out.is_empty() {
        return Err(no_backend_message(m));
    }
    Ok(out)
}

fn no_backend_message(m: &Media) -> String {
    let _ = m;
    let mut s = String::from("Image generation is unavailable: no image provider is configured.\n\nTo enable it, do one of:\n");
    s.push_str("  1. Get a key at https://fal.ai and set FAL_KEY (or [media.providers.fal] api_key)\n");
    s.push_str("  2. Set OPENAI_API_KEY, GEMINI_API_KEY, XAI_API_KEY, OPENROUTER_API_KEY, KREA_API_KEY, DEEPINFRA_API_KEY, MINIMAX_API_KEY, META_MODEL_API_KEY or VYDRA_API_KEY\n");
    s.push_str("  3. Sign in to Codex (~/.codex/auth.json) for openai-codex, or configure [media.providers.comfy] with a workflow for a local ComfyUI\n");
    s.push_str("Pick one with [media.image] provider = \"<id>\".");
    s
}

/// Closest of `ratios` to `w:h` in log space.
pub fn closest_ratio(w: f64, h: f64, ratios: &[&'static str]) -> Option<&'static str> {
    let target = (w / h).ln();
    ratios.iter().copied().filter_map(|r| parse_ratio(r).map(|(a, b)| (r, ((a / b).ln() - target).abs()))).min_by(|a, b| a.1.total_cmp(&b.1)).map(|x| x.0)
}

pub fn parse_ratio(r: &str) -> Option<(f64, f64)> {
    let (a, b) = r.trim().split_once(':')?;
    let (a, b): (f64, f64) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (a > 0.0 && b > 0.0).then_some((a, b))
}

pub fn parse_size(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.trim().to_ascii_lowercase().split_once('x').map(|(a, b)| (a.to_string(), b.to_string()))?;
    let (w, h): (u32, u32) = (w.parse().ok()?, h.parse().ok()?);
    (w >= 10 && h >= 10 && w <= 99_999 && h <= 99_999).then_some((w, h))
}

/// Hermes semantic aspect from a ratio.
pub fn semantic_of(ratio: Option<&str>) -> &'static str {
    match ratio.and_then(parse_ratio) {
        Some((w, h)) if (w / h) > 1.05 => "landscape",
        Some((w, h)) if (w / h) < 0.95 => "portrait",
        _ => "square",
    }
}

/// `landscape|square|portrait` → ratio; ratios pass through.
pub fn ratio_of_semantic(a: &str) -> String {
    match a.trim().to_ascii_lowercase().as_str() {
        "landscape" | "wide" => "16:9".into(),
        "portrait" | "tall" => "9:16".into(),
        "square" => "1:1".into(),
        other => other.to_string(),
    }
}

/// Drop or translate geometry/output overrides a provider cannot honour (OpenClaw
/// `resolveMediaGeometryOverrides` + output filtering); returns notes on what changed.
pub fn sanitize(req: &mut ImageRequest, caps: &Caps) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(sz) = req.size.clone() {
        let ok = caps.supports_size && (caps.sizes.is_empty() || caps.sizes.contains(&sz.as_str()) || sz == "auto");
        if !ok {
            if caps.supports_size && !caps.sizes.is_empty() {
                if let Some((w, h)) = parse_size(&sz) {
                    let best = caps.sizes.iter().copied().filter_map(|s| parse_size(s).map(|(a, b)| (s, ((a as f64 / b as f64).ln() - (w as f64 / h as f64).ln()).abs() + ((a * b) as f64 - (w * h) as f64).abs() / 1e8))).min_by(|a, b| a.1.total_cmp(&b.1)).map(|x| x.0);
                    if let Some(b) = best {
                        notes.push(format!("size {sz} normalized to {b}"));
                        req.size = Some(b.into());
                    }
                }
            } else {
                if caps.supports_aspect && req.aspect_ratio.is_none() {
                    if let Some((w, h)) = parse_size(&sz) {
                        let ratios: Vec<&'static str> = if caps.aspect_ratios.is_empty() { vec!["1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3"] } else { caps.aspect_ratios.clone() };
                        if let Some(r) = closest_ratio(w as f64, h as f64, &ratios) {
                            notes.push(format!("size {sz} mapped to aspect ratio {r}"));
                            req.aspect_ratio = Some(r.into());
                        }
                    }
                } else {
                    notes.push(format!("ignored unsupported size {sz}"));
                }
                req.size = None;
            }
        }
    }
    if let Some(ar) = req.aspect_ratio.clone() {
        let ok = caps.supports_aspect && (caps.aspect_ratios.is_empty() || caps.aspect_ratios.contains(&ar.as_str()));
        if !ok {
            req.aspect_ratio = None;
            if caps.supports_aspect && !caps.aspect_ratios.is_empty() {
                if let Some((w, h)) = parse_ratio(&ar) {
                    if let Some(r) = closest_ratio(w, h, &caps.aspect_ratios) {
                        notes.push(format!("aspect ratio {ar} normalized to {r}"));
                        req.aspect_ratio = Some(r.into());
                    }
                }
            } else if caps.supports_size && req.size.is_none() {
                if let Some((w, h)) = parse_ratio(&ar) {
                    let sizes: Vec<&'static str> = if caps.sizes.is_empty() { vec!["1024x1024", "1536x1024", "1024x1536"] } else { caps.sizes.clone() };
                    let best = sizes.iter().copied().filter_map(|s| parse_size(s).map(|(a, b)| (s, ((a as f64 / b as f64).ln() - (w / h).ln()).abs()))).min_by(|a, b| a.1.total_cmp(&b.1)).map(|x| x.0);
                    if let Some(b) = best {
                        notes.push(format!("aspect ratio {ar} mapped to size {b}"));
                        req.size = Some(b.into());
                    }
                }
            } else {
                notes.push(format!("ignored unsupported aspect ratio {ar}"));
            }
        }
    }
    if let Some(r) = req.resolution.clone() {
        if !caps.supports_resolution || (!caps.resolutions.is_empty() && !caps.resolutions.contains(&r.as_str())) {
            notes.push(format!("ignored unsupported resolution {r}"));
            req.resolution = None;
        }
    }
    for (name, field, allowed) in [("quality", &mut req.quality, &caps.qualities), ("output format", &mut req.output_format, &caps.formats), ("background", &mut req.background, &caps.backgrounds)] {
        if let Some(v) = field.clone() {
            if !allowed.contains(&v.as_str()) {
                notes.push(format!("ignored unsupported {name} {v}"));
                *field = None;
            }
        }
    }
    if req.count > caps.max_count.max(1) {
        notes.push(format!("count {} clamped to {}", req.count, caps.max_count.max(1)));
        req.count = caps.max_count.max(1);
    }
    notes
}

/// Run the candidates in order until one succeeds; returns `(provider, result, notes, attempts)`.
pub fn generate(m: &Media, base: &ImageRequest, cands: &[Candidate], cancel: &Cancel) -> Result<(String, ImageResult, Vec<String>, Vec<Value>), String> {
    let mut attempts = Vec::new();
    let mut last = String::new();
    for c in cands {
        if cancel.is_cancelled() {
            return Err("cancelled".into());
        }
        let Some(p) = provider(&c.provider) else { continue };
        let mut req = base.clone();
        req.model = c.model.clone().or_else(|| Some(p.default_model(m)).filter(|s| !s.is_empty()));
        let model = req.model.clone().unwrap_or_default();
        let caps = p.caps(&model);
        if req.is_edit() && !caps.edit {
            let e = format!("{}/{model} does not support image editing / reference images", p.id());
            attempts.push(json!({"provider": p.id(), "model": model, "error": e}));
            last = e;
            continue;
        }
        if req.is_edit() && caps.max_inputs > 0 && req.inputs.len() > caps.max_inputs {
            let e = format!("{}/{model} supports at most {} reference image(s) (got {})", p.id(), caps.max_inputs, req.inputs.len());
            attempts.push(json!({"provider": p.id(), "model": model, "error": e}));
            last = e;
            continue;
        }
        if !p.configured(m) {
            let how = if p.env().is_empty() { format!("configure [media.providers.{}]", p.id()) } else { format!("set {} or [media.providers.{}] api_key", p.env().join(" / "), p.id()) };
            let e = format!("{} is not configured ({how})", p.id());
            attempts.push(json!({"provider": p.id(), "model": model, "error": e}));
            last = e;
            continue;
        }
        // Infer the resolution from the reference images when editing (OpenClaw).
        if req.resolution.is_none() && req.is_edit() && caps.supports_resolution {
            let max_dim = req.inputs.iter().filter_map(|i| image::ImageReader::new(std::io::Cursor::new(&i.bytes)).with_guessed_format().ok()?.into_dimensions().ok()).map(|(w, h)| w.max(h)).max().unwrap_or(0);
            let r = if max_dim >= 3000 { "4K" } else if max_dim >= 1500 { "2K" } else { "1K" };
            if caps.resolutions.is_empty() || caps.resolutions.contains(&r) {
                req.resolution = Some(r.into());
            }
        }
        let notes = sanitize(&mut req, &caps);
        match p.generate(m, &req, cancel) {
            Ok(mut r) if !r.images.is_empty() => {
                if let Some(i) = r.images.iter().position(|a| a.bytes.is_empty() && a.url.is_none()) {
                    last = format!("{} returned an empty image at index {i}", p.id());
                    attempts.push(json!({"provider": p.id(), "model": model, "error": last}));
                    continue;
                }
                if r.model.is_empty() {
                    r.model = model.clone();
                }
                attempts.push(json!({"provider": p.id(), "model": r.model, "ok": true}));
                return Ok((p.id().to_string(), r, notes, attempts));
            }
            Ok(_) => {
                last = format!("{} returned no images", p.id());
                attempts.push(json!({"provider": p.id(), "model": model, "error": last}));
            }
            Err(e) => {
                if e == "cancelled" {
                    return Err(e);
                }
                attempts.push(json!({"provider": p.id(), "model": model, "error": e}));
                last = format!("{}: {e}", p.id());
            }
        }
    }
    Err(if attempts.len() > 1 { format!("all image providers failed; last error: {last}") } else { last })
}

/// Re-encode images over `max_bytes` as JPEG (OpenClaw fitGeneratedImagesToMaxBytes).
pub fn fit_to_max_bytes(images: Vec<Asset>, max_bytes: usize) -> Result<(Vec<Asset>, Vec<String>), String> {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    for (i, a) in images.into_iter().enumerate() {
        if a.bytes.len() <= max_bytes || a.bytes.is_empty() {
            out.push(a);
            continue;
        }
        let img = image::load_from_memory(&a.bytes).map_err(|e| format!("generated image {} ({} bytes) exceeds the {max_bytes}-byte limit and could not be decoded: {e}", i + 1, a.bytes.len()))?;
        let mut cur = img.to_rgb8();
        let mut done = None;
        for _ in 0..8 {
            for q in [90u8, 80, 70, 60, 50] {
                let mut buf = Vec::new();
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, q).encode_image(&cur).map_err(|e| e.to_string())?;
                if buf.len() <= max_bytes {
                    done = Some(buf);
                    break;
                }
            }
            if done.is_some() {
                break;
            }
            let (w, h) = (cur.width() * 3 / 4, cur.height() * 3 / 4);
            if w < 64 || h < 64 {
                break;
            }
            cur = image::imageops::resize(&cur, w, h, image::imageops::FilterType::Triangle);
        }
        let buf = done.ok_or_else(|| format!("generated image {} exceeds the {max_bytes}-byte limit even after re-encoding", i + 1))?;
        notes.push(format!("generated image {} ({} bytes) exceeded the {max_bytes}-byte limit; saved as image/jpeg, {} bytes, {}x{}", i + 1, a.bytes.len(), buf.len(), cur.width(), cur.height()));
        out.push(Asset { bytes: buf, mime: "image/jpeg".into(), ..a });
    }
    Ok((out, notes))
}

/// Generations running now, per session (for `action=status` and the duplicate guard).
type Running = BTreeMap<String, Vec<(String, String, Instant)>>;
static ACTIVE: Mutex<Running> = Mutex::new(BTreeMap::new());

struct ActiveGuard {
    session: String,
    prompt: String,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Ok(mut a) = ACTIVE.lock() {
            if let Some(v) = a.get_mut(&self.session) {
                v.retain(|(p, _, _)| p != &self.prompt);
            }
        }
    }
}

pub struct ImageGenerate {
    m: Arc<Media>,
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(ImageGenerate { m: m.clone() })]
}

const ASPECTS: &[&str] = &["landscape", "square", "portrait", "1:1", "2:1", "20:9", "19.5:9", "2:3", "3:2", "2.35:1", "3:4", "4:3", "4:5", "5:4", "9:16", "9:19.5", "9:20", "16:9", "21:9", "1:2", "4:1", "1:4", "8:1", "1:8"];

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => vec![s.trim().to_string()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        _ => vec![],
    }
}

/// `image`/`image_url` first, then `images`/`reference_image_urls`, de-duplicated, max 16.
fn source_refs(input: &Value) -> Vec<String> {
    let mut v = Vec::new();
    for k in ["image", "image_url", "images", "reference_image_urls"] {
        for s in str_list(&input[k]) {
            if !v.contains(&s) {
                v.push(s);
            }
        }
    }
    v.truncate(16);
    v
}

impl ImageGenerate {
    fn list(&self) -> ToolOutput {
        let mut lines = vec!["Image generation providers (✓ = configured):".to_string()];
        let m = &self.m;
        let active = m.cfg.str_or("image.provider", "auto");
        for p in providers() {
            let model = p.default_model(m);
            let caps = p.caps(&model);
            let mut c = vec![if caps.edit { format!("generate, edit up to {} ref(s)", caps.max_inputs) } else { "generate".into() }];
            if !caps.resolutions.is_empty() {
                c.push(format!("resolutions {}", caps.resolutions.join("/")));
            }
            if !caps.sizes.is_empty() {
                c.push(format!("sizes {}", caps.sizes.join(", ")));
            }
            if !caps.aspect_ratios.is_empty() {
                c.push(format!("aspect ratios {}", caps.aspect_ratios.join(", ")));
            }
            if !caps.formats.is_empty() {
                c.push(format!("formats {}", caps.formats.join("/")));
            }
            let auth = if p.configured(m) {
                "✓".to_string()
            } else if p.env().is_empty() {
                "✗ (see [media.providers.".to_string() + p.id() + "])"
            } else {
                format!("✗ set {}", p.env().join(" or "))
            };
            let models = p.models();
            lines.push(format!("- {} ({}) {auth}{}\n  default model: {model}\n  models: {}\n  {}", p.id(), p.label(), if active == p.id() { " [selected]" } else { "" }, if models.is_empty() { "(any deployment / live catalog)".into() } else { models.join(", ") }, c.join("; ")));
        }
        ToolOutput::ok(lines.join("\n"))
    }

    fn status(&self, ctx: &ToolCtx) -> ToolOutput {
        let a = ACTIVE.lock().unwrap();
        match a.get(&ctx.session_id).filter(|v| !v.is_empty()) {
            None => ToolOutput::ok("No active image generation task is currently running for this session."),
            Some(v) => ToolOutput::ok(v.iter().map(|(p, prov, t)| format!("- running {}s on {prov}: {}", t.elapsed().as_secs(), crate::http::excerpt(p, 120))).collect::<Vec<_>>().join("\n")),
        }
    }

    fn build_request(&self, ctx: &ToolCtx, input: &Value) -> Result<ImageRequest, String> {
        let m = &self.m;
        let prompt = arg_opt_str(input, "prompt").unwrap_or("").trim().to_string();
        if prompt.is_empty() {
            return Err("Prompt is required and must be a non-empty string".into());
        }
        let aspect_in = arg_opt_str(input, "aspect_ratio").or_else(|| arg_opt_str(input, "aspectRatio")).map(str::trim).filter(|s| !s.is_empty());
        if let Some(a) = aspect_in {
            if !ASPECTS.contains(&a.to_ascii_lowercase().as_str()) && parse_ratio(a).is_none() {
                return Err(format!("invalid aspect_ratio `{a}`; use landscape, square, portrait or W:H"));
            }
        }
        let aspect_ratio = aspect_in.map(ratio_of_semantic);
        let semantic = match aspect_in.map(|s| s.to_ascii_lowercase()) {
            Some(s) if ["landscape", "square", "portrait"].contains(&s.as_str()) => s,
            Some(s) => semantic_of(Some(&s)).to_string(),
            None => "landscape".into(),
        };
        let resolution = match arg_opt_str(input, "resolution").map(|s| s.trim().to_ascii_uppercase()).filter(|s| !s.is_empty()) {
            Some(r) if ["1K", "2K", "4K"].contains(&r.as_str()) => Some(r),
            Some(_) => return Err("resolution must be one of 1K, 2K, or 4K".into()),
            None => None,
        };
        let pick = |k: &str, alt: &str, allowed: &[&str]| -> Result<Option<String>, String> {
            match arg_opt_str(input, k).or_else(|| arg_opt_str(input, alt)).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()) {
                Some(v) if allowed.contains(&v.as_str()) => Ok(Some(v)),
                Some(v) => Err(format!("{k} must be one of {} (got {v})", allowed.join(", "))),
                None => Ok(None),
            }
        };
        let quality = pick("quality", "quality", &["low", "medium", "high", "xhigh", "max", "auto"])?;
        let output_format = pick("output_format", "outputFormat", &["png", "jpeg", "webp"])?.map(|f| if f == "jpg" { "jpeg".into() } else { f });
        let background = pick("background", "background", &["transparent", "opaque", "auto"])?;
        let count = arg_opt_u64(input, "count").or_else(|| arg_opt_u64(input, "num_images")).unwrap_or(1);
        if !(1..=4).contains(&count) {
            return Err("count must be between 1 and 4".into());
        }
        let mut options = json!({});
        for k in ["openai", "fal"] {
            if input[k].is_object() {
                options[k] = input[k].clone();
            }
        }
        if let Some(c) = input["openai"]["outputCompression"].as_i64() {
            if !(0..=100).contains(&c) {
                return Err("openai.outputCompression must be between 0 and 100".into());
            }
        }
        for k in ["creativity", "intensity", "complexity", "movement", "num_inference_steps", "guidance_scale", "styles", "moodboards"] {
            if !input[k].is_null() {
                options[k] = input[k].clone();
            }
        }
        if let Some(c) = options["creativity"].as_str() {
            if !["raw", "low", "medium", "high"].contains(&c) {
                return Err("creativity must be raw, low, medium or high".into());
            }
        }
        for k in ["intensity", "complexity", "movement"] {
            if let Some(v) = options[k].as_i64() {
                if !(-100..=100).contains(&v) {
                    return Err(format!("{k} must be between -100 and 100"));
                }
            }
        }
        let max_in = m.cfg.int_or("image.max_input_bytes", 25 * 1024 * 1024) as usize;
        let mut inputs = Vec::new();
        for r in source_refs(input) {
            let (bytes, mime) = store::load(&r, &ctx.workspace, m, max_in).map_err(|e| format!("Could not load source image `{}`: {e}", crate::http::excerpt(&r, 80)))?;
            if store::class_of(&mime) != "image" {
                return Err(format!("source `{}` is not an image ({mime})", crate::http::excerpt(&r, 80)));
            }
            let name = r.rsplit('/').next().unwrap_or("image").split('?').next().unwrap_or("image").to_string();
            let url = (r.starts_with("http://") || r.starts_with("https://")).then(|| r.clone());
            inputs.push(InputImage { bytes, mime, name: if name.is_empty() || name.starts_with("data:") { "image.png".into() } else { name }, url });
        }
        let timeout = arg_opt_u64(input, "timeout_ms").or_else(|| arg_opt_u64(input, "timeoutMs")).map(Duration::from_millis).unwrap_or_else(|| Duration::from_secs(m.cfg.int_or("image.timeout_secs", 300).max(1) as u64));
        let poll_ms = m.cfg.int_or("image.poll_ms", 0);
        Ok(ImageRequest {
            prompt,
            model: None,
            count: count as u32,
            size: arg_opt_str(input, "size").map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()),
            aspect_ratio,
            semantic_aspect: semantic,
            resolution,
            quality,
            output_format,
            background,
            inputs,
            seed: input["seed"].as_i64(),
            upscale: input["upscale"].as_bool(),
            options,
            timeout,
            poll: (poll_ms > 0).then(|| Duration::from_millis(poll_ms as u64)),
        })
    }

    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let m = &self.m;
        let req = self.build_request(ctx, input)?;
        let cands = candidates(m, arg_opt_str(input, "provider"), arg_opt_str(input, "model"))?;
        {
            let mut a = ACTIVE.lock().unwrap();
            let v = a.entry(ctx.session_id.clone()).or_default();
            if let Some((_, prov, t)) = v.iter().find(|(p, _, _)| p == &req.prompt) {
                return Err(format!("An image generation for this prompt is already running on {prov} ({}s); wait for it instead of starting a duplicate.", t.elapsed().as_secs()));
            }
            v.push((req.prompt.clone(), cands[0].provider.clone(), Instant::now()));
        }
        let _guard = ActiveGuard { session: ctx.session_id.clone(), prompt: req.prompt.clone() };
        ctx.host.progress(&format!("generating image with {}…", cands[0].provider));
        let (prov, mut res, mut notes, attempts) = generate(m, &req, &cands, &ctx.cancel)?;
        // Download URL-only results so channels can deliver a local file.
        for a in res.images.iter_mut() {
            if a.bytes.is_empty() {
                if let Some(u) = a.url.clone() {
                    match m.download(&u, &[]) {
                        Ok((b, ct)) => {
                            let ct = if store::class_of(&ct) == "image" { ct } else { String::new() };
                            *a = Asset { url: Some(u), ..Asset::new(b, &ct) }.with_meta(a);
                        }
                        Err(e) => notes.push(format!("could not cache {u}: {e}")),
                    }
                }
            }
        }
        let max = m.cfg.int_or("image.max_bytes", 20 * 1024 * 1024) as usize;
        let (images, fit_notes) = fit_to_max_bytes(res.images, max)?;
        notes.extend(fit_notes);
        let dir = m.out_dir(ctx, "images");
        let base = arg_opt_str(input, "filename").map(|f| {
            let f = f.rsplit('/').next().unwrap_or(f);
            f.rsplit_once('.').map(|(s, _)| s).unwrap_or(f).to_string()
        });
        let mut paths: Vec<PathBuf> = Vec::new();
        let mut urls = Vec::new();
        for (i, a) in images.iter().enumerate() {
            if a.bytes.is_empty() {
                if let Some(u) = &a.url {
                    urls.push(u.clone());
                }
                continue;
            }
            let stem = match &base {
                Some(b) if images.len() > 1 => format!("{b}-{}", i + 1),
                Some(b) => b.clone(),
                None => format!("{}-{}", store::stem(&format!("{prov}-image")), i + 1),
            };
            paths.push(store::save(&dir, &stem, a)?);
        }
        let revised: Vec<String> = images.iter().filter_map(|a| a.revised_prompt.clone()).collect();
        let first = paths.first().map(|p| p.display().to_string()).or_else(|| urls.first().cloned());
        let out = json!({
            "success": true,
            "provider": prov,
            "model": res.model,
            "modality": if req.is_edit() { "image" } else { "text" },
            "image": first,
            "images": paths.iter().map(|p| p.display().to_string()).chain(urls.iter().cloned()).collect::<Vec<_>>(),
            "revised_prompt": revised.first(),
            "metadata": res.meta,
            "notes": notes,
            "attempts": if attempts.len() > 1 { json!(attempts) } else { Value::Null },
        });
        let mut text = serde_json::to_string_pretty(&out).unwrap_or_default();
        if !paths.is_empty() {
            text.push('\n');
            text.push_str(&store::media_tags(&paths, false));
        }
        Ok(text)
    }
}

trait WithMeta {
    fn with_meta(self, from: &Asset) -> Asset;
}

impl WithMeta for Asset {
    fn with_meta(mut self, from: &Asset) -> Asset {
        self.revised_prompt = from.revised_prompt.clone();
        self.meta = from.meta.clone();
        self
    }
}

impl Tool for ImageGenerate {
    fn spec(&self) -> ToolSpec {
        let s = |d: &str| json!({"type": "string", "description": d});
        ToolSpec {
            name: "image_generate".into(),
            description: "Generate images from a text prompt, or edit / restyle existing images passed in `image`/`images` (paths or URLs). Saves the files and returns their paths with MEDIA: lines (keep them in your reply so the chat delivers the images). Batch with `count`; control geometry with `aspect_ratio` (landscape/square/portrait or W:H), `size` (WxH) or `resolution` (1K/2K/4K); transparent PNG: output_format=png + background=transparent. `action=list` shows providers, models and readiness; `action=status` shows generations running in this session.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["generate", "list", "status"], "description": "\"generate\" (default), \"status\" active task, \"list\" providers/models"},
                    "prompt": s("The image to create, or the edit to apply to the reference image(s). Be detailed and descriptive."),
                    "image": s("Source image to edit (absolute/workspace path, URL or data: URL). Omit for text-to-image."),
                    "images": {"type": "array", "items": {"type": "string"}, "description": "More reference images (style, character, composition) for edits; max 16 in total."},
                    "aspect_ratio": {"type": "string", "enum": ASPECTS, "description": "landscape (16:9), square, portrait (9:16), or an explicit ratio."},
                    "size": s("Size hint WxH: 1024x1024, 1536x1024, 1024x1536, 2048x2048, 3840x2160 (model-specific)."),
                    "resolution": {"type": "string", "enum": ["1K", "2K", "4K"]},
                    "quality": {"type": "string", "enum": ["low", "medium", "high", "xhigh", "max", "auto"]},
                    "output_format": {"type": "string", "enum": ["png", "jpeg", "webp"]},
                    "background": {"type": "string", "enum": ["transparent", "opaque", "auto"], "description": "Transparent needs png or webp output."},
                    "count": {"type": "integer", "minimum": 1, "maximum": 4, "description": "Number of images (1-4)."},
                    "model": s("\"provider/model\" override (e.g. openai/gpt-image-2, fal/fal-ai/nano-banana-pro, google/gemini-3-pro-image) or a model id."),
                    "provider": s("Provider id override (see action=list)."),
                    "filename": s("Output filename hint (basename kept)."),
                    "seed": {"type": "integer"},
                    "upscale": {"type": "boolean", "description": "Post-generation ~2x upscale pass (FAL Clarity / Krea Enhance); can alter fine detail such as text and faces."},
                    "creativity": {"type": "string", "enum": ["raw", "low", "medium", "high"], "description": "Krea prompt expansion."},
                    "intensity": {"type": "integer", "minimum": -100, "maximum": 100, "description": "Krea style intensity."},
                    "complexity": {"type": "integer", "minimum": -100, "maximum": 100, "description": "Krea composition density."},
                    "movement": {"type": "integer", "minimum": -100, "maximum": 100, "description": "Krea motion."},
                    "openai": {"type": "object", "properties": {"background": {"type": "string", "enum": ["transparent", "opaque", "auto"]}, "moderation": {"type": "string", "enum": ["low", "auto"]}, "outputCompression": {"type": "integer", "minimum": 0, "maximum": 100}, "user": {"type": "string"}}},
                    "fal": {"type": "object", "properties": {"creativity": {"type": "string", "enum": ["raw", "low", "medium", "high"]}}},
                    "timeout_ms": {"type": "integer", "minimum": 1, "description": "Provider timeout in ms (300000 is a safe amount)."}
                }
            }),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match arg_opt_str(input, "action").unwrap_or("generate") {
            "list" | "status" => return vec![],
            _ => {}
        }
        let mut fx = Vec::new();
        for r in source_refs(input) {
            if !(r.starts_with("http://") || r.starts_with("https://") || r.starts_with("data:")) {
                fx.push(Effect::Read { path: store::resolve(&r, &ctx.workspace) });
            }
        }
        // `run` tries every candidate in turn (auto chain + fallbacks), so declare a network
        // effect for each destination it can reach, not just the first one.
        if let Ok(c) = candidates(&self.m, arg_opt_str(input, "provider"), arg_opt_str(input, "model")) {
            let payload = arg_opt_str(input, "prompt").unwrap_or("").to_string();
            for c in &c {
                let Some(p) = provider(&c.provider).filter(|p| p.configured(&self.m)) else { continue };
                let dest = crate::http::host_of(&self.m.creds(p.id(), p.env(), p.default_base()).base);
                if !dest.is_empty() && !fx.iter().any(|e| matches!(e, Effect::Net { dest: d, .. } if *d == dest)) {
                    fx.push(Effect::Net { dest, payload: payload.clone() });
                }
            }
        }
        fx.push(Effect::Write { path: self.m.out_dir(ctx, "images") });
        fx
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match arg_opt_str(&input, "action").unwrap_or("generate") {
            "list" => self.list(),
            "status" => self.status(ctx),
            "generate" => match self.run(ctx, &input) {
                Ok(t) => ToolOutput::ok(t),
                Err(e) => ToolOutput::err(json!({"success": false, "image": null, "error": e}).to_string()),
            },
            other => ToolOutput::err(format!("unknown action `{other}` (generate, list, status)")),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
