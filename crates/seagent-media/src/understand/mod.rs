//! Media understanding: describe images and videos with vision-capable provider APIs
//! (OpenClaw `src/media-understanding` providers: google, openai, anthropic, openrouter,
//! deepinfra, minimax, zai, qwen, moonshot, ollama, llama-cpp, plus any OpenAI-compatible
//! endpoint), and the `video_analyze` tool (Hermes `tools/vision_tools.py`).
//!
//! ```toml
//! [media.understanding]
//! image_provider = "auto"   # google | openai | anthropic | openrouter | deepinfra | minimax | zai | qwen | moonshot | ollama | llama-cpp | <custom> | agent
//! video_provider = "auto"   # google | openrouter | qwen | moonshot | <custom>
//! image_model = ""          # "provider/model" or a model id for the provider
//! video_model = ""
//! timeout_secs = 120
//! [media.understanding.providers.<id>]   # extra OpenAI-compatible describer
//! base_url = "http://127.0.0.1:8080/v1"  api_key = ""  model = "…"  video = false
//! ```
//! `ollama` and `llama-cpp` are keyless local endpoints: they are never part of the
//! `auto` chain unless their `[media.understanding.providers.<id>]` table exists (or the
//! provider is named explicitly), and `ollama` needs an explicit model id.
//! With no provider configured, images fall back to the agent's own vision model
//! ([`crate::llm`]) and videos to frames sampled with ffmpeg and shown to that model.

pub mod cli;

use crate::Media;
use seagent_core::tool::arg_opt_str;
use seagent_core::{Block, Cancel, Effect, Message, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DescribeRequest {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub prompt: String,
    pub model: Option<String>,
    pub max_tokens: u32,
}

pub trait Describer: Send + Sync {
    fn id(&self) -> &str;
    fn env(&self) -> &[&str];
    fn image(&self) -> bool;
    fn video(&self) -> bool;
    fn describe(&self, m: &Media, req: &DescribeRequest, cancel: &Cancel) -> Result<String, String>;
    fn configured(&self, m: &Media) -> bool {
        m.cfg.configured(self.id(), self.env())
    }
    /// Default model for `kind`.
    fn default_model(&self, kind: &str) -> String;
    fn base(&self) -> &str {
        ""
    }
    /// A keyless endpoint on this machine: only used by `auto` when explicitly configured.
    fn local(&self) -> bool {
        false
    }
}

/// `[media.understanding.providers.<id>]` overrides for `id` (base_url / model / api_key).
fn understanding_provider(m: &Media, id: &str) -> toml::Table {
    m.cfg.table(&format!("understanding.providers.{id}"))
}

fn understanding_provider_str(m: &Media, id: &str, key: &str) -> Option<String> {
    understanding_provider(m, id).get(key).and_then(|v| v.as_str()).map(|v| m.cfg.substitute(v.trim())).filter(|v| !v.is_empty())
}

fn model_for(m: &Media, d: &dyn Describer, kind: &str, req: &DescribeRequest) -> String {
    req.model
        .clone()
        .map(|mo| mo.split_once('/').filter(|(p, _)| *p == d.id()).map(|(_, r)| r.to_string()).unwrap_or(mo))
        .or_else(|| m.cfg.str(&format!("understanding.{kind}_model")).map(|mo| mo.split_once('/').filter(|(p, _)| *p == d.id()).map(|(_, r)| r.to_string()).unwrap_or(mo)))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| d.default_model(kind))
}

fn kind_of(mime: &str) -> &'static str {
    if mime.starts_with("video/") {
        "video"
    } else {
        "image"
    }
}

// ---------------------------------------------------------------- Google Gemini

pub struct Gemini;

impl Describer for Gemini {
    fn id(&self) -> &str {
        "google"
    }
    fn env(&self) -> &[&str] {
        &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
    }
    fn image(&self) -> bool {
        true
    }
    fn video(&self) -> bool {
        true
    }
    fn default_model(&self, _kind: &str) -> String {
        "gemini-3-flash-preview".into()
    }
    fn base(&self) -> &str {
        "https://generativelanguage.googleapis.com/v1beta"
    }
    fn describe(&self, m: &Media, req: &DescribeRequest, _cancel: &Cancel) -> Result<String, String> {
        let c = m.creds("google", self.env(), self.base());
        let key = c.key.clone().ok_or("Google API key missing")?;
        let model = model_for(m, self, kind_of(&req.mime), req).trim_start_matches("models/").to_string();
        let mut h = c.headers.clone();
        h.push(("x-goog-api-key".into(), key));
        let body = json!({"contents": [{"role": "user", "parts": [{"text": req.prompt}, {"inline_data": {"mime_type": req.mime, "data": crate::store::b64(&req.bytes)}}]}], "generationConfig": {"maxOutputTokens": req.max_tokens.max(256)}});
        let v = m.http.post_json(&format!("{}/models/{model}:generateContent", c.base.trim_end_matches('/')), &h, &body)?;
        let text: Vec<String> = v["candidates"][0]["content"]["parts"].as_array().map(|a| a.iter().filter_map(|p| p["text"].as_str().map(str::to_string)).collect()).unwrap_or_default();
        let t = text.join("").trim().to_string();
        if t.is_empty() {
            return Err(match v["promptFeedback"]["blockReason"].as_str() {
                Some(b) => format!("Google media understanding blocked ({b})"),
                None => "Google media understanding returned no text".into(),
            });
        }
        Ok(t)
    }
}

// ---------------------------------------------------------------- OpenAI-compatible chat

pub struct OpenAiChat {
    pub id: String,
    pub env: Vec<&'static str>,
    pub base: String,
    pub image_model: String,
    /// `None` = no video input.
    pub video_model: Option<String>,
}

impl OpenAiChat {
    pub fn openai() -> Self {
        OpenAiChat { id: "openai".into(), env: vec!["OPENAI_API_KEY"], base: "https://api.openai.com/v1".into(), image_model: "gpt-6-astra".into(), video_model: None }
    }
    pub fn openrouter() -> Self {
        // Hermes video_analyze recommends a video-capable model such as google/gemini-2.5-flash.
        OpenAiChat { id: "openrouter".into(), env: vec!["OPENROUTER_API_KEY"], base: "https://openrouter.ai/api/v1".into(), image_model: "openrouter/auto".into(), video_model: Some("google/gemini-2.5-flash".into()) }
    }
    /// Upstream `extensions/deepinfra` (`DEEPINFRA_VLM_FALLBACK_MODELS[0]`).
    pub fn deepinfra() -> Self {
        OpenAiChat { id: "deepinfra".into(), env: vec!["DEEPINFRA_API_KEY"], base: "https://api.deepinfra.com/v1/openai".into(), image_model: "moonshotai/Kimi-K2.6".into(), video_model: None }
    }
    /// MiniMax intl endpoint (same keys as [`crate::image_gen`]'s MiniMax provider).
    pub fn minimax() -> Self {
        OpenAiChat { id: "minimax".into(), env: vec!["MINIMAX_API_KEY", "MINIMAX_CODE_PLAN_KEY", "MINIMAX_CODING_API_KEY"], base: "https://api.minimax.io/v1".into(), image_model: "MiniMax-VL-01".into(), video_model: None }
    }
    /// Z.AI (GLM) international endpoint.
    pub fn zai() -> Self {
        OpenAiChat { id: "zai".into(), env: vec!["ZAI_API_KEY", "Z_AI_API_KEY"], base: "https://api.z.ai/api/paas/v4".into(), image_model: "glm-4.6v".into(), video_model: None }
    }
    /// Alibaba DashScope (Model Studio) international compatible-mode endpoint.
    pub fn qwen() -> Self {
        OpenAiChat { id: "qwen".into(), env: vec!["DASHSCOPE_API_KEY", "QWEN_API_KEY", "MODELSTUDIO_API_KEY"], base: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1".into(), image_model: "qwen3.6-plus".into(), video_model: Some("qwen3.6-plus".into()) }
    }
    /// Upstream `extensions/moonshot` (`mediaUnderstandingProviderMetadata.moonshot`).
    pub fn moonshot() -> Self {
        OpenAiChat { id: "moonshot".into(), env: vec!["MOONSHOT_API_KEY"], base: "https://api.moonshot.ai/v1".into(), image_model: "kimi-k2.6".into(), video_model: Some("kimi-k2.6".into()) }
    }
}

/// Message text from an OpenAI chat response (string or content parts; reasoning as a last resort).
pub fn chat_text(v: &Value) -> String {
    let msg = &v["choices"][0]["message"];
    let t = match &msg["content"] {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join(""),
        _ => String::new(),
    };
    if t.trim().is_empty() {
        msg["reasoning"].as_str().or(msg["reasoning_content"].as_str()).unwrap_or("").trim().to_string()
    } else {
        t.trim().to_string()
    }
}

impl Describer for OpenAiChat {
    fn id(&self) -> &str {
        &self.id
    }
    fn env(&self) -> &[&str] {
        &self.env
    }
    fn image(&self) -> bool {
        true
    }
    fn video(&self) -> bool {
        self.video_model.is_some()
    }
    fn default_model(&self, kind: &str) -> String {
        if kind == "video" {
            self.video_model.clone().unwrap_or_else(|| self.image_model.clone())
        } else {
            self.image_model.clone()
        }
    }
    fn base(&self) -> &str {
        &self.base
    }
    fn configured(&self, m: &Media) -> bool {
        // `env.is_empty()` covers custom `[understanding.providers.<id>]` entries (CustomChat),
        // which need no key; keyless built-ins use `LocalChat` and its own opt-in rule.
        self.env.is_empty() || m.cfg.configured(&self.id, &self.env)
    }
    fn describe(&self, m: &Media, req: &DescribeRequest, _cancel: &Cancel) -> Result<String, String> {
        let c = m.creds(&self.id, &self.env, &self.base);
        let model = model_for(m, self, kind_of(&req.mime), req);
        post_chat(m, &self.id, &c, &model, req, self.env.is_empty())
    }
}

/// One OpenAI-compatible `/chat/completions` vision request (an `image_url` / `video_url`
/// data-URL content part). `keyless` = the provider needs no API key (local endpoints).
fn post_chat(m: &Media, id: &str, c: &crate::Creds, model: &str, req: &DescribeRequest, keyless: bool) -> Result<String, String> {
    let kind = kind_of(&req.mime);
    let mut h = c.headers.clone();
    if let Some(k) = &c.key {
        h.push(("Authorization".into(), format!("Bearer {k}")));
    } else if !keyless {
        return Err(format!("{id} API key missing"));
    }
    let part = if kind == "video" { "video_url" } else { "image_url" };
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": [{"type": "text", "text": req.prompt}, {"type": part, part: {"url": crate::store::data_url(&req.mime, &req.bytes)}}]}],
        "max_tokens": req.max_tokens.max(256),
        "temperature": 0.1,
    });
    let v = m.http.post_json(&c.url("/chat/completions"), &h, &body)?;
    let t = chat_text(&v);
    if t.is_empty() {
        return Err(format!("{id} returned an empty description"));
    }
    Ok(t)
}

// ---------------------------------------------------------------- Anthropic

pub struct Anthropic;

impl Describer for Anthropic {
    fn id(&self) -> &str {
        "anthropic"
    }
    fn env(&self) -> &[&str] {
        &["ANTHROPIC_API_KEY"]
    }
    fn image(&self) -> bool {
        true
    }
    fn video(&self) -> bool {
        false
    }
    fn default_model(&self, _kind: &str) -> String {
        "claude-opus-5-5".into()
    }
    fn base(&self) -> &str {
        "https://api.anthropic.com"
    }
    fn describe(&self, m: &Media, req: &DescribeRequest, _cancel: &Cancel) -> Result<String, String> {
        let c = m.creds("anthropic", self.env(), self.base());
        let mut h = c.headers.clone();
        h.push(("x-api-key".into(), c.key.clone().ok_or("Anthropic API key missing")?));
        h.push(("anthropic-version".into(), "2023-06-01".into()));
        let body = json!({"model": model_for(m, self, "image", req), "max_tokens": req.max_tokens.max(256), "messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": req.mime, "data": crate::store::b64(&req.bytes)}}, {"type": "text", "text": req.prompt}]}]});
        let v = m.http.post_json(&c.url("/v1/messages"), &h, &body)?;
        let t: String = v["content"].as_array().map(|a| a.iter().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("")).unwrap_or_default();
        if t.trim().is_empty() {
            return Err("Anthropic returned an empty description".into());
        }
        Ok(t.trim().to_string())
    }
}

/// Built-in describers plus `[media.understanding.providers.<id>]` OpenAI-compatible ones.
pub fn describers_for(m: &Media) -> Vec<Box<dyn Describer>> {
    let mut v = describers();
    for (id, t) in m.cfg.table("understanding.providers") {
        let Some(t) = t.as_table() else { continue };
        // A built-in local endpoint reads this table itself (base_url / model / api_key).
        if v.iter().any(|d| d.local() && d.id() == id) {
            continue;
        }
        let s = |k: &str| t.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let model = s("model").unwrap_or_default();
        let video = t.get("video").and_then(|x| x.as_bool()).unwrap_or(false);
        // Credentials resolve through `[media.providers.<id>]` too; an inline key / base wins.
        let base = s("base_url").unwrap_or_default();
        v.push(Box::new(CustomChat { inner: OpenAiChat { id: id.clone(), env: vec![], base, image_model: model.clone(), video_model: video.then_some(model) }, key: s("api_key").map(|k| m.cfg.substitute(&k)) }));
    }
    v
}

struct CustomChat {
    inner: OpenAiChat,
    key: Option<String>,
}

impl Describer for CustomChat {
    fn id(&self) -> &str {
        &self.inner.id
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn image(&self) -> bool {
        true
    }
    fn video(&self) -> bool {
        self.inner.video()
    }
    fn default_model(&self, kind: &str) -> String {
        self.inner.default_model(kind)
    }
    fn configured(&self, _m: &Media) -> bool {
        !self.inner.base.is_empty()
    }
    fn describe(&self, m: &Media, req: &DescribeRequest, cancel: &Cancel) -> Result<String, String> {
        let mut cfg = m.cfg.clone();
        let mut t = cfg.table(&format!("providers.{}", self.inner.id));
        t.insert("base_url".into(), toml::Value::String(self.inner.base.clone()));
        if let Some(k) = &self.key {
            t.insert("api_key".into(), toml::Value::String(k.clone()));
        }
        let providers = cfg.table.entry("providers").or_insert_with(|| toml::Value::Table(Default::default()));
        if let Some(p) = providers.as_table_mut() {
            p.insert(self.inner.id.clone(), toml::Value::Table(t));
        }
        let m2 = Media { cfg, http: crate::http::Http::default() };
        self.inner.describe(&m2, req, cancel)
    }
}

/// A keyless OpenAI-compatible server on this machine (Ollama, llama.cpp). Never picked by
/// `auto` unless its `[media.understanding.providers.<id>]` table exists.
pub struct LocalChat {
    pub id: &'static str,
    pub base: &'static str,
    /// Empty = no default: the user must name a model (`image_model` or the provider table).
    pub image_model: &'static str,
}

impl LocalChat {
    /// Upstream `extensions/ollama`: image capability, no `defaultModels`.
    pub fn ollama() -> Self {
        LocalChat { id: "ollama", base: "http://127.0.0.1:11434/v1", image_model: "" }
    }
    /// Upstream `extensions/llama-cpp` (`LLAMA_CPP_DEFAULT_PORT`).
    pub fn llama_cpp() -> Self {
        LocalChat { id: "llama-cpp", base: "http://127.0.0.1:19432/v1", image_model: "gemma-4-e4b-it-q4_k_m" }
    }
}

impl Describer for LocalChat {
    fn id(&self) -> &str {
        self.id
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn image(&self) -> bool {
        true
    }
    fn video(&self) -> bool {
        false
    }
    fn default_model(&self, _kind: &str) -> String {
        self.image_model.to_string()
    }
    fn base(&self) -> &str {
        self.base
    }
    fn local(&self) -> bool {
        true
    }
    fn configured(&self, m: &Media) -> bool {
        // Keyless: only an explicit `[media.understanding.providers.<id>]` opts it into `auto`.
        !understanding_provider(m, self.id).is_empty()
    }
    fn describe(&self, m: &Media, req: &DescribeRequest, _cancel: &Cancel) -> Result<String, String> {
        let kind = kind_of(&req.mime);
        let cr = m.creds(self.id, self.env(), self.base);
        let key = understanding_provider_str(m, self.id, "api_key").or(cr.key.clone());
        let base = understanding_provider_str(m, self.id, "base_url").unwrap_or_else(|| cr.base.clone());
        let c = crate::Creds { base, key, ..cr };
        let mut model = model_for(m, self, kind, req);
        if model.trim().is_empty() {
            model = understanding_provider_str(m, self.id, "model").unwrap_or_default();
        }
        if model.trim().is_empty() {
            return Err(format!("{} {kind} understanding requires a model id ([media.understanding] {kind}_model or [media.understanding.providers.{}] model)", self.id, self.id));
        }
        post_chat(m, self.id, &c, model.trim(), req, true)
    }
}

pub fn describers() -> Vec<Box<dyn Describer>> {
    vec![
        Box::new(Gemini),
        Box::new(OpenAiChat::openai()),
        Box::new(Anthropic),
        Box::new(OpenAiChat::openrouter()),
        // Additional upstream OpenAI-compatible providers (order preserves existing behaviour).
        Box::new(OpenAiChat::deepinfra()),
        Box::new(OpenAiChat::minimax()),
        Box::new(OpenAiChat::zai()),
        Box::new(OpenAiChat::qwen()),
        Box::new(OpenAiChat::moonshot()),
        // Keyless local endpoints: not auto-selected unless configured.
        Box::new(LocalChat::ollama()),
        Box::new(LocalChat::llama_cpp()),
    ]
}

/// Ask the agent's own model (images only) — the default when no provider is set.
fn agent_describe(llm: Option<Arc<dyn crate::Llm>>, prompt: &str, images: &[(String, Vec<u8>)], max_tokens: u32, cancel: &Cancel) -> Result<String, String> {
    let l = llm.ok_or("no media-understanding provider available")?;
    if !l.vision(None) {
        return Err("no media-understanding provider is configured and the agent model has no vision input".into());
    }
    let mut content = vec![Block::text(prompt)];
    content.extend(images.iter().map(|(mt, b)| Block::Image { media_type: mt.clone(), data: crate::store::b64(b) }));
    let t = l.complete(None, "", vec![Message { role: Role::User, content }], max_tokens.max(512), cancel)?;
    if t.trim().is_empty() {
        return Err("the agent model returned an empty description".into());
    }
    Ok(t.trim().to_string())
}

/// Up to `n` evenly spread JPEG frames of a video (ffmpeg).
pub fn sample_frames(bytes: &[u8], mime: &str, n: usize, cancel: &Cancel) -> Result<Vec<Vec<u8>>, String> {
    let dur = {
        // A unique 0700 work dir: two decodes in the same millisecond must not share `in.*`
        // (and neither may delete the other's files when it finishes).
        let mut d = None;
        if let Ok(dir) = crate::store::temp_dir("vframes") {
            let p = dir.join(format!("in.{}", crate::store::ext_for(mime)));
            let _ = std::fs::write(&p, bytes);
            d = crate::audio::duration_secs(&p, cancel);
            let _ = std::fs::remove_dir_all(&dir);
        }
        d
    };
    let dur = dur.unwrap_or(10.0).max(1.0);
    let fps = format!("fps={:.4},scale=768:-2", n as f64 / dur);
    let n_s = n.to_string();
    let raw = crate::audio::ffmpeg_transcode(bytes, crate::store::ext_for(mime), &["-vf", &fps, "-frames:v", &n_s, "-f", "image2pipe", "-vcodec", "mjpeg"], cancel)?;
    let mut frames = vec![];
    let mut start = None;
    for i in 0..raw.len().saturating_sub(1) {
        if raw[i] == 0xff && raw[i + 1] == 0xd8 && (i == 0 || start.is_some_and(|s| i > s)) {
            if let Some(s) = start {
                frames.push(raw[s..i].to_vec());
            }
            start = Some(i);
        }
    }
    if let Some(s) = start {
        frames.push(raw[s..].to_vec());
    }
    if frames.is_empty() {
        return Err("ffmpeg produced no frames".into());
    }
    Ok(frames)
}

/// Describe an image (`kind` = "image") or video ("video"): the configured provider (or
/// every configured one in order until one answers), falling back to the agent's own vision
/// model through [`crate::llm`]. Returns `(provider, text)`.
pub fn describe(m: &Media, kind: &str, req: &DescribeRequest, cancel: &Cancel) -> Result<(String, String), String> {
    describe_with(m, kind, req, crate::llm(), cancel)
}

/// An empty-but-successful provider answer (Hermes retries these once).
fn is_empty_answer(e: &str) -> bool {
    e.contains("empty description") || e.contains("returned no text")
}

pub(crate) fn describe_with(m: &Media, kind: &str, req: &DescribeRequest, llm: Option<Arc<dyn crate::Llm>>, cancel: &Cancel) -> Result<(String, String), String> {
    let all = describers_for(m);
    let want = req.model.as_deref().and_then(|mo| mo.split_once('/').map(|x| x.0.to_string())).filter(|p| all.iter().any(|d| d.id() == p)).or_else(|| m.cfg.str(&format!("understanding.{kind}_provider"))).or_else(|| m.cfg.str("understanding.provider")).unwrap_or_else(|| "auto".into());
    let fits = |d: &dyn Describer| if kind == "video" { d.video() } else { d.image() };
    let chain: Vec<&dyn Describer> = match want.as_str() {
        "auto" => all.iter().map(|d| &**d).filter(|d| fits(*d)).filter(|d| d.configured(m)).collect(),
        "agent" => vec![],
        id => {
            let d = all.iter().find(|d| d.id() == id).ok_or_else(|| format!("unknown media-understanding provider `{id}`"))?;
            if !fits(&**d) {
                return Err(format!("{id} cannot describe {kind}s"));
            }
            vec![&**d]
        }
    };
    let mut errors = vec![];
    for d in chain {
        // Hermes `_call_vision_llm`: an empty (e.g. reasoning-only) answer is retried once.
        let mut r = d.describe(m, req, cancel);
        if matches!(&r, Err(e) if is_empty_answer(e)) && !cancel.is_cancelled() {
            r = d.describe(m, req, cancel);
        }
        match r {
            Ok(t) => return Ok((d.id().to_string(), t)),
            Err(e) => errors.push(format!("{}: {e}", d.id())),
        }
        if cancel.is_cancelled() {
            return Err("cancelled".into());
        }
    }
    let fallback = if kind == "video" {
        sample_frames(&req.bytes, &req.mime, 6, cancel).and_then(|frames| {
            let imgs: Vec<(String, Vec<u8>)> = frames.into_iter().map(|f| ("image/jpeg".to_string(), f)).collect();
            agent_describe(llm.clone(), &format!("These are frames sampled in order from one video.\n\n{}", req.prompt), &imgs, req.max_tokens, cancel)
        })
    } else {
        agent_describe(llm, &req.prompt, &[(req.mime.clone(), req.bytes.clone())], req.max_tokens, cancel)
    };
    match fallback {
        Ok(t) => Ok(("agent".into(), t)),
        Err(e) => {
            errors.push(format!("agent: {e}"));
            Err(if errors.len() == 1 { "no media-understanding provider available".to_string() + &format!(" ({})", errors[0]) } else { errors.join("; ") })
        }
    }
}

// ---------------------------------------------------------------- video_analyze

/// Hermes `_VIDEO_MIME_TYPES`.
pub const VIDEO_MIME: &[(&str, &str)] = &[(".mp4", "video/mp4"), (".webm", "video/webm"), (".mov", "video/mov"), (".avi", "video/mp4"), (".mkv", "video/mp4"), (".mpeg", "video/mpeg"), (".mpg", "video/mpeg")];
const MAX_VIDEO_BASE64: usize = 50 * 1024 * 1024;

fn video_mime(src: &str) -> Option<&'static str> {
    let path = src.split(['?', '#']).next().unwrap_or(src).to_ascii_lowercase();
    VIDEO_MIME.iter().find(|(e, _)| path.ends_with(e)).map(|x| x.1)
}

fn unsupported(suffix: &str) -> String {
    let mut exts: Vec<&str> = VIDEO_MIME.iter().map(|x| x.0).collect();
    exts.sort();
    format!("Unsupported video format: '{suffix}'. Supported: {}", exts.join(", "))
}

/// Hermes `_SIZE_ERROR_HINTS` (checked last: billing → capability → size).
const SIZE_HINTS: &[&str] = &["too large", "payload", "413", "content_too_large", "request_too_large", "exceeds", "size limit"];

/// Hermes `_VIDEO_ERROR_RULES`: first matching hint set wins.
pub fn video_error_text(e: &str) -> String {
    let l = e.to_ascii_lowercase();
    // Hermes matches these as plain substrings; a bare "402" would also match hex ids and
    // temp-dir names (`seagent-ff-4029952-x`), so numeric hints are matched as whole tokens.
    let any = |hs: &[&str]| {
        hs.iter().any(|h| {
            if h.chars().all(|c| c.is_ascii_digit()) {
                l.match_indices(h).any(|(i, _)| {
                    let before = l[..i].chars().next_back();
                    let after = l[i + h.len()..].chars().next();
                    !before.is_some_and(|c| c.is_ascii_alphanumeric()) && !after.is_some_and(|c| c.is_ascii_alphanumeric())
                })
            } else {
                l.contains(h)
            }
        })
    };
    if any(&["402", "insufficient", "payment required", "credits", "billing"]) {
        return format!("Insufficient credits or payment required. Please top up your API provider account and try again. Error: {e}");
    }
    if any(&["does not support", "not support video", "content_policy", "multimodal", "unrecognized request argument", "video input", "video_url"]) {
        return format!("The model does not support video analysis or the request was rejected. Ensure you're using a video-capable model (e.g. google/gemini-2.5-flash). Error: {e}");
    }
    if any(SIZE_HINTS) {
        return format!("The video is too large for the API. Try compressing or trimming the video (max ~50 MB). Error: {e}");
    }
    format!("There was a problem with the request and the video could not be analyzed. Error: {e}")
}

/// Length of the `data:<mime>;base64,…` payload for `len` raw bytes.
pub fn video_data_url_len(len: usize, mime: &str) -> usize {
    len.div_ceil(3) * 4 + format!("data:{mime};base64,").len()
}

/// Hermes `video_data_url > _MAX_VIDEO_BASE64_BYTES` (50 MB hard cap).
pub fn check_video_payload(len: usize, mime: &str) -> Result<(), String> {
    let b64_len = video_data_url_len(len, mime);
    if b64_len > MAX_VIDEO_BASE64 {
        return Err(format!("Video too large for API: base64 payload is {:.1} MB (limit {} MB). Compress or trim the video and retry.", b64_len as f64 / (1024.0 * 1024.0), MAX_VIDEO_BASE64 / (1024 * 1024)));
    }
    Ok(())
}

pub struct VideoAnalyze {
    pub m: Arc<Media>,
}

impl VideoAnalyze {
    pub fn run(&self, ctx: &ToolCtx, video_url: &str, question: &str) -> Result<(String, String), String> {
        let src = video_url.trim().trim_start_matches("file://");
        if src.is_empty() {
            return Err("Invalid video source. Provide an HTTP/HTTPS URL or a valid local file path.".into());
        }
        let remote = src.starts_with("http://") || src.starts_with("https://");
        let (bytes, sniffed) = crate::store::load(src, &ctx.workspace, &self.m, MAX_VIDEO_BASE64)?;
        let mime = match (video_mime(src), remote) {
            (Some(m), _) => m.to_string(),
            (None, true) if sniffed.starts_with("video/") => sniffed.clone(),
            (None, true) => "video/mp4".into(),
            (None, false) => {
                let suffix = std::path::Path::new(src).extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
                return Err(unsupported(&suffix));
            }
        };
        check_video_payload(bytes.len(), &mime)?;
        let prompt = format!("Fully describe and explain everything happening in this video, including visual content, motion, audio cues, text overlays, and scene transitions. Then answer the following question:\n\n{question}");
        let model = self.m.cfg.str("understanding.video_model").or_else(|| self.m.cfg.str("vision.video_model"));
        let req = DescribeRequest { bytes, mime, prompt, model, max_tokens: 4096 };
        describe(&self.m, "video", &req, &ctx.cancel)
    }
}

impl Tool for VideoAnalyze {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "video_analyze".into(),
            description: "Analyze a video from a URL or local file path using a multimodal AI model. Sends the video to a video-capable model (e.g. Gemini) for understanding. Use this for video files — for images, use vision_analyze instead. Supports mp4, webm, mov, avi, mkv, mpeg formats. Note: large videos (>20 MB) may be slow; max ~50 MB.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "video_url": {"type": "string", "description": "Video URL (http/https) or local file path to analyze."},
                    "question": {"type": "string", "description": "Your specific question about the video. The AI will describe what happens in the video and answer your question."}
                },
                "required": ["video_url", "question"]
            }),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let src = arg_opt_str(input, "video_url").unwrap_or("").trim_start_matches("file://");
        let mut fx = vec![];
        if !src.is_empty() && !src.starts_with("http") && !src.starts_with("data:") {
            fx.push(Effect::Read { path: crate::store::resolve(src, &ctx.workspace) });
        }
        let ds = describers_for(&self.m);
        if let Some(d) = ds.iter().find(|d| d.video() && d.configured(&self.m)) {
            fx.push(Effect::Net { dest: crate::http::host_of(&self.m.creds(d.id(), d.env(), d.base()).base), payload: format!("video {src}: {}", arg_opt_str(input, "question").unwrap_or("")) });
        }
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let url = arg_opt_str(&input, "video_url").unwrap_or("");
        let q = arg_opt_str(&input, "question").unwrap_or("");
        match self.run(ctx, url, q) {
            Ok((provider, a)) => ToolOutput::ok(serde_json::to_string_pretty(&json!({"success": true, "analysis": if a.trim().is_empty() { "There was a problem with the request and the video could not be analyzed.".to_string() } else { a }, "provider": provider})).unwrap_or_default()),
            Err(e) => ToolOutput::err(serde_json::to_string_pretty(&json!({"success": false, "error": format!("Error analyzing video: {e}"), "analysis": video_error_text(&e)})).unwrap_or_default()),
        }
    }
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(VideoAnalyze { m: m.clone() })]
}

#[cfg(test)]
mod tests;
