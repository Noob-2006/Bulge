//! OpenAI Images API (`/images/generations`, `/images/edits`; Azure OpenAI deployments)
//! and the ChatGPT/Codex OAuth route (Hermes `openai-codex`: native Codex
//! `images/*`; OpenClaw: Responses + hosted `image_generation` tool over SSE).

use super::common::{openai_size_for, require_key, Compat};
use super::{parse_size, Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::{self, Asset};
use crate::{Creds, Media};
use ark_core::Cancel;
use serde_json::{json, Map, Value};

pub struct OpenAi;
pub struct Codex;

const ENV: &[&str] = &["OPENAI_API_KEY"];
const BASE: &str = "https://api.openai.com/v1";
const CODEX_BASE: &str = "https://chatgpt.com/backend-api/codex";
const SIZES: &[&str] = &["1024x1024", "1536x1024", "1024x1536", "2048x2048", "2048x1152", "3840x2160", "2160x3840"];
const LEGACY_SIZES: &[&str] = &["1024x1024", "1536x1024", "1024x1536"];
const QUALITIES: &[&str] = &["low", "medium", "high", "auto"];
const QUALITIES_25: &[&str] = &["low", "medium", "high", "xhigh", "max", "auto"];
const MODELS_25: &[&str] = &["gpt-image-2.5-flare", "gpt-image-2.5-sunburst"];
const FLEXIBLE: &[&str] = &["gpt-image-2", "gpt-image-2.5-flare", "gpt-image-2.5-sunburst", "gpt-image-2-2026-04-21"];
const TRANSPARENT_MODEL: &str = "gpt-image-1.5";
const DEFAULT_TIER: &str = "gpt-image-2-medium";
const CODEX_INSTRUCTIONS: &str = "You are an image generation assistant.";
const CODEX_RESPONSES_MODEL: &str = "gpt-6-astra";

/// Hermes tier ids (`gpt-image-2-medium`, `gpt-image-2.5-flare-high`) → `(api model, quality)`.
pub fn tier(model: &str) -> (String, Option<String>) {
    for q in ["low", "medium", "high", "xhigh", "max"] {
        if let Some(base) = model.strip_suffix(&format!("-{q}")) {
            if base == "gpt-image-2" || MODELS_25.contains(&base) {
                if base == "gpt-image-2" && !["low", "medium", "high"].contains(&q) {
                    break;
                }
                return (base.to_string(), Some(q.to_string()));
            }
        }
    }
    (model.to_string(), None)
}

fn is_azure(base: &str) -> bool {
    let host = crate::http::host_of(base).to_ascii_lowercase();
    [".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com"].iter().any(|s| host.ends_with(s))
}

fn is_public(base: &str) -> bool {
    base.trim_end_matches('/') == BASE
}

fn valid_flexible(model: &str, size: &str) -> bool {
    if !FLEXIBLE.contains(&model) {
        return false;
    }
    if size == "auto" {
        return MODELS_25.contains(&model);
    }
    let Some((w, h)) = parse_size(size) else { return false };
    let px = w as u64 * h as u64;
    w % 16 == 0 && h % 16 == 0 && w.max(h) <= 3840 && (655_360..=8_294_400).contains(&px) && w <= h * 3 && h <= w * 3
}

/// The shared OpenAI option fields (OpenClaw resolveOpenAIImageOptions).
fn options(req: &ImageRequest, quality: Option<String>) -> Map<String, Value> {
    let mut o = Map::new();
    if let Some(q) = req.quality.clone().or(quality) {
        o.insert("quality".into(), json!(q));
    }
    if let Some(f) = &req.output_format {
        o.insert("output_format".into(), json!(f));
    }
    if let Some(bg) = req.opt_str("openai.background").or_else(|| req.background.clone()) {
        o.insert("background".into(), json!(bg));
    }
    if let Some(mo) = req.opt_str("openai.moderation") {
        o.insert("moderation".into(), json!(mo));
    }
    if matches!(req.output_format.as_deref(), Some("jpeg" | "webp")) {
        if let Some(c) = req.opt_i64("openai.outputCompression") {
            o.insert("output_compression".into(), json!(c));
        }
    }
    o
}

fn output_mime(req: &ImageRequest) -> &'static str {
    match req.output_format.as_deref() {
        Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        _ => "image/png",
    }
}

fn openai_creds(m: &Media) -> Creds {
    let base = std::env::var("OPENAI_BASE_URL").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| BASE.into());
    let mut c = m.creds("openai", ENV, &base);
    if let Some(env) = c.str("key_env") {
        if let Ok(v) = std::env::var(&env) {
            c.key = Some(v);
        }
    }
    c
}

fn resolve_size(model: &str, req: &ImageRequest, apply_limits: bool) -> String {
    let requested = req.size.clone().unwrap_or_else(|| openai_size_for(&req.semantic_aspect).to_string());
    if valid_flexible(model, &requested) || !apply_limits {
        return requested;
    }
    let supported = if model == "gpt-image-1" || model == "gpt-image-1-mini" { LEGACY_SIZES } else { SIZES };
    if supported.contains(&requested.as_str()) {
        return requested;
    }
    match parse_size(&requested) {
        Some((w, h)) => supported.iter().copied().min_by(|a, b| {
            let d = |s: &str| {
                let (x, y) = parse_size(s).unwrap_or((1024, 1024));
                ((x as f64 / y as f64).ln() - (w as f64 / h as f64).ln()).abs() * 10.0 + ((x * y) as f64 - (w * h) as f64).abs() / 1e7
            };
            d(a).total_cmp(&d(b))
        }).unwrap_or("1024x1024").to_string(),
        None => "1024x1024".into(),
    }
}

impl ImageProvider for OpenAi {
    fn id(&self) -> &'static str {
        "openai"
    }
    fn label(&self) -> &'static str {
        "OpenAI"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.openai.model").or_else(|| std::env::var("OPENAI_IMAGE_MODEL").ok().filter(|s| !s.trim().is_empty())).unwrap_or_else(|| DEFAULT_TIER.into())
    }
    fn models(&self) -> Vec<String> {
        let mut v: Vec<String> = ["gpt-image-2", "gpt-image-2.5-flare", "gpt-image-2.5-sunburst", "gpt-image-1.5", "gpt-image-1", "gpt-image-1-mini"].map(String::from).to_vec();
        v.extend(["gpt-image-2-low", "gpt-image-2-medium", "gpt-image-2-high"].map(String::from));
        for b in MODELS_25 {
            for q in ["low", "medium", "high", "xhigh", "max"] {
                v.push(format!("{b}-{q}"));
            }
        }
        v
    }
    fn configured(&self, m: &Media) -> bool {
        openai_creds(m).key.is_some()
    }
    fn caps(&self, model: &str) -> Caps {
        let (api, _) = tier(model);
        Caps {
            max_count: 4,
            edit: true,
            max_inputs: 16,
            supports_size: true,
            sizes: if FLEXIBLE.contains(&api.as_str()) { vec![] } else if api.starts_with("gpt-image-1") && api != "gpt-image-1.5" { LEGACY_SIZES.to_vec() } else { SIZES.to_vec() },
            formats: vec!["png", "jpeg", "webp"],
            qualities: if MODELS_25.contains(&api.as_str()) { QUALITIES_25.to_vec() } else { QUALITIES.to_vec() },
            backgrounds: vec!["transparent", "opaque", "auto"],
            ..Caps::default()
        }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = openai_creds(m);
        let key = require_key(&c, ENV)?.to_string();
        let (mut model, tier_q) = tier(&super::common::model_or(req, &self.default_model(m)));
        let azure = is_azure(&c.base);
        let public = is_public(&c.base);
        let bg = req.opt_str("openai.background").or_else(|| req.background.clone());
        if public && model == "gpt-image-2" && bg.as_deref() == Some("transparent") {
            model = TRANSPARENT_MODEL.into();
        }
        let size = resolve_size(&model, req, public || azure);
        let mut body = Map::new();
        if !azure {
            body.insert("model".into(), json!(model));
        }
        body.insert("prompt".into(), json!(req.prompt));
        body.insert("n".into(), json!(req.count.clamp(1, 4)));
        body.insert("size".into(), json!(size));
        body.extend(options(req, tier_q.clone()));
        if let Some(u) = req.opt_str("openai.user") {
            body.insert("user".into(), json!(u));
        }
        let mut headers = c.headers.clone();
        if azure {
            headers.insert(0, ("api-key".into(), key));
        } else {
            headers.insert(0, ("authorization".into(), format!("Bearer {key}")));
        }
        let label = if req.is_edit() { "OpenAI image edit" } else { "OpenAI image generation" };
        let v = if azure {
            let ver = c.str("azure_api_version").or_else(|| std::env::var("AZURE_OPENAI_API_VERSION").ok()).unwrap_or_else(|| "2024-12-01-preview".into());
            let root = c.base.trim_end_matches('/').trim_end_matches("/openai/v1").trim_end_matches("/openai").to_string();
            let action = if req.is_edit() { "edits" } else { "generations" };
            let url = format!("{root}/openai/deployments/{model}/images/{action}?api-version={ver}");
            if req.is_edit() {
                let fields: Vec<(&str, String)> = body.iter().map(|(k, v)| (k.as_str(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect();
                let mut form = crate::http::Multipart::new();
                for (k, v) in fields {
                    form = form.text(k, v);
                }
                for (i, img) in req.inputs.iter().enumerate() {
                    form = form.file("image[]", &super::common::upload_name(&img.name, &img.mime, i), &img.mime, img.bytes.clone());
                }
                m.http.post_multipart(&url, &headers, &form).map_err(|e| format!("{label} failed: {e}"))?.json()?
            } else {
                m.http.post_json(&url, &headers, &Value::Object(body.clone())).map_err(|e| format!("{label} failed: {e}"))?
            }
        } else {
            let compat = Compat { label, creds: &c, headers: headers.clone(), edit_field: "image[]", default_mime: output_mime(req) };
            if req.is_edit() {
                let fields: Vec<(&str, String)> = body.iter().map(|(k, v)| (k.as_str(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))).collect();
                compat.edit(m, &fields, req)?
            } else {
                compat.generate(m, &Value::Object(body.clone()))?
            }
        };
        let images = super::common::parse_openai_images(&v, output_mime(req), "OpenAI")?;
        let mut meta = super::common::usage_meta(&v);
        meta["size"] = json!(size);
        if let Some(q) = body.get("quality") {
            meta["quality"] = q.clone();
        }
        Ok(ImageResult { images, model, meta })
    }
}

/// Codex OAuth token: config `api_key`, `CODEX_ACCESS_TOKEN`, or the Codex CLI auth file.
fn codex_creds(m: &Media) -> Creds {
    let mut c = m.creds("openai-codex", &["CODEX_ACCESS_TOKEN", "OPENAI_CODEX_TOKEN"], CODEX_BASE);
    if c.key.is_none() {
        let path = c.str("auth_file").map(|p| ark_core::tool::expand_home(&p)).unwrap_or_else(|| {
            let home = std::env::var("CODEX_HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| ark_core::tool::expand_home("~/.codex"));
            home.join("auth.json")
        });
        if let Ok(s) = std::fs::read_to_string(&path) {
            let v: Value = serde_json::from_str(&s).unwrap_or_default();
            c.key = v["tokens"]["access_token"].as_str().or_else(|| v["access_token"].as_str()).filter(|s| !s.is_empty()).map(str::to_string);
            if let Some(a) = v["tokens"]["account_id"].as_str() {
                c.extra.insert("account_id".into(), toml::Value::String(a.into()));
            }
        }
    }
    c
}

/// Workspace headers derived from the OAuth JWT (`https://api.openai.com/auth` claims).
pub fn codex_account_headers(token: &str) -> Vec<(String, String)> {
    let mut h = Vec::new();
    let Some(payload) = token.split('.').nth(1) else { return h };
    let Ok(bytes) = store::b64_decode(&payload.replace('-', "+").replace('_', "/")) else { return h };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let auth = &v["https://api.openai.com/auth"];
    if let Some(a) = auth["chatgpt_account_id"].as_str().filter(|s| !s.is_empty()) {
        h.push(("ChatGPT-Account-ID".into(), a.into()));
    }
    if let Some(r) = auth["chatgpt_data_residency"].as_str().or_else(|| auth["chatgpt_compute_residency"].as_str()).filter(|s| !s.is_empty()) {
        h.push(("x-openai-internal-codex-residency".into(), r.into()));
    }
    h
}

fn codex_headers(c: &Creds, token: &str) -> Vec<(String, String)> {
    let mut h = vec![("authorization".into(), format!("Bearer {token}")), ("originator".into(), "ark".into()), ("user-agent".into(), format!("ark/{}", env!("CARGO_PKG_VERSION")))];
    let acct = codex_account_headers(token);
    if acct.is_empty() {
        if let Some(a) = c.str("account_id") {
            h.push(("ChatGPT-Account-ID".into(), a));
        }
    }
    h.extend(acct);
    h.extend(c.headers.iter().cloned());
    h
}

const CODEX_INPUT_MIMES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp"];

/// Server-sent events body → images (OpenClaw readCodexImageGenerationResponse).
fn parse_codex_sse(body: &str, mime: &str) -> Result<Vec<Asset>, String> {
    let mut done_items: Vec<Value> = vec![];
    let mut completed: Option<Value> = None;
    for frame in body.replace("\r\n", "\n").split("\n\n") {
        let data: String = frame.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.strip_prefix(' ').unwrap_or(l)).collect::<Vec<_>>().join("\n");
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<Value>(data) else { continue };
        match ev["type"].as_str().unwrap_or("") {
            "response.failed" | "error" => {
                let err = if ev["response"]["error"].is_object() { &ev["response"]["error"] } else { &ev["error"] };
                let msg = err["message"].as_str().or_else(|| ev["message"].as_str()).map(str::to_string).or_else(|| err["code"].as_str().map(|c| format!("OpenAI Codex image generation failed ({c})")));
                return Err(msg.unwrap_or_else(|| "OpenAI Codex image generation failed".into()));
            }
            "response.incomplete" => return Err(format!("OpenAI Codex image generation response incomplete: {}", ev["response"]["incomplete_details"]["reason"].as_str().unwrap_or("unknown"))),
            "response.completed" => {
                completed = Some(ev["response"].clone());
                break;
            }
            "response.output_item.done" => done_items.push(ev["item"].clone()),
            _ => {}
        }
    }
    let resp = completed.ok_or("OpenAI Codex image generation stream closed before response.completed")?;
    let out: Vec<Value> = resp["output"].as_array().cloned().unwrap_or_default();
    let mut items: Vec<Value> = out.iter().filter(|i| i["type"] == "image_generation_call").cloned().collect();
    if items.is_empty() {
        items = done_items.iter().filter(|i| i["type"] == "image_generation_call").cloned().collect();
    }
    let diagnostic = || {
        for i in out.iter().chain(done_items.iter()) {
            let parts: Vec<Value> = if i["type"] == "message" { i["content"].as_array().cloned().unwrap_or_default() } else { vec![i.clone()] };
            for p in parts {
                match p["type"].as_str() {
                    Some("refusal") => return Some(format!("OpenAI Codex image generation refused by provider: \"{}\"", crate::http::excerpt(p["refusal"].as_str().or(p["text"].as_str()).unwrap_or(""), 256))),
                    Some("output_text") => return Some(format!("OpenAI Codex image generation returned text instead of an image: \"{}\"", crate::http::excerpt(p["text"].as_str().unwrap_or(""), 256))),
                    _ => {}
                }
            }
        }
        None
    };
    let mut images = vec![];
    for i in items.iter().take(4) {
        if let Some(s) = i["status"].as_str().filter(|s| *s != "completed") {
            return Err(match diagnostic() {
                Some(d) => format!("{d} (image call did not complete ({s}))"),
                None => format!("OpenAI Codex image generation image call did not complete ({s})"),
            });
        }
        let Some(r) = i["result"].as_str().filter(|s| !s.is_empty()) else { continue };
        let mut a = Asset::new(store::b64_decode(r).map_err(|_| "OpenAI Codex image generation returned malformed base64 image data")?, mime);
        a.revised_prompt = i["revised_prompt"].as_str().map(str::to_string);
        images.push(a);
    }
    if images.is_empty() {
        return Err(diagnostic().unwrap_or_else(|| "OpenAI Codex image generation completed but did not produce an image".into()));
    }
    Ok(images)
}

impl Codex {
    fn native(&self, m: &Media, c: &Creds, token: &str, req: &ImageRequest, model: &str, quality: &str) -> Result<ImageResult, String> {
        let size = req.size.clone().unwrap_or_else(|| openai_size_for(&req.semantic_aspect).to_string());
        let mut inputs = vec![];
        for img in &req.inputs {
            if img.bytes.len() > 25 * 1024 * 1024 {
                return Err("Invalid image input for Codex image editing: image exceeds 25MB cap".into());
            }
            let mime = store::sniff(&img.bytes);
            if !CODEX_INPUT_MIMES.contains(&mime) {
                return Err(format!("Invalid image input for Codex image editing: {} is not a supported image", img.name));
            }
            inputs.push(json!({"image_url": store::data_url(mime, &img.bytes)}));
        }
        let (path, mut body) = (if inputs.is_empty() { "images/generations" } else { "images/edits" }, json!({"prompt": req.prompt, "model": model, "n": 1, "quality": quality, "size": size, "background": req.background.clone().unwrap_or_else(|| "opaque".into())}));
        if !inputs.is_empty() {
            body["images"] = json!(inputs);
        }
        let mut images = vec![];
        let mut ids = vec![];
        for _ in 0..req.count.clamp(1, 4) {
            let mut h = codex_headers(c, token);
            h.push(("x-codex-image-turn-id".into(), store::stem("turn")));
            let raw = serde_json::to_vec(&body).unwrap_or_default();
            let r = m.http.send("POST", &c.url(path), &h, Some(("application/json", &raw)))?;
            if !r.ok() {
                return Err(format!("OpenAI image generation via Codex auth failed: Codex images API returned HTTP {}: {}", r.status, crate::http::error_message(&r.text())));
            }
            let reqid = r.header("x-codex-imagegen-request-id").map(str::to_string);
            let v = r.json()?;
            let b64 = v["data"][0]["b64_json"].as_str().filter(|s| !s.is_empty()).ok_or("Codex images API response contained no image data")?;
            images.push(Asset::new(store::b64_decode(b64)?, "image/png"));
            ids.push(json!({"imagegen_request_id": reqid, "reported_quality": v["quality"], "reported_size": v["size"]}));
        }
        Ok(ImageResult { images, model: model.into(), meta: json!({"size": size, "quality": quality, "requested_size": size, "input_image_count": req.inputs.len(), "responses": ids}) })
    }

    fn responses(&self, m: &Media, c: &Creds, token: &str, req: &ImageRequest, model: &str) -> Result<ImageResult, String> {
        let size = resolve_size(model, req, true);
        let mut content = vec![json!({"type": "input_text", "text": req.prompt})];
        content.extend(req.inputs.iter().map(|i| json!({"type": "input_image", "image_url": i.data_url(), "detail": "auto"})));
        let mut tool = Map::new();
        tool.insert("type".into(), json!("image_generation"));
        tool.insert("model".into(), json!(model));
        tool.insert("size".into(), json!(size));
        tool.extend(options(req, None));
        let mut retry: Vec<String> = c.str("responses_model").into_iter().collect();
        retry.push(CODEX_RESPONSES_MODEL.into());
        let mut images = vec![];
        for _ in 0..req.count.clamp(1, 4) {
            let mut rm = retry[0].clone();
            let mut rest: Vec<String> = retry[1..].to_vec();
            loop {
                let body = json!({"model": rm, "input": [{"role": "user", "content": content}], "instructions": CODEX_INSTRUCTIONS, "tools": [Value::Object(tool.clone())], "tool_choice": {"type": "image_generation"}, "stream": true, "store": false});
                let mut h = codex_headers(c, token);
                h.push(("accept".into(), "text/event-stream".into()));
                let raw = serde_json::to_vec(&body).unwrap_or_default();
                let r = m.http.send("POST", &c.url("responses"), &h, Some(("application/json", &raw)))?;
                if r.status == 400 && r.text().contains(&format!("The '{rm}' model is not supported when using Codex with a ChatGPT account.")) && !rest.is_empty() {
                    rm = rest.remove(0);
                    continue;
                }
                let r = r.check("OpenAI Codex image generation failed")?;
                images.extend(parse_codex_sse(&r.text(), output_mime(req))?);
                break;
            }
        }
        Ok(ImageResult { images, model: model.into(), meta: json!({"size": size, "transport": "codex-responses"}) })
    }
}

impl ImageProvider for Codex {
    fn id(&self) -> &'static str {
        "openai-codex"
    }
    fn label(&self) -> &'static str {
        "OpenAI (Codex auth)"
    }
    fn env(&self) -> &'static [&'static str] {
        &[]
    }
    fn default_base(&self) -> &'static str {
        CODEX_BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.openai-codex.model").unwrap_or_else(|| DEFAULT_TIER.into())
    }
    fn models(&self) -> Vec<String> {
        ["gpt-image-2-low", "gpt-image-2-medium", "gpt-image-2-high"].map(String::from).to_vec()
    }
    fn configured(&self, m: &Media) -> bool {
        codex_creds(m).key.is_some()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 4, edit: true, max_inputs: 16, supports_size: true, sizes: vec![], formats: vec!["png", "jpeg", "webp"], qualities: QUALITIES.to_vec(), backgrounds: vec!["transparent", "opaque", "auto"], ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = codex_creds(m);
        let token = c.key.clone().ok_or("No Codex/ChatGPT OAuth credentials available. Sign in with the Codex CLI (`codex login`, ~/.codex/auth.json) or set [media.providers.openai-codex] api_key.")?;
        let (model, q) = tier(&super::common::model_or(req, &self.default_model(m)));
        let quality = req.quality.clone().or(q).unwrap_or_else(|| "medium".into());
        match c.str("transport").as_deref() {
            Some("responses") => self.responses(m, &c, &token, req, &model),
            _ => self.native(m, &c, &token, req, &model, &quality),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_and_sizes() {
        assert_eq!(tier("gpt-image-2-high"), ("gpt-image-2".into(), Some("high".into())));
        assert_eq!(tier("gpt-image-2.5-flare-xhigh"), ("gpt-image-2.5-flare".into(), Some("xhigh".into())));
        assert_eq!(tier("gpt-image-1"), ("gpt-image-1".into(), None));
        assert!(valid_flexible("gpt-image-2", "1280x720") && !valid_flexible("gpt-image-2", "100x100"));
        let r = ImageRequest { size: Some("1792x1024".into()), ..Default::default() };
        assert_eq!(resolve_size("gpt-image-1", &r, true), "1536x1024");
        assert!(is_azure("https://x.openai.azure.com/openai") && !is_azure(BASE));
    }

    #[test]
    fn codex_sse_parsing() {
        let b64 = store::b64(b"\x89PNG\r\n\x1a\nzz");
        let body = format!("data: {{\"type\":\"response.output_item.done\",\"item\":{{\"type\":\"image_generation_call\",\"status\":\"completed\",\"result\":\"{b64}\"}}}}\n\ndata: {{\"type\":\"response.completed\",\"response\":{{\"output\":[{{\"type\":\"image_generation_call\",\"status\":\"completed\",\"result\":\"{b64}\",\"revised_prompt\":\"rp\"}}]}}}}\n\n");
        let imgs = parse_codex_sse(&body, "image/png").unwrap();
        assert_eq!((imgs.len(), imgs[0].revised_prompt.as_deref()), (1, Some("rp")));
        let e = parse_codex_sse("data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"refusal\",\"refusal\":\"no\"}]}]}}\n\n", "image/png").unwrap_err();
        assert!(e.contains("refused by provider"), "{e}");
        assert!(parse_codex_sse("data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n", "image/png").unwrap_err().contains("boom"));
    }

    #[test]
    fn jwt_account_headers() {
        let claims = store::b64(br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acc1","chatgpt_compute_residency":"eu"}}"#).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
        let h = codex_account_headers(&format!("h.{claims}.s"));
        assert_eq!(h, vec![("ChatGPT-Account-ID".to_string(), "acc1".to_string()), ("x-openai-internal-codex-residency".to_string(), "eu".to_string())]);
    }
}
