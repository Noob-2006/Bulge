//! FAL.ai: the Hermes catalog models (payload whitelists, edit endpoints, Clarity
//! upscaler, queue API) plus OpenClaw's generic FAL schemas for any other model id
//! (flux image-to-image, Krea 2 style references, Nano Banana, Grok Imagine, GPT Image 2.5).
//! Queue protocol: `POST {queue}/{model}` → `{request_id, status_url, response_url}`,
//! poll `status_url` until `COMPLETED`, then `GET response_url`.

use super::catalog::{self, SizeStyle};
use super::common::require_key;
use super::{parse_ratio, Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::Asset;
use crate::{Creds, Media};
use seagent_core::Cancel;
use serde_json::{json, Map, Value};
use std::time::Duration;

pub struct Fal;

const ENV: &[&str] = &["FAL_KEY", "FAL_API_KEY"];
const QUEUE_BASE: &str = "https://queue.fal.run";
const SYNC_BASE: &str = "https://fal.run";

const FAL_ASPECTS: &[&str] = &["1:1", "2:3", "3:2", "2.35:1", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9", "4:1", "1:4", "8:1", "1:8"];
const KREA_ASPECTS: &[&str] = &["1:1", "4:3", "3:2", "16:9", "2.35:1", "4:5", "2:3", "9:16"];
const NANO_LEGACY_ASPECTS: &[&str] = &["21:9", "16:9", "3:2", "4:3", "5:4", "1:1", "4:5", "3:4", "2:3", "9:16"];
const NANO_ASPECTS: &[&str] = &["21:9", "16:9", "3:2", "4:3", "5:4", "1:1", "4:5", "3:4", "2:3", "9:16", "4:1", "1:4", "8:1", "1:8"];
const GROK_ASPECTS: &[&str] = &["2:1", "20:9", "19.5:9", "16:9", "4:3", "3:2", "1:1", "2:3", "3:4", "9:16", "9:19.5", "9:20", "1:2"];
const GPT25: &[&str] = &["openai/gpt-image-2.5/flare/text-to-image", "openai/gpt-image-2.5/flare/edit", "openai/gpt-image-2.5/sunburst/text-to-image", "openai/gpt-image-2.5/sunburst/edit"];

/// OpenClaw `FalImageModelSchema` for models outside the Hermes catalog.
#[derive(Debug, Clone, PartialEq)]
struct Schema {
    native_aspect: bool,
    aspects: Option<&'static [&'static str]>,
    /// None = any; Some(empty) = none allowed.
    resolutions: Option<&'static [&'static str]>,
    lower_resolution: bool,
    refs: &'static str,
    max_inputs: usize,
    label: &'static str,
    noun: &'static str,
    edit_suffix: Option<&'static str>,
    count: bool,
    output_format: bool,
}

fn schema(model: &str) -> Schema {
    let edit = Schema { native_aspect: false, aspects: None, resolutions: None, lower_resolution: false, refs: "image_urls", max_inputs: 10, label: "", noun: "reference image", edit_suffix: Some("edit"), count: true, output_format: true };
    if GPT25.contains(&model) {
        return Schema { max_inputs: 16, label: "fal GPT Image 2.5 edit", ..edit };
    }
    if model.starts_with("krea/v2/") {
        return Schema { native_aspect: true, aspects: Some(KREA_ASPECTS), resolutions: None, lower_resolution: false, refs: "image_style_references", max_inputs: 10, label: "fal Krea 2", noun: "style reference", edit_suffix: None, count: false, output_format: false };
    }
    if model == "fal-ai/nano-banana" || model.starts_with("fal-ai/nano-banana/") {
        return Schema { native_aspect: true, aspects: Some(NANO_LEGACY_ASPECTS), resolutions: Some(&[]), max_inputs: 3, label: "fal Nano Banana", ..edit };
    }
    if model.starts_with("openai/gpt-image-") || model.starts_with("fal-ai/nano-banana-") {
        let nano = model.starts_with("fal-ai/nano-banana-");
        return Schema { native_aspect: nano, aspects: nano.then_some(NANO_ASPECTS), max_inputs: if nano { 14 } else { 10 }, label: if nano { "fal Nano Banana 2" } else { "fal GPT Image edit" }, ..edit };
    }
    if model.starts_with("google/nano-banana-2-lite") {
        return Schema { native_aspect: true, aspects: Some(NANO_ASPECTS), resolutions: Some(&[]), max_inputs: 14, label: "fal Nano Banana 2 Lite", ..edit };
    }
    if model.starts_with("xai/grok-imagine-image") {
        return Schema { native_aspect: true, aspects: Some(GROK_ASPECTS), resolutions: Some(&["1K", "2K"]), lower_resolution: true, max_inputs: 3, label: "fal Grok Imagine", ..edit };
    }
    Schema { native_aspect: false, aspects: None, resolutions: None, lower_resolution: false, refs: "image_url", max_inputs: 1, label: "fal flux image generation currently", noun: "reference image", edit_suffix: Some("image-to-image"), count: true, output_format: true }
}

fn edit_path(model: &str, s: &Schema) -> String {
    let Some(suffix) = s.edit_suffix else { return model.to_string() };
    if GPT25.contains(&model) {
        return model.trim_end_matches("/text-to-image").to_string() + "/edit";
    }
    if model.contains("/image-to-image/") || [suffix, "edit", "image-to-image"].iter().any(|x| model.ends_with(&format!("/{x}"))) {
        model.to_string()
    } else {
        format!("{model}/{suffix}")
    }
}

fn ratio_dims(ar: &str, edge: u32) -> Result<(u32, u32), String> {
    let (w, h) = parse_ratio(ar).ok_or_else(|| format!("Invalid fal aspect ratio: {ar}"))?;
    Ok(if w >= h { (edge, ((edge as f64 * h / w).round() as u32).max(1)) } else { (((edge as f64 * w / h).round() as u32).max(1), edge) })
}

fn preset_for(ar: &str) -> Option<&'static str> {
    Some(match ar {
        "1:1" => "square_hd",
        "4:3" => "landscape_4_3",
        "3:4" => "portrait_4_3",
        "16:9" => "landscape_16_9",
        "9:16" => "portrait_16_9",
        _ => return None,
    })
}

fn openclaw_image_size(req: &ImageRequest) -> Result<Option<Value>, String> {
    if let Some((w, h)) = req.size.as_deref().and_then(super::parse_size) {
        return Ok(Some(json!({"width": w, "height": h})));
    }
    let edge = req.resolution.as_deref().map(|r| match r {
        "4K" => 4096,
        "2K" => 2048,
        _ => 1024,
    });
    if let Some(ar) = req.aspect_ratio.as_deref() {
        if let (Some(e), false) = (edge, req.is_edit()) {
            let (w, h) = ratio_dims(ar, e)?;
            return Ok(Some(json!({"width": w, "height": h})));
        }
        return Ok(Some(match preset_for(ar) {
            Some(p) => json!(p),
            None => {
                let (w, h) = ratio_dims(ar, 1024)?;
                json!({"width": w, "height": h})
            }
        }));
    }
    Ok(edge.map(|e| json!({"width": e, "height": e})))
}

fn validate_gpt25(size: &Value) -> Result<(), String> {
    let (Some(w), Some(h)) = (size["width"].as_u64(), size["height"].as_u64()) else { return Ok(()) };
    let px = w * h;
    if w % 16 != 0 || h % 16 != 0 || w.max(h) > 3840 || !(655_360..=8_294_400).contains(&px) || w > h * 3 || h > w * 3 {
        return Err("fal GPT Image 2.5 requires size dimensions divisible by 16, edges up to 3840, 655360-8294400 pixels, and aspect ratio between 1:3 and 3:1. Use size 1024x1024, 1536x1024, 1024x1536, or auto instead of incompatible geometry hints.".into());
    }
    Ok(())
}

/// `(endpoint, body)` for a model outside the catalog (OpenClaw buildFalImageGenerationProvider).
fn openclaw_body(req: &ImageRequest, requested: &str) -> Result<(String, Value), String> {
    let s = schema(requested);
    let gpt25 = GPT25.contains(&requested);
    if gpt25 && req.resolution.is_some() {
        return Err("fal GPT Image 2.5 does not support resolution overrides; use size instead".into());
    }
    if gpt25 && req.size.as_deref().is_some_and(|z| z != "auto" && super::parse_size(z).is_none()) {
        return Err("fal GPT Image 2.5 size must be WIDTHxHEIGHT or auto".into());
    }
    let size = if gpt25 && req.size.as_deref() == Some("auto") {
        Some(json!("auto"))
    } else if gpt25 && req.size.is_none() && req.aspect_ratio.is_some() {
        let (w, h) = ratio_dims(req.aspect_ratio.as_deref().unwrap_or("1:1"), 1536)?;
        Some(json!({"width": ((w as f64 / 16.0).round() as u32) * 16, "height": ((h as f64 / 16.0).round() as u32) * 16}))
    } else {
        openclaw_image_size(req)?
    };
    if gpt25 {
        if let Some(sz) = &size {
            validate_gpt25(sz)?;
        }
    }
    let endpoint = if req.is_edit() { edit_path(requested, &s) } else { requested.to_string() };
    if req.is_edit() && req.inputs.len() > s.max_inputs {
        let (lim, noun) = if s.max_inputs == 1 { ("one".to_string(), s.noun.to_string()) } else { (s.max_inputs.to_string(), format!("{}s", s.noun)) };
        return Err(format!("{} supports at most {lim} {noun} (requested {})", s.label, req.inputs.len()));
    }
    if req.is_edit() && s.refs == "image_url" && req.aspect_ratio.is_some() {
        return Err("fal flux image edit endpoint does not support aspectRatio overrides".into());
    }
    if !s.count && req.count > 1 {
        return Err(format!("fal {requested} supports one output image per request"));
    }
    if !s.output_format && req.output_format.is_some() {
        return Err(format!("fal {requested} does not support outputFormat overrides"));
    }
    let mut b = Map::new();
    b.insert("prompt".into(), json!(req.prompt));
    if s.count {
        b.insert("num_images".into(), json!(req.count));
    }
    if s.output_format {
        b.insert("output_format".into(), json!(req.output_format.clone().unwrap_or_else(|| "png".into())));
    }
    if gpt25 {
        if let Some(q) = &req.quality {
            b.insert("quality".into(), json!(q));
        }
        if let Some(bg) = &req.background {
            b.insert("background".into(), json!(bg));
        }
    }
    if s.refs == "image_style_references" {
        let c = req.opt_str("fal.creativity").or_else(|| req.opt_str("creativity")).filter(|c| ["raw", "low", "medium", "high"].contains(&c.as_str())).unwrap_or_else(|| "medium".into());
        b.insert("creativity".into(), json!(c));
    }
    if s.native_aspect {
        if req.resolution.is_some() && s.refs == "image_style_references" {
            return Err("fal Krea 2 supports aspectRatio but not resolution overrides".into());
        }
        let ar = match req.aspect_ratio.as_deref() {
            Some(a) => {
                if let Some(allowed) = s.aspects {
                    if !allowed.contains(&a) {
                        return Err(format!("{} supports aspectRatio values: {}", s.label, allowed.join(", ")));
                    }
                }
                Some(a.to_string())
            }
            None => match (s.aspects, req.size.as_deref().and_then(super::parse_size)) {
                (Some(allowed), Some((w, h))) => super::closest_ratio(w as f64, h as f64, allowed).map(str::to_string),
                _ => None,
            },
        };
        if let Some(a) = ar {
            b.insert("aspect_ratio".into(), json!(a));
        }
        if let (Some(r), "image_urls") = (&req.resolution, s.refs) {
            match s.resolutions {
                None => {
                    b.insert("resolution".into(), json!(r));
                }
                Some([]) => return Err(format!("{} does not support resolution overrides", s.label)),
                Some(allowed) if !allowed.contains(&r.as_str()) => return Err(format!("{} supports resolution values: {}", s.label, allowed.join(", "))),
                Some(_) => {
                    b.insert("resolution".into(), json!(if s.lower_resolution { r.to_ascii_lowercase() } else { r.clone() }));
                }
            }
        }
    } else if let Some(sz) = size {
        b.insert("image_size".into(), sz);
    }
    if req.is_edit() {
        let enc: Vec<String> = req.inputs.iter().map(|i| i.url_or_data()).collect();
        match s.refs {
            "image_urls" => {
                b.insert("image_urls".into(), json!(enc));
            }
            "image_style_references" => {
                b.insert("image_style_references".into(), json!(enc.iter().map(|u| json!({"image_url": u})).collect::<Vec<_>>()));
            }
            _ => {
                b.insert("image_url".into(), json!(enc[0]));
            }
        }
    }
    if let Some(seed) = req.seed {
        b.insert("seed".into(), json!(seed));
    }
    Ok((endpoint, Value::Object(b)))
}

/// `(endpoint, body)` for a Hermes catalog model (whitelisted payload).
fn hermes_body(req: &ImageRequest, meta: &catalog::FalModel) -> Result<(String, Value), String> {
    if req.is_edit() && meta.edit_endpoint.is_none() {
        return Err(format!("Model '{}' ({}) is not capable of image-to-image / editing. Provide a text-only prompt (omit image), or switch to an edit-capable model.", meta.display, meta.id));
    }
    let edit = req.is_edit();
    let supports: &[&str] = if edit { meta.edit_supports } else { meta.supports };
    let mut payload = meta.defaults.as_object().cloned().unwrap_or_default();
    payload.insert("prompt".into(), json!(req.prompt.trim()));
    let mut required = vec!["prompt"];
    if edit {
        let max = meta.max_refs.max(1);
        let srcs: Vec<String> = req.inputs.iter().take(max).map(|i| i.url_or_data()).collect();
        if meta.edit_image_param == "image_urls" {
            payload.insert("image_urls".into(), json!(srcs));
        } else {
            payload.insert(meta.edit_image_param.into(), json!(srcs[0]));
        }
        required.push(meta.edit_image_param);
    }
    let size_key = match meta.style {
        SizeStyle::Preset | SizeStyle::Literal => "image_size",
        SizeStyle::Aspect => "aspect_ratio",
    };
    if !edit || supports.contains(&size_key) {
        payload.insert(size_key.into(), meta.size_for(&req.semantic_aspect).clone());
    }
    if let Some(seed) = req.seed {
        payload.insert("seed".into(), json!(seed));
    }
    let mut overrides: Vec<(&str, Value)> = vec![];
    if let Some(v) = req.opt("num_inference_steps") {
        overrides.push(("num_inference_steps", v.clone()));
    }
    if let Some(v) = req.opt("guidance_scale") {
        overrides.push(("guidance_scale", v.clone()));
    }
    if req.count > 1 {
        overrides.push(("num_images", json!(req.count)));
    }
    if let Some(f) = &req.output_format {
        overrides.push(("output_format", json!(f)));
    }
    if let Some(q) = &req.quality {
        overrides.push(("quality", json!(q)));
    }
    if let Some(bg) = &req.background {
        overrides.push(("background", json!(bg)));
    }
    if let Some(r) = &req.resolution {
        overrides.push(("resolution", json!(if meta.id.starts_with("xai/") { r.to_ascii_lowercase() } else { r.clone() })));
    }
    if let Some(c) = req.opt_str("creativity").or_else(|| req.opt_str("fal.creativity")) {
        overrides.push(("creativity", json!(c)));
    }
    for (k, v) in overrides {
        payload.insert(k.into(), v);
    }
    payload.retain(|k, _| supports.contains(&k.as_str()) || required.contains(&k.as_str()));
    let endpoint = if edit { meta.edit_endpoint.unwrap_or(meta.id).to_string() } else { meta.id.to_string() };
    Ok((endpoint, Value::Object(payload)))
}

fn headers(c: &Creds, key: &str) -> Vec<(String, String)> {
    let mut h = c.headers.clone();
    h.insert(0, ("authorization".into(), format!("Key {key}")));
    h.push(("x-idempotency-key".into(), crate::store::stem("seagent")));
    h
}

/// Submit and wait (queue) or call synchronously; returns the result JSON.
#[allow(clippy::too_many_arguments)]
pub fn run(m: &Media, c: &Creds, key: &str, endpoint: &str, args: &Value, poll: Duration, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
    let h = headers(c, key);
    let first = m.http.post_json(&c.url(endpoint), &h, args).map_err(|e| format!("fal image generation failed: {e}"))?;
    if first.get("images").is_some() || first.get("image").is_some() || first.get("request_id").is_none() {
        return Ok(first);
    }
    let id = first["request_id"].as_str().unwrap_or_default().to_string();
    let app: String = endpoint.split('/').take(2).collect::<Vec<_>>().join("/");
    let status_url = first["status_url"].as_str().map(str::to_string).unwrap_or_else(|| c.url(&format!("{app}/requests/{id}/status")));
    let response_url = first["response_url"].as_str().map(str::to_string).unwrap_or_else(|| c.url(&format!("{app}/requests/{id}")));
    let auth = vec![h[0].clone()];
    crate::http::poll(cancel, poll, timeout, || {
        let s = m.http.get_json(&status_url, &auth).map_err(|e| format!("fal queue status failed: {e}"))?;
        match s["status"].as_str().unwrap_or("") {
            "COMPLETED" => {
                if let Some(err) = s["error"].as_str().filter(|e| !e.is_empty()) {
                    return Err(format!("fal request {id} failed: {err}"));
                }
                Ok(Some(()))
            }
            "FAILED" | "ERROR" | "CANCELLED" => Err(format!("fal request {id} failed: {}", s["error"].as_str().unwrap_or("unknown error"))),
            _ => Ok(None),
        }
    })?;
    m.http.get_json(&response_url, &auth).map_err(|e| format!("fal result fetch failed: {e}"))
}

fn creds(m: &Media) -> Creds {
    let queue = m.creds("fal", ENV, "").extra.get("queue").and_then(|v| v.as_bool()).unwrap_or(true);
    m.creds("fal", ENV, if queue { QUEUE_BASE } else { SYNC_BASE })
}

fn download_all(m: &Media, entries: &[Value]) -> Result<Vec<Asset>, String> {
    let mut out = Vec::new();
    for e in entries {
        let url = e["url"].as_str().filter(|u| !u.is_empty()).ok_or("fal image generation response malformed")?;
        let (bytes, ct) = m.download(url, &[]).map_err(|e| format!("fal image download failed: {e}"))?;
        let mut a = Asset::new(bytes, if ct.starts_with("image/") { &ct } else { "" });
        a.url = Some(url.to_string());
        a.meta = json!({"width": e["width"], "height": e["height"]});
        out.push(a);
    }
    Ok(out)
}

fn upscale(m: &Media, c: &Creds, key: &str, url: &str, prompt: &str, req: &ImageRequest, cancel: &Cancel) -> Option<Asset> {
    let args = json!({
        "image_url": url, "prompt": format!("{}, {prompt}", catalog::UPSCALER_DEFAULT_PROMPT),
        "upscale_factor": catalog::UPSCALER_FACTOR, "negative_prompt": catalog::UPSCALER_NEGATIVE_PROMPT,
        "creativity": catalog::UPSCALER_CREATIVITY, "resemblance": catalog::UPSCALER_RESEMBLANCE,
        "guidance_scale": catalog::UPSCALER_GUIDANCE_SCALE, "num_inference_steps": catalog::UPSCALER_NUM_INFERENCE_STEPS,
        "enable_safety_checker": false,
    });
    let r = run(m, c, key, catalog::UPSCALER_MODEL, &args, req.poll_or(1000), req.timeout, cancel).ok()?;
    let img = r.get("image")?;
    let mut a = download_all(m, std::slice::from_ref(img)).ok()?.pop()?;
    a.meta = json!({"width": img["width"], "height": img["height"], "upscaled": true, "upscale_factor": catalog::UPSCALER_FACTOR});
    Some(a)
}

impl ImageProvider for Fal {
    fn id(&self) -> &'static str {
        "fal"
    }
    fn label(&self) -> &'static str {
        "FAL.ai"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        QUEUE_BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.fal.model").or_else(|| std::env::var("FAL_IMAGE_MODEL").ok().filter(|s| !s.trim().is_empty())).unwrap_or_else(|| catalog::DEFAULT_MODEL.into())
    }
    fn models(&self) -> Vec<String> {
        let mut v: Vec<String> = catalog::models().iter().map(|m| format!("{} ({}; {}; {}; {})", m.id, m.display, m.speed, m.strengths, m.price)).collect();
        v.extend(["fal-ai/flux/dev", "fal-ai/flux/dev/image-to-image", "krea/v2/medium/text-to-image", "krea/v2/large/text-to-image", "fal-ai/nano-banana", "xai/grok-imagine-image"].map(String::from));
        v
    }
    fn caps(&self, model: &str) -> Caps {
        if let Some(meta) = catalog::find(model) {
            return Caps {
                max_count: 4,
                edit: meta.edit_endpoint.is_some(),
                max_inputs: meta.max_refs,
                supports_size: true,
                supports_aspect: true,
                supports_resolution: meta.supports.contains(&"resolution"),
                qualities: if meta.supports.contains(&"quality") { vec!["low", "medium", "high", "xhigh", "max", "auto"] } else { vec![] },
                formats: if meta.supports.contains(&"output_format") { vec!["png", "jpeg", "webp"] } else { vec![] },
                backgrounds: if meta.supports.contains(&"background") { vec!["transparent", "opaque", "auto"] } else { vec![] },
                ..Caps::default()
            };
        }
        let s = schema(model);
        let gpt25 = GPT25.contains(&model);
        Caps {
            max_count: if s.count { 4 } else { 1 },
            edit: true,
            max_inputs: s.max_inputs,
            supports_size: true,
            supports_aspect: true,
            supports_resolution: !gpt25 && !matches!(s.resolutions, Some([])) && s.refs != "image_style_references",
            sizes: if gpt25 || s.refs == "image_style_references" { vec![] } else { vec!["1024x1024", "1024x1536", "1536x1024", "1024x1792", "1792x1024"] },
            aspect_ratios: s.aspects.map(|a| a.to_vec()).unwrap_or_else(|| FAL_ASPECTS.to_vec()),
            resolutions: s.resolutions.map(|r| r.to_vec()).unwrap_or_else(|| vec!["1K", "2K", "4K"]),
            qualities: if gpt25 { vec!["low", "medium", "high", "xhigh", "max", "auto"] } else { vec![] },
            formats: if gpt25 { vec!["png", "jpeg", "webp"] } else if s.output_format { vec!["png", "jpeg"] } else { vec![] },
            backgrounds: if gpt25 { vec!["transparent", "opaque", "auto"] } else { vec![] },
        }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, cancel: &Cancel) -> Result<ImageResult, String> {
        let c = creds(m);
        let key = require_key(&c, ENV)?.to_string();
        let model = super::common::model_or(req, &self.default_model(m));
        let meta = catalog::find(&model);
        let (endpoint, args) = match &meta {
            Some(meta) => hermes_body(req, meta)?,
            None => openclaw_body(req, &model)?,
        };
        let r = run(m, &c, &key, &endpoint, &args, req.poll_or(500), req.timeout, cancel)?;
        let entries = r["images"].as_array().cloned().ok_or("Invalid response from FAL.ai API — no images returned")?;
        if entries.is_empty() {
            return Err("No images were generated".into());
        }
        let mut images = download_all(m, &entries)?;
        // Hermes: an explicit `upscale` wins (edits included); the catalog default never upscales
        // edits, because Clarity is a text-to-image pass that would alter the composition.
        let want_upscale = match req.upscale {
            Some(u) => u,
            None => c.extra.get("upscale").and_then(|v| v.as_bool()).unwrap_or(false) && !req.is_edit(),
        };
        let mut notes = vec![];
        if want_upscale {
            for (i, e) in entries.iter().enumerate() {
                match e["url"].as_str().and_then(|u| upscale(m, &c, &key, u, req.prompt.trim(), req, cancel)) {
                    Some(up) => images[i] = up,
                    None => notes.push("upscale failed; kept the original image".to_string()),
                }
            }
        }
        // Report the model the caller selected, not the (possibly `/edit`) endpoint that served it.
        Ok(ImageResult { images, model: model.clone(), meta: json!({"endpoint": endpoint, "prompt": r["prompt"], "upscaled": want_upscale && notes.is_empty(), "notes": notes}) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openclaw_schemas_and_paths() {
        assert_eq!(edit_path("fal-ai/flux/dev", &schema("fal-ai/flux/dev")), "fal-ai/flux/dev/image-to-image");
        assert_eq!(edit_path("openai/gpt-image-2.5/flare/text-to-image", &schema("openai/gpt-image-2.5/flare/text-to-image")), "openai/gpt-image-2.5/flare/edit");
        assert_eq!(edit_path("krea/v2/medium/text-to-image", &schema("krea/v2/medium/text-to-image")), "krea/v2/medium/text-to-image");
        let req = ImageRequest { prompt: "p".into(), aspect_ratio: Some("16:9".into()), resolution: Some("2K".into()), ..Default::default() };
        let (_, b) = openclaw_body(&req, "fal-ai/flux/dev").unwrap();
        assert_eq!(b["image_size"], json!({"width": 2048, "height": 1152}));
        let (_, b) = openclaw_body(&req, "xai/grok-imagine-image").unwrap();
        assert_eq!((b["aspect_ratio"].as_str(), b["resolution"].as_str()), (Some("16:9"), Some("2k")));
        let e = openclaw_body(&ImageRequest { prompt: "p".into(), resolution: Some("2K".into()), ..Default::default() }, "fal-ai/nano-banana").unwrap_err();
        assert!(e.contains("does not support resolution"), "{e}");
        let e = openclaw_body(&ImageRequest { prompt: "p".into(), size: Some("100x100".into()), ..Default::default() }, "openai/gpt-image-2.5/flare/text-to-image").unwrap_err();
        assert!(e.contains("divisible by 16"), "{e}");
    }

    #[test]
    fn hermes_payload_whitelist() {
        let meta = catalog::find("fal-ai/nano-banana-pro").unwrap();
        let req = ImageRequest { prompt: " cat ".into(), semantic_aspect: "portrait".into(), seed: Some(7), options: json!({"guidance_scale": 3}), ..Default::default() };
        let (ep, b) = hermes_body(&req, &meta).unwrap();
        assert_eq!(ep, "fal-ai/nano-banana-pro");
        assert_eq!((b["aspect_ratio"].as_str(), b["prompt"].as_str(), b["seed"].as_i64()), (Some("9:16"), Some("cat"), Some(7)));
        assert!(b.get("guidance_scale").is_none(), "not in whitelist");
        let z = catalog::find("fal-ai/z-image/turbo").unwrap();
        let e = hermes_body(&ImageRequest { prompt: "x".into(), inputs: vec![super::super::InputImage { bytes: vec![1], mime: "image/png".into(), ..Default::default() }], ..Default::default() }, &z).unwrap_err();
        assert!(e.contains("not capable of image-to-image"));
        let k = catalog::find("fal-ai/kling-image/v3/text-to-image").unwrap();
        let req = ImageRequest { prompt: "x".into(), inputs: vec![super::super::InputImage { bytes: vec![1], mime: "image/png".into(), url: Some("https://e/a.png".into()), ..Default::default() }], ..Default::default() };
        let (ep, b) = hermes_body(&req, &k).unwrap();
        assert_eq!((ep.as_str(), b["image_url"].as_str()), ("fal-ai/kling-image/v3/image-to-image", Some("https://e/a.png")));
    }
}
