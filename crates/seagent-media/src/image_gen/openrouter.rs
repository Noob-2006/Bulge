//! OpenRouter: chat-completions image output (`modalities: ["image","text"]`) and the
//! dedicated Image API (`POST /images/generations`, own catalog at `GET /images/models`).
//! Hermes `plugins/image_gen/openrouter` (curated Image API knobs, default model chain)
//! + OpenClaw `openrouter/image-generation-provider.ts` (response shapes).

use super::common::require_key;
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::{self, Asset};
use crate::{Creds, Media};
use seagent_core::Cancel;
use serde_json::{json, Map, Value};

pub struct OpenRouter;

const ENV: &[&str] = &["OPENROUTER_API_KEY"];
const BASE: &str = "https://openrouter.ai/api/v1";
const DEFAULT_MODEL: &str = "openai/gpt-5.4-image-2";
const FALLBACK_MODEL: &str = "google/gemini-3-pro-image";
const CHAT_ONLY: &[&str] = &[DEFAULT_MODEL, FALLBACK_MODEL, "google/gemini-3.1-flash-image-preview", "google/gemini-3-pro-image-preview"];
const FALLBACK_STATUSES: &[u16] = &[402, 404, 408, 409, 425, 429, 500, 502, 503, 504];

const GEMINI_RATIOS: &[&str] = &["1:1", "1:4", "1:8", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4", "8:1", "9:16", "16:9", "21:9"];
const MAI_RATIOS: &[&str] = &["1:1", "4:3", "3:4", "16:9", "9:16", "3:2", "2:3", "auto"];
const KREA_RATIOS: &[&str] = &["1:1", "4:3", "3:2", "16:9", "4:5", "2:3", "9:16"];
const OPENAI_QUALITY: &[&str] = &["auto", "low", "medium", "high"];
/// Union of exact ratios the Image API accepts (Hermes `_ENDPOINT_ASPECT_RATIOS`): an override for a
/// model whose enum the curated catalog does not describe is kept only when it is in this set.
const ENDPOINT_ASPECT_RATIOS: &[&str] = &["1:1", "1:2", "1:4", "1:8", "2:1", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4", "8:1", "9:16", "16:9", "9:19.5", "19.5:9", "9:20", "20:9", "9:21", "21:9", "auto"];

/// A curated Image API model (Hermes `_IMAGE_API_MODELS`).
pub(super) struct ApiModel {
    id: &'static str,
    ratios: &'static [&'static str],
    resolutions: &'static [&'static str],
    quality: &'static [&'static str],
    background: &'static [&'static str],
    compression: bool,
    seed: bool,
    max_n: u32,
    max_refs: usize,
}

const fn am(id: &'static str, ratios: &'static [&'static str], resolutions: &'static [&'static str], max_n: u32, max_refs: usize) -> ApiModel {
    ApiModel { id, ratios, resolutions, quality: &[], background: &[], compression: false, seed: false, max_n, max_refs }
}

const API_MODELS: &[ApiModel] = &[
    am("google/gemini-3.1-flash-lite-image", GEMINI_RATIOS, &["1K"], 1, 14),
    am("google/gemini-3.1-flash-image", GEMINI_RATIOS, &["512", "1K", "2K", "4K"], 1, 14),
    ApiModel { id: "openai/gpt-image-2", ratios: &["1:1", "3:2", "2:3", "4:3", "3:4", "16:9", "9:16", "21:9", "auto"], resolutions: &[], quality: OPENAI_QUALITY, background: &["auto", "opaque"], compression: true, seed: false, max_n: 10, max_refs: 16 },
    ApiModel { id: "openai/gpt-image-1-mini", ratios: &["1:1", "3:2", "2:3", "auto"], resolutions: &[], quality: OPENAI_QUALITY, background: &["auto", "transparent", "opaque"], compression: true, seed: false, max_n: 10, max_refs: 16 },
    am("microsoft/mai-image-2.5", MAI_RATIOS, &[], 1, 1),
    am("microsoft/mai-image-2.5-pro", MAI_RATIOS, &[], 1, 1),
    am("x-ai/grok-imagine-image-quality", &["1:1", "3:4", "4:3", "9:16", "16:9", "2:3", "3:2", "9:19.5", "19.5:9", "9:20", "20:9", "1:2", "2:1", "auto"], &["1K", "2K"], 1, 3),
    ApiModel { seed: true, ..am("krea/krea-2-medium", KREA_RATIOS, &["1K"], 1, 1) },
    ApiModel { seed: true, ..am("krea/krea-2-medium-turbo", KREA_RATIOS, &["1K"], 1, 1) },
    ApiModel { seed: true, ..am("qwen/qwen-image-3-pro", &["1:1", "1:2", "1:4", "2:1", "2:3", "3:2", "3:4", "4:1", "4:3", "4:5", "5:4", "9:16", "16:9"], &["1K", "2K"], 6, 4) },
];

fn api_model(id: &str) -> Option<&'static ApiModel> {
    API_MODELS.iter().find(|m| m.id == id)
}

fn prefs(semantic: &str) -> &'static [&'static str] {
    match semantic {
        "landscape" => &["16:9", "3:2", "4:3", "5:4", "21:9", "2:1", "19.5:9", "20:9", "4:1", "8:1"],
        "portrait" => &["9:16", "2:3", "3:4", "4:5", "9:21", "1:2", "9:19.5", "9:20", "1:4", "1:8"],
        _ => &["1:1"],
    }
}

/// Image API body with every knob filtered against the model (Hermes _build_image_api_payload).
pub(super) fn api_payload(meta: Option<&ApiModel>, model: &str, req: &ImageRequest, refs: &[String], notes: &mut Vec<String>) -> Value {
    let mut p = Map::new();
    p.insert("model".into(), json!(model));
    p.insert("prompt".into(), json!(req.prompt));
    let supported: &[&str] = meta.map(|m| m.ratios).unwrap_or(&[]);
    let ratio = match req.aspect_ratio.as_deref() {
        Some(r) if supported.contains(&r) => Some(r.to_string()),
        forced => {
            // A model outside the catalog: Hermes keeps the ratio when the endpoint union lists it.
            let keep = forced.filter(|f| supported.is_empty() && ENDPOINT_ASPECT_RATIOS.contains(f)).map(str::to_string);
            if keep.is_none() {
                if let Some(f) = forced {
                    notes.push(format!("requested aspect_ratio '{f}' is unsupported by this model; used the '{}' mapping instead", req.semantic_aspect));
                }
            }
            if keep.is_some() {
                keep
            } else if supported.is_empty() {
                notes.push(format!("model is not in the curated catalog, so its aspect_ratio enum is unknown; the field was omitted and '{}' was not applied", req.semantic_aspect));
                None
            } else {
                prefs(&req.semantic_aspect).iter().find(|c| supported.contains(c)).map(|s| s.to_string()).or_else(|| Some(if supported.contains(&"auto") { "auto".into() } else { supported[0].to_string() }))
            }
        }
    };
    if let Some(r) = ratio {
        p.insert("aspect_ratio".into(), json!(r));
    }
    let mut enum_knob = |name: &str, value: Option<String>, allowed: &[&str]| {
        if let Some(v) = value {
            if allowed.is_empty() {
                notes.push(format!("'{name}' is not supported by this model; dropped"));
            } else if !allowed.contains(&v.as_str()) {
                notes.push(format!("'{name}={v}' is not valid for this model (accepts {}); dropped", allowed.join(", ")));
            } else {
                p.insert(name.into(), json!(v));
            }
        }
    };
    enum_knob("resolution", req.resolution.clone(), meta.map(|m| m.resolutions).unwrap_or(&[]));
    enum_knob("quality", req.quality.clone(), meta.map(|m| m.quality).unwrap_or(&[]));
    enum_knob("background", req.background.clone(), meta.map(|m| m.background).unwrap_or(&[]));
    if let Some(f) = &req.output_format {
        if meta.is_some_and(|m| m.compression) {
            p.insert("output_format".into(), json!(f));
        } else {
            notes.push("'output_format' is not supported by this model; dropped".into());
        }
    }
    if let Some(c) = req.opt_i64("openai.outputCompression") {
        if meta.is_some_and(|m| m.compression) {
            p.insert("output_compression".into(), json!(c.clamp(0, 100)));
        } else {
            notes.push("'output_compression' is not supported by this model; dropped".into());
        }
    }
    if let Some(s) = req.seed {
        if meta.is_some_and(|m| m.seed) {
            p.insert("seed".into(), json!(s));
        } else {
            notes.push("'seed' is not supported by this model; dropped".into());
        }
    }
    if req.count > 1 {
        let max = meta.map(|m| m.max_n).unwrap_or(1);
        if req.count > max {
            notes.push(format!("'n={}' exceeds this model's cap of {max}; clamped", req.count));
        }
        p.insert("n".into(), json!(req.count.min(max).max(1)));
    }
    if !refs.is_empty() {
        let max = meta.map(|m| m.max_refs).unwrap_or(16);
        if refs.len() > max {
            notes.push(format!("{} reference image(s) supplied but this model accepts {max}; extras dropped", refs.len()));
        }
        let used: Vec<Value> = refs.iter().take(max).map(|u| json!({"type": "image_url", "image_url": {"url": u}})).collect();
        if !used.is_empty() {
            p.insert("input_references".into(), json!(used));
        }
    }
    Value::Object(p)
}

/// Images from a chat-completions response (message.images, content parts, inline data URLs).
fn chat_images(v: &Value) -> Result<Vec<Asset>, String> {
    let mut out = vec![];
    let push_url = |u: &str, out: &mut Vec<Asset>| {
        if let Some((mime, b)) = store::decode_data_url(u) {
            out.push(Asset::new(b, &mime));
        } else if u.starts_with("http") {
            out.push(Asset::from_url(u, "image/png"));
        }
    };
    for ch in v["choices"].as_array().cloned().unwrap_or_default() {
        let msg = &ch["message"];
        for im in msg["images"].as_array().cloned().unwrap_or_default() {
            let u = im["image_url"]["url"].as_str().or_else(|| im["imageUrl"]["url"].as_str()).ok_or("OpenRouter image generation response malformed")?;
            push_url(u, &mut out);
        }
        match &msg["content"] {
            Value::String(s) => {
                let mut rest = s.as_str();
                while let Some(i) = rest.find("data:image/") {
                    let tail = &rest[i..];
                    let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || "+/=:;,.-_".contains(c))).unwrap_or(tail.len());
                    push_url(&tail[..end], &mut out);
                    rest = &tail[end..];
                }
            }
            Value::Array(parts) => {
                for p in parts {
                    if p["type"] == "image_url" {
                        if let Some(u) = p["image_url"]["url"].as_str() {
                            push_url(u, &mut out);
                        }
                    } else if let Some(b) = p["b64_json"].as_str() {
                        out.push(Asset::new(store::b64_decode(b)?, "image/png"));
                    } else if let Some(d) = p["inline_data"]["data"].as_str().or_else(|| p["inlineData"]["data"].as_str()) {
                        out.push(Asset::new(store::b64_decode(d)?, p["inline_data"]["mime_type"].as_str().or_else(|| p["inlineData"]["mimeType"].as_str()).unwrap_or("image/png")));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn headers(c: &Creds) -> Vec<(String, String)> {
    let mut h = c.bearer();
    h.push(("HTTP-Referer".into(), "https://github.com/Noob-2006/SE-Agent".into()));
    h.push(("X-Title".into(), "SE Agent".into()));
    h
}

/// Err((message, retryable)).
type Attempt = Result<ImageResult, (String, bool)>;

impl OpenRouter {
    fn surface(&self, m: &Media, c: &Creds, model: &str) -> &'static str {
        if CHAT_ONLY.contains(&model) {
            return "chat";
        }
        if api_model(model).is_some() {
            return "images";
        }
        match m.http.get_json(&c.url("images/models"), &headers(c)) {
            Ok(v) => {
                let ids: Vec<&str> = v["data"].as_array().or_else(|| v["models"].as_array()).map(|a| a.iter().filter_map(|e| e["id"].as_str()).collect()).unwrap_or_default();
                if ids.contains(&model) {
                    "images"
                } else {
                    "chat"
                }
            }
            Err(_) => "chat",
        }
    }

    fn via_images(&self, m: &Media, c: &Creds, model: &str, req: &ImageRequest) -> Attempt {
        let refs: Vec<String> = req.inputs.iter().map(|i| i.url_or_data()).collect();
        let mut notes = vec![];
        let body = api_payload(api_model(model), model, req, &refs, &mut notes);
        let raw = serde_json::to_vec(&body).unwrap_or_default();
        let r = m.http.send("POST", &c.url("images/generations"), &headers(c), Some(("application/json", &raw))).map_err(|e| (e, true))?;
        if !r.ok() {
            let msg = crate::http::error_message(&r.text());
            return Err(match r.status {
                401 | 403 => (format!("OpenRouter rejected the API key ({}): {msg}", r.status), false),
                404 => (format!("Model '{model}' does not exist on the OpenRouter Image API (its catalog is separate from chat-completions — check GET {}/images/models).", c.base), true),
                s => (format!("OpenRouter image generation failed ({s}): {msg}"), FALLBACK_STATUSES.contains(&s)),
            });
        }
        let v = r.json().map_err(|e| (e, false))?;
        let images = super::common::parse_openai_images(&v, "image/png", "OpenRouter").map_err(|e| (e, true))?;
        let mut meta = json!({"endpoint": "images/generations", "exact_aspect_ratio": body["aspect_ratio"], "notes": notes});
        if let Some(cost) = v["usage"]["cost"].as_f64() {
            meta["cost_usd"] = json!(cost);
        }
        Ok(ImageResult { images, model: model.into(), meta })
    }

    fn via_chat(&self, m: &Media, c: &Creds, model: &str, req: &ImageRequest) -> Attempt {
        let content: Value = if req.inputs.is_empty() {
            json!(req.prompt)
        } else {
            let mut parts = vec![json!({"type": "text", "text": req.prompt})];
            parts.extend(req.inputs.iter().map(|i| json!({"type": "image_url", "image_url": {"url": i.url_or_data()}})));
            json!(parts)
        };
        let mut body = json!({"model": model, "modalities": ["image", "text"], "messages": [{"role": "user", "content": content}]});
        if req.count > 1 {
            body["n"] = json!(req.count);
        }
        let mut ic = Map::new();
        ic.insert("aspect_ratio".into(), json!(req.aspect_ratio.clone().unwrap_or_else(|| super::ratio_of_semantic(&req.semantic_aspect))));
        if let Some(r) = &req.resolution {
            if model.starts_with("google/gemini-") {
                ic.insert("image_size".into(), json!(r));
            }
        }
        body["image_config"] = Value::Object(ic);
        let raw = serde_json::to_vec(&body).unwrap_or_default();
        let r = m.http.send("POST", &c.url("chat/completions"), &headers(c), Some(("application/json", &raw))).map_err(|e| (e, false))?;
        if !r.ok() {
            let msg = crate::http::error_message(&r.text());
            let access = model.starts_with("openai/") && matches!(r.status, 401 | 403 | 404) && !msg.to_ascii_lowercase().contains("api key");
            return Err(if access {
                (format!("OpenRouter: model '{model}' needs account access (OpenAI image models may require enablement or BYOK on OpenRouter): {msg}"), true)
            } else {
                (format!("OpenRouter image generation failed ({}): {msg}", r.status), false)
            });
        }
        let v = r.json().map_err(|e| (e, false))?;
        let images = chat_images(&v).map_err(|e| (e, false))?;
        if images.is_empty() {
            return Err((format!("OpenRouter returned no image. Ensure the model '{model}' supports image output."), true));
        }
        Ok(ImageResult { images, model: model.into(), meta: json!({"endpoint": "chat/completions"}) })
    }
}

impl ImageProvider for OpenRouter {
    fn id(&self) -> &'static str {
        "openrouter"
    }
    fn label(&self) -> &'static str {
        "OpenRouter"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.openrouter.model").or_else(|| std::env::var("OPENROUTER_IMAGE_MODEL").ok().filter(|s| !s.trim().is_empty())).unwrap_or_else(|| DEFAULT_MODEL.into())
    }
    fn models(&self) -> Vec<String> {
        let mut v: Vec<String> = CHAT_ONLY.iter().map(|s| s.to_string()).collect();
        v.extend(API_MODELS.iter().map(|m| m.id.to_string()));
        v
    }
    fn caps(&self, model: &str) -> Caps {
        let meta = api_model(model);
        Caps {
            max_count: 4,
            edit: true,
            max_inputs: meta.map(|m| m.max_refs).unwrap_or(5),
            supports_aspect: true,
            supports_resolution: true,
            aspect_ratios: vec![],
            resolutions: vec![],
            qualities: OPENAI_QUALITY.to_vec(),
            formats: vec!["png", "jpeg", "webp"],
            backgrounds: vec!["transparent", "opaque", "auto"],
            ..Caps::default()
        }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("openrouter", ENV, BASE);
        require_key(&c, ENV)?;
        let chain: Vec<String> = match &req.model {
            Some(x) if x != DEFAULT_MODEL => vec![x.clone()],
            _ => vec![DEFAULT_MODEL.into(), FALLBACK_MODEL.into()],
        };
        let mut last = String::new();
        for (i, model) in chain.iter().enumerate() {
            let r = match self.surface(m, &c, model) {
                "images" => self.via_images(m, &c, model, req),
                _ => self.via_chat(m, &c, model, req),
            };
            match r {
                Ok(mut res) => {
                    if i > 0 {
                        res.meta["fallback_from"] = json!(chain[0]);
                    }
                    return Ok(res);
                }
                Err((e, retry)) => {
                    last = e;
                    if !retry {
                        break;
                    }
                }
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_api_knobs_filtered() {
        let mut notes = vec![];
        let req = ImageRequest { prompt: "p".into(), semantic_aspect: "portrait".into(), background: Some("transparent".into()), seed: Some(1), count: 3, ..Default::default() };
        let b = api_payload(api_model("openai/gpt-image-2"), "openai/gpt-image-2", &req, &[], &mut notes);
        assert_eq!((b["aspect_ratio"].as_str(), b["n"].as_u64()), (Some("9:16"), Some(3)));
        assert!(b.get("background").is_none() && b.get("seed").is_none());
        assert!(notes.iter().any(|n| n.contains("background=transparent")), "{notes:?}");
        let b = api_payload(None, "x/unknown", &req, &["https://e/a.png".into()], &mut notes);
        assert!(b.get("aspect_ratio").is_none() && b["input_references"][0]["image_url"]["url"] == "https://e/a.png");
    }

    #[test]
    fn chat_image_shapes() {
        let png = store::data_url("image/png", b"\x89PNG\r\n\x1a\nxx");
        let v = json!({"choices": [{"message": {"images": [{"image_url": {"url": png}}], "content": format!("here {png} done")}}]});
        assert_eq!(chat_images(&v).unwrap().len(), 2);
    }
}
