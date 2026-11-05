//! Google Gemini image models (`models/{m}:generateContent` with IMAGE modality,
//! OpenClaw `google/image-generation-provider.ts`) and Imagen (`models/{m}:predict`).

use super::common::require_key;
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::{self, Asset};
use crate::Media;
use seagent_core::Cancel;
use serde_json::{json, Map, Value};

pub struct Google;

const ENV: &[&str] = &["GEMINI_API_KEY", "GOOGLE_API_KEY"];
const BASE: &str = "https://generativelanguage.googleapis.com/v1beta";
const DEFAULT_MODEL: &str = "gemini-3.1-flash-image";
const ASPECTS: &[&str] = &["1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9"];
const IMAGEN_ASPECTS: &[&str] = &["1:1", "3:4", "4:3", "9:16", "16:9"];

/// `size` → `{aspectRatio?, imageSize?}` (OpenClaw mapSizeToImageConfig).
fn size_config(size: Option<&str>) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(s) = size.map(|s| s.to_ascii_lowercase()) else { return out };
    let ar = match s.as_str() {
        "1024x1024" => Some("1:1"),
        "1024x1536" => Some("2:3"),
        "1536x1024" => Some("3:2"),
        "1024x1792" => Some("9:16"),
        "1792x1024" => Some("16:9"),
        _ => None,
    };
    let Some((w, h)) = super::parse_size(&s) else { return out };
    let edge = w.max(h);
    if let Some(a) = ar {
        out.insert("aspectRatio".into(), json!(a));
    }
    if edge >= 3072 {
        out.insert("imageSize".into(), json!("4K"));
    } else if edge >= 1536 {
        out.insert("imageSize".into(), json!("2K"));
    }
    out
}

fn normalize_model(m: &str) -> String {
    m.trim().trim_start_matches("models/").trim_start_matches("google/").to_string()
}

impl Google {
    fn imagen(&self, m: &Media, url: &str, headers: &[(String, String)], req: &ImageRequest, model: &str) -> Result<ImageResult, String> {
        let mut params = json!({"sampleCount": req.count.clamp(1, 4)});
        if let Some(a) = &req.aspect_ratio {
            params["aspectRatio"] = json!(a);
        }
        if let Some(r) = &req.resolution {
            params["sampleImageSize"] = json!(r);
        }
        if let Some(f) = &req.output_format {
            params["outputOptions"] = json!({"mimeType": format!("image/{f}")});
        }
        let v = m.http.post_json(&format!("{url}/models/{model}:predict"), headers, &json!({"instances": [{"prompt": req.prompt}], "parameters": params})).map_err(|e| format!("Google Imagen generation failed: {e}"))?;
        let mut images = vec![];
        for p in v["predictions"].as_array().cloned().unwrap_or_default() {
            if let Some(b) = p["bytesBase64Encoded"].as_str() {
                images.push(Asset::new(store::b64_decode(b).map_err(|_| "Google image generation response malformed")?, p["mimeType"].as_str().unwrap_or("image/png")));
            }
        }
        if images.is_empty() {
            return Err("Google image generation response missing image data (filtered by safety settings?)".into());
        }
        Ok(ImageResult { images, model: model.into(), meta: json!({}) })
    }
}

impl ImageProvider for Google {
    fn id(&self) -> &'static str {
        "google"
    }
    fn label(&self) -> &'static str {
        "Google"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.google.model").unwrap_or_else(|| DEFAULT_MODEL.into())
    }
    fn models(&self) -> Vec<String> {
        [DEFAULT_MODEL, "gemini-3-pro-image", "imagen-4.0-generate-001", "imagen-4.0-ultra-generate-001", "imagen-4.0-fast-generate-001"].map(String::from).to_vec()
    }
    fn caps(&self, model: &str) -> Caps {
        let imagen = normalize_model(model).starts_with("imagen-");
        Caps {
            max_count: 4,
            edit: !imagen,
            max_inputs: if imagen { 0 } else { 5 },
            supports_size: !imagen,
            supports_aspect: true,
            supports_resolution: true,
            sizes: if imagen { vec![] } else { vec!["1024x1024", "1024x1536", "1536x1024", "1024x1792", "1792x1024"] },
            aspect_ratios: if imagen { IMAGEN_ASPECTS.to_vec() } else { ASPECTS.to_vec() },
            resolutions: if imagen { vec!["1K", "2K"] } else { vec!["1K", "2K", "4K"] },
            formats: if imagen { vec!["png", "jpeg"] } else { vec![] },
            ..Caps::default()
        }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("google", ENV, BASE);
        let key = require_key(&c, ENV)?.to_string();
        let model = normalize_model(&super::common::model_or(req, &self.default_model(m)));
        let headers = c.header_key("x-goog-api-key");
        let base = c.base.trim_end_matches('/').to_string();
        let _ = key;
        if model.starts_with("imagen-") {
            return self.imagen(m, &base, &headers, req, &model);
        }
        let mut cfg = size_config(req.size.as_deref());
        if let Some(a) = &req.aspect_ratio {
            cfg.insert("aspectRatio".into(), json!(a));
        }
        if let Some(r) = &req.resolution {
            cfg.insert("imageSize".into(), json!(r));
        }
        let mut parts: Vec<Value> = req.inputs.iter().map(|i| json!({"inlineData": {"mimeType": i.mime, "data": store::b64(&i.bytes)}})).collect();
        parts.push(json!({"text": req.prompt}));
        let mut gen = json!({"responseModalities": ["TEXT", "IMAGE"]});
        if !cfg.is_empty() {
            gen["imageConfig"] = Value::Object(cfg);
        }
        if req.count > 1 {
            gen["candidateCount"] = json!(req.count.min(4));
        }
        let v = m.http.post_json(&format!("{base}/models/{model}:generateContent"), &headers, &json!({"contents": [{"role": "user", "parts": parts}], "generationConfig": gen})).map_err(|e| format!("Google image generation failed: {e}"))?;
        let mut images = vec![];
        let mut text = vec![];
        for cand in v["candidates"].as_array().cloned().unwrap_or_default() {
            for p in cand["content"]["parts"].as_array().cloned().unwrap_or_default() {
                let inline = if p["inlineData"].is_object() { &p["inlineData"] } else { &p["inline_data"] };
                if let Some(d) = inline["data"].as_str() {
                    let d = d.replace('-', "+").replace('_', "/");
                    let mime = inline["mimeType"].as_str().or_else(|| inline["mime_type"].as_str()).unwrap_or("image/png");
                    images.push(Asset::new(store::b64_decode(&d).map_err(|_| "Google image generation response malformed")?, mime));
                } else if let Some(t) = p["text"].as_str() {
                    text.push(t.to_string());
                }
            }
        }
        if images.is_empty() {
            let reason = v["promptFeedback"]["blockReason"].as_str().map(|r| format!(" (blocked: {r})")).unwrap_or_default();
            return Err(format!("Google image generation response missing image data{reason}"));
        }
        Ok(ImageResult { images, model, meta: if text.is_empty() { json!({}) } else { json!({"text": text.join("\n")}) } })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_mapping() {
        let c = size_config(Some("1792x1024"));
        assert_eq!((c["aspectRatio"].as_str(), c["imageSize"].as_str()), (Some("16:9"), Some("2K")));
        assert!(size_config(Some("1024x1024")).get("imageSize").is_none());
        assert_eq!(size_config(Some("4096x4096"))["imageSize"], "4K");
        assert_eq!(normalize_model("models/imagen-4.0-generate-001"), "imagen-4.0-generate-001");
    }
}
