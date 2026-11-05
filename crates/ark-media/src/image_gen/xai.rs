//! xAI Grok Imagine (`/images/generations`, JSON `/images/edits`): Hermes
//! `plugins/image_gen/xai` + OpenClaw `xai/image-generation-provider.ts`.
//! `[media.providers.xai] storage = true` (+ `public_url`, `expires_after` seconds)
//! asks xAI to keep the file and return a reusable public URL (Hermes Imagine storage).

use super::common::{require_key, usage_meta};
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::{self, Asset};
use crate::Media;
use ark_core::Cancel;
use serde_json::{json, Value};

pub struct Xai;

const ENV: &[&str] = &["XAI_API_KEY"];
const BASE: &str = "https://api.x.ai/v1";
const DEFAULT_MODEL: &str = "grok-imagine-image";
const EDIT_FALLBACK: &str = "grok-imagine-image-quality";
const ASPECTS: &[&str] = &["1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3", "2:1", "1:2", "19.5:9", "9:19.5", "20:9", "9:20"];

impl ImageProvider for Xai {
    fn id(&self) -> &'static str {
        "xai"
    }
    fn label(&self) -> &'static str {
        "xAI (Grok Imagine)"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.xai.model").or_else(|| std::env::var("XAI_IMAGE_MODEL").ok().filter(|s| !s.trim().is_empty())).unwrap_or_else(|| DEFAULT_MODEL.into())
    }
    fn models(&self) -> Vec<String> {
        [DEFAULT_MODEL, "grok-imagine-image-2.0", EDIT_FALLBACK].map(String::from).to_vec()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 4, edit: true, max_inputs: 3, supports_aspect: true, supports_resolution: true, aspect_ratios: ASPECTS.to_vec(), resolutions: vec!["1K", "2K"], ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("xai", ENV, BASE);
        require_key(&c, ENV).map_err(|_| "No xAI credentials found. Set XAI_API_KEY or [media.providers.xai] api_key.".to_string())?;
        let mut headers = c.bearer();
        headers.push(("user-agent".into(), format!("ark/{}", env!("CARGO_PKG_VERSION"))));
        let explicit = req.model.clone();
        let mut model = explicit.clone().unwrap_or_else(|| self.default_model(m));
        let mut body = json!({"prompt": req.prompt, "n": req.count.clamp(1, 4), "response_format": "b64_json"});
        let path = if req.is_edit() {
            if req.inputs.len() > 3 {
                return Err("xAI image editing supports at most 3 source images".into());
            }
            // Hermes: an explicit model that accepts image input, else the quality baseline.
            if explicit.is_none() || model == DEFAULT_MODEL {
                model = EDIT_FALLBACK.into();
            }
            let fields: Vec<Value> = req.inputs.iter().map(|i| json!({"url": i.url_or_data(), "type": "image_url"})).collect();
            if fields.len() == 1 {
                body["image"] = fields[0].clone();
            } else {
                body["images"] = json!(fields);
            }
            "images/edits"
        } else {
            "images/generations"
        };
        body["model"] = json!(model);
        let ar = req.aspect_ratio.clone().unwrap_or_else(|| super::ratio_of_semantic(&req.semantic_aspect));
        if ASPECTS.contains(&ar.as_str()) {
            body["aspect_ratio"] = json!(ar);
        }
        let res = req.resolution.clone().map(|r| r.to_ascii_lowercase()).or_else(|| c.str("resolution").filter(|r| r == "1k" || r == "2k"));
        if let Some(r) = res.or_else(|| (!req.is_edit()).then(|| "1k".to_string())) {
            body["resolution"] = json!(r);
        }
        if c.extra.get("storage").and_then(|v| v.as_bool()).unwrap_or(false) {
            let mut so = json!({"filename": format!("{}.png", store::stem("ark-xai-image")), "public_url": c.extra.get("public_url").and_then(|v| v.as_bool()).unwrap_or(true)});
            if let Some(e) = c.extra.get("expires_after").and_then(|v| v.as_integer()) {
                so["expires_after"] = json!(e);
            }
            body["storage_options"] = so;
        }
        let v = m.http.post_json(&c.url(path), &headers, &body).map_err(|e| format!("xAI image {} failed: {e}", if req.is_edit() { "edit" } else { "generation" }))?;
        let data = v["data"].as_array().cloned().unwrap_or_default();
        if data.is_empty() {
            return Err("xAI returned no image data".into());
        }
        let mut images = vec![];
        let mut public = vec![];
        for d in &data {
            if let Some(u) = d["file_output"]["public_url"].as_str() {
                public.push(u.to_string());
            }
            if let Some(b) = d["b64_json"].as_str().filter(|s| !s.is_empty()) {
                let mut a = Asset::new(store::b64_decode(b)?, "image/png");
                a.revised_prompt = d["revised_prompt"].as_str().map(str::to_string);
                images.push(a);
            } else if let Some(u) = d["url"].as_str().or_else(|| d["file_output"]["public_url"].as_str()) {
                images.push(Asset::from_url(u, "image/png"));
            }
        }
        if images.is_empty() {
            return Err("xAI response contained neither b64_json nor URL".into());
        }
        let mut meta = usage_meta(&v);
        if !public.is_empty() {
            meta["public_urls"] = json!(public);
        }
        if let Some(r) = body.get("resolution") {
            meta["resolution"] = r.clone();
        }
        Ok(ImageResult { images, model, meta })
    }
}
