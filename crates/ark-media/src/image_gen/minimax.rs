//! MiniMax `image-01` (`POST /v1/image_generation`, base64 output, character
//! subject reference). China accounts use `api.minimaxi.com` (`MINIMAX_API_HOST`).

use super::common::require_key;
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::{self, Asset};
use crate::Media;
use ark_core::Cancel;
use serde_json::json;

pub struct Minimax;

const ENV: &[&str] = &["MINIMAX_API_KEY", "MINIMAX_CODE_PLAN_KEY", "MINIMAX_CODING_API_KEY"];
const BASE: &str = "https://api.minimax.io";
const CN_BASE: &str = "https://api.minimaxi.com";
const ASPECTS: &[&str] = &["1:1", "16:9", "4:3", "3:2", "2:3", "3:4", "9:16", "21:9"];

fn is_cn(h: &str) -> bool {
    let host = crate::http::host_of(if h.contains("://") { h.to_string() } else { format!("https://{h}") }.as_str()).to_ascii_lowercase();
    host == "minimaxi.com" || host.ends_with(".minimaxi.com")
}

impl ImageProvider for Minimax {
    fn id(&self) -> &'static str {
        "minimax"
    }
    fn label(&self) -> &'static str {
        "MiniMax"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.minimax.model").unwrap_or_else(|| "image-01".into())
    }
    fn models(&self) -> Vec<String> {
        vec!["image-01".into()]
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 9, edit: true, max_inputs: 1, supports_aspect: true, aspect_ratios: ASPECTS.to_vec(), ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let host_env = std::env::var("MINIMAX_API_HOST").unwrap_or_default();
        let c = m.creds("minimax", ENV, if is_cn(&host_env) { CN_BASE } else { BASE });
        require_key(&c, ENV)?;
        let model = super::common::model_or(req, &self.default_model(m));
        let mut body = json!({"model": model, "prompt": req.prompt, "response_format": "base64", "n": req.count});
        if let Some(a) = &req.aspect_ratio {
            body["aspect_ratio"] = json!(a);
        }
        if let Some(r) = req.inputs.first() {
            body["subject_reference"] = json!([{"type": "character", "image_file": r.data_url()}]);
        }
        let v = m.http.post_json(&c.url("v1/image_generation"), &c.bearer(), &body).map_err(|e| format!("MiniMax image generation failed: {e}"))?;
        if let Some(code) = v["base_resp"]["status_code"].as_i64().filter(|c| *c != 0) {
            return Err(format!("MiniMax image generation API error ({code}): {}", v["base_resp"]["status_msg"].as_str().unwrap_or("")));
        }
        let mut images = vec![];
        for b in v["data"]["image_base64"].as_array().cloned().unwrap_or_default() {
            if let Some(s) = b.as_str().filter(|s| !s.is_empty()) {
                images.push(Asset::new(store::b64_decode(s).map_err(|_| "MiniMax image generation returned malformed image base64")?, "image/png"));
            }
        }
        if images.is_empty() {
            let failed = v["metadata"]["failed_count"].as_i64().unwrap_or(0);
            let reason = if failed > 0 { format!("{failed} image(s) failed to generate") } else { "no images returned".into() };
            return Err(format!("MiniMax image generation returned no images: {reason}"));
        }
        Ok(ImageResult { images, model, meta: json!({"id": v["id"]}) })
    }
}
