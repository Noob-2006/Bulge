//! Microsoft Foundry MAI image deployments (`{endpoint}/mai/v1/images/{generations,edits}`,
//! `api-key` header; OpenClaw `microsoft-foundry/image-generation-provider.ts`).
//! `[media.providers.microsoft-foundry] base_url` = the resource endpoint
//! (or `AZURE_OPENAI_ENDPOINT`); `model` = the deployment name; `model_name` =
//! the MAI model behind a custom deployment name (needed for edits).

use super::common::require_key;
use super::{parse_size, Caps, ImageProvider, ImageRequest, ImageResult};
use crate::http::Multipart;
use crate::Media;
use seagent_core::Cancel;
use serde_json::json;

pub struct Foundry;

const ENV: &[&str] = &["AZURE_OPENAI_API_KEY", "MICROSOFT_FOUNDRY_API_KEY"];
const MAI: &[&str] = &["mai-image-2.5-flash", "mai-image-2.5", "mai-image-2e", "mai-image-2", "mai-image-2-efficient"];

fn is_mai(m: &str) -> bool {
    MAI.contains(&m.to_ascii_lowercase().as_str())
}

/// Scheme + host of a Foundry/Azure URL (paths like `/openai/v1` are dropped).
fn endpoint(u: &str) -> Option<String> {
    let u = u.trim();
    let (scheme, rest) = u.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let host = rest.split(['/', '?']).next().filter(|h| !h.is_empty())?;
    Some(format!("{scheme}://{host}"))
}

fn mai_size(size: Option<&str>) -> Result<(u32, u32), String> {
    let Some(s) = size else { return Ok((1024, 1024)) };
    let (w, h) = parse_size(s).ok_or_else(|| format!("Microsoft Foundry MAI image size must use WIDTHxHEIGHT, got \"{s}\"."))?;
    if w < 768 || h < 768 || w as u64 * h as u64 > 1_048_576 {
        return Err(format!("Microsoft Foundry MAI image size must be at least 768x768 and at most 1,048,576 total pixels, got \"{s}\"."));
    }
    Ok((w, h))
}

impl ImageProvider for Foundry {
    fn id(&self) -> &'static str {
        "microsoft-foundry"
    }
    fn label(&self) -> &'static str {
        "Microsoft Foundry"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        ""
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.microsoft-foundry.model").unwrap_or_default()
    }
    fn models(&self) -> Vec<String> {
        vec![]
    }
    fn configured(&self, m: &Media) -> bool {
        let c = m.creds("microsoft-foundry", ENV, &std::env::var("AZURE_OPENAI_ENDPOINT").unwrap_or_default());
        c.key.is_some() && endpoint(&c.base).is_some()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 1, edit: true, max_inputs: 1, supports_size: true, formats: vec!["png"], ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("microsoft-foundry", ENV, &std::env::var("AZURE_OPENAI_ENDPOINT").unwrap_or_default());
        let key = require_key(&c, ENV)?.to_string();
        let model = req.model.clone().filter(|s| !s.trim().is_empty()).ok_or("Microsoft Foundry MAI image generation requires a deployment name.")?;
        let configured_name = c.str("model_name");
        let model_name = configured_name.clone().unwrap_or_else(|| model.clone());
        let has_meta = configured_name.as_deref().is_some_and(|n| !n.eq_ignore_ascii_case(&model));
        let lower = model.to_ascii_lowercase();
        if !is_mai(&model_name) && (has_meta || (lower.starts_with("mai-") && !lower.starts_with("mai-image-"))) {
            return Err(format!("Microsoft Foundry image generation supports MAI image deployments only, got \"{model_name}\"."));
        }
        if req.count != 1 {
            return Err("Microsoft Foundry MAI image models return one image per request.".into());
        }
        let edit = req.is_edit();
        if req.inputs.len() > 1 {
            return Err("Microsoft Foundry MAI image edits support one input image.".into());
        }
        let edit_model = matches!(model_name.to_ascii_lowercase().as_str(), "mai-image-2.5" | "mai-image-2.5-flash");
        if edit && (has_meta || is_mai(&model)) && !edit_model {
            return Err(format!("{model_name} does not support Microsoft Foundry MAI image edits."));
        }
        if edit && !has_meta && !is_mai(&model) {
            return Err("Microsoft Foundry MAI image edits require MAI-Image-2.5 model metadata for custom deployment names (set [media.providers.microsoft-foundry] model_name).".into());
        }
        let ep = endpoint(&c.base).ok_or("Microsoft Foundry endpoint missing for MAI image generation (set [media.providers.microsoft-foundry] base_url or AZURE_OPENAI_ENDPOINT).")?;
        let mut headers = c.headers.clone();
        headers.insert(0, ("api-key".into(), key));
        let label = if edit { "Microsoft Foundry MAI image edit" } else { "Microsoft Foundry MAI image generation" };
        let v = if edit {
            let img = &req.inputs[0];
            let mime = if img.mime == "image/jpg" { "image/jpeg".to_string() } else { img.mime.clone() };
            if mime != "image/png" && mime != "image/jpeg" {
                return Err("Microsoft Foundry MAI image edits require a PNG or JPEG input image.".into());
            }
            let form = Multipart::new().text("model", model.clone()).text("prompt", req.prompt.clone()).file("image", &super::common::upload_name(&img.name, &mime, 0), &mime, img.bytes.clone());
            m.http.post_multipart(&format!("{ep}/mai/v1/images/edits"), &headers, &form).map_err(|e| format!("{label} failed: {e}"))?.json()?
        } else {
            let (w, h) = mai_size(req.size.as_deref())?;
            m.http.post_json(&format!("{ep}/mai/v1/images/generations"), &headers, &json!({"model": model, "prompt": req.prompt, "width": w, "height": h})).map_err(|e| format!("{label} failed: {e}"))?
        };
        let images = super::common::parse_openai_images(&v, "image/png", label).map_err(|_| format!("{label} response missing image data"))?;
        Ok(ImageResult { images, model, meta: json!({}) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_size_rules() {
        assert_eq!(endpoint("https://r.services.ai.azure.com/openai/v1").as_deref(), Some("https://r.services.ai.azure.com"));
        assert!(mai_size(Some("512x512")).unwrap_err().contains("at least 768x768"));
        assert_eq!(mai_size(None).unwrap(), (1024, 1024));
    }
}
