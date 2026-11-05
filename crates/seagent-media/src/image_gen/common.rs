//! Shared provider plumbing: OpenAI-compatible `/images/generations` + `/images/edits`
//! (OpenClaw `openai-compatible-image-provider.ts` / `image-assets.ts`), response
//! parsing, and small helpers.

use super::{ImageRequest, ImageResult};
use crate::http::Multipart;
use crate::store::{self, Asset};
use crate::{Creds, Media};
use serde_json::{json, Value};

/// OpenAI semantic sizes (Hermes `OPENAI_SIZES`).
pub fn openai_size_for(aspect: &str) -> &'static str {
    match aspect {
        "landscape" => "1536x1024",
        "portrait" => "1024x1536",
        _ => "1024x1024",
    }
}

/// `data[]` of an OpenAI-style images response → assets (b64_json inline, url kept for download).
pub fn parse_openai_images(v: &Value, default_mime: &str, label: &str) -> Result<Vec<Asset>, String> {
    let data = v.get("data").ok_or_else(|| format!("{label} response malformed: no `data`"))?;
    let arr = data.as_array().ok_or_else(|| format!("{label} response malformed: `data` is not a list"))?;
    let mut out = Vec::new();
    for e in arr {
        let mime = e["mime_type"].as_str().or_else(|| e["media_type"].as_str()).unwrap_or(default_mime);
        let mut a = if let Some(b) = e["b64_json"].as_str().filter(|s| !s.is_empty()) {
            let bytes = store::b64_decode(b).map_err(|e| format!("{label} returned malformed base64 image data: {e}"))?;
            let sniffed = store::sniff(&bytes);
            Asset::new(bytes, if sniffed != "application/octet-stream" { sniffed } else { mime })
        } else if let Some(u) = e["url"].as_str().filter(|s| !s.is_empty()) {
            if let Some((m, b)) = store::decode_data_url(u) {
                Asset::new(b, &m)
            } else {
                Asset::from_url(u, mime)
            }
        } else {
            continue;
        };
        a.revised_prompt = e["revised_prompt"].as_str().map(str::to_string);
        out.push(a);
    }
    if out.is_empty() {
        return Err(format!("{label} response contained neither b64_json nor URL"));
    }
    Ok(out)
}

pub fn usage_meta(v: &Value) -> Value {
    if v["usage"].is_null() {
        json!({})
    } else {
        json!({"usage": v["usage"]})
    }
}

/// Standard OpenAI-compatible generate (JSON) or edit (multipart) call.
pub struct Compat<'a> {
    pub label: &'a str,
    pub creds: &'a Creds,
    pub headers: Vec<(String, String)>,
    /// Field name for edit images ("image", or "image[]" for several).
    pub edit_field: &'a str,
    pub default_mime: &'a str,
}

impl Compat<'_> {
    pub fn generate(&self, m: &Media, body: &Value) -> Result<Value, String> {
        let url = self.creds.url("images/generations");
        m.http.post_json(&url, &self.headers, body).map_err(|e| format!("{} image generation failed: {e}", self.label))
    }
    pub fn edit(&self, m: &Media, fields: &[(&str, String)], req: &ImageRequest) -> Result<Value, String> {
        let mut form = Multipart::new();
        for (k, v) in fields {
            form = form.text(k, v.clone());
        }
        let field = if req.inputs.len() > 1 && self.edit_field == "image" { "image[]" } else { self.edit_field };
        for (i, img) in req.inputs.iter().enumerate() {
            let name = upload_name(&img.name, &img.mime, i);
            form = form.file(field, &name, &img.mime, img.bytes.clone());
        }
        let url = self.creds.url("images/edits");
        m.http.post_multipart(&url, &self.headers, &form).map_err(|e| format!("{} image edit failed: {e}", self.label))?.json()
    }
    pub fn result(&self, v: &Value, model: &str) -> Result<ImageResult, String> {
        Ok(ImageResult { images: parse_openai_images(v, self.default_mime, self.label)?, model: model.to_string(), meta: usage_meta(v) })
    }
}

/// Upload filename with an extension matching the MIME type.
pub fn upload_name(name: &str, mime: &str, i: usize) -> String {
    let ext = store::ext_for(mime);
    let n = name.trim();
    if !n.is_empty() && n.contains('.') && !n.starts_with("data:") {
        n.to_string()
    } else {
        format!("image-{}.{ext}", i + 1)
    }
}

/// Require a key or explain how to set one.
pub fn require_key<'a>(c: &'a Creds, envs: &[&str]) -> Result<&'a str, String> {
    c.key.as_deref().ok_or_else(|| format!("{} API key missing (set {} or [media.providers.{}] api_key)", c.id, envs.join(" / "), c.id))
}

/// Trim a model name supplied as "provider/model" for this provider.
pub fn model_or(req: &ImageRequest, default: &str) -> String {
    req.model.clone().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| default.to_string())
}
