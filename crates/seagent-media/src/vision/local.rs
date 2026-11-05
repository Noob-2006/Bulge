//! `local_image`: inspect a local image with a local llama.cpp `llama-server` (OpenClaw
//! `extensions/llama-cpp/src/media-tool.ts` + `media-provider.runtime.ts`). Two saved routes —
//! an OCR model and a vision model — on a direct loopback server; no cloud fallback, no URLs,
//! one image per request, image bytes never leave the machine.

use crate::Media;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

/// OpenClaw `LLAMA_CPP_MEDIA_*` limits.
pub const MAX_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_TOKENS: u64 = 2048;
pub const MAX_CHARS: usize = 12_000;
pub const TIMEOUT_SECS: u64 = 600;
const DEFAULT_OCR_PROMPT: &str = "Text Recognition:";

struct Routes {
    base: String,
    ocr: String,
    vision: String,
    ocr_prompt: String,
}

/// Managed media never sends image bytes to a non-loopback endpoint (OpenClaw
/// `isManagedLlamaCppMediaProvider`): plain http on 127.0.0.1 / [::1] / localhost, no userinfo.
pub fn loopback(base: &str) -> bool {
    let Some(rest) = base.strip_prefix("http://") else { return false };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') { authority.split(']').next().map(|h| format!("{h}]")).unwrap_or_default() } else { authority.split(':').next().unwrap_or("").to_string() };
    matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost")
}

fn routes(m: &Media) -> Result<Routes, String> {
    let base = m.cfg.str("local_image.base_url").map(|s| s.trim_end_matches('/').to_string()).unwrap_or_default();
    let ocr = m.cfg.str("local_image.ocr_model").unwrap_or_default();
    let vision = m.cfg.str("local_image.vision_model").unwrap_or_default();
    if base.is_empty() || ocr.trim().is_empty() || vision.trim().is_empty() {
        return Err("The configured local media routes are incomplete. Set [media.local_image] base_url, ocr_model and vision_model.".into());
    }
    if !loopback(&base) {
        return Err("Managed local images require a direct loopback llama.cpp server (http://127.0.0.1:<port>).".into());
    }
    if ocr == vision {
        return Err("The configured local media recipe is unavailable: the OCR and vision models must differ.".into());
    }
    Ok(Routes { base, ocr, vision, ocr_prompt: m.cfg.str("local_image.ocr_prompt").filter(|s| !s.trim().is_empty()).unwrap_or_else(|| DEFAULT_OCR_PROMPT.into()) })
}

pub fn configured(m: &Media) -> bool {
    routes(m).is_ok()
}

pub struct LocalImage {
    pub m: Arc<Media>,
}

impl LocalImage {
    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let task = match input.get("task") {
            None | Some(Value::Null) => "vision",
            Some(Value::String(s)) if s == "ocr" || s == "vision" => s.as_str(),
            _ => return Err("Local image task must be ocr or vision.".into()),
        };
        let path = input["path"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("Local image path is required.")?;
        let lower = path.to_ascii_lowercase();
        let has_scheme = lower.split_once(':').is_some_and(|(s, _)| s.len() > 1 && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)));
        if has_scheme && !lower.starts_with("file://") {
            return Err("Local image requires a local path; URLs are not accepted.".into());
        }
        let prompt_arg = match input.get("prompt") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.chars().count() <= 8192 => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            _ => return Err("Local image prompt must be a string of at most 8192 characters.".into()),
        };
        let r = routes(&self.m).map_err(|e| format!("{e} Run local media setup before using local_image."))?;
        let max_bytes = (self.m.cfg.int_or("local_image.max_bytes", MAX_BYTES as i64).max(1) as usize).min(MAX_BYTES);
        let max_chars = (self.m.cfg.int_or("local_image.max_chars", MAX_CHARS as i64).max(1) as usize).min(MAX_CHARS);
        let p = crate::store::resolve(path, &ctx.workspace);
        let len = std::fs::metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?.len() as usize;
        if len == 0 || len > max_bytes {
            return Err("Local image input must contain between 1 byte and 10 MiB of image data.".into());
        }
        let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let mime = crate::store::sniff(&bytes);
        if !mime.starts_with("image/") {
            return Err("Local image input must be an image.".into());
        }
        let (model, prompt) = if task == "ocr" { (&r.ocr, r.ocr_prompt.clone()) } else { (&r.vision, prompt_arg.unwrap_or_else(|| "Describe the image.".into())) };
        let max_tokens = (self.m.cfg.int_or("local_image.max_tokens", MAX_TOKENS as i64).max(1) as u64).min(MAX_TOKENS);
        // GLM-OCR's trained task token belongs beside the image in the user message.
        let body = json!({"model": model, "temperature": 0, "seed": 4827, "max_tokens": max_tokens, "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": crate::store::data_url(mime, &bytes)}},
            {"type": "text", "text": prompt}
        ]}]});
        let mut h: Vec<(String, String)> = Vec::new();
        if let Some(k) = self.m.cfg.str("local_image.api_key").filter(|k| !k.is_empty()) {
            h.push(("authorization".into(), format!("Bearer {k}")));
        }
        let http = crate::http::Http::new(std::time::Duration::from_secs(self.m.cfg.int_or("local_image.timeout_secs", TIMEOUT_SECS as i64).max(1) as u64));
        let v = http.post_json(&format!("{}/chat/completions", r.base), &h, &body)?;
        let text = v["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
        if text.trim().is_empty() {
            return Err("The local image model returned no text. Run local media setup again.".into());
        }
        Ok(text.chars().take(max_chars).collect())
    }
}

impl Tool for LocalImage {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "local_image".into(),
            description: "Inspect a local image with installed local models. Choose task ocr to transcribe visible text, or vision for photos, charts, diagrams, and spatial questions (default). No cloud fallback or model downloads. The original image remains available.".into(),
            input_schema: json!({"type": "object", "properties": {
                "path": {"type": "string", "minLength": 1, "description": "Local image path."},
                "task": {"type": "string", "enum": ["ocr", "vision"], "default": "vision"},
                "prompt": {"type": "string", "maxLength": 8192}
            }, "required": ["path"], "additionalProperties": false}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        input["path"].as_str().map(|p| vec![Effect::Read { path: crate::store::resolve(p, &ctx.workspace) }]).unwrap_or_default()
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ctx, FakeServer};

    #[test]
    fn local_image_ocr_and_vision_routes() {
        let srv = FakeServer::start(|r, _| {
            let v = r.json();
            let text = v["messages"][0]["content"][1]["text"].as_str().unwrap_or("").to_string();
            (200, vec![], json!({"choices": [{"message": {"content": format!("{}|{}", v["model"].as_str().unwrap_or(""), text)}}]}).to_string())
        });
        let toml = format!("[local_image]\nbase_url = \"{}/v1\"\nocr_model = \"glm-ocr-q8_0\"\nvision_model = \"smolvlm2\"\n", srv.url);
        let m = Media::new(crate::MediaConfig::from_toml(&toml));
        assert!(configured(&m));
        assert!(super::super::tools(&m).iter().any(|t| t.spec().name == "local_image"));
        let c = ctx("local-image");
        std::fs::write(c.workspace.join("p.png"), super::super::prep::test_png(4, 4)).unwrap();
        let t = LocalImage { m: m.clone() };
        let out = t.call(&c, json!({"path": "p.png", "task": "ocr", "prompt": "ignored"}));
        assert_eq!(out.content, "glm-ocr-q8_0|Text Recognition:");
        let out = t.call(&c, json!({"path": "p.png", "prompt": "count the dots"}));
        assert_eq!(out.content, "smolvlm2|count the dots");
        let req = &srv.requests()[0];
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!((req.json()["temperature"].as_i64(), req.json()["seed"].as_i64()), (Some(0), Some(4827)));
        assert!(t.call(&c, json!({"path": "https://e/x.png"})).content.contains("URLs are not accepted"));
        assert!(t.call(&c, json!({"path": "p.png", "task": "draw"})).content.contains("ocr or vision"));
        assert!(!loopback("http://10.0.0.2:8080/v1") && !loopback("https://127.0.0.1/v1") && !loopback("http://u:p@127.0.0.1/v1") && loopback("http://[::1]:9/v1"));
        let remote = Media::new(crate::MediaConfig::from_toml("[local_image]\nbase_url = \"http://10.1.1.1:8080/v1\"\nocr_model = \"a\"\nvision_model = \"b\"\n"));
        assert!(!configured(&remote));
    }
}
