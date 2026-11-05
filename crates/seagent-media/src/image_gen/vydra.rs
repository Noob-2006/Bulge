//! Vydra (`POST {base}/models/{model}` → result URL, or `jobId` polled at
//! `/jobs/{id}`; OpenClaw `vydra/shared.ts`). Text-to-image only, one image per call.

use super::common::require_key;
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::Asset;
use crate::{Creds, Media};
use seagent_core::Cancel;
use serde_json::{json, Value};

pub struct Vydra;

const ENV: &[&str] = &["VYDRA_API_KEY"];
const BASE: &str = "https://www.vydra.ai/api/v1";
const DEFAULT_MODEL: &str = "grok-imagine";

/// Result URLs anywhere in a Vydra payload (`imageUrl`, `resultUrls`, `output[]`, …).
pub fn result_urls(v: &Value, kind: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    fn add(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) if s.starts_with("http://") || s.starts_with("https://") => {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
            Value::Array(a) => a.iter().for_each(|x| add(x, out)),
            _ => {}
        }
    }
    fn visit(v: &Value, kind: &str, depth: u32, out: &mut Vec<String>) {
        if depth > 5 {
            return;
        }
        match v {
            Value::Array(a) => a.iter().for_each(|x| visit(x, kind, depth + 1, out)),
            Value::Object(o) => {
                for k in [format!("{kind}Url"), format!("{kind}Urls"), "resultUrl".into(), "resultUrls".into(), "outputUrl".into(), "outputUrls".into(), "url".into(), "urls".into()] {
                    if let Some(x) = o.get(&k) {
                        add(x, out);
                    }
                }
                for k in ["output", "outputs", "result", "results", "data", "asset", "assets"] {
                    if let Some(x) = o.get(k) {
                        visit(x, kind, depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
    visit(v, kind, 0, &mut out);
    out
}

fn status(v: &Value) -> String {
    v["status"].as_str().unwrap_or("").to_ascii_lowercase()
}

fn err_msg(v: &Value) -> Option<String> {
    v["error"].as_str().map(str::to_string).or_else(|| v["error"]["message"].as_str().or(v["error"]["detail"].as_str()).map(str::to_string)).or_else(|| v["message"].as_str().map(str::to_string))
}

/// Submit, poll if needed, download the first result (shared with Vydra video).
#[allow(clippy::too_many_arguments)]
pub fn run(m: &Media, c: &Creds, model: &str, body: &Value, kind: &str, req_poll: std::time::Duration, timeout: std::time::Duration, cancel: &Cancel) -> Result<(Asset, Value), String> {
    let headers = c.bearer();
    let sub = m.http.post_json(&c.url(&format!("models/{model}")), &headers, body).map_err(|e| format!("Vydra {kind} generation failed: {e}"))?;
    let complete = |v: &Value| status(v) == "completed" || !result_urls(v, kind).is_empty();
    let done = if complete(&sub) {
        sub.clone()
    } else {
        let id = sub["jobId"].as_str().or_else(|| sub["id"].as_str()).map(str::to_string).ok_or_else(|| err_msg(&sub).unwrap_or_else(|| format!("Vydra {kind} generation response missing job id")))?;
        crate::http::poll(cancel, req_poll, timeout, || {
            let v = m.http.get_json(&c.url(&format!("jobs/{id}")), &headers).map_err(|e| format!("Vydra job status request failed: {e}"))?;
            if matches!(status(&v).as_str(), "failed" | "error" | "cancelled") {
                return Err(err_msg(&v).unwrap_or_else(|| format!("Vydra job {id} failed")));
            }
            Ok(complete(&v).then_some(v))
        })
        .map_err(|e| if e.starts_with("timed out") { format!("Vydra job {id} did not finish in time") } else { e })?
    };
    let url = result_urls(&done, kind).into_iter().next().ok_or_else(|| format!("Vydra {kind} generation completed without a {kind} URL"))?;
    // The API key only goes to Vydra's own origin.
    let same = crate::http::host_of(&url) == crate::http::host_of(&c.base);
    let (bytes, ct) = m.download(&url, if same { &headers } else { &[] })?;
    let fallback = match kind {
        "image" => "image/png",
        "audio" => "audio/mpeg",
        _ => "video/mp4",
    };
    let mut a = Asset::new(bytes, if ct.is_empty() { fallback } else { &ct });
    a.url = Some(url.clone());
    let meta = json!({"jobId": done["jobId"].as_str().or(done["id"].as_str()).or(sub["jobId"].as_str()), "status": if status(&done).is_empty() { "completed".into() } else { status(&done) }, format!("{kind}Url"): url});
    Ok((a, meta))
}

pub fn creds(m: &Media) -> Creds {
    let mut c = m.creds("vydra", ENV, BASE);
    c.base = c.base.replace("://vydra.ai", "://www.vydra.ai");
    c
}

impl ImageProvider for Vydra {
    fn id(&self) -> &'static str {
        "vydra"
    }
    fn label(&self) -> &'static str {
        "Vydra"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.vydra.model").unwrap_or_else(|| DEFAULT_MODEL.into())
    }
    fn models(&self) -> Vec<String> {
        vec![DEFAULT_MODEL.into()]
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 1, ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, cancel: &Cancel) -> Result<ImageResult, String> {
        if req.is_edit() {
            return Err("Vydra image generation currently supports text-to-image only.".into());
        }
        if req.count > 1 {
            return Err("Vydra image generation supports at most one image per request.".into());
        }
        let c = creds(m);
        require_key(&c, ENV)?;
        let model = super::common::model_or(req, &self.default_model(m));
        let (a, meta) = run(m, &c, &model, &json!({"prompt": req.prompt, "model": "text-to-image"}), "image", req.poll_or(2500), req.timeout, cancel)?;
        Ok(ImageResult { images: vec![a], model, meta })
    }
}
