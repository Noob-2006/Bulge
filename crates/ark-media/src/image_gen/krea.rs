//! Krea 2 (Medium / Large / Medium Turbo): async jobs (`POST
//! /generate/image/krea/krea-2/{tier}` → `job_id`, poll `GET /jobs/{id}`), style
//! references, creative sliders, moodboards, and Krea Enhance upscaling
//! (Hermes `plugins/image_gen/krea`).

use super::common::require_key;
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::store::Asset;
use crate::{Creds, Media};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub struct Krea;

const ENV: &[&str] = &["KREA_API_KEY"];
const BASE: &str = "https://api.krea.ai";
const MODELS: &[(&str, &str)] = &[("krea-2-medium", "medium"), ("krea-2-large", "large"), ("krea-2-medium-turbo", "medium-turbo")];
const RETRYABLE: &[u16] = &[408, 409, 425, 429, 500, 502, 503, 504];
const ASPECTS: &[&str] = &["1:1", "4:3", "3:2", "16:9", "2.35:1", "4:5", "2:3", "9:16"];

fn headers(c: &Creds) -> Vec<(String, String)> {
    let mut h = c.bearer();
    h.push(("user-agent".into(), format!("ark/{} (krea-image-gen)", env!("CARGO_PKG_VERSION"))));
    h
}

/// Poll a job to a terminal state (`completed` / `failed` / `cancelled`, or `completed_at`).
fn poll_job(m: &Media, c: &Creds, id: &str, first: Duration, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
    let url = c.url(&format!("jobs/{id}"));
    let deadline = Instant::now() + timeout;
    let mut interval = first;
    let mut last: Option<String> = None;
    loop {
        let until = Instant::now() + interval;
        while Instant::now() < until {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            std::thread::sleep(Duration::from_millis(10).min(interval));
        }
        interval = Duration::from_secs_f64((interval.as_secs_f64() * 1.3).min(5.0)).max(first.min(Duration::from_secs(5)));
        match m.http.send("GET", &url, &headers(c), None) {
            Ok(r) if r.ok() => {
                let job = r.json()?;
                if let Some(s) = job["status"].as_str() {
                    last = Some(s.to_string());
                }
                if matches!(job["status"].as_str(), Some("completed" | "failed" | "cancelled")) || job["completed_at"].as_str().is_some_and(|s| !s.is_empty()) {
                    return Ok(job);
                }
            }
            Ok(r) if !RETRYABLE.contains(&r.status) => return Err(format!("Krea poll failed ({}) for job {id}", r.status)),
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(format!("Krea job {id} did not complete within {}s (last status: {})", timeout.as_secs(), last.unwrap_or_else(|| "unknown".into())));
        }
    }
}

fn result_url(job: &Value) -> Option<String> {
    let r = &job["result"];
    r["urls"].as_array().and_then(|a| a.iter().find_map(|u| u.as_str().map(str::trim).filter(|s| !s.is_empty()))).or_else(|| r["url"].as_str()).map(str::to_string)
}

/// The generation body (Hermes `_build_payload`).
fn payload(req: &ImageRequest, creativity: &str) -> Value {
    let ar = req.aspect_ratio.clone().filter(|a| ASPECTS.contains(&a.as_str())).unwrap_or_else(|| super::ratio_of_semantic(&req.semantic_aspect));
    let mut p = json!({"prompt": req.prompt, "aspect_ratio": ar, "resolution": "1K", "creativity": creativity});
    if let Some(s) = req.seed {
        p["seed"] = json!(s);
    }
    for k in ["intensity", "complexity", "movement"] {
        if let Some(v) = req.opt_i64(k).filter(|v| (-100..=100).contains(v)) {
            p[k] = json!(v);
        }
    }
    if let Some(s) = req.opt("styles").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        p["styles"] = json!(s);
    }
    if !req.inputs.is_empty() {
        p["image_style_references"] = json!(req.inputs.iter().take(10).map(|i| json!({"url": i.url_or_data(), "strength": 0.6})).collect::<Vec<_>>());
    }
    if let Some(mb) = req.opt("moodboards").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        p["moodboards"] = json!([mb[0]]);
    }
    p
}

impl ImageProvider for Krea {
    fn id(&self) -> &'static str {
        "krea"
    }
    fn label(&self) -> &'static str {
        "Krea"
    }
    fn env(&self) -> &'static [&'static str] {
        ENV
    }
    fn default_base(&self) -> &'static str {
        BASE
    }
    fn default_model(&self, m: &Media) -> String {
        std::env::var("KREA_IMAGE_MODEL").ok().filter(|s| MODELS.iter().any(|(id, _)| id == s)).or_else(|| m.cfg.str("providers.krea.model")).unwrap_or_else(|| "krea-2-medium".into())
    }
    fn models(&self) -> Vec<String> {
        MODELS.iter().map(|(id, _)| id.to_string()).collect()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 1, edit: true, max_inputs: 10, supports_aspect: true, aspect_ratios: ASPECTS.to_vec(), ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("krea", ENV, BASE);
        require_key(&c, ENV)?;
        let model = super::common::model_or(req, &self.default_model(m));
        let path = MODELS.iter().find(|(id, _)| *id == model).map(|(_, p)| *p).ok_or_else(|| format!("unknown Krea model `{model}` (krea-2-medium, krea-2-large, krea-2-medium-turbo)"))?;
        let local: usize = req.inputs.iter().filter(|i| i.url.is_none()).map(|i| i.bytes.len()).sum();
        if local > 3 * 1024 * 1024 {
            return Err("Local style reference images total over 3 MB; resize them or pass public URLs".into());
        }
        let creativity = req.opt_str("creativity").or_else(|| req.opt_str("fal.creativity")).or_else(|| c.str("creativity")).filter(|v| ["raw", "low", "medium", "high"].contains(&v.as_str())).unwrap_or_else(|| "medium".into());
        let body = payload(req, &creativity);
        let sub = m.http.post_json(&c.url(&format!("generate/image/krea/krea-2/{path}")), &headers(&c), &body).map_err(|e| format!("Krea image generation failed: {e}"))?;
        let id = sub["job_id"].as_str().filter(|s| !s.is_empty()).ok_or("Krea submit response missing job_id")?.to_string();
        let first = req.poll_or(2000);
        let timeout = req.timeout.min(Duration::from_secs(180)).max(first);
        let job = poll_job(m, &c, &id, first, timeout, cancel)?;
        match job["status"].as_str() {
            Some("failed") => return Err(format!("Krea job {id} failed: {}", job["result"]["error"].as_str().unwrap_or("unknown error"))),
            Some("cancelled") => return Err(format!("Krea job {id} was cancelled")),
            _ => {}
        }
        if !job["result"].is_object() {
            return Err("Krea job completed but result was missing".into());
        }
        let mut url = result_url(&job).ok_or("Krea result contained no image URL")?;
        let want_up = req.upscale.unwrap_or_else(|| c.extra.get("upscale").and_then(|v| v.as_bool()).unwrap_or(false));
        let mut upscaled = false;
        if want_up {
            let enh = m.http.post_json(&c.url("generate/enhance/krea/enhance"), &headers(&c), &json!({"image_url": url, "image_scaling_factor": 2, "prompt": req.prompt}));
            if let Some(eid) = enh.ok().and_then(|v| v["job_id"].as_str().map(str::to_string)) {
                if let Ok(j) = poll_job(m, &c, &eid, first, timeout, cancel) {
                    if j["status"] == "completed" || j["completed_at"].is_string() {
                        if let Some(u) = result_url(&j) {
                            url = u;
                            upscaled = true;
                        }
                    }
                }
            }
        }
        let (bytes, ct) = m.download(&url, &[])?;
        let mut a = Asset::new(bytes, if ct.starts_with("image/") { &ct } else { "" });
        a.url = Some(url.clone());
        Ok(ImageResult { images: vec![a], model, meta: json!({"job_id": id, "creativity": creativity, "upscaled": upscaled, "url": url}) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape() {
        let req = ImageRequest { prompt: "p".into(), semantic_aspect: "portrait".into(), options: json!({"intensity": 50, "movement": 500, "moodboards": ["a", "b"]}), ..Default::default() };
        let p = payload(&req, "high");
        assert_eq!((p["aspect_ratio"].as_str(), p["intensity"].as_i64(), p["creativity"].as_str()), (Some("9:16"), Some(50), Some("high")));
        assert!(p.get("movement").is_none());
        assert_eq!(p["moodboards"], json!(["a"]));
        assert_eq!(result_url(&json!({"result": {"urls": ["", "https://x/1.png"]}})).as_deref(), Some("https://x/1.png"));
    }
}
