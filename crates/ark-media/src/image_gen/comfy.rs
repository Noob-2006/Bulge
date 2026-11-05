//! ComfyUI workflows, local (`http://127.0.0.1:8188`) or Comfy Cloud
//! (`https://cloud.comfy.org`, `X-API-Key`): set the prompt (and seed / input
//! image) into an API-format workflow, `POST /prompt`, poll `/history/{id}`
//! (cloud: `/api/job/{id}/status` → `/api/history_v2/{id}`), download outputs via
//! `/view` (OpenClaw `comfy/workflow-runtime.ts`). Shared with video/music generation
//! through [`run_workflow`].
//!
//! `[media.providers.comfy]` (shared) with per-capability overrides in
//! `[media.providers.comfy.image]` / `.video` / `.music`: `mode`, `base_url`,
//! `api_key`, `workflow` (inline table) or `workflow_path`, `prompt_node_id`,
//! `prompt_input_name`, `input_image_node_id`, `input_image_input_name`,
//! `seed_node_id`, `seed_input_name`, `output_node_id`, `poll_interval_ms` (1500),
//! `timeout_ms` (300000), `headers`.

use super::{Caps, ImageProvider, ImageRequest, ImageResult, InputImage};
use crate::http::Multipart;
use crate::store::{self, Asset};
use crate::Media;
use ark_core::Cancel;
use serde_json::{json, Value};
use std::time::Duration;

pub struct Comfy;

const LOCAL: &str = "http://127.0.0.1:8188";
const CLOUD: &str = "https://cloud.comfy.org";

/// One downloaded workflow output.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowAsset {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub file_name: String,
    pub node_id: String,
}

fn toml_to_json(v: &toml::Value) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// The shared table merged with the capability's sub-table.
fn config(m: &Media, capability: &str) -> toml::Table {
    let mut t = m.cfg.table("providers.comfy");
    let nested = t.get(capability).and_then(|v| v.as_table()).cloned();
    for k in ["image", "video", "music"] {
        t.remove(k);
    }
    if let Some(n) = nested {
        for (k, v) in n {
            t.insert(k, v);
        }
    }
    t
}

fn s(t: &toml::Table, k: &str) -> Option<String> {
    t.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
}

fn load_workflow(t: &toml::Table) -> Result<Value, String> {
    if let Some(w) = t.get("workflow") {
        return match w {
            toml::Value::Table(_) => Ok(toml_to_json(w)),
            toml::Value::String(js) => serde_json::from_str(js).map_err(|e| format!("Comfy workflow JSON: {e}")),
            _ => Err("Comfy workflow must be a table or a JSON string".into()),
        };
    }
    let p = s(t, "workflow_path").ok_or("[media.providers.comfy] workflow or workflow_path is required")?;
    let path = ark_core::tool::expand_home(&p);
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("Comfy workflow at {}: {e}", path.display()))?;
    if !v.is_object() {
        return Err(format!("Comfy workflow at {} must be a JSON object", path.display()));
    }
    Ok(v)
}

fn set_input(wf: &mut Value, node: &str, input: &str, value: Value) -> Result<(), String> {
    let n = wf.get_mut(node).ok_or_else(|| format!("Comfy workflow missing node \"{node}\""))?;
    let inputs = n.get_mut("inputs").filter(|i| i.is_object()).ok_or_else(|| format!("Comfy workflow node \"{node}\" is missing an inputs object"))?;
    inputs[input] = value;
    Ok(())
}

fn configured_in(t: &toml::Table) -> bool {
    (t.contains_key("workflow") || t.contains_key("workflow_path")) && t.contains_key("prompt_node_id")
}

/// Run the configured workflow for `capability` ("image" | "video" | "music").
pub fn run_workflow(m: &Media, capability: &str, prompt: &str, input: Option<&InputImage>, timeout: Duration, cancel: &Cancel) -> Result<(Vec<WorkflowAsset>, String), String> {
    let t = config(m, capability);
    let cloud = s(&t, "mode").as_deref() == Some("cloud");
    let mut wf = load_workflow(&t)?;
    let prompt_node = s(&t, "prompt_node_id").ok_or("[media.providers.comfy] prompt_node_id is required")?;
    set_input(&mut wf, &prompt_node, &s(&t, "prompt_input_name").unwrap_or_else(|| "text".into()), json!(prompt))?;
    if let Some(seed_node) = s(&t, "seed_node_id") {
        let seed = u64::from_le_bytes(ark_net::crypto::random_bytes(8).try_into().unwrap_or([7; 8])) % ((1u64 << 48) - 1);
        set_input(&mut wf, &seed_node, &s(&t, "seed_input_name").unwrap_or_else(|| "seed".into()), json!(seed))?;
    }
    let key = s(&t, "api_key").map(|k| m.cfg.substitute(&k)).or_else(|| m.creds("comfy", &["COMFY_API_KEY", "COMFY_CLOUD_API_KEY"], "").key);
    if cloud && key.is_none() {
        return Err("Comfy Cloud API key missing".into());
    }
    let base = s(&t, "base_url").unwrap_or_else(|| if cloud { CLOUD.into() } else { LOCAL.into() }).trim_end_matches('/').to_string();
    let mut headers: Vec<(String, String)> = t.get("headers").and_then(|h| h.as_table()).map(|h| h.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), m.cfg.substitute(v)))).collect()).unwrap_or_default();
    if cloud {
        headers.push(("X-API-Key".into(), key.clone().unwrap_or_default()));
    }
    let api = if cloud { "/api" } else { "" };
    if let Some(img) = input {
        let node = s(&t, "input_image_node_id").ok_or_else(|| format!("Comfy edit requests require [media.providers.comfy.{capability}] input_image_node_id"))?;
        let name = if img.name.contains('.') { img.name.clone() } else { format!("input.{}", store::ext_for(&img.mime)) };
        let form = Multipart::new().file("image", &name, &img.mime, img.bytes.clone()).text("type", "input").text("overwrite", "true");
        let up = m.http.post_multipart(&format!("{base}{api}/upload/image"), &headers, &form).map_err(|e| format!("Comfy image upload failed: {e}"))?.json()?;
        let uploaded = up["filename"].as_str().or_else(|| up["name"].as_str()).filter(|s| !s.is_empty()).ok_or("Comfy image upload response missing filename")?;
        set_input(&mut wf, &node, &s(&t, "input_image_input_name").unwrap_or_else(|| "image".into()), json!(uploaded))?;
    }
    let mut submit = json!({"prompt": wf});
    if cloud {
        submit["extra_data"] = json!({"api_key_comfy_org": key});
    }
    let r = m.http.post_json(&format!("{base}{api}/prompt"), &headers, &submit).map_err(|e| format!("Comfy workflow submit failed: {e}"))?;
    let pid = r["prompt_id"].as_str().filter(|s| !s.is_empty()).ok_or("Comfy workflow submit response missing prompt_id")?.to_string();
    let every = Duration::from_millis(t.get("poll_interval_ms").and_then(|v| v.as_integer()).filter(|v| *v > 0).unwrap_or(1500) as u64);
    let limit = t.get("timeout_ms").and_then(|v| v.as_integer()).filter(|v| *v > 0).map(|v| Duration::from_millis(v as u64)).unwrap_or(timeout);
    let entry: Value = crate::http::poll(cancel, every, limit, || {
        if cloud {
            let st = m.http.get_json(&format!("{base}/api/job/{pid}/status"), &headers).map_err(|e| format!("Comfy status lookup failed: {e}"))?;
            match st["status"].as_str() {
                Some("completed") => {
                    let h = m.http.get_json(&format!("{base}/api/history_v2/{pid}"), &headers).map_err(|e| format!("Comfy history lookup failed: {e}"))?;
                    Ok(Some(h.get(&pid).cloned().unwrap_or(h)))
                }
                Some(s @ ("failed" | "cancelled")) => Err(format!("Comfy workflow {s}: {}", st["error"].as_str().or_else(|| st["message"].as_str()).unwrap_or(&pid))),
                _ => Ok(None),
            }
        } else {
            let h = m.http.get_json(&format!("{base}/history/{pid}"), &headers).map_err(|e| format!("Comfy history lookup failed: {e}"))?;
            let Some(e) = h.get(&pid).cloned() else { return Ok(None) };
            if e["status"]["status_str"] == "error" {
                let detail = e["status"]["messages"].as_array().and_then(|ms| ms.iter().rev().find(|m| m[0] == "execution_error")).and_then(|m| m[1]["exception_message"].as_str().map(str::to_string));
                return Err(format!("Comfy workflow failed{}", detail.map(|d| format!(": {d}")).unwrap_or_default()));
            }
            let done = e["status"]["completed"] == true || e["outputs"].as_object().is_some_and(|o| !o.is_empty());
            Ok(done.then_some(e))
        }
    })?;
    let kinds: &[&str] = match capability {
        "music" => &["audio"],
        "video" => &["images", "gifs", "videos"],
        _ => &["images"],
    };
    let outputs = entry["outputs"].as_object().cloned().unwrap_or_default();
    let nodes: Vec<String> = match s(&t, "output_node_id") {
        Some(n) => vec![n],
        None => outputs.keys().cloned().collect(),
    };
    let mut files = vec![];
    for n in &nodes {
        for k in kinds {
            for f in outputs.get(n).and_then(|o| o[*k].as_array()).cloned().unwrap_or_default() {
                let name = f["filename"].as_str().or_else(|| f["name"].as_str()).unwrap_or("").to_string();
                if capability == "video" && *k == "images" && !(name.to_ascii_lowercase().ends_with(".mp4") || name.to_ascii_lowercase().ends_with(".webm")) {
                    continue;
                }
                files.push((n.clone(), f));
            }
        }
    }
    if files.is_empty() {
        return Err(format!("Comfy workflow {pid} completed without {capability} outputs"));
    }
    let mut out = vec![];
    for (node, f) in files {
        let name = f["filename"].as_str().or_else(|| f["name"].as_str()).filter(|s| !s.is_empty()).ok_or("Comfy output entry missing filename")?.to_string();
        let q = format!("filename={}&subfolder={}&type={}", ark_net::urlencode(&name), ark_net::urlencode(f["subfolder"].as_str().unwrap_or("")), ark_net::urlencode(f["type"].as_str().unwrap_or("output")));
        let r = m.http.get(&format!("{base}{api}/view?{q}"), &headers).map_err(|e| format!("Comfy output download failed: {e}"))?;
        let ct = r.content_type();
        let mime = if ct.is_empty() || ct == "application/octet-stream" { store::sniff(&r.body).to_string() } else { ct };
        out.push(WorkflowAsset { bytes: r.body, mime, file_name: name, node_id: node });
    }
    Ok((out, pid))
}

impl ImageProvider for Comfy {
    fn id(&self) -> &'static str {
        "comfy"
    }
    fn label(&self) -> &'static str {
        "ComfyUI"
    }
    fn env(&self) -> &'static [&'static str] {
        &[]
    }
    fn default_base(&self) -> &'static str {
        LOCAL
    }
    fn default_model(&self, _m: &Media) -> String {
        "workflow".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["workflow".into()]
    }
    fn configured(&self, m: &Media) -> bool {
        configured_in(&config(m, "image"))
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 1, edit: true, max_inputs: 1, ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, cancel: &Cancel) -> Result<ImageResult, String> {
        let (assets, pid) = run_workflow(m, "image", &req.prompt, req.inputs.first(), req.timeout, cancel)?;
        let images = assets.into_iter().map(|a| {
            let mut x = Asset::new(a.bytes, &a.mime);
            x.meta = json!({"node_id": a.node_id, "file_name": a.file_name});
            x
        });
        Ok(ImageResult { images: images.collect(), model: req.model.clone().unwrap_or_else(|| "workflow".into()), meta: json!({"prompt_id": pid}) })
    }
}
