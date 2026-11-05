//! MiniMax, Runway, BytePlus, Alibaba/Qwen (DashScope Wan), Kie AI, PixVerse,
//! Together, Z.AI, Novita, Vydra and ComfyUI video providers (OpenClaw
//! `extensions/*/video-generation-provider.ts`, `src/video-generation/dashscope-compatible.ts`).

use super::{download, err_of, remote, require_key, src_url, sstr, ModeCaps, VideoCaps, VideoProvider, VideoRequest, VideoResult};
use crate::genrt::{self, ProviderInfo};
use crate::http::Multipart;
use crate::store::Asset;
use crate::Media;
use seagent_core::Cancel;
use serde_json::{json, Map, Value};
use std::time::Duration;

fn bearer(c: &crate::Creds) -> Vec<(String, String)> {
    let mut v = c.headers.clone();
    v.extend(c.bearer());
    v
}

fn timed_out(label: String) -> impl Fn(String) -> String {
    move |e: String| if e.starts_with("timed out") { label.clone() } else { e }
}

#[allow(clippy::too_many_arguments)]
fn poll(m: &Media, cancel: &Cancel, url: &str, headers: &[(String, String)], every_ms: u64, timeout: Duration, what: &str, done: impl FnMut(&Value) -> Result<Option<Value>, String>) -> Result<Value, String> {
    genrt::poll_json(m, cancel, url, headers, every_ms, timeout, done).map_err(timed_out(format!("{what} did not finish in time")))
}

// ================================================================ MiniMax

pub struct Minimax;

fn minimax_base(m: &Media) -> crate::Creds {
    let mut c = m.creds("minimax", &["MINIMAX_API_KEY"], "https://api.minimax.io");
    if m.cfg.str("providers.minimax.base_url").is_none() {
        if let Ok(h) = std::env::var("MINIMAX_API_HOST") {
            let h = h.trim().trim_end_matches('/');
            if !h.is_empty() {
                c.base = if h.contains("://") { h.to_string() } else { format!("https://{h}") };
            }
        }
    }
    c
}

/// MiniMax `base_resp.status_code != 0` → error.
pub(crate) fn minimax_ok(v: &Value, label: &str) -> Result<(), String> {
    match v["base_resp"]["status_code"].as_i64() {
        Some(0) | None => Ok(()),
        Some(code) => Err(format!("{label}: {} (status_code {code})", v["base_resp"]["status_msg"].as_str().unwrap_or("error"))),
    }
}

const MM_DURS: &[(&str, &[u32])] = &[("MiniMax-Hailuo-2.3", &[6, 10]), ("MiniMax-Hailuo-02", &[6, 10])];
const MM_RES_ORDER: &[&str] = &["480P", "720P", "768P", "1080P"];

impl ProviderInfo for Minimax {
    fn id(&self) -> &'static str {
        "minimax"
    }
    fn label(&self) -> &'static str {
        "MiniMax"
    }
    fn env(&self) -> &'static [&'static str] {
        &["MINIMAX_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.minimax.io"
    }
    fn default_model(&self) -> String {
        "MiniMax-Hailuo-2.3".into()
    }
    fn models(&self) -> Vec<String> {
        ["MiniMax-Hailuo-2.3", "MiniMax-Hailuo-2.3-Fast", "MiniMax-Hailuo-02", "I2V-01-Director", "I2V-01-live", "I2V-01"].iter().map(|s| s.to_string()).collect()
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        minimax_base(m)
    }
}

impl VideoProvider for Minimax {
    fn caps(&self, model: &str) -> VideoCaps {
        let d = MM_DURS.iter().find(|(k, _)| *k == model).map(|x| x.1).unwrap_or(&[]);
        let g = ModeCaps::on().max_dur(10).durs(d).res(&["768P", "1080P"]);
        VideoCaps { i2v: g.clone().images(1), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("MiniMax video generation does not support video reference inputs.".into());
        }
        let c = self.creds(m);
        require_key(&c, "MiniMax")?;
        let h = bearer(&c);
        let mut body = json!({"model": req.model, "prompt": req.prompt});
        if let Some(i) = req.images.first() {
            body["first_frame_image"] = json!(src_url(i));
        }
        if let Some(r) = req.resolution.as_deref().map(str::to_ascii_uppercase) {
            let allowed: &[&str] = if ["MiniMax-Hailuo-2.3", "MiniMax-Hailuo-2.3-Fast", "MiniMax-Hailuo-02"].contains(&req.model.as_str()) { &["768P", "1080P"] } else { &[] };
            let pick = if allowed.is_empty() || allowed.contains(&r.as_str()) {
                Some(r.clone())
            } else {
                MM_RES_ORDER.iter().position(|x| *x == r).map(|ri| allowed.iter().min_by_key(|a| (MM_RES_ORDER.iter().position(|x| x == *a).unwrap_or(0) as i64 - ri as i64).abs()).unwrap().to_string())
            };
            if let Some(p) = pick {
                body["resolution"] = json!(p);
            }
        }
        if let Some(d) = req.duration {
            let allowed = MM_DURS.iter().find(|(k, _)| *k == req.model).map(|x| x.1);
            body["duration"] = json!(allowed.map(|a| *a.iter().min_by_key(|x| (**x as i64 - d as i64).abs()).unwrap()).unwrap_or(d));
        }
        let sub = m.http.post_json(&c.url("/v1/video_generation"), &h, &body).map_err(|e| format!("MiniMax video generation failed: {e}"))?;
        minimax_ok(&sub, "MiniMax video generation failed")?;
        let task = sstr(&sub, "task_id").ok_or("MiniMax video generation response missing task_id")?;
        let done = poll(m, cancel, &c.url(&format!("/v1/query/video_generation?task_id={}", seagent_net::urlencode(&task))), &h, 10000, req.timeout, &format!("MiniMax video generation task {task}"), |v| {
            minimax_ok(v, "MiniMax video generation failed")?;
            match v["status"].as_str() {
                Some("Success") => Ok(Some(v.clone())),
                Some("Fail") => Err(v["base_resp"]["status_msg"].as_str().filter(|s| !s.is_empty()).unwrap_or("MiniMax video generation failed").to_string()),
                _ => Ok(None),
            }
        })?;
        let (url, file_name) = if let Some(u) = sstr(&done, "video_url") {
            (u, None)
        } else if let Some(fid) = sstr(&done, "file_id") {
            let f = m.http.get_json(&c.url(&format!("/v1/files/retrieve?file_id={}", seagent_net::urlencode(&fid))), &h).map_err(|e| format!("MiniMax generated video metadata request failed: {e}"))?;
            minimax_ok(&f, "MiniMax generated video metadata request failed")?;
            (f["file"]["download_url"].as_str().filter(|s| !s.is_empty()).ok_or("MiniMax generated video metadata missing download_url")?.to_string(), f["file"]["filename"].as_str().map(str::to_string))
        } else {
            return Err("MiniMax video generation completed without a video URL or file_id".into());
        };
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model: req.model.clone(), meta: json!({"taskId": task, "status": done["status"], "fileId": done["file_id"], "videoUrl": url, "fileName": file_name}) })
    }
}

// ================================================================ Runway

pub struct Runway;

const RW_TEXT: &[&str] = &["gen4.5", "veo3.1", "veo3.1_fast", "veo3"];
const RW_IMAGE: &[&str] = &["gen4.5", "gen4_turbo", "gen3a_turbo", "veo3.1", "veo3.1_fast", "veo3"];
const RW_RATIOS: &[(&str, &str)] = &[("9:16", "720:1280"), ("16:9", "1280:720"), ("1:1", "960:960"), ("3:4", "832:1104"), ("4:3", "1104:832"), ("21:9", "1584:672")];
const RW_EDIT_ASPECTS: &[&str] = &["1:1", "16:9", "9:16", "3:4", "4:3", "21:9"];

impl ProviderInfo for Runway {
    fn id(&self) -> &'static str {
        "runway"
    }
    fn label(&self) -> &'static str {
        "Runway"
    }
    fn env(&self) -> &'static [&'static str] {
        &["RUNWAYML_API_SECRET", "RUNWAY_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.dev.runwayml.com"
    }
    fn default_model(&self) -> String {
        "gen4.5".into()
    }
    fn models(&self) -> Vec<String> {
        ["gen4.5", "gen4_turbo", "gen4_aleph", "gen3a_turbo", "veo3.1", "veo3.1_fast", "veo3"].iter().map(|s| s.to_string()).collect()
    }
}

impl VideoProvider for Runway {
    fn caps(&self, _model: &str) -> VideoCaps {
        VideoCaps { generate: ModeCaps::on().max_dur(10).aspects(&["16:9", "9:16"]), i2v: ModeCaps::on().images(1).max_dur(10).aspects(RW_EDIT_ASPECTS), v2v: ModeCaps::on().videos(1).aspects(RW_EDIT_ASPECTS), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let (ni, nv) = (req.images.len(), req.videos.len());
        if ni > 0 && nv > 0 {
            return Err("Runway video generation does not support image and video inputs together.".into());
        }
        if ni > 1 || nv > 1 {
            return Err("Runway video generation supports at most one input image or one input video.".into());
        }
        let endpoint = if nv > 0 { "/v1/video_to_video" } else if ni > 0 { "/v1/image_to_video" } else { "/v1/text_to_video" };
        let duration = req.duration.map(|d| d.clamp(2, 10)).unwrap_or(5);
        let ratio = match req.size.clone().or_else(|| req.aspect_ratio.as_deref().and_then(|a| RW_RATIOS.iter().find(|(k, _)| *k == a).map(|x| x.1.to_string()))) {
            Some(r) => {
                if ni == 0 && r != "1280:720" && r != "720:1280" {
                    return Err("Runway text-to-video currently supports only 16:9 or 9:16 output ratios.".into());
                }
                r
            }
            None => "1280:720".into(),
        };
        let model = req.model.clone();
        let body = if endpoint != "/v1/video_to_video" {
            let i2v = endpoint == "/v1/image_to_video";
            let allowed = if i2v { RW_IMAGE } else { RW_TEXT };
            if !allowed.contains(&model.as_str()) {
                return Err(format!("Runway {} does not support model {model}. Use one of: {}.", if i2v { "image-to-video" } else { "text-to-video" }, allowed.join(", ")));
            }
            let mut b = json!({"model": model, "promptText": req.prompt, "ratio": ratio, "duration": duration});
            if i2v {
                b["promptImage"] = json!(src_url(&req.images[0]));
            }
            b
        } else {
            if model != "gen4_aleph" {
                return Err("Runway video-to-video currently requires model gen4_aleph.".into());
            }
            json!({"model": model, "promptText": req.prompt, "videoUri": src_url(&req.videos[0]), "ratio": ratio})
        };
        let c = self.creds(m);
        require_key(&c, "Runway")?;
        let mut h = bearer(&c);
        h.push(("X-Runway-Version".into(), "2024-11-06".into()));
        let sub = m.http.post_json(&c.url(endpoint), &h, &body).map_err(|e| format!("Runway video generation failed: {e}"))?;
        let id = sstr(&sub, "id").ok_or("Runway video generation response missing task id")?;
        let done = poll(m, cancel, &c.url(&format!("/v1/tasks/{id}")), &h, 5000, req.timeout, &format!("Runway video generation task {id}"), |v| match v["status"].as_str() {
            Some("SUCCEEDED") => Ok(Some(v.clone())),
            Some(s @ ("FAILED" | "CANCELLED")) => Err(v["failure"].as_str().map(str::to_string).or_else(|| v["failure"]["message"].as_str().map(str::to_string)).unwrap_or_else(|| format!("Runway video generation {}", s.to_ascii_lowercase()))),
            Some("PENDING" | "RUNNING" | "THROTTLED") => Ok(None),
            Some(s) => Err(format!("Runway video status response returned unknown task status: {s}")),
            None => Err("Runway video status response missing task status".into()),
        })?;
        let urls: Vec<String> = done["output"].as_array().ok_or("Runway video generation completed with malformed output URLs")?.iter().filter_map(|u| u.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)).collect();
        if urls.is_empty() {
            return Err("Runway video generation completed without output URLs".into());
        }
        let mut videos = vec![];
        for u in &urls {
            let mut a = download(m, u, &h, &c.base)?;
            a.url = Some(u.clone());
            videos.push(a);
        }
        Ok(VideoResult { videos, model, meta: json!({"taskId": id, "status": done["status"], "endpoint": endpoint, "outputUrls": urls}) })
    }
}

// ================================================================ BytePlus (Seedance)

pub struct BytePlus;

impl ProviderInfo for BytePlus {
    fn id(&self) -> &'static str {
        "byteplus"
    }
    fn label(&self) -> &'static str {
        "BytePlus"
    }
    fn env(&self) -> &'static [&'static str] {
        &["BYTEPLUS_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://seagent.ap-southeast.bytepluses.com/api/v3"
    }
    fn default_model(&self) -> String {
        "seedance-1-0-pro-250528".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["seedance-1-0-pro-250528".into(), "seedance-1-5-pro-251215".into()]
    }
}

impl VideoProvider for BytePlus {
    fn caps(&self, _model: &str) -> VideoCaps {
        let g = ModeCaps::on().max_dur(12).aspect_ok().res_ok().audio().watermark().opts(&[("seed", "number"), ("draft", "boolean"), ("camera_fixed", "boolean")]);
        VideoCaps { i2v: g.clone().images(1), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("BytePlus video generation does not support video reference inputs.".into());
        }
        let c = self.creds(m);
        require_key(&c, "BytePlus")?;
        let h = bearer(&c);
        let mut content = vec![json!({"type": "text", "text": req.prompt})];
        if let Some(i) = req.images.first() {
            content.push(json!({"type": "image_url", "image_url": {"url": src_url(i)}, "role": "first_frame"}));
        }
        let mut body = json!({"model": req.model, "content": content});
        if let Some(a) = &req.aspect_ratio {
            body["ratio"] = json!(a);
        }
        if let Some(r) = &req.resolution {
            body["resolution"] = json!(r.to_ascii_lowercase());
        }
        if let Some(d) = req.duration.filter(|d| (2..=12).contains(d)) {
            body["duration"] = json!(d);
        }
        if let Some(a) = req.audio {
            body["generate_audio"] = json!(a);
        }
        if let Some(w) = req.watermark {
            body["watermark"] = json!(w);
        }
        if let Some(s) = req.seed().filter(|s| (-1..=2_147_483_647).contains(s)) {
            body["seed"] = json!(s);
        }
        if req.opt_bool("draft") == Some(true) && body["resolution"].is_null() {
            body["resolution"] = json!("480p");
        }
        if let Some(cf) = req.opt_bool("camera_fixed") {
            body["camera_fixed"] = json!(cf);
        }
        let sub = m.http.post_json(&c.url("/contents/generations/tasks"), &h, &body).map_err(|e| format!("BytePlus video generation failed: {e}"))?;
        let id = sstr(&sub, "id").ok_or("BytePlus video generation response missing task id")?;
        let done = poll(m, cancel, &c.url(&format!("/contents/generations/tasks/{id}")), &h, 5000, req.timeout, &format!("BytePlus video generation task {id}"), |v| match v["status"].as_str() {
            Some("succeeded") => Ok(Some(v.clone())),
            Some("failed" | "cancelled") => Err(v["error"]["message"].as_str().filter(|s| !s.is_empty()).unwrap_or("BytePlus video generation failed").to_string()),
            Some("running" | "queued") => Ok(None),
            Some(s) => Err(format!("BytePlus video status response returned unknown task status: {s}")),
            None => Err("BytePlus video status response missing task status".into()),
        })?;
        let url = done["content"]["video_url"].as_str().filter(|s| !s.is_empty()).ok_or("BytePlus video generation completed without a video URL")?.to_string();
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model: sstr(&done, "model").unwrap_or_else(|| req.model.clone()), meta: json!({"taskId": id, "status": done["status"], "videoUrl": url, "ratio": done["ratio"], "resolution": done["resolution"], "duration": done["duration"]}) })
    }
}

// ================================================================ DashScope Wan (Alibaba, Qwen)

pub struct Dashscope {
    id: &'static str,
    label: &'static str,
    task_label: &'static str,
    env: &'static [&'static str],
}

impl Dashscope {
    pub fn alibaba() -> Self {
        Dashscope { id: "alibaba", label: "Alibaba Model Studio", task_label: "Alibaba Wan", env: &["MODELSTUDIO_API_KEY", "DASHSCOPE_API_KEY", "QWEN_API_KEY"] }
    }
    pub fn qwen() -> Self {
        Dashscope { id: "qwen", label: "Qwen Cloud", task_label: "Qwen", env: &["QWEN_API_KEY", "MODELSTUDIO_API_KEY", "DASHSCOPE_API_KEY"] }
    }
}

const WAN_DURS_LONG: &[u32] = &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const WAN_DURS_SHORT: &[u32] = &[2, 3, 4, 5, 6, 7, 8, 9, 10];
const WAN_ASPECTS: &[&str] = &["16:9", "9:16", "1:1", "4:3", "3:4"];
const WAN_GEOM: &[(&str, &[(&str, &str)])] = &[
    ("480P", &[("16:9", "832*480"), ("9:16", "480*832"), ("1:1", "624*624")]),
    ("720P", &[("16:9", "1280*720"), ("9:16", "720*1280"), ("1:1", "960*960"), ("4:3", "1088*832"), ("3:4", "832*1088")]),
    ("1080P", &[("16:9", "1920*1080"), ("9:16", "1080*1920"), ("1:1", "1440*1440"), ("4:3", "1632*1248"), ("3:4", "1248*1632")]),
];

fn wan_sizes() -> Vec<&'static str> {
    WAN_GEOM.iter().filter(|(r, _)| *r != "480P").flat_map(|(_, s)| s.iter().map(|x| x.1)).collect()
}

fn wan_mode(model: &str, ni: usize, nv: usize) -> &'static str {
    let l = model.to_ascii_lowercase();
    if l.contains("-i2v") {
        "i2v"
    } else if l.contains("-r2v") {
        "r2v"
    } else if l.contains("-t2v") {
        "t2v"
    } else if nv > 0 || ni > 1 {
        "r2v"
    } else if ni == 1 {
        "i2v"
    } else {
        "t2v"
    }
}

/// OpenClaw `buildDashscopeVideoGenerationInput` + `…Parameters`.
pub fn wan_body(label: &str, req: &VideoRequest) -> Result<Value, String> {
    let mut model = req.model.trim().to_string();
    if model.starts_with("wan") && model.contains("-t2v") && req.images.len() == 1 && req.videos.is_empty() {
        let sib = model.replacen("-t2v", "-i2v", 1);
        if sib == "wan2.6-i2v" {
            model = sib;
        }
    }
    let (ni, nv) = (req.images.len(), req.videos.len());
    if req.videos.iter().any(|v| remote(v).is_none()) {
        return Err(format!("{label} video generation requires remote http(s) URLs for reference videos."));
    }
    let mode = wan_mode(&model, ni, nv);
    match mode {
        "t2v" if ni + nv > 0 => return Err(format!("{label} model {model} is text-to-video and does not accept reference media; use an i2v or r2v Wan model.")),
        "i2v" if ni != 1 || nv > 0 => return Err(format!("{label} model {model} requires exactly one reference image and no reference videos.")),
        "r2v" if ni + nv == 0 || ni + nv > 5 || nv > 3 => return Err(format!("{label} model {model} requires 1-5 reference images/videos, with at most 3 videos.")),
        _ => {}
    }
    let wan27 = model.to_ascii_lowercase().starts_with("wan2.7");
    let max_mb = if ["wan2.5", "wan2.6", "wan2.7"].iter().any(|p| model.starts_with(p)) { 20 } else { 10 };
    let mut urls = vec![];
    for i in &req.images {
        if mode == "r2v" && !wan27 {
            urls.push(remote(i).ok_or_else(|| format!("{label} model {model} requires remote http(s) URLs for reference images; use an i2v or Wan 2.7 model for local images."))?);
            continue;
        }
        if remote(i).is_none() && i.asset.bytes.len() > max_mb * 1024 * 1024 {
            return Err(format!("{label} reference image exceeds the {max_mb} MB limit."));
        }
        urls.push(src_url(i));
    }
    let mut input = json!({"prompt": req.prompt});
    if mode == "i2v" {
        input["img_url"] = json!(urls[0]);
    } else if mode == "r2v" && wan27 {
        let mut media: Vec<Value> = req.images.iter().zip(&urls).map(|(i, u)| json!({"type": i.role.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| "reference_image".into()), "url": u})).collect();
        media.extend(req.videos.iter().map(|v| json!({"type": v.role.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| "reference_video".into()), "url": remote(v).unwrap_or_default()})));
        input["media"] = json!(media);
    } else if mode == "r2v" {
        let mut r = urls.clone();
        r.extend(req.videos.iter().filter_map(remote));
        input["reference_urls"] = json!(r);
    }
    let mut params = Map::new();
    let geom = req.size.as_deref().and_then(|s| {
        let n = s.trim().to_ascii_lowercase().replace('x', "*");
        WAN_GEOM.iter().find_map(|(res, list)| list.iter().find(|(_, c)| c.eq_ignore_ascii_case(&n)).map(|(a, _)| (res.to_string(), a.to_string())))
    });
    if wan27 || mode == "i2v" {
        if let Some(r) = req.resolution.clone().or_else(|| geom.as_ref().map(|g| g.0.clone())) {
            params.insert("resolution".into(), json!(r));
        }
        if wan27 && mode != "i2v" {
            if let Some(a) = req.aspect_ratio.clone().or_else(|| geom.as_ref().map(|g| g.1.clone())) {
                params.insert("ratio".into(), json!(a));
            }
        }
    } else {
        let ratio = req.aspect_ratio.clone().unwrap_or_else(|| "16:9".into());
        let size = req.size.clone().or_else(|| {
            req.resolution.as_deref().and_then(|r| WAN_GEOM.iter().find(|(k, _)| *k == r).and_then(|(_, l)| l.iter().find(|(a, _)| *a == ratio).map(|x| x.1.to_string())).or_else(|| [("480P", "832*480"), ("720P", "1280*720"), ("1080P", "1920*1080")].iter().find(|(k, _)| *k == r).map(|x| x.1.to_string())))
        });
        if let Some(s) = size {
            params.insert("size".into(), json!(s));
        }
    }
    params.insert("duration".into(), json!(req.duration.unwrap_or(5)));
    if let (Some(a), false) = (req.audio, wan27) {
        params.insert("audio".into(), json!(a));
    }
    if let Some(w) = req.watermark {
        params.insert("watermark".into(), json!(w));
    }
    Ok(json!({"model": model, "input": input, "parameters": params}))
}

/// DashScope / Model Studio hosts take the AIGC API at the origin.
fn dashscope_origin(base: &str) -> String {
    let host = crate::http::host_of(base).to_ascii_lowercase();
    if (host.contains("dashscope") && host.ends_with(".aliyuncs.com")) || host.ends_with(".maas.aliyuncs.com") {
        let scheme = base.split_once("://").map(|x| x.0).unwrap_or("https");
        format!("{scheme}://{host}")
    } else {
        base.trim_end_matches('/').to_string()
    }
}

impl ProviderInfo for Dashscope {
    fn id(&self) -> &'static str {
        self.id
    }
    fn aliases(&self) -> &'static [&'static str] {
        if self.id == "alibaba" {
            &["dashscope", "modelstudio", "wan"]
        } else {
            &[]
        }
    }
    fn label(&self) -> &'static str {
        self.label
    }
    fn env(&self) -> &'static [&'static str] {
        self.env
    }
    fn default_base(&self) -> &'static str {
        "https://dashscope-intl.aliyuncs.com"
    }
    fn default_model(&self) -> String {
        "wan2.6-t2v".into()
    }
    fn models(&self) -> Vec<String> {
        ["wan2.6-t2v", "wan2.6-i2v", "wan2.6-r2v", "wan2.6-r2v-flash", "wan2.7-r2v"].iter().map(|s| s.to_string()).collect()
    }
}

impl VideoProvider for Dashscope {
    fn caps(&self, model: &str) -> VideoCaps {
        let sizes = wan_sizes();
        let g = ModeCaps::on().max_dur(15).durs(WAN_DURS_LONG).sizes(&sizes).aspects(WAN_ASPECTS).res(&["720P", "1080P"]).audio().watermark();
        let i = ModeCaps::on().images(1).max_dur(15).durs(WAN_DURS_LONG).res(&["720P", "1080P"]).audio().watermark();
        let mut v = ModeCaps::on().images(5).videos(3).max_dur(10).durs(WAN_DURS_SHORT).sizes(&sizes).aspects(WAN_ASPECTS).res(&["720P", "1080P"]).audio().watermark();
        let r2v = wan_mode(model, 0, 0) == "r2v";
        // OpenClaw `dashscopeWanR2vCapabilities`: an r2v model's image-to-video surface IS its
        // video-to-video caps (5 images / 3 videos / 10s), and wan2.7 adds aspect_ratio, drops audio.
        let wan27 = model.to_ascii_lowercase().starts_with("wan2.7");
        let mut i = if r2v { v.clone() } else { i };
        if r2v && wan27 {
            i = i.aspects(WAN_ASPECTS);
            i.supports_audio = false;
            v = v.aspects(WAN_ASPECTS);
            v.supports_audio = false;
        }
        let modes = match wan_mode(model, 0, 0) {
            "t2v" if model.contains("-t2v") => Some(vec!["generate", "i2v"]),
            "i2v" => Some(vec!["i2v"]),
            "r2v" => Some(vec!["i2v", "v2v"]),
            _ => None,
        };
        VideoCaps { generate: g, i2v: i, v2v: v, modes }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let c = self.creds(m);
        let key = require_key(&c, self.task_label)?;
        let unsupported = format!("{} video generation requires a Standard DashScope endpoint and a same-region Standard API key; Coding Plan and Token Plan credentials are not supported.", self.task_label);
        let host = crate::http::host_of(&c.base).to_ascii_lowercase();
        if key.trim().starts_with("sk-sp-") || host.starts_with("coding.dashscope") || host.starts_with("coding-intl.dashscope") || (host.starts_with("token-plan.") && host.ends_with(".maas.aliyuncs.com")) {
            return Err(unsupported);
        }
        let body = wan_body(self.task_label, req)?;
        let origin = dashscope_origin(&c.base);
        let mut h = bearer(&c);
        h.push(("X-DashScope-Async".into(), "enable".into()));
        let sub = m.http.post_json(&format!("{origin}/api/v1/services/aigc/video-generation/video-synthesis"), &h, &body).map_err(|e| format!("{} video generation failed: {e}", self.task_label))?;
        let task = sub["output"]["task_id"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| format!("{} video generation response missing task_id", self.task_label))?.to_string();
        let tl = self.task_label;
        let done = poll(m, cancel, &format!("{origin}/api/v1/tasks/{task}"), &h, 2500, req.timeout, &format!("{tl} video generation task {task}"), |v| {
            let st = v["output"]["task_status"].as_str().unwrap_or("").trim().to_ascii_uppercase();
            let msg = v["output"]["message"].as_str().or(v["message"].as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            match st.as_str() {
                "SUCCEEDED" => Ok(Some(v.clone())),
                "UNKNOWN" => Err(format!("{tl} video generation task {task} is unknown or expired{}", msg.map(|m| format!(": {m}")).unwrap_or_default())),
                "FAILED" | "CANCELED" => Err(msg.unwrap_or_else(|| format!("{tl} video generation task {task} {}", st.to_ascii_lowercase()))),
                _ => Ok(None),
            }
        })?;
        let mut urls: Vec<String> = done["output"]["results"].as_array().map(|a| a.iter().filter_map(|r| r["video_url"].as_str().map(str::to_string)).collect()).unwrap_or_default();
        if let Some(u) = done["output"]["video_url"].as_str() {
            urls.push(u.to_string());
        }
        urls.retain(|u| !u.trim().is_empty());
        urls.dedup();
        if urls.is_empty() {
            return Err(format!("{tl} video generation completed without output video URLs"));
        }
        let mut videos = vec![];
        for u in &urls {
            let mut a = download(m, u, &[], &origin)?;
            if !(a.mime.starts_with("video/") || a.mime == "application/octet-stream") {
                return Err(format!("{tl} generated video download: malformed video response"));
            }
            a.url = Some(u.clone());
            videos.push(a);
        }
        Ok(VideoResult { videos, model: body["model"].as_str().unwrap_or_default().to_string(), meta: json!({"requestId": sub["request_id"], "taskId": task, "taskStatus": done["output"]["task_status"]}) })
    }
}

// ================================================================ Kie AI

pub struct Kie;

#[derive(Clone, Copy)]
struct KieInput {
    durations: &'static [u32],
    numeric: bool,
    aspects: Option<&'static [&'static str]>,
    resolutions: Option<&'static [&'static str]>,
    upper_res: bool,
    audio_field: Option<&'static str>,
    image_field: Option<&'static str>,
    max_prompt: usize,
    min_prompt: usize,
}

const KI: KieInput = KieInput { durations: &[], numeric: false, aspects: None, resolutions: None, upper_res: false, audio_field: None, image_field: None, max_prompt: 5000, min_prompt: 1 };
const KLING: KieInput = KieInput { durations: &[5, 10], audio_field: Some("sound"), max_prompt: 1000, ..KI };
const GROK_D: &[u32] = &[6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
const GROK: KieInput = KieInput { durations: GROK_D, resolutions: Some(&["480P", "720P", "1080P"]), ..KI };
const WAN: KieInput = KieInput { durations: &[5, 10, 15], resolutions: Some(&["1080P", "720P"]), ..KI };
const HAILUO: KieInput = KieInput { max_prompt: 1500, ..KI };
const HAILUO23: KieInput = KieInput { durations: &[6, 10], resolutions: Some(&["768P", "1080P"]), upper_res: true, image_field: Some("image_url"), ..KI };
const SEEDANCE: KieInput = KieInput { durations: &[4, 5, 6, 7, 8, 9, 10, 11, 12], numeric: true, resolutions: Some(&["720P", "480P", "1080P"]), aspects: Some(&["16:9", "1:1", "4:3", "3:4", "9:16", "21:9"]), audio_field: Some("generate_audio"), max_prompt: 20000, min_prompt: 3, ..KI };

struct KieFamily {
    text: Option<(&'static str, KieInput)>,
    image: (&'static str, KieInput),
}

const KIE: &[KieFamily] = &[
    KieFamily { text: Some(("kling-2.6/text-to-video", KieInput { aspects: Some(&["16:9", "1:1", "9:16"]), ..KLING })), image: ("kling-2.6/image-to-video", KieInput { image_field: Some("image_urls"), ..KLING }) },
    KieFamily { text: Some(("grok-imagine/text-to-video", KieInput { numeric: true, aspects: Some(&["16:9", "2:3", "3:2", "1:1", "9:16"]), ..GROK })), image: ("grok-imagine/image-to-video", KieInput { image_field: Some("image_urls"), ..GROK }) },
    KieFamily { text: Some(("wan/2-6-text-to-video", WAN)), image: ("wan/2-6-image-to-video", KieInput { image_field: Some("image_urls"), min_prompt: 2, ..WAN }) },
    KieFamily { text: Some(("hailuo/02-text-to-video-standard", KieInput { durations: &[6, 10], ..HAILUO })), image: ("hailuo/02-image-to-video-standard", KieInput { durations: &[6, 10], resolutions: Some(&["768P", "512P"]), upper_res: true, image_field: Some("image_url"), ..HAILUO }) },
    KieFamily { text: Some(("hailuo/02-text-to-video-pro", HAILUO)), image: ("hailuo/02-image-to-video-pro", KieInput { image_field: Some("image_url"), ..HAILUO }) },
    KieFamily { text: None, image: ("hailuo/2-3-image-to-video-standard", HAILUO23) },
    KieFamily { text: None, image: ("hailuo/2-3-image-to-video-pro", HAILUO23) },
    KieFamily { text: Some(("bytedance/seedance-1.5-pro", SEEDANCE)), image: ("bytedance/seedance-1.5-pro", KieInput { image_field: Some("input_urls"), ..SEEDANCE }) },
];

fn kie_family(model: &str) -> Result<&'static KieFamily, String> {
    KIE.iter().find(|f| f.text.map(|t| t.0) == Some(model) || f.image.0 == model).ok_or_else(|| format!("Kie AI video generation does not support model {model}."))
}

fn kie_mode(i: Option<&KieInput>, image: bool) -> ModeCaps {
    let Some(i) = i else { return ModeCaps::off() };
    let mut c = ModeCaps::on().durs(i.durations).opts(&[]);
    if let Some(&d) = i.durations.iter().max() {
        c = c.max_dur(d);
    }
    if let Some(a) = i.aspects {
        c = c.aspects(a);
    }
    if let Some(r) = i.resolutions {
        c = c.res(r);
    }
    if i.audio_field.is_some() {
        c = c.audio();
    }
    if image {
        c = c.images(1);
    }
    c
}

fn kie_data(v: &Value) -> Result<Value, String> {
    if v["code"].as_i64() != Some(200) || v["success"] == false {
        return Err(format!("Kie AI request failed: {}", v["msg"].as_str().map(str::to_string).unwrap_or_else(|| format!("code {}", v["code"]))));
    }
    if !v["data"].is_object() {
        return Err("Kie AI response missing data.".into());
    }
    Ok(v["data"].clone())
}

impl ProviderInfo for Kie {
    fn id(&self) -> &'static str {
        "kie"
    }
    fn label(&self) -> &'static str {
        "Kie AI"
    }
    fn env(&self) -> &'static [&'static str] {
        &["KIE_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.kie.ai"
    }
    fn default_model(&self) -> String {
        "kling-2.6/text-to-video".into()
    }
    fn models(&self) -> Vec<String> {
        let mut v: Vec<String> = vec![];
        for f in KIE {
            for m in f.text.map(|t| t.0).into_iter().chain(std::iter::once(f.image.0)) {
                if !v.iter().any(|x| x == m) {
                    v.push(m.into());
                }
            }
        }
        v
    }
}

impl VideoProvider for Kie {
    fn caps(&self, model: &str) -> VideoCaps {
        let Ok(f) = kie_family(model) else { return VideoCaps::default() };
        VideoCaps { generate: kie_mode(f.text.as_ref().map(|t| &t.1), false), i2v: kie_mode(Some(&f.image.1), true), v2v: ModeCaps::off(), modes: Some(if f.text.is_some() { vec!["generate", "i2v"] } else { vec!["i2v"] }) }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() || !req.audios.is_empty() {
            return Err("Kie AI video generation does not support video or audio reference inputs.".into());
        }
        if req.images.len() > 1 {
            return Err("Kie AI video generation supports at most one input image.".into());
        }
        let image = req.images.first();
        if image.is_some() && !matches!(req.image_role(0).as_deref(), None | Some("") | Some("first_frame")) {
            return Err("Kie AI image-to-video supports only an ordinary or first_frame image.".into());
        }
        let f = kie_family(if req.model.trim().is_empty() { "kling-2.6/text-to-video" } else { req.model.trim() })?;
        let (model, spec) = match image {
            Some(_) => f.image,
            None => f.text.ok_or_else(|| format!("Kie AI model {} requires one input image.", req.model))?,
        };
        let plen = req.prompt.trim().chars().count();
        if plen < spec.min_prompt || req.prompt.chars().count() > spec.max_prompt {
            return Err(format!("Kie AI {model} requires a prompt of {}-{} characters.", spec.min_prompt, spec.max_prompt));
        }
        let mut input = json!({"prompt": req.prompt});
        if !spec.durations.is_empty() {
            let d = req.duration.map(|d| *spec.durations.iter().min_by_key(|x| (**x as i64 - d as i64).abs()).unwrap()).unwrap_or(spec.durations[0]);
            input["duration"] = if spec.numeric { json!(d) } else { json!(d.to_string()) };
        }
        if let Some(a) = spec.aspects {
            input["aspect_ratio"] = json!(req.aspect_ratio.clone().filter(|x| a.contains(&x.as_str())).unwrap_or_else(|| a[0].into()));
        }
        if let Some(r) = spec.resolutions {
            let want = req.resolution.as_deref().map(str::to_ascii_uppercase);
            let res = r.iter().find(|x| Some(x.to_string()) == want).copied().unwrap_or(r[0]);
            input["resolution"] = json!(if spec.upper_res { res.to_string() } else { res.to_ascii_lowercase() });
            if model.starts_with("hailuo/2-3-") && res == "1080P" && input["duration"] == "10" {
                return Err("Kie AI Hailuo 2.3 supports 1080P only at 6 seconds; use 768P for 10 seconds.".into());
            }
        }
        if let Some(af) = spec.audio_field {
            input[af] = json!(req.audio.unwrap_or(false));
        }
        let c = self.creds(m);
        require_key(&c, "Kie AI")?;
        let h = bearer(&c);
        if let (Some(img), Some(field)) = (image, spec.image_field) {
            let url = match remote(img) {
                Some(u) => u,
                None => {
                    if img.asset.bytes.len() > 10 * 1024 * 1024 {
                        return Err("Kie AI image-to-video supports images up to 10 MB.".into());
                    }
                    let ok: &[&str] = if model.starts_with("kling-") { &["image/jpeg", "image/png"] } else { &["image/jpeg", "image/png", "image/webp"] };
                    if !ok.contains(&img.asset.mime.as_str()) {
                        return Err(format!("Kie AI {model} requires {} image data.", ok.join(" or ")));
                    }
                    let up_base = m.cfg.str("providers.kie.upload_base_url").unwrap_or_else(|| "https://kieai.redpandaai.co".into());
                    let up = kie_data(&m.http.post_json(&format!("{}/api/file-base64-upload", up_base.trim_end_matches('/')), &h, &json!({"base64Data": img.data_url(), "uploadPath": "seagent/video-inputs"})).map_err(|e| format!("Kie AI request failed: {e}"))?)?;
                    up["downloadUrl"].as_str().filter(|u| u.starts_with("http")).ok_or("Kie AI image upload response missing downloadUrl.")?.to_string()
                }
            };
            input[field] = if field == "image_url" { json!(url) } else { json!([url]) };
        }
        let sub = kie_data(&m.http.post_json(&c.url("/api/v1/jobs/createTask"), &h, &json!({"model": model, "input": input})).map_err(|e| format!("Kie AI request failed: {e}"))?)?;
        let task = sstr(&sub, "taskId").ok_or("Kie AI video generation response missing taskId.")?;
        let done = poll(m, cancel, &c.url(&format!("/api/v1/jobs/recordInfo?taskId={}", seagent_net::urlencode(&task))), &h, 5000, req.timeout, &format!("Kie AI video generation task {task}"), |v| {
            let d = kie_data(v)?;
            match d["state"].as_str() {
                Some("success") => Ok(Some(d)),
                Some("waiting" | "queuing" | "generating") => Ok(None),
                Some("fail") => Err(format!("Kie AI video generation failed{}: {}", d["failCode"].as_str().map(str::to_string).or_else(|| d["failCode"].as_i64().map(|n| n.to_string())).map(|c| format!(" ({c})")).unwrap_or_default(), d["failMsg"].as_str().unwrap_or("generation failed"))),
                other => Err(format!("Kie AI video status response has unknown state: {}", other.unwrap_or("undefined"))),
            }
        })?;
        let result: Value = match done["resultJson"].as_str() {
            Some(s) => serde_json::from_str(s).map_err(|_| "Kie AI video generation returned malformed resultJson.".to_string())?,
            None => done["response"].clone(),
        };
        let urls: Vec<String> = result["resultUrls"].as_array().filter(|a| !a.is_empty()).ok_or("Kie AI video generation completed without result URLs.")?.iter().map(|u| u.as_str().filter(|s| !s.is_empty()).map(str::to_string).ok_or("Kie AI video generation returned a malformed result URL.".to_string())).collect::<Result<_, _>>()?;
        let mut videos = vec![];
        for u in &urls {
            let mut a = download(m, u, &h, &c.base)?;
            a.url = Some(u.clone());
            videos.push(a);
        }
        Ok(VideoResult { videos, model: model.into(), meta: json!({"taskId": task, "outputUrls": urls}) })
    }
}

// ================================================================ PixVerse

pub struct PixVerse;

const PV_ASPECTS: &[&str] = &["16:9", "4:3", "1:1", "3:4", "9:16", "2:3", "3:2", "21:9"];
const PV_Q: &[&str] = &["360p", "540p", "720p", "1080p"];

fn pv_ok(v: &Value, label: &str) -> Result<Value, String> {
    if v["ErrCode"].as_f64() != Some(0.0) {
        return Err(format!("{label}: {}", v["ErrMsg"].as_str().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| format!("ErrCode {}", v["ErrCode"]))));
    }
    if v["Resp"].is_null() {
        return Err(format!("{label}: response missing Resp"));
    }
    Ok(v["Resp"].clone())
}

impl ProviderInfo for PixVerse {
    fn id(&self) -> &'static str {
        "pixverse"
    }
    fn label(&self) -> &'static str {
        "PixVerse"
    }
    fn env(&self) -> &'static [&'static str] {
        &["PIXVERSE_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://app-api.pixverse.ai/openapi/v2"
    }
    fn default_model(&self) -> String {
        "v6".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["v6".into(), "c1".into()]
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        let mut c = m.creds("pixverse", self.env(), self.default_base());
        if m.cfg.str("providers.pixverse.base_url").is_none() && matches!(m.cfg.str("providers.pixverse.region").map(|r| r.to_ascii_lowercase()).as_deref(), Some("cn" | "china" | "mainland" | "pai")) {
            c.base = "https://app-api.pixverseai.cn/openapi/v2".into();
        }
        c
    }
}

impl VideoProvider for PixVerse {
    fn caps(&self, _model: &str) -> VideoCaps {
        let durs: Vec<u32> = (1..=15).collect();
        let o: &[(&str, &str)] = &[("seed", "number"), ("negative_prompt", "string"), ("negativePrompt", "string"), ("quality", "string"), ("camera_movement", "string"), ("cameraMovement", "string"), ("template_id", "number"), ("templateId", "number")];
        let mut oi = o.to_vec();
        oi.extend([("motion_mode", "string"), ("motionMode", "string")]);
        let g = ModeCaps::on().max_dur(15).durs(&durs).aspects(PV_ASPECTS).res(&["360P", "540P", "720P", "1080P"]).audio().opts(o);
        let mut i = ModeCaps::on().images(1).max_dur(15).durs(&durs).res(&["360P", "540P", "720P", "1080P"]).audio();
        i.options = Some(oi);
        VideoCaps { generate: g, i2v: i, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("PixVerse video generation does not support video reference inputs.".into());
        }
        if req.images.len() > 1 {
            return Err("PixVerse image-to-video supports at most one input image.".into());
        }
        let c = self.creds(m);
        let key = require_key(&c, "PixVerse")?;
        let hdr = |json_ct: bool| {
            let mut v = c.headers.clone();
            v.push(("API-KEY".into(), key.clone()));
            v.push(("Ai-trace-id".into(), crate::store::stem("seagent")));
            let _ = json_ct;
            v
        };
        let model = req.model.trim().trim_start_matches("pixverse/").to_ascii_lowercase();
        let model = if model.is_empty() { "v6".to_string() } else { model };
        let mut img_id = None;
        if let Some(i) = req.images.first() {
            let form = match remote(i) {
                Some(u) => Multipart::new().text("image_url", u),
                None => Multipart::new().file("image", &i.filename("image"), &i.asset.mime, i.asset.bytes.clone()),
            };
            let r = m.http.post_multipart(&c.url("/image/upload"), &hdr(false), &form).map_err(|e| format!("PixVerse image upload failed: {e}"))?.json()?;
            let resp = pv_ok(&r, "PixVerse image upload failed")?;
            img_id = Some(resp["img_id"].as_i64().filter(|n| *n >= 0).ok_or("PixVerse image upload response missing img_id")?);
        }
        let q = req.opt_str(&["quality"]).or_else(|| req.resolution.clone()).or_else(|| req.size.clone()).map(|q| q.to_ascii_lowercase()).map(|q| if q == "480p" { "540p".into() } else { q }).filter(|q| PV_Q.contains(&q.as_str())).unwrap_or_else(|| "540p".into());
        let mut body = json!({"duration": req.duration.unwrap_or(5).min(15), "model": model, "prompt": req.prompt, "quality": q});
        match img_id {
            Some(id) => {
                body["img_id"] = json!(id);
                body["motion_mode"] = json!(req.opt_str(&["motion_mode", "motionMode"]).unwrap_or_else(|| "normal".into()));
            }
            None => body["aspect_ratio"] = json!(req.aspect_ratio.clone().unwrap_or_else(|| "16:9".into())),
        }
        if let Some(n) = req.negative() {
            body["negative_prompt"] = json!(n);
        }
        if let Some(cm) = req.opt_str(&["camera_movement", "cameraMovement"]) {
            body["camera_movement"] = json!(cm);
        }
        if let Some(t) = req.opt_num(&["template_id", "templateId"]) {
            body["template_id"] = json!(t);
        }
        if let Some(s) = req.seed().filter(|s| (0..=2_147_483_647).contains(s)) {
            body["seed"] = json!(s);
        }
        if let Some(a) = req.audio {
            body["generate_audio_switch"] = json!(a);
        }
        let endpoint = if img_id.is_none() { "/video/text/generate" } else { "/video/img/generate" };
        let r = m.http.post_json(&c.url(endpoint), &hdr(true), &body).map_err(|e| format!("PixVerse video generation failed: {e}"))?;
        let resp = pv_ok(&r, "PixVerse video generation failed")?;
        let vid = resp["video_id"].as_i64().filter(|n| *n >= 0).ok_or("PixVerse video generation response missing video_id")?;
        let done = crate::http::poll(cancel, crate::http::poll_every(5000), req.timeout, || {
            let v = m.http.get_json(&c.url(&format!("/video/result/{vid}")), &hdr(false)).map_err(|e| format!("PixVerse video status request failed: {e}"))?;
            let r = pv_ok(&v, "PixVerse video status request failed")?;
            match r["status"].as_i64().ok_or("PixVerse video status response missing status")? {
                1 => Ok(Some(r)),
                7 => Err("PixVerse video generation failed content moderation".into()),
                8 => Err("PixVerse video generation failed".into()),
                6 => Err("PixVerse video generation was deleted before completion".into()),
                _ => Ok(None),
            }
        })
        .map_err(timed_out(format!("PixVerse video generation task {vid} did not finish in time")))?;
        let url = sstr(&done, "url").ok_or("PixVerse video generation completed without output URL")?;
        let mut a = genrt::fetch_asset(m, &url, &[], "video/mp4").unwrap_or_else(|_| Asset::from_url(&url, "video/mp4"));
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model, meta: json!({"endpoint": endpoint, "videoId": vid, "status": done["status"], "seed": done["seed"], "outputWidth": done["outputWidth"], "outputHeight": done["outputHeight"]}) })
    }
}

// ================================================================ Together

pub struct Together;

const TG_WAN_DURS: &[u32] = &[2, 3, 4, 5, 6, 7, 8, 9, 10];
const TG_SIZES: &[(&str, &str, &str)] = &[("1280x720", "720P", "16:9"), ("1920x1080", "1080P", "16:9"), ("720x1280", "720P", "9:16"), ("1080x1920", "1080P", "9:16"), ("960x960", "720P", "1:1"), ("1440x1440", "1080P", "1:1"), ("1104x832", "720P", "4:3"), ("1648x1248", "1080P", "4:3"), ("832x1104", "720P", "3:4"), ("1248x1648", "1080P", "3:4")];

impl ProviderInfo for Together {
    fn id(&self) -> &'static str {
        "together"
    }
    fn label(&self) -> &'static str {
        "Together"
    }
    fn env(&self) -> &'static [&'static str] {
        &["TOGETHER_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.together.xyz/v2"
    }
    fn default_model(&self) -> String {
        "Wan-AI/wan2.7-t2v".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["Wan-AI/wan2.7-t2v".into(), "Wan-AI/wan2.7-i2v".into(), "minimax/hailuo-02".into()]
    }
    fn default_timeout(&self) -> Duration {
        // OpenClaw `DEFAULT_OPERATION_TIMEOUT_MS` (live Wan 2.7 runs take ~10 minutes).
        Duration::from_secs(1200)
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        let mut c = m.creds("together", self.env(), self.default_base());
        // The chat base (`/v1`) is not the video surface.
        if c.base.trim_end_matches('/') == "https://api.together.xyz/v1" {
            c.base = self.default_base().into();
        }
        c
    }
}

impl VideoProvider for Together {
    fn caps(&self, model: &str) -> VideoCaps {
        let wan = model.starts_with("Wan-AI/wan2.7");
        let g = ModeCaps::on().max_dur(10).durs(if wan { TG_WAN_DURS } else { &[] }).size_ok();
        VideoCaps { i2v: g.clone().images(if model == "Wan-AI/wan2.7-i2v" { 1 } else { 0 }), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("Together video generation does not support video reference inputs.".into());
        }
        let c = self.creds(m);
        require_key(&c, "Together")?;
        let h = bearer(&c);
        let model = req.model.clone();
        let wan = model == "Wan-AI/wan2.7-t2v" || model == "Wan-AI/wan2.7-i2v";
        let mut body = json!({"model": model, "prompt": req.prompt});
        if let Some(d) = req.duration.filter(|d| (if wan { 2 } else { 1 }..=10).contains(d)) {
            body["seconds"] = json!(d.to_string());
        }
        if let Some(s) = &req.size {
            if wan {
                let (_, r, a) = TG_SIZES.iter().find(|x| x.0 == s).ok_or_else(|| format!("Together video model {model} does not support size {s}. Use {} or omit size.", TG_SIZES.iter().map(|x| x.0).collect::<Vec<_>>().join(", ")))?;
                body["resolution"] = json!(r);
                body["ratio"] = json!(a);
            } else if let Some((w, hh)) = genrt::parse_size(s) {
                body["width"] = json!(w);
                body["height"] = json!(hh);
            }
        }
        if let Some(i) = req.images.first() {
            if model != "Wan-AI/wan2.7-i2v" {
                return Err(format!("Together video model {model} does not support image reference inputs. Use Wan-AI/wan2.7-i2v or omit input images."));
            }
            body["media"] = json!({"frame_images": [{"input_image": src_url(i), "frame": "first"}]});
        }
        let failed = |v: &Value| (v["status"] == "failed").then(|| v["error"]["message"].as_str().filter(|s| !s.is_empty()).unwrap_or("Together video generation failed").to_string());
        let sub = m.http.post_json(&c.url("/videos"), &h, &body).map_err(|e| format!("Together video generation failed: {e}"))?;
        if let Some(e) = failed(&sub) {
            return Err(e);
        }
        let id = sstr(&sub, "id").ok_or("Together video generation response missing id")?;
        let done = if sub["status"] == "completed" {
            sub
        } else {
            poll(m, cancel, &c.url(&format!("/videos/{id}")), &h, 5000, req.timeout, &format!("Together video generation task {id}"), |v| match failed(v) {
                Some(e) => Err(e),
                None => Ok((v["status"] == "completed").then(|| v.clone())),
            })?
        };
        let url = match &done["outputs"] {
            Value::Array(a) => a.iter().find_map(|e| sstr(e, "video_url").or_else(|| sstr(e, "url"))),
            o => sstr(o, "video_url").or_else(|| sstr(o, "url")),
        }
        .ok_or("Together video generation completed without an output URL")?;
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model: sstr(&done, "model").unwrap_or(model), meta: json!({"videoId": id, "status": done["status"], "videoUrl": url}) })
    }
}

// ================================================================ Z.AI (CogVideoX)

pub struct Zai;

const ZAI_SIZES: &[&str] = &["1280x720", "720x1280", "1024x1024", "1920x1080", "1080x1920", "2048x1080", "3840x2160"];

impl ProviderInfo for Zai {
    fn id(&self) -> &'static str {
        "zai"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["z-ai", "z.ai", "zhipu", "glm"]
    }
    fn label(&self) -> &'static str {
        "Z.AI"
    }
    fn env(&self) -> &'static [&'static str] {
        &["ZAI_API_KEY", "Z_AI_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.z.ai/api/paas/v4"
    }
    fn default_model(&self) -> String {
        "cogvideox-3".into()
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        let mut c = m.creds("zai", self.env(), self.default_base());
        c.base = match c.base.trim_end_matches('/') {
            "https://open.bigmodel.cn/api/coding/paas/v4" => "https://open.bigmodel.cn/api/paas/v4".into(),
            "https://api.z.ai/api/coding/paas/v4" => "https://api.z.ai/api/paas/v4".into(),
            b => b.to_string(),
        };
        c
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

impl VideoProvider for Zai {
    fn caps(&self, _model: &str) -> VideoCaps {
        let g = ModeCaps::on().max_dur(10).durs(&[5, 10]).sizes(ZAI_SIZES).aspects(&["16:9", "9:16", "1:1"]).audio().opts(&[("quality", "string"), ("fps", "number")]);
        VideoCaps { i2v: g.clone().images(1), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if req.model != "cogvideox-3" {
            return Err(format!("Z.AI video generation does not support model {}. Use cogvideox-3.", req.model));
        }
        if !req.videos.is_empty() || !req.audios.is_empty() {
            return Err("Z.AI video generation does not support video or audio reference inputs.".into());
        }
        if req.images.len() > 1 {
            return Err("Z.AI video generation supports at most one input image.".into());
        }
        let quality = req.options.get("quality").cloned().unwrap_or(json!("speed"));
        if quality != "speed" && quality != "quality" {
            return Err("Z.AI video quality must be \"speed\" or \"quality\".".into());
        }
        let fps = req.options.get("fps").and_then(|v| v.as_f64()).unwrap_or(30.0);
        if fps != 30.0 && fps != 60.0 {
            return Err("Z.AI video fps must be 30 or 60.".into());
        }
        let sizes: Vec<String> = ZAI_SIZES.iter().map(|s| s.to_string()).collect();
        let size = genrt::closest_size(req.size.as_deref(), req.aspect_ratio.as_deref(), &sizes).unwrap_or_else(|| "1280x720".into());
        let mut body = json!({"model": req.model, "prompt": req.prompt, "quality": quality, "fps": fps as i64, "duration": req.duration.unwrap_or(5), "size": size, "with_audio": req.audio.unwrap_or(false)});
        if let Some(i) = req.images.first() {
            if !matches!(req.image_role(0).as_deref(), None | Some("") | Some("first_frame")) {
                return Err("Z.AI image-to-video supports only an ordinary or first_frame image.".into());
            }
            if remote(i).is_none() {
                if i.asset.bytes.len() > 5 * 1024 * 1024 {
                    return Err("Z.AI image-to-video requires a PNG or JPEG image no larger than 5 MB.".into());
                }
                if i.asset.mime != "image/png" && i.asset.mime != "image/jpeg" {
                    return Err("Z.AI image-to-video requires a PNG or JPEG image.".into());
                }
            }
            body["image_url"] = json!(src_url(i));
        }
        let c = self.creds(m);
        require_key(&c, "Z.AI")?;
        let h = bearer(&c);
        let sub = m.http.post_json(&c.url("/videos/generations"), &h, &body).map_err(|e| format!("Z.AI video generation failed: {e}"))?;
        let id = sstr(&sub, "id").ok_or("Z.AI video generation response missing task id")?;
        let done = poll(m, cancel, &c.url(&format!("/async-result/{}", seagent_net::urlencode(&id))), &h, 5000, req.timeout, &format!("Z.AI video generation task {id}"), |v| match v["task_status"].as_str() {
            Some("SUCCESS") => Ok(Some(v.clone())),
            Some("PROCESSING") => Ok(None),
            Some("FAIL") => Err(err_of(v).unwrap_or_else(|| "Z.AI video generation failed".into())),
            _ => Err("Z.AI video status response missing or unknown task_status".into()),
        })?;
        let url = done["video_result"][0]["url"].as_str().filter(|s| !s.is_empty()).ok_or("Z.AI video generation completed without a video URL")?.to_string();
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model: "cogvideox-3".into(), meta: json!({"taskId": id, "status": done["task_status"], "videoUrl": url}) })
    }
}

// ================================================================ Novita

pub struct Novita;

const NV_WAN_SIZES: &[&str] = &["1280x720", "720x1280", "960x960", "1088x832", "832x1088", "1920x1080", "1080x1920", "1440x1440", "1632x1248", "1248x1632"];
const NV_WAN_ASPECTS: &[&str] = &["16:9", "9:16", "1:1", "4:3", "3:4"];
const NV_WAN_OPTS: &[(&str, &str)] = &[("negative_prompt", "string"), ("prompt_extend", "boolean"), ("shot_type", "string"), ("seed", "number")];
const NV_HAILUO_OPTS: &[(&str, &str)] = &[("enable_prompt_expansion", "boolean"), ("fast_pretreatment", "boolean")];
const NV_MODELS: &[&str] = &["wan2.6-t2v", "wan2.6-i2v", "minimax-hailuo-2.3-t2v", "minimax-hailuo-2.3-i2v", "minimax-hailuo-2.3-fast-i2v"];

impl ProviderInfo for Novita {
    fn id(&self) -> &'static str {
        "novita"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["novita-ai", "novitaai"]
    }
    fn label(&self) -> &'static str {
        "NovitaAI"
    }
    fn env(&self) -> &'static [&'static str] {
        &["NOVITA_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.novita.ai"
    }
    fn default_model(&self) -> String {
        "wan2.6-t2v".into()
    }
    fn models(&self) -> Vec<String> {
        NV_MODELS.iter().map(|s| s.to_string()).collect()
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        let mut c = m.creds("novita", self.env(), self.default_base());
        c.base = c.base.trim_end_matches('/').trim_end_matches("/openai/v1").to_string();
        c
    }
}

impl VideoProvider for Novita {
    fn caps(&self, model: &str) -> VideoCaps {
        if model.starts_with("wan") {
            let base = ModeCaps::on().max_dur(15).durs(&[5, 10, 15]).res(&["720P", "1080P"]).audio().watermark().audios(1).opts(NV_WAN_OPTS);
            return VideoCaps { generate: base.clone().sizes(NV_WAN_SIZES).aspects(NV_WAN_ASPECTS), i2v: base.images(1), v2v: ModeCaps::off(), modes: Some(if model.ends_with("-i2v") { vec!["i2v"] } else { vec!["generate", "i2v"] }) };
        }
        let base = ModeCaps::on().max_dur(10).durs(&[6, 10]).res(&["768P", "1080P"]).opts(NV_HAILUO_OPTS);
        let mut i = base.clone().images(1);
        if model == "minimax-hailuo-2.3-fast-i2v" {
            i.options = Some(vec![("enable_prompt_expansion", "boolean")]);
        }
        VideoCaps { generate: base, i2v: i, v2v: ModeCaps::off(), modes: Some(if model.ends_with("-i2v") { vec!["i2v"] } else { vec!["generate", "i2v"] }) }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let mut model = req.model.clone();
        if !NV_MODELS.contains(&model.as_str()) {
            return Err(format!("Novita video generation does not support model {model}."));
        }
        if !req.videos.is_empty() {
            return Err("Novita video generation does not support video reference inputs.".into());
        }
        if req.images.len() > 1 {
            return Err("Novita video generation supports at most one input image.".into());
        }
        if req.images.is_empty() && model.ends_with("-i2v") {
            return Err(format!("Novita {model} requires one input image."));
        }
        if !req.images.is_empty() && !matches!(req.image_role(0).as_deref(), None | Some("") | Some("first_frame")) {
            return Err("Novita image-to-video supports only an ordinary or first_frame image.".into());
        }
        if !req.images.is_empty() {
            model = model.trim_end_matches("-t2v").to_string() + if model.ends_with("-t2v") { "-i2v" } else { "" };
        }
        let wan = model.starts_with("wan");
        let image = req.images.first().map(src_url);
        let caps = self.caps(&model);
        let schema = if image.is_some() { caps.i2v.options.unwrap_or_default() } else { caps.generate.options.unwrap_or_default() };
        for (k, v) in &req.options {
            let t = match v {
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                _ => "object",
            };
            if !schema.iter().any(|(sk, st)| sk == k && *st == t) {
                return Err(format!("Novita {model} does not support provider option {k} with this value."));
            }
        }
        if req.audios.len() > if wan { 1 } else { 0 } {
            return Err(format!("Novita {model} supports {} audio reference input.", if wan { "at most one" } else { "no" }));
        }
        let duration = req.duration.unwrap_or(if wan { 5 } else { 6 });
        let res = match req.resolution.as_deref().map(str::to_ascii_uppercase).as_deref() {
            Some("1080P") => "1080P",
            _ if wan => "720P",
            _ => "768P",
        };
        let body = if !wan {
            if duration == 10 && res == "1080P" {
                return Err("Novita Hailuo 1080P requires a 6-second duration; use 768P for 10 seconds.".into());
            }
            let mut b = json!({"prompt": req.prompt, "duration": duration, "resolution": res});
            for (k, v) in &req.options {
                b[k] = v.clone();
            }
            if let Some(i) = &image {
                b["image"] = json!(i);
            }
            b
        } else {
            let shot = req.options.get("shot_type").and_then(|v| v.as_str()).unwrap_or("multi");
            if shot != "single" && shot != "multi" {
                return Err("Novita Wan shot_type must be single or multi.".into());
            }
            if let Some(s) = req.options.get("seed") {
                if !s.as_i64().is_some_and(|n| (0..=2_147_483_647).contains(&n)) {
                    return Err("Novita Wan seed must be an integer between 0 and 2147483647.".into());
                }
            }
            let audio_url = req.audios.first().map(|a| remote(a).ok_or("Novita Wan audio reference input requires a remote http(s) URL.".to_string())).transpose()?;
            let mut input = json!({"prompt": req.prompt});
            if let Some(i) = &image {
                input["img_url"] = json!(i);
            }
            if let Some(a) = audio_url {
                input["audio_url"] = json!(a);
            }
            if let Some(n) = req.options.get("negative_prompt") {
                input["negative_prompt"] = n.clone();
            }
            let mut params = json!({"duration": duration, "audio": req.audio.unwrap_or(false), "prompt_extend": req.options.get("prompt_extend").cloned().unwrap_or(json!(true)), "shot_type": shot, "watermark": req.watermark.unwrap_or(false)});
            if image.is_some() {
                params["resolution"] = json!(res);
            } else {
                let size = req.size.as_deref().map(|s| s.replace('*', "x")).filter(|s| NV_WAN_SIZES.contains(&s.as_str())).unwrap_or_else(|| {
                    let ai = req.aspect_ratio.as_deref().and_then(|a| NV_WAN_ASPECTS.iter().position(|x| *x == a)).unwrap_or(0);
                    NV_WAN_SIZES[ai + if res == "1080P" { 5 } else { 0 }].to_string()
                });
                params["size"] = json!(size.replace('x', "*"));
            }
            if let Some(s) = req.options.get("seed") {
                params["seed"] = s.clone();
            }
            json!({"input": input, "parameters": params})
        };
        let c = self.creds(m);
        require_key(&c, "Novita")?;
        let h = bearer(&c);
        let endpoint = format!("/v3/async/{model}");
        let sub = m.http.post_json(&c.url(&endpoint), &h, &body).map_err(|e| format!("Novita video generation failed: {e}"))?;
        let task = sstr(&sub, "task_id").ok_or("Novita video generation response missing task_id")?;
        let done = poll(m, cancel, &c.url(&format!("/v3/async/task-result?task_id={}", seagent_net::urlencode(&task))), &h, 5000, req.timeout, &format!("Novita video generation task {task}"), |v| {
            if !v["task"].is_object() {
                return Err("Novita video status response missing task.".into());
            }
            match v["task"]["status"].as_str() {
                Some("TASK_STATUS_SUCCEED") => Ok(Some(v.clone())),
                Some("TASK_STATUS_QUEUED" | "TASK_STATUS_PROCESSING") => Ok(None),
                Some("TASK_STATUS_FAILED") => Err(format!("Novita video generation failed: {}", v["task"]["reason"].as_str().filter(|s| !s.is_empty()).unwrap_or("task failed"))),
                _ => Err("Novita video status response returned an unknown task status.".into()),
            }
        })?;
        let url = done["videos"][0]["video_url"].as_str().filter(|s| !s.is_empty()).ok_or("Novita video generation completed without a video URL")?.to_string();
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model, meta: json!({"taskId": task, "endpoint": endpoint, "videoUrl": url}) })
    }
}

// ================================================================ Vydra

pub struct Vydra;

/// Result URLs anywhere in a Vydra payload.
fn vydra_urls(v: &Value, out: &mut Vec<String>, depth: u32) {
    if depth > 5 {
        return;
    }
    match v {
        Value::String(s) if s.starts_with("http") && !out.contains(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| vydra_urls(x, out, depth + 1)),
        Value::Object(o) => {
            for k in ["videoUrl", "videoUrls", "resultUrl", "resultUrls", "outputUrl", "outputUrls", "url", "urls", "output", "outputs", "result", "results", "data", "asset", "assets"] {
                if let Some(x) = o.get(k) {
                    vydra_urls(x, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

impl ProviderInfo for Vydra {
    fn id(&self) -> &'static str {
        "vydra"
    }
    fn label(&self) -> &'static str {
        "Vydra"
    }
    fn env(&self) -> &'static [&'static str] {
        &["VYDRA_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://www.vydra.ai/api/v1"
    }
    fn default_model(&self) -> String {
        "veo3".into()
    }
    fn models(&self) -> Vec<String> {
        vec!["veo3".into(), "kling".into()]
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(120)
    }
    fn creds(&self, m: &Media) -> crate::Creds {
        let mut c = m.creds("vydra", self.env(), self.default_base());
        c.base = c.base.replace("://vydra.ai", "://www.vydra.ai");
        c
    }
}

impl VideoProvider for Vydra {
    fn caps(&self, _model: &str) -> VideoCaps {
        VideoCaps { generate: ModeCaps::on(), i2v: ModeCaps::on().images(1), v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("Vydra video generation does not support video reference inputs.".into());
        }
        let model = req.model.clone();
        let mut body = json!({"prompt": req.prompt});
        if model == "kling" {
            let u = req.images.first().and_then(remote).ok_or("Vydra kling currently requires a remote image URL reference.")?;
            // Vydra's kling route has been inconsistent about which field it requires.
            body["image_url"] = json!(u);
            body["video_url"] = json!(u);
        } else if !req.images.is_empty() {
            return Err(format!("Vydra {model} does not support image reference inputs in the Vydra plugin."));
        }
        let c = self.creds(m);
        require_key(&c, "Vydra")?;
        let h = bearer(&c);
        let sub = m.http.post_json(&c.url(&format!("models/{model}")), &h, &body).map_err(|e| format!("Vydra video generation failed: {e}"))?;
        let status = |v: &Value| v["status"].as_str().unwrap_or("").to_ascii_lowercase();
        let urls_of = |v: &Value| {
            let mut o = vec![];
            vydra_urls(v, &mut o, 0);
            o
        };
        let done = if status(&sub) == "completed" || !urls_of(&sub).is_empty() {
            sub.clone()
        } else {
            let id = sstr(&sub, "jobId").or_else(|| sstr(&sub, "id")).ok_or_else(|| err_of(&sub).unwrap_or_else(|| "Vydra video generation response missing job id".into()))?;
            poll(m, cancel, &c.url(&format!("jobs/{id}")), &h, 2500, req.timeout, &format!("Vydra job {id}"), |v| {
                if matches!(status(v).as_str(), "failed" | "error" | "cancelled") {
                    return Err(err_of(v).unwrap_or_else(|| format!("Vydra job {id} failed")));
                }
                Ok((status(v) == "completed" || !urls_of(v).is_empty()).then(|| v.clone()))
            })?
        };
        let url = urls_of(&done).into_iter().next().ok_or("Vydra video generation completed without a video URL")?;
        let mut a = download(m, &url, &h, &c.base)?;
        a.url = Some(url.clone());
        Ok(VideoResult { videos: vec![a], model, meta: json!({"jobId": done["jobId"].as_str().or(sub["jobId"].as_str()), "videoUrl": url, "status": "completed"}) })
    }
}

// ================================================================ ComfyUI

pub struct Comfy;

/// `[media.providers.comfy]` merged with its `video`/`music` sub-table has a workflow + prompt node.
pub(crate) fn comfy_configured(m: &Media, capability: &str) -> bool {
    let mut t = m.cfg.table("providers.comfy");
    if let Some(n) = t.get(capability).and_then(|v| v.as_table()).cloned() {
        t.extend(n);
    }
    (t.contains_key("workflow") || t.contains_key("workflow_path")) && t.contains_key("prompt_node_id")
}

impl ProviderInfo for Comfy {
    fn id(&self) -> &'static str {
        "comfy"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["comfyui"]
    }
    fn label(&self) -> &'static str {
        "ComfyUI"
    }
    fn env(&self) -> &'static [&'static str] {
        &[]
    }
    fn default_base(&self) -> &'static str {
        "http://127.0.0.1:8188"
    }
    fn default_model(&self) -> String {
        "workflow".into()
    }
    fn configured(&self, m: &Media) -> bool {
        comfy_configured(m, "video")
    }
}

impl VideoProvider for Comfy {
    fn caps(&self, _model: &str) -> VideoCaps {
        VideoCaps { generate: ModeCaps::on(), i2v: ModeCaps::on().images(1), v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let input = req.images.first().map(|s| crate::image_gen::InputImage { bytes: s.asset.bytes.clone(), mime: s.asset.mime.clone(), name: s.filename("input"), url: s.asset.url.clone() });
        let (assets, pid) = crate::image_gen::run_comfy_workflow(m, "video", &req.prompt, input.as_ref(), req.timeout, cancel)?;
        let videos = assets.into_iter().map(|a| {
            let mut x = Asset::new(a.bytes, &a.mime);
            x.meta = json!({"node_id": a.node_id, "file_name": a.file_name});
            x
        });
        Ok(VideoResult { videos: videos.collect(), model: "workflow".into(), meta: json!({"prompt_id": pid}) })
    }
}

