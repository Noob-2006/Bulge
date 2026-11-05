//! fal, xAI, OpenRouter, DeepInfra and Google video providers (OpenClaw
//! `extensions/{fal,xai,openrouter,deepinfra,google}/video-generation-provider.ts`,
//! Hermes `plugins/video_gen/{fal,xai,openrouter,deepinfra}`).

use super::{download, err_of, remote, require_key, snap_duration, src_url, sstr, ModeCaps, RunResult, VideoCaps, VideoProvider, VideoRequest, VideoResult};
use crate::genrt::{self, ProviderInfo};
use crate::store::Asset;
use crate::Media;
use seagent_core::Cancel;
use serde_json::{json, Map, Value};
use std::time::Duration;

fn h(c: &crate::Creds) -> Vec<(String, String)> {
    let mut v = c.headers.clone();
    v.extend(c.bearer());
    v
}

// ================================================================ fal

pub struct Fal;

/// One Hermes FAL model family (`plugins/video_gen/fal FAL_FAMILIES`).
pub struct Family {
    pub id: &'static str,
    pub t2v: Option<&'static str>,
    pub i2v: &'static str,
    pub aspects: &'static [&'static str],
    pub resolutions: &'static [&'static str],
    pub durations: Option<(u32, u32)>,
    pub duration_enum: &'static [u32],
    pub duration_int: bool,
    pub duration_suffix: &'static str,
    pub audio: bool,
    pub audio_native: bool,
    pub negative: bool,
    pub seed: bool,
    pub image_key: &'static str,
    pub drop_aspect_on_image: bool,
    pub audio_key: &'static str,
    pub res_aliases: &'static [(&'static str, &'static str)],
    pub static_payload: &'static [(&'static str, &'static str)],
    pub cap_by_res: &'static [(&'static str, u32)],
}

const F: Family = Family { id: "", t2v: None, i2v: "", aspects: &[], resolutions: &[], durations: None, duration_enum: &[], duration_int: false, duration_suffix: "", audio: false, audio_native: false, negative: false, seed: false, image_key: "image_url", drop_aspect_on_image: false, audio_key: "generate_audio", res_aliases: &[], static_payload: &[], cap_by_res: &[] };
const SIX: &[&str] = &["21:9", "16:9", "4:3", "1:1", "3:4", "9:16"];
const H3: &[(&str, &str)] = &[("480p", "768P"), ("540p", "768P"), ("720p", "768P"), ("768p", "768P"), ("1080p", "2K"), ("2k", "2K"), ("4k", "4K"), ("2160p", "4K")];
const H3_MAX: &[(&str, &str)] = &[("480p", "480P"), ("540p", "480P"), ("720p", "768P"), ("768p", "768P"), ("1080p", "768P"), ("2k", "768P"), ("4k", "768P"), ("2160p", "768P")];
const H3_TURBO: &[(&str, &str)] = &[("480p", "480P"), ("540p", "480P"), ("720p", "768P"), ("768p", "768P"), ("1080p", "1080P"), ("2k", "1080P"), ("4k", "1080P"), ("2160p", "1080P")];
const BAL: &[(&str, &str)] = &[("prompt_expansion_mode", "balanced")];

pub const FAMILIES: &[Family] = &[
    Family { id: "ltx-2.3", t2v: Some("fal-ai/ltx-2.3-22b/text-to-video"), i2v: "fal-ai/ltx-2.3-22b/image-to-video", audio: true, negative: true, seed: true, ..F },
    Family { id: "ltx-2.5", t2v: Some("lightricks/ltx-2.5/text-to-video/fast"), i2v: "lightricks/ltx-2.5/image-to-video/fast", duration_int: true, aspects: &["16:9", "9:16"], resolutions: &["720p", "1080p", "1440p", "2160p"], res_aliases: &[("2k", "1440p"), ("4k", "2160p")], durations: Some((6, 20)), duration_enum: &[6, 8, 10, 12, 14, 16, 18, 20], cap_by_res: &[("1440p", 10), ("2160p", 10)], audio: true, ..F },
    Family { id: "pixverse-v6", t2v: Some("fal-ai/pixverse/v6/text-to-video"), i2v: "fal-ai/pixverse/v6/image-to-video", resolutions: &["360p", "540p", "720p", "1080p"], durations: Some((1, 15)), audio: true, negative: true, seed: true, ..F },
    Family { id: "seedance-2.0-mini", t2v: Some("bytedance/seedance-2.0/mini/text-to-video"), i2v: "bytedance/seedance-2.0/mini/image-to-video", aspects: SIX, resolutions: &["480p", "720p"], durations: Some((4, 15)), audio: true, ..F },
    Family { id: "veo3.1", t2v: Some("fal-ai/veo3.1"), i2v: "fal-ai/veo3.1/image-to-video", aspects: &["16:9", "9:16"], resolutions: &["720p", "1080p", "4k"], durations: Some((4, 8)), duration_enum: &[4, 6, 8], duration_suffix: "s", audio: true, negative: true, seed: true, ..F },
    Family { id: "seedance-2.0", t2v: Some("bytedance/seedance-2.0/text-to-video"), i2v: "bytedance/seedance-2.0/image-to-video", aspects: SIX, resolutions: &["480p", "720p", "1080p"], durations: Some((4, 15)), audio: true, ..F },
    Family { id: "seedance-2.5", t2v: Some("bytedance/seedance-2.5/text-to-video"), i2v: "bytedance/seedance-2.5/image-to-video", aspects: SIX, drop_aspect_on_image: true, resolutions: &["480p", "720p"], durations: Some((4, 30)), audio: true, ..F },
    Family { id: "minimax-h3", t2v: Some("minimax/h3/text-to-video"), i2v: "minimax/h3/image-to-video", duration_int: true, drop_aspect_on_image: true, aspects: SIX, resolutions: &["768P", "2K", "4K"], res_aliases: H3, durations: Some((5, 15)), audio_native: true, ..F },
    Family { id: "minimax-h3-max", t2v: Some("minimax/h3-max/text-to-video"), i2v: "minimax/h3-max/image-to-video", duration_int: true, drop_aspect_on_image: true, aspects: SIX, resolutions: &["480P", "768P"], res_aliases: H3_MAX, durations: Some((5, 15)), static_payload: BAL, audio_native: true, seed: true, ..F },
    Family { id: "minimax-h3-max-turbo", t2v: Some("minimax/h3-max-turbo/text-to-video"), i2v: "minimax/h3-max-turbo/image-to-video", duration_int: true, drop_aspect_on_image: true, aspects: SIX, resolutions: &["480P", "768P", "1080P"], res_aliases: H3_TURBO, durations: Some((5, 15)), static_payload: BAL, audio_native: true, seed: true, ..F },
    Family { id: "flux-3", t2v: Some("blackforestlabs/flux-3/text-to-video"), i2v: "blackforestlabs/flux-3/image-to-video", duration_int: true, aspects: &["21:9", "2:1", "16:9", "4:3", "1:1", "3:4", "9:16"], resolutions: &["720p", "1080p"], durations: Some((5, 20)), audio: true, ..F },
    Family { id: "grok-imagine-1.5", t2v: Some("xai/grok-imagine-video/v1.5/text-to-video"), i2v: "xai/grok-imagine-video/v1.5/image-to-video", duration_int: true, drop_aspect_on_image: true, aspects: &["16:9", "4:3", "3:2", "1:1", "2:3", "3:4", "9:16"], resolutions: &["480p", "720p", "1080p"], durations: Some((1, 15)), audio_native: true, ..F },
    Family { id: "gemini-omni-flash", t2v: Some("google/gemini-omni-flash/v1.1/text-to-video"), i2v: "google/gemini-omni-flash/v1.1/image-to-video", duration_int: true, aspects: &["16:9", "9:16"], resolutions: &["360p", "720p", "1080p", "4k"], durations: Some((3, 10)), audio_native: true, ..F },
    Family { id: "kling-v3", t2v: Some("fal-ai/kling-video/v3/standard/text-to-video"), i2v: "fal-ai/kling-video/v3/standard/image-to-video", image_key: "start_image_url", drop_aspect_on_image: true, aspects: &["16:9", "9:16", "1:1"], durations: Some((3, 15)), audio: true, negative: true, ..F },
    Family { id: "kling-v3-pro", t2v: Some("fal-ai/kling-video/v3/pro/text-to-video"), i2v: "fal-ai/kling-video/v3/pro/image-to-video", image_key: "start_image_url", drop_aspect_on_image: true, aspects: &["16:9", "9:16", "1:1"], durations: Some((3, 15)), audio: true, negative: true, ..F },
    Family { id: "kling-v3-4k", t2v: Some("fal-ai/kling-video/v3/4k/text-to-video"), i2v: "fal-ai/kling-video/v3/4k/image-to-video", image_key: "start_image_url", aspects: &["16:9", "9:16", "1:1"], durations: Some((3, 15)), audio: true, negative: true, seed: true, ..F },
    Family { id: "kling-o3", t2v: Some("fal-ai/kling-video/o3/standard/text-to-video"), i2v: "fal-ai/kling-video/o3/standard/image-to-video", drop_aspect_on_image: true, aspects: &["16:9", "9:16", "1:1"], durations: Some((3, 15)), audio: true, ..F },
    Family { id: "wan-3.0", t2v: Some("alibaba/wan-3.0/text-to-video"), i2v: "alibaba/wan-3.0/image-to-video", image_key: "start_image_url", duration_int: true, audio_key: "audio", aspects: &["16:9", "4:3", "1:1", "3:4", "9:16"], resolutions: &["480p", "720p", "1080p"], durations: Some((2, 30)), audio: true, seed: true, ..F },
    Family { id: "wan-3.0-prime", t2v: Some("alibaba/wan-3.0-prime/text-to-video"), i2v: "alibaba/wan-3.0-prime/image-to-video", image_key: "start_image_url", duration_int: true, audio_key: "audio", aspects: &["16:9", "4:3", "1:1", "3:4", "9:16"], resolutions: &["480p", "720p", "1080p"], durations: Some((2, 30)), audio: true, seed: true, ..F },
    Family { id: "happy-horse", t2v: Some("alibaba/happy-horse/v1.1/text-to-video"), i2v: "alibaba/happy-horse/v1.1/image-to-video", duration_int: true, drop_aspect_on_image: true, aspects: &["16:9", "9:16", "1:1", "4:3", "3:4", "21:9", "9:21", "5:4", "4:5"], resolutions: &["720p", "1080p"], durations: Some((3, 15)), audio_native: true, seed: true, ..F },
];

const FAL_DEFAULT: &str = "pixverse-v6";
const FAL_MINIMAX_LIVE: &str = "fal-ai/minimax/video-01-live";
const FAL_HEYGEN: &str = "fal-ai/heygen/v2/video-agent";
const SEEDANCE_TI: &[&str] = &["bytedance/seedance-2.0/fast/text-to-video", "bytedance/seedance-2.0/fast/image-to-video", "bytedance/seedance-2.0/text-to-video", "bytedance/seedance-2.0/image-to-video"];
const SEEDANCE_REF: &[&str] = &["bytedance/seedance-2.0/fast/reference-to-video", "bytedance/seedance-2.0/reference-to-video"];
const SEEDANCE_DURS: &[u32] = &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const FAL_UPSCALER: &str = "fal-ai/seedvr/upscale/video";

/// Hermes `_normalize_family_key`: a family id from a bare id, endpoint path, stem or prefixed name.
pub fn family_of(c: &str) -> Option<&'static Family> {
    let c = c.trim();
    if c.is_empty() {
        return None;
    }
    if let Some(f) = FAMILIES.iter().find(|f| f.id == c) {
        return Some(f);
    }
    let eps = || FAMILIES.iter().flat_map(|f| f.t2v.into_iter().chain(std::iter::once(f.i2v)).map(move |e| (f, e)));
    if let Some((f, _)) = eps().find(|(_, e)| *e == c) {
        return Some(f);
    }
    if let Some((f, _)) = eps().find(|(_, e)| e.strip_prefix(&format!("{c}/")).map(|r| r.split('/').next().is_some_and(|s| s == "text-to-video" || s == "image-to-video")).unwrap_or(false)) {
        return Some(f);
    }
    let parts: Vec<&str> = c.split('/').collect();
    let mut hits: Vec<&Family> = FAMILIES.iter().filter(|f| parts.contains(&f.id)).collect();
    hits.sort_by_key(|f| std::cmp::Reverse(f.id.len()));
    hits.first().copied()
}

fn fal_clamp(f: &Family, d: Option<u32>, res: Option<&str>) -> Option<u32> {
    let d = d?;
    let mut v = if !f.duration_enum.is_empty() {
        *f.duration_enum.iter().min_by_key(|e| (**e as i64 - d as i64).abs()).unwrap()
    } else {
        let (lo, hi) = f.durations?;
        d.clamp(lo, hi)
    };
    if let Some((_, cap)) = f.cap_by_res.iter().find(|(r, _)| Some(*r) == res) {
        v = v.min(*cap);
    }
    Some(v)
}

/// Hermes `_build_payload`.
pub fn family_payload(f: &Family, req: &VideoRequest, image_url: Option<&str>) -> Value {
    let mut p = Map::new();
    p.insert("prompt".into(), json!(req.prompt));
    if let Some(u) = image_url {
        p.insert(f.image_key.into(), json!(u));
    }
    if let (Some(s), true) = (req.seed(), f.seed) {
        p.insert("seed".into(), json!(s));
    }
    let aspect = req.aspect_ratio.clone().unwrap_or_else(|| "16:9".into());
    if f.aspects.contains(&aspect.as_str()) {
        p.insert("aspect_ratio".into(), json!(aspect));
    }
    let res_in = req.resolution.clone().unwrap_or_else(|| "720p".into());
    let resolved = f.res_aliases.iter().find(|(k, _)| k.eq_ignore_ascii_case(&res_in)).map(|(_, v)| v.to_string()).unwrap_or_else(|| if f.resolutions.iter().any(|r| r.eq_ignore_ascii_case(&res_in)) { f.resolutions.iter().find(|r| r.eq_ignore_ascii_case(&res_in)).unwrap().to_string() } else { res_in.clone() });
    if f.resolutions.contains(&resolved.as_str()) {
        p.insert("resolution".into(), json!(resolved));
    }
    if f.durations.is_some() {
        if let Some(d) = fal_clamp(f, req.duration, Some(&resolved)) {
            p.insert("duration".into(), if f.duration_int { json!(d) } else { json!(format!("{d}{}", f.duration_suffix)) });
        }
    }
    if let (true, Some(a)) = (f.audio, req.audio) {
        p.insert(f.audio_key.into(), json!(a));
    }
    if let (true, Some(n)) = (f.negative, req.negative()) {
        p.insert("negative_prompt".into(), json!(n));
    }
    if image_url.is_some() && f.drop_aspect_on_image {
        p.remove("aspect_ratio");
    }
    for (k, v) in f.static_payload {
        p.entry(k.to_string()).or_insert(json!(v));
    }
    Value::Object(p)
}

/// OpenClaw `buildFalVideoRequestBody` for raw fal endpoints.
pub fn endpoint_payload(req: &VideoRequest, model: &str) -> Result<Value, String> {
    let (ni, nv, na) = (req.images.len(), req.videos.len(), req.audios.len());
    let reference = SEEDANCE_REF.contains(&model);
    let seedance = reference || SEEDANCE_TI.contains(&model);
    if reference {
        for (count, max, label) in [(ni, 9, "reference images"), (nv, 3, "reference videos"), (na, 3, "reference audios"), (ni + nv + na, 12, "total reference files")] {
            if count > max {
                return Err(format!("fal Seedance reference-to-video supports at most {max} {label}."));
            }
        }
        if na > 0 && ni == 0 && nv == 0 {
            return Err("fal Seedance reference-to-video requires at least one image or video reference when audio references are provided.".into());
        }
    } else {
        if nv > 0 {
            return Err("fal video generation does not support video reference inputs.".into());
        }
        if na > 0 {
            return Err("fal video generation does not support audio reference inputs.".into());
        }
        if ni > 1 {
            return Err("fal video generation supports at most one image reference.".into());
        }
    }
    let mut b = Map::new();
    b.insert("prompt".into(), json!(req.prompt));
    let controls = |b: &mut Map<String, Value>| {
        if let Some(a) = &req.aspect_ratio {
            b.insert("aspect_ratio".into(), json!(a));
        }
        if let Some(s) = &req.size {
            b.insert("size".into(), json!(s));
        }
        if let Some(r) = &req.resolution {
            b.insert("resolution".into(), json!(if seedance { r.to_ascii_lowercase() } else { r.clone() }));
        }
        if let Some(d) = req.duration {
            if seedance {
                if SEEDANCE_DURS.contains(&d) {
                    b.insert("duration".into(), json!(d.to_string()));
                }
            } else {
                b.insert("duration".into(), json!(d));
            }
        }
        if let (true, Some(a)) = (seedance, req.audio) {
            b.insert("generate_audio".into(), json!(a));
        }
    };
    if reference {
        for (field, list) in [("image_urls", &req.images), ("video_urls", &req.videos), ("audio_urls", &req.audios)] {
            if !list.is_empty() {
                b.insert(field.into(), json!(list.iter().map(src_url).collect::<Vec<_>>()));
            }
        }
        controls(&mut b);
        return Ok(Value::Object(b));
    }
    if let Some(i) = req.images.first() {
        b.insert("image_url".into(), json!(src_url(i)));
    }
    let lm = model.to_ascii_lowercase();
    if lm != FAL_MINIMAX_LIVE && lm != FAL_HEYGEN {
        controls(&mut b);
    }
    Ok(Value::Object(b))
}

fn fal_queue_base(base: &str) -> String {
    base.trim_end_matches('/').replace("://fal.run", "://queue.fal.run")
}

fn fal_headers(c: &crate::Creds) -> Result<Vec<(String, String)>, String> {
    let k = c.key.clone().ok_or("No FAL backend available. Set FAL_KEY (or [media.providers.fal] api_key).")?;
    let mut v = c.headers.clone();
    v.push(("Authorization".into(), format!("Key {k}")));
    Ok(v)
}

/// Submit to the fal queue and wait for the result payload. Returns `(request_id, payload)`.
pub fn fal_queue(m: &Media, c: &crate::Creds, endpoint: &str, body: &Value, timeout: Duration, cancel: &Cancel) -> Result<(Option<String>, Value), String> {
    let mut headers = fal_headers(c)?;
    let base = fal_queue_base(&c.base);
    let mut sh = headers.clone();
    sh.push(("x-idempotency-key".into(), crate::store::stem("seagent")));
    let sub = m.http.post_json(&format!("{base}/{endpoint}"), &sh, body).map_err(|e| format!("fal video generation failed: {e}"))?;
    let rid = sstr(&sub, "request_id");
    let (Some(status_url), Some(response_url)) = (sstr(&sub, "status_url"), sstr(&sub, "response_url")) else {
        return Err("fal video generation response missing queue URLs".into());
    };
    headers.dedup();
    let mut last = "unknown".to_string();
    crate::http::poll(cancel, crate::http::poll_every(5000), timeout, || {
        let st = m.get_json_checked(&status_url, &headers).map_err(|e| format!("fal video status request failed: {e}"))?;
        let s = st["status"].as_str().map(|s| s.to_ascii_uppercase()).ok_or("fal video generation response malformed")?;
        last = s.clone();
        match s.as_str() {
            "COMPLETED" => Ok(Some(())),
            "FAILED" | "CANCELLED" => Err(sstr(&st, "detail").or_else(|| err_of(&st)).unwrap_or_else(|| format!("fal video generation {}", s.to_ascii_lowercase()))),
            "IN_QUEUE" | "IN_PROGRESS" | "PROCESSING" | "QUEUED" | "STARTED" => Ok(None),
            _ => Err("fal video generation response malformed".into()),
        }
    })
    .map_err(|e| if e.starts_with("timed out") { format!("fal video generation did not finish in time (last status: {last})") } else { e })?;
    let res = m.get_json_checked(&response_url, &headers).map_err(|e| format!("fal video result request failed: {e}"))?;
    let payload = if res.get("response").is_some_and(|r| r.is_object()) { res["response"].clone() } else { res };
    Ok((rid, payload))
}

fn fal_video_url(p: &Value) -> Option<(String, Value)> {
    if let Some(u) = p["video"]["url"].as_str().filter(|s| !s.is_empty()) {
        return Some((u.to_string(), p["video"].clone()));
    }
    if let Some(u) = p["video"].as_str().filter(|s| !s.is_empty()) {
        return Some((u.to_string(), Value::Null));
    }
    p["videos"].as_array().and_then(|a| a.iter().find_map(|v| v["url"].as_str().filter(|s| !s.is_empty()).map(|u| (u.to_string(), v.clone()))))
}

impl ProviderInfo for Fal {
    fn id(&self) -> &'static str {
        "fal"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["fal-ai", "falai"]
    }
    fn label(&self) -> &'static str {
        "fal"
    }
    fn env(&self) -> &'static [&'static str] {
        &["FAL_KEY", "FAL_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://queue.fal.run"
    }
    fn default_model(&self) -> String {
        std::env::var("FAL_VIDEO_MODEL").ok().filter(|s| family_of(s).is_some()).unwrap_or_else(|| FAL_DEFAULT.into())
    }
    fn models(&self) -> Vec<String> {
        let mut v: Vec<String> = FAMILIES.iter().map(|f| f.id.to_string()).collect();
        v.extend([FAL_MINIMAX_LIVE, FAL_HEYGEN].iter().chain(SEEDANCE_TI).chain(SEEDANCE_REF).chain(["fal-ai/kling-video/v2.1/master/text-to-video", "fal-ai/wan/v2.2-a14b/text-to-video", "fal-ai/wan/v2.2-a14b/image-to-video"].iter()).map(|s| s.to_string()));
        v
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(1200)
    }
}

impl VideoProvider for Fal {
    fn caps(&self, model: &str) -> VideoCaps {
        if let Some(f) = family_of(model) {
            // Hermes clamps durations into the family range inside the payload builder.
            let mut g = ModeCaps::on().aspect_ok().res_ok();
            if f.audio {
                g = g.audio();
            }
            return VideoCaps { generate: g.clone(), i2v: ModeCaps { enabled: true, max_images: 1, ..g }, v2v: ModeCaps::off(), modes: Some(if f.t2v.is_some() { vec!["generate", "i2v"] } else { vec!["i2v"] }) };
        }
        let seedance = SEEDANCE_TI.contains(&model) || SEEDANCE_REF.contains(&model);
        let mut base = ModeCaps::on().aspect_ok().res_ok().size_ok().audio();
        if seedance {
            base = base.durs(SEEDANCE_DURS);
        }
        if SEEDANCE_REF.contains(&model) {
            let r = base.clone().images(9).videos(3).audios(3);
            return VideoCaps { generate: base, i2v: r.clone(), v2v: r, modes: None };
        }
        VideoCaps { generate: base.clone(), i2v: base.images(1), v2v: ModeCaps::off(), modes: None }
    }

    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let c = self.creds(m);
        let (endpoint, body, family) = match family_of(&req.model) {
            Some(f) => {
                if !req.videos.is_empty() || !req.audios.is_empty() || req.images.len() > 1 {
                    return Err(format!("FAL family {} accepts at most one image and no video/audio references.", f.id));
                }
                let img = req.images.first().map(src_url);
                let ep = match &img {
                    Some(_) => f.i2v.to_string(),
                    None => f.t2v.map(str::to_string).ok_or_else(|| format!("FAL family {} has no text-to-video endpoint. Pass an image_url to use its image-to-video endpoint, or pick a different family.", f.id))?,
                };
                (ep, family_payload(f, req, img.as_deref()), Some(f.id))
            }
            None => (req.model.clone(), endpoint_payload(req, &req.model)?, None),
        };
        let (rid, payload) = fal_queue(m, &c, &endpoint, &body, req.timeout, cancel)?;
        let (mut url, info) = fal_video_url(&payload).ok_or("fal video generation response missing output URL")?;
        let mut meta = json!({"endpoint": endpoint, "requestId": rid, "upscaled": false});
        if let Some(f) = family_of(&req.model).filter(|f| f.audio_native) {
            // Native audio with no toggle (Hermes `audio_always_on`).
            meta["audio_always_on"] = json!(true);
            let _ = f;
        }
        if let Some(s) = payload["seed"].as_i64() {
            meta["seed"] = json!(s);
        }
        if req.upscale == Some(true) {
            // Best effort SeedVR2 ~2x pass (Hermes `_upscale_video`); native video on failure.
            let up = fal_queue(m, &c, FAL_UPSCALER, &json!({"video_url": url, "upscale_mode": "factor", "upscale_factor": 2}), req.timeout, cancel).ok().and_then(|(_, p)| fal_video_url(&p)).map(|x| x.0);
            if let Some(u) = up {
                url = u;
                meta["upscaled"] = json!(true);
                meta["upscale_factor"] = json!(2);
            } else {
                meta["upscale_error"] = json!("Video upscale pass failed — returning native-resolution video");
            }
        }
        let mut a = genrt::fetch_asset(m, &url, &[], info["content_type"].as_str().unwrap_or("video/mp4")).unwrap_or_else(|_| Asset::from_url(&url, "video/mp4"));
        a.url = Some(url);
        Ok(VideoResult { videos: vec![a], model: family.map(str::to_string).unwrap_or_else(|| req.model.clone()), meta })
    }
}

// ================================================================ xAI

pub struct Xai;

const XAI_ASPECTS: &[&str] = &["1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3"];
const XAI_V15: &str = "grok-imagine-video-1.5";
const XAI_DEFAULT: &str = "grok-imagine-video";
const XAI_FAIL: &[&str] = &["failed", "error", "expired", "cancelled"];

fn is_v15(model: &str) -> bool {
    model.starts_with("grok-imagine-video-1.5")
}

impl ProviderInfo for Xai {
    fn id(&self) -> &'static str {
        "xai"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["grok", "x-ai"]
    }
    fn label(&self) -> &'static str {
        "xAI"
    }
    fn env(&self) -> &'static [&'static str] {
        &["XAI_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.x.ai/v1"
    }
    fn default_model(&self) -> String {
        XAI_DEFAULT.into()
    }
    fn models(&self) -> Vec<String> {
        vec![XAI_DEFAULT.into(), XAI_V15.into()]
    }
}

impl VideoProvider for Xai {
    fn caps(&self, model: &str) -> VideoCaps {
        let g = ModeCaps::on().max_dur(15).aspects(XAI_ASPECTS).res(&["480P", "720P"]);
        if is_v15(model) {
            let i = ModeCaps::on().images(1).max_dur(15).aspects(XAI_ASPECTS).res(&["480P", "720P", "1080P"]);
            return VideoCaps { generate: g, i2v: i, v2v: ModeCaps::off(), modes: Some(vec!["i2v"]) };
        }
        VideoCaps { i2v: g.clone().images(7), generate: g, v2v: ModeCaps::on().videos(1).max_dur(10), modes: None }
    }

    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        let model = if req.model.is_empty() { XAI_DEFAULT.to_string() } else { req.model.clone() };
        let refs: Vec<bool> = (0..req.images.len()).map(|i| req.image_role(i).as_deref() == Some("reference_image")).collect();
        let has_refs = refs.iter().any(|r| *r);
        if is_v15(&model) {
            if !req.videos.is_empty() {
                return Err("xAI grok-imagine-video-1.5 does not support video inputs.".into());
            }
            if req.images.len() != 1 {
                return Err("xAI grok-imagine-video-1.5 requires exactly one first-frame image.".into());
            }
            if !matches!(req.image_role(0).as_deref(), None | Some("") | Some("first_frame")) {
                return Err("xAI grok-imagine-video-1.5 supports only an ordinary or first_frame image.".into());
            }
        }
        if has_refs && !refs.iter().all(|r| *r) {
            return Err("xAI reference-image video generation requires every image role to be reference_image.".into());
        }
        if !has_refs && req.images.len() > 1 {
            return Err("xAI image-to-video generation supports at most one first-frame image.".into());
        }
        if has_refs && req.images.len() > 7 {
            return Err("xAI reference-image video generation supports at most 7 reference images.".into());
        }
        if req.videos.len() > 1 {
            return Err("xAI video generation supports at most one input video.".into());
        }
        if !req.images.is_empty() && !req.videos.is_empty() {
            return Err("xAI video generation does not support image and video inputs together.".into());
        }
        let mut body = json!({"model": model, "prompt": req.prompt});
        let (endpoint, mode) = if let Some(v) = req.videos.first() {
            let url = remote(v).ok_or("xAI video editing currently requires a remote mp4 URL input.")?;
            body["video"] = json!({"url": url});
            match req.duration {
                Some(d) => {
                    body["duration"] = json!(d.clamp(2, 10));
                    ("/videos/extensions", "extend")
                }
                None => ("/videos/edits", "edit"),
            }
        } else {
            let img = if has_refs { None } else { req.images.first().map(src_url) };
            if has_refs {
                body["reference_images"] = json!(req.images.iter().map(|i| json!({"url": src_url(i)})).collect::<Vec<_>>());
            } else if let Some(u) = &img {
                body["image"] = json!({"url": u});
            }
            body["duration"] = json!(req.duration.map(|d| d.clamp(1, if has_refs { 10 } else { 15 })).unwrap_or(8));
            let aspect = req.aspect_ratio.clone().filter(|a| XAI_ASPECTS.contains(&a.as_str()));
            if aspect.is_some() || img.is_none() {
                body["aspect_ratio"] = json!(aspect.unwrap_or_else(|| "16:9".into()));
            }
            let res = match req.resolution.as_deref().map(|r| r.to_ascii_lowercase()).as_deref() {
                Some("480p") => "480p",
                Some("720p") => "720p",
                Some("1080p") if !has_refs && is_v15(&model) => "1080p",
                Some("1080p") => "720p",
                _ => "480p",
            };
            body["resolution"] = json!(res);
            ("/videos/generations", if has_refs { "referenceToVideo" } else { "generate" })
        };
        xai_submit(m, &self.creds(m), endpoint, &body, mode, req.timeout, cancel)
    }
}

fn xai_submit(m: &Media, c: &crate::Creds, endpoint: &str, body: &Value, mode: &str, timeout: Duration, cancel: &Cancel) -> Result<VideoResult, String> {
    require_key(c, "xAI").map_err(|_| "No xAI credentials found. Set XAI_API_KEY from https://console.x.ai/ (or [media.providers.xai] api_key).".to_string())?;
    let headers = h(c);
    let mut sh = headers.clone();
    sh.push(("x-idempotency-key".into(), crate::store::stem("seagent")));
    let sub = m.http.post_json(&c.url(endpoint), &sh, body).map_err(|e| format!("xAI video generation failed: {e}"))?;
    let id = sstr(&sub, "request_id").ok_or_else(|| err_of(&sub).unwrap_or_else(|| "xAI video generation response missing request_id".into()))?;
    let done: Value = crate::http::poll(cancel, crate::http::poll_every(5000), timeout, || {
        let v = m.http.get_json(&c.url(&format!("/videos/{id}")), &headers).map_err(|e| format!("xAI video status request failed: {e}"))?;
        let st = v["status"].as_str().unwrap_or("").to_ascii_lowercase();
        if st == "done" {
            return Ok(Some(v));
        }
        if XAI_FAIL.contains(&st.as_str()) {
            return Err(err_of(&v).unwrap_or_else(|| format!("xAI video generation {st}")));
        }
        Ok(None)
    })
    .map_err(|e| if e.starts_with("timed out") { format!("xAI video generation task {id} did not finish in time") } else { e })?;
    let stored = done["video"]["file_output"]["public_url"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    let temporary = done["video"]["url"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    let url = stored.clone().or(temporary.clone()).ok_or("xAI video generation response malformed")?;
    let mut a = download(m, &url, &[], &c.base)?;
    a.url = Some(url.clone());
    let mut meta = json!({"requestId": id, "status": "done", "videoUrl": url, "mode": mode});
    if let Some(d) = done["video"]["duration"].as_f64() {
        meta["duration"] = json!(d);
    }
    if !done["usage"].is_null() {
        meta["usage"] = done["usage"].clone();
    }
    if stored.is_some() && temporary.is_some() && stored != temporary {
        meta["temporary_url"] = json!(temporary);
    }
    Ok(VideoResult { videos: vec![a], model: done["model"].as_str().map(str::to_string).unwrap_or_else(|| body["model"].as_str().unwrap_or(XAI_DEFAULT).to_string()), meta })
}

/// Hermes `run_xai_video_edit` / `run_xai_video_extend` (extension clamped 1–10 s, default 6).
pub fn xai_mutate(m: &Media, prompt: &str, video_url: &str, extend: bool, duration: Option<i64>, cancel: &Cancel) -> Result<RunResult, String> {
    let c = Xai.creds(m);
    let model = m.cfg.str("video.model").map(|s| s.trim_start_matches("xai/").to_string()).filter(|s| !is_v15(s)).unwrap_or_else(|| XAI_DEFAULT.into());
    let mut body = json!({"model": model, "prompt": prompt, "video": {"url": video_url}});
    let d = duration.map(|d| d.clamp(1, 10) as u32).unwrap_or(if extend { 6 } else { 8 });
    if extend {
        body["duration"] = json!(d);
    }
    let r = xai_submit(m, &c, if extend { "/videos/extensions" } else { "/videos/edits" }, &body, if extend { "extend" } else { "edit" }, Duration::from_secs(240), cancel)?;
    Ok(RunResult { provider: "xai".into(), result: r, duration: Some(d), aspect_ratio: Some("16:9".into()), ..Default::default() })
}

// ================================================================ OpenRouter

pub struct OpenRouter;

impl ProviderInfo for OpenRouter {
    fn id(&self) -> &'static str {
        "openrouter"
    }
    fn label(&self) -> &'static str {
        "OpenRouter"
    }
    fn env(&self) -> &'static [&'static str] {
        &["OPENROUTER_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://openrouter.ai/api/v1"
    }
    fn default_model(&self) -> String {
        "google/veo-3.1-fast".into()
    }
}

impl VideoProvider for OpenRouter {
    fn caps(&self, _model: &str) -> VideoCaps {
        let g = ModeCaps::on().durs(&[4, 6, 8]).aspects(&["16:9", "9:16"]).res(&["720P", "1080P"]).size_ok().audio().opts(&[("callback_url", "string"), ("seed", "number")]);
        VideoCaps { i2v: g.clone().images(4), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("OpenRouter video generation does not support video reference inputs.".into());
        }
        let c = self.creds(m);
        require_key(&c, "OpenRouter")?;
        let headers = h(&c);
        let mut body = json!({"model": req.model, "prompt": req.prompt});
        if let Some(d) = req.duration {
            body["duration"] = json!(snap_duration(d, &[4, 6, 8]));
        }
        if let Some(r) = &req.resolution {
            body["resolution"] = json!(r.to_ascii_lowercase());
        }
        if let Some(a) = &req.aspect_ratio {
            body["aspect_ratio"] = json!(a);
        }
        if let Some(s) = &req.size {
            body["size"] = json!(s);
        }
        if let Some(a) = req.audio {
            body["generate_audio"] = json!(a);
        }
        let (mut frames, mut refs) = (vec![], vec![]);
        let mut seen: Vec<String> = vec![];
        for (i, img) in req.images.iter().enumerate() {
            let part = json!({"type": "image_url", "image_url": {"url": src_url(img)}});
            let role = req.image_role(i).unwrap_or_default();
            if role == "reference_image" {
                refs.push(part);
                continue;
            }
            let ft = if role == "first_frame" || role == "last_frame" { role } else if seen.contains(&"first_frame".to_string()) { "last_frame".into() } else { "first_frame".into() };
            if seen.contains(&ft) {
                refs.push(part);
            } else {
                let mut p = part;
                p["frame_type"] = json!(ft);
                frames.push(p);
                seen.push(ft);
            }
        }
        if !frames.is_empty() {
            body["frame_images"] = json!(frames);
        }
        if !refs.is_empty() {
            body["input_references"] = json!(refs);
        }
        if let Some(s) = req.seed() {
            body["seed"] = json!(s);
        }
        if let Some(cb) = req.opt_str(&["callback_url"]) {
            body["callback_url"] = json!(cb);
        }
        let sub = m.http.post_json(&c.url("/videos"), &headers, &body).map_err(|e| format!("OpenRouter video generation failed: {e}"))?;
        let id = sstr(&sub, "id").ok_or("OpenRouter video generation response missing job details")?;
        let state = |s: &str| -> Result<&'static str, String> {
            match s {
                "completed" => Ok("completed"),
                "failed" | "cancelled" | "expired" => Ok("failure"),
                "queued" | "pending" | "in_progress" | "processing" | "running" | "" => Ok("active"),
                _ => Err("OpenRouter video generation response malformed".into()),
            }
        };
        // Poll our own origin (Hermes), honouring a same-origin `polling_url` (OpenClaw).
        let poll_url = sstr(&sub, "polling_url").map(|u| if u.starts_with("http") { u } else { c.url(&u) }).filter(|u| crate::http::host_of(u) == crate::http::host_of(&c.base)).unwrap_or_else(|| c.url(&format!("/videos/{id}")));
        let mut done = sub.clone();
        match state(sub["status"].as_str().unwrap_or(""))? {
            "failure" => return Err(err_of(&sub).unwrap_or_else(|| format!("OpenRouter video generation {}", sub["status"].as_str().unwrap_or("failed")))),
            "completed" => {}
            _ => {
                done = crate::http::poll(cancel, crate::http::poll_every(5000), req.timeout, || {
                    let v = m.http.get_json(&poll_url, &headers).map_err(|e| format!("OpenRouter video status request failed: {e}"))?;
                    match state(v["status"].as_str().unwrap_or(""))? {
                        "completed" => Ok(Some(v)),
                        "failure" => Err(err_of(&v).unwrap_or_else(|| format!("OpenRouter video generation {}", v["status"].as_str().unwrap_or("failed")))),
                        _ => Ok(None),
                    }
                })
                .map_err(|e| if e.starts_with("timed out") { "OpenRouter video generation did not finish in time".into() } else { e })?;
            }
        }
        // The content endpoint is derived from the configured origin, never from `unsigned_urls`.
        let mut a = download(m, &c.url(&format!("/videos/{id}/content?index=0")), &headers, &c.base)?;
        a.url = done["unsigned_urls"][0].as_str().filter(|u| u.starts_with("https://") || u.starts_with("http://")).map(str::to_string);
        let mut meta = json!({"jobId": id, "status": done["status"]});
        if let Some(g) = sstr(&done, "generation_id") {
            meta["generationId"] = json!(g);
        }
        if done["usage"].is_object() {
            meta["usage"] = done["usage"].clone();
        }
        Ok(VideoResult { videos: vec![a], model: sstr(&done, "model").unwrap_or_else(|| req.model.clone()), meta })
    }
}

// ================================================================ DeepInfra

pub struct DeepInfra;

impl ProviderInfo for DeepInfra {
    fn id(&self) -> &'static str {
        "deepinfra"
    }
    fn label(&self) -> &'static str {
        "DeepInfra"
    }
    fn env(&self) -> &'static [&'static str] {
        &["DEEPINFRA_API_KEY", "DEEPINFRA_TOKEN"]
    }
    fn default_base(&self) -> &'static str {
        "https://api.deepinfra.com/v1/openai"
    }
    fn default_model(&self) -> String {
        "Pixverse/Pixverse-T2V".into()
    }
    fn models(&self) -> Vec<String> {
        ["Pixverse/Pixverse-T2V", "Pixverse/Pixverse-T2V-HD", "Wan-AI/Wan2.6-T2V", "google/veo-3.1-fast"].iter().map(|s| s.to_string()).collect()
    }
}

impl VideoProvider for DeepInfra {
    fn caps(&self, _model: &str) -> VideoCaps {
        let g = ModeCaps::on().max_dur(8).durs(&[5, 8]).aspects(&["16:9", "9:16", "1:1"]).opts(&[("seed", "number"), ("negative_prompt", "string"), ("negativePrompt", "string"), ("style", "string")]);
        // Hermes advertises image-to-video through the OpenAI-compatible `image_url` extra field.
        VideoCaps { i2v: g.clone().images(1), generate: g, v2v: ModeCaps::off(), modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if !req.videos.is_empty() {
            return Err("DeepInfra video generation does not support video reference inputs.".into());
        }
        let c = self.creds(m);
        if c.base.contains("/v1/inference") {
            return Err("DeepInfra video generation requires an OpenAI-compatible endpoint, but [media.providers.deepinfra] base_url targets the retired native /v1/inference surface.".into());
        }
        require_key(&c, "DeepInfra")?;
        let headers = h(&c);
        let model = req.model.trim_start_matches("deepinfra/").to_string();
        let mut body = json!({"model": model, "prompt": req.prompt});
        if let Some(a) = &req.aspect_ratio {
            body["aspect_ratio"] = json!(a);
        }
        if let Some(d) = req.duration {
            body["seconds"] = json!(if d as f64 <= 6.5 { 5 } else { 8 });
        }
        if let Some(s) = req.seed().filter(|s| (0..=4_294_967_295).contains(s)) {
            body["seed"] = json!(s);
        }
        if let Some(n) = req.negative() {
            body["negative_prompt"] = json!(n);
        }
        if let Some(s) = req.opt_str(&["style"]) {
            body["style"] = json!(s);
        }
        if let Some(i) = req.images.first() {
            body["image_url"] = json!(src_url(i));
        }
        let sub = m.http.post_json(&c.url("/videos"), &headers, &body).map_err(|e| format!("DeepInfra video generation failed: {e}"))?;
        let id = sstr(&sub, "id").ok_or("DeepInfra video generation response missing job id")?;
        let failed = |v: &Value| v["status"] == "failed" || v["status"] == "error";
        if failed(&sub) {
            return Err(err_of(&sub).unwrap_or_else(|| "DeepInfra video generation failed".into()));
        }
        let ok = |v: &Value| v["status"] == "succeeded" || v["status"] == "completed";
        let done = if ok(&sub) {
            sub
        } else {
            crate::http::poll(cancel, crate::http::poll_every(5000), req.timeout, || {
                let v = m.http.get_json(&c.url(&format!("/videos/{}", seagent_net::urlencode(&id))), &headers).map_err(|e| format!("DeepInfra video status request failed: {e}"))?;
                if failed(&v) {
                    return Err(err_of(&v).unwrap_or_else(|| "DeepInfra video generation failed".into()));
                }
                Ok(ok(&v).then_some(v))
            })
            .map_err(|e| if e.starts_with("timed out") { format!("DeepInfra video generation job {id} did not finish in time") } else { e })?
        };
        let url = done["data"].as_array().and_then(|a| a.iter().find_map(|e| e["url"].as_str().filter(|s| !s.is_empty()).map(str::to_string)));
        let a = match url {
            Some(u) if u.starts_with("data:") => {
                let (mime, bytes) = crate::store::decode_data_url(&u).ok_or("DeepInfra video response: malformed video response")?;
                if !(mime.starts_with("video/") || mime == "application/octet-stream") || !crate::store::sniff(&bytes).starts_with("video/") {
                    return Err("DeepInfra video response: malformed video response".into());
                }
                let mime = crate::store::sniff(&bytes).to_string();
                Asset::new(bytes, &mime)
            }
            Some(u) => {
                let full = if u.starts_with("http") { u } else { c.url(&u) };
                let mut a = download(m, &full, &headers, &c.base).unwrap_or_else(|_| Asset::from_url(&full, "video/mp4"));
                a.url = Some(full);
                a
            }
            // OpenAI-compatible `download_content` (Hermes OpenAICompatibleVideoGenProvider).
            None => download(m, &c.url(&format!("/videos/{id}/content")), &headers, &c.base)?,
        };
        Ok(VideoResult { videos: vec![a], model: sstr(&done, "model").unwrap_or(model), meta: json!({"jobId": id, "status": done["status"]}) })
    }
}

// ================================================================ Google (Veo)

pub struct Google;

/// `files/<id>` — a Google Files API handle (no further path/query).
fn files_handle(n: &str) -> bool {
    n.strip_prefix("files/").is_some_and(|rest| !rest.is_empty() && !rest.chars().any(|c| matches!(c, '/' | '?' | '#')))
}

impl ProviderInfo for Google {
    fn id(&self) -> &'static str {
        "google"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["gemini", "veo"]
    }
    fn label(&self) -> &'static str {
        "Google"
    }
    fn env(&self) -> &'static [&'static str] {
        &["GEMINI_API_KEY", "GOOGLE_API_KEY"]
    }
    fn default_base(&self) -> &'static str {
        "https://generativelanguage.googleapis.com/v1beta"
    }
    fn default_model(&self) -> String {
        "veo-3.1-fast-generate-preview".into()
    }
    fn models(&self) -> Vec<String> {
        ["veo-3.1-fast-generate-preview", "veo-3.1-generate-preview", "veo-3.1-lite-generate-preview"].iter().map(|s| s.to_string()).collect()
    }
}

impl VideoProvider for Google {
    fn caps(&self, _model: &str) -> VideoCaps {
        let g = ModeCaps::on().max_dur(8).durs(&[4, 6, 8]).aspects(&["16:9", "9:16"]).res(&["720P", "1080P"]).size_ok();
        VideoCaps { i2v: g.clone().images(1), v2v: g.clone().videos(1), generate: g, modes: None }
    }
    fn generate(&self, m: &Media, req: &VideoRequest, cancel: &Cancel) -> Result<VideoResult, String> {
        if req.images.len() > 1 {
            return Err("Google video generation supports at most one input image.".into());
        }
        if req.videos.len() > 1 {
            return Err("Google video generation supports at most one input video.".into());
        }
        if !req.images.is_empty() && !req.videos.is_empty() {
            return Err("Google video generation does not support image and video inputs together.".into());
        }
        let c = self.creds(m);
        let key = require_key(&c, "Google")?;
        let mut headers = c.headers.clone();
        headers.push(("x-goog-api-key".into(), key.clone()));
        let base = c.base.trim_end_matches('/').to_string();
        let model = req.model.trim_start_matches("google/").to_string();
        let path = if model.starts_with("models/") { model.clone() } else { format!("models/{model}") };
        let wh = req.size.as_deref().and_then(genrt::parse_size);
        let aspect = req.aspect_ratio.clone().filter(|a| a == "16:9" || a == "9:16").or_else(|| wh.map(|(w, h)| if w >= h { "16:9".into() } else { "9:16".into() }));
        let resolution = match req.resolution.as_deref() {
            Some("720P") => Some("720p"),
            Some("1080P") => Some("1080p"),
            _ => wh.and_then(|(w, h)| match w.max(h) {
                e if e >= 1920 => Some("1080p"),
                e if e >= 1280 => Some("720p"),
                _ => None,
            }),
        };
        let mut instance = json!({"prompt": req.prompt});
        if let Some(i) = req.images.first() {
            instance["image"] = json!({"bytesBase64Encoded": i.b64(), "mimeType": i.asset.mime});
        }
        if let Some(v) = req.videos.first() {
            instance["video"] = json!({"bytesBase64Encoded": v.b64(), "mimeType": v.asset.mime});
        }
        let mut params = json!({});
        if let Some(d) = req.duration {
            params["durationSeconds"] = json!(snap_duration(d, &[4, 6, 8]));
        }
        if let Some(a) = aspect {
            params["aspectRatio"] = json!(a);
        }
        if let Some(r) = resolution {
            params["resolution"] = json!(r);
        }
        let mut op = m.http.post_json(&format!("{base}/{path}:predictLongRunning"), &headers, &json!({"instances": [instance], "parameters": params})).map_err(|e| format!("Google video generation failed: {e}"))?;
        if op["done"] != true {
            let name = sstr(&op, "name").ok_or("Google video operation response missing name for polling")?;
            op = crate::http::poll(cancel, crate::http::poll_every(10000), req.timeout, || {
                let v = m.http.get_json(&format!("{base}/{name}"), &headers).map_err(|e| format!("Google video status request failed: {e}"))?;
                Ok((v["done"] == true).then_some(v))
            })
            .map_err(|e| if e.starts_with("timed out") { "Google video generation did not finish in time".into() } else { e })?;
        }
        if !op["error"].is_null() {
            return Err(op["error"].to_string());
        }
        let samples = op["response"]["generatedVideos"].as_array().filter(|a| !a.is_empty()).or_else(|| op["response"]["generateVideoResponse"]["generatedSamples"].as_array()).cloned().unwrap_or_default();
        if samples.is_empty() {
            return Err("Google video generation response missing generated videos".into());
        }
        let api_host = crate::http::host_of(&base);
        let mut videos = vec![];
        for s in samples {
            let v = &s["video"];
            if let Some(b) = v["videoBytes"].as_str() {
                videos.push(Asset::from_b64(b, v["mimeType"].as_str().unwrap_or("video/mp4"))?);
                continue;
            }
            let field = |k: &str| v[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            // An absolute https URL on Google's own (or the configured) origin is downloaded as-is;
            // a Files API handle (`files/<id>`) becomes the bounded REST media endpoint
            // (OpenClaw `resolveGoogleGeneratedVideoFileDownloadUrl`).
            let uri = match field("uri").filter(|u| u.starts_with("https://") || u.starts_with("http://")) {
                Some(u) => {
                    let allowed = crate::http::host_of(&u) == api_host || crate::http::host_of(&u) == "generativelanguage.googleapis.com";
                    if !allowed {
                        return Err("Google generated video missing bounded download URL".into());
                    }
                    u
                }
                None => {
                    let name = field("name").or_else(|| field("uri")).filter(|n| files_handle(n)).ok_or("Google generated video missing file handle")?;
                    format!("{base}/{name}:download?alt=media")
                }
            };
            let url = if uri.contains("key=") { uri } else { format!("{uri}{}key={}", if uri.contains('?') { '&' } else { '?' }, seagent_net::urlencode(&key)) };
            let (bytes, ct) = m.download(&url, &c.headers).map_err(|e| format!("Failed to download Google generated video: {e}"))?;
            videos.push(Asset::new(bytes, if ct.is_empty() { "video/mp4" } else { &ct }));
        }
        Ok(VideoResult { videos, model, meta: json!({"operationName": op["name"]}) })
    }
}
