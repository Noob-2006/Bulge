//! Shared generation runtime for image, video and music: provider identity,
//! `provider/model` references, candidate selection with fallbacks (OpenClaw
//! `media-generation/runtime-shared.ts`), geometry normalization, reference-input
//! loading, the background job registry with completion delivery
//! (OpenClaw `media-generate-background*.ts`), and small helpers providers share.

use crate::store::Asset;
use crate::Media;
use ark_core::{Cancel, ToolCtx};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Identity + configuration state every generation provider shares.
pub trait ProviderInfo: Send + Sync {
    fn id(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
    fn label(&self) -> &'static str;
    /// Env vars holding the API key (first wins). Empty = no key needed.
    fn env(&self) -> &'static [&'static str];
    /// Default API base URL (overridable by `[media.providers.<id>] base_url`).
    fn default_base(&self) -> &'static str {
        ""
    }
    fn default_model(&self) -> String;
    fn models(&self) -> Vec<String> {
        vec![self.default_model()]
    }
    /// Provider default operation timeout.
    fn default_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
    /// Whether this provider can be used (key present / local endpoint configured).
    fn configured(&self, m: &Media) -> bool {
        !self.env().is_empty() && m.cfg.configured(self.id(), self.env())
    }
    /// Connection details (`[media.providers.<id>]`, env vars, vault).
    fn creds(&self, m: &Media) -> crate::Creds {
        m.creds(self.id(), self.env(), self.default_base())
    }
}

/// True when `[media.providers.<id>]` exists (local providers with no key: comfy, llama-cpp).
pub fn has_section(m: &Media, id: &str) -> bool {
    m.cfg.get(&format!("providers.{id}")).map(|v| v.is_table()).unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRef {
    pub provider: String,
    pub model: String,
}

fn find_provider<P: ProviderInfo + ?Sized>(providers: &[Arc<P>], id: &str) -> Option<Arc<P>> {
    let id = id.trim().to_ascii_lowercase();
    providers.iter().find(|p| p.id() == id || p.aliases().iter().any(|a| *a == id)).cloned()
}

/// Resolve a raw model reference against the registry: `provider/model`, a bare
/// provider id (→ its default model), or a model id one provider lists.
pub fn resolve_ref<P: ProviderInfo + ?Sized>(providers: &[Arc<P>], raw: &str) -> Option<ModelRef> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((head, rest)) = raw.split_once('/') {
        if let Some(p) = find_provider(providers, head) {
            let model = if rest.trim().is_empty() { p.default_model() } else { rest.trim().to_string() };
            return Some(ModelRef { provider: p.id().into(), model });
        }
    }
    if let Some(p) = find_provider(providers, raw) {
        return Some(ModelRef { provider: p.id().into(), model: p.default_model() });
    }
    providers.iter().find(|p| p.models().iter().any(|m| m == raw)).map(|p| ModelRef { provider: p.id().into(), model: raw.to_string() })
}

/// Ordered `(provider, model)` candidates for one request.
///
/// Explicit `provider`/`model` arguments are authoritative (single candidate, no
/// fallback). Otherwise: `[media.<kind>] provider` + `model`, then `fallbacks`, then
/// (unless `auto_fallback = false`) every configured provider's default model in
/// registry order.
pub fn candidates<P: ProviderInfo + ?Sized>(m: &Media, kind: &str, providers: &[Arc<P>], provider_arg: Option<&str>, model_arg: Option<&str>) -> Result<Vec<(Arc<P>, String)>, String> {
    let provider_arg = provider_arg.map(str::trim).filter(|s| !s.is_empty() && *s != "auto");
    let model_arg = model_arg.map(str::trim).filter(|s| !s.is_empty());
    let lookup = |r: ModelRef| find_provider(providers, &r.provider).map(|p| (p, r.model));
    if let Some(pid) = provider_arg {
        let p = find_provider(providers, pid).ok_or_else(|| format!("Unknown {kind}-generation provider: {pid}. Known: {}", ids(providers)))?;
        let model = match model_arg {
            Some(mo) => match mo.split_once('/') {
                Some((h, rest)) if find_provider(providers, h).map(|x| x.id() == p.id()).unwrap_or(false) => rest.to_string(),
                _ => mo.to_string(),
            },
            None => configured_model_for(m, kind, p.id()).unwrap_or_else(|| p.default_model()),
        };
        return Ok(vec![(p, model)]);
    }
    if let Some(mo) = model_arg {
        let r = resolve_ref(providers, mo).ok_or_else(|| format!("Unknown model override: {mo}. Use a provider/model reference or a model listed by a provider."))?;
        return Ok(lookup(r).into_iter().collect());
    }
    let mut out: Vec<(Arc<P>, String)> = Vec::new();
    let add = |p: Arc<P>, model: String, out: &mut Vec<(Arc<P>, String)>| {
        if !out.iter().any(|(q, mm)| q.id() == p.id() && *mm == model) {
            out.push((p, model));
        }
    };
    let prov = m.cfg.str_or(&format!("{kind}.provider"), "auto");
    let model_cfg = m.cfg.str(&format!("{kind}.model"));
    if prov != "auto" {
        let p = find_provider(providers, &prov).ok_or_else(|| format!("[media.{kind}] provider = \"{prov}\" is not a known {kind}-generation provider. Known: {}", ids(providers)))?;
        let model = match &model_cfg {
            Some(mo) => match mo.split_once('/') {
                Some((h, rest)) if find_provider(providers, h).map(|x| x.id() == p.id()).unwrap_or(false) => rest.to_string(),
                _ => mo.clone(),
            },
            None => p.default_model(),
        };
        add(p, model, &mut out);
    } else if let Some(mo) = &model_cfg {
        if let Some((p, model)) = resolve_ref(providers, mo).and_then(lookup) {
            add(p, model, &mut out);
        }
    }
    // `fallbacks` (OpenClaw) or `fallback` (the image section's spelling).
    let mut fb = m.cfg.list(&format!("{kind}.fallbacks"));
    fb.extend(m.cfg.list(&format!("{kind}.fallback")));
    for f in fb {
        if let Some((p, model)) = resolve_ref(providers, &f).and_then(lookup) {
            add(p, model, &mut out);
        }
    }
    if m.cfg.bool_or(&format!("{kind}.auto_fallback"), true) {
        for p in providers {
            if p.configured(m) && !out.iter().any(|(q, _)| q.id() == p.id()) {
                add(p.clone(), p.default_model(), &mut out);
            }
        }
    }
    if out.is_empty() {
        let hints: Vec<String> = providers.iter().filter(|p| !p.env().is_empty()).take(4).map(|p| format!("{}: {}", p.id(), p.env().join(" / "))).collect();
        let sample = providers.first().map(|p| format!("{}/{}", p.id(), p.default_model())).unwrap_or_default();
        return Err(format!("No {kind}-generation provider configured. Set [media.{kind}] provider/model (e.g. model = \"{sample}\") and configure that provider's API key ({}).", hints.join("; ")));
    }
    Ok(out)
}

fn configured_model_for(m: &Media, kind: &str, pid: &str) -> Option<String> {
    let prov = m.cfg.str(&format!("{kind}.provider"))?;
    if prov != pid {
        return None;
    }
    let mo = m.cfg.str(&format!("{kind}.model"))?;
    Some(match mo.split_once('/') {
        Some((h, rest)) if h == pid => rest.to_string(),
        _ => mo,
    })
}

fn ids<P: ProviderInfo + ?Sized>(providers: &[Arc<P>]) -> String {
    providers.iter().map(|p| p.id()).collect::<Vec<_>>().join(", ")
}

/// One failed or skipped candidate.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub provider: String,
    pub model: String,
    pub error: String,
}

/// The error after every candidate failed (OpenClaw `throwCapabilityGenerationFailure`).
pub fn failure(label: &str, attempts: &[Attempt]) -> String {
    if attempts.len() == 1 {
        return attempts[0].error.clone();
    }
    let parts: Vec<String> = attempts.iter().map(|a| format!("{}/{}: {}", a.provider, a.model, a.error)).collect();
    format!("All {label} models failed ({}): {}", attempts.len(), if parts.is_empty() { "unknown".into() } else { parts.join(" | ") })
}

// ---------------------------------------------------------------- geometry

fn pair(raw: &str, sep: char) -> Option<(f64, f64)> {
    let (a, b) = raw.trim().split_once(sep).or_else(|| if sep == 'x' { raw.trim().split_once('X') } else { None })?;
    let w: f64 = a.trim().parse().ok()?;
    let h: f64 = b.trim().parse().ok()?;
    (w > 0.0 && h > 0.0 && w.is_finite() && h.is_finite()).then_some((w, h))
}

/// `"16:9"` → (16, 9).
pub fn parse_aspect(raw: &str) -> Option<(f64, f64)> {
    pair(raw, ':')
}

/// `"1024x768"` → (1024, 768).
pub fn parse_size(raw: &str) -> Option<(u32, u32)> {
    let (w, h) = pair(raw, 'x')?;
    (w.fract() == 0.0 && h.fract() == 0.0).then_some((w as u32, h as u32))
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a.max(1)
    } else {
        gcd(b, a % b)
    }
}

/// Reduced aspect ratio of a `WxH` size.
pub fn aspect_of_size(size: &str) -> Option<String> {
    let (w, h) = parse_size(size)?;
    let g = gcd(w, h);
    Some(format!("{}:{}", w / g, h / g))
}

fn closest<'a>(values: &'a [String], score: impl Fn(&str) -> Option<(f64, f64)>) -> Option<String> {
    let mut best: Option<(&'a String, f64, f64)> = None;
    for v in values {
        if let Some((p, s)) = score(v) {
            let better = match &best {
                None => true,
                Some((bv, bp, bs)) => {
                    if (p - bp).abs() > 1e-12 {
                        p < *bp
                    } else if (s - bs).abs() > 1e-12 {
                        s < *bs
                    } else {
                        v.as_str() < bv.as_str()
                    }
                }
            };
            if better {
                best = Some((v, p, s));
            }
        }
    }
    best.map(|b| b.0.clone())
}

pub fn closest_aspect(requested_aspect: Option<&str>, requested_size: Option<&str>, supported: &[String]) -> Option<String> {
    if supported.is_empty() {
        return requested_aspect.map(str::to_string).or_else(|| requested_size.and_then(aspect_of_size));
    }
    if let Some(a) = requested_aspect {
        if supported.iter().any(|s| s == a) {
            return Some(a.to_string());
        }
    }
    let req = requested_aspect.and_then(parse_aspect).or_else(|| requested_size.and_then(aspect_of_size).and_then(|a| parse_aspect(&a)))?;
    let rv = req.0 / req.1;
    closest(supported, |c| {
        let (w, h) = parse_aspect(c)?;
        Some(((w / h / rv).ln().abs(), (w * req.1 - req.0 * h).abs()))
    })
}

pub fn closest_size(requested_size: Option<&str>, requested_aspect: Option<&str>, supported: &[String]) -> Option<String> {
    if supported.is_empty() {
        return requested_size.map(str::to_string);
    }
    if let Some(s) = requested_size {
        if supported.iter().any(|x| x == s) {
            return Some(s.to_string());
        }
    }
    let req = requested_size.and_then(parse_size);
    let ra = requested_aspect.and_then(parse_aspect);
    if req.is_none() && ra.is_none() {
        return None;
    }
    let target = req.map(|(w, h)| w as f64 / h as f64).unwrap_or_else(|| ra.map(|(w, h)| w / h).unwrap_or(1.0));
    closest(supported, |c| {
        let (w, h) = parse_size(c)?;
        let area = w as f64 * h as f64;
        let sec = match req {
            Some((rw, rh)) => (area / (rw as f64 * rh as f64)).ln().abs(),
            None => area,
        };
        Some(((w as f64 / h as f64 / target).ln().abs(), sec))
    })
}

fn res_rank(r: &str) -> Option<(f64, char)> {
    let r = r.trim();
    let unit = r.chars().last()?.to_ascii_uppercase();
    if unit != 'K' && unit != 'P' {
        return None;
    }
    let v: f64 = r[..r.len() - 1].parse().ok()?;
    Some((if unit == 'K' { v * 1000.0 } else { v }, unit))
}

pub fn closest_resolution(requested: Option<&str>, supported: &[String]) -> Option<String> {
    if supported.is_empty() {
        return requested.map(str::to_string);
    }
    let r = requested?;
    if let Some(s) = supported.iter().find(|s| s.eq_ignore_ascii_case(r)) {
        return Some(s.clone());
    }
    let (rv, ru) = res_rank(r)?;
    closest(supported, |c| {
        let (cv, cu) = res_rank(c)?;
        (cu == ru).then_some(((cv - rv).abs(), if cv < rv { 1.0 } else { 0.0 }))
    })
}

/// Geometry capabilities of one provider/model/mode.
#[derive(Debug, Clone, Default)]
pub struct GeometryCaps {
    pub supports_size: bool,
    pub supports_aspect_ratio: bool,
    pub supports_resolution: bool,
    pub sizes: Vec<String>,
    pub aspect_ratios: Vec<String>,
    pub resolutions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Geometry {
    pub size: Option<String>,
    pub aspect_ratio: Option<String>,
    pub resolution: Option<String>,
    /// `(key, requested value)` dropped because the provider cannot honour it.
    pub ignored: Vec<(String, String)>,
    /// `(key, requested, applied)` adjusted to the closest supported value.
    pub normalized: Vec<(String, String, String)>,
}

/// Port of OpenClaw `resolveMediaGeometryOverrides`.
pub fn normalize_geometry(size: Option<&str>, aspect: Option<&str>, resolution: Option<&str>, caps: &GeometryCaps, report_unrecognized: bool, use_aspect_for_size: bool) -> Geometry {
    let mut g = Geometry { size: size.map(str::to_string), aspect_ratio: aspect.map(str::to_string), resolution: resolution.map(str::to_string), ..Default::default() };
    if let Some(s) = g.size.clone() {
        if !caps.sizes.is_empty() && caps.supports_size {
            let n = closest_size(Some(&s), if use_aspect_for_size { g.aspect_ratio.as_deref() } else { None }, &caps.sizes);
            match &n {
                Some(v) if *v != s => g.normalized.push(("size".into(), s.clone(), v.clone())),
                None if report_unrecognized => g.ignored.push(("size".into(), s.clone())),
                _ => {}
            }
            g.size = n;
        }
    }
    if let Some(s) = g.size.clone() {
        if !caps.supports_size {
            let t = if caps.supports_aspect_ratio { closest_aspect(g.aspect_ratio.as_deref(), Some(&s), &caps.aspect_ratios) } else { None };
            match t {
                Some(a) => {
                    g.normalized.push(("aspectRatio".into(), format!("size {s}"), a.clone()));
                    g.aspect_ratio = Some(a);
                }
                None => g.ignored.push(("size".into(), s.clone())),
            }
            g.size = None;
        }
    }
    if let Some(a) = g.aspect_ratio.clone() {
        if !caps.aspect_ratios.is_empty() && caps.supports_aspect_ratio {
            let n = closest_aspect(Some(&a), g.size.as_deref(), &caps.aspect_ratios);
            match &n {
                Some(v) if *v != a => g.normalized.push(("aspectRatio".into(), a.clone(), v.clone())),
                None if report_unrecognized => g.ignored.push(("aspectRatio".into(), a.clone())),
                _ => {}
            }
            g.aspect_ratio = n;
        } else if !caps.supports_aspect_ratio {
            let t = if caps.supports_size && g.size.is_none() { closest_size(size, Some(&a), &caps.sizes) } else { None };
            match t {
                Some(s) => {
                    g.normalized.push(("size".into(), format!("aspectRatio {a}"), s.clone()));
                    g.size = Some(s);
                }
                None => g.ignored.push(("aspectRatio".into(), a.clone())),
            }
            g.aspect_ratio = None;
        }
    }
    if let Some(r) = g.resolution.clone() {
        if !caps.resolutions.is_empty() && caps.supports_resolution {
            let n = closest_resolution(Some(&r), &caps.resolutions);
            match &n {
                Some(v) if *v != r => g.normalized.push(("resolution".into(), r.clone(), v.clone())),
                None if report_unrecognized => g.ignored.push(("resolution".into(), r.clone())),
                _ => {}
            }
            g.resolution = n;
        } else if !caps.supports_resolution {
            g.ignored.push(("resolution".into(), r.clone()));
            g.resolution = None;
        }
    }
    g
}

/// Notes for the tool result about ignored / normalized overrides.
pub fn geometry_notes(g: &Geometry) -> Vec<String> {
    let mut v = Vec::new();
    for (k, req, app) in &g.normalized {
        v.push(format!("{k} {req} → {app} (closest supported)"));
    }
    for (k, val) in &g.ignored {
        v.push(format!("ignored unsupported {k}={val}"));
    }
    v
}

/// Hermes aspect names → ratios (`landscape` 16:9, `portrait` 9:16, `square` 1:1).
pub fn hermes_aspect(a: &str) -> String {
    match a.trim().to_ascii_lowercase().as_str() {
        "landscape" => "16:9".into(),
        "portrait" => "9:16".into(),
        "square" => "1:1".into(),
        other => other.to_string(),
    }
}

/// Ratio → Hermes aspect name (closest of landscape/portrait/square).
pub fn aspect_name(a: Option<&str>) -> &'static str {
    match a.and_then(parse_aspect) {
        Some((w, h)) if w / h > 1.1 => "landscape",
        Some((w, h)) if w / h < 0.9 => "portrait",
        Some(_) => "square",
        None => "landscape",
    }
}

// ---------------------------------------------------------------- inputs

/// A reference input: loaded bytes plus the original URL when it was remote.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Source {
    pub asset: Asset,
    /// Semantic role hint (`first_frame`, `last_frame`, `reference_image`, `reference_video`, `reference_audio`).
    pub role: Option<String>,
}

impl Source {
    /// The public URL when the input was remote, else a `data:` URL.
    pub fn url_or_data(&self) -> String {
        match &self.asset.url {
            Some(u) if u.starts_with("http") => u.clone(),
            _ => crate::store::data_url(&self.asset.mime, &self.asset.bytes),
        }
    }
    pub fn data_url(&self) -> String {
        crate::store::data_url(&self.asset.mime, &self.asset.bytes)
    }
    pub fn b64(&self) -> String {
        crate::store::b64(&self.asset.bytes)
    }
    pub fn filename(&self, stem: &str) -> String {
        format!("{stem}.{}", crate::store::ext_for(&self.asset.mime))
    }
}

/// Load reference inputs (paths, http(s) URLs, `data:` URLs).
pub fn load_sources(m: &Media, ctx: &ToolCtx, srcs: &[String], roles: &[String], max_bytes: usize) -> Result<Vec<Source>, String> {
    let mut out = Vec::new();
    for (i, s) in srcs.iter().enumerate() {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let (bytes, mime) = crate::store::load(s, &ctx.workspace, m, max_bytes)?;
        let mut a = Asset::new(bytes, &mime);
        if s.starts_with("http://") || s.starts_with("https://") {
            a.url = Some(s.to_string());
        }
        let role = roles.get(i).map(|r| r.trim().to_string()).filter(|r| !r.is_empty());
        out.push(Source { asset: a, role });
    }
    Ok(out)
}

/// `[prefix]` + `[prefix]s` string/array args, in order, deduplicated when asked.
pub fn str_list(input: &Value, keys: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in keys {
        match input.get(*k) {
            Some(Value::String(s)) if !s.trim().is_empty() => out.push(s.trim().to_string()),
            Some(Value::Array(a)) => out.extend(a.iter().filter_map(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
            _ => {}
        }
    }
    out
}

/// Read a string arg under camelCase or snake_case.
pub fn arg<'a>(input: &'a Value, camel: &str) -> Option<&'a str> {
    let snake: String = camel.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['_', c.to_ascii_lowercase()] } else { vec![c] }).collect();
    input.get(camel).or_else(|| input.get(&snake)).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())
}

pub fn arg_val<'a>(input: &'a Value, camel: &str) -> Option<&'a Value> {
    let snake: String = camel.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['_', c.to_ascii_lowercase()] } else { vec![c] }).collect();
    input.get(camel).or_else(|| input.get(&snake)).filter(|v| !v.is_null())
}

pub fn arg_int(input: &Value, camel: &str) -> Result<Option<i64>, String> {
    match arg_val(input, camel) {
        None => Ok(None),
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)).map(Some).ok_or_else(|| format!("{camel} must be an integer")),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| format!("{camel} must be an integer")),
        Some(_) => Err(format!("{camel} must be an integer")),
    }
}

pub fn arg_bool(input: &Value, camel: &str) -> Option<bool> {
    match arg_val(input, camel) {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" | "on" => Some(true),
            "false" | "no" | "0" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------- provider helpers

/// Download a provider-hosted output into an `Asset` (keeps the URL).
pub fn fetch_asset(m: &Media, url: &str, headers: &[(String, String)], fallback_mime: &str) -> Result<Asset, String> {
    let (bytes, ct) = m.download(url, headers)?;
    if bytes.is_empty() {
        return Err(format!("empty download from {}", crate::http::host_of(url)));
    }
    let mime = if ct.is_empty() || ct == "application/octet-stream" || ct == "binary/octet-stream" { fallback_mime.to_string() } else { ct };
    let mut a = Asset::new(bytes, &mime);
    let sniffed = crate::store::sniff(&a.bytes);
    if sniffed != "application/octet-stream" {
        a.mime = sniffed.to_string();
    }
    if !url.starts_with("data:") {
        a.url = Some(url.to_string());
    }
    Ok(a)
}

/// Poll a JSON status endpoint until `done` returns `Some`. `done` returns
/// `Err` for terminal failures.
pub fn poll_json<T>(m: &Media, cancel: &Cancel, url: &str, headers: &[(String, String)], every_ms: u64, timeout: Duration, mut done: impl FnMut(&Value) -> Result<Option<T>, String>) -> Result<T, String> {
    crate::http::poll(cancel, crate::http::poll_every(every_ms), timeout, || {
        let v = m.http.get_json(url, headers)?;
        done(&v)
    })
}

/// First string at any of the JSON pointers.
pub fn first_str(v: &Value, pointers: &[&str]) -> Option<String> {
    pointers.iter().find_map(|p| v.pointer(p).and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
}

// ---------------------------------------------------------------- background jobs

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Job {
    pub id: String,
    /// "image" | "video" | "music".
    pub kind: String,
    pub session: String,
    /// "running" | "succeeded" | "failed".
    pub status: String,
    pub prompt: String,
    pub request_key: String,
    pub progress: String,
    pub started_ms: u128,
    pub finished_ms: Option<u128>,
    /// Final tool-style text (with `MEDIA:` lines) or the error.
    pub result: Option<String>,
}

/// Delivered when a background job finishes: the lead hooks this to inject a
/// later turn / channel message into `session` (OpenClaw completion wake).
#[derive(Debug, Clone, PartialEq)]
pub struct Completion {
    pub session: String,
    pub kind: String,
    pub job_id: String,
    pub ok: bool,
    /// Text with `MEDIA:<path>` lines for successful jobs, the error otherwise.
    pub text: String,
}

pub type CompletionSink = Arc<dyn Fn(Completion) + Send + Sync>;

static SINK: OnceLock<Mutex<Option<CompletionSink>>> = OnceLock::new();
static JOBS: OnceLock<Mutex<HashMap<String, Job>>> = OnceLock::new();

fn jobs() -> &'static Mutex<HashMap<String, Job>> {
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install the completion sink (called once by the binary).
pub fn set_completion_sink(f: CompletionSink) {
    *SINK.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(f);
}

fn now_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Stable-ish key for duplicate detection.
pub fn request_key(tool: &str, v: &Value) -> String {
    format!("{tool}:{}", serde_json::to_string(v).unwrap_or_default())
}

/// Running job of `kind` in `session` with the same request key (duplicate guard).
pub fn find_duplicate(kind: &str, session: &str, key: &str) -> Option<Job> {
    jobs().lock().unwrap().values().find(|j| j.kind == kind && j.session == session && j.request_key == key && j.status == "running").cloned()
}

/// Jobs of `kind` for `session`, newest first.
pub fn list_jobs(kind: &str, session: &str) -> Vec<Job> {
    let mut v: Vec<Job> = jobs().lock().unwrap().values().filter(|j| j.kind == kind && (session.is_empty() || j.session == session)).cloned().collect();
    v.sort_by_key(|j| std::cmp::Reverse(j.started_ms));
    v
}

pub fn get_job(id: &str) -> Option<Job> {
    jobs().lock().unwrap().get(id).cloned()
}

/// Progress reporter handed to a running job.
#[derive(Clone)]
pub struct Progress {
    id: Option<String>,
    host: Option<Arc<dyn ark_core::ToolHost>>,
}

impl Progress {
    pub fn none() -> Self {
        Progress { id: None, host: None }
    }
    pub fn for_ctx(ctx: &ToolCtx) -> Self {
        Progress { id: None, host: Some(ctx.host.clone()) }
    }
    pub fn set(&self, s: &str) {
        if let Some(id) = &self.id {
            if let Some(j) = jobs().lock().unwrap().get_mut(id) {
                j.progress = s.to_string();
            }
        }
        if let Some(h) = &self.host {
            h.progress(s);
        }
    }
}

/// Run `work` on a background thread, registered as a job; returns the job id.
/// When it ends the completion sink (if any) receives the result.
pub fn spawn_job(kind: &str, ctx: &ToolCtx, prompt: &str, key: &str, work: impl FnOnce(&Cancel, &Progress) -> Result<String, String> + Send + 'static) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let id = format!("{kind}-{:x}-{}", now_ms() % 0xffff_ffff, N.fetch_add(1, Ordering::SeqCst));
    let job = Job { id: id.clone(), kind: kind.into(), session: ctx.session_id.clone(), status: "running".into(), prompt: prompt.into(), request_key: key.into(), progress: "queued".into(), started_ms: now_ms(), finished_ms: None, result: None };
    jobs().lock().unwrap().insert(id.clone(), job);
    let cancel = Cancel::new();
    let id2 = id.clone();
    let kind2 = kind.to_string();
    let session = ctx.session_id.clone();
    std::thread::spawn(move || {
        let prog = Progress { id: Some(id2.clone()), host: None };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&cancel, &prog))).unwrap_or_else(|_| Err("generation task panicked".into()));
        let (ok, text) = match r {
            Ok(t) => (true, t),
            Err(e) => (false, e),
        };
        if let Some(j) = jobs().lock().unwrap().get_mut(&id2) {
            j.status = if ok { "succeeded" } else { "failed" }.into();
            j.finished_ms = Some(now_ms());
            j.progress = if ok { "done" } else { "failed" }.into();
            j.result = Some(text.clone());
        }
        let sink = SINK.get().and_then(|s| s.lock().unwrap().clone());
        if let Some(f) = sink {
            f(Completion { session, kind: kind2, job_id: id2, ok, text });
        }
    });
    id
}

/// Status text for `action=status` (one job or the session's jobs).
pub fn status_text(kind: &str, session: &str, job_id: Option<&str>) -> (String, Value) {
    let list = match job_id {
        Some(id) => get_job(id).into_iter().collect::<Vec<_>>(),
        None => list_jobs(kind, session),
    };
    if list.is_empty() {
        return (format!("No active {kind} generation task is currently running for this session."), json!({"tasks": []}));
    }
    let mut lines = Vec::new();
    for j in &list {
        let mut l = format!("{} [{}] {}: {}", j.id, j.status, j.progress, crate::http::excerpt(&j.prompt, 80));
        if let Some(r) = &j.result {
            l.push('\n');
            l.push_str(r);
        }
        lines.push(l);
    }
    (lines.join("\n\n"), json!({"tasks": list}))
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Make polling instant for tests.
    pub fn fast_poll() {
        std::env::set_var("ARK_MEDIA_POLL_MS", "1");
    }
    pub const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDRfake";
    pub const MP4: &[u8] = b"\0\0\0\x18ftypmp42\0\0\0\0mp42isomfake";
    pub const MP3: &[u8] = b"ID3\x04\0\0\0\0\0\0fake-mp3";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct P(&'static str, &'static str, &'static [&'static str]);
    impl ProviderInfo for P {
        fn id(&self) -> &'static str {
            self.0
        }
        fn label(&self) -> &'static str {
            self.0
        }
        fn env(&self) -> &'static [&'static str] {
            self.2
        }
        fn default_model(&self) -> String {
            self.1.into()
        }
        fn models(&self) -> Vec<String> {
            vec![self.1.into(), format!("{}-alt", self.1)]
        }
    }

    fn reg() -> Vec<Arc<P>> {
        vec![Arc::new(P("fal", "fal-ai/flux", &["ARK_T_FAL_UNSET"])), Arc::new(P("google", "imagen", &["ARK_T_G_UNSET"])), Arc::new(P("openai", "gpt-image-2", &["ARK_T_OA_UNSET"]))]
    }

    #[test]
    fn refs_and_candidates() {
        let r = reg();
        assert_eq!(resolve_ref(&r, "fal/fal-ai/flux-2"), Some(ModelRef { provider: "fal".into(), model: "fal-ai/flux-2".into() }));
        assert_eq!(resolve_ref(&r, "imagen-alt").unwrap().provider, "google");
        assert_eq!(resolve_ref(&r, "openai").unwrap().model, "gpt-image-2");
        let m = crate::Media::new(crate::MediaConfig::from_toml("[image]\nprovider=\"google\"\nfallbacks=[\"fal/x\"]\n[providers.openai]\napi_key=\"k\"\n"));
        let c = candidates(&m, "image", &r, None, None).unwrap();
        let v: Vec<_> = c.iter().map(|(p, mo)| format!("{}/{mo}", p.id())).collect();
        assert_eq!(v, vec!["google/imagen", "fal/x", "openai/gpt-image-2"]);
        let c = candidates(&m, "image", &r, Some("fal"), None).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].1, "fal-ai/flux");
        assert!(candidates(&m, "image", &r, None, Some("nope-model")).unwrap_err().contains("Unknown model override"));
        let empty = crate::Media::new(crate::MediaConfig::default());
        assert!(candidates(&empty, "image", &r, None, None).unwrap_err().contains("No image-generation provider configured"));
    }

    #[test]
    fn geometry() {
        let sup = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(closest_aspect(Some("21:9"), None, &sup(&["1:1", "16:9", "9:16"])).as_deref(), Some("16:9"));
        assert_eq!(closest_size(Some("1000x1000"), None, &sup(&["1024x1024", "1536x1024"])).as_deref(), Some("1024x1024"));
        assert_eq!(closest_resolution(Some("1440P"), &sup(&["720P", "1080P"])).as_deref(), Some("1080P"));
        assert_eq!(aspect_of_size("1920x1080").as_deref(), Some("16:9"));
        let caps = GeometryCaps { supports_size: true, sizes: sup(&["1024x1024", "1536x1024", "1024x1536"]), ..Default::default() };
        let g = normalize_geometry(None, Some("16:9"), Some("2K"), &caps, false, false);
        assert_eq!(g.size.as_deref(), Some("1536x1024"));
        assert!(g.aspect_ratio.is_none() && g.resolution.is_none());
        assert_eq!(g.ignored, vec![("resolution".to_string(), "2K".to_string())]);
        assert_eq!(hermes_aspect("portrait"), "9:16");
        assert_eq!(aspect_name(Some("9:16")), "portrait");
    }

    #[test]
    fn jobs_complete_and_deliver() {
        let got = Arc::new(Mutex::new(Vec::<Completion>::new()));
        let g2 = got.clone();
        set_completion_sink(Arc::new(move |c| g2.lock().unwrap().push(c)));
        let ctx = crate::testutil::ctx("jobs");
        let id = spawn_job("testkind", &ctx, "a cat", "k1", |_c, p| {
            p.set("working");
            std::thread::sleep(Duration::from_millis(50));
            Ok("MEDIA:/tmp/x.png".into())
        });
        assert!(find_duplicate("testkind", "s-test", "k1").is_some());
        for _ in 0..200 {
            if get_job(&id).unwrap().status != "running" {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let j = get_job(&id).unwrap();
        assert_eq!(j.status, "succeeded");
        std::thread::sleep(Duration::from_millis(20));
        assert!(got.lock().unwrap().iter().any(|c| c.job_id == id && c.ok && c.text.contains("MEDIA:")));
        let (t, _) = status_text("testkind", "s-test", None);
        assert!(t.contains(&id) && t.contains("succeeded"));
    }
}
