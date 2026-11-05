//! Vision: load images for the model, image prep (normalize/validate/crop/resize/sanitize),
//! send-path image eviction, and the tools `vision_analyze` (Hermes `tools/vision_tools.py`),
//! `view_image` (OpenClaw `src/agents/tools/image-tool.ts`) and `local_image` (OpenClaw
//! `extensions/llama-cpp` media tool: a loopback llama-server describes/OCRs an image).
//!
//! Two routes, chosen per call: **native** — the main model sees images, so the prepared
//! picture is attached to the tool result (an `ark_core::tool::image_marker` line the kernel
//! turns into an image block) — or **describe** — a vision-capable model (`[media.vision]
//! model`, else the agent's own via [`crate::llm`], else the tool host's `analyze_image`)
//! answers the question and the tool returns text.
//!
//! ```toml
//! [media.vision]
//! mode = "auto"                 # auto (native when the main model has vision) | native | describe
//! model = ""                    # provider/model for the describe route ("" = agent default)
//! embed_target_bytes = 262144   # vision_analyze native embed budget (64 KiB..4 MiB)
//! max_calls_per_image = 0       # native embeds of one image per session (0 = unlimited)
//! max_dimension_px = 1200       # view_image sanitization (OpenClaw imageMaxDimensionPx)
//! max_bytes = 5242880
//! allow_private_urls = false    # let http(s) image URLs reach private/loopback addresses
//! [media.local_image]           # local_image tool (only registered when configured)
//! base_url = "http://127.0.0.1:8080/v1"
//! ocr_model = "glm-ocr-q8_0"    ocr_prompt = "Text Recognition:"
//! vision_model = "smolvlm2-2.2b-instruct-q4_k_m"
//! ```

pub mod evict;
mod local;
pub mod prep;

use crate::Media;
use ark_core::{Block, Cancel, Effect, Message, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

/// Hermes `_VISION_MAX_DOWNLOAD_BYTES`.
pub const MAX_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;
/// Hermes `_MAX_BASE64_BYTES`: no major provider accepts a larger image payload.
pub const MAX_BASE64_BYTES: usize = 20 * 1024 * 1024;
/// Hermes `_RESIZE_TARGET_BYTES`: retry target after a provider size rejection.
pub const RESIZE_TARGET_BYTES: usize = 5 * 1024 * 1024;
/// Hermes `_EMBED_MAX_DIMENSION` (Anthropic downsamples to a 1568 px long edge anyway).
pub const EMBED_MAX_DIMENSION: u32 = 1568;
const DEFAULT_EMBED_TARGET: usize = 256 * 1024;

/// Downscale/re-encode an image so it fits `max_dim` px on its longest side and
/// `max_bytes`; returns `(bytes, mime)` (input unchanged when it already fits). Unsupported
/// formats are normalized to PNG first. (OpenClaw image sanitization.)
pub fn prepare(bytes: &[u8], mime: &str, max_dim: u32, max_bytes: usize) -> Result<(Vec<u8>, String), String> {
    let (b, m) = prep::normalize(bytes, mime)?;
    prep::sanitize(&b, &m, max_dim, max_bytes, false)
}

/// Sanitize every image block in place (OpenClaw `sanitizeContentBlocksImages`): oversized
/// images are shrunk; undecodable or unshrinkable ones become a text note at the same
/// position. Returns how many blocks changed.
pub fn sanitize_blocks(blocks: &mut [Block], label: &str, max_dim: u32, max_bytes: usize) -> usize {
    let mut changed = 0;
    for b in blocks.iter_mut() {
        let Block::Image { media_type, data } = b else { continue };
        if data.len() / 4 * 3 > prep::MAX_INPUT_BYTES {
            *b = Block::text(format!("[{label}] omitted image payload: image exceeds input size limit (10.00MB)"));
            changed += 1;
            continue;
        }
        let raw = match crate::store::b64_decode(data.trim()) {
            Ok(r) if !r.is_empty() => r,
            Ok(_) => {
                *b = Block::text(format!("[{label}] omitted empty image payload"));
                changed += 1;
                continue;
            }
            Err(_) => {
                *b = Block::text(format!("[{label}] omitted image payload: invalid base64"));
                changed += 1;
                continue;
            }
        };
        match prep::normalize(&raw, media_type).and_then(|(n, m)| prep::sanitize(&n, &m, max_dim, max_bytes, true)) {
            Ok((out, m)) => {
                if out != raw || m != *media_type {
                    *media_type = m;
                    *data = crate::store::b64(&out);
                    changed += 1;
                }
            }
            Err(e) => {
                *b = Block::text(format!("[{label}] omitted image payload: {e}"));
                changed += 1;
            }
        }
    }
    changed
}

// ───── kernel / send-path hooks ─────
//
// `ark_core::tool` has no `set_image_post`-style slot (only the `IMAGE_TOOLS` allowlist and
// `take_images`), so these are plain functions the kernel/binary calls at the two send-path
// sites; nothing is registered inside ark-core. See the report for the wiring.

/// Defaults for the tool-image hooks, from `[media.vision]` (`max_dimension_px`, `max_bytes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookSettings {
    pub max_dim: u32,
    pub max_bytes: usize,
}

impl Default for HookSettings {
    fn default() -> Self {
        HookSettings { max_dim: prep::DEFAULT_MAX_DIMENSION_PX, max_bytes: prep::DEFAULT_MAX_BYTES }
    }
}

fn hook_settings() -> &'static Mutex<HookSettings> {
    static H: OnceLock<Mutex<HookSettings>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HookSettings::default()))
}

/// This crate's per-session eviction latches (see [`ark_core::imageevict::Latches`]). ark-media
/// keeps its own table: the kernel's send path latches the same tool ids for its own pass.
fn latches() -> &'static ark_core::imageevict::Latches {
    static L: OnceLock<ark_core::imageevict::Latches> = OnceLock::new();
    L.get_or_init(|| ark_core::imageevict::Latches::new(512))
}

/// Install the send-path image hooks from `[media]` and return the settings the caller must use.
/// Idempotent; the last call wins (the binary calls it once at startup, after `set_llm`).
pub fn install_tool_hooks(m: &Arc<Media>) -> HookSettings {
    let s = HookSettings {
        max_dim: cfg_usize(m, "vision.max_dimension_px", prep::DEFAULT_MAX_DIMENSION_PX as usize) as u32,
        max_bytes: cfg_usize(m, "vision.max_bytes", prep::DEFAULT_MAX_BYTES),
    };
    *hook_settings().lock().unwrap() = s;
    s
}

/// Sanitize the image blocks a tool result just attached (OpenClaw `tool-images.ts`) with the
/// installed [`HookSettings`]; undecodable/oversized images become a text note in place.
/// Call right after `ark_core::tool::take_images(&out.content)`.
pub fn post_tool_images(blocks: &mut [Block]) -> usize {
    let s = *hook_settings().lock().unwrap();
    sanitize_blocks(blocks, "image:tool", s.max_dim, s.max_bytes)
}

/// [`evict::evict`] with the per-session latch kept inside ark-media: call on the per-request
/// copy of the conversation just before the provider request is built. `&mut Vec<Message>`
/// coerces to the slice.
pub fn evict_for_session(session: &str, msgs: &mut [Message]) -> usize {
    latches().with(session, |set| evict::evict(msgs, Some(set)))
}

/// Drop the eviction latch for `session` (call after compaction: retired tool ids are gone).
pub fn reset_session(session: &str) {
    latches().forget(session);
}

/// Sessions that currently hold an eviction latch (diagnostics/tests).
pub fn latched_sessions() -> usize {
    latches().len()
}

fn cfg_usize(m: &Media, key: &str, default: usize) -> usize {
    let v = m.cfg.int_or(key, default as i64);
    if v > 0 {
        v as usize
    } else {
        default
    }
}

/// `vision.embed_target_bytes` clamped to 64 KiB..4 MiB (Hermes `resolve_embed_target_bytes`).
pub fn embed_target_bytes(m: &Media) -> usize {
    match m.cfg.get("vision.embed_target_bytes").and_then(|v| v.as_integer()) {
        Some(n) => (n.max(0) as usize).clamp(64 * 1024, 4 * 1024 * 1024),
        None => DEFAULT_EMBED_TARGET,
    }
}

/// Whether this call should attach pixels for the main model.
fn native(m: &Media) -> bool {
    match m.cfg.str_or("vision.mode", "auto").as_str() {
        "native" => true,
        "describe" | "aux" => false,
        _ => crate::llm().map(|l| l.vision(None)).unwrap_or(true),
    }
}

// ───── loading ─────

/// Private / loopback / link-local / CGNAT / reserved classes: the shared SSRF classifier
/// (Hermes `tools/url_safety.py`, `ark_security::url_safety::is_blocked_ip`).
fn private_ip(ip: std::net::IpAddr) -> bool {
    ark_security::url_safety::is_blocked_ip(ip)
}

/// Cloud metadata hostnames, blocked before the `allow_private_urls` toggle is consulted
/// (Hermes `url_safety._BLOCKED_HOSTNAMES`); the one list lives in ark-security.
pub const BLOCKED_HOSTNAMES: &[&str] = ark_security::url_safety::BLOCKED_HOSTNAMES;

/// Cloud metadata / credential address floor, blocked regardless of the toggle (Hermes
/// `_METADATA_V4` + `fd00:ec2::254`). The classification is the shared one
/// ([`ark_security::url_safety::is_always_blocked_ip`]); media additionally refuses the whole
/// IPv6 link-local range here, as this floor always has.
fn always_blocked(ip: std::net::IpAddr) -> bool {
    ark_security::url_safety::is_always_blocked_ip(ip) || matches!(ip, std::net::IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80)
}

/// SSRF guard for model-supplied URLs (Hermes `tools/url_safety.is_safe_url`): the host must not
/// resolve to a private, loopback, link-local or metadata address. Metadata hostnames/addresses
/// stay blocked even with `vision.allow_private_urls = true` ("skips private-IP blocking, but
/// cloud metadata endpoints remain blocked regardless"), and DNS failures fail closed.
pub fn check_url(m: &Media, url: &str) -> Result<(), String> {
    UrlPolicy { allow_private: m.cfg.bool_or("vision.allow_private_urls", false), trusted_hosts: Vec::new() }.check(url)
}

/// The url-safety decision for one fetch: [`check_url`] plus the addresses the operator
/// explicitly trusts. Used for every provider-supplied result URL (`http::Http::download`
/// → `store::load` → generated image/video/audio caching), which is why a provider may live
/// on localhost or the LAN without opening that space to arbitrary URLs.
#[derive(Debug, Clone, Default)]
pub struct UrlPolicy {
    /// `[media] allow_private_urls` / `[media.vision] allow_private_urls`.
    pub allow_private: bool,
    /// `host[:port]` of operator-configured provider origins ([`crate::MediaConfig::provider_hosts`]).
    pub trusted_hosts: Vec<String>,
}

impl UrlPolicy {
    pub fn for_config(cfg: &crate::MediaConfig) -> UrlPolicy {
        UrlPolicy { allow_private: cfg.bool_or("allow_private_urls", false) || cfg.bool_or("vision.allow_private_urls", false), trusted_hosts: cfg.provider_hosts() }
    }

    /// Refuse `url` when it would reach cloud metadata, or private space this policy does
    /// not trust.
    pub fn check(&self, url: &str) -> Result<(), String> {
        let host = crate::http::host_of(url);
        let (name, _) = split_port(&host);
        // Refuse a known metadata name before touching DNS: it may not resolve at all.
        if name.is_empty() || BLOCKED_HOSTNAMES.contains(&name.as_str()) {
            return Err(format!("Blocked request to internal hostname: {url}"));
        }
        let addrs: Vec<_> = (name.as_str(), 0).to_socket_addrs().map_err(|e| format!("cannot resolve {name}: {e}"))?.collect();
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        self.check_resolved(&host, &ips).map_err(|m| format!("{m}: {url}"))
    }

    /// The address-level half of [`UrlPolicy::check`], shared with the connect-time resolver
    /// (`http::PinnedResolver`): the metadata floor ignores the toggle and the trusted list,
    /// private space is allowed only for operator-trusted hosts. `host` may carry a port — a
    /// trusted entry with a port trusts only that port, so a provider on `127.0.0.1:8080`
    /// does not smuggle in `127.0.0.1:22`.
    pub fn check_resolved(&self, host: &str, ips: &[std::net::IpAddr]) -> Result<(), String> {
        let (name, port) = split_port(host);
        if name.is_empty() || BLOCKED_HOSTNAMES.contains(&name.as_str()) {
            return Err("Blocked request to internal hostname".into());
        }
        if ips.iter().any(|ip| always_blocked(*ip)) {
            return Err("Blocked request to cloud metadata address".into());
        }
        if self.allow_private || self.trusted_hosts.iter().any(|e| {
            let (en, ep) = split_port(e);
            en == name && (ep.is_none() || ep == port)
        }) {
            return Ok(());
        }
        if ips.is_empty() || ips.iter().any(|ip| private_ip(*ip)) {
            return Err("Blocked request to private/internal address".into());
        }
        Ok(())
    }
}

/// `example.com:8443` → (`example.com`, Some(8443)); `[::1]:80` → (`::1`, Some(80));
/// `::1` → (`::1`, None). One parser for trusted-host matching and the resolver.
fn split_port(host: &str) -> (String, Option<u16>) {
    let h = host.trim();
    if let Some(rest) = h.strip_prefix('[') {
        if let Some((bare, port)) = rest.split_once(']') {
            return (bare.to_ascii_lowercase(), port.strip_prefix(':').and_then(|p| p.parse().ok()));
        }
    }
    match h.rsplit_once(':') {
        Some((name, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (name.to_ascii_lowercase(), p.parse().ok()),
        _ => (h.to_ascii_lowercase(), None),
    }
}

/// The bare host of a `host[:port]` / `[v6][:port]` string, lower-cased (tests only: the
/// production paths compare through [`split_port`]).
#[cfg(test)]
fn host_name(host: &str) -> String {
    split_port(host).0
}

/// A loaded image: bytes, sniffed MIME, and a stable identity for repeat accounting.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub key: String,
}

fn image_key(src: &str, ctx: &ToolCtx) -> String {
    if src.starts_with("data:") {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(src, &mut h);
        return format!("data:{:x}", std::hash::Hasher::finish(&h));
    }
    let s = src.split('#').next().unwrap_or(src).trim_start_matches("file://");
    if s.contains("://") {
        return format!("url:{s}");
    }
    let p = ctx.resolve(s);
    format!("file:{}", std::fs::canonicalize(&p).unwrap_or(p).display())
}

/// Resolve a path, `file://`, `data:` or http(s) source into image bytes (Hermes
/// `resolve_image_source`, OpenClaw `loadWebMedia`), capped at `max` bytes.
pub fn load(m: &Media, ctx: &ToolCtx, src: &str, max: usize) -> Result<Loaded, String> {
    let src = src.trim();
    if src.is_empty() {
        return Err("image_url is required".into());
    }
    let lower = src.to_ascii_lowercase();
    if let Some(scheme) = lower.split_once(':').map(|(s, _)| s).filter(|s| s.len() > 1 && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))) {
        if !["http", "https", "data", "file"].contains(&scheme) {
            return Err(format!("Unsupported image reference: {src}. Use a file path, a file:// URL, a data: URL, or an http(s) URL."));
        }
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        check_url(m, src)?;
    }
    let (bytes, mime) = crate::store::load(src, &ctx.workspace, m, max).map_err(|e| if e.contains("exceeds") { format!("Image too large ({e}, max {max} bytes)") } else { e })?;
    let sniffed = crate::store::sniff(&bytes);
    let mime = if sniffed.starts_with("image/") { sniffed.to_string() } else { mime };
    if !mime.starts_with("image/") {
        return Err(format!("Unsupported media type: {} is not an image", if mime.is_empty() { "unknown" } else { &mime }));
    }
    Ok(Loaded { key: image_key(src, ctx), bytes, mime })
}

/// Save a prepared image where the kernel can pick it up and return its marker line.
fn attach(m: &Media, ctx: &ToolCtx, bytes: &[u8], mime: &str) -> Result<String, String> {
    let dir = m.out_dir(ctx, "vision");
    let p = crate::store::save(&dir, &crate::store::stem("view"), &crate::Asset::new(bytes.to_vec(), mime))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(ark_core::tool::image_marker(mime, &p))
}

// ───── describe route ─────

const BILLING: &[&str] = &["402", "insufficient", "payment required", "credits", "billing"];
const SIZE_HINTS: &[&str] = &["too large", "payload", "413", "content_too_large", "request_too_large", "exceeds", "size limit"];

fn is_size_error(e: &str) -> bool {
    let l = e.to_ascii_lowercase();
    SIZE_HINTS.iter().chain(["image_url", "invalid_request"].iter()).any(|h| l.contains(h))
}

/// Hermes `_IMAGE_ERROR_RULES`: the explanation handed back when analysis fails.
pub fn explain_error(e: &str, model: Option<&str>) -> String {
    let l = e.to_ascii_lowercase();
    if BILLING.iter().any(|h| l.contains(h)) {
        return format!("Insufficient credits or payment required. Please top up your API provider account and try again. Error: {e}");
    }
    if ["does not support", "not support image", "content_policy", "multimodal", "unrecognized request argument", "image input"].iter().any(|h| l.contains(h)) {
        return format!("{} does not support vision or our request was not accepted by the server. Error: {e}", model.unwrap_or("The model"));
    }
    if ["invalid_request", "image_url"].iter().any(|h| l.contains(h)) {
        return format!("The vision API rejected the image. This can happen when the image is in an unsupported format, corrupted, or still too large after auto-resize. Try a smaller JPEG/PNG and retry. Error: {e}");
    }
    format!("There was a problem with the request and the image could not be analyzed. Error: {e}")
}

fn describe_model(m: &Media, arg: Option<&str>) -> Option<String> {
    arg.map(str::to_string).filter(|s| !s.trim().is_empty()).or_else(|| m.cfg.str("vision.model").filter(|s| !s.trim().is_empty()))
}

/// Ask a vision-capable model about `images` (`(mime, bytes)`): the configured/agent model
/// through [`crate::llm`], else the tool host's `analyze_image`. Retries once on an empty answer.
pub fn describe(ctx: &ToolCtx, model: Option<&str>, prompt: &str, images: &[(String, Vec<u8>)], cancel: &Cancel) -> Result<String, String> {
    describe_with(crate::llm(), ctx, model, prompt, images, cancel)
}

pub(crate) fn describe_with(llm: Option<Arc<dyn crate::Llm>>, ctx: &ToolCtx, model: Option<&str>, prompt: &str, images: &[(String, Vec<u8>)], cancel: &Cancel) -> Result<String, String> {
    if let Some(l) = llm {
        let mut content = vec![Block::text(prompt)];
        content.extend(images.iter().map(|(mt, b)| Block::Image { media_type: mt.clone(), data: crate::store::b64(b) }));
        let msgs = vec![Message { role: Role::User, content }];
        let mut out = l.complete(model, "", msgs.clone(), 4096, cancel)?;
        if out.trim().is_empty() && !cancel.is_cancelled() {
            out = l.complete(model, "", msgs, 4096, cancel)?;
        }
        return Ok(out);
    }
    let mut parts = Vec::new();
    let n = images.len();
    for (i, (mt, b)) in images.iter().enumerate() {
        // OpenClaw `model-execution.ts`: multi-image runs get a per-image prompt suffix and
        // `Image i:` prefixes; single-image runs pass the prompt through untouched.
        let p = if n == 1 { prompt.to_string() } else { format!("{prompt}\n\nDescribe image {} of {n}.", i + 1) };
        let a = ctx.host.analyze_image(&p, mt, &crate::store::b64(b))?;
        parts.push(if n > 1 { format!("Image {}:\n{}", i + 1, a.trim()) } else { a.trim().to_string() });
    }
    Ok(parts.join("\n\n").trim().to_string())
}

// ───── repeat cap (Hermes vision_tools_history_budget) ─────

/// `(session, prompt key)` → `(repeat count, first-seen ms)`.
type RepeatCounts = HashMap<(String, String), (usize, u64)>;

fn repeat_counts() -> &'static Mutex<RepeatCounts> {
    static R: OnceLock<Mutex<RepeatCounts>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn repeat_seq() -> u64 {
    static S: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    S.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Reserve one native embed; `Err(refusal)` when the per-session cap is spent.
fn reserve_embed(m: &Media, session: &str, key: &str) -> Result<bool, String> {
    let cap = m.cfg.int_or("vision.max_calls_per_image", 0).max(0) as usize;
    if cap == 0 {
        return Ok(false);
    }
    let mut r = repeat_counts().lock().unwrap();
    if r.len() > 4096 {
        // Evict the single oldest counter (Hermes drops the oldest key) so live caps keep enforcing.
        if let Some(k) = r.iter().min_by_key(|(_, v)| v.1).map(|(k, _)| k.clone()) {
            r.remove(&k);
        }
    }
    let seq = repeat_seq();
    let n = r.entry((session.to_string(), key.to_string())).or_insert((0, seq));
    if n.0 < cap {
        n.0 += 1;
        n.1 = seq;
        return Ok(true);
    }
    let n = n.0;
    Err(format!("vision_analyze refused: this image has already been loaded into context {n} time(s) in this session (region crops of the same file count too), and every native load re-sends the full image on each later API call. Answer from what you can already see, or ask the user. (vision.max_calls_per_image = {cap}; 0 = unlimited)"))
}

fn release_embed(session: &str, key: &str) {
    let mut r = repeat_counts().lock().unwrap();
    let k = (session.to_string(), key.to_string());
    match r.get(&k).copied() {
        Some((n, seq)) if n > 1 => {
            r.insert(k, (n - 1, seq));
        }
        _ => {
            r.remove(&k);
        }
    }
}

fn region_arg(input: &Value) -> Result<Option<Vec<i64>>, String> {
    match input.get("region") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.len() == 4 && a.iter().all(|v| v.is_number()) => Ok(Some(a.iter().map(|v| v.as_f64().unwrap_or(0.0) as i64).collect())),
        _ => Err("Invalid region: expected [x1, y1, x2, y2] as four numbers (pixel coordinates in the original image).".into()),
    }
}

fn net_effects(srcs: &[String], payload: &str) -> Vec<Effect> {
    srcs.iter().filter(|s| s.starts_with("http://") || s.starts_with("https://")).map(|s| Effect::Net { dest: crate::http::host_of(s), payload: payload.to_string() }).collect()
}

fn read_effects(ctx: &ToolCtx, srcs: &[String]) -> Vec<Effect> {
    srcs.iter().filter(|s| !s.contains("://") || s.starts_with("file://")).filter(|s| !s.starts_with("data:")).map(|s| Effect::Read { path: crate::store::resolve(s.trim_start_matches('@'), &ctx.workspace) }).collect()
}

// ───── vision_analyze (Hermes) ─────

pub struct VisionAnalyze {
    pub m: Arc<Media>,
}

impl VisionAnalyze {
    fn native_call(&self, ctx: &ToolCtx, src: &str, question: &str, region: Option<Vec<i64>>) -> Result<String, String> {
        let m = &self.m;
        let img = load(m, ctx, src, MAX_DOWNLOAD_BYTES)?;
        let reserved = reserve_embed(m, &ctx.session_id, &img.key)?;
        let r = (|| {
            let (bytes, mime) = prep::normalize(&img.bytes, &img.mime)?;
            prep::validate_decodable(&bytes, &mime)?;
            let (bytes, mime, crop) = match &region {
                Some(r) => {
                    let (b, off) = prep::crop(&bytes, &mime, r)?;
                    (b, "image/png".to_string(), Some(off))
                }
                None => (bytes, mime, None),
            };
            let target = embed_target_bytes(m);
            let over = prep::dimensions(&bytes).is_some_and(|(w, h)| w.max(h) > EMBED_MAX_DIMENSION);
            let (bytes, mime, scale) = if prep::data_url_len(&mime, bytes.len()) > target || over { prep::resize_for_vision(&bytes, &mime, target, Some(EMBED_MAX_DIMENSION), true) } else { (bytes, mime, None) };
            if prep::data_url_len(&mime, bytes.len()) > MAX_BASE64_BYTES {
                return Err(too_large(prep::data_url_len(&mime, bytes.len())));
            }
            let mut text = "Image loaded into your context — you can see it natively now. Use your built-in vision to answer the user.".to_string();
            if !question.trim().is_empty() {
                text.push_str(&format!("\n\nQuestion: {}", question.trim()));
            }
            if let Some(n) = prep::scale_note(scale, crop) {
                text.push_str(&format!("\n\nNote: {n}"));
            }
            Ok(format!("{text}\n{}", attach(m, ctx, &bytes, &mime)?))
        })();
        if r.is_err() && reserved {
            release_embed(&ctx.session_id, &img.key);
        }
        r
    }

    fn describe_call(&self, ctx: &ToolCtx, src: &str, question: &str, region: Option<Vec<i64>>, model: Option<&str>) -> Value {
        let m = &self.m;
        let run = || -> Result<(String, Option<String>), String> {
            let img = load(m, ctx, src, MAX_DOWNLOAD_BYTES)?;
            let (bytes, mime) = prep::normalize(&img.bytes, &img.mime)?;
            let (bytes, mime, crop) = match &region {
                Some(r) => {
                    let (b, off) = prep::crop(&bytes, &mime, r)?;
                    (b, "image/png".to_string(), Some(off))
                }
                None => (bytes, mime, None),
            };
            let (mut bytes, mut mime, mut scale) = (bytes, mime, None);
            if prep::data_url_len(&mime, bytes.len()) > MAX_BASE64_BYTES {
                let r = prep::resize_for_vision(&bytes, &mime, RESIZE_TARGET_BYTES, None, false);
                (bytes, mime, scale) = r;
                if prep::data_url_len(&mime, bytes.len()) > MAX_BASE64_BYTES {
                    return Err(too_large(prep::data_url_len(&mime, bytes.len())));
                }
            }
            let prompt = format!("Fully describe and explain everything about this image, then answer the following question:\n\n{question}");
            let a = match describe(ctx, model, &prompt, &[(mime.clone(), bytes.clone())], &ctx.cancel) {
                Err(e) if is_size_error(&e) && prep::data_url_len(&mime, bytes.len()) > RESIZE_TARGET_BYTES => {
                    let (b, mt, s) = prep::resize_for_vision(&bytes, &mime, RESIZE_TARGET_BYTES, None, false);
                    scale = s.or(scale);
                    describe(ctx, model, &prompt, &[(mt, b)], &ctx.cancel)?
                }
                r => r?,
            };
            Ok((a, prep::scale_note(scale, crop)))
        };
        match run() {
            Ok((a, note)) => {
                let a = if a.trim().is_empty() { "There was a problem with the request and the image could not be analyzed.".to_string() } else { a };
                let mut v = json!({"success": true, "analysis": match &note { Some(n) => format!("[{n}] {a}"), None => a }});
                if let Some(n) = note {
                    v["scale_note"] = json!(n);
                }
                v
            }
            Err(e) => json!({"success": false, "error": format!("Error analyzing image: {e}"), "analysis": explain_error(&e, model)}),
        }
    }
}

fn too_large(n: usize) -> String {
    format!("Image too large for vision API: base64 payload is {:.1} MB (limit {} MB) even after resizing. Compress the image manually and retry.", n as f64 / (1024.0 * 1024.0), MAX_BASE64_BYTES / (1024 * 1024))
}

impl Tool for VisionAnalyze {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "vision_analyze".into(),
            description: "Load an image into the conversation so you can see it. Call it any time the user references an image — then answer from what you see.".into(),
            input_schema: json!({"type": "object", "properties": {
                "image_url": {"type": "string", "description": "Image URL (http/https), local file path, or data: URL to load."},
                "question": {"type": "string", "description": "Your question or request about the image."},
                "region": {"type": "array", "items": {"type": "integer"}, "minItems": 4, "maxItems": 4, "description": "Optional [x1, y1, x2, y2] crop in ORIGINAL-image pixel coordinates, applied before any downscaling — the crop keeps full resolution. Load the full image first, then re-call with a region to zoom into small text or fine detail."}
            }, "required": ["image_url", "question"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let src = vec![input["image_url"].as_str().unwrap_or("").to_string()];
        let mut fx = read_effects(ctx, &src);
        fx.extend(net_effects(&src, ""));
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let src = input["image_url"].as_str().unwrap_or("");
        if src.trim().is_empty() {
            return ToolOutput::err(json!({"success": false, "error": "image_url is required"}).to_string());
        }
        let question = input["question"].as_str().unwrap_or("");
        let region = match region_arg(&input) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(json!({"success": false, "error": e}).to_string()),
        };
        if ctx.cancel.is_cancelled() {
            return ToolOutput::err(json!({"success": false, "error": "Interrupted"}).to_string());
        }
        if native(&self.m) {
            return match self.native_call(ctx, src, question, region) {
                Ok(s) => ToolOutput::ok(s),
                Err(e) => ToolOutput::err(json!({"success": false, "error": e}).to_string()),
            };
        }
        let model = describe_model(&self.m, None);
        let v = self.describe_call(ctx, src, question, region, model.as_deref());
        let ok = v["success"] == true;
        let s = serde_json::to_string_pretty(&v).unwrap_or_default();
        if ok {
            ToolOutput::ok(s)
        } else {
            ToolOutput::err(s)
        }
    }
}

// ───── view_image (OpenClaw) ─────

pub struct ViewImage {
    pub m: Arc<Media>,
}

const DEFAULT_MAX_IMAGES: usize = 20;
/// OpenClaw `MAX_IMAGE_BYTES` (`packages/media-core/src/constants.ts`): the outbound image cap
/// the media loader applies when `maxBytesMb` / `agents.defaults.mediaMaxMb` are unset.
pub const MEDIA_MAX_IMAGE_BYTES: usize = 6 * 1024 * 1024;

fn path_inputs(input: &Value) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim();
        let s = s.strip_prefix('@').map(str::trim).unwrap_or(s);
        if !s.is_empty() && !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    };
    if let Some(p) = input["path"].as_str() {
        push(p);
    }
    for p in input["paths"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        push(p);
    }
    v
}

impl Tool for ViewImage {
    fn spec(&self) -> ToolSpec {
        let desc = if native(&self.m) {
            "Load image(s) into private model context for inspection: path accepts one local image path or permitted URL; paths accepts up to maxImages entries (20 by default). Does not display, attach, or send files to the user. Prompt images are already visible."
        } else {
            "Inspect image(s) in private model context with available vision: path accepts one local image path or permitted URL; paths accepts up to maxImages entries (20 by default). Does not display, attach, or send files to the user."
        };
        ToolSpec {
            name: "view_image".into(),
            description: desc.into(),
            input_schema: json!({"type": "object", "properties": {
                "prompt": {"type": "string"},
                "path": {"type": "string", "description": "One local image path or permitted URL."},
                "paths": {"type": "array", "items": {"type": "string"}, "description": "Local image paths or permitted URLs; maxImages default 20."},
                "model": {"type": "string"},
                "maxBytesMb": {"type": "number", "exclusiveMinimum": 0},
                "maxImages": {"type": "integer", "minimum": 1}
            }}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let srcs = path_inputs(input);
        let mut fx = read_effects(ctx, &srcs);
        fx.extend(net_effects(&srcs, ""));
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let m = &self.m;
        let paths = path_inputs(&input);
        if paths.is_empty() {
            return ToolOutput::err("path required");
        }
        let max_images = input["maxImages"].as_u64().filter(|n| *n > 0).map(|n| n as usize).unwrap_or(DEFAULT_MAX_IMAGES);
        if paths.len() > max_images {
            return ToolOutput::err(format!("Too many images: {} provided, maximum is {max_images}. Please reduce the number of images.", paths.len()));
        }
        let max_bytes = match input.get("maxBytesMb") {
            Some(v) if !v.is_null() => match v.as_f64() {
                Some(x) if x > 0.0 => (x * 1024.0 * 1024.0) as usize,
                _ => return ToolOutput::err("maxBytesMb must be greater than 0"),
            },
            _ => MEDIA_MAX_IMAGE_BYTES,
        };
        let prompt = input["prompt"].as_str().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("Describe the image.");
        let mut loaded = Vec::new();
        for p in &paths {
            if ctx.cancel.is_cancelled() {
                return ToolOutput::err("cancelled");
            }
            match load(m, ctx, p, max_bytes) {
                Ok(l) => loaded.push((p.clone(), l)),
                Err(e) => return ToolOutput::err(e),
            }
        }
        let max_dim = cfg_usize(m, "vision.max_dimension_px", prep::DEFAULT_MAX_DIMENSION_PX as usize) as u32;
        let max_b = cfg_usize(m, "vision.max_bytes", prep::DEFAULT_MAX_BYTES);
        if native(m) {
            let mut lines = Vec::new();
            let mut kept = 0;
            for (_, l) in &loaded {
                match prep::normalize(&l.bytes, &l.mime).and_then(|(b, mt)| prep::sanitize(&b, &mt, max_dim, max_b, true)) {
                    Ok((b, mt)) => match attach(m, ctx, &b, &mt) {
                        Ok(mk) => {
                            kept += 1;
                            lines.push(mk);
                        }
                        Err(e) => lines.push(format!("[image:native] omitted image payload: {e}")),
                    },
                    Err(e) => lines.push(format!("[image:native] omitted image payload: {e}")),
                }
            }
            let head = format!("Loaded {kept} image{} into private model context for inspection; not displayed, attached, or sent to the user.", if kept == 1 { "" } else { "s" });
            return ToolOutput::ok(format!("{head}\n{}", lines.join("\n")));
        }
        // Text-only runs delegate image understanding to a vision model.
        let model = describe_model(m, input["model"].as_str());
        let mut imgs = Vec::new();
        for (_, l) in &loaded {
            match prep::normalize(&l.bytes, &l.mime).and_then(|(b, mt)| prep::sanitize(&b, &mt, max_dim, max_b, false)) {
                Ok(x) => imgs.push((x.1, x.0)),
                Err(e) => return ToolOutput::err(e),
            }
        }
        match describe(ctx, model.as_deref(), prompt, &imgs, &ctx.cancel) {
            Ok(t) if !t.trim().is_empty() => ToolOutput::ok(t),
            Ok(_) => ToolOutput::err("The image model returned no text."),
            Err(e) => ToolOutput::err(explain_error(&e, model.as_deref())),
        }
    }
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = vec![Arc::new(VisionAnalyze { m: m.clone() }), Arc::new(ViewImage { m: m.clone() })];
    if local::configured(m) {
        v.push(Arc::new(local::LocalImage { m: m.clone() }));
    }
    v
}

/// Directory prepared images are written to for the kernel (for cleanup tools).
pub fn attach_dir(m: &Media, ctx: &ToolCtx) -> PathBuf {
    m.out_dir(ctx, "vision")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    struct FakeLlm {
        vision: bool,
        seen: Mutex<Vec<(Option<String>, usize)>>,
    }
    impl crate::Llm for FakeLlm {
        fn complete(&self, model: Option<&str>, _s: &str, msgs: Vec<Message>, _t: u32, _c: &Cancel) -> Result<String, String> {
            let imgs = msgs[0].content.iter().filter(|b| matches!(b, Block::Image { .. })).count();
            self.seen.lock().unwrap().push((model.map(str::to_string), imgs));
            Ok(format!("saw {imgs} image(s)"))
        }
        fn vision(&self, _m: Option<&str>) -> bool {
            self.vision
        }
    }

    fn media(extra: &str) -> Arc<Media> {
        Media::new(crate::MediaConfig::from_toml(extra))
    }

    #[test]
    fn vision_analyze_native_attaches_resized_image() {
        let ctx = testutil::ctx("vision-native");
        std::fs::write(ctx.workspace.join("shot.png"), prep::test_png(3200, 800)).unwrap();
        let m = media("[vision]\nmode = \"native\"\nmax_calls_per_image = 2\n");
        let t = VisionAnalyze { m: m.clone() };
        let out = t.call(&ctx, json!({"image_url": "shot.png", "question": "what is it?"}));
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("Question: what is it?") && out.content.contains("downscaled from 3200x800"), "{}", out.content);
        let (text, imgs) = ark_core::tool::take_images(&out.content);
        assert_eq!(imgs.len(), 1, "{text}");
        let raw = crate::store::b64_decode(&imgs[0].1).unwrap();
        assert!(raw.len() <= DEFAULT_EMBED_TARGET && prep::dimensions(&raw).unwrap().0 <= EMBED_MAX_DIMENSION);
        // Region crop keeps the original resolution and reports the offset.
        let out = t.call(&ctx, json!({"image_url": "shot.png", "question": "zoom", "region": [100, 100, 300, 200]}));
        assert!(out.content.contains("offset (100, 100)"), "{}", out.content);
        // The per-image cap counts crops too.
        let out = t.call(&ctx, json!({"image_url": "shot.png", "question": "again"}));
        assert!(out.is_error && out.content.contains("max_calls_per_image = 2"), "{}", out.content);
        let out = t.call(&ctx, json!({"image_url": "ftp://x/y.png", "question": "q"}));
        assert!(out.is_error && out.content.contains("Unsupported image reference"));
        let out = t.call(&ctx, json!({"image_url": "http://127.0.0.1:9/a.png", "question": "q"}));
        assert!(out.is_error && out.content.contains("private/internal"), "{}", out.content);
    }

    #[test]
    fn ssrf_floor_ignores_allow_private_urls() {
        // The cloud-metadata floor is consulted before the config toggle (Hermes url_safety).
        let open = media("[vision]\nallow_private_urls = true\n");
        assert!(check_url(&open, "http://127.0.0.1:8080/x.png").is_ok());
        assert!(check_url(&open, "http://[::1]:8080/x.png").is_ok());
        assert!(check_url(&open, "http://169.254.169.254/latest/meta-data").unwrap_err().contains("cloud metadata"));
        assert!(check_url(&open, "http://[fd00:ec2::254]/x").unwrap_err().contains("cloud metadata"));
        assert!(check_url(&open, "http://100.100.100.200/x").unwrap_err().contains("cloud metadata"));
        assert!(check_url(&open, "http://metadata.google.internal/x").unwrap_err().contains("internal hostname"));
        assert!(check_url(&open, "http://metadata.goog/x").unwrap_err().contains("internal hostname"));
        // Without the toggle, ordinary private space is blocked too.
        let closed = media("");
        assert!(check_url(&closed, "http://127.0.0.1:9/a.png").unwrap_err().contains("private/internal address"));
        assert!(check_url(&closed, "http://10.1.2.3/a.png").unwrap_err().contains("private/internal address"));
    }

    #[test]
    fn ssrf_classification_is_the_shared_one() {
        // The media fetchers decide with ark_security::url_safety (web tools, browser, media): one
        // address classifier, one metadata floor.
        use std::net::IpAddr;
        let table: &[(&str, bool)] = &[
            ("127.0.0.1", true),
            ("::1", true),
            ("169.254.169.254", true),
            ("10.0.0.1", true),
            ("100.64.0.1", true),
            ("8.8.8.8", false),
            ("fe80::1", true),
            ("fd00:ec2::254", true),
            ("::ffff:10.0.0.1", true),
        ];
        for (s, blocked) in table {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(ark_security::url_safety::is_blocked_ip(ip), *blocked, "{s}: the shared verdict");
            assert_eq!(private_ip(ip), *blocked, "{s}: media private_ip is the shared rule");
        }
        // Metadata host names are the shared list, and stay blocked with the toggle on.
        assert_eq!(BLOCKED_HOSTNAMES, ark_security::url_safety::BLOCKED_HOSTNAMES);
        let open = media("[vision]\nallow_private_urls = true\n");
        let url_policy = ark_security::url_safety::UrlPolicy::default();
        let host_policy = ark_security::url_safety::HostPolicy { url: &url_policy, allowed_hostnames: &[], hostname_allowlist: &[], blocked_hostnames: &[] };
        for host in ["metadata.google.internal", "metadata.goog"] {
            assert!(ark_security::url_safety::check_host(host, "https", &host_policy).is_err(), "{host}: the shared host rule");
            assert!(check_url(&open, &format!("http://{host}/x")).unwrap_err().contains("internal hostname"), "{host}: delegated");
        }
        // The metadata address floor (metadata addresses win over `allow_private_urls`).
        for s in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(ark_security::url_safety::is_always_blocked_ip(ip), "{s}: the shared floor");
            assert!(always_blocked(ip), "{s}: media always_blocked delegates");
        }
        // An ordinary public address and a private one, through the whole policy.
        let closed = media("");
        assert!(check_url(&closed, "http://8.8.8.8/a.png").is_ok());
        assert!(check_url(&closed, "http://10.0.0.1/a.png").unwrap_err().contains("private/internal address"));
    }

    #[test]
    fn trusted_provider_origins_are_trusted_only_on_the_port_they_name() {
        // A15: the trusted list is `host[:port]` as the operator configured it. Trusting
        // 127.0.0.1:8080 must not open 127.0.0.1:22 (or another service on the same host).
        let p = UrlPolicy { allow_private: false, trusted_hosts: vec!["127.0.0.1:8080".into(), "cdn.example.com".into()] };
        let loopback: Vec<std::net::IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        assert!(p.check_resolved("127.0.0.1:8080", &loopback).is_ok(), "the configured origin");
        assert!(p.check_resolved("127.0.0.1:22", &loopback).is_err(), "another port on the same host");
        assert!(p.check_resolved("127.0.0.1", &loopback).is_err(), "no port means the default port");
        assert!(p.check_resolved("cdn.example.com:443", &["93.184.216.34".parse().unwrap()]).is_ok());
        assert!(p.check_resolved("other.example.com:443", &["93.184.216.34".parse().unwrap()]).is_ok(), "public space needs no trust");
        // The metadata floor ignores both the toggle and the trusted list.
        let open = UrlPolicy { allow_private: true, trusted_hosts: vec!["169.254.169.254".into()] };
        for ip in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"] {
            let e = open.check_resolved("169.254.169.254:80", &[ip.parse().unwrap()]).unwrap_err();
            assert!(e.contains("cloud metadata"), "{ip}: {e}");
        }
        assert!(open.check_resolved("metadata.google.internal", &loopback).unwrap_err().contains("internal hostname"));
        // `[v6]:port` parsing is the same parser as `host:port`.
        assert!(p.check_resolved("[::1]:8080", &["::1".parse().unwrap()]).is_err(), "v6 loopback is not the trusted v4 origin");
        assert_eq!(host_name("[::1]:8080"), "::1");
        assert_eq!(host_name("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn tool_hooks_sanitize_and_evict_per_session() {
        let ctx = testutil::ctx("vision-hooks");
        std::fs::write(ctx.workspace.join("wide.png"), prep::test_png(2000, 40)).unwrap();
        let m = media("[vision]\nmax_dimension_px = 64\nmax_bytes = 4096\nmax_calls_per_image = 0\n");
        let s = install_tool_hooks(&m);
        assert_eq!((s.max_dim, s.max_bytes), (64, 4096));
        // Post-processing uses the installed settings and rewrites in place.
        let mut blocks = vec![Block::Image { media_type: "image/png".into(), data: crate::store::b64(&prep::test_png(2000, 40)) }, Block::text("kept")];
        assert_eq!(post_tool_images(&mut blocks), 1);
        let (mt, data) = match &blocks[0] {
            Block::Image { media_type, data } => (media_type.clone(), data.clone()),
            _ => panic!("expected an image"),
        };
        let raw = crate::store::b64_decode(&data).unwrap();
        assert!(prep::dimensions(&raw).unwrap().0 <= 64, "{mt}");
        assert!(raw.len() <= 4096);
        assert!(matches!(&blocks[1], Block::Text { text } if text == "kept"));
        // Eviction keeps one latch per session id and remembers what it retired.
        let carrier = |id: &str| Message {
            role: Role::User,
            content: vec![Block::ToolResult { tool_use_id: id.into(), content: "shot".into(), is_error: false }, Block::Image { media_type: "image/png".into(), data: "AAAA".into() }],
        };
        let orig: Vec<Message> = (0..25).map(|i| carrier(&format!("h{i}"))).collect();
        let mut msgs = orig.clone();
        assert_eq!(evict_for_session("s-hooks", &mut msgs), 8);
        assert_eq!(latched_sessions(), 1);
        let mut fewer = orig[..10].to_vec();
        assert_eq!(evict_for_session("s-hooks", &mut fewer), 8, "the latch keeps retired carriers retired");
        // Another session has its own latch and leaves the smaller request untouched.
        assert_eq!(evict_for_session("s-other", &mut orig[..10].to_vec()), 0);
        reset_session("s-hooks");
        assert_eq!(latched_sessions(), 1);
        reset_session("s-other");
        assert_eq!(latched_sessions(), 0);
        // Restore the process-wide defaults other tests rely on.
        install_tool_hooks(&media(""));
    }

    #[test]
    fn view_image_byte_caps_follow_openclaw() {
        let ctx = testutil::ctx("view-image-cap");
        std::fs::write(ctx.workspace.join("a.png"), prep::test_png(20, 20)).unwrap();
        let m = media("[vision]\nmode = \"native\"\n");
        let t = ViewImage { m };
        // Default cap is OpenClaw's MAX_IMAGE_BYTES (6 MiB), not Hermes' 50 MiB download cap.
        assert_eq!(MEDIA_MAX_IMAGE_BYTES, 6 * 1024 * 1024);
        std::fs::write(ctx.workspace.join("big.png"), vec![0u8; MEDIA_MAX_IMAGE_BYTES + 1]).unwrap();
        let out = t.call(&ctx, json!({"path": "big.png"}));
        assert!(out.is_error && out.content.contains("Image too large"), "{}", out.content);
        // Explicit maxBytesMb wins, and must be positive.
        let out = t.call(&ctx, json!({"path": "a.png", "maxBytesMb": 0.00001}));
        assert!(out.is_error && out.content.contains("Image too large"), "{}", out.content);
        let out = t.call(&ctx, json!({"path": "a.png", "maxBytesMb": 0}));
        assert!(out.is_error && out.content == "maxBytesMb must be greater than 0", "{}", out.content);
        assert!(t.call(&ctx, json!({"path": "a.png", "maxBytesMb": 1})).content.starts_with("Loaded 1 image"));
    }

    #[test]
    fn view_image_and_describe_routes() {
        let ctx = testutil::ctx("view-image");
        std::fs::write(ctx.workspace.join("a.png"), prep::test_png(2000, 1000)).unwrap();
        std::fs::write(ctx.workspace.join("b.png"), prep::test_png(10, 10)).unwrap();
        std::fs::write(ctx.workspace.join("c.txt"), b"hello").unwrap();
        let m = media("[vision]\nmode = \"native\"\n");
        let t = ViewImage { m: m.clone() };
        let out = t.call(&ctx, json!({"path": "a.png", "paths": ["@b.png", "a.png"]}));
        assert!(out.content.starts_with("Loaded 2 images into private model context"), "{}", out.content);
        let (_, imgs) = ark_core::tool::take_images(&out.content);
        assert_eq!(imgs[0].0, "image/jpeg", "oversized → sanitized JPEG");
        let d = prep::dimensions(&crate::store::b64_decode(&imgs[0].1).unwrap()).unwrap();
        assert!(d.0 <= 1200 && d.1 <= 1200);
        assert_eq!(imgs[1].0, "image/png");
        assert!(t.call(&ctx, json!({"paths": ["a.png", "b.png"], "maxImages": 1})).content.starts_with("Too many images: 2 provided, maximum is 1"));
        assert!(t.call(&ctx, json!({"path": "c.txt"})).content.contains("not an image"));
        assert!(t.call(&ctx, json!({})).content == "path required");
        // Describe route via the tool host (no LLM installed in this test process slot).
        let m2 = media("[vision]\nmode = \"describe\"\n");
        let v = VisionAnalyze { m: m2 };
        let out = v.call(&ctx, json!({"image_url": "b.png", "question": "q"}));
        assert!(out.is_error && out.content.contains("no vision model is available"), "{}", out.content);
        // Describe route through an LLM: the configured model sees every image.
        let llm = Arc::new(FakeLlm { vision: false, seen: Mutex::new(vec![]) });
        let imgs = vec![("image/png".to_string(), prep::test_png(4, 4)), ("image/png".to_string(), prep::test_png(5, 5))];
        let out = describe_with(Some(llm.clone()), &ctx, Some("google/gemini-2.5-flash"), "compare", &imgs, &Cancel::new()).unwrap();
        assert_eq!(out, "saw 2 image(s)");
        assert_eq!(llm.seen.lock().unwrap()[0], (Some("google/gemini-2.5-flash".to_string()), 2));
    }

    #[test]
    fn sanitize_blocks_replaces_bad_images() {
        let mut blocks = vec![
            Block::text("hi"),
            Block::Image { media_type: "image/png".into(), data: crate::store::b64(&prep::test_png(1600, 100)) },
            Block::Image { media_type: "image/png".into(), data: "!!!".into() },
            Block::Image { media_type: "image/png".into(), data: crate::store::b64(&prep::test_png(8, 8)) },
        ];
        assert_eq!(sanitize_blocks(&mut blocks, "image:native", 1200, prep::DEFAULT_MAX_BYTES), 2);
        assert!(matches!(&blocks[1], Block::Image { media_type, .. } if media_type == "image/jpeg"));
        assert!(matches!(&blocks[2], Block::Text { text } if text.starts_with("[image:native] omitted image payload")));
        assert!(matches!(&blocks[3], Block::Image { media_type, .. } if media_type == "image/png"));
        assert!(explain_error("HTTP 402 payment required", None).starts_with("Insufficient credits"));
        assert!(explain_error("model does not support image input", Some("x/y")).starts_with("x/y does not support vision"));
    }
}
