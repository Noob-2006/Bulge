//! Model metadata and pricing. Three layers, most specific first:
//! 1. a models.dev registry snapshot (`https://models.dev/api.json`) cached on disk by
//!    `ark models refresh` (Hermes `agent/models_dev.py`, ETag-conditional refresh);
//! 2. official-docs price snapshots (Hermes `agent/usage_pricing.py` `_SNAPSHOTS`);
//! 3. context-window table by id substring, longest key first (Hermes
//!    `agent/model_metadata.py` `DEFAULT_CONTEXT_LENGTHS`), then name heuristics.
//!
//! Cache hierarchy (Hermes `fetch_models_dev`): the held in-memory registry is served at any age;
//! once it is older than [`CACHE_TTL`] exactly one background thread revalidates it while callers
//! keep reading the stale copy. Disk is consulted once per process (cold start, any age). A failed
//! refresh arms a process-wide [`RETRY_DELAY`] backoff, so an unreachable mirror can never turn
//! into one request per call. A corrupt/empty disk cache is quarantined (renamed to
//! `<path>.corrupt`) instead of being served as `{}`.
//!
//! Mirror: [`set_mirror`]/[`mirror`] (Hermes `models_dev.url`). `refresh(None)` honours it; an
//! explicit `refresh(Some(url))` still wins. The manager wires the config key in
//! `crates/ark/src/models_cli.rs::init`: `modelsdb::set_mirror(&cfg.pricing.models_dev_url)`.

use ark_core::ModelCaps;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

pub const MODELS_DEV_URL: &str = "https://models.dev/api.json";
/// Registry TTL: older than this, a held registry is still served while ONE background refresh runs.
pub const CACHE_TTL: Duration = Duration::from_secs(4 * 3600);
/// Failed-refresh backoff (Hermes `_MODELS_DEV_RETRY_DELAY`).
pub const RETRY_DELAY: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pricing {
    /// USD per million tokens.
    pub input: f64,
    pub output: f64,
    pub cache_read: Option<f64>,
    pub cache_write: Option<f64>,
    /// Where the numbers come from (`models.dev`, a docs snapshot id, `config`).
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelInfo {
    pub id: String,
    pub provider: String,
    pub name: String,
    pub context: u64,
    pub max_output: u32,
    pub reasoning: bool,
    pub tool_call: bool,
    /// Image/file attachments (`attachment` or `image` in the input modalities).
    pub vision: bool,
    /// `modalities.input` — `["text", "image", "pdf", "audio", …]`.
    pub input_modalities: Vec<String>,
    /// `modalities.output` — usually `["text"]`.
    pub output_modalities: Vec<String>,
    /// Schema-enforced JSON output.
    pub structured_output: bool,
    /// Weights are downloadable, so the model can run locally.
    pub open_weights: bool,
    /// Training-data cutoff, e.g. `"2026-03"` (`knowledge` upstream).
    pub knowledge_cutoff: String,
    pub release_date: String,
    /// Lifecycle marker: `"alpha"`, `"beta"`, `"deprecated"`, or `""`.
    pub status: String,
    pub pricing: Option<Pricing>,
}

impl ModelInfo {
    pub fn caps(&self) -> ModelCaps {
        let h = crate::heuristic_caps(&self.id);
        ModelCaps {
            context_window: if self.context > 0 {
                self.context
            } else {
                h.context_window
            },
            max_output: if self.max_output > 0 {
                self.max_output
            } else {
                h.max_output
            },
            tools: self.tool_call || h.tools,
            // models.dev is authoritative when it lists modalities (`vision` alone only carries
            // the legacy `attachment` flag); otherwise fall back to name heuristics.
            vision: self.supports_vision() || h.vision,
            explicit_cache: h.explicit_cache,
        }
    }

    /// Image input (`attachment`/`vision` flag, or `image` in the input modalities).
    pub fn supports_vision(&self) -> bool {
        self.vision || self.has_input_modality("image")
    }

    /// PDF input (documents are read natively, not OCR'd through images).
    pub fn supports_pdf(&self) -> bool {
        self.has_input_modality("pdf")
    }

    pub fn supports_audio_input(&self) -> bool {
        self.has_input_modality("audio")
    }

    pub fn has_input_modality(&self, m: &str) -> bool {
        self.input_modalities.iter().any(|x| x.eq_ignore_ascii_case(m))
    }

    pub fn has_cost_data(&self) -> bool {
        self.pricing
            .as_ref()
            .is_some_and(|p| p.input > 0.0 || p.output > 0.0)
    }

    pub fn is_deprecated(&self) -> bool {
        self.status.eq_ignore_ascii_case("deprecated")
    }

    /// Human-readable capability line, e.g. `"reasoning, tools, vision"` (`"basic"` if none).
    pub fn format_capabilities(&self) -> String {
        let flags: [(bool, &str); 7] = [
            (self.reasoning, "reasoning"),
            (self.tool_call, "tools"),
            (self.supports_vision(), "vision"),
            (self.supports_pdf(), "PDF"),
            (self.supports_audio_input(), "audio"),
            (self.structured_output, "structured output"),
            (self.open_weights, "open weights"),
        ];
        let on: Vec<&str> = flags.iter().filter(|(on, _)| *on).map(|(_, l)| *l).collect();
        if on.is_empty() {
            "basic".into()
        } else {
            on.join(", ")
        }
    }
}

type Rate = (&'static str, f64, f64, Option<f64>, Option<f64>);

const OPUS: (f64, f64, Option<f64>, Option<f64>) = (5.0, 25.0, Some(0.5), Some(6.25));
const SONNET: (f64, f64, Option<f64>, Option<f64>) = (3.0, 15.0, Some(0.3), Some(3.75));
const OPUS_5_5: (f64, f64, Option<f64>, Option<f64>) = (4.0, 20.0, Some(0.2), Some(5.0));

fn r(id: &'static str, t: (f64, f64, Option<f64>, Option<f64>)) -> Rate {
    (id, t.0, t.1, t.2, t.3)
}

/// (provider, snapshot version, rates) — ported from Hermes official-docs snapshots.
fn snapshots() -> Vec<(&'static str, &'static str, Vec<Rate>)> {
    let rr =
        |id: &'static str, i: f64, o: f64, cr: Option<f64>, cw: Option<f64>| (id, i, o, cr, cw);
    vec![
        (
            "openai",
            "openai-gpt-5.6-2026-07",
            vec![
                rr("gpt-5.6-sol", 5.0, 30.0, Some(0.5), Some(6.25)),
                rr("gpt-5.6-terra", 2.5, 15.0, Some(0.25), Some(3.125)),
                rr("gpt-5.6-luna", 1.0, 6.0, Some(0.1), Some(1.25)),
            ],
        ),
        (
            "openai",
            "openai-gpt-6-tiers-2026-09",
            vec![
                rr("gpt-6-sol", 2.0, 10.0, Some(0.2), Some(2.5)),
                rr("gpt-6.1-sol", 2.0, 10.0, Some(0.1), Some(2.5)),
                rr("gpt-6-luna", 0.1, 0.5, Some(0.01), Some(0.125)),
                rr("gpt-6-astra", 10.0, 50.0, Some(1.0), Some(12.5)),
            ],
        ),
        (
            "openai",
            "openai-pricing-2026-03-16",
            vec![
                rr("gpt-4o", 2.5, 10.0, Some(1.25), None),
                rr("gpt-4o-mini", 0.15, 0.6, Some(0.075), None),
                rr("gpt-4.1", 2.0, 8.0, Some(0.5), None),
                rr("gpt-4.1-mini", 0.4, 1.6, Some(0.1), None),
                rr("gpt-4.1-nano", 0.1, 0.4, Some(0.025), None),
                rr("o3", 10.0, 40.0, Some(2.5), None),
                rr("o3-mini", 1.1, 4.4, Some(0.55), None),
            ],
        ),
        (
            "anthropic",
            "anthropic-pricing-2026-05",
            vec![
                r("claude-opus-4-8", OPUS),
                r("claude-opus-4-7", OPUS),
                r("claude-opus-4-6", OPUS),
                r("claude-opus-4-5", OPUS),
                r("claude-sonnet-4-6", SONNET),
                r("claude-sonnet-4-5", SONNET),
                r("claude-sonnet-4-20250514", SONNET),
                r("claude-3-5-sonnet-20241022", SONNET),
                rr("claude-haiku-4-5", 1.0, 5.0, Some(0.1), Some(1.25)),
                rr("claude-opus-4-20250514", 15.0, 75.0, Some(1.5), Some(18.75)),
                rr("claude-3-opus-20240229", 15.0, 75.0, Some(1.5), Some(18.75)),
                rr("claude-3-5-haiku-20241022", 0.8, 4.0, Some(0.08), Some(1.0)),
                rr("claude-3-haiku-20240307", 0.25, 1.25, Some(0.03), Some(0.3)),
                rr("claude-opus-4-8-fast", 10.0, 50.0, Some(1.0), Some(12.5)),
            ],
        ),
        (
            "anthropic",
            "anthropic-pricing-2026-06-intro",
            vec![rr("claude-sonnet-5", 2.0, 10.0, Some(0.2), Some(2.5))],
        ),
        (
            "anthropic",
            "anthropic-pricing-2026-09",
            vec![r("claude-opus-5", OPUS), r("claude-opus-5-5", OPUS_5_5)],
        ),
        (
            "deepseek",
            "deepseek-pricing-2026-09-10",
            vec![
                rr("deepseek-flash", 0.15, 0.6, Some(0.003), None),
                rr("deepseek-v4-flash", 0.15, 0.6, Some(0.003), None),
                rr("deepseek-chat", 0.15, 0.6, Some(0.003), None),
                rr("deepseek-reasoner", 0.15, 0.6, Some(0.003), None),
                rr("deepseek-v4-pro", 0.66, 1.98, Some(0.022), None),
            ],
        ),
        (
            "google",
            "google-pricing-2026-10-13",
            vec![rr("gemini-4-argon", 2.0, 10.0, Some(0.1), None)],
        ),
        (
            "google",
            "google-pricing-2026-09-02",
            vec![
                rr("gemini-3.8-flash", 0.75, 3.75, Some(0.075), None),
                rr("gemini-3.7-flash", 0.75, 3.75, Some(0.075), None),
            ],
        ),
        (
            "google",
            "google-pricing-2026-07-28",
            vec![
                rr("gemini-3.6-flash", 1.5, 7.5, Some(0.15), None),
                rr("gemini-3.5-flash-lite", 0.3, 2.5, Some(0.03), None),
            ],
        ),
        (
            "google",
            "google-pricing-2026-07-07",
            vec![
                rr("gemini-3.5-flash", 1.5, 9.0, Some(0.15), None),
                rr("gemini-3.1-flash-lite", 0.25, 1.5, Some(0.025), None),
                rr(
                    "gemini-3.1-flash-lite-preview",
                    0.25,
                    1.5,
                    Some(0.025),
                    None,
                ),
                rr("gemini-3-pro-preview", 2.0, 12.0, Some(0.2), None),
                rr("gemini-3-flash-preview", 0.5, 3.0, Some(0.05), None),
                rr("gemini-3.1-pro", 2.0, 12.0, Some(0.2), None),
                rr("gemini-3.1-pro-preview", 2.0, 12.0, Some(0.2), None),
                rr("gemini-2.5-pro", 1.25, 10.0, Some(0.125), None),
                rr("gemini-2.5-flash", 0.15, 0.6, Some(0.015), None),
                rr("gemini-2.0-flash", 0.1, 0.4, Some(0.01), None),
            ],
        ),
        (
            "bedrock",
            "bedrock-pricing-2026-09",
            vec![
                r("anthropic.claude-opus-4-8", OPUS),
                r("anthropic.claude-opus-4-7", OPUS),
                r("anthropic.claude-opus-4-6", OPUS),
                r("anthropic.claude-opus-5", OPUS),
                r("anthropic.claude-opus-5-5", OPUS_5_5),
                r("anthropic.claude-sonnet-5", SONNET),
                r("anthropic.claude-sonnet-4-6", SONNET),
                r("anthropic.claude-sonnet-4-5", SONNET),
                rr(
                    "anthropic.claude-haiku-4-5",
                    0.8,
                    4.0,
                    Some(0.08),
                    Some(1.0),
                ),
                rr("amazon.nova-pro", 0.8, 3.2, None, None),
                rr("amazon.nova-lite", 0.06, 0.24, None, None),
                rr("amazon.nova-micro", 0.035, 0.14, None, None),
            ],
        ),
        (
            "minimax",
            "minimax-pricing-2026-04",
            vec![rr("minimax-m2.7", 0.3, 1.2, None, None)],
        ),
        (
            "fireworks",
            "fireworks-pricing-2026-07",
            vec![
                rr("kimi-k2p6", 0.95, 4.0, Some(0.16), None),
                rr("kimi-k2p7-code", 0.95, 4.0, Some(0.19), None),
                rr("glm-5p2", 1.4, 4.4, Some(0.14), None),
                rr("deepseek-v4-pro", 1.74, 3.48, Some(0.145), None),
                rr("deepseek-v4-flash", 0.14, 0.28, Some(0.028), None),
                rr("qwen3p7-plus", 0.4, 1.6, Some(0.08), None),
                rr("minimax-m3", 0.3, 1.2, Some(0.06), None),
                rr("gpt-oss-120b", 0.15, 0.6, Some(0.015), None),
                rr("gpt-oss-20b", 0.07, 0.3, Some(0.035), None),
            ],
        ),
    ]
}

/// Anthropic fast mode premium (`speed: "fast"`).
pub fn fast_pricing(model: &str) -> Option<Pricing> {
    let m = normalize_id(model);
    let (i, o, cr, cw) = match m.as_str() {
        "claude-opus-4-8" | "claude-opus-5" => (10.0, 50.0, 1.0, 12.5),
        "claude-opus-5-5" => (8.0, 40.0, 0.4, 10.0),
        _ => return None,
    };
    Some(Pricing {
        input: i,
        output: o,
        cache_read: Some(cr),
        cache_write: Some(cw),
        source: "anthropic-fast-mode-2026-09".into(),
    })
}

/// Context windows by id substring (longest key wins).
const CONTEXT: &[(&str, u64)] = &[
    ("claude-fable-5", 1_000_000),
    ("claude-fable", 1_000_000),
    ("claude-opus-5", 1_000_000),
    ("claude-sonnet-5", 1_000_000),
    ("claude-opus-4-8", 1_000_000),
    ("claude-opus-4.8", 1_000_000),
    ("claude-opus-4-7", 1_000_000),
    ("claude-opus-4.7", 1_000_000),
    ("claude-opus-4-6", 1_000_000),
    ("claude-sonnet-4-6", 1_000_000),
    ("claude-opus-4.6", 1_000_000),
    ("claude-sonnet-4.6", 1_000_000),
    ("claude", 200_000),
    ("gpt-6-astra", 1_050_000),
    ("gpt-6.1-sol", 1_050_000),
    ("gpt-6-sol", 1_050_000),
    ("gpt-6-luna", 1_050_000),
    ("gpt-5.6-luna", 1_050_000),
    ("gpt-5.6-terra", 1_050_000),
    ("gpt-5.6-sol", 1_050_000),
    ("gpt-5.5", 1_050_000),
    ("gpt-5.4-nano", 400_000),
    ("gpt-5.4-mini", 400_000),
    ("gpt-5.4", 1_050_000),
    ("gpt-5.3-codex-spark", 128_000),
    ("gpt-5.1-chat", 128_000),
    ("gpt-5", 400_000),
    ("gpt-4.1", 1_047_576),
    ("gpt-4o", 128_000),
    ("gpt-4", 128_000),
    ("gemini", 1_048_576),
    ("gemma-4", 256_000),
    ("gemma4", 256_000),
    ("gemma-3", 131_072),
    ("gemma", 8192),
    ("deepseek-v4-pro", 1_000_000),
    ("deepseek-v4.1-flash", 1_000_000),
    ("deepseek-v4-flash", 1_000_000),
    ("deepseek-chat", 1_000_000),
    ("deepseek-reasoner", 1_000_000),
    ("deepseek-flash", 1_000_000),
    ("deepseek", 128_000),
    ("llama", 131_072),
    ("muse-spark", 1_048_576),
    ("inkling", 1_048_576),
    ("qwen3.8-max", 1_000_000),
    ("qwen3.8-flash", 1_000_000),
    ("qwen3.6-plus", 1_048_576),
    ("qwen3.7-plus", 1_048_576),
    ("qwen3-coder-plus", 1_000_000),
    ("qwen3-coder", 262_144),
    ("qwen3-max", 262_144),
    ("qwen", 131_072),
    ("minimax-m3", 1_000_000),
    ("minimax", 204_800),
    ("glm-5.3-flashx", 1_048_576),
    ("glm-5.3", 1_310_720),
    ("glm-5.2", 1_048_576),
    ("glm-5.1", 204_800),
    ("glm-5-turbo", 202_752),
    ("glm-5", 204_800),
    ("glm-4.7-flash", 202_752),
    ("glm-4.7", 204_800),
    ("glm-4.6", 204_800),
    ("glm", 202_752),
    ("grok-composer", 200_000),
    ("grok-build", 256_000),
    ("grok-code-fast", 256_000),
    ("grok-4-fast", 2_000_000),
    ("grok-4.20", 2_000_000),
    ("grok-4.6", 500_000),
    ("grok-4.5", 500_000),
    ("grok-4.3", 1_000_000),
    ("grok-4", 256_000),
    ("grok-3", 131_072),
    ("grok", 131_072),
    ("kimi-k3", 1_048_576),
    ("kimi", 262_144),
    ("solar-pro3", 131_072),
    ("solar-pro2", 65_536),
    ("solar-mini", 32_768),
    ("solar-", 524_288),
    ("hy3", 262_144),
    ("nemotron", 131_072),
    ("mimo-v2.6-pro", 1_048_576),
    ("mimo-v2.5-pro", 1_048_576),
    ("mimo-v2-flash", 262_144),
    ("mimo", 262_144),
    ("mistral-large", 131_072),
    ("mistral", 131_072),
    ("codestral", 256_000),
    ("sonar", 127_072),
];

/// Lowercase, vendor prefix and date suffix stripped, `4.8` → `4-8` for Claude.
pub fn normalize_id(model: &str) -> String {
    let mut m = model.trim().to_lowercase();
    if let Some((_, rest)) = m.rsplit_once('/') {
        m = rest.to_string();
    }
    if let Some((base, _)) = m
        .split_once(':')
        .filter(|(b, _)| !b.starts_with("anthropic.") && !b.starts_with("amazon."))
    {
        m = base.to_string();
    }
    for p in ["us.", "eu.", "apac.", "global."] {
        if let Some(r) = m.strip_prefix(p) {
            if r.starts_with("anthropic.") || r.starts_with("amazon.") {
                m = r.to_string();
            }
        }
    }
    if m.starts_with("anthropic.") || m.starts_with("amazon.") {
        // Bedrock ids: `anthropic.claude-sonnet-4-5-20250929-v1:0`
        m = m.split(':').next().unwrap_or(&m).to_string();
        if let Some(i) = m.find("-v1").or_else(|| m.find("-v2")) {
            m.truncate(i);
        }
    }
    if m.contains("claude") {
        let b = m.as_bytes();
        let mut out = String::new();
        for (i, c) in m.chars().enumerate() {
            if c == '.'
                && i > 0
                && i + 1 < b.len()
                && b[i - 1].is_ascii_digit()
                && b[i + 1].is_ascii_digit()
            {
                out.push('-');
            } else {
                out.push(c);
            }
        }
        m = out;
    }
    // Drop a trailing -YYYYMMDD date.
    if m.len() > 9
        && m.as_bytes()[m.len() - 9] == b'-'
        && m[m.len() - 8..].chars().all(|c| c.is_ascii_digit())
    {
        let base = m[..m.len() - 9].to_string();
        if snapshot_price_exact(&m).is_none() {
            m = base;
        }
    }
    m
}

fn snapshot_price_exact(id: &str) -> Option<Pricing> {
    for (_, ver, rows) in snapshots() {
        if let Some((_, i, o, cr, cw)) = rows.iter().find(|(m, ..)| *m == id) {
            return Some(Pricing {
                input: *i,
                output: *o,
                cache_read: *cr,
                cache_write: *cw,
                source: ver.to_string(),
            });
        }
    }
    None
}

/// Official-docs price for a model id (normalised).
pub fn snapshot_price(model: &str) -> Option<Pricing> {
    snapshot_price_exact(&model.to_lowercase())
        .or_else(|| snapshot_price_exact(&normalize_id(model)))
}

pub fn context_for(model: &str) -> Option<u64> {
    let m = model.to_lowercase();
    let mut best: Option<(&str, u64)> = None;
    for (k, v) in CONTEXT {
        if m.contains(k) && best.is_none_or(|(b, _)| k.len() > b.len()) {
            best = Some((k, *v));
        }
    }
    best.map(|(_, v)| v)
}

// ───────────────────────── models.dev cache ─────────────────────────

pub struct Registry {
    /// model id (lowercase) → infos (one per provider).
    by_model: HashMap<String, Vec<ModelInfo>>,
}

fn cache_path() -> &'static Mutex<Option<PathBuf>> {
    static P: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

fn registry() -> &'static RwLock<Option<Registry>> {
    static R: OnceLock<RwLock<Option<Registry>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(None))
}

/// Mirror URL (`models_dev.url`): used by `refresh(None)` / background refreshes.
fn mirror_slot() -> &'static Mutex<Option<String>> {
    static M: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(None))
}

/// Point refreshes at a mirror of `api.json`; `""` clears the override.
pub fn set_mirror(url: &str) {
    let u = url.trim();
    *mirror_slot().lock().unwrap_or_else(|e| e.into_inner()) =
        if u.is_empty() { None } else { Some(u.to_string()) };
}

pub fn mirror() -> Option<String> {
    mirror_slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[derive(Default)]
struct State {
    /// When the held registry was loaded or confirmed fresh (`None` = nothing loaded yet).
    at: Option<SystemTime>,
    /// End of the failed-refresh backoff window.
    retry_after: Option<SystemTime>,
    /// The disk cache has been consulted (at most once per `set_cache`).
    disk_loaded: bool,
    /// First-discovery error (corrupt cache), surfaced exactly once.
    pending_error: Option<String>,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State::default()))
}

/// One background refresh at most, however many hot-path callers notice the stale registry.
static INFLIGHT: AtomicBool = AtomicBool::new(false);

fn fetch_lock() -> &'static Mutex<()> {
    static L: Mutex<()> = Mutex::new(());
    &L
}

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_age(at: SystemTime) -> Option<Duration> {
    SystemTime::now().duration_since(at).ok()
}

/// Remaining backoff window, or `None` when a refresh may be attempted.
fn backoff_remaining() -> Option<Duration> {
    let st = lock(state());
    let ra = st.retry_after?;
    match ra.duration_since(SystemTime::now()) {
        Ok(d) if !d.is_zero() => Some(d),
        _ => None,
    }
}

fn arm_backoff() {
    lock(state()).retry_after = Some(SystemTime::now() + RETRY_DELAY);
}

fn mark_fresh() {
    let mut st = lock(state());
    st.at = Some(SystemTime::now());
    st.retry_after = None;
}

/// Rename a rejected cache aside and drop its ETag sidecar, so the rejection is a one-time event
/// and the sidecar never vouches for a registry we no longer hold.
fn quarantine(path: &Path) {
    let mut q = path.as_os_str().to_owned();
    q.push(".corrupt");
    let _ = std::fs::rename(path, PathBuf::from(q));
    let _ = std::fs::remove_file(path.with_extension("etag"));
}

/// Read the disk cache into memory. Called once per `set_cache`; the error for a corrupt cache is
/// stored and handed to the *next* `ensure_fresh`/`refresh` call, so it never becomes a per-call
/// warning.
fn load_from_disk(path: &Path) -> Result<(), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            quarantine(path);
            return Err(format!(
                "models.dev disk cache {} could not be read ({e}); quarantined",
                path.display()
            ));
        }
    };
    let parsed = serde_json::from_str::<Value>(&text).ok().map(|v| parse_registry(&v));
    match parsed {
        Some(reg) if !reg.by_model.is_empty() => {
            // Anchor freshness to the file's age: a cache written 10h ago is already stale.
            let age = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok());
            *registry().write().unwrap_or_else(|e| e.into_inner()) = Some(reg);
            lock(state()).at = Some(SystemTime::now().checked_sub(age.unwrap_or_default()).unwrap_or_else(SystemTime::now));
            Ok(())
        }
        _ => {
            quarantine(path);
            Err(format!(
                "models.dev disk cache {} is corrupt or empty; quarantined as {}.corrupt (will refetch from the network)",
                path.display(),
                path.display()
            ))
        }
    }
}

/// Read the disk cache into memory, at most once per `set_cache`. A corrupt file is quarantined
/// and the error is parked in `pending_error` so the next `ensure_fresh`/`refresh` reports it
/// exactly once.
fn load_once() {
    let first = {
        let mut st = lock(state());
        if st.disk_loaded {
            false
        } else {
            st.disk_loaded = true;
            true
        }
    };
    if !first {
        return;
    }
    if let Some(p) = cache_path().lock().unwrap_or_else(|e| e.into_inner()).clone() {
        if let Err(e) = load_from_disk(&p) {
            lock(state()).pending_error = Some(e);
        }
    }
}

fn disk_load() -> Result<(), String> {
    load_once();
    match lock(state()).pending_error.take() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Serve the held registry immediately; start ONE background refresh when it is older than
/// [`CACHE_TTL`]. Hot paths never block and never touch the network. Returns the one-time error
/// for a corrupt disk cache (which was quarantined, never served as an empty registry).
pub fn ensure_fresh() -> Result<(), String> {
    disk_load()?;
    let stale = {
        let st = lock(state());
        match st.at {
            // Nothing held: cold start belongs to `refresh`/`ark models refresh`, not to a hot path.
            None => false,
            Some(at) => now_age(at).is_some_and(|age| age >= CACHE_TTL),
        }
    };
    if stale {
        spawn_background_refresh();
    }
    Ok(())
}

fn spawn_background_refresh() {
    if backoff_remaining().is_some() {
        return;
    }
    if INFLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("models-dev-refresh".into())
        .spawn(|| {
            let _ = refresh_inner(None);
            INFLIGHT.store(false, Ordering::SeqCst);
        });
    if spawned.is_err() {
        // Thread/fd exhaustion: never leave refresh disabled for the rest of the process.
        INFLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Use (and load) the models.dev snapshot at `path`.
pub fn set_cache(path: PathBuf) {
    {
        let mut st = lock(state());
        *st = State::default();
    }
    *cache_path().lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
    // Eager load (as before): `ark models status` must see metadata without a network round trip.
    // A corrupt file is quarantined here; the error surfaces on the next `ensure_fresh`/`refresh`.
    load_once();
}

pub fn parse_registry(v: &Value) -> Registry {
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default()
    };
    let mut by_model: HashMap<String, Vec<ModelInfo>> = HashMap::new();
    for (pid, p) in v.as_object().into_iter().flatten() {
        for (mid, m) in p["models"].as_object().into_iter().flatten() {
            let cost = &m["cost"];
            let pricing = cost["input"].as_f64().map(|i| Pricing {
                input: i,
                output: cost["output"].as_f64().unwrap_or(0.0),
                cache_read: cost["cache_read"].as_f64(),
                cache_write: cost["cache_write"].as_f64(),
                source: "models.dev".into(),
            });
            let input_modalities = strings(&m["modalities"]["input"]);
            let output_modalities = strings(&m["modalities"]["output"]);
            let vision = m["attachment"].as_bool().unwrap_or(false)
                || input_modalities.iter().any(|x| x == "image");
            let info = ModelInfo {
                id: mid.clone(),
                provider: pid.clone(),
                name: m["name"].as_str().unwrap_or(mid).to_string(),
                context: m["limit"]["context"].as_u64().unwrap_or(0),
                max_output: m["limit"]["output"]
                    .as_u64()
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as u32,
                reasoning: m["reasoning"].as_bool().unwrap_or(false),
                tool_call: m["tool_call"].as_bool().unwrap_or(false),
                vision,
                input_modalities,
                output_modalities,
                structured_output: m["structured_output"].as_bool().unwrap_or(false),
                open_weights: m["open_weights"].as_bool().unwrap_or(false),
                knowledge_cutoff: m["knowledge"].as_str().unwrap_or("").to_string(),
                release_date: m["release_date"].as_str().unwrap_or("").to_string(),
                status: m["status"].as_str().unwrap_or("").to_string(),
                pricing,
            };
            by_model.entry(mid.to_lowercase()).or_default().push(info);
        }
    }
    Registry { by_model }
}

/// ark provider id → models.dev provider id (Hermes `PROVIDER_TO_MODELS_DEV`, restricted to ids
/// ark presets actually use; unknown ids are their own models.dev slug).
const PROVIDER_MAP: &[(&str, &str)] = &[
    ("openai", "openai"),
    ("openai-api", "openai"),
    ("openai-responses", "openai"),
    ("openai-chat", "openai"),
    ("openai-codex", "openai"),
    ("azure-openai", "openai"),
    ("azure-openai-entra", "openai"),
    ("anthropic", "anthropic"),
    ("gemini", "google"),
    ("google", "google"),
    ("google-vertex", "google"),
    ("vertex", "google"),
    ("anthropic-vertex", "google-vertex-anthropic"),
    ("bedrock", "amazon-bedrock"),
    ("bedrock-mantle", "amazon-bedrock"),
    ("dashscope", "alibaba"),
    ("dashscope-cn", "alibaba"),
    ("qwen", "alibaba"),
    ("alibaba", "alibaba"),
    ("alibaba-coding-plan", "alibaba"),
    ("alibaba-coding-plan-cn", "alibaba"),
    ("alibaba-token-plan", "alibaba"),
    ("alibaba-token-plan-cn", "alibaba"),
    ("moonshot", "moonshotai"),
    ("moonshot-cn", "moonshotai-cn"),
    // Kimi's coding endpoints are the same catalogue models.dev keys as `kimi-for-coding`.
    ("kimi", "kimi-for-coding"),
    ("kimi-coding", "kimi-for-coding"),
    ("kimi-coding-cn", "kimi-for-coding"),
    ("zai", "zai"),
    ("zai-coding", "zai"),
    ("zhipu", "zhipuai"),
    ("minimax", "minimax"),
    ("minimax-anthropic", "minimax"),
    ("minimax-oauth", "minimax"),
    ("minimax-oauth-cn", "minimax"),
    ("minimax-cn", "minimax-cn"),
    ("deepseek", "deepseek"),
    ("stepfun", "stepfun"),
    ("stepfun-plan", "stepfun"),
    ("xai", "xai"),
    ("xai-responses", "xai"),
    ("xai-oauth", "xai"),
    ("xiaomi", "xiaomi"),
    ("xiaomi-token-plan", "xiaomi"),
    ("github-copilot", "github-copilot"),
    ("copilot", "github-copilot"),
    ("copilot-proxy", "github-copilot"),
    ("ai-gateway", "vercel"),
    ("kilocode", "kilo"),
    ("opencode-zen", "opencode"),
    ("opencode-go", "opencode-go"),
    ("novita", "novita-ai"),
    ("together", "togetherai"),
    ("fireworks", "fireworks-ai"),
    ("groq", "groq"),
    ("mistral", "mistral"),
    ("cohere", "cohere"),
    ("perplexity", "perplexity"),
    ("cerebras", "cerebras"),
    ("deepinfra", "deepinfra"),
    ("huggingface", "huggingface"),
    ("nvidia", "nvidia"),
    ("openrouter", "openrouter"),
    ("ollama-cloud", "ollama-cloud"),
    ("meta-ai", "meta"),
    ("meta", "meta"),
];

/// ark provider id → models.dev provider id.
pub fn models_dev_provider(id: &str) -> &str {
    let id = id.trim();
    PROVIDER_MAP
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(id))
        .map(|(_, v)| *v)
        .unwrap_or(id)
}

/// Reverse lookup: the ark provider ids that resolve to a models.dev id (Hermes
/// `_models_dev_to_hermes_ids`; many-to-one).
pub fn ark_providers_for(models_dev_id: &str) -> Vec<&'static str> {
    PROVIDER_MAP
        .iter()
        .filter(|(_, v)| v.eq_ignore_ascii_case(models_dev_id))
        .map(|(k, _)| *k)
        .collect()
}

/// The models.dev registry entry for a model (preferring `provider`'s), without the
/// snapshot/heuristic fallbacks `lookup_for` applies. `None` when the registry has no such model.
pub fn registry_entry(provider: Option<&str>, model: &str) -> Option<ModelInfo> {
    let key = model.trim().to_lowercase();
    let short = key
        .rsplit_once('/')
        .map(|(_, m)| m.to_string())
        .unwrap_or_else(|| key.clone());
    let reg = registry().read().unwrap_or_else(|e| e.into_inner());
    let reg = reg.as_ref()?;
    let c = reg.by_model.get(&key).or_else(|| reg.by_model.get(&short))?;
    let want = provider.map(models_dev_provider);
    want.and_then(|w| c.iter().find(|i| i.provider == w))
        .or_else(|| c.first())
        .cloned()
}

/// Context window from the models.dev registry only (0/absent entries are `None`).
pub fn registry_context(provider: Option<&str>, model: &str) -> Option<u64> {
    registry_entry(provider, model).map(|i| i.context).filter(|c| *c > 0)
}

/// Metadata for a model: models.dev (preferring `provider`'s entry), then snapshots.
pub fn lookup_for(provider: Option<&str>, model: &str) -> Option<ModelInfo> {
    // Hot path: serve the held registry, kick one background revalidation when it is stale.
    let _ = ensure_fresh();
    if let Some(i) = registry_entry(provider, model) {
        return Some(i);
    }
    let price = snapshot_price(model);
    let ctx = context_for(model);
    if price.is_none() && ctx.is_none() {
        return None;
    }
    let h = crate::heuristic_caps(model);
    Some(ModelInfo {
        id: model.to_string(),
        provider: provider.unwrap_or("").to_string(),
        name: model.to_string(),
        context: ctx.unwrap_or(h.context_window),
        max_output: h.max_output,
        reasoning: false,
        tool_call: true,
        vision: h.vision,
        pricing: price,
        ..Default::default()
    })
}

pub fn lookup(model: &str) -> Option<ModelInfo> {
    lookup_for(None, model)
}

/// Price for `provider/model` (USD per million tokens).
pub fn price_for(provider: &str, model: &str) -> Option<Pricing> {
    lookup_for(Some(provider), model).and_then(|m| m.pricing)
}

/// All models.dev entries for a provider (pickers, `ark models list --all`).
pub fn models_of(provider: &str) -> Vec<ModelInfo> {
    let _ = ensure_fresh();
    let want = models_dev_provider(provider);
    let mut v: Vec<ModelInfo> = registry()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|r| {
            r.by_model
                .values()
                .flatten()
                .filter(|i| i.provider == want)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v
}

fn registry_len() -> usize {
    registry()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|r| r.by_model.values().map(Vec::len).sum())
        .unwrap_or(0)
}

/// Download models.dev into the cache (ETag-conditional). Returns (models, changed).
///
/// Honours the process-wide failure backoff: inside the 5-minute window this returns an error
/// without touching the network. Inside, `url = None` falls back to the [`mirror`] and then
/// [`MODELS_DEV_URL`].
pub fn refresh(url: Option<&str>) -> Result<(usize, bool), String> {
    // Hydrate the disk cache once, so a conditional GET can be re-confirmed by a 304 and a corrupt
    // cache is quarantined before we write over it. A pending corrupt-cache error stays parked for
    // `ensure_fresh` (the surface that renders it), because this call is about to heal the file.
    load_once();
    refresh_inner(url)
}

fn refresh_inner(url: Option<&str>) -> Result<(usize, bool), String> {
    ark_net::http::ensure_online("the models.dev price table refresh")?;
    if let Some(d) = backoff_remaining() {
        return Err(format!(
            "models.dev refresh failed recently; retrying in {}s without a request",
            d.as_secs().max(1)
        ));
    }
    // Singleflight: one fetch at a time, foreground or background.
    let _fetch = lock(fetch_lock());
    // Re-check under the lock: another caller may have armed it while we waited.
    if let Some(d) = backoff_remaining() {
        return Err(format!(
            "models.dev refresh failed recently; retrying in {}s without a request",
            d.as_secs().max(1)
        ));
    }
    let path = cache_path()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("no models.dev cache path configured")?;
    let mirror = mirror();
    let url = url.or(mirror.as_deref()).unwrap_or(MODELS_DEV_URL);
    let etag_path = path.with_extension("etag");
    let mut req = crate::net::agent(std::time::Duration::from_secs(60), url)
        .get(url)
        .header("accept", "application/json");
    if let Ok(e) = std::fs::read_to_string(&etag_path) {
        // Only revalidate when a servable registry is held: a 304 without data leaves us empty.
        if path.exists() && registry().read().unwrap_or_else(|e| e.into_inner()).is_some() {
            req = req.header("if-none-match", e.trim());
        }
    }
    let out = fetch_and_store(req, url, &path, &etag_path);
    if out.is_err() {
        arm_backoff();
    }
    out
}

fn fetch_and_store(
    req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    url: &str,
    path: &Path,
    etag_path: &Path,
) -> Result<(usize, bool), String> {
    use std::io::Read;
    let resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    if status == 304 {
        if registry().read().unwrap_or_else(|e| e.into_inner()).is_none() {
            // Should be unreachable (conditional GETs require a servable registry) but it used to
            // cause a permanent empty-registry loop: drop the sidecar so the next fetch is
            // unconditional, and arm the backoff rather than declaring `{}` fresh.
            let _ = std::fs::remove_file(etag_path);
            return Err("models.dev returned 304 but no cached registry is held; cleared the ETag sidecar".into());
        }
        mark_fresh();
        return Ok((registry_len(), false));
    }
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let mut body = String::new();
    resp.into_body()
        .into_reader()
        .take(64 << 20)
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    let v: Value =
        serde_json::from_str(&body).map_err(|e| format!("models.dev: not JSON ({e})"))?;
    let reg = parse_registry(&v);
    if reg.by_model.is_empty() {
        // Never replace a good cache with an empty registry.
        return Err("models.dev returned no models; keeping the cached copy".into());
    }
    let n = reg.by_model.values().map(Vec::len).sum();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &body)
        .and_then(|_| std::fs::rename(&tmp, path))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(e) = etag {
        let _ = std::fs::write(etag_path, e);
    }
    *registry().write().unwrap_or_else(|e| e.into_inner()) = Some(reg);
    mark_fresh();
    Ok((n, true))
}

/// Cost of one call in USD.
pub fn cost(p: &Pricing, input: u64, output: u64, cache_read: u64, cache_write: u64) -> f64 {
    (input as f64 * p.input
        + output as f64 * p.output
        + cache_read as f64 * p.cache_read.unwrap_or(p.input * 0.1)
        + cache_write as f64 * p.cache_write.unwrap_or(p.input * 1.25))
        / 1e6
}

#[cfg(test)]
pub(crate) fn test_lock() -> MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reset every process-wide models.dev slot (tests only; hold [`test_lock`]).
#[cfg(test)]
pub(crate) fn reset_for_test() {
    *lock(state()) = State::default();
    *registry().write().unwrap_or_else(|e| e.into_inner()) = None;
    *lock(mirror_slot()) = None;
    INFLIGHT.store(false, Ordering::SeqCst);
}

/// Pretend the held registry was loaded `d` ago (tests only; hold [`test_lock`]).
#[cfg(test)]
pub(crate) fn age_for_test(d: Duration) {
    lock(state()).at = Some(SystemTime::now().checked_sub(d).unwrap_or_else(SystemTime::now));
}

/// Install a registry in memory without touching the disk cache (tests only).
#[cfg(test)]
pub(crate) fn set_registry_for_test(v: &Value) {
    *registry().write().unwrap_or_else(|e| e.into_inner()) = Some(parse_registry(v));
    let mut st = lock(state());
    // Pretend the disk cache was already consulted, so `ensure_fresh` cannot overwrite this.
    st.disk_loaded = true;
    st.at = Some(SystemTime::now());
    st.pending_error = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Fresh temp dir per test (never `/tmp` by hand: `std::env::temp_dir()`).
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-mdev-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Local fake models.dev. `respond(path) -> (status, body)`; every request is counted as soon
    /// as it is parsed, after an optional `delay` (to keep a refresh "in flight").
    fn fake_mirror(
        delay: Duration,
        respond: impl Fn(&str) -> (u16, String) + Send + 'static,
    ) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                let _ = r.read_line(&mut line);
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(delay);
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = respond(&path);
                let code = if status == 200 { "200 OK" } else { "500 Internal Server Error" };
                let _ = write!(
                    s,
                    "HTTP/1.1 {code}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (base, hits)
    }

    fn one_model(id: &str, ctx: u64) -> String {
        let mut models = serde_json::Map::new();
        models.insert(id.into(), serde_json::json!({"limit": {"context": ctx, "output": 1024}}));
        serde_json::json!({"zz-mirror": {"models": models}}).to_string()
    }

    fn wait_for(what: &str, f: impl Fn() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn snapshot_prices_and_normalisation() {
        assert_eq!(normalize_id("anthropic/claude-opus-4.8"), "claude-opus-4-8");
        assert_eq!(
            normalize_id("claude-sonnet-4-5-20250929"),
            "claude-sonnet-4-5"
        );
        assert_eq!(
            normalize_id("us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
            "anthropic.claude-sonnet-4-5"
        );
        let p = snapshot_price("claude-opus-5-5").unwrap();
        assert_eq!((p.input, p.output, p.cache_read), (4.0, 20.0, Some(0.2)));
        assert_eq!(snapshot_price("openai/gpt-4o-mini").unwrap().input, 0.15);
        assert!(
            snapshot_price("claude-3-5-sonnet-20241022").is_some(),
            "dated id kept when listed"
        );
        assert!(snapshot_price("totally-unknown").is_none());
        assert_eq!(fast_pricing("claude-opus-5-5").unwrap().input, 8.0);
    }

    #[test]
    fn context_longest_key_wins() {
        assert_eq!(context_for("glm-5.3-flashx"), Some(1_048_576));
        assert_eq!(context_for("glm-5.3-flash"), Some(1_310_720));
        assert_eq!(context_for("deepseek-flash"), Some(1_000_000));
        assert_eq!(context_for("deepseek-coder"), Some(128_000));
        assert_eq!(context_for("gpt-5.4-mini"), Some(400_000));
        assert_eq!(context_for("nope"), None);
    }

    #[test]
    fn models_dev_registry_parsing_and_cost() {
        let v = serde_json::json!({"anthropic": {"models": {"claude-x": {"name": "Claude X", "reasoning": true, "tool_call": true, "attachment": true, "cost": {"input": 3, "output": 15, "cache_read": 0.3}, "limit": {"context": 200000, "output": 64000}}}}, "openrouter": {"models": {"claude-x": {"cost": {"input": 3.3, "output": 16}, "limit": {"context": 200000}}}}});
        let r = parse_registry(&v);
        let c = &r.by_model["claude-x"];
        assert_eq!(c.len(), 2);
        let a = c.iter().find(|i| i.provider == "anthropic").unwrap();
        assert!(a.reasoning && a.vision);
        assert_eq!(a.caps().context_window, 200_000);
        let p = a.pricing.clone().unwrap();
        assert!((cost(&p, 1_000_000, 100_000, 0, 0) - 4.5).abs() < 1e-9);
    }

    #[test]
    fn refresh_writes_cache_and_honours_etag() {
        let _g = test_lock();
        reset_for_test();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/api.json", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for (i, s) in l.incoming().enumerate() {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut inm = false;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    inm |= h.to_lowercase().starts_with("if-none-match: \"v1\"");
                }
                if i > 0 && inm {
                    let _ = write!(s, "HTTP/1.1 304 Not Modified\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                } else {
                    let b = r#"{"zz-test":{"models":{"zz-model-1":{"cost":{"input":1,"output":2},"limit":{"context":4096,"output":512}}}}}"#;
                    let _ = write!(s, "HTTP/1.1 200 OK\r\netag: \"v1\"\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}", b.len());
                }
            }
        });
        let dir = std::env::temp_dir().join(format!("ark-mdev-{}", std::process::id()));
        set_cache(dir.join("models-dev.json"));
        assert_eq!(refresh(Some(&url)).unwrap(), (1, true));
        assert!(!refresh(Some(&url)).unwrap().1, "304 keeps the cache");
        assert_eq!(
            lookup_for(Some("zz-test"), "zz-model-1").unwrap().context,
            4096
        );
        assert_eq!(price_for("zz-test", "zz-model-1").unwrap().output, 2.0);
        assert_eq!(models_of("zz-test").len(), 1);
    }

    #[test]
    fn mirror_url_is_used_by_refresh_and_explicit_url_wins() {
        let _g = test_lock();
        reset_for_test();
        let (base, hits) = fake_mirror(Duration::ZERO, |path: &str| {
            let ctx = if path.contains("mirror") { 2048 } else { 8192 };
            (200, one_model(&format!("zz-m-{ctx}"), ctx))
        });
        let dir = tmp("mirror");
        set_cache(dir.join("models-dev.json"));
        set_mirror(&format!("{base}/mirror.json"));
        assert_eq!(mirror().as_deref(), Some(format!("{base}/mirror.json").as_str()));
        assert_eq!(refresh(None).unwrap(), (1, true), "refresh(None) honours the mirror");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(lookup_for(Some("zz-mirror"), "zz-m-2048").unwrap().context, 2048);
        // An explicit URL still wins over the mirror.
        assert_eq!(refresh(Some(&format!("{base}/explicit.json"))).unwrap(), (1, true));
        assert_eq!(lookup_for(Some("zz-mirror"), "zz-m-8192").unwrap().context, 8192);
        // Clearing the mirror restores the built-in default (no request here: backoff-free but offline).
        set_mirror("");
        assert_eq!(mirror(), None);
    }

    #[test]
    fn stale_registry_is_served_while_one_background_refresh_runs() {
        let _g = test_lock();
        reset_for_test();
        let (base, hits) = fake_mirror(Duration::from_millis(300), |_| {
            (200, one_model("zz-stale-2", 16384))
        });
        let dir = tmp("stale");
        let path = dir.join("models-dev.json");
        std::fs::write(&path, one_model("zz-stale-1", 4096)).unwrap();
        set_cache(path.clone());
        assert_eq!(lookup_for(Some("zz-mirror"), "zz-stale-1").unwrap().context, 4096);
        age_for_test(CACHE_TTL + Duration::from_secs(1));
        set_mirror(&format!("{base}/api.json"));

        // Hot path: the stale copy is served immediately, never a blocking fetch.
        for _ in 0..8 {
            let t = std::time::Instant::now();
            ensure_fresh().unwrap();
            assert!(t.elapsed() < Duration::from_millis(250), "ensure_fresh must not block");
        }
        assert_eq!(lookup_for(None, "zz-stale-1").unwrap().context, 4096, "stale data is served");
        wait_for("the background refresh to arrive", || hits.load(Ordering::SeqCst) >= 1);
        // Still inside the 300 ms response window: only ONE worker may be running.
        for _ in 0..8 {
            ensure_fresh().unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly one refresh in flight");
        wait_for("the refreshed registry", || lookup_for(None, "zz-stale-2").is_some());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no second refresh after it went fresh");
        // The new registry was committed to disk too.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("zz-stale-2"));
        // Fresh again: no further refresh.
        ensure_fresh().unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_refresh_arms_backoff_without_second_request() {
        let _g = test_lock();
        reset_for_test();
        let (base, hits) = fake_mirror(Duration::ZERO, |_| (500, "nope".into()));
        set_cache(tmp("backoff").join("models-dev.json"));
        let e = refresh(Some(&format!("{base}/api.json"))).unwrap_err();
        assert!(e.contains("500"), "{e}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let e2 = refresh(Some(&format!("{base}/api.json"))).unwrap_err();
        assert!(e2.contains("failed recently"), "{e2}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "backoff window makes no request");
        // A stale registry does not spawn a worker either while the backoff is armed.
        age_for_test(CACHE_TTL + Duration::from_secs(1));
        ensure_fresh().unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // `set_cache` (a fresh process/session) clears the backoff.
        set_cache(tmp("backoff2").join("models-dev.json"));
        assert!(backoff_remaining().is_none());
    }

    #[test]
    fn corrupt_cache_is_quarantined_not_served_empty() {
        let _g = test_lock();
        reset_for_test();
        let dir = tmp("corrupt");
        let path = dir.join("models-dev.json");
        std::fs::write(&path, "{\"anthropic\": {\"models\": ").unwrap();
        set_cache(path.clone());
        let e = ensure_fresh().unwrap_err();
        assert!(e.contains("corrupt"), "{e}");
        let q = PathBuf::from(format!("{}.corrupt", path.display()));
        assert!(q.exists(), "renamed aside, upstream behaviour");
        assert!(!path.exists());
        assert!(registry_entry(None, "claude-x").is_none(), "never served as a registry");
        assert!(models_of("anthropic").is_empty());
        assert!(ensure_fresh().is_ok(), "quarantine is a one-time event");
        assert!(ensure_fresh().is_ok(), "and never warns again");

        // An empty JSON object is just as unusable as invalid JSON.
        let path2 = dir.join("empty.json");
        std::fs::write(&path2, "{}").unwrap();
        set_cache(path2.clone());
        assert!(ensure_fresh().unwrap_err().contains("corrupt or empty"));
        assert!(PathBuf::from(format!("{}.corrupt", path2.display())).exists());
        assert!(!path2.exists());
    }

    #[test]
    fn metadata_richness_and_capabilities() {
        let v = serde_json::json!({"anthropic": {"models": {
            "zz-rich": {
                "name": "Rich", "reasoning": true, "tool_call": true,
                "structured_output": true, "open_weights": true,
                "modalities": {"input": ["text", "image", "pdf"], "output": ["text"]},
                "knowledge": "2026-01-15", "release_date": "2026-06-01", "status": "beta",
                "limit": {"context": 1000000, "output": 128000}
            },
            "zz-plain": {"limit": {"context": 1000}}
        }}});
        let r = parse_registry(&v);
        let i = &r.by_model["zz-rich"][0];
        assert_eq!(i.input_modalities, vec!["text", "image", "pdf"]);
        assert_eq!(i.output_modalities, vec!["text"]);
        assert!(i.structured_output && i.open_weights);
        assert_eq!(i.knowledge_cutoff, "2026-01-15");
        assert_eq!(i.release_date, "2026-06-01");
        assert_eq!(i.status, "beta");
        assert!(!i.is_deprecated());
        assert!(i.supports_vision() && i.supports_pdf() && !i.supports_audio_input());
        assert_eq!(
            i.format_capabilities(),
            "reasoning, tools, vision, PDF, structured output, open weights"
        );
        assert!(i.caps().vision, "modalities feed ModelCaps::vision");
        assert!(!i.has_cost_data(), "no cost block");

        let p = &r.by_model["zz-plain"][0];
        assert!(p.input_modalities.is_empty() && p.status.is_empty());
        assert_eq!(p.format_capabilities(), "basic");
        assert!(!p.supports_vision() && !p.supports_pdf());
    }

    #[test]
    fn provider_mapping_matches_upstream_table() {
        assert_eq!(models_dev_provider("novita"), "novita-ai");
        assert_eq!(models_dev_provider("kimi"), "kimi-for-coding");
        assert_eq!(models_dev_provider("kimi-coding"), "kimi-for-coding");
        assert_eq!(models_dev_provider("kimi-coding-cn"), "kimi-for-coding");
        assert_eq!(models_dev_provider("copilot"), "github-copilot");
        assert_eq!(models_dev_provider("github-copilot"), "github-copilot");
        assert_eq!(models_dev_provider("ai-gateway"), "vercel");
        assert_eq!(models_dev_provider("kilocode"), "kilo");
        assert_eq!(models_dev_provider("opencode-zen"), "opencode");
        assert_eq!(models_dev_provider("opencode-go"), "opencode-go");
        assert_eq!(models_dev_provider("qwen"), "alibaba");
        assert_eq!(models_dev_provider("minimax-cn"), "minimax-cn");
        assert_eq!(models_dev_provider("minimax-oauth"), "minimax");
        assert_eq!(models_dev_provider("meta-ai"), "meta");
        assert_eq!(models_dev_provider("meta"), "meta");
        assert_eq!(models_dev_provider("ollama-cloud"), "ollama-cloud");
        assert_eq!(models_dev_provider("xai-oauth"), "xai");
        assert_eq!(models_dev_provider("moonshot"), "moonshotai");
        assert_eq!(models_dev_provider("some-custom"), "some-custom");
        // Reverse: many-to-one.
        assert!(ark_providers_for("kimi-for-coding").contains(&"kimi"));
        assert!(ark_providers_for("meta").contains(&"meta-ai"));
        assert!(ark_providers_for("nope-nope").is_empty());
    }

    #[test]
    fn registry_context_prefers_the_asked_provider() {
        let _g = test_lock();
        reset_for_test();
        set_registry_for_test(&serde_json::json!({
            "anthropic": {"models": {"zz-ctx": {"limit": {"context": 200000}}}},
            "openrouter": {"models": {"zz-ctx": {"limit": {"context": 100000}}}}
        }));
        assert_eq!(registry_context(Some("anthropic"), "zz-ctx"), Some(200_000));
        assert_eq!(registry_context(Some("openrouter"), "zz-ctx"), Some(100_000));
        // Unknown provider → the registry-wide best match, not a miss.
        assert_eq!(registry_context(Some("bedrock"), "zz-ctx"), Some(200_000));
        assert_eq!(registry_context(None, "zz-ctx"), Some(200_000));
        assert_eq!(registry_context(None, "zz-absent"), None);
        assert_eq!(lookup_for(Some("openrouter"), "zz-ctx").unwrap().context, 100_000);
        reset_for_test();
    }
}
