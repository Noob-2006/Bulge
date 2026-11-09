//! Per-task auxiliary model routing, health and fallback.
//!
//! Hermes resolves every auxiliary call through an `auxiliary.<task>` config block
//! (`agent/auxiliary_task_config.py`): the *route keys* (`provider`, `model`, `base_url`,
//! `api_key`, `reasoning_effort`) travel as one unit — a task that pins a provider never
//! inherits another vendor's endpoint or key — plus non-route policy (`timeout`,
//! `extra_body`, `fallback` chain). Endpoint health is tracked per provider
//! (`agent/auxiliary_health.py`): a lane that failed with a capacity error (payment/quota,
//! rate limit, connection, invalid response) is held out for a while and the next candidate
//! in the task's chain serves the call; auth errors are excluded — they have their own
//! refresh-then-quarantine path in [`crate::auth`].
//!
//! Config shape (TOML):
//!
//! ```toml
//! [auxiliary.compression]
//! provider = "groq"          # "auto" (default) = follow `[model] aux` / default
//! model = "llama-3.3-70b"
//! reasoning_effort = "low"
//! timeout = 60
//! fallback = ["openai/gpt-5.4-mini", "ollama/qwen3"]
//! ```

use seagent_core::ProviderErrorKind;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Held out this long after a payment/quota, auth-shaped-capacity or unknown failure.
/// (Hermes keeps the long default TTL for payment/quota depletion and dead credentials.)
pub const LONG_HOLD_SECS: u64 = 6 * 3_600;
/// Rate limits, dropped connections and garbled bodies clear quickly.
pub const SHORT_HOLD_SECS: u64 = 60;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Route {
    /// Provider id (`auto`/empty = follow the aux/default model).
    pub provider: String,
    pub model: String,
    /// Explicit endpoint for this task only (custom providers).
    pub base_url: String,
    /// Env var holding this task's key (never the value).
    pub api_key_env: String,
    pub reasoning_effort: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TaskConfig {
    pub route: Route,
    /// `provider/model` candidates tried after the primary.
    pub fallback: Vec<String>,
    pub timeout_secs: Option<u64>,
    /// Provider-specific request body merged into the call.
    pub extra_body: toml::Table,
    /// `false` disables model-backed work for this task (e.g. `title_generation`).
    pub enabled: bool,
}

fn s(t: &toml::Table, k: &str) -> String {
    t.get(k)
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// Parse one `[auxiliary.<task>]` block. Unknown keys are ignored (the table is a passthrough
/// from the kernel config, and plugins may add their own policy keys).
pub fn parse_task(t: &toml::Table) -> TaskConfig {
    let mut route = Route {
        provider: s(t, "provider"),
        model: s(t, "model"),
        base_url: s(t, "base_url"),
        api_key_env: {
            let a = s(t, "api_key_env");
            if a.is_empty() {
                s(t, "key_env")
            } else {
                a
            }
        },
        reasoning_effort: s(t, "reasoning_effort"),
    };
    // `provider: auto` plus empty route fields means "follow the main selection".
    if route.provider.eq_ignore_ascii_case("auto") {
        route = Route { provider: String::new(), ..route };
    }
    let fallback = t
        .get("fallback")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(toml::Value::as_str)
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let extra_body = t
        .get("extra_body")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    TaskConfig {
        enabled: t.get("enabled").and_then(toml::Value::as_bool).unwrap_or(true),
        timeout_secs: t.get("timeout").and_then(|v| v.as_integer()).map(|x| x.max(1) as u64),
        route,
        fallback,
        extra_body,
    }
}

/// Upstream task names that seagent calls something else (`[auxiliary.compression]` also configures
/// seagent's `compaction`; Hermes' sampling ladder is `auxiliary.mcp`).
pub fn upstream_name(task: &str) -> &str {
    match task {
        "compaction" => "compression",
        "sampling" => "mcp",
        "background_review" => "review",
        other => other,
    }
}

/// The config block for `task`, accepting either seagent's name or the upstream one.
pub fn config_for<'a>(tasks: &'a BTreeMap<String, toml::Table>, task: &str) -> Option<&'a toml::Table> {
    tasks
        .get(task)
        .or_else(|| tasks.get(upstream_name(task)))
}

/// Route a task pins, when it pins one (`None` = follow `aux`/default).
pub fn pinned_model(tasks: &BTreeMap<String, toml::Table>, task: &str, aux: &str, default: &str) -> Route {
    let Some(t) = config_for(tasks, task) else {
        return Route { provider: String::new(), model: String::new(), ..Default::default() };
    };
    let c = parse_task(t);
    let _ = (aux, default);
    c.route
}

/// Ordered `provider/model` candidates for a task: the pinned route (or `aux`, then the default
/// model), the task's `fallback` chain, then the main `[model] fallback` chain. Providers that
/// are currently held out (see [`mark_down`]) are skipped, unless every candidate is down.
pub fn plan(
    tasks: &BTreeMap<String, toml::Table>,
    task: &str,
    aux: &str,
    default: &str,
    main_fallback: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(t) = config_for(tasks, task) {
        let c = parse_task(t);
        let r = &c.route;
        if !r.model.is_empty() || !r.provider.is_empty() {
            let m = if r.model.contains('/') || r.provider.is_empty() {
                r.model.clone()
            } else {
                format!("{}/{}", r.provider, r.model)
            };
            if !m.is_empty() {
                out.push(m);
            }
        }
        out.extend(c.fallback.iter().cloned());
    }
    for m in [aux, default] {
        if !m.trim().is_empty() {
            out.push(m.trim().to_string());
        }
    }
    out.extend(main_fallback.iter().filter(|m| !m.trim().is_empty()).cloned());
    // Task-level `model` without a provider ("claude-haiku-4-5") follows the aux model's provider.
    for i in 0..out.len() {
        if !out[i].contains('/') {
            if let Some((p, _)) = out.iter().find(|m| m.contains('/')).and_then(|m| m.split_once('/')) {
                out[i] = format!("{p}/{}", out[i]);
            }
        }
    }
    let mut seen = Vec::new();
    out.retain(|m| {
        if seen.contains(m) {
            return false;
        }
        seen.push(m.clone());
        true
    });
    out
}

/// The model a task should use right now: the first candidate whose provider is not held out,
/// else the primary (a doubly-down fleet must still try something).
pub fn pick(plan: &[String]) -> Option<String> {
    plan.iter()
        .find(|m| m.split_once('/').is_none_or(|(p, _)| !down(p)))
        .cloned()
        .or_else(|| plan.first().cloned())
}

// ───────────────────────── endpoint health ─────────────────────────

fn holds() -> &'static Mutex<HashMap<String, u64>> {
    static H: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> u64 {
    crate::ratelimit::now_ms()
}

/// Labels Hermes puts on a failed auxiliary lane (`_FALLBACK_REASONS`).
///
/// seagent folds payment/quota responses (402, 429 `insufficient_quota`) into
/// [`ProviderErrorKind::Auth`] — another provider may still work — so the payment class is
/// recognised from the message, exactly like Hermes distinguishes it from a dead credential
/// (which keeps its own refresh-then-quarantine path and never benches the whole lane).
pub fn classify(err: &seagent_core::ProviderError) -> Option<&'static str> {
    let m = err.message.to_lowercase();
    let payment = m.contains("insufficient_quota")
        || m.contains("out of credit")
        || m.contains("no credits")
        || m.contains("insufficient balance")
        || m.contains("billing")
        || m.contains("payment required")
        || err.status == Some(402);
    match err.kind {
        _ if payment => Some("payment/quota"),
        ProviderErrorKind::RateLimited { .. } => Some("rate limit"),
        ProviderErrorKind::Network | ProviderErrorKind::Timeout => Some("connection error"),
        ProviderErrorKind::Protocol => Some("invalid provider response"),
        // A 400 request-shape error is the caller's bug: never benched, always propagated;
        // a real 401/403 is a credential problem with its own path.
        _ => None,
    }
}

/// How long a lane stays out for `reason` (None = the long default).
pub fn hold_secs(reason: &str) -> u64 {
    match reason {
        "rate limit" | "connection error" | "invalid provider response" => SHORT_HOLD_SECS,
        _ => LONG_HOLD_SECS,
    }
}

/// Hold `provider` out of auxiliary routing until `until_ms`.
pub fn hold_until(provider: &str, reason: &str, now: u64) -> u64 {
    let until = now + hold_secs(reason) * 1000;
    holds().lock().unwrap().insert(provider.to_string(), until);
    until
}

/// Record a failed auxiliary call for `provider`.
pub fn mark_down(provider: &str, reason: &str) -> u64 {
    hold_until(provider, reason, now_ms())
}

/// When `provider` may be used again (`None` = now).
pub fn down_until(provider: &str) -> Option<u64> {
    let mut h = holds().lock().unwrap();
    match h.get(provider).copied() {
        Some(t) if t > now_ms() => Some(t),
        Some(_) => {
            h.remove(provider);
            None
        }
        None => None,
    }
}

/// Whether `provider` is currently held out of auxiliary routing.
pub fn down(provider: &str) -> bool {
    down_until(provider).is_some()
}

/// A provider answered: forget its hold.
pub fn clear(provider: &str) {
    holds().lock().unwrap().remove(provider);
}

/// Hold `provider` out when `err` is a capacity failure (auth errors are excluded: they have
/// their own refresh path). Returns the reason label when the lane was benched.
pub fn observe_error(provider: &str, err: &seagent_core::ProviderError) -> Option<&'static str> {
    let reason = classify(err)?;
    mark_down(provider, reason);
    Some(reason)
}

/// A [`seagent_core::Provider`] decorator that feeds the auxiliary health table: a capacity failure
/// benches the provider for the task ladder, a success clears it.
pub struct Watched {
    pub inner: std::sync::Arc<dyn seagent_core::Provider>,
    pub provider: String,
}

impl seagent_core::Provider for Watched {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, model: &str) -> seagent_core::ModelCaps {
        self.inner.caps(model)
    }
    fn complete(
        &self,
        req: &seagent_core::ModelRequest,
        on_event: &mut dyn FnMut(seagent_core::StreamEvent),
        cancel: &seagent_core::Cancel,
    ) -> Result<seagent_core::ModelResponse, seagent_core::ProviderError> {
        let r = self.inner.complete(req, on_event, cancel);
        match &r {
            Ok(_) => clear(&self.provider),
            Err(e) => {
                observe_error(&self.provider, e);
            }
        }
        r
    }
}

/// Idle timeout for a task (`timeout` in its block).
pub fn timeout(tasks: &BTreeMap<String, toml::Table>, task: &str) -> Option<Duration> {
    let t = config_for(tasks, task)?;
    parse_task(t).timeout_secs.map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tasks(s: &str) -> BTreeMap<String, toml::Table> {
        let v: toml::Table = s.parse().unwrap();
        v.into_iter()
            .filter_map(|(k, v)| v.as_table().cloned().map(|t| (k, t)))
            .collect()
    }

    #[test]
    fn a_pinned_route_wins_and_alias_names_are_accepted() {
        let t = tasks(
            r#"
[compression]
provider = "groq"
model = "llama-3.3-70b"
reasoning_effort = "low"
timeout = 45
fallback = ["openai/gpt-5.4-mini"]
[title_generation]
enabled = false
"#,
        );
        let p = plan(&t, "compaction", "anthropic/claude-haiku-4-5", "anthropic/claude-sonnet-5-5", &[]);
        assert_eq!(p, vec!["groq/llama-3.3-70b", "openai/gpt-5.4-mini", "anthropic/claude-haiku-4-5", "anthropic/claude-sonnet-5-5"]);
        let c = parse_task(config_for(&t, "compaction").unwrap());
        assert_eq!((c.route.provider.as_str(), c.timeout_secs), ("groq", Some(45)));
        assert_eq!(c.route.reasoning_effort, "low");
        assert!(!parse_task(config_for(&t, "title_generation").unwrap()).enabled);
        assert_eq!(timeout(&t, "compaction"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn auto_provider_follows_the_main_selection_and_bare_models_inherit_its_provider() {
        let t = tasks(
            r#"
[vision]
provider = "auto"
model = "qwen3.7-plus"
fallback = ["glm-5.3"]
"#,
        );
        let p = plan(&t, "vision", "dashscope/qwen3-coder-plus", "anthropic/claude-sonnet-5-5", &["openai/gpt-5.4-mini".into()]);
        assert_eq!(p[0], "dashscope/qwen3.7-plus");
        assert_eq!(p[1], "dashscope/glm-5.3");
        assert_eq!(p[2], "dashscope/qwen3-coder-plus");
    }

    #[test]
    fn a_benched_provider_is_skipped_until_its_hold_expires() {
        let t = tasks(
            r#"
[sampling]
provider = "groq"
model = "llama-3.3-70b"
fallback = ["openai/gpt-5.4-mini"]
"#,
        );
        let p = plan(&t, "sampling", "anthropic/claude-haiku-4-5", "anthropic/claude-sonnet-5-5", &[]);
        assert_eq!(pick(&p).as_deref(), Some("groq/llama-3.3-70b"));
        // A rate limit benches the lane for a minute, a quota failure for hours.
        let until = mark_down("groq", "rate limit");
        assert!(until > now_ms());
        assert!(down("groq"));
        assert_eq!(pick(&p).as_deref(), Some("openai/gpt-5.4-mini"));
        clear("groq");
        assert_eq!(pick(&p).as_deref(), Some("groq/llama-3.3-70b"));
        // An expired hold is forgotten on read.
        hold_until("groq", "rate limit", now_ms().saturating_sub(SHORT_HOLD_SECS * 1000 + 5_000));
        assert!(!down("groq"));
        // Everything down: the primary is still tried rather than failing without a call.
        mark_down("groq", "payment/quota");
        mark_down("openai", "payment/quota");
        mark_down("anthropic", "payment/quota");
        assert_eq!(pick(&p).as_deref(), Some("groq/llama-3.3-70b"));
        for p in ["groq", "openai", "anthropic"] {
            clear(p);
        }
    }

    #[test]
    fn capacity_failures_bench_a_lane_and_a_four_hundred_does_not() {
        use seagent_core::ProviderError;
        let mut quota = ProviderError::new(ProviderErrorKind::Auth, "402: You are out of credit");
        quota.status = Some(402);
        assert_eq!(observe_error("x-prov", &quota), Some("payment/quota"));
        assert!(down("x-prov"));
        clear("x-prov");
        let rl = ProviderError::new(ProviderErrorKind::RateLimited { retry_after: None }, "429");
        assert_eq!(observe_error("x-prov", &rl), Some("rate limit"));
        assert_eq!(hold_secs("rate limit"), SHORT_HOLD_SECS);
        assert_eq!(hold_secs("payment/quota"), LONG_HOLD_SECS);
        clear("x-prov");
        let bad = ProviderError::new(ProviderErrorKind::BadRequest, "bad shape");
        assert_eq!(observe_error("x-prov", &bad), None);
        assert!(!down("x-prov"));
        let auth = ProviderError::new(ProviderErrorKind::Auth, "401 invalid api key");
        assert_eq!(observe_error("x-prov", &auth), None, "auth has its own refresh path");
        clear("x-prov");
        let _ = LONG_HOLD_SECS;
    }
}
