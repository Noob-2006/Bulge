//! `model.context_length` is an explicit pin: it wins over what the provider advertises
//! (Hermes `agent/context_pin.py`, #66168).
//!
//! Two helpers make that visible without changing the number a surface uses: a label for every
//! place that renders the context window, and a one-time startup warning when the pin disagrees
//! with the provider-known window. The advertised window comes from LOCAL sources only — a window
//! learned on this endpoint, the models.dev registry, the built-in `DEFAULT_CONTEXT_LENGTHS` table.
//! Never a network probe: users pin precisely when the endpoint cannot report its window, so the
//! check must not add startup latency or a failing request.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// True when the shown window is the `model.context_length` pin (a positive pin equal to `shown`).
pub fn is_pinned(shown: u64, pin: Option<u64>) -> bool {
    matches!(pin, Some(p) if p > 0 && p == shown)
}

/// `" (pinned)"` when the shown value comes from `model.context_length`, else `""`.
pub fn suffix(shown: u64, pin: Option<u64>) -> &'static str {
    if is_pinned(shown, pin) {
        " (pinned)"
    } else {
        ""
    }
}

/// True when `shown` is only a default because no local source knows this model's window
/// (Hermes `is_fallback_context_length`). A pin, an endpoint-learned window, the models.dev
/// registry or the built-in table all count as knowledge; the generic heuristic does not.
pub fn is_fallback(shown: u64, model: &str, base_url: &str, pin: Option<u64>) -> bool {
    if shown == 0 || is_pinned(shown, pin) || pin.is_some_and(|p| p > 0) {
        return false;
    }
    if learned(model, base_url).is_some() {
        return false;
    }
    if advertised(model, base_url).is_some() {
        return false;
    }
    // A provider that reports its own (different) window is authoritative even when the local
    // catalogue does not list the model.
    shown == crate::caps_for(model).context_window
}

/// `" (pinned)"`, `" (fallback)"` or `""` for a rendered context window.
pub fn marker(shown: u64, model: &str, base_url: &str, pin: Option<u64>) -> &'static str {
    if is_pinned(shown, pin) {
        "pinned"
    } else if is_fallback(shown, model, base_url, pin) {
        "fallback"
    } else {
        ""
    }
}

fn learned_map() -> &'static Mutex<HashMap<(String, String), u64>> {
    static M: OnceLock<Mutex<HashMap<(String, String), u64>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn warned() -> &'static Mutex<std::collections::HashSet<(String, u64)>> {
    static W: OnceLock<Mutex<std::collections::HashSet<(String, u64)>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn endpoint_key(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_lowercase()
}

/// Record a window learned from this endpoint (Hermes `save_context_length`), so the pin check and
/// later renders use it without probing again.
pub fn set_learned(model: &str, base_url: &str, context: u64) {
    if context == 0 {
        return;
    }
    let key = (model.trim().to_lowercase(), endpoint_key(base_url));
    if let Ok(mut m) = learned_map().lock() {
        m.insert(key, context);
    }
}

/// A previously learned window for `model` on this endpoint, if any (Hermes
/// `get_cached_context_length`). In-process only; the disk copy of that cache lives in the kernel.
pub fn learned(model: &str, base_url: &str) -> Option<u64> {
    let key = (model.trim().to_lowercase(), endpoint_key(base_url));
    learned_map().lock().ok()?.get(&key).copied()
}

pub fn clear_learned() {
    if let Ok(mut m) = learned_map().lock() {
        m.clear();
    }
}

/// The smallest window worth adopting from an endpoint (Hermes `MINIMUM_CONTEXT_LENGTH`): a
/// server that reports 512 tokens for a model we know is large is misconfigured, and blessing
/// that number would strangle every later run. Smaller reports are used for the current call
/// only, never remembered.
pub const MINIMUM_CONTEXT_LENGTH: u64 = 64_000;

/// Adopt a window an endpoint reported about itself (its model list entry, or a context-overflow
/// error naming its limit). Returns the value when it was remembered. This is the production
/// writer behind `learned`: the pin check and every render then use the endpoint's own number
/// instead of a catalogue guess, so a local vLLM/Ollama box needs no `model.context_length` pin.
pub fn learn_from_endpoint(model: &str, base_url: &str, reported: u64) -> Option<u64> {
    if reported < MINIMUM_CONTEXT_LENGTH {
        return None;
    }
    set_learned(model, base_url, reported);
    Some(reported)
}

/// The models.dev provider id implied by a base URL (so a provider-specific window wins over an
/// aggregator's copy of the same model id). Unknown hosts fall back to the registry-wide match.
fn provider_for(base_url: &str) -> Option<&'static str> {
    let u = base_url.to_lowercase();
    if u.is_empty() {
        return None;
    }
    let hit = |n: &str| u.contains(n);
    Some(if hit("anthropic.com") {
        "anthropic"
    } else if hit("openai.com") || hit("chatgpt.com") {
        "openai"
    } else if hit("generativelanguage") || hit("googleapis.com") {
        "gemini"
    } else if hit("openrouter.ai") {
        "openrouter"
    } else if hit("api.deepseek.com") {
        "deepseek"
    } else if hit("kimi.com") {
        "kimi-coding"
    } else if hit("moonshot") {
        "moonshot"
    } else if hit("bigmodel.cn") || hit("z.ai") {
        "zai"
    } else if hit("dashscope") || hit("aliyuncs.com") {
        "qwen"
    } else if hit("api.x.ai") {
        "xai"
    } else if hit("minimax") {
        "minimax"
    } else if hit("meta.ai") {
        "meta-ai"
    } else if hit("groq.com") {
        "groq"
    } else if hit("mistral.ai") {
        "mistral"
    } else if hit("together.xyz") || hit("together.ai") {
        "together"
    } else if hit("cerebras.ai") {
        "cerebras"
    } else if hit("novita.ai") {
        "novita"
    } else if hit("copilot") {
        "github-copilot"
    } else if hit("amazonaws.com") || hit("bedrock") {
        "bedrock"
    } else if hit("openai.azure.com") {
        "azure-openai"
    } else {
        return None;
    })
}

/// Provider-advertised context window from LOCAL sources only (never a network probe):
/// window learned on this endpoint → models.dev registry entry → `DEFAULT_CONTEXT_LENGTHS` table.
pub fn advertised(model: &str, base_url: &str) -> Option<u64> {
    let raw = model.trim();
    if raw.is_empty() {
        return None;
    }
    // Serve the registry (starting at most one background revalidation when it is stale).
    let _ = crate::modelsdb::ensure_fresh();
    if !base_url.trim().is_empty() {
        if let Some(c) = learned(raw, base_url) {
            return Some(c);
        }
    }
    let bare = crate::modelsdb::normalize_id(raw);
    let provider = provider_for(base_url);
    if let Some(c) = crate::modelsdb::registry_context(provider, raw)
        .or_else(|| crate::modelsdb::registry_context(provider, &bare))
    {
        return Some(c);
    }
    crate::modelsdb::context_for(&bare).or_else(|| crate::modelsdb::context_for(raw))
}

/// `1310720` → `"1,310,720"` (upstream formats every count in the warning with `f"{n:,}"`).
fn thousands(n: u64) -> String {
    let mut groups = Vec::new();
    let mut rest = n;
    while rest >= 1000 {
        groups.push(format!("{:03}", rest % 1000));
        rest /= 1000;
    }
    groups.push(rest.to_string());
    groups.iter().rev().cloned().collect::<Vec<_>>().join(",")
}

/// The one-time warning when `model.context_length` disagrees with the advertised window. Returns
/// the message exactly once per `(model, pin)`; `None` when they agree or nothing is advertised.
/// The pin still wins — the text says so.
pub fn warn_once(model: &str, base_url: &str, pin: Option<u64>) -> Option<String> {
    let pin = pin.filter(|p| *p > 0)?;
    let adv = advertised(model, base_url)?;
    if adv == pin {
        return None;
    }
    let key = (model.trim().to_string(), pin);
    let first = warned().lock().map(|mut w| w.insert(key)).unwrap_or(false);
    if !first {
        return None;
    }
    Some(format!(
        "model.context_length pins {model} at {} tokens but the provider advertises {}; the pin wins. \
         Remove model.context_length from config to use the advertised window.",
        thousands(pin),
        thousands(adv)
    ))
}

/// The number a surface must display: the pin when set, else a window this endpoint taught us,
/// else the resolved capability window.
pub fn window(model: &str, provider_base_url: &str, pin: Option<u64>) -> u64 {
    match pin.filter(|p| *p > 0) {
        Some(p) => p,
        // A window learned on this endpoint is the endpoint's own statement about itself; it
        // beats the registry/table guess (never a per-endpoint network probe — this reads the
        // in-process cache only).
        None => learned(model, provider_base_url).unwrap_or_else(|| crate::caps_for(model).context_window),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_wins_over_the_catalog_window_and_is_labelled() {
        // `glm-5.3-flash` is in the built-in table (1_310_720) and `caps_for` resolves to it.
        assert_eq!(window("glm-5.3-flash", "", None), 1_310_720);
        assert_eq!(advertised("glm-5.3-flash", ""), Some(1_310_720));
        assert_eq!(window("glm-5.3-flash", "", Some(4_096)), 4_096);
        assert_eq!(suffix(4_096, Some(4_096)), " (pinned)");
        assert_eq!(suffix(1_310_720, Some(4_096)), "");
        assert_eq!(suffix(1_310_720, None), "");
        assert_eq!(suffix(1_310_720, Some(0)), "", "zero is not a pin");
        assert!(is_pinned(4_096, Some(4_096)));
        assert!(!is_pinned(4_096, None));
        assert!(!is_pinned(4_096, Some(0)));
    }

    #[test]
    fn pin_wins_over_a_models_dev_registry_window() {
        let _g = crate::modelsdb::test_lock();
        crate::modelsdb::reset_for_test();
        crate::modelsdb::set_registry_for_test(&serde_json::json!({
            "anthropic": {"models": {"zz-pin-reg": {"limit": {"context": 500000}}}},
            "openrouter": {"models": {"zz-pin-reg": {"limit": {"context": 250000}}}}
        }));
        // The provider derived from the endpoint picks the provider-specific registry entry.
        assert_eq!(advertised("zz-pin-reg", "https://api.anthropic.com/v1"), Some(500_000));
        // No endpoint known → the registry-wide best match.
        assert_eq!(advertised("zz-pin-reg", ""), Some(500_000));
        // Unpinned: the registry window is what surfaces show.
        assert_eq!(window("zz-pin-reg", "https://api.anthropic.com/v1", None), 500_000);
        // Pinned: the pin wins and is labelled.
        assert_eq!(window("zz-pin-reg", "https://api.anthropic.com/v1", Some(65_536)), 65_536);
        assert_eq!(suffix(65_536, Some(65_536)), " (pinned)");
        let w = warn_once("zz-pin-reg", "https://api.anthropic.com/v1", Some(65_536)).expect("warns");
        assert!(w.contains("pins zz-pin-reg at 65,536 tokens"), "{w}");
        assert!(w.contains("advertises 500,000"), "{w}");
        crate::modelsdb::reset_for_test();
    }

    #[test]
    fn learned_endpoint_window_beats_the_registry_and_the_table() {
        let _g = crate::modelsdb::test_lock();
        clear_learned();
        let model = "zz-pin-learned";
        assert_eq!(advertised(model, ""), None);
        set_learned(model, "https://api.example.test/v1/", 12_345);
        assert_eq!(learned(model, "https://api.example.test/v1"), Some(12_345));
        assert_eq!(advertised(model, "https://api.example.test/v1"), Some(12_345));
        // No endpoint → nothing learned for it.
        assert_eq!(advertised(model, "https://other.example.test"), None);
        // Learn a window for a model the built-in table knows; the learned value wins locally.
        set_learned("glm-5.3-flash", "https://api.example.test/v1", 65_536);
        assert_eq!(advertised("glm-5.3-flash", "https://api.example.test/v1"), Some(65_536));
        assert_eq!(advertised("glm-5.3-flash", ""), Some(1_310_720));
        clear_learned();
    }

    #[test]
    fn defaulted_windows_are_labelled_and_known_ones_are_not() {
        let _g = crate::modelsdb::test_lock();
        clear_learned();
        // Unknown model: the generic heuristic is a default, not a detected limit.
        let generic = crate::caps_for("zz-totally-unknown").context_window;
        assert!(is_fallback(generic, "zz-totally-unknown", "", None));
        assert_eq!(marker(generic, "zz-totally-unknown", "", None), "fallback");
        // A catalogue entry is knowledge.
        assert!(!is_fallback(1_310_720, "glm-5.3-flash", "", None));
        assert_eq!(marker(1_310_720, "glm-5.3-flash", "", None), "");
        // An endpoint-learned window is knowledge.
        set_learned("zz-pin-learned", "https://api.example.test/v1", 65_536);
        assert!(!is_fallback(65_536, "zz-pin-learned", "https://api.example.test/v1", None));
        // A pin is labelled pinned, never fallback.
        assert!(!is_fallback(4_096, "zz-totally-unknown", "", Some(4_096)));
        assert_eq!(marker(4_096, "zz-totally-unknown", "", Some(4_096)), "pinned");
        clear_learned();
    }

    #[test]
    fn disagreeing_pin_warns_exactly_once_and_agreeing_pin_never_warns() {
        let _g = crate::modelsdb::test_lock();
        // No advertised window → nothing to disagree with.
        assert_eq!(warn_once("zz-pin-unknown-xyz", "", Some(4_096)), None);
        // Disagreeing pin: one warning, then silence.
        let first = warn_once("glm-5.3-flash", "", Some(4_096)).expect("warns");
        assert!(first.contains("pins glm-5.3-flash at 4,096 tokens"), "{first}");
        assert!(first.contains("advertises 1,310,720"), "{first}");
        assert!(first.contains("the pin wins"), "{first}");
        assert!(first.contains("Remove model.context_length"), "{first}");
        assert_eq!(warn_once("glm-5.3-flash", "", Some(4_096)), None, "never repeats");
        // A different pin is a different pair.
        assert!(warn_once("glm-5.3-flash", "", Some(8_192)).is_some());
        // Agreeing pin: no warning, and it does not consume the once-only slot.
        assert_eq!(warn_once("glm-5.3-flash", "", Some(1_310_720)), None);
        // No pin at all: no warning.
        assert_eq!(warn_once("glm-5.3-flash", "", None), None);
        assert_eq!(warn_once("glm-5.3-flash", "", Some(0)), None);
    }
}
