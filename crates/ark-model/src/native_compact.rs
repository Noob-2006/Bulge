//! Server-side ("native") compaction for the OpenAI Responses wire — a port of Hermes
//! `agent/native_compaction.py`.
//!
//! `context_management: [{"type": "compaction", "compact_threshold": N}]` lets the server
//! summarise older context into an opaque `compaction` item once the input crosses `N` tokens,
//! so the client stops paying for a second summarisation round-trip. Deliberately narrow:
//! `gpt-5.6` on a direct OpenAI route (`api.openai.com`) or the ChatGPT Codex backend, plus the
//! Astra models on official Codex OAuth; xAI and GitHub routes never get the field. ark's own
//! compaction stays armed as the fallback: the kernel keeps the native threshold below the local
//! trigger (`compaction.native`), so the server gets the first shot.
//!
//! Every gate is re-checked per request, so a mid-session model switch or an in-session
//! rejection takes effect on the next call. A *structured* rejection (HTTP 400 naming
//! `context_management`/`compact_threshold` alongside rejection wording) strips the field,
//! remembers the `(provider, model)` pair for the rest of the process and retries once; a 5xx
//! that merely echoes the request body must not downgrade the feature.

use crate::net::host_port;
use ark_core::{ModelRequest, ProviderError};
use serde_json::{json, Value};
use std::sync::Mutex;

/// Substring match, so dated snapshots and variants (`gpt-5.6-mini`) stay eligible.
pub const ELIGIBLE_MODEL_MARKER: &str = "gpt-5.6";

/// Wording a provider uses when it refuses a request field (Hermes `_REJECTION_MARKERS`).
const REJECTION_MARKERS: &[&str] = &[
    "unknown",
    "unsupported",
    "invalid",
    "unexpected",
    "not permitted",
    "not allowed",
    "unrecognized",
    "extra field",
    "no such",
    "bad request",
    "not supported",
];

/// `(provider, model)` pairs a provider refused `context_management` for: the field is never
/// sent to them again while this process lives (Hermes disables it "for the session").
static REJECTED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn key(conn_id: &str, model: &str) -> String {
    format!("{conn_id}\u{1}{model}")
}

/// True once a provider rejected the field for this model (or for the whole provider when
/// `model` is empty).
pub fn is_rejected(conn_id: &str, model: &str) -> bool {
    let k = key(conn_id, model);
    let all = key(conn_id, "");
    REJECTED.lock().unwrap().iter().any(|r| *r == k || *r == all)
}

fn remember_rejection(conn_id: &str, model: &str) {
    let k = key(conn_id, model);
    let mut r = REJECTED.lock().unwrap();
    if !r.contains(&k) {
        r.push(k);
    }
}

/// Astra (Hermes `is_astra_model`): the `-900k` picker alias is the same wire slug.
pub fn is_astra_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("astra")
}

/// `https://chatgpt.com/backend-api/codex[/…]` exactly — custom proxies do not count.
pub fn is_official_codex_base_url(base_url: &str) -> bool {
    let (scheme, rest) = base_url.split_once("://").unwrap_or(("", base_url));
    if scheme != "https" {
        return false;
    }
    let (host, port) = host_port(base_url);
    if host != "chatgpt.com" || !matches!(port, None | Some(443)) {
        return false;
    }
    let path = match rest.split_once('/') {
        Some((_, p)) => format!("/{}", p.split(['?', '#']).next().unwrap_or("")),
        None => String::new(),
    };
    let path = path.trim_end_matches('/');
    path == "/backend-api/codex" || path.starts_with("/backend-api/codex/")
}

/// True for `api.openai.com` or the ChatGPT Codex backend — nothing else.
pub fn is_direct_openai_route(base_url: &str, codex_backend: bool) -> bool {
    codex_backend || host_port(base_url).0 == "api.openai.com"
}

/// Model families that may use native compaction on a direct route.
pub fn is_native_compaction_model(model: &str, provider: &str, base_url: &str) -> bool {
    let m = model.to_ascii_lowercase();
    m.contains(ELIGIBLE_MODEL_MARKER)
        || (is_astra_model(&m)
            && provider.trim().eq_ignore_ascii_case("openai-codex")
            && is_official_codex_base_url(base_url))
}

/// Everything the per-request decision depends on.
pub struct Gates<'a> {
    pub model: &'a str,
    /// Provider id (`openai`, `openai-codex`, `xai-responses`…).
    pub provider: &'a str,
    pub base_url: &'a str,
    /// ChatGPT Codex backend (`quirks = ["codex"]`).
    pub codex_backend: bool,
    /// Operator vouched for a proxy that speaks the field (`quirks = ["native_compaction"]`,
    /// Hermes `capabilities.openai_native_compaction`).
    pub trusted_proxy: bool,
    pub xai: bool,
    pub github: bool,
}

/// The `context_management` payload, or `None` = do not send.
pub fn payload(g: &Gates<'_>, threshold: u64) -> Option<Value> {
    if g.xai || g.github || threshold == 0 {
        return None;
    }
    if !is_native_compaction_model(g.model, g.provider, g.base_url) {
        return None;
    }
    if !g.trusted_proxy && !is_direct_openai_route(g.base_url, g.codex_backend) {
        return None;
    }
    Some(json!([{"type": "compaction", "compact_threshold": threshold}]))
}

/// Was this provider error a structured refusal of `context_management`?
///
/// Narrow on purpose: the text must name the field *and* carry rejection wording, and the
/// status must be 400 (or unknown — some transports only surface a message string), so a
/// transient 5xx that echoes the request cannot disable the feature.
pub fn is_native_compaction_rejection(msg: &str, status: Option<u16>) -> bool {
    let t = msg.to_ascii_lowercase();
    if !(t.contains("context_management") || t.contains("compact_threshold")) {
        return false;
    }
    if status.is_some_and(|s| s != 400) {
        return false;
    }
    REJECTION_MARKERS.iter().any(|m| t.contains(m))
}

fn is_xai(conn: &crate::Conn) -> bool {
    conn.id.starts_with("xai") || conn.base.contains("api.x.ai")
}

fn is_github(conn: &crate::Conn) -> bool {
    conn.id.starts_with("github") || conn.base.contains("github")
}

/// Add `context_management` to a Responses request body when every gate allows it.
/// Called once, from the Responses body builder.
pub(crate) fn apply(body: &mut Value, req: &ModelRequest, conn: &crate::Conn, codex_backend: bool) {
    let Some(threshold) = req.options.native_compaction.filter(|t| *t > 0) else {
        return;
    };
    if is_rejected(&conn.id, &req.model) {
        return;
    }
    let g = Gates {
        model: &req.model,
        provider: &conn.id,
        base_url: &conn.base,
        codex_backend,
        trusted_proxy: conn.quirk("native_compaction"),
        xai: is_xai(conn),
        github: is_github(conn),
    };
    if let Some(cm) = payload(&g, threshold) {
        if let Some(o) = body.as_object_mut() {
            o.insert("context_management".to_string(), cm);
        }
    }
}

/// Send once; on a structured rejection strip the field, remember it and retry once.
///
/// Safe to retry because a 400 arrives before any streamed delta (`http::open` classifies the
/// status line before handing the body over), so no partial content is left behind.
pub(crate) fn send_with_recovery<T>(
    body: &mut Value,
    conn_id: &str,
    model: &str,
    mut send: impl FnMut(&Value) -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    let native = body.get("context_management").is_some();
    match send(body) {
        Err(e) if native && is_native_compaction_rejection(&e.message, e.status) => {
            strip(body);
            remember_rejection(conn_id, model);
            send(body)
        }
        other => other,
    }
}

/// Drop the field from a request body.
pub fn strip(body: &mut Value) {
    if let Some(o) = body.as_object_mut() {
        o.remove("context_management");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gates<'a>(model: &'a str, provider: &'a str, base: &'a str) -> Gates<'a> {
        Gates { model, provider, base_url: base, codex_backend: false, trusted_proxy: false, xai: false, github: false }
    }

    #[test]
    fn payload_requires_a_direct_route_and_an_eligible_model() {
        let g = gates("gpt-5.6", "openai", "https://api.openai.com/v1");
        assert_eq!(payload(&g, 120_000).unwrap(), json!([{"type": "compaction", "compact_threshold": 120_000}]));
        // Dated snapshots and variants stay eligible.
        assert!(payload(&gates("gpt-5.6-mini-2026-01-01", "openai", "https://api.openai.com/v1"), 1).is_some());
        // Older/other models never are.
        assert!(payload(&gates("gpt-5.5", "openai", "https://api.openai.com/v1"), 1).is_none());
        // A proxy is refused unless the operator trusts it.
        let proxy = gates("gpt-5.6", "openai", "https://llm.internal/v1");
        assert!(payload(&proxy, 1).is_none());
        let trusted = Gates { trusted_proxy: true, ..proxy };
        assert!(payload(&trusted, 1).is_some());
        // The Codex backend is a direct route by construction.
        let codex = Gates { codex_backend: true, ..gates("gpt-5.6", "openai-codex", "https://chatgpt.com/backend-api/codex") };
        assert!(payload(&codex, 1).is_some());
        // xAI / GitHub routes are excluded even when the model name matches.
        assert!(payload(&Gates { xai: true, ..gates("gpt-5.6", "xai-responses", "https://api.openai.com/v1") }, 1).is_none());
        assert!(payload(&Gates { github: true, ..gates("gpt-5.6", "openai", "https://api.openai.com/v1") }, 1).is_none());
        // No threshold, no request.
        assert!(payload(&g, 0).is_none());
    }

    #[test]
    fn astra_needs_official_codex_oauth() {
        let base = "https://chatgpt.com/backend-api/codex";
        assert!(is_native_compaction_model("gpt-6-astra-900k", "openai-codex", base));
        assert!(!is_native_compaction_model("gpt-6-astra-900k", "openai", base), "direct API is not enough");
        assert!(!is_native_compaction_model("gpt-6-astra-900k", "openai-codex", "https://proxy.example/backend-api/codex"));
        assert!(!is_native_compaction_model("gpt-6-astra-900k", "openai-codex", "http://chatgpt.com/backend-api/codex"), "https only");
        assert!(is_official_codex_base_url("https://chatgpt.com/backend-api/codex/"));
        assert!(!is_official_codex_base_url("https://chatgpt.com/backend-api/other"));
        assert!(is_direct_openai_route("https://api.openai.com/v1", false));
        assert!(!is_direct_openai_route("https://api.openai.com.evil/v1", false));
        assert!(is_direct_openai_route("", true), "the codex backend needs no host check");
    }

    #[test]
    fn rejection_detection_is_narrow() {
        let unknown = "Unknown parameter: 'context_management'";
        assert!(is_native_compaction_rejection(unknown, Some(400)));
        assert!(is_native_compaction_rejection("invalid value for compact_threshold", None), "message-only transports still match");
        assert!(!is_native_compaction_rejection(unknown, Some(500)), "a 5xx echo must not downgrade native compaction");
        assert!(!is_native_compaction_rejection("invalid api key", Some(400)));
        assert!(!is_native_compaction_rejection("context_management", Some(400)), "naming the field is not a rejection");
    }

    #[test]
    fn recovery_strips_and_remembers() {
        let mut body = json!({"model": "gpt-5.6", "context_management": [{"type": "compaction"}]});
        let (id, model) = ("openai-recovery-test", "gpt-5.6-recovery");
        let mut seen: Vec<bool> = Vec::new();
        let r: Result<(), ProviderError> = send_with_recovery(&mut body, id, model, |b| {
            seen.push(b.get("context_management").is_some());
            if b.get("context_management").is_some() {
                Err(ProviderError::new(ark_core::ProviderErrorKind::BadRequest, "Unsupported parameter: context_management").with_status(400))
            } else {
                Ok(())
            }
        });
        assert!(r.is_ok() && seen == [true, false], "one retry without the field");
        assert!(is_rejected(id, model), "the pair is remembered for later requests");
        assert!(body.get("context_management").is_none());
        // A non-rejection error is passed straight through, field intact.
        let mut body2 = json!({"context_management": []});
        let r: Result<(), ProviderError> = send_with_recovery(&mut body2, id, "other-model", |_| {
            Err(ProviderError::new(ark_core::ProviderErrorKind::Server, "context_management exploded").with_status(503))
        });
        assert!(r.is_err() && body2.get("context_management").is_some());
    }
}
