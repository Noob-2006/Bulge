//! LangSmith's OTLP ingestion profile, as a thin layer over the monitoring exporter.
//!
//! LangSmith does not accept a plain OTLP collector URL: it expects
//! `POST {endpoint}/otel/v1/traces` with an `x-api-key` header, the project in a
//! `Langsmith-Project` header, and the span's kind in a `langsmith.span.kind` attribute
//! (verified against `langsmith-sdk/python`:
//! `integrations/otel/processor.py` (endpoint + headers), `_internal/_addressing.py:154-168`
//! (`otlp_destination_headers`), `_internal/otel/_otel_exporter.py:103-110`
//! (`LANGSMITH_RUN_TYPE`, `LANGSMITH_SESSION_ID`, `LANGSMITH_NAME`)).
//!
//! Nothing here talks to the network: the exporter in [`super`] calls these functions, so a
//! `[telemetry] endpoint = "https://api.smith.langchain.com"` behaves like the SDK. The
//! payload stays OTLP/HTTP JSON (the OTLP spec's JSON encoding; the Python SDK uses the
//! protobuf encoding), and [`validate_otlp_json`] checks the shape the receiver requires.
//!
//! ```toml
//! [telemetry]
//! enabled = true
//! endpoint = "https://api.smith.langchain.com"      # → …/otel/v1/traces
//! headers = { "x-api-key" = "{{secret:LANGSMITH_API_KEY}}", "Langsmith-Project" = "ark" }
//! ```

use serde_json::{json, Value};

/// Header the SDK always sends for a project (`_addressing.otlp_destination_headers`).
pub const PROJECT_HEADER: &str = "Langsmith-Project";
pub const API_KEY_HEADER: &str = "x-api-key";
/// Run-type attribute (`LANGSMITH_RUN_TYPE`).
pub const SPAN_KIND: &str = "langsmith.span.kind";
/// Human name of the run (`LANGSMITH_NAME`).
pub const RUN_NAME: &str = "langsmith.trace.name";

/// LangSmith's own hosts: the only ones for which an API key from the environment is
/// attached. A self-hosted collector under `…/otel` gets the URL and project header, never
/// the key — otherwise a project-level `[telemetry] endpoint` could post `LANGSMITH_API_KEY`
/// to whatever host it names.
pub fn is_hosted(endpoint: &str) -> bool {
    let host = host_of(endpoint);
    host == "api.smith.langchain.com"
        || host == "api.smith.langchain.dev"
        || host == "smith.langchain.com"
        || host.ends_with(".smith.langchain.com")
        || host.ends_with(".smith.langchain.dev")
        || host.ends_with(".langsmith.com")
        || host.ends_with(".langsmith.dev")
}

fn host_of(endpoint: &str) -> String {
    let e = endpoint.trim();
    let rest = e.split_once("://").map(|(_, r)| r).unwrap_or(e);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    host.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// Does this endpoint belong to LangSmith (hosted or self-hosted)?
pub fn is_langsmith(endpoint: &str) -> bool {
    let e = endpoint.trim();
    if e.is_empty() {
        return false;
    }
    let rest = e.split_once("://").map(|(_, r)| r).unwrap_or(e);
    is_hosted(e) || rest.trim_end_matches('/').ends_with("/otel") || rest.contains("/otel/v1/")
}

/// `<endpoint>/otel/v1/traces` for a LangSmith base; an already complete traces URL is kept.
pub fn traces_url(endpoint: &str) -> String {
    let e = endpoint.trim().trim_end_matches('/');
    if e.ends_with("/v1/traces") {
        return e.to_string();
    }
    if let Some(base) = e.strip_suffix("/v1/metrics") {
        return format!("{base}/v1/traces");
    }
    if e.ends_with("/otel") {
        return format!("{e}/v1/traces");
    }
    if is_langsmith(e) {
        return format!("{e}/otel/v1/traces");
    }
    format!("{e}/v1/traces")
}

/// Headers to send, given the operator's `[telemetry] headers`: the project and API key are
/// filled in from `LANGSMITH_PROJECT` / `LANGSMITH_API_KEY` (via the vault) when missing.
/// `sub` resolves `{{secret:NAME}}`; an unresolved secret is never sent.
pub fn headers(endpoint: &str, configured: &[(String, String)], sub: &dyn Fn(&str) -> String) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = configured.iter().map(|(k, v)| (k.clone(), sub(v))).collect();
    if !is_langsmith(endpoint) {
        return out;
    }
    fn has(hs: &[(String, String)], name: &str) -> bool {
        hs.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }
    // The key comes from the environment only for LangSmith's own hosts over https: a
    // self-hosted `…/otel` endpoint may be anyone, and the endpoint can come from project
    // config, so an automatic key there would be an exfiltration path.
    let https = endpoint.trim().to_ascii_lowercase().starts_with("https://");
    if !has(&out, API_KEY_HEADER) && https && is_hosted(endpoint) {
        let key = std::env::var("LANGSMITH_API_KEY").unwrap_or_default();
        if !key.trim().is_empty() {
            out.push((API_KEY_HEADER.into(), key));
        }
    }
    if !has(&out, PROJECT_HEADER) {
        if let Ok(p) = std::env::var("LANGSMITH_PROJECT") {
            if !p.trim().is_empty() {
                out.push((PROJECT_HEADER.into(), p.trim().into()));
            }
        }
    }
    out
}

/// The project this export names, if any (for `ark telemetry` output and docs).
pub fn project(headers: &[(String, String)]) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(PROJECT_HEADER)).map(|(_, v)| v.clone()).filter(|v| !v.trim().is_empty())
}

/// LangSmith only renders a span when it knows the run type; ark's monitoring spans are
/// logical steps, so they map to `chain` (the SDK's default for a non-LLM run).
pub fn map_span(span: &mut Value) {
    let name = span["name"].as_str().unwrap_or("ark.event").to_string();
    let attrs = match span.get_mut("attributes").and_then(Value::as_array_mut) {
        Some(a) => a,
        None => {
            span["attributes"] = json!([]);
            span["attributes"].as_array_mut().unwrap()
        }
    };
    fn has(attrs: &[Value], k: &str) -> bool {
        attrs.iter().any(|a| a["key"].as_str() == Some(k))
    }
    if !has(attrs, SPAN_KIND) {
        attrs.push(json!({"key": SPAN_KIND, "value": {"stringValue": "chain"}}));
    }
    if !has(attrs, RUN_NAME) {
        attrs.push(json!({"key": RUN_NAME, "value": {"stringValue": name}}));
    }
}

fn hex_ok(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c != '0')
}

/// Check an OTLP/HTTP JSON trace body against what an OTLP receiver requires (field names,
/// id widths, nanosecond timestamps as strings, one-of attribute values). This is the check
/// `ark telemetry --check` runs, and the reason a malformed export fails loudly instead of
/// silently disappearing into a collector.
pub fn validate_otlp_json(body: &Value) -> Result<(), String> {
    let rs = body.get("resourceSpans").and_then(Value::as_array).ok_or("resourceSpans[] is required")?;
    if rs.is_empty() {
        return Err("resourceSpans[] is empty".into());
    }
    for (i, r) in rs.iter().enumerate() {
        let rattrs = r.pointer("/resource/attributes").and_then(Value::as_array).ok_or(format!("resourceSpans[{i}].resource.attributes[] is required"))?;
        if !rattrs.iter().any(|a| a["key"] == "service.name") {
            return Err(format!("resourceSpans[{i}]: resource needs service.name (LangSmith groups by it)"));
        }
        for a in rattrs {
            check_attr(i, a)?;
        }
        let ss = r.get("scopeSpans").and_then(Value::as_array).ok_or(format!("resourceSpans[{i}].scopeSpans[] is required"))?;
        for (j, s) in ss.iter().enumerate() {
            let spans = s.get("spans").and_then(Value::as_array).ok_or(format!("scopeSpans[{j}].spans[] is required"))?;
            for (k, sp) in spans.iter().enumerate() {
                let at = |m: &str| format!("resourceSpans[{i}].scopeSpans[{j}].spans[{k}].{m}");
                let tid = sp.get("traceId").and_then(Value::as_str).ok_or(at("traceId is required"))?;
                if !hex_ok(tid, 32) {
                    return Err(format!("{}: traceId must be 32 hex chars (got `{tid}`)", at("traceId")));
                }
                let sid = sp.get("spanId").and_then(Value::as_str).ok_or(at("spanId is required"))?;
                if !hex_ok(sid, 16) {
                    return Err(format!("{}: spanId must be 16 hex chars (got `{sid}`)", at("spanId")));
                }
                for f in ["startTimeUnixNano", "endTimeUnixNano"] {
                    let v = sp.get(f).and_then(Value::as_str).ok_or(format!("{}: {f} must be a string (uint64 as decimal)", at(f)))?;
                    if v.parse::<u64>().is_err() {
                        return Err(format!("{}: {f} is not a decimal uint64", at(f)));
                    }
                }
                if sp.get("name").and_then(Value::as_str).unwrap_or("").is_empty() {
                    return Err(format!("{}: name is required", at("name")));
                }
                for a in sp.get("attributes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
                    check_attr(i, a)?;
                }
            }
        }
    }
    Ok(())
}

fn check_attr(i: usize, a: &Value) -> Result<(), String> {
    let key = a.get("key").and_then(Value::as_str).ok_or(format!("resourceSpans[{i}]: attribute without `key`"))?;
    let v = a.get("value").and_then(Value::as_object).ok_or(format!("resourceSpans[{i}]: attribute `{key}` without `value`"))?;
    const KINDS: [&str; 5] = ["stringValue", "boolValue", "intValue", "doubleValue", "arrayValue"];
    let n = v.keys().filter(|k| KINDS.contains(&k.as_str())).count();
    if n != 1 {
        return Err(format!("resourceSpans[{i}]: attribute `{key}` must set exactly one of {:?} (got {})", KINDS, n));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(s: &str) -> String {
        if s == "{{secret:LS}}" { "sk-test".into() } else { s.into() }
    }

    #[test]
    fn langsmith_endpoints_are_rewritten_like_the_sdk() {
        assert_eq!(traces_url("https://api.smith.langchain.com"), "https://api.smith.langchain.com/otel/v1/traces");
        assert_eq!(traces_url("https://api.smith.langchain.com/"), "https://api.smith.langchain.com/otel/v1/traces");
        assert_eq!(traces_url("https://api.smith.langchain.com/otel"), "https://api.smith.langchain.com/otel/v1/traces");
        assert_eq!(traces_url("https://api.smith.langchain.com/otel/v1/traces"), "https://api.smith.langchain.com/otel/v1/traces");
        assert_eq!(traces_url("https://ls.internal.example"), "https://ls.internal.example/v1/traces");
        assert_eq!(traces_url("http://127.0.0.1:4318"), "http://127.0.0.1:4318/v1/traces");
        // Self-hosted LangSmith on a private host with the SDK's own path shape.
        assert_eq!(traces_url("https://smith.acme.example/otel"), "https://smith.acme.example/otel/v1/traces");
        assert!(is_langsmith("https://api.smith.langchain.com"));
        assert!(is_langsmith("https://eu.api.smith.langchain.com/"));
        assert!(!is_langsmith("http://127.0.0.1:4318"));
    }

    #[test]
    fn headers_carry_the_key_and_the_project() {
        let h = headers("https://api.smith.langchain.com", &[("x-api-key".into(), "{{secret:LS}}".into()), (PROJECT_HEADER.into(), "ark-prod".into())], &sub);
        assert!(h.iter().any(|(k, v)| k == "x-api-key" && v == "sk-test"), "the vault reference is resolved");
        assert_eq!(project(&h).as_deref(), Some("ark-prod"));
        assert_eq!(headers("http://127.0.0.1:4318", &[("a".into(), "b".into())], &sub), vec![("a".to_string(), "b".to_string())], "a plain collector gets nothing added");
        // An unresolved secret is not silently turned into a literal request header value.
        let unresolved = |s: &str| s.to_string();
        let h = headers("https://api.smith.langchain.com", &[("x-api-key".into(), "{{secret:MISSING}}".into())], &unresolved);
        assert!(h.iter().any(|(k, v)| k == "x-api-key" && v.contains("{{secret:")));
    }

    #[test]
    fn the_key_never_leaks_to_a_self_hosted_otel_endpoint() {
        // `…/otel` on someone else's host switches on the LangSmith profile (URL/project),
        // but an environment key must not be attached there.
        std::env::set_var("LANGSMITH_API_KEY", "sk-env-should-not-leak");
        let h = headers("https://collector.example/otel", &[], &sub);
        assert!(!h.iter().any(|(k, _)| k.eq_ignore_ascii_case(API_KEY_HEADER)), "{h:?}");
        // LangSmith's own host still gets it.
        let h = headers("https://api.smith.langchain.com", &[], &sub);
        assert!(h.iter().any(|(k, v)| k.eq_ignore_ascii_case(API_KEY_HEADER) && v == "sk-env-should-not-leak"));
        // …but never over plain http.
        let h = headers("http://api.smith.langchain.com", &[], &sub);
        assert!(!h.iter().any(|(k, _)| k.eq_ignore_ascii_case(API_KEY_HEADER)));
        std::env::remove_var("LANGSMITH_API_KEY");
    }

    #[test]
    fn spans_get_a_langsmith_run_type() {
        let mut s = json!({"name": "ark.gateway_health", "traceId": "ab".repeat(16), "spanId": "cd".repeat(8),
            "startTimeUnixNano": "1", "endTimeUnixNano": "2", "attributes": [{"key": "ark.event", "value": {"stringValue": "gateway_health"}}]});
        map_span(&mut s);
        let keys: Vec<&str> = s["attributes"].as_array().unwrap().iter().map(|a| a["key"].as_str().unwrap()).collect();
        assert_eq!(keys, vec!["ark.event", SPAN_KIND, RUN_NAME]);
        assert_eq!(s["attributes"][1]["value"]["stringValue"], "chain");
        assert_eq!(s["attributes"][2]["value"]["stringValue"], "ark.gateway_health");
        // Idempotent: a second mapping does not duplicate the attributes.
        map_span(&mut s);
        assert_eq!(s["attributes"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn otlp_json_is_validated_before_it_is_sent() {
        let good = json!({"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ark-gateway"}}]},
            "scopeSpans": [{"scope": {"name": "ark.monitoring"}, "spans": [{"traceId": "aa".repeat(16), "spanId": "bb".repeat(8),
                "name": "ark.gateway_health", "kind": 1, "startTimeUnixNano": "1700000000000000000", "endTimeUnixNano": "1700000000000000000",
                "attributes": [{"key": "ark.event", "value": {"stringValue": "gateway_health"}}], "status": {}}]}]}]});
        assert_eq!(validate_otlp_json(&good), Ok(()));
        let no_service = json!({"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": []}]}]});
        assert!(validate_otlp_json(&no_service).unwrap_err().contains("service.name"));
        let mut bad_id = good.clone();
        bad_id["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"] = json!("xyz");
        assert!(validate_otlp_json(&bad_id).unwrap_err().contains("32 hex"));
        let mut bad_ts = good.clone();
        bad_ts["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["endTimeUnixNano"] = json!(17);
        assert!(validate_otlp_json(&bad_ts).unwrap_err().contains("must be a string"));
        let mut two_vals = good.clone();
        two_vals["resourceSpans"][0]["resource"]["attributes"][0]["value"] = json!({"stringValue": "a", "intValue": "1"});
        assert!(validate_otlp_json(&two_vals).unwrap_err().contains("exactly one"));
    }
}
