//! Parallel search + extract. OpenClaw `extensions/parallel` (`POST /v1/search` with
//! search_queries ≤ 5 × 200 chars, objective ≤ 5 000, advanced_settings.max_results ≤ 40,
//! session_id / client_model, x-api-key) + Hermes `plugins/web/parallel` (objective = query,
//! PARALLEL_SEARCH_MODE, `extract` with full_content, keyless ring). `parallel-free` (OpenClaw's
//! keyless Search MCP) is the keyless path of this provider.

use super::{hit, Hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::keyless;
use serde_json::{json, Value};

pub struct Parallel;

const ENV: &[&str] = &["PARALLEL_API_KEY"];
const DEFAULT_BASE: &str = "https://api.parallel.ai";
const MAX_COUNT: usize = 40;

fn base(c: &WebCtx) -> Result<String, String> {
    let b = c.base_url("parallel", None, DEFAULT_BASE);
    let l = b.to_ascii_lowercase();
    if b.contains("://") && !l.starts_with("http://") && !l.starts_with("https://") {
        return Err(format!("[web.providers.parallel] base_url must be a valid http(s) URL. Got: {b}"));
    }
    let b = if b.contains("://") { b } else { format!("https://{b}") };
    Ok(b.trim_end_matches("/v1/search").to_string())
}

/// Trim, drop empty / duplicate entries, cap each at 200 chars and the list at 5.
pub fn normalize_queries(c: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for q in c {
        let t = q.trim();
        if t.is_empty() {
            continue;
        }
        let capped: String = t.chars().take(200).collect();
        if !out.contains(&capped) {
            out.push(capped);
        }
        if out.len() == 5 {
            break;
        }
    }
    out
}

fn mode(c: &WebCtx) -> Option<String> {
    c.opt("parallel", "mode").or_else(|| c.var("PARALLEL_SEARCH_MODE")).map(|m| m.to_ascii_lowercase()).map(|m| if ["fast", "one-shot", "agentic"].contains(&m.as_str()) { m } else { "agentic".into() })
}

fn map(v: &Value, n: usize) -> Vec<Hit> {
    v.get("results").and_then(|r| r.as_array()).into_iter().flatten().filter(|r| r.is_object()).take(n).map(|e| {
        let ex: Vec<&str> = e.get("excerpts").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|s| s.as_str()).collect();
        Hit { published: Some(http::s(e, "publish_date")).filter(|p| !p.is_empty()), ..hit(&http::s(e, "title"), &http::s(e, "url"), &ex.join("\n\n")) }
    })
    .collect()
}

fn post(c: &WebCtx, path: &str, key: &str, body: &Value, beta: bool) -> Result<Value, String> {
    c.check_cancel()?;
    let mut h = vec![("Accept", "application/json".to_string()), ("x-api-key", key.to_string()), ("User-Agent", format!("seagent-parallel/{}", env!("CARGO_PKG_VERSION")))];
    if beta {
        h.push(("parallel-beta", "search-extract-2025-10-10".into()));
    }
    let r = http::post_json(&format!("{}{path}", base(c)?), &h, body, c.timeout("parallel")).map_err(|e| format!("Parallel request failed: {e}"))?;
    if !r.ok() {
        // Proxy error pages can echo the x-api-key header back.
        return Err(http::api_error("Parallel", &r, Some(key)));
    }
    r.json()
}

impl WebProvider for Parallel {
    fn id(&self) -> &'static str {
        "parallel"
    }
    fn label(&self) -> &'static str {
        "Parallel Search"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["parallel-free"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("parallel", ENV).is_some()
    }
    fn keyless(&self) -> bool {
        true
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        if self.routes_keyless(c) {
            keyless::endpoint(c, "parallel")
        } else {
            format!("{}/v1/search", base(c).unwrap_or_default())
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://parallel.ai"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("parallel", ENV);
        let free = c.cfg.search_pin() == "parallel-free";
        if free || keyless::use_keyless(c, "parallel", key.as_deref()) {
            return keyless::search_with_failover(c, "parallel", &r.query, r.count).1.map(SearchOutput::Results);
        }
        let key = key.ok_or("web_search (parallel) needs a Parallel API key. Set PARALLEL_API_KEY or [web.providers.parallel] api_key. Get one at https://parallel.ai")?;
        let extra_q: Vec<String> = r.extra.get("search_queries").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let mut queries = normalize_queries(&extra_q);
        if queries.is_empty() {
            queries = normalize_queries(&[r.query.chars().take(5000).collect()]);
        }
        if queries.is_empty() {
            return Err("search_queries must be a non-empty array of keyword strings (max 5, max 200 chars each). See https://docs.parallel.ai/search/best-practices.".into());
        }
        let count = r.count.clamp(1, MAX_COUNT);
        let objective: String = r.extra_str("objective").unwrap_or_else(|| r.query.clone()).chars().take(5000).collect();
        let mut body = json!({"search_queries": queries, "objective": objective, "advanced_settings": {"max_results": count}});
        if let Some(s) = r.extra_str("session_id") {
            body["session_id"] = json!(s.chars().take(1000).collect::<String>());
        }
        if let Some(m) = r.extra_str("client_model") {
            body["client_model"] = json!(m.chars().take(100).collect::<String>());
        }
        if let Some(m) = mode(c) {
            body["mode"] = json!(m);
        }
        Ok(SearchOutput::Results(map(&post(c, "/v1/search", &key, &body, false)?, count)))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        let key = c.key("parallel", ENV);
        if keyless::use_keyless(c, "parallel", key.as_deref()) {
            return Ok(keyless::extract_with_failover(c, "parallel", urls));
        }
        let key = key.ok_or("PARALLEL_API_KEY environment variable not set. Get your API key at https://parallel.ai")?;
        let v = post(c, "/v1beta/extract", &key, &json!({"urls": urls, "full_content": true}), true)?;
        let mut out: Vec<Page> = v.get("results").and_then(|r| r.as_array()).into_iter().flatten().map(|r| {
            let content = Some(http::s(r, "full_content")).filter(|x| !x.is_empty()).unwrap_or_else(|| r.get("excerpts").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join("\n\n")).unwrap_or_default());
            Page::ok(&http::s(r, "url"), &http::s(r, "title"), &content)
        }).collect();
        for e in v.get("errors").and_then(|r| r.as_array()).into_iter().flatten() {
            let u = http::s(e, "url");
            let msg = [http::s(e, "content"), http::s(e, "error_type")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "extraction failed".into());
            out.push(Page { source_url: Some(u.clone()), ..Page::err(&u, msg) });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn search_and_extract() {
        let s = FakeServer::start(vec![
            ("POST /v1/search", 200, "application/json", json!({"search_id":"s1","results":[{"title":"A","url":"https://a.com","excerpts":["e1","e2"],"publish_date":"2025-03-01"}]}).to_string()),
            ("POST /v1beta/extract", 200, "application/json", json!({"results":[{"url":"https://a.com","title":"A","full_content":"FULL"}],"errors":[{"url":"https://b.com","error_type":"fetch_failed"}]}).to_string()),
        ]);
        let c = wctx(json!({"providers":{"parallel":{"base_url":s.url.clone(),"mode":"fast"}}}), &[("PARALLEL_API_KEY", "par-test")]);
        let mut r = SearchRequest { query: "rust async".into(), count: 99, ..Default::default() };
        r.extra.insert("search_queries".into(), json!([" a ", "a", "", "b"]));
        let SearchOutput::Results(h) = Parallel.search(&c, &r).unwrap() else { panic!() };
        assert_eq!((h[0].snippet.as_str(), h[0].published.as_deref()), ("e1\n\ne2", Some("2025-03-01")));
        let q = s.last();
        assert_eq!(q.header("x-api-key").as_deref(), Some("par-test"));
        let b = q.json();
        assert_eq!((b["search_queries"].clone(), b["objective"].as_str(), b["advanced_settings"]["max_results"].as_u64(), b["mode"].as_str()), (json!(["a", "b"]), Some("rust async"), Some(40), Some("fast")));
        let p = Parallel.extract(&c, &["https://a.com".into(), "https://b.com".into()]).unwrap();
        assert_eq!((p[0].content.as_str(), p[1].error.as_deref()), ("FULL", Some("fetch_failed")));
        assert_eq!(s.last().header("parallel-beta").as_deref(), Some("search-extract-2025-10-10"));
        assert_eq!(normalize_queries(&["x".repeat(300), "1".into(), "2".into(), "3".into(), "4".into(), "5".into()]).len(), 5);
    }

    #[test]
    fn keyless_and_errors() {
        let text = json!({"results":[{"url":"https://free.com","title":"F"}]}).to_string();
        let mcp = FakeServer::start(vec![("POST /mcp", 200, "application/json", json!({"result":{"content":[{"text":text}]}}).to_string())]);
        let c = wctx(json!({"search":{"provider":"parallel-free"},"providers":{"parallel":{"keyless_url":format!("{}/mcp",mcp.url)}}}), &[("PARALLEL_API_KEY", "k")]);
        let SearchOutput::Results(h) = Parallel.search(&c, &SearchRequest { query: "q".into(), count: 2, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h[0].url, "https://free.com");
        let bad = FakeServer::start(vec![("POST /v1/search", 401, "text/plain", "bad x-api-key: par-test".into())]);
        let c = wctx(json!({"providers":{"parallel":{"base_url":bad.url.clone()}}}), &[("PARALLEL_API_KEY", "par-test")]);
        assert_eq!(Parallel.search(&c, &SearchRequest { query: "q".into(), count: 2, ..Default::default() }).unwrap_err(), "Parallel API error (401): bad x-api-key: ***");
    }
}
