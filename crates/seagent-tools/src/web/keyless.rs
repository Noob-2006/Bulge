//! Keyless web search/extract via public free tiers (Hermes `plugins/web/keyless_mcp.py`):
//! Exa and Parallel hosted MCP servers, Firecrawl's anonymous cloud API and Keenable's
//! public endpoints. Strictly the last autodetect rung and the one-shot rescue for a
//! failed configured backend. Unpinned requests round-robin across the ring; rate limits
//! and vendor refusals (401/402/403/5xx) fail over to the next vendor. No user identifiers
//! are sent; Parallel gets a random per-process session id. Off with `web.keyless_fallback = false`.

use super::http::{self, WebCtx};
use super::providers::{hit, Hit, Page};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub const RING: [&str; 4] = ["exa", "parallel", "firecrawl", "keenable"];
const TIMEOUT: u64 = 30;

const EXA_MCP_URL: &str = "https://mcp.exa.ai/mcp";
const PARALLEL_MCP_URL: &str = "https://search.parallel.ai/mcp";
const FIRECRAWL_CLOUD: &str = "https://api.firecrawl.dev";
const KEENABLE_API_URL: &str = "https://api.keenable.ai";

fn session_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16)))
}

fn cursor() -> &'static AtomicUsize {
    static C: OnceLock<AtomicUsize> = OnceLock::new();
    C.get_or_init(|| AtomicUsize::new(seagent_net::crypto::random_bytes(1)[0] as usize % RING.len()))
}

/// Endpoint of a ring vendor's free tier (`[web.providers.<v>] keyless_url` overrides, for tests / mirrors).
pub fn endpoint(c: &WebCtx, vendor: &str) -> String {
    let default = match vendor {
        "exa" => EXA_MCP_URL,
        "parallel" => PARALLEL_MCP_URL,
        "firecrawl" => FIRECRAWL_CLOUD,
        _ => KEENABLE_API_URL,
    };
    c.opt(vendor, "keyless_url").unwrap_or_else(|| default.to_string()).trim_end_matches('/').to_string()
}

pub fn enabled(c: &WebCtx) -> bool {
    c.cfg.keyless_fallback
}

/// Single chokepoint (Hermes `use_keyless`): `free` → keyless even with a key; `paid` → keyed
/// (missing-key error); `auto` → keyless only without a key and with the tier enabled.
pub fn use_keyless(c: &WebCtx, vendor: &str, key: Option<&str>) -> bool {
    match c.cfg.tier(vendor) {
        "free" => true,
        "paid" => false,
        _ => key.is_none_or(|k| k.trim().is_empty()) && enabled(c),
    }
}

/// A ring vendor can serve this capability anonymously right now.
pub fn available(c: &WebCtx, vendor: &str) -> bool {
    RING.contains(&vendor) && enabled(c) && c.cfg.tier(vendor) != "paid"
}

const RATE_LIMIT_MARKERS: &[&str] = &["rate limit", "rate-limit", "ratelimit", "too many requests", "429", "quota exceeded", "slow down"];

pub fn is_rate_limitish(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    RATE_LIMIT_MARKERS.iter().any(|x| m.contains(x))
}

/// Rate limits and structured 401/402/403/5xx refusals are local to one free endpoint.
pub fn search_failover_eligible(msg: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)^\s*(?:keyless\s+\w+\s+search\s+failed:\s*)?(?:http(?:\s+status)?|status(?:\s+code)?|client\s+error|error\s+code)\s*[:=']*\s*(?:40[123]|5\d\d)\b").unwrap());
    is_rate_limitish(msg) || re.is_match(msg)
}

fn hint(vendor: &str) -> (&'static str, &'static str, &'static str) {
    match vendor {
        "exa" => ("Exa", "EXA_API_KEY", "https://exa.ai"),
        "parallel" => ("Parallel", "PARALLEL_API_KEY", "https://parallel.ai"),
        "firecrawl" => ("Firecrawl", "FIRECRAWL_API_KEY", "https://firecrawl.dev"),
        _ => ("Keenable", "KEENABLE_API_KEY", "https://keenable.ai"),
    }
}

fn fail_msg(vendor: &str, kind: &str, e: &str, other: bool) -> String {
    let (label, env, site) = hint(vendor);
    let alt = if other { " or another web backend via [web] search.provider" } else { "" };
    format!("Keyless {label} {kind} failed: {e}. Set {env} ({site}){alt} for reliable service.")
}

// ── MCP transport ──────────────────────────────────────────────────────────────

/// First text item of an MCP `tools/call` result: plain JSON (Parallel) or SSE `data:` lines (Exa).
pub fn parse_mcp_body(body: &str) -> Result<String, String> {
    let from = |payload: &str| -> Result<Option<String>, String> {
        let p = payload.trim();
        if !p.starts_with('{') {
            return Ok(None);
        }
        let Ok(d) = serde_json::from_str::<Value>(p) else { return Ok(None) };
        if let Some(e) = d.get("error").filter(|e| !e.is_null()) {
            return Err(e.get("message").and_then(|m| m.as_str()).map(str::to_string).unwrap_or_else(|| e.to_string()));
        }
        let res = d.get("result").cloned().unwrap_or(Value::Null);
        let texts: Vec<String> = res.get("content").and_then(|c| c.as_array()).into_iter().flatten().filter_map(|c| c.get("text").and_then(|t| t.as_str()).map(str::to_string)).collect();
        if res.get("isError").and_then(|b| b.as_bool()) == Some(true) {
            let t = texts.iter().filter(|t| !t.is_empty()).cloned().collect::<Vec<_>>().join(" ");
            return Err(if t.is_empty() { "MCP tool call failed".into() } else { t });
        }
        Ok(Some(texts.into_iter().find(|t| !t.is_empty()).unwrap_or_default()))
    };
    let stripped = body.trim();
    let mut cands: Vec<&str> = if stripped.starts_with('{') { vec![stripped] } else { vec![] };
    // SSE line terminators only (CRLF, CR, LF): CJK page text may hold U+2028 etc.
    cands.extend(body.split(['\n', '\r']).filter_map(|l| l.strip_prefix("data: ")));
    let mut seen_envelope = false;
    for c in cands {
        match from(c)? {
            Some(t) if !t.is_empty() => return Ok(t),
            Some(_) => seen_envelope = true,
            None => {}
        }
    }
    Err(if seen_envelope { "MCP response contained no text content".into() } else { "Unrecognized MCP response shape".into() })
}

pub fn mcp_call(url: &str, tool: &str, args: Value) -> Result<String, String> {
    let payload = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}});
    let r = http::post_json(url, &[("Accept", "application/json, text/event-stream".into()), ("User-Agent", "seagent".into())], &payload, TIMEOUT).map_err(|e| format!("request failed: {e}"))?;
    if r.status >= 400 {
        return Err(format!("HTTP {}: {}", r.status, crate::util::truncate_str(&r.body, 300)));
    }
    parse_mcp_body(&r.body)
}

// ── vendors ─────────────────────────────────────────────────────────────────────

fn parallel_search(c: &WebCtx, q: &str, limit: usize) -> Result<Vec<Hit>, String> {
    let text = mcp_call(&endpoint(c, "parallel"), "web_search", json!({"objective":q,"search_queries":[q],"session_id":session_id()})).map_err(|e| fail_msg("parallel", "search", &e, true))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("Keyless Parallel search returned an unexpected payload: {e}"))?;
    let rows = v.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    Ok(rows.iter().take(if limit == 0 { usize::MAX } else { limit }).map(|r| hit(&http::s(r, "title"), &http::s(r, "url"), &join_strs(r.get("excerpts")))).collect())
}

fn join_strs(v: Option<&Value>) -> String {
    v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default()
}

fn parallel_extract(c: &WebCtx, urls: &[String]) -> Vec<Page> {
    let res = mcp_call(&endpoint(c, "parallel"), "web_fetch", json!({"urls":urls,"objective":"Full page content","session_id":session_id()})).and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()));
    let data = match res {
        Ok(d) => d,
        Err(e) => {
            let m = fail_msg("parallel", "extract", &e, true);
            return urls.iter().map(|u| Page::err(u, m.clone())).collect();
        }
    };
    let mut out: Vec<Page> = data
        .get("results")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
        .map(|r| {
            let content = [http::s(r, "full_content"), http::s(r, "content")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| join_strs(r.get("excerpts")).replace("  ", "\n\n"));
            Page::ok(&http::s(r, "url"), &http::s(r, "title"), &content)
        })
        .collect();
    for e in data.get("errors").and_then(|r| r.as_array()).into_iter().flatten() {
        let url = http::s(e, "url");
        let msg = [http::s(e, "content"), http::s(e, "error_type")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "extraction failed".into());
        out.push(Page { source_url: Some(url.clone()), ..Page::err(&url, msg) });
    }
    for u in urls {
        if !out.iter().any(|p| &p.url == u) {
            out.push(Page::err(u, "no content returned"));
        }
    }
    out
}

/// Exa's `---`-separated `Title:/URL:/Published:/Author:/Highlights:` blocks.
pub fn parse_exa_text(text: &str, limit: usize) -> Vec<Hit> {
    const LABELS: [&str; 5] = ["Title:", "URL:", "Highlights:", "Published:", "Author:"];
    let mut out = Vec::new();
    for block in text.split("\n---\n") {
        let (mut title, mut url, mut hl, mut in_hl) = (String::new(), String::new(), Vec::new(), false);
        for line in block.lines().map(str::trim) {
            if let Some(t) = line.strip_prefix("Title:") {
                title = t.trim().into();
            } else if let Some(u) = line.strip_prefix("URL:") {
                url = u.trim().into();
            } else if in_hl && !line.is_empty() && !LABELS.iter().any(|l| line.starts_with(l)) {
                hl.push(line.to_string());
            }
            if LABELS.iter().any(|l| line.starts_with(l)) {
                in_hl = line.starts_with("Highlights:");
            }
        }
        if !url.is_empty() {
            out.push(hit(&title, &url, &hl.join(" ")));
        }
        if limit > 0 && out.len() >= limit {
            break;
        }
    }
    out
}

fn exa_search(c: &WebCtx, q: &str, limit: usize) -> Result<Vec<Hit>, String> {
    let t = mcp_call(&endpoint(c, "exa"), "web_search_exa", json!({"query":q,"numResults":limit.max(1)})).map_err(|e| fail_msg("exa", "search", &e, true))?;
    Ok(parse_exa_text(&t, limit))
}

fn exa_extract(c: &WebCtx, urls: &[String]) -> Vec<Page> {
    urls.iter()
        .map(|u| match mcp_call(&endpoint(c, "exa"), "web_fetch_exa", json!({"urls":[u]})) {
            Ok(text) => {
                let title = text.lines().map(str::trim).find_map(|l| l.strip_prefix("# ").or_else(|| l.strip_prefix("Title:"))).unwrap_or("").trim().to_string();
                Page::ok(u, &title, &text)
            }
            Err(e) => Page::err(u, fail_msg("exa", "extract", &e, false)),
        })
        .collect()
}

/// Firecrawl search rows across response shapes (`data: [...]`, `data.web`, `web`, `results`).
pub fn firecrawl_rows(v: &Value) -> Vec<Value> {
    if let Some(a) = v.get("data").and_then(|d| d.as_array()) {
        return a.clone();
    }
    let d = v.get("data");
    for cand in [d.and_then(|d| d.get("web")), d.and_then(|d| d.get("results")), v.get("web"), v.get("results")].into_iter().flatten() {
        if let Some(a) = cand.as_array().filter(|a| !a.is_empty()) {
            return a.clone();
        }
    }
    vec![]
}

pub fn firecrawl_hit(r: &Value) -> Hit {
    let snippet = [http::s(r, "description"), http::s(r, "snippet"), http::s(r, "markdown")].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
    hit(&http::s(r, "title"), &http::s(r, "url"), crate::util::truncate_str(&snippet, 1000))
}

fn firecrawl_post(c: &WebCtx, path: &str, body: Value) -> Result<Value, String> {
    let r = http::post_json(&format!("{}{path}", endpoint(c, "firecrawl")), &[], &body, 60).map_err(|e| format!("request failed: {e}"))?;
    if r.status >= 400 {
        return Err(format!("HTTP {}: {}", r.status, crate::util::truncate_str(r.body.trim(), 300)));
    }
    r.json()
}

fn firecrawl_search(c: &WebCtx, q: &str, limit: usize) -> Result<Vec<Hit>, String> {
    let v = firecrawl_post(c, "/v2/search", json!({"query":q,"limit":limit.max(1)})).map_err(|e| fail_msg("firecrawl", "search", &e, true))?;
    Ok(firecrawl_rows(&v).iter().map(firecrawl_hit).collect())
}

fn firecrawl_extract(c: &WebCtx, urls: &[String]) -> Vec<Page> {
    urls.iter()
        .map(|u| match firecrawl_post(c, "/v2/scrape", json!({"url":u,"formats":["markdown"]})) {
            Ok(v) => {
                let d = v.get("data").filter(|d| d.is_object()).unwrap_or(&v);
                let title = d.get("metadata").map(|m| http::s(m, "title")).unwrap_or_default();
                let body = [http::s(d, "markdown"), http::s(d, "html")].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
                Page::ok(u, &title, &body)
            }
            Err(e) => Page::err(u, fail_msg("firecrawl", "extract", &e, false)),
        })
        .collect()
}

fn keenable(c: &WebCtx, post: bool, path: &str, body: Value, query: &[(&str, String)]) -> Result<Value, String> {
    let url = format!("{}{path}", endpoint(c, "keenable"));
    let h = [("X-Keenable-Title", "seagent".to_string())];
    let r = if post { http::post_json(&url, &h, &body, TIMEOUT) } else { http::get(&url, query, &h, TIMEOUT) }?;
    if r.status >= 400 {
        return Err(format!("HTTP {}: {}", r.status, crate::util::truncate_str(r.body.trim(), 300)));
    }
    r.json()
}

fn keenable_search(c: &WebCtx, q: &str, limit: usize) -> Result<Vec<Hit>, String> {
    let v = keenable(c, true, "/v1/search/public", json!({"query":q,"max_results":limit.max(1)}), &[]).map_err(|e| format!("Keyless Keenable search failed: {e}."))?;
    Ok(v.get("results").and_then(|r| r.as_array()).into_iter().flatten().map(|r| hit(&http::s(r, "title"), &http::s(r, "url"), &[http::s(r, "snippet"), http::s(r, "description")].into_iter().find(|x| !x.is_empty()).unwrap_or_default())).collect())
}

fn keenable_extract(c: &WebCtx, urls: &[String]) -> Vec<Page> {
    urls.iter()
        .map(|u| match keenable(c, false, "/v1/fetch/public", Value::Null, &[("url", u.clone())]) {
            Ok(d) => {
                let url = Some(http::s(&d, "url")).filter(|x| !x.is_empty()).unwrap_or_else(|| u.clone());
                Page { source_url: Some(u.clone()), ..Page::ok(&url, &http::s(&d, "title"), &http::s(&d, "content")) }
            }
            Err(e) => Page::err(u, fail_msg("keenable", "extract", &e, false)),
        })
        .collect()
}

fn search_one(c: &WebCtx, vendor: &str, q: &str, limit: usize) -> Result<Vec<Hit>, String> {
    match vendor {
        "exa" => exa_search(c, q, limit),
        "parallel" => parallel_search(c, q, limit),
        "firecrawl" => firecrawl_search(c, q, limit),
        _ => keenable_search(c, q, limit),
    }
}

fn extract_one(c: &WebCtx, vendor: &str, urls: &[String]) -> Vec<Page> {
    match vendor {
        "exa" => exa_extract(c, urls),
        "parallel" => parallel_extract(c, urls),
        "firecrawl" => firecrawl_extract(c, urls),
        _ => keenable_extract(c, urls),
    }
}

// ── ring ─────────────────────────────────────────────────────────────────────────

/// Walk order: a pinned vendor starts the walk; else round-robin from the cursor.
/// Vendors pinned `paid` are left out.
pub fn ring_order(c: &WebCtx, name: &str) -> Vec<&'static str> {
    let pinned = c.cfg.tier(name) == "free" || c.cfg.selects(name) || c.cfg.selects(&format!("{name}-free"));
    let start = if pinned && RING.contains(&name) { RING.iter().position(|v| *v == name).unwrap_or(0) } else { cursor().fetch_add(1, Ordering::Relaxed) % RING.len() };
    (0..RING.len()).map(|i| RING[(start + i) % RING.len()]).filter(|v| c.cfg.tier(v) != "paid").collect()
}

const ALL_PAID: &str = "All keyless web providers are pinned to paid tiers.";

/// `(served_by, result)`. Throttles fail over; other errors stop the walk.
pub fn search_with_failover(c: &WebCtx, name: &str, q: &str, limit: usize) -> (String, Result<Vec<Hit>, String>) {
    let order = ring_order(c, name);
    if order.is_empty() {
        return (name.into(), Err(ALL_PAID.into()));
    }
    let mut last = (order[0].to_string(), Err(String::new()));
    for v in &order {
        if c.cancel.is_cancelled() {
            return (v.to_string(), Err("Interrupted".into()));
        }
        let r = search_one(c, v, q, limit);
        match &r {
            Err(e) if search_failover_eligible(e) => last = (v.to_string(), r),
            _ => return (v.to_string(), r),
        }
    }
    let (v, r) = last;
    (v, r.map_err(|e| format!("{e} (all keyless vendors unavailable: {})", order.join(", "))))
}

/// Fails over only when EVERY url in the batch came back rate-limited.
pub fn extract_with_failover(c: &WebCtx, name: &str, urls: &[String]) -> Vec<Page> {
    let order = ring_order(c, name);
    if order.is_empty() {
        return urls.iter().map(|u| Page::err(u, ALL_PAID)).collect();
    }
    let mut last = Vec::new();
    for v in &order {
        last = extract_one(c, v, urls);
        let throttled = !last.is_empty() && last.iter().all(|p| p.error.as_deref().is_some_and(is_rate_limitish));
        if !throttled {
            break;
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    fn sse(text: &str) -> String {
        format!("event: message\ndata: {}\n\n", json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":text}]}}))
    }

    #[test]
    fn mcp_bodies() {
        assert_eq!(parse_mcp_body(&sse("hi 中文\u{2028}x")).unwrap(), "hi 中文\u{2028}x");
        assert_eq!(parse_mcp_body(r#"{"result":{"content":[{"text":"plain"}]}}"#).unwrap(), "plain");
        assert_eq!(parse_mcp_body(r#"{"error":{"message":"rate limit"}}"#).unwrap_err(), "rate limit");
        assert_eq!(parse_mcp_body(r#"{"result":{"isError":true,"content":[{"text":"429 slow down"}]}}"#).unwrap_err(), "429 slow down");
        assert_eq!(parse_mcp_body(r#"{"result":{"content":[]}}"#).unwrap_err(), "MCP response contained no text content");
        assert_eq!(parse_mcp_body("<html>").unwrap_err(), "Unrecognized MCP response shape");
    }

    #[test]
    fn classification_and_tiers() {
        assert!(is_rate_limitish("HTTP 429: Too Many Requests") && search_failover_eligible("HTTP 503: down") && search_failover_eligible("Keyless Exa search failed: HTTP 403: nope"));
        assert!(!search_failover_eligible("HTTP 400: invalid query 'http 503'"));
        let c = wctx(json!({"provider_tier":{"exa":"free","parallel":"paid"}}), &[]);
        assert!(use_keyless(&c, "exa", Some("k")) && !use_keyless(&c, "parallel", None) && use_keyless(&c, "keenable", None) && !use_keyless(&c, "keenable", Some("k")));
        assert!(!available(&c, "parallel") && available(&c, "exa"));
        assert_eq!(ring_order(&c, "exa"), vec!["exa", "firecrawl", "keenable"]);
        let off = wctx(json!({"keyless_fallback":false}), &[]);
        assert!(!use_keyless(&off, "exa", None));
        let all_paid = wctx(json!({"provider_tier":{"exa":"paid","parallel":"paid","firecrawl":"paid","keenable":"paid"}}), &[]);
        assert_eq!(search_with_failover(&all_paid, "exa", "q", 3).1.unwrap_err(), ALL_PAID);
    }

    #[test]
    fn ring_failover_across_vendors() {
        // exa throttled → parallel serves.
        let exa = FakeServer::start(vec![("POST /mcp", 429, "text/plain", "Too Many Requests".into())]);
        let par_text = json!({"results":[{"url":"https://p.com","title":"P","excerpts":["one","two"]}]}).to_string();
        let par = FakeServer::start(vec![("POST /mcp", 200, "application/json", json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":par_text}]}}).to_string())]);
        let c = wctx(json!({"backend":"exa","providers":{"exa":{"keyless_url":format!("{}/mcp",exa.url)},"parallel":{"keyless_url":format!("{}/mcp",par.url)}}}), &[]);
        let (by, r) = search_with_failover(&c, "exa", "rust", 3);
        assert_eq!(by, "parallel");
        assert_eq!(r.unwrap()[0].snippet, "one two");
        let call = par.last().json();
        assert_eq!(call["params"]["name"], "web_search");
        assert_eq!(call["params"]["arguments"]["objective"], "rust");
        assert_eq!(call["params"]["arguments"]["session_id"].as_str().unwrap().len(), 32);
        // A terminal error stops the walk.
        let bad = FakeServer::start(vec![("POST /mcp", 400, "text/plain", "bad query".into())]);
        let c = wctx(json!({"backend":"exa","providers":{"exa":{"keyless_url":format!("{}/mcp",bad.url)}}}), &[]);
        let (by, r) = search_with_failover(&c, "exa", "q", 3);
        assert_eq!(by, "exa");
        assert!(r.unwrap_err().starts_with("Keyless Exa search failed: HTTP 400"));
    }

    #[test]
    fn vendor_parsers() {
        let text = "Title: A\nURL: https://a.com\nPublished: 2024\nHighlights:\nfirst\nsecond\nAuthor: x\n---\nTitle: B\nURL: https://b.com\n";
        let h = parse_exa_text(text, 5);
        assert_eq!((h.len(), h[0].snippet.as_str(), h[1].url.as_str()), (2, "first second", "https://b.com"));
        assert_eq!(parse_exa_text(text, 1).len(), 1);
        assert_eq!(firecrawl_rows(&json!({"data":{"web":[{"url":"u"}]}})).len(), 1);
        assert_eq!(firecrawl_rows(&json!({"results":[{"url":"u"}]})).len(), 1);
        assert_eq!(firecrawl_hit(&json!({"url":"https://f.com","title":"F","markdown":"md"})).snippet, "md");
    }

    #[test]
    fn extract_vendors() {
        let fc = FakeServer::start(vec![("POST /v2/scrape", 200, "application/json", json!({"data":{"markdown":"# Hi","metadata":{"title":"Hi"}}}).to_string())]);
        let ke = FakeServer::start(vec![("GET /v1/fetch/public", 200, "application/json", json!({"url":"https://final.com","title":"K","content":"body"}).to_string())]);
        let c = wctx(json!({"backend":"firecrawl","providers":{"firecrawl":{"keyless_url":fc.url.clone()},"keenable":{"keyless_url":ke.url.clone()}}}), &[]);
        let p = extract_with_failover(&c, "firecrawl", &["https://x.com".into()]);
        assert_eq!((p[0].title.as_str(), p[0].content.as_str()), ("Hi", "# Hi"));
        assert_eq!(fc.last().json()["formats"], json!(["markdown"]));
        let p = keenable_extract(&c, &["https://x.com".into()]);
        assert_eq!((p[0].url.as_str(), p[0].source_url.as_deref()), ("https://final.com", Some("https://x.com")));
        assert_eq!(ke.last().header("x-keenable-title").as_deref(), Some("seagent"));
        // Parallel drops a URL silently → per-URL error entry.
        let pt = json!({"results":[{"url":"https://a.com","title":"A","full_content":"full"}],"errors":[{"url":"https://b.com","error_type":"timeout"}]}).to_string();
        let par = FakeServer::start(vec![("POST /mcp", 200, "application/json", json!({"result":{"content":[{"text":pt}]}}).to_string())]);
        let c = wctx(json!({"providers":{"parallel":{"keyless_url":format!("{}/mcp",par.url)}}}), &[]);
        let p = parallel_extract(&c, &["https://a.com".into(), "https://b.com".into(), "https://c.com".into()]);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].error.as_deref(), Some("timeout"));
        assert_eq!(p[2].error.as_deref(), Some("no content returned"));
    }
}
