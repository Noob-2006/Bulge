//! Tavily search + extract (`/search`, `/extract`). Hermes `plugins/web/tavily` (opt-in keyless
//! access when Tavily is selected without a key, `TAVILY_BASE_URL`) + OpenClaw `extensions/tavily`
//! (search_depth / topic / include_answer / time_range / domain filters, result URL and date
//! normalisation; the dedicated `tavily_search` / `tavily_extract` tools live in `web::vendor_tools`).

use super::{site_name, Hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::keyless;
use serde_json::{json, Value};

pub struct Tavily;

const ENV: &[&str] = &["TAVILY_API_KEY"];
const DEFAULT_BASE: &str = "https://api.tavily.com";
const SEARCH_MAX_CONTENT: usize = 20_000;
/// OpenClaw `TAVILY_EXTRACT_MAX_RESULTS`: URLs per extract call, results and images kept.
pub const EXTRACT_MAX_RESULTS: usize = 20;

fn base(c: &WebCtx) -> String {
    c.base_url("tavily", Some("TAVILY_BASE_URL"), DEFAULT_BASE)
}

/// `(key, keyless)`: the key to send ("" = keyless), or the missing-key error.
fn auth(c: &WebCtx, action: &str) -> Result<(String, bool), String> {
    let key = c.key("tavily", ENV);
    if keyless::use_keyless(c, "tavily", key.as_deref()) && (c.cfg.selects("tavily") || c.cfg.tier("tavily") == "free") {
        return Ok((String::new(), true));
    }
    key.map(|k| (k, false)).ok_or_else(|| format!("TAVILY_API_KEY is not set. Get a key at https://app.tavily.com/home or select Tavily ([web.search] provider = \"tavily\") for opt-in keyless {action}."))
}

fn post(c: &WebCtx, path: &str, body: &Value, label: &str, timeout: u64, action: &str) -> Result<Value, String> {
    let (key, _) = auth(c, action)?;
    let mut h = vec![("X-Client-Name", "seagent".to_string()), ("X-Client-Source", "seagent".to_string()), ("Accept", "application/json".to_string())];
    if key.is_empty() {
        h.push(("X-Tavily-Access-Mode", "keyless".into()));
    } else {
        h.push(super::bearer(&key));
    }
    c.check_cancel()?;
    let r = http::post_json(&format!("{}{path}", base(c)), &h, body, timeout).map_err(|e| format!("Could not reach Tavily: {e}"))?;
    if !r.ok() {
        // Tavily's own rate-limit / upgrade text must reach the model.
        return Err(http::api_error(label, &r, Some(&key)));
    }
    r.json()
}

/// Only http(s) URLs up to 2 048 chars (OpenClaw `normalizeTavilyResultUrl`).
pub fn result_url(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    (s.len() <= 2048 && (s.starts_with("http://") || s.starts_with("https://")) && crate::web::ssrf::parse_url(s).is_ok()).then(|| s.to_string())
}

/// `YYYY-MM-DD[...]` with a real calendar date, or an RFC 1123 GMT date converted to ISO.
pub fn published(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    if s.len() > 31 {
        return None;
    }
    if s.len() >= 10 && super::valid_iso_date(&s[..10]) && s[10..].chars().all(|c| c.is_ascii_digit() || " T:.+Z-".contains(c)) {
        return Some(s.to_string());
    }
    // "Tue, 03 Jun 2025 10:00:00 GMT"
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() == 6 && p[5] == "GMT" {
        const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let m = M.iter().position(|x| *x == p[2])? + 1;
        let iso = format!("{}-{m:02}-{:0>2}", p[3], p[1]);
        let t: Vec<&str> = p[4].split(':').collect();
        if super::valid_iso_date(&iso) && t.len() == 3 && t.iter().all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_digit())) {
            return Some(format!("{iso}T{}.000Z", p[4]));
        }
    }
    None
}

#[derive(Debug, Default, Clone)]
pub struct SearchParams {
    pub query: String,
    pub max_results: usize,
    pub search_depth: Option<String>,
    pub topic: Option<String>,
    pub include_answer: bool,
    pub time_range: Option<String>,
    pub include_domains: Vec<String>,
    pub exclude_domains: Vec<String>,
}

/// `(hits, answer, truncated)`.
pub fn run_search(c: &WebCtx, p: &SearchParams) -> Result<(Vec<Hit>, Option<String>, bool), String> {
    let (rows, answer, truncated) = run_search_scored(c, p)?;
    Ok((rows.into_iter().map(|(h, _)| h).collect(), answer, truncated))
}

/// Search rows with each result's relevance `score` kept, plus the answer and a truncation flag.
pub type ScoredSearch = (Vec<(Hit, Option<f64>)>, Option<String>, bool);

/// `run_search` keeping each result's relevance `score` (the `tavily_search` tool reports it).
pub fn run_search_scored(c: &WebCtx, p: &SearchParams) -> Result<ScoredSearch, String> {
    let count = p.max_results.clamp(1, 20);
    let mut body = json!({"query": p.query, "max_results": count, "include_raw_content": false, "include_images": false});
    for (k, v) in [("search_depth", &p.search_depth), ("topic", &p.topic), ("time_range", &p.time_range)] {
        if let Some(v) = v {
            body[k] = json!(v);
        }
    }
    if p.include_answer {
        body["include_answer"] = json!(true);
    }
    if !p.include_domains.is_empty() {
        body["include_domains"] = json!(p.include_domains);
    }
    if !p.exclude_domains.is_empty() {
        body["exclude_domains"] = json!(p.exclude_domains);
    }
    let v = post(c, "/search", &body, "Tavily Search", c.opt_u64("tavily", "timeout_seconds").unwrap_or(30), "search")?;
    let rows = v.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let mut budget = SEARCH_MAX_CONTENT;
    let mut truncated = rows.len() > count;
    let mut take = |s: &str| -> String {
        let t = crate::util::truncate_str(s, budget).to_string();
        truncated |= t.len() < s.len();
        budget -= t.len();
        t
    };
    let hits = rows
        .iter()
        .take(count)
        .filter_map(|e| {
            let url = result_url(e.get("url")?)?;
            Some((Hit { title: take(&http::s(e, "title")), snippet: take(&http::s(e, "content")), published: e.get("published_date").and_then(published), site_name: site_name(&url), url }, e.get("score").and_then(|x| x.as_f64())))
        })
        .collect();
    let answer = v.get("answer").and_then(|a| a.as_str()).filter(|a| !a.is_empty()).map(take);
    Ok((hits, answer, truncated))
}

#[derive(Debug, Default, Clone)]
pub struct ExtractParams {
    pub urls: Vec<String>,
    pub query: Option<String>,
    pub extract_depth: Option<String>,
    pub chunks_per_source: Option<u64>,
    pub include_images: bool,
}

pub fn run_extract(c: &WebCtx, p: &ExtractParams) -> Result<Value, String> {
    let mut body = json!({"urls": p.urls});
    if p.include_images {
        body["include_images"] = json!(true);
    }
    if let Some(q) = &p.query {
        body["query"] = json!(q);
    }
    if let Some(d) = &p.extract_depth {
        body["extract_depth"] = json!(d);
    }
    if let Some(n) = p.chunks_per_source {
        body["chunks_per_source"] = json!(n);
    }
    post(c, "/extract", &body, "Tavily Extract", c.opt_u64("tavily", "extract_timeout_seconds").unwrap_or(60), "extract")
}

fn pages(v: &Value) -> Vec<Page> {
    let mut out: Vec<Page> = v.get("results").and_then(|r| r.as_array()).into_iter().flatten().map(|r| {
        let content = Some(http::s(r, "raw_content")).filter(|x| !x.is_empty()).unwrap_or_else(|| http::s(r, "content"));
        Page::ok(&http::s(r, "url"), &http::s(r, "title"), &content)
    }).collect();
    for f in v.get("failed_results").and_then(|r| r.as_array()).into_iter().flatten() {
        let u = http::s(f, "url");
        out.push(Page { source_url: Some(u.clone()), ..Page::err(&u, Some(http::s(f, "error")).filter(|e| !e.is_empty()).unwrap_or_else(|| "extraction failed".into())) });
    }
    for u in v.get("failed_urls").and_then(|r| r.as_array()).into_iter().flatten() {
        let u = u.as_str().map(str::to_string).unwrap_or_else(|| u.to_string());
        out.push(Page { source_url: Some(u.clone()), ..Page::err(&u, "extraction failed") });
    }
    out
}

impl WebProvider for Tavily {
    fn id(&self) -> &'static str {
        "tavily"
    }
    fn label(&self) -> &'static str {
        "Tavily Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("tavily", ENV).is_some() || c.cfg.selects("tavily")
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/search", base(c))
    }
    fn signup_url(&self) -> &'static str {
        "https://app.tavily.com/home"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let p = SearchParams {
            query: r.query.clone(),
            max_results: r.count,
            search_depth: r.extra_str("search_depth"),
            topic: r.extra_str("topic"),
            time_range: r.extra_str("time_range"),
            ..Default::default()
        };
        Ok(SearchOutput::Results(run_search(c, &p)?.0))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        Ok(pages(&run_extract(c, &ExtractParams { urls: urls.to_vec(), ..Default::default() })?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    fn srv() -> FakeServer {
        FakeServer::start(vec![
            ("POST /search", 200, "application/json", json!({"answer":"Short answer","results":[{"title":"A","url":"https://a.com/x","content":"ca","score":0.9,"published_date":"Tue, 03 Jun 2025 10:00:00 GMT"},{"title":"bad","url":"javascript:alert(1)"},{"title":"B","url":"https://b.com","content":"cb","published_date":"2025-02-30"}]}).to_string()),
            ("POST /extract", 200, "application/json", json!({"results":[{"url":"https://a.com","title":"A","raw_content":"raw a","images":["https://a.com/i.png","nope"]}],"failed_results":[{"url":"https://b.com","error":"blocked"}],"failed_urls":["https://c.com"]}).to_string()),
        ])
    }

    #[test]
    fn search_request_and_normalisation() {
        let s = srv();
        let c = wctx(json!({"providers":{"tavily":{"base_url":s.url.clone()}}}), &[("TAVILY_API_KEY", "tvly-test")]);
        let mut r = SearchRequest { query: "q".into(), count: 50, ..Default::default() };
        r.extra.insert("topic".into(), json!("news"));
        let SearchOutput::Results(h) = Tavily.search(&c, &r).unwrap() else { panic!() };
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].published.as_deref(), Some("2025-06-03T10:00:00.000Z"));
        assert_eq!(h[1].published, None, "impossible calendar date dropped");
        let q = s.last();
        assert_eq!(q.header("authorization").as_deref(), Some("Bearer tvly-test"));
        let b = q.json();
        assert_eq!((b["max_results"].as_u64(), b["topic"].as_str(), b["include_raw_content"].as_bool()), (Some(20), Some("news"), Some(false)));
    }

    #[test]
    fn keyless_when_selected_without_key() {
        let s = srv();
        let c = wctx(json!({"search":{"provider":"tavily"},"providers":{"tavily":{"base_url":s.url.clone()}}}), &[]);
        assert!(Tavily.configured(&c));
        Tavily.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap();
        assert_eq!(s.last().header("x-tavily-access-mode").as_deref(), Some("keyless"));
        assert!(s.last().header("authorization").is_none());
        let c = wctx(json!({"providers":{"tavily":{"base_url":s.url.clone()}}}), &[]);
        assert!(!Tavily.configured(&c));
        assert!(Tavily.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap_err().contains("TAVILY_API_KEY is not set"));
    }

    #[test]
    fn extract_pages_and_errors() {
        let s = srv();
        let c = wctx(json!({"providers":{"tavily":{"base_url":s.url.clone(),"api_key":"tvly-test"}}}), &[]);
        let p = Tavily.extract(&c, &["https://a.com".into(), "https://b.com".into(), "https://c.com".into()]).unwrap();
        assert_eq!((p.len(), p[0].content.as_str(), p[1].error.as_deref(), p[2].error.as_deref()), (3, "raw a", Some("blocked"), Some("extraction failed")));
        let bad = FakeServer::start(vec![("POST /search", 432, "application/json", r#"{"detail":"plan limit for tvly-test"}"#.into())]);
        let c = wctx(json!({"providers":{"tavily":{"base_url":bad.url.clone()}}}), &[("TAVILY_API_KEY", "tvly-test")]);
        assert_eq!(Tavily.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err(), r#"Tavily Search API error (432): {"detail":"plan limit for ***"}"#);
    }
}
