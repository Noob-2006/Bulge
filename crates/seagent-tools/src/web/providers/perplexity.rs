//! Perplexity. Two transports (OpenClaw `extensions/perplexity`): the native Search API
//! (`POST /search`: country, language, freshness → recency, M/D/YYYY date filters, domain
//! allow/deny list, max_tokens / max_tokens_per_page) and Sonar chat completions (OpenRouter
//! keys or a `base_url` / `model` override; answer + citations). Hermes `plugins/web/perplexity`
//! adds `search_context_size: low`, PERPLEXITY_BASE_URL and extract via
//! `POST /sdk/content/snippets` with a relevance query from the URL path words.
//! The Nous managed gateway route (proprietary subscription) is not ported.

use super::{hit, iso_to_mdy, parse_time_filters, Citation, Hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::{json, Value};

pub struct Perplexity;

const ENV: &[&str] = &["PERPLEXITY_API_KEY", "OPENROUTER_API_KEY"];
const DIRECT: &str = "https://api.perplexity.ai";
const OPENROUTER: &str = "https://openrouter.ai/api/v1";
const DEFAULT_MODEL: &str = "perplexity/sonar-pro";

struct Runtime {
    key: String,
    /// Chat-completions base (Sonar) — only used for the chat transport.
    chat_base: String,
    model: String,
    chat: bool,
}

fn search_base(c: &WebCtx) -> String {
    c.opt("perplexity", "search_base_url").or_else(|| c.var("PERPLEXITY_BASE_URL")).unwrap_or_else(|| DIRECT.into()).trim_end_matches('/').to_string()
}

fn runtime(c: &WebCtx) -> Option<Runtime> {
    let (key, source) = if let Some(k) = c.opt("perplexity", "api_key") {
        (k, "config")
    } else if let Some(k) = c.var("PERPLEXITY_API_KEY") {
        (k, "perplexity_env")
    } else {
        (c.var("OPENROUTER_API_KEY")?, "openrouter_env")
    };
    let over_base = c.opt("perplexity", "base_url");
    let over_model = c.opt("perplexity", "model");
    let direct_key = source == "perplexity_env" || (source == "config" && !key.to_ascii_lowercase().starts_with("sk-or-"));
    let chat_base = over_base.clone().unwrap_or_else(|| if direct_key { DIRECT.into() } else { OPENROUTER.into() }).trim_end_matches('/').to_string();
    let is_direct = http::host_of(&chat_base) == "api.perplexity.ai";
    Some(Runtime { chat: over_base.is_some() || over_model.is_some() || !is_direct, model: over_model.unwrap_or_else(|| DEFAULT_MODEL.into()), chat_base, key })
}

fn headers(key: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", format!("Bearer {key}")),
        ("Accept", "application/json".into()),
        ("User-Agent", format!("seagent/{}", env!("CARGO_PKG_VERSION"))),
        ("X-Title", "seagent".into()),
        ("X-Pplx-Integration", "seagent".into()),
    ]
}

fn post(c: &WebCtx, url: &str, key: &str, body: &Value, label: &str) -> Result<Value, String> {
    c.check_cancel()?;
    let r = http::post_json(url, &headers(key), body, c.timeout("perplexity").max(60)).map_err(|e| format!("Perplexity search failed: {e}"))?;
    if !r.ok() {
        return Err(http::api_error(label, &r, Some(key)));
    }
    r.json()
}

/// Citations: top-level `citations`, else `url_citation` annotations of the choices.
fn chat_citations(v: &Value) -> Vec<Citation> {
    let mut urls: Vec<String> = v.get("citations").and_then(|c| c.as_array()).into_iter().flatten().filter_map(|u| u.as_str()).map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    if urls.is_empty() {
        for ch in v.get("choices").and_then(|c| c.as_array()).into_iter().flatten() {
            for a in ch.pointer("/message/annotations").and_then(|a| a.as_array()).into_iter().flatten() {
                if a.get("type").and_then(|t| t.as_str()) == Some("url_citation") {
                    let u = a.pointer("/url_citation/url").and_then(|u| u.as_str()).map(str::to_string).unwrap_or_else(|| http::s(a, "url"));
                    if !u.is_empty() {
                        urls.push(u);
                    }
                }
            }
        }
    }
    let mut out: Vec<Citation> = Vec::new();
    for u in urls {
        if !out.iter().any(|c| c.url == u) {
            out.push(Citation { url: u, title: None });
        }
    }
    out
}

/// Relevance query from URL path words (`/bloom-filter` → `bloom filter`), host for bare origins.
pub fn query_for_urls(urls: &[String]) -> String {
    let mut words: Vec<String> = Vec::new();
    for u in urls {
        let p = crate::web::ssrf::parse_url(u);
        let path = p.as_ref().map(|p| p.path.split('?').next().unwrap_or("").to_string()).unwrap_or_default();
        for t in path.replace(['-', '_', '/'], " ").split_whitespace() {
            let t = t.to_lowercase();
            if !words.contains(&t) && !t.chars().all(|c| c.is_ascii_digit()) {
                words.push(t);
            }
        }
        if path.trim_matches('/').is_empty() {
            if let Ok(p) = &p {
                words.push(p.host.clone());
            }
        }
    }
    let q: String = words.join(" ").chars().take(500).collect();
    if q.is_empty() {
        urls.join(" ").chars().take(500).collect()
    } else {
        q
    }
}

impl WebProvider for Perplexity {
    fn id(&self) -> &'static str {
        "perplexity"
    }
    fn label(&self) -> &'static str {
        "Perplexity Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        runtime(c).is_some()
    }
    fn filters(&self) -> &'static [&'static str] {
        &["country", "language", "freshness", "date_after", "date_before", "domain_filter", "max_tokens", "max_tokens_per_page"]
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        match runtime(c) {
            Some(rt) if rt.chat => format!("{}/chat/completions", rt.chat_base),
            _ => format!("{}/search", search_base(c)),
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://www.perplexity.ai/settings/api"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let rt = runtime(c).ok_or("web_search (perplexity) needs an API key. Set PERPLEXITY_API_KEY or OPENROUTER_API_KEY, or [web.providers.perplexity] api_key. If you do not want to configure a search API key, use web_fetch for a specific URL.")?;
        if rt.chat {
            let unsupported: [(bool, &str); 5] = [
                (r.country.is_some(), "country filtering is"),
                (r.language.is_some(), "language filtering is"),
                (r.date_after.is_some() || r.date_before.is_some(), "date_after/date_before are"),
                (!r.domain_filter.is_empty(), "domain_filter is"),
                (r.max_tokens.is_some() || r.max_tokens_per_page.is_some(), "max_tokens and max_tokens_per_page are"),
            ];
            if let Some((_, what)) = unsupported.iter().find(|(set, _)| *set) {
                let pron = if what.ends_with("are") { "them" } else { "it" };
                return Err(format!("{what} only supported by the native Perplexity Search API path. Remove Perplexity base_url/model overrides or use a direct PERPLEXITY_API_KEY to enable {pron}."));
            }
        }
        if let Some(l) = &r.language {
            if !(l.len() == 2 && l.chars().all(|ch| ch.is_ascii_alphabetic())) {
                return Err("language must be a 2-letter ISO 639-1 code like 'en', 'de', or 'fr'.".into());
            }
        }
        let t = parse_time_filters(r, "perplexity")?;
        if !r.domain_filter.is_empty() {
            let deny = r.domain_filter.iter().any(|d| d.starts_with('-'));
            let allow = r.domain_filter.iter().any(|d| !d.starts_with('-'));
            if deny && allow {
                return Err("domain_filter cannot mix allowlist and denylist entries. Use either all positive entries (allowlist) or all entries prefixed with '-' (denylist).".into());
            }
            if r.domain_filter.len() > 20 {
                return Err("domain_filter supports a maximum of 20 domains.".into());
            }
        }
        if rt.chat {
            let model = if http::host_of(&rt.chat_base) == "api.perplexity.ai" { rt.model.trim_start_matches("perplexity/").to_string() } else { rt.model.clone() };
            let mut body = json!({"model": model, "messages": [{"role":"user","content": r.query}]});
            if let Some(f) = &t.freshness {
                body["search_recency_filter"] = json!(f);
            }
            let v = post(c, &format!("{}/chat/completions", rt.chat_base), &rt.key, &body, "Perplexity")?;
            let content = v.pointer("/choices/0/message/content").and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).ok_or("Perplexity search returned no final answer. Retry the query or choose another search provider.")?;
            return Ok(SearchOutput::Answer { content: content.to_string(), citations: chat_citations(&v) });
        }
        let count = r.count.clamp(1, 20);
        let mut body = json!({"query": r.query, "max_results": count, "search_context_size": "low"});
        if let Some(x) = &r.country {
            body["country"] = json!(x);
        }
        if !r.domain_filter.is_empty() {
            body["search_domain_filter"] = json!(r.domain_filter);
        }
        if let Some(f) = &t.freshness {
            body["search_recency_filter"] = json!(f);
        }
        if let Some(l) = &r.language {
            body["search_language_filter"] = json!([l]);
        }
        if let Some(a) = t.date_after.as_deref().and_then(iso_to_mdy) {
            body["search_after_date_filter"] = json!(a);
        }
        if let Some(b) = t.date_before.as_deref().and_then(iso_to_mdy) {
            body["search_before_date_filter"] = json!(b);
        }
        if let Some(m) = r.max_tokens {
            body["max_tokens"] = json!(m.min(1_000_000));
        }
        if let Some(m) = r.max_tokens_per_page {
            body["max_tokens_per_page"] = json!(m);
        }
        let v = post(c, &format!("{}/search", search_base(c)), &rt.key, &body, "Perplexity Search")?;
        let hits: Vec<Hit> = v.get("results").and_then(|x| x.as_array()).into_iter().flatten().take(count).map(|e| Hit { published: Some(http::s(e, "date")).filter(|d| !d.is_empty()), ..hit(&http::s(e, "title"), &http::s(e, "url"), &http::s(e, "snippet")) }).collect();
        Ok(SearchOutput::Results(hits))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        let key = c.opt("perplexity", "api_key").or_else(|| c.var("PERPLEXITY_API_KEY")).ok_or("PERPLEXITY_API_KEY is not set. Get a key at https://www.perplexity.ai/account/api")?;
        let body = json!({"query": query_for_urls(urls), "urls": urls, "max_tokens": 16384, "max_tokens_per_page": 4096});
        let v = post(c, &format!("{}/sdk/content/snippets", search_base(c)), &key, &body, "Perplexity")?;
        // One document per requested URL, in order; a 200 does not mean every page succeeded.
        Ok(urls
            .iter()
            .map(|u| {
                let r = v.get("results").and_then(|x| x.as_array()).and_then(|a| a.iter().find(|r| http::s(r, "url") == *u)).cloned().unwrap_or(Value::Null);
                let text = http::s(&r, "text");
                let err = r.get("error").and_then(|e| e.as_str()).map(str::to_string).or_else(|| text.is_empty().then(|| "no content returned".to_string()));
                Page { url: u.clone(), title: String::new(), content: text, error: err, source_url: Some(u.clone()) }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    fn srv() -> FakeServer {
        FakeServer::start(vec![
            ("POST /search", 200, "application/json", json!({"results":[{"title":"P","url":"https://p.com","snippet":"sn","date":"2025-01-01"}]}).to_string()),
            ("POST /chat/completions", 200, "application/json", json!({"choices":[{"message":{"content":"Answer","annotations":[{"type":"url_citation","url_citation":{"url":"https://c.com"}}]}}]}).to_string()),
            ("POST /sdk/content/snippets", 200, "application/json", json!({"results":[{"url":"https://a.com/bloom-filter","text":"bits"},{"url":"https://b.com","error":"blocked"}]}).to_string()),
        ])
    }

    #[test]
    fn search_api_body() {
        let s = srv();
        let c = wctx(json!({"providers":{"perplexity":{"search_base_url":s.url.clone()}}}), &[("PERPLEXITY_API_KEY", "pplx-test")]);
        let r = SearchRequest { query: "q".into(), count: 3, country: Some("US".into()), language: Some("en".into()), date_after: Some("2025-01-05".into()), domain_filter: vec!["-x.com".into()], max_tokens: Some(9), ..Default::default() };
        let SearchOutput::Results(h) = Perplexity.search(&c, &r).unwrap() else { panic!() };
        assert_eq!(h[0].published.as_deref(), Some("2025-01-01"));
        let q = s.last();
        assert_eq!(q.header("authorization").as_deref(), Some("Bearer pplx-test"));
        let b = q.json();
        assert_eq!((b["search_after_date_filter"].as_str(), b["search_language_filter"][0].as_str(), b["search_domain_filter"][0].as_str(), b["max_tokens"].as_u64(), b["search_context_size"].as_str()), (Some("1/5/2025"), Some("en"), Some("-x.com"), Some(9), Some("low")));
        let r = SearchRequest { query: "q".into(), count: 3, freshness: Some("pw".into()), ..Default::default() };
        Perplexity.search(&c, &r).unwrap();
        assert_eq!(s.last().json()["search_recency_filter"], "week");
    }

    #[test]
    fn chat_transport_for_openrouter_and_overrides() {
        let s = srv();
        let c = wctx(json!({"providers":{"perplexity":{"base_url":s.url.clone()}}}), &[("OPENROUTER_API_KEY", "sk-or-test")]);
        let SearchOutput::Answer { content, citations } = Perplexity.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((content.as_str(), citations[0].url.as_str()), ("Answer", "https://c.com"));
        assert_eq!(s.last().json()["model"], "perplexity/sonar-pro");
        assert!(Perplexity.search(&c, &SearchRequest { query: "q".into(), count: 3, country: Some("US".into()), ..Default::default() }).unwrap_err().contains("only supported by the native"));
        let c = wctx(json!({}), &[("OPENROUTER_API_KEY", "sk-or-test")]);
        assert_eq!(Perplexity.endpoint(&c), "https://openrouter.ai/api/v1/chat/completions");
        let c = wctx(json!({}), &[("PERPLEXITY_API_KEY", "pplx")]);
        assert_eq!(Perplexity.endpoint(&c), "https://api.perplexity.ai/search");
    }

    #[test]
    fn validation_and_extract() {
        let s = srv();
        let c = wctx(json!({"providers":{"perplexity":{"search_base_url":s.url.clone()}}}), &[("PERPLEXITY_API_KEY", "pplx-test")]);
        let bad = |r: SearchRequest| Perplexity.search(&c, &r).unwrap_err();
        assert!(bad(SearchRequest { query: "q".into(), language: Some("eng".into()), ..Default::default() }).contains("2-letter"));
        assert!(bad(SearchRequest { query: "q".into(), domain_filter: vec!["a.com".into(), "-b.com".into()], ..Default::default() }).contains("cannot mix"));
        let p = Perplexity.extract(&c, &["https://a.com/bloom-filter".into(), "https://b.com".into(), "https://c.com/x".into()]).unwrap();
        assert_eq!((p[0].content.as_str(), p[1].error.as_deref(), p[2].error.as_deref()), ("bits", Some("blocked"), Some("no content returned")));
        assert_eq!(s.last().json()["query"], "bloom filter b.com x");
        assert!(wctx(json!({}), &[]).cfg.providers.is_empty() && !Perplexity.configured(&wctx(json!({}), &[])));
    }
}
