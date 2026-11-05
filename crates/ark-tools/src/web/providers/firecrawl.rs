//! Firecrawl search + scrape (`/v2/search`, `/v2/scrape`). Hermes `plugins/web/firecrawl`
//! (direct key, self-hosted FIRECRAWL_API_URL, keyless ring without credentials, per-URL scrape
//! with a 60 s deadline) + OpenClaw `extensions/firecrawl` (search sources / categories / domain
//! filters / tbs / location / country / scrapeResults, scrape onlyMainContent / maxAge / proxy /
//! storeInCache, base-URL validation, the web_fetch fallback and the `firecrawl_search` /
//! `firecrawl_scrape` tools). The Nous managed tool-gateway route is a proprietary Nous
//! subscription and is not ported.

use super::{site_name, Hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::content::wrap_web;
use crate::web::http::{self, EnvFn, WebCtx};
use crate::web::{keyless, ssrf, WebConfig};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct Firecrawl;

const ENV: &[&str] = &["FIRECRAWL_API_KEY"];
const CLOUD: &str = "https://api.firecrawl.dev";
const MAX_SEARCH_RESULTS: usize = 100;
const SEARCH_MAX_CONTENT: usize = 20_000;
const DEFAULT_SCRAPE_MAX_CHARS: usize = 50_000;
const DEFAULT_MAX_AGE_MS: u64 = 172_800_000;

fn self_hosted_url(c: &WebCtx) -> Option<String> {
    c.opt("firecrawl", "base_url").or_else(|| c.var("FIRECRAWL_API_URL")).or_else(|| c.var("FIRECRAWL_BASE_URL")).map(|u| u.trim().trim_end_matches('/').to_string()).filter(|u| !u.is_empty())
}

fn base(c: &WebCtx) -> String {
    self_hosted_url(c).unwrap_or_else(|| CLOUD.into())
}

/// Official https cloud is fine; anything else must be a private self-hosted instance.
fn validate_base(b: &str) -> Result<(), String> {
    let u = ssrf::parse_url(b).map_err(|_| "Firecrawl baseUrl must use http:// or https://.".to_string())?;
    if u.scheme == "https" && u.host == "api.firecrawl.dev" {
        return Ok(());
    }
    let private = match u.host.parse::<std::net::IpAddr>() {
        Ok(ip) => ssrf::is_private_ip(ip),
        Err(_) => {
            use std::net::ToSocketAddrs;
            ssrf::check_host(&u.host, false, &ssrf::SsrfPolicy::default()).is_err() || (u.host.as_str(), u.port).to_socket_addrs().map(|mut a| a.all(|a| ssrf::is_private_ip(a.ip()))).unwrap_or(false)
        }
    };
    if private {
        Ok(())
    } else if u.scheme == "http" {
        Err("Firecrawl HTTP baseUrl must target a private or internal self-hosted endpoint. Use https:// for public hosts.".into())
    } else {
        Err(format!("Firecrawl custom baseUrl must target a private or internal self-hosted endpoint. Host: {}", u.host))
    }
}

fn error_detail(body: &str, fallback: &str) -> String {
    serde_json::from_str::<Value>(body).ok().and_then(|v| v.get("error").or(v.get("message")).and_then(|e| e.as_str()).map(str::to_string)).unwrap_or_else(|| if body.trim().is_empty() { fallback.to_string() } else { body.trim().to_string() })
}

fn post(c: &WebCtx, path: &str, body: &Value, label: &str, timeout: u64) -> Result<Value, String> {
    let b = base(c);
    validate_base(&b)?;
    let key = c.key("firecrawl", ENV);
    let h: Vec<(&str, String)> = key.iter().map(|k| super::bearer(k)).collect();
    c.check_cancel()?;
    let r = http::post_json(&format!("{b}{path}"), &h, body, timeout).map_err(|e| format!("{label} request failed: {e}"))?;
    if !r.ok() {
        let mut d = error_detail(&r.body, "request failed");
        if let Some(k) = key.as_deref().filter(|k| k.len() >= 4) {
            d = d.replace(k, "***");
        }
        return Err(format!("{label} API error ({}): {}", r.status, crate::util::truncate_str(&d, 1000)));
    }
    let v = r.json()?;
    if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
        return Err(format!("{label} API error: {}", crate::util::truncate_str(&error_detail(&v.to_string(), "unknown error"), 1000)));
    }
    Ok(v)
}

fn result_url(s: &str) -> Option<String> {
    (s.len() <= 2048 && (s.starts_with("http://") || s.starts_with("https://")) && ssrf::parse_url(s).is_ok()).then(|| s.to_string())
}

fn published_ok(s: &str) -> bool {
    s.len() >= 10 && super::valid_iso_date(&s[..10]) && s.len() <= 31 && s[10..].chars().all(|c| c.is_ascii_digit() || " T:.+Z-".contains(c))
}

/// OpenClaw `resolveSearchItems`: envelope arrays, then per-source arrays, then legacy `web.results`.
pub fn search_items(v: &Value, count: usize) -> Vec<(Hit, Option<String>)> {
    let d = v.get("data");
    let env = [d, v.get("results"), d.and_then(|x| x.get("results")), d.and_then(|x| x.get("data"))];
    let srcs: Vec<&Value> = ["web", "news", "images"].iter().filter_map(|k| d.and_then(|x| x.get(*k))).filter(|x| x.is_array()).collect();
    let rows: Vec<Value> = if let Some(a) = env.iter().flatten().find_map(|x| x.as_array()) {
        a.clone()
    } else if !srcs.is_empty() {
        srcs.iter().flat_map(|x| x.as_array().cloned().unwrap_or_default()).collect()
    } else {
        v.pointer("/web/results").and_then(|x| x.as_array()).cloned().unwrap_or_default()
    };
    let mut out = Vec::new();
    for (inspected, e) in rows.iter().filter(|e| e.is_object()).enumerate() {
        if inspected >= MAX_SEARCH_RESULTS || out.len() >= count {
            break;
        }
        let meta = e.get("metadata").cloned().unwrap_or(Value::Null);
        let first = |pairs: &[(&Value, &str)]| pairs.iter().map(|(o, k)| http::s(o, k)).find(|x| !x.is_empty());
        let Some(url) = first(&[(e, "url"), (e, "sourceURL"), (e, "sourceUrl"), (&meta, "sourceURL")]).and_then(|u| result_url(&u)) else { continue };
        let title = first(&[(e, "title"), (&meta, "title")]).unwrap_or_default();
        let desc = first(&[(e, "description"), (e, "snippet"), (e, "summary")]).unwrap_or_default();
        let content = first(&[(e, "markdown"), (e, "content"), (e, "text")]);
        let published = first(&[(e, "publishedDate"), (e, "published"), (&meta, "publishedTime"), (&meta, "publishedDate")]).filter(|p| published_ok(p));
        let site = site_name(&url).map(|s| s.trim_start_matches("www.").to_string());
        out.push((Hit { title, url, snippet: desc, published, site_name: site }, content));
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct SearchParams {
    pub query: String,
    pub count: usize,
    pub sources: Vec<String>,
    pub categories: Vec<String>,
    pub scrape_results: bool,
    pub include_domains: Vec<String>,
    pub exclude_domains: Vec<String>,
    pub tbs: Option<String>,
    pub location: Option<String>,
    pub country: Option<String>,
    pub timeout_seconds: Option<u64>,
}

pub fn run_search(c: &WebCtx, p: &SearchParams) -> Result<Vec<(Hit, Option<String>)>, String> {
    if !p.include_domains.is_empty() && !p.exclude_domains.is_empty() {
        return Err("Firecrawl search accepts includeDomains or excludeDomains, not both.".into());
    }
    let count = p.count.clamp(1, 100);
    let mut body = json!({"query": p.query, "limit": count});
    for (k, v) in [("sources", &p.sources), ("categories", &p.categories), ("includeDomains", &p.include_domains), ("excludeDomains", &p.exclude_domains)] {
        if !v.is_empty() {
            body[k] = json!(v);
        }
    }
    for (k, v) in [("tbs", &p.tbs), ("location", &p.location), ("country", &p.country)] {
        if let Some(v) = v {
            body[k] = json!(v);
        }
    }
    if p.scrape_results {
        body["scrapeOptions"] = json!({"formats":["markdown"]});
    }
    let v = post(c, "/v2/search", &body, "Firecrawl Search", p.timeout_seconds.or(c.opt_u64("firecrawl", "timeout_seconds")).unwrap_or(30))?;
    Ok(search_items(&v, count))
}

#[derive(Debug, Clone)]
pub struct ScrapeParams {
    pub url: String,
    /// `markdown` | `text`.
    pub extract_mode: String,
    pub max_chars: Option<usize>,
    pub only_main_content: Option<bool>,
    pub max_age_ms: Option<u64>,
    pub proxy: Option<String>,
    pub store_in_cache: Option<bool>,
    pub timeout_seconds: Option<u64>,
}

impl ScrapeParams {
    pub fn new(url: &str) -> ScrapeParams {
        ScrapeParams { url: url.into(), extract_mode: "markdown".into(), max_chars: None, only_main_content: None, max_age_ms: None, proxy: None, store_in_cache: None, timeout_seconds: None }
    }
}

/// One scrape: `{url, finalUrl, status?, title?, extractor, extractMode, truncated, rawLength, text, warning?}`.
pub fn scrape(c: &WebCtx, p: &ScrapeParams) -> Result<Value, String> {
    let u = ssrf::parse_url(&p.url).map_err(|_| "Invalid URL supplied to Firecrawl scrape".to_string())?;
    if ssrf::check_host(&u.host, u.scheme == "https", &ssrf::SsrfPolicy { allow_private: false, ..Default::default() }).is_err() {
        return Err(format!("Blocked hostname or private/internal IP in Firecrawl scrape URL: {}", u.host));
    }
    scrape_unchecked(c, p)
}

fn scrape_unchecked(c: &WebCtx, p: &ScrapeParams) -> Result<Value, String> {
    let timeout = p.timeout_seconds.or(c.opt_u64("firecrawl", "scrape_timeout_seconds")).unwrap_or(60).max(1);
    let body = json!({
        "url": p.url, "formats": ["markdown"],
        "onlyMainContent": p.only_main_content.or(c.opt_bool("firecrawl", "only_main_content")).unwrap_or(true),
        "timeout": timeout * 1000,
        "maxAge": p.max_age_ms.or(c.opt_u64("firecrawl", "max_age_ms")).unwrap_or(DEFAULT_MAX_AGE_MS),
        "proxy": p.proxy.clone().unwrap_or_else(|| "auto".into()),
        "storeInCache": p.store_in_cache.unwrap_or(true),
    });
    let v = post(c, "/v2/scrape", &body, "Firecrawl", timeout + 5)?;
    let d = v.get("data").filter(|d| d.is_object()).cloned().unwrap_or(v.clone());
    let meta = d.get("metadata").cloned().unwrap_or(Value::Null);
    let status = meta.get("statusCode").or(d.get("statusCode")).and_then(|s| s.as_f64()).map(|s| s as u64);
    if let Some(s) = status.filter(|s| !(200..300).contains(s)) {
        return Err(format!("Firecrawl fetch failed ({s}): target returned an unsuccessful HTTP status."));
    }
    let md = [http::s(&d, "markdown"), http::s(&d, "content")].into_iter().find(|x| !x.is_empty()).ok_or("Firecrawl scrape returned no content.")?;
    let raw = if p.extract_mode == "text" { crate::web::markdown::markdown_to_text(&md) } else { md };
    let max = p.max_chars.unwrap_or(DEFAULT_SCRAPE_MAX_CHARS).min(DEFAULT_SCRAPE_MAX_CHARS.max(c.cfg.fetch.max_chars_cap));
    let text = crate::util::truncate_str(&raw, max).to_string();
    let final_url = result_url(&http::s(&meta, "sourceURL")).or_else(|| result_url(&http::s(&d, "url"))).unwrap_or_else(|| p.url.clone());
    let mut out = json!({"url": p.url, "finalUrl": final_url, "extractor": "firecrawl", "extractMode": p.extract_mode, "truncated": text.len() < raw.len(), "rawLength": raw.chars().count(), "text": text});
    if let Some(s) = status {
        out["status"] = json!(s);
    }
    let title = http::s(&meta, "title");
    if !title.is_empty() {
        out["title"] = json!(crate::util::truncate_str(&title, 4000));
    }
    if let Some(w) = v.get("warning").and_then(|w| w.as_str()).filter(|w| !w.is_empty()) {
        out["warning"] = json!(w);
    }
    Ok(out)
}

impl WebProvider for Firecrawl {
    fn id(&self) -> &'static str {
        "firecrawl"
    }
    fn label(&self) -> &'static str {
        "Firecrawl Search"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["firecrawl-free"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("firecrawl", ENV).is_some() || self_hosted_url(c).is_some()
    }
    fn keyless(&self) -> bool {
        true
    }
    fn routes_keyless(&self, c: &WebCtx) -> bool {
        c.key("firecrawl", ENV).is_none() && self_hosted_url(c).is_none() && keyless::use_keyless(c, "firecrawl", None)
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        if self.routes_keyless(c) {
            format!("{}/v2/search", keyless::endpoint(c, "firecrawl"))
        } else {
            format!("{}/v2/search", base(c))
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://www.firecrawl.dev/"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        if self.routes_keyless(c) {
            return keyless::search_with_failover(c, "firecrawl", &r.query, r.count).1.map(SearchOutput::Results);
        }
        if !self.configured(c) {
            return Err("web_search (firecrawl) needs a Firecrawl API key. Set FIRECRAWL_API_KEY (or FIRECRAWL_API_URL for a self-hosted instance), or [web.providers.firecrawl] api_key.".into());
        }
        let p = SearchParams { query: r.query.clone(), count: r.count, ..Default::default() };
        Ok(SearchOutput::Results(run_search(c, &p)?.into_iter().map(|(h, _)| h).collect()))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        if self.routes_keyless(c) {
            return Ok(keyless::extract_with_failover(c, "firecrawl", urls));
        }
        Ok(urls
            .iter()
            .map(|u| {
                if c.cancel.is_cancelled() {
                    return Page::err(u, "Interrupted");
                }
                match scrape(c, &ScrapeParams { max_chars: Some(crate::web::cache::MAX_STORED_TEXT_CHARS), ..ScrapeParams::new(u) }) {
                    Ok(v) => {
                        let fin = http::s(&v, "finalUrl");
                        Page { url: fin.clone(), title: http::s(&v, "title"), content: http::s(&v, "text"), error: None, source_url: Some(u.clone()).filter(|x| *x != fin) }
                    }
                    Err(e) if e.contains("timed out") || e.to_ascii_lowercase().contains("timeout") => Page::err(u, "Scrape timed out after 60s — page may be too large or unresponsive. Try the browser instead."),
                    Err(e) => Page::err(u, e),
                }
            })
            .collect())
    }
}

// ── web_fetch fallback (OpenClaw `firecrawl-fetch-provider.ts`) ─────────────────────

/// Firecrawl backs `web_fetch` when `web.fetch.provider` is `firecrawl` or unset, and a key /
/// self-hosted URL is configured (the keyless ring does not serve fetch fallbacks).
pub fn fetch_fallback_enabled(c: &WebCtx) -> bool {
    matches!(c.cfg.fetch.provider.trim().to_ascii_lowercase().as_str(), "" | "firecrawl") && Firecrawl.configured(c)
}

/// One fallback scrape for `web_fetch`. The target host meets web_fetch's own SSRF policy
/// (`allow_private_urls` / `fetch.allowed_hostnames` count) instead of the strict default.
pub fn fetch_fallback(c: &WebCtx, url: &str, text_mode: bool) -> Result<Value, String> {
    let u = ssrf::parse_url(url).map_err(|_| "Invalid URL supplied to Firecrawl scrape".to_string())?;
    ssrf::check_host(&u.host, u.scheme == "https", &ssrf::SsrfPolicy::from_config(&c.cfg)).map_err(|_| format!("Blocked hostname or private/internal IP in Firecrawl scrape URL: {}", u.host))?;
    let p = ScrapeParams { extract_mode: if text_mode { "text" } else { "markdown" }.into(), max_chars: Some(crate::web::cache::MAX_STORED_TEXT_CHARS), ..ScrapeParams::new(url) };
    scrape_unchecked(c, &p)
}

/// Where a fetch fallback goes (for the egress gate).
pub fn fetch_fallback_endpoint(c: &WebCtx) -> String {
    format!("{}/v2/scrape", base(c))
}

// ── dedicated tools (OpenClaw firecrawl_search / firecrawl_scrape) ─────────────────

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
}

fn ostr(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub struct FirecrawlSearchTool {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Tool for FirecrawlSearchTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "firecrawl_search".into(),
            description: "Search the web using Firecrawl. Supports sources (web/news/images), categories, domain filters, time filters (tbs), location/country targeting and optional scraping of result content.".into(),
            input_schema: json!({"type":"object","required":["query"],"additionalProperties":false,"properties":{
                "query":{"type":"string","description":"Search query string."},
                "count":{"type":"integer","minimum":1,"maximum":100,"description":"Number of results to return (1-100)."},
                "sources":{"type":"array","items":{"type":"string"},"description":"Optional sources list, for example [\"web\"], [\"news\"], or [\"images\"]."},
                "categories":{"type":"array","items":{"type":"string"},"description":"Optional Firecrawl categories, for example [\"github\"] or [\"research\"]."},
                "includeDomains":{"type":"array","items":{"type":"string"},"description":"Only return results from these domains (not with excludeDomains)."},
                "excludeDomains":{"type":"array","items":{"type":"string"},"description":"Exclude results from these domains (not with includeDomains)."},
                "tbs":{"type":"string","description":"Time-based search filter, for example \"qdr:d\", \"qdr:w\" or a custom date range."},
                "location":{"type":"string","description":"Location for geo-targeted results, for example \"Berlin, Germany\"."},
                "country":{"type":"string","description":"ISO country code for geo-targeting, for example \"US\", \"DE\", or \"JP\"."},
                "scrapeResults":{"type":"boolean","description":"Include scraped result content when Firecrawl returns it."},
                "timeoutSeconds":{"type":"integer","minimum":1,"description":"Timeout in seconds for the Firecrawl Search request."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        vec![Effect::Net { dest: http::host_of(&base(&c)), payload: ostr(input, "query").unwrap_or_default() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        let Some(query) = ostr(&input, "query") else { return ToolOutput::err("missing string argument `query`") };
        let count = match input.get("count") {
            None | Some(Value::Null) => 5,
            Some(v) => match v.as_u64().filter(|n| (1..=100).contains(n)) {
                Some(n) => n as usize,
                None => return ToolOutput::err("count must be an integer from 1 to 100."),
            },
        };
        let p = SearchParams {
            query: query.clone(),
            count,
            sources: strs(&input, "sources"),
            categories: strs(&input, "categories"),
            scrape_results: input.get("scrapeResults").and_then(|b| b.as_bool()) == Some(true),
            include_domains: strs(&input, "includeDomains"),
            exclude_domains: strs(&input, "excludeDomains"),
            tbs: ostr(&input, "tbs"),
            location: ostr(&input, "location"),
            country: ostr(&input, "country"),
            timeout_seconds: input.get("timeoutSeconds").and_then(|t| t.as_u64()),
        };
        if c.key("firecrawl", ENV).is_none() && self_hosted_url(&c).is_none() && !keyless::use_keyless(&c, "firecrawl", None) {
            return ToolOutput::err("firecrawl_search needs a Firecrawl API key. Set FIRECRAWL_API_KEY or [web.providers.firecrawl] api_key.");
        }
        match run_search(&c, &p) {
            Ok(items) => {
                let mut budget = SEARCH_MAX_CONTENT;
                let mut truncated = false;
                let mut rows = Vec::new();
                for (h, content) in items {
                    let mut cut = |s: &str| {
                        let t = crate::util::truncate_str(s, budget).to_string();
                        truncated |= t.len() < s.len();
                        budget -= t.len();
                        t
                    };
                    let mut row = json!({"title": cut(&h.title), "url": h.url, "description": cut(&h.snippet)});
                    if let Some(pb) = h.published {
                        row["published"] = json!(pb);
                    }
                    if let Some(s) = h.site_name {
                        row["siteName"] = json!(s);
                    }
                    if let Some(ct) = content.filter(|_| p.scrape_results) {
                        row["content"] = json!(cut(&ct));
                    }
                    rows.push(row);
                }
                let provider = if c.key("firecrawl", ENV).is_none() && self_hosted_url(&c).is_none() { "firecrawl-free" } else { "firecrawl" };
                let mut v = json!({"query": query, "provider": provider, "count": rows.len(), "results": rows, "externalContent":{"untrusted":true,"source":"web_search","wrapped":true,"provider":provider}});
                if truncated {
                    v["truncated"] = json!(true);
                }
                ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(&v).unwrap_or_default(), "web_search"))
            }
            Err(e) => ToolOutput::err(e),
        }
    }
}

pub struct FirecrawlScrapeTool {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Tool for FirecrawlScrapeTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "firecrawl_scrape".into(),
            description: "Scrape a page with Firecrawl (renders JavaScript, bypasses simple bot walls) and return its main content as markdown or text.".into(),
            input_schema: json!({"type":"object","required":["url"],"additionalProperties":false,"properties":{
                "url":{"type":"string","description":"HTTP or HTTPS URL to scrape via Firecrawl."},
                "extractMode":{"type":"string","enum":["markdown","text"],"description":"Extraction mode (\"markdown\" or \"text\"). Default: markdown."},
                "maxChars":{"type":"integer","minimum":100,"description":"Maximum characters to return."},
                "onlyMainContent":{"type":"boolean","description":"Keep only main content when Firecrawl supports it."},
                "maxAgeMs":{"type":"integer","minimum":0,"description":"Maximum Firecrawl cache age in milliseconds."},
                "proxy":{"type":"string","enum":["auto","basic","stealth"],"description":"Firecrawl proxy mode (\"auto\", \"basic\", or \"stealth\")."},
                "storeInCache":{"type":"boolean","description":"Whether Firecrawl should store the scrape in its cache."},
                "timeoutSeconds":{"type":"integer","minimum":1,"description":"Timeout in seconds for the Firecrawl scrape request."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        vec![Effect::Net { dest: http::host_of(&base(&c)), payload: ostr(input, "url").unwrap_or_default() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        let Some(url) = ostr(&input, "url") else { return ToolOutput::err("missing string argument `url`") };
        if c.key("firecrawl", ENV).is_none() && self_hosted_url(&c).is_none() {
            return ToolOutput::err("firecrawl_scrape needs a Firecrawl API key. Set FIRECRAWL_API_KEY or [web.providers.firecrawl] api_key.");
        }
        let p = ScrapeParams {
            url,
            extract_mode: if ostr(&input, "extractMode").as_deref() == Some("text") { "text".into() } else { "markdown".into() },
            max_chars: input.get("maxChars").and_then(|m| m.as_u64()).map(|m| m.max(100) as usize),
            only_main_content: input.get("onlyMainContent").and_then(|b| b.as_bool()),
            max_age_ms: input.get("maxAgeMs").and_then(|m| m.as_u64()),
            proxy: ostr(&input, "proxy"),
            store_in_cache: input.get("storeInCache").and_then(|b| b.as_bool()),
            timeout_seconds: input.get("timeoutSeconds").and_then(|t| t.as_u64()),
        };
        match scrape(&c, &p) {
            Ok(mut v) => {
                let text = http::s(&v, "text");
                v["text"] = json!(wrap_web(&text, "web_fetch"));
                v["externalContent"] = json!({"untrusted":true,"source":"web_fetch","wrapped":true});
                ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default())
            }
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, wctx, FakeServer};

    fn srv() -> FakeServer {
        FakeServer::with(|r| {
            let body = match r.path.as_str() {
                "/v2/search" => json!({"success":true,"data":{"web":[{"url":"https://www.a.com/x","title":"A","description":"da","markdown":"# A body","publishedDate":"2025-01-02"},{"url":"ftp://bad"}],"news":[{"url":"https://n.com","title":"N","snippet":"sn","publishedDate":"yesterday"}]}}),
                "/v2/scrape" if r.json()["url"] == "https://redir.com/" => json!({"data":{"markdown":"moved","metadata":{"sourceURL":"https://final.com/page","title":"F","statusCode":200}}}),
                "/v2/scrape" if r.json()["url"] == "https://gone.com/" => json!({"data":{"markdown":"x","metadata":{"statusCode":404}}}),
                "/v2/scrape" => json!({"success":true,"data":{"markdown":"# Title\n\nSome **bold** text","metadata":{"title":"T","statusCode":200}},"warning":"cached copy"}),
                _ => json!({}),
            };
            (200, "application/json".into(), body.to_string().into_bytes(), vec![])
        })
    }

    #[test]
    fn search_items_shapes() {
        let s = srv();
        let c = wctx(json!({"providers":{"firecrawl":{"base_url":s.url.clone()}}}), &[("FIRECRAWL_API_KEY", "fc-test")]);
        let SearchOutput::Results(h) = Firecrawl.search(&c, &SearchRequest { query: "q".into(), count: 5, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].site_name.as_deref(), h[0].published.as_deref(), h[1].published.as_deref()), (Some("a.com"), Some("2025-01-02"), None));
        let q = s.last();
        assert_eq!(q.header("authorization").as_deref(), Some("Bearer fc-test"));
        assert_eq!((q.json()["limit"].as_u64(), q.json()["query"].as_str()), (Some(5), Some("q")));
        assert_eq!(search_items(&json!({"web":{"results":[{"url":"https://l.com"}]}}), 5).len(), 1, "legacy shape");
        assert_eq!(search_items(&json!({"data":[{"url":"https://d.com","metadata":{"title":"MT"}}]}), 5)[0].0.title, "MT");
    }

    #[test]
    fn scrape_and_extract() {
        let s = srv();
        let c = wctx(json!({"providers":{"firecrawl":{"base_url":s.url.clone(),"api_key":"fc-test","only_main_content":false}}}), &[]);
        let v = scrape(&c, &ScrapeParams { extract_mode: "text".into(), ..ScrapeParams::new("https://ok.com/") }).unwrap();
        assert_eq!((v["text"].as_str(), v["status"].as_u64(), v["warning"].as_str()), (Some("Title\n\nSome **bold** text"), Some(200), Some("cached copy")));
        let b = s.last().json();
        assert_eq!((b["onlyMainContent"].as_bool(), b["timeout"].as_u64(), b["maxAge"].as_u64(), b["proxy"].as_str()), (Some(false), Some(60_000), Some(DEFAULT_MAX_AGE_MS), Some("auto")));
        let pages = Firecrawl.extract(&c, &["https://redir.com/".into(), "https://gone.com/".into()]).unwrap();
        assert_eq!((pages[0].url.as_str(), pages[0].source_url.as_deref(), pages[0].content.as_str()), ("https://final.com/page", Some("https://redir.com/"), "moved"));
        assert!(pages[1].error.as_deref().unwrap().contains("(404)"));
        assert!(scrape(&c, &ScrapeParams::new("http://127.0.0.1/")).unwrap_err().contains("private/internal"));
    }

    #[test]
    fn keyless_and_validation() {
        let ring = FakeServer::start(vec![("POST /v2/search", 200, "application/json", json!({"data":[{"url":"https://free.com","title":"F"}]}).to_string())]);
        let c = wctx(json!({"backend":"firecrawl","provider_tier":{"exa":"paid","parallel":"paid","keenable":"paid"},"providers":{"firecrawl":{"keyless_url":ring.url.clone()}}}), &[]);
        assert!(Firecrawl.routes_keyless(&c) && !Firecrawl.configured(&c));
        let SearchOutput::Results(h) = Firecrawl.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h[0].url, "https://free.com");
        assert!(ring.last().header("authorization").is_none());
        let c = wctx(json!({"keyless_fallback":false}), &[]);
        assert!(Firecrawl.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap_err().contains("needs a Firecrawl API key"));
        assert!(validate_base("https://api.firecrawl.dev").is_ok());
        assert!(validate_base("http://8.8.8.8").unwrap_err().contains("HTTP baseUrl"));
        assert!(validate_base("https://8.8.8.8").unwrap_err().contains("Host: 8.8.8.8"));
        let c = wctx(json!({}), &[("FIRECRAWL_API_URL", "http://10.0.0.5:3002/")]);
        assert!(Firecrawl.configured(&c) && !Firecrawl.routes_keyless(&c));
        assert_eq!(Firecrawl.endpoint(&c), "http://10.0.0.5:3002/v2/search");
        let bad = FakeServer::start(vec![("POST /v2/search", 402, "application/json", r#"{"error":"Payment required for fc-test"}"#.into())]);
        let c = wctx(json!({"providers":{"firecrawl":{"base_url":bad.url.clone()}}}), &[("FIRECRAWL_API_KEY", "fc-test")]);
        assert_eq!(run_search(&c, &SearchParams { query: "q".into(), count: 1, ..Default::default() }).unwrap_err(), "Firecrawl Search API error (402): Payment required for ***");
        assert!(run_search(&c, &SearchParams { query: "q".into(), count: 1, include_domains: vec!["a".into()], exclude_domains: vec!["b".into()], ..Default::default() }).unwrap_err().contains("not both"));
    }

    #[test]
    fn dedicated_tools() {
        let s = srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"firecrawl":{"base_url":s.url.clone()}}})).unwrap());
        let env = env_of(&[("FIRECRAWL_API_KEY", "fc-test")]);
        let tc = ctx("fc-tool");
        let t = FirecrawlSearchTool { cfg: cfg.clone(), env: env.clone() };
        let o = t.call(&tc, json!({"query":"q","sources":["news"],"tbs":"qdr:w","scrapeResults":true,"count":2}));
        assert!(!o.is_error && o.content.contains("# A body"), "{}", o.content);
        let b = s.last().json();
        assert_eq!((b["sources"][0].as_str(), b["tbs"].as_str(), b["scrapeOptions"]["formats"][0].as_str()), (Some("news"), Some("qdr:w"), Some("markdown")));
        assert!(t.call(&tc, json!({"query":"q","count":0})).is_error);
        let sc = FirecrawlScrapeTool { cfg, env };
        let o = sc.call(&tc, json!({"url":"https://ok.com/","proxy":"stealth","maxChars":100}));
        assert!(!o.is_error && o.content.contains("EXTERNAL_UNTRUSTED_CONTENT") && o.content.contains("\"extractor\": \"firecrawl\""), "{}", o.content);
        assert_eq!(s.last().json()["proxy"], "stealth");
    }
}
