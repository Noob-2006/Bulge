//! `web_search`: provider selection (explicit pin, else autodetect by credentials, else the
//! keyless ring), filter validation, the single-flight result memo, one-shot keyless rescue
//! and the normalised, untrusted-wrapped output (Hermes `web_search_tool`, OpenClaw `web-search.ts`).

use super::cache::{self, bucket_limit, normalize_query};
use super::content::wrap_web;
use super::http::{host_of, EnvFn, WebCtx};
use super::keyless;
use super::providers::{self, duckduckgo::DuckDuckGo, Citation, Hit, SearchOutput, SearchRequest, WebProvider};
use super::WebConfig;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_COUNT: usize = 100;
const OUTPUT_MAX_CHARS: usize = 20_000;
const FILTERS: [&str; 10] = ["country", "language", "freshness", "date_after", "date_before", "search_lang", "ui_lang", "domain_filter", "max_tokens", "max_tokens_per_page"];
/// Typed keys; everything else in the input is passed to the provider in `extra`.
const TYPED: [&str; 13] = ["query", "count", "limit", "country", "language", "freshness", "date_after", "date_before", "search_lang", "ui_lang", "domain_filter", "max_tokens", "max_tokens_per_page"];

/// Who serves a search.
pub enum Route {
    Provider(&'static dyn WebProvider),
    /// Nothing configured: anonymous free tiers, round-robin.
    Keyless,
}

impl Route {
    pub fn id(&self) -> &'static str {
        match self {
            Route::Provider(p) => p.id(),
            Route::Keyless => "keyless",
        }
    }
}

/// Explicit `web.search.provider` / `web.backend` (strict: a bad name is an error, never a
/// silent switch), else the first configured provider in autodetect order, else the ring.
pub fn resolve(c: &WebCtx) -> Result<Route, String> {
    let pin = c.cfg.search_pin();
    if !pin.is_empty() {
        return providers::get(&pin).map(Route::Provider).ok_or_else(|| {
            let known: Vec<&str> = providers::all().iter().map(|p| p.id()).collect();
            format!("web.search.provider is set to '{pin}', but no web search provider has that name (known: {}).", known.join(", "))
        });
    }
    if let Some(p) = providers::all().iter().copied().find(|p| p.auto_detect() && p.configured(c)) {
        return Ok(Route::Provider(p));
    }
    if keyless::enabled(c) {
        return Ok(Route::Keyless);
    }
    Err("No web search provider configured. Set an API key (e.g. BRAVE_API_KEY, TAVILY_API_KEY, EXA_API_KEY) or [web.search] provider; run `seagent web providers` to see what is available.".into())
}

fn str_arg(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn parse_request(input: &Value, default_count: usize) -> Result<SearchRequest, String> {
    let query = str_arg(input, "query").ok_or("missing string argument `query`")?;
    let count = match input.get("count").or_else(|| input.get("limit")) {
        None | Some(Value::Null) => default_count,
        Some(v) => {
            let n = v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).ok_or("count must be an integer")?;
            if n < 1.0 || n.fract() != 0.0 {
                return Err(format!("count must be an integer from 1 to {MAX_COUNT}."));
            }
            n as usize
        }
    }
    .clamp(1, MAX_COUNT);
    let num = |k: &str| input.get(k).and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)));
    let domain_filter = match input.get("domain_filter") {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        _ => vec![],
    };
    let extra: Map<String, Value> = input.as_object().map(|o| o.iter().filter(|(k, _)| !TYPED.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
    Ok(SearchRequest {
        query,
        count,
        country: str_arg(input, "country"),
        language: str_arg(input, "language"),
        freshness: str_arg(input, "freshness"),
        date_after: str_arg(input, "date_after"),
        date_before: str_arg(input, "date_before"),
        search_lang: str_arg(input, "search_lang"),
        ui_lang: str_arg(input, "ui_lang"),
        domain_filter,
        max_tokens: num("max_tokens"),
        max_tokens_per_page: num("max_tokens_per_page"),
        extra,
    })
}

fn set_filters(r: &SearchRequest) -> Vec<&'static str> {
    let has = [
        r.country.is_some(),
        r.language.is_some(),
        r.freshness.is_some(),
        r.date_after.is_some(),
        r.date_before.is_some(),
        r.search_lang.is_some(),
        r.ui_lang.is_some(),
        !r.domain_filter.is_empty(),
        r.max_tokens.is_some(),
        r.max_tokens_per_page.is_some(),
    ];
    FILTERS.iter().zip(has).filter(|(_, h)| *h).map(|(f, _)| *f).collect()
}

/// OpenClaw `buildUnsupportedSearchFilterResponse`: `(error code, message)`.
pub fn unsupported_filter(r: &SearchRequest, route: &Route) -> Option<(String, String)> {
    let supported: &[&str] = match route {
        Route::Provider(p) => p.filters(),
        Route::Keyless => &[],
    };
    let f = set_filters(r).into_iter().find(|f| !supported.contains(f))?;
    let date = f.starts_with("date_");
    let label = if date { "date_after/date_before filtering".to_string() } else { format!("{f} filtering") };
    let with: Vec<&str> = providers::all().iter().filter(|p| p.filters().contains(&f)).map(|p| p.label()).collect();
    let tail = if with.is_empty() { String::new() } else { format!(" Providers that support it: {}.", with.join(", ")) };
    let code = if date { "unsupported_date_filter".to_string() } else { format!("unsupported_{f}") };
    Some((code, format!("{label} is not supported by the {} provider.{tail}", route.id())))
}

fn memo_key(route: &str, r: &SearchRequest) -> String {
    let mut extra: Vec<(&String, &Value)> = r.extra.iter().collect();
    extra.sort_by_key(|(k, _)| *k);
    let parts = json!([route, normalize_query(&r.query), bucket_limit(r.count), r.country, r.language, r.freshness, r.date_after, r.date_before, r.search_lang, r.ui_lang, r.domain_filter, r.max_tokens, r.max_tokens_per_page, extra]);
    cache::digest(&parts.to_string())
}

/// A search outcome before rendering.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub provider: String,
    pub output: SearchOutput,
    pub cached: bool,
    /// Annotations: `served_by` (keyless vendor), `rescued_from`, `backend_error`.
    pub notes: Map<String, Value>,
}

fn to_value(o: &SearchOutput) -> Value {
    match o {
        SearchOutput::Results(h) => json!({"results": h}),
        SearchOutput::Answer { content, citations } => json!({"content": content, "citations": citations}),
    }
}

fn from_value(v: &Value) -> Option<SearchOutput> {
    if let Some(r) = v.get("results") {
        return serde_json::from_value::<Vec<Value>>(r.clone()).ok().map(|rows| {
            SearchOutput::Results(rows.iter().map(|h| Hit { title: super::http::s(h, "title"), url: super::http::s(h, "url"), snippet: super::http::s(h, "snippet"), published: h.get("published").and_then(|x| x.as_str()).map(Into::into), site_name: h.get("siteName").and_then(|x| x.as_str()).map(Into::into) }).collect())
        });
    }
    let content = v.get("content")?.as_str()?.to_string();
    let citations = v.get("citations").and_then(|c| c.as_array()).map(|a| a.iter().map(|c| Citation { url: super::http::s(c, "url"), title: c.get("title").and_then(|t| t.as_str()).map(Into::into) }).collect()).unwrap_or_default();
    Some(SearchOutput::Answer { content, citations })
}

fn slice(o: SearchOutput, n: usize) -> SearchOutput {
    match o {
        SearchOutput::Results(mut h) => {
            h.truncate(n);
            SearchOutput::Results(h)
        }
        a => a,
    }
}

fn rescue_eligible(c: &WebCtx, route: &Route) -> bool {
    c.cfg.keyless_rescue && keyless::enabled(c) && matches!(route, Route::Provider(p) if !p.routes_keyless(c))
}

fn keyless_search(c: &WebCtx, name: &str, r: &SearchRequest) -> (String, Result<SearchOutput, String>) {
    let (by, res) = keyless::search_with_failover(c, name, &r.query, r.count);
    match res {
        Ok(h) => (by, Ok(SearchOutput::Results(h))),
        // Whole ring down: DuckDuckGo's keyless HTML endpoint is the last resort.
        Err(e) if name.is_empty() || name == "keyless" => match DuckDuckGo.search(c, r) {
            Ok(o) => ("duckduckgo".into(), Ok(o)),
            Err(d) => (by, Err(format!("{e}; DuckDuckGo fallback also failed: {d}"))),
        },
        Err(e) => (by, Err(e)),
    }
}

/// Run one search end to end (no rendering). `Err((code, message))`.
pub fn run(c: &WebCtx, route: &Route, r: &SearchRequest) -> Result<Outcome, (String, String)> {
    if let Some(u) = unsupported_filter(r, route) {
        return Err(u);
    }
    c.check_cancel().map_err(|e| ("interrupted".to_string(), e))?;
    let id = route.id().to_string();
    let key = memo_key(&id, r);
    let memo = cache::search_memo();
    let ttl = Duration::from_secs(c.cfg.ttl_secs());
    let hit = |v: &Value| from_value(v).map(|o| Outcome { provider: v["provider"].as_str().unwrap_or(&id).to_string(), output: slice(o, r.count), cached: true, notes: Map::new() });
    if c.cfg.cache_enabled {
        if let Some(v) = memo.get(&key) {
            return Ok(hit(&v).unwrap());
        }
    }
    let lock = memo.flight(&key);
    let _g = lock.lock().unwrap();
    if c.cfg.cache_enabled {
        if let Some(v) = memo.get(&key) {
            return Ok(hit(&v).unwrap());
        }
    }
    let mut wide = r.clone();
    wide.count = bucket_limit(r.count);
    let mut notes = Map::new();
    let (provider, result, rescued) = match route {
        Route::Keyless => {
            let (by, res) = keyless_search(c, "", &wide);
            notes.insert("served_by".into(), json!(by));
            (by, res, false)
        }
        Route::Provider(p) => match p.search(c, &wide) {
            Ok(o) => (id.clone(), Ok(o), false),
            Err(e) if e != "Interrupted" && rescue_eligible(c, route) => {
                let (by, res) = keyless_search(c, p.id(), &wide);
                match res {
                    Ok(o) => {
                        notes.insert("served_by".into(), json!(by));
                        notes.insert("rescued_from".into(), json!(p.id()));
                        notes.insert("backend_error".into(), json!(format!("Configured backend '{}' failed this call ({}); result served by the keyless free tier. The next call will use '{}' again.", p.id(), crate::util::truncate_str(&e, 300), p.id())));
                        (id.clone(), Ok(o), true)
                    }
                    Err(k) => (id.clone(), Err(format!("{e} (keyless rescue also failed: {k})")), true),
                }
            }
            Err(e) => (id.clone(), Err(e), false),
        },
    };
    let output = result.map_err(|e| ("provider_error".to_string(), e))?;
    // Only successful, non-rescued responses are cached: a rescue must stay one-shot.
    if c.cfg.cache_enabled && !rescued {
        let mut v = to_value(&output);
        v["provider"] = json!(provider);
        memo.put(&key, v, ttl, 1000);
    }
    Ok(Outcome { provider, output: slice(output, r.count), cached: false, notes })
}

/// Model-facing JSON (OpenClaw `normalizeWebSearchOutput` branches `results` / `answer`).
pub fn render(o: &Outcome, query: &str, took: Duration) -> Value {
    let mut v = match &o.output {
        SearchOutput::Results(h) => json!({"kind":"results","provider":o.provider,"query":query,"count":h.len(),"results":h}),
        SearchOutput::Answer { content, citations } => json!({"kind":"answer","provider":o.provider,"query":query,"content":content,"citations":citations}),
    };
    v["tookMs"] = json!(took.as_millis() as u64);
    v["externalContent"] = json!({"untrusted":true,"source":"web_search","wrapped":true,"provider":o.provider});
    if o.cached {
        v["cached"] = json!(true);
    }
    for (k, x) in &o.notes {
        v[k] = x.clone();
    }
    v
}

pub struct WebSearch {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl WebSearch {
    fn ctx(&self, t: &ToolCtx) -> WebCtx {
        WebCtx::from_tool(self.cfg.clone(), self.env.clone(), t)
    }
}

pub fn error_output(provider: &str, code: &str, message: &str) -> ToolOutput {
    ToolOutput::err(json!({"kind":"error","provider":provider,"error":code,"message":message,"docs":providers::DOCS}).to_string())
}

impl Tool for WebSearch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "web_search".into(),
            description: "Search the web; returns normalized results (title, url, snippet) or a grounded answer with citations from the configured provider. Query operators such as site:, filetype:, -term and \"exact phrase\" pass through when the backend supports them. Supports freshness / date_after / date_before, country / language and domain_filter where the provider does. Use web_extract or web_fetch for page contents.".into(),
            input_schema: json!({"type":"object","required":["query"],"properties":{
                "query":{"type":"string","description":"Search query."},
                "count":{"type":"integer","minimum":1,"maximum":MAX_COUNT,"description":"Result count (default 5)."},
                "country":{"type":"string","description":"2-letter country code."},
                "language":{"type":"string","description":"ISO 639-1 language."},
                "freshness":{"type":"string","description":"Time filter: day/week/month/year."},
                "date_after":{"type":"string","description":"Published after YYYY-MM-DD."},
                "date_before":{"type":"string","description":"Published before YYYY-MM-DD."},
                "search_lang":{"type":"string","description":"Brave result language."},
                "ui_lang":{"type":"string","description":"Brave UI locale."},
                "domain_filter":{"type":"array","items":{"type":"string"},"description":"Restrict to (or exclude with -) domains."},
                "max_tokens":{"type":"integer","minimum":1,"maximum":1000000,"description":"Perplexity total token budget."},
                "max_tokens_per_page":{"type":"integer","minimum":1,"description":"Perplexity tokens per page."},
                "categories":{"type":"string","description":"SearXNG categories (general, news, …)."},
                "topic":{"type":"string","description":"Tavily topic: general / news / finance."},
                "search_depth":{"type":"string","description":"Tavily depth: basic / advanced."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = self.ctx(ctx);
        let payload = input.get("query").and_then(|q| q.as_str()).unwrap_or("").to_string();
        match resolve(&c) {
            Ok(Route::Provider(p)) => vec![Effect::Net { dest: host_of(&p.endpoint(&c)), payload }],
            Ok(Route::Keyless) => keyless::RING.iter().map(|v| Effect::Net { dest: host_of(&keyless::endpoint(&c, v)), payload: payload.clone() }).collect(),
            Err(_) => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if !self.cfg.search.enabled {
            return ToolOutput::err("web_search is disabled ([web.search] enabled = false).");
        }
        let c = self.ctx(ctx);
        let r = match parse_request(&input, self.cfg.search.max_results.max(1)) {
            Ok(r) => r,
            Err(e) => return error_output("", "invalid_arguments", &e),
        };
        let route = match resolve(&c) {
            Ok(x) => x,
            Err(e) => return error_output("", "missing_provider", &e),
        };
        let started = Instant::now();
        match run(&c, &route, &r) {
            Ok(o) => {
                let text = serde_json::to_string_pretty(&render(&o, &r.query, started.elapsed())).unwrap_or_default();
                let text = if text.chars().count() > OUTPUT_MAX_CHARS { format!("{}\n[truncated]", crate::util::truncate_str(&text, OUTPUT_MAX_CHARS - 12)) } else { text };
                ToolOutput::ok(wrap_web(&text, "web_search"))
            }
            Err((code, msg)) => error_output(route.id(), &code, &msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, wctx, FakeServer};

    fn tool(cfg: Value, env: &[(&str, &str)]) -> WebSearch {
        WebSearch { cfg: Arc::new(WebConfig::from_value(cfg).unwrap()), env: env_of(env) }
    }

    fn searx(srv: &FakeServer) -> Value {
        json!({"search":{"provider":"searxng"},"providers":{"searxng":{"base_url":srv.url.clone()}},"keyless_rescue":false})
    }

    fn results_srv(n: usize) -> FakeServer {
        let rows: Vec<Value> = (0..n).map(|i| json!({"title":format!("t{i}"),"url":format!("https://r{i}.com"),"content":format!("s{i}")})).collect();
        FakeServer::start(vec![("GET /search", 200, "application/json", json!({"results":rows}).to_string())])
    }

    #[test]
    fn parse_and_validate() {
        let r = parse_request(&json!({"query":" q ","limit":"7","domain_filter":"a.com,b.com","topic":"news"}), 5).unwrap();
        assert_eq!((r.query.as_str(), r.count, r.domain_filter.len()), ("q", 7, 2));
        assert_eq!(r.extra_str("topic").as_deref(), Some("news"));
        assert_eq!(parse_request(&json!({"query":"q","count":500}), 5).unwrap().count, 100);
        assert!(parse_request(&json!({"query":"q","count":0}), 5).is_err());
        assert!(parse_request(&json!({}), 5).is_err());
        let route = Route::Provider(providers::get("searxng").unwrap());
        let (code, msg) = unsupported_filter(&parse_request(&json!({"query":"q","freshness":"day"}), 5).unwrap(), &route).unwrap();
        assert_eq!(code, "unsupported_freshness");
        assert!(msg.starts_with("freshness filtering is not supported by the searxng provider."), "{msg}");
        let (code, _) = unsupported_filter(&parse_request(&json!({"query":"q","date_after":"2025-01-01"}), 5).unwrap(), &route).unwrap();
        assert_eq!(code, "unsupported_date_filter");
        assert!(unsupported_filter(&parse_request(&json!({"query":"q","language":"de"}), 5).unwrap(), &route).is_none());
    }

    #[test]
    fn resolution_order() {
        let c = wctx(json!({"search":{"provider":"bogus"}}), &[]);
        assert!(resolve(&c).err().unwrap().contains("no web search provider has that name"));
        let c = wctx(json!({"backend":"SearXNG"}), &[]);
        assert_eq!(resolve(&c).unwrap().id(), "searxng");
        let c = wctx(json!({}), &[("SEARXNG_BASE_URL", "http://127.0.0.1:1")]);
        assert_eq!(resolve(&c).unwrap().id(), "searxng", "autodetect by credential");
        let c = wctx(json!({}), &[]);
        assert_eq!(resolve(&c).unwrap().id(), "keyless");
        let c = wctx(json!({"keyless_fallback":false}), &[]);
        assert!(resolve(&c).err().unwrap().contains("No web search provider"));
    }

    #[test]
    fn tool_call_renders_wrapped_json_and_caches() {
        let _memo = crate::web::testutil::search_memo_guard();
        cache::search_memo().clear();
        let srv = results_srv(12);
        let t = tool(searx(&srv), &[]);
        let c = ctx("websearch");
        let q = format!("cache probe {}", srv.url);
        let o = t.call(&c, json!({"query":q,"count":3}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("<<<EXTERNAL_UNTRUSTED_CONTENT") && o.content.contains("Source: Web Search"));
        let json_part = &o.content[o.content.find("---\n").unwrap() + 4..o.content.rfind("\n<<<END").unwrap()];
        let v: Value = serde_json::from_str(json_part).unwrap();
        assert_eq!((v["kind"].as_str(), v["count"].as_u64(), v["provider"].as_str()), (Some("results"), Some(3), Some("searxng")));
        assert_eq!(v["results"][0]["siteName"], "r0.com");
        assert!(v.get("cached").is_none());
        // Bucketed: the provider was asked for up to 10, a second call with count 5 is a memo hit.
        let o2 = t.call(&c, json!({"query":q.to_uppercase(),"count":5}));
        let v2: Value = serde_json::from_str(&o2.content[o2.content.find("---\n").unwrap() + 4..o2.content.rfind("\n<<<END").unwrap()]).unwrap();
        assert_eq!((v2["cached"].as_bool(), v2["count"].as_u64()), (Some(true), Some(5)));
        assert_eq!(srv.requests().len(), 1);
        let eff = t.effects(&c, &json!({"query":"x"}));
        assert!(matches!(&eff[..], [Effect::Net { dest, payload }] if dest == "127.0.0.1" && payload == "x"));
    }

    #[test]
    fn errors_are_structured() {
        let srv = FakeServer::start(vec![("GET /search", 500, "text/plain", "down".into())]);
        let t = tool(searx(&srv), &[]);
        let c = ctx("websearch-err");
        let o = t.call(&c, json!({"query":"boom unique"}));
        assert!(o.is_error);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!((v["kind"].as_str(), v["error"].as_str(), v["provider"].as_str()), (Some("error"), Some("provider_error"), Some("searxng")));
        let o = t.call(&c, json!({"query":"x","freshness":"week"}));
        assert!(o.content.contains("unsupported_freshness"));
        assert!(tool(json!({"search":{"enabled":false}}), &[]).call(&c, json!({"query":"x"})).content.contains("disabled"));
    }

    #[test]
    fn rescue_serves_from_ring_once_and_is_not_cached() {
        let _memo = crate::web::testutil::search_memo_guard();
        cache::search_memo().clear();
        let bad = FakeServer::start(vec![("GET /search", 503, "text/plain", "unavailable".into())]);
        let text = json!({"results":[{"url":"https://rescued.com","title":"R","excerpts":["x"]}]}).to_string();
        let ring = FakeServer::start(vec![("POST /mcp", 200, "application/json", json!({"result":{"content":[{"text":text}]}}).to_string())]);
        let cfg = json!({"search":{"provider":"searxng"},"provider_tier":{"exa":"paid","firecrawl":"paid","keenable":"paid"},
            "providers":{"searxng":{"base_url":bad.url.clone()},"parallel":{"keyless_url":format!("{}/mcp",ring.url)}}});
        let c = wctx(cfg, &[]);
        let route = resolve(&c).unwrap();
        let r = parse_request(&json!({"query":"rescue me"}), 5).unwrap();
        let o = run(&c, &route, &r).unwrap();
        assert_eq!(o.notes["rescued_from"], "searxng");
        assert_eq!(o.notes["served_by"], "parallel");
        assert!(o.notes["backend_error"].as_str().unwrap().contains("unavailable"));
        let SearchOutput::Results(h) = &o.output else { panic!() };
        assert_eq!(h[0].url, "https://rescued.com");
        run(&c, &route, &r).unwrap();
        assert_eq!(bad.requests().len(), 2, "rescued results are not cached");
    }

    /// Every bundled search backend is selectable by config alone (`[web.search] provider` +
    /// `[web.providers.<id>] base_url`) and the registered `web_search` really calls it: the fake
    /// server answers 404 for everything, so the call fails naming that provider and no other
    /// backend (keyless ring, rescue) was touched.
    #[test]
    fn every_provider_is_reachable_through_config() {
        let cases: &[(&str, &str, &str)] = &[
            ("brave", "BRAVE_API_KEY", "base_url"),
            ("minimax", "MINIMAX_API_KEY", "base_url"),
            ("gemini", "GEMINI_API_KEY", "base_url"),
            ("xai", "XAI_API_KEY", "base_url"),
            ("kimi", "KIMI_API_KEY", "base_url"),
            ("perplexity", "PERPLEXITY_API_KEY", "search_base_url"),
            ("firecrawl", "FIRECRAWL_API_KEY", "base_url"),
            ("exa", "EXA_API_KEY", "base_url"),
            ("tavily", "TAVILY_API_KEY", "base_url"),
            ("parallel", "PARALLEL_API_KEY", "base_url"),
            ("keenable", "KEENABLE_API_KEY", "base_url"),
            ("deepseek", "DEEPSEEK_API_KEY", "base_url"),
            ("duckduckgo", "", "base_url"),
            ("ollama", "", "base_url"),
            ("searxng", "", "base_url"),
            ("openai-native", "OPENAI_API_KEY", "base_url"),
        ];
        let covered: Vec<&str> = cases.iter().map(|(id, ..)| *id).collect();
        for p in providers::all() {
            // `codex` drives a local app-server process: covered by `codex::tests`.
            assert!(p.id() == "codex" || covered.contains(&p.id()), "{} has no reachability case", p.id());
        }
        let c = ctx("websearch-every");
        for (id, var, base_key) in cases {
            let srv = FakeServer::with(|_| (404, "text/plain".into(), b"no route".to_vec(), vec![]));
            let mut base = serde_json::Map::new();
            base.insert((*base_key).to_string(), json!(srv.url));
            let mut provs = serde_json::Map::new();
            provs.insert((*id).to_string(), Value::Object(base));
            let cfg = json!({"search":{"provider":id},"keyless_fallback":false,"keyless_rescue":false,"providers":Value::Object(provs)});
            let env: Vec<(&str, &str)> = if var.is_empty() { vec![] } else { vec![(*var, "test-key-123456")] };
            let o = tool(cfg, &env).call(&c, json!({"query": format!("reach {id}")}));
            assert!(o.is_error, "{id} unexpectedly succeeded against an empty fake server: {}", o.content);
            let v: Value = serde_json::from_str(&o.content).unwrap_or_else(|_| panic!("{id}: {}", o.content));
            assert_eq!(v["provider"], json!(id), "{id} routing: {}", o.content);
            assert!(!srv.requests().is_empty(), "{id} was never called");
        }
        // The upstream config names (`brave_free`, `ddgs`, `moonshot`, `grok`, …) are aliases.
        for (alias, id) in [("brave-free", "brave"), ("ddgs", "duckduckgo"), ("ddg", "duckduckgo"), ("moonshot", "kimi"), ("grok", "xai"), ("firecrawl-free", "firecrawl"), ("openai", "openai-native")] {
            assert_eq!(providers::get(alias).map(|p| p.id()), Some(id), "{alias}");
        }
        // `codex` has no HTTP endpoint of its own (it drives a local app-server turn), so config
        // selection is what is checked here; the turn itself is `codex::tests`.
        let c = wctx(json!({"search":{"provider":"codex"},"providers":{"codex":{"command":"/bin/false"}}}), &[]);
        assert_eq!(resolve(&c).unwrap().id(), "codex");
    }
}
