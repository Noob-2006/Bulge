//! The Tavily dedicated tools: `tavily_search` and `tavily_extract`. Ported from OpenClaw
//! `extensions/tavily/index.ts` (both TypeBox schemas verbatim: `search_depth` / `topic` /
//! `time_range` enums, `include_domains` / `exclude_domains`, `urls` 1–20, `query`,
//! `extract_depth`, `chunks_per_source` 1–5, `include_images`; argument validation messages
//! and the per-tool missing-key errors) and `src/tavily-client.ts` (result `score`, published
//! date, answer, `truncated`, the default count of 5, extract `rawContent` / `content` / images /
//! `failedResults`, the 20 000-char content and 4 000-char error budgets, the 20-result extract
//! cap and the 20-image budget). HTTP, credentials, base URL, keyless mode and response
//! normalisation are the provider layer's: [`crate::web::providers::tavily`].
//! OpenClaw is MIT-licensed; see `THIRD_PARTY_NOTICES.md`.
//!
//! Per-tool request timeouts stay where the provider already implements upstream's defaults:
//! `resolveTavilySearchTimeoutSeconds` (30 s) and `resolveTavilyExtractTimeoutSeconds` (60 s),
//! overridable with `[web.providers.tavily] timeout_seconds` / `extract_timeout_seconds`.

use crate::web::content::wrap_web;
use crate::web::http::{self, EnvFn, WebCtx};
use crate::web::providers::tavily::{self, ExtractParams, SearchParams, Tavily, EXTRACT_MAX_RESULTS};
use crate::web::providers::WebProvider;
use crate::web::{keyless, WebConfig};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

/// OpenClaw `TAVILY_SEARCH_MAX_CONTENT_CHARS`.
const SEARCH_MAX_CONTENT: usize = 20_000;
/// OpenClaw `DEFAULT_SEARCH_COUNT`: the count when the model passes no `max_results`.
const SEARCH_DEFAULT_COUNT: usize = 5;
/// OpenClaw `TAVILY_EXTRACT_MAX_CONTENT_CHARS` / `TAVILY_EXTRACT_MAX_ERROR_CHARS`.
const EXTRACT_MAX_CONTENT: usize = 20_000;
const EXTRACT_MAX_ERROR_CHARS: usize = 4_000;
/// `readStringArrayParam` on a >20-entry `urls` list would already fail upstream's schema.
const MAX_EXTRACT_URLS: usize = EXTRACT_MAX_RESULTS;

fn ostr(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// `readStringArrayParam`: a lone string is a one-element list, entries are trimmed and blanks
/// dropped.
fn strs(v: &Value, k: &str) -> Vec<String> {
    let item = |s: &str| s.trim().to_string();
    match v.get(k) {
        Some(Value::String(s)) => vec![item(s)],
        Some(Value::Array(a)) => a.iter().filter_map(|s| s.as_str()).map(item).collect(),
        _ => vec![],
    }
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect()
}

fn wc(cfg: &Arc<WebConfig>, env: &EnvFn, t: &ToolCtx) -> WebCtx {
    WebCtx::from_tool(cfg.clone(), env.clone(), t)
}

/// Opt-in keyless Tavily (Hermes): selected as the backend, or pinned to the free tier.
fn keyless_ok(c: &WebCtx) -> bool {
    keyless::use_keyless(c, "tavily", None) && (c.cfg.selects("tavily") || c.cfg.tier("tavily") == "free")
}

/// Upstream `runTavilySearch` / `runTavilyExtract` key gate, before any request is made.
fn key_error(c: &WebCtx, tool: &str) -> Option<String> {
    if c.key("tavily", Tavily.env_vars()).is_some() || keyless_ok(c) {
        return None;
    }
    Some(match tool {
        "tavily_search" => "web_search (tavily) needs a Tavily API key. Set TAVILY_API_KEY in the environment, or configure [web.providers.tavily] api_key.".to_string(),
        _ => "tavily_extract needs a Tavily API key. Set TAVILY_API_KEY in the environment, or configure [web.providers.tavily] api_key.".to_string(),
    })
}

/// A budgeted string, sharing one call-wide char budget (upstream's `wrapBounded*`).
fn take(s: &str, budget: &mut usize, truncated: &mut bool) -> String {
    let t = crate::util::truncate_str(s, *budget).to_string();
    *truncated |= t.len() < s.len();
    *budget -= t.len();
    t
}

/// `max_results` as upstream `readPositiveIntegerParam` reads it.
fn max_results(v: &Value) -> Result<Option<usize>, String> {
    let Some(x) = v.get("max_results").filter(|x| !x.is_null()) else { return Ok(None) };
    let msg = "max_results must be an integer from 1 to 20.";
    let n = x.as_u64().or_else(|| x.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0).map(|f| f as u64)).ok_or(msg)?;
    if !(1..=20).contains(&n) {
        return Err(msg.into());
    }
    Ok(Some(n as usize))
}

/// One of `allowed` when the key is present (upstream `optionalStringEnum`).
fn enum_arg(v: &Value, k: &str, allowed: &[&str], msg: &str) -> Result<Option<String>, String> {
    match ostr(v, k) {
        None => Ok(None),
        Some(s) => {
            if allowed.contains(&s.as_str()) {
                Ok(Some(s))
            } else {
                Err(format!("{msg} (one of {}).", allowed.join(", ")))
            }
        }
    }
}

// ───────────────────────────── tavily_search ─────────────────────────────

pub struct TavilySearchTool {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Tool for TavilySearchTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "tavily_search".into(),
            description: "Search the web using Tavily Search API. Supports search depth, topic filtering, domain filters, time ranges, and AI answer summaries.".into(),
            input_schema: json!({"type":"object","required":["query"],"additionalProperties":false,"properties":{
                "query":{"type":"string","description":"Search query string."},
                "search_depth":{"type":"string","enum":["basic","advanced"],"description":"Search depth: \"basic\" (default, faster) or \"advanced\" (more thorough)."},
                "topic":{"type":"string","enum":["general","news","finance"],"description":"Search topic: \"general\" (default), \"news\", or \"finance\"."},
                "max_results":{"type":"integer","minimum":1,"maximum":20,"description":"Number of results to return (1-20)."},
                "include_answer":{"type":"boolean","description":"Include an AI-generated answer summary (default: false)."},
                "time_range":{"type":"string","enum":["day","week","month","year"],"description":"Filter results by recency: 'day', 'week', 'month', or 'year'."},
                "include_domains":{"type":"array","items":{"type":"string"},"description":"Only include results from these domains."},
                "exclude_domains":{"type":"array","items":{"type":"string"},"description":"Exclude results from these domains."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = wc(&self.cfg, &self.env, ctx);
        vec![Effect::Net { dest: http::host_of(&Tavily.endpoint(&c)), payload: ostr(input, "query").unwrap_or_default() }]
    }
    fn call(&self, t: &ToolCtx, input: Value) -> ToolOutput {
        let c = wc(&self.cfg, &self.env, t);
        let Some(query) = ostr(&input, "query") else { return ToolOutput::err("query required") };
        let search_depth = match enum_arg(&input, "search_depth", &["basic", "advanced"], "search_depth must be \"basic\" or \"advanced\"") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let topic = match enum_arg(&input, "topic", &["general", "news", "finance"], "topic must be \"general\", \"news\" or \"finance\"") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let time_range = match enum_arg(&input, "time_range", &["day", "week", "month", "year"], "time_range must be \"day\", \"week\", \"month\" or \"year\"") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let n = match max_results(&input) {
            Ok(n) => n,
            Err(e) => return ToolOutput::err(e),
        };
        if let Some(e) = key_error(&c, "tavily_search") {
            return ToolOutput::err(e);
        }
        let p = SearchParams {
            query: query.clone(),
            max_results: n.unwrap_or(SEARCH_DEFAULT_COUNT),
            search_depth,
            topic,
            include_answer: input.get("include_answer").and_then(|b| b.as_bool()) == Some(true),
            time_range,
            include_domains: strs(&input, "include_domains"),
            exclude_domains: strs(&input, "exclude_domains"),
        };
        let started = Instant::now();
        let (rows, answer, mut truncated) = match tavily::run_search_scored(&c, &p) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let mut budget = SEARCH_MAX_CONTENT;
        let mut results: Vec<Value> = vec![];
        for (h, score) in rows {
            let mut row = json!({"title": take(&h.title, &mut budget, &mut truncated), "url": h.url, "snippet": take(&h.snippet, &mut budget, &mut truncated)});
            if let Some(s) = score {
                row["score"] = json!(s);
            }
            if let Some(pb) = h.published {
                row["published"] = json!(pb);
            }
            results.push(row);
        }
        let mut v = json!({
            "query": query,
            "provider": "tavily",
            "count": results.len(),
            "tookMs": started.elapsed().as_millis() as u64,
            "externalContent": {"untrusted": true, "source": "web_search", "provider": "tavily", "wrapped": true},
            "results": results,
        });
        if let Some(a) = answer {
            v["answer"] = json!(take(&a, &mut budget, &mut truncated));
        }
        if truncated {
            v["truncated"] = json!(true);
        }
        ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(&v).unwrap_or_default(), "web_search"))
    }
}

// ───────────────────────────── tavily_extract ─────────────────────────────

pub struct TavilyExtractTool {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Tool for TavilyExtractTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "tavily_extract".into(),
            description: "Extract clean content from one or more URLs using Tavily. Handles JS-rendered pages. Supports query-focused chunking.".into(),
            input_schema: json!({"type":"object","required":["urls"],"additionalProperties":false,"properties":{
                "urls":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"One or more URLs to extract content from (max 20)."},
                "query":{"type":"string","description":"Rerank extracted chunks by relevance to this query."},
                "extract_depth":{"type":"string","enum":["basic","advanced"],"description":"\"basic\" (default) or \"advanced\" (for JS-heavy pages)."},
                "chunks_per_source":{"type":"integer","minimum":1,"maximum":5,"description":"Chunks per URL (1-5, requires query)."},
                "include_images":{"type":"boolean","description":"Include image URLs in extraction results."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = wc(&self.cfg, &self.env, ctx);
        let payload = strs(input, "urls").join(" ");
        // One request per extract call, even for several URLs.
        vec![Effect::Net { dest: http::host_of(&format!("{}/extract", c.base_url("tavily", Some("TAVILY_BASE_URL"), "https://api.tavily.com"))), payload }]
    }
    fn call(&self, t: &ToolCtx, input: Value) -> ToolOutput {
        let c = wc(&self.cfg, &self.env, t);
        let urls = strs(&input, "urls");
        if urls.is_empty() {
            return ToolOutput::err("tavily_extract requires at least one URL.");
        }
        if urls.len() > MAX_EXTRACT_URLS {
            return ToolOutput::err(format!("tavily_extract accepts at most {MAX_EXTRACT_URLS} URLs per call."));
        }
        let query = ostr(&input, "query");
        let extract_depth = match enum_arg(&input, "extract_depth", &["basic", "advanced"], "extract_depth must be \"basic\" or \"advanced\"") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let chunks = match input.get("chunks_per_source").filter(|x| !x.is_null()) {
            None => None,
            Some(x) => {
                let msg = "chunks_per_source must be an integer from 1 to 5.";
                match x.as_u64().filter(|n| (1..=5).contains(n)) {
                    Some(n) => Some(n),
                    None => return ToolOutput::err(msg),
                }
            }
        };
        if chunks.is_some() && query.is_none() {
            return ToolOutput::err("tavily_extract requires query when chunks_per_source is set.");
        }
        if let Some(e) = key_error(&c, "tavily_extract") {
            return ToolOutput::err(e);
        }
        let p = ExtractParams {
            urls: urls.clone(),
            query,
            extract_depth,
            chunks_per_source: chunks,
            include_images: input.get("include_images").and_then(|b| b.as_bool()) == Some(true),
        };
        let started = Instant::now();
        let payload = match tavily::run_extract(&c, &p) {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let (results, failed, truncated) = shape_extract(&payload);
        let mut v = json!({
            "provider": "tavily",
            "count": results.len(),
            "tookMs": started.elapsed().as_millis() as u64,
            "externalContent": {"untrusted": true, "source": "web_fetch", "provider": "tavily", "wrapped": true},
            "results": results,
        });
        if !failed.is_empty() {
            v["failedResults"] = json!(failed);
        }
        if truncated {
            v["truncated"] = json!(true);
        }
        ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(&v).unwrap_or_default(), "web_fetch"))
    }
}

/// `run_extract` payload → upstream's `results` / `failedResults` lists, with the shared content
/// and error budgets, the 20-result caps and the 20-image budget (`TAVILY_EXTRACT_MAX_*`).
fn shape_extract(payload: &Value) -> (Vec<Value>, Vec<Value>, bool) {
    let raw = payload.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let mut truncated = raw.len() > EXTRACT_MAX_RESULTS;
    let mut content_budget = EXTRACT_MAX_CONTENT;
    let mut image_budget = EXTRACT_MAX_RESULTS;
    let mut results: Vec<Value> = vec![];
    for r in raw.iter().take(EXTRACT_MAX_RESULTS) {
        let Some(url) = tavily::result_url(r.get("url").unwrap_or(&Value::Null)) else { continue };
        // `rawContent` is always present (empty when Tavily sends none); `content` is the shorter
        // extract preview and stays its own field, as upstream keeps them apart.
        let raw_content = r.get("raw_content").and_then(|t| t.as_str()).unwrap_or("");
        let mut row = json!({"url": url, "rawContent": take(raw_content, &mut content_budget, &mut truncated)});
        if let Some(text) = r.get("content").and_then(|t| t.as_str()) {
            row["content"] = json!(take(text, &mut content_budget, &mut truncated));
        }
        // Images are reported whenever Tavily returns an array, whatever `include_images` asked
        // for, sharing one 20-image budget across the whole call.
        if let Some(raw_images) = r.get("images").and_then(|i| i.as_array()) {
            truncated |= raw_images.len() > image_budget;
            let images: Vec<String> = raw_images.iter().take(image_budget).filter_map(tavily::result_url).collect();
            image_budget -= images.len();
            row["images"] = json!(images);
        }
        results.push(row);
    }
    let mut error_budget = EXTRACT_MAX_ERROR_CHARS;
    let raw_failed = payload.get("failed_results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    truncated |= raw_failed.len() > EXTRACT_MAX_RESULTS;
    // A failure without a usable URL or a string `error` is dropped, as upstream does.
    let failed: Vec<Value> = raw_failed
        .iter()
        .take(EXTRACT_MAX_RESULTS)
        .filter_map(|f| {
            let url = tavily::result_url(f.get("url").unwrap_or(&Value::Null))?;
            let e = f.get("error").and_then(|e| e.as_str())?;
            Some(json!({"url": url, "error": take(e, &mut error_budget, &mut truncated)}))
        })
        .collect();
    (results, failed, truncated)
}

/// Both dedicated tools for this `[web]` config. Upstream registers them with the plugin
/// unconditionally (`index.ts` `register`) and only reports a missing key per call
/// (`tavily-client.ts`); with no plugin entitlements in seagent, they are registered when Tavily is
/// the selected backend, a credential is configured, or keyless access applies.
pub fn tools(cfg: Arc<WebConfig>, env: EnvFn) -> Vec<Arc<dyn Tool>> {
    let c = WebCtx::new(cfg.clone(), env.clone());
    // A configured `api_key` counts even as a `{{secret:…}}` placeholder: the vault resolves it
    // at call time (registration only needs to know a credential exists).
    let configured = c.cfg.provider("tavily").get("api_key").and_then(|v| v.as_str()).is_some_and(|k| !k.trim().is_empty());
    let key = configured || Tavily.env_vars().iter().any(|v| c.var(v).is_some()) || keyless_ok(&c);
    if !key {
        return vec![];
    }
    vec![Arc::new(TavilySearchTool { cfg: cfg.clone(), env: env.clone() }), Arc::new(TavilyExtractTool { cfg, env })]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, FakeServer};

    fn search_srv() -> FakeServer {
        FakeServer::start(vec![(
            "POST /search",
            200,
            "application/json",
            json!({
                "answer": "Short answer",
                "results": [
                    {"title":"A","url":"https://a.com/x","content":"ca","score":0.91,"published_date":"Tue, 03 Jun 2025 10:00:00 GMT"},
                    {"title":"B","url":"https://b.com","content":"cb"},
                    {"title":"no url"}
                ]
            })
            .to_string(),
        )])
    }

    fn extract_srv() -> FakeServer {
        FakeServer::start(vec![(
            "POST /extract",
            200,
            "application/json",
            json!({
                "results": [{"url":"https://a.com","title":"A","raw_content":"raw a","images":["https://a.com/i.png"]}],
                "failed_results": [{"url":"https://b.com","error":"blocked by site"}]
            })
            .to_string(),
        )])
    }

    fn unwrap_json(out: &ToolOutput) -> Value {
        assert!(!out.is_error, "{}", out.content);
        let body = &out.content[out.content.find("---\n").expect("envelope") + 4..out.content.rfind("\n<<<END").expect("envelope end")];
        serde_json::from_str(body.trim()).expect("json body")
    }

    #[test]
    fn search_schema_and_request_shape() {
        let s = search_srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilySearchTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        let spec = t.spec();
        let props = &spec.input_schema["properties"];
        let names: Vec<&String> = props.as_object().unwrap().keys().collect();
        assert_eq!(names, ["exclude_domains", "include_answer", "include_domains", "max_results", "query", "search_depth", "time_range", "topic"]);
        assert_eq!(spec.input_schema["required"], json!(["query"]));
        assert_eq!(props["search_depth"]["enum"], json!(["basic", "advanced"]));
        assert_eq!(props["topic"]["enum"], json!(["general", "news", "finance"]));
        assert_eq!(props["time_range"]["enum"], json!(["day", "week", "month", "year"]));
        assert_eq!((props["max_results"]["minimum"].as_u64(), props["max_results"]["maximum"].as_u64()), (Some(1), Some(20)));

        let out = t.call(
            &ctx("tavily-search"),
            json!({"query":"rust async","search_depth":"advanced","topic":"news","max_results":2,"include_answer":true,
                   "time_range":"week","include_domains":["a.com"],"exclude_domains":["b.com"]}),
        );
        let v = unwrap_json(&out);
        // Every result keeps its relevance score; entries without a usable URL are dropped.
        assert_eq!((v["provider"].as_str(), v["count"].as_u64()), (Some("tavily"), Some(2)));
        assert_eq!(v["results"][0]["score"].as_f64(), Some(0.91));
        assert_eq!(v["results"][0]["published"], "2025-06-03T10:00:00.000Z");
        assert!(v["results"][1].get("score").is_none(), "{v}");
        assert_eq!(v["answer"], "Short answer");
        // Upstream flags `truncated` when the payload holds more rows than were asked for.
        assert_eq!(v["truncated"].as_bool(), Some(true));
        assert!(out.content.contains("<<<EXTERNAL_UNTRUSTED_CONTENT"));
        let q = s.last();
        assert_eq!(q.header("authorization").as_deref(), Some("Bearer tvly-test"));
        assert_eq!(q.header("x-client-source").as_deref(), Some("seagent"));
        let b = q.json();
        assert_eq!((b["query"].as_str(), b["max_results"].as_u64()), (Some("rust async"), Some(2)));
        assert_eq!((b["search_depth"].as_str(), b["topic"].as_str()), (Some("advanced"), Some("news")));
        assert_eq!((b["include_answer"].as_bool(), b["time_range"].as_str()), (Some(true), Some("week")));
        assert_eq!((b["include_domains"][0].as_str(), b["exclude_domains"][0].as_str()), (Some("a.com"), Some("b.com")));
        assert_eq!(b["include_raw_content"].as_bool(), Some(false), "raw content stays off for search");
    }

    #[test]
    fn search_argument_validation_and_missing_key() {
        let cfg = Arc::new(WebConfig::from_value(json!({})).unwrap());
        let t = TavilySearchTool { cfg, env: env_of(&[]) };
        let c = ctx("tavily-args");
        assert_eq!(t.call(&c, json!({})).content, "query required");
        assert_eq!(t.call(&c, json!({"query":"q","max_results":0})).content, "max_results must be an integer from 1 to 20.");
        assert_eq!(t.call(&c, json!({"query":"q","max_results":21})).content, "max_results must be an integer from 1 to 20.");
        assert_eq!(t.call(&c, json!({"query":"q","max_results":"many"})).content, "max_results must be an integer from 1 to 20.");
        assert!(t.call(&c, json!({"query":"q","search_depth":"deep"})).content.contains("search_depth must be"));
        // Upstream's per-tool key error, before any request.
        let e = t.call(&c, json!({"query":"q"})).content;
        assert_eq!(e, "web_search (tavily) needs a Tavily API key. Set TAVILY_API_KEY in the environment, or configure [web.providers.tavily] api_key.");
        assert!(e.contains("TAVILY_API_KEY"));
    }

    #[test]
    fn search_truncates_the_content_budget() {
        let long = "x".repeat(30_000);
        let s = FakeServer::start(vec![("POST /search", 200, "application/json", json!({"results":[{"title":"t","url":"https://a.com","content":long}]}).to_string())]);
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone(),"api_key":"k-123456"}}})).unwrap());
        let t = TavilySearchTool { cfg, env: env_of(&[]) };
        let v = unwrap_json(&t.call(&ctx("tavily-trunc"), json!({"query":"q"})));
        assert_eq!(v["truncated"].as_bool(), Some(true));
        assert!(v["results"][0]["snippet"].as_str().unwrap().chars().count() <= SEARCH_MAX_CONTENT);
    }

    #[test]
    fn extract_schema_request_and_output() {
        let s = extract_srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilyExtractTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        let spec = t.spec();
        assert_eq!(spec.input_schema["properties"]["urls"]["maxItems"].as_u64(), Some(20));
        assert_eq!(spec.input_schema["properties"]["extract_depth"]["enum"], json!(["basic", "advanced"]));
        assert_eq!(spec.input_schema["properties"]["chunks_per_source"]["maximum"].as_u64(), Some(5));

        let out = t.call(&ctx("tavily-extract"), json!({"urls":["https://a.com","https://b.com"],"query":"pricing","extract_depth":"advanced","chunks_per_source":3,"include_images":true}));
        let v = unwrap_json(&out);
        assert_eq!((v["provider"].as_str(), v["count"].as_u64()), (Some("tavily"), Some(1)));
        assert_eq!((v["results"][0]["url"].as_str(), v["results"][0]["rawContent"].as_str()), (Some("https://a.com"), Some("raw a")));
        assert_eq!(v["failedResults"][0]["url"], "https://b.com");
        assert_eq!(v["failedResults"][0]["error"], "blocked by site");
        assert!(out.content.contains("Source: Web Fetch"), "extract text carries the fetch warning");
        let b = s.last().json();
        assert_eq!((b["urls"][0].as_str(), b["query"].as_str()), (Some("https://a.com"), Some("pricing")));
        assert_eq!((b["extract_depth"].as_str(), b["chunks_per_source"].as_u64(), b["include_images"].as_bool()), (Some("advanced"), Some(3), Some(true)));
    }

    #[test]
    fn extract_argument_validation_and_missing_key() {
        let cfg = Arc::new(WebConfig::from_value(json!({})).unwrap());
        let t = TavilyExtractTool { cfg, env: env_of(&[]) };
        let c = ctx("tavily-extract-args");
        assert_eq!(t.call(&c, json!({"urls":[]})).content, "tavily_extract requires at least one URL.");
        assert_eq!(t.call(&c, json!({})).content, "tavily_extract requires at least one URL.");
        assert_eq!(t.call(&c, json!({"urls":"   "})).content, "tavily_extract requires at least one URL.");
        assert!(t.call(&c, json!({"urls":["https://a.com"],"chunks_per_source":2})).content.contains("requires query when chunks_per_source is set"));
        assert!(t.call(&c, json!({"urls":["https://a.com"],"chunks_per_source":9,"query":"q"})).content.contains("1 to 5"));
        assert!(t.call(&c, json!({"urls":["https://a.com"],"extract_depth":"deep"})).content.contains("extract_depth must be"));
        let many: Vec<String> = (0..21).map(|i| format!("https://a.com/{i}")).collect();
        assert!(t.call(&c, json!({"urls": many})).content.contains("at most 20 URLs"));
        assert_eq!(
            t.call(&c, json!({"urls":["https://a.com"]})).content,
            "tavily_extract needs a Tavily API key. Set TAVILY_API_KEY in the environment, or configure [web.providers.tavily] api_key."
        );
    }

    #[test]
    fn provider_errors_reach_the_model() {
        let s = FakeServer::start(vec![("POST /extract", 401, "application/json", r#"{"detail":"invalid api key tvly-bad-key"}"#.into())]);
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilyExtractTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-bad-key")]) };
        let out = t.call(&ctx("tavily-err"), json!({"urls":["https://a.com"]}));
        assert!(out.is_error);
        assert!(out.content.contains("Tavily Extract API error (401)"), "{}", out.content);
        assert!(!out.content.contains("tvly-bad-key"), "the key is redacted");
    }

    #[test]
    fn tools_only_exist_when_tavily_is_usable() {
        let names = |cfg: Value, env: &[(&str, &str)]| -> Vec<String> {
            tools(Arc::new(WebConfig::from_value(cfg).unwrap()), env_of(env)).iter().map(|t| t.spec().name).collect()
        };
        assert_eq!(names(json!({}), &[]), Vec::<String>::new());
        assert_eq!(names(json!({}), &[("TAVILY_API_KEY", "k")]), vec!["tavily_search", "tavily_extract"]);
        assert_eq!(names(json!({"search":{"provider":"tavily"}}), &[]), vec!["tavily_search", "tavily_extract"]);
        assert_eq!(names(json!({"providers":{"tavily":{"api_key":"{{secret:TAVILY_API_KEY}}"}}}), &[]), vec!["tavily_search", "tavily_extract"]);
        assert!(names(json!({"search":{"provider":"brave"}}), &[]).is_empty());
    }

    /// Upstream's `DEFAULT_SEARCH_COUNT` (5) wins over `[web.search] max_results` when the model
    /// passes none; an explicit `max_results` still does.
    #[test]
    fn search_defaults_to_five_results() {
        let s = search_srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"search":{"max_results":10},"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilySearchTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        let v = unwrap_json(&t.call(&ctx("tavily-default"), json!({"query":"q"})));
        assert_eq!(s.last().json()["max_results"].as_u64(), Some(SEARCH_DEFAULT_COUNT as u64));
        assert_eq!(v["count"].as_u64(), Some(2));
        assert!(v.get("truncated").is_none(), "three rows fit in the default count: {v}");
        unwrap_json(&t.call(&ctx("tavily-default-3"), json!({"query":"q","max_results":1})));
        assert_eq!(s.last().json()["max_results"].as_u64(), Some(1));
    }

    /// `readStringArrayParam` takes a lone string wherever it takes a list (`urls`,
    /// `include_domains`, `exclude_domains`), trimming entries.
    #[test]
    fn single_string_lists_are_accepted() {
        let s = search_srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilySearchTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        unwrap_json(&t.call(&ctx("tavily-str"), json!({"query":"q","include_domains":"a.com","exclude_domains":" b.com "})));
        let b = s.last().json();
        assert_eq!((b["include_domains"][0].as_str(), b["exclude_domains"][0].as_str()), (Some("a.com"), Some("b.com")));

        let s = extract_srv();
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilyExtractTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        let v = unwrap_json(&t.call(&ctx("tavily-str-e"), json!({"urls":" https://a.com "})));
        assert_eq!(s.last().json()["urls"][0].as_str(), Some("https://a.com"));
        assert_eq!(v["count"].as_u64(), Some(1));
    }

    /// Upstream keeps `rawContent` and `content` apart, reports `images` for every row under one
    /// 20-image budget, and drops failures without a string `error` (and ignores `failed_urls`).
    #[test]
    fn extract_rows_keep_content_and_images_within_budgets() {
        let rows: Vec<Value> = (0..3)
            .map(|i| {
                json!({"url": format!("https://a.com/{i}"), "raw_content": format!("raw {i}"), "content": format!("short {i}"),
                       "images": (0..12).map(|j| format!("https://a.com/{i}/{j}.png")).collect::<Vec<_>>(), "title": "T"})
            })
            .collect();
        let payload = json!({
            "results": rows,
            "failed_results": [
                {"url":"https://b.com","error":"blocked"},
                {"url":"https://c.com"},
                {"url":"javascript:alert(1)","error":"bad"},
                {"url":"https://d.com","error":42}
            ],
            "failed_urls": ["https://e.com"]
        });
        let (results, failed, truncated) = shape_extract(&payload);
        assert_eq!(results.len(), 3);
        assert_eq!((results[0]["rawContent"].as_str(), results[0]["content"].as_str()), (Some("raw 0"), Some("short 0")));
        assert!(results[0].get("title").is_none(), "upstream keeps url/rawContent/content/images only: {}", results[0]);
        let images: usize = results.iter().map(|r| r["images"].as_array().unwrap().len()).sum();
        assert_eq!(images, EXTRACT_MAX_RESULTS, "one 20-image budget for the whole call");
        assert_eq!((results[0]["images"].as_array().unwrap().len(), results[2]["images"].as_array().unwrap().len()), (12, 0));
        assert!(truncated);
        assert_eq!(failed.len(), 1, "only a usable URL plus a string error survives: {failed:?}");
        assert_eq!((failed[0]["url"].as_str(), failed[0]["error"].as_str()), (Some("https://b.com"), Some("blocked")));
    }

    /// One 20 000-char budget covers `rawContent` and `content` of every row (`TAVILY_EXTRACT_MAX_CONTENT_CHARS`).
    #[test]
    fn extract_shares_one_content_budget() {
        let payload = json!({"results":[
            {"url":"https://a.com","raw_content":"r".repeat(15_000),"content":"c".repeat(15_000)},
            {"url":"https://b.com","raw_content":"second"}
        ]});
        let (results, _, truncated) = shape_extract(&payload);
        assert!(truncated);
        let first = results[0]["rawContent"].as_str().unwrap().len() + results[0]["content"].as_str().unwrap().len();
        assert_eq!(first, EXTRACT_MAX_CONTENT);
        assert_eq!(results[1]["rawContent"], "");
    }

    /// The model sees upstream's extract object: no `query`, no `title`, `failedResults` only when
    /// something failed.
    #[test]
    fn extract_output_shape_matches_upstream() {
        let s = FakeServer::start(vec![(
            "POST /extract",
            200,
            "application/json",
            json!({"results":[{"url":"https://a.com","raw_content":"raw a","content":"short a","images":["https://a.com/i.png","nope"]}]}).to_string(),
        )]);
        let cfg = Arc::new(WebConfig::from_value(json!({"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        let t = TavilyExtractTool { cfg, env: env_of(&[("TAVILY_API_KEY", "tvly-test")]) };
        let v = unwrap_json(&t.call(&ctx("tavily-shape"), json!({"urls":["https://a.com"],"query":"pricing"})));
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["count", "externalContent", "provider", "results", "tookMs"]);
        assert_eq!(v["results"][0]["images"], json!(["https://a.com/i.png"]));
        assert_eq!(v["results"][0]["content"], "short a");
        assert!(v["results"][0].get("title").is_none());
        assert_eq!(v["externalContent"], json!({"untrusted":true,"source":"web_fetch","provider":"tavily","wrapped":true}));
    }

    /// Keyless Tavily (selected, no key) still serves both tools, as the provider layer allows.
    #[test]
    fn keyless_selection_serves_both_tools() {
        let s = FakeServer::start(vec![
            ("POST /search", 200, "application/json", json!({"results":[{"title":"T","url":"https://t.example","content":"c","score":0.5}]}).to_string()),
            ("POST /extract", 200, "application/json", json!({"results":[{"url":"https://t.example","raw_content":"body"}]}).to_string()),
        ]);
        let cfg = Arc::new(WebConfig::from_value(json!({"search":{"provider":"tavily"},"providers":{"tavily":{"base_url":s.url.clone()}}})).unwrap());
        assert_eq!(tools(cfg.clone(), env_of(&[])).len(), 2);
        let se = TavilySearchTool { cfg: cfg.clone(), env: env_of(&[]) };
        assert!(!se.call(&ctx("tavily-keyless-s"), json!({"query":"q"})).is_error);
        assert_eq!(s.last().header("x-tavily-access-mode").as_deref(), Some("keyless"));
        let ex = TavilyExtractTool { cfg, env: env_of(&[]) };
        assert!(!ex.call(&ctx("tavily-keyless-e"), json!({"urls":["https://t.example"]})).is_error);
    }
}
