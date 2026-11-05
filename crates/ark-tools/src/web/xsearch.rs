//! `x_search`: search X (Twitter) posts through xAI's server-side `x_search` tool on the
//! Responses API. Hermes `tools/x_search_tool.py` (strict date validation incl. "from_date in the
//! future", `@`-stripped handles, configurable model / reasoning effort / timeout / retries with
//! backoff on 5xx and transport errors, `degraded` when filters matched no citations) merged with
//! OpenClaw `extensions/xai/x-search*.ts` (handle limit, calendar-date checks, grok-4.7 default
//! with low tool reasoning, `max_turns`, `store: false`, bounded content, citation / inline
//! citation normalisation, per-credential answer cache, untrusted wrapping).
//! xAI OAuth is not ported: the key comes from XAI_API_KEY or `[web.providers.xai] api_key`.

use super::cache;
use super::content::wrap;
use super::http::{self, host_of, EnvFn, WebCtx};
use super::providers::{self, xai};
use super::WebConfig;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// OpenClaw `X_SEARCH_HANDLE_LIMIT` (the xAI API limit; Hermes uses 10).
pub const HANDLE_LIMIT: usize = 20;
const MAX_CONTENT: usize = 20_000;
const MAX_CITATIONS: usize = 20;
const EFFORTS: [&str; 4] = ["low", "medium", "high", "xhigh"];

pub struct XSearch {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

/// Registered when enabled and an xAI key resolves.
pub fn available(c: &WebCtx) -> bool {
    c.cfg.x_search.enabled && c.key("xai", xai::ENV).is_some()
}

/// Validated tool arguments.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct XArgs {
    pub query: String,
    pub allowed: Vec<String>,
    pub excluded: Vec<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub images: bool,
    pub videos: bool,
}

impl XArgs {
    fn active_filters(&self) -> Vec<&'static str> {
        [("allowed_x_handles", !self.allowed.is_empty()), ("excluded_x_handles", !self.excluded.is_empty()), ("from_date", self.from_date.is_some()), ("to_date", self.to_date.is_some())].into_iter().filter(|(_, on)| *on).map(|(k, _)| k).collect()
    }
}

fn handles(v: &Value, k: &str) -> Result<Vec<String>, String> {
    let out: Vec<String> = match v.get(k) {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().trim_start_matches('@').trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|s| s.trim().trim_start_matches('@').trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(_) => return Err(format!("{k} must be an array of X handles")),
    };
    if out.len() > HANDLE_LIMIT {
        return Err(format!("{k} cannot contain more than {HANDLE_LIMIT} handles"));
    }
    Ok(out)
}

fn date(v: &Value, k: &str) -> Result<Option<String>, String> {
    let Some(s) = v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    let shape = s.len() == 10 && s.char_indices().all(|(i, c)| if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() });
    if !shape {
        return Err(format!("{k} must use YYYY-MM-DD (got '{s}')"));
    }
    if !providers::valid_iso_date(s) {
        return Err(format!("{k} must be a valid calendar date (got '{s}')"));
    }
    Ok(Some(s.to_string()))
}

fn today_utc() -> String {
    let days = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) / 86_400) as i64;
    providers::brave::civil(days)
}

/// Client-side validation, so malformed filters fail before a billable call.
pub fn parse_args(input: &Value) -> Result<XArgs, String> {
    let query = input.get("query").and_then(|q| q.as_str()).map(str::trim).filter(|q| !q.is_empty()).ok_or("query is required for x_search")?.to_string();
    let allowed = handles(input, "allowed_x_handles")?;
    let excluded = handles(input, "excluded_x_handles")?;
    if !allowed.is_empty() && !excluded.is_empty() {
        return Err("allowed_x_handles and excluded_x_handles cannot be used together".into());
    }
    let (from_date, to_date) = (date(input, "from_date")?, date(input, "to_date")?);
    if let (Some(f), Some(t)) = (&from_date, &to_date) {
        if f > t {
            return Err(format!("from_date ({f}) must be on or before to_date ({t})"));
        }
    }
    if let Some(f) = &from_date {
        let today = today_utc();
        if *f > today {
            return Err(format!("from_date ({f}) is in the future; X Search only indexes past posts (today UTC is {today})"));
        }
    }
    let flag = |k: &str| input.get(k).and_then(|b| b.as_bool()) == Some(true);
    Ok(XArgs { query, allowed, excluded, from_date, to_date, images: flag("enable_image_understanding"), videos: flag("enable_video_understanding") })
}

/// The `{"type":"x_search", …}` tool definition (only set filters are sent).
pub fn tool_def(a: &XArgs) -> Value {
    let mut t = json!({"type": "x_search"});
    if !a.allowed.is_empty() {
        t["allowed_x_handles"] = json!(a.allowed);
    }
    if !a.excluded.is_empty() {
        t["excluded_x_handles"] = json!(a.excluded);
    }
    if let Some(f) = &a.from_date {
        t["from_date"] = json!(f);
    }
    if let Some(d) = &a.to_date {
        t["to_date"] = json!(d);
    }
    if a.images {
        t["enable_image_understanding"] = json!(true);
    }
    if a.videos {
        t["enable_video_understanding"] = json!(true);
    }
    t
}

/// Configured model (`xai/` prefix dropped), else OpenClaw's default.
pub fn model(cfg: &WebConfig) -> String {
    let m = cfg.x_search.model.trim();
    let m = m.strip_prefix("xai/").unwrap_or(m);
    if m.is_empty() { xai::ANSWER_MODEL } else { m }.to_string()
}

/// Configured effort (validated), else low on models that take tool reasoning.
pub fn reasoning(cfg: &WebConfig, model: &str) -> Result<Option<String>, String> {
    let raw = cfg.x_search.reasoning_effort.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Ok(xai::tool_reasoning(model).map(str::to_string));
    }
    if !EFFORTS.contains(&raw.as_str()) {
        return Err(format!("x_search.reasoning_effort must be one of: {} (got '{}')", EFFORTS.join(", "), cfg.x_search.reasoning_effort));
    }
    Ok(Some(raw))
}

pub fn request_body(cfg: &WebConfig, a: &XArgs) -> Result<Value, String> {
    let model = model(cfg);
    let mut body = json!({"model": model, "input": [{"role": "user", "content": a.query}], "tools": [tool_def(a)], "store": false});
    if let Some(e) = reasoning(cfg, &model)? {
        body["reasoning"] = json!({"effort": e});
    }
    if let Some(t) = cfg.x_search.max_turns.filter(|t| *t > 0) {
        body["max_turns"] = json!(t);
    }
    Ok(body)
}

/// Hermes `_http_error_message`: `code: error` from a JSON body, else the first 500 chars.
fn http_error_message(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(o)) => {
            let code = o.get("code").and_then(|c| c.as_str()).unwrap_or("").trim().to_string();
            let msg = match o.get("error") {
                Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
                Some(Value::Object(e)) => e.get("message").and_then(|m| m.as_str()).unwrap_or("").trim().to_string(),
                _ => String::new(),
            };
            let msg = if msg.is_empty() { Value::Object(o).to_string() } else { msg };
            if !code.is_empty() && !msg.contains(&code) {
                format!("{code}: {msg}")
            } else {
                msg
            }
        }
        _ => crate::util::truncate_str(body.trim(), 500).to_string(),
    }
}

#[cfg(not(test))]
const BACKOFF_UNIT_MS: u64 = 1000;
#[cfg(test)]
const BACKOFF_UNIT_MS: u64 = 10;

/// Hermes backoff: min(5 s, 1.5 s × attempt), interruptible.
fn backoff(c: &WebCtx, attempt: u32) -> Result<(), String> {
    let total = Duration::from_millis((BACKOFF_UNIT_MS * 3 * (attempt as u64 + 1) / 2).min(BACKOFF_UNIT_MS * 5));
    let start = Instant::now();
    while start.elapsed() < total {
        c.check_cancel()?;
        std::thread::sleep(Duration::from_millis(10).min(total));
    }
    Ok(())
}

/// `Err((code, message))`.
type CallErr = (String, String);

/// POST `/responses`, retrying 5xx / timeouts / connection failures `retries` times.
pub fn post_with_retries(c: &WebCtx, key: &str, body: &Value) -> Result<Value, (String, String)> {
    let timeout = c.cfg.x_search.timeout_seconds.max(30);
    let retries = c.cfg.x_search.retries;
    let url = format!("{}/responses", xai::base(c));
    let headers = [providers::bearer(key), ("User-Agent", format!("ark/{}", env!("CARGO_PKG_VERSION")))];
    let redact = |s: String| if key.len() >= 4 { s.replace(key, "***") } else { s };
    let mut attempt = 0;
    loop {
        c.check_cancel().map_err(|e| ("interrupted".to_string(), e))?;
        let err: CallErr = match http::post_json(&url, &headers, body, timeout) {
            Ok(r) if r.ok() => {
                let v = r.json().map_err(|_| ("provider_error".to_string(), "Could not parse xAI Responses API reply as JSON".to_string()))?;
                if let Some(e) = v.get("error").filter(|e| e.is_object()) {
                    let m = [http::s(e, "message"), http::s(e, "code")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "unknown error".into());
                    return Err(("provider_error".into(), redact(format!("xAI returned an error: {m}"))));
                }
                return Ok(v);
            }
            Ok(r) => {
                let e = ("provider_error".to_string(), redact(format!("xAI X search failed (HTTP {}): {}", r.status, http_error_message(&r.body))));
                if r.status < 500 {
                    return Err(e);
                }
                e
            }
            Err(e) => {
                let l = e.to_ascii_lowercase();
                if l.contains("timed out") || l.contains("timeout") {
                    ("timeout".to_string(), format!("xAI x_search timed out after {timeout} seconds"))
                } else {
                    ("network_error".to_string(), redact(format!("Could not reach xAI: {e}")))
                }
            }
        };
        if attempt >= retries {
            return Err(err);
        }
        backoff(c, attempt).map_err(|e| ("interrupted".to_string(), e))?;
        attempt += 1;
    }
}

/// Parsed answer: bounded text, citation URLs and (when enabled) validated inline citations.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub content: String,
    pub citations: Vec<String>,
    pub inline: Option<Vec<Value>>,
    pub truncated: bool,
}

/// OpenClaw `requireXaiResponseTextCitationsAndInline` + Hermes annotation offsets.
pub fn parse_answer(v: &Value, inline: bool) -> Result<Answer, String> {
    let (texts, anns) = xai::output_blocks(v);
    let raw = if texts.is_empty() { v.get("output_text").and_then(|t| t.as_str()).unwrap_or("").to_string() } else { texts.join("") };
    if raw.trim().is_empty() {
        return Err("xAI X search failed: no answer text returned; try a simpler request".into());
    }
    let raw_len = raw.chars().count();
    let truncated = raw_len > MAX_CONTENT;
    let content: String = if truncated { raw.chars().take(MAX_CONTENT).collect() } else { raw };
    let kept = content.chars().count() as u64;
    let mut citations: Vec<String> = Vec::new();
    let add = |u: &str, cs: &mut Vec<String>| {
        if cs.len() < MAX_CITATIONS {
            if let Some(u) = xai::citation_url(u).filter(|u| !cs.contains(u)) {
                cs.push(u);
            }
        }
    };
    for c in v.get("citations").and_then(|c| c.as_array()).into_iter().flatten().take(1000) {
        let u = c.as_str().map(str::to_string).unwrap_or_else(|| http::s(c, "url"));
        add(&u, &mut citations);
    }
    if citations.is_empty() {
        for a in anns.iter().take(1000).filter(|a| a.get("type").and_then(|t| t.as_str()) == Some("url_citation")) {
            add(&http::s(a, "url"), &mut citations);
        }
    }
    let inline = inline.then(|| {
        let explicit = v.get("inline_citations").and_then(|c| c.as_array());
        let src: Vec<&Value> = match explicit {
            Some(a) => a.iter().collect(),
            None => anns.iter().filter(|a| a.get("type").and_then(|t| t.as_str()) == Some("url_citation")).collect(),
        };
        src.into_iter()
            .take(MAX_CITATIONS)
            .filter_map(|c| {
                let url = xai::citation_url(&http::s(c, "url"))?;
                let (s, e) = (c.get("start_index")?.as_u64()?, c.get("end_index")?.as_u64()?);
                if s > e || e > kept {
                    return None;
                }
                let mut o = json!({"start_index": s, "end_index": e, "url": url});
                if let Some(t) = c.get("title").and_then(|t| t.as_str()).filter(|t| !t.is_empty()) {
                    o["title"] = json!(crate::util::truncate_str(t, 300));
                }
                Some(o)
            })
            .collect()
    });
    Ok(Answer { content, citations, inline, truncated })
}

/// OpenClaw `buildXaiXSearchPayload` (+ Hermes `degraded`).
pub fn payload(a: &XArgs, model: &str, took: Duration, ans: &Answer) -> Value {
    let mut v = json!({
        "query": a.query, "provider": "xai", "model": model, "tookMs": took.as_millis() as u64,
        "externalContent": {"untrusted": true, "source": "x_search", "provider": "xai", "wrapped": true},
        "content": ans.content, "citations": ans.citations,
    });
    if let Some(i) = &ans.inline {
        v["inlineCitations"] = json!(i);
    }
    if ans.truncated {
        v["truncated"] = json!(true);
    }
    for (k, on, val) in [("allowedXHandles", !a.allowed.is_empty(), json!(a.allowed)), ("excludedXHandles", !a.excluded.is_empty(), json!(a.excluded)), ("fromDate", a.from_date.is_some(), json!(a.from_date)), ("toDate", a.to_date.is_some(), json!(a.to_date)), ("enableImageUnderstanding", a.images, json!(true)), ("enableVideoUnderstanding", a.videos, json!(true))] {
        if on {
            v[k] = val;
        }
    }
    // xAI answers 200 from training data when filters match no posts: no citations anywhere.
    let filters = a.active_filters();
    if !filters.is_empty() && ans.citations.is_empty() && ans.inline.as_ref().is_none_or(|i| i.is_empty()) {
        v["degraded"] = json!(true);
        v["degradedReason"] = json!(format!("no citations returned despite filters: {}", filters.join(", ")));
    }
    v
}

/// Answer cache (OpenClaw keeps its own `X_SEARCH_CACHE`, separate from web_search).
fn memo() -> &'static cache::Memo {
    static M: std::sync::OnceLock<cache::Memo> = std::sync::OnceLock::new();
    M.get_or_init(cache::Memo::default)
}

fn cache_key(key: &str, url: &str, body: &Value, inline: bool) -> String {
    cache::digest(&json!(["x_search", cache::digest(key), url, body, inline]).to_string())
}

fn ttl(cfg: &WebConfig) -> Option<Duration> {
    if !cfg.cache_enabled {
        return None;
    }
    match cfg.x_search.cache_ttl_minutes {
        Some(m) if !m.is_finite() || m <= 0.0 => None,
        Some(m) => Some(Duration::from_secs((m.min(1440.0) * 60.0) as u64)),
        None => Some(Duration::from_secs(cfg.ttl_secs())),
    }
}

/// One x_search end to end: rendered JSON or `(code, message)`.
pub fn run(c: &WebCtx, a: &XArgs) -> Result<Value, CallErr> {
    let key = c.key("xai", xai::ENV).ok_or_else(|| ("missing_xai_api_key".to_string(), "x_search needs xAI credentials. Set XAI_API_KEY or [web.providers.xai] api_key (get one at https://console.x.ai).".to_string()))?;
    let body = request_body(&c.cfg, a).map_err(|e| ("invalid_config".to_string(), e))?;
    let model = body["model"].as_str().unwrap_or_default().to_string();
    let inline = c.cfg.x_search.inline_citations;
    let ttl = ttl(&c.cfg);
    let ck = cache_key(&key, &xai::base(c), &body, inline);
    let memo = memo();
    if ttl.is_some() {
        if let Some(mut v) = memo.get(&ck) {
            v["cached"] = json!(true);
            return Ok(v);
        }
    }
    let started = Instant::now();
    let v = post_with_retries(c, &key, &body)?;
    let ans = parse_answer(&v, inline).map_err(|e| ("provider_error".to_string(), e))?;
    let out = payload(a, &model, started.elapsed(), &ans);
    // A result that finished after the caller cancelled is not cached.
    if let Some(t) = ttl.filter(|_| !c.cancel.is_cancelled()) {
        memo.put(&ck, out.clone(), t, 1000);
    }
    Ok(out)
}

fn error(code: &str, message: &str) -> ToolOutput {
    let mut v = json!({"error": code, "message": message, "provider": "xai", "tool": "x_search"});
    if code == "missing_xai_api_key" {
        v["docs"] = json!(providers::DOCS);
    }
    ToolOutput::err(v.to_string())
}

impl Tool for XSearch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "x_search".into(),
            description: "Search X (formerly Twitter) posts, profiles and threads using xAI's built-in X Search, including targeted post or thread lookups. Read-only discovery: use it for current discussion, reactions or claims on public X rather than general web pages; it cannot post, reply, like, DM or read the user's own account. For per-post stats like reposts, replies, bookmarks or views, prefer the exact post URL or status ID.".into(),
            input_schema: json!({"type":"object","required":["query"],"additionalProperties":false,"properties":{
                "query":{"type":"string","description":"Natural-language instruction sent to the Grok X-search agent. Must be meaningful and non-empty."},
                "allowed_x_handles":{"type":"array","items":{"type":"string","minLength":1},"maxItems":HANDLE_LIMIT,"description":format!("Only include posts from these X handles (max {HANDLE_LIMIT}). Cannot be combined with excluded_x_handles.")},
                "excluded_x_handles":{"type":"array","items":{"type":"string","minLength":1},"maxItems":HANDLE_LIMIT,"description":format!("Exclude posts from these X handles (max {HANDLE_LIMIT}). Cannot be combined with allowed_x_handles.")},
                "from_date":{"type":"string","description":"Only include posts on or after this date (YYYY-MM-DD)."},
                "to_date":{"type":"string","description":"Only include posts on or before this date (YYYY-MM-DD)."},
                "enable_image_understanding":{"type":"boolean","description":"Allow xAI to inspect images attached to matching posts (default false)."},
                "enable_video_understanding":{"type":"boolean","description":"Allow xAI to inspect videos attached to matching posts (default false)."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        vec![Effect::Net { dest: host_of(&xai::base(&c)), payload: input.get("query").and_then(|q| q.as_str()).unwrap_or("").to_string() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if !self.cfg.x_search.enabled {
            return ToolOutput::err("x_search is disabled ([web.x_search] enabled = false).");
        }
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        let a = match parse_args(&input) {
            Ok(a) => a,
            Err(e) => return error("invalid_arguments", &e),
        };
        match run(&c, &a) {
            Ok(v) => ToolOutput::ok(wrap(&serde_json::to_string_pretty(&v).unwrap_or_default(), "x_search", false)),
            Err((code, msg)) => error(&code, &msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, wctx, FakeServer};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tool(cfg: Value, env: &[(&str, &str)]) -> XSearch {
        XSearch { cfg: Arc::new(WebConfig::from_value(cfg).unwrap()), env: env_of(env) }
    }

    fn answer(text: &str) -> String {
        json!({"output":[{"type":"x_search_call"},{"type":"message","content":[{"type":"output_text","text":text,"annotations":[{"type":"url_citation","url":"https://x.com/a/status/1","title":"post","start_index":0,"end_index":4},{"type":"url_citation","url":"javascript:alert(1)","start_index":0,"end_index":1}]}]}],"citations":["https://x.com/a/status/1","ftp://nope"]}).to_string()
    }

    #[test]
    fn validation() {
        let a = parse_args(&json!({"query":" q ","allowed_x_handles":["@openclaw"," ",""],"from_date":"2025-03-01","to_date":"2025-03-20","enable_image_understanding":true})).unwrap();
        assert_eq!((a.query.as_str(), a.allowed.clone(), a.images, a.videos), ("q", vec!["openclaw".to_string()], true, false));
        assert_eq!(tool_def(&a), json!({"type":"x_search","allowed_x_handles":["openclaw"],"from_date":"2025-03-01","to_date":"2025-03-20","enable_image_understanding":true}));
        let err = |v: Value| parse_args(&v).unwrap_err();
        assert_eq!(err(json!({"query":"  "})), "query is required for x_search");
        assert_eq!(err(json!({"query":"q","allowed_x_handles":["a"],"excluded_x_handles":["b"]})), "allowed_x_handles and excluded_x_handles cannot be used together");
        let many: Vec<String> = (0..21).map(|i| format!("h{i}")).collect();
        assert_eq!(err(json!({"query":"q","allowed_x_handles":many})), "allowed_x_handles cannot contain more than 20 handles");
        assert!(parse_args(&json!({"query":"q","excluded_x_handles":many[..20]})).is_ok());
        assert!(err(json!({"query":"q","from_date":"2025/03/01"})).contains("from_date must use YYYY-MM-DD"));
        assert!(err(json!({"query":"q","to_date":"2025-02-30"})).contains("to_date must be a valid calendar date"));
        assert!(err(json!({"query":"q","from_date":"2025-03-20","to_date":"2025-03-01"})).contains("must be on or before to_date"));
        assert!(err(json!({"query":"q","from_date":"2999-01-01"})).contains("is in the future"));
        assert!(parse_args(&json!({"query":"q","to_date":"2999-01-01"})).is_ok(), "to_date may be in the future");
    }

    #[test]
    fn request_shape_citations_and_cache() {
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", answer("Posts say hi"))]);
        let cfg = json!({"x_search":{"max_turns":2},"providers":{"xai":{"base_url":s.url.clone()}}});
        let t = tool(cfg, &[("XAI_API_KEY", "xai-test")]);
        let tc = ctx("xsearch");
        let o = t.call(&tc, json!({"query":"dinner recipes","allowed_x_handles":["openclaw"],"from_date":"2025-03-01","enable_video_understanding":true}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("Source: X Search") && o.content.contains("Posts say hi") && o.content.contains("\"allowedXHandles\"") && !o.content.contains("degraded"), "{}", o.content);
        assert!(!o.content.contains("inlineCitations") && !o.content.contains("ftp://"));
        let q = s.last();
        assert_eq!(q.path, "/responses");
        assert_eq!(q.header("authorization").as_deref(), Some("Bearer xai-test"));
        assert_eq!(q.json(), json!({"model":"grok-4.7","input":[{"role":"user","content":"dinner recipes"}],"tools":[{"type":"x_search","allowed_x_handles":["openclaw"],"from_date":"2025-03-01","enable_video_understanding":true}],"store":false,"reasoning":{"effort":"low"},"max_turns":2}));
        // Same call again: served from the memo, no second request.
        let o2 = t.call(&tc, json!({"query":"dinner recipes","allowed_x_handles":["openclaw"],"from_date":"2025-03-01","enable_video_understanding":true}));
        assert!(o2.content.contains("\"cached\": true"), "{}", o2.content);
        assert_eq!(s.requests().len(), 1);
        // A different key does not share the cached answer.
        tool(json!({"x_search":{"max_turns":2},"providers":{"xai":{"base_url":s.url.clone()}}}), &[("XAI_API_KEY", "xai-other")]).call(&tc, json!({"query":"dinner recipes","allowed_x_handles":["openclaw"],"from_date":"2025-03-01","enable_video_understanding":true}));
        assert_eq!(s.requests().len(), 2);
        assert!(matches!(&t.effects(&tc, &json!({"query":"q"}))[..], [Effect::Net { dest, payload }] if dest == "127.0.0.1" && payload == "q"));
    }

    #[test]
    fn config_model_reasoning_inline_and_ttl() {
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", answer("Text body"))]);
        let cfg = json!({"x_search":{"model":"xai/grok-4.5","reasoning_effort":"HIGH","inline_citations":true,"cache_ttl_minutes":0},"providers":{"xai":{"base_url":s.url.clone()}}});
        let t = tool(cfg, &[("XAI_API_KEY", "k-123")]);
        let tc = ctx("xsearch2");
        let o = t.call(&tc, json!({"query":"q"}));
        assert!(o.content.contains("\"inlineCitations\"") && o.content.contains("\"start_index\": 0") && !o.content.contains("javascript:"), "{}", o.content);
        let b = s.last().json();
        assert_eq!((b["model"].as_str(), b["reasoning"]["effort"].as_str(), b.get("max_turns")), (Some("grok-4.5"), Some("high"), None));
        t.call(&tc, json!({"query":"q"}));
        assert_eq!(s.requests().len(), 2, "ttl 0 disables caching");
        let bad = tool(json!({"x_search":{"reasoning_effort":"max"},"providers":{"xai":{"base_url":s.url.clone()}}}), &[("XAI_API_KEY", "k")]);
        assert!(bad.call(&tc, json!({"query":"q"})).content.contains("x_search.reasoning_effort must be one of: low, medium, high, xhigh"));
        let mut c = WebConfig::default();
        c.x_search.model = "grok-4.5".into();
        assert_eq!(reasoning(&c, &model(&c)).unwrap(), None, "grok-4.5 takes no tool reasoning by default");
    }

    #[test]
    fn answer_parsing() {
        let long = "x".repeat(MAX_CONTENT + 10);
        let a = parse_answer(&json!({"output_text": long, "inline_citations":[{"url":"https://x.com/1","start_index":5,"end_index":MAX_CONTENT + 5},{"url":"https://x.com/2","start_index":1,"end_index":2}]}), true).unwrap();
        assert!(a.truncated && a.content.chars().count() == MAX_CONTENT && a.citations.is_empty());
        assert_eq!(a.inline.unwrap(), vec![json!({"start_index":1,"end_index":2,"url":"https://x.com/2"})], "offsets past the kept text dropped");
        let a = parse_answer(&json!({"output":[{"type":"message","content":[{"type":"output_text","text":"a","annotations":[{"type":"url_citation","url":"https://x.com/9"}]}]}]}), false).unwrap();
        assert_eq!((a.citations, a.inline), (vec!["https://x.com/9".to_string()], None), "annotations used when `citations` is absent");
        assert_eq!(parse_answer(&json!({"output":[]}), false).unwrap_err(), "xAI X search failed: no answer text returned; try a simpler request");
    }

    #[test]
    fn degraded_when_filters_match_nothing() {
        let a = parse_args(&json!({"query":"q","excluded_x_handles":["spam"],"to_date":"2025-01-01"})).unwrap();
        let ans = Answer { content: "From memory".into(), citations: vec![], inline: None, truncated: false };
        let v = payload(&a, "grok-4.7", Duration::from_millis(3), &ans);
        assert_eq!((v["degraded"].as_bool(), v["degradedReason"].as_str()), (Some(true), Some("no citations returned despite filters: excluded_x_handles, to_date")));
        let plain = payload(&parse_args(&json!({"query":"q"})).unwrap(), "m", Duration::ZERO, &ans);
        assert!(plain.get("degraded").is_none());
    }

    #[test]
    fn retries_5xx_then_succeeds_and_fails_fast_on_4xx() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let s = FakeServer::with(move |_| {
            if n2.fetch_add(1, Ordering::SeqCst) < 2 {
                (503, "application/json".into(), br#"{"code":"overloaded","error":"try later"}"#.to_vec(), vec![])
            } else {
                (200, "application/json".into(), answer("ok now").into_bytes(), vec![])
            }
        });
        let tc = ctx("xsearch3");
        let cfg = |r: u32| json!({"x_search":{"retries":r,"cache_ttl_minutes":0},"providers":{"xai":{"base_url":s.url.clone()}}});
        let o = tool(cfg(2), &[("XAI_API_KEY", "xai-test")]).call(&tc, json!({"query":"q"}));
        assert!(!o.is_error && o.content.contains("ok now"), "{}", o.content);
        assert_eq!(n.load(Ordering::SeqCst), 3);
        n.store(0, Ordering::SeqCst);
        let o = tool(cfg(1), &[("XAI_API_KEY", "xai-test")]).call(&tc, json!({"query":"q"}));
        assert!(o.is_error && o.content.contains("xAI X search failed (HTTP 503): overloaded: try later"), "{}", o.content);
        assert_eq!(n.load(Ordering::SeqCst), 2);
        let bad = FakeServer::start(vec![("POST /responses", 401, "application/json", r#"{"error":"bad key xai-test"}"#.into())]);
        let o = tool(json!({"providers":{"xai":{"base_url":bad.url.clone()}}}), &[("XAI_API_KEY", "xai-test")]).call(&tc, json!({"query":"q"}));
        assert!(o.content.contains("(HTTP 401): bad key ***") && o.content.contains("\"provider_error\""), "{}", o.content);
        assert_eq!(bad.requests().len(), 1, "4xx is not retried");
        let env = FakeServer::start(vec![("POST /responses", 200, "application/json", json!({"error":{"message":"quota"}}).to_string())]);
        let o = tool(json!({"providers":{"xai":{"base_url":env.url.clone()}}}), &[("XAI_API_KEY", "k")]).call(&tc, json!({"query":"q"}));
        assert!(o.content.contains("xAI returned an error: quota"));
    }

    #[test]
    fn availability_and_missing_key() {
        assert!(!available(&wctx(json!({}), &[])));
        assert!(available(&wctx(json!({}), &[("XAI_API_KEY", "k")])));
        assert!(available(&wctx(json!({"providers":{"xai":{"api_key":"k"}}}), &[])));
        assert!(!available(&wctx(json!({"x_search":{"enabled":false}}), &[("XAI_API_KEY", "k")])));
        let tc = ctx("xsearch4");
        let o = tool(json!({}), &[]).call(&tc, json!({"query":"q"}));
        assert!(o.is_error && o.content.contains("missing_xai_api_key") && o.content.contains("XAI_API_KEY"), "{}", o.content);
        let o = tool(json!({}), &[("XAI_API_KEY", "k")]).call(&tc, json!({"query":"q","from_date":"bad"}));
        assert!(o.is_error && o.content.contains("invalid_arguments"));
        assert!(tool(json!({"x_search":{"enabled":false}}), &[]).call(&tc, json!({"query":"q"})).content.contains("disabled"));
    }
}
