//! `web_fetch` (OpenClaw `src/agents/tools/web-fetch.ts`): one URL under the SSRF guard
//! (every redirect hop and every connect re-checked), website blocklist, Readability →
//! Markdown / text, PDF text, Markdown / JSON passthrough, an in-memory payload cache plus the
//! on-disk page cache, head+tail truncation with the full text spilled to a file, and the
//! Firecrawl fallback when the direct fetch or extraction fails. seagent keeps its earlier
//! `method` / `body` / `headers` arguments (POST and custom headers skip cache and fallback).

use super::cache::{self, DiskCache};
use super::content::{self, wrap_web};
use super::http::{host_of, process_env, EnvFn, WebCtx};
use super::providers::firecrawl;
use super::ssrf::{self, SsrfPolicy};
use super::truncate;
use super::{markdown, pdf, policy, readability, WebConfig};
use crate::util::truncate_str;
use seagent_core::tool::{arg_opt_str, arg_str};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use regex::Regex;
use serde_json::{json, Value};
use std::io::Read as _;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MIN_MAX_CHARS: usize = 100;
const DEFAULT_ERROR_MAX_CHARS: usize = 4_000;
const DEFAULT_ERROR_MAX_BYTES: u64 = 64_000;
const MEMO_MAX_ENTRIES: usize = 100;
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36";
const ACCEPT: &str = "text/markdown, text/html;q=0.9, */*;q=0.1";
/// Framing / routing headers an operator or the model may not override.
const RESERVED_HEADERS: &[&str] = &["host", "content-length", "connection", "transfer-encoding", "upgrade", "te", "trailer", "keep-alive", "proxy-authorization", "proxy-connection"];

/// Basic HTML → text cleanup (no main-content detection).
pub fn html_to_text(html: &str) -> String {
    static RES: OnceLock<[Regex; 4]> = OnceLock::new();
    let [blocks, breaks, tags, spaces] = RES.get_or_init(|| {
        [
            Regex::new(r"(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>|<!--.*?-->").unwrap(),
            Regex::new(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr|/section|/article)\b[^>]*>").unwrap(),
            Regex::new(r"(?s)<[^>]*>").unwrap(),
            Regex::new(r"[ \t\r\f]+").unwrap(),
        ]
    });
    let s = blocks.replace_all(html, " ");
    let s = breaks.replace_all(&s, "\n");
    let s = tags.replace_all(&s, " ");
    let s = super::html::decode_entities(&s);
    let s = spaces.replace_all(&s, " ");
    let mut out = String::new();
    let mut blank = 0;
    for line in s.lines().map(str::trim) {
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_string()
}

/// What to fetch.
#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    pub method: String,
    pub body: Option<String>,
    pub headers: Vec<(String, String)>,
    pub text_mode: bool,
    /// Readability for HTML (off: only the fallback provider / basic cleanup).
    pub readability: bool,
}

impl Request {
    pub fn get(url: &str, text_mode: bool) -> Request {
        Request { url: url.into(), method: "GET".into(), body: None, headers: vec![], text_mode, readability: true }
    }
}

/// An extracted document.
#[derive(Debug, Clone, Default)]
pub struct Doc {
    pub final_url: String,
    pub status: u16,
    pub content_type: String,
    pub title: Option<String>,
    pub extractor: String,
    pub text: String,
    pub warning: Option<String>,
    /// Readability found nothing and the text is the basic cleanup (a fallback provider may do better).
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchErr {
    /// SSRF / blocklist / policy refusal: never retried through a provider.
    Blocked(String),
    Transport(String),
    Status { status: u16, detail: String },
    /// Readability disabled, or nothing extractable.
    Extract(String),
    /// A binary file (not a page): not retried.
    Binary(String),
    Cancelled,
}

impl FetchErr {
    pub fn message(&self) -> String {
        match self {
            FetchErr::Blocked(m) | FetchErr::Transport(m) | FetchErr::Extract(m) | FetchErr::Binary(m) => m.clone(),
            FetchErr::Status { status, detail } => format!("Web fetch failed ({status}): {detail}"),
            FetchErr::Cancelled => "cancelled".into(),
        }
    }
    fn fallback_worthy(&self) -> bool {
        matches!(self, FetchErr::Transport(_) | FetchErr::Status { .. } | FetchErr::Extract(_))
    }
}

fn normalize_content_type(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Operator `[web.fetch] headers` then call headers, reserved names dropped, later wins.
fn merged_headers(cfg: &WebConfig, extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    for (k, v) in cfg.fetch.headers.iter().map(|(k, v)| (k.clone(), v.clone())).chain(extra.iter().cloned()) {
        let lk = k.trim().to_ascii_lowercase();
        if lk.is_empty() || RESERVED_HEADERS.contains(&lk.as_str()) || lk.starts_with("proxy-") {
            continue;
        }
        out.retain(|(o, _)| !o.eq_ignore_ascii_case(&lk));
        out.push((k.trim().to_string(), v));
    }
    out
}

/// Direct fetch + extraction under the SSRF guard (no provider fallback).
pub fn fetch_document(c: &WebCtx, req: &Request) -> Result<Doc, FetchErr> {
    let cfg = &c.cfg;
    let policy = Arc::new(SsrfPolicy::from_config(cfg));
    let timeout = cfg.fetch.timeout_seconds.clamp(1, 600);
    let agent = ssrf::guarded_agent(policy.clone(), timeout);
    let ua = if cfg.fetch.user_agent.trim().is_empty() { USER_AGENT.to_string() } else { cfg.fetch.user_agent.trim().to_string() };
    let headers = merged_headers(cfg, &req.headers);
    let mut cur = ssrf::normalize_url_for_request(&req.url);
    let mut method = req.method.clone();
    let mut body = req.body.clone();
    let max_redirects = cfg.fetch.max_redirects.min(10);
    let mut hops = 0u32;
    let mut resp = loop {
        c.check_cancel().map_err(|_| FetchErr::Cancelled)?;
        ssrf::check_url(&cur, &policy).map_err(FetchErr::Blocked)?;
        policy::enforce(cfg, &c.home, &cur).map_err(FetchErr::Blocked)?;
        let call = if method == "POST" {
            let mut r = agent.post(&cur).header("Accept", ACCEPT).header("User-Agent", &ua).header("Accept-Language", "en-US,en;q=0.9");
            for (k, v) in &headers {
                r = r.header(k, v);
            }
            r.send(body.clone().unwrap_or_default().as_bytes())
        } else {
            let mut r = agent.get(&cur).header("Accept", ACCEPT).header("User-Agent", &ua).header("Accept-Language", "en-US,en;q=0.9");
            for (k, v) in &headers {
                r = r.header(k, v);
            }
            r.call()
        };
        let resp = call.map_err(|e| if ssrf::is_block_error(&e) { FetchErr::Blocked(ssrf::error_text(&e)) } else { FetchErr::Transport(format!("request to {} failed: {}", truncate_str(&cur, 200), ssrf::error_text(&e))) })?;
        let status = resp.status();
        if status.is_redirection() {
            if let Some(loc) = resp.headers().get("location").and_then(|l| l.to_str().ok()) {
                hops += 1;
                if hops > max_redirects {
                    return Err(FetchErr::Transport(format!("Too many redirects (limit: {max_redirects})")));
                }
                cur = ssrf::normalize_url_for_request(&ssrf::join_url(&cur, loc));
                if !matches!(status.as_u16(), 307 | 308) {
                    method = "GET".into();
                    body = None;
                }
                continue;
            }
        }
        break resp;
    };
    let status = resp.status().as_u16();
    let ctype_raw = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let ctype = normalize_content_type(&ctype_raw);
    if !(200..300).contains(&status) {
        let mut raw = Vec::new();
        let _ = resp.body_mut().with_config().limit(u64::MAX).reader().take(DEFAULT_ERROR_MAX_BYTES).read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let detail = if ctype.contains("html") || text.trim_start().starts_with('<') { html_to_text(&text) } else { text.trim().to_string() };
        let detail = if detail.is_empty() { resp.status().canonical_reason().unwrap_or("").to_string() } else { detail };
        return Err(FetchErr::Status { status, detail: content::wrap(truncate_str(&detail, DEFAULT_ERROR_MAX_CHARS), "web_fetch", false) });
    }
    let max = cfg.fetch.max_response_bytes.max(1024);
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(max + 1).read_to_end(&mut raw).map_err(|e| FetchErr::Transport(format!("reading response body failed: {e}")))?;
    let cut = raw.len() as u64 > max;
    raw.truncate(max as usize);
    c.check_cancel().map_err(|_| FetchErr::Cancelled)?;
    let warning = cut.then(|| format!("Response body incomplete after {max} bytes."));
    let mut doc = Doc { final_url: cur.clone(), status, content_type: if ctype.is_empty() { "application/octet-stream".into() } else { ctype.clone() }, warning, ..Default::default() };
    if ctype == "application/pdf" || pdf::is_pdf(&raw) {
        doc.text = pdf::extract_text(&raw).map_err(|e| FetchErr::Extract(format!("PDF extraction failed: {e}")))?;
        doc.title = pdf::title(&raw);
        doc.extractor = "pdf".into();
        doc.content_type = "application/pdf".into();
        return Ok(doc);
    }
    if let Some(kind) = truncate::binary_kind_bytes(&raw) {
        return Err(FetchErr::Binary(format!("URL returned binary content ({kind}), not a page. Download it with the shell (curl -L -o) and read the file instead.")));
    }
    let textual = ctype.is_empty() || ctype.starts_with("text/") || ctype.contains("json") || ctype.contains("xml") || ctype.contains("javascript");
    if !textual {
        return Err(FetchErr::Binary(format!("URL returned binary content ({ctype}, {} bytes), not a page. Download it with the shell (curl -L -o) and read the file instead.", raw.len())));
    }
    let body = String::from_utf8_lossy(&raw).into_owned();
    let html = ctype == "text/html" || ctype == "application/xhtml+xml" || (ctype.is_empty() && body.trim_start().starts_with('<'));
    if ctype == "text/markdown" {
        doc.extractor = "cf-markdown".into();
        doc.text = if req.text_mode { markdown::markdown_to_text(&body) } else { body };
    } else if html {
        if !req.readability {
            return Err(FetchErr::Extract("Web fetch extraction failed: Readability disabled and no fetch provider is available.".into()));
        }
        match readability::extract(&body, &cur, req.text_mode) {
            Some(a) => {
                doc.title = a.title;
                doc.text = a.text;
                doc.extractor = "readability".into();
            }
            None => {
                let (md, title) = markdown::html_to_markdown(&body, &cur);
                let text = if req.text_mode { markdown::markdown_to_text(&md) } else { md };
                if text.trim().is_empty() {
                    return Err(FetchErr::Extract("Web fetch extraction failed: Readability and basic HTML cleanup returned no content.".into()));
                }
                doc.title = title;
                doc.text = text;
                doc.extractor = "raw-html".into();
                doc.degraded = true;
            }
        }
    } else if ctype == "application/json" || ctype.ends_with("+json") {
        match serde_json::from_str::<Value>(&body) {
            Ok(v) => {
                doc.text = serde_json::to_string_pretty(&v).unwrap_or(body);
                doc.extractor = "json".into();
            }
            Err(_) => {
                doc.text = body;
                doc.extractor = "raw".into();
            }
        }
    } else {
        doc.text = body;
        doc.extractor = "raw".into();
    }
    doc.text = content::strip_invisible(&doc.text);
    Ok(doc)
}

/// Firecrawl scrape as a [`Doc`] (OpenClaw `resolveProviderFallback`).
fn fallback_doc(c: &WebCtx, url: &str, text_mode: bool) -> Result<Doc, String> {
    let v = firecrawl::fetch_fallback(c, url, text_mode)?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    Ok(Doc {
        final_url: s("finalUrl").unwrap_or_else(|| url.to_string()),
        status: v.get("status").and_then(|x| x.as_u64()).unwrap_or(200) as u16,
        content_type: "text/markdown".into(),
        title: s("title"),
        extractor: "firecrawl".into(),
        text: s("text").unwrap_or_default(),
        warning: s("warning"),
        degraded: false,
    })
}

#[cfg(test)]
thread_local! {
    /// Tests fetch from 127.0.0.1, which the cache gate skips as a local-dev host.
    pub static CACHE_LOCAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn cacheable(cfg: &WebConfig, url: &str) -> bool {
    #[cfg(test)]
    if CACHE_LOCAL.with(|c| c.get()) {
        return cfg.cache_enabled;
    }
    cache::cacheable(cfg, url)
}

pub struct WebFetch {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Default for WebFetch {
    fn default() -> Self {
        WebFetch { cfg: Arc::new(WebConfig::default()), env: process_env() }
    }
}

fn headers_of(input: &Value) -> Result<Vec<(String, String)>, String> {
    match input.get("headers") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Object(m)) => m.iter().map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())).ok_or_else(|| format!("header `{k}` must be a string"))).collect(),
        Some(_) => Err("`headers` must be an object of string values".into()),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl WebFetch {
    fn ctx(&self, t: &ToolCtx) -> WebCtx {
        WebCtx::from_tool(self.cfg.clone(), self.env.clone(), t)
    }

    fn max_chars(&self, input: &Value) -> usize {
        let cap = self.cfg.fetch.max_chars_cap.max(MIN_MAX_CHARS);
        let n = input.get("maxChars").or_else(|| input.get("max_chars")).and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))).filter(|f| f.is_finite() && *f >= 0.0);
        n.map(|f| f as usize).unwrap_or(self.cfg.fetch.max_chars).clamp(MIN_MAX_CHARS, cap)
    }

    /// Model payload for an extracted document (OpenClaw `buildWebFetchPayload` + `spillWebFetchContent`).
    fn payload(&self, c: &WebCtx, url: &str, doc: &Doc, mode: &str, max_chars: usize, took: Duration) -> Value {
        let raw_len = truncate::char_len(&doc.text);
        let (text, truncated) = truncate::truncate_with_footer_for("web_fetch", &doc.text, &doc.final_url, max_chars, &c.spill_dir);
        let mut v = json!({
            "url": url, "finalUrl": doc.final_url, "status": doc.status, "contentType": doc.content_type,
            "extractMode": mode, "extractor": doc.extractor,
            "externalContent": {"untrusted": true, "source": "web_fetch", "wrapped": true},
            "truncated": truncated || doc.warning.is_some(), "length": truncate::char_len(&text), "rawLength": raw_len,
            "fetchedAt": now_ms(), "tookMs": took.as_millis() as u64, "text": text,
        });
        if let Some(t) = doc.title.as_deref().filter(|t| !t.trim().is_empty()) {
            v["title"] = json!(truncate_str(t.trim(), 256));
        }
        if let Some(w) = &doc.warning {
            v["warning"] = json!(truncate_str(w, 256));
        }
        if truncated {
            if let Some(p) = text.lines().find_map(|l| l.strip_prefix("Full text saved to: ")) {
                v["spill"] = json!({"path": p, "chars": raw_len.min(truncate::MAX_STORED_TEXT_CHARS)});
            }
        }
        v
    }

    fn render(v: &Value) -> ToolOutput {
        ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(v).unwrap_or_default(), "web_fetch"))
    }
}

impl Tool for WebFetch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "web_fetch".into(),
            description: "Fetch a URL over HTTP(S) and extract readable content (HTML → markdown/text via Readability, PDF text, JSON, Markdown). Private/internal addresses are blocked. Long pages are cut to maxChars with the full text saved to a file named in the footer (page through it with read). Use for lightweight page access without browser automation.".into(),
            input_schema: json!({"type":"object","properties":{
                "url":{"type":"string","description":"HTTP(S) URL."},
                "extractMode":{"type":"string","enum":["markdown","text"],"default":"markdown","description":"Extract as markdown/text."},
                "maxChars":{"type":"integer","minimum":MIN_MAX_CHARS,"description":"Max chars returned; truncates."},
                "method":{"type":"string","enum":["GET","POST"],"default":"GET"},
                "body":{"type":"string","description":"POST body."},
                "headers":{"type":"object","additionalProperties":{"type":"string"}}},
                "required":["url"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Ok(url) = arg_str(input, "url") else { return vec![] };
        let Ok(u) = ssrf::parse_url(url) else { return vec![] };
        let mut payload = String::new();
        if let Some(Value::Object(h)) = input.get("headers") {
            for (k, v) in h {
                payload.push_str(&format!("{k}: {}\n", v.as_str().unwrap_or("")));
            }
        }
        if let Some(b) = arg_opt_str(input, "body") {
            payload.push_str(b);
        }
        // The full URL can carry data too (query strings).
        let mut out = vec![Effect::Net { dest: u.host, payload: format!("{url}\n{payload}") }];
        let c = self.ctx(ctx);
        if firecrawl::fetch_fallback_enabled(&c) && !arg_opt_str(input, "method").is_some_and(|m| m.eq_ignore_ascii_case("POST")) {
            out.push(Effect::Net { dest: host_of(&firecrawl::fetch_fallback_endpoint(&c)), payload: url.to_string() });
        }
        out
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if !self.cfg.fetch.enabled {
            return ToolOutput::err("web_fetch is disabled ([web.fetch] enabled = false).");
        }
        let raw_url = match arg_str(&input, "url") {
            Ok(u) => u.trim().to_string(),
            Err(e) => return ToolOutput::err(e),
        };
        // Model-written secrets in a URL are exfiltration; vault placeholders are substituted after.
        if let Some(e) = ssrf::url_secret_refusal(&raw_url) {
            return ToolOutput::err(e);
        }
        let url = ssrf::normalize_url_for_request(&(ctx.secrets)(&raw_url));
        if let Err(e) = ssrf::parse_url(&url) {
            return ToolOutput::err(e);
        }
        let mode = match arg_opt_str(&input, "extractMode").or(arg_opt_str(&input, "extract_mode")).unwrap_or("markdown") {
            m if m.eq_ignore_ascii_case("text") => "text",
            m if m.eq_ignore_ascii_case("markdown") => "markdown",
            m => return ToolOutput::err(format!("extractMode must be \"markdown\" or \"text\", got `{}`", truncate_str(m, 40))),
        };
        let max_chars = self.max_chars(&input);
        let method = arg_opt_str(&input, "method").unwrap_or("GET").to_ascii_uppercase();
        if method != "GET" && method != "POST" {
            return ToolOutput::err(format!("unsupported method `{method}`; use GET or POST"));
        }
        let headers = match headers_of(&input) {
            Ok(h) => h.into_iter().map(|(k, v)| (k, (ctx.secrets)(&v))).collect::<Vec<_>>(),
            Err(e) => return ToolOutput::err(e),
        };
        let body = arg_opt_str(&input, "body").map(|b| (ctx.secrets)(b));
        if method == "GET" && body.is_some() {
            return ToolOutput::err("GET requests cannot carry a body; use method POST");
        }
        if ctx.cancel.is_cancelled() {
            return ToolOutput::err("cancelled");
        }
        let c = self.ctx(ctx);
        let plain = method == "GET" && headers.is_empty();
        let use_cache = plain && cacheable(&self.cfg, &url) && self.cfg.fetch.cache_ttl_minutes > 0.0;
        let ttl = (self.cfg.fetch.cache_ttl_minutes.clamp(0.0, 1440.0) * 60.0) as u64;
        let key = cache::digest(&format!("fetch:{url}:{mode}:{max_chars}:readability={}", self.cfg.fetch.readability));
        let memo = cache::fetch_memo();
        if use_cache {
            if let Some(mut v) = memo.get(&key) {
                let spill_ok = v.get("spill").and_then(|s| s["path"].as_str()).is_none_or(|p| std::path::Path::new(p).is_file());
                if spill_ok {
                    v["cached"] = json!(true);
                    return Self::render(&v);
                }
            }
        }
        let started = Instant::now();
        let disk = DiskCache::new(&c.home);
        if use_cache {
            if let Some((title, text)) = disk.get(&url, mode, "web_fetch", ttl) {
                let doc = Doc { final_url: url.clone(), status: 200, content_type: "text/markdown".into(), title: Some(title), extractor: "disk-cache".into(), text, ..Default::default() };
                let mut v = self.payload(&c, &url, &doc, mode, max_chars, started.elapsed());
                v["cached"] = json!(true);
                return Self::render(&v);
            }
        }
        let req = Request { url: url.clone(), method: method.clone(), body, headers, text_mode: mode == "text", readability: self.cfg.fetch.readability };
        let fallback_ok = plain && firecrawl::fetch_fallback_enabled(&c);
        let doc = match fetch_document(&c, &req) {
            Ok(d) if d.degraded && fallback_ok => fallback_doc(&c, &d.final_url, req.text_mode).ok().filter(|f| !f.text.trim().is_empty()).unwrap_or(d),
            Ok(d) => d,
            Err(FetchErr::Cancelled) => return ToolOutput::err("cancelled"),
            Err(e) if fallback_ok && e.fallback_worthy() => match fallback_doc(&c, &url, req.text_mode) {
                Ok(d) if !d.text.trim().is_empty() => d,
                Ok(_) => return ToolOutput::err(format!("{} (Firecrawl fallback returned no content)", e.message())),
                Err(f) => return ToolOutput::err(format!("{} (Firecrawl fallback failed: {f})", e.message())),
            },
            Err(e) => return ToolOutput::err(e.message()),
        };
        let v = self.payload(&c, &url, &doc, mode, max_chars, started.elapsed());
        if use_cache {
            memo.put(&key, v.clone(), Duration::from_secs(ttl.max(1)), MEMO_MAX_ENTRIES);
            if doc.warning.is_none() {
                disk.put(&url, mode, "web_fetch", doc.title.as_deref().unwrap_or(""), &doc.text);
            }
        }
        Self::render(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, FakeServer};

    fn tool(cfg: Value) -> WebFetch {
        WebFetch { cfg: Arc::new(WebConfig::from_value(cfg).unwrap()), env: env_of(&[]) }
    }
    /// Loopback fake servers need `allow_private_urls` (the guard is on by default).
    fn open() -> WebFetch {
        tool(json!({"allow_private_urls": true}))
    }
    fn json_of(o: &ToolOutput) -> Value {
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("<<<EXTERNAL_UNTRUSTED_CONTENT") && o.content.contains("Source: Web Fetch"), "{}", o.content);
        serde_json::from_str(&o.content[o.content.find("---\n").unwrap() + 4..o.content.rfind("\n<<<END").unwrap()]).unwrap()
    }
    const ARTICLE: &str = "<html><head><title>Rust Ownership Explained In Depth | Blog</title><script>evil()</script></head><body><nav><a href='/'>Home</a> <a href='/x'>About</a></nav><article><h1>Ownership</h1><p>Rust's ownership model guarantees memory safety without a garbage collector. Each value has a single owner, and the value is dropped when the owner goes out of scope. Borrowing lets code use a value without taking ownership, &amp; the borrow checker enforces the rules at compile time.</p><p>References must always be valid. Mutable references are exclusive: while one exists, no other reference to the same value may be used. This prevents data races at compile time, which is one of Rust's headline features for systems programming.</p></article><footer>© 2025</footer></body></html>";

    #[test]
    fn ssrf_guard_blocks_loopback_by_default() {
        let srv = FakeServer::start(vec![("GET /", 200, "text/plain", "secret intranet".into())]);
        let c = ctx("webfetch-ssrf");
        let o = tool(json!({})).call(&c, json!({"url": srv.url}));
        assert!(o.is_error && o.content.contains("Blocked") && !o.content.contains("secret intranet"), "{}", o.content);
        assert!(srv.requests().is_empty(), "never connected");
        // A public-looking redirect target that lands on loopback is re-checked per hop.
        let o = tool(json!({})).call(&c, json!({"url": "http://169.254.169.254/latest/meta-data"}));
        assert!(o.is_error && o.content.contains("metadata"), "{}", o.content);
        let o = open().call(&c, json!({"url": "http://169.254.169.254/"}));
        assert!(o.is_error && o.content.contains("metadata"), "metadata stays blocked with allow_private_urls");
        let o = tool(json!({"allow_private_urls": true, "blocklist": {"domains": ["127.0.0.1"]}})).call(&c, json!({"url": srv.url}));
        assert!(o.is_error && o.content.contains("Blocked by website policy"), "{}", o.content);
    }

    #[test]
    fn html_is_readable_markdown_or_text() {
        let srv = FakeServer::start(vec![("GET /a", 200, "text/html; charset=utf-8", ARTICLE.into())]);
        let c = ctx("webfetch-html");
        let v = json_of(&open().call(&c, json!({"url": format!("{}/a?q=1", srv.url)})));
        assert_eq!((v["status"].as_u64(), v["extractor"].as_str(), v["extractMode"].as_str(), v["contentType"].as_str()), (Some(200), Some("readability"), Some("markdown"), Some("text/html")));
        let text = v["text"].as_str().unwrap();
        assert!(text.contains("# Ownership") && text.contains("garbage collector") && text.contains("& the borrow") && !text.contains("evil") && !text.contains("About"), "{text}");
        assert_eq!(v["title"], "Rust Ownership Explained In Depth");
        assert_eq!(v["truncated"], false);
        assert!(srv.last().head.starts_with("GET /a?q=1 ") && srv.last().header("accept").unwrap().starts_with("text/markdown"));
        let v = json_of(&open().call(&c, json!({"url": format!("{}/a", srv.url), "extractMode": "text"})));
        assert!(!v["text"].as_str().unwrap().contains("# Ownership") && v["text"].as_str().unwrap().contains("Ownership"));
        assert!(open().call(&c, json!({"url": srv.url, "extractMode": "html"})).content.contains("extractMode"));
    }

    #[test]
    fn pdf_json_and_markdown_bodies() {
        let pdfb = crate::web::pdf::tests::sample_pdf("Quarterly report text");
        let srv = FakeServer::with(move |r| match r.path.as_str() {
            "/doc.pdf" => (200, "application/pdf".into(), pdfb.clone(), vec![]),
            "/j" => (200, "application/json".into(), br#"{"a":[1,2],"b":"x"}"#.to_vec(), vec![]),
            "/m" => (200, "text/markdown".into(), b"# Title\n\nSome **bold** [link](https://x.com)".to_vec(), vec![]),
            _ => (200, "image/png".into(), b"\x89PNG\r\n\x1a\n\0\0".to_vec(), vec![]),
        });
        let c = ctx("webfetch-kinds");
        let v = json_of(&open().call(&c, json!({"url": format!("{}/doc.pdf", srv.url)})));
        assert_eq!(v["extractor"], "pdf");
        assert!(v["text"].as_str().unwrap().contains("Quarterly report text"));
        let v = json_of(&open().call(&c, json!({"url": format!("{}/j", srv.url)})));
        assert_eq!(v["extractor"], "json");
        assert!(v["text"].as_str().unwrap().contains("\"a\": [\n"));
        let v = json_of(&open().call(&c, json!({"url": format!("{}/m", srv.url), "extractMode": "text"})));
        assert_eq!(v["extractor"], "cf-markdown");
        let t = v["text"].as_str().unwrap();
        assert!(t.contains("Some **bold** link") && !t.contains("# Title") && !t.contains("](https"), "{t}");
        let o = open().call(&c, json!({"url": format!("{}/img", srv.url)}));
        assert!(o.is_error && o.content.contains("binary content (PNG image data)"), "{}", o.content);
    }

    #[test]
    fn max_chars_truncates_with_spill() {
        let long: String = (0..3000).map(|i| format!("row {i:05} {}\n", "y".repeat(30))).collect();
        let srv = FakeServer::start(vec![("GET /big", 200, "text/plain", long.clone())]);
        let c = ctx("webfetch-spill");
        let v = json_of(&open().call(&c, json!({"url": format!("{}/big", srv.url), "maxChars": 3000})));
        assert_eq!(v["truncated"], true);
        let text = v["text"].as_str().unwrap();
        assert!(truncate::char_len(text) <= 3000 && text.starts_with("row 00000") && text.contains("row 02999") && text.contains("[TRUNCATED]"), "{}", truncate::char_len(text));
        let spill = v["spill"]["path"].as_str().unwrap();
        assert!(spill.contains("web-fetch-") && spill.starts_with(c.artifacts.join("web").to_str().unwrap()), "{spill}");
        assert_eq!(std::fs::read_to_string(spill).unwrap(), long);
        assert_eq!(v["rawLength"].as_u64(), Some(long.chars().count() as u64));
        // maxChars is clamped to [100, max_chars_cap].
        let t = tool(json!({"fetch": {"max_chars_cap": 5000}}));
        assert_eq!((t.max_chars(&json!({"maxChars": 1})), t.max_chars(&json!({"maxChars": 99999})), t.max_chars(&json!({}))), (100, 5000, 5000));
    }

    #[test]
    fn memo_and_disk_cache() {
        CACHE_LOCAL.with(|c| c.set(true));
        cache::fetch_memo().clear();
        let srv = FakeServer::start(vec![("GET /c", 200, "text/html", ARTICLE.into())]);
        let c = ctx("webfetch-cache");
        let url = format!("{}/c", srv.url);
        let t = open();
        let v1 = json_of(&t.call(&c, json!({"url": url})));
        assert!(v1.get("cached").is_none());
        let v2 = json_of(&t.call(&c, json!({"url": url})));
        assert_eq!((v2["cached"].as_bool(), v2["text"].as_str()), (Some(true), v1["text"].as_str()));
        assert_eq!(srv.requests().len(), 1, "memo hit");
        // Memo gone (new process): the on-disk page cache still serves it.
        cache::fetch_memo().clear();
        let v3 = json_of(&t.call(&c, json!({"url": url})));
        assert_eq!((v3["cached"].as_bool(), v3["extractor"].as_str()), (Some(true), Some("disk-cache")));
        assert!(v3["text"].as_str().unwrap().contains("garbage collector"));
        assert_eq!(srv.requests().len(), 1);
        // Custom headers bypass the cache.
        json_of(&t.call(&c, json!({"url": url, "headers": {"X-A": "1"}})));
        assert_eq!(srv.requests().len(), 2);
        CACHE_LOCAL.with(|c| c.set(false));
    }

    #[test]
    fn firecrawl_fallback_on_http_error_and_empty_extraction() {
        let target = FakeServer::start(vec![("GET /blocked", 403, "text/html", "<html><body>Access denied</body></html>".into()), ("GET /empty", 200, "text/html", "<html><body><script>x()</script></body></html>".into())]);
        let fc = FakeServer::start(vec![("POST /v2/scrape", 200, "application/json", json!({"success":true,"data":{"markdown":"# Scraped\n\nvia firecrawl","metadata":{"title":"FC","sourceURL":"https://example.com/final","statusCode":200}}}).to_string())]);
        let t = WebFetch { cfg: Arc::new(WebConfig::from_value(json!({"allow_private_urls": true, "providers": {"firecrawl": {"base_url": fc.url.clone()}}})).unwrap()), env: env_of(&[("FIRECRAWL_API_KEY", "fc-test")]) };
        let c = ctx("webfetch-fc");
        let v = json_of(&t.call(&c, json!({"url": format!("{}/blocked", target.url)})));
        assert_eq!((v["extractor"].as_str(), v["title"].as_str(), v["finalUrl"].as_str()), (Some("firecrawl"), Some("FC"), Some("https://example.com/final")));
        assert!(v["text"].as_str().unwrap().contains("via firecrawl"));
        assert_eq!(fc.last().json()["url"], format!("{}/blocked", target.url));
        assert!(fc.last().header("authorization").unwrap().contains("fc-test"));
        let v = json_of(&t.call(&c, json!({"url": format!("{}/empty", target.url)})));
        assert_eq!(v["extractor"], "firecrawl");
        let eff = t.effects(&c, &json!({"url": "https://example.com/"}));
        assert_eq!(eff.len(), 2, "target + fallback provider");
        // Without a fallback the HTTP error surfaces, wrapped.
        let o = open().call(&c, json!({"url": format!("{}/blocked", target.url)}));
        assert!(o.is_error && o.content.contains("Web fetch failed (403)") && o.content.contains("Access denied"), "{}", o.content);
        // SSRF refusals are never routed through the provider.
        let o = WebFetch { cfg: Arc::new(WebConfig::from_value(json!({"providers": {"firecrawl": {"base_url": fc.url.clone()}}})).unwrap()), env: env_of(&[("FIRECRAWL_API_KEY", "fc-test")]) }.call(&c, json!({"url": format!("{}/blocked", target.url)}));
        assert!(o.is_error && o.content.contains("Blocked"), "{}", o.content);
        assert_eq!(fc.requests().len(), 2);
    }

    #[test]
    fn post_substitutes_secrets_but_effects_do_not() {
        let c = ctx("webpost");
        let srv = FakeServer::start(vec![("POST /p", 201, "application/json", r#"{"ok":true}"#.into())]);
        let input = json!({"url": format!("{}/p", srv.url),"method":"POST","body":"key={{secret:TOKEN}}","headers":{"X-Auth":"{{secret:TOKEN}}"}});
        let eff = open().effects(&c, &input);
        match &eff[..] {
            [Effect::Net { dest, payload }] => {
                assert_eq!(dest, "127.0.0.1");
                assert!(payload.contains("key={{secret:TOKEN}}") && !payload.contains("s3cr3t"));
                assert!(payload.contains("X-Auth: {{secret:TOKEN}}"));
            }
            other => panic!("{other:?}"),
        }
        let v = json_of(&open().call(&c, input));
        assert!(v["text"].as_str().unwrap().contains("\"ok\": true"));
        let req = srv.last();
        assert!(req.body == "key=s3cr3t" && req.header("x-auth").as_deref() == Some("s3cr3t"), "{req:?}");
    }

    #[test]
    fn failures() {
        let c = ctx("webf");
        let t = open();
        assert!(t.call(&c, json!({})).is_error);
        let o = t.call(&c, json!({"url":"ftp://example.com/x"}));
        assert!(o.is_error && o.content.contains("must be http or https"), "{}", o.content);
        assert!(t.call(&c, json!({"url":"http:///nohost"})).content.contains("no host"));
        assert!(t.call(&c, json!({"url":"http://127.0.0.1:9/","method":"DELETE"})).content.contains("unsupported method"));
        assert!(t.call(&c, json!({"url":"http://127.0.0.1:9/","body":"x"})).content.contains("cannot carry a body"));
        assert!(t.call(&c, json!({"url":"http://127.0.0.1:9/","headers":["x"]})).content.contains("headers"));
        assert!(t.call(&c, json!({"url":"https://x.com/?k=sk-abcdefghijklmnopqrst"})).content.contains("appears to be an API key"));
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let o = t.call(&c, json!({"url": format!("http://127.0.0.1:{port}/")}));
        assert!(o.is_error && o.content.contains("failed"), "{}", o.content);
        assert!(t.effects(&c, &json!({"url":"ftp://x"})).is_empty());
        assert!(tool(json!({"fetch": {"enabled": false}})).call(&c, json!({"url":"https://a.com"})).content.contains("disabled"));
        c.cancel.cancel();
        assert_eq!(t.call(&c, json!({"url":"http://127.0.0.1:9/"})).content, "cancelled");
    }

    #[test]
    fn redirects_are_followed_and_capped() {
        let srv = FakeServer::with(|r| match r.path.as_str() {
            "/r1" => (302, "text/plain".into(), vec![], vec![("Location".into(), "/r2".into())]),
            "/r2" => (301, "text/plain".into(), vec![], vec![("Location".into(), "/final".into())]),
            "/loop" => (302, "text/plain".into(), vec![], vec![("Location".into(), "/loop".into())]),
            _ => (200, "text/plain".into(), b"landed".to_vec(), vec![]),
        });
        let c = ctx("webfetch-redir");
        let v = json_of(&open().call(&c, json!({"url": format!("{}/r1", srv.url)})));
        assert_eq!(v["finalUrl"], format!("{}/final", srv.url));
        let o = open().call(&c, json!({"url": format!("{}/loop", srv.url)}));
        assert!(o.is_error && o.content.contains("Too many redirects (limit: 3)"), "{}", o.content);
        assert_eq!(merged_headers(&WebConfig::from_value(json!({"fetch":{"headers":{"X-Op":"1","Host":"evil"}}})).unwrap(), &[("x-op".into(), "2".into())]), vec![("x-op".to_string(), "2".to_string())]);
    }
}
