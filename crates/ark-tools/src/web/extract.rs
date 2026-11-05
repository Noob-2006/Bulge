//! `web_extract` (Hermes `tools/web_tools.py::web_extract_tool` + `web_tools_extract.py` +
//! `web_tools_truncate.py`): clean page content for up to `max_urls` URLs per call, no LLM.
//! Secret-bearing URLs refuse the whole call; private / blocklisted URLs fail per entry.
//! Backend: `web.extract.provider` (strict) > `web.backend` > the first configured extract
//! provider > the keyless ring; `local` is ark's own guarded fetch + Readability / PDF. Fresh
//! pages come from the on-disk cache; a provider that fails every URL gets one keyless rescue,
//! and URLs still failing are retried locally. Long pages become a head+tail window with the
//! full text spilled to a file.

use super::cache::{self, DiskCache};
use super::content::wrap_web;
use super::fetch::{fetch_document, Request};
use super::http::{host_of, EnvFn, WebCtx};
use super::providers::{self, Page, WebProvider};
use super::{keyless, policy, ssrf, truncate, WebConfig};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// Who extracts.
pub enum Route {
    Provider(&'static dyn WebProvider),
    Keyless,
    Local,
}

impl Route {
    pub fn id(&self) -> &'static str {
        match self {
            Route::Provider(p) => p.id(),
            Route::Keyless => "keyless",
            Route::Local => "local",
        }
    }
}

fn extract_capable() -> Vec<&'static str> {
    let mut v: Vec<&str> = providers::all().iter().filter(|p| p.supports_extract()).map(|p| p.id()).collect();
    v.extend(["keyless", "local"]);
    v
}

/// Strict when pinned: a search-only backend or an unknown name is an error, never a silent switch.
pub fn resolve(c: &WebCtx) -> Result<Route, String> {
    let pin = c.cfg.extract_pin();
    let hint = || format!("Set [web.extract] provider to one of: {}.", extract_capable().join(", "));
    match pin.as_str() {
        "" => {}
        "local" => return Ok(Route::Local),
        "keyless" => return Ok(Route::Keyless),
        _ => {
            return match providers::get(&pin) {
                Some(p) if p.supports_extract() => Ok(Route::Provider(p)),
                Some(p) => Err(format!("{} is a search-only backend and cannot extract URL content. {}", p.label(), hint())),
                None => Err(format!("web.extract.provider is set to '{pin}', but no web extract provider has that name. {}", hint())),
            }
        }
    }
    if let Some(p) = providers::all().iter().copied().find(|p| p.supports_extract() && p.auto_detect() && p.configured(c)) {
        return Ok(Route::Provider(p));
    }
    Ok(if keyless::enabled(c) { Route::Keyless } else { Route::Local })
}

fn local_page(c: &WebCtx, url: &str, text_mode: bool) -> Page {
    match fetch_document(c, &Request::get(url, text_mode)) {
        Ok(d) => {
            let mut p = Page::ok(url, d.title.as_deref().unwrap_or(""), &d.text);
            if d.final_url != url {
                p.source_url = Some(d.final_url);
            }
            p
        }
        Err(e) => Page::err(url, e.message()),
    }
}

/// Provider call under `[web.extract] timeout_seconds` (0 = no wall-clock cap).
fn provider_pages(c: &WebCtx, p: &'static dyn WebProvider, urls: &[String]) -> Vec<Page> {
    let secs = c.cfg.extract.timeout_seconds;
    let (cc, uu) = (c.clone(), urls.to_vec());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(p.extract(&cc, &uu));
    });
    let res = if secs == 0 { rx.recv().map_err(|_| "extract worker died".to_string()) } else { rx.recv_timeout(Duration::from_secs(secs)).map_err(|_| format!("{} extract timed out after {secs}s", p.label())) };
    match res.and_then(|r| r) {
        Ok(pages) => urls.iter().map(|u| pages.iter().find(|pg| pg.url == *u || pg.source_url.as_deref() == Some(u)).cloned().unwrap_or_else(|| Page::err(u, "provider returned no result for this URL"))).collect(),
        Err(e) => urls.iter().map(|u| Page::err(u, e.clone())).collect(),
    }
}

fn dispatch(c: &WebCtx, route: &Route, urls: &[String], text_mode: bool) -> (Vec<Page>, String) {
    match route {
        Route::Local => (urls.iter().map(|u| local_page(c, u, text_mode)).collect(), "local".into()),
        Route::Keyless => {
            let pages = keyless::extract_with_failover(c, "", urls);
            (urls.iter().map(|u| pages.iter().find(|p| p.url == *u).cloned().unwrap_or_else(|| Page::err(u, "keyless extract returned no result"))).collect(), "keyless".into())
        }
        Route::Provider(p) => {
            let pages = provider_pages(c, *p, urls);
            if pages.iter().all(|pg| pg.error.is_some()) && c.cfg.keyless_rescue && keyless::enabled(c) && !p.routes_keyless(c) {
                let rescued = keyless::extract_with_failover(c, p.id(), urls);
                if rescued.iter().any(|pg| pg.error.is_none()) {
                    return (urls.iter().zip(pages).map(|(u, orig)| rescued.iter().find(|r| r.url == *u && r.error.is_none()).cloned().unwrap_or(orig)).collect(), "keyless".into());
                }
            }
            (pages, p.id().into())
        }
    }
}

/// One entry of the model-facing result.
fn entry(p: &Page, blocked: Option<&str>) -> Value {
    let mut v = json!({"url": p.url, "title": p.title, "content": p.content, "error": p.error});
    if let Some(b) = blocked {
        v["blocked_by_policy"] = json!(b);
    }
    v
}

/// End to end: `Ok(results)` or a whole-call refusal.
pub fn run(c: &WebCtx, items: &[Value], text_mode: bool, char_limit: usize) -> Result<Vec<Value>, String> {
    let cfg = &c.cfg;
    let format = if text_mode { "text" } else { "markdown" };
    let max = cfg.extract.max_urls.max(1);
    let mut out: Vec<Option<Value>> = vec![None; items.len().min(max)];
    let mut todo: Vec<(usize, String)> = vec![];
    let ssrf_policy = ssrf::SsrfPolicy::from_config(cfg);
    for (i, item) in items.iter().take(max).enumerate() {
        let Some(raw) = item.as_str().or_else(|| item.get("url").and_then(|u| u.as_str())).map(str::trim).filter(|u| !u.is_empty()) else {
            out[i] = Some(entry(&Page::err("", format!("Invalid URL entry at index {i}: expected a string URL")), None));
            continue;
        };
        if let Some(e) = ssrf::url_secret_refusal(raw) {
            return Err(e);
        }
        let url = ssrf::normalize_url_for_request(raw);
        if let Err(m) = policy::enforce(cfg, &c.home, &url) {
            out[i] = Some(entry(&Page::err(&url, m.clone()), Some(&m)));
            continue;
        }
        if let Err(e) = ssrf::check_url(&url, &ssrf_policy) {
            out[i] = Some(entry(&Page::err(&url, e), None));
            continue;
        }
        todo.push((i, url));
    }
    let route = if todo.is_empty() { Route::Local } else { resolve(c)? };
    let disk = DiskCache::new(&c.home);
    let ttl = cfg.ttl_secs();
    let mut fetch: Vec<(usize, String)> = vec![];
    let mut pages: Vec<(usize, Page)> = vec![];
    for (i, url) in todo {
        match cache::cacheable(cfg, &url).then(|| disk.get(&url, format, route.id(), ttl)).flatten() {
            Some((title, content)) => pages.push((i, Page::ok(&url, &title, &content))),
            None => fetch.push((i, url)),
        }
    }
    if !fetch.is_empty() {
        c.check_cancel()?;
        let urls: Vec<String> = fetch.iter().map(|(_, u)| u.clone()).collect();
        let (mut got, _served) = dispatch(c, &route, &urls, text_mode);
        if !matches!(route, Route::Local) && cfg.extract.local_fallback {
            for p in got.iter_mut().filter(|p| p.error.is_some()) {
                let local = local_page(c, &p.url, text_mode);
                if local.error.is_none() {
                    *p = local;
                }
            }
        }
        for ((i, url), p) in fetch.into_iter().zip(got) {
            if p.error.is_none() && !p.content.is_empty() && cache::cacheable(cfg, &url) {
                disk.put(&url, format, route.id(), &p.title, &p.content);
            }
            pages.push((i, p));
        }
    }
    for (i, mut p) in pages {
        if p.error.is_none() {
            if let Some(kind) = truncate::binary_kind(&p.content) {
                p.content.clear();
                p.error = Some(format!("URL returned binary content ({kind}), not a page. Download it with the shell (curl -L -o) and read the file instead."));
            } else if p.content.trim().is_empty() {
                p.error = Some("No content extracted".into());
            } else {
                let clean = truncate::convert_base64_images(&p.content);
                p.content = truncate::truncate_with_footer(&clean, &p.url, char_limit, &c.spill_dir).0;
            }
        }
        out[i] = Some(entry(&p, None));
    }
    Ok(out.into_iter().flatten().collect())
}

pub struct WebExtract {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl WebExtract {
    fn ctx(&self, t: &ToolCtx) -> WebCtx {
        WebCtx::from_tool(self.cfg.clone(), self.env.clone(), t)
    }
}

fn err_json(e: &str) -> ToolOutput {
    ToolOutput::err(json!({"success": false, "error": e}).to_string())
}

impl Tool for WebExtract {
    fn spec(&self) -> ToolSpec {
        let max = self.cfg.extract.max_urls.max(1);
        ToolSpec {
            name: "web_extract".into(),
            description: format!("Extract content from web page URLs. Returns clean page content in markdown/text (no LLM summarization — fast). Also works with PDF URLs (arxiv papers, documents) — pass the PDF link directly. Pages within the char budget (default {}) return whole; larger pages return a head+tail window with a footer telling you the full text's saved file path and the read call to page through the omitted middle. Inline images appear as [IMAGE: alt] placeholders; real image URLs are kept as links. If a URL fails or times out, use the browser tool instead.", truncate::clamp_char_limit(self.cfg.extract.char_limit)),
            input_schema: json!({"type":"object","required":["urls"],"properties":{
                "urls":{"type":"array","items":{"type":"string"},"maxItems":max,"description":format!("List of URLs to extract content from (max {max} URLs per call)")},
                "char_limit":{"type":"integer","minimum":truncate::CHAR_LIMIT_FLOOR,"description":"Optional per-page character budget sent back. Pages larger than this are head+tail truncated with the full text stored to disk. Raise it when you need more of a long page inline."},
                "format":{"type":"string","enum":["markdown","text"],"default":"markdown"}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = self.ctx(ctx);
        let urls: Vec<String> = input.get("urls").and_then(|u| u.as_array()).map(|a| a.iter().take(self.cfg.extract.max_urls.max(1)).filter_map(|u| u.as_str()).map(String::from).collect()).unwrap_or_default();
        let all = urls.join("\n");
        let mut out: Vec<Effect> = vec![];
        let route = resolve(&c);
        let local = matches!(route, Ok(Route::Local)) || self.cfg.extract.local_fallback;
        match route {
            Ok(Route::Provider(p)) => out.push(Effect::Net { dest: host_of(&p.endpoint(&c)), payload: all.clone() }),
            Ok(Route::Keyless) => out.extend(keyless::RING.iter().map(|v| Effect::Net { dest: host_of(&keyless::endpoint(&c, v)), payload: all.clone() })),
            _ => {}
        }
        if local {
            out.extend(urls.iter().filter_map(|u| ssrf::parse_url(u).ok().map(|p| Effect::Net { dest: p.host, payload: u.clone() })));
        }
        out
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if !self.cfg.extract.enabled {
            return ToolOutput::err("web_extract is disabled ([web.extract] enabled = false).");
        }
        let Some(items) = input.get("urls").and_then(|u| u.as_array()).filter(|a| !a.is_empty()) else {
            return err_json("`urls` must be a non-empty array of URLs");
        };
        let text_mode = input.get("format").and_then(|f| f.as_str()).is_some_and(|f| f.eq_ignore_ascii_case("text"));
        let limit = truncate::effective_char_limit(input.get("char_limit"), self.cfg.extract.char_limit);
        let c = self.ctx(ctx);
        match run(&c, items, text_mode, limit) {
            Ok(results) if results.iter().all(|r| r["content"].as_str().unwrap_or("").is_empty()) && results.iter().all(|r| r["error"].is_null()) => err_json("Content was inaccessible or not found"),
            Ok(results) => {
                let text = truncate::convert_base64_images(&serde_json::to_string_pretty(&json!({"results": results})).unwrap_or_default());
                ToolOutput::ok(wrap_web(&text, "web_extract"))
            }
            Err(e) => err_json(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, wctx, FakeServer};

    fn tool(cfg: Value, env: &[(&str, &str)]) -> WebExtract {
        WebExtract { cfg: Arc::new(WebConfig::from_value(cfg).unwrap()), env: env_of(env) }
    }
    fn results(o: &ToolOutput) -> Vec<Value> {
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("Source: Web Fetch") || o.content.contains("<<<EXTERNAL_UNTRUSTED_CONTENT"), "{}", o.content);
        let v: Value = serde_json::from_str(&o.content[o.content.find("---\n").unwrap() + 4..o.content.rfind("\n<<<END").unwrap()]).unwrap();
        v["results"].as_array().unwrap().clone()
    }
    const PAGE: &str = "<html><head><title>Guide</title></head><body><article><h1>Install</h1><p>Download the installer and run it. The installer checks your system, unpacks the files into the right place and adds the program to your path so that it is available from every terminal you open afterwards.</p><p>Then open a new shell and type the program name to verify the installation worked as expected on your machine.</p></article></body></html>";

    #[test]
    fn routing_is_strict_when_pinned() {
        assert_eq!(resolve(&wctx(json!({"extract":{"provider":"local"}}), &[])).unwrap().id(), "local");
        assert!(resolve(&wctx(json!({"extract":{"provider":"brave"}}), &[])).err().unwrap().contains("search-only backend"));
        assert!(resolve(&wctx(json!({"backend":"nope"}), &[])).err().unwrap().contains("no web extract provider has that name"));
        assert_eq!(resolve(&wctx(json!({}), &[("TAVILY_API_KEY", "tv")])).unwrap().id(), "tavily", "autodetect by credential");
        assert_eq!(resolve(&wctx(json!({}), &[])).unwrap().id(), "keyless");
        assert_eq!(resolve(&wctx(json!({"keyless_fallback":false}), &[])).unwrap().id(), "local");
    }

    #[test]
    fn local_extract_orders_results_and_blocks_per_entry() {
        let srv = FakeServer::start(vec![("GET /guide", 200, "text/html", PAGE.into())]);
        let t = tool(json!({"extract":{"provider":"local"},"fetch":{"allowed_hostnames":["127.0.0.1"]},"blocklist":{"domains":["blocked.example"]}}), &[]);
        let c = ctx("webextract-local");
        let r = results(&t.call(&c, json!({"urls":[format!("{}/guide", srv.url), 42, "http://10.0.0.1/x", "https://blocked.example/p"]})));
        assert_eq!(r.len(), 4);
        assert_eq!(r[0]["title"], "Guide");
        assert!(r[0]["content"].as_str().unwrap().contains("# Install") && r[0]["error"].is_null());
        assert!(r[1]["error"].as_str().unwrap().contains("index 1"));
        assert!(r[2]["error"].as_str().unwrap().starts_with("Blocked: URL targets a private or internal network address"));
        assert!(r[3]["blocked_by_policy"].as_str().unwrap_or_else(|| panic!("{:?}", r[3])).contains("blocked.example"));
        let o = t.call(&c, json!({"urls":["https://x.com/?key=ghp_abcdefghijklmnop1234"]}));
        assert!(o.is_error && o.content.contains("appears to be an API key"));
        assert!(t.call(&c, json!({"urls":[]})).is_error);
    }

    #[test]
    fn provider_extract_with_cache_truncation_and_local_fallback() {
        let long: String = (0..4000).map(|i| format!("para {i:05} {}\n", "z".repeat(30))).collect();
        let tv = FakeServer::start(vec![("POST /extract", 200, "application/json", json!({"results":[{"url":"https://93.184.216.34/long","raw_content":long,"title":"Long"}],"failed_results":[{"url":"https://93.184.216.34/fail","error":"timeout"}]}).to_string())]);
        let t = tool(json!({"extract":{"provider":"tavily","local_fallback":false},"keyless_rescue":false,"providers":{"tavily":{"base_url":tv.url.clone()}},"cache_exempt_hosts":[]}), &[("TAVILY_API_KEY", "tvly-test")]);
        let c = ctx("webextract-tavily");
        let urls = json!(["https://93.184.216.34/long", "https://93.184.216.34/fail"]);
        let r = results(&t.call(&c, json!({"urls": urls, "char_limit": 3000})));
        let content = r[0]["content"].as_str().unwrap();
        assert!(content.contains("[TRUNCATED]") && truncate::char_len(content) <= 3000 && content.starts_with("para 00000") && content.contains("para 03999"), "{}", truncate::char_len(content));
        let spill = content.lines().find_map(|l| l.strip_prefix("Full text saved to: ")).unwrap();
        assert_eq!(std::fs::read_to_string(spill).unwrap(), long.trim_end(), "provider text is stored whole");
        assert!(r[1]["error"].as_str().unwrap().contains("timeout"));
        assert_eq!(tv.requests().len(), 1);
        // Second call: the good page is a disk-cache hit, only the failed URL goes out.
        let r = results(&t.call(&c, json!({"urls": urls, "char_limit": 3000})));
        assert!(r[0]["content"].as_str().unwrap().contains("[TRUNCATED]"));
        assert_eq!(tv.requests().len(), 2);
        assert_eq!(tv.last().json()["urls"], json!(["https://93.184.216.34/fail"]));
        let eff = t.effects(&c, &json!({"urls": urls}));
        assert!(matches!(&eff[..], [Effect::Net { dest, .. }] if dest == "127.0.0.1"), "{eff:?}");
    }

    #[test]
    fn failed_provider_urls_retry_locally() {
        let srv = FakeServer::start(vec![("GET /guide", 200, "text/html", PAGE.into())]);
        let tv = FakeServer::start(vec![("POST /extract", 500, "text/plain", "upstream down".into())]);
        let t = tool(json!({"extract":{"provider":"tavily"},"keyless_rescue":false,"allow_private_urls":true,"providers":{"tavily":{"base_url":tv.url.clone()}}}), &[("TAVILY_API_KEY", "tvly-test")]);
        let c = ctx("webextract-fallback");
        let r = results(&t.call(&c, json!({"urls":[format!("{}/guide", srv.url)], "format": "text"})));
        assert!(r[0]["error"].is_null() && r[0]["content"].as_str().unwrap().contains("Download the installer") && !r[0]["content"].as_str().unwrap().contains("# Install"), "{:?}", r[0]);
        assert_eq!(tv.requests().len(), 1);
    }

    #[test]
    fn keyless_ring_serves_extract() {
        let text = json!({"results":[{"url":"https://93.184.216.34/a","title":"Paper","full_content":"Abstract body text of the paper."}]}).to_string();
        let ring = FakeServer::start(vec![("POST /mcp", 200, "application/json", json!({"result":{"content":[{"text":text}]}}).to_string())]);
        let t = tool(json!({"extract":{"local_fallback":false},"provider_tier":{"exa":"paid","firecrawl":"paid","keenable":"paid"},"providers":{"parallel":{"keyless_url":format!("{}/mcp", ring.url)}}}), &[]);
        let c = ctx("webextract-keyless");
        let o = t.call(&c, json!({"urls":["https://93.184.216.34/a"]}));
        let r = results(&o);
        assert!(r[0]["error"].is_null(), "{:?}", r[0]);
        assert!(r[0]["content"].as_str().unwrap().contains("Abstract body"), "{:?}", r[0]);
        assert!(ring.last().json()["params"]["name"].as_str().is_some());
        // A configured provider that fails every URL gets one keyless rescue.
        let tv = FakeServer::start(vec![("POST /extract", 503, "text/plain", "unavailable".into())]);
        let t = tool(json!({"extract":{"provider":"tavily","local_fallback":false},"provider_tier":{"exa":"paid","firecrawl":"paid","keenable":"paid"},"providers":{"tavily":{"base_url":tv.url.clone()},"parallel":{"keyless_url":format!("{}/mcp", ring.url)}}}), &[("TAVILY_API_KEY", "tvly-test")]);
        let r = results(&t.call(&c, json!({"urls":["https://93.184.216.34/a"]})));
        assert!(r[0]["content"].as_str().unwrap().contains("Abstract body") && tv.requests().len() == 1, "{:?}", r[0]);
    }
}
