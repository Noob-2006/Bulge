//! xAI web search via Grok's server-side `web_search` tool on the Responses API (`POST /responses`).
//! Two shapes: `answer` (OpenClaw `extensions/xai`: grounded answer + url_citation citations,
//! `store: false`, low reasoning on new models, inline citations opt-in) and `results`
//! (Hermes `plugins/web/xai`: Grok is asked for a JSON result list; parsed from the JSON block,
//! then url_citation annotations, then `citations`; allowed / excluded domain filters, max 5).
//! xAI OAuth refresh is not ported (seagent keeps no xAI OAuth store): XAI_API_KEY or config key.

use super::{hit, Citation, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub struct Xai;

pub const ENV: &[&str] = &["XAI_API_KEY"];
const DEFAULT_BASE: &str = "https://api.x.ai/v1";
pub const ANSWER_MODEL: &str = "grok-4.7";
const RESULTS_MODEL: &str = "grok-build-0.1";
const MAX_CONTENT: usize = 20_000;

pub fn base(c: &WebCtx) -> String {
    c.base_url("xai", Some("XAI_BASE_URL"), DEFAULT_BASE)
}

/// Grok 4.3 and ≥ 4.6 take an explicit low reasoning effort for tool calls.
pub fn tool_reasoning(model: &str) -> Option<&'static str> {
    let m = model.trim_start_matches("xai/");
    let v = m.strip_prefix("grok-")?;
    let mut it = v.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse::<u32>().unwrap_or(0));
    let (maj, min) = (it.next()?, it.next().unwrap_or(0));
    ((maj, min) == (4, 3) || maj > 4 || (maj == 4 && min >= 6)).then_some("low")
}

fn domains(c: &WebCtx, k: &str) -> Vec<String> {
    c.opt_list("xai", k).into_iter().take(5).collect()
}

pub fn prompt(query: &str, limit: usize) -> String {
    format!(
        "Use the web_search tool to find current information for the query below, then respond with ONLY a single JSON object — no prose, no markdown fences, no inline citation links — matching this exact schema:\n\n{{\"results\": [{{\"title\": \"string\", \"url\": \"string\", \"description\": \"1-2 sentence summary\"}}]}}\n\nReturn at most {limit} results, ordered by relevance, with absolute https:// URLs. If no usable results exist, return {{\"results\": []}}.\n\nQuery: {query}"
    )
}

/// `(output_text texts, their annotations)` from a Responses payload (message blocks + bare output_text).
pub fn output_blocks(v: &Value) -> (Vec<String>, Vec<Value>) {
    let mut texts = Vec::new();
    let mut anns = Vec::new();
    for item in v.get("output").and_then(|o| o.as_array()).into_iter().flatten() {
        let blocks: Vec<&Value> = match item.get("type").and_then(|t| t.as_str()) {
            Some("message") => item.get("content").and_then(|c| c.as_array()).map(|a| a.iter().collect()).unwrap_or_default(),
            Some("output_text") => vec![item],
            _ => vec![],
        };
        for b in blocks {
            if b.get("type").and_then(|t| t.as_str()) != Some("output_text") {
                continue;
            }
            if let Some(t) = b.get("text").and_then(|t| t.as_str()).filter(|t| !t.trim().is_empty()) {
                texts.push(t.to_string());
            }
            anns.extend(b.get("annotations").and_then(|a| a.as_array()).cloned().unwrap_or_default());
        }
    }
    (texts, anns)
}

fn json_results(text: &str, limit: usize) -> Option<Vec<Hit>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\{[\s\S]*\}").unwrap());
    let mut cands = vec![text.to_string()];
    if let Some(m) = re.find(text).filter(|m| m.as_str() != text) {
        cands.push(m.as_str().to_string());
    }
    for c in cands {
        let Ok(v) = serde_json::from_str::<Value>(&c) else { continue };
        let Some(rows) = v.get("results").and_then(|r| r.as_array()) else { continue };
        let out: Vec<Hit> = rows.iter().take(limit).filter(|r| !http::s(r, "url").is_empty()).map(|r| hit(&http::s(r, "title"), &http::s(r, "url"), &http::s(r, "description"))).collect();
        if !out.is_empty() {
            return Some(out);
        }
    }
    None
}

/// Hermes `_extract_results`: JSON block → annotations (+ ~200 chars of preceding text) → `citations`.
pub fn extract_results(v: &Value, limit: usize) -> Vec<Hit> {
    let (texts, anns) = output_blocks(v);
    if let Some(h) = texts.iter().find_map(|t| json_results(t, limit)) {
        return h;
    }
    let joined = texts.join("\n");
    let mut out: Vec<Hit> = Vec::new();
    for a in &anns {
        let url = if a.get("type").and_then(|t| t.as_str()) == Some("url_citation") { http::s(a, "url") } else { String::new() };
        if url.is_empty() || out.iter().any(|h| h.url == url) {
            continue;
        }
        let (s, e) = (a.get("start_index").and_then(|x| x.as_u64()), a.get("end_index").and_then(|x| x.as_u64()));
        let chars: Vec<char> = joined.chars().collect();
        let desc = match (s, e) {
            (Some(s), Some(e)) if (s as usize) < (e as usize) && (e as usize) <= chars.len() => chars[(s as usize).saturating_sub(200)..s as usize].iter().collect::<String>().trim().to_string(),
            _ => String::new(),
        };
        out.push(hit("", &url, &desc));
        if out.len() >= limit {
            return out;
        }
    }
    if !out.is_empty() {
        return out;
    }
    v.get("citations").and_then(|c| c.as_array()).into_iter().flatten().filter_map(|u| u.as_str()).filter(|u| !u.trim().is_empty()).take(limit).map(|u| hit("", u, "")).collect()
}

/// OpenClaw answer shape: concatenated output_text (capped) + up to 20 url_citation URLs.
pub fn extract_answer(v: &Value, inline: bool) -> Result<(String, Vec<Citation>), String> {
    let (texts, anns) = output_blocks(v);
    let mut content = if texts.is_empty() { v.get("output_text").and_then(|t| t.as_str()).unwrap_or("").to_string() } else { texts.join("") };
    if content.trim().is_empty() {
        return Err("xAI web search failed: response contained no text".into());
    }
    if content.chars().count() > MAX_CONTENT {
        content = content.chars().take(MAX_CONTENT).collect();
    }
    let mut cites: Vec<Citation> = Vec::new();
    for a in anns.iter().take(1000) {
        if cites.len() >= 20 {
            break;
        }
        let u = http::s(a, "url");
        if a.get("type").and_then(|t| t.as_str()) == Some("url_citation") && u.len() <= 2048 && (u.starts_with("http://") || u.starts_with("https://")) && !cites.iter().any(|c| c.url == u) {
            cites.push(Citation { url: u, title: None });
        }
    }
    for u in v.get("citations").and_then(|c| c.as_array()).into_iter().flatten().filter_map(|u| u.as_str()) {
        if cites.len() < 20 && !cites.iter().any(|c| c.url == u) {
            cites.push(Citation { url: u.to_string(), title: None });
        }
    }
    let _ = inline; // inline citation offsets are reported by x_search; web_search keeps the text as given
    Ok((content, cites))
}

/// POST `/responses` with the Grok tool and return the parsed body (HTTP-200 error envelopes too).
pub fn responses(c: &WebCtx, key: &str, body: &Value, timeout: u64, label: &str) -> Result<Value, String> {
    c.check_cancel()?;
    let r = http::post_json(&format!("{}/responses", base(c)), &[super::bearer(key), ("User-Agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))], body, timeout).map_err(|e| {
        if e.to_ascii_lowercase().contains("timeout") || e.to_ascii_lowercase().contains("timed out") {
            format!("{label} timed out after {timeout}s. Check xAI authentication or try a simpler request.")
        } else {
            format!("Could not reach xAI: {e}")
        }
    })?;
    if !r.ok() {
        return Err(format!("{label} returned HTTP {}: {}", r.status, crate::util::truncate_str(&r.body.replace(key, "***"), 300)).trim_end().to_string());
    }
    let v = r.json().map_err(|_| "Could not parse xAI Responses API reply as JSON".to_string())?;
    if let Some(e) = v.get("error").filter(|e| e.is_object()) {
        return Err(format!("xAI returned an error: {}", [http::s(e, "message"), http::s(e, "code")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "unknown error".into())));
    }
    Ok(v)
}

impl WebProvider for Xai {
    fn id(&self) -> &'static str {
        "xai"
    }
    fn label(&self) -> &'static str {
        "xAI Web Search (Grok)"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["grok"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("xai", ENV).is_some()
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/responses", base(c))
    }
    fn signup_url(&self) -> &'static str {
        "https://console.x.ai"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("xai", ENV).ok_or("web_search (grok) needs xAI credentials. Set XAI_API_KEY or [web.providers.xai] api_key. If you do not want to configure search credentials, use web_fetch for a specific URL.")?;
        let results_mode = c.opt("xai", "mode").is_some_and(|m| m.eq_ignore_ascii_case("results"));
        let (allowed, excluded) = (domains(c, "allowed_domains"), domains(c, "excluded_domains"));
        if !allowed.is_empty() && !excluded.is_empty() {
            return Err("[web.providers.xai] allowed_domains and excluded_domains cannot both be set (xAI restriction).".into());
        }
        let mut tool = json!({"type": "web_search"});
        if !allowed.is_empty() {
            tool["filters"] = json!({"allowed_domains": allowed});
        } else if !excluded.is_empty() {
            tool["filters"] = json!({"excluded_domains": excluded});
        }
        let timeout = c.opt_u64("xai", "timeout_seconds").unwrap_or(if results_mode { 90 } else { 60 });
        if results_mode {
            let model = c.opt("xai", "model").unwrap_or_else(|| RESULTS_MODEL.into());
            let limit = r.count.clamp(1, 100);
            let body = json!({"model": model, "input": [{"role":"user","content": prompt(&r.query, limit)}], "tools": [tool], "include": ["no_inline_citations"]});
            let v = responses(c, &key, &body, timeout, "xAI web search")?;
            return Ok(SearchOutput::Results(extract_results(&v, limit)));
        }
        let model = c.opt("xai", "model").unwrap_or_else(|| ANSWER_MODEL.into());
        let mut body = json!({"model": model, "input": [{"role":"user","content": r.query}], "tools": [tool], "store": false});
        if let Some(e) = tool_reasoning(&model) {
            body["reasoning"] = json!({"effort": e});
        }
        let v = responses(c, &key, &body, timeout, "xAI web search")?;
        let (content, citations) = extract_answer(&v, c.opt_bool("xai", "inline_citations").unwrap_or(false))?;
        Ok(SearchOutput::Answer { content, citations })
    }
}

/// OpenClaw `normalizeXaiCitationUrl`: http(s) only, at most 2 048 chars.
pub fn citation_url(u: &str) -> Option<String> {
    (u.len() <= 2048 && (u.starts_with("http://") || u.starts_with("https://")) && crate::web::ssrf::parse_url(u).is_ok()).then(|| u.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    fn answer_body() -> String {
        json!({"output":[{"type":"web_search_call"},{"type":"message","content":[{"type":"output_text","text":"Grok says hi [[1]](https://a.com).","annotations":[{"type":"url_citation","url":"https://a.com"},{"type":"url_citation","url":"javascript:x"}]}]}],"citations":["https://b.com"]}).to_string()
    }

    #[test]
    fn answer_mode() {
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", answer_body())]);
        let c = wctx(json!({"providers":{"xai":{"base_url":s.url.clone(),"allowed_domains":["x.com"]}}}), &[("XAI_API_KEY", "xai-test")]);
        let SearchOutput::Answer { content, citations } = Xai.search(&c, &SearchRequest { query: "q".into(), count: 5, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(content, "Grok says hi [[1]](https://a.com).");
        assert_eq!(citations.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(), vec!["https://a.com", "https://b.com"]);
        let b = s.last().json();
        assert_eq!((b["model"].as_str(), b["store"].as_bool(), b["reasoning"]["effort"].as_str(), b["tools"][0]["filters"]["allowed_domains"][0].as_str()), (Some("grok-4.7"), Some(false), Some("low"), Some("x.com")));
        assert_eq!(s.last().header("authorization").as_deref(), Some("Bearer xai-test"));
        assert_eq!((tool_reasoning("grok-4.3"), tool_reasoning("grok-4.5"), tool_reasoning("grok-5")), (Some("low"), None, Some("low")));
    }

    #[test]
    fn results_mode_parsing_ladder() {
        let json_block = json!({"output":[{"type":"message","content":[{"type":"output_text","text":"Sure! {\"results\":[{\"title\":\"T\",\"url\":\"https://t.com\",\"description\":\"d\"},{\"title\":\"no url\"}]}"}]}]});
        assert_eq!(extract_results(&json_block, 5)[0].url, "https://t.com");
        let anns = json!({"output":[{"type":"message","content":[{"type":"output_text","text":"Rust is fast. Read more","annotations":[{"type":"url_citation","url":"https://r.com","start_index":13,"end_index":23}]}]}]});
        assert_eq!(extract_results(&anns, 5)[0].snippet, "Rust is fast.");
        assert_eq!(extract_results(&json!({"citations":["https://c.com"," "]}), 5).len(), 1);
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", json_block.to_string())]);
        let c = wctx(json!({"providers":{"xai":{"base_url":s.url.clone(),"mode":"results"}}}), &[("XAI_API_KEY", "xai-test")]);
        let SearchOutput::Results(h) = Xai.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h.len(), 1);
        let b = s.last().json();
        assert_eq!((b["model"].as_str(), b["include"][0].as_str()), (Some("grok-build-0.1"), Some("no_inline_citations")));
        assert!(b["input"][0]["content"].as_str().unwrap().contains("Return at most 3 results"));
    }

    #[test]
    fn errors() {
        let c = wctx(json!({"providers":{"xai":{"allowed_domains":["a"],"excluded_domains":["b"]}}}), &[("XAI_API_KEY", "k")]);
        assert!(Xai.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err().contains("cannot both be set"));
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", json!({"error":{"message":"overloaded"}}).to_string())]);
        let c = wctx(json!({"providers":{"xai":{"base_url":s.url.clone()}}}), &[("XAI_API_KEY", "k")]);
        assert_eq!(Xai.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err(), "xAI returned an error: overloaded");
        let s = FakeServer::start(vec![("POST /responses", 401, "text/plain", "bad key xai-test".into())]);
        let c = wctx(json!({"providers":{"xai":{"base_url":s.url.clone()}}}), &[("XAI_API_KEY", "xai-test")]);
        assert_eq!(Xai.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err(), "xAI web search returned HTTP 401: bad key ***");
        assert!(!Xai.configured(&wctx(json!({}), &[])));
    }
}
