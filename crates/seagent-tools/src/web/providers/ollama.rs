//! Ollama web search (OpenClaw `extensions/ollama`): a local host tries the experimental proxy
//! `/api/experimental/web_search`, then `/api/web_search` (404 falls through), then Ollama Cloud
//! with OLLAMA_API_KEY; `https://ollama.com` goes straight to the hosted API. Snippets ≤ 300 chars.
//! Never auto-selected (no credential signal upstream).

use super::{hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::json;

pub struct Ollama;

const LOCAL: &str = "http://127.0.0.1:11434";
const CLOUD: &str = "https://ollama.com";
const AUTH_ERR: &str = "Hosted Ollama Web Search requires an API key. Set OLLAMA_API_KEY or [web.providers.ollama] api_key.";

fn base(c: &WebCtx) -> String {
    c.base_url("ollama", Some("OLLAMA_HOST"), LOCAL).trim_end_matches("/api").to_string()
}

fn is_cloud(b: &str) -> bool {
    b.starts_with("https://") && http::host_of(b) == "ollama.com"
}

impl WebProvider for Ollama {
    fn id(&self) -> &'static str {
        "ollama"
    }
    fn label(&self) -> &'static str {
        "Ollama Web Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        &["OLLAMA_API_KEY"]
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.opt("ollama", "base_url").is_some() || c.key("ollama", &["OLLAMA_API_KEY"]).is_some()
    }
    fn auto_detect(&self) -> bool {
        false
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        let b = base(c);
        if is_cloud(&b) {
            format!("{b}/api/web_search")
        } else {
            format!("{b}/api/experimental/web_search")
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://ollama.com/"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let b = base(c);
        let cfg_key = c.opt("ollama", "api_key");
        let env_key = c.var("OLLAMA_API_KEY");
        let count = r.count.clamp(1, 10);
        let q = r.query.trim();
        if q.is_empty() {
            return Err("query parameter is required".into());
        }
        let mut attempts: Vec<(String, Option<String>)> = if is_cloud(&b) {
            vec![(format!("{b}/api/web_search"), cfg_key.clone().or(env_key.clone()))]
        } else {
            vec![(format!("{b}/api/experimental/web_search"), cfg_key.clone()), (format!("{b}/api/web_search"), cfg_key.clone())]
        };
        if !is_cloud(&b) {
            if let Some(k) = env_key {
                attempts.push((format!("{}/api/web_search", c.opt("ollama", "cloud_url").unwrap_or_else(|| CLOUD.into())), Some(k)));
            }
        }
        let body = json!({"query": q, "max_results": count});
        let mut last = String::from("Ollama web search failed");
        for (url, key) in attempts {
            c.check_cancel()?;
            let h: Vec<(&str, String)> = key.iter().map(|k| super::bearer(k)).collect();
            let resp = http::post_json(&url, &h, &body, 15).map_err(|e| format!("Ollama web search failed: {e}. Is Ollama running at {b}?"))?;
            match resp.status {
                401 => return Err(if is_cloud(&url) { AUTH_ERR.into() } else { "Ollama web search authentication failed. Run `ollama signin`.".into() }),
                403 => return Err("Ollama web search is unavailable. Check that cloud-backed web search is enabled on the Ollama host.".into()),
                404 => {
                    last = format!("Ollama web search failed (404): {}", resp.body.trim());
                    continue;
                }
                s if !(200..300).contains(&s) => return Err(format!("Ollama web search failed ({s}): {}", key.as_deref().map(|k| resp.body.replace(k, "***")).unwrap_or(resp.body).trim())),
                _ => {}
            }
            let v = resp.json()?;
            let hits = v
                .get("results")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
                .filter(|e| !http::s(e, "url").is_empty())
                .take(count)
                .map(|e| {
                    let content = http::s(e, "content");
                    hit(&http::s(e, "title"), &http::s(e, "url"), &content.chars().take(300).collect::<String>())
                })
                .collect();
            return Ok(SearchOutput::Results(hits));
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn local_fallthrough_and_cloud() {
        let s = FakeServer::start(vec![("POST /api/web_search", 200, "application/json", json!({"results":[{"title":"O","url":"https://o.com","content":"x".repeat(400)},{"title":"no url"}]}).to_string())]);
        let c = wctx(json!({"providers":{"ollama":{"base_url":s.url.clone()}}}), &[]);
        let SearchOutput::Results(h) = Ollama.search(&c, &SearchRequest { query: " q ".into(), count: 3, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((h.len(), h[0].snippet.len()), (1, 300));
        let paths: Vec<String> = s.requests().iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, vec!["/api/experimental/web_search", "/api/web_search"]);
        assert_eq!(s.last().json(), json!({"query":"q","max_results":3}));
        let u = FakeServer::start(vec![("POST /api/experimental/web_search", 401, "text/plain", "".into())]);
        let c = wctx(json!({"providers":{"ollama":{"base_url":u.url.clone()}}}), &[]);
        assert!(Ollama.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap_err().contains("ollama signin"));
        let c = wctx(json!({"providers":{"ollama":{"base_url":"https://ollama.com"}}}), &[("OLLAMA_API_KEY", "ol")]);
        assert_eq!(Ollama.endpoint(&c), "https://ollama.com/api/web_search");
        assert!(!Ollama.auto_detect());
    }
}
