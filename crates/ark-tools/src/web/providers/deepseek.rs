//! DeepSeek web search (OpenClaw `extensions/deepseek`): `POST /v1/tools/search`
//! `{query, count, need_content: false}`, Bearer DEEPSEEK_API_KEY; queries ≤ 128 characters,
//! no structured filters (operators go in the query); non-http(s) result URLs are dropped.

use super::{Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::json;

pub struct DeepSeek;

const ENV: &[&str] = &["DEEPSEEK_API_KEY"];
const DEFAULT_BASE: &str = "https://api.deepseek.com";

impl WebProvider for DeepSeek {
    fn id(&self) -> &'static str {
        "deepseek"
    }
    fn label(&self) -> &'static str {
        "DeepSeek Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("deepseek", ENV).is_some()
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/v1/tools/search", c.base_url("deepseek", None, DEFAULT_BASE))
    }
    fn signup_url(&self) -> &'static str {
        "https://platform.deepseek.com"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        if r.query.chars().count() > 128 {
            return Err("DeepSeek search queries must contain 1 to 128 Unicode characters. Shorten the query; it has not been sent.".into());
        }
        let key = c.key("deepseek", ENV).ok_or("web_search (deepseek) needs a DeepSeek API key. Set DEEPSEEK_API_KEY or [web.providers.deepseek] api_key. Use web_fetch for a specific URL if you do not want to configure search.")?;
        let count = r.count.clamp(1, 10);
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &[super::bearer(&key), ("Accept", "application/json".into())], &json!({"query": r.query, "count": count, "need_content": false}), c.timeout("deepseek")).map_err(|e| format!("DeepSeek API error: {e}"))?;
        if !resp.ok() {
            return Err(http::api_error("DeepSeek", &resp, Some(&key)));
        }
        let v = resp.json().map_err(|_| "DeepSeek API error: malformed JSON response".to_string())?;
        let rows = v.get("results").and_then(|x| x.as_array()).ok_or("DeepSeek API error: malformed JSON response")?;
        Ok(SearchOutput::Results(
            rows.iter()
                .take(count)
                .filter_map(|e| {
                    let url = http::s(e, "url");
                    let ok = url.len() <= 2048 && (url.starts_with("http://") || url.starts_with("https://")) && crate::web::ssrf::parse_url(&url).is_ok();
                    ok.then(|| Hit {
                        title: http::s(e, "title"),
                        snippet: Some(http::s(e, "summary")).filter(|x| !x.is_empty()).unwrap_or_else(|| http::s(e, "snippet")),
                        published: Some(http::s(e, "date")).filter(|x| !x.is_empty()),
                        site_name: Some(http::s(e, "site_name")).filter(|x| !x.is_empty()),
                        url,
                    })
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn search_and_limits() {
        let s = FakeServer::start(vec![("POST /v1/tools/search", 200, "application/json", json!({"results":[{"title":"D","url":"https://d.com","summary":"sum","site_name":"D Site","date":"2025-01-01"},{"title":"bad","url":"file:///etc/passwd"}]}).to_string())]);
        let c = wctx(json!({"providers":{"deepseek":{"base_url":s.url.clone()}}}), &[("DEEPSEEK_API_KEY", "sk-ds-test")]);
        let SearchOutput::Results(h) = DeepSeek.search(&c, &SearchRequest { query: "q site:x.com".into(), count: 20, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((h.len(), h[0].site_name.as_deref(), h[0].snippet.as_str()), (1, Some("D Site"), "sum"));
        assert_eq!(s.last().json(), json!({"query":"q site:x.com","count":10,"need_content":false}));
        assert!(DeepSeek.search(&c, &SearchRequest { query: "字".repeat(129), ..Default::default() }).unwrap_err().contains("128"));
        assert!(DeepSeek.filters().is_empty());
    }
}
