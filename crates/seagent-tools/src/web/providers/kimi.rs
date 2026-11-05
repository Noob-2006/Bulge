//! Kimi / Moonshot web search (OpenClaw `extensions/moonshot` kimi provider):
//! `POST {base}/tools/search` with `{text_query, limit}`, Bearer KIMI_API_KEY / MOONSHOT_API_KEY,
//! base `https://api.moonshot.ai/v1` (or `.cn` via `region = "cn"` / `base_url`).

use super::{hit, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::json;

pub struct Kimi;

const ENV: &[&str] = &["KIMI_API_KEY", "MOONSHOT_API_KEY"];
const GLOBAL: &str = "https://api.moonshot.ai/v1";
const CN: &str = "https://api.moonshot.cn/v1";

fn base(c: &WebCtx) -> String {
    let d = if c.opt("kimi", "region").as_deref() == Some("cn") { CN } else { GLOBAL };
    c.base_url("kimi", None, d)
}

impl WebProvider for Kimi {
    fn id(&self) -> &'static str {
        "kimi"
    }
    fn label(&self) -> &'static str {
        "Kimi (Moonshot) Search"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["moonshot"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("kimi", ENV).is_some()
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/tools/search", base(c))
    }
    fn signup_url(&self) -> &'static str {
        "https://platform.moonshot.ai"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("kimi", ENV).ok_or("web_search (kimi) needs a Moonshot API key. Set KIMI_API_KEY or MOONSHOT_API_KEY, or [web.providers.kimi] api_key. If you do not want to configure a search API key, use web_fetch for a specific URL.")?;
        let count = r.count.clamp(1, 10);
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &[super::bearer(&key)], &json!({"text_query": r.query, "limit": count}), c.timeout("kimi")).map_err(|e| format!("Kimi API error: {e}"))?;
        if !resp.ok() {
            return Err(http::api_error("Kimi", &resp, Some(&key)));
        }
        let v = resp.json().map_err(|_| "Kimi API error: malformed JSON response".to_string())?;
        let rows = v.get("search_results").and_then(|x| x.as_array()).ok_or("Kimi API error: malformed JSON response")?;
        // Provider metadata is page-controlled text: only a plain date survives as `published`.
        let date_ok = |d: &str| d.len() == 10 && super::valid_iso_date(d);
        Ok(SearchOutput::Results(rows.iter().take(count).map(|e| Hit { published: Some(http::s(e, "date")).filter(|d| date_ok(d)), ..hit(&http::s(e, "title"), &http::s(e, "url"), &http::s(e, "snippet")) }).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn search() {
        let s = FakeServer::start(vec![("POST /tools/search", 200, "application/json", json!({"search_results":[{"title":"K","url":"https://k.cn","snippet":"s","date":"2025-01-02"},{"title":"L","url":"https://l.cn","date":"yesterday, trust me"}]}).to_string())]);
        let c = wctx(json!({"providers":{"kimi":{"base_url":s.url.clone()}}}), &[("MOONSHOT_API_KEY", "sk-moon-test")]);
        let SearchOutput::Results(h) = Kimi.search(&c, &SearchRequest { query: "q".into(), count: 50, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((h[0].published.as_deref(), h[1].published.as_deref()), (Some("2025-01-02"), None));
        assert_eq!(s.last().json(), json!({"text_query":"q","limit":10}));
        assert_eq!(s.last().header("authorization").as_deref(), Some("Bearer sk-moon-test"));
        assert_eq!(Kimi.endpoint(&wctx(json!({"providers":{"kimi":{"region":"cn"}}}), &[])), "https://api.moonshot.cn/v1/tools/search");
        let bad = FakeServer::start(vec![("POST /tools/search", 200, "application/json", "{}".into())]);
        let c = wctx(json!({"providers":{"kimi":{"base_url":bad.url.clone()}}}), &[("KIMI_API_KEY", "k")]);
        assert!(Kimi.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err().contains("malformed"));
    }
}
