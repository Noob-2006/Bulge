//! MiniMax Token-Plan search (OpenClaw `extensions/minimax`): `POST /v1/coding_plan/search`
//! `{q}` on api.minimax.io (global) or api.minimaxi.com (`region = "cn"` or a minimaxi.com
//! MINIMAX_API_HOST); organic results; `base_resp.status_code != 0` is an error.

use super::{hit, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::json;

pub struct Minimax;

const ENV: &[&str] = &["MINIMAX_CODE_PLAN_KEY", "MINIMAX_CODING_API_KEY", "MINIMAX_OAUTH_TOKEN", "MINIMAX_API_KEY"];
const GLOBAL: &str = "https://api.minimax.io";
const CN: &str = "https://api.minimaxi.com";

fn base(c: &WebCtx) -> String {
    let cn = match c.opt("minimax", "region") {
        Some(r) => r == "cn",
        None => c.var("MINIMAX_API_HOST").is_some_and(|h| h.contains("minimaxi.com")),
    };
    c.base_url("minimax", None, if cn { CN } else { GLOBAL })
}

impl WebProvider for Minimax {
    fn id(&self) -> &'static str {
        "minimax"
    }
    fn label(&self) -> &'static str {
        "MiniMax Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("minimax", ENV).is_some()
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/v1/coding_plan/search", base(c))
    }
    fn signup_url(&self) -> &'static str {
        "https://platform.minimax.io"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("minimax", ENV).ok_or("web_search (minimax) needs a MiniMax Token Plan key or OAuth token. Set MINIMAX_CODE_PLAN_KEY, MINIMAX_CODING_API_KEY, MINIMAX_OAUTH_TOKEN, or MINIMAX_API_KEY, or [web.providers.minimax] api_key.")?;
        let count = r.count.clamp(1, 10);
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &[super::bearer(&key), ("Accept", "application/json".into())], &json!({"q": r.query}), c.timeout("minimax")).map_err(|e| format!("MiniMax Search API error: {e}"))?;
        if !resp.ok() {
            return Err(http::api_error("MiniMax Search", &resp, Some(&key)));
        }
        let v = resp.json()?;
        if let Some(code) = v.pointer("/base_resp/status_code").and_then(|x| x.as_i64()).filter(|c| *c != 0) {
            let msg = v.pointer("/base_resp/status_msg").and_then(|x| x.as_str()).filter(|m| !m.is_empty()).unwrap_or("unknown error");
            return Err(format!("MiniMax Search API error ({code}): {msg}"));
        }
        Ok(SearchOutput::Results(v.get("organic").and_then(|o| o.as_array()).into_iter().flatten().take(count).map(|e| Hit { published: Some(http::s(e, "date")).filter(|d| !d.is_empty()), ..hit(&http::s(e, "title"), &http::s(e, "link"), &http::s(e, "snippet")) }).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn search_and_status_errors() {
        let s = FakeServer::start(vec![("POST /v1/coding_plan/search", 200, "application/json", json!({"organic":[{"title":"M","link":"https://m.com","snippet":"s","date":"2025-02-02"}],"related_searches":[{"query":"x"}],"base_resp":{"status_code":0}}).to_string())]);
        let c = wctx(json!({"providers":{"minimax":{"base_url":s.url.clone()}}}), &[("MINIMAX_CODE_PLAN_KEY", "mm-test")]);
        let SearchOutput::Results(h) = Minimax.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((h[0].url.as_str(), h[0].published.as_deref()), ("https://m.com", Some("2025-02-02")));
        assert_eq!(s.last().json(), json!({"q":"q"}));
        let e = FakeServer::start(vec![("POST /v1/coding_plan/search", 200, "application/json", json!({"base_resp":{"status_code":1004,"status_msg":"invalid key"}}).to_string())]);
        let c = wctx(json!({"providers":{"minimax":{"base_url":e.url.clone()}}}), &[("MINIMAX_API_KEY", "k")]);
        assert_eq!(Minimax.search(&c, &SearchRequest { query: "q".into(), count: 3, ..Default::default() }).unwrap_err(), "MiniMax Search API error (1004): invalid key");
        assert_eq!(Minimax.endpoint(&wctx(json!({}), &[("MINIMAX_API_HOST", "https://api.minimaxi.com")])), "https://api.minimaxi.com/v1/coding_plan/search");
    }
}
