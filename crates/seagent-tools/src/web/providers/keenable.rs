//! Keenable search + fetch (Hermes `plugins/web/keenable`): `POST /v1/search`, `GET /v1/fetch`,
//! optional Bearer key, mandatory `X-Keenable-Title` app id; keyless ring member.

use super::{hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::keyless;
use serde_json::json;

pub struct Keenable;

const ENV: &[&str] = &["KEENABLE_API_KEY"];
const DEFAULT_BASE: &str = "https://api.keenable.ai";

fn headers(key: &str) -> Vec<(&'static str, String)> {
    let mut h = vec![("X-Keenable-Title", "seagent".to_string())];
    if !key.is_empty() {
        h.push(super::bearer(key));
    }
    h
}

impl WebProvider for Keenable {
    fn id(&self) -> &'static str {
        "keenable"
    }
    fn label(&self) -> &'static str {
        "Keenable"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("keenable", ENV).is_some()
    }
    fn keyless(&self) -> bool {
        true
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        if self.routes_keyless(c) {
            format!("{}/v1/search/public", keyless::endpoint(c, "keenable"))
        } else {
            format!("{}/v1/search", c.base_url("keenable", None, DEFAULT_BASE))
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://keenable.ai"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("keenable", ENV);
        if keyless::use_keyless(c, "keenable", key.as_deref()) {
            return keyless::search_with_failover(c, "keenable", &r.query, r.count).1.map(SearchOutput::Results);
        }
        let key = key.unwrap_or_default();
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &headers(&key), &json!({"query": r.query, "max_results": r.count.clamp(1, 20)}), 30).map_err(|e| format!("Keenable search failed: {e}"))?;
        if resp.status >= 400 {
            let body = resp.body.trim();
            return Err(format!("Keenable search failed: {}", if body.is_empty() { format!("HTTP {}", resp.status) } else { if key.is_empty() { body.to_string() } else { body.replace(&key, "***") } }));
        }
        let v = resp.json().map_err(|e| format!("Keenable search failed: {e}"))?;
        Ok(SearchOutput::Results(v.get("results").and_then(|x| x.as_array()).into_iter().flatten().map(|e| hit(&http::s(e, "title"), &http::s(e, "url"), &[http::s(e, "snippet"), http::s(e, "description")].into_iter().find(|x| !x.is_empty()).unwrap_or_default())).collect()))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        let key = c.key("keenable", ENV);
        if keyless::use_keyless(c, "keenable", key.as_deref()) {
            return Ok(keyless::extract_with_failover(c, "keenable", urls));
        }
        let key = key.unwrap_or_default();
        let base = c.base_url("keenable", None, DEFAULT_BASE);
        Ok(urls
            .iter()
            .map(|u| {
                let r = http::get(&format!("{base}/v1/fetch"), &[("url", u.clone())], &headers(&key), 30).and_then(|r| if r.status >= 400 { Err(if r.body.trim().is_empty() { format!("HTTP {}", r.status) } else { r.body.trim().to_string() }) } else { r.json() });
                match r {
                    Ok(d) => {
                        let url = Some(http::s(&d, "url")).filter(|x| !x.is_empty()).unwrap_or_else(|| u.clone());
                        Page { source_url: Some(u.clone()), ..Page::ok(&url, &http::s(&d, "title"), &http::s(&d, "content")) }
                    }
                    Err(e) => Page::err(u, format!("Keenable extract failed: {e}")),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn keyed_search_and_fetch() {
        let s = FakeServer::start(vec![
            ("POST /v1/search", 200, "application/json", json!({"results":[{"title":"K","url":"https://k.com","description":"d"}]}).to_string()),
            ("GET /v1/fetch", 200, "application/json", json!({"url":"https://k.com/final","title":"K","content":"body"}).to_string()),
        ]);
        let c = wctx(json!({"providers":{"keenable":{"base_url":s.url.clone()}}}), &[("KEENABLE_API_KEY", "ke-test")]);
        let SearchOutput::Results(h) = Keenable.search(&c, &SearchRequest { query: "q".into(), count: 50, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h[0].snippet, "d");
        let q = s.last();
        assert_eq!((q.header("authorization").as_deref(), q.header("x-keenable-title").as_deref(), q.json()["max_results"].as_u64()), (Some("Bearer ke-test"), Some("seagent"), Some(20)));
        let p = Keenable.extract(&c, &["https://k.com".into()]).unwrap();
        assert_eq!((p[0].url.as_str(), p[0].source_url.as_deref(), p[0].content.as_str()), ("https://k.com/final", Some("https://k.com"), "body"));
        assert_eq!(s.last().query("url").as_deref(), Some("https://k.com"));
    }

    #[test]
    fn keyless_and_errors() {
        let ring = FakeServer::start(vec![("POST /v1/search/public", 200, "application/json", json!({"results":[{"title":"P","url":"https://p.com","snippet":"s"}]}).to_string())]);
        let c = wctx(json!({"backend":"keenable","providers":{"keenable":{"keyless_url":ring.url.clone()}}}), &[]);
        let SearchOutput::Results(h) = Keenable.search(&c, &SearchRequest { query: "q".into(), count: 2, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(h[0].url, "https://p.com");
        let bad = FakeServer::start(vec![("POST /v1/search", 403, "text/plain", "".into())]);
        let c = wctx(json!({"providers":{"keenable":{"base_url":bad.url.clone(),"api_key":"ke-test"}}}), &[]);
        assert_eq!(Keenable.search(&c, &SearchRequest { query: "q".into(), count: 2, ..Default::default() }).unwrap_err(), "Keenable search failed: HTTP 403");
    }
}
