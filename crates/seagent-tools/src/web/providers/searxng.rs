//! SearXNG via a user-hosted instance (`/search?format=json`), search only.
//! Hermes `plugins/web/searxng` (SEARXNG_URL, score sort) + OpenClaw `extensions/searxng`
//! (SEARXNG_BASE_URL, categories/language, http:// only for private hosts, empty-category retry).

use super::{hit, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::ssrf;
use serde_json::Value;

pub struct Searxng;

const ENV: &[&str] = &["SEARXNG_BASE_URL", "SEARXNG_URL"];

fn base(c: &WebCtx) -> Option<String> {
    c.opt("searxng", "base_url").or_else(|| ENV.iter().find_map(|e| c.var(e))).map(|b| b.trim().trim_end_matches('/').to_string()).filter(|b| !b.is_empty())
}

fn search_url(base: &str) -> String {
    if base.ends_with("/search") {
        base.to_string()
    } else {
        format!("{base}/search")
    }
}

/// Plain http:// is only allowed for private / loopback instances (OpenClaw).
fn validate_base(base: &str) -> Result<(), String> {
    let u = ssrf::parse_url(base).map_err(|_| "SearXNG base URL must be a valid http:// or https:// URL.".to_string())?;
    if u.scheme == "http" {
        let private = match u.host.parse::<std::net::IpAddr>() {
            Ok(ip) => ssrf::is_private_ip(ip),
            Err(_) => ssrf::check_host(&u.host, false, &ssrf::SsrfPolicy::default()).is_err() || {
                use std::net::ToSocketAddrs;
                (u.host.as_str(), u.port).to_socket_addrs().map(|mut a| a.all(|a| ssrf::is_private_ip(a.ip()))).unwrap_or(false)
            },
        };
        if !private {
            return Err("SearXNG HTTP base URL must target a trusted private or loopback host. Use https:// for public hosts.".into());
        }
    }
    Ok(())
}

fn parse(body: &str, count: usize) -> Result<Vec<Hit>, String> {
    let v: Value = serde_json::from_str(body).map_err(|_| "SearXNG returned invalid JSON.".to_string())?;
    let mut rows: Vec<&Value> = v.get("results").and_then(|r| r.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
    // Hermes: SearXNG may return a score; highest first (stable for equal scores).
    rows.sort_by(|a, b| {
        let s = |x: &Value| x.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);
        s(b).partial_cmp(&s(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(rows
        .into_iter()
        .filter(|r| r.get("url").and_then(|u| u.as_str()).is_some() && r.get("title").and_then(|t| t.as_str()).is_some())
        .take(count)
        .map(|r| hit(&http::s(r, "title"), &http::s(r, "url"), &http::s(r, "content")))
        .collect())
}

impl WebProvider for Searxng {
    fn id(&self) -> &'static str {
        "searxng"
    }
    fn label(&self) -> &'static str {
        "SearXNG Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        base(c).is_some()
    }
    fn filters(&self) -> &'static [&'static str] {
        &["language"]
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        base(c).map(|b| search_url(&b)).unwrap_or_default()
    }
    fn signup_url(&self) -> &'static str {
        "https://docs.searxng.org/"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let base = base(c).ok_or("SearXNG base URL is not configured. Set SEARXNG_BASE_URL or [web.providers.searxng] base_url.")?;
        validate_base(&base)?;
        let categories = r.extra_str("categories").or_else(|| c.opt("searxng", "categories"));
        let language = r.language.clone().or_else(|| c.opt("searxng", "language"));
        let timeout = c.opt_u64("searxng", "timeout_seconds").unwrap_or(20);
        let run = |cats: Option<&str>| -> Result<Vec<Hit>, String> {
            c.check_cancel()?;
            let mut q = vec![("q", r.query.clone()), ("format", "json".to_string()), ("pageno", "1".to_string())];
            if let Some(cat) = cats {
                q.push(("categories", cat.to_string()));
            }
            if let Some(l) = &language {
                q.push(("language", l.clone()));
            }
            let resp = http::get(&search_url(&base), &q, &[("Accept", "application/json".into())], timeout).map_err(|e| format!("Could not reach SearXNG at {base}: {e}"))?;
            if !resp.ok() {
                return Err(format!("SearXNG search error ({}): {}", resp.status, resp.body.trim()));
            }
            if resp.body.len() > 1_000_000 {
                return Err(format!("SearXNG response incomplete after {} bytes.", resp.body.len()));
            }
            parse(&resp.body, r.count)
        };
        let mut hits = run(categories.as_deref())?;
        let retry = categories.as_deref().is_some_and(|cs| {
            let cs: Vec<String> = cs.split(',').map(|x| x.trim().to_ascii_lowercase()).filter(|x| !x.is_empty()).collect();
            !cs.is_empty() && !cs.iter().any(|x| x == "general")
        });
        if hits.is_empty() && retry {
            hits = run(Some("general"))?;
        }
        Ok(SearchOutput::Results(hits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};
    use serde_json::json;

    fn req(q: &str) -> SearchRequest {
        SearchRequest { query: q.into(), count: 2, ..Default::default() }
    }

    #[test]
    fn searches_sorted_by_score_and_capped() {
        let body = json!({"results":[{"title":"low","url":"https://a.com","content":"A","score":0.5},{"title":"high","url":"https://b.com","content":"B","score":2.0},{"title":"mid","url":"https://c.com","score":1.0},{"url":"https://notitle"}]}).to_string();
        let srv = FakeServer::start(vec![("GET /search", 200, "application/json", body)]);
        let c = wctx(json!({"providers":{"searxng":{"base_url":srv.url.clone(),"language":"de"}}}), &[]);
        assert!(Searxng.configured(&c));
        let SearchOutput::Results(h) = Searxng.search(&c, &req("rust")).unwrap() else { panic!() };
        assert_eq!(h.iter().map(|x| x.title.as_str()).collect::<Vec<_>>(), vec!["high", "mid"]);
        assert_eq!(h[0].site_name.as_deref(), Some("b.com"));
        let r = srv.last();
        assert_eq!((r.query("q").as_deref(), r.query("format").as_deref(), r.query("language").as_deref(), r.query("pageno").as_deref()), (Some("rust"), Some("json"), Some("de"), Some("1")));
    }

    #[test]
    fn empty_category_retries_general_and_env_url() {
        let srv = FakeServer::with(|r| {
            let body = if r.query("categories").as_deref() == Some("general") { json!({"results":[{"title":"g","url":"https://g.com"}]}) } else { json!({"results":[]}) };
            (200, "application/json".into(), body.to_string().into_bytes(), vec![])
        });
        let c = wctx(json!({}), &[("SEARXNG_URL", &format!("{}/", srv.url))]);
        let mut r = req("x");
        r.extra.insert("categories".into(), json!("news"));
        let SearchOutput::Results(h) = Searxng.search(&c, &r).unwrap() else { panic!() };
        assert_eq!(h[0].title, "g");
        assert_eq!(srv.requests().len(), 2);
        assert_eq!(Searxng.endpoint(&c), format!("{}/search", srv.url));
    }

    #[test]
    fn errors() {
        let c = wctx(json!({}), &[]);
        assert!(!Searxng.configured(&c));
        assert!(Searxng.search(&c, &req("x")).unwrap_err().contains("not configured"));
        let c = wctx(json!({"providers":{"searxng":{"base_url":"http://8.8.8.8"}}}), &[]);
        assert!(Searxng.search(&c, &req("x")).unwrap_err().contains("private or loopback"));
        let srv = FakeServer::start(vec![("GET /search", 500, "text/plain", "boom".into())]);
        let c = wctx(json!({"providers":{"searxng":{"base_url":srv.url.clone()}}}), &[]);
        assert_eq!(Searxng.search(&c, &req("x")).unwrap_err(), "SearXNG search error (500): boom");
        let srv = FakeServer::start(vec![("GET /search", 200, "application/json", "not json".into())]);
        let c = wctx(json!({"providers":{"searxng":{"base_url":srv.url.clone()}}}), &[]);
        assert_eq!(Searxng.search(&c, &req("x")).unwrap_err(), "SearXNG returned invalid JSON.");
    }
}
