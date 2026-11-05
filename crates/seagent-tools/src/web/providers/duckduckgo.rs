//! DuckDuckGo, keyless, search only: OpenClaw `extensions/duckduckgo` (HTML endpoint scrape,
//! `region` → `kl`, `safe_search` → `kp`, bot-challenge detection) with Hermes `ddgs`
//! semantics (alias `ddgs`, 30 s hard cap, its error texts). Never auto-selected: it is
//! the last keyless fallback, or picked explicitly.

use super::{hit, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::html::decode_entities;
use crate::web::http::{self, WebCtx};
use regex::Regex;
use std::sync::OnceLock;

pub struct DuckDuckGo;

const ENDPOINT: &str = "https://html.duckduckgo.com/html";
/// Hermes `_SEARCH_TIMEOUT_SECS`: the whole search, not one request.
const TIMEOUT: u64 = 30;

fn strip(html: &str) -> String {
    static RES: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (b, tags) = RES.get_or_init(|| (Regex::new(r"(?i)</?b\b[^>]*>").unwrap(), Regex::new(r"<[^>]+>").unwrap()));
    // Match highlights can sit inside words: drop them without adding whitespace.
    let s = b.replace_all(html, "");
    tags.replace_all(&s, " ").split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text(html: &str) -> String {
    decode_entities(&strip(html)).replace('\u{a0}', " ").replace('—', "--").replace('–', "-").replace('…', "...")
}

/// `//duckduckgo.com/l/?uddg=<target>` redirect links → the target.
pub fn decode_ddg_url(raw: &str) -> String {
    let q = raw.split_once('?').map(|(_, q)| q).unwrap_or("");
    q.split('&').find_map(|kv| kv.strip_prefix("uddg=")).map(crate::web::ssrf::percent_decode).filter(|u| !u.is_empty()).unwrap_or_else(|| raw.to_string())
}

pub fn is_bot_challenge(html: &str) -> bool {
    static RES: OnceLock<(Regex, Regex)> = OnceLock::new();
    let (result, challenge) = RES.get_or_init(|| (Regex::new(r#"(?i)class="[^"]*\bresult__a\b[^"]*""#).unwrap(), Regex::new(r#"(?i)g-recaptcha|are you a human|id="challenge-form"|name="challenge""#).unwrap()));
    !result.is_match(html) && challenge.is_match(html)
}

pub fn parse(html: &str, count: usize) -> Vec<Hit> {
    static RES: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (anchor, href, snippet) = RES.get_or_init(|| {
        (
            Regex::new(r#"(?is)<a\b([^>]*\bclass="[^"]*\bresult__a\b[^"]*"[^>]*)>(.*?)</a>"#).unwrap(),
            Regex::new(r#"(?i)\bhref="([^"]*)""#).unwrap(),
            Regex::new(r#"(?is)<a\b[^>]*\bclass="[^"]*\bresult__snippet\b[^"]*"[^>]*>(.*?)</a>"#).unwrap(),
        )
    });
    let matches: Vec<_> = anchor.captures_iter(html).collect();
    let mut out = Vec::new();
    for (i, m) in matches.iter().enumerate() {
        let whole = m.get(0).unwrap();
        // The snippet must belong to this result: search only up to the next result anchor.
        let scope_end = matches.get(i + 1).map(|n| n.get(0).unwrap().start()).unwrap_or(html.len());
        let tail = &html[whole.end()..scope_end];
        let raw_url = href.captures(&m[1]).map(|c| c[1].to_string()).unwrap_or_default();
        let url = decode_ddg_url(&decode_entities(&raw_url));
        let title = text(&m[2]);
        let snip = snippet.captures(tail).map(|c| text(&c[1])).unwrap_or_default();
        if !title.is_empty() && !url.is_empty() {
            out.push(hit(&title, &url, &snip));
            if out.len() >= count {
                break;
            }
        }
    }
    out
}

impl WebProvider for DuckDuckGo {
    fn id(&self) -> &'static str {
        "duckduckgo"
    }
    fn label(&self) -> &'static str {
        "DuckDuckGo"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["ddgs", "ddg"]
    }
    fn configured(&self, _c: &WebCtx) -> bool {
        true
    }
    fn auto_detect(&self) -> bool {
        false
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        c.base_url("duckduckgo", None, ENDPOINT)
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let mut q = vec![("q", r.query.clone())];
        if let Some(region) = c.opt("duckduckgo", "region") {
            q.push(("kl", region));
        }
        let kp = match c.opt("duckduckgo", "safe_search").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("strict") => "1",
            Some("off") => "-2",
            _ => "-1",
        };
        q.push(("kp", kp.into()));
        c.check_cancel().map_err(|_| "DuckDuckGo search interrupted".to_string())?;
        let ua = format!("seagent-duckduckgo/{} (+https://github.com/seagent)", env!("CARGO_PKG_VERSION"));
        let resp = http::get(&self.endpoint(c), &q, &[("User-Agent", ua)], c.opt_u64("duckduckgo", "timeout_seconds").unwrap_or(TIMEOUT)).map_err(|e| {
            if e.to_ascii_lowercase().contains("timeout") || e.to_ascii_lowercase().contains("timed out") {
                format!("DuckDuckGo search timed out after {TIMEOUT}s — DuckDuckGo may be rate-limiting or slow. Try again later or switch to a different search provider.")
            } else {
                format!("DuckDuckGo search failed: {e}")
            }
        })?;
        if !resp.ok() {
            return Err(format!("DuckDuckGo search error ({}): {}", resp.status, crate::util::truncate_str(resp.body.trim(), 2000)));
        }
        if is_bot_challenge(&resp.body) {
            return Err("DuckDuckGo returned a bot-detection challenge.".into());
        }
        Ok(SearchOutput::Results(parse(&resp.body, r.count.clamp(1, 30))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};
    use serde_json::json;

    const PAGE: &str = r#"<div class="result"><h2><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.rust-lang.org%2F&amp;rut=x">The <b>Rust</b> Programming&nbsp;Language</a></h2>
<a class="result__snippet" href="x">A language empowering <b>every</b>one &mdash; fast&hellip;</a></div>
<div class="result"><a class="result__a" href="https://doc.rust-lang.org/">Docs</a></div>
<div class="result"><a class="result__a" href="https://c.com/">C</a><a class="result__snippet">c snip</a></div>"#;

    #[test]
    fn parses_results_and_scopes_snippets() {
        let h = parse(PAGE, 5);
        assert_eq!(h.len(), 3);
        assert_eq!((h[0].title.as_str(), h[0].url.as_str()), ("The Rust Programming Language", "https://www.rust-lang.org/"));
        assert_eq!(h[0].snippet, "A language empowering everyone -- fast...");
        assert_eq!(h[1].snippet, "", "no snippet borrowed from the next result");
        assert_eq!(h[2].snippet, "c snip");
        assert_eq!(parse(PAGE, 1).len(), 1);
    }

    #[test]
    fn request_params_and_challenge() {
        let srv = FakeServer::start(vec![("GET /html", 200, "text/html", PAGE.into())]);
        let c = wctx(json!({"providers":{"duckduckgo":{"base_url":format!("{}/html",srv.url),"region":"tw-tzh","safe_search":"strict"}}}), &[]);
        let r = SearchRequest { query: "rust lang".into(), count: 2, ..Default::default() };
        let SearchOutput::Results(h) = DuckDuckGo.search(&c, &r).unwrap() else { panic!() };
        assert_eq!(h.len(), 2);
        let q = srv.last();
        assert_eq!((q.query("q").as_deref(), q.query("kl").as_deref(), q.query("kp").as_deref()), (Some("rust lang"), Some("tw-tzh"), Some("1")));
        assert!(q.header("user-agent").unwrap().starts_with("seagent-duckduckgo/"));
        let bot = FakeServer::start(vec![("GET /html", 200, "text/html", r#"<form id="challenge-form">are you a human</form>"#.into())]);
        let c = wctx(json!({"providers":{"duckduckgo":{"base_url":format!("{}/html",bot.url)}}}), &[]);
        assert_eq!(DuckDuckGo.search(&c, &r).unwrap_err(), "DuckDuckGo returned a bot-detection challenge.");
        assert_eq!(bot.last().query("kp").as_deref(), Some("-1"), "moderate by default");
        let down = FakeServer::start(vec![("GET /html", 503, "text/plain", "busy".into())]);
        let c = wctx(json!({"providers":{"duckduckgo":{"base_url":format!("{}/html",down.url)}}}), &[]);
        assert_eq!(DuckDuckGo.search(&c, &r).unwrap_err(), "DuckDuckGo search error (503): busy");
        assert!(DuckDuckGo.configured(&c) && !DuckDuckGo.auto_detect());
        assert_eq!(decode_ddg_url("https://direct.com/"), "https://direct.com/");
    }
}
