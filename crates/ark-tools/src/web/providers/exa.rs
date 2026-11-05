//! Exa search + contents. Hermes `plugins/web/exa` (exa-py SDK, ported to the documented REST
//! API: `POST /search` with highlights, `POST /contents` with text; keyless ring without a key)
//! + OpenClaw `extensions/exa` (search `type`, `contents` options, freshness → startPublishedDate,
//!   date_after / date_before, `x-exa-integration`).

use super::{hit, Hit, Page, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::keyless;
use serde_json::{json, Map, Value};

pub struct Exa;

const ENV: &[&str] = &["EXA_API_KEY"];
const DEFAULT_BASE: &str = "https://api.exa.ai";
const TYPES: &[&str] = &["auto", "neural", "fast", "deep", "deep-reasoning", "instant"];
const MAX_COUNT: usize = 100;

fn base(c: &WebCtx) -> Result<String, String> {
    let b = c.base_url("exa", None, DEFAULT_BASE);
    let lower = b.to_ascii_lowercase();
    if b.contains("://") && !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!("[web.providers.exa] base_url must be a valid http(s) URL. Got: {b}"));
    }
    let b = if b.contains("://") { b } else { format!("https://{b}") };
    Ok(b.trim_end_matches("/search").to_string())
}

/// UTC ISO timestamp `days_back` days (or one calendar month / year) before now.
pub fn freshness_start(freshness: &str, now_secs: u64) -> Option<String> {
    let day = 86_400u64;
    let (date_days, tod) = ((now_secs / day) as i64, now_secs % day);
    let clock = format!("T{:02}:{:02}:{:02}.000Z", tod / 3600, tod % 3600 / 60, tod % 60);
    let shift = |d: i64| format!("{}{clock}", super::brave::civil(d));
    match freshness {
        "day" => Some(shift(date_days - 1)),
        "week" => Some(shift(date_days - 7)),
        "month" | "year" => {
            let today = super::brave::civil(date_days);
            let (y, m, d): (i64, i64, i64) = (today[..4].parse().ok()?, today[5..7].parse().ok()?, today[8..].parse().ok()?);
            let (y, m) = if freshness == "year" { (y - 1, m) } else if m == 1 { (y - 1, 12) } else { (y, m - 1) };
            let mut dd = d;
            while dd > 28 && !super::valid_iso_date(&format!("{y:04}-{m:02}-{dd:02}")) {
                dd -= 1;
            }
            Some(format!("{y:04}-{m:02}-{dd:02}{clock}"))
        }
        _ => None,
    }
}

/// OpenClaw `parseExaContents`: only text / highlights / summary with their known fields.
pub fn parse_contents(raw: &Value) -> Result<Value, String> {
    let Some(o) = raw.as_object() else { return Err("contents must be an object with optional text, highlights, and summary fields.".into()) };
    let fields: &[(&str, &[&str])] = &[("text", &["maxCharacters"]), ("highlights", &["maxCharacters", "query", "numSentences", "highlightsPerUrl"]), ("summary", &["query"])];
    for k in o.keys() {
        if !fields.iter().any(|(s, _)| s == k) {
            return Err(format!("contents has unknown field \"{k}\". Only \"text\", \"highlights\", and \"summary\" are allowed."));
        }
    }
    let mut out = Map::new();
    for (section, allowed) in fields {
        let Some(v) = o.get(*section) else { continue };
        if v.is_boolean() {
            out.insert(section.to_string(), v.clone());
            continue;
        }
        let Some(opt) = v.as_object() else { return Err(format!("contents.{section} must be a boolean or an object.")) };
        for k in opt.keys() {
            if !allowed.contains(&k.as_str()) {
                let hint = if *section == "highlights" { "Allowed fields are \"maxCharacters\", \"query\", \"numSentences\", and \"highlightsPerUrl\".".to_string() } else { format!("Only \"{}\" is allowed.", allowed[0]) };
                return Err(format!("contents.{section} has unknown field \"{k}\". {hint}"));
            }
        }
        for (k, val) in opt {
            if k == "query" {
                if !val.is_string() {
                    return Err(format!("contents.{section}.query must be a string."));
                }
            } else if !val.as_u64().is_some_and(|n| n > 0) {
                return Err(format!("contents.{section}.{k} must be a positive integer."));
            }
        }
        out.insert(section.to_string(), v.clone());
    }
    Ok(Value::Object(out))
}

fn map(v: &Value, n: usize) -> Vec<Hit> {
    v.get("results").and_then(|r| r.as_array()).into_iter().flatten().filter(|r| r.is_object()).take(n).map(|e| {
        let hl: Vec<&str> = e.get("highlights").and_then(|h| h.as_array()).into_iter().flatten().filter_map(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).collect();
        let desc = if hl.is_empty() { [http::s(e, "summary"), http::s(e, "text")].into_iter().find(|x| !x.is_empty()).unwrap_or_default() } else { hl.join("\n") };
        Hit { published: Some(http::s(e, "publishedDate")).filter(|p| !p.is_empty()), ..hit(&http::s(e, "title"), &http::s(e, "url"), &desc) }
    })
    .collect()
}

fn post(c: &WebCtx, path: &str, key: &str, body: &Value) -> Result<Value, String> {
    c.check_cancel()?;
    let h = [("Accept", "application/json".to_string()), ("x-api-key", key.to_string()), ("x-exa-integration", "ark".to_string())];
    let r = http::post_json(&format!("{}{path}", base(c)?), &h, body, c.timeout("exa")).map_err(|e| format!("Exa {path} failed: {e}"))?;
    if !r.ok() {
        return Err(http::api_error("Exa", &r, Some(key)));
    }
    r.json().map_err(|_| "Exa API returned malformed JSON".to_string())
}

impl WebProvider for Exa {
    fn id(&self) -> &'static str {
        "exa"
    }
    fn label(&self) -> &'static str {
        "Exa Search"
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("exa", ENV).is_some()
    }
    fn keyless(&self) -> bool {
        true
    }
    fn filters(&self) -> &'static [&'static str] {
        &["freshness", "date_after", "date_before"]
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        if self.routes_keyless(c) {
            keyless::endpoint(c, "exa")
        } else {
            format!("{}/search", base(c).unwrap_or_default())
        }
    }
    fn signup_url(&self) -> &'static str {
        "https://exa.ai"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("exa", ENV);
        if keyless::use_keyless(c, "exa", key.as_deref()) {
            return keyless::search_with_failover(c, "exa", &r.query, r.count).1.map(SearchOutput::Results);
        }
        let key = key.ok_or("web_search (exa) needs an Exa API key. Set EXA_API_KEY or [web.providers.exa] api_key. Get one at https://exa.ai")?;
        let fresh = match r.freshness.as_deref() {
            Some(f) => Some(["day", "week", "month", "year"].into_iter().find(|x| x.eq_ignore_ascii_case(f.trim())).ok_or("freshness must be one of \"day\", \"week\", \"month\", or \"year\".")?),
            None => None,
        };
        if fresh.is_some() && (r.date_after.is_some() || r.date_before.is_some()) {
            return Err("freshness cannot be combined with date_after or date_before. Use one time-filter mode.".into());
        }
        let t = super::parse_time_filters(&SearchRequest { freshness: None, ..r.clone() }, "exa").map_err(|e| e.replace("must be before", "must be earlier than or equal to"))?;
        let contents = match r.extra.get("contents") {
            Some(v) => Some(parse_contents(v)?).filter(|v| v.as_object().is_some_and(|o| !o.is_empty())),
            None => None,
        };
        let typ = r.extra_str("type").filter(|x| TYPES.contains(&x.as_str())).unwrap_or_else(|| "auto".into());
        let count = r.count.clamp(1, MAX_COUNT);
        let mut body = json!({"query": r.query, "numResults": count, "type": typ, "contents": contents.unwrap_or(json!({"highlights": true}))});
        if let Some(a) = &t.date_after {
            body["startPublishedDate"] = json!(a);
        } else if let Some(f) = fresh {
            body["startPublishedDate"] = json!(freshness_start(f, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
        }
        if let Some(b) = &t.date_before {
            body["endPublishedDate"] = json!(b);
        }
        Ok(SearchOutput::Results(map(&post(c, "/search", &key, &body)?, count)))
    }
    fn supports_extract(&self) -> bool {
        true
    }
    fn extract(&self, c: &WebCtx, urls: &[String]) -> Result<Vec<Page>, String> {
        let key = c.key("exa", ENV);
        if keyless::use_keyless(c, "exa", key.as_deref()) {
            return Ok(keyless::extract_with_failover(c, "exa", urls));
        }
        let key = key.ok_or("EXA_API_KEY environment variable not set. Get your API key at https://exa.ai")?;
        let v = post(c, "/contents", &key, &json!({"urls": urls, "text": true}))?;
        Ok(v.get("results").and_then(|r| r.as_array()).into_iter().flatten().map(|r| Page::ok(&http::s(r, "url"), &http::s(r, "title"), &http::s(r, "text"))).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    fn srv() -> FakeServer {
        FakeServer::start(vec![
            ("POST /search", 200, "application/json", json!({"results":[{"title":"A","url":"https://a.com","highlights":[" h1 ","h2"],"publishedDate":"2025-01-01"},{"title":"B","url":"https://b.com","summary":"sum"}]}).to_string()),
            ("POST /contents", 200, "application/json", json!({"results":[{"url":"https://a.com","title":"A","text":"full text"}]}).to_string()),
        ])
    }

    #[test]
    fn search_body_and_mapping() {
        let s = srv();
        let c = wctx(json!({"providers":{"exa":{"base_url":format!("{}/search",s.url)}}}), &[("EXA_API_KEY", "exa_test")]);
        let mut r = SearchRequest { query: "q".into(), count: 3, date_after: Some("2025-01-01".into()), ..Default::default() };
        r.extra.insert("type".into(), json!("neural"));
        r.extra.insert("contents".into(), json!({"text":{"maxCharacters":500}}));
        let SearchOutput::Results(h) = Exa.search(&c, &r).unwrap() else { panic!() };
        assert_eq!((h[0].snippet.as_str(), h[0].published.as_deref(), h[1].snippet.as_str()), ("h1\nh2", Some("2025-01-01"), "sum"));
        let q = s.last();
        assert_eq!((q.header("x-api-key").as_deref(), q.header("x-exa-integration").as_deref()), (Some("exa_test"), Some("ark")));
        let b = q.json();
        assert_eq!((b["type"].as_str(), b["numResults"].as_u64(), b["startPublishedDate"].as_str(), b["contents"]["text"]["maxCharacters"].as_u64()), (Some("neural"), Some(3), Some("2025-01-01"), Some(500)));
        let r = SearchRequest { query: "q".into(), count: 3, freshness: Some("week".into()), ..Default::default() };
        Exa.search(&c, &r).unwrap();
        let b = s.last().json();
        assert_eq!(b["contents"], json!({"highlights":true}));
        assert!(b["startPublishedDate"].as_str().unwrap().ends_with("Z"));
        let p = Exa.extract(&c, &["https://a.com".into()]).unwrap();
        assert_eq!(p[0].content, "full text");
        assert_eq!(s.last().json()["text"], true);
    }

    #[test]
    fn validation() {
        assert!(parse_contents(&json!({"bogus":true})).unwrap_err().contains("unknown field \"bogus\""));
        assert!(parse_contents(&json!({"highlights":{"numSentences":0}})).unwrap_err().contains("positive integer"));
        assert!(parse_contents(&json!({"summary":{"query":1}})).unwrap_err().contains("must be a string"));
        assert!(parse_contents(&json!({"text":{"x":1}})).unwrap_err().contains("Only \"maxCharacters\""));
        assert_eq!(freshness_start("day", 86_400 * 2 + 3661).unwrap(), "1970-01-02T01:01:01.000Z");
        assert_eq!(freshness_start("month", 86_400 * 89).unwrap(), "1970-02-28T00:00:00.000Z", "Mar 31 → Feb 28");
        assert_eq!(freshness_start("year", 86_400 * 400).unwrap(), "1970-02-05T00:00:00.000Z");
        let c = wctx(json!({"keyless_fallback":false}), &[]);
        assert!(Exa.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err().contains("needs an Exa API key"));
        let c = wctx(json!({}), &[("EXA_API_KEY", "k")]);
        let r = SearchRequest { query: "q".into(), count: 1, freshness: Some("day".into()), date_before: Some("2025-01-01".into()), ..Default::default() };
        assert!(Exa.search(&c, &r).unwrap_err().contains("cannot be combined"));
        let r = SearchRequest { query: "q".into(), count: 1, freshness: Some("decade".into()), ..Default::default() };
        assert!(Exa.search(&c, &r).unwrap_err().contains("freshness must be"));
        let c = wctx(json!({"providers":{"exa":{"base_url":"ftp://x"}}}), &[("EXA_API_KEY", "k")]);
        assert!(Exa.search(&c, &SearchRequest { query: "q".into(), count: 1, ..Default::default() }).unwrap_err().contains("valid http(s) URL"));
    }
}
