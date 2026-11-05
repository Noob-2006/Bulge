//! Brave Search. Hermes `plugins/web/brave_free` (BRAVE_SEARCH_API_KEY, count ≤ 20) +
//! OpenClaw `extensions/brave` (BRAVE_API_KEY, `web` and `llm-context` modes, country /
//! search_lang / ui_lang normalisation with swapped-field detection, freshness and date ranges).

use super::{hit, parse_time_filters, Hit, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::ssrf;
use serde_json::Value;

pub struct Brave;

const ENV: &[&str] = &["BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"];
const DEFAULT_BASE: &str = "https://api.search.brave.com";

/// Brave-supported `country` codes (unknown ones become `ALL`, as upstream).
const COUNTRIES: &[&str] = &[
    "AR", "AU", "AT", "BE", "BR", "CA", "CL", "DK", "FI", "FR", "DE", "GR", "HK", "IN", "ID", "IT", "JP", "KR", "MY", "MX", "NL", "NZ", "NO", "CN", "PL", "PT", "PH", "RU", "SA", "ZA", "ES", "SE", "CH", "TW", "TR", "GB", "US", "ALL",
];
const SEARCH_LANGS: &[&str] = &[
    "ar", "eu", "bn", "bg", "ca", "zh-hans", "zh-hant", "hr", "cs", "da", "nl", "en", "en-gb", "et", "fi", "fr", "gl", "de", "el", "gu", "he", "hi", "hu", "is", "it", "jp", "kn", "ko", "lv", "lt", "ms", "ml", "mr", "nb", "pl", "pt-br", "pt-pt", "pa",
    "ro", "ru", "sr", "sk", "sl", "es", "sv", "ta", "te", "th", "tr", "uk", "vi",
];
const LANG_ALIASES: &[(&str, &str)] = &[("ja", "jp"), ("zh", "zh-hans"), ("zh-cn", "zh-hans"), ("zh-hk", "zh-hant"), ("zh-sg", "zh-hans"), ("zh-tw", "zh-hant")];

pub fn normalize_country(v: &str) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        return None;
    }
    let up = t.to_ascii_uppercase();
    Some(if COUNTRIES.contains(&up.as_str()) { up } else { "ALL".into() })
}

fn search_lang(v: &str) -> Option<String> {
    let l = v.trim().to_ascii_lowercase();
    let c = LANG_ALIASES.iter().find(|(a, _)| *a == l).map(|(_, b)| b.to_string()).unwrap_or(l);
    SEARCH_LANGS.contains(&c.as_str()).then_some(c)
}

fn ui_lang(v: &str) -> Option<String> {
    let (a, b) = v.trim().split_once('-')?;
    (a.len() == 2 && b.len() == 2 && a.chars().chain(b.chars()).all(|c| c.is_ascii_alphabetic())).then(|| format!("{}-{}", a.to_ascii_lowercase(), b.to_ascii_uppercase()))
}

/// `(search_lang, ui_lang)`; a swapped pair (`en-US` as search_lang, `en` as ui_lang) is fixed.
pub fn normalize_langs(sl: Option<&str>, ul: Option<&str>) -> Result<(Option<String>, Option<String>), String> {
    let (mut s, mut u) = (sl.map(str::trim).filter(|x| !x.is_empty()), ul.map(str::trim).filter(|x| !x.is_empty()));
    if s.is_some_and(|x| ui_lang(x).is_some()) && u.is_some_and(|x| search_lang(x).is_some()) {
        std::mem::swap(&mut s, &mut u);
    }
    let sv = match s {
        Some(x) => Some(search_lang(x).ok_or("search_lang must be a Brave-supported language code like 'en', 'en-gb', 'zh-hans', or 'zh-hant'.")?),
        None => None,
    };
    let uv = match u {
        Some(x) => Some(ui_lang(x).ok_or("ui_lang must be a language-region locale like 'en-US'.")?),
        None => None,
    };
    Ok((sv, uv))
}

fn today() -> String {
    let days = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) / 86_400) as i64;
    civil(days)
}

/// Days since 1970-01-01 → `YYYY-MM-DD` (Howard Hinnant's civil_from_days).
pub fn civil(z: i64) -> String {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn base(c: &WebCtx) -> String {
    c.base_url("brave", None, DEFAULT_BASE)
}

fn mode(c: &WebCtx) -> &'static str {
    match c.opt("brave", "mode").map(|m| m.to_ascii_lowercase()).as_deref() {
        Some("llm-context" | "llm_context" | "llmcontext") => "llm-context",
        _ => "web",
    }
}

fn validate_base(b: &str) -> Result<(), String> {
    let u = ssrf::parse_url(b).map_err(|_| "Brave Search base URL must be a valid http:// or https:// URL.".to_string())?;
    if u.scheme == "http" {
        let private = u.host.parse::<std::net::IpAddr>().map(ssrf::is_private_ip).unwrap_or_else(|_| ssrf::check_host(&u.host, false, &ssrf::SsrfPolicy::default()).is_err());
        if !private {
            return Err("Brave Search HTTP base URL must target a trusted private or loopback host. Use https:// for public hosts.".into());
        }
    }
    Ok(())
}

fn map_web(v: &Value, n: usize) -> Vec<Hit> {
    v.pointer("/web/results").and_then(|r| r.as_array()).into_iter().flatten().take(n).map(|e| Hit { published: Some(http::s(e, "page_age")).filter(|x| !x.is_empty()), ..hit(&http::s(e, "title"), &http::s(e, "url"), &http::s(e, "description")) }).collect()
}

/// LLM Context grounding rows; `published` only from the absolute `age` slots (3 = timestamp, 1 = date).
fn map_llm(v: &Value, n: usize) -> Vec<Hit> {
    v.pointer("/grounding/generic").and_then(|r| r.as_array()).into_iter().flatten().take(n).map(|e| {
        let url = http::s(e, "url");
        let snippets: Vec<&str> = e.get("snippets").and_then(|s| s.as_array()).into_iter().flatten().filter_map(|s| s.as_str()).filter(|s| !s.is_empty()).collect();
        let age = v.get("sources").and_then(|s| s.get(&url)).and_then(|s| s.get("age")).and_then(|a| a.as_array());
        let published = age.and_then(|a| a.get(3).or(a.get(1))).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(str::to_string);
        Hit { published, ..hit(&http::s(e, "title"), &url, &snippets.join("\n")) }
    })
    .collect()
}

impl WebProvider for Brave {
    fn id(&self) -> &'static str {
        "brave"
    }
    fn label(&self) -> &'static str {
        "Brave Search"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["brave-free"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("brave", ENV).is_some()
    }
    fn filters(&self) -> &'static [&'static str] {
        &["country", "language", "freshness", "date_after", "date_before", "search_lang", "ui_lang"]
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}{}", base(c), if mode(c) == "llm-context" { "/res/v1/llm/context" } else { "/res/v1/web/search" })
    }
    fn signup_url(&self) -> &'static str {
        "https://brave.com/search/api/"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("brave", ENV).ok_or("web_search (brave) needs a Brave Search API key. Set BRAVE_API_KEY (or BRAVE_SEARCH_API_KEY), or [web.providers.brave] api_key. If you do not want to configure a search API key, use web_fetch for a specific URL.")?;
        let b = base(c);
        validate_base(&b)?;
        let m = mode(c);
        let country = r.country.as_deref().and_then(normalize_country);
        let (sl, ul) = normalize_langs(r.search_lang.as_deref().or(r.language.as_deref()), r.ui_lang.as_deref())?;
        if ul.is_some() && m == "llm-context" {
            return Err("ui_lang is not supported by Brave llm-context mode. Remove ui_lang or use Brave web mode for locale-based UI hints.".into());
        }
        let t = parse_time_filters(r, "brave")?;
        let today = today();
        if m == "llm-context" {
            if t.date_after.as_deref().is_some_and(|a| t.date_before.is_none() && a > today.as_str()) {
                return Err("date_after cannot be in the future for Brave llm-context mode.".into());
            }
            if t.date_before.is_some() && t.date_after.is_none() {
                return Err("Brave llm-context mode requires date_after when date_before is set. Use a bounded date range or freshness.".into());
            }
        }
        let count = r.count.clamp(1, 20);
        let mut q = vec![("q", r.query.clone())];
        if let Some(x) = country {
            q.push(("country", x));
        }
        if let Some(x) = &sl {
            q.push(("search_lang", x.clone()));
        }
        let fresh = match (&t.freshness, &t.date_after, &t.date_before) {
            (Some(f), _, _) => Some(f.clone()),
            (None, Some(a), Some(b)) => Some(format!("{a}to{b}")),
            (None, Some(a), None) => Some(format!("{a}to{today}")),
            (None, None, Some(b)) if m == "web" => Some(format!("1970-01-01to{b}")),
            _ => None,
        };
        if let Some(f) = fresh {
            q.push(("freshness", f));
        }
        if m == "web" {
            q.push(("count", count.to_string()));
            if let Some(u) = ul {
                q.push(("ui_lang", u));
            }
        }
        c.check_cancel()?;
        let resp = http::get(&self.endpoint(c), &q, &[("Accept", "application/json".into()), ("X-Subscription-Token", key.clone())], c.timeout("brave")).map_err(|e| format!("Could not reach Brave Search: {e}"))?;
        let label = if m == "llm-context" { "Brave LLM Context" } else { "Brave Search" };
        if !resp.ok() {
            return Err(http::api_error(label, &resp, Some(&key)));
        }
        let v = resp.json().map_err(|_| format!("Could not parse {label} response as JSON"))?;
        Ok(SearchOutput::Results(if m == "llm-context" { map_llm(&v, count) } else { map_web(&v, count) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};
    use serde_json::json;

    fn req() -> SearchRequest {
        SearchRequest { query: "rust".into(), count: 2, ..Default::default() }
    }

    #[test]
    fn normalisers() {
        assert_eq!(normalize_country("tw").as_deref(), Some("TW"));
        assert_eq!(normalize_country("XX").as_deref(), Some("ALL"));
        assert_eq!(normalize_langs(Some("zh-TW"), None).unwrap().0.as_deref(), Some("zh-hant"));
        assert_eq!(normalize_langs(Some("en-us"), Some("ja")).unwrap(), (Some("jp".into()), Some("en-US".into())), "swapped fields");
        assert!(normalize_langs(Some("klingon"), None).unwrap_err().contains("search_lang"));
        assert!(normalize_langs(None, Some("english")).unwrap_err().contains("ui_lang"));
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(20_000), "2024-10-04");
    }

    #[test]
    fn web_mode_request_and_mapping() {
        let body = json!({"web":{"results":[{"title":"A","url":"https://a.com/x","description":"da","page_age":"2024-05-01T00:00:00"},{"title":"B","url":"https://b.com","description":"db"},{"title":"C","url":"https://c.com"}]}}).to_string();
        let srv = FakeServer::start(vec![("GET /res/v1/web/search", 200, "application/json", body)]);
        let c = wctx(json!({"providers":{"brave":{"base_url":srv.url.clone()}}}), &[("BRAVE_SEARCH_API_KEY", "bk")]);
        assert!(Brave.configured(&c));
        let mut r = req();
        r.country = Some("de".into());
        r.ui_lang = Some("de-de".into());
        r.date_after = Some("2024-01-01".into());
        r.date_before = Some("2024-02-01".into());
        let SearchOutput::Results(h) = Brave.search(&c, &r).unwrap() else { panic!() };
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].published.as_deref(), h[0].site_name.as_deref(), h[1].published.as_deref()), (Some("2024-05-01T00:00:00"), Some("a.com"), None));
        let q = srv.last();
        assert_eq!(q.header("x-subscription-token").as_deref(), Some("bk"));
        assert_eq!((q.query("country").as_deref(), q.query("ui_lang").as_deref(), q.query("count").as_deref(), q.query("freshness").as_deref()), (Some("DE"), Some("de-DE"), Some("2"), Some("2024-01-01to2024-02-01")));
        let mut r = req();
        r.freshness = Some("week".into());
        Brave.search(&c, &r).unwrap();
        assert_eq!(srv.last().query("freshness").as_deref(), Some("pw"));
        let mut r = req();
        r.date_before = Some("2020-01-01".into());
        Brave.search(&c, &r).unwrap();
        assert_eq!(srv.last().query("freshness").as_deref(), Some("1970-01-01to2020-01-01"));
    }

    #[test]
    fn llm_context_mode() {
        let body = json!({"grounding":{"generic":[{"url":"https://a.com","title":"A","snippets":["s1","","s2"]}]},"sources":{"https://a.com":{"age":["Monday","2024-01-02","2 days ago","2024-01-02T10:00:00"]}}}).to_string();
        let srv = FakeServer::start(vec![("GET /res/v1/llm/context", 200, "application/json", body)]);
        let c = wctx(json!({"providers":{"brave":{"base_url":srv.url.clone(),"mode":"llm-context","api_key":"k"}}}), &[]);
        let SearchOutput::Results(h) = Brave.search(&c, &req()).unwrap() else { panic!() };
        assert_eq!((h[0].snippet.as_str(), h[0].published.as_deref()), ("s1\ns2", Some("2024-01-02T10:00:00")));
        assert!(srv.last().query("count").is_none());
        let mut r = req();
        r.ui_lang = Some("en-US".into());
        assert!(Brave.search(&c, &r).unwrap_err().contains("llm-context"));
        let mut r = req();
        r.date_before = Some("2024-01-01".into());
        assert!(Brave.search(&c, &r).unwrap_err().contains("requires date_after"));
        let mut r = req();
        r.date_after = Some("2999-01-01".into());
        assert!(Brave.search(&c, &r).unwrap_err().contains("future"));
    }

    #[test]
    fn errors() {
        let c = wctx(json!({}), &[]);
        assert!(!Brave.configured(&c) && Brave.search(&c, &req()).unwrap_err().contains("needs a Brave Search API key"));
        let srv = FakeServer::start(vec![("GET /res/v1/web/search", 429, "application/json", r#"{"error":"rate limited for key bk-test"}"#.into())]);
        let c = wctx(json!({"providers":{"brave":{"base_url":srv.url.clone()}}}), &[("BRAVE_API_KEY", "bk-test")]);
        assert_eq!(Brave.search(&c, &req()).unwrap_err(), r#"Brave Search API error (429): {"error":"rate limited for key ***"}"#);
        let c = wctx(json!({"providers":{"brave":{"base_url":"http://8.8.8.8"}}}), &[("BRAVE_API_KEY", "bk")]);
        assert!(Brave.search(&c, &req()).unwrap_err().contains("trusted private"));
        assert_eq!(Brave.endpoint(&wctx(json!({}), &[])), "https://api.search.brave.com/res/v1/web/search");
    }
}
