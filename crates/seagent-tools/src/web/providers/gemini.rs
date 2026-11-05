//! Gemini with Google Search grounding (OpenClaw `extensions/google` gemini web-search provider):
//! `POST {base}/models/{model}:generateContent` with `tools: [{google_search: {timeRangeFilter?}}]`,
//! `x-goog-api-key`; answer from candidate parts, citations from grounding chunks with their
//! vertexaisearch redirect links resolved (HEAD, SSRF-guarded, batches of 10).

use super::{parse_time_filters, Citation, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use crate::web::ssrf;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct Gemini;

const ENV: &[&str] = &["GEMINI_API_KEY"];
const DEFAULT_BASE: &str = "https://generativelanguage.googleapis.com/v1beta";
const DEFAULT_MODEL: &str = "gemini-3.6-flash";
const DAY_HINT: &str = "Prioritize web sources published in the last 24 hours.";
const RESERVED_HEADERS: &[&str] = &["connection", "content-length", "expect", "host", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];
const OWNED_HEADERS: &[&str] = &["content-type", "x-goog-api-client", "x-goog-api-key"];

fn base(c: &WebCtx) -> String {
    c.base_url("gemini", None, DEFAULT_BASE)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// RFC 3339 with second precision (Gemini rejects fractional seconds).
pub fn rfc3339(secs: i64) -> String {
    let (d, t) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    format!("{}T{:02}:{:02}:{:02}Z", super::brave::civil(d), t / 3600, t % 3600 / 60, t % 60)
}

fn date_secs(iso: &str) -> i64 {
    // days from civil (inverse of brave::civil)
    let (y, m, d): (i64, i64, i64) = (iso[..4].parse().unwrap_or(1970), iso[5..7].parse().unwrap_or(1), iso[8..10].parse().unwrap_or(1));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
}

/// `(timeRangeFilter, freshness)`; a 24 h window is rejected by Gemini, so `day` becomes a prompt hint.
pub fn time_range(r: &SearchRequest, now: i64) -> Result<(Option<Value>, Option<String>), String> {
    let t = parse_time_filters(r, "perplexity").map_err(|e| if e.starts_with("freshness must") { "freshness must be day, week, month, year, or the shortcuts pd, pw, pm, py.".to_string() } else { e })?;
    if let Some(f) = t.freshness {
        let days = match f.as_str() {
            "day" => return Ok((None, Some(f))),
            "week" => 7,
            "month" => 30,
            _ => 365,
        };
        return Ok((Some(json!({"startTime": rfc3339(now - days * 86_400), "endTime": rfc3339(now)})), Some(f)));
    }
    if t.date_after.is_none() && t.date_before.is_none() {
        return Ok((None, None));
    }
    let start = t.date_after.as_deref().map(|a| format!("{a}T00:00:00Z")).unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    let end = t.date_before.as_deref().map(|b| rfc3339(date_secs(b) + 86_400)).unwrap_or_else(|| rfc3339(now));
    Ok((Some(json!({"startTime": start, "endTime": end})), None))
}

fn operator_headers(c: &WebCtx) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    if let Some(Value::Object(h)) = c.opt_value("gemini", "headers") {
        for (k, v) in h {
            let name = k.trim().to_ascii_lowercase();
            let val = v.as_str().map(|s| (c.secrets)(s)).ok_or_else(|| format!("[web.providers.gemini] headers[{k:?}] must be a string."))?;
            if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || "-_!#$%&'*+.^`|~".contains(ch)) || val.contains(['\r', '\n']) {
                return Err(format!("[web.providers.gemini] headers[{k:?}] is not a valid HTTP header."));
            }
            if RESERVED_HEADERS.contains(&name.as_str()) {
                return Err(format!("[web.providers.gemini] headers[{k:?}] uses a reserved or framing HTTP header."));
            }
            if !OWNED_HEADERS.contains(&name.as_str()) {
                out.push((name, val));
            }
        }
    }
    Ok(out)
}

impl WebProvider for Gemini {
    fn id(&self) -> &'static str {
        "gemini"
    }
    fn label(&self) -> &'static str {
        "Gemini (Google Search)"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["google"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("gemini", ENV).is_some()
    }
    fn filters(&self) -> &'static [&'static str] {
        &["freshness", "date_after", "date_before"]
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/models/{}:generateContent", base(c), c.opt("gemini", "model").unwrap_or_else(|| DEFAULT_MODEL.into()))
    }
    fn signup_url(&self) -> &'static str {
        "https://aistudio.google.com/apikey"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let (range, fresh) = time_range(r, now_secs())?;
        let key = c.key("gemini", ENV).ok_or("web_search (gemini) needs an API key. Set GEMINI_API_KEY or [web.providers.gemini] api_key. If you do not want to configure a search API key, use web_fetch for a specific URL.")?;
        let headers = operator_headers(c)?;
        let q = if fresh.as_deref() == Some("day") { format!("{}\n\nSearch recency instruction: {DAY_HINT} If no matching recent sources are available, state that limitation and use the most relevant available sources.", r.query) } else { r.query.clone() };
        let gs = match range {
            Some(t) => json!({"timeRangeFilter": t}),
            None => json!({}),
        };
        let body = json!({"contents": [{"parts": [{"text": q}]}], "tools": [{"google_search": gs}]});
        let mut h: Vec<(&str, String)> = headers.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        h.push(("x-goog-api-key", key.clone()));
        h.push(("x-goog-api-client", format!("seagent/{}", env!("CARGO_PKG_VERSION"))));
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &h, &body, c.timeout("gemini")).map_err(|e| format!("Gemini API error: {e}"))?;
        let redact = |s: &str| regex::Regex::new(r"(?i)key=[^&\s]+").unwrap().replace_all(&s.replace(&key, "***"), "key=***").into_owned();
        if !resp.ok() {
            return Err(redact(&http::api_error("Gemini", &resp, Some(&key))));
        }
        let v = resp.json().map_err(|_| "Gemini API error: malformed JSON response".to_string())?;
        if let Some(e) = v.get("error") {
            let msg = [http::s(e, "message"), http::s(e, "status")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "unknown".into());
            return Err(redact(&format!("Gemini API error ({}): {msg}", e.get("code").and_then(|x| x.as_i64()).unwrap_or(0))));
        }
        let cand = v.pointer("/candidates/0").cloned().unwrap_or(Value::Null);
        let content = cand.pointer("/content/parts").and_then(|p| p.as_array()).into_iter().flatten().filter_map(|p| p.get("text").and_then(|t| t.as_str())).filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n");
        if content.is_empty() {
            let reason = [v.pointer("/promptFeedback/blockReason"), cand.get("finishReason")].into_iter().flatten().filter_map(|x| x.as_str()).find(|x| !x.is_empty());
            return Err(format!("Gemini search returned no final answer{}.", reason.map(|r| format!(" ({})", crate::util::truncate_str(r, 120))).unwrap_or_default()));
        }
        let raw: Vec<(String, Option<String>)> = cand.pointer("/groundingMetadata/groundingChunks").and_then(|g| g.as_array()).into_iter().flatten().filter_map(|ch| Some((ch.pointer("/web/uri")?.as_str()?.to_string(), ch.pointer("/web/title").and_then(|t| t.as_str()).map(str::to_string)))).collect();
        let resolve = c.opt_bool("gemini", "resolve_citations").unwrap_or(true);
        let policy = Arc::new(ssrf::SsrfPolicy::from_config(&c.cfg));
        let mut citations = Vec::new();
        for batch in raw.chunks(10) {
            let handles: Vec<_> = batch
                .iter()
                .cloned()
                .map(|(u, t)| {
                    let p = policy.clone();
                    std::thread::spawn(move || (if resolve { ssrf::resolve_redirect(&u, p, 5) } else { u }, t))
                })
                .collect();
            for h in handles {
                if let Ok((url, title)) = h.join() {
                    citations.push(Citation { url, title });
                }
            }
        }
        Ok(SearchOutput::Answer { content, citations })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn grounded_answer_and_redirects() {
        let target = FakeServer::start(vec![("HEAD /final", 200, "text/html", String::new())]);
        let redir = format!("{}/final", target.url);
        let g = FakeServer::with(move |r| {
            if r.method == "HEAD" {
                return (302, "text/plain".into(), vec![], vec![("Location".into(), redir.clone())]);
            }
            let host = r.header("host").unwrap_or_default();
            let body = json!({"candidates":[{"content":{"parts":[{"text":"Grounded"},{"text":"answer"}]},"groundingMetadata":{"groundingChunks":[{"web":{"uri":format!("http://{host}/grounding-api-redirect/abc"),"title":"src"}},{"retrievedContext":{}}]}}]}).to_string();
            (200, "application/json".into(), body.into_bytes(), vec![])
        });
        let c = wctx(json!({"allow_private_urls":true,"providers":{"gemini":{"base_url":g.url.clone(),"model":"gm","headers":{"X-Trace":"1","x-goog-api-key":"ignored"}}}}), &[("GEMINI_API_KEY", "AIza-test")]);
        let SearchOutput::Answer { content, citations } = Gemini.search(&c, &SearchRequest { query: "q".into(), count: 3, freshness: Some("week".into()), ..Default::default() }).unwrap() else { panic!() };
        assert_eq!(content, "Grounded\nanswer");
        assert_eq!(citations, vec![Citation { url: format!("{}/final", target.url), title: Some("src".into()) }]);
        let req = g.requests().into_iter().find(|r| r.method == "POST").unwrap();
        assert_eq!((req.path.as_str(), req.header("x-goog-api-key").as_deref(), req.header("x-trace").as_deref()), ("/models/gm:generateContent", Some("AIza-test"), Some("1")));
        assert!(req.json()["tools"][0]["google_search"]["timeRangeFilter"]["startTime"].as_str().unwrap().ends_with('Z'));
        assert_eq!(ssrf::resolve_redirect("http://127.0.0.1:1/x", Arc::new(ssrf::SsrfPolicy::default()), 5), "http://127.0.0.1:1/x", "blocked → unchanged");
    }

    #[test]
    fn time_ranges_and_errors() {
        let now = 1_700_000_000;
        let r = |f: Option<&str>, a: Option<&str>, b: Option<&str>| SearchRequest { query: "q".into(), freshness: f.map(Into::into), date_after: a.map(Into::into), date_before: b.map(Into::into), ..Default::default() };
        assert_eq!(time_range(&r(Some("pd"), None, None), now).unwrap(), (None, Some("day".into())));
        let (t, _) = time_range(&r(None, Some("2024-01-01"), Some("2024-01-31")), now).unwrap();
        assert_eq!(t.unwrap(), json!({"startTime":"2024-01-01T00:00:00Z","endTime":"2024-02-01T00:00:00Z"}));
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(date_secs("2024-02-29"), 1_709_164_800);
        assert!(time_range(&r(Some("x"), None, None), now).unwrap_err().contains("shortcuts"));
        let s = FakeServer::start(vec![("POST /models/gemini-3.6-flash:generateContent", 200, "application/json", json!({"error":{"code":400,"message":"API key not valid key=AIza-test"}}).to_string())]);
        let c = wctx(json!({"providers":{"gemini":{"base_url":s.url.clone()}}}), &[("GEMINI_API_KEY", "AIza-test")]);
        assert_eq!(Gemini.search(&c, &SearchRequest { query: "q".into(), ..Default::default() }).unwrap_err(), "Gemini API error (400): API key not valid key=***");
        let s = FakeServer::start(vec![("POST /models/gemini-3.6-flash:generateContent", 200, "application/json", json!({"candidates":[{"finishReason":"SAFETY"}]}).to_string())]);
        let c = wctx(json!({"providers":{"gemini":{"base_url":s.url.clone()}}}), &[("GEMINI_API_KEY", "k")]);
        assert_eq!(Gemini.search(&c, &SearchRequest { query: "q".into(), ..Default::default() }).unwrap_err(), "Gemini search returned no final answer (SAFETY).");
        let c = wctx(json!({"providers":{"gemini":{"headers":{"Host":"x"}}}}), &[("GEMINI_API_KEY", "k")]);
        assert!(Gemini.search(&c, &SearchRequest { query: "q".into(), ..Default::default() }).unwrap_err().contains("reserved"));
    }
}
