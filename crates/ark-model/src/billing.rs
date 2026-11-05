//! What providers actually billed, from their organization reporting APIs (admin keys only):
//! - Anthropic `GET /v1/organizations/cost_report` (amounts are decimal strings in cents),
//! - OpenAI `GET /v1/organization/costs` (amounts are numbers in the currency unit).
//!
//! ark's own ledger estimates spend from token counts and list prices; this is the
//! provider's ledger, used by `ark usage --billing` to show both side by side.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Spend {
    pub provider: String,
    pub days: u64,
    pub total_usd: f64,
    /// Line items (Anthropic `description`, OpenAI `line_item`), largest first.
    pub items: Vec<(String, f64)>,
}

/// Admin-key env var / vault secret per provider.
pub fn admin_key_name(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("ANTHROPIC_ADMIN_KEY"),
        "openai" => Some("OPENAI_ADMIN_KEY"),
        _ => None,
    }
}

fn origin(var: &str, default: &str) -> String {
    std::env::var(var).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

/// `YYYY-MM-DDT00:00:00Z` for a Unix time in seconds (UTC).
fn rfc3339_day(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

fn finish(provider: &str, days: u64, items: BTreeMap<String, f64>) -> Spend {
    let mut items: Vec<(String, f64)> = items.into_iter().filter(|(_, v)| *v != 0.0).collect();
    items.sort_by(|a, b| b.1.total_cmp(&a.1));
    Spend { provider: provider.into(), days, total_usd: items.iter().map(|(_, v)| v).sum(), items }
}

/// Follow `has_more` / `next_page`, at most `max_pages` pages.
fn pages(mut url_for: impl FnMut(Option<&str>) -> String, headers: &[(&str, &str)], max_pages: usize) -> Result<Vec<Value>, String> {
    let mut out = vec![];
    let mut page: Option<String> = None;
    for _ in 0..max_pages {
        let v = crate::login::get_json(&url_for(page.as_deref()), headers)?;
        let more = v["has_more"].as_bool().unwrap_or(false);
        page = v["next_page"].as_str().map(String::from);
        out.push(v);
        if !more || page.is_none() {
            break;
        }
    }
    Ok(out)
}

/// Anthropic organization cost report over the last `days` days (USD).
pub fn anthropic(admin_key: &str, days: u64) -> Result<Spend, String> {
    let now = crate::ratelimit::now_ms() / 1000;
    let start = rfc3339_day(now.saturating_sub(days.saturating_sub(1) * 86_400));
    let base = origin("ARK_ANTHROPIC_ADMIN_ORIGIN", "https://api.anthropic.com");
    let limit = days.clamp(1, 31);
    let headers = [("x-api-key", admin_key), ("anthropic-version", "2023-06-01"), ("user-agent", concat!("ark/", env!("CARGO_PKG_VERSION")))];
    let bodies = pages(
        |p| {
            let mut u = format!("{base}/v1/organizations/cost_report?starting_at={start}&bucket_width=1d&group_by[]=description&limit={limit}");
            if let Some(p) = p {
                u.push_str(&format!("&page={p}"));
            }
            u
        },
        &headers,
        8,
    )?;
    let mut items = BTreeMap::new();
    for v in &bodies {
        for b in v["data"].as_array().into_iter().flatten() {
            for r in b["results"].as_array().into_iter().flatten() {
                if r["currency"].as_str().is_some_and(|c| !c.eq_ignore_ascii_case("usd")) {
                    continue;
                }
                // Lowest currency unit (cents) as a decimal string.
                let cents = r["amount"].as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| r["amount"].as_f64()).unwrap_or(0.0);
                let label = r["description"].as_str().or_else(|| r["model"].as_str()).unwrap_or("other").to_string();
                *items.entry(label).or_insert(0.0) += cents / 100.0;
            }
        }
    }
    Ok(finish("anthropic", days, items))
}

/// OpenAI organization costs over the last `days` days (USD).
pub fn openai(admin_key: &str, days: u64) -> Result<Spend, String> {
    let now = crate::ratelimit::now_ms() / 1000;
    let start = (now / 86_400).saturating_sub(days.saturating_sub(1)) * 86_400;
    let base = origin("ARK_OPENAI_ADMIN_ORIGIN", "https://api.openai.com");
    let limit = days.clamp(1, 180);
    let bearer = format!("Bearer {admin_key}");
    let headers = [("authorization", bearer.as_str())];
    let bodies = pages(
        |p| {
            let mut u = format!("{base}/v1/organization/costs?start_time={start}&bucket_width=1d&group_by=line_item&limit={limit}");
            if let Some(p) = p {
                u.push_str(&format!("&page={p}"));
            }
            u
        },
        &headers,
        8,
    )?;
    let mut items = BTreeMap::new();
    for v in &bodies {
        for b in v["data"].as_array().into_iter().flatten() {
            // The spec names the bucket list `result`; accept `results` too.
            let rows = b["result"].as_array().or_else(|| b["results"].as_array());
            for r in rows.into_iter().flatten() {
                let amount = &r["amount"];
                if amount["currency"].as_str().is_some_and(|c| !c.eq_ignore_ascii_case("usd")) {
                    continue;
                }
                let value = amount["value"].as_f64().or_else(|| amount["value"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0);
                let label = r["line_item"].as_str().unwrap_or("other").to_string();
                *items.entry(label).or_insert(0.0) += value;
            }
        }
    }
    Ok(finish("openai", days, items))
}

pub fn fetch(provider: &str, admin_key: &str, days: u64) -> Result<Spend, String> {
    match provider {
        "anthropic" => anthropic(admin_key, days),
        "openai" => openai(admin_key, days),
        p => Err(format!("{p}: no billing report API")),
    }
}

pub fn describe(s: &Spend) -> String {
    let mut out = format!("{}: USD {:.2} billed over {} day(s)", s.provider, s.total_usd, s.days);
    for (k, v) in s.items.iter().take(8) {
        out.push_str(&format!("\n  {v:>9.2}  {k}"));
    }
    if s.items.len() > 8 {
        out.push_str(&format!("\n  … {} more line item(s)", s.items.len() - 8));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Serve `bodies` in order; record each request line and headers.
    fn serve(bodies: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for body in bodies {
                let (mut c, _) = l.accept().unwrap();
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    head.push_str(&line);
                }
                s2.lock().unwrap().push(head);
                write!(c, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (addr, seen)
    }

    #[test]
    fn day_formatting() {
        assert_eq!(rfc3339_day(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_day(1_793_683_166), "2026-11-03T00:00:00Z");
        assert_eq!(rfc3339_day(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn anthropic_cost_report_cents_and_pages() {
        let p1 = r#"{"data":[{"starting_at":"2026-11-02T00:00:00Z","ending_at":"2026-11-03T00:00:00Z","results":[
            {"amount":"123.45","currency":"USD","description":"Claude Opus 5.5 Usage - Input Tokens"},
            {"amount":"50","currency":"USD","description":"Claude Opus 5.5 Usage - Output Tokens"}]}],
            "has_more":true,"next_page":"page_2"}"#;
        let p2 = r#"{"data":[{"starting_at":"2026-11-03T00:00:00Z","ending_at":"2026-11-04T00:00:00Z","results":[
            {"amount":"100","currency":"USD","description":"Claude Opus 5.5 Usage - Output Tokens"}]}],
            "has_more":false,"next_page":null}"#;
        let (addr, seen) = serve(vec![p1.into(), p2.into()]);
        std::env::set_var("ARK_ANTHROPIC_ADMIN_ORIGIN", &addr);
        let s = anthropic("sk-ant-admin01-test", 2).unwrap();
        std::env::remove_var("ARK_ANTHROPIC_ADMIN_ORIGIN");
        assert!((s.total_usd - 2.7345).abs() < 1e-9, "{s:?}");
        assert_eq!(s.items[0], ("Claude Opus 5.5 Usage - Output Tokens".to_string(), 1.5));
        let reqs = seen.lock().unwrap();
        assert!(reqs[0].starts_with("GET /v1/organizations/cost_report?starting_at=") && reqs[0].contains("group_by[]=description"), "{}", reqs[0]);
        assert!(reqs[0].to_lowercase().contains("x-api-key: sk-ant-admin01-test"));
        assert!(reqs[1].contains("&page=page_2"));
    }

    #[test]
    fn openai_costs_amount_objects() {
        let body = r#"{"object":"page","data":[{"object":"bucket","start_time":1,"end_time":2,"result":[
            {"object":"organization.costs.result","amount":{"value":0.06,"currency":"usd"},"line_item":"Image models"},
            {"object":"organization.costs.result","amount":{"value":1.5,"currency":"usd"},"line_item":"gpt-5.5, input"}]}],
            "has_more":false,"next_page":null}"#;
        let (addr, seen) = serve(vec![body.into()]);
        std::env::set_var("ARK_OPENAI_ADMIN_ORIGIN", &addr);
        let s = openai("sk-admin-test", 7).unwrap();
        std::env::remove_var("ARK_OPENAI_ADMIN_ORIGIN");
        assert!((s.total_usd - 1.56).abs() < 1e-9);
        assert_eq!(s.items[0].0, "gpt-5.5, input");
        let req = &seen.lock().unwrap()[0];
        assert!(req.starts_with("GET /v1/organization/costs?start_time=") && req.contains("group_by=line_item"));
        assert!(req.to_lowercase().contains("authorization: bearer sk-admin-test"));
    }
}
