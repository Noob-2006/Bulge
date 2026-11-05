//! Rate-limit header tracking (Hermes `agent/rate_limit_tracker.py`): every response's
//! `x-ratelimit-*` / `anthropic-ratelimit-*` headers are recorded per provider, shown by
//! `/usage`, and used to wait out an exhausted window *before* sending a doomed request.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Window {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    /// Unix millis when the window resets.
    pub reset_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Snapshot {
    pub requests: Window,
    pub tokens: Window,
    pub input_tokens: Window,
    pub output_tokens: Window,
    /// Anthropic fast-mode limits (0 = organization has no fast capacity).
    pub fast_input_limit: Option<u64>,
    pub fast_output_limit: Option<u64>,
    /// Unix millis of the response these came from.
    pub seen_ms: u64,
}

fn table() -> &'static Mutex<BTreeMap<String, Snapshot>> {
    static T: OnceLock<Mutex<BTreeMap<String, Snapshot>>> = OnceLock::new();
    T.get_or_init(Default::default)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Headers worth keeping from a response (lowercased name, value).
pub fn interesting(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("x-ratelimit")
        || n.starts_with("anthropic-ratelimit")
        || n.starts_with("anthropic-fast")
        || n == "retry-after"
        || n.starts_with("ratelimit")
}

/// `"1m30s"`, `"6ms"`, `"20s"`, `"2.5"` (seconds), RFC 3339 → millis from now.
pub fn parse_reset(v: &str, now: u64) -> Option<u64> {
    let v = v.trim();
    if let Ok(secs) = v.parse::<f64>() {
        // Big numbers are absolute epoch seconds.
        return Some(if secs > 1e9 {
            (secs * 1000.0) as u64
        } else {
            now + (secs * 1000.0) as u64
        });
    }
    if v.contains('T') && v.contains('-') {
        return parse_rfc3339(v);
    }
    let mut total = 0f64;
    let mut num = String::new();
    let mut chars = v.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let n: f64 = num.parse().ok()?;
        num.clear();
        let unit = match c {
            'h' => 3_600_000.0,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                1.0
            }
            'm' => 60_000.0,
            's' => 1000.0,
            _ => return None,
        };
        total += n * unit;
        any = true;
    }
    if !num.is_empty() {
        return None;
    }
    any.then(|| now + total as u64)
}

/// Minimal RFC 3339 (`2026-01-02T03:04:05Z` / with offset) → unix millis.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>());
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (clock, offset) = match time.find(['Z', '+', '-']) {
        Some(i) => (&time[..i], &time[i..]),
        None => (time, "Z"),
    };
    let mut c = clock.split(':');
    let h: i64 = c.next()?.parse().ok()?;
    let mi: i64 = c.next()?.parse().ok()?;
    let sec: f64 = c.next().unwrap_or("0").parse().ok()?;
    let off_min = if offset == "Z" || offset.is_empty() {
        0
    } else {
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let (oh, om) = offset[1..].split_once(':').unwrap_or((&offset[1..], "0"));
        sign * (oh.parse::<i64>().ok()? * 60 + om.parse::<i64>().ok()?)
    };
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 - off_min * 60;
    (secs >= 0).then_some((secs as f64 * 1000.0 + sec * 1000.0) as u64)
}

/// Fold response headers into a snapshot.
pub fn parse(headers: &[(String, String)], now: u64) -> Snapshot {
    let mut s = Snapshot {
        seen_ms: now,
        ..Default::default()
    };
    for (k, v) in headers {
        let k = k.to_ascii_lowercase();
        let num = || v.trim().parse::<u64>().ok();
        let (field, which) = if let Some(r) = k.strip_prefix("x-ratelimit-") {
            // OpenAI style: x-ratelimit-{limit,remaining,reset}-{requests,tokens}
            match r.split_once('-') {
                Some((f, w)) => (f.to_string(), w.to_string()),
                None => continue,
            }
        } else if let Some(r) = k.strip_prefix("anthropic-ratelimit-") {
            // Anthropic style: anthropic-ratelimit-{requests,tokens,input-tokens,output-tokens}-{limit,remaining,reset}
            match r.rsplit_once('-') {
                Some((w, f)) => (f.to_string(), w.to_string()),
                None => continue,
            }
        } else if k == "anthropic-fast-input-tokens-limit" {
            s.fast_input_limit = num();
            continue;
        } else if k == "anthropic-fast-output-tokens-limit" {
            s.fast_output_limit = num();
            continue;
        } else {
            continue;
        };
        let win = match which.as_str() {
            "requests" => &mut s.requests,
            "input-tokens" => &mut s.input_tokens,
            "output-tokens" => &mut s.output_tokens,
            _ => &mut s.tokens,
        };
        match field.as_str() {
            "limit" => win.limit = num(),
            "remaining" => win.remaining = num(),
            "reset" => win.reset_at_ms = parse_reset(v, now),
            _ => {}
        }
    }
    s
}

/// Record the rate-limit headers of a response from `provider`.
pub fn record(provider: &str, headers: &[(String, String)]) {
    if !headers
        .iter()
        .any(|(k, _)| interesting(k) && !k.eq_ignore_ascii_case("retry-after"))
    {
        return;
    }
    let s = parse(headers, now_ms());
    table().lock().unwrap().insert(provider.to_string(), s);
}

pub fn get(provider: &str) -> Option<Snapshot> {
    table().lock().unwrap().get(provider).cloned()
}

pub fn all() -> BTreeMap<String, Snapshot> {
    table().lock().unwrap().clone()
}

/// How long to hold the next request to `provider`: the request window is spent and
/// resets soon (≤ `max`). Longer waits are left to the normal 429 retry/fallback path.
pub fn wait_before(provider: &str, max: Duration) -> Option<Duration> {
    let s = get(provider)?;
    let now = now_ms();
    let spent = |w: &Window| w.remaining == Some(0) && w.reset_at_ms.is_some_and(|r| r > now);
    let mut wait = 0u64;
    for w in [&s.requests, &s.tokens, &s.input_tokens, &s.output_tokens] {
        if spent(w) {
            wait = wait.max(w.reset_at_ms.unwrap() - now);
        }
    }
    (wait > 0 && wait <= max.as_millis() as u64).then(|| Duration::from_millis(wait))
}

/// One-line summary for `/usage`.
pub fn describe(s: &Snapshot) -> String {
    let now = now_ms();
    let f = |name: &str, w: &Window| -> Option<String> {
        let rem = w.remaining?;
        let lim = w.limit.map(|l| format!("/{l}")).unwrap_or_default();
        let reset = w
            .reset_at_ms
            .filter(|r| *r > now)
            .map(|r| format!(" (resets in {}s)", (r - now).div_ceil(1000)))
            .unwrap_or_default();
        Some(format!("{name} {rem}{lim} left{reset}"))
    };
    let parts: Vec<String> = [
        ("requests", &s.requests),
        ("tokens", &s.tokens),
        ("input", &s.input_tokens),
        ("output", &s.output_tokens),
    ]
    .iter()
    .filter_map(|(n, w)| f(n, w))
    .collect();
    if parts.is_empty() {
        "no rate-limit headers seen".into()
    } else {
        parts.join(" · ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn openai_and_anthropic_shapes() {
        let now = 1_000_000;
        let s = parse(
            &h(&[
                ("x-ratelimit-limit-requests", "500"),
                ("x-ratelimit-remaining-requests", "0"),
                ("x-ratelimit-reset-requests", "1m2s"),
                ("x-ratelimit-remaining-tokens", "1200"),
                ("x-ratelimit-reset-tokens", "6ms"),
            ]),
            now,
        );
        assert_eq!(
            s.requests,
            Window {
                limit: Some(500),
                remaining: Some(0),
                reset_at_ms: Some(now + 62_000)
            }
        );
        assert_eq!(s.tokens.reset_at_ms, Some(now + 6));
        let a = parse(
            &h(&[
                ("anthropic-ratelimit-input-tokens-remaining", "10"),
                (
                    "anthropic-ratelimit-input-tokens-reset",
                    "2026-01-01T00:00:10Z",
                ),
                ("anthropic-fast-output-tokens-limit", "0"),
            ]),
            now,
        );
        assert_eq!(a.input_tokens.remaining, Some(10));
        assert_eq!(a.input_tokens.reset_at_ms, Some(1_767_225_610_000));
        assert_eq!(a.fast_output_limit, Some(0));
    }

    #[test]
    fn reset_formats() {
        assert_eq!(parse_reset("20s", 0), Some(20_000));
        assert_eq!(parse_reset("1h1m", 0), Some(3_660_000));
        assert_eq!(parse_reset("250ms", 0), Some(250));
        assert_eq!(parse_reset("2.5", 0), Some(2500));
        assert_eq!(parse_reset("garbage", 0), None);
        assert_eq!(parse_rfc3339("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
    }

    #[test]
    fn waits_only_for_spent_short_windows() {
        let now = now_ms();
        record(
            "rl-test",
            &h(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("x-ratelimit-reset-requests", "2s"),
            ]),
        );
        let w = wait_before("rl-test", Duration::from_secs(60)).unwrap();
        assert!(
            w <= Duration::from_secs(2) && w > Duration::from_millis(1000),
            "{w:?}"
        );
        assert!(
            wait_before("rl-test", Duration::from_secs(1)).is_none(),
            "too long: leave it to retry/fallback"
        );
        record(
            "rl-test2",
            &h(&[
                ("x-ratelimit-remaining-requests", "5"),
                ("x-ratelimit-reset-requests", "2s"),
            ]),
        );
        assert!(wait_before("rl-test2", Duration::from_secs(60)).is_none());
        assert!(describe(&get("rl-test2").unwrap()).contains("requests 5 left"));
        let _ = now;
        record("rl-none", &h(&[("content-type", "x")]));
        assert!(get("rl-none").is_none());
    }
}
