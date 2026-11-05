//! Shared helpers: tokenizing (words + CJK bigrams, OpenClaw memory-core tokenize.ts),
//! hashing, civil dates, atomic files, HTTP with 429/5xx retries.

use ring::digest;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DAY_MS: f64 = 86_400_000.0;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn sha256_hex(data: &[u8]) -> String {
    digest::digest(&digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x3040..=0x309f | 0x30a0..=0x30ff | 0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xac00..=0xd7af | 0x1100..=0x11ff | 0xf900..=0xfaff)
}

/// Search tokens: lowercase words (letters/digits/_), and for CJK runs both bigrams and
/// unigrams (only adjacent CJK chars form bigrams).
pub fn tokens(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    let mut word = String::new();
    let mut run: Vec<char> = Vec::new();
    let flush_run = |run: &mut Vec<char>, out: &mut Vec<String>| {
        for w in run.windows(2) {
            out.push(w.iter().collect());
        }
        for c in run.iter() {
            out.push(c.to_string());
        }
        run.clear();
    };
    for c in lower.chars() {
        if is_cjk(c) {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            run.push(c);
        } else {
            flush_run(&mut run, &mut out);
            if c.is_alphanumeric() || c == '_' {
                word.push(c);
            } else if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    flush_run(&mut run, &mut out);
    out
}

pub fn token_set(text: &str) -> BTreeSet<String> {
    tokens(text).into_iter().collect()
}

/// Jaccard similarity; token-less texts compare by literal equality.
pub fn similarity(a: &str, b: &str) -> f64 {
    let (x, y) = (token_set(a), token_set(b));
    if x.is_empty() && y.is_empty() {
        return if a.trim().to_lowercase() == b.trim().to_lowercase() { 1.0 } else { 0.0 };
    }
    let inter = x.intersection(&y).count() as f64;
    inter / ((x.len() + y.len()) as f64 - inter)
}

/// Days since 1970-01-01 → (year, month, day) (proleptic Gregorian, Howard Hinnant).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` of `ms` shifted by `offset_minutes`.
pub fn day_stamp(ms: u64, offset_minutes: i32) -> String {
    let t = ms as i64 + offset_minutes as i64 * 60_000;
    let (y, m, d) = civil(t.div_euclid(86_400_000));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parse `YYYY-MM-DD` → UTC midnight ms (validated).
pub fn parse_day(s: &str) -> Option<u64> {
    let p: Vec<&str> = s.split('-').collect();
    if p.len() != 3 || p[0].len() != 4 || p[1].len() != 2 || p[2].len() != 2 {
        return None;
    }
    let (y, m, d) = (p[0].parse::<i64>().ok()?, p[1].parse::<u32>().ok()?, p[2].parse::<u32>().ok()?);
    let days = days_from_civil(y, m, d);
    (civil(days) == (y, m, d)).then_some((days * 86_400_000) as u64)
}

pub fn iso(ms: u64) -> String {
    let (y, m, d) = civil((ms / 86_400_000) as i64);
    let s = (ms % 86_400_000) / 1000;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}

pub fn parse_iso(s: &str) -> Option<u64> {
    let day = parse_day(s.get(..10)?)?;
    let t = s.get(11..19).unwrap_or("00:00:00");
    let p: Vec<u64> = t.split(':').filter_map(|x| x.parse().ok()).collect();
    Some(day + p.first().copied().unwrap_or(0) * 3_600_000 + p.get(1).copied().unwrap_or(0) * 60_000 + p.get(2).copied().unwrap_or(0) * 1000)
}

/// Cut to at most `max` chars.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

pub fn compact_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn write_atomic(p: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }
    ark_kernel::util::atomic_write(p, data).map_err(|e| format!("cannot write {}: {e}", p.display()))
}

pub fn read_json(p: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(p).ok()?).ok()
}

pub fn write_json(p: &Path, v: &Value) -> Result<(), String> {
    write_atomic(p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes())
}

pub fn append_line(p: &Path, line: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(p).map_err(|e| format!("cannot open {}: {e}", p.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("cannot write {}: {e}", p.display()))
}

/// Secret / config value substituter (`{{secret:NAME}}` → value), supplied by the host.
pub type Subst = std::sync::Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Resolve a config value: substitute secrets; `env:NAME` or empty → env var fallback.
pub fn resolve_value(subst: &Subst, raw: &str, env_names: &[&str]) -> String {
    let v = subst(raw.trim());
    if let Some(name) = v.strip_prefix("env:") {
        return std::env::var(name).unwrap_or_default();
    }
    if !v.is_empty() {
        return v;
    }
    env_names.iter().find_map(|n| std::env::var(n).ok().filter(|s| !s.is_empty())).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after_ms: Option<u64>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Result<Value, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("invalid JSON response (HTTP {}): {e}", self.status))
    }
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// One HTTP request; transport failures are `Err`, any status is `Ok`.
pub fn http(method: &str, url: &str, headers: &[(String, String)], body: Option<&[u8]>, timeout: Duration) -> Result<Resp, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(timeout)).max_redirects(3).build().into();
    let res = match method {
        "GET" | "DELETE" => {
            let mut r = if method == "GET" { agent.get(url) } else { agent.delete(url) };
            for (k, v) in headers {
                r = r.header(k, v);
            }
            r.call()
        }
        _ => {
            let mut r = if method == "PUT" { agent.put(url) } else { agent.post(url) };
            for (k, v) in headers {
                r = r.header(k, v);
            }
            r.send(body.unwrap_or_default())
        }
    };
    let mut resp = res.map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = resp.status().as_u16();
    let retry_after_ms = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<f64>().ok()).map(|s| (s * 1000.0) as u64);
    let mut buf = Vec::new();
    resp.body_mut().with_config().limit(64 * 1024 * 1024).reader().read_to_end(&mut buf).map_err(|e| format!("reading response from {url} failed: {e}"))?;
    Ok(Resp { status, body: buf, retry_after_ms })
}

pub fn json_headers(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
    h.extend(extra.iter().cloned());
    h
}

/// Retry budget (OpenClaw manager-embedding-policy.ts): transient 3×500ms…8s, rate limits
/// `rate_attempts` with `rate_base_ms` doubling up to `rate_max_ms`, Retry-After honoured.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub attempts: u32,
    pub base_ms: u64,
    pub max_ms: u64,
    pub rate_attempts: u32,
    pub rate_base_ms: u64,
    pub rate_max_ms: u64,
}

pub const RETRY_INDEX: Retry = Retry { attempts: 3, base_ms: 500, max_ms: 8000, rate_attempts: 5, rate_base_ms: 5000, rate_max_ms: 60_000 };
pub const RETRY_QUERY: Retry = Retry { attempts: 3, base_ms: 500, max_ms: 8000, rate_attempts: 3, rate_base_ms: 500, rate_max_ms: 8000 };

/// Test hook: scale every retry sleep (0 in tests).
pub static RETRY_SCALE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);

pub fn is_rate_limited(status: u16, body: &str) -> bool {
    status == 429 || regex::Regex::new(r"(?i)(rate[_ ]limit|too many requests|resource has been exhausted|tokens per day)").unwrap().is_match(body)
}

/// POST JSON with retries on 429 / 5xx / transport errors; returns the 2xx JSON body.
pub fn post_json_retry(url: &str, headers: &[(String, String)], body: &Value, timeout: Duration, retry: Retry, label: &str) -> Result<Value, String> {
    send_retry("POST", url, headers, Some(body), timeout, retry, label)
}

pub fn send_retry(method: &str, url: &str, headers: &[(String, String)], body: Option<&Value>, timeout: Duration, retry: Retry, label: &str) -> Result<Value, String> {
    let data = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let res = http(method, url, headers, data.as_deref(), timeout);
        let (rate, retryable, msg, after) = match &res {
            Ok(r) if r.ok() => return r.json(),
            Ok(r) => {
                let t = redact(&r.text(), headers);
                let rate = is_rate_limited(r.status, &t);
                (rate, rate || r.status >= 500, format!("{label} HTTP {}: {}", r.status, clip(t.trim(), 500)), r.retry_after_ms)
            }
            Err(e) => (false, true, format!("{label}: {e}"), None),
        };
        let (max_attempts, base, cap) = if rate { (retry.rate_attempts, retry.rate_base_ms, retry.rate_max_ms) } else { (retry.attempts, retry.base_ms, retry.max_ms) };
        if !retryable || attempt >= max_attempts {
            return Err(msg);
        }
        let delay = after.map(|a| a.min(cap)).unwrap_or_else(|| (base * 2u64.pow(attempt - 1)).min(cap));
        let scale = RETRY_SCALE.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(delay * scale / 1000));
    }
}

/// Remove header secrets reflected in an error body.
pub fn redact(text: &str, headers: &[(String, String)]) -> String {
    let mut t = text.to_string();
    for (k, v) in headers {
        let k = k.to_ascii_lowercase();
        if k == "authorization" || k.contains("key") || k.contains("token") {
            let secret = v.trim_start_matches("Bearer ").trim();
            if secret.len() >= 6 {
                t = t.replace(secret, "[redacted]");
            }
        }
    }
    t
}

pub fn headers_from(map: &HashMap<String, String>, subst: &Subst) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = map.iter().map(|(k, v)| (k.clone(), subst(v))).collect();
    v.sort();
    v
}

#[cfg(test)]
pub mod testutil {
    //! A scripted HTTP fake: each request is recorded (method, path, headers, body) and
    //! answered by `handler`.
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Default)]
    pub struct Req {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }
    impl Req {
        pub fn header(&self, k: &str) -> Option<String> {
            self.headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone())
        }
        pub fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
        }
    }

    pub struct Fake {
        pub url: String,
        pub reqs: Arc<Mutex<Vec<Req>>>,
    }

    pub fn fake(handler: impl Fn(&Req, usize) -> (u16, String) + Send + Sync + 'static) -> Fake {
        crate::util::RETRY_SCALE.store(0, std::sync::atomic::Ordering::Relaxed);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let r2 = reqs.clone();
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let (r2, handler) = (r2.clone(), handler.clone());
                std::thread::spawn(move || {
                    let mut rd = BufReader::new(s.try_clone().unwrap());
                    let mut line = String::new();
                    if rd.read_line(&mut line).is_err() || line.is_empty() {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let mut headers = Vec::new();
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        if rd.read_line(&mut h).is_err() || h.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.trim_end().split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                            headers.push((k.to_string(), v.trim().to_string()));
                        }
                    }
                    let mut body = vec![0u8; len];
                    let _ = rd.read_exact(&mut body);
                    let req = Req { method, path, headers, body };
                    let n = {
                        let mut g = r2.lock().unwrap();
                        g.push(req.clone());
                        g.len() - 1
                    };
                    let (code, out) = handler(&req, n);
                    let extra = if code == 429 { "Retry-After: 0\r\n" } else { "" };
                    let _ = s.write_all(format!("HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len()).as_bytes());
                });
            }
        });
        Fake { url, reqs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_and_similarity() {
        assert_eq!(tokens("Hello, World_1!"), vec!["hello", "world_1"]);
        let t = tokens("我喜欢hello你好");
        assert!(t.contains(&"我喜".to_string()) && t.contains(&"你好".to_string()) && !t.contains(&"欢你".to_string()));
        assert!(t.contains(&"hello".to_string()) && t.contains(&"欢".to_string()));
        assert!((similarity("a b c", "a b c") - 1.0).abs() < 1e-9);
        assert!((similarity("a b", "b c") - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(similarity("!!", "??"), 0.0);
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(day_stamp(0, 0), "1970-01-01");
        assert_eq!(day_stamp(1_700_000_000_000, 480), "2023-11-15");
        assert_eq!(parse_day("2024-02-29").map(|ms| day_stamp(ms, 0)), Some("2024-02-29".into()));
        assert!(parse_day("2023-02-29").is_none() && parse_day("x").is_none());
        let ms = 1_700_000_123_000;
        assert_eq!(parse_iso(&iso(ms)), Some(ms));
    }

    #[test]
    fn retries_on_429_then_succeeds() {
        let f = testutil::fake(|_, n| if n < 2 { (429, r#"{"error":"rate limit"}"#.into()) } else { (200, r#"{"ok":true}"#.into()) });
        let v = post_json_retry(&format!("{}/x", f.url), &[], &serde_json::json!({}), Duration::from_secs(5), RETRY_QUERY, "t").unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(f.reqs.lock().unwrap().len(), 3);
        let f = testutil::fake(|_, _| (400, r#"{"error":"bad key sk-secret-123456"}"#.into()));
        let e = post_json_retry(&format!("{}/x", f.url), &[("Authorization".into(), "Bearer sk-secret-123456".into())], &serde_json::json!({}), Duration::from_secs(5), RETRY_QUERY, "t").unwrap_err();
        assert!(e.contains("HTTP 400") && e.contains("[redacted]") && !e.contains("sk-secret"));
        assert_eq!(f.reqs.lock().unwrap().len(), 1, "4xx is not retried");
    }
}
