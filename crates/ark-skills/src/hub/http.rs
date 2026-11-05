//! Guarded HTTP for the skills hub (Hermes `tools/skills_hub.py` `_guarded_http_get` and the
//! index cache, MIT): every hop — the first request and each redirect — is checked against the
//! SSRF policy and the website blocklist; redirects are followed by hand (at most 5); bodies are
//! capped. `[skills.hub] allow_private = true` admits loopback / private registries (local
//! mirrors, tests); cloud metadata stays blocked regardless. JSON listings are cached under
//! `.hub/index-cache/` for `cache_ttl_secs`. Requests to the GitHub API additionally retry
//! rate-limit 403/429 (waiting until `Retry-After` / `X-RateLimit-Reset`, capped 60 s) and 5xx
//! with exponential backoff, like Hermes' `_github_get` — one shared limit zeroes every tap at once.

use super::super::core::settings::{Settings, Store};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

pub const MAX_REDIRECTS: usize = 5;
pub const MAX_BODY: u64 = 25 * 1024 * 1024;
/// GitHub API attempts per request (Hermes `_github_get(max_retries=3)`).
pub const MAX_ATTEMPTS: usize = 3;
const MAX_BACKOFF_SECS: f64 = 30.0;
const MAX_RATE_LIMIT_WAIT_SECS: f64 = 60.0;
const UA: &str = concat!("ark-skills-hub/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
    pub url: String,
}

impl Resp {
    pub fn ok(&self) -> bool {
        self.status == 200
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

pub struct Http {
    pub settings: Settings,
    pub store: Store,
}

fn join_url(base: &str, loc: &str) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    let host = rest.split('/').next().unwrap_or("");
    if loc.starts_with('/') {
        format!("{scheme}://{host}{loc}")
    } else {
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        format!("{dir}/{loc}")
    }
}

/// Trimmed value of a response header ("" when absent or not ASCII).
fn header<'a>(h: &'a ureq::http::HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::trim).unwrap_or("")
}

/// 403 with an exhausted quota, or any 429 (Hermes `_is_rate_limit_response`).
fn is_rate_limit(status: u16, h: &ureq::http::HeaderMap) -> bool {
    status == 429 || (status == 403 && header(h, "x-ratelimit-remaining") == "0")
}

/// Wait before retrying a rate-limited request: numeric `Retry-After` first, else the gap to
/// `X-RateLimit-Reset` when it falls in the next 60 s (None → exponential backoff).
fn rate_limit_wait(h: &ureq::http::HeaderMap) -> Option<f64> {
    if let Ok(v) = header(h, "retry-after").parse::<f64>() {
        return Some(v.clamp(0.0, MAX_RATE_LIMIT_WAIT_SECS));
    }
    let delta = header(h, "x-ratelimit-reset").parse::<f64>().ok().map(|t| t - ark_kernel::util::unix_now() as f64);
    delta.filter(|d| *d > 0.0 && *d <= MAX_RATE_LIMIT_WAIT_SECS)
}

pub fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

pub fn with_query(url: &str, q: &[(&str, String)]) -> String {
    let mut full = url.to_string();
    for (i, (k, v)) in q.iter().enumerate() {
        full.push(if i == 0 && !url.contains('?') { '?' } else { '&' });
        full.push_str(&format!("{}={}", enc(k), enc(v)));
    }
    full
}

impl Http {
    pub fn new(settings: &Settings, store: &Store) -> Http {
        Http { settings: settings.clone(), store: store.clone() }
    }

    /// The policy check applied to every hop.
    pub fn check(&self, url: &str) -> Result<(), String> {
        ark_net::http::ensure_online("the skills hub")?;
        if let Some(m) = ark_security::url_safety::check_website_global(url) {
            return Err(m);
        }
        let mut policy = ark_security::url_safety::global_policy();
        policy.allow_private_urls |= self.settings.hub.allow_private;
        ark_security::url_safety::is_safe_url(url, &policy)
    }

    fn headers_for(&self, url: &str, auth: bool) -> Vec<(String, String)> {
        let mut h = vec![("User-Agent".to_string(), UA.to_string())];
        if url.starts_with(&self.settings.hub.github_api) {
            h.push(("Accept".into(), "application/vnd.github+json".into()));
            if auth {
                if let Ok(t) = std::env::var(&self.settings.hub.github_token_env) {
                    if !t.is_empty() {
                        h.push(("Authorization".into(), format!("Bearer {t}")));
                    }
                }
            }
        }
        h
    }

    /// One request with the GitHub API retry policy (rate-limit 403/429 and 5xx only): the final
    /// response, or None when every attempt hit a transport error. Other hosts get a single attempt.
    fn request(&self, agent: &ureq::Agent, url: &str) -> Option<ureq::http::Response<ureq::Body>> {
        let api = url.starts_with(&self.settings.hub.github_api);
        let attempts = if api { MAX_ATTEMPTS } else { 1 };
        let mut backoff = 1.0f64;
        let mut auth = true;
        for attempt in 0..attempts {
            let headers = self.headers_for(url, auth);
            let sent = headers.iter().any(|(k, _)| k == "Authorization");
            let mut req = agent.get(url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let resp = match req.call() {
                Ok(r) => r,
                Err(_) => {
                    if attempt + 1 == attempts {
                        return None;
                    }
                    std::thread::sleep(Duration::from_secs_f64(backoff));
                    backoff = (backoff * 2.0).min(MAX_BACKOFF_SECS);
                    continue;
                }
            };
            let status = resp.status().as_u16();
            if status == 401 && sent {
                // Bad credentials: stop sending the token, so a revoked one does not shadow the
                // next credential and finally anonymous access to public repos (#98725).
                auth = false;
                continue;
            }
            let limited = is_rate_limit(status, resp.headers());
            if attempt + 1 == attempts || (!limited && !(500..600).contains(&status)) {
                return Some(resp);
            }
            let wait = if limited { rate_limit_wait(resp.headers()).unwrap_or(backoff) } else { backoff };
            std::thread::sleep(Duration::from_secs_f64(wait));
            backoff = (backoff * 2.0).min(MAX_BACKOFF_SECS);
        }
        None
    }

    /// Guarded GET: None on a blocked hop, transport error or too many redirects.
    pub fn get(&self, url: &str) -> Option<Resp> {
        let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(Duration::from_secs(20))).http_status_as_error(false).max_redirects(0).build().into();
        let mut cur = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            if self.check(&cur).is_err() {
                return None;
            }
            let mut r = self.request(&agent, &cur)?;
            let status = r.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let loc = r.headers().get("location")?.to_str().ok()?.to_string();
                cur = join_url(&cur, &loc);
                continue;
            }
            if let Some(len) = r.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) {
                if len > MAX_BODY {
                    return None;
                }
            }
            let mut body = Vec::new();
            r.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY + 1).read_to_end(&mut body).ok()?;
            if body.len() as u64 > MAX_BODY {
                return None;
            }
            return Some(Resp { status, body, url: cur });
        }
        None
    }

    /// One guarded request with a JSON body (`POST` / `PUT` / `PATCH`); no redirects.
    pub fn send_json(&self, method: &str, url: &str, body: &Value) -> Result<Resp, String> {
        self.check(url)?;
        let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(Duration::from_secs(30))).http_status_as_error(false).max_redirects(0).build().into();
        let data = serde_json::to_vec(body).unwrap_or_default();
        let mut req = match method {
            "PUT" => agent.put(url),
            "PATCH" => agent.patch(url),
            _ => agent.post(url),
        };
        for (k, v) in self.headers_for(url, true) {
            req = req.header(k, v);
        }
        let mut r = req.header("Content-Type", "application/json").send(data.as_slice()).map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        let mut out = Vec::new();
        r.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY).read_to_end(&mut out).map_err(|e| e.to_string())?;
        Ok(Resp { status, body: out, url: url.to_string() })
    }

    pub fn get_json(&self, url: &str) -> Option<Value> {
        self.get(url).filter(Resp::ok).and_then(|r| r.json())
    }

    pub fn get_text(&self, url: &str) -> Option<String> {
        self.get(url).filter(Resp::ok).map(|r| r.text())
    }

    fn cache_path(&self, key: &str) -> std::path::PathBuf {
        let safe: String = key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        self.store.hub().join("index-cache").join(format!("{safe}.json"))
    }

    /// Cached JSON (younger than the TTL), else `compute()`; a Some result is written back.
    pub fn memo(&self, key: &str, compute: impl FnOnce() -> Option<Value>) -> Option<Value> {
        let p = self.cache_path(key);
        if let Ok(m) = std::fs::metadata(&p) {
            let fresh = m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_secs() < self.settings.hub.cache_ttl_secs);
            if fresh {
                if let Some(v) = std::fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str(&t).ok()) {
                    return Some(v);
                }
            }
        }
        let v = compute()?;
        if std::fs::create_dir_all(p.parent().unwrap()).is_ok() {
            let _ = std::fs::write(self.store.hub().join(".ignore"), "# Exclude hub internals from search tools\n*\n");
            let _ = std::fs::write(&p, v.to_string());
        }
        Some(v)
    }
}

/// A tiny HTTP server for tests: `routes` maps a path (query included, or the bare path) to
/// (status, headers, body). Returns the base URL and a log of request lines.
#[cfg(test)]
pub mod testserver {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    pub type Route = (String, u16, Vec<(String, String)>, Vec<u8>);

    pub fn serve(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
        serve_on(TcpListener::bind("127.0.0.1:0").unwrap(), routes)
    }

    /// Serve `routes` on an already-bound listener: a route body may then name its own base URL
    /// (bind first, build the routes with `http://{addr}`, then serve).
    pub fn serve_on(l: TcpListener, routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let lg = log.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                if r.read_line(&mut first).is_err() {
                    continue;
                }
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
                lg.lock().unwrap().push(path.clone());
                let bare = path.split('?').next().unwrap_or("").to_string();
                let hit = routes.iter().find(|r| r.0 == path).or_else(|| routes.iter().find(|r| r.0 == bare));
                let mut s = s;
                match hit {
                    Some((_, st, hs, body)) => {
                        let mut head = format!("HTTP/1.1 {st} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                        for (k, v) in hs {
                            head.push_str(&format!("{k}: {v}\r\n"));
                        }
                        head.push_str("\r\n");
                        let _ = s.write_all(head.as_bytes());
                        let _ = s.write_all(body);
                    }
                    None => {
                        let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            }
        });
        (base, log)
    }

    pub fn ok(path: &str, body: impl Into<Vec<u8>>) -> Route {
        (path.to_string(), 200, vec![], body.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_mode_stops_the_hub_ent039() {
        let s = Settings::from_table(&toml::Table::new());
        let st = Store::at(std::path::Path::new("/nonexistent/ark-hub-offline"));
        let h = Http::new(&s, &st);
        let offline = ark_net::http::NetConfig { offline: true, ..Default::default() };
        let e = ark_net::http::with_config(offline, || h.check("https://github.com/x/y")).unwrap_err();
        assert!(e.contains("skills hub") && e.contains("offline"), "{e}");
    }

    #[test]
    fn redirects_policy_and_cache() {
        let (base, log) = testserver::serve(vec![testserver::ok("/a.json", "{\"x\":1}"), ("/r".into(), 302, vec![("Location".into(), "/a.json".into())], vec![]), ("/loop".into(), 302, vec![("Location".into(), "/loop".into())], vec![])]);
        let d = ark_core::tmp::scratch_path(format!("ark-hubhttp-{}", std::process::id()));
        let st = Store::at(&d);
        let mut s = Settings::from_table(&toml::Table::new());
        let h = Http::new(&s, &st);
        assert!(h.get(&format!("{base}/a.json")).is_none(), "loopback blocked by default");
        s.hub.allow_private = true;
        let h = Http::new(&s, &st);
        assert_eq!(h.get_json(&format!("{base}/r")).unwrap()["x"], 1, "redirect followed");
        assert!(h.get(&format!("{base}/loop")).is_none(), "redirect cap");
        assert!(h.check("http://169.254.169.254/latest").is_err(), "metadata always blocked");
        let n = log.lock().unwrap().len();
        assert_eq!(h.memo("k", || h.get_json(&format!("{base}/a.json"))).unwrap()["x"], 1);
        assert_eq!(h.memo("k", || panic!("cached")).unwrap()["x"], 1);
        assert_eq!(log.lock().unwrap().len(), n + 1);
        assert_eq!(join_url("http://h/x/y.md", "z.md"), "http://h/x/z.md");
        assert_eq!(with_query("http://h/s", &[("q", "a b".into())]), "http://h/s?q=a%20b");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn github_rate_limit_retry_and_backoff_headers() {
        let (base, log) = testserver::serve(vec![
            ("/gh/limited".into(), 429, vec![("Retry-After".into(), "0".into())], vec![]),
            ("/gh/quota".into(), 403, vec![("X-RateLimit-Remaining".into(), "0".into()), ("Retry-After".into(), "0".into())], vec![]),
            ("/gh/forbidden".into(), 403, vec![("X-RateLimit-Remaining".into(), "5".into())], vec![]),
            ("/other/limited".into(), 429, vec![("Retry-After".into(), "0".into())], vec![]),
        ]);
        let d = ark_core::tmp::scratch_path(format!("ark-hubhttp-rl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::from_str(&format!("[hub]\nallow_private = true\ngithub_api = \"{base}/gh\"\n")).unwrap());
        let h = Http::new(&s, &st);
        let hits = |p: &str| log.lock().unwrap().iter().filter(|l| *l == p).count();
        // 429 and 403-with-exhausted-quota are retried up to MAX_ATTEMPTS; the final status is returned.
        assert_eq!(h.get(&format!("{base}/gh/limited")).map(|r| r.status), Some(429));
        assert_eq!(hits("/gh/limited"), MAX_ATTEMPTS);
        assert_eq!(h.get(&format!("{base}/gh/quota")).map(|r| r.status), Some(403));
        assert_eq!(hits("/gh/quota"), MAX_ATTEMPTS);
        // A 403 that is not quota exhaustion and a non-API host are single attempts.
        assert_eq!(h.get(&format!("{base}/gh/forbidden")).map(|r| r.status), Some(403));
        assert_eq!(hits("/gh/forbidden"), 1);
        assert_eq!(h.get(&format!("{base}/other/limited")).map(|r| r.status), Some(429));
        assert_eq!(hits("/other/limited"), 1);
        let mut hm = ureq::http::HeaderMap::new();
        hm.insert("retry-after", "45".parse().unwrap());
        assert_eq!(rate_limit_wait(&hm), Some(45.0));
        assert_eq!(rate_limit_wait(&ureq::http::HeaderMap::new()), None);
        let mut hm = ureq::http::HeaderMap::new();
        hm.insert("retry-after", "600".parse().unwrap());
        assert_eq!(rate_limit_wait(&hm), Some(60.0), "wait capped at 60 s");
        let mut hm = ureq::http::HeaderMap::new();
        hm.insert("x-ratelimit-reset", (ark_kernel::util::unix_now() + 30).to_string().parse().unwrap());
        assert!(rate_limit_wait(&hm).is_some_and(|w| (25.0..=30.0).contains(&w)), "reset header honoured");
        let mut hm = ureq::http::HeaderMap::new();
        hm.insert("x-ratelimit-reset", (ark_kernel::util::unix_now() - 5).to_string().parse().unwrap());
        assert_eq!(rate_limit_wait(&hm), None, "stale reset falls back to backoff");
        assert!(is_rate_limit(429, &ureq::http::HeaderMap::new()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn github_401_drops_the_rejected_token() {
        let (base, log) = testserver::serve(vec![
            ("/gh/stale".into(), 401, vec![], b"{}".to_vec()),
            ("/gh/anon".into(), 401, vec![], b"{}".to_vec()),
        ]);
        let d = ark_core::tmp::scratch_path(format!("ark-hubhttp-401-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let cfg = |env: &str| {
            Settings::from_table(&toml::from_str(&format!("[hub]\nallow_private = true\ngithub_api = \"{base}/gh\"\ngithub_token_env = \"{env}\"\n")).unwrap())
        };
        // SAFETY: test-local env var read back by this thread's Http only (never `GITHUB_TOKEN`).
        unsafe { std::env::set_var("ARK_HUB_TEST_GH_401", "ghp_stale") };
        let h = Http::new(&cfg("ARK_HUB_TEST_GH_401"), &st);
        assert_eq!(h.get(&format!("{base}/gh/stale")).map(|r| r.status), Some(401));
        unsafe { std::env::remove_var("ARK_HUB_TEST_GH_401") };
        let hits = |p: &str| log.lock().unwrap().iter().filter(|l| *l == p).count();
        assert_eq!(hits("/gh/stale"), 2, "a 401 with a token retries once without it");
        let h2 = Http::new(&cfg("ARK_HUB_TEST_GH_UNSET"), &st);
        assert_eq!(h2.get(&format!("{base}/gh/anon")).map(|r| r.status), Some(401));
        assert_eq!(hits("/gh/anon"), 1, "no credential to drop, no retry");
        let _ = std::fs::remove_dir_all(&d);
    }
}
