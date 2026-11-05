//! Local fake HTTP server for provider tests (never a real API).

use super::config::WebConfig;
use super::http::{EnvFn, WebCtx};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// The search memo is process-wide: tests that clear it or assert a cache hit hold this lock so
/// a parallel test's `clear()` cannot run between their two calls.
static SEARCH_MEMO_LOCK: Mutex<()> = Mutex::new(());

pub fn search_memo_guard() -> std::sync::MutexGuard<'static, ()> {
    SEARCH_MEMO_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Default)]
pub struct Req {
    /// Request line + headers as received.
    pub head: String,
    pub method: String,
    /// Path including the query string.
    pub path: String,
    pub body: String,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<String> {
        let want = format!("{}:", name.to_ascii_lowercase());
        self.head.lines().find(|l| l.to_ascii_lowercase().starts_with(&want)).map(|l| l[want.len()..].trim().to_string())
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
    /// Decoded query parameter.
    pub fn query(&self, k: &str) -> Option<String> {
        let q = self.path.split_once('?')?.1;
        q.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=').unwrap_or((kv, ""));
            (a == k).then(|| super::ssrf::percent_decode(b))
        })
    }
}

/// `(status, content-type, body, extra headers)`.
pub type Reply = (u16, String, Vec<u8>, Vec<(String, String)>);
type Handler = Arc<dyn Fn(&Req) -> Reply + Send + Sync>;

pub struct FakeServer {
    pub url: String,
    reqs: Arc<Mutex<Vec<Req>>>,
}

impl FakeServer {
    /// Routes: `"METHOD /path"` (query ignored) → status, content type, body. Unmatched → 404.
    pub fn start(routes: Vec<(&str, u16, &str, String)>) -> FakeServer {
        let routes: Vec<(String, u16, String, String)> = routes.into_iter().map(|(k, s, c, b)| (k.to_string(), s, c.to_string(), b)).collect();
        Self::with(move |r| {
            let key = format!("{} {}", r.method, r.path.split('?').next().unwrap_or(""));
            match routes.iter().find(|(k, ..)| *k == key) {
                Some((_, s, c, b)) => (*s, c.clone(), b.clone().into_bytes(), vec![]),
                None => (404, "text/plain".into(), format!("no route {key}").into_bytes(), vec![]),
            }
        })
    }

    pub fn with(handler: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> FakeServer {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let (h, rq): (Handler, _) = (Arc::new(handler), reqs.clone());
        thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let (h, rq) = (h.clone(), rq.clone());
                thread::spawn(move || {
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    loop {
                        let mut head = String::new();
                        let mut len = 0usize;
                        let mut chunked = false;
                        loop {
                            let mut line = String::new();
                            if r.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            if line == "\r\n" {
                                break;
                            }
                            let lower = line.to_ascii_lowercase();
                            if let Some(v) = lower.strip_prefix("content-length:") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                            chunked |= lower.starts_with("transfer-encoding:") && lower.contains("chunked");
                            head.push_str(&line);
                        }
                        let mut body = vec![0u8; len];
                        if chunked {
                            body.clear();
                            loop {
                                let mut sz = String::new();
                                r.read_line(&mut sz).unwrap();
                                let n = usize::from_str_radix(sz.trim(), 16).unwrap_or(0);
                                let mut chunk = vec![0u8; n + 2];
                                r.read_exact(&mut chunk).unwrap();
                                if n == 0 {
                                    break;
                                }
                                body.extend_from_slice(&chunk[..n]);
                            }
                        } else if r.read_exact(&mut body).is_err() {
                            return;
                        }
                        let first = head.lines().next().unwrap_or("").to_string();
                        let mut parts = first.split_whitespace();
                        let req = Req { method: parts.next().unwrap_or("").into(), path: parts.next().unwrap_or("").into(), head: head.clone(), body: String::from_utf8_lossy(&body).into_owned() };
                        rq.lock().unwrap().push(req.clone());
                        let (status, ctype, body, extra) = h(&req);
                        let mut out = format!("HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n", body.len());
                        for (k, v) in extra {
                            out.push_str(&format!("{k}: {v}\r\n"));
                        }
                        out.push_str("\r\n");
                        if s.write_all(out.as_bytes()).is_err() || s.write_all(&body).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeServer { url, reqs }
    }

    pub fn requests(&self) -> Vec<Req> {
        self.reqs.lock().unwrap().clone()
    }
    pub fn last(&self) -> Req {
        self.requests().pop().expect("no request received")
    }
}

/// Env lookup from a fixed map.
pub fn env_of(pairs: &[(&str, &str)]) -> EnvFn {
    let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Arc::new(move |k: &str| m.get(k).cloned())
}

/// A context whose `[web]` table is `cfg` (JSON) and whose environment is `env`.
pub fn wctx(cfg: serde_json::Value, env: &[(&str, &str)]) -> WebCtx {
    let mut c = WebCtx::new(Arc::new(WebConfig::from_value(cfg).unwrap()), env_of(env));
    c.spill_dir = crate::testutil::tmpdir("webspill");
    c.home = c.spill_dir.clone();
    c
}
