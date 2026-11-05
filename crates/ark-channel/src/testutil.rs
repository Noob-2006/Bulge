//! Scripted HTTP server for tests (one request per connection).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Req {
    #[allow(dead_code)]
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    #[allow(dead_code)]
    pub raw: Vec<u8>,
}

impl Req {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }
}

pub type Reply = (u16, Vec<(String, String)>, String);
pub type RawReply = (u16, Vec<(String, String)>, Vec<u8>);

pub struct FakeServer {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Req>>>,
}

impl FakeServer {
    pub fn start(handler: impl Fn(&Req, usize) -> Reply + Send + 'static) -> FakeServer {
        FakeServer::start_raw(move |r, n| {
            let (s, h, b) = handler(r, n);
            (s, h, b.into_bytes())
        })
    }
    /// Binary request/response bodies (media).
    pub fn start_raw(handler: impl Fn(&Req, usize) -> RawReply + Send + 'static) -> FakeServer {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut headers = vec![];
                let mut len = 0;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let req = Req { method, path, headers, body: String::from_utf8_lossy(&body).into_owned(), raw: body };
                let n = {
                    let mut g = s2.lock().unwrap();
                    g.push(req.clone());
                    g.len() - 1
                };
                let (status, hs, body) = handler(&req, n);
                let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                for (k, v) in hs {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                let mut bytes = out.into_bytes();
                bytes.extend_from_slice(&body);
                let _ = stream.write_all(&bytes);
            }
        });
        FakeServer { url, seen }
    }
    pub fn requests(&self) -> Vec<Req> {
        self.seen.lock().unwrap().clone()
    }
}

pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    // Removed when the test's thread ends (ark_core::tmp::scratch): a plain `PathBuf` for the
    // callers, no tree left in $TMPDIR after the suite.
    let d = ark_core::tmp::scratch(&format!("ark-ch-{tag}"));
    crate::media_guard::allow_for_tests(&d);
    d
}

/// A `ToolCtx` for channel-tool tests (no host services).
pub fn tool_ctx() -> ark_core::ToolCtx {
    struct H;
    impl ark_core::ToolHost for H {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }
    let d = ark_core::tmp::scratch("ark-ch-ctx");
    ark_core::ToolCtx { workspace: d.clone(), session_id: "s".into(), artifacts: d.clone(), home: d, cancel: ark_core::Cancel::new(), host: Arc::new(H), secrets: Arc::new(|s: &str| s.to_string()) }
}
