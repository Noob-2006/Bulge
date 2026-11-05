//! Test helpers: a scripted HTTP server (one request per connection), a scripted
//! WebSocket server, temp dirs and a tool context.

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
    // Removed when the test's thread ends (seagent_core::tmp::scratch): the callers keep their
    // `PathBuf`, and the media tests stop leaving `seagent-media-*` trees in $TMPDIR.
    seagent_core::tmp::scratch(&format!("seagent-media-{tag}"))
}

/// A scripted WebSocket server: each accepted connection runs `handler` with the
/// upgrade request head and the server-side socket. Returns `ws://127.0.0.1:port`.
pub fn ws_server(handler: impl Fn(String, &mut seagent_net::ws::WebSocket<std::net::TcpStream>) + Send + Sync + 'static) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", l.local_addr().unwrap());
    let h = Arc::new(handler);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let h = h.clone();
            std::thread::spawn(move || {
                let Ok((head, rest)) = seagent_net::ws::read_head(&mut s, 64 * 1024) else { return };
                let Ok(mut ws) = seagent_net::ws::WebSocket::accept(s, &head, rest) else { return };
                h(head, &mut ws);
            });
        }
    });
    url
}

#[derive(Default)]
pub struct FakeHost {
    pub progress: Mutex<Vec<String>>,
}

impl seagent_core::ToolHost for FakeHost {
    fn spawn_agent(&self, _req: seagent_core::tool::SpawnRequest, _c: &seagent_core::Cancel) -> Result<String, String> {
        Err("no sub-agents in tests".into())
    }
    fn ask_user(&self, _q: &str) -> Result<String, String> {
        Err("headless".into())
    }
    fn progress(&self, t: &str) {
        self.progress.lock().unwrap().push(t.to_string());
    }
}

/// A tool context rooted in a fresh temp workspace.
pub fn ctx(tag: &str) -> seagent_core::ToolCtx {
    let ws = temp_dir(tag);
    seagent_core::ToolCtx {
        artifacts: ws.join(".artifacts"),
        home: ws.join(".home"),
        workspace: ws,
        session_id: "s-test".into(),
        cancel: seagent_core::Cancel::new(),
        host: Arc::new(FakeHost::default()),
        secrets: Arc::new(|s: &str| s.to_string()),
    }
}

/// A config whose provider `id` points at `base` with key `k`; `extra` is TOML placed
/// before it (top-level keys or other `[sections]`).
pub fn cfg_for(id: &str, base: &str, extra: &str) -> crate::MediaConfig {
    crate::MediaConfig::from_toml(&format!("{extra}\n[providers.{id}]\napi_key = \"k\"\nbase_url = \"{base}\"\n"))
}
