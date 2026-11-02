//! A small threaded HTTP/1.1 server: webhook ingress for channels, OAuth
//! redirect callbacks, the app server's REST/SSE endpoints and WebSocket
//! upgrades. One thread per connection with a hard cap, strict header/body
//! limits and read timeouts so slow or hostile clients cannot wedge it.
//! Every response closes the connection; no keep-alive bookkeeping.

use crate::stream::parse_query;
use crate::ws::read_head;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub raw_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: Option<SocketAddr>,
    /// The raw head, kept for WebSocket upgrades.
    pub head: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
    pub fn is_upgrade(&self) -> bool {
        self.header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    }
    /// `Authorization: Bearer <t>` value.
    pub fn bearer(&self) -> Option<&str> {
        let h = self.header("authorization")?;
        h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")).map(str::trim)
    }
}

pub type StreamFn = Box<dyn FnOnce(&mut dyn Write) -> io::Result<()> + Send>;
pub type UpgradeFn = Box<dyn FnOnce(TcpStream, String, Vec<u8>) + Send>;

pub enum Body {
    Bytes(Vec<u8>),
    /// Written after the head; the connection closes when the closure returns (SSE, downloads).
    Stream(StreamFn),
    /// Hand the raw socket to the closure (WebSocket); no response is written by the server.
    Upgrade(UpgradeFn),
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
        Response { status, headers: vec![("content-type".into(), content_type.into())], body: Body::Bytes(body.into()) }
    }
    pub fn text(status: u16, body: &str) -> Response {
        Response::new(status, "text/plain; charset=utf-8", body.as_bytes().to_vec())
    }
    pub fn json(status: u16, v: &impl serde_like::ToJson) -> Response {
        Response::new(status, "application/json", v.to_json().into_bytes())
    }
    pub fn html(body: &str) -> Response {
        Response::new(200, "text/html; charset=utf-8", body.as_bytes().to_vec())
    }
    pub fn empty(status: u16) -> Response {
        Response { status, headers: vec![], body: Body::Bytes(vec![]) }
    }
    pub fn sse(f: StreamFn) -> Response {
        Response {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into()), ("cache-control".into(), "no-cache".into())],
            body: Body::Stream(f),
        }
    }
    pub fn upgrade(f: UpgradeFn) -> Response {
        Response { status: 101, headers: vec![], body: Body::Upgrade(f) }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }
}

/// Keeps this crate free of serde: anything that renders itself as JSON text.
pub mod serde_like {
    pub trait ToJson {
        fn to_json(&self) -> String;
    }
    impl ToJson for String {
        fn to_json(&self) -> String {
            self.clone()
        }
    }
    impl ToJson for &str {
        fn to_json(&self) -> String {
            self.to_string()
        }
    }
}

pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Opts {
    pub max_body: usize,
    pub max_conns: usize,
    pub read_timeout: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { max_body: 8 * 1024 * 1024, max_conns: 64, read_timeout: Duration::from_secs(15) }
    }
}

pub struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn bind(addr: &str, opts: Opts, handler: Handler) -> io::Result<Server> {
        let l = TcpListener::bind(addr)?;
        let addr = l.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        std::thread::Builder::new().name(format!("httpd {addr}")).spawn(move || accept_loop(l, st, opts, handler))?;
        Ok(Server { addr, stop })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

fn accept_loop(l: TcpListener, stop: Arc<AtomicBool>, opts: Opts, handler: Handler) {
    let live = Arc::new(AtomicUsize::new(0));
    for conn in l.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut s) = conn else { continue };
        if live.load(Ordering::SeqCst) >= opts.max_conns {
            let _ = write_simple(&mut s, 503, "busy");
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (h, o, lv) = (handler.clone(), opts.clone(), live.clone());
        let spawned = std::thread::Builder::new().name("httpd conn".into()).spawn(move || {
            serve(s, &o, &h);
            lv.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn write_simple(s: &mut TcpStream, status: u16, msg: &str) -> io::Result<()> {
    write!(s, "HTTP/1.1 {status} {}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{msg}", reason(status), msg.len())
}

/// (method, path, raw query, headers)
pub type RequestLine = (String, String, String, Vec<(String, String)>);

pub fn parse_request(head: &str) -> Option<RequestLine> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    if !first.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let headers = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Some((method, path, query, headers))
}

fn read_body(s: &mut TcpStream, headers: &[(String, String)], mut have: Vec<u8>, max: usize) -> Result<Vec<u8>, u16> {
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
    if get("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
        let mut out = Vec::new();
        loop {
            let line = loop {
                if let Some(i) = have.windows(2).position(|w| w == b"\r\n") {
                    let l = String::from_utf8_lossy(&have[..i]).into_owned();
                    have.drain(..i + 2);
                    break l;
                }
                fill(s, &mut have, max)?;
            };
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| 400u16)?;
            if out.len() + size > max {
                return Err(413);
            }
            while have.len() < size + 2 {
                fill(s, &mut have, max + 2)?;
            }
            if size == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&have[..size]);
            have.drain(..size + 2);
        }
    }
    let len: usize = match get("content-length") {
        Some(v) => v.parse().map_err(|_| 400u16)?,
        None => 0,
    };
    if len > max {
        return Err(413);
    }
    while have.len() < len {
        fill(s, &mut have, max)?;
    }
    have.truncate(len);
    Ok(have)
}

/// Closing with unread input makes the kernel send RST, which can destroy the error
/// response before the client reads it. Half-close, then drain briefly (bounded).
fn linger(s: &mut TcpStream) {
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let mut sink = [0u8; 16 * 1024];
    let mut left = 4usize << 20;
    while left > 0 {
        match s.read(&mut sink) {
            Ok(n) if n > 0 => left = left.saturating_sub(n),
            _ => break,
        }
    }
}

fn fill(s: &mut TcpStream, buf: &mut Vec<u8>, max: usize) -> Result<(), u16> {
    if buf.len() > max + 64 {
        return Err(413);
    }
    let mut chunk = [0u8; 16 * 1024];
    match s.read(&mut chunk) {
        Ok(0) => Err(400),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(_) => Err(408),
    }
}

fn serve(mut s: TcpStream, opts: &Opts, handler: &Handler) {
    let _ = s.set_read_timeout(Some(opts.read_timeout));
    let _ = s.set_write_timeout(Some(opts.read_timeout));
    let peer = s.peer_addr().ok();
    let Ok((head, rest)) = read_head(&mut s, 32 * 1024) else {
        let _ = write_simple(&mut s, 400, "bad request");
        return;
    };
    let Some((method, path, raw_query, headers)) = parse_request(&head) else {
        let _ = write_simple(&mut s, 400, "bad request");
        return;
    };
    let upgrade = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"));
    let (body, leftover) = if upgrade {
        (Vec::new(), rest)
    } else {
        match read_body(&mut s, &headers, rest, opts.max_body) {
            Ok(b) => (b, Vec::new()),
            Err(code) => {
                let _ = write_simple(&mut s, code, "request body rejected");
                linger(&mut s);
                return;
            }
        }
    };
    let req = Request { method, query: parse_query(&raw_query), path, raw_query, headers, body, peer, head: head.clone() };
    let resp = handler(req);
    match resp.body {
        Body::Upgrade(f) => {
            let _ = s.set_read_timeout(None);
            f(s, head, leftover);
            return;
        }
        Body::Bytes(b) => {
            let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
            for (k, v) in &resp.headers {
                out.push_str(&format!("{k}: {v}\r\n"));
            }
            out.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", b.len()));
            let _ = s.write_all(out.as_bytes()).and_then(|_| s.write_all(&b)).and_then(|_| s.flush());
        }
        Body::Stream(f) => {
            let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
            for (k, v) in &resp.headers {
                out.push_str(&format!("{k}: {v}\r\n"));
            }
            out.push_str("connection: close\r\n\r\n");
            if s.write_all(out.as_bytes()).and_then(|_| s.flush()).is_ok() {
                let _ = s.set_write_timeout(None);
                let _ = f(&mut s);
            }
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{Message, WebSocket};

    fn raw(addr: SocketAddr, req: &[u8]) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(req).unwrap();
        let mut out = String::new();
        let _ = c.read_to_string(&mut out);
        out
    }

    fn server() -> Server {
        let h: Handler = Arc::new(|r: Request| match (r.method.as_str(), r.path.as_str()) {
            ("POST", "/echo") => Response::text(200, &format!("{}|{}|{}", r.query("a").unwrap_or(""), r.header("x-sig").unwrap_or(""), r.body_str())),
            ("GET", "/events") => Response::sse(Box::new(|w| {
                for i in 0..3 {
                    write!(w, "data: {i}\n\n")?;
                    w.flush()?;
                }
                Ok(())
            })),
            ("GET", "/ws") if r.is_upgrade() => Response::upgrade(Box::new(|s, head, rest| {
                let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                if let Ok(Message::Text(t)) = ws.recv_blocking() {
                    ws.send_text(&t.to_uppercase()).unwrap();
                }
            })),
            _ => Response::text(404, "nope"),
        });
        Server::bind("127.0.0.1:0", Opts { max_body: 64, max_conns: 4, read_timeout: Duration::from_millis(500) }, h).unwrap()
    }

    #[test]
    fn routes_bodies_chunked_sse_and_websocket() {
        let srv = server();
        let a = srv.local_addr();
        let r = raw(a, b"POST /echo?a=1%202 HTTP/1.1\r\nHost: x\r\nX-Sig: s\r\nContent-Length: 5\r\n\r\nhello");
        assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("1 2|s|hello"), "{r}");
        let r = raw(a, b"POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext\r\nde\r\n0\r\n\r\n");
        assert!(r.ends_with("||abcde"), "{r}");
        let r = raw(a, b"GET /events HTTP/1.1\r\n\r\n");
        assert!(r.contains("text/event-stream") && r.ends_with("data: 0\n\ndata: 1\n\ndata: 2\n\n"), "{r}");
        assert!(raw(a, b"GET /missing HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
        let (mut ws, _) = WebSocket::connect(&format!("ws://{a}/ws"), &[], Duration::from_secs(2)).unwrap();
        ws.send_text("shout").unwrap();
        assert_eq!(ws.recv_blocking().unwrap(), Message::Text("SHOUT".into()));
    }

    #[test]
    fn rejects_oversize_malformed_and_slow_requests() {
        let srv = server();
        let a = srv.local_addr();
        assert!(raw(a, b"POST /echo HTTP/1.1\r\nContent-Length: 999\r\n\r\n").starts_with("HTTP/1.1 413"));
        assert!(raw(a, b"POST /echo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFF\r\n").starts_with("HTTP/1.1 413"));
        assert!(raw(a, b"garbage\r\n\r\n").starts_with("HTTP/1.1 400"));
        // A client that sends half a body and stalls gets a timeout, and the server keeps serving.
        let mut slow = TcpStream::connect(a).unwrap();
        slow.write_all(b"POST /echo HTTP/1.1\r\nContent-Length: 10\r\n\r\nab").unwrap();
        let r = raw(a, b"POST /echo HTTP/1.1\r\nContent-Length: 2\r\n\r\nok");
        assert!(r.ends_with("||ok"), "{r}");
        let mut out = String::new();
        let _ = slow.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 408"), "{out}");
    }
}
