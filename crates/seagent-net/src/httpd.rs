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
    /// Every listener's address (two when `[::]` fell back to `[::]` + `0.0.0.0`).
    addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    /// TLS mode: the plain server behind the terminator (`bind_tls`).
    inner: Option<Box<Server>>,
}

/// Bind `addr` ([`crate::listen::tcp`]: `[::]:<port>` is dual-stack) and run `each` on every
/// listener in its own thread. Returns (first address, all addresses).
fn spawn_listeners(addr: &str, name: &str, each: impl Fn(TcpListener) + Send + Sync + 'static) -> io::Result<(SocketAddr, Vec<SocketAddr>)> {
    let ls = crate::listen::tcp(addr)?;
    let addrs = ls.iter().map(|l| l.local_addr()).collect::<io::Result<Vec<_>>>()?;
    let each = Arc::new(each);
    for l in ls {
        let e = each.clone();
        std::thread::Builder::new().name(format!("{name} {}", l.local_addr()?)).spawn(move || e(l))?;
    }
    Ok((addrs[0], addrs))
}

impl Server {
    pub fn bind(addr: &str, opts: Opts, handler: Handler) -> io::Result<Server> {
        let stop = Arc::new(AtomicBool::new(false));
        let (st, live) = (stop.clone(), Arc::new(AtomicUsize::new(0)));
        let (addr, addrs) = spawn_listeners(addr, "httpd", move |l| accept_loop(l, st.clone(), opts.clone(), handler.clone(), live.clone()))?;
        Ok(Server { addr, addrs, stop, inner: None })
    }

    /// Like [`Server::bind`], but speaking TLS (and mutual TLS when `tls.client_auth` asks for
    /// it) on `addr` — see [`crate::tlsd`]. The handler sees the real peer address, and the
    /// verified client certificate identity in the `x-seagent-tls-client` header.
    pub fn bind_tls(addr: &str, opts: Opts, handler: Handler, tls: &crate::tlsd::ServerTls) -> io::Result<Server> {
        use crate::tlsd::{H_CLIENT, H_PEER, H_SECRET};
        let cfg = tls.config().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let loopback_plain = tls.loopback_plain;
        let secret = Arc::new(crate::crypto::random_token(24));
        let s2 = secret.clone();
        let wrapped: Handler = Arc::new(move |mut r: Request| {
            if !r.header(H_SECRET).is_some_and(|v| crate::crypto::ct_eq(v.as_bytes(), s2.as_bytes())) {
                return Response::text(403, "forbidden");
            }
            let peer = r.header(H_PEER).and_then(|p| p.parse::<SocketAddr>().ok());
            let client = r.header(H_CLIENT).map(str::to_string);
            r.headers.retain(|(k, _)| !k.to_ascii_lowercase().starts_with("x-seagent-tls-"));
            r.head = r.head.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with(H_SECRET)).collect::<Vec<_>>().join("\r\n");
            if let Some(c) = client {
                r.headers.push((H_CLIENT.into(), c));
            }
            r.peer = peer.or(r.peer);
            handler(r)
        });
        let inner = Server::bind("127.0.0.1:0", opts.clone(), wrapped)?;
        let inner_addr = inner.local_addr();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let live = Arc::new(AtomicUsize::new(0));
        let (addr, addrs) = spawn_listeners(addr, "httpsd", move |l| {
            for conn in l.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(s) = conn else { continue };
                if live.load(Ordering::SeqCst) >= opts.max_conns {
                    continue; // dropped before the handshake: no plaintext 503 on a TLS port
                }
                live.fetch_add(1, Ordering::SeqCst);
                let (c, sec, lv, t, plain) = (cfg.clone(), secret.clone(), live.clone(), opts.read_timeout, loopback_plain);
                let spawned = std::thread::Builder::new().name("httpsd conn".into()).spawn(move || {
                    let _ = crate::tlsd::terminate(s, c, inner_addr, &sec, t, plain);
                    lv.fetch_sub(1, Ordering::SeqCst);
                });
                if spawned.is_err() {
                    live.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })?;
        Ok(Server { addr, addrs, stop, inner: Some(Box::new(inner)) })
    }

    /// Whether this server speaks TLS.
    pub fn is_tls(&self) -> bool {
        self.inner.is_some()
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake each blocking accept (a wildcard listener through loopback: Windows will not
        // connect to `0.0.0.0` / `::`; a dual-stack one also through 127.0.0.1).
        for a in &self.addrs {
            let mut tries = vec![*a];
            if a.ip().is_unspecified() {
                let lo: std::net::IpAddr = if a.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() };
                tries = vec![SocketAddr::new(lo, a.port()), SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), a.port())];
            }
            let _ = tries.iter().find(|t| TcpStream::connect_timeout(t, Duration::from_millis(200)).is_ok());
        }
    }
}

fn accept_loop(l: TcpListener, stop: Arc<AtomicBool>, opts: Opts, handler: Handler, live: Arc<AtomicUsize>) {
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
    // A dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`; policy sees `a.b.c.d`.
    let peer = s.peer_addr().ok().map(crate::listen::canonical);
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

    #[test]
    fn tls_and_mutual_tls_with_the_real_peer_and_client_identity() {
        let td = |f: &str| format!("{}/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"));
        let tls = crate::tlsd::ServerTls { cert: td("server.pem"), key: td("server.key"), client_ca: Some(td("ca.pem")), client_auth: crate::tlsd::ClientAuth::Optional, loopback_plain: false };
        let h: Handler = Arc::new(|r: Request| {
            Response::text(200, &format!("peer={} client={} forged={}", r.peer.map(|p| p.ip().to_string()).unwrap_or_default(), r.header("x-seagent-tls-client").unwrap_or("-"), r.header("x-seagent-tls-peer").unwrap_or("-")))
        });
        let srv = Server::bind_tls("127.0.0.1:0", Opts::default(), h, &tls).unwrap();
        assert!(srv.is_tls());
        let url = format!("https://localhost:{}/x", srv.local_addr().port());
        let get = |c: crate::http::NetConfig, forged: bool| {
            crate::http::with_config(c, || {
                let a = crate::http::agent();
                let mut rq = a.get(&url);
                if forged {
                    rq = rq.header("x-seagent-tls-client", "spiffe://evil/admin").header("x-seagent-tls-peer", "1.2.3.4:1");
                }
                rq.call().map(|mut r| r.body_mut().read_to_string().unwrap()).map_err(|e| e.to_string())
            })
        };
        let trust = crate::http::NetConfig { ca_file: Some(td("ca.pem")), ..Default::default() };
        // Server-only TLS (client sends no certificate): the peer is real, no identity, and a
        // client cannot inject the terminator's headers.
        let body = get(trust.clone(), true).unwrap();
        assert_eq!(body, "peer=127.0.0.1 client=- forged=-");
        // mTLS: the verified SPIFFE ID reaches the handler.
        let with_cert = crate::http::NetConfig { client_cert: Some(td("client.pem")), client_key: Some(td("client.key")), ..trust.clone() };
        assert_eq!(get(with_cert.clone(), false).unwrap(), "peer=127.0.0.1 client=spiffe://example.org/ark/node/n1 forged=-");
        // Without our CA the server certificate is refused (custom roots only, ent-037).
        assert!(get(crate::http::NetConfig::default(), false).is_err());
        // A certificate from an untrusted issuer fails the handshake.
        let rogue = crate::http::NetConfig { client_cert: Some(td("other.pem")), client_key: Some(td("other.key")), ..trust.clone() };
        assert!(get(rogue, false).is_err());
        // The plain server behind the terminator refuses requests that bypass it.
        let inner = srv.inner.as_ref().unwrap().local_addr();
        let r = crate::http::with_config(trust.clone(), || crate::http::agent().get(&format!("http://{inner}/x")).call().map(|r| r.status().as_u16()).unwrap_or_else(|e| if let ureq::Error::StatusCode(c) = e { c } else { 0 }));
        assert_eq!(r, 403);
        // Required client auth: a client without a certificate cannot connect at all.
        let req = crate::tlsd::ServerTls { client_auth: crate::tlsd::ClientAuth::Require, ..tls };
        let h2: Handler = Arc::new(|r: Request| Response::text(200, r.header("x-seagent-tls-client").unwrap_or("-")));
        let srv2 = Server::bind_tls("127.0.0.1:0", Opts::default(), h2, &req).unwrap();
        let url2 = format!("https://localhost:{}/", srv2.local_addr().port());
        let call2 = |c| crate::http::with_config(c, || crate::http::agent().get(&url2).call().map(|mut r| r.body_mut().read_to_string().unwrap()).map_err(|e| e.to_string()));
        assert!(call2(trust).is_err());
        assert_eq!(call2(with_cert).unwrap(), "spiffe://example.org/ark/node/n1");
    }

    /// LAN mode's port speaks TLS to everyone and also plain HTTP to loopback clients (the
    /// local console); a forged terminator header is still stripped on the plain path.
    #[test]
    fn loopback_plain_shares_the_tls_port() {
        let td = |f: &str| format!("{}/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"));
        let tls = crate::tlsd::ServerTls { cert: td("server.pem"), key: td("server.key"), loopback_plain: true, ..Default::default() };
        let h: Handler = Arc::new(|r: Request| Response::text(200, &format!("peer={} client={}", r.peer.map(|p| p.ip().to_string()).unwrap_or_default(), r.header("x-seagent-tls-client").unwrap_or("-"))));
        let srv = Server::bind_tls("127.0.0.1:0", Opts::default(), h, &tls).unwrap();
        let mut s = TcpStream::connect(srv.local_addr()).unwrap();
        s.write_all(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nx-seagent-tls-client: spiffe://evil\r\nConnection: close\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 200") && out.ends_with("peer=127.0.0.1 client=-"), "{out}");
        let trust = crate::http::NetConfig { ca_file: Some(td("ca.pem")), ..Default::default() };
        let url = format!("https://localhost:{}/x", srv.local_addr().port());
        let body = crate::http::with_config(trust, || crate::http::agent().get(&url).call().map(|mut r| r.body_mut().read_to_string().unwrap()).map_err(|e| e.to_string()));
        assert_eq!(body.unwrap(), "peer=127.0.0.1 client=-");
    }

    /// LAN mode listens on `[::]`: one TLS port reached over 127.0.0.1 and ::1, the IPv4
    /// peer reported as `127.0.0.1` (not `::ffff:127.0.0.1`), the pinned client happy with both.
    #[test]
    fn dual_stack_tls_listener_takes_ipv4_and_ipv6_clients() {
        let td = |f: &str| format!("{}/src/testdata/{f}", env!("CARGO_MANIFEST_DIR"));
        let tls = crate::tlsd::ServerTls { cert: td("server.pem"), key: td("server.key"), loopback_plain: true, ..Default::default() };
        let fp = crate::tlsd::identity_of_pem(&td("server.pem")).unwrap().fingerprint;
        let h: Handler = Arc::new(|r: Request| Response::text(200, &format!("peer={}", r.peer.map(|p| p.ip().to_string()).unwrap_or_default())));
        let srv = Server::bind_tls("[::]:0", Opts::default(), h, &tls).unwrap();
        let port = srv.local_addr().port();
        let get = |host: &str| crate::stream::pinned_request(&format!("https://{host}:{port}/x"), &fp, "GET", &[], b"", Duration::from_secs(5));
        assert_eq!(get("127.0.0.1").unwrap(), (200, "peer=127.0.0.1".to_string()));
        if srv.local_addr().is_ipv4() {
            eprintln!("skipping the IPv6 half: no IPv6 on this machine");
            return;
        }
        assert_eq!(get("[::1]").unwrap(), (200, "peer=::1".to_string()));
        // Plain HTTP from loopback still shares the port over both families.
        for a in ["127.0.0.1", "::1"] {
            let mut s = TcpStream::connect((a, port)).unwrap();
            s.write_all(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            assert!(out.ends_with(&format!("peer={a}")), "{out}");
        }
        drop(srv);
    }
}
