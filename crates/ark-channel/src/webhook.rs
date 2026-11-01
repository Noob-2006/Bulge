//! Generic webhook channel. Outbound: JSON POST to a URL. Inbound: a minimal
//! HTTP/1.1 listener accepting `POST /inbound` with a bearer token.

use crate::http::{agent, post_cancellable};
use crate::{sleep_cancellable, Channel, ChannelError, ChannelErrorKind as K, Inbound, Outbound};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_BODY: usize = 1024 * 1024;
const MAX_HEAD: usize = 16 * 1024;

pub struct Webhook {
    id: String,
    outbound_url: Option<String>,
    outbound_token: Option<String>,
    agent: ureq::Agent,
    rx: Mutex<Receiver<Inbound>>,
    server: Option<Server>,
    poll_timeout: Duration,
    pub retry_base: Duration,
    pub max_retries: u32,
}

struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook").field("id", &self.id).field("listen", &self.local_addr()).field("outbound", &self.outbound_url.is_some()).finish()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wake accept()
    }
}

pub struct WebhookOpts<'a> {
    pub listen: Option<&'a str>,
    pub token: Option<&'a str>,
    pub outbound_url: Option<&'a str>,
    pub outbound_token: Option<&'a str>,
    pub poll_timeout: Duration,
}

impl Webhook {
    pub fn new(id: &str, o: WebhookOpts) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let server = match o.listen {
            None => None,
            Some(addr) => {
                let token = o.token.map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| format!("channel {id}: an inbound webhook needs a token"))?;
                let l = TcpListener::bind(addr).map_err(|e| format!("channel {id}: cannot listen on {addr}: {e}"))?;
                let addr = l.local_addr().map_err(|e| e.to_string())?;
                let stop = Arc::new(AtomicBool::new(false));
                let (s, t, ch) = (stop.clone(), token.to_string(), id.to_string());
                std::thread::spawn(move || accept_loop(l, s, t, ch, tx));
                Some(Server { addr, stop })
            }
        };
        if server.is_none() && o.outbound_url.is_none() {
            return Err(format!("channel {id}: webhook needs `listen` and/or `outbound_url`"));
        }
        Ok(Webhook {
            id: id.to_string(),
            outbound_url: o.outbound_url.map(str::to_string),
            outbound_token: o.outbound_token.map(str::to_string).filter(|t| !t.is_empty()),
            agent: agent(Duration::from_secs(30)),
            rx: Mutex::new(rx),
            server,
            poll_timeout: o.poll_timeout,
            retry_base: Duration::from_millis(200),
            max_retries: 2,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(|s| s.addr)
    }
}

fn accept_loop(l: TcpListener, stop: Arc<AtomicBool>, token: String, channel: String, tx: Sender<Inbound>) {
    let token = Arc::new(token);
    for stream in l.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else { continue };
        let (t, c, tx) = (token.clone(), channel.clone(), tx.clone());
        std::thread::spawn(move || handle(stream, &t, &c, &tx));
    }
}

fn respond(s: &mut TcpStream, status: u16, msg: &str) {
    let reason = match status {
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let body = if status == 202 { msg.to_string() } else { json!({ "ok": false, "error": msg }).to_string() };
    let _ = write!(s, "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    // Lingering close: drain what the client is still sending so the kernel
    // doesn't answer with RST and destroy the response before it is read.
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 4096];
    let mut drained = 0;
    while drained < 2 * MAX_BODY {
        match s.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// Constant-time comparison so the token can't be guessed byte by byte.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn id_str(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).filter(|s| !s.is_empty()).or_else(|| v.as_i64().map(|n| n.to_string()))
}

fn handle(mut s: TcpStream, token: &str, channel: &str, tx: &Sender<Inbound>) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if i > MAX_HEAD {
                return respond(&mut s, 431, "headers too large");
            }
            break i;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut s, 431, "headers too large");
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut rl = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (rl.next().unwrap_or(""), rl.next().unwrap_or(""));
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let h = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    if path.split('?').next() != Some("/inbound") {
        return respond(&mut s, 404, "not found");
    }
    if method != "POST" {
        return respond(&mut s, 405, "use POST");
    }
    let auth = h("authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
    if !same(auth.trim().as_bytes(), token.as_bytes()) {
        return respond(&mut s, 401, "bad or missing bearer token");
    }
    if h("transfer-encoding").is_some() {
        return respond(&mut s, 411, "chunked bodies are not supported; send Content-Length");
    }
    let Some(len) = h("content-length") else { return respond(&mut s, 411, "Content-Length required") };
    let Ok(len) = len.parse::<usize>() else { return respond(&mut s, 400, "bad Content-Length") };
    if len > MAX_BODY {
        return respond(&mut s, 413, "body over 1 MiB");
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return respond(&mut s, 400, "body shorter than Content-Length"),
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(len);
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return respond(&mut s, 400, "body must be a JSON object"),
        Err(e) => return respond(&mut s, 400, &format!("malformed JSON: {e}")),
    };
    let (Some(chat), Some(sender), Some(text)) = (id_str(&v["chat"]), id_str(&v["sender"]), v["text"].as_str().filter(|t| !t.trim().is_empty())) else {
        return respond(&mut s, 400, "need `chat`, `sender` and non-empty `text`");
    };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let message_id = id_str(&v["id"]).unwrap_or_else(|| format!("wh-{ts}-{}", SEQ.fetch_add(1, Ordering::SeqCst)));
    let m = Inbound { channel: channel.to_string(), chat, sender, sender_name: v["sender_name"].as_str().unwrap_or("").to_string(), text: text.to_string(), message_id: message_id.clone(), ts };
    if tx.send(m).is_err() {
        return respond(&mut s, 404, "channel closed");
    }
    respond(&mut s, 202, &json!({ "ok": true, "message_id": message_id }).to_string());
}

impl Channel for Webhook {
    fn id(&self) -> &str {
        &self.id
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if self.server.is_none() {
            sleep_cancellable(self.poll_timeout, cancel);
            return Ok(vec![]);
        }
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        let mut out = vec![];
        while !cancel.is_cancelled() && Instant::now() < until {
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok(m) => {
                    out.push(m);
                    out.extend(rx.try_iter());
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Fatal, "webhook listener stopped")),
            }
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<(), ChannelError> {
        let url = self.outbound_url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, format!("channel {} has no outbound_url", self.id)))?;
        let headers: Vec<(String, String)> = self.outbound_token.iter().map(|t| ("authorization".to_string(), format!("Bearer {t}"))).collect();
        let body = serde_json::to_vec(&json!({ "chat": out.chat, "text": out.text, "reply_to": out.reply_to })).expect("json");
        let cancel = Cancel::new();
        let mut attempt = 0;
        loop {
            let err = match post_cancellable(&self.agent, url, &headers, body.clone(), &cancel) {
                Ok(Some(r)) => match r.status {
                    200..=299 => return Ok(()),
                    401 | 403 => return Err(ChannelError::new(K::Auth, format!("webhook rejected credentials (HTTP {})", r.status))),
                    429 => ChannelError::new(K::RateLimited { retry_after: r.retry_after }, "webhook rate limited"),
                    s if s >= 500 => ChannelError::new(K::Network, format!("webhook HTTP {s}")),
                    s => return Err(ChannelError::new(K::Protocol, format!("webhook HTTP {s}: {}", r.body.chars().take(200).collect::<String>()))),
                },
                Ok(None) => return Err(ChannelError::new(K::Network, "cancelled")),
                Err(e) => e,
            };
            if attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(10) => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            sleep_cancellable(wait, &cancel);
            attempt += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;

    fn inbound_only() -> Webhook {
        Webhook::new("wh", WebhookOpts { listen: Some("127.0.0.1:0"), token: Some("tok"), outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(300) }).unwrap()
    }

    /// Raw request; returns (status, body).
    fn raw(addr: SocketAddr, req: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(req).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let status = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        (status, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
    }

    fn post(addr: SocketAddr, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
        let a = auth.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
        raw(addr, format!("POST {path} HTTP/1.1\r\nHost: x\r\n{a}Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
    }

    #[test]
    fn accepts_authorised_messages_and_rejects_everything_else() {
        let w = inbound_only();
        let a = w.local_addr().unwrap();
        let good = r#"{"chat":"c1","sender":7,"text":"hello","id":"m1"}"#;
        assert_eq!(post(a, "/inbound", None, good).0, 401);
        assert_eq!(post(a, "/inbound", Some("tok2"), good).0, 401);
        assert_eq!(post(a, "/inbound", Some("to"), good).0, 401);
        assert_eq!(post(a, "/other", Some("tok"), good).0, 404);
        assert_eq!(raw(a, b"GET /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\n\r\n").0, 405);
        assert_eq!(post(a, "/inbound", Some("tok"), "{not json").0, 400);
        assert_eq!(post(a, "/inbound", Some("tok"), "[1,2]").0, 400);
        assert_eq!(post(a, "/inbound", Some("tok"), r#"{"chat":"c","sender":"s","text":"  "}"#).0, 400);
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").0, 411);
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\n\r\n").0, 411);
        let big = format!("POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(raw(a, big.as_bytes()).0, 413, "rejected before reading the body");
        let huge_head = format!("POST /inbound HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD + 10));
        assert_eq!(raw(a, huge_head.as_bytes()).0, 431);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty(), "nothing rejected got through");

        let (st, body) = post(a, "/inbound", Some("tok"), good);
        assert_eq!(st, 202, "{body}");
        assert!(body.contains("\"m1\""));
        assert_eq!(post(a, "/inbound?x=1", Some("tok"), r#"{"chat":5,"sender":"u","text":"two"}"#).0, 202);
        std::thread::sleep(Duration::from_millis(50));
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].text.as_str(), got[0].message_id.as_str()), ("c1", "7", "hello", "m1"));
        assert_eq!(got[1].chat, "5");
        assert!(got[1].message_id.starts_with("wh-"));
    }

    #[test]
    fn slow_or_truncated_clients_do_not_wedge_the_listener() {
        let w = inbound_only();
        let a = w.local_addr().unwrap();
        // Client promises 100 bytes and hangs up after 3.
        let mut half = TcpStream::connect(a).unwrap();
        half.write_all(b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nContent-Length: 100\r\n\r\n{\"a").unwrap();
        half.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = String::new();
        let _ = half.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        let _idle = TcpStream::connect(a).unwrap(); // never sends anything
        assert_eq!(post(a, "/inbound", Some("tok"), r#"{"chat":"c","sender":"s","text":"ok"}"#).0, 202);
        let c = Cancel::new();
        assert_eq!(w.poll(&c).unwrap().len(), 1);
        // Timeout and cancel both return empty quickly.
        let t = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_secs(2));
        c.cancel();
        assert!(w.poll(&c).unwrap().is_empty());
    }

    #[test]
    fn listener_requires_token_and_free_port() {
        let o = |listen, token| WebhookOpts { listen, token, outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(10) };
        assert!(Webhook::new("w", o(Some("127.0.0.1:0"), None)).unwrap_err().contains("token"));
        assert!(Webhook::new("w", o(Some("127.0.0.1:0"), Some(" "))).is_err());
        assert!(Webhook::new("w", o(None, None)).unwrap_err().contains("outbound_url"));
        let w = inbound_only();
        let taken = w.local_addr().unwrap().to_string();
        assert!(Webhook::new("w", o(Some(&taken), Some("t"))).unwrap_err().contains("cannot listen"));
        drop(w);
    }

    #[test]
    fn outbound_posts_json_with_bearer_and_maps_errors() {
        let srv = FakeServer::start(|req, _| match req.json()["chat"].as_str() {
            Some("ok") => (200, vec![], "{}".into()),
            Some("auth") => (403, vec![], "".into()),
            Some("bad") => (422, vec![], "unprocessable".into()),
            Some("slow") => (429, vec![("Retry-After".into(), "120".into())], "".into()),
            _ => (503, vec![], "".into()),
        });
        let mut w = Webhook::new("wh", WebhookOpts { listen: None, token: None, outbound_url: Some(&format!("{}/hook", srv.url)), outbound_token: Some("out"), poll_timeout: Duration::from_millis(10) }).unwrap();
        w.retry_base = Duration::from_millis(1);
        let send = |chat: &str| w.send(&Outbound { chat: chat.into(), text: "hi".into(), reply_to: Some("r".into()) });
        send("ok").unwrap();
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/hook", Some("Bearer out")));
        assert_eq!(r.json(), json!({"chat": "ok", "text": "hi", "reply_to": "r"}));
        assert_eq!(send("auth").unwrap_err().kind, K::Auth);
        assert_eq!(send("bad").unwrap_err().kind, K::Protocol);
        assert_eq!(send("slow").unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(120)) });
        let before = srv.requests().len();
        assert_eq!(send("down").unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len() - before, 3, "retried 5xx");
        // Inbound-only channel cannot send; outbound-only poll just waits.
        assert_eq!(inbound_only().send(&Outbound { chat: "c".into(), text: "x".into(), reply_to: None }).unwrap_err().kind, K::Fatal);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty());
    }
}
