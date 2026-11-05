//! RFC 6455 WebSocket, client and server side, over any blocking stream.
//! Used by Discord/Slack/Mattermost/Feishu/QQ gateways, Nostr relays, the
//! node protocol and the app server. `recv` returns `Ok(None)` when the
//! stream's read timeout fires, keeping partial frames buffered, so a caller
//! can interleave heartbeats and outgoing messages on one thread.

use crate::crypto;
use crate::stream::{is_timeout, Stream, Url};
use std::io::{self, Read, Write};
use std::time::Duration;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest message we accept (Discord READY payloads can reach a few MB).
pub const DEFAULT_MAX: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Client,
    Server,
}

pub struct WebSocket<S: Read + Write> {
    s: S,
    buf: Vec<u8>,
    role: Role,
    frag: Option<(u8, Vec<u8>)>,
    max: usize,
    closed: bool,
}

pub fn accept_key(key: &str) -> String {
    crypto::b64(&crypto::sha1(format!("{}{GUID}", key.trim()).as_bytes()))
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Read an HTTP head (up to the blank line). Returns (head, leftover bytes).
pub fn read_head<S: Read>(s: &mut S, limit: usize) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() > limit {
            return Err(bad("HTTP head too large"));
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during HTTP head"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Header lookup in a raw HTTP head (case-insensitive name).
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

impl WebSocket<Stream> {
    /// Connect to `ws://` or `wss://`. Returns the socket and the server's response head.
    pub fn connect(url: &str, headers: &[(&str, &str)], timeout: Duration) -> io::Result<(Self, String)> {
        let u = Url::parse(url).map_err(bad)?;
        let mut s = Stream::connect(&u.host, u.port, u.tls(), timeout)?;
        let key = crypto::b64(&crypto::random_bytes(16));
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: seagent\r\n",
            u.path,
            u.host_header()
        );
        for (k, v) in headers {
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
                return Err(bad("header contains a newline"));
            }
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())?;
        s.flush()?;
        let (head, rest) = read_head(&mut s, 64 * 1024)?;
        let status = head.split_whitespace().nth(1).unwrap_or("");
        if status != "101" {
            return Err(bad(format!("websocket upgrade refused: {}", head.lines().next().unwrap_or(""))));
        }
        if header(&head, "sec-websocket-accept") != Some(accept_key(&key).as_str()) {
            return Err(bad("bad Sec-WebSocket-Accept"));
        }
        let mut ws = WebSocket::from_stream(s, true);
        ws.buf = rest;
        Ok((ws, head))
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.s.set_read_timeout(d)
    }

    pub fn shutdown_handle(&self) -> io::Result<std::net::TcpStream> {
        self.s.shutdown_handle()
    }
}

impl<S: Read + Write> WebSocket<S> {
    /// Wrap an already-upgraded stream. `client` = we mask outgoing frames.
    pub fn from_stream(s: S, client: bool) -> Self {
        WebSocket { s, buf: Vec::new(), role: if client { Role::Client } else { Role::Server }, frag: None, max: DEFAULT_MAX, closed: false }
    }

    /// Server side: answer an upgrade request whose head was already read.
    pub fn accept(mut s: S, request_head: &str, leftover: Vec<u8>) -> io::Result<Self> {
        let key = header(request_head, "sec-websocket-key").ok_or_else(|| bad("missing Sec-WebSocket-Key"))?;
        let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept_key(key));
        s.write_all(resp.as_bytes())?;
        s.flush()?;
        let mut ws = WebSocket::from_stream(s, false);
        ws.buf = leftover;
        Ok(ws)
    }

    /// Bytes already read past the HTTP head (start of the first frame).
    pub fn with_leftover(mut self, rest: Vec<u8>) -> Self {
        self.buf = rest;
        self
    }

    pub fn set_max_message(&mut self, max: usize) {
        self.max = max;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn get_ref(&self) -> &S {
        &self.s
    }

    pub fn send_text(&mut self, t: &str) -> io::Result<()> {
        self.write_frame(0x1, t.as_bytes())
    }

    pub fn send(&mut self, m: &Message) -> io::Result<()> {
        match m {
            Message::Text(t) => self.write_frame(0x1, t.as_bytes()),
            Message::Binary(b) => self.write_frame(0x2, b),
            Message::Ping(b) => self.write_frame(0x9, b),
            Message::Pong(b) => self.write_frame(0xA, b),
            Message::Close(c) => {
                let mut p = Vec::new();
                if let Some((code, reason)) = c {
                    p.extend_from_slice(&code.to_be_bytes());
                    p.extend_from_slice(reason.as_bytes());
                }
                self.closed = true;
                self.write_frame(0x8, &p)
            }
        }
    }

    fn write_frame(&mut self, op: u8, payload: &[u8]) -> io::Result<()> {
        let mut f = Vec::with_capacity(payload.len() + 14);
        f.push(0x80 | op);
        let mask_bit = if self.role == Role::Client { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(mask_bit | n as u8),
            n if n <= 0xffff => {
                f.push(mask_bit | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(mask_bit | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if self.role == Role::Client {
            let key = crypto::random_bytes(4);
            f.extend_from_slice(&key);
            f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            f.extend_from_slice(payload);
        }
        self.s.write_all(&f)?;
        self.s.flush()
    }

    /// Next complete message. `Ok(None)`: the read timed out with no full message yet.
    /// Pings are answered automatically and not surfaced; a Close is answered and returned.
    pub fn recv(&mut self) -> io::Result<Option<Message>> {
        loop {
            if let Some(m) = self.parse()? {
                match m {
                    Message::Ping(p) => {
                        self.write_frame(0xA, &p)?;
                        continue;
                    }
                    Message::Close(c) => {
                        if !self.closed {
                            let _ = self.send(&Message::Close(c.clone().map(|(code, _)| (code, String::new()))));
                        }
                        self.closed = true;
                        return Ok(Some(Message::Close(c)));
                    }
                    m => return Ok(Some(m)),
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.s.read(&mut chunk) {
                Ok(0) => {
                    self.closed = true;
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed without close frame"));
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Block until a message arrives (ignores read timeouts).
    pub fn recv_blocking(&mut self) -> io::Result<Message> {
        loop {
            if let Some(m) = self.recv()? {
                return Ok(m);
            }
        }
    }

    /// Pull one frame out of the buffer; assemble fragments into a message.
    fn parse(&mut self) -> io::Result<Option<Message>> {
        loop {
            let b = &self.buf;
            if b.len() < 2 {
                return Ok(None);
            }
            let fin = b[0] & 0x80 != 0;
            if b[0] & 0x70 != 0 {
                return Err(bad("reserved bits set (no extensions negotiated)"));
            }
            let op = b[0] & 0x0f;
            let masked = b[1] & 0x80 != 0;
            if self.role == Role::Server && !masked {
                return Err(bad("client frame not masked"));
            }
            let (len, mut off) = match b[1] & 0x7f {
                126 => {
                    if b.len() < 4 {
                        return Ok(None);
                    }
                    (u16::from_be_bytes([b[2], b[3]]) as u64, 4)
                }
                127 => {
                    if b.len() < 10 {
                        return Ok(None);
                    }
                    (u64::from_be_bytes(b[2..10].try_into().unwrap()), 10)
                }
                n => (n as u64, 2),
            };
            if len > self.max as u64 {
                return Err(bad(format!("websocket frame of {len} bytes exceeds limit")));
            }
            let key = if masked {
                if b.len() < off + 4 {
                    return Ok(None);
                }
                let k = [b[off], b[off + 1], b[off + 2], b[off + 3]];
                off += 4;
                Some(k)
            } else {
                None
            };
            let end = off + len as usize;
            if b.len() < end {
                return Ok(None);
            }
            let mut payload = b[off..end].to_vec();
            self.buf.drain(..end);
            if let Some(k) = key {
                for (i, x) in payload.iter_mut().enumerate() {
                    *x ^= k[i % 4];
                }
            }
            match op {
                0x8 => {
                    let c = (payload.len() >= 2).then(|| (u16::from_be_bytes([payload[0], payload[1]]), String::from_utf8_lossy(&payload[2..]).into_owned()));
                    return Ok(Some(Message::Close(c)));
                }
                0x9 => return Ok(Some(Message::Ping(payload))),
                0xA => return Ok(Some(Message::Pong(payload))),
                0x0 => {
                    let Some((fop, mut acc)) = self.frag.take() else { return Err(bad("continuation without start")) };
                    if acc.len() + payload.len() > self.max {
                        return Err(bad("fragmented message exceeds limit"));
                    }
                    acc.extend_from_slice(&payload);
                    if fin {
                        return finish(fop, acc).map(Some);
                    }
                    self.frag = Some((fop, acc));
                }
                0x1 | 0x2 => {
                    if self.frag.is_some() {
                        return Err(bad("new data frame inside a fragmented message"));
                    }
                    if fin {
                        return finish(op, payload).map(Some);
                    }
                    self.frag = Some((op, payload));
                }
                other => return Err(bad(format!("unknown opcode {other}"))),
            }
        }
    }
}

fn finish(op: u8, data: Vec<u8>) -> io::Result<Message> {
    if op == 0x1 {
        String::from_utf8(data).map(Message::Text).map_err(|_| bad("text frame is not UTF-8"))
    } else {
        Ok(Message::Binary(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn accept_key_matches_rfc_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn client_and_server_exchange_messages_fragments_pings_and_close() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let (head, rest) = read_head(&mut s, 8192).unwrap();
            assert!(head.starts_with("GET /chat?x=1 HTTP/1.1"));
            assert_eq!(header(&head, "authorization"), Some("Bearer t"));
            let mut ws = WebSocket::accept(s, &head, rest).unwrap();
            assert_eq!(ws.recv_blocking().unwrap(), Message::Text("hello".into()));
            let big = "x".repeat(70_000);
            ws.send_text(&big).unwrap();
            // Fragmented text sent by hand: "fr" + "ag" + "中".
            let mut raw = ws.s.try_clone().unwrap();
            raw.write_all(&[0x01, 2, b'f', b'r', 0x00, 2, b'a', b'g', 0x80, 3, 0xe4, 0xb8, 0xad]).unwrap();
            raw.write_all(&[0x89, 1, b'p']).unwrap(); // ping, expect pong
            // The client answers the ping on its next recv, after sending binary.
            assert_eq!(ws.recv_blocking().unwrap(), Message::Binary(vec![1, 2, 3]));
            assert_eq!(ws.recv_blocking().unwrap(), Message::Pong(b"p".to_vec()));
            ws.send(&Message::Close(Some((1000, "bye".into())))).unwrap();
            assert!(matches!(ws.recv_blocking().unwrap(), Message::Close(Some((1000, _)))));
        });
        let (mut ws, head) = WebSocket::connect(&format!("ws://{addr}/chat?x=1"), &[("Authorization", "Bearer t")], Duration::from_secs(5)).unwrap();
        assert!(head.contains("101"));
        ws.send_text("hello").unwrap();
        assert_eq!(ws.recv_blocking().unwrap(), Message::Text("x".repeat(70_000)));
        assert_eq!(ws.recv_blocking().unwrap(), Message::Text("frag中".into()));
        // The server's ping was answered automatically; it is now waiting for binary.
        ws.send(&Message::Binary(vec![1, 2, 3])).unwrap();
        assert_eq!(ws.recv_blocking().unwrap(), Message::Close(Some((1000, "bye".into()))));
        srv.join().unwrap();
    }

    #[test]
    fn read_timeouts_keep_partial_frames_and_limits_are_enforced() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            // Masked "ok" text frame (zero mask key), delivered in two halves.
            c.write_all(&[0x81, 0x82, 0, 0, 0, 0]).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            c.write_all(b"ok").unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let mut ws = WebSocket::from_stream(s, false);
        let mut timeouts = 0;
        let got = loop {
            match ws.recv().unwrap() {
                Some(m) => break m,
                None => timeouts += 1,
            }
        };
        assert_eq!(got, Message::Text("ok".into()));
        assert!(timeouts >= 2, "partial frame survived {timeouts} timeouts");
        writer.join().unwrap();
        // Unmasked client frame and oversize frames are protocol errors.
        let mut ws = WebSocket::from_stream(io::Cursor::new(vec![0x81, 0x02, b'h', b'i']), false);
        assert!(ws.recv().is_err());
        let mut ws = WebSocket::from_stream(io::Cursor::new(vec![0x82, 0x7e, 0x01, 0x00]), true);
        ws.set_max_message(10);
        assert!(ws.recv().is_err());
    }
}
