//! Tiny scripted HTTP/1.1 server for offline adapter tests.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub enum Reply {
    /// Plain response with a body.
    Status { code: u16, headers: Vec<(&'static str, String)>, body: String },
    /// 200 text/event-stream, one HTTP chunk per entry.
    Sse { chunks: Vec<String>, end: End },
    /// Read the request, never answer.
    Hang,
}

pub enum End {
    /// Proper chunked terminator.
    Clean,
    /// Keep the socket open forever after the last chunk.
    Hang,
    /// Drop the connection mid-body.
    Abort,
}

pub struct Recorded {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

impl Recorded {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

pub struct Mock {
    pub base: String,
    rx: Receiver<Recorded>,
}

impl Mock {
    pub fn request(&self) -> Recorded {
        self.rx.recv_timeout(Duration::from_secs(5)).expect("server saw no request")
    }
}

pub fn sse(events: &[&str]) -> Reply {
    Reply::Sse { chunks: events.iter().map(|e| format!("{e}\n\n")).collect(), end: End::Clean }
}

pub fn serve(reply: Reply) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let Some(rec) = read_request(&mut s) else { return };
        let _ = tx.send(rec);
        respond(s, reply);
    });
    Mock { base, rx }
}

fn read_request(s: &mut TcpStream) -> Option<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Some(Recorded { path, headers, body })
}

fn respond(mut s: TcpStream, reply: Reply) {
    match reply {
        Reply::Status { code, headers, body } => {
            let mut h = format!(
                "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (k, v) in headers {
                h.push_str(&format!("{k}: {v}\r\n"));
            }
            let _ = s.write_all(format!("{h}\r\n{body}").as_bytes());
        }
        Reply::Sse { chunks, end } => {
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            );
            for c in chunks {
                let _ = s.write_all(format!("{:x}\r\n{c}\r\n", c.len()).as_bytes());
                let _ = s.flush();
                std::thread::sleep(Duration::from_millis(5));
            }
            match end {
                End::Clean => {
                    let _ = s.write_all(b"0\r\n\r\n");
                }
                End::Hang => std::thread::sleep(Duration::from_secs(30)),
                End::Abort => {
                    let _ = s.write_all(b"40\r\ndata: {\"partial");
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
        }
        Reply::Hang => std::thread::sleep(Duration::from_secs(30)),
    }
}
