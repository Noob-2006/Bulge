//! A non-blocking JSON-over-WebSocket connection (OpenClaw
//! `RealtimeTranscriptionWebSocketTransport` / `RealtimeVoiceWebSocketTransport`):
//! connect with retries, send JSON/binary, drain whatever has arrived without
//! blocking, and wait (bounded) for a provider's "ready" event.

use seagent_net::ws::{Message, WebSocket};
use seagent_net::Stream;
use serde_json::Value;
use std::time::{Duration, Instant};

/// Inbound messages larger than this end the session (OpenClaw 16 MiB cap).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Audio queued while the provider is not ready yet (OpenClaw `DEFAULT_MAX_QUEUED_BYTES`).
pub const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Json(Value),
    Binary(Vec<u8>),
    /// The server closed the socket (code, reason).
    Closed(Option<(u16, String)>),
}

pub struct Conn {
    ws: WebSocket<Stream>,
    closed: bool,
}

/// `http(s)://` → `ws(s)://`; `ws(s)://` kept.
pub fn ws_scheme(url: &str) -> String {
    if let Some(r) = url.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = url.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        url.to_string()
    }
}

impl Conn {
    /// Connect, retrying transport failures `attempts` times `delay` apart (OpenClaw
    /// `maxReconnectAttempts` / `reconnectDelayMs`). An HTTP refusal of the upgrade is final.
    pub fn open(
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
        attempts: u32,
        delay: Duration,
        label: &str,
    ) -> Result<Conn, String> {
        let hs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut last = String::new();
        for i in 0..attempts.max(1) {
            if i > 0 {
                std::thread::sleep(delay);
            }
            match WebSocket::connect(url, &hs, timeout) {
                Ok((mut ws, _)) => {
                    ws.set_max_message(MAX_MESSAGE_BYTES);
                    ws.set_read_timeout(Some(Duration::from_millis(5)))
                        .map_err(|e| format!("{label}: {e}"))?;
                    return Ok(Conn { ws, closed: false });
                }
                Err(e) => {
                    last = e.to_string();
                    if last.contains("upgrade refused") {
                        return Err(format!("{label} connection failed: {last}"));
                    }
                }
            }
        }
        Err(format!("{label} connection failed: {last}"))
    }

    pub fn is_open(&self) -> bool {
        !self.closed && !self.ws.is_closed()
    }

    pub fn send_json(&mut self, v: &Value) -> bool {
        self.is_open() && self.ws.send_text(&v.to_string()).is_ok()
    }

    pub fn send_binary(&mut self, b: &[u8]) -> bool {
        self.is_open() && self.ws.send(&Message::Binary(b.to_vec())).is_ok()
    }

    /// Everything that has arrived (non-blocking). Malformed JSON text frames are skipped.
    pub fn drain(&mut self) -> Vec<Incoming> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        loop {
            match self.ws.recv() {
                Ok(None) => break,
                Ok(Some(Message::Text(t))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        out.push(Incoming::Json(v));
                    }
                }
                Ok(Some(Message::Binary(b))) => match serde_json::from_slice::<Value>(&b) {
                    Ok(v) if v.is_object() => out.push(Incoming::Json(v)),
                    _ => out.push(Incoming::Binary(b)),
                },
                Ok(Some(Message::Close(c))) => {
                    self.closed = true;
                    out.push(Incoming::Closed(c));
                    break;
                }
                Ok(Some(_)) => {}
                Err(_) => {
                    self.closed = true;
                    out.push(Incoming::Closed(None));
                    break;
                }
            }
        }
        out
    }

    /// Drain until `f` returns `Some` (or the deadline passes / the socket closes).
    pub fn wait<T>(
        &mut self,
        timeout: Duration,
        mut f: impl FnMut(&Incoming) -> Option<T>,
    ) -> Option<T> {
        let end = Instant::now() + timeout;
        loop {
            for m in self.drain() {
                if let Some(t) = f(&m) {
                    return Some(t);
                }
                if matches!(m, Incoming::Closed(_)) {
                    return None;
                }
            }
            if Instant::now() >= end || self.closed {
                return None;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn close(&mut self) {
        if !self.closed {
            let _ = self.ws.send(&Message::Close(Some((1000, String::new()))));
            if let Ok(t) = self.ws.shutdown_handle() {
                let _ = t.shutdown(std::net::Shutdown::Both);
            }
        }
        self.closed = true;
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close();
    }
}
