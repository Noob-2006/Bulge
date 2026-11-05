//! Blocking HTTP on a worker thread, consumed through a channel so the caller can
//! enforce an idle timeout and observe cancellation while the socket is blocked.

use crate::classify;
use crate::sse::{SseEvent, SseParser};
use ark_core::{Cancel, ProviderError, ProviderErrorKind as K};
use serde_json::Value;
use std::io::Read;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(25);
/// Bytes of a non-SSE body kept to diagnose JSON errors sent with status 200.
const RAW_KEEP: usize = 64 * 1024;

enum Msg {
    Head {
        status: u16,
        retry_after: Option<Duration>,
        headers: Vec<(String, String)>,
    },
    Chunk(Vec<u8>),
    Eof,
    Err(ProviderError),
}

#[derive(Clone)]
pub struct Http {
    pub idle: Duration,
    /// Provider id: rate-limit headers are recorded under it.
    label: String,
}

/// Longest pre-emptive wait for a spent rate-limit window.
const MAX_PREWAIT: Duration = Duration::from_secs(60);

impl Http {
    pub fn new(idle: Duration, label: &str) -> Self {
        Http {
            idle,
            label: label.to_string(),
        }
    }

    /// Open a streaming POST; returns the receiver after the status line arrived (2xx), or
    /// the classified error for any other status.
    fn open(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        cancel: &Cancel,
        last: &mut Instant,
    ) -> Result<Receiver<Msg>, ProviderError> {
        crate::net::check_host(url).map_err(|e| ProviderError::new(K::BadRequest, e))?;
        if let Some(w) = crate::ratelimit::wait_before(&self.label, MAX_PREWAIT) {
            let until = Instant::now() + w;
            while Instant::now() < until {
                if cancel.is_cancelled() {
                    return Err(ProviderError::new(K::Cancelled, "cancelled"));
                }
                std::thread::sleep(POLL.min(until - Instant::now()));
            }
        }
        let rx = self.spawn(url, headers, body);
        *last = Instant::now();
        let (status, retry_after) = match self.recv(&rx, cancel, last)? {
            Msg::Head {
                status,
                retry_after,
                headers,
            } => {
                crate::ratelimit::record(&self.label, &headers);
                (status, retry_after)
            }
            Msg::Err(e) => return Err(e),
            _ => return Err(ProviderError::new(K::Protocol, "response without status")),
        };
        if !(200..300).contains(&status) {
            let mut raw = Vec::new();
            loop {
                match self.recv(&rx, cancel, last)? {
                    Msg::Chunk(c) => {
                        if raw.len() < RAW_KEEP {
                            raw.extend_from_slice(&c)
                        }
                    }
                    Msg::Eof | Msg::Err(_) => break,
                    Msg::Head { .. } => {}
                }
            }
            return Err(classify::from_status(
                status,
                retry_after,
                &String::from_utf8_lossy(&raw),
            ));
        }
        Ok(rx)
    }

    /// POST raw `body` and hand every received chunk to `on_chunk` until it returns
    /// `Ok(true)` or the stream ends (binary streams such as AWS event streams).
    /// Only the gated adapters (bedrock) need it, hence `allow(dead_code)`.
    #[allow(dead_code)]
    pub fn post_stream(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        cancel: &Cancel,
        mut on_chunk: impl FnMut(&[u8]) -> Result<bool, ProviderError>,
    ) -> Result<(), ProviderError> {
        let mut last = Instant::now();
        let rx = self.open(url, headers, body, cancel, &mut last)?;
        loop {
            match self.recv(&rx, cancel, &mut last)? {
                Msg::Chunk(c) => {
                    if on_chunk(&c)? {
                        return Ok(());
                    }
                }
                Msg::Eof => return Ok(()),
                Msg::Err(e) => return Err(e),
                Msg::Head { .. } => {}
            }
        }
    }

    /// POST `body` and feed SSE events to `on_event` until it returns `Ok(true)` (terminal)
    /// or the stream ends. Non-2xx responses become classified errors.
    pub fn post_sse(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &Value,
        cancel: &Cancel,
        mut on_event: impl FnMut(SseEvent) -> Result<bool, ProviderError>,
    ) -> Result<(), ProviderError> {
        let mut last = Instant::now();
        let rx = self.open(
            url,
            headers,
            serde_json::to_vec(body).expect("json"),
            cancel,
            &mut last,
        )?;
        let mut parser = SseParser::new();
        let mut raw = Vec::new();
        let mut seen = false;
        loop {
            match self.recv(&rx, cancel, &mut last)? {
                Msg::Chunk(c) => {
                    if !seen && raw.len() < RAW_KEEP {
                        raw.extend_from_slice(&c);
                    }
                    for ev in parser.feed(&c) {
                        seen = true;
                        if on_event(ev)? {
                            return Ok(());
                        }
                    }
                }
                Msg::Eof => {
                    for ev in parser.finish() {
                        seen = true;
                        if on_event(ev)? {
                            return Ok(());
                        }
                    }
                    if !seen {
                        let text = String::from_utf8_lossy(&raw);
                        if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
                            if v.get("error").is_some() {
                                return Err(classify::from_stream_error(&v));
                            }
                        }
                    }
                    return Ok(());
                }
                Msg::Err(e) => return Err(e),
                Msg::Head { .. } => {}
            }
        }
    }

    fn recv(
        &self,
        rx: &Receiver<Msg>,
        cancel: &Cancel,
        last: &mut Instant,
    ) -> Result<Msg, ProviderError> {
        loop {
            if cancel.is_cancelled() {
                return Err(ProviderError::new(K::Cancelled, "cancelled"));
            }
            let left = self.idle.saturating_sub(last.elapsed());
            if left.is_zero() {
                return Err(ProviderError::new(
                    K::Timeout,
                    format!("no data for {:?}", self.idle),
                ));
            }
            match rx.recv_timeout(left.min(POLL)) {
                Ok(m) => {
                    *last = Instant::now();
                    return Ok(m);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(ProviderError::new(K::Network, "connection worker exited"));
                }
            }
        }
    }

    fn spawn(&self, url: &str, headers: &[(String, String)], body: Vec<u8>) -> Receiver<Msg> {
        let (tx, rx) = mpsc::channel();
        // Upper bound for a detached worker whose caller already gave up.
        let agent = crate::net::agent_with(Duration::from_secs(3600), Duration::from_secs(30), url);
        let url = url.to_string();
        let headers = headers.to_vec();
        std::thread::spawn(move || {
            let mut req = agent.post(&url);
            if !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                req = req.header("content-type", "application/json");
            }
            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }
            let resp = match req.send(&body[..]) {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Msg::Err(map_ureq(e)));
                    return;
                }
            };
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(classify::parse_retry_after);
            let kept: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter(|(k, _)| crate::ratelimit::interesting(k.as_str()))
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (k.as_str().to_string(), v.to_string()))
                })
                .collect();
            if tx
                .send(Msg::Head {
                    status: resp.status().as_u16(),
                    retry_after,
                    headers: kept,
                })
                .is_err()
            {
                return;
            }
            let mut reader = resp.into_body().into_reader();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let msg = match reader.read(&mut buf) {
                    Ok(0) => Msg::Eof,
                    Ok(n) => Msg::Chunk(buf[..n].to_vec()),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let kind = if e.kind() == std::io::ErrorKind::TimedOut {
                            K::Timeout
                        } else {
                            K::Network
                        };
                        Msg::Err(ProviderError::new(kind, format!("stream read failed: {e}")))
                    }
                };
                let end = !matches!(msg, Msg::Chunk(_));
                if tx.send(msg).is_err() || end {
                    return;
                }
            }
        });
        rx
    }
}

fn map_ureq(e: ureq::Error) -> ProviderError {
    match e {
        ureq::Error::Timeout(t) => ProviderError::new(K::Timeout, format!("timeout: {t}")),
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => {
            ProviderError::new(K::Timeout, io.to_string())
        }
        other => ProviderError::new(K::Network, other.to_string()),
    }
}

/// Parse an SSE data payload as JSON, mapping failure to `Protocol`.
pub fn json(data: &str) -> Result<Value, ProviderError> {
    serde_json::from_str(data).map_err(|e| {
        let mut snippet = data.chars().take(200).collect::<String>();
        if data.len() > snippet.len() {
            snippet.push('…');
        }
        ProviderError::new(
            K::Protocol,
            format!("malformed stream chunk ({e}): {snippet}"),
        )
    })
}

pub fn truncated(what: &str) -> ProviderError {
    ProviderError::new(K::Protocol, format!("stream ended before {what}"))
}
