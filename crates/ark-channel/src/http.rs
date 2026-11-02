//! Outbound HTTP shared by the channels: JSON POST on a worker thread so a
//! blocked socket (Telegram long-poll) never delays cancellation.

use crate::{ChannelError, ChannelErrorKind as K};
use ark_core::Cancel;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

const MAX_BODY: u64 = 16 * 1024 * 1024;

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub body: String,
    /// Response headers, names lower-cased.
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn new(status: u16, body: impl Into<String>) -> Resp {
        Resp { status, retry_after: None, body: body.into(), headers: Vec::new() }
    }
    /// First value of a header (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn header_list(h: &ureq::http::HeaderMap) -> Vec<(String, String)> {
    h.iter().filter_map(|(k, v)| Some((k.as_str().to_ascii_lowercase(), v.to_str().ok()?.to_string()))).collect()
}

pub fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(timeout))
        .build()
        .into()
}

fn post(agent: &ureq::Agent, url: &str, headers: &[(String, String)], body: &[u8]) -> Result<Resp, ChannelError> {
    let mut req = agent.post(url).header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(k, v);
    }
    // The URL may carry a bot token; never echo it in errors.
    let mut r = req.send(body).map_err(|e| ChannelError::new(K::Network, format!("request failed: {}", redact(&e.to_string()))))?;
    let status = r.status().as_u16();
    let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()).map(Duration::from_secs);
    let headers = header_list(r.headers());
    let mut raw = Vec::new();
    r.body_mut()
        .with_config()
        .limit(u64::MAX)
        .reader()
        .take(MAX_BODY)
        .read_to_end(&mut raw)
        .map_err(|e| ChannelError::new(K::Network, format!("reading response: {}", redact(&e.to_string()))))?;
    Ok(Resp { status, retry_after, body: String::from_utf8_lossy(&raw).into_owned(), headers })
}

/// `Ok(None)` when cancelled; the worker is abandoned and finishes on its own.
pub fn post_cancellable(agent: &ureq::Agent, url: &str, headers: &[(String, String)], body: Vec<u8>, cancel: &Cancel) -> Result<Option<Resp>, ChannelError> {
    let (tx, rx) = mpsc::channel();
    let (a, u, h) = (agent.clone(), url.to_string(), headers.to_vec());
    std::thread::spawn(move || {
        let _ = tx.send(post(&a, &u, &h, &body));
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(r) => return r.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if cancel.is_cancelled() {
                    return Ok(None);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "http worker died")),
        }
    }
}

/// Map an HTTP status to the error kind the delivery layer acts on.
pub fn classify(status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
    let snippet: String = redact(body).chars().take(300).collect();
    let kind = match status {
        401 | 403 => K::Auth,
        404 | 410 => K::NotFound,
        408 | 425 | 500..=599 => K::Network,
        429 => K::RateLimited { retry_after },
        _ => K::Protocol,
    };
    ChannelError::new(kind, format!("{what}: HTTP {status} {snippet}"))
}

/// Blocking request helper used by every HTTP channel. Bodies over `MAX_BODY` are cut.
#[derive(Clone)]
pub struct Http {
    pub agent: ureq::Agent,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Copy)]
pub enum Payload<'a> {
    None,
    Json(&'a serde_json::Value),
    Form(&'a [(&'a str, &'a str)]),
    Raw(&'a str, &'a [u8]),
    /// multipart/form-data: (name, filename, content-type, bytes); filename empty = plain field.
    Multipart(&'a [(&'a str, &'a str, &'a str, &'a [u8])]),
}

impl Http {
    pub fn new(timeout: Duration) -> Http {
        Http { agent: agent(timeout), headers: Vec::new() }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Http {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn bearer(self, token: &str) -> Http {
        self.with_header("authorization", &format!("Bearer {token}"))
    }

    /// Raw call: (status, retry_after, body). Network failures are `Network` errors.
    pub fn call(&self, method: &str, url: &str, extra: &[(&str, &str)], body: Payload) -> Result<Resp, ChannelError> {
        let boundary = format!("ark{}", std::process::id() as u64 * 7919 + std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0));
        let (ctype, bytes): (Option<String>, Vec<u8>) = match body {
            Payload::None => (None, Vec::new()),
            Payload::Json(v) => (Some("application/json".into()), serde_json::to_vec(v).unwrap_or_default()),
            Payload::Form(f) => (Some("application/x-www-form-urlencoded".into()), ark_net::form_encode(f).into_bytes()),
            Payload::Raw(t, b) => (Some(t.into()), b.to_vec()),
            Payload::Multipart(parts) => {
                let mut b = Vec::new();
                for (name, file, ct, data) in parts {
                    b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                    if file.is_empty() {
                        b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
                    } else {
                        let ct = if ct.is_empty() { "application/octet-stream" } else { ct };
                        b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", file.replace('"', "")).as_bytes());
                    }
                    b.extend_from_slice(data);
                    b.extend_from_slice(b"\r\n");
                }
                b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
                (Some(format!("multipart/form-data; boundary={boundary}")), b)
            }
        };
        let mut hs: Vec<(String, String)> = self.headers.clone();
        hs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let resp = match method {
            "GET" | "DELETE" | "HEAD" => {
                let mut r = match method {
                    "GET" => self.agent.get(url),
                    "HEAD" => self.agent.head(url),
                    _ => self.agent.delete(url),
                };
                for (k, v) in &hs {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.call()
            }
            _ => {
                let mut r = match method {
                    "PUT" => self.agent.put(url),
                    "PATCH" => self.agent.patch(url),
                    _ => self.agent.post(url),
                };
                if let Some(ct) = &ctype {
                    r = r.header("content-type", ct.as_str());
                }
                for (k, v) in &hs {
                    r = r.header(k.as_str(), v.as_str());
                }
                r.send(&bytes[..])
            }
        };
        let mut r = resp.map_err(|e| ChannelError::new(K::Network, format!("{method} request failed: {}", redact(&e.to_string()))))?;
        let status = r.status().as_u16();
        let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<f64>().ok()).map(|s| Duration::from_secs_f64(s.max(0.0)));
        let headers = header_list(r.headers());
        let mut raw = Vec::new();
        r.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("reading response: {}", redact(&e.to_string()))))?;
        Ok(Resp { status, retry_after, body: String::from_utf8_lossy(&raw).into_owned(), headers })
    }

    /// Call and parse JSON, mapping non-2xx to classified errors.
    pub fn json(&self, method: &str, url: &str, body: Payload) -> Result<serde_json::Value, ChannelError> {
        let r = self.call(method, url, &[], body)?;
        if !(200..300).contains(&r.status) {
            return Err(classify(r.status, r.retry_after, method, &r.body));
        }
        if r.body.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&r.body).map_err(|e| ChannelError::new(K::Protocol, format!("{method}: bad JSON ({e}): {}", redact(&r.body.chars().take(200).collect::<String>()))))
    }
}

/// Download bytes with optional headers (auth), capped at `max`.
pub fn get_bytes(url: &str, headers: &[(&str, &str)], max: u64) -> Result<Vec<u8>, ChannelError> {
    let a = agent(Duration::from_secs(120));
    let mut r = a.get(url);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let mut resp = r.call().map_err(|e| ChannelError::new(K::Network, format!("download failed: {}", redact(&e.to_string()))))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(classify(status, None, "download", ""));
    }
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(max + 1).read_to_end(&mut raw).map_err(|e| ChannelError::new(K::Network, format!("download: {e}")))?;
    if raw.len() as u64 > max {
        return Err(ChannelError::new(K::Protocol, format!("attachment larger than {max} bytes")));
    }
    Ok(raw)
}

/// Strip `/bot<token>/` path segments from transport error strings.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("/bot") {
        out.push_str(&rest[..i + 4]);
        let tail = &rest[i + 4..];
        let end = tail.find(['/', ' ', '"', '\'']).unwrap_or(tail.len());
        out.push_str("***");
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn redacts_bot_tokens() {
        assert_eq!(super::redact("GET https://api.telegram.org/bot123:ABC/getUpdates failed"), "GET https://api.telegram.org/bot***/getUpdates failed");
        assert_eq!(super::redact("no token here"), "no token here");
    }
}
