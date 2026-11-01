//! Outbound HTTP shared by the channels: JSON POST on a worker thread so a
//! blocked socket (Telegram long-poll) never delays cancellation.

use crate::{ChannelError, ChannelErrorKind as K};
use ark_core::Cancel;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

const MAX_BODY: u64 = 4 * 1024 * 1024;

pub struct Resp {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub body: String,
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
    let mut raw = Vec::new();
    r.body_mut()
        .with_config()
        .limit(u64::MAX)
        .reader()
        .take(MAX_BODY)
        .read_to_end(&mut raw)
        .map_err(|e| ChannelError::new(K::Network, format!("reading response: {}", redact(&e.to_string()))))?;
    Ok(Resp { status, retry_after, body: String::from_utf8_lossy(&raw).into_owned() })
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
