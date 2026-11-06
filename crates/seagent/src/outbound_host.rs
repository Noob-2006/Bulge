//! The process's delivery host (`seagent_kernel::outbound`): channel targets go
//! through the configured channels, webhook targets are POSTed as JSON and
//! signed with HMAC-SHA256 when a secret is given.

use seagent_channel::{Channel, Outbound};
use seagent_kernel::outbound::{self, Payload, Target, SIGNATURE_HEADER};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub type Secrets = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Install the sender for `channels` (name → channel, default chat). `data` is the seagent
/// data directory, used by `room:<id>` targets.
pub fn install(channels: BTreeMap<String, (Arc<dyn Channel>, Option<String>)>, secrets: Secrets, data: std::path::PathBuf) {
    let names = channels.keys().cloned().collect();
    outbound::install(Arc::new(move |t: &Target, p: &Payload| send(&channels, &secrets, &data, t, p)), names);
}

fn send(channels: &BTreeMap<String, (Arc<dyn Channel>, Option<String>)>, secrets: &Secrets, data: &std::path::Path, t: &Target, p: &Payload) -> Result<String, String> {
    match t {
        Target::Channel { name, chat, thread } => {
            let (ch, default_chat) = channels.get(name).ok_or_else(|| format!("unknown channel `{name}`; configured: {}", channels.keys().cloned().collect::<Vec<_>>().join(", ")))?;
            let chat = chat.clone().or_else(|| seagent_channel::outfile::effective_default(name, default_chat.as_ref())).ok_or_else(|| format!("channel `{name}` has no default_chat; use `{name}:<chat>`"))?;
            let mut o = Outbound::text(&chat, &p.text);
            o.thread = thread.clone();
            ch.send(&o).map_err(|e| format!("send to {name}/{chat} failed: {e}"))?;
            Ok(format!("sent to {name}/{chat}"))
        }
        Target::Room { id } => crate::ops::rooms::post_message(data, id, &p.text),
        Target::Webhook { url, secret } => post_webhook(url, secret.as_deref().map(|s| secrets(s)).as_deref(), p),
        Target::Local => Ok("kept local".into()),
        Target::Origin => Err("unresolved `origin` target".into()),
    }
}

/// POST `{"event","text","data","ts"}`; 2xx = delivered.
pub fn post_webhook(url: &str, secret: Option<&str>, p: &Payload) -> Result<String, String> {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let body = json!({"event": p.event, "text": p.text, "data": p.data, "ts": ts}).to_string();
    let agent: ureq::Agent = seagent_net::http::builder().timeout_global(Some(Duration::from_secs(15))).http_status_as_error(false).build().into();
    let mut req = agent.post(url).header("Content-Type", "application/json").header("User-Agent", concat!("seagent/", env!("CARGO_PKG_VERSION"))).header("X-Seagent-Event", &p.event);
    if let Some(s) = secret.filter(|s| !s.is_empty()) {
        req = req.header(SIGNATURE_HEADER, &format!("sha256={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(s.as_bytes(), body.as_bytes()))));
    }
    let r = req.send(body.as_bytes()).map_err(|e| format!("webhook {url}: {e}"))?;
    let status = r.status().as_u16();
    if (200..300).contains(&status) {
        Ok(format!("HTTP {status}"))
    } else {
        Err(format!("webhook {url} answered HTTP {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn webhook_is_signed_and_status_checked() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let mut got = Vec::new();
            for code in [200, 500] {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = vec![0u8; 8192];
                let mut req = Vec::new();
                loop {
                    let n = s.read(&mut buf).unwrap();
                    req.extend_from_slice(&buf[..n]);
                    let t = String::from_utf8_lossy(&req).to_string();
                    if let Some(i) = t.find("\r\n\r\n") {
                        let len: usize = t.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                        if req.len() >= i + 4 + len {
                            break;
                        }
                    }
                }
                got.push(String::from_utf8_lossy(&req).to_string());
                write!(s, "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            }
            got
        });
        let url = format!("http://{addr}/hook");
        let p = Payload::new("cron.finished", "done").with_data(json!({"job": "j1"}));
        assert_eq!(post_webhook(&url, Some("k"), &p).unwrap(), "HTTP 200");
        assert!(post_webhook(&url, None, &p).unwrap_err().contains("500"));
        let got = h.join().unwrap();
        let body = got[0].split("\r\n\r\n").nth(1).unwrap();
        let sig = format!("sha256={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(b"k", body.as_bytes())));
        assert!(got[0].to_ascii_lowercase().contains(&format!("x-seagent-signature: {sig}")), "{}", got[0]);
        assert!(body.contains("\"event\":\"cron.finished\"") && body.contains("\"job\":\"j1\""));
        assert!(!got[1].to_ascii_lowercase().contains("x-seagent-signature"));
    }
}
