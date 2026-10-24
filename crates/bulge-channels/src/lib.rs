//! Messaging-app channels: the owner talks to bulge from a chat app.
//!
//! A [`Channel`] turns one app account into a stream of [`Inbound`] messages
//! and can send text back. Everything above that is shared: who may command
//! bulge ([`access`]: allow-list, pairing codes for unknown senders, group
//! mention gating), how long replies are split ([`chunk`]), and what state
//! survives a restart ([`state`]: poll offsets, chat → conversation mapping).
//!
//! Every channel talks to its app from the HOST, with outbound connections
//! (long polling or a client websocket): tokens never enter the VM, which only
//! ever receives the text of a job. The one transport that must accept inbound
//! connections (LINE webhooks) does so through a listener that keeps the
//! two-key rule of bulge's egress gateway.

pub mod access;
pub mod discord;
pub mod history;
pub mod line;
pub mod matrix;
pub mod signal;
pub mod slack;
pub mod state;
pub mod telegram;

pub use bulge_channel_api::{Attachment, Channel, ChannelError, Inbound, chunk, commands, kind_from_mime, reply_long, send_long};

/// Whether `url` is HTTPS on one of `hosts` (exactly, or a subdomain): files
/// are only fetched from the app's own servers, never from an address a
/// message could point anywhere.
pub(crate) fn https_on(url: &str, hosts: &[&str]) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").to_ascii_lowercase();
    !host.contains('@') && !host.contains(':') && hosts.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// Download a response body, refusing more than `max` bytes (checked against
/// the declared length first, then while streaming). Errors never carry the
/// URL (it may hold a token).
pub(crate) async fn download_capped(request: reqwest::RequestBuilder, max: u64, channel: &str) -> Result<Vec<u8>, ChannelError> {
    use futures::StreamExt;
    let transient = |message: String| ChannelError::Transient { channel: channel.to_owned(), message, retry_after_secs: None };
    let response = request.send().await.map_err(|e| transient(format!("download: {}", e.without_url())))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(match status {
            401 | 403 => ChannelError::Auth { channel: channel.to_owned(), message: format!("download: HTTP {status}") },
            404 | 410 => ChannelError::Other { channel: channel.to_owned(), message: "the file is no longer available".into() },
            _ => transient(format!("download: HTTP {status}")),
        });
    }
    if response.content_length().is_some_and(|len| len > max) {
        return Err(ChannelError::Other { channel: channel.to_owned(), message: format!("the file is larger than {} MB", max / (1024 * 1024)) });
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| transient(format!("download: {}", e.without_url())))?;
        if body.len() as u64 + chunk.len() as u64 > max {
            return Err(ChannelError::Other { channel: channel.to_owned(), message: format!("the file is larger than {} MB", max / (1024 * 1024)) });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    #[test]
    fn files_come_only_from_the_apps_own_https_hosts() {
        assert!(https_on("https://cdn.discordapp.com/attachments/1/2/a.png?ex=1", &["cdn.discordapp.com"]));
        assert!(https_on("https://files.slack.com/files-pri/T1/x", &["files.slack.com"]));
        assert!(!https_on("http://cdn.discordapp.com/a.png", &["cdn.discordapp.com"]), "https only");
        assert!(!https_on("https://cdn.discordapp.com.evil.example/a.png", &["cdn.discordapp.com"]));
        assert!(!https_on("https://evil.example/cdn.discordapp.com/a.png", &["cdn.discordapp.com"]));
        assert!(!https_on("https://cdn.discordapp.com@evil.example/a.png", &["cdn.discordapp.com"]));
        assert!(!https_on("https://127.0.0.1:8080/a", &["cdn.discordapp.com"]));
        assert_eq!(kind_from_mime("image/png"), "image");
        assert_eq!(kind_from_mime("application/pdf"), "file");
        assert_eq!(kind_from_mime(""), "file");
    }
}
