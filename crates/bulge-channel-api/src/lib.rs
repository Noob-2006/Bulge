//! The interface between bulge and chat apps: a normalized [`Inbound`]
//! message, the [`Channel`] trait each app account implements, sending long
//! replies in parts ([`chunk`], with retries), and the chat commands
//! ([`commands`]). Kept apart from the app implementations so a channel (the
//! remote device channel, a test double) needs none of their dependencies.

pub mod chunk;
pub mod commands;

use futures::future::BoxFuture;

/// A file attached to a message (an image, a document, a voice note...).
/// It is fetched from the app only when the message is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// `image`, `video`, `audio` or `file`.
    pub kind: String,
    /// The file name the sender gave, if the app has one (untrusted).
    pub name: Option<String>,
    /// The app's handle for downloading it (message id, file id, URL...).
    pub source: String,
    /// The size the app reports, if any.
    pub size: Option<u64>,
}

/// One message from a chat app, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// The channel kind and account, e.g. `telegram:main`.
    pub channel: String,
    /// Where to reply (a chat, DM, room, or channel id in the app).
    pub chat_id: String,
    /// Who sent it (the app's stable user id).
    pub sender_id: String,
    /// A display name for logs and prompts (untrusted).
    pub sender_name: String,
    /// True for group chats / rooms with more than the owner and the bot.
    pub is_group: bool,
    /// True when the bot was explicitly addressed (mention, reply, command).
    pub mentioned: bool,
    pub text: String,
    /// The app's id for this message (to reply in thread where supported).
    pub message_id: String,
    /// Files sent with (or as) this message.
    pub attachments: Vec<Attachment>,
}

impl Inbound {
    /// The conversation key: one bulge conversation per chat per channel.
    pub fn chat_key(&self) -> String {
        format!("{}:{}", self.channel, self.chat_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The credentials were refused; retrying will not help.
    #[error("{channel}: authentication failed: {message}")]
    Auth { channel: String, message: String },
    /// A temporary failure (network, rate limit, server error); retry later.
    #[error("{channel}: {message}")]
    Transient { channel: String, message: String, retry_after_secs: Option<u64> },
    #[error("{channel}: {message}")]
    Other { channel: String, message: String },
}

impl ChannelError {
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Auth { .. })
    }
}

/// One connected app account.
pub trait Channel: Send + Sync {
    /// `kind:account`, e.g. `telegram:main`.
    fn name(&self) -> &str;
    /// The app's per-message length limit for sent text.
    fn text_limit(&self) -> usize;
    /// Wait for the next messages (long poll / next websocket events). Returns
    /// an empty batch on a quiet timeout.
    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>>;
    /// Send one message (already within `text_limit`) to `chat_id`.
    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>>;
    /// The poll position to persist after a batch was taken (so a restart
    /// neither repeats nor skips messages), for apps that have one.
    fn cursor(&self) -> Option<String> {
        None
    }
    /// True when the channel itself authenticates every sender (bulge's own
    /// remote devices, paired with keys): the pairing-code flow is skipped.
    fn authenticates_senders(&self) -> bool {
        false
    }
    /// Publish the command list to the app's own command menu, where it has
    /// one (Telegram's "/" menu). Others show `/help` only.
    fn register_commands<'a>(&'a self, commands: &'a [commands::Command]) -> BoxFuture<'a, Result<(), ChannelError>> {
        let _ = commands;
        Box::pin(async { Ok(()) })
    }
    /// Send `text` to a group, addressed to the sender of `message` — a real
    /// mention where the app has one. The default writes their name first.
    fn send_mention<'a>(&'a self, message: &'a Inbound, text: &'a str) -> BoxFuture<'a, Result<(), ChannelError>> {
        let name = if message.sender_name.is_empty() { message.sender_id.as_str() } else { message.sender_name.as_str() };
        let addressed = format!("{name}：\n{text}");
        Box::pin(async move { self.send(&message.chat_id, &addressed).await })
    }
    /// Download an attachment of a message this channel delivered, refusing
    /// anything larger than `max_bytes`. Channels that cannot fetch files
    /// say so.
    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        let _ = (attachment, max_bytes);
        Box::pin(async move { Err(ChannelError::Other { channel: self.name().to_owned(), message: "this channel cannot fetch files yet".into() }) })
    }
    /// Show a "working…" indicator where the app has one. Best effort.
    fn typing(&self, _chat_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

/// `image`, `video`, `audio` or `file`, from a MIME type.
pub fn kind_from_mime(mime: &str) -> &'static str {
    match mime.split('/').next().unwrap_or("") {
        "image" => "image",
        "video" => "video",
        "audio" => "audio",
        _ => "file",
    }
}

/// Reply to `message`: in groups the first part is addressed to its sender
/// (see [`Channel::send_mention`]); the rest, and direct chats, are plain.
pub async fn reply_long(channel: &dyn Channel, message: &Inbound, text: &str) -> Result<(), ChannelError> {
    if !message.is_group {
        return send_long(channel, &message.chat_id, text).await;
    }
    // Leave room for the name or mention in front of the first part.
    let limit = channel.text_limit().saturating_sub(100).max(1);
    let mut parts = chunk::split(text, limit).into_iter();
    if let Some(first) = parts.next() {
        with_retry(|| channel.send_mention(message, &first)).await?;
    }
    for part in parts {
        with_retry(|| channel.send(&message.chat_id, &part)).await?;
    }
    Ok(())
}

/// Attempts at sending one part before giving up.
const SEND_ATTEMPTS: u32 = 3;

/// Retry a send that failed for a passing reason (rate limit, network),
/// waiting as the app asks (`retry_after`) or 1, 2, 4 s.
async fn with_retry<'a, F>(send: impl Fn() -> F) -> Result<(), ChannelError>
where
    F: std::future::Future<Output = Result<(), ChannelError>> + 'a,
{
    let mut wait = 1u64;
    let mut attempt = 1;
    loop {
        match send().await {
            Err(ChannelError::Transient { retry_after_secs, .. }) if attempt < SEND_ATTEMPTS => {
                tokio::time::sleep(std::time::Duration::from_secs(retry_after_secs.unwrap_or(wait).min(60))).await;
                wait *= 2;
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// Send `text` as as many messages as the channel's limit requires.
pub async fn send_long(channel: &dyn Channel, chat_id: &str, text: &str) -> Result<(), ChannelError> {
    for part in chunk::split(text, channel.text_limit()) {
        with_retry(|| channel.send(chat_id, &part)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refuses the first send with a rate limit, then accepts.
    struct Flaky {
        calls: std::sync::Mutex<u32>,
    }

    impl Channel for Flaky {
        fn name(&self) -> &str {
            "flaky"
        }
        fn text_limit(&self) -> usize {
            100
        }
        fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn send(&self, _chat_id: &str, _text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            let first = *calls == 1;
            Box::pin(async move { if first { Err(ChannelError::Transient { channel: "flaky".into(), message: "429".into(), retry_after_secs: Some(0) }) } else { Ok(()) } })
        }
    }

    #[tokio::test]
    async fn a_rate_limited_send_is_retried() {
        let flaky = Flaky { calls: std::sync::Mutex::new(0) };
        send_long(&flaky, "c", "hello").await.unwrap();
        assert_eq!(*flaky.calls.lock().unwrap(), 2);
    }
}
