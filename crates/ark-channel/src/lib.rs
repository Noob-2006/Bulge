//! ark-channel: human chat channels (Telegram, webhook), the kernel-agnostic
//! router that maps inbound messages to sessions, and the `channel_send` tool.
//! Blocking std threads only; every network wait observes a `Cancel`.

pub mod config;
mod http;
pub mod router;
pub mod telegram;
pub mod tool;
pub mod webhook;

#[cfg(test)]
mod testutil;

use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

pub use config::{build, parse_config, ChannelConfig, Secrets};
pub use router::{Action, Command, Route, RouteKey, Router, RouterConfig, SessionPer};
pub use telegram::Telegram;
pub use tool::ChannelSend;
pub use webhook::Webhook;

/// A message from a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inbound {
    pub channel: String,
    pub chat: String,
    pub sender: String,
    #[serde(default)]
    pub sender_name: String,
    pub text: String,
    /// Channel-native id; used for replies and redelivery dedup.
    pub message_id: String,
    /// Unix seconds.
    #[serde(default)]
    pub ts: i64,
}

/// A message to a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outbound {
    pub chat: String,
    pub text: String,
    #[serde(default)]
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelErrorKind {
    /// Bad or revoked credentials: stop polling, tell the operator.
    Auth,
    RateLimited { retry_after: Option<Duration> },
    /// Transient: back off and try again.
    Network,
    /// The other side answered something we did not understand or rejected the request.
    Protocol,
    /// Misconfiguration or a state retrying cannot fix.
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelError {
    pub kind: ChannelErrorKind,
    pub message: String,
}

impl ChannelError {
    pub fn new(kind: ChannelErrorKind, message: impl Into<String>) -> Self {
        ChannelError { kind, message: message.into() }
    }
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, ChannelErrorKind::Network | ChannelErrorKind::RateLimited { .. })
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ChannelError {}

pub trait Channel: Send + Sync {
    fn id(&self) -> &str;
    /// Block until messages arrive, the poll timeout passes (→ empty), or `cancel` fires (→ empty).
    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError>;
    fn send(&self, out: &Outbound) -> Result<(), ChannelError>;
}

/// Sleep in small slices so cancellation is noticed quickly. Returns false if cancelled.
pub(crate) fn sleep_cancellable(d: Duration, cancel: &Cancel) -> bool {
    let until = std::time::Instant::now() + d;
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= until {
            return true;
        }
        std::thread::sleep((until - now).min(Duration::from_millis(25)));
    }
}

/// Write via temp file + rename so a crash never leaves a half-written state file.
pub(crate) fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
