//! Provider-neutral failure classification consumed by retry and the agent loop.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Auth,
    Quota,
    RateLimit,
    ContextWindowExceeded,
    InvalidRequest,
    Server,
    /// Other HTTP status not covered above.
    Http(u16),
    Network,
    StreamClosed,
    StreamIdle,
    MalformedResponse,
    EmptyResponse,
    UnsupportedContent,
    UnsupportedReasoningEffort,
    Aborted,
}

impl ErrorCode {
    /// Codes the default retry policy retries.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimit | Self::Server | Self::Network | Self::StreamClosed | Self::StreamIdle
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmError {
    pub code: ErrorCode,
    pub message: String,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    /// Provider `retry-after`, already converted to milliseconds.
    pub retry_after_ms: Option<u64>,
}

impl LlmError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), status: None, request_id: None, retry_after_ms: None }
    }

    pub fn malformed(detail: impl fmt::Display) -> Self {
        Self::new(ErrorCode::MalformedResponse, format!("malformed response: {detail}"))
    }

    pub fn unsupported(detail: impl fmt::Display) -> Self {
        Self::new(ErrorCode::UnsupportedContent, format!("cannot represent {detail}"))
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for LlmError {}

/// Classify a provider failure from an HTTP status and/or a decoded error
/// envelope (`{"error": {"type", "code", "message"}}`, also used in-band).
/// Never trusts fields beyond type/code/message.
/// MARK: M5 — transcribed by dsh; see marks/M5-error-map.md.
pub fn classify_http(
    status: Option<u16>,
    body: &serde_json::Value,
    retry_after: Option<&str>,
    request_id: Option<&str>,
) -> LlmError {
    let _ = (status, body, retry_after, request_id);
    todo!("M5")
}
