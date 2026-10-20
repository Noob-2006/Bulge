//! Wire protocols. Each protocol is pure: it encodes a [`GenerateRequest`] to a
//! JSON body and decodes SSE events to [`StreamChunk`]s. HTTP, retry, and
//! cancellation live in `crate::http`.

pub mod anthropic;
pub mod openai_chat;

use crate::error::LlmError;
use crate::types::{GenerateRequest, ModelInfo, StreamChunk};

/// One complete SSE frame. `event` is the `event:` field if present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Per-route options the protocol needs while encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodeContext<'a> {
    pub model: &'a ModelInfo,
    /// Used when the request sets no `max_tokens` and the model has none.
    pub default_max_tokens: u32,
}

pub trait WireProtocol: Send + Sync {
    /// Path appended to the configured base URL, e.g. `/v1/messages`.
    fn endpoint_path(&self) -> &'static str;

    /// Credential headers for an API key.
    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)>;

    /// Build the streaming JSON body. Must validate tool call/result pairing.
    fn encode(&self, request: &GenerateRequest, cx: &EncodeContext<'_>) -> Result<serde_json::Value, LlmError>;

    /// Fresh decoder for one response stream.
    fn decoder(&self, model: &str) -> Box<dyn StreamDecoder>;

    /// Classify a non-2xx response body (already read) or an in-band error event.
    fn classify_error(&self, status: Option<u16>, body: &serde_json::Value, retry_after: Option<&str>, request_id: Option<&str>) -> LlmError;
}

pub trait StreamDecoder: Send {
    /// Feed one SSE event; returns zero or more chunks in order. Emits the
    /// terminal `Usage` + `Finish` when the protocol's end marker arrives.
    fn on_event(&mut self, event: SseEvent) -> Result<Vec<StreamChunk>, LlmError>;

    /// Called when the byte stream ends. Returns an error if no terminal
    /// `Finish` was emitted yet (`ErrorCode::StreamClosed`).
    fn on_close(&mut self) -> Result<Vec<StreamChunk>, LlmError>;
}
