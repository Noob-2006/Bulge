//! Anthropic Messages wire protocol (DeepSeek's `/anthropic` endpoint uses it).
//! MARK: M3 — transcribed by dsh; see marks/M3-anthropic.md.

use super::{EncodeContext, StreamDecoder, WireProtocol};
use crate::error::LlmError;
use crate::types::GenerateRequest;

#[derive(Debug, Clone, Default)]
pub struct AnthropicMessages;

impl WireProtocol for AnthropicMessages {
    fn endpoint_path(&self) -> &'static str {
        "/v1/messages"
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![("x-api-key", api_key.to_owned()), ("anthropic-version", "2023-06-01".to_owned())]
    }

    fn encode(&self, request: &GenerateRequest, cx: &EncodeContext<'_>) -> Result<serde_json::Value, LlmError> {
        let _ = (request, cx);
        todo!("M3")
    }

    fn decoder(&self, model: &str) -> Box<dyn StreamDecoder> {
        let _ = model;
        todo!("M3")
    }

    fn classify_error(&self, status: Option<u16>, body: &serde_json::Value, retry_after: Option<&str>, request_id: Option<&str>) -> LlmError {
        crate::error::classify_http(status, body, retry_after, request_id)
    }
}

