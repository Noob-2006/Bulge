//! OpenAI Chat Completions wire protocol (OpenAI-compatible endpoints,
//! including DeepSeek's native `/chat/completions` with `reasoning_content`).
//! MARK: M6 — transcribed by dsh; see marks/M6-openai-chat.md.

use super::{EncodeContext, StreamDecoder, WireProtocol};
use crate::error::LlmError;
use crate::types::GenerateRequest;

#[derive(Debug, Clone, Default)]
pub struct OpenAiChat;

impl WireProtocol for OpenAiChat {
    fn endpoint_path(&self) -> &'static str {
        "/chat/completions"
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![("authorization", format!("Bearer {api_key}"))]
    }

    fn encode(&self, request: &GenerateRequest, cx: &EncodeContext<'_>) -> Result<serde_json::Value, LlmError> {
        let _ = (request, cx);
        todo!("M6")
    }

    fn decoder(&self, model: &str) -> Box<dyn StreamDecoder> {
        let _ = model;
        todo!("M6")
    }

    fn classify_error(&self, status: Option<u16>, body: &serde_json::Value, retry_after: Option<&str>, request_id: Option<&str>) -> LlmError {
        crate::error::classify_http(status, body, retry_after, request_id)
    }
}
