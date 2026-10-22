//! OpenAI Chat Completions wire protocol (OpenAI-compatible endpoints,
//! including DeepSeek's native `/chat/completions` with `reasoning_content`).
//! MARK: M6 — transcribed by dsh; see marks/M6-openai-chat.md.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::{EncodeContext, SseEvent, StreamDecoder, WireProtocol};
use crate::error::{ErrorCode, LlmError};
use crate::types::{
    BlockKind, ContentBlock, FinishReason, GenerateRequest, Message, ReasoningEffort, Role,
    StreamChunk, TokenUsage, ToolChoice,
};

#[derive(Debug, Clone, Default)]
pub struct OpenAiChat;

impl WireProtocol for OpenAiChat {
    fn endpoint_path(&self) -> &'static str {
        "/chat/completions"
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![("authorization", format!("Bearer {api_key}"))]
    }

    fn encode(
        &self,
        request: &GenerateRequest,
        cx: &EncodeContext<'_>,
    ) -> Result<serde_json::Value, LlmError> {
        validate_tool_pairing(&request.messages)?;

        let mut messages = Vec::new();
        for message in &request.messages {
            match message.role {
                Role::System => messages.push(system_message(message)?),
                Role::User => messages.push(user_message(message)?),
                Role::Assistant => {
                    // Blank assistant turns carry no content; replaying them only
                    // confuses providers that require non-empty assistant turns.
                    if is_blank_assistant(message) {
                        continue;
                    }
                    messages.push(assistant_message(message, &request.model)?);
                }
                Role::Tool => messages.push(tool_message(message)?),
            }
        }

        let effort = request.reasoning_effort.unwrap_or(if cx.model.reasoning {
            ReasoningEffort::High
        } else {
            ReasoningEffort::Off
        });
        let max_tokens = request
            .max_tokens
            .or_else(|| (cx.model.max_tokens > 0).then_some(cx.model.max_tokens))
            .unwrap_or(cx.default_max_tokens);

        let mut body = json!({
            "model": request.model,
            "messages": messages,
            "stream": true,
            "stream_options": { "include_usage": true },
            "max_tokens": max_tokens,
        });
        if cx.model.reasoning && effort != ReasoningEffort::Off {
            body["reasoning_effort"] = json!(effort_name(effort));
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }
        if !request.stop.is_empty() {
            body["stop"] = json!(request.stop);
        }
        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|tool| {
                    // `defer_loading` has no Chat Completions equivalent, so the
                    // tool is declared normally (active immediately).
                    json!({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters,
                        },
                    })
                })
                .collect();
            body["tools"] = json!(tools);
            if request.tool_choice == ToolChoice::None {
                body["tool_choice"] = json!("none");
            }
        }
        Ok(body)
    }

    fn decoder(&self, model: &str) -> Box<dyn StreamDecoder> {
        let _ = model;
        Box::new(OpenAiChatDecoder::new())
    }

    fn classify_error(
        &self,
        status: Option<u16>,
        body: &serde_json::Value,
        retry_after: Option<&str>,
        request_id: Option<&str>,
    ) -> LlmError {
        crate::error::classify_http(status, body, retry_after, request_id)
    }
}

fn unsupported(detail: impl std::fmt::Display) -> LlmError {
    LlmError::unsupported(detail)
}

fn invalid_request(detail: impl std::fmt::Display) -> LlmError {
    LlmError::new(
        ErrorCode::InvalidRequest,
        format!("Chat Completions request: {detail}"),
    )
}

fn malformed(detail: impl std::fmt::Display) -> LlmError {
    LlmError::new(
        ErrorCode::MalformedResponse,
        format!("Chat Completions stream: {detail}"),
    )
}

fn block_label(block: &ContentBlock) -> &'static str {
    match block {
        ContentBlock::Text { .. } => "text",
        ContentBlock::Reasoning { .. } => "reasoning",
        ContentBlock::ToolCall { .. } => "tool call",
        ContentBlock::Image { .. } => "image",
        ContentBlock::ToolAddition { .. } => "tool addition",
        ContentBlock::ToolRemoval { .. } => "tool removal",
    }
}

fn system_message(message: &Message) -> Result<Value, LlmError> {
    let mut text = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text: value } => text.push(value.clone()),
            ContentBlock::ToolAddition { .. } | ContentBlock::ToolRemoval { .. } => {
                return Err(unsupported(format!(
                    "system content block {} in Chat Completions",
                    block_label(block)
                )));
            }
            other => {
                return Err(unsupported(format!(
                    "system content block {}",
                    block_label(other)
                )));
            }
        }
    }
    Ok(json!({ "role": "system", "content": text.join("\n") }))
}

fn user_message(message: &Message) -> Result<Value, LlmError> {
    let mut text = String::new();
    let mut parts = Vec::new();
    let mut has_image = false;
    for block in &message.content {
        match block {
            ContentBlock::Text { text: value } => {
                text.push_str(value);
                parts.push(json!({ "type": "text", "text": value }));
            }
            ContentBlock::Image { media_type, data } => {
                has_image = true;
                parts.push(json!({
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:{media_type};base64,{data}"),
                    },
                }));
            }
            other => {
                return Err(unsupported(format!(
                    "user content block {}",
                    block_label(other)
                )));
            }
        }
    }
    // Plain text turns use the compact string form; mixed turns need parts.
    let content = if has_image { json!(parts) } else { json!(text) };
    Ok(json!({ "role": "user", "content": content }))
}

fn assistant_message(message: &Message, model: &str) -> Result<Value, LlmError> {
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut tool_calls = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text: value } => text.push_str(value),
            ContentBlock::Reasoning { text: value, .. } => reasoning.push_str(value),
            ContentBlock::ToolCall {
                id,
                name,
                arguments,
            } => tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": { "name": name, "arguments": arguments },
            })),
            other => {
                return Err(unsupported(format!(
                    "assistant content block {}",
                    block_label(other)
                )));
            }
        }
    }

    let content = if text.is_empty() && !tool_calls.is_empty() {
        Value::Null
    } else {
        json!(text)
    };
    let mut value = json!({ "role": "assistant", "content": content });
    if !tool_calls.is_empty() {
        value["tool_calls"] = json!(tool_calls);
    }
    // Reasoning is only replayable to the model that produced it.
    if message.source_model.as_deref() == Some(model) && !reasoning.is_empty() {
        value["reasoning_content"] = json!(reasoning);
    }
    Ok(value)
}

fn tool_message(message: &Message) -> Result<Value, LlmError> {
    let call_id = message
        .tool_call_id
        .as_deref()
        .ok_or_else(|| invalid_request("tool message without a tool_call_id"))?;
    let mut text = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text: value } => text.push(value.clone()),
            other => {
                return Err(unsupported(format!(
                    "tool-result content block {}",
                    block_label(other)
                )));
            }
        }
    }
    // Chat Completions has no error flag on tool messages; carry it in-band so
    // the model can still tell a failed call from a successful one.
    let mut content = text.join("\n");
    if message.is_error == Some(true) {
        content.insert_str(0, "[tool error]\n");
    }
    Ok(json!({
        "role": "tool",
        "tool_call_id": call_id,
        "content": content,
    }))
}

#[cfg(test)]
mod tool_error_tests {
    use super::*;

    #[test]
    fn tool_error_flag_is_carried_in_content() {
        let failed = Message::tool_result("call-1", "boom", true);
        assert_eq!(tool_message(&failed).map(|v| v["content"].clone()).ok(), Some(json!("[tool error]\nboom")));
        let ok = Message::tool_result("call-1", "fine", false);
        assert_eq!(tool_message(&ok).map(|v| v["content"].clone()).ok(), Some(json!("fine")));
    }
}

fn is_blank_assistant(message: &Message) -> bool {
    message
        .content
        .iter()
        .all(|block| matches!(block, ContentBlock::Text { text } if text.trim().is_empty()))
}

/// Every call must be answered by the tool messages that immediately follow its
/// assistant turn; duplicate ids and orphan results are invalid.
fn validate_tool_pairing(messages: &[Message]) -> Result<(), LlmError> {
    let mut pending: Vec<String> = Vec::new();
    for message in messages {
        match message.role {
            Role::Tool => {
                let id = message
                    .tool_call_id
                    .as_deref()
                    .ok_or_else(|| invalid_request("tool message without a tool_call_id"))?;
                let Some(position) = pending.iter().position(|call| call == id) else {
                    return Err(invalid_request("tool result has no matching call"));
                };
                pending.remove(position);
            }
            Role::Assistant => {
                if !pending.is_empty() {
                    return Err(invalid_request("tool calls need immediate results"));
                }
                let mut calls = Vec::new();
                for block in &message.content {
                    let ContentBlock::ToolCall { id, .. } = block else {
                        continue;
                    };
                    if calls.iter().any(|call| call == id) {
                        return Err(invalid_request("duplicate tool call id"));
                    }
                    calls.push(id.clone());
                }
                pending = calls;
            }
            Role::System | Role::User => {
                if !pending.is_empty() {
                    return Err(invalid_request("tool calls need immediate results"));
                }
            }
        }
    }
    if !pending.is_empty() {
        return Err(invalid_request("history ends with unresolved tool calls"));
    }
    Ok(())
}

fn effort_name(effort: ReasoningEffort) -> &'static str {
    match effort {
        // Off is never encoded; keep a total mapping for exhaustiveness.
        ReasoningEffort::Off => "off",
        ReasoningEffort::Low => "low",
        ReasoningEffort::High | ReasoningEffort::Max => "high",
    }
}

#[derive(Debug)]
struct DecoderBlock {
    index: usize,
    kind: BlockKind,
    content: ContentBlock,
    closed: bool,
}

/// Stateful decoder for the Chat Completions event stream. Wire tool-call
/// indexes are aggregated into dense local block indexes; parallel tool calls
/// stay open together, while a switch between text, reasoning, and tools closes
/// the previous kind first so block order matches arrival order.
#[derive(Debug)]
struct OpenAiChatDecoder {
    finished: bool,
    finish_reason: Option<FinishReason>,
    usage: TokenUsage,
    blocks: Vec<DecoderBlock>,
    tools: HashMap<u64, usize>,
}

impl OpenAiChatDecoder {
    fn new() -> Self {
        Self {
            finished: false,
            finish_reason: None,
            usage: TokenUsage::default(),
            blocks: Vec::new(),
            tools: HashMap::new(),
        }
    }

    fn open_index(&self, kind: BlockKind) -> Option<usize> {
        self.blocks
            .iter()
            .rev()
            .find(|block| !block.closed && block.kind == kind)
            .map(|block| block.index)
    }

    /// Close every open block whose kind is not `keep`, preserving index order.
    fn close_open(&mut self, keep: Option<BlockKind>, out: &mut Vec<StreamChunk>) {
        for block in &mut self.blocks {
            if block.closed || keep == Some(block.kind) {
                continue;
            }
            block.closed = true;
            out.push(StreamChunk::BlockEnd {
                index: block.index,
                block: block.content.clone(),
            });
        }
    }

    fn push_text(&mut self, text: &str, out: &mut Vec<StreamChunk>) {
        if let Some(index) = self.open_index(BlockKind::Text) {
            if let ContentBlock::Text { text: current } = &mut self.blocks[index].content {
                current.push_str(text);
            }
            out.push(StreamChunk::TextDelta {
                index,
                text: text.to_owned(),
            });
            return;
        }
        self.close_open(Some(BlockKind::Text), out);
        let index = self.blocks.len();
        self.blocks.push(DecoderBlock {
            index,
            kind: BlockKind::Text,
            content: ContentBlock::Text {
                text: text.to_owned(),
            },
            closed: false,
        });
        out.push(StreamChunk::BlockStart {
            index,
            kind: BlockKind::Text,
        });
        out.push(StreamChunk::TextDelta {
            index,
            text: text.to_owned(),
        });
    }

    fn push_reasoning(&mut self, text: &str, out: &mut Vec<StreamChunk>) {
        if let Some(index) = self.open_index(BlockKind::Reasoning) {
            if let ContentBlock::Reasoning { text: current, .. } = &mut self.blocks[index].content {
                current.push_str(text);
            }
            out.push(StreamChunk::ReasoningDelta {
                index,
                text: text.to_owned(),
            });
            return;
        }
        self.close_open(Some(BlockKind::Reasoning), out);
        let index = self.blocks.len();
        self.blocks.push(DecoderBlock {
            index,
            kind: BlockKind::Reasoning,
            content: ContentBlock::Reasoning {
                text: text.to_owned(),
                signature: None,
            },
            closed: false,
        });
        out.push(StreamChunk::BlockStart {
            index,
            kind: BlockKind::Reasoning,
        });
        out.push(StreamChunk::ReasoningDelta {
            index,
            text: text.to_owned(),
        });
    }

    fn push_tool_delta(
        &mut self,
        wire_index: u64,
        id: Option<&str>,
        name: Option<&str>,
        arguments: &str,
        out: &mut Vec<StreamChunk>,
    ) -> Result<(), LlmError> {
        if let Some(&index) = self.tools.get(&wire_index) {
            if self.blocks[index].closed {
                return Err(malformed("tool call delta after its block closed"));
            }
            let ContentBlock::ToolCall {
                id: call_id,
                arguments: current,
                ..
            } = &mut self.blocks[index].content
            else {
                return Err(malformed("tool index is not a tool call block"));
            };
            current.push_str(arguments);
            if !arguments.is_empty() {
                out.push(StreamChunk::ToolCallDelta {
                    index,
                    id: call_id.clone(),
                    name: None,
                    arguments_delta: arguments.to_owned(),
                });
            }
            return Ok(());
        }

        let id = id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| malformed("tool call delta is missing an id on first appearance"))?;
        let name = name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| malformed("tool call delta is missing a name on first appearance"))?;
        self.close_open(Some(BlockKind::ToolCall), out);
        let index = self.blocks.len();
        self.blocks.push(DecoderBlock {
            index,
            kind: BlockKind::ToolCall,
            content: ContentBlock::ToolCall {
                id: id.to_owned(),
                name: name.to_owned(),
                arguments: arguments.to_owned(),
            },
            closed: false,
        });
        self.tools.insert(wire_index, index);
        out.push(StreamChunk::BlockStart {
            index,
            kind: BlockKind::ToolCall,
        });
        out.push(StreamChunk::ToolCallDelta {
            index,
            id: id.to_owned(),
            name: Some(name.to_owned()),
            arguments_delta: arguments.to_owned(),
        });
        Ok(())
    }

    fn settle(&mut self, out: &mut Vec<StreamChunk>) {
        self.close_open(None, out);
    }

    fn terminal(&mut self, reason: FinishReason, out: &mut Vec<StreamChunk>) {
        out.push(StreamChunk::Usage(self.usage));
        out.push(StreamChunk::Finish(reason));
        self.finished = true;
    }
}

impl StreamDecoder for OpenAiChatDecoder {
    fn on_event(&mut self, event: SseEvent) -> Result<Vec<StreamChunk>, LlmError> {
        if self.finished {
            return Ok(Vec::new());
        }
        if event.data.trim() == "[DONE]" {
            let mut chunks = Vec::new();
            self.settle(&mut chunks);
            let reason = self
                .finish_reason
                .clone()
                .ok_or_else(|| malformed("stream ended without a finish_reason"))?;
            self.terminal(reason, &mut chunks);
            return Ok(chunks);
        }

        let parsed = serde_json::from_str::<Value>(&event.data);
        let value = match parsed {
            Ok(value) => value,
            Err(error) => {
                if event.event.as_deref() == Some("error") {
                    return Err(crate::error::classify_http(None, &Value::Null, None, None));
                }
                return Err(malformed(format!("invalid event JSON: {error}")));
            }
        };
        let Some(object) = value.as_object() else {
            if event.event.as_deref() == Some("error") {
                return Err(crate::error::classify_http(None, &value, None, None));
            }
            return Err(malformed("event is not a JSON object"));
        };
        if event.event.as_deref() == Some("error")
            || object.get("error").is_some_and(|error| !error.is_null())
        {
            return Err(crate::error::classify_http(None, &value, None, None));
        }

        if let Some(usage) = object.get("usage").filter(|usage| !usage.is_null()) {
            update_usage(&mut self.usage, usage)?;
        }
        let choices = match object.get("choices") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(choices)) => choices.as_slice(),
            Some(_) => return Err(malformed("choices is not an array")),
        };
        let choice = choices.first();
        if let Some(choice) = choice
            && let Some(usage) = choice.get("usage").filter(|usage| !usage.is_null())
        {
            update_usage(&mut self.usage, usage)?;
        }

        if self.finish_reason.is_some() {
            if choice.is_some_and(has_late_content) {
                return Err(malformed("content after the finish_reason"));
            }
            return Ok(Vec::new());
        }

        let mut chunks = Vec::new();
        if let Some(choice) = choice {
            if let Some(delta) = choice.get("delta").filter(|delta| !delta.is_null()) {
                let delta = delta
                    .as_object()
                    .ok_or_else(|| malformed("delta is not an object"))?;
                let reasoning = match optional_string(delta, "reasoning_content")? {
                    Some(text) => Some(text),
                    None => optional_string(delta, "reasoning")?,
                };
                if let Some(text) = reasoning.filter(|text| !text.is_empty()) {
                    self.push_reasoning(&text, &mut chunks);
                }
                if let Some(text) =
                    optional_string(delta, "content")?.filter(|text| !text.is_empty())
                {
                    self.push_text(&text, &mut chunks);
                }
                if let Some(tools) = delta.get("tool_calls").filter(|tools| !tools.is_null()) {
                    let tools = tools
                        .as_array()
                        .ok_or_else(|| malformed("tool_calls is not an array"))?;
                    for tool in tools {
                        let tool = tool
                            .as_object()
                            .ok_or_else(|| malformed("tool call delta is not an object"))?;
                        let wire_index = tool
                            .get("index")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| malformed("tool call delta without an index"))?;
                        let id = optional_string(tool, "id")?;
                        let (name, arguments) =
                            match tool.get("function").filter(|function| !function.is_null()) {
                                None => (None, String::new()),
                                Some(function) => {
                                    let function = function.as_object().ok_or_else(|| {
                                        malformed("tool call function is not an object")
                                    })?;
                                    (
                                        optional_string(function, "name")?,
                                        optional_string(function, "arguments")?.unwrap_or_default(),
                                    )
                                }
                            };
                        self.push_tool_delta(
                            wire_index,
                            id.as_deref(),
                            name.as_deref(),
                            &arguments,
                            &mut chunks,
                        )?;
                    }
                }
            }
            if let Some(reason) = choice
                .get("finish_reason")
                .filter(|reason| !reason.is_null())
            {
                let reason = reason
                    .as_str()
                    .ok_or_else(|| malformed("finish_reason is not a string"))?;
                let reason = map_finish_reason(reason)?;
                self.settle(&mut chunks);
                self.finish_reason = Some(reason);
            }
        }
        Ok(chunks)
    }

    fn on_close(&mut self) -> Result<Vec<StreamChunk>, LlmError> {
        if self.finished {
            return Ok(Vec::new());
        }
        let Some(reason) = self.finish_reason.clone() else {
            return Err(LlmError::new(
                ErrorCode::StreamClosed,
                "Chat Completions stream ended without [DONE] or a finish_reason",
            ));
        };
        let mut chunks = Vec::new();
        self.settle(&mut chunks);
        self.terminal(reason, &mut chunks);
        Ok(chunks)
    }
}

fn has_late_content(choice: &Value) -> bool {
    let Some(delta) = choice.get("delta") else {
        return false;
    };
    let Some(delta) = delta.as_object() else {
        return !delta.is_null();
    };
    ["content", "reasoning_content", "reasoning"]
        .iter()
        .any(|field| {
            delta
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty())
        })
        || delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|tools| !tools.is_empty())
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, LlmError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(malformed(format!("expected a string {field}"))),
    }
}

fn optional_count(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, LlmError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| malformed(format!("expected an integer {field}"))),
    }
}

fn update_usage(usage: &mut TokenUsage, raw: &Value) -> Result<(), LlmError> {
    let fields = raw
        .as_object()
        .ok_or_else(|| malformed("usage is not an object"))?;
    let prompt = optional_count(fields, "prompt_tokens")?;
    let completion = optional_count(fields, "completion_tokens")?;
    let cached_in_details = match fields
        .get("prompt_tokens_details")
        .filter(|details| !details.is_null())
    {
        None => None,
        Some(details) => {
            let details = details
                .as_object()
                .ok_or_else(|| malformed("prompt_tokens_details is not an object"))?;
            optional_count(details, "cached_tokens")?
        }
    };
    let cached = match cached_in_details {
        Some(cached) => Some(cached),
        None => optional_count(fields, "prompt_cache_hit_tokens")?,
    };
    if let Some(prompt) = prompt {
        let cached = cached.unwrap_or(0);
        usage.cache_read_tokens = cached;
        usage.input_tokens = prompt.saturating_sub(cached);
    } else if let Some(cached) = cached {
        usage.cache_read_tokens = cached;
    }
    if let Some(completion) = completion {
        usage.output_tokens = completion;
    }
    if let Some(details) = fields
        .get("completion_tokens_details")
        .filter(|details| !details.is_null())
    {
        let details = details
            .as_object()
            .ok_or_else(|| malformed("completion_tokens_details is not an object"))?;
        if let Some(reasoning) = optional_count(details, "reasoning_tokens")? {
            usage.reasoning_tokens = reasoning;
        }
    }
    Ok(())
}

fn map_finish_reason(raw: &str) -> Result<FinishReason, LlmError> {
    match raw {
        "stop" => Ok(FinishReason::Stop),
        "tool_calls" | "function_call" => Ok(FinishReason::ToolCalls),
        "length" => Ok(FinishReason::MaxTokens),
        "content_filter" => Ok(FinishReason::Stop),
        other => Err(malformed(format!("unsupported finish_reason {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ModelInfo, Purpose, SystemPromptUpdate, ToolSchema};

    fn model(reasoning: bool) -> ModelInfo {
        ModelInfo {
            id: "test-model".to_owned(),
            context_window: 128_000,
            max_tokens: 4_096,
            system_prompt_update: SystemPromptUpdate::LeadingOnly,
            deferred_tools: false,
            images: true,
            reasoning,
        }
    }

    fn request(messages: Vec<Message>) -> GenerateRequest {
        GenerateRequest {
            model: "test-model".to_owned(),
            messages,
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Conversation,
        }
    }

    fn encode(request: &GenerateRequest, model: &ModelInfo) -> Value {
        OpenAiChat
            .encode(
                request,
                &EncodeContext {
                    model,
                    default_max_tokens: 1_024,
                },
            )
            .expect("encode")
    }

    fn encode_error(request: &GenerateRequest, model: &ModelInfo) -> LlmError {
        OpenAiChat
            .encode(
                request,
                &EncodeContext {
                    model,
                    default_max_tokens: 1_024,
                },
            )
            .expect_err("encode should fail")
    }

    fn assistant(blocks: Vec<ContentBlock>, source_model: Option<&str>) -> Message {
        Message {
            role: Role::Assistant,
            content: blocks,
            tool_call_id: None,
            is_error: None,
            source_model: source_model.map(str::to_owned),
        }
    }

    fn tool_call(id: &str, name: &str, arguments: &str) -> ContentBlock {
        ContentBlock::ToolCall {
            id: id.to_owned(),
            name: name.to_owned(),
            arguments: arguments.to_owned(),
        }
    }

    fn sse(value: Value) -> SseEvent {
        SseEvent {
            event: None,
            data: value.to_string(),
        }
    }

    fn feed(decoder: &mut OpenAiChatDecoder, value: Value) -> Vec<StreamChunk> {
        decoder.on_event(sse(value)).expect("event")
    }

    fn feed_done(decoder: &mut OpenAiChatDecoder) -> Vec<StreamChunk> {
        decoder
            .on_event(SseEvent {
                event: None,
                data: "[DONE]".to_owned(),
            })
            .expect("[DONE]")
    }

    #[test]
    fn mid_history_system_updates_are_each_emitted_in_order() {
        let body = encode(
            &request(vec![
                Message::text(Role::System, "base"),
                Message::text(Role::User, "hello"),
                Message::text(Role::System, "update"),
                Message::text(Role::Assistant, "first"),
            ]),
            &model(true),
        );
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"]["include_usage"], true);
        assert_eq!(body["max_tokens"], 4_096);
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "base");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "hello");
        assert_eq!(messages[2]["role"], "system");
        assert_eq!(messages[2]["content"], "update");
        assert_eq!(messages[3]["role"], "assistant");
        assert_eq!(messages[3]["content"], "first");
    }

    #[test]
    fn reasoning_is_replayed_only_for_the_same_source_model() {
        let reasoning = || {
            assistant(
                vec![
                    ContentBlock::Reasoning {
                        text: "think".to_owned(),
                        signature: Some("sig".to_owned()),
                    },
                    ContentBlock::Text {
                        text: "answer".to_owned(),
                    },
                ],
                Some("test-model"),
            )
        };
        let same = encode(&request(vec![reasoning()]), &model(true));
        assert_eq!(same["messages"][0]["content"], "answer");
        assert_eq!(same["messages"][0]["reasoning_content"], "think");

        for source in [Some("other-model"), None] {
            let mut message = reasoning();
            message.source_model = source.map(str::to_owned);
            let body = encode(&request(vec![message]), &model(true));
            assert_eq!(body["messages"][0]["content"], "answer");
            assert!(body["messages"][0].get("reasoning_content").is_none());
        }
    }

    #[test]
    fn tool_pairing_errors_are_invalid_requests() {
        let orphan = encode_error(
            &request(vec![Message::tool_result("missing", "result", false)]),
            &model(true),
        );
        assert_eq!(orphan.code, ErrorCode::InvalidRequest);

        let unresolved = encode_error(
            &request(vec![assistant(
                vec![tool_call("call-1", "lookup", "{}")],
                None,
            )]),
            &model(true),
        );
        assert_eq!(unresolved.code, ErrorCode::InvalidRequest);

        let duplicate = encode_error(
            &request(vec![assistant(
                vec![
                    tool_call("call-1", "lookup", "{}"),
                    tool_call("call-1", "lookup", "{}"),
                ],
                None,
            )]),
            &model(true),
        );
        assert_eq!(duplicate.code, ErrorCode::InvalidRequest);

        let broken_sequence = encode_error(
            &request(vec![
                assistant(vec![tool_call("call-1", "lookup", "{}")], None),
                Message::text(Role::User, "not a result"),
                Message::tool_result("call-1", "too late", false),
            ]),
            &model(true),
        );
        assert_eq!(broken_sequence.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn images_are_encoded_as_data_uri_image_urls() {
        let body = encode(
            &request(vec![Message {
                role: Role::User,
                content: vec![
                    ContentBlock::Text {
                        text: "look".to_owned(),
                    },
                    ContentBlock::Image {
                        media_type: "image/png".to_owned(),
                        data: "aGVsbG8=".to_owned(),
                    },
                ],
                tool_call_id: None,
                is_error: None,
                source_model: None,
            }]),
            &model(true),
        );
        let content = body["messages"][0]["content"].as_array().expect("content");
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "look");
        assert_eq!(content[1]["type"], "image_url");
        assert_eq!(
            content[1]["image_url"]["url"],
            "data:image/png;base64,aGVsbG8="
        );

        let text_only = encode(
            &request(vec![Message::text(Role::User, "plain")]),
            &model(true),
        );
        assert_eq!(text_only["messages"][0]["content"], "plain");
    }

    #[test]
    fn reasoning_effort_is_gated_by_the_model_capability() {
        let on = model(true);
        let default = encode(&request(vec![Message::text(Role::User, "hi")]), &on);
        assert_eq!(default["reasoning_effort"], "high");

        for (effort, expected) in [
            (ReasoningEffort::Low, Some("low")),
            (ReasoningEffort::High, Some("high")),
            (ReasoningEffort::Max, Some("high")),
            (ReasoningEffort::Off, None),
        ] {
            let mut req = request(vec![Message::text(Role::User, "hi")]);
            req.reasoning_effort = Some(effort);
            let body = encode(&req, &on);
            match expected {
                Some(expected) => assert_eq!(body["reasoning_effort"], expected),
                None => assert!(body.get("reasoning_effort").is_none()),
            }
        }

        let off = model(false);
        let body = encode(&request(vec![Message::text(Role::User, "hi")]), &off);
        assert!(body.get("reasoning_effort").is_none());
        let mut req = request(vec![Message::text(Role::User, "hi")]);
        req.reasoning_effort = Some(ReasoningEffort::High);
        let body = encode(&req, &off);
        assert!(body.get("reasoning_effort").is_none());
    }

    #[test]
    fn tool_choice_none_keeps_tools_and_forbids_calls() {
        let mut req = request(vec![Message::text(Role::User, "hi")]);
        req.tools = vec![ToolSchema {
            name: "lookup".to_owned(),
            description: "find a thing".to_owned(),
            parameters: json!({"type": "object"}),
            defer_loading: false,
        }];
        let auto = encode(&req, &model(false));
        assert!(auto.get("tool_choice").is_none());
        req.tool_choice = ToolChoice::None;
        let none = encode(&req, &model(false));
        assert_eq!(none["tools"], auto["tools"], "tool list must stay byte-identical");
        assert_eq!(none["tool_choice"], "none");
    }

    #[test]
    fn tools_are_declared_normally_even_when_deferred() {
        let mut req = request(vec![Message::text(Role::User, "hi")]);
        req.tools = vec![ToolSchema {
            name: "lookup".to_owned(),
            description: "find a thing".to_owned(),
            parameters: json!({"type": "object"}),
            defer_loading: true,
        }];
        let body = encode(&req, &model(true));
        let tool = &body["tools"][0];
        assert_eq!(tool["type"], "function");
        assert_eq!(tool["function"]["name"], "lookup");
        assert_eq!(tool["function"]["description"], "find a thing");
        assert_eq!(tool["function"]["parameters"], json!({"type": "object"}));
        assert!(tool.get("defer_loading").is_none());
        assert!(tool["function"].get("defer_loading").is_none());

        let none = encode(
            &request(vec![Message::text(Role::User, "hi")]),
            &model(true),
        );
        assert!(none.get("tools").is_none());
    }

    #[test]
    fn tool_messages_join_text_blocks_and_tool_calls_keep_raw_arguments() {
        let body = encode(
            &request(vec![
                assistant(
                    vec![
                        ContentBlock::Text {
                            text: "calling".to_owned(),
                        },
                        tool_call("call-1", "lookup", "{\"q\":1}"),
                    ],
                    None,
                ),
                Message {
                    role: Role::Tool,
                    content: vec![
                        ContentBlock::Text {
                            text: "one".to_owned(),
                        },
                        ContentBlock::Text {
                            text: "two".to_owned(),
                        },
                    ],
                    tool_call_id: Some("call-1".to_owned()),
                    is_error: None,
                    source_model: None,
                },
            ]),
            &model(true),
        );
        let messages = body["messages"].as_array().expect("messages");
        assert_eq!(messages[0]["content"], "calling");
        assert_eq!(messages[0]["tool_calls"][0]["id"], "call-1");
        assert_eq!(messages[0]["tool_calls"][0]["type"], "function");
        assert_eq!(messages[0]["tool_calls"][0]["function"]["name"], "lookup");
        assert_eq!(
            messages[0]["tool_calls"][0]["function"]["arguments"],
            "{\"q\":1}"
        );
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "call-1");
        assert_eq!(messages[1]["content"], "one\ntwo");

        let tool_only = encode(
            &request(vec![
                assistant(vec![tool_call("call-1", "lookup", "{}")], None),
                Message::tool_result("call-1", "result", false),
            ]),
            &model(true),
        );
        assert!(tool_only["messages"][0]["content"].is_null());
    }

    #[test]
    fn unsupported_blocks_are_reported() {
        let system_tool_change = encode_error(
            &request(vec![Message {
                role: Role::System,
                content: vec![ContentBlock::ToolAddition {
                    name: "lookup".to_owned(),
                }],
                tool_call_id: None,
                is_error: None,
                source_model: None,
            }]),
            &model(true),
        );
        assert_eq!(system_tool_change.code, ErrorCode::UnsupportedContent);

        let assistant_image = encode_error(
            &request(vec![assistant(
                vec![ContentBlock::Image {
                    media_type: "image/png".to_owned(),
                    data: "aGVsbG8=".to_owned(),
                }],
                None,
            )]),
            &model(true),
        );
        assert_eq!(assistant_image.code, ErrorCode::UnsupportedContent);
    }

    #[test]
    fn decoder_translates_reasoning_text_parallel_tools_usage_and_done() {
        let mut decoder = OpenAiChatDecoder::new();
        let mut chunks = Vec::new();
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [{ "delta": { "reasoning_content": "think" } }]
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({ "choices": [{ "delta": { "content": "Hello" } }] }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({ "choices": [{ "delta": { "content": " world" } }] }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-1",
                                "type": "function",
                                "function": { "name": "lookup", "arguments": "{\"q\":" }
                            },
                            {
                                "index": 1,
                                "id": "call-2",
                                "type": "function",
                                "function": { "name": "other", "arguments": "{\"x\":" }
                            }
                        ]
                    }
                }]
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [
                            { "index": 0, "function": { "arguments": "1}" } }
                        ]
                    }
                }]
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [{
                    "delta": {
                        "tool_calls": [
                            { "index": 1, "function": { "arguments": "2}" } }
                        ]
                    }
                }]
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({ "choices": [{ "delta": {}, "finish_reason": "tool_calls" }] }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "prompt_tokens_details": { "cached_tokens": 3 },
                    "completion_tokens_details": { "reasoning_tokens": 2 }
                }
            }),
        ));
        chunks.extend(feed_done(&mut decoder));

        assert_eq!(
            chunks,
            vec![
                StreamChunk::BlockStart {
                    index: 0,
                    kind: BlockKind::Reasoning
                },
                StreamChunk::ReasoningDelta {
                    index: 0,
                    text: "think".to_owned()
                },
                StreamChunk::BlockEnd {
                    index: 0,
                    block: ContentBlock::Reasoning {
                        text: "think".to_owned(),
                        signature: None
                    }
                },
                StreamChunk::BlockStart {
                    index: 1,
                    kind: BlockKind::Text
                },
                StreamChunk::TextDelta {
                    index: 1,
                    text: "Hello".to_owned()
                },
                StreamChunk::TextDelta {
                    index: 1,
                    text: " world".to_owned()
                },
                StreamChunk::BlockEnd {
                    index: 1,
                    block: ContentBlock::Text {
                        text: "Hello world".to_owned()
                    }
                },
                StreamChunk::BlockStart {
                    index: 2,
                    kind: BlockKind::ToolCall
                },
                StreamChunk::ToolCallDelta {
                    index: 2,
                    id: "call-1".to_owned(),
                    name: Some("lookup".to_owned()),
                    arguments_delta: "{\"q\":".to_owned()
                },
                StreamChunk::BlockStart {
                    index: 3,
                    kind: BlockKind::ToolCall
                },
                StreamChunk::ToolCallDelta {
                    index: 3,
                    id: "call-2".to_owned(),
                    name: Some("other".to_owned()),
                    arguments_delta: "{\"x\":".to_owned()
                },
                StreamChunk::ToolCallDelta {
                    index: 2,
                    id: "call-1".to_owned(),
                    name: None,
                    arguments_delta: "1}".to_owned()
                },
                StreamChunk::ToolCallDelta {
                    index: 3,
                    id: "call-2".to_owned(),
                    name: None,
                    arguments_delta: "2}".to_owned()
                },
                StreamChunk::BlockEnd {
                    index: 2,
                    block: ContentBlock::ToolCall {
                        id: "call-1".to_owned(),
                        name: "lookup".to_owned(),
                        arguments: "{\"q\":1}".to_owned()
                    }
                },
                StreamChunk::BlockEnd {
                    index: 3,
                    block: ContentBlock::ToolCall {
                        id: "call-2".to_owned(),
                        name: "other".to_owned(),
                        arguments: "{\"x\":2}".to_owned()
                    }
                },
                StreamChunk::Usage(TokenUsage {
                    input_tokens: 7,
                    output_tokens: 5,
                    cache_read_tokens: 3,
                    cache_write_tokens: 0,
                    reasoning_tokens: 2
                }),
                StreamChunk::Finish(FinishReason::ToolCalls),
            ]
        );
        assert!(feed_done(&mut decoder).is_empty());
    }

    #[test]
    fn deepseek_cache_hits_are_subtracted_from_prompt_tokens() {
        let mut decoder = OpenAiChatDecoder::new();
        let mut chunks = feed(
            &mut decoder,
            json!({ "choices": [{ "delta": { "content": "hi" } }] }),
        );
        chunks.extend(feed(
            &mut decoder,
            json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "choices": [],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 10,
                    "prompt_cache_hit_tokens": 40,
                    "completion_tokens_details": { "reasoning_tokens": 1 }
                }
            }),
        ));
        chunks.extend(feed_done(&mut decoder));
        assert!(matches!(
            &chunks[chunks.len() - 2],
            StreamChunk::Usage(TokenUsage {
                input_tokens: 60,
                output_tokens: 10,
                cache_read_tokens: 40,
                cache_write_tokens: 0,
                reasoning_tokens: 1,
            })
        ));
        assert_eq!(
            chunks.last(),
            Some(&StreamChunk::Finish(FinishReason::Stop))
        );
    }

    #[test]
    fn on_close_finishes_when_a_finish_reason_was_seen() {
        let mut decoder = OpenAiChatDecoder::new();
        let mut chunks = feed(
            &mut decoder,
            json!({ "choices": [{ "delta": { "content": "hi" } }] }),
        );
        chunks.extend(feed(
            &mut decoder,
            json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] }),
        ));
        assert!(matches!(
            chunks.last(),
            Some(StreamChunk::BlockEnd {
                index: 0,
                block: ContentBlock::Text { .. }
            })
        ));

        let closed = decoder.on_close().expect("close");
        assert!(matches!(
            closed.as_slice(),
            [
                StreamChunk::Usage(_),
                StreamChunk::Finish(FinishReason::Stop)
            ]
        ));
        assert!(decoder.on_close().expect("second close").is_empty());
    }

    #[test]
    fn on_close_without_done_or_finish_reason_is_stream_closed() {
        let mut decoder = OpenAiChatDecoder::new();
        feed(
            &mut decoder,
            json!({ "choices": [{ "delta": { "content": "hi" } }] }),
        );
        let error = decoder.on_close().expect_err("should fail");
        assert_eq!(error.code, ErrorCode::StreamClosed);
    }

    #[test]
    fn in_band_errors_are_classified() {
        let mut decoder = OpenAiChatDecoder::new();
        let error = decoder
            .on_event(sse(json!({
                "error": { "type": "rate_limit_error", "message": "slow down" }
            })))
            .expect_err("in-band error");
        assert_eq!(error.code, ErrorCode::RateLimit);
    }

    #[test]
    fn unsupported_finish_reasons_are_malformed() {
        let mut decoder = OpenAiChatDecoder::new();
        let error = decoder
            .on_event(sse(json!({
                "choices": [{ "delta": {}, "finish_reason": "banana" }]
            })))
            .expect_err("unknown finish reason");
        assert_eq!(error.code, ErrorCode::MalformedResponse);
    }
}
