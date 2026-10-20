//! Anthropic Messages wire protocol (DeepSeek's `/anthropic` endpoint uses it).
//! MARK: M3 — transcribed by dsh; see marks/M3-anthropic.md.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use super::{EncodeContext, SseEvent, StreamDecoder, WireProtocol};
use crate::error::{ErrorCode, LlmError};
use crate::types::{
    BlockKind, ContentBlock, FinishReason, GenerateRequest, Message, ReasoningEffort, Role,
    StreamChunk, SystemPromptUpdate, TokenUsage,
};

#[derive(Debug, Clone, Default)]
pub struct AnthropicMessages;

impl WireProtocol for AnthropicMessages {
    fn endpoint_path(&self) -> &'static str {
        "/v1/messages"
    }

    fn models_path(&self) -> &'static str {
        "/v1/models"
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![
            ("x-api-key", api_key.to_owned()),
            ("anthropic-version", "2023-06-01".to_owned()),
        ]
    }

    fn encode(
        &self,
        request: &GenerateRequest,
        cx: &EncodeContext<'_>,
    ) -> Result<serde_json::Value, LlmError> {
        let in_history = cx.model.system_prompt_update == SystemPromptUpdate::InHistory;
        let mut messages: Vec<Value> = Vec::new();
        // System updates queued in history order; flushed after the preceding
        // user/tool-result turn and before the next assistant turn.
        let mut pending_system: Vec<Value> = Vec::new();
        let mut system: Option<String> = None;
        let mut first_system = true;

        for message in &request.messages {
            match message.role {
                Role::System => {
                    let content = system_content(message)?;
                    if first_system {
                        // The leading system message is the top-level prompt; any
                        // tool changes it carries still need conversation ordering.
                        first_system = false;
                        let text = system_text(&content);
                        append_system_text(&mut system, &text, false);
                        let tools = without_text(content);
                        if !tools.is_empty() {
                            pending_system.push(json!({ "role": "system", "content": tools }));
                        }
                    } else if in_history {
                        if content.is_empty() {
                            return Err(unsupported("empty in-history system update"));
                        }
                        pending_system.push(json!({ "role": "system", "content": content }));
                    } else {
                        // Leading-only routes merge later prompt text into the
                        // top-level system prompt; tool changes remain turns.
                        let text = system_text(&content);
                        append_system_text(&mut system, &text, true);
                        let tools = without_text(content);
                        if !tools.is_empty() {
                            pending_system.push(json!({ "role": "system", "content": tools }));
                        }
                    }
                }
                Role::Assistant => {
                    let content = assistant_content(message, &request.model)?;
                    // Empty assistant text contributes no turn at all.
                    if content.is_empty() {
                        continue;
                    }
                    flush_system_updates(&mut messages, &mut pending_system)?;
                    push_turn(&mut messages, "assistant", content);
                }
                Role::Tool => {
                    let call_id = message
                        .tool_call_id
                        .as_deref()
                        .ok_or_else(|| invalid_request("tool message without a tool_call_id"))?;
                    let content = input_content(&message.content, "tool-result")?;
                    let mut block = json!({ "type": "tool_result", "tool_use_id": call_id, "content": content });
                    if let Some(is_error) = message.is_error {
                        block["is_error"] = json!(is_error);
                    }
                    push_turn(&mut messages, "user", vec![block]);
                }
                Role::User => {
                    let content = input_content(&message.content, "user")?;
                    if content.is_empty() {
                        continue;
                    }
                    push_turn(&mut messages, "user", content);
                }
            }
        }
        flush_system_updates(&mut messages, &mut pending_system)?;

        validate_tool_pairing(&mut messages)?;

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
            "stream": true,
            "messages": messages,
            "max_tokens": max_tokens,
            "thinking": { "type": if effort == ReasoningEffort::Off { "disabled" } else { "enabled" } },
        });
        if effort != ReasoningEffort::Off {
            body["output_config"] = json!({ "effort": effort_name(effort) });
        }
        if let Some(system) = system.filter(|text| !text.is_empty()) {
            body["system"] = json!(system);
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }
        if !request.stop.is_empty() {
            body["stop_sequences"] = json!(request.stop);
        }
        if !request.tools.is_empty() {
            let tools: Vec<Value> = request
                .tools
                .iter()
                .map(|tool| {
                    let mut value = json!({
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.parameters,
                    });
                    if cx.model.deferred_tools && tool.defer_loading {
                        value["defer_loading"] = json!(true);
                    }
                    value
                })
                .collect();
            body["tools"] = json!(tools);
        }
        Ok(body)
    }

    fn decoder(&self, model: &str) -> Box<dyn StreamDecoder> {
        let _ = model;
        Box::new(AnthropicDecoder::new())
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
        format!("Messages request: {detail}"),
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

fn tool_input(raw: &str) -> Value {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) => Value::Object(object),
        _ => json!({}),
    }
}

fn assistant_content(message: &Message, model: &str) -> Result<Vec<Value>, LlmError> {
    let mut content = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text } => {
                if !text.is_empty() {
                    content.push(json!({ "type": "text", "text": text }));
                }
            }
            ContentBlock::Reasoning { text, signature } => {
                let mut value = json!({ "type": "thinking", "thinking": text });
                // Native thinking signatures are only replayable for the model
                // that produced the message.
                if message.source_model.as_deref() == Some(model)
                    && let Some(signature) = signature
                {
                    value["signature"] = json!(signature);
                }
                content.push(value);
            }
            ContentBlock::ToolCall {
                id,
                name,
                arguments,
            } => {
                content.push(json!({
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    "input": tool_input(arguments),
                }));
            }
            other => {
                return Err(unsupported(format!(
                    "assistant content block {}",
                    block_label(other)
                )));
            }
        }
    }
    Ok(content)
}

fn input_content(blocks: &[ContentBlock], context: &str) -> Result<Vec<Value>, LlmError> {
    let mut content = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text { text } => {
                if !text.is_empty() {
                    content.push(json!({ "type": "text", "text": text }));
                }
            }
            ContentBlock::Image { media_type, data } => {
                content.push(json!({
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": data,
                    },
                }));
            }
            other => {
                return Err(unsupported(format!(
                    "{context} content block {}",
                    block_label(other)
                )));
            }
        }
    }
    Ok(content)
}

fn system_content(message: &Message) -> Result<Vec<Value>, LlmError> {
    let mut content = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text } => {
                if !text.is_empty() {
                    content.push(json!({ "type": "text", "text": text }));
                }
            }
            ContentBlock::ToolAddition { name } => {
                content.push(json!({
                    "type": "tool_addition",
                    "tool": { "type": "tool_reference", "name": name },
                }));
            }
            ContentBlock::ToolRemoval { name } => {
                content.push(json!({
                    "type": "tool_removal",
                    "tool": { "type": "tool_reference", "name": name },
                }));
            }
            other => {
                return Err(unsupported(format!(
                    "system content block {}",
                    block_label(other)
                )));
            }
        }
    }
    Ok(content)
}

fn system_text(content: &[Value]) -> String {
    content
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect()
}

fn without_text(content: Vec<Value>) -> Vec<Value> {
    content
        .into_iter()
        .filter(|block| block.get("type").and_then(Value::as_str) != Some("text"))
        .collect()
}

fn append_system_text(system: &mut Option<String>, text: &str, separate: bool) {
    if text.is_empty() {
        return;
    }
    match system {
        Some(current) if separate => {
            current.push_str("\n\n");
            current.push_str(text);
        }
        Some(current) => current.push_str(text),
        None => *system = Some(text.to_owned()),
    }
}

fn flush_system_updates(
    messages: &mut Vec<Value>,
    pending: &mut Vec<Value>,
) -> Result<(), LlmError> {
    if pending.is_empty() {
        return Ok(());
    }
    let after_user = messages
        .last()
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        == Some("user");
    if !after_user {
        return Err(unsupported(
            "system update without a preceding user or tool-result turn",
        ));
    }
    messages.append(pending);
    Ok(())
}

fn push_turn(messages: &mut Vec<Value>, role: &str, content: Vec<Value>) {
    if let Some(previous) = messages.last_mut()
        && previous.get("role").and_then(Value::as_str) == Some(role)
        && let Some(existing) = previous.get_mut("content").and_then(Value::as_array_mut)
    {
        existing.extend(content);
        return;
    }
    messages.push(json!({ "role": role, "content": content }));
}

fn validate_tool_pairing(messages: &mut [Value]) -> Result<(), LlmError> {
    let mut pending: HashSet<String> = HashSet::new();
    for message in messages {
        match message.get("role").and_then(Value::as_str) {
            Some("assistant") => {
                let content = message
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid_request("assistant turn has no content array"))?;
                let mut calls = HashSet::new();
                for block in content {
                    if block.get("type").and_then(Value::as_str) != Some("tool_use") {
                        continue;
                    }
                    let id = block
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid_request("tool call without an id"))?;
                    if !calls.insert(id.to_owned()) {
                        return Err(invalid_request("duplicate tool call id"));
                    }
                }
                pending = calls;
            }
            Some("user") => {
                let content = message
                    .get_mut("content")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| invalid_request("user turn has no content array"))?;
                let mut results = Vec::new();
                let mut rest = Vec::new();
                for block in content.drain(..) {
                    if block.get("type").and_then(Value::as_str) != Some("tool_result") {
                        rest.push(block);
                        continue;
                    }
                    let id = block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid_request("tool result without a call id"))?;
                    if !pending.remove(id) {
                        return Err(invalid_request("tool result has no matching call"));
                    }
                    results.push(block);
                }
                if !pending.is_empty() {
                    return Err(invalid_request("tool calls need immediate results"));
                }
                // Results must precede every other block in the answering turn.
                results.extend(rest);
                *content = results;
            }
            _ => {}
        }
    }
    if !pending.is_empty() {
        return Err(invalid_request("history ends with unresolved tool calls"));
    }
    Ok(())
}

fn effort_name(effort: ReasoningEffort) -> &'static str {
    match effort {
        ReasoningEffort::Off => "off",
        ReasoningEffort::Low => "low",
        ReasoningEffort::High => "high",
        ReasoningEffort::Max => "max",
    }
}

#[derive(Debug)]
struct DecoderBlock {
    wire_index: u64,
    index: usize,
    content: ContentBlock,
    closed: bool,
    json: String,
}

/// Stateful decoder for the Messages event stream. Wire block indexes are
/// mapped to dense local indexes in the order blocks open.
#[derive(Debug)]
struct AnthropicDecoder {
    started: bool,
    finished: bool,
    reason: Option<FinishReason>,
    usage: TokenUsage,
    blocks: Vec<DecoderBlock>,
}

impl AnthropicDecoder {
    fn new() -> Self {
        Self {
            started: false,
            finished: false,
            reason: None,
            usage: TokenUsage::default(),
            blocks: Vec::new(),
        }
    }

    fn block_position(&self, wire_index: u64) -> Result<usize, LlmError> {
        self.blocks
            .iter()
            .position(|block| block.wire_index == wire_index)
            .ok_or_else(|| malformed("delta/stop without an open block"))
    }
}

impl StreamDecoder for AnthropicDecoder {
    fn on_event(&mut self, event: SseEvent) -> Result<Vec<StreamChunk>, LlmError> {
        if self.finished {
            return Ok(Vec::new());
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
        let event_type = object.get("type").and_then(Value::as_str);
        if event.event.as_deref() == Some("error") || event_type == Some("error") {
            return Err(crate::error::classify_http(None, &value, None, None));
        }
        let Some(event_type) = event_type else {
            // Anthropic permits additional event types; they carry no blocks.
            return Ok(Vec::new());
        };

        match event_type {
            "message_start" => {
                if self.started {
                    return Err(malformed("duplicate message_start"));
                }
                if let Some(message) = object.get("message").and_then(Value::as_object) {
                    update_usage(&mut self.usage, message.get("usage"))?;
                }
                self.started = true;
                Ok(Vec::new())
            }
            "content_block_start" => {
                if !self.started {
                    return Err(malformed("event precedes message_start"));
                }
                let wire_index = event_index(object)?;
                if self.reason.is_some()
                    || self
                        .blocks
                        .iter()
                        .any(|block| block.wire_index == wire_index)
                {
                    return Err(malformed(
                        "block starts after settlement or repeats an index",
                    ));
                }
                let native = object
                    .get("content_block")
                    .and_then(Value::as_object)
                    .ok_or_else(|| malformed("content_block_start without a content block"))?;
                let local_index = self.blocks.len();
                let (content, kind, initial) = start_block(native)?;
                let mut chunks = vec![StreamChunk::BlockStart {
                    index: local_index,
                    kind,
                }];
                match kind {
                    BlockKind::Text | BlockKind::Reasoning => {
                        if !initial.is_empty() {
                            if kind == BlockKind::Text {
                                chunks.push(StreamChunk::TextDelta {
                                    index: local_index,
                                    text: initial,
                                });
                            } else {
                                chunks.push(StreamChunk::ReasoningDelta {
                                    index: local_index,
                                    text: initial,
                                });
                            }
                        }
                    }
                    BlockKind::ToolCall => {
                        let ContentBlock::ToolCall { id, name, .. } = &content else {
                            return Err(malformed("tool block without a tool call"));
                        };
                        chunks.push(StreamChunk::ToolCallDelta {
                            index: local_index,
                            id: id.clone(),
                            name: Some(name.clone()),
                            arguments_delta: String::new(),
                        });
                    }
                }
                self.blocks.push(DecoderBlock {
                    wire_index,
                    index: local_index,
                    content,
                    closed: false,
                    json: String::new(),
                });
                Ok(chunks)
            }
            "content_block_delta" => {
                if !self.started {
                    return Err(malformed("event precedes message_start"));
                }
                let wire_index = event_index(object)?;
                let delta = object
                    .get("delta")
                    .and_then(Value::as_object)
                    .ok_or_else(|| malformed("content_block_delta without a delta"))?;
                let position = self.block_position(wire_index)?;
                if self.blocks[position].closed {
                    return Err(malformed("delta/stop without an open block"));
                }
                let block = &mut self.blocks[position];
                let delta_type = delta
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("delta without a type"))?;
                match (delta_type, &mut block.content) {
                    ("text_delta", ContentBlock::Text { text }) => {
                        let piece = required_string(delta, "text")?;
                        text.push_str(&piece);
                        Ok(vec![StreamChunk::TextDelta {
                            index: block.index,
                            text: piece,
                        }])
                    }
                    ("thinking_delta", ContentBlock::Reasoning { text, .. }) => {
                        let piece = required_string(delta, "thinking")?;
                        text.push_str(&piece);
                        Ok(vec![StreamChunk::ReasoningDelta {
                            index: block.index,
                            text: piece,
                        }])
                    }
                    ("signature_delta", ContentBlock::Reasoning { signature, .. }) => {
                        let piece = required_string(delta, "signature")?;
                        signature.get_or_insert_with(String::new).push_str(&piece);
                        Ok(Vec::new())
                    }
                    ("input_json_delta", ContentBlock::ToolCall { id, .. }) => {
                        let piece = required_string(delta, "partial_json")?;
                        block.json.push_str(&piece);
                        Ok(vec![StreamChunk::ToolCallDelta {
                            index: block.index,
                            id: id.clone(),
                            name: None,
                            arguments_delta: piece,
                        }])
                    }
                    _ => Err(malformed(format!(
                        "unsupported delta {delta_type} for block {}",
                        block.index
                    ))),
                }
            }
            "content_block_stop" => {
                if !self.started {
                    return Err(malformed("event precedes message_start"));
                }
                let wire_index = event_index(object)?;
                let position = self.block_position(wire_index)?;
                if self.blocks[position].closed {
                    return Err(malformed("delta/stop without an open block"));
                }
                let block = &mut self.blocks[position];
                block.closed = true;
                if let ContentBlock::ToolCall { arguments, .. } = &mut block.content
                    && !block.json.is_empty()
                {
                    *arguments = block.json.clone();
                }
                Ok(vec![StreamChunk::BlockEnd {
                    index: block.index,
                    block: block.content.clone(),
                }])
            }
            "message_delta" => {
                if !self.started {
                    return Err(malformed("event precedes message_start"));
                }
                let delta = object
                    .get("delta")
                    .and_then(Value::as_object)
                    .ok_or_else(|| malformed("message_delta without a delta"))?;
                if let Some(reason) = delta.get("stop_reason")
                    && !reason.is_null()
                {
                    let reason = reason
                        .as_str()
                        .ok_or_else(|| malformed("stop_reason is not a string"))?;
                    self.reason = Some(stop_reason(reason)?);
                }
                update_usage(&mut self.usage, object.get("usage"))?;
                Ok(Vec::new())
            }
            "message_stop" => {
                if !self.started {
                    return Err(malformed("event precedes message_start"));
                }
                let reason = self
                    .reason
                    .clone()
                    .ok_or_else(|| malformed("message_stop without a stop reason"))?;
                if self.blocks.iter().any(|block| !block.closed) {
                    return Err(malformed("message_stop without settled blocks"));
                }
                if self.blocks.is_empty() && reason == FinishReason::Stop {
                    return Err(LlmError::new(
                        ErrorCode::EmptyResponse,
                        "Messages returned no content",
                    ));
                }
                // Truncated tool JSON is retained on the stream and pruned by
                // the shared assembler.
                if reason != FinishReason::MaxTokens {
                    for block in &self.blocks {
                        let ContentBlock::ToolCall { arguments, .. } = &block.content else {
                            continue;
                        };
                        let parsed = serde_json::from_str::<Value>(arguments)
                            .map_err(|_| malformed("tool input is invalid JSON"))?;
                        if !parsed.is_object() {
                            return Err(malformed("tool input is not an object"));
                        }
                    }
                }
                self.finished = true;
                Ok(vec![
                    StreamChunk::Usage(self.usage),
                    StreamChunk::Finish(reason),
                ])
            }
            // `ping` and any other provider-specific event carry no content.
            _ => Ok(Vec::new()),
        }
    }

    fn on_close(&mut self) -> Result<Vec<StreamChunk>, LlmError> {
        if self.finished {
            return Ok(Vec::new());
        }
        Err(LlmError::new(
            ErrorCode::StreamClosed,
            "Messages stream ended before message_stop",
        ))
    }
}

fn malformed(detail: impl std::fmt::Display) -> LlmError {
    LlmError::new(
        ErrorCode::MalformedResponse,
        format!("Messages stream: {detail}"),
    )
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, LlmError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| malformed(format!("expected a string {field}")))
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, LlmError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(malformed(format!("expected a string {field}"))),
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, LlmError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(format!("expected an object {field}")))
}

fn event_index(object: &Map<String, Value>) -> Result<u64, LlmError> {
    object
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("invalid block index"))
}

fn start_block(native: &Map<String, Value>) -> Result<(ContentBlock, BlockKind, String), LlmError> {
    match native.get("type").and_then(Value::as_str) {
        Some("text") => {
            let text = required_string(native, "text")?;
            Ok((
                ContentBlock::Text { text: text.clone() },
                BlockKind::Text,
                text,
            ))
        }
        Some("thinking") => {
            let text = required_string(native, "thinking")?;
            let signature = optional_string(native, "signature")?;
            Ok((
                ContentBlock::Reasoning {
                    text: text.clone(),
                    signature,
                },
                BlockKind::Reasoning,
                text,
            ))
        }
        Some("tool_use") => {
            let id = required_string(native, "id")?;
            let name = required_string(native, "name")?;
            if id.is_empty() || name.is_empty() {
                return Err(malformed("empty tool identity"));
            }
            let input = required_object(native, "input")?;
            let arguments = Value::Object(input.clone()).to_string();
            Ok((
                ContentBlock::ToolCall {
                    id,
                    name,
                    arguments,
                },
                BlockKind::ToolCall,
                String::new(),
            ))
        }
        Some(other) => Err(unsupported(format!("response block {other}"))),
        None => Err(malformed("content block without a type")),
    }
}

fn stop_reason(raw: &str) -> Result<FinishReason, LlmError> {
    match raw {
        "end_turn" | "stop_sequence" => Ok(FinishReason::Stop),
        "tool_use" => Ok(FinishReason::ToolCalls),
        "max_tokens" => Ok(FinishReason::MaxTokens),
        other => Err(malformed(format!("unsupported stop reason {other}"))),
    }
}

fn update_usage(usage: &mut TokenUsage, raw: Option<&Value>) -> Result<(), LlmError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let fields = raw
        .as_object()
        .ok_or_else(|| malformed("usage is not an object"))?;
    for (wire, slot) in [
        ("input_tokens", &mut usage.input_tokens),
        ("output_tokens", &mut usage.output_tokens),
        ("cache_read_input_tokens", &mut usage.cache_read_tokens),
        ("cache_creation_input_tokens", &mut usage.cache_write_tokens),
    ] {
        if let Some(value) = fields.get(wire) {
            let count = value
                .as_u64()
                .ok_or_else(|| malformed(format!("invalid {wire}")))?;
            *slot = count;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ModelInfo, ToolSchema};

    fn model(
        system_prompt_update: SystemPromptUpdate,
        reasoning: bool,
        deferred_tools: bool,
    ) -> ModelInfo {
        ModelInfo {
            id: "test-model".to_owned(),
            context_window: 128_000,
            max_tokens: 4_096,
            system_prompt_update,
            deferred_tools,
            images: true,
            reasoning,
        }
    }

    fn request(messages: Vec<Message>) -> GenerateRequest {
        GenerateRequest {
            model: "test-model".to_owned(),
            messages,
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: crate::types::Purpose::Conversation,
        }
    }

    fn encode(request: &GenerateRequest, model: &ModelInfo) -> Value {
        AnthropicMessages
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
        AnthropicMessages
            .encode(
                request,
                &EncodeContext {
                    model,
                    default_max_tokens: 1_024,
                },
            )
            .expect_err("encode should fail")
    }

    fn assistant_text(text: &str) -> Message {
        Message::text(Role::Assistant, text)
    }

    fn tool_call(id: &str, name: &str, arguments: &str) -> ContentBlock {
        ContentBlock::ToolCall {
            id: id.to_owned(),
            name: name.to_owned(),
            arguments: arguments.to_owned(),
        }
    }

    fn tool_message(id: &str, text: &str) -> Message {
        Message::tool_result(id, text, false)
    }

    #[test]
    fn in_history_system_updates_follow_the_preceding_user_turn() {
        let messages = vec![
            Message::text(Role::System, "base"),
            Message::text(Role::User, "hello"),
            Message::text(Role::System, "update"),
            assistant_text("first"),
            Message::text(Role::User, "again"),
            assistant_text("second"),
        ];
        let body = encode(
            &request(messages),
            &model(SystemPromptUpdate::InHistory, true, false),
        );
        assert_eq!(body["system"], "base");
        let turns = body["messages"].as_array().expect("messages");
        assert_eq!(turns.len(), 5);
        assert_eq!(turns[0]["role"], "user");
        assert_eq!(turns[0]["content"][0]["text"], "hello");
        assert_eq!(turns[1]["role"], "system");
        assert_eq!(turns[1]["content"][0]["text"], "update");
        assert_eq!(turns[2]["role"], "assistant");
        assert_eq!(turns[3]["role"], "user");
        assert_eq!(turns[4]["role"], "assistant");
    }

    #[test]
    fn in_history_update_without_a_user_turn_is_unsupported() {
        let messages = vec![
            Message::text(Role::System, "base"),
            Message::text(Role::System, "update"),
        ];
        let error = encode_error(
            &request(messages),
            &model(SystemPromptUpdate::InHistory, true, false),
        );
        assert_eq!(error.code, ErrorCode::UnsupportedContent);
    }

    #[test]
    fn leading_only_system_updates_merge_into_the_top_level_prompt() {
        let messages = vec![
            Message::text(Role::System, "base"),
            Message::text(Role::User, "hello"),
            Message::text(Role::System, "extra"),
            assistant_text("ok"),
        ];
        let body = encode(
            &request(messages),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(body["system"], "base\n\nextra");
        let turns = body["messages"].as_array().expect("messages");
        assert_eq!(turns.len(), 2);
        assert_eq!(turns[0]["role"], "user");
        assert_eq!(turns[1]["role"], "assistant");
    }

    #[test]
    fn signatures_are_replayed_only_for_the_same_source_model() {
        let reasoning = |source_model: Option<&str>| Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Reasoning {
                text: "thinking".to_owned(),
                signature: Some("sig".to_owned()),
            }],
            tool_call_id: None,
            is_error: None,
            source_model: source_model.map(str::to_owned),
        };

        let same = encode(
            &request(vec![reasoning(Some("test-model"))]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(same["messages"][0]["content"][0]["signature"], "sig");

        for source in [Some("other-model"), None] {
            let body = encode(
                &request(vec![reasoning(source)]),
                &model(SystemPromptUpdate::LeadingOnly, true, false),
            );
            let thinking = &body["messages"][0]["content"][0];
            assert_eq!(thinking["type"], "thinking");
            assert_eq!(thinking["thinking"], "thinking");
            assert!(thinking.get("signature").is_none());
        }
    }

    #[test]
    fn invalid_tool_arguments_become_an_empty_object() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                tool_call("call-1", "lookup", "not json"),
                tool_call("call-2", "lookup", "[1,2]"),
            ],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        };
        let body = encode(
            &request(vec![
                message,
                tool_message("call-1", "one"),
                tool_message("call-2", "two"),
            ]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(body["messages"][0]["content"][0]["input"], json!({}));
        assert_eq!(body["messages"][0]["content"][1]["input"], json!({}));
    }

    #[test]
    fn duplicate_tool_call_ids_are_invalid() {
        let message = Message {
            role: Role::Assistant,
            content: vec![
                tool_call("call-1", "lookup", "{}"),
                tool_call("call-1", "lookup", "{}"),
            ],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        };
        let error = encode_error(
            &request(vec![message]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn tool_results_need_a_matching_call() {
        let error = encode_error(
            &request(vec![tool_message("missing", "result")]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn tool_calls_need_immediate_results() {
        let assistant = Message {
            role: Role::Assistant,
            content: vec![tool_call("call-1", "lookup", "{}")],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        };
        let error = encode_error(
            &request(vec![assistant, Message::text(Role::User, "no result")]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(error.code, ErrorCode::InvalidRequest);

        let assistant = Message {
            role: Role::Assistant,
            content: vec![tool_call("call-1", "lookup", "{}")],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        };
        let error = encode_error(
            &request(vec![assistant]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn tool_results_move_to_the_front_of_the_answering_turn() {
        let assistant = Message {
            role: Role::Assistant,
            content: vec![tool_call("call-1", "lookup", "{\"q\":1}")],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        };
        let body = encode(
            &request(vec![
                assistant,
                Message::text(Role::User, "note"),
                tool_message("call-1", "result"),
            ]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        let content = body["messages"][1]["content"].as_array().expect("content");
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "tool_result");
        assert_eq!(content[0]["tool_use_id"], "call-1");
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "note");
    }

    #[test]
    fn tool_changes_are_only_valid_in_system_messages() {
        let body = encode(
            &request(vec![
                Message {
                    role: Role::System,
                    content: vec![ContentBlock::ToolAddition {
                        name: "lookup".to_owned(),
                    }],
                    tool_call_id: None,
                    is_error: None,
                    source_model: None,
                },
                Message::text(Role::User, "hello"),
                Message::text(Role::System, "update"),
                assistant_text("ok"),
            ]),
            &model(SystemPromptUpdate::InHistory, true, false),
        );
        let turns = body["messages"].as_array().expect("messages");
        assert_eq!(turns[1]["role"], "system");
        assert_eq!(turns[1]["content"][0]["type"], "tool_addition");
        assert_eq!(turns[1]["content"][0]["tool"]["name"], "lookup");

        let error = encode_error(
            &request(vec![Message {
                role: Role::User,
                content: vec![ContentBlock::ToolRemoval {
                    name: "lookup".to_owned(),
                }],
                tool_call_id: None,
                is_error: None,
                source_model: None,
            }]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(error.code, ErrorCode::UnsupportedContent);
    }

    #[test]
    fn images_and_stop_sequences_are_encoded() {
        let mut request = request(vec![Message {
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
        }]);
        request.stop = vec!["STOP".to_owned()];
        let body = encode(
            &request,
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert_eq!(body["stop_sequences"], json!(["STOP"]));
        let content = &body["messages"][0]["content"];
        assert_eq!(content[1]["type"], "image");
        assert_eq!(content[1]["source"]["type"], "base64");
        assert_eq!(content[1]["source"]["media_type"], "image/png");
        assert_eq!(content[1]["source"]["data"], "aGVsbG8=");
    }

    #[test]
    fn effort_defaults_and_overrides_switch_thinking() {
        let model_on = model(SystemPromptUpdate::LeadingOnly, true, false);
        let body = encode(&request(vec![Message::text(Role::User, "hi")]), &model_on);
        assert_eq!(body["thinking"]["type"], "enabled");
        assert_eq!(body["output_config"]["effort"], "high");

        let mut off = request(vec![Message::text(Role::User, "hi")]);
        off.reasoning_effort = Some(ReasoningEffort::Off);
        let body = encode(&off, &model_on);
        assert_eq!(body["thinking"]["type"], "disabled");
        assert!(body.get("output_config").is_none());

        let model_off = model(SystemPromptUpdate::LeadingOnly, false, false);
        let body = encode(&request(vec![Message::text(Role::User, "hi")]), &model_off);
        assert_eq!(body["thinking"]["type"], "disabled");
        assert!(body.get("output_config").is_none());

        let mut low = request(vec![Message::text(Role::User, "hi")]);
        low.reasoning_effort = Some(ReasoningEffort::Low);
        let body = encode(&low, &model_on);
        assert_eq!(body["output_config"]["effort"], "low");
    }

    #[test]
    fn defer_loading_is_gated_by_the_model_capability_and_order_is_kept() {
        let mut request = request(vec![Message::text(Role::User, "hi")]);
        request.tools = vec![
            ToolSchema {
                name: "first".to_owned(),
                description: "one".to_owned(),
                parameters: json!({"type": "object"}),
                defer_loading: false,
            },
            ToolSchema {
                name: "second".to_owned(),
                description: "two".to_owned(),
                parameters: json!({"type": "object"}),
                defer_loading: true,
            },
        ];
        let body = encode(
            &request,
            &model(SystemPromptUpdate::LeadingOnly, true, true),
        );
        let tools = body["tools"].as_array().expect("tools");
        assert_eq!(tools[0]["name"], "first");
        assert!(tools[0].get("defer_loading").is_none());
        assert_eq!(tools[1]["name"], "second");
        assert_eq!(tools[1]["defer_loading"], true);

        let body = encode(
            &request,
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        assert!(body["tools"][1].get("defer_loading").is_none());
        assert_eq!(body["tools"][1]["description"], "two");
    }

    #[test]
    fn max_tokens_falls_back_from_request_to_model_to_default() {
        let mut req = request(vec![Message::text(Role::User, "hi")]);
        let model = model(SystemPromptUpdate::LeadingOnly, true, false);
        assert_eq!(encode(&req, &model)["max_tokens"], 4_096);
        req.max_tokens = Some(12);
        assert_eq!(encode(&req, &model)["max_tokens"], 12);

        let mut no_model_limit = model.clone();
        no_model_limit.max_tokens = 0;
        let fallback = request(vec![Message::text(Role::User, "hi")]);
        assert_eq!(encode(&fallback, &no_model_limit)["max_tokens"], 1_024);
    }

    fn sse(value: Value) -> SseEvent {
        SseEvent {
            event: value.get("type").and_then(Value::as_str).map(str::to_owned),
            data: value.to_string(),
        }
    }

    fn feed(decoder: &mut AnthropicDecoder, value: Value) -> Vec<StreamChunk> {
        decoder.on_event(sse(value)).expect("event")
    }

    #[test]
    fn decoder_translates_a_complete_mixed_stream() {
        let mut decoder = AnthropicDecoder::new();
        let mut chunks = Vec::new();
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "message_start",
                "message": { "usage": {
                    "input_tokens": 10,
                    "output_tokens": 1,
                    "cache_read_input_tokens": 3,
                    "cache_creation_input_tokens": 2
                }}
            }),
        ));
        chunks.extend(feed(&mut decoder, json!({"type": "ping"})));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "thinking", "thinking": "", "signature": "a"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "thinking_delta", "thinking": "think"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "signature_delta", "signature": "b"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "signature_delta", "signature": "c"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({"type": "content_block_stop", "index": 0}),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "text", "text": "Hello"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "text_delta", "text": " world"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({"type": "content_block_stop", "index": 1}),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_start",
                "index": 2,
                "content_block": {
                    "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
                }
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 2,
                "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 2,
                "delta": {"type": "input_json_delta", "partial_json": "\"x\"}"}
            }),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({"type": "content_block_stop", "index": 2}),
        ));
        chunks.extend(feed(
            &mut decoder,
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 5}
            }),
        ));
        chunks.extend(feed(&mut decoder, json!({"type": "message_stop"})));

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
                        signature: Some("abc".to_owned())
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
                    id: "tool-1".to_owned(),
                    name: Some("lookup".to_owned()),
                    arguments_delta: String::new()
                },
                StreamChunk::ToolCallDelta {
                    index: 2,
                    id: "tool-1".to_owned(),
                    name: None,
                    arguments_delta: "{\"q\":".to_owned()
                },
                StreamChunk::ToolCallDelta {
                    index: 2,
                    id: "tool-1".to_owned(),
                    name: None,
                    arguments_delta: "\"x\"}".to_owned()
                },
                StreamChunk::BlockEnd {
                    index: 2,
                    block: ContentBlock::ToolCall {
                        id: "tool-1".to_owned(),
                        name: "lookup".to_owned(),
                        arguments: "{\"q\":\"x\"}".to_owned()
                    }
                },
                StreamChunk::Usage(TokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_read_tokens: 3,
                    cache_write_tokens: 2,
                    reasoning_tokens: 0
                }),
                StreamChunk::Finish(FinishReason::ToolCalls),
            ]
        );
        assert!(decoder.on_close().expect("closed").is_empty());
    }

    #[test]
    fn truncated_tool_json_is_kept_on_max_tokens() {
        let mut decoder = AnthropicDecoder::new();
        feed(&mut decoder, json!({"type": "message_start"}));
        feed(
            &mut decoder,
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
                }
            }),
        );
        feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
            }),
        );
        let stopped = feed(
            &mut decoder,
            json!({"type": "content_block_stop", "index": 0}),
        );
        assert_eq!(
            stopped,
            vec![StreamChunk::BlockEnd {
                index: 0,
                block: ContentBlock::ToolCall {
                    id: "tool-1".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: "{\"q\":".to_owned()
                }
            }]
        );
        feed(
            &mut decoder,
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "max_tokens"}
            }),
        );
        let chunks = feed(&mut decoder, json!({"type": "message_stop"}));
        assert_eq!(
            chunks,
            vec![
                StreamChunk::Usage(TokenUsage::default()),
                StreamChunk::Finish(FinishReason::MaxTokens)
            ]
        );
    }

    #[test]
    fn close_without_message_stop_is_stream_closed() {
        let mut decoder = AnthropicDecoder::new();
        feed(&mut decoder, json!({"type": "message_start"}));
        let error = decoder.on_close().expect_err("must be closed");
        assert_eq!(error.code, ErrorCode::StreamClosed);
    }

    #[test]
    fn unknown_events_are_ignored() {
        let mut decoder = AnthropicDecoder::new();
        feed(&mut decoder, json!({"type": "message_start"}));
        assert!(feed(&mut decoder, json!({"type": "ping"})).is_empty());
        assert!(feed(&mut decoder, json!({"type": "provider_extension"})).is_empty());
        feed(
            &mut decoder,
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
        );
        let chunks = feed(&mut decoder, json!({"type": "message_stop"}));
        assert_eq!(
            chunks,
            vec![
                StreamChunk::Usage(TokenUsage::default()),
                StreamChunk::Finish(FinishReason::ToolCalls)
            ]
        );
    }

    #[test]
    fn empty_stop_response_is_an_error() {
        let mut decoder = AnthropicDecoder::new();
        feed(&mut decoder, json!({"type": "message_start"}));
        feed(
            &mut decoder,
            json!({"type": "message_delta", "delta": {"stop_reason": "stop_sequence"}}),
        );
        let error = decoder
            .on_event(sse(json!({"type": "message_stop"})))
            .expect_err("empty response");
        assert_eq!(error.code, ErrorCode::EmptyResponse);
    }

    #[test]
    fn error_events_are_classified() {
        let mut decoder = AnthropicDecoder::new();
        let error = decoder
            .on_event(sse(json!({
                "type": "error",
                "error": {"type": "invalid_request_error", "message": "bad input"}
            })))
            .expect_err("error event");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.message, "bad input");
    }

    #[test]
    fn malformed_tool_json_is_rejected_unless_truncated() {
        let mut decoder = AnthropicDecoder::new();
        feed(&mut decoder, json!({"type": "message_start"}));
        feed(
            &mut decoder,
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
                }
            }),
        );
        feed(
            &mut decoder,
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
            }),
        );
        feed(
            &mut decoder,
            json!({"type": "content_block_stop", "index": 0}),
        );
        feed(
            &mut decoder,
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
        );
        let error = decoder
            .on_event(sse(json!({"type": "message_stop"})))
            .expect_err("malformed tool json");
        assert_eq!(error.code, ErrorCode::MalformedResponse);
    }
}
