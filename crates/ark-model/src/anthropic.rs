//! Anthropic Messages API.

use crate::http::{json, truncated};
use crate::{caps_for, classify, finalize_usage, parse_args, Conn};
use ark_core::*;
use serde_json::{json, Value};

pub(crate) struct Anthropic {
    conn: Conn,
}

const EPHEMERAL: &str = r#"{"type":"ephemeral"}"#;

impl Anthropic {
    pub fn new(conn: Conn) -> Self {
        Anthropic { conn }
    }

    fn body(&self, req: &ModelRequest) -> Value {
        let cc: Value = serde_json::from_str(EPHEMERAL).unwrap();
        let last_cached = req.system.iter().rposition(|s| s.cache);
        let system: Vec<Value> = req
            .system
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.text.is_empty())
            .map(|(i, s)| {
                let mut o = json!({"type": "text", "text": s.text});
                if Some(i) == last_cached {
                    o["cache_control"] = cc.clone();
                }
                o
            })
            .collect();
        let mut messages = Vec::new();
        for (i, m) in req.messages.iter().enumerate() {
            let mut blocks: Vec<Value> = m
                .content
                .iter()
                .filter_map(|b| match b {
                    Block::Text { text } if text.is_empty() => None,
                    Block::Text { text } => Some(json!({"type": "text", "text": text})),
                    Block::Thinking { text, signature: Some(sig) } => {
                        Some(json!({"type": "thinking", "thinking": text, "signature": sig}))
                    }
                    Block::Thinking { .. } => None,
                    Block::ToolUse { id, name, input } => {
                        Some(json!({"type": "tool_use", "id": id, "name": name, "input": input}))
                    }
                    Block::ToolResult { tool_use_id, content, is_error } => Some(
                        json!({"type": "tool_result", "tool_use_id": tool_use_id, "content": content, "is_error": is_error}),
                    ),
                })
                .collect();
            if blocks.is_empty() {
                blocks.push(json!({"type": "text", "text": "(empty)"}));
            }
            if Some(i) == req.cache_after_message {
                if let Some(last) = blocks.last_mut() {
                    last["cache_control"] = cc.clone();
                }
            }
            let role = if m.role == Role::User { "user" } else { "assistant" };
            messages.push(json!({"role": role, "content": blocks}));
        }
        let mut b = json!({"model": req.model, "max_tokens": req.max_tokens, "messages": messages, "stream": true});
        if !system.is_empty() {
            b["system"] = system.into();
        }
        if let Some(t) = req.temperature {
            b["temperature"] = t.into();
        }
        if !req.tools.is_empty() {
            b["tools"] = req
                .tools
                .iter()
                .map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.input_schema}))
                .collect();
        }
        b
    }
}

enum Part {
    Text(String),
    Thinking(String, String),
    Tool { id: String, name: String, json: String },
}

impl Provider for Anthropic {
    fn id(&self) -> &str {
        &self.conn.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        caps_for(model)
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let mut headers = self.conn.headers_with(self.conn.key.clone().map(|k| ("x-api-key", k)));
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("anthropic-version")) {
            headers.push(("anthropic-version".into(), "2023-06-01".into()));
        }
        let mut parts: Vec<Option<Part>> = Vec::new();
        let mut usage = Usage::default();
        let mut got_usage = false;
        let mut stop_raw: Option<String> = None;
        let mut stopped = false;
        let mut model = req.model.clone();

        self.conn.http.post_sse(&self.conn.url("messages"), &headers, &self.body(req), cancel, |ev| {
            let v = json(&ev.data)?;
            let ty = v.get("type").and_then(Value::as_str).or(ev.event.as_deref()).unwrap_or("");
            match ty {
                "message_start" => {
                    let m = &v["message"];
                    if let Some(id) = m["model"].as_str() {
                        model = id.into();
                    }
                    let u = &m["usage"];
                    if u.is_object() {
                        got_usage = true;
                        usage.input_tokens = u["input_tokens"].as_u64().unwrap_or(0);
                        usage.cache_read_tokens = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                        usage.cache_write_tokens = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
                        usage.output_tokens = u["output_tokens"].as_u64().unwrap_or(0);
                    }
                }
                "content_block_start" => {
                    let idx = v["index"].as_u64().unwrap_or(parts.len() as u64) as usize;
                    while parts.len() <= idx {
                        parts.push(None);
                    }
                    let cb = &v["content_block"];
                    parts[idx] = match cb["type"].as_str() {
                        Some("text") => Some(Part::Text(cb["text"].as_str().unwrap_or("").into())),
                        Some("thinking") => Some(Part::Thinking(cb["thinking"].as_str().unwrap_or("").into(), String::new())),
                        Some("tool_use") => {
                            let (id, name) = (cb["id"].as_str().unwrap_or("").to_string(), cb["name"].as_str().unwrap_or("").to_string());
                            on_event(StreamEvent::ToolUseStart { id: id.clone(), name: name.clone() });
                            Some(Part::Tool { id, name, json: String::new() })
                        }
                        _ => None,
                    };
                }
                "content_block_delta" => {
                    let idx = v["index"].as_u64().unwrap_or(0) as usize;
                    let d = &v["delta"];
                    match (parts.get_mut(idx).and_then(Option::as_mut), d["type"].as_str()) {
                        (Some(Part::Text(t)), Some("text_delta")) => {
                            let s = d["text"].as_str().unwrap_or("");
                            t.push_str(s);
                            on_event(StreamEvent::TextDelta(s.into()));
                        }
                        (Some(Part::Thinking(t, _)), Some("thinking_delta")) => {
                            let s = d["thinking"].as_str().unwrap_or("");
                            t.push_str(s);
                            on_event(StreamEvent::ThinkingDelta(s.into()));
                        }
                        (Some(Part::Thinking(_, sig)), Some("signature_delta")) => sig.push_str(d["signature"].as_str().unwrap_or("")),
                        (Some(Part::Tool { json, .. }), Some("input_json_delta")) => json.push_str(d["partial_json"].as_str().unwrap_or("")),
                        (None, _) => return Err(ProviderError::new(ProviderErrorKind::Protocol, format!("delta for unknown block {idx}"))),
                        _ => {}
                    }
                }
                "message_delta" => {
                    if let Some(s) = v["delta"]["stop_reason"].as_str() {
                        stop_raw = Some(s.into());
                    }
                    if let Some(o) = v["usage"]["output_tokens"].as_u64() {
                        got_usage = true;
                        usage.output_tokens = o;
                    }
                }
                "message_stop" => {
                    stopped = true;
                    return Ok(true);
                }
                "error" => return Err(classify::from_stream_error(&v)),
                _ => {}
            }
            Ok(false)
        })?;

        if !stopped {
            return Err(truncated("message_stop"));
        }
        let content: Vec<Block> = parts
            .into_iter()
            .flatten()
            .map(|p| match p {
                Part::Text(text) => Block::Text { text },
                Part::Thinking(text, sig) => Block::Thinking { text, signature: (!sig.is_empty()).then_some(sig) },
                Part::Tool { id, name, json } => Block::ToolUse { id, name, input: parse_args(&json) },
            })
            .collect();
        let has_tools = content.iter().any(|b| matches!(b, Block::ToolUse { .. }));
        let stop = match stop_raw.as_deref() {
            _ if has_tools => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            Some("refusal") => StopReason::Refusal,
            Some("end_turn") | Some("stop_sequence") | None => StopReason::EndTurn,
            _ => StopReason::Other,
        };
        let message = Message { role: Role::Assistant, content };
        let usage = finalize_usage(got_usage.then_some(usage), req, &message);
        Ok(ModelResponse { message, stop, usage, model })
    }
}
