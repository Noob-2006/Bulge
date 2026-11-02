//! Google Gemini `streamGenerateContent?alt=sse`. Gemini has no stable tool-call ids, so
//! ids are synthesised; `thoughtSignature`s ride on an empty `Thinking` block placed right
//! before the `ToolUse` they belong to.

use crate::http::{json, truncated};
use crate::{caps_for, classify, finalize_usage, thinking_budget, Conn};
use ark_core::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Gemini {
    conn: Conn,
}

impl Gemini {
    pub fn new(conn: Conn) -> Self {
        Gemini { conn }
    }

    fn body(&self, req: &ModelRequest) -> Value {
        let names: HashMap<&str, &str> = req
            .messages
            .iter()
            .flat_map(|m| m.tool_uses())
            .map(|(id, name, _)| (id, name))
            .collect();
        let mut contents = Vec::new();
        for m in &req.messages {
            let mut parts = Vec::new();
            let mut pending_sig: Option<&str> = None;
            for b in &m.content {
                match b {
                    Block::Text { text } if !text.is_empty() => parts.push(json!({"text": text})),
                    Block::Image { media_type, data } => parts.push(json!({"inlineData": {"mimeType": media_type, "data": data}})),
                    Block::Thinking { signature: Some(s), .. } => pending_sig = Some(s),
                    Block::ToolUse { name, input, .. } => {
                        let mut p = json!({"functionCall": {"name": name, "args": input}});
                        if let Some(s) = pending_sig.take() {
                            p["thoughtSignature"] = s.into();
                        }
                        parts.push(p);
                    }
                    Block::ToolResult { tool_use_id, content, is_error } => {
                        let name = names.get(tool_use_id.as_str()).copied().unwrap_or("unknown_tool");
                        let key = if *is_error { "error" } else { "content" };
                        parts.push(json!({"functionResponse": {"name": name, "response": {key: content}}}));
                    }
                    _ => {}
                }
            }
            if parts.is_empty() {
                parts.push(json!({"text": "(empty)"}));
            }
            let role = if m.role == Role::User { "user" } else { "model" };
            contents.push(json!({"role": role, "parts": parts}));
        }
        let mut gen = json!({"maxOutputTokens": req.max_tokens});
        if let Some(t) = req.temperature {
            gen["temperature"] = t.into();
        }
        match (req.reasoning.as_deref(), thinking_budget(req.reasoning.as_deref())) {
            (_, Some(n)) => gen["thinkingConfig"] = json!({"thinkingBudget": n, "includeThoughts": true}),
            (Some("off"), None) => gen["thinkingConfig"] = json!({"thinkingBudget": 0}),
            _ => {}
        }
        let mut b = json!({"contents": contents, "generationConfig": gen});
        let sys = req.system_text();
        if !sys.is_empty() {
            b["systemInstruction"] = json!({"parts": [{"text": sys}]});
        }
        if !req.tools.is_empty() {
            let decls: Vec<Value> = req
                .tools
                .iter()
                .map(|t| json!({"name": t.name, "description": t.description, "parameters": t.input_schema}))
                .collect();
            b["tools"] = json!([{"functionDeclarations": decls}]);
        }
        b
    }
}

impl Provider for Gemini {
    fn id(&self) -> &str {
        &self.conn.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        caps_for(model)
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let headers = self.conn.headers_with(self.conn.key.clone().map(|k| ("x-goog-api-key", k)));
        let url = self.conn.url(&format!("models/{}:streamGenerateContent?alt=sse", req.model));
        let mut content: Vec<Block> = Vec::new();
        let mut text = String::new();
        let mut thinking = String::new();
        let mut finish: Option<String> = None;
        let mut usage = None;
        let mut model = req.model.clone();

        self.conn.http.post_sse(&url, &headers, &self.body(req), cancel, |ev| {
            let v = json(&ev.data)?;
            if v.get("error").is_some() {
                return Err(classify::from_stream_error(&v));
            }
            if let Some(m) = v["modelVersion"].as_str() {
                model = m.into();
            }
            if let Some(u) = v.get("usageMetadata").filter(|u| u.is_object()) {
                let prompt = u["promptTokenCount"].as_u64().unwrap_or(0);
                let cached = u["cachedContentTokenCount"].as_u64().unwrap_or(0);
                usage = Some(Usage {
                    input_tokens: prompt.saturating_sub(cached),
                    output_tokens: u["candidatesTokenCount"].as_u64().unwrap_or(0) + u["thoughtsTokenCount"].as_u64().unwrap_or(0),
                    cache_read_tokens: cached,
                    ..Default::default()
                });
            }
            if let Some(reason) = v["promptFeedback"]["blockReason"].as_str() {
                finish = Some(format!("BLOCKED:{reason}"));
                return Ok(true);
            }
            let Some(cand) = v.get("candidates").and_then(|c| c.get(0)) else { return Ok(false) };
            for p in cand["content"]["parts"].as_array().into_iter().flatten() {
                if let Some(fc) = p.get("functionCall") {
                    if !text.is_empty() {
                        content.push(Block::Text { text: std::mem::take(&mut text) });
                    }
                    let name = fc["name"].as_str().unwrap_or("").to_string();
                    if name.is_empty() {
                        return Err(ProviderError::new(ProviderErrorKind::Protocol, "functionCall without name"));
                    }
                    let id = fc["id"].as_str().map(String::from).unwrap_or_else(|| {
                        format!("gm_{}_{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed))
                    });
                    if let Some(sig) = p["thoughtSignature"].as_str() {
                        content.push(Block::Thinking { text: String::new(), signature: Some(sig.into()) });
                    }
                    on_event(StreamEvent::ToolUseStart { id: id.clone(), name: name.clone() });
                    content.push(Block::ToolUse { id, name, input: fc.get("args").cloned().unwrap_or(json!({})) });
                } else if let Some(t) = p["text"].as_str() {
                    if p["thought"].as_bool() == Some(true) {
                        thinking.push_str(t);
                        on_event(StreamEvent::ThinkingDelta(t.into()));
                    } else {
                        text.push_str(t);
                        on_event(StreamEvent::TextDelta(t.into()));
                    }
                }
            }
            if let Some(f) = cand["finishReason"].as_str() {
                finish = Some(f.into());
            }
            Ok(false)
        })?;

        let Some(finish) = finish else { return Err(truncated("finishReason")) };
        if !text.is_empty() {
            content.push(Block::Text { text });
        }
        if !thinking.is_empty() {
            content.insert(0, Block::Thinking { text: thinking, signature: None });
        }
        let has_tools = content.iter().any(|b| matches!(b, Block::ToolUse { .. }));
        let stop = match finish.as_str() {
            _ if has_tools => StopReason::ToolUse,
            "STOP" => StopReason::EndTurn,
            "MAX_TOKENS" => StopReason::MaxTokens,
            f if f.starts_with("BLOCKED") || matches!(f, "SAFETY" | "RECITATION" | "PROHIBITED_CONTENT" | "BLOCKLIST" | "SPII") => {
                StopReason::Refusal
            }
            _ => StopReason::Other,
        };
        let message = Message { role: Role::Assistant, content };
        let usage = finalize_usage(usage, req, &message);
        Ok(ModelResponse { message, stop, usage, model })
    }
}
