//! OpenAI Chat Completions — also DeepSeek, Groq, OpenRouter, xAI, Mistral, Ollama, vLLM…

use crate::http::{json, truncated};
use crate::{caps_for, classify, data_url, finalize_usage, parse_args, reasoning, Conn, Style};
use seagent_core::*;
use serde_json::{json, Map, Value};

pub(crate) struct OpenAiChat {
    conn: Conn,
}

impl OpenAiChat {
    pub fn new(conn: Conn) -> Self {
        OpenAiChat { conn }
    }

    fn body(&self, req: &ModelRequest) -> Value {
        let mut msgs = Vec::new();
        let sys = req.system_text();
        if !sys.is_empty() {
            msgs.push(json!({"role": "system", "content": sys}));
        }
        for m in &req.messages {
            match m.role {
                Role::User => {
                    let mut text = Vec::new();
                    let mut images = Vec::new();
                    for b in &m.content {
                        match b {
                            Block::ToolResult { tool_use_id, content, .. } => {
                                msgs.push(json!({"role": "tool", "tool_call_id": tool_use_id, "content": content}))
                            }
                            Block::Text { text: t } => text.push(t.as_str()),
                            Block::Image { media_type, data } => images.push(json!({"type": "image_url", "image_url": {"url": data_url(media_type, data)}})),
                            _ => {}
                        }
                    }
                    if !images.is_empty() {
                        // Content parts only when there is an image: text-only servers expect a string.
                        let mut parts = vec![json!({"type": "text", "text": text.join("\n")})];
                        parts.extend(images);
                        msgs.push(json!({"role": "user", "content": parts}));
                    } else if !text.is_empty() {
                        msgs.push(json!({"role": "user", "content": text.join("\n")}));
                    }
                }
                Role::Assistant => {
                    let mut o = Map::new();
                    o.insert("role".into(), "assistant".into());
                    let text = m.text();
                    o.insert(
                        "content".into(),
                        if text.is_empty() {
                            Value::Null
                        } else {
                            text.into()
                        },
                    );
                    let reasoning: String = m
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            Block::Thinking { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect();
                    if !reasoning.is_empty() {
                        o.insert("reasoning_content".into(), reasoning.into());
                    }
                    let calls: Vec<Value> = m
                        .tool_uses()
                        .map(|(id, name, input)| {
                            json!({"id": id, "type": "function", "function": {"name": name, "arguments": input.to_string()}})
                        })
                        .collect();
                    if !calls.is_empty() {
                        o.insert("tool_calls".into(), calls.into());
                    }
                    msgs.push(Value::Object(o));
                }
            }
        }
        let mut b = json!({
            "model": req.model,
            "messages": msgs,
            "stream": true,
            "stream_options": {"include_usage": true},
        });
        // OpenAI proper renamed the field; compatible servers still expect `max_tokens`.
        let key = if self.conn.id.starts_with("openai") || self.conn.id.starts_with("azure") {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        if !self.conn.quirk("no_max_tokens") {
            b[key] = req.max_tokens.into();
        }
        if let Some(t) = req
            .temperature
            .filter(|_| !self.conn.quirk("no_temperature"))
        {
            b["temperature"] = t.into();
        }
        if let Some(e) = self
            .conn
            .effort(reasoning::CHAT_WIRE, req)
            .filter(|e| e != "off")
        {
            b["reasoning_effort"] = e.into();
        }
        let first_party = crate::first_party(&self.conn, &["api.openai.com", "api.x.ai"]);
        if let Some(t) = req.options.service_tier.as_deref().filter(|_| first_party) {
            b["service_tier"] = t.into();
        }
        if let Some(v) = req.options.verbosity.as_deref().filter(|_| first_party) {
            b["verbosity"] = v.into();
        }
        if !req.tools.is_empty() {
            let strict = req.options.strict_tools;
            b["tools"] = req
                .tools
                .iter()
                .map(|t| {
                    let mut f = json!({"name": t.name, "description": t.description, "parameters": t.input_schema});
                    if strict {
                        f["strict"] = true.into();
                    }
                    json!({"type": "function", "function": f})
                })
                .collect();
        }
        b
    }
}

#[derive(Default)]
struct Call {
    id: String,
    name: String,
    args: String,
}

impl Provider for OpenAiChat {
    fn id(&self) -> &str {
        &self.conn.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        caps_for(model)
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let (base, mut headers, _) = self.conn.prepare(Style::Bearer)?;
        if self.conn.quirk("copilot")
            && req
                .messages
                .iter()
                .any(|m| m.content.iter().any(|b| matches!(b, Block::Image { .. })))
        {
            headers.push(("Copilot-Vision-Request".into(), "true".into()));
        }
        let mut text = String::new();
        let mut reasoning = String::new();
        let mut calls: Vec<Call> = Vec::new();
        let mut finish: Option<String> = None;
        let mut done = false;
        let mut usage: Option<Usage> = None;
        let mut model = req.model.clone();

        self.conn.http.post_sse(
            &self.conn.url_on(&base, "chat/completions"),
            &headers,
            &self.body(req),
            cancel,
            |ev| {
                if ev.data.trim() == "[DONE]" {
                    done = true;
                    return Ok(true);
                }
                let v = json(&ev.data)?;
                if v.get("error").is_some() {
                    return Err(classify::from_stream_error(&v));
                }
                if let Some(m) = v.get("model").and_then(Value::as_str) {
                    model = m.to_string();
                }
                if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                    let prompt = u["prompt_tokens"].as_u64().unwrap_or(0);
                    let cached = u["prompt_tokens_details"]["cached_tokens"]
                        .as_u64()
                        .or_else(|| u["prompt_cache_hit_tokens"].as_u64())
                        .unwrap_or(0);
                    usage = Some(Usage {
                        input_tokens: prompt.saturating_sub(cached),
                        output_tokens: u["completion_tokens"].as_u64().unwrap_or(0),
                        cache_read_tokens: cached,
                        ..Default::default()
                    });
                }
                let Some(ch) = v.get("choices").and_then(|c| c.get(0)) else {
                    return Ok(false);
                };
                let d = &ch["delta"];
                if let Some(r) = d
                    .get("reasoning_content")
                    .or_else(|| d.get("reasoning"))
                    .and_then(Value::as_str)
                {
                    if !r.is_empty() {
                        reasoning.push_str(r);
                        on_event(StreamEvent::ThinkingDelta(r.into()));
                    }
                }
                if let Some(t) = d.get("content").and_then(Value::as_str) {
                    if !t.is_empty() {
                        text.push_str(t);
                        on_event(StreamEvent::TextDelta(t.into()));
                    }
                }
                if let Some(tcs) = d.get("tool_calls").and_then(Value::as_array) {
                    for tc in tcs {
                        let idx =
                            tc.get("index")
                                .and_then(Value::as_u64)
                                .unwrap_or(calls.len() as u64) as usize;
                        while calls.len() <= idx {
                            calls.push(Call::default());
                        }
                        let c = &mut calls[idx];
                        if let Some(id) = tc.get("id").and_then(Value::as_str) {
                            c.id = id.into();
                        }
                        let f = &tc["function"];
                        if let Some(n) = f.get("name").and_then(Value::as_str) {
                            let first = c.name.is_empty();
                            c.name.push_str(n);
                            if first {
                                on_event(StreamEvent::ToolUseStart {
                                    id: c.id.clone(),
                                    name: c.name.clone(),
                                });
                            }
                        }
                        if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                            c.args.push_str(a);
                        }
                    }
                }
                if let Some(f) = ch.get("finish_reason").and_then(Value::as_str) {
                    finish = Some(f.to_string());
                }
                Ok(false)
            },
        )?;

        if !done && finish.is_none() {
            return Err(truncated("finish_reason / [DONE]"));
        }
        let mut content = Vec::new();
        if !reasoning.is_empty() {
            content.push(Block::Thinking {
                text: reasoning,
                signature: None,
            });
        }
        if !text.is_empty() {
            content.push(Block::Text { text });
        }
        for (i, c) in calls.into_iter().enumerate() {
            if c.name.is_empty() {
                return Err(ProviderError::new(
                    ProviderErrorKind::Protocol,
                    "tool call without a function name",
                ));
            }
            let id = if c.id.is_empty() {
                format!("call_{i}")
            } else {
                c.id
            };
            content.push(Block::ToolUse {
                id,
                name: c.name,
                input: parse_args(&c.args),
            });
        }
        let has_tools = content.iter().any(|b| matches!(b, Block::ToolUse { .. }));
        let stop = match finish.as_deref() {
            _ if has_tools => StopReason::ToolUse,
            Some("length") => StopReason::MaxTokens,
            Some("content_filter") => StopReason::Refusal,
            Some("stop") | None => StopReason::EndTurn,
            _ => StopReason::Other,
        };
        let message = Message {
            role: Role::Assistant,
            content,
        };
        let usage = finalize_usage(usage, req, &message);
        Ok(ModelResponse {
            message,
            stop,
            usage,
            model,
        })
    }
}
