//! Anthropic Messages API.

use crate::http::{json, truncated};
use crate::{
    caps_for, classify, finalize_usage, parse_args, reasoning, thinking_budget, Conn, Style,
};
use ark_core::*;
use serde_json::{json, Value};

pub(crate) struct Anthropic {
    conn: Conn,
}

const EPHEMERAL: &str = r#"{"type":"ephemeral"}"#;

/// Required with subscription (OAuth / setup-token) credentials; matches Claude Code.
const OAUTH_BETAS: &str = "claude-code-20250219,oauth-2025-04-20";
const FAST_BETA: &str = "fast-mode-2026-02-01";
/// Claude Code identity: OAuth requests without it are rejected or intermittently fail.
pub const CLAUDE_CODE_PREFIX: &str = "You are Claude Code, Anthropic's official CLI for Claude.";
const CLAUDE_CODE_VERSION: &str = "2.1.74";

/// Anthropic subscription tokens (`sk-ant-oat…`, JWTs) vs Console API keys
/// (`sk-ant-api…`, `-usr`, `-svc`, `-admin`), Hermes `_is_oauth_token`.
pub fn is_oauth_token(k: &str) -> bool {
    if k.is_empty()
        || ["sk-ant-api", "sk-ant-usr", "sk-ant-svc", "sk-ant-admin"]
            .iter()
            .any(|p| k.starts_with(p))
    {
        return false;
    }
    k.starts_with("sk-ant-") || k.starts_with("eyJ") || k.starts_with("cc-")
}

/// Models that accept Anthropic fast mode (`speed: "fast"`).
/// Exact ids, not a family prefix (Hermes `_ANTHROPIC_FAST_MODE_MODELS`): Opus 4.7
/// rejects the parameter and Opus 4.6 silently bills standard speed.
pub fn fast_capable(model: &str) -> bool {
    matches!(
        crate::modelsdb::normalize_id(model).as_str(),
        "claude-opus-4-8" | "claude-opus-5" | "claude-opus-5-5"
    )
}

#[derive(Default, Clone, Copy)]
struct Mode {
    oauth: bool,
    fast: bool,
    vertex: bool,
}

impl Anthropic {
    pub fn new(conn: Conn) -> Self {
        Anthropic { conn }
    }

    fn body(&self, req: &ModelRequest, mode: Mode) -> Value {
        let cc: Value = serde_json::from_str(EPHEMERAL).unwrap();
        let last_cached = req.system.iter().rposition(|s| s.cache);
        let mut system: Vec<Value> = req
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
                    Block::Image { media_type, data } => Some(json!({"type": "image", "source": {"type": "base64", "media_type": media_type, "data": data}})),
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
            let role = if m.role == Role::User {
                "user"
            } else {
                "assistant"
            };
            messages.push(json!({"role": role, "content": blocks}));
        }
        if mode.oauth {
            system.insert(0, json!({"type": "text", "text": CLAUDE_CODE_PREFIX}));
        }
        let mut b = json!({"model": req.model, "max_tokens": req.max_tokens, "messages": messages, "stream": true});
        if mode.vertex {
            // Vertex: the model is in the URL and the version in the body.
            b.as_object_mut().unwrap().remove("model");
            b["anthropic_version"] = "vertex-2023-10-16".into();
        }
        if mode.fast {
            b["speed"] = "fast".into();
        }
        if !system.is_empty() {
            b["system"] = system.into();
        }
        if reasoning::claude_adaptive(&req.model) {
            // Budgets are rejected here; effort is the only knob.
            if let Some(e) = self.conn.effort(reasoning::ADAPTIVE_WIRE, req) {
                b["thinking"] = json!({"type": "adaptive"});
                b["output_config"] = json!({"effort": e});
            }
        } else {
            let level = self.conn.effort(reasoning::BUDGET_WIRE, req);
            match thinking_budget(level.as_deref()) {
                // Extended thinking: max_tokens must exceed the budget and temperature must stay default.
                Some(budget) => {
                    b["thinking"] = json!({"type": "enabled", "budget_tokens": budget});
                    b["max_tokens"] = req.max_tokens.max(budget + 4096).into();
                }
                None => {
                    if let Some(t) = req.temperature {
                        b["temperature"] = t.into();
                    }
                }
            }
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
    Tool {
        id: String,
        name: String,
        json: String,
    },
}

impl Provider for Anthropic {
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
        let (base, mut headers, cred) = self.conn.prepare(Style::XApiKey)?;
        let native = crate::first_party(&self.conn, &["api.anthropic.com"]);
        let tok = cred.token.as_deref().unwrap_or("");
        let mode = Mode {
            oauth: (self.conn.auth == "oauth" || native)
                && is_oauth_token(tok)
                && !self.conn.quirk("vertex"),
            fast: native
                && req.options.service_tier.as_deref() == Some("priority")
                && fast_capable(&req.model),
            vertex: self.conn.quirk("vertex"),
        };
        let mut betas: Vec<&str> = Vec::new();
        if mode.oauth {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-api-key"));
            headers.insert(0, ("authorization".into(), format!("Bearer {tok}")));
            headers.push((
                "user-agent".into(),
                format!("claude-cli/{CLAUDE_CODE_VERSION} (external, cli)"),
            ));
            headers.push(("x-app".into(), "cli".into()));
            betas.push(OAUTH_BETAS);
        }
        if mode.fast {
            betas.push(FAST_BETA);
        }
        if !betas.is_empty() {
            match headers
                .iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case("anthropic-beta"))
            {
                Some((_, v)) => {
                    v.push(',');
                    v.push_str(&betas.join(","));
                }
                None => headers.push(("anthropic-beta".into(), betas.join(","))),
            }
        }
        if !mode.vertex
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("anthropic-version"))
        {
            headers.push(("anthropic-version".into(), "2023-06-01".into()));
        }
        let url = if mode.vertex {
            self.conn.url_on(
                &base,
                &format!("publishers/anthropic/models/{}:streamRawPredict", req.model),
            )
        } else {
            self.conn.url_on(&base, "messages")
        };
        let mut parts: Vec<Option<Part>> = Vec::new();
        let mut usage = Usage::default();
        let mut got_usage = false;
        let mut stop_raw: Option<String> = None;
        let mut stopped = false;
        let mut model = req.model.clone();

        self.conn
            .http
            .post_sse(&url, &headers, &self.body(req, mode), cancel, |ev| {
                let v = json(&ev.data)?;
                let ty = v
                    .get("type")
                    .and_then(Value::as_str)
                    .or(ev.event.as_deref())
                    .unwrap_or("");
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
                            usage.cache_read_tokens =
                                u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                            usage.cache_write_tokens =
                                u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
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
                            Some("text") => {
                                Some(Part::Text(cb["text"].as_str().unwrap_or("").into()))
                            }
                            Some("thinking") => Some(Part::Thinking(
                                cb["thinking"].as_str().unwrap_or("").into(),
                                String::new(),
                            )),
                            Some("tool_use") => {
                                let (id, name) = (
                                    cb["id"].as_str().unwrap_or("").to_string(),
                                    cb["name"].as_str().unwrap_or("").to_string(),
                                );
                                on_event(StreamEvent::ToolUseStart {
                                    id: id.clone(),
                                    name: name.clone(),
                                });
                                Some(Part::Tool {
                                    id,
                                    name,
                                    json: String::new(),
                                })
                            }
                            _ => None,
                        };
                    }
                    "content_block_delta" => {
                        let idx = v["index"].as_u64().unwrap_or(0) as usize;
                        let d = &v["delta"];
                        match (
                            parts.get_mut(idx).and_then(Option::as_mut),
                            d["type"].as_str(),
                        ) {
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
                            (Some(Part::Thinking(_, sig)), Some("signature_delta")) => {
                                sig.push_str(d["signature"].as_str().unwrap_or(""))
                            }
                            (Some(Part::Tool { json, .. }), Some("input_json_delta")) => {
                                json.push_str(d["partial_json"].as_str().unwrap_or(""))
                            }
                            (None, _) => {
                                return Err(ProviderError::new(
                                    ProviderErrorKind::Protocol,
                                    format!("delta for unknown block {idx}"),
                                ))
                            }
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
                Part::Thinking(text, sig) => Block::Thinking {
                    text,
                    signature: (!sig.is_empty()).then_some(sig),
                },
                Part::Tool { id, name, json } => Block::ToolUse {
                    id,
                    name,
                    input: parse_args(&json),
                },
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
        let message = Message {
            role: Role::Assistant,
            content,
        };
        let usage = finalize_usage(got_usage.then_some(usage), req, &message);
        Ok(ModelResponse {
            message,
            stop,
            usage,
            model,
        })
    }
}
