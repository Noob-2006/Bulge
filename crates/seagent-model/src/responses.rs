//! OpenAI Responses API. Reasoning items round-trip through `Block::Thinking.signature`
//! as `{"id":..,"encrypted_content":..}` so stateless (`store:false`) tool loops keep them.

use crate::http::{json, truncated};
use crate::{caps_for, classify, data_url, finalize_usage, parse_args, reasoning, Conn, Style};
use seagent_core::*;
use serde_json::{json, Value};

pub(crate) struct Responses {
    conn: Conn,
}

impl Responses {
    pub fn new(conn: Conn) -> Self {
        Responses { conn }
    }

    fn body(&self, req: &ModelRequest) -> Value {
        let mut input = Vec::new();
        for m in &req.messages {
            for b in &m.content {
                match (m.role, b) {
                    (Role::User, Block::Text { text }) => {
                        input.push(json!({"role": "user", "content": [{"type": "input_text", "text": text}]}))
                    }
                    (Role::User, Block::Image { media_type, data }) => {
                        input.push(json!({"role": "user", "content": [{"type": "input_image", "image_url": data_url(media_type, data)}]}))
                    }
                    (Role::Assistant, Block::Text { text }) => {
                        input.push(json!({"role": "assistant", "content": [{"type": "output_text", "text": text}]}))
                    }
                    (_, Block::ToolUse { id, name, input: args }) => input.push(
                        json!({"type": "function_call", "call_id": id, "name": name, "arguments": args.to_string()}),
                    ),
                    (_, Block::ToolResult { tool_use_id, content, .. }) => {
                        input.push(json!({"type": "function_call_output", "call_id": tool_use_id, "output": content}))
                    }
                    (Role::Assistant, Block::Thinking { signature: Some(sig), .. }) => {
                        if let Ok(r) = serde_json::from_str::<Value>(sig) {
                            if r.get("encrypted_content").is_some() {
                                input.push(json!({"type": "reasoning", "id": r["id"], "summary": [], "encrypted_content": r["encrypted_content"]}));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut b = json!({
            "model": req.model,
            "input": input,
            "stream": true,
            "store": false,
            "max_output_tokens": req.max_tokens,
            "include": ["reasoning.encrypted_content"],
        });
        let sys = req.system_text();
        let codex = self.conn.quirk("codex");
        if !sys.is_empty() || codex {
            // The ChatGPT Codex backend requires `instructions`.
            b["instructions"] = if sys.is_empty() {
                "You are a helpful assistant.".into()
            } else {
                sys.into()
            };
        }
        if codex || self.conn.quirk("no_max_tokens") {
            // chatgpt.com/backend-api/codex rejects max_output_tokens and temperature.
            b.as_object_mut().unwrap().remove("max_output_tokens");
        }
        if let Some(t) = req
            .temperature
            .filter(|_| !codex && !self.conn.quirk("no_temperature"))
        {
            b["temperature"] = t.into();
        }
        let wire = if self.conn.id.starts_with("xai") || self.conn.base.contains("api.x.ai") {
            reasoning::XAI_WIRE
        } else {
            reasoning::RESPONSES_WIRE
        };
        if let Some(e) = self.conn.effort(wire, req) {
            b["reasoning"] = if e == "off" {
                json!({"effort": "none"})
            } else {
                json!({"effort": e, "summary": "auto"})
            };
        }
        let first_party =
            codex || crate::first_party(&self.conn, &["api.openai.com", "api.x.ai", "chatgpt.com"]);
        if let Some(t) = req.options.service_tier.as_deref().filter(|_| first_party) {
            b["service_tier"] = t.into();
        }
        if req.options.daybreak && codex {
            // OpenAI Daybreak (Trusted Access for Cyber) on the Codex subscription
            // route. The account's Codex catalog is the authority on which models
            // accept it; keeping this behind an explicit flag means an account
            // without the program is never sent it implicitly.
            b["access_programs"] = json!({"cyber": "daybreak_blue"});
        }
        if let Some(v) = req.options.verbosity.as_deref() {
            b["text"] = json!({"verbosity": v});
        }
        if !req.tools.is_empty() {
            let strict = req.options.strict_tools;
            b["tools"] = req
                .tools
                .iter()
                .map(|t| {
                    let mut f = json!({"type": "function", "name": t.name, "description": t.description, "parameters": t.input_schema});
                    if strict {
                        f["strict"] = true.into();
                    }
                    f
                })
                .collect();
        }
        crate::native_compact::apply(&mut b, req, &self.conn, codex);
        b
    }
}

impl Provider for Responses {
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
        let (base, headers, _) = self.conn.prepare(Style::Bearer)?;
        let mut content: Vec<Block> = Vec::new();
        let mut text = String::new();
        let mut thinking = String::new();
        let mut usage = None;
        let mut status: Option<String> = None;
        let mut model = req.model.clone();

        let mut body = self.body(req);
        crate::native_compact::send_with_recovery(&mut body, &self.conn.id, &req.model, |b| {
            self.conn.http.post_sse(
                &self.conn.url_on(&base, "responses"),
                &headers,
                b,
                cancel,
                |ev| {
                    let v = json(&ev.data)?;
                    let ty = v
                        .get("type")
                        .and_then(Value::as_str)
                        .or(ev.event.as_deref())
                        .unwrap_or("");
                    match ty {
                        "response.output_text.delta" => {
                            let d = v["delta"].as_str().unwrap_or("");
                            text.push_str(d);
                            on_event(StreamEvent::TextDelta(d.into()));
                        }
                        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
                            let d = v["delta"].as_str().unwrap_or("");
                            thinking.push_str(d);
                            on_event(StreamEvent::ThinkingDelta(d.into()));
                        }
                        "response.output_item.added" if v["item"]["type"] == "function_call" => {
                            on_event(StreamEvent::ToolUseStart {
                                id: v["item"]["call_id"].as_str().unwrap_or("").into(),
                                name: v["item"]["name"].as_str().unwrap_or("").into(),
                            });
                        }
                        "response.output_item.done" => {
                            let it = &v["item"];
                            match it["type"].as_str() {
                                Some("function_call") => {
                                    flush_text(&mut content, &mut text);
                                    let name = it["name"].as_str().unwrap_or("");
                                    if name.is_empty() {
                                        return Err(ProviderError::new(
                                            ProviderErrorKind::Protocol,
                                            "function_call without name",
                                        ));
                                    }
                                    content.push(Block::ToolUse {
                                        id: it["call_id"]
                                            .as_str()
                                            .or(it["id"].as_str())
                                            .unwrap_or("call_0")
                                            .into(),
                                        name: name.into(),
                                        input: parse_args(it["arguments"].as_str().unwrap_or("")),
                                    });
                                }
                                Some("reasoning") => {
                                    let sig = it
                                        .get("encrypted_content")
                                        .filter(|e| e.is_string())
                                        .map(|e| {
                                            json!({"id": it["id"], "encrypted_content": e}).to_string()
                                        });
                                    content.push(Block::Thinking {
                                        text: std::mem::take(&mut thinking),
                                        signature: sig,
                                    });
                                }
                                Some("message") => flush_text(&mut content, &mut text),
                                _ => {}
                            }
                        }
                        "response.completed" | "response.incomplete" => {
                            let r = &v["response"];
                            status = Some(ty.trim_start_matches("response.").to_string());
                            if let Some(m) = r["model"].as_str() {
                                model = m.into();
                            }
                            if let Some(u) = r.get("usage").filter(|u| u.is_object()) {
                                let inp = u["input_tokens"].as_u64().unwrap_or(0);
                                let cached = u["input_tokens_details"]["cached_tokens"]
                                    .as_u64()
                                    .unwrap_or(0);
                                usage = Some(Usage {
                                    input_tokens: inp.saturating_sub(cached),
                                    output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
                                    cache_read_tokens: cached,
                                    ..Default::default()
                                });
                            }
                            return Ok(true);
                        }
                        "response.failed" => {
                            let e = &v["response"]["error"];
                            return Err(classify::from_stream_error(&json!({"error": e})));
                        }
                        "error" => return Err(classify::from_stream_error(&v)),
                        _ => {}
                    }
                    Ok(false)
                },
            )
        })?;

        let Some(status) = status else {
            return Err(truncated("response.completed"));
        };
        flush_text(&mut content, &mut text);
        if !thinking.is_empty() {
            content.insert(
                0,
                Block::Thinking {
                    text: thinking,
                    signature: None,
                },
            );
        }
        let has_tools = content.iter().any(|b| matches!(b, Block::ToolUse { .. }));
        let stop = if has_tools {
            StopReason::ToolUse
        } else if status == "incomplete" {
            StopReason::MaxTokens
        } else {
            StopReason::EndTurn
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

fn flush_text(content: &mut Vec<Block>, text: &mut String) {
    if !text.is_empty() {
        content.push(Block::Text {
            text: std::mem::take(text),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Static;
    use std::sync::Arc;

    fn conn(codex: bool) -> Conn {
        Conn {
            id: if codex { "openai-codex" } else { "openai" }.into(),
            base: if codex { "https://chatgpt.com/backend-api/codex" } else { "https://api.openai.com/v1" }.into(),
            cred: Arc::new(Static::new(Some("tok".into()))),
            headers: vec![],
            query: vec![],
            auth: "oauth".into(),
            quirks: if codex { vec!["codex".into()] } else { vec![] },
            efforts: None,
            http: crate::http::Http::new(std::time::Duration::from_secs(5), "responses"),
        }
    }

    #[test]
    fn daybreak_is_explicit_and_codex_only() {
        let p = Responses::new(conn(true));
        let req = |daybreak| ModelRequest {
            model: "gpt-5.5-codex".into(),
            messages: vec![Message::user("assess this incident")],
            max_tokens: 100,
            options: RequestOptions { daybreak, ..Default::default() },
            ..Default::default()
        };
        let b = p.body(&req(true));
        assert_eq!(b["access_programs"]["cyber"], "daybreak_blue");
        assert!(p.body(&req(false)).get("access_programs").is_none(), "off by default");
        let plain = Responses::new(conn(false));
        assert!(plain.body(&req(true)).get("access_programs").is_none(), "never on the public API route");
    }
}
