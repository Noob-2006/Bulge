//! OpenAI Agents API harness (hosted agent sessions): OpenClaw `extensions/agentsapi`.
//! A session is created once per conversation (`POST {base}/agents/sessions`), each user
//! turn is submitted with `POST {base}/agents/sessions/{id}/turns`, and the run streams
//! SSE events: text/reasoning deltas, seagent's function calls, and `session/tokenUsage`-style
//! usage. seagent's own tools travel as hosted function tools; a function call the stream
//! reports becomes a `Block::ToolUse` so the kernel executes it and submits the result on
//! the next turn.
//!
//! Conversation identity: the kernel hands us a (possibly compacted) transcript and no
//! conversation id, so a hosted session is cached under a digest of (model, system
//! prompt, first user message) — see [`conversation_key`]. Two conversations sharing all
//! three share one hosted session; the hosted sandbox is the only state that can leak.

use crate::http::json;
use crate::{
    caps_for, classify, data_url, finalize_usage, parse_args, Conn, ProviderConfig, Style,
};
use seagent_core::*;
use serde_json::{json, Map, Value};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// Hosted sessions kept at once (each pins an OpenAI-side environment).
const MAX_SESSIONS: usize = 4;

pub(crate) struct AgentsApi {
    conn: Conn,
    /// Most recently used first; bounded by [`MAX_SESSIONS`].
    sessions: Mutex<Vec<Cached>>,
}

struct Cached {
    key: u64,
    id: String,
    /// `req.messages.len()` already submitted to this session.
    sent: usize,
}

impl AgentsApi {
    pub(crate) fn new(conn: crate::Conn, cfg: &ProviderConfig) -> AgentsApi {
        let _ = cfg;
        AgentsApi {
            conn,
            sessions: Mutex::new(Vec::new()),
        }
    }

    fn lookup(&self, key: u64) -> Option<(String, usize)> {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let i = guard.iter().position(|c| c.key == key)?;
        let hit = guard.remove(i);
        let out = (hit.id.clone(), hit.sent);
        guard.insert(0, hit);
        Some(out)
    }

    fn store(&self, key: u64, id: &str, sent: usize) {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|c| c.key != key);
        guard.insert(
            0,
            Cached {
                key,
                id: id.to_string(),
                sent,
            },
        );
        guard.truncate(MAX_SESSIONS);
    }

    fn forget(&self, key: u64) {
        let mut guard = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|c| c.key != key);
    }

    /// One non-streamed JSON POST (session create); non-2xx is classified like any other.
    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &Value,
        cancel: &Cancel,
    ) -> Result<Value, ProviderError> {
        let mut buf = Vec::new();
        self.conn.http.post_stream(
            url,
            headers,
            serde_json::to_vec(body).expect("json"),
            cancel,
            |c| {
                buf.extend_from_slice(c);
                Ok(false)
            },
        )?;
        serde_json::from_slice(&buf).map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::Protocol,
                format!("{url}: not JSON ({e})"),
            )
        })
    }

    fn session_body(&self, req: &ModelRequest) -> Value {
        let mut agent = Map::new();
        agent.insert("model".into(), json!(req.model));
        // One seagent turn per user message: the hosted session must not fan out on its own.
        agent.insert("multi_agent".into(), json!({"enabled": false}));
        let sys = req.system_text();
        if !sys.is_empty() {
            agent.insert("instructions".into(), json!(sys));
        }
        if !req.tools.is_empty() {
            agent.insert(
                "tools".into(),
                Value::Array(
                    req.tools
                        .iter()
                        .map(|t| {
                            json!({
                                "type": "function",
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.input_schema,
                            })
                        })
                        .collect(),
                ),
            );
        }
        if let Some(e) = req
            .reasoning
            .as_deref()
            .and_then(|r| crate::reasoning::clamp(r, &["minimal", "low", "medium", "high"]))
            .filter(|e| *e != "off")
        {
            agent.insert("reasoning".into(), json!({"effort": e}));
        }
        json!({"agent": agent, "environment": {"type": "openai_hosted"}})
    }

    fn create_session(
        &self,
        base: &str,
        headers: &[(String, String)],
        req: &ModelRequest,
        cancel: &Cancel,
    ) -> Result<String, ProviderError> {
        let v = self.post_json(
            &self.conn.url_on(base, "agents/sessions"),
            headers,
            &self.session_body(req),
            cancel,
        )?;
        v.get("id")
            .or_else(|| v.get("session_id"))
            .or_else(|| v.get("session").and_then(|s| s.get("id")))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::Protocol,
                    "POST /agents/sessions returned no session id",
                )
            })
    }

    /// Stream one turn and fold its events into a response.
    fn run_turn(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: Value,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<(Message, StopReason, Usage, String), ProviderError> {
        let mut turn = Turn::default();
        self.conn.http.post_sse(url, headers, &body, cancel, |ev| {
            if ev.data.trim() == "[DONE]" {
                turn.done = true;
                return Ok(true);
            }
            let v = json(&ev.data)?;
            turn.event(&v, on_event)
        })?;
        if !turn.done {
            return Err(crate::http::truncated(
                "the turn's completion event (stream closed early)",
            ));
        }
        if let Some(msg) = turn.failed {
            return Err(ProviderError::new(
                ProviderErrorKind::Server,
                format!("Agents API turn failed: {msg}"),
            ));
        }
        let mut content = Vec::new();
        if !turn.reasoning.is_empty() {
            content.push(Block::Thinking {
                text: turn.reasoning,
                signature: None,
            });
        }
        if !turn.text.is_empty() {
            content.push(Block::Text { text: turn.text });
        }
        for (i, c) in turn.calls.iter().enumerate() {
            if c.name.is_empty() {
                return Err(ProviderError::new(
                    ProviderErrorKind::Protocol,
                    "Agents API function call without a name",
                ));
            }
            content.push(Block::ToolUse {
                id: if c.id.is_empty() {
                    format!("call_{i}")
                } else {
                    c.id.clone()
                },
                name: c.name.clone(),
                input: parse_args(&c.args),
            });
        }
        let stop = if content.iter().any(|b| matches!(b, Block::ToolUse { .. })) {
            StopReason::ToolUse
        } else {
            StopReason::EndTurn
        };
        let message = Message {
            role: Role::Assistant,
            content,
        };
        let usage = finalize_usage(turn.usage, req, &message);
        let model = if turn.model.is_empty() {
            req.model.clone()
        } else {
            turn.model
        };
        Ok((message, stop, usage, model))
    }
}

/// Session digest: model + system prompt + first user message (see the module docs).
fn conversation_key(req: &ModelRequest) -> u64 {
    let mut h = DefaultHasher::new();
    req.model.hash(&mut h);
    req.system
        .iter()
        .map(|s| s.text.as_str())
        .collect::<String>()
        .hash(&mut h);
    req.messages
        .iter()
        .find(|m| m.role == Role::User)
        .map(|m| m.text())
        .unwrap_or_default()
        .hash(&mut h);
    h.finish()
}

/// The new part of the conversation, in Agents API input shapes. `fresh` (a brand-new
/// session) also replays assistant turns; on a continuation the hosted session already
/// holds them, so only user input and function-call outputs are submitted.
fn input_items(req: &ModelRequest, from: usize, fresh: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for m in req.messages.iter().skip(from) {
        for b in &m.content {
            match (m.role, b) {
                (Role::User, Block::Text { text }) if !text.is_empty() => out.push(json!({
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": text}],
                })),
                (Role::User, Block::Image { media_type, data }) => out.push(json!({
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_image", "image_url": data_url(media_type, data)}],
                })),
                (
                    _,
                    Block::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    },
                ) => out.push(json!({
                    "type": "function_call_output",
                    "call_id": tool_use_id,
                    "output": content,
                })),
                (Role::Assistant, Block::Text { text }) if fresh && !text.is_empty() => {
                    out.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": text}],
                    }))
                }
                (Role::Assistant, Block::ToolUse { id, name, input }) if fresh => out.push(json!({
                    "type": "function_call",
                    "call_id": id,
                    "name": name,
                    "arguments": input.to_string(),
                })),
                _ => {}
            }
        }
    }
    out
}

#[derive(Default)]
struct Call {
    key: String,
    id: String,
    name: String,
    args: String,
}

#[derive(Default)]
struct Turn {
    text: String,
    reasoning: String,
    calls: Vec<Call>,
    usage: Option<Usage>,
    model: String,
    failed: Option<String>,
    done: bool,
}

impl Turn {
    fn call_mut(&mut self, key: &str) -> &mut Call {
        if !key.is_empty() {
            if let Some(i) = self.calls.iter().position(|c| c.key == key) {
                return &mut self.calls[i];
            }
        }
        self.calls.push(Call {
            key: key.to_string(),
            ..Default::default()
        });
        self.calls.last_mut().unwrap()
    }

    /// Fold one stream event. `Ok(true)` means the turn is over.
    fn event(
        &mut self,
        v: &Value,
        on_event: &mut dyn FnMut(StreamEvent),
    ) -> Result<bool, ProviderError> {
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(classify::from_stream_error(&json!({ "error": err })));
        }
        let ty = v["type"].as_str().unwrap_or("");
        for m in [
            v.get("model"),
            v["response"].get("model"),
            v["turn"].get("model"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        {
            if !m.is_empty() {
                self.model = m.to_string();
            }
        }
        if let Some(u) = find_usage(v) {
            self.usage = Some(u);
        }

        // Terminal events first: `turn/completed` may carry the final text too.
        let terminal = matches!(
            ty,
            "agent.session.turn.completed"
                | "agent.session.turn.failed"
                | "agent.session.turn.cancelled"
                | "agent.session.idle"
                | "response.completed"
                | "response.failed"
        ) || ty.ends_with(".turn.completed")
            || ty.ends_with(".turn.failed")
            || ty.ends_with(".turn.cancelled");
        if terminal {
            if ty.ends_with("failed") {
                self.failed = Some(
                    [
                        v["error"]["message"].as_str(),
                        v["turn"]["error"]["message"].as_str(),
                    ]
                    .into_iter()
                    .flatten()
                    .next()
                    .unwrap_or("turn failed")
                    .to_string(),
                );
            }
            if let Some(t) = v["turn"]["output_text"].as_str().filter(|t| !t.is_empty()) {
                self.text = t.to_string();
            }
            self.done = true;
            return Ok(true);
        }

        let is_text = ty.ends_with("output_text.delta") || ty.ends_with(".text.delta");
        let is_reasoning = ty.contains("reasoning") && ty.ends_with(".delta");
        let delta = |v: &Value| -> String {
            match &v["delta"] {
                Value::String(s) => s.clone(),
                d => d["text"].as_str().unwrap_or("").to_string(),
            }
        };
        if is_reasoning {
            let d = delta(v);
            if !d.is_empty() {
                self.reasoning.push_str(&d);
                on_event(StreamEvent::ThinkingDelta(d));
            }
        } else if is_text {
            let d = delta(v);
            if !d.is_empty() {
                self.text.push_str(&d);
                on_event(StreamEvent::TextDelta(d));
            }
        }

        // Function calls: streamed argument fragments and the settled item.
        let item = if v["item"].is_object() { &v["item"] } else { v };
        let is_call = ty.contains("function_call") || item["type"] == "function_call";
        if is_call && item["name"].as_str().is_some_and(|n| !n.is_empty()) {
            let key = call_key(item);
            let name = item["name"].as_str().unwrap_or("").to_string();
            let args = match &item["arguments"] {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            let first = self
                .calls
                .iter()
                .find(|c| !key.is_empty() && c.key == key)
                .is_none_or(|c| c.name.is_empty());
            let c = self.call_mut(&key);
            c.id = item["call_id"]
                .as_str()
                .or_else(|| item["id"].as_str())
                .unwrap_or(&c.id)
                .to_string();
            c.name = name.clone();
            if !args.is_empty() {
                c.args = args;
            }
            if first {
                let id = if c.id.is_empty() {
                    key.clone()
                } else {
                    c.id.clone()
                };
                on_event(StreamEvent::ToolUseStart { id, name });
            }
        } else if is_call {
            // Argument fragments only (no name yet on this frame).
            let d = delta(v);
            if !d.is_empty() {
                let key = call_key(item);
                self.call_mut(&key).args.push_str(&d);
            }
        }
        Ok(false)
    }
}

fn call_key(v: &Value) -> String {
    for k in ["call_id", "item_id", "id", "output_index"] {
        if let Some(s) = v[k].as_str() {
            return s.to_string();
        }
        if let Some(n) = v[k].as_u64() {
            return format!("#{n}");
        }
    }
    String::new()
}

/// Usage as the Agents API reports it: `{input_tokens, output_tokens,
/// input_tokens_details.cached_tokens}` (Responses spelling) or `{prompt_tokens,
/// completion_tokens, prompt_tokens_details.cached_tokens}`.
fn find_usage(v: &Value) -> Option<Usage> {
    let u = [
        v.get("usage"),
        v["response"].get("usage"),
        v["turn"].get("usage"),
        v["item"].get("usage"),
    ]
    .into_iter()
    .flatten()
    .find(|u| u.is_object())?;
    let input = u["input_tokens"]
        .as_u64()
        .or_else(|| u["prompt_tokens"].as_u64())?;
    let cached = u["input_tokens_details"]["cached_tokens"]
        .as_u64()
        .or_else(|| u["prompt_tokens_details"]["cached_tokens"].as_u64())
        .unwrap_or(0);
    Some(Usage {
        input_tokens: input.saturating_sub(cached),
        output_tokens: u["output_tokens"]
            .as_u64()
            .or_else(|| u["completion_tokens"].as_u64())
            .unwrap_or(0),
        cache_read_tokens: cached,
        ..Default::default()
    })
}

impl Provider for AgentsApi {
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
        headers.push(("content-type".into(), "application/json".into()));
        let key = conversation_key(req);
        // A cached session that has seen everything we hold cannot continue (the kernel
        // re-sent an unchanged or compacted transcript): start over with a fresh one.
        let cached = self
            .lookup(key)
            .filter(|(_, sent)| *sent < req.messages.len());
        let mut recreate = cached.is_none();

        for attempt in 0..2 {
            let (id, sent) = match (recreate, &cached) {
                (false, Some((id, sent))) => (id.clone(), *sent),
                _ => (self.create_session(&base, &headers, req, cancel)?, 0),
            };
            let mut items = input_items(req, sent, sent == 0);
            if items.is_empty() && sent > 0 {
                // The skipped-over messages carried nothing sendable (assistant-only tail):
                // replay the user and tool-result side instead of an empty input array.
                items = input_items(req, 0, false);
            }
            let url = self
                .conn
                .url_on(&base, &format!("agents/sessions/{id}/turns"));
            let body = json!({"input": items, "stream": true});
            match self.run_turn(&url, &headers, body, req, on_event, cancel) {
                Ok((message, stop, usage, model)) => {
                    self.store(key, &id, req.messages.len());
                    return Ok(ModelResponse {
                        message,
                        stop,
                        usage,
                        model,
                    });
                }
                // The hosted session expired or was deleted: recreate once, replaying the
                // whole conversation as input.
                Err(e) if e.status == Some(404) || e.status == Some(410) => {
                    self.forget(key);
                    if attempt == 1 {
                        return Err(e);
                    }
                    recreate = true;
                }
                Err(e) => {
                    // Any other failure leaves the session's state unknown.
                    self.forget(key);
                    return Err(e);
                }
            }
        }
        Err(ProviderError::new(
            ProviderErrorKind::Protocol,
            "Agents API: session could not be (re)established",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    /// What the fake answers for one path.
    enum Resp {
        Json(u16, Value),
        Sse(Vec<String>),
    }

    struct Req {
        path: String,
        body: Value,
    }

    struct Fake {
        base: String,
        rx: Receiver<Req>,
    }

    impl Fake {
        fn next(&self) -> Req {
            self.rx
                .recv_timeout(Duration::from_secs(5))
                .expect("server saw no request")
        }
    }

    /// One request per connection; the fake closes so `ureq` reconnects.
    fn fake(script: impl Fn(&str, &Value) -> Resp + Send + 'static) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { return };
                let Some((path, body)) = read_request(&mut s) else {
                    continue;
                };
                let resp = script(&path, &body);
                if tx.send(Req { path, body }).is_err() {
                    return;
                }
                match resp {
                    Resp::Json(code, v) => {
                        let b = v.to_string();
                        let _ = s.write_all(
                            format!(
                                "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}",
                                b.len()
                            )
                            .as_bytes(),
                        );
                    }
                    Resp::Sse(chunks) => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n");
                        for c in chunks {
                            let _ = s.write_all(format!("{:x}\r\n{c}\r\n", c.len()).as_bytes());
                            let _ = s.flush();
                        }
                        let _ = s.write_all(b"0\r\n\r\n");
                    }
                }
            }
        });
        Fake { base, rx }
    }

    fn read_request(s: &mut std::net::TcpStream) -> Option<(String, Value)> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end = loop {
            let n = s.read(&mut tmp).ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.split("\r\n");
        let path = lines.next()?.split(' ').nth(1)?.to_string();
        let len: usize = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < len {
            let n = s.read(&mut tmp).ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Some((path, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    }

    fn provider(base: &str) -> std::sync::Arc<dyn Provider> {
        crate::build_with_idle(
            &ProviderConfig {
                id: "openai-agents".into(),
                format: crate::WireFormat::AgentsApi,
                base_url: base.into(),
                api_key: Some("sk-test".into()),
                ..Default::default()
            },
            Duration::from_secs(5),
        )
        .unwrap()
    }

    fn req(user: &str) -> ModelRequest {
        ModelRequest {
            model: "gpt-5.5".into(),
            system: vec![SystemSegment {
                id: "s".into(),
                text: "be brief".into(),
                cache: false,
            }],
            messages: vec![Message::user(user)],
            tools: vec![ToolSchema {
                name: "read".into(),
                description: "Read a file".into(),
                input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            }],
            max_tokens: 256,
            ..Default::default()
        }
    }

    fn sse_events(evs: &[Value]) -> Vec<String> {
        evs.iter()
            .map(|e| format!("event: agent\ndata: {e}\n\n"))
            .collect()
    }

    #[test]
    fn streams_text_and_usage_then_reuses_the_session() {
        let f = fake(|path, body| {
            if path.ends_with("/agents/sessions") {
                assert_eq!(body["agent"]["model"], "gpt-5.5");
                assert_eq!(body["agent"]["instructions"], "be brief");
                assert_eq!(body["agent"]["tools"][0]["name"], "read");
                assert_eq!(body["agent"]["tools"][0]["type"], "function");
                Resp::Json(200, json!({"id": "sess-1", "status": "idle"}))
            } else {
                Resp::Sse(sse_events(&[
                    json!({"type": "agent.session.turn.reasoning_summary.delta", "delta": "think"}),
                    json!({"type": "agent.session.turn.output_text.delta", "delta": "Hel"}),
                    json!({"type": "agent.session.turn.output_text.delta", "delta": "lo"}),
                    json!({"type": "agent.session.turn.completed", "turn": {"status": "completed"},
                           "usage": {"input_tokens": 100, "output_tokens": 5,
                                     "input_tokens_details": {"cached_tokens": 60}}}),
                ]))
            }
        });
        let p = provider(&f.base);
        let mut evs = Vec::new();
        let r = p
            .complete(&req("hi"), &mut |e| evs.push(e), &Cancel::new())
            .unwrap();
        assert_eq!(
            evs,
            vec![
                StreamEvent::ThinkingDelta("think".into()),
                StreamEvent::TextDelta("Hel".into()),
                StreamEvent::TextDelta("lo".into())
            ]
        );
        assert_eq!(r.message.text(), "Hello");
        assert!(matches!(&r.message.content[0], Block::Thinking { text, .. } if text == "think"));
        assert_eq!(r.stop, StopReason::EndTurn);
        assert_eq!(
            (
                r.usage.input_tokens,
                r.usage.cache_read_tokens,
                r.usage.output_tokens
            ),
            (40, 60, 5)
        );

        // The first request created a session, the second submitted the turn.
        let create = f.next();
        assert_eq!(create.path, "/agents/sessions");
        let turn = f.next();
        assert_eq!(turn.path, "/agents/sessions/sess-1/turns");
        assert_eq!(turn.body["stream"], true);
        assert_eq!(turn.body["input"][0]["role"], "user");
        assert_eq!(turn.body["input"][0]["content"][0]["text"], "hi");

        // Second turn on the same conversation: same session, only the new message.
        let mut second = req("hi");
        second.messages.push(Message::assistant("Hello"));
        second.messages.push(Message::user("again"));
        let r = p.complete(&second, &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "Hello");
        let turn = f.next();
        assert_eq!(turn.path, "/agents/sessions/sess-1/turns");
        let input = turn.body["input"].as_array().unwrap();
        assert_eq!(
            input.len(),
            1,
            "assistant history is not replayed: {input:?}"
        );
        assert_eq!(input[0]["content"][0]["text"], "again");
    }

    #[test]
    fn function_calls_become_tool_use_blocks() {
        let f = fake(|path, _| {
            if path.ends_with("/agents/sessions") {
                Resp::Json(200, json!({"id": "sess-1"}))
            } else {
                Resp::Sse(sse_events(&[
                    json!({"type": "agent.session.turn.output_text.delta", "delta": "reading"}),
                    json!({"type": "agent.session.turn.item.done",
                           "item": {"type": "function_call", "call_id": "call_9",
                                    "name": "read", "arguments": "{\"path\":\"a.txt\"}"}}),
                    json!({"type": "agent.session.turn.completed"}),
                ]))
            }
        });
        let p = provider(&f.base);
        let mut evs = Vec::new();
        let r = p
            .complete(&req("read a"), &mut |e| evs.push(e), &Cancel::new())
            .unwrap();
        assert_eq!(r.stop, StopReason::ToolUse);
        let uses: Vec<_> = r.message.tool_uses().collect();
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].0, "call_9");
        assert_eq!(uses[0].1, "read");
        assert_eq!(uses[0].2, &json!({"path": "a.txt"}));
        assert!(evs.contains(&StreamEvent::ToolUseStart {
            id: "call_9".into(),
            name: "read".into()
        }));

        // Tool results go back as function_call_output on the next turn.
        let mut next = req("read a");
        next.messages.push(Message {
            role: Role::Assistant,
            content: vec![Block::ToolUse {
                id: "call_9".into(),
                name: "read".into(),
                input: json!({"path": "a.txt"}),
            }],
        });
        next.messages.push(Message {
            role: Role::User,
            content: vec![Block::ToolResult {
                tool_use_id: "call_9".into(),
                content: "hello".into(),
                is_error: false,
            }],
        });
        p.complete(&next, &mut |_| {}, &Cancel::new()).unwrap();
        let _ = f.next(); // session create
        let _ = f.next(); // first turn
        let turn = f.next(); // second turn
        assert_eq!(turn.body["input"][0]["type"], "function_call_output");
        assert_eq!(turn.body["input"][0]["call_id"], "call_9");
        assert_eq!(turn.body["input"][0]["output"], "hello");
    }

    #[test]
    fn rate_limited_turn_reports_retry_after() {
        let f = fake(|path, _| {
            if path.ends_with("/agents/sessions") {
                Resp::Json(200, json!({"id": "sess-1"}))
            } else {
                Resp::Json(
                    429,
                    json!({"error": {"message": "slow down", "type": "rate_limit_error"}}),
                )
            }
        });
        let p = provider(&f.base);
        let err = p
            .complete(&req("hi"), &mut |_| {}, &Cancel::new())
            .unwrap_err();
        assert!(
            matches!(err.kind, ProviderErrorKind::RateLimited { .. }),
            "{err:?}"
        );
        assert!(err.message.contains("slow down"), "{}", err.message);
    }

    #[test]
    fn auth_error_is_not_retried_and_names_the_api_message() {
        let f = fake(|_, _| Resp::Json(401, json!({"error": {"message": "bad key"}})));
        let p = provider(&f.base);
        let err = p
            .complete(&req("hi"), &mut |_| {}, &Cancel::new())
            .unwrap_err();
        assert_eq!(err.kind, ProviderErrorKind::Auth);
        assert!(err.message.contains("bad key"), "{}", err.message);
    }

    #[test]
    fn truncated_stream_is_a_protocol_error() {
        let f = fake(|path, _| {
            if path.ends_with("/agents/sessions") {
                Resp::Json(200, json!({"id": "sess-1"}))
            } else {
                Resp::Sse(sse_events(&[
                    json!({"type": "agent.session.turn.output_text.delta", "delta": "par"}),
                ]))
            }
        });
        let p = provider(&f.base);
        let err = p
            .complete(&req("hi"), &mut |_| {}, &Cancel::new())
            .unwrap_err();
        assert_eq!(err.kind, ProviderErrorKind::Protocol);
        assert!(err.message.contains("completion"), "{}", err.message);
    }

    #[test]
    fn reset_session_when_the_compacted_transcript_shrinks() {
        let n = std::sync::atomic::AtomicUsize::new(0);
        let f = fake(move |path, _| {
            if path.ends_with("/agents/sessions") {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Resp::Json(200, json!({"id": format!("sess-{i}")}))
            } else {
                Resp::Sse(sse_events(&[
                    json!({"type": "agent.session.turn.completed"}),
                ]))
            }
        });
        let p = provider(&f.base);
        let mut full = req("hi");
        full.messages.push(Message::assistant("a"));
        full.messages.push(Message::user("b"));
        p.complete(&full, &mut |_| {}, &Cancel::new()).unwrap();
        // Compaction dropped history: the old session saw more messages than we hold.
        p.complete(&req("hi"), &mut |_| {}, &Cancel::new()).unwrap();
        let _ = f.next();
        let _ = f.next();
        let create = f.next();
        assert_eq!(create.path, "/agents/sessions");
    }
}
