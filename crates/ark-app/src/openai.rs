//! OpenAI-compatible API (parity with Hermes `api_server`): any OpenAI client
//! can talk to the full agent — tools, memory, gates — not just the model.
//!
//! - `GET /v1/models`
//! - `POST /v1/chat/completions` (`stream: true` → SSE `chat.completion.chunk`)
//! - `POST /v1/responses` (text output; `previous_response_id` continues a session)
//!
//! A conversation maps to an ark session: pass `X-Ark-Session` (or `session` in the
//! body, or `previous_response_id`) to continue one; otherwise a new session is
//! created and its id returned in the `X-Ark-Session` header. For a new session the
//! earlier messages of the request become context for the last user message.

use crate::App;
use ark_kernel::kernel::{BusMsg, KernelError, RunOpts};
use ark_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

fn err(status: u16, msg: &str, kind: &str) -> Response {
    Response::json(status, &json!({"error": {"message": msg, "type": kind}}).to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// OpenAI content: a string or a list of parts; only text reaches the agent.
fn text_of(c: &Value) -> String {
    match c {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| match p["type"].as_str() {
                Some("text") | Some("input_text") | Some("output_text") => p["text"].as_str().map(str::to_string),
                Some(t) => Some(format!("[{t} omitted]")),
                None => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

pub fn handle(app: &Arc<App>, r: Request) -> Response {
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/v1/models") => {
            let k = &app.d.k;
            let mut data = vec![json!({"id": "ark", "object": "model", "created": 0, "owned_by": "ark"})];
            for m in std::iter::once(&k.cfg.model.default).chain(k.cfg.model.fallback.iter()) {
                data.push(json!({"id": m, "object": "model", "created": 0, "owned_by": m.split('/').next().unwrap_or("ark")}));
            }
            Response::json(200, &json!({"object": "list", "data": data}).to_string())
        }
        ("POST", "/v1/chat/completions") => chat(app, &r),
        ("POST", "/v1/responses") => responses(app, &r),
        _ => err(404, "unknown endpoint", "invalid_request_error"),
    }
}

struct Turn {
    session: String,
    model: String,
}

/// Find or create the session and queue the user's message.
fn prepare(app: &App, r: &Request, body: &Value, history: &[(String, String)], last: &str, session_hint: Option<&str>) -> Result<Turn, Response> {
    let k = &app.d.k;
    let model = body["model"].as_str().filter(|m| m.contains('/')).map(str::to_string);
    let hint = r.header("x-ark-session").map(str::to_string).or_else(|| body["session"].as_str().map(str::to_string)).or(session_hint.map(str::to_string));
    let (sid, fresh) = match hint {
        Some(s) if k.store.open(&s).is_ok() => (s, false),
        Some(s) => return Err(err(404, &format!("no session {s}"), "invalid_request_error")),
        None => {
            let ws = app.default_workspace();
            let title = body["user"].as_str().map(|u| format!("api · {u}")).unwrap_or_else(|| "api".into());
            (k.create_session(&ws, model.as_deref(), None, Some(&title)).map_err(|e| err(500, &e.to_string(), "server_error"))?, true)
        }
    };
    if k.is_running(&sid) {
        return Err(err(409, "this session is already running a turn", "conflict"));
    }
    let mut text = String::new();
    if fresh && !history.is_empty() {
        text.push_str("Earlier conversation (from the API client):\n");
        for (role, t) in history {
            text.push_str(&format!("{role}: {t}\n"));
        }
        text.push('\n');
    }
    text.push_str(last);
    k.submit(&sid, &text, "api").map_err(|e| err(500, &e.to_string(), "server_error"))?;
    Ok(Turn { session: sid, model: model.unwrap_or_else(|| k.cfg.model.default.clone()) })
}

fn usage_json(u: &ark_core::Usage) -> Value {
    let prompt = u.input_tokens + u.cache_read_tokens + u.cache_write_tokens;
    json!({"prompt_tokens": prompt, "completion_tokens": u.output_tokens, "total_tokens": prompt + u.output_tokens, "prompt_tokens_details": {"cached_tokens": u.cache_read_tokens}})
}

fn finish(reason: &ark_kernel::kernel::EndReason) -> &'static str {
    match reason {
        ark_kernel::kernel::EndReason::MaxTokens | ark_kernel::kernel::EndReason::Budget(_) | ark_kernel::kernel::EndReason::MaxSteps => "length",
        ark_kernel::kernel::EndReason::Refusal => "content_filter",
        _ => "stop",
    }
}

fn chat(app: &Arc<App>, r: &Request) -> Response {
    let body: Value = match serde_json::from_slice(&r.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("invalid JSON: {e}"), "invalid_request_error"),
    };
    let msgs = body["messages"].as_array().cloned().unwrap_or_default();
    let Some(last_user) = msgs.iter().rposition(|m| m["role"] == "user") else { return err(400, "messages must contain a user message", "invalid_request_error") };
    let history: Vec<(String, String)> = msgs[..last_user].iter().map(|m| (m["role"].as_str().unwrap_or("user").to_string(), text_of(&m["content"]))).collect();
    let last = text_of(&msgs[last_user]["content"]);
    let turn = match prepare(app, r, &body, &history, &last, None) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let id = format!("chatcmpl-{}", ark_net::crypto::random_token(12));
    let k = app.d.k.clone();
    if body["stream"].as_bool() == Some(true) {
        let rx = k.bus.subscribe();
        let sid = turn.session.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let (k2, s2) = (k.clone(), sid.clone());
        std::thread::spawn(move || {
            let _ = done_tx.send(k2.run(&s2, RunOpts::default()));
        });
        let model = turn.model.clone();
        let include_usage = body["stream_options"]["include_usage"].as_bool() == Some(true);
        return Response::sse(Box::new(move |w| {
            let chunk = |delta: Value, finish: Option<&str>| json!({"id": id, "object": "chat.completion.chunk", "created": now(), "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
            writeln!(w, "data: {}\n", chunk(json!({"role": "assistant", "content": ""}), None))?;
            w.flush()?;
            let mut sent_any = false;
            loop {
                if let Ok(out) = done_rx.try_recv() {
                    // Drain deltas published before the run returned.
                    for m in rx.try_iter() {
                        if let BusMsg::Delta { session, text, thinking: false } = m {
                            if session == sid {
                                sent_any = true;
                                writeln!(w, "data: {}\n", chunk(json!({"content": text}), None))?;
                            }
                        }
                    }
                    // Providers that answered without streaming: send the whole reply once.
                    if let (false, Ok(o)) = (sent_any, &out) {
                        if !o.text.is_empty() {
                            writeln!(w, "data: {}\n", chunk(json!({"content": o.text}), None))?;
                        }
                    }
                    let (fin, usage) = match &out {
                        Ok(o) => (finish(&o.reason), Some(usage_json(&o.usage))),
                        Err(_) => ("stop", None),
                    };
                    if let Err(e) = &out {
                        writeln!(w, "data: {}\n", chunk(json!({"content": format!("\n[error: {e}]")}), None))?;
                    }
                    writeln!(w, "data: {}\n", chunk(json!({}), Some(fin)))?;
                    if include_usage {
                        if let Some(u) = usage {
                            writeln!(w, "data: {}\n", json!({"id": id, "object": "chat.completion.chunk", "created": now(), "model": model, "choices": [], "usage": u}))?;
                        }
                    }
                    writeln!(w, "data: [DONE]\n")?;
                    return w.flush();
                }
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(BusMsg::Delta { session, text, thinking }) if session == sid => {
                        sent_any |= !thinking;
                        let d = if thinking { json!({"reasoning_content": text}) } else { json!({"content": text}) };
                        writeln!(w, "data: {}\n", chunk(d, None))?;
                        w.flush()?;
                    }
                    _ => {}
                }
            }
        }))
        .with_header("x-ark-session", &turn.session);
    }
    match k.run(&turn.session, RunOpts::default()) {
        Ok(o) => {
            let v = json!({
                "id": id, "object": "chat.completion", "created": now(), "model": turn.model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": o.text}, "finish_reason": finish(&o.reason)}],
                "usage": usage_json(&o.usage),
            });
            Response::json(200, &v.to_string()).with_header("x-ark-session", &turn.session)
        }
        Err(KernelError::AlreadyRunning(_)) => err(409, "this session is already running a turn", "conflict"),
        Err(e) => err(500, &e.to_string(), "server_error"),
    }
}

fn responses(app: &Arc<App>, r: &Request) -> Response {
    let body: Value = match serde_json::from_slice(&r.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("invalid JSON: {e}"), "invalid_request_error"),
    };
    // `input` is a string or a list of messages/items.
    let (history, last) = match &body["input"] {
        Value::String(s) => (vec![], s.clone()),
        Value::Array(items) => {
            let msgs: Vec<(String, String)> = items.iter().map(|m| (m["role"].as_str().unwrap_or("user").to_string(), text_of(&m["content"]))).collect();
            match msgs.split_last() {
                Some((l, h)) => (h.to_vec(), l.1.clone()),
                None => return err(400, "input is empty", "invalid_request_error"),
            }
        }
        _ => return err(400, "input must be a string or a list", "invalid_request_error"),
    };
    let mut last = last;
    if let Some(i) = body["instructions"].as_str() {
        last = format!("{i}\n\n{last}");
    }
    // previous_response_id = "resp_<session>" continues that session.
    let prev = body["previous_response_id"].as_str().and_then(|p| p.strip_prefix("resp_")).map(str::to_string);
    let turn = match prepare(app, r, &body, &history, &last, prev.as_deref()) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match app.d.k.run(&turn.session, RunOpts::default()) {
        Ok(o) => {
            let u = &o.usage;
            let v = json!({
                "id": format!("resp_{}", turn.session), "object": "response", "created_at": now(), "status": if o.reason.ok() { "completed" } else { "incomplete" },
                "model": turn.model,
                "output": [{"type": "message", "id": format!("msg_{}", ark_net::crypto::random_token(8)), "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": o.text, "annotations": []}]}],
                "output_text": o.text,
                "usage": {"input_tokens": u.input_tokens + u.cache_read_tokens + u.cache_write_tokens, "output_tokens": u.output_tokens, "total_tokens": u.input_tokens + u.cache_read_tokens + u.cache_write_tokens + u.output_tokens},
            });
            Response::json(200, &v.to_string()).with_header("x-ark-session", &turn.session)
        }
        Err(e) => err(500, &e.to_string(), "server_error"),
    }
}

