//! Conversation tools for `ark mcp serve`: other agents (Claude Code, Codex, another
//! ark) can list, read, drive and approve ark sessions through the daemon — parity with
//! OpenClaw's channel MCP server and Hermes' mcp-serve (conversations, events, approvals).

use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Conv {
    name: &'static str,
    sock: PathBuf,
}

fn spec(name: &'static str) -> (&'static str, Value) {
    match name {
        "ark_sessions" => ("List ark sessions (id, title, workspace, running).", json!({"type": "object", "properties": {"limit": {"type": "integer"}}})),
        "ark_session_read" => ("Read the last messages of an ark session.", json!({"type": "object", "properties": {"id": {"type": "string"}, "last": {"type": "integer", "description": "messages to return (default 10)"}}, "required": ["id"]})),
        "ark_session_send" => (
            "Send a message to an ark session (or start one with `workspace`). With wait=true, block until the turn ends and return the reply.",
            json!({"type": "object", "properties": {"id": {"type": "string"}, "workspace": {"type": "string"}, "text": {"type": "string"}, "wait": {"type": "boolean"}, "timeout_secs": {"type": "integer"}}, "required": ["text"]}),
        ),
        "ark_pending" => ("List approvals and questions waiting for a human.", json!({"type": "object", "properties": {}})),
        _ => ("Answer a pending approval (once | always | deny) or question (free text).", json!({"type": "object", "properties": {"id": {"type": "string"}, "answer": {"type": "string"}}, "required": ["id", "answer"]})),
    }
}

fn last_text(view: &Value) -> String {
    view["messages"].as_array().into_iter().flatten().rev().find(|m| m["role"] == "assistant").map(|m| m["content"].as_array().into_iter().flatten().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("")).unwrap_or_default()
}

impl Tool for Conv {
    fn spec(&self) -> ToolSpec {
        let (d, s) = spec(self.name);
        ToolSpec { name: self.name.into(), description: d.into(), input_schema: s, parallel_safe: matches!(self.name, "ark_sessions" | "ark_session_read" | "ark_pending"), idempotent: false, pinned: true }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let call = |m: &str, p: Value| ark_kernel::daemon::call(&self.sock, m, p);
        let r: Result<String, String> = (|| match self.name {
            "ark_sessions" => call("session.list", json!({"limit": input["limit"].as_u64().unwrap_or(30)})).map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()),
            "ark_session_read" => {
                let v = call("session.view", json!({"id": input["id"]}))?;
                let n = input["last"].as_u64().unwrap_or(10) as usize;
                let msgs = v["messages"].as_array().cloned().unwrap_or_default();
                let tail: Vec<String> = msgs[msgs.len().saturating_sub(n)..]
                    .iter()
                    .map(|m| {
                        let text: Vec<String> = m["content"].as_array().into_iter().flatten().map(|b| match b["type"].as_str() {
                            Some("text") => b["text"].as_str().unwrap_or("").to_string(),
                            Some("tool_use") => format!("[tool {}]", b["name"].as_str().unwrap_or("")),
                            Some("tool_result") => format!("[result {} chars]", b["content"].as_str().map(str::len).unwrap_or(0)),
                            _ => String::new(),
                        }).collect();
                        format!("{}: {}", m["role"].as_str().unwrap_or(""), text.join(" "))
                    })
                    .collect();
                Ok(format!("running: {}\n{}", v["running"], tail.join("\n")))
            }
            "ark_session_send" => {
                let id = match input["id"].as_str() {
                    Some(id) => id.to_string(),
                    None => {
                        let ws = input["workspace"].as_str().ok_or("give `id` or `workspace`")?;
                        call("session.create", json!({"workspace": ws, "title": "via MCP"}))?["id"].as_str().unwrap_or("").to_string()
                    }
                };
                call("session.submit", json!({"id": id, "text": input["text"], "source": "mcp"}))?;
                if input["wait"].as_bool() != Some(true) {
                    return Ok(format!("queued in session {id}"));
                }
                let deadline = Instant::now() + Duration::from_secs(input["timeout_secs"].as_u64().unwrap_or(300).min(3600));
                std::thread::sleep(Duration::from_millis(300));
                loop {
                    let v = call("session.view", json!({"id": id}))?;
                    if v["running"] != true {
                        return Ok(format!("session {id}:\n{}", last_text(&v)));
                    }
                    if Instant::now() > deadline {
                        return Ok(format!("session {id} is still running; read it later with ark_session_read"));
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            "ark_pending" => call("gate.pending", json!({})).map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()),
            _ => call("gate.answer", json!({"id": input["id"], "answer": input["answer"]})).map(|_| "answered".to_string()),
        })();
        match r {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// The conversation tools, backed by the daemon at `sock`.
pub fn tools(sock: PathBuf) -> Vec<Arc<dyn Tool>> {
    ["ark_sessions", "ark_session_read", "ark_session_send", "ark_pending", "ark_pending_answer"].into_iter().map(|n| Arc::new(Conv { name: n, sock: sock.clone() }) as Arc<dyn Tool>).collect()
}
