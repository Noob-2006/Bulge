//! ACP (Agent Client Protocol) server: expose bulge as an agent an editor can
//! spawn and drive over stdio, reusing the exact same [`Session`] the CLI and app
//! use. Transport is newline-delimited JSON-RPC 2.0 over stdin/stdout.
//!
//! Supported methods: `initialize`, `authenticate`, `session/new`,
//! `session/prompt` (streams `session/update` notifications as the agent works),
//! and the `session/cancel` notification. The model/key come from bulge's own
//! config (env + `~/.bulge/keys`), exactly like `bulge run`; `session/new`'s `cwd`
//! becomes the workspace. This is an initial ACP implementation: the JSON-RPC core
//! and the session lifecycle are covered by tests, and it drives a real agent —
//! field-level conformance against a specific client is still to be validated.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bulge_core::driver::LoopOutcome;
use bulge_store::{Autonomy, Budget};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use crate::backend::{BackendSpec, Protocol};
use crate::run::{RunConfig, Sampling, Session};

/// The ACP protocol version this agent implements.
const PROTOCOL_VERSION: u64 = 1;

type SharedOut = Arc<Mutex<std::io::Stdout>>;
type Cancels = Arc<Mutex<HashMap<String, CancellationToken>>>;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Run the ACP server on stdio until stdin closes. Returns when the client
/// disconnects.
pub async fn serve() -> Result<(), String> {
    let out: SharedOut = Arc::new(Mutex::new(std::io::stdout()));
    let cancels: Cancels = Arc::new(Mutex::new(HashMap::new()));

    // A reader task drains stdin so a `session/cancel` can fire even while a prompt
    // is running; everything else is forwarded to the main loop in order.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let reader_cancels = cancels.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(line) else { continue };
            // Handle cancellation out of band so it isn't stuck behind a prompt.
            if value.get("method").and_then(Value::as_str) == Some("session/cancel") {
                if let Some(sid) = value.get("params").and_then(|p| p.get("sessionId")).and_then(Value::as_str)
                    && let Some(token) = reader_cancels.lock().unwrap().get(sid)
                {
                    token.cancel();
                }
                continue;
            }
            if tx.send(value).is_err() {
                break;
            }
        }
    });

    let mut sessions: HashMap<String, Session> = HashMap::new();
    while let Some(message) = rx.recv().await {
        handle_message(message, &mut sessions, &cancels, &out).await;
    }

    // Client gone: shut every live session down cleanly.
    for (_, session) in sessions.drain() {
        session.shutdown().await;
    }
    Ok(())
}

async fn handle_message(message: Value, sessions: &mut HashMap<String, Session>, cancels: &Cancels, out: &SharedOut) {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let id = message.get("id").cloned();
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    // Notifications (no id) other than cancel are ignored.
    let Some(id) = id else { return };

    match method {
        "initialize" => {
            respond(out, id, json!({
                "protocolVersion": PROTOCOL_VERSION,
                "agentCapabilities": { "loadSession": false, "promptCapabilities": { "image": false, "audio": false, "embeddedContext": true } },
                "authMethods": [],
            }));
        }
        "authenticate" => respond(out, id, json!({})),
        "session/new" => match new_session(params).await {
            Ok((sid, session)) => {
                sessions.insert(sid.clone(), session);
                respond(out, id, json!({ "sessionId": sid }));
            }
            Err(e) => respond_error(out, id, -32000, &e),
        },
        "session/prompt" => {
            prompt(sessions, cancels, out, id, params).await;
        }
        _ => respond_error(out, id, -32601, &format!("method not found: {method}")),
    }
}

/// Build a `RunConfig` from bulge's own config (env + key file) plus the client's
/// requested `cwd`, then launch a session.
async fn new_session(params: Value) -> Result<(String, Session), String> {
    let cwd = params.get("cwd").and_then(Value::as_str).map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if !cwd.is_dir() {
        return Err(format!("cwd is not a directory: {}", cwd.display()));
    }
    let config = acp_run_config(cwd)?;
    let session = Session::launch(config).await?;
    let sid = format!("acp-{}-{}", std::process::id(), SESSION_SEQ.fetch_add(1, Ordering::Relaxed));
    Ok((sid, session))
}

/// Read bulge's model/backend config from the environment (same defaults as the
/// CLI); the API key is read by the backend from `~/.bulge/keys/<host>`.
fn acp_run_config(workspace: PathBuf) -> Result<RunConfig, String> {
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let env_or = |key: &str, default: &str| std::env::var(key).unwrap_or_else(|_| default.to_string());
    let base_url = env_or("BULGE_BASE_URL", "https://api.deepseek.com");
    let model = env_or("BULGE_MODEL", "deepseek-chat");
    let protocol = Protocol::parse(&env_or("BULGE_PROTOCOL", "openai"))?;
    let autonomy = match env_or("BULGE_AUTONOMY", "autonomous").as_str() {
        "collaborative" => Autonomy::Collaborative,
        "full-auto" | "full_auto" => Autonomy::FullAuto,
        _ => Autonomy::Autonomous,
    };
    let host = base_url.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("backend").to_string();
    Ok(RunConfig {
        job_id: None,
        goal: String::new(),
        title: "acp".into(),
        workspace,
        store_root: home.join(".bulge/jobs"),
        harness_dir: home.join(".bulge/harness"),
        autonomy,
        budget: Budget { max_steps: 200, max_tokens: 2_000_000, max_wall_secs: 14_400 },
        backend: BackendSpec { id: host, base_url, protocol, model, context_window: 128_000, max_tokens: 8_192, reasoning: false },
        network: std::env::var("BULGE_NETWORK").is_ok(),
        cpus: 2,
        ram_mib: 1024,
        sampling: Sampling::default(),
        system_prompt: None,
        egress_approvals: None,
    })
}

async fn prompt(sessions: &mut HashMap<String, Session>, cancels: &Cancels, out: &SharedOut, id: Value, params: Value) {
    let Some(sid) = params.get("sessionId").and_then(Value::as_str).map(str::to_owned) else {
        return respond_error(out, id, -32602, "missing sessionId");
    };
    let Some(session) = sessions.get_mut(&sid) else {
        return respond_error(out, id, -32602, "unknown sessionId");
    };
    let text = extract_prompt_text(params.get("prompt"));
    if text.trim().is_empty() {
        return respond_error(out, id, -32602, "empty prompt");
    }

    let cancel = CancellationToken::new();
    cancels.lock().unwrap().insert(sid.clone(), cancel.clone());
    let sink = update_sink(out.clone(), sid.clone());
    let outcome = session.run_turn(text, cancel, sink).await;
    cancels.lock().unwrap().remove(&sid);

    match outcome {
        Ok(result) => respond(out, id, json!({ "stopReason": stop_reason(result.outcome) })),
        Err(e) => {
            // Surface the failure as an agent message, then end the turn.
            notify(out, &json!({
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": { "sessionId": sid, "update": { "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": format!("error: {e}") } } },
            }));
            respond(out, id, json!({ "stopReason": "refusal" }));
        }
    }
}

/// Concatenate the text of an ACP prompt's content blocks.
fn extract_prompt_text(prompt: Option<&Value>) -> String {
    let Some(blocks) = prompt.and_then(Value::as_array) else {
        // Some clients may send a bare string.
        return prompt.and_then(Value::as_str).unwrap_or("").to_string();
    };
    blocks
        .iter()
        .filter_map(|b| match b.get("type").and_then(Value::as_str) {
            Some("text") => b.get("text").and_then(Value::as_str).map(str::to_owned),
            Some("resource") => b.get("resource").and_then(|r| r.get("text")).and_then(Value::as_str).map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Map a loop outcome to an ACP stop reason.
fn stop_reason(outcome: LoopOutcome) -> &'static str {
    match outcome {
        LoopOutcome::Stopped => "end_turn",
        LoopOutcome::Cancelled => "cancelled",
        LoopOutcome::BudgetExhausted => "max_tokens",
        LoopOutcome::Failed | LoopOutcome::Stuck | LoopOutcome::Incomplete => "end_turn",
    }
}

/// A sink that turns each committed job-log line into an ACP `session/update`.
fn update_sink(out: SharedOut, sid: String) -> crate::run::LineSink {
    Box::new(move |line: &str| {
        if let Some(update) = jsonl_to_update(line) {
            notify(&out, &json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": sid, "update": update } }));
        }
    })
}

/// Translate one job-log event into an ACP session update (or `None` to skip).
fn jsonl_to_update(line: &str) -> Option<Value> {
    let event: Value = serde_json::from_str(line).ok()?;
    match event.get("type").and_then(Value::as_str)? {
        "message" => {
            let message = event.get("message")?;
            if message.get("role").and_then(Value::as_str) != Some("assistant") {
                return None;
            }
            for block in message.get("content").and_then(Value::as_array)? {
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        let text = block.get("text").and_then(Value::as_str).unwrap_or("");
                        if !text.trim().is_empty() {
                            return Some(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": text } }));
                        }
                    }
                    Some("reasoning") => {
                        let text = block.get("text").and_then(Value::as_str).unwrap_or("");
                        if !text.trim().is_empty() {
                            return Some(json!({ "sessionUpdate": "agent_thought_chunk", "content": { "type": "text", "text": text } }));
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        "tool_claimed" => Some(json!({
            "sessionUpdate": "tool_call",
            "toolCallId": event.get("call_id").and_then(Value::as_str).unwrap_or(""),
            "title": event.get("name").and_then(Value::as_str).unwrap_or("tool"),
            "status": "in_progress",
        })),
        "tool_completed" => Some(json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": event.get("call_id").and_then(Value::as_str).unwrap_or(""),
            "status": if event.get("ok").and_then(Value::as_bool).unwrap_or(false) { "completed" } else { "failed" },
        })),
        _ => None,
    }
}

fn respond(out: &SharedOut, id: Value, result: Value) {
    notify(out, &json!({ "jsonrpc": "2.0", "id": id, "result": result }));
}

fn respond_error(out: &SharedOut, id: Value, code: i64, message: &str) {
    notify(out, &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
}

/// Write one JSON-RPC message as a single line (the ndjson transport).
fn notify(out: &SharedOut, message: &Value) {
    if let Ok(mut stdout) = out.lock() {
        let _ = writeln!(stdout, "{message}");
        let _ = stdout.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_text_joins_blocks_and_handles_string() {
        let blocks = json!([{ "type": "text", "text": "hello" }, { "type": "text", "text": "world" }]);
        assert_eq!(extract_prompt_text(Some(&blocks)), "hello\nworld");
        assert_eq!(extract_prompt_text(Some(&json!("bare"))), "bare");
        assert_eq!(extract_prompt_text(None), "");
    }

    #[test]
    fn stop_reasons_map() {
        assert_eq!(stop_reason(LoopOutcome::Stopped), "end_turn");
        assert_eq!(stop_reason(LoopOutcome::Cancelled), "cancelled");
        assert_eq!(stop_reason(LoopOutcome::BudgetExhausted), "max_tokens");
    }

    #[test]
    fn assistant_text_becomes_message_chunk() {
        let line = json!({ "type": "message", "message": { "role": "assistant", "content": [{ "type": "text", "text": "hi" }] } }).to_string();
        let update = jsonl_to_update(&line).unwrap();
        assert_eq!(update["sessionUpdate"], "agent_message_chunk");
        assert_eq!(update["content"]["text"], "hi");
    }

    #[test]
    fn tool_events_map_to_calls() {
        let claim = json!({ "type": "tool_claimed", "call_id": "c1", "name": "read" }).to_string();
        let u = jsonl_to_update(&claim).unwrap();
        assert_eq!(u["sessionUpdate"], "tool_call");
        assert_eq!(u["toolCallId"], "c1");

        let done = json!({ "type": "tool_completed", "call_id": "c1", "ok": true }).to_string();
        let u = jsonl_to_update(&done).unwrap();
        assert_eq!(u["sessionUpdate"], "tool_call_update");
        assert_eq!(u["status"], "completed");
    }

    #[test]
    fn user_messages_are_not_echoed_back() {
        let line = json!({ "type": "message", "message": { "role": "user", "content": [{ "type": "text", "text": "x" }] } }).to_string();
        assert!(jsonl_to_update(&line).is_none());
    }
}
