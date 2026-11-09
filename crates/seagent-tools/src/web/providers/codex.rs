//! Codex hosted search (OpenClaw `extensions/codex` web-search provider): one bounded, ephemeral
//! turn on a private `codex app-server` (JSON-RPC lines over stdio) with hosted `web_search`
//! enabled in the thread config, read-only sandbox, every approval declined. The answer is the
//! agent message; `webSearch` items prove a search happened. Uses the user's Codex sign-in.

use super::{Citation, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::WebCtx;
use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct Codex;

const INSTRUCTIONS: &str = "You are seagent's bounded web-search worker. You must use Codex hosted web_search to answer the user's search query. Return a concise grounded answer with source URLs. Do not call other tools, edit files, or ask follow-up questions.";

/// OpenClaw `buildCodexNativeWebSearchThreadConfig`.
pub fn thread_config(c: &WebCtx) -> Value {
    let mut m = Map::new();
    m.insert("features.standalone_web_search".into(), json!(false));
    m.insert("web_search".into(), json!(if c.opt("codex", "mode").as_deref() == Some("live") { "live" } else { "cached" }));
    let domains = c.opt_list("codex", "allowed_domains");
    if !domains.is_empty() {
        m.insert("tools.web_search.allowed_domains".into(), json!(domains));
    }
    if let Some(s) = c.opt("codex", "context_size") {
        m.insert("tools.web_search.context_size".into(), json!(s));
    }
    for k in ["country", "region", "city", "timezone"] {
        if let Some(v) = c.opt("codex", &format!("location_{k}")) {
            m.insert(format!("tools.web_search.location.{k}"), json!(v));
        }
    }
    Value::Object(m)
}

/// OpenClaw `projectCodexWebSearchItem`.
pub fn project_search(item: &Value) -> Value {
    let action = item.get("action").filter(|a| a.is_object());
    let at = action.and_then(|a| a.get("type")).and_then(|t| t.as_str()).unwrap_or("");
    let queries: Vec<String> = if at == "search" { action.and_then(|a| a.get("queries")).and_then(|q| q.as_array()).into_iter().flatten().filter_map(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect() } else { vec![] };
    let q = item.get("query").and_then(|x| x.as_str()).map(str::to_string).or_else(|| (at == "search").then(|| action.and_then(|a| a.get("query")).and_then(|x| x.as_str()).map(str::to_string)).flatten()).or_else(|| queries.first().cloned());
    let mut o = Map::new();
    if let Some(q) = q {
        o.insert("query".into(), json!(q));
    }
    if !queries.is_empty() {
        o.insert("queries".into(), json!(queries));
    }
    if !at.is_empty() && at != "search" {
        o.insert("action".into(), json!(at));
    }
    for k in ["url", "pattern"] {
        if let Some(v) = action.and_then(|a| a.get(k)).and_then(|x| x.as_str()) {
            o.insert(k.into(), json!(v));
        }
    }
    Value::Object(o)
}

fn approval_reply(method: &str) -> Value {
    if method == "item/permissions/requestApproval" {
        json!({"permissions": {}, "scope": "turn"})
    } else if method == "mcpServer/elicitation/request" {
        json!({"action": "decline", "content": null})
    } else {
        json!({"decision": "decline", "reason": "seagent Codex hosted search does not grant tool or file approvals."})
    }
}

/// Run the bounded turn: `(answer, searches)`.
pub fn run_turn(c: &WebCtx, query: &str, timeout: Duration) -> Result<(String, Vec<Value>), String> {
    let cmd = c.opt("codex", "command").unwrap_or_else(|| "codex".into());
    let args = match c.opt_value("codex", "args").and_then(|a| a.as_array()) {
        Some(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        None => vec!["app-server".to_string()],
    };
    // Windows: `codex.cmd` (npm shim) through PATHEXT; Unix: `Command::new(cmd)`.
    let mut child = seagent_core::platform::layout::program_command(&cmd).args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("Codex hosted search could not start `{cmd}`: {e}. Install the Codex CLI and sign in (codex login)."))?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if tx.send(v).is_err() {
                    break;
                }
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let mut next_id = 0u64;
    let result = (|| -> Result<(String, Vec<Value>), String> {
        let send = |stdin: &mut std::process::ChildStdin, v: Value| -> Result<(), String> {
            writeln!(stdin, "{v}").and_then(|_| stdin.flush()).map_err(|e| {
                // A CLI that already exited reports EPIPE here; say so, the write is not at fault.
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    "codex app-server exited before the search completed".into()
                } else {
                    format!("codex app-server write failed: {e}")
                }
            })
        };
        let mut items: Vec<Value> = Vec::new();
        let mut deltas = String::new();
        let mut done: Option<Value> = None;
        let mut call = |stdin: &mut std::process::ChildStdin, method: &str, params: Value, items: &mut Vec<Value>, deltas: &mut String, done: &mut Option<Value>, wait_turn: bool| -> Result<Value, String> {
            next_id += 1;
            let id = next_id;
            if !method.is_empty() {
                send(stdin, json!({"id": id, "method": method, "params": params}))?;
            }
            let mut response = Value::Null;
            loop {
                if c.cancel.is_cancelled() {
                    return Err("Interrupted".into());
                }
                if (!method.is_empty() && !response.is_null() && !wait_turn) || (wait_turn && done.is_some()) {
                    return Ok(response);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(format!("Codex hosted search timed out after {}s.", timeout.as_secs()));
                }
                let msg = match rx.recv_timeout(left.min(Duration::from_millis(200))) {
                    Ok(m) => m,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(_) => return Err("codex app-server exited before the search completed".into()),
                };
                let m = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
                match (msg.get("id"), m) {
                    (Some(rid), "") if rid.as_u64() == Some(id) => {
                        if let Some(e) = msg.get("error") {
                            return Err(format!("codex app-server {method} failed: {}", e.get("message").and_then(|x| x.as_str()).unwrap_or(&e.to_string())));
                        }
                        response = msg.get("result").cloned().unwrap_or(json!({}));
                    }
                    (Some(rid), m) if !m.is_empty() => send(stdin, json!({"id": rid, "result": approval_reply(m)}))?,
                    (None, "item/completed") => items.extend(msg.pointer("/params/item").cloned()),
                    (None, "item/agentMessage/delta") => deltas.push_str(msg.pointer("/params/delta").and_then(|d| d.as_str()).unwrap_or("")),
                    (None, "turn/completed") => *done = Some(msg.pointer("/params/turn").cloned().unwrap_or(json!({}))),
                    (None, "error") if msg.pointer("/params/willRetry").and_then(|w| w.as_bool()) != Some(true) => {
                        return Err(format!("codex app-server hosted search failed: {}", msg.pointer("/params/error/message").and_then(|x| x.as_str()).unwrap_or("error")));
                    }
                    _ => {}
                }
            }
        };
        call(&mut stdin, "initialize", json!({"clientInfo": {"name": "seagent", "title": "seagent", "version": env!("CARGO_PKG_VERSION")}, "capabilities": {"experimentalApi": true}}), &mut items, &mut deltas, &mut done, false)?;
        send(&mut stdin, json!({"method": "initialized"}))?;
        let mut tp = json!({"cwd": std::env::temp_dir(), "approvalPolicy": "on-request", "sandbox": "read-only", "serviceName": "seagent", "developerInstructions": INSTRUCTIONS, "config": thread_config(c), "environments": [], "dynamicTools": [], "ephemeral": true});
        if let Some(m) = c.opt("codex", "model") {
            tp["model"] = json!(m);
        }
        let thread = call(&mut stdin, "thread/start", tp, &mut items, &mut deltas, &mut done, false)?;
        let tid = thread.pointer("/thread/id").and_then(|x| x.as_str()).ok_or("codex app-server thread/start returned no thread id")?.to_string();
        call(&mut stdin, "turn/start", json!({"threadId": tid, "input": [{"type": "text", "text": query, "text_elements": []}], "approvalPolicy": "on-request", "effort": "low"}), &mut items, &mut deltas, &mut done, false)?;
        if done.is_none() {
            call(&mut stdin, "", Value::Null, &mut items, &mut deltas, &mut done, true)?;
        }
        let turn = done.unwrap_or_default();
        let status = turn.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
        if status == "failed" {
            return Err(format!("codex app-server hosted search turn failed: {}", turn.pointer("/error/message").and_then(|x| x.as_str()).unwrap_or("unknown error")));
        }
        if status != "completed" {
            return Err(format!("codex app-server hosted search turn ended with status {status}"));
        }
        let text = items.iter().filter(|i| i.get("type").and_then(|t| t.as_str()) == Some("agentMessage")).filter_map(|i| i.get("text").and_then(|t| t.as_str())).map(str::trim).filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n\n");
        let text = if text.is_empty() { deltas.trim().to_string() } else { text };
        if text.is_empty() {
            return Err("Codex app-server hosted search turn returned no text.".into());
        }
        let searches: Vec<Value> = items.iter().filter(|i| i.get("type").and_then(|t| t.as_str()) == Some("webSearch")).map(project_search).collect();
        if searches.is_empty() {
            return Err("Codex hosted search completed without invoking web search.".into());
        }
        Ok((text, searches))
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

impl WebProvider for Codex {
    fn id(&self) -> &'static str {
        "codex"
    }
    fn label(&self) -> &'static str {
        "Codex Hosted Search"
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.opt("codex", "command").is_some()
    }
    fn auto_detect(&self) -> bool {
        false
    }
    fn endpoint(&self, _c: &WebCtx) -> String {
        "https://chatgpt.com/codex".into()
    }
    fn signup_url(&self) -> &'static str {
        "https://chatgpt.com/codex"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let (content, searches) = run_turn(c, &r.query, Duration::from_secs(c.timeout("codex")))?;
        let citations = searches.iter().filter_map(|s| s.get("url").and_then(|u| u.as_str())).map(|u| Citation { url: u.into(), title: None }).collect();
        Ok(SearchOutput::Answer { content, citations })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::wctx;

    const FAKE: &str = r#"
import json, sys
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line)
    meth = m.get("method")
    if meth == "initialize":
        out({"id": m["id"], "result": {"userAgent": "codex/0.1"}})
    elif meth == "thread/start":
        assert m["params"]["sandbox"] == "read-only"
        assert m["params"]["config"]["web_search"] == "live"
        out({"id": m["id"], "result": {"thread": {"id": "t1"}, "model": "gpt-5"}})
    elif meth == "turn/start":
        out({"id": m["id"], "result": {"turn": {"id": "u1", "status": "inProgress"}}})
        out({"id": 99, "method": "item/commandExecution/requestApproval", "params": {}})
    elif "result" in m and m.get("id") == 99:
        assert m["result"]["decision"] == "decline"
        out({"method": "item/completed", "params": {"item": {"id": "w", "type": "webSearch", "query": "rust", "action": {"type": "openPage", "url": "https://rust-lang.org"}}}})
        out({"method": "item/completed", "params": {"item": {"id": "a", "type": "agentMessage", "text": "Rust is a language."}}})
        out({"method": "turn/completed", "params": {"turn": {"id": "u1", "status": "completed"}}})
"#;

    #[test]
    fn bounded_turn_against_fake_app_server() {
        let d = crate::testutil::tmpdir("codex-fake");
        let script = d.join("fake.py");
        std::fs::write(&script, FAKE).unwrap();
        let c = wctx(json!({"providers":{"codex":{"command":"python3","args":["-I", script.to_string_lossy()],"mode":"live","timeout_seconds":20}}}), &[]);
        assert!(Codex.configured(&c));
        let SearchOutput::Answer { content, citations } = Codex.search(&c, &SearchRequest { query: "rust".into(), count: 1, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((content.as_str(), citations[0].url.as_str()), ("Rust is a language.", "https://rust-lang.org"));
    }

    #[test]
    fn projection_and_errors() {
        let p = project_search(&json!({"action":{"type":"search","queries":[" a ","b"]}}));
        assert_eq!(p, json!({"query":"a","queries":["a","b"]}));
        let c = wctx(json!({"providers":{"codex":{"command":"/nonexistent/codex"}}}), &[]);
        assert!(Codex.search(&c, &SearchRequest { query: "q".into(), ..Default::default() }).unwrap_err().contains("could not start"));
        // A program that exits at once: `true`; Windows has no `true.exe`, so `cmd /c exit 0`.
        let quick = if cfg!(windows) { json!({"command":"cmd","args":["/c","exit 0"]}) } else { json!({"command":"true","args":[]}) };
        let c = wctx(json!({"providers":{"codex":quick}}), &[]);
        assert!(Codex.search(&c, &SearchRequest { query: "q".into(), ..Default::default() }).unwrap_err().contains("exited"));
        assert_eq!(thread_config(&wctx(json!({"providers":{"codex":{"allowed_domains":["a.com"],"location_country":"TW"}}}), &[]))["tools.web_search.location.country"], "TW");
    }
}
