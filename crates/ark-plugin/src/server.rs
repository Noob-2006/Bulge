//! MCP server over newline-delimited stdio: exposes Ark's tools to other agents.
//! Every call passes the caller-supplied `judge` (the two gates) before running.

use crate::mcp::PROTOCOL;
use crate::transport::{read_line_capped, MAX_MESSAGE};
use ark_core::{Effect, Tool, ToolCtx};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::sync::Arc;

pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub instructions: Option<String>,
}

fn reply(out: &mut impl Write, id: &Value, r: Result<Value, (i64, String)>) -> std::io::Result<()> {
    let msg = match r {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err((code, m)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}}),
    };
    let mut b = serde_json::to_vec(&msg).expect("json");
    b.push(b'\n');
    out.write_all(&b)?;
    out.flush()
}

/// Serve until EOF on `input`. Requests are handled one at a time.
pub fn serve<R: BufRead, W: Write>(info: &ServerInfo, tools: &[Arc<dyn Tool>], ctx: &dyn Fn() -> ToolCtx, judge: &dyn Fn(&[Effect]) -> Result<(), String>, mut input: R, mut output: W) -> std::io::Result<()> {
    loop {
        let line = match read_line_capped(&mut input, MAX_MESSAGE)? {
            None => return Ok(()),
            Some(Err(n)) => {
                reply(&mut output, &Value::Null, Err((-32700, format!("message too large ({n} bytes)"))))?;
                continue;
            }
            Some(Ok(l)) => l,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let msg: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => {
                reply(&mut output, &Value::Null, Err((-32700, format!("parse error: {e}"))))?;
                continue;
            }
        };
        let Some(obj) = msg.as_object() else {
            reply(&mut output, &Value::Null, Err((-32600, "expected a JSON-RPC object (batches are not supported)".into())))?;
            continue;
        };
        let Some(id) = obj.get("id").cloned() else { continue }; // notification: no reply
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            if obj.contains_key("result") || obj.contains_key("error") {
                continue; // a reply to something we never asked; ignore
            }
            reply(&mut output, &id, Err((-32600, "missing method".into())))?;
            continue;
        };
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let r = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL);
                let v = if ["2025-06-18", "2025-03-26", "2024-11-05"].contains(&asked) { asked } else { PROTOCOL };
                let mut r = json!({"protocolVersion": v, "capabilities": {"tools": {"listChanged": false}}, "serverInfo": {"name": info.name, "version": info.version}});
                if let Some(i) = &info.instructions {
                    r["instructions"] = json!(i);
                }
                Ok(r)
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools.iter().map(|t| {
                let s = t.spec();
                json!({"name": s.name, "description": s.description, "inputSchema": s.input_schema,
                       "annotations": {"idempotentHint": s.idempotent}})
            }).collect::<Vec<_>>()})),
            "tools/call" => call(tools, ctx, judge, &params),
            m => Err((-32601, format!("method `{m}` not found"))),
        };
        reply(&mut output, &id, r)?;
    }
}

fn call(tools: &[Arc<dyn Tool>], ctx: &dyn Fn() -> ToolCtx, judge: &dyn Fn(&[Effect]) -> Result<(), String>, params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).ok_or((-32602, "tools/call needs `name`".to_string()))?;
    let tool = tools.iter().find(|t| t.spec().name == name).ok_or_else(|| (-32602, format!("unknown tool `{name}`")))?;
    let args = match params.get("arguments") {
        None | Some(Value::Null) => json!({}),
        Some(a @ Value::Object(_)) => a.clone(),
        Some(_) => return Err((-32602, "`arguments` must be an object".into())),
    };
    let c = ctx();
    let text_result = |text: String, is_error: bool| json!({"content": [{"type": "text", "text": text}], "isError": is_error});
    if let Err(why) = judge(&tool.effects(&c, &args)) {
        return Ok(text_result(format!("blocked: {why}"), true));
    }
    // A panicking tool must not take the whole server down.
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tool.call(&c, args))).unwrap_or_else(|_| ark_core::ToolOutput::err(format!("tool `{name}` panicked")));
    Ok(text_result(out.content, out.is_error))
}
