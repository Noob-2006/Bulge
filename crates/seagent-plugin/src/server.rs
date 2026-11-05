//! MCP server (newline-delimited stdio, or any framing via [`Server::handle`],
//! e.g. the outbound relay): exposes SE Agent's tools to other agents.
//! Every call passes the caller-supplied `judge` (the two gates) before running.

use crate::mcp::{MODERN, PROTOCOL};
use crate::transport::{read_line_capped, MAX_MESSAGE};
use seagent_core::{Effect, Tool, ToolCtx};
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

/// One MCP server over any framing: `handle` takes a parsed message and returns
/// the reply (None for notifications and stray responses). Dual-era: answers
/// `initialize` (2025-11-25 and older) and stateless requests carrying the
/// 2026-07-28 `_meta` protocol fields, plus `server/discover`.
pub struct Server<'a> {
    pub info: &'a ServerInfo,
    pub tools: &'a [Arc<dyn Tool>],
    pub ctx: &'a dyn Fn() -> ToolCtx,
    pub judge: &'a dyn Fn(&[Effect]) -> Result<(), String>,
}

const PV: &str = "io.modelcontextprotocol/protocolVersion";

fn rpc(id: &Value, r: Result<Value, (i64, String, Option<Value>)>) -> Value {
    match r {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err((code, m, None)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}}),
        Err((code, m, Some(d))) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m, "data": d}}),
    }
}

impl Server<'_> {
    fn versions() -> Vec<&'static str> {
        std::iter::once(MODERN).chain(crate::mcp::SUPPORTED.iter().copied()).collect()
    }

    pub fn handle(&self, msg: &Value) -> Option<Value> {
        let Some(obj) = msg.as_object() else { return Some(rpc(&Value::Null, Err((-32600, "expected a JSON-RPC object (batches are not supported)".into(), None)))) };
        let id = obj.get("id").cloned()?; // notification: no reply
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            if obj.contains_key("result") || obj.contains_key("error") {
                return None; // a reply to something we never asked; ignore
            }
            return Some(rpc(&id, Err((-32600, "missing method".into(), None))));
        };
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let asked = params["_meta"][PV].as_str();
        if let Some(v) = asked.filter(|v| !Self::versions().contains(v)) {
            return Some(rpc(&id, Err((-32022, "Unsupported protocol version".into(), Some(json!({"supported": Self::versions(), "requested": v}))))));
        }
        let caps = json!({"tools": {"listChanged": false}});
        let info = json!({"name": self.info.name, "version": self.info.version});
        let r = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL);
                let v = if crate::mcp::SUPPORTED.contains(&asked) { asked } else { PROTOCOL };
                let mut r = json!({"protocolVersion": v, "capabilities": caps, "serverInfo": info});
                if let Some(i) = &self.info.instructions {
                    r["instructions"] = json!(i);
                }
                Ok(r)
            }
            "server/discover" => {
                let mut r = json!({"supportedVersions": Self::versions(), "capabilities": caps});
                if let Some(i) = &self.info.instructions {
                    r["instructions"] = json!(i);
                }
                Ok(r)
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools.iter().map(|t| {
                let s = t.spec();
                json!({"name": s.name, "description": s.description, "inputSchema": s.input_schema,
                       "annotations": {"idempotentHint": s.idempotent}})
            }).collect::<Vec<_>>()})),
            "tools/call" => call(self.tools, self.ctx, self.judge, &params),
            m => Err((-32601, format!("method `{m}` not found"))),
        };
        // Modern requests get the polymorphic `resultType` and our identity in `_meta`.
        let r = match r {
            Ok(mut v) if asked.is_some() || method == "server/discover" => {
                v["resultType"] = json!("complete");
                v["_meta"] = json!({"io.modelcontextprotocol/serverInfo": info});
                Ok(v)
            }
            Ok(v) => Ok(v),
            Err((c, m)) => Err((c, m, None)),
        };
        Some(rpc(&id, r))
    }
}

/// Serve until EOF on `input`. Requests are handled one at a time.
pub fn serve<R: BufRead, W: Write>(info: &ServerInfo, tools: &[Arc<dyn Tool>], ctx: &dyn Fn() -> ToolCtx, judge: &dyn Fn(&[Effect]) -> Result<(), String>, mut input: R, mut output: W) -> std::io::Result<()> {
    let srv = Server { info, tools, ctx, judge };
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
        if let Some(r) = srv.handle(&msg) {
            let mut b = serde_json::to_vec(&r).expect("json");
            b.push(b'\n');
            output.write_all(&b)?;
            output.flush()?;
        }
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
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tool.call(&c, args))).unwrap_or_else(|_| seagent_core::ToolOutput::err(format!("tool `{name}` panicked")));
    Ok(text_result(out.content, out.is_error))
}
