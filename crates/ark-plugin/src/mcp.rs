//! MCP client (protocol 2025-06-18; older versions accepted). One `Client` per
//! configured server: it connects lazily, reconnects after a crash on the next
//! call, and never lets server stderr reach the model.

use crate::transport::{Conn, HttpConn, Notify, OnRequest, StdioConn};
use crate::{McpServerConfig, Secrets};
use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const PROTOCOL: &str = "2025-06-18";
const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const STARTUP_MAX: Duration = Duration::from_secs(10);
/// After a failed start, calls fail fast for this long instead of respawning.
const RESTART_COOLDOWN: Duration = Duration::from_secs(3);
const MAX_PAGES: usize = 50;

/// A remote tool as listed by `tools/list` (also the cache format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub text: String,
    pub is_error: bool,
}

struct Live {
    conn: Arc<dyn Conn>,
    init: Value,
}

pub struct Client {
    pub name: String,
    cfg: McpServerConfig,
    secrets: Secrets,
    sink: Mutex<Option<Notify>>,
    live: Mutex<Option<Live>>,
    failed: Mutex<Option<(Instant, String)>>,
    stale: Arc<AtomicBool>,
    cache: Mutex<Option<PathBuf>>,
    starts: AtomicUsize,
}

impl Client {
    pub fn new(name: &str, cfg: McpServerConfig, secrets: Secrets) -> Result<Self, String> {
        cfg.validate(name)?;
        Ok(Client { name: name.into(), cfg, secrets, sink: Mutex::new(None), live: Mutex::new(None), failed: Mutex::new(None), stale: Arc::default(), cache: Mutex::new(None), starts: AtomicUsize::new(0) })
    }

    pub fn config(&self) -> &McpServerConfig {
        &self.cfg
    }
    /// Notifications (other than tools/list_changed) go here; set before the first call.
    pub fn on_notification(&self, f: Notify) {
        *self.sink.lock().unwrap() = Some(f);
    }
    /// Catalog cache to delete when the server reports its tool list changed.
    pub fn set_cache_path(&self, p: PathBuf) {
        *self.cache.lock().unwrap() = Some(p);
    }
    pub fn is_running(&self) -> bool {
        self.live.lock().unwrap().as_ref().is_some_and(|l| l.conn.alive())
    }
    /// How many times the server process / session was started.
    pub fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }
    /// The server said its tool list changed since we cached it.
    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::SeqCst)
    }
    pub fn stderr_tail(&self) -> String {
        self.live.lock().unwrap().as_ref().map(|l| l.conn.stderr_tail()).unwrap_or_default()
    }
    pub fn shutdown(&self) {
        self.live.lock().unwrap().take();
    }

    fn connect(&self) -> Result<Live, String> {
        let sub = |s: &String| (self.secrets)(s);
        let notify: Notify = {
            let (stale, sink, cache) = (self.stale.clone(), self.sink.lock().unwrap().clone(), self.cache.lock().unwrap().clone());
            Arc::new(move |m: &str, p: &Value| {
                if m == "notifications/tools/list_changed" {
                    stale.store(true, Ordering::SeqCst);
                    if let Some(c) = &cache {
                        let _ = std::fs::remove_file(c);
                    }
                } else if let Some(s) = &sink {
                    s(m, p);
                }
            })
        };
        let on_req: OnRequest = Arc::new(|m: &str, _p: &Value| match m {
            "ping" => Ok(json!({})),
            "roots/list" => Ok(json!({"roots": []})),
            _ => Err((-32601, format!("method `{m}` not supported by ark"))),
        });
        let startup = self.cfg.timeout().min(STARTUP_MAX);
        self.starts.fetch_add(1, Ordering::SeqCst);
        let conn: Arc<dyn Conn> = match (&self.cfg.command, &self.cfg.url) {
            (Some(cmd), _) => {
                let env: Vec<(String, String)> = self.cfg.env.iter().map(|(k, v)| (k.clone(), sub(v))).collect();
                StdioConn::spawn(cmd, &self.cfg.args, &env, self.cfg.cwd.as_ref(), notify, on_req)?
            }
            (None, Some(url)) => HttpConn::new(url, self.cfg.headers.iter().map(|(k, v)| (k.clone(), sub(v))).collect(), self.cfg.timeout(), notify),
            _ => return Err("no transport".into()),
        };
        let params = json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {"roots": {"listChanged": false}},
            "clientInfo": {"name": "ark", "version": env!("CARGO_PKG_VERSION")},
        });
        let init = conn.request("initialize", params, startup, &Cancel::new()).map_err(|e| {
            let tail = conn.stderr_tail();
            if tail.is_empty() {
                e
            } else {
                format!("{e}\n--- server stderr (tail) ---\n{}", last_lines(&tail, 15))
            }
        })?;
        let v = init.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
        if !SUPPORTED.contains(&v) {
            return Err(format!("server speaks MCP `{v}`, ark supports {}", SUPPORTED.join(", ")));
        }
        conn.set_protocol(v);
        conn.notify("notifications/initialized", json!({}))?;
        self.stale.store(false, Ordering::SeqCst);
        Ok(Live { conn, init })
    }

    fn conn(&self) -> Result<(Arc<dyn Conn>, Value), String> {
        let mut live = self.live.lock().unwrap();
        if let Some(l) = live.as_ref().filter(|l| l.conn.alive()) {
            return Ok((l.conn.clone(), l.init.clone()));
        }
        if let Some((at, e)) = self.failed.lock().unwrap().as_ref() {
            if at.elapsed() < RESTART_COOLDOWN {
                return Err(e.clone());
            }
        }
        *live = None;
        match self.connect() {
            Ok(l) => {
                *self.failed.lock().unwrap() = None;
                let r = (l.conn.clone(), l.init.clone());
                *live = Some(l);
                Ok(r)
            }
            Err(e) => {
                let e = format!("mcp server `{}`: {e}", self.name);
                *self.failed.lock().unwrap() = Some((Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    /// The `initialize` result (connects if needed).
    pub fn info(&self) -> Result<Value, String> {
        self.conn().map(|c| c.1)
    }

    pub fn request(&self, method: &str, params: Value, cancel: &Cancel) -> Result<Value, String> {
        self.request_timeout(method, params, self.cfg.timeout(), cancel)
    }

    pub fn request_timeout(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        let (conn, _) = self.conn()?;
        conn.request(method, params, timeout, cancel).map_err(|e| {
            if conn.alive() {
                format!("mcp `{}` {e}", self.name)
            } else {
                // Dead now: the next call restarts it. Show why it died.
                let tail = conn.stderr_tail();
                format!("mcp `{}` {e} (server stopped; it will be restarted on the next call){}", self.name, if tail.is_empty() { String::new() } else { format!("\n--- server stderr (tail) ---\n{}", last_lines(&tail, 10)) })
            }
        })
    }

    pub fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        self.conn()?.0.notify(method, params)
    }

    fn paged(&self, method: &str, key: &str) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let r = self.request(method, params, &Cancel::new())?;
            out.extend(r.get(key).and_then(Value::as_array).cloned().unwrap_or_default());
            match r.get("nextCursor").and_then(Value::as_str) {
                Some(c) if !c.is_empty() && cursor.as_deref() != Some(c) => cursor = Some(c.into()),
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    pub fn list_tools(&self) -> Result<Vec<ToolDef>, String> {
        Ok(self
            .paged("tools/list", "tools")?
            .into_iter()
            .filter_map(|t| {
                let ann = t.get("annotations");
                let hint = |k: &str| ann.and_then(|a| a.get(k)).and_then(Value::as_bool).unwrap_or(false);
                Some(ToolDef {
                    name: t.get("name")?.as_str()?.to_string(),
                    description: t.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
                    input_schema: t.get("inputSchema").cloned().unwrap_or_else(|| json!({"type": "object"})),
                    read_only: hint("readOnlyHint"),
                    idempotent: hint("idempotentHint"),
                })
            })
            .collect())
    }

    pub fn call_tool(&self, name: &str, args: Value, cancel: &Cancel) -> Result<CallResult, String> {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}), cancel)?;
        Ok(CallResult { text: render_content(&r), is_error: r.get("isError").and_then(Value::as_bool).unwrap_or(false) })
    }

    pub fn list_resources(&self) -> Result<Vec<Value>, String> {
        self.paged("resources/list", "resources")
    }

    pub fn read_resource(&self, uri: &str, cancel: &Cancel) -> Result<String, String> {
        let r = self.request("resources/read", json!({"uri": uri}), cancel)?;
        let parts: Vec<String> = r
            .get("contents")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|c| c.get("text").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| blob_placeholder(c))).collect())
            .unwrap_or_default();
        Ok(parts.join("\n"))
    }

    pub fn list_prompts(&self) -> Result<Vec<Value>, String> {
        self.paged("prompts/list", "prompts")
    }

    /// A prompt rendered to plain text (message texts joined).
    pub fn get_prompt(&self, name: &str, args: &std::collections::BTreeMap<String, String>) -> Result<String, String> {
        let r = self.request("prompts/get", json!({"name": name, "arguments": args}), &Cancel::new())?;
        let msgs = r.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
        let parts: Vec<String> = msgs.iter().filter_map(|m| m.get("content")).map(|c| render_content(&json!({"content": if c.is_array() { c.clone() } else { json!([c]) }}))).collect();
        Ok(parts.join("\n\n"))
    }
}

fn last_lines(s: &str, n: usize) -> String {
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(n)..].join("\n")
}

/// Decoded size of a base64 string (without decoding it).
fn b64_len(s: &str) -> usize {
    let s = s.trim();
    (s.len() / 4 * 3).saturating_sub(s.bytes().rev().take(2).filter(|&b| b == b'=').count())
}

fn blob_placeholder(c: &Value) -> String {
    let mime = c.get("mimeType").and_then(Value::as_str).unwrap_or("application/octet-stream");
    let n = c.get("blob").or_else(|| c.get("data")).and_then(Value::as_str).map(b64_len).unwrap_or(0);
    match c.get("uri").and_then(Value::as_str) {
        Some(u) => format!("[binary resource {u}: {mime}, {n} bytes]"),
        None => format!("[binary: {mime}, {n} bytes]"),
    }
}

/// Tool-result content blocks → text the model sees. Binary data never enters context.
pub fn render_content(r: &Value) -> String {
    let mut out: Vec<String> = Vec::new();
    for b in r.get("content").and_then(Value::as_array).into_iter().flatten() {
        let ty = b.get("type").and_then(Value::as_str).unwrap_or("");
        out.push(match ty {
            "text" => b.get("text").and_then(Value::as_str).unwrap_or("").to_string(),
            "image" | "audio" => {
                let mime = b.get("mimeType").and_then(Value::as_str).unwrap_or("?");
                let n = b.get("data").and_then(Value::as_str).map(b64_len).unwrap_or(0);
                format!("[{ty}: {mime}, {n} bytes]")
            }
            "resource" => {
                let res = b.get("resource").cloned().unwrap_or_default();
                match res.get("text").and_then(Value::as_str) {
                    Some(t) => format!("[resource {}]\n{t}", res.get("uri").and_then(Value::as_str).unwrap_or("?")),
                    None => blob_placeholder(&res),
                }
            }
            "resource_link" => format!("[resource link: {}]", b.get("uri").and_then(Value::as_str).unwrap_or("?")),
            other => format!("[unsupported content type `{other}`]"),
        });
    }
    if out.is_empty() {
        if let Some(s) = r.get("structuredContent") {
            return s.to_string();
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rendering_keeps_binary_out() {
        let r = json!({"content": [
            {"type": "text", "text": "hi"},
            {"type": "image", "mimeType": "image/png", "data": "AAAA"},
            {"type": "resource", "resource": {"uri": "file:///a", "text": "body"}},
            {"type": "resource", "resource": {"uri": "file:///b", "blob": "AAAAAAAA", "mimeType": "x/y"}},
            {"type": "resource_link", "uri": "file:///c"},
            {"type": "weird"}
        ]});
        let t = render_content(&r);
        assert!(t.contains("hi") && t.contains("[image: image/png, 3 bytes]") && t.contains("[resource file:///a]\nbody"));
        assert!(t.contains("[binary resource file:///b: x/y, 6 bytes]") && t.contains("file:///c") && t.contains("`weird`"));
        assert!(!t.contains("AAAA"));
        assert_eq!(render_content(&json!({"content": [], "structuredContent": {"a": 1}})), r#"{"a":1}"#);
    }
}
