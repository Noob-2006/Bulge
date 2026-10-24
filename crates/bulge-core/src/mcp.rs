//! Minimal MCP (Model Context Protocol) stdio client.
//!
//! Connects to external tool servers the user declares in `~/.bulge/mcp.json`,
//! discovers their tools, and runs tool calls — so the agent's toolbox can grow
//! beyond the VM built-ins without changing the agent. Transport is the MCP stdio
//! transport: newline-delimited JSON-RPC 2.0 over the server process's stdio.
//!
//! TRUST NOTE: an MCP server runs on the HOST, as this process, outside the VM
//! sandbox. It is a user-configured extension, trusted like any program the user
//! installs. bulge connects to one only when the user has written `mcp.json`; the
//! exposed tools are namespaced `mcp__<server>__<tool>` so they never shadow the
//! sandboxed built-ins, and the UI/transcript shows when one is used.

use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bulge_llm::ToolSchema;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

use crate::dispatch::{ToolCall, ToolDispatcher};
use crate::schedule::CallOutcome;

/// MCP protocol version we advertise. Servers negotiate down if needed.
const PROTOCOL_VERSION: &str = "2024-11-05";
/// How long a single request may take before we give up on it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the initialize + tools/list handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Default cap on one tool result shown to the model — the same bound the VM
/// tools apply to their output. Per server: `max_result_bytes` in `mcp.json`.
pub const DEFAULT_MAX_RESULT_BYTES: usize = 50 * 1024;

/// One MCP server declaration from `mcp.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub disabled: bool,
    /// Largest tool result passed to the model; longer ones keep their head and
    /// tail. Default [`DEFAULT_MAX_RESULT_BYTES`].
    #[serde(default)]
    pub max_result_bytes: Option<usize>,
}

/// The `mcp.json` file. Accepts both `{"mcpServers": {...}}` (the common editor
/// format) and `{"servers": {...}}`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpConfig {
    #[serde(default, alias = "mcpServers")]
    pub servers: BTreeMap<String, McpServerConfig>,
}

impl McpConfig {
    /// Load `mcp.json` from a path. A missing file is not an error (returns empty);
    /// a malformed one is.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("mcp.json parse error: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("mcp.json read error: {e}")),
        }
    }
}

/// A tool advertised by a server.
#[derive(Debug, Clone)]
pub struct McpTool {
    /// The server's own tool name.
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

/// A live connection to one MCP server.
pub struct McpClient {
    name: String,
    stdin: Mutex<ChildStdin>,
    pending: Pending,
    next_id: AtomicU64,
    tools: Vec<McpTool>,
    max_result_bytes: usize,
    // Kept so the server process is killed when the client drops.
    _child: Child,
}

impl McpClient {
    /// The server's name (from `mcp.json`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The tools it advertised.
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Spawn the server and run the initialize + tools/list handshake.
    pub async fn connect(name: &str, config: &McpServerConfig) -> Result<Arc<Self>, String> {
        let mut command = tokio::process::Command::new(&config.command);
        command
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for (k, v) in &config.env {
            command.env(k, v);
        }
        let mut child = command.spawn().map_err(|e| format!("spawn {}: {e}", config.command))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;

        let pending: Pending = Arc::default();
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(line) else { continue };
                // Only responses (id + result/error) are routed; server-initiated
                // notifications/requests are ignored (we advertise no such caps).
                let Some(id) = value.get("id").and_then(Value::as_u64) else { continue };
                if value.get("result").is_none() && value.get("error").is_none() {
                    continue;
                }
                if let Some(waiter) = reader_pending.lock().await.remove(&id) {
                    let outcome = if let Some(err) = value.get("error") {
                        Err(rpc_error_message(err))
                    } else {
                        Ok(value.get("result").cloned().unwrap_or(Value::Null))
                    };
                    let _ = waiter.send(outcome);
                }
            }
            // Stream closed: fail every outstanding request.
            for (_, waiter) in reader_pending.lock().await.drain() {
                let _ = waiter.send(Err("server closed the connection".into()));
            }
        });

        let client = Arc::new(Self { name: name.to_string(), stdin: Mutex::new(stdin), pending, next_id: AtomicU64::new(1), tools: Vec::new(), max_result_bytes: config.max_result_bytes.unwrap_or(DEFAULT_MAX_RESULT_BYTES), _child: child });

        // Handshake, bounded so a silent server can't hang the launch.
        tokio::time::timeout(CONNECT_TIMEOUT, client.handshake())
            .await
            .map_err(|_| format!("{name}: timed out during MCP handshake"))??;

        // tools can only be filled before we hand out the Arc; rebuild with them.
        let tools = tokio::time::timeout(CONNECT_TIMEOUT, client.list_tools())
            .await
            .map_err(|_| format!("{name}: timed out listing tools"))??;

        // Replace the tools field (the Arc is unique here).
        let mut client = client;
        Arc::get_mut(&mut client).expect("unique during connect").tools = tools;
        Ok(client)
    }

    async fn handshake(&self) -> Result<(), String> {
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "bulge", "version": env!("CARGO_PKG_VERSION") },
        });
        self.request("initialize", params).await?;
        self.notify("notifications/initialized", json!({})).await?;
        Ok(())
    }

    async fn list_tools(&self) -> Result<Vec<McpTool>, String> {
        let result = self.request("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        let name = t.get("name").and_then(Value::as_str)?.to_string();
                        let description = t.get("description").and_then(Value::as_str).unwrap_or("").to_string();
                        let input_schema = t.get("inputSchema").cloned().unwrap_or_else(|| json!({ "type": "object" }));
                        Some(McpTool { name, description, input_schema })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(tools)
    }

    /// Call one tool on this server. `cancel` stops the wait and tells the
    /// server the request is cancelled (MCP `notifications/cancelled`).
    pub async fn call_tool(&self, tool: &str, arguments: Value, cancel: CancellationToken) -> CallOutcome {
        let params = json!({ "name": tool, "arguments": arguments });
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let result = tokio::select! {
            () = cancel.cancelled() => {
                let _ = self.notify("notifications/cancelled", json!({ "requestId": id, "reason": "cancelled by bulge" })).await;
                return CallOutcome::Skipped;
            }
            r = self.request_with_id(id, "tools/call", params) => r,
        };
        match result {
            Ok(value) => bound_outcome(interpret_tool_result(value), self.max_result_bytes),
            Err(message) => CallOutcome::Err { code: "MCP_CALL_FAILED".into(), message },
        }
    }

    /// Send a JSON-RPC request and await its response (bounded by a timeout).
    async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.request_with_id(id, method, params).await
    }

    /// [`Self::request`] with a caller-chosen id. If this future is dropped
    /// before the response (cancel), its waiter is removed from `pending`.
    async fn request_with_id(&self, id: u64, method: &str, params: Value) -> Result<Value, String> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let _forget = ForgetOnDrop { pending: self.pending.clone(), id };
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        if let Err(e) = self.write_line(&line).await {
            return Err(format!("write failed: {e}"));
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("request channel closed".into()),
            Err(_) => Err(format!("{method} timed out")),
        }
    }

    async fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let line = json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string();
        self.write_line(&line).await.map_err(|e| format!("write failed: {e}"))
    }

    async fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await
    }
}

/// The exposed, namespaced tool name for an MCP tool (`mcp__<server>__<tool>`),
/// so it never collides with built-ins or another server.
pub fn exposed_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

/// Everything the driver needs to offer MCP tools: the live clients (kept alive),
/// the extra tool schemas, the routing map, and any per-server connection errors.
#[derive(Default)]
pub struct McpBundle {
    pub clients: Vec<Arc<McpClient>>,
    pub tools: Vec<ToolSchema>,
    /// exposed tool name → (client, server-side tool name).
    pub routes: HashMap<String, (Arc<McpClient>, String)>,
    pub errors: Vec<String>,
}

/// Connect every enabled server in `config`. Failures are collected (not fatal):
/// a broken server must not stop the agent, only its tools go missing.
pub async fn connect_all(config: &McpConfig) -> McpBundle {
    let mut bundle = McpBundle::default();
    for (name, server) in &config.servers {
        if server.disabled {
            continue;
        }
        match McpClient::connect(name, server).await {
            Ok(client) => {
                for tool in client.tools() {
                    let exposed = exposed_name(name, &tool.name);
                    bundle.tools.push(ToolSchema {
                        name: exposed.clone(),
                        description: format!("[MCP:{name}] {}", tool.description),
                        parameters: tool.input_schema.clone(),
                        defer_loading: false,
                    });
                    bundle.routes.insert(exposed, (client.clone(), tool.name.clone()));
                }
                bundle.clients.push(client);
            }
            Err(e) => bundle.errors.push(format!("{name}: {e}")),
        }
    }
    bundle
}

/// A `ToolDispatcher` that routes MCP tools to their server and everything else to
/// a primary dispatcher (the VM).
pub struct CompositeDispatcher {
    primary: Arc<dyn ToolDispatcher>,
    routes: HashMap<String, (Arc<McpClient>, String)>,
}

impl CompositeDispatcher {
    pub fn new(primary: Arc<dyn ToolDispatcher>, routes: HashMap<String, (Arc<McpClient>, String)>) -> Self {
        Self { primary, routes }
    }
}

impl ToolDispatcher for CompositeDispatcher {
    fn dispatch(&self, call: ToolCall, cancel: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        if let Some((client, tool)) = self.routes.get(&call.name) {
            let client = client.clone();
            let tool = tool.clone();
            let args = Value::Object(call.arguments);
            async move { client.call_tool(&tool, args, cancel).await }.boxed()
        } else {
            self.primary.dispatch(call, cancel)
        }
    }

    fn concurrency_safe(&self, name: &str) -> bool {
        // MCP tools are treated as barriers (we can't know if they mutate).
        if self.routes.contains_key(name) { false } else { self.primary.concurrency_safe(name) }
    }
}

/// Turn an MCP `tools/call` result into a `CallOutcome`. The result carries a
/// `content` array of blocks and an optional `isError` flag.
fn interpret_tool_result(result: Value) -> CallOutcome {
    let is_error = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let text = result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    if is_error {
        let message = if text.is_empty() { "MCP tool reported an error".to_string() } else { text };
        return CallOutcome::Err { code: "MCP_TOOL_ERROR".into(), message };
    }
    if text.is_empty() {
        CallOutcome::Ok(result)
    } else {
        CallOutcome::Ok(json!({ "text": text }))
    }
}

/// Removes a request's waiter from `pending` when the request ends for any
/// reason (answered entries are already gone; removal is then a no-op).
struct ForgetOnDrop {
    pending: Pending,
    id: u64,
}

impl Drop for ForgetOnDrop {
    fn drop(&mut self) {
        let (pending, id) = (self.pending.clone(), self.id);
        if let Ok(mut map) = pending.try_lock() {
            map.remove(&id);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}

/// Cap a tool result at `max_bytes`, keeping its head and tail. The model is
/// told how much was left out.
fn bound_outcome(outcome: CallOutcome, max_bytes: usize) -> CallOutcome {
    match outcome {
        CallOutcome::Ok(Value::Object(map)) if map.len() == 1 && map.get("text").is_some_and(Value::is_string) => {
            let text = map["text"].as_str().unwrap_or_default();
            CallOutcome::Ok(json!({ "text": bound_text(text, max_bytes) }))
        }
        CallOutcome::Ok(value) => {
            let rendered = value.to_string();
            if rendered.len() <= max_bytes { CallOutcome::Ok(value) } else { CallOutcome::Ok(json!({ "text": bound_text(&rendered, max_bytes) })) }
        }
        CallOutcome::Err { code, message } => CallOutcome::Err { code, message: bound_text(&message, max_bytes) },
        other => other,
    }
}

fn bound_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let floor = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let ceil = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i += 1;
        }
        i
    };
    let head = floor(max_bytes / 2);
    let tail = ceil(text.len() - (max_bytes - max_bytes / 2));
    let omitted = tail - head;
    format!("{}\n[... {omitted} bytes of this result omitted (limit {max_bytes}) ...]\n{}", &text[..head], &text[tail..])
}

/// A readable message from a JSON-RPC error object.
fn rpc_error_message(err: &Value) -> String {
    let message = err.get("message").and_then(Value::as_str).unwrap_or("error");
    match err.get("code").and_then(Value::as_i64) {
        Some(code) => format!("{message} (code {code})"),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_results_keep_head_and_tail() {
        let text = format!("{}{}", "a".repeat(10_000), "z".repeat(10_000));
        let CallOutcome::Ok(value) = bound_outcome(CallOutcome::Ok(json!({ "text": text })), 1000) else { panic!() };
        let shown = value["text"].as_str().unwrap();
        assert!(shown.len() < 1200, "{}", shown.len());
        assert!(shown.starts_with("aaa") && shown.ends_with("zzz") && shown.contains("19000 bytes"));
        // Multi-byte text is cut on character boundaries.
        let wide = "測".repeat(1000);
        let CallOutcome::Ok(value) = bound_outcome(CallOutcome::Ok(json!({ "text": wide })), 101) else { panic!() };
        assert!(value["text"].as_str().unwrap().contains("omitted"));
        // Small results are untouched.
        assert_eq!(bound_outcome(CallOutcome::Ok(json!({ "text": "ok" })), 1000), CallOutcome::Ok(json!({ "text": "ok" })));
    }

    #[test]
    fn config_accepts_both_keys() {
        let a: McpConfig = serde_json::from_str(r#"{"mcpServers":{"fs":{"command":"x","args":["y"]}}}"#).unwrap();
        assert!(a.servers.contains_key("fs"));
        assert_eq!(a.servers["fs"].command, "x");
        let b: McpConfig = serde_json::from_str(r#"{"servers":{"g":{"command":"z"}}}"#).unwrap();
        assert!(b.servers.contains_key("g"));
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let cfg = McpConfig::load(std::path::Path::new("/nonexistent/mcp.json")).unwrap();
        assert!(cfg.servers.is_empty());
    }

    #[test]
    fn exposed_name_is_namespaced() {
        assert_eq!(exposed_name("fs", "read_file"), "mcp__fs__read_file");
    }

    #[test]
    fn tool_result_text_and_error() {
        let ok = interpret_tool_result(json!({ "content": [{ "type": "text", "text": "hi" }] }));
        assert!(matches!(ok, CallOutcome::Ok(v) if v.get("text").and_then(Value::as_str) == Some("hi")));
        let err = interpret_tool_result(json!({ "isError": true, "content": [{ "type": "text", "text": "boom" }] }));
        assert!(matches!(err, CallOutcome::Err { message, .. } if message == "boom"));
    }
}
