//! Ark plugin protocol v1 — a strict superset of MCP over stdio.
//!
//! A plugin is any MCP stdio server. Everything MCP offers (tools, resources,
//! prompts) works unchanged; any MCP server can be used as a plugin. A plugin
//! opts into the extras by advertising them in its `initialize` result:
//!
//! ```json
//! {"capabilities": {"tools": {}, "experimental": {"ark": {
//!     "version": 1,
//!     "hooks": ["pre_tool", "post_tool", "session_start", "turn_end", "message_received"],
//!     "channels": ["telegram"],
//!     "commands": [{"name": "weather", "description": "…", "args": "<city>"}],
//!     "routes": [{"path": "/hook", "methods": ["POST"], "public": true}],
//!     "providers": [{"id": "local", "models": ["m1"], "context_window": 32000}],
//!     "services": [{"name": "indexer", "health_secs": 30}],
//!     "cli": [{"name": "kb", "description": "…", "args": "<sub> …"}],
//!     "middleware": ["tool_request", "llm_execution"],
//!     "context_engine": {"owns_compaction": true},
//!     "memory": true,
//!     "node_commands": [{"command": "kb.search", "description": "…", "dangerous": false, "params": {…}}],
//!     "ui": [{"id": "dash", "title": "Dashboard", "surface": "tab"}]
//! }}}}
//! ```
//!
//! The full protocol (every request, result and event name) is in docs/plugins.md.
//!
//! **Hooks** — ark → plugin request, only for events the plugin listed:
//! `{"method": "ark/hook", "params": {"event": "pre_tool", "payload": {...}}}`
//! → result `{"decision": "allow" | "deny" | "modify", "reason"?: str, "input"?: any}`.
//! `modify` replaces the payload's `input` (e.g. a tool's arguments) with `input`.
//! A hook that errors or exceeds its timeout (default 5 s) is treated as `allow`
//! and reported as a warning: a broken plugin never blocks the agent.
//!
//! **Channels** — messaging bridges.
//! - outbound, ark → plugin request: `{"method": "ark/channel.send",
//!   "params": {"channel": "telegram", "message": {"chat": "…", "text": "…", …}}}`
//!   → any result (e.g. `{"id": "…"}`); errors are reported to the caller.
//! - inbound, plugin → ark notification: `{"method": "ark/channel.inbound",
//!   "params": {"channel": "telegram", "message": {"chat": "…", "sender": "…", "text": "…"}}}`.
//!
//! **Commands** — `ark/command {name, args, context}` → `{text?}` (shown to the user) and/or
//! `{prompt?}` (sent to the agent as the user's message).
//!
//! **HTTP routes** — mounted at `/plugins/<plugin>/<path>` on the app server:
//! `ark/http {method, path, query, headers, body | body_base64}` → `{status, headers, body | body_base64}`.
//!
//! **Model providers** — `ark/provider.complete {provider, stream_id, request}` (an ark
//! `ModelRequest`); the plugin may stream `ark/provider.delta {stream_id, text?, thinking?}`
//! notifications and answers with a `ModelResponse` (`{message, stop, usage, model}`) or `{text}`.
//!
//! **Services** — `ark/service.start|stop|health {name}`; health → `{ok, detail?}`. The daemon
//! starts them, polls health and restarts a service that fails twice in a row.
//!
//! **CLI** — `ark <name> args…` → `ark/cli {name, argv, cwd, run_id}`; the plugin may stream
//! `ark/cli.output {run_id, stream: "stdout"|"stderr", text}` and answers `{exit?, stdout?, stderr?}`.
//!
//! **Middleware** (Hermes) — `ark/middleware {kind, phase?, payload}` → `{args}` (tool_request),
//! `{request}` (llm_request), `{result}` (tool_execution), `{response}` (llm_execution) or nothing.
//!
//! **Context engine** (OpenClaw) — `ark/context.assemble {session, workspace, messages, token_budget,
//! model, prompt, bootstrap}` → `{messages?, system_prompt_addition?}`; `ark/context.compact
//! {session, messages, token_budget, current_tokens, force}` → `{compacted, summary?, keep_messages?}`;
//! notification `ark/context.ingest {session, message}`.
//!
//! **Memory provider** — `ark/memory.call {action, file, text?, old?, query?, session}` → `{text}`;
//! `ark/memory.prompt {}` → `{text}` (static system-prompt block).
//!
//! **Node commands** — run on `ark node` hosts: `ark/node.invoke {command, params}` → payload.
//!
//! **UI** — `ark/ui.render {id, query}` → `{html, csp?}`; `ark/ui.call {id, method, params}` → any.
//!
//! Plugin stderr is kept in a small ring buffer for diagnostics and never reaches
//! the model. Unknown `ark/*` methods from a plugin get JSON-RPC -32601.

use crate::bridge::bridge_tools;
use crate::mcp::Client;
use crate::{McpServerConfig, Secrets};
use ark_core::{Cancel, Effect, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, ProviderErrorKind, StopReason, StreamEvent, Tool, ToolCtx, ToolOutput, ToolSpec, Usage};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HOOK_TIMEOUT: Duration = Duration::from_secs(5);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandDecl {
    pub name: String,
    pub description: String,
    /// Argument hint shown in help, e.g. `<city>`.
    pub args: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteDecl {
    /// Prefix under `/plugins/<plugin>`; "/" (default) takes everything.
    pub path: String,
    /// Allowed methods; empty = any.
    pub methods: Vec<String>,
    /// Skip the app token (webhooks that verify their own signatures).
    pub public: bool,
}

impl RouteDecl {
    pub fn matches(&self, method: &str, sub: &str) -> bool {
        let pre = self.path.trim_end_matches('/');
        let path_ok = pre.is_empty() || sub == pre || sub.starts_with(&format!("{pre}/"));
        path_ok && (self.methods.is_empty() || self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderDecl {
    pub id: String,
    pub models: Vec<String>,
    pub context_window: u64,
    pub max_output: u32,
    pub tools: bool,
    pub vision: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceDecl {
    pub name: String,
    /// Health poll interval (default 60 s, minimum 1 s).
    pub health_secs: u64,
}

/// A context engine declaration (`true` or `{owns_compaction}`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineDecl {
    pub owns_compaction: bool,
}

/// A command `ark node` offers on behalf of the plugin (OpenClaw `registerNodeHostCommand`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeCommandDecl {
    pub command: String,
    pub description: String,
    /// Acts on a person's device or data: the egress gate asks first.
    pub dangerous: bool,
    /// JSON Schema of the params (shown by node.describe).
    pub params: Value,
}

/// A web UI panel (OpenClaw `registerControlUiDescriptor`), rendered in a sandboxed frame.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiDecl {
    pub id: String,
    pub title: String,
    /// "tab" (sidebar, default) or "settings".
    pub surface: String,
    pub icon: String,
}

/// What `ark/cli` answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CliReply {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
}

/// What `ark/command` answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommandReply {
    pub text: Option<String>,
    pub prompt: Option<String>,
}

/// What `ark/http` answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

type Streams = Arc<Mutex<HashMap<String, Sender<Value>>>>;

fn decls<T: serde::de::DeserializeOwned>(v: Option<&Value>) -> Vec<T> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect()).unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq)]
pub enum HookDecision {
    Allow,
    Deny(String),
    /// Replacement for the payload's `input`.
    Modify(Value),
}

pub struct PluginHost {
    pub name: String,
    client: Arc<Client>,
    hooks: Vec<String>,
    channels: Vec<String>,
    pub commands: Vec<CommandDecl>,
    pub routes: Vec<RouteDecl>,
    pub providers: Vec<ProviderDecl>,
    pub services: Vec<ServiceDecl>,
    pub cli: Vec<CommandDecl>,
    middleware: Vec<String>,
    pub context_engine: Option<EngineDecl>,
    pub memory: bool,
    pub node_commands: Vec<NodeCommandDecl>,
    pub ui: Vec<UiDecl>,
    inbound: Mutex<Option<Receiver<(String, Value)>>>,
    streams: Streams,
    hook_timeout: Duration,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

impl PluginHost {
    /// Start the plugin process (stdio only) and read its declared extras.
    pub fn start(name: &str, cfg: &McpServerConfig, secrets: Secrets) -> Result<PluginHost, String> {
        if cfg.command.is_none() {
            return Err(format!("plugin `{name}` needs a `command` (plugins speak stdio)"));
        }
        let client = Arc::new(Client::new(name, cfg.clone(), secrets)?);
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let streams: Streams = Arc::default();
        let st = streams.clone();
        client.on_notification(Arc::new(move |m: &str, p: &Value| match m {
            "ark/channel.inbound" => {
                if let (Some(ch), Some(msg)) = (p.get("channel").and_then(Value::as_str), p.get("message")) {
                    let _ = tx.lock().unwrap().send((ch.to_string(), msg.clone()));
                }
            }
            "ark/provider.delta" | "ark/cli.output" => {
                if let Some(s) = p.get("stream_id").or_else(|| p.get("run_id")).and_then(Value::as_str).and_then(|id| st.lock().unwrap().get(id).cloned()) {
                    let _ = s.send(p.clone());
                }
            }
            _ => {}
        }));
        let init = client.info()?;
        let ark = init.pointer("/capabilities/experimental/ark");
        let get = |k: &str| ark.and_then(|a| a.get(k));
        Ok(PluginHost {
            name: name.into(),
            hooks: strings(get("hooks")),
            channels: strings(get("channels")),
            commands: decls::<CommandDecl>(get("commands")).into_iter().filter(|c| !c.name.is_empty()).collect(),
            routes: decls(get("routes")),
            providers: decls::<ProviderDecl>(get("providers")).into_iter().filter(|p| !p.id.is_empty()).collect(),
            services: decls::<ServiceDecl>(get("services")).into_iter().filter(|s| !s.name.is_empty()).collect(),
            cli: decls::<CommandDecl>(get("cli")).into_iter().filter(|c| !c.name.is_empty()).collect(),
            middleware: strings(get("middleware")),
            context_engine: match get("context_engine") {
                Some(Value::Bool(true)) => Some(EngineDecl::default()),
                Some(v @ Value::Object(_)) => serde_json::from_value(v.clone()).ok(),
                _ => None,
            },
            memory: get("memory").is_some_and(|v| v.as_bool() != Some(false) && !v.is_null()),
            node_commands: decls::<NodeCommandDecl>(get("node_commands")).into_iter().filter(|c| !c.command.is_empty()).collect(),
            ui: decls::<UiDecl>(get("ui")).into_iter().filter(|u| !u.id.is_empty() && u.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')).collect(),
            client,
            inbound: Mutex::new(Some(rx)),
            streams,
            hook_timeout: HOOK_TIMEOUT,
        })
    }

    pub fn with_hook_timeout(mut self, d: Duration) -> Self {
        self.hook_timeout = d;
        self
    }
    pub fn hooks(&self) -> &[String] {
        &self.hooks
    }
    pub fn channels(&self) -> &[String] {
        &self.channels
    }
    pub fn middleware_kinds(&self) -> &[String] {
        &self.middleware
    }
    pub fn client(&self) -> &Arc<Client> {
        &self.client
    }
    /// Restart a crashed plugin (channels need it running to deliver inbound messages).
    pub fn ensure_running(&self) -> Result<(), String> {
        self.client.info().map(|_| ())
    }

    pub fn tools(&self, taken: &mut HashSet<String>) -> Result<Vec<Arc<dyn Tool>>, String> {
        let init = self.client.info()?;
        let defs = if init.pointer("/capabilities/tools").is_some() { self.client.list_tools()? } else { vec![] };
        Ok(bridge_tools(&self.client, &defs, init.pointer("/capabilities/resources").is_some(), taken))
    }

    /// Run a hook. `Err` means the plugin failed or timed out: callers fail open
    /// (treat as allow) and surface the message as a warning.
    pub fn hook(&self, event: &str, payload: Value) -> Result<HookDecision, String> {
        if !self.hooks.iter().any(|h| h == event) {
            return Ok(HookDecision::Allow);
        }
        let r = self.client.request_timeout("ark/hook", json!({"event": event, "payload": payload}), self.hook_timeout, &Cancel::new()).map_err(|e| format!("plugin `{}` hook {event} failed, allowing: {e}", self.name))?;
        let reason = r.get("reason").and_then(Value::as_str).map(str::to_string);
        match r.get("decision").and_then(Value::as_str) {
            Some("allow") | None => Ok(HookDecision::Allow),
            Some("deny") => Ok(HookDecision::Deny(reason.unwrap_or_else(|| format!("denied by plugin {}", self.name)))),
            Some("modify") => match r.get("input") {
                Some(i) => Ok(HookDecision::Modify(i.clone())),
                None => Err(format!("plugin `{}` hook {event}: `modify` without `input`, allowing unchanged", self.name)),
            },
            Some(d) => Err(format!("plugin `{}` hook {event}: unknown decision `{d}`, allowing", self.name)),
        }
    }

    pub fn channel_send(&self, channel: &str, message: Value) -> Result<Value, String> {
        if !self.channels.iter().any(|c| c == channel) {
            return Err(format!("plugin `{}` has no channel `{channel}`", self.name));
        }
        self.client.request("ark/channel.send", json!({"channel": channel, "message": message}), &Cancel::new())
    }

    /// Inbound channel messages `(channel, message)`. Can be taken once.
    pub fn take_inbound(&self) -> Option<Receiver<(String, Value)>> {
        self.inbound.lock().unwrap().take()
    }

    /// Run a slash command. `context` says where it was typed (`surface`, `session`, `channel`, `sender`…).
    pub fn command(&self, name: &str, args: &str, context: Value) -> Result<CommandReply, String> {
        if !self.commands.iter().any(|c| c.name == name) {
            return Err(format!("plugin `{}` has no command `{name}`", self.name));
        }
        let r = self.client.request_timeout("ark/command", json!({"name": name, "args": args, "context": context}), CALL_TIMEOUT, &Cancel::new()).map_err(|e| format!("plugin `{}` /{name}: {e}", self.name))?;
        let s = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_string);
        Ok(CommandReply { text: s("text"), prompt: s("prompt") })
    }

    /// The route serving `method` + `sub` (the path after `/plugins/<name>`), if any.
    pub fn route(&self, method: &str, sub: &str) -> Option<&RouteDecl> {
        self.routes.iter().find(|r| r.matches(method, sub))
    }

    /// Proxy one HTTP request to the plugin.
    pub fn http(&self, method: &str, sub: &str, query: &str, headers: &[(String, String)], body: &[u8]) -> Result<HttpReply, String> {
        let hs: serde_json::Map<String, Value> = headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie")).map(|(k, v)| (k.to_ascii_lowercase(), json!(v))).collect();
        let mut p = json!({"method": method, "path": sub, "query": query, "headers": hs});
        match std::str::from_utf8(body) {
            Ok(t) => p["body"] = json!(t),
            Err(_) => p["body_base64"] = json!(ark_net::crypto::b64(body)),
        }
        let r = self.client.request_timeout("ark/http", p, CALL_TIMEOUT, &Cancel::new()).map_err(|e| format!("plugin `{}` http: {e}", self.name))?;
        let body = match (r.get("body_base64").and_then(Value::as_str), &r["body"]) {
            (Some(b), _) => ark_net::crypto::b64_decode(b).ok_or("plugin http: bad body_base64")?,
            (None, Value::String(t)) => t.clone().into_bytes(),
            (None, Value::Null) => vec![],
            (None, other) => other.to_string().into_bytes(),
        };
        let headers = r["headers"].as_object().map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).filter(|(k, v)| !k.contains(['\r', '\n']) && !v.contains(['\r', '\n'])).collect()).unwrap_or_default();
        Ok(HttpReply { status: r["status"].as_u64().filter(|s| (100..600).contains(s)).unwrap_or(200) as u16, headers, body })
    }

    /// Run `ark <name> argv…`. `out(stream, text)` gets streamed output.
    pub fn cli(&self, name: &str, argv: &[String], cwd: &str, out: &mut dyn FnMut(&str, &str)) -> Result<CliReply, String> {
        if !self.cli.iter().any(|c| c.name == name) {
            return Err(format!("plugin `{}` has no CLI command `{name}`", self.name));
        }
        let rid = ark_net::crypto::random_token(9);
        let params = json!({"name": name, "argv": argv, "cwd": cwd, "run_id": rid});
        let r = self.streamed(&rid, "ark/cli", params, self.client.config().timeout().max(Duration::from_secs(600)), &Cancel::new(), &mut |d| {
            if let Some(t) = d.get("text").and_then(Value::as_str) {
                out(d.get("stream").and_then(Value::as_str).unwrap_or("stdout"), t);
            }
        });
        let r = r.map_err(|e| format!("plugin `{}` {name}: {e}", self.name))?;
        let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(CliReply { exit: r.get("exit").and_then(Value::as_i64).unwrap_or(0) as i32, stdout: s("stdout"), stderr: s("stderr") })
    }

    /// A request whose notifications (tagged with `id`) stream to `on` while it runs.
    fn streamed(&self, id: &str, method: &str, params: Value, timeout: Duration, cancel: &Cancel, on: &mut dyn FnMut(Value)) -> Result<Value, String> {
        let (tx, rx) = mpsc::channel();
        self.streams.lock().unwrap().insert(id.to_string(), tx);
        let (client, c, m) = (self.client.clone(), cancel.clone(), method.to_string());
        let worker = std::thread::spawn(move || client.request_timeout(&m, params, timeout, &c));
        while !worker.is_finished() {
            rx.try_iter().for_each(&mut *on);
            std::thread::sleep(Duration::from_millis(10));
        }
        let r = worker.join().unwrap_or_else(|_| Err("plugin worker panicked".into()));
        // Notifications sent just before the result.
        std::thread::sleep(Duration::from_millis(5));
        rx.try_iter().for_each(&mut *on);
        self.streams.lock().unwrap().remove(id);
        r
    }

    /// Hermes middleware: the replacement for `payload`'s key (`args`, `request`, `result`,
    /// `response`), or `None` to leave it. `Err` = the plugin failed (callers fail open).
    pub fn middleware(&self, kind: &str, phase: Option<&str>, payload: Value) -> Result<Option<Value>, String> {
        if !self.middleware.iter().any(|m| m == kind) {
            return Ok(None);
        }
        let key = match kind {
            "tool_request" => "args",
            "llm_request" => "request",
            "tool_execution" => "result",
            "llm_execution" => "response",
            _ => return Err(format!("unknown middleware kind `{kind}`")),
        };
        let t = if kind.ends_with("_execution") { CALL_TIMEOUT } else { self.hook_timeout };
        let mut p = json!({"kind": kind, "payload": payload});
        if let Some(ph) = phase {
            p["phase"] = json!(ph);
        }
        let r = self.client.request_timeout("ark/middleware", p, t, &Cancel::new()).map_err(|e| format!("plugin `{}` middleware {kind} failed, skipping: {e}", self.name))?;
        Ok(r.get(key).filter(|v| !v.is_null()).cloned())
    }

    /// `ark/context.<method>` (assemble, compact) for the context engine.
    pub fn context(&self, method: &str, params: Value) -> Result<Value, String> {
        if self.context_engine.is_none() {
            return Err(format!("plugin `{}` is not a context engine", self.name));
        }
        let t = if method == "compact" { self.client.config().timeout().max(Duration::from_secs(120)) } else { CALL_TIMEOUT };
        self.client.request_timeout(&format!("ark/context.{method}"), params, t, &Cancel::new()).map_err(|e| format!("plugin `{}` context.{method}: {e}", self.name))
    }

    /// `ark/context.ingest` (a notification: never waits).
    pub fn context_ingest(&self, session: &str, message: Value) {
        if self.context_engine.is_some() && self.client.is_running() {
            let _ = self.client.notify("ark/context.ingest", json!({"session": session, "message": message}));
        }
    }

    /// `ark/memory.call`.
    pub fn memory(&self, params: Value) -> Result<String, String> {
        if !self.memory {
            return Err(format!("plugin `{}` is not a memory provider", self.name));
        }
        let r = self.client.request_timeout("ark/memory.call", params, CALL_TIMEOUT, &Cancel::new()).map_err(|e| format!("memory provider `{}`: {e}", self.name))?;
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            return Err(e.to_string());
        }
        Ok(match &r["text"] {
            Value::String(t) => t.clone(),
            Value::Null => r.to_string(),
            v => v.to_string(),
        })
    }

    /// The provider's static system-prompt block (`ark/memory.prompt`), if any.
    pub fn memory_prompt(&self) -> Option<String> {
        let r = self.client.request_timeout("ark/memory.prompt", json!({}), self.hook_timeout, &Cancel::new()).ok()?;
        r.get("text").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()).map(str::to_string)
    }

    /// `ark/node.invoke` for one of `node_commands`.
    pub fn node_invoke(&self, command: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        if !self.node_commands.iter().any(|c| c.command == command) {
            return Err(format!("plugin `{}` has no node command `{command}`", self.name));
        }
        let r = self.client.request_timeout("ark/node.invoke", json!({"command": command, "params": params}), timeout, &Cancel::new()).map_err(|e| format!("plugin `{}` {command}: {e}", self.name))?;
        match r.get("error") {
            Some(Value::String(e)) => Err(e.clone()),
            _ => Ok(r),
        }
    }

    /// `ark/ui.render` → `{html, csp?}` for a declared panel.
    pub fn ui_render(&self, id: &str, query: &str) -> Result<Value, String> {
        if !self.ui.iter().any(|u| u.id == id) {
            return Err(format!("plugin `{}` has no UI panel `{id}`", self.name));
        }
        let r = self.client.request_timeout("ark/ui.render", json!({"id": id, "query": query}), CALL_TIMEOUT, &Cancel::new()).map_err(|e| format!("plugin `{}` ui {id}: {e}", self.name))?;
        if !r["html"].is_string() {
            return Err(format!("plugin `{}` ui {id}: no `html` in the answer", self.name));
        }
        Ok(r)
    }

    /// `ark/ui.call` from a panel (the frame's messages, proxied over ARP).
    pub fn ui_call(&self, id: &str, method: &str, params: Value) -> Result<Value, String> {
        if !self.ui.iter().any(|u| u.id == id) {
            return Err(format!("plugin `{}` has no UI panel `{id}`", self.name));
        }
        self.client.request_timeout("ark/ui.call", json!({"id": id, "method": method, "params": params}), CALL_TIMEOUT, &Cancel::new()).map_err(|e| format!("plugin `{}` ui {id}: {e}", self.name))
    }

    /// `ark/service.<action>` (start, stop, health).
    pub fn service(&self, action: &str, name: &str) -> Result<Value, String> {
        let t = if action == "health" { self.hook_timeout } else { CALL_TIMEOUT };
        self.client.request_timeout(&format!("ark/service.{action}"), json!({"name": name}), t, &Cancel::new()).map_err(|e| format!("plugin `{}` service {name} {action}: {e}", self.name))
    }

    /// The model providers this plugin registers, ready for the model registry.
    pub fn provider_impls(self: &Arc<Self>) -> Vec<(String, Arc<dyn Provider>)> {
        self.providers.iter().map(|d| (d.id.clone(), Arc::new(PluginProvider { host: self.clone(), decl: d.clone() }) as Arc<dyn Provider>)).collect()
    }
}

/// A model provider served by a plugin (`ark/provider.complete`).
pub struct PluginProvider {
    host: Arc<PluginHost>,
    decl: ProviderDecl,
}

impl Provider for PluginProvider {
    fn id(&self) -> &str {
        &self.decl.id
    }
    fn caps(&self, _model: &str) -> ModelCaps {
        ModelCaps { context_window: if self.decl.context_window > 0 { self.decl.context_window } else { 32_000 }, max_output: if self.decl.max_output > 0 { self.decl.max_output } else { 4096 }, tools: self.decl.tools, vision: self.decl.vision, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let sid = ark_net::crypto::random_token(9);
        let (tx, rx) = mpsc::channel();
        self.host.streams.lock().unwrap().insert(sid.clone(), tx);
        let params = json!({"provider": self.decl.id, "stream_id": sid, "request": req});
        let (host, c) = (self.host.clone(), cancel.clone());
        let timeout = self.host.client.config().timeout().max(Duration::from_secs(120));
        let worker = std::thread::spawn(move || host.client.request_timeout("ark/provider.complete", params, timeout, &c));
        let mut text = String::new();
        let mut pump = |rx: &Receiver<Value>, text: &mut String| {
            for d in rx.try_iter() {
                if let Some(t) = d.get("text").and_then(Value::as_str).filter(|t| !t.is_empty()) {
                    text.push_str(t);
                    on_event(StreamEvent::TextDelta(t.to_string()));
                }
                if let Some(t) = d.get("thinking").and_then(Value::as_str).filter(|t| !t.is_empty()) {
                    on_event(StreamEvent::ThinkingDelta(t.to_string()));
                }
            }
        };
        while !worker.is_finished() {
            pump(&rx, &mut text);
            std::thread::sleep(Duration::from_millis(10));
        }
        let r = worker.join().unwrap_or_else(|_| Err("plugin provider worker panicked".into()));
        // Deltas sent just before the result.
        std::thread::sleep(Duration::from_millis(5));
        pump(&rx, &mut text);
        self.host.streams.lock().unwrap().remove(&sid);
        if cancel.is_cancelled() {
            return Err(ProviderError::new(ProviderErrorKind::Cancelled, "cancelled"));
        }
        let v = r.map_err(|e| ProviderError::new(if e.contains("timed out") { ProviderErrorKind::Timeout } else { ProviderErrorKind::Server }, e))?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(ProviderError::new(ProviderErrorKind::BadRequest, format!("plugin provider {}: {e}", self.decl.id)));
        }
        if let Ok(mut resp) = serde_json::from_value::<ModelResponse>(v.clone()) {
            if resp.model.is_empty() {
                resp.model = req.model.clone();
            }
            return Ok(resp);
        }
        let t = v.get("text").and_then(Value::as_str).map(str::to_string).unwrap_or(text);
        let usage = v.get("usage").and_then(|u| serde_json::from_value::<Usage>(u.clone()).ok()).unwrap_or(Usage { input_tokens: ark_core::estimate_tokens(&req.system_text()), output_tokens: ark_core::estimate_tokens(&t), estimated: true, ..Default::default() });
        Ok(ModelResponse { message: ark_core::Message::assistant(t), stop: StopReason::EndTurn, usage, model: req.model.clone() })
    }
}

/// The `memory` tool served by a memory-provider plugin (`[memory] provider = "<plugin>"`).
/// Same actions as the built-in tool plus `search`; the plugin decides how it stores them.
pub struct PluginMemory(pub Arc<PluginHost>);

impl Tool for PluginMemory {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "memory".into(),
            description: format!("Persistent memory across sessions (provider: {}). file=memory for your notes, file=user for facts about the user. Actions: read, search (query), add, replace (old→text), remove (old).", self.0.name),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["read","search","add","replace","remove"]},
                "file":{"type":"string","enum":["memory","user"],"default":"memory"},
                "text":{"type":"string"},
                "query":{"type":"string"},
                "old":{"type":"string","description":"Unique substring of the entry to replace/remove"}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        vec![Effect::Net { dest: format!("mcp:{}", self.0.name), payload: input.to_string() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let s = |k: &str| input.get(k).and_then(Value::as_str);
        let Some(action) = s("action").or(s("command")) else { return ToolOutput::err("memory needs `action`: read, search, add, replace or remove") };
        let mut p = json!({"action": action, "file": s("file").unwrap_or("memory"), "session": ctx.session_id});
        for k in ["text", "old", "query"] {
            if let Some(v) = s(k).or_else(|| if k == "text" { s("content") } else { None }) {
                p[k] = json!(v);
            }
        }
        match self.0.memory(p) {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// Start every service, poll health, restart one that fails twice in a row, stop all on cancel.
pub fn supervise(hosts: Vec<Arc<PluginHost>>, cancel: Cancel) -> Option<std::thread::JoinHandle<()>> {
    let svcs: Vec<(Arc<PluginHost>, ServiceDecl)> = hosts.iter().flat_map(|h| h.services.iter().map(move |s| (h.clone(), s.clone()))).collect();
    if svcs.is_empty() {
        return None;
    }
    Some(std::thread::spawn(move || {
        let mut state: Vec<(u32, std::time::Instant)> = Vec::new();
        for (h, s) in &svcs {
            if let Err(e) = h.service("start", &s.name) {
                eprintln!("ark: {e}");
            }
            state.push((0, std::time::Instant::now()));
        }
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(100));
            for ((h, s), (fails, last)) in svcs.iter().zip(state.iter_mut()) {
                if last.elapsed() < Duration::from_secs(if s.health_secs == 0 { 60 } else { s.health_secs.max(1) }) {
                    continue;
                }
                *last = std::time::Instant::now();
                let ok = matches!(h.service("health", &s.name), Ok(v) if v.get("ok").and_then(Value::as_bool) != Some(false));
                *fails = if ok { 0 } else { *fails + 1 };
                if *fails >= 2 {
                    eprintln!("ark: plugin `{}` service {} unhealthy; restarting", h.name, s.name);
                    let _ = h.service("stop", &s.name);
                    let _ = h.ensure_running();
                    if let Err(e) = h.service("start", &s.name) {
                        eprintln!("ark: {e}");
                    }
                    *fails = 0;
                }
            }
        }
        for (h, s) in &svcs {
            let _ = h.service("stop", &s.name);
        }
    }))
}
