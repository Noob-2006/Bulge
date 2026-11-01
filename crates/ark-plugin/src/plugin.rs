//! Ark plugin protocol v1 — a strict superset of MCP over stdio.
//!
//! A plugin is any MCP stdio server. Everything MCP offers (tools, resources,
//! prompts) works unchanged; any MCP server can be used as a plugin. A plugin
//! opts into the extras by advertising them in its `initialize` result:
//!
//! ```json
//! {"capabilities": {"tools": {}, "experimental": {"ark": {
//!     "version": 1,
//!     "hooks": ["pre_tool", "post_tool", "session_start", "turn_end", "inbound", "outbound"],
//!     "channels": ["telegram"]
//! }}}}
//! ```
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
//! Plugin stderr is kept in a small ring buffer for diagnostics and never reaches
//! the model. Unknown `ark/*` methods from a plugin get JSON-RPC -32601.

use crate::bridge::bridge_tools;
use crate::mcp::Client;
use crate::{McpServerConfig, Secrets};
use ark_core::{Cancel, Tool};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HOOK_TIMEOUT: Duration = Duration::from_secs(5);

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
    inbound: Mutex<Option<Receiver<(String, Value)>>>,
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
        client.on_notification(Arc::new(move |m: &str, p: &Value| {
            if m == "ark/channel.inbound" {
                if let (Some(ch), Some(msg)) = (p.get("channel").and_then(Value::as_str), p.get("message")) {
                    let _ = tx.lock().unwrap().send((ch.to_string(), msg.clone()));
                }
            }
        }));
        let init = client.info()?;
        let ark = init.pointer("/capabilities/experimental/ark");
        Ok(PluginHost {
            name: name.into(),
            hooks: strings(ark.and_then(|a| a.get("hooks"))),
            channels: strings(ark.and_then(|a| a.get("channels"))),
            client,
            inbound: Mutex::new(Some(rx)),
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
}
