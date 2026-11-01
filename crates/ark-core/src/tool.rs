//! Interface: tools. Every tool declares the concrete effects of a call so the two
//! gates can judge it without knowing the tool.

use crate::cancel::Cancel;
use crate::types::ToolSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Read { path: PathBuf },
    Write { path: PathBuf },
    /// A shell command line, judged by the privilege and egress gates.
    Exec { command: String },
    /// Data leaving the machine over the network.
    Net { dest: String, payload: String },
    /// Message to a human channel.
    Send { channel: String, payload: String },
    /// Spawning another agent (budget accounting only).
    Spawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// May run concurrently with other parallel-safe calls in the same step.
    #[serde(default)]
    pub parallel_safe: bool,
    /// Safe to re-run after a crash between `called` and `settled`.
    #[serde(default)]
    pub idempotent: bool,
    /// Pinned tools ship their full schema every request; others are reached
    /// through `tool_describe` + `tool_call` (progressive disclosure).
    #[serde(default)]
    pub pinned: bool,
}

impl ToolSpec {
    pub fn schema(&self) -> ToolSchema {
        ToolSchema { name: self.name.clone(), description: self.description.clone(), input_schema: self.input_schema.clone() }
    }
    /// First sentence of the description for the tool index.
    pub fn summary(&self) -> &str {
        let d = self.description.trim();
        let end = d.find(['\n', '。']).or_else(|| d.find(". ").map(|i| i + 1)).unwrap_or(d.len());
        &d[..end]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
}

impl ToolOutput {
    pub fn ok(s: impl Into<String>) -> Self {
        ToolOutput { content: s.into(), is_error: false }
    }
    pub fn err(s: impl Into<String>) -> Self {
        ToolOutput { content: s.into(), is_error: true }
    }
}

/// Services the kernel offers to a running tool.
pub trait ToolHost: Send + Sync {
    /// Run a sub-agent to completion and return its final answer.
    fn spawn_agent(&self, req: SpawnRequest, cancel: &Cancel) -> Result<String, String>;
    /// Ask the human a question (may fail in headless mode).
    fn ask_user(&self, question: &str) -> Result<String, String>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub task: String,
    #[serde(default)]
    pub model: Option<String>,
    /// Fork: seed the child with the parent's conversation.
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct ToolCtx {
    pub workspace: PathBuf,
    pub session_id: String,
    /// Where large outputs are spilled.
    pub artifacts: PathBuf,
    /// Arkhome (~/.local/share/ark) for memory files etc.
    pub home: PathBuf,
    pub cancel: Cancel,
    pub host: Arc<dyn ToolHost>,
    /// Secret values substituted for `{{secret:NAME}}` at execution time.
    pub secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl ToolCtx {
    /// Resolve a model-supplied path against the workspace.
    pub fn resolve(&self, p: &str) -> PathBuf {
        let p = expand_home(p);
        if p.is_absolute() {
            p
        } else {
            self.workspace.join(p)
        }
    }
}

pub fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return Path::new(&h).join(rest);
        }
    }
    PathBuf::from(p)
}

pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    /// Concrete effects of this particular call (judged by the gates before running).
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect>;
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput;
}

/// Helpers for tool implementations.
pub fn arg_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing string argument `{k}`"))
}
pub fn arg_opt_str<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}
pub fn arg_opt_u64(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(|x| x.as_u64())
}
pub fn arg_opt_bool(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(|x| x.as_bool())
}
