//! The session event log schema. The log is the single source of truth: every
//! byte the model sees must be reconstructible from these events.

use ark_core::{Block, Message, SystemSegment, Usage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const LOG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Unix millis.
    pub ts: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// First event of every session.
    Header {
        version: u32,
        session_id: String,
        workspace: String,
        model: String,
        #[serde(default)]
        parent: Option<String>,
        #[serde(default)]
        title: Option<String>,
    },
    /// Frozen system prompt segments; a new event replaces the previous one.
    System { segments: Vec<SystemSegment> },
    /// Queued input; becomes a user message when a turn consumes it.
    Inbox {
        id: String,
        source: String,
        text: String,
        /// Extra blocks (images) that go into the user message with `text`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<Block>,
    },
    /// Message added to the conversation.
    Message {
        message: Message,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<Usage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        /// Inbox id this user message consumed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inbox: Option<String>,
    },
    /// Write-ahead record: a tool call is about to execute.
    ToolCalled { tool_use_id: String, name: String, input: Value, idempotency_key: String },
    /// The tool call finished (or was resolved during recovery).
    ToolSettled {
        tool_use_id: String,
        is_error: bool,
        bytes: usize,
        #[serde(default)]
        artifact: Option<String>,
        /// MCP Apps view for UIs (`{server, tool, uri, html, csp, toolInput, toolResult}`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui_resource: Option<Value>,
    },
    Gate { tool_use_id: String, gate: String, verdict: String, reason: String },
    /// Older history replaced by a summary; messages with seq < `upto_seq` are dropped.
    Compaction { upto_seq: u64, summary: String, #[serde(default)] pruned: Vec<String>, tokens_before: u64 },
    /// Tool results whose content was replaced by a stub to save tokens.
    Prune { tool_use_ids: Vec<String> },
    TurnStart { turn: u64 },
    TurnEnd { turn: u64, reason: String, usage: Usage },
    Notice { level: String, text: String },
    Error { message: String },
    Model { model: String },
    /// Reasoning effort for later requests ("off", "low", "medium", "high"; "" = provider default).
    Thinking { level: String },
    /// Session renamed (overrides the header's title).
    Title { title: String },
}

impl Event {
    pub fn is_message(&self) -> bool {
        matches!(self.kind, EventKind::Message { .. })
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
