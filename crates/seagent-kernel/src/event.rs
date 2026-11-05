//! The session event log schema. The log is the single source of truth: every
//! byte the model sees must be reconstructible from these events.

use seagent_core::{Block, Message, SystemSegment, Usage};
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
    /// The named agent this session runs as (multi-agent) and the user it belongs to.
    Agent {
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// Tool policy for this session (sub-agent toolsets, agent tool lists): `allow` = only these
    /// (None = all), `deny` = never these. A later event replaces an earlier one.
    Tools {
        #[serde(default)]
        allow: Option<Vec<String>>,
        #[serde(default)]
        deny: Vec<String>,
    },
    /// Conversation rewind (`/undo`, `/retry`): messages with `from_seq <= seq < this event` are gone.
    Rewind { from_seq: u64, turns: u64 },
    /// Session settings (`sessions` tool / CLI): only the fields present change.
    Meta {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pinned: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        archived: Option<bool>,
        /// Sidebar group; "" clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
        /// Short status line; "" clears it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    /// The final answer must be submitted through `structured_output` and validate against this.
    OutputSchema { schema: Value },
    /// A validated `structured_output` submission.
    Structured { value: Value },
    /// Workspace checkpoint taken at the start of a turn (lets a rewind restore files too).
    Checkpoint { id: String, turn: u64 },
    /// Queued inbox entries dropped without running (`/discard`, `/queue rm`).
    Discard { inbox: Vec<String> },
    /// The session moved to another workspace (`/worktree new|exit`): later tool calls run there.
    Workspace { path: String },
    /// Fast mode / service tier for later requests ("" = config default, "normal", "fast",
    /// "ultrafast", "flex", "auto", "cold").
    Fast { tier: String },
    /// Usage of an auxiliary call made for this session (compaction, review, sampling…).
    AuxUsage { task: String, model: String, usage: Usage },
}

impl Event {
    pub fn is_message(&self) -> bool {
        matches!(self.kind, EventKind::Message { .. })
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
