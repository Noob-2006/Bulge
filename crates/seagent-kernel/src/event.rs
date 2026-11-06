//! The session event log schema. The log is the single source of truth: every
//! byte the model sees must be reconstructible from these events.

use seagent_core::{Block, Message, ModelRequest, SystemSegment, Usage};
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
    /// A system-prompt change delivered after the cached history (providers/routes that accept
    /// mid-conversation system updates). The projection appends it as a message at this point
    /// instead of rewriting the `System` head, so the earlier request stays a byte prefix.
    SystemDelta { text: String },
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
    /// Projection hint: do not merge the next message into the previous same-role one.
    /// Used by fork children so their first task stays a separate user message and the
    /// parent's serialized request remains an exact byte prefix.
    MessageBoundary,
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
    /// One model step: time to first token, model vs tool time, and this step's
    /// usage (cache hit rate comes from `cache_read_tokens`). Written after the
    /// step's tools settle, so the next request's prefix is unchanged.
    Step {
        turn: u64,
        step: u64,
        model: String,
        #[serde(default)]
        ttft_ms: u64,
        #[serde(default)]
        model_ms: u64,
        #[serde(default)]
        tool_ms: u64,
        #[serde(default)]
        tool_calls: u64,
        usage: Usage,
    },
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
    /// Execution-time-only tool restrictions. Unlike [`EventKind::Tools`] this does not
    /// change the request's tool list, so a fork child keeps the parent's tool prefix
    /// byte for byte while disallowed calls are refused when the model makes them.
    ToolGuard {
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
    /// The exact envelope sent to a provider (after send-time trimming, image handling, thinking
    /// and middleware). Durable so a past request can be replayed byte for byte when debugging a
    /// cache miss; `purpose` distinguishes conversation calls from compaction.
    Request { purpose: String, request: ModelRequest },
    /// A refused turn removed from the model context (kept in the log and the transcript):
    /// messages with `from_seq <= seq <= upto_seq` are skipped when projecting a request.
    TurnDropped { from_seq: u64, upto_seq: u64, reason: String },
}

impl Event {
    pub fn is_message(&self) -> bool {
        matches!(self.kind, EventKind::Message { .. })
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
