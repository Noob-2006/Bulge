//! Job event vocabulary. Invariants:
//! - Everything the model sees is a `Message` event (model-visible ⟺ logged).
//! - A tool call is `ToolClaimed` *before* it executes and `ToolCompleted`
//!   after, so a crash between the two is detectable on resume.

use std::path::PathBuf;

use bulge_llm::{Message, TokenUsage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FORMAT: &str = "bulge-job";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    /// Approve the plan and every write-back to the host.
    Collaborative,
    /// Approve only the final diff; high-risk gates may still interrupt.
    #[default]
    Autonomous,
    /// Low-risk diffs apply automatically (snapshot kept); high risk still asks.
    FullAuto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub max_steps: u64,
    pub max_tokens: u64,
    pub max_wall_secs: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self { max_steps: 200, max_tokens: 2_000_000, max_wall_secs: 4 * 60 * 60 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub backend: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    pub id: String,
    pub title: String,
    pub goal: String,
    pub workspace: PathBuf,
    pub autonomy: Autonomy,
    pub budget: Budget,
    pub model: ModelRef,
}

/// What the job must produce, written by the model at the start and checked
/// by the completion gate.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Contract {
    pub deliverables: Vec<Deliverable>,
    pub acceptance: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deliverable {
    /// Workspace-relative path.
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Pending,
    InProgress,
    Done,
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanItem {
    pub text: String,
    pub status: PlanStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    /// Waiting for a human decision (approval, clarification).
    Paused,
    Succeeded,
    /// Ended with the contract not fully met; summary says what is missing.
    Incomplete,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Incomplete | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobEvent {
    Created { spec: JobSpec },
    Contract { contract: Contract },
    /// Full replacement of the plan.
    Plan { items: Vec<PlanItem> },
    StepStarted { step: u64 },
    Message { message: Message },
    ToolClaimed { call_id: String, name: String, arguments: Value },
    ToolCompleted { call_id: String, ok: bool, result: Value },
    Usage { model: String, usage: TokenUsage },
    ApprovalAsked { id: String, kind: String, detail: Value },
    ApprovalDecided { id: String, approved: bool, note: Option<String> },
    NetDomain { domain: String, addrs: Vec<String>, decision: String },
    BudgetWarning { kind: String, used: u64, limit: u64 },
    VmStarted { runtime_dir: PathBuf },
    VmStopped { reason: String },
    /// Written on resume for calls that were claimed but never completed.
    Recovered { interrupted_calls: Vec<String> },
    StatusChanged { status: JobStatus, summary: Option<String> },
    /// A context checkpoint: messages before `kept_from` are replaced, for
    /// request-building, by one summary. The full history stays in the log.
    Compacted { kept_from: usize, summary: String },
    /// A request got materially fewer prefix-cache hits than its predecessor's
    /// prompt size: `expected` tokens should have hit, `cached` did. `cause` is a
    /// tag (`system_changed`, `tools_changed`, `pruned`, `message_rewritten`,
    /// `messages_dropped`, `provider`), `detail` a one-line explanation.
    CacheBreak { expected: u64, cached: u64, cause: String, detail: String },
}

/// One log record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub seq: u64,
    pub at_ms: u64,
    #[serde(flatten)]
    pub event: JobEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: String,
    pub version: u32,
    pub id: String,
    pub title: String,
    pub created_ms: u64,
}
