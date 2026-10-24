//! What the driver hands to the host: delegation, recall, host tools,
//! skills, the org status report and role proposals.

use futures::future::LocalBoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// One `delegate` tool call, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateRequest {
    pub goal: String,
    pub context: Option<String>,
    /// Role from the organization's role library; `None` lets the handler pick its default.
    pub role: Option<String>,
    /// Model the head named for this ticket; `None` lets the handler choose.
    pub model: Option<String>,
    /// Acceptance criteria the deliverable must meet (may be empty).
    pub acceptance: Vec<String>,
}

/// Runs a delegated sub-task on behalf of the driver and returns a structured
/// report of what the child did.
///
/// The future is `!Send` on purpose: the implementor runs a nested driver, which
/// (like this one) schedules tool calls on the current thread. The handler object
/// itself is `Send + Sync` so it can live in the `Arc`-shared [`Driver`].
pub trait DelegateHandler: Send + Sync {
    fn run<'a>(&'a self, request: DelegateRequest, cancel: CancellationToken) -> LocalBoxFuture<'a, Result<DelegateReport, String>>;
}

/// What a finished sub-agent reports back to its parent (sent to the model as JSON).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DelegateReport {
    /// The child job's final status, e.g. "succeeded", "incomplete", "failed", "cancelled".
    pub status: String,
    /// Why the child's loop ended, e.g. "stopped", "budget_exhausted", "stuck".
    pub outcome: String,
    /// The role the child ran as.
    pub role: String,
    /// The board ticket id for this delegation.
    pub ticket: String,
    /// The child's final answer, possibly shortened (see `truncated`).
    pub summary: String,
    /// True when `summary` was shortened to fit; the full text stays in the child's job log.
    pub truncated: bool,
    /// Tokens the child spent (already charged to the parent's budget).
    pub tokens: u64,
    pub steps: u64,
    /// The child's job id (its full transcript is stored under that id).
    pub job_id: String,
    /// Workspace paths the child changed in its private VM slot.
    pub changed: Vec<String>,
    /// Paths the child's changes were merged back into the main workspace.
    pub merged: Vec<String>,
    /// Changes not applied because the main workspace moved, as `"{path}: {reason}"`.
    pub conflicts: Vec<String>,
    /// Whether an independent reviewer checked the work before any merge.
    pub reviewed: bool,
    /// The final review verdict; `None` when the work was not reviewed or no verdict was produced.
    pub accepted: Option<bool>,
    /// The last reviewer feedback (empty when there was none).
    pub feedback: String,
    /// Number of worker runs for this ticket, including reworks.
    pub attempts: u32,
    /// Models the worker ran with, in order.
    pub models: Vec<String>,
}

/// Searches the agent's own past jobs and returns a short, model-ready digest.
/// Pure host-side (file search), so it is synchronous.
pub trait RecallHandler: Send + Sync {
    fn recall(&self, query: &str, limit: usize) -> String;
}

/// A tool that runs on the host, synchronously, outside the VM (e.g. search
/// over data the host keeps). Registered with [`Driver::with_host_tool`];
/// its schema must also be in the tool list.
///
/// Host tools are not put through the guard or the reviewer: they are the
/// host's own code, written to touch only what they were built for (read a
/// chat archive, …). A host tool that changes anything outside bulge's own
/// data must do its own checking.
pub trait HostTool: Send + Sync {
    fn name(&self) -> &str;
    /// Run with the call's JSON arguments; the value goes back to the model.
    fn call(&self, arguments: &Value) -> Result<Value, String>;
}

/// Loads one skill's steps for the `skill` tool and records the use (so the
/// skill lifecycle sees which skills earn their place). Host-side, synchronous.
pub trait SkillHandler: Send + Sync {
    fn load(&self, name: &str) -> Result<String, String>;
}

/// Produces the organization's situation report for the `org_status` tool
/// (model-free, synchronous).
pub trait OrgStatusHandler: Send + Sync {
    fn status(&self) -> String;
}

/// Handles a `propose_role` tool call: validates and audits a proposed role,
/// then installs it on trial if both pass. Async because the audit runs an
/// independent agent; the future is `!Send` for the same reason as
/// [`DelegateHandler`].
pub trait ProposeRoleHandler: Send + Sync {
    fn propose<'a>(
        &'a self,
        charter: String,
        reason: String,
        cancel: CancellationToken,
    ) -> LocalBoxFuture<'a, Result<Value, String>>;
}
