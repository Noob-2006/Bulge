//! How a driver is configured (guard, context, completion gate, sampling)
//! and how a loop ends.

use std::sync::{Arc, Mutex};
use bulge_llm::{ReasoningEffort, ToolSchema};
use crate::cache_watch::CacheWatch;
use crate::context::PruneConfig;

/// Steps with a non-empty plan and no item reaching `done` before the driver
/// nudges the model to make progress or re-plan.
pub(crate) const PLAN_STALL_THRESHOLD: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOutcome {
    /// The model stopped calling tools and the completion gate accepted the work
    /// (recorded Succeeded). Without a gate, any stop ends here.
    Stopped,
    BudgetExhausted,
    Cancelled,
    Failed,
    /// A runaway loop was detected and the job was stopped (recorded Incomplete).
    Stuck,
    /// The completion gate kept failing; the job stopped with work unfinished
    /// (recorded Incomplete, with the outstanding items in the summary).
    Incomplete,
}

/// Completion-gate configuration enabled by `Driver::with_completion_gate`.
#[derive(Debug, Clone)]
pub struct CompletionConfig {
    /// Run the model self-review (SELF_REVIEW_CRITERIA) when it stops.
    pub self_review: bool,
    /// Failed-gate retries before the job is accepted as Incomplete.
    pub max_attempts: u32,
}

impl Default for CompletionConfig {
    fn default() -> Self {
        Self { self_review: true, max_attempts: 2 }
    }
}

/// Whether the completion gate accepted the stop or wants another step.
pub(crate) enum GateDecision {
    Done(LoopOutcome),
    Continue,
}

/// Guard configuration enabled by `Driver::with_guard`.
#[derive(Clone)]
pub struct GuardConfig {
    pub rules: bulge_guard::Ruleset,
    pub autonomy: bulge_guard::Autonomy,
    pub loop_detection: bool,
}

/// Context-window limits for pruning and compaction. The window is measured in
/// the same heuristic tokens `context::estimate_tokens` produces.
#[derive(Debug, Clone, Copy)]
pub struct ContextConfig {
    /// The model's usable context window, in estimated tokens.
    pub window: u64,
    /// Tokens held back for the reply and tool schemas when deciding to compact.
    pub reserve: u64,
    /// Fraction of the window kept verbatim after a compaction.
    pub retain_ratio: f64,
    /// Tail messages pruning must never touch.
    pub keep_recent: usize,
    pub prune: PruneConfig,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self { window: 120_000, reserve: 8_192, retain_ratio: 0.5, keep_recent: 6, prune: PruneConfig::default() }
    }
}

/// Sampling controls threaded into every *agent* model call (the step loop and
/// self-review). `None` fields mean "let the provider decide" — its own default.
/// Internal calls (compaction, memory) are left at provider defaults on purpose.
#[derive(Debug, Clone, Default)]
pub struct Sampling {
    pub temperature: Option<f32>,
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Per-call output cap. `None` lets the backend apply its model default.
    pub max_tokens: Option<u32>,
}

/// Everything that determines a loop request's leading bytes. Side calls built
/// from it (see [`side_request`]) reuse the provider's cached prefix.
#[derive(Debug, Clone)]
pub struct RequestPrefix {
    pub system_prompt: String,
    pub tools: Vec<ToolSchema>,
    pub context: ContextConfig,
    /// The conversation's cache-break watcher, shared with the driver so side
    /// calls are compared against the loop's last request.
    pub cache: Arc<Mutex<CacheWatch>>,
}
