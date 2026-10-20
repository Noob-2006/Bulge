//! Tool-call scheduling within one step.
//! MARK: M16 — transcribed by dsh; see marks/M16-tool-schedule.md.

use std::future::Future;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// One tool call requested by the model in this step, in model order.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedCall {
    pub call_id: String,
    pub name: String,
    /// Raw JSON text as produced by the model.
    pub raw_arguments: String,
    /// May run concurrently with adjacent concurrency-safe calls.
    pub concurrency_safe: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallOutcome {
    Ok(Value),
    /// The tool ran (or tried to) and failed; shown to the model as an error.
    Err { code: String, message: String },
    /// Arguments were not a JSON object; the tool was not run.
    InvalidArguments(String),
    /// Not started because the step was cancelled.
    Skipped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub call_id: String,
    pub outcome: CallOutcome,
}

/// Run `calls` and return exactly one result per call, in the original order.
///
/// Grouping: a maximal run of consecutive concurrency-safe calls executes
/// concurrently (at most `max_parallel` in flight); any other call is an
/// exclusive barrier that runs alone. Groups run in order. Arguments are
/// parsed first; a call with invalid arguments gets `InvalidArguments` and is
/// never executed. Once `cancel` fires, calls not yet started get `Skipped`;
/// calls already running are awaited (the executor sees the token).
///
/// `on_start` is invoked right before each call executes (the caller logs the
/// write-ahead `ToolClaimed` there); it is never invoked for invalid or
/// skipped calls.
pub async fn run_tool_calls<E, Fut, S>(
    calls: Vec<PlannedCall>,
    max_parallel: usize,
    cancel: &CancellationToken,
    on_start: S,
    execute: E,
) -> Vec<CallResult>
where
    E: Fn(PlannedCall, serde_json::Map<String, Value>, CancellationToken) -> Fut,
    Fut: Future<Output = CallOutcome>,
    S: FnMut(&PlannedCall, &serde_json::Map<String, Value>),
{
    let _ = (calls, max_parallel, cancel, on_start, execute);
    todo!("M16")
}

pub const DEFAULT_MAX_PARALLEL: usize = 10;
