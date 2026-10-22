//! The step loop. Each step is one model call continued from the job's logged
//! history; tool calls are dispatched (into the VM), and every model-visible
//! message and every claim/completion is appended to the job log before the
//! loop moves on, so a crash is always recoverable.
//!
//! Scope note (C2): "the model stopped calling tools" ends the loop as
//! `Stopped` and is recorded as `Succeeded`. The real completion gate
//! (verify the deliverable contract before declaring success) arrives in C5
//! and will replace that final transition.

use std::sync::{Arc, Mutex};

use bulge_llm::assemble::{Assembled, Assembler};
use bulge_llm::{ContentBlock, FinishReason, GenerateRequest, LlmBackend, LlmError, Message, Purpose, ReasoningEffort, Role, TokenUsage, ToolSchema};
use crate::cache_watch::{self, CacheBreak, CacheWatch, Fingerprint};
use bulge_store::{JobEvent, JobHandle, JobStatus, PlanItem, PlanStatus, StoreError};
use futures::StreamExt;
use futures::future::LocalBoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::budget::{BudgetState, BudgetTracker};
use crate::complete::{self, Check, GateReport};
use crate::context::{self, PruneConfig};
use crate::dispatch::{DELEGATE_TOOL, ORG_STATUS_TOOL, PLAN_TOOL, PROPOSE_ROLE_TOOL, RECALL_TOOL, ToolCall, ToolDispatcher};
use crate::schedule::{CallOutcome, PlannedCall, run_tool_calls};

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

/// Steps with a non-empty plan and no item reaching `done` before the driver
/// nudges the model to make progress or re-plan.
const PLAN_STALL_THRESHOLD: u64 = 8;

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
enum GateDecision {
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

/// The job event for a detected cache break.
pub fn cache_break_event(found: &CacheBreak) -> JobEvent {
    JobEvent::CacheBreak { expected: found.expected, cached: found.cached, cause: found.cause.tag().to_string(), detail: found.cause.describe() }
}

/// Record one call against `cache`; the event to log if it broke the prefix.
pub fn watch_call(cache: &Mutex<CacheWatch>, print: Fingerprint, usage: &TokenUsage) -> Option<JobEvent> {
    let found = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).record(print, usage)?;
    Some(cache_break_event(&found))
}

/// The messages a loop request carries: the system prompt, the latest compaction
/// summary (if any) in place of the messages it replaced, then the live history
/// tail — pruned so long old tool results are trimmed.
fn request_messages(system_prompt: &str, context: &ContextConfig, job: &JobHandle) -> Vec<Message> {
    let state = job.state();
    let mut messages = Vec::with_capacity(state.history.len() + 2);
    messages.push(Message::text(Role::System, system_prompt.to_string()));
    let base = match &state.compaction {
        Some(compaction) => {
            messages.push(context::summary_message(&compaction.summary));
            compaction.kept_from.min(state.history.len())
        }
        None => 0,
    };
    messages.extend(state.history[base..].iter().cloned());
    context::prune(&messages, context.window, context.keep_recent, &context.prune)
}

/// A text-only side call over a job (e.g. post-job learning): exactly the loop's
/// request prefix — same system prompt, same tools, same pruned/compacted
/// history — plus `instruction` as the final user message, so only the
/// instruction and the reply are uncached. Send it with [`stream_toolless`].
pub fn side_request(prefix: &RequestPrefix, job: &JobHandle, instruction: &str, purpose: Purpose) -> GenerateRequest {
    let mut messages = request_messages(&prefix.system_prompt, &prefix.context, job);
    messages.push(Message::text(Role::User, instruction.to_string()));
    GenerateRequest {
        model: job.state().spec.model.model.clone(),
        messages,
        tools: prefix.tools.clone(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose,
    }
}

async fn collect(backend: &dyn LlmBackend, request: GenerateRequest, cancel: CancellationToken) -> Assembled {
    let model = request.model.clone();
    let mut stream = backend.stream(request, cancel);
    let mut assembler = Assembler::new();
    while let Some(chunk) = stream.next().await {
        assembler.push(&chunk);
    }
    assembler.finish(&model)
}

/// Send a request that must be answered in text, while keeping its tool list.
///
/// The tool definitions are part of the provider's cached prefix (DeepSeek
/// renders them right after the system prompt), and dropping them — or sending
/// `tool_choice: "none"`, which DeepSeek treats the same way (measured: 0 cache
/// hits) — invalidates everything after the system prompt. So the request goes
/// out byte-identical to a loop request, the instruction says not to call tools,
/// and any tool call the model makes anyway is stripped (it never ran, so it must
/// not reach the log unanswered). Only if nothing but tool calls came back is the
/// request retried without tools; the returned usage covers both attempts.
pub async fn stream_toolless(backend: &dyn LlmBackend, request: GenerateRequest, cancel: CancellationToken) -> Assembled {
    let retry = (!request.tools.is_empty()).then(|| GenerateRequest { tools: Vec::new(), ..request.clone() });
    let mut assembled = collect(backend, request, cancel.clone()).await;
    let before = assembled.message.content.len();
    assembled.message.content.retain(|block| !matches!(block, ContentBlock::ToolCall { .. }));
    if assembled.message.content.len() == before {
        return assembled;
    }
    if assembled.finish == FinishReason::ToolCalls {
        assembled.finish = FinishReason::Stop;
    }
    match retry {
        Some(retry) if assistant_text(&assembled.message).is_none() => {
            let first = assembled.usage;
            let mut second = collect(backend, retry, cancel).await;
            second.usage = first.plus(second.usage);
            second
        }
        _ => assembled,
    }
}

/// Leads the compaction request's final user message (the summarizer now shares
/// the loop's system prompt, so its role is stated here instead).
const COMPACT_INSTRUCTION: &str = "Stop working on the task for a moment: you are compacting this long agent transcript into a briefing that lets the agent continue. Do not call tools.";

pub struct Driver {
    backend: Arc<dyn LlmBackend>,
    dispatcher: Arc<dyn ToolDispatcher>,
    tools: Vec<ToolSchema>,
    system_prompt: String,
    max_parallel: usize,
    guard: Option<GuardConfig>,
    context: ContextConfig,
    completion: Option<CompletionConfig>,
    sampling: Sampling,
    /// When true, a cheap LLM reviewer vets every mutating (barrier) tool call
    /// before it runs; a deny verdict blocks the call. Off by default.
    review: bool,
    /// Handles `delegate` tool calls (runs a sub-agent). `None` → the tool, if the
    /// model calls it at all, is treated as an unknown tool.
    delegate: Option<Arc<dyn DelegateHandler>>,
    /// Handles `recall` tool calls (searches past jobs). `None` → unknown tool.
    recall: Option<Arc<dyn RecallHandler>>,
    /// Handles `org_status` tool calls (model-free situation report). `None` →
    /// unknown tool.
    org_status: Option<Arc<dyn OrgStatusHandler>>,
    /// Handles `propose_role` tool calls (validate, audit, install on trial).
    /// `None` → unknown tool.
    propose_role: Option<Arc<dyn ProposeRoleHandler>>,
    /// The shared budget tree this agent draws from; every recorded token is
    /// charged to it and its exhaustion stops the loop.
    ledger: Option<Arc<crate::ledger::Ledger>>,
    /// Compares each request with the previous one to explain cache misses.
    cache: Arc<Mutex<CacheWatch>>,
}

impl Driver {
    pub fn new(backend: Arc<dyn LlmBackend>, dispatcher: Arc<dyn ToolDispatcher>, tools: Vec<ToolSchema>, system_prompt: String) -> Self {
        Self {
            backend,
            dispatcher,
            tools,
            system_prompt,
            max_parallel: crate::schedule::DEFAULT_MAX_PARALLEL,
            guard: None,
            context: ContextConfig::default(),
            completion: None,
            sampling: Sampling::default(),
            review: false,
            delegate: None,
            recall: None,
            org_status: None,
            propose_role: None,
            ledger: None,
            cache: Arc::new(Mutex::new(CacheWatch::new())),
        }
    }

    /// Enable the LLM review gate: before any mutating tool call runs, a bounded
    /// reviewer model call decides allow/deny; a deny blocks the call and tells the
    /// model why. A second opinion on top of the sandbox, static policy, and hooks.
    pub fn with_review(mut self, review: bool) -> Self {
        self.review = review;
        self
    }

    /// Install a delegation handler so the model's `delegate` tool calls run a
    /// sub-agent (handled here on the host, never sent to the VM).
    pub fn with_delegate(mut self, handler: Arc<dyn DelegateHandler>) -> Self {
        self.delegate = Some(handler);
        self
    }

    /// Install a recall handler so the model's `recall` tool calls search past
    /// jobs (handled here on the host, never sent to the VM).
    pub fn with_recall(mut self, handler: Arc<dyn RecallHandler>) -> Self {
        self.recall = Some(handler);
        self
    }

    /// Install an organization-status handler so the model's `org_status` calls
    /// return a cheap, model-free situation report (handled here on the host,
    /// never sent to the VM).
    pub fn with_org_status(mut self, handler: Arc<dyn OrgStatusHandler>) -> Self {
        self.org_status = Some(handler);
        self
    }

    /// Install a governance handler so the model's `propose_role` calls are
    /// validated, audited, and installed on trial (handled here on the host,
    /// never sent to the VM).
    pub fn with_propose_role(mut self, handler: Arc<dyn ProposeRoleHandler>) -> Self {
        self.propose_role = Some(handler);
        self
    }

    /// Attach this agent's node of a shared budget tree: every recorded token is
    /// charged to the node (and its ancestors), and the tree's exhaustion stops
    /// the loop. Defaults to no ledger (the job budget alone bounds the run).
    pub fn with_ledger(mut self, ledger: Arc<crate::ledger::Ledger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// The shared budget-tree node this driver charges, if one is attached.
    pub fn ledger(&self) -> Option<&Arc<crate::ledger::Ledger>> {
        self.ledger.as_ref()
    }

    /// Thread sampling controls (temperature / reasoning effort / output cap) into
    /// every agent model call. Defaults leave everything to the provider.
    pub fn with_sampling(mut self, sampling: Sampling) -> Self {
        self.sampling = sampling;
        self
    }

    /// Enable the cautious guard: permission rules (deny → the tool is blocked
    /// and the model is told), and runaway-loop detection (critical → stop).
    pub fn with_guard(mut self, guard: GuardConfig) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Override the context-window limits (window size, compaction reserve/ratio,
    /// pruning). Defaults suit a ~128k model.
    pub fn with_context(mut self, context: ContextConfig) -> Self {
        self.context = context;
        self
    }

    /// Enable the completion gate: when the model stops, verify the deliverable
    /// contract in the VM and run a self-review before accepting the job as done.
    /// Without this, any stop is accepted as Succeeded (the C2 behaviour).
    pub fn with_completion_gate(mut self, completion: CompletionConfig) -> Self {
        self.completion = Some(completion);
        self
    }

    /// The set of registered tool names (for unknown-tool loop detection).
    fn tool_names(&self) -> std::collections::HashSet<String> {
        self.tools.iter().map(|t| t.name.clone()).collect()
    }

    pub async fn run(&self, job: &mut JobHandle, cancel: CancellationToken) -> Result<LoopOutcome, StoreError> {
        let spec = job.state().spec.clone();
        let mut budget = BudgetTracker::with_spent(spec.budget.clone(), job.state().steps, job.state().usage.total());
        if let Some(ledger) = &self.ledger {
            budget = budget.with_ledger(ledger.clone());
        }
        let mut wind_down_announced = false;
        // Loop detector is per-run (history restarts on resume).
        let mut detector = self
            .guard
            .as_ref()
            .filter(|g| g.loop_detection)
            .map(|_| bulge_guard::LoopDetector::new());
        let mut warned: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut gate_attempts: u32 = 0;
        // Plan-stall tracking: the step a plan item last reached `done`, and
        // whether the model has already been nudged about the current stall.
        let mut prev_done = plan_done_count(&job.state().plan);
        let mut last_progress_step = job.state().steps;
        let mut stall_warned = false;

        loop {
            if cancel.is_cancelled() {
                return self.finish(job, LoopOutcome::Cancelled, JobStatus::Cancelled, Some("cancelled".into())).await;
            }
            match budget.state() {
                BudgetState::Exhausted => return self.final_step(job, &mut budget).await,
                BudgetState::WindDown if !wind_down_announced => {
                    wind_down_announced = true;
                    let note = "Budget is nearly spent. Stop exploring, finish and write every requested deliverable now, then stop.";
                    job.append(vec![JobEvent::Message { message: Message::text(Role::User, note) }])?;
                }
                _ => {}
            }

            let step = job.state().steps + 1;
            budget.record_step();
            job.append(vec![JobEvent::StepStarted { step }])?;

            // Roll the context forward if it would overflow: summarize the oldest
            // messages into one checkpoint. Best-effort — a failed summary just
            // leaves the history as-is (pruning still caps request size).
            if let Some(usage) = self.maybe_compact(job, &cancel).await? {
                budget.record_tokens(usage.total());
            }

            let assembled = match self.one_call(job, false, cancel.clone()).await? {
                Ok(assembled) => assembled,
                Err(outcome) => return Ok(outcome),
            };
            budget.record_tokens(assembled.usage.total());

            let tool_calls = extract_tool_calls(&assembled.message);
            if tool_calls.is_empty() {
                let summary = assistant_text(&assembled.message);
                match self.completion_gate(job, summary, &cancel, &mut gate_attempts, &mut budget).await? {
                    GateDecision::Done(outcome) => return Ok(outcome),
                    GateDecision::Continue => continue,
                }
            }

            if let Some(outcome) = self.dispatch_calls(job, tool_calls, &cancel, &mut detector, &mut warned).await? {
                return Ok(outcome);
            }

            // Plan-stall nudge: if the model keeps a plan but no item has reached
            // `done` for a while (and it is not already settled), remind it once.
            let plan = &job.state().plan;
            if !plan.is_empty() && !plan_settled(plan) {
                let done = plan_done_count(plan);
                if done > prev_done {
                    prev_done = done;
                    last_progress_step = step;
                    stall_warned = false;
                } else if !stall_warned && complete::plan_stalled(step.saturating_sub(last_progress_step), PLAN_STALL_THRESHOLD) {
                    stall_warned = true;
                    let note = "You have made no plan progress for several steps. Re-check your plan: finish or drop the stuck item, or change approach — do not keep repeating the same step.";
                    job.append(vec![JobEvent::Message { message: Message::text(Role::User, note) }])?;
                }
            }
        }
    }

    /// One model call: build the request from history, stream, assemble, and log
    /// the assistant message + usage. `Err(outcome)` means the loop must end.
    async fn one_call(
        &self,
        job: &mut JobHandle,
        toolless: bool,
        cancel: CancellationToken,
    ) -> Result<Result<bulge_llm::assemble::Assembled, LoopOutcome>, StoreError> {
        let model = job.state().spec.model.model.clone();
        let messages = self.build_request_messages(job);
        let request = GenerateRequest {
            model: model.clone(),
            messages,
            // Always the full tool list, even for a text-only turn: the tool
            // definitions are part of the provider's cached prefix.
            tools: self.tools.clone(),
            max_tokens: self.sampling.max_tokens,
            temperature: self.sampling.temperature,
            stop: Vec::new(),
            reasoning_effort: self.sampling.reasoning_effort,
            purpose: Purpose::Conversation,
        };

        let print = cache_watch::fingerprint(&request);
        let assembled = if toolless {
            stream_toolless(self.backend.as_ref(), request, cancel).await
        } else {
            collect(self.backend.as_ref(), request, cancel).await
        };

        let mut events = vec![
            JobEvent::Message { message: assembled.message.clone() },
            JobEvent::Usage { model, usage: assembled.usage },
        ];
        events.extend(watch_call(&self.cache, print, &assembled.usage));
        job.append(events)?;

        match &assembled.finish {
            FinishReason::Error(error) => {
                let outcome = self.finish(job, LoopOutcome::Failed, JobStatus::Failed, Some(error_summary(error))).await?;
                Ok(Err(outcome))
            }
            FinishReason::Aborted => {
                let outcome = self.finish(job, LoopOutcome::Cancelled, JobStatus::Cancelled, Some("model stream aborted".into())).await?;
                Ok(Err(outcome))
            }
            _ => Ok(Ok(assembled)),
        }
    }

    /// Build the request messages from logged state: the system prompt, then the
    /// latest compaction summary (if any) in place of the messages it replaced,
    /// then the live history tail — finally pruned so long old tool results are
    /// trimmed. The system prefix stays byte-stable for the provider's cache.
    fn build_request_messages(&self, job: &JobHandle) -> Vec<Message> {
        request_messages(&self.system_prompt, &self.context, job)
    }

    /// The prefix this driver sends (system prompt, tools, context policy), for
    /// side calls made after the loop — see [`side_request`].
    pub fn prefix(&self) -> RequestPrefix {
        RequestPrefix { system_prompt: self.system_prompt.clone(), tools: self.tools.clone(), context: self.context, cache: self.cache.clone() }
    }

    /// When the live context would overflow the window, summarize its oldest span
    /// into one checkpoint and log a `Compacted` event. Returns the summary call's
    /// token usage (also logged as a `Usage` event) so the caller can charge the
    /// budget. Returns `None` when no compaction was needed or the summary failed.
    async fn maybe_compact(&self, job: &mut JobHandle, cancel: &CancellationToken) -> Result<Option<TokenUsage>, StoreError> {
        let model = job.state().spec.model.model.clone();

        // The view the model currently sees: system, the existing summary (if
        // any), then the live tail. Compaction ranges are indices into this view.
        // This is exactly the request the loop sends (pruning keeps the message
        // count), so the summary call reuses the provider's cached prefix.
        let view = self.build_request_messages(job);
        let (base, tail_start) = match &job.state().compaction {
            Some(compaction) => (compaction.kept_from.min(job.state().history.len()), 2),
            None => (0, 1),
        };

        let Some(range) = context::compaction_range(&view, self.context.window, self.context.reserve, self.context.retain_ratio) else {
            return Ok(None);
        };

        // `range.start` is the first message after the system prompt, so
        // system + this span is a byte-exact prefix of the last loop request.
        let to_summarize: Vec<Message> = view[range.start..range.kept_from].to_vec();
        let Some((summary, usage, broke)) = self.summarize(to_summarize, &model, cancel.clone()).await else {
            return Ok(None);
        };

        // Map the view index back to an absolute index into the stored history.
        let new_kept_from = base + range.kept_from.saturating_sub(tail_start);
        let mut events = vec![JobEvent::Compacted { kept_from: new_kept_from, summary }, JobEvent::Usage { model, usage }];
        events.extend(broke);
        job.append(events)?;
        Ok(Some(usage))
    }

    /// Run one non-tool model call that condenses `slice` into a briefing using
    /// the fixed summary template. Returns the summary text and its token usage,
    /// or `None` if the model errored or produced no text.
    async fn summarize(&self, slice: Vec<Message>, model: &str, cancel: CancellationToken) -> Option<(String, TokenUsage, Option<JobEvent>)> {
        let mut messages = Vec::with_capacity(slice.len() + 2);
        // Same system prompt and tools as the loop (calls forbidden) so the
        // provider's cached prefix covers the whole span being summarized.
        messages.push(Message::text(Role::System, self.system_prompt.clone()));
        messages.extend(slice);
        messages.push(Message::text(Role::User, format!("{COMPACT_INSTRUCTION}\n\n{}", context::SUMMARY_TEMPLATE)));
        let request = GenerateRequest {
            model: model.to_string(),
            messages,
            tools: self.tools.clone(),
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Compaction,
        };
        let print = cache_watch::fingerprint(&request);
        let assembled = stream_toolless(self.backend.as_ref(), request, cancel).await;
        let broke = watch_call(&self.cache, print, &assembled.usage);
        if matches!(assembled.finish, FinishReason::Error(_) | FinishReason::Aborted) {
            return None;
        }
        let summary = assistant_text(&assembled.message)?;
        if summary.trim().is_empty() {
            return None;
        }
        Some((summary, assembled.usage, broke))
    }

    /// Claim calls, consult the guard, run the allowed ones, and log results.
    /// Returns `Some(outcome)` when a critical loop requires stopping the job.
    async fn dispatch_calls(
        &self,
        job: &mut JobHandle,
        calls: Vec<ExtractedCall>,
        cancel: &CancellationToken,
        detector: &mut Option<bulge_guard::LoopDetector>,
        warned: &mut std::collections::HashSet<String>,
    ) -> Result<Option<LoopOutcome>, StoreError> {
        // Loop detection (before anything runs): critical → stop; warning → remind once.
        if let Some(detector) = detector.as_ref() {
            let known = self.tool_names();
            for call in &calls {
                let args = parse_lenient(&call.arguments);
                if let Some(verdict) = detector.check(&call.name, &args, !known.contains(&call.name)) {
                    match verdict.level {
                        bulge_guard::Level::Critical => {
                            job.append(vec![JobEvent::Message { message: Message::text(Role::User, verdict.message.clone()) }])?;
                            return Ok(Some(self.finish(job, LoopOutcome::Stuck, JobStatus::Incomplete, Some(verdict.message)).await?));
                        }
                        bulge_guard::Level::Warning => {
                            let key = format!("{:?}:{}", verdict.detector, call.name);
                            if warned.insert(key) {
                                job.append(vec![JobEvent::Message { message: Message::text(Role::User, verdict.message) }])?;
                            }
                        }
                    }
                }
            }
        }

        // Host-side tools are handled here, never sent to the VM. All `delegate`
        // calls of this turn run concurrently on this thread (their futures are
        // `!Send`, so concurrency is cooperative, not multi-threaded): one future
        // per call, then join them all before the remaining calls are dispatched.
        let mut host: std::collections::HashMap<String, CallOutcome> = std::collections::HashMap::new();
        if let Some(handler) = self.delegate.clone() {
            let mut pending: Vec<(String, LocalBoxFuture<'_, CallOutcome>)> = Vec::new();
            for call in &calls {
                if call.name != DELEGATE_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let goal = args.get("goal").and_then(Value::as_str).unwrap_or("").trim().to_string();
                if goal.is_empty() {
                    pending.push((
                        call.id.clone(),
                        Box::pin(async {
                            CallOutcome::Err { code: "BAD_DELEGATE".into(), message: "delegate needs a non-empty `goal`".into() }
                        }),
                    ));
                    continue;
                }
                let context = args.get("context").and_then(Value::as_str).map(str::to_string);
                let role = args.get("role").and_then(Value::as_str).map(str::to_string);
                let model = args
                    .get("model")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|model| !model.is_empty())
                    .map(str::to_string);
                let acceptance = match args.get("acceptance") {
                    Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
                    Some(Value::String(one)) => vec![one.clone()],
                    _ => Vec::new(),
                };
                // Cancelling the parent cancels every child.
                let child_cancel = cancel.child_token();
                let handler = handler.clone();
                pending.push((
                    call.id.clone(),
                    Box::pin(async move {
                        match handler.run(DelegateRequest { goal, context, role, model, acceptance }, child_cancel).await {
                            Ok(report) => CallOutcome::Ok(serde_json::to_value(&report).unwrap_or_default()),
                            Err(message) => CallOutcome::Err { code: "DELEGATE_FAILED".into(), message },
                        }
                    }),
                ));
            }
            let ids: Vec<String> = pending.iter().map(|(id, _)| id.clone()).collect();
            let outcomes = futures::future::join_all(pending.into_iter().map(|(_, future)| future)).await;
            for (id, outcome) in ids.into_iter().zip(outcomes) {
                host.insert(id, outcome);
            }
        }
        if let Some(handler) = self.recall.clone() {
            for call in &calls {
                if call.name != RECALL_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let query = args.get("query").and_then(Value::as_str).unwrap_or("").trim().to_string();
                let outcome = if query.is_empty() {
                    CallOutcome::Err { code: "BAD_RECALL".into(), message: "recall needs a non-empty `query`".into() }
                } else {
                    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5).clamp(1, 20) as usize;
                    CallOutcome::Ok(serde_json::json!({ "results": handler.recall(&query, limit) }))
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.org_status.clone() {
            for call in &calls {
                if call.name != ORG_STATUS_TOOL {
                    continue;
                }
                let outcome = CallOutcome::Ok(serde_json::json!({ "report": handler.status() }));
                host.insert(call.id.clone(), outcome);
            }
        }
        if let Some(handler) = self.propose_role.clone() {
            for call in &calls {
                if call.name != PROPOSE_ROLE_TOOL {
                    continue;
                }
                let args = parse_lenient(&call.arguments);
                let charter = args
                    .get("charter")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let reason = args
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let outcome = if charter.is_empty() {
                    CallOutcome::Err {
                        code: "BAD_PROPOSE_ROLE".into(),
                        message: "propose_role needs a non-empty `charter`".into(),
                    }
                } else if reason.is_empty() {
                    CallOutcome::Err {
                        code: "BAD_PROPOSE_ROLE".into(),
                        message: "propose_role needs a non-empty `reason`".into(),
                    }
                } else {
                    let child_cancel = cancel.child_token();
                    match handler.propose(charter, reason, child_cancel).await {
                        Ok(value) => CallOutcome::Ok(value),
                        Err(message) => CallOutcome::Err {
                            code: "PROPOSE_ROLE_FAILED".into(),
                            message,
                        },
                    }
                };
                host.insert(call.id.clone(), outcome);
            }
        }
        let mut plan_update: Option<Vec<PlanItem>> = None;
        for call in &calls {
            if call.name == PLAN_TOOL {
                match parse_plan(&call.arguments) {
                    Ok(items) => {
                        let outcome = CallOutcome::Ok(serde_json::json!({ "ok": true, "items": items.len() }));
                        plan_update = Some(items);
                        host.insert(call.id.clone(), outcome);
                    }
                    Err(message) => {
                        host.insert(call.id.clone(), CallOutcome::Err { code: "BAD_PLAN".into(), message });
                    }
                }
            }
        }

        // Permission: a blocked call is never run; the model is told so it adapts.
        // `Ask` fails closed too — there is no tool approval channel here.
        let mut blocked: std::collections::HashMap<String, PermissionBlock> = calls
            .iter()
            .filter(|c| !host.contains_key(&c.id))
            .filter_map(|c| self.permission_block(c).map(|block| (c.id.clone(), block)))
            .collect();

        // LLM review gate: a second opinion on every mutating (barrier) call that
        // policy did not already block. Runs sequentially before anything executes.
        if self.review {
            for call in &calls {
                if host.contains_key(&call.id) || blocked.contains_key(&call.id) || self.dispatcher.concurrency_safe(&call.name) {
                    continue;
                }
                if let Some(reason) = self.review_denial(job, call, cancel).await {
                    blocked.insert(call.id.clone(), PermissionBlock::Deny(reason));
                }
            }
        }

        let claims = calls
            .iter()
            .map(|c| JobEvent::ToolClaimed { call_id: c.id.clone(), name: c.name.clone(), arguments: parse_lenient(&c.arguments) })
            .collect();
        job.append(claims)?;
        // Every asked call is recorded as awaiting a human before it is failed
        // closed, so the log preserves what the guard wanted to ask.
        let approvals: Vec<JobEvent> = calls
            .iter()
            .filter_map(|call| match blocked.get(&call.id) {
                Some(PermissionBlock::Ask { resource }) => Some(JobEvent::ApprovalAsked {
                    id: call.id.clone(),
                    kind: "tool".into(),
                    detail: serde_json::json!({
                        "tool": call.name,
                        "resource": resource,
                        "reason": "this action requires a human",
                    }),
                }),
                _ => None,
            })
            .collect();
        if !approvals.is_empty() {
            job.append(approvals)?;
        }
        // Record the plan update (if any) between claim and completion.
        if let Some(items) = plan_update {
            job.append(vec![JobEvent::Plan { items }])?;
        }

        let planned: Vec<PlannedCall> = calls
            .iter()
            .filter(|c| !blocked.contains_key(&c.id) && !host.contains_key(&c.id))
            .map(|c| PlannedCall {
                call_id: c.id.clone(),
                name: c.name.clone(),
                raw_arguments: c.arguments.clone(),
                concurrency_safe: self.dispatcher.concurrency_safe(&c.name),
            })
            .collect();

        let dispatcher = self.dispatcher.clone();
        let mut results = run_tool_calls(
            planned,
            self.max_parallel,
            cancel,
            |_, _| {},
            |call, args, token| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.dispatch(ToolCall { name: call.name, arguments: args }, token).await }
            },
        )
        .await;

        // Fold in blocked calls as errors, preserving model order.
        let by_id: std::collections::HashMap<String, CallOutcome> = results.drain(..).map(|r| (r.call_id, r.outcome)).collect();
        let mut events = Vec::with_capacity(calls.len() * 2);
        for call in &calls {
            let outcome = if let Some(outcome) = host.get(&call.id) {
                outcome.clone()
            } else if let Some(block) = blocked.get(&call.id) {
                match block {
                    PermissionBlock::Deny(reason) => CallOutcome::Err { code: "PERMISSION_DENIED".into(), message: reason.clone() },
                    PermissionBlock::Ask { resource } => CallOutcome::Err {
                        code: "REQUIRES_HUMAN".into(),
                        message: format!(
                            "{} on {resource} needs a human; it was not run. Do not retry it or work around it — finish what you can and say in your answer exactly what the human must do.",
                            call.name
                        ),
                    },
                }
            } else {
                by_id.get(&call.id).cloned().unwrap_or(CallOutcome::Skipped)
            };
            if let Some(detector) = detector.as_mut() {
                let ok = matches!(outcome, CallOutcome::Ok(_));
                let result = outcome_value(&outcome);
                detector.observe(bulge_guard::Observation { tool: call.name.clone(), arguments: parse_lenient(&call.arguments), ok, result });
            }
            let (ok, value, text) = render_outcome(outcome);
            events.push(JobEvent::ToolCompleted { call_id: call.id.clone(), ok, result: value });
            events.push(JobEvent::Message { message: Message::tool_result(call.id.clone(), text, !ok) });
        }
        job.append(events)?;
        Ok(None)
    }

    /// If the guard's rules block this call, why. `Ask` is a block: without a
    /// human approval channel the only safe reading of "ask" is "do not run".
    fn permission_block(&self, call: &ExtractedCall) -> Option<PermissionBlock> {
        let guard = self.guard.as_ref()?;
        let resource = call_resource(call);
        match bulge_guard::evaluate(&call.name, &resource, &[&guard.rules]) {
            bulge_guard::Effect::Deny => Some(PermissionBlock::Deny(format!("blocked by policy: {} on {resource}", call.name))),
            bulge_guard::Effect::Ask => Some(PermissionBlock::Ask { resource }),
            bulge_guard::Effect::Allow => None,
        }
    }

    /// A bounded LLM review of one mutating call. Returns `Some(reason)` to block.
    /// The reviewer sees ONLY the proposed call (never prior tool output), so a
    /// prompt-injection in earlier results cannot talk it into approving. Any
    /// error, timeout, or malformed reply fails OPEN (returns `None`) — the review
    /// is a second opinion, not the primary boundary (the sandbox is).
    async fn review_denial(&self, job: &JobHandle, call: &ExtractedCall, cancel: &CancellationToken) -> Option<String> {
        let model = job.state().spec.model.model.clone();
        let proposal = format!("Tool: {}\nArguments: {}", call.name, call.arguments);
        let request = GenerateRequest {
            model: model.clone(),
            messages: vec![
                Message::text(Role::System, complete::REVIEW_POLICY),
                Message::text(Role::User, proposal),
            ],
            tools: Vec::new(),
            max_tokens: Some(200),
            temperature: Some(0.0),
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Memory,
        };
        let mut stream = self.backend.stream(request, cancel.clone());
        let mut assembler = Assembler::new();
        while let Some(chunk) = stream.next().await {
            assembler.push(&chunk);
        }
        let assembled = assembler.finish(&model);
        let text = assistant_text(&assembled.message)?;
        complete::parse_review_denial(&text)
    }

    /// Budget spent: one final tool-less call asking for a summary, then stop Incomplete.
    async fn final_step(&self, job: &mut JobHandle, budget: &mut BudgetTracker) -> Result<LoopOutcome, StoreError> {
        let strained = budget.strained().map_or("budget", |r| match r {
            crate::budget::Resource::Steps => "step",
            crate::budget::Resource::Tokens => "token",
            crate::budget::Resource::WallClock => "time",
        });
        let note = format!(
            "The {strained} budget for this job is spent. Tools are now disabled. Respond with text only: summarize what was accomplished, list what remains unfinished, and recommend next steps."
        );
        job.append(vec![JobEvent::StepStarted { step: job.state().steps + 1 }, JobEvent::Message { message: Message::text(Role::User, note) }])?;
        budget.record_step();

        let assembled = match self.one_call(job, true, CancellationToken::new()).await? {
            Ok(assembled) => assembled,
            Err(outcome) => return Ok(outcome),
        };
        let summary = assistant_text(&assembled.message);
        self.finish(job, LoopOutcome::BudgetExhausted, JobStatus::Incomplete, summary).await
    }

    /// The completion gate (C5). With no gate configured, a stop is accepted as
    /// Succeeded (C2 behaviour). Otherwise verify the contract mechanically and
    /// run a self-review: pass → Succeeded; fail → feed back and continue, or, once
    /// `max_attempts` is spent, stop Incomplete with the outstanding items.
    async fn completion_gate(
        &self,
        job: &mut JobHandle,
        summary: Option<String>,
        cancel: &CancellationToken,
        attempts: &mut u32,
        budget: &mut BudgetTracker,
    ) -> Result<GateDecision, StoreError> {
        let Some(config) = self.completion.clone() else {
            let outcome = self.finish(job, LoopOutcome::Stopped, JobStatus::Succeeded, summary).await?;
            return Ok(GateDecision::Done(outcome));
        };
        *attempts += 1;

        let checks = self.run_contract_checks(job, cancel).await;
        let self_review_passed = if config.self_review {
            self.self_review(job, cancel, budget).await?
        } else {
            None
        };
        let report = GateReport { checks, self_review_passed };

        if report.passed() {
            let outcome = self.finish(job, LoopOutcome::Stopped, JobStatus::Succeeded, summary).await?;
            return Ok(GateDecision::Done(outcome));
        }

        let feedback = report.failure_feedback();
        if *attempts > config.max_attempts {
            let note = format!("{feedback}\n\n(Completion gate still failing after {attempts} attempts; stopping with work unfinished.)");
            let outcome = self.finish(job, LoopOutcome::Incomplete, JobStatus::Incomplete, Some(note)).await?;
            return Ok(GateDecision::Done(outcome));
        }
        job.append(vec![JobEvent::Message { message: Message::text(Role::User, feedback) }])?;
        Ok(GateDecision::Continue)
    }

    /// Mechanical contract checks, run in the VM: each deliverable must be
    /// readable, each acceptance command must exit 0. No contract → no checks.
    async fn run_contract_checks(&self, job: &JobHandle, cancel: &CancellationToken) -> Vec<Check> {
        let Some(contract) = job.state().contract.clone() else {
            return Vec::new();
        };
        let mut checks = Vec::new();
        for deliverable in &contract.deliverables {
            let outcome = self.dispatcher.dispatch(string_call("read", "path", &deliverable.path), cancel.clone()).await;
            let (passed, detail) = match outcome {
                CallOutcome::Ok(_) => (true, "present".to_string()),
                CallOutcome::Err { message, .. } => (false, format!("missing or unreadable: {message}")),
                other => (false, format!("check did not run: {other:?}")),
            };
            checks.push(Check { what: format!("deliverable `{}` exists", deliverable.path), passed, detail });
        }
        for command in &contract.acceptance {
            let outcome = self.dispatcher.dispatch(string_call("exec", "command", command), cancel.clone()).await;
            let (passed, detail) = match outcome {
                CallOutcome::Ok(value) => {
                    let code = value.get("exit_code").and_then(Value::as_i64);
                    if code == Some(0) {
                        (true, "exit 0".to_string())
                    } else {
                        let stderr = value.get("stderr").and_then(Value::as_str).unwrap_or("");
                        (false, format!("exit {code:?}: {}", truncate(stderr.trim(), 300)))
                    }
                }
                CallOutcome::Err { message, .. } => (false, format!("failed to run: {message}")),
                other => (false, format!("check did not run: {other:?}")),
            };
            checks.push(Check { what: format!("acceptance `{}`", truncate(command, 60)), passed, detail });
        }
        checks
    }

    /// Ask the model to review its own work against the fixed criteria. The
    /// criteria and the reply are logged as ordinary turns (model-visible ⟺
    /// logged). Returns the parsed verdict, or `None` if the model errored or gave
    /// no verdict — a missing verdict never blocks completion on its own.
    async fn self_review(&self, job: &mut JobHandle, cancel: &CancellationToken, budget: &mut BudgetTracker) -> Result<Option<bool>, StoreError> {
        job.append(vec![JobEvent::Message { message: Message::text(Role::User, complete::SELF_REVIEW_CRITERIA) }])?;
        let model = job.state().spec.model.model.clone();
        let request = GenerateRequest {
            model: model.clone(),
            messages: self.build_request_messages(job),
            tools: self.tools.clone(),
            max_tokens: self.sampling.max_tokens,
            temperature: self.sampling.temperature,
            stop: Vec::new(),
            reasoning_effort: self.sampling.reasoning_effort,
            purpose: Purpose::Conversation,
        };
        let print = cache_watch::fingerprint(&request);
        let assembled = stream_toolless(self.backend.as_ref(), request, cancel.clone()).await;
        let mut events = vec![
            JobEvent::Message { message: assembled.message.clone() },
            JobEvent::Usage { model, usage: assembled.usage },
        ];
        events.extend(watch_call(&self.cache, print, &assembled.usage));
        job.append(events)?;
        budget.record_tokens(assembled.usage.total());
        if matches!(assembled.finish, FinishReason::Error(_) | FinishReason::Aborted) {
            return Ok(None);
        }
        Ok(assistant_text(&assembled.message).and_then(|text| complete::parse_verdict(&text)))
    }

    async fn finish(&self, job: &mut JobHandle, outcome: LoopOutcome, status: JobStatus, summary: Option<String>) -> Result<LoopOutcome, StoreError> {
        job.append(vec![JobEvent::StatusChanged { status, summary }])?;
        Ok(outcome)
    }
}

/// Parse the plan tool's arguments into plan items. Lenient on status (defaults
/// to `pending`, unknown values rejected); requires a non-empty `text` per item.
fn parse_plan(raw: &str) -> Result<Vec<PlanItem>, String> {
    let value = serde_json::from_str::<Value>(raw).map_err(|e| format!("arguments are not JSON: {e}"))?;
    let items = value.get("items").and_then(Value::as_array).ok_or("expected an `items` array")?;
    let mut plan = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let text = item.get("text").and_then(Value::as_str).unwrap_or("").trim();
        if text.is_empty() {
            return Err(format!("item {index} has an empty `text`"));
        }
        let status = match item.get("status").and_then(Value::as_str) {
            None | Some("pending") => PlanStatus::Pending,
            Some("in_progress") => PlanStatus::InProgress,
            Some("done") => PlanStatus::Done,
            Some("dropped") => PlanStatus::Dropped,
            Some(other) => return Err(format!("item {index} has an unknown status {other:?}")),
        };
        plan.push(PlanItem { text: text.to_string(), status });
    }
    Ok(plan)
}

/// Count of items the plan has finished (used for stall detection).
fn plan_done_count(plan: &[PlanItem]) -> usize {
    plan.iter().filter(|item| item.status == PlanStatus::Done).count()
}

/// A plan is settled when every item is done or dropped (nothing left to stall on).
fn plan_settled(plan: &[PlanItem]) -> bool {
    !plan.is_empty() && plan.iter().all(|item| matches!(item.status, PlanStatus::Done | PlanStatus::Dropped))
}

/// A one-string-argument tool call (for the gate's own read/exec checks).
fn string_call(name: &str, key: &str, value: &str) -> ToolCall {
    let mut arguments = serde_json::Map::new();
    arguments.insert(key.to_string(), Value::String(value.to_string()));
    ToolCall { name: name.to_string(), arguments }
}

/// Truncate on a char boundary for a short, safe diagnostic snippet.
fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}…")
}

struct ExtractedCall {
    id: String,
    name: String,
    arguments: String,
}

/// Why a call is not dispatched. `Ask` is failed closed until a human channel
/// exists; it is still logged as an approval request for the UI.
enum PermissionBlock {
    Deny(String),
    Ask { resource: String },
}

fn extract_tool_calls(message: &Message) -> Vec<ExtractedCall> {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::ToolCall { id, name, arguments } => {
                Some(ExtractedCall { id: id.clone(), name: name.clone(), arguments: arguments.clone() })
            }
            _ => None,
        })
        .collect()
}

fn assistant_text(message: &Message) -> Option<String> {
    let text: String = message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (!text.is_empty()).then_some(text)
}

fn parse_lenient(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

/// The primary resource a permission rule matches against for this tool.
fn call_resource(call: &ExtractedCall) -> String {
    let args = parse_lenient(&call.arguments);
    let field = match call.name.as_str() {
        "exec" => "command",
        "glob" | "grep" => "pattern",
        _ => "path",
    };
    args.get(field).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// Structured value for loop-detection outcome hashing.
fn outcome_value(outcome: &CallOutcome) -> Value {
    match outcome {
        CallOutcome::Ok(value) => value.clone(),
        CallOutcome::Err { code, message } => serde_json::json!({ "error": code, "message": message }),
        CallOutcome::InvalidArguments(detail) => serde_json::json!({ "error": "INVALID_ARGUMENTS", "message": detail }),
        CallOutcome::Skipped => serde_json::json!({ "error": "SKIPPED" }),
    }
}

fn error_summary(error: &LlmError) -> String {
    format!("model error: {error}")
}

/// (ok, structured result for the log, text the model sees).
fn render_outcome(outcome: CallOutcome) -> (bool, Value, String) {
    match outcome {
        CallOutcome::Ok(value) => {
            let text = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
            (true, value, text)
        }
        CallOutcome::Err { code, message } => {
            let text = format!("{code}: {message}");
            (false, serde_json::json!({ "code": code, "message": message }), text)
        }
        CallOutcome::InvalidArguments(detail) => {
            (false, serde_json::json!({ "code": "INVALID_ARGUMENTS", "message": detail.clone() }), format!("INVALID_ARGUMENTS: {detail}"))
        }
        CallOutcome::Skipped => (false, serde_json::json!({ "code": "SKIPPED", "message": "not run (job stopping)" }), "SKIPPED: not run (job stopping)".into()),
    }
}
