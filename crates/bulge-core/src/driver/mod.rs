//! The step loop. Each step is one model call continued from the job's logged
//! history; tool calls are dispatched (into the VM), and every model-visible
//! message and every claim/completion is appended to the job log before the
//! loop moves on, so a crash is always recoverable.
//!
//! Scope note (C2): "the model stopped calling tools" ends the loop as
//! `Stopped` and is recorded as `Succeeded`. The real completion gate
//! (verify the deliverable contract before declaring success) arrives in C5
//! and will replace that final transition.

mod calls;
mod compaction;
mod config;
mod execute;
mod finish;
mod handlers;
mod request;

pub use calls::*;
pub use config::*;
pub use handlers::*;
pub use request::*;

use std::sync::{Arc, Mutex};

use bulge_llm::{ContentBlock, FinishReason, GenerateRequest, LlmBackend, Message, Purpose, ToolSchema};
use crate::cache_watch::{self, CacheWatch};
use bulge_store::{JobEvent, JobHandle, JobStatus, StoreError};
use tokio_util::sync::CancellationToken;

use crate::budget::{BudgetState, BudgetTracker};
use crate::complete;
use crate::dispatch::ToolDispatcher;

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
    host_tools: Vec<Arc<dyn HostTool>>,
    /// Handles `skill` tool calls (load a skill's steps). `None` → unknown tool.
    skills: Option<Arc<dyn SkillHandler>>,
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
            host_tools: Vec::new(),
            skills: None,
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
    pub fn with_host_tool(mut self, tool: Arc<dyn HostTool>) -> Self {
        self.host_tools.push(tool);
        self
    }

    pub fn with_recall(mut self, handler: Arc<dyn RecallHandler>) -> Self {
        self.recall = Some(handler);
        self
    }

    /// Install a skill handler so the model's `skill` tool calls load a skill's
    /// steps (handled here on the host, never sent to the VM).
    pub fn with_skills(mut self, handler: Arc<dyn SkillHandler>) -> Self {
        self.skills = Some(handler);
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
        let mut budget = BudgetTracker::with_spent(spec.budget.clone(), job.state().steps, job.state().tokens_spent());
        if let Some(ledger) = &self.ledger {
            budget = budget.with_ledger(ledger.clone());
        }
        let mut wind_down_announced = false;
        let (mut compact_failures, mut compact_skip) = (0u32, 0u32);
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
                BudgetState::Exhausted => return self.final_step(job, &mut budget, &cancel).await,
                BudgetState::WindDown if !wind_down_announced => {
                    wind_down_announced = true;
                    let note = "Budget is nearly spent. Stop exploring, finish and write every requested deliverable now, then stop.";
                    job.append(vec![JobEvent::Message { message: harness_note(note) }])?;
                }
                _ => {}
            }

            let step = job.state().steps + 1;
            budget.record_step();
            job.append(vec![JobEvent::StepStarted { step }])?;

            // Roll the context forward if it would overflow: summarize the oldest
            // messages into one checkpoint. Best-effort — a failed summary just
            // leaves the history as-is (pruning still caps request size), but
            // its tokens are still charged. After a failure the next attempts
            // are skipped with exponential backoff, so a provider that keeps
            // failing the summary call is not paid for it on every step.
            if compact_skip > 0 {
                compact_skip -= 1;
            } else {
                let (compaction_usage, compacted) = self.maybe_compact(job, &cancel).await?;
                budget.record_tokens(compaction_usage.total());
                match compacted {
                    Some(false) => {
                        compact_failures = (compact_failures + 1).min(COMPACT_BACKOFF_MAX_DOUBLINGS);
                        compact_skip = (1u32 << compact_failures) - 1;
                    }
                    Some(true) => compact_failures = 0,
                    None => {}
                }
            }

            let assembled = match self.one_call(job, false, cancel.clone()).await? {
                Ok(assembled) => assembled,
                Err(outcome) => return Ok(outcome),
            };
            budget.record_tokens(assembled.usage.total());

            let tool_calls = extract_tool_calls(&assembled.message);
            if tool_calls.is_empty() && assembled.finish == FinishReason::MaxTokens {
                // Cut off by the output limit: the reply is not a final answer
                // (and any tool call it was writing was dropped as incomplete).
                // Ask for the rest; the step and token budgets bound repeats.
                job.append(vec![JobEvent::Message { message: harness_note(TRUNCATED_NOTE) }])?;
                continue;
            }
            if tool_calls.is_empty() {
                let summary = assistant_text(&assembled.message);
                match self.completion_gate(job, summary, &cancel, &mut gate_attempts, &mut budget).await? {
                    GateDecision::Done(outcome) => return Ok(outcome),
                    GateDecision::Continue => continue,
                }
            }

            if let Some(outcome) = self.dispatch_calls(job, tool_calls, &cancel, &mut detector, &mut warned, &mut budget).await? {
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
                    job.append(vec![JobEvent::Message { message: harness_note(note) }])?;
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
        let mut assembled = if toolless {
            stream_toolless(self.backend.as_ref(), request, cancel).await
        } else {
            collect(self.backend.as_ref(), request, cancel).await
        };

        // A failed or aborted turn never runs its tool calls, so they must not
        // enter the history: an assistant tool call with no result makes every
        // later request invalid. Whatever text it produced is kept.
        let failed = matches!(assembled.finish, FinishReason::Error(_) | FinishReason::Aborted);
        if failed {
            assembled.message.content.retain(|block| !matches!(block, ContentBlock::ToolCall { .. }));
        } else if !toolless {
            repair_text_tool_calls(&mut assembled.message, &self.tools);
        }
        unique_call_ids(&mut assembled.message);

        let mut events = Vec::with_capacity(3);
        if !(failed && assembled.message.content.is_empty()) {
            events.push(JobEvent::Message { message: assembled.message.clone() });
        }
        events.push(JobEvent::Usage { model, usage: assembled.usage });
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
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use bulge_llm::Role;

    fn text(m: &Message) -> String {
        m.content.iter().filter_map(|b| if let ContentBlock::Text { text } = b { Some(text.clone()) } else { None }).collect()
    }

    #[test]
    fn earlier_reviews_collapse_but_the_current_one_stays() {
        let review = || harness_note(complete::SELF_REVIEW_CRITERIA);
        let mut view = vec![
            Message::text(Role::System, "sys"),
            Message::text(Role::User, "first task"),
            Message::text(Role::Assistant, "done 1"),
            review(),
            Message::text(Role::Assistant, "1. DELIVERY: yes\nVERDICT: PASS"),
            Message::text(Role::User, "second task"),
            Message::text(Role::Assistant, "done 2"),
            review(),
            Message::text(Role::Assistant, "1. DELIVERY: yes"),
        ];
        let count = view.len();
        collapse_earlier_reviews(&mut view);
        assert_eq!(view.len(), count, "one message per history message");
        assert!(text(&view[3]).contains("was done"));
        assert_eq!(text(&view[4]), "(reviewed)");
        assert_eq!(text(&view[2]), "done 1", "answers are untouched");
        assert!(text(&view[7]).contains(complete::SELF_REVIEW_OPENING), "the newest turn's review is intact");
        assert_eq!(text(&view[8]), "1. DELIVERY: yes");
    }

    #[test]
    fn images_from_earlier_turns_become_text_but_this_turn_keeps_them() {
        let image = |n: &str| Message { content: vec![ContentBlock::Image { media_type: "image/png".into(), data: n.into() }], ..Message::text(Role::User, String::new()) };
        let mut view = vec![Message::text(Role::User, "first"), image("old"), Message::text(Role::User, "second"), image("new")];
        // Image messages start with a harness note in real use; a bare one is
        // not a user turn either (no text block).
        collapse_earlier_reviews(&mut view);
        assert!(matches!(&view[1].content[0], ContentBlock::Text { text } if text.contains("view_image again")));
        assert!(matches!(&view[3].content[0], ContentBlock::Image { .. }));
    }
}
