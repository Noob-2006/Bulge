//! Ending a run: the last step on an exhausted budget, the completion gate
//! (contract checks and self-review), and the final status.

use bulge_llm::{FinishReason, GenerateRequest, Purpose};
use crate::cache_watch;
use bulge_store::{JobEvent, JobHandle, JobStatus, StoreError};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use crate::budget::BudgetTracker;
use crate::complete::{self, Check, GateReport};
use crate::schedule::CallOutcome;
use super::{Driver, GateDecision, LoopOutcome, assistant_text, harness_note, stream_toolless, string_call, truncate, watch_call};

impl Driver {
    /// Budget spent: one final tool-less call asking for a summary, then stop Incomplete.
    pub(super) async fn final_step(&self, job: &mut JobHandle, budget: &mut BudgetTracker, cancel: &CancellationToken) -> Result<LoopOutcome, StoreError> {
        let strained = budget.strained().map_or("budget", |r| match r {
            crate::budget::Resource::Steps => "step",
            crate::budget::Resource::Tokens => "token",
            crate::budget::Resource::WallClock => "time",
        });
        let note = format!(
            "The {strained} budget for this job is spent. Tools are now disabled. Respond with text only: summarize what was accomplished, list what remains unfinished, and recommend next steps."
        );
        job.append(vec![JobEvent::StepStarted { step: job.state().steps + 1 }, JobEvent::Message { message: harness_note(note) }])?;
        budget.record_step();

        let assembled = match self.one_call(job, true, cancel.clone()).await? {
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
    pub(super) async fn completion_gate(
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
        job.append(vec![JobEvent::Message { message: harness_note(feedback) }])?;
        Ok(GateDecision::Continue)
    }

    /// Mechanical contract checks, run in the VM: each deliverable must be
    /// readable, each acceptance command must exit 0. No contract → no checks.
    pub(super) async fn run_contract_checks(&self, job: &JobHandle, cancel: &CancellationToken) -> Vec<Check> {
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
    pub(super) async fn self_review(&self, job: &mut JobHandle, cancel: &CancellationToken, budget: &mut BudgetTracker) -> Result<Option<bool>, StoreError> {
        job.append(vec![JobEvent::Message { message: harness_note(complete::SELF_REVIEW_CRITERIA) }])?;
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

    pub(super) async fn finish(&self, job: &mut JobHandle, outcome: LoopOutcome, status: JobStatus, summary: Option<String>) -> Result<LoopOutcome, StoreError> {
        job.append(vec![JobEvent::StatusChanged { status, summary }])?;
        Ok(outcome)
    }
}
