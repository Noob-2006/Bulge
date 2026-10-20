//! The step loop. Each step is one model call continued from the job's logged
//! history; tool calls are dispatched (into the VM), and every model-visible
//! message and every claim/completion is appended to the job log before the
//! loop moves on, so a crash is always recoverable.
//!
//! Scope note (C2): "the model stopped calling tools" ends the loop as
//! `Stopped` and is recorded as `Succeeded`. The real completion gate
//! (verify the deliverable contract before declaring success) arrives in C5
//! and will replace that final transition.

use std::sync::Arc;

use bulge_llm::assemble::Assembler;
use bulge_llm::{ContentBlock, FinishReason, GenerateRequest, LlmBackend, LlmError, Message, Purpose, Role, ToolSchema};
use bulge_store::{JobEvent, JobHandle, JobStatus, StoreError};
use futures::StreamExt;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::budget::{BudgetState, BudgetTracker};
use crate::dispatch::{ToolCall, ToolDispatcher};
use crate::schedule::{CallOutcome, PlannedCall, run_tool_calls};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOutcome {
    /// The model produced no tool calls (recorded as Succeeded; see scope note).
    Stopped,
    BudgetExhausted,
    Cancelled,
    Failed,
}

pub struct Driver {
    backend: Arc<dyn LlmBackend>,
    dispatcher: Arc<dyn ToolDispatcher>,
    tools: Vec<ToolSchema>,
    system_prompt: String,
    max_parallel: usize,
}

impl Driver {
    pub fn new(backend: Arc<dyn LlmBackend>, dispatcher: Arc<dyn ToolDispatcher>, tools: Vec<ToolSchema>, system_prompt: String) -> Self {
        Self { backend, dispatcher, tools, system_prompt, max_parallel: crate::schedule::DEFAULT_MAX_PARALLEL }
    }

    pub async fn run(&self, job: &mut JobHandle, cancel: CancellationToken) -> Result<LoopOutcome, StoreError> {
        let spec = job.state().spec.clone();
        let mut budget = BudgetTracker::with_spent(spec.budget.clone(), job.state().steps, job.state().usage.total());
        let mut wind_down_announced = false;

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

            let assembled = match self.one_call(job, self.tools.clone(), cancel.clone()).await? {
                Ok(assembled) => assembled,
                Err(outcome) => return Ok(outcome),
            };
            budget.record_tokens(assembled.usage.total());

            let tool_calls = extract_tool_calls(&assembled.message);
            if tool_calls.is_empty() {
                let summary = assistant_text(&assembled.message);
                return self.finish(job, LoopOutcome::Stopped, JobStatus::Succeeded, summary).await;
            }

            self.dispatch_calls(job, tool_calls, &cancel).await?;
        }
    }

    /// One model call: build the request from history, stream, assemble, and log
    /// the assistant message + usage. `Err(outcome)` means the loop must end.
    async fn one_call(
        &self,
        job: &mut JobHandle,
        tools: Vec<ToolSchema>,
        cancel: CancellationToken,
    ) -> Result<Result<bulge_llm::assemble::Assembled, LoopOutcome>, StoreError> {
        let model = job.state().spec.model.model.clone();
        let mut messages = Vec::with_capacity(job.state().history.len() + 1);
        messages.push(Message::text(Role::System, self.system_prompt.clone()));
        messages.extend(job.state().history.iter().cloned());
        let request = GenerateRequest {
            model: model.clone(),
            messages,
            tools,
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Conversation,
        };

        let mut stream = self.backend.stream(request, cancel);
        let mut assembler = Assembler::new();
        while let Some(chunk) = stream.next().await {
            assembler.push(&chunk);
        }
        let assembled = assembler.finish(&model);

        job.append(vec![
            JobEvent::Message { message: assembled.message.clone() },
            JobEvent::Usage { model, usage: assembled.usage },
        ])?;

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

    /// Write-ahead claim every call durably, run them (ordered results), then
    /// log each completion and the tool-result message the model will see.
    async fn dispatch_calls(&self, job: &mut JobHandle, calls: Vec<ExtractedCall>, cancel: &CancellationToken) -> Result<(), StoreError> {
        let claims = calls
            .iter()
            .map(|c| JobEvent::ToolClaimed { call_id: c.id.clone(), name: c.name.clone(), arguments: parse_lenient(&c.arguments) })
            .collect();
        job.append(claims)?;

        let planned: Vec<PlannedCall> = calls
            .iter()
            .map(|c| PlannedCall {
                call_id: c.id.clone(),
                name: c.name.clone(),
                raw_arguments: c.arguments.clone(),
                concurrency_safe: self.dispatcher.concurrency_safe(&c.name),
            })
            .collect();

        let dispatcher = self.dispatcher.clone();
        let results = run_tool_calls(
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

        let mut events = Vec::with_capacity(results.len() * 2);
        for result in results {
            let (ok, value, text) = render_outcome(result.outcome);
            events.push(JobEvent::ToolCompleted { call_id: result.call_id.clone(), ok, result: value });
            events.push(JobEvent::Message { message: Message::tool_result(result.call_id, text, !ok) });
        }
        job.append(events)?;
        Ok(())
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

        let assembled = match self.one_call(job, Vec::new(), CancellationToken::new()).await? {
            Ok(assembled) => assembled,
            Err(outcome) => return Ok(outcome),
        };
        let summary = assistant_text(&assembled.message);
        self.finish(job, LoopOutcome::BudgetExhausted, JobStatus::Incomplete, summary).await
    }

    async fn finish(&self, job: &mut JobHandle, outcome: LoopOutcome, status: JobStatus, summary: Option<String>) -> Result<LoopOutcome, StoreError> {
        job.append(vec![JobEvent::StatusChanged { status, summary }])?;
        Ok(outcome)
    }
}

struct ExtractedCall {
    id: String,
    name: String,
    arguments: String,
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
