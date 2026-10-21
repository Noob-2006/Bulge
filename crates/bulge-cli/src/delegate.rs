//! Sub-agent delegation: a host-handled `delegate` tool that runs a focused
//! sub-task in a fresh nested agent loop and returns ONLY its final summary.
//!
//! The child shares the parent's VM (and so its tools, hooks, and review gate)
//! but runs a separate conversation with its own store job and a smaller budget.
//! The child is given every tool EXCEPT `delegate`, so delegation is naturally
//! capped at one level (no runaway recursion). The parent transcript never sees
//! the child's intermediate steps — only the delegate call and the returned
//! summary — matching the deepseek/Hermes "parent sees the summary, not the
//! child's reasoning" model.
//!
//! The driver calls this through [`bulge_core::driver::DelegateHandler`]: the
//! child runs a nested driver whose future is `!Send` (it schedules tool calls on
//! the current thread), so delegation is handled inside the driver loop, not in a
//! `Send` dispatcher.

use std::path::PathBuf;
use std::sync::Arc;

use bulge_core::driver::{CompletionConfig, ContextConfig, DelegateHandler, Driver, GuardConfig, Sampling};
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_core::ToolDispatcher;
use bulge_llm::{ContentBlock, LlmBackend, Role, ToolSchema};
use bulge_store::{Autonomy, Budget, JobSpec, JobStore, ModelRef};
use futures::future::LocalBoxFuture;
use serde_json::json;
use tokio_util::sync::CancellationToken;

/// Schema for the `delegate` tool the parent model may call.
pub fn delegate_tool() -> ToolSchema {
    ToolSchema {
        name: DELEGATE_TOOL.into(),
        description: "Delegate a focused sub-task to a fresh sub-agent that shares this workspace/VM \
            and reports back a concise result. Use it to isolate a self-contained chunk of work (a \
            search, a build-and-test, a refactor of one module) so your own context stays clean. The \
            sub-agent cannot delegate further. You receive only its final summary, not its steps."
            .into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "goal": { "type": "string", "description": "The sub-task, stated as a complete, self-contained instruction." },
                "context": { "type": "string", "description": "Optional background the sub-agent needs (it does not see your conversation)." }
            },
            "required": ["goal"]
        }),
        defer_loading: false,
    }
}

/// Everything a delegation needs to spawn and run a child agent. All fields are
/// cheap clones / `Arc`s so the dispatcher can capture them per call.
#[derive(Clone)]
pub struct ChildFactory {
    pub backend: Arc<dyn LlmBackend>,
    /// The child's tool dispatcher — the SAME VM/MCP/hook stack as the parent,
    /// but without the delegating wrapper (so the child has no `delegate` tool).
    pub inner: Arc<dyn ToolDispatcher>,
    /// Tools the child sees (parent tools minus `delegate`).
    pub child_tools: Vec<ToolSchema>,
    pub store_root: PathBuf,
    pub workspace: PathBuf,
    pub autonomy: Autonomy,
    pub guard_rules: bulge_guard::Ruleset,
    pub model: String,
    pub backend_id: String,
    pub context_window: u32,
    pub sampling: Sampling,
    pub auto_review: bool,
}

impl ChildFactory {
    /// Run one sub-task to completion and return its summary text.
    async fn run_child(&self, goal: String, context: Option<String>, cancel: CancellationToken) -> Result<String, String> {
        let full_goal = match context {
            Some(c) if !c.trim().is_empty() => format!("{goal}\n\nContext:\n{c}"),
            _ => goal.clone(),
        };
        let store = JobStore::new(&self.store_root);
        let job_id = bulge_store::new_job_id().map_err(|e| format!("child job id: {e}"))?;
        let title: String = full_goal.lines().next().unwrap_or("sub-task").chars().take(80).collect();
        let mut job = store
            .create(JobSpec {
                id: job_id,
                title,
                goal: full_goal.clone(),
                workspace: self.workspace.clone(),
                autonomy: self.autonomy,
                // A sub-agent gets a modest, bounded budget.
                budget: Budget { max_steps: 80, max_tokens: 800_000, max_wall_secs: 1_800 },
                model: ModelRef { backend: self.backend_id.clone(), model: self.model.clone() },
            })
            .map_err(|e| format!("create child job: {e}"))?;

        let system_prompt = format!(
            "You are a focused sub-agent. Complete exactly this one task and then stop, reporting a \
             concise result (what you did and the key outcome). Do not ask questions; make reasonable \
             assumptions. You share the workspace with a parent agent.\n\nTASK:\n{full_goal}"
        );
        let context = ContextConfig { window: self.context_window as u64, ..ContextConfig::default() };
        let driver = Driver::new(self.backend.clone(), self.inner.clone(), self.child_tools.clone(), system_prompt)
            .with_guard(GuardConfig { rules: self.guard_rules.clone(), autonomy: crate::run::guard_autonomy(self.autonomy), loop_detection: true })
            .with_completion_gate(CompletionConfig::default())
            .with_context(context)
            .with_sampling(self.sampling.clone())
            .with_review(self.auto_review);

        driver.run(&mut job, cancel).await.map_err(|e| format!("child run: {e}"))?;

        // Prefer the recorded summary; fall back to the last assistant message.
        let state = job.state();
        if let Some(summary) = state.summary.clone().filter(|s| !s.trim().is_empty()) {
            return Ok(summary);
        }
        let last = state.history.iter().rev().find_map(|m| {
            if m.role != Role::Assistant {
                return None;
            }
            let text: String = m
                .content
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            (!text.trim().is_empty()).then_some(text)
        });
        Ok(last.unwrap_or_else(|| "(sub-agent produced no summary)".to_string()))
    }
}

impl DelegateHandler for ChildFactory {
    fn run<'a>(&'a self, goal: String, context: Option<String>, cancel: CancellationToken) -> LocalBoxFuture<'a, Result<String, String>> {
        Box::pin(self.run_child(goal, context, cancel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegate_tool_schema_is_well_formed() {
        let t = delegate_tool();
        assert_eq!(t.name, DELEGATE_TOOL);
        let required = t.parameters.get("required").and_then(|v| v.as_array()).unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("goal")));
        assert!(t.parameters.get("properties").and_then(|p| p.get("goal")).is_some());
    }
}
