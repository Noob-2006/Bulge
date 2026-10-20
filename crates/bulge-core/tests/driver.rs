//! Loop mechanics against a scripted fake model and a fake tool dispatcher
//! (no VM, no network): tool round-trips, budgets, wind-down, cancellation.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bulge_core::dispatch::{ToolCall, ToolDispatcher};
use bulge_core::driver::{Driver, LoopOutcome};
use bulge_llm::{ContentBlock, FinishReason, LlmBackend, Message, ModelInfo, Role, StreamChunk, TokenUsage};
use bulge_store::{Autonomy, Budget, JobEvent, JobHandle, JobSpec, JobStatus, JobStore, ModelRef};
use futures::FutureExt;
use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use serde_json::json;
use tokio_util::sync::CancellationToken;

// ---- fakes ----

/// Pops one scripted assistant turn (a list of content blocks) per model call.
struct FakeBackend {
    turns: Mutex<VecDeque<Vec<ContentBlock>>>,
    models: Vec<ModelInfo>,
}

impl FakeBackend {
    fn new(turns: Vec<Vec<ContentBlock>>) -> Arc<Self> {
        Arc::new(Self {
            turns: Mutex::new(turns.into()),
            models: vec![ModelInfo {
                id: "m".into(),
                context_window: 100_000,
                max_tokens: 4096,
                system_prompt_update: Default::default(),
                deferred_tools: false,
                images: false,
                reasoning: false,
            }],
        })
    }
}

impl LlmBackend for FakeBackend {
    fn id(&self) -> &str {
        "fake"
    }
    fn models(&self) -> &[ModelInfo] {
        &self.models
    }
    fn stream(&self, _request: bulge_llm::GenerateRequest, _cancel: CancellationToken) -> BoxStream<'static, StreamChunk> {
        let blocks = self.turns.lock().unwrap().pop_front().unwrap_or_else(|| vec![ContentBlock::Text { text: "(no script left)".into() }]);
        let has_tools = blocks.iter().any(|b| matches!(b, ContentBlock::ToolCall { .. }));
        let mut chunks: Vec<StreamChunk> = blocks.into_iter().enumerate().map(|(i, block)| StreamChunk::BlockEnd { index: i, block }).collect();
        chunks.push(StreamChunk::Usage(TokenUsage { output_tokens: 10, ..Default::default() }));
        chunks.push(StreamChunk::Finish(if has_tools { FinishReason::ToolCalls } else { FinishReason::Stop }));
        futures::stream::iter(chunks).boxed()
    }
}

#[derive(Default)]
struct FakeDispatcher {
    seen: Mutex<Vec<ToolCall>>,
}

impl ToolDispatcher for FakeDispatcher {
    fn dispatch(&self, call: ToolCall, _cancel: CancellationToken) -> BoxFuture<'static, bulge_core::schedule::CallOutcome> {
        self.seen.lock().unwrap().push(call.clone());
        async move { bulge_core::schedule::CallOutcome::Ok(json!({ "echo": call.name })) }.boxed()
    }
    fn concurrency_safe(&self, name: &str) -> bool {
        bulge_core::builtin_concurrency_safe(name)
    }
}

// ---- helpers ----

fn tool(id: &str, name: &str, args: serde_json::Value) -> ContentBlock {
    ContentBlock::ToolCall { id: id.into(), name: name.into(), arguments: args.to_string() }
}
fn text(t: &str) -> ContentBlock {
    ContentBlock::Text { text: t.into() }
}

fn job(budget: Budget) -> JobHandle {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("bulge-core-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = JobStore::new(root);
    let mut handle = store
        .create(JobSpec {
            id: "j".into(),
            title: "t".into(),
            goal: "g".into(),
            workspace: PathBuf::from("/tmp/ws"),
            autonomy: Autonomy::default(),
            budget,
            model: ModelRef { backend: "fake".into(), model: "m".into() },
        })
        .unwrap();
    handle.append(vec![JobEvent::Message { message: Message::text(Role::User, "do the thing") }]).unwrap();
    handle
}

fn driver(backend: Arc<FakeBackend>, dispatcher: Arc<FakeDispatcher>) -> Driver {
    Driver::new(backend, dispatcher, bulge_core::builtin_tools(), "You are bulge.".into())
}

// ---- tests ----

#[tokio::test]
async fn tool_call_then_stop_round_trips_and_balances_the_log() {
    let backend = FakeBackend::new(vec![vec![tool("c1", "read", json!({ "path": "a.txt" }))], vec![text("all done")]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    let outcome = driver(backend, dispatcher.clone()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(job.state().status, JobStatus::Succeeded);
    assert_eq!(job.state().summary.as_deref(), Some("all done"));
    assert!(job.state().pending_calls.is_empty(), "every claimed call must be completed");
    assert_eq!(dispatcher.seen.lock().unwrap().len(), 1);
    // A tool-result message for c1 is visible to the model.
    assert!(job.state().history.iter().any(|m| m.tool_call_id.as_deref() == Some("c1")));
}

#[tokio::test]
async fn budget_exhaustion_forces_a_final_toolless_summary() {
    let backend = FakeBackend::new(vec![vec![tool("c1", "exec", json!({ "command": "sleep 1" }))], vec![text("ran out of budget, here is the summary")]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 1, max_tokens: 100_000, max_wall_secs: 3600 });
    let outcome = driver(backend, dispatcher).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::BudgetExhausted);
    assert_eq!(job.state().status, JobStatus::Incomplete);
    assert!(job.state().summary.as_deref().unwrap().contains("summary"));
}

#[tokio::test]
async fn wind_down_reminder_is_injected_once() {
    let mut turns: Vec<Vec<ContentBlock>> = (0..5).map(|i| vec![tool(&format!("c{i}"), "exec", json!({ "command": "x" }))]).collect();
    turns.push(vec![text("summary")]);
    let backend = FakeBackend::new(turns);
    let mut job = job(Budget { max_steps: 5, max_tokens: 100_000, max_wall_secs: 3600 });
    let outcome = driver(backend, Arc::new(FakeDispatcher::default())).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::BudgetExhausted);
    let reminders = job.state().history.iter().filter(|m| m.content.iter().any(|b| matches!(b, ContentBlock::Text { text } if text.contains("Budget is nearly spent")))).count();
    assert_eq!(reminders, 1, "wind-down reminder must appear exactly once");
}

#[tokio::test]
async fn cancel_before_run_stops_immediately() {
    let backend = FakeBackend::new(vec![vec![tool("c1", "read", json!({ "path": "a" }))]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    let cancel = CancellationToken::new();
    cancel.cancel();
    let outcome = driver(backend, dispatcher.clone()).run(&mut job, cancel).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Cancelled);
    assert_eq!(job.state().status, JobStatus::Cancelled);
    assert!(dispatcher.seen.lock().unwrap().is_empty(), "no tool should run after cancel");
}

#[tokio::test]
async fn plain_answer_with_no_tools_stops() {
    let backend = FakeBackend::new(vec![vec![text("the answer is 42")]]);
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    let outcome = driver(backend, Arc::new(FakeDispatcher::default())).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(job.state().summary.as_deref(), Some("the answer is 42"));
}

#[tokio::test]
async fn overflowing_history_is_compacted_before_the_next_call() {
    use bulge_core::context::PruneConfig;
    use bulge_core::driver::ContextConfig;

    // A history large enough to overflow a deliberately tiny window.
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    for i in 0..10 {
        let role = if i % 2 == 0 { Role::Assistant } else { Role::User };
        job.append(vec![JobEvent::Message { message: Message::text(role, "x".repeat(400)) }]).unwrap();
    }
    let history_len_before = job.state().history.len();

    // Turn 0 is consumed by the compaction summary call, turn 1 by the step.
    let backend = FakeBackend::new(vec![vec![text("BRIEFING: earlier work")], vec![text("done")]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let driver = driver(backend, dispatcher).with_context(ContextConfig {
        window: 400,
        reserve: 0,
        retain_ratio: 0.5,
        keep_recent: 2,
        prune: PruneConfig::default(),
    });

    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Stopped);

    // A checkpoint was recorded and rebuilt into state.
    let compaction = job.state().compaction.clone().expect("history should have been compacted");
    assert_eq!(compaction.summary, "BRIEFING: earlier work");
    assert!(compaction.kept_from > 0, "kept_from must advance past the oldest messages");
    assert!(compaction.kept_from <= history_len_before, "kept_from stays within the real history");

    // The full history is never discarded — it stays in the log for replay.
    assert!(job.state().history.len() >= history_len_before);

    // The compaction call's tokens were logged as usage (charged to the budget):
    // the fake emits 10 output tokens per call, so a compaction + a step is >= 20.
    assert!(job.state().usage.output_tokens >= 20, "both the compaction call and the step should log usage");
}
