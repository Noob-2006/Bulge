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
    /// Every request the driver sent, in order (for prefix-stability checks).
    requests: Mutex<Vec<bulge_llm::GenerateRequest>>,
}

impl FakeBackend {
    fn new(turns: Vec<Vec<ContentBlock>>) -> Arc<Self> {
        Arc::new(Self {
            turns: Mutex::new(turns.into()),
            requests: Mutex::new(Vec::new()),
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
    fn stream(&self, request: bulge_llm::GenerateRequest, _cancel: CancellationToken) -> BoxStream<'static, StreamChunk> {
        self.requests.lock().unwrap().push(request);
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

// ---- completion gate (C5) ----

/// Gate-aware dispatcher: `read` reports whether a deliverable exists, `exec`
/// reports a fixed acceptance exit code; everything else is a bland Ok.
struct GateDispatcher {
    read_ok: bool,
    exec_exit: i64,
}

impl ToolDispatcher for GateDispatcher {
    fn dispatch(&self, call: ToolCall, _cancel: CancellationToken) -> BoxFuture<'static, bulge_core::schedule::CallOutcome> {
        let name = call.name.clone();
        let read_ok = self.read_ok;
        let exec_exit = self.exec_exit;
        async move {
            use bulge_core::schedule::CallOutcome;
            match name.as_str() {
                "read" if !read_ok => CallOutcome::Err { code: "ENOENT".into(), message: "no such file".into() },
                "exec" => CallOutcome::Ok(json!({
                    "exit_code": exec_exit,
                    "stdout": "",
                    "stderr": if exec_exit == 0 { "" } else { "assertion failed" },
                })),
                _ => CallOutcome::Ok(json!({ "ok": true })),
            }
        }
        .boxed()
    }
    fn concurrency_safe(&self, name: &str) -> bool {
        bulge_core::builtin_concurrency_safe(name)
    }
}

fn contract(paths: &[&str], acceptance: &[&str]) -> JobEvent {
    JobEvent::Contract {
        contract: bulge_store::Contract {
            deliverables: paths.iter().map(|p| bulge_store::Deliverable { path: (*p).into(), description: "d".into() }).collect(),
            acceptance: acceptance.iter().map(|a| (*a).to_string()).collect(),
        },
    }
}

#[tokio::test]
async fn gate_accepts_when_deliverables_exist_and_self_review_passes() {
    use bulge_core::driver::CompletionConfig;

    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    job.append(vec![contract(&["report.md"], &[])]).unwrap();

    // turn 0: model stops; turn 1: self-review passes.
    let backend = FakeBackend::new(vec![vec![text("I believe it is done.")], vec![text("1..6 all good.\nVERDICT: PASS")]]);
    let dispatcher = Arc::new(GateDispatcher { read_ok: true, exec_exit: 0 });
    let driver = Driver::new(backend, dispatcher, bulge_core::builtin_tools(), "You are bulge.".into())
        .with_completion_gate(CompletionConfig::default());

    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(job.state().status, JobStatus::Succeeded);
}

#[tokio::test]
async fn gate_fails_then_passes_after_more_work() {
    use bulge_core::driver::CompletionConfig;

    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    job.append(vec![contract(&["report.md"], &[])]).unwrap();

    // step1 stop -> review FAIL -> feedback, continue;
    // step2 stop -> review PASS -> succeed.
    let backend = FakeBackend::new(vec![
        vec![text("done?")],
        vec![text("point 6 has a stub.\nVERDICT: FAIL")],
        vec![text("fixed it, done.")],
        vec![text("all addressed.\nVERDICT: PASS")],
    ]);
    let dispatcher = Arc::new(GateDispatcher { read_ok: true, exec_exit: 0 });
    let driver = Driver::new(backend, dispatcher, bulge_core::builtin_tools(), "You are bulge.".into())
        .with_completion_gate(CompletionConfig { self_review: true, max_attempts: 2 });

    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(job.state().status, JobStatus::Succeeded);
    // The failure feedback was fed back into the conversation.
    assert!(job.state().history.iter().any(|m| m.content.iter().any(|b| matches!(b, ContentBlock::Text { text } if text.contains("not complete yet")))));
}

#[tokio::test]
async fn gate_stops_incomplete_when_a_deliverable_is_missing() {
    use bulge_core::driver::CompletionConfig;

    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    job.append(vec![contract(&["report.md"], &["test -f report.md"])]).unwrap();

    // Only one stop turn is needed: no self-review, attempt 1 > max_attempts 0.
    let backend = FakeBackend::new(vec![vec![text("done (but the file is not there)")]]);
    let dispatcher = Arc::new(GateDispatcher { read_ok: false, exec_exit: 1 });
    let driver = Driver::new(backend, dispatcher, bulge_core::builtin_tools(), "You are bulge.".into())
        .with_completion_gate(CompletionConfig { self_review: false, max_attempts: 0 });

    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Incomplete);
    assert_eq!(job.state().status, JobStatus::Incomplete);
    let summary = job.state().summary.clone().unwrap_or_default();
    assert!(summary.contains("report.md"), "summary names the missing deliverable: {summary}");
}

// ---- plan tool (C5) ----

fn driver_with_plan(backend: Arc<FakeBackend>, dispatcher: Arc<FakeDispatcher>) -> Driver {
    let mut tools = bulge_core::builtin_tools();
    tools.push(bulge_core::plan_tool());
    Driver::new(backend, dispatcher, tools, "You are bulge.".into())
}

#[tokio::test]
async fn plan_tool_is_handled_on_the_host_not_the_vm() {
    let plan_call = ContentBlock::ToolCall {
        id: "p1".into(),
        name: bulge_core::PLAN_TOOL.into(),
        arguments: json!({ "items": [
            { "text": "collect sources", "status": "done" },
            { "text": "write report", "status": "in_progress" }
        ] })
        .to_string(),
    };
    let backend = FakeBackend::new(vec![vec![plan_call], vec![text("done")]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });

    let outcome = driver_with_plan(backend, dispatcher.clone()).run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Stopped);

    // The plan was recorded into state...
    assert_eq!(job.state().plan.len(), 2);
    assert_eq!(job.state().plan[0].text, "collect sources");
    // ...and the plan call never reached the VM dispatcher.
    assert!(dispatcher.seen.lock().unwrap().iter().all(|c| c.name != bulge_core::PLAN_TOOL));
}

#[tokio::test]
async fn a_stalled_plan_gets_one_nudge() {
    // One plan with an item that never finishes, then many tool steps with no
    // progress: the driver should nudge about the stall.
    let plan_call = ContentBlock::ToolCall {
        id: "p1".into(),
        name: bulge_core::PLAN_TOOL.into(),
        arguments: json!({ "items": [{ "text": "the hard part", "status": "in_progress" }] }).to_string(),
    };
    let mut turns = vec![vec![plan_call]];
    for i in 0..10 {
        turns.push(vec![tool(&format!("r{i}"), "read", json!({ "path": "a.txt" }))]);
    }
    let backend = FakeBackend::new(turns);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });

    driver_with_plan(backend, dispatcher).run(&mut job, CancellationToken::new()).await.unwrap();

    let nudges = job
        .state()
        .history
        .iter()
        .filter(|m| m.content.iter().any(|b| matches!(b, ContentBlock::Text { text } if text.contains("no plan progress"))))
        .count();
    assert_eq!(nudges, 1, "the stall nudge should fire exactly once");
}

/// Every request after the first must extend the previous one byte-for-byte
/// (same system prompt, same tools, earlier messages unchanged): that is what
/// lets the provider's prefix cache cover the whole conversation so far.
fn assert_prefix_chain(requests: &[bulge_llm::GenerateRequest]) {
    for pair in requests.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        assert_eq!(prev.tools, next.tools, "tool list changed between requests");
        assert!(next.messages.len() >= prev.messages.len());
        assert_eq!(prev.messages[..], next.messages[..prev.messages.len()], "earlier messages were rewritten");
    }
}

#[tokio::test]
async fn toolless_final_step_keeps_the_cached_prefix() {
    let backend = FakeBackend::new(vec![vec![tool("c1", "exec", json!({ "command": "true" }))], vec![text("summary")]]);
    let dispatcher = Arc::new(FakeDispatcher::default());
    let mut job = job(Budget { max_steps: 1, max_tokens: 100_000, max_wall_secs: 3600 });
    driver(backend.clone(), dispatcher).run(&mut job, CancellationToken::new()).await.unwrap();

    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].tool_choice, bulge_llm::ToolChoice::Auto);
    assert_eq!(requests[1].tool_choice, bulge_llm::ToolChoice::None, "tools stay declared but calls are forbidden");
    assert_prefix_chain(&requests);
}

#[tokio::test]
async fn self_review_and_side_requests_keep_the_cached_prefix() {
    use bulge_core::driver::{CompletionConfig, side_request};

    let mut job = job(Budget { max_steps: 50, max_tokens: 100_000, max_wall_secs: 3600 });
    job.append(vec![contract(&["report.md"], &[])]).unwrap();
    let backend = FakeBackend::new(vec![vec![text("I believe it is done.")], vec![text("VERDICT: PASS")]]);
    let dispatcher = Arc::new(GateDispatcher { read_ok: true, exec_exit: 0 });
    let driver = Driver::new(backend.clone(), dispatcher, bulge_core::builtin_tools(), "You are bulge.".into())
        .with_completion_gate(CompletionConfig::default());
    driver.run(&mut job, CancellationToken::new()).await.unwrap();

    // A post-job side call (e.g. learning) built from the driver's prefix.
    let side = side_request(&driver.prefix(), &job, "extract lessons", bulge_llm::Purpose::Memory);
    let mut requests = backend.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2, "loop call + self-review");
    assert_eq!(requests[1].tool_choice, bulge_llm::ToolChoice::None);
    assert_eq!(side.tool_choice, bulge_llm::ToolChoice::None);
    requests.push(side);
    assert_prefix_chain(&requests);
}
