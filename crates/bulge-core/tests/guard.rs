//! Guard wired into the loop: a denied tool is blocked (model continues), and a
//! runaway loop (same failing tool repeated) stops the job as Stuck.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bulge_core::dispatch::{ToolCall, ToolDispatcher};
use bulge_core::driver::{Driver, GuardConfig, LoopOutcome};
use bulge_core::schedule::CallOutcome;
use bulge_guard::{Autonomy as GAutonomy, Effect, Rule};
use bulge_llm::{ContentBlock, FinishReason, LlmBackend, Message, ModelInfo, Role, StreamChunk, TokenUsage};
use bulge_store::{Autonomy, Budget, JobEvent, JobHandle, JobSpec, JobStatus, JobStore, ModelRef};
use futures::FutureExt;
use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use serde_json::json;
use tokio_util::sync::CancellationToken;

struct ScriptBackend {
    turns: Mutex<VecDeque<Vec<ContentBlock>>>,
    models: Vec<ModelInfo>,
}
impl ScriptBackend {
    fn repeating(block: ContentBlock) -> Arc<Self> {
        // The same tool call forever (ids differ each time, like a real model).
        let turns = Mutex::new(VecDeque::new());
        Arc::new(Self { turns, models: vec![model()] }).seed(block)
    }
    fn seed(self: Arc<Self>, block: ContentBlock) -> Arc<Self> {
        for i in 0..40 {
            let b = match &block {
                ContentBlock::ToolCall { name, arguments, .. } => ContentBlock::ToolCall { id: format!("c{i}"), name: name.clone(), arguments: arguments.clone() },
                other => other.clone(),
            };
            self.turns.lock().unwrap().push_back(vec![b]);
        }
        self
    }
    fn scripted(turns: Vec<Vec<ContentBlock>>) -> Arc<Self> {
        Arc::new(Self { turns: Mutex::new(turns.into()), models: vec![model()] })
    }
}
fn model() -> ModelInfo {
    ModelInfo { id: "m".into(), context_window: 100_000, max_tokens: 4096, system_prompt_update: Default::default(), deferred_tools: false, images: false, reasoning: false }
}
impl LlmBackend for ScriptBackend {
    fn id(&self) -> &str { "fake" }
    fn models(&self) -> &[ModelInfo] { &self.models }
    fn stream(&self, _r: bulge_llm::GenerateRequest, _c: CancellationToken) -> BoxStream<'static, StreamChunk> {
        let blocks = self.turns.lock().unwrap().pop_front().unwrap_or_else(|| vec![ContentBlock::Text { text: "stop".into() }]);
        let has_tools = blocks.iter().any(|b| matches!(b, ContentBlock::ToolCall { .. }));
        let mut chunks: Vec<StreamChunk> = blocks.into_iter().enumerate().map(|(i, b)| StreamChunk::BlockEnd { index: i, block: b }).collect();
        chunks.push(StreamChunk::Usage(TokenUsage { output_tokens: 5, ..Default::default() }));
        chunks.push(StreamChunk::Finish(if has_tools { FinishReason::ToolCalls } else { FinishReason::Stop }));
        futures::stream::iter(chunks).boxed()
    }
}

/// Always fails with the same error (no progress), to trip the loop detector.
struct FailingDispatcher {
    ran: Mutex<usize>,
}
impl ToolDispatcher for FailingDispatcher {
    fn dispatch(&self, _call: ToolCall, _c: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        *self.ran.lock().unwrap() += 1;
        async move { CallOutcome::Err { code: "BOOM".into(), message: "same failure".into() } }.boxed()
    }
    fn concurrency_safe(&self, name: &str) -> bool { bulge_core::builtin_concurrency_safe(name) }
}

struct OkDispatcher {
    ran: Mutex<Vec<String>>,
}
impl ToolDispatcher for OkDispatcher {
    fn dispatch(&self, call: ToolCall, _c: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        self.ran.lock().unwrap().push(call.name.clone());
        async move { CallOutcome::Ok(json!({ "echo": call.name })) }.boxed()
    }
    fn concurrency_safe(&self, name: &str) -> bool { bulge_core::builtin_concurrency_safe(name) }
}

fn job(budget: Budget) -> JobHandle {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("bulge-guard-it-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let mut h = JobStore::new(root)
        .create(JobSpec {
            id: "j".into(), title: "t".into(), goal: "g".into(), workspace: PathBuf::from("/tmp/ws"),
            autonomy: Autonomy::Autonomous, budget, model: ModelRef { backend: "fake".into(), model: "m".into() },
        })
        .unwrap();
    h.append(vec![JobEvent::Message { message: Message::text(Role::User, "go") }]).unwrap();
    h
}

fn guard(rules: Vec<Rule>) -> GuardConfig {
    GuardConfig { rules, autonomy: GAutonomy::Autonomous, loop_detection: true }
}

#[tokio::test]
async fn repeated_identical_failure_stops_the_job() {
    let backend = ScriptBackend::repeating(ContentBlock::ToolCall { id: "c".into(), name: "exec".into(), arguments: json!({ "command": "make" }).to_string() });
    let dispatcher = Arc::new(FailingDispatcher { ran: Mutex::new(0) });
    let mut job = job(Budget { max_steps: 100, max_tokens: 10_000_000, max_wall_secs: 3600 });
    let driver = Driver::new(backend, dispatcher.clone(), bulge_core::builtin_tools(), "sp".into()).with_guard(guard(vec![Rule::new("*", "*", Effect::Allow)]));
    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stuck);
    assert_eq!(job.state().status, JobStatus::Incomplete);
    // IDENTICAL_ERROR_STOP = 3: it must stop quickly, not run dozens of times.
    assert!(*dispatcher.ran.lock().unwrap() <= 4, "should stop after a few identical failures");
}

#[tokio::test]
async fn denied_tool_is_blocked_but_the_model_continues() {
    let backend = ScriptBackend::scripted(vec![
        vec![ContentBlock::ToolCall { id: "c1".into(), name: "exec".into(), arguments: json!({ "command": "rm -rf /" }).to_string() }],
        vec![ContentBlock::Text { text: "understood, stopping".into() }],
    ]);
    let dispatcher = Arc::new(OkDispatcher { ran: Mutex::new(Vec::new()) });
    let mut job = job(Budget { max_steps: 100, max_tokens: 10_000_000, max_wall_secs: 3600 });
    let rules = vec![Rule::new("*", "*", Effect::Allow), Rule::new("exec", "rm *", Effect::Deny)];
    let driver = Driver::new(backend, dispatcher.clone(), bulge_core::builtin_tools(), "sp".into()).with_guard(guard(rules));
    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert!(dispatcher.ran.lock().unwrap().is_empty(), "denied exec must not run");
    // The model saw a PERMISSION_DENIED tool result.
    let saw_denial = job.state().history.iter().any(|m| m.content.iter().any(|b| matches!(b, ContentBlock::Text { text } if text.contains("PERMISSION_DENIED"))));
    assert!(saw_denial, "model must be told the tool was blocked");
}

#[tokio::test]
async fn allowed_tools_run_normally_with_guard_on() {
    let backend = ScriptBackend::scripted(vec![
        vec![ContentBlock::ToolCall { id: "c1".into(), name: "read".into(), arguments: json!({ "path": "a.txt" }).to_string() }],
        vec![ContentBlock::Text { text: "done".into() }],
    ]);
    let dispatcher = Arc::new(OkDispatcher { ran: Mutex::new(Vec::new()) });
    let mut job = job(Budget { max_steps: 100, max_tokens: 10_000_000, max_wall_secs: 3600 });
    let driver = Driver::new(backend, dispatcher.clone(), bulge_core::builtin_tools(), "sp".into()).with_guard(guard(vec![Rule::new("*", "*", Effect::Allow)]));
    let outcome = driver.run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(dispatcher.ran.lock().unwrap().as_slice(), ["read"]);
}
