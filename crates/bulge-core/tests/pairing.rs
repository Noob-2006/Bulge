//! Every request the driver sends must pass the provider's tool call/result
//! pairing rule (an assistant tool call is answered immediately, before any
//! other message), on every path: loop warnings and stops, truncated and
//! failed turns, duplicate ids, plain-text calls, and logs left by older
//! versions. The fake backend validates each request with the real OpenAI
//! encoder, which rejects exactly what DeepSeek/OpenAI reject.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bulge_core::dispatch::{ToolCall, ToolDispatcher};
use bulge_core::driver::{Driver, GuardConfig, LoopOutcome};
use bulge_core::schedule::CallOutcome;
use bulge_guard::{Autonomy as GAutonomy, Effect, Rule};
use bulge_llm::protocol::openai_chat::OpenAiChat;
use bulge_llm::protocol::{EncodeContext, WireProtocol};
use bulge_llm::{
    ContentBlock, ErrorCode, FinishReason, GenerateRequest, LlmBackend, LlmError, Message, ModelInfo, Purpose, Role, StreamChunk,
    TokenUsage,
};
use bulge_store::{Autonomy, Budget, JobEvent, JobHandle, JobSpec, JobStatus, JobStore, ModelRef};
use futures::FutureExt;
use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use serde_json::json;
use tokio_util::sync::CancellationToken;

fn model() -> ModelInfo {
    ModelInfo {
        id: "m".into(),
        context_window: 100_000,
        max_tokens: 4096,
        system_prompt_update: Default::default(),
        deferred_tools: false,
        images: false,
        reasoning: false,
        default_effort: None,
    }
}

/// Validate a request the way the OpenAI-compatible route does before sending.
fn encode(request: &GenerateRequest) -> Result<(), LlmError> {
    let model = model();
    OpenAiChat.encode(request, &EncodeContext { model: &model, default_max_tokens: 1024 }).map(|_| ())
}

enum Turn {
    /// Blocks, then usage, then this finish reason.
    Reply(Vec<ContentBlock>, FinishReason),
    /// The same tool call, forever (for loop detection).
    Forever(ContentBlock),
}

struct Backend {
    turns: Mutex<VecDeque<Turn>>,
    models: Vec<ModelInfo>,
    /// Requests the encoder rejected: must stay empty.
    rejected: Mutex<Vec<String>>,
}

impl Backend {
    fn new(turns: Vec<Turn>) -> Arc<Self> {
        Arc::new(Self { turns: Mutex::new(turns.into()), models: vec![model()], rejected: Mutex::new(Vec::new()) })
    }
}

impl LlmBackend for Backend {
    fn id(&self) -> &str {
        "fake"
    }
    fn models(&self) -> &[ModelInfo] {
        &self.models
    }
    fn stream(&self, request: GenerateRequest, _cancel: CancellationToken) -> BoxStream<'static, StreamChunk> {
        if let Err(error) = encode(&request) {
            self.rejected.lock().unwrap().push(error.message.clone());
            return futures::stream::iter(vec![StreamChunk::Finish(FinishReason::Error(error))]).boxed();
        }
        let mut turns = self.turns.lock().unwrap();
        let (blocks, finish) = match turns.front() {
            Some(Turn::Forever(block)) => (vec![block.clone()], FinishReason::ToolCalls),
            Some(Turn::Reply(..)) => match turns.pop_front() {
                Some(Turn::Reply(blocks, finish)) => (blocks, finish),
                _ => unreachable!(),
            },
            None => (vec![ContentBlock::Text { text: "(no script left)".into() }], FinishReason::Stop),
        };
        let mut chunks: Vec<StreamChunk> = blocks.into_iter().enumerate().map(|(index, block)| StreamChunk::BlockEnd { index, block }).collect();
        chunks.push(StreamChunk::Usage(TokenUsage { output_tokens: 10, ..Default::default() }));
        chunks.push(StreamChunk::Finish(finish));
        futures::stream::iter(chunks).boxed()
    }
}

#[derive(Default)]
struct Dispatcher {
    seen: Mutex<Vec<ToolCall>>,
    fail: bool,
}

impl ToolDispatcher for Dispatcher {
    fn dispatch(&self, call: ToolCall, _cancel: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        self.seen.lock().unwrap().push(call.clone());
        let outcome = if self.fail {
            CallOutcome::Err { code: "EXIT_1".into(), message: "make: *** no rule".into() }
        } else {
            CallOutcome::Ok(json!({ "echo": call.name }))
        };
        async move { outcome }.boxed()
    }
    fn concurrency_safe(&self, name: &str) -> bool {
        bulge_core::builtin_concurrency_safe(name)
    }
}

fn call(id: &str, name: &str, args: serde_json::Value) -> ContentBlock {
    ContentBlock::ToolCall { id: id.into(), name: name.into(), arguments: args.to_string() }
}
fn text(t: &str) -> ContentBlock {
    ContentBlock::Text { text: t.into() }
}
fn stop(blocks: Vec<ContentBlock>) -> Turn {
    let finish = if blocks.iter().any(|b| matches!(b, ContentBlock::ToolCall { .. })) { FinishReason::ToolCalls } else { FinishReason::Stop };
    Turn::Reply(blocks, finish)
}

fn store_root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("bulge-pairing-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn spec() -> JobSpec {
    JobSpec {
        id: "j".into(),
        title: "t".into(),
        goal: "g".into(),
        workspace: PathBuf::from("/tmp/ws"),
        autonomy: Autonomy::Autonomous,
        budget: Budget { max_steps: 60, max_tokens: 10_000_000, max_wall_secs: 3600 },
        model: ModelRef { backend: "fake".into(), model: "m".into() },
    }
}

fn job() -> JobHandle {
    let mut handle = JobStore::new(store_root()).create(spec()).unwrap();
    handle.append(vec![JobEvent::Message { message: Message::text(Role::User, "go") }]).unwrap();
    handle
}

fn driver(backend: Arc<Backend>, dispatcher: Arc<Dispatcher>) -> Driver {
    Driver::new(backend, dispatcher, bulge_core::builtin_tools(), "sp".into())
}

/// The next turn on this history (a user follow-up) must be sendable.
fn assert_followup_sendable(job: &JobHandle) {
    let mut messages = vec![Message::text(Role::System, "sp")];
    messages.extend(job.state().history.iter().cloned());
    messages.push(Message::text(Role::User, "next"));
    let request = GenerateRequest {
        model: "m".into(),
        messages,
        tools: bulge_core::builtin_tools(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose: Purpose::Conversation,
    };
    if let Err(error) = encode(&request) {
        panic!("logged history is not sendable: {error}");
    }
}

#[tokio::test]
async fn loop_detection_never_splits_a_call_from_its_result() {
    // The same failing call forever: the detector warns, then stops the job.
    let backend = Backend::new(vec![Turn::Forever(call("c", "exec", json!({ "command": "make" })))]);
    let dispatcher = Arc::new(Dispatcher { fail: true, ..Default::default() });
    let mut job = job();
    let guard = GuardConfig { rules: vec![Rule::new("*", "*", Effect::Allow)], autonomy: GAutonomy::Autonomous, loop_detection: true };
    let outcome = driver(backend.clone(), dispatcher).with_guard(guard).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stuck, "rejected requests: {:?}", backend.rejected.lock().unwrap());
    assert!(backend.rejected.lock().unwrap().is_empty());
    assert!(job.state().pending_calls.is_empty());
    assert_followup_sendable(&job);
}

#[tokio::test]
async fn a_reply_cut_off_by_max_tokens_is_continued_not_accepted() {
    let backend = Backend::new(vec![
        Turn::Reply(vec![text("Here is the first half")], FinishReason::MaxTokens),
        stop(vec![text("and the complete answer.")]),
    ]);
    let mut job = job();
    let outcome = driver(backend.clone(), Arc::default()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert_eq!(job.state().status, JobStatus::Succeeded);
    assert_eq!(job.state().summary.as_deref(), Some("and the complete answer."));
    assert!(job.state().history.iter().any(|m| m.role == Role::User && assistant_like_text(m).contains("cut off")));
}

fn assistant_like_text(message: &Message) -> String {
    message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_turn_that_fails_mid_call_leaves_no_unanswered_call() {
    let error = LlmError::new(ErrorCode::InvalidRequest, "provider rejected the stream");
    let backend = Backend::new(vec![Turn::Reply(vec![text("Let me check"), call("c1", "read", json!({ "path": "a" }))], FinishReason::Error(error))]);
    let dispatcher = Arc::new(Dispatcher::default());
    let mut job = job();
    let outcome = driver(backend, dispatcher.clone()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Failed);
    assert!(dispatcher.seen.lock().unwrap().is_empty(), "a failed turn's calls never run");
    assert_followup_sendable(&job);

    // The conversation continues on the same job.
    job.append(vec![JobEvent::Message { message: Message::text(Role::User, "try again") }]).unwrap();
    let backend = Backend::new(vec![stop(vec![text("done")])]);
    let outcome = driver(backend.clone(), dispatcher).run(&mut job, CancellationToken::new()).await.unwrap();
    assert_eq!(outcome, LoopOutcome::Stopped);
    assert!(backend.rejected.lock().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_and_empty_call_ids_are_made_unique() {
    let backend = Backend::new(vec![
        stop(vec![call("x", "read", json!({ "path": "a" })), call("x", "read", json!({ "path": "b" })), call("", "read", json!({ "path": "c" }))]),
        stop(vec![text("done")]),
    ]);
    let dispatcher = Arc::new(Dispatcher::default());
    let mut job = job();
    let outcome = driver(backend.clone(), dispatcher.clone()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped, "rejected: {:?}", backend.rejected.lock().unwrap());
    assert_eq!(dispatcher.seen.lock().unwrap().len(), 3);
    assert!(backend.rejected.lock().unwrap().is_empty());
    assert_followup_sendable(&job);
}

#[tokio::test]
async fn a_tool_call_written_as_text_is_run() {
    let backend = Backend::new(vec![
        stop(vec![text("<tool_call><function=read><parameter=path>a.txt</parameter></function></tool_call>")]),
        stop(vec![text("<tool_call>\n{\"name\": \"glob\", \"arguments\": {\"pattern\": \"*.md\"}}\n</tool_call>")]),
        stop(vec![text("done")]),
    ]);
    let dispatcher = Arc::new(Dispatcher::default());
    let mut job = job();
    let outcome = driver(backend.clone(), dispatcher.clone()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    let seen = dispatcher.seen.lock().unwrap();
    assert_eq!(seen.iter().map(|call| call.name.as_str()).collect::<Vec<_>>(), ["read", "glob"]);
    assert_eq!(job.state().summary.as_deref(), Some("done"));
    assert!(backend.rejected.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_log_left_with_an_unanswered_call_still_resumes() {
    // What older versions could leave: a call with no claim and no result,
    // followed by another message.
    let mut job = job();
    job.append(vec![
        JobEvent::Message { message: Message { role: Role::Assistant, content: vec![call("old", "read", json!({ "path": "a" }))], tool_call_id: None, is_error: None, source_model: Some("m".into()) } },
        JobEvent::Message { message: Message::text(Role::User, "loop warning from an older version") },
    ])
    .unwrap();
    let backend = Backend::new(vec![stop(vec![text("done")])]);
    let outcome = driver(backend.clone(), Arc::default()).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped, "rejected: {:?}", backend.rejected.lock().unwrap());
}

#[tokio::test]
async fn a_finished_job_with_an_open_claim_is_closed_on_reopen() {
    let root = store_root();
    let store = JobStore::new(root);
    let mut handle = store.create(spec()).unwrap();
    handle
        .append(vec![
            JobEvent::Message { message: Message::text(Role::User, "go") },
            JobEvent::Message { message: Message { role: Role::Assistant, content: vec![call("c1", "exec", json!({ "command": "x" }))], tool_call_id: None, is_error: None, source_model: Some("m".into()) } },
            JobEvent::ToolClaimed { call_id: "c1".into(), name: "exec".into(), arguments: json!({ "command": "x" }) },
            JobEvent::StatusChanged { status: JobStatus::Failed, summary: Some("crashed".into()) },
        ])
        .unwrap();
    let id = handle.state().spec.id.clone();
    drop(handle);

    let (handle, recovery) = store.open(&id).unwrap();
    assert_eq!(recovery.interrupted_calls, vec!["c1".to_string()]);
    assert!(handle.state().pending_calls.is_empty());
    assert_followup_sendable(&handle);
}

struct OneSkill;
impl bulge_core::driver::SkillHandler for OneSkill {
    fn load(&self, name: &str) -> Result<String, String> {
        if name == "release" { Ok("# Skill: release\n1. Tag it.".into()) } else { Err(format!("no skill named `{name}`")) }
    }
}

#[tokio::test]
async fn skill_calls_are_answered_on_the_host() {
    let backend = Backend::new(vec![
        stop(vec![call("s1", "skill", json!({ "name": "release" })), call("s2", "skill", json!({ "name": "missing" }))]),
        stop(vec![text("done")]),
    ]);
    let dispatcher = Arc::new(Dispatcher::default());
    let mut job = job();
    let outcome = driver(backend.clone(), dispatcher.clone()).with_skills(Arc::new(OneSkill)).run(&mut job, CancellationToken::new()).await.unwrap();

    assert_eq!(outcome, LoopOutcome::Stopped);
    assert!(dispatcher.seen.lock().unwrap().is_empty(), "skills never reach the VM");
    let result = |id: &str| job.state().history.iter().find(|m| m.tool_call_id.as_deref() == Some(id)).map(assistant_like_text).unwrap();
    assert!(result("s1").contains("1. Tag it."));
    assert!(result("s2").contains("BAD_SKILL"));
    assert!(backend.rejected.lock().unwrap().is_empty());
}
