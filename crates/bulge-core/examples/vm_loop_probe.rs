//! C2 acceptance: the agent loop drives a REAL guest VM (real tools, real
//! workspace overlay, real job log) with a scripted model, so no API key is
//! needed. Proves loop <-> VM <-> store wiring end to end.
//!
//! usage: vm_loop_probe <workspace-dir> <store-root>

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bulge_core::driver::Driver;
use bulge_core::{VmDispatcher, builtin_tools};
use bulge_llm::{ContentBlock, FinishReason, LlmBackend, ModelInfo, StreamChunk, TokenUsage};
use bulge_llm::{Message, Role};
use bulge_store::{Autonomy, Budget, JobEvent, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::changes;
use bulge_vm::vm::{Vm, VmConfig};
use futures::StreamExt;
use futures::stream::BoxStream;
use serde_json::json;
use tokio_util::sync::CancellationToken;

/// Scripted model: one assistant turn per call.
struct ScriptBackend {
    turns: Mutex<VecDeque<Vec<ContentBlock>>>,
    models: Vec<ModelInfo>,
}

impl LlmBackend for ScriptBackend {
    fn id(&self) -> &str {
        "script"
    }
    fn models(&self) -> &[ModelInfo] {
        &self.models
    }
    fn stream(&self, _r: bulge_llm::GenerateRequest, _c: CancellationToken) -> BoxStream<'static, StreamChunk> {
        let blocks = self.turns.lock().unwrap().pop_front().unwrap_or_else(|| vec![ContentBlock::Text { text: "done".into() }]);
        let has_tools = blocks.iter().any(|b| matches!(b, ContentBlock::ToolCall { .. }));
        let mut chunks: Vec<StreamChunk> = blocks.into_iter().enumerate().map(|(i, block)| StreamChunk::BlockEnd { index: i, block }).collect();
        chunks.push(StreamChunk::Usage(TokenUsage { output_tokens: 20, ..Default::default() }));
        chunks.push(StreamChunk::Finish(if has_tools { FinishReason::ToolCalls } else { FinishReason::Stop }));
        futures::stream::iter(chunks).boxed()
    }
}

fn call(id: &str, name: &str, args: serde_json::Value) -> ContentBlock {
    ContentBlock::ToolCall { id: id.into(), name: name.into(), arguments: args.to_string() }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let workspace = PathBuf::from(args.next().ok_or("usage: vm_loop_probe <workspace> <store-root>")?);
    let store_root = PathBuf::from(args.next().ok_or("usage: vm_loop_probe <workspace> <store-root>")?);
    let home = PathBuf::from(std::env::var("HOME")?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    let vm = Arc::new(
        Vm::launch(VmConfig {
            vmm_binary: repo.join("target/debug/bulge-vmm"),
            libkrun_dir: home.join(".local/lib"),
            rootfs: home.join(".bulge/rootfs/current"),
            workspace: workspace.clone(),
            runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
            cpus: 2,
            ram_mib: 1024,
            network: false,
            egress_allow: Vec::new(),
            egress_approvals: None,
            real_world: std::sync::Arc::new(bulge_guard::RealWorldPolicy::defaults()),
        })
        .await?,
    );

    let backend = Arc::new(ScriptBackend {
        turns: Mutex::new(VecDeque::from(vec![
            vec![call("c1", "write", json!({ "path": "report.md", "content": "# Report\n\ndraft\n" }))],
            vec![call("c2", "edit", json!({ "path": "report.md", "old_string": "draft", "new_string": "final" }))],
            vec![call("c3", "read", json!({ "path": "report.md" }))],
            vec![call("c4", "exec", json!({ "command": "ls -1 && wc -l report.md" }))],
            vec![ContentBlock::Text { text: "Report written and verified.".into() }],
        ])),
        models: vec![ModelInfo { id: "script".into(), context_window: 100_000, max_tokens: 4096, system_prompt_update: Default::default(), deferred_tools: false, images: false, reasoning: false }],
    });
    let dispatcher = Arc::new(VmDispatcher::new(vm.clone(), Duration::from_secs(60)));

    let store = JobStore::new(&store_root);
    let mut job = store.create(JobSpec {
        id: bulge_store::new_job_id()?,
        title: "write a report".into(),
        goal: "Write report.md and verify it.".into(),
        workspace: workspace.clone(),
        autonomy: Autonomy::Autonomous,
        budget: Budget::default(),
        model: ModelRef { backend: "script".into(), model: "script".into() },
    })?;
    job.append(vec![JobEvent::Message { message: Message::text(Role::User, "Write a short report.md, finalize it, and verify.") }])?;

    let driver = Driver::new(backend, dispatcher, builtin_tools(), "You are bulge.".into());
    let outcome = driver.run(&mut job, CancellationToken::new()).await?;

    println!("outcome: {outcome:?}");
    println!("status:  {:?}", job.state().status);
    println!("summary: {:?}", job.state().summary);
    println!("steps:   {}  tokens: {}", job.state().steps, job.state().usage.total());
    println!("pending calls (should be 0): {}", job.state().pending_calls.len());
    let tool_results = job.state().history.iter().filter(|m| m.tool_call_id.is_some()).count();
    println!("tool results in history: {tool_results}");

    // The write/edit happened in the VM overlay; the host workspace is untouched
    // until changes are approved and applied.
    let host_before = std::fs::read_to_string(workspace.join("report.md")).unwrap_or_else(|_| "(absent on host)".into());
    println!("host report.md before apply: {host_before:?}");
    let pending = changes::collect(&vm).await?;
    println!("pending workspace changes: {:?}", pending.iter().map(|c| c.path()).collect::<Vec<_>>());

    let ok = job.state().status == JobStatus::Succeeded && job.state().pending_calls.is_empty() && tool_results == 4 && pending.iter().any(|c| c.path() == "report.md");
    println!("{}", if ok { "PASS C2 loop<->VM" } else { "FAIL C2 loop<->VM" });

    // Release the dispatcher's VM handle, then shut the VM down.
    drop(driver);
    if let Ok(vm) = Arc::try_unwrap(vm) {
        vm.shutdown().await;
    }
    std::process::exit(i32::from(!ok));
}
