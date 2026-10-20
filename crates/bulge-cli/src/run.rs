//! `bulge run`: create a job, launch the sandbox VM, drive the agent loop to
//! completion, stream every logged event as JSONL, then (offline) propose
//! lessons for next time. Workspace changes stay in the VM overlay; the host is
//! never modified — the collected diff is written out for the user to review.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bulge_core::driver::{CompletionConfig, ContextConfig, Driver, GuardConfig, LoopOutcome};
use bulge_core::{VmDispatcher, builtin_tools, plan_tool};
use bulge_guard::{Effect, Rule};
use bulge_harness::{SurfaceSpec, Tree};
use bulge_llm::{GenerateRequest, LlmBackend, Message, Purpose, Role};
use bulge_store::{Autonomy, Budget, JobEvent, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::changes;
use bulge_vm::vm::{Vm, VmConfig};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::backend::{self, BackendSpec};

/// A cautious default prompt used when no harness tree is present.
const DEFAULT_SYSTEM_PROMPT: &str = "\
You are bulge, a careful general-purpose agent working inside a sandboxed Linux VM. \
The workspace is yours; the host and the wider machine are not reachable. Work toward \
the user's goal with the provided tools. Prefer small, verifiable steps. Keep a plan \
with the plan tool and mark items done as you go. When you believe the work is complete, \
stop calling tools and state plainly what you produced and how you verified it.";

/// How many memory lessons to retrieve into the prompt.
const LESSON_COUNT: usize = 5;

pub struct RunConfig {
    /// `Some(id)` continues an existing conversation (a follow-up turn on that job);
    /// `None` starts a fresh job.
    pub job_id: Option<String>,
    pub goal: String,
    pub title: String,
    pub workspace: PathBuf,
    pub store_root: PathBuf,
    pub harness_dir: PathBuf,
    pub autonomy: Autonomy,
    pub budget: Budget,
    pub backend: BackendSpec,
    pub network: bool,
    pub cpus: u8,
    pub ram_mib: u32,
}

/// Map the store's autonomy onto the guard's equivalent (no shared type).
fn guard_autonomy(autonomy: Autonomy) -> bulge_guard::Autonomy {
    match autonomy {
        Autonomy::Collaborative => bulge_guard::Autonomy::Collaborative,
        Autonomy::Autonomous => bulge_guard::Autonomy::Autonomous,
        Autonomy::FullAuto => bulge_guard::Autonomy::FullAuto,
    }
}

/// A modest baseline ruleset. The VM sandbox is the real boundary; these denies
/// are a second line against obviously destructive guest commands.
fn default_ruleset() -> Vec<Rule> {
    vec![
        Rule::new("*", "*", Effect::Allow),
        Rule::new("exec", "rm -rf /*", Effect::Deny),
        Rule::new("exec", "rm -fr /*", Effect::Deny),
    ]
}

/// Read a directory tree into an in-memory `Tree` (relative path → UTF-8 text).
/// Non-UTF-8 and unreadable files are skipped. Missing dir → empty tree.
fn read_tree(root: &Path) -> Tree {
    let mut tree = Tree::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(content) = std::fs::read_to_string(&path)
                && let Ok(rel) = path.strip_prefix(root)
            {
                tree.insert(rel.to_string_lossy().replace('\\', "/"), content);
            }
        }
    }
    tree
}

/// Build the system prompt: the harness surface (or the default prompt), plus the
/// most relevant memory lessons for this goal.
fn build_system_prompt(harness_dir: &Path, goal: &str) -> String {
    let tree = read_tree(harness_dir);
    let spec = SurfaceSpec::default();
    let mut prompt = {
        let surfaced = bulge_harness::materialize(&tree, &spec);
        if surfaced.trim().is_empty() { DEFAULT_SYSTEM_PROMPT.to_string() } else { surfaced }
    };

    let memory_root = harness_dir.join("memory");
    if let Ok((lessons, _problems)) = bulge_harness::memory::load(&memory_root) {
        let hits = bulge_harness::retrieve(&lessons, goal, LESSON_COUNT);
        let brief = bulge_harness::brief(&hits);
        if !brief.is_empty() {
            prompt.push_str("\n\n");
            prompt.push_str(&brief);
        }
    }
    prompt
}

/// Receives each complete JSONL log line as it is committed (one call per line,
/// newline stripped). The CLI prints to stdout; the desktop app forwards each
/// line to the webview. `Send` so it can live in the tailing task.
pub type LineSink = Box<dyn FnMut(&str) + Send>;

/// Stream newly-appended complete lines of a JSONL file to `sink` until `stop`
/// is cancelled, then flush once more. The store writes the log atomically with
/// fsync, so reading committed bytes is safe from this separate reader.
async fn tail_jsonl(path: PathBuf, stop: CancellationToken, mut sink: LineSink, start_offset: usize) {
    let mut offset = start_offset;
    loop {
        offset = flush_new_lines(&path, offset, &mut sink);
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(Duration::from_millis(120)) => {}
        }
    }
    // Final flush: the last events were appended just before the loop ended.
    flush_new_lines(&path, offset, &mut sink);
}

/// Hand each complete line starting at `offset` to `sink`; return the new offset
/// (end of the last newline consumed).
fn flush_new_lines(path: &Path, offset: usize, sink: &mut LineSink) -> usize {
    let Ok(bytes) = std::fs::read(path) else { return offset };
    if bytes.len() <= offset {
        return offset;
    }
    let fresh = &bytes[offset..];
    let Some(last_newline) = fresh.iter().rposition(|&b| b == b'\n') else {
        return offset;
    };
    let printable = &fresh[..=last_newline];
    if let Ok(text) = std::str::from_utf8(printable) {
        for line in text.lines() {
            if !line.is_empty() {
                sink(line);
            }
        }
    }
    offset + last_newline + 1
}

/// The default sink: print each line to stdout, as the headless CLI does.
fn stdout_sink() -> LineSink {
    Box::new(|line: &str| {
        use std::io::Write;
        println!("{line}");
        let _ = std::io::stdout().flush();
    })
}

/// What a completed run produced.
pub struct RunOutcome {
    pub outcome: LoopOutcome,
    pub status: bulge_store::JobStatus,
    pub job_dir: PathBuf,
    /// The host workspace the job ran against (where approved changes are applied).
    pub workspace: PathBuf,
    /// The collected workspace diff, if any changes were made.
    pub diff: Option<String>,
    /// The structured changes behind the diff, kept so a caller (the app) can
    /// apply the approved subset to the host after review. The host is never
    /// modified by the run itself.
    pub changes: Vec<changes::Change>,
}

/// Run one job end to end, printing its event log to stdout (the headless CLI
/// path). Equivalent to [`run_streaming`] with a stdout sink and a fresh,
/// never-cancelled token.
pub async fn run(config: RunConfig) -> Result<RunOutcome, String> {
    run_streaming(config, CancellationToken::new(), stdout_sink()).await
}

/// Run one job end to end, streaming each committed log line to `sink` and
/// honouring `cancel` as an emergency stop. Workspace changes stay in the VM
/// overlay; the collected diff and structured changes are returned for review.
pub async fn run_streaming(config: RunConfig, cancel: CancellationToken, sink: LineSink) -> Result<RunOutcome, String> {
    let backend = backend::build(&config.backend)?;
    let system_prompt = build_system_prompt(&config.harness_dir, &config.goal);

    // New job, or a follow-up turn on an existing conversation.
    let store = JobStore::new(&config.store_root);
    let resuming = config.job_id.is_some();
    let mut job = match &config.job_id {
        // Follow-up: reopen the conversation, append the new user turn, and (best
        // effort) flip a finished job back to Running for this turn. History is
        // replayed by the driver, so the agent remembers the whole conversation.
        Some(id) => {
            let (mut job, _recovery) = store.open(id).map_err(|e| format!("open job: {e}"))?;
            job.append(vec![JobEvent::Message { message: Message::text(Role::User, config.goal.clone()) }])
                .map_err(|e| format!("append turn: {e}"))?;
            let _ = job.append(vec![JobEvent::StatusChanged { status: JobStatus::Running, summary: None }]);
            job
        }
        None => {
            let job_id = bulge_store::new_job_id().map_err(|e| format!("job id: {e}"))?;
            let mut job = store
                .create(JobSpec {
                    id: job_id.clone(),
                    title: config.title.clone(),
                    goal: config.goal.clone(),
                    workspace: config.workspace.clone(),
                    autonomy: config.autonomy,
                    budget: config.budget.clone(),
                    model: ModelRef { backend: config.backend.id.clone(), model: config.backend.model.clone() },
                })
                .map_err(|e| format!("create job: {e}"))?;
            job.append(vec![JobEvent::Message { message: Message::text(Role::User, config.goal.clone()) }])
                .map_err(|e| format!("seed goal: {e}"))?;
            job
        }
    };

    let log_path = job.dir().join("job.jsonl");
    // On a follow-up, the log already holds the previous turns; stream only the new
    // events (start the tail at the current end of file) so the UI doesn't duplicate
    // the transcript it already shows.
    let tail_start = if resuming { std::fs::metadata(&log_path).map(|m| m.len() as usize).unwrap_or(0) } else { 0 };

    // Launch the sandbox VM.
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vm = Arc::new(
        Vm::launch(VmConfig {
            vmm_binary: repo.join("target/debug/bulge-vmm"),
            libkrun_dir: home.join(".local/lib"),
            rootfs: home.join(".bulge/rootfs/current"),
            workspace: config.workspace.clone(),
            runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
            cpus: config.cpus,
            ram_mib: config.ram_mib,
            // Never attach the raw NIC. When the user enables network, outbound goes
            // through the two-key gateway which allows any PUBLIC host ("*") while the
            // gateway still blocks private/LAN/cloud-metadata addresses (DNS-rebind
            // safe). The roadmap's stance: allow public internet, block the host/LAN.
            network: false,
            egress_allow: if config.network { vec!["*".to_string()] } else { Vec::new() },
        })
        .await
        .map_err(|e| format!("launch VM: {e}"))?,
    );

    // Assemble the driver.
    let dispatcher = Arc::new(VmDispatcher::new(vm.clone(), Duration::from_secs(120)));
    let mut tools = builtin_tools();
    tools.push(plan_tool());
    let context = ContextConfig { window: config.backend.context_window as u64, ..ContextConfig::default() };
    let driver = Driver::new(backend.clone(), dispatcher.clone(), tools, system_prompt)
        .with_guard(GuardConfig { rules: default_ruleset(), autonomy: guard_autonomy(config.autonomy), loop_detection: true })
        .with_completion_gate(CompletionConfig::default())
        .with_context(context);

    // Stream events while the loop runs.
    let stop = CancellationToken::new();
    let tail = tokio::spawn(tail_jsonl(log_path.clone(), stop.clone(), sink, tail_start));

    let outcome = driver.run(&mut job, cancel).await.map_err(|e| format!("run: {e}"))?;

    stop.cancel();
    let _ = tail.await;

    // Collect workspace changes and write the diff out (the host is not touched).
    let mut diff: Option<String> = None;
    let mut collected: Vec<changes::Change> = Vec::new();
    if let Ok(pending) = changes::collect(&vm).await {
        if pending.is_empty() {
            eprintln!("no workspace changes");
        } else {
            let rendered = changes::render_diff(&config.workspace, &pending);
            let diff_path = job.dir().join("changes.diff");
            if std::fs::write(&diff_path, &rendered).is_ok() {
                eprintln!("{} change(s) written to {}", pending.len(), diff_path.display());
            }
            diff = Some(rendered);
            collected = pending;
        }
    }

    // Release VM handles and shut it down.
    drop(driver);
    drop(dispatcher);
    if let Ok(vm) = Arc::try_unwrap(vm) {
        vm.shutdown().await;
    }

    // Offline improvement: propose lessons from the finished job. Best-effort.
    improve(backend.as_ref(), &mut job, &config).await;

    eprintln!("outcome: {outcome:?}  status: {:?}  summary: {:?}  steps: {}  tokens: {}", job.state().status, job.state().summary, job.state().steps, job.state().usage.total());
    Ok(RunOutcome {
        outcome,
        status: job.state().status,
        job_dir: job.dir().to_path_buf(),
        workspace: config.workspace.clone(),
        diff,
        changes: collected,
    })
}

/// Ask the model for durable lessons from this job and save them to memory.
async fn improve(backend: &dyn LlmBackend, job: &mut bulge_store::JobHandle, config: &RunConfig) {
    let mut messages = Vec::with_capacity(job.state().history.len() + 1);
    messages.push(Message::text(Role::System, "You review a finished job and extract durable lessons."));
    messages.extend(job.state().history.iter().cloned());
    messages.push(Message::text(Role::User, bulge_harness::PROPOSE_LESSONS_PROMPT));

    let request = GenerateRequest {
        model: config.backend.model.clone(),
        messages,
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose: Purpose::Memory,
    };
    let mut stream = backend.stream(request, CancellationToken::new());
    let mut assembler = bulge_llm::assemble::Assembler::new();
    while let Some(chunk) = stream.next().await {
        assembler.push(&chunk);
    }
    let assembled = assembler.finish(&config.backend.model);
    let reply = assembled.message.content.iter().find_map(|b| match b {
        bulge_llm::ContentBlock::Text { text } => Some(text.clone()),
        _ => None,
    });
    let Some(reply) = reply else { return };

    let memory_root = config.harness_dir.join("memory");
    let existing_ids: Vec<String> = bulge_harness::memory::load(&memory_root)
        .map(|(lessons, _)| lessons.into_iter().map(|l| l.id).collect())
        .unwrap_or_default();
    let proposed = bulge_harness::parse_proposed_lessons(&reply, &existing_ids);
    let mut saved = 0_usize;
    for lesson in &proposed {
        if bulge_harness::memory::save(&memory_root, lesson).is_ok() {
            saved += 1;
        }
    }
    if saved > 0 {
        eprintln!("learned {saved} lesson(s) into {}", memory_root.join("lessons").display());
    }
}
