//! `bulge run`: create a job, launch the sandbox VM, drive the agent loop to
//! completion, stream every logged event as JSONL, then (offline) propose
//! lessons for next time. Workspace changes stay in the VM overlay; the host is
//! never modified — the collected diff is written out for the user to review.
//!
//! The run is structured around a [`Session`]: a live VM plus the store job it
//! serves. A session outlives a single turn, so a follow-up turn on the same
//! conversation reuses the *same* VM — in-VM file edits carry across turns — and
//! its VM can be restarted on its own (e.g. after a settings change) without
//! disturbing the conversation. The headless CLI runs exactly one turn and then
//! shuts the session down; the desktop app keeps a session alive and feeds it
//! more turns.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bulge_core::driver::{CompletionConfig, ContextConfig, Driver, GuardConfig, LoopOutcome, RequestPrefix, side_request, stream_toolless, watch_call};
pub use bulge_core::driver::Sampling;
use crate::delegate;
use bulge_core::hooks::{HookConfig, HookRunner, HookedDispatcher};
use bulge_core::mcp::{self, CompositeDispatcher, McpBundle};
use bulge_core::{ToolDispatcher, VmDispatcher, builtin_tools, plan_tool};
use bulge_guard::{Effect, Rule};
use bulge_harness::{SurfaceSpec, Tree};
use bulge_llm::{GenerateRequest, LlmBackend, Message, Purpose, Role};
use bulge_store::{Autonomy, Budget, JobEvent, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::changes;
use bulge_vm::vm::{Vm, VmConfig};
use tokio_util::sync::CancellationToken;

use crate::backend::{self, BackendSpec};

/// A cautious default prompt used when no harness tree is present.
const DEFAULT_SYSTEM_PROMPT: &str = "\
You are bulge, a careful general-purpose agent working inside a sandboxed Linux VM. \
The workspace is yours; the host and the wider machine are not reachable. Work toward \
the user's goal with the provided tools. Prefer small, verifiable steps. Keep a plan \
with the plan tool and mark items done as you go. When you believe the work is complete, \
stop calling tools and state plainly what you produced and how you verified it.\n\n\
Every extra model round-trip resends the whole conversation, so economise on turns, not \
on care: issue independent tool calls together in one turn (they run in parallel); chain \
dependent shell steps you would not need to inspect in between into one `exec` (e.g. \
create a file and run its check in the same command); trust tool results (a successful \
`write` landed — do not read it back). Save turns only by batching, never by checking \
less: given examples rarely cover a spec's edge cases, so test the cases the wording \
implies too — in the same `exec`.";

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
    /// Sampling controls threaded into the driver (temperature / reasoning effort /
    /// per-call output cap). `Default` means "let the provider decide".
    pub sampling: Sampling,
    /// Optional override of the agent's system prompt / persona. When set it
    /// replaces the harness surface (memory lessons are still appended).
    pub system_prompt: Option<String>,
    /// When set (and the job is collaborative with network on), egress to a host
    /// outside the package/dev allowlist raises an approval prompt on this channel
    /// instead of being allowed outright. `None` → allow any public host.
    pub egress_approvals: Option<bulge_vm::net::EgressApprovalTx>,
    /// Skip the offline learning loop (lessons/profile/skill proposals) when the
    /// session shuts down. Set for autonomous scheduled runs, where a ~30K-token
    /// review fork with no human in the loop is not worth it (matches Hermes).
    pub skip_review: bool,
    /// Enable the LLM review gate: a cheap reviewer model vets every mutating tool
    /// call before it runs. Extra latency/cost for a second safety opinion.
    pub auto_review: bool,
}

/// Current wall-clock time in Unix seconds (0 before the epoch, which never happens).
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map the store's autonomy onto the guard's equivalent (no shared type).
pub(crate) fn guard_autonomy(autonomy: Autonomy) -> bulge_guard::Autonomy {
    match autonomy {
        Autonomy::Collaborative => bulge_guard::Autonomy::Collaborative,
        Autonomy::Autonomous => bulge_guard::Autonomy::Autonomous,
        Autonomy::FullAuto => bulge_guard::Autonomy::FullAuto,
    }
}

/// A modest baseline ruleset. The VM sandbox is the real boundary; these denies
/// are a second line against obviously destructive guest commands.
pub(crate) fn default_ruleset() -> Vec<Rule> {
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

/// Build the system prompt: the explicit persona, else the user-authored
/// always-on harness files, else the default prompt. Only content that is
/// identical across jobs and turns belongs here — the provider's prefix cache
/// covers system + tools, so anything the agent itself rewrites (skills catalog,
/// profile) or that varies per job (lessons, past tasks) goes in
/// [`build_turn_context`].
fn build_system_prompt(harness_dir: &Path, persona: Option<&str>) -> String {
    match persona {
        Some(text) if !text.trim().is_empty() => text.to_string(),
        _ => {
            let surfaced = bulge_harness::always_on(&read_tree(harness_dir), &SurfaceSpec::default());
            if surfaced.trim().is_empty() { DEFAULT_SYSTEM_PROMPT.to_string() } else { surfaced }
        }
    }
}

/// Wraps the per-turn context block inside a user turn. The block is logged as
/// part of the user message (so later requests replay identical bytes); the app
/// hides it from the user bubble and recall skips it when scoring past jobs.
pub const TURN_CONTEXT_OPEN: &str = "<turn-context>";
pub const TURN_CONTEXT_CLOSE: &str = "</turn-context>";

/// Most entries listed in the start-of-task workspace snapshot.
const WORKSPACE_LIST_LIMIT: usize = 80;
/// Directory depth of the workspace snapshot (1 = top level only).
const WORKSPACE_LIST_DEPTH: usize = 2;

/// The volatile context for one user turn: the durable profile (USER/MEMORY),
/// the most relevant past job, the retrieved lessons for this goal, and — on a
/// job's first turn — a bounded listing of the workspace. Empty when there is
/// nothing to add. Rendered once and persisted, never recomputed for a turn.
fn build_turn_context(harness_dir: &Path, goal: &str, jobs_dir: Option<&Path>, current_job_id: &str, workspace: Option<&Path>) -> String {
    let mut context = String::new();
    let memory_root = harness_dir.join("memory");

    // Most stable first (changes only when the workshop installs a skill), so
    // consecutive jobs share the longest possible cached prefix.
    let catalog = bulge_harness::skills_catalog(&read_tree(harness_dir), &SurfaceSpec::default());
    if !catalog.is_empty() {
        context.push_str("\n\n");
        context.push_str(&catalog);
    }

    // Durable profile surfaces: who the user is and how they want the agent to
    // work, plus durable environment facts. Bounded by the save-time char limits.
    let user = bulge_harness::Profile::load(&memory_root.join(bulge_harness::profile::USER_FILE)).unwrap_or_default();
    if !user.sections.is_empty() {
        context.push_str("\n\n# About the user\n");
        context.push_str(&user.render());
    }
    let env = bulge_harness::Profile::load(&memory_root.join(bulge_harness::profile::MEMORY_FILE)).unwrap_or_default();
    if !env.sections.is_empty() {
        context.push_str("\n\n# Environment notes\n");
        context.push_str(&env.render());
    }

    // Surface the single most relevant PAST job for this goal — a "have I done
    // something like this before?" nudge. Unlike Hermes (which keeps past
    // transcripts tool-only), bulge auto-surfaces the top match at task start.
    // Thresholded so it stays quiet when nothing is clearly related.
    if let Some(dir) = jobs_dir
        && let Some(past) = crate::recall::most_relevant(dir, goal, 2.0, current_job_id)
    {
        context.push_str("\n\n# Possibly relevant past task\n");
        context.push_str(&past);
        context.push_str("\n(Call `recall` with a query about it if its result would help; otherwise ignore it.)");
    }

    if let Ok((lessons, _problems)) = bulge_harness::memory::load(&memory_root) {
        let hits = bulge_harness::retrieve(&lessons, goal, LESSON_COUNT);
        let brief = bulge_harness::brief(&hits);
        if !brief.is_empty() {
            context.push_str("\n\n");
            context.push_str(&brief);
        }
    }

    if let Some(dir) = workspace {
        context.push_str("\n\n# Workspace at task start (/workspace; no need to list it again)\n");
        context.push_str(&workspace_listing(dir));
    }

    let body = context.trim();
    if body.is_empty() { String::new() } else { format!("{TURN_CONTEXT_OPEN}\n{body}\n{TURN_CONTEXT_CLOSE}") }
}

/// A sorted, bounded listing of `dir` (relative paths, `/` after directories),
/// skipping hidden entries and well-known dependency/build directories.
fn workspace_listing(dir: &Path) -> String {
    const SKIP: [&str; 4] = ["node_modules", "target", "__pycache__", ".git"];
    let mut lines = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(dir.to_path_buf(), 1_usize)];
    let mut entries_seen = Vec::new();
    while let Some((path, depth)) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&path) else { continue };
        let mut names: Vec<(String, bool)> = read
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                (!name.starts_with('.') && !SKIP.contains(&name.as_str())).then_some((name, is_dir))
            })
            .collect();
        names.sort();
        for (name, is_dir) in names.into_iter().rev() {
            let full = path.join(&name);
            entries_seen.push((full.clone(), is_dir));
            if is_dir && depth < WORKSPACE_LIST_DEPTH {
                stack.push((full, depth + 1));
            }
        }
    }
    entries_seen.sort();
    for (full, is_dir) in entries_seen {
        if lines.len() == WORKSPACE_LIST_LIMIT {
            truncated = true;
            break;
        }
        let rel = full.strip_prefix(dir).unwrap_or(&full).to_string_lossy().into_owned();
        lines.push(if is_dir { format!("{rel}/") } else { rel });
    }
    if lines.is_empty() {
        return "(empty)".to_string();
    }
    if truncated {
        lines.push(format!("… (listing capped at {WORKSPACE_LIST_LIMIT} entries)"));
    }
    lines.join("\n")
}

/// Remove every `<turn-context>…</turn-context>` block from `text` (used by
/// recall so injected context never counts as a past job's own content).
pub fn strip_turn_context(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(TURN_CONTEXT_OPEN) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(TURN_CONTEXT_OPEN) {
        out.push_str(&rest[..start]);
        match rest[start..].find(TURN_CONTEXT_CLOSE) {
            Some(end) => rest = &rest[start + end + TURN_CONTEXT_CLOSE.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
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

/// What a completed turn produced.
pub struct RunOutcome {
    pub outcome: LoopOutcome,
    pub status: bulge_store::JobStatus,
    pub job_dir: PathBuf,
    /// The real store job id (stable across turns of one conversation).
    pub job_id: String,
    /// The host workspace the job ran against (where approved changes are applied).
    pub workspace: PathBuf,
    /// The collected workspace diff, if any changes were made.
    pub diff: Option<String>,
    /// The structured changes behind the diff, kept so a caller (the app) can
    /// apply the approved subset to the host after review. The host is never
    /// modified by the run itself.
    pub changes: Vec<changes::Change>,
}

/// Decide the egress shape. Outbound never uses the raw NIC — it goes through the
/// two-key gateway, which always blocks private/LAN/cloud-metadata addresses
/// (DNS-rebind safe). The roadmap's stance: allow public internet, block the
/// host/LAN. On top of that:
///   - network off → no egress at all;
///   - collaborative + an approval channel → auto-allow package/dev sources, and
///     ASK before the agent reaches any other host (the "only prompt when data
///     leaves to a non-model API" rule — the model API is a host-side call and
///     never comes through here);
///   - otherwise → allow any public host without prompting.
fn egress_setup(network: bool, autonomy: Autonomy, approvals: Option<bulge_vm::net::EgressApprovalTx>) -> (Vec<String>, Option<bulge_vm::net::EgressApprovalTx>) {
    if !network {
        return (Vec::new(), None);
    }
    match (autonomy, approvals) {
        (Autonomy::Collaborative, Some(tx)) => (bulge_guard::netgate::allowlist_suffixes(), Some(tx)),
        _ => (vec!["*".to_string()], None),
    }
}

/// Build the `VmConfig` for this run from the environment plus the mutable shape
/// (cpus / ram / network) a session may later restart with.
fn vm_config_for(
    workspace: &Path,
    cpus: u8,
    ram_mib: u32,
    network: bool,
    autonomy: Autonomy,
    approvals: Option<bulge_vm::net::EgressApprovalTx>,
) -> Result<VmConfig, String> {
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (egress_allow, egress_approvals) = egress_setup(network, autonomy, approvals);
    Ok(VmConfig {
        vmm_binary: repo.join("target/debug/bulge-vmm"),
        libkrun_dir: home.join(".local/lib"),
        rootfs: home.join(".bulge/rootfs/current"),
        workspace: workspace.to_path_buf(),
        runtime_root: PathBuf::from(std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into())).join("bulge"),
        cpus,
        ram_mib,
        network: false,
        egress_allow,
        egress_approvals,
    })
}

/// A live conversation: one VM plus the store job it serves. Outlives a single
/// turn so that follow-up turns reuse the same VM (in-VM files persist) and so
/// the VM can be restarted on its own.
pub struct Session {
    backend: Arc<dyn LlmBackend>,
    vm: Arc<Vm>,
    job: bulge_store::JobHandle,
    harness_dir: PathBuf,
    workspace: PathBuf,
    backend_spec: BackendSpec,
    autonomy: Autonomy,
    sampling: Sampling,
    system_prompt: Option<String>,
    /// Egress approval channel (used when restarting with network on, collaborative).
    egress_approvals: Option<bulge_vm::net::EgressApprovalTx>,
    /// Connected MCP servers (kept alive for the session) plus their tool routing.
    mcp: McpBundle,
    /// User-declared lifecycle hooks (`~/.bulge/hooks.json`), shared across turns.
    hooks: Arc<HookRunner>,
    /// Skip the offline learning loop on shutdown (autonomous scheduled runs).
    skip_review: bool,
    /// Enable the LLM review gate on mutating tool calls.
    auto_review: bool,
    /// The VM shape last launched with; restart tweaks these.
    vm_config: VmConfig,
    /// The last turn's request prefix; post-job learning calls replay it so they
    /// hit the provider's prefix cache instead of resending the job uncached.
    prefix: Option<RequestPrefix>,
}

impl Session {
    /// Open (or create) the conversation's store job and launch its VM. No turn
    /// is run yet — call [`Session::run_turn`].
    pub async fn launch(config: RunConfig) -> Result<Self, String> {
        let backend = backend::build(&config.backend)?;
        let store = JobStore::new(&config.store_root);
        let job = match &config.job_id {
            // Reopen an existing conversation; the driver replays its full history.
            Some(id) => {
                let (job, _recovery) = store.open(id).map_err(|e| format!("open job: {e}"))?;
                job
            }
            None => {
                let job_id = bulge_store::new_job_id().map_err(|e| format!("job id: {e}"))?;
                store
                    .create(JobSpec {
                        id: job_id,
                        title: config.title.clone(),
                        goal: config.goal.clone(),
                        workspace: config.workspace.clone(),
                        autonomy: config.autonomy,
                        budget: config.budget.clone(),
                        model: ModelRef { backend: config.backend.id.clone(), model: config.backend.model.clone() },
                    })
                    .map_err(|e| format!("create job: {e}"))?
            }
        };

        let vm_config = vm_config_for(&config.workspace, config.cpus, config.ram_mib, config.network, config.autonomy, config.egress_approvals.clone())?;
        let vm = Arc::new(Vm::launch(vm_config.clone()).await.map_err(|e| format!("launch VM: {e}"))?);

        // Connect any user-declared MCP servers (~/.bulge/mcp.json). Best-effort: a
        // broken server only loses its tools, it never blocks the run.
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        let mcp = match mcp::McpConfig::load(&home.join(".bulge/mcp.json")) {
            Ok(cfg) => {
                let bundle = mcp::connect_all(&cfg).await;
                for err in &bundle.errors {
                    eprintln!("mcp: {err}");
                }
                if !bundle.tools.is_empty() {
                    eprintln!("mcp: {} tool(s) from {} server(s)", bundle.tools.len(), bundle.clients.len());
                }
                bundle
            }
            Err(e) => {
                eprintln!("mcp: {e}");
                McpBundle::default()
            }
        };

        // Load user-declared lifecycle hooks (~/.bulge/hooks.json). Best-effort:
        // a malformed file loses its hooks but never blocks the run.
        let hooks = match HookConfig::load(&home.join(".bulge/hooks.json")) {
            Ok(cfg) => {
                if !cfg.is_empty() {
                    let count: usize = cfg.hooks.values().map(Vec::len).sum();
                    eprintln!("hooks: {count} matcher group(s) loaded");
                }
                Arc::new(HookRunner::new(cfg))
            }
            Err(e) => {
                eprintln!("hooks: {e}");
                Arc::new(HookRunner::default())
            }
        };

        Ok(Self {
            backend,
            vm,
            job,
            harness_dir: config.harness_dir,
            workspace: config.workspace,
            backend_spec: config.backend,
            autonomy: config.autonomy,
            sampling: config.sampling,
            system_prompt: config.system_prompt,
            egress_approvals: config.egress_approvals,
            mcp,
            hooks,
            skip_review: config.skip_review,
            auto_review: config.auto_review,
            vm_config,
            prefix: None,
        })
    }

    /// The real store job id (stable across turns).
    pub fn job_id(&self) -> &str {
        self.job
            .dir()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }

    /// Run one turn: append the user message, drive the loop to a stop against the
    /// *persistent* VM, and collect the (cumulative) workspace diff for review.
    /// The VM is left running for the next turn.
    pub async fn run_turn(&mut self, goal: String, cancel: CancellationToken, sink: LineSink) -> Result<RunOutcome, String> {
        let jobs_dir = self.job.dir().parent().map(std::path::Path::to_path_buf);
        let system_prompt = build_system_prompt(&self.harness_dir, self.system_prompt.as_deref());
        // The workspace snapshot is only true before the first turn touches it.
        let first_turn = self.job.state().history.is_empty();
        let turn_context = build_turn_context(
            &self.harness_dir,
            &goal,
            jobs_dir.as_deref(),
            self.job_id(),
            first_turn.then_some(self.workspace.as_path()),
        );
        let user_turn = if turn_context.is_empty() { goal.clone() } else { format!("{turn_context}\n\n{goal}") };

        // Append the user turn; flip a finished job back to Running (best effort).
        self.job
            .append(vec![JobEvent::Message { message: Message::text(Role::User, user_turn) }])
            .map_err(|e| format!("append turn: {e}"))?;
        let _ = self.job.append(vec![JobEvent::StatusChanged { status: JobStatus::Running, summary: None }]);

        let log_path = self.job.dir().join("job.jsonl");
        // Stream only the newly-appended events (start at the current EOF) so the
        // UI doesn't duplicate the transcript it already shows.
        let tail_start = std::fs::metadata(&log_path).map(|m| m.len() as usize).unwrap_or(0);

        // Rebuild the per-turn dispatcher/driver against the current VM (so a
        // restarted VM is picked up) — cheap; the VM is the expensive part. MCP
        // tools (if any) route to their server; everything else goes to the VM.
        let vm_dispatcher = Arc::new(VmDispatcher::new(self.vm.clone(), Duration::from_secs(120)));
        let base: Arc<dyn ToolDispatcher> = if self.mcp.routes.is_empty() {
            vm_dispatcher
        } else {
            Arc::new(CompositeDispatcher::new(vm_dispatcher, self.mcp.routes.clone()))
        };
        // Wrap in the lifecycle-hook layer (a no-op pass-through when no hooks are
        // declared). PreToolUse may block/rewrite a call; PostToolUse may inject.
        let hooked: Arc<dyn ToolDispatcher> = if self.hooks.is_empty() {
            base
        } else {
            Arc::new(HookedDispatcher::new(base, self.hooks.clone()))
        };

        // Child tools are everything the parent has EXCEPT `delegate`, so a
        // sub-agent cannot delegate further (delegation is capped at one level).
        let mut child_tools = builtin_tools();
        child_tools.push(plan_tool());
        child_tools.extend(self.mcp.tools.iter().cloned());

        // Wrap in the delegation layer: `delegate` spawns a child agent sharing
        // this VM (and the hook/review stack), reporting back only its summary.
        let factory = delegate::ChildFactory {
            backend: self.backend.clone(),
            inner: hooked.clone(),
            child_tools: child_tools.clone(),
            store_root: self.job.dir().parent().map(std::path::Path::to_path_buf).unwrap_or_default(),
            workspace: self.workspace.clone(),
            autonomy: self.autonomy,
            guard_rules: default_ruleset(),
            model: self.backend_spec.model.clone(),
            backend_id: self.backend_spec.id.clone(),
            context_window: self.backend_spec.context_window,
            sampling: self.sampling.clone(),
            auto_review: self.auto_review,
        };
        let dispatcher: Arc<dyn ToolDispatcher> = hooked;

        let mut tools = child_tools;
        tools.push(delegate::delegate_tool());
        tools.push(crate::recall::recall_tool());
        let recall_handler = Arc::new(crate::recall::StoreRecall { jobs_dir: jobs_dir.clone().unwrap_or_default() });
        let context = ContextConfig { window: self.backend_spec.context_window as u64, ..ContextConfig::default() };
        let driver = Driver::new(self.backend.clone(), dispatcher.clone(), tools, system_prompt)
            .with_guard(GuardConfig { rules: default_ruleset(), autonomy: guard_autonomy(self.autonomy), loop_detection: true })
            .with_completion_gate(CompletionConfig::default())
            .with_context(context)
            .with_sampling(self.sampling.clone())
            .with_review(self.auto_review)
            .with_delegate(Arc::new(factory))
            .with_recall(recall_handler);

        let stop = CancellationToken::new();
        let tail = tokio::spawn(tail_jsonl(log_path.clone(), stop.clone(), sink, tail_start));

        let outcome = driver.run(&mut self.job, cancel).await.map_err(|e| format!("run: {e}"))?;

        stop.cancel();
        let _ = tail.await;

        // Collect workspace changes and write the diff out (the host is not touched).
        let mut diff: Option<String> = None;
        let mut collected: Vec<changes::Change> = Vec::new();
        if let Ok(pending) = changes::collect(&self.vm).await
            && !pending.is_empty()
        {
            let rendered = changes::render_diff(&self.workspace, &pending);
            let diff_path = self.job.dir().join("changes.diff");
            let _ = std::fs::write(&diff_path, &rendered);
            diff = Some(rendered);
            collected = pending;
        }

        // The driver/dispatcher drop here, releasing their VM clones; `self.vm`
        // keeps the VM alive for the next turn.
        self.prefix = Some(driver.prefix());
        drop(driver);
        drop(dispatcher);

        Ok(RunOutcome {
            outcome,
            status: self.job.state().status,
            job_dir: self.job.dir().to_path_buf(),
            job_id: self.job_id().to_string(),
            workspace: self.workspace.clone(),
            diff,
            changes: collected,
        })
    }

    /// Restart the VM on its own with a new shape (cpus / ram / network). The
    /// conversation (store job, history) is untouched; only the machine is
    /// replaced, so this resets in-VM files but never the agent's memory. Used
    /// when the user changes execution settings mid-conversation.
    pub async fn restart_vm(&mut self, cpus: u8, ram_mib: u32, network: bool) -> Result<(), String> {
        let (egress_allow, egress_approvals) = egress_setup(network, self.autonomy, self.egress_approvals.clone());
        let mut cfg = self.vm_config.clone();
        cfg.cpus = cpus;
        cfg.ram_mib = ram_mib;
        cfg.egress_allow = egress_allow;
        cfg.egress_approvals = egress_approvals;

        // Launch the replacement before tearing down the old one, so a failed
        // relaunch leaves the running VM intact.
        let new_vm = Vm::launch(cfg.clone()).await.map_err(|e| format!("restart VM: {e}"))?;
        let old = std::mem::replace(&mut self.vm, Arc::new(new_vm));
        if let Ok(vm) = Arc::try_unwrap(old) {
            vm.shutdown().await;
        }
        self.vm_config = cfg;
        Ok(())
    }

    /// Finish the conversation: propose durable lessons offline, then shut the VM
    /// down (and clean up its runtime directory).
    pub async fn shutdown(mut self) {
        if !self.skip_review
            && let Some(prefix) = self.prefix.take()
        {
            improve(self.backend.as_ref(), &mut self.job, &self.harness_dir, &self.backend_spec.model, &prefix).await;
        }
        let Session { vm, .. } = self;
        if let Ok(vm) = Arc::try_unwrap(vm) {
            vm.shutdown().await;
        }
    }

    /// Shut the VM down without the offline-improvement pass (e.g. on eviction).
    pub async fn shutdown_quietly(self) {
        let Session { vm, .. } = self;
        if let Ok(vm) = Arc::try_unwrap(vm) {
            vm.shutdown().await;
        }
    }
}

/// Run one job end to end, printing its event log to stdout (the headless CLI
/// path). Equivalent to [`run_streaming`] with a stdout sink and a fresh,
/// never-cancelled token.
pub async fn run(config: RunConfig) -> Result<RunOutcome, String> {
    run_streaming(config, CancellationToken::new(), stdout_sink()).await
}

/// Run exactly one turn end to end and then shut the session down (the headless
/// CLI path): launch a session, run the turn, print the footer, tear down.
pub async fn run_streaming(config: RunConfig, cancel: CancellationToken, sink: LineSink) -> Result<RunOutcome, String> {
    let goal = config.goal.clone();
    let mut session = Session::launch(config).await?;
    let outcome = session.run_turn(goal, cancel, sink).await?;

    match &outcome.diff {
        Some(diff) => eprintln!("{} change(s) collected ({} bytes of diff)", outcome.changes.len(), diff.len()),
        None => eprintln!("no workspace changes"),
    }
    eprintln!(
        "outcome: {:?}  status: {:?}  summary: {:?}  steps: {}  tokens: {}",
        outcome.outcome,
        session.job.state().status,
        session.job.state().summary,
        session.job.state().steps,
        session.job.state().usage.total()
    );
    let usage = session.job.state().usage;
    let prompt = usage.input_tokens + usage.cache_read_tokens;
    if prompt > 0 {
        eprintln!("prompt cache: {}/{} input tokens hit ({:.1}%)", usage.cache_read_tokens, prompt, 100.0 * usage.cache_read_tokens as f64 / prompt as f64);
    }

    session.shutdown().await;
    Ok(outcome)
}

/// Ask the model for durable lessons from this job and save them to memory.
/// Opens every post-job learning instruction (the learning calls share the loop's
/// system prompt for cache reuse, so the reviewer role is stated here).
const LEARNING_PREAMBLE: &str = "Stop working on the task and do not call tools: you now review it to learn from it.";

/// Run one post-job learning call and log its usage on the job (so a job's token
/// total includes the learning it paid for).
async fn learning_call(backend: &dyn LlmBackend, job: &mut bulge_store::JobHandle, request: GenerateRequest, model: &str, prefix: &RequestPrefix) -> bulge_llm::assemble::Assembled {
    let print = bulge_core::cache_watch::fingerprint(&request);
    let assembled = stream_toolless(backend, request, CancellationToken::new()).await;
    let mut events = vec![JobEvent::Usage { model: model.to_string(), usage: assembled.usage }];
    events.extend(watch_call(&prefix.cache, print, &assembled.usage));
    let _ = job.append(events);
    assembled
}

async fn improve(backend: &dyn LlmBackend, job: &mut bulge_store::JobHandle, harness_dir: &Path, model: &str, prefix: &RequestPrefix) {
    // One call proposes lessons, profile updates, and a skill together: the
    // instruction is the only uncached text, so it is sent once, not three times.
    let instruction = format!("{LEARNING_PREAMBLE}\n\n{}", bulge_harness::PROPOSE_LEARNING_PROMPT);
    let request = side_request(prefix, job, &instruction, Purpose::Memory);
    let assembled = learning_call(backend, job, request, model, prefix).await;
    let reply = assembled.message.content.iter().find_map(|b| match b {
        bulge_llm::ContentBlock::Text { text } => Some(text.clone()),
        _ => None,
    });
    let Some(reply) = reply else { return };

    let memory_root = harness_dir.join("memory");
    let existing_ids: Vec<String> = bulge_harness::memory::load(&memory_root)
        .map(|(lessons, _)| lessons.into_iter().map(|l| l.id).collect())
        .unwrap_or_default();
    let learned = bulge_harness::parse_proposed_learning(&reply, &existing_ids);
    let proposed = learned.lessons;
    let mut saved = 0_usize;
    for lesson in &proposed {
        if bulge_harness::memory::save(&memory_root, lesson).is_ok() {
            saved += 1;
        }
    }
    if saved > 0 {
        eprintln!("learned {saved} lesson(s) into {}", memory_root.join("lessons").display());
    }

    // Update the durable profile surfaces (USER.md / MEMORY.md) from this job.
    apply_profile(harness_dir, learned.profile);

    // Also look for a reusable skill from this job (the skill workshop). Candidates
    // are written to the harness skills dir; they become active once an always-on
    // file references them (promotion is left manual by design, so the always-on
    // prompt never grows on its own).
    if let Some(draft) = learned.skill {
        save_skill(harness_dir, &draft);
    }
}

/// Write a proposed skill to the harness skills dir (unless a skill of that name
/// already exists). Best-effort.
fn save_skill(harness_dir: &Path, draft: &bulge_harness::SkillDraft) {
    let spec = SurfaceSpec::default();
    let path = harness_dir.join(draft.path(&spec));
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(&path, draft.to_source()).is_ok() {
        eprintln!("proposed skill `{}` → {}", draft.name, path.display());
        // Record authorship in the skill usage ledger (created by the agent), so a
        // later curator can see which skills the agent authored and how they age.
        let skills_root = harness_dir.join(spec.skill_dir.trim_end_matches('/'));
        let ledger_path = skills_root.join(bulge_harness::usage::USAGE_FILE);
        let mut ledger = bulge_harness::UsageLedger::load(&ledger_path).unwrap_or_default();
        ledger.record_created(&draft.name, bulge_harness::Author::Agent, now_unix());
        let _ = ledger.save(&ledger_path);
    }
}

/// Apply proposed updates to the durable profile surfaces (USER.md / MEMORY.md).
/// Every stored body is threat-scanned (these files are auto-injected into every
/// future job, so a prompt-injection here would persist) and secret-redacted
/// before it is written. Best-effort.
fn apply_profile(harness_dir: &Path, updates: Vec<bulge_harness::ProfileUpdate>) {
    if updates.is_empty() {
        return;
    }

    let memory_root = harness_dir.join("memory");
    let user_path = memory_root.join(bulge_harness::profile::USER_FILE);
    let env_path = memory_root.join(bulge_harness::profile::MEMORY_FILE);
    let mut user = bulge_harness::Profile::load(&user_path).unwrap_or_default();
    let mut env = bulge_harness::Profile::load(&env_path).unwrap_or_default();
    let (mut user_dirty, mut env_dirty) = (false, false);

    for update in updates {
        let (profile, dirty) = match update.target {
            bulge_harness::ProfileTarget::User => (&mut user, &mut user_dirty),
            bulge_harness::ProfileTarget::Env => (&mut env, &mut env_dirty),
        };
        if update.remove {
            if profile.remove(&update.key) {
                *dirty = true;
            }
            continue;
        }
        // These files re-enter the system prompt every session, so treat an
        // incoming body as untrusted: refuse anything that reads like an
        // injection, and redact any secret that slipped into it.
        if bulge_guard::is_threat(&update.body, bulge_guard::Scope::Strict) {
            eprintln!("profile: rejected `{}` (threat pattern)", update.key);
            continue;
        }
        let body = bulge_guard::redact_secrets(&update.body);
        profile.upsert(&update.key, &body);
        *dirty = true;
    }

    if user_dirty {
        match user.save(&user_path, bulge_harness::profile::USER_LIMIT) {
            Ok(()) => eprintln!("updated {}", user_path.display()),
            Err(e) => eprintln!("profile: {e} (USER.md left unchanged)"),
        }
    }
    if env_dirty {
        match env.save(&env_path, bulge_harness::profile::MEMORY_LIMIT) {
            Ok(()) => eprintln!("updated {}", env_path.display()),
            Err(e) => eprintln!("profile: {e} (MEMORY.md left unchanged)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_turn_context_removes_only_the_injected_blocks() {
        let text = format!("a {TURN_CONTEXT_OPEN}lesson about csv{TURN_CONTEXT_CLOSE} b {TURN_CONTEXT_OPEN}x{TURN_CONTEXT_CLOSE}c");
        assert_eq!(strip_turn_context(&text), "a  b c");
        assert_eq!(strip_turn_context("plain"), "plain");
        // An unterminated block drops the rest rather than leaking it.
        assert_eq!(strip_turn_context(&format!("keep{TURN_CONTEXT_OPEN}dangling")), "keep");
    }

    #[test]
    fn workspace_listing_is_sorted_bounded_and_skips_noise() {
        let dir = std::env::temp_dir().join(format!("bulge-ws-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src/deep/deeper")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join("b.txt"), "").unwrap();
        std::fs::write(dir.join("a.py"), "").unwrap();
        std::fs::write(dir.join("src/main.rs"), "").unwrap();
        let listing = workspace_listing(&dir);
        assert_eq!(listing, "a.py\nb.txt\nsrc/\nsrc/deep/\nsrc/main.rs");

        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(workspace_listing(&empty), "(empty)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn turn_context_is_wrapped_and_lists_the_workspace() {
        let dir = std::env::temp_dir().join(format!("bulge-turn-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("harness")).unwrap();
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        std::fs::write(dir.join("ws/data.csv"), "x").unwrap();
        let ctx = build_turn_context(&dir.join("harness"), "sum the csv", None, "j-1", Some(&dir.join("ws")));
        assert!(ctx.starts_with(TURN_CONTEXT_OPEN) && ctx.ends_with(TURN_CONTEXT_CLOSE));
        assert!(ctx.contains("data.csv"));
        // Nothing to add (no profile, lessons, or workspace) → no block at all.
        assert!(build_turn_context(&dir.join("harness"), "sum the csv", None, "j-1", None).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
