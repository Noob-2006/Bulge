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

mod learning;
mod session;
mod tail;
mod turn_context;

use learning::*;
pub use session::*;
pub use tail::*;
pub use turn_context::*;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bulge_core::driver::LoopOutcome;
pub use bulge_core::driver::Sampling;

use bulge_harness::Tree;
use bulge_store::{Autonomy, Budget};
use bulge_vm::changes;
use tokio_util::sync::CancellationToken;

use crate::backend::BackendSpec;

/// A cautious default prompt used when no harness tree is present.
const DEFAULT_SYSTEM_PROMPT: &str = "\
You are bulge, a careful general-purpose agent working inside a sandboxed Linux VM. \
The workspace is yours; the host and the wider machine are not reachable. Work toward \
the user's goal with the provided tools. Prefer small, verifiable steps. Keep a plan \
with the plan tool and mark items done as you go. When you believe the work is complete, \
stop calling tools and reply in a few short lines: what you produced and how you verified \
it. The user can open the files; do not restate their contents, and do not include a \
self-review (one is requested separately when needed).\n\n\
Every extra model round-trip resends the whole conversation, so economise on turns, not \
on care: issue independent tool calls together in one turn (they run in parallel); chain \
dependent shell steps you would not need to inspect in between into one `exec` (e.g. \
create a file and run its check in the same command); trust tool results (a successful \
`write` landed — do not read it back). Save turns only by batching, never by checking \
less: given examples rarely cover a spec's edge cases, so test the cases the wording \
implies too — in the same `exec`. Equally, match the depth of checking to the request: do \
not add rigour nobody asked for (mutation testing, rerunning a passing suite to hunt \
flakiness, running the same tests several equivalent ways).\n\n\
You lead an organization of role-based sub-agents. Delegation is expensive: every ticket starts \
a new agent that rebuilds its own context and is then checked by an independent reviewer — \
usually several times the tokens of doing the work yourself. So do the work yourself whenever \
one focused session can finish it (a module and its tests, a bug fix, a report from a few \
sources). Delegate only where it pays for itself: parts that are each substantial and truly \
independent (buildable without seeing each other's results), so running them in parallel saves \
real time. Keep dependent work — code and the tests written against it — in one ticket. When \
you delegate, act as the chief: `delegate` each mission to a `lead` (who runs its own team) or \
a worker role, give every ticket a deliverable and acceptance criteria up front — the user's \
requirements and the edge cases they imply, not extra rituals — and delegate independent parts \
in one turn so they run in parallel. Anything that changes files is independently reviewed \
before you integrate it, and that acceptance is the verification: do not re-check accepted work \
or open another audit ticket for it without a concrete reason to doubt it. Do not do a lead's \
coordinating or a reviewer's checking as the same agent that did the work. `org_status` shows \
the org; integrate only accepted results.";

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
    /// Use the owner's host integrations: MCP servers (`~/.bulge/mcp.json`,
    /// tools that run on the host with the owner's accounts) and lifecycle
    /// hooks (`~/.bulge/hooks.json`, shell commands on the host that see the
    /// tool arguments). Off for chat guests and group requests.
    pub host_integrations: bool,
    /// Host tools for this run only (e.g. `chat_history` for a group's job),
    /// offered to the head agent.
    pub extra_tools: Vec<ExtraTool>,
}

impl RunConfig {
    /// A fresh job for `goal` in `workspace`, with the defaults every front end
    /// starts from: stores under `~/.bulge`, autonomous, the default budget, a
    /// 2-CPU 1 GiB VM without network, provider-chosen sampling, learning on,
    /// no review gate, and no host integrations (each caller that runs for the
    /// owner turns those on). The title is the goal's first line.
    pub fn new(goal: impl Into<String>, workspace: PathBuf, backend: BackendSpec) -> Result<Self, String> {
        let goal = goal.into();
        let (store_root, harness_dir) = (bulge_util::fs::jobs_dir()?, bulge_util::fs::harness_dir()?);
        Ok(Self {
            job_id: None,
            title: goal.lines().next().unwrap_or("job").chars().take(80).collect(),
            goal,
            workspace,
            store_root,
            harness_dir,
            autonomy: Autonomy::Autonomous,
            budget: Budget::default(),
            backend,
            network: false,
            cpus: 2,
            ram_mib: 1_024,
            sampling: Sampling::default(),
            system_prompt: None,
            egress_approvals: None,
            skip_review: false,
            auto_review: false,
            host_integrations: false,
            extra_tools: Vec::new(),
        })
    }
}

/// A host tool and its schema, added to one run.
#[derive(Clone)]
pub struct ExtraTool {
    pub schema: bulge_llm::ToolSchema,
    pub handler: Arc<dyn bulge_core::HostTool>,
}

/// Read a directory tree into an in-memory `Tree` (relative path → UTF-8 text).
/// Non-UTF-8 and unreadable files are skipped. Missing dir → empty tree.
pub(crate) fn read_tree(root: &Path) -> Tree {
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
    /// Changes that are by-products (path, matching rule): listed for review
    /// but not selected for write-back by default.
    pub ignored: Vec<(String, String)>,
    /// Full-auto only: the write-back this turn applied by itself (snapshotted;
    /// undo with `bulge rollback` or the app). Its paths are no longer pending.
    pub auto_writeback: Option<bulge_vm::writeback::Manifest>,
    /// Why the workspace changes could not be collected (e.g. the guest
    /// reported a path outside the workspace). Never silently treated as
    /// "no changes".
    pub changes_error: Option<String>,
}

/// Run one job end to end, printing its event log to stdout (the headless CLI
/// path). Equivalent to [`run_streaming`] with a stdout sink and a fresh,
/// never-cancelled token.
pub async fn run(config: RunConfig) -> Result<RunOutcome, String> {
    run_streaming(config, CancellationToken::new(), stdout_sink()).await.map_err(|failure| failure.message)
}

/// A turn that did not finish, and the job it belongs to once one exists
/// (so a chat can still continue that conversation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFailure {
    pub job_id: Option<String>,
    pub message: String,
}

impl From<String> for RunFailure {
    fn from(message: String) -> Self {
        Self { job_id: None, message }
    }
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Run exactly one turn end to end and then shut the session down (the headless
/// CLI path): launch a session, run the turn, print the footer, tear down.
pub async fn run_streaming(config: RunConfig, cancel: CancellationToken, sink: LineSink) -> Result<RunOutcome, RunFailure> {
    let mut outcome = None;
    run_streaming_then(config, cancel, sink, |result| outcome = Some(result)).await;
    outcome.unwrap_or_else(|| Err(RunFailure::from("the turn ended without a result".to_string())))
}

/// [`run_streaming`], but `report` gets the turn's result as soon as it is
/// known — before the session's offline learning pass and VM shutdown, which
/// still run before this returns. A chat reply need not wait for learning.
pub async fn run_streaming_then(config: RunConfig, cancel: CancellationToken, sink: LineSink, report: impl FnOnce(Result<RunOutcome, RunFailure>)) {
    let goal = config.goal.clone();
    let mut session = match Session::launch(config).await {
        Ok(session) => session,
        Err(failure) => return report(Err(failure.into())),
    };
    let job_id = session.job.state().spec.id.clone();
    let outcome = match session.run_turn(goal, cancel, sink).await {
        Ok(outcome) => outcome,
        Err(message) => {
            report(Err(RunFailure { job_id: Some(job_id), message }));
            session.shutdown().await;
            return;
        }
    };

    match &outcome.diff {
        Some(diff) => eprintln!(
            "{} change(s) collected ({} bytes of diff; {} by-product(s) not selected)",
            outcome.changes.len(),
            diff.len(),
            outcome.ignored.len()
        ),
        None if outcome.changes_error.is_none() => eprintln!("no workspace changes"),
        None => {}
    }
    if let Some(error) = &outcome.changes_error {
        eprintln!("error: {error}");
    }
    if let Some(manifest) = &outcome.auto_writeback {
        eprintln!(
            "full-auto: wrote back {} path(s) under snapshot {} (undo: bulge rollback {} {})",
            manifest.applied_paths().len(),
            manifest.id,
            outcome.job_id,
            manifest.id
        );
        for (path, why) in &manifest.skipped {
            eprintln!("full-auto: not written {path}: {why}");
        }
    }
    eprintln!(
        "outcome: {:?}  status: {:?}  summary: {:?}  steps: {}  tokens: {}",
        outcome.outcome,
        session.job.state().status,
        session.job.state().summary,
        session.job.state().steps,
        session.job.state().tokens_spent()
    );
    let usage = session.job.state().usage;
    let prompt = usage.input_tokens + usage.cache_read_tokens;
    if prompt > 0 {
        eprintln!("prompt cache: {}/{} input tokens hit ({:.1}%)", usage.cache_read_tokens, prompt, 100.0 * usage.cache_read_tokens as f64 / prompt as f64);
    }

    report(Ok(outcome));
    session.shutdown().await;
}

#[cfg(test)]
mod tests;
