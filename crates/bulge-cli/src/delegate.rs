//! Sub-agent delegation: a host-handled `delegate` tool that runs a focused
//! sub-task in a fresh nested agent loop and returns ONLY its final summary.
//!
//! The parent agent is the organization's head (lead): every delegation names a
//! role from the role library, runs a child AS that role (charter as system
//! prompt, tool allowlist, model/reasoning override), and records the work as a
//! ticket on a persistent board. The child's result comes back as an org-bus
//! Report (threat-scanned and redacted) and the head can ask for a model-free
//! situation report at any time.
//!
//! The child runs in the parent's VM but gets its own VM workspace slot: a
//! private overlay, uid and namespace, so concurrent children can edit the same
//! paths without stepping on each other. Hooks and the review gate still apply;
//! MCP tools are deliberately filtered out of the child's tool list because MCP
//! servers run on the host, outside any slot. The child runs a separate
//! conversation with its own store job and a smaller budget.
//! The child is given every tool EXCEPT `delegate` and `org_status`, so
//! delegation is naturally capped at one level (no runaway recursion). The
//! parent transcript never sees the child's intermediate steps — only the
//! delegate call and the structured [`bulge_core::driver::DelegateReport`] —
//! matching the deepseek/Hermes "parent sees the summary, not the child's
//! reasoning" model.
//!
//! Children of one parent run concurrently (up to
//! [`MAX_CONCURRENT_SUBAGENTS`] from a tree-wide slot pool), are charged to the
//! parent's [`Ledger`](bulge_core::ledger::Ledger) so delegating can never spend
//! past the job's own budget, and all instances of one role share a stable
//! charter prompt so their requests share a cached prefix.
//!
//! The driver calls this through [`bulge_core::driver::DelegateHandler`]: the
//! child runs a nested driver whose future is `!Send` (it schedules tool calls on
//! the current thread), so delegation is handled inside the driver loop, not in a
//! `Send` dispatcher.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bulge_core::driver::{
    CompletionConfig, ContextConfig, DelegateHandler, DelegateRequest, DelegateReport, Driver,
    GuardConfig, LoopOutcome, OrgStatusHandler, ProposeRoleHandler, Sampling,
};
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_core::hooks::{HookRunner, HookedDispatcher};
use bulge_core::{ToolDispatcher, VmDispatcher, builtin_tools};
use bulge_llm::{ContentBlock, LlmBackend, Message, ReasoningEffort, Role, ToolSchema};
use bulge_org::{
    Board, BoardEvent, BoardLog, Bus, Delivery, LedgerView, MAX_REJECTIONS, MessageKind, OrgMessage,
    PerformanceBook, Review, RoleCharter, RoleKind, RoleLibrary, TRIAL_BUDGET_SHARE, Ticket,
    TicketStatus, Verdict, append_decision, as_trial, audit_task, check_proposal, parse_charter,
    parse_review, review_task, rework_message, vetoed_names,
};
use bulge_store::{Autonomy, Budget, JobEvent, JobHandle, JobSpec, JobStatus, JobStore, ModelRef};
use bulge_vm::slots::{self, MergeConflict, MergeReport};
use bulge_vm::vm::Vm;
use futures::future::LocalBoxFuture;
use serde_json::json;
use tokio_util::sync::CancellationToken;

/// Most sub-agents that may run at once across one delegation tree (the parent
/// root ledger's slot pool). A call beyond this fails with `SLOTS_FULL` rather
/// than queueing, so the model can adapt instead of hanging.
pub const MAX_CONCURRENT_SUBAGENTS: usize = 8;

/// Deepest level a delegated agent may occupy. The head is depth 0, so leads
/// may sit at depths 1 and 2 and their workers at depth 3.
pub const MAX_DEPTH: u32 = 3;

/// The role a delegation runs as when the head does not name one.
const DEFAULT_ROLE: &str = "implementer";

/// Steps a sub-agent may take before its loop must stop and summarize.
const CHILD_MAX_STEPS: u64 = 80;

/// Tokens a sub-agent may spend (further clamped to what the parent has left
/// and to the role's share of it).
const CHILD_MAX_TOKENS: u64 = 800_000;

/// Wall-clock seconds a sub-agent may run (never later than the parent deadline).
const CHILD_MAX_WALL_SECS: u64 = 1_800;

/// Characters of a child's final answer returned to the parent; longer answers
/// are shortened in the middle (the full text stays in the child's job log).
const SUMMARY_CAP_CHARS: usize = 6_000;

/// The report/board reason used when a ticket changed files but no reviewer exists.
const NO_REVIEWER: &str = "no reviewer role is defined; changes were not merged";

/// How long a ticket waits for a free VM slot for its reviewer before failing.
const REVIEW_SLOT_WAIT: Duration = Duration::from_secs(10 * 60);

/// Which VM workspace slots are in use. Shared by every child of a session.
pub struct VmSlots {
    used: std::sync::Mutex<Vec<bool>>,
}

impl VmSlots {
    /// A pool of `count` slots, all free.
    pub fn new(count: usize) -> Arc<Self> {
        Arc::new(Self {
            used: std::sync::Mutex::new(vec![false; count]),
        })
    }

    /// Lease a free slot. `None` means the pool is exhausted.
    pub fn lease(self: &Arc<Self>) -> Option<SlotLease> {
        let mut used = self.used.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = used.iter().position(|in_use| !in_use)?;
        used[index] = true;
        Some(SlotLease {
            slots: self.clone(),
            index: index as u8,
        })
    }
}

/// One leased VM workspace slot; frees its index when dropped.
pub struct SlotLease {
    slots: Arc<VmSlots>,
    index: u8,
}

impl SlotLease {
    pub fn index(&self) -> u8 {
        self.index
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        let mut used = self.slots.used.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(in_use) = used.get_mut(self.index as usize) {
            *in_use = false;
        }
    }
}

/// The head's organization for one session: its ticket board (persisted) and its
/// message bus (persisted).
pub struct OrgState {
    pub board: Board,
    pub log: BoardLog,
    pub bus: Bus,
    next_ticket: u64,
}

impl OrgState {
    /// Open (or resume) `<dir>/board.jsonl` and `<dir>/bus.jsonl`. `next_ticket`
    /// continues after the highest existing `t-<n>` id.
    pub fn open(dir: &Path) -> Result<OrgState, String> {
        let (log, board) = BoardLog::open(&dir.join("board.jsonl")).map_err(|error| error.to_string())?;
        let bus = Bus::with_log(&dir.join("bus.jsonl"))?;
        let mut next_ticket = 1;
        for ticket in board.tickets() {
            if let Some(number) = ticket.id.strip_prefix("t-").and_then(|rest| rest.parse::<u64>().ok()) {
                next_ticket = next_ticket.max(number.saturating_add(1));
            }
        }
        Ok(OrgState { board, log, bus, next_ticket })
    }

    /// A fresh ticket id `t-<n>`.
    pub fn next_id(&mut self) -> String {
        let id = format!("t-{}", self.next_ticket);
        self.next_ticket = self.next_ticket.saturating_add(1);
        id
    }
}

/// Post one ticket to the board, returning its fresh id. The parent must already
/// exist; the board rejects an unknown parent.
fn post_ticket(
    org: &mut OrgState,
    parent: Option<String>,
    role: &str,
    goal: &str,
    acceptance: &[String],
    budget_tokens: u64,
) -> Result<String, String> {
    let id = org.next_id();
    let at_ms = now_ms();
    let OrgState { board, log, .. } = org;
    log.append(
        board,
        BoardEvent::Posted {
            ticket: Ticket {
                id: id.clone(),
                parent,
                role: role.to_string(),
                goal: goal.to_string(),
                acceptance: acceptance.to_vec(),
                budget_tokens,
                owner: None,
                status: TicketStatus::Posted,
                rejections: 0,
                notes: Vec::new(),
                created_ms: at_ms,
                updated_ms: at_ms,
            },
            at_ms,
        },
    )
    .map_err(|error| format!("post ticket {id}: {error}"))?;
    Ok(id)
}

/// Current wall-clock time in Unix milliseconds (0 before the epoch).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve a requested role, defaulting to [`DEFAULT_ROLE`], for a child of an
/// agent at `depth`. A lead may only be delegated when its own depth
/// (`depth + 1`) is below [`MAX_DEPTH`]; workers and reviewers may be delegated
/// while their depth is at most [`MAX_DEPTH`].
fn resolve_role<'a>(
    roles: &'a RoleLibrary,
    requested: Option<&str>,
    depth: u32,
) -> Result<&'a RoleCharter, String> {
    let name = requested.unwrap_or(DEFAULT_ROLE);
    if name == "chief" {
        return Err("ROLE_NOT_ALLOWED: `chief` is the head's own role; delegate to a `lead` instead".to_string());
    }
    let role = roles.get(name).ok_or_else(|| {
        let names = roles.names();
        let available: Vec<&str> = names.iter().filter(|n| n.as_str() != "chief").map(String::as_str).collect();
        format!("UNKNOWN_ROLE: {name}; available: {}", available.join(", "))
    })?;
    let child_depth = depth.saturating_add(1);
    if role.kind == RoleKind::Lead {
        if child_depth >= MAX_DEPTH {
            return Err(format!(
                "ROLE_NOT_ALLOWED: {name} is a lead role and the team is already {child_depth} levels deep (max {MAX_DEPTH})"
            ));
        }
    } else if child_depth > MAX_DEPTH {
        return Err(format!(
            "ROLE_NOT_ALLOWED: {name} cannot be delegated at depth {child_depth} (max {MAX_DEPTH})"
        ));
    }
    Ok(role)
}

/// The child's first user message: the goal, any context, and the acceptance
/// criteria the deliverable is checked against.
fn child_task_message(goal: &str, context: Option<&str>, acceptance: &[String]) -> String {
    let mut message = goal.to_string();
    if let Some(context) = context.filter(|context| !context.trim().is_empty()) {
        message.push_str("\n\nContext:\n");
        message.push_str(context);
    }
    if !acceptance.is_empty() {
        message.push_str("\n\nAcceptance criteria (your work is checked against these):");
        for criterion in acceptance {
            message.push_str("\n- ");
            message.push_str(criterion);
        }
    }
    message
}

/// The report suffix listing changes that could not be merged back.
fn merge_conflict_summary(conflicts: &[String]) -> String {
    if conflicts.is_empty() {
        return String::new();
    }
    format!(
        "\n\nMerge conflicts (not applied; the main workspace changed since this ticket started): {}",
        conflicts.join(", ")
    )
}

/// The board note prefixed to a submitted ticket's summary when a merge conflicted.
fn merge_conflict_note(paths: &[String]) -> Option<String> {
    (!paths.is_empty()).then(|| format!("Merge conflicts: {}", paths.join(", ")))
}

/// Send a report through the org bus. Returns the summary to put in the delegate
/// report and whether the bus quarantined it.
fn send_bus_report(org: &mut OrgState, ticket: &str, child: &str, head: &str, summary: &str) -> (String, bool) {
    let delivery = org.bus.send(OrgMessage {
        from: child.to_string(),
        to: head.to_string(),
        ticket: Some(ticket.to_string()),
        kind: MessageKind::Report,
        summary: summary.to_string(),
        attachments: Vec::new(),
        at_ms: now_ms(),
    });
    match delivery {
        Delivery::Delivered => (summary.to_string(), false),
        Delivery::Quarantined { hits } => (
            format!(
                "[quarantined by the org bus: possible prompt injection ({}); the full text is in the sub-agent's job log]",
                hits.join(", ")
            ),
            true,
        ),
    }
}

/// What to do after a reviewed worker attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NextStep {
    Merge,
    Rework,
    Replace(String),
    Fail(String),
}

/// The decision after one review verdict.
fn next_step(
    accepted: bool,
    rejections: u32,
    book: &PerformanceBook,
    role: &str,
    candidates: &[String],
    tried: &[String],
) -> NextStep {
    if accepted {
        return NextStep::Merge;
    }
    if rejections <= MAX_REJECTIONS {
        return NextStep::Rework;
    }
    match book.choose(role, candidates, tried) {
        Some(model) => NextStep::Replace(model),
        None => NextStep::Fail(format!("rejected {rejections} times and no alternate model is left")),
    }
}

/// The decision after a worker run that did not succeed: skip rework and move to
/// the best untried model, or fail when none is left.
fn failure_step(book: &PerformanceBook, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
    match book.choose(role, candidates, tried) {
        Some(model) => NextStep::Replace(model),
        None => NextStep::Fail("the worker run did not succeed and no alternate model is left".into()),
    }
}

/// The worker's first model: the head's explicit choice, else the book's choice,
/// else the session default.
fn first_model(requested: Option<&str>, book: &PerformanceBook, role: &str, candidates: &[String], default: &str) -> String {
    if let Some(model) = requested.map(str::trim).filter(|model| !model.is_empty()) {
        return model.to_string();
    }
    book.choose(role, candidates, &[]).unwrap_or_else(|| default.to_string())
}

/// The rework message for the same worker after `rejections` rejections.
fn rework_attempt(feedback: &str, rejections: u32) -> String {
    rework_message(feedback, rejections + 1, MAX_REJECTIONS + 1)
}

/// A replacement worker's task: the original task plus the last feedback.
fn replacement_task(task: &str, feedback: &str) -> String {
    format!("{task}\n\nA previous attempt was rejected. Reviewer feedback:\n{feedback}")
}

/// The verdict line appended to the bus/report summary.
fn review_summary_line(accepted: bool, feedback: &str) -> String {
    let verdict = if accepted { "accepted" } else { "rejected" };
    let feedback: String = feedback.chars().take(300).collect();
    format!("\n\nReview: {verdict} — {feedback}")
}

/// Assemble the bus/report summary: worker summary, an optional note, the verdict
/// line when there is one, then any merge conflicts.
fn report_summary(worker_summary: &str, accepted: Option<bool>, feedback: &str, note: Option<&str>, conflicts: &[String]) -> String {
    let mut summary = worker_summary.to_string();
    if let Some(note) = note.filter(|note| !note.trim().is_empty()) {
        summary.push_str("\n\n");
        summary.push_str(note);
    }
    if let Some(accepted) = accepted {
        summary.push_str(&review_summary_line(accepted, feedback));
    }
    summary.push_str(&merge_conflict_summary(conflicts));
    summary
}

/// Pick the reviewer: the role named `reviewer` when present, else the first
/// reviewer-kind role. `None` means changes must not be merged.
fn reviewer_role(roles: &RoleLibrary) -> Option<&RoleCharter> {
    let reviewers = roles.by_kind(RoleKind::Reviewer);
    reviewers
        .iter()
        .copied()
        .find(|role| role.name == "reviewer")
        .or_else(|| reviewers.first().copied())
}

/// The role's sampling settings, including its reasoning effort override.
fn role_sampling(base: &Sampling, role: &RoleCharter) -> Result<Sampling, String> {
    let mut sampling = base.clone();
    if let Some(effort) = &role.reasoning_effort {
        sampling.reasoning_effort = Some(match effort.as_str() {
            "off" => ReasoningEffort::Off,
            "low" => ReasoningEffort::Low,
            "high" => ReasoningEffort::High,
            "max" => ReasoningEffort::Max,
            other => return Err(format!("unknown reasoning_effort `{other}` for role `{}`", role.name)),
        });
    }
    Ok(sampling)
}

/// A reviewer's frozen role settings for one ticket.
struct ReviewerPlan {
    name: String,
    system_prompt: String,
    tools: Vec<ToolSchema>,
    sampling: Sampling,
    model: String,
}

/// Everything one ticket needs, frozen before the loop starts.
struct TicketPlan {
    ticket_id: String,
    role_name: String,
    system_prompt: String,
    tools: Vec<ToolSchema>,
    sampling: Sampling,
    candidates: Vec<String>,
    base_task: String,
    goal: String,
    acceptance: Vec<String>,
    requested_model: Option<String>,
    reviewer: Option<ReviewerPlan>,
    ledger: Arc<bulge_core::ledger::Ledger>,
}

/// A worker job and its private VM slot, kept across reworks.
struct Worker {
    lease: SlotLease,
    slot: u8,
    job: JobHandle,
    ledger: Arc<bulge_core::ledger::Ledger>,
    job_id: String,
}

/// What one driver run produced.
#[derive(Debug, Clone)]
struct RunSummary {
    status: String,
    outcome: String,
    summary: String,
    truncated: bool,
    succeeded: bool,
    steps: u64,
}

/// What one independent review produced.
struct ReviewOutcome {
    /// At least one reviewer ran (even if it produced no verdict).
    reviewed: bool,
    accepted: Option<bool>,
    feedback: String,
    job_id: String,
}

/// Schema for the `delegate` tool the parent model may call. The role enum and
/// description are built from the library's roles, sorted by name.
pub fn delegate_tool(roles: &RoleLibrary) -> ToolSchema {
    let mut role_names = Vec::new();
    let mut role_lines = Vec::new();
    for name in roles.names() {
        let Some(role) = roles.get(&name) else { continue };
        // `chief` is the head's own persona, not a role you delegate to.
        if role.name == "chief" {
            continue;
        }
        role_names.push(name);
        role_lines.push(format!("- {}: {}", role.name, role.purpose));
    }
    let description = format!(
        "Delegate one ticket to a sub-agent playing a role. Several delegate calls in the same message run in parallel (up to {MAX_CONCURRENT_SUBAGENTS} at once). Give each ticket acceptance criteria. Changed files are independently reviewed before they are merged; rejected work is sent back with feedback and, after repeated rejection, reassigned to another model. You receive a structured report: status, outcome, the role it ran as, its ticket id, a summary, the review verdict and the tokens it spent.\n\nRoles:\n{}",
        role_lines.join("\n")
    );
    ToolSchema {
        name: DELEGATE_TOOL.into(),
        description,
        parameters: json!({
            "type": "object",
            "properties": {
                "goal": { "type": "string", "description": "The ticket's goal, stated as a complete, self-contained instruction." },
                "context": { "type": "string", "description": "Optional background the sub-agent needs (it does not see your conversation)." },
                "role": {
                    "type": "string",
                    "enum": role_names,
                    "description": "Role from the organization's role library (defaults to implementer)."
                },
                "model": {
                    "type": "string",
                    "description": "Model for this ticket (overrides the role's default and the performance-based choice)."
                },
                "acceptance": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Concrete criteria the deliverable must meet."
                }
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
    /// The session's VM. Every child builds its own slot dispatcher against it.
    pub vm: Arc<Vm>,
    /// VM workspace slots shared by every child of this session.
    pub vm_slots: Arc<VmSlots>,
    /// User lifecycle hooks, applied to each child's tool calls.
    pub hooks: Arc<HookRunner>,
    /// Per-tool-call timeout, matching the parent's `VmDispatcher`.
    pub tool_timeout: Duration,
    /// Tools the child sees (parent tools minus `delegate`/`org_status` and any
    /// `mcp__*` tools); the role's allowlist filters this per child.
    pub child_tools: Vec<ToolSchema>,
    /// Tools a sub-lead sees: the child tools plus `delegate` and `org_status`.
    pub lead_tools: Vec<ToolSchema>,
    pub store_root: PathBuf,
    pub workspace: PathBuf,
    pub autonomy: Autonomy,
    pub guard_rules: bulge_guard::Ruleset,
    pub model: String,
    pub backend_id: String,
    pub context_window: u32,
    pub sampling: Sampling,
    pub auto_review: bool,
    /// The parent's node of this turn's budget tree. Children are made as its
    /// child nodes, so their spend is charged to the parent's budget.
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    /// The organization's role library, shared so an installed role becomes
    /// usable in the same session.
    pub roles: Arc<RwLock<RoleLibrary>>,
    /// Where governed role charters are installed.
    pub roles_dir: PathBuf,
    /// The append-only governance decision log.
    pub governance_path: PathBuf,
    /// The session's persistent performance book.
    pub perf: Arc<Mutex<PerformanceBook>>,
    /// Where the performance book is saved after every recorded verdict.
    pub perf_path: PathBuf,
    /// The head's board and bus for this session.
    pub org: Arc<Mutex<OrgState>>,
    /// The parent job id, used as the head's name on the board and bus.
    pub head: String,
    /// Depth of the agent that owns this factory (the head is 0).
    pub depth: u32,
    /// The ticket the owning agent is working on; `None` for the head.
    pub parent_ticket: Option<String>,
    /// Merged paths from this team's children, accumulated for a lead's report.
    pub merged_accumulator: Option<Arc<Mutex<Vec<String>>>>,
}

/// The per-team fields [`ChildFactory::for_sub_team`] replaces. Kept separate
/// from the factory's VM-backed state so the transition is independently
/// testable without launching a VM.
struct SubTeamIdentity {
    depth: u32,
    ticket: String,
    head: String,
    ledger: Arc<bulge_core::ledger::Ledger>,
}

fn sub_team_identity(
    depth: u32,
    ticket: String,
    head: String,
    ledger: Arc<bulge_core::ledger::Ledger>,
) -> SubTeamIdentity {
    SubTeamIdentity {
        depth,
        ticket,
        head,
        ledger,
    }
}

impl ChildFactory {
    /// A clone of this factory for a sub-lead's team: the new team sits one
    /// level deeper, posts tickets under `ticket`, reports to `head`, and spends
    /// from `ledger`. Everything else (VM, slots, hooks, roles, org, perf) is
    /// shared.
    pub fn for_sub_team(
        &self,
        depth: u32,
        ticket: String,
        head: String,
        ledger: Arc<bulge_core::ledger::Ledger>,
    ) -> ChildFactory {
        let identity = sub_team_identity(depth, ticket, head, ledger);
        let mut factory = self.clone();
        factory.depth = identity.depth;
        factory.parent_ticket = Some(identity.ticket);
        factory.head = identity.head;
        factory.ledger = identity.ledger;
        // A new team starts its own merge accumulator; run_lead installs it.
        factory.merged_accumulator = None;
        factory
    }

    /// Build the governance handler this agent uses for `propose_role`. It
    /// shares the role library, organization, ledger, and VM with the factory.
    pub fn governance(&self) -> Governance {
        Governance {
            roles: self.roles.clone(),
            backend: self.backend.clone(),
            vm: self.vm.clone(),
            tool_timeout: self.tool_timeout,
            store_root: self.store_root.clone(),
            workspace: self.workspace.clone(),
            autonomy: self.autonomy,
            guard_rules: self.guard_rules.clone(),
            model: self.model.clone(),
            backend_id: self.backend_id.clone(),
            context_window: self.context_window,
            sampling: self.sampling.clone(),
            auto_review: self.auto_review,
            ledger: self.ledger.clone(),
            org: self.org.clone(),
            head: self.head.clone(),
            depth: self.depth,
            roles_dir: self.roles_dir.clone(),
            governance_path: self.governance_path.clone(),
        }
    }

    /// Run one sub-task to completion and return a structured report. Takes one
    /// tree-wide sub-agent slot for the whole ticket (released on return), draws
    /// the ticket's budget from the parent's ledger node, and gives workers and
    /// reviewers their own VM workspace slots. A resolved lead runs its own team
    /// instead: no VM slot and no review, but a scoped board and its own factory.
    async fn run_child(&self, request: DelegateRequest, cancel: CancellationToken) -> Result<DelegateReport, String> {
        // Take one short read lock to resolve the role, its tools, and the
        // reviewer; never hold it across an await. A newly installed trial role
        // is visible here immediately.
        let (role_name, is_lead, system_prompt, tools, sampling, budget_share, candidates, reviewer) = {
            let roles = self.roles.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            let role = resolve_role(&roles, request.role.as_deref(), self.depth)?;
            let role_name = role.name.clone();
            let is_lead = role.kind == RoleKind::Lead;
            let system_prompt = role.system_prompt();
            let tools = self.tools_for(role);
            let sampling = role_sampling(&self.sampling, role)?;
            let candidates = role.candidate_models(&self.model);
            let accepted_so_far = {
                let mut models = BTreeSet::new();
                models.insert(self.model.clone());
                for name in roles.names() {
                    if let Some(existing) = roles.get(&name) {
                        if let Some(model) = &existing.model {
                            models.insert(model.clone());
                        }
                        for alternate in &existing.alternates {
                            models.insert(alternate.clone());
                        }
                    }
                }
                let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                models
                    .iter()
                    .map(|model| book.get(&role_name, model).accepted)
                    .sum()
            };
            let budget_share = role.effective_budget_share(accepted_so_far);
            let reviewer = if is_lead {
                None
            } else {
                match reviewer_role(&roles) {
                    Some(charter) => Some(ReviewerPlan {
                        name: charter.name.clone(),
                        system_prompt: charter.system_prompt(),
                        tools: self.role_tools(charter),
                        sampling: role_sampling(&self.sampling, charter)?,
                        model: charter.model.clone().unwrap_or_else(|| self.model.clone()),
                    }),
                    None => None,
                }
            };
            (
                role_name,
                is_lead,
                system_prompt,
                tools,
                sampling,
                budget_share,
                candidates,
                reviewer,
            )
        };

        let _slot = match self.ledger.try_acquire_slot() {
            Some(slot) => slot,
            None => {
                let (spawned, total_max) = self.ledger.spawned();
                if spawned >= total_max {
                    return Err(format!(
                        "TOTAL_AGENTS_REACHED: {spawned} of {total_max} agents have been spawned for this goal"
                    ));
                }
                let (used, max) = self.ledger.slots();
                return Err(format!(
                    "SLOTS_FULL: {used} of {max} sub-agents are already running; wait for one to finish or do the work yourself"
                ));
            }
        };

        if !is_lead && !bulge_vm::slots::supports_slots(&self.vm) {
            return Err(
                "SLOTS_UNSUPPORTED: this VM's rootfs has no workspace slot commands; rebuild the rootfs with scripts/build-rootfs.sh".into(),
            );
        }

        // The ticket's budget node: worker and reviewer attempts are its children,
        // so retries and reviews stay inside the role's share of the parent budget.
        let shared_limit = (self.ledger.remaining() as f64 * budget_share) as u64;
        let ticket_limit = CHILD_MAX_TOKENS.min(shared_limit);
        let ticket_ledger = self.ledger.child(ticket_limit, Some(CHILD_MAX_WALL_SECS));
        if ticket_ledger.exhausted() {
            return Err("BUDGET_EXHAUSTED: the parent budget has nothing left for a sub-agent".into());
        }

        // Post the ticket before any work runs. A posting failure fails the
        // delegation (there is no ticket to attach later failures to).
        let ticket_id = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            post_ticket(
                &mut org,
                self.parent_ticket.clone(),
                &role_name,
                &request.goal,
                &request.acceptance,
                ticket_ledger.token_limit(),
            )?
        };

        let base_task = child_task_message(&request.goal, request.context.as_deref(), &request.acceptance);
        let plan = TicketPlan {
            ticket_id: ticket_id.clone(),
            role_name,
            system_prompt,
            tools,
            sampling,
            candidates,
            base_task,
            goal: request.goal,
            acceptance: request.acceptance,
            requested_model: request.model,
            reviewer,
            ledger: ticket_ledger,
        };

        let outcome = if is_lead {
            self.run_lead(&plan, &cancel).await
        } else {
            let mut worker: Option<Worker> = None;
            let outcome = self.ticket_loop(&plan, &cancel, &mut worker).await;
            if let Some(worker) = worker.take() {
                self.finish_worker(worker).await;
            }
            outcome
        };
        match &outcome {
            Ok(report) => self.accumulate_merged(&report.merged),
            Err(reason) => self.fail_if_open(&ticket_id, reason, cancel.is_cancelled()),
        }
        outcome
    }

    /// A sub-lead runs its own team: the same board and bus, a factory whose
    /// children are its tickets, and a situation report scoped to its team. It
    /// edits no files, so it takes no VM slot and its own ticket is never
    /// reviewed or merged; the parent judges its report.
    async fn run_lead(&self, plan: &TicketPlan, cancel: &CancellationToken) -> Result<DelegateReport, String> {
        let model = self.choose_first(plan.requested_model.as_deref(), &plan.role_name, &plan.candidates);
        let (mut job, job_id) = self.create_child_job(&plan.base_task, &model, &plan.ledger)?;
        self.record_board(BoardEvent::Claimed {
            id: plan.ticket_id.clone(),
            owner: job_id.clone(),
            at_ms: now_ms(),
        });
        self.record_board(BoardEvent::Started {
            id: plan.ticket_id.clone(),
            at_ms: now_ms(),
        });

        let merged = Arc::new(Mutex::new(Vec::new()));
        let mut sub_factory = self.for_sub_team(
            self.depth.saturating_add(1),
            plan.ticket_id.clone(),
            job_id.clone(),
            plan.ledger.clone(),
        );
        sub_factory.merged_accumulator = Some(merged.clone());
        let run = self.drive_lead(&mut job, plan, &sub_factory, cancel).await?;

        let merged_paths = merged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let failure = (!run.succeeded).then(|| {
            format!("lead run did not succeed: {}/{}", run.status, run.outcome)
        });
        if run.succeeded {
            self.record_board(BoardEvent::Submitted {
                id: plan.ticket_id.clone(),
                summary: run.summary.clone(),
                at_ms: now_ms(),
            });
        } else {
            let reason = failure.clone().unwrap_or_else(|| "lead run did not succeed".into());
            self.record_board(BoardEvent::Failed {
                id: plan.ticket_id.clone(),
                reason,
                at_ms: now_ms(),
            });
        }

        let summary = report_summary(&run.summary, None, "", failure.as_deref(), &[]);
        let (summary, quarantined) = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            send_bus_report(&mut org, &plan.ticket_id, &job_id, &self.head, &summary)
        };
        Ok(DelegateReport {
            status: run.status.clone(),
            outcome: run.outcome.clone(),
            role: plan.role_name.clone(),
            ticket: plan.ticket_id.clone(),
            summary,
            truncated: run.truncated || quarantined,
            tokens: plan.ledger.spent(),
            steps: run.steps,
            job_id,
            changed: merged_paths.clone(),
            merged: merged_paths,
            conflicts: Vec::new(),
            reviewed: false,
            accepted: None,
            feedback: String::new(),
            attempts: 1,
            models: vec![model],
        })
    }

    /// Drive one lead against the main workspace (no slot) with its own
    /// delegation factory and a team-scoped situation report.
    async fn drive_lead(
        &self,
        job: &mut JobHandle,
        plan: &TicketPlan,
        sub_factory: &ChildFactory,
        cancel: &CancellationToken,
    ) -> Result<RunSummary, String> {
        let base: Arc<dyn ToolDispatcher> = Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout));
        let dispatcher: Arc<dyn ToolDispatcher> = if self.hooks.is_empty() {
            base
        } else {
            Arc::new(HookedDispatcher::new(base, self.hooks.clone()))
        };
        let context = ContextConfig {
            window: self.context_window as u64,
            ..ContextConfig::default()
        };
        let ledger = plan.ledger.clone();
        let driver = Driver::new(self.backend.clone(), dispatcher, plan.tools.clone(), plan.system_prompt.clone())
            .with_guard(GuardConfig {
                rules: self.guard_rules.clone(),
                autonomy: crate::run::guard_autonomy(self.autonomy),
                loop_detection: true,
            })
            .with_completion_gate(CompletionConfig::default())
            .with_context(context)
            .with_sampling(plan.sampling.clone())
            .with_review(self.auto_review)
            .with_delegate(Arc::new(sub_factory.clone()))
            .with_propose_role(Arc::new(sub_factory.governance()))
            .with_org_status(Arc::new(OrgStatus {
                org: self.org.clone(),
                ledger: ledger.clone(),
                scope: Some(plan.ticket_id.clone()),
            }))
            .with_ledger(ledger);

        let outcome = driver
            .run(job, cancel.clone())
            .await
            .map_err(|error| format!("lead run: {error}"))?;
        Ok(run_summary(job, outcome))
    }

    /// The tools one role may use, with host-side MCP tools always removed.
    fn tools_for(&self, role: &RoleCharter) -> Vec<ToolSchema> {
        let all = if role.kind == RoleKind::Lead { &self.lead_tools } else { &self.child_tools };
        role.filter_tools(all)
            .into_iter()
            .filter(|tool| !tool.name.starts_with("mcp__"))
            .collect()
    }

    /// Append a completed child's merged paths to this team's accumulator, if it
    /// has one. Used to build a lead's `changed`/`merged` report lists.
    fn accumulate_merged(&self, merged: &[String]) {
        let Some(accumulator) = &self.merged_accumulator else { return };
        let mut paths = accumulator.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for path in merged {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
    }

    /// The tools one role may use, with host-side MCP tools always removed.
    fn role_tools(&self, role: &RoleCharter) -> Vec<ToolSchema> {
        role.filter_tools(&self.child_tools)
            .into_iter()
            .filter(|tool| !tool.name.starts_with("mcp__"))
            .collect()
    }

    /// The ticket loop: worker attempt, independent review, then merge, rework or
    /// replacement. All terminal board writes happen here; the outer cleanup only
    /// fills in a missing failure/cancellation and closes any open slot.
    async fn ticket_loop(
        &self,
        plan: &TicketPlan,
        cancel: &CancellationToken,
        worker: &mut Option<Worker>,
    ) -> Result<DelegateReport, String> {
        let mut model = self.choose_first(plan.requested_model.as_deref(), &plan.role_name, &plan.candidates);
        let mut task = plan.base_task.clone();
        let mut attempts: u32 = 0;
        let mut models: Vec<String> = Vec::new();
        let mut tried: Vec<String> = Vec::new();
        let mut rejections: u32 = 0;
        let mut feedback = String::new();

        'outer: loop {
            let mut current = self.start_worker(plan, &task, &model, cancel).await?;
            loop {
                let before = current.ledger.spent();
                let run = self.run_worker(&mut current, plan, cancel).await?;
                let worker_tokens = current.ledger.spent().saturating_sub(before);
                let job_id = current.job_id.clone();
                attempts += 1;
                models.push(model.clone());
                if !tried.contains(&model) {
                    tried.push(model.clone());
                }

                if cancel.is_cancelled() || run.status == "cancelled" || run.outcome == "cancelled" {
                    self.record_board(BoardEvent::Cancelled {
                        id: plan.ticket_id.clone(),
                        reason: "cancelled by the parent".into(),
                        at_ms: now_ms(),
                    });
                    *worker = Some(current);
                    return Err("CANCELLED: the delegation was cancelled".into());
                }

                if !run.succeeded {
                    self.record_perf(&plan.role_name, &model, Verdict::Failed, worker_tokens);
                    let run_reason = format!("worker run did not succeed: {}/{}", run.status, run.outcome);
                    match self.next_after_failure(&plan.role_name, &plan.candidates, &tried) {
                        NextStep::Replace(next) => {
                            // A failed run has no review, so make the replacement
                            // transition legal: Submitted -> Rejected -> Reassigned.
                            self.record_board(BoardEvent::Submitted {
                                id: plan.ticket_id.clone(),
                                summary: run.summary.clone(),
                                at_ms: now_ms(),
                            });
                            self.record_board(BoardEvent::Rejected {
                                id: plan.ticket_id.clone(),
                                reviewer: "system".into(),
                                feedback: run_reason.clone(),
                                at_ms: now_ms(),
                            });
                            self.record_board(BoardEvent::Reassigned {
                                id: plan.ticket_id.clone(),
                                role: plan.role_name.clone(),
                                reason: format!("replaced after a failed run: {model} → {next}"),
                                at_ms: now_ms(),
                            });
                            self.finish_worker(current).await;
                            model = next;
                            task = plan.base_task.clone();
                            continue 'outer;
                        }
                        NextStep::Fail(reason) => {
                            self.record_board(BoardEvent::Failed {
                                id: plan.ticket_id.clone(),
                                reason: reason.clone(),
                                at_ms: now_ms(),
                            });
                            self.finish_worker(current).await;
                            return Ok(self.finalize(
                                plan,
                                &run,
                                &job_id,
                                false,
                                None,
                                &feedback,
                                attempts,
                                models,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                Some(&reason),
                            ));
                        }
                        NextStep::Merge | NextStep::Rework => unreachable!("failure cannot merge or rework"),
                    }
                }

                let (changed, lost) = self.collect_changes(current.slot).await;
                let lost_paths: Vec<String> = lost.iter().map(|conflict| conflict.path.clone()).collect();
                let conflicts = format_conflicts(&lost);
                let board_summary = match merge_conflict_note(&lost_paths) {
                    Some(note) => format!("{note}\n\n{}", run.summary),
                    None => run.summary.clone(),
                };

                if changed.is_empty() {
                    self.record_board(BoardEvent::Submitted {
                        id: plan.ticket_id.clone(),
                        summary: board_summary,
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        false,
                        None,
                        &feedback,
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        None,
                    ));
                }

                let Some(reviewer) = &plan.reviewer else {
                    self.record_board(BoardEvent::Submitted {
                        id: plan.ticket_id.clone(),
                        summary: board_summary,
                        at_ms: now_ms(),
                    });
                    self.record_board(BoardEvent::Failed {
                        id: plan.ticket_id.clone(),
                        reason: NO_REVIEWER.into(),
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        false,
                        None,
                        "",
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        Some(NO_REVIEWER),
                    ));
                };

                self.record_board(BoardEvent::Submitted {
                    id: plan.ticket_id.clone(),
                    summary: board_summary,
                    at_ms: now_ms(),
                });

                let review = match self.review(plan, reviewer, &run.summary, &changed, current.slot, cancel).await {
                    Ok(review) => review,
                    Err(error) => {
                        *worker = Some(current);
                        return Err(error);
                    }
                };
                if cancel.is_cancelled() {
                    self.record_board(BoardEvent::Cancelled {
                        id: plan.ticket_id.clone(),
                        reason: "cancelled by the parent".into(),
                        at_ms: now_ms(),
                    });
                    *worker = Some(current);
                    return Err("CANCELLED: the delegation was cancelled".into());
                }
                feedback = review.feedback.clone();

                let Some(verdict) = review.accepted else {
                    self.record_board(BoardEvent::Failed {
                        id: plan.ticket_id.clone(),
                        reason: "review produced no verdict".into(),
                        at_ms: now_ms(),
                    });
                    self.finish_worker(current).await;
                    let mut final_run = run.clone();
                    final_run.summary = format!("{}\n\nreview produced no verdict", run.summary);
                    return Ok(self.finalize(
                        plan,
                        &final_run,
                        &job_id,
                        review.reviewed,
                        None,
                        &feedback,
                        attempts,
                        models,
                        changed,
                        Vec::new(),
                        conflicts,
                        None,
                    ));
                };

                if verdict {
                    self.record_board(BoardEvent::Accepted {
                        id: plan.ticket_id.clone(),
                        reviewer: review.job_id.clone(),
                        note: review.feedback.clone(),
                        at_ms: now_ms(),
                    });
                    self.record_perf(&plan.role_name, &model, Verdict::Accepted, worker_tokens);
                    let merge = self.merge_slot(current.slot, &changed, lost).await;
                    let merged = merge.merged;
                    let conflicts = format_conflicts(&merge.conflicts);
                    if merge.conflicts.is_empty() {
                        self.record_board(BoardEvent::Merged {
                            id: plan.ticket_id.clone(),
                            at_ms: now_ms(),
                        });
                    }
                    self.finish_worker(current).await;
                    return Ok(self.finalize(
                        plan,
                        &run,
                        &job_id,
                        true,
                        Some(true),
                        &review.feedback,
                        attempts,
                        models,
                        changed,
                        merged,
                        conflicts,
                        None,
                    ));
                }

                self.record_board(BoardEvent::Rejected {
                    id: plan.ticket_id.clone(),
                    reviewer: review.job_id.clone(),
                    feedback: review.feedback.clone(),
                    at_ms: now_ms(),
                });
                self.record_perf(&plan.role_name, &model, Verdict::Rejected, worker_tokens);
                rejections += 1;
                match self.next_after_review(false, rejections, &plan.role_name, &plan.candidates, &tried) {
                    NextStep::Merge => unreachable!("a rejection cannot merge"),
                    NextStep::Rework => {
                        let message = rework_attempt(&review.feedback, rejections);
                        if let Err(error) = current.job.append(vec![JobEvent::Message {
                            message: Message::text(Role::User, message),
                        }]) {
                            *worker = Some(current);
                            return Err(format!("append rework message: {error}"));
                        }
                        self.record_board(BoardEvent::Started {
                            id: plan.ticket_id.clone(),
                            at_ms: now_ms(),
                        });
                        continue;
                    }
                    NextStep::Replace(next) => {
                        self.finish_worker(current).await;
                        self.record_board(BoardEvent::Reassigned {
                            id: plan.ticket_id.clone(),
                            role: plan.role_name.clone(),
                            reason: format!("replaced after {rejections} rejections: {model} → {next}"),
                            at_ms: now_ms(),
                        });
                        model = next;
                        task = replacement_task(&plan.base_task, &review.feedback);
                        continue 'outer;
                    }
                    NextStep::Fail(reason) => {
                        self.record_board(BoardEvent::Failed {
                            id: plan.ticket_id.clone(),
                            reason: reason.clone(),
                            at_ms: now_ms(),
                        });
                        self.finish_worker(current).await;
                        return Ok(self.finalize(
                            plan,
                            &run,
                            &job_id,
                            true,
                            Some(false),
                            &review.feedback,
                            attempts,
                            models,
                            changed,
                            Vec::new(),
                            conflicts,
                            Some(&reason),
                        ));
                    }
                }
            }
        }
    }

    fn choose_first(&self, requested: Option<&str>, role: &str, candidates: &[String]) -> String {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        first_model(requested, &book, role, candidates, &self.model)
    }

    fn next_after_review(&self, accepted: bool, rejections: u32, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        next_step(accepted, rejections, &book, role, candidates, tried)
    }

    fn next_after_failure(&self, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
        let book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        failure_step(&book, role, candidates, tried)
    }

    /// Record one outcome and persist the book immediately. The lock is never
    /// held across an await (this method is synchronous).
    fn record_perf(&self, role: &str, model: &str, verdict: Verdict, tokens: u64) {
        let mut book = self.perf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        book.record(role, model, verdict, tokens, now_ms());
        if let Err(error) = book.save(&self.perf_path) {
            eprintln!("org: save performance book {}: {error}", self.perf_path.display());
        }
    }

    fn record_board(&self, event: BoardEvent) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let OrgState { board, log, .. } = &mut *org;
        if let Err(error) = log.append(board, event) {
            eprintln!("org: board write failed: {error}");
        }
    }

    /// Mark a still-open ticket failed or cancelled. Terminal tickets are left
    /// alone, so an error after a deliberate Failed/Merged never double-writes.
    fn fail_if_open(&self, ticket: &str, reason: &str, cancelled: bool) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = org.board.get(ticket).map(|ticket| ticket.status);
        if matches!(
            status,
            Some(TicketStatus::Merged | TicketStatus::Cancelled | TicketStatus::Failed)
        ) {
            return;
        }
        let event = if cancelled {
            BoardEvent::Cancelled {
                id: ticket.to_string(),
                reason: reason.to_string(),
                at_ms: now_ms(),
            }
        } else {
            BoardEvent::Failed {
                id: ticket.to_string(),
                reason: reason.to_string(),
                at_ms: now_ms(),
            }
        };
        let OrgState { board, log, .. } = &mut *org;
        if let Err(error) = log.append(board, event) {
            eprintln!("org: terminal board write for ticket {ticket} failed: {error}");
        }
    }

    /// Lease a VM slot and open it. The reviewer path waits up to ten minutes in
    /// one-second steps (honouring cancellation); the worker path fails at once.
    async fn lease_slot(&self, wait: bool, cancel: &CancellationToken) -> Result<SlotLease, String> {
        let deadline = Instant::now() + REVIEW_SLOT_WAIT;
        loop {
            if cancel.is_cancelled() {
                return Err("CANCELLED: the delegation was cancelled".into());
            }
            if let Some(lease) = self.vm_slots.lease() {
                let slot = lease.index();
                match slots::open(&self.vm, slot).await {
                    Ok(()) => return Ok(lease),
                    Err(error) => {
                        drop(lease);
                        return Err(format!("SLOT_OPEN: could not open VM workspace slot {slot}: {error}"));
                    }
                }
            }
            if !wait {
                return Err(format!(
                    "SLOTS_FULL: all {MAX_CONCURRENT_SUBAGENTS} VM workspace slots are in use; wait for one to finish"
                ));
            }
            if Instant::now() >= deadline {
                return Err("SLOTS_FULL: no VM workspace slot became free for the reviewer within 10 minutes".into());
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                () = cancel.cancelled() => return Err("CANCELLED: the delegation was cancelled".into()),
            }
        }
    }

    fn create_child_job(&self, task: &str, model: &str, ledger: &Arc<bulge_core::ledger::Ledger>) -> Result<(JobHandle, String), String> {
        let store = JobStore::new(&self.store_root);
        let job_id = bulge_store::new_job_id().map_err(|error| format!("child job id: {error}"))?;
        let title: String = task.lines().next().unwrap_or("sub-task").chars().take(80).collect();
        let mut job = store
            .create(JobSpec {
                id: job_id.clone(),
                title,
                goal: task.to_string(),
                workspace: self.workspace.clone(),
                autonomy: self.autonomy,
                budget: Budget {
                    max_steps: CHILD_MAX_STEPS,
                    max_tokens: ledger.token_limit(),
                    max_wall_secs: ledger.remaining_secs().unwrap_or(CHILD_MAX_WALL_SECS),
                },
                model: ModelRef {
                    backend: self.backend_id.clone(),
                    model: model.to_string(),
                },
            })
            .map_err(|error| format!("create child job: {error}"))?;
        job.append(vec![JobEvent::Message {
            message: Message::text(Role::User, task),
        }])
        .map_err(|error| format!("append child task: {error}"))?;
        Ok((job, job_id))
    }

    /// Lease and open the worker's slot, create its job, and claim/start the ticket.
    async fn start_worker(
        &self,
        plan: &TicketPlan,
        task: &str,
        model: &str,
        cancel: &CancellationToken,
    ) -> Result<Worker, String> {
        let lease = self.lease_slot(false, cancel).await?;
        let slot = lease.index();
        let ledger = plan.ledger.child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
        if ledger.exhausted() {
            let _ = slots::close(&self.vm, slot).await;
            return Err("BUDGET_EXHAUSTED: the ticket has nothing left for a worker".into());
        }
        let (job, job_id) = match self.create_child_job(task, model, &ledger) {
            Ok(job) => job,
            Err(error) => {
                let _ = slots::close(&self.vm, slot).await;
                return Err(error);
            }
        };
        self.record_board(BoardEvent::Claimed {
            id: plan.ticket_id.clone(),
            owner: job_id.clone(),
            at_ms: now_ms(),
        });
        self.record_board(BoardEvent::Started {
            id: plan.ticket_id.clone(),
            at_ms: now_ms(),
        });
        Ok(Worker {
            lease,
            slot,
            job,
            ledger,
            job_id,
        })
    }

    async fn run_worker(&self, worker: &mut Worker, plan: &TicketPlan, cancel: &CancellationToken) -> Result<RunSummary, String> {
        self.drive_child(
            &mut worker.job,
            &worker.ledger,
            worker.slot,
            plan.system_prompt.clone(),
            plan.tools.clone(),
            plan.sampling.clone(),
            cancel,
        )
        .await
    }

    /// Run one child driver against a slot and summarize its final state.
    #[allow(clippy::too_many_arguments)]
    async fn drive_child(
        &self,
        job: &mut JobHandle,
        ledger: &Arc<bulge_core::ledger::Ledger>,
        slot: u8,
        system_prompt: String,
        tools: Vec<ToolSchema>,
        sampling: Sampling,
        cancel: &CancellationToken,
    ) -> Result<RunSummary, String> {
        let base: Arc<dyn ToolDispatcher> = Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout).with_slot(slot));
        let dispatcher: Arc<dyn ToolDispatcher> = if self.hooks.is_empty() {
            base
        } else {
            Arc::new(HookedDispatcher::new(base, self.hooks.clone()))
        };
        let context = ContextConfig {
            window: self.context_window as u64,
            ..ContextConfig::default()
        };
        let driver = Driver::new(self.backend.clone(), dispatcher, tools, system_prompt)
            .with_guard(GuardConfig {
                rules: self.guard_rules.clone(),
                autonomy: crate::run::guard_autonomy(self.autonomy),
                loop_detection: true,
            })
            .with_completion_gate(CompletionConfig::default())
            .with_context(context)
            .with_sampling(sampling)
            .with_review(self.auto_review)
            .with_ledger(ledger.clone());

        let outcome = driver
            .run(job, cancel.clone())
            .await
            .map_err(|error| format!("child run: {error}"))?;
        Ok(run_summary(job, outcome))
    }

    async fn collect_changes(&self, slot: u8) -> (Vec<String>, Vec<MergeConflict>) {
        match slots::collect(&self.vm, slot).await {
            Ok(changes) => (changes.iter().map(|change| change.path().to_string()).collect(), Vec::new()),
            Err(error) => {
                eprintln!("delegate: collect changes from VM slot {slot}: {error}");
                (
                    Vec::new(),
                    vec![MergeConflict {
                        path: "*".into(),
                        reason: format!("could not collect the sub-agent's changes: {error}"),
                    }],
                )
            }
        }
    }

    async fn merge_slot(&self, slot: u8, changed: &[String], lost: Vec<MergeConflict>) -> MergeReport {
        let mut merge = match slots::merge(&self.vm, slot, changed).await {
            Ok(report) => report,
            Err(error) => {
                eprintln!("delegate: merge from VM slot {slot}: {error}");
                MergeReport {
                    merged: Vec::new(),
                    conflicts: changed
                        .iter()
                        .map(|path| MergeConflict {
                            path: path.clone(),
                            reason: format!("merge failed: {error}"),
                        })
                        .collect(),
                }
            }
        };
        merge.conflicts.extend(lost);
        merge
    }

    async fn finish_worker(&self, worker: Worker) {
        let Worker { lease, slot, .. } = worker;
        if let Err(error) = slots::close(&self.vm, slot).await {
            eprintln!("delegate: close VM slot {slot}: {error}");
        }
        drop(lease);
    }

    /// Open a staging slot containing the worker's changed files, run the reviewer
    /// (once more if the first answer has no verdict), and always discard the
    /// staging slot afterwards. The worker's slot is not touched here.
    async fn review(
        &self,
        plan: &TicketPlan,
        reviewer: &ReviewerPlan,
        worker_summary: &str,
        changed: &[String],
        from_slot: u8,
        cancel: &CancellationToken,
    ) -> Result<ReviewOutcome, String> {
        let lease = self.lease_slot(true, cancel).await?;
        let slot = lease.index();
        let result: Result<ReviewOutcome, String> = async {
            slots::stage(&self.vm, slot, from_slot, changed)
                .await
                .map_err(|error| format!("SLOT_STAGE: copy the worker's changes into review slot {slot}: {error}"))?;
            let task = review_task(&plan.goal, &plan.acceptance, worker_summary, changed);
            let mut last_job = String::new();
            for attempt in 0..2 {
                let ledger = plan.ledger.child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
                if ledger.exhausted() {
                    return Err("BUDGET_EXHAUSTED: the ticket has nothing left for a reviewer".into());
                }
                let (mut job, job_id) = self.create_child_job(&task, &reviewer.model, &ledger)?;
                last_job = job_id.clone();
                let run = match self
                    .drive_child(
                        &mut job,
                        &ledger,
                        slot,
                        reviewer.system_prompt.clone(),
                        reviewer.tools.clone(),
                        reviewer.sampling.clone(),
                        cancel,
                    )
                    .await
                {
                    Ok(run) => run,
                    Err(error) if cancel.is_cancelled() => {
                        return Err(format!("CANCELLED: the review was cancelled: {error}"));
                    }
                    Err(error) => {
                        if attempt == 0 {
                            eprintln!(
                                "delegate: reviewer {} for ticket {} failed: {error}; asking once more",
                                reviewer.name, plan.ticket_id
                            );
                        } else {
                            eprintln!(
                                "delegate: reviewer {} for ticket {} failed: {error}",
                                reviewer.name, plan.ticket_id
                            );
                        }
                        continue;
                    }
                };
                if cancel.is_cancelled() {
                    return Err("CANCELLED: the review was cancelled".into());
                }
                if let Some(Review { accept, feedback }) = parse_review(&run.summary) {
                    return Ok(ReviewOutcome {
                        reviewed: true,
                        accepted: Some(accept),
                        feedback,
                        job_id,
                    });
                }
                if attempt == 0 {
                    eprintln!(
                        "delegate: reviewer {} for ticket {} produced no verdict; asking once more",
                        reviewer.name, plan.ticket_id
                    );
                }
            }
            Ok(ReviewOutcome {
                reviewed: true,
                accepted: None,
                feedback: String::new(),
                job_id: last_job,
            })
        }
        .await;
        if let Err(error) = slots::close(&self.vm, slot).await {
            eprintln!("delegate: close review slot {slot}: {error}");
        }
        drop(lease);
        result
    }

    /// Build and send the final report, appending the verdict line when there is one.
    #[allow(clippy::too_many_arguments)]
    fn finalize(
        &self,
        plan: &TicketPlan,
        run: &RunSummary,
        job_id: &str,
        reviewed: bool,
        accepted: Option<bool>,
        feedback: &str,
        attempts: u32,
        models: Vec<String>,
        changed: Vec<String>,
        merged: Vec<String>,
        conflicts: Vec<String>,
        note: Option<&str>,
    ) -> DelegateReport {
        let summary = report_summary(&run.summary, accepted, feedback, note, &conflicts);
        let (summary, quarantined) = {
            let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            send_bus_report(&mut org, &plan.ticket_id, job_id, &self.head, &summary)
        };
        DelegateReport {
            status: run.status.clone(),
            outcome: run.outcome.clone(),
            role: plan.role_name.clone(),
            ticket: plan.ticket_id.clone(),
            summary,
            truncated: run.truncated || quarantined,
            tokens: plan.ledger.spent(),
            steps: run.steps,
            job_id: job_id.to_string(),
            changed,
            merged,
            conflicts,
            reviewed,
            accepted,
            feedback: feedback.to_string(),
            attempts,
            models,
        }
    }
}

/// Summarize a finished child (worker, reviewer, or lead) job: prefer its
/// recorded summary, else fall back to the last assistant message.
fn run_summary(job: &JobHandle, outcome: LoopOutcome) -> RunSummary {
    let state = job.state();
    let text = if let Some(summary) = state.summary.clone().filter(|summary| !summary.trim().is_empty()) {
        summary
    } else {
        let last = state.history.iter().rev().find_map(|message| {
            if message.role != Role::Assistant {
                return None;
            }
            let text: String = message
                .content
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            (!text.trim().is_empty()).then_some(text)
        });
        last.unwrap_or_else(|| "(sub-agent produced no summary)".to_string())
    };
    let (summary, truncated) = truncate_summary(&text, SUMMARY_CAP_CHARS);
    let status = serde_json::to_value(state.status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    RunSummary {
        succeeded: state.status == JobStatus::Succeeded,
        status,
        outcome: outcome_name(outcome).to_string(),
        summary,
        truncated,
        steps: state.steps,
    }
}

/// Format merge conflicts for the report.
fn format_conflicts(conflicts: &[MergeConflict]) -> Vec<String> {
    conflicts
        .iter()
        .map(|conflict| format!("{}: {}", conflict.path, conflict.reason))
        .collect()
}

/// The `LoopOutcome`'s snake_case name, for the report's `outcome` field.
fn outcome_name(outcome: LoopOutcome) -> &'static str {
    match outcome {
        LoopOutcome::Stopped => "stopped",
        LoopOutcome::BudgetExhausted => "budget_exhausted",
        LoopOutcome::Cancelled => "cancelled",
        LoopOutcome::Failed => "failed",
        LoopOutcome::Stuck => "stuck",
        LoopOutcome::Incomplete => "incomplete",
    }
}

/// Shorten `text` to at most `cap` characters for the parent's context: short
/// text is returned unchanged; long text keeps the first two-thirds and the last
/// third, joined by a note pointing at the child's full job log. Always slices on
/// char boundaries (never bytes), so it is UTF-8 safe.
pub fn truncate_summary(text: &str, cap: usize) -> (String, bool) {
    let total = text.chars().count();
    if total <= cap {
        return (text.to_string(), false);
    }
    let head_len = cap * 2 / 3;
    let tail_len = cap / 3;
    let omitted = total.saturating_sub(head_len + tail_len);
    let head: String = text.chars().take(head_len).collect();
    let tail: String = text.chars().skip(total - tail_len).collect();
    (
        format!("{head}\n[… {omitted} chars omitted; full text in the sub-agent's job log …]\n{tail}"),
        true,
    )
}

impl DelegateHandler for ChildFactory {
    fn run<'a>(&'a self, request: DelegateRequest, cancel: CancellationToken) -> LocalBoxFuture<'a, Result<DelegateReport, String>> {
        Box::pin(self.run_child(request, cancel))
    }
}

/// Governance of role proposals: validates a proposed charter, runs one
/// independent auditor (the `reviewer` role, no VM slot, read-only tools), and
/// installs the role on trial when both pass. The shared role library is updated
/// in place so the role is usable for the rest of the session.
pub struct Governance {
    pub roles: Arc<RwLock<RoleLibrary>>,
    pub backend: Arc<dyn LlmBackend>,
    pub vm: Arc<Vm>,
    pub tool_timeout: Duration,
    pub store_root: PathBuf,
    pub workspace: PathBuf,
    pub autonomy: Autonomy,
    pub guard_rules: bulge_guard::Ruleset,
    pub model: String,
    pub backend_id: String,
    pub context_window: u32,
    pub sampling: Sampling,
    pub auto_review: bool,
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    pub org: Arc<Mutex<OrgState>>,
    pub head: String,
    pub depth: u32,
    pub roles_dir: PathBuf,
    pub governance_path: PathBuf,
}

impl Governance {
    /// Announce a governance event on the org bus to the human observer.
    fn announce(&self, summary: &str) {
        let mut org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = org.bus.send(OrgMessage {
            from: self.head.clone(),
            to: "observer".to_string(),
            ticket: None,
            kind: MessageKind::Ruling,
            summary: summary.to_string(),
            attachments: Vec::new(),
            at_ms: now_ms(),
        });
    }

    fn decision(&self, event: &str, role: &str, detail: &str) -> Result<(), String> {
        append_decision(
            &self.governance_path,
            event,
            role,
            &self.head,
            detail,
            now_ms(),
        )
    }

    /// Run exactly one auditor child as the reviewer role. It runs in the main
    /// workspace with no VM slot and only read-only tools because it judges the
    /// charter text, not a set of changes.
    async fn audit(
        &self,
        task: &str,
        reviewer: &RoleCharter,
        cancel: &CancellationToken,
    ) -> Result<Option<Review>, String> {
        let ledger = self
            .ledger
            .child(CHILD_MAX_TOKENS, Some(CHILD_MAX_WALL_SECS));
        if ledger.exhausted() {
            return Err("BUDGET_EXHAUSTED: no budget is left to audit the proposal".into());
        }
        let model = reviewer.model.clone().unwrap_or_else(|| self.model.clone());
        let store = JobStore::new(&self.store_root);
        let job_id = bulge_store::new_job_id().map_err(|error| format!("auditor job id: {error}"))?;
        let title: String = task.lines().next().unwrap_or("role audit").chars().take(80).collect();
        let mut job = store
            .create(JobSpec {
                id: job_id,
                title,
                goal: task.to_string(),
                workspace: self.workspace.clone(),
                autonomy: self.autonomy,
                budget: Budget {
                    max_steps: CHILD_MAX_STEPS,
                    max_tokens: ledger.token_limit(),
                    max_wall_secs: ledger.remaining_secs().unwrap_or(CHILD_MAX_WALL_SECS),
                },
                model: ModelRef {
                    backend: self.backend_id.clone(),
                    model: model.clone(),
                },
            })
            .map_err(|error| format!("create auditor job: {error}"))?;
        job.append(vec![JobEvent::Message {
            message: Message::text(Role::User, task.to_string()),
        }])
        .map_err(|error| format!("append auditor task: {error}"))?;

        let tools: Vec<ToolSchema> = reviewer
            .filter_tools(&builtin_tools())
            .into_iter()
            .filter(|tool| matches!(tool.name.as_str(), "read" | "grep" | "glob"))
            .collect();
        let dispatcher: Arc<dyn ToolDispatcher> =
            Arc::new(VmDispatcher::new(self.vm.clone(), self.tool_timeout));
        let context = ContextConfig {
            window: self.context_window as u64,
            ..ContextConfig::default()
        };
        let sampling = role_sampling(&self.sampling, reviewer)?;
        let driver = Driver::new(
            self.backend.clone(),
            dispatcher,
            tools,
            reviewer.system_prompt(),
        )
        .with_guard(GuardConfig {
            rules: self.guard_rules.clone(),
            autonomy: crate::run::guard_autonomy(self.autonomy),
            loop_detection: true,
        })
        .with_completion_gate(CompletionConfig::default())
        .with_context(context)
        .with_sampling(sampling)
        .with_review(self.auto_review)
        .with_ledger(ledger);

        let outcome = driver
            .run(&mut job, cancel.clone())
            .await
            .map_err(|error| format!("auditor run: {error}"))?;
        let run = run_summary(&job, outcome);
        Ok(parse_review(&run.summary))
    }

    async fn propose_inner(
        &self,
        charter: String,
        reason: String,
        cancel: CancellationToken,
    ) -> Result<serde_json::Value, String> {
        let vetoed = vetoed_names(&self.governance_path)?;
        let (checked, library) = {
            let roles = self.roles.read().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut known = BTreeSet::new();
            known.insert(self.model.clone());
            for name in roles.names() {
                if let Some(role) = roles.get(&name) {
                    if let Some(model) = &role.model {
                        known.insert(model.clone());
                    }
                    for alternate in &role.alternates {
                        known.insert(alternate.clone());
                    }
                }
            }
            let known: Vec<String> = known.into_iter().collect();
            let allow_lead = self.depth.saturating_add(1) < MAX_DEPTH;
            match check_proposal(&charter, &roles, &vetoed, allow_lead, &known) {
                Ok(checked) => (checked, roles.clone()),
                Err(violations) => {
                    let violations: Vec<String> =
                        violations.into_iter().map(|violation| violation.0).collect();
                    return Ok(json!({ "installed": false, "violations": violations }));
                }
            }
        };
        let name = checked.name.clone();

        // Announce the proposal before the audit so the observer sees both the
        // proposal and its outcome even if the auditor fails.
        self.decision("proposed", &name, &reason)?;
        self.announce(&format!(
            "{} proposed role {}: {}",
            self.head, name, reason
        ));

        let Some(reviewer) = reviewer_role(&library).cloned() else {
            return Err("no reviewer role is defined; cannot audit the proposal".into());
        };
        let task = audit_task(&self.head, &reason, &charter, &library);
        let verdict = match self.audit(&task, &reviewer, &cancel).await {
            Ok(Some(review)) => review,
            Ok(None) => Review {
                accept: false,
                feedback: "auditor gave no verdict".to_string(),
            },
            Err(error) => Review {
                accept: false,
                feedback: format!("auditor failed: {error}"),
            },
        };
        if cancel.is_cancelled() {
            return Err("CANCELLED: the proposal was cancelled".into());
        }
        if !verdict.accept {
            let feedback = if verdict.feedback.trim().is_empty() {
                "auditor rejected the proposal".to_string()
            } else {
                verdict.feedback.clone()
            };
            self.decision("rejected", &name, &feedback)?;
            self.announce(&format!("rejected role {}: {}", name, feedback));
            return Ok(json!({ "installed": false, "auditor": feedback }));
        }

        let source = as_trial(&charter)?;
        let installed = parse_charter(&source)?;
        let path = self.roles_dir.join(format!("{name}.md"));
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "refusing to overwrite existing role file {}",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!("create {}: {error}", path.display()));
            }
        };
        if let Err(error) = file.write_all(source.as_bytes()) {
            let _ = std::fs::remove_file(&path);
            return Err(format!("write {}: {error}", path.display()));
        }
        drop(file);

        {
            let mut roles = self.roles.write().unwrap_or_else(std::sync::PoisonError::into_inner);
            if roles.get(&name).is_some() {
                let _ = std::fs::remove_file(&path);
                return Err(format!("role `{name}` appeared while the proposal was audited"));
            }
            roles.insert(installed);
        }

        self.decision("installed", &name, "installed on trial")?;
        self.announce(&format!(
            "installed trial role {}; veto with `bulge org veto {}`",
            name, name
        ));
        Ok(json!({
            "installed": true,
            "role": name,
            "trial": true,
            "budget_share": TRIAL_BUDGET_SHARE,
        }))
    }
}

impl ProposeRoleHandler for Governance {
    fn propose<'a>(
        &'a self,
        charter: String,
        reason: String,
        cancel: CancellationToken,
    ) -> LocalBoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(self.propose_inner(charter, reason, cancel))
    }
}

/// The head's live organization status, rendered without a model call.
pub struct OrgStatus {
    pub org: Arc<Mutex<OrgState>>,
    pub ledger: Arc<bulge_core::ledger::Ledger>,
    /// Restrict the report to one lead's descendants (the head uses `None`).
    pub scope: Option<String>,
}

impl OrgStatusHandler for OrgStatus {
    fn status(&self) -> String {
        let org = self.org.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (slots_used, slots_max) = self.ledger.slots();
        let ledger = LedgerView {
            spent: self.ledger.spent(),
            limit: self.ledger.token_limit(),
            slots_used,
            slots_max,
        };
        bulge_org::bus::situation_report_scoped(&org.board, &ledger, 20, self.scope.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = now_ms();
        let path = std::env::temp_dir().join(format!(
            "bulge-cli-delegate-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn post_test_ticket(org: &mut OrgState, id: &str) {
        let at_ms = now_ms();
        org.log
            .append(
                &mut org.board,
                BoardEvent::Posted {
                    ticket: Ticket {
                        id: id.to_string(),
                        parent: None,
                        role: "implementer".to_string(),
                        goal: format!("goal for {id}"),
                        acceptance: vec!["tests pass".to_string()],
                        budget_tokens: 1_000,
                        owner: None,
                        status: TicketStatus::Posted,
                        rejections: 0,
                        notes: Vec::new(),
                        created_ms: at_ms,
                        updated_ms: at_ms,
                    },
                    at_ms,
                },
            )
            .expect("post ticket");
    }

    #[test]
    fn default_role_is_implementer_and_named_roles_resolve() {
        let roles = RoleLibrary::builtin();
        assert_eq!(resolve_role(&roles, None, 0).expect("default role").name, DEFAULT_ROLE);
        assert_eq!(resolve_role(&roles, Some("explorer"), 0).expect("explorer").name, "explorer");
    }

    #[test]
    fn unknown_role_lists_all_roles() {
        let roles = RoleLibrary::builtin();
        let error = resolve_role(&roles, Some("nope"), 0).expect_err("unknown role");
        assert!(error.starts_with("UNKNOWN_ROLE: nope; available: "), "{error}");
        assert!(error.contains("explorer"), "{error}");
        assert!(error.contains("implementer"), "{error}");
        assert!(error.contains("lead"), "{error}");
        assert!(error.contains("reviewer"), "{error}");
    }

    #[test]
    fn lead_depth_gate_allows_shallow_teams_and_refuses_the_deepest() {
        let roles = RoleLibrary::builtin();
        assert_eq!(
            resolve_role(&roles, Some("lead"), 0).expect("lead at depth 1").kind,
            RoleKind::Lead
        );
        assert_eq!(
            resolve_role(&roles, Some("lead"), 1).expect("lead at depth 2").kind,
            RoleKind::Lead
        );
        assert_eq!(
            resolve_role(&roles, Some("lead"), 2).expect_err("lead at depth 3"),
            "ROLE_NOT_ALLOWED: lead is a lead role and the team is already 3 levels deep (max 3)"
        );
        assert_eq!(
            resolve_role(&roles, Some("implementer"), 2)
                .expect("worker at depth 3")
                .kind,
            RoleKind::Worker
        );
        assert!(
            resolve_role(&roles, Some("implementer"), 3).is_err(),
            "a worker cannot be delegated past the depth limit"
        );
    }

    #[test]
    fn task_message_includes_context_and_acceptance() {
        assert_eq!(child_task_message("do it", None, &[]), "do it");
        assert_eq!(
            child_task_message("do it", Some("background"), &[]),
            "do it\n\nContext:\nbackground"
        );
        assert_eq!(
            child_task_message("do it", None, &["a".to_string(), "b".to_string()]),
            "do it\n\nAcceptance criteria (your work is checked against these):\n- a\n- b"
        );
        assert_eq!(
            child_task_message("do it", Some("background"), &["a".to_string()]),
            "do it\n\nContext:\nbackground\n\nAcceptance criteria (your work is checked against these):\n- a"
        );
    }

    fn models(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn book_with(entries: &[(&str, &str, Verdict)]) -> PerformanceBook {
        let mut book = PerformanceBook::default();
        for (index, (role, model, verdict)) in entries.iter().enumerate() {
            book.record(role, model, *verdict, 0, index as u64);
        }
        book
    }

    #[test]
    fn next_step_merges_accepts_and_reworks_until_the_limit() {
        let book = PerformanceBook::default();
        let candidates = models(&["alpha", "beta"]);
        let tried = models(&["alpha"]);
        assert_eq!(next_step(true, 0, &book, "implementer", &candidates, &[]), NextStep::Merge);
        assert_eq!(
            next_step(false, 1, &book, "implementer", &candidates, &tried),
            NextStep::Rework
        );
        assert_eq!(
            next_step(false, MAX_REJECTIONS, &book, "implementer", &candidates, &tried),
            NextStep::Rework
        );
    }

    #[test]
    fn next_step_replaces_after_the_limit_with_the_best_untried_model() {
        let book = book_with(&[
            ("implementer", "alpha", Verdict::Accepted),
            ("implementer", "beta", Verdict::Rejected),
        ]);
        let candidates = models(&["alpha", "beta", "gamma"]);
        let tried = models(&["alpha", "gamma"]);
        assert_eq!(
            next_step(false, MAX_REJECTIONS + 1, &book, "implementer", &candidates, &tried),
            NextStep::Replace("beta".into())
        );
        assert_eq!(
            next_step(false, MAX_REJECTIONS + 1, &book, "implementer", &candidates, &candidates),
            NextStep::Fail("rejected 3 times and no alternate model is left".into())
        );
    }

    #[test]
    fn failed_run_replaces_or_fails_without_rework() {
        let book = PerformanceBook::default();
        let candidates = models(&["alpha", "beta"]);
        assert_eq!(
            failure_step(&book, "implementer", &candidates, &models(&["alpha"])),
            NextStep::Replace("beta".into())
        );
        assert_eq!(
            failure_step(&book, "implementer", &candidates, &candidates),
            NextStep::Fail("the worker run did not succeed and no alternate model is left".into())
        );
    }

    #[test]
    fn first_model_prefers_the_request_then_the_book_then_the_default() {
        let book = book_with(&[("implementer", "beta", Verdict::Accepted)]);
        let candidates = models(&["alpha", "beta"]);
        assert_eq!(
            first_model(Some("explicit"), &book, "implementer", &candidates, "session"),
            "explicit"
        );
        assert_eq!(first_model(None, &book, "implementer", &candidates, "session"), "beta");
        assert_eq!(
            first_model(Some("  "), &PerformanceBook::default(), "implementer", &[], "session"),
            "session"
        );
    }

    #[test]
    fn rework_and_replacement_tasks_carry_the_feedback() {
        assert_eq!(
            rework_attempt("Fix it.", 1),
            "A reviewer rejected your work (attempt 2 of 3). Fix it and report again.\n\nReviewer feedback:\nFix it."
        );
        assert_eq!(
            replacement_task("do it", "Fix it."),
            "do it\n\nA previous attempt was rejected. Reviewer feedback:\nFix it."
        );
    }

    #[test]
    fn review_verdict_line_is_in_the_bus_summary_and_capped() {
        assert_eq!(
            report_summary("did it", Some(true), "looks good", None, &[]),
            "did it\n\nReview: accepted — looks good"
        );
        let long = "x".repeat(400);
        let line = review_summary_line(false, &long);
        assert!(line.starts_with("\n\nReview: rejected — "), "{line}");
        assert_eq!(line.chars().count(), "\n\nReview: rejected — ".chars().count() + 300);
        assert!(!report_summary("did it", None, "", Some(NO_REVIEWER), &[]).contains("Review:"));
        let with_conflicts = report_summary("did it", Some(true), "ok", None, &["a.txt: conflict".into()]);
        assert!(with_conflicts.contains("Review: accepted — ok"));
        assert!(with_conflicts.contains("Merge conflicts"));
    }

    #[test]
    fn reviewer_role_prefers_the_role_named_reviewer() {
        let roles = RoleLibrary::builtin();
        assert_eq!(reviewer_role(&roles).expect("reviewer").name, "reviewer");
    }

    #[test]
    fn reopening_continues_ticket_numbering() {
        let dir = temp_dir("reopen");
        {
            let mut org = OrgState::open(&dir.0).expect("open org");
            let first = org.next_id();
            post_test_ticket(&mut org, &first);
            let second = org.next_id();
            post_test_ticket(&mut org, &second);
            assert_eq!(org.next_id(), "t-3");
        }

        let mut reopened = OrgState::open(&dir.0).expect("reopen org");
        assert_eq!(reopened.next_id(), "t-3");
    }

    #[test]
    fn for_sub_team_sets_depth_parent_ticket_head_and_ledger() {
        let ledger = bulge_core::ledger::Ledger::root(1_000, None, 2);
        let identity = sub_team_identity(2, "t-7".into(), "job-9".into(), ledger);
        assert_eq!(identity.depth, 2);
        assert_eq!(identity.ticket, "t-7");
        assert_eq!(identity.head, "job-9");
        assert_eq!(identity.ledger.spawned(), (0, bulge_core::ledger::DEFAULT_TOTAL_AGENTS));
    }

    #[test]
    fn sub_team_tickets_are_posted_under_the_sub_leads_ticket() {
        let dir = temp_dir("subteam-parent");
        let mut org = OrgState::open(&dir.0).expect("open org");
        let lead = post_ticket(
            &mut org,
            None,
            "lead",
            "run the sub-team",
            &["report back".to_string()],
            1_000,
        )
        .expect("post lead ticket");
        let child = post_ticket(
            &mut org,
            Some(lead.clone()),
            "implementer",
            "do the work",
            &["tests pass".to_string()],
            1_000,
        )
        .expect("post child ticket");
        assert_eq!(
            org.board.get(&child).expect("child ticket").parent.as_deref(),
            Some(lead.as_str())
        );
    }

    #[test]
    fn chief_cannot_be_delegated() {
        let roles = RoleLibrary::builtin();
        let err = resolve_role(&roles, Some("chief"), 0).expect_err("chief refused");
        assert!(err.contains("chief") && err.contains("head"), "{err}");
    }

    #[test]
    fn delegate_tool_lists_delegatable_roles_in_its_enum() {
        let roles = RoleLibrary::builtin();
        let tool = delegate_tool(&roles);
        assert_eq!(tool.name, DELEGATE_TOOL);
        assert!(tool.description.contains(&format!("up to {MAX_CONCURRENT_SUBAGENTS} at once")));
        assert!(tool.description.contains("- explorer: investigate and report facts"), "{}", tool.description);
        assert!(tool.description.contains("- implementer: make exactly the change"), "{}", tool.description);
        assert!(tool.description.contains("- reviewer: independently decide whether a deliverable"), "{}", tool.description);
        assert!(tool.description.contains("- lead: deliver one mission"), "{}", tool.description);
        assert!(tool.description.contains("independently reviewed before they are merged"), "{}", tool.description);
        assert_eq!(
            tool.parameters["properties"]["model"]["description"].as_str(),
            Some("Model for this ticket (overrides the role's default and the performance-based choice).")
        );

        let names = tool.parameters["properties"]["role"]["enum"]
            .as_array()
            .expect("role enum")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["explorer", "implementer", "lead", "reviewer"]);
    }

    #[test]
    fn vm_slot_leases_are_unique_exhaust_and_reuse_dropped_indexes() {
        let slots = VmSlots::new(2);
        let first = slots.lease().expect("first slot");
        let second = slots.lease().expect("second slot");
        assert_ne!(first.index(), second.index(), "live leases must be unique");
        assert!(slots.lease().is_none(), "an exhausted pool returns None");

        let reused_index = first.index();
        drop(first);
        let reused = slots.lease().expect("dropping frees the index");
        assert_eq!(reused.index(), reused_index);
        assert!(slots.lease().is_none());

        drop(reused);
        drop(second);
        let _ = slots.lease().expect("all indexes free again");
    }

    #[test]
    fn merge_conflicts_are_summarized_for_the_report_and_the_board() {
        let conflicts = vec![
            "a.txt: main workspace changed since the slot opened".to_string(),
            "b.txt: main workspace changed since the slot opened".to_string(),
        ];
        assert_eq!(merge_conflict_summary(&[]), "");
        assert_eq!(
            merge_conflict_summary(&conflicts),
            "\n\nMerge conflicts (not applied; the main workspace changed since this ticket started): \
             a.txt: main workspace changed since the slot opened, b.txt: main workspace changed since the slot opened"
        );
        assert_eq!(merge_conflict_note(&[]), None);
        assert_eq!(
            merge_conflict_note(&["a.txt".to_string(), "b.txt".to_string()]).as_deref(),
            Some("Merge conflicts: a.txt, b.txt")
        );
    }

    #[test]
    fn truncate_summary_keeps_short_text() {
        let (summary, truncated) = truncate_summary("a short answer", 100);
        assert_eq!(summary, "a short answer");
        assert!(!truncated);
    }

    #[test]
    fn truncate_summary_shortens_long_text_to_roughly_the_cap() {
        let text = "abcdefghij".repeat(1_000);
        let cap = 300;
        let (summary, truncated) = truncate_summary(&text, cap);
        assert!(truncated, "long text must be flagged as truncated");
        let marker = "chars omitted; full text in the sub-agent's job log";
        assert!(summary.contains(marker), "the shortened text points at the job log");
        assert!(summary.starts_with(&text[..cap * 2 / 3]));
        assert!(summary.ends_with(&text[text.len() - cap / 3..]));
        // The kept text is about the cap (plus the short marker line).
        assert!(summary.chars().count() > cap * 2 / 3);
        assert!(summary.chars().count() < cap + marker.chars().count() + 20);
    }

    #[test]
    fn truncate_summary_is_utf8_safe_for_cjk_and_emoji() {
        let text = "你好🙂".repeat(500);
        let (summary, truncated) = truncate_summary(&text, 60);
        assert!(truncated);
        // No panic and no broken code point: every char is a valid `char`.
        assert!(summary.chars().count() > 0);
        assert!(summary.starts_with("你好🙂"));
        assert!(summary.ends_with("你好🙂"));
    }
}
