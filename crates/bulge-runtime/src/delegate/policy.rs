//! Delegation policy without I/O on the VM: the org state and tickets, role
//! resolution, the next step after a review, the texts sent to children, and
//! the `delegate` tool schema.

use bulge_util::now_ms;
use std::path::Path;
use bulge_core::driver::Sampling;
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_llm::{ReasoningEffort, ToolSchema};
use bulge_org::{Board, BoardEvent, BoardLog, Bus, Delivery, MAX_REJECTIONS, MessageKind, OrgMessage, PerformanceBook, RoleCharter, RoleKind, RoleLibrary, Ticket, TicketStatus, rework_message};
use serde_json::json;
use super::{MAX_CONCURRENT_SUBAGENTS, MAX_DEPTH};

/// The role a delegation runs as when the head does not name one.
pub(crate) const DEFAULT_ROLE: &str = "implementer";

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
pub(crate) fn post_ticket(
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

/// Resolve a requested role, defaulting to [`DEFAULT_ROLE`], for a child of an
/// agent at `depth`. A lead may only be delegated when its own depth
/// (`depth + 1`) is below [`MAX_DEPTH`]; workers and reviewers may be delegated
/// while their depth is at most [`MAX_DEPTH`].
pub(crate) fn resolve_role<'a>(
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
pub(crate) fn child_task_message(goal: &str, context: Option<&str>, acceptance: &[String]) -> String {
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
pub(crate) fn merge_conflict_summary(conflicts: &[String]) -> String {
    if conflicts.is_empty() {
        return String::new();
    }
    format!(
        "\n\nMerge conflicts (not applied; the main workspace changed since this ticket started): {}",
        conflicts.join(", ")
    )
}

/// The board note prefixed to a submitted ticket's summary when a merge conflicted.
pub(crate) fn merge_conflict_note(paths: &[String]) -> Option<String> {
    (!paths.is_empty()).then(|| format!("Merge conflicts: {}", paths.join(", ")))
}

/// Send a report through the org bus. Returns the summary to put in the delegate
/// report and whether the bus quarantined it.
pub(crate) fn send_bus_report(org: &mut OrgState, ticket: &str, child: &str, head: &str, summary: &str) -> (String, bool) {
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
pub(crate) enum NextStep {
    Merge,
    Rework,
    Replace(String),
    Fail(String),
}

/// The decision after one review verdict.
pub(crate) fn next_step(
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
pub(crate) fn failure_step(book: &PerformanceBook, role: &str, candidates: &[String], tried: &[String]) -> NextStep {
    match book.choose(role, candidates, tried) {
        Some(model) => NextStep::Replace(model),
        None => NextStep::Fail("the worker run did not succeed and no alternate model is left".into()),
    }
}

/// The worker's first model: the head's explicit choice, else the book's choice,
/// else the session default.
pub(crate) fn first_model(requested: Option<&str>, book: &PerformanceBook, role: &str, candidates: &[String], default: &str) -> String {
    if let Some(model) = requested.map(str::trim).filter(|model| !model.is_empty()) {
        return model.to_string();
    }
    book.choose(role, candidates, &[]).unwrap_or_else(|| default.to_string())
}

/// The rework message for the same worker after `rejections` rejections.
pub(crate) fn rework_attempt(feedback: &str, rejections: u32) -> String {
    rework_message(feedback, rejections + 1, MAX_REJECTIONS + 1)
}

/// A replacement worker's task: the original task plus the last feedback.
pub(crate) fn replacement_task(task: &str, feedback: &str) -> String {
    format!("{task}\n\nA previous attempt was rejected. Reviewer feedback:\n{feedback}")
}

/// The verdict line appended to the bus/report summary.
pub(crate) fn review_summary_line(accepted: bool, feedback: &str) -> String {
    let verdict = if accepted { "accepted" } else { "rejected" };
    let feedback: String = feedback.chars().take(300).collect();
    format!("\n\nReview: {verdict} — {feedback}")
}

/// Assemble the bus/report summary: worker summary, an optional note, the verdict
/// line when there is one, then any merge conflicts.
pub(crate) fn report_summary(worker_summary: &str, accepted: Option<bool>, feedback: &str, note: Option<&str>, conflicts: &[String]) -> String {
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
pub(crate) fn reviewer_role(roles: &RoleLibrary) -> Option<&RoleCharter> {
    let reviewers = roles.by_kind(RoleKind::Reviewer);
    reviewers
        .iter()
        .copied()
        .find(|role| role.name == "reviewer")
        .or_else(|| reviewers.first().copied())
}

/// The role's sampling settings, including its reasoning effort override.
pub(crate) fn role_sampling(base: &Sampling, role: &RoleCharter) -> Result<Sampling, String> {
    let mut sampling = base.clone();
    if let Some(effort) = &role.reasoning_effort {
        sampling.reasoning_effort = Some(ReasoningEffort::parse(effort).ok_or_else(|| format!("unknown reasoning_effort `{effort}` for role `{}`", role.name))?);
    }
    Ok(sampling)
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
