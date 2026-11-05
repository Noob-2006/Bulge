//! The board kernel: every lifecycle transition (Hermes `kanban_db`). All functions
//! work on a locked `BoardData` (call them inside `store::with_board`), so each one
//! is atomic. Refusals that must leave an audit trail return `Ok(Err(..))`-style
//! values instead of failing the whole write.

use super::notify;
use super::store::{Attachment, BoardData, Link, Run, Task};
use super::workflow::{BLOCK_RECURRENCE_LIMIT, VALID_BLOCK_KINDS, VALID_WORKSPACE_KINDS};
use super::{attachments_dir, now, workspaces_root, ATTACHMENT_MAX_BYTES};
use crate::util::random_hex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const REVIEW_APPROVED_NOTE: &str = "Review approved without additional evidence.";

pub fn new_task_id() -> String {
    format!("t_{}", random_hex(12))
}

/// First non-blank line, capped.
pub fn first_line(s: Option<&str>, limit: usize) -> String {
    s.and_then(|s| s.trim().lines().next()).map(|l| l.chars().take(limit).collect()).unwrap_or_default()
}

/// Strip secrets from durable text: vault values plus common token shapes.
pub fn redact(s: &str) -> String {
    let mut out = match super::kernel() {
        Some(k) => k.vault.redact(s),
        None => s.to_string(),
    };
    static PATS: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    let pats = PATS.get_or_init(|| {
        [r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"github_pat_[A-Za-z0-9_]{30,}", r"xox[abprs]-[A-Za-z0-9\-]{10,}", r"AKIA[0-9A-Z]{16}", r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"]
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect()
    });
    for p in pats {
        out = p.replace_all(&out, "[REDACTED]").into_owned();
    }
    out
}
pub fn redact_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact(s)),
        Value::Array(a) => Value::Array(a.iter().map(redact_value).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), redact_value(v))).collect()),
        o => o.clone(),
    }
}

// ───────────────────────── runs ─────────────────────────

/// Close the active run and clear `current_run_id`; None when nothing was active.
pub fn end_run(b: &mut BoardData, task: &str, outcome: &str, status: Option<&str>, summary: Option<&str>, error: Option<&str>, metadata: Option<Value>) -> Option<u64> {
    let rid = b.task(task)?.current_run_id?;
    let n = now();
    if let Some(r) = b.run_mut(rid).filter(|r| r.ended_at.is_none()) {
        r.status = status.unwrap_or(outcome).into();
        r.outcome = Some(outcome.into());
        r.summary = summary.map(String::from);
        r.error = error.map(String::from);
        r.metadata = metadata.filter(|m| !m.is_null() && m != &json!({}));
        r.ended_at = Some(n);
        r.claim_expires = None;
    }
    if let Some(t) = b.task_mut(task) {
        t.current_run_id = None;
    }
    Some(rid)
}

/// Zero-duration closed run so a handoff on a never-claimed task is not lost.
pub fn synthesize_run(b: &mut BoardData, task: &str, outcome: &str, summary: Option<&str>, error: Option<&str>, metadata: Option<Value>, profile: Option<Option<String>>) -> u64 {
    let n = now();
    let profile = profile.unwrap_or_else(|| b.task(task).and_then(|t| t.assignee.clone()));
    let id = b.new_run_id();
    b.runs.push(Run { id, task_id: task.into(), profile, status: outcome.into(), started_at: n, ended_at: Some(n), outcome: Some(outcome.into()), summary: summary.map(String::from), error: error.map(String::from), metadata: metadata.filter(|m| !m.is_null()), source_status: "ready".into(), ..Default::default() });
    id
}

#[allow(clippy::too_many_arguments)]
fn end_or_synth(b: &mut BoardData, task: &str, outcome: &str, status: &str, summary: Option<&str>, metadata: Option<Value>, synthesize: bool, profile: Option<Option<String>>) -> Option<u64> {
    let r = end_run(b, task, outcome, Some(status), summary, None, metadata.clone());
    if r.is_none() && synthesize {
        return Some(synthesize_run(b, task, outcome, summary, None, metadata, profile));
    }
    r
}

/// `review` when the active run was claimed from review, else `ready`.
pub fn retry_status_for_run(b: &BoardData, task: &str, run: Option<u64>) -> String {
    let run = run.or_else(|| b.task(task).and_then(|t| t.current_run_id));
    match run.and_then(|r| b.run(r)) {
        Some(r) if r.source_status == "review" => "review".into(),
        _ => "ready".into(),
    }
}

fn resume_status_from_events(b: &BoardData, task: &str) -> String {
    const KINDS: &[&str] = &["blocked", "block_loop_detected", "dependency_wait", "gave_up", "unblocked", "changes_requested", "review_reopened", "status", "reclaimed", "stale", "timed_out", "crashed", "spawn_failed", "rate_limited"];
    let ev = b.events.iter().rev().find(|e| e.task_id == task && KINDS.contains(&e.kind.as_str()));
    let p = ev.and_then(|e| e.payload.clone()).unwrap_or(Value::Null);
    if ["resume_status", "retry_status", "source_status"].iter().any(|k| p[*k] == "review") {
        "review".into()
    } else {
        "ready".into()
    }
}

/// The newest blocked/unblocked event says the block waits for an operator (explicit
/// `kanban_block`), or a breaker trip stamped `sticky` since the last unblock.
fn has_sticky_block(b: &BoardData, task: &str) -> bool {
    if b.events.iter().rev().find(|e| e.task_id == task && (e.kind == "blocked" || e.kind == "unblocked")).is_some_and(|e| e.kind == "blocked") {
        return true;
    }
    let last_unblock = b.events.iter().rev().find(|e| e.task_id == task && e.kind == "unblocked").map(|e| e.id).unwrap_or(0);
    b.events.iter().rev().find(|e| e.task_id == task && e.kind == "gave_up" && e.id > last_unblock).is_some_and(|e| e.payload.as_ref().is_some_and(|p| p["sticky"] == true))
}

pub fn parents_satisfied(b: &BoardData, task: &str) -> bool {
    unsatisfied_parents(b, task).is_empty()
}

/// `(parent, status)` for every direct parent that is not done/archived.
pub fn unsatisfied_parents(b: &BoardData, task: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = b.links.iter().filter(|l| l.child == task).filter_map(|l| b.task(&l.parent).map(|p| (p.id.clone(), p.status.clone()))).filter(|(_, s)| s != "done" && s != "archived").collect();
    v.sort();
    v
}

fn landing_after_parents(b: &BoardData, task: &str) -> &'static str {
    if parents_satisfied(b, task) {
        "ready"
    } else {
        "todo"
    }
}

/// Promote todo/blocked tasks whose parents are all done/archived; returns the count.
/// Sticky blocks and tasks at the breaker limit stay put.
pub fn recompute_ready(b: &mut BoardData, failure_limit: u32) -> u32 {
    let ids: Vec<String> = b.tasks.iter().filter(|t| t.status == "todo" || t.status == "blocked").map(|t| t.id.clone()).collect();
    let mut promoted = 0;
    for id in ids {
        let t = b.task(&id).unwrap();
        if t.status == "blocked" && has_sticky_block(b, &id) {
            continue;
        }
        if !parents_satisfied(b, &id) {
            continue;
        }
        if t.scheduled_at.is_some_and(|s| s > now() * 1000) {
            continue; // Workboard schedule hold (epoch ms)
        }
        let blocked = t.status == "blocked";
        let limit = t.max_retries.unwrap_or(failure_limit);
        if blocked && t.consecutive_failures >= limit {
            continue;
        }
        let resume = resume_status_from_events(b, &id);
        b.task_mut(&id).unwrap().status = resume.clone();
        b.append_event(&id, "promoted", (resume != "ready").then(|| json!({"status": resume})), None);
        promoted += 1;
    }
    promoted
}

// ───────────────────────── create / link ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct NewTask {
    pub title: String,
    pub body: Option<String>,
    pub assignee: Option<String>,
    pub created_by: Option<String>,
    pub workspace_kind: Option<String>,
    pub workspace_path: Option<String>,
    pub branch_name: Option<String>,
    pub tenant: Option<String>,
    pub priority: i64,
    pub parents: Vec<String>,
    pub triage: bool,
    pub idempotency_key: Option<String>,
    pub max_runtime_seconds: Option<i64>,
    pub skills: Option<Vec<String>>,
    pub max_retries: Option<u32>,
    pub model_override: Option<String>,
    pub provider_override: Option<String>,
    pub goal_mode: bool,
    pub goal_max_turns: Option<u32>,
    /// `running` (normal dispatch path) or `blocked` (parked for human ops).
    pub initial_status: Option<String>,
    /// Explicit status (Workboard `status` param); overrides the computed one when valid.
    pub status: Option<String>,
    pub session_id: Option<String>,
    pub creator_task_id: Option<String>,
    pub completion_contract: Option<String>,
    pub labels: Vec<String>,
    pub scheduled_at: Option<i64>,
    pub created_by_card: Option<String>,
    pub session_key: Option<String>,
    pub default_workdir: Option<String>,
}

pub fn canonical_assignee(a: Option<&str>) -> Option<String> {
    a.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty() && s != "none")
}

/// Create a task (optionally under `parents`); returns its id (or the existing id for
/// a live `idempotency_key`).
pub fn create_task(b: &mut BoardData, n: NewTask) -> Result<String, String> {
    if n.title.trim().is_empty() {
        return Err("title is required".into());
    }
    let contract = super::pr::validate_contract(n.completion_contract.as_deref())?;
    if n.provider_override.is_some() && n.model_override.is_none() {
        return Err("'provider' requires 'model' to be set as well".into());
    }
    let initial = n.initial_status.clone().unwrap_or_else(|| "running".into());
    if initial != "running" && initial != "blocked" {
        return Err("initial_status must be one of ['blocked', 'running']".into());
    }
    let kind = n.workspace_kind.clone().unwrap_or_else(|| "scratch".into());
    if !VALID_WORKSPACE_KINDS.contains(&kind.as_str()) {
        return Err(format!("workspace_kind must be one of {VALID_WORKSPACE_KINDS:?}, got {kind:?}"));
    }
    let branch = n.branch_name.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    if branch.is_some() && kind != "worktree" {
        return Err("branch_name is only valid for worktree workspaces".into());
    }
    if let Some(k) = n.idempotency_key.as_deref().filter(|k| !k.is_empty()) {
        if let Some(t) = b.tasks.iter().rev().find(|t| t.idempotency_key.as_deref() == Some(k) && t.status != "archived") {
            return Ok(t.id.clone());
        }
    }
    let parents: Vec<String> = n.parents.iter().filter(|p| !p.is_empty()).cloned().collect();
    let missing: Vec<&String> = parents.iter().filter(|p| b.task(p).is_none()).collect();
    if !missing.is_empty() {
        return Err(format!("unknown parent task(s): {}", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    let tenant = n.tenant.clone().or_else(|| parents.iter().find_map(|p| b.task(p).and_then(|t| t.tenant.clone())));
    let mut status = if initial == "blocked" {
        "blocked".to_string()
    } else if n.triage {
        "triage".into()
    } else if parents.iter().any(|p| b.status_of(p) != Some("done")) {
        "todo".into()
    } else {
        "ready".into()
    };
    if let Some(s) = n.status.as_deref().filter(|s| super::workflow::is_status(s) && *s != "running" && *s != "archived") {
        // An explicit status never lets a child skip an open parent.
        status = if s == "ready" && status == "todo" { "todo".into() } else { s.to_string() };
    }
    let mut workspace_path = n.workspace_path.clone();
    if workspace_path.is_none() && (kind == "dir" || kind == "worktree") {
        workspace_path = n.default_workdir.clone();
    }
    let ts = now();
    let mut id = new_task_id();
    while b.task(&id).is_some() {
        id = new_task_id();
    }
    let skills = n.skills.map(|v| {
        let mut seen = Vec::new();
        for s in v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            if !seen.contains(&s) {
                seen.push(s);
            }
        }
        seen
    });
    let session_id = n.session_id.clone().or_else(|| n.creator_task_id.as_deref().and_then(|c| b.task(c)).and_then(|t| t.session_id.clone()));
    b.tasks.push(Task {
        id: id.clone(),
        title: n.title.trim().into(),
        body: n.body.clone(),
        assignee: canonical_assignee(n.assignee.as_deref()),
        status: status.clone(),
        priority: n.priority,
        created_by: n.created_by.clone(),
        created_at: ts,
        updated_at: ts,
        workspace_kind: kind.clone(),
        workspace_path: workspace_path.clone(),
        branch_name: branch.clone(),
        tenant: tenant.clone(),
        idempotency_key: n.idempotency_key.clone().filter(|k| !k.is_empty()),
        max_runtime_seconds: n.max_runtime_seconds,
        skills: skills.clone(),
        max_retries: n.max_retries,
        model_override: n.model_override.clone().filter(|s| !s.is_empty()),
        provider_override: n.provider_override.clone().filter(|s| !s.is_empty()),
        goal_mode: n.goal_mode,
        goal_max_turns: n.goal_max_turns,
        session_id,
        completion_contract: Some(contract),
        labels: n.labels.clone(),
        scheduled_at: n.scheduled_at,
        created_by_card: n.created_by_card.clone(),
        session_key: n.session_key.clone(),
        ..Default::default()
    });
    for p in &parents {
        b.links.push(Link { parent: p.clone(), child: id.clone() });
    }
    b.append_event(&id, "created", Some(json!({"assignee": canonical_assignee(n.assignee.as_deref()), "status": status, "parents": parents, "creator_task_id": n.creator_task_id, "tenant": tenant, "workspace_kind": kind, "workspace_path": workspace_path, "branch_name": branch, "skills": skills, "goal_mode": n.goal_mode.then_some(true), "model_override": n.model_override, "provider_override": n.provider_override})), None);
    if status == "blocked" {
        b.append_event(&id, "blocked", Some(json!({"reason": "initial_status", "status": "blocked", "actor": n.created_by.clone().unwrap_or_else(|| "user".into())})), None);
    }
    if status == "todo" {
        if let Some(g) = parents.iter().find(|p| !matches!(b.status_of(p), Some("done" | "archived"))) {
            let g = g.clone();
            b.append_event(&id, "dependency_wait", Some(json!({"reason": "parent_not_done", "parent": g})), None);
        }
    }
    // The originating channel hears a child's block too, not just the fan-in.
    let mut sources: Vec<String> = parents.clone();
    sources.extend(n.creator_task_id.clone());
    notify::inherit_subscriptions(b, &id, &sources);
    Ok(id)
}

fn would_cycle(b: &BoardData, parent: &str, child: &str) -> bool {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![child.to_string()];
    while let Some(n) = stack.pop() {
        if n == parent {
            return true;
        }
        if !seen.insert(n.clone()) {
            continue;
        }
        stack.extend(b.links.iter().filter(|l| l.parent == n).map(|l| l.child.clone()));
    }
    false
}

/// `parent -> child`. True when the edge gated a ready child back to todo.
pub fn link(b: &mut BoardData, parent: &str, child: &str, expected_child_run: Option<u64>) -> Result<bool, String> {
    if parent == child {
        return Err("a task cannot depend on itself".into());
    }
    let missing: Vec<&str> = [parent, child].into_iter().filter(|i| b.task(i).is_none()).collect();
    if !missing.is_empty() {
        return Err(format!("unknown task(s): {}", missing.join(", ")));
    }
    let c = b.task(child).unwrap();
    if c.status == "running" && (expected_child_run.is_none() || c.current_run_id != expected_child_run) {
        return Err(format!("cannot link {parent} -> {child}: child is already running"));
    }
    if would_cycle(b, parent, child) {
        return Err(format!("linking {parent} -> {child} would create a cycle"));
    }
    if !b.links.iter().any(|l| l.parent == parent && l.child == child) {
        b.links.push(Link { parent: parent.into(), child: child.into() });
    }
    let mut gated = false;
    if !matches!(b.status_of(parent), Some("done" | "archived")) && b.status_of(child) == Some("ready") {
        b.task_mut(child).unwrap().status = "todo".into();
        gated = true;
        b.append_event(child, "dependency_wait", Some(json!({"reason": "parent_not_done", "demoted": true, "parent": parent})), None);
    }
    b.append_event(child, "linked", Some(json!({"parent": parent, "child": child})), None);
    notify::inherit_subscriptions(b, child, &[parent.to_string()]);
    Ok(gated)
}

pub fn unlink(b: &mut BoardData, parent: &str, child: &str, failure_limit: u32) -> bool {
    let n = b.links.len();
    b.links.retain(|l| !(l.parent == parent && l.child == child));
    let removed = b.links.len() != n;
    if removed {
        b.append_event(child, "unlinked", Some(json!({"parent": parent, "child": child})), None);
        recompute_ready(b, failure_limit);
    }
    removed
}

// ───────────────────────── claim / heartbeat ─────────────────────────

pub struct ClaimOpts<'a> {
    pub lock: &'a str,
    pub ttl: i64,
    /// `ready` or `review`.
    pub lane: &'a str,
    pub owner: Option<&'a str>,
    pub token: Option<&'a str>,
}

/// `lane -> running` CAS: opens a run and emits `claimed`. None when lost or gated.
pub fn claim(b: &mut BoardData, id: &str, o: ClaimOpts) -> Option<u64> {
    let t = b.task(id)?;
    let force = t.force_ready;
    if !force && !parents_satisfied(b, id) {
        let st = t.status.clone();
        if st == o.lane && b.task(id).unwrap().claim_lock.is_none() {
            b.task_mut(id).unwrap().status = "todo".into();
            if o.lane == "review" {
                b.append_event(id, "dependency_wait", Some(json!({"reason": "parent_reopened", "source_status": "review"})), None);
            } else {
                b.append_event(id, "claim_rejected", Some(json!({"reason": "parents_not_done"})), None);
            }
        }
        return None;
    }
    let t = b.task(id)?;
    if t.status != o.lane || t.claim_lock.is_some() {
        return None;
    }
    let ts = now();
    // Close a leaked prior run so the invariant (current_run_id <=> open run) holds.
    if let Some(r) = t.current_run_id {
        if let Some(run) = b.run_mut(r).filter(|r| r.ended_at.is_none()) {
            run.status = "reclaimed".into();
            run.outcome = Some("reclaimed".into());
            run.summary.get_or_insert_with(|| "invariant recovery on re-claim".into());
            run.ended_at = Some(ts);
        }
    }
    let rid = b.new_run_id();
    let expires = ts + o.ttl;
    let t = b.task_mut(id).unwrap();
    t.status = "running".into();
    t.claim_lock = Some(o.lock.into());
    t.claim_expires = Some(expires);
    t.claim_owner = o.owner.map(String::from).or_else(|| t.assignee.clone());
    t.claim_token = o.token.map(String::from);
    t.started_at.get_or_insert(ts);
    t.current_run_id = Some(rid);
    t.force_ready = false;
    let (profile, maxrt) = (t.assignee.clone(), t.max_runtime_seconds);
    b.runs.push(Run { id: rid, task_id: id.into(), profile, status: "running".into(), claim_lock: Some(o.lock.into()), claim_expires: Some(expires), max_runtime_seconds: maxrt, started_at: ts, source_status: o.lane.into(), owner_pid: Some(std::process::id()), owner_birth: super::process_birth(std::process::id()), ..Default::default() });
    let mut p = json!({"lock": o.lock, "expires": expires, "run_id": rid});
    if o.lane == "review" {
        p["source_status"] = "review".into();
    }
    b.append_event(id, "claimed", Some(p), Some(rid));
    Some(rid)
}

/// Extend a running claim held by `lock`.
pub fn heartbeat_claim(b: &mut BoardData, id: &str, lock: Option<&str>, ttl: i64) -> bool {
    let expires = now() + ttl;
    let Some(t) = b.task_mut(id) else { return false };
    if t.status != "running" || (lock.is_some() && t.claim_lock.as_deref() != lock) {
        return false;
    }
    t.claim_expires = Some(expires);
    if let Some(r) = t.current_run_id {
        if let Some(run) = b.run_mut(r) {
            run.claim_expires = Some(expires);
        }
    }
    true
}

/// `heartbeat` event + `last_heartbeat_at`; false when not running (or another run).
pub fn heartbeat_worker(b: &mut BoardData, id: &str, note: Option<&str>, expected_run: Option<u64>) -> bool {
    let ts = now();
    let Some(t) = b.task_mut(id) else { return false };
    if t.status != "running" || (expected_run.is_some() && t.current_run_id != expected_run) {
        return false;
    }
    t.last_heartbeat_at = Some(ts);
    let rid = expected_run.or(t.current_run_id);
    if let Some(r) = rid.and_then(|r| b.run_mut(r)) {
        r.last_heartbeat_at = Some(ts);
    }
    b.append_event(id, "heartbeat", note.map(|n| json!({"note": n})), rid);
    true
}

// ───────────────────────── complete ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// Phantom `created_cards` (audit event already recorded).
    Hallucinated(Vec<String>),
    /// No substantive summary/result.
    Empty,
    /// Running under a live worker claim without ownership proof.
    LiveClaim,
    /// A declared scratch artifact could not be preserved.
    Artifact(String),
    /// Bare refusal (unknown id, stale run, wrong status, open parents, PR gate).
    No,
}

#[derive(Debug, Clone, Default)]
pub struct Completion {
    pub result: Option<String>,
    pub summary: Option<String>,
    pub metadata: Option<Value>,
    pub created_cards: Option<Vec<String>>,
    pub expected_run: Option<u64>,
    pub force: bool,
    /// Whether the active claim protects a live worker (decided by the caller).
    pub claim_live: bool,
    /// PR acceptance receipt collected outside the lock: (snapshot, receipt).
    pub acceptance: Option<(super::pr::Snapshot, Value)>,
    /// Workboard: completion proof / artifacts recorded with the transition.
    pub proof: Option<super::store::Proof>,
    pub proof_id: Option<String>,
    pub artifacts: Vec<super::store::Artifact>,
}

/// `(verified, phantom)`: verified = exists and was created by the completing task's
/// assignee (or the task itself), or is linked as its child.
pub fn verify_created_cards(b: &BoardData, task: &str, ids: &[String]) -> (Vec<String>, Vec<String>) {
    let mut ordered: Vec<String> = Vec::new();
    for i in ids.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !ordered.iter().any(|o| o == i) {
            ordered.push(i.to_string());
        }
    }
    let Some(t) = b.task(task) else { return (vec![], ordered) };
    let assignee = t.assignee.clone();
    let children = b.child_ids(task);
    let (mut ok, mut bad) = (vec![], vec![]);
    for c in ordered {
        let trusted = b.task(&c).is_some_and(|ct| (assignee.is_some() && ct.created_by == assignee) || ct.created_by.as_deref() == Some(task) || children.contains(&c));
        if trusted { ok.push(c) } else { bad.push(c) }
    }
    (ok, bad)
}

fn phantom_prose_refs(b: &BoardData, text: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\bt_[a-f0-9]{8,}\b").unwrap());
    let mut v: Vec<String> = Vec::new();
    for m in re.find_iter(text) {
        let s = m.as_str().to_string();
        if b.task(&s).is_none() && !v.contains(&s) {
            v.push(s);
        }
    }
    v
}

/// Copy declared artifacts inside the task's scratch workspace into its durable
/// attachments; returns the metadata with the staged paths. A missing scratch artifact
/// is an error (the task stays in flight).
fn stage_artifacts(b: &mut BoardData, data: &Path, slug: &str, task: &str, metadata: &mut Value, uploaded_by: &str) -> Result<(), String> {
    let Some(list) = metadata.get("artifacts").and_then(|a| a.as_array()).cloned() else { return Ok(()) };
    let t = b.task(task).ok_or("task not found")?;
    let scratch = (t.workspace_kind == "scratch").then(|| t.workspace_path.clone()).flatten().map(PathBuf::from);
    let mut staged = Vec::new();
    let mut copies: Vec<(PathBuf, String, u64)> = Vec::new();
    for a in list.iter().filter_map(|v| v.as_str()) {
        let p = ark_core::tool::expand_home(a);
        let in_scratch = scratch.as_ref().is_some_and(|s| p.starts_with(s));
        if !in_scratch {
            staged.push(a.to_string());
            continue;
        }
        let meta = std::fs::metadata(&p).map_err(|e| format!("declared artifact {a} is missing: {e}"))?;
        if !meta.is_file() {
            return Err(format!("declared artifact {a} is not a regular file"));
        }
        if meta.len() > ATTACHMENT_MAX_BYTES {
            return Err(format!("declared artifact {a} exceeds {} MB limit", ATTACHMENT_MAX_BYTES / (1024 * 1024)));
        }
        let dir = attachments_dir(data, slug, task);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let name = safe_attachment_name(&p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default())?;
        let dest = collision_free(&dir, &name);
        if let Err(e) = std::fs::copy(&p, &dest) {
            for (c, _, _) in &copies {
                let _ = std::fs::remove_file(c);
            }
            return Err(format!("copying {a}: {e}"));
        }
        staged.push(dest.display().to_string());
        copies.push((dest, name, meta.len()));
    }
    for (dest, name, size) in copies {
        b.next_attachment += 1;
        let id = b.next_attachment;
        let fname = dest.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or(name);
        b.attachments.push(Attachment { id, task_id: task.into(), filename: fname.clone(), stored_path: dest.display().to_string(), content_type: guess_mime(&fname).map(String::from), size, uploaded_by: Some(uploaded_by.into()), created_at: now(), note: None });
        b.append_event(task, "attached", Some(json!({"filename": fname, "size": size, "by": uploaded_by})), None);
    }
    metadata["artifacts"] = json!(staged);
    Ok(())
}

/// `running|ready|blocked|review -> done` with a structured handoff.
pub fn complete(b: &mut BoardData, data: &Path, slug: &str, id: &str, mut c: Completion, failure_limit: u32) -> Result<u64, Refusal> {
    let Some(t) = b.task(id) else { return Err(Refusal::No) };
    if !parents_satisfied(b, id) {
        return Err(Refusal::No);
    }
    let prior = t.status.clone();
    let verified = match &c.created_cards {
        Some(cards) if !cards.is_empty() => {
            let (ok, bad) = verify_created_cards(b, id, cards);
            if !bad.is_empty() {
                let prev = first_line(c.summary.as_deref().or(c.result.as_deref()), 200);
                b.append_event(id, "completion_blocked_hallucination", Some(json!({"phantom_cards": bad, "verified_cards": ok, "summary_preview": (!prev.is_empty()).then_some(prev)})), None);
                return Err(Refusal::Hallucinated(bad));
            }
            ok
        }
        _ => vec![],
    };
    let substantive = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.trim().is_empty());
    if prior != "review" && !substantive(&c.result) && !substantive(&c.summary) && !substantive(&t.result) {
        let rp = first_line(c.result.as_deref(), 200);
        let sp = first_line(c.summary.as_deref(), 200);
        b.append_event(id, "completion_blocked_empty_result", Some(json!({"result_preview": (!rp.is_empty()).then_some(rp), "summary_preview": (!sp.is_empty()).then_some(sp)})), None);
        return Err(Refusal::Empty);
    }
    if !matches!(prior.as_str(), "running" | "ready" | "blocked" | "review") {
        return Err(Refusal::No);
    }
    if c.expected_run.is_some() && t.current_run_id != c.expected_run {
        return Err(Refusal::No);
    }
    if c.expected_run.is_none() && !c.force && prior == "running" && t.claim_lock.is_some() && c.claim_live {
        return Err(Refusal::LiveClaim);
    }
    // PR tasks: the receipt was collected outside the lock; it only counts for the same snapshot.
    let contract = t.completion_contract.clone().unwrap_or_else(|| "local-only".into());
    if contract != "local-only" {
        let Some((snap, receipt)) = c.acceptance.take() else { return Err(Refusal::No) };
        if !super::pr::record_acceptance(b, id, &snap, &receipt) {
            return Err(Refusal::No);
        }
    }
    // Fold prose-mentioned artifacts? Only declared ones are staged.
    if let Some(m) = c.metadata.as_mut() {
        stage_artifacts(b, data, slug, id, m, "kanban_complete").map_err(Refusal::Artifact)?;
    }
    let handoff = c.summary.clone().or_else(|| c.result.clone());
    let ts = now();
    {
        let t = b.task_mut(id).unwrap();
        t.status = "done".into();
        t.result = c.result.clone().or(t.result.take());
        t.completed_at = Some(ts);
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        t.block_kind = None;
        t.block_recurrences = 0;
        t.consecutive_failures = 0;
        t.last_failure_error = None;
    }
    let mut rid = end_run(b, id, "completed", Some("done"), handoff.as_deref(), None, c.metadata.clone());
    if rid.is_none() && (c.summary.is_some() || c.metadata.is_some() || c.result.is_some() || prior == "review") {
        let (mut s, mut m) = (handoff.clone(), c.metadata.clone());
        if prior == "review" && s.is_none() && m.is_none() {
            s = Some(REVIEW_APPROVED_NOTE.into());
            m = Some(json!({"source_status": "review", "approval": "manual"}));
        }
        rid = Some(synthesize_run(b, id, "completed", s.as_deref(), None, m, None));
    }
    let event_summary = handoff.clone().or_else(|| (prior == "review").then(|| REVIEW_APPROVED_NOTE.to_string()));
    let mut payload = json!({"result_len": c.result.as_ref().map(|r| r.len()).unwrap_or(0), "summary": event_summary.as_deref().map(|s| first_line(Some(s), 400))});
    if !verified.is_empty() {
        payload["created_cards"] = json!(verified);
    }
    let artifacts: Vec<String> = c.metadata.as_ref().and_then(|m| m["artifacts"].as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    if !artifacts.is_empty() {
        payload["artifacts"] = json!(artifacts);
    }
    b.append_event(id, "completed", Some(payload), rid);
    let phantom = phantom_prose_refs(b, &format!("{} {}", c.summary.as_deref().unwrap_or(""), c.result.as_deref().unwrap_or("")));
    let phantom: Vec<String> = phantom.into_iter().filter(|p| !verified.contains(p)).collect();
    if !phantom.is_empty() {
        b.append_event(id, "suspected_hallucinated_references", Some(json!({"phantom_refs": phantom})), rid);
    }
    if let Some(p) = c.proof.take() {
        super::workboard::append_completion_proof(b, id, p, c.proof_id.as_deref());
    }
    for a in c.artifacts.drain(..) {
        b.artifacts.push(a);
    }
    let msg = event_summary.as_deref().map(|s| first_line(Some(s), 240)).unwrap_or_else(|| "Task completed.".into());
    notify::push(b, id, "completed", &msg, rid, artifacts);
    recompute_ready(b, failure_limit);
    cleanup_workspace(b, data, slug, id);
    Ok(rid.unwrap_or(0))
}

/// Remove a managed scratch workspace (only ever under the board's workspaces root).
pub fn cleanup_workspace(b: &BoardData, data: &Path, slug: &str, id: &str) {
    let Some(t) = b.task(id) else { return };
    if t.workspace_kind != "scratch" {
        return;
    }
    let Some(p) = t.workspace_path.as_deref().map(PathBuf::from) else { return };
    let root = workspaces_root(data, slug);
    if p.starts_with(&root) && p != root {
        let _ = std::fs::remove_dir_all(&p);
    }
}

// ───────────────────────── block / schedule / review ─────────────────────────

/// `running|ready -> blocked` (or todo for `dependency`, triage on a block loop).
pub fn block(b: &mut BoardData, id: &str, reason: Option<&str>, kind: Option<&str>, expected_run: Option<u64>) -> Result<bool, String> {
    if let Some(k) = kind {
        if !VALID_BLOCK_KINDS.contains(&k) {
            return Err(format!("block kind must be one of {VALID_BLOCK_KINDS:?} or None"));
        }
    }
    let Some(t) = b.task(id) else { return Ok(false) };
    if t.status == "blocked" {
        // Classify an untyped breaker block in place; never re-type or flap status.
        if kind.is_none() || expected_run.is_some() || t.block_kind.is_some() || t.current_run_id.is_some() {
            return Ok(false);
        }
        let t = b.task_mut(id).unwrap();
        t.block_kind = kind.map(String::from);
        t.block_recurrences = 1;
        b.append_event(id, "blocked", Some(json!({"kind": kind, "reason": reason, "classified_in_place": true})), None);
        return Ok(true);
    }
    if !matches!(t.status.as_str(), "running" | "ready") || (expected_run.is_some() && t.current_run_id != expected_run) {
        return Ok(false);
    }
    let source = if t.status == "running" { retry_status_for_run(b, id, None) } else { "ready".into() };
    let mut kind = kind.map(String::from);
    let requested = kind.clone();
    let mut rekind = None;
    if kind.as_deref() == Some("dependency") && parents_satisfied(b, id) {
        kind = Some("needs_input".into());
        rekind = Some("no_open_parent");
    }
    let (prev_kind, prev_rec) = (t.block_kind.clone(), t.block_recurrences);
    let (new_status, event_kind, recurrences, mut payload) = if kind.as_deref() == Some("dependency") {
        ("todo", "dependency_wait", prev_rec, json!({"reason": reason, "kind": kind, "source_status": source}))
    } else {
        let rec = if prev_kind == kind { prev_rec + 1 } else { 1 };
        let mut p = json!({"reason": reason, "kind": kind, "recurrences": rec, "source_status": source});
        if rec >= BLOCK_RECURRENCE_LIMIT {
            p["limit"] = BLOCK_RECURRENCE_LIMIT.into();
            ("triage", "block_loop_detected", rec, p)
        } else {
            ("blocked", "blocked", rec, p)
        }
    };
    if let Some(r) = rekind {
        payload["requested_kind"] = json!(requested);
        payload["rekind_reason"] = r.into();
    }
    {
        let t = b.task_mut(id).unwrap();
        t.status = new_status.into();
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        t.block_kind = kind.clone();
        t.block_recurrences = recurrences;
    }
    let rid = end_or_synth(b, id, "blocked", "blocked", reason, None, reason.is_some(), None);
    b.append_event(id, event_kind, Some(payload), rid);
    if new_status != "todo" {
        notify::push(b, id, "blocked", &reason.map(|r| first_line(Some(r), 240)).unwrap_or_else(|| "Task blocked.".into()), rid, vec![]);
    }
    Ok(true)
}

/// Park in `scheduled` (waiting on time, not dispatchable) until unblocked.
pub fn schedule(b: &mut BoardData, id: &str, reason: Option<&str>, expected_run: Option<u64>) -> bool {
    let Some(t) = b.task_mut(id) else { return false };
    if !matches!(t.status.as_str(), "todo" | "ready" | "running" | "blocked") || (expected_run.is_some() && t.current_run_id != expected_run) {
        return false;
    }
    t.status = "scheduled".into();
    t.claim_lock = None;
    t.claim_expires = None;
    t.claim_owner = None;
    t.claim_token = None;
    let rid = end_or_synth(b, id, "scheduled", "scheduled", reason, None, reason.is_some(), None);
    b.append_event(id, "scheduled", Some(json!({"reason": reason})), rid);
    true
}

#[derive(Debug, Clone, Default)]
pub struct ReviewRequest {
    pub summary: Option<String>,
    pub metadata: Option<Value>,
    pub reviewer: Option<String>,
    pub expected_run: Option<u64>,
    pub force: bool,
    pub claim_live: bool,
}

/// Reviewer recorded on the latest `changes_requested` run: Ok(None) = first review,
/// Err = such a run exists but its provenance is missing.
fn prior_reviewer(b: &BoardData, id: &str) -> Result<Option<String>, ()> {
    let Some(run) = b.runs.iter().rev().find(|r| r.task_id == id && r.outcome.as_deref() == Some("changes_requested")) else { return Ok(None) };
    let ev = b.latest_event(id, "changes_requested", Some(run.id));
    match ev.and_then(|e| e.payload.as_ref()).and_then(|p| p["reviewer"].as_str()).filter(|s| !s.trim().is_empty()) {
        Some(r) => Ok(Some(r.to_string())),
        None => Err(()),
    }
}

/// `running|ready -> review`; never touches block-loop accounting.
pub fn request_review(b: &mut BoardData, data: &Path, slug: &str, id: &str, r: ReviewRequest) -> Result<(), String> {
    let summary = r.summary.as_deref().map(redact);
    let mut metadata = r.metadata.as_ref().map(redact_value);
    if !parents_satisfied(b, id) {
        return Err("parent dependencies are not satisfied".into());
    }
    let Some(t) = b.task(id) else { return Err("task not found".into()) };
    if r.expected_run.is_none() && !r.force && t.status == "running" && t.claim_lock.is_some() && r.claim_live {
        return Err("task is running under a live claim; pass expected_run_id (worker ownership) or force=True (explicit operator override) instead of clearing the live run's claim".into());
    }
    let reviewer = match r.reviewer.clone() {
        Some(x) => Some(x),
        None => prior_reviewer(b, id).map_err(|_| "re-review has no durable reviewer provenance (the latest changes_requested event is missing or malformed); pass reviewer= explicitly".to_string())?,
    };
    let reviewer = canonical_assignee(reviewer.as_deref());
    if !matches!(t.status.as_str(), "running" | "ready") || (r.expected_run.is_some() && t.current_run_id != r.expected_run) {
        return Err("task is not in running/ready (or expected_run_id did not match the current run)".into());
    }
    let mut implementer = t.current_run_id.and_then(|rid| b.run(rid)).and_then(|run| run.profile.clone());
    if implementer.is_none() && t.assignee != reviewer {
        implementer = t.assignee.clone();
    }
    if let Some(m) = metadata.as_mut() {
        stage_artifacts(b, data, slug, id, m, "kanban_request_review")?;
    }
    {
        let t = b.task_mut(id).unwrap();
        t.status = "review".into();
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        if reviewer.is_some() {
            t.assignee = reviewer.clone();
        }
    }
    let rid = end_or_synth(b, id, "review_requested", "review", summary.as_deref(), metadata.clone(), summary.is_some() || metadata.is_some(), Some(implementer.clone()));
    let mut payload = json!({"summary": summary.as_deref().map(|s| first_line(Some(s), 400)).filter(|s| !s.is_empty()), "implementer": implementer, "reviewer": reviewer});
    let artifacts: Vec<String> = metadata.as_ref().and_then(|m| m["artifacts"].as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    if !artifacts.is_empty() {
        payload["artifacts"] = json!(artifacts);
    }
    b.append_event(id, "review_requested", Some(payload), rid);
    notify::push(b, id, "review", &summary.as_deref().map(|s| first_line(Some(s), 240)).unwrap_or_else(|| "Review requested.".into()), rid, artifacts);
    Ok(())
}

/// Reviewer verdict: close the review run and hand the task back to its implementer.
pub fn request_changes(b: &mut BoardData, id: &str, reason: &str, expected_run: Option<u64>) -> Result<String, String> {
    let reason = redact(reason).trim().to_string();
    if reason.is_empty() {
        return Err("reason is required".into());
    }
    let Some(t) = b.task(id) else { return Err("task not found".into()) };
    let Some(cur) = t.current_run_id.filter(|_| t.status == "running") else { return Err("task is not in an active review run".into()) };
    if expected_run.is_some_and(|e| e != cur) {
        return Err("run_id mismatch".into());
    }
    if b.run(cur).map(|r| r.source_status.as_str()) != Some("review") {
        return Err("active run was not claimed from review".into());
    }
    let Some(req) = b.latest_event(id, "review_requested", None) else { return Err("no prior review_requested event".into()) };
    let Some(implementer) = req.payload.as_ref().and_then(|p| p["implementer"].as_str()).filter(|s| !s.trim().is_empty()).map(String::from) else {
        return Err("review handoff has no valid implementer provenance".into());
    };
    let reviewer = canonical_assignee(t.assignee.as_deref());
    let new_status = landing_after_parents(b, id);
    {
        let t = b.task_mut(id).unwrap();
        t.status = new_status.into();
        t.assignee = Some(implementer.clone());
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
    }
    let rid = end_run(b, id, "changes_requested", Some(new_status), Some(&reason), None, None);
    b.append_event(id, "changes_requested", Some(json!({"reason": reason, "implementer": implementer, "reviewer": reviewer, "status": new_status})), rid);
    Ok(implementer)
}

/// `blocked|scheduled ->` its resumable phase (parent re-gated; review where it left off).
pub fn unblock(b: &mut BoardData, id: &str) -> bool {
    let Some(t) = b.task(id) else { return false };
    if !matches!(t.status.as_str(), "blocked" | "scheduled") {
        return false;
    }
    let resume = if t.status == "blocked" { resume_status_from_events(b, id) } else { "ready".into() };
    close_dangling_run(b, id, "invariant recovery on unblock");
    let landing = landing_after_parents(b, id);
    let new_status = if landing == "ready" && resume == "review" { "review" } else { landing };
    let t = b.task_mut(id).unwrap();
    t.status = new_status.into();
    t.current_run_id = None;
    t.consecutive_failures = 0;
    t.last_failure_error = None;
    t.scheduled_at = None;
    let payload = (new_status != "ready" || resume != "ready").then(|| json!({"status": new_status, "resume_status": resume}));
    b.append_event(id, "unblocked", payload, None);
    true
}

fn close_dangling_run(b: &mut BoardData, id: &str, note: &str) {
    let ts = now();
    if let Some(r) = b.task(id).and_then(|t| t.current_run_id) {
        if let Some(run) = b.run_mut(r).filter(|r| r.ended_at.is_none()) {
            run.status = "reclaimed".into();
            run.outcome = Some("reclaimed".into());
            run.summary.get_or_insert_with(|| note.into());
            run.ended_at = Some(ts);
            run.claim_lock = None;
            run.claim_expires = None;
        }
    }
}

/// `review -> ready|todo` so the implementer re-runs; restores the implementer.
pub fn reopen_review(b: &mut BoardData, id: &str) -> bool {
    if b.status_of(id) != Some("review") {
        return false;
    }
    close_dangling_run(b, id, "invariant recovery on review reopen");
    let new_status = landing_after_parents(b, id);
    let implementer = b.latest_event(id, "review_requested", None).and_then(|e| e.payload.as_ref()).and_then(|p| p["implementer"].as_str()).filter(|s| !s.trim().is_empty()).map(String::from);
    let t = b.task_mut(id).unwrap();
    t.status = new_status.into();
    t.current_run_id = None;
    t.claim_lock = None;
    t.claim_expires = None;
    if let Some(i) = &implementer {
        t.assignee = Some(i.clone());
    }
    let mut p = json!({"status": new_status});
    if let Some(i) = implementer {
        p["implementer"] = i.into();
    }
    b.append_event(id, "review_reopened", (p != json!({"status": "ready"})).then_some(p), None);
    true
}

/// Operator promotion `todo|blocked -> ready`, refused while a parent is open.
pub fn promote(b: &mut BoardData, id: &str, actor: &str, reason: Option<&str>, dry_run: bool) -> Result<(), String> {
    let Some(st) = b.status_of(id).map(String::from) else { return Err(format!("task {id} not found")) };
    if st != "todo" && st != "blocked" {
        return Err(format!("task {id} is {st:?}; promote only applies to 'todo' or 'blocked'"));
    }
    let open: Vec<String> = unsatisfied_parents(b, id).into_iter().map(|(p, _)| p).collect();
    if !open.is_empty() {
        return Err(format!("unsatisfied parent dependencies: {} (the ready -> running claim re-checks parents, so promotion cannot bypass them; complete the parents or drop the link with `ark kanban unlink <parent_id> {id}`)", open.join(", ")));
    }
    if dry_run {
        return Ok(());
    }
    b.task_mut(id).unwrap().status = "ready".into();
    b.append_event(id, "promoted_manual", Some(json!({"actor": actor, "reason": reason})), None);
    Ok(())
}

/// Archive; returns the worker session to interrupt when the task was running.
pub fn archive(b: &mut BoardData, data: &Path, slug: &str, id: &str, failure_limit: u32) -> Result<Option<String>, String> {
    let Some(t) = b.task(id) else { return Err(format!("task {id} not found")) };
    if t.status == "archived" {
        return Err(format!("task {id} is already archived"));
    }
    let was_running = t.status == "running";
    let session = t.current_run_id.and_then(|r| b.run(r)).and_then(|r| r.worker_session.clone());
    {
        let t = b.task_mut(id).unwrap();
        t.status = "archived".into();
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        t.archived_at = Some(now());
    }
    let rid = end_run(b, id, "reclaimed", Some("reclaimed"), Some("task archived with run still active"), None, None);
    b.append_event(id, "archived", None, rid);
    recompute_ready(b, failure_limit);
    cleanup_workspace(b, data, slug, id);
    Ok(if was_running { session } else { None })
}

/// Restore an archived task to `status` (Workboard unarchive / restore move).
pub fn unarchive(b: &mut BoardData, id: &str, status: &str) -> bool {
    let Some(t) = b.task_mut(id).filter(|t| t.status == "archived") else { return false };
    t.status = status.into();
    t.archived_at = None;
    b.append_event(id, "unarchived", Some(json!({"status": status})), None);
    true
}

fn delete_relations(b: &mut BoardData, id: &str) {
    b.links.retain(|l| l.parent != id && l.child != id);
    b.comments.retain(|c| c.task_id != id);
    b.events.retain(|e| e.task_id != id);
    b.runs.retain(|r| r.task_id != id);
    b.attachments.retain(|a| a.task_id != id);
    b.proofs.retain(|p| p.task_id != id);
    b.artifacts.retain(|a| a.task_id != id);
    b.worker_logs.retain(|w| w.task_id != id);
    b.subscriptions.retain(|s| s.task_id.as_deref() != Some(id));
}

/// Hard-delete an archived task (two deliberate actions for data loss).
pub fn delete_archived(b: &mut BoardData, data: &Path, slug: &str, id: &str) -> bool {
    if b.status_of(id) != Some("archived") {
        return false;
    }
    delete_relations(b, id);
    b.tasks.retain(|t| t.id != id);
    let _ = std::fs::remove_dir_all(attachments_dir(data, slug, id));
    true
}

/// Assign/reassign; refused while running under a claim.
pub fn assign(b: &mut BoardData, id: &str, profile: Option<&str>) -> Result<bool, String> {
    let profile = canonical_assignee(profile);
    let Some(t) = b.task(id) else { return Ok(false) };
    if t.claim_lock.is_some() && t.status == "running" {
        return Err(format!("cannot reassign {id}: currently running (claimed). Wait for completion or reclaim the stale lock first."));
    }
    let from = t.assignee.clone();
    let t = b.task_mut(id).unwrap();
    if t.assignee != profile {
        t.consecutive_failures = 0;
        t.last_failure_error = None;
    }
    t.assignee = profile.clone();
    b.append_event(id, "assigned", Some(json!({"assignee": profile, "from": from})), None);
    Ok(true)
}

/// Operator reclaim regardless of TTL: release the claim, restore the source phase,
/// reset the failure counter. Returns `Some(worker_session)` (maybe None inside) on success.
pub fn reclaim(b: &mut BoardData, id: &str, reason: Option<&str>) -> Option<Option<String>> {
    let t = b.task(id)?;
    if t.status != "running" && t.claim_lock.is_none() {
        return None;
    }
    if !matches!(t.status.as_str(), "running" | "ready" | "blocked") {
        return None;
    }
    let prev = t.claim_lock.clone();
    let session = t.current_run_id.and_then(|r| b.run(r)).and_then(|r| r.worker_session.clone());
    let retry = retry_status_for_run(b, id, None);
    {
        let t = b.task_mut(id).unwrap();
        t.status = retry.clone();
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        t.consecutive_failures = 0;
        t.last_failure_error = None;
    }
    let err = match reason {
        Some(r) => format!("manual_reclaim: {r}"),
        None => format!("manual_reclaim lock={}", prev.as_deref().unwrap_or("")),
    };
    let rid = end_run(b, id, "reclaimed", Some("reclaimed"), None, Some(&err), None);
    b.append_event(id, "reclaimed", Some(json!({"manual": true, "reason": reason, "prev_lock": prev, "retry_status": retry})), rid);
    Some(session)
}

#[derive(Debug, Clone, Default)]
pub struct Edit {
    pub title: Option<String>,
    pub body: Option<String>,
    pub priority: Option<i64>,
    pub result: Option<String>,
    pub summary: Option<String>,
    pub metadata: Option<Value>,
}

/// Edit fields; `result` backfills a done task's handoff on its latest completed run.
pub fn edit(b: &mut BoardData, id: &str, e: Edit) -> bool {
    let Some(st) = b.status_of(id).map(String::from) else { return false };
    if e.result.is_some() && st != "done" {
        return false;
    }
    if e.title.is_none() && e.body.is_none() && e.priority.is_none() && e.result.is_none() {
        return false;
    }
    let mut fields = vec![];
    {
        let t = b.task_mut(id).unwrap();
        if let Some(v) = &e.title {
            t.title = v.trim().into();
            fields.push("title");
        }
        if let Some(v) = &e.body {
            t.body = Some(v.clone());
            fields.push("body");
        }
        if let Some(v) = e.priority {
            t.priority = v;
        }
        if let Some(v) = &e.result {
            t.result = Some(v.clone());
        }
    }
    if let Some(p) = e.priority {
        b.append_event(id, "reprioritized", Some(json!({"priority": p})), None);
    }
    match e.result {
        None => {
            if !fields.is_empty() {
                b.append_event(id, "edited", Some(json!({"fields": fields})), None);
            }
        }
        Some(result) => {
            let handoff = e.summary.clone().unwrap_or_else(|| result.clone());
            let run = b.runs.iter().filter(|r| r.task_id == id && r.outcome.as_deref() == Some("completed")).max_by_key(|r| (r.ended_at.unwrap_or(r.started_at), r.id)).map(|r| r.id);
            let rid = match run {
                Some(r) => {
                    let run = b.run_mut(r).unwrap();
                    run.summary = Some(handoff.clone());
                    if e.metadata.is_some() {
                        run.metadata = e.metadata.clone();
                    }
                    r
                }
                None => synthesize_run(b, id, "completed", Some(&handoff), None, e.metadata.clone(), None),
            };
            let mut f = vec!["result", "summary"];
            if e.metadata.is_some() {
                f.push("metadata");
            }
            b.append_event(id, "edited", Some(json!({"fields": f, "result_len": result.len(), "summary": first_line(Some(&handoff), 400)})), Some(rid));
        }
    }
    true
}

/// `triage|backlog -> todo` with optional title/body/assignee rewrite.
pub fn specify_triage(b: &mut BoardData, id: &str, title: Option<&str>, body: Option<&str>, assignee: Option<&str>, author: Option<&str>, failure_limit: u32) -> Result<bool, String> {
    if title.is_some_and(|t| t.trim().is_empty()) {
        return Err("title cannot be blank".into());
    }
    let assignee = canonical_assignee(assignee);
    let Some(t) = b.task(id).filter(|t| t.status == "triage" || t.status == "backlog") else { return Ok(false) };
    let mut changed = vec![];
    let (ot, ob, oa) = (t.title.clone(), t.body.clone().unwrap_or_default(), t.assignee.clone());
    let t = b.task_mut(id).unwrap();
    t.status = "todo".into();
    if let Some(x) = title.map(str::trim).filter(|x| *x != ot) {
        t.title = x.into();
        changed.push("title");
    }
    if let Some(x) = body.filter(|x| *x != ob) {
        t.body = Some(x.into());
        changed.push("body");
    }
    if let Some(x) = assignee.filter(|x| Some(x) != oa.as_ref()) {
        t.assignee = Some(x);
        changed.push("assignee");
    }
    if let Some(a) = author.map(str::trim).filter(|a| !a.is_empty() && !changed.is_empty()) {
        b.insert_comment(id, a, &format!("Specified — updated {} and promoted to todo.", changed.join(", ")));
    }
    b.append_event(id, "specified", (!changed.is_empty()).then(|| json!({"changed_fields": changed})), None);
    recompute_ready(b, failure_limit);
    Ok(true)
}

#[derive(Debug, Clone, Default)]
pub struct Child {
    pub title: String,
    pub body: Option<String>,
    pub assignee: Option<String>,
    /// Indices into the same children list.
    pub parents: Vec<usize>,
    pub workspace_kind: Option<String>,
    pub workspace_path: Option<String>,
}

/// Fan a triage task out into children; the root waits on every child (todo) and is
/// reassigned to the orchestrator. None when not in triage or already decomposed.
pub fn decompose_triage(b: &mut BoardData, id: &str, root_assignee: Option<&str>, children: &[Child], author: Option<&str>, auto_promote: bool, failure_limit: u32) -> Result<Option<Vec<String>>, String> {
    if children.is_empty() {
        return Ok(None);
    }
    for (i, c) in children.iter().enumerate() {
        if c.title.trim().is_empty() {
            return Err(format!("child[{i}].title is required"));
        }
        for p in &c.parents {
            if *p >= children.len() {
                return Err(format!("child[{i}].parents[{p}] is not a valid index into children"));
            }
            if *p == i {
                return Err(format!("child[{i}] cannot list itself as a parent"));
            }
        }
    }
    // Kahn: a cycle would deadlock every involved child in todo forever.
    let mut indeg: Vec<usize> = children.iter().map(|c| c.parents.len()).collect();
    let mut queue: Vec<usize> = (0..children.len()).filter(|i| indeg[*i] == 0).collect();
    let mut seen = 0;
    while let Some(n) = queue.pop() {
        seen += 1;
        for (i, c) in children.iter().enumerate() {
            if c.parents.contains(&n) {
                indeg[i] -= 1;
                if indeg[i] == 0 {
                    queue.push(i);
                }
            }
        }
    }
    if seen != children.len() {
        return Err("cyclic dependency detected in decomposed children list".into());
    }
    let Some(root) = b.task(id).filter(|t| t.status == "triage").cloned() else { return Ok(None) };
    if b.events.iter().any(|e| e.task_id == id && e.kind == "decomposed") {
        return Ok(None);
    }
    let ts = now();
    let mut ids = vec![];
    for c in children {
        let mut cid = new_task_id();
        while b.task(&cid).is_some() {
            cid = new_task_id();
        }
        let kind = c.workspace_kind.clone().unwrap_or_else(|| root.workspace_kind.clone());
        let path = if c.workspace_path.is_some() { c.workspace_path.clone() } else if kind == "worktree" { None } else if kind == root.workspace_kind { root.workspace_path.clone() } else { None };
        b.tasks.push(Task { id: cid.clone(), title: c.title.trim().into(), body: c.body.clone(), assignee: canonical_assignee(c.assignee.as_deref()), status: "todo".into(), workspace_kind: kind, workspace_path: path, tenant: root.tenant.clone(), created_at: ts, updated_at: ts, created_by: Some(author.unwrap_or("decomposer").into()), session_id: root.session_id.clone(), completion_contract: Some("local-only".into()), ..Default::default() });
        b.append_event(&cid, "created", Some(json!({"by": author.unwrap_or("decomposer"), "from_decompose_of": id})), None);
        notify::inherit_subscriptions(b, &cid, &[id.to_string()]);
        ids.push(cid);
    }
    for (i, c) in children.iter().enumerate() {
        for p in &c.parents {
            b.links.push(Link { parent: ids[*p].clone(), child: ids[i].clone() });
            b.append_event(&ids[i].clone(), "linked", Some(json!({"parent": ids[*p], "child": ids[i]})), None);
        }
    }
    for c in &ids {
        b.links.push(Link { parent: c.clone(), child: id.into() });
    }
    {
        let t = b.task_mut(id).unwrap();
        t.status = "todo".into();
        if let Some(r) = canonical_assignee(root_assignee) {
            t.assignee = Some(r);
        }
    }
    if let Some(a) = author.map(str::trim).filter(|a| !a.is_empty()) {
        b.insert_comment(id, a, &format!("Decomposed into {}. Root will wake when all children complete.", ids.join(", ")));
    }
    b.append_event(id, "decomposed", Some(json!({"child_ids": ids, "root_assignee": root_assignee})), None);
    if auto_promote {
        recompute_ready(b, failure_limit);
    }
    Ok(Some(ids))
}

/// Done-reopen invalidation: every ready/review/running/done descendant of `id` goes
/// back to todo. Returns `(invalidated ids, worker sessions to interrupt)`.
pub fn invalidate_descendants(b: &mut BoardData, id: &str, author: &str) -> (Vec<Value>, Vec<String>) {
    let mut desc: Vec<String> = vec![];
    let mut stack = b.child_ids(id);
    while let Some(n) = stack.pop() {
        if desc.contains(&n) {
            continue;
        }
        stack.extend(b.child_ids(&n));
        desc.push(n);
    }
    desc.sort();
    let (mut out, mut kill) = (vec![], vec![]);
    for d in desc {
        let Some(t) = b.task(&d) else { continue };
        let prev = t.status.clone();
        if !matches!(prev.as_str(), "ready" | "review" | "running" | "done") {
            continue;
        }
        let mut resume = if prev == "review" { "review".to_string() } else { "ready".into() };
        let mut rid = None;
        if prev == "running" {
            resume = retry_status_for_run(b, &d, None);
            if let Some(s) = t.current_run_id.and_then(|r| b.run(r)).and_then(|r| r.worker_session.clone()) {
                kill.push(s);
            }
            rid = end_run(b, &d, "reclaimed", Some("todo"), Some(&format!("ancestor {id} reopened")), None, None);
        }
        {
            let t = b.task_mut(&d).unwrap();
            t.status = "todo".into();
            t.completed_at = None;
            t.claim_lock = None;
            t.claim_expires = None;
            t.claim_owner = None;
            t.claim_token = None;
            t.current_run_id = None;
            t.consecutive_failures = 0;
        }
        b.append_event(&d, "descendant_invalidated", Some(json!({"ancestor": id, "prior_status": prev, "new_status": "todo", "resume_status": resume})), rid);
        b.append_event(&d, "status", Some(json!({"status": "todo", "reason": "ancestor_reopened", "parent": id, "previous_status": prev, "resume_status": resume})), rid);
        b.insert_comment(&d, author, &format!("Invalidated: ancestor {id} was reopened; retracted from '{prev}' to 'todo' (will resume via '{resume}')."));
        out.push(json!({"id": d, "prior_status": prev, "new_status": "todo", "resume_status": resume}));
    }
    (out, kill)
}

/// Manual move (dashboard drag / PATCH status / `workboard_move`), routed through the
/// verb that owns the transition. Returns sessions to interrupt.
pub fn move_task(b: &mut BoardData, data: &Path, slug: &str, id: &str, dst: &str, actor: &str, failure_limit: u32) -> Result<Vec<String>, String> {
    let Some(src) = b.status_of(id).map(String::from) else { return Err(format!("task {id} not found")) };
    if !super::workflow::can_move(&src, dst)? {
        return Err(format!("cannot move {id} from {src} to {dst}"));
    }
    let mut kill = vec![];
    match (src.as_str(), dst) {
        (_, "archived") => kill.extend(archive(b, data, slug, id, failure_limit)?),
        ("archived", d) => {
            unarchive(b, id, d);
        }
        ("review", "done") | (_, "done") => {
            if src == "running" {
                if let Some(s) = b.task(id).and_then(|t| t.current_run_id).and_then(|r| b.run(r)).and_then(|r| r.worker_session.clone()) {
                    kill.push(s);
                }
            }
            let c = Completion { force: true, summary: (src != "review").then(|| format!("Marked done by {actor}.")), ..Default::default() };
            complete(b, data, slug, id, c, failure_limit).map_err(|e| format!("could not complete {id}: {e:?}"))?;
        }
        ("review", _) => {
            reopen_review(b, id);
        }
        ("done", d) => {
            let (_, k) = invalidate_descendants(b, id, actor);
            kill.extend(k);
            let t = b.task_mut(id).unwrap();
            t.status = d.into();
            t.completed_at = None;
            b.append_event(id, "status", Some(json!({"status": d, "previous_status": "done", "actor": actor})), None);
        }
        (s, "blocked") if s == "ready" || s == "running" => {
            block(b, id, Some(&format!("Blocked by {actor}.")), None, None)?;
        }
        (_, "review") => {
            request_review(b, data, slug, id, ReviewRequest { summary: Some(format!("Moved to review by {actor}.")), force: true, ..Default::default() })?;
        }
        ("blocked" | "scheduled", "ready") => {
            if !unblock(b, id) {
                return Err(format!("could not unblock {id}"));
            }
        }
        ("running", d) => {
            if let Some(s) = reclaim(b, id, Some(&format!("moved to {d} by {actor}"))).flatten() {
                kill.push(s);
            }
            set_status(b, id, d, actor);
        }
        (_, "scheduled") => {
            schedule(b, id, Some(&format!("Scheduled by {actor}.")), None);
        }
        (_, d) => set_status(b, id, d, actor),
    }
    // A move to ready still honours parents: gate it like every other ready writer.
    if b.status_of(id) == Some("ready") && !parents_satisfied(b, id) {
        b.task_mut(id).unwrap().status = "todo".into();
        b.append_event(id, "dependency_wait", Some(json!({"reason": "parent_not_done"})), None);
    }
    Ok(kill)
}

fn set_status(b: &mut BoardData, id: &str, d: &str, actor: &str) {
    let t = b.task_mut(id).unwrap();
    let prev = std::mem::replace(&mut t.status, d.into());
    b.append_event(id, "status", Some(json!({"status": d, "previous_status": prev, "actor": actor})), None);
}

// ───────────────────────── failures (circuit breaker) ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Failure<'a> {
    pub error: &'a str,
    pub outcome: &'a str,
    pub limit: Option<u32>,
    pub force_trip: bool,
    /// Spawn path: task still running with an open run (restore phase, close run).
    pub release_claim: bool,
    pub end_run: bool,
    pub extra: Option<Value>,
    /// Host refused the spawn: nothing ran, so the counter and breaker are untouched.
    pub infrastructure: bool,
}

/// Record a non-success attempt and maybe trip the breaker. True when auto-blocked.
pub fn record_failure(b: &mut BoardData, id: &str, f: Failure, default_limit: u32) -> bool {
    let error: String = f.error.chars().take(500).collect();
    let Some(t) = b.task(id) else { return false };
    let retry = if f.release_claim { retry_status_for_run(b, id, t.current_run_id) } else if t.status == "review" { "review".into() } else { "ready".into() };
    let failures = t.consecutive_failures + if f.infrastructure { 0 } else { 1 };
    let (limit, source) = match t.max_retries {
        Some(m) => (m, "task"),
        None => (f.limit.unwrap_or(default_limit), "dispatcher"),
    };
    if f.infrastructure || !(f.force_trip || failures >= limit) {
        let t = b.task_mut(id).unwrap();
        if f.release_claim && t.status == "running" {
            t.status = retry.clone();
            t.claim_lock = None;
            t.claim_expires = None;
            t.claim_owner = None;
            t.claim_token = None;
        }
        t.consecutive_failures = failures;
        t.last_failure_error = Some(error.clone());
        if f.end_run {
            let mut detail = json!({"failures": failures, "retry_status": retry});
            if f.infrastructure {
                detail["infrastructure"] = true.into();
            }
            let rid = end_run(b, id, f.outcome, None, None, Some(&error), Some(detail.clone()));
            let mut p = json!({"error": error});
            p.as_object_mut().unwrap().extend(detail.as_object().unwrap().clone());
            b.append_event(id, f.outcome, Some(p), rid);
        }
        return false;
    }
    {
        let t = b.task_mut(id).unwrap();
        if matches!(t.status.as_str(), "running" | "ready" | "review") {
            t.status = "blocked".into();
        }
        if f.release_claim {
            t.claim_lock = None;
            t.claim_expires = None;
            t.claim_owner = None;
            t.claim_token = None;
        }
        t.consecutive_failures = failures;
        t.last_failure_error = Some(error.clone());
    }
    let mut payload = json!({"failures": failures, "effective_limit": limit, "limit_source": source, "error": error, "trigger_outcome": f.outcome, "retry_status": retry});
    let mut rid = None;
    if f.end_run {
        rid = end_run(b, id, "gave_up", None, None, Some(&error), Some(json!({"failures": failures, "trigger_outcome": f.outcome, "effective_limit": limit, "limit_source": source, "retry_status": retry})));
    }
    if f.force_trip {
        payload["sticky"] = true.into();
    }
    if let Some(Value::Object(x)) = f.extra {
        payload.as_object_mut().unwrap().extend(x);
    }
    b.append_event(id, "gave_up", Some(payload), rid);
    notify::push(b, id, "failed", &format!("Gave up after {failures} failed attempt(s): {}", first_line(Some(&error), 200)), rid, vec![]);
    true
}

// ───────────────────────── comments & attachments ─────────────────────────

pub fn add_comment(b: &mut BoardData, id: &str, author: &str, body: &str) -> Result<u64, String> {
    if b.task(id).is_none() {
        return Err(format!("task {id} not found"));
    }
    if body.trim().is_empty() {
        return Err("comment body is required".into());
    }
    let cid = b.insert_comment(id, author, body);
    b.append_event(id, "commented", Some(json!({"author": author, "comment_id": cid, "len": body.len()})), None);
    Ok(cid)
}

/// Client filename -> safe leaf: no directories, control chars or leading dots.
pub fn safe_attachment_name(raw: &str) -> Result<String, String> {
    let leaf = raw.replace('\\', "/").rsplit('/').next().unwrap_or("").trim().to_string();
    let clean: String = leaf.chars().filter(|c| !c.is_control()).collect();
    let clean = clean.trim().trim_start_matches('.').trim().to_string();
    if clean.is_empty() {
        return Err("invalid attachment filename".into());
    }
    Ok(clean.chars().take(200).collect())
}

/// `foo.pdf`, `foo (1).pdf`, … first free name.
pub fn collision_free(dir: &Path, name: &str) -> PathBuf {
    let (stem, ext) = match name.split_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (name.to_string(), String::new()),
    };
    let mut cand = name.to_string();
    let mut n = 1;
    while dir.join(&cand).exists() {
        cand = format!("{stem} ({n}){ext}");
        n += 1;
    }
    dir.join(cand)
}

pub fn guess_mime(name: &str) -> Option<&'static str> {
    let ext = name.rsplit('.').next()?.to_lowercase();
    Some(match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "json" => "application/json",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => return None,
    })
}

/// The single attachment write path (tools, dashboard, CLI): size cap, safe name,
/// collision-free blob, metadata row + `attached` event.
#[allow(clippy::too_many_arguments)]
pub fn store_attachment(b: &mut BoardData, data: &Path, slug: &str, id: &str, filename: &str, bytes: &[u8], content_type: Option<&str>, uploaded_by: Option<&str>, note: Option<&str>) -> Result<u64, String> {
    if bytes.len() as u64 > ATTACHMENT_MAX_BYTES {
        return Err(format!("attachment exceeds {} MB limit", ATTACHMENT_MAX_BYTES / (1024 * 1024)));
    }
    if b.task(id).is_none() {
        return Err(format!("task {id} not found"));
    }
    let name = safe_attachment_name(filename)?;
    let dir = attachments_dir(data, slug, id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dest = collision_free(&dir, &name);
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
    b.next_attachment += 1;
    let aid = b.next_attachment;
    let fname = dest.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or(name);
    let ctype = content_type.map(String::from).or_else(|| guess_mime(&fname).map(String::from));
    b.attachments.push(Attachment { id: aid, task_id: id.into(), filename: fname.clone(), stored_path: std::fs::canonicalize(&dest).unwrap_or(dest).display().to_string(), content_type: ctype, size: bytes.len() as u64, uploaded_by: uploaded_by.map(String::from), created_at: now(), note: note.map(String::from) });
    b.append_event(id, "attached", Some(json!({"filename": fname, "size": bytes.len(), "by": uploaded_by})), None);
    Ok(aid)
}

pub fn delete_attachment(b: &mut BoardData, aid: u64) -> Option<Attachment> {
    let i = b.attachments.iter().position(|a| a.id == aid)?;
    let a = b.attachments.remove(i);
    let _ = std::fs::remove_file(&a.stored_path);
    b.append_event(&a.task_id.clone(), "attachment_deleted", Some(json!({"attachment_id": aid, "filename": a.filename})), None);
    Some(a)
}

/// `{status: n}` and `{assignee: {status: n}}` plus the oldest ready age.
pub fn stats(b: &BoardData) -> Value {
    let mut by_status = serde_json::Map::new();
    let mut by_assignee: serde_json::Map<String, Value> = serde_json::Map::new();
    for t in &b.tasks {
        *by_status.entry(t.status.clone()).or_insert(json!(0)) = json!(by_status.get(&t.status).and_then(|v| v.as_u64()).unwrap_or(0) + 1);
        let a = t.assignee.clone().unwrap_or_else(|| "(unassigned)".into());
        let e = by_assignee.entry(a).or_insert(json!({}));
        let n = e[&t.status].as_u64().unwrap_or(0) + 1;
        e[&t.status] = json!(n);
    }
    let oldest_ready = b.tasks.iter().filter(|t| t.status == "ready").map(|t| t.created_at).min().map(|c| now() - c);
    json!({"by_status": by_status, "by_assignee": by_assignee, "total": b.tasks.len(), "oldest_ready_age_seconds": oldest_ready})
}

#[cfg(test)]
mod tests;
