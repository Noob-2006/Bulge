//! OpenClaw Workboard's `workboard_*` tools on the same board engine. A Workboard
//! `boardId` is a board slug; card ids are task ids (resolved across boards).
//! Claimed cards reject mutations from other agents unless the caller holds the
//! claim token returned once by `workboard_claim`; every card returned redacts it.

use super::boards::{self, MetaPatch, Orchestration, WorkspaceSpec};
use super::dispatch;
use super::ops::{self, Completion, NewTask};
use super::store::{self, Artifact, BoardData, Proof, Subscription, Task, WorkerLog};
use super::tools::Caller;
use super::{board_dir, notify, now, tool_error, KanbanConfig, ATTACHMENT_MAX_BYTES, DEFAULT_BOARD};
use crate::util::random_hex;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

pub const PRIORITIES: &[&str] = &["low", "normal", "high", "urgent"];
const MAX_COMMENT: usize = 2000;

pub fn priority_num(p: &str) -> Result<i64, String> {
    match p {
        "low" => Ok(-1),
        "normal" => Ok(0),
        "high" => Ok(1),
        "urgent" => Ok(2),
        _ => Err(format!("priority must be one of: {}.", PRIORITIES.join(", "))),
    }
}
pub fn priority_label(n: i64) -> &'static str {
    match n {
        i64::MIN..=-1 => "low",
        0 => "normal",
        1 => "high",
        _ => "urgent",
    }
}

/// Find a card on any board: `(slug, board)`.
pub fn locate(data: &Path, id: &str) -> Option<(String, BoardData)> {
    for m in boards::list_boards(data, true) {
        if let Ok(b) = store::read_board(data, &m.slug) {
            if b.task(id).is_some() {
                return Some((m.slug, b));
            }
        }
    }
    None
}

/// Unambiguous id prefix (CLI / slash commands).
pub fn resolve_prefix(data: &Path, q: &str) -> Result<(String, String), String> {
    let mut hits = vec![];
    for m in boards::list_boards(data, true) {
        if let Ok(b) = store::read_board(data, &m.slug) {
            for t in b.tasks.iter().filter(|t| t.id == q || t.id.starts_with(q) || t.id.strip_prefix("t_").is_some_and(|r| r.starts_with(q))) {
                if t.id == q {
                    return Ok((m.slug.clone(), t.id.clone()));
                }
                hits.push((m.slug.clone(), t.id.clone()));
            }
        }
    }
    match hits.len() {
        0 => Err(format!("card not found: {q}")),
        1 => Ok(hits.remove(0)),
        n => Err(format!("card id prefix {q} is ambiguous ({n} matches)")),
    }
}

/// The Workboard card contract (claim token redacted).
pub fn card_json(b: &BoardData, slug: &str, t: &Task) -> Value {
    let ms = |s: i64| s * 1000;
    let mut links: Vec<Value> = b.parent_ids(&t.id).into_iter().map(|p| json!({"type": "parent", "targetCardId": p})).collect();
    links.extend(b.child_ids(&t.id).into_iter().map(|c| json!({"type": "child", "targetCardId": c})));
    let claim = t.claim_lock.as_ref().map(|_| json!({"ownerId": t.claim_owner, "token": "[redacted]", "claimedAt": t.started_at.map(ms), "lastHeartbeatAt": t.last_heartbeat_at.or(t.started_at).map(ms), "expiresAt": t.claim_expires.map(ms)}));
    let attempts: Vec<Value> = b.runs_for(&t.id).into_iter().map(|r| json!({"id": r.id.to_string(), "status": r.outcome.clone().unwrap_or_else(|| r.status.clone()), "agentId": r.profile, "sessionKey": r.worker_session, "startedAt": ms(r.started_at), "endedAt": r.ended_at.map(ms), "summary": r.summary, "error": r.error})).collect();
    let auto = b.latest_event(&t.id, "workboard_summary", None).and_then(|e| e.payload.clone()).unwrap_or(json!({}));
    let ws = json!({"kind": t.workspace_kind, "path": t.workspace_path, "branch": t.branch_name});
    json!({
        "id": t.id, "title": t.title, "notes": t.body, "status": t.status, "priority": priority_label(t.priority), "labels": t.labels,
        "agentId": t.assignee, "sessionKey": t.session_key, "runId": t.current_run_id.map(|r| r.to_string()),
        "createdAt": ms(t.created_at), "updatedAt": ms(t.updated_at.max(t.created_at)),
        "metadata": {
            "automation": {"tenant": t.tenant, "boardId": slug, "skills": t.skills, "workspace": ws, "maxRuntimeSeconds": t.max_runtime_seconds, "maxRetries": t.max_retries, "idempotencyKey": t.idempotency_key, "scheduledAt": t.scheduled_at, "createdByCardId": t.created_by_card, "summary": auto["summary"], "createdCardIds": auto["createdCardIds"]},
            "links": links,
            "claim": claim,
            "comments": b.comments_for(&t.id).iter().map(|c| json!({"author": c.author, "body": c.body, "createdAt": ms(c.created_at)})).collect::<Vec<_>>(),
            "proof": b.proofs.iter().filter(|p| p.task_id == t.id).collect::<Vec<_>>(),
            "artifacts": b.artifacts.iter().filter(|a| a.task_id == t.id).collect::<Vec<_>>(),
            "attachments": b.attachments_for(&t.id).into_iter().map(|a| json!({"id": format!("{slug}:{}", a.id), "fileName": a.filename, "mimeType": a.content_type, "size": a.size, "note": a.note})).collect::<Vec<_>>(),
            "workerLogs": b.worker_logs.iter().filter(|w| w.task_id == t.id).collect::<Vec<_>>(),
            "attempts": attempts,
            "diagnostics": super::diagnostics::workboard_card_diagnostics(b, t, now()),
            "failureCount": t.consecutive_failures,
            "archivedAt": t.archived_at.map(ms),
            "templateId": t.template_id,
            "notifications": b.notifications.iter().filter(|n| n.task_id == t.id).map(|n| json!({"id": n.seq.to_string(), "kind": n.kind, "message": n.message, "createdAt": ms(n.created_at)})).collect::<Vec<_>>(),
        }
    })
}

fn summary_json(b: &BoardData, slug: &str, t: &Task) -> Value {
    let claim = t.claim_lock.as_ref().map(|_| json!({"ownerId": t.claim_owner, "claimedAt": t.started_at.map(|s| s * 1000), "lastHeartbeatAt": t.last_heartbeat_at.or(t.started_at).map(|s| s * 1000), "expiresAt": t.claim_expires.map(|s| s * 1000)}));
    json!({"id": t.id, "title": t.title, "status": t.status, "priority": priority_label(t.priority), "agentId": t.assignee, "tenant": t.tenant, "boardId": slug, "parents": b.parent_ids(&t.id), "children": b.child_ids(&t.id), "claim": claim, "diagnostics": super::diagnostics::workboard_card_diagnostics(b, t, now()), "archivedAt": t.archived_at.map(|s| s * 1000), "updatedAt": t.updated_at * 1000})
}

pub struct WorkboardTool {
    pub name: &'static str,
    pub cfg: KanbanConfig,
}

fn p(t: &str, d: &str) -> Value {
    json!({"type": t, "description": d})
}
fn opt_strs(d: &str) -> Value {
    json!({"type": "array", "items": {"type": "string"}, "description": d})
}
fn workspace_field() -> Value {
    json!({"type": "object", "additionalProperties": false, "properties": {"kind": p("string", "scratch, dir, or worktree."), "path": p("string", "Absolute dir/worktree path."), "branch": p("string", "Optional worktree source base ref. Re-dispatch reuses a retained checkout; use a new card for a different base ref.")}, "required": ["kind"]})
}
const CARD_ID: &str = "Workboard card id.";
const TOKEN: &str = "Claim token returned by workboard_claim.";
const SCOPED: &str = "Claim token for claimed cards.";

pub fn schema(name: &str) -> (&'static str, Value, Vec<&'static str>) {
    let id = || p("string", CARD_ID);
    let tok = || p("string", TOKEN);
    let scoped = || p("string", SCOPED);
    let card_id = || json!({"id": id(), "token": tok()});
    let proof_obj = json!({"type": "object", "additionalProperties": false, "properties": {"status": p("string", "passed, failed, skipped, or unknown."), "label": p("string", "Proof label."), "command": p("string", "Command or step run."), "url": p("string", "Proof URL."), "note": p("string", "Proof note.")}});
    let child = json!({"type": "object", "additionalProperties": false, "required": ["title"], "properties": {"title": p("string", "Child title."), "notes": p("string", "Child notes."), "agentId": p("string", "Assigned agent id."), "priority": p("string", "low, normal, high, or urgent."), "labels": opt_strs(""), "boardId": p("string", ""), "tenant": p("string", ""), "skills": opt_strs(""), "workspace": workspace_field(), "maxRuntimeSeconds": p("number", ""), "maxRetries": p("number", ""), "idempotencyKey": p("string", "")}});
    let match_rule = json!({"type": "object", "additionalProperties": false, "properties": {"health": {"type": "array", "items": {"type": "string", "enum": super::sessions_board::HEALTH}}, "run": {"type": "array", "items": {"type": "string", "enum": ["active", "idle", "failed"]}}, "pullRequest": {"type": "array", "items": {"type": "string", "enum": ["none", "open", "draft", "merged", "closed"]}}, "archived": {"type": "boolean"}}});
    let column = json!({"type": "object", "additionalProperties": false, "required": ["id", "label", "description"], "properties": {"id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,47}$", "description": "Stable column id. Keep this id when renaming the label."}, "label": {"type": "string", "minLength": 1, "maxLength": 60}, "color": p("string", "red, blue, green, yellow, purple, orange, pink, or cyan."), "description": {"type": "string", "minLength": 1, "maxLength": 400, "description": "Description shown in the column tooltip."}, "match": {"anyOf": [match_rule.clone(), {"type": "array", "items": match_rule, "minItems": 1}]}, "fallback": p("boolean", "Exactly one column must be the unresolved-session fallback.")}});
    let sb_board = || p("string", "Board id. May be omitted only when exactly one Sessions board exists.");
    match name {
        "workboard_list" => ("List Workboard cards with compact claim and diagnostic state. Use before choosing or routing board work.", json!({"status": p("string", "Optional card status filter."), "agentId": p("string", "Optional agent id filter."), "tenant": p("string", "Optional tenant filter."), "boardId": p("string", "Optional board id filter."), "limit": p("number", "Maximum cards to return. Default 50."), "refreshDiagnostics": p("boolean", "Refresh stored diagnostics before listing."), "includeArchived": p("boolean", "Include archived cards. Default false.")}), vec![]),
        "workboard_create" => ("Create a Workboard card, optionally with parent dependencies, tenant, skills, workspace, and key to prevent duplicate requests. Sessions boards do not hold cards; use workboard_sessions_board_read/update/move for them.", json!({"title": p("string", "Card title."), "notes": p("string", "Card notes or acceptance criteria."), "status": p("string", "Initial status."), "priority": p("string", "low, normal, high, or urgent."), "labels": opt_strs("Card labels."), "agentId": p("string", "Assigned agent id."), "parents": opt_strs("Parent card ids."), "token": p("string", "Claim token for claimed parent cards."), "tenant": p("string", "Soft tenant namespace."), "boardId": p("string", "Soft board namespace."), "createdByCardId": p("string", "Parent card that created this card."), "idempotencyKey": p("string", "Reuse this key when retrying to avoid creating a duplicate card."), "skills": opt_strs("Suggested skills."), "workspace": workspace_field(), "maxRuntimeSeconds": p("number", "Run timeout seconds."), "maxRetries": p("number", "Retry budget."), "scheduledAt": p("number", "Unix epoch milliseconds.")}), vec!["title"]),
        "workboard_link" => ("Link a parent card to a child card so the child becomes ready only after parents are done.", json!({"parentId": p("string", "Parent card id."), "childId": p("string", "Child card id."), "token": p("string", "Claim token for claimed parent or child cards.")}), vec!["parentId", "childId"]),
        "workboard_read" => ("Read one Workboard card and return bounded worker context with notes, attempts, comments, proof, links, and diagnostics.", card_id(), vec!["id"]),
        "workboard_claim" => ("Claim a Workboard card for this agent and move backlog/todo cards into running. Returns a claim token for heartbeats and release.", json!({"id": id(), "ttlSeconds": p("number", "Claim TTL in seconds.")}), vec!["id"]),
        "workboard_heartbeat" => ("Refresh this agent's Workboard claim heartbeat. Use during long-running card work so diagnostics do not mark it stale.", json!({"id": id(), "token": tok(), "note": p("string", "Optional compact progress note.")}), vec!["id"]),
        "workboard_release" => ("Release this agent's Workboard claim after finishing, pausing, or handing off card work.", json!({"id": id(), "token": tok(), "status": p("string", "Optional next card status after release.")}), vec!["id"]),
        "workboard_comment" => ("Append a compact comment to a Workboard card.", json!({"id": id(), "body": p("string", "Comment body."), "token": scoped()}), vec!["id", "body"]),
        "workboard_proof" => ("Attach proof or artifact metadata to a Workboard card after running tests, checks, or producing screenshots/logs. Returns proofId; pass it to workboard_complete when that call reports the terminal status for this proof.", json!({"id": id(), "status": p("string", "passed, failed, skipped, or unknown."), "label": p("string", "Proof label."), "command": p("string", "Command or exact step run."), "url": p("string", "Proof or artifact URL."), "note": p("string", "Short proof note."), "artifactPath": p("string", "Optional local artifact path."), "token": scoped()}), vec!["id"]),
        "workboard_complete" => ("Complete a claimed Workboard card with a structured summary, proof, artifacts, and created-card manifest.", json!({"id": id(), "token": tok(), "summary": p("string", "Completion summary."), "proofId": p("string", "Proof id returned by workboard_proof when resolving that pending proof."), "proof": proof_obj, "artifacts": {"type": "array", "items": {"type": "object", "additionalProperties": false, "properties": {"label": {"type": "string"}, "url": {"type": "string"}, "path": {"type": "string"}, "mimeType": {"type": "string"}}}}, "createdCardIds": opt_strs("Cards created during this run.")}), vec!["id"]),
        "workboard_attachment_add" => ("Store a small Workboard attachment and link it to the card.", json!({"id": id(), "fileName": p("string", "Attachment file name."), "contentBase64": p("string", "Base64 attachment content."), "mimeType": p("string", "Attachment MIME type."), "note": p("string", "Optional attachment note."), "token": scoped()}), vec!["id", "fileName", "contentBase64"]),
        "workboard_attachment_read" => ("Read one Workboard attachment.", json!({"id": p("string", "Attachment id.")}), vec!["id"]),
        "workboard_attachment_delete" => ("Delete one Workboard attachment and its card index entry.", json!({"id": id(), "attachmentId": p("string", "Attachment id."), "token": scoped()}), vec!["id", "attachmentId"]),
        "workboard_block" => ("Block a claimed Workboard card with a durable reason and release the claim.", json!({"id": id(), "token": tok(), "reason": p("string", "Blocker summary.")}), vec!["id"]),
        "workboard_unblock" => ("Move a blocked Workboard card back to todo after adding enough context.", card_id(), vec!["id"]),
        "workboard_move" => ("Move a Workboard card to another status. Claimed cards require matching claim scope.", json!({"id": id(), "status": {"type": "string", "enum": super::workflow::WORKBOARD_STATUSES, "description": "Target Workboard status."}, "token": p("string", SCOPED)}), vec!["id", "status"]),
        "workboard_boards" => ("List Workboard board namespaces with active, archived, and status counts.", json!({}), vec![]),
        "workboard_board_create" => ("Create or update a Workboard board with persisted metadata. Choose kind sessions on creation for columns with rules over session facts; card tools do not apply to Sessions boards. Board kind cannot change after creation.", json!({"id": p("string", "Board id."), "kind": {"type": "string", "enum": ["cards", "sessions"], "description": "Board kind, set only at creation. Default cards."}, "name": p("string", "Display name."), "description": p("string", "Board description."), "icon": p("string", "Short icon or label."), "color": p("string", "Display color token."), "automationJobId": {"type": "string", "minLength": 1, "maxLength": 128, "description": "Owning automation job id."}, "defaultWorkspace": workspace_field(), "orchestration": {"type": "object", "additionalProperties": false, "properties": {"autoDecompose": p("boolean", "Mark ready triage cards for decomposition."), "autoDecomposePerDispatch": p("number", "Maximum orchestration candidates per dispatch."), "defaultAssignee": p("string", "Default assignee."), "orchestratorProfile": p("string", "Orchestrator profile id.")}}}), vec!["id"]),
        "workboard_board_archive" => ("Archive or restore persisted Workboard board metadata.", json!({"id": p("string", "Board id."), "archived": p("boolean", "Archive when true.")}), vec!["id"]),
        "workboard_board_delete" => ("Delete an empty non-default Workboard board metadata record.", json!({"id": p("string", "Board id.")}), vec!["id"]),
        "workboard_stats" => ("Summarize Workboard counts by status and assignee for one board or all boards.", json!({"boardId": p("string", "Optional board id filter.")}), vec![]),
        "workboard_runs" => ("List persisted Workboard run attempts for one card.", card_id(), vec!["id"]),
        "workboard_specify" => ("Turn a rough triage/backlog Workboard card into a specified todo card after reasoning through the requirements.", json!({"id": p("string", CARD_ID), "title": p("string", "Clarified title."), "notes": p("string", "Clarified notes or acceptance criteria."), "agentId": p("string", "Assigned agent id."), "priority": p("string", "low, normal, high, or urgent."), "labels": opt_strs("Card labels."), "boardId": p("string", "Board id."), "tenant": p("string", "Tenant or routing namespace."), "skills": opt_strs("Suggested skills."), "workspace": workspace_field(), "maxRuntimeSeconds": p("number", "Runtime budget."), "maxRetries": p("number", "Retry budget."), "summary": p("string", "Specification summary comment."), "token": p("string", SCOPED)}), vec!["id"]),
        "workboard_decompose" => ("Fan out a Workboard card into linked child cards and optionally complete the parent orchestration card.", json!({"id": p("string", "Parent Workboard card id."), "token": p("string", SCOPED), "summary": p("string", "Decomposition summary."), "completeParent": p("boolean", "Complete the parent after child creation. Default true."), "children": {"type": "array", "items": child}}), vec!["id", "children"]),
        "workboard_notify_subscribe" => ("Persist a Workboard notification subscription.", json!({"boardId": p("string", "Board id. Default default."), "cardId": p("string", "Card id."), "sessionKey": p("string", "Session key."), "runId": p("string", "Run id."), "target": p("string", "Human-readable target."), "eventKinds": opt_strs("completed, failed, stale.")}), vec![]),
        "workboard_notify_list" => ("List persisted Workboard notification subscriptions.", json!({"boardId": p("string", "Board id."), "cardId": p("string", "Card id.")}), vec![]),
        "workboard_notify_events" => ("Read replay-safe Workboard notification events without advancing cursors.", json!({"subscriptionId": p("string", "Subscription id."), "boardId": p("string", "Board id."), "cardId": p("string", "Card id."), "limit": p("number", "Maximum events. Default 50.")}), vec![]),
        "workboard_notify_advance" => ("Read Workboard notification events and advance the subscription cursor.", json!({"subscriptionId": p("string", "Subscription id."), "limit": p("number", "Maximum events. Default 50.")}), vec!["subscriptionId"]),
        "workboard_notify_unsubscribe" => ("Delete a persisted Workboard notification subscription.", json!({"id": p("string", "Subscription id.")}), vec!["id"]),
        "workboard_promote" => ("Promote a todo card into ready, optionally forcing past dependency or schedule holds. Unblock blocked cards first.", json!({"id": id(), "token": scoped(), "force": p("boolean", "Bypass dependency or schedule holds."), "reason": p("string", "Optional operator note.")}), vec!["id"]),
        "workboard_reassign" => ("Change a card assignee and optionally reset failure state during recovery.", json!({"id": id(), "token": scoped(), "agentId": p("string", "New assignee id."), "status": p("string", "Optional next status."), "resetFailures": p("boolean", "Reset failure count."), "reason": p("string", "Optional operator note.")}), vec!["id"]),
        "workboard_reclaim" => ("Release a stale claim and stop running attempts so another agent can pick it up.", json!({"id": id(), "token": scoped(), "status": p("string", "Optional next status."), "reason": p("string", "Optional operator note.")}), vec!["id"]),
        "workboard_dispatch" => ("Advance persisted board state without launching workers: promote unblocked cards, reclaim expired claims, and block timed-out runs.", json!({"boardId": p("string", "Optional board id filter.")}), vec![]),
        "workboard_worker_log" => ("Append a persisted worker log entry to a Workboard card.", json!({"id": id(), "level": p("string", "info, warning, or error."), "message": p("string", "Worker log message."), "sessionKey": p("string", "Linked session key."), "runId": p("string", "Linked run id."), "token": scoped()}), vec!["id", "message"]),
        "workboard_protocol_violation" => ("Block a card and record a worker protocol violation when work stops without complete/block.", json!({"id": id(), "detail": p("string", "Violation detail."), "sessionKey": p("string", "Linked session key."), "runId": p("string", "Linked run id."), "token": scoped()}), vec!["id"]),
        "workboard_sessions_board_read" => ("Read a Sessions board and its session placements. Columns match seagent session run state, health, and pull-request facts in order; operator pins take precedence. Card tools do not apply to Sessions boards.", json!({"boardId": sb_board()}), vec![]),
        "workboard_sessions_board_update" => ("Edit a Sessions board's columns, match rules, or scope. columns replaces the full ordered list; preserve ids when renaming labels. All fields in each rule must match; a match array accepts any rule, and the first matching column wins. Exactly one fallback is required. Card tools do not apply to Sessions boards.", json!({"boardId": sb_board(), "columns": {"type": "array", "items": column, "minItems": 2, "maxItems": 12}, "scope": {"type": "object", "additionalProperties": false, "properties": {"agentIds": opt_strs(""), "includeArchived": {"type": "boolean"}, "includeAutomation": p("boolean", "Include automation (cron) and system sessions. Defaults to false."), "includeHome": p("boolean", "Include home sessions. Defaults to false."), "maxAgeHours": {"type": "number", "exclusiveMinimum": 0}}}}), vec![]),
        "workboard_sessions_board_move" => ("Pin a session in a Sessions board column. The pin overrides match rules while the column exists. Card tools do not apply to Sessions boards.", json!({"boardId": sb_board(), "sessionKey": p("string", "Exact session key from the board read."), "columnId": p("string", "Destination column id from the board read.")}), vec!["sessionKey", "columnId"]),
        _ => ("", json!({}), vec![]),
    }
}

pub const NAMES: &[&str] = &[
    "workboard_list", "workboard_create", "workboard_link", "workboard_read", "workboard_claim", "workboard_heartbeat", "workboard_release", "workboard_comment", "workboard_proof", "workboard_complete",
    "workboard_attachment_add", "workboard_attachment_read", "workboard_attachment_delete", "workboard_block", "workboard_unblock", "workboard_move", "workboard_boards", "workboard_board_create",
    "workboard_board_archive", "workboard_board_delete", "workboard_stats", "workboard_runs", "workboard_specify", "workboard_decompose", "workboard_notify_subscribe", "workboard_notify_list",
    "workboard_notify_events", "workboard_notify_advance", "workboard_notify_unsubscribe", "workboard_promote", "workboard_reassign", "workboard_reclaim", "workboard_dispatch", "workboard_worker_log",
    "workboard_protocol_violation", "workboard_sessions_board_read", "workboard_sessions_board_update", "workboard_sessions_board_move",
];
const READ_ONLY: &[&str] = &["workboard_list", "workboard_read", "workboard_attachment_read", "workboard_boards", "workboard_stats", "workboard_runs", "workboard_notify_list", "workboard_notify_events", "workboard_sessions_board_read"];
/// What OpenClaw grants each dispatched worker for its card (plus read).
const WORKER: &[&str] = &["workboard_read", "workboard_heartbeat", "workboard_complete", "workboard_block"];

pub fn all_tools(cfg: &KanbanConfig) -> Vec<Arc<dyn Tool>> {
    NAMES.iter().map(|n| Arc::new(WorkboardTool { name: n, cfg: cfg.clone() }) as Arc<dyn Tool>).collect()
}
pub fn worker_tools(cfg: &KanbanConfig) -> Vec<Arc<dyn Tool>> {
    WORKER.iter().map(|n| Arc::new(WorkboardTool { name: n, cfg: cfg.clone() }) as Arc<dyn Tool>).collect()
}

impl Tool for WorkboardTool {
    fn spec(&self) -> ToolSpec {
        let (d, props, req) = schema(self.name);
        ToolSpec { name: self.name.into(), description: d.into(), input_schema: json!({"type": "object", "additionalProperties": false, "properties": props, "required": req}), parallel_safe: READ_ONLY.contains(&self.name), idempotent: READ_ONLY.contains(&self.name), pinned: false }
    }
    fn effects(&self, ctx: &ToolCtx, _: &Value) -> Vec<Effect> {
        let path = super::boards_root(&ctx.home);
        if READ_ONLY.contains(&self.name) {
            vec![Effect::Read { path }]
        } else {
            vec![Effect::Write { path }]
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let props = schema(self.name).1;
        if let Some(o) = input.as_object() {
            let mut unknown: Vec<&String> = o.keys().filter(|k| props.get(k.as_str()).is_none()).collect();
            unknown.sort();
            if !unknown.is_empty() {
                return ToolOutput::err(tool_error(format!("{}: unexpected parameter(s): {}", self.name, unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))));
            }
        }
        let c = Caller::of(ctx);
        match self.handle(&c, &input) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(tool_error(e)),
        }
    }
}

fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty())
}
fn need<'a>(a: &'a Value, k: &str) -> Result<&'a str, String> {
    s(a, k).ok_or_else(|| format!("{k} required"))
}
fn strs(a: &Value, k: &str) -> Result<Option<Vec<String>>, String> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(v)) => {
            let out: Vec<String> = v.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            if out.len() > 64 {
                return Err(format!("{k} must have at most 64 entries."));
            }
            Ok(Some(out))
        }
        _ => Err(format!("{k} must be an array of strings.")),
    }
}
fn num(a: &Value, k: &str) -> Option<i64> {
    a.get(k).and_then(|v| v.as_f64()).map(|f| f as i64)
}
fn cap(s: &str, n: usize, what: &str) -> Result<String, String> {
    if s.chars().count() > n {
        return Err(format!("{what} must be at most {n} characters."));
    }
    Ok(s.to_string())
}

impl WorkboardTool {
    fn owner(&self, c: &Caller) -> String {
        c.scope.as_ref().and_then(|s| s.profile.clone()).unwrap_or_else(|| if c.session.is_empty() { "agent".into() } else { c.session.clone() })
    }

    /// Claim scope check: another agent's claim refuses unless the token matches.
    fn scoped(&self, c: &Caller, a: &Value, require_claim: bool) -> Result<(String, String, BoardData), String> {
        let id = need(a, "id")?.to_string();
        let (slug, b) = locate(&c.data, &id).ok_or_else(|| format!("card not found: {id}"))?;
        let t = b.task(&id).unwrap();
        if t.claim_lock.is_some() {
            let owner = self.owner(c);
            let token_ok = s(a, "token").is_some_and(|tk| t.claim_token.as_deref().is_some_and(|ct| seagent_ct_eq(tk, ct)));
            if t.claim_owner.as_deref() != Some(owner.as_str()) && !token_ok {
                return Err(format!("card is claimed by {}.", t.claim_owner.as_deref().unwrap_or("another agent")));
            }
        } else if require_claim {
            return Err("card must be claimed before lifecycle completion.".into());
        }
        Ok((slug, id, b))
    }

    fn card(&self, c: &Caller, slug: &str, id: &str) -> Result<Value, String> {
        let b = store::read_board(&c.data, slug)?;
        let t = b.task(id).ok_or_else(|| format!("card not found: {id}"))?;
        Ok(card_json(&b, slug, t))
    }

    fn board_slug(&self, c: &Caller, a: &Value, key: &str) -> Result<String, String> {
        match s(a, key) {
            Some(b) => Ok(super::normalize_slug(Some(b))?.unwrap_or_else(|| DEFAULT_BOARD.into())),
            None => Ok(super::current_board(&c.data)),
        }
    }

    fn handle(&self, c: &Caller, a: &Value) -> Result<Value, String> {
        let cfg = &self.cfg;
        let data = c.data.as_path();
        let lim = cfg.failure_limit;
        let mutating = !READ_ONLY.contains(&self.name);
        if mutating && c.delegated_child {
            return Err(format!("{} refused: delegated sub-agents are not board run owners.", self.name));
        }
        if let Some(scope) = &c.scope {
            if let Some(id) = s(a, "id").filter(|_| WORKER.contains(&self.name) && self.name != "workboard_read") {
                if id != scope.task {
                    return Err(format!("worker is scoped to card {}; refusing to mutate {id}.", scope.task));
                }
            }
        }
        match self.name {
            "workboard_list" => {
                let limit = num(a, "limit").unwrap_or(50).clamp(1, 200) as usize;
                let inc = a["includeArchived"] == true;
                let mut out = vec![];
                let slugs: Vec<String> = match s(a, "boardId") {
                    Some(bid) => vec![super::normalize_slug(Some(bid))?.unwrap_or_default()],
                    None => boards::list_boards(data, true).into_iter().map(|m| m.slug).collect(),
                };
                for slug in slugs {
                    let b = store::read_board(data, &slug)?;
                    for t in &b.tasks {
                        if (!inc && (t.archived_at.is_some() || t.status == "archived")) || s(a, "status").is_some_and(|x| x != t.status) || s(a, "agentId").is_some_and(|x| t.assignee.as_deref() != Some(x)) || s(a, "tenant").is_some_and(|x| t.tenant.as_deref() != Some(x)) {
                            continue;
                        }
                        out.push(summary_json(&b, &slug, t));
                    }
                }
                out.truncate(limit);
                Ok(json!({"cards": out}))
            }
            "workboard_create" => {
                let slug = self.board_slug(c, a, "boardId")?;
                let meta = boards::read_meta(data, &slug);
                if meta.kind == "sessions" {
                    return Err(format!("board {slug} is a Sessions board; Sessions boards do not hold cards."));
                }
                let parents = strs(a, "parents")?.unwrap_or_default();
                // Claimed parents require the caller's claim scope (token or ownership).
                for pid in &parents {
                    if let Some((_, pb)) = locate(data, pid) {
                        let pt = pb.task(pid).unwrap();
                        if pt.claim_lock.is_some() && pt.claim_owner.as_deref() != Some(self.owner(c).as_str()) && !s(a, "token").is_some_and(|tk| pt.claim_token.as_deref() == Some(tk)) {
                            return Err(format!("card is claimed by {}.", pt.claim_owner.as_deref().unwrap_or("another agent")));
                        }
                    }
                }
                let ws = a.get("workspace").filter(|w| w.is_object()).or(None);
                let dws = meta.default_workspace.clone();
                let n = NewTask {
                    title: cap(need(a, "title")?, 200, "title")?,
                    body: s(a, "notes").map(String::from),
                    status: s(a, "status").map(String::from),
                    priority: s(a, "priority").map(priority_num).transpose()?.unwrap_or(0),
                    labels: strs(a, "labels")?.unwrap_or_default(),
                    assignee: s(a, "agentId").map(String::from),
                    parents,
                    tenant: s(a, "tenant").map(String::from),
                    created_by_card: s(a, "createdByCardId").map(String::from),
                    creator_task_id: s(a, "createdByCardId").map(String::from),
                    idempotency_key: s(a, "idempotencyKey").map(String::from),
                    skills: strs(a, "skills")?,
                    workspace_kind: ws.and_then(|w| w["kind"].as_str()).map(String::from).or(dws.as_ref().map(|d| d.kind.clone()).filter(|k| !k.is_empty())),
                    workspace_path: ws.and_then(|w| w["path"].as_str()).map(String::from).or(dws.as_ref().and_then(|d| d.path.clone())),
                    branch_name: ws.and_then(|w| w["branch"].as_str()).map(String::from),
                    max_runtime_seconds: num(a, "maxRuntimeSeconds"),
                    max_retries: num(a, "maxRetries").map(|x| x.max(0) as u32),
                    scheduled_at: num(a, "scheduledAt"),
                    created_by: Some(self.owner(c)),
                    default_workdir: meta.default_workdir.clone(),
                    session_key: None,
                    ..Default::default()
                };
                if let Some(st) = &n.status {
                    if !super::workflow::WORKBOARD_STATUSES.contains(&st.as_str()) {
                        return Err(format!("status must be one of: {}.", super::workflow::WORKBOARD_STATUSES.join(", ")));
                    }
                }
                let id = store::with_board(data, &slug, |b| ops::create_task(b, n))?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_link" => {
                let (pid, cid) = (need(a, "parentId")?, need(a, "childId")?);
                let (slug, b) = locate(data, cid).ok_or_else(|| format!("card not found: {cid}"))?;
                if b.task(pid).is_none() {
                    return Err(format!("parent and child must be on the same board (card not found on {slug}: {pid})"));
                }
                for x in [pid, cid] {
                    let t = b.task(x).unwrap();
                    if t.claim_lock.is_some() && t.claim_owner.as_deref() != Some(self.owner(c).as_str()) && !s(a, "token").is_some_and(|tk| t.claim_token.as_deref() == Some(tk)) {
                        return Err(format!("card is claimed by {}.", t.claim_owner.as_deref().unwrap_or("another agent")));
                    }
                }
                let run = c.scope.as_ref().filter(|s| s.task == cid).map(|s| s.run);
                store::with_board(data, &slug, |b| ops::link(b, pid, cid, run))?;
                Ok(json!({"card": self.card(c, &slug, cid)?}))
            }
            "workboard_read" => {
                let id = need(a, "id")?;
                let (slug, b) = locate(data, id).ok_or_else(|| format!("card not found: {id}"))?;
                Ok(json!({"card": card_json(&b, &slug, b.task(id).unwrap()), "workerContext": super::context::build_worker_context(&b, id, now())?}))
            }
            "workboard_claim" => {
                let id = need(a, "id")?.to_string();
                let (slug, _) = locate(data, &id).ok_or_else(|| format!("card not found: {id}"))?;
                let owner = self.owner(c);
                let ttl = num(a, "ttlSeconds").filter(|t| *t >= 1).unwrap_or(cfg.claim_ttl_secs);
                let token = random_hex(32);
                let lock = format!("{}wb:{owner}", super::host_prefix());
                store::with_board(data, &slug, |b| {
                    ops::recompute_ready(b, lim);
                    let t = b.task(&id).unwrap().clone();
                    if t.archived_at.is_some() || t.status == "archived" {
                        return Err("card is archived.".into());
                    }
                    if t.claim_lock.is_some() {
                        return Err(format!("card already claimed by {}.", t.claim_owner.as_deref().unwrap_or("another agent")));
                    }
                    match t.status.as_str() {
                        "blocked" => return Err("card is blocked; use workboard_unblock before claiming.".into()),
                        "scheduled" => return Err("card is scheduled for later.".into()),
                        "backlog" | "todo" | "ready" => {}
                        s => return Err(format!("card is {s}; only backlog, todo, or ready cards can be claimed.")),
                    }
                    if t.status != "ready" && !t.force_ready && !ops::parents_satisfied(b, &id) {
                        return Err("card dependencies are not done.".into());
                    }
                    if t.max_retries.is_some_and(|m| t.consecutive_failures >= m) {
                        return Err("card exhausted its retry budget.".into());
                    }
                    b.task_mut(&id).unwrap().status = "ready".into();
                    ops::claim(b, &id, ops::ClaimOpts { lock: &lock, ttl, lane: "ready", owner: Some(&owner), token: Some(&token) }).ok_or("card dependencies are not done.")?;
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?, "token": token}))
            }
            "workboard_heartbeat" => {
                let (slug, id, b) = self.scoped(c, a, false)?;
                if b.task(&id).unwrap().claim_lock.is_none() {
                    return Err("card is not claimed.".into());
                }
                let note = s(a, "note").map(|n| cap(n, 400, "heartbeat note")).transpose()?;
                let author = self.owner(c);
                store::with_board(data, &slug, |b| {
                    ops::heartbeat_claim(b, &id, None, cfg.claim_ttl_secs);
                    ops::heartbeat_worker(b, &id, note.as_deref(), None);
                    if let Some(n) = &note {
                        b.insert_comment(&id, &author, n);
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_release" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let status = s(a, "status").map(String::from);
                if let Some(st) = &status {
                    if !super::workflow::WORKBOARD_STATUSES.contains(&st.as_str()) {
                        return Err(format!("status must be one of: {}.", super::workflow::WORKBOARD_STATUSES.join(", ")));
                    }
                }
                store::with_board(data, &slug, |b| {
                    let t = b.task(&id).unwrap().clone();
                    if t.claim_lock.is_some() {
                        let next = status.clone().unwrap_or_else(|| if t.status == "running" { ops::retry_status_for_run(b, &id, None) } else { t.status.clone() });
                        let tm = b.task_mut(&id).unwrap();
                        tm.claim_lock = None;
                        tm.claim_expires = None;
                        tm.claim_owner = None;
                        tm.claim_token = None;
                        tm.status = next.clone();
                        let rid = ops::end_run(b, &id, "released", None, Some("claim released"), None, None);
                        b.append_event(&id, "released", Some(json!({"status": next})), rid);
                    } else if let Some(st) = &status {
                        ops::move_task(b, data, &slug, &id, st, "workboard", lim)?;
                    }
                    if b.status_of(&id) == Some("ready") && !ops::parents_satisfied(b, &id) {
                        b.task_mut(&id).unwrap().status = "todo".into();
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_comment" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let body = cap(need(a, "body")?, MAX_COMMENT, "comment")?;
                let author = self.owner(c);
                store::with_board(data, &slug, |b| ops::add_comment(b, &id, &author, &ops::redact(&body)))?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_proof" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let pr = proof_from(a, &id)?;
                let pid = pr.id.clone();
                let has_artifact = pr.artifact_path.is_some() || pr.url.is_some();
                store::with_board(data, &slug, |b| {
                    b.proofs.push(pr.clone());
                    if has_artifact {
                        b.artifacts.push(Artifact { task_id: id.clone(), label: pr.label.clone(), url: pr.url.clone(), path: pr.artifact_path.clone(), mime_type: None, created_at: now() });
                        b.append_event(&id, "artifact_added", Some(json!({"proof_id": pr.id})), None);
                    }
                    b.append_event(&id, "proof_added", Some(json!({"proof_id": pr.id, "status": pr.status})), None);
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?, "proofId": pid}))
            }
            "workboard_complete" => {
                let (slug, id, b) = self.scoped(c, a, true)?;
                let created = strs(a, "createdCardIds")?.unwrap_or_default();
                let children = b.child_ids(&id);
                for cc in &created {
                    let Some(ct) = locate(data, cc) else { return Err(format!("created card not found: {cc}")) };
                    if !(children.contains(cc) && ct.1.parent_ids(cc).contains(&id)) {
                        return Err(format!("created card is not linked to this card: {cc}"));
                    }
                }
                let summary = s(a, "summary").map(|x| cap(x, 2000, "summary")).transpose()?;
                if a.get("proofId").is_some() && s(a, "proofId").is_none() {
                    return Err("proofId must be a non-empty string.".into());
                }
                let proof = a.get("proof").filter(|p| p.is_object()).map(|p| proof_from(p, &id)).transpose()?;
                let artifacts: Vec<Artifact> = a.get("artifacts").and_then(|v| v.as_array()).map(|v| v.iter().filter(|x| x["url"].is_string() || x["path"].is_string()).map(|x| Artifact { task_id: id.clone(), label: x["label"].as_str().map(String::from), url: x["url"].as_str().map(String::from), path: x["path"].as_str().map(String::from), mime_type: x["mimeType"].as_str().map(String::from), created_at: now() }).collect()).unwrap_or_default();
                let comp = Completion { summary: Some(summary.clone().unwrap_or_else(|| "Workboard card completed.".into())), force: true, proof, proof_id: s(a, "proofId").map(String::from), artifacts, expected_run: c.scope.as_ref().filter(|s| s.task == id).map(|s| s.run), ..Default::default() };
                super::tools::complete_task(data, &slug, cfg, &id, comp).map_err(|(r, e)| e.unwrap_or_else(|| match r {
                    ops::Refusal::No => {
                        let open = store::read_board(data, &slug).ok().map(|b| ops::unsatisfied_parents(&b, &id)).unwrap_or_default();
                        if open.is_empty() { "card cannot be completed from its current state.".into() } else { "card dependencies are not done.".into() }
                    }
                    other => format!("{other:?}"),
                }))?;
                store::with_board(data, &slug, |b| {
                    b.append_event(&id, "workboard_summary", Some(json!({"summary": summary, "createdCardIds": created})), None);
                    if let Some(sm) = &summary {
                        b.insert_comment(&id, "workboard", sm);
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_attachment_add" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD.decode(need(a, "contentBase64")?).map_err(|e| format!("contentBase64 is not valid base64: {e}"))?;
                if bytes.len() as u64 > ATTACHMENT_MAX_BYTES {
                    return Err(format!("attachment exceeds {} MB limit", ATTACHMENT_MAX_BYTES / (1024 * 1024)));
                }
                let by = self.owner(c);
                store::with_board(data, &slug, |b| ops::store_attachment(b, data, &slug, &id, need(a, "fileName")?, &bytes, s(a, "mimeType"), Some(&by), s(a, "note")))?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_attachment_read" => {
                let aid = need(a, "id")?;
                let (slug, n) = parse_attachment_id(data, aid)?;
                let b = store::read_board(data, &slug)?;
                let at = b.attachments.iter().find(|x| x.id == n).ok_or_else(|| format!("attachment not found: {aid}"))?;
                use base64::Engine;
                let bytes = std::fs::read(&at.stored_path).map_err(|e| format!("attachment blob unreadable: {e}"))?;
                Ok(json!({"id": format!("{slug}:{n}"), "cardId": at.task_id, "fileName": at.filename, "mimeType": at.content_type, "size": at.size, "note": at.note, "contentBase64": base64::engine::general_purpose::STANDARD.encode(bytes)}))
            }
            "workboard_attachment_delete" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let (aslug, n) = parse_attachment_id(data, need(a, "attachmentId")?)?;
                if aslug != slug {
                    return Err("attachment is not on this card.".into());
                }
                store::with_board(data, &slug, |b| {
                    if !b.attachments.iter().any(|x| x.id == n && x.task_id == id) {
                        return Err("attachment is not on this card.".into());
                    }
                    ops::delete_attachment(b, n);
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_block" => {
                let (slug, id, _) = self.scoped(c, a, true)?;
                let reason = s(a, "reason").map(|r| cap(r, 2000, "block reason")).transpose()?.unwrap_or_else(|| "Workboard card blocked.".into());
                let run = c.scope.as_ref().filter(|s| s.task == id).map(|s| s.run);
                let okb = store::with_board(data, &slug, |b| {
                    let r = ops::block(b, &id, Some(&ops::redact(&reason)), None, run)?;
                    if r {
                        b.insert_comment(&id, "workboard", &reason);
                    }
                    Ok(r)
                })?;
                if !okb {
                    return Err("card cannot be blocked from its current state.".into());
                }
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_unblock" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                store::with_board(data, &slug, |b| {
                    if !ops::unblock(b, &id) {
                        return Err("card is not blocked.".into());
                    }
                    if b.status_of(&id) == Some("ready") {
                        b.task_mut(&id).unwrap().status = "todo".into();
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_move" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let st = need(a, "status")?;
                if !super::workflow::WORKBOARD_STATUSES.contains(&st) {
                    return Err(format!("status must be one of: {}.", super::workflow::WORKBOARD_STATUSES.join(", ")));
                }
                let actor = self.owner(c);
                let kill = store::with_board(data, &slug, |b| ops::move_task(b, data, &slug, &id, st, &actor, lim))?;
                interrupt(kill);
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_boards" => {
                let list: Vec<Value> = boards::list_boards(data, true).into_iter().map(|m| {
                    let b = store::read_board(data, &m.slug).unwrap_or_default();
                    let counts = boards::task_counts(data, &m.slug);
                    let archived = b.tasks.iter().filter(|t| t.status == "archived").count();
                    json!({"id": m.slug, "name": m.name, "kind": m.kind, "description": m.description, "icon": m.icon, "color": m.color, "archived": m.archived, "automationJobId": m.automation_job_id, "defaultWorkspace": m.default_workspace, "orchestration": m.orchestration, "counts": counts, "active": b.tasks.len() - archived, "archivedCards": archived})
                }).collect();
                Ok(json!({"boards": list}))
            }
            "workboard_board_create" => {
                let slug = super::normalize_slug(Some(need(a, "id")?))?.ok_or("id required")?;
                let o = &a["orchestration"];
                let ws = a.get("defaultWorkspace").filter(|w| w.is_object()).map(|w| WorkspaceSpec { kind: w["kind"].as_str().unwrap_or("scratch").into(), path: w["path"].as_str().map(String::from), branch: w["branch"].as_str().map(String::from) });
                let patch = MetaPatch { name: s(a, "name").map(String::from), description: s(a, "description").map(String::from), icon: s(a, "icon").map(String::from), color: s(a, "color").map(String::from), kind: s(a, "kind").map(String::from), automation_job_id: s(a, "automationJobId").map(String::from), default_workspace: ws, orchestration: o.is_object().then(|| Orchestration { auto_decompose: o["autoDecompose"].as_bool(), auto_decompose_per_dispatch: o["autoDecomposePerDispatch"].as_u64().map(|x| x as u32), default_assignee: o["defaultAssignee"].as_str().map(String::from), orchestrator_profile: o["orchestratorProfile"].as_str().map(String::from) }), ..Default::default() };
                let m = if boards::board_exists(data, &slug) && slug != DEFAULT_BOARD || slug == DEFAULT_BOARD { boards::write_meta(data, &slug, patch)? } else { boards::create_board(data, &slug, patch)? };
                Ok(json!({"board": m}))
            }
            "workboard_board_archive" => {
                let slug = super::normalize_slug(Some(need(a, "id")?))?.ok_or("id required")?;
                if !boards::board_exists(data, &slug) {
                    return Err(format!("board not found: {slug}"));
                }
                if slug == DEFAULT_BOARD {
                    return Err("the default board cannot be archived.".into());
                }
                Ok(json!({"board": boards::write_meta(data, &slug, MetaPatch { archived: Some(a["archived"] != false), ..Default::default() })?}))
            }
            "workboard_board_delete" => {
                let slug = super::normalize_slug(Some(need(a, "id")?))?.ok_or("id required")?;
                if slug == DEFAULT_BOARD {
                    return Err("the default board cannot be deleted.".into());
                }
                if !store::read_board(data, &slug)?.tasks.is_empty() {
                    return Err("board still contains cards; only empty boards can be deleted.".into());
                }
                boards::remove_board(data, &slug, false)?;
                Ok(json!({"deleted": true, "id": slug}))
            }
            "workboard_stats" => match s(a, "boardId") {
                Some(bid) => {
                    let slug = super::normalize_slug(Some(bid))?.unwrap_or_default();
                    Ok(json!({"boardId": slug, "stats": ops::stats(&store::read_board(data, &slug)?)}))
                }
                None => {
                    let all: Vec<Value> = boards::list_boards(data, true).into_iter().map(|m| json!({"boardId": m.slug, "stats": ops::stats(&store::read_board(data, &m.slug).unwrap_or_default())})).collect();
                    Ok(json!({"boards": all}))
                }
            },
            "workboard_runs" => {
                let id = need(a, "id")?;
                let (slug, b) = locate(data, id).ok_or_else(|| format!("card not found: {id}"))?;
                let card = card_json(&b, &slug, b.task(id).unwrap());
                Ok(json!({"attempts": card["metadata"]["attempts"].clone(), "card": card}))
            }
            "workboard_specify" => {
                let (slug, id, b) = self.scoped(c, a, false)?;
                let st = b.status_of(&id).unwrap_or("").to_string();
                if !matches!(st.as_str(), "triage" | "backlog" | "todo") {
                    return Err("only triage, backlog, or todo cards can be specified.".into());
                }
                let pr = s(a, "priority").map(priority_num).transpose()?;
                let labels = strs(a, "labels")?;
                let skills = strs(a, "skills")?;
                let summary = s(a, "summary").map(|x| cap(x, 2000, "spec summary")).transpose()?;
                let author = self.owner(c);
                store::with_board(data, &slug, |b| {
                    let t = b.task_mut(&id).unwrap();
                    t.status = "todo".into();
                    if let Some(x) = s(a, "title") {
                        t.title = x.into();
                    }
                    if let Some(x) = a.get("notes").and_then(|v| v.as_str()) {
                        t.body = Some(x.into());
                    }
                    if let Some(x) = s(a, "agentId") {
                        t.assignee = ops::canonical_assignee(Some(x));
                    }
                    if let Some(x) = pr {
                        t.priority = x;
                    }
                    if let Some(x) = labels.clone() {
                        t.labels = x;
                    }
                    if let Some(x) = skills.clone() {
                        t.skills = Some(x);
                    }
                    if let Some(x) = s(a, "tenant") {
                        t.tenant = Some(x.into());
                    }
                    if let Some(w) = a.get("workspace").filter(|w| w.is_object()) {
                        t.workspace_kind = w["kind"].as_str().unwrap_or("scratch").into();
                        t.workspace_path = w["path"].as_str().map(String::from);
                        t.branch_name = w["branch"].as_str().map(String::from);
                    }
                    if let Some(x) = num(a, "maxRuntimeSeconds") {
                        t.max_runtime_seconds = Some(x);
                    }
                    if let Some(x) = num(a, "maxRetries") {
                        t.max_retries = Some(x.max(0) as u32);
                    }
                    if let Some(sm) = &summary {
                        b.insert_comment(&id, &author, sm);
                        b.append_event(&id, "workboard_summary", Some(json!({"summary": sm})), None);
                    }
                    b.append_event(&id, "specified", None, None);
                    ops::recompute_ready(b, lim);
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_decompose" => {
                let (slug, id, b) = self.scoped(c, a, false)?;
                let children = a.get("children").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                if children.is_empty() {
                    return Err("children are required.".into());
                }
                if children.len() > 20 {
                    return Err("at most 20 children can be created at once.".into());
                }
                let parent = b.task(&id).unwrap().clone();
                let owner = self.owner(c);
                let mut ids = vec![];
                for (i, ch) in children.iter().enumerate() {
                    if !ch.is_object() {
                        return Err("children must be objects.".into());
                    }
                    let ws = ch.get("workspace").filter(|w| w.is_object());
                    let n = NewTask { title: cap(need(ch, "title")?, 200, "title")?, body: s(ch, "notes").map(String::from), assignee: s(ch, "agentId").map(String::from), priority: s(ch, "priority").map(priority_num).transpose()?.unwrap_or(0), labels: strs(ch, "labels")?.unwrap_or_default(), tenant: s(ch, "tenant").map(String::from).or(parent.tenant.clone()), skills: strs(ch, "skills")?, workspace_kind: ws.and_then(|w| w["kind"].as_str()).map(String::from), workspace_path: ws.and_then(|w| w["path"].as_str()).map(String::from), max_runtime_seconds: num(ch, "maxRuntimeSeconds"), max_retries: num(ch, "maxRetries").map(|x| x.max(0) as u32), idempotency_key: s(ch, "idempotencyKey").map(String::from).or(parent.idempotency_key.as_ref().map(|k| format!("{k}:child:{}", i + 1))), parents: vec![id.clone()], created_by_card: Some(id.clone()), creator_task_id: Some(id.clone()), created_by: Some(owner.clone()), ..Default::default() };
                    ids.push(store::with_board(data, &slug, |b| ops::create_task(b, n))?);
                }
                let summary = s(a, "summary").map(|x| cap(x, 2000, "decompose summary")).transpose()?;
                if a["completeParent"] != false {
                    let comp = Completion { summary: Some(summary.clone().unwrap_or_else(|| format!("Decomposed into {}.", ids.join(", ")))), created_cards: Some(ids.clone()), force: true, expected_run: c.scope.as_ref().filter(|s| s.task == id).map(|s| s.run), ..Default::default() };
                    let st = store::read_board(data, &slug)?.status_of(&id).unwrap_or("").to_string();
                    if matches!(st.as_str(), "triage" | "backlog" | "todo") {
                        store::with_board(data, &slug, |b| {
                            b.task_mut(&id).unwrap().status = "ready".into();
                            Ok(())
                        })?;
                    }
                    super::tools::complete_task(data, &slug, cfg, &id, comp).map_err(|(r, e)| e.unwrap_or_else(|| format!("could not complete the parent: {r:?}")))?;
                } else {
                    store::with_board(data, &slug, |b| {
                        let t = b.task_mut(&id).unwrap();
                        if t.status == "triage" || t.status == "backlog" {
                            t.status = "todo".into();
                        }
                        Ok(())
                    })?;
                }
                store::with_board(data, &slug, |b| {
                    b.append_event(&id, "workboard_summary", Some(json!({"summary": summary, "createdCardIds": ids})), None);
                    b.append_event(&id, "decomposed", Some(json!({"child_ids": ids})), None);
                    Ok(())
                })?;
                let kids: Result<Vec<Value>, String> = ids.iter().map(|k| self.card(c, &slug, k)).collect();
                Ok(json!({"parent": self.card(c, &slug, &id)?, "children": kids?}))
            }
            "workboard_notify_subscribe" => {
                let slug = self.board_slug(c, a, "boardId")?;
                let kinds = strs(a, "eventKinds")?.unwrap_or_default();
                let sub = Subscription { task_id: s(a, "cardId").map(String::from), session_key: s(a, "sessionKey").map(String::from), run_id: s(a, "runId").map(String::from), target: s(a, "target").map(String::from), event_kinds: kinds, delivery_mode: "pull".into(), ..Default::default() };
                let sub = store::with_board(data, &slug, |b| notify::subscribe(b, sub))?;
                Ok(json!({"subscription": sub_json(&slug, &sub)}))
            }
            "workboard_notify_list" => {
                let slugs: Vec<String> = match s(a, "boardId") {
                    Some(x) => vec![super::normalize_slug(Some(x))?.unwrap_or_default()],
                    None => boards::list_boards(data, true).into_iter().map(|m| m.slug).collect(),
                };
                let mut out = vec![];
                for slug in slugs {
                    for sb in store::read_board(data, &slug)?.subscriptions.iter().filter(|x| s(a, "cardId").is_none_or(|cid| x.task_id.as_deref() == Some(cid))) {
                        out.push(sub_json(&slug, sb));
                    }
                }
                Ok(json!({"subscriptions": out}))
            }
            "workboard_notify_events" => {
                let limit = num(a, "limit").unwrap_or(50).clamp(1, 500) as usize;
                if let Some(sid) = s(a, "subscriptionId") {
                    let (slug, b) = find_sub(data, sid)?;
                    let sub = b.subscriptions.iter().find(|x| x.id == sid).unwrap();
                    return Ok(json!({"subscriptionId": sid, "boardId": slug, "cursor": sub.cursor, "events": notify::pending(&b, sub, limit).iter().map(note_json).collect::<Vec<_>>()}));
                }
                let slug = self.board_slug(c, a, "boardId")?;
                let b = store::read_board(data, &slug)?;
                let evs: Vec<Value> = b.notifications.iter().filter(|n| s(a, "cardId").is_none_or(|cid| n.task_id == cid)).rev().take(limit).collect::<Vec<_>>().into_iter().rev().map(note_json).collect();
                Ok(json!({"boardId": slug, "events": evs}))
            }
            "workboard_notify_advance" => {
                let sid = need(a, "subscriptionId")?;
                let limit = num(a, "limit").unwrap_or(50).clamp(1, 500) as usize;
                let (slug, _) = find_sub(data, sid)?;
                let (evs, cursor) = store::with_board(data, &slug, |b| notify::advance(b, sid, limit))?;
                Ok(json!({"subscriptionId": sid, "cursor": cursor, "events": evs.iter().map(note_json).collect::<Vec<_>>()}))
            }
            "workboard_notify_unsubscribe" => {
                let sid = need(a, "id")?;
                let (slug, _) = find_sub(data, sid)?;
                let okd = store::with_board(data, &slug, |b| Ok(notify::unsubscribe(b, sid)))?;
                Ok(json!({"deleted": okd, "id": sid}))
            }
            "workboard_promote" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let force = a["force"] == true;
                let actor = self.owner(c);
                store::with_board(data, &slug, |b| {
                    if b.status_of(&id) != Some("todo") {
                        return Err(format!("only todo cards can be promoted (card is {}); unblock blocked cards first.", b.status_of(&id).unwrap_or("?")));
                    }
                    if force {
                        let t = b.task_mut(&id).unwrap();
                        t.status = "ready".into();
                        t.force_ready = true;
                        t.scheduled_at = None;
                        b.append_event(&id, "promoted_manual", Some(json!({"actor": actor, "reason": s(a, "reason"), "force": true})), None);
                        Ok(())
                    } else {
                        ops::promote(b, &id, &actor, s(a, "reason"), false)
                    }
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_reassign" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let reset = a["resetFailures"] != false;
                let actor = self.owner(c);
                let kill = store::with_board(data, &slug, |b| {
                    let mut kill = vec![];
                    if a.get("agentId").is_some() {
                        let to = s(a, "agentId");
                        if b.status_of(&id) == Some("running") {
                            kill.extend(ops::reclaim(b, &id, Some("reassign")).flatten());
                        }
                        ops::assign(b, &id, to)?;
                    }
                    if reset {
                        let t = b.task_mut(&id).unwrap();
                        t.consecutive_failures = 0;
                        t.last_failure_error = None;
                    }
                    if let Some(st) = s(a, "status").filter(|st| b.status_of(&id) != Some(*st)) {
                        kill.extend(ops::move_task(b, data, &slug, &id, st, &actor, lim)?);
                    }
                    if let Some(r) = s(a, "reason") {
                        b.insert_comment(&id, &actor, r);
                    }
                    Ok(kill)
                })?;
                interrupt(kill);
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_reclaim" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let reason = s(a, "reason").unwrap_or("Workboard claim reclaimed.").to_string();
                let actor = self.owner(c);
                let kill = store::with_board(data, &slug, |b| {
                    let mut kill: Vec<String> = ops::reclaim(b, &id, Some(&reason)).flatten().into_iter().collect();
                    if let Some(st) = s(a, "status").filter(|st| b.status_of(&id) != Some(*st)) {
                        kill.extend(ops::move_task(b, data, &slug, &id, st, &actor, lim)?);
                    }
                    b.insert_comment(&id, &actor, &reason);
                    ops::recompute_ready(b, lim);
                    Ok(kill)
                })?;
                interrupt(kill);
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_dispatch" => {
                let slugs: Vec<String> = match s(a, "boardId") {
                    Some(x) => vec![super::normalize_slug(Some(x))?.unwrap_or_default()],
                    None => boards::list_boards(data, false).into_iter().map(|m| m.slug).collect(),
                };
                let o = dispatch::TickOpts { no_spawn: true, ..Default::default() };
                let mut out = vec![];
                for slug in slugs {
                    let r = match super::kernel() {
                        Some(k) => dispatch::tick_board(data, &slug, cfg, &dispatch::KernelSpawner { k }, &o)?,
                        None => dispatch::tick_board(data, &slug, cfg, &dispatch::RecordingSpawner::default(), &o)?,
                    };
                    out.push(r);
                }
                let promoted: u32 = out.iter().map(|r| r.promoted).sum();
                let reclaimed: Vec<&String> = out.iter().flat_map(|r| r.reclaimed.iter().chain(r.recovered.iter()).chain(r.crashed.iter())).collect();
                let blocked: Vec<&String> = out.iter().flat_map(|r| r.auto_blocked.iter().chain(r.timed_out.iter())).collect();
                Ok(json!({"promoted": promoted, "reclaimed": reclaimed, "blocked": blocked, "boards": out}))
            }
            "workboard_worker_log" => {
                let (slug, id, _) = self.scoped(c, a, false)?;
                let level = s(a, "level").unwrap_or("info");
                if !matches!(level, "info" | "warning" | "error") {
                    return Err("level must be info, warning, or error.".into());
                }
                let msg = cap(need(a, "message")?, 2000, "message")?;
                if s(a, "runId").is_some_and(|r| r.len() > 512) {
                    return Err("runId must be at most 512 characters.".into());
                }
                store::with_board(data, &slug, |b| {
                    b.worker_logs.push(WorkerLog { task_id: id.clone(), level: level.into(), message: ops::redact(&msg), session_key: s(a, "sessionKey").map(String::from), run_id: s(a, "runId").map(String::from), created_at: now() });
                    let n = b.worker_logs.iter().filter(|w| w.task_id == id).count();
                    if n > 200 {
                        let first = b.worker_logs.iter().position(|w| w.task_id == id).unwrap();
                        b.worker_logs.remove(first);
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_protocol_violation" => {
                let (slug, id, _) = self.scoped(c, a, true)?;
                let detail = s(a, "detail").unwrap_or("worker stopped without workboard_complete or workboard_block").to_string();
                store::with_board(data, &slug, |b| {
                    b.append_event(&id, "protocol_violation", Some(json!({"detail": detail, "sessionKey": s(a, "sessionKey"), "runId": s(a, "runId")})), b.task(&id).and_then(|t| t.current_run_id));
                    if !ops::block(b, &id, Some(&format!("protocol violation: {detail}")), None, None)? {
                        return Err("card cannot be blocked from its current state.".into());
                    }
                    Ok(())
                })?;
                Ok(json!({"card": self.card(c, &slug, &id)?}))
            }
            "workboard_sessions_board_read" => {
                let slug = super::sessions_board::resolve_board_id(data, s(a, "boardId"))?;
                super::sessions_board::read(data, &slug)
            }
            "workboard_sessions_board_update" => {
                let slug = super::sessions_board::resolve_board_id(data, s(a, "boardId"))?;
                Ok(json!({"board": super::sessions_board::update(data, &slug, a)?}))
            }
            "workboard_sessions_board_move" => {
                let slug = super::sessions_board::resolve_board_id(data, s(a, "boardId"))?;
                super::sessions_board::pin(data, &slug, need(a, "sessionKey")?, need(a, "columnId")?)
            }
            other => Err(format!("unknown workboard tool {other}")),
        }
    }
}

fn seagent_ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn interrupt(sessions: Vec<String>) {
    if let Some(k) = super::kernel() {
        for s in sessions {
            k.interrupt(&s);
        }
    }
}

fn proof_from(a: &Value, task: &str) -> Result<Proof, String> {
    let status = s(a, "status").unwrap_or("unknown");
    if !matches!(status, "passed" | "failed" | "skipped" | "unknown") {
        return Err("proof status must be passed, failed, skipped, or unknown.".into());
    }
    let url = s(a, "url").map(String::from);
    if url.as_deref().is_some_and(|u| !(u.starts_with("http://") || u.starts_with("https://"))) {
        return Err("proof url must be http(s).".into());
    }
    let n = now();
    Ok(Proof { id: format!("proof_{}", random_hex(12)), task_id: task.into(), status: status.into(), label: s(a, "label").map(String::from), command: s(a, "command").map(String::from), url, note: s(a, "note").map(|x| x.chars().take(1000).collect()), artifact_path: s(a, "artifactPath").map(String::from), created_at: n, updated_at: n })
}

/// Completion proof: resolve the pending record named by `proof_id` in place (same id
/// and timestamp); an identical terminal status is reused; otherwise append.
pub fn append_completion_proof(b: &mut BoardData, task: &str, p: Proof, proof_id: Option<&str>) {
    if let Some(pid) = proof_id {
        if let Some(e) = b.proofs.iter_mut().find(|x| x.id == pid && x.task_id == task) {
            if e.status != p.status {
                e.status = p.status;
                e.note = p.note.or(e.note.take());
                e.command = p.command.or(e.command.take());
                e.url = p.url.or(e.url.take());
                e.label = p.label.or(e.label.take());
                e.updated_at = now();
            }
            return;
        }
    }
    b.append_event(task, "proof_added", Some(json!({"proof_id": p.id, "status": p.status})), None);
    b.proofs.push(p);
}

fn parse_attachment_id(data: &Path, raw: &str) -> Result<(String, u64), String> {
    match raw.split_once(':') {
        Some((slug, n)) => Ok((super::normalize_slug(Some(slug))?.unwrap_or_default(), n.parse().map_err(|_| format!("invalid attachment id: {raw}"))?)),
        None => Ok((super::current_board(data), raw.parse().map_err(|_| format!("invalid attachment id: {raw}"))?)),
    }
}

fn find_sub(data: &Path, id: &str) -> Result<(String, BoardData), String> {
    for m in boards::list_boards(data, true) {
        let b = store::read_board(data, &m.slug)?;
        if b.subscriptions.iter().any(|x| x.id == id) {
            return Ok((m.slug, b));
        }
    }
    Err(format!("subscription not found: {id}"))
}

fn sub_json(slug: &str, x: &Subscription) -> Value {
    json!({"id": x.id, "boardId": slug, "cardId": x.task_id, "sessionKey": x.session_key, "runId": x.run_id, "target": x.target, "eventKinds": x.event_kinds, "cursor": x.cursor, "createdAt": x.created_at * 1000})
}
fn note_json(n: &store::Notification) -> Value {
    json!({"seq": n.seq, "cardId": n.task_id, "kind": n.kind, "message": n.message, "runId": n.run_id.map(|r| r.to_string()), "sessionKey": n.session_key, "artifacts": n.artifacts, "createdAt": n.created_at * 1000})
}

pub fn effects_dir(data: &Path, slug: &str) -> std::path::PathBuf {
    board_dir(data, slug)
}

#[cfg(test)]
mod tests;
