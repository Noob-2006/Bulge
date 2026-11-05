//! Board health: read-only rules over a task's row, events and runs (Hermes
//! `kanban_diagnostics`), plus OpenClaw Workboard's card checks. Nothing here
//! mutates the board.

use super::store::{BoardData, Event, Run, Task};
use super::DiagnosticsConfig;
use serde::Serialize;
use serde_json::{json, Value};

pub const SEVERITY_ORDER: &[&str] = &["warning", "error", "critical"];

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub kind: String,
    pub label: String,
    pub payload: Value,
    pub suggested: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub actions: Vec<Action>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub count: u64,
    pub data: Value,
}

pub fn severity_at_or_above(s: &str, threshold: Option<&str>) -> bool {
    let Some(t) = threshold else { return true };
    match (SEVERITY_ORDER.iter().position(|x| *x == s), SEVERITY_ORDER.iter().position(|x| *x == t)) {
        (Some(a), Some(b)) => a >= b,
        _ => false,
    }
}

fn act(kind: &str, label: &str, payload: Value, suggested: bool) -> Action {
    Action { kind: kind.into(), label: label.into(), payload, suggested }
}
fn hint(label: &str, cmd: &str, suggested: bool) -> Action {
    act("cli_hint", label, json!({"command": cmd}), suggested)
}
fn recovery(t: &Task) -> Vec<Action> {
    let running = t.status == "running";
    let mut v = vec![];
    if running {
        v.push(act("reclaim", "Reclaim task", json!({}), false));
    }
    v.push(act("reassign", "Reassign to different profile", json!({"reclaim_first": running}), false));
    v
}
/// Every diagnostic field is already named at the call site; a struct would only add
/// boilerplate, so the nine scalars stay positional.
#[allow(clippy::too_many_arguments)]
fn diag(kind: &str, severity: &str, title: String, detail: String, actions: Vec<Action>, first: i64, last: i64, count: u64, data: Value) -> Diagnostic {
    Diagnostic { kind: kind.into(), severity: severity.into(), title, detail, actions, first_seen_at: first, last_seen_at: last, count, data }
}

/// Events of `kind` with no `completed`/`edited` after them.
fn active_hits<'a>(events: &[&'a Event], kind: &str) -> Vec<&'a Event> {
    let mut v = vec![];
    for e in events {
        if e.kind == "completed" || e.kind == "edited" {
            v.clear();
        } else if e.kind == kind {
            v.push(*e);
        }
    }
    v
}
fn payload_ids(hits: &[&Event], key: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for e in hits {
        for x in e.payload.as_ref().and_then(|p| p[key].as_array()).into_iter().flatten().filter_map(|x| x.as_str()) {
            if !v.iter().any(|y| y == x) {
                v.push(x.into());
            }
        }
    }
    v
}
fn newest_first<'a>(runs: &[&'a Run]) -> Vec<&'a Run> {
    let mut v = runs.to_vec();
    v.sort_by_key(|r| std::cmp::Reverse((r.ended_at.unwrap_or(r.started_at), r.id)));
    v
}
fn snippet(e: Option<&str>) -> String {
    e.map(|e| super::context::cap(e, 1200)).unwrap_or_default()
}
fn latest_ts(events: &[&Event], kinds: &[&str]) -> i64 {
    events.iter().filter(|e| kinds.contains(&e.kind.as_str())).map(|e| e.created_at).max().unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn rules(b: &BoardData, t: &Task, ev: &[&Event], runs: &[&Run], now: i64, c: &DiagnosticsConfig, failure_limit: u32, out: &mut Vec<Diagnostic>) {
    let id = t.id.as_str();
    // hallucinated cards
    let hits = active_hits(ev, "completion_blocked_hallucination");
    if !hits.is_empty() {
        let mut a = vec![act("comment", "Add a comment explaining what to do", json!({}), false)];
        a.extend(recovery(t));
        out.push(diag("hallucinated_cards", "error", "Worker claimed cards that don't exist".into(), "The completing worker declared created_cards that either didn't exist or weren't created by its profile. The completion was blocked and the task stayed in its prior state. Usually means the worker hallucinated ids instead of capturing return values from kanban_create.".into(), a, hits[0].created_at, hits[hits.len() - 1].created_at, hits.len() as u64, json!({"phantom_ids": payload_ids(&hits, "phantom_cards")})));
    }
    // prose phantom refs
    let hits = active_hits(ev, "suspected_hallucinated_references");
    if !hits.is_empty() {
        out.push(diag("prose_phantom_refs", "warning", "Completion summary references unknown task ids".into(), "The completion summary mentions task ids that don't resolve in this board. The completion itself succeeded, but downstream consumers parsing the summary may be pointed at cards that never existed.".into(), recovery(t), hits[0].created_at, hits[hits.len() - 1].created_at, hits.len() as u64, json!({"phantom_refs": payload_ids(&hits, "phantom_refs")})));
    }
    let threshold = c.failure_threshold.unwrap_or(failure_limit).max(1);
    let exempt = matches!(t.status.as_str(), "done" | "archived" | "running");
    // repeated failures
    if !exempt && t.consecutive_failures >= threshold {
        let f = t.consecutive_failures;
        let recent = newest_first(runs).into_iter().find_map(|r| r.outcome.as_deref().filter(|o| matches!(*o, "spawn_failed" | "timed_out" | "crashed")).map(String::from));
        let mut a = vec![];
        match recent.as_deref() {
            Some("spawn_failed") => a.push(hint(&format!("Check the profile config: ark kanban show {id}"), &format!("ark kanban show {id}"), true)),
            Some("timed_out" | "crashed") => a.push(act("cli_hint", "View worker log", json!({"command": format!("ark kanban log {id}")}), true)),
            _ => {}
        }
        a.extend(recovery(t));
        let label = match recent.as_deref() {
            Some("spawn_failed") => "spawn",
            Some("timed_out") => "timeout",
            Some("crashed") => "crash",
            _ => "failure",
        };
        let err = snippet(t.last_failure_error.as_deref());
        let (title, detail) = if err.is_empty() {
            (format!("Agent {label} x{f} (no error recorded)"), format!("This task has failed {f} times in a row (most recent: {label}) but no error text was captured. Check the suggested command or the worker log."))
        } else {
            (format!("Agent {label} x{f}: {}", err.lines().next().unwrap_or("").chars().take(160).collect::<String>()), format!("This task has failed {f} times in a row (most recent: {label}). Full last error:\n\n{err}\n\nThe dispatcher circuit breaker is configured for {failure_limit} consecutive non-success attempts. Fix the root cause and reclaim or unblock the task to retry."))
        };
        out.push(diag("repeated_failures", if f >= threshold * 2 { "critical" } else { "error" }, title, detail, a, now, now, f as u64, json!({"consecutive_failures": f, "most_recent_outcome": recent, "last_error": t.last_failure_error, "failure_threshold": threshold, "failure_limit": failure_limit})));
    }
    // repeated crashes (suppressed when the unified rule fires)
    if !exempt && t.consecutive_failures < threshold {
        let mut n = 0u64;
        let mut last_err = None;
        for r in newest_first(runs) {
            match r.outcome.as_deref() {
                Some("crashed") => {
                    n += 1;
                    if last_err.is_none() {
                        last_err = r.error.clone();
                    }
                }
                Some("completed" | "reclaimed") => break,
                _ => {}
            }
        }
        if n >= c.crash_threshold as u64 && n > 0 {
            let err = snippet(last_err.as_deref());
            let mut a = vec![act("cli_hint", "View worker log", json!({"command": format!("ark kanban log {id}")}), true)];
            a.extend(recovery(t));
            let title = if err.is_empty() { format!("Agent crashed {n}x (no error recorded)") } else { format!("Agent crashed {n}x: {}", err.lines().next().unwrap_or("").chars().take(160).collect::<String>()) };
            out.push(diag("repeated_crashes", if n >= c.crash_threshold as u64 * 2 { "critical" } else { "error" }, title, format!("The last {n} runs ended with outcome=crashed. Full last error:\n\n{err}"), a, now, now, n, json!({"consecutive_crashes": n, "last_error": last_err})));
        }
    }
    // review dependency deadlock
    if t.status == "blocked" {
        if let Some(lb) = ev.iter().rev().find(|e| e.kind == "blocked") {
            let reason = lb.payload.as_ref().and_then(|p| p["reason"].as_str()).unwrap_or("").trim().to_string();
            let waiting: Vec<String> = b.child_ids(id).into_iter().filter(|c| b.status_of(c) == Some("todo")).collect();
            if reason.to_lowercase().starts_with("review-required:") && !waiting.is_empty() {
                let a = vec![hint("Complete the finished implementation phase", &format!("ark kanban complete {id}"), true), hint("Or unlink the incorrectly gated reviewer", &format!("ark kanban unlink {id} {}", waiting[0]), false)];
                out.push(diag("review_dependency_deadlock", "error", format!("Review handoff blocks {} dependent task(s)", waiting.len()), "This implementation is sticky-blocked for review while its downstream task(s) require the implementation to be done or archived before they can run. Complete the finished phase, unlink the incorrect dependency, or use the first-class review lifecycle (kanban_request_review).".into(), a, lb.created_at, lb.created_at, waiting.len() as u64, json!({"blocked_parent_id": id, "waiting_child_ids": waiting, "block_reason": reason})));
            }
        }
    }
    // running with open parents
    if t.status == "running" {
        let open = super::ops::unsatisfied_parents(b, id);
        if !open.is_empty() {
            let seen = t.started_at.unwrap_or(now);
            out.push(diag("running_with_open_parents", "warning", format!("Running while {} parent(s) are not done", open.len()), "This card is running concurrently with a parent it declares a dependency on, so the parent's work is not serialised ahead of it and completion will be refused until every parent is done or archived. Finish the parent, or unlink the edge if it was never meant to gate this run.".into(), vec![hint("Unlink the parent that should not gate this run", &format!("ark kanban unlink {} {id}", open[0].0), false)], seen, now, open.len() as u64, json!({"open_parents": open.iter().map(|(i, s)| json!({"id": i, "status": s})).collect::<Vec<_>>()})));
        }
    }
    // stuck in blocked
    if t.status == "blocked" {
        let lb = latest_ts(ev, &["blocked"]);
        let age_h = (now - lb) as f64 / 3600.0;
        if lb > 0 && age_h >= c.blocked_stale_hours && !ev.iter().any(|e| (e.kind == "commented" || e.kind == "unblocked") && e.created_at > lb) {
            out.push(diag("stuck_in_blocked", "warning", format!("Task has been blocked for {}h", age_h as i64), format!("This task transitioned to blocked {}h ago and has had no comments or unblock attempts since. Blocked tasks are waiting for human input — check the block reason and either unblock with feedback or answer with a comment.", age_h as i64), vec![act("comment", "Add a comment / unblock the task", json!({}), true)], lb, lb, 1, json!({"blocked_at": lb, "age_hours": (age_h * 10.0).round() / 10.0})));
        }
    }
    // block -> unblock cycling
    let cutoff = now - c.block_cycle_window_secs;
    let (mut cycles, mut seen_unblock, mut first, mut last) = (0u64, false, 0i64, 0i64);
    for e in ev.iter().filter(|e| e.created_at >= cutoff) {
        if e.kind == "blocked" {
            if first == 0 {
                first = e.created_at;
            }
            if seen_unblock {
                cycles += 1;
                last = e.created_at;
                seen_unblock = false;
            }
        } else if e.kind == "unblocked" {
            seen_unblock = true;
        }
    }
    if cycles >= c.block_cycle_threshold.max(1) as u64 {
        let cmd = format!("ark kanban show {id}");
        out.push(diag("block_unblock_cycling", "warning", format!("Task block→unblock cycled {cycles}x in {}h", c.block_cycle_window_secs / 3600), format!("This task has been blocked {cycles} times after being unblocked, suggesting the unblock is not addressing the root cause and the worker keeps hitting the same wall. Review the block reasons in the event history; a different intervention (reassign, change scope, archive) may be needed."), vec![hint(&format!("Check block reasons: {cmd}"), &cmd, true)], if first > 0 { first } else { now }, if last > 0 { last } else { now }, cycles, json!({"cycles": cycles, "window_seconds": c.block_cycle_window_secs})));
    }
    // stranded in ready
    if t.status == "ready" && t.claim_lock.is_none() {
        if let Some(a) = t.assignee.as_deref().filter(|a| !a.trim().is_empty()) {
            let mut since = latest_ts(ev, &["created", "promoted", "reclaimed", "unblocked"]);
            if since == 0 {
                since = t.created_at;
            }
            let age = now - since;
            let th = c.stranded_threshold_secs.max(1);
            if since > 0 && age >= th {
                let age_s = if age >= 3600 { format!("{:.1}h", age as f64 / 3600.0) } else { format!("{}m", age / 60) };
                let sev = if age >= th * 6 { "critical" } else if age >= th * 2 { "error" } else { "warning" };
                out.push(diag("stranded_in_ready", sev, format!("Ready for {age_s} with no worker"), format!("This task has been ready for {age_s} but nothing has claimed it. Common causes: assignee {a:?} is misspelled or not a configured [kanban.profiles] entry, the dispatcher is not running (arkd with [kanban] enabled), or the worker cap is saturated. Confirm the assignee is correct and that a dispatcher is ticking."), vec![act("reassign", "Reassign to a different worker", json!({"current_assignee": a}), false), hint("Check dispatcher status", "ark kanban diagnostics", false)], since, since, 1, json!({"ready_since": since, "age_seconds": age, "assignee": a, "threshold_seconds": th})));
            }
        }
    }
    // stale running (expired claim, no live worker, no fresh heartbeat)
    if t.status == "running" {
        if let Some(exp) = t.claim_expires {
            let grace = c.stale_running_grace_secs;
            let fresh_hb = t.last_heartbeat_at.is_some_and(|h| now - h <= 3600);
            let live = super::dispatch::claim_is_live(b, t);
            if now - exp >= grace && !fresh_hb && !live && t.claim_lock.as_deref().is_some_and(|l| l.starts_with(&super::host_prefix())) {
                let exp_s = now - exp;
                let age_s = if exp_s >= 3600 { format!("{:.1}h", exp_s as f64 / 3600.0) } else { format!("{}m", exp_s / 60) };
                let sev = if exp_s >= grace * 6 { "critical" } else if exp_s >= grace * 2 { "error" } else { "warning" };
                out.push(diag("stale_running", sev, format!("Running {age_s} past its expired claim with no live worker"), format!("Nothing is executing this card and nothing has reclaimed it: the claim expired {age_s} ago, no heartbeat arrived inside the last hour, and its worker session is not running. Check the card's log, then reclaim it."), vec![act("reclaim", "Reclaim the dead claim", json!({}), true), hint("Reclaim from the CLI", &format!("ark kanban reclaim {id}"), false)], exp, exp, 1, json!({"claim_expires": exp, "expired_seconds": exp_s, "last_heartbeat_at": t.last_heartbeat_at, "grace_seconds": grace})));
            }
        }
    }
}

/// Every rule for one task: critical first, then error, warning; ties newest first.
pub fn task_diagnostics(b: &BoardData, id: &str, now: i64, c: &DiagnosticsConfig, failure_limit: u32) -> Vec<Diagnostic> {
    let Some(t) = b.task(id) else { return vec![] };
    let ev = b.events_for(id);
    let runs = b.runs_for(id);
    let mut out = vec![];
    rules(b, t, &ev, &runs, now, c, failure_limit, &mut out);
    out.sort_by_key(|d| (std::cmp::Reverse(SEVERITY_ORDER.iter().position(|s| *s == d.severity).map(|p| p as i64).unwrap_or(-1)), std::cmp::Reverse(d.last_seen_at)));
    out
}

/// `[{task_id, title, status, diagnostics}]` for every task with an active signal.
pub fn board_diagnostics(b: &BoardData, now: i64, c: &DiagnosticsConfig, failure_limit: u32, min_severity: Option<&str>, only: Option<&str>) -> Vec<Value> {
    b.tasks
        .iter()
        .filter(|t| only.is_none_or(|o| o == t.id))
        .filter_map(|t| {
            let d: Vec<Diagnostic> = task_diagnostics(b, &t.id, now, c, failure_limit).into_iter().filter(|d| severity_at_or_above(&d.severity, min_severity)).collect();
            (!d.is_empty()).then(|| json!({"task_id": t.id, "title": t.title, "status": t.status, "assignee": t.assignee, "diagnostics": d}))
        })
        .collect()
}

/// OpenClaw Workboard card diagnostics (`kind`, `severity`, `message`).
pub fn workboard_card_diagnostics(b: &BoardData, t: &Task, now: i64) -> Vec<Value> {
    let mut v = vec![];
    let idle = now - t.updated_at.max(t.created_at);
    let mut push = |kind: &str, severity: &str, message: String| v.push(json!({"kind": kind, "severity": severity, "message": message, "detectedAt": now * 1000}));
    if matches!(t.status.as_str(), "todo" | "backlog" | "ready") && t.assignee.is_some() && idle > 3600 {
        push("stranded_ready", "warning", format!("Assigned {} card has not been updated in {}h.", t.status, idle / 3600));
    }
    if t.status == "running" {
        let last = t.last_heartbeat_at.or(t.started_at).unwrap_or(t.updated_at);
        if now - last > 20 * 60 {
            push("running_without_heartbeat", "warning", format!("Running card has had no claim heartbeat for {}m.", (now - last) / 60));
        }
        let has_exec = t.current_run_id.and_then(|r| b.run(r)).is_some_and(|r| r.worker_session.is_some());
        if t.session_key.is_some() && !has_exec {
            push("orphaned_session", "warning", "Running card links a session but has no execution metadata.".into());
        }
    }
    if t.status == "blocked" && idle > 86_400 {
        push("blocked_too_long", "warning", format!("Blocked for {}h without an update.", idle / 3600));
    }
    if t.consecutive_failures >= 2 {
        push("repeated_failures", "error", format!("Card failed {} times in a row.", t.consecutive_failures));
    }
    if t.status == "done" && !b.proofs.iter().any(|p| p.task_id == t.id) && !b.artifacts.iter().any(|a| a.task_id == t.id) && b.attachments_for(&t.id).is_empty() {
        push("missing_proof", "warning", "Done card has no proof, artifacts, or attachments.".into());
    }
    if t.archived_at.is_some() && t.status != "done" && t.status != "archived" {
        push("archived_but_active", "warning", format!("Archived card is still {}.", t.status));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kanban::ops::{self, Failure, NewTask};

    #[test]
    fn rules_fire_and_clear() {
        let c = DiagnosticsConfig::default();
        let mut b = BoardData::default();
        let id = ops::create_task(&mut b, NewTask { title: "x".into(), assignee: Some("dev".into()), ..Default::default() }).unwrap();
        let now = crate::kanban::now();
        assert!(task_diagnostics(&b, &id, now, &c, 2).is_empty());
        // Stranded in ready after 30 minutes; escalates with age.
        let d = task_diagnostics(&b, &id, now + 1900, &c, 2);
        assert_eq!(d[0].kind, "stranded_in_ready");
        assert_eq!(d[0].severity, "warning");
        assert_eq!(task_diagnostics(&b, &id, now + 30_000, &c, 2)[0].severity, "critical");
        // Repeated failures at the breaker limit.
        ops::record_failure(&mut b, &id, Failure { error: "boom: 429 quota", outcome: "crashed", ..Default::default() }, 5);
        ops::record_failure(&mut b, &id, Failure { error: "boom again", outcome: "crashed", ..Default::default() }, 5);
        let d = task_diagnostics(&b, &id, now, &c, 2);
        assert!(d.iter().any(|d| d.kind == "repeated_failures" && d.title.contains("x2")), "{d:?}");
        // Hallucinated cards until the next completion.
        b.append_event(&id, "completion_blocked_hallucination", Some(json!({"phantom_cards": ["t_dead"]})), None);
        let d = task_diagnostics(&b, &id, now, &c, 2);
        let h = d.iter().find(|d| d.kind == "hallucinated_cards").unwrap();
        assert_eq!(h.data["phantom_ids"][0], "t_dead");
        assert_eq!(d[0].severity, "error", "sorted by severity");
        b.append_event(&id, "completed", None, None);
        assert!(!task_diagnostics(&b, &id, now, &c, 2).iter().any(|d| d.kind == "hallucinated_cards"));
        // Block/unblock cycling.
        for _ in 0..4 {
            b.append_event(&id, "blocked", None, None);
            b.append_event(&id, "unblocked", None, None);
        }
        assert!(task_diagnostics(&b, &id, now, &c, 2).iter().any(|d| d.kind == "block_unblock_cycling" && d.count == 3));
        assert!(severity_at_or_above("critical", Some("error")) && !severity_at_or_above("warning", Some("error")) && severity_at_or_above("warning", None));
        assert_eq!(board_diagnostics(&b, now, &c, 2, Some("critical"), None).len(), 0);
        let t = b.task(&id).unwrap().clone();
        let w = workboard_card_diagnostics(&b, &t, now);
        assert!(w.iter().any(|d| d["kind"] == "repeated_failures"));
    }
}
