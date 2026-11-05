//! What a worker reads about its task (`build_worker_context`): header, body,
//! attachments, prior attempts, parent handoffs, the assignee's recent work and the
//! comment thread. Lists are tail-capped and fields char-capped so the prompt stays
//! bounded on pathological boards.

use super::store::BoardData;
use crate::util::fmt_time;

const MAX_PRIOR_ATTEMPTS: usize = 10;
const MAX_COMMENTS: usize = 30;
const MAX_FIELD: usize = 4 * 1024;
const MAX_BODY: usize = 8 * 1024;
const MAX_COMMENT: usize = 2 * 1024;

/// `just now` / `18h ago` / `3d ago`: a bare timestamp reads as current fact, an age
/// prompts the worker to re-verify stale sibling work.
pub fn relative_age(ts: i64, now: i64) -> String {
    let d = now - ts;
    if d < 60 {
        "just now".into()
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

pub fn cap(s: &str, limit: usize) -> String {
    let s = s.trim();
    let n = s.chars().count();
    if n <= limit {
        return s.to_string();
    }
    let head: String = s.chars().take(limit).collect();
    format!("{head}… [truncated, {} chars omitted]", n - limit)
}

fn stamp(ts: i64, now: i64) -> String {
    format!("{}, {}", fmt_time(ts, 480), relative_age(ts, now))
}

fn meta_line(m: &Option<serde_json::Value>) -> Option<String> {
    let m = m.as_ref().filter(|m| !m.is_null() && m.as_object().is_none_or(|o| !o.is_empty()))?;
    Some(format!("_metadata_: `{}`", cap(&m.to_string(), MAX_FIELD)))
}

pub fn build_worker_context(b: &BoardData, id: &str, now: i64) -> Result<String, String> {
    let t = b.task(id).ok_or_else(|| format!("unknown task {id}"))?;
    let mut l: Vec<String> = vec![];
    l.push(format!("# Kanban task {}: {}", t.id, t.title));
    l.push(String::new());
    l.push(format!("Assignee: {}", t.assignee.as_deref().unwrap_or("(unassigned)")));
    l.push(format!("Status:   {}", t.status));
    if let Some(x) = &t.tenant {
        l.push(format!("Tenant:   {x}"));
    }
    l.push(format!("Workspace: {} @ {}", t.workspace_kind, t.workspace_path.as_deref().unwrap_or("(unresolved)")));
    if let Some(m) = t.max_runtime_seconds {
        l.push(format!("Max runtime: {m}s"));
    }
    if let Some(br) = &t.branch_name {
        l.push(format!("Branch:   {br}"));
    }
    if !t.labels.is_empty() {
        l.push(format!("Labels:   {}", t.labels.join(", ")));
    }
    l.push(String::new());
    if let Some(body) = t.body.as_deref().filter(|s| !s.trim().is_empty()) {
        l.push("## Body".into());
        l.push(cap(body, MAX_BODY));
        l.push(String::new());
    }
    let atts = b.attachments_for(id);
    if !atts.is_empty() {
        l.push("## Attachments".into());
        l.push("Files attached to this task. Read them with the file/terminal tools at the absolute paths below:".into());
        for a in atts {
            let kb = if a.size > 0 { format!(", {} KB", a.size.div_ceil(1024).max(1)) } else { String::new() };
            let ct = a.content_type.as_deref().map(|c| format!(", {c}")).unwrap_or_default();
            l.push(format!("- `{}`{ct}{kb} → `{}`", a.filename, a.stored_path));
        }
        l.push(String::new());
    }
    let prior: Vec<_> = b.runs_for(id).into_iter().filter(|r| r.ended_at.is_some()).collect();
    if !prior.is_empty() {
        let omitted = prior.len().saturating_sub(MAX_PRIOR_ATTEMPTS);
        l.push("## Prior attempts on this task".into());
        if omitted > 0 {
            l.push(format!("_({omitted} earlier attempt{} omitted; showing most recent {MAX_PRIOR_ATTEMPTS})_", if omitted == 1 { "" } else { "s" }));
        }
        for (i, r) in prior.iter().enumerate().skip(omitted) {
            l.push(format!("### Attempt {} — {} ({}, {})", i + 1, r.outcome.as_deref().unwrap_or(&r.status), r.profile.as_deref().unwrap_or("(unknown)"), stamp(r.started_at, now)));
            if let Some(s) = r.summary.as_deref().filter(|s| !s.trim().is_empty()) {
                l.push(cap(s, MAX_FIELD));
            }
            if let Some(e) = r.error.as_deref().filter(|s| !s.trim().is_empty()) {
                l.push(format!("_error_: {}", cap(e, MAX_FIELD)));
            }
            if let Some(m) = meta_line(&r.metadata) {
                l.push(m);
            }
            l.push(String::new());
        }
    }
    let mut header = false;
    for pid in b.parent_ids(id) {
        let Some(p) = b.task(&pid).filter(|p| p.status == "done") else { continue };
        if !header {
            l.push("## Parent task results".into());
            l.push("_Handoffs from upstream tasks, captured when each parent completed (see age below). These are point-in-time snapshots, not live state — if a result drives your current work and it's not recent, re-verify against the source before acting on it as current._".into());
            header = true;
        }
        let run = b.runs_for(&pid).into_iter().filter(|r| r.outcome.as_deref() == Some("completed")).max_by_key(|r| (r.started_at, r.id));
        let done = run.and_then(|r| r.ended_at).or(p.completed_at);
        l.push(format!("### {pid}{}", done.map(|d| format!(" (completed {})", relative_age(d, now))).unwrap_or_default()));
        match (run.and_then(|r| r.summary.as_deref()).filter(|s| !s.trim().is_empty()), p.result.as_deref()) {
            (Some(s), _) => l.push(cap(s, MAX_FIELD)),
            (None, Some(r)) => l.push(cap(r, MAX_FIELD)),
            _ => l.push("(no result recorded)".into()),
        }
        if let Some(m) = run.and_then(|r| meta_line(&r.metadata)) {
            l.push(m);
        }
        l.push(String::new());
    }
    if let Some(a) = &t.assignee {
        let mut recent: Vec<_> = b.runs.iter().filter(|r| r.profile.as_deref() == Some(a) && r.task_id != id && r.outcome.as_deref() == Some("completed")).collect();
        recent.sort_by_key(|r| std::cmp::Reverse(r.ended_at));
        if !recent.is_empty() {
            l.push(format!("## Recent work by @{a}"));
            for r in recent.into_iter().take(5) {
                let title = b.task(&r.task_id).map(|x| x.title.as_str()).unwrap_or("");
                let first = super::ops::first_line(r.summary.as_deref(), 200);
                l.push(format!("- {} — {title} ({}): {}", r.task_id, stamp(r.ended_at.unwrap_or(0), now), if first.is_empty() { "(no summary)".into() } else { first }));
            }
            l.push(String::new());
        }
    }
    let comments = b.comments_for(id);
    if !comments.is_empty() {
        let omitted = comments.len().saturating_sub(MAX_COMMENTS);
        l.push("## Comment thread".into());
        if omitted > 0 {
            l.push(format!("_({omitted} earlier comment{} omitted; showing most recent {MAX_COMMENTS})_", if omitted == 1 { "" } else { "s" }));
        }
        for c in comments.into_iter().skip(omitted) {
            // "comment from worker" framing: an author named like a system role must not
            // read as a directive above an attacker-influenceable body.
            l.push(format!("comment from worker `{}` at {}:", c.author.replace('`', ""), stamp(c.created_at, now)));
            l.push(cap(&c.body, MAX_COMMENT));
            l.push(String::new());
        }
    }
    Ok(l.join("\n").trim_end().to_string() + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kanban::ops::{self, NewTask};

    #[test]
    fn context_sections_and_caps() {
        let mut b = BoardData::default();
        let p = ops::create_task(&mut b, NewTask { title: "research".into(), assignee: Some("r".into()), ..Default::default() }).unwrap();
        let rid = ops::claim(&mut b, &p, ops::ClaimOpts { lock: "h:1", ttl: 60, lane: "ready", owner: None, token: None }).unwrap();
        b.task_mut(&p).unwrap().current_run_id = Some(rid);
        ops::complete(&mut b, std::path::Path::new("/nonexistent"), "default", &p, ops::Completion { summary: Some("found 3 sources".into()), metadata: Some(serde_json::json!({"n": 3})), expected_run: Some(rid), ..Default::default() }, 2).unwrap();
        let c = ops::create_task(&mut b, NewTask { title: "write".into(), body: Some("x".repeat(9000)), assignee: Some("r".into()), parents: vec![p.clone()], ..Default::default() }).unwrap();
        b.insert_comment(&c, "hermes`system", "please cite");
        let ctx = build_worker_context(&b, &c, crate::kanban::now() + 7200).unwrap();
        assert!(ctx.starts_with(&format!("# Kanban task {c}: write")));
        assert!(ctx.contains("## Parent task results") && ctx.contains("found 3 sources") && ctx.contains("(completed 2h ago)"));
        assert!(ctx.contains("_metadata_: `{\"n\":3}`"));
        assert!(ctx.contains("truncated, 808 chars omitted"));
        assert!(ctx.contains("## Recent work by @r"));
        assert!(ctx.contains("comment from worker `hermessystem`"), "backticks stripped from author");
        assert!(build_worker_context(&b, "t_nope", 0).is_err());
        assert_eq!(relative_age(100, 100 - 5), "just now", "clock skew never claims the future");
        assert_eq!(relative_age(0, 3 * 86_400), "3d ago");
    }
}
