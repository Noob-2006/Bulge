use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use bulge_util::now_ms;
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_org::{BoardEvent, MAX_REJECTIONS, PerformanceBook, RoleKind, RoleLibrary, Ticket, TicketStatus, Verdict};

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
