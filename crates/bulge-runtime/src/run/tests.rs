use super::*;
use std::path::PathBuf;
use bulge_core::dispatch::DELEGATE_TOOL;
use bulge_core::ORG_STATUS_TOOL;
use bulge_llm::{Message, Role};
use bulge_store::{Autonomy, Budget, JobEvent, JobSpec, JobStatus, JobStore, ModelRef};

fn finished_job(label: &str, review_reply: Option<&str>, status: JobStatus) -> bulge_store::JobHandle {
    let root = std::env::temp_dir().join(format!("bulge-learn-gate-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let spec = JobSpec {
        id: "j".into(),
        title: "t".into(),
        goal: "g".into(),
        workspace: PathBuf::from("/tmp/ws"),
        autonomy: Autonomy::default(),
        budget: Budget { max_steps: 5, max_tokens: 1000, max_wall_secs: 60 },
        model: ModelRef { backend: "fake".into(), model: "m".into() },
    };
    let mut job = JobStore::new(root).create(spec).unwrap();
    let mut events = vec![
        JobEvent::Message { message: Message::text(Role::User, "do the thing") },
        JobEvent::Message { message: Message::text(Role::Assistant, "done") },
    ];
    if let Some(reply) = review_reply {
        events.push(JobEvent::Message { message: Message::text(Role::User, bulge_core::complete::SELF_REVIEW_CRITERIA) });
        events.push(JobEvent::Message { message: Message::text(Role::Assistant, reply) });
    }
    events.push(JobEvent::StatusChanged { status, summary: None });
    job.append(events).unwrap();
    job
}

#[test]
fn learning_is_skipped_only_for_a_routine_single_turn_success() {
    let routine = finished_job("routine", Some("1. yes\n**LEARN:** no\nVERDICT: PASS"), JobStatus::Succeeded);
    assert!(learning_skip_reason(routine.state(), 1).is_some());
    // A follow-up turn (likely a correction) always learns.
    assert_eq!(learning_skip_reason(routine.state(), 2), None);
    // The reviewer saw something new.
    let novel = finished_job("novel", Some("LEARN: yes\nVERDICT: PASS"), JobStatus::Succeeded);
    assert_eq!(learning_skip_reason(novel.state(), 1), None);
    // Failure, a missing review, or an unparsable line all fail open (learn).
    let failed = finished_job("failed", Some("LEARN: no\nVERDICT: FAIL"), JobStatus::Incomplete);
    assert_eq!(learning_skip_reason(failed.state(), 1), None);
    let unreviewed = finished_job("unreviewed", None, JobStatus::Succeeded);
    assert_eq!(learning_skip_reason(unreviewed.state(), 1), None);
    let vague = finished_job("vague", Some("LEARN: maybe\nVERDICT: PASS"), JobStatus::Succeeded);
    assert_eq!(learning_skip_reason(vague.state(), 1), None);
}

#[test]
fn profiles_are_consolidated_when_keys_repeat_or_space_runs_low() {
    let profile = |sections: &[(&str, &str)]| bulge_harness::Profile { sections: sections.iter().map(|(k, b)| bulge_harness::Section { key: (*k).into(), body: (*b).into() }).collect() };
    assert!(!needs_consolidation(&profile(&[("Language", "zh-TW"), ("Style", "terse")]), 1400));
    assert!(needs_consolidation(&profile(&[("Language", "zh-TW"), ("language", "zh-TW")]), 1400), "same key but for case");
    assert!(needs_consolidation(&profile(&[("Live facts", "a"), ("live-facts", "b")]), 1400), "same key but for punctuation");
    assert!(needs_consolidation(&profile(&[("Long", &"x".repeat(1200))]), 1400), "over 85% full");
}

#[test]
fn the_head_keeps_mcp_tools_and_children_never_get_them() {
    let mcp = vec![bulge_llm::ToolSchema { name: "mcp__shop__create_order".into(), description: "d".into(), parameters: serde_json::json!({}), defer_loading: false }];
    let child = child_tool_list(&mcp);
    assert!(child.iter().all(|t| !t.name.starts_with("mcp__") && t.name != DELEGATE_TOOL && t.name != ORG_STATUS_TOOL));
    let delegate = bulge_llm::ToolSchema { name: DELEGATE_TOOL.into(), description: "d".into(), parameters: serde_json::json!({}), defer_loading: false };
    let head = head_tool_list(&child, &mcp, delegate);
    for name in ["mcp__shop__create_order", DELEGATE_TOOL, ORG_STATUS_TOOL] {
        assert!(head.iter().any(|t| t.name == name), "head is missing {name}");
    }
}

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
