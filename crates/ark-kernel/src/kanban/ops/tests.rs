use super::*;
use std::path::Path;

fn nt(title: &str) -> NewTask {
    NewTask { title: title.into(), assignee: Some("dev".into()), ..Default::default() }
}
fn claim_ready(b: &mut BoardData, id: &str) -> u64 {
    claim(b, id, ClaimOpts { lock: "h:1", ttl: 900, lane: "ready", owner: None, token: None }).unwrap()
}
const NOWHERE: &str = "/nonexistent-ark-kanban";

#[test]
fn create_gating_idempotency_and_validation() {
    let mut b = BoardData::default();
    let p = create_task(&mut b, nt("parent")).unwrap();
    assert_eq!(b.status_of(&p), Some("ready"));
    let c = create_task(&mut b, NewTask { parents: vec![p.clone()], ..nt("child") }).unwrap();
    assert_eq!(b.status_of(&c), Some("todo"));
    assert!(b.events_for(&c).iter().any(|e| e.kind == "dependency_wait"));
    assert_eq!(create_task(&mut b, NewTask { triage: true, ..nt("t") }).map(|i| b.status_of(&i).unwrap().to_string()).unwrap(), "triage");
    let k1 = create_task(&mut b, NewTask { idempotency_key: Some("k".into()), ..nt("a") }).unwrap();
    assert_eq!(create_task(&mut b, NewTask { idempotency_key: Some("k".into()), ..nt("b") }).unwrap(), k1);
    assert!(create_task(&mut b, nt(" ")).is_err());
    assert!(create_task(&mut b, NewTask { parents: vec!["t_missing".into()], ..nt("x") }).unwrap_err().contains("unknown parent"));
    assert!(create_task(&mut b, NewTask { provider_override: Some("p".into()), ..nt("x") }).is_err());
    assert!(create_task(&mut b, NewTask { workspace_kind: Some("vm".into()), ..nt("x") }).is_err());
    assert!(create_task(&mut b, NewTask { branch_name: Some("b".into()), ..nt("x") }).is_err());
    let blk = create_task(&mut b, NewTask { initial_status: Some("blocked".into()), ..nt("ops") }).unwrap();
    assert_eq!(b.status_of(&blk), Some("blocked"));
    assert_eq!(recompute_ready(&mut b, 2), 0, "initial blocked is sticky");
    assert!(new_task_id().starts_with("t_") && new_task_id().len() == 14);
}

#[test]
fn link_cycles_and_running_children() {
    let mut b = BoardData::default();
    let a = create_task(&mut b, nt("a")).unwrap();
    let c = create_task(&mut b, nt("c")).unwrap();
    assert!(link(&mut b, &a, &c, None).unwrap(), "ready child gated to todo");
    assert_eq!(b.status_of(&c), Some("todo"));
    assert!(link(&mut b, &c, &a, None).unwrap_err().contains("cycle"));
    assert!(link(&mut b, &a, &a, None).is_err());
    let r = create_task(&mut b, nt("r")).unwrap();
    let rid = claim_ready(&mut b, &r);
    assert!(link(&mut b, &a, &r, None).unwrap_err().contains("already running"));
    assert!(link(&mut b, &a, &r, Some(rid)).is_ok(), "owning worker may link its own card");
    assert!(unlink(&mut b, &a, &c, 2));
    assert_eq!(b.status_of(&c), Some("ready"), "re-gated immediately");
}

#[test]
fn claim_complete_handoff_and_gates() {
    let mut b = BoardData::default();
    let p = create_task(&mut b, nt("p")).unwrap();
    let c = create_task(&mut b, NewTask { parents: vec![p.clone()], ..nt("c") }).unwrap();
    b.task_mut(&c).unwrap().status = "ready".into();
    assert!(claim(&mut b, &c, ClaimOpts { lock: "h", ttl: 1, lane: "ready", owner: None, token: None }).is_none(), "open parent demotes on claim");
    assert_eq!(b.status_of(&c), Some("todo"));
    let rid = claim_ready(&mut b, &p);
    assert!(claim(&mut b, &p, ClaimOpts { lock: "h2", ttl: 1, lane: "ready", owner: None, token: None }).is_none(), "CAS");
    // Empty completion refused with an audit event.
    assert_eq!(complete(&mut b, Path::new(NOWHERE), "default", &p, Completion { expected_run: Some(rid), ..Default::default() }, 2), Err(Refusal::Empty));
    assert!(b.events_for(&p).iter().any(|e| e.kind == "completion_blocked_empty_result"));
    // Phantom created card refused.
    let r = complete(&mut b, Path::new(NOWHERE), "default", &p, Completion { summary: Some("x".into()), created_cards: Some(vec!["t_deadbeef00".into()]), expected_run: Some(rid), ..Default::default() }, 2);
    assert_eq!(r, Err(Refusal::Hallucinated(vec!["t_deadbeef00".into()])));
    // Live claim without ownership refused; stale run id refused.
    assert_eq!(complete(&mut b, Path::new(NOWHERE), "default", &p, Completion { summary: Some("x".into()), claim_live: true, ..Default::default() }, 2), Err(Refusal::LiveClaim));
    assert_eq!(complete(&mut b, Path::new(NOWHERE), "default", &p, Completion { summary: Some("x".into()), expected_run: Some(rid + 7), ..Default::default() }, 2), Err(Refusal::No));
    let mine = create_task(&mut b, NewTask { created_by: Some("dev".into()), ..nt("follow-up") }).unwrap();
    complete(&mut b, Path::new(NOWHERE), "default", &p, Completion { summary: Some(format!("did it; see t_aaaaaaaabbbb and {mine}")), metadata: Some(json!({"tests_run": 3})), created_cards: Some(vec![mine.clone()]), expected_run: Some(rid), ..Default::default() }, 2).unwrap();
    assert_eq!(b.status_of(&p), Some("done"));
    assert_eq!(b.status_of(&c), Some("ready"), "children promoted");
    let run = b.run(rid).unwrap();
    assert_eq!(run.outcome.as_deref(), Some("completed"));
    assert_eq!(run.metadata.as_ref().unwrap()["tests_run"], 3);
    assert!(b.events_for(&p).iter().any(|e| e.kind == "suspected_hallucinated_references" && e.payload.as_ref().unwrap()["phantom_refs"][0] == "t_aaaaaaaabbbb"));
    assert!(b.notifications.iter().any(|n| n.task_id == p && n.kind == "completed"));
    // Review approvals are exempt from the evidence gate; synthesized run records it.
    let r = create_task(&mut b, nt("rev")).unwrap();
    b.task_mut(&r).unwrap().status = "review".into();
    complete(&mut b, Path::new(NOWHERE), "default", &r, Completion::default(), 2).unwrap();
    assert_eq!(b.latest_run(&r).unwrap().summary.as_deref(), Some(REVIEW_APPROVED_NOTE));
}

#[test]
fn block_kinds_loop_detection_and_unblock() {
    let mut b = BoardData::default();
    let t = create_task(&mut b, nt("t")).unwrap();
    claim_ready(&mut b, &t);
    assert!(block(&mut b, &t, Some("need key"), Some("needs_input"), None).unwrap());
    assert_eq!(b.status_of(&t), Some("blocked"));
    assert_eq!(recompute_ready(&mut b, 2), 0, "explicit block is sticky");
    assert!(unblock(&mut b, &t));
    assert_eq!(b.status_of(&t), Some("ready"));
    claim_ready(&mut b, &t);
    assert!(block(&mut b, &t, Some("need key again"), Some("needs_input"), None).unwrap());
    assert_eq!(b.status_of(&t), Some("triage"), "same-kind re-block escalates");
    assert!(b.events_for(&t).iter().any(|e| e.kind == "block_loop_detected"));
    // dependency with no open parent becomes needs_input.
    let u = create_task(&mut b, nt("u")).unwrap();
    claim_ready(&mut b, &u);
    block(&mut b, &u, Some("wait"), Some("dependency"), None).unwrap();
    assert_eq!(b.task(&u).unwrap().block_kind.as_deref(), Some("needs_input"));
    // dependency with an open parent parks in todo and auto-resumes.
    let p = create_task(&mut b, nt("p")).unwrap();
    let w = create_task(&mut b, nt("w")).unwrap();
    let wr = claim_ready(&mut b, &w);
    link(&mut b, &p, &w, Some(wr)).unwrap();
    block(&mut b, &w, Some("needs p"), Some("dependency"), Some(wr)).unwrap();
    assert_eq!(b.status_of(&w), Some("todo"));
    assert!(block(&mut b, &w, None, Some("bogus"), None).is_err());
    // Classify an untyped breaker block in place.
    let x = create_task(&mut b, nt("x")).unwrap();
    b.task_mut(&x).unwrap().status = "blocked".into();
    assert!(block(&mut b, &x, Some("why"), Some("capability"), None).unwrap());
    assert_eq!(b.status_of(&x), Some("blocked"));
    assert!(!block(&mut b, &x, Some("again"), Some("capability"), None).unwrap(), "typed blocks are not re-typed");
    // schedule + unblock
    let s = create_task(&mut b, nt("s")).unwrap();
    assert!(schedule(&mut b, &s, Some("SCHEDULED_UNTIL=2030-01-01"), None));
    assert_eq!(b.status_of(&s), Some("scheduled"));
    assert!(unblock(&mut b, &s));
    assert_eq!(b.status_of(&s), Some("ready"));
}

#[test]
fn review_cycle_routes_back_to_implementer() {
    let d = crate::kanban::testutil::data();
    let mut b = BoardData::default();
    let t = create_task(&mut b, nt("feature")).unwrap();
    claim_ready(&mut b, &t);
    request_review(&mut b, &d, "default", &t, ReviewRequest { summary: Some("done, tests pass".into()), reviewer: Some("Reviewer".into()), ..Default::default() }).unwrap();
    assert_eq!(b.status_of(&t), Some("review"));
    assert_eq!(b.task(&t).unwrap().assignee.as_deref(), Some("reviewer"));
    let rr = claim(&mut b, &t, ClaimOpts { lock: "h", ttl: 60, lane: "review", owner: None, token: None }).unwrap();
    assert_eq!(b.run(rr).unwrap().source_status, "review");
    assert_eq!(request_changes(&mut b, &t, "add docs", Some(rr)).unwrap(), "dev");
    assert_eq!(b.status_of(&t), Some("ready"));
    assert_eq!(b.task(&t).unwrap().assignee.as_deref(), Some("dev"));
    claim_ready(&mut b, &t);
    request_review(&mut b, &d, "default", &t, ReviewRequest { summary: Some("docs added".into()), ..Default::default() }).unwrap();
    assert_eq!(b.task(&t).unwrap().assignee.as_deref(), Some("reviewer"), "re-review defaults to the prior reviewer");
    assert!(request_changes(&mut b, &t, "x", None).unwrap_err().contains("active review run"));
    assert!(reopen_review(&mut b, &t));
    assert_eq!(b.task(&t).unwrap().assignee.as_deref(), Some("dev"));
    assert!(request_review(&mut b, &d, "default", &t, ReviewRequest { summary: Some("x".into()), claim_live: true, ..Default::default() }).is_ok(), "ready (unclaimed) is fine");
}

#[test]
fn breaker_promote_reclaim_assign_edit_archive() {
    let d = crate::kanban::testutil::data();
    let mut b = BoardData::default();
    let t = create_task(&mut b, nt("t")).unwrap();
    claim_ready(&mut b, &t);
    assert!(!record_failure(&mut b, &t, Failure { error: "boom", outcome: "spawn_failed", release_claim: true, end_run: true, ..Default::default() }, 2));
    assert_eq!(b.status_of(&t), Some("ready"));
    claim_ready(&mut b, &t);
    assert!(record_failure(&mut b, &t, Failure { error: "boom", outcome: "spawn_failed", release_claim: true, end_run: true, ..Default::default() }, 2));
    assert_eq!(b.status_of(&t), Some("blocked"));
    assert_eq!(recompute_ready(&mut b, 2), 0, "at the breaker limit");
    assert_eq!(recompute_ready(&mut b, 5), 1, "raising the limit releases it");
    // forced trips are sticky regardless of limit
    claim_ready(&mut b, &t);
    record_failure(&mut b, &t, Failure { error: "pv", outcome: "crashed", force_trip: true, release_claim: true, ..Default::default() }, 9);
    assert_eq!(recompute_ready(&mut b, 99), 0);
    assert!(promote(&mut b, &t, "op", Some("fixed"), true).is_ok());
    promote(&mut b, &t, "op", None, false).unwrap();
    assert_eq!(b.status_of(&t), Some("ready"));
    assert!(promote(&mut b, &t, "op", None, false).is_err(), "only todo/blocked");
    let rid = claim_ready(&mut b, &t);
    assert!(assign(&mut b, &t, Some("other")).is_err(), "running is refused");
    assert_eq!(reclaim(&mut b, &t, Some("stuck")), Some(None));
    assert_eq!(b.run(rid).unwrap().outcome.as_deref(), Some("reclaimed"));
    assert!(assign(&mut b, &t, Some("Other")).unwrap());
    assert_eq!(b.task(&t).unwrap().assignee.as_deref(), Some("other"));
    assert!(edit(&mut b, &t, Edit { title: Some("renamed".into()), priority: Some(5), ..Default::default() }));
    assert!(!edit(&mut b, &t, Edit { result: Some("x".into()), ..Default::default() }), "result only on done");
    assert_eq!(archive(&mut b, &d, "default", &t, 2).unwrap(), None);
    assert!(delete_archived(&mut b, &d, "default", &t));
    assert!(b.task(&t).is_none());
}

#[test]
fn decompose_specify_invalidate_and_move() {
    let d = crate::kanban::testutil::data();
    let mut b = BoardData::default();
    let root = create_task(&mut b, NewTask { triage: true, ..nt("big idea") }).unwrap();
    let kids = vec![Child { title: "a".into(), assignee: Some("r".into()), ..Default::default() }, Child { title: "b".into(), parents: vec![0], ..Default::default() }];
    assert!(decompose_triage(&mut b, &root, Some("orch"), &[Child { title: "x".into(), parents: vec![0], ..Default::default() }], None, true, 2).is_err(), "self parent");
    assert!(decompose_triage(&mut b, &root, Some("orch"), &[Child { title: "x".into(), parents: vec![1], ..Default::default() }, Child { title: "y".into(), parents: vec![0], ..Default::default() }], None, true, 2).unwrap_err().contains("cyclic"));
    let ids = decompose_triage(&mut b, &root, Some("orch"), &kids, Some("decomposer"), true, 2).unwrap().unwrap();
    assert_eq!(b.status_of(&ids[0]), Some("ready"));
    assert_eq!(b.status_of(&ids[1]), Some("todo"));
    assert_eq!(b.status_of(&root), Some("todo"));
    assert_eq!(b.task(&root).unwrap().assignee.as_deref(), Some("orch"));
    assert_eq!(b.parent_ids(&root).len(), 2, "root waits for every child");
    assert!(decompose_triage(&mut b, &root, None, &kids, None, true, 2).unwrap().is_none(), "already decomposed");
    let s = create_task(&mut b, NewTask { triage: true, ..nt("vague") }).unwrap();
    assert!(specify_triage(&mut b, &s, Some("Clear title"), Some("**Goal** x"), None, Some("spec"), 2).unwrap());
    assert_eq!(b.status_of(&s), Some("ready"));
    assert!(b.comments_for(&s)[0].body.contains("updated title, body"));
    // Done reopen invalidates descendants.
    let a = create_task(&mut b, nt("a")).unwrap();
    let c = create_task(&mut b, NewTask { parents: vec![a.clone()], ..nt("c") }).unwrap();
    complete(&mut b, &d, "default", &a, Completion { summary: Some("ok".into()), ..Default::default() }, 2).unwrap();
    complete(&mut b, &d, "default", &c, Completion { summary: Some("ok".into()), ..Default::default() }, 2).unwrap();
    move_task(&mut b, &d, "default", &a, "todo", "op", 2).unwrap();
    assert_eq!(b.status_of(&c), Some("todo"));
    assert!(b.events_for(&c).iter().any(|e| e.kind == "descendant_invalidated"));
    assert!(move_task(&mut b, &d, "default", &a, "running", "op", 2).is_err());
    move_task(&mut b, &d, "default", &a, "archived", "op", 2).unwrap();
    move_task(&mut b, &d, "default", &a, "todo", "op", 2).unwrap();
    assert_eq!(b.status_of(&a), Some("todo"));
}

#[test]
fn attachments_names_caps_and_redaction() {
    let d = crate::kanban::testutil::data();
    let mut b = BoardData::default();
    let t = create_task(&mut b, nt("t")).unwrap();
    assert_eq!(safe_attachment_name("../../etc/.passwd").unwrap(), "passwd");
    assert!(safe_attachment_name("...").is_err());
    let a1 = store_attachment(&mut b, &d, "default", &t, "r.pdf", b"x", None, Some("agent"), None).unwrap();
    let a2 = store_attachment(&mut b, &d, "default", &t, "r.pdf", b"y", None, None, None).unwrap();
    assert!(b.attachments.iter().find(|a| a.id == a2).unwrap().filename == "r (1).pdf");
    assert_eq!(b.attachments.iter().find(|a| a.id == a1).unwrap().content_type.as_deref(), Some("application/pdf"));
    assert!(store_attachment(&mut b, &d, "default", "t_none", "a", b"x", None, None, None).is_err());
    assert!(delete_attachment(&mut b, a1).is_some());
    assert!(redact("token sk-ant-abcdefghijklmnopqrstuvwx and ghp_abcdefghijklmnopqrstuvwxyz0123456789").matches("[REDACTED]").count() == 2);
    // Artifacts declared inside the scratch workspace are staged into attachments.
    let ws = crate::kanban::workspaces_root(&d, "default").join(&t);
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("chart.png"), b"png").unwrap();
    b.task_mut(&t).unwrap().workspace_path = Some(ws.display().to_string());
    let missing = complete(&mut b, &d, "default", &t, Completion { summary: Some("s".into()), metadata: Some(json!({"artifacts": [ws.join("nope.png").display().to_string()]})), ..Default::default() }, 2);
    assert!(matches!(missing, Err(Refusal::Artifact(_))));
    assert_eq!(b.status_of(&t), Some("ready"), "still in flight");
    complete(&mut b, &d, "default", &t, Completion { summary: Some("s".into()), metadata: Some(json!({"artifacts": [ws.join("chart.png").display().to_string()]})), ..Default::default() }, 2).unwrap();
    assert!(b.attachments.iter().any(|a| a.filename == "chart.png" && std::path::Path::new(&a.stored_path).exists()));
    assert!(!ws.exists(), "scratch workspace cleaned up after completion");
    let st = stats(&b);
    assert_eq!(st["by_status"]["done"], 1);
}
