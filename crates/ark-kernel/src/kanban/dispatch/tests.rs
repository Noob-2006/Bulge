//! Dispatcher behaviour: a tick claims ready (and review) cards, spawns one worker per
//! card with the worker tool subset bound to that session, and books every way a worker
//! can end (clean exit without a terminal call, crash, lost session, repeated failures).
//! Everything runs against a real board document on disk; workers are either recorded
//! (`RecordingSpawner`) or real kernel sessions driven by the testutil scripted model.

use super::*;
use crate::kanban::ops::{self, Completion, NewTask};
use crate::kanban::{boards, testutil, KanbanProfile};

fn cfg() -> KanbanConfig {
    // `crash_grace_secs: 0` so a tick judges a vanished session immediately (no sleeping).
    KanbanConfig { enabled: true, dispatch: true, failure_limit: 2, crash_grace_secs: 0, ..Default::default() }
}

fn board(slug: &str) -> (std::path::PathBuf, String) {
    let d = testutil::data();
    boards::create_board(&d, slug, Default::default()).unwrap();
    (d, slug.into())
}

fn task(d: &Path, slug: &str, n: NewTask) -> String {
    store::with_board(d, slug, |b| ops::create_task(b, n)).unwrap()
}

fn ready(d: &Path, slug: &str, title: &str, assignee: Option<&str>) -> String {
    task(d, slug, NewTask { title: title.into(), assignee: assignee.map(String::from), ..Default::default() })
}

fn status(d: &Path, slug: &str, id: &str) -> String {
    store::read_board(d, slug).unwrap().status_of(id).unwrap_or_default().to_string()
}

fn set_status(d: &Path, slug: &str, id: &str, st: &str) {
    store::with_board(d, slug, |b| {
        b.task_mut(id).unwrap().status = st.into();
        Ok(())
    })
    .unwrap();
}

/// A card that really finished (the dispatcher-side view of `kanban_complete`).
fn finish_card(d: &Path, slug: &str, id: &str) {
    store::with_board(d, slug, |b| ops::complete(b, d, slug, id, Completion { summary: Some("done".into()), force: true, ..Default::default() }, 2).map_err(|e| format!("{e:?}"))).unwrap();
}

fn tick(d: &Path, slug: &str, c: &KanbanConfig, sp: &dyn Spawner, o: &TickOpts) -> DispatchResult {
    tick_board(d, slug, c, sp, o).unwrap()
}

fn session_of(d: &Path, slug: &str, id: &str) -> String {
    let b = store::read_board(d, slug).unwrap();
    let t = b.task(id).unwrap();
    b.run(t.current_run_id.unwrap()).and_then(|r| r.worker_session.clone()).expect("the spawned run names its worker session")
}

fn events(d: &Path, slug: &str, id: &str, kind: &str) -> usize {
    store::read_board(d, slug).unwrap().events_for(id).iter().filter(|e| e.kind == kind).count()
}

fn wait_for(f: impl Fn() -> bool) -> bool {
    for _ in 0..300 {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// `ark pause` (`<data>/ESTOP`) is the same sentinel the scheduler, cron and channel turns
/// honour: a tick must start nothing while it exists, and say so; removing it restores the
/// old behaviour.
#[test]
fn the_emergency_stop_holds_every_board() {
    let (k, _, _) = testutil::kernel(|c| c.kanban.enabled = true);
    let d = k.paths.data.clone();
    boards::create_board(&d, "default", Default::default()).unwrap();
    let id = ready(&d, "default", "paused work", Some("worker"));
    let c = cfg();

    ark_security::estop::engage(&d, Some("maintenance")).unwrap();
    let out = tick_all(&k, &c, &TickOpts::default());
    assert_eq!(out.len(), 1, "one paused outcome, not one per board");
    let r = &out[0];
    assert!(r.paused.as_deref().is_some_and(|m| m.contains("maintenance") && m.contains("ark resume")), "{:?}", r.paused);
    assert!(r.spawned.is_empty() && !r.skipped_locked && r.promoted == 0 && r.reclaimed.is_empty());
    // The JSON (`ark kanban dispatch`, the control UI, `workboard_dispatch`) carries the reason,
    // so a caller that renders the result itself cannot report a successful empty pass either.
    let v = serde_json::to_value(r).unwrap();
    assert!(v["paused"].as_str().is_some_and(|m| m.contains("maintenance")), "{v}");
    let b = store::read_board(&d, "default").unwrap();
    assert_eq!(b.status_of(&id), Some("ready"), "the card was not claimed");
    assert!(b.runs_for(&id).is_empty(), "no worker run was recorded");

    // The per-board entry point (CLI / control UI) honours it too.
    let sp = RecordingSpawner::default();
    let one = tick(&d, "default", &c, &sp, &TickOpts::default());
    assert!(one.paused.is_some() && one.spawned.is_empty());
    assert!(sp.jobs.lock().unwrap().is_empty(), "the spawner was never called");

    // `ark resume`: the very same tick dispatches again (dry run: bookkeeping only).
    assert!(ark_security::estop::disengage(&d));
    let out = tick_all(&k, &c, &TickOpts { dry_run: true, ..Default::default() });
    assert_eq!((out.len(), out[0].board.as_str(), out[0].paused.as_deref()), (1, "default", None));
    assert_eq!(out[0].spawned.len(), 1, "the ready card is dispatched again");
}

#[test]
fn a_tick_claims_ready_cards_and_spawns_one_worker_each() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { max_spawn: Some(2), ..cfg() };
    let low = task(&d, &slug, NewTask { title: "low".into(), assignee: Some("alice".into()), ..Default::default() });
    let high = task(&d, &slug, NewTask { title: "high".into(), assignee: Some("alice".into()), priority: 5, ..Default::default() });
    let last = ready(&d, &slug, "overflow", Some("alice"));

    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());

    assert_eq!(res.board, "proj");
    // Priority wins the free slots; the third card waits in ready.
    assert_eq!(res.spawned.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(), vec![high.clone(), low.clone()]);
    assert_eq!(status(&d, &slug, &last), "ready");
    assert_eq!(status(&d, &slug, &high), "running");

    let jobs = sp.jobs.lock().unwrap().clone();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].task.id, high);
    assert_eq!(jobs[0].lane, "ready");
    assert_eq!(jobs[0].task.assignee.as_deref(), Some("alice"));
    assert!(jobs[0].workspace.starts_with(d.join("kanban/boards/proj/workspaces")), "scratch workspace lives under the board: {}", jobs[0].workspace.display());
    assert!(jobs[0].workspace.is_dir());

    // Durable claim + run so a restarted daemon recovers it instead of duplicating work.
    let b = store::read_board(&d, &slug).unwrap();
    let t = b.task(&high).unwrap();
    assert!(t.claim_lock.as_deref().unwrap().starts_with(&host_prefix()));
    assert!(t.current_run_id.is_some());
    let run = b.run(t.current_run_id.unwrap()).unwrap();
    assert_eq!(run.owner_pid, Some(std::process::id()));
    assert_eq!(run.worker_session.as_deref(), Some(format!("sess-{high}-{}", run.id).as_str()));
    assert_eq!(run.source_status, "ready");
    assert_eq!(events(&d, &slug, &high, "claimed"), 1);
    assert_eq!(events(&d, &slug, &high, "spawned"), 1);
}

#[test]
fn spawned_worker_gets_the_worker_tool_subset_and_loses_it_when_finished() {
    let (k, p, _ws) = testutil::session_kernel(|_| {});
    let d = k.paths.data.clone();
    // The board the worker is bound to is also the board the `kanban_*` tools resolve.
    boards::create_board(&d, "default", Default::default()).unwrap();
    let id = ready(&d, "default", "write docs", Some("alice"));
    // The worker behaves: one terminal board call, then a plain answer.
    p.call("kanban_complete", serde_json::json!({"summary": "docs written and linked"}));
    p.text("done");

    let res = tick(&d, "default", &cfg(), &KernelSpawner { k: k.clone() }, &TickOpts::default());
    assert_eq!(res.spawned.len(), 1, "{res:?}");
    assert!(
        wait_for(|| status(&d, "default", &id) == "done"),
        "the worker never completed the card (status {}): {:#?}",
        status(&d, "default", &id),
        p.seen.lock().unwrap().iter().map(|r| r.messages.iter().map(|m| format!("{:?}", m.content)).collect::<Vec<_>>()).collect::<Vec<_>>()
    );

    // The first model request of the worker session carries exactly the worker subset:
    // mutating kanban tools + the OpenClaw workboard worker tools, no board routing.
    let first = p.seen.lock().unwrap()[0].tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    for want in ["kanban_show", "kanban_complete", "kanban_block", "kanban_heartbeat", "kanban_comment", "kanban_request_review", "workboard_read", "workboard_heartbeat", "workboard_complete", "workboard_block"] {
        assert!(first.contains(&want.to_string()), "worker session is missing {want}: {first:?}");
    }
    for banned in ["kanban_list", "workboard_reassign", "workboard_board_delete"] {
        assert!(!first.contains(&banned.to_string()), "worker session must not get {banned}: {first:?}");
    }
    let prompt: String = p.seen.lock().unwrap()[0].messages[0].content.iter().filter_map(|b| match b { ark_core::Block::Text { text } => Some(text.as_str()), _ => None }).collect();
    assert!(prompt.contains("Kanban task execution protocol") && prompt.contains("write docs"), "the worker prompt is missing: {prompt}");
    // The terminal call settled the run; the dispatcher books nothing on exit.
    let b = store::read_board(&d, "default").unwrap();
    assert_eq!(b.runs_for(&id).iter().filter(|r| r.outcome.as_deref() == Some("completed")).count(), 1);
    // The worker log names the session so `ark kanban log` shows what happened.
    let log = std::fs::read_to_string(crate::kanban::worker_log_path(&d, "default", &id)).unwrap();
    assert!(log.contains(&format!("run {} started: session", 1)) && log.contains("(ready)"), "{log}");
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 0);

    // Cleanup: the very same session, run again, no longer carries the board tools.
    let sid = k.store.list().into_iter().find(|s| s.title.as_deref().is_some_and(|t| t.starts_with(&format!("kanban {id}:")))).expect("the worker session is on disk").id;
    assert!(wait_for(|| !k.is_running(&sid)), "the worker session never stopped");
    std::thread::sleep(std::time::Duration::from_millis(300));
    p.text("nothing left to do");
    k.submit(&sid, "again", "cli").unwrap();
    k.run(&sid, RunOpts::default()).unwrap();
    let last = p.seen.lock().unwrap().last().unwrap().tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    assert!(!last.iter().any(|n| n.starts_with("kanban_") || n.starts_with("workboard_")), "worker tools outlived the run: {last:?}");
}

#[test]
fn board_cap_bounds_parallel_workers_and_completion_frees_a_slot() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { max_spawn: Some(1), ..cfg() };
    let a = ready(&d, &slug, "first", Some("alice"));
    let b = ready(&d, &slug, "second", Some("alice"));

    let sp = RecordingSpawner::default();
    let r1 = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(r1.spawned.len(), 1, "max_spawn=1");
    let r2 = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert!(r2.spawned.is_empty(), "a full board claims nothing: {r2:?}");
    assert_eq!(sp.jobs.lock().unwrap().len(), 1);

    // The running card completes (the worker called kanban_complete) → the slot is free.
    let running = r1.spawned[0].0.clone();
    let other = if running == a { b.clone() } else { a.clone() };
    finish_card(&d, &slug, &running);
    let r3 = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(r3.spawned.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(), vec![other.clone()]);
    assert_eq!(status(&d, &slug, &other), "running");
}

#[test]
fn host_wide_cap_counts_every_board() {
    let (d, alpha) = board("alpha");
    boards::create_board(&d, "beta", Default::default()).unwrap();
    let beta = "beta".to_string();
    let c = KanbanConfig { max_in_progress: Some(1), ..cfg() };
    let ta = ready(&d, &alpha, "alpha card", Some("alice"));
    let tb = ready(&d, &beta, "beta card", Some("alice"));

    let sp = RecordingSpawner::default();
    assert_eq!(tick(&d, &alpha, &c, &sp, &TickOpts::default()).spawned.len(), 1);
    let blocked = tick(&d, &beta, &c, &sp, &TickOpts::default());
    assert!(blocked.spawned.is_empty(), "host-wide cap is shared across boards: {blocked:?}");
    assert_eq!(status(&d, &beta, &tb), "ready");
    assert_eq!(status(&d, &alpha, &ta), "running");

    finish_card(&d, &alpha, &ta);
    assert_eq!(tick(&d, &beta, &c, &sp, &TickOpts::default()).spawned.len(), 1, "the freed host slot goes to the other board");
}

#[test]
fn refused_spawns_trip_the_breaker_at_the_failure_limit() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { failure_limit: 2, ..cfg() };
    let id = ready(&d, &slug, "needs a worker", Some("alice"));

    let sp = RecordingSpawner::default();
    *sp.fail.lock().unwrap() = Some("provider down".into());
    let r1 = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(r1.spawn_failed.len(), 1, "{r1:?}");
    assert_eq!(r1.spawn_failed[0].0, id);
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.task(&id).unwrap().status, "ready", "a refused spawn releases the claim");
    assert!(b.task(&id).unwrap().claim_lock.is_none());
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 1);
    assert_eq!(events(&d, &slug, &id, "spawn_failed"), 1);

    let r2 = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(r2.auto_blocked, vec![id.clone()], "{r2:?}");
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.task(&id).unwrap().status, "blocked");
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 2);
    assert!(b.task(&id).unwrap().last_failure_error.as_deref().unwrap().contains("provider down"));
    assert_eq!(events(&d, &slug, &id, "gave_up"), 1);
    // A blocked card is not dispatched again.
    assert!(tick(&d, &slug, &c, &sp, &TickOpts::default()).spawned.is_empty());
}

#[test]
fn blocked_triage_and_dependency_waiting_cards_are_not_dispatched() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { max_spawn: Some(4), ..cfg() };
    let parent = ready(&d, &slug, "parent", Some("alice"));
    let child = task(&d, &slug, NewTask { title: "child".into(), assignee: Some("alice".into()), parents: vec![parent.clone()], ..Default::default() });
    let blocked = ready(&d, &slug, "needs a human", Some("alice"));
    store::with_board(&d, &slug, |b| ops::block(b, &blocked, Some("waiting for credentials"), Some("needs_input"), None)).unwrap();
    let triage = task(&d, &slug, NewTask { title: "rough idea".into(), assignee: Some("alice".into()), triage: true, ..Default::default() });

    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(), vec![parent.clone()], "only the ready card runs: {res:?}");
    assert_eq!(status(&d, &slug, &child), "todo", "a card with an open parent waits");
    assert_eq!(status(&d, &slug, &blocked), "blocked");
    assert_eq!(status(&d, &slug, &triage), "triage");

    // Finishing the parent releases the dependency and the child is dispatched next tick.
    finish_card(&d, &slug, &parent);
    assert_eq!(status(&d, &slug, &child), "ready", "finishing the parent promotes the child");
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(), vec![child.clone()]);
    assert_eq!(status(&d, &slug, &blocked), "blocked", "a sticky human block is never auto-promoted");
}

#[test]
fn a_clean_exit_without_a_terminal_call_is_a_protocol_violation() {
    let (d, slug) = board("proj");
    let c = cfg();
    let id = ready(&d, &slug, "forgetful worker", Some("alice"));
    let sp = RecordingSpawner::default();

    for attempt in 1..=PROTOCOL_VIOLATION_LIMIT {
        let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
        assert_eq!(res.spawned.len(), 1, "attempt {attempt}: {res:?}");
        let run = store::read_board(&d, &slug).unwrap().task(&id).unwrap().current_run_id.unwrap();
        let sess = session_of(&d, &slug, &id);
        sp.finish(&sess);
        on_worker_exit(&d, &c, &slug, &id, run, Exit::Clean("I looked around and stopped".into())).unwrap();
        let b = store::read_board(&d, &slug).unwrap();
        let r = b.run(run).unwrap();
        assert_eq!(r.outcome.as_deref(), Some("crashed"));
        assert_eq!(r.metadata.as_ref().unwrap()["protocol_violation"], true);
        assert!(r.error.as_deref().unwrap().contains("without kanban_complete"), "the worker is told what it did wrong: {:?}", r.error);
        assert!(b.task(&id).unwrap().last_failure_error.as_deref().unwrap().contains("I looked around and stopped"), "the last output is kept for triage");
        // The protocol streak lives on the runs (`protocol_violations`), not the retry counter,
        // so a worker that merely forgot to report does not eat the failure budget.
        if attempt < PROTOCOL_VIOLATION_LIMIT {
            assert_eq!(b.status_of(&id), Some("ready"), "below the streak limit the card is retried");
            assert_eq!(events(&d, &slug, &id, "gave_up"), 0, "no breaker trip before the streak limit");
        }
    }
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.status_of(&id), Some("blocked"), "a worker that never reports back is parked after {PROTOCOL_VIOLATION_LIMIT} streaks");
    let gave_up = b.events_for(&id).into_iter().find(|e| e.kind == "gave_up").unwrap();
    assert_eq!(gave_up.payload.as_ref().unwrap()["protocol_violations"], PROTOCOL_VIOLATION_LIMIT);
    assert_eq!(events(&d, &slug, &id, "protocol_violation"), PROTOCOL_VIOLATION_LIMIT as usize);
}

#[test]
fn a_worker_crash_counts_against_the_failure_limit() {
    let (d, slug) = board("proj");
    let c = cfg();
    let id = ready(&d, &slug, "crashing worker", Some("alice"));
    let sp = RecordingSpawner::default();

    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.len(), 1);
    let run = store::read_board(&d, &slug).unwrap().task(&id).unwrap().current_run_id.unwrap();
    let sess = session_of(&d, &slug, &id);
    sp.finish(&sess);
    on_worker_exit(&d, &c, &slug, &id, run, Exit::Failed("model exploded".into())).unwrap();
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.status_of(&id), Some("ready"));
    assert_eq!(b.run(run).unwrap().outcome.as_deref(), Some("crashed"));
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 1);
    assert!(b.task(&id).unwrap().last_failure_error.as_deref().unwrap().contains("model exploded"));

    // A provider that rejects the credential can never be healed by retrying.
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.len(), 1);
    let run = store::read_board(&d, &slug).unwrap().task(&id).unwrap().current_run_id.unwrap();
    let sess = session_of(&d, &slug, &id);
    sp.finish(&sess);
    on_worker_exit(&d, &c, &slug, &id, run, Exit::TerminalProvider("401 invalid api key".into())).unwrap();
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.status_of(&id), Some("blocked"), "an auth wall parks the card immediately");
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 2);
    assert_eq!(events(&d, &slug, &id, "gave_up"), 1);

    // Rate limits requeue without eating a retry.
    let id2 = ready(&d, &slug, "rate limited", Some("alice"));
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.iter().map(|(i, _, _)| i.clone()).collect::<Vec<_>>(), vec![id2.clone()]);
    let run = store::read_board(&d, &slug).unwrap().task(&id2).unwrap().current_run_id.unwrap();
    let sess = session_of(&d, &slug, &id2);
    sp.finish(&sess);
    on_worker_exit(&d, &c, &slug, &id2, run, Exit::RateLimited("429 quota".into())).unwrap();
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.status_of(&id2), Some("ready"));
    assert_eq!(b.task(&id2).unwrap().consecutive_failures, 0, "a quota wall is not the worker's fault");
    assert_eq!(b.runs_for(&id2).iter().filter(|r| r.outcome.as_deref() == Some("rate_limited")).count(), 1);
}

#[test]
fn the_dispatcher_reclaims_a_run_whose_session_vanished() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { failure_limit: 2, ..cfg() };
    let id = ready(&d, &slug, "vanishing worker", Some("alice"));
    let sp = RecordingSpawner::default();

    assert_eq!(tick(&d, &slug, &c, &sp, &TickOpts::default()).spawned.len(), 1);
    let run1 = store::read_board(&d, &slug).unwrap().task(&id).unwrap().current_run_id.unwrap();
    let first = session_of(&d, &slug, &id);
    sp.finish(&first); // the session disappears without an exit report

    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.crashed, vec![id.clone()], "{res:?}");
    assert_eq!(res.spawned.iter().map(|(i, _, _)| i.clone()).collect::<Vec<_>>(), vec![id.clone()], "a crashed card is retried in the same tick");
    let b = store::read_board(&d, &slug).unwrap();
    let crashed_run = b.run(run1).unwrap();
    assert_eq!(crashed_run.outcome.as_deref(), Some("crashed"));
    assert!(crashed_run.error.as_deref().unwrap().contains("no longer running"), "{:?}", crashed_run.error);
    assert_eq!(b.task(&id).unwrap().consecutive_failures, 1);

    // Second loss: the breaker trips and nothing is spawned.
    let second = session_of(&d, &slug, &id);
    assert_ne!(first, second);
    sp.finish(&second);
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.crashed, vec![id.clone()]);
    assert_eq!(res.auto_blocked, vec![id.clone()], "{res:?}");
    assert!(res.spawned.is_empty());
    assert_eq!(status(&d, &slug, &id), "blocked");
}

#[test]
fn review_lane_dispatches_a_reviewer_and_never_starves() {
    let (d, slug) = board("proj");
    let c = KanbanConfig { max_spawn: Some(1), ..cfg() };
    let review = ready(&d, &slug, "please review the docs", Some("reviewer"));
    set_status(&d, &slug, &review, "review");
    let fresh = ready(&d, &slug, "brand new work", Some("alice"));

    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    assert_eq!(res.spawned.iter().map(|(i, _, _)| i.clone()).collect::<Vec<_>>(), vec![review.clone()], "one slot is reserved for a waiting reviewer: {res:?}");
    let job = sp.jobs.lock().unwrap()[0].clone();
    assert_eq!(job.lane, "review");
    assert_eq!(job.task.id, review);
    let prompt = worker_prompt(&store::read_board(&d, &slug).unwrap(), &c, &job.task, &job.lane);
    assert!(prompt.contains("You are the REVIEWER for this task"), "{prompt}");
    assert!(prompt.contains("kanban_request_changes"), "a reviewer is told how to return rework");
    assert!(prompt.contains(&review), "the worker prompt carries the task context");
    // The plain ready card is untouched this tick.
    assert_eq!(status(&d, &slug, &fresh), "ready");
}

#[test]
fn a_tick_only_touches_its_own_board() {
    let (d, slug) = board("alpha");
    boards::create_board(&d, "beta", Default::default()).unwrap();
    let ta = ready(&d, &slug, "alpha card", Some("alice"));
    let tb = ready(&d, "beta", "beta card", Some("alice"));

    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &cfg(), &sp, &TickOpts::default());
    assert_eq!(res.board, "alpha");
    assert_eq!(res.spawned.iter().map(|(i, _, _)| i.clone()).collect::<Vec<_>>(), vec![ta.clone()]);
    assert_eq!(status(&d, "beta", &tb), "ready", "the other board is untouched");
    assert!(sp.jobs.lock().unwrap().iter().all(|j| j.slug == "alpha"));

    let res = tick(&d, "beta", &cfg(), &sp, &TickOpts::default());
    assert_eq!(res.board, "beta");
    assert_eq!(res.spawned.len(), 1);
    // Boards are separate namespaces: ids, tenants and runs never cross over.
    let b = store::read_board(&d, "beta").unwrap();
    assert_eq!(b.tasks.len(), 1);
    assert!(b.task(&ta).is_none());
}

#[test]
fn assignee_routing_respects_profiles_defaults_and_per_profile_caps() {
    let (d, slug) = board("proj");
    let mut profiles = std::collections::BTreeMap::new();
    profiles.insert("alice".to_string(), KanbanProfile::default());
    profiles.insert("bob".to_string(), KanbanProfile::default());
    let c = KanbanConfig { default_assignee: "alice".into(), max_in_progress_per_profile: Some(1), profiles, ..cfg() };

    let unassigned = ready(&d, &slug, "nobody picked this", None);
    let ghost = ready(&d, &slug, "assigned to a ghost", Some("nobody-home"));
    let a1 = ready(&d, &slug, "alice one", Some("alice"));
    let a2 = ready(&d, &slug, "alice two", Some("alice"));
    let tenant = task(&d, &slug, NewTask { title: "tenant card".into(), assignee: Some("bob".into()), tenant: Some("acme".into()), ..Default::default() });

    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &c, &sp, &TickOpts::default());
    let spawned: Vec<String> = res.spawned.iter().map(|(i, _, _)| i.clone()).collect();
    assert!(spawned.contains(&unassigned), "the default assignee adopts unassigned cards: {res:?}");
    assert!(res.auto_assigned_default.contains(&unassigned));
    assert_eq!(store::read_board(&d, &slug).unwrap().task(&unassigned).unwrap().assignee.as_deref(), Some("alice"));
    assert_eq!(res.skipped_nonspawnable, vec![ghost.clone()], "a profile that does not exist cannot run");
    assert_eq!(status(&d, &slug, &ghost), "ready");
    assert_eq!(events(&d, &slug, &ghost, "skipped_nonspawnable"), 1);
    assert!(spawned.contains(&tenant), "the last profile slot goes to bob");
    assert!(res.skipped_per_profile_capped.contains(&a1) && res.skipped_per_profile_capped.contains(&a2), "alice is capped at one worker and the adopted card holds it: {res:?}");
    assert_eq!(spawned.iter().filter(|i| [&a1, &a2].contains(i)).count(), 0);
    // The tenant travels with the card into the job.
    let job = sp.jobs.lock().unwrap().iter().find(|j| j.task.id == tenant).cloned().unwrap();
    assert_eq!(job.task.tenant.as_deref(), Some("acme"));
}

#[test]
fn dry_run_reports_what_would_spawn_and_claims_nothing() {
    let (d, slug) = board("proj");
    let id = ready(&d, &slug, "would run", Some("alice"));
    let sp = RecordingSpawner::default();
    let res = tick(&d, &slug, &cfg(), &sp, &TickOpts { dry_run: true, ..Default::default() });
    assert_eq!(res.spawned.iter().map(|(i, a, ws)| (i.clone(), a.clone(), ws.clone())).collect::<Vec<_>>(), vec![(id.clone(), "alice".to_string(), String::new())]);
    assert!(sp.jobs.lock().unwrap().is_empty(), "a dry run starts no worker");
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.status_of(&id), Some("ready"));
    assert!(b.task(&id).unwrap().claim_lock.is_none());
    assert!(b.runs_for(&id).is_empty());

    // `no_spawn` (OpenClaw `workboard_dispatch`) advances data only.
    let res = tick(&d, &slug, &cfg(), &sp, &TickOpts { no_spawn: true, ..Default::default() });
    assert!(res.spawned.is_empty() && sp.jobs.lock().unwrap().is_empty());
}

#[test]
fn arkd_daemon_tick_is_gated_and_runs_the_card_when_enabled() {
    // Off: the scheduler hook returns before touching the board.
    let (off, _, _) = testutil::session_kernel(|c| c.kanban.enabled = false);
    boards::create_board(&off.paths.data, "default", Default::default()).unwrap();
    let id = ready(&off.paths.data, "default", "should not move", Some("alice"));
    daemon_tick(&off);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(status(&off.paths.data, "default", &id), "ready", "kanban disabled ⇒ no dispatch");

    // Enabled but dispatch off: still nothing.
    let (idle, _, _) = testutil::session_kernel(|c| {
        c.kanban.enabled = true;
        c.kanban.dispatch = false;
    });
    boards::create_board(&idle.paths.data, "default", Default::default()).unwrap();
    let id2 = ready(&idle.paths.data, "default", "dispatch off", Some("alice"));
    daemon_tick(&idle);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(status(&idle.paths.data, "default", &id2), "ready", "dispatch=false ⇒ no dispatch");

    // Enabled: the daemon tick claims the card and a real worker session completes it.
    let (k, p, _ws) = testutil::session_kernel(|c| {
        c.kanban.enabled = true;
        c.kanban.dispatch = true;
        c.kanban.max_spawn = Some(1);
        c.kanban.dispatch_interval_secs = 1;
        c.kanban.crash_grace_secs = 0;
    });
    let d = k.paths.data.clone();
    boards::create_board(&d, "default", Default::default()).unwrap();
    let live = ready(&d, "default", "daemon work", Some("alice"));
    p.call("kanban_complete", serde_json::json!({"summary": "handled by arkd"}));
    p.text("done");
    daemon_tick(&k);
    assert!(wait_for(|| status(&d, "default", &live) == "done"), "the daemon tick never ran the card (status {})", status(&d, "default", &live));
    let b = store::read_board(&d, "default").unwrap();
    assert_eq!(b.runs_for(&live).iter().filter(|r| r.outcome.as_deref() == Some("completed")).count(), 1);
    assert_eq!(b.task(&live).unwrap().consecutive_failures, 0);
}
