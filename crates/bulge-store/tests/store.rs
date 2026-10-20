//! bulge-store integration: create / append / reopen / crash recovery.

use std::io::Write;
use std::path::PathBuf;

use bulge_llm::{Message, Role};
use bulge_store::*;
use serde_json::json;

fn root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("bulge-store-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn spec(id: &str) -> JobSpec {
    JobSpec {
        id: id.into(),
        title: "整理報告".into(),
        goal: "summarize notes".into(),
        workspace: "/tmp/ws".into(),
        autonomy: Autonomy::default(),
        budget: Budget::default(),
        model: ModelRef { backend: "deepseek".into(), model: "m".into() },
    }
}

#[test]
fn create_append_reopen_round_trips() {
    let store = JobStore::new(root());
    let mut job = store.create(spec("j-1")).unwrap();
    job.append(vec![
        JobEvent::StepStarted { step: 1 },
        JobEvent::Message { message: Message::text(Role::User, "hi") },
        JobEvent::ToolClaimed { call_id: "c1".into(), name: "read".into(), arguments: json!({"path": "a"}) },
        JobEvent::ToolCompleted { call_id: "c1".into(), ok: true, result: json!("x") },
        JobEvent::StatusChanged { status: JobStatus::Succeeded, summary: Some("done".into()) },
    ])
    .unwrap();
    let before = job.state().clone();
    drop(job);
    let (job, recovery) = store.open("j-1").unwrap();
    assert_eq!(recovery, Recovery::default());
    assert_eq!(job.state(), &before);
    assert_eq!(store.load("j-1").unwrap(), before);
}

#[test]
fn interrupted_tool_call_is_closed_out_on_resume() {
    let store = JobStore::new(root());
    let mut job = store.create(spec("j-2")).unwrap();
    job.append(vec![JobEvent::ToolClaimed { call_id: "c9".into(), name: "exec".into(), arguments: json!({"command": "make"}) }]).unwrap();
    drop(job); // crash: no completion
    let (job, recovery) = store.open("j-2").unwrap();
    assert_eq!(recovery.interrupted_calls, vec!["c9".to_string()]);
    assert!(job.state().pending_calls.is_empty());
    let last = job.state().history.last().unwrap();
    assert_eq!(last.tool_call_id.as_deref(), Some("c9"));
    assert_eq!(last.is_error, Some(true));
    // Recovery is durable: a second open has nothing left to repair.
    drop(job);
    assert_eq!(store.open("j-2").unwrap().1.interrupted_calls, Vec::<String>::new());
}

#[test]
fn torn_tail_is_recovered() {
    let dir = root();
    let store = JobStore::new(&dir);
    let mut job = store.create(spec("j-3")).unwrap();
    job.append(vec![JobEvent::StepStarted { step: 1 }]).unwrap();
    drop(job);
    let mut f = std::fs::OpenOptions::new().append(true).open(dir.join("j-3/job.jsonl")).unwrap();
    f.write_all(br#"{"seq":3,"at_ms":1,"type":"step_star"#).unwrap();
    drop(f);
    let (mut job, recovery) = store.open("j-3").unwrap();
    assert!(recovery.torn_tail_bytes > 0);
    assert_eq!(job.state().steps, 1);
    job.append(vec![JobEvent::StepStarted { step: 2 }]).unwrap();
    drop(job);
    assert_eq!(store.load("j-3").unwrap().steps, 2);
}

#[test]
fn second_writer_is_refused() {
    let store = JobStore::new(root());
    let _job = store.create(spec("j-4")).unwrap();
    assert!(matches!(store.open("j-4"), Err(StoreError::Log(bulge_store::log::LogError::Locked(_)))));
    // Readers are never blocked.
    assert!(store.load("j-4").is_ok());
}

#[test]
fn invalid_events_never_reach_disk() {
    let store = JobStore::new(root());
    let mut job = store.create(spec("j-5")).unwrap();
    let err = job.append(vec![JobEvent::StepStarted { step: 1 }, JobEvent::ToolCompleted { call_id: "nope".into(), ok: true, result: json!(null) }]);
    assert!(err.is_err());
    drop(job);
    assert_eq!(store.load("j-5").unwrap().steps, 0, "the whole batch must be rejected");
}

#[test]
fn ids_are_validated_and_listing_sorts_by_activity() {
    let store = JobStore::new(root());
    assert!(matches!(store.create(spec("../evil")), Err(StoreError::InvalidId(_))));
    let mut a = store.create(spec("j-a")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let _b = store.create(spec("j-b")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    a.append(vec![JobEvent::StepStarted { step: 1 }]).unwrap();
    let ids: Vec<String> = store.list().unwrap().into_iter().map(|j| j.id).collect();
    assert_eq!(ids, vec!["j-a".to_string(), "j-b".to_string()]);
    assert!(new_job_id().unwrap().starts_with("j-"));
}
