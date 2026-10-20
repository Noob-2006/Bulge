//! C1 acceptance: a real process crash (abort) between claiming and
//! completing a tool call, then resume from the log.
//! usage: crash_probe <store-root>          (parent)
//!        crash_probe <store-root> --child  (writes, then aborts)
use bulge_llm::{Message, Role};
use bulge_store::*;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let root = args.get(1).ok_or("usage: crash_probe <store-root>")?;
    let store = JobStore::new(root);
    if args.get(2).map(String::as_str) == Some("--child") {
        let mut job = store.create(JobSpec {
            id: "j-crash".into(),
            title: "crash test".into(),
            goal: "g".into(),
            workspace: "/tmp".into(),
            autonomy: Autonomy::default(),
            budget: Budget::default(),
            model: ModelRef { backend: "b".into(), model: "m".into() },
        })?;
        job.append(vec![JobEvent::StepStarted { step: 1 }, JobEvent::Message { message: Message::text(Role::User, "run make") }])?;
        job.append(vec![JobEvent::ToolClaimed { call_id: "call-1".into(), name: "exec".into(), arguments: json!({"command": "make"}) }])?;
        std::process::abort(); // hard crash: no destructors, no flush beyond what append already fsynced
    }
    let _ = std::fs::remove_dir_all(root);
    let status = std::process::Command::new(&args[0]).args([root.as_str(), "--child"]).status()?;
    println!("child exited: {status} (expected abort)");
    let (job, recovery) = store.open("j-crash")?;
    println!("recovered interrupted calls: {:?}", recovery.interrupted_calls);
    println!("pending after recovery: {}", job.state().pending_calls.len());
    let last = job.state().history.last().ok_or("empty history")?;
    println!("model will see: tool_call_id={:?} is_error={:?}", last.tool_call_id, last.is_error);
    let ok = recovery.interrupted_calls == ["call-1"] && job.state().pending_calls.is_empty() && last.is_error == Some(true);
    println!("{}", if ok { "PASS crash/resume" } else { "FAIL crash/resume" });
    std::process::exit(i32::from(!ok));
}
