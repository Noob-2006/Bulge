//! `dock.snapshot` ARP method for the TUI's status bar and live-work dock (Hermes
//! `_get_status_bar_snapshot` + `SubagentMonitor.refresh`): model, context %, tokens,
//! prompt-cache hit rate and compactions for a session, plus its live sub-agents, active
//! goal, background processes and queued prompts. Registered by `seagent daemon run` next to
//! `ui_methods`.

use seagent_kernel::daemon::MethodExt;
use seagent_kernel::kernel::Kernel;
use seagent_kernel::projection::project;
use serde_json::{json, Value};
use std::sync::Arc;

pub const METHODS: &[&str] = &["dock.snapshot"];

pub fn snapshot(k: &Kernel, session: &str) -> Result<Value, String> {
    let v = project(&k.store.read(session).map_err(|e| e.to_string())?);
    let (pid, m) = seagent_kernel::context::split_model(&v.model);
    let window = k.resolver.provider(pid).map(|p| p.caps(m).context_window).unwrap_or(0);
    let pct = (window > 0).then(|| ((v.last_input_tokens as f64 * 100.0 / window as f64).round() as u64).min(100));
    let prompt = v.usage.input_tokens + v.usage.cache_read_tokens + v.usage.cache_write_tokens;
    let cache = (v.usage.cache_read_tokens > 0 && prompt > 0).then(|| (v.usage.cache_read_tokens as f64 * 1000.0 / prompt as f64).round() / 10.0);
    let goal = std::fs::read_to_string(seagent_kernel::automation::goals_path(&k.paths.data)).ok().and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok()).unwrap_or_default().into_iter().find(|g| g["session"] == session && matches!(g["status"].as_str(), Some("active" | "Active" | "paused" | "Paused"))).map(|g| {
        let paused = g["status"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("paused"));
        format!("{}{} ({}/{} rounds)", if paused { "⏸ " } else { "" }, g["objective"].as_str().unwrap_or(""), g["rounds"], g["max_rounds"])
    });
    Ok(json!({
        "status": {"model": v.model, "context_pct": pct, "context_window": window, "tokens": v.usage.total(), "cache_pct": cache, "compactions": v.compactions, "running": k.is_running(session)},
        "goal": goal.unwrap_or_default(),
        "subagents": k.subagent_list(session, false),
        "processes": processes(session),
        "queued": k.queued(session).into_iter().map(|q| q.2).collect::<Vec<_>>(),
    }))
}

/// This session's background processes — the same registry `job` and `process list` read
/// (`seagent-tools`' exec registry), mapped to the rows the dock paints. Read-only: the call
/// never starts, adopts or stops a process, and an empty registry is an empty list.
fn processes(session: &str) -> Vec<Value> {
    seagent_tools::exec::process::list(session)
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "command": s.command,
                "origin": s.origin,
                "status": if s.running { "running" } else { "exited" },
                "running_seconds": s.elapsed.as_secs(),
                "exit_code": s.exit,
                "pty": s.pty,
            })
        })
        .collect()
}

pub fn methods(k: Kernel) -> MethodExt {
    Arc::new(move |m: &str, p: &Value| (m == "dock.snapshot").then(|| p["session"].as_str().ok_or((-32602, "missing session".to_string())).and_then(|s| snapshot(&k, s).map_err(|e| (-32000, e)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_status_and_queue() {
        let kit = crate::testkit::kit();
        let id = kit.k.create_session(&kit.ws, None, None, Some("t")).unwrap();
        kit.k.submit(&id, "hello", "cli").unwrap();
        kit.k.run(&id, Default::default()).unwrap();
        // A prompt waiting for the next turn shows up in the dock's queue.
        kit.k.submit(&id, "then write the docs", "cli").unwrap();
        // A paused goal for this session is summarised with its round counter.
        let goals = vec![
            json!({"session": "someone-else", "status": "active", "objective": "other", "rounds": 1, "max_rounds": 3}),
            json!({"session": id, "status": "paused", "objective": "ship the release", "rounds": 2, "max_rounds": 5}),
            json!({"session": id, "status": "done", "objective": "stale", "rounds": 9, "max_rounds": 9}),
        ];
        std::fs::write(seagent_kernel::automation::goals_path(&kit.paths.data), serde_json::to_vec(&goals).unwrap()).unwrap();
        let f = methods(kit.k.clone());
        let v = f("dock.snapshot", &json!({"session": id})).unwrap().unwrap();
        assert_eq!(v["status"]["model"], "echo/m");
        assert_eq!(v["status"]["context_window"], 100_000);
        assert_eq!(v["status"]["tokens"], 60, "50 input + 10 output from the echo provider");
        assert_eq!(v["status"]["context_pct"], 0);
        assert_eq!(v["status"]["compactions"], 0);
        assert_eq!(v["status"]["running"], false);
        assert_eq!(v["queued"], json!(["then write the docs"]));
        assert_eq!(v["goal"], "⏸ ship the release (2/5 rounds)");
        assert_eq!(v["subagents"], json!([]));
        // No background process was started for this session: the key is an empty array.
        assert_eq!(v["processes"], json!([]));
        assert!(f("dock.snapshot", &json!({})).unwrap().is_err());
        assert!(f("dock.snapshot", &json!({"session": "missing"})).unwrap().is_err());
        assert!(f("other", &json!({})).is_none());
    }

    /// The dock's process rows come from the registry `job`/`process list` use, so a job the
    /// agent started shows up (and a session with none stays empty).
    #[test]
    fn process_rows_come_from_the_job_registry() {
        use seagent_core::exec::ExecRequest;
        let kit = crate::testkit::kit();
        let id = kit.k.create_session(&kit.ws, None, None, Some("t")).unwrap();
        let dir = kit.paths.data.join("jobs");
        std::fs::create_dir_all(&dir).unwrap();
        let req = ExecRequest { script: "sleep 30".into(), cwd: Some(kit.ws.clone()), env: vec![], stdin: false, stdin_data: None, pty: None, login: false, detach: false, log_file: None, exit_file: None };
        let child = {
            let mut cmd = std::process::Command::new("sleep");
            cmd.arg("30");
            seagent_tools::exec::local::spawn_command(cmd, &req, None).unwrap()
        };
        let backend = std::sync::Arc::new(seagent_tools::exec::local::LocalBackend::new()) as std::sync::Arc<dyn seagent_core::exec::ExecBackend>;
        let entry = seagent_tools::exec::process::register(&id, "sleep 30", child, backend, dir.join("job.log"), false, 200_000);
        let pid = entry.lock().unwrap().id;

        let f = methods(kit.k.clone());
        let v = f("dock.snapshot", &json!({"session": id})).unwrap().unwrap();
        assert_eq!(v["processes"].as_array().map(Vec::len), Some(1), "{v}");
        assert_eq!(v["processes"][0]["command"], "sleep 30");
        assert_eq!(v["processes"][0]["id"], json!(pid), "the id `process list`/`job` know");
        assert_eq!(v["processes"][0]["status"], "running");
        assert_eq!(v["processes"][0]["exit_code"], Value::Null);
        assert_eq!(v["processes"][0]["origin"], "process");
        assert!(v["processes"][0]["running_seconds"].is_u64(), "{v}");
        // Another session sees nothing — the rows are per session.
        let other = kit.k.create_session(&kit.ws, None, None, Some("other")).unwrap();
        assert_eq!(f("dock.snapshot", &json!({"session": other})).unwrap().unwrap()["processes"], json!([]));
        // Cleanup: kill only the process this test started.
        seagent_tools::exec::process::kill(&id, pid).unwrap();
    }
}
