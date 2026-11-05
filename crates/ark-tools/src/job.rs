//! `job`: background commands (dev servers, long builds) the agent can poll
//! instead of blocking a step. The command runs in the session's exec backend
//! (`exec::spawn_tool`), and the process is registered in `exec::process`, so
//! `process` (and `shell`'s yielded commands) see the same id: `job 3` is
//! `process 3`. Output goes to a log file with a 200 KB rolling buffer on top
//! (`[exec] process_buffer_bytes`).
//!
//! `pty=true` runs the command under a pseudo-terminal whose pane `read_terminal`
//! reads (see `terminal.rs`); `notify=true` delivers a completion notice into the
//! session when the job exits (Hermes `notify_on_complete`); `detach=true` (or
//! `persist=true`) starts it detached from ark, with a snapshot in
//! `<home>/jobs/<id>.json`, so it survives an ark restart.

use crate::terminal::{Source, Term};
use ark_core::exec::ExecRequest;
use ark_core::tool::{arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// PTY panes of this process's jobs (`read_terminal` reads them).
static PANES: Mutex<BTreeMap<u32, Arc<Term>>> = Mutex::new(BTreeMap::new());
const MAX_RUNNING: usize = 8;
const TAIL: usize = 8 * 1024;

/// `read_terminal`'s view of this session's jobs.
fn source(session: &str, id: Option<u32>) -> Option<(u32, Source)> {
    let jobs: Vec<crate::exec::process::Snapshot> =
        crate::exec::process::list(session).into_iter().filter(|s| s.origin == "job").collect();
    let id = match id {
        Some(i) => jobs.iter().find(|s| s.id == i)?.id,
        // Newest open pane: prefer PTY jobs, then any job of the session.
        None => {
            let open: Vec<&crate::exec::process::Snapshot> = jobs.iter().filter(|s| !crate::terminal::is_hidden(session, s.id)).collect();
            open.iter().rev().find(|s| s.pty).or_else(|| open.last()).map(|s| s.id)?
        }
    };
    let snap = jobs.iter().find(|s| s.id == id)?;
    let term = if snap.pty { PANES.lock().unwrap().get(&id).cloned() } else { None };
    // The pane may know the exit status a moment before the registry pump does.
    let exit = snap.exit.or_else(|| term.as_ref().and_then(|t| t.exit()).map(|e| e.code.unwrap_or_else(|| -e.signal.unwrap_or(1))));
    Some((id, Source { term, log: snap.log.clone(), running: snap.running, exit, command: snap.command.clone() }))
}

fn status(s: &crate::exec::process::Snapshot) -> String {
    match (s.running, s.exit) {
        (true, _) => format!("running {:.0}s", s.elapsed.as_secs_f32()),
        (false, Some(c)) => format!("exited {c}"),
        (false, None) => "exited".to_string(),
    }
}

pub struct Job;

impl Tool for Job {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "job".into(),
            description: "Run a shell command in the background (servers, long builds). action=start {command, cwd?, pty?, notify?, detach?} returns an id; output {id} shows the latest output; wait {id, timeout_secs} blocks until exit or timeout; kill {id}; list. pty=true runs it under a terminal (read its pane with read_terminal); notify=true tells you when it exits so you need not poll; detach=true keeps it running after ark restarts. The same id works with the `process` tool (poll/log/write/send-keys/paste/close…).".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["start","output","wait","kill","list"]},
                "command":{"type":"string"},
                "cwd":{"type":"string"},
                "id":{"type":"integer"},
                "pty":{"type":"boolean","description":"Run under a pseudo-terminal (interactive CLIs, progress bars); its pane is readable with read_terminal."},
                "notify":{"type":"boolean","description":"Deliver a completion notice into this conversation when the job exits."},
                "detach":{"type":"boolean","description":"Detach from ark: the job keeps running (and stays visible in process list) after ark restarts. Also accepted as persist."},
                "timeout_secs":{"type":"integer","default":30}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        // Any command that might run is judged, whatever `action` says.
        match arg_opt_str(input, "command").or_else(|| arg_opt_str(input, "cmd")) {
            Some(c) => vec![Effect::Exec { command: c.to_string() }],
            None => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::terminal::set_lookup(source);
        crate::util::alias(&mut input, "command", &["cmd"]);
        crate::util::infer_action(&mut input, &[("command", "start"), ("id", "output")]);
        let id = arg_opt_u64(&input, "id").map(|i| i as u32);
        let mine = |id: u32| crate::exec::process::list(&ctx.session_id).into_iter().any(|s| s.id == id && s.origin == "job");
        match arg_opt_str(&input, "action") {
            Some("start") => start(ctx, &input),
            Some("list") => {
                let v: Vec<String> = crate::exec::process::list(&ctx.session_id)
                    .into_iter()
                    .filter(|s| s.origin == "job")
                    .map(|s| {
                        let tag = match (s.pty, crate::terminal::is_hidden(&ctx.session_id, s.id)) {
                            (true, true) => "  [pty, pane closed]",
                            (true, false) => "  [pty]",
                            _ => "",
                        };
                        format!("{}  {}  {}{tag}", s.id, status(&s), s.command.chars().take(80).collect::<String>())
                    })
                    .collect();
                ToolOutput::ok(if v.is_empty() { "no jobs".into() } else { v.join("\n") })
            }
            Some(a @ ("output" | "wait" | "kill")) => {
                let Some(id) = id.filter(|i| mine(*i)) else { return ToolOutput::err("unknown job id; use action=list") };
                if a == "kill" {
                    // Kill the pane's own handle too: it is the one that owns the PTY.
                    // Clone it out of the map first: `Term::kill` takes the pane's child lock,
                    // and holding `PANES` while it runs would stall every other pane lookup.
                    let pane = PANES.lock().unwrap().get(&id).cloned();
                    if let Some(t) = pane {
                        t.kill();
                    }
                    if let Err(e) = crate::exec::process::kill(&ctx.session_id, id) {
                        return ToolOutput::err(e);
                    }
                    return ToolOutput::ok(format!("job {id} killed\n{}", tail(ctx, id)));
                }
                if a == "wait" {
                    let timeout = Duration::from_secs(arg_opt_u64(&input, "timeout_secs").unwrap_or(30).min(600));
                    return match crate::exec::process::wait_with(&ctx.session_id, id, timeout, || ctx.cancel.is_cancelled()) {
                        Some(s) => {
                            if !s.running {
                                wait_pane(id, Duration::from_secs(3));
                            }
                            ToolOutput::ok(format!("job {id} {}\n{}", status(&s), tail(ctx, id)))
                        }
                        None => ToolOutput::err("unknown job id; use action=list"),
                    };
                }
                match crate::exec::process::poll(&ctx.session_id, id) {
                    Some(s) => {
                        if !s.running {
                            wait_pane(id, Duration::from_millis(500));
                        }
                        ToolOutput::ok(format!("job {id} {}\n{}", status(&s), tail(ctx, id)))
                    }
                    None => ToolOutput::err("unknown job id; use action=list"),
                }
            }
            _ => ToolOutput::err("action must be start, output, wait, kill or list"),
        }
    }
}

/// Wait for a PTY job's pane to catch up with the process: the pane's screen is fed
/// by its own reader thread, so `read_terminal` right after `wait` must not see a
/// half-drawn screen. `Term::exit` is set only after the last chunk was fed.
pub fn wait_pane(id: u32, timeout: std::time::Duration) {
    let term = PANES.lock().unwrap().get(&id).cloned();
    let Some(t) = term else { return };
    let deadline = std::time::Instant::now() + timeout;
    while t.exit().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn tail(ctx: &ToolCtx, id: u32) -> String {
    let text = crate::exec::process::tail(&ctx.session_id, id, TAIL).unwrap_or_default();
    crate::tokenjuice::reduce_output(&text, crate::tokenjuice::DEFAULT_BUDGET).unwrap_or(text)
}

/// `detach` / `persist`, or `ARK_EXEC_PERSIST=1` for every job.
fn wants_detach(input: &Value) -> bool {
    let asked = ["detach", "persist"].iter().any(|k| input.get(*k).and_then(Value::as_bool) == Some(true));
    asked || std::env::var("ARK_EXEC_PERSIST").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

fn start(ctx: &ToolCtx, input: &Value) -> ToolOutput {
    let command = match arg_str(input, "command") {
        Ok(c) if !c.trim().is_empty() => c.to_string(),
        _ => return ToolOutput::err("missing `command`"),
    };
    let running = crate::exec::process::list(&ctx.session_id).into_iter().filter(|s| s.origin == "job" && s.running).count();
    if running >= MAX_RUNNING {
        return ToolOutput::err(format!("{MAX_RUNNING} jobs already running; kill one first"));
    }
    let cwd = ctx.resolve(arg_opt_str(input, "cwd").unwrap_or("."));
    if !cwd.is_dir() {
        return ToolOutput::err(format!("cwd {} is not a directory", cwd.display()));
    }
    let pty = input.get("pty").and_then(Value::as_bool).unwrap_or(false);
    let notify = input.get("notify").and_then(Value::as_bool).unwrap_or(false);
    let detach = wants_detach(input);
    let dir = ctx.home.join("jobs");
    if let Err(e) = fs::create_dir_all(&dir) {
        return ToolOutput::err(format!("cannot create {}: {e}", dir.display()));
    }
    let id = crate::exec::process::next_free_id();
    let log = dir.join(format!("job-{}-{id}.log", crate::exec::sanitize(&ctx.session_id)));
    if fs::write(&log, b"").is_err() {
        return ToolOutput::err(format!("cannot create {}", log.display()));
    }
    let exit_file: Option<PathBuf> = detach.then(|| dir.join(format!("{id}.exit")));
    if let Some(f) = &exit_file {
        let _ = fs::remove_file(f);
    }
    let exec_env = crate::exec::global();
    // Secrets are substituted once, here: the command the backend runs never sees a placeholder.
    let mut req = ExecRequest {
        script: (ctx.secrets)(&command),
        cwd: Some(cwd.clone()),
        pty: pty.then_some((24u16, 80u16)),
        stdin: !detach,
        detach,
        log_file: detach.then(|| log.clone()),
        exit_file: exit_file.clone(),
        ..Default::default()
    };
    req.env = exec_env.child_env_for(&[("TERM".to_string(), "xterm-256color".to_string())]);
    // C9: a sub-agent's background jobs run in the child's own home, not the driver's.
    req.env.extend(ctx.host.sandbox_env());
    let elevated = exec_env.elevated(&ctx.session_id);
    let (backend, child) = match crate::exec::spawn_tool(ctx, &req, elevated) {
        Ok(v) => v,
        Err(e) => return ToolOutput::err(format!("start: {e}")),
    };
    let pid = child.pid();
    // `/proc/<pid>/stat` start time: tells a reused pid from ours after a restart.
    let start_time = pid.and_then(crate::exec::local::proc_start_time);
    let persist = match (pid, &exit_file) {
        (Some(pid), Some(exit_file)) => Some(crate::exec::process::Persist {
            dir: dir.clone(),
            pid,
            start: start_time,
            exit_file: exit_file.clone(),
            scope: exec_env.scope_key(&ctx.session_id, &ctx.workspace),
            backend: backend.id().to_string(),
        }),
        _ => None,
    };
    let opts = crate::exec::process::Options {
        pty,
        buffer_cap: exec_env.cfg.process_buffer_bytes,
        detached: detach,
        stdin: !detach,
        notify,
        label: "job ".into(),
        origin: "job".into(),
        persist,
    };
    let entry = match crate::exec::process::register_named(id, &ctx.session_id, &command, child, backend, log.clone(), opts) {
        Ok(e) => e,
        Err(e) => return ToolOutput::err(format!("start: {e}")),
    };
    if pty {
        // The pane reads the process through a tap, so the PTY keeps exactly one
        // reader (the registry pump) and `process` can still type into it.
        let tap = crate::exec::process::tap(&entry);
        let pane_log = dir.join(format!("job-{id}.pane.log"));
        let term = Term::start(tap, 24, 80, pane_log);
        PANES.lock().unwrap().insert(id, term);
        return ToolOutput::ok(format!("job {id} started under a terminal; read its pane with read_terminal process_id={id}"));
    }
    let back = if detach { " (detached: it keeps running after ark exits)" } else { "" };
    if notify {
        return ToolOutput::ok(format!("job {id} started{back}; you will be notified when it exits (or check it with action=output id={id})"));
    }
    ToolOutput::ok(format!("job {id} started{back}; check it with action=output id={id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::time::Instant;

    #[test]
    fn start_poll_wait_kill_and_isolation() {
        let c = ctx("job");
        let o = Job.call(&c, json!({"action":"start","command":"echo hi; echo err >&2; sleep 0.3; echo bye"}));
        assert!(!o.is_error, "{}", o.content);
        let id: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id,"timeout_secs":5}));
        assert!(w.content.contains("exited 0") && w.content.contains("hi") && w.content.contains("err") && w.content.contains("bye"), "{}", w.content);
        let o = Job.call(&c, json!({"action":"output","id":id}));
        assert!(o.content.contains("exited 0") && o.content.contains("bye"), "{}", o.content);
        assert!(Job.call(&c, json!({"action":"start","command":"echo keep; sleep 30"})).content.contains("started"));
        let o = Job.call(&c, json!({"action":"list"}));
        assert!(o.content.contains(&format!("{id}  exited 0  echo hi")) && o.content.contains("running"), "{}", o.content);
        let id2: u64 = o.content.lines().find(|l| l.contains("running")).unwrap().split_whitespace().next().unwrap().parse().unwrap();
        let mut other = c.clone();
        other.session_id = "someone-else".into();
        assert!(Job.call(&other, json!({"action":"kill","id":id2})).is_error, "other sessions can't touch it");
        assert_eq!(Job.call(&other, json!({"action":"list"})).content, "no jobs");
        let t = Instant::now();
        assert!(Job.call(&c, json!({"action":"kill","id":id2})).content.contains("killed"));
        assert!(t.elapsed() < Duration::from_secs(2));
        assert!(Job.call(&c, json!({"action":"output","id":id2})).content.contains("exited -9"));

        assert!(Job.call(&c, json!({"action":"start"})).is_error);
        assert!(Job.call(&c, json!({"action":"start","command":"true","cwd":"nope"})).is_error);
        assert!(Job.call(&c, json!({"action":"output","id":9999})).is_error);
        assert!(Job.call(&c, json!({"action":"output"})).is_error);
        assert!(Job.call(&c, json!({"action":"zap"})).is_error);
    }

    #[test]
    fn pty_pane_queries_notify_and_close_terminal() {
        use crate::terminal::{CloseTerminal, ReadTerminal};
        static GOT: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
        crate::exec::global().set_notifier(Arc::new(|s: &str, t: &str| GOT.lock().unwrap().push((s.into(), t.into()))));
        let c = ctx("jobpty");
        let o = Job.call(&c, json!({"action":"start","command":"[ -t 1 ] && echo TTY; printf '\\033[6n'; if read -t 3 -s -d R r; then echo answered; fi; printf '10%%\\r100%%\\n'; echo done","pty":true,"notify":true}));
        assert!(o.content.contains("under a terminal"), "{}", o.content);
        let id: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id,"timeout_secs":10}));
        assert!(w.content.contains("exited 0"), "{}", w.content);
        // The pane drains the registry buffer on its own thread: poll until the last line
        // the command wrote is on screen (the exit status is known before that).
        let t0 = Instant::now();
        let mut r: Value = Value::Null;
        while t0.elapsed() < Duration::from_secs(5) {
            r = serde_json::from_str(&ReadTerminal.call(&c, json!({})).content).unwrap();
            if r["text"].as_str().unwrap_or("").contains("done") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(r["process_id"], id);
        let text = r["text"].as_str().unwrap();
        assert!(text.contains("TTY") && text.contains("answered") && text.contains("done"), "query answered, not leaked: {text:?}");
        assert!(text.lines().any(|l| l == "100%") && !text.contains("\u{1b}"), "{text:?}");
        assert_eq!((r["pty"].as_bool(), r["running"].as_bool()), (Some(true), Some(false)));
        let t0 = Instant::now();
        while !GOT.lock().unwrap().iter().any(|(s, _)| s == &c.session_id) && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let got = GOT.lock().unwrap().iter().find(|(s, _)| s == &c.session_id).cloned().expect("completion notice delivered");
        assert!(got.1.starts_with(&format!("[IMPORTANT: Background process job {id} completed normally (exit code 0).")) && got.1.contains("done"), "{}", got.1);

        // close_terminal hides without killing; read_terminal reopens.
        let o = Job.call(&c, json!({"action":"start","command":"echo up; sleep 30","pty":true}));
        let id2: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        // Wait for the *pane* to show the line: the job log is filled by the registry pump
        // first, the terminal screen lags behind it by a few milliseconds.
        let mut pane: Value = Value::Null;
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            pane = serde_json::from_str(&ReadTerminal.call(&c, json!({"process_id": id2})).content).unwrap();
            if pane["total_lines"].as_u64().unwrap_or(0) >= 1 && pane["text"].as_str().unwrap_or("").contains("up") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(pane["text"].as_str().unwrap_or("").contains("up"), "the pane shows the command's output: {pane}");
        let cl: Value = serde_json::from_str(&CloseTerminal.call(&c, json!({"process_id": id2})).content).unwrap();
        assert_eq!((cl["closed"].as_bool(), cl["running"].as_bool()), (Some(true), Some(true)));
        assert!(Job.call(&c, json!({"action":"list"})).content.contains("[pty, pane closed]"));
        let r: Value = serde_json::from_str(&ReadTerminal.call(&c, json!({})).content).unwrap();
        assert_eq!(r["process_id"], id, "closed panes are skipped by default");
        let r: Value = serde_json::from_str(&ReadTerminal.call(&c, json!({"process_id": format!("{id2}"), "start_line": 0, "count": 1})).content).unwrap();
        assert_eq!((r["running"].as_bool(), r["start"].as_u64(), r["end"].as_u64()), (Some(true), Some(0), Some(1)));
        assert!(!Job.call(&c, json!({"action":"list"})).content.contains("pane closed"), "reading reopens");
        assert!(Job.call(&c, json!({"action":"kill","id":id2})).content.contains("killed"));
        assert!(CloseTerminal.call(&c, json!({})).is_error);
        assert!(ReadTerminal.call(&c, json!({"process_id": 999})).is_error);
        assert!(ReadTerminal.call(&c, json!({"count": "x"})).is_error);

        // A plain job's log is readable line by line too.
        let o = Job.call(&c, json!({"action":"start","command":"printf 'a\\nb\\nc\\n'"}));
        let id3: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        Job.call(&c, json!({"action":"wait","id":id3,"timeout_secs":5}));
        let r: Value = serde_json::from_str(&ReadTerminal.call(&c, json!({"process_id": id3})).content).unwrap();
        assert_eq!((r["text"].as_str(), r["total_lines"].as_u64(), r["pty"].as_bool()), (Some("a\nb\nc"), Some(3), Some(false)));
        let mut other = c.clone();
        other.session_id = "nobody".into();
        assert!(ReadTerminal.call(&other, json!({"process_id": id3})).is_error, "sessions only see their own panes");
    }

    #[test]
    fn action_inferred_and_effects_always_judged() {
        let c = ctx("job3");
        assert_eq!(Job.effects(&c, &json!({"action":"list","command":"sudo x"})), vec![Effect::Exec { command: "sudo x".into() }]);
        let o = Job.call(&c, json!({"cmd":"echo inferred"}));
        assert!(o.content.starts_with("job "), "{}", o.content);
        let id = o.content.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id,"timeout_secs":5}));
        assert!(w.content.contains("inferred"));
        assert!(Job.call(&c, json!({"id":id})).content.contains("exited 0"), "id alone → output");
    }

    #[test]
    fn large_output_is_tailed_and_secrets_substituted() {
        let c = ctx("job2");
        let o = Job.call(&c, json!({"action":"start","command":"head -c 50000 /dev/zero | tr '\\0' a; echo; echo tok={{secret:TOKEN}}"}));
        let id: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id,"timeout_secs":5}));
        assert!(w.content.contains("earlier bytes") && w.content.len() < 10_000, "tailed");
        assert!(w.content.contains("tok=s3cr3t"), "substituted at exec (the kernel redacts before the model sees it)");
    }

    /// `detach=true` writes the snapshot a restarted ark reads back.
    #[test]
    fn detached_job_writes_a_snapshot() {
        let c = ctx("jobdetach");
        let o = Job.call(&c, json!({"action":"start","command":"sleep 5","detach":true}));
        assert!(o.content.contains("detached"), "{}", o.content);
        let id: u32 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let rec = crate::exec::process::record_path(&c.home.join("jobs"), id);
        assert!(rec.exists(), "snapshot at {}", rec.display());
        let txt = std::fs::read_to_string(&rec).unwrap();
        assert!(txt.contains("\"pid\"") && txt.contains("sleep 5") && txt.contains("\"exit_file\"") && txt.contains("\"origin\": \"job\""), "{txt}");
        let snap = crate::exec::process::poll(&c.session_id, id).unwrap();
        assert!(snap.running && snap.detached && snap.pid.is_some());
        Job.call(&c, json!({"action":"kill","id":id}));
    }
}
