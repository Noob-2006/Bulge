//! `job`: background commands (dev servers, long builds) the agent can poll
//! instead of blocking a step. Output goes straight to a file, so no reader
//! threads and nothing lost if nobody looks. Jobs die with the ark process.

use crate::shell::die_with_parent;
use ark_core::tool::{arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    session: String,
    command: String,
    child: Child,
    log: PathBuf,
    started: Instant,
    exit: Option<i32>,
}

static JOBS: Mutex<BTreeMap<u32, Entry>> = Mutex::new(BTreeMap::new());
const MAX_RUNNING: usize = 8;
const TAIL: u64 = 8 * 1024;

fn reap(j: &mut Entry) {
    if j.exit.is_none() {
        if let Ok(Some(s)) = j.child.try_wait() {
            j.exit = Some(s.code().unwrap_or(-1));
        }
    }
}

fn status(j: &Entry) -> String {
    match j.exit {
        None => format!("running {:.0}s", j.started.elapsed().as_secs_f32()),
        Some(c) => format!("exited {c}"),
    }
}

fn tail(p: &PathBuf, n: u64) -> String {
    let Ok(mut f) = File::open(p) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(n)));
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let s = String::from_utf8_lossy(&buf).into_owned();
    if len > n {
        format!("[… {} earlier bytes in {}]\n{s}", len - n, p.display())
    } else {
        s
    }
}

pub struct Job;

impl Tool for Job {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "job".into(),
            description: "Run a shell command in the background (servers, long builds). action=start {command, cwd?} returns an id; output {id} shows the latest output; wait {id, timeout_secs} blocks until exit or timeout; kill {id}; list.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["start","output","wait","kill","list"]},
                "command":{"type":"string"},
                "cwd":{"type":"string"},
                "id":{"type":"integer"},
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
        crate::util::alias(&mut input, "command", &["cmd"]);
        crate::util::infer_action(&mut input, &[("command", "start"), ("id", "output")]);
        let mut jobs = JOBS.lock().unwrap();
        for j in jobs.values_mut() {
            reap(j);
        }
        // Each session only sees its own jobs.
        let mine = |id: u32, jobs: &BTreeMap<u32, Entry>| jobs.get(&id).is_some_and(|j| j.session == ctx.session_id);
        let id = arg_opt_u64(&input, "id").map(|i| i as u32);
        match arg_opt_str(&input, "action") {
            Some("start") => {
                let command = match arg_str(&input, "command") {
                    Ok(c) if !c.trim().is_empty() => c,
                    _ => return ToolOutput::err("missing `command`"),
                };
                if jobs.values().filter(|j| j.exit.is_none()).count() >= MAX_RUNNING {
                    return ToolOutput::err(format!("{MAX_RUNNING} jobs already running; kill one first"));
                }
                let cwd = ctx.resolve(arg_opt_str(&input, "cwd").unwrap_or("."));
                if !cwd.is_dir() {
                    return ToolOutput::err(format!("cwd {} is not a directory", cwd.display()));
                }
                let dir = ctx.home.join("jobs");
                let _ = fs::create_dir_all(&dir);
                let n = jobs.keys().next_back().copied().unwrap_or(0) + 1;
                let log = dir.join(format!("{}-{n}.log", ctx.session_id));
                let Ok(out) = File::create(&log) else { return ToolOutput::err(format!("cannot create {}", log.display())) };
                let err = out.try_clone().ok();
                let parent = std::process::id() as i32;
                let mut cmd = Command::new("bash");
                cmd.arg("-c").arg((ctx.secrets)(command)).current_dir(&cwd).stdin(Stdio::null()).stdout(out);
                cmd.stderr(err.map(Stdio::from).unwrap_or(Stdio::null()));
                // SAFETY: async-signal-safe calls only.
                unsafe {
                    cmd.pre_exec(move || {
                        libc::setpgid(0, 0);
                        die_with_parent(parent);
                        Ok(())
                    });
                }
                match cmd.spawn() {
                    Ok(child) => {
                        jobs.insert(n, Entry { session: ctx.session_id.clone(), command: command.to_string(), child, log, started: Instant::now(), exit: None });
                        ToolOutput::ok(format!("job {n} started; check it with action=output id={n}"))
                    }
                    Err(e) => ToolOutput::err(format!("start: {e}")),
                }
            }
            Some("list") => {
                let v: Vec<String> = jobs.iter().filter(|(_, j)| j.session == ctx.session_id).map(|(n, j)| format!("{n}  {}  {}", status(j), j.command.chars().take(80).collect::<String>())).collect();
                ToolOutput::ok(if v.is_empty() { "no jobs".into() } else { v.join("\n") })
            }
            Some(a @ ("output" | "wait" | "kill")) => {
                let Some(id) = id.filter(|i| mine(*i, &jobs)) else { return ToolOutput::err("unknown job id; use action=list") };
                if a == "kill" {
                    let j = jobs.get_mut(&id).unwrap();
                    if j.exit.is_none() {
                        unsafe { libc::kill(-(j.child.id() as i32), libc::SIGKILL) };
                        let _ = j.child.wait();
                        j.exit = Some(-9);
                    }
                    return ToolOutput::ok(format!("job {id} killed\n{}", tail(&j.log, 2048)));
                }
                if a == "wait" {
                    let deadline = Instant::now() + Duration::from_secs(arg_opt_u64(&input, "timeout_secs").unwrap_or(30).min(600));
                    drop(jobs);
                    loop {
                        let mut jobs = JOBS.lock().unwrap();
                        let j = jobs.get_mut(&id).unwrap();
                        reap(j);
                        if j.exit.is_some() || Instant::now() >= deadline || ctx.cancel.is_cancelled() {
                            return ToolOutput::ok(format!("job {id} {}\n{}", status(j), tail(&j.log, TAIL)));
                        }
                        drop(jobs);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                let j = &jobs[&id];
                ToolOutput::ok(format!("job {id} {}\n{}", status(j), tail(&j.log, TAIL)))
            }
            _ => ToolOutput::err("action must be start, output, wait, kill or list"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    #[test]
    fn start_poll_wait_kill_and_isolation() {
        let c = ctx("job");
        let o = Job.call(&c, json!({"action":"start","command":"echo hi; echo err >&2; sleep 0.3; echo bye"}));
        assert!(!o.is_error, "{}", o.content);
        let id: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id,"timeout_secs":5}));
        assert!(w.content.contains("exited 0") && w.content.contains("hi") && w.content.contains("err") && w.content.contains("bye"), "{}", w.content);

        let o = Job.call(&c, json!({"action":"start","command":"sleep 30"}));
        let id2: u64 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        let w = Job.call(&c, json!({"action":"wait","id":id2,"timeout_secs":0}));
        assert!(w.content.contains("running"), "{}", w.content);
        assert!(Job.call(&c, json!({"action":"list"})).content.contains("sleep 30"));
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
}
