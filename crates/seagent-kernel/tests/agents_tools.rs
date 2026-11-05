//! Sub-agent / delegation tools end-to-end: `delegate_task`, `sessions_spawn`,
//! `agents_wait`, `sessions_yield`, `subagents`, `agents_list` driven by a scripted
//! provider through a real kernel (no network, no API key).

use seagent_core::*;
use seagent_kernel::approver::{Approval, ApprovalRequest, Approver};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::event::EventKind;
use seagent_kernel::hooks::{Hook, HookDecision, HookEvent};
use seagent_kernel::kernel::{new_kernel, EndReason, Kernel, Resolver, RunOpts};
use seagent_kernel::projection::project;
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ───────────────────────── scripted provider ─────────────────────────

type Step = Box<dyn FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send>;

struct Scripted {
    id: String,
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<ModelRequest>>,
}

impl Scripted {
    fn new(id: &str) -> Arc<Self> {
        Arc::new(Scripted { id: id.into(), steps: Mutex::new(VecDeque::new()), seen: Mutex::new(vec![]) })
    }
    fn push(&self, s: impl FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send + 'static) {
        self.steps.lock().unwrap().push_back(Box::new(s));
    }
    fn text(&self, t: &str) {
        let t = t.to_string();
        self.push(move |_| Ok(resp(vec![Block::text(t)], StopReason::EndTurn)));
    }
    /// A tool call whose input is computed from the request (e.g. an id from an earlier result).
    fn call_with(&self, name: &str, f: impl Fn(&ModelRequest) -> Value + Send + 'static) {
        let name = name.to_string();
        self.push(move |req| Ok(resp(vec![Block::ToolUse { id: format!("tu_{}", rand()), name, input: f(req) }], StopReason::ToolUse)));
    }
    fn call(&self, name: &str, input: Value) {
        let (name, input) = (name.to_string(), input);
        self.push(move |_| Ok(resp(vec![Block::ToolUse { id: format!("tu_{}", rand()), name, input }], StopReason::ToolUse)));
    }
    fn requests(&self) -> Vec<ModelRequest> {
        self.seen.lock().unwrap().clone()
    }
    fn left(&self) -> usize {
        self.steps.lock().unwrap().len()
    }
}

fn rand() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst).to_string()
}

fn rand_hex() -> String {
    format!("{:x}{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(), rand())
}

fn resp(content: Vec<Block>, stop: StopReason) -> ModelResponse {
    ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage { input_tokens: 10, output_tokens: 5, ..Default::default() }, model: String::new() }
}

impl Provider for Scripted {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: true, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        if cancel.is_cancelled() {
            return Err(ProviderError::new(ProviderErrorKind::Cancelled, "c"));
        }
        let step = self.steps.lock().unwrap().pop_front();
        match step {
            Some(s) => {
                let r = s(req);
                if let Ok(r) = &r {
                    on(StreamEvent::TextDelta(r.message.text()));
                }
                r
            }
            None => Ok(resp(vec![Block::text("(script exhausted)")], StopReason::EndTurn)),
        }
    }
}

struct Res(HashMap<String, Arc<Scripted>>);
impl Resolver for Res {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        self.0.get(id).cloned().map(|p| p as Arc<dyn Provider>).ok_or_else(|| format!("no provider {id}"))
    }
}

struct Yes;
impl Approver for Yes {
    fn approve(&self, _: &ApprovalRequest) -> Approval {
        Approval::Always
    }
    fn ask(&self, _: &str, q: &str) -> Result<String, String> {
        Ok(format!("answer to {q}"))
    }
}

// ───────────────────────── hook recorder ─────────────────────────

struct Recorder {
    seen: Arc<Mutex<Vec<(HookEvent, Value)>>>,
    wanted: Vec<HookEvent>,
}

impl Hook for Recorder {
    fn name(&self) -> String {
        "test-recorder".into()
    }
    fn wants(&self, event: HookEvent, _: Option<&str>) -> bool {
        self.wanted.contains(&event)
    }
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        self.seen.lock().unwrap().push((event, payload.clone()));
        Ok(HookDecision::Allow)
    }
}

// ───────────────────────── environment ─────────────────────────

struct Env {
    k: Kernel,
    /// The parent session's model.
    p: Arc<Scripted>,
    /// `model.subagent` — every child runs here, so the two scripts never interleave.
    c: Arc<Scripted>,
    ws: PathBuf,
    hooks: Arc<Mutex<Vec<(HookEvent, Value)>>>,
}

fn env_with(cfg_mut: impl FnOnce(&mut Config), workspace: Option<PathBuf>) -> Env {
    let root = seagent_core::tmp::scratch_path(format!("seagent-agents-tools-{}", rand_hex()));
    let ws = workspace.unwrap_or_else(|| root.join("ws"));
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
    let mut cfg = Config::default();
    cfg.model.default = "main/m1".into();
    cfg.model.subagent = "child/c1".into();
    cfg.model.aux = "main/m1".into();
    cfg.checkpoint.enabled = false;
    cfg_mut(&mut cfg);
    let p = Scripted::new("main");
    let c = Scripted::new("child");
    let mut map = HashMap::new();
    map.insert("main".to_string(), p.clone());
    map.insert("child".to_string(), c.clone());
    let vault = Arc::new(Vault::empty());
    vault.set("TOKEN", "s3cr3t-live-value").unwrap();
    let mut k = new_kernel(cfg, paths, Arc::new(Res(map)), vec![], vault, Arc::new(Yes));
    Arc::get_mut(&mut k).unwrap().retry_sleep = Some(Duration::from_millis(1));
    let hooks = Arc::new(Mutex::new(Vec::new()));
    k.add_hooks(vec![Arc::new(Recorder {
        seen: hooks.clone(),
        wanted: vec![HookEvent::SubagentProgress, HookEvent::SubagentDelivery, HookEvent::SubagentStart, HookEvent::SubagentStop],
    })]);
    Env { k, p, c, ws, hooks }
}

fn env() -> Env {
    env_with(|_| {}, None)
}

fn parent_session(e: &Env, prompt: &str) -> String {
    let id = e.k.create_session(&e.ws, None, None, Some("parent")).unwrap();
    e.k.submit(&id, prompt, "cli").unwrap();
    id
}

fn messages(e: &Env, id: &str) -> Vec<Message> {
    e.k.store.read(id).unwrap().into_iter().filter_map(|ev| match ev.kind {
        EventKind::Message { message, .. } => Some(message),
        _ => None,
    }).collect()
}

/// (content, is_error) of every tool result, in call order.
fn tool_results(e: &Env, id: &str) -> Vec<(String, bool)> {
    messages(e, id)
        .into_iter()
        .flat_map(|m| m.content)
        .filter_map(|b| match b {
            Block::ToolResult { content, is_error, .. } => Some((content, is_error)),
            _ => None,
        })
        .collect()
}

fn tool_json(e: &Env, id: &str, i: usize) -> Value {
    let (text, is_error) = tool_results(e, id)[i].clone();
    assert!(!is_error, "tool call {i} failed: {text}");
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("tool result {i} is not JSON: {text}"))
}

/// The newest sub-agent id mentioned in a request (spawn handle, or a list/info record).
fn run_id(req: &ModelRequest) -> Value {
    for m in req.messages.iter().rev() {
        for b in &m.content {
            if let Block::ToolResult { content, is_error, .. } = b {
                if *is_error {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(content) {
                    if let Some(id) = v["subagent"]["subagent_id"].as_str().or_else(|| v.get("subagent_id").and_then(Value::as_str)) {
                        return json!(id);
                    }
                }
            }
        }
    }
    Value::Null
}

/// The JSON of the most recent tool result in a request (scripted steps need ids
/// that only exist after the previous call).
fn last_tool_json(req: &ModelRequest) -> Value {
    for m in req.messages.iter().rev() {
        for b in &m.content {
            if let Block::ToolResult { content, is_error, .. } = b {
                if *is_error {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(content) {
                    return v;
                }
            }
        }
    }
    Value::Null
}

fn child_sessions(e: &Env, parent: &str) -> Vec<String> {
    e.k.store.list().into_iter().filter(|s| s.parent.as_deref() == Some(parent)).map(|s| s.id).collect()
}

fn child_events(e: &Env, id: &str) -> Vec<EventKind> {
    e.k.store.read(id).unwrap().into_iter().map(|ev| ev.kind).collect()
}

mod agents_tools {
    use super::*;

    // ───────────────────────── delegate_task ─────────────────────────

    #[test]
    fn delegate_task_sync_batch_returns_entries_and_live_transcripts() {
        let e = env();
        e.p.call("delegate_task", json!({"tasks": [{"goal": "first job"}, {"goal": "second job"}], "mode": "sync"}));
        e.p.text("all done");
        e.c.text("child alpha says done");
        e.c.text("child beta says done");
        let id = parent_session(&e, "delegate two jobs");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert!(o.reason.ok(), "{:?}", o.reason);

        let out = tool_json(&e, &id, 0);
        let results = out["results"].as_array().expect("results array");
        assert_eq!(results.len(), 2, "one entry per task: {out}");
        assert!(out["delegation_id"].as_str().is_some());

        // Both children exist as sessions whose parent is the caller.
        let children = child_sessions(&e, &id);
        assert_eq!(children.len(), 2, "two child sessions: {children:?}");
        for r in results {
            let child = r["session_id"].as_str().unwrap();
            assert!(children.contains(&child.to_string()), "child {child} not under the parent");
            assert_eq!(project(&e.k.store.read(child).unwrap()).parent.as_deref(), Some(id.as_str()));
            assert_eq!(r["status"], "completed", "{r}");
            let summary = r["summary"].as_str().unwrap();
            assert!(summary.contains("child") && summary.contains("done"), "{summary}");
            // Every entry names its live transcript, which holds the child's activity.
            let live = r["live_transcript"].as_str().unwrap_or_else(|| panic!("no live_transcript in {r}"));
            let text = std::fs::read_to_string(live).unwrap_or_else(|e| panic!("live.log {live}: {e}"));
            assert!(text.contains("assistant:"), "live log content: {text}");
        }
    }

    #[test]
    fn delegate_task_legacy_goal_and_top_level_defaults_apply_to_every_task() {
        let e = env();
        e.p.call("delegate_task", json!({"goal": "legacy brief", "mode": "sync"}));
        e.p.text("ok");
        e.c.text("legacy child done");
        let id = parent_session(&e, "legacy");
        e.k.run(&id, RunOpts::default()).unwrap();
        let out = tool_json(&e, &id, 0);
        assert_eq!(out["results"].as_array().unwrap().len(), 1);
        assert_eq!(out["results"][0]["goal"], "legacy brief");
        let child = out["results"][0]["session_id"].as_str().unwrap().to_string();
        let req = e.c.requests()[0].clone();
        assert!(req.messages.iter().any(|m| m.text().contains("legacy brief")), "child never saw the goal");
        assert_eq!(project(&e.k.store.read(&child).unwrap()).model, "child/c1", "model.subagent applies to children");
    }

    #[test]
    fn delegate_task_reports_missing_targets_and_unknown_actions() {
        let e = env();
        e.p.call("delegate_task", json!({"action": "steer", "message": "go left"}));
        e.p.call("delegate_task", json!({"action": "steer", "subagent_id": "nope"}));
        e.p.call("delegate_task", json!({"action": "steer", "subagent_id": "nope", "message": "x"}));
        e.p.call("delegate_task", json!({"action": "dance"}));
        e.p.call("delegate_task", json!({"tasks": []}));
        e.p.text("done");
        let id = parent_session(&e, "errors");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = tool_results(&e, &id);
        assert!(r[0].1 && r[0].0.contains("requires `subagent_id`"), "{}", r[0].0);
        assert!(r[1].1 && r[1].0.contains("non-empty `message`"), "{}", r[1].0);
        assert!(r[2].1 && r[2].0.contains("no sub-agent `nope`"), "{}", r[2].0);
        assert!(r[3].1 && r[3].0.contains("unknown action `dance`"), "{}", r[3].0);
        assert!(r[4].1 && r[4].0.contains("no tasks given"), "{}", r[4].0);
    }

    #[test]
    fn background_delegation_delivers_completion_and_fires_hooks() {
        let e = env();
        e.p.call("delegate_task", json!({"tasks": [{"goal": "background job"}], "background": true}));
        e.p.text("dispatched, ending my turn");
        e.p.text("consumed the completion");
        e.c.text("the background child finished");

        let id = parent_session(&e, "background work");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert!(o.reason.ok(), "{:?}", o.reason);

        // Dispatch returned a handle, not a result.
        let handle = tool_json(&e, &id, 0);
        assert_eq!(handle["status"], "dispatched");
        let sub = &handle["subagents"][0];
        let child = sub["session_id"].as_str().unwrap().to_string();
        assert!(sub["subagent_id"].as_str().is_some());
        assert!(sub["live_transcript"].as_str().is_some_and(|p| Path::new(p).exists() || !p.is_empty()));

        // The completion landed in the parent's inbox (announce) and was consumed.
        let inbox: Vec<String> = child_events(&e, &id)
            .into_iter()
            .filter_map(|k| match k {
                EventKind::Inbox { source, text, .. } if source == "subagent" => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(inbox.len(), 1, "exactly one completion message: {inbox:?}");
        assert!(inbox[0].contains("Background delegation") && inbox[0].contains("the background child finished"), "{}", inbox[0]);
        assert!(inbox[0].contains(child.as_str()), "completion names the child session");

        let seen = e.hooks.lock().unwrap().clone();
        let delivery: Vec<&Value> = seen.iter().filter(|(ev, _)| *ev == HookEvent::SubagentDelivery).map(|(_, p)| p).collect();
        assert_eq!(delivery.len(), 1, "one SubagentDelivery: {seen:?}");
        assert!(delivery[0]["delegation_id"].as_str().is_some());
        assert_eq!(delivery[0]["results"][0]["session_id"].as_str(), Some(child.as_str()));
        assert!(seen.iter().any(|(ev, p)| *ev == HookEvent::SubagentStart && p["child_subagent_id"].as_str().is_some()));
        assert!(seen.iter().any(|(ev, _)| *ev == HookEvent::SubagentStop));
        // Progress: at least the start/end phases of the run.
        let phases: Vec<Value> = seen.iter().filter(|(ev, _)| *ev == HookEvent::SubagentProgress).map(|(_, p)| p["phase"].clone()).collect();
        assert!(phases.contains(&json!("started")) && phases.contains(&json!("ended")), "phases: {phases:?}");
        let progress_lines = seen.iter().filter(|(ev, p)| *ev == HookEvent::SubagentProgress && p.get("progress").is_some()).count();
        assert!(progress_lines > 0, "live_log never emitted a progress hook: {seen:?}");
    }

    #[test]
    fn delegate_task_output_schema_yields_structured_result() {
        let e = env();
        e.p.call(
            "delegate_task",
            json!({"tasks": [{"goal": "return json", "output_schema": {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}}], "mode": "sync"}),
        );
        e.p.text("ok");
        e.c.text("{\"answer\": \"42\"}");
        let id = parent_session(&e, "schema");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = &tool_json(&e, &id, 0)["results"][0];
        assert_eq!(r["schema_valid"], true, "{r}");
        assert_eq!(r["structured"]["answer"], "42");
        assert_eq!(r["summary"].as_str().unwrap(), "{\"answer\": \"42\"}");
    }

    #[test]
    fn delegate_task_output_schema_records_errors_after_one_correction() {
        let e = env();
        e.p.call(
            "delegate_task",
            json!({"tasks": [{"goal": "return json", "output_schema": {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}}], "mode": "sync"}),
        );
        e.p.text("ok");
        e.c.text("I could not do it.");
        e.c.text("Sorry, still prose.");
        let id = parent_session(&e, "schema failure");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = &tool_json(&e, &id, 0)["results"][0];
        assert_eq!(r["schema_valid"], false, "{r}");
        assert!(!r["schema_errors"].as_array().unwrap().is_empty(), "{r}");
        // The raw text is never discarded.
        assert!(r["summary"].as_str().unwrap().contains("prose"), "{r}");
        // Exactly one bounded correction turn reached the child.
        assert_eq!(e.c.requests().len(), 2, "one retry only");
    }

    #[test]
    fn worktree_isolation_gives_the_child_its_own_checkout() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-agents-wt-{}", rand_hex()));
        std::fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str], cwd: &Path| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=seagent", "-c", "user.email=seagent@localhost", "-c", "commit.gpgsign=false"])
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git");
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        git(&["init", "-q"], &root);
        std::fs::write(root.join("README.md"), "base\n").unwrap();
        git(&["add", "-A"], &root);
        git(&["commit", "-qm", "base"], &root);

        let e = env_with(|_| {}, Some(root.clone()));
        let repo = e.ws.clone();
        // While the child runs, its worktree must be a real git checkout of the repo.
        let seen_ws = Arc::new(Mutex::new(Vec::<String>::new()));
        let listing = Arc::new(Mutex::new(String::new()));
        let (w, l) = (seen_ws.clone(), listing.clone());
        let repo2 = repo.clone();
        e.c.push(move |req| {
            w.lock().unwrap().push(req.system.iter().map(|s| s.text.clone()).collect::<Vec<_>>().join("\n"));
            let out = std::process::Command::new("git").args(["worktree", "list", "--porcelain"]).current_dir(&repo2).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            *l.lock().unwrap() = out;
            Ok(resp(vec![Block::text("worktree child done")], StopReason::EndTurn))
        });
        e.p.call("delegate_task", json!({"tasks": [{"goal": "isolated edit", "worktree": true}], "mode": "sync"}));
        e.p.text("ok");
        let id = parent_session(&e, "worktree");
        e.k.run(&id, RunOpts::default()).unwrap();

        let r = &tool_json(&e, &id, 0)["results"][0];
        let wt = &r["worktree"];
        let path = wt["path"].as_str().unwrap_or_else(|| panic!("no worktree report: {r}"));
        assert!(path.contains(".worktrees/subagent-"), "{path}");
        assert!(wt["branch"].as_str().unwrap_or_default().starts_with("seagent/subagent-"), "{wt}");
        // The child really was started in that worktree…
        let prompt = seen_ws.lock().unwrap().join("\n");
        assert!(prompt.contains(path), "child workspace was not the worktree: {prompt}");
        // …and git knew about it while it ran.
        let list = listing.lock().unwrap().clone();
        assert!(list.contains(path), "git worktree list did not show {path}:\n{list}");
        // Finalized: a clean worktree is pruned and its branch removed with it.
        assert_eq!(wt["pruned"], true, "{wt}");
        assert!(!Path::new(path).exists(), "clean worktree left behind at {path}");
    }

    // ───────────────────────── sessions_spawn ─────────────────────────

    #[test]
    fn sessions_spawn_returns_a_handle_and_runs_as_the_named_agent() {
        let e = env_with(
            |cfg| {
                cfg.agents.insert(
                    "ops".into(),
                    seagent_kernel::agents::AgentDef { name: "Ops".into(), description: "operations agent".into(), model: "child/c1".into(), ..Default::default() },
                );
            },
            None,
        );
        e.p.call("sessions_spawn", json!({"task": "check the disk", "agentId": "ops", "taskName": "disk-run", "label": "Disk check", "visible": true}));
        e.p.text("dispatched");
        e.p.text("read the completion");
        e.c.text("disk is fine");

        let id = parent_session(&e, "spawn");
        e.k.run(&id, RunOpts::default()).unwrap();
        let h = tool_json(&e, &id, 0);
        let sub_id = h["subagent_id"].as_str().unwrap_or_else(|| panic!("no subagent_id: {h}"));
        let session = h["session_id"].as_str().unwrap_or_else(|| panic!("no session_id: {h}"));
        assert!(!h["live_transcript"].as_str().unwrap_or_default().is_empty(), "{h}");
        assert_eq!(h["status"], "accepted");
        assert_eq!(h["visible"], true);
        // `visible:true` publishes a real sidebar session (OpenClaw sessions-visible), so the
        // handle carries its row and the session is listed even without include_children.
        assert_eq!(h["sidebar"]["label"], "Disk check");
        assert_eq!(h["cleanup"], "keep");
        assert!(h["thread"].is_null(), "a visible session is not a thread: {h}");
        assert_eq!(h["background"], true);

        // The child session runs as the agent and is announced.
        let ev = child_events(&e, session);
        assert!(ev.iter().any(|k| matches!(k, EventKind::Agent { agent, .. } if agent == "ops")), "{ev:?}");
        assert_eq!(project(&e.k.store.read(session).unwrap()).model, "child/c1");
        let inbox: Vec<String> = child_events(&e, &id).into_iter().filter_map(|k| match k {
            EventKind::Inbox { source, text, .. } if source == "subagent" => Some(text),
            _ => None,
        }).collect();
        assert_eq!(inbox.len(), 1, "visible/announce children report back: {inbox:?}");
        assert!(inbox[0].contains(sub_id), "{}", inbox[0]);
    }

    #[test]
    fn sessions_spawn_validates_task_and_context() {
        let e = env();
        e.p.call("sessions_spawn", json!({}));
        e.p.call("sessions_spawn", json!({"task": "x", "context": "weird"}));
        e.p.text("done");
        let id = parent_session(&e, "spawn errors");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = tool_results(&e, &id);
        assert!(r[0].1 && r[0].0.contains("non-empty `task`"), "{}", r[0].0);
        assert!(r[1].1 && r[1].0.contains("unknown context `weird`"), "{}", r[1].0);
        assert!(child_sessions(&e, &id).is_empty(), "no child session for a rejected call");
    }

    #[test]
    fn sessions_spawn_sync_returns_the_result_in_the_call() {
        let e = env();
        e.p.call("sessions_spawn", json!({"task": "quick job", "background": false, "runTimeoutSeconds": 30}));
        e.p.text("ok");
        e.c.text("quick job result");
        let id = parent_session(&e, "sync spawn");
        e.k.run(&id, RunOpts::default()).unwrap();
        let h = tool_json(&e, &id, 0);
        assert_eq!(h["status"], "completed");
        assert_eq!(h["background"], false);
        assert!(h["summary"].as_str().unwrap().contains("quick job result"), "{h}");
        assert!(h["live_transcript"].as_str().is_some(), "sync handle keeps the transcript path: {h}");
    }

    #[test]
    fn agents_wait_collects_an_unannounced_run() {
        let e = env();
        e.p.call("sessions_spawn", json!({"task": "silent job", "announce": false}));
        e.p.call_with("agents_wait", |req| {
            let h = last_tool_json(req);
            json!({"ids": [h["subagent_id"].clone()], "timeout_seconds": 20})
        });
        e.p.text("collected");
        e.c.text("silent job result");

        let id = parent_session(&e, "collect");
        e.k.run(&id, RunOpts::default()).unwrap();
        let h = tool_json(&e, &id, 0);
        assert_eq!(h["status"], "accepted");
        let waited = tool_json(&e, &id, 1);
        let completed = waited["completed"].as_array().unwrap_or_else(|| panic!("no completed: {waited}"));
        assert_eq!(completed.len(), 1, "{waited}");
        assert_eq!(completed[0]["runId"], h["subagent_id"]);
        assert_eq!(completed[0]["status"], "done");
        assert!(completed[0]["result"].as_str().unwrap().contains("silent job result"), "{waited}");
        // announce=false → no completion message.
        let inbox = child_events(&e, &id).into_iter().filter(|k| matches!(k, EventKind::Inbox { source, .. } if source == "subagent")).count();
        assert_eq!(inbox, 0, "no completion message for announce=false");
    }

    #[test]
    fn agents_wait_requires_ids() {
        let e = env();
        e.p.call("agents_wait", json!({"ids": []}));
        e.p.text("done");
        let id = parent_session(&e, "wait errors");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = tool_results(&e, &id);
        assert!(r[0].1 && r[0].0.contains("needs `ids`"), "{}", r[0].0);
    }

    // ───────────────────────── subagents (control plane) ─────────────────────────

    #[test]
    fn subagents_lists_info_stops_and_waits_for_a_live_run() {
        let e = env();
        // The child blocks until the parent has stopped it, so the control actions hit a live run.
        let release = Arc::new(AtomicBool::new(false));
        let r2 = release.clone();
        e.c.push(move |_| {
            let started = Instant::now();
            while !r2.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(20) {
                std::thread::sleep(Duration::from_millis(20));
            }
            // A tool call, not an answer: the child needs another step, where `stop` takes effect
            // (a real provider also honours the cancelled request the same way).
            Ok(resp(vec![Block::ToolUse { id: "tu_child".into(), name: "noop".into(), input: json!({}) }], StopReason::ToolUse))
        });
        e.c.text("this must never be requested");

        e.p.call("delegate_task", json!({"tasks": [{"goal": "long job"}]}));
        e.p.call_with("subagents", |_| json!({"action": "list"}));
        e.p.call_with("subagents", |req| json!({"action": "info", "subagent_id": last_tool_json(req)["subagents"][0]["subagent_id"].clone()}));
        e.p.call_with("delegate_task", |req| json!({"action": "steer", "subagent_id": last_tool_json(req)["subagent"]["subagent_id"].clone(), "message": "skip the network step"}));
        let rel = release.clone();
        e.p.push(move |req| {
            let id = run_id(req);
            rel.store(true, Ordering::SeqCst);
            Ok(resp(vec![Block::ToolUse { id: format!("tu_{}", rand()), name: "subagents".into(), input: json!({"action": "stop", "subagent_id": id}) }], StopReason::ToolUse))
        });
        e.p.call_with("subagents", |req| json!({"action": "wait", "ids": [last_tool_json(req)["subagent_id"].clone()], "timeout_seconds": 20}));
        e.p.text("done");

        let id = parent_session(&e, "control plane");
        e.k.run(&id, RunOpts::default()).unwrap();

        let list = tool_json(&e, &id, 1);
        let runs = list["subagents"].as_array().unwrap();
        assert_eq!(runs.len(), 1, "{list}");
        assert_eq!(runs[0]["goal"], "long job");
        assert_eq!(runs[0]["status"], "running");
        assert!(runs[0]["live_transcript"].as_str().is_some());

        let info = tool_json(&e, &id, 2);
        assert_eq!(info["subagent"]["subagent_id"], runs[0]["subagent_id"]);
        assert_eq!(info["subagent"]["parent_session"], json!(id));

        let steer = tool_json(&e, &id, 3);
        assert_eq!(steer["action"], "steer", "{steer}");
        assert_eq!(steer["queued"], true, "a live child accepts steering: {steer}");
        assert_eq!(steer["running"], true, "{steer}");

        let stop = tool_json(&e, &id, 4);
        assert_eq!(stop["stopped"], true, "{stop}");
        assert_eq!(stop["action"], "stop");

        let waited = tool_json(&e, &id, 5);
        let done = waited["completed"].as_array().unwrap();
        assert_eq!(done.len(), 1, "{waited}");
        assert_eq!(done[0]["status"], "killed", "a stopped child reports killed: {waited}");
    }

    #[test]
    fn subagents_errors_are_specific() {
        let e = env();
        e.p.call("subagents", json!({"action": "info"}));
        e.p.call("subagents", json!({"action": "info", "subagent_id": "sa-9-deadbeef"}));
        e.p.call("subagents", json!({"action": "cancel"}));
        e.p.call("subagents", json!({"action": "explode"}));
        e.p.call("subagents", json!({"action": "wait"}));
        e.p.text("done");
        let id = parent_session(&e, "control errors");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = tool_results(&e, &id);
        assert!(r[0].1 && r[0].0.contains("action='info' requires `subagent_id`"), "{}", r[0].0);
        assert!(r[1].1 && r[1].0.contains("no sub-agent"), "{}", r[1].0);
        assert!(r[2].1 && r[2].0.contains("action='cancel' requires `subagent_id`"), "{}", r[2].0);
        assert!(r[3].1 && r[3].0.contains("unknown action `explode`"), "{}", r[3].0);
        let empty = tool_json(&e, &id, 4);
        assert_eq!(empty["note"], "no live sub-agent of this conversation");
    }

    // ───────────────────────── sessions_yield ─────────────────────────

    #[test]
    fn sessions_yield_ends_the_turn() {
        let e = env();
        e.p.call("sessions_yield", json!({"message": "waiting for the background child"}));
        e.p.text("this must never be requested");
        let id = parent_session(&e, "yield");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert_eq!(o.reason, EndReason::Done);
        let out = tool_json(&e, &id, 0);
        assert_eq!(out["status"], "yielded");
        assert!(out["message"].as_str().unwrap().contains("Turn ended"), "{out}");
        assert!(out["message"].as_str().unwrap().contains("waiting for the background child"));
        assert_eq!(e.p.left(), 1, "the turn ended before the next step");
        assert_eq!(e.p.requests().len(), 1, "no further model call after yielding");
    }

    #[test]
    fn sessions_yield_still_ends_the_turn_when_nothing_is_pending() {
        let e = env();
        e.p.call("sessions_yield", json!({}));
        let id = parent_session(&e, "yield empty");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert_eq!(o.reason, EndReason::Done);
        let out = tool_json(&e, &id, 0);
        assert_eq!(out["pending_children"], 0);
        assert!(out["message"].as_str().unwrap().contains("No background sub-agent"));
    }

    // ───────────────────────── agents_list ─────────────────────────

    #[test]
    fn agents_list_names_configured_agents_and_the_default() {
        let e = env_with(
            |cfg| {
                cfg.agents.insert(
                    "ops".into(),
                    seagent_kernel::agents::AgentDef { name: "Ops".into(), description: "operations".into(), model: "child/c1".into(), default: true, ..Default::default() },
                );
                cfg.agents.insert("writer".into(), seagent_kernel::agents::AgentDef { name: "Writer".into(), description: "prose".into(), ..Default::default() });
            },
            None,
        );
        e.p.call("agents_list", json!({}));
        e.p.text("done");
        let id = parent_session(&e, "list agents");
        e.k.run(&id, RunOpts::default()).unwrap();
        let v = tool_json(&e, &id, 0);
        assert_eq!(v["default_agent"], "ops");
        assert_eq!(v["requester_agent"], "ops", "the session's agent falls back to the default");
        let agents = v["agents"].as_array().unwrap();
        let ops = agents.iter().find(|a| a["id"] == "ops").expect("ops listed");
        assert_eq!(ops["name"], "Ops");
        assert_eq!(ops["model"], "child/c1");
        assert_eq!(ops["default"], true);
        assert_eq!(ops["description"], "operations");
        let writer = agents.iter().find(|a| a["id"] == "writer").expect("writer listed");
        assert_eq!(writer["default"], false);
        assert_eq!(writer["model"], "child/c1", "an agent without a model runs the subagent model");
        assert!(agents.iter().any(|a| a["id"] == "main"), "the built-in agent is always listed: {v}");
    }

    /// `new_kernel` wires the tools, so the model can reach them without any front end
    /// registering anything (this is the wiring proof for the whole file).
    #[test]
    fn kernel_registers_the_delegation_tools() {
        let e = env();
        let names: Vec<String> = e.k.specs().into_iter().map(|s| s.name).collect();
        for n in ["delegate_task", "sessions_spawn", "agents_wait", "sessions_yield", "subagents", "agents_list"] {
            assert!(names.contains(&n.to_string()), "{n} is not in the kernel's tool list: {names:?}");
        }
    }

    /// The child's live transcript is written for every run, and secrets are redacted on
    /// the way in (Hermes delegation_live_log).
    #[test]
    fn live_log_is_written_and_redacted() {
        let e = env();
        e.p.call("delegate_task", json!({"tasks": [{"goal": "leak the token"}], "mode": "sync"}));
        e.p.text("ok");
        e.c.text("the token is s3cr3t-live-value, keep it quiet");
        let id = parent_session(&e, "redaction");
        e.k.run(&id, RunOpts::default()).unwrap();
        let r = &tool_json(&e, &id, 0)["results"][0];
        let live = r["live_transcript"].as_str().unwrap().to_string();
        let text = std::fs::read_to_string(&live).unwrap_or_else(|err| panic!("live.log {live}: {err}"));
        assert!(text.contains("assistant:"), "live log has content: {text}");
        assert!(!text.contains("s3cr3t-live-value"), "the live log leaked the secret: {text}");
        assert!(text.contains("{{secret:TOKEN}}"), "redacted placeholder expected: {text}");
        assert!(!r.to_string().contains("s3cr3t-live-value"), "the result leaked the secret: {r}");
    }

    #[test]
    fn tool_specs_are_model_facing() {
        let specs: HashMap<String, ToolSpec> = seagent_kernel::subagents::tools().iter().map(|t| (t.spec().name.clone(), t.spec())).collect();
        for name in ["delegate_task", "sessions_spawn", "agents_wait", "sessions_yield", "subagents", "agents_list"] {
            let s = specs.get(name).unwrap_or_else(|| panic!("{name} is not registered"));
            assert!(s.description.len() > 80, "{name}: description for the model is too thin");
            assert_eq!(s.input_schema["type"], "object", "{name}: schema must be an object");
        }
        // Spawning and control calls change the world; only the read-only listing may be parallel.
        for name in ["delegate_task", "sessions_spawn", "agents_wait", "sessions_yield", "subagents"] {
            assert!(!specs[name].parallel_safe, "{name}: must not run in parallel with other calls");
        }
        assert!(specs["agents_list"].parallel_safe, "agents_list is read-only");
        assert!(specs["delegate_task"].pinned && specs["sessions_spawn"].pinned && specs["sessions_yield"].pinned, "delegation must stay visible to the model");
        assert!(!specs["delegate_task"].idempotent, "spawning twice is not idempotent");
        assert!(seagent_kernel::subagents::tools().iter().any(|t| matches!(t.effects(&dummy_ctx(), &json!({})).as_slice(), [Effect::Spawn])), "delegate_task announces Effect::Spawn");
    }

    /// A tool context with a foreign host: every tool must refuse politely, never panic.
    fn dummy_ctx() -> ToolCtx {
        struct NoHost;
        impl ToolHost for NoHost {
            fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
                Err("no host".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("no host".into())
            }
        }
        ToolCtx { workspace: seagent_core::tmp::scratch("seagent-ws"), session_id: "s".into(), artifacts: seagent_core::tmp::scratch("seagent-ws"), home: seagent_core::tmp::scratch("seagent-ws"), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|_: &str| String::new()) }
    }

    #[test]
    fn tools_refuse_a_foreign_host() {
        let ctx = dummy_ctx();
        for t in seagent_kernel::subagents::tools() {
            let name = t.spec().name;
            let out = t.call(&ctx, json!({"task": "x", "goal": "x", "ids": ["a"], "action": "list"}));
            assert!(out.is_error, "{name} ran without the seagent kernel");
            assert!(out.content.contains("needs the seagent kernel"), "{name}: {}", out.content);
        }
    }

    // ───────── C3: one call dispatches every task, in parallel, without the model ─────────
    // The original bug: the orchestrator said "dispatch six" but the model emitted one tool
    // call with one task, so five pieces of work never ran. The fix is in the tool's shape —
    // `tasks` is an array and one call fans out — and this test pins it: six tasks in ONE
    // call must produce six children that are all *running at the same time*. A barrier makes
    // that a fact, not a timing guess: if dispatch were serial the first child would starve.

    #[test]
    fn one_call_dispatches_all_six_tasks_in_parallel() {
        use std::sync::atomic::AtomicUsize;
        let e = env_with(|c| c.delegation.max_concurrent_children = 10, None);
        let arrived = Arc::new(AtomicUsize::new(0));
        let starved = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        for i in 0..6 {
            tasks.push(json!({"goal": format!("job {i}"), "context": "barrier"}));
        }
        // Each child blocks until all six are live; a five-second wait means the dispatcher
        // started them one after another. One scripted step per child (they pop in any order).
        for _ in 0..6 {
            let (a, s) = (arrived.clone(), starved.clone());
            e.c.push(move |_| {
                a.fetch_add(1, Ordering::SeqCst);
                let start = Instant::now();
                while a.load(Ordering::SeqCst) < 6 && start.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if a.load(Ordering::SeqCst) < 6 {
                    s.store(true, Ordering::SeqCst);
                }
                Ok(resp(vec![Block::text(format!("job done, {} live", a.load(Ordering::SeqCst)))], StopReason::EndTurn))
            });
        }
        e.p.call("delegate_task", json!({"tasks": tasks, "mode": "sync"}));
        e.p.text("all six are in");

        let id = parent_session(&e, "dispatch six at once");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert!(o.reason.ok(), "{:?}", o.reason);

        let out = tool_json(&e, &id, 0);
        let results = out["results"].as_array().expect("results array");
        assert_eq!(results.len(), 6, "one entry per task in a single call: {out}");
        assert_eq!(child_sessions(&e, &id).len(), 6, "six child sessions exist");
        assert!(!starved.load(Ordering::SeqCst), "the tasks ran one after another; the batch must fan out");
        assert_eq!(arrived.load(Ordering::SeqCst), 6, "every task reached the model");
        for r in results {
            assert_eq!(r["status"], "completed", "{r}");
        }
    }

    /// C4: steering is not just "queued: true" — the text must reach the live child's next
    /// model request, so a running agent can be corrected without being stopped.
    #[test]
    fn steered_text_reaches_the_childs_next_request() {
        let e = env();
        // First child step: a tool call, so the child needs another step (where steering lands).
        e.c.push(|_| Ok(resp(vec![Block::ToolUse { id: "tu_child".into(), name: "noop".into(), input: json!({}) }], StopReason::ToolUse)));
        e.c.text("followed the steer");
        // Parent: dispatch in the background, then steer the live child, then end the turn.
        e.p.call("delegate_task", json!({"tasks": [{"goal": "long job"}]}));
        e.p.call_with("delegate_task", |req| {
            let id = last_tool_json(req)["subagents"][0]["subagent_id"].clone();
            json!({"action": "steer", "subagent_id": id, "message": "use the blue path"})
        });
        e.p.text("steered");

        let id = parent_session(&e, "steer the child");
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert!(o.reason.ok(), "{:?}", o.reason);
        let steer = tool_json(&e, &id, 1);
        assert_eq!(steer["queued"], true, "{steer}");

        // The child saw it: some later request of the child carries the steer text.
        let seen = e.c.requests();
        assert!(seen.len() >= 2, "the child ran a second step: {}", seen.len());
        let last = serde_json::to_string(&seen.last().unwrap().messages).unwrap();
        assert!(last.contains("use the blue path"), "the steer never reached the child: {last}");
    }

    /// The same guarantee for background dispatch: one call, six handles, no waiting.
    #[test]
    fn background_batch_returns_one_handle_per_task_immediately() {
        let e = env_with(|c| c.delegation.max_concurrent_children = 10, None);
        let tasks: Vec<Value> = (0..6).map(|i| json!({"goal": format!("bg {i}")})).collect();
        e.p.call("delegate_task", json!({"tasks": tasks, "background": true, "announce": false}));
        e.p.text("dispatched");
        let id = parent_session(&e, "background six");
        let started = Instant::now();
        let o = e.k.run(&id, RunOpts::default()).unwrap();
        assert!(o.reason.ok(), "{:?}", o.reason);
        assert!(started.elapsed() < Duration::from_secs(20), "background dispatch must not block the turn");

        let out = tool_json(&e, &id, 0);
        assert_eq!(out["status"], "dispatched", "{out}");
        let handles = out["subagents"].as_array().expect("handles");
        assert_eq!(handles.len(), 6, "one handle per task: {out}");
        for h in handles {
            assert!(h["subagent_id"].as_str().is_some_and(|s| !s.is_empty()), "{h}");
            assert!(h["session_id"].as_str().is_some(), "{h}");
        }
        // The children are real sessions under this parent, not promises.
        assert_eq!(child_sessions(&e, &id).len(), 6);
    }
}
