//! Kernel runner tests against a scripted provider. Mostly failure paths.
#![allow(clippy::type_complexity)]

use ark_core::*;
use ark_kernel::approver::{Approval, ApprovalRequest, Approver, Policy};
use ark_kernel::config::{Config, Paths};
use ark_kernel::event::{EventKind, LOG_VERSION};
use ark_kernel::kernel::{new_kernel, EndReason, Kernel, Resolver, RunOpts};
use ark_kernel::ledger::{Budget, Ledger};
use ark_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ───────────── scripted provider ─────────────

type Step = Box<dyn FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send>;

struct Scripted {
    id: String,
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<ModelRequest>>,
    window: u64,
}

impl Scripted {
    fn new(id: &str) -> Arc<Self> {
        Arc::new(Scripted { id: id.into(), steps: Mutex::new(VecDeque::new()), seen: Mutex::new(vec![]), window: 200_000 })
    }
    fn push(&self, s: impl FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send + 'static) {
        self.steps.lock().unwrap().push_back(Box::new(s));
    }
    fn text(&self, t: &str) {
        let t = t.to_string();
        self.push(move |_| Ok(resp(vec![Block::text(t)], StopReason::EndTurn)));
    }
    fn call(&self, name: &str, input: Value) {
        let (name, input) = (name.to_string(), input);
        self.push(move |_| Ok(resp(vec![Block::ToolUse { id: format!("tu_{}", rand()), name, input }], StopReason::ToolUse)));
    }
    fn calls(&self, list: Vec<(&str, Value)>) {
        let blocks: Vec<Block> = list.into_iter().map(|(n, i)| Block::ToolUse { id: format!("tu_{}", rand()), name: n.into(), input: i }).collect();
        self.push(move |_| Ok(resp(blocks, StopReason::ToolUse)));
    }
    fn fail(&self, kind: ProviderErrorKind) {
        self.push(move |_| Err(ProviderError::new(kind, "scripted failure")));
    }
    fn requests(&self) -> Vec<ModelRequest> {
        self.seen.lock().unwrap().clone()
    }
}

fn rand() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst).to_string()
}

fn resp(content: Vec<Block>, stop: StopReason) -> ModelResponse {
    ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage { input_tokens: 100, output_tokens: 20, ..Default::default() }, model: String::new() }
}

impl Provider for Scripted {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, _: &str) -> ModelCaps {
        // Vision-capable on purpose: the send path now degrades images for text-only models
        // (tests/imgprep_send.rs pins that), so this fake keeps every image it is given.
        ModelCaps { context_window: self.window, max_output: 8192, tools: true, vision: true, explicit_cache: false }
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

// ───────────── fake tools ─────────────

struct FTool {
    spec: ToolSpec,
    f: Box<dyn Fn(&ToolCtx, &Value) -> ToolOutput + Send + Sync>,
    effects: Box<dyn Fn(&Value) -> Vec<Effect> + Send + Sync>,
    calls: Arc<AtomicUsize>,
}
impl Tool for FTool {
    fn spec(&self) -> ToolSpec {
        self.spec.clone()
    }
    fn effects(&self, _: &ToolCtx, i: &Value) -> Vec<Effect> {
        (self.effects)(i)
    }
    fn call(&self, c: &ToolCtx, i: Value) -> ToolOutput {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.f)(c, &i)
    }
}

fn tool(name: &str, parallel: bool, idempotent: bool, pinned: bool, f: impl Fn(&ToolCtx, &Value) -> ToolOutput + Send + Sync + 'static) -> (Arc<dyn Tool>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let t = FTool {
        spec: ToolSpec { name: name.into(), description: format!("{name} tool."), input_schema: json!({"type":"object"}), parallel_safe: parallel, idempotent, pinned },
        f: Box::new(f),
        effects: Box::new(|i| i.get("cmd").and_then(|c| c.as_str()).map(|c| vec![Effect::Exec { command: c.into() }]).unwrap_or_default()),
        calls: calls.clone(),
    };
    (Arc::new(t), calls)
}

struct Env {
    k: Kernel,
    p: Arc<Scripted>,
    fb: Arc<Scripted>,
    ws: PathBuf,
    calls: HashMap<&'static str, Arc<AtomicUsize>>,
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

fn env_with(cfg_mut: impl FnOnce(&mut Config), approver: Arc<dyn Approver>) -> Env {
    let root = std::env::temp_dir().join(format!("ark-k-{}", rand_hex()));
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    let mut cfg = Config::default();
    cfg.model.default = "main/m1".into();
    cfg.model.fallback = vec!["backup/m2".into()];
    cfg.checkpoint.enabled = false;
    cfg.runner.max_retries = 2;
    cfg_mut(&mut cfg);
    let p = Scripted::new("main");
    let fb = Scripted::new("backup");
    let mut map = HashMap::new();
    map.insert("main".to_string(), p.clone());
    map.insert("backup".to_string(), fb.clone());
    let mut calls = HashMap::new();
    let mut tools: Vec<Arc<dyn Tool>> = vec![];
    let mut add = |name: &'static str, t: (Arc<dyn Tool>, Arc<AtomicUsize>)| {
        calls.insert(name, t.1);
        tools.push(t.0);
    };
    add("echo", tool("echo", true, true, true, |_, i| ToolOutput::ok(i.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string())));
    add("sleep", tool("sleep", true, true, true, |_, i| {
        std::thread::sleep(Duration::from_millis(i.get("ms").and_then(|v| v.as_u64()).unwrap_or(10)));
        ToolOutput::ok("slept")
    }));
    add("boom", tool("boom", false, false, true, |_, _| panic!("kaboom")));
    add("sh", tool("sh", false, false, true, |_, i| ToolOutput::ok(format!("ran {}", i["cmd"].as_str().unwrap_or("")))));
    add("big", tool("big", false, true, true, |_, _| ToolOutput::ok("x".repeat(100_000))));
    add("shell", tool("shell", false, false, true, |_, i| {
        let out = std::process::Command::new("bash").arg("-c").arg(i["command"].as_str().unwrap_or("")).output().unwrap();
        ToolOutput::ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }));
    add("leak", tool("leak", false, true, true, |_, _| ToolOutput::ok("token is supersecret-value-123")));
    add("write", tool("write", false, false, true, |c, i| {
        let p = c.workspace.join(i["path"].as_str().unwrap_or("f.txt"));
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(&p, i["body"].as_str().unwrap_or("")).unwrap();
        ToolOutput::ok(format!("wrote {}", p.display()))
    }));
    add("hidden", tool("hidden", false, true, false, |_, _| ToolOutput::ok("hidden ran")));
    add("wsfile", tool("wsfile", false, false, true, |c, i| {
        std::fs::write(c.workspace.join(i["name"].as_str().unwrap_or("f.txt")), "x").unwrap();
        ToolOutput::ok(format!("wrote in {}", c.workspace.display()))
    }));
    add("spawn", tool("spawn", false, false, true, |c, i| match c.host.spawn_agent(serde_json::from_value(i.clone()).unwrap_or_default(), &c.cancel) {
        Ok(s) => ToolOutput::ok(s),
        Err(e) => ToolOutput::err(e),
    }));
    {
        let calls_typed = Arc::new(AtomicUsize::new(0));
        let t = FTool {
            spec: ToolSpec { name: "typed".into(), description: "typed tool.".into(), input_schema: json!({"type":"object","properties":{"items":{"type":"array"},"n":{"type":"integer"}}}), parallel_safe: false, idempotent: true, pinned: true },
            f: Box::new(|_, i| ToolOutput::ok(i.to_string())),
            effects: Box::new(|_| vec![]),
            calls: calls_typed.clone(),
        };
        add("typed", (Arc::new(t), calls_typed));
    }
    let vault = Arc::new(Vault::empty());
    vault.set("TOKEN", "supersecret-value-123").unwrap();
    let mut k = new_kernel(cfg, paths, Arc::new(Res(map)), tools, vault, approver);
    Arc::get_mut(&mut k).unwrap().retry_sleep = Some(Duration::from_millis(1));
    Env { k, p, fb, ws, calls }
}

fn env() -> Env {
    env_with(|_| {}, Arc::new(Policy { allow_privilege: false, allow_egress: false }))
}

fn rand_hex() -> String {
    format!("{:x}{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(), rand())
}

fn start(e: &Env, prompt: &str) -> String {
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    e.k.submit(&id, prompt, "cli").unwrap();
    id
}

fn events(e: &Env, id: &str) -> Vec<EventKind> {
    e.k.store.read(id).unwrap().into_iter().map(|ev| ev.kind).collect()
}

fn tool_results(e: &Env, id: &str) -> Vec<(String, bool)> {
    events(e, id)
        .into_iter()
        .filter_map(|k| match k {
            EventKind::Message { message, .. } => Some(message),
            _ => None,
        })
        .flat_map(|m| m.content)
        .filter_map(|b| match b {
            Block::ToolResult { content, is_error, .. } => Some((content, is_error)),
            _ => None,
        })
        .collect()
}

// ───────────── tests ─────────────

#[test]
fn simple_turn_and_tool_loop() {
    let e = env();
    e.p.call("echo", json!({"text":"hi"}));
    e.p.text("done");
    let id = start(&e, "say hi");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.reason, EndReason::Done);
    assert_eq!(o.text, "done");
    assert_eq!(o.usage.total(), 240);
    assert_eq!(tool_results(&e, &id), vec![("hi".into(), false)]);
    // Second request carries the tool result and a cache breakpoint.
    let reqs = e.p.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].messages.len(), 3);
    assert_eq!(reqs[1].cache_after_message, Some(1));
    // System prefix identical across steps (prompt-cache invariant).
    assert_eq!(reqs[0].system, reqs[1].system);
    assert_eq!(reqs[0].tools, reqs[1].tools);
    // Running again with nothing queued is a no-op.
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::Idle);
}

#[test]
fn retries_then_succeeds() {
    let e = env();
    e.p.fail(ProviderErrorKind::RateLimited { retry_after: Some(Duration::from_millis(1)) });
    e.p.fail(ProviderErrorKind::Network);
    e.p.text("ok");
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.reason, EndReason::Done);
    let notices = events(&e, &id).into_iter().filter(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("retry"))).count();
    assert_eq!(notices, 2);
    assert!(e.fb.requests().is_empty(), "no fallback needed");
}

#[test]
fn falls_back_after_retries_exhausted_and_strips_thinking() {
    let e = env();
    // Turn 1 on main leaves a signed thinking block in history.
    e.p.push(|_| Ok(resp(vec![Block::Thinking { text: "hmm".into(), signature: Some("sig".into()) }, Block::text("first")], StopReason::EndTurn)));
    let id = start(&e, "one");
    e.k.run(&id, RunOpts::default()).unwrap();
    for _ in 0..3 {
        e.p.fail(ProviderErrorKind::Server);
    }
    e.fb.text("from backup");
    e.k.submit(&id, "two", "cli").unwrap();
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "from backup");
    let breq = &e.fb.requests()[0];
    assert_eq!(breq.model, "m2");
    assert!(breq.messages.iter().all(|m| m.content.iter().all(|b| !matches!(b, Block::Thinking { .. }))));
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("falling back to backup/m2"))));
}

#[test]
fn auth_error_falls_back_but_bad_request_does_not() {
    let e = env();
    e.p.fail(ProviderErrorKind::Auth);
    e.fb.text("backup ok");
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "backup ok");

    let e = env();
    e.p.fail(ProviderErrorKind::BadRequest);
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert!(matches!(o.reason, EndReason::Error(_)));
    assert!(e.fb.requests().is_empty());
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Error { .. })));
    assert!(matches!(events(&e, &id).last(), Some(EventKind::TurnEnd { .. })), "turn always closes");
}

#[test]
fn auth_failed_provider_is_benched_for_later_steps() {
    let e = env();
    e.p.fail(ProviderErrorKind::Auth);
    e.fb.call("echo", json!({"text": "a"}));
    e.fb.call("echo", json!({"text": "b"}));
    e.fb.text("done");
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "done");
    assert_eq!(e.p.requests().len(), 1, "main is not retried on every step after it rejected us");
    assert_eq!(e.fb.requests().len(), 3);
    // Benched, not removed: if the backup also fails, the main model is still tried last.
    e.fb.fail(ProviderErrorKind::Auth);
    e.p.text("main back");
    e.k.submit(&id, "again", "user").unwrap();
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "main back");
}

#[test]
fn every_provider_down_ends_with_error_not_hang() {
    let e = env_with(|c| c.model.fallback = vec!["missing/x".into()], Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    for _ in 0..3 {
        e.p.fail(ProviderErrorKind::Overloaded);
    }
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    // The last link's failure is the run's error, not an extra notice.
    assert!(matches!(&o.reason, EndReason::Error(m) if m.contains("missing")), "{:?}", o.reason);
    assert!(!events(&e, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("provider missing unavailable"))));
}

#[test]
fn context_overflow_compacts_and_retries() {
    let e = env();
    // Build some history first.
    e.p.call("big", json!({}));
    e.p.text("first answer");
    let id = start(&e, "question one");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.p.fail(ProviderErrorKind::ContextOverflow);
    // Summariser (aux = main) returns a junk summary → deterministic fallback digest.
    e.p.text("junk");
    e.p.text("junk again");
    e.p.text("after compaction");
    e.k.submit(&id, "question two", "cli").unwrap();
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "after compaction");
    let ev = events(&e, &id);
    assert!(ev.iter().any(|k| matches!(k, EventKind::Compaction { summary, .. } if summary.contains("question one"))));
    assert!(ev.iter().any(|k| matches!(k, EventKind::Prune { .. })));
    let last = e.p.requests().last().unwrap().clone();
    assert!(last.messages[0].text().contains("[Summary of earlier conversation]"));
    assert!(last.messages.iter().any(|m| m.text().contains("question two")));
}

#[test]
fn second_overflow_in_a_row_is_an_error() {
    // Summaries go to the backup provider so they don't consume main's script.
    let e = env_with(|c| c.model.aux = "backup/m2".into(), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.text("a");
    let id = start(&e, "q1");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.p.fail(ProviderErrorKind::ContextOverflow);
    e.p.fail(ProviderErrorKind::ContextOverflow);
    e.k.submit(&id, "q2", "cli").unwrap();
    assert!(matches!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::Error(_)));
}

#[test]
fn budget_and_step_limits() {
    let e = env_with(|c| c.budget.max_tokens = Some(150), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.call("echo", json!({"text":"a"}));
    e.p.call("echo", json!({"text":"b"}));
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert!(matches!(o.reason, EndReason::Budget(_)), "{:?}", o.reason);
    assert_eq!(e.p.requests().len(), 2);

    let e = env_with(|c| c.runner.max_steps_per_turn = 2, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    for i in 0..5 {
        e.p.call("echo", json!({"text": i.to_string()}));
    }
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::MaxSteps);

    // A shared parent ledger caps a run started with it.
    let e = env();
    let parent = Ledger::new(Budget { max_steps: Some(1), ..Default::default() });
    e.p.call("echo", json!({"text":"a"}));
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts { ledger: Some(parent.child(Budget::default())), ..Default::default() }).unwrap();
    assert!(matches!(o.reason, EndReason::Budget(_)));
}

#[test]
fn max_tokens_continues_then_gives_up() {
    let e = env_with(|c| c.runner.max_continuations = 1, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.push(|_| Ok(resp(vec![Block::text("part 1")], StopReason::MaxTokens)));
    e.p.push(|_| Ok(resp(vec![Block::text("part 2")], StopReason::MaxTokens)));
    let id = start(&e, "write a lot");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::MaxTokens);
    assert!(e.p.requests()[1].messages.last().unwrap().text().contains("cut off"));
}

#[test]
fn refusal_ends_turn() {
    let e = env();
    e.p.push(|_| Ok(resp(vec![Block::text("no")], StopReason::Refusal)));
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::Refusal);
}

#[test]
fn privilege_gate_denies_headless_and_allows_with_approval() {
    let e = env();
    e.p.call("sh", json!({"cmd":"sudo rm -rf /var/lib/x"}));
    e.p.text("ok, I cannot");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = tool_results(&e, &id);
    assert!(r[0].1 && r[0].0.contains("Blocked by the privilege gate"), "{r:?}");
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 0, "blocked call never ran");
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Gate { verdict, .. } if verdict == "deny")));

    let e = env_with(|_| {}, Arc::new(Yes));
    e.p.call("sh", json!({"cmd":"sudo id"}));
    e.p.call("sh", json!({"cmd":"sudo id"}));
    e.p.text("done");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 2);
    let verdicts: Vec<String> = events(&e, &id).into_iter().filter_map(|k| if let EventKind::Gate { verdict, .. } = k { Some(verdict) } else { None }).collect();
    assert_eq!(verdicts, ["allow (always)", "allow (remembered)"]);
}

#[test]
fn ordinary_commands_are_not_gated() {
    let e = env();
    e.p.call("sh", json!({"cmd":"cargo test && rm -rf target"}));
    e.p.text("ok");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 1);
    assert!(!events(&e, &id).iter().any(|k| matches!(k, EventKind::Gate { .. })));
}

#[test]
fn bad_tool_calls_become_errors_not_crashes() {
    let e = env();
    e.p.calls(vec![("nope", json!({})), ("echo", json!("not an object")), ("boom", json!({})), ("tool_describe", json!({"name":"zzz"})), ("echo", json!({"text":"still works"}))]);
    e.p.text("recovered");
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.reason, EndReason::Done);
    let r = tool_results(&e, &id);
    assert!(r[0].1 && r[0].0.contains("unknown tool `nope`"));
    assert!(r[1].1 && r[1].0.contains("JSON object"));
    assert!(r[2].1 && r[2].0.contains("crashed: kaboom"));
    assert!(r[3].1 && r[3].0.contains("unknown tool"));
    assert_eq!(r[4], ("still works".into(), false));
}

#[test]
fn progressive_disclosure() {
    let e = env();
    let req_tools = |e: &Env| e.p.requests()[0].tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    e.p.call("tool_describe", json!({"name":"hidden"}));
    e.p.call("tool_call", json!({"name":"hidden","input":{}}));
    e.p.text("ok");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    let names = req_tools(&e);
    assert!(!names.contains(&"hidden".to_string()) && names.contains(&"tool_call".to_string()));
    assert!(e.p.requests()[0].system.iter().any(|s| s.text.contains("hidden: hidden tool.")));
    let r = tool_results(&e, &id);
    assert!(r[0].0.contains("input schema"));
    assert_eq!(r[1], ("hidden ran".into(), false));
}

#[test]
fn parallel_safe_tools_run_concurrently_in_order() {
    let e = env();
    e.p.calls(vec![("sleep", json!({"ms":300})), ("sleep", json!({"ms":300})), ("sleep", json!({"ms":300})), ("echo", json!({"text":"last"}))]);
    e.p.text("ok");
    let id = start(&e, "x");
    let t0 = Instant::now();
    e.k.run(&id, RunOpts::default()).unwrap();
    assert!(t0.elapsed() < Duration::from_millis(800), "{:?}", t0.elapsed());
    let r = tool_results(&e, &id);
    assert_eq!(r.len(), 4);
    assert_eq!(r[3].0, "last", "results keep call order");
}

#[test]
fn watchdog_warns_then_stops() {
    let e = env_with(|c| c.runner.repeat_limit = 2, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    for _ in 0..6 {
        e.p.call("echo", json!({"text":"same"}));
    }
    let id = start(&e, "x");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert!(matches!(o.reason, EndReason::Stuck(_)), "{:?}", o.reason);
    let warned = e.p.requests().iter().any(|r| r.messages.iter().any(|m| m.text().contains("[watchdog]")));
    assert!(warned);
}

#[test]
fn secrets_are_redacted_and_large_output_spilled() {
    let e = env();
    e.p.calls(vec![("leak", json!({})), ("big", json!({}))]);
    e.p.text("ok");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    let raw = std::fs::read_to_string(e.k.store.dir(&id).join("events.jsonl")).unwrap();
    assert!(!raw.contains("supersecret-value-123"), "secret never reaches the log");
    let r = tool_results(&e, &id);
    assert!(r[0].0.contains("{{secret:TOKEN}}"));
    assert!(r[1].0.contains("full output (100000 bytes) saved to") && r[1].0.len() < 20_000);
    let art = std::fs::read_dir(e.k.store.dir(&id).join("artifacts")).unwrap().count();
    assert_eq!(art, 1);
}

#[test]
fn crash_recovery_reruns_idempotent_and_flags_others() {
    let e = env();
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    {
        // Simulate: assistant asked for two tools, write-ahead logged, then crash.
        let mut log = e.k.store.open(&id).unwrap();
        log.append(EventKind::Message { message: Message::user("do it"), usage: None, model: None, inbox: None }).unwrap();
        log.append(EventKind::TurnStart { turn: 0 }).unwrap();
        log.append(EventKind::Message {
            message: Message { role: Role::Assistant, content: vec![Block::ToolUse { id: "a".into(), name: "echo".into(), input: json!({"text":"again"}) }, Block::ToolUse { id: "b".into(), name: "sh".into(), input: json!({"cmd":"make deploy"}) }] },
            usage: None,
            model: None,
            inbox: None,
        })
        .unwrap();
        log.append(EventKind::ToolCalled { tool_use_id: "a".into(), name: "echo".into(), input: json!({"text":"again"}), idempotency_key: "k1".into() }).unwrap();
        log.append(EventKind::ToolCalled { tool_use_id: "b".into(), name: "sh".into(), input: json!({"cmd":"make deploy"}), idempotency_key: "k2".into() }).unwrap();
    }
    e.p.text("checked state, continuing");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "checked state, continuing");
    let r = tool_results(&e, &id);
    assert_eq!(r[0], ("again".into(), false), "idempotent call re-run");
    assert!(r[1].1 && r[1].0.contains("side effects are unknown"));
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 0, "non-idempotent call NOT re-run");
    let v = ark_kernel::projection::project(&e.k.store.read(&id).unwrap());
    assert!(v.unsettled.is_empty() && v.dangling.is_empty());
}

#[test]
fn torn_log_tail_recovers_and_continues() {
    let e = env();
    e.p.text("first");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(e.k.store.dir(&id).join("events.jsonl")).unwrap();
    f.write_all(b"{\"seq\":999,\"ts\":0,\"type\":\"messa").unwrap();
    drop(f);
    e.k.submit(&id, "y", "cli").unwrap();
    e.p.text("second");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "second");
}

#[test]
fn steering_mid_turn_and_interrupt() {
    let e = env();
    let k = e.k.clone();
    e.p.push(|_| {
        std::thread::sleep(Duration::from_millis(300));
        Ok(resp(vec![Block::text("working")], StopReason::EndTurn))
    });
    e.p.text("saw the steer");
    let id = start(&e, "long task");
    let h = k.start(&id, RunOpts::default());
    std::thread::sleep(Duration::from_millis(100));
    assert!(k.is_running(&id));
    k.submit(&id, "also do Y", "telegram").unwrap();
    let o = h.join().unwrap().unwrap();
    assert_eq!(o.text, "saw the steer");
    let last_req = e.p.requests().last().unwrap().clone();
    assert!(last_req.messages.last().unwrap().text().contains("[from telegram] also do Y"));
    // Only one runner per session.
    let e2 = env();
    e2.p.push(|_| {
        std::thread::sleep(Duration::from_millis(500));
        Ok(resp(vec![Block::text("slow")], StopReason::EndTurn))
    });
    let id2 = start(&e2, "x");
    let h = e2.k.start(&id2, RunOpts::default());
    std::thread::sleep(Duration::from_millis(100));
    assert!(matches!(e2.k.run(&id2, RunOpts::default()), Err(ark_kernel::kernel::KernelError::AlreadyRunning(_))));
    assert!(e2.k.interrupt(&id2));
    h.join().unwrap().unwrap();
    assert!(!e2.k.interrupt(&id2), "nothing running any more");
}

#[test]
fn interrupt_during_tool_and_retry_backoff() {
    let e = env_with(|c| c.runner.max_retries = 5, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.call("sleep", json!({"ms": 2000}));
    let id = start(&e, "x");
    let k = e.k.clone();
    let h = k.start(&id, RunOpts::default());
    std::thread::sleep(Duration::from_millis(200));
    e.k.interrupt(&id);
    let o = h.join().unwrap().unwrap();
    assert_eq!(o.reason, EndReason::Interrupted);
}

#[test]
fn sub_agents_run_share_budget_and_respect_depth() {
    let e = env_with(|c| c.runner.max_spawn_depth = 1, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.call("spawn", json!({"task":"count files"}));
    // child turn (same scripted provider):
    e.p.call("spawn", json!({"task":"grandchild"}));
    e.p.text("child result: 42");
    // parent continues:
    e.p.text("parent got it");
    let id = start(&e, "delegate");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "parent got it");
    let r = tool_results(&e, &id);
    assert!(r[0].0.contains("child result: 42") && !r[0].1, "{r:?}");
    let sessions = e.k.store.list();
    let child = sessions.iter().find(|s| s.parent.as_deref() == Some(id.as_str())).expect("child session");
    let cr = tool_results(&e, &child.id);
    assert!(cr[0].1 && cr[0].0.contains("depth limit"));
    assert_eq!(sessions.len(), 2, "grandchild never created");
}

#[test]
fn goal_mode_stops_on_goal_done() {
    let e = env();
    e.p.call("goal_done", json!({"summary":"all tests pass","achieved":true}));
    let id = start(&e, "make tests pass");
    let o = e.k.run(&id, RunOpts { goal_mode: true, ..Default::default() }).unwrap();
    assert_eq!(o.reason, EndReason::Done);
    assert_eq!(o.text, "all tests pass");
    assert!(e.p.requests()[0].tools.iter().any(|t| t.name == "goal_done"));
}

#[test]
fn session_search_tool_and_input_validation() {
    let e = env();
    e.p.text("ok");
    let id = start(&e, "部署到正式環境");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.p.call("session_search", json!({"query":"正式環境"}));
    e.p.text("found");
    let id2 = start(&e, "find it");
    e.k.run(&id2, RunOpts::default()).unwrap();
    assert!(tool_results(&e, &id2)[0].0.contains(&id));
    assert!(e.k.submit(&id2, "   ", "cli").is_err());
    assert!(e.k.create_session(&e.ws, Some("noslash"), None, None).is_err());
    assert!(e.k.create_session(&e.ws.join("missing"), None, None, None).is_err());
    assert!(e.k.submit("nonexistent", "x", "cli").is_err());
}

#[test]
fn header_is_versioned() {
    let e = env();
    let id = e.k.create_session(&e.ws, None, None, Some("t")).unwrap();
    assert!(matches!(&events(&e, &id)[0], EventKind::Header { version, .. } if *version == LOG_VERSION));
    assert!(matches!(&events(&e, &id)[1], EventKind::System { .. }));
}

// ───────────── hooks ─────────────

use ark_kernel::hooks::{Hook, HookDecision, HookEvent};

struct FnHook(HookEvent, Box<dyn Fn(&Value) -> Result<HookDecision, String> + Send + Sync>, Arc<Mutex<Vec<Value>>>);
impl Hook for FnHook {
    fn name(&self) -> String {
        "test".into()
    }
    fn wants(&self, e: HookEvent, tool: Option<&str>) -> bool {
        e == self.0 && tool.is_none_or(|t| t == "echo" || t == "sh")
    }
    fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
        self.2.lock().unwrap().push(p.clone());
        (self.1)(p)
    }
}
fn fnhook(e: HookEvent, f: impl Fn(&Value) -> Result<HookDecision, String> + Send + Sync + 'static) -> (Arc<dyn Hook>, Arc<Mutex<Vec<Value>>>) {
    let seen = Arc::new(Mutex::new(vec![]));
    (Arc::new(FnHook(e, Box::new(f), seen.clone())), seen)
}

#[test]
fn pre_tool_hooks_block_rewrite_and_survive_breakage() {
    let e = env();
    let (block, _) = fnhook(HookEvent::PreTool, |p| Ok(if p["tool_input"]["cmd"] == "rm -rf x" { HookDecision::Block("no deleting".into()) } else { HookDecision::Allow }));
    let (rewrite, _) = fnhook(HookEvent::PreTool, |p| Ok(if p["tool_input"]["text"] == "a" { HookDecision::Modify(json!({"text": "rewritten"})) } else { HookDecision::Allow }));
    let (broken, _) = fnhook(HookEvent::PreTool, |_| Err("crashed".into()));
    e.k.add_hooks(vec![broken, block, rewrite]);
    e.p.calls(vec![("sh", json!({"cmd": "rm -rf x"})), ("echo", json!({"text": "a"}))]);
    e.p.text("ok");
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "ok");
    let r = tool_results(&e, &id);
    assert!(r[0].1 && r[0].0.contains("no deleting"), "{r:?}");
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 0, "blocked tool never ran");
    assert_eq!(r[1], ("rewritten".to_string(), false));
    let ev = events(&e, &id);
    assert!(ev.iter().any(|k| matches!(k, EventKind::Gate { gate, verdict, .. } if gate == "hook" && verdict == "deny")));
    assert!(ev.iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("crashed"))), "broken hook warns, doesn't stop");
}

#[test]
fn post_tool_prompt_session_and_turn_end_hooks() {
    let e = env();
    let (post, _) = fnhook(HookEvent::PostTool, |p| Ok(HookDecision::Context(format!("saw {}", p["tool_response"]["content"]))));
    let (prompt, _) = fnhook(HookEvent::UserPrompt, |p| Ok(match p["prompt"].as_str().unwrap() {
        "secret plan" => HookDecision::Block("not allowed".into()),
        "short" => HookDecision::Modify(json!("expanded prompt")),
        _ => HookDecision::Context("ctx line".into()),
    }));
    let (sess, _) = fnhook(HookEvent::SessionStart, |_| Ok(HookDecision::Context("branch: main".into())));
    let (end, ends) = fnhook(HookEvent::TurnEnd, |_| Ok(HookDecision::Allow));
    e.k.add_hooks(vec![post, prompt, sess, end]);
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    assert!(e.k.submit(&id, "secret plan", "user").is_err());
    e.k.submit(&id, "short", "user").unwrap();
    e.p.call("echo", json!({"text": "hi"}));
    e.p.text("done");
    e.k.run(&id, RunOpts::default()).unwrap();
    let req = &e.p.requests()[0];
    assert!(req.system.iter().any(|s| s.id == "hook_context" && s.text.contains("branch: main")));
    assert!(format!("{:?}", req.messages[0]).contains("expanded prompt"));
    assert!(tool_results(&e, &id)[0].0.contains("[hook] saw \"hi\""));
    {
        let ends = ends.lock().unwrap();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0]["last_assistant_message"], "done");
    }
    e.k.submit(&id, "other", "user").unwrap();
    e.p.text("ok");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert!(format!("{:?}", e.p.requests().last().unwrap().messages).contains("ctx line"));
}

#[test]
fn model_compaction_and_host_event_hooks() {
    let e = env();
    let (pre, pres) = fnhook(HookEvent::PreModel, |_| Ok(HookDecision::Allow));
    let (post, posts) = fnhook(HookEvent::PostModel, |_| Ok(HookDecision::Allow));
    let (nocompact, _) = fnhook(HookEvent::PreCompact, |_| Ok(HookDecision::Block("keep everything".into())));
    let (recv, _) = fnhook(HookEvent::MessageReceived, |p| Ok(if p["prompt"] == "spam" { HookDecision::Block("spam".into()) } else { HookDecision::Modify(json!("clean")) }));
    let (end, ends) = fnhook(HookEvent::SessionEnd, |_| Ok(HookDecision::Allow));
    e.k.add_hooks(vec![pre, post, nocompact, recv, end]);
    e.p.text("answer");
    let id = start(&e, "q");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(pres.lock().unwrap()[0]["messages"], 1);
    assert_eq!(posts.lock().unwrap()[0]["text"], "answer");
    for i in 0..12 {
        e.k.submit(&id, &format!("more {i}"), "user").unwrap();
        e.p.text("ok");
        e.k.run(&id, RunOpts::default()).unwrap();
    }
    assert!(!e.k.compact(&id).unwrap(), "pre_compact block skips compaction");
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("keep everything"))));
    assert_eq!(e.k.emit(HookEvent::MessageReceived, json!({"prompt": "spam"}), "prompt").0.as_deref(), Some("test: spam"));
    assert_eq!(e.k.emit(HookEvent::MessageReceived, json!({"prompt": "x"}), "prompt").1, Some(json!("clean")));
    assert_eq!(e.k.emit(HookEvent::MessageSent, json!({}), ""), (None, None), "no hook → nothing");
    e.k.end_session(&id, "deleted");
    assert_eq!(ends.lock().unwrap()[0]["reason"], "deleted");
    // A blocking pre_model hook fails the step instead of calling the provider.
    let e2 = env();
    let (deny, _) = fnhook(HookEvent::PreModel, |_| Ok(HookDecision::Block("offline hours".into())));
    e2.k.add_hooks(vec![deny]);
    let id = start(&e2, "q");
    let o = e2.k.run(&id, RunOpts::default()).unwrap();
    assert!(o.reason.label().contains("offline hours") && e2.p.requests().is_empty(), "{:?}", o.reason);
}

#[test]
fn reasoning_only_truncation_retries_with_more_room() {
    let e = env_with(|c| c.model.max_tokens = 4096, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    let thinking = || Block::Thinking { text: String::new(), signature: Some("sig".into()) };
    e.p.push(move |_| Ok(resp(vec![thinking()], StopReason::MaxTokens)));
    e.p.push(move |_| Ok(resp(vec![thinking()], StopReason::MaxTokens)));
    e.p.text("finally");
    let id = start(&e, "think hard");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!((o.reason, o.text.as_str()), (EndReason::Done, "finally"));
    let r = e.p.requests();
    assert_eq!(r.iter().map(|q| q.max_tokens).collect::<Vec<_>>(), [4096, 8192, 16384]);
    assert_eq!(r[2].messages.len(), 1, "empty truncated replies are not kept in the transcript");
    assert_eq!(o.usage.output_tokens, 60, "their tokens are still counted");
    // Bounded: a model that never produces anything ends with MaxTokens, not a loop.
    let e = env_with(|c| c.model.max_tokens = 16384, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    for _ in 0..6 {
        e.p.push(move |_| Ok(resp(vec![Block::Thinking { text: String::new(), signature: None }], StopReason::MaxTokens)));
    }
    let id = start(&e, "x");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::MaxTokens);
    assert!(e.p.requests().len() <= 6);
}

#[test]
fn stringified_tool_arguments_are_repaired() {
    let e = env();
    e.p.call("typed", json!({"items": "[1, 2]", "n": "5"}));
    e.p.call("tool_call", json!({"name": "typed", "input": {"items": "[\"a\"]", "n": "x"}}));
    e.p.text("done");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = tool_results(&e, &id);
    assert_eq!(serde_json::from_str::<Value>(&r[0].0).unwrap(), json!({"items": [1, 2], "n": 5}));
    assert_eq!(serde_json::from_str::<Value>(&r[1].0).unwrap(), json!({"items": ["a"], "n": "x"}), "unparseable left alone");
}

#[test]
fn kernel_tools_reachable_through_indirection_and_errors_stay_short() {
    let e = env();
    e.p.calls(vec![
        ("tool_describe", json!({"names": ["session_search", "echo", "nope"]})),
        ("tool_call", json!({"name": "session_search", "input": {"query": "zzz-nothing"}})),
        ("tool_call", json!({"action": "create"})),
        ("tool_call", json!({"name": "ech", "input": {}})),
    ]);
    e.p.text("ok");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = tool_results(&e, &id);
    assert!(!r[0].1 && r[0].0.contains("Search past sessions") && r[0].0.contains("## echo") && r[0].0.contains("unknown tool `nope`"), "{:?}", r[0]);
    assert_eq!(r[1], ("no matches".to_string(), false));
    assert!(r[2].1 && r[2].0.contains("tool_call needs"), "{:?}", r[2]);
    assert!(r[3].1 && r[3].0.contains("Did you mean: echo"), "{:?}", r[3]);
    assert!(r[3].0.len() < 300, "no full catalog dump: {}", r[3].0.len());
}

#[test]
fn images_thinking_titles_and_session_tools() {
    let e = env();
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    e.k.set_thinking(&id, "high").unwrap();
    assert!(e.k.set_thinking(&id, "ludicrous").is_err());
    e.k.set_title(&id, "fix the build").unwrap();
    assert_eq!(e.k.store.list()[0].title.as_deref(), Some("fix the build"));
    let (t, calls) = tool("editor_tool", false, true, false, |c, _| ToolOutput::ok(format!("session {}", c.session_id)));
    e.k.set_session_tools(&id, vec![t]);
    let other = e.k.create_session(&e.ws, None, None, None).unwrap();
    e.p.call("editor_tool", json!({}));
    e.p.text("done");
    e.k.submit_with(&id, "what is this?", vec![Block::Image { media_type: "image/png".into(), data: "AAAA".into() }], "cli").unwrap();
    assert!(e.k.run(&id, RunOpts::default()).unwrap().reason.ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "session tool ran");
    let reqs = e.p.requests();
    assert_eq!(reqs[0].reasoning.as_deref(), Some("high"));
    assert!(reqs[0].tools.iter().any(|t| t.name == "editor_tool"), "session tools ship full schemas");
    assert!(reqs[0].messages[0].content.contains(&Block::Image { media_type: "image/png".into(), data: "AAAA".into() }));
    // Other sessions never see it; removing it hides it again.
    e.p.call("editor_tool", json!({}));
    e.p.text("ok");
    e.k.submit(&other, "go", "cli").unwrap();
    e.k.run(&other, RunOpts::default()).unwrap();
    assert!(tool_results(&e, &other).iter().any(|(c, err)| *err && c.contains("unknown tool")), "{:?}", tool_results(&e, &other));
    e.k.set_session_tools(&id, vec![]);
    e.p.text("bye");
    e.k.submit(&id, "again", "cli").unwrap();
    e.k.run(&id, RunOpts::default()).unwrap();
    assert!(!e.p.requests().last().unwrap().tools.iter().any(|t| t.name == "editor_tool"));
}

#[test]
fn middleware_transforms_and_approval_events() {
    let e = env_with(|_| {}, Arc::new(Yes));
    let (req, _) = fnhook(HookEvent::ToolRequest, |p| Ok(if p["tool_input"]["text"] == "a" { HookDecision::Modify(json!({"text": "via middleware"})) } else { HookDecision::Allow }));
    let (exec, execs) = fnhook(HookEvent::ToolExecution, |p| Ok(if p["phase"] == "call" && p["tool_name"] == "sh" { HookDecision::Modify(json!({"content": "cached answer"})) } else { HookDecision::Allow }));
    let (tr, _) = fnhook(HookEvent::TransformToolResult, |p| Ok(HookDecision::Modify(json!(format!("{} [t]", p["result"].as_str().unwrap())))));
    let (llm_req, _) = fnhook(HookEvent::LlmRequest, |p| {
        let mut r = p["request"].clone();
        r["system"].as_array_mut().unwrap().push(json!({"id": "mw", "text": "added by middleware"}));
        Ok(HookDecision::Modify(r))
    });
    let (llm_exec, _) = fnhook(HookEvent::LlmExecution, |p| Ok(if p["phase"] == "call" && format!("{}", p["request"]["messages"]).contains("skip the model") { HookDecision::Modify(json!({"text": "from middleware"})) } else { HookDecision::Allow }));
    let (out, _) = fnhook(HookEvent::TransformLlmOutput, |p| Ok(if p["text"] == "done" { HookDecision::Modify(json!("DONE (transformed)")) } else { HookDecision::Allow }));
    e.k.add_hooks(vec![req, exec, tr, llm_req, llm_exec, out]);
    e.p.calls(vec![("echo", json!({"text": "a"})), ("sh", json!({"cmd": "ls"}))]);
    e.p.text("done");
    let id = start(&e, "go");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "DONE (transformed)");
    let r = tool_results(&e, &id);
    assert_eq!(r[0].0, "via middleware [t]");
    assert_eq!(r[1].0, "cached answer [t]");
    assert_eq!(e.calls["sh"].load(Ordering::SeqCst), 0, "execution middleware answered instead of the tool");
    assert!(execs.lock().unwrap().iter().any(|p| p["phase"] == "result" && p["tool_response"]["content"] == "via middleware"));
    assert!(e.p.requests()[0].system.iter().any(|s| s.text == "added by middleware"));
    // llm_execution can answer without the provider.
    let n = e.p.requests().len();
    e.k.submit(&id, "skip the model please", "user").unwrap();
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "from middleware");
    assert_eq!(e.p.requests().len(), n, "provider not called");

    // Approval observers see the request and the answer.
    let e = env_with(|_| {}, Arc::new(Yes));
    let (pre, pres) = fnhook(HookEvent::PreApprovalRequest, |_| Ok(HookDecision::Allow));
    let (post, posts) = fnhook(HookEvent::PostApprovalResponse, |_| Ok(HookDecision::Allow));
    e.k.add_hooks(vec![pre, post]);
    e.p.call("sh", json!({"cmd": "sudo apt install x"}));
    e.p.text("ok");
    let id = start(&e, "x");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(pres.lock().unwrap().len(), 1);
    assert_eq!(pres.lock().unwrap()[0]["gate"], "privilege");
    assert_eq!(posts.lock().unwrap()[0]["choice"], "always");
}

struct Eng {
    ingested: AtomicUsize,
    assembled: Mutex<Vec<(usize, String)>>,
}
impl ark_kernel::engine::ContextEngine for Eng {
    fn name(&self) -> String {
        "test".into()
    }
    fn owns_compaction(&self) -> bool {
        true
    }
    fn ingest(&self, _: &str, _: &Message) {
        self.ingested.fetch_add(1, Ordering::SeqCst);
    }
    fn assemble(&self, _: &str, _: &str, m: &[Message], _: u64, _: &str, prompt: &str) -> Result<Option<ark_kernel::engine::Assembled>, String> {
        self.assembled.lock().unwrap().push((m.len(), prompt.to_string()));
        Ok(match prompt {
            "only last" => Some(ark_kernel::engine::Assembled { messages: m[m.len() - 1..].to_vec(), system_addition: Some("engine context".into()) }),
            "broken" => Some(ark_kernel::engine::Assembled { messages: vec![Message::assistant("bad")], system_addition: None }),
            _ => None,
        })
    }
    fn compact(&self, _: &str, _: &[Message], _: u64, _: u64, _: bool) -> Result<Option<ark_kernel::engine::Compacted>, String> {
        Ok(Some(ark_kernel::engine::Compacted { summary: "engine summary".into(), keep_messages: Some(2) }))
    }
}

#[test]
fn context_engine_assembles_ingests_and_owns_compaction() {
    let e = env();
    let eng = Arc::new(Eng { ingested: AtomicUsize::new(0), assembled: Mutex::new(vec![]) });
    e.k.set_context_engine(eng.clone());
    e.p.text("first");
    let id = start(&e, "hello");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.k.submit(&id, "only last", "user").unwrap();
    e.p.text("second");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = e.p.requests();
    assert_eq!(r[0].messages.len(), 1);
    assert_eq!(r[1].messages.len(), 1, "the engine trimmed the history");
    assert!(r[1].system.iter().any(|s| s.id == "context_engine" && s.text == "engine context"));
    assert!(eng.ingested.load(Ordering::SeqCst) >= 4, "user and assistant messages were ingested");
    assert_eq!(eng.assembled.lock().unwrap()[1], (3, "only last".to_string()));
    // An invalid history is ignored with a warning.
    e.k.submit(&id, "broken", "user").unwrap();
    e.p.text("third");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(e.p.requests()[2].messages.len(), 5);
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("invalid history"))));
    // Compaction: the engine's summary is recorded.
    assert!(e.k.compact(&id).unwrap());
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Compaction { summary, .. } if summary == "engine summary")));
}

// ───────────── OpenClaw hook points ─────────────

fn assistant_texts(e: &Env, id: &str) -> Vec<String> {
    events(e, id)
        .into_iter()
        .filter_map(|k| match k {
            EventKind::Message { message, .. } if message.role == Role::Assistant => Some(message.text()),
            _ => None,
        })
        .collect()
}

#[test]
fn before_agent_run_gate_and_before_agent_reply_answer_without_the_model() {
    let e = env();
    let (gate, seen) = fnhook(HookEvent::BeforeAgentRun, |p| Ok(if p["prompt"] == "forbidden" { HookDecision::Modify(json!({"outcome": "block", "reason": "internal detail", "message": "not on this channel"})) } else { HookDecision::Allow }));
    let (reply, _) = fnhook(HookEvent::BeforeAgentReply, |p| Ok(if p["cleaned_body"] == "ping" { HookDecision::Modify(json!({"handled": true, "reply": {"text": "pong"}})) } else { HookDecision::Allow }));
    e.k.add_hooks(vec![gate, reply]);
    let id = start(&e, "forbidden");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "Your message could not be sent: not on this channel (blocked by test)");
    assert!(!o.text.contains("internal detail"), "the internal reason is never shown");
    assert!(e.p.requests().is_empty());
    assert_eq!(seen.lock().unwrap()[0]["prompt"], "forbidden");
    e.k.submit(&id, "ping", "cli").unwrap();
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "pong");
    assert!(e.p.requests().is_empty(), "handled by the hook");
    e.k.submit(&id, "hello", "cli").unwrap();
    e.p.text("model answer");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "model answer");
    assert_eq!(assistant_texts(&e, &id).len(), 3, "transcript stays user/assistant alternating");
    // A broken gate fails closed.
    let e2 = env();
    let (broken, _) = fnhook(HookEvent::BeforeAgentRun, |_| Err("crash".into()));
    e2.k.add_hooks(vec![broken]);
    let id = start(&e2, "x");
    assert!(e2.k.run(&id, RunOpts::default()).unwrap().text.starts_with("Your message could not be sent"));
    assert!(e2.p.requests().is_empty());
}

#[test]
fn before_model_resolve_overrides_model_and_fallbacks_for_the_turn() {
    let e = env();
    let (resolve, seen) = fnhook(HookEvent::BeforeModelResolve, |p| Ok(match p["prompt"].as_str().unwrap() {
        "use backup" => HookDecision::Modify(json!({"providerOverride": "backup", "modelOverride": "m9"})),
        "no fallback" => HookDecision::Modify(json!({"fallbacks_override": []})),
        _ => HookDecision::Allow,
    }));
    e.k.add_hooks(vec![resolve]);
    e.fb.text("from backup");
    let id = start(&e, "use backup");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "from backup");
    assert!(e.p.requests().is_empty());
    assert_eq!(e.fb.requests()[0].model, "m9");
    assert_eq!(seen.lock().unwrap()[0]["model"], "main/m1");
    // Next turn: back to the session model, and an empty fallback chain stops at the failure.
    e.k.submit(&id, "no fallback", "cli").unwrap();
    e.p.fail(ProviderErrorKind::Auth);
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert!(!o.reason.ok(), "{:?}", o.reason);
    assert_eq!(e.fb.requests().len(), 1, "fallback disabled for this turn");
}

#[test]
fn turn_prepare_and_prompt_build_shape_every_request_of_the_turn() {
    let e = env();
    let (prep, preps) = fnhook(HookEvent::AgentTurnPrepare, |_| Ok(HookDecision::Modify(json!({"prependContext": "PRE-CTX", "append_context": "POST-CTX"}))));
    let (build, _) = fnhook(HookEvent::BeforePromptBuild, |_| Ok(HookDecision::Modify(json!({"append_system_context": "SYS-TAIL", "prepend_system_context": "SYS-HEAD", "tools_allow": ["echo"]}))));
    e.k.add_hooks(vec![prep, build]);
    e.p.call("hidden", json!({}));
    e.p.text("done");
    let id = start(&e, "go");
    e.k.run(&id, RunOpts::default()).unwrap();
    let reqs = e.p.requests();
    assert_eq!(reqs.len(), 2);
    for r in &reqs {
        assert_eq!(r.system.first().unwrap().text, "SYS-HEAD");
        assert_eq!(r.system.last().unwrap().text, "SYS-TAIL");
        assert!(r.tools.iter().all(|t| t.name == "echo"), "{:?}", r.tools.iter().map(|t| &t.name).collect::<Vec<_>>());
        let first_user = format!("{:?}", r.messages[0]);
        assert!(first_user.contains("PRE-CTX") && first_user.contains("POST-CTX"), "{first_user}");
    }
    assert!(tool_results(&e, &id)[0].0.contains("not available in this turn"));
    assert_eq!(e.calls["hidden"].load(Ordering::SeqCst), 0);
    assert!(!format!("{:?}", events(&e, &id)).contains("PRE-CTX"), "context is not persisted");
    assert_eq!(preps.lock().unwrap()[0]["prompt"], "go");
    // system_prompt replaces the system segments.
    let e2 = env();
    let (sp, _) = fnhook(HookEvent::BeforePromptBuild, |_| Ok(HookDecision::Modify(json!({"systemPrompt": "You are a pirate."}))));
    e2.k.add_hooks(vec![sp]);
    e2.p.text("arr");
    let id = start(&e2, "hi");
    e2.k.run(&id, RunOpts::default()).unwrap();
    let r = &e2.p.requests()[0];
    assert_eq!((r.system.len(), r.system[0].text.as_str()), (1, "You are a pirate."));
}

#[test]
fn before_agent_finalize_requests_bounded_revisions() {
    let e = env();
    let (fin, seen) = fnhook(HookEvent::BeforeAgentFinalize, |p| Ok(if p["last_assistant_message"] == "draft" { HookDecision::Modify(json!({"action": "revise", "retry": {"instruction": "Add sources."}})) } else { HookDecision::Allow }));
    e.k.add_hooks(vec![fin]);
    e.p.text("draft");
    e.p.text("final with sources");
    let id = start(&e, "write");
    assert_eq!(e.k.run(&id, RunOpts::default()).unwrap().text, "final with sources");
    let reqs = e.p.requests();
    assert!(format!("{:?}", reqs[1].messages.last().unwrap()).contains("[before_agent_finalize] Add sources."));
    let seen = seen.lock().unwrap();
    assert_eq!((seen[0]["stop_hook_active"].clone(), seen[1]["stop_hook_active"].clone()), (json!(false), json!(true)));
    // A hook that always blocks is cut off after 3 revisions.
    let e2 = env();
    let (always, _) = fnhook(HookEvent::BeforeAgentFinalize, |_| Ok(HookDecision::Block("try again".into())));
    e2.k.add_hooks(vec![always]);
    for _ in 0..5 {
        e2.p.text("answer");
    }
    let id = start(&e2, "x");
    assert_eq!(e2.k.run(&id, RunOpts::default()).unwrap().reason, EndReason::Done);
    assert_eq!(e2.p.requests().len(), 4, "1 answer + 3 revisions");
    assert!(events(&e2, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("revision limit"))));
}

#[test]
fn before_message_write_rewrites_and_withholds_safely() {
    let e = env();
    let (w, _) = fnhook(HookEvent::BeforeMessageWrite, |p| {
        let text = format!("{}", p["message"]);
        Ok(if text.contains("SSN 123") {
            HookDecision::Modify(json!({"role": "assistant", "content": [{"type": "text", "text": "SSN [redacted]"}]}))
        } else if text.contains("drop me") {
            HookDecision::Block("noise".into())
        } else if text.contains("tool_use") {
            HookDecision::Block("cannot drop tool calls".into())
        } else {
            HookDecision::Allow
        })
    });
    e.k.add_hooks(vec![w]);
    e.p.call("echo", json!({"text": "t"}));
    e.p.text("your SSN 123");
    let id = start(&e, "q");
    e.k.run(&id, RunOpts::default()).unwrap();
    let a = assistant_texts(&e, &id);
    assert_eq!(a.last().unwrap(), "SSN [redacted]");
    assert_eq!(tool_results(&e, &id).len(), 1, "tool call kept despite the block");
    e.k.submit(&id, "drop me", "cli").unwrap();
    e.p.text("fine");
    e.k.run(&id, RunOpts::default()).unwrap();
    let ev = format!("{:?}", events(&e, &id));
    assert!(ev.contains("[message withheld by a before_message_write hook]"), "inbox message consumed as a placeholder");
    assert!(ev.contains("before_message_write block ignored"));
}

#[test]
fn resolve_exec_env_exports_variables_without_logging_them() {
    let e = env();
    let (env_hook, seen) = fnhook(HookEvent::ResolveExecEnv, |_| Ok(HookDecision::Modify(json!({"DEPLOY_TOKEN": "s3cr3t's", "bad-name": "x", "N": 5}))));
    e.k.add_hooks(vec![env_hook]);
    e.p.call("shell", json!({"command": "echo \"$DEPLOY_TOKEN/$N\""}));
    e.p.text("ok");
    let id = start(&e, "deploy");
    e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(tool_results(&e, &id)[0].0, "s3cr3t's/5");
    assert_eq!(seen.lock().unwrap()[0]["tool_name"], "shell");
    let called = events(&e, &id).into_iter().find_map(|k| match k {
        EventKind::ToolCalled { input, .. } => Some(input),
        _ => None,
    });
    assert!(!called.unwrap().to_string().contains("export"), "write-ahead keeps the model's input");
}

struct Routes(Mutex<Vec<(Value, String)>>);
impl ark_kernel::kernel::HostRoutes for Routes {
    fn origin(&self, session: &str) -> Option<Value> {
        Some(json!({"channel": "tg", "to": format!("chat-of-{session}")}))
    }
    fn deliver(&self, origin: &Value, text: &str) -> Result<(), String> {
        self.0.lock().unwrap().push((origin.clone(), text.to_string()));
        Ok(())
    }
}

#[test]
fn subagent_progress_delivery_target_and_before_reset() {
    let e = env();
    let routes = Arc::new(Routes(Mutex::new(vec![])));
    ark_kernel::kernel::set_host_routes(routes.clone());
    let (prog, progs) = fnhook(HookEvent::SubagentProgress, |_| Ok(HookDecision::Allow));
    let (target, targets) = fnhook(HookEvent::SubagentDeliveryTarget, |_| Ok(HookDecision::Modify(json!({"origin": {"channel": "slack", "to": "C1"}}))));
    let (reset, resets) = fnhook(HookEvent::BeforeReset, |_| Ok(HookDecision::Allow));
    e.k.add_hooks(vec![prog, target, reset]);
    e.p.call("spawn", json!({"task": "sub job"}));
    e.p.text("child result");
    e.p.text("parent done");
    let id = start(&e, "delegate");
    e.k.run(&id, RunOpts::default()).unwrap();
    let progs = progs.lock().unwrap();
    // The same event also carries the child's progress lines, without a `phase`.
    let started = progs.iter().find(|p| p["phase"] == "started").expect("started event");
    let ended = progs.iter().find(|p| p["phase"] == "ended").expect("ended event");
    assert_eq!((started["phase"].as_str(), ended["phase"].as_str(), ended["outcome"].as_str()), (Some("started"), Some("ended"), Some("ok")));
    assert_eq!(started["requester"]["to"], format!("chat-of-{id}"));
    assert_eq!(targets.lock().unwrap()[0]["requester_origin"]["channel"], "tg");
    let sent = routes.0.lock().unwrap().clone();
    assert!(sent.iter().any(|(o, t)| o["channel"] == "slack" && t.contains("child result")), "{sent:?}");
    e.k.end_session(&id, "new");
    let r = resets.lock().unwrap();
    assert_eq!(r[0]["reason"], "new");
    assert!(r[0]["messages"].as_array().unwrap().iter().any(|m| m["text"] == "parent done"));
    e.k.end_session(&id, "exit");
    assert_eq!(r.len(), 1, "exit is not a reset");
}

#[test]
fn host_emit_helpers_claim_and_collect() {
    let e = env();
    let (a, _) = fnhook(HookEvent::InboundClaim, |_| Ok(HookDecision::Allow));
    let (b, _) = fnhook(HookEvent::InboundClaim, |_| Ok(HookDecision::Modify(json!({"handled": true, "reply": "mine"}))));
    let (c, cs) = fnhook(HookEvent::InboundClaim, |_| Ok(HookDecision::Modify(json!({"handled": true, "reply": "late"}))));
    let (h1, _) = fnhook(HookEvent::HeartbeatPromptContribution, |_| Ok(HookDecision::Modify(json!({"prepend_context": "P"}))));
    let (h2, _) = fnhook(HookEvent::HeartbeatPromptContribution, |_| Ok(HookDecision::Context("C".into())));
    e.k.add_hooks(vec![a, b, c, h1, h2]);
    let (_, d) = e.k.emit_first(HookEvent::InboundClaim, json!({}), |d| matches!(d, HookDecision::Modify(v) if ark_kernel::hooks::handled(v).is_some())).unwrap();
    assert!(matches!(d, HookDecision::Modify(v) if v["reply"] == "mine"));
    assert!(cs.lock().unwrap().is_empty(), "a claim stops later hooks");
    assert_eq!(ark_kernel::hooks::heartbeat_prompt(&e.k, "s", "/", "hb", "check in"), "P\n\ncheck in\n\nC");
}

#[test]
fn queue_modes_followup_interrupt_and_edit() {
    use ark_kernel::queue::{Mode, Settings};
    // followup: input during a run waits and runs as its own turn afterwards.
    let e = env();
    e.p.push(|_| {
        std::thread::sleep(Duration::from_millis(300));
        Ok(resp(vec![Block::text("first done")], StopReason::EndTurn))
    });
    e.p.text("second done");
    let id = start(&e, "task one");
    e.k.set_queue(&id, Settings { mode: Mode::Followup, ..Default::default() });
    let h = e.k.clone().start(&id, RunOpts::default());
    std::thread::sleep(Duration::from_millis(100));
    e.k.submit(&id, "task two", "cli").unwrap();
    assert_eq!(e.k.queued(&id).len(), 1);
    let o = h.join().unwrap().unwrap();
    assert_eq!((o.text.as_str(), o.turns), ("second done", 2));
    let reqs = e.p.requests();
    assert!(!reqs[0].messages.iter().any(|m| m.text().contains("task two")), "not steered into turn one");
    assert!(reqs[1].messages.last().unwrap().text().contains("task two"));

    // interrupt: the running turn stops and the new input runs right away.
    let e = env();
    e.p.call("sleep", json!({"ms": 600}));
    e.p.text("handled the new one");
    let id = start(&e, "slow");
    e.k.set_queue(&id, Settings { mode: Mode::Interrupt, ..Default::default() });
    let h = e.k.clone().start(&id, RunOpts::default());
    std::thread::sleep(Duration::from_millis(200));
    e.k.submit(&id, "urgent", "cli").unwrap();
    let o = h.join().unwrap().unwrap();
    assert_eq!((o.text.as_str(), o.reason.clone()), ("handled the new one", EndReason::Done), "the interrupted turn was followed by a fresh one");
    assert!(e.p.requests().last().unwrap().messages.last().unwrap().text().contains("urgent"));

    // idle edits: remove / rewrite inbox entries; discarded ones never run.
    let e = env();
    let id = start(&e, "a");
    e.k.submit(&id, "b", "cli").unwrap();
    e.k.submit(&id, "c", "cli").unwrap();
    assert_eq!(e.k.queued(&id).iter().map(|q| q.2.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
    e.k.edit_queue(&id, &|v| {
        v.remove(1);
        v[1].2 = "c2".into();
        v.swap(0, 1);
    })
    .unwrap();
    assert_eq!(e.k.queued(&id).iter().map(|q| q.2.as_str()).collect::<Vec<_>>(), ["c2", "a"]);
    e.p.text("ok");
    e.k.run(&id, RunOpts::default()).unwrap();
    let sent = e.p.requests()[0].messages.last().unwrap().text();
    assert!(sent.contains("c2") && sent.contains('a') && !sent.contains('b'), "{sent}");
    assert!(Config::load(None, None, &["runner.busy_mode=sideways".into()]).is_err());
}

// ───────────── model settings (models stream) ─────────────

#[test]
fn aliases_allowlist_thinking_and_fast_reach_the_request() {
    let e = env_with(
        |c| {
            c.model.aliases.insert("quick".into(), "backup/m2".into());
            c.model.allow = vec!["main/*".into(), "backup/m2".into()];
            c.model.thinking = "medium".into();
        },
        Arc::new(Yes),
    );
    let id = start(&e, "hi");
    assert!(e.k.set_model(&id, "other/x").is_err(), "not allowed");
    e.k.set_model(&id, "quick").unwrap();
    e.k.set_fast(&id, "on").unwrap();
    assert!(e.k.set_fast(&id, "warp").is_err());
    e.fb.text("ok");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = &e.fb.requests()[0];
    assert_eq!(r.model, "m2");
    assert_eq!(r.reasoning.as_deref(), Some("medium"));
    assert_eq!(r.options.service_tier.as_deref(), Some("priority"));
    e.k.set_thinking(&id, "xhigh").unwrap();
    e.k.set_fast(&id, "normal").unwrap();
    e.k.submit(&id, "again", "cli").unwrap();
    e.fb.text("ok2");
    e.k.run(&id, RunOpts::default()).unwrap();
    let r = e.fb.requests().pop().unwrap();
    assert_eq!(r.reasoning.as_deref(), Some("xhigh"));
    assert_eq!(r.options.service_tier, None);
}

#[test]
fn cold_fast_mode_only_on_first_turn() {
    let e = env_with(|c| c.model.fast = "cold".into(), Arc::new(Yes));
    let id = start(&e, "one");
    e.p.text("a");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.k.submit(&id, "two", "cli").unwrap();
    e.p.text("b");
    e.k.run(&id, RunOpts::default()).unwrap();
    let rs = e.p.requests();
    assert_eq!(rs[0].options.service_tier.as_deref(), Some("priority"));
    assert_eq!(rs[1].options.service_tier, None);
}

#[test]
fn aux_compaction_usage_is_recorded_and_charged() {
    let e = env_with(
        |c| {
            c.model.tasks.insert("compaction".into(), "backup/summ".into());
            c.prices.insert("backup/summ".into(), ark_kernel::ledger::Price { input: 1.0, output: 1.0, cache_read: 0.0, cache_write: 0.0 });
        },
        Arc::new(Yes),
    );
    let id = start(&e, "question one");
    e.p.text("answer one");
    e.k.run(&id, RunOpts::default()).unwrap();
    for i in 0..10 {
        e.k.submit(&id, &format!("q{i} {}", "x".repeat(50)), "cli").unwrap();
        e.p.text("a");
        e.k.run(&id, RunOpts::default()).unwrap();
    }
    e.fb.text(&format!("SUMMARY: question one was asked. {}", "detail ".repeat(40)));
    assert!(e.k.compact(&id).unwrap());
    assert_eq!(e.fb.requests()[0].model, "summ", "per-task aux model");
    let aux: Vec<_> = events(&e, &id).into_iter().filter_map(|k| match k {
        EventKind::AuxUsage { task, model, usage } => Some((task, model, usage.input_tokens)),
        _ => None,
    }).collect();
    assert_eq!(aux.len(), 1);
    assert_eq!((aux[0].0.as_str(), aux[0].1.as_str()), ("compaction", "backup/summ"));
    assert!(aux[0].2 >= 100);
    let v = ark_kernel::projection::project(&e.k.store.read(&id).unwrap());
    assert!(v.aux_usage.output_tokens >= 20);
    // Inside a turn, aux calls charge the turn's ledger (no extra step).
    let l = Ledger::new(Budget::default());
    {
        let _g = l.enter();
        Ledger::charge_current(&Usage { input_tokens: 10, ..Default::default() }, None);
    }
    assert_eq!(l.snapshot().0, 10);
}

fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
    let o = std::process::Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]).args(args).current_dir(dir).output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn sub_agent_and_session_worktree_isolation() {
    let e = env();
    git_in(&e.ws, &["init", "-q"]);
    std::fs::write(e.ws.join("a.txt"), "1").unwrap();
    git_in(&e.ws, &["add", "."]);
    git_in(&e.ws, &["commit", "-q", "-m", "init"]);
    // `spawn worktree=true` (OpenClaw sessions_spawn `worktree`; config default delegation.worktree_isolation).
    e.p.call("spawn", json!({"task":"edit files","worktree":true}));
    e.p.call("wsfile", json!({"name":"child.txt"}));
    e.p.text("child done");
    e.p.text("parent done");
    let id = start(&e, "delegate");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "parent done");
    let child = e.k.store.list().into_iter().find(|s| s.parent.as_deref() == Some(id.as_str())).expect("child session");
    let cws = ark_kernel::projection::project(&e.k.store.read(&child.id).unwrap()).workspace;
    assert!(cws.contains("/.worktrees/subagent-"), "child ran in its own worktree: {cws}");
    assert!(!e.ws.join("child.txt").exists(), "the parent's tree is untouched");
    assert!(!std::path::Path::new(&cws).exists(), "finished worktree removed");
    let archived = git_in(&e.ws, &["for-each-ref", "--format=%(refname)", "refs/ark/archive/"]);
    assert!(archived.contains("refs/ark/archive/subagent-"), "uncommitted child work kept: {archived:?}");
    let r = tool_results(&e, &id);
    assert!(r[0].0.contains("[worktree: work kept on branch ark/subagent-"), "{r:?}");

    // The session itself moves into a worktree: its next tool call runs there.
    let info = ark_kernel::worktree::enter_session(&e.k, &id, Some("feat")).unwrap();
    let ws = ark_kernel::projection::project(&e.k.store.read(&id).unwrap()).workspace;
    assert_eq!(ws, info.path);
    assert!(ws.ends_with(".worktrees/feat"), "{ws}");
    e.p.call("wsfile", json!({"name":"in-wt.txt"}));
    e.p.text("ok");
    e.k.submit(&id, "write it", "cli").unwrap();
    e.k.run(&id, RunOpts::default()).unwrap();
    assert!(std::path::Path::new(&ws).join("in-wt.txt").exists() && !e.ws.join("in-wt.txt").exists());
    let rep = ark_kernel::worktree::leave_session(&e.k, &id).unwrap();
    assert!(rep.dirty && rep.pruned && rep.note.unwrap_or_default().contains("ark/feat"), "work kept on the branch");
    let back = ark_kernel::projection::project(&e.k.store.read(&id).unwrap()).workspace;
    assert_eq!(std::path::Path::new(&back).canonicalize().unwrap(), e.ws.canonicalize().unwrap());
    assert!(ark_kernel::worktree::leave_session(&e.k, &id).unwrap_err().contains("not in a worktree"));

    // Config default: every spawned child is isolated.
    let e2 = env_with(|c| c.delegation.worktree_isolation = true, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    git_in(&e2.ws, &["init", "-q"]);
    std::fs::write(e2.ws.join("a.txt"), "1").unwrap();
    git_in(&e2.ws, &["add", "."]);
    git_in(&e2.ws, &["commit", "-q", "-m", "init"]);
    e2.p.call("spawn", json!({"task":"look"}));
    e2.p.text("child looked");
    e2.p.text("done");
    let id2 = start(&e2, "go");
    e2.k.run(&id2, RunOpts::default()).unwrap();
    let c2 = e2.k.store.list().into_iter().find(|s| s.parent.as_deref() == Some(id2.as_str())).unwrap();
    assert!(ark_kernel::projection::project(&e2.k.store.read(&c2.id).unwrap()).workspace.contains("/.worktrees/subagent-"));
    assert!(git_in(&e2.ws, &["branch", "--list", "ark/subagent-*"]).is_empty(), "a clean child's branch is deleted");
}

// ───────────── context features (Hermes §12) ─────────────

/// `@file:` references are expanded into the user message the model sees.
#[test]
fn refs_attach_context_to_the_turn() {
    let e = env();
    std::fs::write(e.ws.join("notes.txt"), "the deploy command is make ship").unwrap();
    e.p.text("thanks");
    let id = start(&e, "what is in @file:notes.txt?");
    e.k.run(&id, RunOpts::default()).unwrap();
    let sent = e.p.requests();
    let user = sent[0].messages.iter().find(|m| m.role == Role::User).unwrap().text();
    assert!(user.contains("what is in @file:notes.txt?"), "{user}");
    assert!(user.contains("the deploy command is make ship") && user.contains("Attached Context"), "{user}");

    let e2 = env_with(|c| c.context.references = false, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    std::fs::write(e2.ws.join("notes.txt"), "the deploy command is make ship").unwrap();
    e2.p.text("ok");
    let id2 = start(&e2, "what is in @file:notes.txt?");
    e2.k.run(&id2, RunOpts::default()).unwrap();
    let u2 = e2.p.requests()[0].messages.iter().find(|m| m.role == Role::User).unwrap().text();
    assert!(!u2.contains("Attached Context"), "references off: {u2}");
}

/// A touched subdirectory's AGENTS.md rides along with the tool result, once.
#[test]
fn subdir_hints_ride_along_with_a_tool_result() {
    let e = env();
    std::fs::create_dir_all(e.ws.join("pkg")).unwrap();
    std::fs::write(e.ws.join("pkg/AGENTS.md"), "pkg rules: run cargo test -p pkg").unwrap();
    e.p.calls(vec![("echo", json!({"text":"x","path":"pkg/a.rs"})), ("echo", json!({"text":"y","path":"pkg/b.rs"}))]);
    e.p.text("done");
    let id = start(&e, "look at pkg");
    e.k.run(&id, RunOpts::default()).unwrap();
    let results = tool_results(&e, &id);
    assert!(results[0].0.contains("pkg rules: run cargo test -p pkg"), "{:?}", results[0]);
    assert!(!results[1].0.contains("pkg rules"), "hint is delivered once: {:?}", results[1]);
}

/// `context.verify_on_stop = "on"` keeps the turn going once after an edit.
#[test]
fn verify_on_stop_nudges_the_model_to_verify() {
    let e = env_with(|c| {
        c.context.verify_on_stop = "on".into();
        c.context.max_verify_nudges = 1;
    }, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e.p.call("write", json!({"path":"src/lib.rs","body":"x"}));
    e.p.text("all done");
    e.p.text("verified");
    let id = start(&e, "change the code");
    let out = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(out.reason, EndReason::Done);
    let texts: Vec<String> = events(&e, &id).into_iter().filter_map(|k| match k {
        EventKind::Message { message, .. } => Some(message.text()),
        _ => None,
    }).collect();
    assert!(texts.iter().any(|t| t.contains("have not verified")), "{texts:?}");
    assert_eq!(e.p.requests().len(), 3, "edit, nudge, final reply");
}

/// Micro-compaction folds the oldest exchange into a rolling summary.
#[test]
fn micro_compaction_folds_the_oldest_exchange() {
    let e = env_with(|c| {
        c.compaction.micro_compact = true;
        c.compaction.micro_compact_every_n_turns = 1;
        c.compaction.keep_messages = 2;
    }, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    let summary = "## Goal\nanswer the first question\n## Progress\nfirst question was answered\n## Next steps\nnone, waiting for the next question";
    for r in ["first reply", "second reply", "third reply"] {
        e.p.text(r);
    }
    e.p.text(summary);
    e.p.text(summary);
    let id = start(&e, "first question");
    e.k.run(&id, RunOpts::default()).unwrap();
    e.k.submit(&id, "second question", "cli").unwrap();
    e.k.run(&id, RunOpts::default()).unwrap();
    e.k.submit(&id, "third question", "cli").unwrap();
    e.k.run(&id, RunOpts::default()).unwrap();
    let compactions: Vec<(u64, String)> = events(&e, &id).into_iter().filter_map(|k| match k {
        EventKind::Compaction { upto_seq, summary, .. } => Some((upto_seq, summary)),
        _ => None,
    }).collect();
    assert!(!compactions.is_empty(), "a micro pass wrote a Compaction event");
    assert!(compactions.last().unwrap().1.contains("first question was answered"), "{compactions:?}");
    let v = ark_kernel::projection::project(&e.k.store.read(&id).unwrap());
    assert!(v.messages[0].text().contains("earlier conversation"), "{:?}", v.messages[0].text());
    assert!(v.messages.iter().any(|m| m.text().contains("third question")), "tail kept");
}

/// `tool_search` is offered with the meta tools and ranks by keyword (BM25).
#[test]
fn tool_search_is_offered_and_finds_tools_by_keyword() {
    let e = env();
    e.p.call("tool_search", json!({"query":"sleep for a while"}));
    e.p.text("done");
    let id = start(&e, "find a tool");
    e.k.run(&id, RunOpts::default()).unwrap();
    let tools: Vec<String> = e.p.requests()[0].tools.iter().map(|t| t.name.clone()).collect();
    assert!(tools.iter().any(|t| t == "tool_search"), "{tools:?}");
    let results = tool_results(&e, &id);
    assert!(results[0].0.contains("sleep"), "{:?}", results[0]);
    // Off by config: no schema offered.
    let e2 = env_with(|c| c.tools.tool_search.enabled = false, Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    e2.p.text("ok");
    let id2 = start(&e2, "hi");
    e2.k.run(&id2, RunOpts::default()).unwrap();
    assert!(!e2.p.requests()[0].tools.iter().any(|t| t.name == "tool_search"));
}

/// C12: a brand-new model that does not know the reasoning parameter answers 400. The run
/// must survive it: probe once, remember the model, retry without the parameter, and never
/// send it to that model again — no user intervention, no failed session.
#[test]
fn a_model_that_rejects_the_reasoning_parameter_is_retried_without_it() {
    let e = env_with(
        |c| {
            c.model.thinking = "high".into();
            c.runner.max_retries = 2;
        },
        Arc::new(Policy { allow_privilege: false, allow_egress: false }),
    );
    e.p.push(|req| {
        assert_eq!(req.reasoning.as_deref(), Some("high"), "the first probe carries the configured level");
        Err(ProviderError::new(ProviderErrorKind::BadRequest, "unsupported parameter: thinking.type").with_status(400))
    });
    e.p.push(|req| {
        assert!(req.reasoning.is_none(), "the retry omits the rejected parameter");
        Ok(resp(vec![Block::text("answered without thinking")], StopReason::EndTurn))
    });
    // Second turn: the model is now known to reject it, so it is never sent again.
    e.p.push(|req| {
        assert!(req.reasoning.is_none(), "a remembered model is not probed twice");
        Ok(resp(vec![Block::text("second answer")], StopReason::EndTurn))
    });

    let id = start(&e, "first");
    let o = e.k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.reason, EndReason::Done, "{:?}", o.reason);
    assert!(o.text.contains("answered without thinking"), "{}", o.text);
    let notices: Vec<String> = events(&e, &id)
        .into_iter()
        .filter_map(|k| match k {
            EventKind::Notice { level, text } if level == "warn" => Some(text),
            _ => None,
        })
        .collect();
    assert!(notices.iter().any(|t| t.contains("rejected the reasoning parameter")), "{notices:?}");

    e.k.submit(&id, "second", "cli").unwrap();
    let o2 = e.k.run(&id, RunOpts::default()).unwrap();
    assert!(o2.reason.ok(), "{:?}", o2.reason);
    assert_eq!(e.p.requests().len(), 3, "one probe, one retry, one clean second turn");
}

/// G19: the runtime window follows a window the endpoint taught us (recorded by `ark models
/// list` through `contextpin::learn_from_endpoint`), so the compaction thresholds match the real
/// endpoint instead of the catalogue guess.
#[test]
fn runtime_window_follows_a_window_learned_from_the_endpoint() {
    let base = "http://127.0.0.1:6599/v1";
    ark_model::contextpin::clear_learned();
    let mut expected: Option<(Option<u64>, Option<u64>)> = None;
    let e = env_with(
        |c| {
            c.compaction.native.enabled = true;
            let mut t = toml::Table::new();
            t.insert("base_url".into(), toml::Value::String(base.into()));
            c.providers.insert("main".into(), t);
            expected = Some((c.compaction.native_threshold(200_000), c.compaction.native_threshold(65_536)));
        },
        Arc::new(Yes),
    );
    let (catalogue, endpoint) = expected.unwrap();
    assert_ne!(catalogue, endpoint, "the two windows must be distinguishable");
    let id = start(&e, "hello");
    e.p.text("one");
    let _ = e.k.run(&id, RunOpts::default());
    assert_eq!(e.p.requests()[0].options.native_compaction, catalogue, "before learning: the provider's own caps");
    // What `ark models list` does when the endpoint reports its window.
    assert_eq!(ark_model::contextpin::learn_from_endpoint("m1", base, 65_536), Some(65_536));
    e.k.submit(&id, "again", "cli").unwrap();
    e.p.text("two");
    let _ = e.k.run(&id, RunOpts::default());
    assert_eq!(e.p.requests().last().unwrap().options.native_compaction, endpoint, "after learning: the endpoint's number");
    ark_model::contextpin::clear_learned();
}
