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
        ModelCaps { context_window: self.window, max_output: 8192, tools: true, vision: false, explicit_cache: false }
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
    add("leak", tool("leak", false, true, true, |_, _| ToolOutput::ok("token is supersecret-value-123")));
    add("hidden", tool("hidden", false, true, false, |_, _| ToolOutput::ok("hidden ran")));
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
    assert!(matches!(o.reason, EndReason::Error(_)), "{:?}", o.reason);
    assert!(events(&e, &id).iter().any(|k| matches!(k, EventKind::Notice { text, .. } if text.contains("provider missing unavailable"))));
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
