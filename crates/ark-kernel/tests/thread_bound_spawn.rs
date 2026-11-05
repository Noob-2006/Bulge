//! Thread-bound and visible sub-agent sessions end to end (OpenClaw
//! `src/agents/subagents/spawn/subagent-spawn-thread-binding.ts`,
//! `src/channels/thread-bindings-*.ts`, `src/agents/tools/sessions-spawn-visible.ts`):
//! a `sessions_spawn thread:true` really opens a thread through the host's channel, binds
//! the child to it, announces the completion into that thread, and `visible:true` publishes
//! a persistent sidebar session. No network: the channel is a fake `HostRoutes`.

use ark_core::*;
use ark_kernel::approver::{Approval, ApprovalRequest, Approver};
use ark_kernel::config::{Config, Paths};
use ark_kernel::event::EventKind;
use ark_kernel::kernel::{new_kernel, HostRoutes, Kernel, Resolver, RunOpts};
use ark_kernel::projection::project;
use ark_kernel::threads;
use ark_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

// ───────────────────────── scripted provider ─────────────────────────

type Step = Box<dyn FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send>;

struct Scripted {
    id: String,
    steps: Mutex<VecDeque<Step>>,
}

impl Scripted {
    fn new(id: &str) -> Arc<Self> {
        Arc::new(Scripted { id: id.into(), steps: Mutex::new(VecDeque::new()) })
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

// ───────────────────────── fake channel routes ─────────────────────────

#[derive(Default)]
struct Seen {
    created: Vec<(String, String)>,
    sent: Vec<(Value, String)>,
}

/// A chat channel that can (or cannot) open threads; `origin` answers for every session.
struct FakeRoutes {
    seen: Mutex<Seen>,
    threads: bool,
}

impl FakeRoutes {
    fn new(threads: bool) -> Arc<FakeRoutes> {
        Arc::new(FakeRoutes { seen: Mutex::new(Seen::default()), threads })
    }
    fn created(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().created.clone()
    }
    fn sent(&self) -> Vec<(Value, String)> {
        self.seen.lock().unwrap().sent.clone()
    }
}

impl HostRoutes for FakeRoutes {
    fn origin(&self, session: &str) -> Option<Value> {
        Some(json!({"channel": "test", "to": format!("chat-{session}")}))
    }
    fn deliver(&self, origin: &Value, text: &str) -> Result<(), String> {
        self.seen.lock().unwrap().sent.push((origin.clone(), text.to_string()));
        Ok(())
    }
    fn supports_threads(&self, _origin: &Value) -> bool {
        self.threads
    }
    fn create_thread(&self, origin: &Value, name: &str) -> Result<String, String> {
        let mut s = self.seen.lock().unwrap();
        let id = format!("th-{}", s.created.len() + 1);
        s.created.push((format!("{}:{}", origin["channel"].as_str().unwrap_or(""), name), id.clone()));
        Ok(id)
    }
}

/// `set_host_routes` is process-global: the tests below take turns.
static ROUTES: Mutex<()> = Mutex::new(());

fn with_routes(threads: bool) -> (Arc<FakeRoutes>, MutexGuard<'static, ()>) {
    let g = ROUTES.lock().unwrap_or_else(|e| e.into_inner());
    let r = FakeRoutes::new(threads);
    ark_kernel::kernel::set_host_routes(r.clone());
    (r, g)
}

// ───────────────────────── environment ─────────────────────────

struct Env {
    k: Kernel,
    p: Arc<Scripted>,
    c: Arc<Scripted>,
    paths: Paths,
}

fn env_with(cfg_mut: impl FnOnce(&mut Config)) -> Env {
    let root = std::env::temp_dir().join(format!("ark-thread-spawn-{}", rand_hex()));
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
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
    let mut k = new_kernel(cfg, paths.clone(), Arc::new(Res(map)), vec![], Arc::new(Vault::empty()), Arc::new(Yes));
    Arc::get_mut(&mut k).unwrap().retry_sleep = Some(Duration::from_millis(1));
    Env { k, p, c, paths }
}

fn parent_session(e: &Env, prompt: &str) -> String {
    let id = e.k.create_session(&PathBuf::from(&e.paths.data).parent().unwrap().join("ws"), None, None, Some("parent")).unwrap();
    e.k.submit(&id, prompt, "cli").unwrap();
    id
}

fn tool_results(e: &Env, id: &str) -> Vec<(String, bool)> {
    e.k.store
        .read(id)
        .unwrap()
        .into_iter()
        .filter_map(|ev| match ev.kind {
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

fn tool_json(e: &Env, id: &str, i: usize) -> Value {
    let (text, is_error) = tool_results(e, id)[i].clone();
    assert!(!is_error, "tool call {i} failed: {text}");
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("tool result {i} is not JSON: {text}"))
}

/// `sessions_list` answers with the rows themselves; a wrapper object is accepted too.
fn rows_of(v: &Value) -> &Vec<Value> {
    v.as_array().or_else(|| v.get("sessions").and_then(Value::as_array)).or_else(|| v.get("rows").and_then(Value::as_array)).unwrap_or_else(|| panic!("no sessions rows: {v}"))
}

fn tool_error(e: &Env, id: &str, i: usize) -> String {
    let (text, is_error) = tool_results(e, id)[i].clone();
    assert!(is_error, "tool call {i} should have failed: {text}");
    text
}

fn first<S: std::fmt::Display>(text: &str, needle: &str, what: S) {
    assert!(text.contains(needle), "{what}: expected `{needle}` in: {text}");
}

// ───────────────────────── tests ─────────────────────────

#[test]
fn thread_spawn_opens_a_thread_and_announces_the_completion_into_it() {
    let (routes, _g) = with_routes(true);
    let e = env_with(|cfg| {
        cfg.channels.insert(
            "test".into(),
            "kind = \"test\"\n[threadBindings]\nidleHours = 2\nmaxAgeHours = 48\n".parse::<toml::Table>().unwrap(),
        );
    });
    e.p.call("sessions_spawn", json!({"task": "audit the repo", "label": "Repo audit", "thread": true}));
    e.p.text("dispatched");
    e.p.call("sessions_list", json!({"include_children": false}));
    e.p.text("read the completion");
    e.c.text("audit done: 3 findings");

    let id = parent_session(&e, "thread spawn");
    e.k.run(&id, RunOpts::default()).unwrap();
    let h = tool_json(&e, &id, 0);
    let child = h["session_id"].as_str().unwrap().to_string();

    // A real thread was opened in the requester's chat, named after the task.
    assert_eq!(routes.created(), vec![("test:🤖 Repo audit".to_string(), "th-1".to_string())], "{h}");
    assert_eq!(h["thread"]["thread_id"], "th-1", "{h}");
    assert_eq!(h["thread"]["channel"], "test", "{h}");
    assert_eq!(h["thread"]["chat"], format!("chat-{id}"), "{h}");
    assert_eq!(h["thread"]["name"], "🤖 Repo audit", "{h}");
    assert_eq!(h["thread"]["idle_ms"], 7_200_000, "policy comes from channels.test.threadBindings: {h}");
    assert_eq!(h["thread"]["max_age_ms"], 172_800_000, "{h}");
    assert_eq!(h["background"], true, "a thread-bound child is a session, not a one-shot run: {h}");

    // The binding is persisted and points at the child session.
    let b = threads::by_session(&e.paths, &child).expect("binding for the child");
    assert_eq!((b.thread.as_str(), b.parent.as_str()), ("th-1", id.as_str()));

    let sent = routes.sent();
    // The thread introduces itself once, with the upstream text.
    let intro = sent.first().expect("intro delivered");
    assert_eq!(intro.0["thread_id"], "th-1");
    assert!(intro.1.starts_with("[system] Repo audit session active (idle expiry after 2h inactivity; max age 48h). Messages here go directly to this session."), "{intro:?}");
    // The completion announcement lands in the thread, not only in the parent chat.
    let announced = sent.iter().any(|(o, t)| o["thread_id"] == "th-1" && t.contains("audit done: 3 findings"));
    assert!(announced, "completion not announced into the thread: {sent:?}");
    assert!(sent.iter().all(|(o, _)| o["to"] == format!("chat-{id}")), "thread messages stay in the chat: {sent:?}");

    // The child is listed for the user even without include_children (it has a thread).
    let list = tool_json(&e, &id, 1);
    let rows = rows_of(&list);
    let row = rows.iter().find(|r| r["id"] == child.as_str()).unwrap_or_else(|| panic!("thread child missing from sessions_list: {list}"));
    assert_eq!(row["thread"]["thread_id"], "th-1", "{row}");
}

#[test]
fn visible_spawn_publishes_a_persistent_sidebar_session() {
    let (_routes, _g) = with_routes(true);
    let e = env_with(|_| {});
    e.p.call("sessions_spawn", json!({"task": "review the diff", "label": "Diff review", "group": "reviews", "visible": true}));
    e.p.text("dispatched");
    e.p.call("sessions_list", json!({"include_children": false, "limit": 50}));
    e.p.text("read the completion");
    e.c.text("review complete");

    let id = parent_session(&e, "visible spawn");
    e.k.run(&id, RunOpts::default()).unwrap();
    let h = tool_json(&e, &id, 0);
    let child = h["session_id"].as_str().unwrap().to_string();
    assert_eq!(h["visible"], true, "{h}");
    assert_eq!(h["cleanup"], "keep", "a visible session is never cleaned up: {h}");
    assert_eq!(h["sidebar"]["label"], "Diff review", "{h}");
    assert_eq!(h["sidebar"]["group"], "reviews", "{h}");
    assert!(h["thread"].is_null(), "visible is not a thread: {h}");

    // Sidebar settings really reached the session log…
    let view = project(&e.k.store.read(&child).unwrap());
    assert_eq!(view.title.as_deref(), Some("Diff review"));
    assert_eq!(view.group.as_deref(), Some("reviews"));
    // …its status follows the run…
    let v = threads::visible_of(&e.paths, &child).expect("visible row");
    assert_eq!(v.status, "completed", "{v:?}");
    // …and it is listed without include_children while a hidden helper is not.
    let view2 = project(&e.k.store.read(&id).unwrap());
    assert!(view2.messages.len() > 1);
    let hidden_ws = std::env::temp_dir().join(format!("ark-thread-vis-{}", rand_hex()));
    std::fs::create_dir_all(&hidden_ws).unwrap();
    let hidden = e.k.create_session(&hidden_ws, None, Some(&id), Some("hidden")).unwrap();
    let listed = tool_json(&e, &id, 1);
    let rows = rows_of(&listed);
    assert!(rows.iter().any(|r| r["id"] == child.as_str() && r["visible"] == true), "visible child missing: {rows:?}");
    assert!(!rows.iter().any(|r| r["id"] == hidden.as_str()), "a hidden helper must need include_children: {rows:?}");
}

#[test]
fn thread_spawn_needs_a_thread_capable_channel_and_enabled_bindings() {
    // A channel that cannot open threads: upstream's "not running on a channel that can bind".
    {
        let (_routes, _g) = with_routes(false);
        let e = env_with(|_| {});
        e.p.call("sessions_spawn", json!({"task": "x", "thread": true}));
        e.p.text("done");
        let id = parent_session(&e, "no thread channel");
        e.k.run(&id, RunOpts::default()).unwrap();
        let err = tool_error(&e, &id, 0);
        assert!(err.contains("only available on channels that open a separate thread"), "{err}");
        assert!(err.contains("Retry without thread=true"), "{err}");
    }
    // Bindings switched off for this channel.
    {
        let (routes, _g) = with_routes(true);
        let e = env_with(|cfg| {
            cfg.channels.insert("test".into(), "kind = \"test\"\n[threadBindings]\nenabled = false\n".parse::<toml::Table>().unwrap());
        });
        e.p.call("sessions_spawn", json!({"task": "x", "thread": true}));
        e.p.text("done");
        let id = parent_session(&e, "bindings off");
        e.k.run(&id, RunOpts::default()).unwrap();
        let err = tool_error(&e, &id, 0);
        first(&err, "Thread bindings are disabled for test", "disabled message");
        first(&err, "channels.test.threadBindings.enabled=true", "how to enable");
        assert!(routes.created().is_empty(), "nothing is opened for a refused spawn");
    }
    // Spawns switched off though bindings work.
    {
        let (routes, _g) = with_routes(true);
        let e = env_with(|cfg| {
            cfg.channels.insert("test".into(), "kind = \"test\"\n[threadBindings]\nspawnSessions = false\n".parse::<toml::Table>().unwrap());
        });
        e.p.call("sessions_spawn", json!({"task": "x", "thread": true}));
        e.p.text("done");
        let id = parent_session(&e, "spawns off");
        e.k.run(&id, RunOpts::default()).unwrap();
        let err = tool_error(&e, &id, 0);
        first(&err, "Thread-bound session spawns are disabled for test", "spawn disabled message");
        assert!(routes.created().is_empty(), "nothing is opened for a refused spawn");
    }
}

#[test]
fn visible_and_thread_and_collect_follow_the_upstream_rules() {
    let (_routes, _g) = with_routes(true);
    let e = env_with(|_| {});
    e.p.call("sessions_spawn", json!({"task": "x", "thread": true, "visible": true}));
    e.p.call("sessions_spawn", json!({"task": "x", "visible": true, "mode": "collect"}));
    e.p.call("sessions_spawn", json!({"task": "x", "thread": true, "mode": "collect"}));
    e.p.text("done");
    let id = parent_session(&e, "combo rules");
    e.k.run(&id, RunOpts::default()).unwrap();
    let both = tool_error(&e, &id, 0);
    first(&both, "Parameters unavailable with visible=true: thread", "thread+visible");
    let collect = tool_error(&e, &id, 1);
    first(&collect, "collect=true does not support thread, visible", "visible+collect");
    let collect2 = tool_error(&e, &id, 2);
    first(&collect2, "collect=true does not support thread, visible", "thread+collect");
}
