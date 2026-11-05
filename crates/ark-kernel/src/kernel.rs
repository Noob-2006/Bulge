//! The kernel: sessions, the turn/step runner, tool dispatch through the gates,
//! retries and provider fallback, compaction, crash recovery and sub-agents.

use crate::approver::{Approver, PendingItem, Remembered};
use crate::checkpoint::Checkpoints;
use crate::compaction;
use crate::config::{Config, Paths};
use crate::context::{self, split_model};
use crate::engine::ContextEngine;
use crate::event::{Event, EventKind, LOG_VERSION};
use crate::hooks::{self, Hook, HookDecision, HookEvent};
use crate::ledger::{Budget, Ledger};
use crate::projection::{project, Queued, View};
use crate::store::{SessionLog, Store, StoreError};
use crate::util::{head_tail, new_id};
use crate::vault::Vault;
use ark_core::tool::SpawnRequest;
use ark_core::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

mod hookpoints;
pub use hookpoints::{history as hook_history, host_routes, set_host_routes, HostRoutes, BLOCK_MESSAGE_PREFIX};

/// Interface: resolve a provider id to an implementation (lives in ark-model).
pub trait Resolver: Send + Sync {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String>;
}

#[derive(Debug, Clone)]
pub enum BusMsg {
    Event { session: String, event: Event },
    Delta { session: String, text: String, thinking: bool },
    Pending(PendingItem),
}

#[derive(Default)]
pub struct Bus {
    subs: Mutex<Vec<mpsc::Sender<BusMsg>>>,
}

impl Bus {
    pub fn subscribe(&self) -> mpsc::Receiver<BusMsg> {
        let (tx, rx) = mpsc::channel();
        self.subs.lock().unwrap().push(tx);
        rx
    }
    pub fn publish(&self, m: BusMsg) {
        self.subs.lock().unwrap().retain(|s| s.send(m.clone()).is_ok());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EndReason {
    Done,
    /// Nothing queued.
    Idle,
    Interrupted,
    Budget(String),
    MaxSteps,
    MaxTokens,
    Refusal,
    Stuck(String),
    Error(String),
    /// Stoppable-and-resumable: the provider was unreachable or out of credit, or a resource
    /// cap was hit. The state is the event log, so a later run continues from the same turn
    /// (C1/C2/C8: pause instead of exiting). Text: why, and when the retry happens.
    Paused(String),
}

impl EndReason {
    pub fn label(&self) -> String {
        match self {
            EndReason::Done => "done".into(),
            EndReason::Idle => "idle".into(),
            EndReason::Interrupted => "interrupted".into(),
            EndReason::Budget(s) => format!("budget: {s}"),
            EndReason::MaxSteps => "max_steps".into(),
            EndReason::MaxTokens => "max_tokens".into(),
            EndReason::Refusal => "refusal".into(),
            EndReason::Stuck(s) => format!("stuck: {s}"),
            EndReason::Error(s) => format!("error: {s}"),
            EndReason::Paused(s) => format!("paused: {s}"),
        }
    }
    pub fn ok(&self) -> bool {
        matches!(self, EndReason::Done | EndReason::Idle)
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub reason: EndReason,
    /// Last assistant text.
    pub text: String,
    pub usage: Usage,
    pub turns: u64,
}

#[derive(Clone, Default)]
pub struct RunOpts {
    pub ledger: Option<Ledger>,
    pub depth: u32,
    pub cancel: Option<Cancel>,
    /// Extra kernel tool for goal runs.
    pub goal_mode: bool,
    /// Return when the inbox is empty even while background sub-agents still run
    /// (their completions are queued in the inbox for a later run).
    pub detach: bool,
}

pub(crate) struct Running {
    cancel: Cancel,
    queue: Arc<Mutex<Vec<Queued>>>,
    /// Settings changes for a running session (its log is held by the run).
    events: Arc<Mutex<Vec<EventKind>>>,
    /// Input held for later turns (`queue` modes other than steer).
    later: Arc<Mutex<Vec<Queued>>>,
    /// Set by `interrupt` mode: the cancelled turn is followed by a fresh one.
    restart: Arc<std::sync::atomic::AtomicBool>,
}

pub struct Runtime {
    pub cfg: Config,
    pub paths: Paths,
    pub store: Store,
    pub resolver: Arc<dyn Resolver>,
    pub tools: Vec<Arc<dyn Tool>>,
    pub vault: Arc<Vault>,
    pub approver: Arc<dyn Approver>,
    pub remembered: Remembered,
    pub bus: Bus,
    pub(crate) running: Mutex<HashMap<String, Running>>,
    /// Models whose provider rejected us (bad key, no credit): tried last until the
    /// cooldown passes, so each step doesn't pay for a doomed request first.
    benched: Mutex<HashMap<String, Instant>>,
    /// C12: models that rejected a reasoning parameter (`400`). Later calls omit it, so a
    /// brand-new model id costs one probe, not a broken session.
    no_reasoning: Mutex<std::collections::HashSet<String>>,
    hooks: std::sync::RwLock<Vec<Arc<dyn Hook>>>,
    session_tools: std::sync::RwLock<HashMap<String, Vec<Arc<dyn Tool>>>>,
    taps: std::sync::RwLock<Vec<Tap>>,
    /// `context_engine = "<plugin>"`: shapes requests and may own compaction.
    engine: std::sync::RwLock<Option<Arc<dyn ContextEngine>>>,
    /// In-process turn observers (memory providers, skill usage, curators).
    lifecycles: std::sync::RwLock<Vec<Arc<dyn crate::lifecycle::Lifecycle>>>,
    /// Native slash commands registered by the host (skills, memory, context, plugins).
    slash: std::sync::RwLock<Vec<Arc<dyn crate::slash::Slash>>>,
    /// Test hook / determinism: override sleep between retries.
    pub retry_sleep: Option<Duration>,
    /// Live and recently finished sub-agents (delegate_task, sessions_spawn…).
    pub subagents: crate::subagents::Registry,
    /// Sessions whose current turn a tool asked to end (sessions_yield, structured_output).
    end_turn: Mutex<std::collections::HashSet<String>>,
    /// Set by the daemon: an idle session that receives a sub-agent completion is started.
    pub auto_resume: std::sync::atomic::AtomicBool,
    /// Per-session `/queue` settings (busy-input behaviour); unset = `runner.busy_mode`.
    pub queue_settings: Mutex<HashMap<String, crate::queue::Settings>>,
    /// `/debug set` runtime overrides (OpenClaw `config/runtime-overrides.ts`): when set,
    /// a validated config replaces `cfg` for turns started after it was applied.
    runtime_cfg: std::sync::RwLock<Option<Config>>,
    /// Per-session context state: subdirectory trackers, micro-compaction, verify loop
    /// (`@`-references, subdirectory hints, `verify_on_stop`, BM25 tool search).
    pub ctx: crate::ctxstate::CtxState,
}

pub type Kernel = Arc<Runtime>;

/// One waiting input entry as reported by `Runtime::queued`: `(inbox id, source, text)`.
pub type QueuedInput = (String, String, String);

/// Synchronous event observer: runs on the appending thread before the bus sees
/// the event (e.g. snapshot a file's text before the tool that edits it runs).
pub type Tap = Arc<dyn Fn(&str, &Event) + Send + Sync>;

#[derive(Default)]
pub(crate) struct Fired {
    pub(crate) block: Option<String>,
    pub(crate) modified: Option<Value>,
    pub(crate) context: Vec<String>,
}

const BENCH_COOLDOWN: Duration = Duration::from_secs(600);
/// Ceiling when retrying a reply that reasoning truncated.
const MAX_BOOSTED_TOKENS: u32 = 32_768;

pub fn new_kernel(cfg: Config, paths: Paths, resolver: Arc<dyn Resolver>, tools: Vec<Arc<dyn Tool>>, vault: Arc<Vault>, approver: Arc<dyn Approver>) -> Kernel {
    let mut tools = tools;
    // Sub-agent / multi-session / typed sub-call tools live next to the kernel: they reach
    // it through `ToolHost::as_any` (Host::of), so every front end gets them without wiring.
    tools.extend(crate::subagents::tools());
    tools.extend(crate::agents::tools());
    tools.extend(crate::coord::tools());
    tools.extend(crate::decision::tools());
    let store = Store::new(paths.sessions());
    cfg.security.activate_at(Some(&paths.config_dir));
    Arc::new(Runtime { cfg, paths, store, resolver, tools, vault, approver, remembered: Remembered::default(), bus: Bus::default(), running: Mutex::new(HashMap::new()), benched: Mutex::new(HashMap::new()), no_reasoning: Mutex::new(std::collections::HashSet::new()), hooks: Default::default(), session_tools: Default::default(), taps: Default::default(), engine: Default::default(), lifecycles: Default::default(), slash: Default::default(), retry_sleep: None, subagents: Default::default(), end_turn: Default::default(), auto_resume: Default::default(), queue_settings: Default::default(), runtime_cfg: Default::default(), ctx: Default::default() })
}

#[derive(Debug)]
pub enum KernelError {
    Store(StoreError),
    AlreadyRunning(String),
    Invalid(String),
}
impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelError::Store(e) => write!(f, "{e}"),
            KernelError::AlreadyRunning(s) => write!(f, "session {s} is already running"),
            KernelError::Invalid(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for KernelError {}
impl From<StoreError> for KernelError {
    fn from(e: StoreError) -> Self {
        KernelError::Store(e)
    }
}

const KERNEL_TOOL_SEARCH: &str = "session_search";
const KERNEL_TOOL_GOAL_DONE: &str = "goal_done";

impl Runtime {
    /// The config turns started now should use: `/debug set` runtime overrides replace the
    /// startup snapshot once they validate (OpenClaw `config/runtime-overrides.ts`).
    pub fn cfg_now(&self) -> Config {
        self.runtime_cfg.read().unwrap().clone().unwrap_or_else(|| self.cfg.clone())
    }
    /// Install (or clear) the runtime override snapshot; `None` restores the startup config.
    pub fn set_runtime_cfg(&self, cfg: Option<Config>) {
        *self.runtime_cfg.write().unwrap() = cfg;
    }
    pub fn runtime_cfg(&self) -> Option<Config> {
        self.runtime_cfg.read().unwrap().clone()
    }
    pub fn specs(&self) -> Vec<ToolSpec> {
        let cfg = self.cfg_now();
        let mut v: Vec<ToolSpec> = self.tools.iter().map(|t| t.spec()).filter(|s| !cfg.tools.disabled.contains(&s.name)).collect();
        v.extend(self.engine_tools().iter().map(|t| t.spec()).filter(|s| !cfg.tools.disabled.contains(&s.name)));
        v
    }
    /// Tools the active context engine brings (Hermes `ContextEngine.get_tool_schemas`).
    fn engine_tools(&self) -> Vec<Arc<dyn Tool>> {
        self.engine().map(|e| e.tools()).unwrap_or_default()
    }
    fn tool(&self, session: &str, name: &str) -> Option<Arc<dyn Tool>> {
        if self.cfg_now().tools.disabled.iter().any(|d| d == name) {
            return None;
        }
        if !self.tool_permitted(session, "", name) {
            return None;
        }
        self.tools.iter().find(|t| t.spec().name == name).cloned().or_else(|| self.engine_tools().into_iter().find(|t| t.spec().name == name)).or_else(|| self.session_tools.read().unwrap().get(session)?.iter().find(|t| t.spec().name == name).cloned())
    }

    /// Short, token-cheap error: closest names instead of the whole catalog.
    fn unknown_tool(&self, name: &str) -> String {
        let mut names: Vec<String> = self.specs().into_iter().map(|s| s.name).collect();
        names.extend(self.kernel_tools(false).into_iter().map(|t| t.name));
        let n = name.to_lowercase();
        let short = n.rsplit("__").next().unwrap_or(&n).to_string();
        let mut close: Vec<&String> = names.iter().filter(|c| { let c = c.to_lowercase(); !short.is_empty() && (c.contains(&short) || short.contains(c.rsplit("__").next().unwrap_or(&c))) }).take(5).collect();
        if close.is_empty() {
            close = names.iter().filter(|c| !c.starts_with("mcp__")).take(12).collect();
        }
        format!("unknown tool `{name}`. Did you mean: {}? (the tool index in your instructions lists them all)", close.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
    }

    fn kernel_tools(&self, goal_mode: bool) -> Vec<ToolSchema> {
        let mut v = vec![
            crate::coderun::spec(),
            ToolSchema {
                name: KERNEL_TOOL_SEARCH.into(),
                description: "Search past sessions' messages (case-insensitive, works for Chinese). `query` searches all sessions; `session` + `read`/`scroll` reads one transcript; `after`/`before` (ISO dates or YYYY-MM-DD), `role` (user|assistant) and `session` filter the hits; `summary` groups them per session.".into(),
                input_schema: crate::agents::session_search_schema(),
            },
        ];
        if self.cfg.tools.tool_search.enabled {
            v.push(crate::ctxrun::tool_search_schema());
        }
        if goal_mode {
            v.push(ToolSchema {
                name: KERNEL_TOOL_GOAL_DONE.into(),
                description: "Declare the current goal achieved (or impossible) with a summary of the evidence. Only call when verified.".into(),
                input_schema: json!({"type":"object","properties":{"summary":{"type":"string"},"achieved":{"type":"boolean"}},"required":["summary","achieved"]}),
            });
        }
        v
    }

    pub(crate) fn request_end_turn(&self, session: &str) {
        self.end_turn.lock().unwrap().insert(session.to_string());
    }

    pub(crate) fn append(&self, log: &mut SessionLog, kind: EventKind) -> Result<Event, StoreError> {
        let kind = if matches!(kind, EventKind::Message { .. }) && self.has_hooks(HookEvent::BeforeMessageWrite) { self.before_message_write(log, kind)? } else { kind };
        let ev = log.append(kind)?;
        for t in self.taps.read().unwrap().iter() {
            t(&log.id, &ev);
        }
        crate::subagents::live_log(self, &log.id, &ev);
        if let (EventKind::Message { message, .. }, Some(e)) = (&ev.kind, self.engine()) {
            e.ingest(&log.id, message);
        }
        self.bus.publish(BusMsg::Event { session: log.id.clone(), event: ev.clone() });
        Ok(ev)
    }

    // ───────────────────────── hooks ─────────────────────────

    pub fn add_hooks(&self, hooks: Vec<Arc<dyn Hook>>) {
        self.hooks.write().unwrap().extend(hooks);
    }
    /// Names of the installed hooks, in install order (`ark doctor`, tests).
    pub fn hook_names(&self) -> Vec<String> {
        self.hooks.read().unwrap().iter().map(|h| h.name()).collect()
    }
    pub fn add_tap(&self, t: Tap) {
        self.taps.write().unwrap().push(t);
    }
    pub fn set_context_engine(&self, e: Arc<dyn ContextEngine>) {
        *self.engine.write().unwrap() = Some(e);
    }
    fn engine(&self) -> Option<Arc<dyn ContextEngine>> {
        self.engine.read().unwrap().clone()
    }
    pub fn add_lifecycle(&self, l: Arc<dyn crate::lifecycle::Lifecycle>) {
        self.lifecycles.write().unwrap().push(l);
    }
    fn lifecycles(&self) -> Vec<Arc<dyn crate::lifecycle::Lifecycle>> {
        self.lifecycles.read().unwrap().clone()
    }
    /// Names of the registered observers (diagnostics and tests: proves a subsystem attached).
    pub fn lifecycle_names(&self) -> Vec<String> {
        self.lifecycles().iter().map(|l| l.name()).collect()
    }
    /// Builtin system segments plus those lifecycle observers contribute (same id replaces).
    fn system_segments(&self, ws: &Path) -> Vec<SystemSegment> {
        let cfg = self.cfg_now();
        let mut segs = context::system_segments(&cfg, &self.paths, ws, &self.specs(), cfg.schedule.utc_offset_minutes);
        let wss = ws.to_string_lossy();
        for l in self.lifecycles() {
            let Some(seg) = l.system_segment(&wss) else { continue };
            if let Some(old) = segs.iter_mut().find(|s| s.id == seg.id) {
                *old = seg;
            } else {
                let at = segs.iter().position(|s| s.id == "project").unwrap_or(segs.len());
                segs.insert(at, seg);
            }
        }
        segs.retain(|s| !s.text.trim().is_empty());
        segs
    }
    pub fn add_slash(&self, s: Arc<dyn crate::slash::Slash>) {
        self.slash.write().unwrap().push(s);
    }
    /// Registered native slash commands as (name, description).
    pub fn slash_commands(&self) -> Vec<(String, String)> {
        self.slash.read().unwrap().iter().flat_map(|s| s.commands()).collect()
    }
    /// Run `line` if it is a registered native slash command (`None` otherwise).
    pub fn run_slash(self: &Arc<Self>, line: &str, session: Option<&str>, surface: &str) -> Option<Result<crate::slash::SlashReply, String>> {
        let (name, args) = crate::slash::split(line)?;
        let handlers = self.slash.read().unwrap().clone();
        let ctx = crate::slash::SlashCtx { kernel: self.clone(), session: session.map(String::from), surface: surface.to_string() };
        handlers.iter().find_map(|h| h.run(&ctx, name, args))
    }

    /// Fire a hook whose `field` a hook may replace; returns the replacement (warnings go to the log).
    fn transform(&self, log: &mut SessionLog, event: HookEvent, tool: Option<&str>, payload: Value, field: &str) -> Result<Option<Value>, StoreError> {
        if !self.hooks.read().unwrap().iter().any(|h| h.wants(event, tool)) {
            return Ok(None);
        }
        Ok(self.fire(Some(log), event, tool, payload, field)?.modified)
    }

    /// Run every matching hook in order. A block wins immediately; modifications
    /// chain (each hook sees the previous one's input); broken hooks only warn.
    pub(crate) fn fire(&self, log: Option<&mut SessionLog>, event: HookEvent, tool: Option<&str>, mut payload: Value, field: &str) -> Result<Fired, StoreError> {
        let hooks: Vec<_> = self.hooks.read().unwrap().iter().filter(|h| h.wants(event, tool)).cloned().collect();
        let mut fired = Fired::default();
        let mut warnings = Vec::new();
        for h in hooks {
            match h.run(event, &payload) {
                Ok(HookDecision::Allow) => {}
                Ok(HookDecision::Block(r)) => {
                    fired.block = Some(format!("{}: {r}", h.name()));
                    break;
                }
                Ok(HookDecision::Modify(v)) => {
                    payload[field] = v.clone();
                    fired.modified = Some(v);
                }
                Ok(HookDecision::Context(c)) => fired.context.push(hooks::spill::spill(&c, payload.get("session_id").and_then(Value::as_str).unwrap_or(""), "hook")),
                Err(e) => warnings.push(format!("hook {} failed ({e}); continuing", h.name())),
            }
        }
        match log {
            Some(log) => {
                for w in warnings {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: w })?;
                }
            }
            None => warnings.iter().for_each(|w| eprintln!("ark: {w}")),
        }
        Ok(fired)
    }

    pub fn has_hooks(&self, event: HookEvent) -> bool {
        self.hooks.read().unwrap().iter().any(|h| h.wants(event, None))
    }

    /// Hooks for events the host raises (channels, daemon, CLI): returns (block reason,
    /// replacement for `payload[field]`). Warnings go to stderr, never to a session log
    /// (the session may be running on another thread).
    pub fn emit(&self, event: HookEvent, payload: Value, field: &str) -> (Option<String>, Option<Value>) {
        if !self.has_hooks(event) {
            return (None, None);
        }
        let f = self.fire(None, event, None, payload, field).unwrap_or_default();
        (f.block, f.modified)
    }

    /// Fire `session_end` for a session the host is done with.
    pub fn end_session(&self, id: &str, reason: &str) {
        if matches!(reason, "new" | "reset" | "idle" | "daily" | "forget") && self.has_hooks(HookEvent::BeforeReset) {
            self.before_reset(id, reason);
        }
        if self.has_hooks(HookEvent::SessionEnd) {
            let ws = self.store.open(id).map(|l| project(l.events()).workspace).unwrap_or_default();
            let mut p = hooks::payload(id, &ws, None, None, None, None);
            p["reason"] = reason.into();
            self.emit(HookEvent::SessionEnd, p, "");
        }
    }

    // ───────────────────────── public API ─────────────────────────

    pub fn create_session(&self, workspace: &Path, model: Option<&str>, parent: Option<&str>, title: Option<&str>) -> Result<String, KernelError> {
        let model = self.cfg.resolve_model(model.unwrap_or(&self.cfg.model.default)).to_string();
        if !model.contains('/') {
            return Err(KernelError::Invalid(format!("model must be provider/model, got `{model}`")));
        }
        let ws = workspace.canonicalize().map_err(|e| KernelError::Invalid(format!("workspace {}: {e}", workspace.display())))?;
        if !ws.is_dir() {
            return Err(KernelError::Invalid(format!("workspace {} is not a directory", ws.display())));
        }
        let id = new_id();
        let mut log = self.store.create(EventKind::Header {
            version: LOG_VERSION,
            session_id: id.clone(),
            workspace: ws.to_string_lossy().into(),
            model,
            parent: parent.map(String::from),
            title: title.map(|t| t.chars().take(80).collect()),
        })?;
        let mut segs = self.system_segments(&ws);
        let fired = self.fire(Some(&mut log), HookEvent::SessionStart, None, hooks::payload(&id, &ws.to_string_lossy(), None, None, None, None), "")?;
        if !fired.context.is_empty() {
            // Frozen with the other segments, so it stays cache-friendly.
            segs.push(SystemSegment { id: "hook_context".into(), text: fired.context.join("\n\n"), cache: false });
        }
        self.append(&mut log, EventKind::System { segments: segs })?;
        Ok(id)
    }

    /// Queue input durably. If the session is running, it is steered mid-turn.
    pub fn submit(&self, id: &str, text: &str, source: &str) -> Result<(), KernelError> {
        self.submit_with(id, text, vec![], source)
    }

    /// `submit` plus extra content blocks (images) for the same user message.
    pub fn submit_with(&self, id: &str, text: &str, attachments: Vec<Block>, source: &str) -> Result<(), KernelError> {
        if text.trim().is_empty() && attachments.is_empty() {
            return Err(KernelError::Invalid("empty prompt".into()));
        }
        let mut text = text.to_string();
        if self.hooks.read().unwrap().iter().any(|h| h.wants(HookEvent::UserPrompt, None)) {
            let ws = self.store.open(id).map(|l| project(l.events()).workspace).unwrap_or_default();
            let f = self.fire(None, HookEvent::UserPrompt, None, hooks::payload(id, &ws, None, None, None, Some(&text)), "prompt")?;
            if let Some(b) = f.block {
                return Err(KernelError::Invalid(format!("prompt blocked by {b}")));
            }
            if let Some(m) = f.modified.as_ref().and_then(Value::as_str) {
                text = m.to_string();
            }
            for c in f.context {
                text.push_str(&format!("\n\n[context from hook]\n{c}"));
            }
        }
        let text = text.as_str();
        crate::secgate::note_source(id, source);
        let running = self.running.lock().unwrap();
        let inbox_id = new_id();
        if let Some(r) = running.get(id) {
            let s = self.queue_for(id);
            let item = (inbox_id, source.to_string(), text.to_string(), attachments);
            match s.mode {
                crate::queue::Mode::Steer => r.queue.lock().unwrap().push(item),
                mode => {
                    if let Some(n) = crate::queue::hold(&r.later, item, &s) {
                        eprintln!("ark: session {id}: {n}");
                    }
                    if mode == crate::queue::Mode::Interrupt {
                        r.restart.store(true, std::sync::atomic::Ordering::SeqCst);
                        r.cancel.cancel();
                    }
                }
            }
            return Ok(());
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Inbox { id: inbox_id, source: source.into(), text: text.into(), attachments })?;
        Ok(())
    }

    /// Effective `/queue` settings for a session.
    pub fn queue_for(&self, id: &str) -> crate::queue::Settings {
        self.queue_settings.lock().unwrap().get(id).copied().unwrap_or_else(|| crate::queue::Settings { mode: crate::queue::Mode::parse(&self.cfg.runner.busy_mode).unwrap_or_default(), ..Default::default() })
    }

    pub fn set_queue(&self, id: &str, s: crate::queue::Settings) {
        self.queue_settings.lock().unwrap().insert(id.to_string(), s);
    }

    /// Input waiting for this session: held for later turns while running, or still in the
    /// inbox. `(inbox id, source, text)`.
    pub fn queued(&self, id: &str) -> Vec<QueuedInput> {
        if let Some(r) = self.running.lock().unwrap().get(id) {
            let mut v: Vec<_> = r.queue.lock().unwrap().iter().map(|q| (q.0.clone(), q.1.clone(), q.2.clone())).collect();
            v.extend(r.later.lock().unwrap().iter().map(|q| (q.0.clone(), q.1.clone(), q.2.clone())));
            return v;
        }
        self.store.open(id).map(|l| project(l.events()).pending_inbox.into_iter().map(|q| (q.0, q.1, q.2)).collect()).unwrap_or_default()
    }

    /// Edit the waiting input: `f` gets the list and may remove, reorder or rewrite entries.
    /// Removed inbox entries are recorded as discarded so they never run.
    pub fn edit_queue(&self, id: &str, f: &dyn Fn(&mut Vec<QueuedInput>)) -> Result<usize, KernelError> {
        if let Some(r) = self.running.lock().unwrap().get(id) {
            let mut l = r.later.lock().unwrap();
            let mut v: Vec<_> = l.iter().map(|q| (q.0.clone(), q.1.clone(), q.2.clone())).collect();
            f(&mut v);
            let old = std::mem::take(&mut *l);
            for (qid, src, t) in &v {
                let att = old.iter().find(|o| &o.0 == qid).map(|o| o.3.clone()).unwrap_or_default();
                l.push((qid.clone(), src.clone(), t.clone(), att));
            }
            return Ok(l.len());
        }
        let mut log = self.store.open(id)?;
        let before = project(log.events()).pending_inbox;
        let mut v: Vec<_> = before.iter().map(|q| (q.0.clone(), q.1.clone(), q.2.clone())).collect();
        f(&mut v);
        let unchanged = v.len() == before.len() && v.iter().zip(&before).all(|(a, b)| a.0 == b.0 && a.2 == b.2);
        if unchanged {
            return Ok(v.len());
        }
        // Rewrite: discard every old entry, re-add the new order.
        self.append(&mut log, EventKind::Discard { inbox: before.iter().map(|q| q.0.clone()).collect() })?;
        for (qid, src, t) in &v {
            let att = before.iter().find(|o| &o.0 == qid).map(|o| o.3.clone()).unwrap_or_default();
            self.append(&mut log, EventKind::Inbox { id: new_id(), source: src.clone(), text: t.clone(), attachments: att })?;
        }
        Ok(v.len())
    }

    pub fn interrupt(&self, id: &str) -> bool {
        match self.running.lock().unwrap().get(id) {
            Some(r) => {
                r.cancel.cancel();
                true
            }
            None => false,
        }
    }
    pub fn is_running(&self, id: &str) -> bool {
        self.running.lock().unwrap().contains_key(id)
    }
    pub fn running_ids(&self) -> Vec<String> {
        self.running.lock().unwrap().keys().cloned().collect()
    }

    pub fn set_model(&self, id: &str, model: &str) -> Result<(), KernelError> {
        let model = self.cfg.resolve_model(model.trim());
        if !model.contains('/') {
            return Err(KernelError::Invalid(format!("model must be provider/model or an alias from model.aliases, got `{model}`")));
        }
        if !self.cfg.model_allowed(model) {
            return Err(KernelError::Invalid(format!("model `{model}` is not in model.allow")));
        }
        self.record(id, EventKind::Model { model: model.into() })
    }

    /// Reasoning effort for the session's next requests ("" = provider default).
    pub fn set_thinking(&self, id: &str, level: &str) -> Result<(), KernelError> {
        if !matches!(level, "" | "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max") {
            return Err(KernelError::Invalid(format!("thinking level `{level}`: use off, minimal, low, medium, high, xhigh or max")));
        }
        self.record(id, EventKind::Thinking { level: level.into() })
    }

    /// Fast mode for the session's next requests ("" = config default).
    pub fn set_fast(&self, id: &str, tier: &str) -> Result<(), KernelError> {
        let t = match tier.trim().to_lowercase().as_str() {
            "" | "default" | "inherit" => "",
            "normal" | "off" | "standard" | "none" => "normal",
            "fast" | "on" | "priority" => "fast",
            "ultra" | "ultrafast" => "ultrafast",
            "flex" => "flex",
            "auto" => "auto",
            "cold" => "cold",
            other => return Err(KernelError::Invalid(format!("fast mode `{other}`: use on, off, ultrafast, flex, auto or cold"))),
        };
        self.record(id, EventKind::Fast { tier: t.into() })
    }

    /// Record an auxiliary call's usage on the session and charge the running turn's ledger.
    fn aux_used(&self, log: &mut SessionLog, task: &str, model: &str, usage: Usage) {
        if usage.input_tokens + usage.output_tokens + usage.cache_read_tokens == 0 {
            return;
        }
        Ledger::charge_current(&usage, self.cfg.price(model));
        let _ = self.append(log, EventKind::AuxUsage { task: task.into(), model: model.into(), usage });
    }

    pub fn set_title(&self, id: &str, title: &str) -> Result<(), KernelError> {
        self.record(id, EventKind::Title { title: title.chars().take(80).collect() })
    }

    /// Tools that exist only for one session (e.g. MCP servers an editor brought);
    /// shipped with full schemas. An empty list removes them.
    pub fn set_session_tools(&self, id: &str, tools: Vec<Arc<dyn Tool>>) {
        let mut st = self.session_tools.write().unwrap();
        if tools.is_empty() {
            st.remove(id);
        } else {
            st.insert(id.to_string(), tools);
        }
    }
    fn session_specs(&self, id: &str, model: &str) -> Vec<ToolSpec> {
        let mut v = self.specs();
        if let Some(ts) = self.session_tools.read().unwrap().get(id) {
            v.extend(ts.iter().map(|t| ToolSpec { pinned: true, ..t.spec() }).filter(|s| !self.cfg.tools.disabled.contains(&s.name)));
        }
        // Tool profiles / allow-deny groups (OpenClaw tool policy).
        v.retain(|s| self.tool_permitted(id, model, &s.name));
        v
    }

    /// Force compaction now (`/compact`).
    pub fn compact(&self, id: &str) -> Result<bool, KernelError> {
        let mut log = self.store.open(id)?;
        let view = project(log.events());
        Ok(self.summarise(&mut log, &view, &Cancel::new())?)
    }

    /// Run until the inbox is empty (or the run stops). Blocks the caller.
    pub fn run(self: &Arc<Self>, id: &str, opts: RunOpts) -> Result<Outcome, KernelError> {
        let mut cancel = opts.cancel.as_ref().map(|c| c.child()).unwrap_or_default();
        let queue = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let later = Arc::new(Mutex::new(Vec::new()));
        let restart = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut running = self.running.lock().unwrap();
            if running.contains_key(id) {
                return Err(KernelError::AlreadyRunning(id.into()));
            }
            running.insert(id.to_string(), Running { cancel: cancel.clone(), queue: queue.clone(), events: events.clone(), later: later.clone(), restart: restart.clone() });
        }
        struct Unregister<'a>(&'a Runtime, String);
        impl Drop for Unregister<'_> {
            fn drop(&mut self) {
                self.0.running.lock().unwrap().remove(&self.1);
            }
        }
        let _guard = Unregister(self, id.to_string());
        let mut log = self.store.open(id)?;
        let ledger = opts.ledger.clone().unwrap_or_else(|| Ledger::new(self.cfg.budget.clone()));
        if ledger.has_cost_cap() {
            let model = project(log.events()).model;
            if self.cfg.price(&model).is_none() {
                let text = format!("no price known for `{model}`: the USD budget cannot be enforced (run `ark models refresh`, or add `[prices.\"{model}\"]`)");
                self.append(&mut log, EventKind::Notice { level: "warn".into(), text })?;
            }
        }
        let mut total = Usage::default();
        let mut turns = 0;
        let mut text = String::new();

        let mut resume = self.recover(&mut log, &cancel)?;
        self.recover_subagents(&mut log)?;
        let mut reason = EndReason::Idle;
        loop {
            self.drain_queue(&mut log, &queue)?;
            if project(log.events()).pending_inbox.is_empty() && !resume {
                // Background sub-agents report back between turns: wait for them here.
                if !opts.detach && self.await_children(&mut log, &queue, &cancel)? {
                    continue;
                }
                break;
            }
            resume = false;
            let o = self.turn(&mut log, &ledger, &cancel, opts.depth, &queue, opts.goal_mode)?;
            let ws = project(log.events()).workspace;
            let mut p = hooks::payload(&log.id, &ws, None, None, None, None);
            p["last_assistant_message"] = o.text.clone().into();
            p["end_reason"] = o.reason.label().into();
            self.fire(Some(&mut log), HookEvent::TurnEnd, None, p, "")?;
            turns += 1;
            total.add(&o.usage);
            text = o.text;
            reason = o.reason;
            if (reason.ok() || reason == EndReason::Interrupted) && restart.swap(false, std::sync::atomic::Ordering::SeqCst) {
                // `interrupt` mode: a new message stopped this turn; run it now.
                cancel = opts.cancel.as_ref().map(|c| c.child()).unwrap_or_default();
                if let Some(r) = self.running.lock().unwrap().get_mut(id) {
                    r.cancel = cancel.clone();
                }
                self.drain_queue(&mut log, &later)?;
                continue;
            }
            if !reason.ok() {
                break;
            }
            let mode = self.queue_for(id).mode;
            for (qid, source, t, attachments) in crate::queue::release(&later, mode) {
                self.append(&mut log, EventKind::Inbox { id: qid, source, text: t, attachments })?;
            }
        }
        // Whatever is still held stays queued in the log for the next run.
        self.drain_queue(&mut log, &later)?;
        // A run that made progress is no longer paused (the marker only existed to make the
        // retry happen); one that ended `Paused` keeps it for `limits::due_pauses`.
        if reason.ok() {
            let _ = crate::limits::resumed(&self.paths.data, id);
        }
        // C7: a sub-agent that ended must not leave process groups behind. Detached
        // processes (explicitly asked to outlive ark) are recorded but never reaped.
        if project(log.events()).parent.is_some() {
            crate::reaper::on_session_end(&self.paths.data, id);
        }
        self.close_run(id, log)?;
        Ok(Outcome { reason, text, usage: total, turns })
    }

    /// Spawn the run on a background thread (daemon use).
    pub fn start(self: &Arc<Self>, id: &str, opts: RunOpts) -> std::thread::JoinHandle<Result<Outcome, KernelError>> {
        let k = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || k.run(&id, opts))
    }

    /// Append a settings event to a session, running or not.
    pub fn record(&self, id: &str, kind: EventKind) -> Result<(), KernelError> {
        {
            let running = self.running.lock().unwrap();
            if let Some(r) = running.get(id) {
                r.events.lock().unwrap().push(kind);
                return Ok(());
            }
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, kind)?;
        Ok(())
    }

    pub(crate) fn drain_queue(&self, log: &mut SessionLog, q: &Mutex<Vec<Queued>>) -> Result<(), StoreError> {
        let evs: Vec<EventKind> = self.running.lock().unwrap().get(&log.id).map(|r| std::mem::take(&mut *r.events.lock().unwrap())).unwrap_or_default();
        for e in evs {
            self.append(log, e)?;
        }
        let items: Vec<_> = std::mem::take(&mut *q.lock().unwrap());
        for (id, source, text, attachments) in items {
            self.append(log, EventKind::Inbox { id, source, text, attachments })?;
        }
        Ok(())
    }

    // ───────────────────────── recovery ─────────────────────────

    /// Resolve a crash mid-step. Returns true if the conversation now needs a reply.
    fn recover(self: &Arc<Self>, log: &mut SessionLog, cancel: &Cancel) -> Result<bool, StoreError> {
        let view = project(log.events());
        let mut changed = false;
        // Nested (code-mode) or orphaned write-ahead records: settle them.
        let dangling_ids: Vec<&str> = view.dangling.iter().map(|(i, _, _)| i.as_str()).collect();
        for u in &view.unsettled {
            if !dangling_ids.contains(&u.tool_use_id.as_str()) {
                self.append(log, EventKind::ToolSettled { tool_use_id: u.tool_use_id.clone(), is_error: true, bytes: 0, artifact: None, ui_resource: None })?;
            }
        }
        if !view.dangling.is_empty() {
            self.append(log, EventKind::Notice { level: "warn".into(), text: format!("recovering {} tool call(s) interrupted by a crash", view.dangling.len()) })?;
            let mut blocks = Vec::new();
            for (id, name, input) in &view.dangling {
                let settled_artifact = log.events().iter().find_map(|e| match &e.kind {
                    EventKind::ToolSettled { tool_use_id, artifact, .. } if tool_use_id == id => Some(artifact.clone()),
                    _ => None,
                });
                let tool = self.tool(&log.id, name);
                let idempotent = tool.as_ref().is_some_and(|t| t.spec().idempotent);
                let out = match settled_artifact {
                    Some(Some(a)) => ToolOutput::ok(format!("[recovered after crash; full output saved at {a}]")),
                    Some(None) if !idempotent => ToolOutput::ok("[the call completed before a crash but its output was lost; check the resulting state before continuing]"),
                    _ if idempotent && !cancel.is_cancelled() => {
                        let ctx = self.ctx(&view, log, cancel, 0, Ledger::new(Budget::default()));
                        let o = run_tool(tool.as_ref().unwrap().as_ref(), &ctx, input.clone());
                        if settled_artifact.is_none() {
                            self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: o.is_error, bytes: o.content.len(), artifact: None, ui_resource: None })?;
                        }
                        o
                    }
                    _ => {
                        if settled_artifact.is_none() {
                            self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: true, bytes: 0, artifact: None, ui_resource: None })?;
                        }
                        ToolOutput::err(format!("[interrupted by a crash while running `{name}`; its side effects are unknown — inspect the state before retrying]"))
                    }
                };
                let content = self.guard_tool_output(name, self.vault.redact(&out.content), out.is_error);
                blocks.push(Block::ToolResult { tool_use_id: id.clone(), content, is_error: out.is_error });
            }
            self.append(log, EventKind::Message { message: Message { role: Role::User, content: blocks }, usage: None, model: None, inbox: None })?;
            changed = true;
        }
        let view = project(log.events());
        // A turn that started but never ended (crash after a tool-result message).
        let open_turn = log.events().iter().rev().find_map(|e| match &e.kind {
            EventKind::TurnStart { .. } => Some(true),
            EventKind::TurnEnd { .. } => Some(false),
            _ => None,
        });
        Ok(changed || (open_turn == Some(true) && view.messages.last().is_some_and(|m| m.role == Role::User)))
    }

    // ───────────────────────── the turn ─────────────────────────

    fn turn(self: &Arc<Self>, log: &mut SessionLog, ledger: &Ledger, cancel: &Cancel, depth: u32, queue: &Mutex<Vec<Queued>>, goal_mode: bool) -> Result<Outcome, StoreError> {
        let cfg = self.cfg_now();
        let turn_no = project(log.events()).turns;
        self.append(log, EventKind::TurnStart { turn: turn_no })?;
        let _charge_aux_here = ledger.enter();
        // Bounded fast mode (Hermes `/fast auto|cold`): this user turn runs fast for a window.
        let fast_word = project(log.events()).fast.unwrap_or_else(|| cfg.model.fast.clone());
        let fast_until = match fast_word.as_str() {
            "auto" => Some(Instant::now() + Duration::from_secs(cfg.model.fast_auto_seconds)),
            "cold" if turn_no == 0 => Some(Instant::now() + Duration::from_secs(cfg.model.fast_auto_seconds)),
            _ => None,
        };
        self.consume_inbox(log)?;
        self.checkpoint(log);
        let mut th = match self.turn_start_hooks(log, depth)? {
            Ok(th) => th,
            Err(text) => {
                // Answered by a hook (gate refusal or before_agent_reply): no model call.
                let usage = Usage::default();
                self.append(log, EventKind::TurnEnd { turn: turn_no, reason: EndReason::Done.label(), usage })?;
                return Ok(Outcome { reason: EndReason::Done, text, usage, turns: 1 });
            }
        };
        let _scope = hookpoints::ScopeGuard::set(&th);

        let mut usage = Usage::default();
        let mut steps = 0u64;
        let mut continuations = 0;
        let mut boost = 0u32;
        let mut overflow_retry = false;
        let mut repeats: Vec<String> = Vec::new();
        let mut last_text = String::new();
        let mut structured_nudges = 0;
        let start_view = project(log.events());
        // A new turn: the edit → verify bookkeeping starts empty.
        crate::ctxrun::reset_turn(&self.ctx, &log.id);
        let kernel_tools: Vec<ToolSchema> = self.kernel_tools(goal_mode).into_iter().chain(start_view.output_schema.as_ref().map(crate::decision::structured_output_schema)).filter(|t| crate::subagents::tool_allowed(&start_view, &t.name)).collect();
        crate::secgate::last_source(log);
        let specs: Vec<ToolSpec> = self.session_specs(&log.id, &self.session_model(log)).into_iter().filter(|t| crate::subagents::tool_allowed(&start_view, &t.name)).collect();
        let mut human_wait_seen = ark_security::approvals::human_wait_total(&log.id);
        // C8 cadence: measure at most once per `[limits] check_interval_secs` (default 60 s);
        // with no `[limits]` section `check` returns `Ok` without any I/O.
        let limit_tick = Duration::from_secs(cfg.limits.check_interval_secs.max(5));
        let mut last_limits = Instant::now();

        let reason = loop {
            if cancel.is_cancelled() {
                break EndReason::Interrupted;
            }
            // Time blocked on a human approval does not count against the wall budget.
            let hw = ark_security::approvals::human_wait_total(&log.id);
            ledger.pause(hw.saturating_sub(human_wait_seen));
            human_wait_seen = hw;
            if let Err(e) = ledger.check() {
                break EndReason::Budget(e.to_string());
            }
            // C8: resource caps (spend, processes, disk). Passive: it never asks, and a breach
            // stops this session only — the fleet, cron jobs and the daemon keep running.
            if last_limits.elapsed() >= limit_tick {
                last_limits = Instant::now();
                match crate::limits::check(self, &log.id) {
                    crate::limits::Verdict::Pause(r) => {
                        self.append(log, EventKind::Notice { level: "warn".into(), text: format!("paused: {r}") })?;
                        break EndReason::Paused(format!("limits: {r}"));
                    }
                    crate::limits::Verdict::Warn(r) => {
                        self.append(log, EventKind::Notice { level: "warn".into(), text: r })?;
                    }
                    crate::limits::Verdict::Ok => {}
                }
            }
            if steps >= cfg.runner.max_steps_per_turn {
                break EndReason::MaxSteps;
            }
            self.drain_queue(log, queue)?;
            self.consume_inbox(log)?;

            let mut view = project(log.events());
            if self.maybe_compact(log, &view, cancel)? {
                view = project(log.events());
            }
            let model = th.model.clone().unwrap_or_else(|| view.model.clone());
            let mut req = context::build_request(&view, &cfg, &specs, &kernel_tools, &model);
            req.options.native_compaction = cfg.compaction.native_threshold(self.window(&model));
            if fast_until.is_some_and(|u| Instant::now() < u) {
                req.options.service_tier = Some("priority".into());
            }
            self.assemble(log, &view, &mut req)?;
            th.apply(&mut req);
            if boost > 0 {
                req.max_tokens = req.max_tokens.saturating_mul(1 << boost).min(MAX_BOOSTED_TOKENS);
            }
            let req_max = req.max_tokens;
            let resp = match self.call_model(log, &model, req, cancel)? {
                Ok(r) => r,
                Err(e) if e.kind == ProviderErrorKind::ContextOverflow && !overflow_retry => {
                    overflow_retry = true;
                    self.append(log, EventKind::Notice { level: "warn".into(), text: "context overflow: compacting and retrying".into() })?;
                    let v = project(log.events());
                    self.prune(log, &v, 0)?;
                    let v = project(log.events());
                    self.summarise(log, &v, cancel)?;
                    continue;
                }
                Err(e) if e.kind == ProviderErrorKind::Cancelled => break EndReason::Interrupted,
                // C1/C2: a transient failure or a drained account pauses the run instead of
                // ending it. Nothing is lost (the log is the state), nothing is asked, and the
                // daemon retries on its own (limits::due_pauses → bump_pause).
                Err(e) if crate::limits::classify(self, &e).is_some() => {
                    let (kind, wait) = crate::limits::classify(self, &e).unwrap_or((crate::limits::PauseKind::Transient, Duration::from_secs(60)));
                    let why = format!("{} provider failure: {e}", kind.label());
                    crate::limits::record_pause(&self.paths.data, &log.id, kind, &e.to_string(), wait);
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("paused ({why}); state saved, retrying automatically in {:.0} min", wait.as_secs_f32() / 60.0) })?;
                    break EndReason::Paused(format!("{why}; retry in {}s", wait.as_secs()));
                }
                Err(e) => {
                    self.append(log, EventKind::Error { message: e.to_string() })?;
                    break EndReason::Error(e.to_string());
                }
            };
            overflow_retry = false;
            // The provider answered: a pause from an earlier attempt is over.
            let _ = crate::limits::resumed(&self.paths.data, &log.id);
            steps += 1;
            usage.add(&resp.usage);
            ledger.charge(&resp.usage, cfg.price(&model));
            let msg = sanitize_assistant(resp.message);
            let text = msg.text();
            let visible = !text.trim().is_empty();
            if visible {
                last_text = text;
            }
            let uses: Vec<(String, String, Value)> = msg.tool_uses().map(|(i, n, v)| (i.to_string(), n.to_string(), v.clone())).collect();
            // Reasoning models can spend the whole output budget thinking. Asking
            // them to "continue" restarts the thinking; retry with more room instead,
            // dropping the empty reply so the transcript stays valid.
            if matches!(resp.stop, StopReason::MaxTokens) && uses.is_empty() && !visible && req_max < MAX_BOOSTED_TOKENS {
                boost += 1;
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("output limit ({req_max} tokens) used up by reasoning with nothing visible; retrying with {}", req_max.saturating_mul(2).min(MAX_BOOSTED_TOKENS)) })?;
                continue;
            }
            self.append(log, EventKind::Message { message: msg, usage: Some(resp.usage), model: Some(resp.model.clone()), inbox: None })?;

            if !uses.is_empty() {
                let (results, goal_done) = self.execute(log, &view, uses.clone(), cancel, depth, ledger)?;
                let mut blocks = results;
                // Watchdog: identical calls repeating.
                for (_, name, input) in &uses {
                    repeats.push(format!("{name}:{input}"));
                }
                let lim = cfg.runner.repeat_limit.max(2);
                let streak = repeats.iter().rev().take_while(|s| *s == repeats.last().unwrap()).count();
                if streak >= lim * 2 {
                    blocks.push(Block::text("[watchdog] stopping: the same call keeps repeating."));
                    self.append(log, EventKind::Message { message: Message { role: Role::User, content: blocks }, usage: None, model: None, inbox: None })?;
                    break EndReason::Stuck(format!("`{}` repeated {streak} times", uses[0].1));
                }
                if streak >= lim {
                    blocks.push(Block::text(format!("[watchdog] You have made the identical call `{}` {streak} times in a row; the result will not change. Change approach.", uses[0].1)));
                }
                self.append(log, EventKind::Message { message: Message { role: Role::User, content: blocks }, usage: None, model: None, inbox: None })?;
                if let Some((achieved, summary)) = goal_done {
                    last_text = summary;
                    break if achieved { EndReason::Done } else { EndReason::Error("goal declared unachievable".into()) };
                }
                if self.end_turn.lock().unwrap().remove(&log.id) {
                    break EndReason::Done;
                }
                if ledger.pressure() >= 0.9 {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: "budget almost exhausted".into() })?;
                }
                continue;
            }
            match resp.stop {
                StopReason::MaxTokens if continuations < cfg.runner.max_continuations => {
                    continuations += 1;
                    self.append(log, EventKind::Message { message: Message::user("[Your reply was cut off by the output limit. Continue exactly where you stopped.]"), usage: None, model: None, inbox: None })?;
                }
                StopReason::MaxTokens => break EndReason::MaxTokens,
                StopReason::Refusal => break EndReason::Refusal,
                _ => {
                    // Steering that arrived during the last step continues the turn.
                    self.drain_queue(log, queue)?;
                    if !project(log.events()).pending_inbox.is_empty() {
                        continue;
                    }
                    // A session with an output contract ends only through `structured_output`.
                    if view.output_schema.is_some() && structured_nudges < crate::decision::STRUCTURED_NUDGES {
                        structured_nudges += 1;
                        self.append(log, EventKind::Message { message: Message::user(crate::decision::STRUCTURED_NUDGE), usage: None, model: None, inbox: None })?;
                        continue;
                    }
                    if let Some(instr) = self.finalize_revision(log, &mut th, &last_text)? {
                        self.append(log, EventKind::Message { message: Message::user(instr), usage: None, model: None, inbox: None })?;
                        continue;
                    }
                    // Edit → verify before finishing (Hermes `verify_hooks.py`): the built-in
                    // nudge, `context.pre_verify` commands, or a registered `VerifyGate`.
                    let src = crate::secgate::last_source(log);
                    let messaging = !matches!(src.as_str(), "" | "cli" | "user" | "tui" | "web" | "chat");
                    let ws = project(log.events()).workspace;
                    if let Some(instr) = crate::ctxrun::verify_message(&self.cfg, &self.ctx, &log.id, &ws, &last_text, messaging) {
                        self.append(log, EventKind::Message { message: Message::user(instr), usage: None, model: None, inbox: None })?;
                        continue;
                    }
                    break EndReason::Done;
                }
            }
        };
        self.append(log, EventKind::TurnEnd { turn: turn_no, reason: reason.label(), usage })?;
        if reason.ok() && depth == 0 && cfg.compaction.micro_compact {
            // Hermes micro-compaction runs after the turn, before the next request.
            let _ = self.micro_pass(log, &Cancel::default());
        }
        let lcs = self.lifecycles();
        if !lcs.is_empty() {
            let v = project(log.events());
            let prompt = v.messages.iter().rev().find(|m| m.role == Role::User && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))).map(|m| crate::lifecycle::strip_fences(&m.text())).unwrap_or_default();
            for l in lcs {
                l.turn_end(&log.id, &v.workspace, &prompt, &last_text, reason.ok());
            }
        }
        if cfg.learn.enabled && reason == EndReason::Done && depth == 0 {
            self.review(log, cancel);
        }
        Ok(Outcome { reason, text: last_text, usage, turns: 1 })
    }

    /// Let the context engine choose what the model sees this step.
    fn assemble(&self, log: &mut SessionLog, view: &View, req: &mut ModelRequest) -> Result<(), StoreError> {
        let Some(e) = self.engine() else { return Ok(()) };
        let prompt = view.messages.iter().rev().find(|m| m.role == Role::User && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))).map(|m| m.text()).unwrap_or_default();
        match e.assemble(&log.id, &view.workspace, &req.messages, self.window(&view.model), &view.model, &prompt) {
            Ok(Some(a)) if crate::engine::valid(&a.messages) => {
                req.messages = a.messages;
                req.cache_after_message = None;
                if let Some(t) = a.system_addition.filter(|t| !t.trim().is_empty()) {
                    req.system.push(SystemSegment { id: "context_engine".into(), text: t, cache: false });
                }
            }
            Ok(Some(_)) => {
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("context engine {} returned an invalid history (must start and end with a user message); using ark's", e.name()) })?;
            }
            Ok(None) => {}
            Err(w) => {
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("context engine {} failed ({w}); using ark's history", e.name()) })?;
            }
        }
        Ok(())
    }

    fn consume_inbox(&self, log: &mut SessionLog) -> Result<(), StoreError> {
        let pending = project(log.events()).pending_inbox;
        let ws = if pending.is_empty() { String::new() } else { project(log.events()).workspace };
        let lcs = if pending.is_empty() { vec![] } else { self.lifecycles() };
        for (id, source, text, attachments) in pending {
            let mut body = if source == "cli" || source == "user" { text.clone() } else { format!("[from {source}] {text}") };
            // `@file:` / `@folder:` / `@diff` / `@git:N` / `@url:` attach context to this turn
            // (Hermes `context_references.py`); warnings ride along in the message.
            if source == "cli" || source == "user" {
                let wsdir = PathBuf::from(&ws);
                let win = self.window(&self.session_model(log));
                let (expanded, warnings) = crate::ctxrun::expand_refs(&self.cfg, &self.paths, &wsdir, &body, win);
                if expanded != body {
                    body = expanded;
                }
                for w in warnings {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("@-reference: {w}") })?;
                }
            }
            for l in &lcs {
                if let Some(extra) = l.prefetch(&log.id, &ws, &text).filter(|t| !t.trim().is_empty()) {
                    body.push_str(&crate::lifecycle::fence(&l.name(), &extra));
                }
            }
            let mut message = Message::user(body);
            message.content.extend(attachments);
            self.append(log, EventKind::Message { message, usage: None, model: None, inbox: Some(id) })?;
        }
        Ok(())
    }

    fn checkpoint(&self, log: &mut SessionLog) {
        if !self.cfg.checkpoint.enabled {
            return;
        }
        let ws = PathBuf::from(project(log.events()).workspace);
        let turn = project(log.events()).turns;
        let r = Checkpoints::new(&self.paths.data, &ws).and_then(|c| {
            let c = c.with_limits(self.cfg.checkpoint.limits());
            let id = c.snapshot(&format!("session {}", log.id), self.cfg.checkpoint.max_files)?;
            // Unchanged workspace: this turn starts from the newest checkpoint.
            Ok(id.or_else(|| c.list(1).ok().and_then(|l| l.first().map(|x| x.id.clone()))))
        });
        match r {
            Ok(Some(id)) => {
                let _ = self.append(log, EventKind::Checkpoint { id, turn });
            }
            Ok(None) => {}
            Err(e) => {
                let _ = self.append(log, EventKind::Notice { level: "info".into(), text: format!("checkpoint skipped: {e}") });
            }
        }
    }

    // ───────────────────────── model calls ─────────────────────────

    /// Retries with backoff, then falls back along the chain. Outer Err = store failure.
    fn call_model(&self, log: &mut SessionLog, model: &str, mut req: ModelRequest, cancel: &Cancel) -> Result<Result<ModelResponse, ProviderError>, StoreError> {
        let mut chain = vec![model.to_string()];
        chain.extend(hookpoints::fallbacks(&self.cfg.model.fallback).into_iter().filter(|m| m != model));
        {
            let mut benched = self.benched.lock().unwrap();
            benched.retain(|_, t| t.elapsed() < BENCH_COOLDOWN);
            // Stable: healthy models keep their order, benched ones move to the back.
            chain.sort_by_key(|m| benched.contains_key(m));
        }
        let mut last = ProviderError::new(ProviderErrorKind::Network, "no provider tried");
        let mut no_fallback = false;
        let session = log.id.clone();
        if self.has_hooks(HookEvent::PreModel) {
            let mut p = hooks::payload(&session, "", None, None, None, None);
            p["model"] = model.into();
            p["messages"] = req.messages.len().into();
            p["tools"] = req.tools.len().into();
            if let Some(b) = self.fire(Some(log), HookEvent::PreModel, None, p, "")?.block {
                return Ok(Err(ProviderError::new(ProviderErrorKind::BadRequest, format!("model call blocked by {b}"))));
            }
        }
        // Middleware: rewrite the request, or answer it without a provider.
        let mw = |log: &mut SessionLog, ev: HookEvent, extra: Value, field: &str| -> Result<Option<Value>, StoreError> {
            let mut p = hooks::payload(&session, "", None, None, None, None);
            p["model"] = model.into();
            if let (Value::Object(o), Value::Object(x)) = (&mut p, extra) {
                o.extend(x);
            }
            self.transform(log, ev, None, p, field)
        };
        if let Some(v) = mw(log, HookEvent::LlmRequest, json!({"request": req}), "request")? {
            match serde_json::from_value::<ModelRequest>(v) {
                Ok(r) => req = r,
                Err(e) => {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("llm_request middleware returned an invalid request ({e}); ignoring it") })?;
                }
            }
        }
        if let Some(v) = mw(log, HookEvent::LlmExecution, json!({"phase": "call", "request": req}), "response")? {
            match response_from(v, model) {
                Some(r) => {
                    let r = self.finish_response(log, &session, r)?;
                    // Nothing streamed: show the answer like a provider would have.
                    self.bus.publish(BusMsg::Delta { session: session.clone(), text: r.message.text(), thinking: false });
                    return Ok(Ok(r));
                }
                None => {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: "llm_execution middleware returned no usable response; calling the model".into() })?;
                }
            }
        }
        for (ci, m) in chain.iter().enumerate() {
            let (pid, mname) = split_model(m);
            let provider = match self.resolver.provider(pid) {
                Ok(p) => p,
                Err(e) => {
                    last = ProviderError::new(ProviderErrorKind::Auth, format!("{pid}: {e}"));
                    // The last link's failure is reported once, as the run's error.
                    if ci + 1 < chain.len() {
                        self.append(log, EventKind::Notice { level: "warn".into(), text: format!("provider {pid} unavailable: {e}") })?;
                    }
                    continue;
                }
            };
            req.model = mname.to_string();
            // C12: this model already rejected a reasoning parameter once — do not send it again.
            if req.reasoning.is_some() && self.no_reasoning.lock().unwrap().contains(m) {
                req.reasoning = None;
            }
            // Wire-level image handling for THIS provider (Hermes image_eviction_policy +
            // vision_message_prep): non-vision models get text stand-ins, vision models get old
            // tool-result images retired once the request would cross a provider image limit.
            crate::imgprep::prepare_in_place(&mut req, provider.caps(mname).vision, &session);
            if ci > 0 {
                // Another provider cannot verify the previous one's reasoning signatures.
                strip_thinking(&mut req);
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("falling back to {m}") })?;
            }
            for attempt in 0..=self.cfg.runner.max_retries {
                if cancel.is_cancelled() {
                    return Ok(Err(ProviderError::new(ProviderErrorKind::Cancelled, "cancelled")));
                }
                let bus = &self.bus;
                let mut on = |e: StreamEvent| match e {
                    StreamEvent::TextDelta(t) => bus.publish(BusMsg::Delta { session: session.clone(), text: t, thinking: false }),
                    StreamEvent::ThinkingDelta(t) => bus.publish(BusMsg::Delta { session: session.clone(), text: t, thinking: true }),
                    StreamEvent::ToolUseStart { .. } => {}
                };
                match provider.complete(&req, &mut on, cancel) {
                    Ok(mut r) => {
                        if r.model.is_empty() {
                            r.model = m.clone();
                        } else if !r.model.contains('/') {
                            r.model = format!("{pid}/{}", r.model);
                        }
                        return Ok(Ok(self.finish_response(log, &session, r)?));
                    }
                    Err(e) => {
                        if matches!(e.kind, ProviderErrorKind::Cancelled | ProviderErrorKind::ContextOverflow | ProviderErrorKind::BadRequest) {
                            // C12: a brand-new model that does not know a reasoning field answers
                            // 400. Spend one probe, then remember the model and retry without it —
                            // the user never sees the failure, and no other model is affected.
                            if e.kind == ProviderErrorKind::BadRequest && req.reasoning.is_some() && names_a_reasoning_field(&e.message) {
                                self.no_reasoning.lock().unwrap().insert(m.clone());
                                req.reasoning = None;
                                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("{m} rejected the reasoning parameter ({}); retrying without it for this model", e.message.chars().take(120).collect::<String>()) })?;
                                continue;
                            }
                            return Ok(Err(e));
                        }
                        let mut retryable = e.is_retryable();
                        if let Some(c) = mw(log, HookEvent::TransformApiError, json!({"classification": {"kind": format!("{:?}", e.kind), "message": e.message, "retryable": retryable, "fallback": e.allows_fallback()}}), "classification")? {
                            retryable = c["retryable"].as_bool().unwrap_or(retryable);
                            no_fallback |= c["fallback"] == false;
                        }
                        let retry = retryable && attempt < self.cfg.runner.max_retries;
                        last = e.clone();
                        if !retry {
                            break;
                        }
                        let wait = self.backoff(attempt, &e);
                        self.append(log, EventKind::Notice { level: "warn".into(), text: format!("{m}: {e}; retry {}/{} in {:.1}s", attempt + 1, self.cfg.runner.max_retries, wait.as_secs_f32()) })?;
                        let until = Instant::now() + wait;
                        while Instant::now() < until {
                            if cancel.is_cancelled() {
                                return Ok(Err(ProviderError::new(ProviderErrorKind::Cancelled, "cancelled")));
                            }
                            std::thread::sleep(Duration::from_millis(50).min(until - Instant::now()));
                        }
                    }
                }
            }
            // Rejected (auth/credit) or still rate-limited after every retry: try it last for a while.
            if matches!(last.kind, ProviderErrorKind::Auth | ProviderErrorKind::RateLimited { .. }) {
                self.benched.lock().unwrap().insert(m.clone(), Instant::now());
            }
            if !last.allows_fallback() || no_fallback {
                break;
            }
        }
        Ok(Err(last))
    }

    /// Execution middleware's result phase, post_model, transform_llm_output.
    fn finish_response(&self, log: &mut SessionLog, session: &str, mut r: ModelResponse) -> Result<ModelResponse, StoreError> {
        let base = |model: &str| {
            let mut p = hooks::payload(session, "", None, None, None, None);
            p["model"] = model.into();
            p
        };
        let mut p = base(&r.model);
        p["phase"] = "result".into();
        p["response"] = json!(r);
        if let Some(v) = self.transform(log, HookEvent::LlmExecution, None, p, "response")? {
            let m = r.model.clone();
            match response_from(v, &m) {
                Some(x) => r = x,
                None => {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: "llm_execution middleware returned no usable response; keeping the model's".into() })?;
                }
            }
        }
        if self.has_hooks(HookEvent::PostModel) {
            let mut p = base(&r.model);
            p["text"] = r.message.text().into();
            p["stop"] = json!(r.stop);
            p["usage"] = json!(r.usage);
            self.fire(Some(log), HookEvent::PostModel, None, p, "")?;
        }
        let mut p = base(&r.model);
        p["text"] = r.message.text().into();
        if let Some(t) = self.transform(log, HookEvent::TransformLlmOutput, None, p, "text")?.as_ref().and_then(Value::as_str) {
            // The new text replaces the text blocks; tool calls and reasoning stay.
            r.message.content.retain(|b| !matches!(b, Block::Text { .. }));
            r.message.content.insert(0, Block::text(t));
        }
        Ok(r)
    }

    fn backoff(&self, attempt: u32, e: &ProviderError) -> Duration {
        if let Some(d) = self.retry_sleep {
            return d;
        }
        if let ProviderErrorKind::RateLimited { retry_after: Some(d) } = e.kind {
            return d.min(Duration::from_millis(self.cfg.runner.retry_max_ms));
        }
        let base = self.cfg.runner.retry_base_ms.saturating_mul(1 << attempt.min(16));
        let jitter = crate::event::now_ms() % 250;
        Duration::from_millis(base.min(self.cfg.runner.retry_max_ms) + jitter)
    }

    // ───────────────────────── compaction ─────────────────────────

    fn window(&self, model: &str) -> u64 {
        let (pid, m) = split_model(model);
        // A window this endpoint reported about itself (its `/models` answer, recorded by
        // `ark models list`) is more accurate than the catalogue guess — compaction thresholds
        // follow it, so an endpoint that really has 32k does not overflow twice before pruning.
        let base = self.cfg.providers.get(pid).and_then(|t| t.get("base_url")).and_then(|v| v.as_str()).unwrap_or("");
        if let Some(w) = ark_model::contextpin::learned(m, base) {
            return w;
        }
        self.resolver.provider(pid).map(|p| p.caps(m).context_window).ok().filter(|w| *w > 0).unwrap_or(128_000)
    }

    fn maybe_compact(&self, log: &mut SessionLog, view: &View, cancel: &Cancel) -> Result<bool, StoreError> {
        let window = self.window(&view.model) as f64;
        let used = if view.last_input_tokens > 0 { view.last_input_tokens } else { estimate_request_tokens(&ModelRequest { model: String::new(), system: view.system.clone(), messages: view.messages.clone(), tools: vec![], max_tokens: 0, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() }) } as f64;
        let c = &self.cfg.compaction;
        if used < window * c.prune_threshold {
            return Ok(false);
        }
        let pruned = self.prune(log, view, c.keep_tool_results)?;
        if used < window * c.threshold {
            return Ok(pruned);
        }
        let v = if pruned { project(log.events()) } else { view.clone() };
        Ok(self.summarise(log, &v, cancel)? || pruned)
    }

    fn prune(&self, log: &mut SessionLog, view: &View, keep: usize) -> Result<bool, StoreError> {
        let ids = compaction::prune_candidates(view, keep);
        if ids.is_empty() {
            return Ok(false);
        }
        self.append(log, EventKind::Prune { tool_use_ids: ids })?;
        Ok(true)
    }

    /// `{{secret:NAME}}` substitution with the vault (for hosts resolving config values).
    pub fn vault_substitute(&self) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
        let v = self.vault.clone();
        Arc::new(move |s: &str| v.substitute(s))
    }

    /// One model completion outside any session (MCP sampling). `model` = "provider/model",
    /// default the aux model. `tools` are offered to the model as-is (sampling tool
    /// rounds: the caller executes nothing, it returns the `tool_use` blocks). Returns
    /// (reply, model used, stop reason).
    pub fn sample(&self, model: Option<&str>, system: &str, messages: Vec<Message>, tools: Vec<ToolSchema>, max_tokens: u32, cancel: &Cancel) -> Result<(Message, String, StopReason), String> {
        let m = model.filter(|m| !m.is_empty()).map(|m| self.cfg.resolve_model(m).to_string()).unwrap_or_else(|| self.cfg.task_model("sampling").to_string());
        let (pid, name) = split_model(&m);
        let p = self.resolver.provider(pid)?;
        if !tools.is_empty() && !p.caps(name).tools {
            return Err(format!("model `{m}` does not support tool use; sampling with tools needs one that does"));
        }
        let req = ModelRequest {
            model: name.to_string(),
            system: if system.is_empty() { vec![] } else { vec![SystemSegment { id: "mcp-sampling".into(), text: system.to_string(), cache: false }] },
            messages,
            tools,
            max_tokens,
            temperature: None,
            cache_after_message: None,
            reasoning: None,
            options: Default::default(),
        };
        let r = p.complete(&req, &mut |_| {}, cancel).map_err(|e| e.message)?;
        Ledger::charge_current(&r.usage, self.cfg.price(&m));
        // Reasoning stays here: sampling results carry text and tool calls only.
        let content = r.message.content.into_iter().filter(|b| !matches!(b, Block::Thinking { .. })).collect();
        Ok((Message { role: Role::Assistant, content }, m, r.stop))
    }

    fn summarise(&self, log: &mut SessionLog, view: &View, cancel: &Cancel) -> Result<bool, StoreError> {
        // An engine that owns compaction writes the summary (and picks how much to keep).
        let mut owned = None;
        if let Some(e) = self.engine().filter(|e| e.owns_compaction()) {
            let current = estimate_tokens(&compaction::render_transcript(&view.messages, usize::MAX));
            match e.compact(&log.id, &view.messages, self.window(&view.model), current, true) {
                Ok(Some(c)) => owned = Some(c),
                Ok(None) => return Ok(false),
                Err(w) => {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("context engine {} could not compact ({w}); using ark's summary", e.name()) })?;
                }
            }
        }
        let keep = owned.as_ref().and_then(|c| c.keep_messages).unwrap_or(self.cfg.compaction.keep_messages);
        let Some(cut) = compaction::cut_index(&view.messages, keep) else { return Ok(false) };
        let aux = self.cfg.task_model("compaction").to_string();
        let (pid, m) = split_model(&aux);
        let before = estimate_tokens(&compaction::render_transcript(&view.messages, usize::MAX));
        let hp = |n: &str, v: Value| {
            let mut p = hooks::payload(&log.id, &view.workspace, None, None, None, None);
            p["messages"] = view.messages.len().into();
            p["tokens_before"] = before.into();
            p[n] = v;
            p
        };
        let (pre, post) = (hp("compacting", cut.into()), hp("compacted", cut.into()));
        if self.has_hooks(HookEvent::PreCompact) {
            if let Some(b) = self.fire(Some(log), HookEvent::PreCompact, None, pre, "")?.block {
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("compaction skipped: {b}") })?;
                return Ok(false);
            }
        }
        for l in self.lifecycles() {
            l.pre_compress(&log.id, &view.workspace, &view.messages[..cut]);
        }
        let (summary, fallback) = match (owned, self.resolver.provider(pid)) {
            (Some(c), _) => (c.summary, false),
            (None, Ok(p)) => {
                let metered = Metered { inner: p, usage: Mutex::new(Usage::default()) };
                let r = compaction::summarise(&metered, m, &view.messages[..cut], cancel);
                let u = *metered.usage.lock().unwrap();
                self.aux_used(log, "compaction", &aux, u);
                r
            }
            (None, Err(_)) => (compaction::fallback_summary(&view.messages[..cut]), true),
        };
        if fallback {
            self.append(log, EventKind::Notice { level: "warn".into(), text: "summary model unavailable or low quality; used deterministic digest".into() })?;
        }
        self.append(log, EventKind::Compaction { upto_seq: view.message_seqs[cut], summary, pruned: vec![], tokens_before: before })?;
        // The history was rewritten: micro-compaction starts over from the new summary.
        crate::ctxrun::micro_reset(&self.ctx, &log.id);
        if self.has_hooks(HookEvent::PostCompact) {
            self.fire(Some(log), HookEvent::PostCompact, None, post, "")?;
        }
        // The cache breaks here anyway: refresh memory / project segments.
        let ws = PathBuf::from(&view.workspace);
        let segs = self.system_segments(&ws);
        if segs != view.system {
            self.append(log, EventKind::System { segments: segs })?;
        }
        Ok(true)
    }

    /// Micro-compaction (Hermes `agent/micro_compaction.py`): every N turns fold the oldest
    /// un-absorbed exchange into a rolling summary, keeping the recent tail byte-identical.
    /// The rolling summary is one `Compaction` event, so replays and rewinds still see what
    /// the model saw.
    fn micro_pass(&self, log: &mut SessionLog, cancel: &Cancel) -> Result<bool, StoreError> {
        if !self.cfg.compaction.micro_compact {
            return Ok(false);
        }
        let view = project(log.events());
        let Some((start, end, _prev, defrag)) = crate::ctxrun::micro_plan(&self.cfg, &self.ctx, &log.id, &view) else { return Ok(false) };
        let Some(&upto) = view.message_seqs.get(end) else { return Ok(false) };
        if start >= end || end > view.messages.len() {
            return Ok(false);
        }
        let aux = self.cfg.task_model("compaction").to_string();
        let (pid, m) = split_model(&aux);
        let Ok(p) = self.resolver.provider(pid) else { return Ok(false) };
        let metered = Metered { inner: p, usage: Mutex::new(Usage::default()) };
        let (fold, fallback) = compaction::summarise(&metered, m, &view.messages[start..end], cancel);
        let u = *metered.usage.lock().unwrap();
        self.aux_used(log, "micro_compaction", &aux, u);
        if fallback || fold.trim().is_empty() {
            // No usable summary: leave the history alone rather than lose detail.
            return Ok(false);
        }
        let before = estimate_tokens(&compaction::render_transcript(&view.messages[start..end], usize::MAX));
        let mut rolling = crate::ctxrun::micro_commit(&self.ctx, &log.id, &fold);
        if defrag {
            let (condensed, _) = compaction::summarise(&metered, m, &[Message::user(rolling.clone())], cancel);
            if !condensed.trim().is_empty() {
                crate::ctxrun::micro_defrag(&self.ctx, &log.id, &condensed);
                rolling = crate::ctxrun::micro_summary(&self.ctx, &log.id).unwrap_or(rolling);
            }
        }
        self.append(log, EventKind::Compaction { upto_seq: upto, summary: rolling, pruned: vec![], tokens_before: before })?;
        Ok(true)
    }

    // ───────────────────────── tools ─────────────────────────

    fn ctx(self: &Arc<Self>, view: &View, log: &SessionLog, cancel: &Cancel, depth: u32, ledger: Ledger) -> ToolCtx {
        let vault = self.vault.clone();
        ToolCtx {
            workspace: PathBuf::from(&view.workspace),
            session_id: log.id.clone(),
            artifacts: log.artifacts(),
            home: self.paths.data.clone(),
            cancel: cancel.child(),
            host: Arc::new(Host { rt: self.clone(), session: log.id.clone(), workspace: PathBuf::from(&view.workspace), depth, ledger, conversation: view.messages.clone() }),
            secrets: Arc::new(move |s: &str| vault.substitute(s)),
        }
    }

    /// Gate, write-ahead, execute (parallel where safe), redact, spill, settle.
    #[allow(clippy::type_complexity)]
    fn execute(self: &Arc<Self>, log: &mut SessionLog, view: &View, uses: Vec<(String, String, Value)>, cancel: &Cancel, depth: u32, ledger: &Ledger) -> Result<(Vec<Block>, Option<(bool, String)>), StoreError> {
        let ctx = self.ctx(view, log, cancel, depth, ledger.clone());
        let mut results: Vec<Option<ToolOutput>> = vec![None; uses.len()];
        let mut runnable: Vec<(usize, Arc<dyn Tool>, Value)> = Vec::new();
        // Calls execution middleware answered (they skip the tool, not the transforms).
        let mut answered: Vec<(usize, String, Value)> = Vec::new();
        let mut goal_done = None;

        for (i, (id, name, input)) in uses.iter().enumerate() {
            // `tool_call {name, input}` is just indirection: unwrap it first so
            // kernel tools are reachable either way.
            let (tname, mut tinput) = if name == "tool_call" {
                let n = input.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if n.is_empty() {
                    results[i] = Some(ToolOutput::err("tool_call needs {\"name\": \"<tool>\", \"input\": {...}}; put the tool's arguments inside `input`."));
                    continue;
                }
                (n, input.get("input").cloned().unwrap_or(json!({})))
            } else {
                (name.clone(), input.clone())
            };
            if !crate::subagents::tool_allowed(view, &tname) {
                results[i] = Some(ToolOutput::err(format!("tool `{tname}` is not available in this session")));
                continue;
            }
            match tname.as_str() {
                "tool_describe" => {
                    crate::normalize::coerce(&json!({"properties":{"names":{"type":"array"}}}), &mut tinput);
                    let mut names: Vec<String> = tinput.get("names").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    if let Some(n) = tinput.get("name").and_then(|v| v.as_str()) {
                        names.push(n.to_string());
                    }
                    names.dedup();
                    if names.is_empty() {
                        results[i] = Some(ToolOutput::err("tool_describe needs `names`: [\"tool\", …]"));
                        continue;
                    }
                    let mut out = Vec::new();
                    let mut bad = 0;
                    for n in names.iter().take(12) {
                        let kernel = self.kernel_tools(true).into_iter().find(|t| &t.name == n).map(|t| (t.description, t.input_schema));
                        out.push(match (self.tool(&log.id, n), kernel) {
                            (Some(t), _) => {
                                let s = t.spec();
                                format!("## {n}\n{}\ninput schema: {}", s.description, s.input_schema)
                            }
                            (None, Some((d, sch))) => format!("## {n}\n{d}\ninput schema: {sch}\n(call it directly)"),
                            (None, None) => {
                                bad += 1;
                                format!("## {n}\n{}", self.unknown_tool(n))
                            }
                        });
                    }
                    let text = out.join("\n\n");
                    results[i] = Some(if bad == names.len().min(12) { ToolOutput::err(text) } else { ToolOutput::ok(text) });
                    continue;
                }
                "tool_search" => {
                    // BM25 over this session's tools (Hermes `tool_search.py`): the model asks
                    // by keyword when it does not know the tool's name.
                    crate::normalize::coerce(&json!({"properties":{"query":{"type":"string"},"limit":{"type":"integer"}}}), &mut tinput);
                    let specs = self.session_specs(&log.id, &self.session_model(log));
                    results[i] = Some(ToolOutput::ok(crate::ctxrun::tool_search(&specs, &self.cfg, &tinput)));
                    continue;
                }
                KERNEL_TOOL_SEARCH => {
                    crate::normalize::coerce(&crate::agents::session_search_schema(), &mut tinput);
                    results[i] = Some(ToolOutput::ok(crate::agents::session_search(&self.store, &tinput)));
                    continue;
                }
                crate::decision::STRUCTURED_OUTPUT if view.output_schema.is_some() => {
                    let out = match crate::decision::check_structured(view.output_schema.as_ref().unwrap(), &tinput) {
                        Ok(v) => {
                            self.append(log, EventKind::Structured { value: v })?;
                            self.end_turn.lock().unwrap().insert(log.id.clone());
                            ToolOutput::ok("accepted: the structured result was recorded; the turn ends here.")
                        }
                        Err(e) => ToolOutput::err(e),
                    };
                    results[i] = Some(out);
                    continue;
                }
                KERNEL_TOOL_GOAL_DONE => {
                    let s = tinput.get("summary").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let a = tinput.get("achieved").and_then(|v| v.as_bool()).unwrap_or(false);
                    goal_done = Some((a, s));
                    results[i] = Some(ToolOutput::ok("recorded"));
                    continue;
                }
                _ => {}
            }
            let p = hooks::payload(&log.id, &view.workspace, Some(&tname), Some(&tinput), None, None);
            if let Some(m) = self.transform(log, HookEvent::ToolRequest, Some(&tname), p, "tool_input")?.filter(Value::is_object) {
                tinput = m;
            }
            match self.pre_tool(log, id, &tname, &tinput, &view.workspace)? {
                Err(blocked) => {
                    results[i] = Some(blocked);
                    continue;
                }
                Ok(Some(m)) => tinput = m,
                Ok(None) => {}
            }
            if tname == "run" {
                runnable.push((i, Arc::new(RunMarker), tinput));
                continue;
            }
            let Some(tool) = self.tool(&log.id, &tname) else {
                results[i] = Some(ToolOutput::err(self.unknown_tool(&tname)));
                continue;
            };
            if let Some(refused) = hookpoints::tool_refused(&tname) {
                results[i] = Some(ToolOutput::err(refused));
                continue;
            }
            crate::normalize::coerce(&tool.spec().input_schema, &mut tinput);
            if let Some(bad) = invalid_input(&tinput) {
                results[i] = Some(ToolOutput::err(bad));
                continue;
            }
            if let Some(denied) = self.gate(log, id, &tname, &tool.effects(&ctx, &tinput), &tinput)? {
                results[i] = Some(denied);
                continue;
            }
            // Execution middleware may answer instead of the tool.
            let mut p = hooks::payload(&log.id, &view.workspace, Some(&tname), Some(&tinput), None, None);
            p["phase"] = "call".into();
            if let Some(v) = self.transform(log, HookEvent::ToolExecution, Some(&tname), p, "tool_response")? {
                results[i] = Some(output_from(v));
                answered.push((i, tname, tinput));
                continue;
            }
            let tool = self.exec_env_tool(log, &view.workspace, &tname, tool)?;
            runnable.push((i, tool, tinput));
        }

        // Write-ahead for everything about to run.
        for (i, tool, input) in &runnable {
            let id = &uses[*i].0;
            let key = format!("{}:{}:{}", log.id, log.next_seq(), id);
            let name = if tool.spec().name.is_empty() { "run".to_string() } else { tool.spec().name };
            self.append(log, EventKind::ToolCalled { tool_use_id: id.clone(), name, input: input.clone(), idempotency_key: key })?;
        }

        // Run: consecutive parallel-safe calls as a batch, others one by one.
        let mut idx = 0;
        while idx < runnable.len() {
            if cancel.is_cancelled() {
                for (i, _, _) in &runnable[idx..] {
                    results[*i] = Some(ToolOutput::err("cancelled before running"));
                }
                break;
            }
            let (i, tool, input) = &runnable[idx];
            if tool.spec().name.is_empty() {
                // Code mode: needs &mut log for nested calls.
                let out = self.code_mode(log, view, &uses[*i].0, input.clone(), &ctx)?;
                results[*i] = Some(out);
                idx += 1;
                continue;
            }
            if !tool.spec().parallel_safe {
                results[*i] = Some(run_tool(tool.as_ref(), &ctx, input.clone()));
                idx += 1;
                continue;
            }
            let mut end = idx;
            while end < runnable.len() && end - idx < self.cfg.runner.max_parallel_tools && runnable[end].1.spec().parallel_safe && !runnable[end].1.spec().name.is_empty() {
                end += 1;
            }
            let outs: Vec<(usize, ToolOutput)> = std::thread::scope(|s| {
                let hs: Vec<_> = runnable[idx..end].iter().map(|(i, t, inp)| (*i, s.spawn(|| run_tool(t.as_ref(), &ctx, inp.clone())))).collect();
                hs.into_iter().map(|(i, h)| (i, h.join().unwrap_or_else(|_| ToolOutput::err("tool panicked")))).collect()
            });
            for (i, o) in outs {
                results[i] = Some(o);
            }
            idx = end;
        }

        // Post-tool hooks may add feedback for the model.
        for (i, tool, input) in &runnable {
            let name = if tool.spec().name.is_empty() { "run".to_string() } else { tool.spec().name };
            if !self.hooks.read().unwrap().iter().any(|h| h.wants(HookEvent::PostTool, Some(&name))) {
                continue;
            }
            let Some(out) = results[*i].as_mut() else { continue };
            let resp = json!({"content": self.vault.redact(&out.content), "is_error": out.is_error});
            let p = hooks::payload(&log.id, &view.workspace, Some(&name), Some(input), Some(&resp), None);
            let f = self.fire(Some(log), HookEvent::PostTool, Some(&name), p, "")?;
            for note in f.block.into_iter().chain(f.context) {
                out.content.push_str(&format!("\n[hook] {note}"));
            }
        }

        // Middleware result phase, then the transform_* hooks (Hermes order: terminal output first).
        let ran_names = runnable.iter().map(|(i, t, inp)| (*i, if t.spec().name.is_empty() { "run".to_string() } else { t.spec().name }, inp.clone(), true));
        let post: Vec<(usize, String, Value, bool)> = ran_names.chain(answered.into_iter().map(|(i, n, v)| (i, n, v, false))).collect();
        for (i, name, input, ran) in &post {
            let Some(out) = results[*i].as_mut() else { continue };
            if *ran {
                let mut p = hooks::payload(&log.id, &view.workspace, Some(name), Some(input), Some(&json!({"content": self.vault.redact(&out.content), "is_error": out.is_error})), None);
                p["phase"] = "result".into();
                if let Some(v) = self.transform(log, HookEvent::ToolExecution, Some(name), p, "tool_response")? {
                    let ui = out.ui_resource.take();
                    *out = output_from(v);
                    out.ui_resource = ui;
                }
            }
            if name == "shell" {
                let mut p = hooks::payload(&log.id, &view.workspace, Some(name), Some(input), None, None);
                p["command"] = input["command"].clone();
                p["output"] = self.vault.redact(&out.content).into();
                if let Some(t) = self.transform(log, HookEvent::TransformTerminalOutput, Some(name), p, "output")?.as_ref().and_then(Value::as_str) {
                    out.content = t.to_string();
                }
            }
            let mut p = hooks::payload(&log.id, &view.workspace, Some(name), Some(input), Some(&json!({"is_error": out.is_error})), None);
            p["result"] = self.vault.redact(&out.content).into();
            if let Some(t) = self.transform(log, HookEvent::TransformToolResult, Some(name), p, "result")?.as_ref().and_then(Value::as_str) {
                out.content = t.to_string();
            }
        }

        // Redact, spill, settle.
        let mut blocks = Vec::new();
        let mut images = Vec::new();
        let ran: Vec<usize> = runnable.iter().map(|(i, _, _)| *i).collect();
        for (i, r) in results.into_iter().enumerate() {
            let id = &uses[i].0;
            let mut out = r.unwrap_or_else(|| ToolOutput::err("not executed"));
            if ark_core::tool::IMAGE_TOOLS.contains(&uses[i].1.as_str()) {
                // `read` of an image file: the model gets the picture itself.
                let (text, imgs) = ark_core::tool::take_images(&out.content);
                out.content = text;
                let mut imgs: Vec<Block> = imgs.into_iter().map(|(media_type, data)| Block::Image { media_type, data }).collect();
                // OpenClaw image-sanitization: shrink/re-encode before the model sees it
                // (installed by the binary; a no-op in a bare kernel).
                ark_core::tool::post_process_images(&mut imgs);
                images.extend(imgs);
            }
            let mut content = self.vault.redact(&out.content);
            if ran.contains(&i) {
                content = self.guard_tool_output(&uses[i].1, content, out.is_error);
            }
            let mut artifact = None;
            if content.len() > self.cfg.runner.spill_bytes {
                let path = log.artifacts().join(format!("{}.txt", sanitize_id(id)));
                if crate::util::atomic_write(&path, content.as_bytes()).is_ok() {
                    let (preview, _) = head_tail(&content, self.cfg.runner.spill_bytes / 2);
                    content = format!("{preview}\n[full output ({} bytes) saved to {} — read it with offset/limit instead of re-running]", content.len(), path.display());
                    artifact = Some(path.to_string_lossy().to_string());
                }
            }
            if ran.contains(&i) {
                // A touched subdirectory's own rules (AGENTS.md / CLAUDE.md / .cursorrules)
                // ride along with the first result that reached it (Hermes §12).
                if let Some(hint) = crate::ctxrun::subdir_hint(&self.cfg, &self.ctx, &log.id, &PathBuf::from(&view.workspace), &uses[i].1, &uses[i].2) {
                    content = format!("{content}\n\n{hint}");
                }
                crate::ctxrun::observe_tool(&self.cfg, &self.ctx, &log.id, &uses[i].1, &uses[i].2, out.is_error);
                for l in self.lifecycles() {
                    l.tool_settled(&log.id, &uses[i].1, &uses[i].2, out.is_error);
                }
                self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: out.is_error, bytes: out.content.len(), artifact, ui_resource: out.ui_resource.clone() })?;
            }
            blocks.push(Block::ToolResult { tool_use_id: id.clone(), content, is_error: out.is_error });
        }
        blocks.extend(images);
        Ok((blocks, goal_done))
    }

    /// Returns Some(error output) if the call must not run (floors, gates, approvals: see secgate.rs).
    fn gate(&self, log: &mut SessionLog, id: &str, tool: &str, effects: &[Effect], input: &Value) -> Result<Option<ToolOutput>, StoreError> {
        self.security_gate(log, id, tool, effects, input)
    }

    /// Ok(Err(output)) = blocked by a hook; Ok(Ok(Some(input))) = input rewritten.
    fn pre_tool(&self, log: &mut SessionLog, id: &str, tool: &str, input: &Value, ws: &str) -> Result<Result<Option<Value>, ToolOutput>, StoreError> {
        if !self.hooks.read().unwrap().iter().any(|h| h.wants(HookEvent::PreTool, Some(tool))) {
            return Ok(Ok(None));
        }
        let p = hooks::payload(&log.id, ws, Some(tool), Some(input), None, None);
        let f = self.fire(Some(log), HookEvent::PreTool, Some(tool), p, "tool_input")?;
        if let Some(b) = f.block {
            self.append(log, EventKind::Gate { tool_use_id: id.into(), gate: "hook".into(), verdict: "deny".into(), reason: b.clone() })?;
            return Ok(Err(ToolOutput::err(format!("Blocked by {b}. Do not retry the same call."))));
        }
        Ok(Ok(f.modified.filter(Value::is_object)))
    }

    fn code_mode(self: &Arc<Self>, log: &mut SessionLog, view: &View, parent_id: &str, input: Value, ctx: &ToolCtx) -> Result<ToolOutput, StoreError> {
        let script = input.get("script").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if script.trim().is_empty() {
            return Ok(ToolOutput::err("missing `script`"));
        }
        let lang = input.get("lang").and_then(|v| v.as_str()).unwrap_or("bash").to_string();
        // The script itself is a shell command: judge it like one.
        let effects = [Effect::Exec { command: script.clone() }];
        if let Some(denied) = self.gate(log, parent_id, "run", &effects, &input)? {
            return Ok(denied);
        }
        let timeout = Duration::from_secs(input.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(300).clamp(1, 3600));
        let (sid, reset) = (log.id.clone(), input.get("reset").and_then(|v| v.as_bool()).unwrap_or(false));
        let mut n = 0;
        let mut store_err: Option<StoreError> = None;
        let mut handle = |nested: crate::coderun::Nested| -> ToolOutput {
            n += 1;
            let nid = format!("{parent_id}.{n}");
            if !crate::subagents::tool_allowed(view, &nested.tool) {
                return ToolOutput::err(format!("tool `{}` is not available in this session", nested.tool));
            }
            let Some(tool) = self.tool(&log.id, &nested.tool) else {
                return ToolOutput::err(format!("unknown tool `{}`", nested.tool));
            };
            let mut nested = nested;
            crate::normalize::coerce(&tool.spec().input_schema, &mut nested.input);
            if let Some(bad) = invalid_input(&nested.input) {
                return ToolOutput::err(bad);
            }
            match self.pre_tool(log, &nid, &nested.tool, &nested.input, &view.workspace) {
                Ok(Err(blocked)) => return blocked,
                Ok(Ok(Some(m))) => nested.input = m,
                Ok(Ok(None)) => {}
                Err(e) => {
                    store_err = Some(e);
                    return ToolOutput::err("kernel log error");
                }
            }
            match self.gate(log, &nid, &nested.tool, &tool.effects(ctx, &nested.input), &nested.input) {
                Ok(Some(d)) => return d,
                Ok(None) => {}
                Err(e) => {
                    store_err = Some(e);
                    return ToolOutput::err("kernel log error");
                }
            }
            let key = format!("{}:{}:{nid}", log.id, log.next_seq());
            if let Err(e) = self.append(log, EventKind::ToolCalled { tool_use_id: nid.clone(), name: nested.tool.clone(), input: nested.input.clone(), idempotency_key: key }) {
                store_err = Some(e);
                return ToolOutput::err("kernel log error");
            }
            let out = run_tool(tool.as_ref(), ctx, nested.input);
            let _ = self.append(log, EventKind::ToolSettled { tool_use_id: nid, is_error: out.is_error, bytes: out.content.len(), artifact: None, ui_resource: None });
            ToolOutput { content: self.vault.redact(&out.content), is_error: out.is_error, ui_resource: None }
        };
        let req = crate::coderun::RunReq { script: &script, lang: &lang, timeout, workspace: Path::new(&view.workspace), session: &sid, reset, backend: None };
        let out = crate::coderun::run_opts(&self.paths.runtime, &req, &ctx.cancel, &mut handle);
        if let Some(e) = store_err {
            return Err(e);
        }
        Ok(out)
    }

    // ───────────────────────── learning loop ─────────────────────────

    /// Post-turn review: the aux model proposes memory entries, staged for the
    /// user (`ark memory review`). Never blocks or fails the turn.
    fn review(&self, log: &mut SessionLog, cancel: &Cancel) {
        let view = project(log.events());
        let tail: Vec<Message> = view.messages.iter().rev().take(12).rev().cloned().collect();
        let aux = self.cfg.task_model("review").to_string();
        let (pid, m) = split_model(&aux);
        let Ok(p) = self.resolver.provider(pid) else { return };
        let prompt = format!(
            "From this exchange, extract durable facts worth remembering across future sessions: user preferences, environment facts, lessons from mistakes. \
Reply ONLY with JSON: {{\"memory\": [\"...\"], \"user\": [\"...\"]}} (empty arrays if nothing is worth keeping). Never include secrets.\n\n{}",
            compaction::render_transcript(&tail, 1500)
        );
        let req = ModelRequest { model: m.into(), system: vec![], messages: vec![Message::user(prompt)], tools: vec![], max_tokens: 1024, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
        let Ok(r) = p.complete(&req, &mut |_| {}, cancel) else { return };
        self.aux_used(log, "review", &aux, r.usage);
        let text = r.message.text();
        let json_part = text.find('{').and_then(|a| text.rfind('}').map(|b| &text[a..=b]));
        let Some(Ok(v)) = json_part.map(serde_json::from_str::<Value>) else { return };
        let count = ["memory", "user"].iter().map(|k| v.get(k).and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0)).sum::<usize>();
        if count == 0 {
            return;
        }
        let path = self.paths.data.join("memory/staging").join(format!("{}.json", new_id()));
        let staged = json!({"session": log.id, "memory": v.get("memory"), "user": v.get("user")});
        if crate::util::atomic_write(&path, self.vault.redact(&staged.to_string()).as_bytes()).is_ok() {
            let _ = self.append(log, EventKind::Notice { level: "info".into(), text: format!("{count} memory suggestion(s) staged; run `ark memory review`") });
        }
    }
}

/// Counts the usage of every call through it (auxiliary accounting).
struct Metered {
    inner: Arc<dyn Provider>,
    usage: Mutex<Usage>,
}

impl Provider for Metered {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, model: &str) -> ark_core::ModelCaps {
        self.inner.caps(model)
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let r = self.inner.complete(req, on_event, cancel);
        if let Ok(x) = &r {
            self.usage.lock().unwrap().add(&x.usage);
        }
        r
    }
}

/// Marker so `run` can sit in the runnable list; its empty name routes it to code mode.
struct RunMarker;
impl Tool for RunMarker {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: String::new(), description: String::new(), input_schema: json!({}), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, _: Value) -> ToolOutput {
        ToolOutput::err("unreachable")
    }
}

fn run_tool(tool: &dyn Tool, ctx: &ToolCtx, input: Value) -> ToolOutput {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tool.call(ctx, input))) {
        Ok(o) => o,
        Err(p) => {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            ToolOutput::err(format!("tool `{}` crashed: {msg}", tool.spec().name))
        }
    }
}

/// Inputs the model botched (non-object, or unparseable JSON wrapped by the adapter).
fn invalid_input(v: &Value) -> Option<String> {
    let Some(o) = v.as_object() else { return Some("tool input must be a JSON object".into()) };
    for k in ["__invalid_input", "__invalid_json"] {
        if let (Some(raw), 1) = (o.get(k), o.len()) {
            return Some(format!("tool input must be a valid JSON object; got {}", head_tail(&raw.to_string(), 300).0));
        }
    }
    None
}

fn sanitize_id(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect()
}

/// Drop empty text blocks; give tool uses without ids a stable id.
fn sanitize_assistant(mut m: Message) -> Message {
    m.role = Role::Assistant;
    let mut n = 0;
    m.content.retain(|b| !matches!(b, Block::Text { text } if text.is_empty()));
    for b in &mut m.content {
        if let Block::ToolUse { id, input, .. } = b {
            if id.is_empty() {
                n += 1;
                *id = format!("call_{}_{n}", crate::util::random_hex(8));
            }
            if !input.is_object() {
                *input = json!({ "__invalid_input": input.clone() });
            }
        }
    }
    if m.content.is_empty() {
        m.content.push(Block::text(""));
    }
    m
}

fn strip_thinking(req: &mut ModelRequest) {
    for m in &mut req.messages {
        m.content.retain(|b| !matches!(b, Block::Thinking { .. }));
        if m.content.is_empty() {
            m.content.push(Block::text("(reasoning omitted)"));
        }
    }
}

/// A middleware's `tool_response`: `{content, is_error}` or plain text.
fn output_from(v: Value) -> ToolOutput {
    match v {
        Value::String(s) => ToolOutput::ok(s),
        v => {
            let content = match &v["content"] {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                c => c.to_string(),
            };
            ToolOutput { content, is_error: v["is_error"].as_bool().unwrap_or(false), ui_resource: None }
        }
    }
}

/// A middleware's `response`: a full ModelResponse, or the `{text}` shorthand.
fn names_a_reasoning_field(msg: &str) -> bool {
    let l = msg.to_lowercase();
    ["reasoning", "thinking", "output_config", "budget_tokens", "effort"].iter().any(|w| l.contains(w))
}

fn response_from(v: Value, model: &str) -> Option<ModelResponse> {
    if let Ok(mut r) = serde_json::from_value::<ModelResponse>(v.clone()) {
        if r.model.is_empty() {
            r.model = model.to_string();
        }
        return Some(r);
    }
    let t = v.get("text").and_then(Value::as_str).or(v.as_str())?;
    Some(ModelResponse { message: Message::assistant(t), stop: StopReason::EndTurn, usage: Usage { estimated: true, output_tokens: estimate_tokens(t), ..Default::default() }, model: model.to_string() })
}

pub(crate) struct Host {
    pub(crate) rt: Arc<Runtime>,
    pub(crate) session: String,
    pub(crate) workspace: PathBuf,
    pub(crate) depth: u32,
    pub(crate) ledger: Ledger,
    pub(crate) conversation: Vec<Message>,
}

impl Host {
    /// The kernel host behind a tool context (None for foreign hosts, e.g. tests).
    pub(crate) fn of(ctx: &ToolCtx) -> Option<&Host> {
        ctx.host.as_any()?.downcast_ref::<Host>()
    }
}

impl ToolHost for Host {
    fn spawn_agent(&self, req: SpawnRequest, cancel: &Cancel) -> Result<String, String> {
        let spec = crate::subagents::ChildSpec { goal: req.task, model: req.model, fork: req.fork, tools: req.tools, worktree: req.worktree, plain: true, ..Default::default() };
        let v = self.rt.delegate(self, vec![spec], crate::subagents::Mode::Sync, cancel)?;
        let e: crate::subagents::Entry = serde_json::from_value(v["results"][0].clone()).map_err(|e| e.to_string())?;
        let header = format!("[sub-agent {} · {} · {} tokens]", e.session_id, e.error.clone().unwrap_or_else(|| e.exit_reason.clone()), e.input_tokens + e.output_tokens);
        // Worktree isolation: say where the child's work was kept (branch / archive ref).
        let wt = e.worktree.as_ref().and_then(|w| w.note.clone()).map(|n| format!("\n[worktree: {n}]")).unwrap_or_default();
        if e.status == "completed" {
            Ok(format!("{header}\n{}{wt}", e.summary))
        } else {
            Err(format!("{header}\n{}{wt}", e.summary))
        }
    }
    fn ask_user(&self, question: &str) -> Result<String, String> {
        let mut p = hooks::payload(&self.session, &self.workspace.to_string_lossy(), None, None, None, None);
        p["kind"] = "question".into();
        p["message"] = question.into();
        self.rt.emit(HookEvent::Notification, p.clone(), "");
        self.rt.emit(HookEvent::HumanInputRequest, p.clone(), "");
        let a = self.rt.approver.ask(&self.session, question);
        if self.rt.has_hooks(HookEvent::HumanInputResolved) {
            p["answer"] = a.as_ref().map(|s| json!(s)).unwrap_or(Value::Null);
            p["cancelled"] = a.is_err().into();
            self.rt.emit(HookEvent::HumanInputResolved, p, "");
        }
        a
    }
    fn progress(&self, text: &str) {
        self.rt.bus.publish(BusMsg::Delta { session: self.session.clone(), text: text.to_string(), thinking: true });
    }
    /// Screenshot analysis (Hermes auxiliary vision): the aux model when it has vision,
    /// else the session's default model; neither → an error the tool reports.
    fn analyze_image(&self, question: &str, media_type: &str, data: &str) -> Result<String, String> {
        let pick = [self.rt.cfg.aux_model().to_string(), self.rt.cfg.model.default.clone()].into_iter().find(|m| {
            let (pid, name) = split_model(m);
            self.rt.resolver.provider(pid).is_ok_and(|p| p.caps(name).vision)
        });
        let m = pick.ok_or("no configured model has vision (set model.aux to a vision-capable model)")?;
        let msg = Message { role: Role::User, content: vec![Block::Image { media_type: media_type.into(), data: data.into() }, Block::text(question)] };
        let (r, _, _) = self.rt.sample(Some(&m), "Answer the question about the screenshot precisely and concisely.", vec![msg], vec![], 1024, &Cancel::new())?;
        Ok(r.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("\n"))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// C9: a sub-agent (`depth > 0`) gets its own home for anything it *spawns*: its own
    /// `ARK_HOME` (config, data, secrets), its own temp and cache dirs. A child that runs
    /// `ark config set …` or `ark auth …` therefore breaks only its own throwaway home —
    /// never the driver that spawned it. The kernel's own bookkeeping (board, leases,
    /// sessions, reaper registry) stays under the real data dir, so coordination still works.
    fn sandbox_env(&self) -> Vec<(String, String)> {
        if self.depth == 0 || self.session.is_empty() {
            return Vec::new();
        }
        let base = self.rt.paths.data.join("subagents").join(&self.session);
        let (home, tmp, cache, cfg) = (base.join("home"), base.join("tmp"), base.join("cache"), base.join("config"));
        for d in [&home, &tmp, &cache, &cfg] {
            let _ = std::fs::create_dir_all(d);
        }
        vec![
            ("ARK_HOME".into(), home.display().to_string()),
            ("TMPDIR".into(), tmp.display().to_string()),
            ("XDG_CACHE_HOME".into(), cache.display().to_string()),
            ("XDG_CONFIG_HOME".into(), cfg.display().to_string()),
        ]
    }
}
