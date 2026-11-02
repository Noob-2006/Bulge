//! The kernel: sessions, the turn/step runner, tool dispatch through the gates,
//! retries and provider fallback, compaction, crash recovery and sub-agents.

use crate::approver::{Approval, ApprovalRequest, Approver, PendingItem, Remembered};
use crate::checkpoint::Checkpoints;
use crate::compaction;
use crate::config::{Config, Paths};
use crate::context::{self, split_model};
use crate::engine::ContextEngine;
use crate::event::{Event, EventKind, LOG_VERSION};
use crate::gate::{Gates, Verdict};
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
}

struct Running {
    cancel: Cancel,
    queue: Arc<Mutex<Vec<Queued>>>,
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
    running: Mutex<HashMap<String, Running>>,
    /// Models whose provider rejected us (bad key, no credit): tried last until the
    /// cooldown passes, so each step doesn't pay for a doomed request first.
    benched: Mutex<HashMap<String, Instant>>,
    hooks: std::sync::RwLock<Vec<Arc<dyn Hook>>>,
    session_tools: std::sync::RwLock<HashMap<String, Vec<Arc<dyn Tool>>>>,
    taps: std::sync::RwLock<Vec<Tap>>,
    /// `context_engine = "<plugin>"`: shapes requests and may own compaction.
    engine: std::sync::RwLock<Option<Arc<dyn ContextEngine>>>,
    /// Test hook / determinism: override sleep between retries.
    pub retry_sleep: Option<Duration>,
}

pub type Kernel = Arc<Runtime>;

/// Synchronous event observer: runs on the appending thread before the bus sees
/// the event (e.g. snapshot a file's text before the tool that edits it runs).
pub type Tap = Arc<dyn Fn(&str, &Event) + Send + Sync>;

#[derive(Default)]
struct Fired {
    block: Option<String>,
    modified: Option<Value>,
    context: Vec<String>,
}

const BENCH_COOLDOWN: Duration = Duration::from_secs(600);
/// Ceiling when retrying a reply that reasoning truncated.
const MAX_BOOSTED_TOKENS: u32 = 32_768;

pub fn new_kernel(cfg: Config, paths: Paths, resolver: Arc<dyn Resolver>, tools: Vec<Arc<dyn Tool>>, vault: Arc<Vault>, approver: Arc<dyn Approver>) -> Kernel {
    let store = Store::new(paths.sessions());
    Arc::new(Runtime { cfg, paths, store, resolver, tools, vault, approver, remembered: Remembered::default(), bus: Bus::default(), running: Mutex::new(HashMap::new()), benched: Mutex::new(HashMap::new()), hooks: Default::default(), session_tools: Default::default(), taps: Default::default(), engine: Default::default(), retry_sleep: None })
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
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).filter(|s| !self.cfg.tools.disabled.contains(&s.name)).collect()
    }
    fn tool(&self, session: &str, name: &str) -> Option<Arc<dyn Tool>> {
        if self.cfg.tools.disabled.iter().any(|d| d == name) {
            return None;
        }
        self.tools.iter().find(|t| t.spec().name == name).cloned().or_else(|| self.session_tools.read().unwrap().get(session)?.iter().find(|t| t.spec().name == name).cloned())
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
                description: "Search past sessions' messages (case-insensitive, works for Chinese). Returns session ids and snippets.".into(),
                input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}},"required":["query"]}),
            },
        ];
        if goal_mode {
            v.push(ToolSchema {
                name: KERNEL_TOOL_GOAL_DONE.into(),
                description: "Declare the current goal achieved (or impossible) with a summary of the evidence. Only call when verified.".into(),
                input_schema: json!({"type":"object","properties":{"summary":{"type":"string"},"achieved":{"type":"boolean"}},"required":["summary","achieved"]}),
            });
        }
        v
    }

    fn append(&self, log: &mut SessionLog, kind: EventKind) -> Result<Event, StoreError> {
        let ev = log.append(kind)?;
        for t in self.taps.read().unwrap().iter() {
            t(&log.id, &ev);
        }
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
    pub fn add_tap(&self, t: Tap) {
        self.taps.write().unwrap().push(t);
    }
    pub fn set_context_engine(&self, e: Arc<dyn ContextEngine>) {
        *self.engine.write().unwrap() = Some(e);
    }
    fn engine(&self) -> Option<Arc<dyn ContextEngine>> {
        self.engine.read().unwrap().clone()
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
    fn fire(&self, log: Option<&mut SessionLog>, event: HookEvent, tool: Option<&str>, mut payload: Value, field: &str) -> Result<Fired, StoreError> {
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
                Ok(HookDecision::Context(c)) => fired.context.push(c),
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
        if self.has_hooks(HookEvent::SessionEnd) {
            let ws = self.store.open(id).map(|l| project(l.events()).workspace).unwrap_or_default();
            let mut p = hooks::payload(id, &ws, None, None, None, None);
            p["reason"] = reason.into();
            self.emit(HookEvent::SessionEnd, p, "");
        }
    }

    // ───────────────────────── public API ─────────────────────────

    pub fn create_session(&self, workspace: &Path, model: Option<&str>, parent: Option<&str>, title: Option<&str>) -> Result<String, KernelError> {
        let model = model.unwrap_or(&self.cfg.model.default).to_string();
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
        let mut segs = context::system_segments(&self.cfg, &self.paths, &ws, &self.specs(), self.cfg.schedule.utc_offset_minutes);
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
        let running = self.running.lock().unwrap();
        let inbox_id = new_id();
        if let Some(r) = running.get(id) {
            r.queue.lock().unwrap().push((inbox_id, source.into(), text.into(), attachments));
            return Ok(());
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Inbox { id: inbox_id, source: source.into(), text: text.into(), attachments })?;
        Ok(())
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
        if !model.contains('/') {
            return Err(KernelError::Invalid("model must be provider/model".into()));
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Model { model: model.into() })?;
        Ok(())
    }

    /// Reasoning effort for the session's next requests ("" = provider default).
    pub fn set_thinking(&self, id: &str, level: &str) -> Result<(), KernelError> {
        if !matches!(level, "" | "off" | "low" | "medium" | "high") {
            return Err(KernelError::Invalid(format!("thinking level `{level}`: use off, low, medium or high")));
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Thinking { level: level.into() })?;
        Ok(())
    }

    pub fn set_title(&self, id: &str, title: &str) -> Result<(), KernelError> {
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Title { title: title.chars().take(80).collect() })?;
        Ok(())
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
    fn session_specs(&self, id: &str) -> Vec<ToolSpec> {
        let mut v = self.specs();
        if let Some(ts) = self.session_tools.read().unwrap().get(id) {
            v.extend(ts.iter().map(|t| ToolSpec { pinned: true, ..t.spec() }).filter(|s| !self.cfg.tools.disabled.contains(&s.name)));
        }
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
        let cancel = opts.cancel.as_ref().map(|c| c.child()).unwrap_or_default();
        let queue = Arc::new(Mutex::new(Vec::new()));
        {
            let mut running = self.running.lock().unwrap();
            if running.contains_key(id) {
                return Err(KernelError::AlreadyRunning(id.into()));
            }
            running.insert(id.to_string(), Running { cancel: cancel.clone(), queue: queue.clone() });
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
        let mut total = Usage::default();
        let mut turns = 0;
        let mut text = String::new();

        let mut resume = self.recover(&mut log, &cancel)?;
        let mut reason = EndReason::Idle;
        loop {
            self.drain_queue(&mut log, &queue)?;
            if project(log.events()).pending_inbox.is_empty() && !resume {
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
            if !reason.ok() {
                break;
            }
        }
        Ok(Outcome { reason, text, usage: total, turns })
    }

    /// Spawn the run on a background thread (daemon use).
    pub fn start(self: &Arc<Self>, id: &str, opts: RunOpts) -> std::thread::JoinHandle<Result<Outcome, KernelError>> {
        let k = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || k.run(&id, opts))
    }

    fn drain_queue(&self, log: &mut SessionLog, q: &Mutex<Vec<Queued>>) -> Result<(), StoreError> {
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
                let content = self.vault.redact(&out.content);
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
        let turn_no = project(log.events()).turns;
        self.append(log, EventKind::TurnStart { turn: turn_no })?;
        self.consume_inbox(log)?;
        self.checkpoint(log);

        let mut usage = Usage::default();
        let mut steps = 0u64;
        let mut continuations = 0;
        let mut boost = 0u32;
        let mut overflow_retry = false;
        let mut repeats: Vec<String> = Vec::new();
        let mut last_text = String::new();
        let kernel_tools = self.kernel_tools(goal_mode);
        let specs = self.session_specs(&log.id);

        let reason = loop {
            if cancel.is_cancelled() {
                break EndReason::Interrupted;
            }
            if let Err(e) = ledger.check() {
                break EndReason::Budget(e.to_string());
            }
            if steps >= self.cfg.runner.max_steps_per_turn {
                break EndReason::MaxSteps;
            }
            self.drain_queue(log, queue)?;
            self.consume_inbox(log)?;

            let mut view = project(log.events());
            if self.maybe_compact(log, &view, cancel)? {
                view = project(log.events());
            }
            let mut req = context::build_request(&view, &self.cfg, &specs, &kernel_tools, &view.model);
            self.assemble(log, &view, &mut req)?;
            if boost > 0 {
                req.max_tokens = req.max_tokens.saturating_mul(1 << boost).min(MAX_BOOSTED_TOKENS);
            }
            let req_max = req.max_tokens;
            let resp = match self.call_model(log, &view.model, req, cancel)? {
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
                Err(e) => {
                    self.append(log, EventKind::Error { message: e.to_string() })?;
                    break EndReason::Error(e.to_string());
                }
            };
            overflow_retry = false;
            steps += 1;
            usage.add(&resp.usage);
            ledger.charge(&resp.usage, self.cfg.price(&view.model));
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
                let lim = self.cfg.runner.repeat_limit.max(2);
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
                if ledger.pressure() >= 0.9 {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: "budget almost exhausted".into() })?;
                }
                continue;
            }
            match resp.stop {
                StopReason::MaxTokens if continuations < self.cfg.runner.max_continuations => {
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
                    break EndReason::Done;
                }
            }
        };
        self.append(log, EventKind::TurnEnd { turn: turn_no, reason: reason.label(), usage })?;
        if self.cfg.learn.enabled && reason == EndReason::Done && depth == 0 {
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
        for (id, source, text, attachments) in project(log.events()).pending_inbox {
            let body = if source == "cli" || source == "user" { text } else { format!("[from {source}] {text}") };
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
        let r = Checkpoints::new(&self.paths.data, &ws).and_then(|c| c.snapshot(&format!("session {}", log.id), self.cfg.checkpoint.max_files));
        if let Err(e) = r {
            let _ = self.append(log, EventKind::Notice { level: "info".into(), text: format!("checkpoint skipped: {e}") });
        }
    }

    // ───────────────────────── model calls ─────────────────────────

    /// Retries with backoff, then falls back along the chain. Outer Err = store failure.
    fn call_model(&self, log: &mut SessionLog, model: &str, mut req: ModelRequest, cancel: &Cancel) -> Result<Result<ModelResponse, ProviderError>, StoreError> {
        let mut chain = vec![model.to_string()];
        chain.extend(self.cfg.model.fallback.iter().filter(|m| *m != model).cloned());
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
            if matches!(last.kind, ProviderErrorKind::Auth) {
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
        self.resolver.provider(pid).map(|p| p.caps(m).context_window).ok().filter(|w| *w > 0).unwrap_or(128_000)
    }

    fn maybe_compact(&self, log: &mut SessionLog, view: &View, cancel: &Cancel) -> Result<bool, StoreError> {
        let window = self.window(&view.model) as f64;
        let used = if view.last_input_tokens > 0 { view.last_input_tokens } else { estimate_request_tokens(&ModelRequest { model: String::new(), system: view.system.clone(), messages: view.messages.clone(), tools: vec![], max_tokens: 0, temperature: None, cache_after_message: None, reasoning: None }) } as f64;
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
        let m = model.filter(|m| !m.is_empty()).map(str::to_string).unwrap_or_else(|| self.cfg.aux_model().to_string());
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
        };
        let r = p.complete(&req, &mut |_| {}, cancel).map_err(|e| e.message)?;
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
        let aux = self.cfg.aux_model().to_string();
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
        let (summary, fallback) = match (owned, self.resolver.provider(pid)) {
            (Some(c), _) => (c.summary, false),
            (None, Ok(p)) => compaction::summarise(p.as_ref(), m, &view.messages[..cut], cancel),
            (None, Err(_)) => (compaction::fallback_summary(&view.messages[..cut]), true),
        };
        if fallback {
            self.append(log, EventKind::Notice { level: "warn".into(), text: "summary model unavailable or low quality; used deterministic digest".into() })?;
        }
        self.append(log, EventKind::Compaction { upto_seq: view.message_seqs[cut], summary, pruned: vec![], tokens_before: before })?;
        if self.has_hooks(HookEvent::PostCompact) {
            self.fire(Some(log), HookEvent::PostCompact, None, post, "")?;
        }
        // The cache breaks here anyway: refresh memory / project segments.
        let ws = PathBuf::from(&view.workspace);
        let segs = context::system_segments(&self.cfg, &self.paths, &ws, &self.specs(), self.cfg.schedule.utc_offset_minutes);
        if segs != view.system {
            self.append(log, EventKind::System { segments: segs })?;
        }
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
                KERNEL_TOOL_SEARCH => {
                    let q = tinput.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    let lim = tinput.get("limit").and_then(|v| v.as_u64()).unwrap_or(10).min(50) as usize;
                    let hits = self.store.search(q, lim);
                    results[i] = Some(if hits.is_empty() { ToolOutput::ok("no matches") } else { ToolOutput::ok(hits.iter().map(|h| format!("{} #{}: {}", h.session, h.seq, h.snippet)).collect::<Vec<_>>().join("\n")) });
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
        let ran: Vec<usize> = runnable.iter().map(|(i, _, _)| *i).collect();
        for (i, r) in results.into_iter().enumerate() {
            let id = &uses[i].0;
            let out = r.unwrap_or_else(|| ToolOutput::err("not executed"));
            let mut content = self.vault.redact(&out.content);
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
                self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: out.is_error, bytes: out.content.len(), artifact, ui_resource: out.ui_resource.clone() })?;
            }
            blocks.push(Block::ToolResult { tool_use_id: id.clone(), content, is_error: out.is_error });
        }
        Ok((blocks, goal_done))
    }

    /// Returns Some(error output) if the call must not run.
    fn gate(&self, log: &mut SessionLog, id: &str, tool: &str, effects: &[Effect], input: &Value) -> Result<Option<ToolOutput>, StoreError> {
        let verdict = Gates { cfg: &self.cfg.gate, vault: &self.vault }.judge(effects);
        let (gate, reason, ask) = match verdict {
            Verdict::Allow => return Ok(None),
            Verdict::Ask { gate, reason } => (gate, reason, true),
            Verdict::Deny { gate, reason } => (gate, reason, false),
        };
        let gname = format!("{gate:?}").to_lowercase();
        let decision = if !ask {
            "deny"
        } else if self.remembered.contains(&log.id, gate, &reason) {
            "allow (remembered)"
        } else {
            let redacted = self.vault.redact(&input.to_string());
            let req = ApprovalRequest { id: new_id(), tool_use_id: id.into(), session: log.id.clone(), tool: tool.into(), summary: head_tail(&redacted, 600).0, input: serde_json::from_str(&redacted).unwrap_or_default(), gate, reason: reason.clone() };
            self.bus.publish(BusMsg::Pending(PendingItem::Approval(req.clone())));
            let sid = log.id.clone();
            let ap = || {
                let mut p = hooks::payload(&sid, "", Some(tool), Some(&req.input), None, None);
                p["kind"] = "approval".into();
                p["gate"] = gname.clone().into();
                p["reason"] = reason.clone().into();
                p["message"] = format!("{tool} needs approval: {reason}").into();
                p
            };
            if self.has_hooks(HookEvent::Notification) {
                self.fire(Some(log), HookEvent::Notification, None, ap(), "")?;
            }
            if self.has_hooks(HookEvent::PreApprovalRequest) {
                self.fire(Some(log), HookEvent::PreApprovalRequest, None, ap(), "")?;
            }
            let (choice, d) = match self.approver.approve(&req) {
                Approval::Once => ("once", "allow"),
                Approval::Always => {
                    self.remembered.insert(&log.id, gate, &reason);
                    ("always", "allow (always)")
                }
                Approval::Deny => ("deny", "deny"),
            };
            if self.has_hooks(HookEvent::PostApprovalResponse) {
                let mut p = ap();
                p["choice"] = choice.into();
                self.fire(Some(log), HookEvent::PostApprovalResponse, None, p, "")?;
            }
            d
        };
        self.append(log, EventKind::Gate { tool_use_id: id.into(), gate: gname.clone(), verdict: decision.into(), reason: reason.clone() })?;
        if decision.starts_with("allow") {
            Ok(None)
        } else {
            Ok(Some(ToolOutput::err(format!("Blocked by the {gname} gate: {reason}. Do not retry the same call; choose another approach or tell the user what they need to do."))))
        }
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
        let mut n = 0;
        let mut store_err: Option<StoreError> = None;
        let mut handle = |nested: crate::coderun::Nested| -> ToolOutput {
            n += 1;
            let nid = format!("{parent_id}.{n}");
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
        let out = crate::coderun::run(&self.paths.runtime, &script, &lang, timeout, Path::new(&view.workspace), &ctx.cancel, &mut handle);
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
        let aux = self.cfg.aux_model().to_string();
        let (pid, m) = split_model(&aux);
        let Ok(p) = self.resolver.provider(pid) else { return };
        let prompt = format!(
            "From this exchange, extract durable facts worth remembering across future sessions: user preferences, environment facts, lessons from mistakes. \
Reply ONLY with JSON: {{\"memory\": [\"...\"], \"user\": [\"...\"]}} (empty arrays if nothing is worth keeping). Never include secrets.\n\n{}",
            compaction::render_transcript(&tail, 1500)
        );
        let req = ModelRequest { model: m.into(), system: vec![], messages: vec![Message::user(prompt)], tools: vec![], max_tokens: 1024, temperature: None, cache_after_message: None, reasoning: None };
        let Ok(r) = p.complete(&req, &mut |_| {}, cancel) else { return };
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

struct Host {
    rt: Arc<Runtime>,
    session: String,
    workspace: PathBuf,
    depth: u32,
    ledger: Ledger,
    conversation: Vec<Message>,
}

impl ToolHost for Host {
    fn spawn_agent(&self, req: SpawnRequest, cancel: &Cancel) -> Result<String, String> {
        if self.depth + 1 > self.rt.cfg.runner.max_spawn_depth {
            return Err(format!("sub-agent depth limit ({}) reached; do the work yourself", self.rt.cfg.runner.max_spawn_depth));
        }
        let model = req.model.clone().filter(|m| !m.is_empty()).unwrap_or_else(|| self.rt.cfg.subagent_model().to_string());
        let title: String = req.task.chars().take(60).collect();
        let child = self.rt.create_session(&self.workspace, Some(&model), Some(&self.session), Some(&title)).map_err(|e| e.to_string())?;
        let sub = |extra: Value| {
            let mut p = hooks::payload(&self.session, &self.workspace.to_string_lossy(), None, None, None, Some(&req.task));
            p["subagent_id"] = child.clone().into();
            p["model"] = model.clone().into();
            if let (Value::Object(m), Some(o)) = (extra, p.as_object_mut()) {
                o.extend(m);
            }
            p
        };
        if let (Some(b), _) = self.rt.emit(HookEvent::SubagentStart, sub(json!({})), "") {
            return Err(format!("sub-agent blocked by {b}"));
        }
        if req.fork {
            let mut log = self.rt.store.open(&child).map_err(|e| e.to_string())?;
            // Everything up to (not including) the assistant message that called spawn.
            let upto = self.conversation.len().saturating_sub(1);
            for m in &self.conversation[..upto] {
                self.rt.append(&mut log, EventKind::Message { message: m.clone(), usage: None, model: None, inbox: None }).map_err(|e| e.to_string())?;
            }
        }
        self.rt.submit(&child, &req.task, "parent").map_err(|e| e.to_string())?;
        let o = self.rt.run(&child, RunOpts { ledger: Some(self.ledger.child(Budget::default())), depth: self.depth + 1, cancel: Some(cancel.clone()), goal_mode: false }).map_err(|e| e.to_string())?;
        self.rt.emit(HookEvent::SubagentStop, sub(json!({"end_reason": o.reason.label(), "text": o.text, "tokens": o.usage.total()})), "");
        let header = format!("[sub-agent {child} · {} · {} tokens]", o.reason.label(), o.usage.total());
        if o.reason.ok() {
            Ok(format!("{header}\n{}", o.text))
        } else {
            Err(format!("{header}\n{}", o.text))
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
}
