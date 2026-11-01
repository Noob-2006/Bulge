//! The kernel: sessions, the turn/step runner, tool dispatch through the gates,
//! retries and provider fallback, compaction, crash recovery and sub-agents.

use crate::approver::{Approval, ApprovalRequest, Approver, PendingItem, Remembered};
use crate::checkpoint::Checkpoints;
use crate::compaction;
use crate::config::{Config, Paths};
use crate::context::{self, split_model};
use crate::event::{Event, EventKind, LOG_VERSION};
use crate::gate::{Gates, Verdict};
use crate::hooks::{self, Hook, HookDecision, HookEvent};
use crate::ledger::{Budget, Ledger};
use crate::projection::{project, View};
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
    queue: Arc<Mutex<Vec<(String, String, String)>>>,
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
    /// Test hook / determinism: override sleep between retries.
    pub retry_sleep: Option<Duration>,
}

pub type Kernel = Arc<Runtime>;

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
    Arc::new(Runtime { cfg, paths, store, resolver, tools, vault, approver, remembered: Remembered::default(), bus: Bus::default(), running: Mutex::new(HashMap::new()), benched: Mutex::new(HashMap::new()), hooks: Default::default(), retry_sleep: None })
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
    fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).filter(|s| !self.cfg.tools.disabled.contains(&s.name)).collect()
    }
    fn tool(&self, name: &str) -> Option<Arc<dyn Tool>> {
        if self.cfg.tools.disabled.iter().any(|d| d == name) {
            return None;
        }
        self.tools.iter().find(|t| t.spec().name == name).cloned()
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
        self.bus.publish(BusMsg::Event { session: log.id.clone(), event: ev.clone() });
        Ok(ev)
    }

    // ───────────────────────── hooks ─────────────────────────

    pub fn add_hooks(&self, hooks: Vec<Arc<dyn Hook>>) {
        self.hooks.write().unwrap().extend(hooks);
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
        if let Some(log) = log {
            for w in warnings {
                self.append(log, EventKind::Notice { level: "warn".into(), text: w })?;
            }
        }
        Ok(fired)
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
        if text.trim().is_empty() {
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
            r.queue.lock().unwrap().push((inbox_id, source.into(), text.into()));
            return Ok(());
        }
        let mut log = self.store.open(id)?;
        self.append(&mut log, EventKind::Inbox { id: inbox_id, source: source.into(), text: text.into() })?;
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

    fn drain_queue(&self, log: &mut SessionLog, q: &Mutex<Vec<(String, String, String)>>) -> Result<(), StoreError> {
        let items: Vec<_> = std::mem::take(&mut *q.lock().unwrap());
        for (id, source, text) in items {
            self.append(log, EventKind::Inbox { id, source, text })?;
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
                self.append(log, EventKind::ToolSettled { tool_use_id: u.tool_use_id.clone(), is_error: true, bytes: 0, artifact: None })?;
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
                let tool = self.tool(name);
                let idempotent = tool.as_ref().is_some_and(|t| t.spec().idempotent);
                let out = match settled_artifact {
                    Some(Some(a)) => ToolOutput::ok(format!("[recovered after crash; full output saved at {a}]")),
                    Some(None) if !idempotent => ToolOutput::ok("[the call completed before a crash but its output was lost; check the resulting state before continuing]"),
                    _ if idempotent && !cancel.is_cancelled() => {
                        let ctx = self.ctx(&view, log, cancel, 0, Ledger::new(Budget::default()));
                        let o = run_tool(tool.as_ref().unwrap().as_ref(), &ctx, input.clone());
                        if settled_artifact.is_none() {
                            self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: o.is_error, bytes: o.content.len(), artifact: None })?;
                        }
                        o
                    }
                    _ => {
                        if settled_artifact.is_none() {
                            self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: true, bytes: 0, artifact: None })?;
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

    fn turn(self: &Arc<Self>, log: &mut SessionLog, ledger: &Ledger, cancel: &Cancel, depth: u32, queue: &Mutex<Vec<(String, String, String)>>, goal_mode: bool) -> Result<Outcome, StoreError> {
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
        let specs = self.specs();

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

    fn consume_inbox(&self, log: &mut SessionLog) -> Result<(), StoreError> {
        for (id, source, text) in project(log.events()).pending_inbox {
            let body = if source == "cli" || source == "user" { text } else { format!("[from {source}] {text}") };
            self.append(log, EventKind::Message { message: Message::user(body), usage: None, model: None, inbox: Some(id) })?;
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
        let session = log.id.clone();
        for (ci, m) in chain.iter().enumerate() {
            let (pid, mname) = split_model(m);
            let provider = match self.resolver.provider(pid) {
                Ok(p) => p,
                Err(e) => {
                    last = ProviderError::new(ProviderErrorKind::Auth, format!("{pid}: {e}"));
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("provider {pid} unavailable: {e}") })?;
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
                        return Ok(Ok(r));
                    }
                    Err(e) => {
                        if matches!(e.kind, ProviderErrorKind::Cancelled | ProviderErrorKind::ContextOverflow | ProviderErrorKind::BadRequest) {
                            return Ok(Err(e));
                        }
                        let retry = e.is_retryable() && attempt < self.cfg.runner.max_retries;
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
            if !last.allows_fallback() {
                break;
            }
        }
        Ok(Err(last))
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
        let used = if view.last_input_tokens > 0 { view.last_input_tokens } else { estimate_request_tokens(&ModelRequest { model: String::new(), system: view.system.clone(), messages: view.messages.clone(), tools: vec![], max_tokens: 0, temperature: None, cache_after_message: None }) } as f64;
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

    fn summarise(&self, log: &mut SessionLog, view: &View, cancel: &Cancel) -> Result<bool, StoreError> {
        let Some(cut) = compaction::cut_index(&view.messages, self.cfg.compaction.keep_messages) else { return Ok(false) };
        let aux = self.cfg.aux_model().to_string();
        let (pid, m) = split_model(&aux);
        let before = estimate_tokens(&compaction::render_transcript(&view.messages, usize::MAX));
        let (summary, fallback) = match self.resolver.provider(pid) {
            Ok(p) => compaction::summarise(p.as_ref(), m, &view.messages[..cut], cancel),
            Err(_) => (compaction::fallback_summary(&view.messages[..cut]), true),
        };
        if fallback {
            self.append(log, EventKind::Notice { level: "warn".into(), text: "summary model unavailable or low quality; used deterministic digest".into() })?;
        }
        self.append(log, EventKind::Compaction { upto_seq: view.message_seqs[cut], summary, pruned: vec![], tokens_before: before })?;
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
                        out.push(match (self.tool(n), kernel) {
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
            let Some(tool) = self.tool(&tname) else {
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
                self.append(log, EventKind::ToolSettled { tool_use_id: id.clone(), is_error: out.is_error, bytes: out.content.len(), artifact })?;
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
            let req = ApprovalRequest { id: new_id(), session: log.id.clone(), tool: tool.into(), summary: head_tail(&self.vault.redact(&input.to_string()), 600).0, gate, reason: reason.clone() };
            self.bus.publish(BusMsg::Pending(PendingItem::Approval(req.clone())));
            match self.approver.approve(&req) {
                Approval::Once => "allow",
                Approval::Always => {
                    self.remembered.insert(&log.id, gate, &reason);
                    "allow (always)"
                }
                Approval::Deny => "deny",
            }
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
            let Some(tool) = self.tool(&nested.tool) else {
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
            let _ = self.append(log, EventKind::ToolSettled { tool_use_id: nid, is_error: out.is_error, bytes: out.content.len(), artifact: None });
            ToolOutput { content: self.vault.redact(&out.content), is_error: out.is_error }
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
        let req = ModelRequest { model: m.into(), system: vec![], messages: vec![Message::user(prompt)], tools: vec![], max_tokens: 1024, temperature: None, cache_after_message: None };
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
        let header = format!("[sub-agent {child} · {} · {} tokens]", o.reason.label(), o.usage.total());
        if o.reason.ok() {
            Ok(format!("{header}\n{}", o.text))
        } else {
            Err(format!("{header}\n{}", o.text))
        }
    }
    fn ask_user(&self, question: &str) -> Result<String, String> {
        self.rt.approver.ask(&self.session, question)
    }
}
