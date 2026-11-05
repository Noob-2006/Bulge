//! Sub-agents: synchronous and background delegation, batches, live control
//! (list / steer / stop / wait), output contracts, worktree isolation, live
//! transcripts and crash recovery. One core behind Hermes `delegate_task`
//! (tools/delegate_tool*.py, async_delegation.py, delegate_tool_registry.py)
//! and OpenClaw `sessions_spawn` / `agents_wait` / `subagents` / `sessions_yield`.
//!
//! A child is an ordinary session whose header names the parent. Background
//! children report back *between* the parent's turns: their completion becomes
//! an inbox message of the parent (source `subagent`), consumed as a new turn.
//! The run loop waits for live background children before it returns, so
//! one-shot runs (`ark run`, cron) collect their results too; a daemon that
//! detached the parent restarts it when a completion arrives (`auto_resume`).
//! A small JSON ledger (`<data>/subagents.json`) makes completions survive a
//! crash: on the parent's next run, children of a dead process are reported as
//! interrupted with a recovery hint, finished-but-undelivered ones are delivered.

use crate::event::{now_ms, Event, EventKind};
use crate::hooks::{self, HookEvent};
use crate::kernel::{Host, RunOpts, Runtime};
use crate::ledger::Budget;
use crate::projection::{project, View};
use crate::store::{SessionLog, StoreError};
use crate::worktree;
use ark_core::{Block, Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// `[delegation]` (Hermes `delegation.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DelegationConfig {
    /// Most tasks in one `delegate_task` call (Hermes default 10).
    pub max_concurrent_children: usize,
    /// Most background children alive at once per parent session; 0 = max_concurrent_children.
    pub max_async_children: usize,
    /// Top-level `delegate_task` runs in the background (results arrive as a new turn).
    pub background: bool,
    /// Split a background call into per-task / per-`group` completion messages.
    pub independent_completions: bool,
    /// Each child gets its own git worktree (`<repo>/.worktrees/subagent-<id>`).
    pub worktree_isolation: bool,
    /// Wall-clock cap per child run in seconds; 0 = none.
    pub child_timeout_secs: u64,
    /// Children below the depth cap may delegate themselves.
    pub orchestrator_enabled: bool,
    /// Background completions older than this are not replayed after a restart (hours).
    pub replay_max_age_hours: u64,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        DelegationConfig { max_concurrent_children: 10, max_async_children: 0, background: true, independent_completions: false, worktree_isolation: false, child_timeout_secs: 0, orchestrator_enabled: true, replay_max_age_hours: 48 }
    }
}

/// Tools a child never gets (Hermes DELEGATE_BLOCKED_TOOLS): no user interaction,
/// no writes to shared memory, no cross-platform side effects, no scheduling.
pub const BLOCKED_FOR_CHILDREN: &[&str] = &["clarify", "ask_user", "memory", "channel_send", "message", "message_agent", "cronjob", "cronjob_manage", "automations", "suggest_task"];

/// Named groups of tools (Hermes toolsets) usable wherever a tool list is accepted.
pub const TOOLSETS: &[(&str, &[&str])] = &[
    ("file", &["read", "write", "edit", "patch", "glob", "grep"]),
    ("terminal", &["shell", "job", "run"]),
    ("code", &["run"]),
    ("web", &["web_fetch", "web_search", "web_extract"]),
    ("memory", &["memory"]),
    ("skills", &["skill"]),
    ("todo", &["todo"]),
    ("session_search", &["session_search"]),
    ("sessions", &["sessions_list", "sessions_history", "sessions_send", "sessions_create", "session_status", "sessions", "agents_list", "session_search"]),
    ("delegation", &["spawn", "delegate_task", "sessions_spawn", "agents_wait", "sessions_yield", "subagents"]),
    ("clarify", &["clarify", "ask_user"]),
    ("messaging", &["channel_send", "message", "message_agent"]),
    ("decisions", &["decision_evaluate", "llm_task"]),
];

/// Expand tool / toolset names. `mcp` stands for every MCP tool (`mcp__*`).
pub fn expand_tools(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let n = n.trim();
        match TOOLSETS.iter().find(|(ts, _)| *ts == n) {
            Some((_, tools)) => out.extend(tools.iter().map(|t| t.to_string())),
            None if n == "mcp" => out.push("mcp__*".into()),
            None if !n.is_empty() => out.push(n.to_string()),
            None => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// The session's tool policy (`Tools` event) allows `name`? Meta tools always pass.
pub fn tool_allowed(view: &View, name: &str) -> bool {
    // context_fetch only re-reads output this session already received (clip markers point at it).
    if matches!(name, "tool_describe" | "tool_call" | "goal_done" | "structured_output" | "context_fetch") {
        return true;
    }
    if view.tool_deny.iter().any(|p| name_matches(p, name)) {
        return false;
    }
    view.tool_allow.as_ref().is_none_or(|a| a.iter().any(|p| name_matches(p, name)))
}

/// Ledger + list status of one child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    Completed,
    Failed,
    Interrupted,
    Timeout,
}

impl State {
    pub fn done(self) -> bool {
        self != State::Running
    }
}

/// How the caller wants the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Block in the tool call and return the results.
    Sync,
    /// Return a handle now; a completion message arrives between turns (`notify`)
    /// or never (fire-and-forget).
    Background { notify: bool },
    /// Background, no completion message: the parent collects with `agents_wait`.
    Collect,
}

/// One child to start.
#[derive(Debug, Clone, Default)]
pub struct ChildSpec {
    pub goal: String,
    pub context: Option<String>,
    pub model: Option<String>,
    /// Run as this named agent (its model, identity, tools, workspace).
    pub agent: Option<String>,
    /// Tool / toolset names the child may use (None = the parent's set).
    pub tools: Option<Vec<String>>,
    /// Seed the child with the parent's conversation.
    pub fork: bool,
    pub output_schema: Option<Value>,
    pub label: Option<String>,
    pub cwd: Option<PathBuf>,
    /// None = `delegation.worktree_isolation`.
    pub worktree: Option<bool>,
    pub timeout_secs: Option<u64>,
    pub thinking: Option<String>,
    /// Images the child must see: local paths become image blocks, URLs path hints.
    pub images: Vec<String>,
    /// Inline files (name, content) written next to the child's artifacts.
    pub attachments: Vec<(String, String)>,
    /// Result-delivery bucket (independent completions).
    pub group: Option<String>,
    /// Bind the child to a NEW thread in the requester's channel conversation
    /// (`sessions_spawn thread:true|<name>`); `Some("")` = default thread name.
    pub thread: Option<String>,
    /// Publish the child as a first-class, persistent sidebar session (`visible:true`).
    pub visible: bool,
    /// Legacy `spawn`: plain brief, no focused system prompt.
    pub plain: bool,
}

/// What a child produced (the parent's view of it).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub task_index: usize,
    pub subagent_id: String,
    pub session_id: String,
    pub goal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub status: String,
    pub exit_reason: String,
    #[serde(default)]
    pub truncated: bool,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_valid: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub duration_seconds: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<worktree::Report>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missed_steer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rec {
    pub id: String,
    pub unit: String,
    pub task_index: usize,
    pub parent: String,
    pub child: String,
    pub goal: String,
    pub label: Option<String>,
    pub model: String,
    pub group: Option<String>,
    pub started_ms: u64,
    started: Instant,
    pub state: State,
    pub background: bool,
    pub notify: bool,
    pub collect: bool,
    pub accepting_steer: bool,
    pub entry: Option<Entry>,
    pub delivered: bool,
    pub live_log: PathBuf,
    cancel: Cancel,
}

#[derive(Default)]
pub struct Inner {
    recs: HashMap<String, Rec>,
    /// Insertion order (listing, pruning).
    order: Vec<String>,
}

/// Live and recently finished sub-agents of this process.
#[derive(Default)]
pub struct Registry {
    inner: Mutex<Inner>,
    cv: Condvar,
}

const RETAIN_FINISHED: usize = 200;

impl Registry {
    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub fn get(&self, id: &str) -> Option<Rec> {
        self.lock().recs.get(id).cloned()
    }
    pub fn by_child(&self, child: &str) -> Option<Rec> {
        self.lock().recs.values().find(|r| r.child == child).cloned()
    }
    /// Every record (oldest first).
    pub fn all(&self) -> Vec<Rec> {
        let g = self.lock();
        g.order.iter().filter_map(|i| g.recs.get(i).cloned()).collect()
    }
    fn insert(&self, r: Rec) {
        let mut g = self.lock();
        g.order.push(r.id.clone());
        g.recs.insert(r.id.clone(), r);
        // Bounded memory: forget the oldest delivered, finished records.
        while g.order.len() > RETAIN_FINISHED {
            let Some(pos) = g.order.iter().position(|i| g.recs.get(i).is_some_and(|r| r.state.done() && (r.delivered || !r.notify))) else { break };
            let id = g.order.remove(pos);
            g.recs.remove(&id);
        }
    }
    /// Does `caller` own `r` (it started it, or started an ancestor of it)?
    pub fn owns(&self, caller: &str, r: &Rec) -> bool {
        let g = self.lock();
        let mut parent = r.parent.clone();
        for _ in 0..16 {
            if parent == caller {
                return true;
            }
            match g.recs.values().find(|x| x.child == parent) {
                Some(up) => parent = up.parent.clone(),
                None => return false,
            }
        }
        false
    }
    pub fn notify_all(&self) {
        self.cv.notify_all();
    }
    fn wait_timeout<'a>(&self, g: MutexGuard<'a, Inner>, d: Duration) -> MutexGuard<'a, Inner> {
        self.cv.wait_timeout(g, d).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0)
    }
}

impl Inner {
    fn has_live_notify(&self, parent: &str) -> bool {
        self.recs.values().any(|r| r.parent == parent && r.notify && !r.state.done())
    }
    fn live_background(&self, parent: &str) -> usize {
        self.recs.values().filter(|r| r.parent == parent && r.background && !r.state.done()).count()
    }
    /// Completion messages ready for `parent`, marking them delivered.
    fn take_ready(&mut self, parent: &str, independent: bool) -> Vec<(String, Vec<Entry>)> {
        let mut units: Vec<String> = Vec::new();
        for id in &self.order {
            if let Some(r) = self.recs.get(id) {
                if r.parent == parent && r.notify && !r.delivered && !units.contains(&r.unit) {
                    units.push(r.unit.clone());
                }
            }
        }
        let mut out = Vec::new();
        for unit in units {
            let ids: Vec<String> = self.order.iter().filter(|i| self.recs.get(*i).is_some_and(|r| r.unit == unit)).cloned().collect();
            // Delivery buckets: the whole call, or (independent) each group / ungrouped task.
            let mut buckets: Vec<Vec<String>> = Vec::new();
            if independent {
                let mut groups: Vec<(String, Vec<String>)> = Vec::new();
                for i in &ids {
                    match self.recs[i].group.clone() {
                        Some(gname) => match groups.iter_mut().find(|(n, _)| *n == gname) {
                            Some((_, v)) => v.push(i.clone()),
                            None => groups.push((gname, vec![i.clone()])),
                        },
                        None => buckets.push(vec![i.clone()]),
                    }
                }
                buckets.extend(groups.into_iter().map(|(_, v)| v));
            } else {
                buckets.push(ids);
            }
            for b in buckets {
                let pending: Vec<&String> = b.iter().filter(|i| !self.recs[*i].delivered).collect();
                if pending.is_empty() || !b.iter().all(|i| self.recs[i].state.done()) {
                    continue;
                }
                let entries: Vec<Entry> = b.iter().filter_map(|i| self.recs[i].entry.clone()).collect();
                for i in &b {
                    if let Some(r) = self.recs.get_mut(i) {
                        r.delivered = true;
                    }
                }
                out.push((unit.clone(), entries));
            }
        }
        out
    }
}

/// The completion message a parent receives (Hermes async delegation event, as text).
pub fn completion_text(unit: &str, entries: &[Entry]) -> String {
    let mut s = format!("[Background delegation {unit} finished — {} task(s). These are the children's SELF-REPORTS: verify claimed side effects before relying on them.]\n", entries.len());
    s.push_str(&serde_json::to_string_pretty(&json!({"delegation_id": unit, "results": entries})).unwrap_or_default());
    s
}

// ───────────────────────── durable ledger ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerRow {
    id: String,
    unit: String,
    parent: String,
    child: String,
    goal: String,
    state: State,
    notify: bool,
    delivered: bool,
    pid: u32,
    started_ms: u64,
    #[serde(default)]
    entry: Option<Entry>,
}

fn ledger_path(data: &Path) -> PathBuf {
    data.join("subagents.json")
}

fn ledger_lock(data: &Path) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let _ = std::fs::create_dir_all(data);
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data.join("subagents.lock")).ok()?;
    // SAFETY: flock on a valid fd; released on close.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    Some(f)
}

fn read_ledger(data: &Path) -> Vec<LedgerRow> {
    std::fs::read_to_string(ledger_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Update (or insert) one row; rows of settled deliveries older than a week are pruned.
fn ledger_upsert(data: &Path, row: LedgerRow) {
    let _l = ledger_lock(data);
    let mut rows = read_ledger(data);
    rows.retain(|r| r.id != row.id);
    rows.push(row);
    let week = 7 * 86_400_000;
    let now = now_ms();
    rows.retain(|r| !(r.delivered || !r.notify) || now.saturating_sub(r.started_ms) < week);
    let _ = crate::util::atomic_write(&ledger_path(data), serde_json::to_string(&rows).unwrap_or_default().as_bytes());
}

fn ledger_row(r: &Rec) -> LedgerRow {
    LedgerRow { id: r.id.clone(), unit: r.unit.clone(), parent: r.parent.clone(), child: r.child.clone(), goal: r.goal.clone(), state: r.state, notify: r.notify, delivered: r.delivered, pid: std::process::id(), started_ms: r.started_ms, entry: r.entry.clone() }
}

fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks for existence.
    pid == std::process::id() || unsafe { libc::kill(pid as i32, 0) } == 0
}

// ───────────────────────── live transcripts ─────────────────────────

/// Append a human-readable line to a sub-agent's `live.log` (tail-able while it runs).
pub fn live_log(rt: &Runtime, session: &str, ev: &Event) {
    let Some(path) = ({
        let g = rt.subagents.lock();
        g.recs.values().find(|r| r.child == session && !r.state.done()).map(|r| r.live_log.clone())
    }) else {
        return;
    };
    let ts = crate::util::fmt_time((ev.ts / 1000) as i64, rt.cfg.schedule.utc_offset_minutes);
    let one = |s: &str, n: usize| -> String {
        let s = s.replace('\n', " ");
        if s.chars().count() > n {
            format!("{}…", s.chars().take(n).collect::<String>())
        } else {
            s
        }
    };
    let line = match &ev.kind {
        EventKind::Message { message, .. } => {
            let mut parts = Vec::new();
            let t = message.text();
            if !t.trim().is_empty() {
                parts.push(format!("{}: {}", if message.role == ark_core::Role::User { "user" } else { "assistant" }, one(&t, 400)));
            }
            for (_, name, input) in message.tool_uses() {
                parts.push(format!("→ {name} {}", one(&input.to_string(), 200)));
            }
            for b in &message.content {
                if let Block::ToolResult { content, is_error, .. } = b {
                    parts.push(format!("{} {}", if *is_error { "✗" } else { "✓" }, one(content, 200)));
                }
            }
            parts.join("\n")
        }
        EventKind::TurnEnd { reason, usage, .. } => format!("■ turn ended: {reason} · {} tokens", usage.total()),
        EventKind::Error { message } => format!("! {message}"),
        EventKind::Notice { level, text } if level == "warn" => format!("! {text}"),
        _ => return,
    };
    if line.is_empty() {
        return;
    }
    if rt.has_hooks(HookEvent::SubagentProgress) {
        let mut p = hooks::payload(session, "", None, None, None, None);
        p["subagent_id"] = session.into();
        p["progress"] = rt.vault.redact(&line).into();
        rt.emit(HookEvent::SubagentProgress, p, "");
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let text = rt.vault.redact(&line);
        let _ = writeln!(f, "[{ts}] {}", text.replace('\n', &format!("\n[{ts}] ")));
    }
}

// ───────────────────────── prompts ─────────────────────────

const COMPLETION_INSTRUCTIONS: &str = "Complete this task using the tools available to you. When finished, provide a clear, concise summary of:\n- What you did\n- What you found or accomplished\n- Any files you created or modified\n- Any issues encountered\n\nImportant workspace rule: never assume a repository lives at /workspace/... or any other container-style path unless the task/context explicitly gives that path. If no exact local path is provided, discover it first before issuing git/workdir-specific commands.\n\nKeep your final summary tight: lead with outcomes, prefer bullet points over paragraphs, and don't replay your whole process. Your response is returned to the parent agent as a summary, and overlong summaries crowd out the parent's context window.";

const ORCHESTRATOR_BLOCK: &str = "## Subagent Spawning (Orchestrator Role)\nYou have access to the `delegate_task` tool and CAN spawn your own subagents to parallelize independent work.\n\nWHEN to delegate:\n- The goal decomposes into 2+ independent subtasks that can run in parallel.\n- A subtask is reasoning-heavy and would flood your context.\n\nWHEN NOT to delegate:\n- Single-step mechanical work, or anything you can do directly in a few tool calls.\n- Tasks with tight sequential dependencies.\n\nDelegated children report self-assessed summaries: verify what matters before reporting it as done.";

fn child_system_prompt(spec: &ChildSpec, workspace: &Path, depth: u32, max_depth: u32, orchestrator: bool) -> String {
    let mut parts = vec!["You are a focused subagent working on a specific delegated task.".to_string()];
    if let Some(c) = spec.context.as_ref().filter(|c| !c.trim().is_empty()) {
        parts.push(format!("CONTEXT:\n{c}"));
    }
    parts.push(format!("WORKSPACE PATH:\n{}\nUse this exact path for local repository/workdir operations unless the task explicitly says otherwise.", workspace.display()));
    if let Some(s) = &spec.output_schema {
        parts.push(crate::jsonschema::output_contract(s));
    }
    parts.push(COMPLETION_INSTRUCTIONS.into());
    if orchestrator && depth < max_depth {
        let note = if depth + 1 >= max_depth { "Your children will be leaf agents and cannot delegate further." } else { "Your children may delegate one level further." };
        parts.push(format!("{ORCHESTRATOR_BLOCK}\nNOTE: You are at depth {depth}. The delegation tree is capped at max_spawn_depth={max_depth}. {note}"));
    }
    parts.join("\n\n")
}

fn image_block(path: &Path) -> Option<Block> {
    let ext = path.extension()?.to_string_lossy().to_lowercase();
    let media = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => return None,
    };
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 8 * 1024 * 1024 {
        return None;
    }
    Some(Block::Image { media_type: media.into(), data: base64_encode(&bytes) })
}

fn base64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

pub const MAX_TASK_IMAGES: usize = 8;

/// Model-facing sub-agent tools (`delegate_task`, `sessions_spawn`, `agents_wait`,
/// `sessions_yield`, `subagents`, `agents_list`). Registered by `new_kernel`; each one
/// reaches the kernel through [`crate::kernel::Host::of`].
pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(DelegateTask), Arc::new(SessionsSpawn), Arc::new(AgentsWait), Arc::new(SessionsYield), Arc::new(SubagentsTool), Arc::new(AgentsList)]
}

fn kernel_host<'a>(ctx: &'a ToolCtx, tool: &str) -> Result<&'a Host, ToolOutput> {
    Host::of(ctx).ok_or_else(|| ToolOutput::err(format!("{tool} needs the ark kernel (no sub-agent runtime behind this host)")))
}

fn json_output(v: &Value) -> ToolOutput {
    ToolOutput::ok(serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()))
}

/// `timeout_seconds` (OpenClaw `timeoutSeconds`), defaulting to `default`.
fn timeout_secs(input: &Value, default: u64) -> u64 {
    input.get("timeout_seconds").or_else(|| input.get("timeoutSeconds")).and_then(Value::as_u64).unwrap_or(default)
}

/// A list of strings: an array, or a single string (`spec_from` accepts both).
fn string_list(v: Option<&Value>, key: &str) -> Result<Vec<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("`{key}` must be an array of strings"))).collect(),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(_) => Err(format!("`{key}` must be an array of strings")),
    }
}

// ───────────────────────── delegate_task ─────────────────────────

/// `delegate_task` (Hermes tools/delegate_tool*.py): batched sub-agents in isolated
/// contexts, plus the live control plane (`action` = list / steer / stop).
pub struct DelegateTask;

const DELEGATE_TASK_DESCRIPTION: &str = "Spawn subagents in isolated contexts: each gets its own conversation and tool set and only its final summary returns to you — never its intermediate tool calls or reasoning. Pass every task in `tasks` (one entry spawns one subagent; several run in parallel).\n\nDelivery: a top-level call dispatches in the BACKGROUND — the call returns handles (subagent_id, session_id, live_transcript) and the results re-enter this conversation as a NEW message BETWEEN turns (announce=false suppresses that message; mode=collect suppresses it too, so collect with agents_wait). A subagent (depth > 0) runs its own tasks SYNCHRONOUSLY because it needs the results inside its turn. `background` and `mode` override this.\n\nUSE FOR: reasoning-heavy subtasks, work that would flood your context, independent parallel workstreams. DO NOT USE FOR: a single tool call (call it), mechanical multi-step work, or anything needing user interaction — children cannot ask questions. Background child results arrive only between turns: finish whatever does not depend on them, then give a one-line status and END YOUR TURN. Never poll transcripts or artifact files.\n\nWhile children run, `action` controls them live: list (ids, goals, status, transcripts), steer (subagent_id + message: course correction queued for the child's next step; its current tool call is never cut), stop (subagent_id: ends it early, the partial result still returns).\n\nRULES: children know nothing about this conversation — pass everything (paths, error text, required output language/tone) via `context`, repeating shared background in every task that needs it. Child summaries are SELF-REPORTS: verify claimed side effects (uploads, remote writes) yourself. Children never get clarify/ask_user/memory/messaging tools, and never a tool you lack. Depth is capped by runner.max_spawn_depth; at most delegation.max_concurrent_children tasks per call.";

fn delegate_task_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "minItems": 1,
                "description": "The task(s): one entry per subagent, up to delegation.max_concurrent_children (default 10) per call. A single task is a one-entry array.",
                "items": {
                    "type": "object",
                    "properties": {
                        "goal": {"type": "string", "description": "What this subagent should accomplish. Be specific and self-contained — it knows nothing about your conversation history."},
                        "context": {"type": "string", "description": "Background THIS child needs: file paths, error messages, constraints. Each child sees only its own context — repeat shared background in every task that needs it."},
                        "output_schema": {"type": "object", "description": "Optional JSON Schema this child's final answer must validate against (told to the child up front; one bounded correction retry; the result gains schema_valid / structured, plus schema_errors on failure — the raw text is still returned as summary). Keep it forgiving."},
                        "images": {"type": "array", "items": {"type": "string"}, "maxItems": 8, "description": "Optional images this child must SEE (max 8): local file paths or http(s) URLs. Text files do NOT belong here — put their paths in 'context'."},
                        "group": {"type": "string", "description": "Optional result-delivery bucket within this call (with delegation.independent_completions): tasks sharing a group return together in ONE message, ungrouped tasks return individually. Does not order execution."}
                    },
                    "required": ["goal"]
                }
            },
            "goal": {"type": "string", "description": "Legacy single-task form: same as tasks=[{goal, context, output_schema, images, group}]."},
            "context": {"type": "string"},
            "output_schema": {"type": "object"},
            "images": {"type": "array", "items": {"type": "string"}},
            "group": {"type": "string"},
            "action": {"type": "string", "enum": ["spawn", "list", "steer", "stop"], "description": "Default 'spawn'. Live control of running children: 'list' = ids/goals/status/transcripts; 'steer' = queue course-correction text into one child (subagent_id + message) without stopping it; 'stop' = end one child early (subagent_id; partial result still returns). Control actions return immediately and ignore goal/tasks."},
            "subagent_id": {"type": "string", "description": "Target for action='steer'/'stop' (ids from the spawn response or action='list')."},
            "message": {"type": "string", "description": "For action='steer': the course correction, shown to the child at its next step. Be directive and specific."},
            "model": {"type": "string", "description": "provider/model override for every child of this call (per-task `model` wins)."},
            "agent": {"type": "string", "description": "Run each child as this configured agent (its model, identity, tool policy, workspace) — see agents_list."},
            "agentId": {"type": "string", "description": "OpenClaw spelling of `agent`."},
            "tools": {"type": "array", "items": {"type": "string"}, "description": "Tools the children may use (names or toolsets like file/terminal/web). Default: the parent's set minus child-blocked tools."},
            "toolsets": {"type": "array", "items": {"type": "string"}, "description": "Named tool groups (alias of `tools`): file, terminal, code, web, memory, skills, todo, session_search, sessions, delegation, clarify, messaging, decisions, mcp."},
            "worktree": {"type": "boolean", "description": "Give each child its own git worktree (<repo>/.worktrees/subagent-<id>) so its edits never touch your checkout; the result reports the branch and any archived work."},
            "thinking": {"type": "string", "enum": ["off", "low", "medium", "high"], "description": "Reasoning effort for the children."},
            "label": {"type": "string", "description": "Short task title for lists (defaults to the start of the goal)."},
            "taskName": {"type": "string", "description": "Alias of `label`."},
            "timeout_seconds": {"type": "integer", "minimum": 0, "description": "Wall-clock cap per child; 0 = the configured delegation.child_timeout_secs."},
            "background": {"type": "boolean", "description": "true = dispatch and return handles (results arrive as a new message); false = wait and return the results in this call. Unset = depth 0 background, subagent sync."},
            "announce": {"type": "boolean", "description": "Background only: deliver the completion message between turns (default true). false = fire-and-forget; collect with agents_wait."},
            "mode": {"type": "string", "enum": ["sync", "background", "collect"], "description": "Explicit delivery mode; overrides `background`. collect = no completion message, collect with agents_wait."}
        },
        "required": []
    })
}

/// Top-level fields inherited by every task unless the task sets its own.
const TASK_DEFAULTS: &[&str] = &["model", "agent", "agentId", "tools", "toolsets", "worktree", "thinking", "timeout_seconds", "runTimeoutSeconds", "output_schema", "outputSchema", "cwd", "fork"];

impl Tool for DelegateTask {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "delegate_task".into(), description: DELEGATE_TASK_DESCRIPTION.into(), input_schema: delegate_task_schema(), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![Effect::Spawn]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "delegate_task") else { return ToolOutput::err("delegate_task needs the ark kernel") };
        let action = input.get("action").and_then(Value::as_str).map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty()).unwrap_or_else(|| "spawn".into());
        let r = if action == "spawn" { delegate_spawn(host, &input, &ctx.cancel) } else { delegate_control(host, &action, &input) };
        match r {
            Ok(v) => json_output(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// `action` on a running child (Hermes `_handle_control_action`): scoped to the
/// caller's own spawn tree, returns immediately.
fn delegate_control(host: &Host, action: &str, input: &Value) -> Result<Value, String> {
    let need_id = |action: &str| -> Result<String, String> {
        input.get("subagent_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from).ok_or_else(|| format!("action='{action}' requires `subagent_id` (from the spawn response or action='list')"))
    };
    match action {
        "list" => Ok(json!({"action": "list", "subagents": host.rt.subagent_list(&host.session, false)})),
        "steer" => {
            let id = need_id(action)?;
            let msg = input.get("message").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty()).ok_or("action='steer' requires a non-empty `message` describing the course correction")?;
            host.rt.subagent_steer(&host.session, &id, msg)
        }
        "stop" => {
            let id = need_id(action)?;
            host.rt.subagent_stop(&host.session, &id)
        }
        other => Err(format!("unknown action `{other}`; use spawn, list, steer or stop")),
    }
}

/// Delivery mode of a spawn: explicit `mode`, then `background`, then Hermes
/// `_model_background_value` (top level background, subagent sync).
fn spawn_mode(host: &Host, input: &Value) -> Result<Mode, String> {
    let announce = input.get("announce").and_then(Value::as_bool).unwrap_or(true);
    if let Some(m) = input.get("mode").and_then(Value::as_str).map(|m| m.trim().to_ascii_lowercase()).filter(|m| !m.is_empty()) {
        return match m.as_str() {
            "sync" => Ok(Mode::Sync),
            "background" | "bg" | "async" => Ok(Mode::Background { notify: announce }),
            "collect" => Ok(Mode::Collect),
            other => Err(format!("unknown mode `{other}`; use sync, background or collect")),
        };
    }
    match input.get("background").and_then(Value::as_bool) {
        Some(true) => Ok(Mode::Background { notify: announce }),
        Some(false) => Ok(Mode::Sync),
        // A thread-bound child is a persistent session upstream, not a one-shot run: it
        // keeps answering messages in its thread, so it dispatches in the background.
        None if input.get("thread_requested").and_then(Value::as_bool) == Some(true) => Ok(Mode::Background { notify: announce }),
        None if host.depth == 0 => Ok(Mode::Background { notify: announce }),
        None => Ok(Mode::Sync),
    }
}

fn delegate_spawn(host: &Host, input: &Value, cancel: &Cancel) -> Result<Value, String> {
    let mut defaults = serde_json::Map::new();
    for k in TASK_DEFAULTS {
        if let Some(v) = input.get(*k).filter(|v| !v.is_null()) {
            defaults.insert((*k).to_string(), v.clone());
        }
    }
    let mut tasks: Vec<Value> = match input.get("tasks") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("`tasks` must be an array of {goal, context?, output_schema?, images?, group?} objects".into()),
    };
    if tasks.is_empty() {
        // Legacy single-task form (top-level goal/context/output_schema).
        if input.get("goal").and_then(Value::as_str).is_some_and(|g| !g.trim().is_empty()) {
            let mut one = serde_json::Map::new();
            for k in ["goal", "context", "output_schema", "images", "group", "label", "taskName", "fork"] {
                if let Some(v) = input.get(k).filter(|v| !v.is_null()) {
                    one.insert(k.to_string(), v.clone());
                }
            }
            tasks.push(Value::Object(one));
        }
    }
    if tasks.is_empty() {
        return Err("no tasks given. Pass tasks=[{goal, context?}] (one entry per subagent), or a single `goal`.".into());
    }
    let mut specs = Vec::new();
    for (i, t) in tasks.iter().enumerate() {
        let obj = t.as_object().ok_or_else(|| format!("task {} must be an object with at least `goal`", i + 1))?;
        let mut merged = defaults.clone();
        for (k, v) in obj {
            if !v.is_null() {
                merged.insert(k.clone(), v.clone());
            }
        }
        specs.push(spec_from(&Value::Object(merged)).map_err(|e| format!("task {}: {e}", i + 1))?);
    }
    let mode = spawn_mode(host, input)?;
    host.rt.delegate(host, specs, mode, cancel)
}

// ───────────────────────── sessions_spawn ─────────────────────────

/// `sessions_spawn` (OpenClaw src/agents/tools/sessions-spawn-tool.ts): one named
/// child session, background by default.
pub struct SessionsSpawn;

const SESSIONS_SPAWN_DESCRIPTION: &str = "Spawn one child session for a bounded, self-contained task (OpenClaw sessions_spawn). The child is an ordinary session whose parent is this one: `task` is its brief, `context` adds background, and only its final summary returns. Returns JSON with subagent_id, session_id and live_transcript (a file you may tail).\n\nDefaults to a background run: the call returns a handle and the completion arrives as a NEW message between turns — finish independent work and end the turn (sessions_yield) instead of polling. `background:false` waits and returns the result in this call. `context:\"fork\"` seeds the child with this conversation; \"isolated\" (default) gives it only task+context. `agentId` runs it as a configured agent (agents_list), `model` overrides the agent's model, `runTimeoutSeconds` caps the run (0 = no cap), `worktree:true` gives it its own git worktree under .worktrees/, `tools`/`toolsets` narrow the tools it may use, `output_schema` validates its final answer (result gains structured / schema_valid).\n\n`thread:true` opens a NEW thread in this chat for the child (Discord/Matrix/Slack style): its progress and completion land there and messages posted in that thread go straight to the child, which stays reachable until the thread's idle/max-age timeout (channels.<name>.threadBindings). `visible:true` instead publishes the child as a first-class sidebar session (title, group, live status) that stays in sessions_list and is never cleaned up — no thread, so the two cannot be combined.\n\nDo the work yourself when it is one tool call or needs user interaction; delegate only bounded, independent work where parallel execution or an independent review is worth it.";

fn sessions_spawn_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "task": {"type": "string", "description": "The child's brief — it knows nothing about this conversation."},
            "goal": {"type": "string", "description": "Alias of `task`."},
            "taskName": {"type": "string", "description": "Stable later-target alias; start with a lowercase letter, then lowercase/digit/_/-."},
            "label": {"type": "string", "description": "Short task title shown in lists; name the work, not the agent."},
            "agentId": {"type": "string", "description": "Run the child as this configured agent (see agents_list)."},
            "model": {"type": "string", "description": "provider/model override for the child."},
            "context": {"type": "string", "enum": ["fork", "isolated"], "description": "fork = seed the child with this conversation; isolated (default) = only task+context."},
            "runTimeoutSeconds": {"type": "integer", "minimum": 0, "description": "Child run timeout in seconds; 0 disables it."},
            "thinking": {"type": "string", "enum": ["off", "low", "medium", "high"], "description": "Reasoning effort override."},
            "cwd": {"type": "string", "description": "Child working directory (default: the parent workspace, or the agent's workspace)."},
            "worktree": {"type": "boolean", "description": "Give the child its own git worktree (<repo>/.worktrees/subagent-<id>)."},
            "tools": {"type": "array", "items": {"type": "string"}, "description": "Tools / toolsets the child may use (default: the parent's set minus child-blocked tools)."},
            "toolsets": {"type": "array", "items": {"type": "string"}, "description": "Named tool groups (alias of `tools`)."},
            "output_schema": {"type": "object", "description": "JSON Schema the child's final answer must validate against."},
            "group": {"type": "string", "description": "Result-delivery bucket for independent completions."},
            "background": {"type": "boolean", "description": "false = wait for the result in this call; default true (handle now, completion later)."},
            "announce": {"type": "boolean", "description": "Deliver the completion message between turns (default true)."},
            "visible": {"type": "boolean", "description": "Publish the child as a first-class, persistent sidebar session (title, group, live status) instead of a hidden helper run. Unavailable with `thread` and with mode=collect."},
            "thread": {"type": ["boolean", "string"], "description": "Open a new thread in this chat for the child and bind it there (true = name from `label`, or give the thread name). Its completion is announced in the thread and messages in the thread reach the child. Needs a channel that opens threads; unavailable with `visible`."}
        },
        "required": []
    })
}

impl Tool for SessionsSpawn {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions_spawn".into(), description: SESSIONS_SPAWN_DESCRIPTION.into(), input_schema: sessions_spawn_schema(), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![Effect::Spawn]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_spawn") else { return ToolOutput::err("sessions_spawn needs the ark kernel") };
        match sessions_spawn(host, &input, &ctx.cancel) {
            Ok(v) => json_output(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn sessions_spawn(host: &Host, input: &Value, cancel: &Cancel) -> Result<Value, String> {
    let task = input.get("task").and_then(Value::as_str).or_else(|| input.get("goal").and_then(Value::as_str)).unwrap_or("").trim().to_string();
    if task.is_empty() {
        return Err("sessions_spawn needs a non-empty `task`: the child's brief (it knows nothing about this conversation)".into());
    }
    let mut obj = input.as_object().cloned().unwrap_or_default();
    obj.insert("goal".into(), json!(task));
    obj.remove("task");
    // `context` is OpenClaw's fork/isolated switch, not prose for the child.
    match input.get("context").and_then(Value::as_str).map(|c| c.trim().to_ascii_lowercase()).filter(|c| !c.is_empty()) {
        None => {}
        Some(c) if c == "fork" => {
            obj.insert("fork".into(), json!(true));
            obj.remove("context");
        }
        Some(c) if c == "isolated" => {
            obj.remove("context");
        }
        Some(other) => return Err(format!("unknown context `{other}`; use \"fork\" (seed the child with this conversation) or \"isolated\" (default)")),
    }
    // `thread` opens (and binds) a new thread in this chat; `visible` publishes a sidebar
    // session instead. Upstream refuses the combination and collect mode with either.
    let thread: Option<String> = match input.get("thread") {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Some(Value::Bool(true)) => Some(String::new()),
        Some(Value::Bool(false)) | None | Some(Value::Null) => None,
        Some(Value::String(_)) => None,
        Some(_) => return Err("`thread` must be true, false or a thread name".into()),
    };
    let visible = input.get("visible").and_then(Value::as_bool).unwrap_or(false);
    if visible && thread.is_some() {
        return Err("Parameters unavailable with visible=true: thread — a visible session is a dashboard/sidebar session, not a channel thread. Drop `thread` (the session is listed in sessions_list) or drop `visible` (the child gets its own thread).".into());
    }
    let announce = input.get("announce").and_then(Value::as_bool).unwrap_or(true);
    let mut mode_input = serde_json::Map::new();
    if let Some(b) = input.get("background") {
        mode_input.insert("background".into(), b.clone());
    }
    if input.get("mode").is_some() {
        mode_input.insert("mode".into(), input["mode"].clone());
    }
    mode_input.insert("announce".into(), json!(announce));
    mode_input.insert("thread_requested".into(), json!(thread.is_some()));
    let mode = spawn_mode(host, &Value::Object(mode_input))?;
    if (visible || thread.is_some()) && mode == Mode::Collect {
        return Err("sessions_spawn collect=true does not support thread, visible, or session mode: a collect run has no delivery and no sidebar row. Use background mode with announce=false if you only need agents_wait.".into());
    }
    let mut spec = spec_from(&Value::Object(obj))?;
    spec.thread = thread.clone();
    spec.visible = visible;
    let out = host.rt.delegate(host, vec![spec], mode, cancel)?;
    // Flatten to one handle: the caller asked for one child.
    let mut handle = match mode {
        Mode::Sync => out.get("results").and_then(|r| r.get(0)).cloned().unwrap_or_default(),
        _ => out.get("subagents").and_then(|s| s.get(0)).cloned().unwrap_or_default(),
    };
    if !handle.is_object() {
        handle = json!({});
    }
    let status = match mode {
        Mode::Sync => handle.get("status").and_then(Value::as_str).unwrap_or("completed").to_string(),
        _ => "accepted".to_string(),
    };
    handle["status"] = json!(status);
    handle["background"] = json!(mode != Mode::Sync);
    handle["announced"] = json!(announce);
    handle["visible"] = json!(visible);
    if let Some(sid) = handle.get("session_id").and_then(Value::as_str).map(str::to_string) {
        if let Some(b) = crate::threads::by_session(&host.rt.paths, &sid) {
            handle["thread"] = b.as_json();
        }
        if let Some(v) = crate::threads::visible_of(&host.rt.paths, &sid) {
            handle["sidebar"] = json!({"session": v.session, "label": v.label, "group": v.group, "status": v.status});
            handle["cleanup"] = json!("keep");
        }
    }
    handle["note"] = json!(match mode {
        Mode::Sync => "The child finished inside this call; its summary is above.",
        Mode::Collect => "No completion message will arrive: collect it with agents_wait (ids = subagent_id).",
        Mode::Background { notify: true } => "Running in the background: its result arrives as a NEW message between your turns. Finish independent work and end the turn; control it with subagents / delegate_task action=list|steer|stop.",
        Mode::Background { notify: false } => "Fire-and-forget: no completion message will arrive.",
    });
    Ok(handle)
}

// ───────────────────────── agents_wait ─────────────────────────

/// `agents_wait` (OpenClaw src/agents/tools/agents-wait-tool.ts): join collector runs.
pub struct AgentsWait;

impl Tool for AgentsWait {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "agents_wait".into(),
            description: "Wait for background sub-agents started with mode=collect (delegate_task) or announce=false (sessions_spawn) and return their results. `ids` takes many subagent_id values; the call returns once any of them finishes (or immediately for already-finished ones) with `completed` (result, structured output, schemaError, usage, label) and `pending` (ids still running). `timeout_seconds` defaults to 30. Waiting never cancels a child and does not consume its completion message; unknown or foreign ids come back under `errors`.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ids": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 1000, "description": "subagent_id values from the spawn response."},
                    "timeout_seconds": {"type": "integer", "minimum": 0, "description": "How long to wait, in seconds (default 30; 0 = a snapshot)."}
                },
                "required": ["ids"]
            }),
            parallel_safe: false,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "agents_wait") else { return ToolOutput::err("agents_wait needs the ark kernel") };
        let ids = match string_list(input.get("ids"), "ids") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        if ids.is_empty() {
            return ToolOutput::err("agents_wait needs `ids`: a non-empty array of subagent_id values (from the spawn response or subagents action=list)");
        }
        let t = timeout_secs(&input, 30);
        json_output(&host.rt.subagent_wait(&host.session, &ids, Some(Duration::from_secs(t)), &ctx.cancel))
    }
}

// ───────────────────────── sessions_yield ─────────────────────────

/// `sessions_yield` (OpenClaw src/agents/tools/sessions-yield-tool.ts): end the turn
/// now so background completions start the next one.
pub struct SessionsYield;

impl Tool for SessionsYield {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "sessions_yield".into(),
            description: "End this turn now, without a final answer, while background sub-agents keep running: their results arrive as a NEW message that starts the next turn. Call it once you have dispatched background work and finished everything that does not depend on it — never poll transcripts or sleep instead. Report what is still outstanding so the next turn has context. Does not message other sessions and does not cancel children.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "One line of status for the user (what you are waiting for)."}
                },
                "required": []
            }),
            parallel_safe: false,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_yield") else { return ToolOutput::err("sessions_yield needs the ark kernel") };
        let pending = host.rt.subagents.lock().recs.values().filter(|r| r.parent == host.session && r.notify && !r.state.done()).count();
        host.rt.request_end_turn(&host.session);
        let what = input.get("message").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty()).map(|m| format!(" Status: {m}")).unwrap_or_default();
        let message = if pending == 0 {
            format!("Turn ended. No background sub-agent of this conversation is pending, so no completion message is due.{what} Continue in the next turn when the user speaks.")
        } else {
            format!("Turn ended; {pending} background sub-agent(s) are still running and their results arrive as a NEW message that starts the next turn. Do not poll transcripts — end here.{what}")
        };
        json_output(&json!({"status": "yielded", "pending_children": pending, "message": message}))
    }
}

// ───────────────────────── subagents ─────────────────────────

/// `subagents` (OpenClaw src/agents/tools/subagents-tool.ts): list / info / cancel / wait.
pub struct SubagentsTool;

impl Tool for SubagentsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "subagents".into(),
            description: "Inspect and control this conversation's sub-agent runs (its whole spawn tree — children you started, and children they started). action=list (default): live runs with goal, status, running_seconds, tool_calls and live_transcript; include_done=true also lists finished runs with their result. action=info: the full record of one run (subagent_id or session_id). action=wait: block until `ids` finish (default: every live run; timeout_seconds default 30). action=cancel / stop: end a run early — its partial result still returns as a completion message. Runs of other conversations are never visible or controllable here.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["list", "info", "cancel", "stop", "wait"], "description": "Default list."},
                    "subagent_id": {"type": "string", "description": "Run id for action=info / cancel / stop (a session id also works)."},
                    "ids": {"type": "array", "items": {"type": "string"}, "description": "Runs to wait for (action=wait); default: every live run."},
                    "timeout_seconds": {"type": "integer", "minimum": 0, "description": "action=wait timeout (default 30; 0 = snapshot)."},
                    "include_done": {"type": "boolean", "description": "action=list: include finished runs and their results."}
                },
                "required": []
            }),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "subagents") else { return ToolOutput::err("subagents needs the ark kernel") };
        let action = input.get("action").and_then(Value::as_str).map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty()).unwrap_or_else(|| "list".into());
        let r = (|| -> Result<Value, String> {
            match action.as_str() {
                "list" => {
                    let include_done = input.get("include_done").and_then(Value::as_bool).unwrap_or(false);
                    Ok(json!({"action": "list", "subagents": host.rt.subagent_list(&host.session, include_done)}))
                }
                "info" => {
                    let id = input.get("subagent_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).ok_or("action='info' requires `subagent_id` (from action='list')")?;
                    let all = host.rt.subagent_list(&host.session, true);
                    let rec = all.iter().find(|r| r["subagent_id"].as_str() == Some(id) || r["session_id"].as_str() == Some(id)).cloned();
                    match rec {
                        Some(r) => Ok(json!({"action": "info", "subagent": r})),
                        None => Err(format!("no sub-agent `{id}` in this conversation's spawn tree (see action='list'; include_done is implied here)")),
                    }
                }
                "cancel" | "stop" => {
                    let id = input.get("subagent_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| format!("action='{action}' requires `subagent_id` (from action='list')"))?;
                    let mut v = host.rt.subagent_stop(&host.session, id)?;
                    v["action"] = json!(action);
                    Ok(v)
                }
                "wait" => {
                    let mut ids = string_list(input.get("ids"), "ids")?;
                    if ids.is_empty() {
                        ids = host.rt.subagent_list(&host.session, false).iter().filter_map(|r| r["subagent_id"].as_str().map(String::from)).collect();
                    }
                    if ids.is_empty() {
                        return Ok(json!({"completed": [], "pending": [], "note": "no live sub-agent of this conversation"}));
                    }
                    Ok(host.rt.subagent_wait(&host.session, &ids, Some(Duration::from_secs(timeout_secs(&input, 30))), &ctx.cancel))
                }
                other => Err(format!("unknown action `{other}`; use list, info, cancel, stop or wait")),
            }
        })();
        match r {
            Ok(v) => json_output(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ───────────────────────── agents_list ─────────────────────────

/// `agents_list` (OpenClaw src/agents/tools/agents-list-tool.ts): spawnable named agents.
pub struct AgentsList;

impl Tool for AgentsList {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "agents_list".into(),
            description: "List the named agents configured on this machine — the valid `agent` / `agentId` targets for delegate_task and sessions_spawn. Each entry has id, name, model (the resolved provider/model it runs), default (is it the routing default) and description; the reply also names the current default agent and the agent this session runs as. Starts nothing.".into(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, _input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "agents_list") else { return ToolOutput::err("agents_list needs the ark kernel") };
        let cfg = host.rt.cfg_now();
        let all = crate::agents::all(&cfg, &host.rt.paths);
        let default = crate::agents::default_agent(&cfg, &host.rt.paths);
        let requester = host.rt.store.read(&host.session).map(|e| project(&e)).ok().and_then(|v| v.agent).unwrap_or_else(|| default.clone());
        let agents: Vec<Value> = all
            .iter()
            .map(|(id, a)| {
                let model = if a.model.trim().is_empty() { cfg.subagent_model().to_string() } else { a.model.clone() };
                json!({
                    "id": id,
                    "name": if a.name.trim().is_empty() { id.clone() } else { a.name.clone() },
                    "model": model,
                    "default": *id == default,
                    "description": a.description,
                    "role": a.role,
                    "workspace": a.workspace,
                })
            })
            .collect();
        json_output(&json!({"default_agent": default, "requester_agent": requester, "agents": agents}))
    }
}

// ───────────────────────── the runtime side ─────────────────────────

struct Prepared {
    id: String,
    child: String,
    model: String,
    task: String,
    images: Vec<Block>,
    worktree: Option<worktree::Info>,
    /// The thread this child was bound to (`sessions_spawn thread:true`).
    thread: Option<crate::threads::Binding>,
    schema: Option<Value>,
    timeout: Option<u64>,
    spec: ChildSpec,
}

// ───────────────────────── thread-bound / visible children ─────────────────────────

/// Upstream `buildThreadBindingUnavailableError`: the channel cannot open a thread at all.
const NO_THREAD_CHANNEL: &str = "thread=true is only available on channels that open a separate thread for the worker (e.g. Discord or Matrix threads). This request is not running on a channel that can bind a subagent thread. Retry without thread=true, or re-run sessions_spawn from a channel that supports threads.";

fn origin_field(o: &Value, k: &str) -> Option<String> {
    o.get(k).and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string()))).filter(|s| !s.is_empty())
}

/// `bindThreadForSubagentSpawn`: open a thread for the child in the requester's channel
/// conversation, record the binding and post the intro there. Policy errors are raised
/// *before* anything is opened, so a refused spawn leaves no thread behind.
fn bind_child_thread(rt: &Runtime, parent: &str, child: &str, agent: &str, label: &str, requested: &str, cwd: &Path) -> Result<crate::threads::Binding, String> {
    let routes = crate::kernel::host_routes().ok_or_else(|| NO_THREAD_CHANNEL.to_string())?;
    let origin = routes.origin(parent).filter(|o| !o.is_null()).ok_or_else(|| NO_THREAD_CHANNEL.to_string())?;
    let channel = origin_field(&origin, "channel").ok_or_else(|| NO_THREAD_CHANNEL.to_string())?;
    let chat = origin_field(&origin, "to").ok_or_else(|| NO_THREAD_CHANNEL.to_string())?;
    let policy = crate::threads::policy(&rt.cfg_now(), &channel);
    if !policy.enabled {
        return Err(format!(
            "Thread bindings are disabled for {channel} (set channels.{channel}.threadBindings.enabled=true to override for this account, or session.threadBindings.enabled=true globally)."
        ));
    }
    if !policy.spawn {
        return Err(format!("Thread-bound session spawns are disabled for {channel} (set channels.{channel}.threadBindings.spawnSessions=true to enable)."));
    }
    if !routes.supports_threads(&origin) {
        return Err(NO_THREAD_CHANNEL.into());
    }
    let name = crate::threads::thread_name(agent, Some(if requested.trim().is_empty() { label } else { requested }));
    let thread = routes.create_thread(&origin, &name).map_err(|e| format!("Thread bind failed: {e}"))?;
    let cwd = cwd.to_string_lossy().to_string();
    let binding = crate::threads::Binding {
        session: child.into(),
        parent: parent.into(),
        channel,
        chat,
        thread,
        agent: agent.into(),
        label: label.into(),
        name,
        intro: crate::threads::intro_text(label, policy.idle_ms, policy.max_age_ms, Some(&cwd)),
        idle_ms: policy.idle_ms,
        max_age_ms: policy.max_age_ms,
        ..Default::default()
    };
    let b = crate::threads::bind(&rt.paths, binding);
    // The thread announces itself once; a later delivery failure is not fatal to the spawn.
    if let Err(e) = routes.deliver(&b.origin(), &b.intro) {
        eprintln!("ark: thread binding intro for {} not delivered: {e}", b.thread);
    }
    Ok(b)
}

/// Publish a child as a visible sidebar session (`maybeSpawnVisibleSession`): its own title,
/// group and live status, kept after the run instead of being a hidden helper.
fn publish_visible(rt: &Runtime, parent: &str, child: &str, agent: &str, label: &str, group: Option<&str>) {
    let v = crate::threads::Visible {
        session: child.into(),
        parent: parent.into(),
        agent: agent.into(),
        label: label.chars().take(80).collect(),
        group: group.unwrap_or_default().chars().take(60).collect(),
        status: "running".into(),
        ..Default::default()
    };
    crate::threads::mark_visible(&rt.paths, v);
}

impl Runtime {
    /// Start one or more children for the session behind `host`. Sync mode returns
    /// `{"results": [Entry…]}`; background modes return the dispatch handle.
    pub(crate) fn delegate(self: &Arc<Self>, host: &Host, specs: Vec<ChildSpec>, mode: Mode, cancel: &Cancel) -> Result<Value, String> {
        let dc = &self.cfg.delegation;
        let max_depth = self.cfg.runner.max_spawn_depth;
        if host.depth + 1 > max_depth {
            return Err(format!("sub-agent depth limit ({max_depth}) reached; do the work yourself"));
        }
        if specs.is_empty() {
            return Err("no tasks given. Pass tasks=[{goal, context?}] (one entry per subagent).".into());
        }
        let max_children = dc.max_concurrent_children.max(1);
        if specs.len() > max_children {
            return Err(format!("{} tasks exceed delegation.max_concurrent_children={max_children}; split the work or raise the limit.", specs.len()));
        }
        if mode != Mode::Sync {
            let cap = if dc.max_async_children == 0 { max_children } else { dc.max_async_children };
            let live = self.subagents.lock().live_background(&host.session);
            if live + specs.len() > cap {
                return Err(format!("{live} background sub-agent(s) still running; at most {cap} may run at once (delegation.max_async_children). Wait for them, or stop one."));
            }
        }
        for s in &specs {
            if s.goal.trim().is_empty() {
                return Err("every task needs a non-empty `goal`".into());
            }
            if s.images.len() > MAX_TASK_IMAGES {
                return Err(format!("at most {MAX_TASK_IMAGES} images per task"));
            }
        }
        let unit = format!("dg-{}", crate::util::random_hex(8));
        let mut prepared = Vec::new();
        for (i, spec) in specs.into_iter().enumerate() {
            match self.prepare_child(host, spec, &unit, i, mode) {
                Ok(p) => prepared.push(p),
                Err(e) => {
                    // A refused sibling aborts the whole call: nothing half-started stays behind.
                    for p in &prepared {
                        self.subagents.lock().recs.remove(&p.id);
                        let _ = self.store.remove(&p.child);
                    }
                    return Err(e);
                }
            }
        }
        match mode {
            Mode::Sync => {
                let ledger = host.ledger.clone();
                let depth = host.depth;
                let entries: Vec<Entry> = std::thread::scope(|s| {
                    let hs: Vec<_> = prepared.into_iter().map(|p| {
                        let (ledger, cancel) = (ledger.clone(), cancel.child());
                        s.spawn(move || self.run_child(p, ledger, depth + 1, cancel))
                    }).collect();
                    hs.into_iter().map(|h| h.join().unwrap_or_default()).collect()
                });
                // Each entry carries its child's live transcript (tail-able after the fact).
                let results: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        let mut v = serde_json::to_value(e).unwrap_or_default();
                        if let Some(r) = self.subagents.get(&e.subagent_id) {
                            v["live_transcript"] = json!(r.live_log);
                        }
                        v
                    })
                    .collect();
                Ok(json!({"delegation_id": unit, "results": results}))
            }
            Mode::Background { .. } | Mode::Collect => {
                let mut handles = Vec::new();
                for p in prepared {
                    let r = self.subagents.get(&p.id).unwrap();
                    handles.push(json!({"subagent_id": p.id, "session_id": p.child, "goal": r.goal, "label": r.label, "model": p.model, "live_transcript": r.live_log, "worktree": p.worktree.as_ref().map(|w| &w.path)}));
                    let (rt, ledger, depth, cancel) = (self.clone(), host.ledger.child(Budget::default()), host.depth + 1, cancel.child());
                    std::thread::spawn(move || rt.run_child(p, ledger, depth, cancel));
                }
                let note = match mode {
                    Mode::Collect => "Children run in the background with no completion message: collect them with agents_wait (ids = subagent_id).",
                    Mode::Background { notify: false } => "Fire-and-forget: no completion message will arrive.",
                    _ => "Children run in the background; their results arrive as a NEW message between your turns. Finish what does not depend on them, give a one-line status and END YOUR TURN (or call sessions_yield). Never poll transcripts. Use action=list/steer/stop to control them.",
                };
                Ok(json!({"status": "dispatched", "delegation_id": unit, "subagents": handles, "note": note}))
            }
        }
    }

    fn prepare_child(self: &Arc<Self>, host: &Host, spec: ChildSpec, unit: &str, index: usize, mode: Mode) -> Result<Prepared, String> {
        let dc = &self.cfg.delegation;
        let id = format!("sa-{index}-{}", crate::util::random_hex(8));
        let agent = match spec.agent.as_deref().filter(|a| !a.is_empty()) {
            Some(a) => Some(crate::agents::resolve(&self.cfg, &self.paths, a).ok_or_else(|| format!("unknown agent `{a}` (see agents_list)"))?),
            None => None,
        };
        let model = spec.model.clone().filter(|m| !m.is_empty()).or_else(|| agent.as_ref().and_then(|a| a.model.clone())).unwrap_or_else(|| self.cfg.subagent_model().to_string());
        let mut ws = spec.cwd.clone().or_else(|| agent.as_ref().and_then(|a| a.workspace.clone())).unwrap_or_else(|| host.workspace.clone());
        if !ws.is_absolute() {
            ws = host.workspace.join(ws);
        }
        let mut wt = None;
        if spec.worktree.unwrap_or(dc.worktree_isolation) {
            match worktree::create(&ws, &format!("subagent-{id}")) {
                Ok(info) => {
                    ws = PathBuf::from(&info.path);
                    wt = Some(info);
                }
                // Outside git (or without commits) children share the parent's workspace.
                Err(_) if spec.worktree.is_none() => {}
                Err(e) => return Err(format!("worktree isolation: {e}")),
            }
        }
        let title: String = spec.label.clone().unwrap_or_else(|| spec.goal.chars().take(60).collect());
        let child = self.create_session(&ws, Some(&model), Some(&host.session), Some(&title)).map_err(|e| e.to_string())?;
        let mut sub = hooks::payload(&host.session, &host.workspace.to_string_lossy(), None, None, None, Some(&spec.goal));
        sub["subagent_id"] = child.clone().into();
        sub["child_subagent_id"] = id.clone().into();
        sub["model"] = model.clone().into();
        sub["depth"] = (host.depth + 1).into();
        if let (Some(b), _) = self.emit(HookEvent::SubagentStart, sub, "") {
            let _ = self.store.remove(&child);
            return Err(format!("sub-agent blocked by {b}"));
        }
        let mut prepared_thread: Option<crate::threads::Binding> = None;
        {
            let mut log = self.store.open(&child).map_err(|e| e.to_string())?;
            let ap = |log: &mut SessionLog, k: EventKind| self.append(log, k).map_err(|e| e.to_string());
            if let Some(a) = &agent {
                ap(&mut log, EventKind::Agent { agent: a.id.clone(), user: None })?;
            }
            let mut deny: Vec<String> = BLOCKED_FOR_CHILDREN.iter().map(|s| s.to_string()).collect();
            if !dc.orchestrator_enabled || host.depth + 2 > self.cfg.runner.max_spawn_depth {
                // Leaf children: delegation stays visible only through the depth error of `spawn`.
                deny.extend(["delegate_task", "sessions_spawn"].map(String::from));
            }
            let mut allow = spec.tools.as_ref().map(|t| expand_tools(t));
            if let Some(a) = &agent {
                deny.extend(a.tools_deny.iter().cloned());
                if allow.is_none() {
                    allow = a.tools_allow.clone().map(|t| expand_tools(&t));
                }
            }
            // A child never gains a tool the parent lacks.
            if let Ok(pv) = self.store.read(&host.session).map(|e| project(&e)) {
                deny.extend(pv.tool_deny.iter().cloned());
                if let (None, Some(pa)) = (&allow, &pv.tool_allow) {
                    allow = Some(pa.clone());
                } else if let (Some(a), Some(pa)) = (allow.as_mut(), &pv.tool_allow) {
                    a.retain(|t| pa.iter().any(|p| name_matches(p, t)));
                }
            }
            deny.sort();
            deny.dedup();
            ap(&mut log, EventKind::Tools { allow, deny })?;
            if !spec.plain || agent.is_some() {
                let mut v = project(log.events());
                if let Some(identity) = agent.as_ref().and_then(|a| a.identity.clone()) {
                    if let Some(seg) = v.system.iter_mut().find(|s| s.id == "identity") {
                        seg.text = format!("{}\n\n{identity}", seg.text);
                    }
                }
                if !spec.plain {
                    v.system.push(ark_core::SystemSegment { id: "subagent".into(), text: child_system_prompt(&spec, &ws, host.depth + 1, self.cfg.runner.max_spawn_depth, dc.orchestrator_enabled), cache: false });
                }
                ap(&mut log, EventKind::System { segments: v.system })?;
            }
            if let Some(t) = spec.thinking.as_deref().filter(|t| !t.is_empty()) {
                if !matches!(t, "off" | "low" | "medium" | "high") {
                    return Err(format!("thinking `{t}`: use off, low, medium or high"));
                }
                ap(&mut log, EventKind::Thinking { level: t.into() })?;
            }
            if spec.fork {
                // Everything up to (not including) the assistant message that called the tool.
                let upto = host.conversation.len().saturating_sub(1);
                for m in &host.conversation[..upto] {
                    ap(&mut log, EventKind::Message { message: m.clone(), usage: None, model: None, inbox: None })?;
                }
            }
            if spec.visible {
                // A visible child carries its sidebar settings from the first turn on.
                ap(&mut log, EventKind::Meta { pinned: None, archived: None, group: spec.group.clone(), status: Some("running".into()) })?;
            }
        }
        // `thread:true` / `visible:true`: bind or publish before the child runs, so a refused
        // spawn (bad channel, bindings off) leaves nothing behind.
        if spec.thread.is_some() || spec.visible {
            let agent_id = agent.as_ref().map(|a| a.id.clone()).unwrap_or_default();
            let label = spec.label.clone().filter(|l| !l.trim().is_empty()).unwrap_or_else(|| title.clone());
            let bound = match spec.thread.as_deref() {
                Some(requested) => match bind_child_thread(self, &host.session, &child, &agent_id, &label, requested, &ws) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        let _ = self.store.remove(&child);
                        return Err(e);
                    }
                },
                None => None,
            };
            if spec.visible {
                publish_visible(self, &host.session, &child, &agent_id, &label, spec.group.as_deref());
            }
            prepared_thread = bound;
        }
        let live = self.store.dir(&child).join("live.log");
        let mut task = spec.goal.clone();
        if spec.plain {
            if let Some(c) = spec.context.as_ref().filter(|c| !c.trim().is_empty()) {
                task.push_str(&format!("\n\nContext:\n{c}"));
            }
            if let Some(s) = &spec.output_schema {
                task.push_str(&format!("\n\n{}", crate::jsonschema::output_contract(s)));
            }
        }
        if !spec.attachments.is_empty() {
            let dir = self.store.dir(&child).join("artifacts").join("attachments");
            let _ = std::fs::create_dir_all(&dir);
            let mut lines = Vec::new();
            for (name, content) in &spec.attachments {
                let safe: String = name.chars().filter(|c| c.is_alphanumeric() || "._-".contains(*c)).collect();
                let safe = if safe.is_empty() || safe.starts_with('.') { format!("file-{}", lines.len()) } else { safe };
                let p = dir.join(&safe);
                std::fs::write(&p, content).map_err(|e| format!("attachment {name}: {e}"))?;
                lines.push(format!("- {}", p.display()));
            }
            task.push_str(&format!("\n\nAttached files (snapshots from the parent):\n{}", lines.join("\n")));
        }
        let mut images = Vec::new();
        let mut hints = Vec::new();
        for i in &spec.images {
            let p = Path::new(i);
            let p = if p.is_absolute() { p.to_path_buf() } else { host.workspace.join(p) };
            match (i.starts_with("http://") || i.starts_with("https://"), image_block(&p)) {
                (false, Some(b)) => images.push(b),
                _ => hints.push(i.clone()),
            }
        }
        if !hints.is_empty() {
            task.push_str(&format!("\n\nImages referenced by the parent (open them with your tools if you need to see them):\n{}", hints.iter().map(|h| format!("- {h}")).collect::<Vec<_>>().join("\n")));
        }
        let (background, notify, collect) = match mode {
            Mode::Sync => (false, false, false),
            Mode::Background { notify } => (true, notify, false),
            Mode::Collect => (true, false, true),
        };
        let rec = Rec {
            id: id.clone(),
            unit: unit.to_string(),
            task_index: index,
            parent: host.session.clone(),
            child: child.clone(),
            goal: spec.goal.clone(),
            label: spec.label.clone(),
            model: model.clone(),
            group: spec.group.clone(),
            started_ms: now_ms(),
            started: Instant::now(),
            state: State::Running,
            background,
            notify,
            collect,
            accepting_steer: true,
            entry: None,
            delivered: false,
            live_log: live,
            cancel: Cancel::new(),
        };
        if background {
            ledger_upsert(&self.paths.data, ledger_row(&rec));
        }
        self.subagents.insert(rec);
        let timeout = spec.timeout_secs.or(Some(dc.child_timeout_secs)).filter(|t| *t > 0);
        Ok(Prepared { id, child, model, task, images, worktree: wt, thread: prepared_thread, schema: spec.output_schema.clone(), timeout, spec })
    }

    /// Run a prepared child to completion and settle it (hooks, ledger, delivery).
    fn run_child(self: &Arc<Self>, p: Prepared, ledger: crate::ledger::Ledger, depth: u32, cancel: Cancel) -> Entry {
        let started = Instant::now();
        let own = self.subagents.get(&p.id).map(|r| r.cancel.clone()).unwrap_or_default();
        // Stoppable from either side: the parent's run, or `stop` on this child.
        let joined = cancel.child();
        let watcher_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let (j, o, d) = (joined.clone(), own.clone(), watcher_done.clone());
            std::thread::spawn(move || {
                while !d.load(std::sync::atomic::Ordering::SeqCst) {
                    if o.is_cancelled() {
                        j.cancel();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
        }
        let run_cancel = match p.timeout {
            Some(t) => joined.with_deadline(Instant::now() + Duration::from_secs(t)),
            None => joined.clone(),
        };
        let run = |text: &str, images: Vec<Block>| -> Result<crate::kernel::Outcome, String> {
            self.submit_with(&p.child, text, images, "parent").map_err(|e| e.to_string())?;
            self.run(&p.child, RunOpts { ledger: Some(ledger.child(Budget::default())), depth, cancel: Some(run_cancel.clone()), goal_mode: false, detach: false }).map_err(|e| e.to_string())
        };
        let mut usage = ark_core::Usage::default();
        let mut entry = Entry { task_index: self.subagents.get(&p.id).map(|r| r.task_index).unwrap_or(0), subagent_id: p.id.clone(), session_id: p.child.clone(), goal: p.spec.goal.clone(), label: p.spec.label.clone(), model: p.model.clone(), ..Default::default() };
        let parent = self.subagents.get(&p.id).map(|r| r.parent.clone()).unwrap_or_default();
        let target = self.subagent_delivery_target(&parent, &p.child);
        self.subagent_progress(&parent, &p.child, "started", None);
        let outcome = run(&p.task, p.images.clone());
        self.subagent_progress(&parent, &p.child, "ended", outcome.as_ref().ok().map(|o| &o.reason));
        let mut timed_out = run_cancel.timed_out();
        match outcome {
            Err(e) => {
                entry.status = "failed".into();
                entry.exit_reason = "error".into();
                entry.summary = e.clone();
                entry.error = Some(e);
            }
            Ok(mut o) => {
                usage.add(&o.usage);
                // Output contract: one bounded correction turn.
                if let (Some(schema), true) = (&p.schema, o.reason.ok()) {
                    match crate::jsonschema::validate_output(&o.text, schema) {
                        Ok(v) => {
                            entry.schema_valid = Some(true);
                            entry.structured = Some(v);
                        }
                        Err(errs) => match run(&crate::jsonschema::retry_message(&errs), vec![]) {
                            Ok(o2) => {
                                usage.add(&o2.usage);
                                match crate::jsonschema::validate_output(&o2.text, schema) {
                                    Ok(v) => {
                                        entry.schema_valid = Some(true);
                                        entry.structured = Some(v);
                                    }
                                    Err(e2) => {
                                        entry.schema_valid = Some(false);
                                        entry.schema_errors = e2;
                                    }
                                }
                                o = crate::kernel::Outcome { usage: o.usage, ..o2 };
                            }
                            Err(_) => {
                                entry.schema_valid = Some(false);
                                entry.schema_errors = errs;
                            }
                        },
                    }
                } else if p.schema.is_some() {
                    entry.schema_valid = Some(false);
                }
                timed_out = timed_out || run_cancel.timed_out();
                use crate::kernel::EndReason as R;
                let (status, exit) = match &o.reason {
                    R::Done | R::Idle => ("completed", "completed"),
                    R::MaxSteps | R::MaxTokens => ("completed", "max_iterations"),
                    R::Interrupted if timed_out => ("timeout", "timeout"),
                    R::Interrupted => ("interrupted", "interrupted"),
                    _ => ("failed", "error"),
                };
                entry.status = status.into();
                entry.exit_reason = exit.into();
                entry.truncated = exit == "max_iterations";
                if status == "failed" {
                    entry.error = Some(o.reason.label());
                }
                entry.summary = if o.text.trim().is_empty() && status != "completed" { format!("[{}]", o.reason.label()) } else { o.text };
            }
        }
        watcher_done.store(true, std::sync::atomic::Ordering::SeqCst);
        entry.summary = self.vault.redact(&entry.summary);
        entry.input_tokens = usage.input_tokens;
        entry.output_tokens = usage.output_tokens;
        entry.duration_seconds = (started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        if let Some(w) = &p.worktree {
            entry.worktree = Some(worktree::finalize(w, true));
        }
        // Steering that arrived too late for any step is reported, not lost.
        if let Ok(v) = self.store.read(&p.child).map(|e| project(&e)) {
            let late: Vec<String> = v.pending_inbox.iter().filter(|q| q.1 == "parent-steer").map(|q| q.2.clone()).collect();
            if !late.is_empty() {
                entry.missed_steer = Some(late.join("\n"));
            }
        }
        if let (Some(t), Some(h)) = (target, crate::kernel::host_routes()) {
            let header = format!("[sub-agent {} · {} · {} tokens]", p.child, entry.exit_reason, usage.input_tokens + usage.output_tokens);
            if let Err(e) = h.deliver(&t, &format!("{header}\n{}", entry.summary)) {
                eprintln!("ark: subagent_delivery_target: {e}");
            }
        }
        let mut stop = hooks::payload(&parent, "", None, None, None, Some(&p.spec.goal));
        stop["subagent_id"] = p.child.clone().into();
        stop["child_subagent_id"] = p.id.clone().into();
        stop["end_reason"] = entry.exit_reason.clone().into();
        stop["status"] = entry.status.clone().into();
        stop["text"] = entry.summary.clone().into();
        stop["tokens"] = (usage.input_tokens + usage.output_tokens).into();
        self.emit(HookEvent::SubagentStop, stop, "");
        self.settle(&p.id, entry.clone());
        // A bound thread sees this run's activity, and a visible session's sidebar row
        // carries the final status instead of "running" forever.
        if p.thread.is_some() {
            crate::threads::touch_session(&self.paths, &p.child);
        }
        crate::threads::set_visible_status(&self.paths, &p.child, &entry.status);
        entry
    }

    /// Record a finished child and deliver its unit's completion if the parent is idle.
    fn settle(self: &Arc<Self>, id: &str, entry: Entry) {
        let state = match entry.status.as_str() {
            "completed" => State::Completed,
            "interrupted" => State::Interrupted,
            "timeout" => State::Timeout,
            _ => State::Failed,
        };
        let independent = self.cfg.delegation.independent_completions;
        let mut g = self.subagents.lock();
        let Some(r) = g.recs.get_mut(id) else { return };
        r.state = state;
        r.accepting_steer = false;
        r.entry = Some(entry);
        if !r.notify {
            r.delivered = true;
        }
        let (parent, background) = (r.parent.clone(), r.background);
        let row = ledger_row(r);
        // A running parent picks completions up between turns (`await_children`);
        // an idle one gets them in its inbox now.
        let mut started = false;
        if !self.is_running(&parent) {
            let ready = g.take_ready(&parent, independent);
            for (unit, entries) in &ready {
                if self.submit(&parent, &completion_text(unit, entries), "subagent").is_ok() {
                    self.fire_delivery(&parent, unit, entries);
                    started = true;
                }
            }
        }
        let rows: Vec<LedgerRow> = g.recs.values().filter(|x| x.parent == parent && x.background).map(ledger_row).collect();
        drop(g);
        if background {
            ledger_upsert(&self.paths.data, row);
            for r in rows {
                ledger_upsert(&self.paths.data, r);
            }
        }
        self.subagents.notify_all();
        if started && self.auto_resume.load(std::sync::atomic::Ordering::SeqCst) && !self.is_running(&parent) {
            let _ = self.start(&parent, Default::default());
        }
    }

    fn fire_delivery(&self, parent: &str, unit: &str, entries: &[Entry]) {
        if self.has_hooks(HookEvent::SubagentDelivery) {
            let mut p = hooks::payload(parent, "", None, None, None, None);
            p["delegation_id"] = unit.into();
            p["results"] = json!(entries);
            self.emit(HookEvent::SubagentDelivery, p, "");
        }
    }

    /// Between turns: deliver ready completions, or wait for live background
    /// children (waking on queued input). Ok(true) = something new to process.
    pub(crate) fn await_children(&self, log: &mut SessionLog, queue: &Mutex<Vec<crate::projection::Queued>>, cancel: &Cancel) -> Result<bool, StoreError> {
        let independent = self.cfg.delegation.independent_completions;
        let mut announced = false;
        loop {
            self.drain_queue(log, queue)?;
            if !project(log.events()).pending_inbox.is_empty() {
                return Ok(true);
            }
            let mut g = self.subagents.lock();
            let ready = g.take_ready(&log.id, independent);
            if !ready.is_empty() {
                drop(g);
                for (unit, entries) in &ready {
                    self.append(log, EventKind::Inbox { id: crate::util::new_id(), source: "subagent".into(), text: completion_text(unit, entries), attachments: vec![] })?;
                    self.fire_delivery(&log.id, unit, entries);
                }
                let rows: Vec<LedgerRow> = self.subagents.lock().recs.values().filter(|x| x.parent == log.id && x.background).map(ledger_row).collect();
                for r in rows {
                    ledger_upsert(&self.paths.data, r);
                }
                return Ok(true);
            }
            if !g.has_live_notify(&log.id) || cancel.is_cancelled() {
                return Ok(false);
            }
            if !announced {
                announced = true;
                let n = g.recs.values().filter(|r| r.parent == log.id && r.notify && !r.state.done()).count();
                drop(g);
                self.append(log, EventKind::Notice { level: "info".into(), text: format!("waiting for {n} background sub-agent(s)…") })?;
                continue;
            }
            let _g = self.subagents.wait_timeout(g, Duration::from_millis(200));
        }
    }

    /// End of a run: hand still-undelivered completions to the inbox, then release
    /// the session — under the registry lock, so a child finishing right now
    /// either sees the session running (and its completion is taken here) or idle.
    pub(crate) fn close_run(self: &Arc<Self>, id: &str, mut log: SessionLog) -> Result<(), StoreError> {
        let g = self.subagents.lock();
        let mut g = g;
        let ready = g.take_ready(id, self.cfg.delegation.independent_completions);
        for (unit, entries) in &ready {
            self.append(&mut log, EventKind::Inbox { id: crate::util::new_id(), source: "subagent".into(), text: completion_text(unit, entries), attachments: vec![] })?;
            self.fire_delivery(id, unit, entries);
        }
        drop(log);
        self.running.lock().unwrap().remove(id);
        drop(g);
        if !ready.is_empty() && self.auto_resume.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self.start(id, Default::default());
        }
        Ok(())
    }

    /// Children of this session left behind by a dead process: report them.
    pub(crate) fn recover_subagents(&self, log: &mut SessionLog) -> Result<(), StoreError> {
        let rows = read_ledger(&self.paths.data);
        let max_age = self.cfg.delegation.replay_max_age_hours * 3_600_000;
        let now = now_ms();
        let mut changed = Vec::new();
        for mut r in rows.into_iter().filter(|r| r.parent == log.id && r.notify && !r.delivered && !pid_alive(r.pid)) {
            if r.state == State::Running {
                let child_text = self.store.read(&r.child).map(|e| project(&e).messages.iter().rev().find(|m| m.role == ark_core::Role::Assistant).map(|m| m.text()).unwrap_or_default()).unwrap_or_default();
                r.state = State::Interrupted;
                r.entry = Some(Entry {
                    subagent_id: r.id.clone(),
                    session_id: r.child.clone(),
                    goal: r.goal.clone(),
                    status: "interrupted".into(),
                    exit_reason: "interrupted".into(),
                    summary: if child_text.is_empty() { "[no output before the interruption]".into() } else { self.vault.redact(&child_text) },
                    error: Some(format!("the process running this sub-agent ended before it finished (restart or crash). Its partial transcript is session {}; inspect it with session_search / sessions_history, or re-delegate the remaining work.", r.child)),
                    ..Default::default()
                });
            }
            r.delivered = true;
            if now.saturating_sub(r.started_ms) > max_age {
                changed.push(r);
                continue;
            }
            changed.push(r);
        }
        let mut units: Vec<(String, Vec<Entry>)> = Vec::new();
        for r in &changed {
            if now.saturating_sub(r.started_ms) > max_age {
                continue;
            }
            if let Some(e) = &r.entry {
                match units.iter_mut().find(|(u, _)| *u == r.unit) {
                    Some((_, v)) => v.push(e.clone()),
                    None => units.push((r.unit.clone(), vec![e.clone()])),
                }
            }
        }
        for (unit, entries) in &units {
            self.append(log, EventKind::Inbox { id: crate::util::new_id(), source: "subagent".into(), text: completion_text(unit, entries), attachments: vec![] })?;
        }
        for r in changed {
            ledger_upsert(&self.paths.data, r);
        }
        Ok(())
    }

    // ───────────────────────── control plane ─────────────────────────

    /// Live and finished children `caller` owns (its spawn tree).
    pub fn subagent_list(&self, caller: &str, include_done: bool) -> Vec<Value> {
        let all = self.subagents.all();
        all.iter()
            .filter(|r| self.subagents.owns(caller, r) && (include_done || !r.state.done()))
            .map(|r| {
                let tools = self.store.read(&r.child).map(|e| e.iter().filter(|e| matches!(e.kind, EventKind::ToolCalled { .. })).count()).unwrap_or(0);
                json!({
                    "subagent_id": r.id, "session_id": r.child, "parent_session": r.parent, "delegation_id": r.unit,
                    "goal": r.goal, "label": r.label, "model": r.model, "status": r.state, "background": r.background,
                    "running_seconds": (r.started.elapsed().as_secs_f64() * 10.0).round() / 10.0, "tool_calls": tools,
                    "accepting_steer": r.accepting_steer, "live_transcript": r.live_log, "result": r.entry,
                })
            })
            .collect()
    }

    fn owned(&self, caller: &str, id: &str) -> Result<Rec, String> {
        let r = self.subagents.get(id).or_else(|| self.subagents.by_child(id)).ok_or_else(|| format!("no sub-agent `{id}` (see action=list)"))?;
        if !self.subagents.owns(caller, &r) {
            return Err(format!("sub-agent `{id}` belongs to another conversation"));
        }
        Ok(r)
    }

    /// Queue course-correction text into a running child (consumed at its next step).
    pub fn subagent_steer(&self, caller: &str, id: &str, text: &str) -> Result<Value, String> {
        if text.trim().is_empty() {
            return Err("steer needs a non-empty `message`".into());
        }
        let r = self.owned(caller, id)?;
        if r.state.done() || !r.accepting_steer {
            return Err(format!("sub-agent {} already finished; nothing to steer", r.id));
        }
        self.submit(&r.child, text, "parent-steer").map_err(|e| e.to_string())?;
        Ok(json!({"action": "steer", "subagent_id": r.id, "queued": true, "running": self.is_running(&r.child)}))
    }

    /// End a child early (its partial result still returns) — and its own children.
    pub fn subagent_stop(&self, caller: &str, id: &str) -> Result<Value, String> {
        let r = self.owned(caller, id)?;
        if r.state.done() {
            return Ok(json!({"action": "stop", "subagent_id": r.id, "stopped": false, "status": r.state, "note": "already finished"}));
        }
        r.cancel.cancel();
        self.interrupt(&r.child);
        Ok(json!({"action": "stop", "subagent_id": r.id, "stopped": true}))
    }

    /// Wait for children to settle. `timeout` None = until all are done (or `cancel`).
    /// Waiting never cancels a child nor consumes its completion delivery.
    pub fn subagent_wait(&self, caller: &str, ids: &[String], timeout: Option<Duration>, cancel: &Cancel) -> Value {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut errors = Vec::new();
        let mut want: Vec<String> = Vec::new();
        for i in ids {
            match self.owned(caller, i) {
                Ok(r) => want.push(r.id),
                Err(e) => errors.push(json!({"runId": i, "error": if e.contains("another") { "not_owner" } else { "not_found" }})),
            }
        }
        let mut g = self.subagents.lock();
        loop {
            let pending: Vec<String> = want.iter().filter(|i| g.recs.get(*i).is_some_and(|r| !r.state.done())).cloned().collect();
            let stop = pending.is_empty() || cancel.is_cancelled() || deadline.is_some_and(|d| Instant::now() >= d);
            if stop {
                let completed: Vec<Value> = want
                    .iter()
                    .filter_map(|i| g.recs.get(i))
                    .filter(|r| r.state.done())
                    .map(|r| {
                        let e = r.entry.clone().unwrap_or_default();
                        let status = match r.state {
                            State::Completed => "done",
                            State::Interrupted => "killed",
                            State::Timeout => "timeout",
                            _ => "failed",
                        };
                        json!({"runId": r.id, "sessionKey": r.child, "status": status, "result": e.summary, "structured": e.structured, "error": e.error, "schemaError": if e.schema_valid == Some(false) { Some(e.schema_errors.join("; ")) } else { None }, "label": r.label, "usage": {"inputTokens": e.input_tokens, "outputTokens": e.output_tokens}})
                    })
                    .collect();
                let mut out = json!({"completed": completed, "pending": pending});
                if !errors.is_empty() {
                    out["errors"] = json!(errors);
                }
                return out;
            }
            g = self.subagents.wait_timeout(g, Duration::from_millis(100));
        }
    }

    /// Plugin / ARP lifecycle: launch a background child for `parent` without a tool call.
    pub fn subagent_launch(self: &Arc<Self>, parent: &str, spec: ChildSpec, notify: bool) -> Result<Value, String> {
        let v = project(&self.store.read(parent).map_err(|e| e.to_string())?);
        let host = Host { rt: self.clone(), session: parent.to_string(), workspace: PathBuf::from(&v.workspace), depth: 0, ledger: crate::ledger::Ledger::new(self.cfg.budget.clone()), conversation: v.messages };
        self.delegate(&host, vec![spec], Mode::Background { notify }, &Cancel::new())
    }
}

/// Parse a Hermes/OpenClaw-style task object into a spec.
pub fn spec_from(v: &Value) -> Result<ChildSpec, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).filter(|x| !x.trim().is_empty());
    let list = |k: &str| -> Result<Vec<String>, String> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("`{k}` must be an array of strings"))).collect(),
            Some(Value::String(x)) => Ok(vec![x.clone()]),
            Some(_) => Err(format!("`{k}` must be an array of strings")),
        }
    };
    let goal = s("goal").or_else(|| s("task")).ok_or("every task needs a `goal`")?;
    let tools = match (list("tools")?, list("toolsets")?) {
        (a, b) if a.is_empty() && b.is_empty() => None,
        (mut a, b) => {
            a.extend(b);
            Some(a)
        }
    };
    let attachments = match v.get("attachments") {
        Some(Value::Array(a)) => {
            if a.len() > 50 {
                return Err("at most 50 attachments".into());
            }
            a.iter()
                .map(|x| {
                    let name = x.get("name").and_then(Value::as_str).ok_or("attachment needs `name`")?;
                    let content = x.get("content").and_then(Value::as_str).ok_or("attachment needs `content`")?;
                    let text = if x.get("encoding").and_then(Value::as_str) == Some("base64") { String::from_utf8_lossy(&base64_decode(content).ok_or("attachment: invalid base64")?).to_string() } else { content.to_string() };
                    Ok((name.to_string(), text))
                })
                .collect::<Result<Vec<_>, String>>()?
        }
        _ => vec![],
    };
    Ok(ChildSpec {
        goal,
        context: s("context"),
        model: s("model"),
        agent: s("agent").or_else(|| s("agentId")),
        tools,
        fork: v.get("fork").and_then(Value::as_bool).unwrap_or(false) || s("context").as_deref() == Some("fork"),
        output_schema: crate::jsonschema::coerce_schema(v.get("output_schema").or_else(|| v.get("outputSchema")))?,
        label: s("label").or_else(|| s("taskName")),
        cwd: s("cwd").map(PathBuf::from),
        worktree: v.get("worktree").and_then(Value::as_bool),
        timeout_secs: v.get("timeout_seconds").or_else(|| v.get("runTimeoutSeconds")).and_then(Value::as_u64),
        thinking: s("thinking"),
        images: list("images")?,
        attachments,
        group: s("group").or_else(|| s("groupId")),
        thread: None,
        visible: false,
        plain: false,
    })
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::new();
    for c in clean.chunks(4) {
        let mut n = 0u32;
        for (i, b) in c.iter().enumerate() {
            n |= val(*b)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if c.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if c.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// The thread-bound `Runtime::track_run` helper sits after the tests on purpose: it belongs
// with the `Runtime` impl at the end of the file, and moving the whole test module would bury
// the (long) production code. Nothing below is a test.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolsets_expand_and_policy() {
        let t = expand_tools(&["file".into(), "web_fetch".into(), "mcp".into(), " ".into()]);
        assert!(t.contains(&"read".to_string()) && t.contains(&"grep".to_string()) && t.contains(&"mcp__*".to_string()));
        assert_eq!(t.iter().filter(|x| *x == "web_fetch").count(), 1);
        let mut v = View { tool_allow: Some(t), tool_deny: vec!["grep".into()], ..Default::default() };
        assert!(tool_allowed(&v, "read") && tool_allowed(&v, "mcp__gh__issues") && tool_allowed(&v, "tool_describe"));
        assert!(!tool_allowed(&v, "grep") && !tool_allowed(&v, "shell"));
        v.tool_allow = None;
        assert!(tool_allowed(&v, "shell"));
    }

    #[test]
    fn spec_parsing() {
        let s = spec_from(&json!({"goal":"g","context":"c","toolsets":["file"],"output_schema":{"type":"object"},"images":"a.png","group":"x","attachments":[{"name":"n.txt","content":"aGk=","encoding":"base64"}]})).unwrap();
        assert_eq!(s.tools.unwrap(), ["file"]);
        assert_eq!(s.images, ["a.png"]);
        assert_eq!(s.attachments, [("n.txt".to_string(), "hi".to_string())]);
        assert!(s.output_schema.is_some() && s.group.as_deref() == Some("x"));
        let s = spec_from(&json!({"task":"t","agentId":"ops","runTimeoutSeconds":5,"taskName":"lbl","context":"fork"})).unwrap();
        assert!(s.fork && s.agent.as_deref() == Some("ops") && s.timeout_secs == Some(5) && s.label.as_deref() == Some("lbl"));
        assert!(spec_from(&json!({"context":"x"})).is_err());
        assert!(spec_from(&json!({"goal":"g","output_schema":"nope"})).is_err());
        assert!(spec_from(&json!({"goal":"g","tools":[1]})).is_err());
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn ready_buckets_respect_groups() {
        let mk = |id: &str, group: Option<&str>, done: bool| Rec {
            id: id.into(), unit: "u".into(), task_index: 0, parent: "p".into(), child: format!("c{id}"), goal: id.into(), label: None, model: "m".into(), group: group.map(String::from),
            started_ms: 0, started: Instant::now(), state: if done { State::Completed } else { State::Running }, background: true, notify: true, collect: false, accepting_steer: true,
            entry: Some(Entry { subagent_id: id.into(), ..Default::default() }), delivered: false, live_log: PathBuf::new(), cancel: Cancel::new(),
        };
        let mut g = Inner::default();
        for r in [mk("a", None, true), mk("b", Some("g"), true), mk("c", Some("g"), false)] {
            g.order.push(r.id.clone());
            g.recs.insert(r.id.clone(), r);
        }
        assert!(g.take_ready("p", false).is_empty(), "whole call waits for c");
        let ready = g.take_ready("p", true);
        assert_eq!(ready.len(), 1, "ungrouped a alone; group g waits for c");
        assert_eq!(ready[0].1[0].subagent_id, "a");
        g.recs.get_mut("c").unwrap().state = State::Failed;
        let ready = g.take_ready("p", true);
        assert_eq!(ready[0].1.len(), 2);
        assert!(g.take_ready("p", true).is_empty(), "delivered once");
        assert!(completion_text("u", &ready[0].1).contains("\"delegation_id\": \"u\""));
    }
}

impl Runtime {
    /// Run an existing session (another agent's chat) as a background job of
    /// `parent`: its reply comes back like a sub-agent completion (`message_agent`).
    pub(crate) fn track_run(self: &Arc<Self>, parent: &str, session: &str, goal: &str) -> String {
        let id = format!("dm-{}", crate::util::random_hex(8));
        let rec = Rec {
            id: id.clone(),
            unit: id.clone(),
            task_index: 0,
            parent: parent.to_string(),
            child: session.to_string(),
            goal: goal.chars().take(200).collect(),
            label: Some("message_agent".into()),
            model: String::new(),
            group: None,
            started_ms: now_ms(),
            started: Instant::now(),
            state: State::Running,
            background: true,
            notify: true,
            collect: false,
            accepting_steer: false,
            entry: None,
            delivered: false,
            live_log: self.store.dir(session).join("live.log"),
            cancel: Cancel::new(),
        };
        ledger_upsert(&self.paths.data, ledger_row(&rec));
        self.subagents.insert(rec);
        let (rt, sid, id2, goal) = (self.clone(), session.to_string(), id.clone(), goal.to_string());
        std::thread::spawn(move || {
            let t = Instant::now();
            // Already running (busy with someone else): our message steers that run; wait it out.
            while rt.is_running(&sid) {
                std::thread::sleep(Duration::from_millis(100));
            }
            let r = rt.run(&sid, RunOpts::default());
            let mut e = Entry { subagent_id: id2.clone(), session_id: sid.clone(), goal, model: project(&rt.store.read(&sid).unwrap_or_default()).model, duration_seconds: (t.elapsed().as_secs_f64() * 10.0).round() / 10.0, ..Default::default() };
            match r {
                Ok(o) => {
                    e.status = if o.reason.ok() { "completed".into() } else { "failed".into() };
                    e.exit_reason = o.reason.label();
                    e.summary = rt.vault.redact(&o.text);
                    e.input_tokens = o.usage.input_tokens;
                    e.output_tokens = o.usage.output_tokens;
                }
                Err(err) => {
                    e.status = "failed".into();
                    e.exit_reason = "error".into();
                    e.summary = err.to_string();
                    e.error = Some(err.to_string());
                }
            }
            rt.settle(&id2, e);
        });
        id
    }
}
