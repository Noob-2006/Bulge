//! OpenClaw hook points the runner fires (src/plugins/hook-types.ts): the turn-start chain
//! (`before_agent_run` gate → `before_agent_reply` → `before_model_resolve` →
//! `agent_turn_prepare` → `before_prompt_build`), `before_agent_finalize` revisions,
//! `before_message_write`, `resolve_exec_env`, `before_reset`, sub-agent progress and
//! delivery target, plus host helpers (`emit_all`, `emit_first`, host routes).
//!
//! Results follow OpenClaw's contracts with snake_case keys (camelCase is accepted too);
//! the hook's answer arrives as a modify of the payload's `result` field.

use super::*;
use std::cell::RefCell;
use std::sync::{OnceLock, RwLock};

/// OpenClaw `MAX_BEFORE_AGENT_FINALIZE_REVISIONS`.
pub(super) const MAX_FINALIZE_REVISIONS: u32 = 3;
/// OpenClaw `BLOCK_MESSAGE_PREFIX` (hook-decision-types.ts).
pub const BLOCK_MESSAGE_PREFIX: &str = "Your message could not be sent";
/// History handed to turn hooks (`messages`): the most recent ones, text only.
const HOOK_HISTORY: usize = 40;

/// What the turn-start hooks decided; applied to every model request of the turn.
#[derive(Default, Debug, Clone)]
pub(super) struct TurnHooks {
    pub model: Option<String>,
    pub fallbacks: Option<Vec<String>>,
    pub tools_allow: Option<Vec<String>>,
    system_prompt: Option<String>,
    prepend_system: Vec<String>,
    append_system: Vec<String>,
    prepend: Vec<String>,
    append: Vec<String>,
    pub revisions: u32,
}

impl TurnHooks {
    /// Shape one request: system prompt / system context, prompt context, tool allow-list.
    pub fn apply(&self, req: &mut ModelRequest) {
        if let Some(s) = &self.system_prompt {
            req.system = vec![SystemSegment { id: "hook_system_prompt".into(), text: s.clone(), cache: true }];
        }
        if !self.prepend_system.is_empty() {
            req.system.insert(0, SystemSegment { id: "hook_prepend_system".into(), text: self.prepend_system.join("\n\n"), cache: true });
        }
        if !self.append_system.is_empty() {
            req.system.push(SystemSegment { id: "hook_append_system".into(), text: self.append_system.join("\n\n"), cache: true });
        }
        if !self.prepend.is_empty() || !self.append.is_empty() {
            // The turn's prompt: the last user message that is not tool results.
            if let Some(m) = req.messages.iter_mut().rev().find(|m| m.role == Role::User && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))) {
                if !self.prepend.is_empty() {
                    m.content.insert(0, Block::text(self.prepend.join("\n\n")));
                }
                if !self.append.is_empty() {
                    m.content.push(Block::text(self.append.join("\n\n")));
                }
            }
        }
        if let Some(allow) = &self.tools_allow {
            req.tools.retain(|t| allowed(allow, &t.name));
        }
    }
}

fn allowed(allow: &[String], name: &str) -> bool {
    name == KERNEL_TOOL_GOAL_DONE || allow.iter().any(|a| a == name)
}

// The turn's fallback chain / tool allow-list, visible to `call_model` and `execute` on the
// turn's own thread (nested sub-agent turns set and restore their own).
/// `(fallbacks, tools_allow)` for the current turn; `None` = inherit the config.
type TurnScope = Option<(Option<Vec<String>>, Option<Vec<String>>)>;
/// One hook's answer, keyed by hook name; `Err` means the hook itself broke.
type HookAnswer = (String, Result<HookDecision, String>);

thread_local! {
    static SCOPE: RefCell<TurnScope> = const { RefCell::new(None) };
}

pub(super) struct ScopeGuard(TurnScope);

impl ScopeGuard {
    pub fn set(th: &TurnHooks) -> ScopeGuard {
        ScopeGuard(SCOPE.with(|s| s.replace(Some((th.fallbacks.clone(), th.tools_allow.clone())))))
    }
}
impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let prev = self.0.take();
        SCOPE.with(|s| *s.borrow_mut() = prev);
    }
}

/// The fallback chain for this turn: a `before_model_resolve` override, else the config's.
pub(super) fn fallbacks(cfg: &[String]) -> Vec<String> {
    SCOPE.with(|s| s.borrow().as_ref().and_then(|(f, _)| f.clone())).unwrap_or_else(|| cfg.to_vec())
}

/// A tool the turn's `before_prompt_build` allow-list excludes (None = allowed).
pub(super) fn tool_refused(name: &str) -> Option<String> {
    SCOPE.with(|s| match s.borrow().as_ref().and_then(|(_, a)| a.as_ref()) {
        Some(a) if !allowed(a, name) => Some(format!("tool `{name}` is not available in this turn (narrowed by a before_prompt_build hook)")),
        _ => None,
    })
}

// ───────────────────────── host routes ─────────────────────────

/// Channel routing the host provides (arkd with channels): where a session's messages come
/// from, and how to send text there. Used by `subagent_delivery_target` and bundled hooks.
pub trait HostRoutes: Send + Sync {
    /// `{channel, to, thread_id}` of the chat bound to `session`.
    fn origin(&self, session: &str) -> Option<Value>;
    /// Send `text` to an origin (`{channel, to, thread_id}`).
    fn deliver(&self, origin: &Value, text: &str) -> Result<(), String>;
    /// Whether the origin's channel can open a thread of its own (Discord / Slack / Matrix
    /// style). Checked before `sessions_spawn thread:true` spawns anything.
    fn supports_threads(&self, _origin: &Value) -> bool {
        false
    }
    /// Open a new thread named `name` inside the origin's conversation and return its id.
    /// `Err` must read as a user-facing reason the channel cannot bind a thread.
    fn create_thread(&self, _origin: &Value, _name: &str) -> Result<String, String> {
        Err("this channel cannot open a thread for a worker".into())
    }
}

fn routes_cell() -> &'static RwLock<Option<Arc<dyn HostRoutes>>> {
    static R: OnceLock<RwLock<Option<Arc<dyn HostRoutes>>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(None))
}

/// Install (or replace) the process's host routes.
pub fn set_host_routes(r: Arc<dyn HostRoutes>) {
    *routes_cell().write().unwrap() = Some(r);
}

pub fn host_routes() -> Option<Arc<dyn HostRoutes>> {
    routes_cell().read().unwrap().clone()
}

/// Recent history as `[{role, text}]` for hook payloads.
pub fn history(messages: &[Message], n: usize) -> Value {
    let start = messages.len().saturating_sub(n);
    Value::Array(
        messages[start..]
            .iter()
            .map(|m| json!({"role": if m.role == Role::User { "user" } else { "assistant" }, "text": m.text()}))
            .collect(),
    )
}

/// A tool wrapper that exports `resolve_exec_env` variables before the shell command.
/// The write-ahead log keeps the original input, so values never reach the session log.
struct EnvShell {
    inner: Arc<dyn Tool>,
    env: Vec<(String, String)>,
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl Tool for EnvShell {
    fn spec(&self) -> ToolSpec {
        self.inner.spec()
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        self.inner.effects(ctx, input)
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        if let Some(c) = input.get("command").and_then(Value::as_str) {
            let exports: String = self.env.iter().map(|(k, v)| format!("export {k}={}\n", sh_quote(v))).collect();
            input["command"] = format!("{exports}{c}").into();
        }
        self.inner.call(ctx, input)
    }
}

impl Runtime {
    // ───────────────────────── host helpers ─────────────────────────

    /// Run every hook for `event` on the same payload (no chaining) and return each answer.
    /// Broken hooks warn on stderr and are left out.
    pub fn emit_all(&self, event: HookEvent, payload: Value) -> Vec<(String, HookDecision)> {
        let hooks: Vec<_> = self.hooks.read().unwrap().iter().filter(|h| h.wants(event, None)).cloned().collect();
        let mut out = Vec::new();
        for h in hooks {
            match h.run(event, &payload) {
                Ok(d) => out.push((h.name(), d)),
                Err(e) => eprintln!("ark: hook {} failed ({e}); continuing", h.name()),
            }
        }
        out
    }

    /// The first hook answer `accept` takes (claim semantics: later hooks do not run).
    pub fn emit_first(&self, event: HookEvent, payload: Value, accept: impl Fn(&HookDecision) -> bool) -> Option<(String, HookDecision)> {
        let hooks: Vec<_> = self.hooks.read().unwrap().iter().filter(|h| h.wants(event, None)).cloned().collect();
        for h in hooks {
            match h.run(event, &payload) {
                Ok(d) if accept(&d) => return Some((h.name(), d)),
                Ok(_) => {}
                Err(e) => eprintln!("ark: hook {} failed ({e}); continuing", h.name()),
            }
        }
        None
    }

    /// Context contributions of every hook: (prepend, append, plain context).
    pub fn emit_collect(&self, event: HookEvent, payload: Value) -> (Vec<String>, Vec<String>, Vec<String>) {
        let (mut pre, mut post, mut ctx) = (vec![], vec![], vec![]);
        for (_, d) in self.emit_all(event, payload) {
            match d {
                HookDecision::Modify(v) => {
                    let (p, a) = hooks::context_parts(&v);
                    pre.extend(p);
                    post.extend(a);
                }
                HookDecision::Context(c) => ctx.push(c),
                _ => {}
            }
        }
        (pre, post, ctx)
    }

    /// Hook answers for the turn-start chain, each against the same payload; broken hooks
    /// are `Err` so gates can fail closed.
    fn fire_each(&self, log: &mut SessionLog, event: HookEvent, payload: &Value) -> Result<Vec<HookAnswer>, StoreError> {
        let hooks: Vec<_> = self.hooks.read().unwrap().iter().filter(|h| h.wants(event, None)).cloned().collect();
        let mut out = Vec::new();
        for h in hooks {
            let r = h.run(event, payload);
            if let Err(e) = &r {
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("hook {} failed ({e})", h.name()) })?;
            }
            out.push((h.name(), r));
        }
        Ok(out)
    }

    /// `before_agent_run` / `before_agent_reply` / `before_model_resolve` / `agent_turn_prepare`
    /// / `before_prompt_build`. `Err(text)` = the turn was answered (gate refusal or a hook reply);
    /// the assistant message is already written.
    pub(super) fn turn_start_hooks(&self, log: &mut SessionLog, depth: u32) -> Result<Result<TurnHooks, String>, StoreError> {
        let mut th = TurnHooks::default();
        let any = [HookEvent::BeforeAgentRun, HookEvent::BeforeAgentReply, HookEvent::BeforeModelResolve, HookEvent::AgentTurnPrepare, HookEvent::BeforePromptBuild];
        if !any.iter().any(|e| self.has_hooks(*e)) {
            return Ok(Ok(th));
        }
        let view = project(log.events());
        // A fresh prompt (not a resumed tool round).
        let last = view.messages.last();
        let fresh = last.filter(|m| m.role == Role::User && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. })));
        let prompt = fresh.map(|m| m.text()).unwrap_or_default();
        let sid = log.id.clone();
        let base = |extra: Value| {
            let mut p = hooks::payload(&sid, &view.workspace, None, None, None, Some(&prompt));
            p["depth"] = depth.into();
            p["model"] = view.model.clone().into();
            if let (Value::Object(m), Some(o)) = (extra, p.as_object_mut()) {
                o.extend(m);
            }
            p
        };
        let source = view.pending_inbox.first().map(|i| i.1.clone()).or_else(|| {
            log.events().iter().rev().find_map(|e| match &e.kind {
                EventKind::Inbox { source, .. } => Some(source.clone()),
                _ => None,
            })
        });
        let source = source.unwrap_or_default();

        if fresh.is_some() && self.has_hooks(HookEvent::BeforeAgentRun) {
            let channel = source.strip_prefix("channel:").unwrap_or("");
            let p = base(json!({"messages": history(&view.messages[..view.messages.len().saturating_sub(1)], HOOK_HISTORY), "system_prompt": view.system.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join("\n\n"), "channel": channel, "source": source, "result": Value::Null}));
            for (name, r) in self.fire_each(log, HookEvent::BeforeAgentRun, &p)? {
                let msg = match r {
                    Ok(HookDecision::Block(_)) => Some(format!("{BLOCK_MESSAGE_PREFIX}: blocked by {name}")),
                    Ok(HookDecision::Modify(v)) if hooks::rget(&v, "outcome").and_then(Value::as_str) == Some("block") => Some(match hooks::rget(&v, "message").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty()) {
                        Some(m) => format!("{BLOCK_MESSAGE_PREFIX}: {m} (blocked by {name})"),
                        None => format!("{BLOCK_MESSAGE_PREFIX}: blocked by {name}"),
                    }),
                    // Fail closed, like OpenClaw's runBeforeAgentRunGate.
                    Err(_) => Some(format!("{BLOCK_MESSAGE_PREFIX}: blocked by {name}")),
                    Ok(_) => None,
                };
                if let Some(m) = msg {
                    self.append(log, EventKind::Notice { level: "warn".into(), text: format!("before_agent_run: turn refused by {name}") })?;
                    self.append(log, EventKind::Message { message: Message::assistant(m.clone()), usage: None, model: Some("hook".into()), inbox: None })?;
                    return Ok(Err(m));
                }
            }
        }

        if fresh.is_some() && self.has_hooks(HookEvent::BeforeAgentReply) {
            let trigger = if source.contains("cron") || source.contains("schedule") {
                "cron"
            } else if source.contains("heartbeat") {
                "heartbeat"
            } else {
                "user"
            };
            let p = base(json!({"cleaned_body": prompt, "trigger": trigger, "result": Value::Null}));
            for (name, r) in self.fire_each(log, HookEvent::BeforeAgentReply, &p)? {
                if let Ok(HookDecision::Modify(v)) = r {
                    if let Some(reply) = hooks::handled(&v) {
                        let text = reply.unwrap_or_default();
                        self.append(log, EventKind::Notice { level: "info".into(), text: format!("before_agent_reply: turn answered by {name}") })?;
                        self.append(log, EventKind::Message { message: Message::assistant(text.clone()), usage: None, model: Some("hook".into()), inbox: None })?;
                        return Ok(Err(text));
                    }
                }
            }
        }

        if self.has_hooks(HookEvent::BeforeModelResolve) {
            let attachments: Vec<Value> = fresh
                .map(|m| {
                    m.content
                        .iter()
                        .filter_map(|b| match b {
                            Block::Image { media_type, .. } => Some(json!({"kind": "image", "mime_type": media_type})),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let p = base(json!({"attachments": attachments, "result": Value::Null}));
            if let Some(v) = self.fire(Some(log), HookEvent::BeforeModelResolve, None, p, "result")?.modified {
                let (provider, name) = view.model.split_once('/').unwrap_or(("", &view.model));
                match &v {
                    Value::String(m) if m.contains('/') => th.model = Some(m.clone()),
                    Value::Object(_) => {
                        let mo = hooks::rget(&v, "model_override").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
                        let po = hooks::rget(&v, "provider_override").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
                        th.model = match (po, mo) {
                            (_, Some(m)) if m.contains('/') => Some(m.to_string()),
                            (Some(p), Some(m)) => Some(format!("{p}/{m}")),
                            (None, Some(m)) => Some(format!("{provider}/{m}")),
                            (Some(p), None) => Some(format!("{p}/{name}")),
                            (None, None) => None,
                        };
                        if let Some(f) = hooks::rget(&v, "fallbacks_override").and_then(Value::as_array) {
                            th.fallbacks = Some(f.iter().filter_map(Value::as_str).filter(|m| m.contains('/')).map(String::from).collect());
                        }
                    }
                    _ => {}
                }
                if let Some(m) = &th.model {
                    self.append(log, EventKind::Notice { level: "info".into(), text: format!("before_model_resolve: this turn uses {m}") })?;
                }
            }
        }

        if self.has_hooks(HookEvent::AgentTurnPrepare) {
            let p = base(json!({"messages": history(&view.messages, HOOK_HISTORY), "queued_injections": [], "result": Value::Null}));
            for (_, r) in self.fire_each(log, HookEvent::AgentTurnPrepare, &p)? {
                match r {
                    Ok(HookDecision::Modify(v)) => {
                        let (pre, post) = hooks::context_parts(&v);
                        th.prepend.extend(pre);
                        th.append.extend(post);
                    }
                    Ok(HookDecision::Context(c)) => th.append.push(c),
                    _ => {}
                }
            }
        }

        if self.has_hooks(HookEvent::BeforePromptBuild) {
            let p = base(json!({"current_user_message": prompt, "messages": history(&view.messages, HOOK_HISTORY), "result": Value::Null}));
            for (_, r) in self.fire_each(log, HookEvent::BeforePromptBuild, &p)? {
                match r {
                    Ok(HookDecision::Modify(v)) => {
                        let (pre, post) = hooks::context_parts(&v);
                        th.prepend.extend(pre);
                        th.append.extend(post);
                        let s = |k: &str| hooks::rget(&v, k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from);
                        if let Some(sp) = s("system_prompt") {
                            th.system_prompt = Some(sp);
                        }
                        th.prepend_system.extend(s("prepend_system_context"));
                        th.append_system.extend(s("append_system_context"));
                        if let Some(a) = hooks::rget(&v, "tools_allow").and_then(Value::as_array) {
                            let mine: Vec<String> = a.iter().filter_map(Value::as_str).map(String::from).collect();
                            // Several hooks narrow together.
                            th.tools_allow = Some(match th.tools_allow.take() {
                                Some(prev) => prev.into_iter().filter(|t| mine.contains(t)).collect(),
                                None => mine,
                            });
                        }
                    }
                    Ok(HookDecision::Context(c)) => th.append.push(c),
                    _ => {}
                }
            }
        }
        Ok(Ok(th))
    }

    /// `before_agent_finalize`: Some(instruction) = ask the model for another pass.
    pub(super) fn finalize_revision(&self, log: &mut SessionLog, th: &mut TurnHooks, last_text: &str) -> Result<Option<String>, StoreError> {
        if !self.has_hooks(HookEvent::BeforeAgentFinalize) || last_text.trim().is_empty() {
            return Ok(None);
        }
        if th.revisions >= MAX_FINALIZE_REVISIONS {
            self.append(log, EventKind::Notice { level: "warn".into(), text: format!("before_agent_finalize revision limit reached ({MAX_FINALIZE_REVISIONS}); finalizing") })?;
            return Ok(None);
        }
        let view = project(log.events());
        let mut p = hooks::payload(&log.id, &view.workspace, None, None, None, None);
        p["model"] = view.model.clone().into();
        p["last_assistant_message"] = last_text.into();
        p["stop_hook_active"] = (th.revisions > 0).into();
        p["messages"] = history(&view.messages, HOOK_HISTORY);
        p["result"] = Value::Null;
        let mut revise: Option<String> = None;
        for (name, r) in self.fire_each(log, HookEvent::BeforeAgentFinalize, &p)? {
            match r {
                // "finalize" wins over any other hook's revision request.
                Ok(HookDecision::Modify(v)) if hooks::rget(&v, "action").and_then(Value::as_str) == Some("finalize") => return Ok(None),
                Ok(HookDecision::Modify(v)) if hooks::rget(&v, "action").and_then(Value::as_str) == Some("revise") => {
                    let instr = hooks::rget(&v, "retry").and_then(|r| r.get("instruction")).and_then(Value::as_str).or_else(|| hooks::rget(&v, "reason").and_then(Value::as_str)).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("Revise your answer before finishing.");
                    revise.get_or_insert_with(|| format!("{instr} (requested by {name})"));
                }
                Ok(HookDecision::Block(r)) => {
                    revise.get_or_insert_with(|| format!("{r} (requested by {name})"));
                }
                _ => {}
            }
        }
        if let Some(r) = &revise {
            th.revisions += 1;
            self.append(log, EventKind::Notice { level: "info".into(), text: format!("before_agent_finalize: revision {}/{MAX_FINALIZE_REVISIONS}", th.revisions) })?;
            return Ok(Some(format!("[before_agent_finalize] {r}")));
        }
        Ok(None)
    }

    /// `before_message_write`: the message to write, or a notice in its place.
    /// Transcript safety: messages carrying tool calls/results are never dropped and keep
    /// their tool ids; a blocked inbox message is written as a placeholder so it is consumed.
    pub(super) fn before_message_write(&self, log: &mut SessionLog, kind: EventKind) -> Result<EventKind, StoreError> {
        let EventKind::Message { message, usage, model, inbox } = kind else { return Ok(kind) };
        let tool_ids = |m: &Message| -> Vec<String> {
            let mut v: Vec<String> = m
                .content
                .iter()
                .filter_map(|b| match b {
                    Block::ToolUse { id, .. } => Some(format!("u:{id}")),
                    Block::ToolResult { tool_use_id, .. } => Some(format!("r:{tool_use_id}")),
                    _ => None,
                })
                .collect();
            v.sort();
            v
        };
        let ids = tool_ids(&message);
        let mut p = hooks::payload(&log.id, "", None, None, None, None);
        p["role"] = if message.role == Role::User { "user" } else { "assistant" }.into();
        p["message"] = serde_json::to_value(&message).unwrap_or(Value::Null);
        let fired = self.fire(Some(log), HookEvent::BeforeMessageWrite, None, p, "message")?;
        if let Some(reason) = fired.block {
            if !ids.is_empty() {
                self.append(log, EventKind::Notice { level: "warn".into(), text: format!("before_message_write block ignored for a message with tool calls ({reason})") })?;
            } else if inbox.is_some() {
                return Ok(EventKind::Message { message: Message { role: message.role, content: vec![Block::text("[message withheld by a before_message_write hook]")] }, usage, model, inbox });
            } else {
                return Ok(EventKind::Notice { level: "info".into(), text: format!("message withheld by before_message_write ({reason})") });
            }
        } else if let Some(v) = fired.modified {
            match serde_json::from_value::<Message>(v) {
                Ok(m) if m.role == message.role && tool_ids(&m) == ids => return Ok(EventKind::Message { message: m, usage, model, inbox }),
                _ => self.append(log, EventKind::Notice { level: "warn".into(), text: "before_message_write replacement ignored (must keep the role and tool calls)".into() })?,
            };
        }
        Ok(EventKind::Message { message, usage, model, inbox })
    }

    /// `resolve_exec_env`: wrap the shell tool so the variables hooks resolve are exported.
    pub(super) fn exec_env_tool(&self, log: &mut SessionLog, workspace: &str, name: &str, tool: Arc<dyn Tool>) -> Result<Arc<dyn Tool>, StoreError> {
        if name != "shell" || !self.has_hooks(HookEvent::ResolveExecEnv) {
            return Ok(tool);
        }
        let mut p = hooks::payload(&log.id, workspace, Some(name), None, None, None);
        p["host"] = "local".into();
        p["result"] = Value::Null;
        let mut env: Vec<(String, String)> = Vec::new();
        for (_, r) in self.fire_each(log, HookEvent::ResolveExecEnv, &p)? {
            if let Ok(HookDecision::Modify(v)) = r {
                for (k, val) in hooks::exec_env(&v) {
                    env.retain(|(e, _)| *e != k);
                    env.push((k, val));
                }
            }
        }
        Ok(if env.is_empty() { tool } else { Arc::new(EnvShell { inner: tool, env }) })
    }

    /// `before_reset` with the history about to be left behind.
    pub(super) fn before_reset(&self, id: &str, reason: &str) {
        let Ok(log) = self.store.open(id) else { return };
        let view = project(log.events());
        let mut p = hooks::payload(id, &view.workspace, None, None, None, None);
        p["reason"] = reason.into();
        p["messages"] = history(&view.messages, 200);
        p["session_file"] = self.store.dir(id).to_string_lossy().to_string().into();
        self.emit(HookEvent::BeforeReset, p, "");
    }

    /// `subagent_progress` (observe only).
    pub(crate) fn subagent_progress(&self, parent: &str, child: &str, phase: &str, outcome: Option<&EndReason>) {
        if !self.has_hooks(HookEvent::SubagentProgress) {
            return;
        }
        let mut p = json!({"session_id": parent, "cwd": "", "phase": phase, "run_id": child, "child_session": child, "requester_session": parent});
        if let Some(r) = outcome {
            p["outcome"] = match r {
                EndReason::Done | EndReason::Idle => "ok",
                EndReason::Interrupted => "killed",
                EndReason::Budget(_) | EndReason::MaxSteps => "timeout",
                _ => "error",
            }
            .into();
        }
        if let Some(o) = host_routes().and_then(|h| h.origin(parent)) {
            p["requester"] = o;
        }
        self.emit(HookEvent::SubagentProgress, p, "");
    }

    /// `subagent_delivery_target`: an extra origin the sub-agent's completion goes to.
    pub(crate) fn subagent_delivery_target(&self, parent: &str, child: &str) -> Option<Value> {
        // A thread-bound child (`sessions_spawn thread:true`) announces into its own thread,
        // hooks or not: that thread is where the user watches this worker.
        if let Some(b) = crate::threads::by_session(&self.paths, child) {
            return Some(b.origin());
        }
        if !self.has_hooks(HookEvent::SubagentDeliveryTarget) {
            return None;
        }
        let origin = host_routes().and_then(|h| h.origin(parent));
        let p = json!({"session_id": parent, "cwd": "", "child_session": child, "requester_session": parent, "requester_origin": origin, "child_run_id": child, "spawn_mode": "run", "expects_completion_message": true, "result": Value::Null});
        let (_, v) = self.emit(HookEvent::SubagentDeliveryTarget, p, "result");
        v.and_then(|v| hooks::rget(&v, "origin").cloned()).filter(|o| o.get("channel").and_then(Value::as_str).is_some_and(|c| !c.is_empty()) && o.get("to").is_some())
    }
}
