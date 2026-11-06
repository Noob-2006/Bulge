//! Lifecycle hooks. The kernel only knows the `Hook` trait; shell hooks
//! (Claude Code–compatible) live here, plugin hooks come from seagent-plugin.
//!
//! Shell hook protocol: the event is written as JSON to stdin
//! (`hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`,
//! `tool_response`, `prompt`). Exit 0 = allow (stdout may be JSON:
//! `{"decision":"block","reason":..}`, `{"updated_input":{..}}`,
//! `{"additional_context":".."}`, or Claude's `hookSpecificOutput` form);
//! exit 2 = block with stderr as the reason; anything else = hook broken,
//! warn and allow. A hook can never take the session down.

pub mod spill;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    SessionStart,
    /// The session is deleted, replaced (`/new`, `/forget`) or its interactive client exits.
    SessionEnd,
    UserPrompt,
    PreTool,
    PostTool,
    TurnEnd,
    /// Before each model request (`model`, `messages`); block = fail the step.
    PreModel,
    /// After a model response (`model`, `text`, `stop`, `usage`); observe only.
    PostModel,
    /// Before summarising the context; block = skip this compaction.
    PreCompact,
    PostCompact,
    /// A channel message passed the access checks (`channel`, `chat`, `sender`, `prompt` = text);
    /// block = drop it, modify = rewrite the text.
    MessageReceived,
    /// A channel reply is about to go out (`prompt` = text); block = don't send, modify = rewrite.
    MessageSending,
    MessageSent,
    SubagentStart,
    SubagentStop,
    /// A background sub-agent's completion was handed to its parent (`results`; observe only).
    SubagentDelivery,
    /// The agent needs a human (approval request or question).
    Notification,
    DaemonStart,
    DaemonStop,
    /// A gate is about to ask the human to approve a tool call (observe only).
    PreApprovalRequest,
    /// The human answered an approval (`choice`: once | always | deny; observe only).
    PostApprovalResponse,
    /// The agent asks the human a question / got the answer (`answer`; observe only).
    HumanInputRequest,
    HumanInputResolved,
    /// A tool's result before the model sees it (`result` = text); modify = replace it.
    TransformToolResult,
    /// The shell tool's output (`output`), before transform_tool_result; modify = replace it.
    TransformTerminalOutput,
    /// The model's reply text (`text`); modify = replace the text blocks.
    TransformLlmOutput,
    /// A failed model call (`classification` = {kind, retryable, fallback}); modify = override them.
    TransformApiError,
    /// Middleware (Hermes): rewrite a tool call's arguments (`tool_input`) before hooks and gates.
    ToolRequest,
    /// Middleware: `phase` "call" — set `tool_response` to answer without running the tool;
    /// `phase` "result" — replace `tool_response`.
    ToolExecution,
    /// Middleware: rewrite the model request (`request`, an seagent ModelRequest).
    LlmRequest,
    /// Middleware: `phase` "call" — set `response` to answer without calling the provider;
    /// `phase` "result" — replace `response`.
    LlmExecution,
    // ── OpenClaw hook points (src/plugins/hook-types.ts). Results are a modify of `result`. ──
    /// Before a turn picks its model (`prompt`, `attachments` = [{kind, mime_type}], `model`).
    /// Result: `"provider/model"` or `{model_override, provider_override, fallbacks_override}`
    /// — applies to this turn only.
    BeforeModelResolve,
    /// A turn is about to start (`prompt`, `messages` = recent history, `queued_injections`).
    /// Result: `{prepend_context, append_context}`; plain-text context = append. Ephemeral.
    AgentTurnPrepare,
    /// Each model request of a turn is being built (`prompt`, `current_user_message`, `messages`).
    /// Result: `{system_prompt, prepend_context, append_context, prepend_system_context,
    /// append_system_context, tools_allow}`. Unlike `user_prompt` (fired once on submit, can
    /// rewrite the stored text) this shapes only what the model sees.
    BeforePromptBuild,
    /// Before the model is asked for a reply (`cleaned_body`, `trigger`). Result
    /// `{handled: true, reply: ".."}` answers the turn without a model call.
    BeforeAgentReply,
    /// Input gate before a turn runs (`prompt`, `messages`, `system_prompt`, `channel`, `sender`).
    /// Block = the turn is answered with "Your message could not be sent: …" (fail closed).
    BeforeAgentRun,
    /// The model produced a final answer (`last_assistant_message`, `stop_hook_active`).
    /// Result `{action: "revise", retry: {instruction}}` (or block = revise with the reason)
    /// asks for another pass; at most 3 revisions per turn.
    BeforeAgentFinalize,
    /// A channel message before anything else handles it (`content`, `channel`, `chat`,
    /// `sender`, `is_group`, …). Result `{handled: true, reply}`: a hook owns this message.
    InboundClaim,
    /// A channel message is about to be dispatched to the agent (`content`, `body`, `channel`,
    /// `session_id`, `sender`, `is_group`, `timestamp`). Result `{handled: true, text}`.
    BeforeDispatch,
    /// The agent run for a channel message is about to start (`session_id`, `channel`, `chat`,
    /// `dispatch_kind` = "agent"). Result `{handled: true, text?}`: the hook delivers the reply.
    ReplyDispatch,
    /// A sub-agent run started / ended (`phase` "started"|"ended", `run_id`, `child_session`,
    /// `outcome`) or made progress (`progress` = one transcript line); observe only.
    SubagentProgress,
    /// Where a sub-agent's completion goes (`child_session`, `requester_session`,
    /// `requester_origin`, `expects_completion_message`). Result `{origin: {channel, to, thread_id}}`:
    /// the completion is also sent there (host channels).
    SubagentDeliveryTarget,
    /// A user or operator explicitly stopped a run (`source`, `actor`, `sessions`, `run_ids`);
    /// observe only. Built by [`run_stopped_payload`].
    RunStopped,
    /// A cron job changed (`action`: added|updated|removed|started|finished|scheduled, `job_id`,
    /// `job`, …); observe only. Built by [`cron_changed_payload`].
    CronChanged,
    /// The scheduler loaded its jobs (`reason`: startup|reload, `enabled`); observe only.
    CronReconciled,
    /// A skill was created / updated / removed (`action`, `source`, `before`, `after`); observe only.
    SkillChanged,
    /// A heartbeat prompt is being built (`session_id`, `heartbeat_name`). Result
    /// `{prepend_context, append_context}` or plain context.
    HeartbeatPromptContribution,
    /// A skill / plugin / hook pack is about to be installed (`target_type`, `target_name`,
    /// `source_path`, `request`, `builtin_scan`). Block (or `{block: true, block_reason}`) refuses it.
    BeforeInstall,
    /// The shell tool is about to run (`tool_name`, `host` = "local"). Result: `{NAME: value}`
    /// environment variables for that command.
    ResolveExecEnv,
    /// An unknown sender asked to pair (`channel`, `sender_id`, `code`, `metadata`); observe only.
    ChannelPairingRequested,
    /// A message is about to be written to a session log (`message`, `role`). Result: replacement
    /// `message`; block = withhold it (see kernel notes for transcript-safety limits).
    BeforeMessageWrite,
    /// A session is about to be reset (`reason`: new|reset|idle|daily|forget, `messages`); observe only.
    BeforeReset,
    /// A chat command ran (`action`: new|stop|status|help|forget, `session_id`, `sender`, `source`);
    /// observe only (OpenClaw internal `command:*` events).
    Command,
}

impl HookEvent {
    pub const ALL: [HookEvent; 53] = [
        HookEvent::SessionStart,
        HookEvent::SessionEnd,
        HookEvent::UserPrompt,
        HookEvent::PreTool,
        HookEvent::PostTool,
        HookEvent::TurnEnd,
        HookEvent::PreModel,
        HookEvent::PostModel,
        HookEvent::PreCompact,
        HookEvent::PostCompact,
        HookEvent::MessageReceived,
        HookEvent::MessageSending,
        HookEvent::MessageSent,
        HookEvent::SubagentStart,
        HookEvent::SubagentStop,
        HookEvent::SubagentDelivery,
        HookEvent::Notification,
        HookEvent::DaemonStart,
        HookEvent::DaemonStop,
        HookEvent::PreApprovalRequest,
        HookEvent::PostApprovalResponse,
        HookEvent::HumanInputRequest,
        HookEvent::HumanInputResolved,
        HookEvent::TransformToolResult,
        HookEvent::TransformTerminalOutput,
        HookEvent::TransformLlmOutput,
        HookEvent::TransformApiError,
        HookEvent::ToolRequest,
        HookEvent::ToolExecution,
        HookEvent::LlmRequest,
        HookEvent::LlmExecution,
        HookEvent::BeforeModelResolve,
        HookEvent::AgentTurnPrepare,
        HookEvent::BeforePromptBuild,
        HookEvent::BeforeAgentReply,
        HookEvent::BeforeAgentRun,
        HookEvent::BeforeAgentFinalize,
        HookEvent::InboundClaim,
        HookEvent::BeforeDispatch,
        HookEvent::ReplyDispatch,
        HookEvent::SubagentProgress,
        HookEvent::SubagentDeliveryTarget,
        HookEvent::RunStopped,
        HookEvent::CronChanged,
        HookEvent::CronReconciled,
        HookEvent::SkillChanged,
        HookEvent::HeartbeatPromptContribution,
        HookEvent::BeforeInstall,
        HookEvent::ResolveExecEnv,
        HookEvent::ChannelPairingRequested,
        HookEvent::BeforeMessageWrite,
        HookEvent::BeforeReset,
        HookEvent::Command,
    ];

    /// Middleware kinds (Hermes `register_middleware`): plugins declare them under `middleware`.
    pub fn is_middleware(self) -> bool {
        matches!(self, HookEvent::ToolRequest | HookEvent::ToolExecution | HookEvent::LlmRequest | HookEvent::LlmExecution)
    }

    /// The payload field a hook's modify replaces for the OpenClaw-style result hooks
    /// (their payload carries the hook's answer under `result`). None = observe-only or a
    /// classic event with its own field.
    pub fn result_field(self) -> Option<&'static str> {
        use HookEvent::*;
        matches!(
            self,
            BeforeModelResolve | AgentTurnPrepare | BeforePromptBuild | BeforeAgentReply | BeforeAgentFinalize | InboundClaim | BeforeDispatch | ReplyDispatch | SubagentDeliveryTarget | HeartbeatPromptContribution | BeforeInstall | ResolveExecEnv
        )
        .then_some("result")
        .or(match self {
            BeforeMessageWrite => Some("message"),
            _ => None,
        })
    }

    /// Plain-text stdout of a shell hook counts as context for these.
    fn takes_text_context(self) -> bool {
        matches!(self, HookEvent::UserPrompt | HookEvent::SessionStart | HookEvent::AgentTurnPrepare | HookEvent::BeforePromptBuild | HookEvent::HeartbeatPromptContribution)
    }

    /// Claude Code's event names, so existing hook scripts work unchanged
    /// (events Claude Code lacks get names in the same style).
    pub fn claude_name(self) -> &'static str {
        match self {
            HookEvent::SessionStart => "SessionStart",
            HookEvent::SessionEnd => "SessionEnd",
            HookEvent::UserPrompt => "UserPromptSubmit",
            HookEvent::PreTool => "PreToolUse",
            HookEvent::PostTool => "PostToolUse",
            HookEvent::TurnEnd => "Stop",
            HookEvent::PreModel => "PreModel",
            HookEvent::PostModel => "PostModel",
            HookEvent::PreCompact => "PreCompact",
            HookEvent::PostCompact => "PostCompact",
            HookEvent::MessageReceived => "MessageReceived",
            HookEvent::MessageSending => "MessageSending",
            HookEvent::MessageSent => "MessageSent",
            HookEvent::SubagentStart => "SubagentStart",
            HookEvent::SubagentStop => "SubagentStop",
            HookEvent::SubagentDelivery => "SubagentDelivery",
            HookEvent::Notification => "Notification",
            HookEvent::DaemonStart => "DaemonStart",
            HookEvent::DaemonStop => "DaemonStop",
            HookEvent::PreApprovalRequest => "PreApprovalRequest",
            HookEvent::PostApprovalResponse => "PostApprovalResponse",
            HookEvent::HumanInputRequest => "HumanInputRequest",
            HookEvent::HumanInputResolved => "HumanInputResolved",
            HookEvent::TransformToolResult => "TransformToolResult",
            HookEvent::TransformTerminalOutput => "TransformTerminalOutput",
            HookEvent::TransformLlmOutput => "TransformLlmOutput",
            HookEvent::TransformApiError => "TransformApiError",
            HookEvent::ToolRequest => "ToolRequest",
            HookEvent::ToolExecution => "ToolExecution",
            HookEvent::LlmRequest => "LlmRequest",
            HookEvent::LlmExecution => "LlmExecution",
            HookEvent::BeforeModelResolve => "BeforeModelResolve",
            HookEvent::AgentTurnPrepare => "AgentTurnPrepare",
            HookEvent::BeforePromptBuild => "BeforePromptBuild",
            HookEvent::BeforeAgentReply => "BeforeAgentReply",
            HookEvent::BeforeAgentRun => "BeforeAgentRun",
            HookEvent::BeforeAgentFinalize => "BeforeAgentFinalize",
            HookEvent::InboundClaim => "InboundClaim",
            HookEvent::BeforeDispatch => "BeforeDispatch",
            HookEvent::ReplyDispatch => "ReplyDispatch",
            HookEvent::SubagentProgress => "SubagentProgress",
            HookEvent::SubagentDeliveryTarget => "SubagentDeliveryTarget",
            HookEvent::RunStopped => "RunStopped",
            HookEvent::CronChanged => "CronChanged",
            HookEvent::CronReconciled => "CronReconciled",
            HookEvent::SkillChanged => "SkillChanged",
            HookEvent::HeartbeatPromptContribution => "HeartbeatPromptContribution",
            HookEvent::BeforeInstall => "BeforeInstall",
            HookEvent::ResolveExecEnv => "ResolveExecEnv",
            HookEvent::ChannelPairingRequested => "ChannelPairingRequested",
            HookEvent::BeforeMessageWrite => "BeforeMessageWrite",
            HookEvent::BeforeReset => "BeforeReset",
            HookEvent::Command => "Command",
        }
    }

    /// snake_case name as written in config and the plugin protocol.
    pub fn name(self) -> String {
        serde_json::to_value(self).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
    }

    /// Parse a config / plugin name, including upstream aliases
    /// (OpenClaw `before_tool_call`, Hermes `pre_llm_call`, seagent's old `inbound`/`outbound`…).
    pub fn parse(s: &str) -> Option<HookEvent> {
        let canon = match s {
            "pre_tool_call" | "before_tool_call" => "pre_tool",
            "post_tool_call" | "after_tool_call" => "post_tool",
            "on_session_start" => "session_start",
            "on_session_end" | "on_session_finalize" => "session_end",
            "pre_llm_call" | "llm_input" | "before_model_call" => "pre_model",
            "post_llm_call" | "llm_output" => "post_model",
            "before_compaction" => "pre_compact",
            "after_compaction" => "post_compact",
            "inbound" | "pre_gateway_dispatch" => "message_received",
            "outbound" | "reply_payload_sending" => "message_sending",
            "subagent_spawned" => "subagent_start",
            "subagent_ended" => "subagent_stop",
            "subagent_delivered" => "subagent_delivery",
            "agent_end" | "stop" => "turn_end",
            "user_prompt_submit" => "user_prompt",
            // OpenClaw internal hook names (`command:new`, `session:compact:before`…).
            "command:new" | "command:reset" | "command:stop" | "command" => "command",
            "session:compact:before" => "pre_compact",
            "session:compact:after" => "post_compact",
            "gateway:startup" => "daemon_start",
            "gateway_start" => "daemon_start",
            "gateway_stop" => "daemon_stop",
            "on_human_input_request" => "human_input_request",
            "on_human_input_resolved" => "human_input_resolved",
            "transform_api_error_classification" => "transform_api_error",
            other => other,
        };
        serde_json::from_value(Value::String(canon.into())).ok()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HookDecision {
    Allow,
    Block(String),
    /// Replace the tool input (pre_tool) or prompt text (user_prompt).
    Modify(Value),
    /// Extra text for the model (appended to the tool result / prompt).
    Context(String),
}

pub trait Hook: Send + Sync {
    fn name(&self) -> String;
    fn wants(&self, event: HookEvent, tool: Option<&str>) -> bool;
    /// Err = the hook itself failed; the kernel warns and carries on.
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    #[serde(deserialize_with = "de_event")]
    pub event: HookEvent,
    /// Regex on the tool name (pre/post_tool). Empty or "*" = all.
    #[serde(default)]
    pub matcher: String,
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// `event` accepts the canonical snake_case name and every upstream alias `HookEvent::parse`
/// knows (`gateway_start`/`gateway_stop`, `gateway:startup`, `pre_llm_call`, …) — otherwise a
/// config written against OpenClaw's names would be rejected while the same name works in a
/// plugin manifest.
fn de_event<'de, D>(d: D) -> Result<HookEvent, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    HookEvent::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("hook event `{s}`: use daemon_start / daemon_stop (gateway_start, gateway_stop and gateway:startup are aliases) or another lifecycle event")))
}

fn default_timeout() -> u64 {
    10
}

pub struct ShellHook {
    cfg: HookConfig,
    matcher: Option<regex::Regex>,
}

impl ShellHook {
    pub fn new(cfg: HookConfig) -> Result<Self, String> {
        let m = cfg.matcher.trim();
        let matcher = if m.is_empty() || m == "*" { None } else { Some(regex::Regex::new(&format!("^(?:{m})$")).map_err(|e| format!("hook matcher `{m}`: {e}"))?) };
        if cfg.command.trim().is_empty() {
            return Err("hook command is empty".into());
        }
        Ok(ShellHook { cfg, matcher })
    }
}

impl Hook for ShellHook {
    fn name(&self) -> String {
        format!("shell:{}", self.cfg.command.chars().take(40).collect::<String>())
    }

    fn wants(&self, event: HookEvent, tool: Option<&str>) -> bool {
        event == self.cfg.event && match (&self.matcher, tool) {
            (None, _) => true,
            (Some(r), Some(t)) => r.is_match(t),
            (Some(_), None) => false,
        }
    }

    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        let mut input = payload.clone();
        input["hook_event_name"] = event.claude_name().into();
        let cwd = payload.get("cwd").and_then(Value::as_str).filter(|c| Path::new(c).is_dir()).unwrap_or("/");
        let parent = std::process::id() as i32;
        let mut cmd = Command::new("bash");
        seagent_security::envscrub::apply(&mut cmd, seagent_security::envscrub::Surface::Hook);
        cmd.arg("-c").arg(&self.cfg.command).current_dir(cwd).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // SAFETY: async-signal-safe calls only.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || {
                libc::setpgid(0, 0);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if libc::getppid() != parent {
                    libc::_exit(137);
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("start hook: {e}"))?;
        let pgid = child.id() as i32;
        let body = input.to_string();
        let mut stdin = child.stdin.take();
        // Write from a thread: a hook that never reads stdin must not block us.
        let writer = std::thread::spawn(move || {
            if let Some(s) = stdin.as_mut() {
                let _ = s.write_all(body.as_bytes());
            }
        });
        let mut out = child.stdout.take();
        let mut err = child.stderr.take();
        let ro = std::thread::spawn(move || read_capped(out.as_mut()));
        let re = std::thread::spawn(move || read_capped(err.as_mut()));
        let deadline = Instant::now() + Duration::from_secs(self.cfg.timeout_secs.max(1));
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    unsafe { libc::kill(-pgid, libc::SIGKILL) };
                    let _ = child.wait();
                    return Err(format!("timed out after {}s", self.cfg.timeout_secs));
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        let _ = writer.join();
        let stdout = ro.join().unwrap_or_default();
        let stderr = re.join().unwrap_or_default();
        match status.code() {
            // Large context is spilled to disk with a preview (it would ride every request).
            Some(0) => Ok(match parse_stdout(event, stdout.trim()) {
                HookDecision::Context(c) => HookDecision::Context(spill::spill(&c, payload.get("session_id").and_then(Value::as_str).unwrap_or(""), "hook")),
                d => d,
            }),
            Some(2) => Ok(HookDecision::Block(if stderr.trim().is_empty() { "blocked by hook".into() } else { stderr.trim().to_string() })),
            c => Err(format!("exit {}: {}", c.map_or("signal".into(), |c| c.to_string()), stderr.trim().chars().take(300).collect::<String>())),
        }
    }
}

fn read_capped(r: Option<&mut impl Read>) -> String {
    let mut buf = Vec::new();
    if let Some(r) = r {
        let _ = r.take(64 * 1024).read_to_end(&mut buf);
        // Drain the rest so a chatty hook doesn't die of SIGPIPE.
        let _ = std::io::copy(r, &mut std::io::sink());
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn parse_stdout(event: HookEvent, s: &str) -> HookDecision {
    if s.is_empty() {
        return HookDecision::Allow;
    }
    let Ok(v) = serde_json::from_str::<Value>(s) else {
        // Plain text: context for prompt/session hooks (Claude semantics), ignored otherwise.
        return if event.takes_text_context() { HookDecision::Context(s.to_string()) } else { HookDecision::Allow };
    };
    let hso = v.get("hookSpecificOutput").unwrap_or(&Value::Null);
    let reason = v.get("reason").or_else(|| hso.get("permissionDecisionReason")).and_then(Value::as_str).unwrap_or("blocked by hook").to_string();
    let decision = v.get("decision").or_else(|| hso.get("permissionDecision")).and_then(Value::as_str).unwrap_or("");
    if matches!(decision, "block" | "deny") {
        return HookDecision::Block(reason);
    }
    if let Some(u) = v.get("updated_input").or_else(|| hso.get("updatedInput")).or_else(|| v.get("prompt").filter(|_| event == HookEvent::UserPrompt)) {
        return HookDecision::Modify(u.clone());
    }
    if let Some(c) = v.get("additional_context").or_else(|| hso.get("additionalContext")).and_then(Value::as_str) {
        return HookDecision::Context(c.to_string());
    }
    // OpenClaw-style result hooks answer with their result object.
    if event.result_field().is_some() && v.as_object().is_some_and(|o| !o.is_empty()) {
        return HookDecision::Modify(v);
    }
    HookDecision::Allow
}

// ───────────────────── result helpers (OpenClaw result contracts) ─────────────────────

/// Read a result key in snake_case or OpenClaw's camelCase.
pub fn rget<'a>(v: &'a Value, snake: &str) -> Option<&'a Value> {
    v.get(snake).or_else(|| {
        let camel: String = snake.split('_').enumerate().map(|(i, w)| if i == 0 { w.to_string() } else { w[..1].to_uppercase() + &w[1..] }).collect();
        v.get(camel)
    })
}

fn rstr(v: &Value, k: &str) -> Option<String> {
    rget(v, k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

/// `{prepend_context, append_context}` of a turn-prepare style result (a bare string = append).
pub fn context_parts(v: &Value) -> (Option<String>, Option<String>) {
    match v {
        Value::String(s) if !s.trim().is_empty() => (None, Some(s.clone())),
        Value::Object(_) => (rstr(v, "prepend_context"), rstr(v, "append_context")),
        _ => (None, None),
    }
}

/// A claim / takeover result: `Some(reply)` when `handled` is true (reply may be absent).
pub fn handled(v: &Value) -> Option<Option<String>> {
    if rget(v, "handled").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let reply = rget(v, "reply").map(|r| r.get("text").cloned().unwrap_or_else(|| r.clone())).or_else(|| rget(v, "text").cloned());
    Some(reply.and_then(|r| r.as_str().map(String::from)).filter(|s| !s.trim().is_empty()))
}

/// Environment variables from a `resolve_exec_env` result: string values with valid names only.
pub fn exec_env(v: &Value) -> Vec<(String, String)> {
    let Some(o) = v.as_object() else { return vec![] };
    o.iter()
        .filter(|(k, _)| !k.is_empty() && k.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(|(k, v)| match v {
            Value::String(s) => Some((k.clone(), s.clone())),
            Value::Number(n) => Some((k.clone(), n.to_string())),
            Value::Bool(b) => Some((k.clone(), b.to_string())),
            _ => None,
        })
        .collect()
}

/// Payload for `run_stopped` (OpenClaw `PluginHookRunStoppedEvent`): who stopped which runs.
pub fn run_stopped_payload(session: &str, cwd: &str, source: &str, actor: &str, run_id: &str) -> Value {
    json!({
        "session_id": session,
        "cwd": cwd,
        "source": source,
        "actor": actor,
        "sessions": [{"sessionKey": session}],
        "run_ids": if run_id.is_empty() { json!([]) } else { json!([run_id]) },
    })
}

/// Fire `run_stopped` (observe only; a hook can never block an explicit Stop).
pub fn fire_run_stopped(rt: &crate::kernel::Runtime, session: &str, cwd: &str, source: &str, actor: &str, run_id: &str) {
    rt.emit(HookEvent::RunStopped, run_stopped_payload(session, cwd, source, actor, run_id), "");
}

/// Payload for `cron_changed` (OpenClaw `PluginHookCronChangedEvent`). `action` is one of
/// added | updated | removed | started | finished | scheduled; `extra` carries the optional
/// fields (`run_at_ms`, `duration_ms`, `status`, `error`, `summary`, `session_id`, `next_run_at_ms`,
/// `model`, `delivered`…) and is merged in as given.
pub fn cron_changed_payload(action: &str, job_id: &str, job: Option<&Value>, extra: Value) -> Value {
    let mut p = json!({"session_id": "", "cwd": "", "action": action, "job_id": job_id});
    if let Some(j) = job {
        p["job"] = j.clone();
        for k in ["session_target", "agent_id"] {
            if let Some(v) = j.get(k) {
                p[k] = v.clone();
            }
        }
    }
    if let (Value::Object(m), Some(o)) = (extra, p.as_object_mut()) {
        o.extend(m);
    }
    p
}

/// Payload for `cron_reconciled`: `reason` is "startup" or "reload".
pub fn cron_reconciled_payload(reason: &str, enabled: bool, jobs: usize) -> Value {
    json!({"session_id": "", "cwd": "", "reason": reason, "enabled": enabled, "jobs": jobs})
}

/// Fire `cron_changed` (observe only).
pub fn fire_cron_changed(rt: &crate::kernel::Runtime, payload: Value) {
    rt.emit(HookEvent::CronChanged, payload, "");
}

/// Fire `cron_reconciled` (observe only).
pub fn fire_cron_reconciled(rt: &crate::kernel::Runtime, reason: &str, enabled: bool, jobs: usize) {
    rt.emit(HookEvent::CronReconciled, cron_reconciled_payload(reason, enabled, jobs), "");
}

/// Payload for `heartbeat_prompt_contribution`.
pub fn heartbeat_payload(session: &str, cwd: &str, heartbeat_name: &str) -> Value {
    json!({"session_id": session, "cwd": cwd, "heartbeat_name": heartbeat_name, "result": Value::Null})
}

/// Ask `heartbeat_prompt_contribution` hooks for context and wrap `prompt` with it
/// (prepend + prompt + append, blank-line separated). Unchanged when no hook answers.
pub fn heartbeat_prompt(rt: &crate::kernel::Runtime, session: &str, cwd: &str, heartbeat_name: &str, prompt: &str) -> String {
    let (pre, post) = heartbeat_contribution(rt, session, cwd, heartbeat_name);
    let mut out = String::new();
    if let Some(p) = pre {
        out.push_str(&p);
        out.push_str("\n\n");
    }
    out.push_str(prompt);
    if let Some(a) = post {
        out.push_str("\n\n");
        out.push_str(&a);
    }
    out
}

/// The (prepend, append) context `heartbeat_prompt_contribution` hooks contribute.
pub fn heartbeat_contribution(rt: &crate::kernel::Runtime, session: &str, cwd: &str, heartbeat_name: &str) -> (Option<String>, Option<String>) {
    let ev = HookEvent::HeartbeatPromptContribution;
    if !rt.has_hooks(ev) {
        return (None, None);
    }
    let (pre, post, ctx) = rt.emit_collect(ev, heartbeat_payload(session, cwd, heartbeat_name));
    let join = |v: Vec<String>| (!v.is_empty()).then(|| v.join("\n\n"));
    let mut post = post;
    post.extend(ctx);
    (join(pre), join(post))
}

pub fn shell_hooks(cfgs: &[HookConfig]) -> Result<Vec<std::sync::Arc<dyn Hook>>, String> {
    cfgs.iter().map(|c| ShellHook::new(c.clone()).map(|h| std::sync::Arc::new(h) as std::sync::Arc<dyn Hook>)).collect()
}

/// Standard payload shape shared by shell and plugin hooks.
pub fn payload(session: &str, cwd: &str, tool: Option<&str>, input: Option<&Value>, response: Option<&Value>, prompt: Option<&str>) -> Value {
    let mut v = json!({"session_id": session, "cwd": cwd});
    if let Some(t) = tool {
        v["tool_name"] = t.into();
    }
    if let Some(i) = input {
        v["tool_input"] = i.clone();
    }
    if let Some(r) = response {
        v["tool_response"] = r.clone();
    }
    if let Some(p) = prompt {
        v["prompt"] = p.into();
    }
    v
}

// ───────────────────────── self-registration ─────────────────────────

use crate::kernel::Kernel;
use std::sync::{Arc, RwLock};

/// A subsystem's hooks, as a factory over a built kernel (it needs `paths`, the config and the
/// bus). Same idea as `seagent_core::registry` for tools: the owner declares the hook, the binary
/// only says which crates are part of this build (audit D1). This table lives here, not in
/// `seagent_core`, because [`Hook`] is a kernel type.
///
/// The hooks one subsystem installs on a built kernel.
pub type HookFactory = fn(&Kernel) -> Result<Vec<Arc<dyn Hook>>, String>;

#[derive(Clone)]
pub struct HookProvider {
    pub name: &'static str,
    pub order: i32,
    pub factory: HookFactory,
}

static PROVIDERS: RwLock<Vec<HookProvider>> = RwLock::new(Vec::new());

/// Declare a hook provider. Idempotent per `name` (the last registration wins), so calling a
/// subsystem's `register()` twice cannot install a hook twice.
pub fn register_provider(name: &'static str, order: i32, factory: HookFactory) {
    let mut g = PROVIDERS.write().unwrap();
    g.retain(|p| p.name != name);
    g.push(HookProvider { name, order, factory });
    g.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(b.name)));
}

/// Names of the registered providers, in install order (tests / `seagent doctor`).
pub fn registered_providers() -> Vec<&'static str> {
    PROVIDERS.read().unwrap().iter().map(|p| p.name).collect()
}

/// Install every registered provider on `k`; a provider that fails is a warning (the rest of
/// the session keeps working). Returns the warnings for the caller to print.
pub fn install_all(k: &Kernel) -> Vec<String> {
    let provs = PROVIDERS.read().unwrap().clone();
    let mut warnings = Vec::new();
    for p in provs {
        match (p.factory)(k) {
            Ok(hooks) => k.add_hooks(hooks),
            Err(e) => warnings.push(format!("{}: {e}", p.name)),
        }
    }
    warnings
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use crate::config::{Config, Paths};

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider `{id}` in this test"))
        }
    }

    struct Noop(&'static str);
    impl Hook for Noop {
        fn name(&self) -> String {
            self.0.to_string()
        }
        fn wants(&self, _: HookEvent, _: Option<&str>) -> bool {
            false
        }
        fn run(&self, _: HookEvent, _: &Value) -> Result<HookDecision, String> {
            Ok(HookDecision::Allow)
        }
    }

    fn kernel() -> (Kernel, seagent_core::tmp::TempDir) {
        let dir = seagent_core::tmp::TempDir::new("seagent-hooks-provider");
        let paths = Paths { data: dir.join("data"), config_dir: dir.join("cfg"), runtime: dir.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let k = crate::kernel::new_kernel(Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }));
        (k, dir)
    }

    /// Providers are ordered, idempotent, and a failing one is a warning: a hook subsystem that
    /// cannot start (no manager, bad config) must not stop the session's other hooks.
    #[test]
    fn providers_install_in_order_and_a_failure_is_a_warning() {
        let (k, dir) = kernel();
        fn late(_: &Kernel) -> Result<Vec<Arc<dyn Hook>>, String> {
            Ok(vec![Arc::new(Noop("z-late"))])
        }
        fn early(_: &Kernel) -> Result<Vec<Arc<dyn Hook>>, String> {
            Ok(vec![Arc::new(Noop("a-early"))])
        }
        fn broken(_: &Kernel) -> Result<Vec<Arc<dyn Hook>>, String> {
            Err("no meeting manager".into())
        }
        register_provider("zz-late", 900, late);
        register_provider("aa-early", 100, early);
        register_provider("mm-broken", 500, broken);
        register_provider("aa-early", 100, early); // twice: still one entry
        let names = registered_providers();
        assert_eq!(names.iter().filter(|n| **n == "aa-early").count(), 1, "{names:?}");
        assert!(names.windows(2).all(|w| w[0] <= w[1]), "providers are sorted by name within an order: {names:?}");
        let warnings = install_all(&k);
        assert_eq!(warnings, ["mm-broken: no meeting manager"]);
        let installed = k.hook_names();
        assert!(installed.contains(&"a-early".to_string()) && installed.contains(&"z-late".to_string()), "{installed:?}");
        // Installing again does not duplicate (the caller may re-attach a kernel in tests).
        install_all(&k);
        assert_eq!(k.hook_names().iter().filter(|n| *n == "a-early").count(), 2, "one per install; the registered table itself has one entry");
        drop(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(event: HookEvent, matcher: &str, cmd: &str) -> ShellHook {
        ShellHook::new(HookConfig { event, matcher: matcher.into(), command: cmd.into(), timeout_secs: 2 }).unwrap()
    }
    fn p() -> Value {
        payload("s1", "/tmp", Some("shell"), Some(&json!({"command": "ls"})), None, None)
    }

    #[test]
    fn oversized_context_is_spilled_with_a_preview() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-hookspill-{}", crate::util::random_hex(6)));
        spill::configure(spill::SpillConfig { directory: d.display().to_string(), ..Default::default() });
        let h = hook(HookEvent::UserPrompt, "", "head -c 30000 /dev/zero | tr '\\0' a; echo END");
        let HookDecision::Context(c) = h.run(HookEvent::UserPrompt, &p()).unwrap() else { panic!("context expected") };
        assert!(c.starts_with("[hook output truncated — 30003 chars; full content saved to ") && c.len() < 1200, "{}", &c[..200.min(c.len())]);
        assert!(c.ends_with("aaaEND"), "tail preview");
        let saved: Vec<_> = std::fs::read_dir(d.join("s1")).unwrap().collect();
        assert_eq!(saved.len(), 1);
        let h = hook(HookEvent::UserPrompt, "", r#"echo '{"additional_context":"small"}'"#);
        assert_eq!(h.run(HookEvent::UserPrompt, &p()).unwrap(), HookDecision::Context("small".into()));
        spill::configure(spill::SpillConfig::default());
    }

    #[test]
    fn matcher_and_event_filtering() {
        let h = hook(HookEvent::PreTool, "shell|write", "true");
        assert!(h.wants(HookEvent::PreTool, Some("shell")));
        assert!(!h.wants(HookEvent::PreTool, Some("shellx")), "anchored");
        assert!(!h.wants(HookEvent::PostTool, Some("shell")));
        assert!(!h.wants(HookEvent::PreTool, None));
        assert!(hook(HookEvent::TurnEnd, "", "true").wants(HookEvent::TurnEnd, None));
        assert!(ShellHook::new(HookConfig { event: HookEvent::PreTool, matcher: "(".into(), command: "x".into(), timeout_secs: 1 }).is_err());
        assert!(ShellHook::new(HookConfig { event: HookEvent::PreTool, matcher: "".into(), command: " ".into(), timeout_secs: 1 }).is_err());
    }

    #[test]
    fn exit_codes_and_json_outputs() {
        assert_eq!(hook(HookEvent::PreTool, "", "cat >/dev/null").run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Allow);
        assert_eq!(hook(HookEvent::PreTool, "", "echo nope >&2; exit 2").run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Block("nope".into()));
        // Sees the payload with Claude's event name.
        let h = hook(HookEvent::PreTool, "", r#"x=$(cat); echo "$x" | grep -q '"hook_event_name":"PreToolUse"' && echo "$x" | grep -q '"command":"ls"' || exit 2"#);
        assert_eq!(h.run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Allow);
        let h = hook(HookEvent::PreTool, "", r#"echo '{"decision":"block","reason":"no ls"}'"#);
        assert_eq!(h.run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Block("no ls".into()));
        let h = hook(HookEvent::PreTool, "", r#"echo '{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"ls -la"}}}'"#);
        assert_eq!(h.run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Modify(json!({"command": "ls -la"})));
        let h = hook(HookEvent::UserPrompt, "", "echo remember the tests");
        assert_eq!(h.run(HookEvent::UserPrompt, &p()).unwrap(), HookDecision::Context("remember the tests".into()));
        assert_eq!(hook(HookEvent::PostTool, "", "echo not json").run(HookEvent::PostTool, &p()).unwrap(), HookDecision::Allow);
    }

    #[test]
    fn event_names_round_trip_and_upstream_aliases() {
        for e in HookEvent::ALL {
            assert_eq!(HookEvent::parse(&e.name()), Some(e));
        }
        assert_eq!(HookEvent::parse("before_tool_call"), Some(HookEvent::PreTool));
        assert_eq!(HookEvent::parse("pre_llm_call"), Some(HookEvent::PreModel));
        assert_eq!(HookEvent::parse("inbound"), Some(HookEvent::MessageReceived));
        assert_eq!(HookEvent::parse("before_compaction"), Some(HookEvent::PreCompact));
        assert_eq!(HookEvent::parse("transform_api_error_classification"), Some(HookEvent::TransformApiError));
        assert_eq!(HookEvent::parse("pre_approval_request"), Some(HookEvent::PreApprovalRequest));
        assert!(HookEvent::ToolExecution.is_middleware() && !HookEvent::PreTool.is_middleware());
        assert_eq!(HookEvent::parse("nope"), None);
        let h: HookConfig = toml::from_str("event = \"pre_compact\"\ncommand = \"true\"").unwrap();
        assert_eq!(h.event, HookEvent::PreCompact);
        // A config may use the upstream names, not only seagent's canonical snake_case ones.
        for (name, want) in [("gateway_start", HookEvent::DaemonStart), ("gateway_stop", HookEvent::DaemonStop), ("gateway:startup", HookEvent::DaemonStart), ("pre_llm_call", HookEvent::PreModel), ("before_tool_call", HookEvent::PreTool)] {
            let h: HookConfig = toml::from_str(&format!("event = \"{name}\"\ncommand = \"true\"")).unwrap_or_else(|e| panic!("`{name}` is refused: {e}"));
            assert_eq!(h.event, want, "{name}");
        }
        let e = toml::from_str::<HookConfig>("event = \"gateway_launch\"\ncommand = \"true\"").unwrap_err().to_string();
        assert!(e.contains("hook event `gateway_launch`"), "{e}");
    }

    #[test]
    fn openclaw_hook_points_have_their_own_events() {
        for (name, e) in [
            ("before_model_resolve", HookEvent::BeforeModelResolve),
            ("agent_turn_prepare", HookEvent::AgentTurnPrepare),
            ("before_prompt_build", HookEvent::BeforePromptBuild),
            ("before_agent_reply", HookEvent::BeforeAgentReply),
            ("before_agent_run", HookEvent::BeforeAgentRun),
            ("before_agent_finalize", HookEvent::BeforeAgentFinalize),
            ("inbound_claim", HookEvent::InboundClaim),
            ("before_dispatch", HookEvent::BeforeDispatch),
            ("reply_dispatch", HookEvent::ReplyDispatch),
            ("subagent_progress", HookEvent::SubagentProgress),
            ("subagent_delivery_target", HookEvent::SubagentDeliveryTarget),
            ("gateway_stop", HookEvent::DaemonStop),
            ("cron_changed", HookEvent::CronChanged),
            ("cron_reconciled", HookEvent::CronReconciled),
            ("skill_changed", HookEvent::SkillChanged),
            ("heartbeat_prompt_contribution", HookEvent::HeartbeatPromptContribution),
            ("before_install", HookEvent::BeforeInstall),
            ("resolve_exec_env", HookEvent::ResolveExecEnv),
            ("channel_pairing_requested", HookEvent::ChannelPairingRequested),
            ("before_message_write", HookEvent::BeforeMessageWrite),
            ("before_reset", HookEvent::BeforeReset),
            ("command:new", HookEvent::Command),
            ("session:compact:before", HookEvent::PreCompact),
        ] {
            assert_eq!(HookEvent::parse(name), Some(e), "{name}");
        }
        // before_prompt_build no longer aliases user_prompt (different semantics).
        assert_ne!(HookEvent::parse("before_prompt_build"), Some(HookEvent::UserPrompt));
        assert_eq!(HookEvent::BeforeModelResolve.result_field(), Some("result"));
        assert_eq!(HookEvent::BeforeMessageWrite.result_field(), Some("message"));
        assert_eq!(HookEvent::CronChanged.result_field(), None);
    }

    #[test]
    fn shell_hooks_answer_result_hooks_with_objects_or_text() {
        let h = hook(HookEvent::InboundClaim, "", r#"echo '{"handled":true,"reply":"got it"}'"#);
        let d = h.run(HookEvent::InboundClaim, &p()).unwrap();
        assert_eq!(d, HookDecision::Modify(json!({"handled": true, "reply": "got it"})));
        let HookDecision::Modify(v) = d else { unreachable!() };
        assert_eq!(handled(&v), Some(Some("got it".into())));
        assert_eq!(hook(HookEvent::AgentTurnPrepare, "", "echo be terse").run(HookEvent::AgentTurnPrepare, &p()).unwrap(), HookDecision::Context("be terse".into()));
        assert_eq!(hook(HookEvent::CronChanged, "", r#"echo '{"x":1}'"#).run(HookEvent::CronChanged, &p()).unwrap(), HookDecision::Allow, "observe-only");
    }

    #[test]
    fn result_helpers() {
        assert_eq!(context_parts(&json!({"prependContext": "a", "append_context": " "})), (Some("a".into()), None));
        assert_eq!(context_parts(&json!("tail")), (None, Some("tail".into())));
        assert_eq!(handled(&json!({"handled": false, "reply": "x"})), None);
        assert_eq!(handled(&json!({"handled": true})), Some(None));
        assert_eq!(handled(&json!({"handled": true, "text": "t"})), Some(Some("t".into())));
        assert_eq!(exec_env(&json!({"A_1": "x", "1A": "y", "B": true, "C": {"no": 1}, "a-b": "z"})), vec![("A_1".into(), "x".into()), ("B".into(), "true".into())]);
        let c = cron_changed_payload("finished", "j1", Some(&json!({"id": "j1", "session_target": "isolated"})), json!({"status": "ok", "duration_ms": 12}));
        assert_eq!((c["action"].as_str(), c["job_id"].as_str(), c["session_target"].as_str(), c["status"].as_str(), c["duration_ms"].as_u64()), (Some("finished"), Some("j1"), Some("isolated"), Some("ok"), Some(12)));
        assert_eq!(cron_reconciled_payload("startup", true, 3)["jobs"], 3);
        assert_eq!(heartbeat_payload("s", "/w", "daily")["heartbeat_name"], "daily");
    }

    #[test]
    fn broken_hooks_are_errors_not_decisions() {
        assert!(hook(HookEvent::PreTool, "", "exit 1").run(HookEvent::PreTool, &p()).unwrap_err().contains("exit 1"));
        let t = Instant::now();
        assert!(hook(HookEvent::PreTool, "", "sleep 30").run(HookEvent::PreTool, &p()).unwrap_err().contains("timed out"));
        assert!(t.elapsed() < Duration::from_secs(5), "killed promptly");
        // Never reads stdin, produces lots of output: must not deadlock.
        let h = hook(HookEvent::PreTool, "", "head -c 200000 /dev/zero | tr '\\0' x");
        assert_eq!(h.run(HookEvent::PreTool, &p()).unwrap(), HookDecision::Allow);
    }
}
