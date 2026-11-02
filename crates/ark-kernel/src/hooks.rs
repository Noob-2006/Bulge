//! Lifecycle hooks. The kernel only knows the `Hook` trait; shell hooks
//! (Claude Code–compatible) live here, plugin hooks come from ark-plugin.
//!
//! Shell hook protocol: the event is written as JSON to stdin
//! (`hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`,
//! `tool_response`, `prompt`). Exit 0 = allow (stdout may be JSON:
//! `{"decision":"block","reason":..}`, `{"updated_input":{..}}`,
//! `{"additional_context":".."}`, or Claude's `hookSpecificOutput` form);
//! exit 2 = block with stderr as the reason; anything else = hook broken,
//! warn and allow. A hook can never take the session down.

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
    /// Middleware: rewrite the model request (`request`, an ark ModelRequest).
    LlmRequest,
    /// Middleware: `phase` "call" — set `response` to answer without calling the provider;
    /// `phase` "result" — replace `response`.
    LlmExecution,
}

impl HookEvent {
    pub const ALL: [HookEvent; 30] = [
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
    ];

    /// Middleware kinds (Hermes `register_middleware`): plugins declare them under `middleware`.
    pub fn is_middleware(self) -> bool {
        matches!(self, HookEvent::ToolRequest | HookEvent::ToolExecution | HookEvent::LlmRequest | HookEvent::LlmExecution)
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
        }
    }

    /// snake_case name as written in config and the plugin protocol.
    pub fn name(self) -> String {
        serde_json::to_value(self).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
    }

    /// Parse a config / plugin name, including upstream aliases
    /// (OpenClaw `before_tool_call`, Hermes `pre_llm_call`, ark's old `inbound`/`outbound`…).
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
            "inbound" | "pre_gateway_dispatch" | "before_dispatch" => "message_received",
            "outbound" | "reply_payload_sending" => "message_sending",
            "subagent_spawned" => "subagent_start",
            "subagent_ended" => "subagent_stop",
            "agent_end" | "stop" => "turn_end",
            "user_prompt_submit" | "before_prompt_build" => "user_prompt",
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
    pub event: HookEvent,
    /// Regex on the tool name (pre/post_tool). Empty or "*" = all.
    #[serde(default)]
    pub matcher: String,
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
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
            Some(0) => Ok(parse_stdout(event, stdout.trim())),
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
        return match event {
            HookEvent::UserPrompt | HookEvent::SessionStart => HookDecision::Context(s.chars().take(4000).collect()),
            _ => HookDecision::Allow,
        };
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
    HookDecision::Allow
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
