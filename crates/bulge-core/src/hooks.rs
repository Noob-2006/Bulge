//! Lifecycle hooks: user-defined logic that runs around every tool call.
//!
//! A `PreToolUse` hook can **block** a call (deterministic policy by code) or
//! **rewrite** its arguments before it runs; a `PostToolUse` hook can inspect
//! the result and **inject extra context** back to the model. Hooks are declared
//! in `~/.bulge/hooks.json`, mirroring the Claude Code / Hermes hook model so a
//! user's existing hook knowledge transfers.
//!
//! Two kinds of action:
//!   * declarative (`deny` / `allow`) — pure, in-process, no host execution; the
//!     safe way to enforce a policy the VM sandbox would otherwise permit.
//!   * `command` — runs a shell command **on the host, outside the sandbox**. It
//!     is a trusted extension the user installs themselves (exactly like an MCP
//!     server): bulge only runs it because the user wrote it into their own
//!     `hooks.json`. The tool call is passed as JSON on stdin; the command's
//!     stdout (JSON) decides allow/deny and may inject context or rewrite args.
//!
//! The whole thing is wired in as a [`HookedDispatcher`] that wraps any
//! [`ToolDispatcher`], so it composes with the VM and MCP dispatchers without
//! touching the driver loop.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::dispatch::{ToolCall, ToolDispatcher};
use crate::schedule::CallOutcome;

/// When a hook fires, relative to the tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HookEvent {
    /// Before the call runs: may block it or rewrite its arguments.
    PreToolUse,
    /// After the call runs: may inject extra context into the result.
    PostToolUse,
}

/// Default timeout for a `command` hook, in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// One action within a matcher group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HookAction {
    /// Block the call (PreToolUse only). `when`, if set, is a glob matched
    /// against the call's primary resource (path / command / domain); absent
    /// means "always".
    Deny {
        #[serde(default)]
        reason: String,
        #[serde(default)]
        when: Option<String>,
    },
    /// Short-circuit: stop evaluating further actions and allow the call. Useful
    /// to carve an exception ahead of a broad `deny`.
    Allow {
        #[serde(default)]
        when: Option<String>,
    },
    /// Run a host command. stdin receives the hook payload as JSON; stdout, if it
    /// parses as a [`CommandReply`], drives the decision.
    Command {
        command: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
}

/// A group of actions that apply to tools matching `matcher`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatcherGroup {
    /// Tool-name matcher: `*` / empty = all; otherwise a `|`-separated list of
    /// exact tool names (e.g. `"write|edit|exec"`).
    #[serde(default)]
    pub matcher: String,
    pub hooks: Vec<HookAction>,
}

impl MatcherGroup {
    fn applies_to(&self, tool: &str) -> bool {
        let m = self.matcher.trim();
        if m.is_empty() || m == "*" {
            return true;
        }
        m.split('|').map(str::trim).any(|name| name == tool)
    }
}

/// The parsed `~/.bulge/hooks.json`. Missing file → empty (no hooks).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HookConfig {
    #[serde(default)]
    pub hooks: BTreeMap<HookEvent, Vec<MatcherGroup>>,
}

impl HookConfig {
    /// Load from a JSON file. A missing file is not an error (returns empty).
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("read {}: {e}", path.display())),
        }
    }

    /// Parse config text. Accepts either `{ "hooks": { ... } }` or the bare
    /// `{ "PreToolUse": [...], ... }` map at top level.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(text).map_err(|e| format!("parse hooks.json: {e}"))?;
        // Bare map form: no `hooks` key but event keys present.
        if value.get("hooks").is_none()
            && value.get("PreToolUse").is_some_and(Value::is_array).then_some(()).or_else(|| value.get("PostToolUse").is_some_and(Value::is_array).then_some(())).is_some()
        {
            let hooks: BTreeMap<HookEvent, Vec<MatcherGroup>> = serde_json::from_value(value).map_err(|e| format!("parse hooks: {e}"))?;
            return Ok(Self { hooks });
        }
        serde_json::from_value(value).map_err(|e| format!("parse hooks.json: {e}"))
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.values().all(Vec::is_empty)
    }
}

/// What a `command` hook may answer on stdout (JSON). All fields optional.
#[derive(Debug, Clone, Default, Deserialize)]
struct CommandReply {
    /// `"allow"` | `"deny"` | `"continue"`. Absent → decided by exit code.
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    /// Extra text to surface to the model (appended to the tool result).
    #[serde(default)]
    context: Option<String>,
    /// Replacement arguments for the call (PreToolUse only).
    #[serde(default)]
    arguments: Option<Map<String, Value>>,
}

/// The outcome of running the hooks for one event.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookDecision {
    /// `Some(reason)` → block the call and show the reason to the model.
    pub block: Option<String>,
    /// Context lines to append to the tool result.
    pub inject: Vec<String>,
    /// Rewritten arguments for the call (PreToolUse), if a hook supplied them.
    pub rewrite: Option<Map<String, Value>>,
}

/// Compiled hooks, ready to evaluate per call.
#[derive(Debug, Clone, Default)]
pub struct HookRunner {
    config: HookConfig,
}

impl HookRunner {
    pub fn new(config: HookConfig) -> Self {
        Self { config }
    }

    pub fn is_empty(&self) -> bool {
        self.config.is_empty()
    }

    /// Whether any hook (of any event) matches this tool name — lets the caller
    /// skip the whole machinery for unhooked tools.
    pub fn matches(&self, tool: &str) -> bool {
        self.config.hooks.values().flatten().any(|g| g.applies_to(tool))
    }

    /// Evaluate `PreToolUse` hooks for a call. Declarative actions run in order
    /// (first decisive one wins); command hooks run in order and can block,
    /// inject, or rewrite.
    pub async fn pre(&self, tool: &str, arguments: &Map<String, Value>, cancel: &CancellationToken) -> HookDecision {
        self.run_event(HookEvent::PreToolUse, tool, arguments, None, cancel).await
    }

    /// Evaluate `PostToolUse` hooks. These never block; they may inject context.
    pub async fn post(&self, tool: &str, arguments: &Map<String, Value>, result: &str, cancel: &CancellationToken) -> HookDecision {
        self.run_event(HookEvent::PostToolUse, tool, arguments, Some(result), cancel).await
    }

    async fn run_event(&self, event: HookEvent, tool: &str, arguments: &Map<String, Value>, result: Option<&str>, cancel: &CancellationToken) -> HookDecision {
        let mut decision = HookDecision::default();
        let Some(groups) = self.config.hooks.get(&event) else {
            return decision;
        };
        let resource = primary_resource(tool, arguments);
        for group in groups.iter().filter(|g| g.applies_to(tool)) {
            for action in &group.hooks {
                match action {
                    HookAction::Deny { reason, when } => {
                        if event == HookEvent::PreToolUse && when_matches(when.as_deref(), &resource) {
                            decision.block = Some(if reason.trim().is_empty() { format!("blocked by hook: {tool}") } else { reason.clone() });
                            return decision;
                        }
                    }
                    HookAction::Allow { when } => {
                        if when_matches(when.as_deref(), &resource) {
                            return decision;
                        }
                    }
                    HookAction::Command { command, timeout_ms } => {
                        let payload = hook_payload(event, tool, arguments, result);
                        let reply = run_command_hook(command, &payload, timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS), cancel).await;
                        if let Some(ctx) = reply.context.filter(|c| !c.trim().is_empty()) {
                            decision.inject.push(ctx);
                        }
                        if event == HookEvent::PreToolUse {
                            if let Some(args) = reply.arguments {
                                decision.rewrite = Some(args);
                            }
                            match reply.action.as_deref() {
                                Some("deny") => {
                                    decision.block = Some(reply.reason.filter(|r| !r.trim().is_empty()).unwrap_or_else(|| format!("blocked by hook: {tool}")));
                                    return decision;
                                }
                                Some("allow") => return decision,
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        decision
    }
}

/// Glob match for a `when` clause: `None` → always matches.
fn when_matches(when: Option<&str>, resource: &str) -> bool {
    match when {
        None => true,
        Some(pat) => bulge_guard::wildcard::matches(resource, pat),
    }
}

/// The primary resource string a `when` clause matches against — mirrors the
/// driver's permission resource: the path for file tools, the command for
/// `exec`, otherwise empty.
fn primary_resource(tool: &str, arguments: &Map<String, Value>) -> String {
    let field = match tool {
        "exec" => "command",
        _ => "path",
    };
    arguments.get(field).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The JSON payload handed to a `command` hook on stdin.
fn hook_payload(event: HookEvent, tool: &str, arguments: &Map<String, Value>, result: Option<&str>) -> Value {
    let mut obj = json!({
        "event": event,
        "tool": tool,
        "arguments": Value::Object(arguments.clone()),
    });
    if let Some(r) = result {
        obj["result"] = Value::String(r.to_string());
    }
    obj
}

/// Run a host command hook: spawn `sh -c <command>`, write `payload` to stdin,
/// read stdout within `timeout_ms`. A clean JSON stdout becomes the reply; a
/// non-JSON stdout on a zero exit is treated as injected context; a non-zero
/// exit (or timeout) blocks the call with stderr as the reason.
async fn run_command_hook(command: &str, payload: &Value, timeout_ms: u64, cancel: &CancellationToken) -> CommandReply {
    let deny = |reason: String| CommandReply { action: Some("deny".into()), reason: Some(reason), ..Default::default() };

    let mut child = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A hook that outlives its timeout or a cancel is killed, not leaked.
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return deny(format!("hook failed to start: {e}")),
    };

    // Feed stdin concurrently with waiting, all under the timeout: a payload
    // larger than the pipe buffer would otherwise block forever on a hook that
    // never reads its input. A hook that exits without reading is fine.
    let stdin = child.stdin.take();
    let bytes = serde_json::to_vec(payload).unwrap_or_default();
    let feed = async move {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        }
    };
    let wait = async move { tokio::join!(feed, child.wait_with_output()).1 };
    let output = tokio::select! {
        _ = cancel.cancelled() => return deny("hook cancelled".into()),
        r = tokio::time::timeout(Duration::from_millis(timeout_ms), wait) => r,
    };

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return deny(format!("hook error: {e}")),
        Err(_) => return deny(format!("hook timed out after {timeout_ms} ms")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_trim = stdout.trim();
    if let Ok(reply) = serde_json::from_str::<CommandReply>(stdout_trim)
        && stdout_trim.starts_with('{')
    {
        return reply;
    }

    if output.status.success() {
        // Plain-text stdout becomes injected context (nothing to block on).
        CommandReply { context: (!stdout_trim.is_empty()).then(|| stdout_trim.to_string()), ..Default::default() }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = if stderr.trim().is_empty() { "hook exited non-zero".to_string() } else { stderr.trim().to_string() };
        deny(reason)
    }
}

/// Append injected context lines to a tool result value, preserving its shape.
fn inject_into(outcome: CallOutcome, inject: &[String]) -> CallOutcome {
    if inject.is_empty() {
        return outcome;
    }
    let note = format!("\n\n[hook] {}", inject.join("\n[hook] "));
    match outcome {
        CallOutcome::Ok(Value::String(s)) => CallOutcome::Ok(Value::String(format!("{s}{note}"))),
        CallOutcome::Ok(Value::Object(mut map)) => {
            // Append to a text-ish field if present, else add a `hook_context` key.
            if let Some(Value::String(s)) = map.get_mut("output") {
                s.push_str(&note);
            } else if let Some(Value::String(s)) = map.get_mut("stdout") {
                s.push_str(&note);
            } else {
                map.insert("hook_context".into(), Value::String(inject.join("\n")));
            }
            CallOutcome::Ok(Value::Object(map))
        }
        CallOutcome::Ok(other) => CallOutcome::Ok(json!({ "result": other, "hook_context": inject.join("\n") })),
        other => other,
    }
}

/// A [`ToolDispatcher`] that runs lifecycle hooks around an inner dispatcher.
pub struct HookedDispatcher {
    inner: Arc<dyn ToolDispatcher>,
    runner: Arc<HookRunner>,
}

impl HookedDispatcher {
    /// Wrap `inner`. When the runner has no hooks this is a thin pass-through, so
    /// callers can wrap unconditionally.
    pub fn new(inner: Arc<dyn ToolDispatcher>, runner: Arc<HookRunner>) -> Self {
        Self { inner, runner }
    }
}

impl ToolDispatcher for HookedDispatcher {
    fn dispatch(&self, call: ToolCall, cancel: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        let inner = self.inner.clone();
        let runner = self.runner.clone();
        Box::pin(async move {
            if !runner.matches(&call.name) {
                return inner.dispatch(call, cancel).await;
            }
            let pre = runner.pre(&call.name, &call.arguments, &cancel).await;
            if let Some(reason) = pre.block {
                return CallOutcome::Err { code: "blocked_by_hook".into(), message: reason };
            }
            let mut call = call;
            if let Some(args) = pre.rewrite {
                call.arguments = args;
            }
            let arguments = call.arguments.clone();
            let name = call.name.clone();
            let outcome = inner.dispatch(call, cancel.clone()).await;

            // PostToolUse only observes successful results.
            let mut inject = pre.inject;
            if let CallOutcome::Ok(ref value) = outcome {
                let result_text = match value {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let post = runner.post(&name, &arguments, &result_text, &cancel).await;
                inject.extend(post.inject);
            }
            inject_into(outcome, &inject)
        })
    }

    fn concurrency_safe(&self, name: &str) -> bool {
        // A hooked tool may have side-effecting command hooks; keep ordering by
        // treating it as a barrier. Unhooked tools defer to the inner dispatcher.
        if self.runner.matches(name) {
            false
        } else {
            self.inner.concurrency_safe(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
    }

    #[test]
    fn parse_wrapped_and_bare_forms() {
        let wrapped = r#"{"hooks":{"PreToolUse":[{"matcher":"exec","hooks":[{"type":"deny","reason":"no"}]}]}}"#;
        let bare = r#"{"PreToolUse":[{"matcher":"exec","hooks":[{"type":"deny","reason":"no"}]}]}"#;
        let a = HookConfig::parse(wrapped).unwrap();
        let b = HookConfig::parse(bare).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn missing_file_is_empty() {
        let cfg = HookConfig::load(Path::new("/no/such/hooks.json")).unwrap();
        assert!(cfg.is_empty());
    }

    #[test]
    fn matcher_pipe_list() {
        let g = MatcherGroup { matcher: "write|edit".into(), hooks: vec![] };
        assert!(g.applies_to("write"));
        assert!(g.applies_to("edit"));
        assert!(!g.applies_to("read"));
        let all = MatcherGroup { matcher: "*".into(), hooks: vec![] };
        assert!(all.applies_to("anything"));
    }

    #[tokio::test]
    async fn declarative_deny_blocks_with_when() {
        let cfg = HookConfig::parse(r#"{"PreToolUse":[{"matcher":"exec","hooks":[{"type":"deny","reason":"git push is manual","when":"git push*"}]}]}"#).unwrap();
        let runner = HookRunner::new(cfg);
        let token = CancellationToken::new();
        let blocked = runner.pre("exec", &args(&[("command", "git push origin main")]), &token).await;
        assert_eq!(blocked.block.as_deref(), Some("git push is manual"));
        let ok = runner.pre("exec", &args(&[("command", "git status")]), &token).await;
        assert_eq!(ok.block, None);
    }

    #[tokio::test]
    async fn allow_short_circuits_before_deny() {
        let cfg = HookConfig::parse(
            r#"{"PreToolUse":[{"matcher":"exec","hooks":[{"type":"allow","when":"git push origin safe*"},{"type":"deny","reason":"no push","when":"git push*"}]}]}"#,
        )
        .unwrap();
        let runner = HookRunner::new(cfg);
        let token = CancellationToken::new();
        assert_eq!(runner.pre("exec", &args(&[("command", "git push origin safe/x")]), &token).await.block, None);
        assert_eq!(runner.pre("exec", &args(&[("command", "git push origin main")]), &token).await.block.as_deref(), Some("no push"));
    }

    #[tokio::test]
    async fn command_hook_denies_on_exit_code() {
        let cfg = HookConfig::parse(r#"{"PreToolUse":[{"matcher":"write","hooks":[{"type":"command","command":"echo blocked by ci >&2; exit 1"}]}]}"#).unwrap();
        let runner = HookRunner::new(cfg);
        let token = CancellationToken::new();
        let d = runner.pre("write", &args(&[("path", "a.txt")]), &token).await;
        assert_eq!(d.block.as_deref(), Some("blocked by ci"));
    }

    #[tokio::test]
    async fn oversized_payload_to_a_hook_that_never_reads_still_times_out() {
        // 1 MiB of arguments: far beyond a pipe buffer. The hook ignores stdin and
        // sleeps; the call must be blocked by the timeout, not hang.
        let payload = json!({ "content": "x".repeat(1 << 20) });
        let token = CancellationToken::new();
        let started = std::time::Instant::now();
        let reply = run_command_hook("sleep 30", &payload, 300, &token).await;
        assert!(started.elapsed() < Duration::from_secs(10), "hook hung: {:?}", started.elapsed());
        assert_eq!(reply.action.as_deref(), Some("deny"));
        assert!(reply.reason.unwrap_or_default().contains("timed out"));
    }

    #[tokio::test]
    async fn command_hook_json_reply_rewrites_and_injects() {
        // The hook reads stdin then prints a JSON decision. Build the config via
        // the structs so the embedded JSON needs no shell/JSON double-escaping.
        let reply = r#"{"action":"allow","context":"scanned ok","arguments":{"path":"safe.txt"}}"#;
        let command = format!("cat >/dev/null; cat <<'EOF'\n{reply}\nEOF");
        let cfg = HookConfig {
            hooks: BTreeMap::from([(
                HookEvent::PreToolUse,
                vec![MatcherGroup { matcher: "write".into(), hooks: vec![HookAction::Command { command, timeout_ms: None }] }],
            )]),
        };
        let runner = HookRunner::new(cfg);
        let token = CancellationToken::new();
        let d = runner.pre("write", &args(&[("path", "a.txt")]), &token).await;
        assert_eq!(d.block, None);
        assert_eq!(d.inject, vec!["scanned ok".to_string()]);
        assert_eq!(d.rewrite.unwrap().get("path").and_then(Value::as_str), Some("safe.txt"));
    }

    #[tokio::test]
    async fn post_hook_injects_into_result() {
        let outcome = inject_into(CallOutcome::Ok(Value::String("done".into())), &["noted".to_string()]);
        match outcome {
            CallOutcome::Ok(Value::String(s)) => assert!(s.contains("done") && s.contains("[hook] noted")),
            _ => panic!("expected string"),
        }
    }
}
