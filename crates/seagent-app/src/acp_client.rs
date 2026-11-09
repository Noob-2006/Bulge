//! ACP client (acpx-style): seagent drives external ACP agents — Claude Code, Codex,
//! Gemini, OpenCode, Qwen, Copilot… — over stdio NDJSON JSON-RPC. Parity with
//! OpenClaw `extensions/acpx` + `src/acp/client.ts` (MIT).
//!
//! ```toml
//! [acp]
//! permission_mode = "approve-reads"   # approve-all | approve-reads | deny-all
//! [acp.agents.mine]
//! command = "my-agent"
//! args = ["--acp"]
//! env = { MY_KEY = "{{secret:MY_KEY}}" }
//! ```
//!
//! Built-in presets mirror acpx's registry ([`PRESETS`]); `[acp.agents.<name>]`
//! overrides or adds. The client side of the protocol is implemented here:
//! fs/read_text_file and fs/write_text_file (confined to the session's cwd),
//! terminal/create|output|wait_for_exit|kill|release (commands judged by seagent's
//! gates first), and session/request_permission answered by the permission mode:
//! approve-all allows everything, approve-reads allows read/search/think and asks
//! a human for the rest (denied when nobody can answer), deny-all refuses. Exposed
//! as the `acp_delegate` tool and `seagent acp-client <agent> "prompt"`.

use seagent_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::gate::{GateConfig, Gates, Verdict};
use seagent_kernel::vault::Vault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read as _, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// `[acp]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcpConfig {
    /// Extra models (provider/model) offered in an editor's model picker when seagent is the agent.
    pub models: Vec<String>,
    /// Run MCP servers an editor passes in with full trust (default: untrusted —
    /// calls to tools without readOnlyHint go through the egress gate).
    pub trust_editor_mcp: bool,
    /// Default for external agents: approve-all | approve-reads (default) | deny-all.
    pub permission_mode: Option<String>,
    /// Per-prompt timeout for external agents (default 1800 s).
    pub timeout_secs: Option<u64>,
    /// External ACP agents by name (adds to / overrides [`PRESETS`]).
    pub agents: BTreeMap<String, AgentSpec>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentSpec {
    pub command: String,
    pub args: Vec<String>,
    /// Values may be `{{secret:NAME}}` references.
    pub env: BTreeMap<String, String>,
    pub permission_mode: Option<String>,
    pub description: Option<String>,
}

impl AcpConfig {
    pub fn parse(t: &toml::Table) -> Result<AcpConfig, String> {
        let c = AcpConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[acp]: {e}"))?;
        if let Some(m) = &c.permission_mode {
            PermissionMode::parse(m)?;
        }
        for (n, a) in &c.agents {
            if a.command.trim().is_empty() {
                return Err(format!("[acp.agents.{n}]: `command` is required"));
            }
            if let Some(m) = &a.permission_mode {
                PermissionMode::parse(m).map_err(|e| format!("[acp.agents.{n}]: {e}"))?;
            }
        }
        Ok(c)
    }
    /// The agent to launch: config first, then the built-in preset.
    pub fn agent(&self, name: &str) -> Result<AgentSpec, String> {
        let name = match name {
            "claude-code" | "claude-agent" => "claude",
            "codex-cli" => "codex",
            "gemini-cli" => "gemini",
            n => n,
        };
        if let Some(a) = self.agents.get(name) {
            return Ok(a.clone());
        }
        PRESETS
            .iter()
            .find(|(n, ..)| *n == name)
            .map(|(n, c, a, d)| {
                // An installed CLI beats fetching the npm package on every run.
                let (c, a) = LOCAL.iter().find(|(ln, lc, _)| ln == n && on_path(lc)).map(|(_, lc, la)| (*lc, *la)).unwrap_or((*c, *a));
                AgentSpec { command: c.to_string(), args: a.iter().map(|s| s.to_string()).collect(), env: BTreeMap::new(), permission_mode: None, description: Some(d.to_string()) }
            })
            .ok_or_else(|| format!("unknown ACP agent `{name}`; known: {}", self.names().join(", ")))
    }
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = PRESETS.iter().map(|p| p.0.to_string()).collect();
        v.extend(self.agents.keys().filter(|k| !PRESETS.iter().any(|p| p.0 == k.as_str())).cloned());
        v
    }
    pub fn mode_for(&self, spec: &AgentSpec) -> PermissionMode {
        spec.permission_mode.as_deref().or(self.permission_mode.as_deref()).and_then(|m| PermissionMode::parse(m).ok()).unwrap_or(PermissionMode::ApproveReads)
    }
}

/// Presets whose agent ships a native ACP mode in its own CLI: used when that CLI is installed.
const LOCAL: &[(&str, &str, &[&str])] = &[("opencode", "opencode", &["acp"])];

fn on_path(cmd: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
}

/// acpx's built-in agent registry: (name, command, args, what it is).
pub const PRESETS: &[(&str, &str, &[&str], &str)] = &[
    ("claude", "npx", &["-y", "@agentclientprotocol/claude-agent-acp"], "Claude Code (Anthropic)"),
    ("codex", "npx", &["-y", "@agentclientprotocol/codex-acp"], "Codex CLI (OpenAI)"),
    ("gemini", "gemini", &["--experimental-acp"], "Gemini CLI (Google)"),
    ("opencode", "npx", &["-y", "opencode-ai", "acp"], "OpenCode"),
    ("qwen", "qwen", &["--acp"], "Qwen Code"),
    ("copilot", "copilot", &["--acp", "--stdio"], "GitHub Copilot CLI"),
    ("cursor", "cursor-agent", &["acp"], "Cursor agent"),
    ("droid", "droid", &["exec", "--output-format", "acp"], "Factory Droid"),
    ("grok-build", "grok", &["agent", "stdio"], "Grok Build"),
    ("iflow", "iflow", &["--experimental-acp"], "iFlow CLI"),
    ("kilocode", "npx", &["-y", "@kilocode/cli", "acp"], "Kilo Code"),
    ("kimi", "kimi", &["acp"], "Kimi CLI"),
    ("kiro", "kiro-cli", &["acp"], "Kiro CLI"),
    ("qoder", "qodercli", &["--acp"], "Qoder CLI"),
    ("openclaw", "openclaw", &["acp"], "OpenClaw"),
    ("seagent", "seagent", &["acp"], "another seagent"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    ApproveAll,
    ApproveReads,
    DenyAll,
}

impl PermissionMode {
    pub fn parse(s: &str) -> Result<PermissionMode, String> {
        match s {
            "approve-all" => Ok(PermissionMode::ApproveAll),
            "approve-reads" => Ok(PermissionMode::ApproveReads),
            "deny-all" => Ok(PermissionMode::DenyAll),
            m => Err(format!("permission mode `{m}`: use approve-all, approve-reads or deny-all")),
        }
    }
}

/// Asks a human yes/no; false when nobody can answer.
pub type Asker = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// Every `session/update` the agent sends, as it arrives.
pub type Progress = Arc<dyn Fn(&Value) + Send + Sync>;

/// What one prompt produced.
#[derive(Debug, Clone, Default)]
pub struct Turn {
    pub text: String,
    pub thoughts: String,
    /// (toolCallId, title, kind, status)
    pub tools: Vec<(String, String, String, String)>,
    pub plan: Vec<String>,
    /// Permission decisions: "allowed: …" / "denied: …".
    pub permissions: Vec<String>,
    pub stop_reason: String,
}

struct Term {
    child: Mutex<Child>,
    out: Arc<Mutex<(String, bool)>>,
    status: Mutex<Option<(Option<i32>, Option<String>)>>,
}

struct State {
    agent: String,
    cwd: PathBuf,
    mode: PermissionMode,
    ask: Asker,
    gate: Option<(GateConfig, Arc<Vault>)>,
    terms: Mutex<HashMap<String, Arc<Term>>>,
    turn: Mutex<Turn>,
    progress: Mutex<Option<Progress>>,
    cancelled: AtomicBool,
}

struct Conn {
    stdin: Mutex<ChildStdin>,
    next: AtomicU64,
    waiting: Mutex<HashMap<u64, mpsc::Sender<Value>>>,
    dead: AtomicBool,
    stderr: Mutex<String>,
}

impl Conn {
    fn send(&self, v: &Value) -> Result<(), String> {
        let mut w = self.stdin.lock().unwrap();
        writeln!(w, "{v}").and_then(|_| w.flush()).map_err(|e| format!("agent stdin: {e}"))
    }
    fn start_request(&self, method: &str, params: Value) -> Result<(u64, mpsc::Receiver<Value>), String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.waiting.lock().unwrap().insert(id, tx);
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        Ok((id, rx))
    }
    fn finish(&self, method: &str, v: Value) -> Result<Value, String> {
        match v.get("error") {
            Some(e) => Err(format!("{method}: {} ({})", e["message"].as_str().unwrap_or("error"), e["code"])),
            None => Ok(v["result"].clone()),
        }
    }
    fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let (id, rx) = self.start_request(method, params)?;
        let r = rx.recv_timeout(timeout);
        self.waiting.lock().unwrap().remove(&id);
        match r {
            Ok(v) => self.finish(method, v),
            Err(_) if self.dead.load(Ordering::SeqCst) => Err(format!("{method}: the agent exited{}", self.tail())),
            Err(_) => Err(format!("{method}: no answer within {}s", timeout.as_secs())),
        }
    }
    fn tail(&self) -> String {
        let s = self.stderr.lock().unwrap();
        let t = s.trim();
        if t.is_empty() {
            String::new()
        } else {
            let n = t.chars().count();
            format!("; stderr: {}", t.chars().skip(n.saturating_sub(800)).collect::<String>())
        }
    }
}

/// One running external agent with one ACP session.
pub struct AcpClient {
    pub agent: String,
    pub session_id: String,
    pub agent_info: Value,
    pub capabilities: Value,
    pub command_line: String,
    conn: Arc<Conn>,
    state: Arc<State>,
    child: Mutex<Child>,
}

fn quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@+,".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn command_line(spec: &AgentSpec) -> String {
    std::iter::once(spec.command.as_str()).chain(spec.args.iter().map(String::as_str)).map(quote).collect::<Vec<_>>().join(" ")
}

/// Own process group: kill reaches a terminal's children, and the terminal's
/// Ctrl-C doesn't hit the agent. (No PDEATHSIG: it fires when the spawning
/// *thread* ends; agents exit on stdin EOF instead.)
#[cfg(unix)]
fn own_group(cmd: &mut Command) {
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
}

/// Windows: a new console process group (Ctrl-C in our console skips it); [`adopt`] after the
/// spawn puts the tree in a Job Object so `kill_term` reaches its children.
#[cfg(not(unix))]
fn own_group(cmd: &mut Command) {
    seagent_core::platform::proc::new_group(cmd, false);
}

/// Windows: the Job Object half of [`own_group`] (Unix: the process group already is the unit).
fn adopt(child: &std::process::Child) {
    #[cfg(not(unix))]
    let _ = seagent_core::platform::proc::adopt(child);
    #[cfg(unix)]
    let _ = child;
}

impl AcpClient {
    /// Spawn the agent and `initialize` it. `secrets` resolves `{{secret:…}}` in env values.
    pub fn start(name: &str, spec: &AgentSpec, cwd: &Path, mode: PermissionMode, ask: Asker, gate: Option<(GateConfig, Arc<Vault>)>, secrets: &dyn Fn(&str) -> String) -> Result<AcpClient, String> {
        // Windows: npm `.cmd` shims and the Python launcher; Unix: `Command::new(command)`.
        let mut cmd = seagent_core::platform::layout::program_command(&spec.command);
        seagent_core::platform::layout::msys_args(&mut cmd, &spec.args);
        cmd.current_dir(cwd).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in &spec.env {
            cmd.env(k, secrets(v));
        }
        // Out of the terminal's group: Ctrl-C becomes session/cancel, not a dead agent.
        own_group(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| format!("cannot start ACP agent `{name}` ({}): {e}", command_line(spec)))?;
        adopt(&child);
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let mut stderr = child.stderr.take().ok_or("no stderr")?;
        let conn = Arc::new(Conn { stdin: Mutex::new(stdin), next: AtomicU64::new(1), waiting: Mutex::default(), dead: AtomicBool::new(false), stderr: Mutex::default() });
        let state = Arc::new(State { agent: name.to_string(), cwd: cwd.to_path_buf(), mode, ask, gate, terms: Mutex::default(), turn: Mutex::default(), progress: Mutex::new(None), cancelled: AtomicBool::new(false) });
        let c2 = conn.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut s = c2.stderr.lock().unwrap();
                s.push_str(&String::from_utf8_lossy(&buf[..n]));
                if s.len() > 16_384 {
                    let cut = s.len() - 8192;
                    let cut = (cut..s.len()).find(|i| s.is_char_boundary(*i)).unwrap_or(0);
                    s.drain(..cut);
                }
            }
        });
        let (c2, s2) = (conn.clone(), state.clone());
        std::thread::spawn(move || read_loop(BufReader::new(stdout), c2, s2));
        let fs_write = mode != PermissionMode::DenyAll;
        let init = conn.request(
            "initialize",
            json!({"protocolVersion": crate::acp::PROTOCOL_VERSION, "clientCapabilities": {"fs": {"readTextFile": true, "writeTextFile": fs_write}, "terminal": fs_write}, "clientInfo": {"name": "seagent", "title": "seagent", "version": env!("CARGO_PKG_VERSION")}}),
            Duration::from_secs(180),
        );
        let init = match init {
            Ok(v) => v,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        Ok(AcpClient { agent: name.into(), session_id: String::new(), agent_info: init["agentInfo"].clone(), capabilities: init["agentCapabilities"].clone(), command_line: command_line(spec), conn, state, child: Mutex::new(child) })
    }

    /// `session/new`, or `session/load` of `resume` when the agent supports it.
    pub fn open_session(&mut self, resume: Option<&str>) -> Result<(), String> {
        let cwd = self.state.cwd.to_string_lossy().to_string();
        if let Some(id) = resume {
            if self.capabilities["loadSession"] != true {
                return Err(format!("{} cannot load sessions", self.agent));
            }
            self.conn.request("session/load", json!({"sessionId": id, "cwd": cwd, "mcpServers": []}), Duration::from_secs(120))?;
            self.session_id = id.to_string();
            // Replayed history is not this turn's output.
            *self.state.turn.lock().unwrap() = Turn::default();
            return Ok(());
        }
        let r = self.conn.request("session/new", json!({"cwd": cwd, "mcpServers": []}), Duration::from_secs(120))?;
        self.session_id = r["sessionId"].as_str().ok_or("session/new: no sessionId")?.to_string();
        Ok(())
    }

    pub fn set_progress(&self, p: Option<Progress>) {
        *self.state.progress.lock().unwrap() = p;
    }

    /// Send a prompt and wait for its stop reason; `cancel` sends `session/cancel`.
    pub fn prompt(&self, text: &str, cancel: &Cancel, timeout: Duration) -> Result<Turn, String> {
        *self.state.turn.lock().unwrap() = Turn::default();
        self.state.cancelled.store(false, Ordering::SeqCst);
        let (id, rx) = self.conn.start_request("session/prompt", json!({"sessionId": self.session_id, "prompt": [{"type": "text", "text": text}]}))?;
        let start = Instant::now();
        let mut cancel_sent: Option<Instant> = None;
        let r = loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(v) => break self.conn.finish("session/prompt", v),
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err("session/prompt: connection closed".into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if self.conn.dead.load(Ordering::SeqCst) {
                break Err(format!("the agent exited mid-prompt{}", self.conn.tail()));
            }
            let over = start.elapsed() > timeout;
            if (cancel.is_cancelled() || over) && cancel_sent.is_none() {
                self.state.cancelled.store(true, Ordering::SeqCst);
                let _ = self.conn.send(&json!({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": self.session_id}}));
                cancel_sent = Some(Instant::now());
            }
            // Agents must answer a cancel with stopReason "cancelled"; don't wait forever.
            if cancel_sent.is_some_and(|t| t.elapsed() > Duration::from_secs(15)) {
                break Err(if over { format!("timed out after {}s", timeout.as_secs()) } else { "cancelled".into() });
            }
        };
        self.conn.waiting.lock().unwrap().remove(&id);
        let mut t = std::mem::take(&mut *self.state.turn.lock().unwrap());
        t.stop_reason = r?["stopReason"].as_str().unwrap_or("end_turn").to_string();
        Ok(t)
    }

    pub fn is_alive(&self) -> bool {
        !self.conn.dead.load(Ordering::SeqCst)
    }

    /// `session/close` when supported, then stop the process.
    pub fn close(&self) {
        if self.capabilities["sessionCapabilities"]["close"].is_object() && !self.session_id.is_empty() && self.is_alive() {
            let _ = self.conn.request("session/close", json!({"sessionId": self.session_id}), Duration::from_secs(5));
        }
        for t in self.state.terms.lock().unwrap().drain() {
            kill_term(&t.1);
        }
        let mut c = self.child.lock().unwrap();
        let _ = c.kill();
        let _ = c.wait();
    }
}

impl Drop for AcpClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_loop(r: impl BufRead, conn: Arc<Conn>, st: Arc<State>) {
    for line in r.lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        match (v.get("method").and_then(Value::as_str), v.get("id").filter(|i| !i.is_null())) {
            (Some(m), Some(id)) => {
                // Agent → client request. Off-thread: permission questions can take minutes.
                let (m, id, p, c, s) = (m.to_string(), id.clone(), v["params"].clone(), conn.clone(), st.clone());
                std::thread::spawn(move || {
                    let reply = match client_method(&s, &m, &p) {
                        Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
                        Err((code, msg)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}),
                    };
                    let _ = c.send(&reply);
                });
            }
            (Some("session/update"), None) => on_update(&st, &v["params"]["update"]),
            (Some(_), None) => {}
            (None, _) => {
                if let Some(tx) = v["id"].as_u64().and_then(|id| conn.waiting.lock().unwrap().remove(&id)) {
                    let _ = tx.send(v);
                }
            }
        }
    }
    conn.dead.store(true, Ordering::SeqCst);
    conn.waiting.lock().unwrap().clear();
}

fn on_update(st: &State, u: &Value) {
    {
        let mut t = st.turn.lock().unwrap();
        let text = u["content"]["text"].as_str().unwrap_or("");
        match u["sessionUpdate"].as_str().unwrap_or("") {
            "agent_message_chunk" => t.text.push_str(text),
            "agent_thought_chunk" => t.thoughts.push_str(text),
            "tool_call" => t.tools.push((u["toolCallId"].as_str().unwrap_or("").into(), u["title"].as_str().unwrap_or("tool").into(), u["kind"].as_str().unwrap_or("other").into(), u["status"].as_str().unwrap_or("pending").into())),
            "tool_call_update" => {
                if let Some(tc) = t.tools.iter_mut().find(|x| Some(x.0.as_str()) == u["toolCallId"].as_str()) {
                    if let Some(s) = u["status"].as_str() {
                        tc.3 = s.into();
                    }
                    if let Some(s) = u["title"].as_str() {
                        tc.1 = s.into();
                    }
                }
            }
            "plan" => t.plan = u["entries"].as_array().into_iter().flatten().map(|e| format!("[{}] {}", e["status"].as_str().unwrap_or("pending"), e["content"].as_str().unwrap_or(""))).collect(),
            _ => {}
        }
    }
    let p = st.progress.lock().unwrap().clone();
    if let Some(p) = p {
        p(u);
    }
}

/// One line for a progress display; None for updates not worth showing.
pub fn describe_update(u: &Value) -> Option<String> {
    match u["sessionUpdate"].as_str()? {
        "tool_call" => Some(format!("→ {} [{}]", u["title"].as_str().unwrap_or("tool"), u["kind"].as_str().unwrap_or("other"))),
        "tool_call_update" => u["status"].as_str().filter(|s| matches!(*s, "completed" | "failed")).map(|s| format!("  {} {}", if s == "failed" { "✗" } else { "✓" }, u["title"].as_str().or(u["toolCallId"].as_str()).unwrap_or(""))),
        "plan" => Some(format!("plan: {}", u["entries"].as_array().into_iter().flatten().map(|e| format!("[{}] {}", e["status"].as_str().unwrap_or(""), e["content"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("; "))),
        _ => None,
    }
}

type RpcResult = Result<Value, (i64, String)>;

/// A path the agent named, confined to the session's cwd (symlinks resolved).
fn confined(st: &State, p: &str) -> Result<PathBuf, (i64, String)> {
    let raw = PathBuf::from(p);
    let path = if raw.is_absolute() { raw } else { st.cwd.join(raw) };
    let root = st.cwd.canonicalize().unwrap_or_else(|_| st.cwd.clone());
    // The file may not exist yet: resolve the deepest existing ancestor.
    let mut probe = path.clone();
    let mut rest = Vec::new();
    while !probe.exists() {
        match (probe.file_name().map(|f| f.to_os_string()), probe.parent()) {
            (Some(f), Some(par)) => {
                rest.push(f);
                probe = par.to_path_buf();
            }
            _ => break,
        }
    }
    let mut real = probe.canonicalize().unwrap_or(probe);
    for f in rest.into_iter().rev() {
        if f == ".." {
            return Err((-32602, format!("{p}: `..` is not allowed")));
        }
        real.push(f);
    }
    if !real.starts_with(&root) {
        return Err((-32602, format!("{p} is outside the session directory {}", root.display())));
    }
    Ok(real)
}

fn gate(st: &State, effects: &[Effect]) -> Verdict {
    match &st.gate {
        Some((cfg, vault)) => Gates { cfg, vault }.judge(effects),
        None => Verdict::Allow,
    }
}

/// approve-all → yes; approve-reads → ask a human; deny-all → no. A gate that asks
/// always goes to the human, whatever the mode.
fn permit(st: &State, what: &str, gate_asks: Option<&str>) -> bool {
    let ok = match (st.mode, gate_asks) {
        (PermissionMode::DenyAll, _) => false,
        (PermissionMode::ApproveAll, None) => true,
        (_, Some(r)) => (st.ask)(&format!("ACP agent `{}` wants to {what} ({r}). Allow?", st.agent)),
        (PermissionMode::ApproveReads, None) => (st.ask)(&format!("ACP agent `{}` wants to {what}. Allow?", st.agent)),
    };
    st.turn.lock().unwrap().permissions.push(format!("{}: {what}", if ok { "allowed" } else { "denied" }));
    ok
}

fn client_method(st: &State, method: &str, p: &Value) -> RpcResult {
    match method {
        "session/request_permission" => Ok(json!({"outcome": permission(st, p)})),
        "fs/read_text_file" => {
            let path = confined(st, p["path"].as_str().unwrap_or(""))?;
            if let Verdict::Deny { reason, .. } = gate(st, &[Effect::Read { path: path.clone() }]) {
                return Err((-32000, reason));
            }
            let text = std::fs::read_to_string(&path).map_err(|e| (-32002, format!("{}: {e}", path.display())))?;
            let line = p["line"].as_u64().unwrap_or(1).max(1) as usize;
            let content = match p["limit"].as_u64() {
                None if line == 1 => text,
                lim => text.split_inclusive('\n').skip(line - 1).take(lim.map(|l| l as usize).unwrap_or(usize::MAX)).collect(),
            };
            Ok(json!({"content": content}))
        }
        "fs/write_text_file" => {
            let path = confined(st, p["path"].as_str().unwrap_or(""))?;
            let asks = match gate(st, &[Effect::Write { path: path.clone() }]) {
                Verdict::Deny { reason, .. } => return Err((-32000, reason)),
                Verdict::Ask { reason, .. } => Some(reason),
                Verdict::Allow => None,
            };
            if !permit(st, &format!("write {}", path.display()), asks.as_deref()) {
                return Err((-32000, format!("writing {} was not permitted (permission mode)", path.display())));
            }
            if let Some(d) = path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::write(&path, p["content"].as_str().unwrap_or("")).map_err(|e| (-32603, format!("{}: {e}", path.display())))?;
            Ok(json!(null))
        }
        "terminal/create" => terminal_create(st, p),
        "terminal/output" | "terminal/wait_for_exit" | "terminal/kill" | "terminal/release" => {
            let id = p["terminalId"].as_str().unwrap_or("");
            let t = st.terms.lock().unwrap().get(id).cloned().ok_or((-32602, format!("unknown terminal `{id}`")))?;
            match method {
                "terminal/output" => {
                    poll_term(&t);
                    let (out, truncated) = t.out.lock().unwrap().clone();
                    let mut r = json!({"output": out, "truncated": truncated});
                    if let Some((code, sig)) = t.status.lock().unwrap().clone() {
                        r["exitStatus"] = json!({"exitCode": code, "signal": sig});
                    }
                    Ok(r)
                }
                "terminal/wait_for_exit" => loop {
                    if let Some((code, sig)) = poll_term(&t) {
                        return Ok(json!({"exitCode": code, "signal": sig}));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                },
                "terminal/kill" => {
                    kill_term(&t);
                    Ok(json!(null))
                }
                _ => {
                    kill_term(&t);
                    st.terms.lock().unwrap().remove(id);
                    Ok(json!(null))
                }
            }
        }
        m => Err((-32601, format!("method `{m}` not supported by seagent's ACP client"))),
    }
}

fn permission(st: &State, p: &Value) -> Value {
    let opts = p["options"].as_array().cloned().unwrap_or_default();
    let pick = |kinds: &[&str]| kinds.iter().find_map(|k| opts.iter().find(|o| o["kind"] == *k)).and_then(|o| o["optionId"].as_str()).map(str::to_string);
    let (allow, reject) = (pick(&["allow_once", "allow_always"]), pick(&["reject_once", "reject_always"]));
    if st.cancelled.load(Ordering::SeqCst) || opts.is_empty() {
        return json!({"outcome": "cancelled"});
    }
    let tc = &p["toolCall"];
    let id = tc["toolCallId"].as_str().unwrap_or("");
    let known = st.turn.lock().unwrap().tools.iter().find(|t| t.0 == id).map(|t| (t.1.clone(), t.2.clone()));
    let kind = tc["kind"].as_str().map(str::to_string).or_else(|| known.as_ref().map(|k| k.1.clone())).unwrap_or_else(|| "other".into());
    let title = tc["title"].as_str().map(str::to_string).or_else(|| known.map(|k| k.0)).unwrap_or_else(|| "a tool".into());
    // Commands the agent wants to run are judged by seagent's gates too.
    let command = tc["rawInput"]["command"].as_str().map(|c| match tc["rawInput"]["args"].as_array() {
        Some(a) => std::iter::once(c.to_string()).chain(a.iter().filter_map(|x| x.as_str().map(quote))).collect::<Vec<_>>().join(" "),
        None => c.to_string(),
    });
    let verdict = command.filter(|_| kind == "execute").map(|c| gate(st, &[Effect::Exec { command: c }])).unwrap_or(Verdict::Allow);
    let ok = match verdict {
        Verdict::Deny { reason, .. } => {
            st.turn.lock().unwrap().permissions.push(format!("denied: {title} ({reason})"));
            false
        }
        Verdict::Ask { reason, .. } => permit(st, &format!("{title} [{kind}]"), Some(&reason)),
        Verdict::Allow if st.mode == PermissionMode::ApproveReads && matches!(kind.as_str(), "read" | "search" | "think") => {
            st.turn.lock().unwrap().permissions.push(format!("allowed: {title} [{kind}]"));
            true
        }
        Verdict::Allow => permit(st, &format!("{title} [{kind}]"), None),
    };
    match (ok, allow, reject) {
        (true, Some(o), _) | (false, _, Some(o)) => json!({"outcome": "selected", "optionId": o}),
        _ => json!({"outcome": "cancelled"}),
    }
}

fn terminal_create(st: &State, p: &Value) -> RpcResult {
    let command = p["command"].as_str().filter(|c| !c.trim().is_empty()).ok_or((-32602, "missing command".to_string()))?;
    let args: Vec<String> = p["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
    // A bare command line ("ls -la | wc") runs through the shell, like seagent's shell tool.
    let line = if args.is_empty() { command.to_string() } else { std::iter::once(quote(command)).chain(args.iter().map(|a| quote(a))).collect::<Vec<_>>().join(" ") };
    let cwd = match p["cwd"].as_str() {
        Some(c) => confined(st, c)?,
        None => st.cwd.clone(),
    };
    let asks = match gate(st, &[Effect::Exec { command: line.clone() }]) {
        Verdict::Deny { reason, .. } => return Err((-32000, format!("blocked by seagent's gate: {reason}"))),
        Verdict::Ask { reason, .. } => Some(reason),
        Verdict::Allow => None,
    };
    if !permit(st, &format!("run `{line}`"), asks.as_deref()) {
        return Err((-32000, format!("running `{line}` was not permitted (permission mode)")));
    }
    let mut cmd = if args.is_empty() {
        // `/bin/sh -c` (Windows: this machine's shell, `seagent_core::platform::shell`).
        seagent_core::platform::shell::command(seagent_core::platform::shell::Style::BinSh, command)
    } else {
        let mut c = Command::new(command);
        c.args(&args);
        c
    };
    seagent_security::envscrub::apply(&mut cmd, seagent_security::envscrub::Surface::Terminal);
    cmd.current_dir(&cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for e in p["env"].as_array().into_iter().flatten() {
        if let Some(n) = e["name"].as_str() {
            cmd.env(n, e["value"].as_str().unwrap_or(""));
        }
    }
    own_group(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| (-32603, format!("{line}: {e}")))?;
    adopt(&child);
    let limit = p["outputByteLimit"].as_u64().unwrap_or(1 << 20).max(1) as usize;
    let out: Arc<Mutex<(String, bool)>> = Arc::default();
    let pipes: Vec<Box<dyn std::io::Read + Send>> = vec![Box::new(child.stdout.take().unwrap()), Box::new(child.stderr.take().unwrap())];
    for mut r in pipes {
        let out = out.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut o = out.lock().unwrap();
                o.0.push_str(&String::from_utf8_lossy(&buf[..n]));
                // Keep the newest `limit` bytes, cut at a character boundary.
                if o.0.len() > limit {
                    let mut cut = o.0.len() - limit;
                    while !o.0.is_char_boundary(cut) {
                        cut += 1;
                    }
                    o.0.drain(..cut);
                    o.1 = true;
                }
            }
        });
    }
    static N: AtomicU64 = AtomicU64::new(1);
    let id = format!("term-{}", N.fetch_add(1, Ordering::SeqCst));
    st.terms.lock().unwrap().insert(id.clone(), Arc::new(Term { child: Mutex::new(child), out, status: Mutex::new(None) }));
    Ok(json!({"terminalId": id}))
}

fn poll_term(t: &Term) -> Option<(Option<i32>, Option<String>)> {
    if let Some(s) = t.status.lock().unwrap().clone() {
        return Some(s);
    }
    let st = t.child.lock().unwrap().try_wait().ok().flatten()?;
    #[cfg(unix)]
    let s = {
        use std::os::unix::process::ExitStatusExt;
        (st.code(), st.signal().map(|n| match n {
            9 => "SIGKILL".to_string(),
            15 => "SIGTERM".to_string(),
            2 => "SIGINT".to_string(),
            n => format!("SIG{n}"),
        }))
    };
    // Windows has no signals: every exit is a code.
    #[cfg(not(unix))]
    let s: (Option<i32>, Option<String>) = (st.code(), None);
    // Let the pipe readers drain what the process wrote last.
    std::thread::sleep(Duration::from_millis(30));
    *t.status.lock().unwrap() = Some(s.clone());
    Some(s)
}

fn kill_term(t: &Term) {
    if poll_term(t).is_none() {
        let pid = t.child.lock().unwrap().id() as i32;
        // SAFETY: plain syscall; negative pid = the terminal's process group.
        #[cfg(unix)]
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        seagent_core::platform::proc::kill_group(pid, Duration::ZERO);
        let _ = t.child.lock().unwrap().wait();
        poll_term(t);
    }
}

/// Final answer of a turn for a model or a terminal.
pub fn render_turn(c: &AcpClient, t: &Turn, label: &str) -> String {
    let mut s = format!("[{} · {} · session {} · {}]\n", c.agent, label, c.session_id, t.stop_reason);
    if !t.tools.is_empty() {
        s.push_str(&format!("tool calls: {}\n", t.tools.iter().map(|x| format!("{} [{}] {}", x.1, x.2, x.3)).collect::<Vec<_>>().join("; ")));
    }
    if !t.plan.is_empty() {
        s.push_str(&format!("plan: {}\n", t.plan.join("; ")));
    }
    if !t.permissions.is_empty() {
        s.push_str(&format!("permissions: {}\n", t.permissions.join("; ")));
    }
    s.push('\n');
    s.push_str(if t.text.trim().is_empty() { "(no text reply)" } else { t.text.trim() });
    s
}

// ───────────────────────── the acp_delegate tool ─────────────────────────

/// Live agents kept for session reuse: key = seagent session + agent + name.
type Pool = Mutex<Vec<(String, PathBuf, Arc<Mutex<AcpClient>>)>>;
fn pool() -> &'static Pool {
    static P: OnceLock<Pool> = OnceLock::new();
    P.get_or_init(Pool::default)
}
const POOL_MAX: usize = 8;

pub struct AcpDelegate {
    pub cfg: AcpConfig,
    pub gate: GateConfig,
    pub vault: Arc<Vault>,
}

impl Tool for AcpDelegate {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "acp_delegate".into(),
            description: format!(
                "Delegate a task to an external coding agent over ACP (Agent Client Protocol) and return its reply. Agents: {}. The agent works in `cwd` (default: the workspace); its file writes and commands follow the configured permission mode and seagent's gates. Pass the returned `session` name to continue the same conversation; `close: true` ends it.",
                self.cfg.names().join(", ")
            ),
            input_schema: json!({"type": "object", "properties": {
                "agent": {"type": "string", "description": "agent name, e.g. claude, codex, gemini, opencode, qwen, copilot"},
                "prompt": {"type": "string"},
                "cwd": {"type": "string", "description": "working directory (inside the workspace by default)"},
                "session": {"type": "string", "description": "session name from an earlier acp_delegate reply, to continue it"},
                "close": {"type": "boolean", "description": "end the session after this prompt (or now, with no prompt)"},
                "timeout_secs": {"type": "integer"}},
                "required": ["agent"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        let agent = input["agent"].as_str().unwrap_or("");
        let mut e = vec![Effect::Spawn];
        if let Ok(spec) = self.cfg.agent(agent) {
            e.push(Effect::Exec { command: command_line(&spec) });
        }
        if let Some(p) = input["prompt"].as_str() {
            e.push(Effect::Net { dest: format!("acp://{agent}"), payload: p.to_string() });
        }
        e
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(s) => ToolOutput::ok(s),
            Err(e) => ToolOutput::err(e),
        }
    }
}

impl AcpDelegate {
    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let agent = input["agent"].as_str().filter(|a| !a.is_empty()).ok_or("missing `agent`")?;
        let spec = self.cfg.agent(agent)?;
        let cwd = ctx.resolve(input["cwd"].as_str().unwrap_or("."));
        let cwd = cwd.canonicalize().map_err(|e| format!("cwd {}: {e}", cwd.display()))?;
        let prompt = input["prompt"].as_str().unwrap_or("");
        let close = input["close"].as_bool().unwrap_or(false);
        let prefix = format!("{}:{agent}:", ctx.session_id);
        let name = input["session"].as_str().map(str::to_string);
        let existing = name.as_ref().and_then(|n| pool().lock().unwrap().iter().find(|(k, c, _)| *k == format!("{prefix}{n}") && *c == cwd).map(|x| x.2.clone()));
        if close && prompt.is_empty() {
            let n = name.ok_or("`close` without a prompt needs `session`")?;
            pool().lock().unwrap().retain(|(k, _, _)| *k != format!("{prefix}{n}"));
            return Ok(match existing {
                Some(c) => {
                    c.lock().unwrap().close();
                    format!("closed {agent} session `{n}`")
                }
                None => format!("no live {agent} session `{n}`"),
            });
        }
        if prompt.trim().is_empty() {
            return Err("missing `prompt`".into());
        }
        if name.is_some() && existing.is_none() {
            return Err(format!("no live {agent} session `{}` for {}; omit `session` to start a new one", name.unwrap_or_default(), cwd.display()));
        }
        let client = match existing.filter(|c| c.lock().unwrap().is_alive()) {
            Some(c) => c,
            None => {
                let host = ctx.host.clone();
                let ask: Asker = Arc::new(move |q: &str| host.ask_user(&format!("{q} (yes/no)")).map(|a| is_yes(&a)).unwrap_or(false));
                let secrets = ctx.secrets.clone();
                let mut c = AcpClient::start(agent, &spec, &cwd, self.cfg.mode_for(&spec), ask, Some((self.gate.clone(), self.vault.clone())), &*secrets)?;
                c.open_session(None)?;
                Arc::new(Mutex::new(c))
            }
        };
        let label = name.clone().unwrap_or_else(|| {
            static N: AtomicU64 = AtomicU64::new(1);
            format!("{agent}-{}", N.fetch_add(1, Ordering::SeqCst))
        });
        let key = format!("{prefix}{label}");
        {
            let mut p = pool().lock().unwrap();
            if !p.iter().any(|(k, _, _)| *k == key) {
                p.push((key.clone(), cwd.clone(), client.clone()));
                while p.len() > POOL_MAX {
                    let (_, _, old) = p.remove(0);
                    std::thread::spawn(move || old.lock().unwrap().close());
                }
            }
        }
        let c = client.lock().unwrap();
        let host = ctx.host.clone();
        let tag = agent.to_string();
        c.set_progress(Some(Arc::new(move |u: &Value| {
            if let Some(line) = describe_update(u) {
                host.progress(&format!("[{tag}] {line}\n"));
            }
        })));
        let timeout = Duration::from_secs(input["timeout_secs"].as_u64().or(self.cfg.timeout_secs).unwrap_or(1800).max(1));
        let r = c.prompt(prompt, &ctx.cancel, timeout);
        c.set_progress(None);
        let out = r.map(|t| render_turn(&c, &t, &label));
        if close || out.is_err() || !c.is_alive() {
            drop(c);
            pool().lock().unwrap().retain(|(k, _, _)| *k != key);
            client.lock().unwrap().close();
            return out.map(|s| format!("{s}\n\n(session closed)"));
        }
        out.map(|s| format!("{s}\n\n(continue with session: \"{label}\")"))
    }
}

pub fn is_yes(a: &str) -> bool {
    matches!(a.trim().to_lowercase().as_str(), "y" | "yes" | "allow" | "ok" | "是" | "好" | "允許" | "可以")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> Option<PathBuf> {
        let p = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/e2e/fake_acp_agent.py"));
        (p.exists() && Command::new("python3").arg("-c").arg("1").output().is_ok_and(|o| o.status.success())).then_some(p)
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-acpc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    fn start(script: &Path, cwd: &Path, mode: PermissionMode, answer: bool) -> AcpClient {
        let spec = AgentSpec { command: "python3".into(), args: vec!["-I".into(), script.to_string_lossy().into()], ..Default::default() };
        let mut c = AcpClient::start("fake", &spec, cwd, mode, Arc::new(move |_| answer), None, &|s| s.to_string()).unwrap();
        c.open_session(None).unwrap();
        c
    }

    #[test]
    fn config_presets_and_modes() {
        let c = AcpConfig::parse(&toml::from_str("permission_mode = \"deny-all\"\n[agents.mine]\ncommand = \"x\"\nargs = [\"--acp\"]\n").unwrap()).unwrap();
        assert_eq!(c.agent("mine").unwrap().args, ["--acp"]);
        assert_eq!(c.agent("claude-code").unwrap().args[1], "@agentclientprotocol/claude-agent-acp");
        assert_eq!(c.agent("gemini").unwrap().args, ["--experimental-acp"]);
        let q = c.agent("qoder").unwrap();
        assert_eq!(q.command, "qodercli");
        assert_eq!(q.args, vec!["--acp".to_string()]);
        assert!(c.agent("nope").unwrap_err().contains("codex"));
        assert_eq!(c.mode_for(&c.agent("mine").unwrap()), PermissionMode::DenyAll);
        assert!(AcpConfig::parse(&toml::from_str("permission_mode = \"yolo\"").unwrap()).is_err());
        assert!(AcpConfig::parse(&toml::from_str("[agents.x]\nargs = []").unwrap()).is_err());
        assert_eq!(command_line(&AgentSpec { command: "a b".into(), args: vec!["-y".into(), "it's".into()], ..Default::default() }), "'a b' -y 'it'\\''s'");
    }

    #[cfg(unix)]
    #[test]
    fn confinement() {
        let d = tmp("conf");
        let st = State { agent: "a".into(), cwd: d.clone(), mode: PermissionMode::ApproveAll, ask: Arc::new(|_| false), gate: None, terms: Mutex::default(), turn: Mutex::default(), progress: Mutex::new(None), cancelled: AtomicBool::new(false) };
        assert!(confined(&st, &d.join("x/y.txt").to_string_lossy()).is_ok());
        assert!(confined(&st, "rel.txt").is_ok());
        assert!(confined(&st, "/etc/passwd").is_err());
        assert!(confined(&st, &d.join("../escape").to_string_lossy()).is_err());
        std::os::unix::fs::symlink("/etc", d.join("link")).unwrap();
        assert!(confined(&st, &d.join("link/passwd").to_string_lossy()).is_err(), "symlinks out are refused");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn drives_a_fake_agent_through_fs_terminal_and_permissions() {
        let Some(script) = fake() else { return };
        let d = tmp("drive");
        std::fs::write(d.join("in.txt"), "line1\nline2\nline3\n").unwrap();
        let c = start(&script, &d, PermissionMode::ApproveAll, false);
        assert_eq!(c.agent_info["name"], "fake-acp");
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let s2 = seen.clone();
        c.set_progress(Some(Arc::new(move |u: &Value| s2.lock().unwrap().push(u["sessionUpdate"].as_str().unwrap_or("").to_string()))));
        let t = c.prompt(&format!("read:{}", d.join("in.txt").display()), &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("line2") && !t.text.contains("line1"), "{t:?}");
        assert!(seen.lock().unwrap().iter().any(|u| u == "tool_call"));
        let t = c.prompt(&format!("write:{}:hello", d.join("sub/out.txt").display()), &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("wrote"), "{t:?}");
        assert_eq!(std::fs::read_to_string(d.join("sub/out.txt")).unwrap(), "hello");
        let t = c.prompt("write:/etc/seagent-should-not-exist:x", &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("error") && t.text.contains("outside"), "{t:?}");
        let t = c.prompt("run:echo hi-from-terminal; exit 3", &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("hi-from-terminal") && t.text.contains("exit 3"), "{t:?}");
        assert_eq!(t.stop_reason, "end_turn");
        let t = c.prompt("slow", &Cancel::new(), Duration::from_secs(1)).unwrap();
        assert_eq!(t.stop_reason, "cancelled", "a timeout cancels the turn");
        c.close();

        // approve-reads: writes go to the human (who says no here), reads pass.
        let c = start(&script, &d, PermissionMode::ApproveReads, false);
        let t = c.prompt(&format!("write:{}:nope", d.join("denied.txt").display()), &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("permission rejected") && !d.join("denied.txt").exists(), "{t:?}");
        assert!(t.permissions.iter().any(|p| p.starts_with("denied")), "{t:?}");
        let t = c.prompt(&format!("read:{}", d.join("in.txt").display()), &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("line2"), "{t:?}");
        let t = c.prompt("run:echo x", &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("error"), "terminal needs the human too: {t:?}");
        drop(c);

        // deny-all: no write capability advertised, permission rejected.
        let c = start(&script, &d, PermissionMode::DenyAll, true);
        let t = c.prompt(&format!("write:{}:nope", d.join("denied.txt").display()), &Cancel::new(), Duration::from_secs(30)).unwrap();
        assert!(t.text.contains("permission rejected"), "{t:?}");
        assert!(!d.join("denied.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
