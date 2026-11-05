//! Agent Client Protocol (ACP v1) backends: `copilot --acp --stdio` driven as a runtime.
//! Hermes `agent/copilot_acp_client.py`, `plugins/model-providers/copilot-acp`.
//!
//! One short-lived ACP session per request: `initialize` → `session/new` →
//! (`session/set_config_option` | `session/set_model`) → `session/prompt`, streaming
//! `session/update` notifications (`agent_message_chunk`, `agent_thought_chunk`) and
//! answering the agent's `fs/read_text_file`, `fs/write_text_file` and
//! `session/request_permission` requests. The agent runs its own tools, so seagent's tool
//! schemas travel INSIDE the prompt (the `<tool_call>` contract) rather than on the wire.

use crate::{finalize_usage, ProviderConfig};
use seagent_core::*;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One budget for the WHOLE session (upstream `_DEFAULT_TIMEOUT_SECONDS`), not per request.
const DEFAULT_TIMEOUT_SECS: u64 = 900;
/// Upstream `CopilotACPClient.list_models` probes with a short timeout.
const DISCOVERY_TIMEOUT_SECS: u64 = 15;
/// Lines of stderr kept for diagnostics (upstream `deque(maxlen=40)`).
const STDERR_TAIL_LINES: usize = 40;
/// Stderr fingerprint of the deprecated `gh copilot` extension: BOTH the product name AND
/// a deprecation marker (the new `@github/copilot` CLI legitimately mentions "copilot-cli").
const DEPRECATION_REQUIRED: &str = "gh-copilot";
const DEPRECATION_MARKERS: &[&str] = &["has been deprecated", "no commands will be executed"];

/// Upstream `_PROMPT_PREAMBLE`.
const PROMPT_PREAMBLE: &[&str] = &[
    "You are being used as the active ACP agent backend for seagent.",
    "Use ACP capabilities to complete tasks.",
    "IMPORTANT: If you take an action with a tool, you MUST output tool calls using <tool_call>{...}</tool_call> blocks with JSON exactly in OpenAI function-call shape.",
    "If no tool is needed, answer normally.",
];

/// Upstream `agent/acp_openai_bridge.TOOL_CALL_CONTRACT`.
const TOOL_CALL_CONTRACT: &str = "Available tools (OpenAI function schema). When using a tool, emit ONLY <tool_call>{...}</tool_call> with one JSON object containing id/type/function{name,arguments}. arguments must be a JSON string.";

/// Upstream `_DEPRECATED_CLI_ERROR`, re-pointed at seagent's provider config.
const DEPRECATED_CLI_ERROR: &str = "seagent ACP mode requires the NEW GitHub Copilot CLI (github.com/github/copilot-cli), but the binary it just spawned is the deprecated `gh copilot` extension.\n\nInstall the new CLI:\n  npm install -g @github/copilot\n  # then verify with: copilot --help\n\nIf `copilot` already resolves to the new CLI but you still see this, point seagent at it explicitly in the provider config:\n  [providers.copilot-acp]\n  command = \"/path/to/new/copilot\"\n\nAlternative: use the `copilot` provider (no ACP, hits the Copilot API directly with a Copilot subscription token).\n\nOriginal error:\n";

pub struct CopilotAcp {
    id: String,
    command: String,
    args: Vec<String>,
    /// The session workspace (upstream `acp_cwd`): the ACP child's cwd and the root the
    /// agent's `fs/*` requests may touch.
    cwd: PathBuf,
    timeout: Duration,
    allow_write: bool,
}

impl CopilotAcp {
    pub fn new(cfg: &ProviderConfig) -> Result<CopilotAcp, String> {
        let cwd = std::env::current_dir().map_err(|e| format!("provider `{}`: cwd: {e}", cfg.id))?;
        Ok(CopilotAcp {
            id: cfg.id.clone(),
            command: cfg.command.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| "copilot".into()),
            args: if cfg.args.is_empty() {
                vec!["--acp".into(), "--stdio".into()]
            } else {
                cfg.args.clone()
            },
            cwd: realpath(&cwd),
            timeout: Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1)),
            allow_write: !cfg.has_quirk("read_only"),
        })
    }

    /// Spawn one ACP agent process with piped stdio; stderr is tailed for diagnostics.
    fn spawn(&self) -> Result<Rpc, ProviderError> {
        if self.acp_supported() == Some(false) {
            let preview = if self.args.is_empty() {
                "(none)".to_string()
            } else {
                self.args.iter().take(3).cloned().collect::<Vec<_>>().join(" ")
            };
            return Err(ProviderError::new(
                ProviderErrorKind::BadRequest,
                format!(
                    "ACP transport not supported by '{}': `{}` is rejected as an unknown option. This usually means the CLI is an older release or a different tool than expected. Install a CLI that ships with --acp support (e.g. `@github/copilot` late 2025+), or set the provider's `command`/`args` to a working pair.",
                    self.command, preview
                ),
            ));
        }
        let mut child = Command::new(&self.command)
            .args(&self.args)
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::Network,
                    format!(
                        "{}: cannot start ACP command `{}`: {e} (install GitHub Copilot CLI or set the provider's `command`)",
                        self.id, self.command
                    ),
                )
            })?;
        let stdin = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let stderr = Arc::new(Mutex::new(Tail::default()));
        let tail = Arc::clone(&stderr);
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                let mut t = tail.lock().unwrap();
                if t.lines.len() == STDERR_TAIL_LINES {
                    t.lines.pop_front();
                }
                t.lines.push_back(l);
            }
            tail.lock().unwrap().eof = true;
        });
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&l) {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Rpc { child, stdin, rx, stderr, next: 0 })
    }

    /// Tri-state `--acp` probe (upstream `_acp_supported`): `Some(false)` means `--help` ran
    /// cleanly without advertising `--acp`, so the spawn is fast-failed instead of waiting the
    /// full timeout for stdout that never arrives. Cached per command, definitive verdicts only.
    fn acp_supported(&self) -> Option<bool> {
        if !self.args.iter().any(|a| a == "--acp") {
            return Some(true); // custom transport: nothing to probe
        }
        static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(v) = cache.lock().unwrap().get(&self.command).copied() {
            return Some(v);
        }
        let mut child = Command::new(&self.command)
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let out = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut BufReader::new(out), &mut s);
            s
        });
        let end = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(25)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let help = reader.join().unwrap_or_default();
        if !status?.success() {
            return None;
        }
        let verdict = advertises_acp(&help);
        cache.lock().unwrap().insert(self.command.clone(), verdict);
        Some(verdict)
    }

    /// `initialize` + `session/new`; returns the `session/new` result.
    fn open(
        &self,
        rpc: &mut Rpc,
        deadline: Instant,
        cancel: &Cancel,
        on: &mut dyn FnMut(&mut Rpc, Value) -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError> {
        let init = json!({
            "protocolVersion": 1,
            "clientCapabilities": {"fs": {"readTextFile": true, "writeTextFile": true}},
            "clientInfo": {"name": "seagent", "title": "seagent", "version": env!("CARGO_PKG_VERSION")},
        });
        let id = rpc.request("initialize", init)?;
        rpc.wait(id, deadline, cancel, on)?;
        // Upstream sends no `initialized` notification: the initialize response completes it.
        let id = rpc.request(
            "session/new",
            json!({"cwd": self.cwd.to_string_lossy(), "mcpServers": []}),
        )?;
        let session = rpc.wait(id, deadline, cancel, on)?;
        if session["sessionId"].as_str().unwrap_or("").trim().is_empty() {
            return Err(ProviderError::new(
                ProviderErrorKind::Protocol,
                "Copilot ACP did not return a sessionId.",
            ));
        }
        Ok(session)
    }

    /// Enabled model ids advertised by a short-lived authenticated session (upstream `list_models`).
    /// File requests are refused for the whole discovery: it writes nothing.
    fn session_models(&self) -> Result<Vec<String>, ProviderError> {
        let mut rpc = self.spawn()?;
        let deadline = Instant::now() + self.timeout.min(Duration::from_secs(DISCOVERY_TIMEOUT_SECS));
        let mut sink = |_: StreamEvent| {};
        let stream = std::cell::Cell::new(false);
        let mut turn = Turn {
            cwd: self.cwd.clone(),
            allow_write: false,
            allow_files: false,
            stream: &stream,
            text: String::new(),
            on_event: &mut sink,
        };
        let mut on = |r: &mut Rpc, v: Value| turn.handle(r, &v);
        let session = self.open(&mut rpc, deadline, &Cancel::new(), &mut on)?;
        Ok(session_model_ids(&session))
    }
}

/// Model ids the ACP agent advertises (upstream `CopilotACPClient.list_models`).
pub fn models(cfg: &ProviderConfig) -> Result<Vec<String>, String> {
    CopilotAcp::new(cfg)?.session_models().map_err(|e| e.message)
}

/// Whether `--help` text advertises the `--acp` flag token (tolerates `[--acp]` / `--acp=x`).
fn advertises_acp(help: &str) -> bool {
    help.match_indices("--acp").any(|(i, _)| {
        let before = help[..i].chars().next_back();
        let after = help[i + "--acp".len()..].chars().next();
        let ok_before = !matches!(before, Some(c) if !(c.is_whitespace() || c == '['));
        let ok_after = !matches!(after, Some(c) if !(c.is_whitespace() || c == '=' || c == ']' || c == ','));
        ok_before && ok_after
    })
}

/// True iff stderr looks like the deprecated gh-copilot extension's banner.
fn is_deprecated_banner(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains(DEPRECATION_REQUIRED) && DEPRECATION_MARKERS.iter().any(|m| lower.contains(m))
}

#[derive(Default)]
struct Tail {
    lines: VecDeque<String>,
    eof: bool,
}

/// One ACP session's pipes: a JSON-lines reader thread, the stderr tail, the child itself.
struct Rpc {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
    stderr: Arc<Mutex<Tail>>,
    next: u64,
}

impl Rpc {
    fn send(&mut self, v: &Value) -> Result<(), ProviderError> {
        writeln!(self.stdin, "{v}")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| ProviderError::new(ProviderErrorKind::Network, format!("copilot acp stdin: {e}")))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<u64, ProviderError> {
        self.next += 1;
        let id = self.next;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        Ok(id)
    }

    /// Wait for the response to `id`, handing notifications and server→client requests to `on`.
    fn wait(
        &mut self,
        id: u64,
        deadline: Instant,
        cancel: &Cancel,
        on: &mut dyn FnMut(&mut Rpc, Value) -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError> {
        loop {
            let v = self.recv(deadline, cancel)?;
            if v.get("method").is_none() && v["id"].as_u64() == Some(id) {
                if let Some(e) = v.get("error") {
                    return Err(ProviderError::new(
                        ProviderErrorKind::BadRequest,
                        format!("Copilot ACP request failed: {}", e["message"].as_str().unwrap_or("error")),
                    ));
                }
                return Ok(v["result"].clone());
            }
            on(self, v)?;
        }
    }

    fn recv(&mut self, deadline: Instant, cancel: &Cancel) -> Result<Value, ProviderError> {
        loop {
            if cancel.is_cancelled() {
                return Err(ProviderError::new(ProviderErrorKind::Cancelled, "cancelled"));
            }
            if Instant::now() > deadline {
                return Err(ProviderError::new(
                    ProviderErrorKind::Timeout,
                    "Copilot ACP timed out waiting for the agent.",
                ));
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(v) => return Ok(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.child.try_wait().is_ok_and(|s| s.is_some()) {
                        return Err(self.exit_error());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.exit_error()),
            }
        }
    }

    /// A dead CLI: report the crash text (or the deprecation banner) rather than a bare exit code.
    fn exit_error(&mut self) -> ProviderError {
        // The stderr pump can still hold the crash text when stdout first hits EOF; wait for
        // its EOF (upstream joins it for 1s) so a dead CLI is not reported as a Timeout.
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            if self.stderr.lock().unwrap().eof || Instant::now() > end {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = self
            .stderr
            .lock()
            .unwrap()
            .lines
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let text = text.trim().to_string();
        let _ = self.child.kill();
        let status = self.child.wait();
        if is_deprecated_banner(&text) {
            return ProviderError::new(
                ProviderErrorKind::BadRequest,
                format!("{DEPRECATED_CLI_ERROR}{text}"),
            );
        }
        let why = if text.is_empty() {
            match status {
                Ok(s) => format!("exit code {s}"),
                Err(e) => e.to_string(),
            }
        } else {
            text
        };
        ProviderError::new(
            ProviderErrorKind::Server,
            format!("Copilot ACP process exited early: {why}"),
        )
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// State of one ACP turn: the files it may touch, the text it streamed so far.
struct Turn<'a> {
    cwd: PathBuf,
    allow_write: bool,
    /// False only during model discovery (upstream `allow_file_requests=False`).
    allow_files: bool,
    /// Chunks are collected from the start but only forwarded once the prompt is running.
    stream: &'a std::cell::Cell<bool>,
    text: String,
    on_event: &'a mut dyn FnMut(StreamEvent),
}

impl Turn<'_> {
    /// Consume one server→client message (upstream `_handle_server_message`).
    fn handle(&mut self, r: &mut Rpc, v: &Value) -> Result<(), ProviderError> {
        let Some(method) = v["method"].as_str() else {
            return Ok(());
        };
        if method == "session/update" {
            let update = &v["params"]["update"];
            let chunk = update["content"]["text"].as_str().unwrap_or("");
            let stream = self.stream.get();
            if chunk.is_empty() {
                return Ok(());
            }
            match update["sessionUpdate"].as_str().unwrap_or("").trim() {
                "agent_message_chunk" => {
                    self.text.push_str(chunk);
                    if stream {
                        (self.on_event)(StreamEvent::TextDelta(chunk.into()));
                    }
                }
                "agent_thought_chunk" if stream => {
                    (self.on_event)(StreamEvent::ThinkingDelta(chunk.into()));
                }
                _ => {}
            }
            return Ok(());
        }
        let Some(id) = v.get("id").cloned() else {
            return Ok(());
        };
        let reply = match method {
            "session/request_permission" => {
                // No human channel here: cancelling is the fail-closed answer.
                json!({"jsonrpc": "2.0", "id": id, "result": {"outcome": {"outcome": "cancelled"}}})
            }
            "fs/read_text_file" | "fs/write_text_file" => {
                if !self.allow_files {
                    rpc_error(id, -32601, "File access is unavailable during model discovery.")
                } else {
                    let params = &v["params"];
                    let res = if method == "fs/read_text_file" {
                        fs_read(params, &self.cwd)
                    } else {
                        fs_write(params, &self.cwd, self.allow_write)
                    };
                    match res {
                        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                        Err(e) => rpc_error(id, -32602, &e),
                    }
                }
            }
            other => rpc_error(id, -32601, &format!("ACP client method '{other}' is not supported by seagent.")),
        };
        r.send(&reply)
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn fs_read(params: &Value, cwd: &Path) -> Result<Value, String> {
    let path = within_cwd(params["path"].as_str().unwrap_or(""), cwd, "Read")?;
    if let Some(why) = read_denied(&path) {
        return Err(why);
    }
    let mut content = match std::fs::read_to_string(&path) {
        Ok(c) => c.strip_prefix('\u{feff}').unwrap_or(&c).to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("Read failed: {e}")),
    };
    if let Some(line) = params["line"].as_u64().filter(|l| *l > 1) {
        let take = params["limit"].as_u64().filter(|l| *l > 0).map(|l| l as usize);
        content = content
            .split_inclusive('\n')
            .skip((line - 1) as usize)
            .take(take.unwrap_or(usize::MAX))
            .collect();
    }
    Ok(json!({"content": content}))
}

fn fs_write(params: &Value, cwd: &Path, allow_write: bool) -> Result<Value, String> {
    let path = within_cwd(params["path"].as_str().unwrap_or(""), cwd, "Write")?;
    if !allow_write {
        return Err(format!(
            "Write denied: '{}' cannot be written because this provider is configured `read_only`.",
            path.display()
        ));
    }
    if write_needs_approval(&path) {
        // Soft-gated for interactive tools; the ACP bridge has no human channel → fail closed.
        return Err(format!(
            "Write denied: '{}' requires interactive approval and cannot be written through the ACP file bridge.",
            path.display()
        ));
    }
    if let Some(why) = write_denied(&path) {
        return Err(why);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Write failed: {e}"))?;
    }
    std::fs::write(&path, params["content"].as_str().unwrap_or(""))
        .map_err(|e| format!("Write failed: {e}"))?;
    Ok(Value::Null)
}

/// Upstream `_ensure_path_within_cwd`: the NT-namespace check runs on the RAW string (resolving
/// such a path is the NTLM-leak trigger), then absolute-only, then containment in the session cwd.
fn within_cwd(raw: &str, cwd: &Path, verb: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    let lower = raw.to_ascii_lowercase();
    let nt = ["\\\\?\\", "\\\\.\\", "\\??\\", "//?/", "//./"]
        .iter()
        .any(|p| lower.starts_with(p))
        || lower.contains("globalroot");
    if nt {
        return Err(format!(
            "{verb} denied: '{raw}' uses a Windows NT/device namespace prefix (\\??\\, \\\\.\\, \\\\?\\UNC\\, or GLOBALROOT). These paths bypass normal path normalization and can trigger outbound SMB authentication (NTLM credential leak) merely by being resolved. Use a normal absolute path instead."
        ));
    }
    if !Path::new(raw).is_absolute() {
        return Err("ACP file-system paths must be absolute.".into());
    }
    let resolved = realpath(Path::new(raw));
    let root = realpath(cwd);
    if !resolved.starts_with(&root) {
        return Err(format!(
            "Path '{}' is outside the session cwd '{}'.",
            resolved.display(),
            root.display()
        ));
    }
    Ok(resolved)
}

/// `realpath` that also works for paths that do not exist yet (deepest existing ancestor).
fn realpath(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for t in tail.iter().rev() {
                out.push(t);
            }
            return normalize(&out);
        }
        match (cur.file_name().map(|f| f.to_os_string()), cur.parent()) {
            (Some(f), Some(parent)) => {
                tail.push(f);
                cur = parent.to_path_buf();
            }
            _ => return normalize(p),
        }
    }
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Secret-bearing project env files (upstream `_BLOCKED_PROJECT_ENV_BASENAMES`).
const ENV_BASENAMES: &[&str] = &[".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.staging", ".envrc"];
/// Home files that must never be written (upstream `build_write_denied_paths`).
const HOME_WRITE_DENIED: &[&str] = &[
    ".ssh/authorized_keys",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
];
/// Home credential directories (seagent-security `HOME_CREDENTIAL_DIRS`).
const HOME_CREDENTIAL_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh", ".config/gcloud"];

/// Read denials at the ACP boundary. seagent's full policy lives in `seagent-security` (which
/// `seagent-model` cannot depend on); this is the part of the upstream list an agent hits.
fn read_denied(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    ENV_BASENAMES.contains(&name.as_str()).then(|| {
        format!(
            "Read denied: {} is a secret-bearing environment file and cannot be read through the ACP file bridge.",
            path.display()
        )
    })
}

/// Write denials at the ACP boundary (see [`read_denied`]).
fn write_denied(path: &Path) -> Option<String> {
    let rel = home_relative(path)?;
    let hit = HOME_WRITE_DENIED.iter().any(|p| rel == *p)
        || HOME_CREDENTIAL_DIRS
            .iter()
            .any(|d| rel == *d || rel.starts_with(&format!("{d}/")));
    hit.then(|| {
        format!(
            "Write denied: '{}' is a protected system/credential file.",
            path.display()
        )
    })
}

/// Approval-gated paths: they hold no key bytes but can run code (`~/.ssh/config` ProxyCommand).
fn write_needs_approval(path: &Path) -> bool {
    home_relative(path).is_some_and(|rel| rel == ".ssh/config")
}

fn home_relative(path: &Path) -> Option<String> {
    let home = std::env::var_os("HOME")?;
    let rel = path.strip_prefix(realpath(Path::new(&home))).ok()?;
    Some(rel.to_string_lossy().replace('\\', "/"))
}

/// Enabled ids of `entries` whose `_meta.copilotEnablement` is not `disabled`.
fn enabled_ids(entries: &Value, key: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries.as_array().map(Vec::as_slice).unwrap_or_default() {
        let value = entry[key].as_str().unwrap_or("").trim();
        if value.is_empty() || !seen.insert(value.to_string()) {
            continue;
        }
        if entry["_meta"]["copilotEnablement"]
            .as_str()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("disabled")
        {
            continue;
        }
        out.push(value.to_string());
    }
    out
}

/// The session's model `configOptions` entry (ACP v1 stable shape).
fn model_config_option(session: &Value) -> Option<&Value> {
    session["configOptions"]
        .as_array()?
        .iter()
        .find(|o| o["category"].as_str() == Some("model") || o["id"].as_str() == Some("model"))
}

/// Account-authorized model ids advertised by `session/new`, v1 or the legacy extension.
fn session_model_ids(session: &Value) -> Vec<String> {
    match model_config_option(session) {
        Some(o) => enabled_ids(&o["options"], "value"),
        None => enabled_ids(&session["models"]["availableModels"], "modelId"),
    }
}

/// Upstream `_model_selection_request`: the stable v1 `session/set_config_option`, else
/// Copilot's pre-stabilization `session/set_model`. A reported model list is authoritative:
/// unknown and policy-disabled ids return `None` instead of being sent.
fn model_selection_request(session: &Value, requested: &str) -> Option<(&'static str, Value)> {
    let session_id = session["sessionId"].as_str().unwrap_or("").trim().to_string();
    let requested = requested.trim();
    if session_id.is_empty() || requested.is_empty() || requested == "copilot-acp" {
        return None;
    }
    if let Some(option) = model_config_option(session) {
        if !enabled_ids(&option["options"], "value").iter().any(|m| m == requested) {
            return None;
        }
        let config_id = option["id"].as_str().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("model");
        return Some((
            "session/set_config_option",
            json!({"sessionId": session_id, "configId": config_id, "value": requested}),
        ));
    }
    let available = enabled_ids(&session["models"]["availableModels"], "modelId");
    if !available.is_empty() && !available.iter().any(|m| m == requested) {
        return None;
    }
    Some(("session/set_model", json!({"sessionId": session_id, "modelId": requested})))
}

/// Upstream `_format_messages_as_prompt`: one ACP prompt carrying seagent's system segments, the
/// ACP preamble, the forwarded tool schemas and the rendered conversation.
fn render_prompt(req: &ModelRequest) -> String {
    let mut sections: Vec<String> = Vec::new();
    let sys = req.system_text();
    if !sys.trim().is_empty() {
        sections.push(format!("<instructions>\n{sys}\n</instructions>"));
    }
    sections.extend(PROMPT_PREAMBLE.iter().map(|s| (*s).to_string()));
    if !req.tools.is_empty() {
        let specs: Vec<Value> = req
            .tools
            .iter()
            .map(|t| json!({"name": t.name, "description": t.description, "parameters": t.input_schema}))
            .collect();
        sections.push(format!("{TOOL_CALL_CONTRACT}\n{}", Value::Array(specs)));
    }
    let transcript = crate::transcript(req);
    if !transcript.trim().is_empty() {
        sections.push(format!("Conversation transcript:\n\n{}", transcript.trim_end()));
    }
    sections.push("Continue the conversation from the latest user request.".into());
    sections.join("\n\n")
}

impl Provider for CopilotAcp {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        // The ACP agent runs its own tools; seagent's schemas travel inside the prompt.
        ModelCaps {
            tools: false,
            ..crate::caps_for(model)
        }
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let mut rpc = self.spawn()?;
        let deadline = Instant::now() + self.timeout;
        let stream = std::cell::Cell::new(false);
        let mut turn = Turn {
            cwd: self.cwd.clone(),
            allow_write: self.allow_write,
            allow_files: true,
            stream: &stream,
            text: String::new(),
            on_event,
        };
        let mut on = |r: &mut Rpc, v: Value| turn.handle(r, &v);
        let session = self.open(&mut rpc, deadline, cancel, &mut on)?;
        let session_id = session["sessionId"].as_str().unwrap_or("").trim().to_string();
        let requested = req.model.trim();
        if !requested.is_empty() && requested != "default" {
            match model_selection_request(&session, requested) {
                Some((method, params)) => {
                    let sent = rpc.request(method, params).and_then(|id| rpc.wait(id, deadline, cancel, &mut on));
                    match sent {
                        Ok(_) => {}
                        Err(e) if matches!(e.kind, ProviderErrorKind::Cancelled | ProviderErrorKind::Timeout) => {
                            return Err(e)
                        }
                        Err(e) => eprintln!(
                            "seagent: {}: model selection for `{requested}` failed; continuing with the session default: {e}",
                            self.id
                        ),
                    }
                }
                None => eprintln!(
                    "seagent: {}: ACP session does not offer model `{requested}`; using the session default.",
                    self.id
                ),
            }
        }
        stream.set(true);
        let prompt = json!({
            "sessionId": session_id,
            "prompt": [{"type": "text", "text": render_prompt(req)}],
        });
        let id = rpc.request("session/prompt", prompt)?;
        rpc.wait(id, deadline, cancel, &mut on)?;
        drop(on);
        let message = Message {
            role: Role::Assistant,
            content: vec![Block::Text {
                text: turn.text.trim_end().to_string(),
            }],
        };
        let usage = finalize_usage(None, req, &message);
        Ok(ModelResponse {
            message,
            stop: StopReason::EndTurn,
            usage,
            model: format!(
                "{}/{}",
                self.id,
                if requested.is_empty() { "default" } else { requested }
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake ACP agent: a `python3 -I` script written to a temp dir. `body` gets `RECORD`
    /// (a path the test reads back) substituted.
    fn fake(name: &str, body: &str) -> (ProviderConfig, PathBuf) {
        let d = seagent_core::tmp::scratch_path(format!("seagent-acp-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let record = d.join("record.json");
        let _ = std::fs::remove_file(&record);
        let script = d.join("fake.py");
        std::fs::write(
            &script,
            format!("RECORD = {record:?}\n{body}"),
        )
        .unwrap();
        let cfg = ProviderConfig {
            id: "copilot-acp".into(),
            format: crate::WireFormat::Acp,
            command: Some("python3".into()),
            args: vec!["-I".into(), script.to_string_lossy().into_owned()],
            ..Default::default()
        };
        (cfg, record)
    }

    fn request(model: &str) -> ModelRequest {
        ModelRequest {
            model: model.into(),
            system: vec![SystemSegment { id: "core".into(), text: "be brief".into(), cache: false }],
            messages: vec![Message::user("hi there")],
            tools: vec![ToolSchema {
                name: "read".into(),
                description: "read a file".into(),
                input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            }],
            max_tokens: 64,
            ..Default::default()
        }
    }

    const HAPPY: &str = r#"import json, sys
def out(o): print(json.dumps(o), flush=True)
for line in sys.stdin:
    m = json.loads(line)
    meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if meth == "initialize":
        assert p["protocolVersion"] == 1
        assert p["clientInfo"]["name"] == "seagent"
        assert p["clientCapabilities"]["fs"]["writeTextFile"] is True
        out({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1}})
    elif meth == "session/new":
        assert "cwd" in p and p["mcpServers"] == []
        out({"jsonrpc": "2.0", "id": mid, "result": {"sessionId": "s1", "configOptions": [
            {"id": "model", "category": "model", "options": [
                {"value": "gpt-5.5"}, {"value": "claude-sonnet-4.5"},
                {"value": "policy-off", "_meta": {"copilotEnablement": "disabled"}}]}]}})
    elif meth == "session/set_config_option":
        open(RECORD, "w").write(json.dumps({"method": meth, "params": p}))
        out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/prompt":
        assert p["sessionId"] == "s1"
        text = p["prompt"][0]["text"]
        assert p["prompt"][0]["type"] == "text"
        assert text.startswith("<instructions>\nbe brief\n</instructions>"), text
        assert "active ACP agent backend" in text
        assert '"name":"read"' in text and '"parameters"' in text
        assert "Conversation transcript:" in text and "User: hi there" in text
        out({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1",
            "update": {"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "hm "}}}})
        out({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1",
            "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "hel"}}}})
        out({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s1",
            "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "lo"}}}})
        out({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": "end_turn"}})
"#;

    #[test]
    fn streams_chunks_and_selects_model_via_config_option() {
        let (cfg, record) = fake("happy", HAPPY);
        let p = CopilotAcp::new(&cfg).unwrap();
        let mut events = Vec::new();
        let r = p.complete(&request("gpt-5.5"), &mut |e| events.push(e), &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "hello");
        assert_eq!(r.stop, StopReason::EndTurn);
        assert_eq!(r.model, "copilot-acp/gpt-5.5");
        assert_eq!(
            events,
            vec![
                StreamEvent::ThinkingDelta("hm ".into()),
                StreamEvent::TextDelta("hel".into()),
                StreamEvent::TextDelta("lo".into()),
            ]
        );
        assert!(r.usage.output_tokens > 0 && r.usage.estimated);
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        assert_eq!(rec["method"], "session/set_config_option");
        assert_eq!(rec["params"]["configId"], "model");
        assert_eq!(rec["params"]["value"], "gpt-5.5");
        assert_eq!(rec["params"]["sessionId"], "s1");
    }

    const LEGACY: &str = r#"import json, sys
def out(o): print(json.dumps(o), flush=True)
for line in sys.stdin:
    m = json.loads(line)
    meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if meth == "initialize": out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/new":
        out({"jsonrpc": "2.0", "id": mid, "result": {"sessionId": "s2", "models": {"availableModels": [
            {"modelId": "gpt-5.5"}, {"modelId": "off", "_meta": {"copilotEnablement": "disabled"}}]}}})
    elif meth == "session/set_model":
        open(RECORD, "w").write(json.dumps({"method": meth, "params": p}))
        out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/prompt":
        out({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s2",
            "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "ok"}}}})
        out({"jsonrpc": "2.0", "id": mid, "result": {}})
"#;

    #[test]
    fn legacy_session_set_model_fallback() {
        let (cfg, record) = fake("legacy", LEGACY);
        let p = CopilotAcp::new(&cfg).unwrap();
        let r = p.complete(&request("gpt-5.5"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "ok");
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        assert_eq!(rec["method"], "session/set_model");
        assert_eq!(rec["params"]["modelId"], "gpt-5.5");
        // A model the session did not advertise is never sent; the turn still runs on the default.
        std::fs::remove_file(&record).unwrap();
        let r = p.complete(&request("nope"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "ok");
        assert!(!record.exists());
    }

    /// The fake agent asks for a file inside the session cwd, one outside it, a write while the
    /// provider is `read_only`, and a permission; the test checks every reply.
    const SERVER_REQS: &str = r#"import json, sys
def out(o): print(json.dumps(o), flush=True)
prompt_id = None
pending = {}
cwd = sys.argv[1]
for line in sys.stdin:
    m = json.loads(line)
    meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if meth == "initialize": out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/new": out({"jsonrpc": "2.0", "id": mid, "result": {"sessionId": "s3"}})
    elif meth == "session/prompt":
        prompt_id = mid
        out({"jsonrpc": "2.0", "id": 501, "method": "fs/read_text_file", "params": {"path": cwd + "/Cargo.toml"}})
        out({"jsonrpc": "2.0", "id": 502, "method": "fs/read_text_file", "params": {"path": "/etc/hostname"}})
        out({"jsonrpc": "2.0", "id": 503, "method": "fs/write_text_file", "params": {"path": cwd + "/should-not-exist.txt", "content": "x"}})
        out({"jsonrpc": "2.0", "id": 504, "method": "session/request_permission", "params": {"sessionId": "s3", "options": []}})
        out({"jsonrpc": "2.0", "id": 505, "method": "terminal/create", "params": {}})
    elif meth is None and mid in (501, 502, 503, 504, 505):
        pending[str(mid)] = m
        if len(pending) == 5:
            open(RECORD, "w").write(json.dumps(pending))
            out({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "s3",
                "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "seen"}}}})
            out({"jsonrpc": "2.0", "id": prompt_id, "result": {}})
"#;

    #[test]
    fn answers_file_and_permission_requests() {
        let (mut cfg, record) = fake("fs", SERVER_REQS);
        let cwd = std::env::current_dir().unwrap();
        cfg.args.push(cwd.to_string_lossy().into_owned());
        cfg.quirks.push("read_only".into());
        let p = CopilotAcp::new(&cfg).unwrap();
        let r = p.complete(&request("default"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "seen");
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        let inside = rec["501"]["result"]["content"].as_str().unwrap();
        assert!(inside.contains("seagent-model"), "{inside}");
        let outside = rec["502"]["error"]["message"].as_str().unwrap();
        assert!(outside.contains("outside the session cwd"), "{outside}");
        assert_eq!(rec["502"]["error"]["code"], -32602);
        let denied = rec["503"]["error"]["message"].as_str().unwrap();
        assert!(denied.contains("read_only"), "{denied}");
        assert!(!cwd.join("should-not-exist.txt").exists());
        assert_eq!(rec["504"]["result"]["outcome"]["outcome"], "cancelled");
        assert_eq!(rec["505"]["error"]["code"], -32601);
        assert!(rec["505"]["error"]["message"].as_str().unwrap().contains("not supported by seagent"));
    }

    const DEPRECATED: &str = r#"import sys
sys.stderr.write("gh-copilot: this extension has been deprecated and no commands will be executed.\n")
sys.stderr.flush()
sys.exit(1)
"#;

    #[test]
    fn deprecated_gh_copilot_banner_is_reported() {
        let (cfg, _) = fake("deprecated", DEPRECATED);
        let p = CopilotAcp::new(&cfg).unwrap();
        let e = p.complete(&request("default"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::BadRequest);
        assert!(e.message.contains("@github/copilot"), "{}", e.message);
        assert!(e.message.contains("deprecated `gh copilot` extension"), "{}", e.message);
        assert!(e.message.contains("no commands will be executed"), "{}", e.message);
    }

    #[test]
    fn deprecated_banner_requires_both_fingerprint_halves() {
        assert!(is_deprecated_banner("gh-copilot: has been deprecated"));
        assert!(!is_deprecated_banner("gh-copilot: v2.0 installed"));
        assert!(!is_deprecated_banner("copilot-cli: has been deprecated"));
    }

    /// `session/new` advertises a file request before answering: discovery must refuse it.
    const DISCOVER: &str = r#"import json, sys
def out(o): print(json.dumps(o), flush=True)
pending_new = None
for line in sys.stdin:
    m = json.loads(line)
    meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if meth == "initialize": out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/new":
        pending_new = mid
        out({"jsonrpc": "2.0", "id": 700, "method": "fs/read_text_file", "params": {"path": "/etc/hostname"}})
    elif meth is None and mid == 700:
        open(RECORD, "w").write(json.dumps(m))
        out({"jsonrpc": "2.0", "id": pending_new, "result": {"sessionId": "s4", "configOptions": [
            {"id": "model", "category": "model", "options": [
                {"value": "gpt-5.5"}, {"value": "off", "_meta": {"copilotEnablement": "disabled"}}]}]}})
"#;

    #[test]
    fn discovers_models_with_file_requests_disabled() {
        let (cfg, record) = fake("discover", DISCOVER);
        let p = CopilotAcp::new(&cfg).unwrap();
        assert_eq!(p.session_models().unwrap(), vec!["gpt-5.5".to_string()]);
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
        assert_eq!(rec["error"]["code"], -32601);
        assert!(rec["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unavailable during model discovery"));
    }

    const NO_SESSION: &str = r#"import json, sys
def out(o): print(json.dumps(o), flush=True)
for line in sys.stdin:
    m = json.loads(line)
    meth, mid = m.get("method"), m.get("id")
    if meth == "initialize": out({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif meth == "session/new": out({"jsonrpc": "2.0", "id": mid, "result": {"models": {}}})
"#;

    #[test]
    fn missing_session_id_is_reported() {
        let (cfg, _) = fake("nosession", NO_SESSION);
        let p = CopilotAcp::new(&cfg).unwrap();
        let e = p.complete(&request("default"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Protocol);
        assert!(e.message.contains("did not return a sessionId"), "{}", e.message);
    }

    /// A silent agent: the idle timeout and `Cancel` must both end the turn and kill the child.
    const SILENT: &str = r#"import sys
for line in sys.stdin:
    pass
"#;

    #[test]
    fn timeout_and_cancel_end_the_turn() {
        let (cfg, _) = fake("silent", SILENT);
        let cfg = ProviderConfig {
            idle_timeout_secs: Some(1),
            ..cfg
        };
        let p = CopilotAcp::new(&cfg).unwrap();
        let start = Instant::now();
        let e = p.complete(&request("default"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_secs(5));
        let cancel = Cancel::new();
        let flag = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            flag.cancel();
        });
        let start = Instant::now();
        let e = p.complete(&request("default"), &mut |_| {}, &cancel).unwrap_err();
        assert_eq!(e.kind, ProviderErrorKind::Cancelled);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
