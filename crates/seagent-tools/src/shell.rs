//! `shell`: run a bash script through the session's execution backend.
//!
//! Every call is handed to `seagent_core::exec::ExecBackend` (`crate::exec` decides which one:
//! local, OS sandbox, container, SSH host, cloud sandbox) instead of spawning `bash` here,
//! so `[exec]` / `[exec.sandbox]` / `/elevated` decide where commands run and how their
//! child is driven. Ported upstream behaviour:
//!
//! - `pty` (+ `rows`/`cols`): a pseudo-terminal for REPLs and TTY-only CLIs (OpenClaw
//!   `exec pty`, Hermes `terminal(pty=true)`); PTY queries are answered (`exec::ptyq`) and
//!   the transcript is rendered like a screen.
//! - `yield_ms` / `background`: a command still running when the yield expires is moved to
//!   the background **without being killed** and registered in `exec::process`, so the
//!   model gets a process handle plus the output so far instead of blocking (OpenClaw
//!   `yieldMs`/`background`, Hermes foreground→background promotion).
//! - `env`: per-call variables on top of `[exec] env`, credentials removed unless
//!   `env_passthrough` lists them (OpenClaw `exec env`).
//! - `cd` / `export` persist between calls through `exec::session` (Hermes local session
//!   snapshot) when the backend shares the host file system.
//! - ANSI escapes are stripped from the returned text (`[exec] strip_ansi`, Hermes
//!   `ansi_strip.py`).
//!
//! Unchanged: `[exec] sudo_password_secret` handling (command rewritten to `sudo -S`,
//! password fed on stdin), head/tail truncation, failure hints and the `[exit N]` footer.

use crate::exec::ansi;
use crate::exec::ptyq::PtyQueryResponder;
use crate::exec::sh_quote;
use seagent_core::exec::{ExecChild, ExecRequest, ExitInfo};
use seagent_core::tool::{arg_opt_str, arg_str};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::io::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: u64 = 120;
const MAX_TIMEOUT: u64 = 3600;
const HALF_CAP: usize = 512 * 1024;
/// After the main process exits, how long to wait for background children
/// that still hold the output pipes.
const DRAIN_GRACE: Duration = Duration::from_millis(500);
/// How long a stopped command may ignore SIGTERM before it is SIGKILLed.
const TERM_GRACE: Duration = Duration::from_secs(2);
/// Default terminal size for `pty`.
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;

/// Keeps the first and last HALF_CAP bytes of a stream.
#[derive(Default)]
struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
}

impl Capture {
    fn push(&mut self, data: &[u8]) {
        self.total += data.len();
        let room = HALF_CAP.saturating_sub(self.head.len());
        let (h, t) = data.split_at(room.min(data.len()));
        self.head.extend_from_slice(h);
        self.tail.extend_from_slice(t);
        if self.tail.len() > 2 * HALF_CAP {
            let cut = self.tail.len() - HALF_CAP;
            self.tail.drain(..cut);
        }
    }
    fn render(&self) -> String {
        let kept = self.head.len() + self.tail.len().min(HALF_CAP);
        if self.total <= kept {
            let mut all = self.head.clone();
            all.extend_from_slice(&self.tail);
            return String::from_utf8_lossy(&all).into_owned();
        }
        let tail = &self.tail[self.tail.len().saturating_sub(HALF_CAP)..];
        format!(
            "{}\n…[output truncated: {} bytes omitted of {} total]…\n{}",
            String::from_utf8_lossy(&self.head),
            self.total - self.head.len() - tail.len(),
            self.total,
            String::from_utf8_lossy(tail)
        )
    }
}

/// Feed one chunk through the PTY query responder and into the capture.
fn feed(cap: &mut Capture, resp: &mut Option<PtyQueryResponder>, child: &mut dyn ExecChild, data: &[u8]) {
    match resp {
        Some(r) => {
            let (out, reply) = r.process(data);
            cap.push(&out);
            if !reply.is_empty() {
                // Answer device-status / cursor-position probes so a TUI does not hang.
                let _ = child.write_stdin(&reply);
            }
        }
        None => cap.push(data),
    }
}

pub struct Shell;

impl Tool for Shell {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "shell".into(),
            description: {
                let d = "Run a bash command in the workspace. Returns combined stdout/stderr and exit code. `cd` and `export` persist between calls, `env` adds variables for this call, `pty` gives a terminal, and `yield_ms`/`background` return a process handle instead of blocking. Use {{secret:NAME}} for credentials.";
                // Windows / Android: say which shell actually runs (PowerShell needs its own syntax).
                match crate::exec::local::shell_note() {
                    Some(n) => format!("{d} {n}"),
                    None => d.to_string(),
                }
            },
            input_schema: json!({"type":"object","properties":{
                "command":{"type":"string"},
                "timeout_secs":{"type":"integer","minimum":1,"maximum":MAX_TIMEOUT,"default":DEFAULT_TIMEOUT},
                "cwd":{"type":"string","description":"Working directory (default: workspace, or the directory the last call left off in)"},
                "env":{"type":"object","additionalProperties":{"type":"string"},"description":"Environment variables for this command only (literal, no expansion); credentials are dropped unless config lists them"},
                "pty":{"type":"boolean","description":"Run under a pseudo-terminal: interactive CLIs, REPLs, programs that require a TTY"},
                "rows":{"type":"integer","minimum":1,"maximum":1000,"description":"Terminal rows with pty (default 24)"},
                "cols":{"type":"integer","minimum":1,"maximum":1000,"description":"Terminal columns with pty (default 80)"},
                "yield_ms":{"type":"integer","minimum":0,"description":"Return a process handle if the command is still running after this many milliseconds (0 = wait for it)"},
                "background":{"type":"boolean","description":"Start it and return immediately with the process handle; the command keeps running"},
                "elevated":{"type":"boolean","description":"Run on the host outside the sandbox (refused when [exec.sandbox] elevated = \"off\")"},
                "host":{"type":"string","enum":["auto","host","sandbox","gateway","node"],"description":"Where this command runs: auto (session route), host (this machine, outside the sandbox), sandbox/gateway (the sandbox backend), node (a paired node — use node_invoke instead)"}},
                "required":["command"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: true,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match arg_str(input, "command") {
            Ok(c) => vec![Effect::Exec { command: c.to_string() }],
            Err(_) => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let command = match arg_str(&input, "command") {
            Ok(c) if !c.trim().is_empty() => c,
            Ok(_) => return ToolOutput::err("command must not be empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let env_cfg = crate::exec::global();
        let timeout = match input.get("timeout_secs") {
            None | Some(Value::Null) => env_cfg.cfg.default_timeout.clamp(1, MAX_TIMEOUT),
            Some(v) => match v.as_u64() {
                Some(t) if (1..=MAX_TIMEOUT).contains(&t) => t,
                _ => return ToolOutput::err(format!("timeout_secs must be an integer in 1..={MAX_TIMEOUT}")),
            },
        };
        let call_env: Vec<(String, String)> = match parse_env(&input) {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let pty = match flag(&input, "pty") {
            Ok(b) => b,
            Err(e) => return ToolOutput::err(e),
        };
        let (rows, cols) = match term_size(&input) {
            Ok(s) => s,
            Err(e) => return ToolOutput::err(e),
        };
        let yield_ms = match opt_uint(&input, "yield_ms") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(e),
        };
        let background = match flag(&input, "background") {
            Ok(b) => b,
            Err(e) => return ToolOutput::err(e),
        };
        let requested = match arg_opt_str(&input, "cwd") {
            Some(c) if !c.trim().is_empty() => Some(ctx.resolve(c)),
            _ => None,
        };
        if let Some(c) = &requested {
            if !c.is_dir() {
                return ToolOutput::err(format!("cwd {} is not an existing directory", c.display()));
            }
        }
        let resolved = (ctx.secrets)(command);
        let sudo_secret = env_cfg.cfg.sudo_password_secret.clone();
        let lookup = |n: &str| {
            let ph = format!("{{{{secret:{n}}}}}");
            let v = (ctx.secrets)(&ph);
            if v != ph && !v.is_empty() {
                Some(v)
            } else {
                std::env::var(n).ok().filter(|s| !s.is_empty())
            }
        };
        let sudo = crate::exec::sudo::prepare(&resolved, &sudo_secret, &ctx.session_id, &lookup);
        // Secrets in `env` values are substituted here, at execution time, never earlier.
        let call_env: Vec<(String, String)> = call_env.into_iter().map(|(k, v)| (k, (ctx.secrets)(&v))).collect();
        // OpenClaw `exec` takes `elevated` and `host` per call; they only ever *ask* for the
        // host: `/elevated`, `[exec.sandbox] elevated = "off"` and the route still decide.
        let host = input.get("host").and_then(Value::as_str).map(String::from);
        if host.as_deref() == Some("node") {
            return ToolOutput::err("host=node: run it on the paired node with `node_invoke` (action=invoke, command=system.run, params={command})");
        }
        let want_host = input.get("elevated").and_then(Value::as_bool).unwrap_or(false) || host.as_deref() == Some("host");
        let elevated = match (want_host, host.as_deref()) {
            (_, Some("sandbox" | "gateway")) => false,
            _ => want_host || env_cfg.elevated(&ctx.session_id),
        };
        let backend = match crate::exec::backend_tool(ctx, elevated) {
            Ok(b) => b,
            Err(e) => return ToolOutput::err(format!("cannot run command: {e}")),
        };

        // ── script: unset credentials, session snapshot, command, snapshot dump ──
        let mut script = String::new();
        if env_cfg.cfg.scrub_env {
            // Same policy the old `Command`-based path applied with `envscrub::apply`: the
            // inherited credentials are gone before the command (and its snapshot) exist.
            // `unset` only takes shell identifiers; a blocked name that is not one
            // (`FOO-BAR-API-KEY`) cannot be unset here and is removed from the spawned child
            // instead (`exec::local::spawn_command`).
            let vars: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
            let blocked: Vec<String> = seagent_security::envscrub::blocked_names(vars.iter().map(|s| s.as_str()), seagent_security::envscrub::Surface::Terminal)
                .into_iter()
                .filter(|n| is_env_name(n))
                .collect();
            if !blocked.is_empty() {
                script.push_str(&format!("unset {} 2>/dev/null\n", blocked.join(" ")));
            }
        }
        let mut cwd = requested.clone().unwrap_or_else(|| ctx.workspace.clone());
        let skip: Vec<String> = call_env.iter().map(|(k, _)| k.clone()).collect();
        // Persistent `cd` / `export` (Hermes local session snapshot) only where the backend
        // sees the host file system: a remote sandbox would replay host paths.
        let mut snapshot: Option<Arc<std::sync::Mutex<crate::exec::ShellState>>> = None;
        if env_cfg.cfg.persistent_shell && backend.shares_host_fs() {
            let state = env_cfg.shell(&ctx.session_id, &*backend, &ctx.workspace);
            let mut s = state.lock().unwrap();
            let dir = s.set_state_dir(&ctx.home, &env_cfg.scope_key(&ctx.session_id, &ctx.workspace), &skip, env_cfg.cfg.scrub_env, &env_cfg.cfg.passthrough()).is_ok();
            if dir && s.ready() {
                if requested.is_none() {
                    if s.cwd.is_dir() {
                        cwd = s.cwd.clone();
                    } else {
                        // The last command deleted its own cwd (Hermes `_recover_cwd`).
                        s.cwd = ctx.workspace.clone();
                    }
                }
                script.push_str(&s.prologue(&cwd, &skip, env_cfg.cfg.scrub_env, &env_cfg.cfg.passthrough()));
                snapshot = Some(state.clone());
            }
        }
        script.push_str(&format!("eval {}\n__seagent_ec=$?\n", sh_quote(&sudo.command)));
        if let Some(state) = &snapshot {
            script.push_str(&state.lock().unwrap().epilogue(&skip));
        }
        script.push_str("exit $__seagent_ec\n");

        let req = ExecRequest {
            script,
            cwd: Some(cwd.clone()),
            env: {
                // C9: a sub-agent's processes get their own SEAGENT_HOME / TMPDIR (never inherit
                // the driver's). Applied last so nothing in `[exec] env` can re-point a child
                // at the real home.
                let mut env = env_cfg.child_env_for(&call_env);
                env.extend(ctx.host.sandbox_env());
                env
            },
            // A background process may be driven later (`process` write / submit).
            stdin: pty || background,
            stdin_data: sudo.stdin.as_ref().map(|s| s.as_bytes().to_vec()),
            pty: pty.then_some((rows, cols)),
            login: false,
            detach: false,
            log_file: None,
            exit_file: None,
        };
        // Attribute every group this call spawns to the session (C7 reaper registry).
        let _reaper = crate::exec::local::reap_scope(&ctx.home, &ctx.session_id, "shell");
        let (backend, mut child) = match crate::exec::spawn_tool(ctx, &req, elevated) {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(format!("cannot run command: {e}")),
        };

        // ── drive the child ──
        let mut cap = Capture::default();
        let mut resp = pty.then(|| PtyQueryResponder::new(rows, cols));
        let mut buf = [0u8; 16384];
        let started = Instant::now();
        let deadline = started + Duration::from_secs(timeout);
        let yield_at = yield_deadline(started, &env_cfg.cfg, timeout, yield_ms, background);
        let mut status: Option<ExitInfo> = None;
        let mut stopped: Option<&'static str> = None;
        let mut yielded = false;
        let mut eof = false;
        loop {
            match child.read(&mut buf, Duration::from_millis(20)) {
                Ok(0) => eof = true,
                Ok(n) => feed(&mut cap, &mut resp, child.as_mut(), &buf[..n]),
                Err(_) => {}
            }
            if let Ok(Some(st)) = child.try_wait() {
                status = Some(st);
                break;
            }
            let now = Instant::now();
            if ctx.cancel.is_cancelled() {
                stopped = Some("cancelled");
                break;
            }
            if now >= deadline {
                stopped = Some("timed out");
                break;
            }
            if yield_at.is_some_and(|y| now >= y) {
                yielded = true;
                break;
            }
            if eof {
                thread::sleep(Duration::from_millis(10));
            }
        }

        if yielded {
            // Hand the live child to the process registry: it keeps running (nothing calls
            // kill and the child is moved, not dropped) and the model gets a handle.
            let waited = yield_at.map(|y| y.saturating_duration_since(started).as_millis() as u64);
            return hand_off(ctx, &env_cfg, backend, child, cap, command, pty, (rows, cols), started, waited, background);
        }

        if stopped.is_some() {
            // SIGTERM the whole tree, then SIGKILL whatever ignored it.
            child.kill(false);
            let grace = Instant::now() + TERM_GRACE;
            while Instant::now() < grace && status.is_none() {
                if let Ok(Some(st)) = child.try_wait() {
                    status = Some(st);
                } else {
                    thread::sleep(Duration::from_millis(20));
                }
            }
            if status.is_none() {
                child.kill(true);
                let hard = Instant::now() + TERM_GRACE;
                while Instant::now() < hard && status.is_none() {
                    if let Ok(Some(st)) = child.try_wait() {
                        status = Some(st);
                    } else {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            let until = Instant::now() + Duration::from_millis(200);
            while Instant::now() < until {
                match child.read(&mut buf, Duration::from_millis(20)) {
                    Ok(0) => break,
                    Ok(n) => feed(&mut cap, &mut resp, child.as_mut(), &buf[..n]),
                    Err(_) => {}
                }
            }
        }

        // Collect what a finished command left in the pipe; a background grandchild that
        // still holds it only gets the grace period (its later output is not captured).
        let mut lingering = false;
        if status.is_some() && !eof {
            let until = Instant::now() + DRAIN_GRACE;
            let mut closed = false;
            while !closed && Instant::now() < until {
                match child.read(&mut buf, Duration::from_millis(20)) {
                    Ok(0) => closed = true,
                    Ok(n) => feed(&mut cap, &mut resp, child.as_mut(), &buf[..n]),
                    Err(_) => {}
                }
            }
            lingering = !closed;
        }
        drop(child);
        if snapshot.is_some() {
            let _ = backend.after_exec();
        }

        // ── result ──
        let mut out = cap.render();
        if env_cfg.cfg.strip_ansi {
            out = ansi::strip_output(&out, pty);
        }
        // The next call starts where this one ended, with this one's exports.
        if let Some(state) = &snapshot {
            state.lock().unwrap().reload(&skip, env_cfg.cfg.scrub_env, &env_cfg.cfg.passthrough());
        }
        if lingering {
            out.push_str("\n[note: background processes are still running and holding output; their later output is not captured]");
        }
        if let Some(note) = crate::exec::sudo::after(&sudo, &resolved, &ctx.session_id, &sudo_secret, &out) {
            out.push_str(&format!("\n[{note}]"));
        }
        if env_cfg.cfg.failure_hints {
            let code = match (stopped, status.as_ref().and_then(|s| s.code)) {
                (Some("timed out"), _) => Some(124),
                (Some(_), _) => None,
                (None, c) => c.or_else(|| status.as_ref().and_then(|s| s.signal).map(|s| 128 + s)),
            };
            match code {
                Some(0) => {
                    if let Some(w) = crate::exec::hints::annotate_masked_success(command, &out) {
                        out.push_str(&format!("\n[warning: {w}]"));
                    }
                }
                Some(c) => {
                    if let Some(h) = crate::exec::hints::annotate_failure(command, c, &out) {
                        out.push_str(&format!("\n[hint: {h}]"));
                    }
                }
                None => {}
            }
        }
        // tokenjuice: compact big results (hints and sudo notes above see the raw text).
        if let Some(compact) = crate::tokenjuice::reduce_command_output(command, &out, crate::tokenjuice::DEFAULT_BUDGET) {
            out = compact;
        }
        if pty {
            let stripped = if env_cfg.cfg.strip_ansi { "ANSI escapes removed" } else { "ANSI escapes kept" };
            out.push_str(&format!("\n[pty terminal {rows}x{cols}, {stripped}]"));
        }
        if let Some(why) = stopped {
            let msg = if why == "timed out" { format!("timed out after {timeout}s; process group killed") } else { "cancelled; process group killed".into() };
            return ToolOutput::err(format!("{out}\n[{msg}]"));
        }
        match status {
            Some(s) if s.success() => ToolOutput::ok(if out.is_empty() { "[exit 0, no output]".into() } else { format!("{out}\n[exit 0]") }),
            Some(s) => match (s.code, s.signal) {
                (Some(c), _) => ToolOutput::err(format!("{out}\n[exit {c}]")),
                (None, Some(sig)) => ToolOutput::err(format!("{out}\n[killed by signal {sig}]")),
                _ => ToolOutput::err(format!("{out}\n[exited abnormally]")),
            },
            None => ToolOutput::err(format!("{out}\n[could not collect exit status]")),
        }
    }
}

/// When to stop waiting and hand the live child to the process registry:
/// `background` = now, `yield_ms` = that many milliseconds, otherwise never — unless the
/// requested timeout exceeds `[exec] foreground_max_timeout`, which promotes the command
/// to a background process at that point (Hermes foreground→background promotion).
fn yield_deadline(started: Instant, cfg: &crate::exec::ExecConfig, timeout: u64, yield_ms: Option<u64>, background: bool) -> Option<Instant> {
    if background {
        return Some(started);
    }
    match yield_ms.unwrap_or(cfg.yield_ms) {
        0 => {
            if cfg.foreground_max_timeout > 0 && timeout > cfg.foreground_max_timeout {
                Some(started + Duration::from_secs(cfg.foreground_max_timeout))
            } else {
                None
            }
        }
        ms => Some(started + Duration::from_millis(ms)),
    }
}

/// Move a still-running child into `exec::process` and describe the handle.
#[allow(clippy::too_many_arguments)]
fn hand_off(
    ctx: &ToolCtx,
    env_cfg: &crate::exec::ExecEnv,
    backend: Arc<dyn seagent_core::exec::ExecBackend>,
    child: Box<dyn ExecChild>,
    cap: Capture,
    command: &str,
    pty: bool,
    size: (u16, u16),
    started: Instant,
    waited_ms: Option<u64>,
    background: bool,
) -> ToolOutput {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let log = ctx.home.join("jobs").join(format!("{}-{}.log", crate::exec::sanitize(&ctx.session_id), SEQ.fetch_add(1, Ordering::Relaxed) + 1));
    if let Some(dir) = log.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // What was already read belongs to this process's transcript too.
    let early = cap.render();
    if !early.is_empty() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log) {
            let _ = f.write_all(early.as_bytes());
        }
    }
    let entry = crate::exec::process::register(&ctx.session_id, command, child, backend, log.clone(), pty, env_cfg.cfg.process_buffer_bytes);
    let id = entry.lock().unwrap().id;
    let elapsed = started.elapsed().as_millis();
    let mut note = if background {
        format!("background process started (id {id}); do not re-run it")
    } else {
        format!("process started (id {id}); still running after {elapsed}ms (yield {}ms) and moved to the background without being killed", waited_ms.unwrap_or(0))
    };
    note.push_str(&format!("; poll it with the process tool (action=poll id={id}), log: {}", log.display()));
    if pty {
        note.push_str(&format!("; terminal (pty) {}x{}", size.0, size.1));
    }
    let mut out = if env_cfg.cfg.strip_ansi { ansi::strip_output(&early, pty) } else { early };
    if out.trim().is_empty() {
        ToolOutput::ok(format!("[{note}]"))
    } else {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        ToolOutput::ok(format!("{out}[{note}]"))
    }
}

fn parse_env(input: &Value) -> Result<Vec<(String, String)>, String> {
    match input.get("env") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(m)) => {
            let mut v = Vec::with_capacity(m.len());
            for (k, val) in m {
                if !is_env_name(k) {
                    return Err(format!("env: `{k}` is not a valid environment variable name"));
                }
                match val.as_str() {
                    Some(s) => v.push((k.clone(), s.to_string())),
                    None => return Err(format!("env: `{k}` must be a string")),
                }
            }
            Ok(v)
        }
        Some(_) => Err("env must be an object of NAME: value strings".into()),
    }
}

/// A shell-identifier environment name (`unset` / `export` take nothing else).
pub(crate) fn is_env_name(k: &str) -> bool {
    let mut c = k.chars();
    matches!(c.next(), Some(c) if c.is_ascii_alphabetic() || c == '_') && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A boolean flag: absent = false, a JSON bool only.
fn flag(input: &Value, key: &str) -> Result<bool, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

/// A non-negative integer, absent = None.
fn opt_uint(input: &Value, key: &str) -> Result<Option<u64>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("{key} must be a non-negative integer")),
    }
}

fn term_size(input: &Value) -> Result<(u16, u16), String> {
    let dim = |key: &str, default: u16| -> Result<u16, String> {
        match opt_uint(input, key)? {
            None => Ok(default),
            Some(n) if (1..=1000).contains(&n) => Ok(n as u16),
            Some(n) => Err(format!("{key} must be an integer in 1..=1000 (got {n})")),
        }
    };
    Ok((dim("rows", DEFAULT_ROWS)?, dim("cols", DEFAULT_COLS)?))
}

/// If seagent is killed (even SIGKILL), the command dies too instead of finishing
/// unobserved: crash recovery reports "side effects unknown", and an orphan
/// completing later would make that report wrong.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn die_with_parent(parent: i32) {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != parent {
            libc::_exit(137); // parent already gone before prctl took effect
        }
    }
}

/// No parent-death signal outside Linux / Android: macOS children are stopped by
/// `LocalChild`'s drop; Windows children die with their kill-on-close Job Object.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn die_with_parent(_parent: i32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    fn group_alive(pgid: i32) -> bool {
        unsafe { libc::kill(-pgid, 0) == 0 }
    }

    #[test]
    fn success_and_exit_codes() {
        let c = ctx("sh");
        let o = Shell.call(&c, json!({"command":"echo hi; echo err >&2"}));
        assert!(!o.is_error);
        assert!(o.content.contains("hi") && o.content.contains("err") && o.content.ends_with("[exit 0]"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo partial; exit 3"}));
        assert!(o.is_error && o.content.contains("partial") && o.content.contains("[exit 3]"));
        let o = Shell.call(&c, json!({"command":"kill -9 $$"}));
        assert!(o.is_error && o.content.contains("signal 9"), "{}", o.content);
        assert_eq!(Shell.call(&c, json!({"command":"true"})).content, "[exit 0, no output]");
    }

    #[test]
    fn bad_args() {
        let c = ctx("shbad");
        assert!(Shell.call(&c, json!({})).is_error);
        assert!(Shell.call(&c, json!({"command":"   "})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":0})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":99999})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":"5"})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","cwd":"nope"})).content.contains("not an existing directory"));
        assert!(Shell.call(&c, json!({"command":"true","env":{"A B":"1"}})).content.contains("not a valid environment"));
        assert!(Shell.call(&c, json!({"command":"true","env":{"A":1}})).content.contains("must be a string"));
        assert!(Shell.call(&c, json!({"command":"true","pty":"yes"})).content.contains("must be a boolean"));
        assert!(Shell.call(&c, json!({"command":"true","yield_ms":-1})).content.contains("non-negative"));
        assert!(Shell.call(&c, json!({"command":"true","pty":true,"cols":0})).content.contains("cols"));
    }

    #[test]
    fn cwd_is_honored() {
        let c = ctx("shcwd");
        std::fs::create_dir(c.workspace.join("sub")).unwrap();
        let o = Shell.call(&c, json!({"command":"pwd","cwd":"sub"}));
        assert!(o.content.contains("/sub"), "{}", o.content);
    }

    #[test]
    fn timeout_kills_whole_group() {
        let c = ctx("shto");
        let pidfile = c.workspace.join("pgid");
        let cmd = format!("echo $$ > {}; sleep 30 & sleep 30", pidfile.display());
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":cmd,"timeout_secs":1}));
        assert!(t.elapsed() < Duration::from_secs(6), "took {:?}", t.elapsed());
        assert!(o.is_error && o.content.contains("timed out after 1s"), "{}", o.content);
        let pgid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let gone = (0..100).any(|_| {
            thread::sleep(Duration::from_millis(20));
            !group_alive(pgid)
        });
        assert!(gone, "process group {pgid} still alive");
    }

    #[test]
    fn sigterm_ignoring_child_still_dies() {
        let c = ctx("shterm");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"trap '' TERM; sleep 30","timeout_secs":1}));
        assert!(o.is_error && t.elapsed() < Duration::from_secs(8));
    }

    #[test]
    fn cancel_mid_run() {
        let c = ctx("shcancel");
        let cancel = c.cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            cancel.cancel();
        });
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"echo started; sleep 30"}));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(o.is_error && o.content.contains("cancelled") && o.content.contains("started"), "{}", o.content);
    }

    #[test]
    fn output_is_capped_head_and_tail() {
        let c = ctx("shcap");
        let o = Shell.call(&c, json!({"command":"echo FIRST; head -c 3000000 /dev/zero | tr '\\0' x; echo; echo LAST"}));
        assert!(!o.is_error);
        assert!(o.content.contains("FIRST") && o.content.contains("LAST"));
        assert!(o.content.contains("output truncated"));
        assert!(o.content.len() < 1_200_000, "{}", o.content.len());
    }

    #[test]
    fn background_process_does_not_block_return() {
        let c = ctx("shbg");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"(sleep 3; echo late) & echo now"}));
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(o.content.contains("now") && o.content.contains("background processes"));
    }

    #[test]
    fn sudo_password_is_piped_and_failures_get_hints() {
        let c = ctx("shsudo");
        let bin = c.workspace.join("bin");
        std::fs::create_dir(&bin).unwrap();
        // A fake sudo: with -S it reads one password line from stdin, without it fails like sudo.
        std::fs::write(bin.join("sudo"), "#!/bin/sh\nif [ \"$1\" = -S ]; then read pw; echo \"pw=$pw args=$*\"; else echo 'sudo: a password is required' >&2; exit 1; fi\n").unwrap();
        std::process::Command::new("chmod").arg("+x").arg(bin.join("sudo")).status().unwrap();
        let cmd = format!("PATH={}:$PATH sudo whoami && echo after", bin.display());
        let o = Shell.call(&c, json!({"command": cmd}));
        assert!(o.is_error && o.content.contains("a password is required") && o.content.contains("seagent secrets set SUDO_PASSWORD"), "{}", o.content);
        crate::exec::sudo::cache_password(&c.session_id, "hunter2");
        let o = Shell.call(&c, json!({"command": cmd}));
        assert!(!o.is_error && o.content.contains("pw=hunter2 args=-S -p  whoami") && o.content.contains("after"), "{}", o.content);
        crate::exec::sudo::cache_password(&c.session_id, "");

        let o = Shell.call(&c, json!({"command":"definitely_not_a_cmd_x1"}));
        assert!(o.is_error && o.content.contains("[hint: `definitely_not_a_cmd_x1` is not installed"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"(printf 'error: could not compile `x`\\n') | cat"}));
        assert!(!o.is_error && o.content.contains("[warning: exit_code 0 here is the status of the last pipeline command"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"exit 3"}));
        assert!(!o.content.contains("[hint:"), "nothing recognised, no hint: {}", o.content);
    }

    #[test]
    fn secrets_substituted_only_at_exec() {
        let c = ctx("shsec");
        let input = json!({"command":"echo token={{secret:TOKEN}}"});
        assert_eq!(Shell.effects(&c, &input), vec![Effect::Exec { command: "echo token={{secret:TOKEN}}".into() }]);
        let o = Shell.call(&c, input);
        assert!(o.content.contains("token=s3cr3t"));
        assert!(Shell.effects(&c, &json!({})).is_empty());
        // `env` values are only substituted when the command runs, too.
        let input = json!({"command":"echo e=$E","env":{"E":"{{secret:TOKEN}}"}});
        assert_eq!(Shell.effects(&c, &input), vec![Effect::Exec { command: "echo e=$E".into() }]);
        assert!(Shell.call(&c, input).content.contains("e=s3cr3t"));
    }

    // ── env parameter (OpenClaw `exec env`) ──

    /// OpenClaw `exec`'s per-call `host` / `elevated` (the escape hatches are honest about it).
    #[test]
    fn host_and_elevated_parameters() {
        let c = ctx("shhost");
        let o = Shell.call(&c, json!({"command":"echo x","host":"node"}));
        assert!(o.is_error && o.content.contains("node_invoke") && o.content.contains("system.run"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo here","host":"host"}));
        assert!(!o.is_error && o.content.contains("here"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo elev","elevated":true}));
        assert!(!o.is_error && o.content.contains("elev"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo sbx","host":"sandbox"}));
        assert!(!o.is_error, "host=sandbox without a sandbox route still runs: {}", o.content);
    }

    /// A blocked variable whose name is not a shell identifier cannot be `unset`, so the
    /// spawn must drop it — otherwise the policy would "block" it without removing it.
    #[test]
    fn odd_named_blocked_variable_does_not_reach_the_child() {
        seagent_security::envscrub::configure(true, &["FOO-BAR-*".into()], &[]);
        std::env::set_var("FOO-BAR-API-KEY", "hunter2-odd-name");
        let c = ctx("shodd");
        let o = Shell.call(&c, json!({"command":"env"}));
        std::env::remove_var("FOO-BAR-API-KEY");
        seagent_security::envscrub::configure(true, &[], &[]);
        assert!(!o.is_error, "{}", o.content);
        assert!(!o.content.contains("FOO-BAR-API-KEY") && !o.content.contains("hunter2-odd-name"), "the child still sees it: {}", o.content);
        // The plain-identifier path still works through the `unset` prelude.
        seagent_security::envscrub::configure(true, &["SEAGENT-STRIP-NAME".into()], &[]);
        std::env::set_var("SEAGENT_STRIP_NAME", "hunter3");
        let o = Shell.call(&c, json!({"command":"env; echo done"}));
        std::env::remove_var("SEAGENT_STRIP_NAME");
        seagent_security::envscrub::configure(true, &[], &[]);
        assert!(!o.content.contains("hunter3"), "{}", o.content);
    }

    #[test]
    fn env_parameter_reaches_the_command_only() {
        let c = ctx("shenv");
        let o = Shell.call(&c, json!({"command":"echo \"x=$SEAGENT_X y=${SEAGENT_Y:-unset}\"","env":{"SEAGENT_X":"1"}}));
        assert!(!o.is_error && o.content.contains("x=1 y=unset"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo \"x=${SEAGENT_X:-unset}\""}));
        assert!(o.content.contains("x=unset"), "per-call env must not persist: {}", o.content);
        // Credential names are not forwarded while scrubbing is on.
        let o = Shell.call(&c, json!({"command":"echo \"k=${SEAGENT_TEST_API_KEY:-unset}\"","env":{"SEAGENT_TEST_API_KEY":"sk-live-abc"}}));
        assert!(o.content.contains("k=unset"), "{}", o.content);
        // `[exec] env` is layered under the call's own variables (child_env_for).
        let mut cfg = crate::exec::ExecConfig::default();
        cfg.env.insert("CFG_ONLY".into(), "cfg".into());
        cfg.env.insert("SEAGENT_X".into(), "cfg".into());
        let env = crate::exec::ExecEnv::new(cfg.clone());
        let merged = env.child_env_for(&[("SEAGENT_X".into(), "call".into())]);
        assert!(merged.iter().any(|(k, v)| k == "CFG_ONLY" && v == "cfg"), "{merged:?}");
        assert!(merged.iter().any(|(k, v)| k == "SEAGENT_X" && v == "call"), "the call wins: {merged:?}");
        assert_eq!(merged.iter().filter(|(k, _)| k == "SEAGENT_X").count(), 1);
    }

    // ── PTY + ANSI stripping ──

    #[test]
    fn pty_runs_in_a_terminal_and_output_is_cleaned() {
        let c = ctx("shpty");
        let o = Shell.call(&c, json!({"command":"tty; stty size; printf '\\033[31mred\\033[0m\\n'","pty":true}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("/dev/pts/"), "a terminal: {}", o.content);
        assert!(o.content.contains("24 80"), "default size: {}", o.content);
        assert!(o.content.contains("red") && !o.content.contains('\x1b'), "ANSI removed: {:?}", o.content);
        assert!(o.content.contains("[pty terminal 24x80, ANSI escapes removed]"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"stty size","pty":true,"rows":40,"cols":120}));
        assert!(o.content.contains("40 120"), "{}", o.content);
        // A plain pipe is not a terminal.
        let o = Shell.call(&c, json!({"command":"tty || echo not-a-tty"}));
        assert!(o.content.contains("not-a-tty"), "{}", o.content);
        // ANSI escapes are stripped without pty too.
        let o = Shell.call(&c, json!({"command":"printf '\\033[32mgreen\\033[0m\\n'"}));
        assert!(!o.content.contains('\x1b') && o.content.contains("green"), "{:?}", o.content);
    }

    // ── yield_ms / background (OpenClaw `yieldMs`, `background`) ──

    #[test]
    fn yield_deadline_defaults_and_promotion() {
        let now = Instant::now();
        let mut cfg = crate::exec::ExecConfig::default();
        assert_eq!(yield_deadline(now, &cfg, 120, None, false), None, "yield_ms = 0 waits for the command");
        assert_eq!(yield_deadline(now, &cfg, 700, None, false), Some(now + Duration::from_secs(cfg.foreground_max_timeout)), "a wait longer than foreground_max_timeout is promoted");
        cfg.yield_ms = 10_000;
        assert_eq!(yield_deadline(now, &cfg, 120, None, false), Some(now + Duration::from_millis(10_000)), "[exec] yield_ms is the default");
        assert_eq!(yield_deadline(now, &cfg, 120, Some(50), false), Some(now + Duration::from_millis(50)), "the call wins");
        assert_eq!(yield_deadline(now, &cfg, 120, None, true), Some(now), "background = return now");
    }

    #[test]
    fn yield_ms_hands_a_running_command_to_the_process_registry() {
        let c = ctx("shyield");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"echo early; sleep 30","yield_ms":600}));
        let took = t.elapsed();
        assert!(!o.is_error, "{}", o.content);
        assert!(took < Duration::from_secs(10), "returned after {took:?}");
        assert!(o.content.contains("early"), "{}", o.content);
        assert!(o.content.contains("process started (id "), "{}", o.content);
        assert!(o.content.contains("poll it with the process tool"), "{}", o.content);
        let id: u32 = o.content.split("process started (id ").nth(1).unwrap().split(')').next().unwrap().parse().unwrap();
        let snap = crate::exec::process::poll(&c.session_id, id).expect("registered");
        assert!(snap.running, "the child must still be alive after the hand-off");
        assert_eq!(snap.command, "echo early; sleep 30");
        let log = std::fs::read_to_string(&snap.log).unwrap_or_default();
        assert!(log.contains("early"), "already-read output goes into the transcript: {log}");
        crate::exec::process::kill(&c.session_id, id).unwrap();
        assert!(crate::exec::process::wait(&c.session_id, id, Duration::from_secs(5)).is_some_and(|s| !s.running));
        // Leave the process registry clean for the other tests in this binary.
        crate::exec::process::remove(&c.session_id, id).unwrap();
    }

    #[test]
    fn background_returns_immediately_with_a_handle() {
        let c = ctx("shbgh");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"sleep 30","background":true}));
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        assert!(!o.is_error && o.content.contains("background process started (id "), "{}", o.content);
        let id: u32 = o.content.split("background process started (id ").nth(1).unwrap().split(')').next().unwrap().parse().unwrap();
        assert!(crate::exec::process::poll(&c.session_id, id).is_some_and(|s| s.running));
        crate::exec::process::kill(&c.session_id, id).unwrap();
        crate::exec::process::wait(&c.session_id, id, Duration::from_secs(5));
        crate::exec::process::remove(&c.session_id, id).unwrap();
    }

    // ── the tool really goes through the backend (ExecBackend) ──

    struct Recording {
        inner: crate::exec::local::LocalBackend,
    }

    impl seagent_core::exec::ExecBackend for Recording {
        fn id(&self) -> &str {
            "wshell-fake"
        }
        fn describe(&self) -> String {
            "wshell-fake: records the ExecRequest, then runs it locally".into()
        }
        fn spawn(&self, req: &ExecRequest) -> std::io::Result<Box<dyn ExecChild>> {
            RECORDED.lock().unwrap().push(req.script.clone());
            self.inner.spawn(req)
        }
        fn temp_dir(&self) -> String {
            self.inner.temp_dir()
        }
    }

    static RECORDED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    #[test]
    fn commands_go_through_the_configured_backend() {
        crate::exec::register_provider(
            "wshell-fake",
            Arc::new(|_v: &Value, _c: &crate::exec::BackendCtx| Ok(Arc::new(Recording { inner: crate::exec::local::LocalBackend::new() }) as Arc<dyn seagent_core::exec::ExecBackend>)),
        );
        let cfg = crate::exec::ExecConfig::parse(&json!({"backend":"wshell-fake"})).unwrap();
        let fake = Arc::new(crate::exec::ExecEnv::new(cfg));
        // Other tests in this binary run in the same process and register a completion
        // notifier on the global environment: keep delivering their notices while this
        // environment is installed, and leave it installed afterwards (its backend just
        // delegates to the local one, and swapping it back would drop whatever notifier a
        // concurrently running test installed in the meantime).
        let prev = crate::exec::global();
        fake.set_notifier(Arc::new(move |s: &str, t: &str| {
            prev.notify(s, t);
        }));
        crate::exec::install(fake);
        RECORDED.lock().unwrap().clear();
        let c = ctx("shbackend");
        let o = Shell.call(&c, json!({"command":"echo via-backend","cwd":"."}));
        assert!(!o.is_error && o.content.contains("via-backend"), "{}", o.content);
        let seen = RECORDED.lock().unwrap().clone();
        let mine: Vec<&String> = seen.iter().filter(|s| s.contains("echo via-backend")).collect();
        assert_eq!(mine.len(), 1, "the backend got exactly one script for this call: {seen:?}");
        assert!(mine[0].contains("export -p") && mine[0].contains("__seagent_ec"), "the session snapshot is part of it: {:?}", mine[0]);
        // The provider is visible to `seagent sandbox`-style listings and config validation.
        assert!(crate::exec::ExecConfig::parse(&json!({"backend":"wshell-fake"})).is_ok());
    }
}
