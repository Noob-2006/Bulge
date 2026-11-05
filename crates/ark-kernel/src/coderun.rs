//! Code mode without an embedded interpreter. The model writes a bash or python
//! script; inside it, `ark-call <tool> '<json>'` reaches back into the kernel over
//! a one-shot unix socket. Every nested call still goes through the gates and the
//! log; only the script's own output enters the context.
//!
//! Hermes parity (`tools/code_execution_*.py`, `tools/code_kernel*.py`): python3 cells run in a
//! session-persistent kernel (`pykernel`, `reset=true` starts fresh), every call has a nested
//! tool-call budget (`max_tool_calls`, default 50), the child environment is an allowlist
//! (`env`), and when the session's execution backend is not the local host the script runs
//! inside it with a file-based call protocol (`remote`).

mod env;
pub mod pykernel;
mod remote;

use ark_core::{Cancel, ToolOutput};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

pub const MAX_OUTPUT: usize = 256 * 1024;

/// `[exec.code]` (installed by the binary with [`configure`]).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodeConfig {
    /// Nested tool calls allowed per `run` call (Hermes `max_tool_calls`).
    pub max_tool_calls: u32,
    /// python3 scripts run in a session-persistent kernel.
    pub persistent: bool,
    /// Live kernels at most (least recently used ones are stopped).
    pub max_kernels: usize,
    /// Stop a kernel unused for this long.
    pub kernel_idle_timeout_secs: u64,
    /// Run scripts in the session's execution backend when it is not the local host.
    pub use_backend: bool,
}

impl Default for CodeConfig {
    fn default() -> Self {
        CodeConfig { max_tool_calls: 50, persistent: true, max_kernels: 4, kernel_idle_timeout_secs: 1800, use_backend: true }
    }
}

static CONFIG: RwLock<Option<CodeConfig>> = RwLock::new(None);

pub fn configure(c: CodeConfig) {
    *CONFIG.write().unwrap() = Some(c);
}

pub fn config() -> CodeConfig {
    CONFIG.read().unwrap().clone().unwrap_or_default()
}

/// Per-call nested tool budget; refusals are free, only dispatched calls count.
pub struct Budget {
    pub max: u32,
    pub used: u32,
    pub failed: Vec<String>,
}

impl Budget {
    pub fn new(max: u32) -> Budget {
        Budget { max, used: 0, failed: vec![] }
    }
    pub fn dispatch(&mut self, n: Nested, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
        if self.used >= self.max {
            return ToolOutput::err(format!("Tool call limit reached ({}). No more tool calls allowed in this execution.", self.max));
        }
        self.used += 1;
        let tool = n.tool.clone();
        let o = handle(n);
        if o.is_error {
            let first: String = o.content.lines().next().unwrap_or("").chars().take(160).collect();
            self.failed.push(format!("{tool}: {first}"));
        }
        o
    }
    /// Hermes `tool_errors_since`: a script that ignores a failed helper would otherwise look fine.
    fn annotate(&self, mut o: ToolOutput) -> ToolOutput {
        if !self.failed.is_empty() {
            o.content.push_str(&format!("\n[{} of {} tool calls in this script failed — check before relying on their effects]\n{}", self.failed.len(), self.used, self.failed.iter().map(|f| format!("  {f}")).collect::<Vec<_>>().join("\n")));
        }
        o
    }
}

/// One `run` call.
pub struct RunReq<'a> {
    pub script: &'a str,
    pub lang: &'a str,
    pub timeout: Duration,
    pub workspace: &'a Path,
    /// Owner of persistent kernels; empty = no persistence.
    pub session: &'a str,
    pub reset: bool,
    /// Execution backend override (tests); None = the installed selector's choice.
    pub backend: Option<Arc<dyn ark_core::exec::ExecBackend>>,
}

impl<'a> RunReq<'a> {
    /// From the tool input (`script`, `lang`, `timeout_secs`, `reset`).
    pub fn from_input(input: &'a Value, session: &'a str, workspace: &'a Path) -> RunReq<'a> {
        RunReq {
            script: input.get("script").and_then(Value::as_str).unwrap_or(""),
            lang: input.get("lang").and_then(Value::as_str).unwrap_or("bash"),
            timeout: Duration::from_secs(input.get("timeout_secs").and_then(Value::as_u64).unwrap_or(300).clamp(1, 3600)),
            workspace,
            session,
            reset: input.get("reset").and_then(Value::as_bool).unwrap_or(false),
            backend: None,
        }
    }
}

/// Run a code-mode call: remote backend, persistent python kernel, or a one-shot local child.
pub fn run_opts(runtime_dir: &Path, r: &RunReq, cancel: &Cancel, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    let cfg = config();
    let interp = match r.lang {
        "bash" | "" => "bash",
        "python3" | "python" => "python3",
        other => return ToolOutput::err(format!("unsupported lang `{other}` (bash or python3)")),
    };
    let mut budget = Budget::new(cfg.max_tool_calls);
    let backend = r.backend.clone().or_else(|| if cfg.use_backend { ark_core::exec::backend_for(r.session, r.workspace) } else { None }).filter(|b| b.id() != "local");
    if let Some(b) = backend {
        let o = remote::run(b, r.script, interp, r.timeout, r.workspace, cancel, &mut budget, handle);
        return budget.annotate(o);
    }
    if interp == "python3" && cfg.persistent && !r.session.is_empty() {
        if let Err(e) = std::fs::create_dir_all(runtime_dir) {
            return ToolOutput::err(format!("cannot create runtime dir: {e}"));
        }
        let path = match shim_dir(runtime_dir) {
            Ok(d) => format!("{}:{}", d.display(), std::env::var("PATH").unwrap_or_default()),
            Err(e) => return ToolOutput::err(e),
        };
        let cell = pykernel::CellReq { code: r.script, session: r.session, workspace: r.workspace, timeout: r.timeout, reset: r.reset, max_kernels: cfg.max_kernels, idle_timeout: Duration::from_secs(cfg.kernel_idle_timeout_secs.max(1)), path_env: path };
        let o = pykernel::run_cell(runtime_dir, &cell, cancel, &mut budget, handle);
        return budget.annotate(o);
    }
    let o = run_local(runtime_dir, r.script, interp, r.timeout, r.workspace, cancel, &mut budget, handle);
    budget.annotate(o)
}

pub fn spec() -> ark_core::ToolSchema {
    ark_core::ToolSchema {
        name: "run".into(),
        description: "Run a bash or python3 script that can call other tools with `ark-call <tool> '<json input>'` (prints the tool output; exit status 1 on tool error; python3 cells can also call `ark_call(tool, {...})`). Use it to chain many tool calls or process their outputs without filling the conversation: only the script's stdout/stderr comes back. python3 runs in a persistent session kernel: variables, imports and loaded data survive across calls (a timed-out call loses that state). Limits: 50 tool calls per call.".into(),
        input_schema: json!({"type":"object","properties":{
            "script":{"type":"string"},
            "lang":{"type":"string","enum":["bash","python3"]},
            "reset":{"type":"boolean","description":"python3: discard the persistent kernel's state and start fresh before running this code."},
            "timeout_secs":{"type":"integer","minimum":1,"maximum":3600}
        },"required":["script"]}),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallRequest {
    pub token: String,
    pub tool: String,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallResponse {
    pub ok: bool,
    pub content: String,
}

/// A nested tool call waiting for the kernel thread to execute it.
pub struct Nested {
    pub tool: String,
    pub input: Value,
    pub reply: mpsc::Sender<ToolOutput>,
}

/// Run `script` once, servicing nested calls through `handle` on the calling thread
/// (which owns the session log). Returns the script's output. (No session: no persistence.)
pub fn run(runtime_dir: &Path, script: &str, lang: &str, timeout: Duration, workspace: &Path, cancel: &Cancel, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    run_opts(runtime_dir, &RunReq { script, lang, timeout, workspace, session: "", reset: false, backend: None }, cancel, handle)
}

#[allow(clippy::too_many_arguments)]
fn run_local(runtime_dir: &Path, script: &str, interp: &str, timeout: Duration, workspace: &Path, cancel: &Cancel, budget: &mut Budget, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    if let Err(e) = std::fs::create_dir_all(runtime_dir) {
        return ToolOutput::err(format!("cannot create runtime dir: {e}"));
    }
    let token = crate::util::random_hex(32);
    let sock = runtime_dir.join(format!("call-{}.sock", crate::util::random_hex(8)));
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => return ToolOutput::err(format!("cannot bind {}: {e}", sock.display())),
    };
    let _cleanup = Cleanup(sock.clone());
    let bin_dir = match shim_dir(runtime_dir) {
        Ok(d) => d,
        Err(e) => return ToolOutput::err(e),
    };
    let (tx, rx) = mpsc::channel::<Nested>();
    let tok = token.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let accept = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if done2.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let Ok(conn) = conn else { break };
            let tx = tx.clone();
            let tok = tok.clone();
            std::thread::spawn(move || serve(conn, &tok, tx));
        }
    });

    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap_or_default());
    let mut cmd = Command::new(interp);
    cmd.env_clear().envs(env::child_env());
    cmd.arg("-c").arg(script).current_dir(workspace).env("PATH", path).env("ARK_CALL_SOCK", &sock).env("ARK_CALL_TOKEN", &token).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let parent = std::process::id() as i32;
    // SAFETY: setpgid in the child before exec so the whole tree can be killed;
    // PDEATHSIG so a SIGKILLed ark doesn't leave the script running unobserved.
    unsafe {
        cmd.pre_exec(move || {
            libc::setpgid(0, 0);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if libc::getppid() != parent {
                libc::_exit(137);
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            wake(&sock, &done);
            let _ = accept.join();
            return ToolOutput::err(format!("cannot start {interp}: {e}"));
        }
    };
    let pid = child.id() as i32;
    let out = reader(child.stdout.take());
    let err = reader(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let mut killed: Option<&str> = None;
    let status = loop {
        while let Ok(n) = rx.try_recv() {
            let reply = n.reply.clone();
            let _ = reply.send(budget.dispatch(n, handle));
        }
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(_) => break None,
        }
        if killed.is_none() && (cancel.is_cancelled() || Instant::now() >= deadline) {
            killed = Some(if cancel.is_cancelled() { "cancelled" } else { "timed out" });
            kill_group(pid);
        }
        // Block briefly on nested calls so they are serviced promptly.
        if let Ok(n) = rx.recv_timeout(Duration::from_millis(20)) {
            let reply = n.reply.clone();
            let _ = reply.send(budget.dispatch(n, handle));
        }
    };
    wake(&sock, &done);
    let _ = accept.join();
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    let mut text = stdout;
    if !stderr.is_empty() {
        text.push_str("\n[stderr]\n");
        text.push_str(&stderr);
    }
    let (mut text, _) = crate::util::head_tail(&text, MAX_OUTPUT);
    let code = status.and_then(|s| s.code());
    if let Some(k) = killed {
        text.push_str(&format!("\n[script {k}; process group killed]"));
        return ToolOutput::err(text);
    }
    match code {
        Some(0) => ToolOutput::ok(text),
        Some(c) => ToolOutput::err(format!("{text}\n[exit status {c}]")),
        None => ToolOutput::err(format!("{text}\n[killed by signal]")),
    }
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Unblock `incoming()` so the accept thread exits.
fn wake(sock: &Path, done: &std::sync::atomic::AtomicBool) {
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = UnixStream::connect(sock);
}

pub(crate) fn serve(conn: UnixStream, token: &str, tx: mpsc::Sender<Nested>) {
    let mut w = match conn.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut line = String::new();
    if BufReader::new(conn).take(4 * 1024 * 1024).read_line(&mut line).is_err() {
        return;
    }
    let resp = match serde_json::from_str::<CallRequest>(&line) {
        Err(e) => CallResponse { ok: false, content: format!("bad request: {e}") },
        Ok(r) if r.token != token => CallResponse { ok: false, content: "bad token".into() },
        Ok(r) if r.tool == "run" => CallResponse { ok: false, content: "`run` cannot be nested".into() },
        Ok(r) => {
            let (rtx, rrx) = mpsc::channel();
            if tx.send(Nested { tool: r.tool, input: r.input, reply: rtx }).is_err() {
                CallResponse { ok: false, content: "script finished".into() }
            } else {
                match rrx.recv() {
                    Ok(o) => CallResponse { ok: !o.is_error, content: o.content },
                    Err(_) => CallResponse { ok: false, content: "kernel dropped the call".into() },
                }
            }
        }
    };
    let _ = serde_json::to_writer(&mut w, &resp);
    let _ = w.write_all(b"\n");
}

fn reader<R: Read + Send + 'static>(r: Option<R>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = r {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = r.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if buf.len() < MAX_OUTPUT * 2 {
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    })
}

pub(crate) fn kill_group(pid: i32) {
    // SAFETY: plain signal syscalls on our own child's process group.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(300));
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

/// `ark-call` shim: a symlink to the running ark binary.
fn shim_dir(runtime_dir: &Path) -> Result<PathBuf, String> {
    let dir = runtime_dir.join("bin");
    let link = dir.join("ark-call");
    let exe = std::env::var_os("ARK_BIN").map(PathBuf::from).or_else(|| std::env::current_exe().ok()).ok_or("cannot locate ark binary")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    if std::fs::read_link(&link).ok().as_deref() != Some(exe.as_path()) {
        let tmp = dir.join(format!(".ark-call-{}", crate::util::random_hex(6)));
        std::os::unix::fs::symlink(&exe, &tmp).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &link).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

/// Client side, used by `ark call` / `ark-call`.
pub fn client(tool: &str, input: &str) -> Result<String, String> {
    let sock = std::env::var("ARK_CALL_SOCK").map_err(|_| "ARK_CALL_SOCK not set: ark-call only works inside the `run` tool")?;
    let token = std::env::var("ARK_CALL_TOKEN").unwrap_or_default();
    let input: Value = if input.trim().is_empty() { json!({}) } else { serde_json::from_str(input).map_err(|e| format!("input is not JSON: {e}"))? };
    let mut s = UnixStream::connect(&sock).map_err(|e| format!("connect {sock}: {e}"))?;
    serde_json::to_writer(&mut s, &CallRequest { token, tool: tool.into(), input }).map_err(|e| e.to_string())?;
    s.write_all(b"\n").map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let r: CallResponse = serde_json::from_str(&line).map_err(|e| format!("bad response: {e}"))?;
    if r.ok {
        Ok(r.content)
    } else {
        Err(r.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-run-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // Nested calls are exercised end-to-end through the real binary in the CLI
    // tests; here we drive the socket protocol directly.
    #[test]
    fn script_output_exit_codes_and_nested_protocol() {
        let d = dir();
        let mut calls = Vec::new();
        let script = "python3 - <<'EOF'\nimport os,socket,json\ns=socket.socket(socket.AF_UNIX)\ns.connect(os.environ['ARK_CALL_SOCK'])\ns.sendall((json.dumps({'token':os.environ['ARK_CALL_TOKEN'],'tool':'echo','input':{'x':1}})+'\\n').encode())\nprint(s.makefile().readline().strip())\nb=socket.socket(socket.AF_UNIX)\nb.connect(os.environ['ARK_CALL_SOCK'])\nb.sendall(b'{\"token\":\"wrong\",\"tool\":\"echo\"}\\n')\nprint(b.makefile().readline().strip())\nEOF";
        let out = run(&d, script, "bash", Duration::from_secs(20), &d, &Cancel::new(), &mut |n| {
            calls.push(n.tool.clone());
            ToolOutput::ok(format!("got {}", n.input))
        });
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains(r#""ok":true"#) && out.content.contains(r#"got {\"x\":1}"#), "{}", out.content);
        assert!(out.content.contains("bad token"));
        assert_eq!(calls, ["echo"], "bad-token call never reached the kernel");
        assert_eq!(std::fs::read_dir(&d).unwrap().filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "sock")).count(), 0, "socket cleaned up");
    }

    #[test]
    fn failures_timeout_cancel_and_bad_lang() {
        let d = dir();
        let o = run(&d, "echo oops >&2; exit 3", "bash", Duration::from_secs(5), &d, &Cancel::new(), &mut |_| ToolOutput::ok(""));
        assert!(o.is_error && o.content.contains("oops") && o.content.contains("exit status 3"));
        let t0 = Instant::now();
        let o = run(&d, "sleep 30 & sleep 30", "bash", Duration::from_millis(300), &d, &Cancel::new(), &mut |_| ToolOutput::ok(""));
        assert!(o.is_error && o.content.contains("timed out"));
        assert!(t0.elapsed() < Duration::from_secs(5));
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.cancel();
        });
        let o = run(&d, "sleep 30", "bash", Duration::from_secs(60), &d, &c, &mut |_| ToolOutput::ok(""));
        assert!(o.content.contains("cancelled"));
        assert!(run(&d, "x", "ruby", Duration::from_secs(1), &d, &Cancel::new(), &mut |_| ToolOutput::ok("")).content.contains("unsupported"));
        let o = run(&d, "print(1/0)", "python3", Duration::from_secs(10), &d, &Cancel::new(), &mut |_| ToolOutput::ok(""));
        assert!(o.is_error && o.content.contains("ZeroDivisionError"));
    }

    #[test]
    fn persistent_python_kernel_reset_and_nested_calls() {
        let d = dir();
        let sid = format!("kern-{}", crate::util::random_hex(4));
        let mut calls = Vec::new();
        let mut h = |n: Nested| {
            calls.push(n.tool.clone());
            ToolOutput::ok(format!("tool {} got {}", n.tool, n.input))
        };
        let req = |code: &'static str, reset: bool| RunReq { script: code, lang: "python3", timeout: Duration::from_secs(20), workspace: &d, session: &sid, reset, backend: None };
        let o = run_opts(&d, &req("x = 41\nimport os\nprint('env', os.environ.get('PYTHONUTF8'))", false), &Cancel::new(), &mut h);
        assert!(!o.is_error && o.content.contains("env 1") && o.content.contains("cell 1"), "{}", o.content);
        let o = run_opts(&d, &req("print(x + 1)\nprint(ark_call('echo', {'a': 1}))", false), &Cancel::new(), &mut h);
        assert!(!o.is_error && o.content.contains("42") && o.content.contains("tool echo got {\"a\":1}") && o.content.contains("cell 2"), "state survives: {}", o.content);
        let o = run_opts(&d, &req("raise ValueError('boom')", false), &Cancel::new(), &mut h);
        assert!(o.is_error && o.content.contains("ValueError: boom"), "{}", o.content);
        let o = run_opts(&d, &req("print(x)", true), &Cancel::new(), &mut h);
        assert!(o.is_error && o.content.contains("kernel reset") && o.content.contains("NameError"), "reset discards state: {}", o.content);
        let t0 = Instant::now();
        let o = run_opts(&d, &RunReq { timeout: Duration::from_millis(500), ..req("y = 1\nimport time\ntime.sleep(30)", false) }, &Cancel::new(), &mut h);
        assert!(o.is_error && o.content.contains("timed out; kernel killed, state lost") && t0.elapsed() < Duration::from_secs(5), "{}", o.content);
        let o = run_opts(&d, &req("print(globals().get('y', 'gone'))", false), &Cancel::new(), &mut h);
        assert!(o.content.contains("gone") && o.content.contains("cell 1"), "a killed kernel is replaced: {}", o.content);
        assert_eq!(calls, ["echo"]);
        pykernel::reset(&sid);
    }

    #[test]
    fn nested_call_budget_and_failed_call_report() {
        let mut b = Budget::new(2);
        let mut n = 0;
        let mut h = |x: Nested| {
            n += 1;
            if x.tool == "bad" { ToolOutput::err("no such file") } else { ToolOutput::ok("fine") }
        };
        let mk = |t: &str| Nested { tool: t.into(), input: json!({}), reply: mpsc::channel().0 };
        assert!(!b.dispatch(mk("read"), &mut h).is_error);
        assert!(b.dispatch(mk("bad"), &mut h).is_error);
        let o = b.dispatch(mk("read"), &mut h);
        assert!(o.is_error && o.content.contains("Tool call limit reached (2)"), "{}", o.content);
        assert_eq!(n, 2, "refused calls never reach the kernel");
        let o = b.annotate(ToolOutput::ok("done"));
        assert!(o.content.contains("1 of 2 tool calls in this script failed") && o.content.contains("bad: no such file"), "{}", o.content);
    }

    /// A backend that runs scripts locally but shares nothing with the host: private temp dir,
    /// empty environment — like a container or SSH host.
    struct FakeRemote {
        tmp: PathBuf,
    }
    struct FakeChild {
        c: std::process::Child,
        rx: mpsc::Receiver<Vec<u8>>,
        stdin: Option<std::process::ChildStdin>,
    }
    impl ark_core::exec::ExecChild for FakeChild {
        fn pid(&self) -> Option<u32> {
            Some(self.c.id())
        }
        fn read(&mut self, buf: &mut [u8], t: Duration) -> std::io::Result<usize> {
            match self.rx.recv_timeout(t) {
                Ok(v) => {
                    let n = v.len().min(buf.len());
                    buf[..n].copy_from_slice(&v[..n]);
                    Ok(n)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::ErrorKind::TimedOut.into()),
                Err(_) => Ok(0),
            }
        }
        fn write_stdin(&mut self, d: &[u8]) -> std::io::Result<()> {
            self.stdin.as_mut().ok_or(std::io::ErrorKind::BrokenPipe)?.write_all(d)
        }
        fn close_stdin(&mut self) {
            self.stdin = None;
        }
        fn try_wait(&mut self) -> std::io::Result<Option<ark_core::exec::ExitInfo>> {
            Ok(self.c.try_wait()?.map(|s| ark_core::exec::ExitInfo { code: s.code(), signal: None }))
        }
        fn kill(&mut self, _f: bool) {
            let _ = self.c.kill();
        }
    }
    impl ark_core::exec::ExecBackend for FakeRemote {
        fn id(&self) -> &str {
            "fake-remote"
        }
        fn describe(&self) -> String {
            "fake".into()
        }
        fn shares_host_fs(&self) -> bool {
            false
        }
        fn temp_dir(&self) -> String {
            self.tmp.display().to_string()
        }
        fn spawn(&self, req: &ark_core::exec::ExecRequest) -> std::io::Result<Box<dyn ark_core::exec::ExecChild>> {
            let mut c = Command::new("bash");
            c.env_clear().env("PATH", "/usr/bin:/bin").env("HOME", &self.tmp).arg("-c").arg(format!("{} 2>&1", req.script)).stdout(Stdio::piped()).stdin(Stdio::piped());
            let mut c = c.spawn()?;
            let mut stdin = c.stdin.take();
            if let (Some(d), Some(w)) = (&req.stdin_data, stdin.as_mut()) {
                w.write_all(d)?;
            }
            if !req.stdin {
                stdin = None;
            }
            let mut out = c.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = out.read(&mut b) {
                    if n == 0 || tx.send(b[..n].to_vec()).is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(FakeChild { c, rx, stdin }))
        }
    }

    #[test]
    fn remote_backend_file_rpc_and_no_host_env() {
        let d = dir();
        let tmp = d.join("remote-tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let b: Arc<dyn ark_core::exec::ExecBackend> = Arc::new(FakeRemote { tmp: tmp.clone() });
        let mut calls = Vec::new();
        let mut h = |n: Nested| {
            calls.push((n.tool.clone(), n.input.clone()));
            if n.tool == "fail" { ToolOutput::err("nope") } else { ToolOutput::ok(format!("result for {}", n.input["q"])) }
        };
        let script = "echo start; ark-call search '{\"q\":\"x y\"}'; echo rc=$?; ark-call fail || echo failed-ok; ark-call run '{}' || echo nested-refused; echo home=$HOME; echo token=${ARK_CALL_TOKEN:+set}";
        let o = run_opts(&d, &RunReq { script, lang: "bash", timeout: Duration::from_secs(30), workspace: &d, session: "r1", reset: false, backend: Some(b.clone()) }, &Cancel::new(), &mut h);
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("start") && o.content.contains("result for \"x y\"") && o.content.contains("rc=0"), "{}", o.content);
        assert!(o.content.contains("failed-ok") && o.content.contains("nested-refused"), "{}", o.content);
        assert!(o.content.contains(&format!("home={}", tmp.display())), "runs with the backend's env, not ours: {}", o.content);
        assert!(o.content.contains("1 of 2 tool calls in this script failed"), "{}", o.content);
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0, "rpc dir removed");
        let o = run_opts(&d, &RunReq { script: "import sys; print('py', sys.version_info[0])", lang: "python3", timeout: Duration::from_secs(30), workspace: &d, session: "r1", reset: false, backend: Some(b) }, &Cancel::new(), &mut h);
        assert!(!o.is_error && o.content.contains("py 3") && !o.content.contains("persistent kernel"), "remote python runs per call: {}", o.content);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn client_without_env_fails_cleanly() {
        if std::env::var("ARK_CALL_SOCK").is_err() {
            assert!(client("read", "{}").unwrap_err().contains("only works inside"));
        }
    }
}
