//! Session-persistent Python kernels for code mode (Hermes `tools/code_kernel.py`): one child per
//! (session, workspace), one cell per `run` call, variables and imports survive across calls.
//!
//! Same envelope as the per-call path (scrubbed env, token-checked nested calls with the per-call
//! budget, output caps); only the lifetime widens. A wedged kernel dies, never hangs the agent:
//! timeout / cancel kills the process tree and drops the kernel (state loss is deliberate).
//! The environment is frozen at spawn; `reset=true` starts a fresh kernel.
//!
//! Wire protocol: one JSON request per stdin line `{"id","code"}`; replies framed on stdout as
//! `\n<SENTINEL> <byte-length>\n<json>` with a per-kernel random sentinel. Bytes outside frames
//! are raw fd output attributed to the running cell (calls are serialised per kernel).

use super::callsock::{self, CallListener};
use super::{kill_group, serve, Budget, Nested};
use seagent_core::{Cancel, ToolOutput};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const RUNNER: &str = r#"
import contextlib, io, json, os, socket, sys, threading, traceback
_S = os.environ.pop("SEAGENT_KERNEL_SENTINEL")
_OUT = sys.stdout.buffer
_CAP = 1000000
_PPID = os.getppid()
def _watch():
    import time
    while True:
        time.sleep(1)
        if os.getppid() != _PPID:
            os._exit(0)
threading.Thread(target=_watch, daemon=True).start()
def seagent_call(tool, input=None, **kw):
    """Call an seagent tool; returns its output text, raises RuntimeError on a tool error."""
    if input is None:
        input = kw
    a = os.environ["SEAGENT_CALL_SOCK"]
    if a.startswith("tcp:"):
        h, _, p = a[4:].rpartition(":")
        s = socket.create_connection((h, int(p)))
    else:
        s = socket.socket(socket.AF_UNIX)
        s.connect(a)
    s.sendall((json.dumps({"token": os.environ["SEAGENT_CALL_TOKEN"], "tool": tool, "input": input}) + "\n").encode())
    r = json.loads(s.makefile().readline())
    s.close()
    if not r.get("ok"):
        raise RuntimeError(r.get("content", ""))
    return r.get("content", "")
G = {"__name__": "__main__", "__builtins__": __builtins__, "seagent_call": seagent_call}
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    n += 1
    out, err = io.StringIO(), io.StringIO()
    status, tb = "ok", ""
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exec(compile(req["code"], "<cell>", "exec"), G)
    except SystemExit as e:
        status, tb = "exit", "SystemExit: " + repr(e.code)
    except BaseException:
        status, tb = "error", traceback.format_exc()
    p = json.dumps({"id": req.get("id", ""), "status": status, "stdout": out.getvalue()[:_CAP], "stderr": err.getvalue()[:_CAP], "traceback": tb, "execution_count": n}).encode()
    sys.stdout.flush()
    _OUT.write(("\n%s %d\n" % (_S, len(p))).encode() + p)
    _OUT.flush()
"#;

pub struct Kernel {
    child: Child,
    stdin: ChildStdin,
    out: mpsc::Receiver<Vec<u8>>,
    nested: mpsc::Receiver<Nested>,
    sentinel: String,
    /// The `SEAGENT_CALL_SOCK` value (socket path, or `tcp:` address on Windows).
    sock: String,
    done: Arc<AtomicBool>,
    last_used: Instant,
    cells: u64,
}

impl Drop for Kernel {
    fn drop(&mut self) {
        kill_group(self.child.id() as i32);
        let _ = self.child.wait();
        self.done.store(true, Ordering::SeqCst);
        let _ = callsock::connect(&self.sock);
        callsock::cleanup(&self.sock);
    }
}

type Registry = Mutex<HashMap<String, Arc<Mutex<Kernel>>>>;
static KERNELS: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

fn registry() -> &'static Registry {
    KERNELS.get_or_init(Default::default)
}

fn key(session: &str, ws: &Path) -> String {
    format!("{session}|{}", ws.display())
}

/// Kill every kernel of `session` (`/new`, session end).
pub fn reset(session: &str) {
    registry().lock().unwrap().retain(|k, _| !k.starts_with(&format!("{session}|")));
}

/// Live kernels (for status / tests).
pub fn live() -> usize {
    registry().lock().unwrap().len()
}

fn spawn(runtime_dir: &Path, ws: &Path, path_env: &str) -> Result<Kernel, String> {
    let token = crate::util::random_hex(32);
    let sentinel = format!("SEAGENT-KERNEL-{}", crate::util::random_hex(16));
    let listener = CallListener::bind(runtime_dir, "kernel")?;
    let sock = listener.addr().to_string();
    let (ntx, nrx) = mpsc::channel::<Nested>();
    let tok = token.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done2 = done.clone();
    std::thread::spawn(move || loop {
        let Ok(conn) = listener.accept() else { break };
        if done2.load(Ordering::SeqCst) {
            break;
        }
        let tx = ntx.clone();
        let tok = tok.clone();
        std::thread::spawn(move || serve(conn, &tok, tx));
    });
    let mut cmd = super::python_command();
    cmd.env_clear().envs(super::env::child_env()).arg("-u").arg("-c").arg(RUNNER).current_dir(ws).env("PATH", path_env).env("SEAGENT_CALL_SOCK", &sock).env("SEAGENT_CALL_TOKEN", &token).env("SEAGENT_KERNEL_SENTINEL", &sentinel);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Unix: setpgid only (the runner watches its parent pid itself: PDEATHSIG is bound to the
    // spawning thread, and kernels outlive the turn thread that started them).
    // Windows: a new process group plus a kill-on-close Job Object (not thread-bound, so it
    // also covers a seagent that dies without running drop handlers).
    seagent_core::platform::proc::new_group(&mut cmd, false);
    let mut child = cmd.spawn().map_err(|e| format!("cannot start python3: {e}"))?;
    if let Err(e) = seagent_core::platform::proc::adopt(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot tie python3 to seagent: {e}"));
    }
    let stdin = child.stdin.take().ok_or("no stdin")?;
    let (otx, orx) = mpsc::channel::<Vec<u8>>();
    for r in [child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>)].into_iter().flatten() {
        let tx = otx.clone();
        std::thread::spawn(move || {
            let mut r = r;
            let mut buf = [0u8; 8192];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
    }
    Ok(Kernel { child, stdin, out: orx, nested: nrx, sentinel, sock, done, last_used: Instant::now(), cells: 0 })
}

/// Split one framed reply out of `buf`: (raw bytes before it, the json) when complete.
fn take_frame(buf: &mut Vec<u8>, sentinel: &str) -> Option<(Vec<u8>, Value)> {
    let pat = format!("\n{sentinel} ");
    let at = buf.windows(pat.len()).position(|w| w == pat.as_bytes())?;
    let rest = &buf[at + pat.len()..];
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let len: usize = std::str::from_utf8(&rest[..nl]).ok()?.trim().parse().ok()?;
    let start = at + pat.len() + nl + 1;
    if buf.len() < start + len {
        return None;
    }
    let v: Value = serde_json::from_slice(&buf[start..start + len]).ok()?;
    let raw = buf[..at].to_vec();
    buf.drain(..start + len);
    Some((raw, v))
}

pub struct CellReq<'a> {
    pub code: &'a str,
    pub session: &'a str,
    pub workspace: &'a Path,
    pub timeout: Duration,
    pub reset: bool,
    pub max_kernels: usize,
    pub idle_timeout: Duration,
    pub path_env: String,
}

/// Run one cell in the session's kernel (spawning it as needed).
pub fn run_cell(runtime_dir: &Path, r: &CellReq, cancel: &Cancel, budget: &mut Budget, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    let k = key(r.session, r.workspace);
    let mut notes: Vec<String> = Vec::new();
    let kernel = {
        let mut reg = registry().lock().unwrap();
        // Idle kernels die first; then the least recently used beyond the cap.
        let idle: Vec<String> = reg.iter().filter(|(_, v)| v.try_lock().is_ok_and(|g| g.last_used.elapsed() > r.idle_timeout)).map(|(k, _)| k.clone()).collect();
        for i in idle {
            reg.remove(&i);
        }
        if r.reset && reg.remove(&k).is_some() {
            notes.push("[kernel reset: previous state discarded]".into());
        }
        if let Some(existing) = reg.get(&k).cloned() {
            let alive = existing.lock().unwrap().child.try_wait().ok().flatten().is_none();
            if alive {
                existing
            } else {
                reg.remove(&k);
                notes.push("[the previous kernel had died: state lost, started a new one]".into());
                match spawn(runtime_dir, r.workspace, &r.path_env) {
                    Ok(n) => {
                        let a = Arc::new(Mutex::new(n));
                        reg.insert(k.clone(), a.clone());
                        a
                    }
                    Err(e) => return ToolOutput::err(e),
                }
            }
        } else {
            while reg.len() >= r.max_kernels.max(1) {
                let Some(oldest) = reg.iter().filter_map(|(k, v)| v.try_lock().ok().map(|g| (k.clone(), g.last_used))).min_by_key(|(_, t)| *t).map(|(k, _)| k) else { break };
                reg.remove(&oldest);
            }
            match spawn(runtime_dir, r.workspace, &r.path_env) {
                Ok(n) => {
                    let a = Arc::new(Mutex::new(n));
                    reg.insert(k.clone(), a.clone());
                    a
                }
                Err(e) => return ToolOutput::err(e),
            }
        }
    };
    let mut g = kernel.lock().unwrap();
    g.last_used = Instant::now();
    g.cells += 1;
    let id = format!("c{}", g.cells);
    let line = json!({"id": id, "code": r.code}).to_string() + "\n";
    if g.stdin.write_all(line.as_bytes()).and_then(|_| g.stdin.flush()).is_err() {
        drop(g);
        registry().lock().unwrap().remove(&k);
        return ToolOutput::err("the kernel stopped accepting code (state lost); run again to start a new one");
    }
    let deadline = Instant::now() + r.timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut raw: Vec<u8> = Vec::new();
    let reply = loop {
        while let Ok(n) = g.nested.try_recv() {
            let reply = n.reply.clone();
            let _ = reply.send(budget.dispatch(n, handle));
        }
        if let Ok(chunk) = g.out.recv_timeout(Duration::from_millis(20)) {
            buf.extend_from_slice(&chunk);
            let mut found = None;
            while let Some((before, v)) = take_frame(&mut buf, &g.sentinel) {
                raw.extend_from_slice(&before);
                // A stale frame (from a cell that timed out) is skipped.
                if v["id"] == id.as_str() {
                    found = Some(v);
                    break;
                }
            }
            if let Some(v) = found {
                break Ok(v);
            }
        }
        if let Ok(Some(st)) = g.child.try_wait() {
            break Err(format!("[kernel died ({st}); state lost]"));
        }
        if cancel.is_cancelled() || Instant::now() >= deadline {
            break Err(format!("[cell {}; kernel killed, state lost]", if cancel.is_cancelled() { "cancelled" } else { "timed out" }));
        }
    };
    let cells = g.cells;
    drop(g);
    let mut text = String::from_utf8_lossy(&raw).trim_start_matches('\n').to_string();
    let v = match reply {
        Ok(v) => v,
        Err(why) => {
            registry().lock().unwrap().remove(&k);
            text.push_str(&String::from_utf8_lossy(&buf));
            text.push_str(&format!("\n{why}"));
            return ToolOutput::err(text);
        }
    };
    text.push_str(v["stdout"].as_str().unwrap_or(""));
    let stderr = format!("{}{}", v["stderr"].as_str().unwrap_or(""), v["traceback"].as_str().unwrap_or(""));
    if !stderr.is_empty() {
        text.push_str("\n[stderr]\n");
        text.push_str(&stderr);
    }
    let (mut text, _) = crate::util::head_tail(&text, super::MAX_OUTPUT);
    for n in notes {
        text = format!("{n}\n{text}");
    }
    text.push_str(&format!("\n[persistent kernel, cell {cells}; reset=true starts fresh]"));
    match v["status"].as_str() {
        Some("ok") => ToolOutput::ok(text),
        _ => ToolOutput::err(text),
    }
}
