//! Code mode without an embedded interpreter. The model writes a bash or python
//! script; inside it, `ark-call <tool> '<json>'` reaches back into the kernel over
//! a one-shot unix socket. Every nested call still goes through the gates and the
//! log; only the script's own output enters the context.

use ark_core::{Cancel, ToolOutput};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const MAX_OUTPUT: usize = 256 * 1024;

pub fn spec() -> ark_core::ToolSchema {
    ark_core::ToolSchema {
        name: "run".into(),
        description: "Run a bash or python3 script that can call other tools with `ark-call <tool> '<json input>'` (prints the tool output; exit status 1 on tool error). Use it to chain many tool calls or process their outputs without filling the conversation: only the script's stdout/stderr comes back.".into(),
        input_schema: json!({"type":"object","properties":{
            "script":{"type":"string"},
            "lang":{"type":"string","enum":["bash","python3"]},
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

/// Run `script`, servicing nested calls through `handle` on the calling thread
/// (which owns the session log). Returns the script's output.
pub fn run(runtime_dir: &Path, script: &str, lang: &str, timeout: Duration, workspace: &Path, cancel: &Cancel, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    let interp = match lang {
        "bash" | "" => "bash",
        "python3" | "python" => "python3",
        other => return ToolOutput::err(format!("unsupported lang `{other}` (bash or python3)")),
    };
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
            let _ = reply.send(handle(n));
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
            let _ = reply.send(handle(n));
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

fn serve(conn: UnixStream, token: &str, tx: mpsc::Sender<Nested>) {
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

fn kill_group(pid: i32) {
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
        let d = std::env::temp_dir().join(format!("ark-run-{}", crate::util::random_hex(6)));
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
    fn client_without_env_fails_cleanly() {
        if std::env::var("ARK_CALL_SOCK").is_err() {
            assert!(client("read", "{}").unwrap_err().contains("only works inside"));
        }
    }
}
