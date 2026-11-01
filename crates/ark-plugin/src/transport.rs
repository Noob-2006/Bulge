//! JSON-RPC 2.0 transports: newline-delimited stdio to a child process, and
//! MCP Streamable HTTP (POST, JSON or SSE reply). Both are blocking and
//! observe a deadline plus `Cancel` while waiting.

use ark_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio as PStdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Largest single JSON-RPC message accepted from a server.
pub(crate) const MAX_MESSAGE: usize = 4 << 20;
const STDERR_KEEP: usize = 16 * 1024;
const POLL: Duration = Duration::from_millis(25);

type Pending = Arc<Mutex<HashMap<u64, Sender<Result<Value, String>>>>>;

/// Server → client notification sink.
pub type Notify = Arc<dyn Fn(&str, &Value) + Send + Sync>;
/// Server → client request handler (ping, roots/list, …).
pub(crate) type OnRequest = Arc<dyn Fn(&str, &Value) -> Result<Value, (i64, String)> + Send + Sync>;

pub(crate) trait Conn: Send + Sync {
    fn request(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String>;
    fn notify(&self, method: &str, params: Value) -> Result<(), String>;
    fn alive(&self) -> bool;
    fn stderr_tail(&self) -> String {
        String::new()
    }
    fn set_protocol(&self, _v: &str) {}
}

/// Read one `\n`-terminated line, discarding (not buffering) anything past `cap`.
/// Ok(None) = EOF; Ok(Some(Err(n))) = line of n bytes was too long.
pub(crate) fn read_line_capped(r: &mut impl BufRead, cap: usize) -> std::io::Result<Option<Result<Vec<u8>, usize>>> {
    let mut line = Vec::new();
    let mut total = 0usize;
    loop {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(if total == 0 { None } else if total > cap { Some(Err(total)) } else { Some(Ok(line)) });
        }
        let pos = buf.iter().position(|&b| b == b'\n');
        let (chunk, done) = match pos {
            Some(i) => (&buf[..i], i + 1),
            None => (buf, buf.len()),
        };
        total += chunk.len();
        if total <= cap {
            line.extend_from_slice(chunk);
        } else {
            line = Vec::new();
        }
        r.consume(done);
        if pos.is_some() {
            return Ok(Some(if total > cap { Err(total) } else { Ok(line) }));
        }
    }
}

fn wait<T>(rx: &mpsc::Receiver<T>, timeout: Duration, cancel: &Cancel, what: &str) -> Result<T, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return Err(format!("{what}: cancelled"));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("{what}: timed out after {}s", timeout.as_secs_f32().round()));
        }
        match rx.recv_timeout(left.min(POLL)) {
            Ok(v) => return Ok(v),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(format!("{what}: connection closed")),
        }
    }
}

fn rpc_error(method: &str, e: &Value) -> String {
    let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("unknown error");
    format!("{method}: server error {code}: {msg}")
}

/// Route one parsed message; returns a reply to write for server requests.
fn route(v: Value, pending: &Mutex<HashMap<u64, Sender<Result<Value, String>>>>, notify: &Notify, on_req: &OnRequest, log: &mut dyn FnMut(String)) -> Option<Value> {
    let method = v.get("method").and_then(Value::as_str);
    match (method, v.get("id")) {
        (Some(m), Some(id)) => Some(match on_req(m, v.get("params").unwrap_or(&Value::Null)) {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, msg)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}),
        }),
        (Some(m), None) => {
            notify(m, v.get("params").unwrap_or(&Value::Null));
            None
        }
        (None, Some(id)) => {
            let Some(n) = id.as_u64() else {
                log(format!("[ark] response with foreign id {id}"));
                return None;
            };
            let tx = pending.lock().unwrap().remove(&n);
            let res = match v.get("error") {
                Some(e) => Err(e.clone()),
                None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
            };
            match tx {
                Some(tx) => {
                    let _ = tx.send(res.map_err(|e| e.to_string()));
                }
                None => log(format!("[ark] response for unknown request id {n} (late or mismatched)")),
            }
            None
        }
        (None, None) => {
            log("[ark] message without method or id".into());
            None
        }
    }
}

// ───────────────────────── stdio ─────────────────────────

pub(crate) struct StdioConn {
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    pending: Pending,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    pgid: i32,
    stderr: Arc<Mutex<VecDeque<u8>>>,
}

fn push_log(buf: &Mutex<VecDeque<u8>>, bytes: &[u8]) {
    let mut b = buf.lock().unwrap();
    b.extend(bytes);
    if !bytes.ends_with(b"\n") {
        b.push_back(b'\n');
    }
    while b.len() > STDERR_KEEP {
        b.pop_front();
    }
}

impl StdioConn {
    pub fn spawn(command: &str, args: &[String], env: &[(String, String)], cwd: Option<&PathBuf>, notify: Notify, on_req: OnRequest) -> Result<Arc<Self>, String> {
        // The child is spawned and reaped by a keeper thread that lives exactly as long
        // as the child: PDEATHSIG fires when the *spawning thread* dies, so spawning from
        // a short-lived caller thread would kill the server under us.
        let (tx, rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let pending: Pending = Arc::default();
        let stderr: Arc<Mutex<VecDeque<u8>>> = Arc::default();
        let mut cmd = Command::new(command);
        cmd.args(args).envs(env.iter().map(|(k, v)| (k, v))).stdin(PStdio::piped()).stdout(PStdio::piped()).stderr(PStdio::piped());
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        let parent = std::process::id() as i32;
        // SAFETY: setpgid, prctl and getppid are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                libc::setpgid(0, 0);
                #[cfg(target_os = "linux")]
                {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    if libc::getppid() != parent {
                        libc::_exit(137);
                    }
                }
                Ok(())
            });
        }
        // Set once the stderr pipe hits EOF: failures wait briefly for it so the
        // error the user sees includes the server's last words.
        let drained: Arc<(Mutex<bool>, std::sync::Condvar)> = Arc::default();
        let (a, p, se, dr) = (alive.clone(), pending.clone(), stderr.clone(), drained.clone());
        let label = command.to_string();
        std::thread::spawn(move || {
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(format!("cannot start `{label}`: {e}")));
                    return;
                }
            };
            let io = (child.stdin.take(), child.stdout.take(), child.stderr.take(), child.id() as i32);
            if tx.send(Ok(io)).is_err() {
                let _ = child.kill();
            }
            let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            a.store(false, Ordering::SeqCst);
            wait_drained(&dr);
            push_log(&se, format!("[ark] server exited: {status}").as_bytes());
            for (_, tx) in p.lock().unwrap().drain() {
                let _ = tx.send(Err(format!("server exited ({status}) before replying")));
            }
        });
        let (stdin, stdout, child_err, pgid) = rx.recv().map_err(|_| "server keeper thread died".to_string())??;
        let stdin = Arc::new(Mutex::new(stdin));
        let mark = |d: &Arc<(Mutex<bool>, std::sync::Condvar)>| {
            *d.0.lock().unwrap() = true;
            d.1.notify_all();
        };
        match child_err {
            Some(mut e) => {
                let (se, dr) = (stderr.clone(), drained.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = e.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let mut b = se.lock().unwrap();
                        b.extend(&buf[..n]);
                        while b.len() > STDERR_KEEP {
                            b.pop_front();
                        }
                    }
                    mark(&dr);
                });
            }
            None => mark(&drained),
        }
        let out = stdout.ok_or("no stdout pipe")?;
        let (p, a, si, se, dr) = (pending.clone(), alive.clone(), stdin.clone(), stderr.clone(), drained.clone());
        std::thread::spawn(move || {
            let mut r = BufReader::new(out);
            let mut log = |s: String| push_log(&se, s.as_bytes());
            loop {
                match read_line_capped(&mut r, MAX_MESSAGE) {
                    Ok(Some(Ok(line))) => {
                        let text = String::from_utf8_lossy(&line);
                        if text.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<Value>(&text) {
                            Ok(v) if v.is_object() => {
                                if let Some(reply) = route(v, &p, &notify, &on_req, &mut log) {
                                    write_line(&si, &reply).ok();
                                }
                            }
                            _ => log(format!("[ark] ignored non-JSON stdout: {}", text.chars().take(200).collect::<String>())),
                        }
                    }
                    Ok(Some(Err(n))) => log(format!("[ark] dropped oversized message ({n} bytes > {MAX_MESSAGE})")),
                    Ok(None) | Err(_) => break,
                }
            }
            a.store(false, Ordering::SeqCst);
            wait_drained(&dr);
            for (_, tx) in p.lock().unwrap().drain() {
                let _ = tx.send(Err("server closed its output (crashed or exited) before replying".into()));
            }
        });
        Ok(Arc::new(StdioConn { stdin, pending, next: AtomicU64::new(1), alive, pgid, stderr }))
    }
}

fn write_line(stdin: &Mutex<Option<ChildStdin>>, v: &Value) -> Result<(), String> {
    let mut g = stdin.lock().unwrap();
    let s = g.as_mut().ok_or("server stdin closed")?;
    let mut line = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line).and_then(|_| s.flush()).map_err(|e| format!("write to server failed: {e}"))
}

impl Conn for StdioConn {
    fn request(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        if !self.alive() {
            return Err("server is not running".into());
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        if let Err(e) = write_line(&self.stdin, &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})) {
            self.pending.lock().unwrap().remove(&id);
            return Err(e);
        }
        match wait(&rx, timeout, cancel, method) {
            Ok(r) => r.map_err(|e| serde_json::from_str::<Value>(&e).map(|v| rpc_error(method, &v)).unwrap_or(e)),
            Err(e) => {
                self.pending.lock().unwrap().remove(&id);
                if self.alive() {
                    let _ = self.notify("notifications/cancelled", json!({"requestId": id, "reason": e}));
                }
                Err(e)
            }
        }
    }
    fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        write_line(&self.stdin, &json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn stderr_tail(&self) -> String {
        let b = self.stderr.lock().unwrap();
        let v: Vec<u8> = b.iter().copied().collect();
        String::from_utf8_lossy(&v).trim().to_string()
    }
}

impl Drop for StdioConn {
    fn drop(&mut self) {
        self.stdin.lock().unwrap().take(); // EOF lets polite servers exit
        if self.alive() {
            // SAFETY: plain syscall on our own process group.
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
    }
}

// ───────────────────────── Streamable HTTP ─────────────────────────

pub(crate) struct HttpConn {
    agent: ureq::Agent,
    url: String,
    headers: Vec<(String, String)>,
    session: Arc<Mutex<Option<String>>>,
    protocol: Mutex<Option<String>>,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    notify_sink: Notify,
}

impl HttpConn {
    pub fn new(url: &str, headers: Vec<(String, String)>, timeout: Duration, notify: Notify) -> Arc<Self> {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            // Bounds a worker whose caller already gave up.
            .timeout_global(Some(timeout + Duration::from_secs(5)))
            .build()
            .into();
        Arc::new(HttpConn { agent, url: url.into(), headers, session: Arc::default(), protocol: Mutex::new(None), next: AtomicU64::new(1), alive: Arc::new(AtomicBool::new(true)), notify_sink: notify })
    }

    fn post(&self, body: Value, want: Option<u64>) -> mpsc::Receiver<Result<Value, String>> {
        let (tx, rx) = mpsc::channel();
        let mut req = self.agent.post(&self.url).header("content-type", "application/json").header("accept", "application/json, text/event-stream");
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let had_session = self.session.lock().unwrap().clone();
        if let Some(s) = &had_session {
            req = req.header("mcp-session-id", s.as_str());
        }
        if let Some(p) = self.protocol.lock().unwrap().as_deref() {
            req = req.header("mcp-protocol-version", p);
        }
        let (session, alive, notify) = (self.session.clone(), self.alive.clone(), self.notify_sink.clone());
        std::thread::spawn(move || {
            let r = (|| {
                let resp = req.send(&serde_json::to_vec(&body).unwrap()[..]).map_err(|e| format!("HTTP request failed: {e}"))?;
                let status = resp.status().as_u16();
                if let Some(s) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
                    *session.lock().unwrap() = Some(s.to_string());
                }
                let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
                let mut reader = BufReader::new(resp.into_body().into_reader().take(MAX_MESSAGE as u64 + 1));
                if !(200..300).contains(&status) {
                    let mut raw = String::new();
                    let _ = reader.by_ref().take(500).read_to_string(&mut raw);
                    return Err(match status {
                        401 | 403 => format!("unauthorized (HTTP {status}): check the server's headers / token"),
                        404 if had_session.is_some() => {
                            alive.store(false, Ordering::SeqCst); // session expired: reconnect next call
                            "session expired (HTTP 404); will reconnect".to_string()
                        }
                        404 => "not found (HTTP 404): wrong MCP URL?".to_string(),
                        _ => format!("HTTP {status}: {}", raw.trim().chars().take(300).collect::<String>()),
                    });
                }
                let Some(want) = want else { return Ok(Value::Null) };
                let none: OnRequest = Arc::new(|_, _| Err((-32601, "not supported over HTTP".into())));
                let pending = Mutex::new(HashMap::new());
                let (rtx, rrx) = mpsc::channel();
                pending.lock().unwrap().insert(want, rtx);
                let mut ignore = |_s: String| {};
                let mut handle = |v: Value| {
                    route(v, &pending, &notify, &none, &mut ignore);
                    rrx.try_recv().ok()
                };
                if ctype.starts_with("text/event-stream") {
                    let mut data = String::new();
                    loop {
                        let line = match read_line_capped(&mut reader, MAX_MESSAGE) {
                            Ok(Some(Ok(l))) => Some(String::from_utf8_lossy(&l).trim_end_matches('\r').to_string()),
                            Ok(Some(Err(_))) => return Err("SSE event too large".into()),
                            Ok(None) => None,
                            Err(e) => return Err(format!("SSE read failed: {e}")),
                        };
                        match line.as_deref() {
                            Some(l) if l.starts_with("data:") => {
                                let d = &l[5..];
                                if !data.is_empty() {
                                    data.push('\n');
                                }
                                data.push_str(d.strip_prefix(' ').unwrap_or(d));
                                continue;
                            }
                            Some(l) if !l.is_empty() => continue, // event:, id:, comments
                            _ => {}
                        }
                        if let Ok(v) = serde_json::from_str::<Value>(&std::mem::take(&mut data)) {
                            if let Some(r) = handle(v) {
                                return r.map_err(|e| e.to_string());
                            }
                        }
                        if line.is_none() {
                            return Err("SSE stream ended without a response".into());
                        }
                    }
                }
                let mut raw = Vec::new();
                reader.read_to_end(&mut raw).map_err(|e| format!("read failed: {e}"))?;
                if raw.len() > MAX_MESSAGE {
                    return Err(format!("response larger than {MAX_MESSAGE} bytes"));
                }
                let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("invalid JSON response: {e}"))?;
                for m in if let Value::Array(a) = v { a } else { vec![v] } {
                    if let Some(r) = handle(m) {
                        return r.map_err(|e| e.to_string());
                    }
                }
                Err("response did not answer the request (id mismatch)".into())
            })();
            let _ = tx.send(r);
        });
        rx
    }
}

impl Conn for HttpConn {
    fn request(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let rx = self.post(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}), Some(id));
        wait(&rx, timeout, cancel, method)?.map_err(|e| serde_json::from_str::<Value>(&e).map(|v| rpc_error(method, &v)).unwrap_or_else(|_| format!("{method}: {e}")))
    }
    fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let rx = self.post(json!({"jsonrpc": "2.0", "method": method, "params": params}), None);
        wait(&rx, Duration::from_secs(10), &Cancel::new(), method)?.map(|_| ())
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn set_protocol(&self, v: &str) {
        *self.protocol.lock().unwrap() = Some(v.to_string());
    }
}

/// Wait (bounded) for the stderr reader to finish; a grandchild holding the
/// pipe open must not stall error reporting.
fn wait_drained(d: &Arc<(Mutex<bool>, std::sync::Condvar)>) {
    let g = d.0.lock().unwrap();
    let _ = d.1.wait_timeout_while(g, Duration::from_millis(300), |done| !*done);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_lines() {
        let data = b"short\nthis-line-is-way-too-long\nok\nlast-no-newline";
        let mut r = BufReader::with_capacity(4, &data[..]);
        assert_eq!(read_line_capped(&mut r, 10).unwrap(), Some(Ok(b"short".to_vec())));
        assert_eq!(read_line_capped(&mut r, 10).unwrap(), Some(Err(25)));
        assert_eq!(read_line_capped(&mut r, 10).unwrap(), Some(Ok(b"ok".to_vec())));
        assert_eq!(read_line_capped(&mut r, 100).unwrap(), Some(Ok(b"last-no-newline".to_vec())));
        assert_eq!(read_line_capped(&mut r, 100).unwrap(), None);
    }
}
