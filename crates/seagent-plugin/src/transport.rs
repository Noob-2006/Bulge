//! JSON-RPC 2.0 transports: newline-delimited stdio to a child process, and
//! MCP Streamable HTTP (POST, JSON or SSE reply). Both are blocking and
//! observe a deadline plus `Cancel` while waiting.

use seagent_core::Cancel;
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
    /// Same as `request`, plus HTTP headers (the stateless revision's Mcp-Method /
    /// Mcp-Name / Mcp-Param-*); non-HTTP transports ignore them.
    fn request_h(&self, method: &str, params: Value, _headers: &[(String, String)], timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        self.request(method, params, timeout, cancel)
    }
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
    // `data` matters for -32042 (URL elicitations) and -32022 (supported versions).
    match e.get("data").filter(|d| !d.is_null()).map(Value::to_string).filter(|d| d.len() <= 16 * 1024) {
        Some(d) => format!("{method}: server error {code}: {msg} [data:{d}]"),
        None => format!("{method}: server error {code}: {msg}"),
    }
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
                log(format!("[seagent] response with foreign id {id}"));
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
                None => log(format!("[seagent] response for unknown request id {n} (late or mismatched)")),
            }
            None
        }
        (None, None) => {
            log("[seagent] message without method or id".into());
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
        // npx/uvx/pipx packages: refuse known malware (OSV MAL-* advisories); fails open offline.
        if let Some(blocked) = seagent_security::osv::launch_check(command, args) {
            return Err(blocked);
        }
        // The child is spawned and reaped by a keeper thread that lives exactly as long
        // as the child: PDEATHSIG fires when the *spawning thread* dies, so spawning from
        // a short-lived caller thread would kill the server under us.
        let (tx, rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let pending: Pending = Arc::default();
        let stderr: Arc<Mutex<VecDeque<u8>>> = Arc::default();
        let mut cmd = Command::new(command);
        seagent_security::envscrub::apply(&mut cmd, seagent_security::envscrub::Surface::Server);
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
            push_log(&se, format!("[seagent] server exited: {status}").as_bytes());
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
                            _ => log(format!("[seagent] ignored non-JSON stdout: {}", text.chars().take(200).collect::<String>())),
                        }
                    }
                    Ok(Some(Err(n))) => log(format!("[seagent] dropped oversized message ({n} bytes > {MAX_MESSAGE})")),
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

// ───────────────────────── HTTP shared ─────────────────────────

/// Options shared by the HTTP transports.
#[derive(Clone)]
pub(crate) struct HttpOpts {
    pub headers: Vec<(String, String)>,
    pub timeout: Duration,
    /// OAuth token store: bearer on every request, refresh once on 401.
    pub auth: Option<Arc<crate::oauth::Store>>,
    /// Shown in auth errors: `seagent mcp login <name>`.
    pub server: String,
    pub tls: Option<ureq::tls::TlsConfig>,
}

pub(crate) fn http_agent(o: &HttpOpts, global: Option<Duration>) -> ureq::Agent {
    let mut b = seagent_net::http::builder().http_status_as_error(false).timeout_connect(Some(Duration::from_secs(10))).timeout_global(global);
    if let Some(t) = &o.tls {
        b = b.tls_config(t.clone());
    }
    b.build().into()
}

/// TLS config from `ca_cert` / `client_cert` / `client_key` / `ssl_verify`.
pub(crate) fn tls_from(ca: Option<&PathBuf>, cert: Option<&PathBuf>, key: Option<&PathBuf>, verify: bool) -> Result<Option<ureq::tls::TlsConfig>, String> {
    if ca.is_none() && cert.is_none() && verify {
        return Ok(None);
    }
    use ureq::tls::{parse_pem, ClientCert, PemItem, RootCerts, TlsConfig};
    let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let mut b = TlsConfig::builder().disable_verification(!verify);
    if let Some(ca) = ca {
        let pem = read(ca)?;
        let certs: Vec<_> = parse_pem(&pem).filter_map(|i| match i {
            Ok(PemItem::Certificate(c)) => Some(c),
            _ => None,
        }).collect();
        if certs.is_empty() {
            return Err(format!("{}: no PEM certificates", ca.display()));
        }
        b = b.root_certs(RootCerts::new_with_certs(&certs));
    } else if let Some(r) = seagent_net::http::custom_roots() {
        b = b.root_certs(RootCerts::Specific(r)); // no per-server CA: the `[network]` bundle (ent-037)
    }
    match (cert, key) {
        (Some(c), Some(k)) => {
            let cp = read(c)?;
            let chain: Vec<_> = parse_pem(&cp).filter_map(|i| match i {
                Ok(PemItem::Certificate(c)) => Some(c),
                _ => None,
            }).collect();
            let kp = read(k)?;
            let key = parse_pem(&kp).find_map(|i| match i {
                Ok(PemItem::PrivateKey(k)) => Some(k),
                _ => None,
            }).ok_or_else(|| format!("{}: no PEM private key", k.display()))?;
            b = b.client_cert(Some(ClientCert::new_with_certs(&chain, key)));
        }
        (None, None) => {}
        _ => return Err("client_cert and client_key must be set together".into()),
    }
    Ok(Some(b.build()))
}

fn auth_error(status: u16, challenge: Option<&str>, server: &str, oauth: bool) -> String {
    let scope = challenge.and_then(crate::oauth::scope_from_challenge);
    match (status, oauth) {
        (403, _) if challenge.is_some_and(|c| c.contains("insufficient_scope")) => format!("insufficient scope (HTTP 403){}; run `seagent mcp login {server}` to grant it", scope.map(|s| format!(": needs {s}")).unwrap_or_default()),
        (_, true) => format!("unauthorized (HTTP {status}); run `seagent mcp login {server}`"),
        (_, false) if challenge.is_some_and(|c| c.contains("resource_metadata")) => format!("unauthorized (HTTP {status}): this server uses OAuth; set `auth = \"oauth\"` in [mcp.{server}] and run `seagent mcp login {server}`"),
        _ => format!("unauthorized (HTTP {status}): check the server's headers / token"),
    }
}

/// Parse an SSE stream, calling `on_event(data)` per complete event; stops when it returns true.
fn read_sse(reader: &mut impl BufRead, mut on_event: impl FnMut(&str, &str) -> bool) -> Result<bool, String> {
    let mut data = String::new();
    let mut event = String::new();
    loop {
        let line = match read_line_capped(reader, MAX_MESSAGE) {
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
            Some(l) if l.starts_with("event:") => {
                event = l[6..].trim().to_string();
                continue;
            }
            Some(l) if !l.is_empty() => continue, // id:, retry:, comments
            _ => {}
        }
        if !data.is_empty() || !event.is_empty() {
            let ev = if event.is_empty() { "message".to_string() } else { std::mem::take(&mut event) };
            if on_event(&ev, &std::mem::take(&mut data)) {
                return Ok(true);
            }
        }
        if line.is_none() {
            return Ok(false);
        }
    }
}

// ───────────────────────── Streamable HTTP ─────────────────────────

pub(crate) struct HttpConn {
    agent: ureq::Agent,
    url: String,
    o: HttpOpts,
    session: Arc<Mutex<Option<String>>>,
    protocol: Arc<Mutex<Option<String>>>,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    notify_sink: Notify,
    on_req: OnRequest,
}

impl HttpConn {
    pub fn new(url: &str, o: HttpOpts, notify: Notify, on_req: OnRequest) -> Arc<Self> {
        // Bounds a worker whose caller already gave up.
        let agent = http_agent(&o, Some(o.timeout + Duration::from_secs(5)));
        Arc::new(HttpConn { agent, url: url.into(), o, session: Arc::default(), protocol: Arc::default(), next: AtomicU64::new(1), alive: Arc::new(AtomicBool::new(true)), notify_sink: notify, on_req })
    }

    fn post(&self, body: Value, want: Option<u64>) -> mpsc::Receiver<Result<Value, String>> {
        self.post_h(body, want, vec![])
    }

    fn post_h(&self, body: Value, want: Option<u64>, extra: Vec<(String, String)>) -> mpsc::Receiver<Result<Value, String>> {
        let (tx, rx) = mpsc::channel();
        let (agent, url, o) = (self.agent.clone(), self.url.clone(), self.o.clone());
        let (session, protocol, alive, notify, on_req) = (self.session.clone(), self.protocol.clone(), self.alive.clone(), self.notify_sink.clone(), self.on_req.clone());
        std::thread::spawn(move || {
            let send = |bearer: Option<String>| {
                let mut req = agent.post(&url).header("content-type", "application/json").header("accept", "application/json, text/event-stream");
                for (k, v) in &o.headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(t) = bearer {
                    req = req.header("authorization", &format!("Bearer {t}"));
                }
                if let Some(s) = session.lock().unwrap().as_deref() {
                    req = req.header("mcp-session-id", s);
                }
                if let Some(p) = protocol.lock().unwrap().as_deref() {
                    req = req.header("mcp-protocol-version", p);
                }
                for (k, v) in &extra {
                    req = req.header(k.as_str(), v.as_str());
                }
                req.send(&serde_json::to_vec(&body).unwrap()[..]).map_err(|e| format!("HTTP request failed: {e}"))
            };
            let r = (|| {
                let had_session = session.lock().unwrap().is_some();
                let mut resp = send(o.auth.as_ref().and_then(|a| a.bearer()))?;
                if resp.status().as_u16() == 401 {
                    // One refresh-and-retry; a revoked refresh token means a fresh login.
                    if let Some(t) = o.auth.as_ref().and_then(|a| a.force_refresh()) {
                        resp = send(Some(t))?;
                    }
                }
                let status = resp.status().as_u16();
                if let Some(s) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
                    *session.lock().unwrap() = Some(s.to_string());
                }
                let challenge = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
                let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
                let mut reader = BufReader::new(resp.into_body().into_reader().take(MAX_MESSAGE as u64 + 1));
                if !(200..300).contains(&status) {
                    let mut raw = String::new();
                    let _ = reader.by_ref().take(64 * 1024).read_to_string(&mut raw);
                    // A modern server answers 400/404 with a JSON-RPC error body: surface it as one.
                    if let Some(e) = serde_json::from_str::<Value>(&raw).ok().and_then(|v| v.get("error").cloned()).filter(|e| e.get("code").is_some()) {
                        if status == 400 || status == 404 {
                            return Err(e.to_string());
                        }
                    }
                    return Err(match status {
                        401 | 403 => auth_error(status, challenge.as_deref(), &o.server, o.auth.is_some()),
                        404 if had_session => {
                            alive.store(false, Ordering::SeqCst); // session expired: reconnect next call
                            "session expired (HTTP 404); will reconnect".to_string()
                        }
                        404 => "not found (HTTP 404): wrong MCP URL?".to_string(),
                        _ => format!("HTTP {status}: {}", raw.trim().chars().take(300).collect::<String>()),
                    });
                }
                let Some(want) = want else { return Ok(Value::Null) };
                let pending = Mutex::new(HashMap::new());
                let (rtx, rrx) = mpsc::channel();
                pending.lock().unwrap().insert(want, rtx);
                let mut ignore = |_s: String| {};
                // Server → client requests inside the stream (sampling, elicitation, roots) are
                // answered with a separate POST.
                let reply_to = |reply: Value| {
                    let (agent, url, o, session, protocol) = (agent.clone(), url.clone(), o.clone(), session.clone(), protocol.clone());
                    std::thread::spawn(move || {
                        let mut req = agent.post(&url).header("content-type", "application/json").header("accept", "application/json, text/event-stream");
                        for (k, v) in &o.headers {
                            req = req.header(k.as_str(), v.as_str());
                        }
                        if let Some(t) = o.auth.as_ref().and_then(|a| a.bearer()) {
                            req = req.header("authorization", &format!("Bearer {t}"));
                        }
                        if let Some(s) = session.lock().unwrap().as_deref() {
                            req = req.header("mcp-session-id", s);
                        }
                        if let Some(p) = protocol.lock().unwrap().as_deref() {
                            req = req.header("mcp-protocol-version", p);
                        }
                        let _ = req.send(&serde_json::to_vec(&reply).unwrap()[..]);
                    });
                };
                let mut handle = |v: Value| {
                    if let Some(reply) = route(v, &pending, &notify, &on_req, &mut ignore) {
                        reply_to(reply);
                    }
                    rrx.try_recv().ok()
                };
                if ctype.starts_with("text/event-stream") {
                    let mut out = None;
                    read_sse(&mut reader, |_, data| {
                        if let Ok(v) = serde_json::from_str::<Value>(data) {
                            if let Some(r) = handle(v) {
                                out = Some(r);
                                return true;
                            }
                        }
                        false
                    })?;
                    return match out {
                        Some(r) => r.map_err(|e| e.to_string()),
                        None => Err("SSE stream ended without a response".into()),
                    };
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
        self.request_h(method, params, &[], timeout, cancel)
    }
    fn request_h(&self, method: &str, params: Value, headers: &[(String, String)], timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let rx = self.post_h(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}), Some(id), headers.to_vec());
        match wait(&rx, timeout, cancel, method) {
            Ok(r) => r.map_err(|e| serde_json::from_str::<Value>(&e).map(|v| rpc_error(method, &v)).unwrap_or_else(|_| format!("{method}: {e}"))),
            Err(e) => {
                let _ = self.post(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id, "reason": e}}), None);
                Err(e)
            }
        }
    }
    fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let rx = self.post(json!({"jsonrpc": "2.0", "method": method, "params": params}), None);
        wait(&rx, Duration::from_secs(10), &Cancel::new(), method)?.map(|_| ())
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn set_protocol(&self, v: &str) {
        *self.protocol.lock().unwrap() = Some(v.to_string()).filter(|v| !v.is_empty());
    }
}

impl Drop for HttpConn {
    /// Politely end the session (servers may answer 405 when they do not support it).
    fn drop(&mut self) {
        let Some(sid) = self.session.lock().unwrap().clone() else { return };
        let mut req = self.agent.delete(&self.url).header("mcp-session-id", &sid);
        for (k, v) in &self.o.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(t) = self.o.auth.as_ref().and_then(|a| a.bearer()) {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        std::thread::spawn(move || {
            let _ = req.call();
        });
    }
}

// ───────────────────────── legacy HTTP+SSE (2024-11-05) ─────────────────────────

/// GET opens an event stream whose first `endpoint` event names the URL to POST
/// messages to; every response and server request arrives on the stream.
pub(crate) struct SseConn {
    post_agent: ureq::Agent,
    endpoint: String,
    o: HttpOpts,
    pending: Pending,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl SseConn {
    pub fn connect(url: &str, o: HttpOpts, notify: Notify, on_req: OnRequest) -> Result<Arc<Self>, String> {
        let stream_agent = http_agent(&o, None);
        let mut req = stream_agent.get(url).header("accept", "text/event-stream");
        for (k, v) in &o.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(t) = o.auth.as_ref().and_then(|a| a.bearer()) {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        let resp = req.call().map_err(|e| format!("SSE connect failed: {e}"))?;
        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            let ch = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_string);
            return Err(auth_error(status, ch.as_deref(), &o.server, o.auth.is_some()));
        }
        if !(200..300).contains(&status) {
            return Err(format!("SSE connect: HTTP {status}"));
        }
        let mut reader = BufReader::new(resp.into_body().into_reader());
        let (etx, erx) = mpsc::channel::<String>();
        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let base = url.to_string();
        let (p, a, st) = (pending.clone(), alive.clone(), stop.clone());
        let post_agent = http_agent(&o, Some(o.timeout + Duration::from_secs(5)));
        let (pa, oo) = (post_agent.clone(), o.clone());
        std::thread::spawn(move || {
            let endpoint: Arc<Mutex<Option<String>>> = Arc::default();
            let mut ignore = |_s: String| {};
            let _ = read_sse(&mut reader, |ev, data| {
                if st.load(Ordering::SeqCst) {
                    return true;
                }
                if ev == "endpoint" {
                    let full = join_url(&base, data.trim());
                    *endpoint.lock().unwrap() = Some(full.clone());
                    let _ = etx.send(full);
                    return false;
                }
                if let Ok(v) = serde_json::from_str::<Value>(data) {
                    if let Some(reply) = route(v, &p, &notify, &on_req, &mut ignore) {
                        if let Some(ep) = endpoint.lock().unwrap().clone() {
                            let mut req = pa.post(&ep).header("content-type", "application/json");
                            for (k, v) in &oo.headers {
                                req = req.header(k.as_str(), v.as_str());
                            }
                            let _ = req.send(&serde_json::to_vec(&reply).unwrap()[..]);
                        }
                    }
                }
                false
            });
            a.store(false, Ordering::SeqCst);
            for (_, tx) in p.lock().unwrap().drain() {
                let _ = tx.send(Err("SSE stream closed before replying".into()));
            }
        });
        let endpoint = erx.recv_timeout(o.timeout.min(Duration::from_secs(10))).map_err(|_| "SSE server sent no `endpoint` event".to_string())?;
        Ok(Arc::new(SseConn { post_agent, endpoint, o, pending, next: AtomicU64::new(1), alive, stop }))
    }

    fn post(&self, v: &Value) -> Result<(), String> {
        let mut req = self.post_agent.post(&self.endpoint).header("content-type", "application/json");
        for (k, val) in &self.o.headers {
            req = req.header(k.as_str(), val.as_str());
        }
        if let Some(t) = self.o.auth.as_ref().and_then(|a| a.bearer()) {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        let r = req.send(&serde_json::to_vec(v).unwrap()[..]).map_err(|e| format!("POST failed: {e}"))?;
        match r.status().as_u16() {
            200..=299 => Ok(()),
            404 => {
                self.alive.store(false, Ordering::SeqCst);
                Err("session expired (HTTP 404); will reconnect".into())
            }
            s => Err(format!("POST: HTTP {s}")),
        }
    }
}

/// Resolve the server's `endpoint` (absolute, absolute-path or relative).
fn join_url(base: &str, ep: &str) -> String {
    if ep.starts_with("http://") || ep.starts_with("https://") {
        return ep.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("http", base));
    let host = rest.split('/').next().unwrap_or(rest);
    if ep.starts_with('/') {
        format!("{scheme}://{host}{ep}")
    } else {
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        format!("{dir}/{ep}")
    }
}

impl Conn for SseConn {
    fn request(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        if !self.alive() {
            return Err("SSE stream is closed".into());
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().unwrap().insert(id, tx);
        if let Err(e) = self.post(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})) {
            self.pending.lock().unwrap().remove(&id);
            return Err(format!("{method}: {e}"));
        }
        match wait(&rx, timeout, cancel, method) {
            Ok(r) => r.map_err(|e| serde_json::from_str::<Value>(&e).map(|v| rpc_error(method, &v)).unwrap_or(e)),
            Err(e) => {
                self.pending.lock().unwrap().remove(&id);
                let _ = self.post(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id, "reason": e}}));
                Err(e)
            }
        }
    }
    fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        self.post(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Drop for SseConn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Wait (bounded) for the stderr reader to finish; a grandchild holding the
/// pipe open must not stall error reporting.
fn wait_drained(d: &Arc<(Mutex<bool>, std::sync::Condvar)>) {
    let g = d.0.lock().unwrap();
    let _ = d.1.wait_timeout_while(g, Duration::from_millis(1000), |done| !*done);
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
