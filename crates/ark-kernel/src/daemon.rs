//! arkd: the long-running host. Serves ARP (JSON-RPC 2.0, one JSON object per
//! line) on a 0600 unix socket, runs the scheduler and goals, and resumes
//! interrupted sessions after a crash or reboot.

use crate::approver::{Pending, PendingItem};
use crate::automation::{self, Goal, GoalStatus, Job};
use crate::event::EventKind;
use crate::kernel::{BusMsg, Kernel, Runtime};
use crate::util::unix_now;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

pub const PROTOCOL_VERSION: u32 = 1;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Pending approvals/questions published on the kernel bus once it exists.
pub fn pending_approver(timeout: Duration) -> (Arc<Pending>, Arc<OnceLock<Weak<Runtime>>>) {
    let cell: Arc<OnceLock<Weak<Runtime>>> = Arc::new(OnceLock::new());
    let c2 = cell.clone();
    let p = Pending::new(
        timeout,
        Box::new(move |item| {
            // Approvals are already published by the runner; questions are not.
            if let PendingItem::Question { .. } = &item {
                if let Some(k) = c2.get().and_then(|w| w.upgrade()) {
                    k.bus.publish(BusMsg::Pending(item));
                }
            }
        }),
    );
    (Arc::new(p), cell)
}

/// Extra ARP methods registered by the host (channels, MCP, pairing, nodes…).
/// Returns `None` when the method is not theirs.
pub type MethodExt = Arc<dyn Fn(&str, &Value) -> Option<Result<Value, (i32, String)>> + Send + Sync>;

pub struct Daemon {
    pub k: Kernel,
    pub pending: Arc<Pending>,
    busy_jobs: Arc<Mutex<HashSet<String>>>,
    busy_goals: Arc<Mutex<HashSet<String>>>,
    ext: Mutex<Vec<MethodExt>>,
}

impl Daemon {
    pub fn new(k: Kernel, pending: Arc<Pending>) -> Self {
        Daemon { k, pending, busy_jobs: Default::default(), busy_goals: Default::default(), ext: Mutex::new(vec![]) }
    }

    pub fn add_methods(&self, m: MethodExt) {
        self.ext.lock().unwrap().push(m);
    }

    /// Method names served by this daemon (kernel + host extensions are not enumerable;
    /// hosts list theirs via `capabilities`).
    pub const METHODS: &'static [&'static str] = &[
        "ping", "session.list", "session.create", "session.submit", "session.interrupt", "session.history", "session.view",
        "gate.pending", "gate.answer", "session.command", "goal.start", "goal.list", "schedule.list", "models.list", "tools.list", "shutdown", "session.attach", "events.subscribe",
    ];

    pub fn run(self: Arc<Self>) -> Result<(), String> {
        let rt = &self.k.paths.runtime;
        std::fs::create_dir_all(rt).map_err(|e| format!("{}: {e}", rt.display()))?;
        std::fs::set_permissions(rt, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let sock = self.k.paths.socket();
        if sock.exists() {
            if UnixStream::connect(&sock).is_ok() {
                return Err(format!("arkd is already running ({})", sock.display()));
            }
            std::fs::remove_file(&sock).map_err(|e| e.to_string())?; // stale
        }
        let listener = UnixListener::bind(&sock).map_err(|e| format!("bind {}: {e}", sock.display()))?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let pid_path = rt.join("arkd.pid");
        let _ = std::fs::write(&pid_path, std::process::id().to_string());
        // SAFETY: installing a handler that only stores to an atomic.
        unsafe {
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        }
        STOP.store(false, Ordering::SeqCst);

        self.resume();
        // C7: the process-group supervisor. `ark-tools` registers every group it starts;
        // this thread reaps the ones whose owner died (crash, SIGKILL, daemon restart). It
        // only ever signals groups it recorded itself, and only when the recorded start time
        // still matches — a recycled pid (the user's browser) is never touched.
        let reap = self.k.cfg.limits.reap_interval_secs;
        if reap > 0 {
            crate::reaper::spawn_sweeper(self.k.paths.data.clone(), Duration::from_secs(reap));
        }
        let me = self.clone();
        let sched = std::thread::spawn(move || me.scheduler_loop());
        sd_notify("READY=1\nSTATUS=arkd listening");

        while !STOP.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((conn, _)) => {
                    let me = self.clone();
                    std::thread::spawn(move || me.serve(conn));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }

        sd_notify("STOPPING=1");
        // Graceful shutdown: interrupt runs (their logs stay consistent), wait a bit.
        for id in self.k.running_ids() {
            self.k.interrupt(&id);
        }
        let until = Instant::now() + Duration::from_secs(10);
        while !self.k.running_ids().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = sched.join();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_file(&pid_path);
        Ok(())
    }

    pub fn stop() {
        STOP.store(true, Ordering::SeqCst);
    }

    /// Restart work that was in flight when the daemon died.
    fn resume(&self) {
        let week_ms = 7 * 86_400 * 1000;
        let now = crate::event::now_ms();
        for s in self.k.store.list().into_iter().filter(|s| now.saturating_sub(s.updated_ms) < week_ms && s.parent.is_none()) {
            let Ok(events) = self.k.store.read(&s.id) else { continue };
            let v = crate::projection::project(&events);
            let open_turn = events.iter().rev().find_map(|e| match e.kind {
                EventKind::TurnStart { .. } => Some(true),
                EventKind::TurnEnd { .. } => Some(false),
                _ => None,
            }) == Some(true);
            if !v.pending_inbox.is_empty() || open_turn || !v.dangling.is_empty() {
                let _ = self.k.start(&s.id, Default::default());
            }
        }
        if let Ok(goals) = automation::read_list::<Goal>(&automation::goals_path(&self.k.paths.data)) {
            for g in goals.into_iter().filter(|g| g.status == GoalStatus::Active) {
                self.start_goal(&g.id);
            }
        }
    }

    fn start_goal(&self, id: &str) -> bool {
        if ark_security::estop::is_engaged(&self.k.paths.data) {
            eprintln!("arkd: goal {id} not started: paused (ark resume)");
            return false;
        }
        if !self.busy_goals.lock().unwrap().insert(id.to_string()) {
            return false;
        }
        let k = self.k.clone();
        let busy = self.busy_goals.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let _ = automation::run_goal(&k, &id);
            busy.lock().unwrap().remove(&id);
        });
        true
    }

    /// Delete sessions older than `compliance.retention_days` (never a running one).
    /// Retry the session of every due provider pause (`limits::due_pauses`). A pause that
    /// keeps failing backs off (1 min → 1 h for transient, 15 min → 6 h for billing); the
    /// session never dies and its log is untouched between attempts.
    fn retry_paused(&self) -> usize {
        if ark_security::estop::is_engaged(&self.k.paths.data) {
            return 0;
        }
        let mut n = 0;
        for p in crate::limits::due_pauses(&self.k.paths.data, crate::event::now_ms()) {
            if p.session.is_empty() || self.k.is_running(&p.session) {
                continue;
            }
            crate::limits::bump_pause(&self.k.paths.data, &p);
            eprintln!("arkd: resuming paused session {} ({})", p.session, p.reason);
            let _ = self.k.start(&p.session, Default::default());
            n += 1;
        }
        n
    }

    /// One retention pass over sessions, audit, broker log, logs and exports (ent-077),
    /// skipping anything under a legal hold. Returns the number of sessions deleted.
    pub fn enforce_retention(&self) -> usize {
        let out = crate::governance::enforce_retention(&self.k);
        for (class, n) in &out {
            if *n > 0 {
                eprintln!("arkd: retention: removed {n} {class} item(s)");
            }
        }
        out.iter().find(|(c, _)| *c == "sessions").map(|(_, n)| *n).unwrap_or(0)
    }

    /// Forward new audit records to the configured SIEM sinks (ent-074…076).
    fn pump_audit(&self) {
        let cfg = &self.k.cfg.audit.export;
        if cfg.sinks().is_empty() {
            return;
        }
        let subst = self.k.vault_substitute();
        for (sink, r) in ark_security::audit_export::pump(&self.k.paths.data, cfg, &|s: &str| subst(s)) {
            if let Err(e) = r {
                eprintln!("arkd: audit export to {sink}: {e}");
            }
        }
    }

    fn scheduler_loop(&self) {
        let tick = Duration::from_secs(self.k.cfg.schedule.tick_secs.max(1));
        let mut last = Instant::now() - tick;
        let mut last_retention = Instant::now() - Duration::from_secs(3600);
        // C1/C2: paused sessions are retried on their own schedule (a transient network
        // failure or a topped-up account resumes without the user doing anything).
        let mut last_resume = Instant::now() - Duration::from_secs(30);
        let mut last_export = Instant::now() - Duration::from_secs(3600);
        ark_security::audit::set_rotate_bytes(self.k.cfg.audit.rotate_mb.max(1) * 1024 * 1024);
        while !STOP.load(Ordering::SeqCst) {
            if last_export.elapsed() >= Duration::from_secs(self.k.cfg.audit.export_secs.max(1)) {
                last_export = Instant::now();
                self.pump_audit();
            }
            if last_resume.elapsed() >= Duration::from_secs(30) {
                last_resume = Instant::now();
                self.retry_paused();
            }
            if last_retention.elapsed() >= Duration::from_secs(3600) {
                last_retention = Instant::now();
                self.enforce_retention();
                let c = &self.k.cfg.checkpoint;
                if c.auto_prune {
                    let _ = crate::checkpoint::Store::new(&self.k.paths.data).maybe_auto_prune(c.retention_days, c.min_interval_hours, c.max_total_size_mb * 1024 * 1024);
                }
            }
            // Global emergency stop: claim nothing (jobs stay due and run after `ark resume`).
            if last.elapsed() >= tick && ark_security::estop::is_engaged(&self.k.paths.data) {
                last = Instant::now();
            }
            // An external cron provider (chronos) owns firing: it calls back per job.
            if last.elapsed() >= tick && crate::cronjob::chronos::owns_ticks(&self.k.paths.data) {
                last = Instant::now();
            }
            if last.elapsed() >= tick {
                last = Instant::now();
                let busy: Vec<String> = self.busy_jobs.lock().unwrap().iter().cloned().collect();
                match automation::claim_due(&self.k.paths.data, unix_now(), self.k.cfg.schedule.utc_offset_minutes, &busy) {
                    Ok(due) => {
                        for job in due {
                            self.busy_jobs.lock().unwrap().insert(job.id.clone());
                            let k = self.k.clone();
                            let busy = self.busy_jobs.clone();
                            std::thread::spawn(move || {
                                let _ = automation::run_job(&k, &job);
                                busy.lock().unwrap().remove(&job.id);
                            });
                        }
                    }
                    Err(e) => eprintln!("arkd: scheduler: {e}"),
                }
            }
            crate::kanban::dispatch::daemon_tick(&self.k);
            crate::heartbeat::daemon_tick(&self.k);
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn serve(&self, conn: UnixStream) {
        let Ok(mut w) = conn.try_clone() else { return };
        let reader = BufReader::new(conn);
        for line in reader.lines() {
            let Ok(line) = line else { return };
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    if send(&mut w, &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}})).is_err() {
                        return;
                    }
                    continue;
                }
            };
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
            let params = req.get("params").cloned().unwrap_or(json!({}));
            if method == "session.attach" || method == "events.subscribe" {
                self.stream(&mut w, id, &method, &params);
                return;
            }
            let resp = match self.call(&method, &params) {
                Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
                Err((code, message)) => json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
            };
            if send(&mut w, &resp).is_err() {
                return;
            }
        }
    }

    pub fn call(&self, method: &str, p: &Value) -> Result<Value, (i32, String)> {
        let s = |k: &str| p.get(k).and_then(|v| v.as_str()).map(String::from);
        let need = |k: &str| s(k).ok_or((-32602, format!("missing param `{k}`")));
        let kerr = |e: crate::kernel::KernelError| (-32000, e.to_string());
        let k = &self.k;
        match method {
            "ping" => Ok(json!({"protocol": PROTOCOL_VERSION, "version": env!("CARGO_PKG_VERSION"), "running": k.running_ids(), "pid": std::process::id()})),
            "session.list" => {
                let lim = p.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
                Ok(json!(k.store.list().into_iter().take(lim).map(|s| json!({"id":s.id,"title":s.title,"model":s.model,"workspace":s.workspace,"updated_ms":s.updated_ms,"messages":s.messages,"parent":s.parent,"running":k.is_running(&s.id)})).collect::<Vec<_>>()))
            }
            "session.create" => {
                let ws = need("workspace")?;
                let id = k.create_session(Path::new(&ws), s("model").as_deref(), None, s("title").as_deref()).map_err(kerr)?;
                Ok(json!({"id": id}))
            }
            "session.submit" => {
                let id = need("id")?;
                let text = need("text")?;
                k.submit(&id, &text, s("source").as_deref().unwrap_or("cli")).map_err(kerr)?;
                let started = !k.is_running(&id);
                if started {
                    let _ = k.start(&id, Default::default());
                }
                Ok(json!({"queued": true, "started": started}))
            }
            "session.interrupt" => Ok(json!({"interrupted": k.interrupt(&need("id")?)})),
            "gate.pending" => Ok(json!(self.pending.list().into_iter().map(pending_json).collect::<Vec<_>>())),
            "gate.answer" => {
                // `_by` is set by the app server from the authenticated principal; on the
                // owner-only unix socket the caller is the local user.
                let who = s("_by").map(|b| ark_security::audit::Actor::parse_label(&b)).unwrap_or_else(ark_security::audit::Actor::local);
                let via = s("_via").unwrap_or_else(|| "arp".into());
                let ok = crate::approver::answer_by(&*self.pending, &k.paths.data, &need("id")?, &need("answer")?, &who, &via);
                if ok {
                    Ok(json!({"ok": true}))
                } else {
                    Err((-32001, "no such pending item (already answered or timed out)".into()))
                }
            }
            // Security slash commands (/approve /deny /yolo /approvals /elevated /exec /pause /resume)
            // for the TUI and web UI; `handled: false` when the line is not one of them.
            "session.command" => {
                let line = need("line")?;
                let sid = s("id").filter(|i| !i.is_empty());
                if let Some(i) = sid.as_deref().filter(|i| !k.store.exists(i)) {
                    return Err((-32602, format!("no such session `{i}`")));
                }
                Ok(match crate::secgate::chat_command(k, &line, sid.as_deref(), None) {
                    Some(text) => json!({"handled": true, "text": text}),
                    None => json!({"handled": false}),
                })
            }
            "goal.start" => Ok(json!({"started": self.start_goal(&need("id")?)})),
            "goal.list" => automation::read_list::<Goal>(&automation::goals_path(&k.paths.data)).map(|g| json!(g)).map_err(|e| (-32000, e)),
            "schedule.list" => automation::read_list::<Job>(&automation::jobs_path(&k.paths.data)).map(|j| json!(j)).map_err(|e| (-32000, e)),
            "session.history" => {
                let from = p.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let evs = k.store.read(&need("id")?).map_err(|e| (-32000, e.to_string()))?;
                Ok(json!(evs.into_iter().filter(|e| e.seq >= from).collect::<Vec<_>>()))
            }
            "session.view" => {
                // The conversation as the model sees it, for UIs that render a transcript.
                let evs = k.store.read(&need("id")?).map_err(|e| (-32000, e.to_string()))?;
                let v = crate::projection::project(&evs);
                Ok(json!({"messages": v.messages, "running": k.is_running(&need("id")?), "workspace": v.workspace}))
            }
            "models.list" => {
                let c = &k.cfg.model;
                Ok(json!({"default": c.default, "fallback": c.fallback, "aux": k.cfg.aux_model()}))
            }
            "tools.list" => Ok(json!(k.specs().into_iter().map(|s| json!({"name": s.name, "description": s.description})).collect::<Vec<_>>())),
            "shutdown" => {
                Daemon::stop();
                Ok(json!({"stopping": true}))
            }
            "" => Err((-32600, "missing method".into())),
            m if m.starts_with("kanban.") || m.starts_with("board.") => crate::kanban::methods::call(k, m, p).unwrap_or_else(|| Err((-32601, format!("unknown method `{m}`")))),
            m => {
                for f in self.ext.lock().unwrap().iter() {
                    if let Some(r) = f(m, p) {
                        return r;
                    }
                }
                Err((-32601, format!("unknown method `{m}`")))
            }
        }
    }

    /// Stream events. For `session.attach`: replay the log from `from_seq`, then
    /// follow live; ends when the client disconnects.
    fn stream(&self, w: &mut UnixStream, id: Value, method: &str, p: &Value) {
        let mut sink = |v: &Value| send(w, v);
        self.stream_to(&mut sink, id, method, p, &|| false);
    }

    /// Stream to any sink (unix socket, WebSocket, SSE). `stop` ends the stream early.
    pub fn stream_to(&self, sink: &mut dyn FnMut(&Value) -> std::io::Result<()>, id: Value, method: &str, p: &Value, stop: &dyn Fn() -> bool) {
        let w = sink;
        let rx = self.k.bus.subscribe();
        let session = p.get("id").and_then(|v| v.as_str()).map(String::from);
        let mut last_seq: Option<u64> = None;
        if method == "session.attach" {
            let Some(sid) = session.as_deref() else {
                let _ = w(&json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"missing param `id`"}}));
                return;
            };
            let from = p.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(0);
            match self.k.store.read(sid) {
                Ok(evs) => {
                    for e in evs.into_iter().filter(|e| e.seq >= from) {
                        last_seq = Some(e.seq);
                        if w(&json!({"jsonrpc":"2.0","method":"event","params":{"session":sid,"event":e}})).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = w(&json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":e.to_string()}}));
                    return;
                }
            }
        }
        if w(&json!({"jsonrpc":"2.0","id":id,"result":{"live":true,"running": session.as_deref().map(|s| self.k.is_running(s))}})).is_err() {
            return;
        }
        loop {
            if stop() {
                return;
            }
            let msg = match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(m) => m,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Heartbeat doubles as disconnect detection.
                    if w(&json!({"jsonrpc":"2.0","method":"heartbeat","params":{}})).is_err() || STOP.load(Ordering::SeqCst) || stop() {
                        return;
                    }
                    continue;
                }
                Err(_) => return,
            };
            let out = match &msg {
                BusMsg::Event { session: s, event } if session.as_ref().is_none_or(|x| x == s) => {
                    if session.is_some() && last_seq.is_some_and(|l| event.seq <= l) {
                        continue;
                    }
                    json!({"jsonrpc":"2.0","method":"event","params":{"session":s,"event":event}})
                }
                BusMsg::Delta { session: s, text, thinking } if session.as_ref().is_none_or(|x| x == s) => json!({"jsonrpc":"2.0","method":"delta","params":{"session":s,"text":text,"thinking":thinking}}),
                BusMsg::Pending(item) if session.as_ref().is_none_or(|x| pending_session(item) == x) => json!({"jsonrpc":"2.0","method":"pending","params":pending_json(item.clone())}),
                _ => continue,
            };
            if w(&out).is_err() {
                return;
            }
        }
    }
}

fn pending_session(i: &PendingItem) -> &str {
    match i {
        PendingItem::Approval(a) => &a.session,
        PendingItem::Question { session, .. } => session,
    }
}

fn pending_json(i: PendingItem) -> Value {
    match i {
        PendingItem::Approval(a) => json!({"kind":"approval","id":a.id,"session":a.session,"tool":a.tool,"gate":format!("{:?}", a.gate).to_lowercase(),"reason":a.reason,"summary":a.summary}),
        PendingItem::Question { id, session, question, choices, multi } => json!({"kind":"question","id":id,"session":session,"question":question,"choices":choices,"multi_select":multi}),
    }
}

fn send(w: &mut UnixStream, v: &Value) -> std::io::Result<()> {
    let mut b = serde_json::to_vec(v)?;
    b.push(b'\n');
    w.write_all(&b)?;
    w.flush()
}

/// systemd `Type=notify` readiness (no crate: one datagram to $NOTIFY_SOCKET).
pub fn sd_notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let sock = match std::os::unix::net::UnixDatagram::unbound() {
        Ok(s) => s,
        Err(_) => return,
    };
    let p = path.to_string_lossy().into_owned();
    if let Some(abs) = p.strip_prefix('@') {
        // Abstract namespace socket.
        use std::os::linux::net::SocketAddrExt;
        if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(abs.as_bytes()) {
            let _ = sock.send_to_addr(state.as_bytes(), &addr);
        }
    } else {
        let _ = sock.send_to(state.as_bytes(), &p);
    }
}

// ───────────────────────── client side ─────────────────────────

pub fn connect(sock: &Path) -> Result<UnixStream, String> {
    UnixStream::connect(sock).map_err(|e| format!("arkd is not running ({}: {e}). Start it with `ark daemon start`.", sock.display()))
}

pub fn call(sock: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut s = connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    send(&mut s, &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("bad response from arkd: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(err.get("message").and_then(|m| m.as_str()).unwrap_or("error").to_string());
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

/// Open a stream; `on` returns false to stop.
pub fn stream(sock: &Path, method: &str, params: Value, mut on: impl FnMut(&Value) -> bool) -> Result<(), String> {
    let mut s = connect(sock)?;
    send(&mut s, &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).map_err(|e| e.to_string())?;
    for line in BufReader::new(s).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if let Some(err) = v.get("error") {
            return Err(err.get("message").and_then(|m| m.as_str()).unwrap_or("error").to_string());
        }
        if !on(&v) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod session_command_tests {
    use super::*;

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    #[test]
    fn session_command_runs_security_slash_commands() {
        let root = std::env::temp_dir().join(format!("ark-daemon-cmd-{}", std::process::id()));
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let d = Daemon::new(k.clone(), pending);
        let id = k.create_session(&root, None, None, Some("t")).unwrap();
        let r = d.call("session.command", &json!({"id": id, "line": "/yolo on"})).unwrap();
        assert_eq!(r["handled"], true);
        assert!(ark_security::approvals::yolo_active(&k.paths.data, &id));
        let r = d.call("session.command", &json!({"id": id, "line": "/approvals"})).unwrap();
        assert!(r["text"].as_str().unwrap().contains("yolo=true"), "{r}");
        assert_eq!(d.call("session.command", &json!({"id": id, "line": "/compact"})).unwrap()["handled"], false);
        assert!(d.call("session.command", &json!({"id": "nope-123", "line": "/yolo"})).is_err());
        assert!(d.call("session.command", &json!({"id": id})).is_err());
        assert!(Daemon::METHODS.contains(&"session.command"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
