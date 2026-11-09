//! seagentd: the long-running host. Serves ARP (JSON-RPC 2.0, one JSON object per
//! line) on a 0600 unix socket (Windows: an owner-only named pipe, see
//! `seagent_core::platform::ipc`), runs the scheduler and goals, and resumes
//! interrupted sessions after a crash or reboot.

use crate::approver::{Pending, PendingItem};
use crate::automation::{self, Goal, GoalStatus, Job};
use crate::event::EventKind;
use crate::kernel::{BusMsg, Kernel, Runtime};
use crate::util::unix_now;
use serde_json::{json, Value};
use std::collections::HashSet;
use seagent_core::platform::ipc::{IpcListener, IpcStream};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

pub const PROTOCOL_VERSION: u32 = 1;

/// Does [`Daemon::run_with`] serve the control socket? `Off` = embedded in an app (iOS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipc {
    On,
    Off,
}

static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Windows: Ctrl+C, Ctrl+Break, console close, logoff and shutdown all ask for the same
/// graceful stop SIGTERM / SIGINT ask for on Unix. Returning TRUE tells the system the
/// event is handled; the accept loop sees `STOP` within 50 ms.
#[cfg(windows)]
unsafe extern "system" fn on_console_event(_ctrl: u32) -> windows_sys::Win32::Foundation::BOOL {
    STOP.store(true, Ordering::SeqCst);
    1
}

/// SIGTERM / SIGINT (Unix) or the console control events (Windows) set `STOP`.
fn install_stop_handlers() {
    // SAFETY: installing a handler that only stores to an atomic.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    // SAFETY: registering a handler that only stores to an atomic.
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console_event), 1);
    }
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

/// Called with `true` when this daemon starts acting as leader (at once without `[ha]`) and
/// with `false` when it loses the lease: hosts start / stop leader-only services with it
/// (channel polling, backups, report schedules) so two nodes never both answer a chat.
pub type LeaderHook = Box<dyn Fn(bool) + Send + Sync>;

/// A leader-only maintenance job the host registers (plugin auto-update, host backups…). The
/// daemon calls it about once a minute; the hook itself decides whether it is due.
pub type MaintenanceHook = Arc<dyn Fn() + Send + Sync>;

/// JSON-RPC error code a standby returns for methods only the leader may serve.
pub const STANDBY_ERROR: i32 = -32010;

pub struct Daemon {
    pub k: Kernel,
    pub pending: Arc<Pending>,
    busy_jobs: Arc<Mutex<HashSet<String>>>,
    busy_goals: Arc<Mutex<HashSet<String>>>,
    ext: Mutex<Vec<MethodExt>>,
    /// ent-095: the lease elector (only with `[ha] enabled`).
    ha: OnceLock<Arc<crate::ha::Ha>>,
    /// ent-097: the worker pool while this node leads and `[workers] count > 0`.
    pool: Mutex<Option<Arc<crate::workers::Pool>>>,
    leader_hooks: Mutex<Vec<LeaderHook>>,
    maintenance: Mutex<Vec<MaintenanceHook>>,
    /// Sessions a new leader could not resume yet (the old leader still held the log lock),
    /// with the notice to write when it can.
    resume_retry: Arc<Mutex<std::collections::HashMap<String, Option<String>>>>,
    retrying: Arc<AtomicBool>,
    started_ms: u64,
}

impl Daemon {
    pub fn new(k: Kernel, pending: Arc<Pending>) -> Self {
        Daemon {
            k,
            pending,
            busy_jobs: Default::default(),
            busy_goals: Default::default(),
            ext: Mutex::new(vec![]),
            ha: OnceLock::new(),
            pool: Mutex::new(None),
            leader_hooks: Mutex::new(vec![]),
            maintenance: Mutex::new(vec![]),
            resume_retry: Default::default(),
            retrying: Default::default(),
            started_ms: crate::event::now_ms(),
        }
    }

    pub fn ha(&self) -> Option<&Arc<crate::ha::Ha>> {
        self.ha.get()
    }
    pub fn pool(&self) -> Option<Arc<crate::workers::Pool>> {
        self.pool.lock().unwrap().clone()
    }
    pub fn started_ms(&self) -> u64 {
        self.started_ms
    }
    /// Without `[ha]` a daemon always leads.
    pub fn is_leader(&self) -> bool {
        self.ha.get().is_none_or(|h| h.is_leader())
    }
    /// Register a leader-only service switch (see [`LeaderHook`]). Call before `run`.
    pub fn on_leadership(&self, f: LeaderHook) {
        self.leader_hooks.lock().unwrap().push(f);
    }
    fn fire_leadership(&self, leader: bool) {
        for f in self.leader_hooks.lock().unwrap().iter() {
            f(leader);
        }
    }

    pub fn add_methods(&self, m: MethodExt) {
        self.ext.lock().unwrap().push(m);
    }

    /// Register a leader-only, roughly minute-paced maintenance hook (opt-in host services).
    pub fn add_maintenance(&self, f: MaintenanceHook) {
        self.maintenance.lock().unwrap().push(f);
    }

    /// Method names served by this daemon (kernel + host extensions are not enumerable;
    /// hosts list theirs via `capabilities`).
    pub const METHODS: &'static [&'static str] = &[
        "ping", "session.list", "session.create", "session.submit", "session.interrupt", "session.history", "session.view",
        "gate.pending", "gate.answer", "gate.policy.show", "session.review.set", "session.review.list", "session.review.get", "session.command", "goal.start", "goal.list", "schedule.list", "models.list", "tools.list", "tools.call", "shutdown", "session.attach", "events.subscribe",
    ];

    /// Serve until [`Daemon::stop`] / `shutdown`: the control socket plus the scheduler,
    /// cluster and leader services (`seagent daemon run`).
    pub fn run(self: Arc<Self>) -> Result<(), String> {
        self.run_with(Ipc::On)
    }

    /// [`Daemon::run`] with the control socket chosen. `Ipc::Off` is the in-process agent of the
    /// iOS app (`seagent::embed`): no socket, pid file, signal handlers or socket watchdog —
    /// the host app owns the process and reaches the daemon through the App Server.
    pub fn run_with(self: Arc<Self>, ipc: Ipc) -> Result<(), String> {
        let rt = &self.k.paths.runtime;
        std::fs::create_dir_all(rt).map_err(|e| format!("{}: {e}", rt.display()))?;
        // 0700 on Unix; an owner-only DACL on Windows.
        seagent_core::platform::fs_private::set_private(rt).map_err(|e| e.to_string())?;
        let sock = self.k.paths.socket();
        let pid_path = rt.join("seagentd.pid");
        let listener = if ipc == Ipc::On {
            // Unix: a live socket is refused, a stale one removed, the new one chmod 0600.
            // Windows: the owner-only named pipe derived from the same path.
            let listener = match IpcListener::bind(&sock) {
                Ok(l) => l,
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Err(format!("seagentd is already running ({})", seagent_core::platform::ipc::endpoint_display(&sock))),
                Err(e) => return Err(format!("bind {}: {e}", seagent_core::platform::ipc::endpoint_display(&sock))),
            };
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let _ = std::fs::write(&pid_path, std::process::id().to_string());
            install_stop_handlers();
            Some(listener)
        } else {
            None
        };
        STOP.store(false, Ordering::SeqCst);
        if listener.is_some() {
            spawn_watchdog(sock.clone(), self.k.paths.data.clone(), watch_pid_from_env());
        }

        // ent-095: with `[ha]` the leader-only work starts when the lease is won (cluster
        // thread below); without it this daemon leads from the start.
        let cfg = &self.k.cfg;
        if cfg.ha.enabled {
            let h = Arc::new(crate::ha::Ha::for_data(&cfg.ha, &self.k.paths.data));
            self.k.store.set_fence(h.store_fence());
            let _ = self.ha.set(h);
            eprintln!("seagentd: HA node {} (standby until it holds the lease in {})", cfg.ha.node(), cfg.ha.lease_dir(&self.k.paths.data).display());
        } else {
            self.become_leader(None);
        }
        let cluster = (cfg.ha.enabled || cfg.cluster.enabled || !cfg.cluster.console_url.is_empty()).then(|| {
            let me = self.clone();
            std::thread::spawn(move || me.cluster_loop())
        });
        let me = self.clone();
        let sched = std::thread::spawn(move || me.scheduler_loop());
        sd_notify("READY=1\nSTATUS=seagentd listening");

        while !STOP.load(Ordering::SeqCst) {
            let Some(listener) = &listener else {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            };
            match listener.accept() {
                Ok(conn) => {
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
        if let Some(p) = self.pool.lock().unwrap().take() {
            p.shutdown();
        }
        let until = Instant::now() + Duration::from_secs(10);
        while !self.k.running_ids().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = sched.join();
        if let Some(c) = cluster {
            let _ = c.join();
        }
        // A planned stop hands the lease over at once instead of making a standby wait it out.
        if let Some(h) = self.ha.get() {
            if h.step_down().unwrap_or(false) {
                eprintln!("seagentd: released the HA lease");
            }
        }
        if listener.is_some() {
            let _ = std::fs::remove_file(&sock);
            let _ = std::fs::remove_file(&pid_path);
        }
        Ok(())
    }

    pub fn stop() {
        STOP.store(true, Ordering::SeqCst);
    }

    /// Scheduled jobs and goals running right now (claimed by the scheduler, not finished).
    /// The iOS background task waits for this and [`Kernel::running_ids`] to drain.
    pub fn busy(&self) -> usize {
        self.busy_jobs.lock().unwrap().len() + self.busy_goals.lock().unwrap().len()
    }

    /// Start acting as leader: worker pool, leader-only services, the reaper, then resume
    /// interrupted sessions. `term` is `(epoch, previous leader)` after an HA takeover.
    fn become_leader(self: &Arc<Self>, term: Option<(u64, Option<String>)>) {
        let k = &self.k;
        if let Some((epoch, from)) = &term {
            let node = self.ha.get().map(|h| h.node.clone()).unwrap_or_default();
            eprintln!("seagentd: HA node {node} is now the leader (epoch {epoch}{})", from.as_deref().map(|f| format!(", took over from {f}")).unwrap_or_default());
            seagent_security::audit::record(&k.paths.data, seagent_security::audit::Event::new("ha.takeover", seagent_security::audit::Actor::new("node", &node), &node, "ok").detail(json!({"epoch": epoch, "from": from})));
        }
        if k.cfg.workers.count > 0 {
            let env = self.ha.get().map(|h| h.worker_env(&k.paths.data)).unwrap_or_default();
            *self.pool.lock().unwrap() = Some(crate::workers::Pool::start(k.clone(), k.cfg.workers.clone(), env));
        }
        // C7: the process-group supervisor. `seagent-tools` registers every group it starts;
        // this thread reaps the ones whose owner died (crash, SIGKILL, daemon restart). It
        // only ever signals groups it recorded itself, and only when the recorded start time
        // still matches — a recycled pid (the user's browser) is never touched. Leader only:
        // a standby runs nothing, and one sweeper per shared registry is enough.
        static SWEEPER: std::sync::Once = std::sync::Once::new();
        let reap = k.cfg.limits.reap_interval_secs;
        if reap > 0 {
            let data = k.paths.data.clone();
            SWEEPER.call_once(move || {
                crate::reaper::spawn_sweeper(data, Duration::from_secs(reap));
            });
        }
        // A one-shot claimed just before a drain/crash is restored (young claims only) instead of
        // being retired as missed.
        let hold = k.cfg.automation.get("restart_hold_seconds").and_then(|v| v.as_integer()).unwrap_or(3600);
        let restored = crate::automation::recover_claims(&k.paths.data, unix_now(), hold);
        if !restored.is_empty() {
            eprintln!("seagentd: restored {} cron claim(s) interrupted by a restart", restored.len());
        }
        self.fire_leadership(true);
        match term {
            None => self.resume(None),
            Some((epoch, _)) => {
                // Off the lease thread: a session the old leader still holds blocks for ~1.5 s.
                let me = self.clone();
                std::thread::spawn(move || me.resume(Some(epoch)));
            }
        }
    }

    /// Lost the lease (or stepped down): stop everything only a leader may do.
    pub fn on_lost(&self, reason: &str) {
        let node = self.ha.get().map(|h| h.node.clone()).unwrap_or_default();
        eprintln!("seagentd: HA node {node} is no longer the leader: {reason}");
        seagent_security::audit::record(&self.k.paths.data, seagent_security::audit::Event::new("ha.lost", seagent_security::audit::Actor::new("node", &node), &node, "ok").detail(json!({"reason": reason})));
        for id in self.k.running_ids() {
            self.k.interrupt(&id);
        }
        if let Some(p) = self.pool.lock().unwrap().take() {
            p.shutdown();
        }
        self.resume_retry.lock().unwrap().clear();
        self.fire_leadership(false);
    }

    /// Run a session: on a worker when the pool takes everything, else in this process. With
    /// HA, a session still locked by a deposed leader is retried (with its notice) every second.
    fn launch(&self, id: &str, notice: Option<String>) {
        if let Some(text) = notice.clone() {
            if let Err(e) = self.k.record(id, EventKind::Notice { level: "info".into(), text }) {
                if matches!(e, crate::kernel::KernelError::Store(crate::store::StoreError::Locked(_))) && self.ha.get().is_some() {
                    self.resume_retry.lock().unwrap().insert(id.to_string(), notice);
                }
                return;
            }
        }
        if let Some(pool) = self.pool().filter(|_| self.k.cfg.workers.dispatch_all()) {
            pool.dispatch(id);
            return;
        }
        let h = self.k.start(id, Default::default());
        if self.ha.get().is_some() {
            let retry = self.resume_retry.clone();
            let id = id.to_string();
            std::thread::spawn(move || {
                if let Ok(Err(crate::kernel::KernelError::Store(crate::store::StoreError::Locked(_)))) = h.join() {
                    retry.lock().unwrap().insert(id, None);
                }
            });
        }
    }

    fn retry_resumes(self: &Arc<Self>) {
        if self.resume_retry.lock().unwrap().is_empty() || self.retrying.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let todo: Vec<(String, Option<String>)> = me.resume_retry.lock().unwrap().drain().collect();
            for (id, notice) in todo {
                if me.is_leader() && !me.k.is_running(&id) {
                    me.launch(&id, notice);
                }
            }
            me.retrying.store(false, Ordering::SeqCst);
        });
    }

    /// Lease ticks, heartbeats into the node registry and policy pulls (ent-095 / ent-062).
    fn cluster_loop(self: &Arc<Self>) {
        let cfg = self.k.cfg.clone();
        let tick = self.ha.get().map(|h| (h.cfg.renew() / 3).clamp(Duration::from_millis(50), Duration::from_millis(500))).unwrap_or(Duration::from_millis(500));
        let hb = Duration::from_secs(cfg.cluster.heartbeat_secs.max(1));
        let pull = Duration::from_secs(cfg.cluster.pull_secs.max(10));
        let mut last_hb = Instant::now() - hb;
        let mut last_pull = Instant::now() - pull;
        let mut last_retry = Instant::now();
        while !STOP.load(Ordering::SeqCst) {
            if let Some(h) = self.ha.get() {
                match h.tick() {
                    crate::ha::Transition::BecameLeader { epoch, from } => {
                        self.become_leader(Some((epoch, from)));
                        last_hb = Instant::now() - hb;
                    }
                    crate::ha::Transition::Lost { reason } => {
                        self.on_lost(&reason);
                        last_hb = Instant::now() - hb;
                    }
                    crate::ha::Transition::None => {}
                }
                if h.is_leader() && last_retry.elapsed() >= Duration::from_secs(1) {
                    last_retry = Instant::now();
                    self.retry_resumes();
                }
            }
            if last_hb.elapsed() >= hb {
                last_hb = Instant::now();
                if let Err(e) = crate::cluster::write_heartbeat(&self.k.paths.data, &crate::cluster::snapshot(self)) {
                    eprintln!("seagentd: cluster heartbeat: {e}");
                }
            }
            if self.is_leader() && cfg.managed.cluster_key.is_some() && last_pull.elapsed() >= pull {
                last_pull = Instant::now();
                let tok = (self.k.vault_substitute())(&cfg.cluster.console_token);
                match crate::cluster::pull(&self.k.paths.data, &cfg.cluster, cfg.managed.cluster_key.as_deref(), if tok.contains("{{secret:") { "" } else { &tok }) {
                    Ok(Some(v)) => {
                        eprintln!("seagentd: installed cluster policy v{v} (takes effect on restart)");
                        seagent_security::audit::record(&self.k.paths.data, seagent_security::audit::Event::new("cluster.policy.apply", seagent_security::audit::Actor::new("node", &crate::cluster::node_name(self)), &format!("v{v}"), "ok").detail(json!({"version": v, "via": "pull"})));
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("seagentd: cluster policy pull: {e}"),
                }
            }
            std::thread::sleep(tick);
        }
    }

    pub fn stopping() -> bool {
        STOP.load(Ordering::SeqCst)
    }

    /// Restart work that was in flight when the daemon died. `epoch`: after an HA takeover
    /// (each resumed session gets a notice saying which node picked it up).
    fn resume(&self, epoch: Option<u64>) {
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
                let notice = epoch.map(|e| format!("ha: node {} (epoch {e}) resumed this session after failover", self.ha.get().map(|h| h.node.as_str()).unwrap_or("?")));
                self.launch(&s.id, notice);
            }
        }
        if let Ok(goals) = automation::read_list::<Goal>(&automation::goals_path(&self.k.paths.data)) {
            for g in goals.into_iter().filter(|g| g.status == GoalStatus::Active) {
                self.start_goal(&g.id);
            }
        }
    }

    fn start_goal(&self, id: &str) -> bool {
        if seagent_security::estop::is_engaged(&self.k.paths.data) {
            eprintln!("seagentd: goal {id} not started: paused (seagent resume)");
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
        self.retry_paused_at(crate::event::now_ms())
    }

    /// [`Self::retry_paused`] against an explicit clock: the long-task harness (gen1-305)
    /// fast-forwards hours of backoff without waiting for them.
    pub fn retry_paused_at(&self, now_ms: u64) -> usize {
        if seagent_security::estop::is_engaged(&self.k.paths.data) {
            return 0;
        }
        let mut n = 0;
        for p in crate::limits::due_pauses(&self.k.paths.data, now_ms) {
            if p.session.is_empty() || self.k.is_running(&p.session) {
                continue;
            }
            crate::limits::bump_pause(&self.k.paths.data, &p);
            eprintln!("seagentd: resuming paused session {} ({})", p.session, p.reason);
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
                eprintln!("seagentd: retention: removed {n} {class} item(s)");
            }
        }
        out.iter().find(|(c, _)| *c == "sessions").map(|(_, n)| *n).unwrap_or(0)
    }

    /// Forward new audit records to the configured SIEM sinks (ent-074…076).
    fn pump_audit(&self) {
        let cfg = &self.k.cfg.audit.export;
        let subst = self.k.vault_substitute();
        // Sign (and timestamp) the seals of segments rotated since the last pump.
        if let Some(seed) = self.k.cfg.audit.seal_seed(&|s: &str| subst(s)) {
            let tsa = self.k.cfg.audit.tsa_url.trim();
            if let Err(e) = seagent_security::audit_seal::sign_pending(&self.k.paths.data, &seed, (!tsa.is_empty()).then_some(tsa)) {
                seagent_security::audit::note_error(&format!("audit seal signing: {e}"));
            }
        }
        if cfg.sinks().is_empty() {
            return;
        }
        for (sink, r) in seagent_security::audit_export::pump(&self.k.paths.data, cfg, &|s: &str| subst(s)) {
            if let Err(e) = r {
                // Surfaced through `/metrics` (`seagent_audit_errors`) and `/ready`; the cursor stays.
                seagent_security::audit::note_error(&format!("audit export to {sink}: {e}"));
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
        let cleanup_every = Duration::from_secs(crate::scratch::Settings::from_config(&self.k.cfg).cleanup_interval_secs);
        let mut last_cleanup = Instant::now() - cleanup_every;
        // Hermes `gateway/session_retirement.py`: idle live sessions leave memory; the transcript
        // stays on disk and a later request rebuilds the per-session state on demand.
        let idle_secs = self.k.cfg.automation.get("idle_session_secs").and_then(|v| v.as_integer()).unwrap_or(1800).max(0) as u64;
        let idle_every = Duration::from_secs(60);
        let mut last_retire = Instant::now() - idle_every;
        let mut last_maint = Instant::now() - idle_every;
        seagent_security::audit::set_rotate_bytes(self.k.cfg.audit.rotate_mb.max(1) * 1024 * 1024);
        while !STOP.load(Ordering::SeqCst) {
            // ent-095: a standby claims no jobs, resumes nothing and dispatches nothing.
            if !self.is_leader() {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
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
            if crate::scratch::due(&mut last_maint, idle_every) {
                for f in self.maintenance.lock().unwrap().iter() {
                    f();
                }
            }
            if idle_secs > 0 && crate::scratch::due(&mut last_retire, idle_every) {
                let gone = self.k.retire_idle_sessions(Duration::from_secs(idle_secs));
                if !gone.is_empty() {
                    eprintln!("seagentd: retired {} idle session(s) from memory", gone.len());
                }
            }
            // Disposable agent scratch (24 h) and idle worktrees (7 days), both configurable.
            if crate::scratch::due(&mut last_cleanup, cleanup_every) {
                let r = crate::scratch::maintenance(&self.k);
                if !r.removed.is_empty() || !r.errors.is_empty() {
                    eprintln!("seagentd: scratch cleanup removed {} item(s), {} byte(s), {} error(s)", r.removed.len(), r.bytes, r.errors.len());
                }
            }
            // Global emergency stop: claim nothing (jobs stay due and run after `seagent resume`).
            if last.elapsed() >= tick && seagent_security::estop::is_engaged(&self.k.paths.data) {
                last = Instant::now();
            }
            // An external cron provider (chronos) owns firing: it calls back per job.
            if last.elapsed() >= tick && crate::cronjob::chronos::owns_ticks(&self.k.paths.data) {
                last = Instant::now();
            }
            if last.elapsed() >= tick {
                last = Instant::now();
                // A drain must not claim new work: an in-flight one-shot stays due for the next
                // leader instead of being marked missed.
                if STOP.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
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
                    Err(e) => eprintln!("seagentd: scheduler: {e}"),
                }
            }
            crate::kanban::dispatch::daemon_tick(&self.k);
            crate::heartbeat::daemon_tick(&self.k);
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn serve(&self, conn: IpcStream) {
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
        let read_only = read_only_caller(p);
        let s = |k: &str| p.get(k).and_then(|v| v.as_str()).map(String::from);
        let need = |k: &str| s(k).ok_or((-32602, format!("missing param `{k}`")));
        let kerr = |e: crate::kernel::KernelError| (-32000, e.to_string());
        let k = &self.k;
        if let Some(h) = self.ha.get().filter(|h| !h.is_leader()) {
            if !standby_may_serve(method) {
                let l = h.leader();
                let at = l.as_ref().map(|l| format!("node {} (epoch {}{})", l.node, l.epoch, if l.advertise.is_empty() { String::new() } else { format!(", {}", l.advertise) })).unwrap_or_else(|| "not elected yet".into());
                return Err((STANDBY_ERROR, format!("standby: node {} is not the HA leader; `{method}` must go to the leader: {at}", h.node)));
            }
        }
        let pool = self.pool();
        let on_worker = |id: &str| pool.as_ref().is_some_and(|p| p.owns(id));
        match method {
            "ping" => Ok(json!({"protocol": PROTOCOL_VERSION, "version": env!("CARGO_PKG_VERSION"), "running": k.running_ids(), "pid": std::process::id(), "role": match self.ha.get() { Some(h) if h.is_leader() => "leader", Some(_) => "standby", None => "single" }, "node": self.ha.get().map(|h| h.node.clone())})),
            "session.list" => {
                let lim = p.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
                let mut rows: Vec<Value> = k.store.list().into_iter().take(lim).map(|s| json!({"id":s.id,"title":s.title,"model":s.model,"workspace":s.workspace,"updated_ms":s.updated_ms,"messages":s.messages,"parent":s.parent,"running":k.is_running(&s.id) || on_worker(&s.id)})).collect();
                if read_only {
                    // A read-scoped token gets status, not the host's disk layout.
                    for r in &mut rows {
                        if let Some(o) = r.as_object_mut() {
                            o.remove("workspace");
                        }
                    }
                }
                Ok(json!(rows))
            }
            "session.create" => {
                let ws = need("workspace")?;
                let id = k.create_session(Path::new(&ws), s("model").as_deref(), None, s("title").as_deref()).map_err(kerr)?;
                Ok(json!({"id": id}))
            }
            "session.submit" => {
                let id = need("id")?;
                let text = need("text")?;
                let source = s("source").unwrap_or_else(|| "cli".into());
                // ent-097: a worker holds this session's log lock; deliver after its run.
                if let Some(pool) = pool.as_ref().filter(|p| p.running().contains(&id)) {
                    if !k.store.exists(&id) {
                        return Err((-32602, format!("no such session `{id}`")));
                    }
                    pool.hold(&id, &text, &source);
                    return Ok(json!({"queued": true, "started": false, "worker": true}));
                }
                k.submit(&id, &text, &source).map_err(kerr)?;
                let to_worker = pool.as_ref().filter(|_| k.cfg.workers.dispatch_all() || p["worker"].as_bool() == Some(true));
                if let Some(pool) = to_worker.filter(|_| !k.is_running(&id)) {
                    let started = pool.dispatch(&id);
                    return Ok(json!({"queued": true, "started": started, "worker": true}));
                }
                let started = !k.is_running(&id);
                if started {
                    let _ = k.start(&id, Default::default());
                }
                Ok(json!({"queued": true, "started": started}))
            }
            "session.interrupt" => {
                let id = need("id")?;
                // `_by` is the authenticated principal when the app server forwards one; on the
                // owner-only unix socket the caller is the local user. `_source` distinguishes a
                // chat stop from a client/runbook stop in `run_stopped`.
                let who = s("_by").map(|b| seagent_security::audit::Actor::parse_label(&b).with_role(&s("_by_role").unwrap_or_default())).unwrap_or_else(seagent_security::audit::Actor::local);
                let source = s("_source").unwrap_or_else(|| "client".into());
                let interrupted = k.interrupt_as(&id, &who, &source) || pool.as_ref().is_some_and(|p| p.cancel(&id));
                if interrupted && !k.interrupt(&id) {
                    // A worker owns this run: the daemon-side kernel cannot attribute it, so record
                    // the same audit + hook from the control plane.
                    let cwd = crate::projection::project(&k.store.read(&id).unwrap_or_default()).workspace;
                    seagent_security::audit::record(&k.paths.data, seagent_security::audit::Event::new("run.stopped", who.clone(), &id, "ok").session(&id).detail(json!({"source": source, "run_id": id, "actor": who.label(), "worker": true})));
                    crate::hooks::fire_run_stopped(k, &id, &cwd, &source, &who.label(), &id);
                }
                Ok(json!({"interrupted": interrupted}))
            }
            "gate.pending" => Ok(json!(self.pending.list().into_iter().map(pending_json).collect::<Vec<_>>())),
            "gate.answer" => {
                // `_by` is set by the app server from the authenticated principal; on the
                // owner-only unix socket the caller is the local user.
                // `_by_role` (the principal's roles) is set the same way; dual control checks it.
                let who = s("_by").map(|b| seagent_security::audit::Actor::parse_label(&b).with_role(&s("_by_role").unwrap_or_default())).unwrap_or_else(seagent_security::audit::Actor::local);
                let via = s("_via").unwrap_or_else(|| "arp".into());
                match crate::approver::answer_as(&*self.pending, &k.paths.data, &need("id")?, &need("answer")?, &who, &via) {
                    Ok(crate::approver::Answered::Final) => Ok(json!({"ok": true, "final": true})),
                    Ok(crate::approver::Answered::Counted { have, need }) => Ok(json!({"ok": true, "final": false, "approvals": have, "required": need})),
                    Err(e) if e.starts_with("no such pending") => Err((-32001, e)),
                    Err(e) => Err((-32003, e)),
                }
            }
            "gate.policy.show" => Ok(json!({"dual_control": k.cfg.approvals.dual_control})),
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
            "goal.list" => automation::read_list::<Goal>(&automation::goals_path(&k.paths.data)).map(|g| {
                let mut v = json!(g);
                if read_only {
                    for goal in v.as_array_mut().into_iter().flatten() {
                        if let Some(o) = goal.as_object_mut() {
                            o.remove("workspace");
                        }
                    }
                }
                v
            }).map_err(|e| (-32000, e)),
            "schedule.list" => automation::read_list::<Job>(&automation::jobs_path(&k.paths.data)).map(|j| {
                let mut v = json!(j);
                if read_only {
                    for job in v.as_array_mut().into_iter().flatten() {
                        if let Some(o) = job.as_object_mut() {
                            o.remove("workspace");
                        }
                    }
                }
                v
            }).map_err(|e| (-32000, e)),
            "session.history" => {
                let from = p.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let evs = k.store.read(&need("id")?).map_err(|e| (-32000, e.to_string()))?;
                Ok(json!(evs.into_iter().filter(|e| e.seq >= from).collect::<Vec<_>>()))
            }
            "session.view" => {
                // The conversation as the model sees it, for UIs that render a transcript.
                let id = need("id")?;
                let evs = k.store.read(&id).map_err(|e| (-32000, e.to_string()))?;
                let v = crate::projection::project(&evs);
                let mut out = json!({"messages": v.messages, "running": k.is_running(&id)});
                if !read_only {
                    out["workspace"] = json!(v.workspace);
                }
                Ok(out)
            }
            "models.list" => {
                let c = &k.cfg.model;
                Ok(json!({"default": c.default, "fallback": c.fallback, "aux": k.cfg.aux_model()}))
            }
            "tools.list" => Ok(json!(k.specs().into_iter().map(|s| json!({"name": s.name, "description": s.description})).collect::<Vec<_>>())),
            "tools.call" => {
                let tool = s("tool").or_else(|| s("name")).ok_or((-32602, "missing param `tool`".to_string()))?;
                let input = p.get("input").or_else(|| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
                if !input.is_object() {
                    return Err((-32602, "`input` must be a JSON object".into()));
                }
                // Scripts may name an existing session to keep audit/history in one place; without
                // one a fresh session is created so the gate has a real log to write to.
                let session = match s("session").or_else(|| s("id")).filter(|x| !x.trim().is_empty()) {
                    Some(id) => {
                        if !k.store.exists(&id) {
                            return Err((-32602, format!("no such session `{id}`")));
                        }
                        id
                    }
                    None => {
                        let ws = s("workspace").map(std::path::PathBuf::from).unwrap_or_else(|| k.paths.default_workspace());
                        k.create_session(&ws, None, None, Some(&format!("tools.call {tool}"))).map_err(kerr)?
                    }
                };
                let who = s("_by").map(|b| seagent_security::audit::Actor::parse_label(&b).with_role(&s("_by_role").unwrap_or_default())).unwrap_or_else(seagent_security::audit::Actor::local);
                let source = s("_source").unwrap_or_else(|| "arp".into());
                match k.call_tool_as(&session, &tool, input, &who, &source) {
                    Ok((content, is_error)) => Ok(json!({"ok": !is_error, "session": session, "tool": tool, "is_error": is_error, "content": content})),
                    Err(e) => Err(kerr(e)),
                }
            }
            "shutdown" => {
                Daemon::stop();
                Ok(json!({"stopping": true}))
            }
            "" => Err((-32600, "missing method".into())),
            m if m.starts_with("session.review.") => crate::session_review::rpc(k, m, p).unwrap_or_else(|| Err((-32601, format!("unknown method `{m}`")))),
            m if m.starts_with("kanban.") || m.starts_with("board.") => crate::kanban::methods::call(k, m, p).unwrap_or_else(|| Err((-32601, format!("unknown method `{m}`")))),
            m if m.starts_with("ha.") || m.starts_with("workers.") || m.starts_with("cluster.") => crate::cluster::call(self, m, p).unwrap_or_else(|| Err((-32601, format!("unknown method `{m}`")))),
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
    fn stream(&self, w: &mut IpcStream, id: Value, method: &str, p: &Value) {
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

/// Read-only principals (a `read` token, an auditor role) never get the host's disk layout.
fn read_only_caller(p: &Value) -> bool {
    let scope = p.get("_scope").and_then(|v| v.as_str()).unwrap_or("");
    scope == "scope:read" || scope == "auditor"
}

/// What a standby still answers: reads of the shared store, status, and the HA / console
/// surface. Everything that starts work or changes state belongs to the leader.
fn standby_may_serve(m: &str) -> bool {
    const EXACT: &[&str] = &["ping", "initialize", "whoami", "session.list", "session.history", "session.view", "gate.pending", "goal.list", "schedule.list", "models.list", "tools.list", "shutdown", "health.ready"];
    const SUFFIX: &[&str] = &[".list", ".get", ".status", ".show", ".info", ".query", ".describe", ".tail", ".state"];
    EXACT.contains(&m) || m.starts_with("ha.") || m.starts_with("cluster.") || SUFFIX.iter().any(|x| m.ends_with(x))
}

fn pending_session(i: &PendingItem) -> &str {
    match i {
        PendingItem::Approval(a) => &a.session,
        PendingItem::Question { session, .. } => session,
    }
}

fn pending_json(i: PendingItem) -> Value {
    match i {
        PendingItem::Approval(a) => {
            let mut v = json!({"kind":"approval","id":a.id,"session":a.session,"tool":a.tool,"gate":format!("{:?}", a.gate).to_lowercase(),"reason":a.reason,"summary":a.summary,"tier":a.tier});
            // Dual control: who asked, how many approvals are needed, who already approved.
            if let Some(q) = crate::approver::quorum(&a.id) {
                v["dual_control"] = json!({"required": q.required, "approvals": q.approvals(), "votes": q.votes, "requester": q.requester, "approver_roles": q.approver_roles, "approvers": q.approvers, "expires_ms": q.expires_ms, "change_ticket": q.change_ticket});
            }
            v
        }
        PendingItem::Question { id, session, question, choices, multi } => json!({"kind":"question","id":id,"session":session,"question":question,"choices":choices,"multi_select":multi}),
    }
}

fn send(w: &mut IpcStream, v: &Value) -> std::io::Result<()> {
    let mut b = serde_json::to_vec(v)?;
    b.push(b'\n');
    w.write_all(&b)?;
    w.flush()
}

/// systemd `Type=notify` readiness (no crate: one datagram to $NOTIFY_SOCKET).
/// A no-op where there is no systemd (other Unixes: no `NOTIFY_SOCKET` is ever set; Windows
/// services report readiness through the service control manager, not this call).
pub fn sd_notify(state: &str) {
    #[cfg(unix)]
    {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
        let sock = match std::os::unix::net::UnixDatagram::unbound() {
            Ok(s) => s,
            Err(_) => return,
        };
        let p = path.to_string_lossy().into_owned();
        if let Some(abs) = p.strip_prefix('@') {
            // Abstract namespace socket (Linux / Android kernels only).
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(abs.as_bytes()) {
                    let _ = sock.send_to_addr(state.as_bytes(), &addr);
                }
            }
            #[cfg(target_os = "android")]
            {
                use std::os::android::net::SocketAddrExt;
                if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(abs.as_bytes()) {
                    let _ = sock.send_to_addr(state.as_bytes(), &addr);
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let _ = abs;
        } else {
            let _ = sock.send_to(state.as_bytes(), &p);
        }
    }
    #[cfg(not(unix))]
    let _ = state;
}

// ───────────────────────── client side ─────────────────────────

/// Connect to seagentd's control endpoint (Unix socket; Windows named pipe for the same path).
pub fn connect(sock: &Path) -> Result<IpcStream, String> {
    IpcStream::connect(sock).map_err(|e| format!("seagentd is not running ({}: {e}). Start it with `seagent daemon start`.", seagent_core::platform::ipc::endpoint_display(sock)))
}

pub fn call(sock: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut s = connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    send(&mut s, &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("bad response from seagentd: {e}"))?;
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
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    struct Echo;
    impl seagent_core::Tool for Echo {
        fn spec(&self) -> seagent_core::ToolSpec {
            seagent_core::ToolSpec { name: "echo_test".into(), description: "echo".into(), input_schema: json!({"type":"object"}), parallel_safe: false, idempotent: true, pinned: false }
        }
        fn effects(&self, _: &seagent_core::ToolCtx, _: &Value) -> Vec<seagent_core::Effect> {
            vec![]
        }
        fn call(&self, _: &seagent_core::ToolCtx, input: Value) -> seagent_core::ToolOutput {
            seagent_core::ToolOutput::ok(input.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string())
        }
    }

    #[test]
    fn session_command_runs_security_slash_commands() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-daemon-cmd");
        let root = tmp.path().to_path_buf();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let d = Daemon::new(k.clone(), pending);
        let id = k.create_session(&root, None, None, Some("t")).unwrap();
        let r = d.call("session.command", &json!({"id": id, "line": "/yolo on"})).unwrap();
        assert_eq!(r["handled"], true);
        assert!(seagent_security::approvals::yolo_active(&k.paths.data, &id));
        let r = d.call("session.command", &json!({"id": id, "line": "/approvals"})).unwrap();
        assert!(r["text"].as_str().unwrap().contains("yolo=true"), "{r}");
        assert_eq!(d.call("session.command", &json!({"id": id, "line": "/compact"})).unwrap()["handled"], false);
        assert!(d.call("session.command", &json!({"id": "nope-123", "line": "/yolo"})).is_err());
        assert!(d.call("session.command", &json!({"id": id})).is_err());
        assert!(Daemon::METHODS.contains(&"session.command"));
    }

    #[test]
    fn tools_call_goes_through_the_same_log_and_audit() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-daemon-toolcall");
        let root = tmp.path().to_path_buf();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![Arc::new(Echo)], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let d = Daemon::new(k.clone(), pending);
        assert!(Daemon::METHODS.contains(&"tools.call"));
        // A fresh session is created when the caller has none.
        let r = d.call("tools.call", &json!({"tool": "echo_test", "input": {"text": "hi"}, "workspace": root})).unwrap();
        assert_eq!((r["ok"].as_bool(), r["is_error"].as_bool(), r["content"].as_str()), (Some(true), Some(false), Some("hi")));
        let sid = r["session"].as_str().unwrap().to_string();
        let ev = k.store.read(&sid).unwrap();
        assert!(ev.iter().any(|e| matches!(&e.kind, crate::event::EventKind::ToolCalled { name, .. } if name == "echo_test")), "the call is in the session log");
        assert!(ev.iter().any(|e| matches!(&e.kind, crate::event::EventKind::ToolSettled { .. })), "and settled");
        let audit = seagent_security::audit::query(&k.paths.data, &seagent_security::audit::Query { kind: Some("tool.call".into()), session: Some(sid.clone()), ..Default::default() });
        assert_eq!(audit.len(), 1, "{audit:?}");
        assert_eq!(audit[0]["detail"]["tool"], "echo_test");
        // An unknown tool is an error result, not a silent success.
        let r = d.call("tools.call", &json!({"tool": "nope", "session": sid, "input": {}})).unwrap();
        assert_eq!((r["ok"].as_bool(), r["is_error"].as_bool()), (Some(false), Some(true)));
        assert!(r["content"].as_str().unwrap().contains("unknown tool"));
        assert!(d.call("tools.call", &json!({"session": "missing"})).is_err());
    }

    #[test]
    fn read_only_callers_do_not_get_host_paths() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-daemon-paths");
        let root = tmp.path().to_path_buf();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let d = Daemon::new(k.clone(), pending);
        let id = k.create_session(&root, None, None, Some("paths")).unwrap();
        let full = d.call("session.list", &json!({})).unwrap();
        assert!(full.as_array().unwrap().iter().any(|s| s["workspace"].as_str() == Some(root.to_string_lossy().as_ref())));
        let ro = d.call("session.list", &json!({"_scope": "scope:read"})).unwrap();
        assert!(ro.as_array().unwrap().iter().all(|s| s.get("workspace").is_none()), "{ro}");
        let v = d.call("session.view", &json!({"id": id, "_scope": "scope:read"})).unwrap();
        assert!(v.get("workspace").is_none(), "{v}");
        let audit = d.call("session.view", &json!({"id": id, "_scope": "auditor"})).unwrap();
        assert!(audit.get("workspace").is_none(), "{audit}");
        let admin = d.call("session.view", &json!({"id": id})).unwrap();
        assert_eq!(admin["workspace"], root.to_string_lossy().as_ref());
    }

    #[test]
    fn idle_sessions_are_retired_from_memory_and_rebuilt_on_demand() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-daemon-retire");
        let root = tmp.path().to_path_buf();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let id = k.create_session(&root, None, None, Some("idle")).unwrap();
        k.set_queue(&id, crate::queue::Settings { mode: crate::queue::Mode::Collect, cap: 3, ..Default::default() });
        assert_eq!(k.queue_for(&id).mode, crate::queue::Mode::Collect);
        assert!(k.retire_idle_sessions(Duration::ZERO).is_empty(), "0 disables retirement");
        std::thread::sleep(Duration::from_millis(3));
        assert_eq!(k.retire_idle_sessions(Duration::from_millis(1)), vec![id.clone()]);
        assert_eq!(k.queue_for(&id).mode, crate::queue::Mode::Steer, "restored on demand: the config default returns");
    }

    #[test]
    fn explicit_stop_records_the_actor_and_fires_run_stopped() {
        struct Slow;
        impl seagent_core::Provider for Slow {
            fn id(&self) -> &str {
                "slow"
            }
            fn caps(&self, _: &str) -> seagent_core::ModelCaps {
                seagent_core::ModelCaps { context_window: 100_000, max_output: 1000, tools: true, vision: false, explicit_cache: false }
            }
            fn complete(&self, _: &seagent_core::ModelRequest, _: &mut dyn FnMut(seagent_core::StreamEvent), _: &seagent_core::Cancel) -> Result<seagent_core::ModelResponse, seagent_core::ProviderError> {
                std::thread::sleep(Duration::from_millis(300));
                Ok(seagent_core::ModelResponse { message: seagent_core::Message { role: seagent_core::Role::Assistant, content: vec![seagent_core::Block::text("done")] }, stop: seagent_core::StopReason::EndTurn, usage: Default::default(), model: "m".into() })
            }
        }
        struct Res(Arc<Slow>);
        impl crate::kernel::Resolver for Res {
            fn provider(&self, _: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
                Ok(self.0.clone())
            }
        }
        struct Capture(Arc<Mutex<Vec<Value>>>);
        impl crate::hooks::Hook for Capture {
            fn name(&self) -> String {
                "capture-run-stopped".into()
            }
            fn wants(&self, e: crate::hooks::HookEvent, _: Option<&str>) -> bool {
                e == crate::hooks::HookEvent::RunStopped
            }
            fn run(&self, _: crate::hooks::HookEvent, payload: &Value) -> Result<crate::hooks::HookDecision, String> {
                self.0.lock().unwrap().push(payload.clone());
                Ok(crate::hooks::HookDecision::Allow)
            }
        }
        let tmp = seagent_core::tmp::TempDir::new("seagent-daemon-stop");
        let root = tmp.path().to_path_buf();
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "slow/m".into();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&root).unwrap();
        let (pending, cell) = pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(cfg, paths, Arc::new(Res(Arc::new(Slow))), vec![], Arc::new(crate::vault::Vault::empty()), pending.clone());
        let _ = cell.set(Arc::downgrade(&k));
        let seen = Arc::new(Mutex::new(Vec::new()));
        k.add_hooks(vec![Arc::new(Capture(seen.clone()))]);
        let d = Daemon::new(k.clone(), pending);
        let id = k.create_session(&root, None, None, Some("stop")).unwrap();
        k.submit(&id, "hello", "cli").unwrap();
        let h = k.start(&id, Default::default());
        std::thread::sleep(Duration::from_millis(50));
        let r = d.call("session.interrupt", &json!({"id": id, "_by": "token:ops-bot", "_by_role": "scope:write", "_source": "client"})).unwrap();
        assert_eq!(r["interrupted"], true);
        let _ = h.join();
        let audit = seagent_security::audit::query(&k.paths.data, &seagent_security::audit::Query { kind: Some("run.stopped".into()), session: Some(id.clone()), ..Default::default() });
        assert_eq!(audit.len(), 1, "{audit:?}");
        assert_eq!((audit[0]["actor"]["kind"].as_str(), audit[0]["actor"]["name"].as_str()), (Some("token"), Some("ops-bot")));
        assert_eq!(audit[0]["detail"]["source"], "client");
        let p = seen.lock().unwrap();
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!((p[0]["source"].as_str(), p[0]["actor"].as_str()), (Some("client"), Some("token:ops-bot")));
        assert_eq!(p[0]["sessions"][0]["sessionKey"], id);
    }
}

/// `SEAGENT_DAEMON_WATCH_PID`: the daemon shuts down when this process is gone (new-002). Test
/// harnesses (tests/e2e/run.py) and supervisors that start `seagent daemon start` set it to their own
/// pid, so a harness that is interrupted or crashes cannot leave an `seagentd` running for days.
pub fn watch_pid_from_env() -> Option<i32> {
    std::env::var("SEAGENT_DAEMON_WATCH_PID").ok().and_then(|v| v.trim().parse::<i32>().ok()).filter(|p| *p > 1)
}

/// Why the watchdog should stop the daemon now, if it should.
pub fn watchdog_reason(sock: &Path, data: Option<&Path>, watch: Option<i32>) -> Option<String> {
    if let Some(pid) = watch {
        // ESRCH only: EPERM means it exists (another user), which never happens for our parent.
        #[cfg(unix)]
        let gone = unsafe { libc::kill(pid, 0) } != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        // Windows: a process we may not open counts as alive (the EPERM case).
        #[cfg(not(unix))]
        let gone = !seagent_core::platform::proc::alive(pid);
        if gone {
            return Some(format!("watched process {pid} exited (SEAGENT_DAEMON_WATCH_PID)"));
        }
    }
    // The control socket was removed (its SEAGENT_HOME/runtime dir deleted): nobody can reach or
    // stop this daemon any more, so it stops itself instead of lingering unreachable.
    #[cfg(unix)]
    if !sock.exists() {
        return Some(format!("control socket {} was removed", sock.display()));
    }
    // Windows: the endpoint is a named pipe with no file at `sock`; the runtime directory
    // that names it is what a deleted SEAGENT_HOME takes away.
    #[cfg(not(unix))]
    if let Some(rt) = sock.parent().filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
        return Some(format!("runtime directory {} of control endpoint {} was removed", rt.display(), seagent_core::platform::ipc::endpoint_display(sock)));
    }
    // Same for the data directory (SEAGENT_HOME deleted while the socket lives elsewhere, e.g. a
    // long SEAGENT_HOME whose socket moved to $XDG_RUNTIME_DIR).
    if let Some(d) = data.filter(|d| !d.exists()) {
        return Some(format!("data directory {} was removed", d.display()));
    }
    None
}

fn spawn_watchdog(sock: std::path::PathBuf, data: std::path::PathBuf, watch: Option<i32>) {
    // Only watch the data directory if it exists now (it always does once seagentd.log is open).
    let data = data.exists().then_some(data);
    let _ = std::thread::Builder::new().name("seagentd-watchdog".into()).spawn(move || {
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            if let Some(why) = watchdog_reason(&sock, data.as_deref(), watch) {
                eprintln!("seagentd: shutting down: {why}");
                STOP.store(true, Ordering::SeqCst);
                break;
            }
        }
    });
}

#[cfg(test)]
#[cfg(unix)]
mod watchdog_tests {
    use super::*;

    #[test]
    fn watchdog_stops_for_a_dead_watched_pid_or_a_removed_home() {
        let d = seagent_core::tmp::TempDir::new("seagent-daemon-watchdog");
        let sock = d.path().join("seagentd.sock");
        let data = d.path().join("data");
        std::fs::write(&sock, "").unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let me = std::process::id() as i32;
        assert_eq!(watchdog_reason(&sock, Some(&data), Some(me)), None, "we are alive");
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let dead = c.id() as i32;
        c.wait().unwrap();
        assert!(watchdog_reason(&sock, Some(&data), Some(dead)).unwrap().contains("SEAGENT_DAEMON_WATCH_PID"));
        std::fs::remove_dir_all(&data).unwrap();
        assert!(watchdog_reason(&sock, Some(&data), None).unwrap().contains("data directory"));
        std::fs::remove_file(&sock).unwrap();
        assert!(watchdog_reason(&sock, None, None).unwrap().contains("control socket"));
    }
}
