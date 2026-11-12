//! Horizontal worker pool (ent-097): the leader daemon hands sessions to N `seagent worker`
//! processes and re-dispatches a session whose worker died. Design: docs/ARCHITECTURE.md §7.3.
//!
//! Built on the existing worker runtime (`crates/seagent/src/ops/worker.rs`, OpenClaw
//! `src/worker/worker-process.ts`): one private JSONL protocol on stdin/stdout. The pool adds
//! one request, `{"type":"run","turnId","sessionId"}` — continue an *existing* session — so a
//! worker reads and writes the same (shared) `events.jsonl` the daemon would have. The session
//! log stays the source of truth; a worker that dies mid-turn leaves exactly the state a crashed
//! daemon would, and the next worker's `Kernel::run → recover()` settles it.
//!
//! Process hygiene (a two-day-old orphan daemon was found in the previous round):
//! - every worker is spawned from the pool's one long-lived supervisor thread with
//!   `PR_SET_PDEATHSIG = SIGTERM`, so it dies with that thread (and with the daemon, even on
//!   SIGKILL); stdin EOF independently makes `seagent worker` cancel its turn and exit;
//! - [`Pool::shutdown`] and `Drop` send SIGTERM, wait, then SIGKILL and reap every child.

use crate::event::EventKind;
use crate::kernel::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `[workers]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkersConfig {
    /// Worker processes the leader keeps alive. 0 = sessions run inside the daemon (default).
    pub count: usize,
    /// argv of one worker; empty = this executable `worker --internal-worker-ipc`. May be
    /// remote (`["ssh", "host2", "seagent", "worker", "--internal-worker-ipc"]`) on shared storage.
    pub command: Vec<String>,
    /// `all`: every submitted / resumed session goes to a worker. `explicit`: only
    /// `workers.dispatch`.
    pub dispatch: String,
    /// First restart delay after a worker exits (doubles per consecutive crash, max 30 s).
    pub restart_backoff_ms: u64,
}

impl Default for WorkersConfig {
    fn default() -> Self {
        WorkersConfig { count: 0, command: vec![], dispatch: "all".into(), restart_backoff_ms: 500 }
    }
}

impl WorkersConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.dispatch.as_str(), "all" | "explicit") {
            return Err(format!("workers.dispatch must be `all` or `explicit`, got `{}`", self.dispatch));
        }
        if self.count > 256 {
            return Err("workers.count is at most 256".into());
        }
        Ok(())
    }
    pub fn dispatch_all(&self) -> bool {
        self.count > 0 && self.dispatch == "all"
    }
}

enum Ev {
    Line { idx: usize, gen: u64, v: Value },
    Eof { idx: usize, gen: u64 },
}

struct Slot {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    pid: u32,
    gen: u64,
    /// (turn id, session id) while a run is in flight.
    busy: Option<(String, String)>,
    crashes: u32,
    restarts: u32,
    next_spawn: Instant,
    last_exit: Option<String>,
}

#[derive(Default)]
struct Inner {
    slots: Vec<Slot>,
    queue: VecDeque<String>,
    /// Input that arrived while a worker held the session's log lock.
    held: HashMap<String, Vec<(String, String)>>,
    cancel: Vec<String>,
    done: u64,
    redispatched: u64,
    turn_seq: u64,
}

pub struct Pool {
    cfg: WorkersConfig,
    command: Vec<String>,
    env: Vec<(String, String)>,
    k: Kernel,
    inner: Mutex<Inner>,
    tx: Mutex<Sender<Ev>>,
    rx: Mutex<Option<Receiver<Ev>>>,
    stop: AtomicBool,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn default_command() -> Vec<String> {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "seagent".into());
    vec![exe, "worker".into(), "--internal-worker-ipc".into()]
}

impl Pool {
    /// Start the pool and its supervisor thread. `env` is added to every worker (HA fencing).
    pub fn start(k: Kernel, cfg: WorkersConfig, env: Vec<(String, String)>) -> Arc<Pool> {
        let command = if cfg.command.is_empty() { default_command() } else { cfg.command.clone() };
        let (tx, rx) = channel();
        let now = Instant::now();
        let slots = (0..cfg.count).map(|_| Slot { child: None, stdin: None, pid: 0, gen: 0, busy: None, crashes: 0, restarts: 0, next_spawn: now, last_exit: None }).collect();
        let p = Arc::new(Pool { cfg, command, env, k, inner: Mutex::new(Inner { slots, ..Default::default() }), tx: Mutex::new(tx), rx: Mutex::new(Some(rx)), stop: AtomicBool::new(false), thread: Mutex::new(None) });
        let me = p.clone();
        // The supervisor is the only thread that forks: PR_SET_PDEATHSIG fires when the
        // *thread* that spawned a child exits, so spawning from short-lived threads would kill
        // fresh workers at random.
        let h = std::thread::Builder::new().name("seagent-workers".into()).spawn(move || me.supervise()).ok();
        *p.thread.lock().unwrap() = h;
        p
    }

    /// Queue `session` for a worker. Returns false when it is already queued or running.
    pub fn dispatch(&self, session: &str) -> bool {
        let mut i = self.inner.lock().unwrap();
        if i.queue.iter().any(|s| s == session) || i.slots.iter().any(|s| s.busy.as_ref().is_some_and(|b| b.1 == session)) {
            return false;
        }
        i.queue.push_back(session.to_string());
        true
    }

    /// Is `session` queued or running on a worker?
    pub fn owns(&self, session: &str) -> bool {
        let i = self.inner.lock().unwrap();
        i.queue.iter().any(|s| s == session) || i.slots.iter().any(|s| s.busy.as_ref().is_some_and(|b| b.1 == session))
    }

    pub fn running(&self) -> Vec<String> {
        self.inner.lock().unwrap().slots.iter().filter_map(|s| s.busy.as_ref().map(|b| b.1.clone())).collect()
    }

    /// Keep input for a session a worker is running; it is written after the run and the
    /// session is dispatched again.
    pub fn hold(&self, session: &str, text: &str, source: &str) {
        self.inner.lock().unwrap().held.entry(session.to_string()).or_default().push((text.to_string(), source.to_string()));
    }

    /// Ask the worker running `session` to stop (or drop it from the queue).
    pub fn cancel(&self, session: &str) -> bool {
        let mut i = self.inner.lock().unwrap();
        let before = i.queue.len();
        i.queue.retain(|s| s != session);
        if i.queue.len() != before {
            return true;
        }
        if i.slots.iter().any(|s| s.busy.as_ref().is_some_and(|b| b.1 == session)) {
            i.cancel.push(session.to_string());
            return true;
        }
        false
    }

    pub fn status(&self) -> Value {
        let i = self.inner.lock().unwrap();
        json!({
            "count": self.cfg.count,
            "dispatch": self.cfg.dispatch,
            "command": self.command,
            "workers": i.slots.iter().enumerate().map(|(n, s)| json!({"index": n, "pid": (s.pid != 0).then_some(s.pid), "alive": s.child.is_some(), "session": s.busy.as_ref().map(|b| &b.1), "restarts": s.restarts, "last_exit": s.last_exit})).collect::<Vec<_>>(),
            "queue": i.queue,
            "held": i.held.keys().collect::<Vec<_>>(),
            "completed": i.done,
            "redispatched": i.redispatched,
        })
    }

    /// Worker pids (tests use them to kill one; the daemon to show them).
    pub fn pids(&self) -> Vec<u32> {
        self.inner.lock().unwrap().slots.iter().filter(|s| s.child.is_some()).map(|s| s.pid).collect()
    }

    fn spawn(&self, idx: usize, slot: &mut Slot) {
        let mut cmd = seagent_core::platform::proc::command(&self.command[0]);
        cmd.args(&self.command[1..]).envs(self.env.iter().map(|(k, v)| (k, v))).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: prctl is async-signal-safe; no allocation between fork and exec.
            unsafe {
                cmd.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong, 0, 0, 0);
                    Ok(())
                });
            }
        }
        // Windows: a kill-on-close Job Object is the parent-death tie (macOS has none; the
        // worker also exits on stdin EOF, which a dead daemon produces).
        match cmd.spawn().and_then(|c| match seagent_core::platform::proc::adopt(&c) {
            Ok(()) => Ok(c),
            Err(e) => {
                let mut c = c;
                let _ = c.kill();
                let _ = c.wait();
                Err(e)
            }
        }) {
            Ok(mut c) => {
                slot.gen += 1;
                slot.pid = c.id();
                slot.stdin = c.stdin.take();
                let out = c.stdout.take();
                slot.child = Some(c);
                let gen = slot.gen;
                let tx = self.tx.lock().unwrap().clone();
                if let Some(out) = out {
                    std::thread::spawn(move || {
                        for line in BufReader::new(out).lines() {
                            let Ok(line) = line else { break };
                            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                                if tx.send(Ev::Line { idx, gen, v }).is_err() {
                                    return;
                                }
                            }
                        }
                        let _ = tx.send(Ev::Eof { idx, gen });
                    });
                }
            }
            Err(e) => {
                slot.last_exit = Some(format!("spawn {}: {e}", self.command[0]));
                slot.crashes += 1;
                slot.next_spawn = Instant::now() + self.backoff(slot.crashes);
            }
        }
    }

    fn backoff(&self, crashes: u32) -> Duration {
        let base = self.cfg.restart_backoff_ms.max(50);
        Duration::from_millis(base.saturating_mul(1 << crashes.min(10)).min(30_000))
    }

    fn send(slot: &mut Slot, v: &Value) -> bool {
        let Some(w) = slot.stdin.as_mut() else { return false };
        writeln!(w, "{v}").and_then(|_| w.flush()).is_ok()
    }

    fn supervise(self: Arc<Self>) {
        let rx = self.rx.lock().unwrap().take();
        let Some(rx) = rx else { return };
        while !self.stop.load(Ordering::SeqCst) {
            let ev = rx.recv_timeout(Duration::from_millis(50)).ok();
            let mut notices: Vec<(String, String)> = vec![];
            let mut deliver: Vec<(String, Vec<(String, String)>)> = vec![];
            {
                let mut guard = self.inner.lock().unwrap();
                let i = &mut *guard;
                match ev {
                    Some(Ev::Line { idx, gen, v }) if i.slots.get(idx).is_some_and(|s| s.gen == gen) => {
                        if v["type"] == "result" {
                            let slot = &mut i.slots[idx];
                            if slot.busy.as_ref().is_some_and(|b| v["turnId"].as_str() == Some(b.0.as_str())) {
                                let (_, sid) = slot.busy.take().unwrap_or_default();
                                slot.crashes = 0;
                                i.done += 1;
                                if let Some(h) = i.held.remove(&sid) {
                                    deliver.push((sid, h));
                                }
                            }
                        }
                    }
                    Some(Ev::Eof { idx, gen }) if i.slots.get(idx).is_some_and(|s| s.gen == gen) => {
                        let slot = &mut i.slots[idx];
                        let status = slot.child.take().map(|mut c| c.wait().map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())).unwrap_or_default();
                        slot.stdin = None;
                        slot.last_exit = Some(status.clone());
                        slot.crashes += 1;
                        slot.restarts += 1;
                        slot.next_spawn = Instant::now() + self.backoff(slot.crashes.saturating_sub(1));
                        if let Some((_, sid)) = slot.busy.take() {
                            notices.push((sid.clone(), format!("worker {idx} (pid {}) exited mid-run ({status}); session re-dispatched", slot.pid)));
                            i.queue.push_front(sid);
                            i.redispatched += 1;
                        }
                    }
                    _ => {}
                }
                if !self.stop.load(Ordering::SeqCst) {
                    let now = Instant::now();
                    for idx in 0..i.slots.len() {
                        if i.slots[idx].child.is_none() && now >= i.slots[idx].next_spawn {
                            let mut slot = std::mem::replace(&mut i.slots[idx], Slot { child: None, stdin: None, pid: 0, gen: 0, busy: None, crashes: 0, restarts: 0, next_spawn: now, last_exit: None });
                            self.spawn(idx, &mut slot);
                            i.slots[idx] = slot;
                        }
                    }
                    // Cancellations.
                    for sid in std::mem::take(&mut i.cancel) {
                        if let Some(slot) = i.slots.iter_mut().find(|s| s.busy.as_ref().is_some_and(|b| b.1 == sid)) {
                            let turn = slot.busy.as_ref().map(|b| b.0.clone()).unwrap_or_default();
                            Self::send(slot, &json!({"type": "cancel", "turnId": turn}));
                        }
                    }
                    // Assign queued sessions to idle, live workers.
                    while let Some(idx) = i.slots.iter().position(|s| s.child.is_some() && s.busy.is_none()) {
                        let Some(sid) = i.queue.pop_front() else { break };
                        i.turn_seq += 1;
                        let turn = format!("run-{}", i.turn_seq);
                        let slot = &mut i.slots[idx];
                        if Self::send(slot, &json!({"type": "run", "turnId": turn, "sessionId": sid})) {
                            slot.busy = Some((turn, sid));
                        } else {
                            // Broken pipe: the EOF event will respawn it; keep the session queued.
                            i.queue.push_front(sid);
                            break;
                        }
                    }
                }
            }
            for (sid, text) in notices {
                eprintln!("seagentd: {text}");
                let _ = self.k.record(&sid, EventKind::Notice { level: "warn".into(), text });
            }
            for (sid, items) in deliver {
                for (text, source) in items {
                    let _ = self.k.submit(&sid, &text, &source);
                }
                self.dispatch(&sid);
            }
        }
        self.kill_all();
    }

    fn kill_all(&self) {
        let mut children: Vec<Child> = {
            let mut i = self.inner.lock().unwrap();
            i.slots.iter_mut().filter_map(|s| {
                s.stdin = None; // EOF first: `seagent worker` cancels its turn and exits on its own
                s.child.take()
            }).collect()
        };
        let until = Instant::now() + Duration::from_secs(3);
        // Windows has no SIGTERM: the stdin EOF above is the polite stop, `kill` the fallback.
        #[cfg(unix)]
        for c in &children {
            // SAFETY: signalling a child we spawned and have not reaped yet (pid is ours).
            unsafe { libc::kill(c.id() as libc::pid_t, libc::SIGTERM) };
        }
        for c in children.iter_mut() {
            while Instant::now() < until {
                if matches!(c.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if !matches!(c.try_wait(), Ok(Some(_))) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// Stop the supervisor and reap every worker. Idempotent.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.lock().unwrap().take() {
            let _ = h.join();
        }
        self.kill_all();
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.kill_all();
    }
}

#[cfg(test)]
#[cfg(unix)] // the fake worker is a POSIX sh script
mod tests {
    use super::*;

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    /// A fake worker speaking the protocol in POSIX sh: the first process ever started dies on
    /// its first `run` (exit 3) without answering; every later one answers `completed`. `set -C`
    /// (O_EXCL) is the atomic test-and-set — two workers handed their first run at once must not
    /// both crash. Not `mkdir`: uutils coreutils' mkdir (Ubuntu 25.10+) lets both racers win.
    fn fake_worker(dir: &std::path::Path) -> Vec<String> {
        let script = dir.join("worker.sh");
        let mark = dir.join("crashed-once");
        let log = dir.join("runs.log");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nwhile IFS= read -r line; do\n  turn=$(printf '%s' \"$line\" | sed -n 's/.*\"turnId\":\"\\([^\"]*\\)\".*/\\1/p')\n  sid=$(printf '%s' \"$line\" | sed -n 's/.*\"sessionId\":\"\\([^\"]*\\)\".*/\\1/p')\n  if (set -C; : > {mark}) 2>/dev/null; then exit 3; fi\n  echo \"$$ $sid\" >> {log}\n  printf '{{\"type\":\"started\",\"turnId\":\"%s\",\"sessionId\":\"%s\"}}\\n' \"$turn\" \"$sid\"\n  printf '{{\"type\":\"result\",\"turnId\":\"%s\",\"sessionId\":\"%s\",\"status\":\"completed\"}}\\n' \"$turn\" \"$sid\"\ndone\n",
                mark = mark.display(),
                log = log.display()
            ),
        )
        .unwrap();
        vec!["/bin/sh".into(), script.display().to_string()]
    }

    #[test]
    fn sessions_are_spread_redispatched_after_a_crash_and_workers_reaped() {
        let d = seagent_core::tmp::TempDir::new("seagent-workers");
        let paths = crate::config::Paths { data: d.path().join("data"), config_dir: d.path().join("cfg"), runtime: d.path().join("run"), ..Default::default() };
        let (pending, _cell) = crate::daemon::pending_approver(Duration::from_secs(5));
        let k = crate::kernel::new_kernel(crate::config::Config::default(), paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), pending);
        let ids: Vec<String> = (0..4).map(|n| k.create_session(d.path(), Some("x/y"), None, Some(&format!("s{n}"))).unwrap()).collect();
        let cfg = WorkersConfig { count: 2, command: fake_worker(d.path()), restart_backoff_ms: 50, ..Default::default() };
        let pool = Pool::start(k.clone(), cfg, vec![("SEAGENT_TEST_MARK".into(), "1".into())]);
        for id in &ids {
            assert!(pool.dispatch(id));
        }
        assert!(!pool.dispatch(&ids[0]), "a queued session is not queued twice");
        let until = Instant::now() + Duration::from_secs(20);
        while Instant::now() < until && pool.status()["completed"].as_u64() < Some(4) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let st = pool.status();
        assert_eq!(st["completed"], 4, "{st}");
        assert_eq!(st["redispatched"], 1, "exactly the crashed run was re-dispatched: {st}");
        let runs = std::fs::read_to_string(d.path().join("runs.log")).unwrap();
        for id in &ids {
            assert_eq!(runs.lines().filter(|l| l.ends_with(id.as_str())).count(), 1, "each session ran once to completion: {runs}");
        }
        // The crash left a notice in the session that was re-dispatched.
        let notices = ids.iter().filter(|id| k.store.read(id).unwrap().iter().any(|e| matches!(&e.kind, EventKind::Notice { text, .. } if text.contains("re-dispatched")))).count();
        assert_eq!(notices, 1);
        // Held input is written after the run and the session goes out again.
        pool.hold(&ids[1], "later", "test");
        assert!(pool.dispatch(&ids[1]));
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until && pool.status()["completed"].as_u64() < Some(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pids = pool.pids();
        assert_eq!(pids.len(), 2);
        pool.shutdown();
        for pid in pids {
            assert!(!crate::kanban::pid_alive(pid), "worker {pid} survived the pool");
        }
    }
}
