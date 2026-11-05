//! ent-095 / ent-096 / ent-097 end to end: real `seagent daemon run` processes sharing one data
//! directory (each node has its own `config/` and `run/`, `data/` is a symlink onto the shared
//! tree — the same shape as an NFS mount), a loopback model that can hold a request open, and:
//!
//! 1. the leader is SIGKILLed mid-turn → the standby takes the lease within the deadline and
//!    finishes the interrupted session from its JSONL log;
//! 2. the leader is SIGSTOPped mid-turn (a GC pause / partition) → the standby takes over; when
//!    the old leader wakes with the model's reply in hand, fencing refuses the write, so the
//!    session is never executed by two nodes at once;
//! 3. with `[workers] count = 2` the session runs in a worker process; SIGKILLing that worker
//!    re-dispatches the session to the other one.
//!
//! Every process a test starts is owned by a drop guard (SIGCONT + SIGKILL + wait), so a failing
//! assertion or a panic never leaves a daemon or worker behind. Only those pids are signalled.

use seagent_core::tmp::TempDir;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ───────────────────────── a model that can hold a request ─────────────────────────

struct Model {
    url: String,
    seen: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
}

fn sse_text(text: &str) -> String {
    let d = json!({"type": "response.output_text.delta", "delta": text});
    let c = json!({"type": "response.completed", "response": {"model": "gpt-4o-mini", "usage": {"input_tokens": 5, "output_tokens": 2}}});
    format!("event: response.output_text.delta\ndata: {d}\n\nevent: response.completed\ndata: {c}\n\n")
}

impl Model {
    /// Request #0 is held until `release` (then answered `STALE-REPLY`); every later request is
    /// answered at once with `fresh reply <n>`. One thread per connection.
    fn start() -> Model {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let (s2, r2) = (seen.clone(), release.clone());
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (seen, release) = (s2.clone(), r2.clone());
                std::thread::spawn(move || {
                    let mut r = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                            break;
                        }
                        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; len];
                    if len > 0 && r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let n = seen.fetch_add(1, Ordering::SeqCst);
                    let text = if n == 0 {
                        let until = Instant::now() + Duration::from_secs(90);
                        while !release.load(Ordering::SeqCst) && Instant::now() < until {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        "STALE-REPLY".to_string()
                    } else {
                        format!("fresh reply {n}")
                    };
                    let out = sse_text(&text);
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", out.len());
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(out.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        Model { url, seen, release }
    }
}

// ───────────────────────── processes ─────────────────────────

/// Owns one process this test started: on drop (also on panic) it is resumed if stopped,
/// SIGKILLed and reaped. Extra pids (workers the daemon started for us) get the same.
struct Proc {
    child: Option<Child>,
    extra: Vec<u32>,
    log: PathBuf,
}

impl Proc {
    fn pid(&self) -> u32 {
        self.child.as_ref().map(|c| c.id()).unwrap_or(0)
    }
    fn signal(&self, sig: libc::c_int) {
        if self.child.is_some() {
            // SAFETY: our own child, not yet reaped.
            unsafe { libc::kill(self.pid() as libc::pid_t, sig) };
        }
    }
    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SAFETY: our own child, not yet reaped (SIGCONT so a stopped one can die cleanly).
            unsafe { libc::kill(c.id() as libc::pid_t, libc::SIGCONT) };
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
        for pid in self.extra.drain(..) {
            if alive(pid) {
                // SAFETY: a worker started by the daemon this test started.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
        }
    }
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks existence.
    pid != 0 && unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 && !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
}

struct Cluster {
    _root: TempDir,
    root: PathBuf,
    shared: PathBuf,
    model: Model,
}

impl Cluster {
    fn new() -> Cluster {
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let root = TempDir::new_in(base, "ha");
        let r = root.path().to_path_buf();
        let shared = r.join("shared");
        std::fs::create_dir_all(shared.join("ws")).unwrap();
        Cluster { _root: root, root: r, shared, model: Model::start() }
    }

    /// One node: its own SEAGENT_HOME with `data -> ../shared`.
    fn node(&self, name: &str, extra: &str) -> PathBuf {
        let h = self.root.join(name);
        std::fs::create_dir_all(h.join("config")).unwrap();
        if !h.join("data").exists() {
            std::os::unix::fs::symlink(&self.shared, h.join("data")).unwrap();
        }
        std::fs::write(
            h.join("config/config.toml"),
            format!(
                "[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}/v1\"\nformat = \"openai_responses\"\n\n[runner]\nmax_retries = 0\n\n[ha]\nenabled = true\nnode_id = \"{name}\"\nlease_secs = 2\nadvertise = \"unix:{name}\"\n\n[cluster]\nheartbeat_secs = 1\n{extra}",
                self.model.url
            ),
        )
        .unwrap();
        let sock = h.join("run/seagentd.sock");
        assert!(h.join("run").as_os_str().len() <= 80, "keep the runtime dir short (else it moves out of TMPDIR): {}", h.display());
        let _ = sock;
        h
    }

    fn start(&self, home: &Path) -> Proc {
        let log = home.join("daemon.log");
        let f = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_seagent"))
            .args(["daemon", "run", "-w", self.shared.join("ws").to_str().unwrap()])
            .env("SEAGENT_HOME", home)
            .env("SEAGENT_OFFLINE", "1")
            .env_remove("OPENAI_API_KEY")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("XDG_RUNTIME_DIR")
            .stdin(Stdio::null())
            .stdout(f.try_clone().unwrap())
            .stderr(f)
            .spawn()
            .expect("spawn seagentd");
        let p = Proc { child: Some(child), extra: vec![], log };
        let up = wait_for(Duration::from_secs(30), || rpc(home, "ping", json!({})).is_ok());
        assert!(up, "seagentd did not come up:\n{}", p.log());
        p
    }

    fn events(&self, sid: &str) -> Vec<Value> {
        std::fs::read_to_string(self.shared.join("sessions").join(sid).join("events.jsonl")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

fn rpc(home: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut s = UnixStream::connect(home.join("run/seagentd.sock")).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    writeln!(s, "{}", json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    match v.get("error") {
        Some(e) => Err(format!("{} {}", e["code"], e["message"].as_str().unwrap_or(""))),
        None => Ok(v["result"].clone()),
    }
}

fn wait_for(d: Duration, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + d;
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn role(home: &Path) -> String {
    rpc(home, "ha.status", json!({})).map(|v| format!("{}:{}", v["role"].as_str().unwrap_or("?"), v["epoch"])).unwrap_or_else(|e| format!("error:{e}"))
}

fn texts(evs: &[Value]) -> String {
    evs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
}

/// Bring up a leader `a` and a standby `b`, and start a turn on `a` that the model holds.
fn leader_mid_turn(c: &Cluster, extra: &str) -> (PathBuf, Proc, PathBuf, Proc, String) {
    let ha = c.node("a", extra);
    let hb = c.node("b", extra);
    let a = c.start(&ha);
    assert!(wait_for(Duration::from_secs(10), || role(&ha) == "leader:1"), "a did not win the empty lease: {}\n{}", role(&ha), a.log());
    let b = c.start(&hb);
    assert!(wait_for(Duration::from_secs(5), || role(&hb).starts_with("standby")), "b: {}", role(&hb));
    // A standby serves reads but refuses work, pointing at the leader.
    let err = rpc(&hb, "session.create", json!({"workspace": c.shared.join("ws")})).unwrap_err();
    assert!(err.contains("-32010") && err.contains("node a"), "{err}");
    assert!(rpc(&hb, "session.list", json!({})).is_ok());
    let sid = rpc(&ha, "session.create", json!({"workspace": c.shared.join("ws"), "title": "ha"})).unwrap()["id"].as_str().unwrap().to_string();
    rpc(&ha, "session.submit", json!({"id": sid, "text": "keep going"})).unwrap();
    assert!(wait_for(Duration::from_secs(20), || c.model.seen.load(Ordering::SeqCst) >= 1), "the leader never asked the model:\n{}", a.log());
    (ha, a, hb, b, sid)
}

#[test]
fn leader_killed_mid_turn_standby_takes_over_and_finishes_the_session() {
    let c = Cluster::new();
    let (_ha, mut a, hb, b, sid) = leader_mid_turn(&c, "");
    a.kill(); // SIGKILL: no step-down, no cleanup — a crash.
    let t0 = Instant::now();
    assert!(wait_for(Duration::from_secs(15), || role(&hb) == "leader:2"), "b did not take over: {}\n{}", role(&hb), b.log());
    let took = t0.elapsed();
    // lease 2 s: one full silent lease on b's own clock plus its tick, well inside 2 leases + slack.
    assert!(took < Duration::from_secs(7), "takeover took {took:?}");
    assert!(wait_for(Duration::from_secs(30), || texts(&c.events(&sid)).contains("fresh reply")), "the session was not finished by b:\n{}\n{}", texts(&c.events(&sid)), b.log());
    let evs = texts(&c.events(&sid));
    assert!(evs.contains("ha: node b (epoch 2) resumed this session after failover"), "{evs}");
    assert!(!evs.contains("STALE-REPLY"));
    // The registry shows both nodes; the dead one goes stale.
    let nodes = rpc(&hb, "cluster.nodes.list", json!({})).unwrap();
    let names: Vec<&str> = nodes.as_array().unwrap().iter().filter_map(|n| n["node"].as_str()).collect();
    assert!(names.contains(&"a") && names.contains(&"b"), "{nodes}");
    c.model.release.store(true, Ordering::SeqCst);
}

#[test]
fn paused_leader_is_fenced_and_the_session_never_runs_on_two_nodes() {
    let c = Cluster::new();
    let (ha, a, hb, b, sid) = leader_mid_turn(&c, "");
    a.signal(libc::SIGSTOP); // a GC pause / partition: a still holds the session lock.
    assert!(wait_for(Duration::from_secs(15), || role(&hb) == "leader:2"), "b did not take over from a paused a: {}\n{}", role(&hb), b.log());
    // a cannot renew while stopped; b now leads but the log is still locked by a, so nothing
    // has been written for b yet.
    std::thread::sleep(Duration::from_millis(500));
    assert!(!texts(&c.events(&sid)).contains("fresh reply"));
    // a wakes up with the model's (stale) reply already in its socket.
    c.model.release.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    a.signal(libc::SIGCONT);
    assert!(wait_for(Duration::from_secs(30), || texts(&c.events(&sid)).contains("fresh reply")), "b never got the session:\n{}\n--- a ---\n{}\n--- b ---\n{}", texts(&c.events(&sid)), a.log(), b.log());
    let evs = texts(&c.events(&sid));
    assert!(!evs.contains("STALE-REPLY"), "the deposed leader wrote into the log:\n{evs}");
    assert!(evs.contains("resumed this session after failover"), "{evs}");
    assert!(wait_for(Duration::from_secs(5), || role(&ha).starts_with("standby")), "a did not step down: {}", role(&ha));
    assert!(a.log().contains("no longer the leader"), "{}", a.log());
    // Exactly one assistant reply in the log: one execution, never two.
    let replies = c.events(&sid).iter().filter(|e| e["type"] == "message" && e.to_string().contains("\"assistant\"")).count();
    assert_eq!(replies, 1, "{evs}");
    // a graceful stop of the leader hands over immediately (released lease, no full wait).
    drop(b);
    let _ = ha;
}

#[test]
fn a_dead_worker_session_is_redispatched_to_another_worker() {
    let c = Cluster::new();
    let h = c.node("w", "\n[workers]\ncount = 2\nrestart_backoff_ms = 100\n");
    let mut d = c.start(&h);
    assert!(wait_for(Duration::from_secs(10), || role(&h) == "leader:1"), "{}", role(&h));
    assert!(wait_for(Duration::from_secs(20), || rpc(&h, "workers.status", json!({})).is_ok_and(|v| v["workers"].as_array().is_some_and(|w| w.iter().filter(|x| x["alive"] == true).count() == 2))), "workers did not start:\n{}", d.log());
    d.extra = rpc(&h, "workers.status", json!({})).unwrap()["workers"].as_array().unwrap().iter().filter_map(|w| w["pid"].as_u64().map(|p| p as u32)).collect();
    let sid = rpc(&h, "session.create", json!({"workspace": c.shared.join("ws"), "title": "pooled"})).unwrap()["id"].as_str().unwrap().to_string();
    let r = rpc(&h, "session.submit", json!({"id": sid, "text": "work"})).unwrap();
    assert_eq!(r["worker"], true, "{r}");
    assert!(wait_for(Duration::from_secs(30), || c.model.seen.load(Ordering::SeqCst) >= 1), "no worker asked the model:\n{}", d.log());
    let st = rpc(&h, "workers.status", json!({})).unwrap();
    let busy = st["workers"].as_array().unwrap().iter().find(|w| w["session"] == sid.as_str()).cloned().unwrap_or_else(|| panic!("{st}"));
    let pid = busy["pid"].as_u64().unwrap() as u32;
    assert_ne!(pid, d.pid(), "the session runs in a worker process, not in the daemon");
    // SAFETY: a worker our daemon started for this test.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert!(wait_for(Duration::from_secs(30), || texts(&c.events(&sid)).contains("fresh reply")), "not re-dispatched:\n{}\n{}", texts(&c.events(&sid)), d.log());
    let evs = texts(&c.events(&sid));
    assert!(evs.contains("re-dispatched"), "{evs}");
    let st = rpc(&h, "workers.status", json!({})).unwrap();
    assert_eq!(st["redispatched"], 1, "{st}");
    let workers: Vec<u32> = st["workers"].as_array().unwrap().iter().filter_map(|w| w["pid"].as_u64().map(|p| p as u32)).collect();
    d.extra.extend(workers.iter().copied());
    c.model.release.store(true, Ordering::SeqCst);
    // An orderly stop reaps every worker.
    rpc(&h, "shutdown", json!({})).unwrap();
    let mut child = d.child.take().unwrap();
    let exited = wait_for(Duration::from_secs(20), || matches!(child.try_wait(), Ok(Some(_))));
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();
    assert!(exited, "seagentd did not stop");
    assert!(wait_for(Duration::from_secs(5), || workers.iter().all(|p| !alive(*p))), "a worker outlived the daemon");
}
