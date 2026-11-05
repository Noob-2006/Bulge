//! Modal cloud sandbox backend (Hermes tools/environments/modal.py). Modal has
//! no public REST API, so ark drives the official `modal` Python SDK through a
//! small long-lived bridge process speaking JSON lines: create (or re-attach
//! to the scope's running sandbox, or restore its filesystem snapshot), exec
//! with streamed stdout/stderr and real stdin, terminate, snapshot. The
//! managed (Nous subscription) Modal gateway is not applicable to ark.

use super::sync::common::{self, Ev, Record, RemoteChild};
use super::sync::{self, SyncOptions, WorkspaceSync};
use super::{BackendCtx, ExecConfig};
use ark_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `[exec.modal]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModalConfig {
    /// Registry image, or an `im-…` image / snapshot id.
    pub image: String,
    /// Modal app the sandboxes belong to (created if missing).
    pub app: String,
    pub python: String,
    pub token_id_secret: String,
    pub token_secret_secret: String,
    pub cpu: f64,
    pub memory_mb: u64,
    /// Sandbox lifetime (s).
    pub timeout_secs: u64,
    /// Snapshot the filesystem on cleanup and restore it next time.
    pub persistent: bool,
    pub workspace_root: String,
}

impl Default for ModalConfig {
    fn default() -> Self {
        ModalConfig {
            image: "nousresearch/hermes-sandbox:desktop".into(),
            app: "ark-agent".into(),
            python: "python3".into(),
            token_id_secret: "MODAL_TOKEN_ID".into(),
            token_secret_secret: "MODAL_TOKEN_SECRET".into(),
            cpu: 1.0,
            memory_mb: 5120,
            timeout_secs: 3600,
            persistent: true,
            workspace_root: "/root/workspace".into(),
        }
    }
}

/// The SDK side. Kept small: every call is one JSON line in, one reply line out
/// (`rid`), plus `ev` lines streaming exec output.
const BRIDGE: &str = r#"
import sys, json, base64, threading
import modal

_lock = threading.Lock()
def send(o):
    with _lock:
        sys.stdout.write(json.dumps(o) + "\n")
        sys.stdout.flush()

sb = None
procs = {}

def image_for(spec):
    if spec.startswith("im-"):
        return modal.Image.from_id(spec)
    setup = ["RUN rm -rf /usr/local/lib/python*/site-packages/pip* 2>/dev/null; python -m ensurepip --upgrade --default-pip 2>/dev/null || true"]
    if any(b in spec.lower() for b in ("ubuntu", "debian")):
        setup.insert(0, "RUN apt-get update -qq && apt-get install -y -qq python3 python3-venv > /dev/null 2>&1 || true")
    return modal.Image.from_registry(spec, setup_dockerfile_commands=setup)

def b(x):
    if x is None:
        return b""
    return x if isinstance(x, bytes) else x.encode("utf-8", "surrogateescape")

def pump(eid, stream):
    try:
        for chunk in stream:
            if chunk:
                send({"ev": "out", "id": eid, "data": base64.b64encode(b(chunk)).decode()})
    except Exception as e:
        send({"ev": "out", "id": eid, "data": base64.b64encode(("[modal stream error: %s]\n" % e).encode()).decode()})

def run_exec(eid, p):
    ts = [threading.Thread(target=pump, args=(eid, s), daemon=True) for s in (p.stdout, p.stderr)]
    for t in ts: t.start()
    for t in ts: t.join()
    try:
        code = p.wait()
        if code is None:
            code = p.returncode
    except Exception:
        code = None
    procs.pop(eid, None)
    send({"ev": "exit", "id": eid, "code": code})

def handle(r):
    global sb
    op = r["op"]
    if op == "create":
        app = modal.App.lookup(r.get("app") or "ark-agent", create_if_missing=True)
        if r.get("sandbox_id"):
            try:
                s = modal.Sandbox.from_id(r["sandbox_id"])
                if s.poll() is None:
                    sb = s
                    return {"sandbox_id": s.object_id, "reused": True}
            except Exception:
                pass
        kw = {"timeout": int(r.get("timeout") or 3600)}
        if r.get("cpu"): kw["cpu"] = float(r["cpu"])
        if r.get("memory"): kw["memory"] = int(r["memory"])
        sb, restored, note = None, False, ""
        if r.get("snapshot"):
            try:
                sb = modal.Sandbox.create("sleep", "infinity", image=modal.Image.from_id(r["snapshot"]), app=app, **kw)
                restored = True
            except Exception as e:
                note = "snapshot restore failed: %s" % e
        if sb is None:
            sb = modal.Sandbox.create("sleep", "infinity", image=image_for(r["image"]), app=app, **kw)
        return {"sandbox_id": sb.object_id, "restored": restored, "note": note}
    if op == "exec":
        p = sb.exec(*r["argv"], timeout=r.get("timeout") or None)
        procs[r["id"]] = p
        threading.Thread(target=run_exec, args=(r["id"], p), daemon=True).start()
        return {}
    if op == "stdin":
        p = procs.get(r["id"])
        if p is None:
            raise RuntimeError("process already finished")
        data = base64.b64decode(r.get("data") or "")
        if data:
            p.stdin.write(data)
            p.stdin.drain()
        if r.get("eof"):
            p.stdin.write_eof()
            p.stdin.drain()
        return {}
    if op == "poll":
        return {"running": sb is not None and sb.poll() is None}
    if op == "snapshot":
        return {"image_id": sb.snapshot_filesystem().object_id}
    if op == "terminate":
        if sb is not None:
            sb.terminate()
        return {}
    raise RuntimeError("unknown op " + op)

for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue
    try:
        res = handle(req) or {}
        res.update(rid=req.get("rid"), ok=True)
    except Exception as e:
        res = {"rid": req.get("rid"), "ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    send(res)
"#;

/// Modal's stdin buffer limits (Hermes `_STDIN_CHUNK_SIZE`).
const STDIN_CHUNK: usize = 1024 * 1024;

type Waiters = Arc<Mutex<HashMap<u64, Sender<Value>>>>;
type Streams = Arc<Mutex<HashMap<u64, Sender<Ev>>>>;

struct Bridge {
    child: Child,
    stdin: Mutex<ChildStdin>,
    waiters: Waiters,
    streams: Streams,
    seq: AtomicU64,
}

impl Bridge {
    fn start(python: &str, env: &[(String, String)], dir: &Path) -> Result<Arc<Bridge>, String> {
        let mut cmd = Command::new(python);
        cmd.arg("-u").arg("-c").arg(BRIDGE).current_dir(dir).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        // A freshly written `python` (or a just-installed one) can be `ETXTBSY` for a moment
        // while a forked child still holds its write descriptor.
        let mut child = super::retry_etxtbsy(|| cmd.spawn()).map_err(|e| format!("exec backend modal: cannot start {python}: {e}"))?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let stdin = child.stdin.take().unwrap();
        let b = Arc::new(Bridge { child, stdin: Mutex::new(stdin), waiters: Default::default(), streams: Default::default(), seq: AtomicU64::new(1) });
        let (w, s) = (b.waiters.clone(), b.streams.clone());
        let err_tail = Arc::new(Mutex::new(String::new()));
        let et = err_tail.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut t = et.lock().unwrap();
                t.push_str(&l);
                t.push('\n');
                let n = t.len();
                if n > 4000 {
                    t.drain(..n - 4000);
                }
            }
        });
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                if let Some(ev) = v.get("ev").and_then(|e| e.as_str()) {
                    let id = v.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
                    let mut streams = s.lock().unwrap();
                    match ev {
                        "out" => {
                            let data = common::unb64(v.get("data").and_then(|d| d.as_str()).unwrap_or("").as_bytes()).unwrap_or_default();
                            if let Some(tx) = streams.get(&id) {
                                let _ = tx.send(Ev::Out(data));
                            }
                        }
                        "exit" => {
                            if let Some(tx) = streams.remove(&id) {
                                let code = v.get("code").and_then(|c| c.as_i64());
                                let _ = tx.send(Ev::Exit(code.map(|c| ExitInfo::code(c as i32)).unwrap_or(ExitInfo { code: None, signal: None })));
                            }
                        }
                        _ => {}
                    }
                } else if let Some(rid) = v.get("rid").and_then(|r| r.as_u64()) {
                    if let Some(tx) = w.lock().unwrap().remove(&rid) {
                        let _ = tx.send(v);
                    }
                }
            }
            // Bridge gone: fail everyone still waiting.
            let tail = err_tail.lock().unwrap().clone();
            for (_, tx) in w.lock().unwrap().drain() {
                let _ = tx.send(json!({"ok": false, "error": format!("modal bridge exited: {}", tail.trim())}));
            }
            for (_, tx) in s.lock().unwrap().drain() {
                let _ = tx.send(Ev::Out(format!("\n[modal bridge exited: {}]\n", tail.trim()).into_bytes()));
            }
        });
        Ok(b)
    }

    fn call(&self, mut req: Value, timeout: Duration) -> Result<Value, String> {
        let rid = self.seq.fetch_add(1, Ordering::SeqCst);
        req["rid"] = json!(rid);
        let (tx, rx) = mpsc::channel();
        self.waiters.lock().unwrap().insert(rid, tx);
        {
            let mut w = self.stdin.lock().unwrap();
            let line = format!("{}\n", serde_json::to_string(&req).unwrap_or_default());
            if let Err(e) = w.write_all(line.as_bytes()).and_then(|_| w.flush()) {
                self.waiters.lock().unwrap().remove(&rid);
                return Err(format!("modal bridge: {e}"));
            }
        }
        let v = rx.recv_timeout(timeout).map_err(|_| {
            self.waiters.lock().unwrap().remove(&rid);
            format!("modal: `{}` timed out after {}s", req["op"].as_str().unwrap_or("?"), timeout.as_secs())
        })?;
        if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
            Ok(v)
        } else {
            Err(format!("modal: {}", v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error")))
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn build(v: &Value, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    let mc: ModalConfig = if v.is_null() { ModalConfig::default() } else { serde_json::from_value(v.clone()).map_err(|e| format!("[exec.modal]: {e}"))? };
    Ok(Arc::new(ModalBackend::new(mc, cfg, ctx)?))
}

pub struct ModalBackend {
    cfg: ModalConfig,
    bridge: Arc<Bridge>,
    sandbox: Mutex<String>,
    record: Record,
    host_ws: PathBuf,
    sync: WorkspaceSync,
    creds: Vec<String>,
    creds_done: AtomicBool,
    passthrough: Vec<String>,
    gone: AtomicBool,
    seq: AtomicU64,
}

impl ModalBackend {
    pub fn new(cfg: ModalConfig, ecfg: &ExecConfig, ctx: &BackendCtx) -> Result<ModalBackend, String> {
        let mut env = Vec::new();
        for (secret, var) in [(&cfg.token_id_secret, "MODAL_TOKEN_ID"), (&cfg.token_secret_secret, "MODAL_TOKEN_SECRET")] {
            if let Some(v) = ctx.secret(secret) {
                env.push((var.to_string(), v));
            }
        }
        let has_profile = std::env::var_os("HOME").is_some_and(|h| Path::new(&h).join(".modal.toml").exists());
        if env.len() < 2 && !has_profile {
            return Err(format!("exec backend modal: no credentials (store `{}` and `{}` with `ark secrets set`, or run `modal token new`)", cfg.token_id_secret, cfg.token_secret_secret));
        }
        let dir = ctx.home.join("sandboxes").join("modal");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let bridge = Bridge::start(&cfg.python, &env, &dir)?;
        let me = ModalBackend {
            bridge,
            sandbox: Mutex::new(String::new()),
            record: Record::new(&ctx.home, "modal", &ctx.scope_key),
            host_ws: ctx.workspace.clone(),
            sync: WorkspaceSync::new(&ctx.workspace, &cfg.workspace_root, SyncOptions::default()),
            creds: ecfg.credential_files.clone(),
            creds_done: AtomicBool::new(false),
            passthrough: ecfg.passthrough(),
            gone: AtomicBool::new(false),
            seq: AtomicU64::new(1),
            cfg,
        };
        me.create(true)?;
        Ok(me)
    }

    fn create(&self, reuse: bool) -> Result<(), String> {
        let req = json!({
            "op": "create",
            "app": self.cfg.app,
            "image": self.cfg.image,
            "sandbox_id": if reuse { self.record.get("sandbox") } else { None },
            "snapshot": if self.cfg.persistent { self.record.get("snapshot") } else { None },
            "timeout": self.cfg.timeout_secs,
            "cpu": self.cfg.cpu,
            "memory": self.cfg.memory_mb,
        });
        let r = self.bridge.call(req, Duration::from_secs(600))?;
        if r.get("note").and_then(|n| n.as_str()).is_some_and(|n| !n.is_empty()) {
            // Hermes: a failed restore drops the stale snapshot id.
            self.record.set("snapshot", None);
        }
        let id = r.get("sandbox_id").and_then(|s| s.as_str()).ok_or("modal: create returned no sandbox id")?.to_string();
        self.record.set("sandbox", Some(&id));
        *self.sandbox.lock().unwrap() = id;
        Ok(())
    }

    fn runner(&self) -> impl Fn(&str, Option<&[u8]>) -> Result<super::Capture, String> + '_ {
        move |script: &str, stdin: Option<&[u8]>| super::run_capture(self, script, stdin, Duration::from_secs(600))
    }
}

impl ExecBackend for ModalBackend {
    fn id(&self) -> &str {
        "modal"
    }
    fn describe(&self) -> String {
        format!("modal: Modal sandbox {} ({}); workspace mirrored to {}", self.sandbox.lock().unwrap(), self.cfg.image, self.cfg.workspace_root)
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        if req.pty.is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "the modal backend has no pseudo-terminals; run without pty"));
        }
        let mut script = common::env_prefix(&req.env, &self.passthrough);
        if let Some(c) = &req.cwd {
            script.push_str(&format!("mkdir -p {0} && cd {0} || exit 126\n", super::sh_quote(&self.map_path(c))));
        }
        script.push_str(&req.script);
        let eid = self.seq.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.bridge.streams.lock().unwrap().insert(eid, tx);
        let argv = json!(["bash", if req.login { "-lc" } else { "-c" }, script]);
        if let Err(e) = self.bridge.call(json!({"op": "exec", "id": eid, "argv": argv}), Duration::from_secs(120)) {
            self.bridge.streams.lock().unwrap().remove(&eid);
            return Err(io::Error::other(e));
        }
        let b = self.bridge.clone();
        let send_stdin = move |data: &[u8], eof: bool| -> io::Result<()> {
            let chunks: Vec<&[u8]> = if data.is_empty() { vec![data] } else { data.chunks(STDIN_CHUNK).collect() };
            let last = chunks.len() - 1;
            for (i, c) in chunks.into_iter().enumerate() {
                b.call(json!({"op": "stdin", "id": eid, "data": common::b64(c), "eof": eof && i == last}), Duration::from_secs(120)).map_err(io::Error::other)?;
            }
            Ok(())
        };
        if let Some(d) = &req.stdin_data {
            send_stdin(d, !req.stdin)?;
        }
        let s2 = send_stdin.clone();
        let stdin: Option<common::StdinFn> = req.stdin.then(|| Box::new(move |d: &[u8]| send_stdin(d, false)) as common::StdinFn);
        let close: Option<Box<dyn FnMut() + Send>> = req.stdin.then(|| Box::new(move || {
            let _ = s2(&[], true);
        }) as Box<dyn FnMut() + Send>);
        let bk = self.bridge.clone();
        // Modal has no per-process kill: like Hermes, interrupting terminates the sandbox
        // (the next command recreates it).
        let killer: common::KillFn = Box::new(move |_| {
            let _ = bk.call(json!({"op": "terminate"}), Duration::from_secs(15));
        });
        Ok(Box::new(RemoteChild::new(rx, stdin, close, Some(killer), "start the command with stdin=true to write to it")))
    }
    fn map_path(&self, host: &Path) -> String {
        common::map_under(&self.host_ws, &self.cfg.workspace_root, host)
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        false
    }
    fn before_exec(&self) -> Result<(), String> {
        let running = self.bridge.call(json!({"op": "poll"}), Duration::from_secs(60))?.get("running").and_then(|r| r.as_bool()).unwrap_or(false);
        if !running {
            self.create(false)?;
            self.sync.reset();
            self.creds_done.store(false, Ordering::SeqCst);
        }
        let run = self.runner();
        if !self.creds.is_empty() && !self.creds_done.load(Ordering::SeqCst) {
            sync::upload_files(&run, &self.creds, false)?;
            self.creds_done.store(true, Ordering::SeqCst);
        }
        self.sync.push(&run).map(|_| ())
    }
    fn after_exec(&self) -> Result<(), String> {
        let run = self.runner();
        let r = self.sync.pull(&run)?;
        if r.skipped.is_empty() {
            Ok(())
        } else {
            Err(format!("workspace sync: {}", r.skipped.join("; ")))
        }
    }
    fn cleanup(&self) {
        if self.gone.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.after_exec();
        if self.cfg.persistent {
            if let Ok(r) = self.bridge.call(json!({"op": "snapshot"}), Duration::from_secs(120)) {
                if let Some(id) = r.get("image_id").and_then(|i| i.as_str()) {
                    self.record.set("snapshot", Some(id));
                }
            }
        }
        let _ = self.bridge.call(json!({"op": "terminate"}), Duration::from_secs(15));
        self.record.set("sandbox", None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmpdir;

    /// A stand-in `modal` package: sandboxes are local dirs, exec runs bash.
    const FAKE_MODAL: &str = r#"
import os, subprocess, threading, json
LOG = os.environ["FAKE_MODAL_LOG"]
def log(*a):
    with open(LOG, "a") as f: f.write(json.dumps(a) + "\n")
_alive = {}
class App:
    @staticmethod
    def lookup(name, create_if_missing=False):
        log("app", name, create_if_missing); return App()
class Image:
    def __init__(self, oid): self.object_id = oid
    @staticmethod
    def from_registry(spec, setup_dockerfile_commands=None): log("registry", spec); return Image("reg:" + spec)
    @staticmethod
    def from_id(i):
        log("from_id", i)
        if i == "im-bad": raise RuntimeError("no such image")
        return Image(i)
class _Stdin:
    def __init__(self, p): self.p = p
    def write(self, d): self.p.stdin.write(d)
    def drain(self): self.p.stdin.flush()
    def write_eof(self): self.p.stdin.close()
class _Proc:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.stdin = _Stdin(self.p)
        self.stdout = iter(lambda: self.p.stdout.read1(4096), b"")
        self.stderr = iter(lambda: self.p.stderr.read1(4096), b"")
        self.returncode = None
    def wait(self):
        self.returncode = self.p.wait(); return self.returncode
class Sandbox:
    n = 0
    def __init__(self, oid): self.object_id = oid
    @staticmethod
    def create(*cmd, image=None, app=None, timeout=None, **kw):
        Sandbox.n += 1; oid = "sb-%d-%s" % (Sandbox.n, image.object_id)
        log("create", list(cmd), image.object_id, timeout, kw); _alive[oid] = True
        return Sandbox(oid)
    @staticmethod
    def from_id(i):
        log("sandbox_from_id", i)
        if os.environ.get("FAKE_MODAL_ALIVE") != i: raise RuntimeError("gone")
        _alive[i] = True; return Sandbox(i)
    def poll(self): return None if _alive.get(self.object_id) else 0
    def exec(self, *argv, timeout=None): log("exec", argv[0], argv[1]); return _Proc(list(argv))
    def terminate(self): log("terminate", self.object_id); _alive[self.object_id] = False
    def snapshot_filesystem(self): log("snapshot"); return Image("im-snap1")
"#;

    fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let d = tmpdir(tag);
        let pkg = d.join("py/modal");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("__init__.py"), FAKE_MODAL).unwrap();
        let (home, ws, remote) = (d.join("home"), d.join("ws"), d.join("remote"));
        for p in [&home, &ws, &remote] {
            std::fs::create_dir_all(p).unwrap();
        }
        (d, home, ws, remote)
    }

    fn ctx(home: &Path, ws: &Path) -> BackendCtx {
        let sec = |s: &str| s.replace("{{secret:MODAL_TOKEN_ID}}", "ak-1").replace("{{secret:MODAL_TOKEN_SECRET}}", "as-1");
        BackendCtx { workspace: ws.to_path_buf(), scope_key: "s-m".into(), secrets: Arc::new(sec), home: home.to_path_buf(), sandboxed: true }
    }

    /// The bridge reads PYTHONPATH / FAKE_MODAL_* from the environment, which is
    /// process-wide: one test drives the whole lifecycle.
    #[test]
    fn bridge_lifecycle_exec_stdin_sync_snapshot() {
        if super::super::local::which("python3").is_none() {
            eprintln!("skipping: no python3");
            return;
        }
        let (d, home, ws, remote) = setup("modal");
        std::env::set_var("PYTHONPATH", d.join("py"));
        std::env::set_var("FAKE_MODAL_LOG", d.join("log"));
        std::fs::write(ws.join("in.txt"), "hi from host").unwrap();
        let v = json!({"image": "debian:12", "workspace_root": remote.display().to_string(), "timeout_secs": 99});
        let b = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        let log = || std::fs::read_to_string(d.join("log")).unwrap_or_default();
        assert!(log().contains("[\"registry\", \"debian:12\"]") && log().contains("\"create\", [\"sleep\", \"infinity\"]"), "{}", log());
        assert!(log().contains("99"), "timeout forwarded");
        b.before_exec().unwrap();
        assert_eq!(std::fs::read_to_string(remote.join("in.txt")).unwrap(), "hi from host");
        let req = ExecRequest { script: "cat in.txt; echo; echo e >&2; read l; echo got=$l; echo out > made.txt; exit 3".into(), cwd: Some(ws.clone()), stdin: true, ..Default::default() };
        let mut c = b.spawn(&req).unwrap();
        c.write_stdin(b"typed\n").unwrap();
        c.close_stdin();
        let (st, out) = crate::exec::drain(c, Duration::from_secs(20)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert_eq!(st.code, Some(3), "{s}");
        assert!(s.contains("hi from host") && s.contains("got=typed") && s.contains('e'), "{s}");
        b.after_exec().unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("made.txt")).unwrap(), "out\n");
        let (st, out) = super::super::run_capture(b.as_ref(), "wc -c", Some(&vec![b'x'; 3 * 1024 * 1024 + 5]), Duration::from_secs(30)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).trim() == "3145733", "chunked stdin: {}", String::from_utf8_lossy(&out));
        assert!(b.spawn(&ExecRequest { pty: Some((1, 1)), ..Default::default() }).is_err());
        // Kill terminates the sandbox; the next command recreates it.
        let mut k = b.spawn(&ExecRequest { script: "sleep 0.2".into(), ..Default::default() }).unwrap();
        k.kill(true);
        let _ = crate::exec::drain(k, Duration::from_secs(10));
        b.before_exec().unwrap();
        assert_eq!(log().matches("\"create\"").count(), 2, "{}", log());
        // Cleanup snapshots; the next backend restores from the snapshot.
        b.cleanup();
        assert_eq!(Record::new(&home, "modal", "s-m").get("snapshot").as_deref(), Some("im-snap1"));
        assert!(log().contains("terminate"));
        let b2 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert!(log().contains("[\"from_id\", \"im-snap1\"]"));
        // Re-attach to a still-running sandbox after a restart.
        let alive = Record::new(&home, "modal", "s-m").get("sandbox").unwrap();
        std::env::set_var("FAKE_MODAL_ALIVE", &alive);
        drop(b2);
        let b3 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert!(log().contains(&format!("[\"sandbox_from_id\", \"{alive}\"]")));
        assert_eq!(log().matches("\"create\"").count(), 3, "reused, not created");
        assert!(b3.describe().contains(&alive));
        // A bad snapshot falls back to the image and is forgotten.
        Record::new(&home, "modal", "s-m").set("snapshot", Some("im-bad"));
        Record::new(&home, "modal", "s-m").set("sandbox", None);
        let _b4 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert_eq!(Record::new(&home, "modal", "s-m").get("snapshot"), None);
        // Credentials are required.
        let mut c = ctx(&home, &ws);
        c.secrets = Arc::new(|s: &str| s.to_string());
        let no_profile = std::env::var_os("HOME").is_none_or(|h| !Path::new(&h).join(".modal.toml").exists());
        if no_profile && std::env::var_os("MODAL_TOKEN_ID").is_none() {
            assert!(build(&v, &ExecConfig::default(), &c).err().unwrap().contains("no credentials"));
        }
    }

    /// `[exec] backend = "modal"` → `ExecEnv::backend` → spawn (the user-reachable path).
    /// The fake SDK gets its log path baked into the package and a wrapper `python`
    /// that sets `PYTHONPATH` itself, so this test needs no process-wide env.
    #[test]
    fn reachable_through_exec_backend_config() {
        if super::super::local::which("python3").is_none() {
            eprintln!("skipping: no python3");
            return;
        }
        let d = tmpdir("modalreach");
        let (home, ws, remote) = (d.join("home"), d.join("ws"), d.join("remote"));
        for p in [&home, &ws, &remote] {
            std::fs::create_dir_all(p).unwrap();
        }
        let log = d.join("log");
        let pkg = d.join("py/modal");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("__init__.py"), FAKE_MODAL.replace("os.environ[\"FAKE_MODAL_LOG\"]", &format!("{log:?}"))).unwrap();
        let py = d.join("python3");
        std::fs::write(&py, format!("#!/bin/sh\nPYTHONPATH={} exec python3 \"$@\"\n", d.join("py").display())).unwrap();
        std::fs::set_permissions(&py, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.replace("{{secret:MODAL_TOKEN_ID}}", "ak-1").replace("{{secret:MODAL_TOKEN_SECRET}}", "as-1"));
        let env = crate::exec::ExecEnv::new(ExecConfig {
            backend: "modal".into(),
            modal: json!({"python": py.display().to_string(), "image": "debian:12", "workspace_root": remote.display().to_string(), "persistent": false}),
            ..Default::default()
        });
        let b = env.backend("m1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "modal");
        assert!(b.describe().contains("Modal sandbox"), "{}", b.describe());
        b.before_exec().unwrap();
        let (st, out) = crate::exec::run_capture(b.as_ref(), "echo from-modal", None, Duration::from_secs(30)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("from-modal"), "{}", String::from_utf8_lossy(&out));
        let log = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(log.contains("\"create\"") && log.contains("debian:12"), "the SDK bridge really ran: {log}");
    }
}
