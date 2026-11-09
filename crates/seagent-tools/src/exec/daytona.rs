//! Daytona cloud sandbox backend (Hermes tools/environments/daytona.py), over
//! the Daytona REST API instead of the Python SDK: one sandbox per sandbox
//! scope (`seagent-<scope>`), resumed across seagent restarts, stopped (persistent) or
//! deleted on cleanup. Commands run in toolbox process *sessions* so output
//! streams while they run and stdin can be fed; the workspace is mirrored
//! with `sync::WorkspaceSync`.

use super::sync::common::{self, Api, Ev, Record, RemoteChild};
use super::sync::{self, SyncOptions, WorkspaceSync};
use super::{BackendCtx, ExecConfig};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `[exec.daytona]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaytonaConfig {
    pub api_url: String,
    /// Toolbox base; `{id}` is replaced by the sandbox id. Empty = `<api_url>/toolbox/{id}/toolbox`.
    pub toolbox_url: String,
    /// Vault secret (or env var) with the API key.
    pub api_key_secret: String,
    /// Container image (built through a one-line Dockerfile) unless `snapshot` is set.
    pub image: String,
    pub snapshot: String,
    /// Region / runner target (optional).
    pub target: String,
    pub cpu: u32,
    pub memory_mb: u64,
    /// Capped at 10 GiB (platform limit, as Hermes does).
    pub disk_mb: u64,
    /// Keep the sandbox (stopped) after cleanup and resume it next time.
    pub persistent: bool,
    /// Minutes of inactivity before Daytona auto-stops it (0 = never).
    pub auto_stop_minutes: u64,
    /// Remote workspace root; empty = `$HOME/workspace`.
    pub workspace_root: String,
    /// Seconds to wait for the sandbox to reach `started`.
    pub start_timeout: u64,
    /// Log polling interval (ms).
    pub poll_ms: u64,
}

impl Default for DaytonaConfig {
    fn default() -> Self {
        DaytonaConfig {
            api_url: "https://app.daytona.io/api".into(),
            toolbox_url: String::new(),
            api_key_secret: "DAYTONA_API_KEY".into(),
            image: "nousresearch/hermes-sandbox:desktop".into(),
            snapshot: String::new(),
            target: String::new(),
            cpu: 1,
            memory_mb: 5120,
            disk_mb: 10240,
            persistent: true,
            auto_stop_minutes: 0,
            workspace_root: String::new(),
            start_timeout: 180,
            poll_ms: 250,
        }
    }
}

pub fn build(v: &Value, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    let dc: DaytonaConfig = if v.is_null() { DaytonaConfig::default() } else { serde_json::from_value(v.clone()).map_err(|e| format!("[exec.daytona]: {e}"))? };
    Ok(Arc::new(DaytonaBackend::new(dc, cfg, ctx)?))
}

static SEQ: AtomicU64 = AtomicU64::new(0);

pub struct DaytonaBackend {
    cfg: DaytonaConfig,
    api: Api,
    id: Mutex<String>,
    record: Record,
    host_ws: PathBuf,
    remote_root: String,
    sync: WorkspaceSync,
    creds: Vec<String>,
    creds_done: AtomicBool,
    passthrough: Vec<String>,
    gone: AtomicBool,
}

fn state_of(v: &Value) -> String {
    v.get("state").and_then(|s| s.as_str()).unwrap_or("").to_ascii_lowercase()
}

impl DaytonaBackend {
    pub fn new(cfg: DaytonaConfig, ecfg: &ExecConfig, ctx: &BackendCtx) -> Result<DaytonaBackend, String> {
        let key = ctx.secret(&cfg.api_key_secret).ok_or_else(|| format!("exec backend daytona: no API key (store it with `seagent secrets set {}`)", cfg.api_key_secret))?;
        let mut headers = vec![("authorization".into(), format!("Bearer {key}"))];
        if !cfg.target.is_empty() {
            headers.push(("x-daytona-target".into(), cfg.target.clone()));
        }
        let api = Api::new(&cfg.api_url, headers);
        let record = Record::new(&ctx.home, "daytona", &ctx.scope_key);
        let name = format!("seagent-{}", super::sanitize(&ctx.scope_key));
        let mut me = DaytonaBackend {
            api,
            id: Mutex::new(String::new()),
            record,
            host_ws: ctx.workspace.clone(),
            remote_root: String::new(),
            sync: WorkspaceSync::new(&ctx.workspace, "/", SyncOptions::default()),
            creds: ecfg.credential_files.clone(),
            creds_done: AtomicBool::new(false),
            passthrough: ecfg.passthrough(),
            gone: AtomicBool::new(false),
            cfg,
        };
        let id = me.attach(&name, &ctx.scope_key)?;
        *me.id.lock().unwrap() = id;
        let home = me.exec_simple("printf %s \"$HOME\"").ok().map(|s| s.trim().to_string()).filter(|h| h.starts_with('/')).unwrap_or_else(|| "/home/daytona".into());
        me.remote_root = if me.cfg.workspace_root.is_empty() { format!("{home}/workspace") } else { me.cfg.workspace_root.clone() };
        me.sync = WorkspaceSync::new(&ctx.workspace, &me.remote_root, SyncOptions::default());
        Ok(me)
    }

    fn tb(&self, id: &str) -> String {
        if self.cfg.toolbox_url.is_empty() {
            format!("/toolbox/{id}/toolbox")
        } else {
            self.cfg.toolbox_url.replace("{id}", id)
        }
    }
    fn sid(&self) -> String {
        self.id.lock().unwrap().clone()
    }

    /// Resume the recorded / named sandbox, else create one.
    fn attach(&self, name: &str, scope: &str) -> Result<String, String> {
        if self.cfg.persistent {
            for candidate in [self.record.get("id"), Some(name.to_string())].into_iter().flatten() {
                if let Ok(sb) = self.api.json("GET", &format!("/sandbox/{}", common::qenc(&candidate)), None) {
                    let id = sb.get("id").and_then(|v| v.as_str()).unwrap_or(&candidate).to_string();
                    if state_of(&sb) == "error" || state_of(&sb) == "destroyed" {
                        continue;
                    }
                    self.ensure_started(&id, &sb)?;
                    self.record.set("id", Some(&id));
                    return Ok(id);
                }
            }
        }
        let gib = |mb: u64| mb.div_ceil(1024).max(1);
        let mut body = json!({
            "name": name,
            "labels": {"seagent_scope": scope},
            "autoStopInterval": self.cfg.auto_stop_minutes,
            "cpu": self.cfg.cpu,
            "memory": gib(self.cfg.memory_mb),
            "disk": gib(self.cfg.disk_mb).min(10),
        });
        if !self.cfg.snapshot.is_empty() {
            body["snapshot"] = json!(self.cfg.snapshot);
        } else {
            body["buildInfo"] = json!({"dockerfileContent": format!("FROM {}\n", self.cfg.image)});
        }
        if !self.cfg.target.is_empty() {
            body["target"] = json!(self.cfg.target);
        }
        let sb = self.api.json("POST", "/sandbox", Some(&body)).map_err(|e| format!("daytona: create sandbox: {e}"))?;
        let id = sb.get("id").and_then(|v| v.as_str()).ok_or("daytona: create sandbox returned no id")?.to_string();
        self.record.set("id", Some(&id));
        self.ensure_started(&id, &sb)?;
        Ok(id)
    }

    /// Start a stopped/archived sandbox and wait until it reports `started`.
    fn ensure_started(&self, id: &str, current: &Value) -> Result<(), String> {
        let mut st = state_of(current);
        if st == "started" {
            return Ok(());
        }
        if matches!(st.as_str(), "stopped" | "archived") {
            self.api.json("POST", &format!("/sandbox/{id}/start"), None).map_err(|e| format!("daytona: start sandbox: {e}"))?;
        }
        let deadline = Instant::now() + Duration::from_secs(self.cfg.start_timeout);
        while st != "started" {
            if Instant::now() > deadline {
                return Err(format!("daytona: sandbox {id} did not start (last state `{st}`)"));
            }
            if st == "error" || st == "build_failed" {
                return Err(format!("daytona: sandbox {id} entered state `{st}`"));
            }
            std::thread::sleep(Duration::from_millis(self.cfg.poll_ms.max(10)));
            st = state_of(&self.api.json("GET", &format!("/sandbox/{id}"), None)?);
        }
        Ok(())
    }

    /// Synchronous toolbox execute (setup probes only).
    fn exec_simple(&self, script: &str) -> Result<String, String> {
        let id = self.sid();
        let cmd = format!("bash -c \"$(printf %s {} | base64 -d)\"", common::b64(script.as_bytes()));
        let r = self.api.json("POST", &format!("{}/process/execute", self.tb(&id)), Some(&json!({"command": cmd, "timeout": 60})))?;
        Ok(r.get("result").and_then(|v| v.as_str()).unwrap_or("").to_string())
    }

    fn upload(&self, remote: &str, data: &[u8]) -> Result<(), String> {
        let id = self.sid();
        let (ct, body) = common::multipart_file("file", "upload", data);
        let (s, out) = self.api.raw("POST", &format!("{}/files/upload?path={}", self.tb(&id), common::qenc(remote)), Some((&ct, &body)))?;
        if !(200..300).contains(&s) {
            return Err(format!("daytona: upload {remote}: HTTP {s}: {}", String::from_utf8_lossy(&out)));
        }
        Ok(())
    }

    fn runner(&self) -> impl Fn(&str, Option<&[u8]>) -> Result<super::Capture, String> + '_ {
        move |script: &str, stdin: Option<&[u8]>| super::run_capture(self, script, stdin, Duration::from_secs(600))
    }
}

impl ExecBackend for DaytonaBackend {
    fn id(&self) -> &str {
        "daytona"
    }
    fn describe(&self) -> String {
        format!("daytona: Daytona cloud sandbox {} ({}); workspace mirrored to {}", self.sid(), if self.cfg.snapshot.is_empty() { &self.cfg.image } else { &self.cfg.snapshot }, self.remote_root)
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let err = |e: String| io::Error::other(e);
        if req.pty.is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "the daytona backend has no pseudo-terminals; run without pty"));
        }
        let id = self.sid();
        let tb = self.tb(&id);
        let mut script = common::env_prefix(&req.env, &self.passthrough);
        if let Some(c) = &req.cwd {
            script.push_str(&format!("cd {} || exit 126\n", super::sh_quote(&self.map_path(c))));
        }
        script.push_str(&req.script);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut cmd = format!("bash {}-c \"$(printf %s {} | base64 -d)\"", if req.login { "-l " } else { "" }, common::b64(script.as_bytes()));
        if let Some(d) = &req.stdin_data {
            // Staged file: the toolbox cannot close a command's stdin (Hermes stages it too).
            let staged = super::stdin_staging("daytona");
            self.upload(&staged, d).map_err(err)?;
            cmd = format!("{cmd} < {staged}; s=$?; rm -f {staged}; exit $s");
        }
        let session = format!("seagent-{}-{n}", std::process::id());
        self.api.json("POST", &format!("{tb}/process/session"), Some(&json!({"sessionId": session}))).map_err(err)?;
        let r = self.api.json("POST", &format!("{tb}/process/session/{session}/exec"), Some(&json!({"command": cmd, "runAsync": true}))).map_err(err)?;
        let cmd_id = r.get("cmdId").or_else(|| r.get("cmd_id")).and_then(|v| v.as_str()).ok_or_else(|| err("daytona: exec returned no cmdId".into()))?.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let api = self.api.clone();
        let base = format!("{tb}/process/session/{session}");
        let poll = Duration::from_millis(self.cfg.poll_ms.max(10));
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let (b2, c2) = (base.clone(), cmd_id.clone());
        std::thread::spawn(move || {
            let mut seen = 0usize;
            let logs = |api: &Api| -> Result<Vec<u8>, String> {
                let (s, raw) = api.raw("GET", &format!("{b2}/command/{c2}/logs"), None)?;
                if !(200..300).contains(&s) {
                    return Err(format!("HTTP {s}"));
                }
                // Newer API: {"stdout","stderr","output"}; older: plain text.
                Ok(match serde_json::from_slice::<Value>(&raw) {
                    Ok(Value::Object(o)) => o.get("output").and_then(|v| v.as_str()).map(|s| s.as_bytes().to_vec()).unwrap_or_else(|| {
                        let mut v = o.get("stdout").and_then(|v| v.as_str()).unwrap_or("").as_bytes().to_vec();
                        v.extend_from_slice(o.get("stderr").and_then(|v| v.as_str()).unwrap_or("").as_bytes());
                        v
                    }),
                    _ => raw,
                })
            };
            loop {
                let status = api.json("GET", &format!("{b2}/command/{c2}"), None);
                let out = logs(&api).unwrap_or_default();
                if out.len() > seen {
                    if tx.send(Ev::Out(out[seen..].to_vec())).is_err() {
                        break;
                    }
                    seen = out.len();
                }
                match status {
                    Ok(v) => {
                        if let Some(code) = v.get("exitCode").and_then(|c| c.as_i64()) {
                            let _ = tx.send(Ev::Exit(ExitInfo::code(code as i32)));
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Ev::Out(format!("\n[daytona: lost the command: {e}]\n").into_bytes()));
                        let _ = tx.send(Ev::Exit(ExitInfo { code: None, signal: None }));
                        break;
                    }
                }
                if stop2.load(Ordering::SeqCst) {
                    let _ = tx.send(Ev::Exit(ExitInfo { code: None, signal: Some(9) }));
                    break;
                }
                std::thread::sleep(poll);
            }
            let _ = api.raw("DELETE", &b2, None);
        });
        let (api_in, bi, ci) = (self.api.clone(), base.clone(), cmd_id.clone());
        let stdin: Option<common::StdinFn> = req.stdin.then(|| {
            Box::new(move |data: &[u8]| -> io::Result<()> {
                api_in.json("POST", &format!("{bi}/command/{ci}/input"), Some(&json!({"data": String::from_utf8_lossy(data)}))).map(|_| ()).map_err(io::Error::other)
            }) as common::StdinFn
        });
        let api_k = self.api.clone();
        let killer: common::KillFn = Box::new(move |_force| {
            // Deleting the session terminates its processes.
            let _ = api_k.raw("DELETE", &base, None);
            stop.store(true, Ordering::SeqCst);
        });
        Ok(Box::new(RemoteChild::new(rx, stdin, None, Some(killer), "start the command with stdin=true to write to it")))
    }
    fn map_path(&self, host: &Path) -> String {
        common::map_under(&self.host_ws, &self.remote_root, host)
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        false
    }
    fn before_exec(&self) -> Result<(), String> {
        let id = self.sid();
        let sb = self.api.json("GET", &format!("/sandbox/{id}"), None)?;
        if state_of(&sb) != "started" {
            self.ensure_started(&id, &sb)?;
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
        let id = self.sid();
        if self.cfg.persistent {
            let _ = self.api.json("POST", &format!("/sandbox/{id}/stop"), None);
        } else {
            let _ = self.api.raw("DELETE", &format!("/sandbox/{id}?force=true"), None);
            self.record.set("id", None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sync::common::fake::{self, ok, Req};
    use crate::testutil::tmpdir;
    use std::collections::HashMap;

    /// Fake Daytona: sandboxes in memory, session commands really run locally.
    /// Session id → (buffered output, exit code) of the fake's running commands.
    type CmdBufs = Mutex<HashMap<String, Arc<Mutex<(Vec<u8>, Option<i32>)>>>>;

    struct Fake {
        state: Mutex<String>,
        created: AtomicBool,
        cmds: CmdBufs,
        files: Mutex<HashMap<String, Vec<u8>>>,
        home: PathBuf,
    }

    fn handler(f: Arc<Fake>) -> fake::Handler {
        Arc::new(move |r: &Req| {
            assert_eq!(r.header("authorization"), Some("Bearer dt-key"), "{} {}", r.method, r.path);
            let p = r.path.as_str();
            match (r.method.as_str(), p) {
                ("GET", "/sandbox/seagent-s-1") | ("GET", "/sandbox/sb-1") if f.created.load(Ordering::SeqCst) => {
                    let mut st = f.state.lock().unwrap();
                    if *st == "starting" {
                        *st = "started".into(); // finished booting
                    }
                    ok(json!({"id":"sb-1","state": *st}))
                }
                ("GET", _) if p.starts_with("/sandbox/") && !p.contains("toolbox") => (404, b"{\"message\":\"not found\"}".to_vec()),
                ("POST", "/sandbox") => {
                    let b = r.json();
                    assert!(b["name"].as_str().unwrap().starts_with("seagent-"), "sandbox name: {}", b["name"]);
                    assert_eq!(b["disk"], 10, "capped");
                    assert_eq!(b["buildInfo"]["dockerfileContent"], "FROM img:1\n");
                    f.created.store(true, Ordering::SeqCst);
                    *f.state.lock().unwrap() = "starting".into();
                    ok(json!({"id":"sb-1","state":"starting"}))
                }
                ("POST", "/sandbox/sb-1/start") => {
                    *f.state.lock().unwrap() = "started".into();
                    ok(json!({}))
                }
                ("POST", "/sandbox/sb-1/stop") => {
                    *f.state.lock().unwrap() = "stopped".into();
                    ok(json!({}))
                }
                ("DELETE", p) if p.starts_with("/sandbox/sb-1") && !p.contains("toolbox") => ok(json!({})),
                ("POST", "/toolbox/sb-1/toolbox/process/execute") => {
                    let cmd = r.json()["command"].as_str().unwrap().to_string();
                    let o = crate::testutil::remote_bash().arg("-c").arg(&cmd).env("HOME", crate::testutil::remote_path(&f.home)).output().unwrap();
                    ok(json!({"exitCode": o.status.code(), "result": String::from_utf8_lossy(&o.stdout)}))
                }
                ("POST", p) if p.starts_with("/toolbox/sb-1/toolbox/files/upload?path=") => {
                    let path = p.split("path=").nth(1).unwrap().replace("%2F", "/");
                    let body = &r.body;
                    let start = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let data = &body[start..];
                    let tail = data.windows(4).rposition(|w| w == b"\r\n--").unwrap();
                    std::fs::write(crate::testutil::local_of_remote(&path), &data[..tail]).unwrap();
                    f.files.lock().unwrap().insert(path, data[..tail].to_vec());
                    ok(json!({}))
                }
                ("POST", "/toolbox/sb-1/toolbox/process/session") => ok(json!({})),
                ("POST", p) if p.ends_with("/exec") => {
                    let b = r.json();
                    assert_eq!(b["runAsync"], true);
                    let id = format!("c{}", f.cmds.lock().unwrap().len());
                    let slot = Arc::new(Mutex::new((Vec::new(), None)));
                    f.cmds.lock().unwrap().insert(id.clone(), slot.clone());
                    let (cmd, home) = (b["command"].as_str().unwrap().to_string(), f.home.clone());
                    std::thread::spawn(move || {
                        let o = crate::testutil::remote_bash().arg("-c").arg(&cmd).env("HOME", crate::testutil::remote_path(&home)).output().unwrap();
                        let mut s = slot.lock().unwrap();
                        s.0.extend_from_slice(&o.stdout);
                        s.0.extend_from_slice(&o.stderr);
                        s.1 = o.status.code();
                    });
                    ok(json!({"cmdId": id}))
                }
                ("GET", p) if p.ends_with("/logs") => {
                    let id = p.rsplit('/').nth(1).unwrap();
                    let s = f.cmds.lock().unwrap()[id].clone();
                    let out = s.lock().unwrap().0.clone();
                    (200, out)
                }
                ("GET", p) if p.contains("/command/") => {
                    let id = p.rsplit('/').next().unwrap();
                    let s = f.cmds.lock().unwrap()[id].clone();
                    let code = s.lock().unwrap().1;
                    ok(json!({"id": id, "exitCode": code}))
                }
                ("DELETE", p) if p.contains("/process/session/") => ok(json!({})),
                _ => (500, format!("unexpected {} {}", r.method, r.path).into_bytes()),
            }
        })
    }

    fn ctx(home: &Path, ws: &Path) -> BackendCtx {
        BackendCtx { workspace: ws.to_path_buf(), scope_key: "s-1".into(), secrets: Arc::new(|s: &str| s.replace("{{secret:DAYTONA_API_KEY}}", "dt-key")), home: home.to_path_buf(), sandboxed: true }
    }

    #[test]
    fn create_exec_stream_sync_and_cleanup() {
        let rhome = tmpdir("dtremotehome");
        let f = Arc::new(Fake { state: Mutex::new(String::new()), created: AtomicBool::new(false), cmds: Default::default(), files: Default::default(), home: rhome.clone() });
        let srv = fake::serve(handler(f.clone()));
        let (home, ws) = (tmpdir("dthome"), tmpdir("dtws"));
        std::fs::write(ws.join("in.txt"), "from host").unwrap();
        let v = json!({"api_url": srv.url, "image": "img:1", "disk_mb": 50000, "poll_ms": 10});
        let b = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert!(srv.paths().contains(&"POST /sandbox".to_string()));
        assert_eq!(f.state.lock().unwrap().as_str(), "started");
        assert_eq!(b.map_path(&ws.join("a/b")), format!("{}/workspace/a/b", crate::testutil::remote_path(&rhome)));
        assert!(!b.shares_host_fs() && !b.supports_pty());
        b.before_exec().unwrap();
        assert_eq!(std::fs::read_to_string(rhome.join("workspace/in.txt")).unwrap(), "from host");
        let req = ExecRequest { script: "cat in.txt; echo; echo made > out.txt; echo err >&2; exit 5".into(), cwd: Some(ws.clone()), env: vec![("GREETING".into(), "hi".into()), ("SECRET_TOKEN".into(), "x".into())], ..Default::default() };
        let (st, out) = crate::exec::drain(b.spawn(&req).unwrap(), Duration::from_secs(20)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert_eq!(st.code, Some(5));
        assert!(s.contains("from host") && s.contains("err"), "{s}");
        let decode = |r: &Req| {
            let cmd = r.json()["command"].as_str().unwrap_or("").to_string();
            let b64 = cmd.split("printf %s ").nth(1).unwrap_or("").split(' ').next().unwrap_or("").to_string();
            String::from_utf8(common::unb64(b64.as_bytes()).unwrap_or_default()).unwrap_or_default()
        };
        let exec = srv.find(|r| r.path.ends_with("/exec") && decode(r).contains("cat in.txt")).unwrap();
        let script = decode(&exec);
        assert!(script.contains("export GREETING=hi") && !script.contains("SECRET_TOKEN"), "credentials never forwarded: {script}");
        b.after_exec().unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("out.txt")).unwrap(), "made\n", "pulled back");
        // stdin_data is staged through the files API.
        let (st, out) = super::super::run_capture(b.as_ref(), "tr a-z A-Z", Some(b"quiet"), Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("QUIET"));
        assert!(srv.paths().iter().any(|p| p.contains("/files/upload?path=/tmp/.seagent-stdin-")));
        assert!(b.spawn(&ExecRequest { pty: Some((1, 1)), ..Default::default() }).is_err());
        // Persistent: stop, record kept, and a new backend resumes the same sandbox.
        b.cleanup();
        assert_eq!(f.state.lock().unwrap().as_str(), "stopped");
        assert_eq!(Record::new(&home, "daytona", "s-1").get("id").as_deref(), Some("sb-1"));
        let n_create = srv.paths().iter().filter(|p| *p == "POST /sandbox").count();
        let b2 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert_eq!(srv.paths().iter().filter(|p| *p == "POST /sandbox").count(), n_create, "resumed, not recreated");
        assert_eq!(f.state.lock().unwrap().as_str(), "started");
        // Non-persistent deletes.
        let v2 = json!({"api_url": srv.url, "image": "img:1", "persistent": false, "poll_ms": 10});
        let b3 = build(&v2, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        b3.cleanup();
        assert!(srv.paths().iter().any(|p| p.starts_with("DELETE /sandbox/sb-1")));
        assert_eq!(Record::new(&home, "daytona", "s-1").get("id"), None);
        drop(b2);
    }

    #[test]
    fn reachable_through_exec_backend_config() {
        // `[exec] backend = "daytona"` → `ExecEnv::backend` → spawn: the user-reachable
        // path (build_backend + install in the binary) end to end, against the fake API.
        let rhome = tmpdir("dtremotehome2");
        let f = Arc::new(Fake { state: Mutex::new(String::new()), created: AtomicBool::new(false), cmds: Default::default(), files: Default::default(), home: rhome.clone() });
        let srv = fake::serve(handler(f.clone()));
        let (home, ws) = (tmpdir("dthome2"), tmpdir("dtws2"));
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.replace("{{secret:DAYTONA_API_KEY}}", "dt-key"));
        let env = crate::exec::ExecEnv::new(ExecConfig {
            backend: "daytona".into(),
            daytona: json!({"api_url": srv.url, "image": "img:1", "poll_ms": 10}),
            ..Default::default()
        });
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "daytona");
        assert!(b.describe().contains("Daytona"), "{}", b.describe());
        b.before_exec().unwrap();
        let (st, out) = crate::exec::run_capture(b.as_ref(), "echo from-daytona", None, Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("from-daytona"), "{}", String::from_utf8_lossy(&out));
        assert!(!srv.paths().is_empty(), "the backend really talked to the API");
    }

    #[test]
    fn missing_key_and_bad_config() {
        let d = tmpdir("dtnokey");
        let mut c = ctx(&d, &d);
        c.secrets = Arc::new(|s: &str| s.to_string());
        std::env::remove_var("DAYTONA_API_KEY_ARK_TEST");
        let e = build(&json!({"api_key_secret":"DAYTONA_API_KEY_ARK_TEST"}), &ExecConfig::default(), &c).err().unwrap();
        assert!(e.contains("no API key"), "{e}");
        assert!(build(&json!({"bogus": 1}), &ExecConfig::default(), &c).is_err());
    }
}
