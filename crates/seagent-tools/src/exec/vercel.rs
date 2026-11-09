//! Vercel Sandbox backend (Hermes tools/environments/vercel_sandbox.py) over
//! the Vercel Sandbox REST API: create (from a stored snapshot when the scope
//! has one), detached commands with streamed NDJSON logs, kill, file writes
//! (gzipped tar), snapshot + stop on cleanup. A running sandbox is reused
//! across seagent restarts until Vercel times it out.

use super::sync::common::{self, Api, Ev, Record, RemoteChild};
use super::sync::{self, SyncOptions, Tar, WorkspaceSync};
use super::{BackendCtx, ExecConfig};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_CWD: &str = "/vercel/sandbox";

/// `[exec.vercel]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VercelConfig {
    pub api_url: String,
    pub token_secret: String,
    /// Vault secret / env var with the team id (`teamId` query), optional.
    pub team_id_secret: String,
    pub project_id_secret: String,
    /// Managed or registry image; ignored when the deprecated `runtime` is set.
    pub image: String,
    /// Deprecated by Vercel (node24 | node22 | python3.13); overrides `image`.
    pub runtime: String,
    pub vcpus: u32,
    /// Sandbox lifetime in seconds (minimum 300, as Hermes enforces).
    pub timeout_secs: u64,
    /// Snapshot on cleanup and restore from it next time.
    pub persistent: bool,
    pub start_timeout: u64,
}

impl Default for VercelConfig {
    fn default() -> Self {
        VercelConfig {
            api_url: "https://api.vercel.com".into(),
            token_secret: "VERCEL_TOKEN".into(),
            team_id_secret: "VERCEL_TEAM_ID".into(),
            project_id_secret: "VERCEL_PROJECT_ID".into(),
            image: "vercel/sandbox/universal:latest".into(),
            runtime: String::new(),
            vcpus: 1,
            timeout_secs: 3600,
            persistent: true,
            start_timeout: 30,
        }
    }
}

pub fn build(v: &Value, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    let vc: VercelConfig = if v.is_null() { VercelConfig::default() } else { serde_json::from_value(v.clone()).map_err(|e| format!("[exec.vercel]: {e}"))? };
    Ok(Arc::new(VercelBackend::new(vc, cfg, ctx)?))
}

pub struct VercelBackend {
    cfg: VercelConfig,
    api: Api,
    project: Option<String>,
    id: Mutex<String>,
    root: Mutex<String>,
    record: Record,
    host_ws: PathBuf,
    sync: Mutex<Arc<WorkspaceSync>>,
    creds: Vec<String>,
    creds_done: AtomicBool,
    passthrough: Vec<String>,
    gone: AtomicBool,
}

fn status_of(v: &Value) -> String {
    v.get("sandbox").unwrap_or(v).get("status").and_then(|s| s.as_str()).unwrap_or("").to_string()
}
fn terminal(s: &str) -> bool {
    matches!(s, "stopped" | "failed" | "aborted" | "stopping")
}

impl VercelBackend {
    pub fn new(cfg: VercelConfig, ecfg: &ExecConfig, ctx: &BackendCtx) -> Result<VercelBackend, String> {
        let token = ctx.secret(&cfg.token_secret).ok_or_else(|| format!("exec backend vercel: no token (store it with `seagent secrets set {}`)", cfg.token_secret))?;
        let mut api = Api::new(&cfg.api_url, vec![("authorization".into(), format!("Bearer {token}"))]);
        if let Some(team) = ctx.secret(&cfg.team_id_secret) {
            api.query = format!("teamId={}", common::qenc(&team));
        }
        let me = VercelBackend {
            api,
            project: ctx.secret(&cfg.project_id_secret),
            id: Mutex::new(String::new()),
            root: Mutex::new(DEFAULT_CWD.into()),
            record: Record::new(&ctx.home, "vercel", &ctx.scope_key),
            host_ws: ctx.workspace.clone(),
            sync: Mutex::new(Arc::new(WorkspaceSync::new(&ctx.workspace, DEFAULT_CWD, SyncOptions::default()))),
            creds: ecfg.credential_files.clone(),
            creds_done: AtomicBool::new(false),
            passthrough: ecfg.passthrough(),
            gone: AtomicBool::new(false),
            cfg,
        };
        me.attach()?;
        Ok(me)
    }

    fn sid(&self) -> String {
        self.id.lock().unwrap().clone()
    }

    fn create(&self, snapshot: Option<&str>) -> Result<Value, String> {
        let mut body = json!({"timeout": self.cfg.timeout_secs.max(300) * 1000, "resources": {"vcpus": self.cfg.vcpus.max(1)}});
        if let Some(p) = &self.project {
            body["projectId"] = json!(p);
        }
        match snapshot {
            // A snapshot carries its own filesystem: no runtime/image with it.
            Some(s) => body["source"] = json!({"type": "snapshot", "snapshotId": s}),
            None if !self.cfg.runtime.is_empty() => body["runtime"] = json!(self.cfg.runtime),
            None => body["image"] = json!(self.cfg.image),
        }
        self.api.json("POST", "/v1/sandboxes", Some(&body))
    }

    /// Reuse the recorded running sandbox, else restore the snapshot, else create fresh.
    fn attach(&self) -> Result<(), String> {
        if let Some(id) = self.record.get("id") {
            if let Ok(v) = self.api.json("GET", &format!("/v1/sandboxes/{id}"), None) {
                if !terminal(&status_of(&v)) {
                    return self.adopt(&v);
                }
            }
            self.record.set("id", None);
        }
        let snap = if self.cfg.persistent { self.record.get("snapshot") } else { None };
        let v = match snap {
            Some(s) => match self.create(Some(&s)) {
                Ok(v) => v,
                Err(_) => {
                    // Hermes: a failed restore drops the stale id and falls back to a fresh sandbox.
                    self.record.set("snapshot", None);
                    self.create(None).map_err(|e| format!("vercel: create sandbox: {e}"))?
                }
            },
            None => self.create(None).map_err(|e| format!("vercel: create sandbox: {e}"))?,
        };
        self.adopt(&v)
    }

    fn adopt(&self, v: &Value) -> Result<(), String> {
        let sb = v.get("sandbox").unwrap_or(v);
        let id = sb.get("id").and_then(|s| s.as_str()).ok_or("vercel: sandbox response has no id")?.to_string();
        let cwd = sb.get("cwd").and_then(|s| s.as_str()).filter(|c| c.starts_with('/')).unwrap_or(DEFAULT_CWD).to_string();
        *self.id.lock().unwrap() = id.clone();
        self.record.set("id", Some(&id));
        if *self.root.lock().unwrap() != cwd || self.sync.lock().unwrap().remote_root() != cwd {
            *self.sync.lock().unwrap() = Arc::new(WorkspaceSync::new(&self.host_ws, &cwd, SyncOptions::default()));
        }
        *self.root.lock().unwrap() = cwd;
        self.wait_running(status_of(v))
    }

    fn wait_running(&self, mut st: String) -> Result<(), String> {
        let id = self.sid();
        let deadline = Instant::now() + Duration::from_secs(self.cfg.start_timeout.max(1));
        while !st.is_empty() && st != "running" {
            if terminal(&st) {
                return Err(format!("vercel: sandbox {id} entered terminal state `{st}`"));
            }
            if Instant::now() > deadline {
                return Err(format!("vercel: sandbox {id} did not reach running state (last status: {st})"));
            }
            std::thread::sleep(Duration::from_millis(250));
            st = status_of(&self.api.json("GET", &format!("/v1/sandboxes/{id}"), None)?);
        }
        Ok(())
    }

    /// Write files into the sandbox (gzipped tar, absolute paths).
    fn write_files(&self, files: &[(&str, &[u8])]) -> Result<(), String> {
        let mut t = Tar::default();
        for (p, d) in files {
            t.file(p.trim_start_matches('/'), d, 0o600, 0);
        }
        let gz = common::gzip_stored(&t.finish());
        let mut api = self.api.clone();
        api.headers.push(("x-cwd".into(), "/".into()));
        let (s, out) = api.raw("POST", &format!("/v1/sandboxes/{}/fs/write", self.sid()), Some(("application/gzip", &gz)))?;
        if !(200..300).contains(&s) {
            return Err(format!("vercel: write files: HTTP {s}: {}", String::from_utf8_lossy(&out)));
        }
        Ok(())
    }

    fn runner(&self) -> impl Fn(&str, Option<&[u8]>) -> Result<super::Capture, String> + '_ {
        move |script: &str, stdin: Option<&[u8]>| super::run_capture(self, script, stdin, Duration::from_secs(600))
    }
}

impl ExecBackend for VercelBackend {
    fn id(&self) -> &str {
        "vercel"
    }
    fn describe(&self) -> String {
        format!("vercel: Vercel Sandbox {} ({}); workspace mirrored to {}", self.sid(), if self.cfg.runtime.is_empty() { &self.cfg.image } else { &self.cfg.runtime }, self.root.lock().unwrap())
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        if req.pty.is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "the vercel backend has no pseudo-terminals; run without pty"));
        }
        let id = self.sid();
        let mut script = common::env_prefix(&req.env, &self.passthrough);
        if let Some(d) = &req.stdin_data {
            // No stdin API: stage the payload and redirect (Hermes does the same).
            let staged = super::stdin_staging("vercel");
            self.write_files(&[(&staged, d)]).map_err(io::Error::other)?;
            script.push_str(&format!("exec < {staged}; rm -f {staged}\n"));
        }
        script.push_str(&req.script);
        let cwd = req.cwd.as_ref().map(|c| self.map_path(c)).unwrap_or_else(|| self.root.lock().unwrap().clone());
        let body = json!({"command": "bash", "args": [if req.login { "-lc" } else { "-c" }, script], "cwd": cwd});
        let r = self.api.json("POST", &format!("/v1/sandboxes/{id}/cmd"), Some(&body)).map_err(io::Error::other)?;
        let cmd = r.get("command").and_then(|c| c.get("id")).and_then(|v| v.as_str()).ok_or_else(|| io::Error::other("vercel: run command returned no id"))?.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let api = self.api.clone();
        let base = format!("/v1/sandboxes/{id}/cmd/{cmd}");
        let b2 = base.clone();
        std::thread::spawn(move || {
            match api.stream(&format!("{b2}/logs")) {
                Ok(r) => {
                    for line in BufReader::new(r).lines() {
                        let Ok(line) = line else { break };
                        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                        if let Some(d) = v.get("data").and_then(|d| d.as_str()) {
                            if tx.send(Ev::Out(d.as_bytes().to_vec())).is_err() {
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Ev::Out(format!("[vercel: log stream failed: {e}]\n").into_bytes()));
                }
            }
            let exit = api.json("GET", &format!("{b2}?wait=true"), None).ok().and_then(|v| v.get("command").and_then(|c| c.get("exitCode")).and_then(|c| c.as_i64()));
            let _ = tx.send(Ev::Exit(exit.map(|c| ExitInfo::code(c as i32)).unwrap_or(ExitInfo { code: None, signal: None })));
        });
        let api_k = self.api.clone();
        let killer: common::KillFn = Box::new(move |force| {
            let _ = api_k.json("POST", &format!("{base}/kill"), Some(&json!({"signal": if force { 9 } else { 15 }})));
        });
        Ok(Box::new(RemoteChild::new(rx, None, None, Some(killer), "the vercel backend cannot write to a running command's stdin (no stdin API); pass input with the command instead")))
    }
    fn map_path(&self, host: &Path) -> String {
        common::map_under(&self.host_ws, &self.root.lock().unwrap(), host)
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        false
    }
    fn before_exec(&self) -> Result<(), String> {
        let v = self.api.json("GET", &format!("/v1/sandboxes/{}", self.sid()), None);
        let healthy = v.as_ref().map(|v| !terminal(&status_of(v))).unwrap_or(false);
        if !healthy {
            // Hermes: recreate when refresh fails or the sandbox hit a terminal state.
            self.record.set("id", None);
            self.attach()?;
            self.sync.lock().unwrap().reset();
            self.creds_done.store(false, Ordering::SeqCst);
        } else if let Ok(v) = v {
            self.wait_running(status_of(&v))?;
        }
        let run = self.runner();
        if !self.creds.is_empty() && !self.creds_done.load(Ordering::SeqCst) {
            sync::upload_files(&run, &self.creds, false)?;
            self.creds_done.store(true, Ordering::SeqCst);
        }
        let s = self.sync.lock().unwrap().clone();
        s.push(&run).map(|_| ())
    }
    fn after_exec(&self) -> Result<(), String> {
        let run = self.runner();
        let s = self.sync.lock().unwrap().clone();
        let r = s.pull(&run)?;
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
            match self.api.json("POST", &format!("/v1/sandboxes/{id}/snapshot"), None) {
                Ok(v) => {
                    let snap = v.get("snapshot").and_then(|s| s.get("id")).or_else(|| v.get("snapshotId")).and_then(|s| s.as_str());
                    if let Some(s) = snap {
                        self.record.set("snapshot", Some(s));
                    }
                }
                Err(e) => eprintln!("seagent: vercel: filesystem snapshot failed: {e}"),
            }
        }
        let _ = self.api.json("POST", &format!("/v1/sandboxes/{id}/stop"), None);
        self.record.set("id", None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sync::common::fake::{self, ok, Req};
    use crate::testutil::tmpdir;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;

    struct Fake {
        n: AtomicU64,
        status: Mutex<HashMap<String, String>>,
        cmds: Mutex<HashMap<String, (String, i32)>>,
        root: PathBuf,
    }

    /// Unpack our stored-gzip tar into the fake "sandbox" (paths rewritten under `root`).
    fn unpack(root: &Path, gz: &[u8]) {
        assert_eq!(&gz[..3], &[0x1f, 0x8b, 8]);
        let mut raw = Vec::new();
        let mut i = 10;
        loop {
            let last = gz[i] & 1;
            let len = u16::from_le_bytes([gz[i + 1], gz[i + 2]]) as usize;
            raw.extend_from_slice(&gz[i + 5..i + 5 + len]);
            i += 5 + len;
            if last == 1 {
                break;
            }
        }
        for e in sync::read_tar(&raw).unwrap() {
            let p = crate::testutil::local_of_remote(&format!("/{}", e.path.trim_start_matches('/')));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, &e.data).unwrap();
        }
        let _ = root;
    }

    fn handler(f: Arc<Fake>) -> fake::Handler {
        Arc::new(move |r: &Req| {
            assert_eq!(r.header("authorization"), Some("Bearer vt"));
            assert!(r.path.contains("teamId=team1"), "{}", r.path);
            let path = r.path.split('?').next().unwrap().to_string();
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match (r.method.as_str(), parts.as_slice()) {
                ("POST", ["v1", "sandboxes"]) => {
                    let b = r.json();
                    assert_eq!(b["projectId"], "proj1");
                    assert!(b["timeout"].as_u64().unwrap() >= 300_000);
                    if b["source"]["type"] == "snapshot" {
                        assert!(b.get("image").is_none() && b.get("runtime").is_none());
                    } else {
                        assert_eq!(b["image"], "vercel/sandbox/universal:latest");
                    }
                    let id = format!("sbx{}", f.n.fetch_add(1, Ordering::SeqCst));
                    f.status.lock().unwrap().insert(id.clone(), "pending".into());
                    ok(json!({"sandbox": {"id": id, "status": "pending", "cwd": crate::testutil::remote_path(&f.root)}}))
                }
                ("GET", ["v1", "sandboxes", id]) => {
                    let mut s = f.status.lock().unwrap();
                    let st = s.get_mut(*id).unwrap();
                    if st == "pending" {
                        *st = "running".into();
                    }
                    ok(json!({"sandbox": {"id": id, "status": st, "cwd": crate::testutil::remote_path(&f.root)}}))
                }
                ("POST", ["v1", "sandboxes", _, "cmd"]) => {
                    let b = r.json();
                    assert_eq!(b["command"], "bash");
                    let args: Vec<String> = b["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
                    let o = crate::testutil::remote_bash().args(&args).current_dir(crate::testutil::local_of_remote(b["cwd"].as_str().unwrap())).output().unwrap();
                    let id = format!("cmd{}", f.n.fetch_add(1, Ordering::SeqCst));
                    let mut log = String::new();
                    for (stream, data) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
                        if !data.is_empty() {
                            log.push_str(&serde_json::to_string(&json!({"stream": stream, "data": String::from_utf8_lossy(data)})).unwrap());
                            log.push('\n');
                        }
                    }
                    f.cmds.lock().unwrap().insert(id.clone(), (log, o.status.code().unwrap_or(-1)));
                    ok(json!({"command": {"id": id, "exitCode": null}}))
                }
                ("GET", ["v1", "sandboxes", _, "cmd", c, "logs"]) => (200, f.cmds.lock().unwrap()[*c].0.clone().into_bytes()),
                ("GET", ["v1", "sandboxes", _, "cmd", c]) => {
                    assert!(r.path.contains("wait=true"));
                    ok(json!({"command": {"id": c, "exitCode": f.cmds.lock().unwrap()[*c].1}}))
                }
                ("POST", ["v1", "sandboxes", _, "cmd", _, "kill"]) => ok(json!({})),
                ("POST", ["v1", "sandboxes", _, "fs", "write"]) => {
                    assert_eq!(r.header("content-type"), Some("application/gzip"));
                    unpack(&f.root, &r.body);
                    ok(json!({}))
                }
                ("POST", ["v1", "sandboxes", id, "snapshot"]) => {
                    f.status.lock().unwrap().insert(id.to_string(), "stopped".into());
                    ok(json!({"snapshot": {"id": "snap_1"}}))
                }
                ("POST", ["v1", "sandboxes", id, "stop"]) => {
                    f.status.lock().unwrap().insert(id.to_string(), "stopped".into());
                    ok(json!({}))
                }
                _ => (500, format!("unexpected {} {}", r.method, r.path).into_bytes()),
            }
        })
    }

    fn ctx(home: &Path, ws: &Path) -> BackendCtx {
        let sec = |s: &str| s.replace("{{secret:VERCEL_TOKEN}}", "vt").replace("{{secret:VERCEL_TEAM_ID}}", "team1").replace("{{secret:VERCEL_PROJECT_ID}}", "proj1");
        BackendCtx { workspace: ws.to_path_buf(), scope_key: "s-v".into(), secrets: Arc::new(sec), home: home.to_path_buf(), sandboxed: true }
    }

    #[test]
    fn create_run_logs_sync_snapshot_restore() {
        let root = tmpdir("vcroot");
        let f = Arc::new(Fake { n: AtomicU64::new(0), status: Default::default(), cmds: Default::default(), root: root.clone() });
        let srv = fake::serve(handler(f.clone()));
        let (home, ws) = (tmpdir("vchome"), tmpdir("vcws"));
        std::fs::write(ws.join("a.txt"), "host").unwrap();
        let v = json!({"api_url": srv.url});
        let b = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert_eq!(b.map_path(&ws.join("d")), format!("{}/d", crate::testutil::remote_path(&root)));
        b.before_exec().unwrap();
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "host");
        let req = ExecRequest { script: "cat a.txt; echo oops >&2; echo gen > b.txt; exit 2".into(), cwd: Some(ws.clone()), ..Default::default() };
        let mut child = b.spawn(&req).unwrap();
        assert!(child.write_stdin(b"x").unwrap_err().to_string().contains("no stdin API"));
        child.kill(false);
        let (st, out) = crate::exec::drain(b.spawn(&req).unwrap(), Duration::from_secs(10)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.code == Some(2) && s.contains("host") && s.contains("oops"), "{s}");
        b.after_exec().unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("b.txt")).unwrap(), "gen\n");
        let (st, out) = super::super::run_capture(b.as_ref(), "tr a-z A-Z", Some(b"staged"), Duration::from_secs(10)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("STAGED"), "{}", String::from_utf8_lossy(&out));
        assert!(srv.paths().iter().any(|p| p.contains("/kill")));
        // Restart reuses the running sandbox.
        let b2 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        assert_eq!(srv.paths().iter().filter(|p| p.starts_with("POST /v1/sandboxes?")).count(), 1);
        drop(b2);
        // Cleanup snapshots and stops; the next build restores from the snapshot.
        b.cleanup();
        assert_eq!(Record::new(&home, "vercel", "s-v").get("snapshot").as_deref(), Some("snap_1"));
        let _b3 = build(&v, &ExecConfig::default(), &ctx(&home, &ws)).unwrap();
        let creates: Vec<Req> = srv.log.lock().unwrap().iter().filter(|r| r.method == "POST" && r.path.starts_with("/v1/sandboxes?")).cloned().collect();
        assert_eq!(creates.len(), 2);
        assert_eq!(creates[1].json()["source"]["snapshotId"], "snap_1");
    }

    #[test]
    fn reachable_through_exec_backend_config() {
        // `[exec] backend = "vercel"` → `ExecEnv::backend` → spawn, against the fake API.
        let root = tmpdir("vcroot2");
        let f = Arc::new(Fake { n: AtomicU64::new(0), status: Default::default(), cmds: Default::default(), root: root.clone() });
        let srv = fake::serve(handler(f.clone()));
        let (home, ws) = (tmpdir("vchome2"), tmpdir("vcws2"));
        let sec = |s: &str| s.replace("{{secret:VERCEL_TOKEN}}", "vt").replace("{{secret:VERCEL_TEAM_ID}}", "team1").replace("{{secret:VERCEL_PROJECT_ID}}", "proj1");
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(sec);
        let env = crate::exec::ExecEnv::new(ExecConfig {
            backend: "vercel".into(),
            vercel: json!({"api_url": srv.url}),
            ..Default::default()
        });
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "vercel");
        assert!(b.describe().contains("Vercel"), "{}", b.describe());
        b.before_exec().unwrap();
        let (st, out) = crate::exec::run_capture(b.as_ref(), "echo from-vercel", None, Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("from-vercel"), "{}", String::from_utf8_lossy(&out));
        assert!(srv.paths().iter().any(|p| p.starts_with("POST /v1/sandboxes?")), "created through the API: {:?}", srv.paths());
    }

    #[test]
    fn needs_token() {
        let d = tmpdir("vcnokey");
        let mut c = ctx(&d, &d);
        c.secrets = Arc::new(|s: &str| s.to_string());
        let e = build(&json!({"token_secret": "VERCEL_TOKEN_ARK_TEST_NONE"}), &ExecConfig::default(), &c).err().unwrap();
        assert!(e.contains("no token"));
    }
}
