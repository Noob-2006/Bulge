//! Plugin-supplied execution environments (Hermes `agent/terminal_env_provider.py`
//! + `agent/terminal_env_registry.py`).
//!
//! Hermes lets a plugin register a terminal environment under
//! `PluginContext.register_terminal_environment_provider`; `terminal.backend` (seagent: `[exec]
//! backend`) then selects it by name, and the provider builds a `BaseEnvironment` duck type.
//! seagent's equivalent seam is `seagent_tools::exec::register_provider`: a closure
//! `Fn(&Value, &BackendCtx) -> Result<Arc<dyn seagent_core::exec::ExecBackend>, String>` stored
//! under a name, which `seagent_tools::exec::build_backend` consults for any name that is not a
//! built-in. That registry lives in `seagent-tools`, but a plugin is a **separate crate or an
//! external process**, so this module is the plugin-facing end of it:
//!
//! * in-process code (seagent's built-in plugins — see [`builtin`]) registers here with
//!   [`register`];
//! * the host (the `seagent` binary, which links both crates) bridges this registry into
//!   `seagent_tools::exec` once at startup with [`install_into`] — six lines, see that function;
//! * a plugin that really is a separate process cannot hand seagent an `Arc<dyn ExecBackend>`;
//!   it declares the backend through the plugin protocol and the host-side adapter lives with
//!   the host. Until then such a plugin is selected with `[exec] backend = "<name>"` and gets a
//!   clear "no such backend" error, not a silent fallback.
//!
//! Name rules follow upstream: lowercase `[a-z0-9_-]`, and a built-in backend name is
//! reserved (a plugin may never shadow `local`/`docker`/`ssh`/…).
//!
//! ## Example (a plugin's `register()`)
//!
//! ```ignore
//! seagent_plugin::exec::register("my-sandbox", std::sync::Arc::new(|cfg: &serde_json::Value, ctx: &seagent_plugin::exec::Ctx| {
//!     let token = ctx.secret("MY_SANDBOX_TOKEN").ok_or("set MY_SANDBOX_TOKEN with `seagent secrets set`")?;
//!     Ok(std::sync::Arc::new(MySandbox::new(&ctx.workspace, token, cfg) .map_err(|e| e.to_string())?))
//! }))?;
//! ```

use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, OnceLock, RwLock};
use std::time::Duration;

/// Built-in backend names: reserved, exactly like Hermes `BUILTIN_BACKEND_NAMES`
/// (mirrors `seagent_tools::exec::BACKENDS`; a plugin may not shadow them).
pub const RESERVED: &[&str] = &["local", "bwrap", "landlock", "docker", "podman", "singularity", "apptainer", "ssh", "modal", "daytona", "vercel", "openshell"];

/// The vault lookup a [`Ctx`] carries: name in, secret out (`None` when absent).
///
/// A `type` alias purely to keep the field and constructor signatures readable.
type SecretLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// What a provider gets: the session's workspace, its sandbox scope, the seagent data
/// dir, whether the session is sandboxed, and the vault lookup.
pub struct Ctx {
    pub workspace: PathBuf,
    /// Container / sandbox identity (per session, workspace or shared).
    pub scope_key: String,
    /// seagent data dir (`~/.local/share/seagent`).
    pub home: PathBuf,
    /// Is this the sandbox backend of a sandboxed session?
    pub sandboxed: bool,
    secret: SecretLookup,
}

impl Ctx {
    pub fn new(workspace: PathBuf, scope_key: String, home: PathBuf, sandboxed: bool, secret: SecretLookup) -> Ctx {
        Ctx { workspace, scope_key, home, sandboxed, secret }
    }
    /// A vault secret (or env var) by name; `None` when absent.
    pub fn secret(&self, name: &str) -> Option<String> {
        (self.secret)(name).filter(|v| !v.is_empty())
    }
}

/// Builds the backend for `[exec] backend = "<name>"`; `Value` is that backend's
/// config table (`[exec.<name>]`, or the table the host passes for external plugins).
pub type Provider = Arc<dyn Fn(&Value, &Ctx) -> Result<Arc<dyn ExecBackend>, String> + Send + Sync>;

fn registry() -> &'static RwLock<BTreeMap<String, Provider>> {
    static R: OnceLock<RwLock<BTreeMap<String, Provider>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Is `name` usable for a plugin backend? (`my-sandbox`, `acme_2` — not `ssh`.)
pub fn valid_name(name: &str) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(format!("exec provider name `{name}`: use lowercase letters, digits, `-` or `_`"));
    }
    if RESERVED.contains(&name) {
        return Err(format!("exec provider name `{name}` is reserved for the built-in {name} backend and cannot be registered by a plugin"));
    }
    Ok(())
}

/// Register (or replace) the provider for `name` (`[exec] backend = "<name>"`).
pub fn register(name: &str, p: Provider) -> Result<(), String> {
    valid_name(name)?;
    registry().write().unwrap().insert(name.to_string(), p);
    Ok(())
}

pub fn get(name: &str) -> Option<Provider> {
    registry().read().unwrap().get(name).cloned()
}

/// Registered names, sorted.
pub fn names() -> Vec<String> {
    registry().read().unwrap().keys().cloned().collect()
}

/// Every registration, sorted by name.
pub fn providers() -> Vec<(String, Provider)> {
    registry().read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Hand every registration to `f` — the host's one-line bridge into the tools crate:
///
/// ```ignore
/// seagent_plugin::exec::install_into(|name, p| {
///     let p = p.clone();
///     seagent_tools::exec::register_provider(name, std::sync::Arc::new(move |v: &serde_json::Value, c: &seagent_tools::exec::BackendCtx| {
///         let ctx = seagent_plugin::exec::Ctx::new(c.workspace.clone(), c.scope_key.clone(), c.home.clone(), c.sandboxed,
///             std::sync::Arc::new(move |n: &str| c.secret(n)));
///         p(v, &ctx)
///     }));
/// });
/// ```
///
/// Call it after `seagent_plugin::exec::register_builtin()` and before `seagent_tools::exec::install`.
pub fn install_into(mut f: impl FnMut(&str, Provider)) {
    for (name, p) in providers() {
        f(&name, p);
    }
}

// ───────────── the reference provider shipped with seagent ─────────────

/// The provider a built-in plugin registers: `[exec] backend = "workspace-copy"`.
///
/// Commands run in a private copy of the workspace under
/// `<seagent data>/sandboxes/plugin-exec/<scope>/workspace`, so a destructive or untrusted
/// command cannot touch the real tree (and nothing is synced back: the copy is the sandbox).
/// It exists to be *read*: it is the smallest complete `ExecBackend` a plugin can copy,
/// including the "spawn a child with merged output" plumbing a plugin would otherwise have to
/// re-derive (`seagent-tools`' `spawn_command` is not reachable from another crate).
pub fn workspace_copy_provider() -> Provider {
    Arc::new(|cfg: &Value, ctx: &Ctx| {
        let dir = cfg.get("dir").and_then(Value::as_str).map(|d| seagent_path(d, ctx)).unwrap_or_else(|| ctx.home.join("sandboxes").join("plugin-exec").join(sanitize(&ctx.scope_key)).join("workspace"));
        Ok(Arc::new(WorkspaceCopy::new(&ctx.workspace, dir)?) as Arc<dyn ExecBackend>)
    })
}

/// Register the providers that ship with seagent (idempotent). The host calls this once
/// at startup, before [`install_into`].
pub fn register_builtin() -> Vec<String> {
    let mut done = Vec::new();
    if register("workspace-copy", workspace_copy_provider()).is_ok() {
        done.push("workspace-copy".to_string());
    }
    done
}

fn seagent_path(p: &str, ctx: &Ctx) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => ctx.home.join(rest),
        None => PathBuf::from(p),
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(48).collect()
}

/// Directory names a workspace copy never descends into (build output, VCS, deps).
const COPY_SKIP: &[&str] = &["target", "node_modules", ".git", ".venv", "__pycache__"];

fn copy_tree(src: &Path, dst: &Path, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err(format!("workspace copy: {} is nested more than 32 levels deep", src.display()));
    }
    std::fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let rd = std::fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let from = entry.path();
        let to = dst.join(&name);
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            if name.to_string_lossy().as_ref().is_empty() || COPY_SKIP.contains(&name.to_string_lossy().as_ref()) {
                continue;
            }
            copy_tree(&from, &to, depth + 1)?;
        } else if meta.is_file() {
            std::fs::copy(&from, &to).map_err(|e| format!("copy {}: {e}", from.display()))?;
        }
    }
    Ok(())
}

struct WorkspaceCopy {
    src: PathBuf,
    dir: PathBuf,
}

impl WorkspaceCopy {
    fn new(src: &Path, dir: PathBuf) -> Result<WorkspaceCopy, String> {
        if !dir.exists() {
            copy_tree(src, &dir, 0)?;
        }
        Ok(WorkspaceCopy { src: src.to_path_buf(), dir })
    }
}

impl ExecBackend for WorkspaceCopy {
    fn id(&self) -> &str {
        "workspace-copy"
    }
    fn describe(&self) -> String {
        format!("workspace-copy (plugin provider): a private copy of {} at {} — changes stay in the copy", self.src.display(), self.dir.display())
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut script = String::new();
        #[cfg(not(unix))]
        let mut cwd = self.dir.clone();
        if let Some(c) = &req.cwd {
            let rel = c.strip_prefix(&self.src).map(|r| r.to_path_buf()).unwrap_or_default();
            let dir = if rel.as_os_str().is_empty() { self.dir.clone() } else { self.dir.join(rel) };
            #[cfg(unix)]
            script.push_str(&format!("mkdir -p {0} && cd {0} || exit 126\n", shell_quote(&dir)));
            // Not every Windows shell is POSIX: make the directory here and start in it.
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(&dir)?;
                cwd = dir;
            }
        }
        script.push_str(&req.script);
        #[cfg(unix)]
        return PipeChild::start(&script, req, &self.dir);
        #[cfg(not(unix))]
        PipeChild::start(&script, req, &cwd)
    }
    fn map_path(&self, host: &Path) -> String {
        match host.strip_prefix(&self.src) {
            Ok(rel) => self.dir.join(rel).display().to_string(),
            Err(_) => host.display().to_string(),
        }
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn temp_dir(&self) -> String {
        self.dir.display().to_string()
    }
}

#[cfg(unix)]
fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}

/// A child whose merged stdout+stderr arrives over a channel (reference plumbing for
/// providers: `ExecChild` is a trait every backend must implement by hand).
struct PipeChild {
    child: std::process::Child,
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    exit: Option<ExitInfo>,
    stdin: Option<std::process::ChildStdin>,
    killed: Arc<AtomicBool>,
}

impl PipeChild {
    fn start(script: &str, req: &ExecRequest, cwd: &Path) -> io::Result<Box<dyn ExecChild>> {
        #[cfg(unix)]
        let (child, stdout) = {
            let mut cmd = seagent_core::platform::proc::command("bash");
            // `exec 2>&1` merges stderr into the one pipe the reader thread drains.
            let body = format!("exec 2>&1\n{script}");
            cmd.arg(if req.login { "-lc" } else { "-c" }).arg(body).current_dir(cwd);
            for (k, v) in &req.env {
                cmd.env(k, v);
            }
            cmd.stdin(if req.stdin || req.stdin_data.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
            let mut child = cmd.spawn()?;
            let stdout = child.stdout.take().ok_or_else(|| io::Error::other("no stdout pipe"))?;
            (child, stdout)
        };
        // Windows: this machine's shell (Git Bash, else PowerShell); stdout and stderr share
        // one anonymous pipe, which is what `exec 2>&1` does for bash.
        #[cfg(not(unix))]
        let (child, stdout) = {
            use seagent_core::platform::shell::{command, Style};
            let mut cmd = command(Style::bash(req.login), script);
            cmd.current_dir(cwd);
            for (k, v) in &req.env {
                cmd.env(k, v);
            }
            let (reader, writer) = std::io::pipe()?;
            cmd.stdin(if req.stdin || req.stdin_data.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(writer.try_clone()?).stderr(writer);
            let child = cmd.spawn()?;
            drop(cmd); // our copies of the write end: the reader sees EOF when the child exits
            (child, reader)
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut r = stdout;
            let mut buf = vec![0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut me = PipeChild { child, rx, pending: Vec::new(), exit: None, stdin: None, killed: Arc::new(AtomicBool::new(false)) };
        if let Some(data) = &req.stdin_data {
            me.stdin = child_stdin(&mut me.child);
            if let Some(s) = me.stdin.as_mut() {
                let _ = s.write_all(data);
            }
            if !req.stdin {
                me.stdin = None;
            }
        } else if req.stdin {
            me.stdin = child_stdin(&mut me.child);
        }
        Ok(Box::new(me))
    }
}

fn child_stdin(c: &mut std::process::Child) -> Option<std::process::ChildStdin> {
    c.stdin.take()
}

impl ExecChild for PipeChild {
    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv_timeout(timeout) {
                Ok(chunk) => self.pending = chunk,
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(io::ErrorKind::TimedOut.into()),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(s) => s.write_all(data),
            None => Err(io::Error::new(io::ErrorKind::Unsupported, "start the command with stdin=true to write to it")),
        }
    }
    fn close_stdin(&mut self) {
        self.stdin = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        if self.exit.is_none() {
            if let Some(st) = self.child.try_wait()? {
                #[cfg(unix)]
                let signal = {
                    use std::os::unix::process::ExitStatusExt;
                    st.signal()
                };
                // Windows exit statuses always carry a code.
                #[cfg(not(unix))]
                let signal = None;
                self.exit = Some(match st.code() {
                    Some(c) => ExitInfo::code(c),
                    None => ExitInfo { code: None, signal },
                });
            }
        }
        Ok(self.exit)
    }
    fn kill(&mut self, _force: bool) {
        if !self.killed.swap(true, Ordering::SeqCst) {
            let _ = self.child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(ws: &Path, home: &Path) -> Ctx {
        let sec = |s: &str| (s == "MY_TOKEN").then(|| "tok-1".to_string());
        Ctx::new(ws.to_path_buf(), "s-1".into(), home.to_path_buf(), true, Arc::new(sec))
    }

    /// Self-removing scratch dir: `seagent-plugin-exec-*` used to be left in the temp dir after every
    /// run. The guard derefs to `Path`, so call sites keep using `dir.join(..)`.
    fn tmpdir(tag: &str) -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new(&format!("seagent-plugin-exec-{tag}"))
    }

    #[test]
    fn registry_rules_and_bridging() {
        // Names: lowercase only, and built-ins are reserved (Hermes BUILTIN_BACKEND_NAMES).
        assert!(register("Acme", workspace_copy_provider()).is_err());
        assert!(register("ssh", workspace_copy_provider()).unwrap_err().contains("reserved"));
        assert!(register("acme-sandbox", workspace_copy_provider()).is_ok());
        assert!(names().contains(&"acme-sandbox".to_string()));
        assert!(get("acme-sandbox").is_some() && get("nope").is_none());

        // The host bridge (`install_into`) sees every registration, exactly once each.
        let mut seen = Vec::new();
        install_into(|n, _p| seen.push(n.to_string()));
        assert_eq!(seen.iter().filter(|n| *n == "acme-sandbox").count(), 1, "{seen:?}");
        assert!(seen.contains(&"acme-sandbox".to_string()));
    }

    #[test]
    fn builtin_provider_creates_and_spawns_in_a_copy() {
        let base = tmpdir("copy");
        let (ws, home) = (base.join("ws"), base.join("home"));
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::create_dir_all(ws.join("target")).unwrap();
        std::fs::write(ws.join("src/a.txt"), "original").unwrap();
        std::fs::write(ws.join("target/junk"), "junk").unwrap();
        let registered = register_builtin();
        assert!(registered.contains(&"workspace-copy".to_string()));
        let p = get("workspace-copy").unwrap();
        let c = ctx(&ws, &home);
        let b = p(&json!({}), &c).unwrap();
        assert_eq!(b.id(), "workspace-copy");
        assert!(!b.shares_host_fs());
        let dir = PathBuf::from(b.map_path(&ws.join("src/a.txt")));
        assert!(dir.ends_with("src/a.txt") && dir.starts_with(&home), "{}", dir.display());
        assert_eq!(std::fs::read_to_string(&dir).unwrap(), "original");
        assert!(!home.join("sandboxes/plugin-exec/s-1/workspace/target").exists(), "skip dirs are not copied");

        // A command runs in the copy: reads the file, writes next to it, host untouched.
        let req = ExecRequest { script: "cat src/a.txt; echo; echo copy > src/b.txt; echo err >&2; exit 7".into(), cwd: Some(ws.clone()), ..Default::default() };
        let (st, out) = drain(b.spawn(&req).unwrap(), Duration::from_secs(20));
        let s = String::from_utf8_lossy(&out);
        assert_eq!(st.code, Some(7), "{s}");
        assert!(s.contains("original") && s.contains("err"), "merged output: {s}");
        let copy = home.join("sandboxes/plugin-exec/s-1/workspace");
        assert_eq!(std::fs::read_to_string(copy.join("src/b.txt")).unwrap(), "copy\n");
        assert!(!ws.join("src/b.txt").exists(), "the real workspace is untouched");

        // stdin round-trips through the pipe child.
        let mut child = b.spawn(&ExecRequest { script: "read x; echo got=$x".into(), stdin: true, ..Default::default() }).unwrap();
        child.write_stdin(b"typed\n").unwrap();
        child.close_stdin();
        let (st, out) = drain(child, Duration::from_secs(20));
        assert!(st.success() && String::from_utf8_lossy(&out).contains("got=typed"));
        assert!(b.spawn(&ExecRequest { script: "true".into(), ..Default::default() }).is_ok());
    }

    fn drain(mut c: Box<dyn ExecChild>, timeout: Duration) -> (ExitInfo, Vec<u8>) {
        let start = std::time::Instant::now();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match c.read(&mut buf, Duration::from_millis(50)) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
            if let Some(st) = c.try_wait().unwrap() {
                while let Ok(n) = c.read(&mut buf, Duration::from_millis(20)) {
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                return (st, out);
            }
            if start.elapsed() > timeout {
                c.kill(true);
                return (ExitInfo { code: None, signal: None }, out);
            }
        }
        // The child closes stdout just before it exits, so an EOF no longer implies "already
        // reaped": under load the process is still running when the pipe closes. Poll for the
        // status for the rest of the timeout instead of returning an exit code of `None`, which
        // callers read as a failure.
        while start.elapsed() <= timeout {
            if let Some(st) = c.try_wait().unwrap() {
                return (st, out);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        c.kill(true);
        (ExitInfo { code: None, signal: None }, out)
    }
}
