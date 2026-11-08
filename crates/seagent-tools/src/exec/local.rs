//! Host-side processes: the local backend, the process-group registry the kernel's reaper
//! reads, the mount layout the OS sandboxes share, and `spawn_command`, which every wrapper
//! backend (docker exec, ssh, apptainer exec…) uses to run its client program with merged
//! output pipes or a pseudo-terminal.
//!
//! The OS mechanics live in one file per family (docs/cross-platform.md):
//!
//! | | Linux / Android / macOS (`local_unix`) | Windows (`local_windows`) |
//! |---|---|---|
//! | output | one pipe, `poll(2)` | anonymous pipe + reader thread |
//! | terminal | `posix_openpt` | ConPTY |
//! | group | `setpgid` / `setsid` (+ PDEATHSIG on Linux / Android) | kill-on-close Job Object |
//! | detached | `/bin/sh` wrapper writes the exit file | PowerShell wrapper writes the exit file |
//!
//! The OS sandboxes: bubblewrap and Landlock (`sandbox_linux`, Linux / Android), Seatbelt
//! (`seatbelt`, macOS). On Windows the commands run in a kill-on-close Job Object only (no
//! file-system sandbox yet: `appcontainer` is an explicit "not available" error and `auto`
//! reports the host level). iOS cannot start processes; every spawn there is an error.

use super::sandbox::SandboxConfig;
use super::BackendCtx;
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use super::local_unix as imp;
#[cfg(windows)]
use super::local_windows as imp;

pub use imp::{pid_alive, LocalChild};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use super::sandbox_linux::{landlock_abi, probe_net_namespace, BwrapBackend, LandlockBackend};
#[cfg(target_os = "macos")]
pub use super::seatbelt::SeatbeltBackend;

/// Hooks a sandbox backend runs in the child after fork, before exec
/// (Landlock). Must be async-signal-safe. Unix only: on Windows a hook is refused.
pub type PreExec = Box<dyn FnMut() -> io::Result<()> + Send + Sync>;

/// Remove inherited variables that are blocked by policy but whose names bash's `unset`
/// cannot touch (`FOO-BAR-API-KEY` — the shell tool only unsets shell identifiers, so this is
/// where those names leave the child's environment). Runs before `req.env`, so a value a
/// tool sets on purpose still wins.
pub(super) fn drop_odd_named_secrets(cmd: &mut Command) {
    use seagent_security::envscrub::{is_blocked, Surface};
    for (k, _) in std::env::vars_os() {
        if let Some(k) = k.to_str() {
            if !crate::shell::is_env_name(k) && is_blocked(k, Surface::Terminal) {
                cmd.env_remove(k);
            }
        }
    }
}

/// Spawn `cmd` (the backend's client program) for `req`: merged output on one
/// pipe or a PTY, own process group, dies with seagent unless `req.detach`.
pub fn spawn_command(mut cmd: Command, req: &ExecRequest, extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    if cfg!(target_os = "ios") {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "running commands is not available on iOS: apps cannot start processes there; pair a computer and run the command on it (`node_invoke`)"));
    }
    drop_odd_named_secrets(&mut cmd);
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    if req.detach {
        return imp::spawn_detached(cmd, req, extra);
    }
    imp::spawn_attached(cmd, req, extra)
}

/// Start time of `pid` as an opaque token (Linux: `/proc/<pid>/stat` field 22, as before;
/// macOS: `proc_pidinfo`; Windows: creation time): tells a reused pid from ours.
pub fn proc_start_time(pid: u32) -> Option<u64> {
    seagent_core::platform::proc::start_time(pid as i32)
}

/// The status a detached wrapper wrote to its exit file (`None` while it runs). Unix shells
/// report a signal death as `128 + n`.
pub(super) fn exit_file_status(path: &Path) -> Option<ExitInfo> {
    let s = std::fs::read_to_string(path).ok()?;
    #[cfg(unix)]
    {
        let c: i32 = s.trim().parse().ok()?;
        Some(if c > 128 { ExitInfo { code: Some(c), signal: Some(c - 128) } } else { ExitInfo::code(c) })
    }
    #[cfg(not(unix))]
    {
        // Windows exit codes are 32-bit unsigned (NTSTATUS values such as 0xC0000005).
        let c: i64 = s.trim().parse().ok()?;
        Some(ExitInfo::code(c as u32 as i32))
    }
}

// ───────── process-group registry (section C7; the reaper lives in seagent-kernel) ─────────
//
// Every child starts its own group (`setpgid(0,0)` / `setsid`; a Job Object on Windows), so
// pgid == pid. Recording it in `<home>/reaper/procs.jsonl` is what lets the kernel reap a
// crashed session's children without guessing: the line carries the start time (PID reuse
// check) and the seagent pid (is the owner still alive?). Best-effort by design — a command
// must never fail to run because its bookkeeping could not be written.

static REAPER_HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// `[exec.cgroups]` (ent-024): every local/bwrap/landlock command also gets its own cgroup —
/// v1 or v2, whichever the host runs — when seagent may write to its cgroup subtree (a systemd
/// service with `Delegate=yes`, or root). The reaper then also finds members that escaped
/// the process group, and the caps below apply per command. Off by default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CgroupConfig {
    pub enabled: bool,
    /// `memory.max` / `memory.limit_in_bytes` per command; 0 = no cap.
    pub memory_mb: u64,
    /// `pids.max` per command (fork-bomb guard); 0 = no cap.
    pub pids_max: u64,
}

static CGROUPS: std::sync::OnceLock<(seagent_vm::cgroup::Cgroups, CgroupConfig)> = std::sync::OnceLock::new();

/// Turn on per-command cgroups (binary startup). `Err` says why not (no delegated subtree):
/// commands still run, tracked by process group only.
pub fn enable_cgroups(cfg: &CgroupConfig, root: &Path) -> Result<seagent_vm::hostcaps::CgroupVersion, String> {
    if !cfg.enabled {
        return Err("[exec.cgroups] enabled = false".into());
    }
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        // The per-command group on this OS is the Job Object the local backend already uses.
        return Err(format!("[exec.cgroups] is not available on {}: cgroups are a Linux kernel feature (commands are still tracked as one process group / job each)", std::env::consts::OS));
    }
    let cg = seagent_vm::cgroup::Cgroups::discover(root)?;
    cg.prepare()?;
    let v = cg.version;
    let _ = CGROUPS.set((cg, cfg.clone()));
    Ok(v)
}

/// Put `pid` into a fresh cgroup with the configured caps; the path for the reaper record.
fn cgroup_for(pid: u32, session: &str) -> Option<String> {
    let (cg, cfg) = CGROUPS.get()?;
    let g = cg.create(&format!("{}-{pid}", if session.is_empty() { "exec" } else { session })).ok()?;
    let _ = g.limit(cfg.memory_mb << 20, cfg.pids_max);
    g.add(pid).ok()?;
    Some(g.primary().display().to_string())
}

thread_local! {
    static REAPER_SCOPE: std::cell::RefCell<Option<(PathBuf, String, String)>> = const { std::cell::RefCell::new(None) };
}

/// Install the seagent data dir once (daemon / binary startup) for child registration. Without it
/// nothing is recorded — seagent-tools never guesses a home, so tests and library users stay inert.
pub fn set_reaper_home(home: &Path) {
    let _ = REAPER_HOME.set(home.to_path_buf());
}

/// Attribute the process groups spawned on this thread to `session` / `tool` until the guard
/// drops (the shell tool sets it around `spawn_tool`).
pub fn reap_scope(home: &Path, session: &str, tool: &str) -> ReapScope {
    let prev = REAPER_SCOPE.with(|s| s.borrow_mut().replace((home.to_path_buf(), session.to_string(), tool.to_string())));
    ReapScope(prev)
}

pub struct ReapScope(Option<(PathBuf, String, String)>);

impl Drop for ReapScope {
    fn drop(&mut self) {
        let prev = self.0.take();
        REAPER_SCOPE.with(|s| *s.borrow_mut() = prev);
    }
}

/// Append one `{"pgid":…,"start":…,"session":…,"tool":…,"seagent_pid":…,"ts_ms":…}` line.
/// Errors are ignored: the registry is a hint for the reaper, never a precondition.
pub fn register_pgid(home: &Path, pgid: u32, session: &str, tool: &str) {
    register_pgid_in(home, pgid, session, tool, None)
}

fn register_pgid_in(home: &Path, pgid: u32, session: &str, tool: &str, cgroup: Option<String>) {
    let dir = home.join("reaper");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let line = serde_json::json!({
        "pgid": pgid,
        "start": proc_start_time(pgid),
        "session": session,
        "tool": tool,
        "seagent_pid": std::process::id(),
        "ts_ms": ts_ms,
        "cgroup": cgroup,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("procs.jsonl")) {
        let _ = writeln!(f, "{line}");
    }
}

/// Register a freshly spawned child (best-effort, never fails a command). `kind` overrides the
/// recorded tool name ("" = the [`reap_scope`] tool, else `exec`); `"detached"` marks a process
/// meant to survive an seagent restart, which the reaper records but never kills.
pub(super) fn register_child(pid: u32, kind: &str) {
    let scope = REAPER_SCOPE.with(|s| s.borrow().clone());
    let named = |t: &str| if kind.is_empty() { t.to_string() } else { kind.to_string() };
    // A detached job is meant to outlive this seagent: it is not put in a cgroup seagent may reap.
    let cg = |session: &str| if kind == "detached" { None } else { cgroup_for(pid, session) };
    match (scope, REAPER_HOME.get()) {
        (Some((home, session, tool)), _) => register_pgid_in(&home, pid, &session, &named(&tool), cg(&session)),
        (None, Some(home)) => register_pgid_in(home, pid, "", &named("exec"), cg("")),
        (None, None) => {}
    }
}

// ───────── small portable process helpers (used across the crate) ─────────

/// `SIGKILL` the process group `pgid` at once (Windows: terminate its job, or the process).
/// Never pgid 0/1.
pub fn kill_group_now(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    #[cfg(unix)]
    // SAFETY: a plain signal to a process group; never pid 0/1.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    seagent_core::platform::proc::kill_group(pgid, std::time::Duration::ZERO);
}

/// `SIGKILL` one process (Windows: `TerminateProcess`, or its job when it leads one).
pub fn kill_pid_now(pid: i32) {
    if pid <= 1 {
        return;
    }
    #[cfg(unix)]
    // SAFETY: a plain signal to one process.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    seagent_core::platform::proc::kill_group(pid, std::time::Duration::ZERO);
}

/// Spawn `cmd` as the leader of a new process group (`process_group(0)`; Windows: a new
/// console process group in a kill-on-close job), so [`kill_group_now`] reaches its tree.
pub fn spawn_own_group(cmd: &mut Command) -> io::Result<std::process::Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0).spawn()
    }
    #[cfg(not(unix))]
    {
        seagent_core::platform::proc::new_group(cmd, false);
        let mut child = cmd.spawn()?;
        if let Err(e) = seagent_core::platform::proc::adopt(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", child.id())));
        }
        Ok(child)
    }
}

/// `ETXTBSY` ("Text file busy"): a program just written is still open for writing in a
/// sibling thread's fork that has not reached exec yet. Unix only; never on Windows.
pub fn is_text_busy(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ETXTBSY)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

// ───────────── the local backend ─────────────

/// `bash -c` / `bash -lc` on Linux and macOS exactly as before; elsewhere this machine's
/// shell (`seagent_core::platform::shell`: Android `sh`, Windows Git Bash / PowerShell).
pub(super) fn bash_command(req: &ExecRequest) -> Command {
    let mut cmd = seagent_core::platform::shell::command(seagent_core::platform::shell::Style::bash(req.login), &req.script);
    if let Some(d) = &req.cwd {
        cmd.current_dir(d);
    }
    cmd
}

/// The sentence that tells the model which shell runs its commands, when it is not the
/// plain Unix bash (Windows, Android). `None` on Linux and macOS.
pub fn shell_note() -> Option<String> {
    let sh = seagent_core::platform::shell::active();
    (cfg!(windows) || sh.kind != seagent_core::platform::shell::ShellKind::Bash).then(|| sh.prompt_note())
}

/// Commands run directly on this machine.
#[derive(Default)]
pub struct LocalBackend;

impl LocalBackend {
    pub fn new() -> LocalBackend {
        LocalBackend
    }
}

impl ExecBackend for LocalBackend {
    fn id(&self) -> &str {
        "local"
    }
    fn describe(&self) -> String {
        match shell_note() {
            Some(n) => format!("local: commands run directly on this machine as the seagent user. {n}"),
            None => "local: commands run directly on this machine as the seagent user".into(),
        }
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        spawn_command(bash_command(req), req, None)
    }
    fn temp_dir(&self) -> String {
        std::env::temp_dir().display().to_string()
    }
}

/// `bin` on `PATH` (or `bin` itself when it is a path). Windows: `PATHEXT` and `\` paths too.
pub fn which(bin: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if bin.contains(['/', '\\']) {
            return Path::new(bin).is_file().then(|| PathBuf::from(bin));
        }
        seagent_core::platform::layout::which(bin)
    }
    #[cfg(not(windows))]
    {
        if bin.contains('/') {
            return Path::new(bin).is_file().then(|| PathBuf::from(bin));
        }
        std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
    }
}

// ───────────── what the OS sandboxes share ─────────────

/// `[exec.bwrap]` (parsed on every OS so one config file works everywhere; the backend
/// itself exists on Linux / Android only).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BwrapConfig {
    pub binary: String,
    /// Host directories mounted read-only to make a usable system.
    pub ro_paths: Vec<String>,
    pub extra_args: Vec<String>,
    /// Apply seagent's seccomp deny-list (`exec::seccomp`) with `bwrap --seccomp` (ent-023).
    pub seccomp: bool,
}

impl Default for BwrapConfig {
    fn default() -> Self {
        BwrapConfig { binary: "bwrap".into(), ro_paths: ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc", "/opt", "/nix", "/run/current-system"].map(String::from).to_vec(), extra_args: vec![], seccomp: true }
    }
}

/// Mount layout shared by the OS sandboxes (bwrap, Landlock, Seatbelt, AppContainer): the
/// workspace (or its private scratch copy) is the only user data visible. Unused where the
/// OS has no sandbox backend in this build (Windows, iOS).
#[cfg_attr(not(any(target_os = "linux", target_os = "android", target_os = "macos")), allow(dead_code))]
pub(super) struct Layout {
    pub workspace: PathBuf,
    pub writable: bool,
    pub tmp: PathBuf,
    pub binds: Vec<(PathBuf, String, bool)>,
    pub network: bool,
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android", target_os = "macos")), allow(dead_code))]
pub(super) fn layout(sb: &SandboxConfig, ctx: &BackendCtx) -> Result<Layout, String> {
    // `[exec] credential_files` are relative to the user's home, as configured.
    let home = super::sandbox::host_home();
    layout_with(sb, ctx, &super::global().cfg.credential_files, &home)
}

/// [`layout`] with the credential entries and the user's home spelled out (tests, embedders).
#[cfg_attr(not(any(target_os = "linux", target_os = "android", target_os = "macos")), allow(dead_code))]
pub(super) fn layout_with(sb: &SandboxConfig, ctx: &BackendCtx, creds: &[String], host_home: &Path) -> Result<Layout, String> {
    let (workspace, writable) = match (ctx.sandboxed, sb.workspace_access.as_str()) {
        (true, "none") => {
            let w = sb.scratch_workspace(&ctx.home, &ctx.scope_key);
            std::fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
            (w, true)
        }
        (true, "ro") => (ctx.workspace.clone(), false),
        _ => (ctx.workspace.clone(), true),
    };
    let tmp = sb.root(&ctx.home).join(&ctx.scope_key).join("tmp");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    let mut binds = sb.binds.iter().map(|b| super::sandbox::parse_bind(b)).collect::<Result<Vec<_>, _>>()?;
    // Credential files land read-only at the same path under the sandbox home (bwrap sets
    // `HOME=/tmp`; landlock only needs the host path to be readable).
    let (creds, _errs) = super::sandbox::credential_binds(creds, "/tmp", host_home);
    binds.extend(creds);
    Ok(Layout { workspace, writable, tmp, binds, network: sb.network == "host" })
}

/// The error a sandbox backend name gives on an OS that does not have it.
pub fn not_available(backend: &str, why: &str) -> String {
    let os = std::env::consts::OS;
    let alt = if cfg!(target_os = "macos") {
        "use `seatbelt`, `docker` or `vm`"
    } else if cfg!(windows) {
        "use `appcontainer`, `docker` or `vm`"
    } else if cfg!(any(target_os = "linux", target_os = "android")) {
        "use `bwrap`, `landlock`, `docker` or `vm`"
    } else {
        "use a remote backend (`ssh`) or a paired node"
    };
    format!("exec backend {backend} is not available on {os}: {why}; {alt}")
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::exec::{drain, run_capture};
    use crate::testutil::tmpdir;
    use std::sync::Arc;
    use std::time::Duration;

    fn req(script: &str) -> ExecRequest {
        ExecRequest { script: script.into(), ..Default::default() }
    }

    #[test]
    fn local_merged_output_exit_and_stdin() {
        let b = LocalBackend::new();
        let (st, out) = run_capture(&b, "echo out; echo err >&2; exit 4", None, Duration::from_secs(5)).unwrap();
        assert_eq!(st.code, Some(4));
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("out") && s.contains("err"));
        let (st, out) = run_capture(&b, "tr a-z A-Z", Some(b"hello"), Duration::from_secs(5)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("HELLO"));
        let mut c = b.spawn(&ExecRequest { stdin: true, ..req("read x; echo got=$x") }).unwrap();
        c.write_stdin(b"abc\n").unwrap();
        let (st, out) = drain(c, Duration::from_secs(5)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("got=abc"));
    }

    #[test]
    fn spawned_group_is_registered_for_the_reaper() {
        // Section C7: what a spawned command records so the kernel's reaper can decide later.
        let home = tmpdir("reaper-reg");
        let b = LocalBackend::new();
        let scope = reap_scope(&home, "s-reg", "shell");
        let mut c = b.spawn(&req("sleep 30")).unwrap();
        drop(scope);
        let pgid = c.pid().unwrap();
        let text = std::fs::read_to_string(home.join("reaper/procs.jsonl")).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().last().expect("one registry line")).unwrap();
        assert_eq!(line["pgid"], pgid);
        assert_eq!(line["session"], "s-reg");
        assert_eq!(line["tool"], "shell");
        assert_eq!(line["seagent_pid"], std::process::id());
        assert_eq!(line["start"].as_u64(), proc_start_time(pgid), "the start time is what defeats PID reuse");
        c.kill(true);
        let _ = drain(c, Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// ent-024: with `[exec.cgroups]` on and a delegated (here: fake v2) subtree, a spawned
    /// command lands in its own cgroup with the caps, and the reaper line names it.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn commands_get_their_own_cgroup_when_enabled() {
        assert!(enable_cgroups(&CgroupConfig::default(), Path::new("/")).unwrap_err().contains("enabled = false"));
        let root = tmpdir("cgroot");
        let w = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w("proc/self/cgroup", "0::/system.slice/seagent.service\n");
        w("sys/fs/cgroup/cgroup.controllers", "memory pids");
        w("sys/fs/cgroup/system.slice/seagent.service/cgroup.controllers", "memory pids");
        let on = CgroupConfig { enabled: true, memory_mb: 512, pids_max: 100 };
        assert_eq!(enable_cgroups(&on, &root).unwrap(), seagent_vm::hostcaps::CgroupVersion::V2);
        let home = tmpdir("cgreg");
        let b = LocalBackend::new();
        let scope = reap_scope(&home, "s-cg", "shell");
        let mut c = b.spawn(&req("sleep 30")).unwrap();
        drop(scope);
        let pid = c.pid().unwrap();
        let text = std::fs::read_to_string(home.join("reaper/procs.jsonl")).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        let cg = PathBuf::from(line["cgroup"].as_str().expect("the cgroup is recorded"));
        assert_eq!(cg, root.join(format!("sys/fs/cgroup/system.slice/seagent.service/seagent-exec/s-cg-{pid}")));
        assert_eq!(std::fs::read_to_string(cg.join("cgroup.procs")).unwrap(), pid.to_string());
        assert_eq!(std::fs::read_to_string(cg.join("memory.max")).unwrap(), (512u64 << 20).to_string());
        assert_eq!(std::fs::read_to_string(cg.join("pids.max")).unwrap(), "100");
        c.kill(true);
        let _ = drain(c, Duration::from_secs(5));
    }

    #[test]
    fn pty_is_a_terminal_and_resizes() {
        let b = LocalBackend::new();
        let mut c = b.spawn(&ExecRequest { pty: Some((24, 80)), stdin: true, ..req("[ -t 0 ] && echo TTY; stty size; read l; echo line=$l") }).unwrap();
        assert!(c.is_pty());
        c.write_stdin(b"zz\r").unwrap();
        let (st, out) = drain(c, Duration::from_secs(5)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.success() && s.contains("TTY") && s.contains("24 80") && s.contains("line=zz"), "{s}");
        let mut c = b.spawn(&ExecRequest { pty: Some((10, 20)), stdin: true, ..req("sleep 0.3; stty size") }).unwrap();
        c.resize(30, 100).unwrap();
        let (_, out) = drain(c, Duration::from_secs(5)).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("30 100"));
        let mut p = b.spawn(&req("true")).unwrap();
        assert!(p.resize(1, 1).is_err());
    }

    #[test]
    fn kill_and_detached_survival_files() {
        let b = LocalBackend::new();
        let mut c = b.spawn(&req("sleep 30")).unwrap();
        c.kill(true);
        let t = std::time::Instant::now();
        while c.try_wait().unwrap().is_none() && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(c.try_wait().unwrap().and_then(|e| e.signal), Some(9));

        let d = tmpdir("detach");
        let (log, exit) = (d.join("p.log"), d.join("p.exit"));
        let c = b.spawn(&ExecRequest { detach: true, log_file: Some(log.clone()), exit_file: Some(exit.clone()), ..req("echo one; sleep 0.2; echo two; exit 7") }).unwrap();
        let pid = c.pid().unwrap();
        let start = proc_start_time(pid);
        drop(c); // seagent "restarts": the process keeps running
        let mut r = LocalChild::reattach(pid, start, &log, &exit, 0).unwrap();
        let (st, out) = drain(Box::new(LocalChild::reattach(pid, start, &log, &exit, 0).unwrap()), Duration::from_secs(5)).unwrap();
        assert_eq!(st.code, Some(7));
        assert!(String::from_utf8_lossy(&out).contains("one\ntwo"));
        assert_eq!(r.try_wait().unwrap().unwrap().code, Some(7));
    }

    #[test]
    fn credential_files_land_in_the_sandbox_layout() {
        // `Layout::binds` is what bwrap/landlock mount: a valid credential file is read-only,
        // an ssh key is refused, and nothing lands outside the sandbox home.
        let home = tmpdir("credlayout-home");
        std::fs::write(home.join("api-token"), "t").unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), "k").unwrap();
        let sb = SandboxConfig { workspace_access: "rw".into(), network: "host".into(), ..Default::default() };
        let ctx = BackendCtx { workspace: tmpdir("credlayout-ws"), scope_key: "t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: tmpdir("credlayout-seagent"), sandboxed: true };
        let creds = vec!["api-token".to_string(), ".ssh/id_rsa".to_string(), "/etc/passwd".to_string()];
        let l = layout_with(&sb, &ctx, &creds, &home).unwrap();
        assert_eq!(l.binds, vec![(std::fs::canonicalize(home.join("api-token")).unwrap(), "/tmp/api-token".to_string(), true)], "{:?}", l.binds);
        assert!(layout_with(&sb, &ctx, &[], &home).unwrap().binds.is_empty(), "no configured files, no mounts");
        // Operator binds and credential binds coexist.
        let sb = SandboxConfig { workspace_access: "rw".into(), network: "host".into(), binds: vec!["/usr/share:/share:ro".into()], ..Default::default() };
        let l = layout_with(&sb, &ctx, &creds, &home).unwrap();
        assert!(l.binds.iter().any(|(_, dst, ro)| dst == "/share" && *ro) && l.binds.iter().any(|(_, dst, _)| dst == "/tmp/api-token"));
    }

    #[test]
    fn portable_helpers_keep_unix_semantics() {
        assert!(is_text_busy(&io::Error::from_raw_os_error(libc::ETXTBSY)));
        assert!(!is_text_busy(&io::Error::from_raw_os_error(libc::ENOENT)));
        let mut c = Command::new("sleep");
        c.arg("30");
        let mut child = spawn_own_group(&mut c).unwrap();
        kill_group_now(child.id() as i32);
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        assert!(not_available("seatbelt", "no Seatbelt").contains("not available on"));
        assert_eq!(exit_file_status(Path::new("/nonexistent/exit")), None);
    }
}
