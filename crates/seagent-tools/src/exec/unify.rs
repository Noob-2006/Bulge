//! Every `exec` backend behind one interface: [`IsolatedEnv`] (B6).
//!
//! The microVM is the reference implementation of [`IsolatedEnv`] (`seagent_vm::unify`
//! plus the thin [`VmBackend`](super::vm::VmBackend) glue); everything else here is
//! an adapter over an existing [`ExecBackend`]. That is deliberate: no backend is
//! rewritten, and the answers each one gives about itself (`EnvCaps`) come from the
//! one isolation table in [`seagent_vm::isolation`], so `seagent sandbox explain`, the
//! system prompt and this module can never disagree.
//!
//! Two rules the adapters must keep, because the alternative is a lie:
//!
//! * **No silent `local`.** When the requested environment cannot be built (engine
//!   missing, config absent, no microVM and no namespace sandbox) [`open`] returns
//!   an `Err` that names the reason. Falling back to the host is a decision for
//!   [`seagent_vm::policy`], which says so in a warning — never for an adapter.
//! * **Honest depth.** stdout/stderr are captured separately by wrapping the script
//!   in a small preamble that redirects the two streams into files inside the
//!   environment and reads them back byte-exactly (see [`wrap_script`]). A backend
//!   that cannot even run a shell wrapper keeps the merged stream on `stdout` and an
//!   empty `stderr` — [`split_streams`]' fallback — rather than pretending.
//!
//! Files: `put_file`/`get_file` address the environment's *workspace*. For a
//! backend that shares the host file system (local, bwrap, Landlock, a bind-mounted
//! container) that is the same directory the command sees. For a copy-based backend
//! (microVM, ssh, modal, daytona, vercel, openshell) the host side is the source of
//! truth: a file written here is pushed by the next [`IsolatedEnv::run`], and a file
//! a command created is visible after that run pulled the workspace back.

use super::sync::safe_host_path;
use super::{build_backend, sh_quote, BackendCtx, ExecConfig, BACKENDS};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use seagent_vm::isolation::{isolation_of_backend, IsolationLevel};
use seagent_vm::policy::{self, Query};
use seagent_vm::proto::AGENT_UID;
use seagent_vm::unify::{EnvCaps, EnvOutcome, EnvSpec, IsolatedEnv};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The one name seagent accepts where a backend name goes and no backend was chosen
/// yet: [`seagent_vm::policy::resolve`] turns it into one (with a warning when the
/// result is weaker than a microVM).
pub const AUTO: &str = "auto";

/// Open the environment `name` asks for.
///
/// `auto` goes through [`seagent_vm::policy::resolve`] (data dir = `ctx.home`,
/// `sandboxed` = `ctx.sandboxed`), so an unconfigured seagent picks the strongest
/// environment this machine can actually give and carries its warning into
/// [`IsolatedEnv::caps`]. An explicit name is honoured verbatim; if it cannot be
/// built the error names the reason and nothing is started instead.
pub fn open(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn IsolatedEnv>, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err(format!("no exec backend named: pass one of {AUTO}, {}", BACKENDS.join(", ")));
    }
    let (backend, plan_warning) = if n == AUTO {
        let plan = policy::resolve(&Query { requested: AUTO, cfg: &cfg.vm, data: &ctx.home, sandboxed: ctx.sandboxed });
        (plan.backend, plan.warning)
    } else {
        (n.to_string(), None)
    };

    if backend == seagent_vm::BACKEND_NAME {
        return open_vm(cfg, ctx, plan_warning);
    }
    // A plugin backend keeps working (it is built by `build_backend`), but it has no
    // row in the isolation table: it is reported as host-level with a warning
    // instead of being given a level seagent cannot vouch for.
    let classified = BACKENDS.contains(&backend.as_str());
    let level = isolation_of_backend(&backend);
    let warning = if classified {
        level.warning().map(|w| format!("{backend}: {w}"))
    } else {
        Some(format!("{backend}: a plugin-provided backend with no isolation level in seagent's table; treat it as running on the host"))
    };
    let extra = extra_config(cfg, &backend);
    let be = build_backend(&backend, cfg, &extra, ctx).map_err(|e| format!("exec backend `{backend}`: {e}"))?;
    let workspace = visible_workspace(&backend, cfg, ctx);
    Ok(Arc::new(BackendEnv { backend: be, name: backend, workspace, level, warning, freed: AtomicBool::new(false) }))
}

/// The floor `name` claims, without starting anything.
///
/// This is the *table* answer: `caps_of(name).level == isolation_of_backend(name)`
/// for every name in [`BACKENDS`], plus the warning that goes with a level weaker
/// than a microVM — and, for `vm`, a warning when this machine cannot boot one
/// (so the claim is not mistaken for a fact). [`open`]'s environment answers for
/// itself in [`IsolatedEnv::caps`], which is where a downgrade actually shows up.
///
/// No VM, container or ssh connection is created: only `PATH` and the data dir are
/// inspected.
pub fn caps_of(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<EnvCaps, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err(format!("no exec backend named: pass one of {AUTO}, {}", BACKENDS.join(", ")));
    }
    if n != AUTO {
        return table_caps(n, cfg, ctx);
    }
    let plan = policy::resolve(&Query { requested: AUTO, cfg: &cfg.vm, data: &ctx.home, sandboxed: ctx.sandboxed });
    let mut caps = table_caps(&plan.backend, cfg, ctx)?;
    // The plan's warning explains *why* this level and names the blocker; the
    // table's warning explains what the level itself means. Prefer the former.
    caps.warning = plan.warning.or(caps.warning);
    if plan.provider.is_some() {
        caps.provider = plan.provider;
    }
    Ok(caps)
}

/// One line per backend ([`AUTO`] first, then [`BACKENDS`]) for
/// `seagent sandbox explain`: names, levels and warnings, nothing started.
pub fn describe_names(cfg: &ExecConfig, ctx: &BackendCtx) -> String {
    std::iter::once(AUTO)
        .chain(BACKENDS.iter().copied())
        .map(|name| match caps_of(name, cfg, ctx) {
            Ok(c) => c.line(),
            Err(e) => format!("{name}: unavailable — {e}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// [`caps_of`] for a concrete backend name.
fn table_caps(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<EnvCaps, String> {
    if !BACKENDS.contains(&name) {
        return Err(format!("unknown exec backend `{name}`: use {AUTO} or one of {}", BACKENDS.join(", ")));
    }
    let level = isolation_of_backend(name);
    let warning = level.warning().map(|w| format!("{name}: {w}"));
    if name == seagent_vm::BACKEND_NAME {
        // Detection only (PATH + the data dir): `policy::capabilities` never boots.
        let caps = policy::capabilities(&cfg.vm, &ctx.home);
        let (kind, note) = seagent_vm::provider::select(&cfg.vm, &caps);
        if !kind.is_vm() {
            // The table says `vm` *is* a microVM; this machine cannot honour that
            // right now. Say so in one phrase, and let `open` report the level it
            // really gives.
            let why = policy::blockers(&caps);
            return Ok(EnvCaps {
                id: name.to_string(),
                level,
                provider: None,
                warning: Some(format!("{name}: this machine cannot boot a microVM ({why}); opening it reports the level it really gives")),
                workspace_copy: true,
                snapshots: cfg.vm.snapshots,
                broker: cfg.vm.broker,
                uid: Some(AGENT_UID),
            });
        }
        return Ok(EnvCaps { id: name.to_string(), level, provider: Some(kind.name().to_string()), warning: warning.or(note), workspace_copy: true, snapshots: cfg.vm.snapshots, broker: cfg.vm.broker, uid: Some(AGENT_UID) });
    }
    let (copy, uid) = match name {
        // Local work runs as the seagent user; Landlock changes permissions, not identity.
        "local" | "landlock" | "seatbelt" => (false, current_uid()),
        "bwrap" | "appcontainer" | "docker" | "podman" | "singularity" | "apptainer" => (false, None),
        "ssh" | "modal" | "daytona" | "vercel" | "openshell" => (true, None),
        other => return Err(format!("unknown exec backend `{other}`: no isolation level in seagent's table")),
    };
    Ok(EnvCaps { id: name.to_string(), level, provider: None, warning, workspace_copy: copy, snapshots: false, broker: false, uid })
}

/// The workspace the environment's commands actually see.
///
/// With `[exec.sandbox] workspace_access = "none"` every host-side sandbox (bwrap,
/// Landlock, containers, singularity) runs in the scope's private scratch copy, and
/// the microVM of an untrusted tier does the same — a path in the project would not
/// be the directory the command is in, so `put_file` must not write there.
fn visible_workspace(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> PathBuf {
    match name {
        "bwrap" | "landlock" | "docker" | "podman" | "singularity" | "apptainer" if ctx.sandboxed && cfg.sandbox.workspace_access == "none" => {
            cfg.sandbox.scratch_workspace(&ctx.home, &ctx.scope_key)
        }
        _ => ctx.workspace.clone(),
    }
}

/// `[exec.modal]` / `[exec.daytona]` / `[exec.vercel]` / `[exec.providers.<name>]`:
/// the table `build_backend` hands to a provider. Mirrors `ExecEnv::extra_config`
/// (that method is private and tied to an `ExecEnv`; `open` must work without one).
fn extra_config(cfg: &ExecConfig, name: &str) -> Value {
    match name {
        "modal" => cfg.modal.clone(),
        "daytona" => cfg.daytona.clone(),
        "vercel" => cfg.vercel.clone(),
        other => cfg.providers.get(other).cloned().unwrap_or(Value::Null),
    }
}

/// The seagent user's uid; `None` where the OS has no numeric uid (Windows).
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    Some(unsafe { libc::getuid() })
}
#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

// ───────────── the microVM adapter ─────────────

fn open_vm(cfg: &ExecConfig, ctx: &BackendCtx, plan_warning: Option<String>) -> Result<Arc<dyn IsolatedEnv>, String> {
    // `selection()` is detection only (it reads PATH and the data dir); the VM is
    // created by the first command, not here.
    let mgr = super::vm::manager_for(&cfg.vm, &ctx.home);
    let (kind, sel_warning) = mgr.selection();
    let be = super::vm::VmBackend::new(&cfg.vm, &cfg.sandbox, ctx, !ctx.sandboxed)?;
    let level = be.isolation();
    let microvm = level == IsolationLevel::MicroVm;
    Ok(Arc::new(VmEnv {
        workspace: be.workspace().to_path_buf(),
        be,
        level,
        provider: Some(kind.name().to_string()),
        warning: if microvm { plan_warning.or(sel_warning) } else { sel_warning.or(plan_warning) },
        microvm,
        snapshots: microvm && cfg.vm.snapshots,
        broker: microvm && cfg.vm.broker,
        freed: AtomicBool::new(false),
    }))
}

/// The microVM as an [`IsolatedEnv`]: the reference implementation. It keeps the
/// concrete [`super::vm::VmBackend`] rather than only the trait object because undo
/// points are a pool operation (`VmManager::snapshot`/`restore`), not an
/// `ExecBackend` one.
struct VmEnv {
    be: super::vm::VmBackend,
    /// Host workspace the VM copies (`VmBackend::workspace`: the project, or the
    /// private copy an untrusted tier gets).
    workspace: PathBuf,
    level: IsolationLevel,
    provider: Option<String>,
    warning: Option<String>,
    microvm: bool,
    snapshots: bool,
    broker: bool,
    freed: AtomicBool,
}

impl IsolatedEnv for VmEnv {
    fn caps(&self) -> EnvCaps {
        EnvCaps {
            id: "vm".into(),
            level: self.level,
            provider: self.provider.clone(),
            warning: self.warning.clone(),
            // A namespace fallback sees the host's bind mounts; a real VM works on a copy.
            workspace_copy: !self.be.shares_host_fs(),
            snapshots: self.snapshots,
            broker: self.broker,
            uid: self.microvm.then_some(AGENT_UID),
        }
    }
    fn run(&self, spec: &EnvSpec) -> Result<EnvOutcome, String> {
        run_in(&self.be, spec)
    }
    fn put_file(&self, rel: &str, data: &[u8]) -> Result<(), String> {
        put_in(&self.workspace, "vm", rel, data)
    }
    fn get_file(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        get_in(&self.workspace, "vm", rel)
    }
    fn snapshot(&self, reason: &str) -> Result<Option<String>, String> {
        if !self.microvm {
            return Ok(None);
        }
        Ok(self.be.snapshot(reason)?.map(|m| m.name))
    }
    fn undo(&self, name: Option<&str>) -> Result<Option<String>, String> {
        if !self.microvm {
            return Ok(None);
        }
        Ok(self.be.restore(name)?.map(|m| m.name))
    }
    fn free(&self) {
        if self.freed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Stops this session's VM(s) through the pool; snapshots stay on disk, and
        // no other session's VM is touched (the key is derived from tier + session).
        ExecBackend::cleanup(&self.be);
    }
}

// ───────────── the generic adapter ─────────────

/// Any `ExecBackend` as an [`IsolatedEnv`]. It claims no undo points: only the
/// microVM has a snapshot stack, and inventing one for a container would be the
/// fake `Some` the interface forbids.
struct BackendEnv {
    backend: Arc<dyn ExecBackend>,
    name: String,
    workspace: PathBuf,
    level: IsolationLevel,
    warning: Option<String>,
    freed: AtomicBool,
}

impl IsolatedEnv for BackendEnv {
    fn caps(&self) -> EnvCaps {
        EnvCaps {
            id: self.name.clone(),
            level: self.level,
            provider: None,
            warning: self.warning.clone(),
            workspace_copy: !self.backend.shares_host_fs(),
            snapshots: false,
            broker: false,
            uid: match self.name.as_str() {
                "local" | "landlock" | "seatbelt" => current_uid(),
                _ => None,
            },
        }
    }
    fn run(&self, spec: &EnvSpec) -> Result<EnvOutcome, String> {
        run_in(self.backend.as_ref(), spec)
    }
    fn put_file(&self, rel: &str, data: &[u8]) -> Result<(), String> {
        put_in(&self.workspace, &self.name, rel, data)
    }
    fn get_file(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        get_in(&self.workspace, &self.name, rel)
    }
    fn snapshot(&self, _reason: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn undo(&self, _name: Option<&str>) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn free(&self) {
        if self.freed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Containers, remote sandboxes and per-scope state this backend created;
        // `cleanup` removes by its own scope name, never by label-wide pruning.
        self.backend.cleanup();
    }
}

// ───────────── shared mechanics ─────────────

const STREAM_MARK: &str = "__ARK_UNIFY_STREAMS__";

/// The preamble that splits the two output streams.
///
/// The script runs in a subshell whose stdout/stderr are files inside the
/// environment (so a command's `exit` cannot skip the collection), then the byte
/// counts are printed on one marker line followed by the two streams and the exit
/// code of the subshell. Reading it back is [`split_streams`]; everything the
/// environment adds around the script (a failed redirect, a shell warning) ends up
/// in front of the marker and is kept as stdout.
fn wrap_script(script: &str, out: &str, err: &str) -> String {
    let (o, e) = (sh_quote(out), sh_quote(err));
    format!(
        "(\n{script}\n) >{o} 2>{e}\n\
         rc=$?\n\
         s1=$(wc -c <{o} 2>/dev/null || echo 0)\n\
         s2=$(wc -c <{e} 2>/dev/null || echo 0)\n\
         printf '\\n{STREAM_MARK} %s %s\\n' \"$s1\" \"$s2\"\n\
         cat {o} 2>/dev/null\n\
         cat {e} 2>/dev/null\n\
         rm -f {o} {e}\n\
         exit $rc\n"
    )
}

/// Two unique paths inside the environment for one command's streams.
fn stream_paths(backend: &dyn ExecBackend) -> (String, String) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = backend.temp_dir();
    let dir = dir.trim_end_matches('/');
    let tag = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
    (format!("{dir}/.seagent-unify-{tag}.out"), format!("{dir}/.seagent-unify-{tag}.err"))
}

/// Split what [`wrap_script`] printed into the two real streams.
///
/// Documented fallback: if the marker is absent (a shell that could not run the
/// preamble at all) everything read is reported as stdout with an empty stderr —
/// the same answer a merged-stream backend gives, and no pretending.
fn split_streams(merged: &[u8]) -> EnvOutcome {
    let mut pos = 0usize;
    while pos < merged.len() {
        let end = merged[pos..].iter().position(|b| *b == b'\n').map(|n| pos + n).unwrap_or(merged.len());
        let line = &merged[pos..end];
        if let Some(sizes) = parse_marker(line) {
            let body = &merged[(end + 1).min(merged.len())..];
            let n1 = sizes.0.min(body.len());
            let n2 = sizes.1.min(body.len() - n1);
            // Pre-marker output is the environment's own diagnostics; it is not the
            // command's stdout, so it keeps its place *before* it, without the
            // newline the preamble printed to start the marker on a fresh line.
            let mut preamble = merged[..pos].to_vec();
            if preamble.last() == Some(&b'\n') {
                preamble.pop();
            }
            preamble.extend_from_slice(&body[..n1]);
            return EnvOutcome { stdout: preamble, stderr: body[n1..n1 + n2].to_vec(), ..Default::default() };
        }
        pos = end + 1;
    }
    EnvOutcome { stdout: merged.to_vec(), stderr: Vec::new(), ..Default::default() }
}

fn parse_marker(line: &[u8]) -> Option<(usize, usize)> {
    let text = std::str::from_utf8(line).ok()?;
    let rest = text.strip_prefix(STREAM_MARK)?;
    let mut it = rest.split_whitespace();
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    Some((a, b))
}

/// Read a child to the end, killing it at `deadline`.
///
/// Deliberately not `exec::drain`: a timeout there is an `Err`, and for this
/// interface it is a *result* (`timed_out`), because the caller asked for "at most
/// this long" rather than for a diagnosis.
fn supervise(mut child: Box<dyn ExecChild>, timeout: Duration) -> Result<(Option<ExitInfo>, Vec<u8>, bool), String> {
    let deadline = Instant::now() + timeout.max(Duration::from_millis(100));
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let mut quiet = false;
        match child.read(&mut buf, Duration::from_millis(50)) {
            Ok(0) => quiet = true,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            // Some backends report "nothing yet" as an error rather than 0 bytes.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => quiet = true,
            Err(e) => return Err(format!("reading the command's output: {e}")),
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Whatever the pipe still holds belongs to this command.
                let until = Instant::now() + Duration::from_secs(1);
                while Instant::now() < until {
                    match child.read(&mut buf, Duration::from_millis(20)) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                    }
                }
                return Ok((Some(status), out, false));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("waiting for the command: {e}")),
        }
        if Instant::now() >= deadline {
            child.kill(true);
            return Ok((None, out, true));
        }
        if quiet {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Run one spec through an `ExecBackend`.
///
/// The environment is bound to the workspace it was opened on, so `spec.workspace`
/// is not used to re-target the command: an untrusted tier's microVM copies the
/// caller's workspace, it never mounts it.
fn run_in(backend: &dyn ExecBackend, spec: &EnvSpec) -> Result<EnvOutcome, String> {
    let (out, err) = stream_paths(backend);
    let req = ExecRequest { script: wrap_script(&spec.script, &out, &err), cwd: spec.cwd.clone(), env: spec.env.clone(), ..Default::default() };
    backend.before_exec()?;
    let child = backend.spawn(&req).map_err(|e| format!("{}: {e}", backend.id()))?;
    let (status, merged, timed_out) = supervise(child, spec.timeout)?;
    // The wrapper's own `rm -f` never runs when the command was killed (timeout, cancel). The
    // names carry this process's pid and a sequence number, so removing them host-side is safe and
    // is what keeps a local backend's temp directory clean; a remote environment just has no such path.
    let _ = (std::fs::remove_file(&out), std::fs::remove_file(&err));
    let mut outcome = split_streams(&merged);
    outcome.exit = status.and_then(|s| s.code);
    outcome.timed_out = timed_out;
    // Copy-based backends pull their workspace after the command. Failing to sync
    // back is not "the command did not run": it is appended to stderr so the output
    // and the exit code survive, and the caller still sees that something is off.
    if let Err(e) = backend.after_exec() {
        outcome.stderr.extend(format!("\n[seagent: could not sync the workspace back: {e}]").into_bytes());
    }
    Ok(outcome)
}

/// Write one file into the environment's workspace (the host side for copy-based
/// backends: the next `run` pushes it).
fn put_in(workspace: &Path, name: &str, rel: &str, data: &[u8]) -> Result<(), String> {
    let path = safe_host_path(workspace, rel).ok_or_else(|| format!("{name}: refusing to write `{rel}`: a relative path inside the workspace is required (no `..`, no absolute path, no symlinked parent)"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{name}: create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, data).map_err(|e| format!("{name}: write {}: {e}", path.display()))
}

/// Read one file back from the environment's workspace.
fn get_in(workspace: &Path, name: &str, rel: &str) -> Result<Option<Vec<u8>>, String> {
    let path = safe_host_path(workspace, rel).ok_or_else(|| format!("{name}: refusing to read `{rel}`: a relative path inside the workspace is required (no `..`, no absolute path, no symlinked parent)"))?;
    match std::fs::read(&path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{name}: read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmpdir;

    fn ctx(tag: &str) -> BackendCtx {
        let d = tmpdir(tag);
        BackendCtx { workspace: d.join("ws"), scope_key: "unify-t".into(), secrets: Arc::new(|s: &str| s.to_string()), home: d.join("home"), sandboxed: false }
    }

    #[test]
    fn the_wrapper_splits_two_streams_byte_exactly() {
        let script = wrap_script("printf 'a\\nb\\n'; printf 'e1\\ne2\\n' >&2; exit 3", "/tmp/o", "/tmp/e");
        assert!(script.starts_with("(\n"), "the command runs in a subshell: {script}");
        assert!(script.contains("/tmp/o") && script.contains("/tmp/e"));
        let merged = format!("\n{STREAM_MARK} 4 6\na\nb\ne1\ne2\n");
        let out = split_streams(merged.as_bytes());
        assert_eq!(out.stdout, b"a\nb\n");
        assert_eq!(out.stderr, b"e1\ne2\n");
        // A backend that ran nothing of the preamble: one merged stream, admitted.
        let out = split_streams(b"plain output\n");
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice()), (b"plain output\n".as_slice(), b"".as_slice()));
        // Shell noise before the marker is kept, in front of stdout.
        let out = split_streams(format!("bash: cannot create /tmp/o: read-only\n\n{STREAM_MARK} 2 0\nhi").as_bytes());
        assert_eq!(out.stdout, b"bash: cannot create /tmp/o: read-only\nhi");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn caps_come_from_the_one_table_and_an_unknown_name_is_an_error() {
        let c = ctx("caps");
        for name in BACKENDS.iter().filter(|n| **n != AUTO) {
            let caps = caps_of(name, &ExecConfig::default(), &c).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(caps.id, *name);
            assert_eq!(caps.level, isolation_of_backend(name), "{name}");
            if caps.level != IsolationLevel::MicroVm {
                assert!(caps.warning.as_deref().is_some_and(|w| !w.is_empty()), "{name} must warn: {caps:?}");
            }
        }
        assert!(caps_of("nope", &ExecConfig::default(), &c).unwrap_err().contains("unknown exec backend"));
        assert!(caps_of("", &ExecConfig::default(), &c).is_err());
        // `auto` answers with a level from the same table, and warns when it is not a microVM.
        let a = caps_of(AUTO, &ExecConfig::default(), &c).unwrap();
        assert_eq!(a.level, isolation_of_backend(&a.id), "{a:?}");
        assert!(a.level == IsolationLevel::MicroVm || a.warning.is_some(), "{a:?}");
        let text = describe_names(&ExecConfig::default(), &c);
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("--- seagent sandbox explain (names only) ---\n{text}\n--- end ---\n").as_bytes());
        assert!(text.lines().count() == BACKENDS.len() + 1, "{text}");
    }

    #[test]
    fn put_and_get_stay_inside_the_workspace() {
        let c = ctx("files");
        std::fs::create_dir_all(&c.workspace).unwrap();
        let local = open("local", &ExecConfig::default(), &c).unwrap();
        local.put_file("sub/dir/x.txt", b"hello").unwrap();
        assert_eq!(local.get_file("sub/dir/x.txt").unwrap().as_deref(), Some(b"hello".as_slice()));
        assert_eq!(local.get_file("missing.txt").unwrap(), None);
        assert!(local.put_file("../escape", b"x").is_err());
        assert!(local.put_file("/etc/passwd", b"x").is_err());
        assert!(!c.workspace.join("../escape").exists());
    }
}
