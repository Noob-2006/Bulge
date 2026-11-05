//! One interface for every isolated environment (B6).
//!
//! ark grew a dozen ways to run a tool call away from the host: a microVM, two
//! namespace sandboxes, three container runtimes, an ssh host and four cloud
//! sandboxes. They all implement [`ark_core::exec::ExecBackend`] — good for the
//! shell tool, which only needs "a process with merged output" — but that trait
//! cannot answer the questions the rest of ark asks: *what wall is this?*, *may
//! files be dropped in by path?*, *is there an undo point?*, *what uid does the
//! work run as?*.
//!
//! [`IsolatedEnv`] is that interface. It is defined **here**, in `ark-vm`, and not
//! in `ark-tools`, so the microVM — the reference implementation — owns its shape
//! and no dependency on the tool layer is created (the adapters over the other
//! backends live in `ark-tools::exec::unify`).
//!
//! Three rules, all §0 ("isolation instead of asking") in nature:
//!
//! * **No lying about the floor.** [`EnvCaps::level`] is the wall the environment
//!   actually provides; [`EnvCaps::warning`] carries the sentence a weaker one
//!   owes the operator. A microVM is the only level with nothing to warn about.
//! * **No fake undo.** [`IsolatedEnv::snapshot`] returns `Ok(None)` when the
//!   environment cannot snapshot — never a made-up name that `undo` would then
//!   fail to honour.
//! * **Honest file transfer.** [`EnvCaps::workspace_copy`] says whether files are
//!   copies (pushed before a command, pulled after) or the host's own directory
//!   seen through a bind mount; the caller must not assume either.

use crate::isolation::IsolationLevel;
use crate::trust::TrustTier;
use std::path::PathBuf;
use std::time::Duration;

/// One command, and where it should run.
///
/// `cwd` is a **host** path inside `workspace`; the environment maps it into its
/// own view (the microVM turns it into `/workspace/<rel>`, a container into its
/// workdir). `env` is the already-sanitised environment the caller wants the
/// command to see — each adapter still owns the final filtering, so a secret
/// never crosses a boundary because a caller asked nicely.
#[derive(Debug, Clone)]
pub struct EnvSpec {
    /// The workspace the command works on (host path). An environment is opened
    /// *for* one workspace, so this is normally the directory it was opened on; a
    /// run never re-targets an environment to a different one.
    pub workspace: PathBuf,
    /// Provenance of the work; environments that separate tiers use it to pick a
    /// VM / container, and untrusted work never gets the owner's workspace.
    pub tier: TrustTier,
    /// A complete shell script (the caller already wrapped it).
    pub script: String,
    /// Working directory, as a host path inside `workspace`.
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Wall-clock ceiling; on expiry the command is killed and
    /// [`EnvOutcome::timed_out`] is set (never an error: a timeout is a result).
    pub timeout: Duration,
}

impl EnvSpec {
    pub fn new(workspace: impl Into<PathBuf>, tier: TrustTier, script: impl Into<String>, timeout: Duration) -> EnvSpec {
        EnvSpec { workspace: workspace.into(), tier, script: script.into(), cwd: None, env: vec![], timeout }
    }
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> EnvSpec {
        self.cwd = Some(cwd.into());
        self
    }
    pub fn with_env(mut self, env: Vec<(String, String)>) -> EnvSpec {
        self.env = env;
        self
    }
}

/// What one command produced. `stdout` and `stderr` are kept apart where the
/// environment can tell them apart; an environment that can only hand back one
/// merged stream reports it as `stdout` and leaves `stderr` empty (documented per
/// adapter, never guessed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvOutcome {
    /// Exit code; `None` when the command died of a signal or was killed for its
    /// timeout.
    pub exit: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl EnvOutcome {
    pub fn success(&self) -> bool {
        self.exit == Some(0)
    }
    /// Lossy text of both streams, stdout first — for logs and assertions.
    pub fn text(&self) -> String {
        let mut s = String::from_utf8_lossy(&self.stdout).to_string();
        s.push_str(&String::from_utf8_lossy(&self.stderr));
        s
    }
}

/// What an environment *is*, in the terms the rest of ark asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvCaps {
    /// Wire name of the backend that serves this environment (`vm`, `bwrap`, …).
    pub id: String,
    /// The wall between the work and the host (the one table,
    /// [`crate::isolation::isolation_of_backend`]).
    pub level: IsolationLevel,
    /// Which implementation inside that level: the VMM (`firecracker`, `qemu`) for
    /// a microVM, the engine for a container. `None` when ark cannot tell.
    pub provider: Option<String>,
    /// The sentence to show the operator when the level is weaker than a microVM;
    /// `None` only for a real microVM with nothing to qualify.
    pub warning: Option<String>,
    /// Files reach the environment by copy + sync, not by sharing the host fs.
    pub workspace_copy: bool,
    /// Can this environment give undo points (`Some(name)` from [`IsolatedEnv::snapshot`])?
    pub snapshots: bool,
    /// Guest→daemon requests (egress, privileged commands) go through a broker
    /// instead of the environment holding a socket or a key.
    pub broker: bool,
    /// uid the work runs as inside, when the environment can tell (microVM: 1000).
    pub uid: Option<u32>,
}

impl EnvCaps {
    /// One line for `ark sandbox explain` / the system prompt.
    pub fn line(&self) -> String {
        let mut s = format!("{}: {}", self.id, self.level.label());
        if let Some(p) = &self.provider {
            s.push_str(&format!(" via {p}"));
        }
        let mut facts: Vec<String> = Vec::new();
        facts.push(if self.workspace_copy { "workspace by copy+sync".into() } else { "host workspace visible".into() });
        if self.snapshots {
            facts.push("snapshots/undo".into());
        }
        if self.broker {
            facts.push("broker (no direct egress)".into());
        }
        if let Some(u) = self.uid {
            facts.push(format!("runs as uid {u}"));
        }
        s.push_str(&format!(" — {}", facts.join(", ")));
        if let Some(w) = &self.warning {
            s.push_str(&format!(" — WARNING: {w}"));
        }
        s
    }
}

/// One isolated environment, whatever implements it.
///
/// Implementations must be usable from several threads: the shell tool and the
/// job reaper do not share a runtime. Everything here is blocking; a long command
/// belongs behind a timeout.
pub trait IsolatedEnv: Send + Sync {
    /// Static description of this environment (no side effects, cheap).
    fn caps(&self) -> EnvCaps;
    /// Run one command to completion (blocking, timeout honoured).
    fn run(&self, spec: &EnvSpec) -> Result<EnvOutcome, String>;
    /// Place a file at `rel` (relative to the workspace) in this environment.
    /// Refuses absolute paths and `..`; a parent that is a symlink is refused too.
    fn put_file(&self, rel: &str, data: &[u8]) -> Result<(), String>;
    /// Read `rel` back; `Ok(None)` when the file does not exist (an unreadable
    /// file or a broken environment is an `Err`, not an empty file).
    fn get_file(&self, rel: &str) -> Result<Option<Vec<u8>>, String>;
    /// Create an undo point. `Ok(None)` when this environment cannot — honest
    /// refusal, never a fake name.
    fn snapshot(&self, reason: &str) -> Result<Option<String>, String>;
    /// Go back to `name` (or the newest undo point when `None`).
    fn undo(&self, name: Option<&str>) -> Result<Option<String>, String>;
    /// Tear the environment down (containers, VMs, remote sandboxes). Must be
    /// idempotent and must only touch what this environment created.
    fn free(&self);
}

/// One line per environment, in the order given — the body of
/// `ark sandbox explain`'s "what would run where" block.
pub fn describe_all(envs: &[&dyn IsolatedEnv]) -> String {
    if envs.is_empty() {
        return "no execution environment".into();
    }
    envs.iter().map(|e| e.caps().line()).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// An environment that cannot snapshot: `snapshot` must say so instead of
    /// inventing a name `undo` would then fail on.
    struct Bare {
        level: IsolationLevel,
        freed: AtomicBool,
    }

    impl IsolatedEnv for Bare {
        fn caps(&self) -> EnvCaps {
            EnvCaps { id: "bare".into(), level: self.level, provider: None, warning: self.level.warning().map(String::from), workspace_copy: false, snapshots: false, broker: false, uid: Some(1000) }
        }
        fn run(&self, spec: &EnvSpec) -> Result<EnvOutcome, String> {
            Ok(EnvOutcome { exit: Some(0), stdout: spec.script.clone().into_bytes(), stderr: vec![], timed_out: false })
        }
        fn put_file(&self, _rel: &str, _data: &[u8]) -> Result<(), String> {
            Err("read-only".into())
        }
        fn get_file(&self, _rel: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        fn snapshot(&self, _reason: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn undo(&self, _name: Option<&str>) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn free(&self) {
            self.freed.store(true, Ordering::SeqCst);
        }
    }

    fn bare(level: IsolationLevel) -> Bare {
        Bare { level, freed: AtomicBool::new(false) }
    }

    #[test]
    fn describe_all_is_one_line_per_environment() {
        let a = bare(IsolationLevel::MicroVm);
        let b = bare(IsolationLevel::UserNamespace);
        let envs: Vec<&dyn IsolatedEnv> = vec![&a, &b];
        let out = describe_all(&envs);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(lines[0].starts_with("bare: microVM"), "{out}");
        assert!(!lines[0].contains("WARNING"), "a microVM has nothing to warn about: {out}");
        assert!(lines[1].contains("user-namespace") && lines[1].contains("WARNING"), "{out}");
        assert!(out.contains("host workspace visible") && out.contains("runs as uid 1000"), "{out}");
        assert_eq!(describe_all(&[]), "no execution environment");
    }

    #[test]
    fn a_timeout_is_a_result_and_an_absent_undo_point_is_none() {
        let e = bare(IsolationLevel::Host);
        let spec = EnvSpec::new("/w", TrustTier::Owner, "echo hi", Duration::from_secs(1)).with_cwd("/w/sub").with_env(vec![("A".into(), "b".into())]);
        assert_eq!(spec.cwd.as_deref(), Some(std::path::Path::new("/w/sub")));
        let out = e.run(&spec).unwrap();
        assert!(out.success() && !out.timed_out && out.text() == "echo hi");
        assert_eq!(e.snapshot("before rm").unwrap(), None, "no fake undo names");
        assert_eq!(e.undo(None).unwrap(), None);
        assert!(!e.freed.load(Ordering::SeqCst));
        e.free();
        assert!(e.freed.load(Ordering::SeqCst));
        e.free();
    }
}
