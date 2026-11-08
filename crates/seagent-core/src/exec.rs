//! Interface: execution backends. The shell, process and code tools never spawn
//! a program themselves; they hand a bash script to the backend selected for the
//! session (local, OS sandbox, container, SSH host, cloud sandbox) and drive the
//! returned child: read its merged output, write stdin, resize its PTY, wait, kill.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// What to run. `script` is a complete bash script (the caller already wrapped
/// it with the session snapshot / cwd markers); backends only transport it.
#[derive(Debug, Clone, Default)]
pub struct ExecRequest {
    pub script: String,
    /// Working directory as a *host* path; the backend maps it into its own view.
    pub cwd: Option<PathBuf>,
    /// Extra environment for the command (already secret-substituted).
    pub env: Vec<(String, String)>,
    /// Keep stdin open as a pipe (or PTY) so the caller can write to it.
    pub stdin: bool,
    /// Bytes fed to stdin right after start (sudo password, heredoc payload).
    pub stdin_data: Option<Vec<u8>>,
    /// Run under a pseudo-terminal of this size (rows, cols).
    pub pty: Option<(u16, u16)>,
    /// `bash -l` instead of `bash -c` (no snapshot yet).
    pub login: bool,
    /// Detach from seagent: own session, no parent-death signal, so the command
    /// survives an seagent restart. Only meaningful for host-side processes.
    pub detach: bool,
    /// Where a detached process writes its output and exit status (host paths).
    pub log_file: Option<PathBuf>,
    pub exit_file: Option<PathBuf>,
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitInfo {
    pub fn code(c: i32) -> Self {
        ExitInfo { code: Some(c), signal: None }
    }
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    /// `exit 3`, `signal 9` — for result footers.
    pub fn describe(&self) -> String {
        match (self.code, self.signal) {
            (Some(c), _) => format!("exit {c}"),
            (None, Some(s)) => format!("killed by signal {s}"),
            _ => "exited abnormally".into(),
        }
    }
}

/// A running command. Output is one merged stream (stdout+stderr, or the PTY).
pub trait ExecChild: Send {
    /// Host pid of the local process carrying the command (the wrapper for
    /// docker/ssh), if there is one.
    fn pid(&self) -> Option<u32>;
    /// Read available output, waiting at most `timeout`. Ok(0) = end of output.
    /// Err(TimedOut/WouldBlock) = nothing yet.
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize>;
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()>;
    fn close_stdin(&mut self);
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>>;
    /// SIGTERM the whole process tree (`force`: SIGKILL).
    fn kill(&mut self, force: bool);
    fn resize(&mut self, _rows: u16, _cols: u16) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "this process has no terminal"))
    }
    fn is_pty(&self) -> bool {
        false
    }
}

/// Where tool calls run. Implementations: seagent-tools `exec::*`.
pub trait ExecBackend: Send + Sync {
    /// `local`, `bwrap`, `landlock`, `docker`, `podman`, `singularity`, `ssh`, `modal`, `daytona`, `vercel`, …
    fn id(&self) -> &str;
    /// One line for the system prompt / `seagent sandbox explain`.
    fn describe(&self) -> String;
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>>;
    /// The path a host workspace path has inside the backend.
    fn map_path(&self, host: &Path) -> String {
        host.display().to_string()
    }
    /// Commands run on this machine with the host's view of the file system
    /// (local, bubblewrap, bind-mounted containers): file tools need no sync.
    fn shares_host_fs(&self) -> bool {
        true
    }
    fn supports_pty(&self) -> bool {
        true
    }
    /// Directory for snapshot / marker files, as seen by the backend.
    fn temp_dir(&self) -> String {
        if cfg!(unix) {
            "/tmp".into()
        } else {
            crate::tmp::system_temp_root().display().to_string()
        }
    }
    /// Push workspace changes before a command (remote backends).
    fn before_exec(&self) -> Result<(), String> {
        Ok(())
    }
    /// Pull changes the command made back into the host workspace.
    fn after_exec(&self) -> Result<(), String> {
        Ok(())
    }
    /// Tear down containers / remote sandboxes.
    fn cleanup(&self) {}
}

/// Picks the backend for a session; installed once by the binary so code mode
/// in the kernel runs where the shell tool runs.
pub type Selector = Arc<dyn Fn(&str, &Path) -> Arc<dyn ExecBackend> + Send + Sync>;

static SELECTOR: RwLock<Option<Selector>> = RwLock::new(None);

pub fn install_selector(s: Selector) {
    *SELECTOR.write().unwrap() = Some(s);
}

/// Drop the selector: `backend_for` reports `None` again (a host tearing exec down, and
/// tests that install a non-local backend must not leak it into later sessions).
pub fn clear_selector() {
    *SELECTOR.write().unwrap() = None;
}

/// The backend for `session` in `workspace`; None when nothing was installed
/// (library use, tests): callers then spawn locally themselves.
pub fn backend_for(session: &str, workspace: &Path) -> Option<Arc<dyn ExecBackend>> {
    SELECTOR.read().unwrap().as_ref().map(|s| s(session, workspace))
}
