#![cfg_attr(not(unix), allow(dead_code, unused_imports))]
use seagent_core::tool::SpawnRequest;
use seagent_core::{Cancel, ToolCtx, ToolHost};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A scratch dir for one test: `seagent-tools-<tag>-*`, removed when the test's thread ends
/// (`seagent_core::tmp::scratch`), so the suite no longer leaves a tree behind per call.
pub fn tmpdir(tag: &str) -> PathBuf {
    seagent_core::tmp::scratch(&format!("seagent-tools-{tag}"))
}

/// The bash that plays a POSIX remote in the fake-backend tests: `bash` on Unix (as always),
/// Git Bash / MSYS2 on Windows (never `System32\bash.exe`, which is WSL with other files).
pub fn remote_bash() -> std::process::Command {
    #[cfg(unix)]
    return std::process::Command::new("bash");
    #[cfg(not(unix))]
    return std::process::Command::new(seagent_core::platform::layout::bash().expect("Git Bash / MSYS2 bash for the remote fakes"));
}

/// A local directory as that remote spells it: unchanged on Unix, `/c/Users/…` on Windows.
pub fn remote_path(p: &std::path::Path) -> String {
    #[cfg(unix)]
    return p.display().to_string();
    #[cfg(not(unix))]
    return format!("/{}", crate::exec::sync::windows_remote_rel(p));
}

/// The reverse of [`remote_path`]: where a remote path (`/tmp/x`, `/c/Users/…`) is on this
/// host. Unix: the same path; Windows: `cygpath -w` from that bash.
pub fn local_of_remote(p: &str) -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from(p);
    #[cfg(not(unix))]
    {
        let o = remote_bash().arg("-c").arg("cygpath -w \"$1\"").arg("cygpath").arg(p).output().expect("cygpath");
        PathBuf::from(String::from_utf8_lossy(&o.stdout).trim())
    }
}

/// Point `HOME` at a test tree for the duration, restoring it on drop. Tests that exercise
/// `~` expansion / credential upload must not read or write the real home directory.
pub struct HomeGuard(Option<std::ffi::OsString>);
impl Drop for HomeGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
pub fn test_home(home: &std::path::Path) -> HomeGuard {
    let old = std::env::vars_os().find(|(k, _)| k == "HOME").map(|(_, v)| v);
    std::env::set_var("HOME", home);
    HomeGuard(old)
}

#[derive(Default)]
pub struct FakeHost {
    pub spawned: Mutex<Vec<SpawnRequest>>,
    pub fail: bool,
}

impl ToolHost for FakeHost {
    fn spawn_agent(&self, req: SpawnRequest, _c: &Cancel) -> Result<String, String> {
        let task = req.task.clone();
        self.spawned.lock().unwrap().push(req);
        if self.fail {
            Err("child agent exceeded budget".into())
        } else {
            Ok(format!("done: {task}"))
        }
    }
    fn ask_user(&self, q: &str) -> Result<String, String> {
        if self.fail {
            Err("no human attached (headless)".into())
        } else {
            Ok(format!("answer to {q}"))
        }
    }
}

pub fn ctx_with(ws: PathBuf, host: Arc<dyn ToolHost>) -> ToolCtx {
    // Unique per context: file-tool read tracking is keyed by session.
    let session_id = format!("s-{}", ws.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    ToolCtx {
        artifacts: ws.join(".artifacts"),
        home: ws.join(".home"),
        workspace: ws,
        session_id,
        cancel: Cancel::new(),
        host,
        secrets: Arc::new(|s: &str| s.replace("{{secret:TOKEN}}", "s3cr3t")),
    }
}

pub fn ctx(tag: &str) -> ToolCtx {
    ctx_with(tmpdir(tag), Arc::new(FakeHost::default()))
}
