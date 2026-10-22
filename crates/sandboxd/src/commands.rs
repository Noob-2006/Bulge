//! Built-in guest commands.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::runtime::{HandlerError, InvocationContext};
use crate::setup::{WORKSPACE, WORKSPACE_LOWER, WORKSPACE_UPPER};

/// Hard per-stream read cap (memory bound); what the model sees is further
/// bounded by `tools::handlers::bounded`, which spills the full text to a file.
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecParams {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
}

fn bad_params(error: impl std::fmt::Display) -> HandlerError {
    HandlerError::new("INVALID_PARAMS", error.to_string())
}

/// `sh -c <command>` in the workspace. Cancellation (timeout or host cancel) kills it.
pub async fn exec(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: ExecParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let cwd = params.cwd.unwrap_or_else(|| WORKSPACE.to_owned());
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(&params.command)
        .current_dir(&cwd)
        // The daemon already runs unprivileged; give commands a writable HOME on
        // the tmpfs so tools that need one (git, pip, npm) work without root.
        .env("HOME", crate::setup::AGENT_HOME)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Outbound access, if any, is only through the two-key egress proxy.
    if let Some(proxy) = crate::EGRESS_PROXY.get() {
        command.env("HTTPS_PROXY", proxy).env("https_proxy", proxy).env("ALL_PROXY", proxy);
        // Local traffic (a dev server the agent started and then tests) must not
        // be sent to the CONNECT-only egress proxy.
        command.env("NO_PROXY", "127.0.0.1,localhost,::1").env("no_proxy", "127.0.0.1,localhost,::1");
    }
    let mut child = command.spawn().map_err(|e| HandlerError::new("SPAWN_FAILED", e.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| HandlerError::new("SPAWN_FAILED", "no stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| HandlerError::new("SPAWN_FAILED", "no stderr"))?;
    let collect = async {
        let (out, err, status) = tokio::join!(capped(stdout), capped(stderr), child.wait());
        (out, err, status)
    };
    let (out, err, status) = tokio::select! {
        result = collect => result,
        () = cx.cancellation.cancelled() => return Err(HandlerError::new("CANCELLED", "command cancelled")),
    };
    let status = status.map_err(|e| HandlerError::new("WAIT_FAILED", e.to_string()))?;
    Ok(json!({
        "exit_code": status.code(),
        "stdout": crate::tools::handlers::bounded(&out.0)?,
        "stdout_dropped_bytes": out.1,
        "stderr": crate::tools::handlers::bounded(&err.0)?,
        "stderr_dropped_bytes": err.1,
    }))
}

/// Read a stream fully, keeping the first `MAX_STREAM_BYTES` (lossy UTF-8)
/// and counting the rest.
async fn capped(mut stream: impl tokio::io::AsyncRead + Unpin) -> (String, u64) {
    let mut kept = Vec::new();
    let mut dropped = 0u64;
    let mut buf = [0u8; 8192];
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let room = MAX_STREAM_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&buf[..n.min(room)]);
        dropped += (n - n.min(room)) as u64;
    }
    (String::from_utf8_lossy(&kept).into_owned(), dropped)
}

/// What the base layer (the layer below an upper dir) contains at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseEntry {
    /// Nothing in the base: a file in the upper dir is `added`.
    Absent,
    /// A regular file in the base, which may hold identical contents.
    File(PathBuf),
    /// Anything else that exists in the base (directory, symlink, ...).
    Other(PathBuf),
}

impl BaseEntry {
    pub fn absent() -> Self {
        Self::Absent
    }

    /// Classify an existing path by the metadata already obtained for it.
    pub fn from_metadata(path: PathBuf, meta: &std::fs::Metadata) -> Self {
        if meta.file_type().is_file() { Self::File(path) } else { Self::Other(path) }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Absent => None,
            Self::File(path) | Self::Other(path) => Some(path),
        }
    }

    pub fn exists(&self) -> bool {
        !matches!(self, Self::Absent)
    }

    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::File(path) => Some(path),
            _ => None,
        }
    }
}

/// Base lookup for the main workspace: the read-only host share.
pub fn host_base_entry(lower: &Path, rel: &Path) -> BaseEntry {
    let path = lower.join(rel);
    match std::fs::metadata(&path) {
        Ok(meta) => BaseEntry::from_metadata(path, &meta),
        Err(_) => BaseEntry::Absent,
    }
}

/// List workspace changes held in the overlay upper dir:
/// `added` / `modified` regular files, `deleted` (whiteouts), `symlink`, `dir`.
pub async fn changes(_cx: InvocationContext) -> Result<Value, HandlerError> {
    tokio::task::spawn_blocking(|| {
        let base = |rel: &Path| host_base_entry(Path::new(WORKSPACE_LOWER), rel);
        let mut out = walk_changes(Path::new(WORKSPACE_UPPER), &base).map_err(|e| HandlerError::new("WALK_FAILED", e.to_string()))?;
        out.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(json!({ "changes": out }))
    })
    .await
    .map_err(|e| HandlerError::new("WALK_FAILED", e.to_string()))?
}

/// Walk an overlay upper dir and describe its pending changes against `base`.
///
/// The caller supplies what the base layer contains at each workspace-relative
/// path: the host share for the main workspace, or the slot's snapshot-over-host
/// layer for a slot. `upper` must be the upper directory itself.
pub fn walk_changes(upper: &Path, base: &dyn Fn(&Path) -> BaseEntry) -> std::io::Result<Vec<Value>> {
    let mut out = Vec::new();
    walk(upper, Path::new(""), base, &mut out)?;
    Ok(out)
}

fn walk(upper: &Path, rel: &Path, base: &dyn Fn(&Path) -> BaseEntry, out: &mut Vec<Value>) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    for entry in std::fs::read_dir(upper.join(rel))? {
        let entry = entry?;
        let rel_path: PathBuf = rel.join(entry.file_name());
        let meta = entry.metadata()?;
        let base_entry = base(&rel_path);
        let path = rel_path.to_string_lossy().into_owned();
        let ft = meta.file_type();
        if ft.is_char_device() && meta.rdev() == 0 {
            if !base_entry.exists() {
                continue; // already deleted on the host
            }
            out.push(json!({ "path": path, "kind": "deleted" }));
        } else if ft.is_dir() {
            if !base_entry.exists() {
                out.push(json!({ "path": path, "kind": "dir" }));
            }
            walk(upper, &rel_path, base, out)?;
        } else if ft.is_symlink() {
            out.push(json!({ "path": path, "kind": "symlink" }));
        } else if ft.is_file() {
            if let Some(base_file) = base_entry.file_path()
                && same_contents(&upper.join(&rel_path), base_file)
            {
                continue; // already applied on the host
            }
            let kind = if base_entry.exists() { "modified" } else { "added" };
            out.push(json!({ "path": path, "kind": kind, "size": meta.len() }));
        }
    }
    Ok(())
}

fn same_contents(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) if ma.len() == mb.len() => std::fs::read(a).ok() == std::fs::read(b).ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("bulge-walk-{}-{label}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn walk_changes_main_mode_lists_added_and_modified_but_skips_unchanged() {
        let upper = TempDir::new("upper");
        let lower = TempDir::new("lower");
        std::fs::write(lower.path().join("same.txt"), b"same\n").unwrap();
        std::fs::write(upper.path().join("same.txt"), b"same\n").unwrap();
        std::fs::write(lower.path().join("modified.txt"), b"old\n").unwrap();
        std::fs::write(upper.path().join("modified.txt"), b"new\n").unwrap();
        std::fs::write(upper.path().join("added.txt"), b"added\n").unwrap();

        let base = |rel: &Path| host_base_entry(lower.path(), rel);
        let mut changes = walk_changes(upper.path(), &base).unwrap();
        changes.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        let listed: Vec<(String, String)> = changes
            .iter()
            .map(|change| {
                (
                    change["path"].as_str().unwrap().to_owned(),
                    change["kind"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("added.txt".to_owned(), "added".to_owned()),
                ("modified.txt".to_owned(), "modified".to_owned()),
            ]
        );
    }
}
