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
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(&params.command)
        .current_dir(&cwd)
        // The daemon already runs unprivileged; give commands a writable HOME on
        // the tmpfs so tools that need one (git, pip, npm) work without root.
        .env("HOME", crate::setup::AGENT_HOME)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| HandlerError::new("SPAWN_FAILED", e.to_string()))?;
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

/// List workspace changes held in the overlay upper dir:
/// `added` / `modified` regular files, `deleted` (whiteouts), `symlink`, `dir`.
pub async fn changes(_cx: InvocationContext) -> Result<Value, HandlerError> {
    tokio::task::spawn_blocking(|| {
        let mut out = Vec::new();
        walk(Path::new(WORKSPACE_UPPER), Path::new(""), &mut out).map_err(|e| HandlerError::new("WALK_FAILED", e.to_string()))?;
        out.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(json!({ "changes": out }))
    })
    .await
    .map_err(|e| HandlerError::new("WALK_FAILED", e.to_string()))?
}

fn walk(upper: &Path, rel: &Path, out: &mut Vec<Value>) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    for entry in std::fs::read_dir(upper.join(rel))? {
        let entry = entry?;
        let rel_path: PathBuf = rel.join(entry.file_name());
        let meta = entry.metadata()?;
        let lower = Path::new(WORKSPACE_LOWER).join(&rel_path);
        let path = rel_path.to_string_lossy().into_owned();
        let ft = meta.file_type();
        if ft.is_char_device() && meta.rdev() == 0 {
            if !lower.exists() {
                continue; // already deleted on the host
            }
            out.push(json!({ "path": path, "kind": "deleted" }));
        } else if ft.is_dir() {
            if !lower.exists() {
                out.push(json!({ "path": path, "kind": "dir" }));
            }
            walk(upper, &rel_path, out)?;
        } else if ft.is_symlink() {
            out.push(json!({ "path": path, "kind": "symlink" }));
        } else if ft.is_file() {
            if lower.is_file() && same_contents(&upper.join(&rel_path), &lower) {
                continue; // already applied on the host
            }
            let kind = if lower.exists() { "modified" } else { "added" };
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
