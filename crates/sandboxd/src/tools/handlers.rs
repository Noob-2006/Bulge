//! Runtime command handlers for the file tools.
//!
//! Relative paths resolve against `/workspace`. The VM is the security
//! boundary, so absolute guest paths are allowed (e.g. spill files in
//! `/run/bulge/spill`); host paths simply do not exist in here.

use std::path::{Path, PathBuf};

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::process::Command;

use super::edit::{EditError, apply_edit};
use super::read::{Page, ReadError, read_page};
use super::truncate::{Limits, bound_output};
use crate::runtime::{HandlerError, InvocationContext};
use crate::setup::{WORKSPACE, WORKSPACE_LOWER, WORKSPACE_UPPER};

pub const SPILL_DIR: &str = "/run/bulge/spill";
/// Largest single file `export_changes` will carry back to the host.
const MAX_EXPORT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GLOB_RESULTS: usize = 1000;

fn resolve(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() { path.to_path_buf() } else { Path::new(WORKSPACE).join(path) }
}

fn params<T: for<'de> Deserialize<'de>>(cx: &InvocationContext) -> Result<T, HandlerError> {
    serde_json::from_value(cx.invocation.params.clone()).map_err(|e| HandlerError::new("INVALID_PARAMS", e.to_string()))
}

fn io_error(e: impl std::fmt::Display) -> HandlerError {
    HandlerError::new("IO_ERROR", e.to_string())
}

/// Bound text for the model, spilling the rest to a guest file.
pub fn bounded(text: &str) -> Result<Value, HandlerError> {
    let b = bound_output(text, Limits::default(), Path::new(SPILL_DIR)).map_err(io_error)?;
    Ok(json!({
        "text": b.text,
        "truncated": b.truncated,
        "spill_path": b.spill_path,
        "total_lines": b.total_lines,
        "total_bytes": b.total_bytes,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadParams {
    path: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

pub async fn read(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: ReadParams = params(&cx)?;
    let path = resolve(&p.path);
    let page = tokio::task::spawn_blocking(move || read_page(&path, p.offset, p.limit)).await.map_err(io_error)?;
    match page {
        Ok(Page::Text { text, total_lines, next_offset }) => {
            Ok(json!({ "kind": "text", "text": text, "total_lines": total_lines, "next_offset": next_offset }))
        }
        Ok(Page::Directory { entries, total, next_offset }) => {
            Ok(json!({ "kind": "directory", "entries": entries, "total": total, "next_offset": next_offset }))
        }
        Err(ReadError::NotFound(p)) => Err(HandlerError::new("NOT_FOUND", p)),
        Err(ReadError::Binary(p)) => Err(HandlerError::new("BINARY_FILE", p)),
        Err(e @ ReadError::OffsetPastEnd { .. }) => Err(HandlerError::new("OFFSET_PAST_END", e.to_string())),
        Err(ReadError::Io(e)) => Err(io_error(e)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteParams {
    path: String,
    content: String,
}

pub async fn write(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: WriteParams = params(&cx)?;
    let path = resolve(&p.path);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
    }
    let existed = tokio::fs::try_exists(&path).await.unwrap_or(false);
    tokio::fs::write(&path, p.content.as_bytes()).await.map_err(io_error)?;
    Ok(json!({ "path": path, "created": !existed, "bytes": p.content.len() }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditParams {
    path: String,
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
}

pub async fn edit(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: EditParams = params(&cx)?;
    let path = resolve(&p.path);
    let content = tokio::fs::read_to_string(&path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => HandlerError::new("NOT_FOUND", path.display().to_string()),
        _ => io_error(e),
    })?;
    let outcome = apply_edit(&content, &p.old_string, &p.new_string, p.replace_all).map_err(|e| {
        let code = match e {
            EditError::EmptyOldString | EditError::NoChange => "INVALID_PARAMS",
            EditError::NotFound => "NO_MATCH",
            EditError::Ambiguous(_) => "AMBIGUOUS_MATCH",
        };
        HandlerError::new(code, e.to_string())
    })?;
    tokio::fs::write(&path, outcome.content.as_bytes()).await.map_err(io_error)?;
    Ok(json!({ "path": path, "replacements": outcome.replacements }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobParams {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
}

/// File names matching a glob, via ripgrep (respects .gitignore), sorted.
pub async fn glob(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: GlobParams = params(&cx)?;
    let root = resolve(p.path.as_deref().unwrap_or("."));
    let output = Command::new("rg")
        .args(["--files", "--hidden", "--glob", "!.git", "--glob", &p.pattern])
        .arg(&root)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(io_error)?;
    let mut files: Vec<String> = String::from_utf8_lossy(&output.stdout).lines().map(str::to_owned).collect();
    files.sort();
    let total = files.len();
    files.truncate(MAX_GLOB_RESULTS);
    Ok(json!({ "files": files, "total": total, "truncated": total > MAX_GLOB_RESULTS }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrepParams {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    case_insensitive: bool,
}

/// `path:line:text` matches via ripgrep, bounded like any other output.
pub async fn grep(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: GrepParams = params(&cx)?;
    let root = resolve(p.path.as_deref().unwrap_or("."));
    let mut command = Command::new("rg");
    command.args(["--line-number", "--no-heading", "--color=never", "--hidden", "--glob", "!.git"]);
    if p.case_insensitive {
        command.arg("--ignore-case");
    }
    if let Some(glob) = &p.glob {
        command.args(["--glob", glob]);
    }
    command.arg("--regexp").arg(&p.pattern).arg(&root).kill_on_drop(true);
    let output = command.output().await.map_err(io_error)?;
    // rg: 0 = matches, 1 = none, 2 = error.
    if output.status.code() == Some(2) {
        return Err(HandlerError::new("GREP_FAILED", String::from_utf8_lossy(&output.stderr).into_owned()));
    }
    bounded(&String::from_utf8_lossy(&output.stdout))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportParams {
    paths: Vec<String>,
}

/// Contents of changed workspace entries (relative paths from `changes`),
/// read from the overlay upper dir so only guest-made changes are exported.
pub async fn export_changes(cx: InvocationContext) -> Result<Value, HandlerError> {
    let p: ExportParams = params(&cx)?;
    tokio::task::spawn_blocking(move || {
        let mut files = Vec::with_capacity(p.paths.len());
        for rel in p.paths {
            let rel_path = Path::new(&rel);
            if rel_path.is_absolute() || rel_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(HandlerError::new("INVALID_PATH", rel));
            }
            let upper = Path::new(WORKSPACE_UPPER).join(rel_path);
            let meta = std::fs::symlink_metadata(&upper).map_err(io_error)?;
            let entry = if meta.file_type().is_symlink() {
                json!({ "path": rel, "kind": "symlink", "target": std::fs::read_link(&upper).map_err(io_error)? })
            } else if meta.is_file() {
                if meta.len() > MAX_EXPORT_FILE_BYTES {
                    json!({ "path": rel, "kind": "too_large", "size": meta.len() })
                } else {
                    let data = std::fs::read(&upper).map_err(io_error)?;
                    let lower = Path::new(WORKSPACE_LOWER).join(rel_path);
                    json!({
                        "path": rel,
                        "kind": "file",
                        "executable": std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o111 != 0,
                        "existed": lower.exists(),
                        "data_b64": base64::engine::general_purpose::STANDARD.encode(&data),
                    })
                }
            } else if meta.is_dir() {
                json!({ "path": rel, "kind": "dir" })
            } else {
                json!({ "path": rel, "kind": "deleted" })
            };
            files.push(entry);
        }
        Ok(json!({ "files": files }))
    })
    .await
    .map_err(io_error)?
}
