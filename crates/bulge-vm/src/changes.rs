//! Workspace change review: collect what the guest changed in its overlay,
//! render it as a diff for approval, and apply only approved paths to the
//! real host workspace.

use std::path::{Component, Path, PathBuf};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use similar::TextDiff;

use crate::vm::Vm;
use bulge_proto::msg::Outcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// New or modified regular file with its full guest content.
    File { path: String, data: Vec<u8>, executable: bool, existed: bool },
    Deleted { path: String },
    Dir { path: String },
    Symlink { path: String, target: PathBuf },
    /// Exported only by size; cannot be applied without a separate transfer.
    TooLarge { path: String, size: u64 },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Deleted { path } | Self::Dir { path } | Self::Symlink { path, .. } | Self::TooLarge { path, .. } => path,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeError {
    #[error("guest {code}: {message}")]
    Guest { code: String, message: String },
    #[error("malformed guest reply: {0}")]
    Malformed(String),
    #[error("refusing {path}: {reason}")]
    Refused { path: String, reason: &'static str },
    #[error("io on {path}: {source}")]
    Io { path: String, source: std::io::Error },
}

#[derive(Deserialize)]
struct Listing {
    changes: Vec<ListedChange>,
}

#[derive(Deserialize)]
struct ListedChange {
    path: String,
}

#[derive(Deserialize)]
struct Export {
    files: Vec<ExportedFile>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExportedFile {
    File { path: String, data_b64: String, executable: bool, existed: bool },
    Deleted { path: String },
    Dir { path: String },
    Symlink { path: String, target: PathBuf },
    TooLarge { path: String, size: u64 },
}

fn value(outcome: Outcome) -> Result<serde_json::Value, ChangeError> {
    match outcome {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, message } => Err(ChangeError::Guest { code, message }),
    }
}

/// Ask the guest for every pending workspace change and its content.
pub async fn collect(vm: &Vm) -> Result<Vec<Change>, ChangeError> {
    let listing: Listing =
        serde_json::from_value(value(vm.invoke("changes", json!(null), None).await)?).map_err(|e| ChangeError::Malformed(e.to_string()))?;
    if listing.changes.is_empty() {
        return Ok(Vec::new());
    }
    let paths: Vec<String> = listing.changes.into_iter().map(|c| c.path).collect();
    let export: Export = serde_json::from_value(value(vm.invoke("export_changes", json!({ "paths": paths }), None).await)?)
        .map_err(|e| ChangeError::Malformed(e.to_string()))?;
    export
        .files
        .into_iter()
        .map(|file| {
            Ok(match file {
                ExportedFile::File { path, data_b64, executable, existed } => {
                    let data = base64::engine::general_purpose::STANDARD.decode(data_b64).map_err(|e| ChangeError::Malformed(e.to_string()))?;
                    Change::File { path, data, executable, existed }
                }
                ExportedFile::Deleted { path } => Change::Deleted { path },
                ExportedFile::Dir { path } => Change::Dir { path },
                ExportedFile::Symlink { path, target } => Change::Symlink { path, target },
                ExportedFile::TooLarge { path, size } => Change::TooLarge { path, size },
            })
        })
        .collect()
}

/// Unified diff of every change against the current host workspace.
pub fn render_diff(workspace: &Path, changes: &[Change]) -> String {
    let mut out = String::new();
    for change in changes {
        let path = change.path();
        match change {
            Change::File { data, .. } => {
                let old = std::fs::read(workspace.join(path)).unwrap_or_default();
                match (std::str::from_utf8(&old), std::str::from_utf8(data)) {
                    (Ok(old), Ok(new)) => {
                        let diff = TextDiff::from_lines(old, new);
                        out.push_str(&diff.unified_diff().context_radius(3).header(&format!("a/{path}"), &format!("b/{path}")).to_string());
                    }
                    _ => out.push_str(&format!("Binary file {path} ({} -> {} bytes)\n", old.len(), data.len())),
                }
            }
            Change::Deleted { .. } => out.push_str(&format!("deleted: {path}\n")),
            Change::Dir { .. } => out.push_str(&format!("new directory: {path}\n")),
            Change::Symlink { target, .. } => out.push_str(&format!("symlink: {path} -> {}\n", target.display())),
            Change::TooLarge { size, .. } => out.push_str(&format!("too large to review inline: {path} ({size} bytes)\n")),
        }
    }
    out
}

/// A workspace-relative path with no `..`, root, or prefix components.
fn checked_relative(path: &str) -> Result<&Path, ChangeError> {
    let rel = Path::new(path);
    let ok = !path.is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_)));
    if ok { Ok(rel) } else { Err(ChangeError::Refused { path: path.to_owned(), reason: "not a plain workspace-relative path" }) }
}

/// Refuse to traverse any existing symlink between the workspace root and
/// the target's parent: an attacker-planted link must not redirect a write
/// outside the workspace.
fn ensure_no_symlink_parents(workspace: &Path, rel: &Path, display: &str) -> Result<(), ChangeError> {
    let mut current = workspace.to_path_buf();
    if let Some(parent) = rel.parent() {
        for component in parent.components() {
            current.push(component);
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(ChangeError::Refused { path: display.to_owned(), reason: "a parent directory is a symlink" });
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

/// Apply the changes whose paths are in `approved`. Every other change is left
/// untouched. Per-path failures are reported, not fatal.
pub fn apply(workspace: &Path, changes: &[Change], approved: &[String]) -> ApplyReport {
    let mut report = ApplyReport::default();
    // Directories first so files can land in them; deletions last.
    let mut ordered: Vec<&Change> = changes.iter().filter(|c| approved.iter().any(|a| a == c.path())).collect();
    ordered.sort_by_key(|c| match c {
        Change::Dir { .. } => 0,
        Change::Deleted { .. } => 2,
        _ => 1,
    });
    for change in ordered {
        let path = change.path().to_owned();
        match apply_one(workspace, change) {
            Ok(()) => report.applied.push(path),
            Err(error) => report.skipped.push((path, error.to_string())),
        }
    }
    report
}

fn apply_one(workspace: &Path, change: &Change) -> Result<(), ChangeError> {
    let display = change.path();
    let rel = checked_relative(display)?;
    ensure_no_symlink_parents(workspace, rel, display)?;
    let target = workspace.join(rel);
    let io = |source| ChangeError::Io { path: display.to_owned(), source };
    match change {
        Change::Dir { .. } => std::fs::create_dir_all(&target).map_err(io),
        Change::File { data, executable, .. } => {
            if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(ChangeError::Refused { path: display.to_owned(), reason: "target is a symlink" });
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            // Write a sibling temp file, then rename: no half-written files.
            let tmp = target.with_file_name(format!(".{}.bulge-tmp", rel.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
            std::fs::write(&tmp, data).map_err(io)?;
            use std::os::unix::fs::PermissionsExt;
            let mode = if *executable { 0o755 } else { 0o644 };
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(io)?;
            std::fs::rename(&tmp, &target).map_err(io)
        }
        Change::Deleted { .. } => match std::fs::symlink_metadata(&target) {
            Err(_) => Ok(()),
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&target).map_err(io),
            Ok(_) => std::fs::remove_file(&target).map_err(io),
        },
        Change::Symlink { target: link, .. } => {
            let stays_inside = link.is_relative() && {
                let mut depth: isize = rel.components().count() as isize - 1;
                link.components().all(|c| {
                    match c {
                        Component::ParentDir => depth -= 1,
                        Component::Normal(_) => depth += 1,
                        Component::CurDir => {}
                        _ => return false,
                    }
                    depth >= 0
                })
            };
            if !stays_inside {
                return Err(ChangeError::Refused { path: display.to_owned(), reason: "symlink points outside the workspace" });
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            let _ = std::fs::remove_file(&target);
            std::os::unix::fs::symlink(link, &target).map_err(io)
        }
        Change::TooLarge { .. } => Err(ChangeError::Refused { path: display.to_owned(), reason: "file too large for inline transfer" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("bulge-changes-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file(path: &str, text: &str) -> Change {
        Change::File { path: path.into(), data: text.as_bytes().to_vec(), executable: false, existed: false }
    }

    #[test]
    fn applies_only_approved_paths() {
        let ws = scratch();
        std::fs::write(ws.join("keep.txt"), "old").unwrap();
        let changes = vec![file("a/new.txt", "hi\n"), file("keep.txt", "new"), Change::Deleted { path: "gone.txt".into() }];
        let report = apply(&ws, &changes, &["a/new.txt".into()]);
        assert_eq!(report.applied, vec!["a/new.txt".to_string()]);
        assert_eq!(std::fs::read_to_string(ws.join("a/new.txt")).unwrap(), "hi\n");
        assert_eq!(std::fs::read_to_string(ws.join("keep.txt")).unwrap(), "old");
    }

    #[test]
    fn refuses_traversal_and_absolute_paths() {
        let ws = scratch();
        for bad in ["../escape.txt", "/etc/passwd", "a/../../x", ""] {
            let report = apply(&ws, &[file(bad, "x")], &[bad.into()]);
            assert!(report.applied.is_empty(), "{bad} must be refused");
        }
    }

    #[test]
    fn refuses_writes_through_existing_symlinked_parent() {
        let ws = scratch();
        let outside = scratch().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, ws.join("link")).unwrap();
        let report = apply(&ws, &[file("link/pwned.txt", "x")], &["link/pwned.txt".into()]);
        assert!(report.applied.is_empty());
        assert!(!outside.join("pwned.txt").exists());
    }

    #[test]
    fn symlinks_must_stay_inside_workspace() {
        let ws = scratch();
        let inside = Change::Symlink { path: "d/l".into(), target: "../real.txt".into() };
        let escape = Change::Symlink { path: "d/e".into(), target: "../../etc/passwd".into() };
        let absolute = Change::Symlink { path: "a".into(), target: "/etc/passwd".into() };
        let report = apply(&ws, &[inside, escape, absolute], &["d/l".into(), "d/e".into(), "a".into()]);
        assert_eq!(report.applied, vec!["d/l".to_string()]);
    }

    #[test]
    fn diff_shows_text_changes() {
        let ws = scratch();
        std::fs::write(ws.join("n.txt"), "hello\n").unwrap();
        let diff = render_diff(&ws, &[file("n.txt", "HELLO\n"), Change::Deleted { path: "x".into() }]);
        assert!(diff.contains("-hello") && diff.contains("+HELLO") && diff.contains("deleted: x"));
    }
}
