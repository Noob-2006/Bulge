//! Workspace change review: collect what the guest changed in its overlay,
//! render it as a diff for approval, and apply only approved paths to the
//! real host workspace.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AT_FDCWD, AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, symlinkat, unlinkat};

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

/// Parse the guest's change listing into the paths it names.
pub(crate) fn parse_listing(value: serde_json::Value) -> Result<Vec<String>, ChangeError> {
    let listing: Listing = serde_json::from_value(value).map_err(|e| ChangeError::Malformed(e.to_string()))?;
    listing.changes.into_iter().map(|c| guest_path(c.path)).collect()
}

/// A path the guest reported, accepted only as a plain workspace-relative path.
/// The guest is untrusted: an absolute or `..` path would make the host read
/// (diff) or write (apply) outside the workspace, so the whole reply is
/// rejected as malformed rather than any single entry being dropped.
fn guest_path(path: String) -> Result<String, ChangeError> {
    match checked_relative(&path) {
        Ok(_) => Ok(path),
        Err(_) => Err(ChangeError::Malformed(format!("guest reported a path outside the workspace: {path:?}"))),
    }
}

/// Parse the guest's export reply into changes with content.
pub(crate) fn parse_export(value: serde_json::Value) -> Result<Vec<Change>, ChangeError> {
    let export: Export = serde_json::from_value(value).map_err(|e| ChangeError::Malformed(e.to_string()))?;
    export
        .files
        .into_iter()
        .map(|file| {
            Ok(match file {
                ExportedFile::File { path, data_b64, executable, existed } => {
                    let data = base64::engine::general_purpose::STANDARD.decode(data_b64).map_err(|e| ChangeError::Malformed(e.to_string()))?;
                    Change::File { path: guest_path(path)?, data, executable, existed }
                }
                ExportedFile::Deleted { path } => Change::Deleted { path: guest_path(path)? },
                ExportedFile::Dir { path } => Change::Dir { path: guest_path(path)? },
                ExportedFile::Symlink { path, target } => Change::Symlink { path: guest_path(path)?, target },
                ExportedFile::TooLarge { path, size } => Change::TooLarge { path: guest_path(path)?, size },
            })
        })
        .collect()
}

/// Ask the guest for every pending workspace change and its content.
pub async fn collect(vm: &Vm) -> Result<Vec<Change>, ChangeError> {
    let listing = value(vm.invoke("changes", json!(null), None).await)?;
    let paths = parse_listing(listing)?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let export = value(vm.invoke("export_changes", json!({ "paths": paths }), None).await)?;
    parse_export(export)
}

/// Unified diff of every change against the current host workspace. Changes
/// in `ignored` (path, reason — see [`crate::review`]) are listed by path in a
/// closing section instead of being diffed: still visible, not reviewed in full.
pub fn render_diff(workspace: &Path, changes: &[Change], ignored: &[(String, String)]) -> String {
    let mut out = String::new();
    for change in changes {
        let path = change.path();
        if ignored.iter().any(|(ignored, _)| ignored == path) {
            continue;
        }
        match change {
            Change::File { data, .. } => {
                let old = match read_host(workspace, path) {
                    Ok(old) => old,
                    Err(error) => {
                        out.push_str(&format!("note: current host {path} not read ({error}); diff is against empty\n"));
                        Vec::new()
                    }
                };
                match (std::str::from_utf8(&old), std::str::from_utf8(data)) {
                    (Ok(old), Ok(new)) => {
                        let diff = TextDiff::from_lines(old, new);
                        let rendered = diff.unified_diff().context_radius(3).header(&format!("a/{path}"), &format!("b/{path}")).to_string();
                        if !rendered.is_empty() {
                            out.push_str(&rendered);
                        } else if new.is_empty() {
                            // No text to diff, but the change must still be visible for review.
                            out.push_str(&format!("new empty file: {path}\n"));
                        } else {
                            out.push_str(&format!("content unchanged (mode or type only): {path}\n"));
                        }
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
    if !ignored.is_empty() {
        out.push_str(&format!("\n# {} by-product change(s), not selected for write-back by default:\n", ignored.len()));
        for (path, reason) in ignored {
            out.push_str(&format!("#   {path}  ({reason})\n"));
        }
    }
    out
}

/// A workspace-relative path with no `..`, root, or prefix components.
pub(crate) fn checked_relative(path: &str) -> Result<&Path, ChangeError> {
    let rel = Path::new(path);
    let ok = !path.is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_)));
    if ok { Ok(rel) } else { Err(ChangeError::Refused { path: path.to_owned(), reason: "not a plain workspace-relative path" }) }
}

pub(crate) const DIR_FLAGS: OFlag = OFlag::O_RDONLY.union(OFlag::O_DIRECTORY).union(OFlag::O_NOFOLLOW).union(OFlag::O_CLOEXEC);

pub(crate) fn errno_io(display: &str, errno: Errno) -> ChangeError {
    ChangeError::Io { path: display.to_owned(), source: std::io::Error::from(errno) }
}

/// Open the directory that holds `rel`, walking one component at a time with
/// `O_NOFOLLOW`: no symlink anywhere between the workspace root and the target
/// is ever followed, including links an earlier change of the same batch just
/// created. Holding the directory fd also closes the check-then-use window.
/// `Ok(None)` means a parent is missing and `create` was false.
pub(crate) fn open_parent<'a>(workspace: &Path, rel: &'a Path, create: bool, display: &str) -> Result<Option<(OwnedFd, &'a OsStr)>, ChangeError> {
    let name = rel.file_name().ok_or_else(|| ChangeError::Refused { path: display.to_owned(), reason: "not a plain workspace-relative path" })?;
    let mut dir = openat(AT_FDCWD, workspace, OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty()).map_err(|e| errno_io(display, e))?;
    for component in rel.parent().into_iter().flat_map(Path::components) {
        let mut next = openat(&dir, component.as_os_str(), DIR_FLAGS, Mode::empty());
        if matches!(next, Err(Errno::ENOENT)) {
            if !create {
                return Ok(None);
            }
            match mkdirat(&dir, component.as_os_str(), Mode::from_bits_truncate(0o755)) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(errno_io(display, e)),
            }
            next = openat(&dir, component.as_os_str(), DIR_FLAGS, Mode::empty());
        }
        dir = match next {
            Ok(fd) => fd,
            Err(Errno::ELOOP | Errno::ENOTDIR) => {
                return Err(ChangeError::Refused { path: display.to_owned(), reason: "a parent directory is a symlink or not a directory" });
            }
            Err(e) => return Err(errno_io(display, e)),
        };
    }
    Ok(Some((dir, name)))
}

/// File type of `name` in `dir` without following a final symlink.
pub(crate) fn kind_at(dir: &OwnedFd, name: &OsStr) -> Result<Option<SFlag>, Errno> {
    match fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(SFlag::from_bits_truncate(stat.st_mode & SFlag::S_IFMT.bits()))),
        Err(Errno::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Current host content of a workspace file, read without following any
/// symlink. A missing file reads as empty.
pub(crate) fn read_host(workspace: &Path, path: &str) -> Result<Vec<u8>, ChangeError> {
    let rel = checked_relative(path)?;
    let Some((dir, name)) = open_parent(workspace, rel, false, path)? else { return Ok(Vec::new()) };
    match openat(&dir, name, OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, Mode::empty()) {
        Ok(fd) => {
            let mut data = Vec::new();
            std::fs::File::from(fd).read_to_end(&mut data).map_err(|source| ChangeError::Io { path: path.to_owned(), source })?;
            Ok(data)
        }
        Err(Errno::ENOENT) => Ok(Vec::new()),
        Err(Errno::ELOOP) => Err(ChangeError::Refused { path: path.to_owned(), reason: "target is a symlink" }),
        Err(e) => Err(errno_io(path, e)),
    }
}

/// Remove the directory `name` in `parent` and everything under it, never
/// following a symlink (a link inside is unlinked, not descended into).
pub(crate) fn remove_tree(parent: &OwnedFd, name: &OsStr) -> Result<(), Errno> {
    let dir = openat(parent, name, DIR_FLAGS, Mode::empty())?;
    let entries: Vec<std::ffi::OsString> = {
        let mut listing = Dir::from_fd(dir.try_clone().map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(Errno::EIO as i32)))?)?;
        listing
            .iter()
            .filter_map(Result::ok)
            .map(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string())
            .filter(|n| n != "." && n != "..")
            .collect()
    };
    for entry in &entries {
        if kind_at(&dir, entry)? == Some(SFlag::S_IFDIR) {
            remove_tree(&dir, entry)?;
        } else {
            unlinkat(&dir, entry.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
        }
    }
    unlinkat(parent, name, UnlinkatFlags::RemoveDir)
}

/// A symlink target the host may create: relative, every `..` before any
/// named component, and never climbing above the workspace root. `a/../b`
/// is refused because `a` may itself be a link, so lexical depth would not
/// match where the kernel resolves it; with `..` only leading, the climb goes
/// through real parent directories (`open_parent` never follows links), and
/// any named component that is a link was itself created under this rule.
fn symlink_stays_inside(rel: &Path, link: &Path) -> bool {
    if !link.is_relative() || link.as_os_str().is_empty() {
        return false;
    }
    let mut depth = rel.components().count() as isize - 1;
    let mut named = false;
    link.components().all(|c| match c {
        Component::ParentDir if !named => {
            depth -= 1;
            depth >= 0
        }
        Component::Normal(_) => {
            named = true;
            true
        }
        Component::CurDir => true,
        _ => false,
    })
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
    let io = |e: Errno| errno_io(display, e);
    let refused = |reason| ChangeError::Refused { path: display.to_owned(), reason };
    if let Change::TooLarge { .. } = change {
        return Err(refused("file too large for inline transfer"));
    }
    if let Change::Symlink { target: link, .. } = change
        && !symlink_stays_inside(rel, link)
    {
        return Err(refused("symlink points outside the workspace"));
    }
    let create = !matches!(change, Change::Deleted { .. });
    let Some((dir, name)) = open_parent(workspace, rel, create, display)? else {
        return Ok(()); // deleting under a parent that does not exist: nothing to do
    };
    let existing = kind_at(&dir, name).map_err(io)?;
    match change {
        Change::Dir { .. } => match existing {
            None => mkdirat(&dir, name, Mode::from_bits_truncate(0o755)).map_err(io),
            Some(SFlag::S_IFDIR) => Ok(()),
            Some(_) => Err(refused("a non-directory already exists there")),
        },
        Change::File { data, executable, .. } => {
            match existing {
                Some(SFlag::S_IFLNK) => return Err(refused("target is a symlink")),
                Some(SFlag::S_IFDIR) => return Err(refused("target is a directory")),
                _ => {}
            }
            // Write a sibling temp file, then rename: no half-written files.
            // O_EXCL|O_NOFOLLOW: a planted file or link at the temp name is
            // removed (the link itself, never its target) and never written through.
            let tmp = OsString::from(format!(".{}.bulge-tmp", name.to_string_lossy()));
            match unlinkat(&dir, tmp.as_os_str(), UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(e) => return Err(io(e)),
            }
            let mode = Mode::from_bits_truncate(if *executable { 0o755 } else { 0o644 });
            let fd = openat(&dir, tmp.as_os_str(), OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, mode).map_err(io)?;
            let written = fchmod(&fd, mode).map_err(io).and_then(|()| {
                std::fs::File::from(fd).write_all(data).map_err(|source| ChangeError::Io { path: display.to_owned(), source })
            });
            let result = written.and_then(|()| renameat(&dir, tmp.as_os_str(), &dir, name).map_err(io));
            if result.is_err() {
                let _ = unlinkat(&dir, tmp.as_os_str(), UnlinkatFlags::NoRemoveDir);
            }
            result
        }
        Change::Deleted { .. } => match existing {
            None => Ok(()),
            Some(SFlag::S_IFDIR) => remove_tree(&dir, name).map_err(io),
            Some(_) => unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir).map_err(io),
        },
        Change::Symlink { target: link, .. } => {
            match existing {
                None => {}
                Some(SFlag::S_IFDIR) => return Err(refused("a directory already exists there")),
                Some(_) => unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir).map_err(io)?,
            }
            symlinkat(link.as_path(), &dir, name).map_err(io)
        }
        Change::TooLarge { .. } => unreachable!("refused above"),
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
    fn chained_symlinks_in_one_batch_cannot_redirect_a_write() {
        // The guest controls export order: a link to the root, then a link at
        // the temp-file name that climbs through it, then a file write.
        let base = scratch();
        let ws = base.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let changes = vec![
            Change::Symlink { path: "d/e/f/a".into(), target: "../../..".into() },
            Change::Symlink { path: "d/e/f/.x.bulge-tmp".into(), target: "a/../victim".into() },
            file("d/e/f/x", "pwned"),
        ];
        let names: Vec<String> = changes.iter().map(|c| c.path().to_string()).collect();
        let report = apply(&ws, &changes, &names);
        assert!(!base.join("victim").exists(), "write escaped the workspace: {report:?}");
        assert_eq!(std::fs::read_to_string(ws.join("d/e/f/x")).unwrap(), "pwned");
        // The climbing link was refused, not created.
        assert!(report.skipped.iter().any(|(p, _)| p == "d/e/f/.x.bulge-tmp"));
    }

    #[test]
    fn planted_temp_link_is_replaced_not_followed() {
        let base = scratch();
        let ws = base.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(base.join("outside.txt"), "keep").unwrap();
        std::os::unix::fs::symlink(base.join("outside.txt"), ws.join(".x.bulge-tmp")).unwrap();
        let report = apply(&ws, &[file("x", "new")], &["x".into()]);
        assert_eq!(report.applied, vec!["x".to_string()]);
        assert_eq!(std::fs::read_to_string(base.join("outside.txt")).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(ws.join("x")).unwrap(), "new");
    }

    #[test]
    fn deleting_a_directory_never_descends_into_links() {
        let base = scratch();
        let ws = base.join("ws");
        let outside = base.join("outside");
        std::fs::create_dir_all(ws.join("d/sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "keep").unwrap();
        std::os::unix::fs::symlink(&outside, ws.join("d/sub/link")).unwrap();
        let report = apply(&ws, &[Change::Deleted { path: "d".into() }], &["d".into()]);
        assert_eq!(report.applied, vec!["d".to_string()]);
        assert!(!ws.join("d").exists());
        assert!(outside.join("keep.txt").exists());
    }

    #[test]
    fn symlink_targets_may_not_climb_after_a_name() {
        let rel = Path::new("d/e/l");
        assert!(symlink_stays_inside(rel, Path::new("../x")));
        assert!(symlink_stays_inside(rel, Path::new("../../x/y")));
        assert!(!symlink_stays_inside(rel, Path::new("a/../x")));
        assert!(!symlink_stays_inside(rel, Path::new("../../../x")));
        assert!(!symlink_stays_inside(rel, Path::new("")));
    }

    #[test]
    fn export_with_a_path_outside_the_workspace_is_rejected() {
        for bad in ["/home/user/.ssh/id_rsa", "../x", "a/../../x", ""] {
            let reply = json!({ "files": [{ "kind": "file", "path": bad, "data_b64": "", "executable": false, "existed": true }] });
            assert!(matches!(parse_export(reply), Err(ChangeError::Malformed(_))), "{bad:?} must be rejected");
            let listing = json!({ "changes": [{ "path": bad }] });
            assert!(matches!(parse_listing(listing), Err(ChangeError::Malformed(_))), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn diff_never_reads_through_a_link() {
        let base = scratch();
        let ws = base.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(base.join("secret"), "TOPSECRET\n").unwrap();
        std::os::unix::fs::symlink(base.join("secret"), ws.join("l")).unwrap();
        std::os::unix::fs::symlink(&base, ws.join("dir")).unwrap();
        let diff = render_diff(&ws, &[file("l", "x\n"), file("dir/secret", "y\n")], &[]);
        assert!(!diff.contains("TOPSECRET"), "{diff}");
    }

    #[test]
    fn diff_shows_text_changes() {
        let ws = scratch();
        std::fs::write(ws.join("n.txt"), "hello\n").unwrap();
        let diff = render_diff(&ws, &[file("n.txt", "HELLO\n"), Change::Deleted { path: "x".into() }], &[]);
        assert!(diff.contains("-hello") && diff.contains("+HELLO") && diff.contains("deleted: x"));
        // An empty new file has no text diff but must still be listed.
        let diff = render_diff(&ws, &[file("tests/__init__.py", "")], &[]);
        assert_eq!(diff, "new empty file: tests/__init__.py\n");
        // By-products are listed with their reason, not diffed.
        let ignored = vec![("c.pyc".to_string(), "`*.py[cod]` in built-in review rules".to_string())];
        let diff = render_diff(&ws, &[file("n.txt", "HELLO\n"), file("c.pyc", "BYTECODE")], &ignored);
        assert!(diff.contains("+HELLO") && !diff.contains("BYTECODE"));
        assert!(diff.contains("c.pyc  (`*.py[cod]` in built-in review rules)"));
    }
}
