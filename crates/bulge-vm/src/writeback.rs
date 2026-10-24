//! Write-back with a snapshot and one-click rollback (ORG.md §11 decision 1).
//!
//! Every write-back to the host workspace first records, for each path it will
//! touch, exactly what was there before — file bytes and mode, symlink target,
//! a whole directory tree when it deletes one, or nothing — plus the parent
//! directories it will create. The snapshot is written to disk before anything
//! is applied, so even a crash mid-apply can be rolled back.
//!
//! The snapshot's manifest is also the audit record: what was written, whether
//! a human approved it (`auto` is false) or it was applied by full-auto rules,
//! what was skipped and why, and when and how it was rolled back.
//!
//! Rollback restores the before-state in reverse order, but only where the
//! path still holds what the write-back put there: a path changed since (by
//! the user, or by a later write-back) is a conflict and is left alone unless
//! the caller forces it. All filesystem access goes through the same no-follow
//! directory walk as [`crate::changes::apply`].
//!
//! Known limit: the guest's lower layer is the live host share, so there is
//! no record of the version a guest edit started from. Two jobs that run at
//! once in the same workspace and both change one file each write their whole
//! version; the later write-back wins (each file is replaced atomically, and
//! the earlier version stays in the later snapshot, so it can be rolled back
//! to).

use bulge_util::{hex, now_ms};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{OFlag, openat, readlinkat, renameat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, symlinkat, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::changes::{self, Change, ChangeError, DIR_FLAGS, checked_relative, kind_at, open_parent};

/// Where a job keeps its write-back snapshots (one directory per write-back).
pub const WRITEBACKS_DIR: &str = "writebacks";
const MANIFEST: &str = "manifest.json";
const BLOBS: &str = "blobs";

/// What a path held at one moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Node {
    Absent,
    /// `blob` names the saved content (by hash) in the snapshot; `None` for an
    /// after-state, which is only compared, never restored.
    File { sha256: String, mode: u32, blob: Option<String> },
    Symlink { target: PathBuf },
    /// `children` is the full tree only when it must be restored (a deleted
    /// directory); `None` just records that a directory was there.
    Dir { mode: u32, children: Option<Vec<(String, Node)>> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub before: Node,
    pub after: Node,
    pub applied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Snapshot written, apply not (yet) finished — e.g. a crash mid-apply.
    Pending,
    Applied,
    RolledBack,
    /// Rolled back except for the listed conflicts.
    PartiallyRolledBack,
}

/// One write-back: its snapshot and its audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub workspace: PathBuf,
    pub created_ms: u64,
    /// Applied by full-auto rules rather than approved path by path by a human.
    pub auto: bool,
    pub state: State,
    pub entries: Vec<Entry>,
    /// Directories the apply created (parents first); removed on rollback when
    /// they are empty again.
    pub created_dirs: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub rolled_back_ms: Option<u64>,
    /// Paths a rollback left alone, and why.
    pub rollback_conflicts: Vec<(String, String)>,
}

impl Manifest {
    pub fn applied_paths(&self) -> Vec<String> {
        self.entries.iter().filter(|e| e.applied).map(|e| e.path.clone()).collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    pub restored: Vec<String>,
    pub conflicts: Vec<(String, String)>,
}



fn sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn io_err(path: &str, source: std::io::Error) -> ChangeError {
    ChangeError::Io { path: path.to_owned(), source }
}

// ---- reading host state (never following links) ----

/// Read what `rel` holds now. `deep` captures a directory's whole tree (with
/// file contents handed to `save`); otherwise a directory is just recorded.
fn read_node(workspace: &Path, rel: &Path, deep: bool, save: &mut dyn FnMut(&[u8]) -> Result<String, ChangeError>) -> Result<Node, ChangeError> {
    let display = rel.to_string_lossy().into_owned();
    let Some((dir, name)) = open_parent(workspace, rel, false, &display)? else { return Ok(Node::Absent) };
    read_at(&dir, name, deep, &display, save)
}

fn read_at(dir: &OwnedFd, name: &OsStr, deep: bool, display: &str, save: &mut dyn FnMut(&[u8]) -> Result<String, ChangeError>) -> Result<Node, ChangeError> {
    let stat = match fstatat(dir, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(Node::Absent),
        Err(e) => return Err(changes::errno_io(display, e)),
    };
    let kind = SFlag::from_bits_truncate(stat.st_mode & SFlag::S_IFMT.bits());
    let mode = stat.st_mode & 0o7777;
    if kind == SFlag::S_IFLNK {
        let target = readlinkat(dir, name).map_err(|e| changes::errno_io(display, e))?;
        return Ok(Node::Symlink { target: PathBuf::from(target) });
    }
    if kind == SFlag::S_IFDIR {
        if !deep {
            return Ok(Node::Dir { mode, children: None });
        }
        let fd = openat(dir, name, DIR_FLAGS, Mode::empty()).map_err(|e| changes::errno_io(display, e))?;
        let mut children = Vec::new();
        for child in list_dir(&fd).map_err(|e| changes::errno_io(display, e))? {
            let child_display = format!("{display}/{}", child.to_string_lossy());
            let node = read_at(&fd, &child, true, &child_display, save)?;
            children.push((child.to_string_lossy().into_owned(), node));
        }
        return Ok(Node::Dir { mode, children: Some(children) });
    }
    if kind != SFlag::S_IFREG {
        return Err(ChangeError::Refused { path: display.to_owned(), reason: "not a regular file, directory, or symlink" });
    }
    let fd = openat(dir, name, OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, Mode::empty()).map_err(|e| changes::errno_io(display, e))?;
    let mut data = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut data).map_err(|e| io_err(display, e))?;
    let blob = save(&data)?;
    Ok(Node::File { sha256: sha256(&data), mode, blob: Some(blob) })
}

fn list_dir(fd: &OwnedFd) -> Result<Vec<OsString>, Errno> {
    let dup = fd.try_clone().map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(Errno::EIO as i32)))?;
    let mut listing = Dir::from_fd(dup)?;
    let mut names: Vec<OsString> = listing
        .iter()
        .filter_map(Result::ok)
        .map(|entry| OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string())
        .filter(|n| n != "." && n != "..")
        .collect();
    names.sort();
    Ok(names)
}

/// What a change will leave at its path (compared on rollback).
fn after_node(change: &Change) -> Node {
    match change {
        Change::File { data, executable, .. } => Node::File { sha256: sha256(data), mode: if *executable { 0o755 } else { 0o644 }, blob: None },
        Change::Deleted { .. } => Node::Absent,
        Change::Dir { .. } => Node::Dir { mode: 0o755, children: None },
        Change::Symlink { target, .. } => Node::Symlink { target: target.clone() },
        Change::TooLarge { .. } => Node::Absent,
    }
}

/// Whether `current` is what the write-back left (content and type; a mode
/// change alone is not counted as a later edit).
fn matches_after(current: &Node, after: &Node) -> bool {
    match (current, after) {
        (Node::Absent, Node::Absent) => true,
        (Node::File { sha256: a, .. }, Node::File { sha256: b, .. }) => a == b,
        (Node::Symlink { target: a }, Node::Symlink { target: b }) => a == b,
        (Node::Dir { .. }, Node::Dir { .. }) => true,
        _ => false,
    }
}

// ---- snapshot storage ----

struct Snapshot {
    dir: PathBuf,
}

impl Snapshot {
    fn save_blob(&self, data: &[u8]) -> Result<String, ChangeError> {
        let name = sha256(data);
        let path = self.dir.join(BLOBS).join(&name);
        if !path.exists() {
            write_durable(&path, data)?;
        }
        Ok(name)
    }

    fn blob(&self, name: &str) -> Result<Vec<u8>, ChangeError> {
        std::fs::read(self.dir.join(BLOBS).join(name)).map_err(|e| io_err(name, e))
    }
}

fn write_durable(path: &Path, data: &[u8]) -> Result<(), ChangeError> {
    let display = path.display().to_string();
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp).map_err(|e| io_err(&display, e))?;
    file.write_all(data).and_then(|()| file.sync_all()).map_err(|e| io_err(&display, e))?;
    std::fs::rename(&tmp, path).map_err(|e| io_err(&display, e))?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn save_manifest(dir: &Path, manifest: &Manifest) -> Result<(), ChangeError> {
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| ChangeError::Malformed(e.to_string()))?;
    write_durable(&dir.join(MANIFEST), &json)
}

/// Read one write-back's manifest.
pub fn load(writeback_dir: &Path) -> Result<Manifest, ChangeError> {
    let path = writeback_dir.join(MANIFEST);
    let bytes = std::fs::read(&path).map_err(|e| io_err(&path.display().to_string(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| ChangeError::Malformed(format!("{}: {e}", path.display())))
}

/// Every write-back recorded under a job directory, oldest first.
pub fn list(job_dir: &Path) -> Vec<Manifest> {
    let Ok(entries) = std::fs::read_dir(job_dir.join(WRITEBACKS_DIR)) else { return Vec::new() };
    let mut found: Vec<Manifest> = entries.flatten().filter_map(|entry| load(&entry.path()).ok()).collect();
    found.sort_by(|a, b| a.created_ms.cmp(&b.created_ms).then_with(|| a.id.cmp(&b.id)));
    found
}

// ---- apply with snapshot ----

/// Apply the approved `changes` to `workspace` like [`changes::apply`], after
/// snapshotting every path it will touch into `<job_dir>/writebacks/<id>/`.
/// Returns the manifest (also saved there). Fails before touching the
/// workspace if the snapshot cannot be taken.
pub fn apply(workspace: &Path, changes: &[Change], approved: &[String], job_dir: &Path, auto: bool) -> Result<Manifest, ChangeError> {
    let created_ms = now_ms();
    let mut nonce = [0u8; 4];
    getrandom::fill(&mut nonce).map_err(|e| ChangeError::Malformed(format!("random id: {e}")))?;
    let id = format!("w-{created_ms}-{}", hex(&nonce));
    let dir = job_dir.join(WRITEBACKS_DIR).join(&id);
    // create_dir (not _all) on the leaf: an id collision fails instead of mixing two snapshots.
    std::fs::create_dir_all(job_dir.join(WRITEBACKS_DIR)).map_err(|e| io_err(&dir.display().to_string(), e))?;
    std::fs::create_dir(&dir).and_then(|()| std::fs::create_dir(dir.join(BLOBS))).map_err(|e| io_err(&dir.display().to_string(), e))?;
    let snapshot = Snapshot { dir: dir.clone() };

    let mut selected: Vec<&Change> = changes.iter().filter(|c| approved.iter().any(|a| a == c.path())).collect();
    selected.sort_by_key(|c| match c {
        Change::Dir { .. } => 0,
        Change::Deleted { .. } => 2,
        _ => 1,
    });

    let mut entries = Vec::with_capacity(selected.len());
    let mut created_dirs: Vec<String> = Vec::new();
    for change in &selected {
        let rel = checked_relative(change.path())?;
        // Parent directories the apply will create, parents first.
        let mut ancestor = PathBuf::new();
        for component in rel.parent().into_iter().flat_map(Path::components) {
            ancestor.push(component);
            let key = ancestor.to_string_lossy().into_owned();
            if !created_dirs.contains(&key) && read_node(workspace, &ancestor, false, &mut |_| Ok(String::new()))? == Node::Absent {
                created_dirs.push(key);
            }
        }
        let deep = matches!(change, Change::Deleted { .. });
        let before = read_node(workspace, rel, deep, &mut |data| snapshot.save_blob(data))?;
        entries.push(Entry { path: change.path().to_owned(), before, after: after_node(change), applied: false });
    }

    let mut manifest = Manifest {
        id,
        workspace: workspace.to_path_buf(),
        created_ms,
        auto,
        state: State::Pending,
        entries,
        created_dirs,
        skipped: Vec::new(),
        rolled_back_ms: None,
        rollback_conflicts: Vec::new(),
    };
    // Write-ahead: the snapshot is durable before the workspace changes.
    save_manifest(&dir, &manifest)?;

    let report = changes::apply(workspace, changes, approved);
    for entry in &mut manifest.entries {
        entry.applied = report.applied.contains(&entry.path);
    }
    manifest.skipped = report.skipped;
    manifest.state = State::Applied;
    save_manifest(&dir, &manifest)?;
    Ok(manifest)
}

// ---- rollback ----

/// Undo write-back `id` of the job at `job_dir`. A path whose current state is
/// not what the write-back left is a conflict and is skipped unless `force`.
/// A pending write-back (interrupted mid-apply) can be rolled back too.
pub fn rollback(job_dir: &Path, id: &str, force: bool) -> Result<RollbackReport, ChangeError> {
    if id.contains('/') || id.contains("..") {
        return Err(ChangeError::Refused { path: id.to_owned(), reason: "not a write-back id" });
    }
    let dir = job_dir.join(WRITEBACKS_DIR).join(id);
    let mut manifest = load(&dir)?;
    if matches!(manifest.state, State::RolledBack) {
        return Err(ChangeError::Refused { path: id.to_owned(), reason: "already rolled back" });
    }
    let snapshot = Snapshot { dir: dir.clone() };
    let workspace = manifest.workspace.clone();
    let pending = manifest.state == State::Pending;
    let mut report = RollbackReport::default();

    for entry in manifest.entries.iter().rev() {
        // After a crash mid-apply, `applied` was never recorded: check each path.
        if !entry.applied && !pending {
            continue;
        }
        let rel = checked_relative(&entry.path)?;
        // A path that can no longer be read safely (e.g. a parent replaced by a
        // link) is reported, never restored through.
        let current = match read_node(workspace.as_path(), rel, false, &mut |_| Ok(String::new())) {
            Ok(node) => node,
            Err(error) => {
                report.conflicts.push((entry.path.clone(), error.to_string()));
                continue;
            }
        };
        if matches_after(&current, &entry.before) {
            continue; // already as it was (e.g. the apply never reached it)
        }
        if !force && !matches_after(&current, &entry.after) {
            report.conflicts.push((entry.path.clone(), "changed since the write-back; left as it is".into()));
            continue;
        }
        match restore(&workspace, rel, &entry.before, &snapshot) {
            Ok(()) => report.restored.push(entry.path.clone()),
            Err(error) => report.conflicts.push((entry.path.clone(), error.to_string())),
        }
    }
    // Directories the apply created go away again when nothing else is in them.
    for created in manifest.created_dirs.iter().rev() {
        let rel = Path::new(created);
        if let Ok(Some((parent, name))) = open_parent(&workspace, rel, false, created) {
            let _ = unlinkat(&parent, name, UnlinkatFlags::RemoveDir);
        }
    }

    manifest.state = if report.conflicts.is_empty() { State::RolledBack } else { State::PartiallyRolledBack };
    manifest.rolled_back_ms = Some(now_ms());
    manifest.rollback_conflicts.clone_from(&report.conflicts);
    save_manifest(&dir, &manifest)?;
    Ok(report)
}

/// Put `before` back at `rel`, replacing whatever is there now.
fn restore(workspace: &Path, rel: &Path, before: &Node, snapshot: &Snapshot) -> Result<(), ChangeError> {
    let display = rel.to_string_lossy().into_owned();
    let create = !matches!(before, Node::Absent);
    let Some((dir, name)) = open_parent(workspace, rel, create, &display)? else { return Ok(()) };
    clear_at(&dir, name, before, &display)?;
    write_at(&dir, name, before, snapshot, &display)
}

/// Remove what is at `name` so `before` can be written, keeping a directory
/// that `before` also describes as a directory (its children are restored into
/// it). A directory that is not empty and is to become something else is only
/// removed when it was this write-back's own (an empty one).
fn clear_at(dir: &OwnedFd, name: &OsStr, before: &Node, display: &str) -> Result<(), ChangeError> {
    match kind_at(dir, name).map_err(|e| changes::errno_io(display, e))? {
        None => Ok(()),
        Some(SFlag::S_IFDIR) => match before {
            Node::Dir { .. } => Ok(()),
            _ => unlinkat(dir, name, UnlinkatFlags::RemoveDir).map_err(|e| match e {
                Errno::ENOTEMPTY | Errno::EEXIST => ChangeError::Refused { path: display.to_owned(), reason: "directory is not empty" },
                e => changes::errno_io(display, e),
            }),
        },
        Some(_) => unlinkat(dir, name, UnlinkatFlags::NoRemoveDir).map_err(|e| changes::errno_io(display, e)),
    }
}

fn write_at(dir: &OwnedFd, name: &OsStr, node: &Node, snapshot: &Snapshot, display: &str) -> Result<(), ChangeError> {
    let io = |e: Errno| changes::errno_io(display, e);
    match node {
        Node::Absent => Ok(()),
        Node::Symlink { target } => symlinkat(target.as_path(), dir, name).map_err(io),
        Node::File { mode, blob, .. } => {
            let Some(blob) = blob else { return Err(ChangeError::Malformed(format!("{display}: no saved content"))) };
            let data = snapshot.blob(blob)?;
            let tmp = OsString::from(format!(".{}.bulge-tmp", name.to_string_lossy()));
            match unlinkat(dir, tmp.as_os_str(), UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(e) => return Err(io(e)),
            }
            let fd = openat(dir, tmp.as_os_str(), OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC, Mode::from_bits_truncate(*mode)).map_err(io)?;
            fchmod(&fd, Mode::from_bits_truncate(*mode)).map_err(io)?;
            std::fs::File::from(fd).write_all(&data).map_err(|e| io_err(display, e))?;
            renameat(dir, tmp.as_os_str(), dir, name).map_err(io)
        }
        Node::Dir { mode, children } => {
            match mkdirat(dir, name, Mode::from_bits_truncate(*mode)) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(io(e)),
            }
            let Some(children) = children else { return Ok(()) };
            let sub = openat(dir, name, DIR_FLAGS, Mode::empty()).map_err(io)?;
            for (child, node) in children {
                let child_display = format!("{display}/{child}");
                let child = OsStr::new(child);
                clear_at(&sub, child, node, &child_display)?;
                write_at(&sub, child, node, snapshot, &child_display)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("bulge-writeback-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        std::fs::create_dir_all(dir.join("job")).unwrap();
        dir
    }

    fn file(path: &str, text: &str) -> Change {
        Change::File { path: path.into(), data: text.as_bytes().to_vec(), executable: false, existed: false }
    }

    fn names(changes: &[Change]) -> Vec<String> {
        changes.iter().map(|c| c.path().to_owned()).collect()
    }

    #[test]
    fn rollback_restores_every_kind_of_change() {
        let base = scratch();
        let (ws, job) = (base.join("ws"), base.join("job"));
        std::fs::write(ws.join("keep.txt"), "original\n").unwrap();
        std::fs::set_permissions(ws.join("keep.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all(ws.join("old/inner")).unwrap();
        std::fs::write(ws.join("old/inner/a.txt"), "A").unwrap();
        std::os::unix::fs::symlink("inner/a.txt", ws.join("old/link")).unwrap();
        std::fs::write(ws.join("gone.txt"), "bye").unwrap();
        let changes = vec![
            file("keep.txt", "modified\n"),
            file("new/deep/file.txt", "new"),
            Change::Deleted { path: "old".into() },
            Change::Deleted { path: "gone.txt".into() },
            Change::Symlink { path: "ln".into(), target: "keep.txt".into() },
        ];
        let manifest = apply(&ws, &changes, &names(&changes), &job, true).unwrap();
        assert_eq!(manifest.state, State::Applied);
        assert_eq!(manifest.applied_paths().len(), 5);
        assert!(manifest.auto);
        assert_eq!(manifest.created_dirs, ["new", "new/deep"]);
        assert!(!ws.join("old").exists());

        let report = rollback(&job, &manifest.id, false).unwrap();
        assert!(report.conflicts.is_empty(), "{report:?}");
        assert_eq!(std::fs::read_to_string(ws.join("keep.txt")).unwrap(), "original\n");
        assert_eq!(std::fs::metadata(ws.join("keep.txt")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(ws.join("old/inner/a.txt")).unwrap(), "A");
        assert_eq!(std::fs::read_link(ws.join("old/link")).unwrap(), PathBuf::from("inner/a.txt"));
        assert_eq!(std::fs::read_to_string(ws.join("gone.txt")).unwrap(), "bye");
        assert!(!ws.join("new").exists(), "created parents are removed again");
        assert!(std::fs::symlink_metadata(ws.join("ln")).is_err());
        let saved = load(&job.join(WRITEBACKS_DIR).join(&manifest.id)).unwrap();
        assert_eq!(saved.state, State::RolledBack);
        assert!(saved.rolled_back_ms.is_some());
        assert!(rollback(&job, &manifest.id, false).is_err(), "a second rollback is refused");
    }

    #[test]
    fn later_edits_are_conflicts_unless_forced() {
        let base = scratch();
        let (ws, job) = (base.join("ws"), base.join("job"));
        std::fs::write(ws.join("a.txt"), "v1").unwrap();
        let changes = vec![file("a.txt", "v2"), file("b.txt", "new")];
        let manifest = apply(&ws, &changes, &names(&changes), &job, false).unwrap();
        std::fs::write(ws.join("a.txt"), "user edit after write-back").unwrap();

        let report = rollback(&job, &manifest.id, false).unwrap();
        assert_eq!(report.restored, ["b.txt"]);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "user edit after write-back");
        assert_eq!(load(&job.join(WRITEBACKS_DIR).join(&manifest.id)).unwrap().state, State::PartiallyRolledBack);

        let forced = rollback(&job, &manifest.id, true).unwrap();
        assert_eq!(forced.restored, ["a.txt"]);
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "v1");
    }

    #[test]
    fn an_older_write_back_does_not_undo_a_newer_one() {
        let base = scratch();
        let (ws, job) = (base.join("ws"), base.join("job"));
        let first = apply(&ws, &[file("x", "one")], &["x".into()], &job, true).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2)); // list() orders by time
        let second = apply(&ws, &[file("x", "two")], &["x".into()], &job, true).unwrap();
        let report = rollback(&job, &first.id, false).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(std::fs::read_to_string(ws.join("x")).unwrap(), "two");
        rollback(&job, &second.id, false).unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("x")).unwrap(), "one");
        assert_eq!(list(&job).len(), 2);
    }

    #[test]
    fn rollback_never_follows_a_link_planted_after_the_write_back() {
        let base = scratch();
        let (ws, job) = (base.join("ws"), base.join("job"));
        std::fs::create_dir_all(ws.join("d")).unwrap();
        std::fs::write(ws.join("d/f"), "before").unwrap();
        let manifest = apply(&ws, &[file("d/f", "after")], &["d/f".into()], &job, true).unwrap();
        // Replace the directory with a link to somewhere outside.
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::fs::remove_dir_all(ws.join("d")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), ws.join("d")).unwrap();
        let report = rollback(&job, &manifest.id, true).unwrap();
        assert!(report.restored.is_empty());
        assert!(!base.join("outside/f").exists());
    }

    #[test]
    fn the_snapshot_is_written_before_the_workspace_changes() {
        let base = scratch();
        let (ws, job) = (base.join("ws"), base.join("job"));
        std::fs::write(ws.join("a"), "keep me").unwrap();
        let manifest = apply(&ws, &[file("a", "x")], &["a".into()], &job, true).unwrap();
        let Node::File { blob: Some(blob), .. } = &manifest.entries[0].before else { panic!("{:?}", manifest.entries[0].before) };
        let saved = std::fs::read(job.join(WRITEBACKS_DIR).join(&manifest.id).join(BLOBS).join(blob)).unwrap();
        assert_eq!(saved, b"keep me");
    }
}
