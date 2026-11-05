//! Workspace snapshots — the mechanism that lets seagent say "do it" instead of
//! "may I?", and that makes a deleted file recoverable (B4, H1).
//!
//! Design rules this implements (§0 of the plan):
//! * **Undo beats asking.** A destructive command inside the VM is allowed; it
//!   is *snapshotted* first. The operator gets a restore point, not a dialog.
//! * Snapshots live under seagent's data dir, never inside the workspace (a wipe of
//!   the workspace must not wipe the restore points, H1: PocketOS deleted the
//!   backups too because they sat next to the data).
//! * A restore first snapshots the current state, so a restore is itself
//!   undoable.
//! * Symlinks are recorded as links and never followed while copying: a link to
//!   `/etc/shadow` in the workspace must not be turned into a file in seagent's data
//!   dir, and a link pointing outside is dropped on restore.
//! * The index hash is over the *listing* (path, size, mtime), not the content:
//!   cheap enough to take on every destructive command, strong enough to prove
//!   nothing was dropped from the index.

use crate::image::sha256_file;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotMeta {
    /// Directory name; sorts chronologically (`0007-rm-rf`).
    pub name: String,
    pub created_at: u64,
    /// Why it was taken: `session-start`, `destructive-command`, `manual`, `pre-restore`.
    pub reason: String,
    pub files: usize,
    pub bytes: u64,
    pub symlinks: usize,
    /// sha256 over the sorted `path\tmode\tsize\tmtime` listing.
    pub index_sha256: String,
    /// Provider memory image, when the provider supports one.
    pub ram: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotStack {
    /// `<data>/vm/snapshots/<vm-key>`
    dir: PathBuf,
    keep: usize,
}

impl SnapshotStack {
    pub fn new(dir: PathBuf, keep: usize) -> SnapshotStack {
        SnapshotStack { dir, keep: keep.max(1) }
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn list(&self) -> Vec<SnapshotMeta> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&self.dir) else { return out };
        for e in rd.flatten() {
            let meta = e.path().join("meta.json");
            if let Ok(text) = fs::read_to_string(&meta) {
                if let Ok(m) = serde_json::from_str::<SnapshotMeta>(&text) {
                    out.push(m);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Copy `workspace` into a new snapshot. `reason` is free text shown by
    /// `seagent sandbox vm snapshot --list`.
    pub fn create(&self, workspace: &Path, reason: &str) -> Result<SnapshotMeta, String> {
        if !workspace.is_dir() {
            return Err(format!("workspace {} is not a directory", workspace.display()));
        }
        fs::create_dir_all(&self.dir).map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let seq = self.list().len() + 1;
        let slug: String = reason.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(24).collect();
        let name = format!("{seq:04}-{slug}");
        let dest = self.dir.join(&name);
        fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
        let mut t = Tally::default();
        copy_tree(workspace, &dest.join("tree"), Path::new(""), &mut t)?;
        // A snapshot without its index is not a snapshot.
        let meta = SnapshotMeta {
            name: name.clone(),
            created_at: now(),
            reason: reason.to_string(),
            files: t.files,
            bytes: t.bytes,
            symlinks: t.symlinks,
            index_sha256: sha256_hex(t.idx.join("\n").as_bytes()),
            ram: None,
        };
        let text = serde_json::to_string_pretty(&meta).map_err(|e| format!("serialize meta: {e}"))?;
        write_atomic(&dest.join("meta.json"), text.as_bytes())?;
        write_atomic(&dest.join("index.txt"), t.idx.join("\n").as_bytes())?;
        write_atomic(&dest.join("dropped.txt"), t.dropped.join("\n").as_bytes())?;
        self.prune()?;
        Ok(meta)
    }

    /// Which snapshot would `restore` pick with no name? The newest.
    pub fn newest(&self) -> Option<SnapshotMeta> {
        self.list().pop()
    }

    /// Restore `workspace` from a snapshot (newest when `name` is None).
    /// Before touching anything it snapshots the current state as
    /// `pre-restore`, so the restore itself can be undone.
    pub fn restore(&self, workspace: &Path, name: Option<&str>) -> Result<SnapshotMeta, String> {
        let list = self.list();
        let chosen = match name {
            Some(n) => list.iter().find(|m| m.name == n || m.name.ends_with(n)).cloned(),
            None => list.last().cloned(),
        }
        .ok_or_else(|| format!("no snapshot to restore (looked in {})", self.dir.display()))?;
        let src = self.dir.join(&chosen.name).join("tree");
        if !src.is_dir() {
            return Err(format!("snapshot {} has no tree", chosen.name));
        }
        if workspace.is_dir() {
            let _ = self.create(workspace, "pre-restore");
        }
        // Empty the workspace, but keep the directory itself (mounts, cwd).
        if let Ok(rd) = fs::read_dir(workspace) {
            for e in rd.flatten() {
                let p = e.path();
                let _ = if e.file_type().map(|t| t.is_dir()).unwrap_or(false) { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
            }
        } else {
            fs::create_dir_all(workspace).map_err(|e| format!("create {}: {e}", workspace.display()))?;
        }
        let mut t = Tally::default();
        copy_tree(&src, workspace, Path::new(""), &mut t)?;
        Ok(chosen)
    }

    /// Keep the newest `keep` snapshots, drop the rest.
    pub fn prune(&self) -> Result<usize, String> {
        let list = self.list();
        if list.len() <= self.keep {
            return Ok(0);
        }
        let mut removed = 0;
        for m in &list[..list.len() - self.keep] {
            let d = self.dir.join(&m.name);
            // Refuse to delete anything that is not one of our snapshot dirs.
            if d.parent() != Some(self.dir.as_path()) {
                continue;
            }
            if fs::remove_dir_all(&d).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Integrity check: the index on disk still matches the tree.
    pub fn verify(&self, name: &str) -> Result<(), String> {
        let root = self.dir.join(name);
        let want = fs::read_to_string(root.join("index.txt")).map_err(|e| format!("read index of {name}: {e}"))?;
        let mut t = Tally::default();
        copy_tree_dry(&root.join("tree"), Path::new(""), &mut t)?;
        if t.idx.join("\n") != want {
            return Err(format!("snapshot {name}: index does not match the stored tree"));
        }
        Ok(())
    }
}

/// Counters of one snapshot walk.
#[derive(Default)]
struct Tally {
    files: usize,
    bytes: u64,
    symlinks: usize,
    idx: Vec<String>,
    dropped: Vec<String>,
}

/// Copy `src` under `dst`, recording a listing. Symlinks are recreated as links
/// (never followed); sockets/fifos/devices are skipped.
fn copy_tree(src: &Path, dst: &Path, rel: &Path, t: &mut Tally) -> Result<(), String> {
    if !dst.exists() {
        fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    }
    let rd = fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for e in rd.flatten() {
        let name = e.file_name();
        let from = src.join(&name);
        let to = dst.join(&name);
        let child_rel = rel.join(&name);
        let md = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = e.file_type().map_err(|err| format!("stat {}: {err}", from.display()))?;
        if ft.is_symlink() {
            let target = fs::read_link(&from).map_err(|err| format!("readlink {}: {err}", from.display()))?;
            // A link is restored as a link; an absolute or escaping target is
            // dropped rather than materialised.
            if target.is_absolute() || target.components().any(|c| c == Component::ParentDir) {
                // Recorded separately: it is not in the tree, so it must not be
                // in the index that `verify` recomputes from the tree.
                t.dropped.push(format!("{}\t->\t{}", child_rel.display(), target.display()));
                continue;
            }
            let _ = std::os::unix::fs::symlink(&target, &to);
            t.symlinks += 1;
            t.idx.push(format!("{}\tlink:{}\t0\t0", child_rel.display(), target.display()));
            continue;
        }
        if ft.is_dir() {
            copy_tree(&from, &to, &child_rel, t)?;
            t.idx.push(format!("{}/\tdir\t0\t0", child_rel.display()));
            continue;
        }
        if !ft.is_file() {
            continue; // socket / fifo / device: not part of a workspace snapshot
        }
        fs::copy(&from, &to).map_err(|err| format!("copy {}: {err}", from.display()))?;
        let _ = fs::set_permissions(&to, md.permissions());
        t.files += 1;
        t.bytes += md.len();
        let mtime = md.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        t.idx.push(format!("{}\tfile\t{}\t{mtime}", child_rel.display(), md.len()));
    }
    t.idx.sort();
    Ok(())
}

/// Same walk without writing anything (verify).
fn copy_tree_dry(src: &Path, rel: &Path, t: &mut Tally) -> Result<(), String> {
    let rd = fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for e in rd.flatten() {
        let name = e.file_name();
        let from = src.join(&name);
        let child_rel = rel.join(&name);
        let md = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = e.file_type().map_err(|err| format!("stat {}: {err}", from.display()))?;
        if ft.is_symlink() {
            let target = fs::read_link(&from).map_err(|err| format!("readlink {}: {err}", from.display()))?;
            if target.is_absolute() || target.components().any(|c| c == Component::ParentDir) {
                continue;
            }
            t.symlinks += 1;
            t.idx.push(format!("{}\tlink:{}\t0\t0", child_rel.display(), target.display()));
            continue;
        }
        if ft.is_dir() {
            copy_tree_dry(&from, &child_rel, t)?;
            t.idx.push(format!("{}/\tdir\t0\t0", child_rel.display()));
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        t.files += 1;
        t.bytes += md.len();
        let mtime = md.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        t.idx.push(format!("{}\tfile\t{}\t{mtime}", child_rel.display(), md.len()));
    }
    t.idx.sort();
    Ok(())
}

fn write_atomic(p: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, p).map_err(|e| format!("rename {}: {e}", p.display()))
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    seagent_net::crypto::sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Commands that can destroy work in a way the operator would notice. Used to
/// decide "snapshot first, then let it run" — never to ask permission.
pub fn is_destructive(script: &str) -> Option<&'static str> {
    const RULES: &[(&str, &str)] = &[
        ("rm -rf", "recursive delete"),
        ("rm -fr", "recursive delete"),
        ("git reset --hard", "discards commits and working tree"),
        ("git clean -", "deletes untracked files"),
        ("git checkout --", "discards working tree"),
        ("git push --force", "rewrites a remote branch"),
        ("git push -f", "rewrites a remote branch"),
        ("drop table", "drops a database table"),
        ("drop database", "drops a database"),
        ("truncate table", "empties a table"),
        ("mkfs", "formats a file system"),
        ("shred ", "irreversibly overwrites files"),
        ("> /dev/sd", "writes to a raw block device"),
    ];
    let low = script.to_lowercase();
    RULES.iter().find(|(needle, _)| low.contains(needle)).map(|(_, why)| *why)
}

/// sha256 of a workspace file, for the sync manifest (B3 push/pull checks).
pub fn file_digest(p: &Path) -> Option<String> {
    sha256_file(p).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-vm-snap-{tag}-{}-{}", std::process::id(), now()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn ws(tag: &str) -> PathBuf {
        let d = tmp(tag);
        fs::create_dir_all(d.join("src")).unwrap();
        fs::write(d.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(d.join("README.md"), "hello\n").unwrap();
        d
    }

    #[test]
    fn a_deleted_file_comes_back_and_the_workspace_is_restored_exactly() {
        let root = tmp("restore");
        let w = ws("restore-ws");
        let stack = SnapshotStack::new(root.join("snaps"), 5);
        let snap = stack.create(&w, "before-rm").unwrap();
        assert_eq!(snap.files, 2);
        // The accident (H1: an agent deletes the workspace).
        fs::remove_dir_all(w.join("src")).unwrap();
        fs::write(w.join("README.md"), "clobbered\n").unwrap();
        fs::write(w.join("junk.txt"), "x").unwrap();
        assert!(!w.join("src/main.rs").exists());
        let restored = stack.restore(&w, None).unwrap();
        assert_eq!(restored.name, snap.name);
        assert_eq!(fs::read_to_string(w.join("src/main.rs")).unwrap(), "fn main() {}\n");
        assert_eq!(fs::read_to_string(w.join("README.md")).unwrap(), "hello\n");
        assert!(!w.join("junk.txt").exists(), "restore removes files created after the snapshot");
        assert!(stack.list().iter().any(|m| m.reason == "pre-restore"), "the restore itself is undoable");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&w);
    }

    #[test]
    fn symlinks_are_never_followed_out_of_the_workspace() {
        let root = tmp("links");
        let w = ws("links-ws");
        std::os::unix::fs::symlink("/etc/passwd", w.join("secret")).unwrap();
        std::os::unix::fs::symlink("src/main.rs", w.join("ok-link")).unwrap();
        let stack = SnapshotStack::new(root.join("snaps"), 5);
        let snap = stack.create(&w, "links").unwrap();
        assert_eq!(snap.symlinks, 1, "only the relative link is kept");
        let stored = fs::read(root.join("snaps").join(&snap.name).join("tree/secret"));
        assert!(stored.is_err(), "an absolute link is dropped, not copied as a file");
        let dropped = fs::read_to_string(root.join("snaps").join(&snap.name).join("dropped.txt")).unwrap();
        assert!(dropped.contains("/etc/passwd"), "the dropped link is recorded, not copied: {dropped}");
        let idx = fs::read_to_string(root.join("snaps").join(&snap.name).join("index.txt")).unwrap();
        assert!(!idx.contains("secret"), "the absolute link is not in the index: {idx}");
        stack.verify(&snap.name).unwrap();
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&w);
    }

    #[test]
    fn pruning_keeps_the_newest_and_refuses_to_escape_the_snapshot_dir() {
        let root = tmp("prune");
        let w = ws("prune-ws");
        let stack = SnapshotStack::new(root.join("snaps"), 2);
        for i in 0..5 {
            stack.create(&w, &format!("s{i}")).unwrap();
        }
        let list = stack.list();
        assert_eq!(list.len(), 2, "keep honoured");
        assert!(list[1].name.ends_with("s4"), "{list:?}");
        // A stray directory (or a hand-written meta) outside the stack is not removed.
        fs::create_dir_all(root.join("elsewhere")).unwrap();
        stack.prune().unwrap();
        assert!(root.join("elsewhere").exists());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&w);
    }

    #[test]
    fn destructive_commands_are_recognised_for_auto_snapshot() {
        assert_eq!(is_destructive("rm -rf build/"), Some("recursive delete"));
        assert_eq!(is_destructive("git reset --hard origin/main"), Some("discards commits and working tree"));
        assert!(is_destructive("DROP TABLE users").is_some(), "case-insensitive");
        assert!(is_destructive("cargo test").is_none());
        assert!(is_destructive("git status").is_none());
    }

    #[test]
    fn verify_detects_a_tampered_tree() {
        let root = tmp("verify");
        let w = ws("verify-ws");
        let stack = SnapshotStack::new(root.join("snaps"), 5);
        let s = stack.create(&w, "v").unwrap();
        stack.verify(&s.name).unwrap();
        fs::write(root.join("snaps").join(&s.name).join("tree/README.md"), "tampered\n").unwrap();
        assert!(stack.verify(&s.name).unwrap_err().contains("does not match"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&w);
    }

    #[test]
    fn the_stack_lives_outside_the_workspace() {
        // H1: the restore points must not be inside the thing they protect.
        let root = tmp("outside");
        let w = root.join("project");
        fs::create_dir_all(&w).unwrap();
        fs::write(w.join("a"), "1").unwrap();
        let stack = SnapshotStack::new(root.join("data/snapshots/project"), 3);
        stack.create(&w, "s").unwrap();
        assert!(!stack.dir().starts_with(&w));
        let _ = fs::remove_dir_all(&root);
    }
}
