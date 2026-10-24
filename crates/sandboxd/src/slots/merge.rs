//! Base lookup, export, and the merge decision for changes made in a slot.

use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use crate::commands::BaseEntry;
use crate::setup::WORKSPACE_LOWER;
use super::SlotError;

/// A snapshot whiteout is a 0/0 character device.
pub fn is_overlay_whiteout(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_char_device() && meta.rdev() == 0,
        Err(_) => false,
    }
}

/// Base entry for a slot: the snapshot layer first, falling back to the
/// read-only host share. A whiteout in the snapshot means the path is absent.
pub fn slot_base_entry(snap: &Path, lower: &Path, rel: &Path, whiteout: &dyn Fn(&Path) -> bool) -> BaseEntry {
    let snap_path = snap.join(rel);
    if whiteout(&snap_path) {
        return BaseEntry::Absent;
    }
    if let Ok(meta) = std::fs::symlink_metadata(&snap_path) {
        return BaseEntry::from_metadata(snap_path, &meta);
    }
    let lower_path = lower.join(rel);
    match std::fs::metadata(&lower_path) {
        Ok(meta) => BaseEntry::from_metadata(lower_path, &meta),
        Err(_) => BaseEntry::Absent,
    }
}

/// [`slot_base_entry`] for the live helper, refusing a path whose parents in the
/// snapshot or the host share are symlinks (reported as absent from the base, so
/// any change to it conflicts or is added — never read through a link as root).
pub(crate) fn base_entry_checked(snap: &Path, rel: &Path) -> BaseEntry {
    let lower = Path::new(WORKSPACE_LOWER);
    if ensure_no_symlink_parents(snap, rel).is_err() || ensure_no_symlink_parents(lower, rel).is_err() {
        return BaseEntry::Absent;
    }
    slot_base_entry(snap, lower, rel, &is_overlay_whiteout)
}

/// Run `work` in a forked child that has (optionally) entered the mount namespace
/// of process `mount_ns_of` and then dropped to `uid`/`gid` (no supplementary
/// groups, `no_new_privs`), and return its result. The helper is single-threaded,
/// so forking is safe; the child reports back as one JSON value over a pipe and
/// exits without unwinding. Used so that the root helper never reads or writes a
/// path an unprivileged process could have redirected.
#[allow(unsafe_code)]
pub(crate) fn run_as<T, F>(mount_ns_of: Option<i32>, uid: u32, gid: u32, work: F) -> Result<T, SlotError>
where
    T: Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Result<T, SlotError>,
{
    use std::io::Read;
    use std::os::fd::OwnedFd;

    let (read_end, write_end): (OwnedFd, OwnedFd) = nix::unistd::pipe().map_err(SlotError::failed)?;
    // SAFETY: the helper process is single-threaded (no tokio, no spawned
    // threads), so the child may run ordinary Rust code after fork.
    match unsafe { nix::unistd::fork() }.map_err(SlotError::failed)? {
        nix::unistd::ForkResult::Child => {
            drop(read_end);
            let result = (|| -> Result<T, SlotError> {
                if let Some(pid) = mount_ns_of {
                    let ns = std::fs::File::open(format!("/proc/{pid}/ns/mnt")).map_err(SlotError::failed)?;
                    nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNS).map_err(SlotError::failed)?;
                    std::env::set_current_dir("/").map_err(SlotError::failed)?;
                }
                let gid = nix::unistd::Gid::from_raw(gid);
                nix::unistd::setgroups(&[gid]).map_err(SlotError::failed)?;
                nix::unistd::setresgid(gid, gid, gid).map_err(SlotError::failed)?;
                let uid = nix::unistd::Uid::from_raw(uid);
                nix::unistd::setresuid(uid, uid, uid).map_err(SlotError::failed)?;
                nix::sys::prctl::set_no_new_privs().map_err(SlotError::failed)?;
                work()
            })();
            let payload: Result<T, (String, String)> = result.map_err(|error| (error.code, error.message));
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            let mut file = std::fs::File::from(write_end);
            let code = if file.write_all(&bytes).is_ok() { 0 } else { 1 };
            // SAFETY: terminate the forked child without running the parent's
            // destructors or flushing its buffers twice.
            unsafe { nix::libc::_exit(code) }
        }
        nix::unistd::ForkResult::Parent { child } => {
            drop(write_end);
            let mut bytes = Vec::new();
            let read = std::fs::File::from(read_end).read_to_end(&mut bytes);
            let status = nix::sys::wait::waitpid(child, None).map_err(SlotError::failed)?;
            read.map_err(SlotError::failed)?;
            if !matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)) {
                return Err(SlotError::failed(format!("unprivileged worker ended abnormally: {status:?}")));
            }
            let payload: Result<T, (String, String)> = serde_json::from_slice(&bytes).map_err(SlotError::failed)?;
            payload.map_err(|(code, message)| SlotError::new(code, message))
        }
    }
}

pub(crate) fn export_from(root: &Path, paths: &[PathBuf], base_exists: &dyn Fn(&Path) -> bool) -> Result<Value, SlotError> {
    let mut files = Vec::with_capacity(paths.len());
    for rel in paths {
        let display = rel.to_string_lossy().into_owned();
        ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
        let path = root.join(rel);
        let entry = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                json!({ "path": display, "kind": "deleted" })
            }
            Err(error) => return Err(SlotError::failed(error)),
            Ok(meta) if meta.file_type().is_symlink() => json!({
                "path": display,
                "kind": "symlink",
                "target": std::fs::read_link(&path).map_err(SlotError::failed)?,
            }),
            Ok(meta) if meta.is_file() => {
                if meta.len() > crate::tools::handlers::MAX_EXPORT_FILE_BYTES {
                    json!({ "path": display, "kind": "too_large", "size": meta.len() })
                } else {
                    let data = std::fs::read(&path).map_err(SlotError::failed)?;
                    json!({
                        "path": display,
                        "kind": "file",
                        "executable": meta.permissions().mode() & 0o111 != 0,
                        "existed": base_exists(rel),
                        "data_b64": base64::engine::general_purpose::STANDARD.encode(&data),
                    })
                }
            }
            Ok(meta) if meta.is_dir() => json!({ "path": display, "kind": "dir" }),
            Ok(_) => json!({ "path": display, "kind": "deleted" }),
        };
        files.push(entry);
    }
    Ok(json!({ "files": files }))
}

/// A version of one workspace path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    File { data: Vec<u8>, mode: u32 },
    Symlink { target: PathBuf },
    Dir,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do (both sides absent, or both deleted).
    Nothing,
    /// Apply the slot version to the main workspace.
    Apply,
    /// The main workspace changed since the slot opened.
    Conflict(String),
}

/// Pure three-way merge decision. The main workspace may only be touched when
/// it still matches the slot's base version.
pub fn merge_decision(base: Option<&Entry>, slot: Option<&Entry>, main: Option<&Entry>) -> Decision {
    // Main already holds exactly what the slot has (both deleted it, or another
    // merge made the same change): the edits converged, nothing to do.
    if same_version(slot, main) {
        return Decision::Nothing;
    }
    if !same_version(base, main) {
        return Decision::Conflict("main workspace changed since the slot opened".into());
    }
    // Main still equals the base: apply the slot's version (or its deletion).
    Decision::Apply
}

pub(crate) fn same_version(a: Option<&Entry>, b: Option<&Entry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Entry::File { data: a, .. }), Some(Entry::File { data: b, .. })) => a == b,
        (Some(Entry::Symlink { target: a }), Some(Entry::Symlink { target: b })) => a == b,
        (Some(Entry::Dir), Some(Entry::Dir)) => true,
        (Some(Entry::Other), Some(Entry::Other)) => true,
        _ => false,
    }
}

pub(crate) fn read_entry_opt(path: Option<&Path>) -> Result<Option<Entry>, SlotError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SlotError::failed(error)),
    };
    let file_type = meta.file_type();
    let entry = if file_type.is_symlink() {
        Entry::Symlink {
            target: std::fs::read_link(path).map_err(SlotError::failed)?,
        }
    } else if file_type.is_dir() {
        Entry::Dir
    } else if file_type.is_file() {
        Entry::File {
            data: std::fs::read(path).map_err(SlotError::failed)?,
            // Permission bits only: setuid/setgid/sticky never cross a merge.
            mode: meta.permissions().mode() & 0o777,
        }
    } else {
        Entry::Other
    };
    Ok(Some(entry))
}

pub(crate) fn apply_entry(root: &Path, rel: &Path, entry: Option<&Entry>, uid: u32, gid: u32) -> io::Result<()> {
    let target = root.join(rel);
    match entry {
        None => {
            ensure_no_symlink_parents(root, rel)?;
            remove_existing(&target)
        }
        Some(Entry::File { data, mode }) => {
            ensure_parent(root, rel, uid, gid)?;
            let name = target.file_name().unwrap_or_default().to_string_lossy();
            let temp = target.with_file_name(format!(
                ".{name}.bulge-slot-{}-{}",
                std::process::id(),
                next_temp_id()
            ));
            let write = (|| -> io::Result<()> {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temp)?;
                file.write_all(data)?;
                file.flush()?;
                drop(file);
                std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(*mode))?;
                std::os::unix::fs::chown(&temp, Some(uid), Some(gid))
            })();
            if let Err(error) = write {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
            if std::fs::symlink_metadata(&target).is_ok_and(|meta| meta.is_dir()) {
                std::fs::remove_dir_all(&target)?;
            }
            if let Err(error) = std::fs::rename(&temp, &target) {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
            Ok(())
        }
        Some(Entry::Symlink { target: link }) => {
            ensure_parent(root, rel, uid, gid)?;
            remove_existing(&target)?;
            std::os::unix::fs::symlink(link, &target)?;
            let _ = nix::unistd::fchownat(
                nix::fcntl::AT_FDCWD,
                &target,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            );
            Ok(())
        }
        Some(Entry::Dir) => {
            ensure_parent(root, rel, uid, gid)?;
            if let Ok(meta) = std::fs::symlink_metadata(&target)
                && !meta.is_dir()
            {
                remove_existing(&target)?;
            }
            std::fs::create_dir_all(&target)?;
            std::os::unix::fs::chown(&target, Some(uid), Some(gid))?;
            Ok(())
        }
        Some(Entry::Other) => Err(io::Error::other("cannot merge a special file")),
    }
}

pub(crate) fn next_temp_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn ensure_parent(root: &Path, rel: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::other(format!(
                    "refusing to traverse symlink parent {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))?;
                std::os::unix::fs::chown(&current, Some(uid), Some(gid))?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Refuse to read/write through an existing symlink in any parent component.
pub(crate) fn ensure_no_symlink_parents(root: &Path, rel: &Path) -> io::Result<()> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&current)
            && meta.file_type().is_symlink()
        {
            return Err(io::Error::other(format!(
                "refusing to traverse symlink parent {}",
                current.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn remove_existing(target: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(target),
        Ok(_) => std::fs::remove_file(target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
