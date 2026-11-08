//! Self-cleaning temporary directories.
//!
//! Tests are the main user — a test that creates `<temp_dir>/seagent-k-xxxx` and forgets it leaves
//! the tree behind in `/tmp` forever (this workspace had ~30k such leftovers). `TempDir` makes
//! the cleanup structural: the tree is removed when the guard is dropped, including on panic
//! (unwinding runs destructors), so nothing has to be remembered at the end of a test.
//!
//! Production code may use it too. The daemon, the CLI and long-lived helpers that need a scratch
//! directory (unpacking a plugin, staging a patch, spooling an upload) get the same guarantee:
//! the directory disappears when the value goes out of scope, even on an early return or `?`.
//! The only difference from a test is that callers who want to keep the tree call
//! [`TempDir::into_path`] and take ownership of the removal.
//!
//! The location follows the platform: [`std::env::temp_dir`], so `TMPDIR` is respected. Tests can
//! therefore point `TMPDIR` at a scratch directory and observe exactly what they leave behind.
//!
//! ```ignore
//! use seagent_core::tmp::TempDir;
//!
//! let dir = TempDir::new("seagent-k");            // <temp_dir>/seagent-k-<random>
//! std::fs::write(dir.path().join("x"), b"1")?;
//! // ... dropped here, whole tree removed
//! ```

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic tie-breaker so two calls in the same nanosecond (or from threads) never collide.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that removes itself (and everything inside) on drop.
///
/// Errors during removal are ignored: a `Drop` impl must not panic, and a half-removed scratch
/// tree is not worth aborting a test or a daemon over.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
    /// Set by [`TempDir::into_path`] so `Drop` leaves the tree alone.
    keep: bool,
}

/// The OS temp root (`TMPDIR` / `%TEMP%`), for code that only needs to *name* it — e.g. a backend
/// reporting where its marker files go on a non-unix host. Creating scratch trees there goes through
/// [`TempDir`], which cleans up; this keeps the raw `std::env::temp_dir` call in this one module.
pub fn system_temp_root() -> PathBuf {
    std::env::temp_dir()
}

impl TempDir {
    /// Create `<temp_dir>/<prefix>-<random>`. `TMPDIR` (via [`std::env::temp_dir`]) is respected.
    ///
    /// `prefix` should identify the caller (`"seagent-k"`, `"seagent-ch-tg"`, …) so leftovers are
    /// attributable, and so `seagent system temp-clean` can recognise them.
    pub fn new(prefix: &str) -> Self {
        Self::new_in(std::env::temp_dir(), prefix)
    }

    /// Create `<base>/<prefix>-<random>`, creating `base` if needed.
    ///
    /// Use this when the tree has to live next to other data instead of in the system temp
    /// directory (a workspace-local scratch dir, a test fixture root, a container's volume).
    pub fn new_in<P: AsRef<Path>>(base: P, prefix: &str) -> Self {
        let base = base.as_ref();
        let _ = std::fs::create_dir_all(base);
        let prefix = sanitize(prefix);
        // Retry on the (astronomically unlikely) collision instead of failing outright.
        for _ in 0..64 {
            let path = base.join(format!("{prefix}-{}", unique_suffix()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path, keep: false },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => break,
            }
        }
        // Last resort: still hand back a path so callers get a normal "no such file" error from
        // their first write rather than a panic from inside the allocator-ish helper.
        Self { path: base.join(format!("{prefix}-{}", unique_suffix())), keep: false }
    }

    /// The directory this guard owns.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keep the tree: disable the automatic removal and return the path.
    ///
    /// The caller is now responsible for deleting it (or for leaving it on purpose, e.g. a
    /// `--keep-temp` debugging flag). Tests that call this must remove the tree themselves.
    pub fn into_path(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.keep {
            remove_tree(&self.path);
        }
    }
}

/// Remove `path` (tree or single file), retrying while it keeps coming back.
///
/// A background thread or a just-killed child can still be writing into the tree when the guard
/// drops (`remove_dir_all` then fails with "directory not empty" half-way and leaves the rest).
/// A few short retries make that race lose instead of leaking the directory.
fn remove_tree(path: &Path) {
    for attempt in 0..20 {
        let gone = match std::fs::remove_dir_all(path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => std::fs::remove_file(path).is_ok(),
        };
        if gone {
            return;
        }
        if attempt < 19 {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

// Same shape as `std::path::PathBuf`: callers can use `join`/`display`/`exists` directly, and
// `&*guard` / `guard.path()` give the `&Path` that APIs want. The guard keeps owning the tree.
impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

/// Create a scratch directory that is removed when the *current thread* ends.
///
/// The test harness runs every `#[test]` on its own thread, so for a test this is "for the rest
/// of the test": callers keep the plain `PathBuf` they already pass around (no guard to thread
/// through a struct or a helper's return type), but the tree still disappears afterwards —
/// including when the test panics. Long-lived threads get the directory for their own lifetime,
/// which is the point; use [`TempDir`] directly when the tree has to go away sooner.
pub fn scratch(prefix: &str) -> PathBuf {
    thread_local! {
        // Dropped with the thread: `TempDir::drop` removes the tree.
        static HELD: RefCell<Vec<TempDir>> = const { RefCell::new(Vec::new()) };
    }
    let dir = TempDir::new(prefix);
    let path = dir.path().to_path_buf();
    HELD.with(|held| held.borrow_mut().push(dir));
    path
}

/// Register `<temp_dir>/<name>` for removal when the *current thread* ends and return the path.
///
/// Unlike [`scratch`] nothing is created: this is the drop-in for the old
/// `std::env::temp_dir().join(name)` idiom, where the caller picks a unique `name` and creates
/// the directory (or file) itself. Whatever exists at that path when the thread ends — a tree or
/// a single file — is deleted, panic included. As with [`scratch`], hand the tree to a
/// long-lived thread or a child process only if the test outlives it, otherwise use [`TempDir`].
pub fn scratch_path(name: impl AsRef<Path>) -> PathBuf {
    /// How many live threads asked for each path. Several tests may derive the same name (a
    /// `pid`-only suffix), so the tree goes away when the *last* of them ends, not the first.
    static HOLDERS: std::sync::Mutex<Vec<(PathBuf, usize)>> = std::sync::Mutex::new(Vec::new());
    struct Doomed(PathBuf);
    impl Drop for Doomed {
        fn drop(&mut self) {
            let last = {
                let mut h = HOLDERS.lock().unwrap_or_else(|e| e.into_inner());
                match h.iter().position(|(p, _)| *p == self.0) {
                    Some(i) if h[i].1 > 1 => {
                        h[i].1 -= 1;
                        false
                    }
                    Some(i) => {
                        h.swap_remove(i);
                        true
                    }
                    None => true,
                }
            };
            if last {
                remove_tree(&self.0);
            }
        }
    }
    thread_local! {
        static HELD: RefCell<Vec<Doomed>> = const { RefCell::new(Vec::new()) };
    }
    let path = std::env::temp_dir().join(name);
    {
        let mut h = HOLDERS.lock().unwrap_or_else(|e| e.into_inner());
        match h.iter_mut().find(|(p, _)| *p == path) {
            Some((_, n)) => *n += 1,
            None => h.push((path.clone(), 1)),
        }
    }
    HELD.with(|held| held.borrow_mut().push(Doomed(path.clone())));
    path
}

/// `prefix` ends up in a file name: keep it boring so odd input cannot escape `base`.
fn sanitize(prefix: &str) -> String {
    let cleaned: String = prefix
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '.' || c == '-');
    if trimmed.is_empty() {
        "tmp".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `<nanos>-<pid>-<counter>`: unique enough without pulling in `rand`.
fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{:x}-{:x}", std::process::id(), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_a_directory_under_temp_dir() {
        let td = TempDir::new("seagent-core-tmp");
        assert!(td.path().is_dir(), "{} should exist", td.path().display());
        let name = td.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("seagent-core-tmp-"), "name {name} should carry the prefix");
        assert_eq!(td.path().parent().unwrap(), std::env::temp_dir());
        // Two calls never hand out the same directory.
        let other = TempDir::new("seagent-core-tmp");
        assert_ne!(td.path(), other.path());
    }

    #[test]
    fn new_creates_the_directory_inside_its_base() {
        let base = TempDir::new("seagent-core-tmp-base");
        let td = TempDir::new_in(base.path(), "seagent-core-in");
        assert_eq!(td.path().parent().unwrap(), base.path());
        assert!(td.path().is_dir());
        // new_in also creates a base that does not exist yet.
        let nested = base.path().join("a/b");
        let td2 = TempDir::new_in(&nested, "seagent-core-in");
        assert_eq!(td2.path().parent().unwrap(), nested);
        assert!(nested.is_dir());
    }

    #[test]
    fn drop_removes_the_whole_tree() {
        let base = TempDir::new("seagent-core-tmp-drop");
        let path;
        {
            let td = TempDir::new_in(base.path(), "seagent-core-gone");
            path = td.path().to_path_buf();
            std::fs::create_dir_all(path.join("sub/dir")).unwrap();
            std::fs::write(path.join("sub/dir/file"), b"x").unwrap();
            assert!(path.is_dir());
        }
        assert!(!path.exists(), "{} should be gone after drop", path.display());
        assert!(base.path().is_dir(), "the base must survive");
    }

    #[test]
    fn drop_survives_an_already_deleted_tree() {
        let td = TempDir::new("seagent-core-tmp-twice");
        let path = td.path().to_path_buf();
        std::fs::remove_dir_all(&path).unwrap();
        drop(td); // must not panic
        assert!(!path.exists());
    }

    #[test]
    fn into_path_keeps_the_tree() {
        let base = TempDir::new("seagent-core-tmp-keep");
        let kept = TempDir::new_in(base.path(), "seagent-core-kept").into_path();
        std::fs::write(kept.join("file"), b"y").unwrap();
        assert!(kept.join("file").is_file(), "into_path must not remove the tree");
        // The test owns it now.
        std::fs::remove_dir_all(&kept).unwrap();
        assert!(!kept.exists());
    }

    #[test]
    fn scratch_path_removes_a_tree_or_a_file_when_the_last_holder_ends() {
        let name = format!("seagent-core-tmp-sp-{}", unique_suffix());
        let (tree, file) = (std::env::temp_dir().join(&name), std::env::temp_dir().join(format!("{name}.txt")));
        // Two threads derive the same name: the first to end must not pull the tree from the other.
        let (registered_tx, registered_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let n1 = name.clone();
        let first = std::thread::spawn(move || {
            let p = scratch_path(&n1);
            std::fs::create_dir_all(p.join("sub")).unwrap();
            let f = scratch_path(format!("{n1}.txt"));
            std::fs::write(f, b"x").unwrap();
            registered_tx.send(()).unwrap();
            go_rx.recv().unwrap();
        });
        registered_rx.recv().unwrap();
        let n2 = name.clone();
        let second = std::thread::spawn(move || {
            let p = scratch_path(&n2);
            go_tx.send(()).unwrap();
            first.join().unwrap();
            assert!(p.join("sub").is_dir(), "the first holder ending must leave the tree alone");
        });
        second.join().unwrap();
        assert!(!tree.exists(), "gone once the last holder ended");
        assert!(!file.exists(), "a plain file is removed as well");
    }

    #[test]
    fn scratch_lives_until_the_thread_ends() {
        // The test harness runs each `#[test]` on its own thread, so a helper that hands back a
        // plain `PathBuf` can still clean up: the guard is held per thread.
        let path = std::thread::spawn(|| {
            let p = scratch("seagent-core-tmp-scratch");
            assert!(p.is_dir(), "{} should exist inside the thread", p.display());
            assert!(p.file_name().unwrap().to_string_lossy().starts_with("seagent-core-tmp-scratch-"));
            std::fs::create_dir_all(p.join("sub")).unwrap();
            std::fs::write(p.join("sub/f"), b"x").unwrap();
            p
        })
        .join()
        .unwrap();
        assert!(!path.exists(), "{} should be gone once the thread is", path.display());
    }

    #[test]
    fn prefix_is_sanitised() {
        assert_eq!(sanitize("seagent-k"), "seagent-k");
        assert!(!sanitize("../etc").contains('/'), "a prefix must not introduce a path separator");
        assert_eq!(sanitize("a/b c"), "a_b_c");
        assert_eq!(sanitize(""), "tmp");
        let base = TempDir::new("seagent-core-tmp-sane");
        let td = TempDir::new_in(base.path(), "../escape");
        assert_eq!(td.path().parent().unwrap(), base.path());
    }
}
