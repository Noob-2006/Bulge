//! Private files: written atomically with mode 600 from the first byte,
//! refused when other users can read them, and changed by several processes
//! only under a lock.

use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Refuse a file that other users can read (Unix permissions).
pub fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!("{} is readable by other users; run chmod 600 on it", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Create `dir` (mode 700 on Unix) if it is missing.
pub fn create_private_dir(dir: &Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| format!("create {}: {e}", dir.display()))
}

/// `~/.bulge`, created if needed and kept mode 700: everything bulge stores
/// (jobs, memory, chat archives with their SQLite side files, keys) is then
/// private to the user whatever each file's own mode is.
pub fn bulge_home() -> Result<std::path::PathBuf, String> {
    let dir = crate::home_dir()?.join(".bulge");
    create_private_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod 700 {}: {e}", dir.display()))?;
        }
    }
    Ok(dir)
}

/// `~/.bulge/jobs`: the job store (`~/.bulge` made private first).
pub fn jobs_dir() -> Result<std::path::PathBuf, String> {
    Ok(bulge_home()?.join("jobs"))
}

/// `~/.bulge/harness`: memory, skills, roles (`~/.bulge` made private first).
pub fn harness_dir() -> Result<std::path::PathBuf, String> {
    Ok(bulge_home()?.join("harness"))
}

/// Write `bytes` to `path` atomically (temp file, fsync, rename), mode 600
/// from creation — never readable by others, not even for a moment.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut file = options.open(&tmp).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            // An existing temp file keeps its mode; force 600.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        }
        file.write_all(bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.sync_all().map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Read a private JSON file; `None` when it does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            check_private(path)?;
            serde_json::from_slice(&bytes).map(Some).map_err(|e| format!("parse {}: {e}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Write a private JSON file (pretty, atomic, mode 600).
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    write_private(path, &serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
}

/// Run `f` on the JSON file's current contents under an exclusive lock on
/// `<file>.lock`; `f` returns its result and whether it changed the data
/// (then the file is rewritten). Processes sharing a file never work from a
/// stale copy.
pub fn transact_json<T, R>(path: &Path, f: impl FnOnce(&mut T) -> Result<(R, bool), String>) -> Result<R, String>
where
    T: Serialize + DeserializeOwned + Default,
{
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }
    let lock_path = path.with_extension("lock");
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path).map_err(|e| format!("open {}: {e}", lock_path.display()))?;
    lock.lock().map_err(|e| format!("lock {}: {e}", lock_path.display()))?;
    let mut data = read_json(path)?.unwrap_or_default();
    let (out, changed) = f(&mut data)?;
    if changed {
        write_json(path, &data)?;
    }
    Ok(out)
}

/// Read a secret from a file: refused unless private, trimmed, non-empty.
pub fn read_secret_file(path: &Path) -> Result<String, String> {
    check_private(path)?;
    let value = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value = value.trim();
    if value.is_empty() { Err(format!("{} is empty", path.display())) } else { Ok(value.to_owned()) }
}

/// Held while this process is the only instance of something (a daemon).
#[derive(Debug)]
pub struct SingleInstance {
    _file: std::fs::File,
}

/// Why [`single_instance`] did not get the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Another process holds it (the message names what).
    Held(String),
    /// The lock file could not be created or locked.
    Failed(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(message) | Self::Failed(message) => f.write_str(message),
        }
    }
}

impl From<LockError> for String {
    fn from(error: LockError) -> Self {
        error.to_string()
    }
}

/// Take the exclusive lock `path` (created mode 600 in a private directory),
/// or say who holds it.
pub fn single_instance(path: &Path, what: &str) -> Result<SingleInstance, LockError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent).map_err(LockError::Failed)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|e| LockError::Failed(format!("open {}: {e}", path.display())))?;
    match file.try_lock() {
        Ok(()) => Ok(SingleInstance { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(LockError::Held(format!("another {what} is already running"))),
        Err(std::fs::TryLockError::Error(e)) => Err(LockError::Failed(format!("lock {}: {e}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bulge-util-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn private_files_are_600_from_the_start_and_shared_lists_see_each_write() {
        let dir = temp("fs");
        let path = dir.join("list.json");
        transact_json::<Vec<String>, ()>(&path, |v| {
            v.push("a".into());
            Ok(((), true))
        })
        .unwrap();
        transact_json::<Vec<String>, ()>(&path, |v| {
            v.push("b".into());
            Ok(((), true))
        })
        .unwrap();
        assert_eq!(read_json::<Vec<String>>(&path).unwrap().unwrap(), ["a", "b"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_json::<Vec<String>>(&path).unwrap_err().contains("chmod 600"));
            write_private(&dir.join("key"), b" secret \n").unwrap();
            assert_eq!(read_secret_file(&dir.join("key")).unwrap(), "secret");
            std::fs::set_permissions(dir.join("key"), std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(read_secret_file(&dir.join("key")).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_instance_is_refused_while_the_first_holds_the_lock() {
        let dir = temp("lock");
        let first = single_instance(&dir.join("serve.lock"), "serve").unwrap();
        assert!(matches!(single_instance(&dir.join("serve.lock"), "serve").unwrap_err(), LockError::Held(_)));
        drop(first);
        assert!(single_instance(&dir.join("serve.lock"), "serve").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
