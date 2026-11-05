//! Credential-file passthrough registry for isolated exec backends (Hermes
//! `tools/credential_files.py`).
//!
//! Sandboxes start with no host files. `security.credential_files` (and skills that
//! declare `required_credential_files`) name files under the user's home that a
//! sandbox should mount read-only at the same relative path under its home. Every
//! entry is validated here: it must be relative, stay inside the home after symlinks
//! and `..` are resolved, exist as a regular file, and must not be one of seagent's own
//! credential stores (those are read-denied).

use crate::paths::{read_block, realpath, validate_within_dir, SeagentDirs, PathPolicy};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub host: PathBuf,
    pub container: String,
}

/// Validate one home-relative entry and map it under `container_home`.
pub fn mount_for(rel: &str, home: &Path, container_home: &str, dirs: &SeagentDirs) -> Result<Mount, String> {
    let rel = rel.trim().trim_start_matches("~/");
    if rel.is_empty() {
        return Err("empty credential file entry".into());
    }
    if Path::new(rel).is_absolute() {
        return Err(format!("credential file `{rel}` must be relative to your home directory"));
    }
    if crate::paths::has_traversal_component(rel) || crate::paths::has_unsafe_path_chars(rel) {
        return Err(format!("credential file `{rel}` contains a path traversal or control character"));
    }
    let host = home.join(rel);
    if let Some(e) = validate_within_dir(&host, home) {
        return Err(format!("credential file `{rel}`: {e}"));
    }
    if let Some(e) = read_block(&host, dirs, &PathPolicy::default()) {
        return Err(format!("credential file `{rel}` is not passable: {e}"));
    }
    let real = realpath(&host);
    if !real.is_file() {
        return Err(format!("credential file `{rel}` does not exist"));
    }
    Ok(Mount { host: real, container: format!("{}/{}", container_home.trim_end_matches('/'), rel) })
}

/// Every valid mount; invalid entries are reported, never mounted.
pub fn mounts(entries: &[String], home: &Path, container_home: &str, dirs: &SeagentDirs) -> (Vec<Mount>, Vec<String>) {
    let mut ok = Vec::new();
    let mut errs = Vec::new();
    for e in entries {
        match mount_for(e, home, container_home, dirs) {
            Ok(m) if !ok.contains(&m) => ok.push(m),
            Ok(_) => {}
            Err(x) => errs.push(x),
        }
    }
    (ok, errs)
}

/// The same mounts as an exec backend takes them: `(host, container path, read_only)` —
/// credential files are always read-only — plus the entries that were refused. This is
/// the entry point bwrap / landlock / docker call; validation is [`mounts`]'.
pub fn sandbox_binds(entries: &[String], container_home: &str, host_home: &Path, dirs: &SeagentDirs) -> (Vec<(PathBuf, String, bool)>, Vec<String>) {
    let (mounts, errs) = mounts(entries, host_home, container_home, dirs);
    (mounts.into_iter().map(|m| (m.host, m.container, true)).collect(), errs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_binds_are_read_only_and_refuse_escapes() {
        let home = seagent_core::tmp::scratch_path(format!("seagent-cred-binds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::write(home.join(".config/gh/hosts.yml"), "x").unwrap();
        std::fs::write(home.join("api-token"), "t").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", home.join("escape")).unwrap_or(());
        let dirs = SeagentDirs { config_dir: home.join(".config/seagent"), data_dir: home.join(".local/share/seagent") };
        let (binds, errs) = sandbox_binds(
            &["api-token".into(), ".config/gh/hosts.yml".into(), "/etc/passwd".into(), "../x".into(), "escape".into(), "missing".into()],
            "/home/sandbox",
            &home,
            &dirs,
        );
        let real = realpath(&home.join("api-token"));
        assert_eq!(binds[0], (real, "/home/sandbox/api-token".to_string(), true), "a real home file, read-only");
        assert!(binds.iter().all(|(_, _, ro)| *ro), "credential files are never writable");
        assert_eq!(binds.len(), 2, "{binds:?}");
        assert_eq!(errs.len(), 4, "{errs:?}");
        for (needle, why) in [("/etc/passwd", "must be relative"), ("../x", "traversal"), ("escape", "escapes allowed directory"), ("missing", "does not exist")] {
            assert!(errs.iter().any(|e| e.contains(needle) && e.contains(why)), "{needle}/{why}: {errs:?}");
        }
        // seagent's own secret store is never passable, whatever the sandbox asks for.
        std::fs::create_dir_all(&dirs.config_dir).unwrap();
        std::fs::write(dirs.config_dir.join("secrets.toml"), "").unwrap();
        let (binds, errs) = sandbox_binds(&[".config/seagent/secrets.toml".into()], "/h", &home, &dirs);
        assert!(binds.is_empty() && errs[0].contains("not passable"), "{errs:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn entries_are_contained_and_existing() {
        let home = seagent_core::tmp::scratch_path(format!("seagent-cred-{}", std::process::id()));
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::write(home.join(".config/gh/hosts.yml"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", home.join("escape")).unwrap_or(());
        let dirs = SeagentDirs { config_dir: home.join(".config/seagent"), data_dir: home.join(".local/share/seagent") };
        let (m, e) = mounts(&["~/.config/gh/hosts.yml".into(), "/etc/passwd".into(), "../x".into(), "escape".into(), "missing".into(), ".config/gh/hosts.yml".into()], &home, "/home/sandbox", &dirs);
        assert_eq!(m, vec![Mount { host: realpath(&home.join(".config/gh/hosts.yml")), container: "/home/sandbox/.config/gh/hosts.yml".into() }]);
        assert_eq!(e.len(), 4, "{e:?}");
        std::fs::create_dir_all(&dirs.config_dir).unwrap();
        std::fs::write(dirs.config_dir.join("secrets.toml"), "").unwrap();
        assert!(mount_for(".config/seagent/secrets.toml", &home, "/h", &dirs).unwrap_err().contains("not passable"));
    }
}
