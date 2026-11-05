//! File-tool path guards (Hermes `agent/file_safety.py`, `tools/path_security.py`;
//! OpenClaw `tools.fs.workspaceOnly`).
//!
//! Defense in depth, not a security boundary: the shell runs as the same user. The
//! value is a clear denial for models that respect tool errors and an audit trail.
//! The OS sandbox (exec backends) is what actually confines a hostile process.

use crate::glob::{expand_home, fnmatch, normalize};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// `[security]` path keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathPolicy {
    /// File tools may only touch the workspace (plus session artifacts and skill dirs for reads).
    pub workspace_only: bool,
    /// Extra read-denied globs (`~/.config/acme/*`).
    pub read_deny: Vec<String>,
    /// Extra write-denied globs.
    pub write_deny: Vec<String>,
    /// When set, writes outside these roots are refused (Hermes HERMES_WRITE_SAFE_ROOT).
    pub write_safe_roots: Vec<String>,
}

/// ark's own state locations.
#[derive(Debug, Clone)]
pub struct ArkDirs {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

const HOME_WRITE_DENIED: &[&str] = &[".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials"];
pub const HOME_CREDENTIAL_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh", ".config/gcloud"];
const SYSTEM_WRITE_DENIED: &[&str] = &["/etc/sudoers", "/etc/passwd", "/etc/shadow"];
const SYSTEM_WRITE_DENIED_DIRS: &[&str] = &["/etc/sudoers.d", "/etc/systemd"];
/// Project env files: secrets by convention (`.env.example` is the documented shape).
pub const ENV_BASENAMES: &[&str] = &[".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.staging", ".envrc"];
/// Under the data dir: credentials and ark's own security state.
const DATA_CREDENTIALS: &[&str] = &["mcp-oauth", "node.key", "node.token", "channels/pairing.json", "approvals", "ESTOP"];
/// Under the data dir: writable only through ark itself (forging them rewrites history).
const DATA_PROTECTED: &[&str] = &["sessions", "checkpoints"];

/// `realpath` that also works for paths that do not exist yet (resolves the
/// deepest existing ancestor and appends the rest lexically).
pub fn realpath(p: &Path) -> PathBuf {
    let p = PathBuf::from(expand_home(&p.to_string_lossy()));
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.clone();
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for t in tail.iter().rev() {
                out.push(t);
            }
            return PathBuf::from(normalize(&out.to_string_lossy()));
        }
        match (cur.file_name().map(|f| f.to_os_string()), cur.parent()) {
            (Some(f), Some(parent)) => {
                tail.push(f);
                cur = parent.to_path_buf();
            }
            _ => return PathBuf::from(normalize(&p.to_string_lossy())),
        }
    }
}

fn under(p: &Path, base: &Path) -> bool {
    p == base || p.starts_with(base)
}

fn homes() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var_os("HOME") {
        v.push(realpath(Path::new(&h)));
    }
    // The real account home, when HOME was redirected (sandbox / profile homes).
    // SAFETY: getpwuid returns a pointer into static storage or NULL.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() && !(*pw).pw_dir.is_null() {
            let d = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            let d = realpath(Path::new(&d));
            if !v.contains(&d) {
                v.push(d);
            }
        }
    }
    v
}

fn glob_hit(globs: &[String], p: &Path) -> Option<String> {
    let s = p.to_string_lossy();
    globs.iter().find(|g| {
        let g = expand_home(g.trim());
        !g.is_empty() && (fnmatch(&g, &s) || Path::new(&g) == p || (!g.contains(['*', '?', '[']) && p.starts_with(&g)))
    }).cloned()
}

/// Error when a read of `path` is denied (credential stores, `.env` files, user rules).
pub fn read_block(path: &Path, dirs: &ArkDirs, policy: &PathPolicy) -> Option<String> {
    let r = realpath(path);
    let suffix = " (Defense-in-depth — not a security boundary.)";
    if under(&r, &realpath(&dirs.config_dir.join("secrets.toml"))) {
        return Some(format!("Access denied: {} is ark's secret vault and cannot be read directly. Tools receive secrets through {{{{secret:NAME}}}} substitution.{suffix}", path.display()));
    }
    let data = realpath(&dirs.data_dir);
    for c in DATA_CREDENTIALS {
        if under(&r, &data.join(c)) {
            return Some(format!("Access denied: {} is an ark credential/security store and cannot be read directly.{suffix}", path.display()));
        }
    }
    let name = r.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ENV_BASENAMES.contains(&name.as_str()) {
        return Some(format!("Access denied: {} is a secret-bearing environment file and cannot be read to prevent credential leakage. If you need to check the file structure, read .env.example instead.{suffix}", path.display()));
    }
    if let Some(g) = glob_hit(&policy.read_deny, &r) {
        return Some(format!("Access denied: {} matches security.read_deny rule '{g}'.", path.display()));
    }
    None
}

/// Error when a write to `path` is denied.
pub fn write_block(path: &Path, dirs: &ArkDirs, policy: &PathPolicy) -> Option<String> {
    let r = realpath(path);
    if write_needs_approval(path) {
        return None;
    }
    let denied = |why: &str| Some(format!("Write denied: '{}' is {why}.", path.display()));
    for h in homes() {
        if HOME_WRITE_DENIED.iter().any(|f| r == h.join(f)) || HOME_CREDENTIAL_DIRS.iter().any(|d| under(&r, &h.join(d))) {
            return denied("a protected system/credential file");
        }
    }
    if SYSTEM_WRITE_DENIED.iter().any(|f| r == Path::new(f)) || SYSTEM_WRITE_DENIED_DIRS.iter().any(|d| under(&r, Path::new(d))) {
        return denied("a protected system/credential file");
    }
    if under(&r, &realpath(&dirs.config_dir.join("secrets.toml"))) {
        return denied("ark's secret vault (use `ark secrets set`)");
    }
    let data = realpath(&dirs.data_dir);
    for c in DATA_CREDENTIALS.iter().chain(DATA_PROTECTED) {
        if under(&r, &data.join(c)) {
            return denied("ark's own credential / session state");
        }
    }
    if let Some(g) = glob_hit(&policy.write_deny, &r) {
        return Some(format!("Write denied: '{}' matches security.write_deny rule '{g}'.", path.display()));
    }
    let roots: Vec<PathBuf> = policy.write_safe_roots.iter().filter(|s| !s.trim().is_empty()).map(|s| realpath(Path::new(s.trim()))).collect();
    if !roots.is_empty() && !roots.iter().any(|root| under(&r, root)) {
        return Some(format!("Write denied: '{}' is outside security.write_safe_roots ({}).", path.display(), roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(":")));
    }
    None
}

/// Paths that hold no key bytes but can run code (`~/.ssh/config` ProxyCommand): ask first.
pub fn write_needs_approval(path: &Path) -> bool {
    let r = realpath(path);
    homes().iter().any(|h| r == h.join(".ssh/config"))
}

/// ark's own policy files: writable, but only with the user's say-so.
pub fn writes_ark_policy(path: &Path, dirs: &ArkDirs, workspace: &Path) -> bool {
    let r = realpath(path);
    r == realpath(&dirs.config_dir.join("config.toml")) || r == realpath(&workspace.join(".ark/config.toml"))
}

/// OpenClaw `workspaceOnly`: Some(error) when `path` leaves the workspace and every extra root.
pub fn outside_workspace(path: &Path, workspace: &Path, extra_roots: &[PathBuf]) -> Option<String> {
    let r = realpath(path);
    let ws = realpath(workspace);
    if under(&r, &ws) || extra_roots.iter().any(|x| under(&r, &realpath(x))) {
        return None;
    }
    Some(format!("Access denied: '{}' is outside the workspace {} (security.workspace_only).", path.display(), ws.display()))
}

/// Error when `path` does not resolve inside `root` (symlinks and `..` followed).
pub fn validate_within_dir(path: &Path, root: &Path) -> Option<String> {
    let r = realpath(path);
    let root = realpath(root);
    (!under(&r, &root)).then(|| format!("Path escapes allowed directory: {} is not under {}", r.display(), root.display()))
}

pub fn has_traversal_component(p: &str) -> bool {
    Path::new(p).components().any(|c| c == Component::ParentDir)
}

/// Control characters and Unicode line separators corrupt line protocols and forge logs.
pub fn has_unsafe_path_chars(p: &str) -> bool {
    p.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{85}' || c == '\u{2028}' || c == '\u{2029}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-paths-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_of_credential_stores_and_env_files_are_denied() {
        let root = tmp();
        let dirs = ArkDirs { config_dir: root.join("cfg"), data_dir: root.join("data") };
        let p = PathPolicy::default();
        assert!(read_block(&dirs.config_dir.join("secrets.toml"), &dirs, &p).unwrap().contains("secret vault"));
        assert!(read_block(&dirs.data_dir.join("mcp-oauth/gh.json"), &dirs, &p).is_some());
        assert!(read_block(&root.join("proj/.env"), &dirs, &p).unwrap().contains(".env.example"));
        assert!(read_block(&root.join("proj/.env.example"), &dirs, &p).is_none());
        assert!(read_block(&root.join("proj/src/main.rs"), &dirs, &p).is_none());
        let p = PathPolicy { read_deny: vec![format!("{}/private/*", root.display())], ..Default::default() };
        assert!(read_block(&root.join("private/x.txt"), &dirs, &p).unwrap().contains("read_deny"));
        // A symlink into the vault is followed.
        std::fs::create_dir_all(&dirs.config_dir).unwrap();
        std::fs::write(dirs.config_dir.join("secrets.toml"), "").unwrap();
        std::os::unix::fs::symlink(dirs.config_dir.join("secrets.toml"), root.join("innocent.txt")).unwrap();
        assert!(read_block(&root.join("innocent.txt"), &dirs, &PathPolicy::default()).is_some());
    }

    #[test]
    fn writes_to_credentials_ark_state_and_outside_safe_roots_are_denied() {
        let root = tmp();
        let dirs = ArkDirs { config_dir: root.join("cfg"), data_dir: root.join("data") };
        let p = PathPolicy::default();
        let home = std::env::var("HOME").unwrap();
        assert!(write_block(Path::new(&format!("{home}/.ssh/authorized_keys")), &dirs, &p).is_some());
        assert!(write_block(Path::new(&format!("{home}/.aws/credentials")), &dirs, &p).is_some());
        assert!(write_block(Path::new(&format!("{home}/.ssh/config")), &dirs, &p).is_none(), "approval-gated, not denied");
        assert!(write_needs_approval(Path::new(&format!("{home}/.ssh/config"))));
        assert!(write_block(Path::new("/etc/sudoers.d/x"), &dirs, &p).is_some());
        assert!(write_block(&dirs.data_dir.join("sessions/abc/log.jsonl"), &dirs, &p).is_some());
        assert!(write_block(&dirs.data_dir.join("approvals/allowlist.json"), &dirs, &p).is_some());
        assert!(write_block(&root.join("proj/x.rs"), &dirs, &p).is_none());
        let p = PathPolicy { write_safe_roots: vec![root.join("proj").display().to_string()], ..Default::default() };
        assert!(write_block(&root.join("proj/x.rs"), &dirs, &p).is_none());
        assert!(write_block(&root.join("other/x.rs"), &dirs, &p).unwrap().contains("write_safe_roots"));
        assert!(writes_ark_policy(&dirs.config_dir.join("config.toml"), &dirs, &root.join("proj")));
    }

    #[test]
    fn workspace_containment_follows_symlinks_and_dotdot() {
        let root = tmp();
        let ws = root.join("ws");
        std::fs::create_dir_all(ws.join("sub")).unwrap();
        assert!(outside_workspace(&ws.join("sub/new.txt"), &ws, &[]).is_none());
        assert!(outside_workspace(&ws.join("../escape.txt"), &ws, &[]).is_some());
        std::os::unix::fs::symlink("/etc", ws.join("etc-link")).unwrap();
        assert!(outside_workspace(&ws.join("etc-link/hosts"), &ws, &[]).is_some());
        assert!(outside_workspace(&root.join("art/x.txt"), &ws, &[root.join("art")]).is_none());
        assert!(validate_within_dir(&ws.join("sub/../sub/a"), &ws).is_none());
        assert!(validate_within_dir(&ws.join("../x"), &ws).is_some());
        assert!(has_traversal_component("a/../b") && !has_traversal_component("a/b..c"));
        assert!(has_unsafe_path_chars("a\nb") && has_unsafe_path_chars("a\u{2028}") && !has_unsafe_path_chars("a b/ü"));
    }
}
