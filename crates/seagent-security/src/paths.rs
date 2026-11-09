//! File-tool path guards (Hermes `agent/file_safety.py`, `tools/path_security.py`;
//! OpenClaw `tools.fs.workspaceOnly`).
//!
//! Defense in depth, not a security boundary: the shell runs as the same user. The
//! value is a clear denial for models that respect tool errors and an audit trail.
//! The OS sandbox (exec backends) is what actually confines a hostile process.

#[cfg(not(windows))]
use crate::glob::normalize;
use crate::glob::{expand_home, fnmatch};
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

/// seagent's own state locations.
#[derive(Debug, Clone)]
pub struct SeagentDirs {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

const HOME_WRITE_DENIED: &[&str] = &[".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials"];
pub const HOME_CREDENTIAL_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh", ".config/gcloud"];
const SYSTEM_WRITE_DENIED: &[&str] = &["/etc/sudoers", "/etc/passwd", "/etc/shadow"];
const SYSTEM_WRITE_DENIED_DIRS: &[&str] = &["/etc/sudoers.d", "/etc/systemd"];
/// macOS: `/etc` is a symlink to `/private/etc`, so both spellings are listed (a resolved path
/// is always the `/private` one); launchd plists are the boot-persistence twin of systemd units.
const MACOS_WRITE_DENIED: &[&str] = &["/etc/sudoers", "/private/etc/sudoers", "/etc/passwd", "/private/etc/passwd", "/etc/master.passwd", "/private/etc/master.passwd"];
const MACOS_WRITE_DENIED_DIRS: &[&str] = &["/etc/sudoers.d", "/private/etc/sudoers.d", "/etc/pam.d", "/private/etc/pam.d", "/System", "/Library/LaunchDaemons", "/Library/LaunchAgents"];

/// Which OS's system-file table applies (a parameter, so every table is testable anywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemTable {
    /// Linux, Android and other unixes: the original `/etc` list.
    Unix,
    MacOs,
    Windows,
}

impl SystemTable {
    pub fn current() -> SystemTable {
        if cfg!(windows) {
            SystemTable::Windows
        } else if cfg!(any(target_os = "macos", target_os = "ios")) {
            SystemTable::MacOs
        } else {
            SystemTable::Unix
        }
    }
}

/// Windows system trees: the OS (`%SystemRoot%`, which holds `System32` and the registry
/// hive files under `System32\config`), installed programs, and the all-users Startup folder
/// (the boot-persistence twin of `/etc/systemd`). Read from the environment with the stock
/// locations as fallback, so a relocated `%SystemRoot%` is still covered.
fn windows_denied_dirs(env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let drive = env("SystemDrive").filter(|d| !d.is_empty()).unwrap_or_else(|| "C:".into());
    let mut v = vec![format!(r"{drive}\Windows"), format!(r"{drive}\Program Files"), format!(r"{drive}\Program Files (x86)"), format!(r"{drive}\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")];
    for k in ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(d) = env(k).filter(|d| !d.trim().is_empty()) {
            v.push(d);
        }
    }
    if let Some(pd) = env("ProgramData").filter(|d| !d.trim().is_empty()) {
        v.push(format!(r"{pd}\Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    v
}

/// Case-insensitive, separator-agnostic "`p` is `base` or below it" for the Windows and
/// macOS tables (both default to case-insensitive file systems). `\\?\` prefixes are ignored.
fn under_folded(p: &str, base: &str) -> bool {
    let (p, b) = (fold(p), fold(base));
    !b.is_empty() && (p == b || p.starts_with(&format!("{b}/")))
}

fn fold(s: &str) -> String {
    let s = s.strip_prefix(r"\\?\").unwrap_or(s).replace('\\', "/").to_lowercase();
    s.trim_end_matches('/').to_string()
}

/// Whether the resolved path `r` is a protected system file or lies in a protected system
/// tree on `table`'s OS.
pub fn system_write_protected(table: SystemTable, r: &Path, env: &dyn Fn(&str) -> Option<String>) -> bool {
    match table {
        SystemTable::Unix => SYSTEM_WRITE_DENIED.iter().any(|f| r == Path::new(f)) || SYSTEM_WRITE_DENIED_DIRS.iter().any(|d| under(r, Path::new(d))),
        SystemTable::MacOs => {
            let s = r.to_string_lossy();
            MACOS_WRITE_DENIED.iter().any(|f| fold(&s) == fold(f)) ||MACOS_WRITE_DENIED_DIRS.iter().any(|d| under_folded(&s, d))
        }
        SystemTable::Windows => {
            let s = r.to_string_lossy();
            windows_denied_dirs(env).iter().any(|d| under_folded(&s, d))
        }
    }
}
/// Project env files: secrets by convention (`.env.example` is the documented shape).
pub const ENV_BASENAMES: &[&str] = &[".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.staging", ".envrc"];
/// Under the data dir: credentials and seagent's own security state.
const DATA_CREDENTIALS: &[&str] = &["mcp-oauth", "node.key", "node.token", "channels/pairing.json", "approvals", "ESTOP"];
/// Under the data dir: writable only through seagent itself (forging them rewrites history).
const DATA_PROTECTED: &[&str] = &["sessions", "checkpoints"];

/// `realpath` that also works for paths that do not exist yet (resolves the
/// deepest existing ancestor and appends the rest lexically).
pub fn realpath(p: &Path) -> PathBuf {
    let p = PathBuf::from(expand_home(&p.to_string_lossy()));
    if let Ok(c) = canonical(&p) {
        return c;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.clone();
    loop {
        if let Ok(c) = canonical(&cur) {
            let mut out = c;
            for t in tail.iter().rev() {
                out.push(t);
            }
            return lexical(&out);
        }
        match (cur.file_name().map(|f| f.to_os_string()), cur.parent()) {
            (Some(f), Some(parent)) => {
                tail.push(f);
                cur = parent.to_path_buf();
            }
            _ => return lexical(&p),
        }
    }
}

#[cfg(not(windows))]
fn canonical(p: &Path) -> std::io::Result<PathBuf> {
    p.canonicalize()
}

/// Windows `canonicalize` answers in `\\?\C:\…` form; every comparison here (and every
/// message) wants the ordinary `C:\…` spelling, so the verbatim prefix is dropped.
#[cfg(windows)]
fn canonical(p: &Path) -> std::io::Result<PathBuf> {
    let c = p.canonicalize()?.to_string_lossy().into_owned();
    Ok(PathBuf::from(match c.strip_prefix(r"\\?\UNC\") {
        Some(unc) => format!(r"\\{unc}"),
        None => c.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(c),
    }))
}

#[cfg(not(windows))]
fn lexical(p: &Path) -> PathBuf {
    PathBuf::from(normalize(&p.to_string_lossy()))
}

/// Lexical `.`/`..` resolution by path components (drive prefixes and both separators),
/// the Windows counterpart of [`normalize`], which only knows `/`.
#[cfg(windows)]
fn lexical(p: &Path) -> PathBuf {
    let mut out: Vec<Component> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => out.push(c),
            },
            c => out.push(c),
        }
    }
    out.iter().collect()
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
    // Windows: the profile directory (HOME is usually unset there, or set by Git Bash).
    #[cfg(not(unix))]
    if let Some(h) = std::env::var_os("USERPROFILE") {
        let d = realpath(Path::new(&h));
        if !v.contains(&d) {
            v.push(d);
        }
    }
    // SAFETY: getpwuid returns a pointer into static storage or NULL.
    #[cfg(unix)]
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
        !g.is_empty() && (fnmatch(&g, &s) || Path::new(&g) == p || (!g.contains(['*', '?', '[']) && p.starts_with(&g)) || folded_glob_hit(&g, &s))
    }).cloned()
}

/// Windows: rules are written as `C:\Users\me\private\*` or `C:/Users/me/private/*` and the
/// file system is case-insensitive, so both sides are folded (`/`, lower case, no `\\?\`)
/// before matching (a `\` in a Windows rule is a separator, never a glob escape).
#[cfg(windows)]
fn folded_glob_hit(g: &str, s: &str) -> bool {
    let (g, s) = (fold(g), fold(s));
    fnmatch(&g, &s) || (!g.contains(['*', '?', '[']) && (s == g || s.starts_with(&format!("{g}/"))))
}

#[cfg(not(windows))]
fn folded_glob_hit(_g: &str, _s: &str) -> bool {
    false
}

/// Error when a read of `path` is denied (credential stores, `.env` files, user rules).
pub fn read_block(path: &Path, dirs: &SeagentDirs, policy: &PathPolicy) -> Option<String> {
    let r = realpath(path);
    let suffix = " (Defense-in-depth — not a security boundary.)";
    if under(&r, &realpath(&dirs.config_dir.join("secrets.toml"))) {
        return Some(format!("Access denied: {} is seagent's secret vault and cannot be read directly. Tools receive secrets through {{{{secret:NAME}}}} substitution.{suffix}", path.display()));
    }
    let data = realpath(&dirs.data_dir);
    for c in DATA_CREDENTIALS {
        if under(&r, &data.join(c)) {
            return Some(format!("Access denied: {} is an seagent credential/security store and cannot be read directly.{suffix}", path.display()));
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
pub fn write_block(path: &Path, dirs: &SeagentDirs, policy: &PathPolicy) -> Option<String> {
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
    if system_write_protected(SystemTable::current(), &r, &|k| std::env::var(k).ok()) {
        return denied("a protected system/credential file");
    }
    if under(&r, &realpath(&dirs.config_dir.join("secrets.toml"))) {
        return denied("seagent's secret vault (use `seagent secrets set`)");
    }
    let data = realpath(&dirs.data_dir);
    for c in DATA_CREDENTIALS.iter().chain(DATA_PROTECTED) {
        if under(&r, &data.join(c)) {
            return denied("seagent's own credential / session state");
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

/// seagent's own policy files: writable, but only with the user's say-so.
pub fn writes_seagent_policy(path: &Path, dirs: &SeagentDirs, workspace: &Path) -> bool {
    let r = realpath(path);
    r == realpath(&dirs.config_dir.join("config.toml")) || r == realpath(&workspace.join(".seagent/config.toml"))
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
        let d = seagent_core::tmp::scratch_path(format!("seagent-paths-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_of_credential_stores_and_env_files_are_denied() {
        let root = tmp();
        let dirs = SeagentDirs { config_dir: root.join("cfg"), data_dir: root.join("data") };
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
        // (Windows needs developer mode for symlinks; without it this part is skipped.)
        let linked = crate::os::symlink(dirs.config_dir.join("secrets.toml"), root.join("innocent.txt"));
        assert!(linked.is_ok() || !cfg!(unix), "{linked:?}");
        if linked.is_ok() {
            assert!(read_block(&root.join("innocent.txt"), &dirs, &PathPolicy::default()).is_some());
        }
    }

    #[test]
    fn writes_to_credentials_seagent_state_and_outside_safe_roots_are_denied() {
        let root = tmp();
        let dirs = SeagentDirs { config_dir: root.join("cfg"), data_dir: root.join("data") };
        let p = PathPolicy::default();
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap();
        assert!(write_block(Path::new(&format!("{home}/.ssh/authorized_keys")), &dirs, &p).is_some());
        assert!(write_block(Path::new(&format!("{home}/.aws/credentials")), &dirs, &p).is_some());
        assert!(write_block(Path::new(&format!("{home}/.ssh/config")), &dirs, &p).is_none(), "approval-gated, not denied");
        assert!(write_needs_approval(Path::new(&format!("{home}/.ssh/config"))));
        #[cfg(unix)]
        assert!(write_block(Path::new("/etc/sudoers.d/x"), &dirs, &p).is_some());
        #[cfg(windows)]
        assert!(write_block(Path::new(r"C:\Windows\System32\drivers\etc\hosts"), &dirs, &p).is_some());
        assert!(write_block(&dirs.data_dir.join("sessions/abc/log.jsonl"), &dirs, &p).is_some());
        assert!(write_block(&dirs.data_dir.join("approvals/allowlist.json"), &dirs, &p).is_some());
        assert!(write_block(&root.join("proj/x.rs"), &dirs, &p).is_none());
        let p = PathPolicy { write_safe_roots: vec![root.join("proj").display().to_string()], ..Default::default() };
        assert!(write_block(&root.join("proj/x.rs"), &dirs, &p).is_none());
        assert!(write_block(&root.join("other/x.rs"), &dirs, &p).unwrap().contains("write_safe_roots"));
        assert!(writes_seagent_policy(&dirs.config_dir.join("config.toml"), &dirs, &root.join("proj")));
    }

    #[test]
    fn workspace_containment_follows_symlinks_and_dotdot() {
        let root = tmp();
        let ws = root.join("ws");
        std::fs::create_dir_all(ws.join("sub")).unwrap();
        assert!(outside_workspace(&ws.join("sub/new.txt"), &ws, &[]).is_none());
        assert!(outside_workspace(&ws.join("../escape.txt"), &ws, &[]).is_some());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", ws.join("etc-link")).unwrap();
            assert!(outside_workspace(&ws.join("etc-link/hosts"), &ws, &[]).is_some());
        }
        assert!(outside_workspace(&root.join("art/x.txt"), &ws, &[root.join("art")]).is_none());
        assert!(validate_within_dir(&ws.join("sub/../sub/a"), &ws).is_none());
        assert!(validate_within_dir(&ws.join("../x"), &ws).is_some());
        assert!(has_traversal_component("a/../b") && !has_traversal_component("a/b..c"));
        assert!(has_unsafe_path_chars("a\nb") && has_unsafe_path_chars("a\u{2028}") && !has_unsafe_path_chars("a b/ü"));
    }

    #[test]
    fn every_os_has_its_system_write_table() {
        let none = |_: &str| None;
        let t = |table, p: &str| system_write_protected(table, Path::new(p), &none);
        // Unix (Linux/Android): exactly the original list.
        assert!(t(SystemTable::Unix, "/etc/sudoers") && t(SystemTable::Unix, "/etc/systemd/system/x.service") && t(SystemTable::Unix, "/etc/sudoers.d/x"));
        assert!(!t(SystemTable::Unix, "/etc/hosts") && !t(SystemTable::Unix, "/etc/sudoers.bak") && !t(SystemTable::Unix, "/home/u/x"));
        // macOS: both /etc spellings, launchd persistence, the sealed system volume; case-folded.
        for p in ["/private/etc/sudoers", "/etc/sudoers", "/private/etc/sudoers.d/x", "/Library/LaunchDaemons/evil.plist", "/library/launchagents/x.plist", "/System/Library/x", "/private/etc/master.passwd"] {
            assert!(t(SystemTable::MacOs, p), "{p}");
        }
        for p in ["/Users/u/Library/LaunchAgents/x.plist", "/private/etc/hosts", "/Systematic", "/private/etc/sudoers.bak"] {
            assert!(!t(SystemTable::MacOs, p), "{p}");
        }
        // Windows: the OS tree (System32, registry hives), program dirs, all-users Startup.
        for p in [r"C:\Windows\System32\drivers\etc\hosts", r"c:\windows\system32\config\SAM", r"\\?\C:\Windows\System32\x.dll", r"C:\Program Files\App\a.exe", r"C:\Program Files (x86)\x", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\run.lnk", "C:/Windows/win.ini"] {
            assert!(t(SystemTable::Windows, p), "{p}");
        }
        for p in [r"C:\Users\u\project\a.rs", r"C:\WindowsApps", r"D:\Windows\x", r"C:\ProgramData\app\x"] {
            assert!(!t(SystemTable::Windows, p), "{p}");
        }
        // A relocated %SystemRoot% / %ProgramFiles% is covered through the environment.
        let env = |k: &str| match k {
            "SystemRoot" => Some(r"D:\Win".to_string()),
            "SystemDrive" => Some("D:".to_string()),
            "ProgramFiles" => Some(r"E:\Apps".to_string()),
            _ => None,
        };
        assert!(system_write_protected(SystemTable::Windows, Path::new(r"D:\Win\System32\x"), &env));
        assert!(system_write_protected(SystemTable::Windows, Path::new(r"E:\Apps\tool\x.exe"), &env));
        assert!(system_write_protected(SystemTable::Windows, Path::new(r"D:\Windows\x"), &env));
        assert_eq!(SystemTable::current(), if cfg!(windows) { SystemTable::Windows } else if cfg!(any(target_os = "macos", target_os = "ios")) { SystemTable::MacOs } else { SystemTable::Unix });
    }
}
