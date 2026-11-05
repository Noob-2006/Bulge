//! Where outbound attachments may come from (srv-012).
//!
//! A channel that uploads "a local file" reads it on the **host**, outside the microVM /
//! bwrap sandbox the agent runs in. Without a check a model that asks Discord to
//! `upload-file` `~/.ssh/id_ed25519` would exfiltrate it, stopped only by the egress
//! approval. This is the second, independent layer: a local path is accepted only when
//! it resolves (symlinks followed) inside one of the allowed roots — the session's
//! workspace (which is also where the copy-based microVM workspace is pulled back to, and
//! where generated media lands by default) and its artifact spill directory — plus any
//! operator-listed extra roots (`ARK_SEND_ROOTS`, `:`-separated). Key material is refused
//! even inside a root.
//!
//! Two enforcement points use the same rule:
//! * [`guard_args`] in [`crate::message_tool::dispatch`] rewrites every local path a
//!   channel action names into its checked absolute form (or refuses the call) before any
//!   channel sees it — this covers every channel, including ones whose loaders are not
//!   patched individually.
//! * [`check_current`] inside the loaders that read files (`discord_actions::load_media`,
//!   Slack `upload-file`, Feishu `read_local`, Yuanbao `send_dm`), so a path that reaches
//!   a loader some other way is still refused.
//!
//! Roots travel with the call on a thread-local ([`scoped`]); a call with no scope (the
//! owner's own `ark message` CLI) is limited to the current directory.

use serde_json::Value;
use std::cell::RefCell;
use std::path::{Component, Path, PathBuf};

thread_local! {
    static SCOPE: RefCell<Option<Vec<PathBuf>>> = const { RefCell::new(None) };
}

/// Env var with extra allowed roots (`:`-separated absolute directories).
pub const EXTRA_ROOTS_ENV: &str = "ARK_SEND_ROOTS";

/// Directory names never sent, wherever they are.
const SECRET_DIRS: &[&str] = &[".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", ".gcloud"];
/// File names never sent, wherever they are.
const SECRET_FILES: &[&str] = &["secrets.enc", "secrets.key", "secrets.toml", ".netrc", ".git-credentials", ".pgpass", "credentials.json", "vault.key"];
const SECRET_PREFIXES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

pub fn extra_roots() -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut v: Vec<PathBuf> = std::env::var_os(EXTRA_ROOTS_ENV).map(|v| std::env::split_paths(&v).filter(|p| p.is_absolute()).collect()).unwrap_or_default();
    #[cfg(test)]
    TEST_ROOTS.with(|t| v.extend(t.borrow().iter().cloned()));
    v
}

#[cfg(test)]
thread_local! {
    /// Scratch dirs the channel tests write fixtures into (`testutil::temp_dir`): the
    /// tests' stand-in for a workspace.
    static TEST_ROOTS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn allow_for_tests(p: &Path) {
    TEST_ROOTS.with(|t| t.borrow_mut().push(p.to_path_buf()));
}

/// The roots a tool call may send from: its workspace, its artifact directory, and the
/// operator's extra roots.
pub fn roots_for(ctx: &ark_core::tool::ToolCtx) -> Vec<PathBuf> {
    let mut v = vec![ctx.workspace.clone(), ctx.artifacts.clone()];
    v.extend(extra_roots());
    v
}

/// Run `f` with `roots` as the allowed send roots for this thread.
pub fn scoped<T>(roots: Vec<PathBuf>, f: impl FnOnce() -> T) -> T {
    let prev = SCOPE.with(|s| s.replace(Some(roots)));
    struct Restore(Option<Vec<PathBuf>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let p = self.0.take();
            SCOPE.with(|s| *s.borrow_mut() = p);
        }
    }
    let _r = Restore(prev);
    f()
}

/// The roots in force on this thread (the scope, else the current directory + extras).
pub fn current_roots() -> Vec<PathBuf> {
    SCOPE.with(|s| s.borrow().clone()).unwrap_or_else(|| {
        let mut v: Vec<PathBuf> = std::env::current_dir().into_iter().collect();
        v.extend(extra_roots());
        v
    })
}

fn is_secret(p: &Path) -> bool {
    p.components().any(|c| match c {
        Component::Normal(n) => {
            let n = n.to_string_lossy();
            SECRET_DIRS.contains(&n.as_ref()) || SECRET_FILES.contains(&n.as_ref()) || SECRET_PREFIXES.iter().any(|x| n.starts_with(x))
        }
        _ => false,
    })
}

/// `p` (absolute, or relative to `base`) resolved with symlinks followed, if it lies
/// inside one of `roots` and is not key material.
pub fn check(p: &Path, base: &Path, roots: &[PathBuf]) -> Result<PathBuf, String> {
    let p = if p.is_absolute() { p.to_path_buf() } else { base.join(p) };
    let real = std::fs::canonicalize(&p).map_err(|e| format!("cannot send {}: {e}", p.display()))?;
    if is_secret(&real) || is_secret(&p) {
        return Err(format!("refusing to send {}: it looks like key material", p.display()));
    }
    let inside = roots.iter().filter_map(|r| std::fs::canonicalize(r).ok()).any(|r| real.starts_with(&r));
    if !inside {
        let shown: Vec<String> = roots.iter().map(|r| r.display().to_string()).collect();
        return Err(format!(
            "refusing to send {}: it is outside the workspace and the sandbox output area ({}); copy the file there first or add a root to {EXTRA_ROOTS_ENV}",
            p.display(),
            shown.join(", ")
        ));
    }
    Ok(real)
}

/// [`check`] against [`current_roots`], relative paths against the first root.
pub fn check_current(p: &Path) -> Result<PathBuf, String> {
    let roots = current_roots();
    let base = roots.first().cloned().unwrap_or_else(|| PathBuf::from("/"));
    check(p, &base, &roots)
}

/// Argument keys that carry an attachment source in some channel's action.
const MEDIA_KEYS: &[&str] = &[
    "filePath", "file_path", "path", "media", "mediaUrl", "media_url", "mediaUrls", "media_files", "file", "files", "image", "photo", "video", "audio", "voice", "document", "sticker", "animation", "attachment", "attachments", "buffer", "cover", "avatar", "thumbnail",
];

/// Does `s` name a local file (as opposed to a URL, a data: URL or a platform file id)?
fn local_ref(s: &str, base: &Path) -> Option<PathBuf> {
    let s = s.trim();
    if s.is_empty() || s.starts_with("data:") || s.contains("://") && !s.starts_with("file://") {
        return None;
    }
    let raw = s.strip_prefix("file://").unwrap_or(s);
    let looks = s.starts_with("file://") || raw.starts_with('/') || raw.starts_with("~/") || raw.starts_with("./") || raw.starts_with("../") || raw.contains('/');
    if looks {
        return Some(ark_core::tool::expand_home(raw));
    }
    // A bare name is a path only if it exists next to the workspace (otherwise it is an id).
    base.join(raw).exists().then(|| PathBuf::from(raw))
}

fn guard_value(v: &mut Value, base: &Path, roots: &[PathBuf]) -> Result<(), String> {
    match v {
        Value::String(s) => {
            if let Some(p) = local_ref(s, base) {
                *s = check(&p, base, roots)?.display().to_string();
            }
            Ok(())
        }
        Value::Array(a) => a.iter_mut().try_for_each(|x| guard_value(x, base, roots)),
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "path" || k == "url" || k == "file" {
                    guard_value(x, base, roots)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Check (and canonicalise) every local attachment path in a channel action's args.
pub fn guard_args(args: &mut Value) -> Result<(), String> {
    let roots = current_roots();
    let base = roots.first().cloned().unwrap_or_else(|| PathBuf::from("/"));
    let Value::Object(m) = args else { return Ok(()) };
    for (k, v) in m.iter_mut() {
        if MEDIA_KEYS.contains(&k.as_str()) {
            guard_value(v, &base, &roots)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp() -> (ark_core::tmp::TempDir, PathBuf, PathBuf) {
        let t = ark_core::tmp::TempDir::new("media-guard");
        let ws = t.path().join("ws");
        let home = t.path().join("home");
        std::fs::create_dir_all(ws.join("out")).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(ws.join("out/report.pdf"), b"%PDF-1.4").unwrap();
        std::fs::write(home.join(".ssh/id_ed25519"), b"KEY").unwrap();
        std::fs::write(home.join("notes.txt"), b"n").unwrap();
        (t, ws, home)
    }

    #[test]
    fn a_workspace_file_passes_and_a_host_key_is_refused() {
        let (_t, ws, home) = tmp();
        let roots = vec![ws.clone()];
        assert!(check(Path::new("out/report.pdf"), &ws, &roots).unwrap().ends_with("out/report.pdf"));
        let e = check(&home.join(".ssh/id_ed25519"), &ws, &roots).unwrap_err();
        assert!(e.contains("key material"), "{e}");
        let e = check(&home.join("notes.txt"), &ws, &roots).unwrap_err();
        assert!(e.contains("workspace"), "{e}");
        // `..` escapes are resolved before the containment check.
        assert!(check(Path::new("../home/notes.txt"), &ws, &roots).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_workspace_is_refused() {
        let (_t, ws, home) = tmp();
        std::os::unix::fs::symlink(home.join("notes.txt"), ws.join("link.txt")).unwrap();
        assert!(check(Path::new("link.txt"), &ws, std::slice::from_ref(&ws)).is_err());
    }

    #[test]
    fn key_material_is_refused_even_inside_a_root() {
        let (_t, ws, _home) = tmp();
        std::fs::create_dir_all(ws.join(".ssh")).unwrap();
        std::fs::write(ws.join(".ssh/id_rsa"), b"K").unwrap();
        assert!(check(Path::new(".ssh/id_rsa"), &ws, std::slice::from_ref(&ws)).is_err());
    }

    #[test]
    fn guard_args_rewrites_workspace_paths_and_refuses_host_paths() {
        let (_t, ws, home) = tmp();
        scoped(vec![ws.clone()], || {
            let mut a = json!({"target": "C1", "filePath": "out/report.pdf", "message": "/etc/passwd is just text"});
            guard_args(&mut a).unwrap();
            assert_eq!(a["filePath"], json!(std::fs::canonicalize(ws.join("out/report.pdf")).unwrap().display().to_string()));
            assert_eq!(a["message"], json!("/etc/passwd is just text"), "non-media keys are left alone");
            for bad in [json!({"filePath": home.join(".ssh/id_ed25519").display().to_string()}), json!({"media": format!("file://{}", home.join("notes.txt").display())}), json!({"media_files": [{"path": home.join("notes.txt").display().to_string()}]})] {
                let mut a = bad.clone();
                assert!(guard_args(&mut a).is_err(), "{bad}");
            }
            // URLs, data: URLs and platform ids pass through untouched.
            let mut a = json!({"media": "https://example.com/a.png", "image": "data:image/png;base64,AA", "file": "AgACAgIAAxkB"});
            let before = a.clone();
            guard_args(&mut a).unwrap();
            assert_eq!(a, before);
        });
    }
}
