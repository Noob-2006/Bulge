//! Per-session worktree moves for `/worktree` (Hermes `/worktree new|exit`, OpenClaw managed
//! worktrees). `seagent_kernel::worktree::{enter_session,leave_session}` own the git work and record
//! `EventKind::Workspace`; this module is the single place the interactive surfaces call them,
//! so `/worktree new` actually moves the session (the action it returns was dropped by every
//! dispatcher before) and `/worktree exit` brings it back.

use crate::slash::Ctx;
use seagent_kernel::worktree as wt;

/// Create `<repo>/.worktrees/<name>` and move the calling session into it, so its tools run
/// there from the next call on. Without a bound session the tree is only created, as before.
pub fn enter(c: &Ctx, name: &str) -> Result<wt::Info, String> {
    match c.session.as_deref() {
        Some(s) => wt::enter_session(c.k, s, Some(name)),
        None => wt::create(&c.workspace, name),
    }
}

/// Move the calling session back to the main checkout and finalize its worktree (removed when
/// clean, work kept on its branch / an archive ref otherwise).
pub fn leave(c: &Ctx) -> Result<String, String> {
    let s = c.session.as_deref().ok_or("no session here; run /worktree exit from a session")?;
    let r = wt::leave_session(c.k, s)?;
    let mut t = match (&r.note, r.pruned) {
        (Some(n), _) => format!("left the worktree {}\n{n}", r.path),
        (None, true) => format!("left the worktree; {} removed (branch {})", r.path, r.branch),
        (None, false) => format!("left the worktree; kept at {}", r.path),
    };
    t.push_str("\nthe session is back in the main checkout");
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_kernel::event::EventKind;
    use seagent_kernel::projection::project;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    fn git(args: &[&str], cwd: &Path) {
        let out = Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=seagent", "-c", "user.email=seagent@localhost"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn repo(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-wtsess-{tag}-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        git(&["init", "-q"], &d);
        std::fs::write(d.join("a.txt"), "1").unwrap();
        git(&["add", "."], &d);
        git(&["commit", "-q", "-m", "init"], &d);
        // How the kernel and git spell it (`layout::canonicalize`: no `\\?\` on Windows).
        seagent_core::platform::layout::canonicalize(&d).unwrap()
    }

    /// `/worktree new` reaches `worktree::enter_session`: the session's workspace moves into the
    /// tree and `EventKind::Workspace` is recorded; `/worktree exit` moves it back and reclaims
    /// the clean tree.
    #[test]
    fn slash_new_moves_the_session_and_exit_returns_it() {
        let kit = crate::testkit::kit();
        let r = repo("move");
        let id = kit.k.create_session(&r, None, None, Some("worktree")).unwrap();
        let c = Ctx { k: &kit.k, ext: None, session: Some(id.clone()), workspace: r.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };

        let rep = crate::ops::worktree::slash(&c, "new feat").unwrap();
        let path = match &rep.action {
            Some(crate::slash::Action::Local(k, p)) if k == "workspace" => PathBuf::from(p),
            other => panic!("expected the workspace action, got {other:?}"),
        };
        assert_eq!(path, r.join(".worktrees").join("feat"));
        assert!(path.join("a.txt").is_file(), "the tree was created");
        let ev = kit.k.store.read(&id).unwrap();
        assert!(ev.iter().any(|e| matches!(&e.kind, EventKind::Workspace { path: p } if Path::new(p) == path)), "EventKind::Workspace is recorded");
        assert_eq!(PathBuf::from(project(&ev).workspace), path, "the session's tools now run in the tree");

        let out = crate::ops::worktree::slash(&c, "exit").unwrap().text.unwrap();
        assert!(out.contains("main checkout"), "{out}");
        let ev = kit.k.store.read(&id).unwrap();
        assert_eq!(PathBuf::from(project(&ev).workspace), r, "back in the main checkout");
        assert!(!path.exists(), "a clean worktree is reclaimed: {out}");
    }

    /// The unbound surface (no session) still gets a tree, but nothing to move.
    #[test]
    fn new_without_a_session_only_creates_the_tree() {
        let kit = crate::testkit::kit();
        let r = repo("bare");
        let c = Ctx { k: &kit.k, ext: None, session: None, workspace: r.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        let rep = crate::ops::worktree::slash(&c, "new bare").unwrap();
        assert!(matches!(&rep.action, Some(crate::slash::Action::Local(k, p)) if k == "workspace" && Path::new(p) == r.join(".worktrees/bare")));
        assert!(crate::ops::worktree::slash(&c, "exit").unwrap_err().contains("from a session"));
    }
}
