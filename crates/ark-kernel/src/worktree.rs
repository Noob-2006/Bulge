//! Git worktrees for isolated work (Hermes tools/subagent_worktree.py,
//! hermes_cli/worktree_*.py; OpenClaw per-session worktrees). One worktree per
//! name under `<repo>/.worktrees/<name>` on branch `ark/<name>`. Git runs
//! non-interactively with hooks and filters disabled: the repo's own config
//! must not execute anything when ark creates or inspects a worktree.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DIR: &str = ".worktrees";
pub const BRANCH_PREFIX: &str = "ark/";
pub const ARCHIVE_REF: &str = "refs/ark/archive/";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Info {
    pub path: String,
    pub branch: String,
    pub repo_root: String,
    pub base_commit: String,
}

/// What a finished worktree left behind (the parent's result payload).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub path: String,
    pub branch: String,
    pub commits: u64,
    pub dirty: bool,
    pub pruned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn git(args: &[&str], cwd: &Path) -> Result<String, String> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-c", "commit.gpgsign=false", "-c", "user.name=ark", "-c", "user.email=ark@localhost"])
        .args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git not available: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// The git toplevel containing `path`, or None outside a work tree.
pub fn repo_root(path: &Path) -> Option<PathBuf> {
    git(&["rev-parse", "--show-toplevel"], path).ok().filter(|s| !s.is_empty()).map(PathBuf::from)
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 80 && n.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && !n.starts_with('.')
}

fn ensure_gitignore(root: &Path) {
    let p = root.join(".gitignore");
    let existing = std::fs::read_to_string(&p).unwrap_or_default();
    if !existing.lines().any(|l| l.trim() == ".worktrees/") {
        let sep = if existing.is_empty() || existing.ends_with('\n') { "" } else { "\n" };
        let _ = std::fs::write(&p, format!("{existing}{sep}.worktrees/\n"));
    }
}

/// Create `<repo>/.worktrees/<name>` on a new branch `ark/<name>` from HEAD.
pub fn create(workspace: &Path, name: &str) -> Result<Info, String> {
    if !valid_name(name) {
        return Err(format!("bad worktree name `{name}` (letters, digits, - _ .)"));
    }
    let root = repo_root(workspace).ok_or_else(|| format!("{} is not inside a git repository", workspace.display()))?;
    let path = root.join(DIR).join(name);
    if path.exists() {
        return Err(format!("worktree {} already exists", path.display()));
    }
    std::fs::create_dir_all(root.join(DIR)).map_err(|e| e.to_string())?;
    ensure_gitignore(&root);
    let base = git(&["rev-parse", "HEAD"], &root).map_err(|e| format!("repository has no commits to branch from ({e})"))?;
    let branch = format!("{BRANCH_PREFIX}{name}");
    git(&["worktree", "add", "-q", &path.to_string_lossy(), "-b", &branch, "HEAD"], &root)?;
    Ok(Info { path: path.to_string_lossy().into(), branch, repo_root: root.to_string_lossy().into(), base_commit: base })
}

/// Inspect a finished worktree. Clean with no commits → removed (branch deleted);
/// uncommitted work → committed onto an archive ref, then removed (branch kept so
/// the parent can merge it); a failed probe → kept and flagged.
pub fn finalize(info: &Info, prune: bool) -> Report {
    let path = Path::new(&info.path);
    let mut r = Report { path: info.path.clone(), branch: info.branch.clone(), ..Default::default() };
    if !path.is_dir() {
        r.pruned = true;
        return r;
    }
    let commits = git(&["rev-list", "--count", &format!("{}..HEAD", info.base_commit)], path).map(|s| s.parse::<u64>().unwrap_or(0));
    let dirty = git(&["status", "--porcelain", "--untracked-files=normal"], path).map(|s| !s.is_empty());
    let (commits, dirty) = match (commits, dirty) {
        (Ok(c), Ok(d)) => (c, d),
        (c, d) => {
            let why = [c.err(), d.err()].into_iter().flatten().collect::<Vec<_>>().join("; ");
            r.note = Some(format!("git inspection failed ({why}): commits/dirty UNKNOWN — the worktree and branch were preserved; inspect {} (branch {}) before assuming no work", info.path, info.branch));
            return r;
        }
    };
    r.commits = commits;
    r.dirty = dirty;
    if !prune {
        return r;
    }
    let root = Path::new(&info.repo_root);
    if dirty {
        // Snapshot the uncommitted state without touching the branch: a commit on a private ref.
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let archived = (|| -> Result<String, String> {
            git(&["add", "-A", "."], path)?;
            let tree = git(&["write-tree"], path)?;
            let head = git(&["rev-parse", "HEAD"], path)?;
            let c = git(&["commit-tree", &tree, "-p", &head, "-m", &format!("ark: uncommitted work left in worktree {name}")], path)?;
            let rf = format!("{ARCHIVE_REF}{name}");
            git(&["update-ref", &rf, &c], path)?;
            Ok(rf)
        })();
        match archived {
            Ok(rf) => r.archived = Some(rf),
            Err(e) => {
                r.note = Some(format!("could not archive uncommitted work ({e}); worktree kept at {}", info.path));
                return r;
            }
        }
    }
    match git(&["worktree", "remove", "--force", &info.path], root) {
        Ok(_) => {
            r.pruned = true;
            if commits == 0 && !dirty {
                let _ = git(&["branch", "-D", &info.branch], root);
            } else {
                r.note = Some(format!("work kept on branch {}{}; merge it with `git merge {}`", info.branch, r.archived.as_ref().map(|a| format!(" and archive ref {a}")).unwrap_or_default(), r.archived.as_deref().unwrap_or(&info.branch)));
            }
        }
        Err(e) => r.note = Some(format!("could not remove worktree ({e}); kept at {}", info.path)),
    }
    r
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub path: String,
    pub branch: String,
    pub head: String,
    pub ark: bool,
}

/// Worktrees of the repository containing `workspace` (`git worktree list --porcelain`).
pub fn list(workspace: &Path) -> Result<Vec<Entry>, String> {
    let root = repo_root(workspace).ok_or_else(|| format!("{} is not inside a git repository", workspace.display()))?;
    let out = git(&["worktree", "list", "--porcelain"], &root)?;
    let mut v = Vec::new();
    let mut cur: Option<Entry> = None;
    for line in out.lines().chain(std::iter::once("")) {
        if let Some(p) = line.strip_prefix("worktree ") {
            cur = Some(Entry { path: p.into(), branch: String::new(), head: String::new(), ark: Path::new(p).starts_with(root.join(DIR)) });
        } else if let Some(h) = line.strip_prefix("HEAD ") {
            if let Some(c) = cur.as_mut() {
                c.head = h.chars().take(12).collect();
            }
        } else if let Some(b) = line.strip_prefix("branch ") {
            if let Some(c) = cur.as_mut() {
                c.branch = b.trim_start_matches("refs/heads/").into();
            }
        } else if line.is_empty() {
            if let Some(c) = cur.take() {
                v.push(c);
            }
        }
    }
    Ok(v)
}

/// Remove ark worktrees with nothing in them (no commits beyond the main branch
/// head, clean), plus git's stale administrative entries. `dry_run` only reports.
pub fn prune(workspace: &Path, dry_run: bool) -> Result<Vec<String>, String> {
    let root = repo_root(workspace).ok_or_else(|| format!("{} is not inside a git repository", workspace.display()))?;
    let main_head = git(&["rev-parse", "HEAD"], &root)?;
    let mut removed = Vec::new();
    for e in list(&root)?.into_iter().filter(|e| e.ark) {
        let p = Path::new(&e.path);
        let ahead = git(&["rev-list", "--count", &format!("{main_head}..HEAD")], p).ok().and_then(|s| s.parse::<u64>().ok());
        let clean = git(&["status", "--porcelain"], p).map(|s| s.is_empty()).unwrap_or(false);
        if ahead == Some(0) && clean {
            if !dry_run {
                git(&["worktree", "remove", "--force", &e.path], &root)?;
                if !e.branch.is_empty() {
                    let _ = git(&["branch", "-D", &e.branch], &root);
                }
            }
            removed.push(e.path);
        }
    }
    if !dry_run {
        git(&["worktree", "prune"], &root)?;
    }
    Ok(removed)
}

/// Remove one worktree by name or path (`--force` semantics: uncommitted work is lost).
pub fn remove(workspace: &Path, name: &str) -> Result<String, String> {
    let root = repo_root(workspace).ok_or_else(|| format!("{} is not inside a git repository", workspace.display()))?;
    let path = if Path::new(name).is_absolute() { PathBuf::from(name) } else { root.join(DIR).join(name) };
    git(&["worktree", "remove", "--force", &path.to_string_lossy()], &root)?;
    Ok(path.to_string_lossy().into())
}

/// The worktree a workspace path lives in, when it is one of ark's (`<repo>/.worktrees/<name>`):
/// (main checkout, name).
pub fn ark_worktree_of(ws: &Path) -> Option<(PathBuf, String)> {
    let mut cur = Some(ws);
    while let Some(p) = cur {
        if p.parent().and_then(|q| q.file_name()).is_some_and(|n| n == DIR) {
            let main = p.parent()?.parent()?.to_path_buf();
            return Some((main, p.file_name()?.to_string_lossy().into()));
        }
        cur = p.parent();
    }
    None
}

fn session_ws(k: &crate::kernel::Kernel, session: &str) -> Result<PathBuf, String> {
    let ev = k.store.read(session).map_err(|e| e.to_string())?;
    Ok(PathBuf::from(crate::projection::project(&ev).workspace))
}

/// Per-session isolation (OpenClaw managed worktrees, Hermes `/worktree new`): create
/// `<repo>/.worktrees/<name>` and move `session` into it, so its tools run there from the next
/// call on. Refused while a turn runs.
pub fn enter_session(k: &crate::kernel::Kernel, session: &str, name: Option<&str>) -> Result<Info, String> {
    if k.is_running(session) {
        return Err("a turn is running; wait for it (or /stop) before moving the session".into());
    }
    let ws = session_ws(k, session)?;
    let base = ark_worktree_of(&ws).map(|(m, _)| m).unwrap_or(ws);
    let name = name.map(String::from).unwrap_or_else(|| format!("session-{}", crate::util::random_hex(6)));
    let info = create(&base, &name)?;
    if let Err(e) = k.record(session, crate::event::EventKind::Workspace { path: info.path.clone() }) {
        let _ = remove(&base, &name);
        return Err(format!("could not move the session: {e}"));
    }
    Ok(info)
}

/// Move `session` back to the main checkout and finalize its worktree: removed when empty, work
/// kept on its branch / an archive ref otherwise (see [`finalize`]).
pub fn leave_session(k: &crate::kernel::Kernel, session: &str) -> Result<Report, String> {
    if k.is_running(session) {
        return Err("a turn is running; wait for it (or /stop) first".into());
    }
    let ws = session_ws(k, session)?;
    let Some((main, name)) = ark_worktree_of(&ws) else { return Err("this session is not in a worktree".into()) };
    let info = Info { path: main.join(DIR).join(&name).to_string_lossy().into(), branch: format!("{BRANCH_PREFIX}{name}"), repo_root: main.to_string_lossy().into(), base_commit: git(&["rev-parse", "HEAD"], &main)? };
    k.record(session, crate::event::EventKind::Workspace { path: main.to_string_lossy().into() }).map_err(|e| e.to_string())?;
    Ok(finalize(&info, true))
}

#[cfg(test)]
pub(crate) fn test_repo(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ark-wt-{tag}-{}", crate::util::random_hex(8)));
    std::fs::create_dir_all(&d).unwrap();
    git(&["init", "-q"], &d).unwrap();
    std::fs::write(d.join("a.txt"), "1").unwrap();
    git(&["add", "."], &d).unwrap();
    git(&["commit", "-q", "-m", "init"], &d).unwrap();
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_finalize_clean_dirty_and_committed() {
        let repo = test_repo("fin");
        let a = create(&repo, "clean").unwrap();
        assert!(Path::new(&a.path).join("a.txt").exists() && a.branch == "ark/clean");
        assert!(std::fs::read_to_string(repo.join(".gitignore")).unwrap().contains(".worktrees/"));
        let r = finalize(&a, true);
        assert!(r.pruned && r.commits == 0 && !r.dirty && r.archived.is_none());
        assert!(git(&["rev-parse", "--verify", "-q", "ark/clean"], &repo).is_err(), "empty branch deleted");

        let b = create(&repo, "dirty").unwrap();
        std::fs::write(Path::new(&b.path).join("new.txt"), "x").unwrap();
        let r = finalize(&b, true);
        assert!(r.dirty && r.pruned && r.archived.as_deref() == Some("refs/ark/archive/dirty"), "{r:?}");
        assert!(git(&["show", "refs/ark/archive/dirty:new.txt"], &repo).unwrap() == "x", "uncommitted work kept on the archive ref");

        let c = create(&repo, "work").unwrap();
        std::fs::write(Path::new(&c.path).join("b.txt"), "y").unwrap();
        git(&["add", "."], Path::new(&c.path)).unwrap();
        git(&["commit", "-q", "-m", "w"], Path::new(&c.path)).unwrap();
        let r = finalize(&c, true);
        assert_eq!(r.commits, 1);
        assert!(r.note.unwrap().contains("ark/work"));
        assert!(git(&["rev-parse", "--verify", "-q", "ark/work"], &repo).is_ok(), "branch with commits kept");
    }

    #[test]
    fn list_prune_remove_and_errors() {
        let repo = test_repo("list");
        create(&repo, "one").unwrap();
        let two = create(&repo, "two").unwrap();
        std::fs::write(Path::new(&two.path).join("z"), "1").unwrap();
        let l = list(&repo).unwrap();
        assert_eq!(l.iter().filter(|e| e.ark).count(), 2);
        assert!(l.iter().any(|e| e.branch == "ark/one"));
        let dry = prune(&repo, true).unwrap();
        assert_eq!(dry.len(), 1, "dirty one stays: {dry:?}");
        assert!(Path::new(&dry[0]).exists(), "dry run removes nothing");
        assert_eq!(prune(&repo, false).unwrap().len(), 1);
        assert_eq!(list(&repo).unwrap().iter().filter(|e| e.ark).count(), 1);
        remove(&repo, "two").unwrap();
        assert!(!Path::new(&two.path).exists());
        assert!(create(&repo, "../x").is_err());
        let outside = std::env::temp_dir().join(format!("ark-nogit-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&outside).unwrap();
        assert!(create(&outside, "x").unwrap_err().contains("not inside a git repository"));
        assert!(repo_root(&outside).is_none());
        let a = Info { path: "/nonexistent/x".into(), branch: "b".into(), repo_root: repo.to_string_lossy().into(), base_commit: "0".into() };
        assert!(finalize(&a, true).pruned);
    }
}
