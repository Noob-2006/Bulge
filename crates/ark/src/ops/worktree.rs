//! Managed git worktrees (Hermes `hermes worktree` list/prune/restore + `/worktree`,
//! OpenClaw `openclaw worktrees` list/create/remove/restore/gc).
//!
//! Trees live under `<repo>/.worktrees/<name>` on branch `ark/<name>` (the layout of
//! `ark_kernel::worktree`, which sub-agents also use). Removing a tree never loses
//! work: uncommitted changes are snapshotted onto `refs/ark/archive/<name>` first
//! and branches with unique commits are kept. `prune` only reclaims trees that are
//! clean, have no commits beyond the main checkout's HEAD and no live process in
//! them, plus fully merged `ark/*` branches without a tree and stale registrations.
//! `restore` recreates an archived tree with its uncommitted state back in place.

use crate::args::Args;
use crate::slash::{Ctx, Reply};
use crate::R;
use ark_kernel::worktree as wt;
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const COMMANDS: &[&str] = &["worktree", "worktrees"];
pub const VALUE_FLAGS: &[&str] = &["older-than", "path", "base-ref"];
pub const BOOL_FLAGS: &[&str] = &["dry-run", "trees-only", "branches-only", "force"];

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
        // `trim_end` only: porcelain status keeps meaning in its leading columns.
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn root_of(ws: &Path) -> Result<PathBuf, String> {
    wt::repo_root(ws).ok_or_else(|| format!("{} is not inside a git repository", ws.display()))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tree {
    pub name: String,
    pub path: String,
    pub branch: String,
    pub age_days: f64,
    pub size_mb: Option<u64>,
    /// `reap` (safe to remove) or `keep`.
    pub verdict: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct External {
    pub path: String,
    pub branch: String,
    pub missing: bool,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Branch {
    pub name: String,
    /// `delete` (merged, no tree) or `keep`.
    pub verdict: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Archive {
    pub name: String,
    pub r#ref: String,
    pub sha: String,
    pub created: u64,
    pub head: String,
    pub branch: String,
}

fn age_days(p: &Path) -> f64 {
    let m = std::fs::metadata(p).and_then(|m| m.modified()).ok();
    m.and_then(|t| t.elapsed().ok()).map(|d| d.as_secs_f64() / 86_400.0).unwrap_or(0.0)
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() && !m.file_type().is_symlink() {
                stack.push(e.path());
            } else {
                total += m.len();
            }
        }
    }
    total
}

/// Processes whose cwd is inside `p` (Linux `/proc`); a tree someone works in is never reaped.
pub fn live_pids(p: &Path) -> Vec<u32> {
    let Ok(canon) = p.canonicalize() else { return vec![] };
    let me = std::process::id();
    std::fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .filter(|pid| *pid != me)
                .filter(|pid| std::fs::read_link(format!("/proc/{pid}/cwd")).is_ok_and(|c| c.starts_with(&canon)))
                .collect()
        })
        .unwrap_or_default()
}

/// Audit every ark-managed tree. `older_than` (days) keeps younger trees regardless.
pub fn audit(ws: &Path, with_sizes: bool, older_than: Option<f64>) -> Result<(Vec<Tree>, Vec<External>), String> {
    let root = root_of(ws)?;
    let main_head = git(&["rev-parse", "HEAD"], &root)?;
    let porcelain = git(&["worktree", "list", "--porcelain"], &root)?;
    let mut locked: Vec<String> = vec![];
    let mut cur = String::new();
    for l in porcelain.lines() {
        if let Some(p) = l.strip_prefix("worktree ") {
            cur = p.to_string();
        } else if l.starts_with("locked") {
            locked.push(cur.clone());
        }
    }
    let mut trees = vec![];
    let mut ext = vec![];
    let root_s = root.to_string_lossy().to_string();
    for e in wt::list(&root)? {
        let p = Path::new(&e.path);
        if !e.ark {
            if e.path != root_s {
                ext.push(External { path: e.path.clone(), branch: e.branch.clone(), missing: !p.exists(), locked: locked.contains(&e.path) });
            }
            continue;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let age = age_days(p);
        let size_mb = with_sizes.then(|| dir_size(p) / (1024 * 1024));
        let (verdict, reason) = if !p.exists() {
            ("reap", "directory missing (stale registration)".to_string())
        } else if locked.contains(&e.path) {
            ("keep", "locked".to_string())
        } else {
            let ahead = git(&["rev-list", "--count", &format!("{main_head}..HEAD")], p).ok().and_then(|s| s.parse::<u64>().ok());
            let dirty = git(&["status", "--porcelain", "--untracked-files=normal"], p).map(|s| !s.is_empty());
            let live = live_pids(p);
            match (ahead, dirty) {
                (None, _) | (_, Err(_)) => ("keep", "git inspection failed".to_string()),
                _ if !live.is_empty() => ("keep", format!("in use by pid {}", live.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))),
                (Some(n), _) if n > 0 => ("keep", format!("{n} unique commit(s) on {}", e.branch)),
                (_, Ok(true)) => ("keep", "uncommitted changes".to_string()),
                _ if older_than.is_some_and(|d| age < d) => ("keep", format!("younger than {} day(s)", older_than.unwrap_or(0.0))),
                _ => ("reap", "clean, nothing beyond HEAD".to_string()),
            }
        };
        trees.push(Tree { name, path: e.path, branch: e.branch, age_days: (age * 10.0).round() / 10.0, size_mb, verdict: verdict.into(), reason });
    }
    Ok((trees, ext))
}

/// `ark/*` branches with no worktree: merged into HEAD → delete, else keep.
pub fn audit_branches(ws: &Path) -> Result<Vec<Branch>, String> {
    let root = root_of(ws)?;
    let checked_out: Vec<String> = wt::list(&root)?.into_iter().map(|e| e.branch).collect();
    let all = git(&["for-each-ref", "--format=%(refname:short)", &format!("refs/heads/{}", wt::BRANCH_PREFIX)], &root)?;
    let merged = git(&["branch", "--merged", "HEAD", "--format=%(refname:short)"], &root)?;
    Ok(all
        .lines()
        .filter(|b| !b.is_empty() && !checked_out.iter().any(|c| c == b))
        .map(|b| {
            if merged.lines().any(|m| m == b) {
                Branch { name: b.into(), verdict: "delete".into(), reason: "fully merged into HEAD, no worktree".into() }
            } else {
                Branch { name: b.into(), verdict: "keep".into(), reason: "has commits not in HEAD".into() }
            }
        })
        .collect())
}

pub fn archives(ws: &Path) -> Result<Vec<Archive>, String> {
    let root = root_of(ws)?;
    let out = git(&["for-each-ref", "--format=%(refname) %(objectname) %(creatordate:unix)", wt::ARCHIVE_REF], &root)?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let r = it.next()?.to_string();
            let sha = it.next()?.to_string();
            let created = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let name = r.strip_prefix(wt::ARCHIVE_REF)?.to_string();
            let head = git(&["rev-parse", &format!("{sha}^1")], &root).unwrap_or_default();
            let branch = format!("{}{name}", wt::BRANCH_PREFIX);
            let branch = if git(&["rev-parse", "--verify", "-q", &format!("refs/heads/{branch}")], &root).is_ok() { branch } else { String::new() };
            Some(Archive { name, r#ref: r, sha, created, head, branch })
        })
        .collect())
}

/// Create a managed tree, optionally from `base` instead of HEAD.
pub fn create(ws: &Path, name: &str, base: Option<&str>) -> Result<wt::Info, String> {
    match base {
        None => wt::create(ws, name),
        Some(b) => {
            let root = root_of(ws)?;
            let commit = git(&["rev-parse", "--verify", "-q", &format!("{b}^{{commit}}")], &root).map_err(|_| format!("unknown base ref `{b}`"))?;
            let info = wt::create(ws, name)?;
            git(&["reset", "-q", "--hard", &commit], Path::new(&info.path))?;
            Ok(wt::Info { base_commit: commit, ..info })
        }
    }
}

fn find_tree(ws: &Path, name: &str) -> Result<wt::Entry, String> {
    let root = root_of(ws)?;
    wt::list(&root)?
        .into_iter()
        .find(|e| e.ark && (e.path == name || Path::new(&e.path).file_name().is_some_and(|n| n == name)))
        .ok_or_else(|| format!("no managed worktree `{name}` (see `ark worktree list`)"))
}

/// Snapshot (uncommitted work → archive ref) and remove; branches with commits are kept.
pub fn remove(ws: &Path, name: &str, force: bool) -> Result<wt::Report, String> {
    let root = root_of(ws)?;
    let e = find_tree(ws, name)?;
    let live = live_pids(Path::new(&e.path));
    if !live.is_empty() && !force {
        return Err(format!("worktree {} is in use by pid {:?}; pass --force to remove anyway", e.path, live));
    }
    let main_head = git(&["rev-parse", "HEAD"], &root)?;
    let base = git(&["merge-base", &main_head, &e.head], &root).unwrap_or(main_head);
    let info = wt::Info { path: e.path.clone(), branch: e.branch.clone(), repo_root: root.to_string_lossy().into(), base_commit: base };
    let r = wt::finalize(&info, true);
    if !r.pruned && !force {
        return Err(r.note.unwrap_or_else(|| "could not remove the worktree".into()));
    }
    if !r.pruned {
        git(&["worktree", "remove", "--force", &e.path], &root)?;
    }
    Ok(r)
}

/// Recreate an archived tree with its uncommitted work restored (unstaged).
pub fn restore(ws: &Path, name: &str, target: Option<&Path>) -> Result<serde_json::Value, String> {
    let root = root_of(ws)?;
    let arc = archives(ws)?.into_iter().find(|a| a.name == name).ok_or_else(|| format!("no archive named {name} (see `ark worktree list`)"))?;
    let dest = target.map(PathBuf::from).unwrap_or_else(|| root.join(wt::DIR).join(&arc.name));
    if dest.exists() && (!dest.is_dir() || std::fs::read_dir(&dest).map(|mut d| d.next().is_some()).unwrap_or(true)) {
        return Err(format!("{} already exists; pass a different --path", dest.display()));
    }
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let d = dest.to_string_lossy().to_string();
    let detached = if !arc.branch.is_empty() {
        git(&["worktree", "add", "-q", &d, &arc.branch], &root).is_err() && {
            git(&["worktree", "add", "-q", "--detach", &d, &arc.head], &root)?;
            true
        }
    } else {
        let b = format!("{}{}", wt::BRANCH_PREFIX, arc.name);
        git(&["worktree", "add", "-q", &d, "-b", &b, &arc.head], &root)?;
        false
    };
    git(&["read-tree", &format!("{}^{{tree}}", arc.sha)], &dest)?;
    git(&["checkout-index", "-a", "-f"], &dest)?;
    git(&["read-tree", &format!("{}^{{tree}}", arc.head)], &dest)?;
    let _ = git(&["update-index", "-q", "--refresh"], &dest);
    Ok(json!({"path": d, "branch": if arc.branch.is_empty() { format!("{}{}", wt::BRANCH_PREFIX, arc.name) } else { arc.branch.clone() }, "detached": detached, "head": arc.head, "ref": arc.r#ref}))
}

/// Attended reclaim: reapable trees, stale registrations, merged branches.
pub fn prune(ws: &Path, dry: bool, older_than: Option<f64>, trees: bool, branches: bool) -> Result<(Vec<String>, Vec<Tree>), String> {
    let root = root_of(ws)?;
    let mut actions = vec![];
    let mut kept = vec![];
    if trees {
        let (recs, ext) = audit(ws, false, older_than)?;
        for e in ext.iter().filter(|e| e.missing && !e.locked) {
            actions.push(format!("prune stale registration {}", e.path));
        }
        for t in recs {
            if t.verdict != "reap" {
                kept.push(t);
                continue;
            }
            actions.push(format!("remove tree {} ({})", t.name, t.reason));
            if !dry {
                if Path::new(&t.path).exists() {
                    git(&["worktree", "remove", "--force", &t.path], &root)?;
                }
                if !t.branch.is_empty() {
                    let _ = git(&["branch", "-D", &t.branch], &root);
                }
            }
        }
        if !dry {
            git(&["worktree", "prune"], &root)?;
        }
    }
    if branches {
        for b in audit_branches(ws)?.into_iter().filter(|b| b.verdict == "delete") {
            actions.push(format!("delete branch {} ({})", b.name, b.reason));
            if !dry {
                git(&["branch", "-D", &b.name], &root)?;
            }
        }
    }
    Ok((actions, kept))
}

fn fmt_size(mb: Option<u64>) -> String {
    match mb {
        None => "?".into(),
        Some(m) if m >= 1024 => format!("{:.1}G", m as f64 / 1024.0),
        Some(m) => format!("{m}M"),
    }
}

pub fn list_text(ws: &Path, older_than: Option<f64>) -> Result<String, String> {
    let (trees, ext) = audit(ws, true, older_than)?;
    let arcs = archives(ws)?;
    let mut o = String::new();
    if !arcs.is_empty() {
        o.push_str(&format!("{} archived worktree(s) (restore with `ark worktree restore <name>`):\n", arcs.len()));
        let now = ark_kernel::event::now_ms() / 1000;
        for a in &arcs {
            o.push_str(&format!("  {:40} {:5.1}d  {}\n", a.name, now.saturating_sub(a.created) as f64 / 86_400.0, if a.branch.is_empty() { "detached" } else { &a.branch }));
        }
        o.push('\n');
    }
    if trees.is_empty() && ext.is_empty() {
        o.push_str("No worktrees under .worktrees/ — nothing to reclaim.\n");
        return Ok(o);
    }
    if !trees.is_empty() {
        let total: u64 = trees.iter().map(|t| t.size_mb.unwrap_or(0)).sum();
        let reap: u64 = trees.iter().filter(|t| t.verdict == "reap").map(|t| t.size_mb.unwrap_or(0)).sum();
        o.push_str(&format!("{:32} {:>6} {:>6} {:13} REASON\n", "TREE", "AGE", "SIZE", "VERDICT"));
        let mut sorted = trees.clone();
        sorted.sort_by_key(|t| std::cmp::Reverse(t.size_mb.unwrap_or(0)));
        for t in &sorted {
            o.push_str(&format!("{:32} {:>5.1}d {:>6} {:13} {}\n", t.name.chars().take(32).collect::<String>(), t.age_days, fmt_size(t.size_mb), t.verdict, t.reason));
        }
        o.push_str(&format!("\n{} tree(s), {} total — {} reclaimable now via `ark worktree prune`.\n", trees.len(), fmt_size(Some(total)), fmt_size(Some(reap))));
    }
    if !ext.is_empty() {
        o.push_str(&format!("\n{} externally-registered worktree(s) (never touched by prune):\n", ext.len()));
        for e in &ext {
            o.push_str(&format!("  {}  [{}]  {}\n", e.path, if e.branch.is_empty() { "?" } else { &e.branch }, if e.missing { "MISSING" } else if e.locked { "locked" } else { "ok" }));
        }
    }
    let del = audit_branches(ws)?.into_iter().filter(|b| b.verdict == "delete").count();
    if del > 0 {
        o.push_str(&format!("{del} local ark/* branch(es) fully merged into HEAD would also be deleted.\n"));
    }
    Ok(o)
}

fn older(a: &Args) -> Result<Option<f64>, String> {
    a.num::<f64>("older-than")
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some((|| -> R {
        let ws = crate::workspace(a)?;
        let js = a.flag("json");
        match a.pos(0).unwrap_or("list") {
            "list" | "ls" => {
                if js {
                    let (trees, ext) = audit(&ws, true, older(a)?)?;
                    println!("{}", serde_json::to_string_pretty(&json!({"repo": root_of(&ws)?, "trees": trees, "external_trees": ext, "branches": audit_branches(&ws)?, "archives": archives(&ws)?})).unwrap_or_default());
                } else {
                    print!("{}", list_text(&ws, older(a)?)?);
                }
                Ok(0)
            }
            "prune" | "gc" => {
                let dry = a.flag("dry-run");
                let (actions, kept) = prune(&ws, dry, older(a)?, !a.flag("branches-only"), !a.flag("trees-only"))?;
                if js {
                    println!("{}", serde_json::to_string_pretty(&json!({"repo": root_of(&ws)?, "dry_run": dry, "actions": actions, "preserved": kept})).unwrap_or_default());
                    return Ok(0);
                }
                print!("{}", prune_text(&actions, &kept, dry));
                Ok(0)
            }
            "restore" => {
                let name = a.need(1, "name")?;
                let r = restore(&ws, name, a.val("path").map(Path::new))?;
                if js {
                    println!("{r}");
                } else {
                    println!("restored {name} at {} (branch {}); its uncommitted changes are back in the working tree", r["path"].as_str().unwrap_or(""), r["branch"].as_str().unwrap_or(""));
                }
                Ok(0)
            }
            "add" | "new" | "create" => {
                let name = a.pos(1).or(a.val("name")).map(String::from).unwrap_or_else(|| format!("wt-{}", ark_kernel::util::random_hex(4)));
                let i = create(&ws, &name, a.val("base-ref"))?;
                if js {
                    println!("{}", serde_json::to_value(&i).unwrap_or_default());
                } else {
                    println!("created {} on branch {}", i.path, i.branch);
                }
                Ok(0)
            }
            "rm" | "remove" => {
                let r = remove(&ws, a.need(1, "name")?, a.flag("force"))?;
                if js {
                    println!("{}", serde_json::to_value(&r).unwrap_or_default());
                } else {
                    println!("removed {}{}", r.path, r.note.map(|n| format!(" — {n}")).unwrap_or_default());
                }
                Ok(0)
            }
            other => crate::usage(format!("unknown `worktree {other}` (list | prune [--dry-run] [--older-than DAYS] [--trees-only|--branches-only] | restore <name> [--path DIR] | add [name] [--base-ref REF] | rm <name> [--force])")),
        }
    })())
}

fn prune_text(actions: &[String], kept: &[Tree], dry: bool) -> String {
    let mut o = String::new();
    if actions.is_empty() {
        o.push_str("Nothing to reclaim — all trees/branches carry real work or are in use.\n");
    } else {
        for l in actions {
            o.push_str(&format!("  {l}\n"));
        }
        o.push_str(&format!("{} action(s) {}.\n", actions.len(), if dry { "planned" } else { "done" }));
    }
    let real: Vec<&Tree> = kept.iter().filter(|t| !t.reason.starts_with("in use")).collect();
    if !real.is_empty() {
        o.push_str(&format!("Preserved {} tree(s) with real work:\n", real.len()));
        for t in real {
            o.push_str(&format!("    {}: {}\n", t.name, t.reason));
        }
    }
    o
}

/// `/worktree [status|new [name]|exit|list|prune [--dry-run]]`.
pub fn slash(c: &Ctx, args: &str) -> Result<Reply, String> {
    let mut w = args.split_whitespace();
    let sub = w.next().unwrap_or("status").to_lowercase();
    let rest: Vec<&str> = w.collect();
    let ws = &c.workspace;
    let in_repo = wt::repo_root(ws).is_some();
    let text = match sub.as_str() {
        "status" | "show" => {
            // `repo_root()` of a linked worktree is the worktree itself, so `list()` cannot say
            // which tree this session is in: read the path (`/worktree new` moves the session).
            let mut t = match wt::ark_worktree_of(ws) {
                Some((main, name)) => format!("active worktree: {}\nbranch: {}{name}", main.join(wt::DIR).join(&name).display(), wt::BRANCH_PREFIX),
                None => "no worktree active for this session".to_string(),
            };
            t.push_str(if in_repo { "\n/worktree new [name] — create an isolated tree · /worktree exit — back to the main checkout · /worktree prune — reclaim clean trees" } else { "\n(not inside a git repository)" });
            t
        }
        _ if !in_repo => return Err(if sub == "new" { "/worktree new needs a git repository".into() } else { "not inside a git repository".into() }),
        "new" => {
            let name = rest.first().map(|s| s.to_string()).unwrap_or_else(|| format!("wt-{}", ark_kernel::util::random_hex(4)));
            // Creates the tree *and* moves the session (`worktree::enter_session` → `EventKind::Workspace`).
            let i = crate::worktree_session::enter(c, &name)?;
            let text = match c.session.is_some() {
                true => format!("created {} on branch {}\nthe session now runs there (/worktree exit returns to the main checkout)", i.path, i.branch),
                false => format!("created {} on branch {}\nwork there with `ark chat -w {}`", i.path, i.branch, i.path),
            };
            return Ok(Reply { text: Some(text), action: Some(crate::slash::Action::Local("workspace".into(), i.path)), ..Default::default() });
        }
        // Back to the main checkout (`worktree::leave_session` finalizes the tree).
        "exit" | "leave" => crate::worktree_session::leave(c)?,
        "list" => list_text(ws, None)?,
        "prune" => {
            let dry = rest.iter().any(|r| *r == "--dry-run" || *r == "-n");
            let (actions, kept) = prune(ws, dry, None, true, true)?;
            prune_text(&actions, &kept, dry)
        }
        other => return Err(format!("unknown /worktree {other} (usage: /worktree [new [name]|exit|list|prune [--dry-run]])")),
    };
    Ok(Reply { text: Some(text.trim_end().to_string()), ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-owt-{tag}-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        git(&["init", "-q"], &d).unwrap();
        std::fs::write(d.join("a.txt"), "1").unwrap();
        git(&["add", "."], &d).unwrap();
        git(&["commit", "-q", "-m", "init"], &d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn audit_prune_remove_restore() {
        let r = repo("all");
        let clean = create(&r, "clean", None).unwrap();
        let work = create(&r, "work", None).unwrap();
        std::fs::write(Path::new(&work.path).join("b.txt"), "y").unwrap();
        git(&["add", "."], Path::new(&work.path)).unwrap();
        git(&["commit", "-q", "-m", "w"], Path::new(&work.path)).unwrap();
        let dirty = create(&r, "dirty", None).unwrap();
        std::fs::write(Path::new(&dirty.path).join("a.txt"), "changed").unwrap();
        std::fs::write(Path::new(&dirty.path).join("new.txt"), "fresh").unwrap();

        let (trees, _) = audit(&r, true, None).unwrap();
        let v = |n: &str| trees.iter().find(|t| t.name == n).map(|t| (t.verdict.clone(), t.reason.clone())).unwrap();
        assert_eq!(v("clean").0, "reap");
        assert!(v("work").1.contains("1 unique commit"), "{:?}", v("work"));
        assert_eq!(v("dirty"), ("keep".into(), "uncommitted changes".into()));
        assert_eq!(audit(&r, false, Some(5.0)).unwrap().0.iter().find(|t| t.name == "clean").unwrap().verdict, "keep", "--older-than protects young trees");
        assert!(list_text(&r, None).unwrap().contains("reclaimable now"));

        // dry run changes nothing
        let (acts, _) = prune(&r, true, None, true, true).unwrap();
        assert!(acts.iter().any(|a| a.contains("remove tree clean")));
        assert!(Path::new(&clean.path).exists());
        let (acts, kept) = prune(&r, false, None, true, true).unwrap();
        assert_eq!(acts.len(), 1, "{acts:?}");
        assert!(!Path::new(&clean.path).exists() && Path::new(&work.path).exists() && Path::new(&dirty.path).exists());
        assert_eq!(kept.len(), 2);
        assert!(git(&["rev-parse", "--verify", "-q", "ark/clean"], &r).is_err());

        // remove snapshots the dirty tree; restore brings the uncommitted work back
        let rep = remove(&r, "dirty", false).unwrap();
        assert!(rep.pruned && rep.archived.as_deref() == Some("refs/ark/archive/dirty"));
        assert!(!Path::new(&dirty.path).exists());
        let arcs = archives(&r).unwrap();
        assert_eq!(arcs.len(), 1);
        let out = restore(&r, "dirty", None).unwrap();
        let p = PathBuf::from(out["path"].as_str().unwrap());
        assert_eq!(std::fs::read_to_string(p.join("a.txt")).unwrap(), "changed");
        assert_eq!(std::fs::read_to_string(p.join("new.txt")).unwrap(), "fresh");
        let st = git(&["status", "--porcelain"], &p).unwrap();
        assert!(st.contains(" M a.txt") && st.contains("?? new.txt"), "unstaged again: {st}");
        assert!(restore(&r, "dirty", None).unwrap_err().contains("already exists"));
        assert!(restore(&r, "nope", None).is_err());

        // merged branch without a tree is reclaimed by the branch pass
        git(&["branch", "ark/merged"], &r).unwrap();
        let b = audit_branches(&r).unwrap();
        assert!(b.iter().any(|x| x.name == "ark/merged" && x.verdict == "delete"));
        let (acts, _) = prune(&r, false, None, false, true).unwrap();
        assert!(acts.iter().any(|a| a.contains("ark/merged")));
        // a custom base ref
        let based = create(&r, "based", Some("HEAD")).unwrap();
        assert_eq!(based.base_commit, git(&["rev-parse", "HEAD"], &r).unwrap());
        assert!(create(&r, "bad", Some("no-such-ref")).is_err());
    }

    #[test]
    fn slash_worktree() {
        let kit = crate::testkit::kit();
        let r = repo("slash");
        let c = Ctx { k: &kit.k, ext: None, session: None, workspace: r.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        assert!(slash(&c, "").unwrap().text.unwrap().contains("no worktree active"));
        let rep = slash(&c, "new feat").unwrap();
        assert!(matches!(rep.action, Some(crate::slash::Action::Local(ref k, _)) if k == "workspace"));
        assert!(slash(&c, "list").unwrap().text.unwrap().contains("feat"));
        assert!(slash(&c, "prune --dry-run").unwrap().text.unwrap().contains("planned"));
        assert!(slash(&c, "bogus").is_err());
        let c2 = Ctx { workspace: std::env::temp_dir(), ..c };
        assert!(slash(&c2, "new").unwrap_err().contains("git repository"));
    }
}
