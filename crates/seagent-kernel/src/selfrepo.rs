//! Self-repo guard (Hermes `tools/self_repo_guard.py`): refuse git operations that
//! would rewrite the source checkout the running seagent binary was built from (checkout,
//! switch, rebase, merge, pull, restore, clean, cherry-pick, revert, bisect, reset
//! --hard/--merge/--keep, stash push, `worktree remove|move` of the root, `gh pr
//! checkout`, and git aliases that expand to those). Off by default
//! (`security.self_repo_guard`): like Hermes on POSIX, a running binary is unaffected,
//! but developers running seagent from its own tree can turn it on.

use crate::shell;
use std::path::{Path, PathBuf};

const WORKTREE_MUTATIONS: &[&str] = &["checkout", "switch", "rebase", "merge", "pull", "restore", "clean", "cherry-pick", "revert", "bisect"];
const STASH_SAFE: &[&str] = &["list", "show", "create", "store", "drop", "clear"];
const KNOWN_BUILTINS: &[&str] = &[
    "add", "am", "apply", "blame", "branch", "bundle", "cat-file", "clean", "clone", "commit", "config", "describe", "diff", "fetch", "format-patch", "grep", "help", "init", "log", "ls-files", "ls-remote", "ls-tree", "maintenance", "merge-base", "mv", "notes", "push", "range-diff", "reflog", "remote", "repack", "replace", "reset", "restore", "rev-list", "rev-parse", "rm", "shortlog", "show", "show-ref", "stash", "status", "submodule", "tag", "worktree",
];
const MAX_RECURSION: usize = 4;

/// The checkout backing this binary, when the binary runs from inside it.
pub fn running_source_root() -> Option<PathBuf> {
    seagent_core::share::running_source_root()
}

fn resolve(p: &str, base: &Path) -> PathBuf {
    let p = seagent_core::tool::expand_home(p);
    let p = if p.is_absolute() { p } else { base.join(p) };
    p.canonicalize().unwrap_or(p)
}

fn has_flag(args: &[String], long: &str, letter: char, short_only: bool) -> bool {
    args.iter().any(|a| a == long || (a.starts_with('-') && a[1..].contains(letter) && !(short_only && a.starts_with("--"))))
}

fn mutates(sub: &str, args: &[String]) -> bool {
    match sub {
        "reset" => args.iter().any(|a| matches!(a.as_str(), "--hard" | "--merge" | "--keep") || (a.starts_with("--h") && "--hard".starts_with(a.as_str()))),
        "stash" => !STASH_SAFE.contains(&args.iter().find(|a| !a.starts_with('-')).map(String::as_str).unwrap_or("push")),
        "clean" => !has_flag(args, "--dry-run", 'n', true),
        "restore" => has_flag(args, "--worktree", 'W', false) || !has_flag(args, "--staged", 'S', false),
        s => WORKTREE_MUTATIONS.contains(&s),
    }
}

fn read_alias(target: &Path, alias: &str) -> Option<String> {
    let out = std::process::Command::new("git").arg("-C").arg(target).args(["config", "--get", &format!("alias.{alias}")]).stdin(std::process::Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()).filter(|s| !s.is_empty())
}

fn inspect_git(args: &[String], cwd: &Path, root: &Path, depth: usize) -> Option<String> {
    let mut target = cwd.to_path_buf();
    let mut work_tree: Option<String> = None;
    let mut aliases: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') {
            break;
        }
        let (opt, val): (&str, Option<String>) = if ["-C", "-c", "--work-tree", "--git-dir", "--namespace", "--exec-path"].contains(&a.as_str()) {
            i += 1;
            (a.as_str(), args.get(i).cloned())
        } else if let Some(v) = a.strip_prefix("--work-tree=") {
            ("--work-tree", Some(v.to_string()))
        } else {
            (a.as_str(), None)
        };
        match (opt, val) {
            ("-C", Some(v)) => target = resolve(&v, &target),
            ("--work-tree", Some(v)) => work_tree = Some(v),
            ("-c", Some(v)) => {
                if let Some((k, val)) = v.split_once('=') {
                    if let Some(name) = k.to_lowercase().strip_prefix("alias.") {
                        aliases.push((name.to_string(), val.to_string()));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(w) = work_tree {
        target = resolve(&w, &target);
    }
    let sub = args.get(i)?.to_lowercase();
    let rest = &args[i + 1..];
    if sub == "worktree" {
        let action = rest.iter().find(|a| !a.starts_with('-'))?;
        if matches!(action.as_str(), "move" | "remove") {
            let tgt = rest.iter().skip_while(|a| *a != action).skip(1).find(|a| !a.starts_with('-'))?;
            if resolve(tgt, &target) == root {
                return Some(format!("git worktree {action}"));
            }
        }
        return None;
    }
    if !target.starts_with(root) {
        return None;
    }
    if mutates(&sub, rest) {
        return Some(format!("git {sub}"));
    }
    if KNOWN_BUILTINS.contains(&sub.as_str()) || depth >= MAX_RECURSION {
        return None;
    }
    let alias = aliases.iter().find(|(n, _)| *n == sub).map(|(_, v)| v.clone()).or_else(|| read_alias(&target, &sub))?;
    if let Some(sh) = alias.strip_prefix('!') {
        return find_mutation_at(sh, &target, root, depth + 1);
    }
    let mut a: Vec<String> = alias.split_whitespace().map(String::from).collect();
    a.extend(rest.iter().cloned());
    inspect_git(&a, &target, root, depth + 1)
}

fn find_mutation_at(command: &str, cwd: &Path, root: &Path, depth: usize) -> Option<String> {
    if depth > MAX_RECURSION {
        return None;
    }
    let mut cwd = cwd.to_path_buf();
    for c in shell::parse(command) {
        let args = &c.argv[1.min(c.argv.len())..];
        match c.name() {
            "cd" | "pushd" => {
                if let Some(t) = args.iter().find(|a| !a.starts_with('-')) {
                    let p = resolve(t, &cwd);
                    if p.is_dir() {
                        cwd = p;
                    }
                }
            }
            "git" => {
                if let Some(op) = inspect_git(args, &cwd, root, depth) {
                    return Some(op);
                }
            }
            n @ ("gh" | "hub") => {
                let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
                if cwd.starts_with(root) && pos.len() >= 2 && pos[0] == "pr" && pos[1] == "checkout" {
                    return Some(format!("{n} pr checkout"));
                }
            }
            _ => {}
        }
    }
    None
}

/// Name of the first operation in `command` that would rewrite `root`.
pub fn find_mutation(command: &str, cwd: &Path, root: &Path) -> Option<String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    find_mutation_at(command, &cwd, &root, 0)
}

pub fn block_message(op: &str, root: &Path) -> String {
    format!("Blocked: `{op}` would rewrite seagent's own source checkout ({}). Use a separate worktree or a shared clone on real disk, e.g. `git clone --shared {} ~/scratch/<task>` (avoid /tmp, which is often RAM-backed). To change this checkout, stop seagent, run the command yourself, then restart seagent.", root.display(), root.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_worktree_rewrites_only_inside_root() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-selfrepo-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let other = seagent_core::tmp::scratch("seagent-ws");
        for (cmd, op) in [
            ("git checkout main", "git checkout"),
            ("git reset --hard HEAD~1", "git reset"),
            ("git reset --ha", "git reset"),
            ("git stash", "git stash"),
            ("git clean -fd", "git clean"),
            ("cd sub && git pull", "git pull"),
            ("git -c alias.co=checkout co x", "git checkout"),
            ("git -c 'alias.nuke=!git reset --hard' nuke", "git reset"),
            ("bash -c 'git rebase main'", "git rebase"),
            ("gh pr checkout 12", "gh pr checkout"),
        ] {
            assert_eq!(find_mutation(cmd, &root, &root).as_deref(), Some(op), "{cmd}");
        }
        for cmd in ["git status", "git log -5", "git reset --soft HEAD~1", "git stash list", "git clean -n", "git restore --staged x", "git diff", "git commit -m 'git checkout'"] {
            assert_eq!(find_mutation(cmd, &root, &root), None, "{cmd}");
        }
        assert_eq!(find_mutation("git checkout main", &other, &root), None, "other repo");
        assert_eq!(find_mutation(&format!("git -C {} checkout x", root.display()), &other, &root).as_deref(), Some("git checkout"));
        assert_eq!(find_mutation(&format!("git worktree remove {}", root.display()), &other, &root).as_deref(), Some("git worktree remove"));
        assert!(block_message("git checkout", &root).contains("separate worktree"));
    }
}
