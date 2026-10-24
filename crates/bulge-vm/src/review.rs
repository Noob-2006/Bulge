//! Which workspace changes are by-products rather than work: interpreter
//! caches, build output, anything the project itself tells git to ignore.
//!
//! The rules are data, in gitignore syntax, from the same places git reads
//! them, with git's precedence (later wins): the user's review rules
//! (`~/.bulge/review_ignore`, built-in defaults when the file is absent), then
//! the workspace's `.git/info/exclude`, its root `.gitignore`, and the
//! `.gitignore` of every directory down to the changed path. Rules are read from
//! the HOST workspace as it was before the run, so the agent cannot hide a
//! change by editing a `.gitignore` in the guest.
//!
//! An ignored change is never dropped: it is still listed for review, with the
//! rule that matched, but it is not selected for write-back by default.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::changes::{Change, read_host};

/// Built-in user rules: files tools write as a side effect of running code,
/// never something a task asked for.
pub const DEFAULT_REVIEW_IGNORE: &str = "\
# By-products of running code. Edit ~/.bulge/review_ignore to change these.
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
";

/// The user's review rules (one gitignore-syntax line per entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRules {
    lines: Vec<String>,
    source: String,
}

impl ReviewRules {
    /// The built-in defaults.
    pub fn defaults() -> Self {
        Self { lines: DEFAULT_REVIEW_IGNORE.lines().map(str::to_owned).collect(), source: "built-in review rules".into() }
    }

    /// Load `path`, or the defaults when it does not exist. A pattern that is
    /// not valid gitignore syntax is an error, so a typo cannot silently widen
    /// or narrow what gets reviewed.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::defaults()),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        let rules = Self { lines: text.lines().map(str::to_owned).collect(), source: path.display().to_string() };
        let mut builder = GitignoreBuilder::new("/");
        for line in &rules.lines {
            builder.add_line(None, line).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        Ok(rules)
    }
}

/// Matcher for one review of one workspace.
pub struct ReviewIgnore {
    workspace: PathBuf,
    user: Gitignore,
    user_source: String,
    /// Per workspace-relative directory: its rule files, built on first use.
    dirs: HashMap<PathBuf, Vec<(Gitignore, String)>>,
}

impl ReviewIgnore {
    pub fn new(workspace: &Path, rules: &ReviewRules) -> Self {
        let mut builder = GitignoreBuilder::new(workspace);
        for line in &rules.lines {
            // Validated by `ReviewRules::load`; the defaults are valid.
            let _ = builder.add_line(None, line);
        }
        let user = builder.build().unwrap_or_else(|_| Gitignore::empty());
        Self { workspace: workspace.to_path_buf(), user, user_source: rules.source.clone(), dirs: HashMap::new() }
    }

    /// Why `change` is a by-product (`"<pattern>" in <file>`), or `None` if it
    /// is ordinary work.
    pub fn reason(&mut self, change: &Change) -> Option<String> {
        let rel = Path::new(change.path());
        let is_dir = matches!(change, Change::Dir { .. });
        let absolute = self.workspace.join(rel);
        let mut verdict: Option<(bool, String)> = None;
        let mut consider = |matcher: &Gitignore, source: &str| match matcher.matched_path_or_any_parents(&absolute, is_dir) {
            Match::Ignore(glob) => verdict = Some((true, format!("`{}` in {source}", glob.original()))),
            Match::Whitelist(_) => verdict = Some((false, String::new())),
            Match::None => {}
        };
        consider(&self.user, &self.user_source);
        let mut dir = PathBuf::new();
        let parents: Vec<PathBuf> = std::iter::once(PathBuf::new())
            .chain(rel.parent().into_iter().flat_map(Path::components).map(|component| {
                dir.push(component);
                dir.clone()
            }))
            .collect();
        for parent in parents {
            for (matcher, source) in self.rule_files(&parent) {
                consider(matcher, source);
            }
        }
        match verdict {
            Some((true, reason)) => Some(reason),
            _ => None,
        }
    }

    /// The rule files that apply at workspace-relative directory `dir`: the
    /// repository's `.git/info/exclude` at the root, then `dir/.gitignore`.
    /// Read without following symlinks; a missing or unreadable file has no rules.
    fn rule_files(&mut self, dir: &Path) -> &[(Gitignore, String)] {
        let workspace = self.workspace.clone();
        self.dirs.entry(dir.to_path_buf()).or_insert_with(|| {
            let mut files = Vec::new();
            let mut names = Vec::new();
            if dir.as_os_str().is_empty() {
                names.push(PathBuf::from(".git/info/exclude"));
            }
            names.push(dir.join(".gitignore"));
            for name in names {
                let Some(text) = name.to_str().and_then(|name| read_host(&workspace, name).ok()) else { continue };
                if text.is_empty() {
                    continue;
                }
                let mut builder = GitignoreBuilder::new(workspace.join(dir));
                for line in String::from_utf8_lossy(&text).lines() {
                    // Like git, an invalid pattern in a project file is skipped.
                    let _ = builder.add_line(None, line);
                }
                if let Ok(matcher) = builder.build() {
                    files.push((matcher, name.display().to_string()));
                }
            }
            files
        })
    }
}

/// Split `changes` into ignored paths with their reasons (in change order).
pub fn classify(workspace: &Path, rules: &ReviewRules, changes: &[Change]) -> Vec<(String, String)> {
    let mut ignore = ReviewIgnore::new(workspace, rules);
    changes.iter().filter_map(|change| ignore.reason(change).map(|reason| (change.path().to_owned(), reason))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("bulge-review-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file(path: &str) -> Change {
        Change::File { path: path.into(), data: Vec::new(), executable: false, existed: false }
    }

    fn ignored(workspace: &Path, rules: &ReviewRules, paths: &[&str]) -> Vec<String> {
        let changes: Vec<Change> = paths.iter().map(|p| file(p)).collect();
        classify(workspace, rules, &changes).into_iter().map(|(path, _)| path).collect()
    }

    #[test]
    fn defaults_catch_interpreter_caches_only() {
        let ws = scratch();
        let got = ignored(&ws, &ReviewRules::defaults(), &["__pycache__/inventory.cpython-312.pyc", "pkg/__pycache__/a.pyc", "x.pyc", "inventory.py", "NOTES.md", ".pytest_cache/v/cache/nodeids"]);
        assert_eq!(got, ["__pycache__/inventory.cpython-312.pyc", "pkg/__pycache__/a.pyc", "x.pyc", ".pytest_cache/v/cache/nodeids"]);
    }

    #[test]
    fn a_real_guest_python_run_leaves_only_the_edit_selected() {
        // Exactly what the guest reported after `python3 -m unittest` + one edit.
        let ws = scratch();
        let changes = vec![
            Change::Dir { path: "__pycache__".into() },
            file("__pycache__/inventory.cpython-312.pyc"),
            file("__pycache__/test_inventory.cpython-312.pyc"),
            Change::File { path: "inventory.py".into(), data: Vec::new(), executable: false, existed: true },
        ];
        let ignored: Vec<String> = classify(&ws, &ReviewRules::defaults(), &changes).into_iter().map(|(path, _)| path).collect();
        assert_eq!(ignored, ["__pycache__", "__pycache__/inventory.cpython-312.pyc", "__pycache__/test_inventory.cpython-312.pyc"]);
    }

    #[test]
    fn project_gitignores_apply_with_git_precedence() {
        let ws = scratch();
        std::fs::write(ws.join(".gitignore"), "target/\n*.log\n").unwrap();
        std::fs::create_dir_all(ws.join("app")).unwrap();
        std::fs::write(ws.join("app/.gitignore"), "!keep.log\ndist/\n").unwrap();
        std::fs::create_dir_all(ws.join(".git/info")).unwrap();
        std::fs::write(ws.join(".git/info/exclude"), "scratch.txt\n").unwrap();
        let got = ignored(&ws, &ReviewRules::defaults(), &["target/debug/app", "run.log", "app/keep.log", "app/dist/bundle.js", "scratch.txt", "src/main.rs"]);
        assert_eq!(got, ["target/debug/app", "run.log", "app/dist/bundle.js", "scratch.txt"]);
    }

    #[test]
    fn the_reason_names_the_rule_and_its_file() {
        let ws = scratch();
        std::fs::write(ws.join(".gitignore"), "*.log\n").unwrap();
        let reasons = classify(&ws, &ReviewRules::defaults(), &[file("a.log"), file("__pycache__/index.json")]);
        assert_eq!(reasons[0].1, "`*.log` in .gitignore");
        assert_eq!(reasons[1].1, "`__pycache__/` in built-in review rules");
    }

    #[test]
    fn a_linked_gitignore_is_not_followed() {
        let base = scratch();
        let ws = base.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(base.join("outside"), "*\n").unwrap();
        std::os::unix::fs::symlink(base.join("outside"), ws.join(".gitignore")).unwrap();
        assert!(ignored(&ws, &ReviewRules::defaults(), &["work.txt"]).is_empty());
    }

    #[test]
    fn user_rules_load_and_reject_bad_patterns() {
        let dir = scratch();
        assert_eq!(ReviewRules::load(&dir.join("missing")).unwrap(), ReviewRules::defaults());
        std::fs::write(dir.join("rules"), "*.tmp\n").unwrap();
        let rules = ReviewRules::load(&dir.join("rules")).unwrap();
        assert_eq!(ignored(&dir, &rules, &["a.tmp", "__pycache__/x.pyc"]), ["a.tmp"]);
        for bad in ["[z-a]", "a{b"] {
            std::fs::write(dir.join("bad"), format!("*.tmp\n{bad}\n")).unwrap();
            assert!(ReviewRules::load(&dir.join("bad")).is_err(), "{bad} must be rejected");
        }
    }
}
