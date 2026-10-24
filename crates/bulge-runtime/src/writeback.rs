//! Write-back policy and the `writebacks` / `rollback` commands.
//!
//! In full-auto mode a finished turn writes its changes back by itself — under
//! a snapshot, so every such write-back can be undone in one step — except
//! what the risk gate holds for a human and the by-products review rules
//! exclude (ORG.md §11 decision 1, CORE.md §0). Other modes never write back
//! on their own; there a human approves the diff, and that write-back is
//! snapshotted the same way.

use std::path::{Path, PathBuf};

use bulge_guard::risk::{self, Autonomy, ChangeKind};
use bulge_vm::changes::Change;
use bulge_vm::writeback::{self, Manifest, State};

/// The risk tier of one change.
pub fn change_risk(change: &Change) -> risk::Risk {
    let kind = match change {
        Change::File { existed: true, .. } => ChangeKind::Modify,
        Change::File { .. } | Change::TooLarge { .. } => ChangeKind::Add,
        Change::Deleted { .. } => ChangeKind::Delete,
        Change::Dir { .. } => ChangeKind::Dir,
        Change::Symlink { .. } => ChangeKind::Symlink,
    };
    let executable = matches!(change, Change::File { executable: true, .. });
    let path = change.path();
    risk::classify_change(kind, executable || risk::is_sensitive_path(path), risk::runs_on_host(path))
}

/// The paths full-auto writes back without asking: everything the risk gate
/// allows in full-auto, except by-products (`ignored`) and changes too large to
/// transfer. The rest stays in the diff for a human.
pub fn auto_selection(changes: &[Change], ignored: &[(String, String)]) -> Vec<String> {
    changes
        .iter()
        .filter(|change| !matches!(change, Change::TooLarge { .. }))
        .filter(|change| !ignored.iter().any(|(path, _)| path == change.path()))
        .filter(|change| risk::gate(change_risk(change), Autonomy::FullAuto) == bulge_guard::Effect::Allow)
        .map(|change| change.path().to_owned())
        .collect()
}

/// One line describing a write-back for listings.
pub fn describe(manifest: &Manifest) -> String {
    let state = match manifest.state {
        State::Pending => "interrupted",
        State::Applied => "applied",
        State::RolledBack => "rolled back",
        State::PartiallyRolledBack => "partly rolled back",
    };
    format!(
        "{}  {}  {} path(s){}  {}",
        manifest.id,
        state,
        manifest.applied_paths().len(),
        if manifest.skipped.is_empty() { String::new() } else { format!(", {} skipped", manifest.skipped.len()) },
        if manifest.auto { "auto (full-auto rules)" } else { "approved by a human" },
    )
}

/// The newest write-back of a job that can still be rolled back.
pub fn latest_undoable(job_dir: &Path) -> Option<Manifest> {
    writeback::list(job_dir).into_iter().rev().find(|m| !matches!(m.state, State::RolledBack))
}

const USAGE: &str = "\
usage:
    bulge writebacks <job-id> [--store DIR]
    bulge rollback <job-id> [<writeback-id>] [--force] [--store DIR]
  `rollback` without an id undoes the job's newest write-back. A path changed
  since the write-back is left alone (reported as a conflict) unless --force.
";

/// `bulge writebacks …` / `bulge rollback …`. Returns the process exit code.
pub fn dispatch(command: &str, args: &[String]) -> i32 {
    let mut positional: Vec<&str> = Vec::new();
    let mut store: Option<PathBuf> = None;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--force" => force = true,
            "--store" => match iter.next() {
                Some(dir) => store = Some(PathBuf::from(dir)),
                None => {
                    eprint!("error: --store needs a directory\n{USAGE}");
                    return 2;
                }
            },
            flag if flag.starts_with("--") => {
                eprint!("error: unknown flag {flag}\n{USAGE}");
                return 2;
            }
            value => positional.push(value),
        }
    }
    let Some(job_id) = positional.first() else {
        eprint!("{USAGE}");
        return 2;
    };
    if job_id.contains('/') || job_id.contains("..") {
        eprintln!("error: not a job id: {job_id}");
        return 2;
    }
    let store = match store {
        Some(store) => store,
        None => match bulge_util::fs::jobs_dir() {
            Ok(jobs) => jobs,
            Err(error) => {
                eprintln!("error: {error}; pass --store");
                return 2;
            }
        },
    };
    let job_dir = store.join(job_id);
    if !job_dir.is_dir() {
        eprintln!("error: no job {job_id} under {}", store.display());
        return 1;
    }

    match command {
        "writebacks" => {
            let all = writeback::list(&job_dir);
            if all.is_empty() {
                println!("no write-backs for {job_id}");
            }
            for manifest in all {
                println!("{}", describe(&manifest));
            }
            0
        }
        _ => {
            let id = match positional.get(1) {
                Some(id) => (*id).to_owned(),
                None => match latest_undoable(&job_dir) {
                    Some(manifest) => manifest.id,
                    None => {
                        eprintln!("nothing to roll back for {job_id}");
                        return 1;
                    }
                },
            };
            match writeback::rollback(&job_dir, &id, force) {
                Ok(report) => {
                    println!("rolled back {id}: {} path(s) restored", report.restored.len());
                    for (path, why) in &report.conflicts {
                        println!("  left as is: {path} ({why})");
                    }
                    if !report.conflicts.is_empty() && !force {
                        println!("  (rerun with --force to overwrite those too)");
                    }
                    i32::from(!report.conflicts.is_empty())
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    1
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, existed: bool, executable: bool) -> Change {
        Change::File { path: path.into(), data: b"x".to_vec(), executable, existed }
    }

    #[test]
    fn full_auto_takes_all_but_by_products_oversized_and_what_the_host_would_run() {
        let changes = vec![
            file("src/a.rs", true, false),
            file("new.txt", false, false),
            Change::Deleted { path: "old.txt".into() },
            file(".env", true, false),
            file("run.sh", false, true),
            Change::Symlink { path: "ln".into(), target: "a".into() },
            file(".git/hooks/pre-commit", false, true),
            file(".git/config", true, false),
            file("__pycache__/m.pyc", false, false),
            Change::TooLarge { path: "big.bin".into(), size: 1 << 30 },
        ];
        let ignored = vec![("__pycache__/m.pyc".to_string(), "rule".to_string())];
        // Symlinks and git internals stay for a human: the host would follow
        // or run them (a hook or `core.fsmonitor` runs on the next `git status`).
        assert_eq!(auto_selection(&changes, &ignored), ["src/a.rs", "new.txt", "old.txt", ".env", "run.sh"]);
        assert_eq!(change_risk(&changes[6]), risk::Risk::High);
        assert_eq!(change_risk(&changes[3]), risk::Risk::Medium);
        assert_eq!(change_risk(&changes[0]), risk::Risk::Low);
    }

    #[test]
    fn rollback_command_undoes_the_newest_write_back() {
        let base = std::env::temp_dir().join(format!("bulge-wb-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (store, ws) = (base.join("jobs"), base.join("ws"));
        std::fs::create_dir_all(store.join("j-1")).unwrap();
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("a"), "before").unwrap();
        let change = vec![Change::File { path: "a".into(), data: b"after".to_vec(), executable: false, existed: true }];
        writeback::apply(&ws, &change, &["a".into()], &store.join("j-1"), true).unwrap();
        let args = vec!["j-1".to_string(), "--store".into(), store.display().to_string()];
        assert_eq!(dispatch("rollback", &args), 0);
        assert_eq!(std::fs::read_to_string(ws.join("a")).unwrap(), "before");
        assert_eq!(dispatch("rollback", &args), 1, "nothing left to roll back");
        assert_eq!(dispatch("writebacks", &args), 0);
    }
}
