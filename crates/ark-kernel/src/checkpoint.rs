//! Shadow-git workspace checkpoints: the safety net that replaces confirmation
//! prompts. Uses a separate git dir, so the user's own repository is untouched.

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Checkpoints {
    git_dir: PathBuf,
    work: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub id: String,
    pub time: String,
    pub label: String,
}

const EXCLUDES: &str = ".git/\ntarget/\nnode_modules/\n.venv/\n__pycache__/\n*.o\n.ark/cache/\n";

impl Checkpoints {
    pub fn new(data: &Path, workspace: &Path) -> Result<Self, String> {
        let work = workspace.canonicalize().map_err(|e| format!("{}: {e}", workspace.display()))?;
        if work == Path::new("/") || std::env::var_os("HOME").is_some_and(|h| Path::new(&h) == work) {
            return Err("refusing to checkpoint / or the home directory; run ark inside a project folder".into());
        }
        let key: u64 = work.to_string_lossy().bytes().fold(0xcbf29ce484222325, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        Ok(Checkpoints { git_dir: data.join("checkpoints").join(format!("{key:016x}")), work })
    }

    fn git(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .arg("--work-tree")
            .arg(&self.work)
            .args(["-c", "user.name=ark", "-c", "user.email=ark@localhost", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .output()
            .map_err(|e| format!("git not available: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn init(&self) -> Result<(), String> {
        if self.git_dir.join("HEAD").exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.git_dir).map_err(|e| e.to_string())?;
        self.git(&["init", "-q"])?;
        std::fs::create_dir_all(self.git_dir.join("info")).map_err(|e| e.to_string())?;
        std::fs::write(self.git_dir.join("info/exclude"), EXCLUDES).map_err(|e| e.to_string())
    }

    /// Snapshot the workspace. Returns None when nothing changed since the last one.
    pub fn snapshot(&self, label: &str, max_files: usize) -> Result<Option<String>, String> {
        self.init()?;
        self.git(&["add", "-A", "."])?;
        let n = self.git(&["ls-files", "--cached"])?.lines().count();
        if n > max_files {
            self.git(&["reset", "-q"]).ok();
            return Err(format!("workspace has {n} files (> {max_files}); checkpoint skipped"));
        }
        let has_head = self.git(&["rev-parse", "--verify", "-q", "HEAD"]).is_ok();
        if has_head && self.git(&["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(None);
        }
        self.git(&["commit", "-q", "--allow-empty", "-m", label])?;
        Ok(Some(self.git(&["rev-parse", "--short", "HEAD"])?.trim().to_string()))
    }

    pub fn list(&self, limit: usize) -> Result<Vec<Checkpoint>, String> {
        if !self.git_dir.join("HEAD").exists() {
            return Ok(vec![]);
        }
        let out = match self.git(&["log", &format!("-{limit}"), "--format=%h\t%ci\t%s"]) {
            Ok(o) => o,
            Err(e) if e.contains("does not have any commits") => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        Ok(out
            .lines()
            .filter_map(|l| {
                let mut p = l.splitn(3, '\t');
                Some(Checkpoint { id: p.next()?.into(), time: p.next()?.into(), label: p.next().unwrap_or("").into() })
            })
            .collect())
    }

    /// Restore the workspace to a checkpoint. The current state is snapshotted
    /// first, so a restore is itself undoable.
    pub fn restore(&self, id: &str) -> Result<Option<String>, String> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad checkpoint id `{id}`"));
        }
        self.git(&["rev-parse", "--verify", "-q", &format!("{id}^{{commit}}")]).map_err(|_| format!("no checkpoint {id}"))?;
        let before = self.snapshot(&format!("before restore to {id}"), usize::MAX)?;
        self.git(&["read-tree", "-u", "--reset", id])?;
        Ok(before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup() -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("ark-ckpt-{}", crate::util::random_hex(8)));
        let ws = root.join("ws");
        fs::create_dir_all(ws.join("src")).unwrap();
        (root.join("data"), ws)
    }

    #[test]
    fn snapshot_restore_roundtrip_including_new_and_deleted_files() {
        let (data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap();
        fs::write(ws.join("src/a.txt"), "v1").unwrap();
        fs::write(ws.join("keep.txt"), "k").unwrap();
        let first = c.snapshot("turn 1", 1000).unwrap().unwrap();
        assert_eq!(c.snapshot("again", 1000).unwrap(), None, "no change, no commit");
        fs::write(ws.join("src/a.txt"), "v2").unwrap();
        fs::write(ws.join("new.txt"), "n").unwrap();
        fs::remove_file(ws.join("keep.txt")).unwrap();
        let undo = c.restore(&first).unwrap();
        assert!(undo.is_some(), "state before restore was saved");
        assert_eq!(fs::read_to_string(ws.join("src/a.txt")).unwrap(), "v1");
        assert!(ws.join("keep.txt").exists());
        assert!(!ws.join("new.txt").exists());
        // Undo the restore.
        c.restore(&undo.unwrap()).unwrap();
        assert_eq!(fs::read_to_string(ws.join("src/a.txt")).unwrap(), "v2");
        assert!(c.list(10).unwrap().len() >= 3);
    }

    #[test]
    fn user_repo_untouched_and_excludes_respected() {
        let (data, ws) = setup();
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::create_dir_all(ws.join("target")).unwrap();
        fs::write(ws.join("target/big"), "x").unwrap();
        fs::write(ws.join("a"), "1").unwrap();
        let c = Checkpoints::new(&data, &ws).unwrap();
        c.snapshot("t", 1000).unwrap();
        let files = c.git(&["ls-files"]).unwrap();
        assert_eq!(files.trim(), "a");
        assert_eq!(fs::read_to_string(ws.join(".git/HEAD")).unwrap(), "ref: refs/heads/main\n");
    }

    #[test]
    fn failure_paths() {
        let (data, ws) = setup();
        let c = Checkpoints::new(&data, &ws).unwrap();
        assert!(c.list(5).unwrap().is_empty());
        assert!(c.restore("zzz").unwrap_err().contains("bad checkpoint"));
        assert!(c.restore("").is_err());
        fs::write(ws.join("a"), "1").unwrap();
        c.snapshot("t", 1000).unwrap();
        assert!(c.restore("deadbeef").unwrap_err().contains("no checkpoint"));
        fs::write(ws.join("b"), "1").unwrap();
        assert!(c.snapshot("t", 1).unwrap_err().contains("skipped"));
        assert!(Checkpoints::new(&data, Path::new("/")).is_err());
        assert!(Checkpoints::new(&data, Path::new("/nonexistent/ws")).is_err());
    }
}
