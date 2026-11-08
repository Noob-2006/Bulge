//! Agent scratch and idle-worktree hygiene (OpenClaw `src/infra/scratch-expiry.ts`,
//! `scratch-cleanup.ts` and the 7-day idle worktree GC).
//!
//! The daemon runs this on its retention pass. Scratch roots are the stable places seagent and
//! its tools put disposable data — `<data>/tmp`, `<data>/scratch`, `<data>/art` and each
//! session's `artifacts/` — and trailing worktrees under a session workspace's
//! `<repo>/.worktrees/`. Cleanup is age-based, never follows symlinks, and skips a session that
//! is running (a live turn may still be writing its artifacts).
//!
//! Config (all optional, `[automation]`):
//! - `scratch_ttl_hours` (default 24; 0 disables scratch expiry)
//! - `worktree_idle_hours` (default 168; 0 disables worktree expiry)
//! - `cleanup_interval_secs` (default 3600; how often the daemon runs this pass)

use crate::config::{Config, Paths};
use crate::kernel::Kernel;
use crate::worktree;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_SCRATCH_TTL_HOURS: u64 = 24;
pub const DEFAULT_WORKTREE_IDLE_HOURS: u64 = 168;
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 3600;

/// What one pass removed (and what it deliberately kept back).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub removed: Vec<String>,
    pub bytes: u64,
    pub skipped_live: usize,
    pub errors: Vec<String>,
}

/// The `[automation]` knobs, with defaults that keep scratch bounded without touching fresh data.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub scratch_ttl_hours: u64,
    pub worktree_idle_hours: u64,
    pub cleanup_interval_secs: u64,
}

impl Settings {
    pub fn from_config(cfg: &Config) -> Settings {
        let n = |key: &str, default: u64| cfg.automation.get(key).and_then(|v| v.as_integer()).filter(|n| *n >= 0).map(|n| n as u64).unwrap_or(default);
        Settings {
            scratch_ttl_hours: n("scratch_ttl_hours", DEFAULT_SCRATCH_TTL_HOURS),
            worktree_idle_hours: n("worktree_idle_hours", DEFAULT_WORKTREE_IDLE_HOURS),
            cleanup_interval_secs: n("cleanup_interval_secs", DEFAULT_CLEANUP_INTERVAL_SECS).max(1),
        }
    }
    pub fn enabled(&self) -> bool {
        self.scratch_ttl_hours > 0 || self.worktree_idle_hours > 0
    }
}

/// One daemon maintenance pass: expiry + worktrees, with each session's live state consulted.
pub fn maintenance(k: &Kernel) -> Report {
    let st = Settings::from_config(&k.cfg);
    if !st.enabled() {
        return Report::default();
    }
    let running: Vec<String> = k.running_ids();
    let mut workspaces: Vec<PathBuf> = Vec::new();
    for s in k.store.list() {
        let Ok(evs) = k.store.read(&s.id) else { continue };
        let ws = PathBuf::from(crate::projection::project(&evs).workspace);
        if !ws.as_os_str().is_empty() && !workspaces.contains(&ws) {
            workspaces.push(ws);
        }
    }
    expire_at(&k.paths, unix_now(), &st, &workspaces, &|id| running.iter().any(|r| r == id), false)
}

/// Testable core: `now` is unix seconds and `running` says whether a session is live.
#[allow(clippy::too_many_arguments)]
pub fn expire_at(paths: &Paths, now: i64, st: &Settings, workspaces: &[PathBuf], running: &dyn Fn(&str) -> bool, dry_run: bool) -> Report {
    let mut r = Report::default();
    if st.scratch_ttl_hours > 0 {
        let cutoff = now.saturating_sub((st.scratch_ttl_hours.saturating_mul(3600)) as i64);
        for root in [paths.data.join("tmp"), paths.data.join("scratch"), paths.data.join("art")] {
            sweep_root(&root, cutoff, dry_run, &mut r);
        }
        if let Ok(rd) = std::fs::read_dir(paths.sessions()) {
            for e in rd.flatten() {
                let id = e.file_name().to_string_lossy().to_string();
                if running(&id) {
                    r.skipped_live += 1;
                    continue;
                }
                let artifacts = e.path().join("artifacts");
                if artifacts.is_dir() {
                    sweep_entry(&artifacts, cutoff, dry_run, &mut r);
                }
            }
        }
    }
    if st.worktree_idle_hours > 0 && !dry_run {
        let mut repos: Vec<PathBuf> = Vec::new();
        for ws in workspaces {
            if let Some(root) = worktree::repo_root(ws) {
                if !repos.contains(&root) {
                    repos.push(root);
                }
            }
        }
        for repo in repos {
            match worktree::prune_idle(&repo, st.worktree_idle_hours, false) {
                Ok(v) => r.removed.extend(v),
                Err(e) => r.errors.push(format!("{}: {e}", repo.display())),
            }
        }
    }
    r
}

fn sweep_root(root: &Path, cutoff: i64, dry_run: bool, r: &mut Report) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        sweep_entry(&e.path(), cutoff, dry_run, r);
    }
}

fn sweep_entry(p: &Path, cutoff: i64, dry_run: bool, r: &mut Report) {
    let Ok(md) = std::fs::symlink_metadata(p) else { return };
    // A symlink is never followed and never removed: it may point outside the scratch root.
    if md.file_type().is_symlink() {
        return;
    }
    let newest = if md.is_dir() { worktree::newest_mtime(p) } else { md.modified().ok() };
    let Some(newest) = newest else { return };
    let secs = newest.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if secs > cutoff {
        return;
    }
    let bytes = if md.is_file() { md.len() } else { dir_size(p) };
    if dry_run {
        r.removed.push(p.display().to_string());
        r.bytes += bytes;
        return;
    }
    let res = if md.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
    match res {
        Ok(()) => {
            r.removed.push(p.display().to_string());
            r.bytes += bytes;
        }
        Err(e) => r.errors.push(format!("{}: {e}", p.display())),
    }
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    let mut seen = 0;
    while let Some(d) = stack.pop() {
        seen += 1;
        if seen > 100_000 {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(md) = std::fs::symlink_metadata(e.path()) else { continue };
            if md.file_type().is_symlink() {
                continue;
            }
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    total
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// For the daemon loop: has `interval` elapsed since `last`?
pub fn due(last: &mut std::time::Instant, interval: Duration) -> bool {
    if last.elapsed() >= interval {
        *last = std::time::Instant::now();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-scratch-{tag}-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn age(p: &Path, secs: u64) {
        let t = SystemTime::now() - Duration::from_secs(secs);
        let times = std::fs::FileTimes::new().set_accessed(t).set_modified(t);
        if p.is_dir() {
            for e in std::fs::read_dir(p).unwrap().flatten() {
                age(&e.path(), secs);
            }
        } else if let Ok(f) = std::fs::OpenOptions::new().write(true).open(p) {
            f.set_times(times).unwrap();
        }
    }

    #[test]
    fn expires_old_scratch_and_live_or_fresh_artifacts() {
        let root = tmp("expire");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(paths.data.join("tmp/old")).unwrap();
        std::fs::write(paths.data.join("tmp/old/x"), "old").unwrap();
        std::fs::create_dir_all(paths.data.join("tmp/fresh")).unwrap();
        std::fs::write(paths.data.join("tmp/fresh/x"), "new").unwrap();
        std::fs::create_dir_all(paths.data.join("scratch/old")).unwrap();
        std::fs::write(paths.data.join("scratch/old/y"), "old").unwrap();
        std::fs::create_dir_all(paths.sessions().join("s1/artifacts")).unwrap();
        std::fs::write(paths.sessions().join("s1/artifacts/old.txt"), "old").unwrap();
        std::fs::create_dir_all(paths.sessions().join("s2/artifacts")).unwrap();
        std::fs::write(paths.sessions().join("s2/artifacts/live.txt"), "old").unwrap();
        age(&paths.data.join("tmp/old"), 2 * 86_400);
        age(&paths.data.join("scratch/old"), 2 * 86_400);
        age(&paths.sessions().join("s1/artifacts"), 2 * 86_400);
        age(&paths.sessions().join("s2/artifacts"), 2 * 86_400);
        // A symlink under a scratch root is never followed or removed.
        let outside = tmp("outside");
        std::fs::write(outside.join("keep"), "keep").unwrap();
        // Windows may refuse to create one (no Developer Mode): then there is nothing to keep.
        let linked = crate::util::symlink_dir(&outside, &paths.data.join("tmp/link")).is_ok();
        assert!(linked || cfg!(windows), "symlink");

        let st = Settings { scratch_ttl_hours: 24, worktree_idle_hours: 0, cleanup_interval_secs: 3600 };
        let dry = expire_at(&paths, unix_now(), &st, &[], &|_| false, true);
        assert_eq!(dry.removed.len(), 4, "old tmp, scratch and both artifacts dirs: {:?}", dry.removed);
        assert!(paths.data.join("tmp/old").exists(), "dry run removes nothing");
        let r = expire_at(&paths, unix_now(), &st, &[], &|id| id == "s2", false);
        assert_eq!(r.removed.len(), 3, "{:?}", r);
        assert!(!paths.data.join("tmp/old").exists() && !paths.data.join("scratch/old").exists());
        assert!(!paths.sessions().join("s1/artifacts/old.txt").exists());
        assert!(paths.data.join("tmp/fresh/x").exists(), "fresh scratch kept");
        assert!(paths.sessions().join("s2/artifacts/live.txt").exists(), "live session artifacts kept");
        assert!(!linked || paths.data.join("tmp/link").is_symlink(), "symlink kept");
        assert!(outside.join("keep").exists(), "symlink target untouched");
    }

    #[test]
    fn settings_default_and_zero_disables() {
        let mut cfg = Config::default();
        assert_eq!(Settings::from_config(&cfg), Settings { scratch_ttl_hours: 24, worktree_idle_hours: 168, cleanup_interval_secs: 3600 });
        cfg.automation.insert("scratch_ttl_hours".into(), toml::Value::Integer(0));
        cfg.automation.insert("worktree_idle_hours".into(), toml::Value::Integer(48));
        let st = Settings::from_config(&cfg);
        assert_eq!((st.scratch_ttl_hours, st.worktree_idle_hours), (0, 48));
        assert!(st.enabled());
        cfg.automation.insert("worktree_idle_hours".into(), toml::Value::Integer(0));
        assert!(!Settings::from_config(&cfg).enabled());
    }
}
