//! `seagent system temp-clean` through the real binary, with `TMPDIR` pointed at a scratch tree this
//! test owns (never the machine's real `/tmp`).
//!
//! The command is the janitor for test leftovers: dry run by default, `--yes` to delete, a
//! minimum age of 6 hours, and only names that belong to the test suite. Each of those rules is
//! checked here end to end, because the safety of the tool is the point of the tool.

use seagent_core::tmp::TempDir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Backdate an entry (works on directories: the fd is opened read-only, `futimens` needs
/// ownership, not write access).
fn backdate(path: &Path, secs_ago: u64) {
    let t = SystemTime::now() - Duration::from_secs(secs_ago);
    let f = {
        #[cfg(not(windows))]
        let f = std::fs::File::open(path);
        // Windows: FILE_WRITE_ATTRIBUTES, and FILE_FLAG_BACKUP_SEMANTICS so directories open too.
        #[cfg(windows)]
        let f = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().access_mode(0x100).custom_flags(0x0200_0000).open(path)
        };
        f
    }
    .expect("open for set_times");
    f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t)).expect("set_times");
}

fn scratch_dir(root: &Path, name: &str) -> PathBuf {
    let d = root.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("payload"), b"x").unwrap();
    d
}

/// Run the real binary with `TMPDIR`/`SEAGENT_HOME` inside `root`, so nothing outside the scratch
/// tree can be created, read or removed.
fn seagent(root: &Path, args: &[&str]) -> (i32, String, String) {
    let home = root.join("seagentcfg-home");
    std::fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_seagent"))
        .args(args)
        .env("TMPDIR", root)
        .env("SEAGENT_HOME", &home)
        // Offline by default: no models.dev price download from a fresh SEAGENT_HOME.
        .env("SEAGENT_OFFLINE", "1")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("XAI_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .output()
        .expect("run seagent");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn temp_clean_is_a_dry_run_by_default_and_only_deletes_with_yes() {
    let scratch = TempDir::new("seagent-tmpclean-cli");
    let root = scratch.path();
    let stale = scratch_dir(root, "seagent-store-stale");
    let fresh = scratch_dir(root, "seagent-ch-tg-fresh");
    let foreign = scratch_dir(root, "user-notes");
    backdate(&stale, 3 * 24 * 3600);
    backdate(&foreign, 30 * 24 * 3600); // old, but not ours: never touched

    // 1. No flags: report only.
    let (code, out, err) = seagent(root, &["system", "temp-clean"]);
    assert_eq!(code, 0, "dry run should succeed: {out}{err}");
    assert!(out.contains("would remove") && out.contains("seagent-store-stale"), "stdout: {out}");
    assert!(out.contains("dry run:"), "stdout: {out}");
    assert!(out.contains("--yes to delete"), "stdout should point at --yes: {out}");
    assert!(stale.is_dir(), "a dry run must not delete anything");

    // 2. Too short a window is refused before anything is scanned.
    let (code, out, err) = seagent(root, &["system", "temp-clean", "--older-than", "1", "--yes"]);
    assert_ne!(code, 0, "a 1h window must be rejected: {out}{err}");
    assert!(format!("{out}{err}").contains("at least 6 hours"), "stdout: {out} stderr: {err}");
    assert!(stale.is_dir(), "a rejected window must not delete anything");

    // 3. Real deletion with --yes, stated window included.
    let (code, out, err) = seagent(root, &["system", "temp-clean", "--older-than", "24", "--yes"]);
    assert_eq!(code, 0, "clean should succeed: {out}{err}");
    assert!(out.contains("removed") && out.contains("seagent-store-stale"), "stdout: {out}");
    assert!(!stale.exists(), "the stale test dir must be gone");
    assert!(fresh.is_dir(), "a dir newer than the cutoff must be kept");
    assert!(foreign.is_dir(), "unknown prefixes are never touched");

    // 4. --json carries the same numbers for scripts.
    let (code, out, err) = seagent(root, &["system", "temp-clean", "--json", "--dry-run"]);
    assert_eq!(code, 0, "json dry run: {out}{err}");
    assert!(out.contains("\"dry_run\": true"), "stdout: {out}");
    assert!(out.contains("\"matched\": 0"), "the only stale entry was just removed: {out}");
}
