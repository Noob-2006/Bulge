//! `seagent system event|heartbeat|presence|temp-clean` (OpenClaw `src/cli/system-cli.ts`) and
//! `seagent suggestions …` (Hermes `/suggestions`). Both work on the data dir directly, so they
//! need no running daemon: events land in the wake queue the daemon's heartbeat drains.
//!
//! `temp-clean` is the janitor for test leftovers: tests that predate `seagent_core::tmp::TempDir`
//! left tens of thousands of `seagent-*` scratch dirs in `/tmp`. It is opt-in (`--yes`), defaults to
//! a dry run, only knows the prefixes tests actually use, and only touches entries older than
//! `--older-than` hours so a concurrent `cargo test` is never robbed of its scratch space.

use seagent_kernel::config::{Config, Paths};
use seagent_kernel::{cronjob, heartbeat, wake};
use serde_json::{json, Value};
use std::path::Path;

pub const USAGE: &str = "usage: seagent system event --text <text> [--mode now|next-heartbeat] [--json]\n       seagent system heartbeat last|enable|disable [--json]\n       seagent system presence [--json]\n       seagent system temp-clean [--older-than <hours>] [--dry-run] [--yes] [--json]";

fn flag(argv: &[String], name: &str) -> bool {
    argv.iter().any(|a| a == name)
}

fn value(argv: &[String], name: &str) -> Option<String> {
    let eq = format!("{name}=");
    argv.iter().enumerate().find_map(|(i, a)| if a == name { argv.get(i + 1).cloned() } else { a.strip_prefix(&eq).map(String::from) })
}

fn emit(json_out: bool, v: &Value, text: &str) {
    if json_out {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    } else {
        println!("{text}");
    }
}

/// `seagent system …`; `argv` excludes the command word. Returns the exit code.
pub fn system(argv: &[String], paths: &Paths, cfg: &Config) -> Result<i32, String> {
    let json_out = flag(argv, "--json");
    let pos: Vec<&String> = {
        let mut out = Vec::new();
        let mut skip = false;
        for a in argv {
            if skip {
                skip = false;
                continue;
            }
            if matches!(a.as_str(), "--text" | "--mode" | "--session-key" | "-w" | "--workspace" | "--older-than") {
                skip = true;
                continue;
            }
            if !a.starts_with('-') {
                out.push(a);
            }
        }
        out
    };
    let data = &paths.data;
    match pos.first().map(|s| s.as_str()) {
        Some("event") => {
            let text = value(argv, "--text").unwrap_or_default();
            if text.trim().is_empty() {
                return Err("--text is required. Example: seagent system event --text \"deploy finished\".".into());
            }
            let mode = value(argv, "--mode").unwrap_or_else(|| "next-heartbeat".into());
            if mode != "now" && mode != "next-heartbeat" {
                return Err("--mode must be now or next-heartbeat".into());
            }
            let ev = wake::request(data, &text, &mode, "cli")?;
            emit(json_out, &json!({"ok": true, "mode": ev.mode, "queued": wake::pending(data).len()}), "ok");
            // Distinguish "not configured" from "configured but unreadable" (upstream reports the
            // latter as a config error instead of silently queueing forever).
            match heartbeat::HeartbeatConfig::from_table(&cfg.heartbeat) {
                Ok(Some(_)) => {}
                Ok(None) => eprintln!("note: [heartbeat] is not configured, so queued events wait until it is (see `seagent config`)."),
                Err(e) => eprintln!("warning: [heartbeat] is invalid ({e}), so queued events will not be delivered until it is fixed."),
            }
            Ok(0)
        }
        Some("heartbeat") => match pos.get(1).map(|s| s.as_str()) {
            Some("last") => {
                let last = heartbeat::last(data);
                let text = if last.is_null() {
                    "no heartbeat has run yet".to_string()
                } else {
                    format!(
                        "{} · {}{}{}",
                        seagent_kernel::util::fmt_time(last["at"].as_i64().unwrap_or(0), cfg.schedule.utc_offset_minutes),
                        last["status"].as_str().unwrap_or("?"),
                        last["text"].as_str().filter(|t| !t.is_empty()).map(|t| format!(" · {t}")).unwrap_or_default(),
                        last["delivery"].as_str().map(|d| format!(" · {d}")).unwrap_or_default()
                    )
                };
                emit(json_out, &last, &text);
                Ok(0)
            }
            Some(s @ ("enable" | "disable")) => {
                heartbeat::set_enabled(data, s == "enable");
                emit(json_out, &json!({"ok": true, "enabled": s == "enable"}), &format!("heartbeats {s}d"));
                Ok(0)
            }
            _ => Err(USAGE.into()),
        },
        Some("presence") => {
            let entries = heartbeat::presence(data);
            let text = if entries.is_empty() {
                "no presence entries (start `seagent daemon` to register one)".to_string()
            } else {
                entries.iter().map(|e| format!("{:<8} pid {:<7} {} {} · {} · {}s ago", e["mode"].as_str().unwrap_or("?"), e["pid"], e["host"].as_str().unwrap_or(""), e["version"].as_str().unwrap_or(""), if e["alive"].as_bool() == Some(true) { "alive" } else { "stale" }, e["age_secs"])).collect::<Vec<_>>().join("\n")
            };
            emit(json_out, &json!(entries), &text);
            Ok(0)
        }
        Some("temp-clean") => temp_clean(argv, json_out),
        _ => Err(USAGE.into()),
    }
}

/// Scratch-directory name prefixes created by tests (and by `seagent_core::tmp::TempDir` callers).
///
/// Deliberately a curated list, never a blanket `seagent-*`: `$TMPDIR` is shared with the user's own
/// files, so `temp-clean` may only touch names it can attribute to the test suite. Families are
/// listed short (`seagent-ch-` covers `seagent-ch-x-`/`seagent-ch-tg-`) so a new tag does not need a new
/// entry. Keep in sync with the header of `crates/seagent/tests/test_hygiene_allow.txt`.
pub const TEST_TEMP_PREFIXES: &[&str] = &[
    ".seagent-sync-",
    "seagent-agent-",
    "seagent-auto-",
    "seagent-ch-",
    "seagent-cfg-",
    "seagent-ckpt-",
    "seagent-core-tmp-",
    "seagent-k-",
    "seagent-kernel-",
    "seagent-media-",
    "seagent-mem-",
    "seagent-plugin-",
    "seagent-run-",
    "seagent-store-",
    "seagent-tmp-",
    "seagent-vault-",
    "seagent-wire-",
];

/// Minimum age `temp-clean` accepts: a `cargo test` run that is still going owns its scratch
/// dirs, and no test suite needs a scratch dir older than this.
pub const MIN_AGE_HOURS: u64 = 6;

/// What a `temp-clean` pass found (and, unless `dry_run`, removed).
#[derive(Debug, Default)]
pub struct CleanOutcome {
    pub root: std::path::PathBuf,
    pub older_than_hours: u64,
    pub dry_run: bool,
    /// Direct children under `root` that matched a known prefix and were old enough.
    pub matched: Vec<std::path::PathBuf>,
    /// How many of `matched` were actually deleted (always 0 for a dry run).
    pub removed: usize,
    /// Bytes accounted for by matched *files* (dirs are not walked, so this is a lower bound).
    pub bytes: u64,
    /// Entries with a known prefix that were skipped for being too new.
    pub skipped_fresh: usize,
    /// Symlinks with a known prefix: never followed, never removed.
    pub skipped_links: usize,
    /// One line per entry that could not be removed.
    pub errors: Vec<String>,
}

/// Remove (or, with `dry_run`, list) stale test scratch entries directly inside `root`.
///
/// `root` is a parameter instead of always `env::temp_dir()` so tests can point it at their own
/// scratch tree; the CLI passes the real temp dir.
pub fn temp_clean_in(root: &Path, older_than_hours: u64, dry_run: bool) -> Result<CleanOutcome, String> {
    if older_than_hours < MIN_AGE_HOURS {
        return Err(format!("--older-than must be at least {MIN_AGE_HOURS} hours (got {older_than_hours}): a shorter window would delete scratch dirs that a running `cargo test` still owns."));
    }
    let rd = std::fs::read_dir(root).map_err(|e| format!("cannot read {}: {e}", root.display()))?;
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(older_than_hours * 3600))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut out = CleanOutcome { root: root.to_path_buf(), older_than_hours, dry_run, ..Default::default() };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !TEST_TEMP_PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        // Only direct children: never descend, never delete `..` tricks.
        if path.parent() != Some(root) {
            continue;
        }
        let md = match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(_) => continue, // vanished between readdir and stat
        };
        if md.file_type().is_symlink() {
            out.skipped_links += 1;
            continue;
        }
        let stale = matches!(md.modified(), Ok(t) if t < cutoff);
        if !stale {
            out.skipped_fresh += 1;
            continue;
        }
        if md.is_file() {
            out.bytes += md.len();
        }
        out.matched.push(path.clone());
        if !dry_run {
            let res = if md.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            match res {
                Ok(()) => out.removed += 1,
                Err(e) => out.errors.push(format!("{}: {e}", path.display())),
            }
        }
    }
    out.matched.sort();
    Ok(out)
}

/// `seagent system temp-clean [--older-than <hours>] [--dry-run] [--yes] [--json]`.
///
/// Parsed separately from the scan so the safety rules (minimum age, dry run by default) can be
/// unit-tested without touching a real temp directory.
fn parse_temp_clean_args(argv: &[String]) -> Result<(u64, bool), String> {
    let hours = match value(argv, "--older-than") {
        Some(v) => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("--older-than expects hours as a whole number, got {v:?}"))?,
        None => 24,
    };
    // Deleting needs an explicit `--yes`; `--dry-run` (the default) wins if both are given.
    let dry_run = !flag(argv, "--yes") || flag(argv, "--dry-run");
    Ok((hours, dry_run))
}

fn temp_clean(argv: &[String], json_out: bool) -> Result<i32, String> {
    let (hours, dry_run) = parse_temp_clean_args(argv)?;
    let root = std::env::temp_dir();
    let outcome = temp_clean_in(&root, hours, dry_run)?;
    let verb = if outcome.dry_run { "would remove" } else { "removed" };
    let shown: Vec<String> = outcome
        .matched
        .iter()
        .take(40)
        .map(|p| format!("{verb} {}", p.display()))
        .collect();
    let mut text = shown.join("\n");
    if outcome.matched.len() > 40 {
        text.push_str(&format!("\n… {} more", outcome.matched.len() - 40));
    }
    let summary = format!(
        "{} {verb} {} entr{} under {} older than {}h ({} newer kept, {} symlinks skipped, {} bytes)",
        if outcome.dry_run { "dry run:" } else { "total:" },
        if outcome.dry_run { outcome.matched.len() } else { outcome.removed },
        if (if outcome.dry_run { outcome.matched.len() } else { outcome.removed }) == 1 { "y" } else { "ies" },
        outcome.root.display(),
        outcome.older_than_hours,
        outcome.skipped_fresh,
        outcome.skipped_links,
        outcome.bytes
    );
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&summary);
    if outcome.dry_run && !flag(argv, "--yes") {
        text.push_str("\n(re-run with --yes to delete)");
    } else if outcome.dry_run {
        text.push_str("\n(--dry-run was passed, so --yes was ignored)");
    }
    emit(
        json_out,
        &json!({
            "root": outcome.root.display().to_string(),
            "older_than_hours": outcome.older_than_hours,
            "dry_run": outcome.dry_run,
            "matched": outcome.matched.len(),
            "removed": outcome.removed,
            "bytes": outcome.bytes,
            "skipped_fresh": outcome.skipped_fresh,
            "skipped_links": outcome.skipped_links,
            "errors": outcome.errors,
        }),
        &text,
    );
    if outcome.errors.is_empty() {
        Ok(0)
    } else {
        Err(format!("{} entr{} could not be removed (see above)", outcome.errors.len(), if outcome.errors.len() == 1 { "y" } else { "ies" }))
    }
}

/// `seagent suggestions [accept N | dismiss N | catalog | clear]`.
pub fn suggestions(argv: &[String], paths: &Paths, cfg: &Config, ws: &Path) -> Result<i32, String> {
    let args: Vec<&str> = argv.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
    let st = cronjob::Settings::from_config(cfg);
    println!("{}", cronjob::suggestions::command(&paths.data, &st, &args.join(" "), ws, None, "cli"));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (seagent_core::tmp::TempDir, Paths) {
        // Guard, not a bare dir: the test used to leave `seagent-syscli-*` behind on every run.
        let td = seagent_core::tmp::TempDir::new("seagent-syscli");
        let root = td.path().to_path_buf();
        (td, Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() })
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn event_heartbeat_and_presence_commands() {
        let (_td, p) = paths();
        let cfg = Config::default();
        assert!(system(&s(&["event"]), &p, &cfg).unwrap_err().contains("--text is required"));
        assert!(system(&s(&["event", "--text", "x", "--mode", "later"]), &p, &cfg).unwrap_err().contains("--mode"));
        assert_eq!(system(&s(&["event", "--text", "deploy finished", "--mode", "now", "--json"]), &p, &cfg).unwrap(), 0);
        let q = wake::pending(&p.data);
        assert_eq!((q.len(), q[0].mode.as_str(), q[0].source.as_str()), (1, "now", "cli"));
        assert_eq!(system(&s(&["heartbeat", "disable"]), &p, &cfg).unwrap(), 0);
        assert_eq!(heartbeat::enabled_override(&p.data), Some(false));
        assert_eq!(system(&s(&["heartbeat", "enable"]), &p, &cfg).unwrap(), 0);
        assert_eq!(heartbeat::enabled_override(&p.data), Some(true));
        assert_eq!(system(&s(&["heartbeat", "last", "--json"]), &p, &cfg).unwrap(), 0);
        heartbeat::touch_presence(&p.data, "daemon");
        let e = heartbeat::presence(&p.data);
        assert_eq!((e.len(), e[0]["alive"].as_bool()), (1, Some(true)));
        assert_eq!(system(&s(&["presence"]), &p, &cfg).unwrap(), 0);
        assert!(system(&s(&["bogus"]), &p, &cfg).is_err());
        assert_eq!(suggestions(&s(&["catalog"]), &p, &cfg, &p.data).unwrap(), 0);
        assert_eq!(cronjob::suggestions::pending(&p.data).len(), 4);
    }

    // ---- `seagent system temp-clean` -----------------------------------------------------------------

    /// Backdate an entry so it looks like an old test leftover. `File::set_times` works on
    /// directories too on Unix (the fd is opened read-only, `futimens` needs ownership only).
    fn backdate(path: &Path, secs_ago: u64) {
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(secs_ago);
        let f = std::fs::File::open(path).expect("open for set_times");
        f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t)).expect("set_times");
    }

    fn touch_dir(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("payload"), b"x").unwrap();
    }

    fn names(o: &CleanOutcome) -> Vec<String> {
        o.matched.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn temp_clean_removes_stale_keeps_fresh_and_unknown() {
        let root = seagent_core::tmp::TempDir::new("seagent-tmpclean");
        let stale = root.path().join("seagent-store-stale");
        let fresh = root.path().join("seagent-ch-tg-fresh");
        let unknown = root.path().join("my-own-scratch");
        touch_dir(&stale);
        touch_dir(&fresh);
        touch_dir(&unknown);
        backdate(&stale, 3 * 24 * 3600);
        backdate(&unknown, 30 * 24 * 3600);
        let o = temp_clean_in(root.path(), 24, false).unwrap();
        assert_eq!(names(&o), vec!["seagent-store-stale".to_string()]);
        assert_eq!((o.removed, o.skipped_fresh, o.errors.len()), (1, 1, 0));
        assert!(!stale.exists(), "the stale test dir must be gone");
        assert!(fresh.is_dir(), "a newer-than-cutoff dir must be kept");
        assert!(unknown.is_dir(), "unknown prefixes are never touched");
    }

    #[test]
    fn temp_clean_dry_run_deletes_nothing() {
        let root = seagent_core::tmp::TempDir::new("seagent-tmpclean");
        let stale = root.path().join("seagent-k-1234");
        touch_dir(&stale);
        backdate(&stale, 48 * 3600);
        let o = temp_clean_in(root.path(), 24, true).unwrap();
        assert!(o.dry_run);
        assert_eq!((names(&o).len(), o.removed), (1, 0));
        assert!(stale.join("payload").is_file(), "a dry run must leave the tree intact");
    }

    #[cfg(unix)]
    #[test]
    fn temp_clean_handles_files_and_never_follows_symlinks() {
        let root = seagent_core::tmp::TempDir::new("seagent-tmpclean");
        let stamp = root.path().join(".seagent-sync-abc.stamp");
        std::fs::write(&stamp, b"").unwrap();
        backdate(&stamp, 24 * 3600 + 60);
        let outside = root.path().join("plain-target");
        touch_dir(&outside);
        let link = root.path().join("seagent-vault-link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        // Backdating through a symlink would touch the target; symlinks are skipped before the
        // age check, so leave it fresh.
        let o = temp_clean_in(root.path(), 24, false).unwrap();
        assert_eq!(names(&o), vec![".seagent-sync-abc.stamp".to_string()]);
        assert_eq!((o.removed, o.skipped_links), (1, 1));
        assert!(!stamp.exists());
        assert!(link.exists() && outside.is_dir(), "symlinks and their targets survive");
    }

    #[test]
    fn temp_clean_refuses_a_short_window() {
        let root = seagent_core::tmp::TempDir::new("seagent-tmpclean");
        let err = temp_clean_in(root.path(), 1, true).unwrap_err();
        assert!(err.contains("at least 6 hours"), "unexpected error: {err}");
    }

    #[test]
    fn temp_clean_args_default_to_a_safe_dry_run() {
        assert_eq!(parse_temp_clean_args(&s(&[])).unwrap(), (24, true));
        assert_eq!(parse_temp_clean_args(&s(&["--older-than", "12"])).unwrap(), (12, true));
        assert_eq!(parse_temp_clean_args(&s(&["--older-than=72"])).unwrap(), (72, true));
        assert_eq!(parse_temp_clean_args(&s(&["--yes"])).unwrap(), (24, false));
        assert_eq!(parse_temp_clean_args(&s(&["--yes", "--dry-run"])).unwrap(), (24, true));
        assert!(parse_temp_clean_args(&s(&["--older-than", "soon"])).unwrap_err().contains("whole number"));
        // The argv path rejects the same short window before it ever scans a temp dir.
        let p = Config::default();
        let (td, paths_) = paths();
        let err = system(&s(&["temp-clean", "--older-than", "2", "--json"]), &paths_, &p).unwrap_err();
        assert!(err.contains("at least 6 hours"), "unexpected error: {err}");
        drop(td);
    }
}
