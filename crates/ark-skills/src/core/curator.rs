//! Curator: background skill-library maintenance (Hermes `agent/curator.py` +
//! `agent/curator_backup.py`, MIT).
//!
//! Inactivity-triggered, no cron daemon: after a turn, when the agent has been idle for
//! `min_idle_hours` and the last run is older than `interval_hours`, a pass (1) moves every
//! curator-managed skill between active / stale / archived from its latest real activity
//! (pinned and cron-referenced skills are never touched; never-used skills younger than
//! `stale_after_days` are left alone), and (2) optionally — `consolidate`, off by default —
//! forks a sub-agent with the umbrella-building review prompt over the candidate list,
//! after snapshotting the skills tree. The first observation only seeds `last_run_at` so a
//! fresh install never mutates the library on its first tick. Only archiving, never delete;
//! every run writes `logs/curator/<ts>/{run.json,REPORT.md}`.

use super::settings::{Settings, Store};
use super::usage;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const DAY: i64 = 86_400;

fn now() -> i64 {
    ark_kernel::util::unix_now()
}

pub fn load_state(st: &Store) -> Value {
    fs::read_to_string(st.curator_state()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
}

pub fn save_state(st: &Store, v: &Value) {
    let _ = fs::create_dir_all(&st.skills);
    let _ = ark_kernel::util::atomic_write(&st.curator_state(), serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}

pub fn set_paused(st: &Store, paused: bool) {
    let mut s = load_state(st);
    s["paused"] = json!(paused);
    save_state(st, &s);
}

/// Gates: enabled, not paused, idle long enough, `last_run_at` present and older than the
/// interval. The first observation seeds `last_run_at = now` and defers one interval.
pub fn should_run_now(s: &Settings, st: &Store, last_activity: Option<i64>) -> bool {
    if !s.curator.enabled {
        return false;
    }
    let mut state = load_state(st);
    if state["paused"].as_bool() == Some(true) {
        return false;
    }
    let Some(last) = state["last_run_at"].as_i64() else {
        state["last_run_at"] = json!(now());
        save_state(st, &state);
        return false;
    };
    if let Some(a) = last_activity {
        if now() - a < (s.curator.min_idle_hours * 3600.0) as i64 {
            return false;
        }
    }
    now() - last >= s.curator.interval_hours as i64 * 3600
}

/// Skill names cron jobs depend on (the job's `skills` field, or a prompt that loads the skill by
/// name): treated as pinned, since usage only bumps when a job fires and a paused/rare job would
/// otherwise age its skill out (Hermes `cron.jobs.referenced_skill_names`).
pub fn cron_referenced(st: &Store) -> Vec<String> {
    let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&st.data)).unwrap_or_default();
    let names: Vec<String> = usage::local_skills(st).into_iter().map(|s| s.name).collect();
    names.into_iter().filter(|n| jobs.iter().any(|j| j.ext.skills.iter().any(|s| s == n) || j.prompt.contains(&format!("`{n}` skill")) || j.prompt.starts_with(&format!("/{n}")))).collect()
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Counts {
    pub checked: usize,
    pub seeded: usize,
    pub marked_stale: usize,
    pub archived: usize,
    pub reactivated: usize,
}

/// Deterministic half of a pass. `dry_run` reports without changing anything.
pub fn apply_transitions(s: &Settings, st: &Store, at: i64, dry_run: bool) -> (Counts, Vec<String>) {
    let stale_cut = at - s.curator.stale_after_days as i64 * DAY;
    let archive_cut = at - s.curator.archive_after_days as i64 * DAY;
    let protected = cron_referenced(st);
    let mut c = Counts::default();
    let mut log = Vec::new();
    let usage_map = usage::load(st);
    for sk in usage::local_skills(st) {
        let name = sk.name.clone();
        if !usage::curator_managed(s, st, &name) {
            continue;
        }
        c.checked += 1;
        let rec = usage::get(st, &name);
        if rec["pinned"].as_bool() == Some(true) || protected.contains(&name) {
            continue;
        }
        if !usage_map.contains_key(&name) {
            if !dry_run {
                usage::mutate(st, &name, |r| {
                    r.insert("first_seen_at".into(), json!(at));
                    r.insert("created_at".into(), json!(at));
                });
            }
            c.seeded += 1;
            continue;
        }
        let anchor = usage::latest_activity(&rec).or(rec["first_seen_at"].as_i64()).or(rec["created_at"].as_i64()).unwrap_or(at);
        let state = rec["state"].as_str().unwrap_or(usage::ACTIVE).to_string();
        if rec["use_count"].as_i64().unwrap_or(0) == 0 && usage::latest_activity(&rec).is_none() && anchor > stale_cut {
            continue;
        }
        if anchor <= archive_cut && state != usage::ARCHIVED {
            log.push(format!("archive {name} (idle {}d)", (at - anchor) / DAY));
            if dry_run || usage::archive(s, st, &name, "curator").is_ok() {
                c.archived += 1;
            }
        } else if anchor <= stale_cut && state == usage::ACTIVE {
            log.push(format!("stale {name} (idle {}d)", (at - anchor) / DAY));
            if !dry_run {
                usage::set_state(st, &name, usage::STALE);
            }
            c.marked_stale += 1;
        } else if anchor > stale_cut && state == usage::STALE {
            log.push(format!("reactivate {name}"));
            if !dry_run {
                usage::set_state(st, &name, usage::ACTIVE);
            }
            c.reactivated += 1;
        }
    }
    (c, log)
}

pub const REVIEW_PROMPT: &str = "You are ark's background skill CURATOR running an umbrella-building consolidation pass over the agent's own skill library.\n\
The goal is a library of CLASS-LEVEL skills: one broad skill with labeled sections beats many narrow, one-session skills, because the agent routes on short descriptions. Consolidating means distilling: absorbed content becomes imperative rules with one clause of why; repeated lessons become one rule; incident stories, issue numbers and dates are dropped. Push topical depth into references/, keep SKILL.md to the always-on rules.\n\
Hard rules:\n\
1. Touch only the candidates listed below (local, curator-managed). Never bundled, hub-installed or external skills.\n\
2. Never delete a skill. Archiving (`skill action=archive`) is the most destructive action allowed.\n\
3. Skip skills marked pinned=yes or cron=yes.\n\
4. Use the `skill` tool (view / update / create / archive) for every change.\n\
When done, end your reply with a fenced ```yaml block:\nconsolidations:\n  - {from: old-name, into: umbrella-name, why: ...}\nprunings:\n  - {name: skill, why: ...}\n";

pub const DRY_RUN_BANNER: &str = "DRY-RUN — REPORT ONLY. DO NOT MUTATE THE SKILL LIBRARY. Describe what you would change.";

/// The candidate list the review fork sees.
pub fn candidates(s: &Settings, st: &Store) -> String {
    let protected = cron_referenced(st);
    let mut lines = Vec::new();
    for sk in usage::local_skills(st) {
        if !usage::curator_managed(s, st, &sk.name) || usage::provenance(s, st, &sk.name) != "agent" {
            continue;
        }
        let r = usage::get(st, &sk.name);
        lines.push(format!("- {} — {} (uses={}, views={}, state={}, pinned={}, cron={})", sk.name, sk.description.chars().take(120).collect::<String>(), r["use_count"], r["view_count"], r["state"].as_str().unwrap_or("active"), if r["pinned"].as_bool() == Some(true) { "yes" } else { "no" }, if protected.contains(&sk.name) { "yes" } else { "no" }));
    }
    lines.join("\n")
}

// ───────────── backups ─────────────

/// Never rolled into a snapshot (Hermes `_EXCLUDE_TOP_LEVEL`): the backup dir itself, hub state,
/// locks, VCS metadata, the restore target `.archive/` and the append-only ledger — rolling any of
/// those back loses skills/entries or grows without bound.
const EXCLUDE: &[&str] = &[".curator_backups", ".hub", ".locks", ".git", ".archive", ".curator_ledger.jsonl"];

fn skill_files(root: &std::path::Path) -> usize {
    let mut n = 0;
    for e in fs::read_dir(root).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            n += skill_files(&p);
        } else if p.file_name().is_some_and(|f| f == "SKILL.md") {
            n += 1;
        }
    }
    n
}

/// Snapshot `<data>/skills` (minus `.hub`/`.archive`/backups/ledger) to `.curator_backups/<ts>/`,
/// with the live cron job store copied alongside (the consolidation pass may rewrite skill
/// references, so rollback restores those fields); keeps `keep` snapshots.
pub fn backup(st: &Store, reason: &str, keep: usize) -> Result<PathBuf, String> {
    let id = format!("{}", now());
    let mut dest = st.backups().join(&id);
    let mut n = 1;
    while dest.exists() {
        dest = st.backups().join(format!("{id}-{n}"));
        n += 1;
    }
    fs::create_dir_all(dest.join("skills")).map_err(|e| e.to_string())?;
    for e in fs::read_dir(&st.skills).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if EXCLUDE.contains(&name.as_str()) {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            usage::copy_tree(&p, &dest.join("skills").join(&name))?;
        } else if p.is_file() {
            fs::copy(&p, dest.join("skills").join(&name)).map_err(|e| e.to_string())?;
        }
    }
    let jobs = ark_kernel::automation::jobs_path(&st.data);
    let cron = match fs::read_to_string(&jobs) {
        Ok(src) => {
            fs::write(dest.join("cron-jobs.json"), &src).map_err(|e| e.to_string())?;
            json!({"backed_up": true, "jobs_count": ark_kernel::automation::read_list::<ark_kernel::automation::Job>(&jobs).map(|v| v.len()).unwrap_or(0)})
        }
        Err(_) => json!({"backed_up": false, "jobs_count": 0, "reason": "no cron job store present"}),
    };
    let manifest = json!({"id": dest.file_name().unwrap_or_default().to_string_lossy(), "reason": reason, "created_at": now(), "skill_files": skill_files(&dest.join("skills")), "cron_jobs": cron});
    fs::write(dest.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap_or_default()).map_err(|e| e.to_string())?;
    let mut all = list_backups(st);
    while all.len() > keep {
        let old = all.remove(0);
        let _ = fs::remove_dir_all(st.backups().join(old));
    }
    Ok(dest)
}

pub fn list_backups(st: &Store) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(st.backups()).into_iter().flatten().flatten().filter(|e| e.path().join("manifest.json").is_file()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    v.sort();
    v
}

/// Restore the whole tree from a snapshot (newest by default), after a safety snapshot. `.archive/`,
/// the ledger, hub state and locks are left alone; cron jobs that still exist get their `skills`
/// fields back from the snapshot (all other job fields stay live).
pub fn rollback_tree(st: &Store, id: Option<&str>) -> Result<String, String> {
    let all = list_backups(st);
    let id = match id {
        Some(i) => all.iter().find(|b| *b == i).cloned().ok_or_else(|| format!("no snapshot `{i}`"))?,
        None => all.last().cloned().ok_or("no curator snapshots")?,
    };
    let snap = st.backups().join(&id);
    let src = snap.join("skills");
    let safety = backup(st, &format!("pre-rollback to {id}"), usize::MAX)?;
    for e in fs::read_dir(&st.skills).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if EXCLUDE.contains(&name.as_str()) {
            continue;
        }
        let p = e.path();
        let _ = if p.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
    }
    usage::copy_tree(&src, &st.skills)?;
    let jobs = restore_cron_skills(st, &snap);
    Ok(format!("restored skills from snapshot {id} (current state saved as {}{})", safety.file_name().unwrap().to_string_lossy(), if jobs > 0 { format!("; {jobs} cron job(s) skill list(s) restored") } else { String::new() }))
}

/// Restore only the `skills` field of cron jobs that still exist (Hermes `curator_backup.rollback`).
fn restore_cron_skills(st: &Store, snap: &std::path::Path) -> usize {
    let Ok(text) = fs::read_to_string(snap.join("cron-jobs.json")) else { return 0 };
    let Ok(old) = serde_json::from_str::<Vec<ark_kernel::automation::Job>>(&text) else { return 0 };
    let by_id: std::collections::HashMap<String, Vec<String>> = old.into_iter().map(|j| (j.id, j.ext.skills)).collect();
    let mut n = 0;
    let _ = ark_kernel::automation::with_list::<ark_kernel::automation::Job, _>(&ark_kernel::automation::jobs_path(&st.data), |v| {
        for j in v.iter_mut() {
            if let Some(skills) = by_id.get(&j.id) {
                if *skills != j.ext.skills {
                    j.ext.skills = skills.clone();
                    n += 1;
                }
            }
        }
    });
    n
}

// ───────────── runs ─────────────

/// What a run did (`run.json`).
#[derive(Debug, Clone)]
pub struct RunResult {
    pub counts: Counts,
    pub log: Vec<String>,
    pub summary: String,
    pub report_dir: Option<PathBuf>,
}

/// One pass. `fork` runs the LLM consolidation (a sub-agent with the given prompt) and
/// returns its final reply; it is only called when consolidation is on and there are candidates.
pub fn run(s: &Settings, st: &Store, dry_run: bool, consolidate: Option<bool>, fork: Option<super::Fork<'_>>) -> RunResult {
    let at = now();
    let before: Vec<String> = usage::local_skills(st).into_iter().map(|s| s.name).collect();
    let (counts, mut log) = apply_transitions(s, st, at, dry_run);
    let auto = format!("checked {}, stale {}, archived {}, reactivated {}, seeded {}", counts.checked, counts.marked_stale, counts.archived, counts.reactivated, counts.seeded);
    let mut summary = format!("{}auto: {auto}", if dry_run { "[dry-run] " } else { "" });
    let mut llm = String::new();
    if consolidate.unwrap_or(s.curator.consolidate) {
        let cands = candidates(s, st);
        match (fork, cands.is_empty()) {
            (_, true) => summary.push_str("; llm: no candidates"),
            (None, false) => summary.push_str("; llm: skipped (consolidation needs a running agent: use /curator run --consolidate)"),
            (Some(f), false) => {
                if !dry_run && s.curator.backup {
                    if let Err(e) = backup(st, "pre-consolidation", s.curator.backup_keep) {
                        log.push(format!("backup failed: {e}"));
                    }
                }
                let mut prompt = format!("{REVIEW_PROMPT}\nCandidates:\n{cands}");
                if dry_run {
                    prompt = format!("{DRY_RUN_BANNER}\n\n{prompt}");
                }
                match f(&prompt) {
                    Ok(r) => {
                        summary.push_str(&format!("; llm: {}", r.lines().find(|l| !l.trim().is_empty()).unwrap_or("done").chars().take(240).collect::<String>()));
                        llm = r;
                    }
                    Err(e) => summary.push_str(&format!("; llm: error ({e})")),
                }
            }
        }
    }
    let after: Vec<String> = usage::local_skills(st).into_iter().map(|s| s.name).collect();
    let removed: Vec<&String> = before.iter().filter(|n| !after.contains(n)).collect();
    if !removed.is_empty() {
        summary.push_str(&format!("\narchived: {} (restore with `ark curator restore <name>`)", removed.iter().take(10).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    let report_dir = write_report(st, at, &counts, &log, &summary, &llm, dry_run, &removed, (before.len(), after.len()));
    if !dry_run {
        let mut state = load_state(st);
        state["last_run_at"] = json!(at);
        state["last_summary"] = json!(summary);
        state["last_report_path"] = json!(report_dir.as_ref().map(|d| d.display().to_string()));
        state["runs"] = json!(state["runs"].as_i64().unwrap_or(0) + 1);
        save_state(st, &state);
    }
    RunResult { counts, log, summary, report_dir }
}

// Every field is a distinct part of the rendered report (counts, log, summary, llm note, archive
// list, before/after sizes); bundling them would only move the same data into a throwaway struct.
#[allow(clippy::too_many_arguments)]
fn write_report(st: &Store, at: i64, c: &Counts, log: &[String], summary: &str, llm: &str, dry_run: bool, archived: &[&String], skills: (usize, usize)) -> Option<PathBuf> {
    let base = st.curator_reports().join(ark_kernel::util::fmt_time(at, 0).replace([' ', ':'], "-"));
    let mut dir = base.clone();
    let mut n = 1;
    while dir.exists() {
        dir = PathBuf::from(format!("{}-{n}", base.display()));
        n += 1;
    }
    fs::create_dir_all(&dir).ok()?;
    let run = json!({"at": at, "dry_run": dry_run, "checked": c.checked, "seeded": c.seeded, "marked_stale": c.marked_stale, "archived": c.archived, "reactivated": c.reactivated, "counts": {"before": skills.0, "after": skills.1, "delta": skills.1 as i64 - skills.0 as i64}, "archived_names": archived, "actions": log, "summary": summary, "llm": llm});
    fs::write(dir.join("run.json"), serde_json::to_string_pretty(&run).ok()?).ok()?;
    let mut md = format!("# Curator run{}\n\n{summary}\n\n## Actions\n", if dry_run { " (dry run)" } else { "" });
    for l in log {
        md.push_str(&format!("- {l}\n"));
    }
    if !llm.is_empty() {
        md.push_str(&format!("\n## Consolidation\n\n{llm}\n"));
    }
    fs::write(dir.join("REPORT.md"), md).ok()?;
    Some(dir)
}

/// Archive curator-managed skills idle ≥ `days` (`ark curator prune`).
pub fn prune(s: &Settings, st: &Store, days: u64, dry_run: bool) -> Vec<String> {
    let cut = now() - days.max(1) as i64 * DAY;
    let mut out = Vec::new();
    for sk in usage::local_skills(st) {
        if !usage::curator_managed(s, st, &sk.name) {
            continue;
        }
        let r = usage::get(st, &sk.name);
        if r["pinned"].as_bool() == Some(true) {
            continue;
        }
        let anchor = usage::latest_activity(&r).or(r["created_at"].as_i64()).unwrap_or(now());
        if anchor <= cut && (dry_run || usage::archive(s, st, &sk.name, "user").is_ok()) {
            out.push(sk.name);
        }
    }
    out
}

/// Delete archived skills older than `days` (explicit only; ledgered).
pub fn purge(s: &Settings, st: &Store, days: u64, dry_run: bool) -> Result<Vec<String>, String> {
    if days == 0 {
        return Err("archive_ttl_days is 0 (never purge); pass --days N".into());
    }
    let cut = now() - days as i64 * DAY;
    let mut out = Vec::new();
    for name in usage::archived_names(st) {
        let dir = st.archive().join(&name);
        let rec = usage::get(st, &name);
        let at = rec["archived_at"].as_i64().unwrap_or_else(|| fs::metadata(&dir).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(now()));
        if at > cut {
            continue;
        }
        if !dry_run {
            let before = super::ledger::capture_before(s, st, &dir);
            fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
            super::ledger::record(s, st, "user", "purge", &name, before, None, "");
            usage::forget(st, &name);
        }
        out.push(name);
    }
    Ok(out)
}

pub fn status(s: &Settings, st: &Store) -> String {
    let state = load_state(st);
    let rows = usage::report(s, st, &usage::local_skills(st));
    let managed = rows.iter().filter(|r| usage::curator_managed(s, st, r["name"].as_str().unwrap_or(""))).count();
    let stale = rows.iter().filter(|r| r["state"] == usage::STALE).count();
    let fmt = |v: &Value| v.as_i64().map(|t| ark_kernel::util::fmt_time(t, 0)).unwrap_or_else(|| "never".into());
    format!(
        "curator: {}{}\ninterval: {}h · idle ≥ {}h · stale after {}d · archive after {}d · consolidate {}\nlast run: {}\nlast summary: {}\nlast report: {}\nskills: {} local, {} curator-managed, {} stale, {} archived, {} pinned",
        if s.curator.enabled { "enabled" } else { "disabled" },
        if state["paused"].as_bool() == Some(true) { " (paused)" } else { "" },
        s.curator.interval_hours,
        s.curator.min_idle_hours,        s.curator.stale_after_days,
        s.curator.archive_after_days,
        if s.curator.consolidate { "on" } else { "off" },
        fmt(&state["last_run_at"]),
        state["last_summary"].as_str().unwrap_or("-"),
        state["last_report_path"].as_str().map(|p| format!("{p}{}", if std::path::Path::new(p).exists() { "" } else { " (missing)" })).unwrap_or_else(|| "-".into()),
        rows.len(),
        managed,
        stale,
        usage::archived_names(st).len(),
        rows.iter().filter(|r| r["pinned"].as_bool() == Some(true)).count()
    )
}

/// Lifecycle hook: after each turn, run a deterministic pass when the gates allow (in a
/// background thread so the turn is never delayed).
pub struct CuratorTick {
    pub settings: Settings,
    pub store: Store,
}

impl ark_kernel::lifecycle::Lifecycle for CuratorTick {
    fn name(&self) -> String {
        "curator".into()
    }
    fn turn_end(&self, _session: &str, _workspace: &str, _user: &str, _assistant: &str, _ok: bool) {
        // The turn that just ended is the latest activity; idle is measured from the previous one.
        let prev = load_state(&self.store)["last_turn_at"].as_i64();
        let mut state = load_state(&self.store);
        state["last_turn_at"] = json!(now());
        save_state(&self.store, &state);
        if should_run_now(&self.settings, &self.store, prev) {
            let (s, st) = (self.settings.clone(), self.store.clone());
            std::thread::spawn(move || {
                run(&s, &st, false, Some(false), None);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(st: &Store, n: &str) {
        fs::create_dir_all(st.skills.join(n)).unwrap();
        fs::write(st.skills.join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: about {n}\n---\nbody")).unwrap();
        usage::record_created(st, n, true);
    }

    /// Snapshots skip `.archive/`, the ledger and hub state, carry the cron job store, and a
    /// whole-tree rollback restores only cron `skills` fields while leaving archives alone.
    #[test]
    fn snapshot_excludes_archive_and_restores_cron_skills() {
        let d = std::env::temp_dir().join(format!("ark-curator3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        for n in ["kept", "gone"] {
            skill(&st, n);
        }
        usage::archive(&s, &st, "gone", "user").unwrap();
        assert!(st.archive().join("gone/SKILL.md").is_file());
        assert!(st.ledger().is_file(), "the archive wrote a ledger entry");
        let ws = d.join("ws");
        fs::create_dir_all(&ws).unwrap();
        let job = ark_kernel::automation::add_job(&st.data, "0 8 * * *", "digest", &ws, None, false, 0).unwrap();
        let set_skills = |v: Vec<String>| {
            ark_kernel::automation::with_list::<ark_kernel::automation::Job, _>(&ark_kernel::automation::jobs_path(&st.data), |l| l.iter_mut().find(|j| j.id == job.id).map(|j| j.ext.skills = v.clone())).unwrap()
        };
        set_skills(vec!["gone".into()]);
        let snap = backup(&st, "pre-consolidation", 2).unwrap();
        assert!(!snap.join("skills/.archive").exists() && !snap.join("skills/.curator_ledger.jsonl").exists(), "excluded: archive + ledger");
        assert!(snap.join("skills/kept/SKILL.md").is_file() && snap.join("cron-jobs.json").is_file());
        let manifest: Value = serde_json::from_str(&fs::read_to_string(snap.join("manifest.json")).unwrap()).unwrap();
        assert_eq!((manifest["skill_files"].as_u64(), manifest["cron_jobs"]["backed_up"].as_bool()), (Some(1), Some(true)), "{manifest}");
        // The consolidation pass renamed the skill → the job lost its reference; rollback restores it.
        set_skills(vec![]);
        fs::remove_dir_all(st.skills.join("kept")).unwrap();
        let msg = rollback_tree(&st, None).unwrap();
        assert!(msg.contains("cron job(s) skill list(s) restored"), "{msg}");
        let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&st.data)).unwrap();
        assert_eq!(jobs.iter().find(|j| j.id == job.id).unwrap().ext.skills, ["gone"]);
        assert!(st.skills.join("kept/SKILL.md").is_file(), "tree restored");
        assert!(st.archive().join("gone/SKILL.md").is_file(), "archives survive a rollback");
        assert!(st.ledger().is_file(), "the ledger survives a rollback");
        let _ = fs::remove_dir_all(&d);
    }

    /// Cron-protected skills survive, a used-again stale skill reactivates, snapshots stay bounded
    /// and `run.json` carries the counters (Hermes `apply_automatic_transitions` + `curator_backup`).
    #[test]
    fn cron_protection_reactivation_and_snapshot_bounds() {
        let d = std::env::temp_dir().join(format!("ark-curator2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        for n in ["cronned", "revived", "gone"] {
            skill(&st, n);
        }
        let t = now();
        for (n, age) in [("cronned", 90), ("revived", 2), ("gone", 31)] {
            usage::mutate(&st, n, |r| {
                r.insert("last_used_at".into(), json!(t - age * DAY));
                r.insert("use_count".into(), json!(1));
            });
        }
        usage::set_state(&st, "revived", usage::STALE);
        // A real cron job that loads `cronned` through the job's `skills` field.
        let ws = d.join("ws");
        fs::create_dir_all(&ws).unwrap();
        let job = ark_kernel::automation::add_job(&st.data, "0 8 * * *", "run the digest", &ws, None, false, 0).unwrap();
        ark_kernel::automation::with_list::<ark_kernel::automation::Job, _>(&ark_kernel::automation::jobs_path(&st.data), |v| v.iter_mut().find(|j| j.id == job.id).map(|j| j.ext.skills = vec!["cronned".into()])).unwrap();
        assert_eq!(cron_referenced(&st), ["cronned"]);
        let (c, log) = apply_transitions(&s, &st, t, false);
        assert_eq!((c.archived, c.marked_stale, c.reactivated), (1, 0, 1), "{log:?}");
        assert!(st.skills.join("cronned").exists(), "a cron-referenced skill is never archived");
        assert_eq!(usage::get(&st, "revived")["state"], usage::ACTIVE, "used again after going stale → reactivated");
        assert!(!st.skills.join("gone").exists() && st.archive().join("gone/SKILL.md").is_file());
        // Snapshots: `keep` bounds the directory, the run report records the counters.
        for i in 0..3 {
            backup(&st, &format!("r{i}"), 2).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(list_backups(&st).len(), 2, "keep=2");
        let r = run(&s, &st, true, Some(false), None);
        let json: Value = serde_json::from_str(&fs::read_to_string(r.report_dir.unwrap().join("run.json")).unwrap()).unwrap();
        assert_eq!((json["dry_run"].as_bool(), json["checked"].as_u64().is_some(), json["actions"].is_array()), (Some(true), true, true), "{json}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn transitions_gates_backup_and_reports() {
        let d = std::env::temp_dir().join(format!("ark-curator-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        for n in ["old", "stale", "fresh", "pinned", "unmanaged"] {
            skill(&st, n);
        }
        usage::forget(&st, "unmanaged");
        usage::mutate(&st, "unmanaged", |r| {
            r.insert("created_by".into(), json!(null));
        });
        let t = now();
        for (n, age) in [("old", 40), ("stale", 20), ("pinned", 90)] {
            usage::mutate(&st, n, |r| {
                r.insert("last_used_at".into(), json!(t - age * DAY));
                r.insert("use_count".into(), json!(1));
            });
        }
        usage::mutate(&st, "pinned", |r| {
            r.insert("pinned".into(), json!(true));
        });
        let (c, log) = apply_transitions(&s, &st, t, true);
        assert_eq!((c.archived, c.marked_stale), (1, 1), "{log:?}");
        assert!(st.skills.join("old").exists(), "dry run changes nothing");
        // Gates: first sight seeds and defers.
        assert!(!should_run_now(&s, &st, None));
        assert!(load_state(&st)["last_run_at"].is_i64());
        let mut st8 = load_state(&st);
        st8["last_run_at"] = json!(t - 8 * DAY);
        save_state(&st, &st8);
        assert!(should_run_now(&s, &st, Some(t - 3 * 3600)));
        assert!(!should_run_now(&s, &st, Some(t - 60)), "not idle long enough");
        set_paused(&st, true);
        assert!(!should_run_now(&s, &st, None));
        set_paused(&st, false);
        let calls = std::cell::Cell::new(0);
        let fork = |p: &str| {
            calls.set(calls.get() + 1);
            assert!(p.contains("Candidates:") && p.contains("- fresh") && !p.contains("- unmanaged"), "{p}");
            Ok("merged nothing\n```yaml\nconsolidations: []\n```".to_string())
        };
        let r = run(&s, &st, false, Some(true), Some(&fork));
        assert_eq!(calls.get(), 1);
        assert!(r.summary.contains("archived 1") && r.summary.contains("llm: merged nothing") && r.summary.contains("archived: old"), "{}", r.summary);
        assert!(!st.skills.join("old").exists() && st.archive().join("old/SKILL.md").is_file());
        assert_eq!(usage::get(&st, "stale")["state"], usage::STALE);
        assert!(st.skills.join("pinned").exists() && st.skills.join("unmanaged").exists());
        assert!(r.report_dir.unwrap().join("REPORT.md").is_file());
        assert_eq!(list_backups(&st).len(), 1, "pre-consolidation snapshot");
        fs::remove_dir_all(st.skills.join("fresh")).unwrap();
        assert!(rollback_tree(&st, None).unwrap().contains("restored"));
        assert!(st.skills.join("fresh/SKILL.md").is_file());
        assert!(status(&s, &st).contains("1 archived"));
        assert_eq!(prune(&s, &st, 10, true), ["stale"]);
        usage::mutate(&st, "old", |r| {
            r.insert("archived_at".into(), json!(t - 100 * DAY));
        });
        assert!(purge(&s, &st, 0, true).is_err());
        assert_eq!(purge(&s, &st, 30, false).unwrap(), ["old"]);
        assert!(!st.archive().join("old").exists());
        let _ = fs::remove_dir_all(&d);
    }
}
