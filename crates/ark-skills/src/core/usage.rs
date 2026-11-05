//! Skill usage telemetry and provenance for the curator (Hermes `tools/skill_usage.py`, MIT).
//!
//! A sidecar `<data>/skills/.usage.json` keyed by skill name (never frontmatter: telemetry stays
//! out of user-authored SKILL.md and off bundled/hub skills). Counters are best-effort and
//! never break a tool call. Curator management is an explicit `created_by: "agent"` marker
//! written when the agent creates a skill (or `ark curator adopt`), never inferred from
//! location. Lifecycle: active → stale → archived (moved to `.archive/`); `pinned` opts out
//! of automatic transitions. Provenance: hub (lock file), bundled (sync manifest), external
//! (only under `external_dirs`), agent (everything else local).

use super::settings::{Settings, Store};
use crate::skill::{self, Skill};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const ACTIVE: &str = "active";
pub const STALE: &str = "stale";
pub const ARCHIVED: &str = "archived";

static LOCK: Mutex<()> = Mutex::new(());

fn now() -> i64 {
    ark_kernel::util::unix_now()
}

pub fn empty_record() -> Value {
    json!({"created_by": null, "use_count": 0, "view_count": 0, "patch_count": 0, "last_used_at": null, "last_viewed_at": null, "last_patched_at": null, "created_at": now(), "state": ACTIVE, "pinned": false, "archived_at": null, "first_seen_at": null})
}

fn backfill(rec: Option<&Value>) -> Value {
    let mut base = empty_record();
    if let (Some(Value::Object(r)), Value::Object(b)) = (rec, &mut base) {
        for (k, v) in r {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

pub fn load(st: &Store) -> Map<String, Value> {
    fs::read_to_string(st.usage()).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v.as_object().cloned()).map(|m| m.into_iter().filter(|(_, v)| v.is_object()).collect()).unwrap_or_default()
}

fn save(st: &Store, m: &Map<String, Value>) -> bool {
    fs::create_dir_all(&st.skills).is_ok() && ark_kernel::util::atomic_write(&st.usage(), serde_json::to_string_pretty(m).unwrap_or_default().as_bytes()).is_ok()
}

/// Load, mutate `name`'s (backfilled) record, save. Returns the new record when it landed.
pub fn mutate(st: &Store, name: &str, f: impl FnOnce(&mut Map<String, Value>)) -> Option<Value> {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut m = load(st);
    let mut rec = backfill(m.get(name));
    f(rec.as_object_mut()?);
    m.insert(name.to_string(), rec.clone());
    save(st, &m).then_some(rec)
}

pub fn get(st: &Store, name: &str) -> Value {
    backfill(load(st).get(name))
}

fn int(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_i64).unwrap_or(0)
}

/// Newest use / view / patch timestamp (`created_at` excluded).
pub fn latest_activity(rec: &Value) -> Option<i64> {
    ["last_used_at", "last_viewed_at", "last_patched_at"].iter().filter_map(|k| rec.get(*k).and_then(Value::as_i64)).max()
}

pub fn activity_count(rec: &Value) -> i64 {
    int(rec, "use_count") + int(rec, "view_count") + int(rec, "patch_count")
}

fn bump(st: &Store, name: &str, count: &str, at: &str) -> Option<Value> {
    mutate(st, name, |r| {
        let c = r.get(count).and_then(Value::as_i64).unwrap_or(0) + 1;
        r.insert(count.into(), json!(c));
        r.insert(at.into(), json!(now()));
        if r.get("state").and_then(Value::as_str) == Some(STALE) {
            r.insert("state".into(), json!(ACTIVE));
        }
    })
}

pub fn bump_view(st: &Store, name: &str) -> Option<Value> {
    bump(st, name, "view_count", "last_viewed_at")
}
pub fn bump_use(st: &Store, name: &str) -> Option<Value> {
    bump(st, name, "use_count", "last_used_at")
}
pub fn bump_patch(st: &Store, name: &str) -> Option<Value> {
    bump(st, name, "patch_count", "last_patched_at")
}

/// A create resets the record. Foreground creates the user asked for (`/learn`) are stamped
/// `learn`, a learning signal — not the curator-management opt-in (`agent`).
pub fn record_created(st: &Store, name: &str, agent_created: bool) -> Option<Value> {
    mutate(st, name, |r| {
        *r = empty_record().as_object().cloned().unwrap();
        r.insert("created_by".into(), json!(if agent_created { "agent" } else { "learn" }));
    })
}

pub fn record_installed(st: &Store, name: &str) -> Option<Value> {
    mutate(st, name, |r| {
        r.insert("created_by".into(), json!("installed"));
        r.insert("state".into(), json!(ACTIVE));
        r.insert("archived_at".into(), Value::Null);
    })
}

pub fn forget(st: &Store, name: &str) {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut m = load(st);
    if m.remove(name).is_some() {
        save(st, &m);
    }
}

// ───────────── provenance ─────────────

pub fn bundled_names(st: &Store) -> Vec<String> {
    let mut v: Vec<String> = fs::read_to_string(st.manifest()).unwrap_or_default().lines().filter_map(|l| l.split(':').next()).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    v.extend(suppressed(st));
    v
}

pub fn hub_names(st: &Store) -> Vec<String> {
    let v: Value = fs::read_to_string(st.hub().join("lock.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
    v["installed"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default()
}

pub fn suppressed(st: &Store) -> Vec<String> {
    fs::read_to_string(st.suppressed()).unwrap_or_default().lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#')).map(String::from).collect()
}

pub fn set_suppressed(st: &Store, name: &str, on: bool) {
    let mut v = suppressed(st);
    let had = v.iter().any(|n| n == name);
    if on == had {
        return;
    }
    if on {
        v.push(name.into());
    } else {
        v.retain(|n| n != name);
    }
    let _ = fs::create_dir_all(&st.skills);
    let _ = fs::write(st.suppressed(), v.join("\n") + "\n");
}

/// Skills in the local store (`<data>/skills`, excluding hub internals and the archive).
pub fn local_skills(st: &Store) -> Vec<Skill> {
    skill::discover(&[(st.skills.clone(), skill::Source::User)])
}

pub fn find_local(st: &Store, name: &str) -> Option<Skill> {
    local_skills(st).into_iter().find(|s| s.name == name)
}

fn external_names(s: &Settings) -> Vec<String> {
    let roots: Vec<_> = s.external_dirs.iter().map(|d| (d.clone(), skill::Source::Extra)).collect();
    skill::discover(&roots).into_iter().map(|s| s.name).collect()
}

/// `hub` | `bundled` | `external` | `agent`.
pub fn provenance(s: &Settings, st: &Store, name: &str) -> &'static str {
    if hub_names(st).iter().any(|n| n == name) {
        "hub"
    } else if bundled_names(st).iter().any(|n| n == name) {
        "bundled"
    } else if find_local(st, name).is_none() && external_names(s).iter().any(|n| n == name) {
        "external"
    } else {
        "agent"
    }
}

/// Agent-created: yes. Bundled: only with `curator.prune_builtins`. Hub / external: never.
pub fn curation_eligible(s: &Settings, st: &Store, name: &str) -> bool {
    match provenance(s, st, name) {
        "agent" => true,
        "bundled" => s.curator.prune_builtins,
        _ => false,
    }
}

pub fn curator_managed(s: &Settings, st: &Store, name: &str) -> bool {
    match provenance(s, st, name) {
        "agent" => get(st, name)["created_by"] == "agent",
        "bundled" => s.curator.prune_builtins,
        _ => false,
    }
}

/// Opt a skill into curator management (`ark curator adopt`); the inactivity clock is not reset.
pub fn adopt(s: &Settings, st: &Store, name: &str) -> Result<String, String> {
    match provenance(s, st, name) {
        "hub" => return Err(format!("skill '{name}' is hub-installed; the curator never manages it")),
        "external" => return Err(format!("skill '{name}' lives in an external dir and is read-only here")),
        "bundled" => return Err(format!("skill '{name}' is a bundled built-in; enable curator.prune_builtins instead")),
        _ => {}
    }
    if find_local(st, name).is_none() {
        return Err(format!("skill '{name}' not found"));
    }
    mutate(st, name, |r| {
        r.insert("created_by".into(), json!("agent"));
    })
    .map(|_| format!("adopted '{name}' (curator-managed)"))
    .ok_or_else(|| "could not write usage record".into())
}

pub fn set_pinned(s: &Settings, st: &Store, name: &str, pinned: bool) -> Result<(), String> {
    if !curation_eligible(s, st, name) {
        return Err(format!("skill '{name}' is not curation-eligible ({})", provenance(s, st, name)));
    }
    mutate(st, name, |r| {
        r.insert("pinned".into(), json!(pinned));
    })
    .map(|_| ())
    .ok_or_else(|| "could not write usage record".into())
}

pub fn set_state(st: &Store, name: &str, state: &str) {
    mutate(st, name, |r| {
        r.insert("state".into(), json!(state));
        r.insert("archived_at".into(), if state == ARCHIVED { json!(now()) } else { Value::Null });
    });
}

fn move_dir(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::rename(src, dest).or_else(|_| {
        copy_tree(src, dest)?;
        fs::remove_dir_all(src).map_err(|e| e.to_string())
    })
}

pub fn copy_tree(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    for e in fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
        let (p, d) = (e.path(), dest.join(e.file_name()));
        let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
        if m.is_dir() {
            copy_tree(&p, &d)?;
        } else if m.is_file() {
            fs::copy(&p, &d).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Move a curation-eligible skill to `.archive/<name>` (timestamp suffix on collision), with a
/// ledger entry. Never hub; bundled only with `prune_builtins` (and then suppressed from re-seeding).
pub fn archive(s: &Settings, st: &Store, name: &str, actor: &str) -> Result<String, String> {
    let sk = find_local(st, name);
    if !curation_eligible(s, st, name) {
        return Err(match provenance(s, st, name) {
            "hub" => format!("skill '{name}' is hub-installed; never archive"),
            "external" => format!("skill '{name}' lives in an external dir and is read-only here"),
            _ => format!("skill '{name}' is a bundled built-in; enable curator.prune_builtins to allow pruning it"),
        });
    }
    let sk = sk.ok_or_else(|| format!("skill '{name}' not found"))?;
    let mut dest = st.archive().join(name);
    if dest.exists() {
        dest = st.archive().join(format!("{name}-{}", now()));
    }
    let before = super::ledger::capture_before(s, st, &sk.dir);
    move_dir(&sk.dir, &dest)?;
    super::ledger::record(s, st, actor, "archive", name, before, None, &format!("→ {}", dest.display()));
    if provenance(s, st, name) == "bundled" {
        set_suppressed(st, name, true);
    }
    set_state(st, name, ARCHIVED);
    Ok(format!("archived '{name}' → {}", dest.display()))
}

pub fn archived_names(st: &Store) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(st.archive()).into_iter().flatten().flatten().filter(|e| e.path().join("SKILL.md").is_file()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    v.sort();
    v
}

pub fn restore(s: &Settings, st: &Store, name: &str, actor: &str) -> Result<String, String> {
    if hub_names(st).iter().any(|n| n == name) {
        return Err(format!("skill '{name}' is now hub-installed; restore would shadow the upstream version"));
    }
    if bundled_names(st).iter().any(|n| n == name) && !suppressed(st).iter().any(|n| n == name) && !s.curator.prune_builtins {
        return Err(format!("skill '{name}' is now bundled; restore would shadow the upstream version"));
    }
    let src: PathBuf = {
        let exact = st.archive().join(name);
        if exact.is_dir() {
            exact
        } else {
            // `<name>-<digits>` only: a bare prefix would let restoring "git" steal "git-helpers"
            // (Hermes `restore_skill` checks the timestamp suffix length).
            let mut c: Vec<PathBuf> = fs::read_dir(st.archive()).map_err(|_| "no archive directory".to_string())?.flatten().map(|e| e.path()).filter(|p| {
                p.file_name().and_then(|f| f.to_str()).and_then(|f| f.strip_prefix(&format!("{name}-"))).is_some_and(|s| s.len() >= 8 && s.chars().all(|c| c.is_ascii_digit()))
            }).collect();
            c.sort();
            // Older archives were flattened under the directory name; fall back to the frontmatter name.
            c.pop().or_else(|| fs::read_dir(st.archive()).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir() && p.join("SKILL.md").is_file()).find(|p| crate::skill::Skill::load(p, &st.archive(), crate::skill::Source::User).is_ok_and(|s| s.name == name))).ok_or_else(|| format!("'{name}' is not archived"))?
        }
    };
    let dest = st.skills.join(name);
    if dest.exists() {
        return Err(format!("{} already exists", dest.display()));
    }
    move_dir(&src, &dest)?;
    super::ledger::record(s, st, actor, "restore", name, None, Some(&dest), "");
    set_suppressed(st, name, false);
    set_state(st, name, ACTIVE);
    Ok(format!("restored '{name}' → {}", dest.display()))
}

/// One row per skill on disk (local store + bundled + external) with provenance and activity.
pub fn report(s: &Settings, st: &Store, all: &[Skill]) -> Vec<Value> {
    let usage = load(st);
    let mut rows: Vec<Value> = all
        .iter()
        .map(|sk| {
            let rec = backfill(usage.get(&sk.name));
            let mut r = rec.as_object().cloned().unwrap();
            r.insert("name".into(), json!(sk.name));
            r.insert("provenance".into(), json!(provenance(s, st, &sk.name)));
            r.insert("last_activity_at".into(), json!(latest_activity(&rec)));
            r.insert("activity_count".into(), json!(activity_count(&rec)));
            Value::Object(r)
        })
        .collect();
    rows.sort_by(|a, b| b["activity_count"].as_i64().cmp(&a["activity_count"].as_i64()).then(a["name"].as_str().cmp(&b["name"].as_str())));
    rows
}

/// Lifecycle observer: skill views / creates / patches through the `skill` tool (and
/// `skill_view` / `skill_manage` spellings) bump the sidecar counters.
pub struct UsageTracker {
    pub store: Store,
}

impl ark_kernel::lifecycle::Lifecycle for UsageTracker {
    fn name(&self) -> String {
        "skill-usage".into()
    }
    fn tool_settled(&self, _session: &str, tool: &str, input: &Value, is_error: bool) {
        if is_error {
            return;
        }
        let name = input.get("name").and_then(Value::as_str).unwrap_or("").trim();
        let name = name.rsplit('/').next().unwrap_or(name);
        if name.is_empty() {
            return;
        }
        let action = input.get("action").and_then(Value::as_str).unwrap_or(match tool {
            "skill_view" | "skills_read" => "view",
            _ => "",
        });
        match (tool, action) {
            ("skill" | "skill_view" | "skills_read", "view") => {
                bump_view(&self.store, name);
            }
            ("skill" | "skill_manage", "create") => {
                record_created(&self.store, name, true);
            }
            ("skill" | "skill_manage", "update" | "patch" | "edit" | "write_file") => {
                bump_patch(&self.store, name);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_kernel::lifecycle::Lifecycle;

    /// `restore git` must never steal `git-helpers-<ts>`: only an exact name or a `<name>-<digits>`
    /// timestamp suffix counts (Hermes `restore_skill`), else the frontmatter name decides.
    #[test]
    fn restore_matches_exact_name_not_a_shared_prefix() {
        let d = ark_core::tmp::scratch_path(format!("ark-usage2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        for (dir, name) in [("git-helpers-1700000000", "git-helpers"), ("git-1700000001", "git"), ("legacy", "renamed")] {
            let p = st.archive().join(dir);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("SKILL.md"), format!("---\nname: {name}\ndescription: d\n---\nbody")).unwrap();
            if name == "renamed" {
                mutate(&st, name, |r| {
                    r.insert("state".into(), serde_json::json!(ARCHIVED));
                });
            }
        }
        assert_eq!(archived_names(&st), ["git-1700000001", "git-helpers-1700000000", "legacy"]);
        assert!(restore(&s, &st, "git", "user").is_ok());
        assert!(st.skills.join("git/SKILL.md").is_file());
        assert!(st.archive().join("git-helpers-1700000000").is_dir(), "a prefix is not a match");
        assert!(st.archive().join("legacy").is_dir());
        // The fallback: a directory named differently from its frontmatter name.
        assert!(restore(&s, &st, "renamed", "user").is_ok());
        assert!(st.skills.join("renamed/SKILL.md").is_file() && !st.archive().join("legacy").exists());
        assert!(restore(&s, &st, "git", "user").unwrap_err().contains("is not archived"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn counters_provenance_archive_restore() {
        let d = ark_core::tmp::scratch_path(format!("ark-usage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        for n in ["mine", "builtin", "hubbed"] {
            fs::create_dir_all(st.skills.join(n)).unwrap();
            fs::write(st.skills.join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: d\n---\n")).unwrap();
        }
        fs::write(st.manifest(), "builtin:abc\n").unwrap();
        fs::create_dir_all(st.hub()).unwrap();
        fs::write(st.hub().join("lock.json"), r#"{"version":1,"installed":{"hubbed":{}}}"#).unwrap();
        let t = UsageTracker { store: st.clone() };
        t.tool_settled("s", "skill", &json!({"action": "create", "name": "mine"}), false);
        t.tool_settled("s", "skill", &json!({"action": "view", "name": "mine"}), false);
        t.tool_settled("s", "skill", &json!({"name": "mine", "action": "update"}), false);
        t.tool_settled("s", "skill", &json!({"action": "view", "name": "mine"}), true);
        let r = get(&st, "mine");
        assert_eq!((r["view_count"].as_i64(), r["patch_count"].as_i64(), r["created_by"].as_str()), (Some(1), Some(1), Some("agent")));
        assert!(latest_activity(&r).is_some() && activity_count(&r) == 2);
        assert_eq!((provenance(&s, &st, "mine"), provenance(&s, &st, "builtin"), provenance(&s, &st, "hubbed")), ("agent", "bundled", "hub"));
        assert!(curator_managed(&s, &st, "mine") && !curation_eligible(&s, &st, "builtin") && !curation_eligible(&s, &st, "hubbed"));
        assert!(archive(&s, &st, "hubbed", "user").unwrap_err().contains("hub-installed"));
        assert!(archive(&s, &st, "builtin", "user").unwrap_err().contains("prune_builtins"));
        assert!(archive(&s, &st, "mine", "user").unwrap().contains(".archive"));
        assert!(!st.skills.join("mine").exists() && archived_names(&st) == ["mine"]);
        assert_eq!(get(&st, "mine")["state"], ARCHIVED);
        assert!(restore(&s, &st, "mine", "user").is_ok());
        assert!(st.skills.join("mine/SKILL.md").is_file());
        assert_eq!(get(&st, "mine")["state"], ACTIVE);
        assert_eq!(super::super::ledger::list(&st, Some("mine"), 5).len(), 2, "archive + restore recorded");
        let rows = report(&s, &st, &local_skills(&st));
        assert_eq!(rows[0]["name"], "mine");
        set_pinned(&s, &st, "mine", true).unwrap();
        assert!(set_pinned(&s, &st, "hubbed", true).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
