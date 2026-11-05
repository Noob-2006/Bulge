//! Skill bundles: aliases that load several skills under one slash command (Hermes
//! `agent/skill_bundles.py` + `hermes_cli/bundles.py`, MIT).
//!
//! YAML files in `<data>/skill-bundles/` (`name`, `description`, `skills: [...]`, optional
//! `instruction`; the file stem is the fallback name). `/<bundle>` loads every member into one
//! user message. When a bundle and a skill share a slug the bundle wins (checked first).

use super::invoke::slug;
use super::settings::Store;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub name: String,
    pub slug: String,
    pub description: String,
    pub skills: Vec<String>,
    pub instruction: String,
    pub path: PathBuf,
}

fn load_file(p: &Path) -> Option<Bundle> {
    let text = fs::read_to_string(p).ok()?;
    let v = crate::yaml::parse(&text).ok()?;
    let stem = p.file_stem()?.to_string_lossy().to_string();
    let name = v.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&stem).to_string();
    let skills: Vec<String> = match v.get("skills") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        _ => vec![],
    };
    if skills.is_empty() {
        return None;
    }
    let sl = slug(&name);
    // Same default as upstream `_load_bundle_file`: an absent/blank description still routes.
    let description = match v.get("description").and_then(Value::as_str).map(str::trim) {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => format!("Load {} skills as a bundle", skills.len()),
    };
    (!sl.is_empty()).then(|| Bundle { slug: sl, name, description, skills, instruction: v.get("instruction").and_then(Value::as_str).unwrap_or("").trim().to_string(), path: p.to_path_buf() })
}

fn scan(st: &Store) -> Vec<Bundle> {
    let mut files: Vec<PathBuf> = fs::read_dir(st.bundles()).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml"))).collect();
    files.sort();
    let mut out: Vec<Bundle> = Vec::new();
    for f in files {
        if let Some(b) = load_file(&f) {
            if !out.iter().any(|o| o.slug == b.slug) {
                out.push(b);
            }
        }
    }
    out
}

/// Slugs of the last scan, per bundles directory (a process's first scan has no baseline).
fn last() -> &'static Mutex<HashMap<PathBuf, Vec<String>>> {
    static L: OnceLock<Mutex<HashMap<PathBuf, Vec<String>>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

fn slugs(bs: &[Bundle]) -> Vec<String> {
    bs.iter().map(|b| b.slug.clone()).collect()
}

/// Every bundle, alphabetical by file; duplicate slugs keep the first.
pub fn list(st: &Store) -> Vec<Bundle> {
    let out = scan(st);
    last().lock().unwrap().insert(st.bundles(), slugs(&out));
    out
}

/// Look up by typed command (`_` ≡ `-`).
pub fn get(st: &Store, name: &str) -> Option<Bundle> {
    let k = slug(&name.trim_start_matches('/').replace('_', "-"));
    list(st).into_iter().find(|b| b.slug == k)
}

pub fn path_for(st: &Store, name: &str) -> Result<PathBuf, String> {
    let s = slug(name);
    if s.is_empty() {
        return Err(format!("Bundle name {name:?} normalizes to an empty slug"));
    }
    Ok(st.bundles().join(format!("{s}.yaml")))
}

pub fn save(st: &Store, name: &str, skills: &[String], description: &str, instruction: &str, overwrite: bool) -> Result<PathBuf, String> {
    let skills: Vec<String> = skills.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if skills.is_empty() {
        return Err("A bundle must reference at least one skill.".into());
    }
    let p = path_for(st, name)?;
    if p.exists() && !overwrite {
        return Err(format!("Bundle already exists: {} (pass --force to overwrite)", p.display()));
    }
    let mut v = json!({"name": name.trim(), "skills": skills});
    if !description.trim().is_empty() {
        v["description"] = json!(description.trim());
    }
    if !instruction.trim().is_empty() {
        v["instruction"] = json!(instruction.trim());
    }
    fs::create_dir_all(st.bundles()).map_err(|e| e.to_string())?;
    fs::write(&p, crate::yaml::to_yaml(&v)).map_err(|e| e.to_string())?;
    Ok(p)
}

pub fn delete(st: &Store, name: &str) -> Result<PathBuf, String> {
    let b = get(st, name).ok_or_else(|| format!("Bundle {name:?} not found"))?;
    fs::remove_file(&b.path).map_err(|e| e.to_string())?;
    Ok(b.path)
}

/// (added, removed, total) against a previous snapshot of slugs (`seagent bundles reload`, `/reload-skills`).
pub fn diff(before: &[String], st: &Store) -> (Vec<String>, Vec<String>, usize) {
    let now: Vec<String> = list(st).into_iter().map(|b| b.slug).collect();
    let added = now.iter().filter(|s| !before.contains(s)).cloned().collect();
    let removed = before.iter().filter(|s| !now.contains(s)).cloned().collect();
    (added, removed, now.len())
}

/// Re-scan and diff against the previous scan (upstream `reload_bundles`), then become the baseline.
fn rescan(st: &Store) -> (Vec<Bundle>, Vec<String>, usize) {
    let all = scan(st);
    let now = slugs(&all);
    let before = last().lock().unwrap().insert(st.bundles(), now.clone()).unwrap_or_else(|| now.clone());
    let added = all.into_iter().filter(|b| !before.contains(&b.slug)).collect();
    let removed = before.into_iter().filter(|s| !now.contains(s)).collect();
    (added, removed, now.len())
}

/// Re-scan the bundles directory: (added slugs, removed slugs, total). A process's first scan
/// reports no changes — there is no earlier state to diff against (same as a fresh `hermes` run).
pub fn reload(st: &Store) -> (Vec<String>, Vec<String>, usize) {
    let (added, removed, total) = rescan(st);
    (added.into_iter().map(|b| b.slug).collect(), removed, total)
}

/// `seagent bundles list|show|create|delete|reload`.
pub fn cli(st: &Store, argv: &[String]) -> Result<String, String> {
    let sub = argv.first().map(String::as_str).unwrap_or("list");
    let arg = |i: usize| argv.get(i).filter(|a| !a.starts_with('-')).cloned();
    match sub {
        "list" | "ls" => {
            let all = list(st);
            if all.is_empty() {
                return Ok(format!("No bundles installed yet. Create one with:\n  seagent bundles create <name> --skill skill1 --skill skill2\nBundles directory: {}", st.bundles().display()));
            }
            let mut o = format!("Skill bundles ({}):\n", all.len());
            for b in &all {
                o.push_str(&format!("  /{:<20} {:<20} {:>2} skills  {}\n", b.slug, b.name, b.skills.len(), b.description));
            }
            o.push_str(&format!("Bundles directory: {}", st.bundles().display()));
            Ok(o)
        }
        "show" => {
            let n = arg(1).ok_or("usage: seagent bundles show <name>")?;
            let b = get(st, &n).ok_or_else(|| format!("Bundle {n:?} not found."))?;
            let mut o = format!("/{}  {}\n", b.slug, b.name);
            if !b.description.is_empty() {
                o.push_str(&format!("  {}\n", b.description));
            }
            o.push_str(&format!("  File: {}\n  Skills ({}):\n", b.path.display(), b.skills.len()));
            for s in &b.skills {
                o.push_str(&format!("    - {s}\n"));
            }
            if !b.instruction.is_empty() {
                o.push_str(&format!("  Instruction:\n    {}\n", b.instruction));
            }
            Ok(o.trim_end().to_string())
        }
        "create" => {
            let n = arg(1).ok_or("usage: seagent bundles create <name> --skill <s>… [--description d] [--instruction i] [--force]")?;
            let (mut skills, mut desc, mut instr, mut force) = (Vec::new(), String::new(), String::new(), false);
            let mut i = 2;
            while i < argv.len() {
                match argv[i].as_str() {
                    "--skill" | "-s" => {
                        skills.extend(argv.get(i + 1).cloned());
                        i += 1;
                    }
                    "--description" | "-d" => {
                        desc = argv.get(i + 1).cloned().unwrap_or_default();
                        i += 1;
                    }
                    "--instruction" | "-i" => {
                        instr = argv.get(i + 1).cloned().unwrap_or_default();
                        i += 1;
                    }
                    "--force" | "-f" => force = true,
                    _ => {}
                }
                i += 1;
            }
            let p = save(st, &n, &skills, &desc, &instr, force)?;
            let b = get(st, &n).ok_or("bundle written but unreadable")?;
            Ok(format!("Created bundle: {}\n  Invoke with: /{}  (loads {} skills)", p.display(), b.slug, b.skills.len()))
        }
        "delete" | "rm" => {
            let n = arg(1).ok_or("usage: seagent bundles delete <name>")?;
            Ok(format!("Deleted bundle: {}", delete(st, &n)?.display()))
        }
        "reload" => {
            let (added, removed, total) = rescan(st);
            let mut lines: Vec<String> = Vec::new();
            if !added.is_empty() {
                lines.push(format!("Added ({}):", added.len()));
                lines.extend(added.iter().map(|b| format!("  + /{} — {}", b.slug, b.description)));
            }
            if !removed.is_empty() {
                lines.push(format!("Removed ({}):", removed.len()));
                lines.extend(removed.iter().map(|s| format!("  - /{s}")));
            }
            if lines.is_empty() {
                lines.push(format!("No changes. {total} bundle(s) loaded."));
            } else {
                lines.push(format!("Total bundles now: {total}"));
            }
            Ok(lines.join("\n"))
        }
        other => Err(format!("unknown `seagent bundles` subcommand `{other}` (list, show, create, delete, reload)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crud_and_cli() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-bundles-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let a = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(cli(&st, &a(&["list"])).unwrap().contains("No bundles installed yet"));
        assert!(cli(&st, &a(&["create", "Ship Day"])).unwrap_err().contains("at least one skill"));
        let o = cli(&st, &a(&["create", "Ship Day", "-s", "deploy", "--skill", "review", "-d", "release kit", "-i", "be careful"])).unwrap();
        assert!(o.contains("/ship-day") && o.contains("loads 2 skills"), "{o}");
        assert!(cli(&st, &a(&["create", "ship day", "-s", "x"])).unwrap_err().contains("already exists"));
        let b = get(&st, "/ship_day").unwrap();
        assert_eq!((b.name.as_str(), b.skills.clone(), b.instruction.as_str()), ("Ship Day", a(&["deploy", "review"]), "be careful"));
        fs::write(st.bundles().join("csv.yml"), "skills: a, b\n").unwrap();
        fs::write(st.bundles().join("broken.yaml"), "skills: [\n").unwrap();
        let (added, removed, total) = diff(&["gone".into()], &st);
        assert_eq!((added.len(), removed, total), (2, vec!["gone".to_string()], 2));
        assert!(cli(&st, &a(&["show", "csv"])).unwrap().contains("- b"));
        assert!(cli(&st, &a(&["delete", "ship-day"])).unwrap().contains("Deleted"));
        assert!(get(&st, "ship-day").is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reload_diffs_and_defaults() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-bundles-reload-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let a = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        fs::create_dir_all(st.bundles()).unwrap();
        fs::write(st.bundles().join("pair.yml"), "name: Pair\nskills: [a, b]\n").unwrap();
        assert_eq!(get(&st, "pair").unwrap().description, "Load 2 skills as a bundle");
        let o = cli(&st, &a(&["reload"])).unwrap();
        assert!(o.starts_with("No changes.") && o.contains("1 bundle(s) loaded."), "{o}");
        fs::write(st.bundles().join("trio.yaml"), "name: Trio\nskills: [a, b, c]\n").unwrap();
        let o = cli(&st, &a(&["reload"])).unwrap();
        assert!(o.contains("Added (1):") && o.contains("  + /trio — Load 3 skills as a bundle") && o.contains("Total bundles now: 2"), "{o}");
        fs::remove_file(st.bundles().join("pair.yml")).unwrap();
        let o = cli(&st, &a(&["reload"])).unwrap();
        assert!(o.contains("Removed (1):") && o.contains("  - /pair") && o.contains("Total bundles now: 1"), "{o}");
        let (added, removed, total) = reload(&st);
        assert_eq!((added, removed, total), (vec![], vec![], 1));
        let _ = fs::remove_dir_all(&d);
    }
}
