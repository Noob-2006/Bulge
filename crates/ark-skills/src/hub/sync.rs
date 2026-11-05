//! Bundled-skill sync (Hermes `tools/skills_sync.py` + `skills_sync_bundled_ops.py`, MIT):
//! manifest-based seeding of ark's shipped skills (`share/skills`) into `<data>/skills`.
//!
//! `.bundled_manifest` holds `name:origin-hash` lines. New skills are copied and recorded;
//! existing ones update only when the bundled copy changed AND the user copy still matches the
//! recorded origin hash (otherwise it is user-modified and skipped); user-deleted skills are
//! not re-added; skills the curator pruned (`.curator_suppressed`) stay archived; skills an
//! external dir provides are never shadowed; upstream-removed ones leave the manifest once no
//! copy remains. `.no-bundled-skills` opts a profile out of seeding.
//!
//! Supply chain (A13): this path copies files that ship *inside the ark binary*'s
//! `share/skills`, so there is no download to verify here — signatures, version pins and
//! integrity-at-use-time are enforced where bytes arrive from a network source
//! (`hub::install::Hub::{install,install_bundle,check,update}` → `hub::verify`). A bundled skill
//! that a user later replaces with a hub install stays under that install's pin.

use super::super::core::settings::{Settings, Store};
use super::super::core::usage;
use super::install::{dir_files, files_hash};
use crate::skill::{self, Skill};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SyncResult {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub skipped_modified: Vec<String>,
    pub skipped_deleted: Vec<String>,
    pub removed_from_manifest: Vec<String>,
    pub unchanged: usize,
    /// Copies moved to their new path after an upstream rename/recategorisation.
    pub relocated: Vec<String>,
    /// The profile opted out (`.no-bundled-skills`): only `ESSENTIAL_SKILLS` were considered.
    pub essential_only: bool,
    /// gen2-508: shipped skills whose bytes no longer match this build's pins — not seeded.
    pub tampered: Vec<String>,
}

/// Skills a `.no-bundled-skills` profile still seeds (Hermes `agent.skill_utils.ESSENTIAL_SKILLS`):
/// the one the system prompt always points at. Everything else stays untouched.
pub const ESSENTIAL_SKILLS: &[&str] = &["ark-agent"];

pub fn bundled_dir() -> Option<PathBuf> {
    std::env::var_os("ARK_BUNDLED_SKILLS_DIR").map(PathBuf::from).or_else(|| skill::share_dir().map(|d| d.join("skills"))).filter(|d| d.is_dir())
}

pub fn read_manifest(st: &Store) -> BTreeMap<String, String> {
    fs::read_to_string(st.manifest()).unwrap_or_default().lines().filter_map(|l| {
        let l = l.trim();
        if l.is_empty() {
            return None;
        }
        Some(match l.split_once(':') {
            Some((n, h)) => (n.trim().to_string(), h.trim().to_string()),
            None => (l.to_string(), String::new()),
        })
    }).collect()
}

fn write_manifest(st: &Store, m: &BTreeMap<String, String>) -> Result<(), String> {
    fs::create_dir_all(&st.skills).map_err(|e| e.to_string())?;
    let body: String = m.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    ark_kernel::util::atomic_write(&st.manifest(), body.as_bytes()).map_err(|e| e.to_string())
}

pub fn dir_hash(d: &Path) -> String {
    files_hash(&dir_files(d))
}

fn bundled(dir: &Path) -> Vec<Skill> {
    skill::discover(&[(dir.to_path_buf(), skill::Source::Bundled)])
}

fn dest_for(st: &Store, bdir: &Path, s: &Skill) -> PathBuf {
    st.skills.join(s.dir.strip_prefix(bdir).unwrap_or(Path::new(&s.name)))
}

/// Seed / update bundled skills. `only` restricts to some names (repair, `ensure`).
pub fn sync(s: &Settings, st: &Store, bdir: &Path) -> Result<SyncResult, String> {
    let mut r = SyncResult { essential_only: st.no_bundled_marker().exists(), ..Default::default() };
    let mut man = read_manifest(st);
    let suppressed = usage::suppressed(st);
    let local: Vec<Skill> = usage::local_skills(st);
    let external: Vec<String> = skill::discover(&s.external_dirs.iter().map(|d| (d.clone(), skill::Source::Extra)).collect::<Vec<_>>()).into_iter().map(|x| x.name).collect();
    let hub = usage::hub_names(st);
    let all = bundled(bdir);
    let pinned = crate::integrity::applies(bdir);
    for b in &all {
        let name = b.name.clone();
        if pinned {
            if let Err(e) = crate::integrity::check_skill(bdir, &b.dir) {
                eprintln!("ark: skills: {e}; not seeded");
                r.tampered.push(name);
                continue;
            }
        }
        let origin = dir_hash(&b.dir);
        // An opted-out profile (.no-bundled-skills) still seeds the essentials (upstream
        // `sync_skills`); the curator's pruned list never hides an essential either.
        if r.essential_only && !ESSENTIAL_SKILLS.contains(&name.as_str()) {
            r.unchanged += 1;
            continue;
        }
        if (suppressed.contains(&name) && !ESSENTIAL_SKILLS.contains(&name.as_str())) || hub.contains(&name) {
            continue;
        }
        let dest = local.iter().find(|l| l.name == name).map(|l| l.dir.clone()).unwrap_or_else(|| dest_for(st, bdir, b));
        if external.contains(&name) {
            // An external dir provides this skill: never shadow it, and drop a stale identical
            // copy an earlier sync left behind (a user's own skill differs, so it stays).
            if dest.exists() && dir_hash(&dest) == origin {
                let _ = fs::remove_dir_all(&dest);
                man.remove(&name);
            }
            continue;
        }
        // A half-finished update may have left the user's only copy in `dest.bak`.
        let bak = dest.with_extension("bak");
        if !dest.exists() && bak.is_dir() {
            let _ = fs::rename(&bak, &dest);
        }
        match man.get(&name).cloned() {
            None => {
                if dest.exists() {
                    // A same-named local skill the user made: never overwrite, but track it once identical.
                    if dir_hash(&dest) == origin {
                        man.insert(name.clone(), origin);
                    }
                    r.unchanged += 1;
                    continue;
                }
                usage::copy_tree(&b.dir, &dest)?;
                man.insert(name.clone(), origin);
                r.added.push(name);
            }
            Some(recorded) => {
                // The bundled tree's path is canonical; the user's copy normally sits there. When it
                // sits elsewhere and is byte-identical to the recorded origin, upstream moved the
                // skill (rename / recategorisation) and the copy relocates with it; a customised copy
                // stays put and keeps updating in place.
                let canonical = dest_for(st, bdir, b);
                let mut dest = dest;
                if !recorded.is_empty() && dest != canonical && dest.exists() && dir_hash(&dest) == recorded && relocate(&dest, &canonical) {
                    r.relocated.push(name.clone());
                    dest = canonical;
                }
                if !dest.exists() {
                    r.skipped_deleted.push(name);
                    continue;
                }
                let current = dir_hash(&dest);
                if recorded.is_empty() {
                    // v1 manifest (plain name, no hash): an edit cannot be told apart from an
                    // upstream change, so adopt the user's copy as the baseline (upstream).
                    man.insert(name.clone(), current);
                    r.unchanged += 1;
                } else if recorded == origin || current == origin {
                    if current == origin && recorded != origin {
                        man.insert(name.clone(), origin);
                    }
                    r.unchanged += 1;
                } else if current == recorded {
                    let bak = dest.with_extension("bak");
                    let _ = fs::remove_dir_all(&bak);
                    fs::rename(&dest, &bak).map_err(|e| e.to_string())?;
                    match usage::copy_tree(&b.dir, &dest) {
                        Ok(()) => {
                            let _ = fs::remove_dir_all(&bak);
                            man.insert(name.clone(), origin);
                            r.updated.push(name);
                        }
                        Err(e) => {
                            let _ = fs::remove_dir_all(&dest);
                            let _ = fs::rename(&bak, &dest);
                            return Err(e);
                        }
                    }
                } else {
                    r.skipped_modified.push(name);
                }
            }
        }
    }
    let names: Vec<String> = all.iter().map(|b| b.name.clone()).collect();
    // An opted-out profile only looked at the essentials, so it must not clean anything else.
    let gone: Vec<String> = if r.essential_only {
        Vec::new()
    } else {
        man.keys().filter(|k| !names.contains(k) && !local.iter().any(|l| &l.name == *k) && !usage::archived_names(st).contains(k)).cloned().collect()
    };
    for g in gone {
        man.remove(&g);
        r.removed_from_manifest.push(g);
    }
    seed_descriptions(st, bdir, r.essential_only, &all);
    write_manifest(st, &man)?;
    Ok(r)
}

/// Move a pristine copy to its canonical path (upstream rename/recategorisation recovery). Only a
/// copy byte-identical to the recorded origin is ours; moving a customised one would edit user work.
fn relocate(from: &Path, dest: &Path) -> bool {
    if from == dest || !from.is_dir() {
        return false;
    }
    if fs::create_dir_all(dest.parent().unwrap_or(dest)).is_err() {
        return false;
    }
    fs::rename(from, dest).is_ok()
}

/// Copy category `DESCRIPTION.md` files the user does not have yet (upstream
/// `_seed_category_descriptions`); an opted-out profile seeds only the essentials' categories.
fn seed_descriptions(st: &Store, bdir: &Path, essential_only: bool, all: &[Skill]) {
    let keep: Vec<PathBuf> = all
        .iter()
        .filter(|b| !essential_only || ESSENTIAL_SKILLS.contains(&b.name.as_str()))
        .filter_map(|b| b.dir.strip_prefix(bdir).ok().and_then(|p| p.parent()).map(|p| st.skills.join(p)))
        .collect();
    for (rel, data) in dir_files(bdir) {
        if rel.rsplit('/').next() != Some("DESCRIPTION.md") {
            continue;
        }
        let dest = st.skills.join(&rel);
        if dest.exists() || (essential_only && !dest.parent().is_some_and(|d| keep.iter().any(|k| k == d))) {
            continue;
        }
        if let Some(p) = dest.parent() {
            let _ = fs::create_dir_all(p);
        }
        let _ = fs::write(&dest, data);
    }
}

/// Bundled skills the user edited (kept by sync): (name, user copy, bundled source).
pub fn list_modified(st: &Store, bdir: &Path) -> Vec<(String, PathBuf, PathBuf)> {
    let man = read_manifest(st);
    let local = usage::local_skills(st);
    let mut v = Vec::new();
    for b in bundled(bdir) {
        let (Some(rec), Some(l)) = (man.get(&b.name), local.iter().find(|l| l.name == b.name)) else { continue };
        let cur = dir_hash(&l.dir);
        if &cur != rec && cur != dir_hash(&b.dir) {
            v.push((b.name.clone(), l.dir.clone(), b.dir.clone()));
        }
    }
    v
}

/// Line diff of the user's copy against stock: (path, status, diff text).
pub fn diff(st: &Store, bdir: &Path, name: &str) -> Result<Vec<(String, String, String)>, String> {
    let b = bundled(bdir).into_iter().find(|b| b.name == name).ok_or_else(|| format!("'{name}' is not a bundled skill"))?;
    let l = usage::find_local(st, name).ok_or_else(|| format!("'{name}' is not installed in {}", st.skills.display()))?;
    let (bf, lf) = (dir_files(&b.dir), dir_files(&l.dir));
    let mut out = Vec::new();
    for k in bf.keys().chain(lf.keys()).collect::<std::collections::BTreeSet<_>>() {
        match (bf.get(k), lf.get(k)) {
            (Some(a), Some(c)) if a == c => {}
            (Some(a), Some(c)) => match (std::str::from_utf8(a), std::str::from_utf8(c)) {
                (Ok(a), Ok(c)) => out.push((k.clone(), "modified".into(), line_diff(a, c))),
                _ => out.push((k.clone(), "binary".into(), String::new())),
            },
            (None, Some(_)) => out.push((k.clone(), "added".into(), String::new())),
            (Some(_), None) => out.push((k.clone(), "removed".into(), String::new())),
            (None, None) => {}
        }
    }
    Ok(out)
}

/// Minimal unified-style diff (LCS on lines).
pub fn line_diff(a: &str, b: &str) -> String {
    let (x, y): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    if x.len() * y.len() > 4_000_000 {
        return format!("--- stock ({} lines)\n+++ yours ({} lines)\n(too large to diff)", x.len(), y.len());
    }
    let mut l = vec![vec![0u32; y.len() + 1]; x.len() + 1];
    for i in (0..x.len()).rev() {
        for j in (0..y.len()).rev() {
            l[i][j] = if x[i] == y[j] { l[i + 1][j + 1] + 1 } else { l[i + 1][j].max(l[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut o) = (0, 0, String::from("--- stock\n+++ yours\n"));
    while i < x.len() || j < y.len() {
        if i < x.len() && j < y.len() && x[i] == y[j] {
            i += 1;
            j += 1;
        } else if j < y.len() && (i == x.len() || l[i][j + 1] > l[i + 1][j]) {
            o.push_str(&format!("+{}\n", y[j]));
            j += 1;
        } else {
            o.push_str(&format!("-{}\n", x[i]));
            i += 1;
        }
    }
    o
}

/// Clear a bundled skill's manifest entry (`restore` also replaces the user copy with stock).
pub fn reset(st: &Store, bdir: &Path, name: &str, restore: bool) -> Result<String, String> {
    let mut man = read_manifest(st);
    let b = bundled(bdir).into_iter().find(|b| b.name == name);
    if !restore {
        return Ok(if man.remove(name).is_some() {
            write_manifest(st, &man)?;
            format!("cleared '{name}' from the bundled manifest; the next sync tracks it again")
        } else {
            format!("'{name}' is not in the bundled manifest")
        });
    }
    let b = b.ok_or_else(|| format!("'{name}' is not a bundled skill"))?;
    let dest = usage::find_local(st, name).map(|l| l.dir).unwrap_or_else(|| dest_for(st, bdir, &b));
    if dest.exists() {
        fs::remove_dir_all(&dest).map_err(|e| e.to_string())?;
    }
    usage::copy_tree(&b.dir, &dest)?;
    man.insert(name.to_string(), dir_hash(&b.dir));
    write_manifest(st, &man)?;
    usage::set_suppressed(st, name, false);
    Ok(format!("restored '{name}' from the bundled copy → {}", dest.display()))
}

/// Toggle the opt-out marker; `remove` also deletes pristine (unedited, manifest-tracked) copies.
pub fn opt_out(st: &Store, bdir: &Path, on: bool, remove: bool) -> Result<String, String> {
    fs::create_dir_all(&st.skills).map_err(|e| e.to_string())?;
    if !on {
        let _ = fs::remove_file(st.no_bundled_marker());
        return Ok("bundled-skill seeding re-enabled".into());
    }
    fs::write(st.no_bundled_marker(), "").map_err(|e| e.to_string())?;
    let mut removed = Vec::new();
    if remove {
        let mut man = read_manifest(st);
        for b in bundled(bdir) {
            let Some(l) = usage::find_local(st, &b.name) else { continue };
            if man.get(&b.name).is_some_and(|h| *h == dir_hash(&l.dir)) {
                fs::remove_dir_all(&l.dir).map_err(|e| e.to_string())?;
                man.remove(&b.name);
                removed.push(b.name.clone());
            }
        }
        write_manifest(st, &man)?;
    }
    Ok(format!("bundled-skill seeding disabled{}", if removed.is_empty() { String::new() } else { format!("; removed {} pristine skill(s)", removed.len()) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_update_modified_deleted_reset_optout() {
        let d = std::env::temp_dir().join(format!("ark-sync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let b = d.join("bundled");
        for (n, body) in [("a", "A1"), ("b", "B1"), ("c", "C1")] {
            fs::create_dir_all(b.join("cat").join(n)).unwrap();
            fs::write(b.join("cat").join(n).join("SKILL.md"), format!("---\nname: {n}\n---\n{body}")).unwrap();
        }
        let st = Store::at(&d.join("data"));
        let s = Settings::from_table(&toml::Table::new());
        let r = sync(&s, &st, &b).unwrap();
        assert_eq!(r.added, ["a", "b", "c"]);
        assert!(st.skills.join("cat/a/SKILL.md").is_file(), "category structure kept");
        // Upstream changes a and b; the user edited b and deleted c.
        fs::write(b.join("cat/a/SKILL.md"), "---\nname: a\n---\nA2").unwrap();
        fs::write(b.join("cat/b/SKILL.md"), "---\nname: b\n---\nB2").unwrap();
        fs::write(st.skills.join("cat/b/SKILL.md"), "---\nname: b\n---\nmine").unwrap();
        fs::remove_dir_all(st.skills.join("cat/c")).unwrap();
        let r = sync(&s, &st, &b).unwrap();
        assert_eq!((r.updated.clone(), r.skipped_modified.clone(), r.skipped_deleted.clone()), (vec!["a".to_string()], vec!["b".to_string()], vec!["c".to_string()]));
        assert!(fs::read_to_string(st.skills.join("cat/a/SKILL.md")).unwrap().contains("A2"));
        assert_eq!(list_modified(&st, &b).len(), 1);
        let df = diff(&st, &b, "b").unwrap();
        assert!(df[0].2.contains("-B2") && df[0].2.contains("+mine"), "{df:?}");
        assert!(reset(&st, &b, "b", true).unwrap().contains("restored"));
        assert!(fs::read_to_string(st.skills.join("cat/b/SKILL.md")).unwrap().contains("B2"));
        // Upstream removal leaves the manifest once no copy remains.
        fs::remove_dir_all(b.join("cat/c")).unwrap();
        assert_eq!(sync(&s, &st, &b).unwrap().removed_from_manifest, ["c"]);
        assert!(opt_out(&st, &b, true, true).unwrap().contains("removed 2"));
        assert!(sync(&s, &st, &b).unwrap().added.is_empty() && !st.skills.join("cat/a").exists());
        opt_out(&st, &b, false, false).unwrap();
        assert_eq!(sync(&s, &st, &b).unwrap().added, ["a", "b"]);
        assert!(line_diff("x\ny", "x\nz").contains("-y\n+z"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rename_recovery_v1_migration_backup_and_descriptions() {
        let d = std::env::temp_dir().join(format!("ark-sync2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let b = d.join("bundled");
        for (n, body) in [("x", "X1"), ("y", "Y1"), ("z", "Z1")] {
            fs::create_dir_all(b.join("cat").join(n)).unwrap();
            fs::write(b.join("cat").join(n).join("SKILL.md"), format!("---\nname: {n}\n---\n{body}")).unwrap();
        }
        fs::write(b.join("cat/DESCRIPTION.md"), "Cat skills").unwrap();
        let st = Store::at(&d.join("data"));
        let s = Settings::from_table(&toml::Table::new());
        assert_eq!(sync(&s, &st, &b).unwrap().added, ["x", "y", "z"]);
        assert_eq!(fs::read_to_string(st.skills.join("cat/DESCRIPTION.md")).unwrap(), "Cat skills", "category descriptions are seeded");
        // A v1 manifest line (plain name, no hash) plus a hand-edited copy: never overwritten.
        let man = read_manifest(&st);
        let mut v1: String = man.iter().filter(|(k, _)| k.as_str() != "y").map(|(k, v)| format!("{k}:{v}\n")).collect();
        v1.push_str("y\n");
        fs::write(st.manifest(), v1).unwrap();
        fs::write(st.skills.join("cat/y/SKILL.md"), "---\nname: y\n---\nmine").unwrap();
        // An interrupted update left the only copy in `z.bak`.
        fs::rename(st.skills.join("cat/z"), st.skills.join("cat/z.bak")).unwrap();
        // Upstream recategorised x: `cat/x` → `other/x`.
        fs::create_dir_all(b.join("other")).unwrap();
        fs::rename(b.join("cat/x"), b.join("other/x")).unwrap();
        fs::write(b.join("cat/y/SKILL.md"), "---\nname: y\n---\nY2").unwrap();

        let r = sync(&s, &st, &b).unwrap();
        // `x` moves with its category; `z` comes back from its orphaned `.bak` (still named z there).
        assert_eq!(r.relocated, ["z", "x"], "{r:?}");
        assert!(st.skills.join("other/x/SKILL.md").is_file() && !st.skills.join("cat/x").exists(), "the pristine copy moved with the category");
        assert!(st.skills.join("cat/z/SKILL.md").is_file() && !st.skills.join("cat/z.bak").exists(), "an orphaned .bak is recovered, not read as user-deleted");
        assert_eq!(fs::read_to_string(st.skills.join("cat/y/SKILL.md")).unwrap(), "---\nname: y\n---\nmine", "a v1 entry never clobbers the user's copy");
        assert_eq!(read_manifest(&st)["y"], dir_hash(&st.skills.join("cat/y")), "the v1 entry is baselined from the user's copy");

        // An opted-out profile seeds only the essentials and never cleans the manifest.
        fs::write(st.no_bundled_marker(), "").unwrap();
        let before = read_manifest(&st);
        let r = sync(&s, &st, &b).unwrap();
        assert!(r.essential_only && r.added.is_empty() && r.removed_from_manifest.is_empty(), "{r:?}");
        assert_eq!(read_manifest(&st), before, "an opted-out sync leaves the manifest alone");
        assert!(ESSENTIAL_SKILLS.contains(&"ark-agent"));
        let _ = fs::remove_dir_all(&d);
    }
}
