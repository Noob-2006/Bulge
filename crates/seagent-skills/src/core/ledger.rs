//! Per-mutation skill audit ledger with single-edit rollback (Hermes `tools/skill_ledger.py`, MIT).
//!
//! Every skill mutation (agent, curator, user, hub) appends one JSONL entry to
//! `<data>/skills/.curator_ledger.jsonl` with before/after file manifests; file contents are
//! stored content-addressed (sha256, deduped) under `<data>/.curator_backups/blobs/`. It is
//! telemetry, not a gate — appends never fail the caller — except `rollback`, which fails
//! closed: every before-blob must exist before anything changes, and a safety entry of the
//! current state is appended first. Unchanged paths are dropped from entries (delta), and
//! the file is kept under `ledger_max_bytes` by dropping the oldest entries.

use super::settings::{Settings, Store};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".hub", ".archive", ".curator_backups"];
/// Blobs younger than this are never garbage-collected: an in-flight `capture_before` has written
/// them but not yet appended its entry (Hermes `_BLOB_GC_GRACE_SECS`).
const BLOB_GC_GRACE_SECS: u64 = 3600;

pub fn sha256_hex(data: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> i64 {
    seagent_kernel::util::unix_now()
}

/// Store one blob; returns its hash.
fn put_blob(st: &Store, data: &[u8]) -> std::io::Result<String> {
    let h = sha256_hex(data);
    let p = st.blobs().join(&h[..2]).join(&h);
    if !p.exists() {
        fs::create_dir_all(p.parent().unwrap())?;
        seagent_kernel::util::atomic_write(&p, data)?;
    }
    Ok(h)
}

pub fn read_blob(st: &Store, hash: &str) -> Option<Vec<u8>> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let data = fs::read(st.blobs().join(&hash[..2]).join(hash)).ok()?;
    (sha256_hex(&data) == hash).then_some(data)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut es: Vec<_> = rd.flatten().collect();
    es.sort_by_key(|e| e.file_name());
    for e in es {
        let p = e.path();
        let n = e.file_name().to_string_lossy().to_string();
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        if m.is_dir() {
            if !SKIP_DIRS.contains(&n.as_str()) {
                walk(&p, out);
            }
        } else if m.is_file() {
            out.push(p);
        }
    }
}

/// `[{path, sha256}]` for every file under `root` (paths relative to the skills root), each
/// stored as a blob. `[]` when root is missing.
pub fn snapshot(st: &Store, root: &Path) -> std::io::Result<Vec<Value>> {
    let mut files = Vec::new();
    if root.is_dir() {
        walk(root, &mut files);
    } else if root.is_file() {
        files.push(root.to_path_buf());
    }
    let mut v = Vec::new();
    for f in files {
        let data = fs::read(&f)?;
        let h = put_blob(st, &data)?;
        let rel = f.strip_prefix(&st.data).map(|r| r.to_string_lossy().to_string()).unwrap_or_else(|_| f.display().to_string());
        v.push(json!({"path": rel, "sha256": h}));
    }
    Ok(v)
}

/// Drop paths whose hash is identical on both sides.
fn delta(before: Vec<Value>, after: Vec<Value>) -> (Vec<Value>, Vec<Value>) {
    let same = |a: &Value, list: &[Value]| list.iter().any(|b| b["path"] == a["path"] && b["sha256"] == a["sha256"]);
    let b2: Vec<Value> = before.iter().filter(|b| !same(b, &after)).cloned().collect();
    let a2: Vec<Value> = after.iter().filter(|a| !same(a, &before)).cloned().collect();
    // Keep every after-only and before-only path: rollback restores `before` and removes after-only paths.
    (b2, a2)
}

/// Capture before a mutation; None when disabled or the capture failed.
pub fn capture_before(s: &Settings, st: &Store, root: &Path) -> Option<Vec<Value>> {
    if !s.ledger {
        return None;
    }
    snapshot(st, root).ok()
}

/// Append one entry; returns its id (None when disabled or the write failed). Never fails.
// One flat positional call is the ledger's published signature (every call site names the actor /
// action / skill / before / after / note); a struct would churn all of them for no behaviour gain.
#[allow(clippy::too_many_arguments)]
pub fn record(s: &Settings, st: &Store, actor: &str, action: &str, skill: &str, before: Option<Vec<Value>>, after_root: Option<&Path>, note: &str) -> Option<String> {
    if !s.ledger {
        return None;
    }
    let after = match after_root {
        Some(r) => snapshot(st, r).ok()?,
        None => vec![],
    };
    let (b, a) = delta(before.unwrap_or_default(), after);
    let id = format!("{}-{}", now(), seagent_kernel::util::random_hex(4));
    let e = json!({"id": id, "ts": now(), "actor": actor, "action": action, "skill": skill, "before": b, "after": a, "note": note});
    let p = st.ledger();
    fs::create_dir_all(p.parent()?).ok()?;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&p).ok()?;
    writeln!(f, "{e}").ok()?;
    drop(f);
    maintain(s, st);
    Some(id)
}

fn maintain(s: &Settings, st: &Store) {
    if s.ledger_max_bytes == 0 {
        return;
    }
    let p = st.ledger();
    let Ok(text) = fs::read_to_string(&p) else { return };
    if text.len() as u64 <= s.ledger_max_bytes {
        return;
    }
    let lines: Vec<&str> = text.lines().collect();
    let (mut keep, mut size) = (0usize, 0u64);
    for l in lines.iter().rev() {
        let ls = l.len() as u64 + 1;
        if keep > 0 && size + ls > s.ledger_max_bytes {
            break;
        }
        size += ls;
        keep += 1;
    }
    let tail = lines[lines.len() - keep..].join("\n") + "\n";
    let _ = seagent_kernel::util::atomic_write(&p, tail.as_bytes());
}

/// Entries newest first (malformed lines skipped), optionally for one skill.
pub fn list(st: &Store, skill: Option<&str>, limit: usize) -> Vec<Value> {
    let text = fs::read_to_string(st.ledger()).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|e| skill.is_none_or(|s| e["skill"] == s)).take(limit).collect()
}

pub fn get(st: &Store, id: &str) -> Option<Value> {
    list(st, None, usize::MAX).into_iter().find(|e| e["id"] == id)
}

/// Every path must stay under the data dir — a hand-edited ledger must not become a write-anywhere primitive.
fn safe_path(st: &Store, rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|p| p == ".." || p.is_empty()) {
        return Err(format!("unsafe ledger path: {rel}"));
    }
    Ok(st.data.join(rel))
}

/// Restore the before-state of entry `id`. Fails closed.
pub fn rollback(s: &Settings, st: &Store, id: &str) -> Result<String, String> {
    let e = get(st, id).ok_or_else(|| format!("no ledger entry `{id}`"))?;
    let before: Vec<Value> = e["before"].as_array().cloned().unwrap_or_default();
    let after: Vec<Value> = e["after"].as_array().cloned().unwrap_or_default();
    let mut restores = Vec::new();
    for b in &before {
        let p = safe_path(st, b["path"].as_str().unwrap_or(""))?;
        let data = read_blob(st, b["sha256"].as_str().unwrap_or("")).ok_or_else(|| format!("missing blob for {}; nothing was changed", b["path"]))?;
        restores.push((p, data));
    }
    let mut removes = Vec::new();
    for a in &after {
        let rel = a["path"].as_str().unwrap_or("");
        if !before.iter().any(|b| b["path"] == rel) {
            removes.push(safe_path(st, rel)?);
        }
    }
    // Safety entry: the current state of every touched path.
    let mut current = Vec::new();
    for p in restores.iter().map(|r| &r.0).chain(removes.iter()) {
        if p.is_file() {
            let data = fs::read(p).map_err(|e| format!("safety capture failed: {e}"))?;
            let h = put_blob(st, &data).map_err(|e| format!("safety capture failed: {e}"))?;
            current.push(json!({"path": p.strip_prefix(&st.data).unwrap().to_string_lossy(), "sha256": h}));
        }
    }
    let skill = e["skill"].as_str().unwrap_or("");
    let safety = json!({"id": format!("{}-{}", now(), seagent_kernel::util::random_hex(4)), "ts": now(), "actor": "user", "action": "pre-rollback", "skill": skill, "before": current, "after": [], "note": format!("state before rolling back {id}")});
    if s.ledger {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(st.ledger()).map_err(|e| format!("safety entry: {e}"))?;
        writeln!(f, "{safety}").map_err(|e| format!("safety entry: {e}"))?;
    }
    for p in &removes {
        let _ = fs::remove_file(p);
    }
    for (p, data) in &restores {
        fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        seagent_kernel::util::atomic_write(p, data).map_err(|e| e.to_string())?;
    }
    Ok(format!("rolled back {id} ({} {skill}): restored {} file(s), removed {}", e["action"].as_str().unwrap_or(""), restores.len(), removes.len()))
}

/// Rewrite the ledger as compact JSONL (upstream `_compact_ledger_locked`): every parseable entry
/// is re-serialized with before/after paths whose hash matches on both sides dropped, blank and
/// malformed lines are discarded. Ids and append order are kept, so rollback still works.
/// Returns (entries kept, bytes before, bytes after).
pub fn compact(st: &Store) -> Result<(usize, u64, u64), String> {
    let p = st.ledger();
    let text = match fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0, 0)),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let before = text.len() as u64;
    let mut lines: Vec<String> = Vec::new();
    for l in text.lines() {
        if l.trim().is_empty() {
            continue;
        }
        let Ok(mut e) = serde_json::from_str::<Value>(l) else { continue };
        if e["action"] != "pre-rollback" {
            let (b, a) = delta(e["before"].as_array().cloned().unwrap_or_default(), e["after"].as_array().cloned().unwrap_or_default());
            e["before"] = json!(b);
            e["after"] = json!(a);
        }
        lines.push(serde_json::to_string(&e).map_err(|e| e.to_string())?);
    }
    let data = if lines.is_empty() { String::new() } else { lines.join("\n") + "\n" };
    seagent_kernel::util::atomic_write(&p, data.as_bytes()).map_err(|e| e.to_string())?;
    Ok((lines.len(), before, data.len() as u64))
}

/// Delete blobs no entry references; returns (deleted, bytes).
pub fn gc_blobs(st: &Store) -> (usize, u64) {
    let text = match fs::read_to_string(st.ledger()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return (0, 0),
    };
    let mut live = std::collections::HashSet::new();
    for l in text.lines() {
        let Ok(e) = serde_json::from_str::<Value>(l) else { return (0, 0) };
        for side in ["before", "after"] {
            for f in e[side].as_array().into_iter().flatten() {
                if let Some(h) = f["sha256"].as_str() {
                    live.insert(h.to_string());
                }
            }
        }
    }
    let (mut n, mut bytes) = (0, 0);
    let Ok(rd) = fs::read_dir(st.blobs()) else { return (0, 0) };
    for d in rd.flatten() {
        for f in fs::read_dir(d.path()).into_iter().flatten().flatten() {
            let name = f.file_name().to_string_lossy().to_string();
            // Blobs younger than the grace window may belong to a capture that has not appended its
            // entry yet: never collect those (Hermes `_BLOB_GC_GRACE_SECS`).
            let fresh = f.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_none_or(|age| age.as_secs() < BLOB_GC_GRACE_SECS);
            if !live.contains(&name) && !fresh {
                bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                if fs::remove_file(f.path()).is_ok() {
                    n += 1;
                }
            }
        }
    }
    (n, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backdate a blob past `BLOB_GC_GRACE_SECS` so GC may collect it (there is no `filetime` dep).
    fn age_blob(st: &Store, hash: &str) {
        let p = st.blobs().join(&hash[..2]).join(hash);
        let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(BLOB_GC_GRACE_SECS * 2)).unwrap();
    }

    #[test]
    fn record_rollback_and_gc() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-ledger-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        let sk = st.skills.join("deploy");
        fs::create_dir_all(&sk).unwrap();
        fs::write(sk.join("SKILL.md"), "v1").unwrap();
        fs::write(sk.join("notes.md"), "same").unwrap();
        let before = capture_before(&s, &st, &sk);
        fs::write(sk.join("SKILL.md"), "v2").unwrap();
        fs::write(sk.join("extra.md"), "new").unwrap();
        let id = record(&s, &st, "agent", "patch", "deploy", before, Some(&sk), "").unwrap();
        let e = get(&st, &id).unwrap();
        assert_eq!(e["before"].as_array().unwrap().len(), 1, "unchanged notes.md dropped: {e}");
        assert_eq!(e["after"].as_array().unwrap().len(), 2);
        let msg = rollback(&s, &st, &id).unwrap();
        assert!(msg.contains("restored 1") && msg.contains("removed 1"), "{msg}");
        assert_eq!(fs::read_to_string(sk.join("SKILL.md")).unwrap(), "v1");
        assert!(!sk.join("extra.md").exists());
        assert_eq!(list(&st, Some("deploy"), 10)[0]["action"], "pre-rollback");
        // Fail closed on a missing blob, and refuse paths outside the data dir.
        let bad = json!({"id": "x1", "skill": "deploy", "action": "patch", "before": [{"path": "skills/deploy/SKILL.md", "sha256": "0".repeat(64)}], "after": []});
        let mut f = fs::OpenOptions::new().append(true).open(st.ledger()).unwrap();
        writeln!(f, "{bad}").unwrap();
        writeln!(f, "{}", json!({"id": "x2", "skill": "deploy", "before": [], "after": [{"path": "../../etc/passwd", "sha256": "a"}]})).unwrap();
        assert!(rollback(&s, &st, "x1").unwrap_err().contains("missing blob"));
        assert!(rollback(&s, &st, "x2").unwrap_err().contains("unsafe"));
        assert_eq!(fs::read_to_string(sk.join("SKILL.md")).unwrap(), "v1");
        // GC: fresh orphans are held for the in-flight grace window; aged ones go.
        let orphan = put_blob(&st, b"orphan").unwrap();
        assert_eq!(gc_blobs(&st).0, 0, "a fresh unreferenced blob is an in-flight capture");
        age_blob(&st, &orphan);
        assert!(gc_blobs(&st).0 >= 1);
        // Size cap keeps the newest entries.
        let mut small = s.clone();
        small.ledger_max_bytes = 600;
        for i in 0..10 {
            record(&small, &st, "user", "edit", &format!("s{i}"), None, None, "");
        }
        let all = list(&st, None, 100);
        assert!(all.len() < 10 && all[0]["skill"] == "s9");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compact_rewrites_and_gc_keeps_referenced() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-ledger-compact-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let s = Settings::from_table(&toml::Table::new());
        let sk = st.skills.join("deploy");
        fs::create_dir_all(&sk).unwrap();
        fs::write(sk.join("SKILL.md"), "v1").unwrap();
        let before = capture_before(&s, &st, &sk);
        fs::write(sk.join("SKILL.md"), "v2").unwrap();
        let id1 = record(&s, &st, "agent", "patch", "deploy", before, Some(&sk), "").unwrap();
        let before2 = capture_before(&s, &st, &sk);
        fs::write(sk.join("SKILL.md"), "v3").unwrap();
        let id2 = record(&s, &st, "agent", "patch", "deploy", before2, Some(&sk), "").unwrap();
        // Blank and malformed lines are not entries; compaction drops them.
        let mut f = fs::OpenOptions::new().append(true).open(st.ledger()).unwrap();
        write!(f, "\nnot json\n").unwrap();
        drop(f);
        let before_bytes = fs::metadata(st.ledger()).unwrap().len();
        let (n, b, a) = compact(&st).unwrap();
        assert_eq!(n, 2);
        assert_eq!(b, before_bytes);
        assert!(a <= b, "{a} > {b}");
        let ids: Vec<String> = list(&st, None, 10).iter().map(|e| e["id"].as_str().unwrap_or("").to_string()).collect();
        assert_eq!(ids, vec![id2.clone(), id1.clone()], "ids and append order preserved");
        // GC keeps the blobs an entry still points at, and drops unreferenced ones.
        let live = get(&st, &id2).unwrap()["before"][0]["sha256"].as_str().unwrap().to_string();
        let orphan = put_blob(&st, b"orphan-after-compact").unwrap();
        age_blob(&st, &orphan);
        gc_blobs(&st);
        assert!(read_blob(&st, &live).is_some(), "referenced blob survived GC");
        assert!(read_blob(&st, &orphan).is_none(), "an aged orphan is collected");
        assert!(rollback(&s, &st, &id2).unwrap().contains("restored 1"));
        assert_eq!(fs::read_to_string(sk.join("SKILL.md")).unwrap(), "v2");
        let _ = fs::remove_dir_all(&d);
    }
}
