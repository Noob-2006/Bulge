//! The unified long-term memory table (`memories` in `<data>/index.db`, srv-031/042).
//!
//! Before this, long-term memory lived in several unrelated stores: the vector memory's
//! `memory/vector/memories.json`, MEMORY.md / USER.md, the search index's JSON. Now every
//! long-term item is one row of one table with content, category, **source**, **trust**,
//! importance, created, **last used** / use count, origin session and its embedding.
//!
//! Sources of truth stay files, so the table is rebuildable (`ark index rebuild`):
//! * `memory/memories.jsonl` — the append-only ledger of `add` / `forget` / `trust` ops
//!   (vector memory writes, auto-capture, imports, quarantines);
//! * `memory/MEMORY.md`, `memory/USER.md` — mirrored entry by entry (`source = file:<name>`);
//! * the legacy `memory/vector/memories.json` is imported once into the ledger and renamed.
//!
//! Usage statistics (`last_used_ms`, `use_count`) and embeddings are derived data: a
//! rebuild resets the former and re-embeds lazily.

use crate::trust;
use crate::util;
use ark_kernel::sqlindex::{self, blob_to_vec, err, meta_get, meta_set, vec_to_blob};
use ark_kernel::sqlindex::rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MemRow {
    pub id: String,
    pub text: String,
    pub category: String,
    pub source: String,
    pub trust: String,
    pub importance: f64,
    pub created_ms: u64,
    pub last_used_ms: u64,
    pub use_count: u64,
    /// Session that wrote it (empty = none / unknown).
    pub origin: String,
    /// `provider/model` of `vec` (empty = not embedded yet).
    pub model: String,
    pub vec: Vec<f32>,
}

impl MemRow {
    pub fn weight(&self) -> f64 {
        trust::weight(&self.trust)
    }
    /// Mirrored from MEMORY.md / USER.md (already in the system prompt snapshot).
    pub fn is_file_entry(&self) -> bool {
        self.source.starts_with("file:")
    }
}

pub fn ledger_path(data: &Path) -> PathBuf {
    data.join("memory/memories.jsonl")
}

fn legacy_vector(data: &Path) -> PathBuf {
    data.join("memory/vector/memories.json")
}

fn append_ledger(data: &Path, v: &Value) -> Result<(), String> {
    let p = ledger_path(data);
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    f.write_all(format!("{v}\n").as_bytes()).map_err(|e| format!("{}: {e}", p.display()))
}

fn add_op(r: &MemRow) -> Value {
    json!({"op": "add", "id": r.id, "text": r.text, "category": r.category, "source": r.source, "trust": r.trust, "importance": r.importance, "created_ms": r.created_ms, "origin": r.origin})
}

fn insert(c: &Connection, r: &MemRow) -> Result<(), String> {
    let vec = (!r.vec.is_empty()).then(|| vec_to_blob(&r.vec));
    c.execute(
        "INSERT OR IGNORE INTO memories(id, text, category, source, trust, importance, created_ms, last_used_ms, use_count, origin, model, vec) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![r.id, r.text, r.category, r.source, r.trust, r.importance, r.created_ms as i64, r.last_used_ms as i64, r.use_count as i64, r.origin, r.model, vec],
    )
    .map(|_| ())
    .map_err(err)
}

fn apply_op(c: &Connection, v: &Value) -> Result<(), String> {
    let id = v["id"].as_str().unwrap_or_default();
    if id.is_empty() {
        return Ok(());
    }
    match v["op"].as_str() {
        Some("add") => insert(
            c,
            &MemRow {
                id: id.into(),
                text: v["text"].as_str().unwrap_or_default().into(),
                category: v["category"].as_str().unwrap_or("other").into(),
                source: v["source"].as_str().unwrap_or("unknown").into(),
                trust: v["trust"].as_str().unwrap_or(trust::EXTERNAL).into(),
                importance: v["importance"].as_f64().unwrap_or(0.7),
                created_ms: v["created_ms"].as_u64().unwrap_or(0),
                origin: v["origin"].as_str().unwrap_or_default().into(),
                ..Default::default()
            },
        ),
        Some("forget") => c.execute("DELETE FROM memories WHERE id=?1", params![id]).map(|_| ()).map_err(err),
        Some("trust") => c.execute("UPDATE memories SET trust=?2, flagged=?3 WHERE id=?1", params![id, v["trust"].as_str().unwrap_or(trust::QUARANTINED), v["flagged"].as_str().unwrap_or_default()]).map(|_| ()).map_err(err),
        _ => Ok(()),
    }
}

/// Bring the table up to date: legacy import, ledger tail, MEMORY.md / USER.md mirror.
pub fn sync(data: &Path) -> Result<(), String> {
    import_legacy(data)?;
    sqlindex::with(data, |c| {
        let p = ledger_path(data);
        let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        let mut from: u64 = meta_get(c, "ledger_bytes").and_then(|s| s.parse().ok()).unwrap_or(0);
        let tx = c.transaction().map_err(err)?;
        if size < from {
            // The ledger was replaced: replay it from the start.
            tx.execute("DELETE FROM memories WHERE source NOT LIKE 'file:%'", []).map_err(err)?;
            from = 0;
        }
        if size > from {
            let mut f = fs::File::open(&p).map_err(|e| e.to_string())?;
            f.seek(SeekFrom::Start(from)).map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
            for line in String::from_utf8_lossy(&buf[..end]).lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    apply_op(&tx, &v)?;
                }
            }
            meta_set(&tx, "ledger_bytes", &(from + end as u64).to_string())?;
        }
        mirror_files(&tx, data)?;
        tx.commit().map_err(err)
    })
}

/// MEMORY.md / USER.md entries as rows (`source = file:<name>`), re-read when the file changes.
fn mirror_files(c: &Connection, data: &Path) -> Result<(), String> {
    for (file, cat) in [("MEMORY.md", "fact"), ("USER.md", "preference")] {
        let p = data.join("memory").join(file);
        let meta = fs::metadata(&p).ok();
        let stamp = meta.as_ref().map(|m| format!("{}:{}", m.len(), m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0))).unwrap_or_default();
        let key = format!("mirror:{file}");
        if meta_get(c, &key).as_deref() == Some(stamp.as_str()) {
            continue;
        }
        let created = meta.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        let text = fs::read_to_string(&p).unwrap_or_default();
        let source = format!("file:{file}");
        let mut ids = Vec::new();
        for e in text.split(ark_tools::memory_store::SEP).map(str::trim).filter(|e| !e.is_empty()) {
            let id = format!("md:{file}:{}", &util::sha256_hex(e.as_bytes())[..16]);
            insert(c, &MemRow { id: id.clone(), text: e.into(), category: cat.into(), source: source.clone(), trust: trust::AGENT.into(), importance: 0.8, created_ms: created, ..Default::default() })?;
            ids.push(id);
        }
        let existing: Vec<String> = {
            let mut st = c.prepare("SELECT id FROM memories WHERE source=?1").map_err(err)?;
            let rows = st.query_map(params![source], |r| r.get::<_, String>(0)).map_err(err)?;
            rows.flatten().collect()
        };
        for id in existing.iter().filter(|i| !ids.contains(i)) {
            c.execute("DELETE FROM memories WHERE id=?1", params![id]).map_err(err)?;
        }
        meta_set(c, &key, &stamp)?;
    }
    Ok(())
}

/// One-time migration of `memory/vector/memories.json` (the old vector store): rows go to the
/// ledger (with their vectors straight into the table) and the file is renamed `.imported`.
fn import_legacy(data: &Path) -> Result<usize, String> {
    let p = legacy_vector(data);
    let Some(v) = util::read_json(&p) else { return Ok(0) };
    let rows: Vec<Value> = v.as_array().cloned().unwrap_or_default();
    let mut n = 0;
    sqlindex::with(data, |c| {
        for r in &rows {
            let row = MemRow {
                id: r["id"].as_str().unwrap_or_default().into(),
                text: r["text"].as_str().unwrap_or_default().into(),
                category: r["category"].as_str().unwrap_or("other").into(),
                source: "legacy:vector".into(),
                trust: trust::AGENT.into(),
                importance: r["importance"].as_f64().unwrap_or(0.7),
                created_ms: r["created_ms"].as_u64().unwrap_or(0),
                model: r["model"].as_str().unwrap_or_default().into(),
                vec: r["vector"].as_array().map(|a| a.iter().filter_map(Value::as_f64).map(|x| x as f32).collect()).unwrap_or_default(),
                ..Default::default()
            };
            if row.id.is_empty() || row.text.trim().is_empty() {
                continue;
            }
            append_ledger(data, &add_op(&row))?;
            insert(c, &row)?;
            n += 1;
        }
        Ok(())
    })?;
    fs::rename(&p, p.with_extension("json.imported")).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(n)
}

/// Record a new memory: ledger first (the source of truth), then the table.
pub fn add(data: &Path, r: &MemRow) -> Result<(), String> {
    append_ledger(data, &add_op(r))?;
    sqlindex::with(data, |c| insert(c, r))
}

pub fn forget(data: &Path, id: &str) -> Result<bool, String> {
    let n = sqlindex::with(data, |c| c.execute("DELETE FROM memories WHERE id=?1 AND source NOT LIKE 'file:%'", params![id]).map_err(err))?;
    if n > 0 {
        append_ledger(data, &json!({"op": "forget", "id": id}))?;
    }
    Ok(n > 0)
}

/// Quarantine a row that failed the read-time scan (kept in the ledger so a rebuild keeps it).
pub fn quarantine(data: &Path, id: &str, findings: &[String]) -> Result<(), String> {
    let flagged = findings.join(",");
    if !id.starts_with("md:") {
        append_ledger(data, &json!({"op": "trust", "id": id, "trust": trust::QUARANTINED, "flagged": flagged}))?;
    }
    sqlindex::with(data, |c| c.execute("UPDATE memories SET trust=?2, flagged=?3 WHERE id=?1", params![id, trust::QUARANTINED, flagged]).map(|_| ()).map_err(err))
}

pub fn set_vec(data: &Path, id: &str, model: &str, v: &[f32]) -> Result<(), String> {
    sqlindex::with(data, |c| c.execute("UPDATE memories SET model=?2, vec=?3 WHERE id=?1", params![id, model, vec_to_blob(v)]).map(|_| ()).map_err(err))
}

/// Recall bookkeeping: `last_used_ms` / `use_count` of the rows handed to the model.
pub fn touch(data: &Path, ids: &[&str], now: u64) {
    let _ = sqlindex::with(data, |c| {
        for id in ids {
            c.execute("UPDATE memories SET last_used_ms=?2, use_count=use_count+1 WHERE id=?1", params![id, now as i64]).map_err(err)?;
        }
        Ok(())
    });
}

pub fn all(data: &Path) -> Result<Vec<MemRow>, String> {
    sqlindex::with(data, |c| {
        let mut st = c.prepare("SELECT id, text, category, source, trust, importance, created_ms, last_used_ms, use_count, origin, model, vec FROM memories ORDER BY created_ms, id").map_err(err)?;
        let rows = st
            .query_map([], |r| {
                Ok(MemRow {
                    id: r.get(0)?,
                    text: r.get(1)?,
                    category: r.get(2)?,
                    source: r.get(3)?,
                    trust: r.get(4)?,
                    importance: r.get(5)?,
                    created_ms: r.get::<_, i64>(6)? as u64,
                    last_used_ms: r.get::<_, i64>(7)? as u64,
                    use_count: r.get::<_, i64>(8)? as u64,
                    origin: r.get(9)?,
                    model: r.get(10)?,
                    vec: r.get::<_, Option<Vec<u8>>>(11)?.map(|b| blob_to_vec(&b)).unwrap_or_default(),
                })
            })
            .map_err(err)?;
        Ok(rows.flatten().collect())
    })
}

pub fn get(data: &Path, id: &str) -> Option<MemRow> {
    all(data).ok()?.into_iter().find(|r| r.id == id)
}

/// Count per trust level (status output).
pub fn trust_counts(data: &Path) -> Vec<(String, i64)> {
    sqlindex::with(data, |c| {
        let mut st = c.prepare("SELECT trust, count(*) FROM memories GROUP BY trust ORDER BY trust").map_err(err)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(err)?;
        Ok(rows.flatten().collect())
    })
    .unwrap_or_default()
}

/// Was the memory with this id flagged? (tests, diagnostics)
pub fn flagged(data: &Path, id: &str) -> Option<String> {
    sqlindex::with(data, |c| c.query_row("SELECT flagged FROM memories WHERE id=?1", params![id], |r| r.get::<_, String>(0)).optional().map_err(err)).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_is_the_truth_and_the_table_rebuilds_from_it() {
        let h = crate::test_host("memstore", |_| {});
        let d = h.data.clone();
        // Legacy vector store: imported once, vectors kept.
        fs::create_dir_all(d.join("memory/vector")).unwrap();
        fs::write(legacy_vector(&d), json!([{"id": "old1", "text": "likes green tea", "vector": [1.0, 0.0], "importance": 0.5, "category": "preference", "created_ms": 5, "model": "local/hash"}]).to_string()).unwrap();
        fs::write(d.join("memory/MEMORY.md"), "uses cargo nextest\n§\nprod db is postgres").unwrap();
        sync(&d).unwrap();
        assert!(!legacy_vector(&d).exists() && d.join("memory/vector/memories.json.imported").exists());
        let rows = all(&d).unwrap();
        assert_eq!(rows.len(), 3, "{rows:?}");
        let old = rows.iter().find(|r| r.id == "old1").unwrap();
        assert_eq!((old.source.as_str(), old.trust.as_str(), old.vec.len()), ("legacy:vector", "agent", 2));
        assert_eq!(rows.iter().filter(|r| r.is_file_entry()).count(), 2);

        add(&d, &MemRow { id: "n1".into(), text: "deploys on fridays are banned".into(), category: "decision".into(), source: "memory_store".into(), trust: trust::TAINTED.into(), importance: 0.7, created_ms: 9, origin: "s1".into(), ..Default::default() }).unwrap();
        touch(&d, &["n1"], 42);
        assert_eq!(get(&d, "n1").unwrap().use_count, 1);
        quarantine(&d, "old1", &["x".into()]).unwrap();
        assert!(forget(&d, "n1").unwrap());
        assert!(!forget(&d, "md:MEMORY.md:nope").unwrap());

        // Editing MEMORY.md re-mirrors it.
        fs::write(d.join("memory/MEMORY.md"), "uses cargo nextest").unwrap();
        sync(&d).unwrap();
        assert_eq!(all(&d).unwrap().iter().filter(|r| r.is_file_entry()).count(), 1);

        // Rebuild: drop everything, replay the ledger and the files.
        sqlindex::clear(&d).unwrap();
        assert!(all(&d).unwrap().is_empty());
        sync(&d).unwrap();
        let rows = all(&d).unwrap();
        assert_eq!(rows.len(), 2, "old1 (quarantined) + one MEMORY.md entry; n1 stays forgotten: {rows:?}");
        assert_eq!(get(&d, "old1").unwrap().trust, trust::QUARANTINED, "the quarantine survives a rebuild");
        assert!(get(&d, "old1").unwrap().vec.is_empty(), "embeddings are derived: re-embedded lazily");
        let _ = fs::remove_dir_all(&d);
    }
}
