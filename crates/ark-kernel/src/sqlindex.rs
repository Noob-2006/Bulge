//! The SQLite index (`<data>/index.db`, BATCH-next §6): one schema for everything ark
//! searches — session messages (FTS5), tool results (FTS5, for retrieval instead of
//! carrying old outputs in every request), memory-note chunks and their vectors, and the
//! long-term memory table (content, source, trust, created, last used).
//!
//! The database is an **index, never the source of truth**. Every row is derived from files
//! that stay authoritative: `sessions/<id>/events.jsonl` (append-only, auditable),
//! `memory/**/*.md` and `memory/memories.jsonl` (the long-term memory ledger). Each source is
//! synced incrementally (byte cursors for append-only logs, mtime/size/hash for notes), so a
//! lost, corrupt or outdated database is rebuilt by deleting its rows and syncing again
//! (`ark index rebuild`). A schema version mismatch or an unreadable file triggers that
//! automatically on open.
//!
//! `rusqlite` is built with `bundled` (SQLite compiled in statically): no system libsqlite3,
//! so the musl static binary and old distributions are unaffected.

use crate::event::{Event, EventKind};
use ark_core::{Block, Message, Role};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Bump when the schema changes: an index of another version is dropped and rebuilt.
pub const SCHEMA_VERSION: i64 = 1;
pub const FILE: &str = "index.db";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- Sessions (source: sessions/<id>/events.jsonl). `bytes` is how far the log has been read.
CREATE TABLE IF NOT EXISTS session_cursor(session TEXT PRIMARY KEY, bytes INTEGER NOT NULL, title TEXT, updated_ms INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, session TEXT NOT NULL, seq INTEGER NOT NULL, ts INTEGER NOT NULL, role TEXT NOT NULL, text TEXT NOT NULL, UNIQUE(session, seq));
CREATE INDEX IF NOT EXISTS messages_ts ON messages(ts);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(text, content='messages', content_rowid='id', tokenize='trigram');
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN INSERT INTO messages_fts(rowid, text) VALUES (new.id, new.text); END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN INSERT INTO messages_fts(messages_fts, rowid, text) VALUES ('delete', old.id, old.text); END;
CREATE TABLE IF NOT EXISTS rewinds(session TEXT NOT NULL, from_seq INTEGER NOT NULL, at_seq INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rewinds_session ON rewinds(session);

-- Tool results (source: the same logs plus spilled artifact files): the full output behind
-- every clipped or spilled result, retrievable by id or by text.
CREATE TABLE IF NOT EXISTS tool_results(id INTEGER PRIMARY KEY, session TEXT NOT NULL, seq INTEGER NOT NULL, tool_use_id TEXT NOT NULL, tool TEXT NOT NULL DEFAULT '', is_error INTEGER NOT NULL DEFAULT 0, text TEXT NOT NULL, UNIQUE(session, tool_use_id));
CREATE VIRTUAL TABLE IF NOT EXISTS tool_results_fts USING fts5(text, content='tool_results', content_rowid='id', tokenize='trigram');
CREATE TRIGGER IF NOT EXISTS tool_results_ai AFTER INSERT ON tool_results BEGIN INSERT INTO tool_results_fts(rowid, text) VALUES (new.id, new.text); END;
CREATE TRIGGER IF NOT EXISTS tool_results_ad AFTER DELETE ON tool_results BEGIN INSERT INTO tool_results_fts(tool_results_fts, rowid, text) VALUES ('delete', old.id, old.text); END;
CREATE TRIGGER IF NOT EXISTS tool_results_au AFTER UPDATE ON tool_results BEGIN INSERT INTO tool_results_fts(tool_results_fts, rowid, text) VALUES ('delete', old.id, old.text); INSERT INTO tool_results_fts(rowid, text) VALUES (new.id, new.text); END;

-- Memory notes and knowledge files (source: memory/**/*.md, [memory.search] extra_paths,
-- session transcripts when the `sessions` corpus is on), chunked for hybrid search.
CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, source TEXT NOT NULL, mtime_ms INTEGER NOT NULL, size INTEGER NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, path TEXT NOT NULL, ord INTEGER NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, text TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS chunks_path ON chunks(path);
-- Embedding cache: `provider/model|content hash` → little-endian f32 BLOB (brute-force cosine).
CREATE TABLE IF NOT EXISTS vectors(key TEXT PRIMARY KEY, vec BLOB NOT NULL);

-- Long-term memory items (source: memory/memories.jsonl, MEMORY.md / USER.md entries).
-- trust: user | agent | external | tainted | quarantined (see ark-memory trust.rs).
CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY, text TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'other', source TEXT NOT NULL, trust TEXT NOT NULL, importance REAL NOT NULL DEFAULT 0.7, created_ms INTEGER NOT NULL, last_used_ms INTEGER NOT NULL DEFAULT 0, use_count INTEGER NOT NULL DEFAULT 0, origin TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', vec BLOB, flagged TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS memories_source ON memories(source);
"#;

/// Tables cleared by a rebuild (everything but `meta`'s version row).
const DERIVED: &[&str] = &["session_cursor", "messages", "rewinds", "tool_results", "files", "chunks", "vectors", "memories"];

type Shared = Arc<Mutex<Connection>>;

fn pool() -> &'static Mutex<HashMap<PathBuf, Shared>> {
    static P: OnceLock<Mutex<HashMap<PathBuf, Shared>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn path(data: &Path) -> PathBuf {
    data.join(FILE)
}

fn remove_db_files(p: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", p.display()));
    }
}

fn connect(p: &Path) -> Result<Connection, rusqlite::Error> {
    let c = Connection::open(p)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(c)
}

fn version(c: &Connection) -> Result<Option<i64>, rusqlite::Error> {
    let has_meta: bool = c.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'", [], |r| r.get::<_, i64>(0)).map(|n| n > 0)?;
    if !has_meta {
        return Ok(None);
    }
    c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0)).optional().map(|v| v.and_then(|s| s.parse().ok()))
}

/// Open (creating or rebuilding as needed) the index of `data`.
fn open_fresh(data: &Path) -> Result<Connection, String> {
    fs::create_dir_all(data).map_err(|e| format!("{}: {e}", data.display()))?;
    let p = path(data);
    let attempt = |p: &Path| -> Result<Connection, rusqlite::Error> {
        let c = connect(p)?;
        match version(&c)? {
            Some(v) if v == SCHEMA_VERSION => {
                c.execute_batch(SCHEMA)?;
                Ok(c)
            }
            Some(_) => Err(rusqlite::Error::InvalidQuery), // other version: rebuilt below
            None => {
                c.execute_batch(SCHEMA)?;
                c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?1)", params![SCHEMA_VERSION.to_string()])?;
                Ok(c)
            }
        }
    };
    match attempt(&p) {
        Ok(c) => Ok(c),
        Err(first) => {
            // Outdated schema or an unreadable file: the index is derived, so start over.
            if p.exists() {
                let keep = PathBuf::from(format!("{}.broken", p.display()));
                let _ = fs::rename(&p, &keep);
                remove_db_files(&p);
            }
            attempt(&p).map_err(|e| format!("index {}: {e} (after: {first})", p.display()))
        }
    }
}

fn shared(data: &Path) -> Result<Shared, String> {
    let mut g = pool().lock().unwrap();
    if let Some(c) = g.get(data) {
        return Ok(c.clone());
    }
    let c = Arc::new(Mutex::new(open_fresh(data)?));
    g.insert(data.to_path_buf(), c.clone());
    Ok(c)
}

/// Run `f` on the (shared, per data dir) connection.
pub fn with<T>(data: &Path, f: impl FnOnce(&mut Connection) -> Result<T, String>) -> Result<T, String> {
    let c = shared(data)?;
    let mut g = c.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut g)
}

pub fn err(e: rusqlite::Error) -> String {
    format!("index: {e}")
}

/// Drop every derived row (other processes keep working on the same file) so the next sync
/// re-reads every source from the start. `ark index rebuild` = this + a full sync.
pub fn clear(data: &Path) -> Result<(), String> {
    with(data, |c| {
        let tx = c.transaction().map_err(err)?;
        for t in DERIVED {
            tx.execute(&format!("DELETE FROM {t}"), []).map_err(err)?;
        }
        tx.execute("DELETE FROM meta WHERE key <> 'schema_version'", []).map_err(err)?;
        tx.commit().map_err(err)
    })
}

pub fn meta_get(c: &Connection, key: &str) -> Option<String> {
    c.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0)).optional().ok().flatten()
}

pub fn meta_set(c: &Connection, key: &str, value: &str) -> Result<(), String> {
    c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?1, ?2)", params![key, value]).map(|_| ()).map_err(err)
}

/// Row counts per table (`ark index status`).
pub fn counts(data: &Path) -> Result<Vec<(String, i64)>, String> {
    with(data, |c| {
        let mut out = Vec::new();
        for t in DERIVED {
            let n: i64 = c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0)).map_err(err)?;
            out.push((t.to_string(), n));
        }
        Ok(out)
    })
}

// ───────────────────────── vectors as BLOBs ─────────────────────────

pub fn vec_to_blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn blob_to_vec(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

// ───────────────────────── sessions ─────────────────────────

/// The searchable text of a message: its text blocks, or `[called a, b]` for a tool-only
/// assistant turn; `None` for messages with neither (tool-result carriers).
pub fn message_text(m: &Message) -> Option<String> {
    let text = m.text();
    if !text.trim().is_empty() {
        return Some(text);
    }
    let tools: Vec<&str> = m.tool_uses().map(|(_, n, _)| n).collect();
    (!tools.is_empty()).then(|| format!("[called {}]", tools.join(", ")))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionSync {
    pub sessions: usize,
    pub read_bytes: u64,
    pub messages: usize,
    pub tool_results: usize,
    pub removed: usize,
}

/// Bring the session tables up to date with `<sessions_root>/*/events.jsonl` (only the bytes
/// appended since the last sync are read).
pub fn sync_sessions(data: &Path, sessions_root: &Path) -> Result<SessionSync, String> {
    let mut ids: Vec<String> = fs::read_dir(sessions_root).map(|rd| rd.flatten().filter(|e| e.path().join("events.jsonl").is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    ids.sort();
    with(data, |c| {
        let mut rep = SessionSync { sessions: ids.len(), ..Default::default() };
        let known: Vec<String> = {
            let mut st = c.prepare("SELECT session FROM session_cursor").map_err(err)?;
            let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(err)?;
            rows.flatten().collect()
        };
        let tx = c.transaction().map_err(err)?;
        for gone in known.iter().filter(|k| !ids.contains(k)) {
            drop_session(&tx, gone)?;
            rep.removed += 1;
        }
        for id in &ids {
            let (m, t, b) = sync_one(&tx, sessions_root, id)?;
            rep.messages += m;
            rep.tool_results += t;
            rep.read_bytes += b;
        }
        tx.commit().map_err(err)?;
        Ok(rep)
    })
}

/// Sync one session only (cheap; used before a lookup in the running session).
pub fn sync_session(data: &Path, sessions_root: &Path, id: &str) -> Result<(), String> {
    with(data, |c| {
        let tx = c.transaction().map_err(err)?;
        sync_one(&tx, sessions_root, id)?;
        tx.commit().map_err(err)
    })
}

fn drop_session(c: &Connection, id: &str) -> Result<(), String> {
    for t in ["messages", "rewinds", "tool_results", "session_cursor"] {
        c.execute(&format!("DELETE FROM {t} WHERE session=?1"), params![id]).map_err(err)?;
    }
    Ok(())
}

fn sync_one(c: &Connection, root: &Path, id: &str) -> Result<(usize, usize, u64), String> {
    let p = root.join(id).join("events.jsonl");
    let Ok(meta) = fs::metadata(&p) else { return Ok((0, 0, 0)) };
    let size = meta.len();
    let cursor: Option<(u64, Option<String>)> = c.query_row("SELECT bytes, title FROM session_cursor WHERE session=?1", params![id], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))).optional().map_err(err)?;
    let (mut from, mut title) = cursor.unwrap_or((0, None));
    if size == from {
        return Ok((0, 0, 0));
    }
    if size < from {
        // The log shrank (crash repair truncated a torn line): re-read it from the start.
        drop_session(c, id)?;
        from = 0;
        title = None;
    }
    let mut f = fs::File::open(&p).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(from)).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    // Only complete lines: a torn tail is picked up by the next sync.
    let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
    let mut tool_names: HashMap<String, String> = HashMap::new();
    let (mut nm, mut nt, mut last_ts) = (0, 0, 0u64);
    for line in buf[..end].split(|b| *b == b'\n') {
        let Ok(s) = std::str::from_utf8(line) else { continue };
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<Event>(s) else { continue };
        last_ts = ev.ts;
        nm += index_event(c, id, &ev, &mut tool_names, &mut title, &mut nt)?;
    }
    let bytes = from + end as u64;
    c.execute(
        "INSERT INTO session_cursor(session, bytes, title, updated_ms) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(session) DO UPDATE SET bytes=excluded.bytes, title=excluded.title, updated_ms=max(updated_ms, excluded.updated_ms)",
        params![id, bytes as i64, title, last_ts as i64],
    )
    .map_err(err)?;
    Ok((nm, nt, end as u64))
}

fn index_event(c: &Connection, id: &str, ev: &Event, tool_names: &mut HashMap<String, String>, title: &mut Option<String>, nt: &mut usize) -> Result<usize, String> {
    match &ev.kind {
        EventKind::Header { title: t, .. } => {
            if t.is_some() {
                *title = t.clone();
            }
        }
        EventKind::Title { title: t } => *title = Some(t.clone()),
        EventKind::Rewind { from_seq, .. } => {
            c.execute("INSERT INTO rewinds(session, from_seq, at_seq) VALUES (?1, ?2, ?3)", params![id, *from_seq as i64, ev.seq as i64]).map_err(err)?;
        }
        EventKind::ToolCalled { tool_use_id, name, .. } => {
            tool_names.insert(tool_use_id.clone(), name.clone());
        }
        EventKind::ToolSettled { tool_use_id, artifact: Some(a), .. } => {
            // The log holds a preview; the artifact file holds the whole output.
            if let Ok(full) = fs::read_to_string(a) {
                c.execute("UPDATE tool_results SET text=?3 WHERE session=?1 AND tool_use_id=?2", params![id, tool_use_id, full]).map_err(err)?;
            }
        }
        EventKind::Message { message, .. } => {
            for (tid, name, _) in message.tool_uses() {
                tool_names.insert(tid.to_string(), name.to_string());
            }
            for b in &message.content {
                if let Block::ToolResult { tool_use_id, content, is_error } = b {
                    let tool = tool_names.get(tool_use_id).cloned().unwrap_or_default();
                    c.execute(
                        "INSERT INTO tool_results(session, seq, tool_use_id, tool, is_error, text) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(session, tool_use_id) DO NOTHING",
                        params![id, ev.seq as i64, tool_use_id, tool, *is_error as i64, content],
                    )
                    .map_err(err)?;
                    *nt += 1;
                }
            }
            if let Some(text) = message_text(message) {
                let role = if message.role == Role::User { "user" } else { "assistant" };
                c.execute("INSERT OR IGNORE INTO messages(session, seq, ts, role, text) VALUES (?1, ?2, ?3, ?4, ?5)", params![id, ev.seq as i64, ev.ts as i64, role, text]).map_err(err)?;
                return Ok(1);
            }
        }
        _ => {}
    }
    Ok(0)
}

#[derive(Debug, Clone, Default)]
pub struct MsgFilter {
    pub session: Option<String>,
    /// None = user and assistant.
    pub roles: Option<Vec<String>>,
    pub after: Option<u64>,
    pub before: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MsgHit {
    pub session: String,
    pub seq: u64,
    pub ts: u64,
    pub role: String,
    pub text: String,
}

/// FTS5 phrase for a literal substring (the trigram tokenizer matches substrings, folded case).
fn fts_phrase(q: &str) -> String {
    format!("\"{}\"", q.replace('"', "\"\""))
}

/// Messages containing `query` (case-insensitive substring; empty = any), newest first.
/// Rewound messages are hidden. Queries of three or more characters go through the FTS5
/// trigram index; shorter ones are filtered row by row.
pub fn search_messages(data: &Path, query: &str, f: &MsgFilter, limit: usize) -> Result<Vec<MsgHit>, String> {
    let q = query.trim().to_lowercase();
    with(data, |c| {
        let mut sql = String::from("SELECT m.session, m.seq, m.ts, m.role, m.text FROM messages m WHERE NOT EXISTS (SELECT 1 FROM rewinds r WHERE r.session=m.session AND r.from_seq<=m.seq AND m.seq<r.at_seq)");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let fts = q.chars().count() >= 3;
        if fts {
            sql.push_str(" AND m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)");
            args.push(fts_phrase(&q).into());
        }
        if let Some(s) = &f.session {
            sql.push_str(" AND m.session = ?");
            args.push(s.clone().into());
        }
        if let Some(roles) = &f.roles {
            sql.push_str(&format!(" AND m.role IN ({})", roles.iter().map(|_| "?").collect::<Vec<_>>().join(",")));
            args.extend(roles.iter().map(|r| r.clone().into()));
        }
        if let Some(a) = f.after {
            sql.push_str(" AND m.ts >= ?");
            args.push((a as i64).into());
        }
        if let Some(b) = f.before {
            sql.push_str(" AND m.ts < ?");
            args.push((b as i64).into());
        }
        sql.push_str(" ORDER BY m.ts DESC, m.seq DESC");
        let mut st = c.prepare(&sql).map_err(err)?;
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| Ok(MsgHit { session: r.get(0)?, seq: r.get::<_, i64>(1)? as u64, ts: r.get::<_, i64>(2)? as u64, role: r.get(3)?, text: r.get(4)? }))
            .map_err(err)?;
        let mut out = Vec::new();
        for h in rows.flatten() {
            if !q.is_empty() && !h.text.to_lowercase().contains(&q) {
                continue;
            }
            out.push(h);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    })
}

/// Indexed title of a session (from its header / latest Title event).
pub fn session_title(data: &Path, id: &str) -> Option<String> {
    with(data, |c| c.query_row("SELECT title FROM session_cursor WHERE session=?1", params![id], |r| r.get::<_, Option<String>>(0)).optional().map(|v| v.flatten()).map_err(err)).ok().flatten()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolHit {
    pub tool_use_id: String,
    pub tool: String,
    pub seq: u64,
    pub is_error: bool,
    pub text: String,
}

/// The full stored output of one tool call.
pub fn tool_result(data: &Path, session: &str, tool_use_id: &str) -> Result<Option<ToolHit>, String> {
    with(data, |c| {
        c.query_row("SELECT tool_use_id, tool, seq, is_error, text FROM tool_results WHERE session=?1 AND tool_use_id=?2", params![session, tool_use_id], |r| {
            Ok(ToolHit { tool_use_id: r.get(0)?, tool: r.get(1)?, seq: r.get::<_, i64>(2)? as u64, is_error: r.get::<_, i64>(3)? != 0, text: r.get(4)? })
        })
        .optional()
        .map_err(err)
    })
}

/// Tool outputs of `session` containing `query` (substring, case-insensitive), newest first.
pub fn search_tool_results(data: &Path, session: &str, query: &str, limit: usize) -> Result<Vec<ToolHit>, String> {
    let q = query.trim().to_lowercase();
    with(data, |c| {
        let fts = q.chars().count() >= 3;
        let sql = if fts {
            "SELECT tool_use_id, tool, seq, is_error, text FROM tool_results WHERE session=?1 AND id IN (SELECT rowid FROM tool_results_fts WHERE tool_results_fts MATCH ?2) ORDER BY seq DESC"
        } else {
            "SELECT tool_use_id, tool, seq, is_error, text FROM tool_results WHERE session=?1 AND ?2 <> '' ORDER BY seq DESC"
        };
        let mut st = c.prepare(sql).map_err(err)?;
        let arg = if fts { fts_phrase(&q) } else { q.clone() };
        let rows = st
            .query_map(params![session, arg], |r| Ok(ToolHit { tool_use_id: r.get(0)?, tool: r.get(1)?, seq: r.get::<_, i64>(2)? as u64, is_error: r.get::<_, i64>(3)? != 0, text: r.get(4)? }))
            .map_err(err)?;
        Ok(rows.flatten().filter(|h| h.text.to_lowercase().contains(&q)).take(limit).collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use ark_core::Message;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            pool().lock().unwrap().remove(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tmp() -> Tmp {
        let d = std::env::temp_dir().join(format!("ark-sqlindex-{}", crate::util::random_hex(8)));
        fs::create_dir_all(d.join("sessions")).unwrap();
        Tmp(d)
    }

    fn header(id: &str) -> EventKind {
        EventKind::Header { version: crate::event::LOG_VERSION, session_id: id.into(), workspace: "/w".into(), model: "m".into(), parent: None, title: Some("first".into()) }
    }
    fn msg(m: Message) -> EventKind {
        EventKind::Message { message: m, usage: None, model: None, inbox: None }
    }

    #[test]
    fn sessions_index_incrementally_and_search_like_the_scan() {
        let t = tmp();
        let mut store = Store::new(t.0.join("sessions"));
        store.sync = false;
        let mut log = store.create(header("s-one")).unwrap();
        log.append(msg(Message::user("我想查詢 Alpha 專案的部署"))).unwrap();
        log.append(msg(Message::assistant("Deploy notes for ALPHA are in ops/"))).unwrap();
        let r = sync_sessions(&t.0, store.root()).unwrap();
        assert_eq!(r.messages, 2);
        // Nothing new: nothing read.
        assert_eq!(sync_sessions(&t.0, store.root()).unwrap().read_bytes, 0);
        let second = log.append(msg(Message::user("second alpha question"))).unwrap();
        log.append(EventKind::Title { title: "renamed".into() }).unwrap();
        assert_eq!(sync_sessions(&t.0, store.root()).unwrap().messages, 1, "only the appended tail is read");
        assert_eq!(session_title(&t.0, "s-one").as_deref(), Some("renamed"));

        let all = search_messages(&t.0, "alpha", &MsgFilter::default(), 10).unwrap();
        assert_eq!(all.len(), 3, "case-insensitive substring over FTS5 trigram: {all:?}");
        assert_eq!(all[0].text, "second alpha question", "newest first");
        let cjk = search_messages(&t.0, "部署", &MsgFilter::default(), 10).unwrap();
        assert_eq!(cjk.len(), 1, "two-character CJK query (below the trigram size) still matches");
        let asst = search_messages(&t.0, "alpha", &MsgFilter { roles: Some(vec!["assistant".into()]), ..Default::default() }, 10).unwrap();
        assert_eq!(asst.len(), 1);

        // A rewind hides the undone messages.
        log.append(EventKind::Rewind { from_seq: second.seq, turns: 1 }).unwrap();
        sync_sessions(&t.0, store.root()).unwrap();
        let after = search_messages(&t.0, "second", &MsgFilter::default(), 10).unwrap();
        assert!(after.is_empty(), "rewound message hidden: {after:?}");

        // The index is derived: clear + resync gives the same answers.
        clear(&t.0).unwrap();
        assert_eq!(search_messages(&t.0, "alpha", &MsgFilter::default(), 10).unwrap().len(), 0);
        sync_sessions(&t.0, store.root()).unwrap();
        assert_eq!(search_messages(&t.0, "alpha", &MsgFilter::default(), 10).unwrap().len(), 2);

        // A deleted session leaves the index.
        drop(log);
        store.remove("s-one").unwrap();
        assert_eq!(sync_sessions(&t.0, store.root()).unwrap().removed, 1);
        assert!(search_messages(&t.0, "alpha", &MsgFilter::default(), 10).unwrap().is_empty());
    }

    #[test]
    fn tool_results_are_stored_whole_and_searchable() {
        let t = tmp();
        let mut store = Store::new(t.0.join("sessions"));
        store.sync = false;
        let mut log = store.create(header("s-two")).unwrap();
        log.append(msg(Message { role: Role::Assistant, content: vec![Block::ToolUse { id: "tu1".into(), name: "shell".into(), input: serde_json::json!({}) }] })).unwrap();
        let big = format!("{}\nerror[E0425]: cannot find value `frobnicate`\n{}", "ok\n".repeat(3000), "done\n".repeat(100));
        log.append(msg(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "tu1".into(), content: big.clone(), is_error: false }] })).unwrap();
        // A spilled result: the log holds a preview, the artifact the whole thing.
        let art = log.artifacts().join("tu2.txt");
        fs::write(&art, "FULL artifact body with needle-xyz inside").unwrap();
        log.append(msg(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "tu2".into(), content: "preview…".into(), is_error: false }] })).unwrap();
        log.append(EventKind::ToolSettled { tool_use_id: "tu2".into(), is_error: false, bytes: 40, artifact: Some(art.display().to_string()), ui_resource: None }).unwrap();
        sync_session(&t.0, store.root(), "s-two").unwrap();
        let r = tool_result(&t.0, "s-two", "tu1").unwrap().unwrap();
        assert_eq!(r.text, big);
        assert_eq!(r.tool, "shell");
        assert!(tool_result(&t.0, "s-two", "tu2").unwrap().unwrap().text.starts_with("FULL artifact"));
        let hits = search_tool_results(&t.0, "s-two", "FROBNICATE", 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(search_tool_results(&t.0, "s-two", "needle-xyz", 5).unwrap()[0].tool_use_id, "tu2");
        // The tool-result carrier messages are not in the message index.
        assert!(search_messages(&t.0, "frobnicate", &MsgFilter::default(), 5).unwrap().is_empty());
    }

    #[test]
    fn outdated_or_corrupt_index_is_rebuilt_on_open() {
        let t = tmp();
        fs::write(path(&t.0), b"this is not a sqlite database at all, just junk bytes......").unwrap();
        with(&t.0, |c| meta_set(c, "k", "v")).unwrap();
        assert!(PathBuf::from(format!("{}.broken", path(&t.0).display())).exists(), "the unreadable file is kept aside");
        pool().lock().unwrap().remove(&t.0);
        // Another schema version: dropped and recreated.
        {
            let c = Connection::open(path(&t.0)).unwrap();
            c.execute("UPDATE meta SET value='999' WHERE key='schema_version'", []).unwrap();
        }
        let v = with(&t.0, |c| Ok(meta_get(c, "schema_version"))).unwrap();
        assert_eq!(v.as_deref(), Some(SCHEMA_VERSION.to_string().as_str()));
        assert_eq!(with(&t.0, |c| Ok(meta_get(c, "k"))).unwrap(), None, "old rows are gone");
    }

    #[test]
    fn blobs_round_trip() {
        let v = vec![0.5f32, -1.25, 3.0];
        assert_eq!(blob_to_vec(&vec_to_blob(&v)), v);
    }
}
