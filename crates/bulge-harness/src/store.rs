//! The agent's durable memory in SQLite (PLAN.md: host-side SQLite memory —
//! preferences and lessons, written automatically, retrieved by relevance).
//!
//! One database, `<memory root>/memory.db`, holds the evidence-cited lessons and
//! the two profile surfaces (USER: who the user is and how they want the agent
//! to work; ENV: durable facts about this environment). Lessons are retrieved
//! with SQLite FTS5 and BM25, the cue weighted over the body and the score
//! scaled by confidence; every retrieval is counted (`uses`, `last_used_at`),
//! the inputs to ageing lessons out (CORE.md §5).
//!
//! Text is indexed as terms: Latin words whole, CJK runs as overlapping bigrams
//! (Chinese has no spaces; a bigram index finds 「測試」 inside 「單元測試失敗」).
//!
//! On first open the store imports the earlier markdown memory (`lessons/*.md`,
//! `USER.md`, `MEMORY.md`) in one transaction; those files are left on disk but
//! are no longer read. The database runs in WAL mode with a busy timeout, so the
//! app, the CLI, and scheduled runs can use it at the same time.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use crate::improve::ProfileTarget;
use crate::memory::{self, Lesson};
use crate::profile::{MEMORY_FILE, MEMORY_LIMIT, Profile, Section, USER_FILE, USER_LIMIT};

/// The database file under a memory root.
pub const DB_FILE: &str = "memory.db";
const SCHEMA_VERSION: i64 = 2;
/// Active lessons kept; beyond this the least useful move to the archive
/// table (kept, not deleted, but no longer retrieved).
pub const MAX_LESSONS: usize = 300;
/// A new lesson sharing at least this fraction of its terms with an
/// existing one replaces it instead of piling up beside it.
const MERGE_OVERLAP: f64 = 0.6;
/// Ranking weights for the indexed columns (cue, lesson).
const CUE_WEIGHT: f64 = 2.0;
const BODY_WEIGHT: f64 = 1.0;

pub struct MemoryStore {
    conn: Connection,
}

/// The character limit a profile surface is held to.
pub fn profile_limit(target: ProfileTarget) -> usize {
    match target {
        ProfileTarget::User => USER_LIMIT,
        ProfileTarget::Env => MEMORY_LIMIT,
    }
}

fn target_key(target: ProfileTarget) -> &'static str {
    match target {
        ProfileTarget::User => "user",
        ProfileTarget::Env => "env",
    }
}

fn now_secs() -> i64 {
    i64::try_from(bulge_util::now_secs()).unwrap_or(i64::MAX)
}

fn db_err(error: rusqlite::Error) -> String {
    format!("memory database: {error}")
}

pub use bulge_util::search::terms;
use bulge_util::search::match_expression;

/// What [`MemoryStore::save_lesson`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    New,
    /// Merged into this existing lesson (it said nearly the same).
    Merged(String),
    /// Added; this many old lessons moved to the archive to make room.
    NewArchiving(usize),
}

impl MemoryStore {
    /// Open (creating if needed) the store under `root`, importing the markdown
    /// memory the first time.
    pub fn open(root: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
        let conn = Connection::open(root.join(DB_FILE)).map_err(db_err)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(db_err)?;
        let store = Self { conn };
        store.migrate()?;
        store.import_markdown(root)?;
        Ok(store)
    }

    /// An in-memory store (tests).
    pub fn open_in_memory() -> Result<Self, String> {
        let store = Self { conn: Connection::open_in_memory().map_err(db_err)? };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |row| row.get(0)).map_err(db_err)?;
        if version >= SCHEMA_VERSION {
            return Ok(());
        }
        if version == 1 {
            return self.migrate_v2();
        }
        self.conn
            .execute_batch(
                "BEGIN;
                 CREATE TABLE IF NOT EXISTS lessons (
                     rowid INTEGER PRIMARY KEY,
                     id TEXT NOT NULL UNIQUE,
                     cue TEXT NOT NULL,
                     lesson TEXT NOT NULL,
                     evidence TEXT NOT NULL,
                     confidence REAL NOT NULL,
                     uses INTEGER NOT NULL DEFAULT 0,
                     created_at INTEGER NOT NULL,
                     last_used_at INTEGER
                 );
                 CREATE VIRTUAL TABLE IF NOT EXISTS lessons_fts USING fts5(cue_terms, lesson_terms);
                 CREATE TABLE IF NOT EXISTS profile (
                     target TEXT NOT NULL,
                     position INTEGER NOT NULL,
                     key TEXT NOT NULL,
                     body TEXT NOT NULL,
                     PRIMARY KEY (target, key)
                 );
                 CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )
            .map_err(db_err)?;
        self.migrate_v2()
    }

    /// v2: the lesson archive.
    fn migrate_v2(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "BEGIN;
                 CREATE TABLE IF NOT EXISTS lessons_archive (
                     id TEXT NOT NULL, cue TEXT NOT NULL, lesson TEXT NOT NULL, evidence TEXT NOT NULL,
                     confidence REAL NOT NULL, uses INTEGER NOT NULL, created_at INTEGER NOT NULL,
                     last_used_at INTEGER, archived_at INTEGER NOT NULL, reason TEXT NOT NULL
                 );
                 PRAGMA user_version = 2;
                 COMMIT;",
            )
            .map_err(db_err)
    }

    fn meta(&self, key: &str) -> Result<Option<String>, String> {
        self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get(0)).optional().map_err(db_err)
    }

    /// Problems found while importing the markdown memory (malformed lesson
    /// files are reported here instead of being silently skipped).
    pub fn import_problems(&self) -> Result<Vec<String>, String> {
        Ok(self.meta("import_problems")?.map(|text| text.lines().map(str::to_owned).collect()).unwrap_or_default())
    }

    /// One-time import of `lessons/*.md`, `USER.md` and `MEMORY.md`.
    fn import_markdown(&self, root: &Path) -> Result<(), String> {
        if self.meta("markdown_imported")?.is_some() {
            return Ok(());
        }
        let mut lessons = Vec::new();
        let mut problems = Vec::new();
        if let Ok(entries) = std::fs::read_dir(root.join(memory::LESSONS_DIR)) {
            let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "md")).collect();
            paths.sort();
            for path in paths {
                let Some(id) = path.file_stem().and_then(|s| s.to_str()) else { continue };
                match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|source| memory::parse(id, &source)) {
                    Ok(lesson) => lessons.push(lesson),
                    Err(message) => problems.push(format!("{}: {message}", path.display())),
                }
            }
        }
        let user = Profile::load(&root.join(USER_FILE))?;
        let env = Profile::load(&root.join(MEMORY_FILE))?;

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        for lesson in &lessons {
            self.write_lesson(lesson, Some(lesson.uses))?;
        }
        // Imported as found, even over today's limit: dropping sections on import
        // would lose them silently; the next save is held to the limit.
        self.write_profile(ProfileTarget::User, &user)?;
        self.write_profile(ProfileTarget::Env, &env)?;
        self.conn
            .execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('markdown_imported', ?1)", [now_secs().to_string()])
            .map_err(db_err)?;
        if !problems.is_empty() {
            self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('import_problems', ?1)", [problems.join("\n")]).map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    // ---- lessons ----

    fn write_lesson(&self, lesson: &Lesson, uses: Option<u32>) -> Result<(), String> {
        let existing: Option<(i64, i64)> = self
            .conn
            .query_row("SELECT rowid, uses FROM lessons WHERE id = ?1", [&lesson.id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .map_err(db_err)?;
        let uses = uses.map(i64::from).or(existing.map(|(_, uses)| uses)).unwrap_or(0);
        let rowid = match existing {
            Some((rowid, _)) => {
                self.conn
                    .execute(
                        "UPDATE lessons SET cue = ?2, lesson = ?3, evidence = ?4, confidence = ?5, uses = ?6 WHERE rowid = ?1",
                        params![rowid, lesson.cue.trim(), lesson.lesson.trim(), lesson.evidence.trim(), f64::from(lesson.confidence), uses],
                    )
                    .map_err(db_err)?;
                self.conn.execute("DELETE FROM lessons_fts WHERE rowid = ?1", [rowid]).map_err(db_err)?;
                rowid
            }
            None => {
                self.conn
                    .execute(
                        "INSERT INTO lessons (id, cue, lesson, evidence, confidence, uses, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![lesson.id, lesson.cue.trim(), lesson.lesson.trim(), lesson.evidence.trim(), f64::from(lesson.confidence), uses, now_secs()],
                    )
                    .map_err(db_err)?;
                self.conn.last_insert_rowid()
            }
        };
        self.conn
            .execute(
                "INSERT INTO lessons_fts (rowid, cue_terms, lesson_terms) VALUES (?1, ?2, ?3)",
                params![rowid, terms(&lesson.cue).join(" "), terms(&lesson.lesson).join(" ")],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Add or replace (by id) one lesson. A new lesson that says nearly the
    /// same as an existing one replaces that one (keeping its id, uses and
    /// the higher confidence) instead of piling up. When the store passes
    /// [`MAX_LESSONS`], the least used, longest unused lessons move to the
    /// archive. A lesson missing its cue, body, or evidence is refused.
    pub fn save_lesson(&self, lesson: &Lesson) -> Result<Saved, String> {
        if !lesson.is_well_formed() {
            return Err("lesson is missing cue, lesson, or evidence".into());
        }
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let known: bool = self.conn.query_row("SELECT EXISTS(SELECT 1 FROM lessons WHERE id = ?1)", [&lesson.id], |row| row.get(0)).map_err(db_err)?;
        let saved = match (known, self.near_duplicate(lesson)?) {
            (false, Some(existing)) => {
                let merged = Lesson {
                    id: existing.id.clone(),
                    confidence: lesson.confidence.max(existing.confidence),
                    evidence: format!("{}; earlier: {}", lesson.evidence.trim(), existing.evidence.trim()).chars().take(600).collect(),
                    ..lesson.clone()
                };
                self.write_lesson(&merged, None)?;
                Saved::Merged(existing.id)
            }
            _ => {
                self.write_lesson(lesson, None)?;
                Saved::New
            }
        };
        let archived = self.archive_overflow()?;
        tx.commit().map_err(db_err)?;
        Ok(if archived > 0 && saved == Saved::New { Saved::NewArchiving(archived) } else { saved })
    }

    /// An existing lesson whose terms overlap `lesson`'s by [`MERGE_OVERLAP`].
    fn near_duplicate(&self, lesson: &Lesson) -> Result<Option<Lesson>, String> {
        let text = format!("{} {}", lesson.cue, lesson.lesson);
        let mine: std::collections::HashSet<String> = terms(&text).into_iter().collect();
        if mine.is_empty() {
            return Ok(None);
        }
        let Some(expression) = match_expression(&text) else { return Ok(None) };
        let mut stmt = self
            .conn
            .prepare("SELECT l.id, l.cue, l.lesson, l.evidence, l.confidence, l.uses FROM lessons_fts JOIN lessons l ON l.rowid = lessons_fts.rowid WHERE lessons_fts MATCH ?1 ORDER BY bm25(lessons_fts) LIMIT 5")
            .map_err(db_err)?;
        let candidates = stmt.query_map([expression], Self::lesson_from_row).map_err(db_err)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)?;
        Ok(candidates.into_iter().find(|other| {
            let theirs: std::collections::HashSet<String> = terms(&format!("{} {}", other.cue, other.lesson)).into_iter().collect();
            let shared = mine.intersection(&theirs).count() as f64;
            let union = mine.union(&theirs).count() as f64;
            union > 0.0 && shared / union >= MERGE_OVERLAP
        }))
    }

    /// Move lessons beyond [`MAX_LESSONS`] to the archive: fewest uses
    /// first, then longest unused, then lowest confidence.
    fn archive_overflow(&self) -> Result<usize, String> {
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM lessons", [], |row| row.get(0)).map_err(db_err)?;
        let overflow = (count as usize).saturating_sub(MAX_LESSONS);
        if overflow == 0 {
            return Ok(0);
        }
        let rowids: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT rowid FROM lessons ORDER BY uses ASC, COALESCE(last_used_at, created_at) ASC, confidence ASC LIMIT ?1").map_err(db_err)?;
            stmt.query_map([overflow as i64], |row| row.get(0)).map_err(db_err)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)?
        };
        for rowid in &rowids {
            self.conn
                .execute(
                    "INSERT INTO lessons_archive (id, cue, lesson, evidence, confidence, uses, created_at, last_used_at, archived_at, reason)
                     SELECT id, cue, lesson, evidence, confidence, uses, created_at, last_used_at, ?2, 'over capacity' FROM lessons WHERE rowid = ?1",
                    params![rowid, now_secs()],
                )
                .map_err(db_err)?;
            self.conn.execute("DELETE FROM lessons_fts WHERE rowid = ?1", [rowid]).map_err(db_err)?;
            self.conn.execute("DELETE FROM lessons WHERE rowid = ?1", [rowid]).map_err(db_err)?;
        }
        Ok(rowids.len())
    }

    /// How many lessons are in the archive.
    pub fn archived_count(&self) -> Result<usize, String> {
        self.conn.query_row("SELECT COUNT(*) FROM lessons_archive", [], |row| row.get::<_, i64>(0)).map(|n| n as usize).map_err(db_err)
    }

    pub fn remove_lesson(&self, id: &str) -> Result<bool, String> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let rowid: Option<i64> = self.conn.query_row("SELECT rowid FROM lessons WHERE id = ?1", [id], |row| row.get(0)).optional().map_err(db_err)?;
        if let Some(rowid) = rowid {
            self.conn.execute("DELETE FROM lessons_fts WHERE rowid = ?1", [rowid]).map_err(db_err)?;
            self.conn.execute("DELETE FROM lessons WHERE rowid = ?1", [rowid]).map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(rowid.is_some())
    }

    fn lesson_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lesson> {
        Ok(Lesson {
            id: row.get(0)?,
            cue: row.get(1)?,
            lesson: row.get(2)?,
            evidence: row.get(3)?,
            confidence: row.get::<_, f64>(4)? as f32,
            uses: row.get::<_, i64>(5)?.try_into().unwrap_or(u32::MAX),
        })
    }

    /// Every lesson, by id.
    pub fn lessons(&self) -> Result<Vec<Lesson>, String> {
        let mut stmt = self.conn.prepare("SELECT id, cue, lesson, evidence, confidence, uses FROM lessons ORDER BY id").map_err(db_err)?;
        let rows = stmt.query_map([], Self::lesson_from_row).map_err(db_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
    }

    /// The `k` lessons most relevant to `query`, best first; lessons sharing no
    /// term with the query are left out. Each one returned is counted as used.
    pub fn retrieve(&self, query: &str, k: usize) -> Result<Vec<Lesson>, String> {
        let Some(expression) = match_expression(query) else { return Ok(Vec::new()) };
        // bm25() is lower-is-better (negative); confidence never zeroes a match
        // (floor 0.1) but orders near-ties, as in the earlier ranker.
        let sql = format!(
            "SELECT l.id, l.cue, l.lesson, l.evidence, l.confidence, l.uses
             FROM lessons_fts JOIN lessons l ON l.rowid = lessons_fts.rowid
             WHERE lessons_fts MATCH ?1
             ORDER BY bm25(lessons_fts, {CUE_WEIGHT}, {BODY_WEIGHT}) * (0.1 + 0.9 * l.confidence), l.confidence DESC, l.id
             LIMIT ?2"
        );
        let found = {
            let mut stmt = self.conn.prepare(&sql).map_err(db_err)?;
            let rows = stmt.query_map(params![expression, k as i64], Self::lesson_from_row).map_err(db_err)?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)?
        };
        let now = now_secs();
        for lesson in &found {
            self.conn.execute("UPDATE lessons SET uses = uses + 1, last_used_at = ?2 WHERE id = ?1", params![lesson.id, now]).map_err(db_err)?;
        }
        Ok(found)
    }

    // ---- profile ----

    fn write_profile(&self, target: ProfileTarget, profile: &Profile) -> Result<(), String> {
        let key = target_key(target);
        self.conn.execute("DELETE FROM profile WHERE target = ?1", [key]).map_err(db_err)?;
        for (position, section) in profile.sections.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO profile (target, position, key, body) VALUES (?1, ?2, ?3, ?4)",
                    params![key, position as i64, section.key.trim(), section.body.trim()],
                )
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// One profile surface, in section order.
    pub fn profile(&self, target: ProfileTarget) -> Result<Profile, String> {
        let mut stmt = self.conn.prepare("SELECT key, body FROM profile WHERE target = ?1 ORDER BY position").map_err(db_err)?;
        let rows = stmt.query_map([target_key(target)], |row| Ok(Section { key: row.get(0)?, body: row.get(1)? })).map_err(db_err)?;
        Ok(Profile { sections: rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)? })
    }

    /// Replace a profile surface. Refused, without writing, when it renders over
    /// the surface's character limit — the caller trims first, never silently.
    pub fn save_profile(&self, target: ProfileTarget, profile: &Profile) -> Result<(), String> {
        let limit = profile_limit(target);
        let length = profile.char_len();
        if length > limit {
            return Err(format!("profile is {length} chars, over the {limit}-char limit"));
        }
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        self.write_profile(target, profile)?;
        tx.commit().map_err(db_err)
    }

    /// Remove one section. Always allowed — it only shrinks the surface — so a
    /// profile that is over its limit can still be cleaned up.
    pub fn remove_profile_section(&self, target: ProfileTarget, key: &str) -> Result<bool, String> {
        let removed = self.conn.execute("DELETE FROM profile WHERE target = ?1 AND key = ?2", params![target_key(target), key.trim()]).map_err(db_err)?;
        Ok(removed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lesson(id: &str, cue: &str, body: &str, confidence: f32) -> Lesson {
        Lesson::new(id, cue, body, "seen in job j1", confidence)
    }

    fn ids(found: &[Lesson]) -> Vec<&str> {
        found.iter().map(|l| l.id.as_str()).collect()
    }

    #[test]
    fn terms_split_latin_words_and_cjk_bigrams() {
        assert_eq!(terms("Run cargo-test, 2x!"), ["run", "cargo", "test", "2x"]);
        assert_eq!(terms("單元測試失敗"), ["單元", "元測", "測試", "試失", "失敗"]);
        assert_eq!(terms("用 pytest 跑測試"), ["用", "pytest", "跑測", "測試"]);
    }

    #[test]
    fn retrieval_ranks_cue_over_body_and_counts_uses() {
        let store = MemoryStore::open_in_memory().unwrap();
        store.save_lesson(&lesson("a", "running cargo tests", "use --workspace", 0.9)).unwrap();
        store.save_lesson(&lesson("b", "editing TOML", "cargo manifests need a newline", 0.9)).unwrap();
        store.save_lesson(&lesson("c", "writing docs", "keep it short", 0.9)).unwrap();
        let found = store.retrieve("cargo", 5).unwrap();
        assert_eq!(ids(&found), ["a", "b"]);
        assert!(store.retrieve("nothing relevant", 5).unwrap().is_empty());
        let a = store.lessons().unwrap().into_iter().find(|l| l.id == "a").unwrap();
        assert_eq!(a.uses, 1);
    }

    #[test]
    fn chinese_queries_find_chinese_lessons() {
        let store = MemoryStore::open_in_memory().unwrap();
        store.save_lesson(&lesson("zh", "單元測試失敗時", "先讀第一個錯誤訊息,再一次修完所有偏差", 0.8)).unwrap();
        store.save_lesson(&lesson("en", "csv parsing", "check the header row", 0.8)).unwrap();
        assert_eq!(ids(&store.retrieve("幫我修好測試", 5).unwrap()), ["zh"]);
    }

    #[test]
    fn confidence_orders_equal_matches_and_saving_replaces_by_id() {
        let store = MemoryStore::open_in_memory().unwrap();
        store.save_lesson(&lesson("low", "deploy checklist", "x", 0.2)).unwrap();
        store.save_lesson(&lesson("high", "deploy checklist", "y", 0.9)).unwrap();
        assert_eq!(ids(&store.retrieve("deploy", 5).unwrap()), ["high", "low"]);
        store.save_lesson(&lesson("low", "release notes", "z", 0.2)).unwrap();
        assert_eq!(ids(&store.retrieve("deploy", 5).unwrap()), ["high"], "old index terms are replaced");
        assert_eq!(store.lessons().unwrap().len(), 2);
        assert!(store.remove_lesson("high").unwrap());
        assert!(store.retrieve("deploy", 5).unwrap().is_empty());
    }

    #[test]
    fn query_syntax_is_never_interpreted() {
        let store = MemoryStore::open_in_memory().unwrap();
        store.save_lesson(&lesson("a", "quotes and NEAR", "body", 0.5)).unwrap();
        assert_eq!(ids(&store.retrieve("\"quotes\" AND NEAR( OR *", 5).unwrap()), ["a"]);
        assert!(store.save_lesson(&Lesson::new("bad", "", "x", "y", 0.5)).is_err());
    }

    #[test]
    fn profiles_keep_order_and_respect_limits() {
        let store = MemoryStore::open_in_memory().unwrap();
        let mut profile = Profile::default();
        profile.upsert("lang", "Reply in Traditional Chinese.");
        profile.upsert("style", "Short answers.");
        store.save_profile(ProfileTarget::User, &profile).unwrap();
        assert_eq!(store.profile(ProfileTarget::User).unwrap(), profile);
        assert!(store.profile(ProfileTarget::Env).unwrap().sections.is_empty());
        let mut big = Profile::default();
        big.upsert("x", &"字".repeat(USER_LIMIT + 1));
        assert!(store.save_profile(ProfileTarget::User, &big).is_err());
        assert_eq!(store.profile(ProfileTarget::User).unwrap(), profile, "a refused save writes nothing");
        // Removing a section is allowed even from an over-limit profile.
        store.write_profile(ProfileTarget::Env, &big).unwrap();
        assert!(store.remove_profile_section(ProfileTarget::Env, "x").unwrap());
        assert!(store.profile(ProfileTarget::Env).unwrap().sections.is_empty());
    }

    #[test]
    fn markdown_memory_is_imported_once_and_left_on_disk() {
        let root = std::env::temp_dir().join(format!("bulge-memstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lessons")).unwrap();
        std::fs::write(root.join("lessons/fix-all.md"), memory::render(&lesson("fix-all", "failing tests", "fix every deviation at once", 0.7))).unwrap();
        std::fs::write(root.join("lessons/broken.md"), "no frontmatter").unwrap();
        std::fs::write(root.join(USER_FILE), "## lang\nTraditional Chinese.\n").unwrap();
        std::fs::write(root.join(MEMORY_FILE), "## shell\nOnly dash.\n").unwrap();

        let store = MemoryStore::open(&root).unwrap();
        assert_eq!(ids(&store.lessons().unwrap()), ["fix-all"]);
        assert_eq!(store.import_problems().unwrap().len(), 1);
        assert_eq!(store.profile(ProfileTarget::User).unwrap().get("lang"), Some("Traditional Chinese."));
        assert_eq!(store.profile(ProfileTarget::Env).unwrap().get("shell"), Some("Only dash."));
        store.remove_lesson("fix-all").unwrap();
        drop(store);
        // Reopening does not import again; the markdown files are untouched.
        let store = MemoryStore::open(&root).unwrap();
        assert!(store.lessons().unwrap().is_empty());
        assert!(root.join("lessons/fix-all.md").exists());
    }

    #[test]
    fn near_duplicates_merge_and_overflow_moves_to_the_archive() {
        let store = MemoryStore::open_in_memory().unwrap();
        assert_eq!(store.save_lesson(&lesson("a", "running cargo tests in the workspace", "use cargo test --workspace", 0.6)).unwrap(), Saved::New);
        let again = lesson("b", "running cargo tests in the workspace", "use cargo test --workspace always", 0.9);
        assert_eq!(store.save_lesson(&again).unwrap(), Saved::Merged("a".into()));
        let all = store.lessons().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].lesson, "use cargo test --workspace always", "the newer wording wins");
        assert!((all[0].confidence - 0.9).abs() < 1e-6 && all[0].evidence.contains("earlier:"));
        // An unrelated lesson is its own.
        assert_eq!(store.save_lesson(&lesson("c", "編輯 TOML 檔案", "結尾要有換行", 0.8)).unwrap(), Saved::New);
        for i in 0..MAX_LESSONS {
            store.save_lesson(&lesson(&format!("n{i}"), &format!("topic{i} alpha{i}"), &format!("do thing{i} beta{i}"), 0.5)).unwrap();
        }
        assert_eq!(store.lessons().unwrap().len(), MAX_LESSONS);
        assert_eq!(store.archived_count().unwrap(), 2, "the overflow is archived, not deleted");
    }
}
