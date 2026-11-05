//! The memory search index (OpenClaw memory-core, MIT): Markdown chunking (400 tokens /
//! 80 overlap), incremental sync by mtime+size then content hash, BM25 full-text ranking,
//! cosine vector ranking over an on-disk embedding cache, hybrid merge (0.7 / 0.3),
//! temporal decay (30-day half-life, evergreen root files exempt), MMR (λ 0.7) and the
//! min-score selection with lexical fallback. Stored in the SQLite index (`<data>/index.db`,
//! tables `files` / `chunks` / `vectors`, BLOB vectors with brute-force cosine) next to the
//! session FTS and the long-term `memories` table, which this search also ranks (srv-031/034):
//! every candidate is weighted by its source's trust level and re-scanned for threats before
//! it is returned (H8). The JSON index of earlier versions is imported once and removed.

use crate::embed::{self, Embedder, Kind};
use crate::settings::SearchSettings;
use crate::util::{self, sha256_hex, tokens};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::memstore;
use crate::trust;
use ark_kernel::sqlindex::rusqlite::params;
use ark_kernel::sqlindex::{self, blob_to_vec, err, vec_to_blob};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CHARS_PER_TOKEN: usize = 4;
const EMBED_BATCH_MAX_TOKENS: usize = 8000;
/// Sub-directories of `<data>/memory` that are not memory notes.
pub const SKIP_DIRS: &[&str] = &["index", "staging", "wiki", "users", "dreaming", "vector", "events", "active-memory", "flush", "retaindb"];
pub const IMAGE_EXT: &[&str] = &["jpg", "jpeg", "png", "webp", "gif", "heic", "heif"];
pub const AUDIO_EXT: &[&str] = &["mp3", "wav", "ogg", "opus", "m4a", "m2a", "aac", "flac"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Chunk {
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    pub hash: String,
}

/// Split Markdown into line-aligned chunks of ≈`tokens` tokens with `overlap` carried over.
pub fn chunk_markdown(content: &str, tokens_per_chunk: usize, overlap: usize) -> Vec<Chunk> {
    let max_chars = (tokens_per_chunk * CHARS_PER_TOKEN).max(32);
    let overlap_chars = overlap * CHARS_PER_TOKEN;
    let mut chunks = Vec::new();
    let mut cur: Vec<(String, usize)> = Vec::new();
    let mut cur_chars = 0usize;
    let flush = |cur: &[(String, usize)], chunks: &mut Vec<Chunk>| {
        if let (Some(f), Some(l)) = (cur.first(), cur.last()) {
            let text = cur.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join("\n");
            if !text.trim().is_empty() {
                chunks.push(Chunk { start_line: f.1, end_line: l.1, hash: sha256_hex(text.as_bytes()), text });
            }
        }
    };
    for (i, line) in content.split('\n').enumerate() {
        let line_no = i + 1;
        let chars: Vec<char> = line.chars().collect();
        let segments: Vec<String> = if chars.len() > max_chars { chars.chunks(max_chars).map(|c| c.iter().collect()).collect() } else { vec![line.to_string()] };
        for seg in segments {
            let size = seg.chars().count() + 1;
            if cur_chars + size > max_chars && !cur.is_empty() {
                flush(&cur, &mut chunks);
                let window = overlap_chars.min(max_chars.saturating_sub(size));
                let mut kept = Vec::new();
                let mut acc = 0;
                for (t, n) in cur.iter().rev() {
                    let s = t.chars().count() + 1;
                    if acc + s > window {
                        break;
                    }
                    acc += s;
                    kept.insert(0, (t.clone(), *n));
                }
                cur = kept;
                cur_chars = acc;
            }
            cur.push((seg, line_no));
            cur_chars += size;
        }
    }
    flush(&cur, &mut chunks);
    chunks
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileRec {
    source: String,
    mtime_ms: u64,
    size: u64,
    hash: String,
    chunks: Vec<Chunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hit {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub score: f64,
    pub vector_score: f64,
    pub text_score: f64,
    pub snippet: String,
    pub source: String,
}

impl Hit {
    pub fn citation(&self) -> String {
        if self.start_line == self.end_line {
            format!("{}#L{}", self.path, self.start_line)
        } else {
            format!("{}#L{}-L{}", self.path, self.start_line, self.end_line)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncReport {
    pub files: usize,
    pub changed: usize,
    pub removed: usize,
    pub chunks: usize,
    pub embedded: usize,
    pub warnings: Vec<String>,
}

/// One indexable file: display path, absolute path, source, and how to read its text.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub display: String,
    pub abs: PathBuf,
    pub source: String,
}

pub struct Index {
    data: PathBuf,
    files: BTreeMap<String, FileRec>,
    /// `model|chunk hash` → vector.
    vectors: HashMap<String, Vec<f32>>,
    /// Rows to write on the next save.
    dirty: BTreeSet<String>,
    removed: Vec<String>,
    new_vectors: BTreeSet<String>,
}

/// Knowledge documents accepted from `[memory.search] extra_paths` besides Markdown (srv-036).
pub fn knowledge_file(p: &Path) -> bool {
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "md" | "markdown" | "txt" | "text" | "rst" | "org" | "csv" | "html" | "htm" => true,
        // Databases are extractable for `read`, but never knowledge (or the index itself).
        "db" | "sqlite" | "sqlite3" => false,
        _ => ark_tools::documents::is_extractable(p),
    }
}

/// Trust weight of an indexed file: the memory dir is the operator's own (1.0), session
/// transcripts carry model text (agent), extra paths are imported documents (external).
fn file_trust(path: &str, source: &str) -> f64 {
    match source {
        "sessions" => trust::weight(trust::AGENT),
        _ if path.starts_with('/') => trust::weight(trust::EXTERNAL),
        _ => trust::weight(trust::USER),
    }
}

/// Is `display` (relative to the memory root) a dated daily note (`…/YYYY-MM-DD[-x].md`)?
pub fn dated(display: &str) -> Option<u64> {
    let re = regex::Regex::new(r"(?:^|/)(\d{4}-\d{2}-\d{2})(?:-[^/]+)?\.md$").unwrap();
    re.captures(display).and_then(|c| util::parse_day(&c[1]))
}

pub fn modality(p: &Path) -> Option<&'static str> {
    let ext = p.extension()?.to_str()?.to_lowercase();
    if IMAGE_EXT.contains(&ext.as_str()) {
        Some("image")
    } else if AUDIO_EXT.contains(&ext.as_str()) {
        Some("audio")
    } else {
        None
    }
}

pub fn mime_of(p: &Path) -> String {
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg".into(),
        "png" | "webp" | "gif" | "heic" | "heif" => format!("image/{ext}"),
        "mp3" => "audio/mpeg".into(),
        "m4a" | "m2a" => "audio/mp4".into(),
        other => format!("audio/{other}"),
    }
}

/// Sidecar text of a media file: `<file>.txt|.md|.caption`, `<stem>.txt|.md|.srt|.vtt`.
pub fn sidecar(p: &Path) -> String {
    let mut cands = vec![];
    for ext in ["txt", "md", "caption"] {
        cands.push(PathBuf::from(format!("{}.{ext}", p.display())));
    }
    for ext in ["txt", "md", "srt", "vtt", "caption"] {
        cands.push(p.with_extension(ext));
    }
    for c in cands {
        if let Ok(t) = fs::read_to_string(&c) {
            if !t.trim().is_empty() {
                return t;
            }
        }
    }
    String::new()
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>, depth: usize) {
    if depth > 12 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let r = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        if ft.is_dir() {
            if depth == 0 && SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(&e.path(), &r, out, depth + 1);
        } else if ft.is_file() {
            out.push((r, e.path()));
        }
    }
}

/// Every file the configured sources cover.
pub fn source_files(data: &Path, s: &SearchSettings) -> Vec<SourceFile> {
    let mut out = Vec::new();
    let root = data.join("memory");
    if s.sources.iter().any(|x| x == "memory") {
        let mut files = Vec::new();
        walk(&root, "", &mut files, 0);
        for (rel, abs) in files {
            if rel.ends_with(".md") {
                out.push(SourceFile { display: rel, abs, source: "memory".into() });
            } else if s.multimodal.enabled && modality(&abs).is_some_and(|m| s.multimodal.modalities.iter().any(|x| x == "all" || x == m)) {
                out.push(SourceFile { display: rel, abs, source: "media".into() });
            }
        }
        for extra in &s.extra_paths {
            let p = ark_core::tool::expand_home(extra);
            if p.is_dir() {
                let mut files = Vec::new();
                walk(&p, "", &mut files, 1);
                for (_, abs) in files.into_iter().filter(|(_, a)| knowledge_file(a)) {
                    out.push(SourceFile { display: abs.display().to_string(), abs, source: "memory".into() });
                }
            } else if p.is_file() && knowledge_file(&p) {
                out.push(SourceFile { display: p.display().to_string(), abs: p, source: "memory".into() });
            }
        }
    }
    if s.sources.iter().any(|x| x == "sessions") {
        if let Ok(rd) = fs::read_dir(data.join("sessions")) {
            let mut ids: Vec<_> = rd.flatten().filter(|e| e.path().join("events.jsonl").is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            ids.sort();
            for id in ids {
                out.push(SourceFile { display: format!("sessions/{id}"), abs: data.join("sessions").join(&id).join("events.jsonl"), source: "sessions".into() });
            }
        }
    }
    out
}

/// Visible conversation of a session log as `role: text` lines (one per message line).
pub fn session_text(events_jsonl: &str) -> String {
    let mut out = Vec::new();
    for line in events_jsonl.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        if v["type"] != "message" {
            continue;
        }
        let role = v["message"]["role"].as_str().unwrap_or("?");
        let text: Vec<String> = v["message"]["content"].as_array().map(|a| a.iter().filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).map(ark_kernel::lifecycle::strip_fences).collect()).unwrap_or_default();
        let t = text.join(" ");
        let t = t.trim();
        if !t.is_empty() {
            out.push(format!("{role}: {}", util::compact_ws(t)));
        }
    }
    out.join("\n")
}

fn mtime_ms(m: &fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

const VEC_MAGIC: &[u8] = b"ARKVEC1\n";

/// The pre-SQLite cache `<data>/memory/index/vectors.bin` (`ARKVEC1`), for the one-time import.
fn legacy_vectors(dir: &Path) -> HashMap<String, Vec<f32>> {
    let mut vectors = HashMap::new();
    if let Ok(mut f) = fs::File::open(dir.join("vectors.bin")) {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() && buf.starts_with(VEC_MAGIC) {
            let mut i = VEC_MAGIC.len();
            while i + 6 <= buf.len() {
                let klen = u16::from_le_bytes([buf[i], buf[i + 1]]) as usize;
                let dims = u32::from_le_bytes([buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]]) as usize;
                i += 6;
                if i + klen + dims * 4 > buf.len() {
                    break;
                }
                let key = String::from_utf8_lossy(&buf[i..i + klen]).into_owned();
                i += klen;
                vectors.insert(key, blob_to_vec(&buf[i..i + dims * 4]));
                i += dims * 4;
            }
        }
    }
    vectors
}

impl Index {
    pub fn open(data: &Path) -> Index {
        let mut ix = Index { data: data.to_path_buf(), files: BTreeMap::new(), vectors: HashMap::new(), dirty: BTreeSet::new(), removed: vec![], new_vectors: BTreeSet::new() };
        // One-time migration: embeddings from the old JSON/bin index (paid for, so kept);
        // the file list is re-derived by the next sync.
        let legacy = data.join("memory/index");
        if legacy.is_dir() {
            let old = legacy_vectors(&legacy);
            let saved = sqlindex::with(data, |c| {
                let tx = c.transaction().map_err(err)?;
                for (k, v) in &old {
                    tx.execute("INSERT OR IGNORE INTO vectors(key, vec) VALUES (?1, ?2)", params![k, vec_to_blob(v)]).map_err(err)?;
                }
                tx.commit().map_err(err)
            });
            if saved.is_ok() {
                let _ = fs::remove_dir_all(&legacy);
            }
        }
        let loaded = sqlindex::with(data, |c| {
            let mut st = c.prepare("SELECT path, source, mtime_ms, size, hash FROM files").map_err(err)?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, FileRec { source: r.get(1)?, mtime_ms: r.get::<_, i64>(2)? as u64, size: r.get::<_, i64>(3)? as u64, hash: r.get(4)?, chunks: vec![] }))).map_err(err)?;
            let mut files: BTreeMap<String, FileRec> = rows.flatten().collect();
            let mut st = c.prepare("SELECT path, start_line, end_line, text, hash FROM chunks ORDER BY path, ord").map_err(err)?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, Chunk { start_line: r.get::<_, i64>(1)? as usize, end_line: r.get::<_, i64>(2)? as usize, text: r.get(3)?, hash: r.get(4)? }))).map_err(err)?;
            for (p, c) in rows.flatten() {
                if let Some(f) = files.get_mut(&p) {
                    f.chunks.push(c);
                }
            }
            let mut st = c.prepare("SELECT key, vec FROM vectors").map_err(err)?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, blob_to_vec(&r.get::<_, Vec<u8>>(1)?)))).map_err(err)?;
            Ok((files, rows.flatten().collect::<HashMap<_, _>>()))
        });
        match loaded {
            Ok((files, vectors)) => {
                ix.files = files;
                ix.vectors = vectors;
            }
            Err(e) => eprintln!("ark: memory index: {e}; starting empty"),
        }
        ix
    }

    pub fn chunk_count(&self) -> usize {
        self.files.values().map(|f| f.chunks.len()).sum()
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    pub fn vector_count(&self) -> usize {
        self.vectors.len()
    }

    /// Forget the indexed files, chunks and embeddings (the next sync re-reads everything).
    pub fn reset(data: &Path) -> Result<(), String> {
        let d = data.join("memory/index");
        if let Err(e) = fs::remove_dir_all(&d) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("cannot remove {}: {e}", d.display()));
            }
        }
        sqlindex::with(data, |c| {
            for t in ["files", "chunks", "vectors"] {
                c.execute(&format!("DELETE FROM {t}"), []).map_err(err)?;
            }
            Ok(())
        })
    }

    fn save(&mut self, cache_max: usize) -> Result<(), String> {
        if self.vectors.len() > cache_max {
            let live: HashSet<String> = self.files.values().flat_map(|f| f.chunks.iter().map(|c| c.hash.clone())).collect();
            let dead: Vec<String> = self.vectors.keys().filter(|k| !live.contains(k.rsplit('|').next().unwrap_or(""))).cloned().collect();
            for k in &dead {
                self.vectors.remove(k);
                self.new_vectors.remove(k);
            }
            sqlindex::with(&self.data, |c| {
                for k in &dead {
                    c.execute("DELETE FROM vectors WHERE key=?1", params![k]).map_err(err)?;
                }
                Ok(())
            })?;
        }
        if self.dirty.is_empty() && self.removed.is_empty() && self.new_vectors.is_empty() {
            return Ok(());
        }
        let (files, vectors) = (&self.files, &self.vectors);
        let (dirty, removed, new_vectors) = (&self.dirty, &self.removed, &self.new_vectors);
        sqlindex::with(&self.data, |c| {
            let tx = c.transaction().map_err(err)?;
            for p in removed.iter().chain(dirty.iter()) {
                tx.execute("DELETE FROM chunks WHERE path=?1", params![p]).map_err(err)?;
                tx.execute("DELETE FROM files WHERE path=?1", params![p]).map_err(err)?;
            }
            for p in dirty {
                let Some(r) = files.get(p) else { continue };
                tx.execute("INSERT INTO files(path, source, mtime_ms, size, hash) VALUES (?1, ?2, ?3, ?4, ?5)", params![p, r.source, r.mtime_ms as i64, r.size as i64, r.hash]).map_err(err)?;
                for (i, ch) in r.chunks.iter().enumerate() {
                    tx.execute("INSERT INTO chunks(path, ord, start_line, end_line, text, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![p, i as i64, ch.start_line as i64, ch.end_line as i64, ch.text, ch.hash]).map_err(err)?;
                }
            }
            for k in new_vectors {
                if let Some(v) = vectors.get(k) {
                    tx.execute("INSERT OR REPLACE INTO vectors(key, vec) VALUES (?1, ?2)", params![k, vec_to_blob(v)]).map_err(err)?;
                }
            }
            tx.commit().map_err(err)
        })?;
        self.dirty.clear();
        self.removed.clear();
        self.new_vectors.clear();
        Ok(())
    }

    fn text_of(f: &SourceFile) -> Result<String, String> {
        match f.source.as_str() {
            "sessions" => Ok(session_text(&fs::read_to_string(&f.abs).map_err(|e| e.to_string())?)),
            "media" => {
                let label = format!("{} file: {}", if modality(&f.abs) == Some("image") { "Image" } else { "Audio" }, f.display);
                let side = sidecar(&f.abs);
                Ok(if side.is_empty() { label } else { format!("{label}\n{side}") })
            }
            _ => {
                let bytes = fs::read(&f.abs).map_err(|e| e.to_string())?;
                if f.abs.extension().is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm")) {
                    // Confluence / Notion HTML exports.
                    return Ok(ark_tools::documents::html_text(&String::from_utf8_lossy(&bytes)));
                }
                if ark_tools::documents::is_extractable(&f.abs) {
                    // PDF / DOCX / PPTX / HTML / Notion & Confluence exports → text (srv-036).
                    return ark_tools::documents::extract(&f.abs, &bytes);
                }
                String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", f.display))
            }
        }
    }

    /// Bring the index up to date with the sources; embeds new chunks when `embedder` is set.
    pub fn sync(&mut self, data: &Path, s: &SearchSettings, embedder: Option<&dyn Embedder>) -> SyncReport {
        let mut rep = SyncReport::default();
        let files = source_files(data, s);
        let live: HashSet<&str> = files.iter().map(|f| f.display.as_str()).collect();
        let gone: Vec<String> = self.files.keys().filter(|k| !live.contains(k.as_str())).cloned().collect();
        for k in &gone {
            self.files.remove(k);
        }
        rep.removed = gone.len();
        self.removed.extend(gone);
        for f in &files {
            let Ok(meta) = fs::metadata(&f.abs) else { continue };
            if f.source == "media" && meta.len() > s.multimodal.max_file_bytes {
                rep.warnings.push(format!("{}: skipped, {} bytes exceeds multimodal max_file_bytes", f.display, meta.len()));
                continue;
            }
            let (mt, size) = (mtime_ms(&meta), meta.len());
            if let Some(r) = self.files.get(&f.display) {
                if r.mtime_ms == mt && r.size == size && f.source != "media" {
                    continue;
                }
            }
            let text = match Self::text_of(f) {
                Ok(t) => t,
                Err(e) => {
                    rep.warnings.push(format!("{}: {e}", f.display));
                    continue;
                }
            };
            let hash = sha256_hex(text.as_bytes());
            self.dirty.insert(f.display.clone());
            let rec = self.files.entry(f.display.clone()).or_default();
            rec.mtime_ms = mt;
            rec.size = size;
            rec.source = f.source.clone();
            if rec.hash != hash {
                rec.hash = hash;
                rec.chunks = if f.source == "media" {
                    vec![Chunk { start_line: 1, end_line: text.lines().count().max(1), hash: sha256_hex(&[text.as_bytes(), &fs::read(&f.abs).unwrap_or_default()].concat()), text }]
                } else {
                    chunk_markdown(&text, s.chunk_tokens, s.chunk_overlap)
                };
                rep.changed += 1;
            }
        }
        rep.files = self.files.len();
        rep.chunks = self.chunk_count();
        if let Some(e) = embedder {
            let mk = format!("{}/{}", e.id(), e.model());
            let mut todo: Vec<(String, String, String, String)> = Vec::new();
            for (path, r) in &self.files {
                for c in &r.chunks {
                    let key = format!("{mk}|{}", c.hash);
                    if !self.vectors.contains_key(&key) && !todo.iter().any(|t| t.0 == key) {
                        todo.push((key, c.text.clone(), r.source.clone(), path.clone()));
                    }
                }
            }
            let (media, text): (Vec<_>, Vec<_>) = todo.into_iter().partition(|t| t.2 == "media");
            for (key, label, _, path) in media {
                let abs = data.join("memory").join(&path);
                match fs::read(&abs).map_err(|e| e.to_string()).and_then(|b| e.embed_media(&mime_of(&abs), &b, label.lines().next().unwrap_or(""))) {
                    Ok(v) => {
                        self.new_vectors.insert(key.clone());
                        self.vectors.insert(key, v);
                        rep.embedded += 1;
                    }
                    Err(err) => rep.warnings.push(format!("{path}: {err}")),
                }
            }
            let mut batch: Vec<(String, String)> = Vec::new();
            let mut tok = 0;
            let mut batches = Vec::new();
            for (key, t, _, _) in text {
                let est = t.len() / CHARS_PER_TOKEN + 1;
                if !batch.is_empty() && tok + est > EMBED_BATCH_MAX_TOKENS {
                    batches.push(std::mem::take(&mut batch));
                    tok = 0;
                }
                tok += est;
                batch.push((key, t));
            }
            if !batch.is_empty() {
                batches.push(batch);
            }
            for b in batches {
                let texts: Vec<String> = b.iter().map(|x| x.1.clone()).collect();
                match embed::embed_all(e, &texts, Kind::Document, util::RETRY_INDEX) {
                    Ok(vs) => {
                        for ((k, _), v) in b.into_iter().zip(vs) {
                            if !v.is_empty() {
                                self.new_vectors.insert(k.clone());
                                self.vectors.insert(k, v);
                                rep.embedded += 1;
                            }
                        }
                    }
                    Err(err) => {
                        rep.warnings.push(format!("embedding failed; keyword search still works: {err}"));
                        break;
                    }
                }
            }
        }
        if let Err(e) = self.save(s.cache_max_entries) {
            rep.warnings.push(format!("index not saved: {e}"));
        }
        rep
    }

    /// Hybrid search. `sources` restricts to `memory`/`sessions`/`media`/`memories` (empty =
    /// all; `memory` includes media and the long-term `memories` rows).
    #[allow(clippy::too_many_arguments)]
    pub fn search(&self, data: &Path, s: &SearchSettings, query: &str, query_vec: Option<(&str, &[f32])>, max_results: usize, min_score: f64, sources: &[&str], now: u64) -> Vec<Hit> {
        struct Doc<'a> {
            path: &'a str,
            source: &'a str,
            chunk: &'a Chunk,
            trust: f64,
            vec: Option<&'a [f32]>,
            ts: Option<u64>,
        }
        struct Cand<'a> {
            doc: &'a Doc<'a>,
            vs: f64,
            ts: f64,
            kw: bool,
        }
        let allow = |src: &str| sources.is_empty() || sources.contains(&src) || ((src == "media" || src == "memories") && sources.contains(&"memory"));
        let mk = query_vec.map(|(m, _)| m);
        // Long-term memory rows (vector memory, auto-capture, imports) join the same ranking.
        // MEMORY.md / USER.md entries are skipped here: the files themselves are indexed.
        let mem: Vec<(String, Chunk, memstore::MemRow)> = if allow("memories") {
            let _ = memstore::sync(data);
            memstore::all(data)
                .unwrap_or_default()
                .into_iter()
                .filter(|r| !r.is_file_entry() && r.trust != trust::QUARANTINED && !r.text.trim().is_empty())
                .map(|r| (format!("memories/{}", r.id), Chunk { start_line: 1, end_line: 1, text: r.text.clone(), hash: r.id.clone() }, r))
                .collect()
        } else {
            vec![]
        };
        let mut all: Vec<Doc> = self
            .files
            .iter()
            .filter(|(_, r)| allow(&r.source))
            .flat_map(|(p, r)| {
                r.chunks.iter().map(move |c| Doc { path: p.as_str(), source: r.source.as_str(), chunk: c, trust: file_trust(p, &r.source), vec: mk.and_then(|m| self.vectors.get(&format!("{m}|{}", c.hash))).map(|v| v.as_slice()), ts: timestamp(data, p, &r.source, &self.files) })
            })
            .collect();
        all.extend(mem.iter().map(|(p, c, r)| Doc { path: p.as_str(), source: "memories", chunk: c, trust: r.weight(), vec: (Some(r.model.as_str()) == mk && !r.vec.is_empty()).then_some(r.vec.as_slice()), ts: Some(r.created_ms.max(r.last_used_ms)) }));
        if all.is_empty() {
            return vec![];
        }
        let pool = (max_results * s.candidate_multiplier.max(1)).max(max_results);
        // Keyword (BM25, k1 = 1.2, b = 0.75).
        let qt: Vec<String> = {
            let mut seen = HashSet::new();
            tokens(query).into_iter().filter(|t| seen.insert(t.clone())).collect()
        };
        let docs: Vec<Vec<String>> = all
            .iter()
            .map(|d| {
                let mut t = tokens(&d.chunk.text);
                t.extend(tokens(d.path));
                t
            })
            .collect();
        let n = docs.len() as f64;
        let avgdl = docs.iter().map(|d| d.len()).sum::<usize>() as f64 / n.max(1.0);
        let df: HashMap<&str, usize> = qt.iter().map(|q| (q.as_str(), docs.iter().filter(|d| d.iter().any(|t| t == q)).count())).collect();
        let mut kw: Vec<(usize, f64)> = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            let mut sc = 0.0;
            for q in &qt {
                let tf = d.iter().filter(|t| *t == q).count() as f64;
                if tf == 0.0 {
                    continue;
                }
                let dfq = df[q.as_str()] as f64;
                let idf = ((n - dfq + 0.5) / (dfq + 0.5) + 1.0).ln();
                sc += idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * d.len() as f64 / avgdl.max(1.0)));
            }
            if sc > 0.0 {
                kw.push((i, sc / (1.0 + sc)));
            }
        }
        kw.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        kw.truncate(pool);
        if kw.is_empty() {
            // Whole-token matching missed ("flight" vs "flights"). OpenClaw falls back to
            // bounded substring search when the FTS match yields nothing.
            let terms: Vec<String> = qt.iter().filter(|t| t.chars().count() >= 3).cloned().collect();
            for (i, d) in all.iter().enumerate() {
                let t = d.chunk.text.to_lowercase();
                let n = terms.iter().filter(|q| t.contains(q.as_str())).count();
                if n > 0 {
                    kw.push((i, n as f64 / terms.len().max(1) as f64));
                }
            }
            kw.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            kw.truncate(pool);
        }
        // Vector (brute-force cosine over the BLOB vectors).
        let mut vecs: Vec<(usize, f64)> = Vec::new();
        if let Some((_, qv)) = query_vec {
            for (i, d) in all.iter().enumerate() {
                if let Some(v) = d.vec {
                    vecs.push((i, embed::cosine(qv, v).max(0.0)));
                }
            }
            vecs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            vecs.truncate(pool);
        }
        let have_vec = !vecs.is_empty();
        let (vw, tw) = if have_vec { (s.vector_weight, s.text_weight) } else { (0.0, 1.0) };
        let mut by: BTreeMap<usize, Cand> = BTreeMap::new();
        for &(i, v) in &vecs {
            by.insert(i, Cand { doc: &all[i], vs: v, ts: 0.0, kw: false });
        }
        for &(i, t) in &kw {
            let c = by.entry(i).or_insert(Cand { doc: &all[i], vs: 0.0, ts: 0.0, kw: false });
            c.ts = t;
            c.kw = true;
        }
        let half = s.half_life_days.max(0.0001);
        let mut ranked: Vec<(Hit, bool)> = by
            .values()
            .map(|c| {
                let d = c.doc;
                let media_only = d.source == "media" && !c.kw && vw > 0.0;
                let mut score = if media_only { c.vs } else { vw * c.vs + tw * c.ts };
                if s.temporal_decay {
                    if let Some(ts) = d.ts {
                        let age = (now.saturating_sub(ts)) as f64 / util::DAY_MS;
                        score *= (-(std::f64::consts::LN_2 / half) * age).exp();
                    }
                }
                // H8: provenance weighs in (memory notes 1.0, transcripts 0.9, imported
                // documents 0.75, memories written from a tainted context 0.4).
                score *= d.trust;
                let snippet = util::clip(d.chunk.text.trim(), 700);
                (Hit { path: d.path.to_string(), start_line: d.chunk.start_line, end_line: d.chunk.end_line, score, vector_score: c.vs, text_score: c.ts, snippet, source: d.source.to_string() }, c.kw)
            })
            .collect();
        ranked.sort_by(|a, b| b.0.score.partial_cmp(&a.0.score).unwrap().then_with(|| a.0.path.cmp(&b.0.path)).then(a.0.start_line.cmp(&b.0.start_line)));
        if s.mmr {
            ranked = mmr(ranked, s.mmr_lambda);
        }
        // Read-time re-check (srv-035): whatever is about to reach the model is scanned again;
        // a hit is dropped, and a memories row is quarantined for good.
        let clean = |h: &Hit| -> bool {
            let found = trust::recheck(&h.snippet);
            if found.is_empty() {
                return true;
            }
            if let Some(id) = h.path.strip_prefix("memories/") {
                let _ = memstore::quarantine(data, id, &found);
            }
            false
        };
        let mut out: Vec<Hit> = Vec::new();
        for (h, _) in ranked.iter().filter(|(h, _)| h.score >= min_score) {
            if out.len() >= max_results {
                break;
            }
            if clean(h) {
                out.push(h.clone());
            }
        }
        if out.len() < max_results {
            // Lexical fallback: keyword candidates below the threshold fill spare capacity.
            for (h, is_kw) in &ranked {
                if out.len() >= max_results {
                    break;
                }
                if *is_kw && h.score < min_score && (h.vector_score == 0.0 || !have_vec) && !out.iter().any(|o| o.path == h.path && o.start_line == h.start_line) && clean(h) {
                    out.push(h.clone());
                }
            }
        }
        let used: Vec<&str> = out.iter().filter_map(|h| h.path.strip_prefix("memories/")).collect();
        if !used.is_empty() {
            memstore::touch(data, &used, now);
        }
        out
    }

    /// The chunk vector for `hash` under `model_key` (tests, diagnostics).
    pub fn has_vector(&self, model_key: &str, hash: &str) -> bool {
        self.vectors.contains_key(&format!("{model_key}|{hash}"))
    }
}

/// Timestamp for decay: dated notes use their date, root/topic memory files are evergreen,
/// sessions and extra paths use the file mtime.
fn timestamp(data: &Path, path: &str, source: &str, files: &BTreeMap<String, FileRec>) -> Option<u64> {
    if source == "sessions" {
        return files.get(path).map(|r| r.mtime_ms);
    }
    if let Some(d) = dated(path) {
        return Some(d);
    }
    if !path.starts_with('/') {
        return None;
    }
    let _ = data;
    files.get(path).map(|r| r.mtime_ms)
}

/// Maximal marginal relevance (Carbonell & Goldstein): λ·relevance − (1−λ)·max similarity.
fn mmr(items: Vec<(Hit, bool)>, lambda: f64) -> Vec<(Hit, bool)> {
    if items.len() <= 1 || lambda >= 1.0 {
        return items;
    }
    let max = items.iter().map(|i| i.0.score).fold(f64::MIN, f64::max);
    let min = items.iter().map(|i| i.0.score).fold(f64::MAX, f64::min);
    let range = max - min;
    let mut rest: Vec<(f64, f64, (Hit, bool))> = items.into_iter().map(|i| (if range == 0.0 { 1.0 } else { (i.0.score - min) / range }, 0.0, i)).collect();
    let mut out = Vec::new();
    while !rest.is_empty() {
        let mut best = 0;
        let mut best_s = f64::MIN;
        for (j, (rel, sim, it)) in rest.iter().enumerate() {
            let s = lambda * rel - (1.0 - lambda) * sim;
            if s > best_s || (s == best_s && it.0.score > rest[best].2 .0.score) {
                best_s = s;
                best = j;
            }
        }
        let (_, _, picked) = rest.remove(best);
        for r in rest.iter_mut() {
            let s = util::similarity(&r.2 .0.snippet, &picked.0.snippet);
            if s > r.1 {
                r.1 = s;
            }
        }
        out.push(picked);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::LocalHash;

    pub fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-memory-{tag}-{}-{}", std::process::id(), util::now_ms()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("memory")).unwrap();
        d
    }

    #[test]
    fn chunking_respects_budget_and_overlap() {
        let text: String = (1..=100).map(|i| format!("line {i} with some words here")).collect::<Vec<_>>().join("\n");
        let c = chunk_markdown(&text, 50, 10);
        assert!(c.len() > 3);
        for ch in &c {
            assert!(ch.text.chars().count() <= 50 * 4 + 40, "{}", ch.text.len());
        }
        assert!(c[1].start_line <= c[0].end_line, "overlap carries trailing lines");
        assert_eq!(c[0].start_line, 1);
        assert_eq!(c.last().unwrap().end_line, 100);
        let long = "x".repeat(1000);
        assert!(chunk_markdown(&long, 50, 0).len() >= 5, "over-long lines are split");
        assert!(chunk_markdown("\n\n", 50, 0).is_empty());
    }

    #[test]
    fn fts_only_search_with_citations_and_incremental_sync() {
        let d = tmp("fts");
        fs::write(d.join("memory/MEMORY.md"), "prefers Rust\n§\nuses Arch Linux on the laptop").unwrap();
        fs::create_dir_all(d.join("memory/daily")).unwrap();
        fs::write(d.join("memory/daily/2026-10-30.md"), "# Notes\nDeployed the billing service to staging.\nThe flight to Tokyo is on Friday.").unwrap();
        fs::create_dir_all(d.join("memory/staging")).unwrap();
        fs::write(d.join("memory/staging/x.md"), "billing secret staged").unwrap();
        let s = SearchSettings::default();
        let mut ix = Index::open(&d);
        let r = ix.sync(&d, &s, None);
        assert_eq!((r.files, r.changed), (2, 2), "{r:?}");
        let hits = ix.search(&d, &s, "billing deploy", None, 6, 0.35, &[], util::now_ms());
        assert_eq!(hits[0].path, "daily/2026-10-30.md");
        assert!(hits[0].citation().starts_with("daily/2026-10-30.md#L1"));
        assert!(hits.iter().all(|h| !h.path.contains("staging")));
        // Re-sync without changes touches nothing; an edit re-chunks one file.
        let ix2 = Index::open(&d);
        assert_eq!(ix2.chunk_count(), ix.chunk_count());
        let r = ix.sync(&d, &s, None);
        assert_eq!(r.changed, 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(d.join("memory/MEMORY.md"), "prefers Go now").unwrap();
        let r = ix.sync(&d, &s, None);
        assert_eq!(r.changed, 1);
        assert!(ix.search(&d, &s, "Rust", None, 6, 0.35, &[], util::now_ms()).is_empty());
        fs::remove_file(d.join("memory/MEMORY.md")).unwrap();
        assert_eq!(ix.sync(&d, &s, None).removed, 1);
        // Chinese query against CJK text.
        fs::write(d.join("memory/USER.md"), "使用者住在台灣，喜歡喝烏龍茶").unwrap();
        ix.sync(&d, &s, None);
        assert_eq!(ix.search(&d, &s, "烏龍茶", None, 6, 0.0, &[], util::now_ms())[0].path, "USER.md");
    }

    #[test]
    fn vectors_cached_and_hybrid_ranks() {
        let d = tmp("vec");
        fs::write(d.join("memory/MEMORY.md"), "the user prefers aisle seats on long flights").unwrap();
        fs::write(d.join("memory/topics.md"), "kubernetes cluster upgrade notes").unwrap();
        let s = SearchSettings::default();
        let mut ix = Index::open(&d);
        let r = ix.sync(&d, &s, Some(&LocalHash));
        assert_eq!(r.embedded, 2);
        assert_eq!(Index::open(&d).vector_count(), 2, "vectors persisted");
        assert_eq!(ix.sync(&d, &s, Some(&LocalHash)).embedded, 0, "cache hit, nothing re-embedded");
        let q = crate::embed::local_vector("aisle seats flights");
        let hits = ix.search(&d, &s, "aisle seats flights", Some(("local/hash-256", &q)), 6, 0.35, &[], util::now_ms());
        assert_eq!(hits[0].path, "MEMORY.md");
        assert!(hits[0].vector_score > 0.3 && hits[0].text_score > 0.0);
    }

    #[test]
    fn temporal_decay_and_evergreen() {
        let d = tmp("decay");
        fs::create_dir_all(d.join("memory/daily")).unwrap();
        fs::write(d.join("memory/daily/2020-01-01.md"), "espresso machine settings").unwrap();
        fs::write(d.join("memory/MEMORY.md"), "espresso machine settings").unwrap();
        let s = SearchSettings::default();
        let mut ix = Index::open(&d);
        ix.sync(&d, &s, None);
        let hits = ix.search(&d, &s, "espresso machine", None, 6, 0.0, &[], util::now_ms());
        assert_eq!(hits[0].path, "MEMORY.md", "evergreen root file outranks a stale daily note");
        assert!(hits[1].score < hits[0].score / 100.0);
        assert_eq!(dated("notes/2024-02-29-trip.md"), util::parse_day("2024-02-29"));
        assert_eq!(dated("MEMORY.md"), None);
    }

    #[test]
    fn mmr_diversifies_duplicates() {
        let mk = |p: &str, s: f64, t: &str| (Hit { path: p.into(), start_line: 1, end_line: 1, score: s, vector_score: 0.0, text_score: s, snippet: t.into(), source: "memory".into() }, true);
        let out = mmr(vec![mk("a", 1.0, "alpha beta gamma"), mk("b", 0.95, "alpha beta gamma"), mk("c", 0.9, "delta epsilon"), mk("d", 0.5, "zeta")], 0.7);
        assert_eq!(out.iter().map(|h| h.0.path.as_str()).collect::<Vec<_>>(), vec!["a", "c", "b", "d"]);
    }

    #[test]
    fn sessions_and_media_sources() {
        let d = tmp("sess");
        fs::create_dir_all(d.join("sessions/s1")).unwrap();
        fs::write(d.join("sessions/s1/events.jsonl"), [
            r#"{"seq":0,"ts":1,"type":"header","version":1,"session_id":"s1","workspace":"/w","model":"m"}"#,
            r#"{"seq":1,"ts":2,"type":"message","message":{"role":"user","content":[{"type":"text","text":"we decided to use postgres for the ledger"}]}}"#,
            r#"{"seq":2,"ts":3,"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"Noted: postgres."}]}}"#,
        ].join("\n")).unwrap();
        fs::write(d.join("memory/cat.png"), b"\x89PNG").unwrap();
        fs::write(d.join("memory/cat.png.txt"), "a ginger cat sleeping on the keyboard").unwrap();
        let mut s = SearchSettings { sources: vec!["memory".into(), "sessions".into()], ..Default::default() };
        s.multimodal.enabled = true;
        let mut ix = Index::open(&d);
        ix.sync(&d, &s, None);
        let h = ix.search(&d, &s, "postgres ledger", None, 6, 0.0, &["sessions"], util::now_ms());
        assert_eq!(h[0].path, "sessions/s1");
        assert!(h[0].snippet.starts_with("user: we decided"));
        let h = ix.search(&d, &s, "ginger cat", None, 6, 0.0, &["memory"], util::now_ms());
        assert_eq!(h[0].source, "media");
        assert!(h[0].snippet.starts_with("Image file: cat.png"));
        assert!(ix.search(&d, &s, "postgres", None, 6, 0.0, &["memory"], util::now_ms()).is_empty());
    }
}
