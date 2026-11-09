//! Append-only JSONL session store with crash repair and single-writer locking.

use crate::event::{now_ms, Event, EventKind, LOG_VERSION};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    /// Another process holds the session's write lock.
    Locked(String),
    NotFound(String),
    /// A line in the middle of the log does not parse. Never silently skipped.
    Corrupt { line: usize, reason: String },
    Version(u32),
    /// HA fencing (ent-095): this process no longer holds the cluster lease; nothing was written.
    Fenced(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Locked(id) => write!(f, "session {id} is in use by another seagent process"),
            StoreError::NotFound(id) => write!(f, "session {id} not found"),
            StoreError::Corrupt { line, reason } => write!(f, "event log corrupt at line {line}: {reason}"),
            StoreError::Version(v) => write!(f, "event log version {v} is newer than this seagent ({LOG_VERSION})"),
            StoreError::Fenced(why) => write!(f, "write refused by HA fencing: {why}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// A write guard consulted before every append (HA fencing, `crate::ha`). `Err` = refuse.
pub type Fence = std::sync::Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

pub struct Store {
    root: PathBuf,
    /// fsync every append (durability) — on by default; tests may turn it off.
    pub sync: bool,
    /// Set once by an HA daemon / worker: every log opened afterwards checks it per append.
    fence: std::sync::OnceLock<Fence>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub workspace: String,
    pub model: String,
    pub parent: Option<String>,
    pub title: Option<String>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub messages: usize,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub session: String,
    pub seq: u64,
    pub snippet: String,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into(), sync: true, fence: std::sync::OnceLock::new() }
    }
    /// Install the HA fence (first call wins; a store is fenced for the life of the process).
    pub fn set_fence(&self, f: Fence) -> bool {
        self.fence.set(f).is_ok()
    }
    fn check_fence(&self) -> Result<(), StoreError> {
        match self.fence.get() {
            Some(f) => f().map_err(StoreError::Fenced),
            None => Ok(()),
        }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
    pub fn exists(&self, id: &str) -> bool {
        valid_id(id) && self.dir(id).join("events.jsonl").is_file()
    }

    pub fn create(&self, header: EventKind) -> Result<SessionLog, StoreError> {
        let id = match &header {
            EventKind::Header { session_id, .. } => session_id.clone(),
            _ => panic!("create() needs a Header event"),
        };
        if !valid_id(&id) {
            return Err(StoreError::NotFound(id));
        }
        self.check_fence()?;
        let dir = self.dir(&id);
        fs::create_dir_all(dir.join("artifacts"))?;
        let path = dir.join("events.jsonl");
        let file = OpenOptions::new().create_new(true).append(true).read(true).open(&path)?;
        lock(&file, &id)?;
        let mut log = SessionLog { id, dir, file, events: Vec::new(), sync: self.sync, fence: self.fence.get().cloned() };
        log.append(header)?;
        Ok(log)
    }

    pub fn open(&self, id: &str) -> Result<SessionLog, StoreError> {
        if !self.exists(id) {
            return Err(StoreError::NotFound(id.to_string()));
        }
        self.check_fence()?;
        let dir = self.dir(id);
        let path = dir.join("events.jsonl");
        let mut file = OpenOptions::new().read(true).append(true).open(&path)?;
        lock(&file, id)?;
        let events = read_events(&mut file, true)?;
        Ok(SessionLog { id: id.to_string(), dir, file, events, sync: self.sync, fence: self.fence.get().cloned() })
    }

    /// Read without taking the write lock (for listing / display while a session runs).
    pub fn read(&self, id: &str) -> Result<Vec<Event>, StoreError> {
        if !self.exists(id) {
            return Err(StoreError::NotFound(id.to_string()));
        }
        let mut f = File::open(self.dir(id).join("events.jsonl"))?;
        read_events(&mut f, false)
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&self.root) else { return out };
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().to_string();
            let Ok(events) = self.read(&id) else { continue };
            let Some(first) = events.first() else { continue };
            if let EventKind::Header { workspace, model, parent, title, .. } = &first.kind {
                let title = events.iter().rev().find_map(|e| if let EventKind::Title { title } = &e.kind { Some(title.clone()) } else { None }).or_else(|| title.clone());
                out.push(SessionInfo {
                    id,
                    workspace: workspace.clone(),
                    model: model.clone(),
                    parent: parent.clone(),
                    title,
                    created_ms: first.ts,
                    updated_ms: events.last().map(|e| e.ts).unwrap_or(first.ts),
                    messages: events.iter().filter(|e| e.is_message()).count(),
                });
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.updated_ms));
        out
    }

    /// Case-insensitive substring search over message text (works for CJK).
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let q = query.to_lowercase();
        let mut hits = Vec::new();
        if q.trim().is_empty() || limit == 0 {
            return hits;
        }
        // The SQLite index (FTS5, synced from these logs) first; the scan is the fallback.
        if let Some(data) = self.root.parent() {
            if crate::sqlindex::sync_sessions(data, &self.root).is_ok() {
                if let Ok(found) = crate::sqlindex::search_messages(data, query, &crate::sqlindex::MsgFilter::default(), limit) {
                    return found
                        .into_iter()
                        .map(|h| {
                            let lower = h.text.to_lowercase();
                            let pos = lower.find(&q).unwrap_or(0);
                            SearchHit { session: h.session, seq: h.seq, snippet: snippet(&lower, &h.text, pos, q.len()) }
                        })
                        .collect();
                }
            }
        }
        for info in self.list() {
            let Ok(events) = self.read(&info.id) else { continue };
            for ev in events.iter().rev() {
                if let EventKind::Message { message, .. } = &ev.kind {
                    let text = message.text();
                    let lower = text.to_lowercase();
                    if let Some(pos) = lower.find(&q) {
                        hits.push(SearchHit { session: info.id.clone(), seq: ev.seq, snippet: snippet(&lower, &text, pos, q.len()) });
                        if hits.len() >= limit {
                            return hits;
                        }
                    }
                }
            }
        }
        hits
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        let log = self.open(id)?; // refuses while another process holds it
        drop(log);
        fs::remove_dir_all(self.dir(id))?;
        Ok(())
    }
}

fn snippet(lower: &str, orig: &str, pos: usize, qlen: usize) -> String {
    // `lower` and `orig` may differ in byte length for some scripts; fall back to lower.
    let src = if lower.len() == orig.len() { orig } else { lower };
    let mut a = pos.saturating_sub(60);
    while !src.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = (pos + qlen + 60).min(src.len());
    while !src.is_char_boundary(b) {
        b += 1;
    }
    src[a..b].replace('\n', " ")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Take the exclusive write lock. Retries briefly: a forked child (shell tool,
/// git) holds inherited fds until its exec closes them, which would otherwise
/// look like "in use by another process" for a few microseconds.
fn lock(f: &File, id: &str) -> Result<(), StoreError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    loop {
        // `try_lock` is flock(LOCK_EX | LOCK_NB) on Unix; released when the file closes.
        match try_lock_writer(f) {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(err)) => return Err(err.into()),
        }
        if std::time::Instant::now() >= deadline {
            return Err(StoreError::Locked(id.to_string()));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(not(windows))]
fn try_lock_writer(f: &File) -> Result<(), std::fs::TryLockError> {
    f.try_lock()
}

/// Windows byte-range locks are mandatory: `File::try_lock` (the whole file) would stop every
/// other process from *reading* the log while a writer holds it. The writer lock is therefore
/// one byte at the very end of the 64-bit range, which no read or append ever touches: still
/// one exclusive writer per log, readers unaffected. Released when the handle closes.
#[cfg(windows)]
fn try_lock_writer(f: &File) -> Result<(), std::fs::TryLockError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: zeroed OVERLAPPED with the lock offset set; synchronous handle, valid for the call.
    let ok = unsafe {
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.Anonymous.Anonymous.Offset = 0xFFFF_FFFE;
        ov.Anonymous.Anonymous.OffsetHigh = 0x7FFF_FFFF;
        LockFileEx(f.as_raw_handle() as _, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &mut ov)
    };
    if ok != 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error().map(|c| c as u32) {
        Some(ERROR_LOCK_VIOLATION) | Some(ERROR_IO_PENDING) => Err(std::fs::TryLockError::WouldBlock),
        _ => Err(std::fs::TryLockError::Error(e)),
    }
}

/// Parse a log. A torn final line (crash mid-write) is dropped — and truncated
/// from disk when `repair` — but corruption anywhere else is an error.
fn read_events(file: &mut File, repair: bool) -> Result<Vec<Event>, StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(&*file);
    let mut events: Vec<Event> = Vec::new();
    let mut good_len: u64 = 0;
    let mut line_no = 0;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        let complete = buf.last() == Some(&b'\n');
        let text = String::from_utf8_lossy(&buf);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            good_len += n as u64;
            continue;
        }
        match serde_json::from_str::<Event>(trimmed) {
            Ok(ev) if complete => {
                if let EventKind::Header { version, .. } = &ev.kind {
                    if *version > LOG_VERSION {
                        return Err(StoreError::Version(*version));
                    }
                }
                if let Some(prev) = events.last() {
                    if ev.seq != prev.seq + 1 {
                        return Err(StoreError::Corrupt { line: line_no, reason: format!("seq {} after {}", ev.seq, prev.seq) });
                    }
                }
                events.push(ev);
                good_len += n as u64;
            }
            // Incomplete last line, whether or not it happens to parse: torn write.
            _ if !complete => break,
            Err(e) => {
                // A complete but unparseable line is only tolerated if it is the last one.
                let mut rest = Vec::new();
                reader.read_until(b'\n', &mut rest)?;
                if rest.iter().all(|b| b.is_ascii_whitespace()) {
                    break;
                }
                return Err(StoreError::Corrupt { line: line_no, reason: e.to_string() });
            }
            Ok(_) => unreachable!(),
        }
    }
    if repair && file.metadata()?.len() != good_len {
        truncate_to(file, good_len)?;
    }
    Ok(events)
}

#[cfg(not(windows))]
fn truncate_to(file: &File, len: u64) -> std::io::Result<()> {
    file.set_len(len)?;
    file.sync_all()
}

/// Windows: an append-only handle lacks `FILE_WRITE_DATA`, which `SetEndOfFile` needs, so the
/// torn tail is cut through a second handle to the same file (`ReOpenFile`, write access). The
/// writer lock sits at the far end of the range, so it does not get in the way.
#[cfg(windows)]
fn truncate_to(file: &File, len: u64) -> std::io::Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
    // SAFETY: `file` is a valid open handle; a returned handle is owned by the new `File`.
    let h = unsafe { ReOpenFile(file.as_raw_handle() as _, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0) };
    if h == INVALID_HANDLE_VALUE || h == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let w = unsafe { File::from_raw_handle(h as _) };
    w.set_len(len)?;
    w.sync_all()
}

pub struct SessionLog {
    pub id: String,
    pub dir: PathBuf,
    file: File,
    events: Vec<Event>,
    sync: bool,
    fence: Option<Fence>,
}

impl SessionLog {
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn artifacts(&self) -> PathBuf {
        self.dir.join("artifacts")
    }
    pub fn next_seq(&self) -> u64 {
        self.events.last().map(|e| e.seq + 1).unwrap_or(0)
    }
    pub fn append(&mut self, kind: EventKind) -> Result<Event, StoreError> {
        // ent-095: re-checked on every write, so a deposed HA leader that wakes up with a
        // model reply in hand cannot add it to a log the new leader now owns.
        if let Some(f) = &self.fence {
            f().map_err(StoreError::Fenced)?;
        }
        let ev = Event { seq: self.next_seq(), ts: now_ms(), kind };
        let mut line = serde_json::to_vec(&ev).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        if self.sync {
            self.file.sync_data()?;
        }
        self.events.push(ev.clone());
        Ok(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::Message;

    /// A store on a self-removing temp dir. The guard is returned so the caller keeps it alive
    /// for the whole test: `let (_dir, s) = tmp();`. (Previously every run left `seagent-store-*`
    /// behind in the temp directory — 800+ of them on the author's machine.)
    fn tmp() -> (seagent_core::tmp::TempDir, Store) {
        let dir = seagent_core::tmp::TempDir::new("seagent-store");
        // `<data>/sessions`, like a real install: `search` keeps its SQLite index in the parent,
        // which used to be $TMPDIR itself (an `index.db` left behind by every run).
        let mut s = Store::new(dir.path().join("sessions"));
        s.sync = false;
        (dir, s)
    }
    fn header(id: &str) -> EventKind {
        EventKind::Header { version: LOG_VERSION, session_id: id.into(), workspace: "/w".into(), model: "m".into(), parent: None, title: None }
    }
    fn msg(t: &str) -> EventKind {
        EventKind::Message { message: Message::user(t), usage: None, model: None, inbox: None }
    }

    #[test]
    fn create_append_reopen() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("a1")).unwrap();
        log.append(msg("hello 世界")).unwrap();
        drop(log);
        let log = s.open("a1").unwrap();
        assert_eq!(log.events().len(), 2);
        assert_eq!(log.next_seq(), 2);
        assert_eq!(s.list()[0].messages, 1);
    }

    #[test]
    fn fenced_store_refuses_writes_and_writes_nothing() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("f1")).unwrap();
        let ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let o2 = ok.clone();
        // Logs opened before the fence was installed are not retrofitted; new ones are.
        assert!(s.set_fence(std::sync::Arc::new(move || if o2.load(std::sync::atomic::Ordering::SeqCst) { Ok(()) } else { Err("node b holds epoch 2".into()) })));
        log.append(msg("before")).unwrap();
        drop(log);
        let mut log = s.open("f1").unwrap();
        log.append(msg("leader")).unwrap();
        ok.store(false, std::sync::atomic::Ordering::SeqCst);
        match log.append(msg("stale")) {
            Err(StoreError::Fenced(w)) => assert!(w.contains("epoch 2")),
            other => panic!("expected Fenced, got {other:?}"),
        }
        drop(log);
        assert!(matches!(s.open("f1"), Err(StoreError::Fenced(_))), "a fenced node cannot even open for writing");
        let texts: Vec<String> = s.read("f1").unwrap().iter().filter_map(|e| if let EventKind::Message { message, .. } = &e.kind { Some(message.text()) } else { None }).collect();
        assert_eq!(texts, vec!["before", "leader"], "the stale write never reached the log");
        assert!(s.read("f1").is_ok(), "reads are never fenced");
    }

    #[test]
    fn second_writer_is_refused() {
        let (_dir, s) = tmp();
        let _log = s.create(header("a2")).unwrap();
        match s.open("a2") {
            Err(StoreError::Locked(_)) => {}
            other => panic!("expected Locked, got {:?}", other.err()),
        }
        // Readers are fine while locked.
        assert_eq!(s.read("a2").unwrap().len(), 1);
    }

    #[test]
    fn torn_tail_is_repaired() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("a3")).unwrap();
        log.append(msg("one")).unwrap();
        drop(log);
        let p = s.dir("a3").join("events.jsonl");
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(br#"{"seq":2,"ts":1,"type":"mess"#).unwrap();
        drop(f);
        let mut log = s.open("a3").unwrap();
        assert_eq!(log.events().len(), 2);
        log.append(msg("two")).unwrap();
        drop(log);
        let log = s.open("a3").unwrap();
        assert_eq!(log.events().len(), 3);
        assert_eq!(log.events()[2].seq, 2);
    }

    #[test]
    fn complete_but_garbage_last_line_is_dropped() {
        let (_dir, s) = tmp();
        drop(s.create(header("a4")).unwrap());
        let p = s.dir("a4").join("events.jsonl");
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"not json\n").unwrap();
        drop(f);
        assert_eq!(s.open("a4").unwrap().events().len(), 1);
    }

    #[test]
    fn mid_file_corruption_is_an_error() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("a5")).unwrap();
        log.append(msg("x")).unwrap();
        drop(log);
        let p = s.dir("a5").join("events.jsonl");
        let content = fs::read_to_string(&p).unwrap();
        let broken = content.replacen("\"type\":\"header\"", "\"type\":\"heade", 1);
        fs::write(&p, broken).unwrap();
        assert!(matches!(s.open("a5"), Err(StoreError::Corrupt { line: 1, .. })));
    }

    #[test]
    fn seq_gap_is_corruption() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("a6")).unwrap();
        log.append(msg("x")).unwrap();
        log.append(msg("y")).unwrap();
        drop(log);
        let p = s.dir("a6").join("events.jsonl");
        let lines: Vec<String> = fs::read_to_string(&p).unwrap().lines().map(String::from).collect();
        fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(s.open("a6"), Err(StoreError::Corrupt { .. })));
    }

    #[test]
    fn newer_version_refused_and_bad_ids_rejected() {
        let (_dir, s) = tmp();
        let h = EventKind::Header { version: 99, session_id: "a7".into(), workspace: "/".into(), model: "m".into(), parent: None, title: None };
        drop(s.create(h).unwrap());
        assert!(matches!(s.open("a7"), Err(StoreError::Version(99))));
        assert!(matches!(s.open("../etc"), Err(StoreError::NotFound(_))));
        assert!(matches!(s.open("missing"), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn search_finds_cjk_and_respects_limit() {
        let (_dir, s) = tmp();
        let mut log = s.create(header("a8")).unwrap();
        log.append(msg("部署到正式環境")).unwrap();
        log.append(msg("Deploy again")).unwrap();
        drop(log);
        assert_eq!(s.search("正式", 10).len(), 1);
        assert_eq!(s.search("DEPLOY", 10).len(), 1);
        assert_eq!(s.search("", 10).len(), 0);
        assert_eq!(s.search("部署", 0).len(), 0);
    }

    #[test]
    fn remove_refuses_locked_session() {
        let (_dir, s) = tmp();
        let log = s.create(header("a9")).unwrap();
        assert!(matches!(s.remove("a9"), Err(StoreError::Locked(_))));
        drop(log);
        s.remove("a9").unwrap();
        assert!(!s.exists("a9"));
    }
}
