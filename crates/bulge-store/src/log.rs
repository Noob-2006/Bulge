//! Append-only JSONL log with a single-writer lease and torn-tail recovery.
//! MARK: M15 — transcribed by dsh; see marks/M15-jsonl-log.md.
//!
//! File layout: line 1 is the header object, every further line is one record.
//! Every line is a single compact JSON value terminated by `\n`.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("log already exists: {0}")]
    Exists(String),
    #[error("log is locked by another writer: {0}")]
    Locked(String),
    #[error("log has no header line: {0}")]
    MissingHeader(String),
    /// A complete (newline-terminated) line that is not valid JSON. Only an
    /// unterminated final line is recoverable; anything else is corruption.
    #[error("corrupt record at line {line}: {reason}")]
    Corrupt { line: usize, reason: String },
    #[error("record too large: {0} bytes")]
    RecordTooLarge(usize),
}

/// Contents of a log as read.
#[derive(Debug, Clone, PartialEq)]
pub struct Scan {
    pub header: Value,
    pub records: Vec<Value>,
    /// Bytes of an unterminated final line that were ignored (0 if none).
    pub torn_tail_bytes: u64,
}

/// Exclusive writer. Holding a `JsonlLog` holds the OS file lock.
#[derive(Debug)]
pub struct JsonlLog {
    file: File,
    /// Bytes committed to the file, always ending on a line boundary.
    len: u64,
}

/// Largest single encoded record (line) accepted.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

impl JsonlLog {
    /// Create a new log (fails if it exists), write + fsync the header line,
    /// fsync the parent directory, and take the writer lock.
    pub fn create(path: &Path, header: &Value) -> Result<Self, LogError> {
        let mut file = match OpenOptions::new().create_new(true).read(true).write(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(LogError::Exists(path_display(path)));
            }
            Err(error) => return Err(LogError::Io(error)),
        };
        lock(&file, path)?;
        let line = encode_line(header)?;
        file.write_all(&line)?;
        file.sync_all()?;
        sync_parent(path)?;
        let len = line.len() as u64;
        Ok(Self { file, len })
    }

    /// Open an existing log for appending: take the lock (`Locked` if held),
    /// scan it, and durably truncate an unterminated final line before
    /// returning, so the next append starts on a clean line boundary.
    pub fn open(path: &Path) -> Result<(Self, Scan), LogError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&file, path)?;
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut bytes)?;
        let scan = scan_bytes(&bytes, path)?;
        // The scanner only counts a final fragment without `\n` as torn; every
        // newline-terminated line before it is committed.
        let len = bytes.len() as u64 - scan.torn_tail_bytes;
        if scan.torn_tail_bytes > 0 {
            file.set_len(len)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::Start(len))?;
        Ok((Self { file, len }, scan))
    }

    /// Read a log without locking or modifying it; a torn tail is ignored.
    pub fn read(path: &Path) -> Result<Scan, LogError> {
        let bytes = std::fs::read(path)?;
        scan_bytes(&bytes, path)
    }

    /// Append records as one write, then fsync. On any failure the file is
    /// truncated back to its previous length (no partial batch survives).
    pub fn append(&mut self, records: &[Value]) -> Result<(), LogError> {
        if records.is_empty() {
            return Ok(());
        }
        // Encode (and size-check) the whole batch before touching the file so
        // an oversized member cannot leave a partial batch behind.
        let mut buffer = Vec::new();
        for record in records {
            buffer.extend_from_slice(&encode_line(record)?);
        }
        let old_len = self.len;
        // Keep the write position at the committed end even if a previous
        // rollback could not fully restore the descriptor position.
        self.file.seek(SeekFrom::Start(old_len))?;
        if let Err(error) = self.file.write_all(&buffer).and_then(|()| self.file.sync_all()) {
            // Best effort rollback: a failed write/sync must not leave a
            // partial batch that a later reader would treat as corruption.
            let _ = self.file.seek(SeekFrom::Start(old_len));
            let _ = self.file.set_len(old_len);
            let _ = self.file.sync_all();
            return Err(LogError::Io(error));
        }
        self.len = old_len + buffer.len() as u64;
        Ok(())
    }

    /// Current committed length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

/// Take the exclusive OS lock: `Locked` if another writer holds it, `Io` for real errors.
fn lock(file: &File, path: &Path) -> Result<(), LogError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(LogError::Locked(path_display(path))),
        Err(TryLockError::Error(error)) => Err(LogError::Io(error)),
    }
}

/// Encode one compact JSON line, including its terminating newline.
fn encode_line(value: &Value) -> Result<Vec<u8>, LogError> {
    let text = serde_json::to_string(value).map_err(|error| LogError::Io(std::io::Error::other(error)))?;
    if text.len() > MAX_RECORD_BYTES {
        return Err(LogError::RecordTooLarge(text.len()));
    }
    let mut line = Vec::with_capacity(text.len() + 1);
    line.extend_from_slice(text.as_bytes());
    line.push(b'\n');
    Ok(line)
}

/// Fsync the directory holding `path` so a freshly created entry is durable.
fn sync_parent(path: &Path) -> Result<(), LogError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Parse a raw log: header line first, then newline-terminated records. An
/// unterminated final line is a torn tail; a terminated unparsable line is
/// corruption.
fn scan_bytes(bytes: &[u8], path: &Path) -> Result<Scan, LogError> {
    let Some(header_end) = bytes.iter().position(|&byte| byte == b'\n') else {
        // Empty, or a header that never reached its newline: not readable.
        return Err(LogError::MissingHeader(path_display(path)));
    };
    let header = parse_line(&bytes[..header_end], 1)?;
    let mut records = Vec::new();
    let mut line_number = 2usize;
    let mut line_start = header_end + 1;
    loop {
        match bytes[line_start..].iter().position(|&byte| byte == b'\n') {
            Some(offset) => {
                let line_end = line_start + offset;
                records.push(parse_line(&bytes[line_start..line_end], line_number)?);
                line_number += 1;
                line_start = line_end + 1;
            }
            None => {
                let torn_tail_bytes = (bytes.len() - line_start) as u64;
                return Ok(Scan { header, records, torn_tail_bytes });
            }
        }
    }
}

fn parse_line(line: &[u8], line_number: usize) -> Result<Value, LogError> {
    serde_json::from_slice(line).map_err(|error| LogError::Corrupt { line: line_number, reason: error.to_string() })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir() -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        let path = std::env::temp_dir().join(format!("bulge-store-log-{}-{sequence}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn file_len(path: &Path) -> u64 {
        std::fs::metadata(path).expect("metadata").len()
    }

    fn assert_locked(result: Result<(JsonlLog, Scan), LogError>) {
        match result {
            Err(LogError::Locked(_)) => {}
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn create_append_reopen_round_trip() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        let header = json!({"format": "bulge-job", "version": 1, "id": "j-1"});
        let batches = [vec![json!({"seq": 1}), json!({"seq": 2})], vec![json!({"seq": 3})]];

        let mut log = JsonlLog::create(&path, &header).expect("create");
        assert_eq!(log.len(), file_len(&path));
        let mut expected_len = file_len(&path);
        for batch in &batches {
            log.append(batch).expect("append");
            expected_len += batch.iter().map(|r| r.to_string().len() as u64 + 1).sum::<u64>();
            assert_eq!(log.len(), expected_len);
            assert_eq!(file_len(&path), expected_len);
        }
        // An empty batch is a no-op.
        log.append(&[]).expect("empty append");
        assert_eq!(file_len(&path), expected_len);
        drop(log);

        let (log, scan) = JsonlLog::open(&path).expect("reopen");
        assert_eq!(scan.header, header);
        assert_eq!(scan.records, vec![json!({"seq": 1}), json!({"seq": 2}), json!({"seq": 3})]);
        assert_eq!(scan.torn_tail_bytes, 0);
        assert_eq!(log.len(), expected_len);
        assert!(!log.is_empty());
        drop(log);

        let read = JsonlLog::read(&path).expect("read");
        assert_eq!(read.header, header);
        assert_eq!(read.records, scan.records);
        assert_eq!(read.torn_tail_bytes, 0);
    }

    #[test]
    fn create_existing_path_is_exists() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        let _log = JsonlLog::create(&path, &json!({"v": 1})).expect("create");
        match JsonlLog::create(&path, &json!({"v": 1})) {
            Err(LogError::Exists(_)) => {}
            other => panic!("expected Exists, got {other:?}"),
        }
    }

    #[test]
    fn second_open_is_locked_until_drop() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        let log = JsonlLog::create(&path, &json!({"v": 1})).expect("create");
        assert_locked(JsonlLog::open(&path));
        // Readers never take the lock.
        let scan = JsonlLog::read(&path).expect("read while locked");
        assert_eq!(scan.header, json!({"v": 1}));
        drop(log);
        let (reopened, _) = JsonlLog::open(&path).expect("open after drop");
        assert_eq!(reopened.len(), file_len(&path));
    }

    #[test]
    fn torn_tail_is_ignored_by_read_and_truncated_by_open() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        {
            let mut log = JsonlLog::create(&path, &json!({"v": 1})).expect("create");
            log.append(&[json!({"seq": 1})]).expect("append");
        }
        let committed = file_len(&path);
        let torn = b"{\"seq\":2,\"partial\":";
        {
            let mut file = OpenOptions::new().append(true).open(&path).expect("open raw");
            file.write_all(torn).expect("write torn tail");
        }
        assert_eq!(file_len(&path), committed + torn.len() as u64);

        let read = JsonlLog::read(&path).expect("read");
        assert_eq!(read.records, vec![json!({"seq": 1})]);
        assert_eq!(read.torn_tail_bytes, torn.len() as u64);
        assert_eq!(file_len(&path), committed + torn.len() as u64, "read must not modify");

        let (mut log, scan) = JsonlLog::open(&path).expect("open repairs");
        assert_eq!(scan.records, vec![json!({"seq": 1})]);
        assert_eq!(scan.torn_tail_bytes, torn.len() as u64);
        assert_eq!(file_len(&path), committed, "open truncates the torn bytes");
        assert_eq!(log.len(), committed);

        log.append(&[json!({"seq": 2})]).expect("append after repair");
        drop(log);
        let read = JsonlLog::read(&path).expect("read after repair");
        assert_eq!(read.records, vec![json!({"seq": 1}), json!({"seq": 2})]);
        assert_eq!(read.torn_tail_bytes, 0);
    }

    #[test]
    fn corrupt_complete_line_reports_line_number() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        {
            let mut log = JsonlLog::create(&path, &json!({"v": 1})).expect("create");
            log.append(&[json!({"seq": 1}), json!({"seq": 2})]).expect("append");
        }
        let mut lines: Vec<Vec<u8>> = std::fs::read(&path)
            .expect("read file")
            .split_inclusive(|&byte| byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(lines.len(), 3);
        lines[1] = b"{not json}\n".to_vec();
        std::fs::write(&path, lines.concat()).expect("rewrite");

        for result in [
            JsonlLog::read(&path).map(|_| ()),
            JsonlLog::open(&path).map(|(_, scan)| {
                let _ = scan;
            }),
        ] {
            match result {
                Err(LogError::Corrupt { line, .. }) => assert_eq!(line, 2),
                other => panic!("expected Corrupt at line 2, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_header_on_empty_or_unterminated_first_line() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        std::fs::write(&path, b"").expect("write empty");
        assert!(matches!(JsonlLog::read(&path), Err(LogError::MissingHeader(_))));
        assert!(matches!(JsonlLog::open(&path), Err(LogError::MissingHeader(_))));

        std::fs::write(&path, b"{\"v\":1}").expect("write no newline");
        assert!(matches!(JsonlLog::read(&path), Err(LogError::MissingHeader(_))));
        assert!(matches!(JsonlLog::open(&path), Err(LogError::MissingHeader(_))));
    }

    #[test]
    fn oversized_record_is_rejected_without_writing() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        let mut log = JsonlLog::create(&path, &json!({"v": 1})).expect("create");
        let before = file_len(&path);
        let oversized = json!({"text": "x".repeat(MAX_RECORD_BYTES)});
        match log.append(&[json!({"seq": 1}), oversized]) {
            Err(LogError::RecordTooLarge(bytes)) => assert!(bytes > MAX_RECORD_BYTES),
            other => panic!("expected RecordTooLarge, got {other:?}"),
        }
        assert_eq!(file_len(&path), before, "a rejected batch writes nothing");
        assert_eq!(log.len(), before);
        drop(log);
        let read = JsonlLog::read(&path).expect("read");
        assert!(read.records.is_empty());
        assert_eq!(read.torn_tail_bytes, 0);
    }

    #[test]
    fn unicode_and_escapes_round_trip() {
        let dir = temp_dir();
        let path = dir.0.join("job.jsonl");
        let header = json!({"標題": "工作 🚀", "note": "a/b\\c\"d"});
        let records = vec![
            json!({"訊息": "你好，世界", "換行": "line1\nline2", "tab": "\t", "emoji": "🧪"}),
            json!({"nested": {"key": ["值", null, true, -1.5e10]}}),
        ];
        {
            let mut log = JsonlLog::create(&path, &header).expect("create");
            log.append(&records).expect("append");
        }
        let scan = JsonlLog::read(&path).expect("read");
        assert_eq!(scan.header, header);
        assert_eq!(scan.records, records);
        let (log, reopened) = JsonlLog::open(&path).expect("open");
        assert_eq!(reopened.header, header);
        assert_eq!(reopened.records, records);
        assert_eq!(log.len(), file_len(&path));
    }
}
