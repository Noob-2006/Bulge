//! Append-only JSONL log with a single-writer lease and torn-tail recovery.
//! MARK: M15 — transcribed by dsh; see marks/M15-jsonl-log.md.
//!
//! File layout: line 1 is the header object, every further line is one record.
//! Every line is a single compact JSON value terminated by `\n`.

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
    // M15
}

/// Largest single encoded record (line) accepted.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

impl JsonlLog {
    /// Create a new log (fails if it exists), write + fsync the header line,
    /// fsync the parent directory, and take the writer lock.
    pub fn create(path: &Path, header: &Value) -> Result<Self, LogError> {
        let _ = (path, header);
        todo!("M15")
    }

    /// Open an existing log for appending: take the lock (`Locked` if held),
    /// scan it, and durably truncate an unterminated final line before
    /// returning, so the next append starts on a clean line boundary.
    pub fn open(path: &Path) -> Result<(Self, Scan), LogError> {
        let _ = path;
        todo!("M15")
    }

    /// Read a log without locking or modifying it; a torn tail is ignored.
    pub fn read(path: &Path) -> Result<Scan, LogError> {
        let _ = path;
        todo!("M15")
    }

    /// Append records as one write, then fsync. On any failure the file is
    /// truncated back to its previous length (no partial batch survives).
    pub fn append(&mut self, records: &[Value]) -> Result<(), LogError> {
        let _ = records;
        todo!("M15")
    }

    /// Current committed length in bytes.
    pub fn len(&self) -> u64 {
        todo!("M15")
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
