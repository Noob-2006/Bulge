//! Job store: one directory per job under the store root, holding `job.jsonl`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bulge_llm::Message;
use serde_json::json;

use crate::events::{Envelope, FORMAT, FORMAT_VERSION, Header, JobEvent, JobSpec, JobStatus};
use crate::log::{JsonlLog, LogError};
use crate::state::{JobState, StateError};

const LOG_FILE: &str = "job.jsonl";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("malformed record: {0}")]
    Malformed(String),
    #[error("not a bulge job log (format {format:?} v{version})")]
    Format { format: String, version: u32 },
    #[error("invalid job id: {0}")]
    InvalidId(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

/// Random job id: `j-` + 16 hex chars.
pub fn new_job_id() -> Result<String, StoreError> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
    Ok(format!("j-{}", buf.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, PartialEq)]
pub struct JobSummary {
    pub id: String,
    pub title: String,
    pub status: JobStatus,
    pub created_ms: u64,
    pub last_ms: u64,
}

/// What `open` had to repair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    pub torn_tail_bytes: u64,
    /// Tool calls that were claimed but never completed; each now has a
    /// synthetic failed completion and an error tool result in history.
    pub interrupted_calls: Vec<String>,
}

pub struct JobStore {
    root: PathBuf,
}

/// Exclusive writer for one job. Keeps the in-memory state in sync with
/// every successful append.
pub struct JobHandle {
    log: JsonlLog,
    state: JobState,
    dir: PathBuf,
}

impl JobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir(&self, id: &str) -> Result<PathBuf, StoreError> {
        if valid_id(id) { Ok(self.root.join(id)) } else { Err(StoreError::InvalidId(id.to_owned())) }
    }

    pub fn create(&self, spec: JobSpec) -> Result<JobHandle, StoreError> {
        let dir = self.dir(&spec.id)?;
        std::fs::create_dir_all(&dir)?;
        let created_ms = now_ms();
        let header = Header { format: FORMAT.into(), version: FORMAT_VERSION, id: spec.id.clone(), title: spec.title.clone(), created_ms };
        let header = serde_json::to_value(&header).map_err(|e| StoreError::Malformed(e.to_string()))?;
        let mut log = JsonlLog::create(&dir.join(LOG_FILE), &header)?;
        let first = Envelope { seq: 1, at_ms: created_ms, event: JobEvent::Created { spec } };
        log.append(&[to_value(&first)?])?;
        let state = JobState::from_events([&first])?;
        Ok(JobHandle { log, state, dir })
    }

    /// Open a job for writing, rebuild its state, and repair crash damage.
    pub fn open(&self, id: &str) -> Result<(JobHandle, Recovery), StoreError> {
        let dir = self.dir(id)?;
        let (log, scan) = JsonlLog::open(&dir.join(LOG_FILE))?;
        check_header(&scan.header)?;
        let envelopes = parse_records(&scan.records)?;
        let state = JobState::from_events(&envelopes)?;
        let mut handle = JobHandle { log, state, dir };
        let mut recovery = Recovery { torn_tail_bytes: scan.torn_tail_bytes, ..Recovery::default() };
        if !handle.state.status.is_terminal() && !handle.state.pending_calls.is_empty() {
            recovery.interrupted_calls = handle.recover_interrupted()?;
        }
        Ok((handle, recovery))
    }

    /// Read-only snapshot (no lock): safe while another process writes.
    pub fn load(&self, id: &str) -> Result<JobState, StoreError> {
        let scan = JsonlLog::read(&self.dir(id)?.join(LOG_FILE))?;
        check_header(&scan.header)?;
        Ok(JobState::from_events(&parse_records(&scan.records)?)?)
    }

    /// All jobs, newest activity first. Unreadable entries are skipped.
    pub fn list(&self) -> Result<Vec<JobSummary>, StoreError> {
        let mut jobs = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(jobs),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if let Ok(state) = self.load(&id) {
                jobs.push(JobSummary { id, title: state.spec.title, status: state.status, created_ms: state.created_ms, last_ms: state.last_ms });
            }
        }
        jobs.sort_by_key(|job| std::cmp::Reverse(job.last_ms));
        Ok(jobs)
    }
}

impl JobHandle {
    pub fn state(&self) -> &JobState {
        &self.state
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Durably append events (one fsync for the batch), then fold them into state.
    pub fn append(&mut self, events: Vec<JobEvent>) -> Result<(), StoreError> {
        let at_ms = now_ms().max(self.state.last_ms);
        let envelopes: Vec<Envelope> = events
            .into_iter()
            .enumerate()
            .map(|(i, event)| Envelope { seq: self.state.last_seq + 1 + i as u64, at_ms, event })
            .collect();
        // Validate against a scratch copy first so a rejected event never reaches disk.
        let mut next = self.state.clone();
        for envelope in &envelopes {
            next.apply(envelope)?;
        }
        let records = envelopes.iter().map(to_value).collect::<Result<Vec<_>, _>>()?;
        self.log.append(&records)?;
        self.state = next;
        Ok(())
    }

    /// Close out calls interrupted by a crash: failed completion + an error
    /// tool result the model will see, then a `Recovered` marker.
    fn recover_interrupted(&mut self) -> Result<Vec<String>, StoreError> {
        let calls: Vec<String> = self.state.pending_calls.keys().cloned().collect();
        let mut events = Vec::with_capacity(calls.len() * 2 + 1);
        for call_id in &calls {
            let note = "interrupted: bulge stopped before this call finished; its effects are unknown. Check the current state before retrying.";
            events.push(JobEvent::ToolCompleted { call_id: call_id.clone(), ok: false, result: json!({ "error": note }) });
            events.push(JobEvent::Message { message: Message::tool_result(call_id.clone(), note, true) });
        }
        events.push(JobEvent::Recovered { interrupted_calls: calls.clone() });
        self.append(events)?;
        Ok(calls)
    }
}

fn to_value(envelope: &Envelope) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(envelope).map_err(|e| StoreError::Malformed(e.to_string()))
}

fn check_header(header: &serde_json::Value) -> Result<(), StoreError> {
    let header: Header = serde_json::from_value(header.clone()).map_err(|e| StoreError::Malformed(e.to_string()))?;
    if header.format != FORMAT || header.version != FORMAT_VERSION {
        return Err(StoreError::Format { format: header.format, version: header.version });
    }
    Ok(())
}

fn parse_records(records: &[serde_json::Value]) -> Result<Vec<Envelope>, StoreError> {
    records
        .iter()
        .enumerate()
        .map(|(i, r)| serde_json::from_value(r.clone()).map_err(|e| StoreError::Malformed(format!("record {}: {e}", i + 1))))
        .collect()
}
