//! Board document: every table of a board in one JSON file, rewritten atomically
//! under an exclusive `flock`, so the CLI, seagentd's dispatcher and worker tools can
//! mutate it concurrently. Never nest `with_board` calls for the same board (a
//! second lock in the same process would wait on the first).

use super::{board_dir, now};
use crate::util::atomic_write;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub body: Option<String>,
    pub assignee: Option<String>,
    pub status: String,
    pub priority: i64,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub workspace_kind: String,
    pub workspace_path: Option<String>,
    pub branch_name: Option<String>,
    pub claim_lock: Option<String>,
    pub claim_expires: Option<i64>,
    /// Workboard claim owner (agent id) and token (redacted on every read surface).
    pub claim_owner: Option<String>,
    pub claim_token: Option<String>,
    pub tenant: Option<String>,
    pub result: Option<String>,
    pub idempotency_key: Option<String>,
    pub consecutive_failures: u32,
    pub last_failure_error: Option<String>,
    pub max_runtime_seconds: Option<i64>,
    pub last_heartbeat_at: Option<i64>,
    pub current_run_id: Option<u64>,
    /// None = defaults only; Some([]) = explicitly none.
    pub skills: Option<Vec<String>>,
    pub model_override: Option<String>,
    pub provider_override: Option<String>,
    pub max_retries: Option<u32>,
    pub goal_mode: bool,
    pub goal_max_turns: Option<u32>,
    /// Session that created the task (notifications wake it).
    pub session_id: Option<String>,
    pub block_kind: Option<String>,
    pub block_recurrences: u32,
    pub completion_contract: Option<String>,
    /// Workboard fields.
    pub labels: Vec<String>,
    pub scheduled_at: Option<i64>,
    pub created_by_card: Option<String>,
    /// `workboard_promote(force)`: claim skips the dependency gate once.
    pub force_ready: bool,
    pub archived_at: Option<i64>,
    pub updated_at: i64,
    /// Linked chat session (Workboard `sessionKey`).
    pub session_key: Option<String>,
    pub template_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Run {
    pub id: u64,
    pub task_id: String,
    pub profile: Option<String>,
    pub status: String,
    pub claim_lock: Option<String>,
    pub claim_expires: Option<i64>,
    pub max_runtime_seconds: Option<i64>,
    pub last_heartbeat_at: Option<i64>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub outcome: Option<String>,
    pub summary: Option<String>,
    pub metadata: Option<Value>,
    pub error: Option<String>,
    /// `ready` or `review`: which lane the run was claimed from.
    pub source_status: String,
    /// Kernel session executing the run, and the process that owns it.
    pub worker_session: Option<String>,
    pub owner_pid: Option<u32>,
    pub owner_birth: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Comment {
    pub id: u64,
    pub task_id: String,
    pub author: String,
    pub body: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    pub id: u64,
    pub task_id: String,
    pub kind: String,
    pub payload: Option<Value>,
    pub created_at: i64,
    pub run_id: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Attachment {
    pub id: u64,
    pub task_id: String,
    pub filename: String,
    pub stored_path: String,
    pub content_type: Option<String>,
    pub size: u64,
    pub uploaded_by: Option<String>,
    pub created_at: i64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Link {
    pub parent: String,
    pub child: String,
}

/// Workboard proof record (worker-reported outcome of a check).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Proof {
    pub id: String,
    pub task_id: String,
    pub status: String,
    pub label: Option<String>,
    pub command: Option<String>,
    pub url: Option<String>,
    pub note: Option<String>,
    pub artifact_path: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Artifact {
    pub task_id: String,
    pub label: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WorkerLog {
    pub task_id: String,
    pub level: String,
    pub message: String,
    pub session_key: Option<String>,
    pub run_id: Option<String>,
    pub created_at: i64,
}

/// A notification subscription: a chat (`platform`/`chat_id`), an seagent session to wake
/// (`session_key`), or a pull-only cursor (Workboard `workboard_notify_*`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub id: String,
    /// None = every task on the board.
    pub task_id: Option<String>,
    pub platform: Option<String>,
    pub chat_id: Option<String>,
    pub thread_id: Option<String>,
    pub user_id: Option<String>,
    pub session_key: Option<String>,
    pub run_id: Option<String>,
    pub target: Option<String>,
    /// `completed`, `failed`, `stale`, `blocked`, `review` … empty = completed+failed+blocked.
    pub event_kinds: Vec<String>,
    /// `notify` (message), `notify+wake`, `wake`, or `pull` (cursor only).
    pub delivery_mode: String,
    /// Highest notification seq already delivered / advanced past.
    pub cursor: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Notification {
    pub seq: u64,
    pub task_id: String,
    pub kind: String,
    pub message: String,
    pub run_id: Option<u64>,
    pub session_key: Option<String>,
    pub artifacts: Vec<String>,
    pub created_at: i64,
}

/// Sessions-board operator pin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Placement {
    pub session_key: String,
    pub column_id: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BoardData {
    pub version: u32,
    /// Bumped on every write (UI change detection).
    pub revision: u64,
    pub next_run: u64,
    pub next_comment: u64,
    pub next_event: u64,
    pub next_attachment: u64,
    pub next_notification: u64,
    pub tasks: Vec<Task>,
    pub links: Vec<Link>,
    pub comments: Vec<Comment>,
    pub events: Vec<Event>,
    pub runs: Vec<Run>,
    pub attachments: Vec<Attachment>,
    pub proofs: Vec<Proof>,
    pub artifacts: Vec<Artifact>,
    pub worker_logs: Vec<WorkerLog>,
    pub subscriptions: Vec<Subscription>,
    pub notifications: Vec<Notification>,
    pub placements: Vec<Placement>,
}

impl BoardData {
    pub fn task(&self, id: &str) -> Option<&Task> {
        self.tasks.iter().find(|t| t.id == id)
    }
    pub fn task_mut(&mut self, id: &str) -> Option<&mut Task> {
        self.tasks.iter_mut().find(|t| t.id == id)
    }
    pub fn run(&self, id: u64) -> Option<&Run> {
        self.runs.iter().find(|r| r.id == id)
    }
    pub fn run_mut(&mut self, id: u64) -> Option<&mut Run> {
        self.runs.iter_mut().find(|r| r.id == id)
    }
    pub fn parent_ids(&self, id: &str) -> Vec<String> {
        let mut v: Vec<String> = self.links.iter().filter(|l| l.child == id).map(|l| l.parent.clone()).collect();
        v.sort();
        v
    }
    pub fn child_ids(&self, id: &str) -> Vec<String> {
        let mut v: Vec<String> = self.links.iter().filter(|l| l.parent == id).map(|l| l.child.clone()).collect();
        v.sort();
        v
    }
    pub fn status_of(&self, id: &str) -> Option<&str> {
        self.task(id).map(|t| t.status.as_str())
    }
    pub fn comments_for(&self, id: &str) -> Vec<&Comment> {
        self.comments.iter().filter(|c| c.task_id == id).collect()
    }
    pub fn events_for(&self, id: &str) -> Vec<&Event> {
        self.events.iter().filter(|e| e.task_id == id).collect()
    }
    pub fn runs_for(&self, id: &str) -> Vec<&Run> {
        self.runs.iter().filter(|r| r.task_id == id).collect()
    }
    pub fn attachments_for(&self, id: &str) -> Vec<&Attachment> {
        self.attachments.iter().filter(|a| a.task_id == id).collect()
    }
    pub fn latest_run(&self, id: &str) -> Option<&Run> {
        self.runs.iter().filter(|r| r.task_id == id).max_by_key(|r| r.id)
    }
    /// Newest event of `kind`, optionally scoped to one run.
    pub fn latest_event(&self, id: &str, kind: &str, run: Option<u64>) -> Option<&Event> {
        self.events.iter().rev().find(|e| e.task_id == id && e.kind == kind && (run.is_none() || e.run_id == run))
    }

    pub fn append_event(&mut self, task_id: &str, kind: &str, payload: Option<Value>, run_id: Option<u64>) -> u64 {
        self.next_event += 1;
        let id = self.next_event;
        self.events.push(Event { id, task_id: task_id.into(), kind: kind.into(), payload, created_at: now(), run_id });
        if let Some(t) = self.task_mut(task_id) {
            t.updated_at = now();
        }
        id
    }
    pub fn insert_comment(&mut self, task_id: &str, author: &str, body: &str) -> u64 {
        self.next_comment += 1;
        let id = self.next_comment;
        self.comments.push(Comment { id, task_id: task_id.into(), author: author.into(), body: body.into(), created_at: now() });
        id
    }
    pub fn new_run_id(&mut self) -> u64 {
        self.next_run += 1;
        self.next_run
    }
}

pub fn board_file(data: &Path, slug: &str) -> PathBuf {
    board_dir(data, slug).join("kanban.json")
}

struct Lock(std::fs::File);
impl Lock {
    fn take(path: &Path) -> Result<Lock, String> {
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
        let f = OpenOptions::new().create(true).truncate(false).write(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // SAFETY: blocking flock on an fd we own.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Lock(f))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn load(path: &Path) -> Result<BoardData, String> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(|e| format!("{} is corrupt: {e}", path.display())),
        Ok(_) => Ok(BoardData { version: FORMAT_VERSION, ..Default::default() }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BoardData { version: FORMAT_VERSION, ..Default::default() }),
        Err(e) => Err(e.to_string()),
    }
}

/// Read-modify-write a board under its exclusive lock. `f` returning `Err` writes nothing.
pub fn with_board<R>(data: &Path, slug: &str, f: impl FnOnce(&mut BoardData) -> Result<R, String>) -> Result<R, String> {
    let path = board_file(data, slug);
    let _g = Lock::take(&board_dir(data, slug).join("kanban.lock"))?;
    let mut b = load(&path)?;
    let before = b.clone();
    let r = f(&mut b)?;
    if b != before {
        b.revision += 1;
        b.version = FORMAT_VERSION;
        let text = serde_json::to_string(&b).map_err(|e| e.to_string())?;
        atomic_write(&path, text.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(r)
}

/// Snapshot read (no lock needed: writes are atomic renames).
pub fn read_board(data: &Path, slug: &str) -> Result<BoardData, String> {
    load(&board_file(data, slug))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rmw_is_atomic_and_errors_write_nothing() {
        let d = super::super::testutil::data();
        with_board(&d, "default", |b| {
            b.tasks.push(Task { id: "t_1".into(), title: "x".into(), status: "ready".into(), ..Default::default() });
            Ok(())
        })
        .unwrap();
        let r: Result<(), String> = with_board(&d, "default", |b| {
            b.tasks.clear();
            Err("nope".into())
        });
        assert!(r.is_err());
        let b = read_board(&d, "default").unwrap();
        assert_eq!(b.tasks.len(), 1);
        assert_eq!(b.revision, 1);
        // Unchanged closure does not bump the revision.
        with_board(&d, "default", |_| Ok(())).unwrap();
        assert_eq!(read_board(&d, "default").unwrap().revision, 1);
        std::fs::write(board_file(&d, "default"), "{oops").unwrap();
        assert!(with_board(&d, "default", |_| Ok(())).unwrap_err().contains("corrupt"));
    }

    #[test]
    fn concurrent_writers_keep_every_update() {
        let d = super::super::testutil::data();
        let hs: Vec<_> = (0..6)
            .map(|i| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for j in 0..5 {
                        with_board(&d, "default", |b| {
                            b.insert_comment("t", "a", &format!("{i}-{j}"));
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let b = read_board(&d, "default").unwrap();
        assert_eq!(b.comments.len(), 30);
        assert_eq!(b.next_comment, 30);
    }
}
