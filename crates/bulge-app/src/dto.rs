//! What the webview receives: streamed events and the shapes of changes,
//! write-backs and rollbacks.

use bulge_vm::changes::Change;
use serde::Serialize;

/// One streamed log line, tagged with the session it belongs to.
#[derive(Clone, Serialize)]
pub(crate) struct LineEvent {
    pub(crate) handle: String,
    pub(crate) line: String,
}

/// An egress-approval prompt pushed to the UI: the agent inside this session's VM
/// is trying to reach `host:port` and (collaborative mode) needs the user's OK.
#[derive(Clone, Serialize)]
pub(crate) struct EgressAskEvent {
    pub(crate) handle: String,
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// A single workspace change, for the review list. The full unified diff is sent
/// separately as text; this drives the per-file approval checkboxes.
#[derive(Clone, Serialize)]
pub(crate) struct ChangeDto {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) detail: String,
    /// Set for a by-product (the review rule that matched): shown, but not
    /// selected for write-back by default.
    pub(crate) ignored: Option<String>,
    /// Already written back this turn by full-auto (snapshotted, undoable).
    pub(crate) applied: bool,
}

impl ChangeDto {
    pub(crate) fn from_change(change: &Change, ignored: &[(String, String)], applied: &[String]) -> Self {
        let (kind, detail) = match change {
            Change::File { data, existed, executable, .. } => (
                "file",
                format!("{} · {} bytes{}", if *existed { "修改" } else { "新增" }, data.len(), if *executable { " · 可執行" } else { "" }),
            ),
            Change::Deleted { .. } => ("deleted", "刪除".to_string()),
            Change::Dir { .. } => ("dir", "新資料夾".to_string()),
            Change::Symlink { target, .. } => ("symlink", format!("符號連結 → {}", target.display())),
            Change::TooLarge { size, .. } => ("too_large", format!("過大,無法內嵌審閱 ({size} bytes)")),
        };
        let ignored = ignored.iter().find(|(path, _)| path == change.path()).map(|(_, reason)| reason.clone());
        let applied = applied.iter().any(|path| path == change.path());
        Self { path: change.path().to_string(), kind: kind.to_string(), detail, ignored, applied }
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct DoneEvent {
    /// Full-auto: what this turn already wrote back (undoable).
    pub(crate) auto_writeback: Option<WritebackDto>,
    pub(crate) handle: String,
    /// The real store job id, so the UI can send a follow-up turn on this same
    /// conversation instead of starting a new one.
    pub(crate) job_id: String,
    pub(crate) status: String,
    pub(crate) outcome: String,
    pub(crate) diff: Option<String>,
    pub(crate) changes: Vec<ChangeDto>,
    pub(crate) job_dir: String,
    pub(crate) error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ApplyReportDto {
    pub(crate) applied: Vec<String>,
    pub(crate) skipped: Vec<(String, String)>,
    /// The snapshot this write-back can be undone from.
    pub(crate) writeback_id: String,
}

/// One snapshotted write-back (the audit record, summarised for the UI).
#[derive(Clone, Serialize)]
pub(crate) struct WritebackDto {
    pub(crate) id: String,
    pub(crate) created_ms: u64,
    /// Applied by full-auto rules rather than approved by a human.
    pub(crate) auto: bool,
    /// "applied" | "rolled_back" | "partially_rolled_back" | "pending"
    pub(crate) state: String,
    pub(crate) paths: Vec<String>,
    pub(crate) skipped: Vec<(String, String)>,
    pub(crate) rollback_conflicts: Vec<(String, String)>,
}

impl WritebackDto {
    pub(crate) fn from_manifest(manifest: &bulge_vm::writeback::Manifest) -> Self {
        let state = match manifest.state {
            bulge_vm::writeback::State::Pending => "pending",
            bulge_vm::writeback::State::Applied => "applied",
            bulge_vm::writeback::State::RolledBack => "rolled_back",
            bulge_vm::writeback::State::PartiallyRolledBack => "partially_rolled_back",
        };
        Self {
            id: manifest.id.clone(),
            created_ms: manifest.created_ms,
            auto: manifest.auto,
            state: state.into(),
            paths: manifest.applied_paths(),
            skipped: manifest.skipped.clone(),
            rollback_conflicts: manifest.rollback_conflicts.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct RollbackDto {
    pub(crate) restored: Vec<String>,
    pub(crate) conflicts: Vec<(String, String)>,
}
