//! Board columns and the manual-move matrix (Hermes `kanban_workflow`). `archived`
//! is a filter, never a column. `backlog` is OpenClaw Workboard's parking column;
//! the dispatcher treats it like `triage` (never claimed).

use serde_json::{json, Value};

pub const ARCHIVED: &str = "archived";

pub struct Column {
    pub key: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    /// Offered as a drag target (false: reached only through a verb or the kernel).
    pub drag_target: bool,
}

pub const COLUMNS: &[Column] = &[
    Column { key: "triage", label: "Triage", icon: "◇", drag_target: true },
    Column { key: "backlog", label: "Backlog", icon: "▤", drag_target: true },
    Column { key: "todo", label: "Todo", icon: "◻", drag_target: true },
    Column { key: "scheduled", label: "Scheduled", icon: "⏱", drag_target: false },
    Column { key: "ready", label: "Ready", icon: "▶", drag_target: true },
    Column { key: "running", label: "Running", icon: "●", drag_target: false },
    Column { key: "blocked", label: "Blocked", icon: "⊘", drag_target: true },
    Column { key: "review", label: "Review", icon: "◎", drag_target: false },
    Column { key: "done", label: "Done", icon: "✓", drag_target: true },
];

/// Hermes' column set (the `kanban_list` status enum, minus `archived`).
pub const HERMES_STATUSES: &[&str] = &["triage", "todo", "scheduled", "ready", "running", "blocked", "review", "done"];
/// OpenClaw Workboard statuses.
pub const WORKBOARD_STATUSES: &[&str] = &["triage", "backlog", "todo", "scheduled", "ready", "running", "review", "blocked", "done"];
pub const VALID_BLOCK_KINDS: &[&str] = &["capability", "dependency", "needs_input", "transient"];
pub const VALID_WORKSPACE_KINDS: &[&str] = &["dir", "scratch", "worktree"];
/// Same-kind re-blocks after an unblock before the task escalates to triage.
pub const BLOCK_RECURRENCE_LIMIT: u32 = 2;

/// Manual moves a human may request (`src -> dsts`); archiving is always allowed.
fn manual(src: &str) -> &'static [&'static str] {
    match src {
        "triage" => &["backlog", "todo", "ready"],
        "backlog" => &["triage", "todo", "ready"],
        "todo" => &["triage", "backlog", "scheduled", "ready"],
        "scheduled" => &["triage", "todo", "ready"],
        "ready" => &["triage", "backlog", "todo", "scheduled", "blocked", "review", "done"],
        "running" => &["triage", "todo", "scheduled", "ready", "blocked", "review", "done"],
        "blocked" => &["triage", "todo", "scheduled", "ready", "done"],
        "review" => &["triage", "todo", "ready", "done"],
        "done" => &["triage", "todo", "ready"],
        ARCHIVED => &["triage", "backlog", "todo", "ready"],
        _ => &[],
    }
}

pub fn is_status(s: &str) -> bool {
    s == ARCHIVED || COLUMNS.iter().any(|c| c.key == s)
}

/// True when a human may request `src -> dst`.
pub fn can_move(src: &str, dst: &str) -> Result<bool, String> {
    if !is_status(src) {
        return Err(format!("unknown kanban workflow column {src:?}"));
    }
    if src == dst {
        return Ok(false);
    }
    if dst == ARCHIVED {
        return Ok(true);
    }
    if !is_status(dst) {
        return Err(format!("unknown kanban workflow column {dst:?}"));
    }
    Ok(manual(src).contains(&dst))
}

/// The `GET /workflow` shape the dashboard renders.
pub fn to_json() -> Value {
    let mut m = serde_json::Map::new();
    for src in COLUMNS.iter().map(|c| c.key).chain([ARCHIVED]) {
        let mut d: Vec<&str> = manual(src).to_vec();
        d.sort();
        m.insert(src.into(), json!(d));
    }
    json!({
        "columns": COLUMNS.iter().map(|c| json!({"key": c.key, "label": c.label, "icon": c.icon, "drag_target": c.drag_target})).collect::<Vec<_>>(),
        "manual": m,
        "archived": ARCHIVED,
    })
}

pub fn icon(status: &str) -> &'static str {
    COLUMNS.iter().find(|c| c.key == status).map(|c| c.icon).unwrap_or(if status == ARCHIVED { "▣" } else { "?" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_matrix() {
        assert!(can_move("todo", "ready").unwrap());
        assert!(!can_move("todo", "running").unwrap(), "running is kernel-only");
        assert!(can_move("running", "archived").unwrap());
        assert!(can_move("archived", "todo").unwrap());
        assert!(!can_move("done", "done").unwrap());
        assert!(can_move("nope", "todo").is_err());
        assert!(can_move("todo", "nope").is_err());
        let j = to_json();
        assert_eq!(j["columns"].as_array().unwrap().len(), COLUMNS.len());
        assert!(j["manual"]["archived"].as_array().unwrap().iter().any(|v| v == "todo"));
        for s in HERMES_STATUSES.iter().chain(WORKBOARD_STATUSES) {
            assert!(is_status(s));
        }
    }
}
