//! Global emergency stop (Hermes `agent/estop.py`): a resumable pause for NEW work.
//!
//! `seagent pause [reason]` writes `<data>/ESTOP`; `seagent resume` removes it. While it exists
//! the scheduler, goals, channel turns and new runs skip work; in-flight work is never
//! killed. A corrupt or empty file still counts as engaged (fail safe), and so does a
//! stat error.

use serde_json::json;
use std::path::{Path, PathBuf};

pub const SENTINEL: &str = "ESTOP";

pub fn sentinel(data_dir: &Path) -> PathBuf {
    data_dir.join(SENTINEL)
}

pub fn is_engaged(data_dir: &Path) -> bool {
    match std::fs::symlink_metadata(sentinel(data_dir)) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Engage (idempotent; re-engaging updates the reason).
pub fn engage(data_dir: &Path, reason: Option<&str>) -> Result<PathBuf, String> {
    let p = sentinel(data_dir);
    std::fs::create_dir_all(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let body = json!({"engaged_at": crate::now_rfc3339(), "reason": reason.filter(|r| !r.trim().is_empty())});
    if std::fs::write(&p, format!("{}\n", serde_json::to_string_pretty(&body).unwrap_or_default())).is_err() {
        std::fs::File::create(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    Ok(p)
}

/// Lift the stop; false when it was not engaged.
pub fn disengage(data_dir: &Path) -> bool {
    std::fs::remove_file(sentinel(data_dir)).is_ok()
}

/// `(reason, engaged_at)` when engaged; both None for an unreadable body.
pub fn state(data_dir: &Path) -> Option<(Option<String>, Option<String>)> {
    if !is_engaged(data_dir) {
        return None;
    }
    let v: serde_json::Value = std::fs::read_to_string(sentinel(data_dir)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(String::from);
    Some((s("reason"), s("engaged_at")))
}

/// Short notice for new channel turns, or None when not paused.
pub fn paused_reply(data_dir: &Path) -> Option<String> {
    let (reason, _) = state(data_dir)?;
    let tag = reason.map(|r| format!(" ({r})")).unwrap_or_default();
    Some(format!("⏸️ seagent is paused{tag}. New work is on hold; run `seagent resume` to pick things back up."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engage_state_and_resume() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-estop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert!(!is_engaged(&d) && paused_reply(&d).is_none());
        engage(&d, Some("maintenance")).unwrap();
        assert!(is_engaged(&d));
        assert_eq!(state(&d).unwrap().0.as_deref(), Some("maintenance"));
        assert!(paused_reply(&d).unwrap().contains("(maintenance)"));
        // A corrupt body still pauses.
        std::fs::write(sentinel(&d), "{not json").unwrap();
        assert_eq!(state(&d), Some((None, None)));
        assert!(disengage(&d) && !is_engaged(&d) && !disengage(&d));
    }
}
