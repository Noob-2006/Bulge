//! Host-side client for per-agent VM workspace slots.
//!
//! A slot-capable guest exposes `slot_open`/`slot_run`/`slot_changes`/
//! `slot_export`/`slot_merge`/`slot_stage`/`slot_close`. Each slot is a private
//! overlay of the main workspace, so concurrent sub-agents never write to the
//! same files. This module only speaks the guest protocol; the CLI leases slot
//! numbers and decides what to merge back.

use std::time::Duration;

use bulge_proto::msg::Outcome;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::changes::Change;
use crate::vm::Vm;

/// Guest commands a slot-capable rootfs must advertise (checked against `Vm::commands()`).
pub const SLOT_COMMANDS: [&str; 7] = ["slot_open", "slot_run", "slot_changes", "slot_export", "slot_merge", "slot_stage", "slot_close"];

const OPEN_TIMEOUT: Duration = Duration::from_secs(120);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(120);
const MERGE_TIMEOUT: Duration = Duration::from_secs(120);
const STAGE_TIMEOUT: Duration = Duration::from_secs(300);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(300);

/// Whether this VM's rootfs was built with the slot commands.
pub fn supports_slots(vm: &Vm) -> bool {
    SLOT_COMMANDS
        .iter()
        .all(|wanted| vm.commands().iter().any(|available| available == wanted))
}

#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("this rootfs has no VM workspace slots; rebuild the rootfs with scripts/build-rootfs.sh")]
    Unsupported,
    #[error("guest {code}: {message}")]
    Guest { code: String, message: String },
    #[error("malformed guest reply: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MergeConflict {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub merged: Vec<String>,
    pub conflicts: Vec<MergeConflict>,
}

fn ensure_supported(vm: &Vm) -> Result<(), SlotError> {
    if supports_slots(vm) {
        Ok(())
    } else {
        Err(SlotError::Unsupported)
    }
}

fn value(outcome: Outcome) -> Result<Value, SlotError> {
    match outcome {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, message } => Err(SlotError::Guest { code, message }),
    }
}

fn map_change_error(error: crate::changes::ChangeError) -> SlotError {
    match error {
        crate::changes::ChangeError::Malformed(message) => SlotError::Malformed(message),
        other => SlotError::Malformed(other.to_string()),
    }
}

fn parse_merge_report(value: Value) -> Result<MergeReport, SlotError> {
    let Value::Object(mut object) = value else {
        return Err(SlotError::Malformed("merge reply is not an object".into()));
    };
    let merged = object
        .remove("merged")
        .ok_or_else(|| SlotError::Malformed("merge reply has no merged list".into()))?;
    let conflicts = object
        .remove("conflicts")
        .ok_or_else(|| SlotError::Malformed("merge reply has no conflicts list".into()))?;
    let merged = serde_json::from_value(merged).map_err(|e| SlotError::Malformed(format!("merged: {e}")))?;
    let conflicts = serde_json::from_value(conflicts).map_err(|e| SlotError::Malformed(format!("conflicts: {e}")))?;
    Ok(MergeReport { merged, conflicts })
}

fn parse_staged(value: Value) -> Result<Vec<String>, SlotError> {
    let Value::Object(mut object) = value else {
        return Err(SlotError::Malformed("stage reply is not an object".into()));
    };
    let staged = object
        .remove("staged")
        .ok_or_else(|| SlotError::Malformed("stage reply has no staged list".into()))?;
    serde_json::from_value(staged).map_err(|e| SlotError::Malformed(format!("staged: {e}")))
}

pub async fn open(vm: &Vm, slot: u8) -> Result<(), SlotError> {
    ensure_supported(vm)?;
    value(vm.invoke("slot_open", json!({ "slot": slot }), Some(OPEN_TIMEOUT)).await)?;
    Ok(())
}

pub async fn close(vm: &Vm, slot: u8) -> Result<(), SlotError> {
    ensure_supported(vm)?;
    value(vm.invoke("slot_close", json!({ "slot": slot }), Some(CLOSE_TIMEOUT)).await)?;
    Ok(())
}

/// The slot's pending changes with content, in the same `Change` type
/// `changes::collect` returns. The listing and export payloads share that
/// module's parsers so the two paths cannot drift.
pub async fn collect(vm: &Vm, slot: u8) -> Result<Vec<Change>, SlotError> {
    ensure_supported(vm)?;
    let listing = value(vm.invoke("slot_changes", json!({ "slot": slot }), Some(COLLECT_TIMEOUT)).await)?;
    let paths = crate::changes::parse_listing(listing).map_err(map_change_error)?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let export = value(vm.invoke("slot_export", json!({ "slot": slot, "paths": paths }), Some(COLLECT_TIMEOUT)).await)?;
    crate::changes::parse_export(export).map_err(map_change_error)
}

pub async fn merge(vm: &Vm, slot: u8, paths: &[String]) -> Result<MergeReport, SlotError> {
    ensure_supported(vm)?;
    let value = value(vm.invoke("slot_merge", json!({ "slot": slot, "paths": paths }), Some(MERGE_TIMEOUT)).await)?;
    parse_merge_report(value)
}

/// Copy `paths`' current versions from slot `from` into slot `slot`, so a
/// reviewer sees exactly the worker's files. Returns the staged paths.
pub async fn stage(vm: &Vm, slot: u8, from: u8, paths: &[String]) -> Result<Vec<String>, SlotError> {
    ensure_supported(vm)?;
    let value = value(
        vm.invoke("slot_stage", json!({ "slot": slot, "from": from, "paths": paths }), Some(STAGE_TIMEOUT))
            .await,
    )?;
    parse_staged(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_report_parses_merged_paths_and_conflicts() {
        let report = parse_merge_report(json!({
            "merged": ["a.txt", "dir/b.txt"],
            "conflicts": [{
                "path": "c.txt",
                "reason": "main workspace changed since the slot opened",
            }],
        }))
        .expect("valid merge report");

        assert_eq!(report.merged, vec!["a.txt".to_string(), "dir/b.txt".to_string()]);
        assert_eq!(
            report.conflicts,
            vec![MergeConflict {
                path: "c.txt".into(),
                reason: "main workspace changed since the slot opened".into(),
            }]
        );
    }

    #[test]
    fn merge_report_accepts_empty_lists() {
        let report = parse_merge_report(json!({ "merged": [], "conflicts": [] })).expect("empty merge report");
        assert_eq!(report, MergeReport::default());
    }

    #[test]
    fn merge_report_rejects_malformed_payloads() {
        assert!(matches!(parse_merge_report(json!([])), Err(SlotError::Malformed(_))));
        assert!(matches!(parse_merge_report(json!({ "merged": [] })), Err(SlotError::Malformed(_))));
        assert!(matches!(
            parse_merge_report(json!({ "merged": "nope", "conflicts": [] })),
            Err(SlotError::Malformed(_))
        ));
        assert!(matches!(
            parse_merge_report(json!({ "merged": [], "conflicts": [{ "path": "a" }] })),
            Err(SlotError::Malformed(_))
        ));
    }

    #[test]
    fn stage_reply_parses_staged_paths() {
        assert_eq!(
            parse_staged(json!({ "staged": ["a.txt", "dir/b.txt"] })).expect("valid stage reply"),
            vec!["a.txt".to_string(), "dir/b.txt".to_string()]
        );
        assert_eq!(parse_staged(json!({ "staged": [] })).expect("empty stage reply"), Vec::<String>::new());
        assert!(matches!(parse_staged(json!([])), Err(SlotError::Malformed(_))));
        assert!(matches!(parse_staged(json!({ "merged": [] })), Err(SlotError::Malformed(_))));
        assert!(matches!(parse_staged(json!({ "staged": "nope" })), Err(SlotError::Malformed(_))));
    }

    #[test]
    fn slot_commands_include_staging() {
        assert_eq!(SLOT_COMMANDS.len(), 7);
        assert!(SLOT_COMMANDS.contains(&"slot_stage"));
    }

    #[test]
    fn change_listing_and_export_parse_into_changes() {
        let paths = crate::changes::parse_listing(json!({
            "changes": [{ "path": "a.txt" }, { "path": "dir/b.txt" }],
        }))
        .expect("valid listing");
        assert_eq!(paths, vec!["a.txt".to_string(), "dir/b.txt".to_string()]);

        let changes = crate::changes::parse_export(json!({
            "files": [
                { "kind": "deleted", "path": "gone.txt" },
                { "kind": "dir", "path": "newdir" },
                {
                    "kind": "file",
                    "path": "a.txt",
                    "data_b64": "aGk=",
                    "executable": false,
                    "existed": true,
                },
            ],
        }))
        .expect("valid export");

        assert_eq!(
            changes,
            vec![
                Change::Deleted { path: "gone.txt".into() },
                Change::Dir { path: "newdir".into() },
                Change::File { path: "a.txt".into(), data: b"hi".to_vec(), executable: false, existed: true },
            ]
        );
    }

    #[test]
    fn empty_change_listing_has_no_changes() {
        let paths = crate::changes::parse_listing(json!({ "changes": [] })).expect("empty listing");
        assert!(paths.is_empty());
        let changes = crate::changes::parse_export(json!({ "files": [] })).expect("empty export");
        assert!(changes.is_empty());
    }
}
