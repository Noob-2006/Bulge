use super::*;
use crate::commands::BaseEntry;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("bulge-slot-{}-{label}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file(data: &[u8]) -> Entry {
    Entry::File {
        data: data.to_vec(),
        mode: 0o644,
    }
}

#[test]
fn validate_slot_accepts_only_configured_indices() {
    for slot in 0..MAX_SLOTS {
        assert_eq!(validate_slot(slot), Ok(slot));
    }
    assert!(validate_slot(MAX_SLOTS).is_err());
    assert!(validate_slot(u8::MAX).is_err());
}

#[test]
fn stage_slots_must_be_valid_and_different() {
    assert_eq!(validate_stage_slots(1, 2), Ok((1, 2)));
    assert!(validate_stage_slots(3, 3).is_err());
    assert!(validate_stage_slots(MAX_SLOTS, 0).is_err());
    assert!(validate_stage_slots(0, MAX_SLOTS).is_err());
}

#[test]
fn parses_stage_params_and_helper_request() {
    let params: SlotStageParams = serde_json::from_str(r#"{"slot":2,"from":1,"paths":["a.txt","dir/b"]}"#)
        .expect("stage params");
    assert_eq!((params.slot, params.from), (2, 1));
    assert_eq!(params.paths, vec!["a.txt".to_owned(), "dir/b".to_owned()]);
    assert!(serde_json::from_str::<SlotStageParams>(r#"{"slot":2,"from":1,"paths":[],"extra":true}"#).is_err());

    let request = parse_helper_request(r#"{"id":11,"op":"stage","slot":2,"from":1,"paths":["a.txt"]}"#)
        .expect("helper stage request");
    assert_eq!(request.op, "stage");
    assert_eq!((request.slot, request.from), (2, 1));
    assert_eq!(request.paths, vec!["a.txt".to_owned()]);
    let legacy = parse_helper_request(r#"{"id":1,"op":"open","slot":0}"#).expect("legacy request");
    assert_eq!(legacy.from, 0);
}

#[test]
fn validate_rel_path_accepts_and_normalises_safe_paths() {
    assert_eq!(validate_rel_path("a/b.txt").unwrap(), PathBuf::from("a/b.txt"));
    assert_eq!(validate_rel_path("a//b.txt").unwrap(), PathBuf::from("a/b.txt"));
    assert_eq!(validate_rel_path("a/").unwrap(), PathBuf::from("a"));
}

#[test]
fn validate_rel_path_rejects_unsafe_paths() {
    for path in [
        "/etc/passwd",
        "../x",
        "a/../b",
        "./a",
        "",
        "a\0b",
        ".overlay-x/y",
        ".overlay",
        "a/.overlay-whiteout",
    ] {
        assert!(validate_rel_path(path).is_err(), "should reject {path:?}");
    }
}

#[test]
fn identical_concurrent_changes_are_not_conflicts() {
    let base = file(b"VERSION = 1.0");
    let both = file(b"VERSION = 1.1");
    // Another slot already merged the same edit: converged.
    assert_eq!(merge_decision(Some(&base), Some(&both), Some(&both)), Decision::Nothing);
    // Both created the same directory.
    assert_eq!(merge_decision(None, Some(&Entry::Dir), Some(&Entry::Dir)), Decision::Nothing);
    // A different edit on top of someone else's change still conflicts.
    assert!(matches!(merge_decision(Some(&base), Some(&file(b"VERSION = 2.0")), Some(&both)), Decision::Conflict(_)));
}

#[test]
fn merge_decision_table() {
    let base = file(b"base");
    let changed = file(b"slot");
    let main_changed = file(b"main");

    // unchanged main -> apply
    assert_eq!(merge_decision(Some(&base), Some(&changed), Some(&base)), Decision::Apply);
    // main changed -> conflict
    assert!(matches!(
        merge_decision(Some(&base), Some(&changed), Some(&main_changed)),
        Decision::Conflict(_)
    ));
    // both deleted -> nothing to do
    assert_eq!(merge_decision(Some(&base), None, None), Decision::Nothing);
    // added in slot, absent in main -> apply
    assert_eq!(merge_decision(None, Some(&changed), None), Decision::Apply);
    // added in both differently -> conflict
    assert!(matches!(
        merge_decision(None, Some(&changed), Some(&main_changed)),
        Decision::Conflict(_)
    ));
    // unchanged main and slot deleted -> delete
    assert_eq!(merge_decision(Some(&base), None, Some(&base)), Decision::Apply);
    // type change on main since the base -> conflict
    assert!(matches!(
        merge_decision(Some(&base), Some(&changed), Some(&Entry::Dir)),
        Decision::Conflict(_)
    ));
}

#[test]
fn slot_base_prefers_snapshot_then_lower_and_honours_whiteouts() {
    let snap = TempDir::new("snap");
    let lower = TempDir::new("lower");
    std::fs::write(snap.path().join("in-snap.txt"), b"snap").unwrap();
    std::fs::write(lower.path().join("in-snap.txt"), b"lower").unwrap();
    std::fs::write(lower.path().join("only-lower.txt"), b"lower").unwrap();
    std::fs::write(snap.path().join("whited.txt"), b"whiteout placeholder").unwrap();
    std::fs::write(lower.path().join("whited.txt"), b"lower").unwrap();

    let no_whiteout = |_: &Path| false;
    let snap_entry = slot_base_entry(snap.path(), lower.path(), Path::new("in-snap.txt"), &no_whiteout);
    assert_eq!(snap_entry, BaseEntry::File(snap.path().join("in-snap.txt")));
    assert_eq!(std::fs::read(snap_entry.file_path().unwrap()).unwrap(), b"snap");

    let lower_entry = slot_base_entry(snap.path(), lower.path(), Path::new("only-lower.txt"), &no_whiteout);
    assert_eq!(lower_entry, BaseEntry::File(lower.path().join("only-lower.txt")));

    let whiteout = |path: &Path| path.file_name().is_some_and(|name| name == "whited.txt");
    assert_eq!(
        slot_base_entry(snap.path(), lower.path(), Path::new("whited.txt"), &whiteout),
        BaseEntry::Absent
    );
    assert_eq!(
        slot_base_entry(snap.path(), lower.path(), Path::new("missing.txt"), &no_whiteout),
        BaseEntry::Absent
    );
}

#[test]
fn parses_helper_request_line() {
    let request = parse_helper_request(r#"{"id":9,"op":"merge","slot":2,"paths":["a/b"]}"#).unwrap();
    assert_eq!(request.id, 9);
    assert_eq!(request.op, "merge");
    assert_eq!(request.slot, 2);
    assert_eq!(request.paths, vec!["a/b".to_owned()]);
    // Unknown operation fields are rejected as malformed.
    assert!(parse_helper_request(r#"{"id":1,"op":"open","slot":0,"extra":1}"#).is_err());
    assert!(parse_helper_request(r#"{"id":1,"op":"open","slot":256}"#).is_err());
}

#[test]
fn parses_slot_request_line() {
    let request = parse_slot_request(
        r#"{"id":7,"command":"read","params":{"path":"a"},"timeout_ms":250}"#,
    )
    .unwrap();
    assert_eq!(request.id, 7);
    assert_eq!(request.command, "read");
    assert_eq!(request.params, json!({"path": "a"}));
    assert_eq!(request.timeout_ms, Some(250));
    assert!(parse_slot_request(r#"{"id":1,"command":"read","extra":true}"#).is_err());
}

#[test]
fn parses_helper_error_response() {
    let reply = parse_helper_response(
        r#"{"id":3,"err":{"code":"INVALID_PARAMS","message":"bad path"}}"#,
    )
    .unwrap();
    assert_eq!(
        reply,
        HelperReply::Err {
            id: 3,
            code: "INVALID_PARAMS".into(),
            message: "bad path".into(),
        }
    );
    let ok = parse_helper_response(r#"{"id":4,"ok":{"slot":4}}"#).unwrap();
    assert_eq!(ok, HelperReply::Ok { id: 4, value: json!({"slot": 4}) });
    let null = parse_helper_response(r#"{"id":5,"ok":null}"#).unwrap();
    assert_eq!(null, HelperReply::Ok { id: 5, value: Value::Null });
    assert!(parse_helper_response(r#"{"id":1,"ok":{"x":1},"err":{"code":"X","message":"y"}}"#).is_err());
}
