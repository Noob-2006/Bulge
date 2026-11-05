//! Session review: a reviewer marks a session `reviewed` or `flagged` (or `cleared`) with a
//! note. Supervisors, compliance and incident response use it to say "someone looked at
//! this conversation, and this is what they found".
//!
//! Marks are append-only (`<data>/reviews/reviews.jsonl`): the current state of a session is
//! its newest mark, the history is every mark. Each mark is also an audit record
//! (`session.review`, with who reviewed and the status; the note text itself stays in the
//! review file — the audit stream carries metadata only). A reviewer cannot review a
//! session they own: the point is a second pair of eyes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const STATUSES: &[&str] = &["reviewed", "flagged", "cleared"];
const MAX_NOTE: usize = 4000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Review {
    pub session: String,
    /// `reviewed`, `flagged` or `cleared` (withdraws an earlier mark).
    pub status: String,
    #[serde(default)]
    pub note: String,
    /// `kind:name` of the reviewer.
    pub by: String,
    pub at_ms: u64,
}

pub fn path(data: &Path) -> PathBuf {
    data.join("reviews").join("reviews.jsonl")
}

/// Every mark, oldest first.
pub fn all(data: &Path) -> Vec<Review> {
    std::fs::read_to_string(path(data))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Mark `session`. `owner` is the session's owner label (see
/// [`crate::governance::owner_label_in`]).
pub fn set(
    data: &Path,
    session: &str,
    status: &str,
    note: &str,
    by: &seagent_security::audit::Actor,
    owner: &str,
) -> Result<Review, String> {
    use std::os::unix::fs::OpenOptionsExt;
    if session.trim().is_empty() {
        return Err("missing session id".into());
    }
    if !STATUSES.contains(&status) {
        return Err(format!(
            "status `{status}`: use reviewed, flagged or cleared"
        ));
    }
    if by.role.split('+').all(|r| r == "auditor") && !by.role.is_empty() {
        return Err("auditors read; they do not mark sessions".into());
    }
    let label = by.label();
    if crate::governance::same_person(data, &label, owner) {
        return Err(format!(
            "`{label}` owns session {session} and cannot review it"
        ));
    }
    let r = Review {
        session: session.into(),
        status: status.into(),
        note: note.chars().take(MAX_NOTE).collect(),
        by: label,
        at_ms: seagent_security::audit::now_ms(),
    };
    let p = path(data);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    writeln!(f, "{}", serde_json::to_string(&r).unwrap_or_default()).map_err(|e| e.to_string())?;
    seagent_security::audit::emit(
        data,
        seagent_security::audit::Event::new("session.review", by.clone(), session, status).session(session).detail(serde_json::json!({"owner": owner, "has_note": !r.note.is_empty(), "note_sha256": seagent_security::audit::sha256_hex(r.note.as_bytes())})),
    )?;
    Ok(r)
}

/// The current mark of each session (newest wins; `cleared` drops it), newest first,
/// optionally only one status.
pub fn current(data: &Path, status: Option<&str>) -> Vec<Review> {
    let mut by: BTreeMap<String, Review> = BTreeMap::new();
    for r in all(data) {
        by.insert(r.session.clone(), r);
    }
    let mut v: Vec<Review> = by
        .into_values()
        .filter(|r| r.status != "cleared" && status.is_none_or(|s| r.status == s))
        .collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    v
}

/// One session's marks, oldest first.
pub fn history(data: &Path, session: &str) -> Vec<Review> {
    all(data)
        .into_iter()
        .filter(|r| r.session == session)
        .collect()
}

/// `session.review.set|list|get` for the daemon and the app server.
pub fn rpc(
    rt: &crate::kernel::Runtime,
    method: &str,
    p: &serde_json::Value,
) -> Option<Result<serde_json::Value, (i32, String)>> {
    use serde_json::json;
    let data = &rt.paths.data;
    let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
    Some(match method {
        "session.review.set" => {
            let id = s("id");
            if !rt.store.exists(&id) {
                return Some(Err((-32602, format!("no such session `{id}`"))));
            }
            let who = match p["_by"].as_str() {
                Some(b) => seagent_security::audit::Actor::parse_label(b)
                    .with_role(p["_by_role"].as_str().unwrap_or("")),
                None => seagent_security::audit::Actor::local(),
            };
            let owner = crate::governance::owner_label_in(&rt.paths, &rt.store, &id);
            set(data, &id, &s("status"), &s("note"), &who, &owner)
                .map(|r| json!(r))
                .map_err(|e| (-32003, e))
        }
        "session.review.list" => {
            let st = p["status"].as_str().filter(|x| !x.is_empty());
            let lim = p["limit"].as_u64().unwrap_or(200) as usize;
            Ok(json!(current(data, st)
                .into_iter()
                .take(lim)
                .collect::<Vec<_>>()))
        }
        "session.review.get" => {
            let id = s("id");
            let h = history(data, &id);
            let cur = h.last().filter(|r| r.status != "cleared").cloned();
            Ok(json!({"session": id, "current": cur, "history": h}))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_security::audit::Actor;

    #[test]
    fn marks_are_stored_audited_queryable_and_not_self_reviewed() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-review");
        let d = tmp.path();
        let rev = Actor::new("sso", "rita@corp.example").with_role("user");
        assert!(set(
            d,
            "s1",
            "reviewed",
            "ok",
            &Actor::new("sso", "own@corp.example"),
            "sso:own@corp.example"
        )
        .unwrap_err()
        .contains("cannot review"));
        assert!(set(d, "s1", "bogus", "", &rev, "sso:own").is_err());
        assert!(set(
            d,
            "s1",
            "reviewed",
            "",
            &Actor::new("token", "aud").with_role("auditor"),
            "sso:own"
        )
        .unwrap_err()
        .contains("auditors"));
        set(
            d,
            "s1",
            "flagged",
            "pasted a customer list",
            &rev,
            "sso:own",
        )
        .unwrap();
        set(d, "s2", "reviewed", "", &rev, "sso:own").unwrap();
        assert_eq!(
            current(d, Some("flagged"))
                .iter()
                .map(|r| r.session.as_str())
                .collect::<Vec<_>>(),
            ["s1"]
        );
        set(d, "s1", "cleared", "false positive", &rev, "sso:own").unwrap();
        assert!(current(d, Some("flagged")).is_empty());
        assert_eq!(history(d, "s1").len(), 2);
        let recs = seagent_security::audit::query(
            d,
            &seagent_security::audit::Query {
                kind: Some("session.review".into()),
                ..Default::default()
            },
        );
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0]["actor"]["name"], "rita@corp.example");
        assert_eq!(recs[0]["outcome"], "flagged");
        assert!(
            !recs[0].to_string().contains("customer list"),
            "the note stays out of the audit stream"
        );
        assert!(seagent_security::audit::verify(d, None).ok);
    }
}
