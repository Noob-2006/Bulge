//! Workboard "Sessions boards": columns with rules over ark session facts (run
//! state, health derived from the last turn, pull-request links). Placement: an
//! operator pin whose column still exists, else the first matching column, else the
//! fallback. Never holds cards.

use super::boards::{self, MetaPatch};
use super::store::{self, Placement};
use super::now;
use crate::event::EventKind;
use serde_json::{json, Value};
use std::path::Path;

pub const HEALTH: &[&str] = &["on-track", "grinding", "stuck", "waiting-on-user", "wrapping-up", "done", "failed"];
const COLORS: &[&str] = &["red", "blue", "green", "yellow", "purple", "orange", "pink", "cyan"];

pub fn default_spec() -> Value {
    json!({"columns": [
        {"id": "needs-input", "label": "Needs input", "color": "yellow", "description": "Observer health is waiting-on-user.", "match": {"health": ["waiting-on-user"]}},
        {"id": "stuck", "label": "Stuck", "color": "red", "description": "Observer health is stuck or failed, or the run failed.", "match": [{"health": ["stuck", "failed"]}, {"run": ["failed"]}]},
        {"id": "working", "label": "Working", "color": "blue", "description": "The run is active.", "match": {"run": ["active"]}},
        {"id": "in-review", "label": "In review", "color": "orange", "description": "A pull request is open or draft.", "match": {"pullRequest": ["open", "draft"]}},
        {"id": "merged", "label": "Merged", "color": "purple", "description": "A pull request is merged.", "match": {"pullRequest": ["merged"]}},
        {"id": "done", "label": "Done", "color": "green", "description": "Observer health is done, or no earlier column rule matches.", "match": {"health": ["done"]}, "fallback": true}
    ]})
}

/// Explicit board, else the only Sessions board.
pub fn resolve_board_id(data: &Path, board: Option<&str>) -> Result<String, String> {
    if let Some(b) = board {
        let s = super::normalize_slug(Some(b))?.unwrap_or_default();
        if boards::read_meta(data, &s).kind != "sessions" || !boards::board_exists(data, &s) {
            return Err(format!("board {s} is not a Sessions board."));
        }
        return Ok(s);
    }
    let v: Vec<String> = boards::list_boards(data, false).into_iter().filter(|m| m.kind == "sessions").map(|m| m.slug).collect();
    match v.len() {
        0 => Err("No Sessions board exists. Create one with workboard_board_create and kind: \"sessions\".".into()),
        1 => Ok(v[0].clone()),
        _ => Err("boardId is required when more than one Sessions board exists. Use workboard_boards to choose one.".into()),
    }
}

fn choices(v: &Value, name: &str, allowed: &[&str]) -> Result<(), String> {
    let a = v.as_array().ok_or_else(|| format!("{name} must be an array."))?;
    for x in a {
        if !x.as_str().is_some_and(|s| allowed.contains(&s)) {
            return Err(format!("{name} values must be one of: {}.", allowed.join(", ")));
        }
    }
    Ok(())
}

fn validate_rule(r: &Value) -> Result<(), String> {
    let o = r.as_object().ok_or("match rule must be an object.")?;
    for (k, v) in o {
        match k.as_str() {
            "health" => choices(v, "health", HEALTH)?,
            "run" => choices(v, "run", &["active", "idle", "failed"])?,
            "pullRequest" => choices(v, "pullRequest", &["none", "open", "draft", "merged", "closed"])?,
            "archived" => {
                if !v.is_boolean() {
                    return Err("archived must be a boolean.".into());
                }
            }
            other => return Err(format!("Unknown match field: {other}.")),
        }
    }
    Ok(())
}

pub fn validate_columns(cols: &Value) -> Result<(), String> {
    let a = cols.as_array().ok_or("columns must be an array.")?;
    if !(2..=12).contains(&a.len()) {
        return Err("columns must have 2..12 entries.".into());
    }
    let mut ids = vec![];
    let mut fallbacks = 0;
    for c in a {
        let id = c["id"].as_str().unwrap_or("");
        let ok = !id.is_empty() && id.len() <= 48 && id.chars().next().is_some_and(|x| x.is_ascii_lowercase() || x.is_ascii_digit()) && id.chars().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == '-');
        if !ok {
            return Err(format!("column id {id:?} must be a lowercase slug of 1..48 characters."));
        }
        if ids.contains(&id) {
            return Err(format!("duplicate column id: {id}."));
        }
        ids.push(id);
        let label = c["label"].as_str().map(str::trim).unwrap_or("");
        if label.is_empty() || label.chars().count() > 60 {
            return Err("column label must be a string with 1..60 characters.".into());
        }
        let desc = c["description"].as_str().map(str::trim).unwrap_or("");
        if desc.is_empty() || desc.chars().count() > 400 {
            return Err("column description must be a string with 1..400 characters.".into());
        }
        if let Some(col) = c.get("color").and_then(|v| v.as_str()) {
            if !COLORS.contains(&col) {
                return Err(format!("column color must be one of: {}.", COLORS.join(", ")));
            }
        }
        match c.get("match") {
            None | Some(Value::Null) => {}
            Some(Value::Array(rs)) if !rs.is_empty() => rs.iter().try_for_each(validate_rule)?,
            Some(r @ Value::Object(_)) => validate_rule(r)?,
            _ => return Err("match must be a rule or a non-empty array of rules.".into()),
        }
        if c["fallback"] == true {
            fallbacks += 1;
        }
    }
    if fallbacks != 1 {
        return Err("Exactly one column must be the fallback.".into());
    }
    Ok(())
}

/// Facts for every ark session in scope.
pub fn facts(data: &Path, scope: &Value) -> Vec<Value> {
    let st = crate::store::Store::new(data.join("sessions"));
    let max_age = scope["maxAgeHours"].as_f64().unwrap_or(72.0);
    let automation = scope["includeAutomation"] == true;
    let cutoff = crate::event::now_ms().saturating_sub((max_age * 3_600_000.0) as u64);
    let k = super::kernel();
    static PR: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pr = PR.get_or_init(|| regex::Regex::new(r"https://github\.com/[^/\s]+/[^/\s]+/pull/(\d+)").unwrap());
    let mut out = vec![];
    for s in st.list().into_iter().filter(|s| s.parent.is_none() && s.updated_ms >= cutoff) {
        let title = s.title.clone().unwrap_or_default();
        if !automation && (title.starts_with("cron ") || title.starts_with("goal: ") || title.starts_with("kanban ")) {
            continue;
        }
        let Ok(events) = st.read(&s.id) else { continue };
        let running = k.as_ref().is_some_and(|k| k.is_running(&s.id));
        let last_end = events.iter().rev().find_map(|e| match &e.kind {
            EventKind::TurnEnd { reason, .. } => Some(reason.clone()),
            _ => None,
        });
        let open_turn = events.iter().rev().find_map(|e| match e.kind {
            EventKind::TurnStart { .. } => Some(true),
            EventKind::TurnEnd { .. } => Some(false),
            _ => None,
        }) == Some(true);
        let failed = last_end.as_deref().is_some_and(|r| r.starts_with("error") || r.starts_with("refusal"));
        let run = if running || (k.is_none() && open_turn) { "active" } else if failed { "failed" } else { "idle" };
        let health = if run == "active" {
            "on-track"
        } else {
            match last_end.as_deref() {
                Some(r) if r.starts_with("stuck") || r.starts_with("budget") || r.starts_with("max") => "stuck",
                Some(r) if r.starts_with("error") || r.starts_with("refusal") => "failed",
                Some(_) => "done",
                None => "waiting-on-user",
            }
        };
        let mut prs: Vec<Value> = vec![];
        let mut preview = String::new();
        for e in &events {
            if let EventKind::Message { message, .. } = &e.kind {
                let t = message.text();
                for c in pr.captures_iter(&t) {
                    let url = c[0].to_string();
                    if !prs.iter().any(|p| p["url"] == url) {
                        prs.push(json!({"number": c[1].parse::<u64>().unwrap_or(0), "url": url}));
                    }
                }
                if message.role == ark_core::Role::Assistant && !t.trim().is_empty() {
                    preview = t.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(400).collect();
                }
            }
        }
        // PR state needs GitHub; links without a known state are "unavailable", never "none".
        out.push(json!({"key": s.id, "sessionId": s.id, "agentId": "ark", "label": s.title, "lastMessagePreview": preview, "run": run, "observerDigest": {"health": health, "headline": last_end.clone().unwrap_or_default(), "revision": events.len()}, "pullRequests": [], "pullRequestLinks": prs, "pullRequestsUnavailable": !prs.is_empty(), "archived": false, "lastActivityAt": s.updated_ms}));
    }
    out
}

fn rule_matches(f: &Value, r: &Value) -> bool {
    let has = |k: &str, v: &Value| r.get(k).and_then(|a| a.as_array()).is_none_or(|a| a.contains(v));
    let health_ok = r.get("health").is_none() || f["observerDigest"]["health"].as_str().is_some_and(|h| has("health", &json!(h)));
    let pr_ok = r.get("pullRequest").is_none_or(|want| f["pullRequestsUnavailable"] != true && match f["pullRequests"].as_array() {
        Some(a) if !a.is_empty() => a.iter().any(|p| want.as_array().is_some_and(|w| w.contains(&p["state"]))),
        _ => want.as_array().is_some_and(|w| w.contains(&json!("none"))),
    });
    health_ok && has("run", &f["run"]) && r.get("archived").is_none_or(|a| a == &f["archived"]) && pr_ok
}

fn place(cols: &[Value], pins: &[Placement], f: &Value) -> (String, &'static str, String) {
    let key = f["key"].as_str().unwrap_or("");
    if let Some(p) = pins.iter().find(|p| p.session_key == key && cols.iter().any(|c| c["id"] == p.column_id)) {
        return (p.column_id.clone(), "operator", "pinned".into());
    }
    for c in cols {
        let rules: Vec<&Value> = match c.get("match") {
            Some(Value::Array(a)) => a.iter().collect(),
            Some(r @ Value::Object(_)) => vec![r],
            _ => vec![],
        };
        if rules.iter().any(|r| rule_matches(f, r)) {
            return (c["id"].as_str().unwrap_or("").into(), "state", "by rule".into());
        }
    }
    let fb = cols.iter().find(|c| c["fallback"] == true).and_then(|c| c["id"].as_str()).unwrap_or("");
    (fb.into(), "state", "fallback".into())
}

pub fn read(data: &Path, slug: &str) -> Result<Value, String> {
    let m = boards::read_meta(data, slug);
    let spec = m.sessions.clone().unwrap_or_else(default_spec);
    let cols: Vec<Value> = spec["columns"].as_array().cloned().unwrap_or_default();
    let pins = store::read_board(data, slug)?.placements;
    let mut sessions = facts(data, &spec["scope"]);
    let total = sessions.len();
    sessions.truncate(100);
    for f in sessions.iter_mut() {
        let (col, source, reason) = place(&cols, &pins, f);
        f["columnId"] = col.into();
        f["source"] = source.into();
        f["reason"] = reason.into();
    }
    Ok(json!({"board": m, "columns": cols, "sessions": sessions, "total": total}))
}

pub fn update(data: &Path, slug: &str, patch: &Value) -> Result<Value, String> {
    let m = boards::read_meta(data, slug);
    let mut spec = m.sessions.clone().unwrap_or_else(default_spec);
    if let Some(cols) = patch.get("columns") {
        validate_columns(cols)?;
        spec["columns"] = cols.clone();
    }
    if let Some(sc) = patch.get("scope") {
        let o = sc.as_object().ok_or("scope must be an object.")?;
        for (k, v) in o {
            match k.as_str() {
                "agentIds" => {
                    if !v.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty()))) {
                        return Err("scope.agentIds must be an array of non-empty strings.".into());
                    }
                }
                "includeArchived" | "includeAutomation" | "includeHome" => {
                    if !v.is_boolean() {
                        return Err(format!("scope.{k} must be a boolean."));
                    }
                }
                "maxAgeHours" => {
                    if !v.as_f64().is_some_and(|x| x > 0.0) {
                        return Err("scope.maxAgeHours must be a positive number.".into());
                    }
                }
                o => return Err(format!("Unknown scope field: {o}.")),
            }
        }
        spec["scope"] = sc.clone();
    }
    let m = boards::write_meta(data, slug, MetaPatch { sessions: Some(spec), ..Default::default() })?;
    serde_json::to_value(m).map_err(|e| e.to_string())
}

pub fn pin(data: &Path, slug: &str, session: &str, column: &str) -> Result<Value, String> {
    let spec = boards::read_meta(data, slug).sessions.unwrap_or_else(default_spec);
    if !spec["columns"].as_array().is_some_and(|a| a.iter().any(|c| c["id"] == column)) {
        return Err(format!("column not found: {column}"));
    }
    store::with_board(data, slug, |b| {
        b.placements.retain(|p| p.session_key != session);
        b.placements.push(Placement { session_key: session.into(), column_id: column.into(), updated_at: now() });
        Ok(())
    })?;
    read(data, slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_pins_and_validation() {
        let d = crate::kanban::testutil::data();
        boards::create_board(&d, "chat", MetaPatch { kind: Some("sessions".into()), ..Default::default() }).unwrap();
        assert_eq!(resolve_board_id(&d, None).unwrap(), "chat");
        assert!(resolve_board_id(&d, Some("default")).is_err());
        let cols: Vec<Value> = default_spec()["columns"].as_array().unwrap().clone();
        let f = |run: &str, health: &str| json!({"key": "s1", "run": run, "observerDigest": {"health": health}, "pullRequests": [], "pullRequestsUnavailable": false, "archived": false});
        assert_eq!(place(&cols, &[], &f("active", "on-track")).0, "working");
        assert_eq!(place(&cols, &[], &f("failed", "done")).0, "stuck");
        assert_eq!(place(&cols, &[], &f("idle", "waiting-on-user")).0, "needs-input");
        assert_eq!(place(&cols, &[], &f("idle", "grinding")).0, "done", "fallback");
        let mut merged = f("idle", "grinding");
        merged["pullRequests"] = json!([{"number": 1, "state": "merged"}]);
        assert_eq!(place(&cols, &[], &merged).0, "merged");
        let mut unk = f("idle", "grinding");
        unk["pullRequestsUnavailable"] = true.into();
        assert_eq!(place(&cols, &[], &unk).0, "done", "unknown PR state is not none");
        let r = pin(&d, "chat", "s1", "stuck").unwrap();
        assert!(r["columns"].is_array());
        let pins = store::read_board(&d, "chat").unwrap().placements;
        assert_eq!(place(&cols, &pins, &f("active", "on-track")), ("stuck".into(), "operator", "pinned".into()));
        assert!(pin(&d, "chat", "s1", "nope").is_err());
        assert!(update(&d, "chat", &json!({"columns": [{"id": "a", "label": "A", "description": "x"}, {"id": "b", "label": "B", "description": "y"}]})).unwrap_err().contains("fallback"));
        assert!(update(&d, "chat", &json!({"columns": [{"id": "a", "label": "A", "description": "x", "match": {"bogus": []}}, {"id": "b", "label": "B", "description": "y", "fallback": true}]})).is_err());
        let m = update(&d, "chat", &json!({"columns": [{"id": "a", "label": "A", "description": "x", "match": {"run": ["active"]}}, {"id": "b", "label": "B", "description": "y", "fallback": true}], "scope": {"maxAgeHours": 1}})).unwrap();
        assert_eq!(m["sessions"]["columns"].as_array().unwrap().len(), 2);
        assert!(update(&d, "chat", &json!({"scope": {"maxAgeHours": 0}})).is_err());
        // Pinned column removed: rules apply again.
        let cols2 = boards::read_meta(&d, "chat").sessions.unwrap()["columns"].as_array().unwrap().clone();
        assert_eq!(place(&cols2, &pins, &f("active", "on-track")).0, "a");
    }
}
