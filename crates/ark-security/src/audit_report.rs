//! The auditor's report (`ark audit report --from --to [--format md|html|json]`, ARP
//! `audit.report`): one artefact summarising a period of the audit stream — logins,
//! privilege changes, approvals with their approvers, denied actions, configuration changes,
//! session reviews — plus the chain verification with the head hash, so the reader can tie
//! the report to the exact chain it was cut from (and to the SIEM copy).
//!
//! The report is built from the audit records only (metadata: who, what, outcome); it never
//! contains conversation content.

use crate::audit;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// Rows per section in the rendered report (the counts always cover everything).
const MAX_ROWS: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub title: &'static str,
    pub count: usize,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub seq: u64,
    pub time: String,
    pub kind: String,
    pub actor: String,
    pub target: String,
    pub outcome: String,
    /// Section-specific summary (approvers, role, reason …).
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub from_ms: u64,
    pub to_ms: u64,
    pub generated_ms: u64,
    pub records: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub sections: Vec<Section>,
    pub verify: audit::Verify,
    /// Signed-seal check (empty when no seal key is configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seals: Option<crate::audit_seal::SealCheck>,
}

fn s(r: &Value, k: &str) -> String {
    r[k].as_str().unwrap_or("").to_string()
}

fn actor(r: &Value) -> String {
    let a = &r["actor"];
    let base = format!(
        "{}:{}",
        a["kind"].as_str().unwrap_or(""),
        a["name"].as_str().unwrap_or("")
    );
    match a["role"].as_str().filter(|x| !x.is_empty()) {
        Some(role) => format!("{base} ({role})"),
        None => base,
    }
}

fn row(r: &Value, note: String) -> Row {
    Row {
        seq: r["seq"].as_u64().unwrap_or(0),
        time: crate::audit_export::rfc3339(r["ts"].as_u64().unwrap_or(0)),
        kind: s(r, "kind"),
        actor: actor(r),
        target: s(r, "target"),
        outcome: s(r, "outcome"),
        note,
    }
}

fn has_prefix(kind: &str, prefixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|p| kind == p.trim_end_matches('.') || (p.ends_with('.') && kind.starts_with(p)))
}

fn denied(r: &Value) -> bool {
    let o = r["outcome"].as_str().unwrap_or("");
    o.starts_with("deny")
        || o == "refused"
        || r["kind"]
            .as_str()
            .is_some_and(|k| k.ends_with(".denied") || k == "auth.failed")
}

fn approval_note(r: &Value) -> String {
    let d = &r["detail"];
    let mut parts = vec![];
    if let Some(t) = d["tool"].as_str() {
        parts.push(format!("tool {t}"));
    }
    if let Some(b) = d["approved_by"].as_str() {
        parts.push(format!("by {b}"));
    }
    if let Some(a) = d["approvals"].as_array().filter(|a| !a.is_empty()) {
        parts.push(format!(
            "approvals [{}]",
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(q) = d["requester"].as_str() {
        parts.push(format!("requested by {q}"));
    }
    if d["dual_control"] == true {
        parts.push(format!(
            "dual control ({} required)",
            d["required"].as_u64().unwrap_or(2)
        ));
    }
    if let Some(x) = d["reason"].as_str() {
        parts.push(x.to_string());
    }
    parts.join("; ")
}

fn detail_note(r: &Value) -> String {
    match &r["detail"] {
        Value::Null => String::new(),
        d => {
            let t = audit::canonical(d);
            if t.chars().count() > 200 {
                format!("{}…", t.chars().take(200).collect::<String>())
            } else {
                t
            }
        }
    }
}

/// Build the report for `[from_ms, to_ms)` (0 = open end).
pub fn build(data: &Path, from_ms: u64, to_ms: u64, seal_key: Option<&[u8]>) -> Report {
    let to = if to_ms == 0 { u64::MAX } else { to_ms };
    let recs: Vec<Value> = audit::all(data)
        .into_iter()
        .filter(|r| r["ts"].as_u64().is_some_and(|t| t >= from_ms && t < to))
        .collect();
    let mut by_kind = BTreeMap::new();
    for r in &recs {
        *by_kind.entry(s(r, "kind")).or_insert(0usize) += 1;
    }
    let section =
        |title: &'static str, pick: &dyn Fn(&Value) -> bool, note: &dyn Fn(&Value) -> String| {
            let hits: Vec<&Value> = recs.iter().filter(|r| pick(r)).collect();
            Section {
                title,
                count: hits.len(),
                rows: hits
                    .iter()
                    .take(MAX_ROWS)
                    .map(|r| row(r, note(r)))
                    .collect(),
            }
        };
    let kind = |r: &Value| s(r, "kind");
    let sections = vec![
        section(
            "Logins and sessions",
            &|r| {
                has_prefix(
                    &kind(r),
                    &["auth.login", "auth.logout", "auth.failed", "auth.revoked"],
                )
            },
            &|r| {
                r["actor"]["ip"]
                    .as_str()
                    .map(|ip| format!("from {ip}"))
                    .unwrap_or_default()
            },
        ),
        section(
            "Privilege and identity changes",
            &|r| {
                has_prefix(
                    &kind(r),
                    &[
                        "token.",
                        "user.",
                        "scim.user.",
                        "scim.group.",
                        "account.",
                        "tenancy.",
                        "role.",
                    ],
                )
            },
            &detail_note,
        ),
        section(
            "Approvals",
            &|r| has_prefix(&kind(r), &["approval."]),
            &approval_note,
        ),
        section(
            "Denied actions",
            &|r| denied(r) && !has_prefix(&kind(r), &["approval."]),
            &|r| {
                r["detail"]["reason"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| detail_note(r))
            },
        ),
        section(
            "Configuration changes",
            &|r| {
                has_prefix(
                    &kind(r),
                    &[
                        "config.",
                        "secret.",
                        "cluster.policy.",
                        "retention.hold_added",
                        "retention.hold_released",
                        "hooks.",
                        "plugin.",
                        "audit.seal_key",
                    ],
                )
            },
            &detail_note,
        ),
        section("Session reviews", &|r| kind(r) == "session.review", &|r| {
            format!("owner {}", r["detail"]["owner"].as_str().unwrap_or("?"))
        }),
        section(
            "Exports and retention",
            &|r| {
                has_prefix(
                    &kind(r),
                    &[
                        "ediscovery.",
                        "session.export",
                        "retention.run",
                        "retention.audit_pruned",
                        "audit.",
                    ],
                ) && kind(r) != "audit.seal_key"
            },
            &detail_note,
        ),
    ];
    let seals = seal_key.map(|k| crate::audit_seal::check_all(data, k));
    Report {
        from_ms,
        to_ms,
        generated_ms: audit::now_ms(),
        records: recs.len(),
        by_kind,
        sections,
        verify: audit::verify(data, None),
        seals,
    }
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn markdown(r: &Report) -> String {
    let t = |ms: u64| {
        if ms == 0 || ms == u64::MAX {
            "—".to_string()
        } else {
            crate::audit_export::rfc3339(ms)
        }
    };
    let mut o = format!(
        "# ark audit report\n\n- Period: {} → {}\n- Generated: {}\n- Records in period: {}\n\n",
        t(r.from_ms),
        t(r.to_ms),
        t(r.generated_ms),
        r.records
    );
    o.push_str("## Chain integrity\n\n");
    o.push_str(&format!(
        "- Result: **{}**{}\n- Segments: {} · events: {} · seq {}–{}\n- Head hash: `{}`\n- Anchor (prev of oldest record): `{}`\n",
        if r.verify.ok { "OK" } else { "FAILED" },
        r.verify.error.as_ref().map(|e| format!(" — {e}")).unwrap_or_default(),
        r.verify.segments,
        r.verify.events,
        r.verify.first_seq,
        r.verify.last_seq,
        if r.verify.head.is_empty() { "-" } else { &r.verify.head },
        if r.verify.anchor.is_empty() { "genesis" } else { &r.verify.anchor },
    ));
    if let Some(s) = &r.seals {
        o.push_str(&format!(
            "- Signed seals: {} signed, {} unsigned, {} timestamped{}\n",
            s.signed,
            s.unsigned,
            s.timestamped,
            if s.errors.is_empty() {
                String::new()
            } else {
                format!(" — **errors:** {}", s.errors.join("; "))
            }
        ));
    }
    o.push_str("\n## Summary\n\n| Section | Records |\n|---|---|\n");
    for s in &r.sections {
        o.push_str(&format!("| {} | {} |\n", s.title, s.count));
    }
    for s in &r.sections {
        o.push_str(&format!("\n## {} ({})\n\n", s.title, s.count));
        if s.rows.is_empty() {
            o.push_str("None in this period.\n");
            continue;
        }
        o.push_str("| seq | time | kind | actor | target | outcome | details |\n|---|---|---|---|---|---|---|\n");
        for x in &s.rows {
            o.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                x.seq,
                x.time,
                md_cell(&x.kind),
                md_cell(&x.actor),
                md_cell(&x.target),
                md_cell(&x.outcome),
                md_cell(&x.note)
            ));
        }
        if s.count > s.rows.len() {
            o.push_str(&format!(
                "\n… {} more (use `ark audit events` for all of them)\n",
                s.count - s.rows.len()
            ));
        }
    }
    o.push_str("\n## Records by kind\n\n| kind | count |\n|---|---|\n");
    for (k, n) in &r.by_kind {
        o.push_str(&format!("| {} | {n} |\n", md_cell(k)));
    }
    o
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Self-contained HTML (no scripts, no external resources): prints and archives as is.
pub fn html(r: &Report) -> String {
    let t = |ms: u64| {
        if ms == 0 || ms == u64::MAX {
            "—".to_string()
        } else {
            crate::audit_export::rfc3339(ms)
        }
    };
    let mut o = String::from("<!doctype html><html><head><meta charset=\"utf-8\"><title>ark audit report</title><style>body{font:14px system-ui,sans-serif;margin:2em;color:#111}table{border-collapse:collapse;margin:.5em 0 1.5em}td,th{border:1px solid #bbb;padding:3px 6px;text-align:left;vertical-align:top}code{font-size:12px}.ok{color:#060}.bad{color:#a00}</style></head><body>");
    o.push_str(&format!(
        "<h1>ark audit report</h1><p>Period: {} → {}<br>Generated: {}<br>Records in period: {}</p>",
        esc(&t(r.from_ms)),
        esc(&t(r.to_ms)),
        esc(&t(r.generated_ms)),
        r.records
    ));
    o.push_str(&format!(
        "<h2>Chain integrity</h2><p class=\"{}\"><b>{}</b>{}</p><p>Segments: {} · events: {} · seq {}–{}<br>Head hash: <code>{}</code><br>Anchor: <code>{}</code></p>",
        if r.verify.ok { "ok" } else { "bad" },
        if r.verify.ok { "OK" } else { "FAILED" },
        r.verify.error.as_ref().map(|e| format!(" — {}", esc(e))).unwrap_or_default(),
        r.verify.segments,
        r.verify.events,
        r.verify.first_seq,
        r.verify.last_seq,
        esc(&r.verify.head),
        esc(if r.verify.anchor.is_empty() { "genesis" } else { &r.verify.anchor }),
    ));
    if let Some(s) = &r.seals {
        o.push_str(&format!(
            "<p>Signed seals: {} signed, {} unsigned, {} timestamped{}</p>",
            s.signed,
            s.unsigned,
            s.timestamped,
            if s.errors.is_empty() {
                String::new()
            } else {
                format!(
                    " — <b class=\"bad\">errors:</b> {}",
                    esc(&s.errors.join("; "))
                )
            }
        ));
    }
    o.push_str("<h2>Summary</h2><table><tr><th>Section</th><th>Records</th></tr>");
    for s in &r.sections {
        o.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            esc(s.title),
            s.count
        ));
    }
    o.push_str("</table>");
    for s in &r.sections {
        o.push_str(&format!("<h2>{} ({})</h2>", esc(s.title), s.count));
        if s.rows.is_empty() {
            o.push_str("<p>None in this period.</p>");
            continue;
        }
        o.push_str("<table><tr><th>seq</th><th>time</th><th>kind</th><th>actor</th><th>target</th><th>outcome</th><th>details</th></tr>");
        for x in &s.rows {
            o.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", x.seq, esc(&x.time), esc(&x.kind), esc(&x.actor), esc(&x.target), esc(&x.outcome), esc(&x.note)));
        }
        o.push_str("</table>");
    }
    o.push_str("</body></html>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{emit, Actor, Event};
    use serde_json::json;

    #[test]
    fn report_sections_cover_the_period_and_carry_the_head_hash() {
        let tmp = ark_core::tmp::TempDir::new("ark-audit-report");
        let d = tmp.path();
        emit(
            d,
            Event::new(
                "auth.login",
                Actor::new("sso", "ann@corp.example").with_ip("10.1.2.3"),
                "oidc",
                "ok",
            ),
        )
        .unwrap();
        emit(
            d,
            Event::new("user.role", Actor::local(), "bob", "ok").detail(json!({"role": "admin"})),
        )
        .unwrap();
        emit(d, Event::new("approval.answer", Actor::new("sso", "cy"), "a1", "once").detail(json!({"tool": "shell", "approved_by": "sso:cy + sso:dee", "approvals": ["sso:cy", "sso:dee"], "dual_control": true, "required": 2, "requester": "sso:ann"}))).unwrap();
        emit(
            d,
            Event::new(
                "app.request",
                Actor::new("token", "ro"),
                "config.set",
                "deny",
            ),
        )
        .unwrap();
        emit(
            d,
            Event::new("config.change", Actor::local(), "approvals.mode", "ok"),
        )
        .unwrap();
        emit(
            d,
            Event::new("session.review", Actor::new("sso", "rita"), "s1", "flagged")
                .detail(json!({"owner": "sso:ann"})),
        )
        .unwrap();
        let r = build(d, 0, 0, None);
        let count = |t: &str| r.sections.iter().find(|s| s.title == t).unwrap().count;
        assert_eq!(count("Logins and sessions"), 1);
        assert_eq!(count("Privilege and identity changes"), 1);
        assert_eq!(count("Approvals"), 1);
        assert_eq!(count("Denied actions"), 1);
        assert_eq!(count("Configuration changes"), 1);
        assert_eq!(count("Session reviews"), 1);
        assert!(r.verify.ok && r.verify.head == audit::head(d).hash);
        let md = markdown(&r);
        assert!(
            md.contains("sso:cy + sso:dee")
                && md.contains("requested by sso:ann")
                && md.contains(&r.verify.head),
            "{md}"
        );
        let h = html(&r);
        assert!(
            h.starts_with("<!doctype html>")
                && !h.contains("<script")
                && h.contains(&r.verify.head)
        );
        // The period filters records; the chain check is always whole.
        let later = build(d, audit::now_ms() + 60_000, 0, None);
        assert_eq!(later.records, 0);
        assert!(later.verify.events == 6);
        assert!(
            serde_json::to_value(&r).unwrap()["sections"]
                .as_array()
                .unwrap()
                .len()
                >= 6
        );
    }
}
