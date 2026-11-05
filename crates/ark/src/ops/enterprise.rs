//! Enterprise operator commands over the identity / audit / governance core:
//!
//! * `ark accounts issue <name> --role R [--ttl-days N] [--description …]`, `list`,
//!   `rotate <name> [--grace-hours H] [--ttl-days N]`, `revoke <name>`, `expiring [--days N]`
//!   — app-server service accounts (ent-058; also `ark app accounts …`);
//! * `ark audit events|verify|rotate|export|head` — the unified audit stream (ent-072…076);
//! * `ark retention run|status`, `ark retention hold add <scope> --reason …|list|release <id>`
//!   (ent-077);
//! * `ark ediscovery export --out DIR [--owner U] [--since D] [--until D] [--keyword K]…
//!   [--matter M] [--keep-pii]`, `ark ediscovery verify DIR` (ent-079, ent-078);
//! * `ark quota status`, `ark usage --by user|team [--days N]` (ent-070 / ent-071);
//! * `ark health --ready` (ent-098) asks the daemon's `health.ready`.

use crate::args::Args;
use crate::R;
use ark_kernel::config::Paths;
use ark_security::audit::{self, Actor};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["accounts", "service-accounts", "retention", "ediscovery", "quota"];
pub const VALUE_FLAGS: &[&str] = &["role", "ttl-days", "grace-hours", "description", "owner", "team", "since", "until", "keyword", "matter", "by", "actor", "outcome", "kind", "anchor", "custodian", "org"];
pub const BOOL_FLAGS: &[&str] = &["keep-pii", "ready"];

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    let paths = Paths::from_env();
    Some(match cmd {
        "accounts" | "service-accounts" => accounts(&paths, a, 0),
        "retention" => retention(a),
        "ediscovery" => ediscovery(a),
        _ => quota(a),
    })
}

fn out(s: String) -> R {
    println!("{s}");
    Ok(0)
}

fn ts(ms: u64) -> String {
    if ms == 0 {
        "never".into()
    } else {
        ark_security::audit_export::rfc3339(ms)
    }
}

/// Parse `2026-11-01`, an RFC 3339 time, Unix ms, or `30d` / `12h` (ago).
pub fn parse_when(v: &str, now: u64) -> Result<u64, String> {
    let v = v.trim();
    if let Some(n) = v.strip_suffix('d').and_then(|n| n.parse::<u64>().ok()) {
        return Ok(now.saturating_sub(n * 86_400_000));
    }
    if let Some(n) = v.strip_suffix('h').and_then(|n| n.parse::<u64>().ok()) {
        return Ok(now.saturating_sub(n * 3_600_000));
    }
    crate::ops::audit::parse_ts(v, "time")
}

/// `ark health --ready` (ent-098): can the daemon do work — model reachable, channels
/// connected, audit writable (the same checks as `GET /ready`). Exit 1 when not ready.
pub fn health_ready(a: &Args) -> R {
    let v = ark_kernel::daemon::call(&Paths::from_env().socket(), "health.ready", json!({}))?;
    if a.flag("json") {
        println!("{v}");
    } else {
        for c in v["checks"].as_array().into_iter().flatten() {
            println!("{} {:<20} {}", if c["ok"] == true { "ok  " } else { "FAIL" }, c["name"].as_str().unwrap_or(""), c["detail"].as_str().or(c["error"].as_str()).unwrap_or(""));
        }
    }
    Ok(if v["ready"] == true { 0 } else { 1 })
}

// ───────────────────────── service accounts ─────────────────────────

/// `off` = index of the subcommand (0 for `ark accounts`, 1 for `ark app accounts`).
pub fn accounts(paths: &Paths, a: &Args, off: usize) -> R {
    let me = Actor::local();
    let d = &paths.data;
    match a.pos(off).unwrap_or("list") {
        "list" | "ls" => {
            let all = ark_app::identity::accounts(d);
            if a.flag("json") {
                return out(serde_json::to_string_pretty(&all).unwrap_or_default());
            }
            if all.is_empty() {
                return out("no service accounts (`ark accounts issue <name> --role operator`)".into());
            }
            let now = audit::now_ms();
            out(all
                .iter()
                .map(|x| format!("{}\t{}\t{}\texpires {}\trotated {}", x.name, x.role, if x.revoked { "revoked" } else if x.active(now) { "active" } else { "expired" }, ts(x.expires_ms), ts(x.rotated_ms)))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "issue" | "create" => {
            let name = a.need(off + 1, "name")?;
            let role = a.val("role").ok_or("--role admin|operator|user|auditor (or scope:read …) is required")?;
            let ttl = a.num::<u64>("ttl-days")?.unwrap_or(90);
            let (mut acct, token) = ark_app::identity::issue(d, name, role, ttl, a.val("description").unwrap_or(""), &me)?;
            // ent-050: limit the account to an organization / team (SCIM for one org, a team bot).
            if a.val("org").is_some() || a.val("team").is_some() {
                acct = ark_app::identity::set_tenant(d, name, a.val("org").unwrap_or(""), a.val("team").unwrap_or(""), &me)?;
            }
            out(format!("{token}\n# service account `{}` ({}), expires {} — the token is shown once; store it now (e.g. `ark secrets set`).", acct.name, acct.role, ts(acct.expires_ms)))
        }
        "rotate" => {
            let name = a.need(off + 1, "name")?;
            let grace = a.num::<u64>("grace-hours")?.unwrap_or(24);
            let (acct, token) = ark_app::identity::rotate(d, name, grace, a.num::<u64>("ttl-days")?, &me)?;
            out(format!("{token}\n# `{}` rotated; the previous token keeps working for {grace} h, expires {}", acct.name, ts(acct.expires_ms)))
        }
        "revoke" => {
            let name = a.need(off + 1, "name")?;
            ark_app::identity::revoke(d, name, &me)?;
            out(format!("revoked `{name}`"))
        }
        "expiring" => {
            let days = a.num::<u64>("days")?.unwrap_or(14);
            let v = ark_app::identity::expiring(d, days);
            out(if v.is_empty() { format!("nothing expires within {days} day(s)") } else { v.iter().map(|x| format!("{}\texpires {}", x.name, ts(x.expires_ms))).collect::<Vec<_>>().join("\n") })
        }
        other => crate::usage(format!("unknown `accounts {other}` (list | issue <name> --role R [--ttl-days N] | rotate <name> [--grace-hours H] | revoke <name> | expiring [--days N])")),
    }
}

// ───────────────────────── audit stream ─────────────────────────

/// `ark audit <events|verify|rotate|export|head>`; `None` when `pos(0)` is not one of them
/// (the activity view in `ops::audit` handles the rest).
pub fn audit_sub(paths: &Paths, a: &Args) -> Option<R> {
    let d = &paths.data;
    Some(match a.pos(0)? {
        "events" | "log" => (|| -> R {
            let now = audit::now_ms();
            let q = audit::Query {
                kind: a.val("kind").map(String::from),
                actor: a.val("actor").map(String::from),
                session: a.val("session").map(String::from),
                outcome: a.val("outcome").map(String::from),
                after_ms: a.val("since").map(|v| parse_when(v, now)).transpose()?,
                before_ms: a.val("until").map(|v| parse_when(v, now)).transpose()?,
                limit: a.num::<usize>("limit")?.unwrap_or(100),
                org: a.val("org").map(String::from),
                team: a.val("team").map(String::from),
            };
            let v = audit::query(d, &q);
            if a.flag("json") {
                return out(serde_json::to_string_pretty(&v).unwrap_or_default());
            }
            out(v
                .iter()
                .map(|r| format!("{:>6} {} {:<18} {}:{} {} → {}", r["seq"], ts(r["ts"].as_u64().unwrap_or(0)), r["kind"].as_str().unwrap_or(""), r["actor"]["kind"].as_str().unwrap_or(""), r["actor"]["name"].as_str().unwrap_or(""), r["target"].as_str().unwrap_or(""), r["outcome"].as_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n"))
        })(),
        "verify" => {
            let v = audit::verify(d, a.val("anchor"));
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else if v.ok {
                println!("audit chain OK: {} record(s) in {} segment(s), seq {}…{}, head {}{}", v.events, v.segments, v.first_seq, v.last_seq, v.head, if v.anchor.is_empty() { String::new() } else { format!(" (anchored after pruned hash {})", v.anchor) });
            } else {
                eprintln!("audit chain BROKEN: {}", v.error.clone().unwrap_or_default());
            }
            Ok(if v.ok { 0 } else { 1 })
        }
        "head" => {
            let h = audit::head(d);
            out(json!({"seq": h.seq, "hash": h.hash}).to_string())
        }
        "rotate" => match audit::rotate(d) {
            Ok(Some(p)) => out(format!("sealed {}", p.display())),
            Ok(None) => out("nothing to rotate".into()),
            Err(e) => Err(e.into()),
        },
        "export" => (|| -> R {
            let cfg = crate::load_config(a, &crate::workspace(a)?, paths)?;
            let vault = crate::load_vault(paths)?;
            let sinks = cfg.audit.export.sinks();
            if sinks.is_empty() {
                return out("no [audit.export] sink configured (syslog, splunk_hec, otlp)".into());
            }
            let mut failed = false;
            for (sink, r) in ark_security::audit_export::pump(d, &cfg.audit.export, &|s: &str| vault.substitute(s)) {
                match r {
                    Ok(n) => println!("{sink}: sent {n} record(s), cursor {}", ark_security::audit_export::cursor(d, sink)),
                    Err(e) => {
                        failed = true;
                        eprintln!("{sink}: {e}");
                    }
                }
            }
            Ok(if failed { 1 } else { 0 })
        })(),
        _ => return None,
    })
}

// ───────────────────────── retention ─────────────────────────

fn retention(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("status") {
        "status" => {
            let cfg = crate::load_config(a, &crate::workspace(a)?, &paths)?;
            let c = &cfg.compliance;
            let show = |v: Option<u32>| v.filter(|d| *d > 0).map(|d| format!("{d} d")).unwrap_or_else(|| "keep".into());
            let holds = ark_kernel::governance::holds(&paths.data);
            out(format!(
                "sessions {} · audit {} · broker log {} · logs {} · exports {}\nlegal holds: {}",
                show(c.retention.sessions_days.or(c.retention_days)),
                show(c.retention.audit_days),
                show(c.retention.broker_days),
                show(c.retention.logs_days),
                show(c.retention.exports_days),
                if holds.is_empty() { "none".to_string() } else { holds.iter().map(|h| format!("{} {} ({})", h.id, h.scope, h.reason)).collect::<Vec<_>>().join("; ") }
            ))
        }
        "run" => {
            let c = crate::build(a, crate::approver_for(a, false))?;
            let r = ark_kernel::governance::enforce_retention(&c.k);
            out(if r.is_empty() { "nothing configured, or a global legal hold is in force".into() } else { r.iter().map(|(k, n)| format!("{k}: removed {n}")).collect::<Vec<_>>().join("\n") })
        }
        "hold" | "holds" => match a.pos(1).unwrap_or("list") {
            "list" => {
                let h = ark_kernel::governance::holds(&paths.data);
                if a.flag("json") {
                    return out(serde_json::to_string_pretty(&h).unwrap_or_default());
                }
                out(if h.is_empty() { "no legal holds".into() } else { h.iter().map(|h| format!("{}\t{}\t{}\tby {}", h.id, h.scope, h.reason, h.by)).collect::<Vec<_>>().join("\n") })
            }
            "add" => {
                let h = ark_kernel::governance::hold_add(&paths.data, a.need(2, "scope (all | audit | session:<id> | user:<name>)")?, a.val("reason").unwrap_or(""), &Actor::local().label())?;
                out(format!("hold {} on {}", h.id, h.scope))
            }
            "release" | "rm" => {
                ark_kernel::governance::hold_release(&paths.data, a.need(2, "hold id")?, &Actor::local().label())?;
                out("released".into())
            }
            other => crate::usage(format!("unknown `retention hold {other}` (list | add <scope> --reason R | release <id>)")),
        },
        other => crate::usage(format!("unknown `retention {other}` (status | run | hold …)")),
    }
}

// ───────────────────────── eDiscovery ─────────────────────────

#[derive(Debug, Default)]
pub struct Search {
    pub user: Option<String>,
    pub team: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub keywords: Vec<String>,
    pub sessions: Vec<String>,
}

/// Write a bundle: one JSON per matching session (PII-masked unless `keep_pii`), a manifest
/// with SHA-256 of each file, and a custody log; the manifest digest goes to the audit stream.
pub fn ediscovery_export(k: &ark_kernel::kernel::Kernel, q: &Search, dir: &Path, matter: &str, keep_pii: bool, who: &Actor) -> Result<Value, String> {
    if dir.exists() && std::fs::read_dir(dir).map(|mut d| d.next().is_some()).unwrap_or(false) {
        return Err(format!("{} is not empty", dir.display()));
    }
    std::fs::create_dir_all(dir.join("sessions")).map_err(|e| e.to_string())?;
    let pii = &k.cfg.compliance.pii;
    let mut files = vec![];
    let mut custody = vec![json!({"ts": audit::now_ms(), "action": "collect", "by": who.label(), "query": format!("{q:?}")})];
    for info in k.store.list() {
        if !q.sessions.is_empty() && !q.sessions.contains(&info.id) {
            continue;
        }
        let owner = ark_kernel::governance::owner_of(k, &info.id);
        if q.user.as_deref().is_some_and(|u| u != owner.user) || q.team.as_deref().is_some_and(|t| t != owner.team) {
            continue;
        }
        let mut events = k.store.read(&info.id).map_err(|e| e.to_string())?;
        events.retain(|e| q.since.is_none_or(|s| e.ts >= s) && q.until.is_none_or(|u| e.ts < u));
        if events.is_empty() {
            continue;
        }
        // Keep the header so the projection still knows the session.
        if let Ok(all) = k.store.read(&info.id) {
            if let Some(h) = all.into_iter().next() {
                if events.first().map(|e| e.seq) != Some(h.seq) {
                    events.insert(0, h);
                }
            }
        }
        // Keywords match anything recorded in the window: messages, queued input, tool calls.
        let text = serde_json::to_string(&events).unwrap_or_default().to_lowercase();
        if !q.keywords.is_empty() && !q.keywords.iter().any(|kw| text.contains(&kw.to_lowercase())) {
            continue;
        }
        let mut s = crate::export::SessionData::from_events(&events);
        s.redact(&k.vault);
        let mut doc = crate::export::render_json(&s);
        if !keep_pii {
            doc = ark_security::pii::mask_json(&doc, pii);
        }
        let body = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
        let name = format!("sessions/{}.json", info.id);
        std::fs::write(dir.join(&name), &body).map_err(|e| e.to_string())?;
        let sha = audit::sha256_hex(body.as_bytes());
        files.push(json!({"session": info.id, "path": name, "sha256": sha, "bytes": body.len(), "events": events.len(), "first_ts": events.first().map(|e| e.ts), "last_ts": events.last().map(|e| e.ts), "owner": owner.user, "team": owner.team}));
        custody.push(json!({"ts": audit::now_ms(), "action": "write", "path": name, "sha256": sha}));
    }
    let manifest = json!({
        "format": "ark-ediscovery/1",
        "matter": matter,
        "generated_at": ts(audit::now_ms()),
        "generated_by": who.label(),
        "tool": format!("ark {}", env!("CARGO_PKG_VERSION")),
        "query": {"user": q.user, "team": q.team, "since": q.since, "until": q.until, "keywords": q.keywords, "sessions": q.sessions},
        "pii_masked": !keep_pii,
        "files": files,
        "audit_head_at_export": audit::head(&k.paths.data).hash,
    });
    let mtext = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("manifest.json"), &mtext).map_err(|e| e.to_string())?;
    let msha = audit::sha256_hex(mtext.as_bytes());
    let seq = audit::emit(&k.paths.data, audit::Event::new("ediscovery.export", who.clone(), matter, "ok").detail(json!({"manifest_sha256": msha, "files": manifest["files"].as_array().map(|a| a.len()), "pii_masked": !keep_pii, "dir": dir.display().to_string(), "custodian": who.label()})))?;
    custody.push(json!({"ts": audit::now_ms(), "action": "seal", "manifest_sha256": msha, "audit_seq": seq}));
    let log: String = custody.iter().map(|c| c.to_string() + "\n").collect();
    std::fs::write(dir.join("custody.jsonl"), log).map_err(|e| e.to_string())?;
    Ok(json!({"dir": dir, "files": manifest["files"].as_array().map(|a| a.len()).unwrap_or(0), "manifest_sha256": msha, "audit_seq": seq}))
}

/// Re-hash every file against the manifest and find the manifest's digest in the audit stream.
pub fn ediscovery_verify(data: &Path, dir: &Path) -> Result<Value, String> {
    let mtext = std::fs::read_to_string(dir.join("manifest.json")).map_err(|e| format!("manifest.json: {e}"))?;
    let m: Value = serde_json::from_str(&mtext).map_err(|e| format!("manifest.json: {e}"))?;
    let mut bad = vec![];
    for f in m["files"].as_array().into_iter().flatten() {
        let p = dir.join(f["path"].as_str().unwrap_or(""));
        let got = std::fs::read(&p).map(|b| audit::sha256_hex(&b)).unwrap_or_default();
        if f["sha256"].as_str() != Some(got.as_str()) {
            bad.push(f["path"].clone());
        }
    }
    let msha = audit::sha256_hex(mtext.as_bytes());
    let recorded = audit::query(data, &audit::Query { kind: Some("ediscovery.export".into()), limit: 10_000, ..Default::default() }).into_iter().any(|r| r["detail"]["manifest_sha256"].as_str() == Some(msha.as_str()));
    Ok(json!({"ok": bad.is_empty() && recorded, "altered": bad, "manifest_sha256": msha, "in_audit_stream": recorded}))
}

fn ediscovery(a: &Args) -> R {
    match a.pos(0).unwrap_or("") {
        "export" => {
            let c = crate::build(a, crate::approver_for(a, false))?;
            let now = audit::now_ms();
            let q = Search {
                user: a.val("owner").map(String::from),
                team: a.val("team").map(String::from),
                since: a.val("since").map(|v| parse_when(v, now)).transpose()?,
                until: a.val("until").map(|v| parse_when(v, now)).transpose()?,
                keywords: a.vals("keyword"),
                sessions: a.vals("session"),
            };
            let dir = PathBuf::from(a.val("out").ok_or("--out <dir> is required")?);
            let r = ediscovery_export(&c.k, &q, &dir, a.val("matter").unwrap_or(""), a.flag("keep-pii"), &Actor::local())?;
            out(if a.flag("json") { r.to_string() } else { format!("exported {} session(s) to {}; manifest sha256 {} (audit seq {})", r["files"], dir.display(), r["manifest_sha256"].as_str().unwrap_or(""), r["audit_seq"]) })
        }
        "verify" => {
            let paths = Paths::from_env();
            let r = ediscovery_verify(&paths.data, Path::new(a.need(1, "dir")?))?;
            println!("{}", if a.flag("json") { r.to_string() } else if r["ok"] == true { format!("bundle intact; manifest {} is in the audit stream", r["manifest_sha256"].as_str().unwrap_or("")) } else { format!("bundle NOT intact: altered {} · recorded in audit stream: {}", r["altered"], r["in_audit_stream"]) });
            Ok(if r["ok"] == true { 0 } else { 1 })
        }
        other => crate::usage(format!("unknown `ediscovery {other}` (export --out DIR [--owner U] [--team T] [--since D] [--until D] [--keyword K]… [--session ID]… [--matter M] [--keep-pii] | verify DIR)")),
    }
}

// ───────────────────────── usage & quotas ─────────────────────────

/// `ark usage --by user|team [--days N]`.
pub fn usage_by(a: &Args, by: &str) -> R {
    if !matches!(by, "user" | "team") {
        return crate::usage("--by user|team");
    }
    let c = crate::build(a, crate::approver_for(a, false))?;
    let days = a.num::<u64>("days")?.unwrap_or(30);
    let rows = ark_kernel::governance::usage_by(&c.k, by, audit::now_ms().saturating_sub(days * 86_400_000));
    if a.flag("json") {
        return out(json!({"by": by, "days": days, "rows": rows}).to_string());
    }
    let mut s = format!("spend by {by} over the last {days} day(s)\n");
    for r in &rows {
        s.push_str(&format!("  {:<32} ${:>10.4}  {:>12} tok  {:>4} session(s)\n", r.key, r.usd, r.tokens, r.sessions));
    }
    if rows.is_empty() {
        s.push_str("  (no priced usage)\n");
    }
    out(s.trim_end().into())
}

fn quota(a: &Args) -> R {
    let c = crate::build(a, crate::approver_for(a, false))?;
    let q = &c.k.cfg.quotas;
    if !q.enabled() {
        return out("no [quotas] configured (user_usd, users, teams)".into());
    }
    let since = ark_kernel::governance::period_start(&q.period, audit::now_ms());
    let users = ark_kernel::governance::usage_by(&c.k, "user", since);
    let teams = ark_kernel::governance::usage_by(&c.k, "team", since);
    let mut s = format!("quota period: {} (since {})\n", q.period, ts(since));
    for r in &users {
        let cap = q.users.get(&r.key).copied().unwrap_or(q.user_usd);
        if cap > 0.0 {
            s.push_str(&format!("  user {:<28} ${:>9.2} / ${:<9.2} {:>5.0} %\n", r.key, r.usd, cap, r.usd / cap * 100.0));
        }
    }
    for (t, cap) in &q.teams {
        let used = teams.iter().find(|r| &r.key == t).map(|r| r.usd).unwrap_or(0.0);
        s.push_str(&format!("  team {:<28} ${:>9.2} / ${:<9.2} {:>5.0} %\n", t, used, cap, if *cap > 0.0 { used / cap * 100.0 } else { 0.0 }));
    }
    out(s.trim_end().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(kit: &crate::testkit::Kit, v: &[&str]) -> Result<i32, String> {
        let a = Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        accounts(&kit.paths, &a, 0).map_err(|e| format!("{e:?}"))
    }

    #[test]
    fn accounts_cli_issue_rotate_revoke() {
        let kit = crate::testkit::kit();
        assert!(run(&kit, &["issue", "ci"]).is_err(), "--role is required");
        assert_eq!(run(&kit, &["issue", "ci", "--role", "operator", "--ttl-days", "7"]).unwrap(), 0);
        assert_eq!(ark_app::identity::accounts(&kit.paths.data)[0].role, "operator");
        assert_eq!(run(&kit, &["rotate", "ci", "--grace-hours", "0"]).unwrap(), 0);
        assert_eq!(run(&kit, &["revoke", "ci"]).unwrap(), 0);
        assert!(ark_app::identity::accounts(&kit.paths.data)[0].revoked);
        assert!(run(&kit, &["bogus"]).is_err());
    }

    #[test]
    fn audit_subcommands_verify_and_query() {
        let kit = crate::testkit::kit();
        let p = &kit.paths;
        audit::emit(&p.data, audit::Event::new("config.change", Actor::local(), "model.default", "ok")).unwrap();
        let a = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert!(audit_sub(p, &a(&["agent_run"])).is_none(), "activity view keeps its own words");
        assert_eq!(audit_sub(p, &a(&["verify"])).unwrap().unwrap(), 0);
        assert_eq!(audit_sub(p, &a(&["events", "--kind", "config"])).unwrap().unwrap(), 0);
        assert_eq!(audit_sub(p, &a(&["rotate"])).unwrap().unwrap(), 0);
        assert!(audit::verify(&p.data, None).ok);
        // A tampered archive makes `verify` exit 1.
        let seg = audit::segments(&p.data).into_iter().next().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&seg, "{}\n").unwrap();
        assert_eq!(audit_sub(p, &a(&["verify"])).unwrap().unwrap(), 1);
        assert!(parse_when("2d", 10 * 86_400_000).unwrap() == 8 * 86_400_000);
    }

    #[test]
    fn ediscovery_bundle_is_masked_hashed_and_recorded() {
        let kit = crate::testkit::kit();
        let k = &kit.k;
        let ws = kit.paths.data.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let s1 = k.create_session(&ws, None, None, Some("contract")).unwrap();
        k.submit(&s1, "the merger contract is with bob@corp.example", "channel:slack:U1").unwrap();
        let mut log = k.store.open(&s1).unwrap();
        log.append(ark_kernel::event::EventKind::Message { message: ark_core::Message::user("the merger contract is with bob@corp.example"), usage: None, model: None, inbox: None }).unwrap();
        let s2 = k.create_session(&ws, None, None, Some("lunch")).unwrap();
        k.submit(&s2, "lunch at noon", "cli").unwrap();
        let u = ark_kernel::agents::user_add(&k.paths, "ann").unwrap();
        ark_kernel::agents::user_link(&k.paths, &u.id, "slack", "U1").unwrap();
        let dir = kit.paths.data.join("bundle");
        let q = Search { user: Some("ann".into()), keywords: vec!["MERGER".into()], ..Default::default() };
        let r = ediscovery_export(k, &q, &dir, "case-7", false, &Actor::local()).unwrap();
        assert_eq!(r["files"], 1);
        let body = std::fs::read_to_string(dir.join(format!("sessions/{s1}.json"))).unwrap();
        assert!(body.contains("merger") && !body.contains("bob@corp.example") && body.contains("[email]"), "{body}");
        assert!(!dir.join(format!("sessions/{s2}.json")).exists());
        let m: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!((m["matter"].as_str(), m["files"][0]["owner"].as_str()), (Some("case-7"), Some("ann")));
        assert!(std::fs::read_to_string(dir.join("custody.jsonl")).unwrap().lines().count() >= 3);
        assert_eq!(ediscovery_verify(&k.paths.data, &dir).unwrap()["ok"], true);
        std::fs::write(dir.join(format!("sessions/{s1}.json")), "{}").unwrap();
        let v = ediscovery_verify(&k.paths.data, &dir).unwrap();
        assert_eq!(v["ok"], false);
        assert!(ediscovery_export(k, &q, &dir, "x", false, &Actor::local()).is_err(), "never writes into a non-empty dir");
    }

    #[test]
    fn dispatch_is_wired() {
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize));
    }
}
