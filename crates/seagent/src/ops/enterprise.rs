//! Enterprise operator commands over the identity / audit / governance core:
//!
//! * `seagent accounts issue <name> --role R [--ttl-days N] [--description …]`, `list`,
//!   `rotate <name> [--grace-hours H] [--ttl-days N]`, `revoke <name>`, `expiring [--days N]`
//!   — app-server service accounts (ent-058; also `seagent app accounts …`);
//! * `seagent audit events|verify|rotate|export|head` — the unified audit stream (ent-072…076);
//! * `seagent retention run|status`, `seagent retention hold add <scope> --reason …|list|release <id>`
//!   (ent-077);
//! * `seagent ediscovery export --out DIR [--owner U] [--since D] [--until D] [--keyword K]…
//!   [--matter M] [--keep-pii]`, `seagent ediscovery verify DIR` (ent-079, ent-078);
//! * `seagent quota status`, `seagent usage --by user|team [--days N]` (ent-070 / ent-071);
//! * `seagent health --ready` (ent-098) asks the daemon's `health.ready`.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use seagent_security::audit::{self, Actor};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["accounts", "service-accounts", "retention", "ediscovery", "quota"];
pub const VALUE_FLAGS: &[&str] = &["role", "ttl-days", "grace-hours", "description", "owner", "team", "since", "until", "keyword", "matter", "by", "actor", "outcome", "kind", "anchor", "custodian", "org", "to", "pubkey", "note", "warn-pending"];
pub const BOOL_FLAGS: &[&str] = &["keep-pii", "ready", "require-signed", "nagios"];

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

pub fn out(s: String) -> R {
    println!("{s}");
    Ok(0)
}

fn ts(ms: u64) -> String {
    if ms == 0 {
        "never".into()
    } else {
        seagent_security::audit_export::rfc3339(ms)
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

/// `seagent health --ready` (ent-098): can the daemon do work — model reachable, channels
/// connected, audit writable (the same checks as `GET /ready`). Exit 1 when not ready.
pub fn health_ready(a: &Args) -> R {
    let v = seagent_kernel::daemon::call(&Paths::from_env().socket(), "health.ready", json!({}))?;
    if a.flag("json") {
        println!("{v}");
    } else {
        for c in v["checks"].as_array().into_iter().flatten() {
            println!("{} {:<20} {}", if c["ok"] == true { "ok  " } else { "FAIL" }, c["name"].as_str().unwrap_or(""), c["detail"].as_str().or(c["error"].as_str()).unwrap_or(""));
        }
    }
    Ok(if v["ready"] == true { 0 } else { 1 })
}

/// Nagios / Icinga plugin output for `seagent health --nagios`: one status line with perfdata
/// and the plugin exit code (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN). `ready` is the
/// daemon's `health.ready` reply (`None` = the daemon did not answer: CRITICAL).
pub fn nagios(ready: Option<&Value>, pending: Option<usize>, warn_pending: usize) -> (i32, String) {
    let Some(r) = ready else { return (2, "SEAGENT CRITICAL - daemon not answering on its socket".into()) };
    let Some(checks) = r["checks"].as_array() else { return (3, "SEAGENT UNKNOWN - unexpected health.ready reply".into()) };
    let failed: Vec<String> = checks.iter().filter(|c| c["ok"] != true).map(|c| format!("{}: {}", c["name"].as_str().unwrap_or("?"), c["error"].as_str().or(c["detail"].as_str()).unwrap_or("failed"))).collect();
    let ok = checks.len() - failed.len();
    let pending = pending.unwrap_or(0);
    let warn = if warn_pending == 0 { String::new() } else { warn_pending.to_string() };
    let perf = format!("checks_ok={ok};;;0;{} checks_failed={};;0;0 approvals_pending={pending};{warn};;0", checks.len(), failed.len());
    // A failed check is critical (not ready); a backlog of approvals waiting for a human is
    // a warning when `--warn-pending N` is given.
    let (code, word) = if !failed.is_empty() || r["ready"] == false {
        (2, "CRITICAL")
    } else if warn_pending > 0 && pending >= warn_pending {
        (1, "WARNING")
    } else {
        (0, "OK")
    };
    let text = if failed.is_empty() { format!("{ok} check(s) passed, {pending} approval(s) pending") } else { failed.join("; ") };
    (code, format!("SEAGENT {word} - {} | {perf}", text.replace('|', "/")))
}

/// `seagent gate list`: one line under a dual-controlled approval — progress, who already
/// approved, who asked, which roles may answer, when it expires, the change ticket.
pub fn dual_control_line(q: &Value) -> Option<String> {
    if !q.is_object() {
        return None;
    }
    let by: Vec<&str> = q["approvals"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
    let roles = q["approver_roles"].as_array().filter(|r| !r.is_empty()).map(|r| r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("|")).unwrap_or_else(|| "any".into());
    Some(format!(
        "    dual control: {}/{} approvals{} · requested by {} · roles {roles} · expires {}{}",
        by.len(),
        q["required"].as_u64().unwrap_or(2),
        if by.is_empty() { String::new() } else { format!(" ({})", by.join(", ")) },
        q["requester"].as_str().unwrap_or("?"),
        ts(q["expires_ms"].as_u64().unwrap_or(0)),
        q["change_ticket"].as_str().map(|t| format!(" · ticket {t}")).unwrap_or_default(),
    ))
}

/// `seagent health --nagios`.
pub fn health_nagios(a: &Args) -> R {
    let sock = Paths::from_env().socket();
    let ready = seagent_kernel::daemon::call(&sock, "health.ready", json!({})).ok();
    let pending = seagent_kernel::daemon::call(&sock, "gate.pending", json!({})).ok().and_then(|v| v.as_array().map(|a| a.len()));
    let (code, line) = nagios(ready.as_ref(), pending, a.num::<usize>("warn-pending")?.unwrap_or(0));
    println!("{line}");
    Ok(code)
}

// ───────────────────────── service accounts ─────────────────────────

/// `off` = index of the subcommand (0 for `seagent accounts`, 1 for `seagent app accounts`).
pub fn accounts(paths: &Paths, a: &Args, off: usize) -> R {
    let me = Actor::local();
    let d = &paths.data;
    match a.pos(off).unwrap_or("list") {
        "list" | "ls" => {
            let all = seagent_app::identity::accounts(d);
            if a.flag("json") {
                return out(serde_json::to_string_pretty(&all).unwrap_or_default());
            }
            if all.is_empty() {
                return out("no service accounts (`seagent accounts issue <name> --role operator`)".into());
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
            let (mut acct, token) = seagent_app::identity::issue(d, name, role, ttl, a.val("description").unwrap_or(""), &me)?;
            // ent-050: limit the account to an organization / team (SCIM for one org, a team bot).
            if a.val("org").is_some() || a.val("team").is_some() {
                acct = seagent_app::identity::set_tenant(d, name, a.val("org").unwrap_or(""), a.val("team").unwrap_or(""), &me)?;
            }
            out(format!("{token}\n# service account `{}` ({}), expires {} — the token is shown once; store it now (e.g. `seagent secrets set`).", acct.name, acct.role, ts(acct.expires_ms)))
        }
        "rotate" => {
            let name = a.need(off + 1, "name")?;
            let grace = a.num::<u64>("grace-hours")?.unwrap_or(24);
            let (acct, token) = seagent_app::identity::rotate(d, name, grace, a.num::<u64>("ttl-days")?, &me)?;
            out(format!("{token}\n# `{}` rotated; the previous token keeps working for {grace} h, expires {}", acct.name, ts(acct.expires_ms)))
        }
        "revoke" => {
            let name = a.need(off + 1, "name")?;
            seagent_app::identity::revoke(d, name, &me)?;
            out(format!("revoked `{name}`"))
        }
        "expiring" => {
            let days = a.num::<u64>("days")?.unwrap_or(14);
            let v = seagent_app::identity::expiring(d, days);
            out(if v.is_empty() { format!("nothing expires within {days} day(s)") } else { v.iter().map(|x| format!("{}\texpires {}", x.name, ts(x.expires_ms))).collect::<Vec<_>>().join("\n") })
        }
        other => crate::usage(format!("unknown `accounts {other}` (list | issue <name> --role R [--ttl-days N] | rotate <name> [--grace-hours H] | revoke <name> | expiring [--days N])")),
    }
}

// ───────────────────────── audit stream ─────────────────────────

/// `[audit] seal_pubkey` (or the key derived from `seal_key`) and `require_signed_seals`, when
/// the configuration loads (verification also works with only `--pubkey`).
fn seal_settings(a: &Args, paths: &Paths) -> (Option<String>, bool) {
    let Ok(ws) = crate::workspace(a) else { return (None, false) };
    let Ok(cfg) = crate::load_config(a, &ws, paths) else { return (None, false) };
    let vault = crate::load_vault(paths).ok();
    let subst = |s: &str| vault.as_ref().map(|v| v.substitute(s)).unwrap_or_else(|| s.to_string());
    (cfg.audit.seal_public(&subst), cfg.audit.require_signed_seals)
}

/// `seagent audit <events|verify|report|rotate|seal|seal-key|export|head>`; `None` when `pos(0)` is not one of them
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
            // Signed seals: `--pubkey`, else `[audit] seal_pubkey` / the key derived from `seal_key`.
            let (cfg_pub, require) = seal_settings(a, paths);
            let pubkey = a.val("pubkey").map(String::from).or(cfg_pub);
            let seals = pubkey.as_deref().map(|k| seagent_security::audit_seal::check_all(d, k.as_bytes()));
            let require = require || a.flag("require-signed");
            let seals_ok = seals.as_ref().is_none_or(|s| s.ok(require)) && !(require && seals.is_none());
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&json!({"chain": v, "seals": seals, "ok": v.ok && seals_ok})).unwrap_or_default());
            } else {
                if v.ok {
                    println!("audit chain OK: {} record(s) in {} segment(s), seq {}…{}, head {}{}", v.events, v.segments, v.first_seq, v.last_seq, v.head, if v.anchor.is_empty() { String::new() } else { format!(" (anchored after pruned hash {})", v.anchor) });
                } else {
                    eprintln!("audit chain BROKEN: {}", v.error.clone().unwrap_or_default());
                }
                match &seals {
                    Some(s) if s.ok(require) => println!("seals OK: {} signed, {} unsigned, {} timestamped", s.signed, s.unsigned, s.timestamped),
                    Some(s) => eprintln!("seals FAILED: {} signed, {} unsigned{}", s.signed, s.unsigned, if s.errors.is_empty() { String::new() } else { format!("; {}", s.errors.join("; ")) }),
                    None if require => eprintln!("seals FAILED: signatures are required but no public key is configured (--pubkey or [audit] seal_pubkey)"),
                    None => {}
                }
            }
            Ok(if v.ok && seals_ok { 0 } else { 1 })
        }
        // `seagent audit report [--from D] [--to D] [--format md|html|json] [--out FILE]`
        "report" => (|| -> R {
            let now = audit::now_ms();
            let from = a.val("from").or(a.val("since")).map(|v| parse_when(v, now)).transpose()?.unwrap_or(0);
            let to = a.val("to").or(a.val("until")).map(|v| parse_when(v, now)).transpose()?.unwrap_or(0);
            let (pubkey, _) = seal_settings(a, paths);
            let pubkey = a.val("pubkey").map(String::from).or(pubkey);
            let r = seagent_security::audit_report::build(d, from, to, pubkey.as_deref().map(str::as_bytes));
            let text = match a.val("format").unwrap_or("md") {
                "md" | "markdown" => seagent_security::audit_report::markdown(&r),
                "html" => seagent_security::audit_report::html(&r),
                "json" => serde_json::to_string_pretty(&r).unwrap_or_default(),
                other => return crate::usage(format!("--format {other}: use md, html or json")),
            };
            audit::record(d, audit::Event::new("audit.report", Actor::local(), "audit", "ok").detail(json!({"from_ms": from, "to_ms": to, "records": r.records, "head": r.verify.head})));
            match a.val("out") {
                Some(p) => {
                    std::fs::write(p, text).map_err(|e| format!("{p}: {e}"))?;
                    out(format!("wrote {p} ({} record(s), chain {})", r.records, if r.verify.ok { "OK" } else { "BROKEN" }))
                }
                None => {
                    print!("{text}");
                    Ok(0)
                }
            }
        })(),
        // `seagent audit seal-key [--out FILE]`: a new Ed25519 seed for `[audit] seal_key`.
        "seal-key" => (|| -> R {
            let seed = seagent_net::crypto::b64(&seagent_net::crypto::random_bytes(32));
            let public = seagent_security::signing::public_of(&seed)?;
            let p = a.val("out").map(PathBuf::from).unwrap_or_else(|| audit::dir(d).join("seal.key"));
            if p.exists() {
                return Err(format!("{} exists; refusing to overwrite a seal key", p.display()).into());
            }
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            crate::ops::hostos::create_private(&p, format!("{seed}\n").as_bytes()).map_err(|e| format!("{}: {e}", p.display()))?;
            audit::record(d, audit::Event::new("audit.seal_key", Actor::local(), "audit", "ok").detail(json!({"public_key": public})));
            out(format!("seal key written to {} (mode 0600)\n[audit]\nseal_key = \"{}\"\nseal_pubkey = \"{public}\"   # give this to the auditor", p.display(), p.display()))
        })(),
        // `seagent audit seal`: sign (and timestamp) the seals of rotated segments now.
        "seal" => (|| -> R {
            let cfg = crate::load_config(a, &crate::workspace(a)?, paths)?;
            let vault = crate::load_vault(paths)?;
            let seed = cfg.audit.seal_seed(&|s: &str| vault.substitute(s)).ok_or("no usable [audit] seal_key (see `seagent audit seal-key`)")?;
            let tsa = cfg.audit.tsa_url.trim();
            let n = seagent_security::audit_seal::sign_pending(d, &seed, (!tsa.is_empty()).then_some(tsa))?;
            out(format!("signed {n} seal(s){}", if tsa.is_empty() { String::new() } else { format!(" (timestamped by {tsa})") }))
        })(),
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
            for (sink, r) in seagent_security::audit_export::pump(d, &cfg.audit.export, &|s: &str| vault.substitute(s)) {
                match r {
                    Ok(n) => println!("{sink}: sent {n} record(s), cursor {}", seagent_security::audit_export::cursor(d, &sink)),
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
            let holds = seagent_kernel::governance::holds(&paths.data);
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
            let r = seagent_kernel::governance::enforce_retention(&c.k);
            out(if r.is_empty() { "nothing configured, or a global legal hold is in force".into() } else { r.iter().map(|(k, n)| format!("{k}: removed {n}")).collect::<Vec<_>>().join("\n") })
        }
        "hold" | "holds" => match a.pos(1).unwrap_or("list") {
            "list" => {
                let h = seagent_kernel::governance::holds(&paths.data);
                if a.flag("json") {
                    return out(serde_json::to_string_pretty(&h).unwrap_or_default());
                }
                out(if h.is_empty() { "no legal holds".into() } else { h.iter().map(|h| format!("{}\t{}\t{}\tby {}", h.id, h.scope, h.reason, h.by)).collect::<Vec<_>>().join("\n") })
            }
            "add" => {
                let h = seagent_kernel::governance::hold_add(&paths.data, a.need(2, "scope (all | audit | session:<id> | user:<name>)")?, a.val("reason").unwrap_or(""), &Actor::local().label())?;
                out(format!("hold {} on {}", h.id, h.scope))
            }
            "release" | "rm" => {
                seagent_kernel::governance::hold_release(&paths.data, a.need(2, "hold id")?, &Actor::local().label())?;
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
pub fn ediscovery_export(k: &seagent_kernel::kernel::Kernel, q: &Search, dir: &Path, matter: &str, keep_pii: bool, who: &Actor) -> Result<Value, String> {
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
        let owner = seagent_kernel::governance::owner_of(k, &info.id);
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
            doc = seagent_security::pii::mask_json(&doc, pii);
        }
        let body = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
        let name = format!("sessions/{}.json", info.id);
        std::fs::write(dir.join(&name), &body).map_err(|e| e.to_string())?;
        let sha = audit::sha256_hex(body.as_bytes());
        files.push(json!({"session": info.id, "path": name, "sha256": sha, "bytes": body.len(), "events": events.len(), "first_ts": events.first().map(|e| e.ts), "last_ts": events.last().map(|e| e.ts), "owner": owner.user, "team": owner.team}));
        custody.push(json!({"ts": audit::now_ms(), "action": "write", "path": name, "sha256": sha}));
    }
    let manifest = json!({
        "format": "seagent-ediscovery/1",
        "matter": matter,
        "generated_at": ts(audit::now_ms()),
        "generated_by": who.label(),
        "tool": format!("seagent {}", env!("CARGO_PKG_VERSION")),
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

/// `seagent usage --by user|team [--days N]`.
pub fn usage_by(a: &Args, by: &str) -> R {
    if !matches!(by, "user" | "team") {
        return crate::usage("--by user|team");
    }
    let c = crate::build(a, crate::approver_for(a, false))?;
    let days = a.num::<u64>("days")?.unwrap_or(30);
    let rows = seagent_kernel::governance::usage_by(&c.k, by, audit::now_ms().saturating_sub(days * 86_400_000));
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
    let since = seagent_kernel::governance::period_start(&q.period, audit::now_ms());
    let users = seagent_kernel::governance::usage_by(&c.k, "user", since);
    let teams = seagent_kernel::governance::usage_by(&c.k, "team", since);
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
        assert_eq!(seagent_app::identity::accounts(&kit.paths.data)[0].role, "operator");
        assert_eq!(run(&kit, &["rotate", "ci", "--grace-hours", "0"]).unwrap(), 0);
        assert_eq!(run(&kit, &["revoke", "ci"]).unwrap(), 0);
        assert!(seagent_app::identity::accounts(&kit.paths.data)[0].revoked);
        assert!(run(&kit, &["bogus"]).is_err());
    }

    #[test]
    fn nagios_plugin_output_and_exit_codes() {
        let good = json!({"ready": true, "checks": [{"name": "model", "ok": true, "detail": "x"}, {"name": "audit", "ok": true}]});
        let (c, l) = nagios(Some(&good), Some(3), 0);
        assert_eq!(c, 0);
        assert_eq!(l, "SEAGENT OK - 2 check(s) passed, 3 approval(s) pending | checks_ok=2;;;0;2 checks_failed=0;;0;0 approvals_pending=3;;;0");
        assert_eq!(nagios(Some(&good), Some(3), 3).0, 1, "--warn-pending 3");
        let bad = json!({"ready": false, "checks": [{"name": "model", "ok": false, "error": "HTTP 401 | bad key"}, {"name": "audit", "ok": true}]});
        let (c, l) = nagios(Some(&bad), None, 0);
        assert_eq!(c, 2);
        assert!(l.starts_with("SEAGENT CRITICAL - model: HTTP 401 / bad key | checks_ok=1"), "a `|` in the text would end it early: {l}");
        assert_eq!(nagios(None, None, 0).0, 2);
        assert_eq!(nagios(Some(&json!({"weird": 1})), None, 0).0, 3);
    }

    #[cfg(unix)]
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
        // Signed seals: a new key, sign the rotated segment, verify with only the public key.
        let key = p.data.join("seal.key");
        assert_eq!(audit_sub(p, &a(&["seal-key", "--out", key.to_str().unwrap()])).unwrap().unwrap(), 0);
        assert!(audit_sub(p, &a(&["seal-key", "--out", key.to_str().unwrap()])).unwrap().is_err(), "never overwrites a key");
        let seed = std::fs::read_to_string(&key).unwrap().trim().to_string();
        let public = seagent_security::signing::public_of(&seed).unwrap();
        assert_eq!(audit_sub(p, &a(&["verify", "--pubkey", &public, "--require-signed"])).unwrap().unwrap(), 1, "the segment is not signed yet");
        assert_eq!(seagent_security::audit_seal::sign_pending(&p.data, &seed, None).unwrap(), 1);
        assert_eq!(audit_sub(p, &a(&["verify", "--pubkey", &public, "--require-signed"])).unwrap().unwrap(), 0);
        // The auditor's report, as a file.
        let rep = p.data.join("report.html");
        assert_eq!(audit_sub(p, &a(&["report", "--from", "1d", "--format", "html", "--pubkey", &public, "--out", rep.to_str().unwrap()])).unwrap().unwrap(), 0);
        let html = std::fs::read_to_string(&rep).unwrap();
        assert!(html.contains("Configuration changes (2)") && html.contains("Signed seals: 1 signed"), "{html}");
        assert!(audit::all(&p.data).iter().any(|r| r["kind"] == "audit.report"));
        assert!(audit_sub(p, &a(&["report", "--format", "pdf"])).unwrap().is_err());
        // A tampered archive makes `verify` exit 1.
        let seg = audit::segments(&p.data).into_iter().next().unwrap();
        #[cfg(unix)]
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
        log.append(seagent_kernel::event::EventKind::Message { message: seagent_core::Message::user("the merger contract is with bob@corp.example"), usage: None, model: None, inbox: None }).unwrap();
        let s2 = k.create_session(&ws, None, None, Some("lunch")).unwrap();
        k.submit(&s2, "lunch at noon", "cli").unwrap();
        let u = seagent_kernel::agents::user_add(&k.paths, "ann").unwrap();
        seagent_kernel::agents::user_link(&k.paths, &u.id, "slack", "U1").unwrap();
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
