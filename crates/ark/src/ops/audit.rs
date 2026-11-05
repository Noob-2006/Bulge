//! `ark audit` (OpenClaw `openclaw audit`): bounded, metadata-only activity history
//! derived from the session event logs — agent runs (turns), tool actions and channel
//! messages — never message text, tool inputs or results.
//!
//! Filters: `--agent`, `--session`, `--run <session>:<turn>`, `--kind
//! agent_run|tool_action|message`, `--status`, `--direction inbound|outbound`,
//! `--channel`, `--after`/`--before` (ISO-8601 or Unix ms), `--limit` (1-500, default
//! 100; 1-100 with `--explain`), `--cursor` (continuation from a previous page),
//! `--json`. `--explain --run R` inspects one exact run: its tools and every gate
//! decision (decision receipts) with reasons, plus the upstream receipt blocks:
//! `identity` (profile, surface, channel, gateway node id), `authority.representedSubject`
//! (the acting user or channel sender), `lineage` (parent session / parent execution)
//! and `coverage.missingEvidence`. Everything comes from the event log; what ark never
//! records (gateway node identity, execution ids) is reported as missing evidence
//! rather than invented.

use crate::args::Args;
use crate::R;
use ark_core::Role;
use ark_kernel::config::Paths;
use ark_kernel::event::{Event, EventKind};
use ark_kernel::store::Store;
use serde::Serialize;
use serde_json::json;

pub const COMMANDS: &[&str] = &["audit"];
pub const VALUE_FLAGS: &[&str] = &["agent", "run", "kind", "status", "direction", "channel", "after", "before", "cursor", "execution"];
pub const BOOL_FLAGS: &[&str] = &["explain"];

pub const KINDS: &[&str] = &["agent_run", "tool_action", "message"];
pub const STATUSES: &[&str] = &["started", "succeeded", "failed", "cancelled", "timed_out", "blocked", "unknown"];
pub const DIRECTIONS: &[&str] = &["inbound", "outbound"];
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;
const DEFAULT_DECISION_LIMIT: usize = 50;
const MAX_DECISION_LIMIT: usize = 100;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Activity {
    #[serde(rename = "occurredAt")]
    pub occurred_at: u64,
    pub kind: String,
    pub status: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "sessionKey")]
    pub session: String,
    #[serde(rename = "runId", skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(rename = "toolName", skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

fn channel_of(source: &str) -> Option<String> {
    let (c, _) = source.split_once(':')?;
    (!c.is_empty() && !matches!(c, "cli" | "tui" | "web" | "app" | "cron" | "schedule" | "subagent" | "hook")).then(|| c.to_string())
}

fn turn_status(reason: &str) -> &'static str {
    match reason {
        "done" | "idle" | "end_turn" | "yield" | "structured" => "succeeded",
        "interrupted" | "cancelled" | "canceled" | "stopped" => "cancelled",
        "timeout" | "timed_out" => "timed_out",
        r if r.contains("budget") || r.contains("denied") || r.contains("blocked") => "blocked",
        r if r.contains("error") || r.contains("fail") => "failed",
        "max_steps" | "max_turns" => "failed",
        _ => "unknown",
    }
}

/// Activity records of one session, oldest first.
pub fn session_activity(session: &str, events: &[Event]) -> Vec<Activity> {
    let mut out: Vec<Activity> = vec![];
    let mut agent = "default".to_string();
    let mut turn: Option<(u64, usize)> = None; // (turn, index of its record)
    let mut tools: std::collections::HashMap<String, usize> = Default::default();
    let mut last_channel: Option<String> = None;
    let rec = |kind: &str, status: &str, action: String, ts: u64, agent: &str, run: Option<String>| Activity { occurred_at: ts, kind: kind.into(), status: status.into(), action, direction: None, channel: None, agent_id: agent.into(), session: session.into(), run_id: run, tool_name: None };
    for e in events {
        let run = turn.map(|(t, _)| format!("{session}:{t}"));
        match &e.kind {
            EventKind::Agent { agent: a, .. } => agent = a.clone(),
            EventKind::TurnStart { turn: t } => {
                out.push(rec("agent_run", "started", "run".into(), e.ts, &agent, Some(format!("{session}:{t}"))));
                turn = Some((*t, out.len() - 1));
            }
            EventKind::TurnEnd { reason, .. } => {
                if let Some((_, i)) = turn.take() {
                    out[i].status = turn_status(reason).into();
                }
            }
            EventKind::Error { .. } => {
                if let Some((_, i)) = turn {
                    out[i].status = "failed".into();
                }
            }
            EventKind::ToolCalled { tool_use_id, name, .. } => {
                let mut r = rec("tool_action", "started", "tool".into(), e.ts, &agent, run);
                r.tool_name = Some(name.clone());
                out.push(r);
                tools.insert(tool_use_id.clone(), out.len() - 1);
            }
            EventKind::ToolSettled { tool_use_id, is_error, .. } => {
                if let Some(&i) = tools.get(tool_use_id) {
                    if out[i].status == "started" {
                        out[i].status = if *is_error { "failed" } else { "succeeded" }.into();
                    }
                }
            }
            EventKind::Gate { tool_use_id, verdict, .. } if matches!(verdict.as_str(), "deny" | "denied" | "block" | "blocked" | "reject") => {
                if let Some(&i) = tools.get(tool_use_id) {
                    out[i].status = "blocked".into();
                }
            }
            EventKind::Inbox { source, .. } => {
                last_channel = channel_of(source);
                if let Some(c) = &last_channel {
                    let mut r = rec("message", "succeeded", "receive".into(), e.ts, &agent, None);
                    r.direction = Some("inbound".into());
                    r.channel = Some(c.clone());
                    out.push(r);
                }
            }
            EventKind::Message { message, .. } if message.role == Role::Assistant && !message.text().trim().is_empty() => {
                if let Some(c) = &last_channel {
                    let mut r = rec("message", "succeeded", "send".into(), e.ts, &agent, run);
                    r.direction = Some("outbound".into());
                    r.channel = Some(c.clone());
                    out.push(r);
                }
            }
            _ => {}
        }
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub agent: Option<String>,
    pub session: Option<String>,
    pub run: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub direction: Option<String>,
    pub channel: Option<String>,
    pub after: Option<u64>,
    pub before: Option<u64>,
}

/// ISO-8601 (`2026-11-03`, `2026-11-03T10:00:00Z`, `…+08:00`) or Unix milliseconds.
pub fn parse_ts(v: &str, flag: &str) -> Result<u64, String> {
    let t = v.trim();
    let bad = || format!("{flag} must be an ISO timestamp or Unix milliseconds.");
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        return t.parse().map_err(|_| bad());
    }
    let (date, rest) = t.split_at(t.find(['T', ' ']).unwrap_or(t.len()));
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 {
        return Err(bad());
    }
    let (y, m, dd) = (d[0].parse::<i64>().map_err(|_| bad())?, d[1].parse::<u32>().map_err(|_| bad())?, d[2].parse::<u32>().map_err(|_| bad())?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&dd) {
        return Err(bad());
    }
    let mut secs = ark_kernel::util::days_from_civil(y, m, dd) * 86_400;
    let mut ms = 0u64;
    let rest = rest.trim_start_matches(['T', ' ']);
    if !rest.is_empty() {
        let (clock, tz) = match rest.find(['Z', 'z', '+', '-']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let c: Vec<&str> = clock.split(':').collect();
        let h: i64 = c.first().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        let mi: i64 = c.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let (s, frac) = c.get(2).map(|s| s.split_once('.').unwrap_or((s, ""))).unwrap_or(("0", ""));
        let s: i64 = s.parse().map_err(|_| bad())?;
        if h > 23 || mi > 59 || s > 60 {
            return Err(bad());
        }
        ms = format!("{frac:0<3}").chars().take(3).collect::<String>().parse().unwrap_or(0);
        secs += h * 3600 + mi * 60 + s;
        if let Some(off) = tz.strip_prefix(['+', '-']) {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            let o: Vec<&str> = off.split(':').collect();
            let oh: i64 = o.first().and_then(|s| s.get(..2)).and_then(|s| s.parse().ok()).ok_or_else(bad)?;
            let om: i64 = o.get(1).and_then(|s| s.parse().ok()).or_else(|| off.get(2..4).and_then(|s| s.parse().ok())).unwrap_or(0);
            secs -= sign * (oh * 3600 + om * 60);
        }
    }
    u64::try_from(secs).map(|s| s * 1000 + ms).map_err(|_| bad())
}

fn one_of(v: &Option<String>, flag: &str, allowed: &[&str]) -> Result<(), String> {
    match v {
        Some(x) if !allowed.contains(&x.as_str()) => Err(format!("{flag} must be {}.", allowed.join(", "))),
        _ => Ok(()),
    }
}

impl Filter {
    pub fn validate(&self) -> Result<(), String> {
        one_of(&self.kind, "--kind", KINDS)?;
        one_of(&self.status, "--status", STATUSES)?;
        one_of(&self.direction, "--direction", DIRECTIONS)?;
        let msg_field = self.direction.is_some() || self.channel.is_some();
        if let Some(k) = &self.kind {
            if k != "message" && msg_field {
                let f = if self.direction.is_some() { "--direction" } else { "--channel" };
                return Err(format!("{f} only applies to --kind message."));
            }
        }
        if self.kind.as_deref() == Some("message") && self.run.is_some() {
            return Err("--run only applies to --kind agent_run, tool_action.".into());
        }
        if let (Some(a), Some(b)) = (self.after, self.before) {
            if a > b {
                return Err("--after must not be later than --before.".into());
            }
        }
        Ok(())
    }
    fn matches(&self, r: &Activity) -> bool {
        let eq = |f: &Option<String>, v: Option<&str>| f.as_deref().is_none_or(|x| Some(x) == v);
        eq(&self.agent, Some(&r.agent_id))
            && eq(&self.session, Some(&r.session))
            && eq(&self.run, r.run_id.as_deref())
            && eq(&self.kind, Some(&r.kind))
            && eq(&self.status, Some(&r.status))
            && eq(&self.direction, r.direction.as_deref())
            && eq(&self.channel, r.channel.as_deref())
            && self.after.is_none_or(|a| r.occurred_at >= a)
            && self.before.is_none_or(|b| r.occurred_at <= b)
    }
}

/// Newest-first page → (records, next cursor). The cursor is the count already returned.
pub fn query(store: &Store, f: &Filter, limit: usize, cursor: usize) -> (Vec<Activity>, Option<String>) {
    let sessions: Vec<String> = match &f.session {
        Some(s) => vec![s.clone()],
        None => store.list().into_iter().map(|s| s.id).collect(),
    };
    let mut all: Vec<Activity> = sessions.iter().filter_map(|s| store.read(s).ok().map(|ev| session_activity(s, &ev))).flatten().filter(|r| f.matches(r)).collect();
    all.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at).then_with(|| b.session.cmp(&a.session)));
    let page: Vec<Activity> = all.iter().skip(cursor).take(limit).cloned().collect();
    let next = (cursor + page.len() < all.len()).then(|| (cursor + page.len()).to_string());
    (page, next)
}

fn short(v: Option<&str>, n: usize) -> String {
    let s: String = v.unwrap_or("").chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        "-".into()
    } else if s.chars().count() <= n {
        s
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

fn iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, m, d) = ark_kernel::util::civil_from_days(secs.div_euclid(86_400));
    let r = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", r / 3600, r / 60 % 60, r % 60, ms % 1000)
}

pub fn rows(v: &[Activity]) -> String {
    let mut o = vec!["TIME\tKIND\tDIRECTION\tCHANNEL\tSTATUS\tAGENT\tRUN\tACTION".to_string()];
    for r in v {
        o.push([iso(r.occurred_at), r.kind.clone(), short(r.direction.as_deref(), 10), short(r.channel.as_deref(), 18), r.status.clone(), short(Some(&r.agent_id), 18), short(r.run_id.as_deref(), 18), match &r.tool_name {
            Some(t) => format!("{}:{}", r.action, short(Some(t), 28)),
            None => r.action.clone(),
        }]
        .join("\t"));
    }
    o.join("\n")
}

/// The ingress source of a run: the inbox entry queued at or before its turn started.
fn ingress_of(ev: &[Event], turn: u64) -> Option<String> {
    let i = ev.iter().position(|e| matches!(&e.kind, EventKind::TurnStart { turn: t } if *t == turn))?;
    ev[..=i].iter().rev().find_map(|e| match &e.kind {
        EventKind::Inbox { source, .. } => Some(source.clone()),
        _ => None,
    })
}

fn subject_of(ev: &[Event], source: Option<&str>) -> serde_json::Value {
    let user = ev.iter().rev().find_map(|e| match &e.kind {
        EventKind::Agent { user: Some(u), .. } if !u.trim().is_empty() => Some(u.clone()),
        _ => None,
    });
    if let Some(u) = user {
        return json!({"state": "present", "kind": "user", "id": u});
    }
    // A channel-backed ingress names the sender (`telegram:42`); CLI inputs do not.
    let sender = source.and_then(|s| {
        channel_of(s)?;
        let (_, id) = s.split_once(':')?;
        let id = id.trim().trim_end_matches('/').to_string();
        (!id.is_empty()).then_some(id)
    });
    match sender {
        Some(id) if !id.is_empty() => json!({"state": "present", "kind": "channel_sender", "id": id}),
        _ => json!({"state": "absent", "reasonCode": "no_identity_event"}),
    }
}

/// Upstream receipt blocks (`identity`, `authority`, `lineage`, `coverage`) built only
/// from what ark actually records: the session header, the agent/user event and the
/// queued inbox source. Gateway identity and execution ids never reach the log, so they
/// are reported as missing evidence instead of being invented.
pub fn receipt_context(session: &str, ev: &[Event], turn: u64) -> (serde_json::Value, serde_json::Value, serde_json::Value, serde_json::Value) {
    let mut missing: Vec<String> = vec![];
    let source = ingress_of(ev, turn);
    let surface = source.as_deref().map(|s| s.split(':').next().unwrap_or("").trim().to_string()).filter(|s| !s.is_empty());
    let channel = surface.as_ref().and(source.as_deref()).and_then(channel_of);
    if surface.is_none() {
        missing.push("identity.surface".into());
    }
    if channel.is_none() {
        missing.push("identity.channel".into());
    }
    missing.push("identity.gatewayNodeId".into());
    let subject = subject_of(ev, source.as_deref());
    if subject["state"] != "present" {
        missing.push("authority.representedSubject".into());
    }
    let parent = ev.iter().find_map(|e| match &e.kind {
        EventKind::Header { parent: Some(p), .. } if !p.trim().is_empty() => Some(p.clone()),
        _ => None,
    });
    missing.push("lineage.parentExecution".into());
    let identity_fields = [surface.is_some(), channel.is_some()];
    // surface and channel known still leaves the gateway node id unrecorded.
    let state = if identity_fields.iter().any(|k| *k) { "partial" } else { "absent" };
    let attributed = identity_fields.iter().any(|k| *k) || subject["state"] == "present" || parent.is_some();
    let coverage = if missing.is_empty() {
        "complete"
    } else if attributed {
        "partial"
    } else {
        "unattributed"
    };
    let identity = json!({
        "state": state,
        "profile": crate::ops::profile::current(),
        "sessionKey": session,
        "surface": surface,
        "channel": channel,
        "gatewayNodeId": serde_json::Value::Null,
        "missingEvidence": missing,
    });
    let lineage = json!({
        "state": if parent.is_some() { "present" } else { "absent" },
        "parentSession": parent,
        "parentExecution": serde_json::Value::Null,
    });
    (identity, json!({"representedSubject": subject}), lineage, json!({"state": coverage, "missingEvidence": missing}))
}

/// `--explain --run S:T`: the run's tools and gate decisions.
pub fn explain(store: &Store, run: &str, limit: usize) -> Result<serde_json::Value, String> {
    let (session, turn) = run.rsplit_once(':').ok_or("--run must be <session>:<turn> as shown by `ark audit`")?;
    let turn: u64 = turn.parse().map_err(|_| "--run must be <session>:<turn>")?;
    let ev = store.read(session).map_err(|e| e.to_string())?;
    let acts: Vec<Activity> = session_activity(session, &ev).into_iter().filter(|a| a.run_id.as_deref() == Some(run)).collect();
    let run_rec = acts.iter().find(|a| a.kind == "agent_run").cloned().ok_or_else(|| format!("no run {run}"))?;
    let mut inside = false;
    let mut decisions = vec![];
    let mut model = String::new();
    for e in &ev {
        match &e.kind {
            EventKind::Header { model: m, .. } | EventKind::Model { model: m } => model = m.clone(),
            EventKind::TurnStart { turn: t } => inside = *t == turn,
            EventKind::TurnEnd { turn: t, .. } if *t == turn => inside = false,
            EventKind::Gate { tool_use_id, gate, verdict, reason } if inside && decisions.len() < limit => decisions.push(json!({"occurredAt": e.ts, "toolUseId": tool_use_id, "gate": gate, "verdict": verdict, "reason": reason})),
            _ => {}
        }
    }
    let (identity, authority, lineage, coverage) = receipt_context(session, &ev, turn);
    Ok(json!({"schemaVersion": 1, "run": {"runId": run, "status": run_rec.status, "agentId": run_rec.agent_id, "sessionKey": session, "model": model, "startedAt": run_rec.occurred_at}, "identity": identity, "authority": authority, "lineage": lineage, "tools": acts.iter().filter(|a| a.kind == "tool_action").map(|a| json!({"tool": a.tool_name, "status": a.status, "occurredAt": a.occurred_at})).collect::<Vec<_>>(), "decisionDisplays": decisions, "coverage": coverage}))
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "audit" {
        return None;
    }
    let paths = Paths::from_env();
    // The unified, hash-chained stream (ent-072/073): `events`, `verify`, `head`, `rotate`, `export`.
    if let Some(r) = crate::ops::enterprise::audit_sub(&paths, a) {
        return Some(r);
    }
    Some(run(&paths, a))
}

/// Command body, parameterised on the paths so tests can point it at a temp layout.
pub fn run(paths: &Paths, a: &Args) -> R {
    (|| -> R {
        let store = Store::new(paths.sessions());
        let explain_mode = a.flag("explain");
        // Upstream rejects mixed modes instead of silently ignoring the activity filters.
        if explain_mode {
            let stray: Vec<String> = ["agent", "session", "kind", "status", "direction", "channel", "after", "before"].into_iter().filter(|k| a.val(k).is_some()).map(|k| format!("--{k}")).collect();
            if !stray.is_empty() {
                return crate::usage(format!("--explain accepts only --run or --execution, plus --limit, --cursor and --json; remove {}", stray.join(", ")));
            }
            if a.val("run").is_some() && a.val("execution").is_some() {
                return crate::usage("pass exactly one of --run <session>:<turn> or --execution <session>:<turn> with --explain");
            }
        } else if a.val("execution").is_some() {
            return crate::usage("--execution requires --explain");
        }
        let (def, max) = if explain_mode { (DEFAULT_DECISION_LIMIT, MAX_DECISION_LIMIT) } else { (DEFAULT_LIMIT, MAX_LIMIT) };
        let limit = match a.val("limit") {
            None => def,
            Some(v) => v.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or_else(|| format!("--limit must be between 1 and {max}{}.", if explain_mode { " with --explain" } else { "" }))?,
        };
        let run = a.val("run").or(a.val("execution")).map(String::from);
        if explain_mode {
            let r = run.ok_or("--explain needs --run <session>:<turn> (or --execution)")?;
            let v = explain(&store, &r, limit)?;
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                println!("Run {} [{}] agent {} model {}", r, v["run"]["status"].as_str().unwrap_or(""), v["run"]["agentId"].as_str().unwrap_or(""), v["run"]["model"].as_str().unwrap_or(""));
                for t in v["tools"].as_array().into_iter().flatten() {
                    println!("  tool {} [{}]", t["tool"].as_str().unwrap_or(""), t["status"].as_str().unwrap_or(""));
                }
                let d = v["decisionDisplays"].as_array().cloned().unwrap_or_default();
                println!("Decisions: {}", if d.is_empty() { "none recorded".to_string() } else { d.len().to_string() });
                for x in d {
                    println!("  {} gate: {} — {}", x["gate"].as_str().unwrap_or(""), x["verdict"].as_str().unwrap_or(""), short(x["reason"].as_str(), 160));
                }
                let id = &v["identity"];
                println!(
                    "Identity: profile {} surface {} channel {} gateway node {}",
                    id["profile"].as_str().unwrap_or("-"),
                    id["surface"].as_str().unwrap_or("-"),
                    id["channel"].as_str().unwrap_or("-"),
                    id["gatewayNodeId"].as_str().unwrap_or("unknown"),
                );
                let s = &v["authority"]["representedSubject"];
                println!("Authority: represented subject {}", match s["state"].as_str() {
                    Some("present") => format!("{}:{}", s["kind"].as_str().unwrap_or("-"), s["id"].as_str().unwrap_or("-")),
                    _ => "not recorded".to_string(),
                });
                println!("Lineage: parent session {}", v["lineage"]["parentSession"].as_str().unwrap_or("none"));
                let missing: Vec<&str> = v["coverage"]["missingEvidence"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
                println!("Coverage: {}{}", v["coverage"]["state"].as_str().unwrap_or("unknown"), if missing.is_empty() { String::new() } else { format!("; missing {}", missing.join(", ")) });
            }
            return Ok(0);
        }
        let ts = |k: &str| a.val(k).map(|v| parse_ts(v, &format!("--{k}"))).transpose();
        let f = Filter { agent: a.val("agent").map(String::from), session: a.val("session").map(String::from), run, kind: a.val("kind").map(String::from), status: a.val("status").map(String::from), direction: a.val("direction").map(String::from), channel: a.val("channel").map(String::from), after: ts("after")?, before: ts("before")? };
        f.validate()?;
        let cursor = match a.val("cursor") {
            None => 0,
            Some(c) => c.parse::<usize>().map_err(|_| "--cursor must be a continuation token returned by a previous audit result.")?,
        };
        let (page, next) = query(&store, &f, limit, cursor);
        if a.flag("json") {
            println!("{}", serde_json::to_string_pretty(&json!({"schemaVersion": 1, "events": page, "nextCursor": next})).unwrap_or_default());
        } else {
            println!("{}", rows(&page));
            if let Some(n) = next {
                println!("more: --cursor {n}");
            }
        }
        Ok(0)
    })()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{Message, Usage};

    fn ev(seq: u64, ts: u64, kind: EventKind) -> Event {
        Event { seq, ts, kind }
    }

    fn sample() -> Vec<Event> {
        vec![
            ev(1, 1000, EventKind::Agent { agent: "ops".into(), user: None }),
            ev(2, 1100, EventKind::Inbox { id: "i1".into(), source: "telegram:42".into(), text: "secret question".into(), attachments: vec![] }),
            ev(3, 1200, EventKind::TurnStart { turn: 1 }),
            ev(4, 1300, EventKind::ToolCalled { tool_use_id: "t1".into(), name: "shell".into(), input: json!({"cmd": "rm -rf"}), idempotency_key: "k".into() }),
            ev(5, 1350, EventKind::Gate { tool_use_id: "t1".into(), gate: "exec".into(), verdict: "deny".into(), reason: "destructive".into() }),
            ev(6, 1400, EventKind::ToolSettled { tool_use_id: "t1".into(), is_error: true, bytes: 3, artifact: None, ui_resource: None }),
            ev(7, 1500, EventKind::ToolCalled { tool_use_id: "t2".into(), name: "read".into(), input: json!({}), idempotency_key: "k2".into() }),
            ev(8, 1550, EventKind::ToolSettled { tool_use_id: "t2".into(), is_error: false, bytes: 3, artifact: None, ui_resource: None }),
            ev(9, 1600, EventKind::Message { message: Message::assistant("private answer"), usage: None, model: None, inbox: None }),
            ev(10, 1700, EventKind::TurnEnd { turn: 1, reason: "done".into(), usage: Usage::default() }),
            ev(11, 1800, EventKind::TurnStart { turn: 2 }),
            ev(12, 1900, EventKind::TurnEnd { turn: 2, reason: "interrupted".into(), usage: Usage::default() }),
        ]
    }

    #[test]
    fn activity_is_metadata_only() {
        let acts = session_activity("s1", &sample());
        let k: Vec<(&str, &str)> = acts.iter().map(|a| (a.kind.as_str(), a.status.as_str())).collect();
        assert_eq!(k, [("message", "succeeded"), ("agent_run", "succeeded"), ("tool_action", "blocked"), ("tool_action", "succeeded"), ("message", "succeeded"), ("agent_run", "cancelled")]);
        assert_eq!(acts[0].direction.as_deref(), Some("inbound"));
        assert_eq!(acts[4].direction.as_deref(), Some("outbound"));
        assert_eq!(acts[4].channel.as_deref(), Some("telegram"));
        assert_eq!(acts[2].run_id.as_deref(), Some("s1:1"));
        assert_eq!(acts[1].agent_id, "ops");
        let j = serde_json::to_string(&acts).unwrap();
        assert!(!j.contains("secret") && !j.contains("private") && !j.contains("rm -rf"), "no payloads: {j}");
        let t = rows(&acts);
        assert!(t.starts_with("TIME\tKIND") && t.contains("tool:shell") && t.contains("1970-01-01T00:00:01.100Z"));
    }

    #[test]
    fn filters_pages_and_explain() {
        let kit = crate::testkit::kit();
        let store = Store::new(kit.paths.sessions());
        let id = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        {
            let mut log = store.open(&id).unwrap();
            for e in sample() {
                log.append(e.kind).unwrap();
            }
        }
        let all = query(&store, &Filter::default(), 100, 0).0;
        assert_eq!(all.len(), 6);
        assert!(all.windows(2).all(|w| w[0].occurred_at >= w[1].occurred_at), "newest first");
        let tools = Filter { kind: Some("tool_action".into()), status: Some("blocked".into()), ..Default::default() };
        assert_eq!(query(&store, &tools, 100, 0).0.len(), 1);
        let (p1, next) = query(&store, &Filter::default(), 4, 0);
        assert_eq!((p1.len(), next.as_deref()), (4, Some("4")));
        let (p2, next) = query(&store, &Filter::default(), 4, 4);
        assert_eq!((p2.len(), next), (2, None));
        assert!(Filter { kind: Some("agent_run".into()), channel: Some("x".into()), ..Default::default() }.validate().unwrap_err().contains("--channel only applies to --kind message"));
        assert!(Filter { kind: Some("nope".into()), ..Default::default() }.validate().is_err());
        let v = explain(&store, &format!("{id}:1"), 50).unwrap();
        assert_eq!(v["run"]["status"], "succeeded");
        assert_eq!(v["decisionDisplays"][0]["reason"], "destructive");
        assert_eq!(v["tools"].as_array().unwrap().len(), 2);
        // The receipt carries the upstream context blocks, filled from the event log.
        assert_eq!(v["identity"]["surface"], "telegram");
        assert_eq!(v["identity"]["channel"], "telegram");
        assert_eq!(v["authority"]["representedSubject"]["kind"], "channel_sender");
        assert_eq!(v["authority"]["representedSubject"]["id"], "42");
        assert_eq!(v["coverage"]["state"], "partial");
        assert!(explain(&store, "bad", 5).is_err());
    }

    #[test]
    fn explain_receipt_reports_identity_lineage_and_missing_evidence() {
        let kit = crate::testkit::kit();
        let store = Store::new(kit.paths.sessions());

        // A run with no identity events at all: no inbox ingress, no agent/user, no parent.
        let bare = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        {
            let mut log = store.open(&bare).unwrap();
            for e in [
                ev(1, 1000, EventKind::TurnStart { turn: 1 }),
                ev(2, 1100, EventKind::ToolCalled { tool_use_id: "t1".into(), name: "shell".into(), input: json!({"cmd": "cat private-notes.txt"}), idempotency_key: "k".into() }),
                ev(3, 1200, EventKind::ToolSettled { tool_use_id: "t1".into(), is_error: false, bytes: 9, artifact: None, ui_resource: None }),
                ev(4, 1300, EventKind::Message { message: Message::assistant("private answer"), usage: None, model: None, inbox: None }),
                ev(5, 1400, EventKind::TurnEnd { turn: 1, reason: "done".into(), usage: Usage::default() }),
            ] {
                log.append(e.kind).unwrap();
            }
        }
        let v = explain(&store, &format!("{bare}:1"), 50).unwrap();
        for block in ["identity", "authority", "lineage", "coverage"] {
            assert!(v.get(block).is_some(), "receipt has a {block} block: {v}");
        }
        assert_eq!(v["identity"]["state"], "absent");
        assert!(v["identity"]["surface"].is_null() && v["identity"]["channel"].is_null());
        assert!(v["identity"]["gatewayNodeId"].is_null(), "gateway identity is never recorded");
        assert!(!v["identity"]["profile"].as_str().unwrap_or("").is_empty(), "profile comes from Paths/profile");
        assert_eq!(v["authority"]["representedSubject"]["state"], "absent");
        assert!(v["lineage"]["parentSession"].is_null());
        let missing: Vec<&str> = v["coverage"]["missingEvidence"].as_array().unwrap().iter().filter_map(|m| m.as_str()).collect();
        for item in ["identity.surface", "identity.channel", "identity.gatewayNodeId", "authority.representedSubject", "lineage.parentExecution"] {
            assert!(missing.contains(&item), "{item} is listed as missing evidence: {missing:?}");
        }
        assert_eq!(v["coverage"]["state"], "unattributed");
        let j = serde_json::to_string(&v).unwrap();
        assert!(!j.contains("private answer") && !j.contains("private-notes"), "metadata only: {j}");

        // A child session with a channel ingress and an acting user: both are attributed.
        let parent = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        let child = kit.k.create_session(&kit.ws, None, Some(&parent), None).unwrap();
        {
            let mut log = store.open(&child).unwrap();
            for e in [
                ev(1, 1000, EventKind::Agent { agent: "ops".into(), user: Some("u42".into()) }),
                ev(2, 1050, EventKind::Inbox { id: "i1".into(), source: "telegram:42".into(), text: "hi".into(), attachments: vec![] }),
                ev(3, 1100, EventKind::TurnStart { turn: 1 }),
                ev(4, 1200, EventKind::TurnEnd { turn: 1, reason: "done".into(), usage: Usage::default() }),
            ] {
                log.append(e.kind).unwrap();
            }
        }
        let v = explain(&store, &format!("{child}:1"), 50).unwrap();
        assert_eq!(v["identity"]["surface"], "telegram");
        assert_eq!(v["identity"]["channel"], "telegram");
        assert_eq!(v["identity"]["state"], "partial", "gateway node id stays unknown");
        assert_eq!(v["authority"]["representedSubject"], json!({"state": "present", "kind": "user", "id": "u42"}));
        assert_eq!(v["lineage"]["parentSession"], parent.as_str());
        assert_eq!(v["lineage"]["state"], "present");
        assert_eq!(v["coverage"]["state"], "partial");
        let missing: Vec<&str> = v["coverage"]["missingEvidence"].as_array().unwrap().iter().filter_map(|m| m.as_str()).collect();
        assert!(!missing.contains(&"identity.surface") && !missing.contains(&"authority.representedSubject"), "{missing:?}");
        assert!(missing.contains(&"identity.gatewayNodeId") && missing.contains(&"lineage.parentExecution"), "{missing:?}");
    }

    #[test]
    fn dispatch_and_flag_handling() {
        let kit = crate::testkit::kit();
        let store = Store::new(kit.paths.sessions());
        let id = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        {
            let mut log = store.open(&id).unwrap();
            for e in sample() {
                log.append(e.kind).unwrap();
            }
        }
        let a = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<String>>()).unwrap();
        assert!(dispatch("not-audit", &a(&[]), &[]).is_none(), "only `audit` is claimed");
        assert_eq!(run(&kit.paths, &a(&["--json", "--limit", "2"])).unwrap(), 0);
        assert!(run(&kit.paths, &a(&["--limit", "501"])).unwrap_err().to_string().contains("--limit must be between 1 and 500"));
        assert!(run(&kit.paths, &a(&["--kind", "message", "--direction", "sideways"])).unwrap_err().to_string().contains("--direction must be inbound, outbound"));
        assert!(run(&kit.paths, &a(&["--explain"])).unwrap_err().to_string().contains("--explain needs --run"));
        assert_eq!(run(&kit.paths, &a(&["--explain", "--run", &format!("{id}:1")])).unwrap(), 0);
        assert_eq!(run(&kit.paths, &a(&["--cursor", "4", "--limit", "2"])).unwrap(), 0);
        assert!(run(&kit.paths, &a(&["--kind", "bogus"])).is_err(), "filter validation runs before the query");
        // mode mixing is refused exactly like upstream's `--explain` guard.
        let e = run(&kit.paths, &a(&["--explain", "--run", &format!("{id}:1"), "--kind", "message"])).unwrap_err().to_string();
        assert!(e.contains("remove --kind"), "{e}");
        assert!(run(&kit.paths, &a(&["--explain", "--run", &format!("{id}:1"), "--execution", &format!("{id}:1")])).is_err());
        assert!(run(&kit.paths, &a(&["--execution", &format!("{id}:1")])).unwrap_err().to_string().contains("--execution requires --explain"));
    }

    #[test]
    fn timestamps() {
        assert_eq!(parse_ts("1700000000000", "--after").unwrap(), 1_700_000_000_000);
        assert_eq!(parse_ts("1970-01-02", "--after").unwrap(), 86_400_000);
        assert_eq!(parse_ts("1970-01-01T01:00:00Z", "--after").unwrap(), 3_600_000);
        assert_eq!(parse_ts("1970-01-01T09:00:00.250+08:00", "--after").unwrap(), 3_600_000 + 250);
        assert!(parse_ts("yesterday", "--after").unwrap_err().contains("ISO timestamp"));
        assert_eq!(iso(86_400_000 + 5), "1970-01-02T00:00:00.005Z");
    }
}
