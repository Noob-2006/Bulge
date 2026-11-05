//! Suggested automations (Hermes `cron/suggestions.py`, `cron/suggestion_catalog.py`,
//! `hermes_cli/suggestions_cmd.py`): ready-to-run job specs the user accepts (creates the real
//! job through `cronjob::create`) or dismisses (latched by `dedup_key`, never re-offered).
//! Nothing auto-schedules (consent first). Stored in `<data>/cron_suggestions.json`.

use super::{create, Settings, Spec};
use crate::automation::{read_list, with_list};
use crate::util::{random_hex, unix_now};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Cap pending suggestions so the list never becomes a nag wall.
pub const MAX_PENDING: usize = 5;
pub const SOURCES: &[&str] = &["catalog", "blueprint", "usage", "integration"];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JobSpec {
    pub prompt: String,
    pub schedule: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub deliver: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    pub id: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub job_spec: JobSpec,
    pub dedup_key: String,
    /// `pending` | `accepted` | `dismissed`
    pub status: String,
    pub created_at: i64,
    #[serde(default)]
    pub resolved_at: Option<i64>,
}

pub fn path(data: &Path) -> PathBuf {
    data.join("cron_suggestions.json")
}

pub fn load(data: &Path) -> Vec<Suggestion> {
    read_list(&path(data)).unwrap_or_default()
}

pub fn pending(data: &Path) -> Vec<Suggestion> {
    load(data).into_iter().filter(|s| s.status == "pending").collect()
}

/// Register a pending suggestion; `Ok(None)` when its dedup_key was already offered/decided or
/// the pending list is full.
pub fn add(data: &Path, title: &str, description: &str, source: &str, spec: JobSpec, dedup_key: &str) -> Result<Option<Suggestion>, String> {
    if !SOURCES.contains(&source) {
        return Err(format!("unknown suggestion source: {source:?}"));
    }
    if title.trim().is_empty() || dedup_key.trim().is_empty() {
        return Err("title and dedup_key are required".into());
    }
    with_list(&path(data), |v: &mut Vec<Suggestion>| {
        if v.iter().any(|s| s.dedup_key == dedup_key.trim()) {
            return None;
        }
        if v.iter().filter(|s| s.status == "pending").count() >= MAX_PENDING {
            return None;
        }
        let rec = Suggestion { id: random_hex(12), title: title.trim().into(), description: description.trim().into(), source: source.into(), job_spec: spec, dedup_key: dedup_key.trim().into(), status: "pending".into(), created_at: unix_now(), resolved_at: None };
        v.push(rec.clone());
        Some(rec)
    })
}

/// By id, 1-based pending index, or exact (case-insensitive) title.
pub fn get(data: &Path, r: &str) -> Option<Suggestion> {
    let all = load(data);
    if let Some(s) = all.iter().find(|s| s.id == r) {
        return Some(s.clone());
    }
    if let Ok(i) = r.parse::<usize>() {
        let p: Vec<&Suggestion> = all.iter().filter(|s| s.status == "pending").collect();
        if i >= 1 && i <= p.len() {
            return Some(p[i - 1].clone());
        }
    }
    all.into_iter().find(|s| s.title.eq_ignore_ascii_case(r))
}

fn set_status(data: &Path, id: &str, status: &str) -> Result<bool, String> {
    with_list(&path(data), |v: &mut Vec<Suggestion>| match v.iter_mut().find(|s| s.id == id) {
        Some(s) => {
            s.status = status.into();
            s.resolved_at = Some(unix_now());
            true
        }
        None => false,
    })
}

pub fn dismiss(data: &Path, r: &str) -> Result<bool, String> {
    match get(data, r) {
        Some(s) if s.status == "pending" => set_status(data, &s.id, "dismissed"),
        _ => Ok(false),
    }
}

/// Create the real job from the stored spec; `origin` = the accepting session.
pub fn accept(data: &Path, st: &Settings, r: &str, ws: &Path, origin: Option<&str>) -> Result<Option<crate::automation::Job>, String> {
    let Some(s) = get(data, r).filter(|s| s.status == "pending") else { return Ok(None) };
    let spec = Spec {
        prompt: Some(s.job_spec.prompt.clone()),
        schedule: Some(s.job_spec.schedule.clone()),
        name: s.job_spec.name.clone().or_else(|| Some(s.title.clone())),
        deliver: s.job_spec.deliver.clone(),
        skills: Some(s.job_spec.skills.clone()),
        origin: origin.map(String::from),
        ..Default::default()
    };
    let job = create(data, st, spec, ws)?;
    set_status(data, &s.id, "accepted")?;
    Ok(Some(job))
}

/// Drop accepted records (dismissed ones stay for their dedup_key).
pub fn clear_resolved(data: &Path) -> Result<usize, String> {
    with_list(&path(data), |v: &mut Vec<Suggestion>| {
        let n = v.len();
        v.retain(|s| s.status != "accepted");
        n - v.len()
    })
}

/// The curated starter set (Hermes `CATALOG`).
pub fn catalog() -> Vec<(&'static str, &'static str, &'static str, JobSpec)> {
    let spec = |prompt: &str, schedule: &str, name: &str| JobSpec { prompt: prompt.into(), schedule: schedule.into(), name: Some(name.into()), deliver: Some("origin".into()), skills: vec![] };
    vec![
        ("catalog:daily-briefing", "Daily briefing", "Every morning at 8am, a short briefing: today's calendar, weather, and anything urgent waiting on you.",
         spec("Produce a concise morning briefing for the user: today's calendar events, the local weather, and any urgent items (unread important email, due tasks). Keep it short and scannable. If you have no connected data sources, give a brief general good-morning with the date and offer to connect calendar/email.", "0 8 * * *", "Daily briefing")),
        ("catalog:important-mail-monitor", "Important-mail monitor", "Check your inbox periodically and ping you ONLY about mail that actually needs attention — never the newsletters.",
         spec("Check the user's inbox for new messages since the last run. For each candidate, judge urgency against this rule: surface only mail that needs a reply today, is from a manager/family member, or mentions a deadline. Deliver ONLY what clears that bar. If nothing clears the bar, respond with [SILENT] so the user is not pinged. Requires a connected mail source; if none is configured, explain how to connect one and then stop.", "every 30m", "Important-mail monitor")),
        ("catalog:weekly-review", "Weekly review", "Every Sunday evening, a recap of the week: what got done, what's still open, and what's coming up next week.",
         spec("Produce a weekly review for the user: summarize what was accomplished this week, list still-open items, and preview next week's calendar. Pull from whatever sources are connected (calendar, task tools, recent conversations). Keep it tight.", "0 18 * * 0", "Weekly review")),
        ("catalog:standup-reminder", "Workday start reminder", "A weekday nudge at 9am with your day's agenda and top priorities, so you start focused.",
         spec("Give the user a brief weekday start-of-day nudge: their calendar for today and the 1-3 highest-priority things to focus on, inferred from recent context and any task tools. Encouraging, short, one message.", "0 9 * * 1-5", "Workday start reminder")),
    ]
}

/// Register catalog entries (idempotent: decided/pending keys and the cap are respected).
pub fn seed_catalog(data: &Path) -> Result<Vec<Suggestion>, String> {
    let mut out = Vec::new();
    for (key, title, desc, spec) in catalog() {
        if let Some(s) = add(data, title, desc, "catalog", spec, key)? {
            out.push(s);
        }
    }
    Ok(out)
}

pub const USAGE: &str = "Usage:\n  /suggestions              list pending\n  /suggestions accept N     schedule suggestion N\n  /suggestions dismiss N    dismiss suggestion N\n  /suggestions catalog      add curated starter automations\n  /suggestions clear        housekeeping";

/// `/suggestions …` and `ark schedule suggestions …` (Hermes `handle_suggestions_command`).
pub fn command(data: &Path, st: &Settings, args: &str, ws: &Path, origin: Option<&str>, surface: &str) -> String {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let rest = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
    match parts.first().map(|s| s.to_ascii_lowercase()).as_deref().unwrap_or("") {
        "" | "list" => {
            let p = pending(data);
            if p.is_empty() {
                return "No suggested automations right now.\nTry `/suggestions catalog` to see the curated starter set.".into();
            }
            let mut lines = vec!["Suggested automations — `/suggestions accept N` or `dismiss N`:\n".to_string()];
            for (i, s) in p.iter().enumerate() {
                lines.push(format!("  {}. {}  [{}]  ({})", i + 1, s.title, s.job_spec.schedule, s.source));
                if !s.description.is_empty() {
                    lines.push(format!("     {}", s.description));
                }
            }
            lines.join("\n")
        }
        "accept" | "add" | "schedule" => {
            if rest.is_empty() {
                return "Usage: /suggestions accept <number|id>".into();
            }
            match accept(data, st, &rest, ws, origin) {
                Ok(Some(j)) => {
                    let manage = if surface == "cli" { "Manage it with `ark schedule`." } else { "Ask me to list, pause, or remove it any time." };
                    format!("Scheduled '{}' ({}). {manage}", j.ext.name.clone().unwrap_or_default(), j.ext.display.clone().unwrap_or_default())
                }
                Ok(None) => format!("No pending suggestion matches '{rest}'. Run /suggestions to list them."),
                Err(e) => format!("Couldn't schedule it: {e}"),
            }
        }
        "dismiss" | "no" | "reject" => {
            if rest.is_empty() {
                return "Usage: /suggestions dismiss <number|id>".into();
            }
            match dismiss(data, &rest) {
                Ok(true) => "Dismissed. Won't suggest that again.".into(),
                _ => format!("No pending suggestion matches '{rest}'."),
            }
        }
        "catalog" => match seed_catalog(data) {
            Ok(c) if c.is_empty() => "No new catalog automations to add (already offered, dismissed, or your suggestion list is full). Run /suggestions to see pending.".into(),
            Ok(c) => format!("Added {} suggestion(s): {}.\nRun /suggestions to review.", c.len(), c.iter().map(|s| s.title.as_str()).collect::<Vec<_>>().join(", ")),
            Err(e) => format!("Couldn't load the catalog: {e}"),
        },
        "clear" => format!("Cleared {} resolved suggestion record(s).", clear_resolved(data).unwrap_or(0)),
        _ => USAGE.into(),
    }
}
