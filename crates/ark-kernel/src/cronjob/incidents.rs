//! Durable cron run history, failure incidents and the per-job notepad (Hermes
//! `cron/executions.py`, `cron/incidents.py`, `cron/notepad.py`).
//!
//! Three stores, all under `<data>/`:
//! - `cron_runs/<job>.jsonl`: one line per attempt (`started_at`/`ended_at`/`duration_ms`,
//!   `status`, `summary`, `error`, delivery receipt), rotated to the newest [`RUN_LOG_KEEP`]
//!   lines so a chatty job can never grow the file without bound;
//! - `cron_incidents.json`: failures grouped by `(job, normalized-error)` signature so the same
//!   breakage is ONE incident (`detected` → `alerted` → `resolved`/`closed`) instead of one per
//!   run; [`INCIDENT_THRESHOLD`] consecutive failures open one, the next success resolves it,
//!   an operator `ack` closes it for good (a changed error mints a new incident);
//! - `cron_notepad/<job>.md`: free text the job (or its operator) leaves for the next run; it is
//!   injected into the prompt and printed by `ark schedule notepad`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Run-log lines kept per job (older attempts rotate out).
pub const RUN_LOG_KEEP: usize = 200;
/// Rotate hard when the file grew past this anyway (very long summaries).
pub const RUN_LOG_MAX_BYTES: usize = 1024 * 1024;
/// Incidents kept in the ledger (oldest rotate out once they are not open).
pub const INCIDENT_KEEP: usize = 200;
/// Consecutive failures before an incident opens (one flaky run is not an incident).
pub const INCIDENT_THRESHOLD: u32 = 3;
pub const MAX_ERROR_CHARS: usize = 500;
pub const MAX_SIGNATURE_CHARS: usize = 200;
pub const NOTEPAD_MAX_BYTES: usize = 64 * 1024;
/// Notepad text injected into a prompt (the CLI shows the whole note).
pub const NOTEPAD_PROMPT_CAP: usize = 4000;
/// A job whose `next_run` is this far in the past is not firing (same grace as `cron doctor`).
pub const OVERDUE_GRACE_SECS: i64 = 15 * 60;

pub const INCIDENT_STATES: [&str; 4] = ["detected", "alerted", "resolved", "closed"];

/// The statuses that count as a failed attempt (a skip is not a failure; `blocked` is).
pub fn failed(status: &str) -> bool {
    matches!(status, "error" | "blocked")
}

// ───────────────────────── paths ─────────────────────────

fn safe(id: &str) -> String {
    id.replace(['/', '.', '\\'], "_")
}

pub fn runs_dir(data: &Path) -> PathBuf {
    data.join("cron_runs")
}
pub fn run_log_path(data: &Path, id: &str) -> PathBuf {
    runs_dir(data).join(format!("{}.jsonl", safe(id)))
}
pub fn incidents_path(data: &Path) -> PathBuf {
    data.join("cron_incidents.json")
}
pub fn health_path(data: &Path) -> PathBuf {
    data.join("cron_health.json")
}
pub fn notepad_dir(data: &Path) -> PathBuf {
    data.join("cron_notepad")
}
pub fn notepad_path(data: &Path, id: &str) -> PathBuf {
    notepad_dir(data).join(format!("{}.md", safe(id)))
}

// ───────────────────────── runs ─────────────────────────

/// One finished attempt (also written by `cronjob::record`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Run {
    pub job_id: String,
    pub run_id: String,
    /// `at` mirrors `ended_at` for readers of the first-generation log format.
    pub at: i64,
    pub started_at: i64,
    pub ended_at: i64,
    #[serde(default)]
    pub duration_ms: u64,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// First-generation field name for `summary` (still written so old readers keep working).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
}

impl Run {
    /// A run that started at `started_at` and finished now.
    pub fn new(job_id: &str, started_at: i64, ended_at: i64, status: &str) -> Run {
        Run {
            job_id: job_id.to_string(),
            run_id: crate::util::new_id(),
            at: ended_at,
            started_at,
            ended_at,
            duration_ms: (ended_at - started_at).max(0) as u64 * 1000,
            status: status.to_string(),
            ..Default::default()
        }
    }
}

/// Latest `n` attempts of a job, newest first (raw records; old log lines still read).
pub fn runs(data: &Path, id: &str, n: usize) -> Vec<Value> {
    let text = std::fs::read_to_string(run_log_path(data, id)).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str(l).ok()).take(n).collect()
}

/// Every attempt of one run log as a [`Run`] (newest first); unknown fields are ignored.
pub fn history(data: &Path, id: &str, n: usize) -> Vec<Run> {
    runs(data, id, n)
        .into_iter()
        .map(|v| {
            let ended_at = v["ended_at"].as_i64().or_else(|| v["at"].as_i64()).unwrap_or(0);
            let summary = v["summary"].as_str().or_else(|| v["output"].as_str()).map(String::from);
            Run {
                job_id: v["job_id"].as_str().unwrap_or(id).to_string(),
                run_id: v["run_id"].as_str().unwrap_or("").to_string(),
                at: v["at"].as_i64().unwrap_or(ended_at),
                started_at: v["started_at"].as_i64().unwrap_or(0),
                ended_at,
                duration_ms: v["duration_ms"].as_u64().unwrap_or(0),
                status: v["status"].as_str().unwrap_or("unknown").to_string(),
                output: summary.clone(),
                summary,
                error: v["error"].as_str().map(String::from),
                delivery: v["delivery"].as_str().map(String::from),
            }
        })
        .collect()
}

/// Append one attempt, rotate the log, then update the streak/incident bookkeeping.
/// Returns the alert line when an incident opened with this attempt.
pub fn record_run(data: &Path, run: &Run) -> Option<String> {
    append_run(data, run);
    let now = run.ended_at;
    if failed(&run.status) {
        let err = run.error.clone().or_else(|| run.summary.clone()).unwrap_or_else(|| run.status.clone());
        let streak = bump_streak(data, &run.job_id, false, Some(&err), now);
        if streak >= INCIDENT_THRESHOLD {
            let (inc, new) = upsert(data, &run.job_id, None, &err, streak, now);
            return new.then_some(inc.alert).filter(|a| !a.trim().is_empty());
        }
        None
    } else {
        bump_streak(data, &run.job_id, true, None, now);
        let _ = resolve_for_job(data, &run.job_id, now);
        None
    }
}

fn append_run(data: &Path, run: &Run) {
    let p = run_log_path(data, &run.job_id);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p).unwrap_or_default().lines().map(String::from).collect();
    let mut line = serde_json::to_string(run).unwrap_or_default();
    line.truncate(line.len().min(8192));
    if serde_json::from_str::<Value>(&line).is_err() {
        line = json!({"at": run.ended_at, "status": run.status, "job_id": run.job_id}).to_string();
    }
    lines.push(line);
    let keep = if lines.iter().map(|l| l.len() + 1).sum::<usize>() > RUN_LOG_MAX_BYTES { RUN_LOG_KEEP / 4 } else { RUN_LOG_KEEP };
    let start = lines.len().saturating_sub(keep);
    let _ = crate::util::atomic_write(&p, (lines[start..].join("\n") + "\n").as_bytes());
}

// ───────────────────────── failure streaks ─────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Health {
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ok_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fail_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub fn load_health(data: &Path) -> HashMap<String, Health> {
    read_json(&health_path(data)).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
}

/// One job's failure streak (zeros when never seen).
pub fn health(data: &Path, id: &str) -> Health {
    load_health(data).remove(id).unwrap_or_default()
}

/// Update the streak; returns the new consecutive-failure count.
fn bump_streak(data: &Path, id: &str, ok: bool, error: Option<&str>, now: i64) -> u32 {
    let mut all = load_health(data);
    let h = all.entry(id.to_string()).or_default();
    h.last_status = Some(if ok { "ok".into() } else { "error".into() });
    if ok {
        h.consecutive_failures = 0;
        h.last_ok_at = Some(now);
    } else {
        h.consecutive_failures = h.consecutive_failures.saturating_add(1);
        h.last_fail_at = Some(now);
        h.last_error = error.map(|e| clip(e, MAX_ERROR_CHARS));
    }
    let streak = h.consecutive_failures;
    let _ = write_json(&health_path(data), &json!(all));
    streak
}

/// Drop a job's streak/health entry (job removed).
pub fn forget_health(data: &Path, id: &str) {
    let mut all = load_health(data);
    if all.remove(id).is_some() {
        let _ = write_json(&health_path(data), &json!(all));
    }
}

// ───────────────────────── incidents ─────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub job_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_name: Option<String>,
    /// Dedup key: the same job failing the same way is the same incident.
    pub signature: String,
    /// `detected` | `alerted` | `resolved` | `closed`.
    pub state: String,
    pub failure_type: String,
    /// When the failure signature was first seen (incident opened).
    pub opened_at: i64,
    pub last_seen_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alerted_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<i64>,
    /// Consecutive failures when the incident was (re)opened / last refreshed.
    #[serde(default)]
    pub retries: u32,
    pub error: String,
    /// The operator-facing alert text (delivered by the job's `failure_deliver`).
    #[serde(default)]
    pub alert: String,
}

impl Incident {
    pub fn open(&self) -> bool {
        matches!(self.state.as_str(), "detected" | "alerted")
    }
}

/// Whitespace-collapsed, lowercased error text with run-to-run durations masked.
pub fn normalize_error(error: &str) -> String {
    const UNITS: [&str; 17] = ["ms", "s", "sec", "secs", "second", "seconds", "m", "min", "mins", "minute", "minutes", "h", "hr", "hrs", "hour", "hours", "hrs"];
    let lower = error.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
            i += 1;
        }
        let num: String = chars[start..i].iter().collect();
        let wstart = i;
        while i < chars.len() && chars[i] == ' ' {
            i += 1;
        }
        let spaces: String = chars[wstart..i].iter().collect();
        let ustart = i;
        while i < chars.len() && chars[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit: String = chars[ustart..i].iter().collect();
        // `12s`, `3h`, `600 ms`, `12.5 seconds` → `#s`; other numbers (status codes) are kept.
        if UNITS.contains(&unit.as_str()) {
            out.push_str("#s");
        } else {
            out.push_str(&num);
            out.push_str(&spaces);
            out.push_str(&unit);
        }
    }
    out.trim().to_string()
}

fn signature(job_id: &str, error: &str) -> String {
    let norm: String = normalize_error(error).chars().take(MAX_SIGNATURE_CHARS).collect();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in job_id.bytes().chain([0u8]).chain(norm.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:012x}", h & 0xffff_ffff_ffff)
}

/// Keyword classification (Hermes `_classify_failure_type`), `unknown` by default.
pub fn classify(error: &str) -> &'static str {
    let t = normalize_error(error);
    if t.is_empty() {
        return "unknown";
    }
    let has = |needles: &[&str]| needles.iter().any(|n| t.contains(n));
    for (kind, needles) in [
        ("rate_limit", &["429", "rate limit", "usage limit", "quota"][..]),
        ("timeout", &["timeout", "timed out"][..]),
        ("auth", &["401", "unauthorized", "authentication", "auth"][..]),
        ("delivery", &["delivery", "deliver", "delivering"][..]),
        ("config", &["config", "configuration", "validation"][..]),
        ("script", &["script", "no_agent"][..]),
        ("agent", &["agent", "model", "provider", "inference"][..]),
    ] {
        if has(needles) {
            return kind;
        }
    }
    "unknown"
}

pub fn incident_id(job_id: &str, signature: &str) -> String {
    let head: String = job_id.chars().take(6).collect();
    format!("{head}_{signature}")
}

fn read_json(p: &Path) -> Option<Value> {
    std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str(&s).ok())
}

fn write_json(p: &Path, v: &Value) -> Result<(), String> {
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    crate::util::atomic_write(p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())
}

/// The incident ledger (`{ "incidents": [...] }`), oldest first; a corrupt file reads empty.
pub fn list(data: &Path, state: Option<&str>) -> Vec<Incident> {
    let mut v: Vec<Incident> = read_json(&incidents_path(data)).and_then(|v| serde_json::from_value(v.get("incidents").cloned().unwrap_or(json!([]))).ok()).unwrap_or_default();
    v.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at).then(b.id.cmp(&a.id)));
    if let Some(s) = state {
        v.retain(|i| i.state == s);
    }
    v
}

/// True when the ledger file exists but cannot be parsed (`ark schedule doctor`).
pub fn ledger_corrupt(data: &Path) -> bool {
    let p = incidents_path(data);
    p.exists() && read_json(&p).is_none()
}

pub fn open_incidents(data: &Path) -> Vec<Incident> {
    list(data, None).into_iter().filter(Incident::open).collect()
}

fn save(data: &Path, mut v: Vec<Incident>) -> Result<(), String> {
    // Newest activity first, but never rotate out an open incident.
    v.sort_by_key(|a| std::cmp::Reverse(a.last_seen_at));
    if v.len() > INCIDENT_KEEP {
        let mut kept: Vec<Incident> = Vec::with_capacity(INCIDENT_KEEP);
        for inc in v {
            if kept.len() < INCIDENT_KEEP {
                kept.push(inc);
            } else if inc.open() {
                // Replace the oldest closed entry so nothing open is forgotten.
                if let Some(i) = kept.iter().rposition(|k| !k.open()) {
                    kept[i] = inc;
                }
            }
        }
        v = kept;
    }
    write_json(&incidents_path(data), &json!({"version": 1, "incidents": v}))
}

/// Record (or refresh) the incident for `job_id` + `error`; `(incident, is_new)`.
/// An open incident keeps its state and only refreshes `last_seen_at`/`retries`; a `resolved`
/// one re-opens as `detected` (the job broke the same way again); a `closed` one stays silent
/// until the error text changes and mints a new signature.
pub fn upsert(data: &Path, job_id: &str, job_name: Option<&str>, error: &str, retries: u32, now: i64) -> (Incident, bool) {
    let sig = signature(job_id, error);
    let id = incident_id(job_id, &sig);
    let error = clip(error, MAX_ERROR_CHARS);
    let mut all = list(data, None);
    if let Some(inc) = all.iter_mut().find(|i| i.id == id) {
        inc.last_seen_at = now;
        inc.error = error;
        inc.retries = retries.max(inc.retries);
        if let Some(n) = job_name {
            inc.job_name = Some(n.to_string());
        }
        let reopened = inc.state == "resolved";
        if reopened {
            inc.state = "detected".into();
            inc.closed_at = None;
            inc.alerted_at = None;
        }
        if inc.state != "closed" {
            inc.alert = alert_text(inc, true);
        }
        let out = inc.clone();
        let _ = save(data, all);
        return (out, reopened);
    }
    let mut inc = Incident {
        id,
        job_id: job_id.to_string(),
        job_name: job_name.map(String::from),
        signature: sig,
        state: "detected".into(),
        failure_type: classify(&error).to_string(),
        opened_at: now,
        last_seen_at: now,
        closed_at: None,
        alerted_at: None,
        acked_at: None,
        retries,
        error,
        alert: String::new(),
    };
    inc.alert = alert_text(&inc, true);
    let out = inc.clone();
    all.push(inc);
    let _ = save(data, all);
    (out, true)
}

fn alert_text(i: &Incident, active: bool) -> String {
    let name = i.job_name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| i.job_id.clone());
    let head = if active {
        format!("⚠ Cron job '{name}' failed {}× in a row ({})", i.retries.max(1), i.failure_type)
    } else {
        format!("Cron incident for job '{name}' is closed ({})", i.failure_type)
    };
    format!("{head}: {}", clip(&i.error, 300))
}

/// Mark a failure ping as delivered (Hermes `set_incident_state("alerted")`).
pub fn mark_alerted(data: &Path, id: &str, now: i64) -> bool {
    let mut all = list(data, None);
    let Some(inc) = all.iter_mut().find(|i| i.id == id) else { return false };
    if matches!(inc.state.as_str(), "closed" | "alerted") {
        return false;
    }
    inc.state = "alerted".into();
    inc.alerted_at = Some(now);
    let _ = save(data, all);
    true
}

/// Close an incident for good (operator ack); `false` when missing or already closed.
pub fn ack(data: &Path, id: &str, now: i64) -> bool {
    let mut all = list(data, None);
    let Some(inc) = all.iter_mut().find(|i| i.id == id) else { return false };
    if inc.state == "closed" {
        return false;
    }
    inc.state = "closed".into();
    inc.closed_at = Some(now);
    inc.acked_at = Some(now);
    let _ = save(data, all);
    true
}

/// A successful run resolves every open incident of the job; returns how many changed.
pub fn resolve_for_job(data: &Path, job_id: &str, now: i64) -> usize {
    let mut all = list(data, None);
    let mut n = 0;
    for inc in all.iter_mut().filter(|i| i.job_id == job_id && i.open()) {
        inc.state = "resolved".into();
        inc.closed_at = Some(now);
        n += 1;
    }
    if n > 0 {
        let _ = save(data, all);
    }
    n
}

// ───────────────────────── notepad ─────────────────────────

pub fn note(data: &Path, id: &str) -> Option<String> {
    std::fs::read_to_string(notepad_path(data, id)).ok().map(|s| s.trim_end().to_string()).filter(|s| !s.trim().is_empty())
}

/// Replace the job's note. `None`/empty clears it; oversized text is refused (the note rides
/// every prompt, so an accidental paste of a log file must not slip in).
pub fn set_note(data: &Path, id: &str, text: Option<&str>) -> Result<bool, String> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else { return clear_note(data, id) };
    if text.len() > NOTEPAD_MAX_BYTES {
        return Err(format!("notepad is too large ({} bytes, max {NOTEPAD_MAX_BYTES})", text.len()));
    }
    let p = notepad_path(data, id);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    crate::util::atomic_write(&p, format!("{}\n", text.trim_end()).as_bytes()).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Append one line to the note (a running log across runs).
pub fn append_note(data: &Path, id: &str, line: &str) -> Result<(), String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }
    let mut text = note(data, id).unwrap_or_default();
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(line);
    set_note(data, id, Some(&text)).map(|_| ())
}

/// `true` when a note existed and was removed.
pub fn clear_note(data: &Path, id: &str) -> Result<bool, String> {
    let p = notepad_path(data, id);
    if !p.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&p).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Prompt section for a job's note; empty when there is none (byte-identical prompts otherwise).
pub fn render_section(data: &Path, id: &str) -> String {
    let Some(text) = note(data, id) else { return String::new() };
    format!("## Job notepad (persistent across runs)\nDurable scratchpad this job shares between runs. Update it with `ark schedule notepad {} <text>`.\n\n{}\n\n", id, clip(&text, NOTEPAD_PROMPT_CAP))
}

// ───────────────────────── shared ─────────────────────────

fn clip(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(max).collect::<String>())
    }
}

// ───────────────────────── doctor ─────────────────────────

/// One job's health findings: `(job id, name, issues)`.
pub type Finding = (String, String, Vec<String>);

/// Read-only health checks behind `ark schedule doctor` (Hermes `cron_doctor`). Every issue is
/// phrased as something the operator can act on.
pub fn doctor(data: &Path, jobs: &[crate::automation::Job], now: i64, offset: i32, daemon_running: bool) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let health = load_health(data);
    let open = open_incidents(data);
    for j in jobs {
        let mut issues: Vec<String> = Vec::new();
        let name = j.ext.name.clone().unwrap_or_else(|| j.prompt.chars().take(40).collect());
        // A schedule the ticker cannot compute never fires.
        if crate::cron::Cron::parse(&j.cron).is_err() {
            issues.push(format!("cron expression `{}` does not parse — fix it with `ark schedule edit {} cron=\"0 9 * * *\"`", j.cron, j.id));
        }
        if j.enabled && j.next_run < now - OVERDUE_GRACE_SECS {
            let late = (now - j.next_run) / 60;
            issues.push(if daemon_running {
                format!("next run is {late}m overdue although arkd is running — check `ark daemon logs` (the tick may be failing)")
            } else {
                format!("next run is {late}m overdue and arkd is not running — start it with `ark daemon start`, or run once with `ark schedule tick`")
            });
        }
        if !std::path::Path::new(&j.workspace).is_dir() {
            issues.push(format!("workspace `{}` is missing — `ark schedule edit {} workdir=<path>`", j.workspace, j.id));
        }
        if j.ext.no_agent && j.ext.script.is_none() {
            issues.push("no_agent job without a script: it can never produce output — add script=<name> or disable it".into());
        }
        if let Some(s) = &j.ext.script {
            if let Err(e) = crate::cronjob::script::resolve(data, s) {
                issues.push(format!("script `{s}` is unusable ({e}) — restore it under {} or edit the job", crate::cronjob::script::scripts_dir(data).display()));
            }
        }
        if let Some(d) = &j.ext.deliver {
            if let Err(e) = crate::cronjob::validate_deliver(d) {
                issues.push(format!("deliver `{d}` is invalid ({e}) — `ark schedule edit {} deliver=origin`", j.id));
            }
        }
        if let Some(h) = health.get(&j.id) {
            if h.consecutive_failures > 0 {
                let err = h.last_error.clone().unwrap_or_default();
                issues.push(format!("{} consecutive failed run(s): {} — `ark schedule runs {}` shows the attempts", h.consecutive_failures, clip(&err, 160), j.id));
            }
        }
        for inc in open.iter().filter(|i| i.job_id == j.id) {
            issues.push(format!("open incident {} ({}, retries={}, last seen {}): {} — `ark schedule incidents ack {}` once handled", inc.id, inc.failure_type, inc.retries, crate::util::fmt_time(inc.last_seen_at, offset), clip(&inc.error, 160), inc.id));
        }
        if let Some(n) = j.ext.name.as_deref() {
            if n.trim().is_empty() {
                issues.push("job name is blank — rename it with `ark schedule edit <id> name=<text>`".into());
            }
        }
        if !issues.is_empty() {
            out.push((j.id.clone(), name, issues));
        }
    }
    out
}

/// Non-job problems (corrupt stores) as `(area, issue)`.
pub fn doctor_stores(data: &Path) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = Vec::new();
    if crate::automation::read_list::<crate::automation::Job>(&crate::automation::jobs_path(data)).is_err() {
        v.push(("schedules.json", format!("cannot be read as JSON — restore it from {} or `ark schedule doctor` after fixing the file by hand", data.display())));
    }
    if ledger_corrupt(data) {
        v.push(("cron_incidents.json", "is not valid JSON — move it aside; incidents will be rebuilt from the run logs".into()));
    }
    if read_json(&health_path(data)).is_none() && health_path(data).exists() {
        v.push(("cron_health.json", "is not valid JSON — delete it; failure streaks restart".into()));
    }
    let bad = runs_dir(data)
        .read_dir()
        .map(|r| r.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "jsonl")).filter(|e| std::fs::read_to_string(e.path()).map(|s| s.lines().any(|l| serde_json::from_str::<Value>(l).is_err())).unwrap_or(false)).count())
        .unwrap_or(0);
    if bad > 0 {
        v.push(("cron_runs/", format!("{bad} run log(s) contain unreadable lines — they are skipped when reading; delete the bad files to silence this")));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-incidents-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn run(data: &Path, id: &str, status: &str, at: i64) -> Option<String> {
        let mut r = Run::new(id, at - 2, at, status);
        if failed(status) {
            r.error = Some("agent: provider said no".into());
            r.summary = Some("run failed".into());
        } else {
            r.summary = Some("all good".into());
        }
        record_run(data, &r)
    }

    #[test]
    fn runs_record_start_end_status_error_and_rotate() {
        let d = tmp();
        assert!(runs(&d, "j1", 5).is_empty());
        run(&d, "j1", "ok", 1_000);
        run(&d, "j1", "error", 1_010);
        let h = history(&d, "j1", 5);
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].status.as_str(), h[1].status.as_str()), ("error", "ok"), "newest first");
        assert_eq!((h[0].started_at, h[0].ended_at, h[0].duration_ms), (1_008, 1_010, 2_000));
        assert!(h[0].error.as_deref().unwrap().contains("provider said no"));
        assert_eq!(h[1].summary.as_deref(), Some("all good"));
        assert_eq!(h[0].job_id, "j1");
        assert!(!h[0].run_id.is_empty());
        // The first-generation record shape (at/status/delivery/output) still reads.
        std::fs::write(run_log_path(&d, "old"), json!({"at": 5, "status": "ok", "delivery": null, "output": "hi"}).to_string() + "\n").unwrap();
        let old = history(&d, "old", 3);
        assert_eq!((old[0].status.as_str(), old[0].summary.as_deref()), ("ok", Some("hi")));
        // Rotation: only the newest RUN_LOG_KEEP attempts stay.
        for i in 0..(RUN_LOG_KEEP + 7) {
            run(&d, "j2", "ok", 2_000 + i as i64);
        }
        assert_eq!(runs(&d, "j2", RUN_LOG_KEEP * 2).len(), RUN_LOG_KEEP);
        assert_eq!(history(&d, "j2", 1)[0].ended_at, 2_000 + (RUN_LOG_KEEP + 6) as i64);
        // Two jobs never share a log; ids are sanitized into file names.
        assert_eq!(runs(&d, "j1", 50).len(), 2);
        run(&d, "../evil", "ok", 9_000);
        assert!(notepad_path(&d, "../evil").starts_with(notepad_dir(&d)));
    }

    #[test]
    fn consecutive_failures_open_one_incident_and_recovery_resolves_it() {
        let d = tmp();
        assert_eq!(run(&d, "j1", "error", 100), None, "one failure is not an incident");
        assert_eq!(run(&d, "j1", "error", 110), None);
        assert!(open_incidents(&d).is_empty());
        let alert = run(&d, "j1", "error", 120).expect("third consecutive failure opens one");
        assert!(alert.contains("failed 3× in a row"), "{alert}");
        let open = open_incidents(&d);
        assert_eq!(open.len(), 1);
        let inc = &open[0];
        assert_eq!((inc.state.as_str(), inc.retries, inc.opened_at, inc.failure_type.as_str()), ("detected", 3, 120, "agent"));
        assert_eq!(inc.job_id, "j1");
        // The same error keeps ONE incident and only bumps the retry count / last_seen.
        let alert = run(&d, "j1", "error", 130);
        assert_eq!(alert, None, "no duplicate alert for the same signature");
        let open = open_incidents(&d);
        assert_eq!((open.len(), open[0].retries, open[0].last_seen_at, open[0].opened_at), (1, 4, 130, 120));
        // A success resolves it and resets the streak.
        run(&d, "j1", "ok", 140);
        let all = list(&d, None);
        assert_eq!((all[0].state.as_str(), all[0].closed_at), ("resolved", Some(140)));
        assert!(open_incidents(&d).is_empty());
        assert_eq!(health(&d, "j1").consecutive_failures, 0);
        // Breaking the same way again re-opens that incident (and alerts again).
        run(&d, "j1", "error", 150);
        run(&d, "j1", "error", 160);
        assert!(run(&d, "j1", "error", 170).is_some());
        let reopened = list(&d, None);
        assert_eq!((reopened.len(), reopened[0].state.as_str(), reopened[0].opened_at), (1, "detected", 120));
    }

    #[test]
    fn changed_errors_mint_new_incidents_and_ack_closes_silently() {
        let d = tmp();
        for i in 0..3 {
            record_run(&d, &{ let mut r = Run::new("j9", 0, 10 + i, "error"); r.error = Some("auth 401 unauthorized".into()); r });
        }
        let first = open_incidents(&d);
        assert_eq!((first.len(), first[0].failure_type.as_str()), (1, "auth"));
        // A different failure is a different incident.
        for i in 0..3 {
            record_run(&d, &{ let mut r = Run::new("j9", 0, 100 + i, "error"); r.error = Some("script boom.sh exited with code 2".into()); r });
        }
        assert_eq!(open_incidents(&d).len(), 2);
        assert_eq!(classify("script boom.sh exited with code 2"), "script");
        // Ack closes; the same signature afterwards stays silent (no third incident, no alert).
        let id = open_incidents(&d).iter().find(|i| i.failure_type == "auth").unwrap().id.clone();
        assert!(ack(&d, &id, 500));
        assert!(!ack(&d, &id, 501), "already closed");
        for i in 0..3 {
            record_run(&d, &{ let mut r = Run::new("j9", 0, 600 + i, "error"); r.error = Some("auth 401 unauthorized".into()); r });
        }
        assert_eq!(list(&d, None).len(), 2, "a closed signature does not mint another incident");
        assert_eq!(open_incidents(&d).len(), 1, "only the script incident remains open");
        assert!(!mark_alerted(&d, &id, 700), "closed stays closed");
        let open_id = open_incidents(&d)[0].id.clone();
        assert!(mark_alerted(&d, &open_id, 700));
        assert_eq!(list(&d, Some("alerted"))[0].alerted_at, Some(700));
        assert_eq!(list(&d, Some("closed"))[0].state, "closed");
    }

    #[test]
    fn incident_ledger_is_capped_and_keeps_every_open_one() {
        let d = tmp();
        for i in 0..(INCIDENT_KEEP + 12) {
            let mut r = Run::new(&format!("job{i}"), 0, 1_000 + i as i64, "error");
            r.error = Some(format!("boom {i}"));
            // Three failures each so an incident opens.
            for k in 0..3 {
                r.ended_at = 1_000 + i as i64 * 10 + k;
                record_run(&d, &r);
            }
        }
        let all = list(&d, None);
        assert!(all.len() <= INCIDENT_KEEP, "{} > {INCIDENT_KEEP}", all.len());
        assert!(all.iter().any(|i| i.job_id == format!("job{}", INCIDENT_KEEP + 11)), "newest kept");
        assert!(!all.iter().any(|i| i.job_id == "job0"), "oldest rotated out");
        // Open incidents are never rotated out, even when they are the oldest.
        let newest = format!("job{}", INCIDENT_KEEP + 11);
        for i in 0..5 {
            let mut r = Run::new(&newest, 0, 9_000 + i, "error");
            r.error = Some("same breaker".into());
            record_run(&d, &r);
        }
        let open_before = open_incidents(&d).len();
        for i in 0..(INCIDENT_KEEP + 5) {
            let mut r = Run::new(&format!("late{i}"), 0, 10_000 + i as i64, "error");
            r.error = Some(format!("late boom {i}"));
            record_run(&d, &r);
        }
        assert!(list(&d, None).len() <= INCIDENT_KEEP);
        assert!(open_incidents(&d).len() >= open_before.max(1));
    }

    #[test]
    fn notepad_round_trips_injects_and_caps() {
        let d = tmp();
        assert!(note(&d, "j1").is_none());
        assert_eq!(render_section(&d, "j1"), "", "no note = byte-identical prompt");
        assert!(set_note(&d, "j1", Some("cursor: PR #41\nwatermark: 2026-01-02")).unwrap());
        assert_eq!(note(&d, "j1").unwrap(), "cursor: PR #41\nwatermark: 2026-01-02");
        let s = render_section(&d, "j1");
        assert!(s.contains("## Job notepad") && s.contains("PR #41") && s.contains("ark schedule notepad j1"));
        append_note(&d, "j1", "last: 3 open issues").unwrap();
        assert!(note(&d, "j1").unwrap().ends_with("last: 3 open issues"));
        assert!(set_note(&d, "j1", Some(&"x".repeat(NOTEPAD_MAX_BYTES + 1))).unwrap_err().contains("too large"));
        assert!(note(&d, "j1").unwrap().contains("PR #41"), "a refused write leaves the note untouched");
        // The prompt section is clipped, the stored note is not.
        set_note(&d, "j2", Some(&"y".repeat(NOTEPAD_PROMPT_CAP + 500))).unwrap();
        assert!(render_section(&d, "j2").chars().count() < NOTEPAD_PROMPT_CAP + 300);
        assert_eq!(note(&d, "j2").unwrap().len(), NOTEPAD_PROMPT_CAP + 500);
        assert!(clear_note(&d, "j1").unwrap());
        assert!(!clear_note(&d, "j1").unwrap());
        assert!(note(&d, "j1").is_none());
        // Setting an empty note clears it.
        set_note(&d, "j3", Some("x")).unwrap();
        set_note(&d, "j3", Some("   ")).unwrap();
        assert!(note(&d, "j3").is_none());
    }

    #[test]
    fn error_signatures_ignore_measurements_but_not_status_codes() {
        assert_eq!(normalize_error("  Idle   for 603s "), "idle for #s");
        assert_eq!(normalize_error("retry in 12.5 seconds"), "retry in #s");
        assert_eq!(normalize_error("HTTP 429 rate limit"), "http 429 rate limit");
        assert_ne!(signature("j1", "idle for 603s"), signature("j2", "idle for 603s"), "job id is part of the signature");
        assert_eq!(signature("j1", "idle for 603s"), signature("j1", "idle for 12s"));
        assert_ne!(signature("j1", "boom 500"), signature("j1", "boom 429"));
        assert_eq!(classify("429 Too Many Requests"), "rate_limit");
        assert_eq!(classify("request timed out"), "timeout");
        assert_eq!(classify("delivery to telegram failed"), "delivery");
        assert_eq!(classify("config validation error"), "config");
        assert_eq!(classify("no_agent job has no script"), "script");
        assert_eq!(classify(""), "unknown");
        assert_eq!(classify("something else entirely"), "unknown");
        assert!(incident_id("abcdefgh", "123456789012").starts_with("abcdef_"));
    }

    #[test]
    fn doctor_flags_broken_jobs_and_corrupt_stores() {
        let d = tmp();
        let mk = |id: &str, cron: &str, next: i64, script: Option<&str>| crate::automation::Job {
            id: id.into(),
            cron: cron.into(),
            prompt: "p".into(),
            workspace: d.to_string_lossy().into(),
            model: None,
            session: None,
            enabled: true,
            next_run: next,
            last_run: None,
            last_session: None,
            last_result: None,
            budget: Default::default(),
            ext: crate::cronjob::JobExt { script: script.map(String::from), no_agent: script.is_some(), deliver: Some("local".into()), ..Default::default() },
        };
        let now = 1_000_000;
        let jobs = vec![mk("a", "0 9 * * *", now + 60, None), mk("b", "not a cron", now - 3600, Some("missing.sh")), mk("c", "@hourly", now - 3600, None)];
        let mut r = Run::new("c", 0, now - 3500, "error");
        r.error = Some("provider down".into());
        for _ in 0..3 {
            record_run(&d, &r);
        }
        let out = doctor(&d, &jobs, now, 0, false);
        let issues = |id: &str| out.iter().find(|f| f.0 == id).map(|f| f.2.join("\n")).unwrap_or_default();
        assert!(issues("a").is_empty(), "a healthy job has no findings");
        let b = issues("b");
        assert!(b.contains("does not parse") && b.contains("is unusable") && b.contains("is not running"), "{b}");
        let c = issues("c");
        assert!(c.contains("overdue") && c.contains("ark schedule tick") && c.contains("consecutive failed") && c.contains("open incident"), "{c}");
        assert!(doctor(&d, &jobs[2..], now, 0, true)[0].2[0].contains("arkd is running"), "daemon running changes the advice");
        // Corrupt ledgers are reported, not fatal.
        std::fs::write(incidents_path(&d), "{not json").unwrap();
        std::fs::write(health_path(&d), "[]oops").unwrap();
        std::fs::create_dir_all(runs_dir(&d)).unwrap();
        std::fs::write(run_log_path(&d, "x"), "{bad\n").unwrap();
        let stores = doctor_stores(&d);
        assert!(stores.iter().any(|(a, _)| *a == "cron_incidents.json"));
        assert!(stores.iter().any(|(a, _)| *a == "cron_health.json"));
        assert!(stores.iter().any(|(a, _)| *a == "cron_runs/"));
        assert!(list(&d, None).is_empty(), "a corrupt ledger reads empty instead of panicking");
    }
}
