//! Resource caps (section C8): spend, process count and disk per agent, plus hourly and
//! global spend and total disk. `[limits]` is off by default — every cap is `0 = off` — so an
//! unconfigured ark behaves exactly as before.
//!
//! Design answers (audit §0):
//!
//! * ① *How many extra stops for an unattended long task?* **None, normally.** There is no
//!   approval prompt anywhere in this module: the check is passive, and a breach pauses only
//!   the session being checked (`<home>/limits/paused/<session>.json`) — for a shared hourly
//!   or global cap that is whichever session is checked while the cap is exceeded, still never
//!   the fleet. Other agents, cron jobs and the daemon keep running. Warnings are recorded in
//!   the status file, not asked about.
//! * ② *Isolate/undo instead of asking?* The cap is the *isolate* answer: instead of asking a
//!   human "this agent is spending fast, allow it?", the runtime gives the agent a scope it
//!   cannot leave (its budget), writes the reason to disk, and resumes with
//!   [`resumed`] once the human (or the owner's policy) grants more. Nothing here is
//!   destructive, so nothing needs consent.
//!
//! Where the numbers come from (single source of truth, no second bookkeeper):
//! * spend — the session event log (`Message.usage`, priced with `[prices]`/the model table,
//!   plus `AuxUsage`), the same numbers the turn ledger charges;
//! * processes — the reaper registry (`crate::reaper::live_count`), so a process that ended
//!   does not count against a cap;
//! * disk — the session's own data dir and its sandbox scratch dirs (`<home>/sandboxes/*`),
//!   and `<home>` as a whole for the global cap.

use crate::config::LimitsConfig;
use crate::event::EventKind;
use crate::kernel::Runtime;
use ark_core::Usage;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cached reads are ~10x cheaper than fresh input on every major provider (same weight the
/// turn ledger uses; kept in sync by hand because `ledger::CACHE_WEIGHT` is private).
const CACHE_WEIGHT: f64 = 0.1;

/// What one check decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Near a cap (`warn_at`): record it, keep working.
    Warn(String),
    /// At/over a cap (or a pause is already in force): this session stops until [`resumed`].
    Pause(String),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Warn(_) => "warn",
            Verdict::Pause(_) => "pause",
        }
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Ok => None,
            Verdict::Warn(r) | Verdict::Pause(r) => Some(r),
        }
    }
}

/// The numbers a check measured (0 = not measured, because the cap is off).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Numbers {
    pub session_usd: f64,
    pub hour_usd: f64,
    pub global_usd: f64,
    pub processes: usize,
    pub disk_mb: u64,
    pub disk_mb_total: u64,
}

pub fn limits_dir(home: &Path) -> PathBuf {
    home.join("limits")
}

pub fn status_path(home: &Path) -> PathBuf {
    limits_dir(home).join("status.json")
}

/// `<home>/limits/paused/<session>.json`
pub fn pause_marker(home: &Path, session: &str) -> PathBuf {
    limits_dir(home).join("paused").join(format!("{}.json", safe_name(session)))
}

fn safe_name(session: &str) -> String {
    let s: String = session.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(64).collect();
    if s.is_empty() {
        "unnamed".into()
    } else {
        s
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn usage_cost(usd_per_mtok_in: f64, usd_per_mtok_out: f64, cache_read: f64, cache_write: f64, u: &Usage) -> f64 {
    let cr = if cache_read > 0.0 { cache_read } else { usd_per_mtok_in * CACHE_WEIGHT };
    let cw = if cache_write > 0.0 { cache_write } else { usd_per_mtok_in };
    u.input_tokens as f64 * usd_per_mtok_in / 1e6 + u.cache_write_tokens as f64 * cw / 1e6 + u.output_tokens as f64 * usd_per_mtok_out / 1e6 + u.cache_read_tokens as f64 * cr / 1e6
}

/// USD of one event, priced with `[prices]` / the built-in table. `None` when the event
/// carries no usage at all (nothing to count).
pub(crate) fn event_cost(cfg: &crate::config::Config, session_model: &str, kind: &EventKind) -> Option<f64> {
    let (usage, model) = match kind {
        EventKind::Message { usage: Some(u), model, .. } => (u, model.as_deref().unwrap_or(session_model)),
        EventKind::AuxUsage { usage, model, .. } => (usage, model.as_str()),
        _ => return None,
    };
    let price = cfg.price(model).or_else(|| cfg.price(session_model))?;
    Some(usage_cost(price.input, price.output, price.cache_read, price.cache_write, usage))
}

fn events(rt: &Runtime, session: &str) -> Vec<crate::event::Event> {
    rt.store.read(session).unwrap_or_default()
}

/// The session's header model (the price fallback for events that do not name one).
pub(crate) fn session_model(evs: &[crate::event::Event]) -> String {
    evs.iter()
        .find_map(|e| match &e.kind {
            EventKind::Header { model, .. } => Some(model.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Spend of one session (all turns), USD.
pub fn session_spend(rt: &Runtime, session: &str) -> f64 {
    let evs = events(rt, session);
    let model = session_model(&evs);
    evs.iter().filter_map(|e| event_cost(&rt.cfg, &model, &e.kind)).sum()
}

/// Spend of every session in the last `since_ms`, USD.
pub fn spend_since(rt: &Runtime, since_ms: u64) -> f64 {
    let mut total = 0.0;
    for info in rt.store.list() {
        let evs = events(rt, &info.id);
        let model = if info.model.is_empty() { session_model(&evs) } else { info.model.clone() };
        total += evs.iter().filter(|e| e.ts >= since_ms).filter_map(|e| event_cost(&rt.cfg, &model, &e.kind)).sum::<f64>();
    }
    total
}

/// Disk held by one session: its data dir (events + artifacts) and any sandbox scratch dir
/// whose scope name carries the session tag (`host-<session>` / `s-<session>`).
pub fn session_disk_mb(home: &Path, session: &str) -> u64 {
    let tag = safe_name(session);
    let mut bytes = dir_bytes(&rt_store_dir(home, session), 50_000);
    if let Ok(rd) = std::fs::read_dir(home.join("sandboxes")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains(&tag) {
                bytes += dir_bytes(&e.path(), 50_000);
            }
        }
    }
    bytes / (1024 * 1024)
}

fn rt_store_dir(home: &Path, session: &str) -> PathBuf {
    home.join("sessions").join(safe_name(session))
}

/// Bytes under `p` (both are counted only up to `budget` entries: a huge tree must not make a
/// periodic check expensive).
fn dir_bytes(p: &Path, budget: usize) -> u64 {
    let mut left = budget;
    walk_bytes(p, &mut left)
}

fn walk_bytes(p: &Path, left: &mut usize) -> u64 {
    if *left == 0 {
        return 0;
    }
    *left -= 1;
    let Ok(md) = std::fs::symlink_metadata(p) else { return 0 };
    if !md.is_dir() {
        return md.len();
    }
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten().map(|e| walk_bytes(&e.path(), left)).sum()
}

/// Disk of the whole ark data dir, MB.
pub fn total_disk_mb(home: &Path) -> u64 {
    dir_bytes(home, 200_000) / (1024 * 1024)
}

fn ratio(used: f64, cap: f64) -> Option<f64> {
    (cap > 0.0).then_some(used / cap)
}

/// Warn at `warn_at`, pause at 100 % of the tightest cap. Reason strings name the cap so the
/// human sees exactly which limit was hit.
fn evaluate(cfg: &LimitsConfig, n: &Numbers) -> Verdict {
    let mut worst: Option<(f64, String)> = None;
    let mut note = |r: Option<f64>, text: String| {
        if let Some(r) = r {
            if worst.as_ref().is_none_or(|(w, _)| r > *w) {
                worst = Some((r, text));
            }
        }
    };
    note(ratio(n.session_usd, cfg.per_agent_spend_usd), format!("session spend ${:.4} of ${:.2} (limits.per_agent_spend_usd)", n.session_usd, cfg.per_agent_spend_usd));
    note(ratio(n.hour_usd, cfg.hourly_spend_usd), format!("hourly spend ${:.4} of ${:.2} (limits.hourly_spend_usd)", n.hour_usd, cfg.hourly_spend_usd));
    note(ratio(n.global_usd, cfg.global_spend_usd), format!("total spend ${:.4} of ${:.2} (limits.global_spend_usd)", n.global_usd, cfg.global_spend_usd));
    note(ratio(n.processes as f64, cfg.max_processes_per_agent as f64), format!("{} live processes of {} (limits.max_processes_per_agent)", n.processes, cfg.max_processes_per_agent));
    note(ratio(n.disk_mb as f64, cfg.disk_mb_per_agent as f64), format!("{} MB of {} MB (limits.disk_mb_per_agent)", n.disk_mb, cfg.disk_mb_per_agent));
    note(ratio(n.disk_mb_total as f64, cfg.disk_mb_total as f64), format!("{} MB of {} MB (limits.disk_mb_total)", n.disk_mb_total, cfg.disk_mb_total));
    match worst {
        None => Verdict::Ok,
        Some((r, text)) if r >= 1.0 => Verdict::Pause(format!("resource cap reached: {text}")),
        Some((r, text)) if r >= cfg.warn_at => Verdict::Warn(format!("approaching a resource cap ({:.0} %): {text}", r * 100.0)),
        Some(_) => Verdict::Ok,
    }
}

/// The reason a session is paused, if it is.
pub fn paused(home: &Path, session: &str) -> Option<String> {
    let text = std::fs::read_to_string(pause_marker(home, session)).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some(v.get("reason").and_then(Value::as_str).unwrap_or("paused by a resource cap").to_string())
}

/// Every paused session (`session`, `reason`, `ts_ms`).
pub fn paused_sessions(home: &Path) -> Vec<(String, String, u64)> {
    let mut out: Vec<(String, String, u64)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(limits_dir(home).join("paused")) else { return out };
    for e in rd.flatten() {
        let Some(v) = std::fs::read_to_string(e.path()).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else { continue };
        let g = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        out.push((g("session"), g("reason"), v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0)));
    }
    out.sort();
    out
}

/// Clear a pause (owner granted more budget, `/limits resume`, or the CLI). Returns whether a
/// marker was removed.
pub fn resumed(home: &Path, session: &str) -> bool {
    let p = pause_marker(home, session);
    let existed = p.exists();
    let _ = std::fs::remove_file(p);
    existed
}

fn write_pause(home: &Path, session: &str, reason: &str) {
    let p = pause_marker(home, session);
    if let Some(dir) = p.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let body = json!({"session": session, "reason": reason, "ts_ms": now_ms()});
    let _ = std::fs::write(p, body.to_string());
}

fn write_status(home: &Path, session: &str, cfg: &LimitsConfig, n: &Numbers, verdict: &Verdict) {
    let dir = limits_dir(home);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let body = json!({
        "ts_ms": now_ms(),
        "session": session,
        "verdict": verdict.label(),
        "reason": verdict.reason(),
        "numbers": {
            "session_usd": n.session_usd,
            "hour_usd": n.hour_usd,
            "global_usd": n.global_usd,
            "processes": n.processes,
            "disk_mb": n.disk_mb,
            "disk_mb_total": n.disk_mb_total,
        },
        "caps": caps_json(cfg),
    });
    let _ = std::fs::write(status_path(home), body.to_string());
}

fn caps_json(cfg: &LimitsConfig) -> Value {
    json!({
        "per_agent_spend_usd": cfg.per_agent_spend_usd,
        "hourly_spend_usd": cfg.hourly_spend_usd,
        "global_spend_usd": cfg.global_spend_usd,
        "max_processes_per_agent": cfg.max_processes_per_agent,
        "disk_mb_per_agent": cfg.disk_mb_per_agent,
        "disk_mb_total": cfg.disk_mb_total,
        "warn_at": cfg.warn_at,
        "check_interval_secs": cfg.check_interval_secs,
        "reap_interval_secs": cfg.reap_interval_secs,
    })
}

/// Measure what is capped and decide. Only configured caps are measured, so an ark without
/// `[limits]` does no I/O at all. Writes `<home>/limits/status.json` on every measurement and
/// the pause marker on a `Pause`; a session that is already paused is not re-measured (the
/// status file keeps the numbers that caused the pause, and the verdict stays `Pause` until
/// [`resumed`]).
pub fn check(rt: &Runtime, session: &str) -> Verdict {
    let home = rt.paths.data.clone();
    let cfg = rt.cfg.limits.clone();
    // A pause stays in force until somebody resumes it; re-measuring must not silently undo it.
    // (No measurement while paused: `status.json` keeps the numbers that caused the pause.)
    // Only a *resource* pause blocks: a provider pause (transient / billing) is what the
    // daemon's retry is trying to end, so it must reach the model (gen1-305).
    if let Some(p) = pause_info(&home, session).filter(|p| PauseKind::from_label(&p.kind).is_none()) {
        return Verdict::Pause(p.reason);
    }
    if !cfg.enabled() {
        return Verdict::Ok;
    }
    let mut n = Numbers::default();
    if cfg.per_agent_spend_usd > 0.0 {
        n.session_usd = session_spend(rt, session);
    }
    if cfg.hourly_spend_usd > 0.0 {
        n.hour_usd = spend_since(rt, now_ms().saturating_sub(3_600_000));
    }
    if cfg.global_spend_usd > 0.0 {
        n.global_usd = spend_since(rt, 0);
    }
    if cfg.max_processes_per_agent > 0 {
        n.processes = crate::reaper::live_count(&home, session);
    }
    if cfg.disk_mb_per_agent > 0 {
        n.disk_mb = session_disk_mb(&home, session);
    }
    if cfg.disk_mb_total > 0 {
        n.disk_mb_total = total_disk_mb(&home);
    }
    let verdict = evaluate(&cfg, &n);
    write_status(&home, session, &cfg, &n, &verdict);
    if let Verdict::Pause(reason) = &verdict {
        write_pause(&home, session, reason);
    }
    verdict
}

/// Status for `ark doctor`, `/limits` and the Web UI: caps, who is paused, and the last
/// written numbers. Read-only.
pub fn status_json(rt: &Runtime) -> Value {
    let home = &rt.paths.data;
    let last: Value = std::fs::read_to_string(status_path(home)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let paused: Vec<Value> = paused_sessions(home).into_iter().map(|(s, r, ts)| json!({"session": s, "reason": r, "ts_ms": ts})).collect();
    json!({
        "enabled": rt.cfg.limits.enabled(),
        "caps": caps_json(&rt.cfg.limits),
        "paused": paused,
        "last": last,
        "limits_dir": limits_dir(home).display().to_string(),
    })
}

// ───────────────── provider pauses (C1/C2): transient failure, billing ─────────────────
//
// A run that loses the network for a minute, or whose provider account runs out of credit,
// must not die with its 8 hours of work: it *pauses* — the event log already holds the state —
// and a later run continues from the same turn. This is the §0 answer in its purest form:
// nothing is asked, nothing is lost, no other agent is stopped.

/// Why a session stopped talking to its provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    /// DNS/TLS/connection reset, timeouts, 5xx, 429 — the provider is unreachable *now*.
    Transient,
    /// Out of credit / quota exhausted (402, `insufficient_quota`, "billing"): retrying is
    /// pointless until a human tops the account up, so the wait is long but the state is kept.
    Billing,
}

impl PauseKind {
    pub fn label(&self) -> &'static str {
        match self {
            PauseKind::Transient => "transient",
            PauseKind::Billing => "billing",
        }
    }
    pub fn from_label(s: &str) -> Option<PauseKind> {
        match s {
            "transient" => Some(PauseKind::Transient),
            "billing" => Some(PauseKind::Billing),
            _ => None,
        }
    }
    /// First wait before the automatic retry (it doubles per attempt, see [`bump_pause`]).
    fn first_wait(&self) -> std::time::Duration {
        match self {
            PauseKind::Transient => std::time::Duration::from_secs(60),
            PauseKind::Billing => std::time::Duration::from_secs(15 * 60),
        }
    }
    /// Longest wait between automatic retries.
    fn max_wait(&self) -> std::time::Duration {
        match self {
            PauseKind::Transient => std::time::Duration::from_secs(60 * 60),
            PauseKind::Billing => std::time::Duration::from_secs(6 * 60 * 60),
        }
    }
}

/// A pause recorded on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Pause {
    pub session: String,
    pub kind: String,
    pub reason: String,
    pub ts_ms: u64,
    /// When the automatic retry is allowed (0 = never: a resource cap needs `ark resume`).
    pub next_ms: u64,
    pub attempts: u32,
}

fn billing_words() -> &'static [&'static str] {
    &["insufficient_quota", "insufficient quota", "quota", "billing", "out of credit", "credit balance", "payment", "exceeded your current"]
}

/// Classify a *terminal* provider error (one that survived the retries and the fallback chain).
/// `None` means "a real error" (bad key, bad request, refusal…): that one is reported, not paused.
pub fn classify(rt: &Runtime, e: &ark_core::ProviderError) -> Option<(PauseKind, std::time::Duration)> {
    use ark_core::ProviderErrorKind as K;
    let lower = e.message.to_lowercase();
    let billing = e.status == Some(402) || billing_words().iter().any(|w| lower.contains(w));
    match &e.kind {
        // A rejected key is `Auth`; a drained account is also `Auth` (classify.rs folds
        // 429 insufficient_quota into it) — only the wording tells them apart, and pausing an
        // actually-invalid key forever would hide the setup error.
        K::Auth if billing => Some((PauseKind::Billing, PauseKind::Billing.first_wait())),
        K::Network | K::Timeout | K::Overloaded | K::Server => Some((PauseKind::Transient, PauseKind::Transient.first_wait())),
        K::RateLimited { retry_after } => {
            // Honour the provider's hint, bounded: a 24 h `Retry-After` must not park the agent.
            let d = retry_after.unwrap_or_else(|| PauseKind::Transient.first_wait());
            Some((PauseKind::Transient, d.clamp(std::time::Duration::from_secs(30), PauseKind::Transient.max_wait())))
        }
        _ => {
            // Provider *pool* failures surface as `Auth` with a "cooling down" message.
            if rt.cfg.model.fallback.is_empty() && lower.contains("cooling down") {
                Some((PauseKind::Transient, PauseKind::Transient.first_wait()))
            } else {
                None
            }
        }
    }
}

fn plan_wait(kind: PauseKind, attempts: u32) -> std::time::Duration {
    let base = kind.first_wait().as_secs().saturating_mul(1u64 << attempts.min(8));
    std::time::Duration::from_secs(base.min(kind.max_wait().as_secs()))
}

/// Record a provider pause for `session` (first attempt). Existing pause markers are kept if
/// they are for the same session (the caller should use [`bump_pause`] when retrying).
pub fn record_pause(home: &Path, session: &str, kind: PauseKind, reason: &str, retry_in: std::time::Duration) {
    write_pause_full(home, session, kind.label(), reason, now_ms() + retry_in.as_millis() as u64, 0);
}

fn write_pause_full(home: &Path, session: &str, kind: &str, reason: &str, next_ms: u64, attempts: u32) {
    let p = pause_marker(home, session);
    if let Some(dir) = p.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let body = json!({"session": session, "kind": kind, "reason": reason, "ts_ms": now_ms(), "next_ms": next_ms, "attempts": attempts});
    let _ = std::fs::write(p, body.to_string());
}

/// Read the pause record of a session (works for resource pauses too: `kind` is `"limits"`).
pub fn pause_info(home: &Path, session: &str) -> Option<Pause> {
    let text = std::fs::read_to_string(pause_marker(home, session)).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let g = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some(Pause {
        session: g("session"),
        kind: if g("kind").is_empty() { "limits".into() } else { g("kind") },
        reason: if g("reason").is_empty() { "paused".into() } else { g("reason") },
        ts_ms: v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0),
        next_ms: v.get("next_ms").and_then(Value::as_u64).unwrap_or(0),
        attempts: v.get("attempts").and_then(Value::as_u64).unwrap_or(0) as u32,
    })
}

/// Every pause whose automatic retry is due at `now_ms` (provider pauses only; a resource pause
/// waits for a human).
pub fn due_pauses(home: &Path, now: u64) -> Vec<Pause> {
    let Ok(rd) = std::fs::read_dir(limits_dir(home).join("paused")) else { return Vec::new() };
    let mut out: Vec<Pause> = Vec::new();
    for e in rd.flatten() {
        let Some(text) = std::fs::read_to_string(e.path()).ok() else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        let g = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let kind = g("kind");
        if PauseKind::from_label(&kind).is_none() {
            continue;
        }
        let next = v.get("next_ms").and_then(Value::as_u64).unwrap_or(0);
        if next == 0 || next > now {
            continue;
        }
        out.push(Pause { session: g("session"), kind, reason: g("reason"), ts_ms: v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0), next_ms: next, attempts: v.get("attempts").and_then(Value::as_u64).unwrap_or(0) as u32 });
    }
    out.sort_by_key(|p| p.next_ms);
    out
}

/// Push a retried pause further out (doubling, capped per kind). Returns the new record.
pub fn bump_pause(home: &Path, p: &Pause) -> Pause {
    let kind = PauseKind::from_label(&p.kind).unwrap_or(PauseKind::Transient);
    let attempts = p.attempts.saturating_add(1);
    let wait = plan_wait(kind, attempts);
    let next = now_ms() + wait.as_millis() as u64;
    write_pause_full(home, &p.session, kind.label(), &p.reason, next, attempts);
    Pause { attempts, next_ms: next, ..p.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Paths};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<Arc<dyn ark_core::provider::Provider>, String> {
            Err(format!("no provider `{id}` in this test"))
        }
    }

    /// Throwaway data dir that removes itself.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("ark-limits-{tag}-{}-{}", std::process::id(), crate::util::random_hex(6)));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A kernel over a temp data dir; `mutate` edits `[limits]` (and prices).
    fn kernel(tmp: &Tmp, mutate: impl FnOnce(&mut Config)) -> crate::kernel::Kernel {
        let root = tmp.0.clone();
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        // $1 per 1k tokens: a few tokens are measurable fractions of a cent.
        cfg.prices.insert("fake/m".into(), crate::ledger::Price { input: 1000.0, output: 1000.0, cache_read: 0.0, cache_write: 0.0 });
        mutate(&mut cfg);
        crate::kernel::new_kernel(cfg, paths, Arc::new(NoModels), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }))
    }

    /// A session that spent `tokens` input tokens (priced at $0.001/token → 1 token = $0.001).
    fn session_with_spend(k: &crate::kernel::Kernel, id: &str, tokens: u64) {
        use ark_core::Message;
        let header = EventKind::Header { version: crate::event::LOG_VERSION, session_id: id.into(), workspace: "/w".into(), model: "fake/m".into(), parent: None, title: None };
        let mut log = k.store.create(header).unwrap();
        let usage = Usage { input_tokens: tokens, output_tokens: 0, ..Default::default() };
        log.append(EventKind::Message { message: Message::assistant("done"), usage: Some(usage), model: Some("fake/m".into()), inbox: None }).unwrap();
    }

    #[test]
    fn no_config_never_warns_or_pauses() {
        let tmp = Tmp::new("off");
        let k = kernel(&tmp, |_| {});
        session_with_spend(&k, "s-a", 10_000_000); // $10 000, but no cap is configured
        assert_eq!(check(&k, "s-a"), Verdict::Ok);
        assert!(!status_path(&k.paths.data).exists(), "no cap configured: nothing is measured or written");
        assert!(paused(&k.paths.data, "s-a").is_none());
        assert!(!k.cfg.limits.enabled());
        assert_eq!(status_json(&k)["enabled"], false);
    }

    #[test]
    fn warn_at_the_threshold_then_pause_at_the_cap() {
        let tmp = Tmp::new("warn");
        let k = kernel(&tmp, |c| {
            c.limits.per_agent_spend_usd = 10.0;
            c.limits.warn_at = 0.8;
        });
        // $0.001 per token: 8_500 tokens = $8.50 of $10 (85 %).
        session_with_spend(&k, "s-warn", 8_500);
        match check(&k, "s-warn") {
            Verdict::Warn(r) => assert!(r.contains("per_agent_spend_usd"), "{r}"),
            other => panic!("expected Warn, got {other:?}"),
        }
        assert!(paused(&k.paths.data, "s-warn").is_none(), "a warning does not pause anybody");
        assert!(status_path(&k.paths.data).exists(), "the numbers are on disk for the CLI");

        session_with_spend(&k, "s-over", 11_000); // $11 of $10
        match check(&k, "s-over") {
            Verdict::Pause(r) => {
                assert!(r.contains("limits.per_agent_spend_usd"), "the reason names the cap: {r}");
                assert!(r.contains("11.0000"), "{r}");
            }
            other => panic!("expected Pause, got {other:?}"),
        }
        match paused(&k.paths.data, "s-over") {
            Some(r) => assert!(r.contains("per_agent_spend_usd"), "{r}"),
            None => panic!("pause marker missing"),
        }
        // The pause is scoped to the offending session.
        assert_ne!(check(&k, "s-warn").label(), "pause", "another session is not paused");
    }

    #[test]
    fn hourly_cap_counts_only_the_last_hour() {
        let tmp = Tmp::new("hour");
        let k = kernel(&tmp, |c| {
            c.limits.hourly_spend_usd = 1.0;
        });
        session_with_spend(&k, "s-h", 500); // $0.50 now
        assert_eq!(check(&k, "s-h"), Verdict::Ok);
        session_with_spend(&k, "s-h2", 600); // $1.10 in the last hour, across two sessions
        match check(&k, "s-h") {
            Verdict::Pause(r) => assert!(r.contains("limits.hourly_spend_usd"), "{r}"),
            other => panic!("expected Pause, got {other:?}"),
        }
    }

    #[test]
    fn process_cap_counts_the_registry() {
        let tmp = Tmp::new("procs");
        let k = kernel(&tmp, |c| {
            c.limits.max_processes_per_agent = 1;
        });
        let home = &k.paths.data;
        let mut a = own_group();
        let mut b = own_group();
        for c in [&a, &b] {
            let rec = crate::reaper::Record { pgid: c.id(), start: crate::reaper::start_time(c.id()), session: "s-proc".into(), tool: "shell".into(), ark_pid: std::process::id(), ts_ms: now_ms() };
            crate::reaper::append(home, &rec).unwrap();
        }
        match check(&k, "s-proc") {
            Verdict::Pause(r) => assert!(r.contains("max_processes_per_agent") && r.contains('2'), "{r}"),
            other => panic!("expected Pause, got {other:?}"),
        }
        kill_own(&mut a);
        kill_own(&mut b);
        assert_ne!(check(&k, "s-proc").label(), "ok", "the pause stays until it is cleared");
        assert!(resumed(home, "s-proc"));
        assert_eq!(check(&k, "s-proc"), Verdict::Ok, "one process ended, the cap is met again");
    }

    #[test]
    fn a_pause_is_sticky_until_resumed() {
        let tmp = Tmp::new("resume");
        let k = kernel(&tmp, |c| {
            c.limits.per_agent_spend_usd = 10.0;
        });
        let home = &k.paths.data;
        session_with_spend(&k, "s-p", 100); // $0.10: far below the cap
        write_pause(home, "s-p", "manual: owner review");
        match check(&k, "s-p") {
            Verdict::Pause(r) => assert!(r.contains("manual: owner review"), "{r}"),
            other => panic!("expected the stored Pause, got {other:?}"),
        }
        assert!(paused(home, "s-p").is_some());
        assert_eq!(paused_sessions(home).len(), 1);
        assert!(resumed(home, "s-p"), "the marker existed");
        assert!(!resumed(home, "s-p"), "clearing twice is a no-op");
        assert!(paused(home, "s-p").is_none());
        assert_eq!(check(&k, "s-p"), Verdict::Ok);
        assert!(status_json(&k)["paused"].as_array().unwrap().is_empty());
    }

    #[test]
    fn disk_cap_is_measured_from_the_session_data_dir() {
        let tmp = Tmp::new("disk");
        let k = kernel(&tmp, |c| {
            c.limits.disk_mb_per_agent = 1;
        });
        session_with_spend(&k, "s-d", 1);
        // 2 MB of session data (one sparse-free file is enough for `dir_bytes`).
        let dir = rt_store_dir(&k.paths.data, "s-d");
        std::fs::write(dir.join("blob.bin"), vec![7u8; 2 * 1024 * 1024]).unwrap();
        match check(&k, "s-d") {
            Verdict::Pause(r) => assert!(r.contains("disk_mb_per_agent"), "{r}"),
            other => panic!("expected Pause, got {other:?}"),
        }
    }

    fn own_group() -> Child {
        Command::new("/bin/sh").arg("-c").arg("sleep 60").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).spawn().expect("spawn sleep")
    }

    fn kill_own(c: &mut Child) {
        // SAFETY: our own child's process group.
        unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
        let _ = c.wait();
    }

    // ───────────── provider pauses: transient failure and billing (C1/C2) ─────────────

    use ark_core::{ProviderError, ProviderErrorKind as K};

    #[test]
    fn transient_failures_pause_instead_of_failing() {
        let tmp = Tmp::new("transient");
        let k = kernel(&tmp, |_| {});
        for e in [
            ProviderError::new(K::Network, "dns lookup failed for api.example"),
            ProviderError::new(K::Timeout, "timed out"),
            ProviderError::new(K::Overloaded, "529 overloaded"),
            ProviderError::new(K::Server, "500 internal"),
            ProviderError::new(K::RateLimited { retry_after: None }, "slow down"),
        ] {
            let (kind, wait) = classify(&k, &e).unwrap_or_else(|| panic!("{e:?} must pause, not fail"));
            assert_eq!(kind, PauseKind::Transient, "{e:?}");
            assert!(wait >= std::time::Duration::from_secs(30) && wait <= PauseKind::Transient.max_wait(), "{e:?} → {wait:?}");
        }
        // A hint from the provider is honoured, bounded.
        let e = ProviderError::new(K::RateLimited { retry_after: Some(std::time::Duration::from_secs(7)) }, "429");
        assert_eq!(classify(&k, &e).unwrap().1, std::time::Duration::from_secs(30), "floored at 30s");
        let e = ProviderError::new(K::RateLimited { retry_after: Some(std::time::Duration::from_secs(86_400)) }, "429");
        assert_eq!(classify(&k, &e).unwrap().1, PauseKind::Transient.max_wait(), "a 24h hint is not honoured verbatim");
    }

    #[test]
    fn a_drained_account_pauses_for_a_long_time_and_a_bad_key_does_not() {
        let tmp = Tmp::new("billing");
        let k = kernel(&tmp, |_| {});
        let quota = ProviderError::new(K::Auth, "You exceeded your current quota, please check your plan and billing details").with_status(429);
        let (kind, wait) = classify(&k, &quota).expect("quota pauses");
        assert_eq!(kind, PauseKind::Billing);
        assert_eq!(wait, std::time::Duration::from_secs(15 * 60));

        let card = ProviderError::new(K::Auth, "payment required").with_status(402);
        assert_eq!(classify(&k, &card).unwrap().0, PauseKind::Billing);

        let bad_key = ProviderError::new(K::Auth, "invalid api key").with_status(401);
        assert!(classify(&k, &bad_key).is_none(), "a rejected credential is a setup error, not a pause");
        let bad = ProviderError::new(K::BadRequest, "tools[3] is invalid").with_status(400);
        assert!(classify(&k, &bad).is_none());
    }

    #[test]
    fn only_due_provider_pauses_are_retried_and_the_wait_doubles() {
        let tmp = Tmp::new("due");
        let home = tmp.0.clone();
        let now = now_ms();
        record_pause(&home, "s-t", PauseKind::Transient, "dns", std::time::Duration::ZERO);
        record_pause(&home, "s-b", PauseKind::Billing, "quota", std::time::Duration::from_secs(3600));
        assert_eq!(due_pauses(&home, now).len(), 1, "the billing pause is not due yet");
        assert_eq!(due_pauses(&home, now)[0].session, "s-t");

        let p = pause_info(&home, "s-t").unwrap();
        let bumped = bump_pause(&home, &p);
        assert_eq!(bumped.attempts, 1);
        assert!(bumped.next_ms > now, "retrying pushed the next attempt out");
        assert!(due_pauses(&home, bumped.next_ms - 1).is_empty());
        assert_eq!(due_pauses(&home, bumped.next_ms).len(), 1);
        assert_eq!(due_pauses(&home, bumped.next_ms)[0].kind, "transient");

        // A resource pause (no kind) is never retried automatically: a human decides.
        write_pause(&home, "s-r", "resource cap reached");
        assert!(pause_info(&home, "s-r").is_some_and(|p| p.kind == "limits" && p.next_ms == 0));
        assert!(due_pauses(&home, u64::MAX).iter().all(|p| p.session != "s-r"));
    }
}
