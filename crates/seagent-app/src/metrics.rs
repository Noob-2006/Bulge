//! Prometheus text exposition (`GET /metrics`, ent-099) and readiness checks (`GET /ready`,
//! ent-098).
//!
//! Counters are process-global atomics bumped by the app server; gauges are read from the
//! daemon at scrape time. Labels never carry content — only route classes, status classes,
//! principal kinds and method names from a fixed vocabulary.
//!
//! Readiness is a list of named checks. Built-in: the kernel answers, the default model's
//! provider resolves and is not marked down, the audit stream is writable. Hosts add their own
//! with [`register_check`] (the `seagent` binary registers channel connections and the VM pool),
//! so `/ready` answers "can this instance do work now", where `/health` only says "the process
//! is up".

use seagent_kernel::daemon::Daemon;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Instant;

fn counters() -> &'static Mutex<BTreeMap<(String, String), u64>> {
    static C: OnceLock<Mutex<BTreeMap<(String, String), u64>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

static STARTED: OnceLock<Instant> = OnceLock::new();
static AUDIT_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Busy-arrival telemetry (Hermes `observability/shared_metrics_busy.py`): how often input
/// reaches an agent mid-turn, and how many distinct chats were busy in a day. No message
/// content and no session id leaves this structure.
#[derive(Default)]
struct BusyState {
    /// Unix day number (`now / 86_400`).
    day: u64,
    sessions: std::collections::HashSet<String>,
    peak: usize,
}
static BUSY: Mutex<Option<BusyState>> = Mutex::new(None);

fn busy_day(now_secs: u64) -> u64 {
    now_secs / 86_400
}

/// Record one busy arrival and mark the chat busy for today. `outcome` is `queued`, `steered`
/// or `dropped` (bounded vocabulary).
pub fn busy_arrival(session: &str, outcome: &str) {
    let outcome = match outcome {
        "steered" | "dropped" => outcome,
        _ => "queued",
    };
    inc("busy_arrivals", &format!("outcome=\"{outcome}\""));
    note_busy_at(session, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
}

/// Testable day-scoped bookkeeping: count distinct busy chats and keep the peak.
pub fn note_busy_at(session: &str, now_secs: u64) {
    if session.is_empty() {
        return;
    }
    let day = busy_day(now_secs);
    let mut g = BUSY.lock().unwrap_or_else(|e| e.into_inner());
    let st = g.get_or_insert_with(BusyState::default);
    if st.day != day {
        st.day = day;
        st.sessions.clear();
        st.peak = 0;
    }
    st.sessions.insert(session.to_string());
    st.peak = st.peak.max(st.sessions.len());
}

/// `(distinct busy chats today, daily peak)`.
pub fn busy_snapshot() -> (usize, usize) {
    let g = BUSY.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().map(|s| (s.sessions.len(), s.peak)).unwrap_or((0, 0))
}

#[cfg(test)]
pub(crate) fn busy_reset() {
    *BUSY.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

pub fn started() {
    let _ = STARTED.get_or_init(Instant::now);
}

/// Bump `seagent_<name>_total{labels}`. `labels` is a pre-rendered `k="v",…` list of fixed values.
pub fn inc(name: &str, labels: &str) {
    let mut c = counters().lock().unwrap_or_else(|e| e.into_inner());
    *c.entry((name.to_string(), labels.to_string())).or_insert(0) += 1;
}

pub fn audit_error() {
    AUDIT_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// The method label: known ARP methods by name, anything else as `other` (bounded cardinality).
pub fn method_label(m: &str) -> &str {
    if crate::exposure::method_scope_table().iter().any(|(k, _)| *k == m) || matches!(m, "audit.query" | "audit.verify" | "whoami") {
        m
    } else {
        "other"
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// The full exposition.
pub fn render(d: &Daemon) -> String {
    let mut out = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for ((name, labels), v) in counters().lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if seen.insert(name.clone()) {
            out.push_str(&format!("# TYPE seagent_{name}_total counter\n"));
        }
        out.push_str(&format!("seagent_{name}_total{{{labels}}} {v}\n"));
    }
    let k = &d.k;
    let sessions = k.store.list();
    let running = k.running_ids().len();
    let pending = d.call("gate.pending", &json!({})).ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
    let gauge = |out: &mut String, name: &str, help: &str, v: f64| {
        out.push_str(&format!("# HELP seagent_{name} {help}\n# TYPE seagent_{name} gauge\nseagent_{name} {v}\n"));
    };
    gauge(&mut out, "up", "1 while the app server answers", 1.0);
    gauge(&mut out, "uptime_seconds", "seconds since the app server started", STARTED.get().map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0));
    gauge(&mut out, "sessions", "sessions on disk", sessions.len() as f64);
    gauge(&mut out, "sessions_running", "sessions with a turn in progress", running as f64);
    gauge(&mut out, "approvals_pending", "approvals and questions waiting for a human", pending as f64);
    gauge(&mut out, "audit_seq", "sequence number of the newest audit record", seagent_security::audit::head(&k.paths.data).seq as f64);
    gauge(&mut out, "audit_write_errors", "audit records that could not be written", AUDIT_ERRORS.load(Ordering::Relaxed) as f64);
    gauge(&mut out, "audit_errors", "audit write / SIEM export failures in this process", seagent_security::audit::errors().0 as f64);
    gauge(&mut out, "estop_engaged", "1 while the emergency stop is engaged", if seagent_security::estop::is_engaged(&k.paths.data) { 1.0 } else { 0.0 });
    let (busy_today, busy_peak) = busy_snapshot();
    gauge(&mut out, "busy_chats_today", "distinct chats that received input while busy today", busy_today as f64);
    gauge(&mut out, "busy_chats_daily_peak", "largest daily count of distinct busy chats", busy_peak as f64);
    for sink in k.cfg.audit.export.sinks() {
        let lag = seagent_security::audit::head(&k.paths.data).seq.saturating_sub(seagent_security::audit_export::cursor(&k.paths.data, &sink));
        out.push_str(&format!("seagent_audit_export_lag{{sink=\"{}\"}} {lag}\n", esc(&sink)));
    }
    for (name, r) in readiness(d).1 {
        out.push_str(&format!("seagent_ready{{check=\"{}\"}} {}\n", esc(&name), if r.is_ok() { 1 } else { 0 }));
    }
    out
}

pub type Check = Arc<dyn Fn() -> Result<String, String> + Send + Sync>;

fn checks() -> &'static RwLock<Vec<(String, Check)>> {
    static C: OnceLock<RwLock<Vec<(String, Check)>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// Add (or replace) a readiness check, e.g. `channel:slack` or `vm_pool`.
pub fn register_check(name: &str, f: Check) {
    let mut c = checks().write().unwrap_or_else(|e| e.into_inner());
    c.retain(|(n, _)| n != name);
    c.push((name.to_string(), f));
}

fn model_check(d: &Daemon) -> Result<String, String> {
    let k = &d.k;
    let model = k.cfg.resolve_model(&k.cfg.model.default);
    let provider = model.split('/').next().unwrap_or("").to_string();
    if k.cfg.aux_holdouts().contains(&provider) {
        return Err(format!("provider `{provider}` is marked down after failed calls"));
    }
    k.resolver.provider(&provider).map(|_| model.to_string()).map_err(|e| format!("{model}: {e}"))
}

/// One named check's outcome.
pub type CheckResult = (String, Result<String, String>);

/// `(ready, [(check, result)])`.
pub fn readiness(d: &Daemon) -> (bool, Vec<CheckResult>) {
    let mut v: Vec<CheckResult> = vec![];
    v.push(("kernel".into(), d.call("ping", &json!({})).map(|_| "ok".to_string()).map_err(|(_, e)| e)));
    v.push(("model".into(), model_check(d)));
    let dir = seagent_security::audit::dir(&d.k.paths.data);
    v.push(("audit".into(), std::fs::create_dir_all(&dir).map(|_| "writable".to_string()).map_err(|e| format!("{}: {e}", dir.display()))));
    if seagent_security::estop::is_engaged(&d.k.paths.data) {
        v.push(("estop".into(), Err("emergency stop is engaged".into())));
    }
    for (name, f) in checks().read().unwrap_or_else(|e| e.into_inner()).iter() {
        v.push((name.clone(), f()));
    }
    (v.iter().all(|(_, r)| r.is_ok()), v)
}

pub fn readiness_json(d: &Daemon) -> (bool, Value) {
    let (ok, v) = readiness(d);
    let checks: Vec<Value> = v.into_iter().map(|(n, r)| match r {
        Ok(detail) => json!({"name": n, "ok": true, "detail": detail}),
        Err(e) => json!({"name": n, "ok": false, "error": e}),
    }).collect();
    (ok, json!({"ready": ok, "checks": checks}))
}

#[cfg(test)]
mod busy_tests {
    use super::*;

    #[test]
    fn busy_chats_are_day_scoped_and_peak_is_kept() {
        busy_reset();
        note_busy_at("s1", 10 * 86_400 + 5);
        note_busy_at("s1", 10 * 86_400 + 6);
        note_busy_at("s2", 10 * 86_400 + 7);
        assert_eq!(busy_snapshot(), (2, 2));
        note_busy_at("s3", 11 * 86_400 + 1);
        assert_eq!(busy_snapshot(), (1, 1), "a new day starts a fresh count");
        busy_reset();
    }

    #[test]
    fn busy_arrivals_only_use_the_fixed_outcome_vocabulary() {
        busy_reset();
        let before = counters().lock().unwrap().len();
        busy_arrival("metric-session-a", "steered");
        busy_arrival("metric-session-a", "not-a-real-outcome");
        let c = counters().lock().unwrap();
        assert!(c.contains_key(&("busy_arrivals".to_string(), "outcome=\"steered\"".to_string())));
        assert!(c.contains_key(&("busy_arrivals".to_string(), "outcome=\"queued\"".to_string())), "unknown outcomes fold into queued");
        assert!(c.len() >= before + 2);
        drop(c);
        assert_eq!(busy_snapshot().0, 1);
        busy_reset();
    }
}
