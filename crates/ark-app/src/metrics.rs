//! Prometheus text exposition (`GET /metrics`, ent-099) and readiness checks (`GET /ready`,
//! ent-098).
//!
//! Counters are process-global atomics bumped by the app server; gauges are read from the
//! daemon at scrape time. Labels never carry content — only route classes, status classes,
//! principal kinds and method names from a fixed vocabulary.
//!
//! Readiness is a list of named checks. Built-in: the kernel answers, the default model's
//! provider resolves and is not marked down, the audit stream is writable. Hosts add their own
//! with [`register_check`] (the `ark` binary registers channel connections and the VM pool),
//! so `/ready` answers "can this instance do work now", where `/health` only says "the process
//! is up".

use ark_kernel::daemon::Daemon;
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

pub fn started() {
    let _ = STARTED.get_or_init(Instant::now);
}

/// Bump `ark_<name>_total{labels}`. `labels` is a pre-rendered `k="v",…` list of fixed values.
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
            out.push_str(&format!("# TYPE ark_{name}_total counter\n"));
        }
        out.push_str(&format!("ark_{name}_total{{{labels}}} {v}\n"));
    }
    let k = &d.k;
    let sessions = k.store.list();
    let running = k.running_ids().len();
    let pending = d.call("gate.pending", &json!({})).ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
    let gauge = |out: &mut String, name: &str, help: &str, v: f64| {
        out.push_str(&format!("# HELP ark_{name} {help}\n# TYPE ark_{name} gauge\nark_{name} {v}\n"));
    };
    gauge(&mut out, "up", "1 while the app server answers", 1.0);
    gauge(&mut out, "uptime_seconds", "seconds since the app server started", STARTED.get().map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0));
    gauge(&mut out, "sessions", "sessions on disk", sessions.len() as f64);
    gauge(&mut out, "sessions_running", "sessions with a turn in progress", running as f64);
    gauge(&mut out, "approvals_pending", "approvals and questions waiting for a human", pending as f64);
    gauge(&mut out, "audit_seq", "sequence number of the newest audit record", ark_security::audit::head(&k.paths.data).seq as f64);
    gauge(&mut out, "audit_write_errors", "audit records that could not be written", AUDIT_ERRORS.load(Ordering::Relaxed) as f64);
    gauge(&mut out, "audit_errors", "audit write / SIEM export failures in this process", ark_security::audit::errors().0 as f64);
    gauge(&mut out, "estop_engaged", "1 while the emergency stop is engaged", if ark_security::estop::is_engaged(&k.paths.data) { 1.0 } else { 0.0 });
    for sink in k.cfg.audit.export.sinks() {
        let lag = ark_security::audit::head(&k.paths.data).seq.saturating_sub(ark_security::audit_export::cursor(&k.paths.data, &sink));
        out.push_str(&format!("ark_audit_export_lag{{sink=\"{}\"}} {lag}\n", esc(&sink)));
    }
    for (name, r) in readiness(d).1 {
        out.push_str(&format!("ark_ready{{check=\"{}\"}} {}\n", esc(&name), if r.is_ok() { 1 } else { 0 }));
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
    let dir = ark_security::audit::dir(&d.k.paths.data);
    v.push(("audit".into(), std::fs::create_dir_all(&dir).map(|_| "writable".to_string()).map_err(|e| format!("{}: {e}", dir.display()))));
    if ark_security::estop::is_engaged(&d.k.paths.data) {
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
