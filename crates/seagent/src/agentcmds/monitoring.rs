//! Gateway monitoring over OTLP (Hermes `agent/monitoring/{emitter,events,otlp_exporter,
//! redaction,policy}.py`): content-free service-health and redacted diagnostic events,
//! exported as OTel spans over OTLP/HTTP JSON to the operator's collector.
//!
//! * [`emit`] never blocks and never fails: a bounded queue (10 000, oldest dropped) drained in
//!   batches of 256 by one dispatcher thread; collection is off until an exporter subscribes.
//! * Events: `gateway_health` (daemon start/stop), `gateway_diagnostic` (model API errors),
//!   `cron_execution` ([`cron_execution`], for the scheduler). Per-kind attribute allowlists:
//!   nothing else (prompts, messages, tool args, session ids) ever leaves the process; every
//!   string passes secret redaction, then e-mail / UUID / phone scrubbing, bounded to 500 chars.
//! * Export: `[telemetry] enabled = true`, `endpoint` (base URL, `/v1/traces` appended; a
//!   `/v1/metrics` path is rewritten), `headers` (`{{secret:NAME}}` resolved at send time and
//!   never logged), resource `service.name`, `service.instance.id` = a persisted pseudonymous
//!   install id (`<data>/monitoring/install_id`, delete to rotate), `telemetry.scope`.
//! * LangSmith: pointing `endpoint` at `https://api.smith.langchain.com` (or any `*.langsmith.com`
//!   host / `…/otel` base) switches the exporter to LangSmith's ingestion profile — URL, headers
//!   and `langsmith.span.kind` — see [`langsmith`] and `docs/ecosystem/langsmith.md`.

pub mod langsmith;

use seagent_kernel::hooks::{Hook, HookDecision, HookEvent};
use seagent_kernel::kernel::Kernel;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

const MAX_QUEUE: usize = 10_000;
const DRAIN_BATCH: usize = 256;

type Sub = Arc<dyn Fn(&[Value]) + Send + Sync>;

#[derive(Default)]
struct Inner {
    q: VecDeque<Value>,
    subs: Vec<Sub>,
    dropped: u64,
    dispatched: u64,
    in_flight: usize,
    started: bool,
}

pub struct Emitter {
    inner: Mutex<Inner>,
    cv: Condvar,
}

pub fn emitter() -> &'static Emitter {
    static E: OnceLock<Emitter> = OnceLock::new();
    E.get_or_init(|| Emitter { inner: Mutex::default(), cv: Condvar::new() })
}

fn now_ns() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

impl Emitter {
    /// Hot path: O(1), never blocks on I/O, never panics into the caller.
    pub fn emit(&'static self, mut ev: Value) {
        let Ok(mut g) = self.inner.lock() else { return };
        if g.subs.is_empty() {
            return;
        }
        if ev.get("ts_ns").is_none() {
            ev["ts_ns"] = json!(now_ns() as u64);
        }
        if g.q.len() >= MAX_QUEUE {
            g.q.pop_front();
            g.dropped += 1;
        }
        g.q.push_back(ev);
        if !g.started {
            g.started = true;
            std::thread::Builder::new().name("seagent-monitoring-dispatch".into()).spawn(move || self.run()).ok();
        }
        self.cv.notify_all();
    }

    fn run(&'static self) {
        loop {
            let (batch, subs) = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                while g.q.is_empty() {
                    g = self.cv.wait_timeout(g, Duration::from_millis(500)).unwrap_or_else(|e| e.into_inner()).0;
                }
                let n = g.q.len().min(DRAIN_BATCH);
                let b: Vec<Value> = g.q.drain(..n).collect();
                g.in_flight = b.len();
                (b, g.subs.clone())
            };
            for s in subs {
                // Fail-isolated: a broken subscriber never stops the others.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s(&batch)));
            }
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.dispatched += batch.len() as u64;
            g.in_flight = 0;
            self.cv.notify_all();
        }
    }

    pub fn subscribe(&self, s: Sub) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).subs.push(s);
    }

    /// Wait (bounded) until queued and in-flight batches are dispatched. Only the tests need to
    /// observe the dispatcher, so this does not exist in a release binary.
    #[cfg(test)]
    pub fn flush(&self, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while (!g.q.is_empty() || g.in_flight > 0) && std::time::Instant::now() < deadline {
            g = self.cv.wait_timeout(g, Duration::from_millis(50)).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    pub fn stats(&self) -> Value {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        json!({"queued": g.q.len(), "dispatched": g.dispatched, "dropped": g.dropped, "subscribers": g.subs.len()})
    }
}

pub fn emit(ev: Value) {
    emitter().emit(ev)
}

// ── events ──────────────────────────────────────────────────────────────────

pub fn gateway_health(k: &Kernel, name: &str, state: Option<&str>) {
    emit(json!({"event": "gateway_health", "name": name, "gateway_state": state, "active_agents": k.running_ids().len(), "gateway_busy": !k.running_ids().is_empty(), "version": env!("CARGO_PKG_VERSION"), "pid": std::process::id()}));
}

pub fn gateway_diagnostic(name: &str, subsystem: &str, error_class: &str, platform: Option<&str>, severity: &str) {
    emit(json!({"event": "gateway_diagnostic", "name": name, "subsystem": subsystem, "error_class": error_class, "platform": platform, "severity": severity, "version": env!("CARGO_PKG_VERSION")}));
}

/// For the scheduler: one durable cron execution state change (content-free).
pub fn cron_execution(status: &str, job_key: &str, source: &str, duration_ms: Option<u64>, delivery_outcome: Option<&str>, error_class: Option<&str>) {
    emit(json!({"event": "cron_execution", "status": status, "job_key": job_key, "source": source, "duration_ms": duration_ms, "delivery_outcome": delivery_outcome, "error_class": error_class}));
}

/// The cron execution observer the binary registers at startup
/// (`seagent_kernel::automation::set_exec_observer` in `wire::attach`): one `cron_execution`
/// event per executed job, with the job id, terminal status, duration and nothing else.
pub fn cron_observer() -> seagent_kernel::automation::ExecObserver {
    Arc::new(|job_id: &str, ok: bool, duration_ms: u64| {
        cron_execution(if ok { "completed" } else { "failed" }, job_id, "builtin", Some(duration_ms), None, (!ok).then_some("unknown"))
    })
}

// ── redaction ───────────────────────────────────────────────────────────────

/// Secrets, then e-mail / UUID / phone shapes (upstream `redact_for_export`).
pub fn redact_for_export(s: &str) -> String {
    static RE: OnceLock<[regex::Regex; 3]> = OnceLock::new();
    let [email, uuid, phone] = RE.get_or_init(|| {
        [
            regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
            regex::Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap(),
            regex::Regex::new(r"(?:^|[^\w])((?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?\d{3}[\s.\-]?\d{3,4}(?:[\s.\-]?\d{2,4})?)(?:$|[^\w])").unwrap(),
        ]
    });
    let out = seagent_kernel::kanban::ops::redact(s);
    let out = email.replace_all(&out, "[email]").into_owned();
    let out = uuid.replace_all(&out, "[id]").into_owned();
    // The phone pattern needs non-word boundaries (no look-around in `regex`): replace the group.
    let mut res = String::with_capacity(out.len());
    let mut last = 0;
    for c in phone.captures_iter(&out) {
        let g = c.get(1).unwrap();
        res.push_str(&out[last..g.start()]);
        res.push_str("[phone]");
        last = g.end();
    }
    res.push_str(&out[last..]);
    res
}

pub fn redact_bounded(s: &str, limit: usize) -> String {
    let r = redact_for_export(s);
    let r = if r.is_empty() { "[redacted]".to_string() } else { r };
    r.chars().take(limit).collect()
}

const KEEP_HEALTH: &[&str] = &["name", "gateway_state", "old_state", "new_state", "exit_reason", "restart_requested", "active_agents", "gateway_busy", "gateway_drainable", "platform_count", "fatal_platform_count", "version", "supervision_mode", "pid"];
const KEEP_DIAG: &[&str] = &["name", "subsystem", "error_class", "error_code", "platform", "old_state", "new_state", "version", "severity"];
const KEEP_CRON: &[&str] = &["status", "job_key", "source", "duration_ms", "delivery_outcome", "error_class"];

fn kv(k: &str, v: &Value) -> Option<Value> {
    let val = match v {
        Value::String(s) => json!({"stringValue": redact_bounded(s, 500)}),
        Value::Bool(b) => json!({"boolValue": b}),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({"intValue": n.to_string()}),
        Value::Number(n) => json!({"doubleValue": n.as_f64()}),
        _ => return None,
    };
    Some(json!({"key": k, "value": val}))
}

/// Span attributes for one event: `seagent.event` plus the kind's allowlist (`seagent.<key>`).
pub fn span_attrs(ev: &Value) -> Vec<Value> {
    let kind = ev["event"].as_str().unwrap_or("unknown");
    let keep: &[&str] = match kind {
        "gateway_health" => KEEP_HEALTH,
        "gateway_diagnostic" => KEEP_DIAG,
        "cron_execution" => KEEP_CRON,
        _ => &[],
    };
    let mut a = vec![json!({"key": "seagent.event", "value": {"stringValue": kind}})];
    a.extend(keep.iter().filter_map(|k| ev.get(*k).filter(|v| !v.is_null()).and_then(|v| kv(&format!("seagent.{k}"), v))));
    a
}

// ── OTLP/HTTP JSON exporter ─────────────────────────────────────────────────

/// `<endpoint>/v1/traces`; a `/v1/metrics` path is rewritten, `/v1/traces` kept. LangSmith
/// hosts get the SDK's `…/otel/v1/traces` instead ([`langsmith::traces_url`]).
pub fn traces_endpoint(endpoint: &str) -> String {
    if langsmith::is_langsmith(endpoint) {
        return langsmith::traces_url(endpoint);
    }
    let e = endpoint.trim_end_matches('/');
    if e.ends_with("/v1/traces") {
        e.to_string()
    } else if let Some(b) = e.strip_suffix("/v1/metrics") {
        format!("{b}/v1/traces")
    } else {
        format!("{e}/v1/traces")
    }
}

const SAFE_RESOURCE: fn(&str) -> bool = |s| !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c));

pub fn install_id(data: &std::path::Path) -> String {
    let p = data.join("monitoring").join("install_id");
    if let Some(id) = std::fs::read_to_string(&p).ok().map(|s| s.trim().to_string()).filter(|s| SAFE_RESOURCE(s)) {
        return id;
    }
    let h = seagent_kernel::util::random_hex(32);
    let id = format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]);
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    let _ = std::fs::write(&p, &id);
    id
}

pub struct Otlp {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub resource: Vec<Value>,
    /// Endpoint is a LangSmith host: spans get its run-type attributes and the body is checked
    /// against the OTLP JSON shape before it is sent.
    pub langsmith: bool,
    pub exported: std::sync::atomic::AtomicU64,
}

impl Otlp {
    pub fn new(k: &Kernel) -> Otlp {
        let t = &k.cfg.telemetry;
        let sub = k.vault_substitute();
        let svc = if SAFE_RESOURCE(&t.service_name) && t.service_name != "seagent" { t.service_name.clone() } else { "seagent-gateway".into() };
        let resource = vec![
            json!({"key": "service.name", "value": {"stringValue": svc}}),
            json!({"key": "service.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}}),
            json!({"key": "service.instance.id", "value": {"stringValue": install_id(&k.paths.data)}}),
            json!({"key": "telemetry.scope", "value": {"stringValue": "gateway_monitoring"}}),
        ];
        Otlp { langsmith: langsmith::is_langsmith(&t.endpoint), url: traces_endpoint(&t.endpoint), headers: langsmith::headers(&t.endpoint, &t.headers.iter().map(|(a, b)| (a.clone(), b.clone())).collect::<Vec<_>>(), &*sub), resource, exported: Default::default() }
    }

    pub fn body(&self, batch: &[Value]) -> Value {
        let spans: Vec<Value> = batch.iter().map(|ev| {
            let ts = ev["ts_ns"].as_u64().unwrap_or(now_ns() as u64);
            let mut span = json!({"traceId": seagent_kernel::util::random_hex(32), "spanId": seagent_kernel::util::random_hex(16), "name": format!("seagent.{}", ev["event"].as_str().unwrap_or("event")), "kind": 1,
                "startTimeUnixNano": ts.to_string(), "endTimeUnixNano": ts.to_string(), "attributes": span_attrs(ev), "status": {}});
            if self.langsmith {
                langsmith::map_span(&mut span);
            }
            span
        }).collect();
        json!({"resourceSpans": [{"resource": {"attributes": self.resource}, "scopeSpans": [{"scope": {"name": "seagent.monitoring", "version": env!("CARGO_PKG_VERSION")}, "spans": spans}]}]})
    }

    pub fn export(&self, batch: &[Value]) -> Result<u16, String> {
        seagent_net::http::ensure_online("telemetry export")?;
        let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(10))).build().into();
        let mut req = agent.post(&self.url).header("content-type", "application/json");
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let body = serde_json::to_vec(&self.body(batch)).unwrap_or_default();
        if self.langsmith {
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            langsmith::validate_otlp_json(&v)?;
        }
        let r = req.send(&body[..]).map_err(|e| e.to_string())?;
        let s = r.status().as_u16();
        if (200..300).contains(&s) {
            self.exported.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(s)
        } else {
            Err(format!("OTLP collector answered HTTP {s}"))
        }
    }
}

/// Kernel hooks that turn daemon lifecycle and model API errors into monitoring events.
struct MonitoringHook;
impl Hook for MonitoringHook {
    fn name(&self) -> String {
        "monitoring".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        matches!(e, HookEvent::DaemonStart | HookEvent::DaemonStop | HookEvent::TransformApiError)
    }
    fn run(&self, e: HookEvent, p: &Value) -> Result<HookDecision, String> {
        match e {
            HookEvent::DaemonStart => emit(json!({"event": "gateway_health", "name": "gateway.start", "gateway_state": "running", "new_state": "running", "version": env!("CARGO_PKG_VERSION"), "pid": std::process::id()})),
            HookEvent::DaemonStop => emit(json!({"event": "gateway_health", "name": "gateway.stop", "gateway_state": "stopped", "old_state": "running", "new_state": "stopped", "exit_reason": p["reason"].as_str().unwrap_or("shutdown"), "version": env!("CARGO_PKG_VERSION"), "pid": std::process::id()})),
            _ => {
                gateway_diagnostic("model.api_error", "model", &api_error_class(p), p["provider"].as_str(), "warning");
            }
        }
        Ok(HookDecision::Allow)
    }
}

/// Error class for a `transform_api_error` payload. The kernel sends
/// `{"classification": {"kind", "message", "retryable", "fallback"}}`
/// (`seagent-kernel/src/kernel.rs`), so reading top-level `status` silently exported
/// `api_error` for every failure; the kind is mapped to the stable class names the rest of
/// the export uses, with the older `status`/`error_type` keys kept as a fallback for
/// shell/plugin payloads.
pub fn api_error_class(p: &Value) -> String {
    let c = &p["classification"];
    if let Some(s) = c["status"].as_u64().or_else(|| p["status"].as_u64()) {
        return format!("http_{s}");
    }
    let kind = c["kind"].as_str().or_else(|| p["error_type"].as_str()).unwrap_or("");
    // `format!("{:?}", e.kind)` renders `RateLimited { retry_after: .. }`: keep the variant.
    match kind.split([' ', '{']).next().unwrap_or("") {
        "" => "api_error".into(),
        "RateLimited" => "rate_limited".into(),
        "Overloaded" => "overloaded".into(),
        "Server" => "server_error".into(),
        "Network" => "network_error".into(),
        "Timeout" => "timeout".into(),
        "Auth" => "auth_failed".into(),
        "Protocol" => "protocol_error".into(),
        other => other.to_string(),
    }
}

static ATTACHED: OnceLock<Arc<Otlp>> = OnceLock::new();

/// `[telemetry] enabled` → subscribe the OTLP exporter and register the hook.
pub fn attach(k: &Kernel) {
    let t = &k.cfg.telemetry;
    if !t.enabled || t.endpoint.trim().is_empty() || ATTACHED.get().is_some() {
        return;
    }
    if let Err(e) = seagent_net::http::ensure_online("telemetry export") {
        eprintln!("seagent: monitoring: {e}");
        return;
    }
    let o = Arc::new(Otlp::new(k));
    if ATTACHED.set(o.clone()).is_err() {
        return;
    }
    emitter().subscribe(Arc::new(move |b: &[Value]| {
        if let Err(e) = o.export(b) {
            eprintln!("seagent: monitoring: OTLP export failed: {e}");
        }
    }));
    k.add_hooks(vec![Arc::new(MonitoringHook)]);
}

/// `seagent telemetry`-style status for operators.
pub fn status() -> Value {
    json!({"exporter": ATTACHED.get().map(|o| json!({"url": o.url, "langsmith": o.langsmith, "project": langsmith::project(&o.headers), "exported": o.exported.load(std::sync::atomic::Ordering::Relaxed)})), "emitter": emitter().stats()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn redaction_and_allowlists() {
        let r = redact_for_export("mail dana@acme.com id 123e4567-e89b-12d3-a456-426614174000 call +1 415 555 0100 key sk-ant-abcdefghijklmnopqrstuv");
        assert!(r.contains("[email]") && r.contains("[id]") && r.contains("[phone]") && r.contains("[REDACTED]"), "{r}");
        assert!(!r.contains("dana@") && !r.contains("555"));
        let a = span_attrs(&json!({"event": "cron_execution", "status": "ok", "job_key": "daily", "prompt": "SECRET PROMPT", "duration_ms": 12}));
        let keys: Vec<&str> = a.iter().map(|x| x["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["seagent.event", "seagent.status", "seagent.job_key", "seagent.duration_ms"], "content never egresses");
        assert_eq!(traces_endpoint("http://c:4318/"), "http://c:4318/v1/traces");
        assert_eq!(traces_endpoint("http://c:4318/v1/metrics"), "http://c:4318/v1/traces");
        assert_eq!(traces_endpoint("http://c/v1/traces"), "http://c/v1/traces");
    }

    fn capture_events(f: impl FnOnce()) -> Vec<Value> {
        let got = Arc::new(Mutex::new(Vec::<Value>::new()));
        let g = got.clone();
        emitter().subscribe(Arc::new(move |b: &[Value]| g.lock().unwrap().extend(b.iter().cloned())));
        f();
        emitter().flush(Duration::from_secs(5));
        let v = got.lock().unwrap().clone();
        v
    }

    #[test]
    fn api_error_class_comes_from_the_classification() {
        // The kernel's payload (kernel.rs): reading top-level `status` always exported api_error.
        let p = json!({"classification": {"kind": "RateLimited { retry_after: Some(2s) }", "message": "429", "retryable": true, "fallback": true}});
        assert_eq!(api_error_class(&p), "rate_limited");
        assert_eq!(api_error_class(&json!({"classification": {"kind": "Auth", "message": "401"}})), "auth_failed");
        assert_eq!(api_error_class(&json!({"classification": {"kind": "Network", "message": "reset"}})), "network_error");
        assert_eq!(api_error_class(&json!({"classification": {"status": 503, "kind": "Server"}})), "http_503");
        // Shell/plugin payloads keep working, and an empty payload stays content-free.
        assert_eq!(api_error_class(&json!({"error_type": "timeout"})), "timeout");
        assert_eq!(api_error_class(&json!({})), "api_error");
        // Through the hook: exactly one diagnostic with the real class and no message text.
        let got = capture_events(|| {
            MonitoringHook.run(HookEvent::TransformApiError, &json!({"classification": {"kind": "Auth", "message": "bad key sk-ant-secret", "retryable": false}})).unwrap();
        });
        let d: Vec<&Value> = got.iter().filter(|e| e["event"] == "gateway_diagnostic").collect();
        assert_eq!(d.len(), 1, "{got:?}");
        assert_eq!(d[0]["error_class"], "auth_failed");
        let a = serde_json::to_string(&span_attrs(d[0])).unwrap();
        assert!(a.contains("auth_failed") && !a.contains("sk-ant-secret"), "{a}");
    }

    #[test]
    fn fired_job_emits_exactly_one_cron_execution() {
        let t = crate::testkit::kit();
        // wire::attach registers the same observer at startup; first registration wins.
        let _ = seagent_kernel::automation::set_exec_observer(cron_observer());
        let job = seagent_kernel::automation::add_job(&t.paths.data, "@every 1h", "SECRET PROMPT: check the disks", &t.ws, None, false, 0).unwrap();
        let got = capture_events(|| {
            seagent_kernel::automation::run_job(&t.k, &job).expect("the job runs");
        });
        let evs: Vec<&Value> = got.iter().filter(|e| e["event"] == "cron_execution").collect();
        assert_eq!(evs.len(), 1, "one event per executed job: {got:?}");
        let ev = evs[0];
        assert_eq!((ev["status"].as_str(), ev["job_key"].as_str()), (Some("completed"), Some(job.id.as_str())));
        assert!(ev["duration_ms"].as_u64().is_some() && ev["source"] == "builtin");
        let a = span_attrs(ev);
        let keys: Vec<&str> = a.iter().map(|x| x["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["seagent.event", "seagent.status", "seagent.job_key", "seagent.source", "seagent.duration_ms"], "allow-list only");
        assert!(!serde_json::to_string(&a).unwrap().contains("SECRET PROMPT"), "no prompt text egresses");
        assert!(!serde_json::to_string(ev).unwrap().contains("SECRET PROMPT"), "the event itself carries no prompt");
    }

    #[test]
    fn langsmith_endpoint_gets_its_own_url_headers_and_run_types() {
        // Point at LangSmith; the URL, the project header and the span kinds must match the
        // profile `langsmith-sdk` uses, or the ingest drops the export.
        let t = crate::testkit::kit_with(|c| {
            c.telemetry.enabled = true;
            c.telemetry.endpoint = "https://api.smith.langchain.com".into();
            c.telemetry.headers.insert("x-api-key".into(), "k-ls".into());
            c.telemetry.headers.insert("Langsmith-Project".into(), "seagent-prod".into());
        });
        let o = Otlp::new(&t.k);
        assert_eq!(o.url, "https://api.smith.langchain.com/otel/v1/traces");
        assert!(o.langsmith);
        let h = |name: &str| o.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
        assert_eq!(h("x-api-key").as_deref(), Some("k-ls"));
        assert_eq!(h("Langsmith-Project").as_deref(), Some("seagent-prod"));
        let body = o.body(&[json!({"event": "cron_execution", "status": "ok", "job_key": "j1", "ts_ns": 1u64})]);
        langsmith::validate_otlp_json(&body).expect("the body satisfies the OTLP JSON shape LangSmith ingests");
        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        let attr = |k: &str| span["attributes"].as_array().unwrap().iter().find(|a| a["key"] == k).and_then(|a| a["value"]["stringValue"].as_str().map(String::from));
        assert_eq!(attr(langsmith::SPAN_KIND).as_deref(), Some("chain"));
        assert_eq!(attr(langsmith::RUN_NAME).as_deref(), Some("seagent.cron_execution"));
        // The project is visible to `seagent telemetry`.
        assert_eq!(langsmith::project(&o.headers).as_deref(), Some("seagent-prod"));
    }

    #[test]
    fn exports_spans_to_a_fake_collector() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let got = Arc::new(Mutex::new(Vec::<String>::new()));
        let g2 = got.clone();
        std::thread::spawn(move || {
            for s in l.incoming().take(3) {
                let mut s = s.unwrap();
                let mut buf = vec![0u8; 65536];
                let mut req = Vec::new();
                loop {
                    let n = s.read(&mut buf).unwrap();
                    req.extend_from_slice(&buf[..n]);
                    let t = String::from_utf8_lossy(&req).to_string();
                    if let Some(i) = t.find("\r\n\r\n") {
                        let len = t.lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                        if req.len() >= i + 4 + len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                g2.lock().unwrap().push(String::from_utf8_lossy(&req).to_string());
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}").unwrap();
            }
        });
        let t = crate::testkit::kit_with(|c| {
            c.telemetry.enabled = true;
            c.telemetry.endpoint = format!("http://127.0.0.1:{port}");
            c.telemetry.headers.insert("x-api-key".into(), "k123".into());
        });
        let o = Otlp::new(&t.k);
        let ev = json!({"event": "gateway_health", "name": "gateway.start", "gateway_state": "running", "pid": 7, "profile": "private-profile"});
        assert_eq!(o.export(&[ev]).unwrap(), 200);
        // Through the emitter: attach subscribes the exporter, emit is non-blocking.
        attach(&t.k);
        gateway_diagnostic("model.api_error", "model", "http_429", Some("openai"), "warning");
        emitter().flush(Duration::from_secs(5));
        for _ in 0..100 {
            if got.lock().unwrap().len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let reqs = got.lock().unwrap().clone();
        assert!(reqs.len() >= 2, "{reqs:?}");
        let r0 = &reqs[0];
        assert!(r0.starts_with("POST /v1/traces ") && r0.to_lowercase().contains("x-api-key: k123"), "{r0}");
        let body: Value = serde_json::from_str(&r0[r0.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        let rs = &body["resourceSpans"][0];
        assert!(rs["resource"]["attributes"].as_array().unwrap().iter().any(|a| a["key"] == "service.instance.id"));
        let span = &rs["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "seagent.gateway_health");
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert!(!r0.contains("private-profile"), "non-allowlisted fields dropped");
        assert!(reqs[1].contains("seagent.gateway_diagnostic") && reqs[1].contains("http_429"));
        assert_eq!(install_id(&t.paths.data), install_id(&t.paths.data), "install id is stable");
        assert!(status()["exporter"]["exported"].as_u64().unwrap() >= 1);
    }
}
