//! Long unattended task, end to end (gen1-305), on an accelerated clock.
//!
//! One task — "do 40 units of work" — run the way a multi-hour job really runs: a scripted
//! model (each step = one `work` tool call, priced like a real model), a task envelope with a
//! spend cap, `[limits]` resource caps, a provider outage that lasts hours, and two daemon
//! restarts. Virtual time only moves the daemon's retry clock ([`Daemon::retry_paused_at`]),
//! so the "hours" pass in milliseconds while everything else (the event log, the pause markers,
//! the envelope store, the kernel loop) is the production code.
//!
//! What it proves, in order:
//! 1. a provider outage pauses the task (state saved, nothing asked) and a *restarted* daemon
//!    resumes it once the backoff is due, continuing from the unit it stopped at;
//! 2. a resource cap pauses it at the start of the next turn and the daemon does **not**
//!    auto-retry that (it waits for a human), and the human resume continues the work;
//! 3. the task envelope's spend cap stops it for good — mid-turn, before the work is done.

use crate::config::{Config, Paths};
use crate::daemon::Daemon;
use crate::kernel::{EndReason, Kernel, RunOpts};
use crate::ledger::Price;
use ark_core::*;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One model "step": a `work` call, a failure, or the final text.
#[derive(Clone)]
enum Step {
    Work,
    Fail,
    Done,
}

/// The scripted model: 100k input + 10k output tokens per answer (≈ $0.14 at the test price).
struct Model {
    script: Mutex<VecDeque<Step>>,
    calls: AtomicUsize,
}

impl Provider for Model {
    fn id(&self) -> &str {
        "fake"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 1_000_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
    }
    fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        // Distinct inputs per call: a real task's steps differ (identical calls trip the
        // stuck-loop detector, which is right for a looping model).
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let usage = Usage { input_tokens: 100_000, output_tokens: 10_000, ..Default::default() };
        match self.script.lock().unwrap().pop_front().unwrap_or(Step::Done) {
            Step::Fail => Err(ProviderError::new(ProviderErrorKind::Overloaded, "upstream overloaded (scripted outage)").with_status(529)),
            Step::Work => Ok(ModelResponse { message: Message { role: Role::Assistant, content: vec![Block::ToolUse { id: format!("tu_{}", crate::util::random_hex(6)), name: "work".into(), input: json!({"step": n}) }] }, stop: StopReason::ToolUse, usage, model: "fake/m".into() }),
            Step::Done => Ok(ModelResponse { message: Message { role: Role::Assistant, content: vec![Block::text("batch finished")] }, stop: StopReason::EndTurn, usage, model: "fake/m".into() }),
        }
    }
}

struct Res(Arc<Model>);
impl crate::kernel::Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

/// The task's tool: one unit of work, counted on disk (the task's real output).
struct Work(std::path::PathBuf);
impl Tool for Work {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "work".into(), description: "do one unit of the task".into(), input_schema: json!({"type": "object"}), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, _: Value) -> ToolOutput {
        let n = units(&self.0) + 1;
        std::fs::write(&self.0, n.to_string()).unwrap();
        ToolOutput::ok(format!("unit {n} done"))
    }
}

fn units(p: &std::path::Path) -> u32 {
    std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// A daemon process "boot": a fresh kernel over the same data dir (what `arkd` does on start).
fn boot(paths: &Paths, model: &Arc<Model>, progress: &std::path::Path, f: impl FnOnce(&mut Config)) -> (Kernel, Daemon) {
    let mut cfg = Config::default();
    cfg.model.default = "fake/m".into();
    cfg.checkpoint.enabled = false;
    cfg.runner.max_retries = 0;
    cfg.runner.retry_base_ms = 1;
    cfg.runner.max_steps_per_turn = 1000;
    cfg.prices.insert("fake/m".into(), Price { input: 1.0, output: 4.0, cache_read: 0.0, cache_write: 0.0 });
    f(&mut cfg);
    let (pending, cell) = crate::daemon::pending_approver(Duration::from_secs(5));
    let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(Work(progress.to_path_buf()))];
    let k = crate::kernel::new_kernel(cfg, paths.clone(), Arc::new(Res(model.clone())), tools, Arc::new(crate::vault::Vault::empty()), pending.clone());
    let _ = cell.set(Arc::downgrade(&k));
    let d = Daemon::new(k.clone(), pending);
    (k, d)
}

/// Wait for the run the daemon started in the background (`Kernel::start`): it registers on
/// its own thread, so "not running" alone could be seen before it began — require that the
/// model was called again, then that the run is over.
fn wait_run(k: &Kernel, sid: &str, model: &Model, calls_before: usize) {
    let ok = ark_core::proc::wait_until(Duration::from_secs(10), || model.calls.load(Ordering::SeqCst) > calls_before && !k.is_running(sid));
    assert!(ok, "resumed run: calls {} -> {}, running {}, notices:\n{}", calls_before, model.calls.load(Ordering::SeqCst), k.is_running(sid), notices(k, sid));
}

fn notices(k: &Kernel, sid: &str) -> String {
    k.store.read(sid).unwrap_or_default().iter().filter_map(|e| match &e.kind { crate::event::EventKind::Notice { text, .. } => Some(text.clone()), _ => None }).collect::<Vec<_>>().join("\n")
}

#[test]
fn longtask_outage_restart_resource_pause_and_envelope_cost_cap() {
    let tmp = ark_core::tmp::TempDir::new("ark-longtask");
    let root = tmp.path();
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    std::fs::create_dir_all(&paths.data).unwrap();
    let progress = root.join("units.txt");
    let hour = 3_600_000u64;
    let mut vnow = crate::event::now_ms();

    // The whole job's model behaviour, as it will unfold over the "hours":
    //   10 units, then a 3-attempt outage, 10 units, end of batch (turn 1);
    //   turn 2 starts over the resource cap → paused before any model call;
    //   after the human resume: work until the envelope's spend cap stops it.
    let mut script: VecDeque<Step> = VecDeque::new();
    script.extend(std::iter::repeat_n(Step::Work, 10));
    script.extend([Step::Fail, Step::Fail, Step::Fail]);
    script.extend(std::iter::repeat_n(Step::Work, 10));
    script.push_back(Step::Done);
    script.extend(std::iter::repeat_n(Step::Work, 40));
    let model = Arc::new(Model { script: Mutex::new(script), calls: AtomicUsize::new(0) });

    // ── daemon #1: the task is opened with a task envelope (approved once, up front) ──
    let (k1, d1) = boot(&paths, &model, &progress, |_| {});
    let sid = k1.create_session(&ws, None, None, Some("long job")).unwrap();
    let env = ark_security::envelope::create(&paths.data, &ark_security::envelope::Spec { label: "nightly-batch".into(), session: Some(sid.clone()), ttl_ms: 24 * hour, max_tier: 1, spend_usd: Some(5.0), ceiling: ark_security::risk::Tier::from_u8(2), ..Default::default() }).unwrap();
    assert_eq!(env.spend_usd, Some(5.0));
    k1.submit(&sid, "do 40 units of work", "test").unwrap();
    let out = k1.run(&sid, RunOpts::default()).unwrap();
    assert!(matches!(&out.reason, EndReason::Paused(r) if r.contains("transient")), "outage pauses the task: {:?}", out.reason);
    assert_eq!(units(&progress), 10);
    let p = crate::limits::pause_info(&paths.data, &sid).expect("pause recorded");
    assert_eq!(p.kind, "transient");
    assert!(crate::limits::due_pauses(&paths.data, vnow).is_empty(), "not due before its backoff");
    drop((d1, k1)); // the daemon dies during the outage

    // ── daemon #2 (restart): the outage lasts; each due retry fails and backs off ──
    let (k2, d2) = boot(&paths, &model, &progress, |_| {});
    for _ in 0..2 {
        vnow += 2 * hour;
        let before = model.calls.load(Ordering::SeqCst);
        assert_eq!(d2.retry_paused_at(vnow), 1, "a due pause is retried by the restarted daemon");
        wait_run(&k2, &sid, &model, before);
        assert_eq!(units(&progress), 10, "no progress while the provider is down");
        assert!(crate::limits::pause_info(&paths.data, &sid).is_some());
    }
    drop((d2, k2));

    // ── daemon #3 (restart): the provider is back; the task continues where it stopped ──
    let (k3, d3) = boot(&paths, &model, &progress, |_| {});
    vnow += 6 * hour;
    let before = model.calls.load(Ordering::SeqCst);
    assert_eq!(d3.retry_paused_at(vnow), 1);
    wait_run(&k3, &sid, &model, before);
    assert_eq!(units(&progress), 20, "resumed from unit 10, not restarted from 0");
    assert!(crate::limits::pause_info(&paths.data, &sid).is_none(), "a successful answer clears the pause");
    let spent = crate::limits::session_spend(&k3, &sid);
    assert!(spent > 2.5 && spent < 5.0, "spend so far {spent}");
    drop((d3, k3));

    // ── daemon #4 with a resource cap below what the task already spent ──
    let (k4, d4) = boot(&paths, &model, &progress, |c| c.limits.per_agent_spend_usd = 2.0);
    let calls = model.calls.load(Ordering::SeqCst);
    k4.submit(&sid, "next batch", "test").unwrap();
    let out = k4.run(&sid, RunOpts::default()).unwrap();
    assert!(matches!(&out.reason, EndReason::Paused(r) if r.starts_with("limits")), "resource cap pauses: {:?}", out.reason);
    assert_eq!(model.calls.load(Ordering::SeqCst), calls, "paused before spending anything more");
    vnow += 12 * hour;
    assert_eq!(d4.retry_paused_at(vnow), 0, "a resource pause waits for a human, never auto-retried");
    drop((d4, k4));

    // ── a human raises the cap and resumes; the envelope's spend cap then stops the task ──
    let (k5, _d5) = boot(&paths, &model, &progress, |c| c.limits.per_agent_spend_usd = 50.0);
    assert!(crate::limits::resumed(&paths.data, &sid));
    let out = k5.run(&sid, RunOpts::default()).unwrap();
    assert!(matches!(&out.reason, EndReason::Budget(r) if r.contains("nightly-batch")), "envelope spend cap stops the task: {:?}", out.reason);
    let spent = crate::limits::session_spend(&k5, &sid);
    let done = units(&progress);
    assert!((5.0..5.0 + 0.2).contains(&spent), "stopped at the cap, not past it: ${spent:.2}");
    assert!(done > 20 && done < 60, "worked until the cap: {done} units");
    assert!(notices(&k5, &sid).contains("spend cap reached"), "{}", notices(&k5, &sid));
    assert!(crate::limits::pause_info(&paths.data, &sid).is_none(), "a cost-cap stop is not a pause: nothing will restart it");
    eprintln!("long task: {done} units, ${spent:.2} spent, {} model calls, {:.0} virtual hours", model.calls.load(Ordering::SeqCst), (vnow - crate::event::now_ms()) as f64 / hour as f64);
}
