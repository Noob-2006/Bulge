//! The dispatcher: one tick reclaims stale / crashed / timed-out runs, promotes
//! dependency-ready tasks, then claims ready (and review) tasks within the
//! concurrency budget and starts each as a kernel session whose kanban tools are
//! bound to that task. Workers are sessions inside the process that claimed them
//! (seagentd or `seagent kanban dispatch`); the run records the owner pid + start time so a
//! restarted daemon recognises (and recovers) runs whose owner is gone.

use super::boards;
use super::ops::{self, ClaimOpts, Failure};
use super::store::{self, BoardData, Task};
use super::{claimer_id, host_prefix, now, process_alive, workspaces_root, KanbanConfig};
use crate::kernel::{EndReason, Kernel, RunOpts};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Clean exits without a terminal board call get this many retries before tripping.
pub const PROTOCOL_VIOLATION_LIMIT: u32 = 3;
pub const PROTOCOL_VIOLATION_ERROR: &str = "worker exited cleanly without kanban_complete, kanban_block or kanban_request_review — protocol violation. If the prior run already did the work, verify it and report it via kanban_complete (or kanban_request_review); a run without a terminal kanban call counts as failed no matter what it did.";
const SUCCESS_WINDOW: i64 = 3600;
const PR_WINDOW: i64 = 86_400;
const STALE_HEARTBEAT_GAP: i64 = 3600;

// ───────────────────────── live worker registry ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Live {
    pub slug: String,
    pub task: String,
    pub run: u64,
    pub profile: Option<String>,
    pub lock: String,
}

static LIVE: Mutex<Option<HashMap<String, Live>>> = Mutex::new(None);

pub fn register_live(session: &str, l: Live) {
    LIVE.lock().unwrap().get_or_insert_with(HashMap::new).insert(session.into(), l);
}
pub fn unregister_live(session: &str) {
    if let Some(m) = LIVE.lock().unwrap().as_mut() {
        m.remove(session);
    }
}
pub fn live(session: &str) -> Option<Live> {
    LIVE.lock().unwrap().as_ref().and_then(|m| m.get(session).cloned())
}
fn live_sessions() -> Vec<String> {
    LIVE.lock().unwrap().as_ref().map(|m| m.keys().cloned().collect()).unwrap_or_default()
}

/// The dispatcher-assigned task of a worker session: the in-process registry, else
/// the durable record (a worker session resumed after a restart).
pub fn scope_for_session(data: &Path, session: &str) -> Option<Live> {
    if session.is_empty() {
        return None;
    }
    if let Some(l) = live(session) {
        return Some(l);
    }
    for m in boards::list_boards(data, false) {
        let Ok(b) = store::read_board(data, &m.slug) else { continue };
        for t in b.tasks.iter().filter(|t| t.status == "running") {
            if let Some(r) = t.current_run_id.and_then(|r| b.run(r)).filter(|r| r.worker_session.as_deref() == Some(session)) {
                return Some(Live { slug: m.slug.clone(), task: t.id.clone(), run: r.id, profile: r.profile.clone(), lock: t.claim_lock.clone().unwrap_or_default() });
            }
        }
    }
    None
}

/// Does the active claim protect a live worker? Ours: the session is registered.
/// Another process's: its owner is alive (a stale TTL alone is not proof of death).
pub fn claim_is_live(b: &BoardData, t: &Task) -> bool {
    if t.status != "running" || t.claim_lock.is_none() {
        return false;
    }
    let Some(run) = t.current_run_id.and_then(|r| b.run(r)) else { return false };
    let Some(sess) = &run.worker_session else { return false };
    if live(sess).is_some_and(|l| l.run == run.id) {
        return true;
    }
    match run.owner_pid {
        Some(p) if p != std::process::id() => process_alive(p, run.owner_birth),
        _ => false,
    }
}

// ───────────────────────── spawning ─────────────────────────

/// Everything a spawner needs to start one worker.
#[derive(Debug, Clone)]
pub struct Job {
    pub data: PathBuf,
    pub slug: String,
    pub task: Task,
    pub run_id: u64,
    pub workspace: PathBuf,
    pub lane: String,
    pub lock: String,
    pub cfg: KanbanConfig,
}

pub trait Spawner: Send + Sync {
    /// Start the worker for a claimed task; returns its session id.
    fn spawn(&self, job: &Job) -> Result<String, String>;
    fn is_running(&self, session: &str) -> bool;
    fn interrupt(&self, session: &str);
}

/// Workers as kernel sessions on background threads.
pub struct KernelSpawner {
    pub k: Kernel,
}

/// Provider/model for a worker: task override, else profile, else the default.
pub fn worker_model(cfg: &KanbanConfig, t: &Task) -> Option<String> {
    if let Some(m) = t.model_override.as_deref() {
        return Some(match t.provider_override.as_deref() {
            Some(p) if !m.starts_with(&format!("{p}/")) => format!("{p}/{m}"),
            _ => m.to_string(),
        });
    }
    t.assignee.as_deref().and_then(|a| cfg.profiles.get(a)).map(|p| p.model.clone()).filter(|m| !m.is_empty())
}

pub const WORKER_GUIDANCE: &str = "# Kanban task execution protocol
You have been assigned ONE task from the shared seagent Kanban board. The `kanban_*` tools are your coordination surface; they default to your task.

## Lifecycle
1. **Orient.** Call `kanban_show()` first (no args). It returns the task, parent handoffs, your prior attempts if this is a retry, the comment thread and a pre-formatted `worker_context` you can treat as ground truth.
2. **Work inside the workspace** (your session's working directory). Don't modify files outside it unless the task explicitly asks.
3. **Heartbeat on long operations.** Call `kanban_heartbeat(note=...)` every few minutes during long subprocesses. If your task may run longer than 1 hour you MUST heartbeat at least once an hour, or the dispatcher reclaims it.
4. **Block on genuine ambiguity.** If you need a human decision you cannot infer, call `kanban_block(reason=..., kind=...)` and stop. Don't guess.
5. **Finish with the structured handoff.** `kanban_complete(summary=..., metadata=..., artifacts=[...])` when done; when this same task needs review before it is final, `kanban_request_review(summary=..., reviewer=<optional>)`. A reviewer approves with `kanban_complete`, returns rework with `kanban_request_changes`. Never put secrets in durable fields.
6. **If follow-up work appears, create it; don't do it.** `kanban_create(title=..., assignee=<profile>, parents=[<your task id>])`, then list the returned ids in `kanban_complete(created_cards=[...])` — never invent ids.
7. **Flag collision hotspots** with `kanban_comment(body=\"hotspot: <path> — <reason>\")` instead of piling on.

A run that ends without `kanban_complete`, `kanban_block`, `kanban_schedule` or `kanban_request_review` counts as failed, whatever it did.";

/// The first message a worker receives.
pub fn worker_prompt(b: &BoardData, cfg: &KanbanConfig, t: &Task, lane: &str) -> String {
    let mut s = String::from(WORKER_GUIDANCE);
    if let Some(p) = t.assignee.as_deref().and_then(|a| cfg.profiles.get(a)).filter(|p| !p.instructions.trim().is_empty()) {
        s.push_str(&format!("\n\n## Profile instructions\n{}", p.instructions.trim()));
    }
    let mut skills: Vec<String> = t.assignee.as_deref().and_then(|a| cfg.profiles.get(a)).map(|p| p.skills.clone()).unwrap_or_default();
    skills.extend(t.skills.clone().unwrap_or_default());
    if lane == "review" {
        skills.push("sdlc-review".into());
        s.push_str("\n\n## You are the REVIEWER for this task\nInspect the implementer's handoff (latest review_requested run and comments). Approve with `kanban_complete(summary=...)`, or return concrete rework with `kanban_request_changes(reason=...)`.");
    }
    skills.dedup();
    if !skills.is_empty() {
        s.push_str(&format!("\n\nLoad these skills before working (if installed): {}.", skills.join(", ")));
    }
    if t.goal_mode {
        s.push_str("\n\nThis task runs in goal mode: after each turn a judge checks your work against the task; keep going until it is verifiably complete, then call kanban_complete with acceptance evidence.");
    }
    let ctx = super::context::build_worker_context(b, &t.id, now()).unwrap_or_default();
    s.push_str(&format!("\n\n---\n\n{ctx}"));
    s
}

fn log_line(data: &Path, slug: &str, task: &str, line: &str) {
    use std::io::Write;
    let p = super::worker_log_path(data, slug, task);
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "[{}] {line}", crate::util::fmt_time(now(), 480));
    }
}

/// How a worker session ended without a terminal board call.
#[derive(Debug, Clone, PartialEq)]
pub enum Exit {
    Clean(String),
    Interrupted,
    RateLimited(String),
    /// Provider rejected the credential/model: a retry cannot heal it.
    TerminalProvider(String),
    Failed(String),
}

pub fn classify_exit(r: &Result<crate::kernel::Outcome, String>) -> Exit {
    match r {
        Err(e) => Exit::Failed(e.clone()),
        Ok(o) => match &o.reason {
            EndReason::Done | EndReason::Idle => Exit::Clean(o.text.clone()),
            EndReason::Interrupted => Exit::Interrupted,
            EndReason::Error(e) => {
                let l = e.to_lowercase();
                if l.contains("ratelimited") || l.contains("rate limit") || l.contains("429") || l.contains("quota") {
                    Exit::RateLimited(e.clone())
                } else if l.contains("auth") && (l.contains("401") || l.contains("403") || l.contains("api key") || l.contains("auth:")) {
                    Exit::TerminalProvider(e.clone())
                } else {
                    Exit::Failed(e.clone())
                }
            }
            // C1/C2: a pause is not a failure — the task goes back to the queue with a delay
            // instead of being marked broken (the run's log is intact and resumes).
            EndReason::Paused(w) => Exit::RateLimited(w.clone()),
            other => Exit::Failed(other.label()),
        },
    }
}

/// Book a worker that ended while its task is still running on that run.
pub fn on_worker_exit(data: &Path, cfg: &KanbanConfig, slug: &str, task: &str, run: u64, exit: Exit) -> Result<(), String> {
    let r = store::with_board(data, slug, |b| {
        let Some(t) = b.task(task) else { return Ok(None) };
        if t.status != "running" || t.current_run_id != Some(run) {
            return Ok(None); // a terminal call (or the dispatcher) already settled it
        }
        let retry = ops::retry_status_for_run(b, task, Some(run));
        let release = |b: &mut BoardData| {
            let t = b.task_mut(task).unwrap();
            t.status = retry.clone();
            t.claim_lock = None;
            t.claim_expires = None;
            t.claim_owner = None;
            t.claim_token = None;
        };
        match &exit {
            Exit::Interrupted => {
                release(b);
                let rid = ops::end_run(b, task, "reclaimed", None, None, Some("worker interrupted"), None);
                b.append_event(task, "reclaimed", Some(json!({"reason": "interrupted", "retry_status": retry})), rid);
                Ok(Some("interrupted"))
            }
            Exit::RateLimited(e) => {
                release(b);
                let err = format!("worker exited rate-limited (quota wall) — requeued without counting a failure: {}", ops::first_line(Some(e), 300));
                let rid = ops::end_run(b, task, "rate_limited", None, None, Some(&err), None);
                b.append_event(task, "rate_limited", Some(json!({"retry_status": retry})), rid);
                b.task_mut(task).unwrap().last_failure_error = Some(err.chars().take(500).collect());
                Ok(Some("rate_limited"))
            }
            Exit::Clean(text) => {
                release(b);
                let out = ops::first_line(Some(text), 400);
                let err = if out.is_empty() { PROTOCOL_VIOLATION_ERROR.to_string() } else { format!("{PROTOCOL_VIOLATION_ERROR} Worker's last output: {out:?}") };
                let rid = ops::end_run(b, task, "crashed", None, None, Some(&err), Some(json!({"protocol_violation": true})));
                b.append_event(task, "protocol_violation", Some(json!({"protocol_violation": true, "worker_output": out, "retry_status": retry})), rid);
                b.task_mut(task).unwrap().last_failure_error = Some(err.chars().take(500).collect());
                let streak = protocol_violation_streak(b, task);
                let limit = b.task(task).unwrap().max_retries.unwrap_or(PROTOCOL_VIOLATION_LIMIT);
                if streak >= limit {
                    ops::record_failure(b, task, Failure { error: &err, outcome: "crashed", limit: Some(limit), force_trip: true, extra: Some(json!({"protocol_violations": streak, "protocol_violation_limit": limit})), ..Default::default() }, cfg.failure_limit);
                }
                Ok(Some("protocol_violation"))
            }
            Exit::TerminalProvider(e) | Exit::Failed(e) => {
                release(b);
                let err = format!("worker failed: {}", ops::first_line(Some(e), 400));
                let rid = ops::end_run(b, task, "crashed", None, None, Some(&err), None);
                b.append_event(task, "crashed", Some(json!({"error": err, "retry_status": retry})), rid);
                let terminal = matches!(exit, Exit::TerminalProvider(_));
                ops::record_failure(b, task, Failure { error: &err, outcome: "crashed", force_trip: terminal, extra: terminal.then(|| json!({"terminal_provider": true})), ..Default::default() }, cfg.failure_limit);
                Ok(Some("crashed"))
            }
        }
    })?;
    if let Some(k) = r {
        log_line(data, slug, task, &format!("run {run} ended without a terminal board call: {k}"));
    }
    Ok(())
}

fn protocol_violation_streak(b: &BoardData, task: &str) -> u32 {
    let mut runs: Vec<_> = b.runs_for(task).into_iter().filter(|r| r.ended_at.is_some()).collect();
    runs.sort_by_key(|r| std::cmp::Reverse(r.id));
    let mut n = 0;
    for r in runs.into_iter().take(50) {
        match r.outcome.as_deref() {
            Some("rate_limited") => continue,
            Some("crashed") if r.metadata.as_ref().is_some_and(|m| m["protocol_violation"] == true) => n += 1,
            _ => break,
        }
    }
    n
}

/// Worker threads started by [`KernelSpawner`], by session id (tests only).
#[cfg(test)]
static WORKERS: Mutex<Option<HashMap<String, std::thread::JoinHandle<()>>>> = Mutex::new(None);

/// Wait until the worker thread of `sid` has booked its exit (tests only).
#[cfg(test)]
pub(crate) fn join_worker(sid: &str) {
    let h = WORKERS.lock().unwrap_or_else(|e| e.into_inner()).as_mut().and_then(|m| m.remove(sid));
    if let Some(h) = h {
        let _ = h.join();
    }
}

impl Spawner for KernelSpawner {
    fn spawn(&self, job: &Job) -> Result<String, String> {
        let k = self.k.clone();
        let t = &job.task;
        let b = store::read_board(&job.data, &job.slug)?;
        let prompt = worker_prompt(&b, &job.cfg, t, &job.lane);
        let model = worker_model(&job.cfg, t);
        let title = format!("kanban {}: {}", t.id, t.title);
        let sid = k.create_session(&job.workspace, model.as_deref(), None, Some(&title)).map_err(|e| e.to_string())?;
        k.set_session_tools(&sid, super::tools::worker_tools(&job.cfg));
        register_live(&sid, Live { slug: job.slug.clone(), task: t.id.clone(), run: job.run_id, profile: t.assignee.clone(), lock: job.lock.clone() });
        if let Err(e) = k.submit(&sid, &prompt, "kanban") {
            unregister_live(&sid);
            k.set_session_tools(&sid, vec![]);
            return Err(e.to_string());
        }
        log_line(&job.data, &job.slug, &t.id, &format!("run {} started: session {sid} ({})", job.run_id, job.lane));
        let job = job.clone();
        let sid2 = sid.clone();
        let worker = std::thread::spawn(move || {
            let exit = run_worker(&k, &job, &sid2);
            unregister_live(&sid2);
            k.set_session_tools(&sid2, vec![]);
            k.end_session(&sid2, "kanban");
            if let Err(e) = on_worker_exit(&job.data, &job.cfg, &job.slug, &job.task.id, job.run_id, exit) {
                eprintln!("seagentd: kanban: booking worker exit for {}: {e}", job.task.id);
            }
        });
        // Tests join the worker (the exit booking writes the board *after* the card is done, which
        // would otherwise re-create a scratch tree the test had already removed).
        #[cfg(test)]
        WORKERS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(sid.clone(), worker);
        #[cfg(not(test))]
        drop(worker);
        Ok(sid)
    }
    fn is_running(&self, session: &str) -> bool {
        self.k.is_running(session) || live(session).is_some()
    }
    fn interrupt(&self, session: &str) {
        self.k.interrupt(session);
    }
}

fn still_owned(job: &Job) -> bool {
    store::read_board(&job.data, &job.slug).ok().and_then(|b| b.task(&job.task.id).map(|t| t.status == "running" && t.current_run_id == Some(job.run_id))).unwrap_or(false)
}

/// Run the worker session; goal-mode tasks loop under the judge until done, blocked or
/// out of turns.
fn run_worker(k: &Kernel, job: &Job, sid: &str) -> Exit {
    let budget = crate::ledger::Ledger::new(k.cfg.budget.clone());
    let max_turns = job.task.goal_max_turns.unwrap_or(job.cfg.goal_max_turns).max(1);
    let goal = format!("{}\n\n{}", job.task.title, job.task.body.clone().unwrap_or_default()).trim().to_string();
    let mut turns = 0;
    let mut nudged = false;
    loop {
        let r = k.run(sid, RunOpts { ledger: Some(budget.clone()), ..Default::default() }).map_err(|e| e.to_string());
        if let Ok(o) = &r {
            log_line(&job.data, &job.slug, &job.task.id, &format!("turn ended ({}): {}", o.reason.label(), ops::first_line(Some(&o.text), 300)));
        }
        let exit = classify_exit(&r);
        let Exit::Clean(text) = &exit else { return exit };
        if !job.task.goal_mode || !still_owned(job) {
            return exit;
        }
        turns += 1;
        let next = match super::llm::judge_goal(k, &goal, text) {
            Err(_) => return exit, // unreachable judge: single-shot semantics
            Ok((v, _)) if v == "done" => {
                if nudged {
                    return exit;
                }
                nudged = true;
                "The goal judge considers this task complete. Call `kanban_complete` now with a summary that cites the acceptance evidence.".to_string()
            }
            Ok((v, reason)) if v == "blocked" => {
                let _ = store::with_board(&job.data, &job.slug, |b| ops::block(b, &job.task.id, Some(&format!("goal judged unachievable: {reason}")), Some("needs_input"), Some(job.run_id)));
                return Exit::Clean(text.clone());
            }
            Ok((_, reason)) => {
                if turns >= max_turns {
                    let _ = store::with_board(&job.data, &job.slug, |b| ops::block(b, &job.task.id, Some(&format!("goal-turn budget exhausted ({max_turns} turns); last judge note: {reason}")), Some("needs_input"), Some(job.run_id)));
                    return Exit::Clean(text.clone());
                }
                format!("Not done yet (goal judge: {reason}). Keep working toward the task's acceptance criteria. Turns left: {}.", max_turns - turns)
            }
        };
        if k.submit(sid, &next, "kanban-goal").is_err() {
            return exit;
        }
    }
}

// ───────────────────────── the tick ─────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct DispatchResult {
    pub board: String,
    /// `Some(reason)` when the global emergency stop (`seagent pause` → `<data>/ESTOP`) held this
    /// pass: nothing was reclaimed, claimed, spawned or decomposed.
    pub paused: Option<String>,
    pub skipped_locked: bool,
    pub reclaimed: Vec<String>,
    pub extended: Vec<String>,
    pub stale: Vec<String>,
    pub crashed: Vec<String>,
    pub recovered: Vec<String>,
    pub timed_out: Vec<String>,
    pub auto_blocked: Vec<String>,
    pub promoted: u32,
    pub spawned: Vec<(String, String, String)>,
    pub spawn_failed: Vec<(String, String)>,
    pub respawn_guarded: Vec<(String, String)>,
    pub skipped_unassigned: Vec<String>,
    pub skipped_nonspawnable: Vec<String>,
    pub skipped_per_profile_capped: Vec<String>,
    pub auto_assigned_default: Vec<String>,
    pub memory_pressure: Option<String>,
    pub decomposed: Vec<String>,
}

#[derive(Clone, Default)]
pub struct TickOpts {
    pub dry_run: bool,
    /// Don't spawn (OpenClaw `workboard_dispatch`: data-only advance).
    pub no_spawn: bool,
    pub max_spawn: Option<usize>,
    pub failure_limit: Option<u32>,
}

struct TickLock(std::fs::File);
impl TickLock {
    fn try_take(path: &Path) -> Option<TickLock> {
        std::fs::create_dir_all(path.parent()?).ok()?;
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path).ok()?;
        // Non-blocking flock(LOCK_EX | LOCK_NB) on Unix, LockFileEx on Windows.
        f.try_lock().is_ok().then_some(TickLock(f))
    }
}
impl Drop for TickLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// (MemTotal, MemAvailable) in kB.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn mem_sample() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let get = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok());
    Some((get("MemTotal:")?, get("MemAvailable:")?))
}

/// (total, available) in kB from the platform layer; `None` where the OS reports no
/// available-memory figure (macOS), which reads as "unknown" pressure.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mem_sample() -> Option<(u64, u64)> {
    use seagent_core::platform::sysinfo;
    Some((sysinfo::total_memory()? / 1024, sysinfo::available_memory()? / 1024))
}
/// MemTotal / 512 MiB clamped to 2..=8; None when unknown.
pub fn derived_max_in_progress() -> Option<usize> {
    mem_sample().map(|(t, _)| ((t / 1024 / 512) as usize).clamp(2, 8))
}
pub fn memory_pressure() -> &'static str {
    match mem_sample() {
        None => "unknown",
        Some((t, a)) => {
            let f = a as f64 / t.max(1) as f64;
            if a < 64 * 1024 || f < 0.05 {
                "critical"
            } else if a < 128 * 1024 || f < 0.15 {
                "elevated"
            } else {
                "ok"
            }
        }
    }
}

fn blocker_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"(?i)\b(quota|rate[\s_\-]?limit|429|403|auth|authenticat(?:e|es|ed|ing|ion)|authoriz(?:e|es|ed|ing|ation)|authoris(?:e|es|ed|ing|ation)|authz|unauthorized|forbidden|billing|subscription|access[\s_]denied|permission[\s_]denied|invalid[\s_]api[\s_]key)\b").unwrap())
}
fn pr_url_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"(?i)https?://github\.com/[^/\s]+/[^/\s]+/pull/\d+").unwrap())
}

/// A reason not to (re)spawn `id` right now, or None.
pub fn respawn_guard(b: &BoardData, id: &str, lane: &str, cfg: &KanbanConfig) -> Option<&'static str> {
    let t = b.task(id)?;
    let n = now();
    let latest = b.runs_for(id).into_iter().filter(|r| r.ended_at.is_some()).max_by_key(|r| (r.ended_at, r.id));
    let cool = cfg.rate_limit_cooldown_secs;
    if let Some(r) = latest {
        if r.outcome.as_deref() == Some("spawn_failed") && cool > 0 && r.metadata.as_ref().is_some_and(|m| m["infrastructure"] == true) && n - r.ended_at.unwrap() < cool {
            return Some("infrastructure_cooldown");
        }
        if r.outcome.as_deref() == Some("rate_limited") {
            return (cool > 0 && n - r.ended_at.unwrap() < cool).then_some("rate_limit_cooldown");
        }
    }
    if let Some(e) = t.last_failure_error.as_deref() {
        if latest.and_then(|r| r.outcome.as_deref()) != Some("crashed") && blocker_re().is_match(e) {
            return Some("blocker_auth");
        }
    }
    if lane == "review" {
        return None;
    }
    let success = b.runs_for(id).into_iter().filter(|r| r.outcome.as_deref() == Some("completed")).filter_map(|r| r.ended_at).filter(|e| *e >= n - SUCCESS_WINDOW).max();
    if let Some(s) = success {
        if !b.events_for(id).iter().any(|e| e.created_at >= s && matches!(e.kind.as_str(), "status" | "promoted" | "unblocked" | "reclaimed" | "promoted_manual" | "unarchived")) {
            return Some("recent_success");
        }
    }
    let pr_times: Vec<i64> = b.comments_for(id).into_iter().filter(|c| c.created_at >= n - PR_WINDOW && pr_url_re().is_match(&c.body)).map(|c| c.created_at).collect();
    if let Some(last) = pr_times.iter().max() {
        let handoff = b.events_for(id).iter().any(|e| {
            e.created_at > *last
                && match e.kind.as_str() {
                    "assigned" => e.payload.as_ref().is_some_and(|p| p["source"] != "kanban.default_assignee" && p.get("from").is_some() && p["assignee"].as_str().is_some_and(|to| p["from"].as_str() != Some(to))),
                    "changes_requested" | "review_reopened" => true,
                    _ => false,
                }
        });
        if !handoff {
            return Some("active_pr");
        }
    }
    None
}

/// Resolve (and create) a claimed task's workspace.
pub fn resolve_workspace(data: &Path, slug: &str, t: &Task) -> Result<(PathBuf, Option<String>), String> {
    match t.workspace_kind.as_str() {
        "dir" => {
            let p = PathBuf::from(t.workspace_path.as_deref().ok_or("dir workspace requires an absolute workspace_path")?);
            if !p.is_absolute() {
                return Err(format!("workspace_path must be absolute, got {}", p.display()));
            }
            std::fs::create_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            Ok((p, None))
        }
        "worktree" => {
            let meta = boards::read_meta(data, slug);
            let repo = meta.default_workdir.clone().map(PathBuf::from);
            let p = match t.workspace_path.as_deref() {
                Some(p) => PathBuf::from(p),
                None => repo.clone().ok_or("worktree workspace needs workspace_path or the board's default workdir")?.join(".worktrees").join(&t.id),
            };
            if !p.is_absolute() {
                return Err(format!("workspace_path must be absolute, got {}", p.display()));
            }
            let branch = t.branch_name.clone().unwrap_or_else(|| format!("wt/{}", t.id));
            if p.join(".git").exists() {
                return Ok((p, Some(branch)));
            }
            let repo = repo.or_else(|| p.ancestors().skip(1).find(|a| a.join(".git").exists()).map(Path::to_path_buf)).ok_or_else(|| format!("no git repository found for worktree {}", p.display()))?;
            let git = |args: &[&str]| seagent_core::platform::proc::command("git").arg("-C").arg(&repo).args(args).output();
            let exists = git(&["rev-parse", "--verify", "--quiet", &format!("refs/heads/{branch}")]).map(|o| o.status.success()).unwrap_or(false);
            let ps = p.to_string_lossy().to_string();
            let out = if exists { git(&["worktree", "add", &ps, &branch]) } else { git(&["worktree", "add", "-b", &branch, &ps]) }.map_err(|e| format!("git: {e}"))?;
            if !out.status.success() {
                return Err(format!("git worktree add failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
            }
            Ok((p, Some(branch)))
        }
        _ => {
            let p = match t.workspace_path.as_deref() {
                Some(p) => PathBuf::from(p),
                None => workspaces_root(data, slug).join(&t.id),
            };
            std::fs::create_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            Ok((p, None))
        }
    }
}

fn interrupt_all(sp: &dyn Spawner, sessions: Vec<String>) {
    for s in sessions {
        sp.interrupt(&s);
    }
}

/// Reclaim phase: TTL-expired claims, stale runs, crashed / owner-less runs, timeouts.
fn reclaim_phase(data: &Path, slug: &str, cfg: &KanbanConfig, sp: &dyn Spawner, limit: u32, res: &mut DispatchResult) -> Result<(), String> {
    let me = std::process::id();
    let hp = host_prefix();
    let mut kill: Vec<String> = vec![];
    store::with_board(data, slug, |b| {
        let n = now();
        let running: Vec<String> = b.tasks.iter().filter(|t| t.status == "running").map(|t| t.id.clone()).collect();
        for id in running {
            let t = b.task(&id).unwrap().clone();
            let run = t.current_run_id.and_then(|r| b.run(r)).cloned();
            let session = run.as_ref().and_then(|r| r.worker_session.clone());
            let host_local = t.claim_lock.as_deref().is_some_and(|l| l.starts_with(&hp));
            let ours = run.as_ref().is_some_and(|r| r.owner_pid == Some(me));
            let ours_live = ours && session.as_deref().is_some_and(|s| sp.is_running(s));
            let other_live = !ours && run.as_ref().is_some_and(|r| r.owner_pid.is_some_and(|p| process_alive(p, r.owner_birth)));
            let started = run.as_ref().map(|r| r.started_at).or(t.started_at).unwrap_or(n);
            let hb_stale = t.last_heartbeat_at.is_some_and(|h| n - h > cfg.heartbeat_max_stale_secs);
            let retry = ops::retry_status_for_run(b, &id, None);
            let requeue = |b: &mut BoardData| {
                let t = b.task_mut(&id).unwrap();
                t.status = retry.clone();
                t.claim_lock = None;
                t.claim_expires = None;
                t.claim_owner = None;
                t.claim_token = None;
                t.last_heartbeat_at = None;
            };
            // 1. Max runtime (per attempt, measured from the active run).
            if let Some(maxrt) = t.max_runtime_seconds.filter(|_| host_local && (ours_live || ours)) {
                let elapsed = n - started;
                if elapsed >= maxrt {
                    kill.extend(session.clone());
                    requeue(b);
                    let p = json!({"elapsed_seconds": elapsed, "limit_seconds": maxrt, "retry_status": retry, "session": session});
                    let err = format!("elapsed {elapsed}s > limit {maxrt}s");
                    let rid = ops::end_run(b, &id, "timed_out", None, None, Some(&err), Some(p.clone()));
                    b.append_event(&id, "timed_out", Some(p), rid);
                    res.timed_out.push(id.clone());
                    if ops::record_failure(b, &id, Failure { error: &err, outcome: "timed_out", ..Default::default() }, limit) {
                        res.auto_blocked.push(id.clone());
                    }
                    continue;
                }
            }
            // 2. Owner recovery / crash sweep (host-local claims only; other hosts' pids say nothing).
            if host_local && n - started >= cfg.crash_grace_secs {
                if ours && !ours_live {
                    requeue(b);
                    let err = "worker session is no longer running (lost without an exit report)";
                    let rid = ops::end_run(b, &id, "crashed", None, None, Some(err), None);
                    b.append_event(&id, "crashed", Some(json!({"error": err, "session": session, "retry_status": retry})), rid);
                    res.crashed.push(id.clone());
                    if ops::record_failure(b, &id, Failure { error: err, outcome: "crashed", ..Default::default() }, limit) {
                        res.auto_blocked.push(id.clone());
                    }
                    continue;
                }
                if !ours && !other_live && run.as_ref().is_some_and(|r| r.owner_pid.is_some()) {
                    // The owning process is gone (restart, OOM): nothing can still be executing
                    // this attempt except a session this process resumed — stop that one first.
                    if let Some(s) = session.as_deref().filter(|s| sp.is_running(s)) {
                        kill.push(s.to_string());
                    }
                    requeue(b);
                    let rid = ops::end_run(b, &id, "reclaimed", None, None, Some("owner process exited"), None);
                    b.append_event(&id, "owner_recovered", Some(json!({"owner_pid": run.as_ref().and_then(|r| r.owner_pid), "session": session, "retry_status": retry})), rid);
                    res.recovered.push(id.clone());
                    continue;
                }
            }
            // 3. Stale: running long with no heartbeat progress (no failure penalty).
            if cfg.stale_timeout_secs > 0 && n - started > cfg.stale_timeout_secs && t.last_heartbeat_at.is_none_or(|h| n - h > STALE_HEARTBEAT_GAP) && (ours || !other_live) {
                kill.extend(session.clone());
                requeue(b);
                let rid = ops::end_run(b, &id, "stale", None, None, Some("no heartbeat progress"), None);
                b.append_event(&id, "stale", Some(json!({"running_seconds": n - started, "last_heartbeat_at": t.last_heartbeat_at, "retry_status": retry})), rid);
                super::notify::push(b, &id, "stale", "Run went stale (no heartbeat progress) and was requeued.", rid, vec![]);
                res.stale.push(id.clone());
                continue;
            }
            // 4. Expired claim TTL.
            if t.claim_expires.is_some_and(|e| e < n) {
                if (ours_live || other_live) && !hb_stale {
                    let e = n + cfg.claim_ttl_secs;
                    let was = t.claim_expires;
                    ops::heartbeat_claim(b, &id, None, cfg.claim_ttl_secs);
                    b.append_event(&id, "claim_extended", Some(json!({"reason": "worker_alive", "claim_expires_was": was, "claim_expires_now": e, "last_heartbeat_at": t.last_heartbeat_at})), t.current_run_id);
                    res.extended.push(id.clone());
                    continue;
                }
                if ours_live {
                    kill.extend(session.clone());
                }
                requeue(b);
                let err = format!("stale_lock={}", t.claim_lock.as_deref().unwrap_or(""));
                let rid = ops::end_run(b, &id, "reclaimed", None, None, Some(&err), None);
                b.append_event(&id, "reclaimed", Some(json!({"stale_lock": t.claim_lock, "claim_expires": t.claim_expires, "last_heartbeat_at": t.last_heartbeat_at, "heartbeat_stale": hb_stale, "retry_status": retry})), rid);
                res.reclaimed.push(id.clone());
                if ops::record_failure(b, &id, Failure { error: &err, outcome: "reclaimed", ..Default::default() }, limit) {
                    res.auto_blocked.push(id.clone());
                }
            }
        }
        res.promoted = ops::recompute_ready(b, limit);
        Ok(())
    })?;
    interrupt_all(sp, kill);
    Ok(())
}

fn count_running_all(data: &Path) -> usize {
    boards::list_boards(data, false).iter().filter_map(|m| store::read_board(data, &m.slug).ok()).map(|b| b.tasks.iter().filter(|t| t.status == "running").count()).sum()
}

/// The global emergency stop (`seagent pause` writes `<data>/ESTOP`; `seagent resume` removes it).
/// Read through `seagent_security::estop`, exactly as the scheduler, goals, cron and channel
/// turns read it, so `seagent pause` holds new board work too. `Some(result)` = skip this pass.
fn estop_result(data: &Path, board: &str) -> Option<DispatchResult> {
    let (reason, _) = seagent_security::estop::state(data)?;
    let tag = reason.map(|r| format!(" ({r})")).unwrap_or_default();
    Some(DispatchResult { board: board.into(), paused: Some(format!("seagent is paused{tag}: no board work was dispatched. `seagent resume` lifts it.")), ..Default::default() })
}

/// One dispatcher pass over one board.
pub fn tick_board(data: &Path, slug: &str, cfg: &KanbanConfig, sp: &dyn Spawner, o: &TickOpts) -> Result<DispatchResult, String> {
    if let Some(r) = estop_result(data, slug) {
        return Ok(r);
    }
    let mut res = DispatchResult { board: slug.into(), ..Default::default() };
    let Some(_lock) = TickLock::try_take(&super::board_dir(data, slug).join("dispatch.lock")) else {
        res.skipped_locked = true;
        return Ok(res);
    };
    let limit = o.failure_limit.unwrap_or(cfg.failure_limit);
    if !o.dry_run {
        reclaim_phase(data, slug, cfg, sp, limit, &mut res)?;
    }
    if o.no_spawn {
        return Ok(res);
    }
    let meta = boards::read_meta(data, slug);
    if meta.kind == "sessions" || meta.archived {
        return Ok(res);
    }
    // Budget: per-board max_spawn counts this board's running tasks; max_in_progress is host-wide.
    let b = store::read_board(data, slug)?;
    let running_here = b.tasks.iter().filter(|t| t.status == "running").count();
    let mut budget: Option<usize> = None;
    if let Some(m) = o.max_spawn.or(cfg.max_spawn) {
        if running_here >= m {
            return Ok(res);
        }
        budget = Some(m - running_here);
    }
    if let Some(m) = cfg.max_in_progress.or_else(derived_max_in_progress) {
        let total = count_running_all(data);
        if total >= m {
            return Ok(res);
        }
        budget = Some(budget.map_or(m - total, |x| x.min(m - total)));
    }
    match memory_pressure() {
        "critical" => {
            res.memory_pressure = Some("critical".into());
            return Ok(res);
        }
        "elevated" => {
            res.memory_pressure = Some("elevated".into());
            budget = Some(budget.map_or(1, |x| x.min(1)));
        }
        _ => {}
    }
    let lane_rows = |b: &BoardData, st: &str| {
        let mut v: Vec<(String, Option<String>, i64, i64)> = b.tasks.iter().filter(|t| t.status == st && t.claim_lock.is_none()).map(|t| (t.id.clone(), t.assignee.clone(), t.priority, t.created_at)).collect();
        v.sort_by_key(|r| (std::cmp::Reverse(r.2), r.3));
        v
    };
    let ready = lane_rows(&b, "ready");
    let review = if cfg.review_dispatch { lane_rows(&b, "review") } else { vec![] };
    let mut per_profile: HashMap<String, usize> = HashMap::new();
    for t in b.tasks.iter().filter(|t| t.status == "running") {
        if let Some(a) = &t.assignee {
            *per_profile.entry(a.clone()).or_insert(0) += 1;
        }
    }
    let default_assignee = meta.orchestration.default_assignee.clone().filter(|s| !s.is_empty()).or_else(|| Some(cfg.default_assignee.clone()).filter(|s| !s.is_empty())).filter(|a| cfg.profile_exists(a));
    // Reserve one slot for a spawnable reviewer so review never starves behind ready work.
    let reviewer_waiting = review.iter().any(|(id, a, _, _)| a.as_deref().is_some_and(|a| cfg.profile_exists(a) && cfg.max_in_progress_per_profile.is_none_or(|c| per_profile.get(a).copied().unwrap_or(0) < c)) && respawn_guard(&b, id, "review", cfg).is_none());
    let ready_budget = match budget {
        Some(x) if x > 0 && reviewer_waiting => Some(x - 1),
        x => x,
    };
    let mut spawned = 0usize;
    let rows: Vec<(String, Option<String>, &str)> = ready.into_iter().map(|(i, a, _, _)| (i, a, "ready")).chain(review.into_iter().map(|(i, a, _, _)| (i, a, "review"))).collect();
    for (id, assignee, lane) in rows {
        let cap = if lane == "ready" { ready_budget } else { budget };
        if cap.is_some_and(|c| spawned >= c) {
            if lane == "ready" {
                continue;
            }
            break;
        }
        let assignee = match assignee {
            Some(a) => a,
            None if lane == "ready" => match &default_assignee {
                Some(d) => {
                    if !o.dry_run {
                        let d2 = d.clone();
                        store::with_board(data, slug, |b| {
                            if let Some(t) = b.task_mut(&id).filter(|t| t.assignee.is_none()) {
                                t.assignee = Some(d2.clone());
                                b.append_event(&id, "assigned", Some(json!({"assignee": d2, "source": "kanban.default_assignee"})), None);
                            }
                            Ok(())
                        })?;
                    }
                    res.auto_assigned_default.push(id.clone());
                    d.clone()
                }
                None => {
                    res.skipped_unassigned.push(id.clone());
                    continue;
                }
            },
            None => {
                res.skipped_unassigned.push(id.clone());
                continue;
            }
        };
        if !cfg.profile_exists(&assignee) {
            res.skipped_nonspawnable.push(id.clone());
            if !o.dry_run {
                store::with_board(data, slug, |b| {
                    let p = json!({"assignee": assignee});
                    let dup = b.events.iter().rev().find(|e| e.task_id == id).is_some_and(|e| e.kind == "skipped_nonspawnable" && e.payload.as_ref() == Some(&p));
                    if !dup {
                        b.append_event(&id, "skipped_nonspawnable", Some(p), None);
                    }
                    Ok(())
                })?;
            }
            continue;
        }
        if let Some(c) = cfg.max_in_progress_per_profile {
            if per_profile.get(&assignee).copied().unwrap_or(0) >= c {
                res.skipped_per_profile_capped.push(id.clone());
                continue;
            }
        }
        let b = store::read_board(data, slug)?;
        if let Some(g) = respawn_guard(&b, &id, lane, cfg) {
            res.respawn_guarded.push((id.clone(), g.into()));
            if !o.dry_run {
                store::with_board(data, slug, |b| {
                    b.append_event(&id, "respawn_guarded", Some(json!({"reason": g})), None);
                    Ok(())
                })?;
            }
            continue;
        }
        if o.dry_run {
            res.spawned.push((id.clone(), assignee.clone(), String::new()));
            spawned += 1;
            *per_profile.entry(assignee).or_insert(0) += 1;
            continue;
        }
        let lock = claimer_id();
        let claimed = store::with_board(data, slug, |b| Ok(ops::claim(b, &id, ClaimOpts { lock: &lock, ttl: cfg.claim_ttl_secs, lane, owner: None, token: None }).map(|r| (r, b.task(&id).unwrap().clone()))))?;
        let Some((run_id, task)) = claimed else { continue };
        let ws = resolve_workspace(data, slug, &task);
        let (ws, branch) = match ws {
            Ok(w) => w,
            Err(e) => {
                let blocked = store::with_board(data, slug, |b| Ok(ops::record_failure(b, &id, Failure { error: &format!("workspace: {e}"), outcome: "spawn_failed", release_claim: true, end_run: true, ..Default::default() }, limit)))?;
                res.spawn_failed.push((id.clone(), e));
                if blocked {
                    res.auto_blocked.push(id.clone());
                }
                continue;
            }
        };
        let mut task = task;
        task.workspace_path = Some(ws.display().to_string());
        let job = Job { data: data.into(), slug: slug.into(), task: task.clone(), run_id, workspace: ws.clone(), lane: lane.into(), lock: lock.clone(), cfg: cfg.clone() };
        // Record the workspace first: the worker's context names it.
        store::with_board(data, slug, |b| {
            if let Some(t) = b.task_mut(&id) {
                t.workspace_path = Some(ws.display().to_string());
                if branch.is_some() {
                    t.branch_name = branch.clone();
                }
            }
            Ok(())
        })?;
        match sp.spawn(&job) {
            Ok(sid) => {
                store::with_board(data, slug, |b| {
                    if let Some(r) = b.run_mut(run_id) {
                        r.worker_session = Some(sid.clone());
                    }
                    b.append_event(&id, "spawned", Some(json!({"session": sid, "workspace": ws, "lane": lane, "owner_pid": std::process::id()})), Some(run_id));
                    Ok(())
                })?;
                res.spawned.push((id.clone(), assignee.clone(), ws.display().to_string()));
                spawned += 1;
                *per_profile.entry(assignee).or_insert(0) += 1;
            }
            Err(e) => {
                let blocked = store::with_board(data, slug, |b| Ok(ops::record_failure(b, &id, Failure { error: &e, outcome: "spawn_failed", release_claim: true, end_run: true, ..Default::default() }, limit)))?;
                res.spawn_failed.push((id.clone(), e));
                if blocked {
                    res.auto_blocked.push(id.clone());
                }
            }
        }
    }
    let _ = live_sessions();
    Ok(res)
}

/// One pass over every active board, plus notification delivery and auto-decompose.
pub fn tick_all(k: &Kernel, cfg: &KanbanConfig, o: &TickOpts) -> Vec<DispatchResult> {
    super::attach(k);
    let data = k.paths.data.clone();
    // `seagent pause` (`<data>/ESTOP`) stops new work everywhere: no claim, no spawn, no
    // auto-decompose, no notification wake-ups. In-flight workers are left alone.
    if let Some(r) = estop_result(&data, "*") {
        return vec![r];
    }
    let sp = KernelSpawner { k: k.clone() };
    let mut out = vec![];
    for m in boards::list_boards(&data, false) {
        let mut r = match tick_board(&data, &m.slug, cfg, &sp, o) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("seagentd: kanban [{}]: {e}", m.slug);
                continue;
            }
        };
        let auto = m.orchestration.auto_decompose.unwrap_or(cfg.auto_decompose);
        if auto && !o.dry_run && !o.no_spawn {
            let per = m.orchestration.auto_decompose_per_dispatch.map(|n| n as usize).unwrap_or(cfg.auto_decompose_per_tick).max(1);
            if let Ok(b) = store::read_board(&data, &m.slug) {
                for id in b.tasks.iter().filter(|t| t.status == "triage").map(|t| t.id.clone()).take(per) {
                    let out = super::llm::decompose_task(k, &data, &m.slug, cfg, &id, None);
                    if out.ok {
                        r.decomposed.push(id);
                    }
                }
            }
        }
        let k2 = k.clone();
        let wake = move |sess: &str, text: &str| -> Result<(), String> {
            if !k2.store.exists(sess) {
                return Err(format!("no session {sess}"));
            }
            k2.submit(sess, text, "kanban").map_err(|e| e.to_string())?;
            if !k2.is_running(sess) {
                let _ = k2.start(sess, Default::default());
            }
            Ok(())
        };
        if let Err(e) = super::notify::deliver(&data, &m.slug, &wake) {
            eprintln!("seagentd: kanban [{}] notify: {e}", m.slug);
        }
        out.push(r);
    }
    out
}

/// seagentd scheduler hook: tick every `dispatch_interval_secs` when `[kanban]` is enabled.
pub fn daemon_tick(k: &Kernel) {
    static LAST: Mutex<Option<std::time::Instant>> = Mutex::new(None);
    let cfg = &k.cfg.kanban;
    if !cfg.enabled || !cfg.dispatch {
        return;
    }
    {
        let mut last = LAST.lock().unwrap();
        if last.is_some_and(|l| l.elapsed() < std::time::Duration::from_secs(cfg.dispatch_interval_secs.max(1))) {
            return;
        }
        *last = Some(std::time::Instant::now());
    }
    let (k2, cfg) = (k.clone(), cfg.clone());
    // Off the scheduler thread: a slow GitHub read or git worktree must not delay cron.
    static BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let _ = tick_all(&k2, &cfg, &TickOpts::default());
        BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    });
}

/// Fake spawner for tests and dry runs: records jobs, sessions "run" until finished.
#[derive(Default)]
pub struct RecordingSpawner {
    pub jobs: Mutex<Vec<Job>>,
    pub running: Mutex<Vec<String>>,
    pub interrupted: Mutex<Vec<String>>,
    pub fail: Mutex<Option<String>>,
}
impl Spawner for RecordingSpawner {
    fn spawn(&self, job: &Job) -> Result<String, String> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        let sid = format!("sess-{}-{}", job.task.id, job.run_id);
        register_live(&sid, Live { slug: job.slug.clone(), task: job.task.id.clone(), run: job.run_id, profile: job.task.assignee.clone(), lock: job.lock.clone() });
        self.running.lock().unwrap().push(sid.clone());
        self.jobs.lock().unwrap().push(job.clone());
        Ok(sid)
    }
    fn is_running(&self, session: &str) -> bool {
        self.running.lock().unwrap().iter().any(|s| s == session)
    }
    fn interrupt(&self, session: &str) {
        self.interrupted.lock().unwrap().push(session.into());
        self.running.lock().unwrap().retain(|s| s != session);
        unregister_live(session);
    }
}
impl RecordingSpawner {
    /// Simulate the worker session ending.
    pub fn finish(&self, session: &str) {
        self.running.lock().unwrap().retain(|s| s != session);
        unregister_live(session);
    }
}

pub type SharedSpawner = Arc<dyn Spawner>;

#[cfg(test)]
mod tests;
