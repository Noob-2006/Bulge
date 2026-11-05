//! Model-facing cron management and the richer job features behind it (Hermes
//! `tools/cronjob_tools.py`, `cron/scheduler_prompt.py`, `cron/scheduler_script.py`; OpenClaw
//! `src/agents/tools/cron-tool*.ts`).
//!
//! The scheduler itself stays in `automation.rs` (`Job`, `claim_due`, `run_job`). This module
//! adds the per-job extras (`JobExt`, flattened into `Job`): name, repeat count, skills,
//! pre-run script / `no_agent`, delivery target, chaining (`context_from` / `continuity`),
//! pause reason, payload kind (agent turn vs. system event) and self-pacing; the prompt
//! assembly with threat scanning; delivery of results; and the two tools
//! (`cronjob_manage`, `automations`) plus `/loop`, `/subgoal`, `/suggestions`.

pub mod chronos;
pub mod incidents;
pub mod schedule;
pub mod script;
pub mod slash;
pub mod suggestions;
pub mod tool;

use crate::automation::{jobs_path, read_list, with_list, Job};
use crate::config::Config;
use crate::kernel::{Kernel, Runtime};
use crate::ledger::Budget;
use crate::outbound::{self, Payload, Target};
use crate::util::{new_id, unix_now};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::Duration;

pub use tool::{tools, Automations, CronjobManage};

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Extra job fields (all optional; old `schedules.json` files load unchanged).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JobExt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human schedule (`every 30m`, `once in 2h`, `weekdays at 9am`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// Run this many times, then disable (None = forever; one-shots are 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeat: Option<u32>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub runs: u32,
    /// Ordered skill names loaded before the prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
    /// Pre-run script under `<data>/scripts/` (stdout injected into the prompt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// The script IS the job: no model call; non-empty stdout is delivered verbatim.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_agent: bool,
    /// Outbound target grammar (`local`, `origin`, `<channel>[:<chat>[:<thread>]]`, webhook URL),
    /// comma-combinable. None = `origin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliver: Option<String>,
    /// Override target for failure notices only (`local` suppresses them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_deliver: Option<String>,
    /// Job ids whose latest output is injected each run (`self` = this job: continuity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<String>,
    /// Session the job was created from (for `origin` delivery and `/loop status`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// OpenClaw payload kind: `agentTurn` (default) or `systemEvent` (queues a wake event).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `now` | `next-heartbeat` for systemEvent jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_mode: Option<String>,
    /// Self-paced loops: `next_check` clamps to [min, max] seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pacing: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// Latest completed output (for continuity / context_from), capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_output: Option<String>,
    /// `ok` | `error` | `silent` | `skipped` | `blocked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_delivery: Option<String>,
}

const LAST_OUTPUT_CAP: usize = 8000;

/// Knobs read from `Config` once, so tools need no kernel at construction.
#[derive(Debug, Clone)]
pub struct Settings {
    pub offset: i32,
    pub threat_scan: bool,
    pub script_timeout: Duration,
    pub default_model: String,
    /// `[automation] allow_agent_scheduling` (default true): cron runs may manage jobs.
    pub allow_in_cron: bool,
}

impl Settings {
    pub fn from_config(cfg: &Config) -> Settings {
        let a = &cfg.automation;
        Settings {
            offset: cfg.schedule.utc_offset_minutes,
            threat_scan: cfg.security.threat_scan.cron,
            script_timeout: Duration::from_secs(a.get("script_timeout_seconds").and_then(|v| v.as_integer()).filter(|n| *n > 0).map(|n| n as u64).unwrap_or(script::DEFAULT_TIMEOUT_SECS)),
            default_model: cfg.model.default.clone(),
            allow_in_cron: a.get("allow_agent_scheduling").and_then(|v| v.as_bool()).unwrap_or(true),
        }
    }
}

/// What a create/update call asks for (tool, `/loop`, suggestions, CLI).
#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub prompt: Option<String>,
    pub schedule: Option<String>,
    /// Pre-parsed schedule (OpenClaw structured form); wins over `schedule`.
    pub sched: Option<schedule::Sched>,
    pub name: Option<String>,
    pub repeat: Option<u32>,
    pub deliver: Option<String>,
    pub failure_deliver: Option<String>,
    pub skills: Option<Vec<String>>,
    pub script: Option<String>,
    pub no_agent: Option<bool>,
    pub context_from: Option<Vec<String>>,
    pub continuity: Option<bool>,
    pub workdir: Option<String>,
    pub model: Option<String>,
    pub paused: bool,
    pub paused_reason: Option<String>,
    pub origin: Option<String>,
    pub kind: Option<String>,
    pub wake_mode: Option<String>,
    pub pacing: Option<(u64, u64)>,
    /// Reuse one session for every run (`/loop`: the current chat session).
    pub session: Option<String>,
    pub budget: Option<Budget>,
}

/// Validate a delivery target string (comma-combined) without resolving `origin`.
pub fn validate_deliver(s: &str) -> Result<(), String> {
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part == "all" {
            continue;
        }
        let t = Target::parse(part)?;
        outbound::validate(&t)?;
    }
    Ok(())
}

/// Every create/update text input goes through the strict cron scan (Hermes `_scan_cron_prompt`).
fn scan(st: &Settings, text: &str) -> Result<(), String> {
    if st.threat_scan {
        if let Some(m) = seagent_security::threat::scan_cron_prompt(text) {
            return Err(m);
        }
    }
    Ok(())
}

pub fn resolve_workdir(w: &str, fallback: &Path) -> Result<PathBuf, String> {
    let w = w.trim();
    if w.is_empty() {
        return Ok(fallback.to_path_buf());
    }
    let p = seagent_core::expand_home(w);
    if !p.is_absolute() {
        return Err(format!("workdir must be an absolute existing path, got `{w}`"));
    }
    let p = p.canonicalize().map_err(|e| format!("workdir {w}: {e}"))?;
    if !p.is_dir() {
        return Err(format!("workdir {} is not a directory", p.display()));
    }
    Ok(p)
}

/// Create a job (Hermes `_action_create`).
pub fn create(data: &Path, st: &Settings, spec: Spec, ws: &Path) -> Result<Job, String> {
    let now = unix_now();
    let sched = match (spec.sched.clone(), spec.schedule.as_deref().map(str::trim).filter(|s| !s.is_empty())) {
        (Some(s), _) => s,
        (None, Some(s)) => schedule::parse(s, now, st.offset)?,
        (None, None) => return Err("schedule is required for create".into()),
    };
    let prompt = spec.prompt.clone().unwrap_or_default();
    let skills: Vec<String> = clean_list(spec.skills.clone().unwrap_or_default());
    let no_agent = spec.no_agent.unwrap_or(false);
    let script = spec.script.clone().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let system_event = spec.kind.as_deref() == Some("systemEvent");
    if no_agent {
        if script.is_none() {
            return Err("create with no_agent=True requires a script — the script is the job. In no_agent mode the LLM is skipped entirely: prompt and skills are ignored, non-empty stdout is delivered verbatim, empty stdout sends nothing (watchdog pattern), and a non-zero exit or timeout sends an error alert.".into());
        }
    } else if prompt.trim().is_empty() && skills.is_empty() {
        return Err(if system_event { "systemEvent payload requires text".into() } else { "create requires either prompt or at least one skill".into() });
    }
    if !prompt.is_empty() {
        scan(st, &prompt)?;
    }
    if let Some(s) = &script {
        if let Some(e) = script::validate_for_create(data, s) {
            return Err(e);
        }
    }
    for d in [&spec.deliver, &spec.failure_deliver].into_iter().flatten() {
        validate_deliver(d)?;
    }
    if spec.paused_reason.is_some() && !spec.paused {
        return Err("paused_reason requires paused=true".into());
    }
    let mut context_from = clean_list(spec.context_from.clone().unwrap_or_default());
    validate_context_refs(data, &context_from)?;
    if spec.continuity == Some(true) && !context_from.iter().any(|c| c == "self") {
        context_from.push("self".into());
    }
    let workspace = resolve_workdir(spec.workdir.as_deref().unwrap_or(""), ws)?;
    let repeat = spec.repeat.filter(|n| *n > 0).or(sched.once.then_some(1));
    let name = spec.name.clone().map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).or_else(|| Some(default_name(&prompt, &skills, script.as_deref())));
    let job = Job {
        id: new_id(),
        cron: sched.expr.clone(),
        prompt,
        workspace: workspace.to_string_lossy().into(),
        model: spec.model.clone().filter(|m| !m.trim().is_empty()),
        session: spec.session.clone(),
        enabled: !spec.paused,
        next_run: sched.first_run,
        last_run: None,
        last_session: None,
        last_result: None,
        budget: spec.budget.clone().unwrap_or_default(),
        ext: JobExt {
            name,
            display: Some(sched.display.clone()),
            repeat,
            skills,
            script,
            no_agent,
            deliver: spec.deliver.clone().filter(|d| !d.trim().is_empty()),
            failure_deliver: spec.failure_deliver.clone().filter(|d| !d.trim().is_empty()),
            context_from,
            paused_reason: spec.paused_reason.clone(),
            origin: spec.origin.clone(),
            kind: spec.kind.clone(),
            wake_mode: spec.wake_mode.clone(),
            pacing: spec.pacing,
            created_at: Some(now),
            ..Default::default()
        },
    };
    with_list(&jobs_path(data), |v: &mut Vec<Job>| v.push(job.clone()))?;
    chronos::jobs_changed(data);
    fire_changed(None, "added", &job, json!({"next_run_at_ms": job.next_run * 1000, "enabled": job.enabled}));
    Ok(job)
}

fn clean_list(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn default_name(prompt: &str, skills: &[String], script: Option<&str>) -> String {
    let p: String = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
    if !p.is_empty() {
        return p.chars().take(50).collect();
    }
    skills.first().cloned().or_else(|| script.map(String::from)).unwrap_or_else(|| "cron job".into())
}

fn validate_context_refs(data: &Path, refs: &[String]) -> Result<(), String> {
    if refs.is_empty() {
        return Ok(());
    }
    let jobs: Vec<Job> = read_list(&jobs_path(data))?;
    for r in refs.iter().filter(|r| r.as_str() != "self") {
        if !jobs.iter().any(|j| &j.id == r) {
            return Err(format!("context_from references unknown job '{r}' (list jobs first — never guess job IDs)"));
        }
    }
    Ok(())
}

/// Find a job by exact id, unique id prefix/suffix, or exact name.
pub fn find(data: &Path, r: &str) -> Result<Job, String> {
    let r = r.trim();
    if r.is_empty() {
        return Err("job_id is required".into());
    }
    let jobs: Vec<Job> = read_list(&jobs_path(data))?;
    if let Some(j) = jobs.iter().find(|j| j.id == r) {
        return Ok(j.clone());
    }
    let m: Vec<&Job> = jobs.iter().filter(|j| j.id.starts_with(r) || j.id.ends_with(r) || j.ext.name.as_deref() == Some(r)).collect();
    match m.len() {
        1 => Ok(m[0].clone()),
        0 => Err(format!("Job '{r}' not found. Use action='list' to see job IDs.")),
        _ => Err(format!("Job reference '{r}' is ambiguous ({} matches); use the full job_id.", m.len())),
    }
}

/// Update in place (Hermes `_action_update`): only given fields change; `""` / `[]` clear.
pub fn update(data: &Path, st: &Settings, id: &str, spec: Spec) -> Result<Job, String> {
    let now = unix_now();
    let sched = match (spec.sched.clone(), spec.schedule.as_deref().map(str::trim).filter(|s| !s.is_empty())) {
        (Some(s), _) => Some(s),
        (None, Some(s)) => Some(schedule::parse(s, now, st.offset)?),
        _ => None,
    };
    if let Some(p) = spec.prompt.as_deref().filter(|p| !p.is_empty()) {
        scan(st, p)?;
    }
    if let Some(s) = spec.script.as_deref().filter(|s| !s.trim().is_empty()) {
        if let Some(e) = script::validate_for_create(data, s) {
            return Err(e);
        }
    }
    for d in [&spec.deliver, &spec.failure_deliver].into_iter().flatten().filter(|d| !d.trim().is_empty()) {
        validate_deliver(d)?;
    }
    if let Some(c) = &spec.context_from {
        validate_context_refs(data, &clean_list(c.clone()))?;
    }
    let ws = spec.workdir.as_deref().filter(|w| !w.trim().is_empty()).map(|w| resolve_workdir(w, Path::new("/"))).transpose()?;
    let r = with_list(&jobs_path(data), |v: &mut Vec<Job>| -> Result<Job, String> {
        let j = v.iter_mut().find(|j| j.id == id).ok_or_else(|| format!("Job '{id}' not found"))?;
        if let Some(s) = &sched {
            j.cron = s.expr.clone();
            j.next_run = s.first_run;
            j.ext.display = Some(s.display.clone());
            if s.once {
                j.ext.repeat = Some(1);
                j.ext.runs = 0;
            }
        }
        if let Some(p) = &spec.prompt {
            j.prompt = p.clone();
        }
        if let Some(n) = &spec.name {
            j.ext.name = Some(n.trim().to_string()).filter(|n| !n.is_empty());
        }
        if let Some(r) = spec.repeat {
            j.ext.repeat = (r > 0).then_some(r);
        }
        if let Some(d) = &spec.deliver {
            j.ext.deliver = Some(d.trim().to_string()).filter(|d| !d.is_empty());
        }
        if let Some(d) = &spec.failure_deliver {
            j.ext.failure_deliver = Some(d.trim().to_string()).filter(|d| !d.is_empty());
        }
        if let Some(s) = &spec.skills {
            j.ext.skills = clean_list(s.clone());
        }
        if let Some(s) = &spec.script {
            j.ext.script = Some(s.trim().to_string()).filter(|s| !s.is_empty());
        }
        if let Some(n) = spec.no_agent {
            j.ext.no_agent = n;
        }
        if let Some(c) = &spec.context_from {
            j.ext.context_from = clean_list(c.clone());
        }
        match spec.continuity {
            Some(true) if !j.ext.context_from.iter().any(|c| c == "self") => j.ext.context_from.push("self".into()),
            Some(false) => j.ext.context_from.retain(|c| c != "self"),
            _ => {}
        }
        if let Some(w) = &ws {
            j.workspace = w.to_string_lossy().into();
        }
        if let Some(m) = &spec.model {
            j.model = Some(m.trim().to_string()).filter(|m| !m.is_empty());
        }
        if j.ext.no_agent && j.ext.script.is_none() {
            return Err("no_agent=True requires a script".into());
        }
        if !j.ext.no_agent && j.prompt.trim().is_empty() && j.ext.skills.is_empty() {
            return Err("a job needs a prompt or at least one skill".into());
        }
        Ok(j.clone())
    })??;
    chronos::jobs_changed(data);
    fire_changed(None, "updated", &r, json!({"next_run_at_ms": r.next_run * 1000, "enabled": r.enabled}));
    Ok(r)
}

/// Pause / resume with an auditable reason. Resuming a one-shot whose time passed fires it soon.
pub fn set_paused(data: &Path, id: &str, paused: bool, reason: Option<&str>) -> Result<Job, String> {
    let r = with_list(&jobs_path(data), |v: &mut Vec<Job>| -> Result<Job, String> {
        let j = v.iter_mut().find(|j| j.id == id).ok_or_else(|| format!("Job '{id}' not found"))?;
        j.enabled = !paused;
        j.ext.paused_reason = if paused { Some(reason.unwrap_or("paused").to_string()) } else { None };
        if !paused && j.next_run < unix_now() {
            j.next_run = unix_now();
        }
        Ok(j.clone())
    })??;
    chronos::jobs_changed(data);
    fire_changed(None, "updated", &r, json!({"paused": paused, "next_run_at_ms": r.next_run * 1000, "enabled": r.enabled}));
    Ok(r)
}

/// Hermes `_format_job` (model-facing view).
pub fn format_job(j: &Job, offset: i32) -> Value {
    let repeat = match j.ext.repeat {
        None => "forever".to_string(),
        Some(1) => if j.ext.runs == 0 { "once".into() } else { "1/1".into() },
        Some(n) => if j.ext.runs > 0 { format!("{}/{n}", j.ext.runs) } else { format!("{n} times") },
    };
    let preview: String = if j.prompt.chars().count() > 100 { format!("{}...", j.prompt.chars().take(100).collect::<String>()) } else { j.prompt.clone() };
    let state = if j.enabled { "scheduled" } else if j.ext.paused_reason.is_some() { "paused" } else if j.ext.repeat.is_some_and(|r| j.ext.runs >= r) { "completed" } else { "disabled" };
    let mut v = json!({
        "job_id": j.id,
        "name": j.ext.name.clone().unwrap_or_else(|| default_name(&j.prompt, &j.ext.skills, j.ext.script.as_deref())),
        "skills": j.ext.skills,
        "prompt_preview": preview,
        "model": j.model,
        "pinned": j.model.as_deref().is_some_and(|m| !m.trim().is_empty()),
        "schedule": j.ext.display.clone().unwrap_or_else(|| j.cron.clone()),
        "cron": j.cron,
        "repeat": repeat,
        "deliver": j.ext.deliver.clone().unwrap_or_else(|| "origin".into()),
        "next_run_at": if j.enabled { Value::String(crate::util::fmt_time(j.next_run, offset)) } else { Value::Null },
        "last_run_at": j.last_run.map(|t| crate::util::fmt_time(t, offset)),
        "last_status": j.ext.last_status,
        "last_result": j.last_result,
        "last_delivery": j.ext.last_delivery,
        "enabled": j.enabled,
        "state": state,
        "paused_reason": j.ext.paused_reason,
        "workdir": j.workspace,
    });
    for (k, val) in [("script", json!(j.ext.script)), ("failure_deliver", json!(j.ext.failure_deliver)), ("kind", json!(j.ext.kind)), ("session", json!(j.session))] {
        if !val.is_null() {
            v[k] = val;
        }
    }
    if j.ext.no_agent {
        v["no_agent"] = json!(true);
    }
    if !j.ext.context_from.is_empty() {
        v["context_from"] = json!(j.ext.context_from.iter().filter(|c| c.as_str() != "self").collect::<Vec<_>>());
        v["continuity"] = json!(j.ext.context_from.iter().any(|c| c == "self"));
    }
    v
}

// ───────────────────────── hook triggers ─────────────────────────

static HOOK_RT: RwLock<Option<Weak<Runtime>>> = RwLock::new(None);

/// Give the cron paths a runtime to fire `cron_changed` / `cron_reconciled` through. The host
/// calls this from [`chronos::install`] (which `wire::attach` runs once the kernel exists), so
/// every process that can create or fire a job — CLI, daemon, app — reports the same events.
pub fn attach(k: &Kernel) {
    *HOOK_RT.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(k));
}

/// The runtime attached by [`attach`], if this process still has it.
pub fn attached() -> Option<Kernel> {
    HOOK_RT.read().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(Weak::upgrade)
}

/// The payload for one job action (OpenClaw `PluginHookCronChangedEvent` shape).
pub fn changed_payload(action: &str, job: &Job, extra: Value) -> Value {
    let view = format_job(job, 0);
    crate::hooks::cron_changed_payload(action, &job.id, Some(&view), extra)
}

/// Fire `cron_changed` for a job mutation (added | updated | removed | started | finished).
/// `None` as the runtime means "the process-wide one"; a missing runtime is a no-op, never an
/// error — hooks are observers and must not be able to break scheduling.
pub fn fire_changed(rt: Option<&Runtime>, action: &str, job: &Job, extra: Value) {
    let owned;
    let rt = match rt {
        Some(r) => Some(r),
        None => {
            owned = attached();
            owned.as_deref()
        }
    };
    if let Some(r) = rt {
        crate::hooks::fire_cron_changed(r, changed_payload(action, job, extra));
    }
}

/// Fire `cron_reconciled` (the scheduler loaded its job set): `reason` is `startup` or `reload`.
pub fn fire_reconciled(rt: Option<&Runtime>, reason: &str, enabled: bool, jobs: usize) {
    let owned;
    let rt = match rt {
        Some(r) => Some(r),
        None => {
            owned = attached();
            owned.as_deref()
        }
    };
    if let Some(r) = rt {
        crate::hooks::fire_cron_reconciled(r, reason, enabled, jobs);
    }
}

/// Announce the loaded job set for `k` (host startup, or a scheduler reload).
pub fn reconciled(k: &Kernel, reason: &str) -> usize {
    let jobs: Vec<Job> = read_list(&jobs_path(&k.paths.data)).unwrap_or_default();
    let enabled = !seagent_security::estop::is_engaged(&k.paths.data) && !chronos::owns_ticks(&k.paths.data);
    let n = jobs.iter().filter(|j| j.enabled).count();
    crate::hooks::fire_cron_reconciled(k, reason, enabled, n);
    jobs.len()
}

// ───────────────────────── running ─────────────────────────

/// Hermes `_CRON_HINT`, adapted to seagent's tool names.
pub const CRON_HINT: &str = "[IMPORTANT: You are running as a scheduled cron job. DELIVERY: Your final response will be automatically delivered to the user — do NOT use channel_send or try to deliver the output yourself. Just produce your report/output as your final response and the system handles the rest. SILENT: If there is genuinely nothing new to report, respond with exactly \"[SILENT]\" (nothing else) to suppress delivery. [SILENT] is a literal ASCII control token — never translate or rephrase it, whatever language the rest of your answer uses. Never combine [SILENT] with content — either report your findings normally, or say [SILENT] and nothing more. FAILURE: If a delegated child fails and this cron run must be recorded as failed, put [CRON_FAILURE] on the first line by itself, then explain the child failure on following lines. RECURSION: This is a run of an EXISTING scheduled job — execute the task now. NEVER create or update a cron job because of recurring or future-schedule language in the task prompt below; treat phrasing like \"each Monday\" or \"every day at 9\" as context for this run, not as a request to schedule another job.]\n\n";
pub const SILENT: &str = "[SILENT]";
pub const FAILURE_MARK: &str = "[CRON_FAILURE]";

/// What a claimed job does this time.
#[derive(Debug, Clone, PartialEq)]
pub enum Prepared {
    /// Run the agent with this prompt.
    Agent(String),
    /// `no_agent`: deliver this text (empty = nothing); `ok=false` → failure alert.
    Direct { ok: bool, text: String },
    /// Nothing to do this tick (empty script output, `wakeAgent:false`).
    Skip(String),
    /// Blocked by the threat scanner (job is auto-paused).
    Blocked(String),
    /// OpenClaw systemEvent: queued as a wake event.
    SystemEvent(String),
}

fn context_block(heading: &str, intro: &str, body: &str, prompt: &str) -> String {
    format!("## {heading}\n{intro}\n\n```\n{body}\n```\n\n{prompt}")
}

/// Build the effective run (Hermes `_build_job_prompt` + `_scan_assembled_cron_prompt`).
/// `extra` is per-fire context from `run` (never persisted).
pub fn prepare(data: &Path, skills_dirs: &[PathBuf], st: &Settings, job: &Job, extra: Option<&str>, redact: &dyn Fn(&str) -> String) -> Prepared {
    let ws = PathBuf::from(&job.workspace);
    if job.ext.kind.as_deref() == Some("systemEvent") {
        let mode = job.ext.wake_mode.as_deref().unwrap_or("now");
        return match crate::wake::request(data, &job.prompt, mode, &format!("cron:{}", job.id)) {
            Ok(_) => Prepared::SystemEvent(format!("queued system event ({mode})")),
            Err(e) => Prepared::Direct { ok: false, text: e },
        };
    }
    if job.ext.no_agent {
        let Some(s) = &job.ext.script else { return Prepared::Direct { ok: false, text: "no_agent job has no script".into() } };
        let (ok, out) = script::run(data, s, Some(&ws), st.script_timeout, redact);
        if ok && !script::wake_gate(&out) {
            return Prepared::Skip("script gate returned wakeAgent=false".into());
        }
        return Prepared::Direct { ok, text: out };
    }
    let mut user_prompt = job.prompt.clone();
    // The job's own notepad rides every prompt (empty note = byte-identical prompt).
    let note = incidents::render_section(data, &job.id);
    if !note.is_empty() {
        user_prompt = format!("{note}{user_prompt}");
    }
    if let Some(e) = extra.filter(|e| !e.trim().is_empty()) {
        user_prompt = format!("{user_prompt}\n\n## Run Context\n{e}");
    }
    let mut prompt = user_prompt.clone();
    let mut injected = false;
    if let Some(s) = &job.ext.script {
        let (ok, out) = script::run(data, s, Some(&ws), st.script_timeout, redact);
        if ok && out.is_empty() {
            return Prepared::Skip("script produced no output".into());
        }
        if ok && !script::wake_gate(&out) {
            return Prepared::Skip("script gate returned wakeAgent=false".into());
        }
        prompt = if ok {
            context_block("Script Output", "The following data was collected by a pre-run script. Use it as context for your analysis.", &out, &prompt)
        } else {
            context_block("Script Error", "The data-collection script failed. Report this to the user.", &out, &prompt)
        };
        injected = true;
    }
    if !job.ext.context_from.is_empty() {
        let jobs: Vec<Job> = read_list(&jobs_path(data)).unwrap_or_default();
        let mut blocks = String::new();
        for r in &job.ext.context_from {
            let (label, out) = if r == "self" {
                ("this job's previous run".to_string(), job.ext.last_output.clone())
            } else {
                match jobs.iter().find(|j| &j.id == r) {
                    Some(j) => (format!("job '{}' ({})", j.ext.name.clone().unwrap_or_default(), j.id), j.ext.last_output.clone()),
                    None => continue,
                }
            };
            if let Some(o) = out.filter(|o| !o.trim().is_empty() && o.trim() != SILENT) {
                blocks.push_str(&format!("## Output from {label}\n```\n{o}\n```\n\n"));
            }
        }
        if !blocks.is_empty() {
            prompt = format!("{blocks}{prompt}");
            injected = true;
        }
    }
    let prompt = format!("{CRON_HINT}{prompt}");
    if job.ext.skills.is_empty() {
        // User prompt + hint only → strict; injected data → loose on the whole, strict on the user part.
        if st.threat_scan {
            let err = if injected {
                let (_, e) = seagent_security::threat::scan_cron_skill_assembled(&prompt);
                e.or_else(|| seagent_security::threat::scan_cron_prompt(&user_prompt))
            } else {
                seagent_security::threat::scan_cron_prompt(&user_prompt)
            };
            if let Some(e) = err {
                return Prepared::Blocked(e);
            }
            if injected {
                return Prepared::Agent(seagent_security::threat::scan_cron_skill_assembled(&prompt).0);
            }
        }
        return Prepared::Agent(prompt);
    }
    let parts = skill_parts(skills_dirs, &job.ext.skills);
    let assembled = format!("{parts}\n\nThe user has provided the following instruction alongside the skill invocation: {prompt}");
    if st.threat_scan {
        let (clean, err) = seagent_security::threat::scan_cron_skill_assembled(&assembled);
        if let Some(e) = err {
            return Prepared::Blocked(e);
        }
        return Prepared::Agent(clean);
    }
    Prepared::Agent(assembled)
}

/// Skill bodies in the Hermes `_load_cron_skill_parts` shape; missing ones get a notice.
pub fn skill_parts(dirs: &[PathBuf], names: &[String]) -> String {
    let found = crate::context::discover_skills(dirs);
    let mut parts: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for n in names {
        let key = n.trim_start_matches('/');
        let Some((name, _, path)) = found.iter().find(|(name, _, _)| name.eq_ignore_ascii_case(key)) else {
            skipped.push(n.clone());
            continue;
        };
        let body = std::fs::read_to_string(path).unwrap_or_default();
        let body = match body.strip_prefix("---").and_then(|r| r.find("\n---").map(|e| r[e + 4..].to_string())) {
            Some(b) => b,
            None => body,
        };
        if !parts.is_empty() {
            parts.push(String::new());
        }
        parts.push(format!("[IMPORTANT: The user has invoked the \"{name}\" skill, indicating they want you to follow its instructions. The full skill content is loaded below.]\n\n{}", body.trim()));
    }
    if !skipped.is_empty() {
        let s = skipped.join(", ");
        parts.insert(0, format!("[IMPORTANT: The following skill(s) were listed for this job but could not be found and were skipped: {s}. Start your response with a brief notice so the user is aware, e.g.: '⚠️ Skill(s) not found and skipped: {s}']"));
    }
    parts.join("\n")
}

/// The chat a session belongs to, from the channel router's bindings (`origin` delivery).
pub fn resolve_origin(data: &Path, session: &str) -> Option<Target> {
    let text = std::fs::read_to_string(data.join("channels/routes.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let (key, _) = v.get("routes")?.as_object()?.iter().find(|(_, s)| s.as_str() == Some(session))?;
    let mut p = key.split('\u{1f}');
    let name = p.next()?.to_string();
    let chat = p.next()?.to_string();
    Some(Target::Channel { name, chat: Some(chat), thread: None })
}

/// Concrete targets for a job's `deliver` (or `failure_deliver`) string.
pub fn targets(data: &Path, job: &Job, failure: bool) -> Vec<Target> {
    let raw = if failure { job.ext.failure_deliver.clone().or_else(|| job.ext.deliver.clone()) } else { job.ext.deliver.clone() };
    let raw = raw.unwrap_or_else(|| "origin".into());
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part {
            "all" => out.extend(outbound::channels().into_iter().map(|name| Target::Channel { name, chat: None, thread: None })),
            "origin" => {
                if let Some(t) = job.ext.origin.as_deref().and_then(|s| resolve_origin(data, s)) {
                    out.push(t);
                }
            }
            p => {
                if let Ok(t) = Target::parse(p) {
                    if t != Target::Local {
                        out.push(t);
                    }
                }
            }
        }
    }
    out.dedup();
    out
}

/// Deliver a run's text (`[SILENT]` / empty → nothing). Returns the receipt line.
pub fn deliver_result(data: &Path, job: &Job, text: &str, failure: bool) -> Option<String> {
    let t = text.trim();
    if t.is_empty() || t == SILENT {
        return None;
    }
    let ts = targets(data, job, failure);
    if ts.is_empty() {
        return None;
    }
    let name = job.ext.name.clone().unwrap_or_else(|| job.id.clone());
    let event = if failure { "cron.failed" } else { "cron.finished" };
    let body = if failure { format!("⚠ Cron job '{name}' failed\n\n{t}") } else { t.to_string() };
    let payload = Payload::new(event, body).with_data(json!({"job_id": job.id, "name": name}));
    let receipts: Vec<String> = ts.iter().map(|tg| match outbound::deliver(tg, &payload) {
        Ok(r) => r,
        Err(e) => format!("delivery to {} failed: {e}", tg.render()),
    }).collect();
    Some(receipts.join("; "))
}

/// Latest `n` run records of a job, newest first (`{at, started_at, ended_at, duration_ms,
/// status, summary, error, delivery}`; first-generation lines carry `output` instead).
pub fn runs(data: &Path, id: &str, n: usize) -> Vec<Value> {
    incidents::runs(data, id, n)
}

/// Start times of in-flight attempts (job id → unix seconds), so [`record`] can stamp the run's
/// duration even though the scheduler hands us only the outcome.
fn start_times() -> &'static Mutex<HashMap<String, i64>> {
    static S: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Mark the start of one attempt (called by [`pre_run`], i.e. on every execution path).
pub fn begin_run(id: &str) -> i64 {
    let now = unix_now();
    start_times().lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), now);
    now
}

/// Record the outcome on the job (status, capped output, delivery receipt), its run log and the
/// failure bookkeeping (streak → incident). Returns the incident alert when one opened.
pub fn record(data: &Path, id: &str, status: &str, output: Option<&str>, delivery: Option<String>) -> Option<String> {
    record_with(data, id, status, output, delivery, None)
}

/// [`record`] with the error text kept apart from the summary.
pub fn record_with(data: &Path, id: &str, status: &str, output: Option<&str>, delivery: Option<String>, error: Option<&str>) -> Option<String> {
    let now = unix_now();
    let started = start_times().lock().unwrap_or_else(|e| e.into_inner()).remove(id).unwrap_or(now);
    let out = output.map(|o| crate::util::head_tail(o, LAST_OUTPUT_CAP).0);
    let mut run = incidents::Run::new(id, started, now, status);
    let summary = out.as_deref().map(|o| crate::util::head_tail(o, 500).0);
    run.summary = summary.clone();
    run.output = summary.clone();
    run.error = error.map(|e| crate::util::head_tail(e, incidents::MAX_ERROR_CHARS).0).or_else(|| if incidents::failed(status) { summary.clone() } else { None });
    run.delivery = delivery.clone();
    let alert = incidents::record_run(data, &run);
    let _ = with_list(&jobs_path(data), |v: &mut Vec<Job>| {
        if let Some(j) = v.iter_mut().find(|j| j.id == id) {
            j.ext.last_status = Some(status.to_string());
            if let Some(o) = &out {
                j.ext.last_output = Some(o.clone());
            }
            if delivery.is_some() {
                j.ext.last_delivery = delivery.clone();
            }
        }
    });
    alert
}

/// Auto-pause a job the scanner blocked (Hermes `_block_and_pause_job`).
pub fn block_and_pause(data: &Path, id: &str, reason: &str) {
    let _ = set_paused(data, id, true, Some(&format!("Auto-paused by scheduler: {reason}")));
    record_with(data, id, "blocked", Some(reason), None, Some(reason));
}

/// Run a job that is not handled by the agent loop, or return the prompt for the agent.
/// Shared by `automation::run_job`.
pub fn pre_run(k: &Kernel, job: &Job, extra: Option<&str>) -> Prepared {
    let st = Settings::from_config(&k.cfg);
    let ws = PathBuf::from(&job.workspace);
    let vault = k.vault.clone();
    begin_run(&job.id);
    fire_changed(Some(k), "started", job, json!({"run_at_ms": unix_now() * 1000, "session_id": job.session, "model": job.model}));
    let p = prepare(&k.paths.data, &k.paths.skills_dirs(&ws), &st, job, extra, &move |t: &str| vault.redact(t));
    let data = &k.paths.data;
    match &p {
        Prepared::Direct { ok, text } => {
            let d = deliver_result(data, job, text, !ok);
            let status = if *ok { if text.trim().is_empty() { "silent" } else { "ok" } } else { "error" };
            let alert = record_with(data, &job.id, status, Some(text), d, (!ok).then_some(text.as_str()));
            finish_hook(k, job, status, (!ok).then_some(text.as_str()), alert);
        }
        Prepared::Skip(why) => {
            record(data, &job.id, "skipped", None, Some(why.clone()));
            finish_hook(k, job, "skipped", Some(why), None);
        }
        Prepared::Blocked(why) => {
            block_and_pause(data, &job.id, why);
            let _ = deliver_result(data, job, &format!("Blocked by the cron prompt scanner and paused: {why}"), true);
            finish_hook(k, job, "blocked", Some(why), None);
        }
        Prepared::SystemEvent(_) => {
            record(data, &job.id, "ok", None, None);
            finish_hook(k, job, "ok", None, None);
        }
        Prepared::Agent(_) => {}
    }
    p
}

/// One `cron_changed` `finished` event (status, error, incident alert).
fn finish_hook(k: &Kernel, job: &Job, status: &str, error: Option<&str>, alert: Option<String>) {
    let mut extra = json!({"status": status, "completion_status": if incidents::failed(status) { "failed" } else { "succeeded" }, "next_run_at_ms": job.next_run * 1000});
    if let Some(e) = error {
        extra["error"] = json!(crate::util::head_tail(e, 500).0);
    }
    if let Some(a) = alert {
        extra["incident"] = json!(a);
        extra["alert"] = json!(true);
    }
    fire_changed(Some(k), "finished", job, extra);
}

/// After an agent run: record and deliver (Hermes `[SILENT]` / `[CRON_FAILURE]` semantics).
pub fn post_run(k: &Kernel, job: &Job, outcome: Result<&crate::kernel::Outcome, &str>) {
    let data = &k.paths.data;
    match outcome {
        Ok(o) => {
            let text = o.text.trim();
            let failed = !o.reason.ok() || text.lines().next().map(str::trim) == Some(FAILURE_MARK);
            let body = text.strip_prefix(FAILURE_MARK).map(str::trim_start).unwrap_or(text);
            let d = if failed && !o.reason.ok() { deliver_result(data, job, &format!("{}\n{body}", o.reason.label()), true) } else { deliver_result(data, job, body, failed) };
            let status = if failed { "error" } else if body == SILENT || body.is_empty() { "silent" } else { "ok" };
            let err: Option<String> = failed.then(|| if o.reason.ok() { body.to_string() } else { format!("{}\n{body}", o.reason.label()) });
            let alert = record_with(data, &job.id, status, Some(body), d, err.as_deref());
            finish_hook(k, job, status, err.as_deref(), alert);
        }
        Err(e) => {
            let d = deliver_result(data, job, e, true);
            let alert = record_with(data, &job.id, "error", Some(e), d, Some(e));
            finish_hook(k, job, "error", Some(e), alert);
        }
    }
}

/// Self-pacing (OpenClaw `next_check`): the job reusing `session` fires again after `secs`.
pub fn next_check(data: &Path, session: &str, secs: u64) -> Result<(String, u64), String> {
    with_list(&jobs_path(data), |v: &mut Vec<Job>| -> Result<(String, u64), String> {
        // The job running in this session: self-paced ones first, then the most recent run.
        let j = v
            .iter_mut()
            .filter(|j| j.session.as_deref() == Some(session) || j.last_session.as_deref() == Some(session))
            .max_by_key(|j| (j.ext.pacing.is_some(), j.last_run.unwrap_or(0)))
            .ok_or("cron next_check is only available to the currently running job")?;
        let (lo, hi) = j.ext.pacing.unwrap_or((60, 3600));
        let d = secs.clamp(lo.max(60), hi.max(lo.max(60)));
        j.next_run = unix_now() + d as i64;
        Ok((j.id.clone(), d))
    })?
}

/// One manual scheduler pass (`seagent schedule tick`): announce the loaded job set
/// (`cron_reconciled` = reload) and run everything that is due now. The daemon does the same in
/// its tick loop; this is the external-crontab/manual entry point.
pub fn tick(k: &Kernel) -> Result<(usize, Vec<String>), String> {
    let data = k.paths.data.clone();
    let seen = reconciled(k, "reload");
    if seagent_security::estop::is_engaged(&data) {
        return Err("paused by the emergency stop (`seagent resume` to continue)".into());
    }
    let due = crate::automation::claim_due(&data, unix_now(), k.cfg.schedule.utc_offset_minutes, &[])?;
    let mut out = Vec::new();
    for job in due {
        let r = crate::automation::run_job(k, &job);
        let status = find(&data, &job.id).ok().and_then(|j| j.ext.last_status.clone()).unwrap_or_else(|| if r.is_ok() { "ok".into() } else { "error".into() });
        let name = job.ext.name.clone().unwrap_or_else(|| job.prompt.chars().take(40).collect());
        out.push(format!("{}  {:<8} {name}", job.id, status));
        if let Err(e) = r {
            out.push(format!("    error: {e}"));
        }
    }
    Ok((seen, out))
}

/// Self-registration (`seagent_core::registry`): `cronjob_manage` (Hermes) and `automations`
/// (OpenClaw) over the one job store. The kernel no longer has to be named in the binary's
/// wiring file for these to appear.
pub fn register() {
    seagent_core::registry::register_tool_provider("cronjob", 200, |env| {
        let cfg = env.config::<Config>()?;
        Ok(tool::tools(cfg))
    });
}

#[cfg(test)]
pub(crate) mod tests;
