//! Scheduled tasks: `bulge schedule …`.
//!
//! A saved task is a full run spec (goal, workspace, model, VM shape) plus a
//! [`Schedule`](bulge_core::Schedule). `bulge schedule tick` runs every task that
//! is due — once, under a single-flight lock so a cron entry, a systemd timer and
//! a manual tick never double-fire — then reschedules it. A scheduled run is
//! autonomous and skips the learning loop (no human to benefit from the review);
//! its result lands in the job store as a reviewable diff, exactly like an
//! interactive run, so nothing is written back to the host without approval.

use std::path::{Path, PathBuf};

use bulge_core::cron::{Schedule, Weekday, next_occurrence};
use bulge_store::{Autonomy, Budget};
use serde::{Deserialize, Serialize};

use crate::backend::{BackendSpec, Protocol};
use crate::run::{self, RunConfig};
use bulge_util::now_secs as now_unix;

/// Where saved tasks live (under `~/.bulge`).
const STORE_FILE: &str = "schedule.json";
/// Single-flight lock for `tick`.
const LOCK_FILE: &str = "schedule.lock";

/// A persisted scheduled task: a run spec plus its schedule and runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedTask {
    pub id: String,
    pub title: String,
    pub goal: String,
    pub workspace: PathBuf,
    #[serde(default)]
    pub autonomy: Autonomy,
    // Backend (stored flat; `Protocol`/`BackendSpec` are not serializable).
    pub model: String,
    pub base_url: String,
    pub protocol: String,
    pub backend_id: String,
    pub context_window: u32,
    pub max_tokens: u32,
    pub reasoning: bool,
    // Budget.
    pub max_steps: u64,
    pub max_model_tokens: u64,
    pub max_secs: u64,
    // VM.
    pub network: bool,
    pub cpus: u8,
    pub ram_mib: u32,
    // Schedule + runtime state.
    pub schedule: Schedule,
    #[serde(default)]
    pub offset_minutes: i32,
    /// Stable anchor (creation time) for relative schedules, so cadence never drifts.
    pub anchor: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub next_run_at: Option<u64>,
    #[serde(default)]
    pub last_run_at: Option<u64>,
    #[serde(default)]
    pub runs: u32,
    /// For an `OnPathChange` schedule: the watched path's mtime last seen by a
    /// tick. The task is due when the path's current mtime differs from this.
    #[serde(default)]
    pub watch_mtime: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl SavedTask {
    /// Rebuild a one-shot `RunConfig` for this task (fresh job, autonomous review off).
    fn to_run_config(&self) -> Result<RunConfig, String> {
        let backend = BackendSpec {
            id: self.backend_id.clone(),
            base_url: self.base_url.clone(),
            protocol: Protocol::parse(&self.protocol)?,
            model: self.model.clone(),
            context_window: self.context_window,
            max_tokens: self.max_tokens,
            reasoning: self.reasoning,
        };
        Ok(RunConfig {
            title: self.title.clone(),
            autonomy: self.autonomy,
            budget: Budget { max_steps: self.max_steps, max_tokens: self.max_model_tokens, max_wall_secs: self.max_secs },
            network: self.network,
            cpus: self.cpus,
            ram_mib: self.ram_mib,
            // A scheduled run has no human to read a review fork.
            skip_review: true,
            // Unattended automation gets the tighter envelope: vet mutating calls.
            auto_review: true,
            host_integrations: true,
            ..RunConfig::new(self.goal.clone(), self.workspace.clone(), backend)?
        })
    }
}

/// The task store, persisted as one JSON file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskStore {
    #[serde(default)]
    pub tasks: Vec<SavedTask>,
}

impl TaskStore {
    /// The saved tasks (goals, workspaces) are private like every bulge
    /// file. A schedule written before that rule (mode 644/664) is tightened
    /// to 600 once instead of being refused; it was inside the 700 ~/.bulge.
    fn load(path: &Path) -> Result<Self, String> {
        #[cfg(unix)]
        if path.exists() && bulge_util::fs::check_private(path).is_err() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod 600 {}: {e}", path.display()))?;
        }
        Ok(bulge_util::fs::read_json(path)?.unwrap_or_default())
    }

    /// Atomic, mode 600 from the first byte.
    fn save(&self, path: &Path) -> Result<(), String> {
        bulge_util::fs::write_json(path, self)
    }
}

/// The user's home, after making sure `~/.bulge` exists and is private (700).
fn bulge_home() -> Result<PathBuf, String> {
    bulge_util::fs::bulge_home()?;
    bulge_util::home_dir()
}

fn store_path(home: &Path) -> PathBuf {
    home.join(".bulge").join(STORE_FILE)
}

/// A read-only summary of one scheduled task (for the desktop settings view).
#[derive(Debug, Clone, Serialize)]
pub struct TaskSummary {
    pub id: String,
    pub title: String,
    pub enabled: bool,
    pub next_run_at: Option<u64>,
    pub last_run_at: Option<u64>,
    pub runs: u32,
    /// A short human description of the schedule (e.g. `daily 09:00`).
    pub schedule: String,
}

/// Describe a schedule compactly for display.
fn describe(s: &Schedule) -> String {
    match s {
        Schedule::AfterSeconds { seconds } => format!("once, +{seconds}s"),
        Schedule::At { unix } => format!("once at unix:{unix}"),
        Schedule::EverySeconds { seconds } => format!("every {seconds}s"),
        Schedule::Daily { hour, minute } => format!("daily {hour:02}:{minute:02}"),
        Schedule::Weekly { weekdays, hour, minute } => format!("weekly {} {hour:02}:{minute:02}", weekdays.len()),
        Schedule::Cron { expr } => format!("cron {expr}"),
        Schedule::OnPathChange { path } => format!("on change: {path}"),
    }
}

/// Whether a task should fire now: a time-based task once its next run has passed;
/// an event task once its watched path's mtime differs from the last-seen value.
fn task_is_due(task: &SavedTask, now: u64) -> bool {
    match &task.schedule {
        Schedule::OnPathChange { path } => match path_mtime(path) {
            Some(mtime) => task.watch_mtime != Some(mtime),
            None => false, // path gone/unreadable: nothing to react to
        },
        _ => task.next_run_at.is_some_and(|at| at <= now),
    }
}

/// The mtime of `path` in Unix seconds, or `None` if it cannot be read.
fn path_mtime(path: &str) -> Option<u64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// All saved tasks, summarised (desktop settings view). Empty on any error.
pub fn summaries() -> Vec<TaskSummary> {
    let Ok(home) = bulge_home() else { return Vec::new() };
    let Ok(store) = TaskStore::load(&store_path(&home)) else { return Vec::new() };
    store
        .tasks
        .into_iter()
        .map(|t| TaskSummary {
            id: t.id,
            title: t.title,
            enabled: t.enabled,
            next_run_at: t.next_run_at,
            last_run_at: t.last_run_at,
            runs: t.runs,
            schedule: describe(&t.schedule),
        })
        .collect()
}

/// Remove a task by id (desktop view). Returns whether anything was removed.
pub fn remove_task(id: &str) -> Result<bool, String> {
    let home = bulge_home()?;
    let path = store_path(&home);
    let mut store = TaskStore::load(&path)?;
    let before = store.tasks.len();
    store.tasks.retain(|t| t.id != id);
    if store.tasks.len() == before {
        return Ok(false);
    }
    store.save(&path)?;
    Ok(true)
}

/// Enable or disable a task by id. Re-enabling recomputes its next run from now.
pub fn set_enabled(id: &str, enabled: bool) -> Result<bool, String> {
    let home = bulge_home()?;
    let path = store_path(&home);
    let mut store = TaskStore::load(&path)?;
    let now = now_unix();
    let Some(task) = store.tasks.iter_mut().find(|t| t.id == id) else {
        return Ok(false);
    };
    task.enabled = enabled;
    if enabled {
        task.next_run_at = next_occurrence(&task.schedule, now, task.anchor, task.offset_minutes);
        if task.next_run_at.is_none() {
            task.enabled = false; // nothing left to run (past one-shot)
        }
    }
    store.save(&path)?;
    Ok(true)
}

/// Add a scheduled task from the desktop UI. `kind` selects the schedule shape
/// (`after`, `at`, `every`, `daily`, `weekly`, `cron`, `on_change`) and `value`
/// is interpreted accordingly. Uses the same fixed run defaults as the app.
#[expect(clippy::too_many_arguments, reason = "mirrors the desktop form's fields so each UI input maps to one argument")]
pub fn add_task(
    goal: &str,
    workspace: &str,
    autonomy: &str,
    model: &str,
    base_url: &str,
    protocol: &str,
    kind: &str,
    value: &str,
    offset_minutes: i32,
) -> Result<String, String> {
    let schedule = build_schedule_for_kind(kind, value)?;
    let autonomy = parse_autonomy(autonomy)?;
    let (id, _next_run_at) = save_task(TaskDraft {
        goal: goal.to_string(),
        title: None,
        workspace: PathBuf::from(workspace),
        autonomy,
        model: model.to_string(),
        base_url: base_url.to_string(),
        protocol: protocol.to_string(),
        backend_id: None,
        context_window: crate::backend::DEFAULT_CONTEXT_WINDOW,
        max_tokens: crate::backend::DEFAULT_MAX_TOKENS,
        reasoning: false,
        max_steps: 200,
        max_model_tokens: 2_000_000,
        max_secs: 14_400,
        network: false,
        cpus: 2,
        ram_mib: 1_024,
        offset_minutes,
        schedule,
    })?;
    Ok(id)
}

/// Entry point for `bulge schedule <sub> …`. Returns a process exit code.
pub fn dispatch(args: &[String]) -> i32 {
    let result = match args.first().map(String::as_str) {
        Some("add") => add(&args[1..]),
        Some("list") | None => list(),
        Some("remove") | Some("rm") => remove(&args[1..]),
        Some("tick") => tick(),
        Some(other) => Err(format!("unknown schedule command {other:?} (add|list|remove|tick)")),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}

/// The fields that differ between a CLI-created task and a UI-created one. Both
/// paths go through [`save_task`], so validation and persistence stay identical.
struct TaskDraft {
    goal: String,
    title: Option<String>,
    workspace: PathBuf,
    autonomy: Autonomy,
    model: String,
    base_url: String,
    protocol: String,
    backend_id: Option<String>,
    context_window: u32,
    max_tokens: u32,
    reasoning: bool,
    max_steps: u64,
    max_model_tokens: u64,
    max_secs: u64,
    network: bool,
    cpus: u8,
    ram_mib: u32,
    offset_minutes: i32,
    schedule: Schedule,
}

/// Build, validate, and persist a new task; returns its id and next run time.
fn save_task(draft: TaskDraft) -> Result<(String, Option<u64>), String> {
    if !draft.workspace.is_dir() {
        return Err(format!("workspace {} is not a directory", draft.workspace.display()));
    }
    // Validate the backend protocol now, so `tick` never fails on a bad value.
    Protocol::parse(&draft.protocol)?;

    let home = bulge_home()?;
    let now = now_unix();
    let backend_host = host_of(&draft.base_url);
    let title = draft.title.unwrap_or_else(|| draft.goal.lines().next().unwrap_or("task").chars().take(80).collect());
    let id = format!("sched-{now:x}-{:x}", std::process::id());
    let (next_run_at, watch_mtime) = initial_run_state(&draft.schedule, now, draft.offset_minutes)?;

    let task = SavedTask {
        id: id.clone(),
        title,
        goal: draft.goal,
        workspace: draft.workspace,
        autonomy: draft.autonomy,
        model: draft.model,
        base_url: draft.base_url,
        protocol: draft.protocol,
        backend_id: draft.backend_id.unwrap_or(backend_host),
        context_window: draft.context_window,
        max_tokens: draft.max_tokens,
        reasoning: draft.reasoning,
        max_steps: draft.max_steps,
        max_model_tokens: draft.max_model_tokens,
        max_secs: draft.max_secs,
        network: draft.network,
        cpus: draft.cpus,
        ram_mib: draft.ram_mib,
        schedule: draft.schedule,
        offset_minutes: draft.offset_minutes,
        anchor: now,
        enabled: true,
        next_run_at,
        last_run_at: None,
        runs: 0,
        watch_mtime,
    };

    let path = store_path(&home);
    let mut store = TaskStore::load(&path)?;
    store.tasks.push(task);
    store.save(&path)?;
    Ok((id, next_run_at))
}

/// The first run time and, for an event task, the mtime to compare against.
fn initial_run_state(schedule: &Schedule, now: u64, offset_minutes: i32) -> Result<(Option<u64>, Option<u64>), String> {
    match schedule {
        Schedule::OnPathChange { path } => Ok((None, Some(path_mtime(path).unwrap_or(0)))),
        other => {
            let next = next_occurrence(other, now, now, offset_minutes);
            match next {
                Some(at) => Ok((Some(at), None)),
                None => Err("that schedule has no future occurrence (a past one-shot, or an invalid cron expression)".into()),
            }
        }
    }
}

/// Build a schedule from the desktop form's `kind` + `value` pair.
fn build_schedule_for_kind(kind: &str, value: &str) -> Result<Schedule, String> {
    match kind {
        "after" => Ok(Schedule::AfterSeconds { seconds: parse_num(value, "after")? }),
        "at" => Ok(Schedule::At { unix: parse_num(value, "at")? }),
        "every" => Ok(Schedule::every(parse_num(value, "every")?)),
        "daily" => {
            let (hour, minute) = parse_hm(value)?;
            Ok(Schedule::Daily { hour, minute })
        }
        "weekly" => {
            let (weekdays, hour, minute) = parse_weekly(value)?;
            Ok(Schedule::Weekly { weekdays, hour, minute })
        }
        "cron" => Ok(Schedule::Cron { expr: value.to_string() }),
        "on_change" => Ok(Schedule::OnPathChange { path: value.to_string() }),
        other => Err(format!("unknown schedule kind {other:?} (after|at|every|daily|weekly|cron|on_change)")),
    }
}

/// `bulge schedule add --goal … --workspace … <selector> [run options]`.
fn add(args: &[String]) -> Result<(), String> {
    let mut goal = None;
    let mut title = None;
    let mut workspace = None;
    let mut autonomy = Autonomy::Autonomous;
    let mut model = crate::backend::DEFAULT_MODEL.to_string();
    let mut base_url = crate::backend::DEFAULT_BASE_URL.to_string();
    let mut protocol = "openai".to_string();
    let mut backend_id: Option<String> = None;
    let mut context_window: u32 = crate::backend::DEFAULT_CONTEXT_WINDOW;
    let mut max_tokens: u32 = crate::backend::DEFAULT_MAX_TOKENS;
    let mut reasoning = false;
    let mut max_steps: u64 = 200;
    let mut max_model_tokens: u64 = 2_000_000;
    let mut max_secs: u64 = 14_400;
    let mut network = false;
    let mut cpus: u8 = 2;
    let mut ram_mib: u32 = 1_024;
    let mut offset_minutes: i32 = 0;
    // Schedule selectors (exactly one required).
    let mut after: Option<u64> = None;
    let mut at: Option<u64> = None;
    let mut every: Option<u64> = None;
    let mut daily: Option<String> = None;
    let mut weekly: Option<String> = None;
    let mut cron: Option<String> = None;
    let mut on_change: Option<String> = None;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().cloned().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--goal" => goal = Some(value()?),
            "--title" => title = Some(value()?),
            "--workspace" => workspace = Some(PathBuf::from(value()?)),
            "--autonomy" => autonomy = parse_autonomy(&value()?)?,
            "--model" => model = value()?,
            "--base-url" => base_url = value()?,
            "--protocol" => protocol = value()?,
            "--backend-id" => backend_id = Some(value()?),
            "--context-window" => context_window = parse_num(&value()?, flag)?,
            "--max-tokens" => max_tokens = parse_num(&value()?, flag)?,
            "--reasoning" => reasoning = true,
            "--max-steps" => max_steps = parse_num(&value()?, flag)?,
            "--max-model-tokens" => max_model_tokens = parse_num(&value()?, flag)?,
            "--max-secs" => max_secs = parse_num(&value()?, flag)?,
            "--network" => network = true,
            "--cpus" => cpus = parse_num(&value()?, flag)?,
            "--ram" => ram_mib = parse_num(&value()?, flag)?,
            "--offset-min" => offset_minutes = parse_num(&value()?, flag)?,
            "--after" => after = Some(parse_num(&value()?, flag)?),
            "--at" => at = Some(parse_num(&value()?, flag)?),
            "--every" => every = Some(parse_num(&value()?, flag)?),
            "--daily" => daily = Some(value()?),
            "--weekly" => weekly = Some(value()?),
            "--cron" => cron = Some(value()?),
            "--on-change" => on_change = Some(value()?),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let schedule = build_schedule(after, at, every, daily.as_deref(), weekly.as_deref(), cron.as_deref(), on_change.as_deref())?;
    let goal = goal.ok_or("--goal is required")?;
    let workspace = workspace.ok_or("--workspace is required")?;
    let (id, next_run_at) = save_task(TaskDraft {
        goal,
        title,
        workspace,
        autonomy,
        model,
        base_url,
        protocol,
        backend_id,
        context_window,
        max_tokens,
        reasoning,
        max_steps,
        max_model_tokens,
        max_secs,
        network,
        cpus,
        ram_mib,
        offset_minutes,
        schedule,
    })?;
    match next_run_at {
        Some(at) => println!("added {id} (next run at unix {at})"),
        None => println!("added {id} (event-driven; fires on change)"),
    }
    Ok(())
}

fn list() -> Result<(), String> {
    let home = bulge_home()?;
    let store = TaskStore::load(&store_path(&home))?;
    if store.tasks.is_empty() {
        println!("no scheduled tasks");
        return Ok(());
    }
    for task in &store.tasks {
        let state = if task.enabled { "on" } else { "off" };
        let next = task.next_run_at.map(|t| t.to_string()).unwrap_or_else(|| "—".into());
        println!("{}  [{state}]  runs={}  next=unix:{next}  {}", task.id, task.runs, task.title);
    }
    Ok(())
}

fn remove(args: &[String]) -> Result<(), String> {
    let mut id = None;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--id" => id = iter.next().cloned(),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let id = id.ok_or("--id is required")?;
    let home = bulge_home()?;
    let path = store_path(&home);
    let mut store = TaskStore::load(&path)?;
    let before = store.tasks.len();
    store.tasks.retain(|t| t.id != id);
    if store.tasks.len() == before {
        return Err(format!("no task with id {id}"));
    }
    store.save(&path)?;
    println!("removed {id}");
    Ok(())
}

/// Run every due task once, under a single-flight lock, then reschedule.
fn tick() -> Result<(), String> {
    let home = bulge_home()?;
    let path = store_path(&home);

    // Single-flight: hold an exclusive lock on a sibling file for the whole tick.
    let _lock = match bulge_util::fs::single_instance(&home.join(".bulge").join(LOCK_FILE), "schedule tick") {
        Ok(lock) => lock,
        Err(bulge_util::fs::LockError::Held(_)) => {
            eprintln!("another tick is already running; skipping");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let now = now_unix();
    let mut store = TaskStore::load(&path)?;
    // Snapshot the ids that are due, so we don't hold borrows across the run. A
    // time-based task is due when its next_run_at has passed; an event task is due
    // when its watched path's mtime differs from what the last tick recorded.
    let due: Vec<String> = store
        .tasks
        .iter()
        .filter(|t| t.enabled && task_is_due(t, now))
        .map(|t| t.id.clone())
        .collect();
    if due.is_empty() {
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    for id in due {
        let Some(task) = store.tasks.iter().find(|t| t.id == id).cloned() else { continue };
        eprintln!("tick: running {id} ({})", task.title);
        match task.to_run_config() {
            Ok(config) => match rt.block_on(run::run(config)) {
                Ok(outcome) => eprintln!("tick: {id} finished: {:?}", outcome.outcome),
                Err(e) => eprintln!("tick: {id} failed: {e}"),
            },
            Err(e) => eprintln!("tick: {id} skipped (bad config): {e}"),
        }

        // Reschedule: bump counters, disable one-shots, advance recurring ones to
        // the next occurrence strictly after now (latest-missed coalescing — we do
        // not backfill occurrences skipped while the machine was off); for an event
        // task, record the path's current mtime so it only fires on the next change.
        if let Some(task) = store.tasks.iter_mut().find(|t| t.id == id) {
            task.runs = task.runs.saturating_add(1);
            task.last_run_at = Some(now);
            match &task.schedule {
                Schedule::OnPathChange { path } => {
                    task.watch_mtime = Some(path_mtime(path).unwrap_or(0));
                }
                s if s.is_one_shot() => {
                    task.enabled = false;
                    task.next_run_at = None;
                }
                _ => {
                    task.next_run_at = next_occurrence(&task.schedule, now, task.anchor, task.offset_minutes);
                    if task.next_run_at.is_none() {
                        task.enabled = false;
                    }
                }
            }
        }
        // Persist after each run so a crash mid-batch never re-runs a finished task.
        store.save(&path)?;
    }
    Ok(())
}

// ---- parsing helpers ----

fn build_schedule(
    after: Option<u64>,
    at: Option<u64>,
    every: Option<u64>,
    daily: Option<&str>,
    weekly: Option<&str>,
    cron: Option<&str>,
    on_change: Option<&str>,
) -> Result<Schedule, String> {
    let mut chosen: Vec<Schedule> = Vec::new();
    if let Some(s) = after {
        chosen.push(Schedule::AfterSeconds { seconds: s });
    }
    if let Some(u) = at {
        chosen.push(Schedule::At { unix: u });
    }
    if let Some(s) = every {
        chosen.push(Schedule::every(s));
    }
    if let Some(spec) = daily {
        let (h, m) = parse_hm(spec)?;
        chosen.push(Schedule::Daily { hour: h, minute: m });
    }
    if let Some(spec) = weekly {
        let (days, h, m) = parse_weekly(spec)?;
        chosen.push(Schedule::Weekly { weekdays: days, hour: h, minute: m });
    }
    if let Some(expr) = cron {
        chosen.push(Schedule::Cron { expr: expr.to_string() });
    }
    if let Some(path) = on_change {
        chosen.push(Schedule::OnPathChange { path: path.to_string() });
    }
    match chosen.len() {
        1 => Ok(chosen.into_iter().next().unwrap()),
        0 => Err("a schedule selector is required (--after|--at|--every|--daily|--weekly|--cron|--on-change)".into()),
        _ => Err("pick exactly one schedule selector".into()),
    }
}

/// Parse `HH:MM` into (hour, minute).
fn parse_hm(spec: &str) -> Result<(u8, u8), String> {
    let (h, m) = spec.split_once(':').ok_or_else(|| format!("expected HH:MM, got {spec:?}"))?;
    let hour: u8 = h.trim().parse().map_err(|_| format!("bad hour in {spec:?}"))?;
    let minute: u8 = m.trim().parse().map_err(|_| format!("bad minute in {spec:?}"))?;
    if hour > 23 || minute > 59 {
        return Err(format!("time out of range in {spec:?}"));
    }
    Ok((hour, minute))
}

/// Parse `mon,wed,fri:HH:MM` into (weekdays, hour, minute).
fn parse_weekly(spec: &str) -> Result<(Vec<Weekday>, u8, u8), String> {
    let (days_part, time_part) = spec.rsplit_once(':').and_then(|(rest, mm)| rest.rsplit_once(':').map(|(days, hh)| (days, format!("{hh}:{mm}")))).ok_or_else(|| format!("expected DAYS:HH:MM, got {spec:?}"))?;
    let (hour, minute) = parse_hm(&time_part)?;
    let mut days = Vec::new();
    for token in days_part.split(',') {
        days.push(parse_weekday(token.trim())?);
    }
    if days.is_empty() {
        return Err("no weekdays given".into());
    }
    Ok((days, hour, minute))
}

fn parse_weekday(token: &str) -> Result<Weekday, String> {
    match token.to_ascii_lowercase().as_str() {
        "mon" | "monday" => Ok(Weekday::Mon),
        "tue" | "tuesday" => Ok(Weekday::Tue),
        "wed" | "wednesday" => Ok(Weekday::Wed),
        "thu" | "thursday" => Ok(Weekday::Thu),
        "fri" | "friday" => Ok(Weekday::Fri),
        "sat" | "saturday" => Ok(Weekday::Sat),
        "sun" | "sunday" => Ok(Weekday::Sun),
        other => Err(format!("unknown weekday {other:?}")),
    }
}

fn parse_autonomy(value: &str) -> Result<Autonomy, String> {
    match value {
        "collaborative" => Ok(Autonomy::Collaborative),
        "autonomous" => Ok(Autonomy::Autonomous),
        "full-auto" | "full_auto" | "fullauto" => Ok(Autonomy::FullAuto),
        other => Err(format!("unknown autonomy {other:?} (collaborative|autonomous|full-auto)")),
    }
}

fn parse_num<T: std::str::FromStr>(value: &str, flag: &str) -> Result<T, String> {
    value.parse::<T>().map_err(|_| format!("{flag} expects a number, got {value:?}"))
}

fn host_of(base_url: &str) -> String {
    base_url.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("backend").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hm_parses_and_rejects() {
        assert_eq!(parse_hm("09:30").unwrap(), (9, 30));
        assert!(parse_hm("24:00").is_err());
        assert!(parse_hm("noon").is_err());
    }

    #[test]
    fn weekly_parses_days_and_time() {
        let (days, h, m) = parse_weekly("mon,wed,fri:08:15").unwrap();
        assert_eq!(days, vec![Weekday::Mon, Weekday::Wed, Weekday::Fri]);
        assert_eq!((h, m), (8, 15));
    }

    #[test]
    fn exactly_one_selector() {
        assert!(build_schedule(Some(60), None, None, None, None, None, None).is_ok());
        assert!(build_schedule(None, None, None, None, None, None, None).is_err());
        assert!(build_schedule(Some(60), Some(10), None, None, None, None, None).is_err());
        assert!(build_schedule(None, None, None, None, None, None, Some("/tmp/x")).is_ok());
    }

    #[test]
    fn store_round_trips() {
        let dir = std::env::temp_dir().join(format!("bulge-sched-{}", std::process::id()));
        let path = dir.join(STORE_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = TaskStore::default();
        store.tasks.push(SavedTask {
            id: "sched-1".into(),
            title: "t".into(),
            goal: "g".into(),
            workspace: PathBuf::from("/tmp"),
            autonomy: Autonomy::Autonomous,
            model: "m".into(),
            base_url: "https://api.deepseek.com".into(),
            protocol: "openai".into(),
            backend_id: "api.deepseek.com".into(),
            context_window: 128_000,
            max_tokens: 8_192,
            reasoning: false,
            max_steps: 200,
            max_model_tokens: 2_000_000,
            max_secs: 14_400,
            network: false,
            cpus: 2,
            ram_mib: 1_024,
            schedule: Schedule::Daily { hour: 9, minute: 0 },
            offset_minutes: 480,
            anchor: 1000,
            enabled: true,
            next_run_at: Some(2000),
            last_run_at: None,
            runs: 0,
            watch_mtime: None,
        });
        store.save(&path).unwrap();
        let loaded = TaskStore::load(&path).unwrap();
        assert_eq!(loaded.tasks.len(), 1);
        assert_eq!(loaded.tasks[0].id, "sched-1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
