//! The two model tools over one job store:
//! - `cronjob_manage` — Hermes' compressed action tool (create/list/update/pause/resume/remove/run;
//!   `run` fires in the background and the outcome re-enters the conversation);
//! - `automations` — OpenClaw's cron tool (status/list/get/add/update/remove/run/runs/next_check/wake;
//!   structured `schedule`/`payload`/`delivery`; `run` waits for the finished run).

use super::{create, find, format_job, next_check, schedule, set_paused, update, Settings, Spec};
use crate::automation::{jobs_path, read_list, remove_job, Job};
use crate::config::Config;
use crate::kernel::Host;
use crate::util::unix_now;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Both tools, configured from `cfg` (registered by the host next to the builtins).
pub fn tools(cfg: &Config) -> Vec<Arc<dyn Tool>> {
    let st = Settings::from_config(cfg);
    vec![Arc::new(CronjobManage { st: st.clone() }), Arc::new(Automations { st })]
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}
fn list(v: &Value, k: &str) -> Option<Vec<String>> {
    match v.get(k)? {
        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
        Value::String(x) => Some(if x.is_empty() { vec![] } else { vec![x.clone()] }),
        Value::Null => Some(vec![]),
        _ => None,
    }
}
fn out(v: Value) -> ToolOutput {
    ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default())
}
fn fail(e: impl Into<String>) -> ToolOutput {
    ToolOutput::err(serde_json::to_string_pretty(&json!({"success": false, "error": e.into()})).unwrap_or_default())
}

/// True when `session` is a cron run of some job (guards recursion unless allowed).
fn in_cron_run(data: &Path, session: &str) -> bool {
    read_list::<Job>(&jobs_path(data)).unwrap_or_default().iter().any(|j| j.last_session.as_deref() == Some(session) && j.session.as_deref() != Some(session))
}

fn daemon_note(ctx: &ToolCtx) -> Option<String> {
    let rt = Host::of(ctx).map(|h| h.rt.paths.socket());
    let alive = rt.map(|sock| crate::daemon::call(&sock, "ping", json!({})).is_ok()).unwrap_or(true);
    (!alive).then(|| "Note: arkd is not running, so scheduled jobs will not fire until `ark daemon start`.".to_string())
}

fn write_effects(ctx: &ToolCtx) -> Vec<Effect> {
    vec![Effect::Write { path: jobs_path(&ctx.home) }]
}

/// Background / waited run of a job through the kernel behind the tool context.
fn run_job(ctx: &ToolCtx, job: Job, extra: Option<String>, wait: Option<Duration>) -> Result<Value, String> {
    let host = Host::of(ctx).ok_or("running a job needs the agent runtime (use `ark schedule run <id>`)")?;
    let k = host.rt.clone();
    let caller = ctx.session_id.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let job2 = job.clone();
    std::thread::spawn(move || {
        let r = crate::automation::run_job_with(&k, &job2, extra.as_deref());
        if wait.is_none() {
            // Hermes: the outcome re-enters the conversation when done.
            let refreshed = super::find(&k.paths.data, &job2.id).ok();
            let status = refreshed.as_ref().and_then(|j| j.ext.last_status.clone()).unwrap_or_else(|| "unknown".into());
            let excerpt = refreshed.and_then(|j| j.ext.last_output).map(|o| crate::util::head_tail(&o, 2000).0).unwrap_or_default();
            let msg = match &r {
                Ok(sid) => format!("[cron job '{}' ({}) finished: {status} — session {sid}]\n{excerpt}", job2.ext.name.clone().unwrap_or_default(), job2.id),
                Err(e) => format!("[cron job '{}' ({}) failed: {e}]", job2.ext.name.clone().unwrap_or_default(), job2.id),
            };
            let _ = k.submit(&caller, &msg, "schedule");
        }
        let _ = tx.send(r);
    });
    match wait {
        None => Ok(json!({"executed": true, "execution_mode": "background", "note": "The job is running in the background; its outcome will re-enter this conversation when it finishes. Do not wait or poll."})),
        Some(d) => match rx.recv_timeout(d) {
            Ok(r) => {
                let j = super::find(&ctx.home, &job.id).ok();
                Ok(json!({"ok": r.is_ok(), "enqueued": true, "finished": true, "run": {"session": r.as_ref().ok(), "error": r.as_ref().err(), "status": j.as_ref().and_then(|j| j.ext.last_status.clone()), "output": j.and_then(|j| j.ext.last_output)}}))
            }
            Err(_) => Ok(json!({"ok": true, "enqueued": true, "finished": false, "note": "Not finished yet: it is still running. Its delivery follows the job settings; check it later with runs jobId. Do not schedule a verification job."})),
        },
    }
}

// ───────────────────────── cronjob_manage (Hermes) ─────────────────────────

pub struct CronjobManage {
    pub st: Settings,
}

impl CronjobManage {
    fn spec(&self, a: &Value, ctx: &ToolCtx) -> Spec {
        let pinned = a.get("pinned").and_then(Value::as_bool);
        Spec {
            prompt: s(a, "prompt").map(String::from),
            schedule: s(a, "schedule").map(String::from),
            name: s(a, "name").map(String::from),
            repeat: a.get("repeat").and_then(Value::as_u64).map(|n| n as u32),
            deliver: s(a, "deliver").map(String::from),
            failure_deliver: s(a, "failure_deliver").map(String::from),
            skills: list(a, "skills").or_else(|| s(a, "skill").map(|x| vec![x.to_string()])),
            script: s(a, "script").map(String::from),
            no_agent: a.get("no_agent").and_then(Value::as_bool),
            context_from: list(a, "context_from"),
            continuity: a.get("continuity").and_then(Value::as_bool),
            workdir: s(a, "workdir").map(String::from),
            // pinned=true locks the CURRENT main model; false releases it.
            model: pinned.map(|p| if p { self.st.default_model.clone() } else { String::new() }),
            paused: a.get("paused").and_then(Value::as_bool).unwrap_or(false),
            paused_reason: s(a, "paused_reason").map(String::from),
            origin: Some(ctx.session_id.clone()).filter(|s| !s.is_empty()),
            ..Default::default()
        }
    }
}

impl Tool for CronjobManage {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "cronjob_manage".into(),
            description: "Manage scheduled cron jobs: action='create' schedules a job from a prompt and/or skills; 'list' inspects jobs; 'update'/'pause'/'resume'/'remove' manage one by job_id (always list first — never guess job IDs); 'run' fires a job immediately in the BACKGROUND (returns at once, outcome re-enters the conversation when done — do not wait or poll; optional 'prompt' adds transient context for that fire only).\n\nJobs run in a fresh session with no current-chat context, so prompts must be self-contained, and the agent's FINAL RESPONSE is what gets delivered — cron runs are autonomous and cannot ask questions. Jobs run on the main agent model unless pinned. Prefer updating an existing job over creating near-duplicates.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["create", "list", "update", "pause", "resume", "remove", "run"], "description": "One of: create, list, update, pause, resume, remove, run. When action=create, the 'schedule' and 'prompt' fields are REQUIRED."},
                    "job_id": {"type": "string", "description": "Required for update/pause/resume/remove/run."},
                    "prompt": {"type": "string", "description": "For create: the full self-contained prompt (paired with any skills as the task instruction). For run: optional transient context for that single fire (never persisted)."},
                    "schedule": {"type": "string", "description": "REQUIRED for create. Forms: (1) recurring interval — '30m', 'every 2h', 'every hour'; (2) one-shot by duration — 'in 30m', 'in 2h' (use this for 'remind me in N minutes' — do NOT hand-compute a timestamp); (3) natural day/time — 'every monday 9am', 'weekdays at 9am', 'every day at 9am'; (4) cron syntax — '0 9 * * *'; (5) absolute one-shot — ISO timestamp '2026-06-01T09:00:00'."},
                    "name": {"type": "string", "description": "Optional human-friendly name"},
                    "repeat": {"type": "integer", "description": "Optional repeat count. Omit for defaults (once for one-shot, forever for recurring)."},
                    "deliver": {"type": "string", "description": "Where the job's output is POSTED. Omit to address the chat this job was created from ('origin'). Otherwise: 'local' (save only), 'all' (every configured channel's default chat), '<channel>' / '<channel>:<chat>[:<thread>]', or a webhook URL. Comma-combine like 'origin,all'."},
                    "failure_deliver": {"type": "string", "description": "Optional override target for FAILURE notices only (same grammar as deliver); 'local' suppresses them. On update, '' clears."},
                    "skills": {"type": "array", "items": {"type": "string"}, "description": "Optional ordered skill names loaded before the cron prompt. On update, [] clears."},
                    "script": {"type": "string", "description": "Optional script run each tick from the ark data dir's scripts/ folder (relative name only); stdout is injected into the prompt as context (with no_agent=true the script IS the job). .sh/.bash via bash, else python3. A last stdout line {\"wakeAgent\": false} skips the run. On update, '' clears."},
                    "no_agent": {"type": "boolean", "default": false, "description": "True = no LLM: run `script` (required) on schedule and deliver its stdout verbatim; empty stdout sends nothing (watchdog pattern); non-zero exit or timeout sends an error alert."},
                    "context_from": {"type": "array", "items": {"type": "string"}, "description": "Optional job ID(s) whose most recent completed output is injected as context each run (chains jobs). On update, [] clears."},
                    "continuity": {"type": "boolean", "description": "True = each run sees the job's own previous output (dedupe, continue where it left off)."},
                    "workdir": {"type": "string", "description": "Optional absolute existing directory to run the job in (its AGENTS.md / context files apply)."},
                    "pinned": {"type": "boolean", "description": "ONLY when the user explicitly asks: true locks the current main model onto the job; false releases it."},
                    "paused": {"type": "boolean", "description": "Create only: persist disabled. Resume to schedule; explicit run remains available."},
                    "paused_reason": {"type": "string", "description": "Create/pause: auditable reason; on create requires paused=true."},
                    "include_disabled": {"type": "boolean", "description": "List: include paused/finished jobs (default true)."}
                },
                "required": ["action"]
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match s(input, "action") {
            Some("list") => vec![Effect::Read { path: jobs_path(&ctx.home) }],
            _ => write_effects(ctx),
        }
    }

    fn call(&self, ctx: &ToolCtx, a: Value) -> ToolOutput {
        let data = ctx.home.clone();
        let action = s(&a, "action").unwrap_or("").trim().to_ascii_lowercase();
        if action != "list" && !self.st.allow_in_cron && in_cron_run(&data, &ctx.session_id) {
            return fail("cron runs may not manage cron jobs here (automation.allow_agent_scheduling = false)");
        }
        let job_ref = || -> Result<Job, String> { find(&data, s(&a, "job_id").unwrap_or("")) };
        let r: Result<Value, String> = (|| match action.as_str() {
            "create" => {
                let j = create(&data, &self.st, self.spec(&a, ctx), &ctx.workspace)?;
                let mut v = json!({"success": true, "job_id": j.id, "name": j.ext.name, "skills": j.ext.skills, "schedule": j.ext.display, "repeat": format_job(&j, self.st.offset)["repeat"], "deliver": j.ext.deliver.clone().unwrap_or_else(|| "origin".into()), "next_run_at": crate::util::fmt_time(j.next_run, self.st.offset), "job": format_job(&j, self.st.offset)});
                let mut msg = format!("Cron job '{}' created.", j.ext.name.clone().unwrap_or_default());
                if !j.enabled {
                    msg.push_str(" Created PAUSED — resume to schedule, or explicitly run now.");
                }
                if j.ext.deliver.as_deref() == Some("local") {
                    msg.push_str(" Output is saved locally only (deliver='local').");
                } else if j.ext.deliver.is_none() && j.ext.origin.as_deref().and_then(|o| super::resolve_origin(&data, o)).is_none() {
                    msg.push_str(" This conversation is not a channel chat, so 'origin' delivery keeps results local; set deliver to a channel to be notified.");
                }
                if let Some(n) = daemon_note(ctx) {
                    msg.push(' ');
                    msg.push_str(&n);
                }
                v["message"] = json!(msg);
                Ok(v)
            }
            "list" => {
                let include = a.get("include_disabled").and_then(Value::as_bool).unwrap_or(true);
                let jobs: Vec<Value> = read_list::<Job>(&jobs_path(&data))?.iter().filter(|j| include || j.enabled).map(|j| format_job(j, self.st.offset)).collect();
                let mut v = json!({"success": true, "count": jobs.len(), "jobs": jobs});
                if !jobs.is_empty() {
                    if let Some(n) = daemon_note(ctx) {
                        v["note"] = json!(n);
                    }
                }
                Ok(v)
            }
            "remove" => {
                let j = job_ref()?;
                if !remove_job(&data, &j.id)? {
                    return Err(format!("Failed to remove job '{}'", j.id));
                }
                super::chronos::jobs_changed(&data);
                Ok(json!({"success": true, "message": format!("Cron job '{}' removed.", j.ext.name.clone().unwrap_or_default()), "removed_job": {"id": j.id, "name": j.ext.name, "schedule": j.ext.display}}))
            }
            "pause" => {
                let j = job_ref()?;
                let j = set_paused(&data, &j.id, true, s(&a, "paused_reason").or(Some("user-paused")))?;
                Ok(json!({"success": true, "job": format_job(&j, self.st.offset)}))
            }
            "resume" => {
                let j = job_ref()?;
                let j = set_paused(&data, &j.id, false, None)?;
                Ok(json!({"success": true, "job": format_job(&j, self.st.offset)}))
            }
            "update" => {
                let j = job_ref()?;
                let mut spec = self.spec(&a, ctx);
                spec.origin = None;
                let j = update(&data, &self.st, &j.id, spec)?;
                Ok(json!({"success": true, "job": format_job(&j, self.st.offset)}))
            }
            "run" => {
                let j = job_ref()?;
                let extra = s(&a, "prompt").filter(|p| !p.trim().is_empty()).map(String::from);
                if let Some(e) = &extra {
                    super::scan(&self.st, e)?;
                }
                let mut v = run_job(ctx, j.clone(), extra, None)?;
                v["success"] = json!(true);
                v["job"] = format_job(&j, self.st.offset);
                Ok(v)
            }
            "" => Err("action is required (create, list, update, pause, resume, remove, run)".into()),
            other => Err(format!("Unknown action '{other}'. Use one of: create, list, update, pause, resume, remove, run.")),
        })();
        match r {
            Ok(v) => out(v),
            Err(e) => fail(e),
        }
    }
}

// ───────────────────────── automations (OpenClaw) ─────────────────────────

pub struct Automations {
    pub st: Settings,
}

const LIST_MAX: usize = 200;

impl Automations {
    /// OpenClaw `job` object → Spec (add: full job; update: partial patch, null clears).
    fn spec(&self, job: &Value, ctx: &ToolCtx, patch: bool) -> Result<Spec, String> {
        let now = unix_now();
        let mut sp = Spec::default();
        if let Some(sc) = job.get("schedule").filter(|v| !v.is_null()) {
            sp.sched = Some(match sc {
                Value::String(x) => schedule::parse(x, now, self.st.offset)?,
                v => schedule::from_openclaw(v, now, self.st.offset)?,
            });
        } else if !patch {
            return Err("job.schedule is required for add".into());
        }
        sp.name = job.get("name").map(|n| n.as_str().unwrap_or("").to_string());
        if let Some(p) = job.get("payload").filter(|v| !v.is_null()) {
            let kind = s(p, "kind").unwrap_or("agentTurn");
            match kind {
                "agentTurn" => sp.prompt = s(p, "message").or_else(|| s(p, "text")).map(String::from),
                "systemEvent" => {
                    sp.prompt = s(p, "text").or_else(|| s(p, "message")).map(String::from);
                    sp.kind = Some("systemEvent".into());
                }
                k => return Err(format!("payload.kind `{k}` is not supported (agentTurn, systemEvent)")),
            }
            if let Some(m) = s(p, "model") {
                sp.model = Some(m.to_string());
            }
        } else if !patch {
            return Err("job.payload is required for add".into());
        }
        if let Some(d) = job.get("delivery") {
            sp.deliver = Some(match d {
                Value::Null => String::new(),
                d => match s(d, "mode").unwrap_or("announce") {
                    "none" => "local".into(),
                    "webhook" => format!("webhook:{}", s(d, "to").or_else(|| s(d, "url")).ok_or("delivery.to (the webhook URL) is required for mode=webhook")?),
                    "announce" => match (s(d, "channel"), s(d, "to")) {
                        (Some(c), Some(t)) => format!("{c}:{t}"),
                        (Some(c), None) => c.to_string(),
                        (None, _) => "origin".into(),
                    },
                    m => return Err(format!("delivery.mode `{m}` must be none, announce or webhook")),
                },
            });
        }
        if let Some(w) = s(job, "wakeMode") {
            if !matches!(w, "now" | "next-heartbeat") {
                return Err("wakeMode must be now or next-heartbeat".into());
            }
            sp.wake_mode = Some(w.into());
        }
        if let Some(p) = job.get("pacing").filter(|v| v.is_object()) {
            let d = |k: &str, def: u64| s(p, k).map(|x| schedule::parse_duration_ms(x).map(|ms| ms / 1000)).transpose().map(|o| o.unwrap_or(def));
            sp.pacing = Some((d("min", 60)?, d("max", 3600)?));
        }
        if s(job, "sessionTarget") == Some("current") && !patch {
            // Runs continue this conversation (OpenClaw `sessionTarget:"current"`).
            sp.session = Some(ctx.session_id.clone()).filter(|x| !x.is_empty());
        }
        if job.get("enabled").and_then(Value::as_bool) == Some(false) {
            sp.paused = true;
            sp.paused_reason = Some("created disabled".into());
        }
        if let Some(w) = s(job, "workdir") {
            sp.workdir = Some(w.into());
        }
        sp.origin = Some(ctx.session_id.clone()).filter(|x| !x.is_empty());
        Ok(sp)
    }

    fn summary(&self, j: &Job) -> Value {
        json!({"id": j.id, "name": j.ext.name, "enabled": j.enabled, "schedule": j.ext.display.clone().unwrap_or_else(|| j.cron.clone()), "nextRunAt": j.enabled.then(|| crate::util::fmt_time(j.next_run, self.st.offset)), "lastRunAt": j.last_run.map(|t| crate::util::fmt_time(t, self.st.offset)), "lastStatus": j.ext.last_status, "kind": j.ext.kind.clone().unwrap_or_else(|| "agentTurn".into())})
    }
}

impl Tool for Automations {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "automations".into(),
            description: "Manage automations (scheduled jobs and wakes). Actions: status; list [includeDisabled,limit,offset]; get jobId; add job; update jobId job (partial patch, null clears); remove jobId; run jobId [runMode due|force, timeoutMs] (waits for the finished run); runs jobId; next_check in:\"15m\" (only inside a running self-paced job); wake text [mode now|next-heartbeat] (queue a system event for the heartbeat). job = {name, schedule:{kind:\"at\",at} | {kind:\"every\",everyMs} | {kind:\"cron\",expr,tz}, payload:{kind:\"agentTurn\",message} | {kind:\"systemEvent\",text}, delivery:{mode:\"none\"|\"announce\"|\"webhook\", channel, to}, sessionTarget:\"current\"|\"isolated\", wakeMode, pacing:{min,max}, enabled}. Use jobId from list; never guess.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["status", "list", "get", "add", "update", "remove", "run", "runs", "next_check", "wake"]},
                    "jobId": {"type": "string"},
                    "includeDisabled": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": LIST_MAX},
                    "offset": {"type": "integer", "minimum": 0},
                    "job": {"type": "object", "description": "Job (add) or partial patch (update)", "properties": {
                        "name": {"type": "string"},
                        "schedule": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["at", "every", "cron"]}, "at": {"type": "string", "description": "ISO-8601 time (kind=at)"}, "everyMs": {"type": "integer", "description": "Interval ms (kind=every, >= 60000)"}, "anchorMs": {"type": "integer"}, "expr": {"type": "string", "description": "Cron wall-time expr (kind=cron)"}, "tz": {"type": "string", "description": "IANA timezone or UTC±H for expr"}}},
                        "payload": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["agentTurn", "systemEvent"]}, "message": {"type": "string"}, "text": {"type": "string"}, "model": {"type": "string"}}},
                        "delivery": {"type": ["object", "null"], "properties": {"mode": {"type": "string", "enum": ["none", "announce", "webhook"]}, "channel": {"type": "string"}, "to": {"type": "string"}}},
                        "sessionTarget": {"type": "string", "enum": ["current", "isolated"]},
                        "wakeMode": {"type": "string", "enum": ["now", "next-heartbeat"]},
                        "pacing": {"type": "object", "properties": {"min": {"type": "string"}, "max": {"type": "string"}}},
                        "enabled": {"type": "boolean"},
                        "workdir": {"type": "string"}
                    }},
                    "runMode": {"type": "string", "enum": ["due", "force"]},
                    "timeoutMs": {"type": "integer"},
                    "in": {"type": "string", "description": "next_check delay, e.g. 15m"},
                    "text": {"type": "string", "description": "wake: system event text"},
                    "mode": {"type": "string", "enum": ["now", "next-heartbeat"]}
                },
                "required": ["action"]
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match s(input, "action") {
            Some("status" | "list" | "get" | "runs") => vec![Effect::Read { path: jobs_path(&ctx.home) }],
            Some("wake") => vec![Effect::Write { path: crate::wake::path(&ctx.home) }],
            _ => write_effects(ctx),
        }
    }

    fn call(&self, ctx: &ToolCtx, a: Value) -> ToolOutput {
        let data: PathBuf = ctx.home.clone();
        let action = s(&a, "action").unwrap_or("");
        if !matches!(action, "status" | "list" | "get" | "runs" | "next_check") && !self.st.allow_in_cron && in_cron_run(&data, &ctx.session_id) {
            return ToolOutput::err("Scheduled runs may only inspect automations (status/list/get/runs) or propose their own next_check.");
        }
        let id = || -> Result<Job, String> { find(&data, s(&a, "jobId").or_else(|| s(&a, "id")).ok_or("jobId required")?) };
        let r: Result<Value, String> = (|| match action {
            "status" => {
                let jobs: Vec<Job> = read_list(&jobs_path(&data))?;
                let next = jobs.iter().filter(|j| j.enabled).map(|j| j.next_run).min();
                let running = Host::of(ctx).map(|h| crate::daemon::call(&h.rt.paths.socket(), "ping", json!({})).is_ok());
                Ok(json!({"enabled": running.unwrap_or(true), "jobs": jobs.len(), "enabledJobs": jobs.iter().filter(|j| j.enabled).count(), "nextWakeAt": next.map(|t| crate::util::fmt_time(t, self.st.offset)), "pendingWakeEvents": crate::wake::pending(&data).len(), "provider": super::chronos::provider_name(&data)}))
            }
            "list" => {
                let include = a.get("includeDisabled").and_then(Value::as_bool).unwrap_or(false);
                let limit = a.get("limit").and_then(Value::as_u64).unwrap_or(50).clamp(1, LIST_MAX as u64) as usize;
                let offset = a.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let jobs: Vec<Job> = read_list::<Job>(&jobs_path(&data))?.into_iter().filter(|j| include || j.enabled).collect();
                let total = jobs.len();
                let page: Vec<Value> = jobs.iter().skip(offset).take(limit).map(|j| self.summary(j)).collect();
                let next = (offset + page.len() < total).then_some(offset + page.len());
                Ok(json!({"jobs": page, "total": total, "nextOffset": next}))
            }
            "get" => {
                let j = id()?;
                let mut v = format_job(&j, self.st.offset);
                v["prompt"] = json!(j.prompt);
                Ok(v)
            }
            "add" => {
                let job = a.get("job").ok_or("job is required for add")?;
                let j = create(&data, &self.st, self.spec(job, ctx, false)?, &ctx.workspace)?;
                let mut v = json!({"ok": true, "job": self.summary(&j)});
                if let Some(n) = daemon_note(ctx) {
                    v["note"] = json!(n);
                }
                Ok(v)
            }
            "update" => {
                let j = id()?;
                let patch = a.get("job").or_else(|| a.get("patch")).ok_or("job (partial patch) is required for update")?;
                let mut sp = self.spec(patch, ctx, true)?;
                sp.origin = None;
                let mut j = update(&data, &self.st, &j.id, sp)?;
                if let Some(e) = patch.get("enabled").and_then(Value::as_bool) {
                    j = set_paused(&data, &j.id, !e, (!e).then_some("disabled"))?;
                }
                Ok(json!({"ok": true, "job": self.summary(&j)}))
            }
            "remove" => {
                let j = id()?;
                let removed = remove_job(&data, &j.id)?;
                super::chronos::jobs_changed(&data);
                Ok(json!({"ok": true, "removed": removed, "id": j.id}))
            }
            "run" => {
                let j = id()?;
                let force = s(&a, "runMode") == Some("force");
                if !force && j.enabled && j.next_run > unix_now() {
                    return Ok(json!({"ok": true, "ran": false, "reason": "not-due", "nextRunAt": crate::util::fmt_time(j.next_run, self.st.offset)}));
                }
                let wait = Duration::from_millis(a.get("timeoutMs").and_then(Value::as_u64).unwrap_or(60_000).min(600_000));
                run_job(ctx, j, None, Some(wait))
            }
            "runs" => {
                let j = id()?;
                Ok(json!({"jobId": j.id, "runs": super::runs(&data, &j.id, 50)}))
            }
            "next_check" => {
                let d = s(&a, "in").ok_or("cron next_check in must be a positive duration")?;
                let ms = schedule::parse_duration_ms(d).map_err(|_| "cron next_check in must be a positive duration".to_string())?;
                if ms == 0 {
                    return Err("cron next_check in must be a positive duration".into());
                }
                let (job, secs) = next_check(&data, &ctx.session_id, ms / 1000)?;
                Ok(json!({"ok": true, "jobId": job, "delayMs": secs * 1000}))
            }
            "wake" => {
                let text = s(&a, "text").ok_or("text required")?;
                let mode = s(&a, "mode").unwrap_or("next-heartbeat");
                let ev = crate::wake::request(&data, text, mode, "automations")?;
                Ok(json!({"ok": true, "mode": ev.mode, "queued": crate::wake::pending(&data).len()}))
            }
            "" => Err("action required".into()),
            other => Err(format!("Unknown action: {other}")),
        })();
        match r {
            Ok(v) => out(v),
            Err(e) => ToolOutput::err(e),
        }
    }
}
