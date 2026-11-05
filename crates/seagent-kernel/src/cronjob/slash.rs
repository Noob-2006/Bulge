//! Native slash commands for automation, registered with `Kernel::add_slash`:
//! - `/loop [interval] <prompt> | status | stop [name]` (OpenClaw `commands-loop.ts`): a
//!   recurring job that re-runs the prompt in THIS session; without an interval it self-paces
//!   (default 15m, `automations next_check` between 1m and 1h);
//! - `/heartbeat` (alias `/hb`) `[status | on | off | run]` (Hermes `hermes_cli/heartbeat.py` +
//!   the CLI's `/heartbeat`): the daemon's proactive runner — its enable override, schedule,
//!   delivery target and last beat, or one beat right now;
//! - `/subgoal [text | remove N | clear]` (Hermes `goal_command.py` / `slash_commands_goals.py`):
//!   extra criteria on the active goal, read at the next round boundary;
//! - `/suggestions [accept N | dismiss N | catalog | clear]` (Hermes `suggestions_cmd.py`).

use super::{create, schedule, Settings, Spec};
use crate::automation::{self, goals_path, jobs_path, read_list, Goal, GoalStatus, Job};
use crate::heartbeat;
use crate::projection::project;
use crate::slash::{Slash, SlashCtx, SlashReply};
use std::path::PathBuf;

pub const LOOP_MIN_INTERVAL_SECS: u64 = 60;
pub const LOOP_DEFAULT_INTERVAL_SECS: u64 = 15 * 60;
pub const LOOP_NAME_MAX: usize = 40;
pub const LOOP_USAGE: &str = "Usage: /loop [interval] <prompt> — repeat a prompt in this chat (e.g. /loop 5m check deploy status). Without interval the loop self-paces between 1m and 1h. /loop status lists loops; /loop stop [name] stops.";

pub struct AutomationSlash;

/// Conversation tag baked into loop job names (OpenClaw `loopNamePrefix`): 48 bits of the
/// session id's hash, so status/stop only ever touch this conversation's loops.
pub fn loop_prefix(session: &str) -> String {
    // FNV-1a 64 → 12 hex chars (no crypto dependency in the kernel).
    let mut h: u64 = 0xcbf29ce484222325;
    for b in session.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("loop[{:012x}]", h & 0xffff_ffff_ffff)
}

fn session_ws(c: &SlashCtx, sid: &str) -> PathBuf {
    c.kernel.store.read(sid).ok().map(|e| PathBuf::from(project(&e).workspace)).filter(|p| p.is_dir()).unwrap_or_else(|| c.kernel.paths.data.clone())
}

pub fn loop_command(c: &SlashCtx, args: &str) -> Result<String, String> {
    let data = &c.kernel.paths.data;
    let spec = args.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("help") {
        return Ok(LOOP_USAGE.into());
    }
    let sid = c.session.as_deref().ok_or("no session yet — send a message first")?;
    let prefix = loop_prefix(sid);
    let mine = || -> Vec<Job> { read_list::<Job>(&jobs_path(data)).unwrap_or_default().into_iter().filter(|j| j.ext.name.as_deref().is_some_and(|n| n.starts_with(&prefix))).collect() };
    let st = Settings::from_config(&c.kernel.cfg);
    if spec.eq_ignore_ascii_case("status") {
        let l = mine();
        if l.is_empty() {
            return Ok("No loops in this conversation.".into());
        }
        return Ok(l.iter().map(|j| {
            let name = j.ext.name.as_deref().unwrap_or("").trim_start_matches(&prefix).trim();
            let pace = if j.ext.pacing.is_some() { "self-paced 1m–1h".to_string() } else { j.ext.display.clone().unwrap_or_else(|| j.cron.clone()) };
            format!("• {name} — {pace} · {} · next {} · last {}", if j.enabled { "on" } else { "off" }, if j.enabled { crate::util::fmt_time(j.next_run, st.offset) } else { "-".into() }, j.last_run.map(|t| crate::util::fmt_time(t, st.offset)).unwrap_or_else(|| "-".into()))
        }).collect::<Vec<_>>().join("\n"));
    }
    let first = spec.split_whitespace().next().unwrap_or("");
    if first.eq_ignore_ascii_case("stop") {
        let name = spec[first.len()..].trim().to_ascii_lowercase();
        let hits: Vec<Job> = mine().into_iter().filter(|j| name.is_empty() || j.ext.name.as_deref().unwrap_or("").to_ascii_lowercase().contains(&name)).collect();
        if hits.is_empty() {
            let active: Vec<String> = mine().iter().filter_map(|j| j.ext.name.as_deref().map(|n| n.trim_start_matches(&prefix).trim().to_string())).collect();
            return Ok(if active.is_empty() { "No loops in this conversation.".into() } else { format!("No loop matched. Active loops: {}", active.join(", ")) });
        }
        let mut names = Vec::new();
        for j in hits {
            automation::remove_job(data, &j.id)?;
            names.push(j.ext.name.unwrap_or_default().trim_start_matches(&prefix).trim().to_string());
        }
        super::chronos::jobs_changed(data);
        return Ok(format!("Stopped: {}", names.join(", ")));
    }
    // OpenClaw: a leading duration is the interval (bare numbers are ms); anything else is prompt text.
    let every = schedule::parse_duration_ms(first).ok().filter(|_| first.chars().any(|c| c.is_ascii_digit()));
    if let Some(ms) = every {
        if ms / 1000 < LOOP_MIN_INTERVAL_SECS {
            return Ok(format!("{LOOP_USAGE} Minimum interval 1m."));
        }
    }
    let prompt = if every.is_some() { spec[first.len()..].trim() } else { spec };
    if prompt.is_empty() {
        return Ok(LOOP_USAGE.into());
    }
    let short: String = prompt.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(LOOP_NAME_MAX).collect::<String>().trim_end().to_string();
    let self_paced = every.is_none();
    let secs = every.map(|ms| ms / 1000).unwrap_or(LOOP_DEFAULT_INTERVAL_SECS);
    let mut message = format!("[loop {short}] {prompt}\nDo the task and reply concisely. If nothing changed since the last run, reply briefly.");
    if self_paced {
        message.push_str("\nBefore replying, ALWAYS call the automations tool action:\"next_check\" with in:\"<duration>\" — pick the next check interval from how active the task is; back off toward 1h when quiet.");
    }
    let now = crate::util::unix_now();
    let sched = schedule::Sched { expr: format!("@every {}m", secs.div_ceil(60)), first_run: now + secs as i64, once: false, display: format!("every {}", schedule::human_secs(secs as i64)) };
    let ws = session_ws(c, sid);
    let job = create(data, &st, Spec { prompt: Some(message), sched: Some(sched), name: Some(format!("{prefix} {short}")), deliver: Some("origin".into()), origin: Some(sid.to_string()), session: Some(sid.to_string()), pacing: self_paced.then_some((60, 3600)), ..Default::default() }, &ws)?;
    let cadence = if self_paced { "self-paced (1m–1h)".to_string() } else { format!("every {}", schedule::human_secs(secs as i64)) };
    let mut out = format!("Loop '{short}' started — {cadence}. Use /loop stop to end it.");
    if crate::daemon::call(&c.kernel.paths.socket(), "ping", serde_json::json!({})).is_err() {
        out.push_str(" (seagentd is not running: loops fire only while `seagent daemon` runs.)");
    }
    let _ = job;
    Ok(out)
}

// ───────────────────────── /heartbeat ─────────────────────────

pub const HEARTBEAT_USAGE: &str = "Usage: /heartbeat [status | on | off | run] — the daemon's proactive heartbeat. `run` fires one beat now (it may take a while); `on`/`off` flip the override on top of `[heartbeat]` in the config.";

fn onoff(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

/// One readable paragraph about the heartbeat (config, override, schedule, last beat).
pub fn heartbeat_status(k: &crate::kernel::Kernel) -> String {
    let data = &k.paths.data;
    let global_on = heartbeat::enabled_override(data) != Some(false);
    let cfg = match heartbeat::HeartbeatConfig::from_table(&k.cfg.heartbeat) {
        Ok(Some(c)) => c,
        Ok(None) => return format!("♥ Heartbeat: not configured ({}). Add a [heartbeat] section with `every`, or set `target`/`prompt` with `seagent config set heartbeat.…`.", onoff(global_on)),
        Err(e) => return format!("⚠ Heartbeat: INVALID [heartbeat] config ({e}) — beats are skipped until it is fixed (`seagent config get heartbeat`)."),
    };
    let state = heartbeat::load_state(data);
    let mut out = format!("♥ Heartbeat: {} · every {} · target {}{}", onoff(global_on), schedule::human_secs(cfg.every_secs), cfg.target, if cfg.isolated_session { " · isolated session" } else { "" });
    if let Some(p) = cfg.prompt.as_deref().filter(|p| !p.trim().is_empty()) {
        out.push_str(&format!("\n  prompt: {}", term_line(p, 200)));
    }
    if let Some(h) = &cfg.active_hours {
        let win = match (h.start, h.end) {
            (Some(s), Some(e)) => format!("{:02}:{:02}–{:02}:{:02}", s / 60, s % 60, e / 60, e % 60),
            _ => "(any hour)".to_string(),
        };
        out.push_str(&format!("\n  active hours: {win}{}", h.timezone.as_deref().map(|z| format!(" ({z})")).unwrap_or_default()));
    }
    let due = state["next_due"].as_i64().unwrap_or(0);
    let now = crate::util::unix_now();
    let next = if !global_on {
        "paused — `/heartbeat on` resumes".to_string()
    } else if due == 0 {
        "next due at the next tick".to_string()
    } else if due <= now {
        "due now (waits for the daemon tick)".to_string()
    } else {
        format!("in {} ({})", schedule::human_secs(due - now), crate::util::fmt_time(due, k.cfg.schedule.utc_offset_minutes))
    };
    out.push_str(&format!("\n  next: {next}"));
    let last = heartbeat::last(data);
    if last.is_null() {
        out.push_str("\n  last: no heartbeat has run yet");
    } else {
        let at = last["at"].as_i64().map(|t| crate::util::fmt_time(t, k.cfg.schedule.utc_offset_minutes)).unwrap_or_else(|| "?".into());
        let status = last["status"].as_str().unwrap_or("?");
        let text = last["text"].as_str().unwrap_or("").trim();
        out.push_str(&format!("\n  last: {at} · {status}{}", if text.is_empty() { String::new() } else { format!(" · {}", term_line(text, 160)) }));
        if let Some(s) = last["session"].as_str() {
            out.push_str(&format!("\n  session: {s}"));
        }
    }
    if crate::daemon::call(&k.paths.socket(), "ping", serde_json::json!({})).is_err() {
        out.push_str("\n  (seagentd is not running: beats only fire while `seagent daemon` runs)");
    }
    out
}

fn term_line(s: &str, max: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= max {
        one
    } else {
        format!("{}…", one.chars().take(max).collect::<String>())
    }
}

/// `/heartbeat` (alias `/hb`): status | on | off | run.
pub fn heartbeat_command(c: &SlashCtx, args: &str) -> Result<String, String> {
    let k = &c.kernel;
    let data = &k.paths.data;
    let verb = args.trim().to_ascii_lowercase();
    match verb.split_whitespace().next().unwrap_or("status") {
        "" | "status" | "show" => Ok(heartbeat_status(k)),
        "on" | "enable" | "resume" => {
            heartbeat::set_enabled(data, true);
            Ok(format!("♥ Heartbeat enabled — the next daemon tick runs a beat.\n{}", heartbeat_status(k)))
        }
        "off" | "disable" | "pause" | "stop" => {
            heartbeat::set_enabled(data, false);
            Ok(format!("⏸ Heartbeat disabled — no beats until `/heartbeat on` (queued system events still wait).\n{}", heartbeat_status(k)))
        }
        "run" | "now" | "fire" | "tick" => {
            if heartbeat::enabled_override(data) == Some(false) {
                return Ok("Heartbeat is disabled (`/heartbeat on` first).".into());
            }
            let cfg = match heartbeat::HeartbeatConfig::from_table(&k.cfg.heartbeat) {
                Ok(Some(c)) => c,
                Ok(None) => return Err("heartbeat is not configured: add a [heartbeat] section (`seagent config set heartbeat.every 30m`)".into()),
                Err(e) => return Err(format!("[heartbeat] is invalid: {e}")),
            };
            let b = heartbeat::run_once(k, &cfg, crate::util::unix_now())?;
            let mut out = format!("♥ Heartbeat ran: {}{}", b.status, if b.notified { " (notified)" } else { "" });
            if !b.text.trim().is_empty() {
                out.push_str(&format!("\n  {}", term_line(&b.text, 500)));
            }
            if let Some(d) = &b.delivery {
                out.push_str(&format!("\n  delivered: {d}"));
            }
            if let Some(s) = &b.session {
                out.push_str(&format!("\n  session: {s}"));
            }
            Ok(out)
        }
        "help" => Ok(HEARTBEAT_USAGE.into()),
        other => Ok(format!("Unknown `/heartbeat {other}`.\n{HEARTBEAT_USAGE}")),
    }
}

/// The goal `/subgoal` applies to: the goal running in this session, else the single active one.
pub fn current_goal(data: &std::path::Path, session: Option<&str>) -> Result<Goal, String> {
    let goals: Vec<Goal> = read_list(&goals_path(data))?;
    if let Some(g) = session.and_then(|s| goals.iter().find(|g| g.session == s && matches!(g.status, GoalStatus::Active | GoalStatus::Paused))) {
        return Ok(g.clone());
    }
    let active: Vec<&Goal> = goals.iter().filter(|g| g.status == GoalStatus::Active).collect();
    match active.len() {
        1 => Ok(active[0].clone()),
        0 => Err("No active goal. Set one with /goal <text>.".into()),
        n => Err(format!("{n} goals are active; use `seagent goal subgoal <id> …` to pick one.")),
    }
}

pub fn subgoal_command(data: &std::path::Path, session: Option<&str>, args: &str) -> String {
    match current_goal(data, session) {
        Ok(g) => apply_subgoal(data, &g, args),
        Err(e) => e,
    }
}

/// `/subgoal` semantics on a specific goal (also `seagent goal subgoal <id> …`).
pub fn apply_subgoal(data: &std::path::Path, g: &Goal, args: &str) -> String {
    let args = args.trim();
    if args.is_empty() {
        let block = automation::render_subgoals(&g.subgoals);
        let status = format!("⊙ Goal ({:?}, {}/{} rounds): {}", g.status, g.rounds, g.max_rounds, g.objective).replace("Active", "active").replace("Paused", "paused");
        return format!("{status}\n{}", if block.is_empty() { "(no subgoals — use /subgoal <text> to add criteria)".into() } else { block });
    }
    let (verb, rest) = args.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((args, ""));
    match verb.to_ascii_lowercase().as_str() {
        "remove" => {
            if rest.is_empty() {
                return "Usage: /subgoal remove <n>".into();
            }
            let Ok(i) = rest.split_whitespace().next().unwrap_or("").parse::<usize>() else { return "/subgoal remove: <n> must be an integer (1-based index).".into() };
            match automation::remove_subgoal(data, &g.id, i) {
                Ok(t) => format!("✓ Removed subgoal {i}: {t}"),
                Err(e) => format!("/subgoal remove: {e}"),
            }
        }
        "clear" => match automation::clear_subgoals(data, &g.id) {
            Ok(0) => "No subgoals to clear.".into(),
            Ok(1) => "✓ Cleared 1 subgoal.".into(),
            Ok(n) => format!("✓ Cleared {n} subgoals."),
            Err(e) => format!("/subgoal clear: {e}"),
        },
        _ => match automation::add_subgoal(data, &g.id, args) {
            Ok(i) => format!("✓ Added subgoal {i}: {args}"),
            Err(e) => format!("/subgoal: {e}"),
        },
    }
}

impl Slash for AutomationSlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![
            ("loop".into(), "Re-run a prompt on a recurring interval in this session: /loop [interval] <prompt> | status | stop [name]".into()),
            ("heartbeat".into(), "The daemon's proactive heartbeat: /heartbeat [status | on | off | run] (alias /hb)".into()),
            ("hb".into(), "Alias of /heartbeat".into()),
            ("subgoal".into(), "Add or manage extra criteria on the active goal: /subgoal [text | remove N | clear]".into()),
            ("suggestions".into(), "Review suggested automations: /suggestions [accept N | dismiss N | catalog | clear]".into()),
        ]
    }
    fn run(&self, c: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        let data = c.kernel.paths.data.clone();
        Some(match name {
            "loop" | "proactive" => loop_command(c, args).map(SlashReply::text),
            "heartbeat" | "hb" => heartbeat_command(c, args).map(SlashReply::text),
            "subgoal" => Ok(SlashReply::text(subgoal_command(&data, c.session.as_deref(), args))),
            "suggestions" => {
                let st = Settings::from_config(&c.kernel.cfg);
                let ws = c.session.as_deref().map(|s| session_ws(c, s)).unwrap_or_else(|| data.clone());
                let surface = if c.surface == "channel" { "gateway" } else { "cli" };
                Ok(SlashReply::text(super::suggestions::command(&data, &st, args, &ws, c.session.as_deref(), surface)))
            }
            _ => return None,
        })
    }
}
