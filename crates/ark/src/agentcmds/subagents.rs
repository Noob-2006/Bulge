//! `/subagents list|info|log|help` and `/agents` (OpenClaw `commands-subagents.ts` and
//! `commands-subagents/action-*.ts`). ark's sub-agent runs are child sessions (`parent` = the
//! current session): `spawn`, `delegate_task`, `/review`, kanban workers. Active = running now,
//! recent = finished within the last 30 minutes. Targets resolve like upstream: `last`, a
//! 1-based index into active+recent, a session id (or prefix), or a label (exact, then prefix).

use super::{iso, now_ms, one_line, sid, text};
use crate::slash::{Ctx, Reply};
use ark_core::{Block, Role};
use ark_kernel::event::EventKind;
use ark_kernel::projection::project;
use ark_kernel::store::SessionInfo;

pub const RECENT_WINDOW_MINUTES: u64 = 30;

pub fn help() -> String {
    ["🧭 Subagents", "Usage:", "- /subagents list", "- /subagents info <id|#>", "- /subagents log <id|#> [limit] [tools]", "- /agents", "", "Ids: use the list index (#), `last`, a session id or a label."].join("\n")
}

pub struct Runs {
    pub active: Vec<SessionInfo>,
    pub recent: Vec<SessionInfo>,
    /// Every child, newest first.
    pub latest: Vec<SessionInfo>,
}

pub fn runs(c: &Ctx, parent: &str) -> Runs {
    let mut latest: Vec<SessionInfo> = c.k.store.list().into_iter().filter(|s| s.parent.as_deref() == Some(parent)).collect();
    latest.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms).then(b.created_ms.cmp(&a.created_ms)));
    let cutoff = now_ms().saturating_sub(RECENT_WINDOW_MINUTES * 60_000);
    let active: Vec<SessionInfo> = latest.iter().filter(|s| c.k.is_running(&s.id)).cloned().collect();
    let recent: Vec<SessionInfo> = latest.iter().filter(|s| !c.k.is_running(&s.id) && s.updated_ms >= cutoff).cloned().collect();
    Runs { active, recent, latest }
}

fn label(s: &SessionInfo) -> String {
    let raw = s.title.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| "subagent".into());
    one_line(&raw, 72)
}

fn ago(ms: u64) -> String {
    let d = now_ms().saturating_sub(ms) / 1000;
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86_399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86_400),
    }
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}

fn line(c: &Ctx, i: usize, s: &SessionInfo) -> String {
    let status = if c.k.is_running(&s.id) { "running".to_string() } else { last_outcome(c, &s.id).unwrap_or_else(|| "done".into()) };
    format!("{i}. {} · {status} · {} · {}", label(s), s.id, ago(s.updated_ms))
}

fn last_outcome(c: &Ctx, id: &str) -> Option<String> {
    c.k.store.read(id).ok()?.iter().rev().find_map(|e| match &e.kind {
        EventKind::TurnEnd { reason, .. } => Some(reason.clone()),
        _ => None,
    })
}

pub enum Target {
    Found(SessionInfo),
    Reply(String),
}

pub fn resolve(r: &Runs, token: Option<&str>) -> Target {
    let fail = |m: String| Target::Reply(format!("⚠️ {m}"));
    let Some(t) = token.map(str::trim).filter(|t| !t.is_empty()) else { return fail("Missing subagent id.".into()) };
    if t == "last" {
        return r.latest.first().cloned().map(Target::Found).unwrap_or_else(|| fail("Unknown subagent.".into()));
    }
    let order: Vec<&SessionInfo> = r.active.iter().chain(r.recent.iter()).collect();
    if t.chars().all(|ch| ch.is_ascii_digit()) {
        let n: usize = t.parse().unwrap_or(0);
        return n.checked_sub(1).and_then(|i| order.get(i)).map(|s| Target::Found((*s).clone())).unwrap_or_else(|| fail(format!("Invalid subagent index: {t}")));
    }
    if let Some(s) = r.latest.iter().find(|s| s.id == t) {
        return Target::Found(s.clone());
    }
    let lower = t.to_lowercase();
    for prefix in [false, true] {
        let m: Vec<&SessionInfo> = r.latest.iter().filter(|s| {
            let l = label(s).to_lowercase();
            if prefix { l.starts_with(&lower) } else { l == lower }
        }).collect();
        match m.len() {
            0 => {}
            1 => return Target::Found(m[0].clone()),
            _ => return fail(format!("Ambiguous subagent label{}: {t}", if prefix { " prefix" } else { "" })),
        }
    }
    let m: Vec<&SessionInfo> = r.latest.iter().filter(|s| s.id.starts_with(t)).collect();
    match m.len() {
        1 => Target::Found(m[0].clone()),
        0 => fail(format!("Unknown subagent id: {t}")),
        _ => fail(format!("Ambiguous run id prefix: {t}")),
    }
}

pub fn cmd_subagents(c: &Ctx, a: &str) -> Result<Reply, String> {
    let toks: Vec<&str> = a.split_whitespace().collect();
    let action = toks.first().map(|s| s.to_lowercase()).unwrap_or_else(|| "list".into());
    let action = if matches!(action.as_str(), "list" | "info" | "log") { action } else { "help".into() };
    if action == "help" {
        return text(help());
    }
    let Ok(id) = sid(c) else { return text("⚠️ Missing session key.") };
    let r = runs(c, id);
    match action.as_str() {
        "list" => {
            let fmt = |rows: &[SessionInfo], start: usize| if rows.is_empty() { "(none)".to_string() } else { rows.iter().enumerate().map(|(i, s)| line(c, start + i + 1, s)).collect::<Vec<_>>().join("\n") };
            text(["active subagents:".to_string(), "-----".into(), fmt(&r.active, 0), String::new(), format!("recent subagents (last {RECENT_WINDOW_MINUTES}m):"), "-----".into(), fmt(&r.recent, r.active.len())].join("\n"))
        }
        "info" => {
            if toks.len() < 2 {
                return text("ℹ️ Usage: /subagents info <id|#>");
            }
            let s = match resolve(&r, toks.get(1).copied()) {
                Target::Found(s) => s,
                Target::Reply(m) => return text(m),
            };
            let events = c.k.store.read(&s.id).map_err(|e| e.to_string())?;
            let v = project(&events);
            let started = events.iter().find(|e| matches!(e.kind, EventKind::TurnStart { .. })).map(|e| e.ts);
            let ended = if c.k.is_running(&s.id) { None } else { events.iter().rev().find(|e| matches!(e.kind, EventKind::TurnEnd { .. })).map(|e| e.ts) };
            let task = events.iter().find_map(|e| match &e.kind {
                EventKind::Message { message, .. } if message.role == Role::User => Some(message.text()),
                _ => None,
            }).unwrap_or_default();
            let outcome = if c.k.is_running(&s.id) { "n/a".to_string() } else { last_outcome(c, &s.id).unwrap_or_else(|| "n/a".into()) };
            let progress = v.messages.iter().rev().find(|m| m.role == Role::Assistant && !m.text().trim().is_empty()).map(|m| one_line(&m.text(), 300));
            let ts = |t: Option<u64>| t.map(|t| format!("{} ({})", iso(t), ago(t))).unwrap_or_else(|| "n/a".into());
            let mut lines = vec![
                "ℹ️ Subagent info".to_string(),
                format!("Status: {}", if c.k.is_running(&s.id) { "running" } else { "done" }),
                format!("Label: {}", label(&s)),
                format!("Task: {}", if task.trim().is_empty() { "n/a".into() } else { one_line(&task, 500) }),
                format!("Session: {}", s.id),
                format!("Model: {}", v.model),
                format!("Runtime: {}", started.map(|st| duration(ended.unwrap_or_else(now_ms).saturating_sub(st))).unwrap_or_else(|| "n/a".into())),
                format!("Created: {}", ts(Some(s.created_ms))),
                format!("Started: {}", ts(started)),
                format!("Ended: {}", ts(ended)),
                format!("Outcome: {outcome}"),
                format!("Tokens: {}", v.usage.total()),
            ];
            if let Some(p) = progress {
                lines.push(format!("Progress: {p}"));
            }
            text(lines.join("\n"))
        }
        _ => {
            if toks.len() < 2 {
                return text("📜 Usage: /subagents log <id|#> [limit]");
            }
            let tools = toks.iter().any(|t| t.eq_ignore_ascii_case("tools"));
            let limit = toks.iter().skip(2).find_map(|t| t.parse::<usize>().ok()).map(|n| n.clamp(1, 200)).unwrap_or(20);
            let s = match resolve(&r, toks.get(1).copied()) {
                Target::Found(s) => s,
                Target::Reply(m) => return text(m),
            };
            let v = project(&c.k.store.read(&s.id).map_err(|e| e.to_string())?);
            let mut lines = vec![];
            for m in &v.messages {
                let is_tool = m.content.iter().any(|b| matches!(b, Block::ToolUse { .. } | Block::ToolResult { .. }));
                if is_tool && !tools {
                    // Text alongside a tool call still counts; pure tool traffic is stripped.
                    if m.text().trim().is_empty() {
                        continue;
                    }
                }
                let mut t = m.text();
                if tools {
                    for b in &m.content {
                        match b {
                            Block::ToolUse { name, input, .. } => t.push_str(&format!(" [tool {name} {}]", one_line(&input.to_string(), 120))),
                            Block::ToolResult { content, .. } => t.push_str(&format!(" [result {}]", one_line(content, 120))),
                            _ => {}
                        }
                    }
                }
                if t.trim().is_empty() {
                    continue;
                }
                lines.push(format!("{}: {}", if m.role == Role::Assistant { "Assistant" } else { "User" }, t.trim()));
            }
            let skip = lines.len().saturating_sub(limit);
            let body = if lines.is_empty() { "(no messages)".to_string() } else { lines[skip..].join("\n") };
            text(format!("📜 Subagent log: {}\n{body}", label(&s)))
        }
    }
}

/// `/agents`: active runs plus those bound to a chat, and this session's own chat bindings.
pub fn cmd_agents(c: &Ctx, _: &str) -> Result<Reply, String> {
    let Ok(id) = sid(c) else { return text("⚠️ Missing session key.") };
    let r = runs(c, id);
    let routes = super::bindings::router().map(|rt| rt.routes()).unwrap_or_default();
    let bound = |s: &str| routes.iter().find(|x| x.session == s).map(|x| format!("{}:{}", x.key.channel, x.key.chat));
    let order: Vec<&SessionInfo> = r.active.iter().chain(r.recent.iter()).collect();
    let mut lines = vec!["agents:".to_string(), "-----".into()];
    let visible: Vec<&SessionInfo> = r.latest.iter().filter(|s| c.k.is_running(&s.id) || bound(&s.id).is_some()).collect();
    if visible.is_empty() {
        lines.push("(none)".into());
    }
    for s in visible {
        let prefix = order.iter().position(|o| o.id == s.id).map(|i| format!("{}.", i + 1)).unwrap_or_else(|| "-".into());
        let b = match bound(&s.id) {
            Some(x) => format!("binding:{x}"),
            None if super::bindings::router().is_some() => "unbound".into(),
            None => "bindings unavailable".into(),
        };
        // A worker spawned with `thread:true` / `visible:true` says where the user finds it.
        let extra = match (ark_kernel::threads::by_session(&c.k.paths, &s.id), ark_kernel::threads::visible_of(&c.k.paths, &s.id)) {
            (Some(t), _) => format!(", thread:{}#{}", t.channel, t.thread),
            (None, Some(v)) => format!(", sidebar:{}", if v.status.is_empty() { "session".into() } else { v.status }),
            (None, None) => String::new(),
        };
        lines.push(format!("{prefix} {} ({b}{extra})", label(s)));
    }
    let mine: Vec<String> = routes.iter().filter(|x| x.session == id).map(|x| format!("- {} (binding:{}:{}, session:{id})", x.key.chat, x.key.channel, x.key.chat)).collect();
    if !mine.is_empty() {
        lines.extend(["".into(), "session bindings:".into(), "-----".into()]);
        lines.extend(mine);
    }
    text(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::super::tests::ctx;
    use crate::slash;
    use crate::testkit::kit;
    use ark_kernel::kernel::RunOpts;

    #[test]
    fn list_info_log_resolution_and_agents() {
        let t = kit();
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        let c = ctx(&t.k, &t.ws, Some(id.clone()));
        let out = |l: &str| slash::run(&c, l).unwrap().text.unwrap();
        assert!(out("/subagents").contains("active subagents:\n-----\n(none)"));
        assert!(out("/subagents nope").contains("/subagents info <id|#>"), "unknown action shows help");
        for task in ["write the parser", "write the tests"] {
            let child = t.k.create_session(&t.ws, None, Some(&id), Some(task)).unwrap();
            t.k.submit(&child, task, "parent").unwrap();
            t.k.run(&child, RunOpts::default()).unwrap();
        }
        let l = out("/subagents list");
        assert!(l.contains("recent subagents (last 30m):") && l.contains("1. ") && l.contains("2. ") && l.contains("write the tests"), "{l}");
        let i = out("/subagents info last");
        assert!(i.contains("ℹ️ Subagent info") && i.contains("Status: done") && i.contains("Outcome: ") && i.contains("Task: ") && i.contains("write the"), "{i}");
        assert!(out("/subagents info write the").contains("Ambiguous") || out("/subagents info write").contains("Ambiguous"), "label prefix is ambiguous");
        assert!(out("/subagents info 9").contains("Invalid subagent index: 9"));
        assert!(out("/subagents info").contains("Usage: /subagents info"));
        let lg = out("/subagents log 1");
        assert!(lg.starts_with("📜 Subagent log: ") && lg.contains("User: ") && lg.contains("write the") && lg.contains("Assistant: reply:"), "{lg}");
        assert!(out("/agents").contains("agents:\n-----\n(none)"), "finished, unbound runs are hidden");
        let none = ctx(&t.k, &t.ws, None);
        assert_eq!(slash::run(&none, "/subagents list").unwrap().text.unwrap(), "⚠️ Missing session key.");
    }
}
