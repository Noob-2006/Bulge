//! Multiple named agents, routing bindings and the users registry
//! (OpenClaw src/routing, `openclaw agents add|bind|unbind|set-identity|delete`,
//! `openclaw users`, personal instructions; Hermes profiles as named agents).
//!
//! Agents come from `[agents.<id>]` in config.toml and from `<config>/agents.toml`
//! (managed by `ark agents`; same shape, it wins on conflicts). The implicit
//! agent `main` is ark's top-level configuration. A session records the agent it
//! runs as (`Agent` event); the agent's model, workspace, persona and tool list
//! shape the session. Bindings route channel traffic to agents, most specific
//! match first: peer → parent peer (thread) → user → peer wildcard (by chat
//! kind) → account → channel → the default agent.

use crate::approver::{ClarifyQuestion, ClarifyReply, RECOMMENDED};
use crate::config::{Config, Paths};
use crate::event::{now_ms, EventKind};
use crate::hooks::{self, HookEvent};
use crate::kernel::{Host, KernelError, RunOpts, Runtime};
use crate::projection::{project, View};
use crate::store::{SessionInfo, Store};
use ark_core::{Effect, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const MAIN: &str = "main";

/// Model-facing session / agent tools (`sessions`, `sessions_create`, `sessions_list`,
/// `sessions_history`, `sessions_send`, `clarify`). Registered by `new_kernel`; each one
/// reaches the kernel through [`Host::of`].
pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(Sessions), Arc::new(SessionsCreate), Arc::new(SessionsList), Arc::new(SessionsHistory), Arc::new(SessionsSend), Arc::new(Clarify)]
}

// ───────────────────────── tool argument helpers ─────────────────────────

/// The kernel host behind a tool context (None for foreign hosts, e.g. plain tests).
fn kernel_host<'a>(ctx: &'a ToolCtx, tool: &str) -> Result<&'a Host, ToolOutput> {
    Host::of(ctx).ok_or_else(|| ToolOutput::err(format!("{tool} needs the ark kernel (this host has no session runtime)")))
}

fn json_out(v: &Value) -> ToolOutput {
    ToolOutput::ok(serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()))
}

/// First present string argument, trimmed; empty = absent.
fn arg_str(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| input.get(*k).and_then(Value::as_str)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn arg_bool(input: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|k| input.get(*k)).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn arg_usize(input: &Value, keys: &[&str]) -> Option<usize> {
    keys.iter().find_map(|k| input.get(*k)).and_then(|v| match v {
        Value::Number(n) => n.as_u64().map(|n| n as usize),
        Value::String(s) => s.trim().parse::<usize>().ok(),
        _ => None,
    })
}

/// `session` / `session_id` / `sessionKey` — the target session of a tool call.
fn session_arg(input: &Value) -> Option<String> {
    arg_str(input, &["session", "session_id", "sessionKey", "sessionId"])
}

/// `no session \`x\``, pointing at the inventory tool (the most common model mistake).
fn no_session(id: &str) -> String {
    format!("no session `{id}` (see sessions_list for the session inventory)")
}

fn ensure_session(rt: &Runtime, id: &str) -> Result<(), String> {
    if rt.store.exists(id) {
        Ok(())
    } else {
        Err(no_session(id))
    }
}

fn view_of(rt: &Runtime, id: &str) -> Result<View, String> {
    rt.store.read(id).map(|e| project(&e)).map_err(|_| no_session(id))
}

/// One line of a transcript: what search and reads see.
struct Msg {
    seq: u64,
    ts: u64,
    role: &'static str,
    text: String,
}

/// The transcript of a session, in log order (tool-only turns are labelled, not dropped).
/// Rewound turns are hidden — undo means undone — while compacted or pruned history stays
/// readable, which is the whole point of recall.
fn messages_of(store: &Store, id: &str) -> Result<Vec<Msg>, String> {
    let events = store.read(id).map_err(|_| no_session(id))?;
    let rewinds: Vec<(u64, u64)> = events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Rewind { from_seq, .. } => Some((*from_seq, e.seq)),
            _ => None,
        })
        .collect();
    let mut out = Vec::new();
    for ev in &events {
        if rewinds.iter().any(|(from, at)| *from <= ev.seq && ev.seq < *at) {
            continue;
        }
        let EventKind::Message { message, .. } = &ev.kind else { continue };
        let mut text = message.text();
        if text.trim().is_empty() {
            let tools: Vec<&str> = message.tool_uses().map(|(_, n, _)| n).collect();
            if tools.is_empty() {
                continue;
            }
            text = format!("[called {}]", tools.join(", "));
        }
        out.push(Msg { seq: ev.seq, ts: ev.ts, role: if message.role == Role::User { "user" } else { "assistant" }, text });
    }
    Ok(out)
}

// ───────────────────────── session_search ─────────────────────────

/// `session_search` input schema (Hermes `tools/session_search_tool.py`): the plain
/// query, plus read/scroll of one session and date / role / session filters.
pub fn session_search_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Text to look for: case-insensitive substring, works for Chinese. Omit to browse recent sessions (or, with `session` + `read`, to read one transcript)."},
            "session": {"type": "string", "description": "Session id (from sessions_list or an earlier hit). Restricts the search to it; with `read` (or alone) it selects the transcript to read."},
            "sessionKey": {"type": "string", "description": "Alias of `session` (OpenClaw spelling)."},
            "read": {"type": "boolean", "description": "Read that session's messages instead of searching: the last `limit` messages, or the page starting at `offset`."},
            "scroll": {"type": "boolean", "description": "With `read`: page FORWARD from `offset` (default 0) and return next_offset so the next call continues where this one stopped. Without `read` it implies reading `session`."},
            "offset": {"type": "integer", "minimum": 0, "description": "Where the read page starts (0-based over the session's messages, oldest first)."},
            "limit": {"type": "integer", "minimum": 1, "description": "Max hits (default 10, max 50), or max messages for a read (default 20, max 500)."},
            "role": {"type": "string", "description": "Only these roles: user | assistant (comma-separated for both). Tool output is never matched."},
            "role_filter": {"type": "string", "description": "Hermes spelling of `role`."},
            "after": {"type": "string", "description": "Only messages at or after this time: an ISO date or date-time (2026-07-01, 2026-07-01T09:30) or a relative span (24h, 7d, 2w)."},
            "before": {"type": "string", "description": "Only messages before this time (same formats as `after`; a date-only value means midnight UTC)."},
            "summary": {"type": "boolean", "description": "One block per session instead of one line per hit: hit count, time range and the first sentence of the first hit."}
        },
        "required": []
    })
}

/// `session_search` (kernel tool): search past sessions' messages, read or scroll one
/// transcript, filter by session/role/time, or summarise the hits per session.
pub fn session_search(store: &Store, input: &Value) -> String {
    match session_search_inner(store, input) {
        Ok(s) => s,
        Err(e) => format!("session_search: {e}"),
    }
}

/// `after` / `before`: ISO date or date-time, or a relative span (`24h`, `7d`, `2w`).
fn time_bound(v: &str) -> Result<u64, String> {
    let bad = || format!("invalid time bound `{v}` (expected a date like 2026-07-01, a date-time like 2026-07-01T09:30, or a span like 24h / 7d / 2w)");
    let t = v.trim();
    if t.is_empty() {
        return Err(bad());
    }
    let lower = t.to_ascii_lowercase();
    if let Some(unit) = lower.chars().last().filter(|c| matches!(c, 'h' | 'd' | 'w')) {
        if let Ok(n) = lower[..lower.len() - 1].trim().parse::<u64>() {
            let secs = match unit {
                'h' => 3_600,
                'd' => 86_400,
                _ => 604_800,
            };
            return Ok((now_ms() / 1000).saturating_sub(n.saturating_mul(secs)) * 1000);
        }
    }
    let (date, rest) = t.split_once(['T', ' ']).unwrap_or((t, ""));
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 {
        return Err(bad());
    }
    let (y, mo, dy) = match (d[0].parse::<i64>(), d[1].parse::<u32>(), d[2].parse::<u32>()) {
        (Ok(y), Ok(mo), Ok(dy)) if (1..=12).contains(&mo) && (1..=31).contains(&dy) => (y, mo, dy),
        _ => return Err(bad()),
    };
    let mut secs = crate::util::days_from_civil(y, mo, dy) * 86_400;
    let mut rest = rest.trim();
    if let Some(r) = rest.strip_suffix(['Z', 'z']) {
        rest = r.trim();
    }
    let mut off = 0i64;
    if let Some(pos) = rest.rfind(['+', '-']).filter(|p| *p > 0) {
        let sign = if rest.as_bytes()[pos] == b'-' { -1 } else { 1 };
        let hhmm = &rest[pos + 1..];
        let (h, mi) = hhmm.split_once(':').unwrap_or((hhmm, "0"));
        match (h.parse::<i64>(), mi.parse::<i64>()) {
            (Ok(h), Ok(mi)) => off = sign * (h * 3600 + mi * 60),
            _ => return Err(bad()),
        }
        rest = rest[..pos].trim();
    }
    if !rest.is_empty() {
        let p: Vec<&str> = rest.split(':').collect();
        let (h, mi, s) = match p.len() {
            2..=3 => (p[0].parse::<i64>().ok(), p[1].parse::<i64>().ok(), p.get(2).map(|x| x.parse::<i64>().ok()).unwrap_or(Some(0))),
            _ => (None, None, None),
        };
        match (h, mi, s) {
            (Some(h), Some(mi), Some(s)) if (0..24).contains(&h) && (0..60).contains(&mi) && (0..60).contains(&s) => secs += h * 3600 + mi * 60 + s,
            _ => return Err(bad()),
        }
    }
    Ok((secs - off).max(0) as u64 * 1000)
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn show_time(ms: u64) -> String {
    crate::util::fmt_time((ms / 1000) as i64, 0)
}

/// Text around a hit, one line, `±60` bytes.
fn snippet(text: &str, lower: &str, pos: usize, qlen: usize) -> String {
    let src = if lower.len() == text.len() { text } else { lower };
    let mut a = pos.saturating_sub(60);
    while a > 0 && !src.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = (pos + qlen + 60).min(src.len());
    while b < src.len() && !src.is_char_boundary(b) {
        b += 1;
    }
    src[a..b].replace('\n', " ")
}

fn first_sentence(text: &str) -> String {
    let flat = text.replace('\n', " ");
    let t = flat.trim();
    let end = t.find(['.', '。', '!', '?', '！', '？']).filter(|i| *i < 240).map(|i| i + 1).unwrap_or(t.len());
    clip(t[..end].trim(), 240)
}

/// Role / time filters shared by every shape.
#[derive(Default)]
struct Filters {
    /// None = user + assistant.
    roles: Option<Vec<&'static str>>,
    after: Option<u64>,
    before: Option<u64>,
}

impl Filters {
    fn ok(&self, m: &Msg) -> bool {
        if let Some(r) = &self.roles {
            if !r.contains(&m.role) {
                return false;
            }
        }
        self.after.is_none_or(|a| m.ts >= a) && self.before.is_none_or(|b| m.ts < b)
    }
}

fn parse_filters(input: &Value) -> Result<Filters, String> {
    let roles = match arg_str(input, &["role", "role_filter", "roleFilter"]) {
        None => None,
        Some(s) => {
            let mut v: Vec<&'static str> = Vec::new();
            for tok in s.split(',') {
                match tok.trim().to_ascii_lowercase().as_str() {
                    "" => {}
                    "user" | "human" => v.push("user"),
                    "assistant" | "agent" | "ai" => v.push("assistant"),
                    "tool" | "tools" | "tool_result" => return Err("tool output is not indexed; filter on user or assistant".into()),
                    other => return Err(format!("unknown role `{other}`: use user, assistant or both (comma-separated)")),
                }
            }
            Some(v).filter(|v| !v.is_empty())
        }
    };
    let after = input.get("after").and_then(Value::as_str).map(time_bound).transpose()?;
    let before = input.get("before").and_then(Value::as_str).map(time_bound).transpose()?;
    Ok(Filters { roles, after, before })
}

/// `session_search` over the SQLite index; `None` = the index is unavailable (scan instead).
fn session_search_indexed(store: &Store, query: &str, sid: Option<&str>, filters: &Filters, limit: usize, summary: bool) -> Option<String> {
    use crate::sqlindex::{search_messages, session_title, sync_sessions, MsgFilter};
    let data = store.root().parent()?.to_path_buf();
    sync_sessions(&data, store.root()).ok()?;
    let f = MsgFilter { session: sid.map(str::to_string), roles: filters.roles.as_ref().map(|r| r.iter().map(|x| x.to_string()).collect()), after: filters.after, before: filters.before };
    let q = query.to_lowercase();
    if !summary {
        let hits = search_messages(&data, query, &f, limit).ok()?;
        let lines: Vec<String> = hits
            .iter()
            .map(|h| {
                let lower = h.text.to_lowercase();
                let pos = lower.find(&q).unwrap_or(0);
                format!("{} #{} [{}] {}", h.session, h.seq, h.role, snippet(&h.text, &lower, pos, q.len()))
            })
            .collect();
        return Some(if lines.is_empty() { "no matches".into() } else { lines.join("\n") });
    }
    let hits = search_messages(&data, query, &f, 20_000).ok()?;
    // Group per session, most recently matched session first; hits within one oldest first.
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<&crate::sqlindex::MsgHit>> = BTreeMap::new();
    for h in &hits {
        if !groups.contains_key(&h.session) {
            order.push(h.session.clone());
        }
        groups.entry(h.session.clone()).or_default().push(h);
    }
    let mut blocks = Vec::new();
    for id in order.into_iter().take(limit) {
        let mut g = groups.remove(&id).unwrap_or_default();
        g.sort_by_key(|h| (h.ts, h.seq));
        let (first, last) = (g[0], g[g.len() - 1]);
        let title = session_title(&data, &id).filter(|t| !t.is_empty()).unwrap_or_else(|| "(untitled)".into());
        blocks.push(format!("{} · {} hit(s) · {} → {}\n  {}\n  [{}] {}", id, g.len(), show_time(first.ts), show_time(last.ts), title, first.role, first_sentence(&first.text)));
    }
    Some(if blocks.is_empty() { "no matches".into() } else { blocks.join("\n\n") })
}

fn session_search_inner(store: &Store, input: &Value) -> Result<String, String> {
    let query = arg_str(input, &["query"]).unwrap_or_default();
    let sid = session_arg(input);
    let read = arg_bool(input, &["read"]).unwrap_or(false);
    let scroll = arg_bool(input, &["scroll"]).unwrap_or(false);
    let summary = arg_bool(input, &["summary"]).unwrap_or(false);
    let offset = arg_usize(input, &["offset"]);
    let filters = parse_filters(input)?;

    if read || scroll || (sid.is_some() && query.is_empty()) {
        let sid = sid.ok_or("reading needs `session` (an id from sessions_list or a previous hit)")?;
        let limit = arg_usize(input, &["limit"]).unwrap_or(20).clamp(1, 500);
        let mut rows: Vec<Msg> = messages_of(store, &sid)?.into_iter().filter(|m| filters.ok(m)).collect();
        let total = rows.len();
        let scroll = scroll || (offset.is_some() && read);
        let start = if scroll {
            offset.unwrap_or(0).min(total)
        } else {
            offset.map(|o| o.min(total)).unwrap_or_else(|| total.saturating_sub(limit))
        };
        let end = (start + limit).min(total);
        let page: Vec<Value> = rows.drain(start..end).map(|m| json!({"seq": m.seq, "role": m.role, "when": show_time(m.ts), "text": clip(&m.text, 2000)})).collect();
        let more = end < total;
        let hint = if scroll {
            if more {
                format!("scroll on with {{\"session\":\"{sid}\",\"read\":true,\"scroll\":true,\"offset\":{end}}}")
            } else {
                "end of the session".to_string()
            }
        } else if start > 0 && more {
            format!("{start} message(s) before this page and {} after it; offset pages from either end, scroll pages forward", total - end)
        } else if start > 0 {
            format!("{start} message(s) before this page")
        } else if more {
            format!("{} message(s) after this page; read offset {end} (or scroll) for the rest", total - end)
        } else {
            String::new()
        };
        return Ok(serde_json::to_string_pretty(&json!({
            "mode": if scroll { "scroll" } else { "read" },
            "session": sid,
            "total": total,
            "offset": start,
            "returned": page.len(),
            "next_offset": more.then_some(end),
            "has_more": more,
            "messages": page,
            "hint": hint,
        }))
        .unwrap_or_default());
    }

    let limit = arg_usize(input, &["limit"]).unwrap_or(10).clamp(1, 50);

    // The SQLite index (FTS5 over every session's messages, synced incrementally from the
    // JSONL logs) answers queries and summaries; the linear log scan below stays as the
    // fallback when the index cannot be opened.
    if summary || !query.is_empty() {
        if let Some(out) = session_search_indexed(store, &query, sid.as_deref(), &filters, limit, summary) {
            return Ok(out);
        }
    }

    if summary {
        let q = query.to_lowercase();
        let mut blocks = Vec::new();
        for info in store.list() {
            if sid.as_deref().is_some_and(|s| s != info.id) {
                continue;
            }
            let Ok(rows) = messages_of(store, &info.id) else { continue };
            let hits: Vec<&Msg> = rows.iter().filter(|m| filters.ok(m) && (q.is_empty() || m.text.to_lowercase().contains(&q))).collect();
            if hits.is_empty() {
                continue;
            }
            let (first, last) = (hits[0], hits[hits.len() - 1]);
            let title = info.title.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| "(untitled)".into());
            blocks.push(format!(
                "{} · {} hit(s) · {} → {}\n  {}\n  [{}] {}",
                info.id,
                hits.len(),
                show_time(first.ts),
                show_time(last.ts),
                title,
                first.role,
                first_sentence(&first.text)
            ));
            if blocks.len() >= limit {
                break;
            }
        }
        return Ok(if blocks.is_empty() { "no matches".into() } else { blocks.join("\n\n") });
    }

    if query.is_empty() {
        // Browse: the most recently active sessions.
        let mut out = Vec::new();
        for info in store.list() {
            if sid.as_deref().is_some_and(|s| s != info.id) {
                continue;
            }
            let preview = messages_of(store, &info.id).ok().and_then(|m| m.into_iter().find(|m| m.role == "user")).map(|m| first_sentence(&m.text)).unwrap_or_default();
            out.push(format!("{} · {} messages · {} · {}", info.id, info.messages, show_time(info.updated_ms), info.title.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| "(untitled)".into())));
            if !preview.is_empty() {
                out.push(format!("  {preview}"));
            }
            if out.len() >= limit * 2 {
                break;
            }
        }
        return Ok(if out.is_empty() { "no sessions yet".into() } else { out.join("\n") });
    }

    let q = query.to_lowercase();
    let mut lines = Vec::new();
    'sessions: for info in store.list() {
        if sid.as_deref().is_some_and(|s| s != info.id) {
            continue;
        }
        let Ok(rows) = messages_of(store, &info.id) else { continue };
        for m in rows.iter().rev() {
            if !filters.ok(m) {
                continue;
            }
            let lower = m.text.to_lowercase();
            let Some(pos) = lower.find(&q) else { continue };
            lines.push(format!("{} #{} [{}] {}", info.id, m.seq, m.role, snippet(&m.text, &lower, pos, q.len())));
            if lines.len() >= limit {
                break 'sessions;
            }
        }
    }
    Ok(if lines.is_empty() { "no matches".into() } else { lines.join("\n") })
}

/// `[agents.<id>]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentDef {
    /// Display name.
    pub name: String,
    pub description: String,
    /// `provider/model`; empty = `model.default`.
    pub model: String,
    /// Workspace directory (`~` allowed); empty = wherever the session is created.
    pub workspace: String,
    /// Persona / standing instructions appended to the identity segment.
    pub identity: String,
    pub emoji: String,
    pub theme: String,
    pub avatar: String,
    /// Only these tools / toolsets (empty = all).
    pub tools_allow: Vec<String>,
    pub tools_deny: Vec<String>,
    /// Routing default when no binding matches (at most one agent).
    pub default: bool,
    /// Role: a team seed this agent was created from (coordinator, researcher, writer,
    /// reviewer — it seeded `identity`), or an occupation (a preset id or role-pack slug from
    /// `share/roles`, see crate::roles) assembled into the agent's `role` segment.
    pub role: String,
}

/// `[[bindings]]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Binding {
    pub agent: String,
    /// Channel name (`[channels.<name>]`), or `*`.
    pub channel: String,
    /// Channel account (multi-account channels); empty = any.
    pub account: String,
    /// Chat or sender id; `*` = any peer of `peer_kind`; empty = no peer constraint.
    pub peer: String,
    /// `direct`, `group` or empty (any).
    pub peer_kind: String,
    /// Users-registry id: matches any identity linked to that user.
    pub user: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct AgentsFile {
    agents: BTreeMap<String, AgentDef>,
    bindings: Vec<Binding>,
}

pub fn agents_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("agents.toml")
}

fn read_file(paths: &Paths) -> Result<AgentsFile, String> {
    let p = agents_file(paths);
    match std::fs::read_to_string(&p) {
        Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AgentsFile::default()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

fn write_file(paths: &Paths, f: &AgentsFile) -> Result<(), String> {
    let text = format!("# Managed by `ark agents` — named agents and routing bindings.\n{}", toml::to_string_pretty(f).map_err(|e| e.to_string())?);
    crate::util::atomic_write(&agents_file(paths), text.as_bytes()).map_err(|e| e.to_string())
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().next().is_some_and(|c| c.is_ascii_lowercase()) && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Every configured agent (config, then agents.toml), plus `main`.
pub fn all(cfg: &Config, paths: &Paths) -> BTreeMap<String, AgentDef> {
    let mut m = cfg.agents.clone();
    if let Ok(f) = read_file(paths) {
        m.extend(f.agents);
    }
    m.entry(MAIN.into()).or_insert_with(|| AgentDef { name: "Ark".into(), description: "the default agent".into(), ..Default::default() });
    m
}

pub fn bindings(cfg: &Config, paths: &Paths) -> Vec<Binding> {
    let mut b = cfg.bindings.clone();
    if let Ok(f) = read_file(paths) {
        b.extend(f.bindings);
    }
    b
}

pub fn default_agent(cfg: &Config, paths: &Paths) -> String {
    all(cfg, paths).into_iter().find(|(_, a)| a.default).map(|(id, _)| id).unwrap_or_else(|| MAIN.into())
}

/// What a session running as an agent gets.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub id: String,
    pub name: String,
    pub model: Option<String>,
    pub workspace: Option<PathBuf>,
    pub identity: Option<String>,
    pub tools_allow: Option<Vec<String>>,
    pub tools_deny: Vec<String>,
    /// Occupation (preset id or pack slug) when `role` is not a team seed.
    pub role: Option<String>,
}

pub fn resolve(cfg: &Config, paths: &Paths, id: &str) -> Option<Resolved> {
    let a = all(cfg, paths).remove(id)?;
    let ne = |s: &str| Some(s.to_string()).filter(|s| !s.trim().is_empty());
    let mut identity = ne(&a.identity);
    if identity.is_none() && (!a.name.is_empty() && id != MAIN) {
        identity = Some(format!("You are {}{}, one of several named agents on this machine.", a.name, if a.emoji.is_empty() { String::new() } else { format!(" {}", a.emoji) }));
    }
    Some(Resolved {
        id: id.to_string(),
        name: if a.name.is_empty() { id.to_string() } else { a.name.clone() },
        model: ne(&a.model),
        workspace: ne(&a.workspace).map(|w| ark_core::tool::expand_home(&w)),
        identity,
        tools_allow: Some(a.tools_allow.clone()).filter(|t| !t.is_empty()),
        tools_deny: a.tools_deny.clone(),
        role: Some(a.role.trim().to_string()).filter(|r| !r.is_empty() && !crate::roles::TEAM_SEEDS.contains(&r.as_str())),
    })
}

/// Who/where an inbound message came from.
#[derive(Debug, Clone, Default)]
pub struct RouteInput<'a> {
    pub channel: &'a str,
    pub account: &'a str,
    pub chat: &'a str,
    pub sender: &'a str,
    /// `direct` or `group`.
    pub kind: &'a str,
    /// Users-registry id of the sender, when known.
    pub user: Option<&'a str>,
}

/// One routing tier: its name and the predicate a binding must satisfy.
type Tier<'a> = (&'static str, &'a dyn Fn(&Binding) -> bool);

/// (agent id, matched_by) for an inbound message.
pub fn route(bindings: &[Binding], default: &str, i: &RouteInput) -> (String, &'static str) {
    let chan_ok = |b: &Binding| b.channel == "*" || b.channel == i.channel;
    let acct_ok = |b: &Binding| b.account.is_empty() || b.account == i.account;
    let kind_ok = |b: &Binding| b.peer_kind.is_empty() || b.peer_kind == i.kind;
    let parent = i.chat.split_once(":thread:").map(|(p, _)| p);
    let tiers: [Tier; 6] = [
        ("binding.peer", &|b| !b.peer.is_empty() && b.peer != "*" && (b.peer == i.chat || b.peer == i.sender) && kind_ok(b)),
        ("binding.peer.parent", &|b| !b.peer.is_empty() && b.peer != "*" && parent.is_some_and(|p| b.peer == p) && kind_ok(b)),
        ("binding.user", &|b| !b.user.is_empty() && i.user == Some(b.user.as_str())),
        ("binding.peer.wildcard", &|b| b.peer == "*" && kind_ok(b) && b.user.is_empty()),
        ("binding.account", &|b| b.peer.is_empty() && b.user.is_empty() && !b.account.is_empty()),
        ("binding.channel", &|b| b.peer.is_empty() && b.user.is_empty() && b.account.is_empty()),
    ];
    for (name, f) in tiers {
        if let Some(b) = bindings.iter().find(|b| chan_ok(b) && acct_ok(b) && f(b)) {
            return (b.agent.clone(), name);
        }
    }
    (default.to_string(), "default")
}

// ───────────────────────── `ark agents` edits ─────────────────────────

/// Role seeds for `ark agents add --role` (OpenClaw team roles).
pub fn role_identity(role: &str) -> Option<&'static str> {
    Some(match role {
        "coordinator" => "You coordinate a team of specialist agents: break work into tasks, delegate them (sessions_spawn with agentId / delegate_task), check their results and report back. Do little hands-on work yourself.",
        "researcher" => "You are a researcher: gather facts from files, the web and past sessions, cite where each fact came from, and separate evidence from inference.",
        "writer" => "You are a writer: turn notes and findings into clear, well-structured prose in the requested tone and language.",
        "reviewer" => "You are a reviewer: read the work critically, check claims against the source, and list concrete problems by severity before any praise.",
        _ => return None,
    })
}

pub fn add(paths: &Paths, id: &str, def: AgentDef) -> Result<(), String> {
    if !valid_id(id) {
        return Err(format!("agent id `{id}`: start with a lowercase letter; then lowercase letters, digits, - or _"));
    }
    if id == MAIN {
        return Err("`main` is the built-in default agent".into());
    }
    let mut f = read_file(paths)?;
    if f.agents.contains_key(id) {
        return Err(format!("agent `{id}` already exists"));
    }
    if def.default {
        f.agents.values_mut().for_each(|a| a.default = false);
    }
    f.agents.insert(id.into(), def);
    write_file(paths, &f)
}

pub fn update(paths: &Paths, id: &str, edit: impl FnOnce(&mut AgentDef)) -> Result<(), String> {
    let mut f = read_file(paths)?;
    let a = f.agents.get_mut(id).ok_or_else(|| format!("agent `{id}` is not managed by `ark agents` (edit config.toml instead)"))?;
    edit(a);
    if a.default {
        let id = id.to_string();
        f.agents.iter_mut().filter(|(k, _)| **k != id).for_each(|(_, a)| a.default = false);
    }
    write_file(paths, &f)
}

/// Delete an agent and its bindings. Sessions stay (they keep the agent id).
pub fn delete(paths: &Paths, id: &str) -> Result<usize, String> {
    let mut f = read_file(paths)?;
    if f.agents.remove(id).is_none() {
        return Err(format!("agent `{id}` is not managed by `ark agents`"));
    }
    let before = f.bindings.len();
    f.bindings.retain(|b| b.agent != id);
    let n = before - f.bindings.len();
    write_file(paths, &f)?;
    Ok(n)
}

/// `channel[:account]` → binding (OpenClaw `--bind`), optional peer.
pub fn parse_bind(agent: &str, spec: &str, peer: Option<&str>) -> Result<Binding, String> {
    let (channel, account) = spec.split_once(':').unwrap_or((spec, ""));
    if channel.is_empty() {
        return Err(format!("--bind `{spec}`: expected channel[:account]"));
    }
    let (peer_kind, peer) = match peer {
        Some(p) => match p.split_once(':') {
            Some((k @ ("direct" | "group"), id)) => (k.to_string(), id.to_string()),
            _ => (String::new(), p.to_string()),
        },
        None => (String::new(), String::new()),
    };
    Ok(Binding { agent: agent.into(), channel: channel.into(), account: account.into(), peer, peer_kind, user: String::new() })
}

pub fn bind(cfg: &Config, paths: &Paths, b: Binding) -> Result<bool, String> {
    if !all(cfg, paths).contains_key(&b.agent) {
        return Err(format!("unknown agent `{}`", b.agent));
    }
    let mut f = read_file(paths)?;
    if f.bindings.contains(&b) {
        return Ok(false);
    }
    f.bindings.push(b);
    write_file(paths, &f)?;
    Ok(true)
}

/// Remove bindings of `agent` matching `spec` (`channel[:account]`), or all of them.
pub fn unbind(paths: &Paths, agent: &str, spec: Option<&str>) -> Result<usize, String> {
    let mut f = read_file(paths)?;
    let before = f.bindings.len();
    let (ch, acct) = spec.map(|s| s.split_once(':').unwrap_or((s, ""))).unwrap_or(("", ""));
    f.bindings.retain(|b| !(b.agent == agent && (spec.is_none() || (b.channel == ch && (acct.is_empty() || b.account == acct)))));
    let n = before - f.bindings.len();
    write_file(paths, &f)?;
    Ok(n)
}

// ───────────────────────── users registry ─────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub channel: String,
    pub sender: String,
}

/// A durable user profile (OpenClaw `users`), with personal instructions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    pub id: String,
    pub name: String,
    pub emails: Vec<String>,
    pub identities: Vec<Identity>,
    /// Personal instructions added to sessions this user starts.
    pub instructions: String,
    pub created_ms: u64,
}

pub fn users_path(paths: &Paths) -> PathBuf {
    paths.data.join("users.json")
}

pub fn users(paths: &Paths) -> Vec<User> {
    std::fs::read_to_string(users_path(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_users(paths: &Paths, u: &[User]) -> Result<(), String> {
    crate::util::atomic_write(&users_path(paths), serde_json::to_string_pretty(u).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())
}

pub fn user_add(paths: &Paths, name: &str) -> Result<User, String> {
    if name.trim().is_empty() {
        return Err("user name must not be empty".into());
    }
    let mut all = users(paths);
    let u = User { id: format!("u-{}", crate::util::random_hex(8)), name: name.trim().into(), created_ms: now_ms(), ..Default::default() };
    all.push(u.clone());
    save_users(paths, &all)?;
    Ok(u)
}

fn edit_user(paths: &Paths, id: &str, f: impl FnOnce(&mut User) -> Result<(), String>) -> Result<User, String> {
    let mut all = users(paths);
    let u = all.iter_mut().find(|u| u.id == id || u.name.eq_ignore_ascii_case(id)).ok_or_else(|| format!("no user `{id}`"))?;
    f(u)?;
    let out = u.clone();
    save_users(paths, &all)?;
    Ok(out)
}

pub fn user_link_email(paths: &Paths, id: &str, email: &str) -> Result<User, String> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(format!("`{email}` is not an email address"));
    }
    if let Some(o) = users(paths).into_iter().find(|u| u.emails.contains(&email) && u.id != id) {
        return Err(format!("{email} already belongs to {} ({}); merge the profiles instead", o.name, o.id));
    }
    edit_user(paths, id, |u| {
        if !u.emails.contains(&email) {
            u.emails.push(email);
        }
        Ok(())
    })
}

pub fn user_link(paths: &Paths, id: &str, channel: &str, sender: &str) -> Result<User, String> {
    if let Some(o) = find_user(paths, channel, sender).filter(|o| o.id != id) {
        return Err(format!("{channel}:{sender} already belongs to {} ({})", o.name, o.id));
    }
    edit_user(paths, id, |u| {
        let i = Identity { channel: channel.into(), sender: sender.into() };
        if !u.identities.contains(&i) {
            u.identities.push(i);
        }
        Ok(())
    })
}

pub fn user_set_instructions(paths: &Paths, id: &str, text: &str) -> Result<User, String> {
    edit_user(paths, id, |u| {
        u.instructions = text.trim().chars().take(8000).collect();
        Ok(())
    })
}

/// Fold `source` into `into` (emails, identities, instructions) and delete it.
pub fn user_merge(paths: &Paths, source: &str, into: &str) -> Result<User, String> {
    let mut all = users(paths);
    let si = all.iter().position(|u| u.id == source).ok_or_else(|| format!("no user `{source}`"))?;
    if !all.iter().any(|u| u.id == into) || source == into {
        return Err(format!("no surviving user `{into}`"));
    }
    let s = all.remove(si);
    let t = all.iter_mut().find(|u| u.id == into).unwrap();
    for e in s.emails {
        if !t.emails.contains(&e) {
            t.emails.push(e);
        }
    }
    for i in s.identities {
        if !t.identities.contains(&i) {
            t.identities.push(i);
        }
    }
    if !s.instructions.is_empty() && !t.instructions.contains(&s.instructions) {
        t.instructions = format!("{}\n{}", t.instructions, s.instructions).trim().to_string();
    }
    let out = t.clone();
    save_users(paths, &all)?;
    Ok(out)
}

pub fn user_remove(paths: &Paths, id: &str) -> Result<(), String> {
    let mut all = users(paths);
    let n = all.len();
    all.retain(|u| u.id != id);
    if all.len() == n {
        return Err(format!("no user `{id}`"));
    }
    save_users(paths, &all)
}

pub fn find_user(paths: &Paths, channel: &str, sender: &str) -> Option<User> {
    users(paths).into_iter().find(|u| u.identities.iter().any(|i| (i.channel == channel || i.channel == "*") && i.sender == sender) || (channel == "email" && u.emails.iter().any(|e| e.eq_ignore_ascii_case(sender))))
}

pub fn get_user(paths: &Paths, id: &str) -> Option<User> {
    users(paths).into_iter().find(|u| u.id == id)
}

// ───────────────────────── sessions as an agent ─────────────────────────

impl Runtime {
    /// Rewind the conversation `turns` user turns (Hermes `hermes_state_rewind.py`, `/undo N`,
    /// `/retry`): the log stays append-only — a `Rewind` event hides everything from the
    /// first rewound message on. Returns the seq the next turn continues from.
    pub fn rewind(&self, session: &str, turns: u64) -> Result<u64, String> {
        if turns == 0 {
            return Err("nothing to rewind (turns must be at least 1)".into());
        }
        if self.is_running(session) {
            return Err("a turn is still running — stop it first".into());
        }
        let events = self.store.read(session).map_err(|e| e.to_string())?;
        let v = crate::projection::project(&events);
        let n = v.user_turns.len();
        if (turns as usize) > n {
            return Err(format!("only {n} turn(s) in this conversation; cannot rewind {turns}"));
        }
        let from = v.user_turns[n - turns as usize];
        self.record(session, EventKind::Rewind { from_seq: from, turns }).map_err(|e| e.to_string())?;
        Ok(from)
    }

    /// Fork the conversation into a new session (OpenClaw `/branch`, `ark session fork`):
    /// everything up to now, or up to `turns` user turns back. Returns the new session id.
    pub fn branch(&self, session: &str, turns: Option<u64>) -> Result<String, String> {
        let events = self.store.read(session).map_err(|e| e.to_string())?;
        let v = crate::projection::project(&events);
        let keep = match turns.filter(|t| *t > 0) {
            Some(t) => {
                let n = v.user_turns.len();
                if (t as usize) > n {
                    return Err(format!("only {n} turn(s) in this conversation; cannot branch at {t}"));
                }
                v.message_seqs.iter().position(|s| *s >= v.user_turns[n - t as usize])
            }
            None => None,
        };
        // Without a cut point: everything, minus a trailing half-finished exchange.
        let upto = keep.unwrap_or(v.messages.len() - usize::from(!v.dangling.is_empty() && v.messages.len() > 1));
        let first = v.messages.first().map(|m| m.text().chars().take(40).collect::<String>()).unwrap_or_else(|| session.chars().take(8).collect());
        let new = self.create_session(Path::new(&v.workspace), Some(&v.model), v.parent.as_deref(), Some(&format!("branch of {first}"))).map_err(|e| e.to_string())?;
        let mut log = self.store.open(&new).map_err(|e| e.to_string())?;
        for m in v.messages.iter().take(upto) {
            log.append(EventKind::Message { message: m.clone(), usage: None, model: None, inbox: None }).map_err(|e| e.to_string())?;
        }
        Ok(new)
    }

    /// Set (or clear) the run's output contract: the next turns must submit `structured_output`
    /// matching `schema` (OpenClaw `structured-output-tool.ts`; Hermes output contracts).
    pub fn set_output_schema(&self, session: &str, schema: Option<serde_json::Value>) -> Result<(), String> {
        let schema = schema.filter(|s| !s.is_null());
        if let Some(s) = &schema {
            crate::jsonschema::coerce_schema(Some(s))?.ok_or("output_schema must be a JSON Schema object")?;
        }
        self.record(session, EventKind::OutputSchema { schema: schema.unwrap_or(serde_json::Value::Null) }).map_err(|e| e.to_string())
    }

    /// Create a session that runs as `agent` (None = default agent) for `user`.
    /// The agent's workspace wins over `workspace` when set.
    pub fn create_agent_session(&self, workspace: &Path, agent: Option<&str>, user: Option<&str>, model: Option<&str>, parent: Option<&str>, title: Option<&str>) -> Result<String, KernelError> {
        let id = agent.filter(|a| !a.is_empty()).map(str::to_string).unwrap_or_else(|| default_agent(&self.cfg, &self.paths));
        let a = resolve(&self.cfg, &self.paths, &id).ok_or_else(|| KernelError::Invalid(format!("unknown agent `{id}`")))?;
        let ws = a.workspace.clone().filter(|w| w.is_dir()).unwrap_or_else(|| workspace.to_path_buf());
        let model = model.map(str::to_string).or(a.model.clone());
        // The agent's occupation replaces the config's `role` segment; its preset's tool profile
        // narrows the tools unless the agent lists its own. Resolved first: an unknown role
        // fails before any session exists.
        let role = match a.role.as_deref() {
            Some(r) => Some(crate::roles::resolve(&self.cfg, &crate::roles::Catalog::for_config(&self.cfg), r).map_err(KernelError::Invalid)?),
            None => None,
        };
        let sid = self.create_session(&ws, model.as_deref(), parent, title)?;
        let u = user.and_then(|u| get_user(&self.paths, u));
        if id == MAIN && u.is_none() && a.identity.is_none() && a.tools_allow.is_none() && a.tools_deny.is_empty() && a.role.is_none() {
            return Ok(sid);
        }
        let mut log = self.store.open(&sid)?;
        self.append(&mut log, EventKind::Agent { agent: id.clone(), user: u.as_ref().map(|u| u.id.clone()) })?;
        let allow = a.tools_allow.clone().or_else(|| role.as_ref().and_then(|r| r.tool_profile()).and_then(|p| ark_security::toolpolicy::profile(p).flatten()));
        if allow.is_some() || !a.tools_deny.is_empty() {
            self.append(&mut log, EventKind::Tools { allow: allow.as_ref().map(|t| crate::subagents::expand_tools(t)), deny: a.tools_deny.clone() })?;
        }
        if let Some(r) = &role {
            let mut v = crate::projection::project(log.events());
            v.system.retain(|s| s.id != crate::roles::SEGMENT_ID);
            let at = v.system.iter().position(|s| s.id == "identity").map(|i| i + 1).unwrap_or(0);
            v.system.insert(at, r.segment());
            self.append(&mut log, EventKind::System { segments: v.system })?;
        }
        let mut extra = Vec::new();
        if let Some(i) = &a.identity {
            extra.push(i.clone());
        }
        if let Some(u) = u.as_ref().filter(|u| !u.instructions.is_empty()) {
            extra.push(format!("# Personal instructions from {} (applies to this conversation)\n{}", u.name, u.instructions));
        }
        if !extra.is_empty() {
            let mut v = crate::projection::project(log.events());
            if let Some(seg) = v.system.iter_mut().find(|s| s.id == "identity") {
                seg.text = format!("{}\n\n{}", seg.text, extra.join("\n\n"));
            }
            self.append(&mut log, EventKind::System { segments: v.system })?;
        }
        Ok(sid)
    }
}

// ───────────────────────── `sessions` ─────────────────────────

/// `sessions` (OpenClaw src/agents/tools/sessions-tool.ts + sessions-tool-patch.ts):
/// sidebar settings, lifecycle control and the output contract, all by session id.
pub struct Sessions;

const SESSIONS_DESCRIPTION: &str = "Read or change a session's settings, stop or reset it, undo turns, fork it, or set the output contract of this run (OpenClaw sessions). `action` (default \"patch\") with `session` (default: this session):\n\n- patch: `label` renames the session (empty string clears it), `pinned` / `archived` (booleans), `group` (sidebar group; empty string ungroups) and `status` (short status line; empty string clears it). Any subset; only the fields you pass change.\n- status: model, workspace, agent, running state, turn/message counts, waiting input, settings and the current output contract.\n- list: the sessions_list rows; accepts sessions_list's filters (limit, archived, pinned, group, query, include_children).\n- stop: cancel the session's running turn. Queued input is kept.\n- reset: end the session (session_end hooks fire, reason \"reset\"); the transcript is kept and stays readable.\n- rewind: hide the last `turns` user turns (default 1) — this is the `/undo` a chat user asks for on an IDLE session; the running caller cannot rewind itself (its own messages are part of the rewind), so finish the turn and let the user undo, or rewind another idle session.\n- branch: copy the conversation into a NEW session (all of it, or up to `turns` user turns back) and return its id — the way to explore an alternative without disturbing the original; continue there with sessions_send.\n- schema: set the run's output contract — `schema` is a JSON Schema object for the final answer, or null to clear it. While it is set the model MUST submit through `structured_output`; a prose answer does not end the turn (it is nudged), so set it only when the caller asked for machine-readable output.\n\nSettings are events, so they apply even while the session runs in another process (a session that is mid-turn sees them at its next step; `patch`/`schema` echo what was applied). Only touch other sessions when the user asked for it; nothing here deletes a session.";

fn sessions_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["patch", "status", "list", "stop", "reset", "rewind", "branch", "schema"], "description": "Default \"patch\"."},
            "session": {"type": "string", "description": "Target session id (sessions_list). Default: this session."},
            "sessionKey": {"type": "string", "description": "OpenClaw spelling of `session`."},
            "turns": {"type": "integer", "minimum": 1, "description": "action=rewind: user turns to hide (default 1). action=branch: keep only up to this many turns back (omit for the whole conversation)."},
            "label": {"type": "string", "description": "patch: sidebar title; empty string clears it."},
            "pinned": {"type": "boolean", "description": "patch: pin the session to the top of lists."},
            "archived": {"type": "boolean", "description": "patch: true archives (hidden from sessions_list by default), false restores."},
            "group": {"type": ["string", "null"], "description": "patch: sidebar group; null or empty clears it."},
            "status": {"type": "string", "description": "patch: short status line; empty string clears it."},
            "schema": {"type": ["object", "null"], "description": "action=schema: JSON Schema the final answer must match (or a JSON string holding one); null clears the contract."},
            "limit": {"type": "integer", "minimum": 1, "description": "action=list: max rows (default 20, max 200)."},
            "query": {"type": "string", "description": "action=list: only sessions whose id or title contains this text."},
            "group_filter": {"type": "string", "description": "action=list: only sessions in this group (empty = ungrouped)."},
            "include_children": {"type": "boolean", "description": "action=list: include hidden sub-agent / child sessions (default true). Children published by sessions_spawn visible:true or bound to a channel thread are always listed."}
        },
        "required": []
    })
}

impl Tool for Sessions {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions".into(), description: SESSIONS_DESCRIPTION.into(), input_schema: sessions_schema(), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions") else { return ToolOutput::err("sessions needs the ark kernel") };
        match sessions_action(host, &input) {
            Ok(v) => json_out(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn sessions_action(host: &Host, input: &Value) -> Result<Value, String> {
    let rt = &host.rt;
    let action = arg_str(input, &["action"]).map(|a| a.to_ascii_lowercase()).unwrap_or_else(|| "patch".into());
    let target = session_arg(input).unwrap_or_else(|| host.session.clone());
    match action.as_str() {
        "patch" => {
            ensure_session(rt, &target)?;
            for k in ["pinned", "archived"] {
                if input.get(k).is_some_and(|v| !v.is_null()) && arg_bool(input, &[k]).is_none() {
                    return Err(format!("`{k}` must be true or false"));
                }
            }
            let mut applied = serde_json::Map::new();
            if let Some(label) = input.get("label").and_then(Value::as_str) {
                let title: String = label.trim().chars().take(80).collect();
                rt.record(&target, EventKind::Title { title: title.clone() }).map_err(|e| e.to_string())?;
                applied.insert("label".into(), json!(title));
            }
            let pinned = arg_bool(input, &["pinned"]);
            let archived = arg_bool(input, &["archived"]);
            let group = input.get("group").filter(|v| !v.is_null()).map(|_| arg_str(input, &["group"]).unwrap_or_default().chars().take(60).collect::<String>());
            let status = input.get("status").filter(|v| !v.is_null()).map(|_| arg_str(input, &["status"]).unwrap_or_default().chars().take(120).collect::<String>());
            if pinned.is_some() || archived.is_some() || group.is_some() || status.is_some() {
                rt.record(&target, EventKind::Meta { pinned, archived, group: group.clone(), status: status.clone() }).map_err(|e| e.to_string())?;
                for (k, v) in [("pinned", json!(pinned)), ("archived", json!(archived)), ("group", json!(group)), ("status", json!(status))] {
                    if !v.is_null() {
                        applied.insert(k.into(), v);
                    }
                }
            }
            if applied.is_empty() {
                return Err("patch needs at least one of label, pinned, archived, group or status (use action=\"schema\" for an output contract, action=\"status\" to read)".into());
            }
            let view = view_of(rt, &target)?;
            // A running session only sees the events at its next step: echo what was applied.
            let mut row = session_row(rt, None, &view);
            for (k, v) in [("label", "title"), ("pinned", "pinned"), ("archived", "archived"), ("group", "group"), ("status", "status")] {
                if let Some(val) = applied.get(k) {
                    row[v] = val.clone();
                }
            }
            Ok(json!({"action": "patch", "sessionKey": target, "applied": applied, "session": row}))
        }
        "schema" => {
            ensure_session(rt, &target)?;
            let Some(schema) = input.get("schema") else {
                return Err("action=\"schema\" needs `schema`: a JSON Schema object the final answer must match, or null to clear it".into());
            };
            let schema = Some(schema.clone()).filter(|s| !s.is_null());
            rt.set_output_schema(&target, schema.clone())?;
            // The event lands at the end of this step when the session is running, so report
            // what was set rather than re-reading the log.
            Ok(json!({
                "action": "schema",
                "sessionKey": target,
                "output_schema": schema,
                "structured_output_tool": schema.is_some(),
                "note": if schema.is_some() {
                    "the output contract applies from the next turn: the kernel rebuilds its tool list at turn start, and the answer must then be submitted through structured_output (a prose answer is nudged, not accepted)"
                } else {
                    "output contract cleared; it applies from the next turn"
                },
            }))
        }
        "status" => {
            ensure_session(rt, &target)?;
            let view = view_of(rt, &target)?;
            let mut row = session_row(rt, None, &view);
            row["pending_input"] = json!(view.pending_inbox.iter().map(|q| q.2.clone()).collect::<Vec<_>>());
            row["thinking"] = json!(view.thinking);
            row["structured"] = json!(view.structured);
            Ok(json!({"action": "status", "session": row}))
        }
        "rewind" => {
            ensure_session(rt, &target)?;
            let turns = arg_usize(input, &["turns"]).unwrap_or(1).max(1) as u64;
            if target == host.session && rt.is_running(&target) {
                return Err("cannot rewind the session that is running this turn: its own messages are part of the rewind. Finish this turn and undo from the chat (/undo), or rewind an idle session".into());
            }
            let from = rt.rewind(&target, turns)?;
            Ok(json!({
                "action": "rewind",
                "sessionKey": target,
                "turns": turns,
                "from_seq": from,
                "note": "the log stays append-only: everything from from_seq on is hidden from the next turn on",
            }))
        }
        "branch" => {
            ensure_session(rt, &target)?;
            let turns = arg_usize(input, &["turns"]).map(|t| t as u64);
            let new = rt.branch(&target, turns)?;
            let view = view_of(rt, &new)?;
            Ok(json!({
                "action": "branch",
                "sessionKey": target,
                "new_session": new,
                "messages": view.messages.len(),
                "note": "a new session holding a copy of this conversation (up to the requested turn); the original is untouched — continue there with sessions_send",
            }))
        }
        "list" => {
            let mut list_input = input.clone();
            if let Some(g) = arg_str(input, &["group_filter"]) {
                list_input["group"] = json!(g);
            }
            Ok(json!({"action": "list", "sessions": list_rows(rt, &list_input)?}))
        }
        "stop" => {
            ensure_session(rt, &target)?;
            let was = rt.is_running(&target);
            let stopped = rt.interrupt(&target);
            Ok(json!({
                "action": "stop",
                "sessionKey": target,
                "wasRunning": was,
                "stopped": stopped,
                "note": if stopped { "cancelled the running turn; input already queued is kept" } else { "the session was not running" },
            }))
        }
        "reset" => {
            ensure_session(rt, &target)?;
            let was = rt.is_running(&target);
            // Never cut the caller's own turn: a self-reset only ends the session logically.
            if was && target != host.session {
                rt.interrupt(&target);
            }
            rt.end_session(&target, "reset");
            Ok(json!({
                "action": "reset",
                "sessionKey": target,
                "wasRunning": was,
                "reset": true,
                "note": "session_end hooks fired (reason \"reset\"); the transcript is kept and stays readable",
            }))
        }
        other => Err(format!("unknown action `{other}`; use patch, status, list, stop, reset or schema")),
    }
}

// ───────────────────────── row rendering ─────────────────────────

fn session_row(rt: &Runtime, info: Option<&SessionInfo>, view: &View) -> Value {
    let id = if view.session_id.is_empty() { info.map(|i| i.id.clone()).unwrap_or_default() } else { view.session_id.clone() };
    let title = view.title.clone().filter(|t| !t.trim().is_empty()).or_else(|| info.and_then(|i| i.title.clone()).filter(|t| !t.trim().is_empty()));
    // `sessions_spawn visible:true` publishes the child as a sidebar session; `thread:true`
    // binds it to a channel thread. Both are visible in this row (OpenClaw sessions_list).
    let sidebar = crate::threads::visible_of(&rt.paths, &id);
    let thread = crate::threads::by_session(&rt.paths, &id);
    json!({
        "visible": sidebar.is_some(),
        "status_line": sidebar.as_ref().map(|v| v.status.clone()),
        "thread": thread.as_ref().map(|b| b.as_json()),
        "id": id,
        "sessionKey": id,
        "title": title,
        "model": view.model,
        "workspace": view.workspace,
        "agent": view.agent,
        "user": view.user,
        "parent": view.parent,
        "created": info.map(|i| i.created_ms).unwrap_or(0),
        "updated": info.map(|i| i.updated_ms).unwrap_or(0),
        "messages": info.map(|i| i.messages).unwrap_or_else(|| view.messages.len()),
        "turns": view.turns,
        "pinned": view.pinned,
        "archived": view.archived,
        "group": view.group,
        "status": view.status,
        "running": rt.is_running(&id),
        "output_schema": view.output_schema,
    })
}

/// `sessions_list` rows: newest activity first, filtered by the tool's arguments.
fn list_rows(rt: &Runtime, input: &Value) -> Result<Vec<Value>, String> {
    let limit = arg_usize(input, &["limit"]).unwrap_or(20).clamp(1, 200);
    let include_children = arg_bool(input, &["include_children", "includeChildren"]).unwrap_or(true);
    let archived = arg_bool(input, &["archived"]).unwrap_or(false);
    let pinned = arg_bool(input, &["pinned"]);
    let group = arg_str(input, &["group"]).or_else(|| arg_str(input, &["group_filter"]));
    let q = arg_str(input, &["query", "title", "search"]).map(|s| s.to_lowercase());
    let mut out = Vec::new();
    for info in rt.store.list() {
        let Ok(view) = view_of(rt, &info.id) else { continue };
        if view.archived && !archived {
            continue;
        }
        if pinned.is_some_and(|p| view.pinned != p) {
            continue;
        }
        if let Some(g) = &group {
            let hit = if g.is_empty() { view.group.is_none() } else { view.group.as_deref() == Some(g.as_str()) };
            if !hit {
                continue;
            }
        }
        // A child the user was told about (`visible:true`, or a thread they can talk in)
        // stays in the sidebar; only hidden helpers need include_children.
        let published = !include_children
            && info.parent.is_some()
            && crate::threads::visible_of(&rt.paths, &info.id).is_none()
            && crate::threads::by_session(&rt.paths, &info.id).is_none();
        if published {
            continue;
        }
        if let Some(q) = &q {
            let hay = format!("{} {}", view.title.clone().unwrap_or_default(), info.id).to_lowercase();
            if !hay.contains(q) {
                continue;
            }
        }
        out.push(session_row(rt, Some(&info), &view));
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

// ───────────────────────── `sessions_create` ─────────────────────────

/// `sessions_create` (OpenClaw src/agents/tools/sessions-create-tool.ts): a new
/// independent, persistent session, optionally running as a configured agent.
pub struct SessionsCreate;

const SESSIONS_CREATE_DESCRIPTION: &str = "Create a new independent, persistent session (OpenClaw sessions_create). Use it only when the user explicitly asks for a new session or task, or when work must continue in its own conversation; a bounded helper task belongs in sessions_spawn / delegate_task instead. `agent` runs the new session as a configured agent (agents_list; its model, identity, tool policy and workspace apply, and an unknown id is an error), `user` attaches a users-registry id (its personal instructions land in the new session's identity segment), `model` overrides the agent's model, `title`/`label` names it and `workspace` is its working directory (default: this session's). Returns JSON with session_id / sessionKey, agent, user, model and workspace. The session starts idle — give it work with sessions_send.";

fn sessions_create_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "agent": {"type": "string", "description": "Run the new session as this configured agent (see agents_list)."},
            "agentId": {"type": "string", "description": "OpenClaw spelling of `agent`."},
            "user": {"type": "string", "description": "Users-registry id whose personal instructions apply to the session."},
            "model": {"type": "string", "description": "provider/model override (default: the agent's model, then model.default)."},
            "title": {"type": "string", "description": "Session title shown in lists."},
            "label": {"type": "string", "description": "Alias of `title`."},
            "workspace": {"type": "string", "description": "Working directory (default: this session's workspace; the agent's own workspace wins when it has one)."}
        },
        "required": []
    })
}

impl Tool for SessionsCreate {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions_create".into(), description: SESSIONS_CREATE_DESCRIPTION.into(), input_schema: sessions_create_schema(), parallel_safe: false, idempotent: false, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_create") else { return ToolOutput::err("sessions_create needs the ark kernel") };
        match sessions_create(host, &input) {
            Ok(v) => json_out(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn sessions_create(host: &Host, input: &Value) -> Result<Value, String> {
    let rt = &host.rt;
    let agent = arg_str(input, &["agent", "agentId"]);
    let user = arg_str(input, &["user"]);
    if let Some(u) = &user {
        if get_user(&rt.paths, u).is_none() {
            return Err(format!("no user `{u}` (see `ark users`; omit `user` to create an unattached session)"));
        }
    }
    let model = arg_str(input, &["model"]);
    let title = arg_str(input, &["title", "label"]);
    let ws = arg_str(input, &["workspace", "cwd"]).map(|w| ark_core::tool::expand_home(&w)).unwrap_or_else(|| host.workspace.clone());
    let sid = rt.create_agent_session(&ws, agent.as_deref(), user.as_deref(), model.as_deref(), None, title.as_deref()).map_err(|e| e.to_string())?;
    let view = view_of(rt, &sid)?;
    Ok(json!({
        "session_id": sid,
        "sessionKey": sid,
        "agent": view.agent,
        "user": view.user,
        "model": view.model,
        "workspace": view.workspace,
        "title": view.title,
        "parent": view.parent,
        "note": "idle session; send it work with sessions_send",
    }))
}

// ───────────────────────── `sessions_list` ─────────────────────────

/// `sessions_list` (OpenClaw src/agents/tools/sessions-list-tool.ts): the session
/// inventory with the sidebar settings sessions_list/sessions own.
pub struct SessionsList;

const SESSIONS_LIST_DESCRIPTION: &str = "List sessions, newest activity first: id, title, model, workspace, agent, message/turn counts, pinned/archived/group/status and parent (OpenClaw sessions_list). Metadata only — read a transcript with sessions_history or session_search(read=true). Filters: `limit` (default 20, max 200), `archived` (default false hides archived rows; true shows both), `pinned`, `group` (empty string = ungrouped), `query` (substring of the id or title), `include_children` (default true; false hides sub-agent / child sessions). Call it before targeting another session with sessions_send or sessions.";

fn sessions_list_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "description": "Max rows (default 20, max 200)."},
            "include_children": {"type": "boolean", "description": "Include sub-agent / child sessions (default true)."},
            "archived": {"type": "boolean", "description": "false (default) hides archived sessions; true returns archived and active rows."},
            "pinned": {"type": "boolean", "description": "Only pinned (true) or only unpinned (false) sessions."},
            "group": {"type": "string", "description": "Only this sidebar group; empty string selects ungrouped sessions."},
            "query": {"type": "string", "description": "Only sessions whose id or title contains this text."},
            "title": {"type": "string", "description": "Alias of `query`."}
        },
        "required": []
    })
}

impl Tool for SessionsList {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions_list".into(), description: SESSIONS_LIST_DESCRIPTION.into(), input_schema: sessions_list_schema(), parallel_safe: true, idempotent: true, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_list") else { return ToolOutput::err("sessions_list needs the ark kernel") };
        match list_rows(&host.rt, &input) {
            Ok(rows) => json_out(&Value::Array(rows)),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ───────────────────────── `sessions_history` ─────────────────────────

/// `sessions_history` (OpenClaw src/agents/tools/sessions-history-tool.ts): the tail
/// of one session's transcript.
pub struct SessionsHistory;

const SESSIONS_HISTORY_DESCRIPTION: &str = "Read the end of one session's transcript (OpenClaw sessions_history): the last `limit` messages with their role and text, oldest first, plus `total` and the offset used. Plain paging: `offset` starts the window there instead (0 = the oldest message) and the reply's `next_offset` + `hasMore` walk forward through a long transcript. `session` defaults to this session; `role` keeps only user or assistant messages; `tools: true` also shows tool calls and tool results (`[called …]`, `[tool_result …]`), which are hidden by default because they flood the context. Read-only; for full-text recall across sessions use session_search.";

fn sessions_history_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "session": {"type": "string", "description": "Session id (default: this session)."},
            "sessionKey": {"type": "string", "description": "OpenClaw spelling of `session`."},
            "limit": {"type": "integer", "minimum": 1, "description": "Messages to return (default 50, max 500): the tail, or one page of `limit` from `offset`."},
            "offset": {"type": "integer", "minimum": 0, "description": "Start the page here (0-based over the session's messages, oldest first) instead of at the tail. Follow `next_offset` while `hasMore` is true."},
            "role": {"type": "string", "enum": ["user", "assistant"], "description": "Only this role."},
            "tools": {"type": "boolean", "description": "Include tool calls / results (default false)."},
            "includeTools": {"type": "boolean", "description": "OpenClaw spelling of `tools`."}
        },
        "required": []
    })
}

impl Tool for SessionsHistory {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions_history".into(), description: SESSIONS_HISTORY_DESCRIPTION.into(), input_schema: sessions_history_schema(), parallel_safe: true, idempotent: true, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_history") else { return ToolOutput::err("sessions_history needs the ark kernel") };
        match sessions_history(host, &input) {
            Ok(v) => json_out(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn sessions_history(host: &Host, input: &Value) -> Result<Value, String> {
    let sid = session_arg(input).unwrap_or_else(|| host.session.clone());
    let limit = arg_usize(input, &["limit"]).unwrap_or(50).clamp(1, 500);
    let role = arg_str(input, &["role"]).map(|r| {
        match r.to_ascii_lowercase().as_str() {
            "user" | "human" => "user",
            "assistant" | "agent" | "ai" => "assistant",
            _ => "",
        }
    });
    if matches!(role, Some("")) {
        return Err("`role` must be user or assistant".into());
    }
    let tools = arg_bool(input, &["tools", "includeTools"]).unwrap_or(false);
    let offset = arg_usize(input, &["offset"]);
    let events = host.rt.store.read(&sid).map_err(|_| no_session(&sid))?;
    let view = project(&events);
    let mut rows = Vec::new();
    for (i, m) in view.messages.iter().enumerate() {
        let r = if m.role == Role::User { "user" } else { "assistant" };
        if role.is_some_and(|f| f != r) {
            continue;
        }
        let text = transcript_text(m, tools);
        if text.trim().is_empty() {
            continue;
        }
        rows.push(json!({"seq": view.message_seqs.get(i).copied(), "role": r, "text": clip(&text, 4000)}));
    }
    let total = rows.len();
    // No `offset` = the tail (what a model usually wants); an explicit `offset` pages forward
    // from there so a long transcript can be walked without re-reading it (OpenClaw's
    // "plain-pagination offset" — `limit` still bounds the window).
    let start = offset.map(|o| o.min(total)).unwrap_or_else(|| total.saturating_sub(limit));
    let end = (start + limit).min(total);
    let page: Vec<Value> = rows.into_iter().skip(start).take(end - start).collect();
    let has_more = end < total;
    Ok(json!({
        "sessionKey": sid,
        "total": total,
        "returned": page.len(),
        "offset": start,
        "next_offset": has_more.then_some(end),
        "hasMore": has_more,
        "messages": page,
    }))
}

/// One message as text; tool blocks only when `tools` is set.
fn transcript_text(m: &ark_core::Message, tools: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    for b in &m.content {
        match b {
            ark_core::Block::Text { text } => parts.push(text.clone()),
            ark_core::Block::Thinking { .. } => {}
            ark_core::Block::ToolUse { name, input, .. } if tools => parts.push(format!("[called {name} {}]", clip(&input.to_string(), 200))),
            ark_core::Block::ToolResult { content, is_error, .. } if tools => parts.push(format!("[tool_result{}] {}", if *is_error { " error" } else { "" }, clip(content, 300))),
            _ => {}
        }
    }
    parts.join("\n")
}

// ───────────────────────── `sessions_send` ─────────────────────────

/// `sessions_send` (OpenClaw src/agents/tools/sessions-send-tool.ts): message another
/// session — wait for its reply, or run it in the background.
pub struct SessionsSend;

const SESSIONS_SEND_DESCRIPTION: &str = "Send a message to another session or agent (OpenClaw sessions_send). `session` must be an existing session id (sessions_list; sessions_create makes one) — a configured agent's own session is a normal session. `wait: true` runs the target now and returns its final reply in this call (it can take a while and may fail on budget/step limits). `wait: false` (default) hands the message to a background run whose completion arrives as a NEW message between your turns — finish independent work and end the turn instead of polling. Never target the calling session: answer here instead. The target sees your text as an `agent` message.";

fn sessions_send_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "session": {"type": "string", "description": "Target session id (from sessions_list)."},
            "sessionKey": {"type": "string", "description": "OpenClaw spelling of `session`."},
            "message": {"type": "string", "description": "What the other session should do or know. Self-contained: it has its own conversation."},
            "wait": {"type": "boolean", "description": "true = run the target and return its reply here; false (default) = background run, result arrives as a new message."}
        },
        "required": ["message"]
    })
}

impl Tool for SessionsSend {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "sessions_send".into(), description: SESSIONS_SEND_DESCRIPTION.into(), input_schema: sessions_send_schema(), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "sessions_send") else { return ToolOutput::err("sessions_send needs the ark kernel") };
        match sessions_send(host, &input) {
            Ok(v) => json_out(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn sessions_send(host: &Host, input: &Value) -> Result<Value, String> {
    let rt = &host.rt;
    let sid = session_arg(input).ok_or("sessions_send needs `session`: the target session id (see sessions_list)")?;
    let msg = input.get("message").and_then(Value::as_str).map(str::trim).filter(|m| !m.is_empty()).ok_or("sessions_send needs a non-empty `message`")?.to_string();
    if sid == host.session {
        return Err("sessions_send cannot target the calling session; just continue here".into());
    }
    ensure_session(rt, &sid)?;
    let wait = arg_bool(input, &["wait"]).unwrap_or(false);
    rt.submit(&sid, &msg, "agent").map_err(|e| e.to_string())?;
    if wait {
        let o = rt.run(&sid, RunOpts::default()).map_err(|e| e.to_string())?;
        return Ok(json!({
            "sessionKey": sid,
            "wait": true,
            "reply": o.text,
            "reason": o.reason.label(),
            "turns": o.turns,
            "tokens": o.usage.total(),
        }));
    }
    let run = rt.track_run(&host.session, &sid, &msg);
    Ok(json!({
        "sessionKey": sid,
        "runId": run,
        "wait": false,
        "note": "running in the background: the reply arrives as a NEW message between your turns",
    }))
}

// ───────────────────────── `clarify` ─────────────────────────

/// `clarify` (Hermes tools/clarify_tool.py + clarify_batch.py): structured questions
/// to the human, through the approver (choice cards on surfaces that have them).
pub struct Clarify;

const MAX_CLARIFY_QUESTIONS: usize = 5;
const MAX_CLARIFY_CHOICES: usize = 4;
const MAX_CHOICE_CHARS: usize = 8000;

const CLARIFY_DESCRIPTION: &str = "Ask the user one or more questions when a decision, clarification or feedback is needed before proceeding (Hermes clarify). Pass EVERY question in `questions` (1-5 entries; a single question is a one-entry array). Independent questions belong in ONE call — one form beats a chain of clarify calls; if one answer would change another question, ask them separately. Per question: single-select with up to 4 `choices` (put your recommended option FIRST: it is labelled \"(Recommended)\" and surfaces append an \"Other (type your answer)\" row), multi-select with `multi_select: true`, or open-ended by omitting `choices`. Options go ONLY in `choices`, never enumerated inside the question text — options written into the question are dead prose the user cannot click. Result JSON: `answers` (qid → answer, null when skipped/unanswered), `responses` (same, in question order, with status answered|skipped|unanswered) and `outcome`: submitted, cancelled, timed_out or undelivered (headless: no human attached — then decide yourself and state the assumption). `timeout_seconds` caps how long this call waits. Do not use it for dangerous-command confirmation (the approval gate handles that), and prefer deciding low-stakes questions yourself.";

fn clarify_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "questions": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_CLARIFY_QUESTIONS,
                "description": "The questions, in the order they should be shown. Responses come back in the same order, with the question text echoed.",
                "items": {
                    "type": "object",
                    "properties": {
                        "question": {"type": "string", "description": "The question text, options excluded."},
                        "choices": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_CLARIFY_CHOICES, "description": "Pickable answers, best first (the first one is marked \"(Recommended)\"). Omit for a free-text question."},
                        "multi_select": {"type": "boolean", "description": "The user may pick several choices (ignored without `choices`)."},
                        "id": {"type": "string", "description": "Stable question id for the answers map (default q0, q1, …)."}
                    },
                    "required": ["question"]
                }
            },
            "question": {"type": "string", "description": "Legacy single-question form: same as questions=[{question, choices, multi_select}]."},
            "choices": {"type": "array", "items": {"type": "string"}, "description": "Legacy: choices for the single `question`."},
            "multi": {"type": "boolean", "description": "Legacy: multi-select for the single `question`."},
            "multi_select": {"type": "boolean", "description": "Legacy: multi-select for the single `question`."},
            "timeout_seconds": {"type": "integer", "minimum": 1, "description": "How long to wait for answers before returning outcome=timed_out (default: the approver's own timeout)."}
        },
        "required": []
    })
}

impl Tool for Clarify {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "clarify".into(), description: CLARIFY_DESCRIPTION.into(), input_schema: clarify_schema(), parallel_safe: false, idempotent: false, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Ok(host) = kernel_host(ctx, "clarify") else { return ToolOutput::err("clarify needs the ark kernel (no approver behind this host)") };
        match clarify_call(host, &input) {
            Ok(v) => json_out(&v),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// Hermes `mark_recommended`: suffix the first choice unless it is the only one.
fn mark_recommended(mut choices: Vec<String>) -> Vec<String> {
    if choices.len() < 2 {
        return choices;
    }
    let first = choices[0].trim().to_string();
    if !first.to_lowercase().ends_with(&RECOMMENDED.to_lowercase()) {
        choices[0] = format!("{first} {RECOMMENDED}");
    }
    choices
}

fn clarify_questions(input: &Value) -> Result<Vec<ClarifyQuestion>, String> {
    let raw: Vec<Value> = match input.get("questions") {
        Some(Value::Array(a)) => a.clone(),
        None | Some(Value::Null) => {
            let q = arg_str(input, &["question"]).ok_or("clarify needs `questions`: [{question, choices?, multi_select?}] (or a single `question`)")?;
            vec![json!({
                "question": q,
                "choices": input.get("choices").cloned().unwrap_or(Value::Null),
                "multi_select": arg_bool(input, &["multi_select", "multi"]).unwrap_or(false),
            })]
        }
        Some(_) => return Err("`questions` must be an array of {question, choices?, multi_select?} objects".into()),
    };
    if raw.is_empty() {
        return Err("`questions` must contain at least one question".into());
    }
    if raw.len() > MAX_CLARIFY_QUESTIONS {
        return Err(format!("`questions` holds {} entries; at most {MAX_CLARIFY_QUESTIONS} are allowed per call", raw.len()));
    }
    let mut out = Vec::new();
    for (i, item) in raw.iter().enumerate() {
        let obj = item.as_object().ok_or_else(|| format!("questions[{i}] must be an object with a `question` field"))?;
        let text = obj.get("question").and_then(Value::as_str).map(str::trim).filter(|q| !q.is_empty()).ok_or_else(|| format!("questions[{i}].question must be non-empty text"))?.to_string();
        let choices: Vec<String> = match obj.get("choices") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => {
                let mut v = Vec::new();
                for (pos, c) in a.iter().enumerate() {
                    let c = c.as_str().ok_or_else(|| format!("questions[{i}].choices[{pos}] must be a string"))?.trim().to_string();
                    if c.chars().count() > MAX_CHOICE_CHARS {
                        return Err(format!("questions[{i}].choices[{pos}] is {} characters; the limit is {MAX_CHOICE_CHARS} (move detail into the question text)", c.chars().count()));
                    }
                    if !c.is_empty() {
                        v.push(c);
                    }
                }
                if v.is_empty() {
                    return Err(format!("questions[{i}].choices has {} entries but all are blank; send real labels, or omit `choices` to ask open-ended", a.len()));
                }
                v.truncate(MAX_CLARIFY_CHOICES);
                mark_recommended(v)
            }
            Some(_) => return Err(format!("questions[{i}].choices must be an array of strings")),
        };
        let qid = obj.get("id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| format!("q{i}"));
        let multi = choices.len() > 1 && obj.get("multi_select").or_else(|| obj.get("multi")).and_then(Value::as_bool).unwrap_or(false);
        out.push(ClarifyQuestion { qid, question: text, choices, multi_select: multi });
    }
    Ok(out)
}

fn clarify_call(host: &Host, input: &Value) -> Result<Value, String> {
    let rt = &host.rt;
    let qs = clarify_questions(input)?;
    let mut payload = hooks::payload(&host.session, &host.workspace.to_string_lossy(), None, None, None, None);
    payload["kind"] = "clarify".into();
    payload["message"] = json!(qs.iter().map(|q| q.question.clone()).collect::<Vec<_>>().join("\n"));
    payload["questions"] = json!(qs);
    payload["choices"] = json!(qs.iter().map(|q| q.choices.clone()).collect::<Vec<_>>());
    rt.emit(HookEvent::Notification, payload.clone(), "");
    rt.emit(HookEvent::HumanInputRequest, payload.clone(), "");
    let timeout = arg_usize(input, &["timeout_seconds", "timeoutSeconds"]).map(|s| Duration::from_secs(s.max(1) as u64));
    let reply = match timeout {
        Some(t) => clarify_within(rt.approver.clone(), &host.session, &qs, t),
        None => rt.approver.clarify(&host.session, &qs),
    };
    if rt.has_hooks(HookEvent::HumanInputResolved) {
        payload["answers"] = json!(reply.answers);
        payload["outcome"] = json!(reply.outcome);
        payload["cancelled"] = json!(reply.outcome != "submitted");
        payload["notice"] = json!(reply.notice);
        rt.emit(HookEvent::HumanInputResolved, payload, "");
    }
    let mut answers = serde_json::Map::new();
    let mut responses = Vec::new();
    for q in &qs {
        let answered = reply.answers.get(&q.qid).cloned().flatten().filter(|v| !v.is_null() && v.as_str() != Some("") && v.as_array().is_none_or(|a| !a.is_empty()));
        let status = if answered.is_some() {
            "answered"
        } else if reply.answers.contains_key(&q.qid) {
            "skipped"
        } else {
            "unanswered"
        };
        answers.insert(q.qid.clone(), answered.clone().unwrap_or(Value::Null));
        responses.push(json!({
            "id": q.qid,
            "question": q.question,
            "choices_offered": q.choices.iter().map(|c| crate::approver::strip_recommended(c)).collect::<Vec<_>>(),
            "multi_select": q.multi_select,
            "status": status,
            "user_response": answered,
        }));
    }
    Ok(json!({
        "answers": answers,
        "responses": responses,
        "outcome": reply.outcome,
        "notice": reply.notice,
    }))
}

/// `timeout_seconds`: wait at most `t` for the approver (a headless approver answers
/// immediately with `undelivered`). The questions stay open in the approver, so a late
/// answer is not lost — it is simply not part of this reply.
fn clarify_within(approver: Arc<dyn crate::approver::Approver>, session: &str, qs: &[ClarifyQuestion], t: Duration) -> ClarifyReply {
    let (tx, rx) = std::sync::mpsc::channel();
    let (a, s, q) = (approver, session.to_string(), qs.to_vec());
    std::thread::spawn(move || {
        let _ = tx.send(a.clarify(&s, &q));
    });
    match rx.recv_timeout(t) {
        Ok(r) => r,
        Err(_) => ClarifyReply { answers: Default::default(), outcome: "timed_out".into(), notice: Some(format!("the user did not answer within {}s; continue with your best judgement or ask again", t.as_secs())) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        let r = std::env::temp_dir().join(format!("ark-agents-{}", crate::util::random_hex(8)));
        Paths { data: r.join("data"), config_dir: r.join("cfg"), runtime: r.join("run") }
    }

    #[test]
    fn add_bind_route_and_delete() {
        let p = paths();
        let mut cfg = Config::default();
        cfg.agents.insert("cfg-agent".into(), AgentDef { name: "From config".into(), ..Default::default() });
        add(&p, "ops", AgentDef { name: "Ops".into(), model: "a/b".into(), identity: role_identity("reviewer").unwrap().into(), tools_deny: vec!["shell".into()], ..Default::default() }).unwrap();
        assert!(add(&p, "ops", AgentDef::default()).unwrap_err().contains("exists"));
        assert!(add(&p, "Bad", AgentDef::default()).is_err() && add(&p, MAIN, AgentDef::default()).is_err());
        let ids: Vec<String> = all(&cfg, &p).into_keys().collect();
        assert_eq!(ids, ["cfg-agent", "main", "ops"]);
        let r = resolve(&cfg, &p, "ops").unwrap();
        assert_eq!(r.model.as_deref(), Some("a/b"));
        assert_eq!(r.tools_deny, ["shell"]);
        assert!(resolve(&cfg, &p, "cfg-agent").unwrap().identity.unwrap().contains("From config"));

        bind(&cfg, &p, parse_bind("ops", "telegram", None).unwrap()).unwrap();
        bind(&cfg, &p, parse_bind("cfg-agent", "telegram:work", Some("group:G1")).unwrap()).unwrap();
        assert!(!bind(&cfg, &p, parse_bind("ops", "telegram", None).unwrap()).unwrap(), "duplicate ignored");
        assert!(bind(&cfg, &p, parse_bind("ghost", "x", None).unwrap()).is_err());
        let b = bindings(&cfg, &p);
        let r = |chat: &str, account: &str, kind: &str| route(&b, MAIN, &RouteInput { channel: "telegram", account, chat, sender: "s1", kind, user: None });
        assert_eq!(r("G1", "work", "group"), ("cfg-agent".into(), "binding.peer"));
        assert_eq!(r("G1:thread:9", "work", "group"), ("cfg-agent".into(), "binding.peer.parent"));
        assert_eq!(r("G1", "work", "direct"), ("ops".into(), "binding.channel"), "peer kind must match");
        assert_eq!(route(&b, MAIN, &RouteInput { channel: "slack", chat: "c", ..Default::default() }), (MAIN.into(), "default"));

        update(&p, "ops", |a| a.default = true).unwrap();
        assert_eq!(default_agent(&cfg, &p), "ops");
        assert_eq!(unbind(&p, "ops", Some("telegram")).unwrap(), 1);
        assert_eq!(delete(&p, "cfg-agent").unwrap_err(), "agent `cfg-agent` is not managed by `ark agents`");
        assert_eq!(delete(&p, "ops").unwrap(), 0);
        assert!(!all(&cfg, &p).contains_key("ops"));
    }

    #[test]
    fn route_tiers_user_wildcard_account() {
        let b = vec![
            Binding { agent: "chan".into(), channel: "tg".into(), ..Default::default() },
            Binding { agent: "acct".into(), channel: "tg".into(), account: "a2".into(), ..Default::default() },
            Binding { agent: "groups".into(), channel: "tg".into(), peer: "*".into(), peer_kind: "group".into(), ..Default::default() },
            Binding { agent: "amy".into(), channel: "*".into(), user: "u-1".into(), ..Default::default() },
        ];
        let i = |kind, account, user| RouteInput { channel: "tg", account, chat: "c", sender: "s", kind, user };
        assert_eq!(route(&b, MAIN, &i("direct", "a2", Some("u-1"))).1, "binding.user");
        assert_eq!(route(&b, MAIN, &i("group", "a2", None)).0, "groups");
        assert_eq!(route(&b, MAIN, &i("direct", "a2", None)).0, "acct");
        assert_eq!(route(&b, MAIN, &i("direct", "a1", None)).0, "chan");
    }

    #[test]
    fn users_registry() {
        let p = paths();
        let a = user_add(&p, "Amy").unwrap();
        let b = user_add(&p, "Amy (work)").unwrap();
        assert!(user_add(&p, " ").is_err());
        user_link_email(&p, &a.id, "Amy@Example.com").unwrap();
        assert!(user_link_email(&p, &b.id, "amy@example.com").unwrap_err().contains("merge"));
        assert!(user_link_email(&p, &a.id, "nope").is_err());
        user_link(&p, &b.id, "telegram", "42").unwrap();
        assert!(user_link(&p, &a.id, "telegram", "42").is_err());
        user_set_instructions(&p, &b.id, "Reply in 繁體中文.").unwrap();
        assert_eq!(find_user(&p, "telegram", "42").unwrap().id, b.id);
        assert_eq!(find_user(&p, "email", "AMY@example.com").unwrap().id, a.id);
        let m = user_merge(&p, &b.id, &a.id).unwrap();
        assert!(m.identities.len() == 1 && m.instructions.contains("繁體中文") && m.emails == ["amy@example.com"]);
        assert_eq!(users(&p).len(), 1);
        assert!(user_merge(&p, &a.id, &a.id).is_err());
        user_remove(&p, &a.id).unwrap();
        assert!(user_remove(&p, &a.id).is_err() && users(&p).is_empty());
    }

    #[test]
    fn time_bounds_parse_dates_offsets_and_spans() {
        let day = crate::util::days_from_civil(2026, 7, 1) * 86_400 * 1000;
        assert_eq!(time_bound("2026-07-01").unwrap(), day as u64);
        assert_eq!(time_bound(" 2026-7-1 ").unwrap(), day as u64);
        assert_eq!(time_bound("2026-07-01T09:30").unwrap(), day as u64 + (9 * 3600 + 1800) * 1000);
        assert_eq!(time_bound("2026-07-01T09:30Z").unwrap(), day as u64 + (9 * 3600 + 1800) * 1000);
        assert_eq!(time_bound("2026-07-01T09:30:00+08:00").unwrap(), day as u64 + (3600 + 1800) * 1000);
        assert_eq!(time_bound("2026-07-01T09:30:00-02:00").unwrap(), day as u64 + (11 * 3600 + 1800) * 1000);
        let now = crate::event::now_ms();
        let two_hours = time_bound("2h").unwrap();
        assert!(two_hours <= now - 7_000_000 && two_hours >= now - 7_400_000, "{two_hours} vs {now}");
        for bad in ["", "nope", "2026-13-01", "2026-07-01T25:00", "2026-07-01T09:70", "2026-07"] {
            assert!(time_bound(bad).is_err(), "`{bad}` must not parse");
        }
    }

    #[test]
    fn clarify_normalisation_marks_and_validates() {
        let qs = clarify_questions(&json!({"questions": [
            {"question": "Which DB?", "choices": ["Postgres", "SQLite"], "id": "db"},
            {"question": "Notes?", "multi_select": true},
            {"question": "Pick", "choices": ["only"], "multi_select": true},
            {"question": "Long", "choices": ["a", "b", "c", "d", "e", "f"]}
        ]}))
        .unwrap();
        assert_eq!(qs.len(), 4);
        assert_eq!(qs[0].qid, "db");
        assert_eq!(qs[0].choices, ["Postgres (Recommended)", "SQLite"]);
        assert!(!qs[0].multi_select);
        // multi_select needs choices; a lone choice is not "recommended" over anything.
        assert!(qs[1].choices.is_empty() && !qs[1].multi_select);
        assert_eq!(qs[2].choices, ["only"]);
        assert!(!qs[2].multi_select);
        assert_eq!(qs[3].choices.len(), 4, "choices are capped at MAX_CLARIFY_CHOICES");
        assert_eq!(qs[3].qid, "q3");
        // The label is idempotent: an already-marked first choice is not marked twice.
        let again = clarify_questions(&json!({"questions": [{"question": "q", "choices": ["A (Recommended)", "B"]}]})).unwrap();
        assert_eq!(again[0].choices, ["A (Recommended)", "B"]);
        // Legacy single-question form.
        let one = clarify_questions(&json!({"question": "Which way?", "choices": ["left", "right"], "multi": true})).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].qid, "q0");
        assert_eq!(one[0].choices, ["left (Recommended)", "right"]);
        assert!(one[0].multi_select);
        // Errors say what to fix.
        assert!(clarify_questions(&json!({})).unwrap_err().contains("needs `questions`"));
        assert!(clarify_questions(&json!({"questions": []})).unwrap_err().contains("at least one"));
        assert!(clarify_questions(&json!({"questions": [{"question": " "}]})).unwrap_err().contains("non-empty"));
        assert!(clarify_questions(&json!({"questions": [{"question": "q", "choices": [" ", ""]}]})).unwrap_err().contains("blank"));
        assert!(clarify_questions(&json!({"questions": [{"question": "q", "choices": "x"}]})).unwrap_err().contains("array of strings"));
        let many: Vec<Value> = (0..6).map(|i| json!({"question": format!("q{i}")})).collect();
        assert!(clarify_questions(&json!({"questions": many})).unwrap_err().contains("at most 5"));
    }
}
