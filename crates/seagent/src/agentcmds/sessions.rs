//! `seagent session rename|pin|unpin|pinned|archive|unarchive|label|group|stats|prune|import|repair`.
//!
//! Ports Hermes `hermes sessions` maintenance (`hermes_cli/sessions_cmd.py`,
//! `hermes_cli/subcommands/sessions.py`, `hermes_cli/session_filters.py`) and the foreign-session
//! importer (`hermes_cli/foreign_sessions.py`) onto seagent's append-only JSONL store.
//!
//! A session's settings are events, not side files: `rename` appends `Title`, `pin`/`archive`/
//! `label`/`group` append `Meta`. So they work on a session another process is running, and every
//! surface (CLI, TUI, Desktop, the `sessions` tool) reads the same values through `project`.
//! `label <id> <group>` and `group <id> <status>` are the OpenClaw sidebar settings the `sessions`
//! tool calls `group`/`status`: both are *set* operations (an empty value clears).
//!
//! `import` reads Claude Code (`~/.claude/projects/**/*.jsonl`) and Codex CLI
//! (`~/.codex/sessions/**/rollout-*.jsonl`) sessions; those files are never written.
//! `repair` fixes seagent's own event logs: bad lines are backed up to `<file>.bak-<ts>` and dropped,
//! a missing header is restored and `seq` is recomputed.

use crate::args::Args;
use seagent_core::{Message, Usage};
use seagent_kernel::config::Paths;
use seagent_kernel::event::{Event, EventKind, LOG_VERSION};
use seagent_kernel::store::{SessionInfo, SessionLog, Store};
use seagent_kernel::util::{atomic_write, days_from_civil, new_id, unix_now};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ───────────────────────── flag bag ─────────────────────────

/// Flags accepted by these subcommands, parsed either from the global [`Args`] or (when the
/// dispatcher hands over the raw arguments, as `seagent kanban` does) by [`Opts::parse`]. Hermes takes
/// its own parser for these commands too: `--include-pinned` and friends must not be rejected as
/// typos by the global parser.
#[derive(Debug, Default, Clone)]
pub(crate) struct Opts {
    pub pos: Vec<String>,
    pub vals: BTreeMap<String, Vec<String>>,
    pub bools: Vec<String>,
}

/// `parse`/`vals` are the raw-argument half of this bag: `cli_raw` and the agents CLI use it, so it
/// only becomes reachable once a dispatcher hands over unparsed arguments.
#[allow(dead_code)]
impl Opts {
    pub(crate) fn from_args(a: &Args, value: &[&str], bools: &[&str]) -> Opts {
        let mut o = Opts { pos: a.pos.clone(), ..Default::default() };
        for k in value {
            let v = a.vals(k);
            if !v.is_empty() {
                o.vals.insert((*k).to_string(), v);
            }
        }
        for k in bools {
            if a.flag(k) {
                o.bools.push((*k).to_string());
            }
        }
        o
    }

    pub(crate) fn parse(raw: &[String], value: &[&str], bools: &[&str]) -> Result<Opts, String> {
        let mut o = Opts::default();
        let mut i = 0;
        let mut only_pos = false;
        while i < raw.len() {
            let r = &raw[i];
            i += 1;
            if only_pos || r == "-" || !r.starts_with('-') {
                o.pos.push(r.clone());
                continue;
            }
            if r == "--" {
                only_pos = true;
                continue;
            }
            let Some(body) = r.strip_prefix("--") else {
                match &r[1..] {
                    "y" => o.bools.push("yes".into()),
                    "q" => o.bools.push("quiet".into()),
                    "h" => o.bools.push("help".into()),
                    s => return Err(format!("unknown option -{s}")),
                }
                continue;
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (body.to_string(), None),
            };
            if value.contains(&name.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let v = raw.get(i).cloned().ok_or_else(|| format!("--{name} needs a value"))?;
                        i += 1;
                        v
                    }
                };
                o.vals.entry(name).or_default().push(v);
            } else if bools.contains(&name.as_str()) {
                if inline.is_some() {
                    return Err(format!("--{name} takes no value"));
                }
                o.bools.push(name);
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(o)
    }

    pub(crate) fn val(&self, k: &str) -> Option<&str> {
        self.vals.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    pub(crate) fn vals(&self, k: &str) -> Vec<String> {
        self.vals.get(k).cloned().unwrap_or_default()
    }
    pub(crate) fn flag(&self, k: &str) -> bool {
        self.bools.iter().any(|b| b == k)
    }
    pub(crate) fn pos(&self, i: usize) -> Option<&str> {
        self.pos.get(i).map(String::as_str)
    }
    pub(crate) fn need(&self, i: usize, what: &str) -> Result<&str, String> {
        self.pos(i).ok_or_else(|| format!("missing <{what}>"))
    }
    pub(crate) fn rest(&self, from: usize) -> String {
        self.pos.iter().skip(from).cloned().collect::<Vec<_>>().join(" ")
    }
    pub(crate) fn num(&self, k: &str) -> Result<Option<usize>, String> {
        match self.val(k) {
            None => Ok(None),
            Some(v) => v.trim().parse().map(Some).map_err(|_| format!("--{k}: `{v}` is not a valid number")),
        }
    }
}

/// Flags this module reads. `--older-than`/`--dry-run`/`--yes`/`--json`/`--limit`/`--model` happen
/// to be known to the global parser already; the rest are ours (see `cli_raw`).
const VALUE_FLAGS: &[&str] = &["older-than", "title", "model", "after", "before", "min-messages", "max-messages", "limit", "from"];
const BOOL_FLAGS: &[&str] = &["dry-run", "yes", "include-pinned", "include-archived", "check-only", "json", "all", "quiet", "help", "force"];

pub const USAGE: &str = "\
seagent session <subcommand>
  rename <id> <title…>            set the title (an empty title clears it)
  pin|unpin <id…>                 durable keep flag (pinned sessions are never pruned)
  pinned [--json]                 list pinned sessions
  archive [filters] [--dry-run]   archive matching sessions (soft hide, reversible)
  unarchive <id…>                 restore archived sessions
  label <id> <group>              set the sidebar group (empty clears it)
  group <id> <status>             set the short status line (empty clears it)
  stats [--json]                  sessions, messages, tokens, disk usage, pin/archive counts
  prune [filters] [--yes]         delete matching sessions (no filters: older than 90 days)
  import [path] [--from claude|codex]  import a Claude Code / Codex CLI session
  repair [id…] [--check-only]     fix corrupted event logs (bad lines, seq, header)
filters: --older-than AGE  --after TIME  --before TIME  --title S  --model S
         --min-messages N  --max-messages N  --include-pinned  --include-archived  --limit N
AGE/TIME: 5h, 30m, 2d, 1w, a bare number of days, or an ISO timestamp.";

/// `seagent session <maintenance subcommand>` (wired from `main.rs::cmd_session`).
pub fn cli(a: &Args) -> Result<String, String> {
    let paths = Paths::from_env();
    run(&Store::new(paths.sessions()), &Opts::from_args(a, VALUE_FLAGS, BOOL_FLAGS))
}

/// Same dispatch from raw arguments (own flag parser). `main.rs` may hand these commands over
/// unparsed, like `seagent kanban`, so every filter flag reaches this module.
#[allow(dead_code)] // reachable once `main.rs` routes `session` maintenance here instead of via `Args`
pub fn cli_raw(raw: &[String]) -> Result<String, String> {
    let paths = Paths::from_env();
    run(&Store::new(paths.sessions()), &Opts::parse(raw, VALUE_FLAGS, BOOL_FLAGS)?)
}

/// Testable entry point: one subcommand against one store.
pub fn run(store: &Store, o: &Opts) -> Result<String, String> {
    match o.pos(0).unwrap_or("help") {
        "rename" | "retitle" => cmd_rename(store, o),
        "pin" => cmd_pin(store, o, true),
        "unpin" => cmd_pin(store, o, false),
        "pinned" => cmd_pinned(store, o),
        "archive" => cmd_archive(store, o),
        "unarchive" | "restore" => cmd_unarchive(store, o),
        "label" => cmd_meta(store, o, MetaField::Group, "label", "group"),
        "group" | "status" => cmd_meta(store, o, MetaField::Status, "group", "status"),
        "stats" => cmd_stats(store, o),
        "prune" | "delete-old" => cmd_prune(store, o),
        "import" => cmd_import(store, o),
        "repair" => cmd_repair(store, o),
        other => Err(format!("unknown `session {other}`\n{USAGE}")),
    }
}

// ───────────────────────── help ─────────────────────────

/// Drop terminal control characters: titles and statuses come from chat messages.
pub(crate) fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Collapse whitespace so a title/status stays one line (other control characters are dropped).
fn one_line(s: &str) -> String {
    s.split_whitespace().map(|w| w.chars().filter(|c| !c.is_control()).collect::<String>()).collect::<Vec<_>>().join(" ")
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    } else {
        s.to_string()
    }
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn util_now_ms() -> u64 {
    super::now_ms()
}

// ───────────────────────── ids ─────────────────────────

/// Resolve `last`, an exact id, or a unique id prefix (Hermes `resolve_session_id`).
fn resolve(store: &Store, q: &str) -> Result<String, String> {
    let q = q.trim();
    let all = all_ids(store);
    if q == "last" || q == "-" {
        // `last` = most recently active session that is not a sub-agent run.
        return store.list().into_iter().find(|s| s.parent.is_none()).map(|s| s.id).ok_or_else(|| "no sessions yet — start one with `seagent run`".to_string());
    }
    if all.iter().any(|id| id == q) {
        return Ok(q.to_string());
    }
    let m: Vec<&String> = all.iter().filter(|id| id.starts_with(q)).collect();
    match m.len() {
        0 => Err(format!("no session `{}` (try `seagent session list`)", safe(q))),
        1 => Ok(m[0].clone()),
        n => {
            let mut ex: Vec<String> = m.iter().take(4).map(|s| (*s).clone()).collect();
            if n > ex.len() {
                ex.push(format!("… {} more", n - ex.len()));
            }
            Err(format!("`{}` matches {n} sessions ({}) — be more specific", safe(q), ex.join(", ")))
        }
    }
}

/// Session ids present on disk, including ones whose log no longer parses (`box.list` skips those).
fn all_ids(store: &Store) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(store.root())
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().join("events.jsonl").is_file())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

// ───────────────────────── rows ─────────────────────────

/// A session plus the settings and usage that live in its event log.
pub struct Row {
    pub info: SessionInfo,
    pub pinned: bool,
    pub archived: bool,
    pub group: Option<String>,
    pub status: Option<String>,
    pub turns: u64,
    pub usage: Usage,
}

impl Row {
    pub fn title(&self) -> String {
        self.info.title.clone().filter(|t| !t.trim().is_empty()).map(|t| one_line(&t)).unwrap_or_else(|| "(untitled)".into())
    }
    pub fn flags(&self) -> String {
        let mut f: Vec<&str> = Vec::new();
        if self.pinned {
            f.push("pinned");
        }
        if self.archived {
            f.push("archived");
        }
        if self.info.parent.is_some() {
            f.push("sub-agent");
        }
        f.join(",")
    }
    pub fn line(&self) -> String {
        let f = self.flags();
        let mut s = format!(
            "  {}  {}  {:>4} msgs  {:<26} {}",
            self.info.id,
            super::iso(self.info.updated_ms),
            self.info.messages,
            clip(&one_line(&self.info.model), 26),
            clip(&self.title(), 44)
        );
        if !f.is_empty() {
            s.push_str(&format!("  [{f}]"));
        }
        if let Some(g) = &self.group {
            s.push_str(&format!("  group:{}", one_line(g)));
        }
        s
    }
}

pub fn row_of(store: &Store, info: SessionInfo) -> Row {
    let mut r = Row { info, pinned: false, archived: false, group: None, status: None, turns: 0, usage: Usage::default() };
    let Ok(events) = store.read(&r.info.id) else { return r };
    for e in &events {
        match &e.kind {
            EventKind::Meta { pinned, archived, group, status } => {
                if let Some(p) = pinned {
                    r.pinned = *p;
                }
                if let Some(a) = archived {
                    r.archived = *a;
                }
                if let Some(g) = group {
                    r.group = Some(g.clone()).filter(|g| !g.is_empty());
                }
                if let Some(s) = status {
                    r.status = Some(s.clone()).filter(|s| !s.is_empty());
                }
            }
            EventKind::TurnEnd { usage, .. } => {
                r.usage.add(usage);
                r.turns += 1;
            }
            _ => {}
        }
    }
    r
}

fn rows(store: &Store) -> Vec<Row> {
    store.list().into_iter().map(|s| row_of(store, s)).collect()
}

fn meta_event(pinned: Option<bool>, archived: Option<bool>, group: Option<String>, status: Option<String>) -> EventKind {
    EventKind::Meta { pinned, archived, group, status }
}

/// Append one event to a session (works while the session runs elsewhere: the log is append-only).
fn record(store: &Store, id: &str, kind: EventKind) -> Result<(), String> {
    let mut log: SessionLog = store.open(id).map_err(|e| e.to_string())?;
    log.append(kind).map_err(|e| e.to_string())?;
    Ok(())
}

/// Successes on stdout, failures on stderr (exit 1) — Hermes prints both.
fn finish(ok: Vec<String>, bad: Vec<String>) -> Result<String, String> {
    if bad.is_empty() {
        Ok(ok.join("\n"))
    } else if ok.is_empty() {
        Err(bad.join("\n"))
    } else {
        Err(format!("{}\n{}", ok.join("\n"), bad.join("\n")))
    }
}

fn title_of(store: &Store, id: &str) -> Option<String> {
    store.list().into_iter().find(|s| s.id == id).and_then(|s| s.title).map(|t| one_line(&t)).filter(|t| !t.is_empty())
}

// ───────────────────────── rename ─────────────────────────

fn cmd_rename(store: &Store, o: &Opts) -> Result<String, String> {
    let id = resolve(store, o.need(1, "session")?)?;
    if o.pos(2).is_none() {
        return Err("missing <title> (pass an empty string to clear the title)".into());
    }
    let title = one_line(&o.rest(2));
    if title.chars().count() > 200 {
        return Err(format!("title is too long ({} characters; keep it under 200)", title.chars().count()));
    }
    record(store, &id, EventKind::Title { title: title.clone() })?;
    Ok(if title.is_empty() { format!("cleared the title of {id}") } else { format!("renamed {id} → {title}") })
}

// ───────────────────────── pin / unpin ─────────────────────────

fn cmd_pin(store: &Store, o: &Opts, pin: bool) -> Result<String, String> {
    let ids: Vec<String> = o.pos.iter().skip(1).cloned().collect();
    if ids.is_empty() {
        return Err(format!("missing <session> (usage: `seagent session {} <id…>`)", if pin { "pin" } else { "unpin" }));
    }
    let verb = if pin { "pinned" } else { "unpinned" };
    let (mut ok, mut bad) = (Vec::new(), Vec::new());
    for q in &ids {
        match resolve(store, q) {
            Ok(id) => match record(store, &id, meta_event(Some(pin), None, None, None)) {
                Ok(()) => {
                    let t = title_of(store, &id).map(|t| format!("  ({t})")).unwrap_or_default();
                    ok.push(format!("{verb} {id}{t}"));
                }
                Err(e) => bad.push(format!("{verb} {}: {e}", safe(q))),
            },
            Err(e) => bad.push(e),
        }
    }
    finish(ok, bad)
}

fn cmd_pinned(store: &Store, o: &Opts) -> Result<String, String> {
    let mut pinned: Vec<Row> = rows(store).into_iter().filter(|r| r.pinned).collect();
    pinned.sort_by_key(|r| std::cmp::Reverse(r.info.updated_ms));
    if o.flag("json") {
        let list: Vec<Value> = pinned.iter().map(|r| json!({"id": r.info.id, "title": r.info.title, "model": r.info.model, "updated": super::iso(r.info.updated_ms), "messages": r.info.messages, "group": r.group})).collect();
        return Ok(serde_json::to_string_pretty(&list).unwrap_or_else(|_| "[]".into()));
    }
    if pinned.is_empty() {
        return Ok("no pinned sessions — pin one with `seagent session pin <id>`".into());
    }
    let mut out = vec![format!("{} pinned session(s):", pinned.len())];
    out.extend(pinned.iter().map(|r| r.line()));
    out.push("pinned sessions are exempt from `seagent session prune` and the auto-archive sweep.".into());
    Ok(out.join("\n"))
}

// ───────────────────────── filters (prune / archive) ─────────────────────────

#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// Last activity before this instant (unix millis).
    pub older_than: Option<u64>,
    /// Session start bounds (`started_ms`), like Hermes `--after`/`--before`.
    pub after: Option<u64>,
    pub before: Option<u64>,
    pub title: Option<String>,
    pub model: Option<String>,
    pub min_messages: Option<usize>,
    pub max_messages: Option<usize>,
    pub include_pinned: bool,
    pub include_archived: bool,
    pub limit: Option<usize>,
    /// Set when `prune`/`archive` implied the cutoff instead of the user passing one.
    pub implied: Option<String>,
}

impl Filter {
    pub fn from(o: &Opts) -> Result<Filter, String> {
        let point = |flag: &str| -> Result<Option<u64>, String> { o.val(flag).map(|v| parse_point_in_time(v, flag)).transpose() };
        let f = Filter {
            older_than: point("older-than")?,
            after: point("after")?,
            before: point("before")?,
            title: o.val("title").map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()),
            model: o.val("model").map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()),
            min_messages: o.num("min-messages")?,
            max_messages: o.num("max-messages")?,
            include_pinned: o.flag("include-pinned"),
            include_archived: o.flag("include-archived"),
            limit: o.num("limit")?,
            implied: None,
        };
        if let (Some(lo), Some(hi)) = (f.after, f.before) {
            if lo >= hi {
                return Err(format!("empty window: --after ({}) is not earlier than --before ({})", super::iso(lo), super::iso(hi)));
            }
        }
        Ok(f)
    }

    /// Whether any selection filter was given (`--include-*` and `--limit` are not selection).
    pub fn any(&self) -> bool {
        self.older_than.is_some() || self.after.is_some() || self.before.is_some() || self.title.is_some() || self.model.is_some() || self.min_messages.is_some() || self.max_messages.is_some()
    }

    pub fn describe(&self) -> String {
        let mut p: Vec<String> = Vec::new();
        if let Some(t) = self.older_than {
            p.push(format!("last active before {}", super::iso(t)));
        }
        if let Some(t) = self.after {
            p.push(format!("started at/after {}", super::iso(t)));
        }
        if let Some(t) = self.before {
            p.push(format!("started before {}", super::iso(t)));
        }
        if let Some(t) = &self.title {
            p.push(format!("title contains \"{t}\""));
        }
        if let Some(m) = &self.model {
            p.push(format!("model contains \"{m}\""));
        }
        if let Some(n) = self.min_messages {
            p.push(format!(">= {n} messages"));
        }
        if let Some(n) = self.max_messages {
            p.push(format!("<= {n} messages"));
        }
        if self.include_pinned {
            p.push("including pinned".into());
        }
        if self.include_archived {
            p.push("including archived".into());
        }
        if let Some(n) = self.limit {
            p.push(format!("limited to {n}"));
        }
        let mut s = if p.is_empty() { "no filters".to_string() } else { p.join(", ") };
        if let Some(i) = &self.implied {
            s.push_str(&format!(" ({i})"));
        }
        s
    }

    pub fn matches(&self, r: &Row) -> bool {
        if r.pinned && !self.include_pinned {
            return false;
        }
        if r.archived && !self.include_archived {
            return false;
        }
        let t = r.info.updated_ms;
        if self.older_than.is_some_and(|c| t >= c) {
            return false;
        }
        // `--after`/`--before` bound the start of the session (`--older-than` bounds its activity).
        if self.after.is_some_and(|c| r.info.created_ms < c) {
            return false;
        }
        if self.before.is_some_and(|c| r.info.created_ms >= c) {
            return false;
        }
        if let Some(q) = &self.title {
            let title = r.title().to_lowercase();
            if !title.contains(q.as_str()) {
                return false;
            }
        }
        if let Some(q) = &self.model {
            if !r.info.model.to_lowercase().contains(q.as_str()) {
                return false;
            }
        }
        if self.min_messages.is_some_and(|n| r.info.messages < n) {
            return false;
        }
        if self.max_messages.is_some_and(|n| r.info.messages > n) {
            return false;
        }
        true
    }

    /// Matching rows, oldest activity first (so `--limit` trims the newest).
    pub fn select(&self, store: &Store) -> Vec<Row> {
        let mut v: Vec<Row> = rows(store).into_iter().filter(|r| self.matches(r)).collect();
        v.sort_by_key(|r| (r.info.updated_ms, r.info.id.clone()));
        if let Some(n) = self.limit {
            v.truncate(n);
        }
        v
    }

    /// Matching rows that were spared because they are pinned (Hermes' note).
    pub fn pinned_spared(&self, store: &Store) -> usize {
        let probe = Filter { include_pinned: true, ..self.clone() };
        probe.select(store).iter().filter(|r| r.pinned).count()
    }
}

/// `5h` / `30m` / `2d` / `1w` / a bare number of days → milliseconds (Hermes
/// `parse_duration_seconds`).
pub fn parse_duration_ms(v: &str) -> Option<u64> {
    let s = v.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = match s.find(|c: char| c.is_ascii_alphabetic()) {
        Some(i) => (s[..i].trim().to_string(), s[i..].trim().to_string()),
        None => (s.clone(), String::new()),
    };
    let n: f64 = num.parse().ok().filter(|n: &f64| *n >= 0.0)?;
    let secs = match unit.as_str() {
        "" => n * 86_400.0, // bare number = days (backwards compatible with `--older-than 90`)
        "s" | "sec" | "secs" | "second" | "seconds" => n,
        "m" | "min" | "mins" | "minute" | "minutes" => n * 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => n * 3_600.0,
        "d" | "day" | "days" => n * 86_400.0,
        "w" | "wk" | "wks" | "week" | "weeks" => n * 604_800.0,
        _ => return None,
    };
    Some((secs * 1000.0) as u64)
}

/// A point in time: a duration means "that long ago", an ISO timestamp is taken as UTC
/// (Hermes `parse_point_in_time`).
pub fn parse_point_in_time(v: &str, flag: &str) -> Result<u64, String> {
    let s = v.trim();
    if let Some(d) = parse_duration_ms(s) {
        return Ok(util_now_ms().saturating_sub(d));
    }
    parse_iso(s).ok_or_else(|| format!("--{flag}: `{s}` is not a duration or an ISO timestamp (try 5h, 30m, 2d, 1w, 90 or 2026-07-05 14:30)"))
}

/// `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, `YYYY-MM-DDTHH:MM:SS`, optional trailing `Z` → unix millis.
pub fn parse_iso(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches(['Z', 'z']).replace('T', " ");
    let (date, time) = match s.split_once(' ') {
        Some((d, t)) => (d, t.trim()),
        None => (s.as_str(), ""),
    };
    let mut dp = date.split('-');
    let (y, m, d) = (dp.next()?, dp.next()?, dp.next()?);
    if dp.next().is_some() {
        return None;
    }
    let (y, m, d): (i64, u32, u32) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || d == 0 || d > 31 || seagent_kernel::util::civil_from_days(days_from_civil(y, m, d)) != (y, m, d) {
        return None;
    }
    let mut secs: i64 = 0;
    if !time.is_empty() {
        let mut tp = time.split(':');
        let hh: i64 = tp.next()?.parse().ok()?;
        let mm: i64 = tp.next().unwrap_or("0").parse().ok()?;
        let ss: i64 = tp.next().unwrap_or("0").parse().ok()?;
        if tp.next().is_some() || hh > 23 || mm > 59 || ss > 59 {
            return None;
        }
        secs = hh * 3_600 + mm * 60 + ss;
    }
    Some((days_from_civil(y, m, d) * 86_400 + secs).max(0) as u64 * 1000)
}

// ───────────────────────── archive / unarchive ─────────────────────────

fn cmd_archive(store: &Store, o: &Opts) -> Result<String, String> {
    let mut f = Filter::from(o)?;
    f.include_archived = false; // already-hidden sessions are left alone
    if !f.any() {
        return Err("refusing to archive every session: pass at least one filter (e.g. --older-than 30d, --title codex, --model sonnet)".into());
    }
    let spared = f.pinned_spared(store);
    let rows = f.select(store);
    let mut out = Vec::new();
    if !f.include_pinned && spared > 0 {
        out.push(format!("note: {spared} pinned session(s) also match but were skipped — unpin them (`seagent session unpin <id>`) or pass --include-pinned"));
    }
    if rows.is_empty() {
        out.push(format!("no sessions match ({})", f.describe()));
        return Ok(out.join("\n"));
    }
    if o.flag("dry-run") {
        out.push(format!("{} session(s) would be archived ({}):", rows.len(), f.describe()));
        out.extend(rows.iter().map(|r| r.line()));
        out.push("dry run — nothing archived.".into());
        return Ok(out.join("\n"));
    }
    let mut n = 0;
    let mut bad = Vec::new();
    for r in &rows {
        match record(store, &r.info.id, meta_event(None, Some(true), None, None)) {
            Ok(()) => n += 1,
            Err(e) => bad.push(format!("{}: {e}", r.info.id)),
        }
    }
    out.push(format!("archived {n} session(s) ({})", f.describe()));
    out.push("they are hidden from listings but nothing was deleted — restore with `seagent session unarchive <id>`.".into());
    if bad.is_empty() {
        Ok(out.join("\n"))
    } else {
        Err(format!("{}\n{}", out.join("\n"), bad.join("\n")))
    }
}

fn cmd_unarchive(store: &Store, o: &Opts) -> Result<String, String> {
    let ids: Vec<String> = o.pos.iter().skip(1).cloned().collect();
    if ids.is_empty() {
        return Err("missing <session> (usage: `seagent session unarchive <id…>`, or filters to `seagent session archive`)".into());
    }
    let (mut ok, mut bad) = (Vec::new(), Vec::new());
    for q in &ids {
        match resolve(store, q) {
            Ok(id) => match record(store, &id, meta_event(None, Some(false), None, None)) {
                Ok(()) => ok.push(format!("unarchived {id}  ({})", title_of(store, &id).unwrap_or_else(|| "(untitled)".into()))),
                Err(e) => bad.push(format!("unarchive {}: {e}", safe(q))),
            },
            Err(e) => bad.push(e),
        }
    }
    finish(ok, bad)
}

// ───────────────────────── label / group (set semantics) ─────────────────────────

enum MetaField {
    Group,
    Status,
}

fn cmd_meta(store: &Store, o: &Opts, field: MetaField, sub: &str, what: &str) -> Result<String, String> {
    let id = resolve(store, o.need(1, "session")?)?;
    if o.pos(2).is_none() {
        return Err(format!("missing <{what}> for `{sub}` (pass an empty string to clear it)"));
    }
    let value = one_line(&o.rest(2));
    let cap = if matches!(field, MetaField::Group) { 60 } else { 120 };
    let value: String = value.chars().take(cap).collect();
    let kind = match field {
        MetaField::Group => meta_event(None, None, Some(value.clone()), None),
        MetaField::Status => meta_event(None, None, None, Some(value.clone())),
    };
    record(store, &id, kind)?;
    let note = format!("set operation — it replaces the previous {what}; an empty {what} clears it");
    Ok(if value.is_empty() {
        format!("{sub} {id}: {what} cleared ({note})")
    } else {
        format!("{sub} {id}: {what} = \"{value}\" ({note})")
    })
}

// ───────────────────────── stats ─────────────────────────

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    for e in rd.flatten() {
        let path = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => total += dir_size(&path),
            Ok(t) if t.is_file() => total += e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => {}
        }
    }
    total
}

fn cmd_stats(store: &Store, o: &Opts) -> Result<String, String> {
    let rows = rows(store);
    let sessions = rows.len();
    let children = rows.iter().filter(|r| r.info.parent.is_some()).count();
    let messages: usize = rows.iter().map(|r| r.info.messages).sum();
    let turns: u64 = rows.iter().map(|r| r.turns).sum();
    let mut usage = Usage::default();
    for r in &rows {
        usage.add(&r.usage);
    }
    let pinned = rows.iter().filter(|r| r.pinned).count();
    let archived = rows.iter().filter(|r| r.archived).count();
    let disk = dir_size(store.root());
    let oldest = rows.iter().min_by_key(|r| r.info.created_ms).map(|r| r.info.created_ms);
    let newest = rows.iter().max_by_key(|r| r.info.updated_ms).map(|r| r.info.updated_ms);
    if o.flag("json") {
        let v = json!({
            "sessions": sessions,
            "children": children,
            "messages": messages,
            "turns": turns,
            "tokens": {"input": usage.input_tokens, "output": usage.output_tokens, "cache_read": usage.cache_read_tokens, "cache_write": usage.cache_write_tokens, "total": usage.total()},
            "bytes": disk,
            "pinned": pinned,
            "archived": archived,
            "oldest": oldest.map(super::iso),
            "newest": newest.map(super::iso),
        });
        return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()));
    }
    if sessions == 0 {
        return Ok("sessions: 0\nmessages: 0\ntokens: 0".into());
    }
    let mut out = vec![
        format!("sessions: {sessions}{}", if children > 0 { format!(" ({children} sub-agent)") } else { String::new() }),
        format!("messages: {messages} ({turns} turns)"),
        format!("tokens: {} (in {} · out {} · cache read {})", usage.total(), usage.input_tokens, usage.output_tokens, usage.cache_read_tokens),
        format!("disk: {} in {}", bytes(disk), store.root().display()),
        format!("pinned: {pinned} · archived: {archived}"),
    ];
    let ts = |ms: Option<u64>| ms.map(super::iso).unwrap_or_else(|| "-".into());
    out.push(format!("oldest: {} · newest: {}", ts(oldest), ts(newest)));
    Ok(out.join("\n"))
}

// ───────────────────────── prune ─────────────────────────

fn cmd_prune(store: &Store, o: &Opts) -> Result<String, String> {
    let mut f = Filter::from(o)?;
    if !f.any() {
        // Bare `prune` keeps the historical default; any filter suppresses the implicit cutoff.
        f.older_than = Some(util_now_ms().saturating_sub(90 * 86_400_000));
        f.implied = Some("default: older than 90 days; pass a filter to change it".into());
    }
    let spared = if f.include_pinned { 0 } else { f.pinned_spared(store) };
    let rows = f.select(store);
    let mut out = Vec::new();
    if spared > 0 {
        out.push(format!("note: {spared} pinned session(s) also match but were skipped (pin is a keep flag) — pass --include-pinned or unpin them first"));
    }
    if rows.is_empty() {
        out.push(format!("no sessions match ({})", f.describe()));
        return Ok(out.join("\n"));
    }
    let dry = o.flag("dry-run");
    let show = if dry { rows.len() } else { rows.len().min(15) };
    out.push(format!("{} session(s) match ({}):", rows.len(), f.describe()));
    out.extend(rows.iter().take(show).map(|r| r.line()));
    if rows.len() > show {
        out.push(format!("  … and {} more", rows.len() - show));
    }
    if dry {
        out.push("dry run — nothing deleted.".into());
        return Ok(out.join("\n"));
    }
    if !o.flag("yes") {
        out.push(format!("nothing deleted — re-run with `--yes` to delete these {} session(s).", rows.len()));
        return Ok(out.join("\n"));
    }
    let (mut n, mut bad) = (0, Vec::new());
    for r in &rows {
        match store.remove(&r.info.id) {
            Ok(()) => n += 1,
            Err(e) => bad.push(format!("  skipped {}: {e}", r.info.id)),
        }
    }
    out.push(format!("deleted {n} session(s)"));
    if bad.is_empty() {
        Ok(out.join("\n"))
    } else {
        Err(format!("{}\n{}", out.join("\n"), bad.join("\n")))
    }
}

// ───────────────────────── import (Claude Code / Codex CLI) ─────────────────────────

/// One conversation read out of a foreign session file.
#[derive(Debug, Default, Clone)]
pub struct Foreign {
    /// "claude" or "codex".
    pub source: String,
    pub path: PathBuf,
    /// (is_assistant, text) in log order, already merged into strict alternation.
    pub turns: Vec<(bool, String)>,
    pub cwd: Option<String>,
    pub title: Option<String>,
    pub model: Option<String>,
}

const CLAUDE_WRAPPERS: &[&str] = &[
    "<user_instructions",
    "<environment_context",
    "<recommended_plugins",
    "<skills_instructions",
    "<permissions_instructions",
    "<permissions-instructions",
    "<turn_context",
    "<command-name",
    "<command-message",
    "<local-command-stdout",
    "<system-reminder",
];

fn is_wrapper(t: &str) -> bool {
    let l = t.trim_start();
    CLAUDE_WRAPPERS.iter().any(|w| l.get(..w.len()).is_some_and(|p| p.eq_ignore_ascii_case(w)))
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    text.lines().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok()).collect()
}

fn block_text(b: &Value) -> Option<String> {
    match b {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => match o.get("type").and_then(Value::as_str).unwrap_or("") {
            "text" | "input_text" | "output_text" => o.get("text").and_then(Value::as_str).map(String::from),
            "tool_use" | "tool_call" | "function_call" => Some(format!("[ran tool: {}]", o.get("name").and_then(Value::as_str).unwrap_or("tool"))),
            "image" => Some("[image]".into()),
            _ => None,
        },
        _ => None,
    }
}

fn flatten(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().filter_map(block_text).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n\n"),
        _ => String::new(),
    }
}

/// One `(role, text)` turn from a `{role, content}` message, or None when it is not importable.
fn message_turn(m: &Value) -> Option<(bool, String)> {
    let role = m.get("role")?.as_str()?;
    if role != "user" && role != "assistant" {
        return None;
    }
    let text = flatten(m.get("content")?);
    if text.trim().is_empty() || (role == "user" && is_wrapper(&text)) {
        return None;
    }
    Some((role == "assistant", text))
}

/// Merge consecutive same-role turns; a conversation that starts with an assistant reply gets a
/// one-line user stub so the provider's alternation invariant holds (Hermes `_merge_turns`).
fn merge_turns(raw: Vec<(bool, String)>) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new();
    for (a, t) in raw {
        let t = t.trim().to_string();
        if t.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some((last, text)) if *last == a => {
                text.push_str("\n\n");
                text.push_str(&t);
            }
            _ => out.push((a, t)),
        }
    }
    if out.first().is_some_and(|(a, _)| *a) {
        out.insert(0, (false, "(imported conversation begins with an assistant reply)".into()));
    }
    out
}

fn first_user_line(turns: &[(bool, String)]) -> Option<String> {
    turns.iter().find(|(a, _)| !*a).map(|(_, t)| t.trim().lines().next().unwrap_or("").trim().to_string()).filter(|s| !s.is_empty())
}

/// Claude Code: one JSONL per session under `~/.claude/projects/<project>/`.
pub fn parse_claude(path: &Path) -> Result<Foreign, String> {
    let mut f = Foreign { source: "claude".into(), path: path.into(), ..Default::default() };
    let mut raw = Vec::new();
    let mut summary: Option<String> = None;
    for obj in read_jsonl(path) {
        match obj.get("type").and_then(Value::as_str).unwrap_or("") {
            "summary" => {
                if let Some(s) = obj.get("summary").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
                    summary = Some(s.to_string());
                }
            }
            "user" | "assistant" => {
                if obj.get("isSidechain").and_then(Value::as_bool) == Some(true) || obj.get("isMeta").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                if f.cwd.is_none() {
                    f.cwd = obj.get("cwd").and_then(Value::as_str).map(String::from);
                }
                if f.model.is_none() {
                    f.model = obj.get("message").and_then(|m| m.get("model")).and_then(Value::as_str).map(String::from);
                }
                if let Some(t) = obj.get("message").and_then(message_turn) {
                    raw.push(t);
                }
            }
            _ => {}
        }
    }
    f.turns = merge_turns(raw);
    f.title = summary.or_else(|| first_user_line(&f.turns));
    Ok(f)
}

/// Codex CLI: `~/.codex/sessions/**/rollout-*.jsonl`, one event object per line.
pub fn parse_codex(path: &Path) -> Result<Foreign, String> {
    let mut f = Foreign { source: "codex".into(), path: path.into(), ..Default::default() };
    let mut raw = Vec::new();
    for obj in read_jsonl(path) {
        let Some(payload) = obj.get("payload").filter(|p| p.is_object()) else { continue };
        match obj.get("type").and_then(Value::as_str).unwrap_or("") {
            "session_meta" => {
                f.cwd = payload.get("cwd").and_then(Value::as_str).map(String::from).or(f.cwd);
                f.model = payload.get("model").and_then(Value::as_str).map(String::from).or(f.model);
            }
            "turn_context" => {
                if f.model.is_none() {
                    f.model = payload.get("model").and_then(Value::as_str).map(String::from);
                }
            }
            "response_item" => match payload.get("type").and_then(Value::as_str).unwrap_or("") {
                "message" => {
                    if let Some(t) = message_turn(payload) {
                        raw.push(t);
                    }
                }
                // Assistant activity; tool outputs and reasoning are skipped.
                "custom_tool_call" | "function_call" | "local_shell_call" => {
                    let name = payload.get("name").or_else(|| payload.get("tool")).and_then(Value::as_str).unwrap_or("tool");
                    raw.push((true, format!("[ran tool: {name}]")));
                }
                _ => {}
            },
            _ => {}
        }
    }
    f.turns = merge_turns(raw);
    f.title = first_user_line(&f.turns);
    Ok(f)
}

fn parse_foreign(source: &str, path: &Path) -> Result<Foreign, String> {
    match source {
        "claude" => parse_claude(path),
        "codex" => parse_codex(path),
        other => Err(format!("unknown source `{other}`: use claude or codex")),
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// Where a tool keeps its sessions: `CLAUDE_CONFIG_DIR` / `CODEX_HOME` win over `~`.
pub fn foreign_root(source: &str) -> Option<PathBuf> {
    let env = |k: &str, sub: &str| std::env::var_os(k).map(PathBuf::from).filter(|p| !p.as_os_str().is_empty()).map(|p| p.join(sub));
    match source {
        "claude" => env("CLAUDE_CONFIG_DIR", "projects").or_else(|| home_dir().map(|h| h.join(".claude/projects"))),
        "codex" => env("CODEX_HOME", "sessions").or_else(|| home_dir().map(|h| h.join(".codex/sessions"))),
        _ => None,
    }
}

fn files_under(root: &Path, recursive: bool) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, recursive: bool, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() && (recursive || depth == 0) => walk(&p, depth + 1, recursive, out),
                Ok(t) if t.is_file() => out.push(p),
                _ => {}
            }
        }
    }
    let mut v = Vec::new();
    walk(root, 0, recursive, &mut v);
    v
}

/// Foreign sessions under `root` (default: the tool's own store), newest first.
pub fn discover(source: Option<&str>, root: Option<&Path>) -> Vec<Foreign> {
    let mut out = Vec::new();
    for src in ["claude", "codex"] {
        if source.is_some_and(|s| s != src) {
            continue;
        }
        let Some(root) = root.map(PathBuf::from).or_else(|| foreign_root(src)) else { continue };
        if !root.is_dir() {
            continue;
        }
        for p in files_under(&root, src == "codex") {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let ok = if src == "codex" { name.starts_with("rollout-") && name.ends_with(".jsonl") } else { name.ends_with(".jsonl") };
            if !ok {
                continue;
            }
            if let Ok(f) = parse_foreign(src, &p) {
                if !f.turns.is_empty() {
                    out.push(f);
                }
            }
        }
    }
    out.sort_by_key(|f| {
        let t = std::fs::metadata(&f.path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        std::cmp::Reverse(t)
    });
    out
}

fn infer_source(p: &Path) -> Option<&'static str> {
    let s = p.to_string_lossy();
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if s.contains("/.codex/") || name.starts_with("rollout-") {
        return Some("codex");
    }
    if s.contains("/.claude/") || (name.ends_with(".jsonl") && s.to_lowercase().contains("claude")) {
        return Some("claude");
    }
    None
}

fn source_label(s: &str) -> &'static str {
    match s {
        "claude" => "Claude Code",
        "codex" => "Codex CLI",
        _ => "foreign",
    }
}

fn cmd_import(store: &Store, o: &Opts) -> Result<String, String> {
    let want = o.val("from").map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    if let Some(w) = &want {
        if !matches!(w.as_str(), "claude" | "codex") {
            return Err(format!("--from `{w}`: use claude or codex"));
        }
    }
    let (source, path) = match o.pos(1) {
        Some(raw) => {
            let p = seagent_core::tool::expand_home(raw);
            if !p.is_file() {
                return Err(format!("file not found: {}", p.display()));
            }
            let src = match &want {
                Some(w) => w.clone(),
                None => infer_source(&p).ok_or_else(|| format!("cannot infer the source from `{}` — pass --from claude|codex", p.display()))?.to_string(),
            };
            (src, p)
        }
        None => {
            let mut found = discover(want.as_deref(), None);
            let pick = found.drain(..).next().ok_or_else(|| format!("no {} sessions found on this machine", want.map(|w| source_label(&w).to_string()).unwrap_or_else(|| "Claude Code or Codex CLI".into())))?;
            (pick.source.clone(), pick.path.clone())
        }
    };
    let parsed = parse_foreign(&source, &path)?;
    if parsed.turns.is_empty() {
        return Err(format!("no user/assistant conversation turns found in {}", path.display()));
    }
    let title = format!("Imported from {}: {}", source_label(&source), parsed.title.clone().unwrap_or_else(|| path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()));
    let id = new_id();
    let model = parsed.model.clone().filter(|m| m.contains('/')).unwrap_or_else(|| seagent_kernel::config::Config::default().model.default);
    // No cwd in the foreign log: the session belongs where the import ran.
    let workspace = parsed.cwd.clone().filter(|c| !c.trim().is_empty()).unwrap_or_else(|| std::env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_default());
    let mut log = store
        .create(EventKind::Header {
            version: LOG_VERSION,
            session_id: id.clone(),
            workspace,
            model,
            parent: None,
            title: Some(clip(&one_line(&title), 60)),
        })
        .map_err(|e| e.to_string())?;
    let mut n = 0;
    for (assistant, text) in &parsed.turns {
        let message = if *assistant { Message::assistant(text.clone()) } else { Message::user(text.clone()) };
        log.append(EventKind::Message { message, usage: None, model: None, inbox: None }).map_err(|e| e.to_string())?;
        n += 1;
    }
    drop(log);
    Ok(format!("imported {} session as {id} ({n} messages)\n  continue it with: seagent session resume {id}", source_label(&source)))
}

// ───────────────────────── repair ─────────────────────────

#[derive(Debug, Default)]
struct Fix {
    dropped: usize,
    added_header: bool,
    renumbered: usize,
    duplicate_headers: usize,
}

/// Rebuild one event log: parse line by line, drop what cannot be parsed, restore a missing
/// header, recompute `seq`. Returns what changed; writes only when `!check_only`.
fn repair_file(path: &Path, id: &str, check_only: bool) -> Result<Fix, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut keep: Vec<Event> = Vec::new();
    let mut fix = Fix::default();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(t) {
            Ok(ev) => match &ev.kind {
                // Only the first event may be the header; a later one is a spliced-in duplicate.
                EventKind::Header { .. } if !keep.is_empty() => fix.duplicate_headers += 1,
                _ => keep.push(ev),
            },
            Err(_) => fix.dropped += 1,
        }
    }
    if !matches!(keep.first().map(|e| &e.kind), Some(EventKind::Header { .. })) {
        let ts = keep.first().map(|e| e.ts).unwrap_or_else(unix_now_ms);
        keep.insert(0, Event { seq: 0, ts, kind: EventKind::Header { version: LOG_VERSION, session_id: id.to_string(), workspace: String::new(), model: String::new(), parent: None, title: None } });
        fix.added_header = true;
    }
    for (i, ev) in keep.iter_mut().enumerate() {
        if ev.seq != i as u64 {
            fix.renumbered += 1;
            ev.seq = i as u64;
        }
    }
    let changed = fix.dropped > 0 || fix.added_header || fix.renumbered > 0 || fix.duplicate_headers > 0;
    if changed && !check_only {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "events.jsonl".into());
        let bak = path.with_file_name(format!("{name}.bak-{}", new_id()));
        std::fs::copy(path, &bak).map_err(|e| format!("backup {}: {e}", bak.display()))?;
        let mut out = String::with_capacity(text.len());
        for ev in &keep {
            out.push_str(&serde_json::to_string(ev).map_err(|e| e.to_string())?);
            out.push('\n');
        }
        atomic_write(path, out.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(fix)
}

fn unix_now_ms() -> u64 {
    unix_now() as u64 * 1000
}

fn cmd_repair(store: &Store, o: &Opts) -> Result<String, String> {
    let check_only = o.flag("check-only");
    let wanted: Vec<String> = o.pos.iter().skip(1).cloned().collect();
    let ids: Vec<String> = if wanted.is_empty() {
        all_ids(store)
    } else {
        let all = all_ids(store);
        let mut v = Vec::new();
        for q in &wanted {
            let m: Vec<&String> = all.iter().filter(|id| *id == q || id.starts_with(q.as_str())).collect();
            match m.len() {
                0 => return Err(format!("no session `{}` (try `seagent session list`)", safe(q))),
                1 => v.push(m[0].clone()),
                n => return Err(format!("`{}` matches {n} sessions — be more specific", safe(q))),
            }
        }
        v
    };
    if ids.is_empty() {
        return Ok("no session logs to repair".into());
    }
    let mut checked = 0;
    let mut repaired = 0;
    let mut dropped = 0;
    let mut renumbered = 0;
    let mut headers = 0;
    let mut skipped: Vec<String> = Vec::new();
    for id in &ids {
        let path = store.dir(id).join("events.jsonl");
        if !path.is_file() {
            continue;
        }
        checked += 1;
        // A session another process is running must not be rewritten underneath it.
        if matches!(store.open(id), Err(seagent_kernel::store::StoreError::Locked(_))) {
            skipped.push(format!("  {id}: in use by another seagent process — skipped"));
            continue;
        }
        let fix = repair_file(&path, id, check_only)?;
        if fix.dropped > 0 || fix.added_header || fix.renumbered > 0 || fix.duplicate_headers > 0 {
            repaired += 1;
            dropped += fix.dropped;
            renumbered += fix.renumbered;
            headers += fix.added_header as usize;
        }
    }
    let mut out = Vec::new();
    if repaired == 0 {
        out.push(format!("all {checked} session log(s) are healthy"));
    } else if check_only {
        out.push(format!("{repaired} of {checked} session log(s) need repair ({dropped} bad line(s), {headers} missing header(s), {renumbered} out-of-order seq) — re-run without --check-only to fix"));
    } else {
        out.push(format!("repaired {repaired} file(s): dropped {dropped} bad line(s), restored {headers} header(s), renumbered {renumbered} event(s); originals kept as <file>.bak-<ts>"));
    }
    out.extend(skipped);
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> Store {
        let root = seagent_core::tmp::scratch_path(format!("seagent-sessions-{}", seagent_kernel::util::random_hex(10)));
        let mut s = Store::new(root);
        s.sync = false;
        s
    }

    fn opts(v: &[&str]) -> Opts {
        Opts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), VALUE_FLAGS, BOOL_FLAGS).unwrap()
    }

    fn run_ok(store: &Store, v: &[&str]) -> String {
        run(store, &opts(v)).unwrap()
    }

    /// Write a session log directly (full control over timestamps, which `store.create` sets to
    /// "now"): header, `msgs` messages, a TurnEnd with usage, then `extra` events.
    fn write_session(store: &Store, id: &str, parent: Option<&str>, msgs: usize, ts: u64, extra: &[EventKind]) {
        let dir = store.dir(id);
        std::fs::create_dir_all(dir.join("artifacts")).unwrap();
        let mut evs = vec![Event {
            seq: 0,
            ts,
            kind: EventKind::Header { version: LOG_VERSION, session_id: id.into(), workspace: "/ws".into(), model: "echo/m".into(), parent: parent.map(String::from), title: Some(format!("session {id}")) },
        }];
        for i in 0..msgs {
            let message = if i % 2 == 0 { Message::user(format!("question {i}")) } else { Message::assistant(format!("answer {i}")) };
            evs.push(Event { seq: 0, ts, kind: EventKind::Message { message, usage: None, model: None, inbox: None } });
        }
        evs.push(Event { seq: 0, ts, kind: EventKind::TurnEnd { turn: 0, reason: "done".into(), usage: Usage { input_tokens: 100, output_tokens: 20, ..Default::default() } } });
        for k in extra {
            evs.push(Event { seq: 0, ts, kind: k.clone() });
        }
        for (i, e) in evs.iter_mut().enumerate() {
            e.seq = i as u64;
        }
        let text: String = evs.iter().map(|e| serde_json::to_string(e).unwrap() + "\n").collect();
        std::fs::write(dir.join("events.jsonl"), text).unwrap();
    }

    fn view(store: &Store, id: &str) -> seagent_kernel::projection::View {
        seagent_kernel::projection::project(&store.read(id).unwrap())
    }

    #[test]
    fn rename_pin_archive_label_group_roundtrip() {
        let store = tmp_store();
        write_session(&store, "s1", None, 2, 1_000, &[]);
        // rename (multi-word title, control characters stripped)
        assert_eq!(run_ok(&store, &["rename", "s1", "fix", "the\u{1b}", "parser"]), "renamed s1 → fix the parser");
        assert_eq!(view(&store, "s1").title.as_deref(), Some("fix the parser"));
        // an explicit empty title clears it
        assert_eq!(run_ok(&store, &["rename", "s1", ""]), "cleared the title of s1");
        assert_eq!(view(&store, "s1").title.as_deref().unwrap_or_default(), "");
        // a prefix resolves to the one session
        assert!(run_ok(&store, &["rename", "s", "by prefix"]).contains("by prefix"));

        assert!(run_ok(&store, &["pin", "s1"]).starts_with("pinned s1"));
        assert!(view(&store, "s1").pinned);
        assert!(run_ok(&store, &["pinned"]).contains("s1") && run_ok(&store, &["pinned", "--json"]).contains("\"id\": \"s1\""));
        assert!(run_ok(&store, &["unpin", "s1"]).starts_with("unpinned s1"));
        assert!(!view(&store, "s1").pinned);

        // label → group, group → status; both are set operations that echo what they set
        let l = run_ok(&store, &["label", "s1", "work"]);
        assert!(l.contains("group = \"work\"") && l.contains("set operation"), "{l}");
        assert_eq!(view(&store, "s1").group.as_deref(), Some("work"));
        let g = run_ok(&store, &["group", "s1", "in review"]);
        assert!(g.contains("status = \"in review\"") && g.contains("set operation"), "{g}");
        assert_eq!(view(&store, "s1").status.as_deref(), Some("in review"));
        // empty values clear them
        assert!(run_ok(&store, &["label", "s1", ""]).contains("group cleared"));
        assert!(run_ok(&store, &["group", "s1", ""]).contains("status cleared"));
        assert!(view(&store, "s1").group.is_none() && view(&store, "s1").status.is_none());

        // archive / unarchive
        assert!(run_ok(&store, &["archive", "--title", "by prefix"]).contains("archived 1 session(s)"));
        assert!(view(&store, "s1").archived);
        assert!(run_ok(&store, &["unarchive", "s1"]).starts_with("unarchived s1"));
        assert!(!view(&store, "s1").archived);

        // concrete errors
        let e = run(&store, &opts(&["rename", "nope", "x"])).unwrap_err();
        assert!(e.contains("no session `nope`") && e.contains("seagent session list"), "{e}");
        assert!(run(&store, &opts(&["rename", "s1"])).is_err(), "missing title is an error");
        assert!(run(&store, &opts(&["pin"])).is_err(), "missing id is an error");
        assert!(run(&store, &opts(&["archive"])).unwrap_err().contains("refusing to archive every session"));
    }

    #[test]
    fn prune_respects_pin_archive_dry_run_and_yes() {
        let store = tmp_store();
        let now = util_now_ms();
        let day = 86_400_000u64;
        write_session(&store, "old", None, 1, now.saturating_sub(100 * day), &[]);
        write_session(&store, "older", None, 6, now.saturating_sub(120 * day), &[]);
        write_session(&store, "fresh", None, 1, now.saturating_sub(day), &[]);
        write_session(&store, "pinned", None, 1, now.saturating_sub(200 * day), &[meta_event(Some(true), None, None, None)]);
        write_session(&store, "archived", None, 1, now.saturating_sub(200 * day), &[meta_event(None, Some(true), None, None)]);

        // bare prune = older than 90 days, pinned/archived spared, never deletes without --yes
        let out = run_ok(&store, &["prune"]);
        assert!(out.contains("2 session(s) match"), "{out}");
        assert!(out.contains("pinned session(s) also match but were skipped"), "{out}");
        assert!(out.contains("nothing deleted — re-run with `--yes`"), "{out}");
        assert_eq!(store.list().len(), 5, "nothing was deleted");

        // --dry-run lists and stops even with --yes
        let out = run_ok(&store, &["prune", "--dry-run", "--yes", "--older-than", "90"]);
        assert!(out.contains("dry run — nothing deleted."), "{out}");
        assert_eq!(store.list().len(), 5);

        // filters: title + message count narrow the set
        let out = run_ok(&store, &["prune", "--older-than", "50d", "--min-messages", "5", "--dry-run"]);
        assert!(out.contains("1 session(s) match") && out.contains("older"), "{out}");
        let out = run_ok(&store, &["prune", "--older-than", "50d", "--max-messages", "1", "--title", "session old", "--dry-run"]);
        assert!(out.contains("1 session(s) match"), "{out}");

        // --after/--before bound the session start (Hermes build_prune_filters)
        let out = run_ok(&store, &["prune", "--after", "110d", "--before", "50d", "--dry-run"]);
        assert!(out.contains("1 session(s) match") && out.contains("  old "), "{out}");

        // --include-archived reaches the archived one, --include-pinned the pinned one
        assert!(run_ok(&store, &["prune", "--older-than", "150d", "--include-pinned", "--include-archived", "--dry-run"]).contains("2 session(s) match"));
        assert!(run_ok(&store, &["prune", "--older-than", "150d", "--dry-run"]).contains("no sessions match"));

        // real delete
        let out = run_ok(&store, &["prune", "--older-than", "90d", "--yes", "--limit", "1"]);
        assert!(out.contains("deleted 1 session(s)"), "{out}");
        let ids: Vec<String> = store.list().into_iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), 4);
        assert!(!ids.contains(&"older".to_string()), "the oldest went first: {ids:?}");
        assert!(ids.contains(&"pinned".to_string()) && ids.contains(&"archived".to_string()) && ids.contains(&"fresh".to_string()));

        // age parsing (Hermes parse_duration_seconds)
        assert_eq!(parse_duration_ms("5h"), Some(5 * 3_600_000));
        assert_eq!(parse_duration_ms("2d"), Some(2 * 86_400_000));
        assert_eq!(parse_duration_ms("1w"), Some(7 * 86_400_000));
        assert_eq!(parse_duration_ms("90"), Some(90 * 86_400_000));
        assert_eq!(parse_duration_ms("30m"), Some(1_800_000));
        assert_eq!(parse_duration_ms("soon"), None);
        let iso = parse_iso("2026-07-05 14:30").unwrap();
        assert_eq!(iso, (days_from_civil(2026, 7, 5) * 86_400 + 14 * 3_600 + 1_800) as u64 * 1000);
        assert!(parse_point_in_time("2026-07-05T14:30:00Z", "after").is_ok());
        assert!(parse_point_in_time("yesterday", "after").is_err());
    }

    #[test]
    fn stats_counts() {
        let store = tmp_store();
        let now = util_now_ms();
        write_session(&store, "a", None, 4, now.saturating_sub(2 * 86_400_000), &[meta_event(Some(true), None, None, None)]);
        write_session(&store, "b", Some("a"), 2, now.saturating_sub(86_400_000), &[meta_event(None, Some(true), None, None)]);
        write_session(&store, "c", None, 1, now, &[]);

        let out = run_ok(&store, &["stats"]);
        assert!(out.contains("sessions: 3 (1 sub-agent)"), "{out}");
        assert!(out.contains("messages: 7 (3 turns)"), "{out}");
        assert!(out.contains("tokens: 360 (in 300 · out 60"), "{out}");
        assert!(out.contains("pinned: 1 · archived: 1"), "{out}");
        assert!(out.contains("disk: ") && out.contains("oldest: ") && out.contains("newest: "), "{out}");

        let j: Value = serde_json::from_str(&run_ok(&store, &["stats", "--json"])).unwrap();
        assert_eq!(j["sessions"], 3);
        assert_eq!(j["children"], 1);
        assert_eq!(j["messages"], 7);
        assert_eq!(j["tokens"]["total"], 360);
        assert_eq!(j["pinned"], 1);
        assert_eq!(j["archived"], 1);
        assert!(j["bytes"].as_u64().unwrap() > 0);
        assert!(j["oldest"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn import_claude_fixture() {
        let store = tmp_store();
        let dir = seagent_core::tmp::scratch_path(format!("seagent-claude-{}", seagent_kernel::util::random_hex(8)));
        let file = dir.join("projects/p1/abc.jsonl");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let lines = [
            r#"{"type":"summary","summary":"Fix the build"}"#,
            r#"{"type":"user","cwd":"/work/repo","sessionId":"abc","message":{"role":"user","content":"fix the build"}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","model":"anthropic/claude-sonnet-4-5","content":[{"type":"text","text":"on it"},{"type":"tool_use","name":"Bash"}]}}"#,
            r#"not json at all"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"thanks"}]}}"#,
        ];
        std::fs::write(&file, lines.join("\n") + "\n").unwrap();

        let out = run_ok(&store, &["import", file.to_str().unwrap()]);
        assert!(out.starts_with("imported Claude Code session as "), "{out}");
        assert!(out.contains("(3 messages)"), "{out}");
        let list = store.list();
        assert_eq!(list.len(), 1);
        let s = &list[0];
        assert_eq!(s.messages, 3);
        assert_eq!(s.model, "anthropic/claude-sonnet-4-5");
        assert_eq!(s.workspace, "/work/repo");
        assert!(s.title.as_deref().unwrap().starts_with("Imported from Claude Code: Fix the build"), "{:?}", s.title);
        let v = view(&store, &s.id);
        assert!(v.messages[1].text().contains("[ran tool: Bash]"), "{:?}", v.messages[1].text());
        // the foreign file is only read
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 5);

        // explicit --from wins; discovery finds the fixture under a claude root
        assert!(run_ok(&store, &["import", "--from", "claude", file.to_str().unwrap()]).contains("imported Claude Code"));
        let found = std::path::Path::new(file.parent().unwrap()).parent().unwrap();
        let d = discover(Some("claude"), Some(found));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].turns.len(), 3);
        assert!(discover(Some("codex"), Some(found)).is_empty());

        // errors are specific
        let e = run(&store, &opts(&["import", "/nonexistent/session.jsonl"])).unwrap_err();
        assert!(e.contains("file not found"), "{e}");
        std::fs::write(dir.join("empty.jsonl"), "").unwrap();
        let e = run(&store, &opts(&["import", "--from", "claude", dir.join("empty.jsonl").to_str().unwrap()])).unwrap_err();
        assert!(e.contains("no user/assistant conversation turns"), "{e}");
    }

    #[test]
    fn repair_drops_bad_lines_and_keeps_backup() {
        let store = tmp_store();
        // a) valid log with a corrupt line in the middle and a broken seq
        write_session(&store, "broken", None, 2, 1_000, &[]);
        let p = store.dir("broken").join("events.jsonl");
        let good = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = good.lines().collect();
        lines.insert(2, "{not json");
        lines.push(r#"{"seq":99,"ts":1000,"type":"title","title":"after the gap"}"#);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        // b) a log whose header is gone
        write_session(&store, "headerless", None, 1, 2_000, &[]);
        let hp = store.dir("headerless").join("events.jsonl");
        let hlines: Vec<String> = std::fs::read_to_string(&hp).unwrap().lines().map(String::from).collect();
        std::fs::write(&hp, hlines[1..].join("\n") + "\n").unwrap();
        // c) a healthy one must not be touched
        write_session(&store, "healthy", None, 1, 3_000, &[]);

        let check = run_ok(&store, &["repair", "--check-only"]);
        assert!(check.contains("2 of 3 session log(s) need repair"), "{check}");
        assert!(check.contains("1 bad line(s)"), "{check}");
        assert!(std::fs::read_to_string(&p).unwrap().contains("{not json"), "--check-only must not write");

        let out = run_ok(&store, &["repair"]);
        assert!(out.starts_with("repaired 2 file(s): dropped 1 bad line(s), restored 1 header(s)"), "{out}");

        // the bad line is gone, the seqs are 0..n and the logs parse again
        let fixed = std::fs::read_to_string(&p).unwrap();
        assert!(!fixed.contains("{not json"), "{fixed}");
        let evs = store.read("broken").unwrap();
        assert_eq!(evs.iter().enumerate().filter(|(i, e)| e.seq != *i as u64).count(), 0);
        assert!(evs.iter().any(|e| matches!(&e.kind, EventKind::Title { title } if title == "after the gap")));
        let hv = view(&store, "headerless");
        assert_eq!(hv.session_id, "headerless");
        assert_eq!(store.list().len(), 3, "every session lists again");
        // a timestamped backup of each rewritten log is kept
        let baks: Vec<String> = std::fs::read_dir(store.dir("broken")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.contains(".bak-")).collect();
        assert_eq!(baks.len(), 1, "{baks:?}");
        assert!(std::fs::read_to_string(store.dir("broken").join(&baks[0])).unwrap().contains("{not json"), "the original is preserved");
        // and it is idempotent
        assert!(run_ok(&store, &["repair"]).contains("are healthy"));
    }

    /// The global `Args` parser feeds the same bag (flags it knows about reach the subcommands).
    #[test]
    fn args_bridge_and_usage() {
        let a = Args::parse(&["prune", "--dry-run", "--older-than", "5h", "--limit", "2", "--yes"].iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let o = Opts::from_args(&a, VALUE_FLAGS, BOOL_FLAGS);
        assert_eq!(o.pos(0), Some("prune"));
        assert_eq!(o.val("older-than"), Some("5h"));
        assert_eq!(o.num("limit").unwrap(), Some(2));
        assert!(o.flag("dry-run") && o.flag("yes"));
        let f = Filter::from(&o).unwrap();
        assert!(f.any() && f.older_than.is_some() && f.limit == Some(2));

        // raw parsing (the dispatcher may hand these over unparsed) accepts our own flags
        let o = opts(&["prune", "--include-pinned", "--title=x", "--min-messages", "3", "id1"]);
        assert!(o.flag("include-pinned") && o.val("title") == Some("x") && o.num("min-messages").unwrap() == Some(3));
        assert_eq!(o.pos, ["prune", "id1"]);
        assert!(Opts::parse(&["prune".to_string(), "--nope".into()], VALUE_FLAGS, BOOL_FLAGS).is_err());
        assert!(run(&tmp_store(), &opts(&["bogus"])).unwrap_err().contains("unknown `session bogus`"));
    }
}
