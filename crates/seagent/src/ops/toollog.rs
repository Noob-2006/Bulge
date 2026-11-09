//! Tool-call log: one compact JSONL record per tool call — when, which session, which tool, a
//! short argument summary (secrets redacted), how long it took, whether it worked and why not —
//! in `<log dir>/tools.jsonl`. It is what the console's Logs page, `seagent logs tools` and
//! `seagent logs export` read; the session event log stays the source of truth.
//!
//! The record is built from the kernel's event tap (no change to the event schema): the
//! `tool_called` event opens it (name, input, start time), `tool_settled` stamps the end, and
//! the tool-result message closes it with the outcome and the error text. A call the gate
//! refused never settles; its result message still closes the record. Calls left open when the
//! turn ends (an interrupt) are closed as failures by `turn_end`.
//!
//! Cheap by design: records go to a buffered writer that is flushed at turn end, when the
//! buffer fills, when somebody reads the log, and at shutdown — no fsync per line. `[tool_log]
//! audit = true` switches to write + fsync per record for installations that treat the log as
//! evidence. Files rotate at `max_mb` and `keep` rotated files are kept; records older than
//! `retention_days` are dropped from reads and whole rotated files past it are deleted.
//!
//! ```toml
//! [tool_log]
//! enabled = true
//! max_mb = 5             # rotate the live file past this size
//! keep = 5               # rotated files kept (tools.1.jsonl … tools.5.jsonl)
//! retention_days = 30    # 0 = keep until rotation drops them
//! audit = false          # fsync every record
//! ```

use crate::args::Args;
use crate::R;
use seagent_core::Block;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::event::{Event, EventKind};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// ARP methods, both read scope. `.history` also makes every read a *content* read in the app
/// server's audit stream (tool arguments are command lines and paths): one audit record per
/// page open, filter change or export — the Logs page does not poll.
pub const METHODS: &[&str] = &["toollog.history", "toollog.status"];
pub const FILE: &str = "tools.jsonl";
const DAY_MS: u64 = 86_400_000;
const ARGS_MAX: usize = 240;
const VALUE_MAX: usize = 80;
const ERR_MAX: usize = 240;
/// Open records per process before the oldest are dropped (a runaway parallel batch).
const OPEN_MAX: usize = 4096;

// ───────────────────────── settings ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub max_bytes: u64,
    pub keep: usize,
    pub retention_days: u64,
    pub audit: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: true, max_bytes: 5 << 20, keep: 5, retention_days: 30, audit: false }
    }
}

const KEYS: &[&str] = &["enabled", "max_mb", "keep", "retention_days", "audit"];

impl Settings {
    pub fn from_table(t: &toml::Table) -> Settings {
        let d = Settings::default();
        let int = |k: &str, def: i64, lo: i64, hi: i64| t.get(k).and_then(|v| v.as_integer()).unwrap_or(def).clamp(lo, hi);
        Settings {
            enabled: t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(d.enabled),
            max_bytes: int("max_mb", 5, 1, 1024) as u64 * (1 << 20),
            keep: int("keep", d.keep as i64, 1, 100) as usize,
            retention_days: int("retention_days", d.retention_days as i64, 0, 3650) as u64,
            audit: t.get("audit").and_then(|v| v.as_bool()).unwrap_or(d.audit),
        }
    }
    pub fn from_config(cfg: &Config) -> Settings {
        Settings::from_table(&cfg.tool_log)
    }
    /// Oldest record a read returns (`retention_days = 0`: everything still on disk).
    pub fn cutoff(&self, now_ms: u64) -> u64 {
        if self.retention_days == 0 {
            0
        } else {
            now_ms.saturating_sub(self.retention_days * DAY_MS)
        }
    }
}

/// `[tool_log]` problems (unknown keys, wrong types), for `Config::validate`.
pub fn validate(cfg: &Config, out: &mut Vec<String>) {
    for (k, v) in &cfg.tool_log {
        match k.as_str() {
            "enabled" | "audit" if !v.is_bool() => out.push(format!("{k} must be true or false")),
            "max_mb" | "keep" | "retention_days" if !v.is_integer() => out.push(format!("{k} must be an integer")),
            k if !KEYS.contains(&k) => out.push(format!("unknown key `{k}` (known: {})", KEYS.join(", "))),
            _ => {}
        }
    }
}

pub fn register() {
    seagent_core::registry::register_config_validator("tool_log", |cfg, out| {
        if let Some(c) = cfg.downcast_ref::<Config>() {
            validate(c, out);
        }
    });
}

// ───────────────────────── record building ─────────────────────────

/// Argument values that are bulk content: only their size is logged.
const BULK: &[&str] = &["content", "contents", "text", "body", "data", "new_string", "old_string", "patch", "diff", "script", "code", "html", "image", "base64", "file_text", "edits", "messages"];

/// Keys shown first, in this order.
const PRIMARY: &[&str] = &["action", "command", "path", "file_path", "url", "query", "pattern", "name", "id"];

fn sensitive_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    ["password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie", "credential", "private_key"].iter().any(|s| k.contains(s))
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `key=value …` for the input object: bulk fields as their size, secrets by name or shape
/// redacted (`redact` runs on each whole value *before* it is shortened, so a clipped token can
/// never slip past the pattern that would have matched it), the whole line bounded.
pub fn summarize_args(input: &Value, redact: &dyn Fn(&str) -> String) -> String {
    let piece = |k: &str, v: &Value| -> String {
        if sensitive_key(k) {
            return "[REDACTED]".into();
        }
        match v {
            Value::String(s) if BULK.contains(&k) => format!("<{} chars>", s.chars().count()),
            Value::String(s) => clip(&one_line(&redact(s)), VALUE_MAX),
            Value::Array(a) if BULK.contains(&k) => format!("<{} items>", a.len()),
            Value::Null => "null".into(),
            Value::Bool(_) | Value::Number(_) => v.to_string(),
            other => clip(&one_line(&redact(&other.to_string())), VALUE_MAX),
        }
    };
    let line = match input {
        Value::Object(m) => {
            // What identifies the call first (the command, the path…), the rest by name.
            let rank = |k: &str| PRIMARY.iter().position(|p| *p == k).unwrap_or(PRIMARY.len());
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| rank(a).cmp(&rank(b)).then(a.cmp(b)));
            keys.iter().map(|k| format!("{k}={}", piece(k, &m[k.as_str()]))).collect::<Vec<_>>().join(" ")
        }
        Value::Null => String::new(),
        other => piece("", other),
    };
    clip(&line, ARGS_MAX)
}

/// The first part of a failed call's output, one line, redacted, bounded.
pub fn summarize_error(content: &str, redact: &dyn Fn(&str) -> String) -> String {
    // Redact a generous head, then clip: a token cut at the head's end cannot reach the
    // first ERR_MAX characters unless thousands of blanks collapse in front of it.
    let head: String = content.chars().take(ERR_MAX * 16).collect();
    clip(&one_line(&redact(&head)), ERR_MAX)
}

struct Open {
    ts: u64,
    tool: String,
    args: String,
    settled: Option<(u64, usize)>,
}

/// Pairs `tool_called` / `tool_settled` / tool-result events into records.
#[derive(Default)]
pub struct Tracker {
    open: HashMap<(String, String), Open>,
}

fn rec(session: &str, id: &str, o: Open, end: u64, ok: bool, err: Option<String>) -> Value {
    let (end, bytes) = o.settled.map(|(t, b)| (t, Some(b))).unwrap_or((end, None));
    let mut r = json!({"ts": o.ts, "session": session, "id": id, "tool": o.tool, "args": o.args, "ms": end.saturating_sub(o.ts), "ok": ok});
    if let Some(b) = bytes {
        r["bytes"] = json!(b);
    }
    if let Some(e) = err.filter(|e| !e.is_empty()) {
        r["err"] = json!(e);
    }
    r
}

impl Tracker {
    /// Feed one event; returns the records it completes.
    pub fn observe(&mut self, session: &str, e: &Event, redact: &dyn Fn(&str) -> String) -> Vec<Value> {
        match &e.kind {
            EventKind::ToolCalled { tool_use_id, name, input, .. } => {
                if self.open.len() >= OPEN_MAX {
                    // Never grow without bound: the oldest open calls are the least likely to close.
                    let mut ts: Vec<u64> = self.open.values().map(|o| o.ts).collect();
                    ts.sort_unstable();
                    let cut = ts[OPEN_MAX / 2];
                    self.open.retain(|_, o| o.ts > cut);
                }
                self.open.insert((session.to_string(), tool_use_id.clone()), Open { ts: e.ts, tool: name.clone(), args: summarize_args(input, redact), settled: None });
                vec![]
            }
            EventKind::ToolSettled { tool_use_id, bytes, .. } => {
                if let Some(o) = self.open.get_mut(&(session.to_string(), tool_use_id.clone())) {
                    o.settled = Some((e.ts, *bytes));
                }
                vec![]
            }
            EventKind::Message { message, .. } => message
                .content
                .iter()
                .filter_map(|b| match b {
                    Block::ToolResult { tool_use_id, content, is_error } => {
                        let o = self.open.remove(&(session.to_string(), tool_use_id.clone()))?;
                        Some(rec(session, tool_use_id, o, e.ts, !is_error, is_error.then(|| summarize_error(content, redact))))
                    }
                    _ => None,
                })
                .collect(),
            EventKind::TurnEnd { reason, .. } => {
                let ids: Vec<(String, String)> = self.open.keys().filter(|(s, _)| s == session).cloned().collect();
                let mut out: Vec<Value> = ids.into_iter().filter_map(|k| self.open.remove(&k).map(|o| rec(session, &k.1, o, e.ts, false, Some(format!("no result: the turn ended ({reason})"))))).collect();
                out.sort_by_key(|r| r["ts"].as_u64());
                out
            }
            _ => vec![],
        }
    }
}

// ───────────────────────── writer ─────────────────────────

pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

fn rotated(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("tools.{i}.jsonl"))
}

/// Every log file, oldest first (rotated ones, then the live file).
pub fn files(dir: &Path, keep: usize) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = (1..=keep.max(1)).rev().map(|i| rotated(dir, i)).filter(|p| p.is_file()).collect();
    if path_in(dir).is_file() {
        v.push(path_in(dir));
    }
    v
}

struct Inner {
    w: Option<BufWriter<File>>,
    size: u64,
}

pub struct Log {
    pub dir: PathBuf,
    pub settings: Settings,
    inner: Mutex<Inner>,
}

impl Log {
    pub fn new(dir: PathBuf, settings: Settings) -> Log {
        Log { dir, settings, inner: Mutex::new(Inner { w: None, size: 0 }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn append(&self, r: &Value) {
        let mut line = r.to_string();
        line.push('\n');
        let mut g = self.lock();
        if g.w.is_none() {
            self.open(&mut g);
        }
        if g.size > 0 && g.size + line.len() as u64 > self.settings.max_bytes {
            self.rotate(&mut g);
            self.open(&mut g);
        }
        let audit = self.settings.audit;
        if let Some(w) = g.w.as_mut() {
            if w.write_all(line.as_bytes()).is_ok() && audit {
                let _ = w.flush();
                let _ = w.get_ref().sync_data();
            }
        }
        g.size += line.len() as u64;
    }

    /// Open (or create, owner-only) the live file for appending; `size` counts what is in it.
    fn open(&self, g: &mut Inner) {
        let _ = std::fs::create_dir_all(&self.dir);
        let p = path_in(&self.dir);
        let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) else { return };
        let _ = crate::ops::hostos::set_mode(&p, 0o600);
        g.size = f.metadata().map(|m| m.len()).unwrap_or(0);
        g.w = Some(BufWriter::with_capacity(16 * 1024, f));
    }

    /// Close the live file, shift `tools.N.jsonl` up by one (dropping the oldest), start fresh.
    /// The writer is dropped first: Windows cannot rename a file this process holds open for
    /// writing (readers are fine — std opens with `FILE_SHARE_DELETE`).
    fn rotate(&self, g: &mut Inner) {
        if let Some(mut w) = g.w.take() {
            let _ = w.flush();
        }
        let keep = self.settings.keep.max(1);
        let _ = std::fs::remove_file(rotated(&self.dir, keep));
        for i in (1..keep).rev() {
            let _ = std::fs::rename(rotated(&self.dir, i), rotated(&self.dir, i + 1));
        }
        let _ = std::fs::rename(path_in(&self.dir), rotated(&self.dir, 1));
        g.size = 0;
        self.prune_locked(seagent_kernel::event::now_ms());
    }

    /// Hand buffered records to the OS (turn end, before a read, at shutdown).
    pub fn flush(&self) {
        if let Some(w) = self.lock().w.as_mut() {
            let _ = w.flush();
        }
    }

    fn prune_locked(&self, now_ms: u64) -> usize {
        let cut = self.settings.cutoff(now_ms);
        if cut == 0 {
            return 0;
        }
        let mut n = 0;
        for i in 1..=self.settings.keep.max(1) + 1 {
            let p = rotated(&self.dir, i);
            let old = std::fs::metadata(&p).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).is_some_and(|d| (d.as_millis() as u64) < cut);
            if old && std::fs::remove_file(&p).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Delete rotated files whose newest record is past retention.
    pub fn prune(&self, now_ms: u64) -> usize {
        let _g = self.lock();
        self.prune_locked(now_ms)
    }
}

/// One writer per log directory in this process: kernels sharing a data dir share the file
/// handle and its buffer; a test's kernel on its own scratch dir gets its own.
fn logs() -> std::sync::MutexGuard<'static, HashMap<PathBuf, Arc<Log>>> {
    static L: OnceLock<Mutex<HashMap<PathBuf, Arc<Log>>>> = OnceLock::new();
    L.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner())
}

fn log_for(dir: &Path, s: &Settings) -> Arc<Log> {
    logs().entry(dir.to_path_buf()).or_insert_with(|| Arc::new(Log::new(dir.to_path_buf(), s.clone()))).clone()
}

/// Write what every log of this process buffers (daemon shutdown).
pub fn flush() {
    let all: Vec<Arc<Log>> = logs().values().cloned().collect();
    for l in all {
        l.flush();
    }
}

/// Retention pass over every log of this process (the daemon's per-minute maintenance; a
/// handful of `stat`s, no writes unless a rotated file is past `retention_days`).
pub fn prune_all() -> usize {
    let all: Vec<Arc<Log>> = logs().values().cloned().collect();
    let now = seagent_kernel::event::now_ms();
    all.iter().map(|l| l.prune(now)).sum()
}

fn flush_dir(dir: &Path) {
    let l = logs().get(dir).cloned();
    if let Some(l) = l {
        l.flush();
    }
}

/// Install the tap on a kernel (`wire::attach`: every host). Returns its log.
pub fn install(k: &seagent_kernel::kernel::Kernel) -> Option<Arc<Log>> {
    let s = Settings::from_config(&k.cfg);
    if !s.enabled {
        return None;
    }
    let log = log_for(&k.paths.log_dir(), &s);
    log.prune(seagent_kernel::event::now_ms());
    let vault = k.vault.clone();
    let tracker = Mutex::new(Tracker::default());
    let w = log.clone();
    k.add_tap(Arc::new(move |sid: &str, e: &Event| {
        if !matches!(e.kind, EventKind::ToolCalled { .. } | EventKind::ToolSettled { .. } | EventKind::Message { .. } | EventKind::TurnEnd { .. }) {
            return;
        }
        let redact = |s: &str| seagent_kernel::trajectory::redact_patterns(&vault.redact(s));
        let done = tracker.lock().unwrap_or_else(|p| p.into_inner()).observe(sid, e, &redact);
        for r in &done {
            w.append(r);
        }
        if matches!(e.kind, EventKind::TurnEnd { .. }) {
            w.flush();
        }
    }));
    Some(log)
}

// ───────────────────────── reading ─────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Session id or prefix.
    pub session: Option<String>,
    /// Exact tool name, or a substring when it ends in `*`.
    pub tool: Option<String>,
    /// `Some(false)` = failures only, `Some(true)` = successes only.
    pub ok: Option<bool>,
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    /// Case-insensitive substring of args / error / tool.
    pub grep: Option<String>,
    pub limit: usize,
}

impl Query {
    pub fn from_params(p: &Value, now_ms: u64) -> Query {
        let s = |k: &str| p[k].as_str().map(str::trim).filter(|v| !v.is_empty()).map(String::from);
        let time = |k: &str| p[k].as_u64().or_else(|| s(k).and_then(|v| crate::ops::logs::parse_since(&v, now_ms)));
        let ok = match s("status").as_deref() {
            Some("ok" | "success") => Some(true),
            Some("error" | "failed" | "failure" | "failures") => Some(false),
            _ if p["failures"] == true => Some(false),
            _ => None,
        };
        Query { session: s("session"), tool: s("tool"), ok, since_ms: time("since"), until_ms: time("until"), grep: s("grep").map(|g| g.to_lowercase()), limit: p["limit"].as_u64().unwrap_or(500).clamp(1, 100_000) as usize }
    }

    pub fn matches(&self, r: &Value) -> bool {
        let ts = r["ts"].as_u64().unwrap_or(0);
        let tool = r["tool"].as_str().unwrap_or("");
        self.session.as_ref().is_none_or(|s| r["session"].as_str().is_some_and(|x| x.starts_with(s.as_str())))
            && self.tool.as_ref().is_none_or(|t| match t.strip_suffix('*') {
                Some(pre) => tool.contains(pre),
                None => tool == t,
            })
            && self.ok.is_none_or(|ok| r["ok"].as_bool() == Some(ok))
            && self.since_ms.is_none_or(|s| ts >= s)
            && self.until_ms.is_none_or(|u| ts <= u)
            && self.grep.as_ref().is_none_or(|g| [&r["args"], &r["err"], &r["tool"]].iter().any(|v| v.as_str().is_some_and(|x| x.to_lowercase().contains(g.as_str()))))
    }
}

/// What a query found: the newest `limit` matches (oldest first) and totals over all matches.
#[derive(Debug, Clone, Default)]
pub struct Found {
    pub records: Vec<Value>,
    pub matched: usize,
    pub failed: usize,
    pub tools: BTreeMap<String, (usize, usize)>,
    pub sessions: usize,
}

impl Found {
    pub fn totals(&self) -> Value {
        let mut tools: Vec<(&String, &(usize, usize))> = self.tools.iter().collect();
        tools.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
        json!({"matched": self.matched, "returned": self.records.len(), "failed": self.failed, "sessions": self.sessions,
            "tools": tools.iter().map(|(t, (n, f))| json!({"tool": t, "calls": n, "failed": f})).collect::<Vec<_>>()})
    }
}

pub fn read(dir: &Path, s: &Settings, q: &Query, now_ms: u64) -> Found {
    let cut = s.cutoff(now_ms);
    let mut f = Found::default();
    let mut sessions = std::collections::HashSet::new();
    let mut ring: std::collections::VecDeque<Value> = std::collections::VecDeque::new();
    for p in files(dir, s.keep) {
        let Ok(file) = File::open(&p) else { continue };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let Ok(r) = serde_json::from_str::<Value>(&line) else { continue };
            if r["ts"].as_u64().unwrap_or(0) < cut || !q.matches(&r) {
                continue;
            }
            f.matched += 1;
            let failed = r["ok"] == false;
            if failed {
                f.failed += 1;
            }
            let e = f.tools.entry(r["tool"].as_str().unwrap_or("").to_string()).or_default();
            e.0 += 1;
            e.1 += failed as usize;
            if let Some(sid) = r["session"].as_str() {
                sessions.insert(sid.to_string());
            }
            ring.push_back(r);
            if ring.len() > q.limit {
                ring.pop_front();
            }
        }
    }
    f.sessions = sessions.len();
    f.records = ring.into_iter().collect();
    f
}

// ───────────────────────── export ─────────────────────────

/// `2026-11-09 14:03:07` at `offset_min` east of UTC.
pub fn clock(ms: u64, offset_min: i32) -> String {
    let secs = (ms / 1000) as i64;
    format!("{}:{:02}", seagent_kernel::util::fmt_time(secs, offset_min), secs.rem_euclid(60))
}

fn utc_iso(ms: u64) -> String {
    format!("{}.{:03}Z", clock(ms, 0).replacen(' ', "T", 1), ms % 1000)
}

/// A CSV cell: quoted, and a leading `= + - @` defused so a spreadsheet never runs it.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Rendered export: `(file name, MIME type, contents)`.
pub fn render(format: &str, found: &Found, q: &Query, offset_min: i32, now_ms: u64) -> Result<(String, &'static str, String), String> {
    let stamp = clock(now_ms, offset_min).replace([' ', ':'], "-");
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    match format {
        "jsonl" | "json" => {
            let mut out = String::new();
            for r in &found.records {
                out.push_str(&r.to_string());
                out.push('\n');
            }
            Ok((format!("seagent-tool-calls-{stamp}.jsonl"), "application/x-ndjson", out))
        }
        "csv" => {
            let mut out = String::from("time_utc,session,tool,status,duration_ms,args,error,bytes,call_id\r\n");
            for r in &found.records {
                let cells = [utc_iso(r["ts"].as_u64().unwrap_or(0)), s(&r["session"]), s(&r["tool"]), if r["ok"] == true { "ok".into() } else { "error".into() }, r["ms"].to_string(), s(&r["args"]), s(&r["err"]), r["bytes"].as_u64().map(|b| b.to_string()).unwrap_or_default(), s(&r["id"])];
                out.push_str(&cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
                out.push_str("\r\n");
            }
            Ok((format!("seagent-tool-calls-{stamp}.csv"), "text/csv", out))
        }
        "html" => Ok((format!("seagent-tool-calls-{stamp}.html"), "text/html", html(found, q, offset_min, now_ms))),
        other => Err(format!("unknown export format `{other}` (jsonl, csv, html)")),
    }
}

/// A standalone report page. The session export template (`export_template.html`) is a
/// transcript viewer driven by a script; a tool-call report is a table, so this page is
/// script-free (`default-src 'none'`) and shares only that template's palette.
fn html(found: &Found, q: &Query, offset_min: i32, now_ms: u64) -> String {
    let filters: Vec<String> = [
        q.session.as_ref().map(|s| format!("session {s}")),
        q.tool.as_ref().map(|t| format!("tool {t}")),
        q.ok.map(|ok| if ok { "successes only".to_string() } else { "failures only".to_string() }),
        q.since_ms.map(|t| format!("since {}", clock(t, offset_min))),
        q.until_ms.map(|t| format!("until {}", clock(t, offset_min))),
        q.grep.as_ref().map(|g| format!("matching “{g}”")),
    ]
    .into_iter()
    .flatten()
    .collect();
    let tz = format!("UTC{}{:02}:{:02}", if offset_min < 0 { '-' } else { '+' }, offset_min.abs() / 60, offset_min.abs() % 60);
    let mut rows = String::new();
    for r in &found.records {
        let ok = r["ok"] == true;
        let st = |k: &str| html_esc(r[k].as_str().unwrap_or(""));
        rows.push_str(&format!(
            "<tr class=\"{}\"><td class=\"t\">{}</td><td><code>{}</code></td><td><b>{}</b></td><td>{}</td><td class=\"n\">{}</td><td class=\"a\">{}</td><td class=\"e\">{}</td></tr>\n",
            if ok { "ok" } else { "bad" },
            html_esc(&clock(r["ts"].as_u64().unwrap_or(0), offset_min)),
            html_esc(&r["session"].as_str().unwrap_or("").chars().take(24).collect::<String>()),
            st("tool"),
            if ok { "ok" } else { "failed" },
            r["ms"].as_u64().unwrap_or(0),
            st("args"),
            st("err"),
        ));
    }
    let tools: String = found.tools.iter().map(|(t, (n, f))| format!("<li><b>{}</b> {n}{}</li>", html_esc(t), if *f > 0 { format!(" <span class=\"badf\">{f} failed</span>") } else { String::new() })).collect();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>SE Agent tool calls</title>
<style>
:root {{ --bg:#F8FAFC; --fg:#0F172A; --dim:#475569; --line:#E2E8F0; --card:#FFFFFF; --accent:#CD7F32; --bad:#B91C1C; --badbg:#FEF2F2; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0F172A; --fg:#F1F5F9; --dim:#94A3B8; --line:#334155; --card:#1E293B; --bad:#FCA5A5; --badbg:#3B1D1D; }} }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }}
h1 {{ font-size:20px; margin:0 0 4px; }} h1 span {{ color:var(--accent); }}
.meta {{ color:var(--dim); margin:0 0 16px; }}
.sum {{ display:flex; flex-wrap:wrap; gap:8px 24px; padding:12px 16px; background:var(--card); border:1px solid var(--line); border-radius:8px; margin-bottom:16px; }}
.sum ul {{ margin:0; padding:0; list-style:none; display:flex; flex-wrap:wrap; gap:4px 16px; }}
.badf {{ color:var(--bad); }}
.wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:8px; background:var(--card); }}
table {{ border-collapse:collapse; width:100%; }}
th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ font-weight:600; color:var(--dim); white-space:nowrap; }}
td.t, td.n {{ white-space:nowrap; }} td.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
td.a, td.e {{ word-break:break-word; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }}
tr.bad td {{ background:var(--badbg); }} tr.bad td.e {{ color:var(--bad); }}
</style>
</head>
<body>
<h1><span>✦</span> SE Agent tool calls</h1>
<p class="meta">Exported {exported} ({tz}) · {filters}</p>
<div class="sum"><div><b>{returned}</b> shown of {matched} calls · <b class="badf">{failed}</b> failed · {sessions} session(s)</div><ul>{tools}</ul></div>
<div class="wrap"><table>
<thead><tr><th>Time</th><th>Session</th><th>Tool</th><th>Result</th><th>ms</th><th>Arguments</th><th>Error</th></tr></thead>
<tbody>
{rows}</tbody>
</table></div>
</body>
</html>
"#,
        exported = html_esc(&clock(now_ms, offset_min)),
        filters = html_esc(&if filters.is_empty() { "all calls".to_string() } else { filters.join(" · ") }),
        returned = found.records.len(),
        matched = found.matched,
        failed = found.failed,
        sessions = found.sessions,
    )
}

// ───────────────────────── ARP ─────────────────────────

fn status(dir: &Path, s: &Settings) -> Value {
    let files: Vec<Value> = files(dir, s.keep).iter().map(|p| json!({"name": p.file_name().map(|n| n.to_string_lossy().to_string()), "bytes": std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)})).collect();
    json!({"enabled": s.enabled, "dir": dir.display().to_string(), "files": files, "maxBytes": s.max_bytes, "keep": s.keep, "retentionDays": s.retention_days, "audit": s.audit})
}

/// `toollog.history {session, tool, status, failures, since, until, grep, limit, format}` and
/// `toollog.status`. Without `format` the records come back as data; with `jsonl|csv|html`
/// the rendered export (`{filename, mime, content, count}`) for the console's download button.
pub fn methods(paths: Paths, cfg: &Config) -> seagent_kernel::daemon::MethodExt {
    let (s, off) = (Settings::from_config(cfg), cfg.schedule.utc_offset_minutes);
    let dir = paths.log_dir();
    Arc::new(move |m: &str, p: &Value| match m {
        "toollog.history" => Some({
            flush_dir(&dir);
            let now = seagent_kernel::event::now_ms();
            let q = Query::from_params(p, now);
            let found = read(&dir, &s, &q, now);
            match p["format"].as_str().filter(|f| !f.is_empty()) {
                None => Ok(json!({"records": found.records, "totals": found.totals(), "file": path_in(&dir).display().to_string(), "offsetMinutes": off})),
                Some(f) => render(f, &found, &q, off, now).map(|(name, mime, content)| json!({"filename": name, "mime": mime, "content": content, "count": found.records.len()})).map_err(|e| (-32602, e)),
            }
        }),
        "toollog.status" => Some(Ok(status(&dir, &s))),
        _ => None,
    })
}

// ───────────────────────── CLI ─────────────────────────

fn params(a: &Args) -> Result<Value, crate::Fail> {
    let mut m = Map::new();
    for k in ["session", "tool", "status", "since", "until", "grep"] {
        if let Some(v) = a.val(k) {
            m.insert(k.into(), json!(v));
        }
    }
    if a.flag("failures") {
        m.insert("failures".into(), json!(true));
    }
    if let Some(n) = a.num::<u64>("limit").map_err(crate::Fail::Usage)?.or(a.num::<u64>("lines").map_err(crate::Fail::Usage)?) {
        m.insert("limit".into(), json!(n));
    }
    Ok(Value::Object(m))
}

/// The daemon's answer when it runs (its buffer is flushed first), else the files directly.
fn query(paths: &Paths, cfg: &Config, p: &Value) -> Result<Value, String> {
    if let Ok(v) = seagent_kernel::daemon::call(&paths.socket(), "toollog.history", p.clone()) {
        return Ok(v);
    }
    (methods(paths.clone(), cfg))("toollog.history", p).unwrap_or_else(|| Err((-32601, "toollog.history".into()))).map_err(|(_, e)| e)
}

/// `seagent logs tools [filters]` and `seagent logs export [--format jsonl|csv|html] [--out FILE] [filters]`.
pub fn cli(sub: &str, a: &Args) -> R {
    let paths = Paths::from_env();
    let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default();
    let mut p = params(a)?;
    match sub {
        "export" => {
            let format = a.val("format").unwrap_or("jsonl");
            if !["jsonl", "json", "csv", "html"].contains(&format) {
                return Err(crate::Fail::Usage(format!("unknown --format `{format}` (jsonl, csv, html)")));
            }
            if p.get("limit").is_none() {
                p["limit"] = json!(100_000);
            }
            p["format"] = json!(format);
            let v = query(&paths, &cfg, &p)?;
            let content = v["content"].as_str().unwrap_or("");
            match a.val("out") {
                Some(out) => {
                    let out = if Path::new(out).is_dir() { Path::new(out).join(v["filename"].as_str().unwrap_or(FILE)) } else { PathBuf::from(out) };
                    std::fs::write(&out, content).map_err(|e| format!("{}: {e}", out.display()))?;
                    eprintln!("wrote {} tool call(s) to {}", v["count"], out.display());
                }
                None => print!("{content}"),
            }
            Ok(0)
        }
        _ => {
            let v = query(&paths, &cfg, &p)?;
            let off = v["offsetMinutes"].as_i64().unwrap_or(cfg.schedule.utc_offset_minutes as i64) as i32;
            if a.flag("json") {
                for r in v["records"].as_array().into_iter().flatten() {
                    println!("{r}");
                }
                return Ok(0);
            }
            let recs = v["records"].as_array().cloned().unwrap_or_default();
            if recs.is_empty() {
                println!("no tool calls recorded{} ({})", if p.as_object().is_some_and(|m| !m.is_empty()) { " that match" } else { "" }, v["file"].as_str().unwrap_or(""));
                return Ok(0);
            }
            for r in &recs {
                let ok = r["ok"] == true;
                println!(
                    "{} {:<5} [{}] {} {}ms {}{}",
                    clock(r["ts"].as_u64().unwrap_or(0), off),
                    if ok { "ok" } else { "ERROR" },
                    r["session"].as_str().unwrap_or("").chars().take(12).collect::<String>(),
                    r["tool"].as_str().unwrap_or(""),
                    r["ms"],
                    r["args"].as_str().unwrap_or(""),
                    r["err"].as_str().map(|e| format!("  — {e}")).unwrap_or_default()
                );
            }
            let t = &v["totals"];
            println!("{} shown · {} matched · {} failed", t["returned"], t["matched"], t["failed"]);
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{Message, Role};

    fn ev(seq: u64, ts: u64, kind: EventKind) -> Event {
        Event { seq, ts, kind }
    }
    fn called(id: &str, name: &str, input: Value) -> EventKind {
        EventKind::ToolCalled { tool_use_id: id.into(), name: name.into(), input, idempotency_key: String::new() }
    }
    fn settled(id: &str, err: bool) -> EventKind {
        EventKind::ToolSettled { tool_use_id: id.into(), is_error: err, bytes: 7, artifact: None, ui_resource: None }
    }
    fn results(r: &[(&str, &str, bool)]) -> EventKind {
        let content = r.iter().map(|(id, c, e)| Block::ToolResult { tool_use_id: (*id).into(), content: (*c).into(), is_error: *e }).collect();
        EventKind::Message { message: Message { role: Role::User, content }, usage: None, model: None, inbox: None }
    }
    fn none(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn records_pair_calls_results_and_interrupted_calls() {
        let mut t = Tracker::default();
        assert!(t.observe("s1", &ev(1, 1000, called("a", "shell", json!({"command": "ls -la"}))), &none).is_empty());
        assert!(t.observe("s1", &ev(2, 1001, called("b", "write", json!({"path": "x.txt", "content": "hello world"}))), &none).is_empty());
        t.observe("s1", &ev(3, 1040, settled("a", false)), &none);
        t.observe("s1", &ev(4, 1050, settled("b", true)), &none);
        // A gate-refused call never settles; its result still closes it.
        t.observe("s1", &ev(5, 1060, called("c", "shell", json!({"command": "sudo rm -rf /"}))), &none);
        let out = t.observe("s1", &ev(6, 1070, results(&[("a", "files", false), ("b", "permission denied: x.txt\nmore", true), ("c", "refused by the privilege gate", true)])), &none);
        assert_eq!(out.len(), 3);
        assert_eq!((out[0]["tool"].as_str(), out[0]["ok"].as_bool(), out[0]["ms"].as_u64(), out[0]["bytes"].as_u64()), (Some("shell"), Some(true), Some(40), Some(7)));
        assert_eq!(out[0]["args"], "command=ls -la");
        assert!(out[0].get("err").is_none());
        assert_eq!(out[1]["args"], "path=x.txt content=<11 chars>", "bulk content is logged as its size");
        assert_eq!((out[1]["ok"].as_bool(), out[1]["err"].as_str(), out[1]["ms"].as_u64()), (Some(false), Some("permission denied: x.txt more"), Some(49)));
        assert_eq!((out[2]["ok"].as_bool(), out[2]["ms"].as_u64()), (Some(false), Some(10)));
        // Left open by an interrupt: closed as a failure at turn end, other sessions untouched.
        t.observe("s1", &ev(7, 2000, called("d", "web_fetch", json!({"url": "https://example.com"}))), &none);
        t.observe("s2", &ev(1, 2001, called("e", "read", json!({"path": "a"}))), &none);
        let end = t.observe("s1", &ev(8, 2500, EventKind::TurnEnd { turn: 1, reason: "interrupted".into(), usage: Default::default() }), &none);
        assert_eq!(end.len(), 1);
        assert_eq!((end[0]["id"].as_str(), end[0]["ok"].as_bool(), end[0]["ms"].as_u64()), (Some("d"), Some(false), Some(500)));
        assert!(end[0]["err"].as_str().unwrap().contains("interrupted"));
        assert_eq!(t.open.len(), 1, "s2's call is still open");
    }

    #[test]
    fn arguments_and_errors_are_redacted_and_bounded() {
        let vault_like = |s: &str| seagent_kernel::trajectory::redact_patterns(&s.replace("hunter2-vault-value", "{{secret:DB_PASS}}"));
        let token = format!("sk-ant-{}", "a".repeat(40));
        let a = summarize_args(&json!({"command": format!("curl -H 'Authorization: Bearer {token}' https://api.x/{}", "p".repeat(200)), "api_key": "plain", "env": {"PGPASSWORD": "hunter2-vault-value"}}), &vault_like);
        assert!(!a.contains("sk-ant-") && !a.contains("aaaaaaaaaa"), "{a}");
        assert!(a.contains("api_key=[REDACTED]") && !a.contains("plain"), "{a}");
        assert!(!a.contains("hunter2"), "vault values are replaced: {a}");
        assert!(a.chars().count() <= ARGS_MAX, "{}", a.chars().count());
        // A token clipped mid-way must not leak its prefix: redaction runs before clipping.
        let long = format!("{}{token}", "x ".repeat(35));
        assert!(!summarize_args(&json!({"q": long}), &vault_like).contains("sk-ant"), "clip after redact");
        let e = summarize_error(&format!("error: auth failed for {token}\n{}", "trace\n".repeat(500)), &vault_like);
        assert!(!e.contains("sk-ant") && e.chars().count() <= ERR_MAX && !e.contains('\n'), "{e}");
        assert_eq!(summarize_args(&Value::Null, &none), "");
        assert_eq!(summarize_args(&json!({"n": 3, "flag": true, "items": ["a"]}), &none), "flag=true items=[\"a\"] n=3");
    }

    fn rec_at(i: u64, ok: bool, session: &str, tool: &str) -> Value {
        json!({"ts": 1_700_000_000_000u64 + i * 1000, "session": session, "id": format!("t{i}"), "tool": tool, "args": format!("command=echo {i}"), "ms": i, "ok": ok, "err": if ok { Value::Null } else { json!(format!("boom {i}")) }})
    }

    #[test]
    fn buffered_writes_rotate_and_reads_filter_across_files() {
        let d = seagent_core::tmp::TempDir::new("seagent-toollog");
        let s = Settings { max_bytes: 600, keep: 2, retention_days: 0, ..Default::default() };
        let log = Log::new(d.path().to_path_buf(), s.clone());
        log.append(&rec_at(0, true, "sA", "shell"));
        assert_eq!(std::fs::metadata(path_in(d.path())).unwrap().len(), 0, "buffered: nothing written per record");
        log.flush();
        assert!(std::fs::metadata(path_in(d.path())).unwrap().len() > 0, "flush hands it to the OS");
        // A reader holding the live file open must not stop rotation (Windows share modes).
        let reader = File::open(path_in(d.path())).unwrap();
        for i in 1..30u64 {
            log.append(&rec_at(i, i % 4 != 0, if i < 15 { "sA" } else { "sB" }, if i % 2 == 0 { "shell" } else { "read" }));
        }
        log.flush();
        drop(reader);
        assert!(rotated(d.path(), 1).is_file() && rotated(d.path(), 2).is_file() && !rotated(d.path(), 3).exists(), "rotated, capped at keep = 2");
        for p in files(d.path(), s.keep) {
            assert!(std::fs::metadata(&p).unwrap().len() <= 600 + 200, "{} stays near the cap", p.display());
        }
        let all = read(d.path(), &s, &Query { limit: 1000, ..Default::default() }, 0);
        assert!(all.matched > 5 && all.matched < 30, "oldest rotated away: {}", all.matched);
        let ts: Vec<u64> = all.records.iter().map(|r| r["ts"].as_u64().unwrap()).collect();
        assert!(ts.windows(2).all(|w| w[0] < w[1]), "oldest first across files");
        let fails = read(d.path(), &s, &Query { ok: Some(false), limit: 1000, ..Default::default() }, 0);
        assert!(fails.records.iter().all(|r| r["ok"] == false) && fails.failed == fails.matched && fails.matched > 0);
        let b = read(d.path(), &s, &Query { session: Some("sB".into()), tool: Some("shell".into()), limit: 2, ..Default::default() }, 0);
        assert_eq!(b.records.len(), 2, "limit keeps the newest");
        assert!(b.records.iter().all(|r| r["session"] == "sB" && r["tool"] == "shell"));
        assert_eq!(b.records.last().unwrap()["id"], "t28");
        let g = read(d.path(), &s, &Query { grep: Some("boom 2".into()), limit: 10, ..Default::default() }, 0);
        assert!(g.records.iter().all(|r| r["err"].as_str().unwrap().contains("boom 2")));
        // Retention: records older than the window drop out of reads.
        let ret = Settings { retention_days: 1, ..s.clone() };
        assert_eq!(read(d.path(), &ret, &Query { limit: 10, ..Default::default() }, 1_700_000_000_000 + 3 * DAY_MS).matched, 0);
        // …and a rotated file whose last write is past it is deleted; a recent one stays.
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::OpenOptions::new().write(true).open(rotated(d.path(), 2)).unwrap().set_modified(old).unwrap();
        let pruner = Log::new(d.path().to_path_buf(), ret);
        assert_eq!(pruner.prune(seagent_kernel::event::now_ms()), 1);
        assert!(!rotated(d.path(), 2).exists() && rotated(d.path(), 1).is_file() && path_in(d.path()).is_file());
    }

    #[test]
    fn audit_mode_writes_every_record_through() {
        let d = seagent_core::tmp::TempDir::new("seagent-toollog-audit");
        let log = Log::new(d.path().to_path_buf(), Settings { audit: true, ..Default::default() });
        log.append(&rec_at(1, false, "s", "shell"));
        let text = std::fs::read_to_string(path_in(d.path())).unwrap();
        assert!(text.ends_with('\n') && text.contains("boom 1"), "on disk without a flush: {text}");
    }

    #[test]
    fn exports_render_jsonl_csv_and_html() {
        let mut f = Found { records: vec![rec_at(1, true, "s1", "shell"), rec_at(2, false, "s1", "write")], matched: 2, failed: 1, sessions: 1, ..Default::default() };
        f.records[1]["args"] = json!("=HYPERLINK(\"http://x\") <script>alert(1)</script>");
        f.tools.insert("shell".into(), (1, 0));
        f.tools.insert("write".into(), (1, 1));
        let q = Query { ok: None, session: Some("s1".into()), ..Default::default() };
        let (name, _, jl) = render("jsonl", &f, &q, 480, 1_700_000_100_000).unwrap();
        assert!(name.ends_with(".jsonl") && jl.lines().count() == 2);
        assert!(jl.lines().all(|l| serde_json::from_str::<Value>(l).is_ok()));
        let (_, _, csv) = render("csv", &f, &q, 480, 0).unwrap();
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert!(lines[0].starts_with("time_utc,session,tool,status"));
        assert!(lines[1].starts_with("\"2023-11-14T22:13:21.000Z\",\"s1\",\"shell\",\"ok\""), "{}", lines[1]);
        assert!(lines[2].contains("\"'=HYPERLINK(\"\"http://x\"\")"), "formula defused and quotes doubled: {}", lines[2]);
        let (_, _, html) = render("html", &f, &q, 480, 0).unwrap();
        assert!(html.contains("default-src 'none'") && !html.contains("<script>alert"), "escaped, script-free");
        assert!(html.contains("&lt;script&gt;") && html.contains("class=\"bad\"") && html.contains("session s1"));
        assert!(html.contains("UTC+08:00") && html.contains("2023-11-15 06:13:21"), "local clock with its offset");
        assert!(render("pdf", &f, &q, 0, 0).is_err());
    }

    #[test]
    fn query_params_and_settings() {
        let q = Query::from_params(&json!({"session": "abc", "tool": "web*", "status": "error", "since": "1h", "limit": 5}), 10 * 3_600_000);
        assert_eq!((q.session.as_deref(), q.ok, q.since_ms, q.limit), (Some("abc"), Some(false), Some(9 * 3_600_000), 5));
        assert!(q.matches(&json!({"ts": 9 * 3_600_000 + 1, "session": "abcdef", "tool": "web_fetch", "ok": false})));
        assert!(!q.matches(&json!({"ts": 9 * 3_600_000 + 1, "session": "abcdef", "tool": "shell", "ok": false})));
        assert_eq!(Query::from_params(&json!({"failures": true}), 0).ok, Some(false));
        assert_eq!(Query::from_params(&json!({}), 0).limit, 500);
        let t: toml::Table = toml::from_str("max_mb = 0\nkeep = 1000\nretention_days = 7\naudit = true").unwrap();
        let s = Settings::from_table(&t);
        assert_eq!((s.max_bytes, s.keep, s.retention_days, s.audit, s.enabled), (1 << 20, 100, 7, true, true), "clamped");
        assert_eq!(s.cutoff(8 * DAY_MS), DAY_MS);
        let cfg = Config { tool_log: toml::from_str("enabled = \"yes\"\nmaxmb = 3").unwrap(), ..Default::default() };
        let mut out = vec![];
        validate(&cfg, &mut out);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(out.iter().any(|m| m.contains("unknown key `maxmb`")));
    }

    /// Through a real kernel: the tap sees the appended events, the turn end flushes, the ARP
    /// method reads it back (filters, export), and a vault secret in the arguments is replaced.
    #[test]
    fn kernel_tap_records_calls_and_the_method_serves_them() {
        let t = crate::testkit::kit();
        t.k.vault.set("DEPLOY_TOKEN", "tok-very-secret-123").unwrap();
        let log = install(&t.k).expect("enabled by default");
        let sid = t.k.create_session(&t.ws, None, None, None).unwrap();
        t.k.record(&sid, called("c1", "shell", json!({"command": "deploy --token tok-very-secret-123"}))).unwrap();
        t.k.record(&sid, settled("c1", false)).unwrap();
        t.k.record(&sid, called("c2", "read", json!({"path": "missing.txt"}))).unwrap();
        t.k.record(&sid, results(&[("c1", "deployed", false), ("c2", "no such file: missing.txt", true)])).unwrap();
        let p = path_in(&t.paths.log_dir());
        assert_eq!(std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0), 0, "buffered until the turn ends");
        t.k.record(&sid, EventKind::TurnEnd { turn: 1, reason: "done".into(), usage: Default::default() }).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(!text.contains("tok-very-secret-123") && text.contains("{{secret:DEPLOY_TOKEN}}"), "{text}");
        let m = methods(t.paths.clone(), &t.k.cfg);
        let v = m("toollog.history", &json!({"status": "error"})).unwrap().unwrap();
        assert_eq!(v["records"].as_array().unwrap().len(), 1);
        assert_eq!((v["records"][0]["tool"].as_str(), v["records"][0]["err"].as_str()), (Some("read"), Some("no such file: missing.txt")));
        assert_eq!((v["totals"]["matched"].as_u64(), v["totals"]["failed"].as_u64()), (Some(1), Some(1)));
        let x = m("toollog.history", &json!({"session": &sid[..6], "format": "csv"})).unwrap().unwrap();
        assert_eq!(x["count"], 2);
        assert!(x["content"].as_str().unwrap().lines().count() == 3 && x["filename"].as_str().unwrap().ends_with(".csv"));
        assert!(m("toollog.history", &json!({"format": "xml"})).unwrap().is_err());
        assert_eq!(m("toollog.status", &json!({})).unwrap().unwrap()["files"][0]["name"], FILE);
        assert!(Arc::ptr_eq(&log, &log_for(&t.paths.log_dir(), &Settings::default())), "one writer per directory");
    }

    /// The console's Logs page (`ui/web/logs.js`) only calls methods this module serves.
    #[test]
    fn logs_js_calls_only_served_methods() {
        const JS: &str = include_str!("../../../../ui/web/logs.js");
        let called: Vec<&str> = JS.match_indices("call('").map(|(i, _)| &JS[i + 6..]).map(|r| &r[..r.find('\'').unwrap_or(0)]).collect();
        assert!(called.contains(&"toollog.history"), "{called:?}");
        for m in called {
            assert!(METHODS.contains(&m) || m.starts_with("ui.logs"), "logs.js calls `{m}`, which nothing serves");
        }
        for m in METHODS {
            assert_eq!(seagent_app::exposure::required_scope(m), seagent_app::exposure::Scope::Read, "{m} is read-only");
        }
        // Tool arguments are command lines and paths: reading them is a content read, which the
        // app server always audits (one record per page open / export, not per poll).
        assert!(seagent_app::identity::is_content_method("toollog.history"));
        assert!(!JS.contains("setInterval(") || JS.contains("TL.follow"), "the tool view never polls");
    }
}
